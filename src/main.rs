use std::ffi::CString;
use std::fs::remove_dir_all;
use std::io::{BufReader, ErrorKind};
use std::path::Path;
use std::process::exit;
use std::{env, fs};

use chrono::{DateTime, Utc};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::unistd::{ForkResult, Pid, chdir, execvp, fork, pivot_root, setsid};

use serde::{Deserialize, Serialize};

use anyhow::{Context, Result, anyhow};
use clap::Parser;

const STACK_SIZE: usize = 1024 * 1024;
const FOUNDRY_STATE_DIR: &str = "/var/run/foundry";
const FOUNDRY_CGROUP_DIR: &str = "/sys/fs/cgroup/foundry";

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciMemory {
    limit: Option<i64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciCpu {
    quota: Option<i64>,
    period: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciResources {
    cpu: Option<OciCpu>,
    memory: Option<OciMemory>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciLinux {
    resources: Option<OciResources>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
}

#[derive(Deserialize, Debug)]
struct OciRoot {
    path: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciConfig {
    process: OciProcess,
    root: OciRoot,
    hostname: Option<String>,
    linux: Option<OciLinux>,
}

/// Represent the container's lifecycle state.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Status {
    /// The Container is being created
    Creating,
    /// The Container has been created and is ready to be started
    Created,
    /// The container is running
    Running,
    /// The container has stopped.
    Stopped,
}

/// Holds the persistent state of a container as described by OCI Runtime spec.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ContainerState {
    /// The unique container ID
    id: String,
    /// The path to OCI bundle
    bundle: String,
    /// The container's current status
    status: Status,
    /// The host-level PID of the container's init process
    pid: Option<i32>,
    /// The OCI Runtime spec version
    oci_version: String,
    /// The time container was created
    created: DateTime<Utc>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Create a container
    Create(CreateArgs),
    /// Start a container that has been created
    Start(LifecycleArgs),
    /// Stop a running container
    Kill(LifecycleArgs),
    /// Delete a stopped container
    Delete(LifecycleArgs),
}

#[derive(Parser, Debug)]
struct CreateArgs {
    /// Path to the OCI bundle directory
    #[arg(required = true)]
    bundle_path: String,
    container_id: String,
}

#[derive(Parser, Debug)]
struct LifecycleArgs {
    /// The unique ID of the container
    #[arg(required = true)]
    container_id: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create(args) => do_create(&args)?,
        Commands::Start(args) => do_start(&args)?,
        Commands::Kill(args) => do_kill(&args)?,
        Commands::Delete(args) => do_delete(&args)?,
    }

    Ok(())
}

fn read_oci_config(path: &Path) -> Result<OciConfig> {
    let file = fs::File::open(path)
        .with_context(|| format!("Failed to open the config.json file at {:?}.", path))?;
    let buf = BufReader::new(file);
    let config =
        serde_json::from_reader(buf).with_context(|| "Failed to parse OCI config from reader")?;

    Ok(config)
}

fn write_container_state(state: &ContainerState, path: &Path) -> Result<()> {
    let json_data = serde_json::to_string(state).with_context(|| "Failed to serialize state.")?;
    fs::write(path, json_data).with_context(|| "Failed to write state to disk.")?;
    Ok(())
}

fn read_container_state(path: &Path) -> Result<ContainerState> {
    let json_data = fs::read_to_string(path)?;
    let data: ContainerState = serde_json::from_str(&json_data)?;
    Ok(data)
}

fn run_container(oci_config: &OciConfig, bundle_path: &str) -> isize {
    if let Some(hostname) = &oci_config.hostname {
        if let Ok(c_hostname) = CString::new(hostname.as_str()) {
            if unsafe { nix::libc::sethostname(c_hostname.as_ptr(), hostname.len()) } != 0 {
                eprintln!("Child process: sethostname failed");
                return -1;
            }
        }
    }

    mount(
        None::<&Path>,
        "/",
        None::<&Path>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&Path>,
    )
    .expect("Failed to make root mount private");

    let rootfs_path = Path::new(bundle_path).join(&oci_config.root.path);

    mount(
        Some(&rootfs_path),
        &rootfs_path,
        None::<&Path>,
        MsFlags::MS_BIND,
        None::<&Path>,
    )
    .expect("Failed to bind mount the new rootfs onto itself");

    let old_root_put_path = rootfs_path.join(".old_root");
    fs::create_dir(&old_root_put_path).expect("failed to create .old_root directory for pivot");

    pivot_root(&rootfs_path, &old_root_put_path)
        .expect("pivot_root failed. Ensure new root is a mount point.");
    chdir("/").expect("Failed to chdir into new root directory");
    umount2("/.old_root", MntFlags::MNT_DETACH).expect("Failed to unmount old root.");
    remove_dir_all("/.old_root").expect("Failed to remove the old root mount directory");

    fs::create_dir_all("/proc").expect("Failed to create /proc");
    fs::create_dir_all("/sys").expect("Failed to create /sys");
    fs::create_dir_all("/dev").expect("Failed to create /dev");

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&Path>,
    )
    .unwrap();
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&Path>,
    )
    .unwrap();
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&Path>,
    )
    .unwrap();

    for var in &oci_config.process.env {
        let parts: Vec<&str> = var.splitn(2, "=").collect();
        if parts.len() == 2 {
            unsafe { env::set_var(parts[0], parts[1]) };
        }
    }

    chdir(Path::new(&oci_config.process.cwd)).expect("Failed to chdir to OCI cwd");

    let mut sig_set = SigSet::empty();
    sig_set.add(Signal::SIGUSR1);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&sig_set), None).expect("Failed to block signal");
    if let Ok(sig) = sig_set.wait() {
        println!("Signal {} received.", sig)
    }

    let command = &oci_config.process.args[0];
    let args = &oci_config.process.args;
    let c_command = CString::new(command.as_bytes()).unwrap();
    let c_args: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();

    match execvp(&c_command, &c_args) {
        Err(err) => {
            eprintln!("Child process: execv failed with error: {err}");
            return 1;
        }
    }
}

fn do_create(args: &CreateArgs) -> Result<()> {
    println!("Creating container from bundle: {}", args.bundle_path);

    let container_state_path = Path::new(FOUNDRY_STATE_DIR).join(&args.container_id);
    if is_path_existing(&container_state_path)? {
        return Err(anyhow!("Error: container ID exists."));
    }

    fs::create_dir_all(&container_state_path)
        .with_context(|| "Failed to create container's directory")?;

    let initial_state = ContainerState {
        id: args.container_id.clone(),
        bundle: args.bundle_path.clone(),
        status: Status::Creating,
        pid: None,
        oci_version: String::from("1.1.0"),
        created: Utc::now(),
    };
    write_container_state(&initial_state, &container_state_path.join("state.json"))?;

    match unsafe { fork()? } {
        ForkResult::Parent { .. } => exit(0),
        ForkResult::Child => {
            setsid().with_context(|| "Failed to creation new session.")?;

            let foundry_cgroup_path = Path::new(FOUNDRY_CGROUP_DIR);
            if !is_path_existing(foundry_cgroup_path)? {
                fs::create_dir_all(foundry_cgroup_path).with_context(|| {
                    format!(
                        "Failed to create cgroup parent directory at {:?}.",
                        foundry_cgroup_path
                    )
                })?;
            }

            let container_cgroup_path = foundry_cgroup_path.join(&args.container_id);
            fs::create_dir(&container_cgroup_path).with_context(|| {
                format!(
                    "Failed to create container cgroup at {:?}",
                    container_cgroup_path
                )
            })?;

            fs::write(
                foundry_cgroup_path.join("cgroup.subtree_control"),
                b"+cpu +memory",
            )
            .with_context(|| "Failed to enable CPU & Memory controllers for container cgroup")?;

            let oci_config = read_oci_config(&Path::new(&args.bundle_path).join("config.json"))?;
            if let Some(oci_linux) = &oci_config.linux {
                if let Some(oci_resources) = &oci_linux.resources {
                    if let Some(oci_memory) = &oci_resources.memory {
                        if let Some(memory_limit) = oci_memory.limit {
                            fs::write(
                                &container_cgroup_path.join("memory.max"),
                                memory_limit.to_string(),
                            )
                            .with_context(|| {
                                format!("Failed to set container memory limit to {}", memory_limit)
                            })?;
                            fs::write(&container_cgroup_path.join("memory.swap.max"), "0")
                                .with_context(|| "Failed to disable memory swap for container")?;
                        }

                        if let Some(oci_cpu) = &oci_resources.cpu {
                            if let (Some(cpu_period), Some(cpu_quota)) =
                                (oci_cpu.quota, oci_cpu.period)
                            {
                                let cpu_max_value = format!("{} {}", cpu_quota, cpu_period);
                                fs::write(&container_cgroup_path.join("cpu.max"), cpu_max_value)
                                    .with_context(|| "Failed to set container CPU limit")?;
                            }
                        }
                    }
                }
            }

            let mut stack = [0_u8; STACK_SIZE];
            let flags =
                CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS;
            let sigchld = Some(Signal::SIGCHLD as i32);

            let child_closure =
                || -> isize { run_container(&oci_config, &args.bundle_path.clone()) };

            match unsafe { clone(Box::new(child_closure), &mut stack, flags, sigchld) } {
                Ok(pid) => {
                    let final_state = ContainerState {
                        status: Status::Created,
                        pid: Some(pid.as_raw()),
                        ..initial_state
                    };
                    write_container_state(&final_state, &container_state_path.join("state.json"))
                        .with_context(
                        || "Failed to write CREATED status to container's state.json file",
                    )?;

                    exit(0)
                }
                Err(err) => fs::write(
                    Path::new(FOUNDRY_STATE_DIR).join("error.log"),
                    err.to_string(),
                )?,
            }
        }
    }

    Ok(())
}

fn is_path_existing(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Ok(false),
            _ => Err(anyhow!("Unexpected error occurred: {e}")),
        },
    }
}

fn do_start(args: &LifecycleArgs) -> Result<()> {
    println!("Starting container: {}", args.container_id);

    let container_state_path =
        &Path::new(FOUNDRY_STATE_DIR).join(format!("{}/state.json", &args.container_id));
    let mut container_state = read_container_state(container_state_path).with_context(|| {
        format!(
            "Error locating container state: {}",
            container_state_path.display()
        )
    })?;

    if container_state.status != Status::Created {
        return Err(anyhow!(
            "Operation not permitted: Expects container's state to be CREATED"
        ));
    }

    if let Some(proc_pid) = container_state.pid {
        let cgroup_procs_path =
            Path::new(FOUNDRY_CGROUP_DIR).join(&format!("{}/cgroup.procs", &args.container_id));
        fs::write(cgroup_procs_path, proc_pid.to_string())
            .with_context(|| "Failed to add process to process ID to cgroup")?;

        match signal::kill(Pid::from_raw(proc_pid), Signal::SIGUSR1) {
            Ok(_) => {
                container_state.status = Status::Running;
                write_container_state(&container_state, container_state_path)
                    .with_context(|| "Failed to write updated container's state to disk")?;
            }
            Err(e) => {
                return Err(anyhow!("Failed to start container: {e}"));
            }
        }
    } else {
        return Err(anyhow!("Inconsistent state: can't find container's PID"));
    }

    Ok(())
}

fn do_kill(args: &LifecycleArgs) -> Result<()> {
    println!("Stopping container: {}", args.container_id);

    let container_state_path =
        &Path::new(FOUNDRY_STATE_DIR).join(format!("{}/state.json", &args.container_id));
    let mut container_state = read_container_state(container_state_path)
        .with_context(|| "Failed to read container's state")?;

    if container_state.status != Status::Created || container_state.status != Status::Running {
        return Err(anyhow!(
            "Operation not permitted: Expects container's state to be either CREATED or RUNNING"
        ));
    }

    if let Some(proc_pid) = container_state.pid {
        match signal::kill(Pid::from_raw(proc_pid), Signal::SIGKILL) {
            Ok(_) => {
                container_state.status = Status::Stopped;
                write_container_state(&container_state, container_state_path)
                    .with_context(|| "Failed to write updated container's state to disk")?;
            }
            Err(e) => {
                return Err(anyhow!("Failed to kill the container: {e}"));
            }
        }
    } else {
        return Err(anyhow!("Inconsistent state: can't find container's PID"));
    }

    Ok(())
}

fn do_delete(args: &LifecycleArgs) -> Result<()> {
    println!("Deleting container: {}", args.container_id);

    let container_state = read_container_state(
        &Path::new(FOUNDRY_STATE_DIR).join(format!("{}/state.json", &args.container_id)),
    )
    .with_context(|| "Failed to read container's state from disk.")?;
    
    if container_state.status != Status::Stopped {
        return Err(anyhow!("Operation not permitted: Expects container's state to be STOPPED"));
    }
    
    cleanup_container_resources(&args.container_id)?;
    
    Ok(())
}

fn cleanup_container_resources(container_id: &str) -> Result<()> {
    let container_state_dir = &Path::new(FOUNDRY_STATE_DIR).join(container_id);
    fs::remove_dir_all(container_state_dir).with_context(|| {
        format!(
            "Failed to delete container's resources at {}",
            container_state_dir.display()
        )
    })?;

    let container_cgroup = &Path::new(FOUNDRY_CGROUP_DIR).join(container_id);
    fs::remove_dir(container_cgroup).with_context(|| {
        format!(
            "Failed to delete container's cgroup at {}",
            container_cgroup.display()
        )
    })?;

    Ok(())
}
