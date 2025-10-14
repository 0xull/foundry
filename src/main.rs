use std::ffi::CString;
use std::fs::remove_dir_all;
use std::io::{BufReader, Write};
use std::path::Path;
use std::{env, fs};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{chdir, execvp, pivot_root};

use serde::Deserialize;
use uuid::Uuid;

use anyhow::{Context, Result, anyhow};
use clap::Parser;

const STACK_SIZE: usize = 1024 * 1024;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCIMemory {
    limit: Option<i64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCICpu {
    quota: Option<i64>,
    period: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCIResources {
    cpu: Option<OCICpu>,
    memory: Option<OCIMemory>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCILinux {
    resources: Option<OCIResources>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCIProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
}

#[derive(Deserialize, Debug)]
struct OCIRoot {
    path: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCIConfig {
    process: OCIProcess,
    root: OCIRoot,
    hostname: Option<String>,
    linux: Option<OCILinux>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Run a container
    Run(RunArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Path to the OCI bundle directory
    #[arg(required = true)]
    bundle_path: String,
}

fn read_from_file(path: &Path) -> Result<OCIConfig> {
    let file = fs::File::open(path)
        .with_context(|| format!("Failed to open the config.json file at {:?}.", path))?;
    let buf = BufReader::new(file);
    let config =
        serde_json::from_reader(buf).with_context(|| "Failed to parse OCI config from reader")?;

    Ok(config)
}

fn run_container(args: &RunArgs) -> Result<()> {
    let bundle_path = Path::new(&args.bundle_path);
    let config_path = bundle_path.join("config.json");

    let oci_config = read_from_file(&config_path)?;
    let rootfs_path = bundle_path.join(&oci_config.root.path);

    let foundry_cgroup_path = Path::new("/sys/fs/cgroup/foundry");
    fs::create_dir_all(&foundry_cgroup_path).with_context(|| {
        format!(
            "Failed to create cgroup parent directory at {:?}.",
            foundry_cgroup_path
        )
    })?;

    let container_id = Uuid::new_v4().to_string();
    let container_cgroup_path = foundry_cgroup_path.join(&container_id);
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

    if let Some(oci_linux) = oci_config.linux {
        if let Some(oci_resources) = oci_linux.resources {
            if let Some(oci_memory) = oci_resources.memory {
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

                if let Some(oci_cpu) = oci_resources.cpu {
                    if let (Some(cpu_period), Some(cpu_quota)) = (oci_cpu.quota, oci_cpu.period) {
                        let cpu_max_value = format!("{} {}", cpu_quota, cpu_period);
                        fs::write(&container_cgroup_path.join("cpu.max"), cpu_max_value)
                            .with_context(|| "Failed to set container CPU limit")?;
                    }
                }
            }
        }
    }

    let mut stack = [0_u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS;
    let sigchld = Some(Signal::SIGCHLD as i32);

    let child_closure = || -> isize {
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
    };

    let clone_result = unsafe { clone(Box::new(child_closure), &mut stack, flags, sigchld) };

    match clone_result {
        Ok(pid) => {
            let cgroup_procs_path = container_cgroup_path.join("cgroup.procs");
            let mut cgroup_procs_file = fs::File::create(&cgroup_procs_path)?;
            cgroup_procs_file.write_all(pid.to_string().as_bytes())?;

            match wait::waitpid(pid, None) {
                Ok(WaitStatus::Exited(child_pid, exit_code)) => {
                    println!(
                        "Parent process: child process {} exited with code {}",
                        child_pid, exit_code
                    );
                    fs::remove_dir(&container_cgroup_path)?;

                    // TODO: Remove foundry cgroup when all container cgroup are deleted.
                    // let mut entries = fs::read_dir(&foundry_cgroup_path)?;
                    // if entries.next().is_none() {
                    //     fs::remove_dir(foundry_cgroup_path)?;
                    // }

                    Ok(())
                }
                Ok(status) => Err(anyhow!(
                    "Parent process: child process exited with unexpected status {status:?}"
                )),
                Err(err) => Err(anyhow!("Parent process: waitpid failed with error: {err}")),
            }
        }
        Err(err) => Err(anyhow!("Parent process: clone failed with error: {err}")),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            run_container(&args)?;
        }
    }

    Ok(())
}
