use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    env,
    ffi::CString,
    fs::{self, remove_dir_all},
    io::{BufRead, BufReader, ErrorKind, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    thread,
};

use chrono::{DateTime, Utc};
use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, clone},
    sys::signal::{self, SigSet, SigmaskHow, Signal, pthread_sigmask},
    unistd::{Pid, Uid, chdir, execvp, pivot_root},
};

const STACK_SIZE: usize = 1024 * 1024;
const FOUNDRY_STATE_DIR: &str = "/var/run/foundry";
const FOUNDRY_CGROUP_DIR: &str = "/sys/fs/cgroup/foundry";
const FOUNDRY_SOCKET_PATH: &str = "/var/run/foundry/foundry.socket";

/// Represents an incoming JSON-RPC request
#[derive(Serialize, Deserialize, Debug)]
struct Request {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

/// Represents an outgoing JSON-RPC response
#[derive(Serialize, Debug)]
struct Response {
    jsonrpc: String,
    result: serde_json::Value,
    id: u64,
}

/// Represents JSON-RPC error
#[derive(Serialize, Debug)]
struct JsonRpcError {
    code: i32,
    message: String,
}

/// Represent an outgoing JSON-RPC error response
#[derive(Serialize, Debug)]
struct ErrorResponse {
    jsonrpc: String,
    error: JsonRpcError,
    id: serde_json::Value,
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

fn main() -> Result<()> {
    println!("[foundryd] Starting daemon...");

    if !Uid::effective().is_root() {
        return Err(anyhow!("foundryd must be run as root"));
    }

    let socket = Path::new(FOUNDRY_SOCKET_PATH);
    if let Some(p_path) = socket.parent() {
        fs::create_dir_all(p_path)
            .with_context(|| format!("Failed to create socket directory: {p_path:?}"))?;
    }

    if socket.exists() {
        fs::remove_file(FOUNDRY_SOCKET_PATH)
            .with_context(|| format!("Failed to remove old UNIX socket file: {socket:?}"))?;
    }

    let listener = UnixListener::bind(socket)
        .with_context(|| format!("Failed to bind to UNIX socket: {socket:?}"))?;

    println!("[foundry] Bound to socket. Listening for connections...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("[foundry] Accepted new connection.");
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream) {
                        eprintln!("[foundry] Error handling connection: {err}");
                    };
                });
            }
            Err(err) => {
                eprintln!("[foundry] Failed to accept connection: {err}")
            }
        }
    }
    Ok(())
}

fn handle_connection(mut stream: UnixStream) -> Result<()> {
    println!("[foundry:handler] Handling client...");

    let mut reader = BufReader::new(&stream);
    let mut request_data = String::new();
    reader
        .read_line(&mut request_data)
        .with_context(|| "Failed to read request body until new line")?; // newline-terminated JSON-RPC requests

    let request = match serde_json::from_str::<Request>(&request_data) {
        Ok(req) => req,
        Err(err) => {
            let err_response = ErrorResponse {
                jsonrpc: "2.0".to_string(),
                error: JsonRpcError {
                    code: -32700,
                    message: format!("Invalid JSON was received: {}", err),
                },
                id: serde_json::Value::Null,
            };
            let response_json = serde_json::to_string(&err_response)? + "\n";
            stream.write_all(response_json.as_bytes())?;
            return Err(anyhow!("[foundry] Failed to parse JSON-RPC request: {}", err));
        }
    };

    let id = request.id;

    let result = match request.method.as_str() {
        "create" => handle_create_request(request.params),
        "start" => handle_start_request(request.params),
        "kill" => handle_kill_request(request.params),
        "delete" => handle_delete_request(request.params),
        _ => Err(anyhow!("[foundry] Method not found: {}", request.method)),
    };

    let response_json = match result {
        Ok(payload) => {
            let response = Response {
                jsonrpc: "2.0".to_string(),
                result: payload,
                id,
            };
            serde_json::to_string(&response)?
        }
        Err(err) => {
            let err_response = ErrorResponse {
                jsonrpc: "2.0".to_string(),
                error: JsonRpcError {
                    code: -32000,
                    message: format!("Failed to process request: {}", err),
                },
                id: json!(id),
            };
            serde_json::to_string(&err_response)?
        }
    };

    stream.write_all((response_json + "\n").as_bytes())?;
    Ok(())
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateParams {
    bundle_path: String,
    container_id: String,
}

fn handle_create_request(params: serde_json::Value) -> Result<serde_json::Value> {
    let args = serde_json::from_value::<CreateParams>(params)?;
    do_create(&args)?;
    Ok(json!({}))
}

fn do_create(args: &CreateParams) -> Result<()> {
    let container_state_path = Path::new(FOUNDRY_STATE_DIR).join(&args.container_id);
    if is_path_existing(&container_state_path)? {
        return Err(anyhow!(
            "[foundry] Container ID already exists: {}",
            args.container_id
        ));
    }

    fs::create_dir_all(&container_state_path)
        .with_context(|| "[foundry] Failed to create container's directory")?;

    let initial_state = ContainerState {
        id: args.container_id.clone(),
        bundle: args.bundle_path.clone(),
        status: Status::Creating,
        pid: None,
        oci_version: String::from("1.1.0"),
        created: Utc::now(),
    };
    write_container_state(&initial_state, &container_state_path.join("state.json"))?;
    
    // setsid().with_context(|| "Failed to creation new session.")?;

    let foundry_cgroup_path = Path::new(FOUNDRY_CGROUP_DIR);
    if !is_path_existing(foundry_cgroup_path)? {
        fs::create_dir_all(foundry_cgroup_path).with_context(|| {
            format!(
                "[foundry] Failed to create cgroup parent directory at {:?}.",
                foundry_cgroup_path
            )
        })?;
    }

    let container_cgroup_path = foundry_cgroup_path.join(&args.container_id);
    fs::create_dir(&container_cgroup_path).with_context(|| {
        format!(
            "[foundry] Failed to create container cgroup at {:?}",
            container_cgroup_path
        )
    })?;

    fs::write(
        foundry_cgroup_path.join("cgroup.subtree_control"),
        b"+cpu +memory",
    )
    .with_context(|| "[foundry] Failed to enable CPU & Memory controllers for container cgroup")?;

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
                        format!("[foundry] Failed to set container memory limit to {}", memory_limit)
                    })?;
                    fs::write(&container_cgroup_path.join("memory.swap.max"), "0")
                        .with_context(|| "[foundry] Failed to disable memory swap for container")?;
                }

                if let Some(oci_cpu) = &oci_resources.cpu {
                    if let (Some(cpu_period), Some(cpu_quota)) = (oci_cpu.quota, oci_cpu.period) {
                        let cpu_max_value = format!("{} {}", cpu_quota, cpu_period);
                        fs::write(&container_cgroup_path.join("cpu.max"), cpu_max_value)
                            .with_context(|| "[foundry] Failed to set container CPU limit")?;
                    }
                }
            }
        }
    }

    let mut stack = [0_u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNS;
    let sigchld = Some(Signal::SIGCHLD as i32);

    let child_closure = || -> isize {
        run_container(
            &oci_config,
            &args.bundle_path.clone(),
            &args.container_id.clone(),
        )
    };
    
    match unsafe { clone(Box::new(child_closure), &mut stack, flags, sigchld) } {
        Ok(pid) => {
            let final_state = ContainerState {
                status: Status::Created,
                pid: Some(pid.as_raw()),
                ..initial_state
            };
            write_container_state(&final_state, &container_state_path.join("state.json"))
                .with_context(|| "[foundry] Failed to write CREATED status to container's state.json file")?;
        }
        Err(err) => eprintln!("[foundry] clone failed: {err}"),
    }

    Ok(())
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LifecycleParams {
    container_id: String,
}

fn handle_start_request(params: serde_json::Value) -> Result<serde_json::Value> {
    let args = serde_json::from_value::<LifecycleParams>(params)?;
    do_start(&args)?;
    Ok(json!({}))
}

fn do_start(args: &LifecycleParams) -> Result<()> {
    let container_state_path =
        &Path::new(FOUNDRY_STATE_DIR).join(format!("{}/state.json", &args.container_id));
    let mut container_state = read_container_state(container_state_path).with_context(|| {
        format!(
            "[foundry] Error locating container state: {}",
            container_state_path.display()
        )
    })?;

    if container_state.status != Status::Created {
        return Err(anyhow!(
            "[foundry] Operation not permitted: Expects container's state to be CREATED"
        ));
    }

    if let Some(proc_pid) = container_state.pid {
        let cgroup_procs_path =
            Path::new(FOUNDRY_CGROUP_DIR).join(&format!("{}/cgroup.procs", &args.container_id));
        fs::write(cgroup_procs_path, proc_pid.to_string())
            .with_context(|| "[foundry] Failed to add process to process ID to cgroup")?;

        match signal::kill(Pid::from_raw(proc_pid), Signal::SIGUSR1) {
            Ok(_) => {
                container_state.status = Status::Running;
                write_container_state(&container_state, container_state_path)
                    .with_context(|| "[foundry] Failed to write updated container's state to disk")?;
            }
            Err(e) => {
                return Err(anyhow!("[foundry] Failed to start container: {e}"));
            }
        }
    } else {
        return Err(anyhow!("[foundry] Inconsistent state: can't find container's PID"));
    }

    Ok(())
}

fn handle_kill_request(params: serde_json::Value) -> Result<serde_json::Value> {
    let args = serde_json::from_value::<LifecycleParams>(params)?;
    do_kill(&args)?;
    Ok(json!({}))
}

fn do_kill(args: &LifecycleParams) -> Result<()> {
    let container_state_path =
        &Path::new(FOUNDRY_STATE_DIR).join(format!("{}/state.json", &args.container_id));
    let mut container_state = read_container_state(container_state_path)
        .with_context(|| "[foundry] Failed to read container's state")?;

    if container_state.status != Status::Created && container_state.status != Status::Running {
        return Err(anyhow!(
            "[foundry] Operation not permitted: Expects container's state to be either CREATED or RUNNING"
        ));
    }

    if let Some(proc_pid) = container_state.pid {
        match signal::kill(Pid::from_raw(proc_pid), Signal::SIGKILL) {
            Ok(_) => {
                container_state.status = Status::Stopped;
                write_container_state(&container_state, container_state_path)
                    .with_context(|| "[foundry] Failed to write updated container's state to disk")?;
            }
            Err(e) => {
                return Err(anyhow!("[foundry] Failed to kill the container: {e}"));
            }
        }
    } else {
        return Err(anyhow!("[foundry] Inconsistent state: can't find container's PID"));
    }

    Ok(())
}

fn handle_delete_request(params: serde_json::Value) -> Result<serde_json::Value> {
    let args = serde_json::from_value::<LifecycleParams>(params)?;
    do_delete(&args)?;
    Ok(json!({}))
}

fn do_delete(args: &LifecycleParams) -> Result<()> {
    let container_state = read_container_state(
        &Path::new(FOUNDRY_STATE_DIR).join(format!("{}/state.json", &args.container_id)),
    )
    .with_context(|| "[foundry] Failed to read container's state from disk.")?;

    if container_state.status != Status::Stopped {
        return Err(anyhow!(
            "[foundry] Operation not permitted: Expects container's state to be STOPPED"
        ));
    }

    cleanup_container_resources(&args.container_id)?;

    Ok(())
}

fn cleanup_container_resources(container_id: &str) -> Result<()> {
    let container_state_dir = &Path::new(FOUNDRY_STATE_DIR).join(container_id);
    fs::remove_dir_all(container_state_dir).with_context(|| {
        format!(
            "[foundry] Failed to delete container's state at {}",
            container_state_dir.display()
        )
    })?;

    let container_cgroup_dir = &Path::new(FOUNDRY_CGROUP_DIR).join(container_id);
    fs::remove_dir(container_cgroup_dir).with_context(|| {
        format!(
            "[foundry] Failed to delete container's cgroup at {}",
            container_cgroup_dir.display()
        )
    })?;

    Ok(())
}

fn is_path_existing(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Ok(false),
            _ => Err(anyhow!("[foundry] Unexpected error occurred: {e}")),
        },
    }
}

fn write_container_state(state: &ContainerState, path: &Path) -> Result<()> {
    let json_data = serde_json::to_string(state).with_context(|| "[foundry] Failed to serialize state.")?;
    fs::write(path, json_data).with_context(|| "[foundry] Failed to write state to disk.")?;
    Ok(())
}

fn read_container_state(path: &Path) -> Result<ContainerState> {
    let json_data = fs::read_to_string(path)?;
    let data: ContainerState = serde_json::from_str(&json_data)?;
    Ok(data)
}

fn read_oci_config(path: &Path) -> Result<OciConfig> {
    let file = fs::File::open(path)
        .with_context(|| format!("[foundry] Failed to open the config.json file at {:?}.", path))?;
    let buf = BufReader::new(file);
    let config =
        serde_json::from_reader(buf).with_context(|| "[foundry] Failed to parse OCI config from reader")?;

    Ok(config)
}

fn run_container(oci_config: &OciConfig, bundle_path: &str, container_id: &str) -> isize {
    if let Some(hostname) = &oci_config.hostname {
        if let Ok(c_hostname) = CString::new(hostname.as_str()) {
            if unsafe { nix::libc::sethostname(c_hostname.as_ptr(), hostname.len()) } != 0 {
                eprintln!("[foundry:{container_id}]: sethostname failed");
                return 1;
            }
        }
    }

    if let Err(err) = mount(
        None::<&Path>,
        "/",
        None::<&Path>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&Path>,
    ) {
        eprintln!("[foundry:{container_id}]: Failed to make root mount private: {err}");
        return 1;
    }
    let rootfs_path = Path::new(bundle_path).join(&oci_config.root.path);

    if let Err(err) = mount(
        Some(&rootfs_path),
        &rootfs_path,
        None::<&Path>,
        MsFlags::MS_BIND,
        None::<&Path>,
    ) {
        eprintln!(
            "[foundry:{container_id}]: Failed to bind mount the new rootfs onto itself: {err}"
        );
        return 1;
    }

    let old_root_put_path = rootfs_path.join(".old_root");
    if let Err(err) = fs::create_dir(&old_root_put_path) {
        eprintln!("[foundry:{container_id}]: Failed to create .old_root directory: {err}");
        return 1;
    }
    if let Err(err) = pivot_root(&rootfs_path, &old_root_put_path) {
        eprintln!("[foundry:{container_id}]: pivot_root failed: {err}");
        return 1;
    }
    if let Err(err) = chdir("/") {
        eprintln!("[foundry:{container_id}]: chdir to new root directory failed: {err}");
        return 1;
    }
    if let Err(err) = umount2("/.old_root", MntFlags::MNT_DETACH) {
        eprintln!("[foundry:{container_id}]: Failed to unmount old root: {err}");
        return 1;
    }
    if let Err(err) = remove_dir_all("/.old_root") {
        eprintln!("[foundry:{container_id}]: Failed to remove the old root mount directory: {err}");
        return 1;
    }

    fs::create_dir_all("/proc").expect("Failed to create /proc");
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&Path>,
    )
    .unwrap();
    fs::create_dir_all("/sys").expect("Failed to create /sys");
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&Path>,
    )
    .unwrap();
    fs::create_dir_all("/dev").expect("Failed to create /dev");
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

    if let Err(err) = chdir(Path::new(&oci_config.process.cwd)) {
        eprintln!("[foundry:{container_id}]: chdir to OCI cwd failed: {err}");
        return 1;
    }

    let mut sig_set = SigSet::empty();
    sig_set.add(Signal::SIGUSR1);
    if let Err(err) = pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&sig_set), None) {
        eprintln!("[foundry:{container_id}]: Failed to block signal: {err}");
        return 1;
    }
    if let Err(err) = sig_set.wait() {
        eprintln!("[foundry:{container_id}]: Failed to wait for signal: {err}");
        return 1;
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
