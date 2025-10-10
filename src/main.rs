use std::error::Error;
use std::ffi::CString;
use std::io::BufReader;
use std::path::Path;
use std::{env, fs};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{chdir, execvp, pivot_root};

use serde::Deserialize;

const STACK_SIZE: usize = 1024 * 1024;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OCIProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String
}

#[derive(Deserialize, Debug)]
struct OCIRoot {
    path: String,
}

#[derive(Deserialize, Debug)]
struct OCIConfig {
    process: OCIProcess,
    root: OCIRoot,
}

fn read_from_file(file: fs::File) -> Result<OCIConfig, Box<dyn Error>> {
    let buf = BufReader::new(file);
    let config = serde_json::from_reader(buf)?;

    Ok(config)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args[1] != "run" {
        return Err("Usage: ./foundry run <path-to-bundle>".into());
    }

    let bundle_path = Path::new(&args[2]);
    let config_path = bundle_path.join("config.json");

    let oci_config = read_from_file(fs::File::open(&config_path)?)?;
    let rootfs_path = bundle_path.join(&oci_config.root.path);

    let mut stack = [0_u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS;
    let sigchld = Some(Signal::SIGCHLD as i32);

    let child_closure = || -> isize {
        let hostname = CString::new("foundry-container").unwrap();

        if unsafe { nix::libc::sethostname(hostname.as_ptr(), hostname.as_bytes().len()) } != 0 {
            eprintln!("Child process: sethostname failed");
            return -1;
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
                unsafe {env::set_var(parts[0], parts[1])};
            }
        }
        
        let cwd = Path::new(&oci_config.process.cwd);
        chdir(cwd).expect("Failed to chdir to OCI cwd");

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
        Ok(pid) => match wait::waitpid(pid, None) {
            Ok(WaitStatus::Exited(child_pid, exit_code)) => {
                println!(
                    "Parent process: child process {} exited with code {}",
                    child_pid, exit_code
                );
                Ok(())
            }
            Ok(status) => Err(format!(
                "Parent process: child process exited with unexpected status {status:?}"
            )
            .into()),
            Err(err) => Err(format!("Parent process: waitpid failed with error: {err}").into()),
        },
        Err(err) => Err(format!("Parent process: clone failed with error: {err}").into()),
    }
}
