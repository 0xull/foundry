use std::error::Error;
use std::ffi::CString;
use std::io::BufReader;
use std::path::Path;
use std::{env, fs};

use nix::mount::{mount, umount, umount2, MntFlags, MsFlags};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{chdir, execv, pivot_root};

use serde::Deserialize;

const STACK_SIZE: usize = 1024 * 1024;

#[derive(Deserialize, Debug)]
struct OCIProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
}

#[derive(Deserialize, Debug)]
struct OCIRoot {
    path: String,
    readonly: bool,
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

fn child_main() -> isize {
    println!("Child process: Setting up environment...");

    unsafe {
        let hostname =
            CString::new("foundry-container").expect("failed to create C nul-terminated string");
        let res = nix::libc::sethostname(hostname.as_ptr(), hostname.as_bytes().len());
        if res != 0 {
            eprintln!("Child process: sethostname failed.");
            return 1;
        }
        println!("Child process: hostname of process changed.");

        let new_root = "./oci-bundle/rootfs";
        mount(
            Some(new_root),
            new_root.as_bytes(),
            None::<&Path>,
            MsFlags::MS_BIND,
            None::<&Path>,
        )
        .expect("failed to bind mount the new rootfs");
        pivot_root(".", ".").expect("failed to stack mount the new rootfs");
        chdir(new_root).expect("failed to change directory");
        umount2(".", MntFlags::MNT_DETACH).expect("failed to unmount old rootfs");
    };

    let shell_path = CString::new("/bin/sh").expect("failed to created C nul-terminated string");
    let shell_args = [shell_path.as_c_str()];

    match execv(&shell_path, &shell_args) {
        Err(err) => {
            eprintln!("Child process: execv failed with error: {err}");
            return 1;
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let oci_config = read_from_file(fs::File::open(&args[1])?)?;
    println!("{oci_config:#?}");

    let mut stack = [0_u8; STACK_SIZE];

    println!("Parent process: about to create a child process");

    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS;
    let sigchld = Some(Signal::SIGCHLD as i32);

    let clone_result = unsafe { clone(Box::new(|| child_main()), &mut stack, flags, sigchld) };

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
