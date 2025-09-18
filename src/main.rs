use std::ffi::CString;

use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::execv;

const STACK_SIZE: usize = 1024 * 1024;

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
    };
    println!("Child process: hostname of process changed.");

    let shell_path = CString::new("/bin/sh").expect("failed to created C nul-terminated string");
    let shell_args = [shell_path.as_c_str()];

    match execv(&shell_path, &shell_args) {
        Err(err) => {
            eprintln!("Child process: execv failed with error: {err}");
            return 1;
        }
    }
}

fn main() {
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
                )
            }
            Ok(status) => {
                println!(
                    "Parent process: child process exited with unexpected status {:?}",
                    status
                )
            }
            Err(err) => eprintln!("Parent process: waitpid failed with error: {err}"),
        },
        Err(err) => eprintln!("Parent process: clone failed with error: {err}"),
    }
}
