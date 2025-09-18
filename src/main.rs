use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::{self, WaitStatus};

const STACK_SIZE: usize = 1024 * 1024;

fn child_main() -> isize {
    println!("Child process: I'm alive people!");
    0
}

fn main() {
    let mut stack = [0_u8; STACK_SIZE];
    
    println!("Parent process: about to create a child process");
    
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS;
    let sigchld = Some(Signal::SIGCHLD as i32);
        
    let clone_result = unsafe {
        clone(Box::new(|| child_main()), &mut stack, flags, sigchld)
    };
    
    match clone_result {
        Ok(pid) => {
            match wait::waitpid(pid, None) {
                Ok(WaitStatus::Exited(child_pid, exit_code)) => {
                    println!("Parent process: child process {} exited with code {}", child_pid, exit_code)
                }
                Ok(status) => {
                    println!("Parent process: child process exited with unexpected status {:?}", status)
                },
                Err(err) => eprintln!("Parent process: waitpid failed with error: {err}")
            }
        },
        Err(err) => eprintln!("Parent process: clone failed with error: {err}")
    }
}
