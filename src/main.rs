const STACK_SIZE: usize = 1024 * 1024;

fn _child_process() -> isize {
    println!("Child process: I'm alive people!");
    0
}

fn main() {
    let _stack = [0_u8; STACK_SIZE];
    
    println!("Parent process: about to create a child process");
}
