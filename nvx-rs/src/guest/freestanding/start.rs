//! The entry point, exit, and panic handler of the freestanding binaries, which have neither
//! `std` nor libc. Each binary defines `run`, which takes the process's arguments and returns its
//! exit status.

use crate::args::Args;

const SYS_EXIT_GROUP: usize = 231;

/// The process entry point. It passes the initial stack pointer, which points at `argc`, to
/// `entry`, with the stack aligned to 16 bytes as a call requires.
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym entry,
    )
}

/// Runs the program with the arguments on the initial stack, and exits with its status.
unsafe extern "C" fn entry(stack: *const usize) -> ! {
    // SAFETY: the kernel starts a process with `argc` at the top of its stack, followed by the
    // `argv` pointers, whose strings stay valid for the life of the process.
    let args = unsafe { Args::new(*stack, stack.add(1).cast()) };
    exit_group(crate::run(args))
}

/// Ends the process with `status`.
fn exit_group(status: i32) -> ! {
    // SAFETY: exit_group takes a status and does not return.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT_GROUP,
            in("rdi") status as isize,
            options(noreturn, nostack),
        )
    }
}

/// Traps on a panic, which only a defect could cause; there is no `std` to report it.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: ud2 raises SIGILL, which ends the process.
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
}
