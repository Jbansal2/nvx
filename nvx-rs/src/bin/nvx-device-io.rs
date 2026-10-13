//! `nvx-device-io`: the device benchmark helper; see `guest/freestanding/device_io.rs`.
//!
//! On x86_64 Linux, the `guest` profile, which aborts on panic, builds it freestanding: without
//! `std` or libc, with its own `_start`. Unwinding profiles cannot build that, so they build the
//! same program on `std`, as `cargo test` does. Other targets build a stub.
#![cfg_attr(
    all(target_os = "linux", target_arch = "x86_64", panic = "abort"),
    no_std,
    no_main
)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../guest/freestanding/args.rs"]
mod args;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../guest/freestanding/device_io.rs"]
mod device_io;
#[cfg(all(target_os = "linux", target_arch = "x86_64", not(panic = "abort")))]
#[path = "../guest/freestanding/hosted.rs"]
mod hosted;
#[cfg(all(target_os = "linux", target_arch = "x86_64", panic = "abort"))]
#[path = "../guest/freestanding/mem.rs"]
mod mem;
#[cfg(all(target_os = "linux", target_arch = "x86_64", panic = "abort"))]
#[path = "../guest/freestanding/start.rs"]
mod start;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../guest/freestanding/syscall.rs"]
mod syscall;

/// Runs the program with the process's arguments, and returns its exit status.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run(args: args::Args<'_>) -> i32 {
    use device_io::{IoBuffer, Output};

    // Static, as in the C program: the 4 KiB block stays out of the stack, and both start zeroed
    // in .bss.
    static mut IO: IoBuffer = IoBuffer::new();
    static mut OUTPUT: Output = Output::new();
    let (io, output) = (&raw mut IO, &raw mut OUTPUT);
    // SAFETY: the program is single-threaded and runs once, so these are the only references to
    // the buffers.
    let (io, output) = unsafe { (&mut *io, &mut *output) };
    device_io::linux::run(args, io, output)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", not(panic = "abort")))]
fn main() {
    hosted::main()
}

// The benchmark uses the system calls of x86_64 Linux. Elsewhere this stub fails, so that every
// target that CI checks with `--all-features` still builds.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    std::process::exit(1);
}
