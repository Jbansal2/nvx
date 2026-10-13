//! `nvx-exit [CODE]`: stops the VM with an 8-bit exit code; see `guest/freestanding/exit.rs`.
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
#[allow(dead_code, reason = "nvx-device-io uses the rest")]
#[path = "../guest/freestanding/args.rs"]
mod args;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../guest/freestanding/exit.rs"]
mod exit;
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
    exit::run(args)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", not(panic = "abort")))]
fn main() {
    hosted::main()
}

// /dev/port and OpenVMM's control port exist only in x86_64 Linux guests. Elsewhere this stub
// fails, so that every target that CI checks with `--all-features` still builds.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    std::process::exit(1);
}
