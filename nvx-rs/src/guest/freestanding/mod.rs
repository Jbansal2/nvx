//! The `core`-only logic of the freestanding guest binaries, `nvx-exit` and `nvx-device-io`.
//!
//! The binaries include these modules by path, so that the `guest` profile builds them without
//! `std` or libc, with their own `_start`; see the README's guest binaries section. The library
//! compiles them only to run their unit tests, on every host.

mod args;
mod device_io;
mod exit;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod mem;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod syscall;
