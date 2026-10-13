//! The programs that run in NVX's Linux guests, which ship as `/sbin/nvx-*`.
//!
//! Each module holds one program, and the crate's binary of the same name runs its `main`. The
//! programs keep the command lines, exit statuses, and output of the C programs that they
//! replace, byte for byte; error messages carry the C library's `strerror` text.

mod parse;
mod sys;

pub mod console_pending;
#[cfg(target_arch = "x86_64")]
pub mod mmio_write;
pub mod port_io;
pub mod reseed;
