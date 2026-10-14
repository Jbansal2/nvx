//! The programs that run in NVX's Linux guests, which ship as `/sbin/nvx-*`.
//!
//! Each module holds one program, and the crate's binary of the same name runs its `main`. The
//! programs keep their established command lines, exit statuses, and byte-level output; error
//! messages carry the C library's `strerror` text.

mod parse;
mod sys;
#[cfg(target_arch = "x86_64")]
mod x86;

pub mod agent;
pub mod console_pending;
pub mod ingress;
#[cfg(target_arch = "x86_64")]
pub mod mmio_write;
pub mod port_io;
pub mod reseed;
#[cfg(target_arch = "x86_64")]
pub mod time;
#[cfg(target_arch = "x86_64")]
pub mod time_probe;
