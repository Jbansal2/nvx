//! The programs that run in NVX's Linux guests, which ship as `/sbin/nvx-*`.
//!
//! Each module holds one program, and the crate's binary of the same name runs its `main`. The
//! programs keep the command lines, exit statuses, and output of the C programs that they
//! replace, byte for byte; error messages carry the C library's `strerror` text.

mod sys;

pub mod console_pending;
