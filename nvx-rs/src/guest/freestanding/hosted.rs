//! The entry point of the freestanding binaries when an unwinding profile builds them, as
//! `cargo test` does: the same program behind `std`'s `main`.

use std::ffi::CString;
use std::os::unix::ffi::OsStringExt;

use crate::args::Args;

/// Runs the program with the process's arguments, and exits with its status.
pub(crate) fn main() -> ! {
    // Rust's runtime ignores SIGPIPE; restore the guest CLI's terminating disposition.
    // SAFETY: a default disposition installs no handler.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let arguments: Vec<CString> = std::env::args_os()
        .map(|argument| CString::new(argument.into_vec()).expect("arguments are C strings"))
        .collect();
    let mut pointers: Vec<*const u8> = arguments
        .iter()
        .map(|argument| argument.as_ptr().cast())
        .collect();
    pointers.push(std::ptr::null());
    // SAFETY: the pointers point to the NUL-terminated arguments, which outlive `args`.
    let args = unsafe { Args::new(arguments.len(), pointers.as_ptr()) };
    std::process::exit(crate::run(args))
}
