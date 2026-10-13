//! The C runtime behavior that the guest programs keep: `errno` and its `strerror` text, the
//! process arguments as C strings, the default `SIGPIPE` disposition, unbuffered messages, and
//! stdio's handling of a failed write to standard output.

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;

/// An `errno` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Errno(pub(crate) libc::c_int);

impl Errno {
    /// Returns the calling thread's `errno`.
    pub(crate) fn last() -> Self {
        Self(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// Returns the `errno` of a failed write: its OS error, or `EIO` for a write that made no
    /// progress.
    pub(crate) fn of(error: &io::Error) -> Self {
        Self(error.raw_os_error().unwrap_or(libc::EIO))
    }

    /// Returns the C library's `strerror` text, which the C programs printed; the text of Rust's
    /// `io::Error` ends with ` (os error N)` instead.
    pub(crate) fn text(self) -> Vec<u8> {
        // SAFETY: strerror returns a NUL-terminated string, which is copied before another call
        // can reuse its buffer; the guest programs are single-threaded.
        unsafe { CStr::from_ptr(libc::strerror(self.0)) }
            .to_bytes()
            .to_vec()
    }
}

/// Returns the process arguments, program name first, as the C strings that `main` received.
pub(crate) fn args() -> Vec<CString> {
    std::env::args_os()
        .map(|argument| CString::new(argument.into_vec()).expect("arguments are C strings"))
        .collect()
}

/// Restores the default `SIGPIPE` disposition, which Rust's runtime replaces with `SIG_IGN`, so
/// that writing to a closed pipe ends a program as it ended the C program.
pub(crate) fn restore_sigpipe() {
    // SAFETY: a default disposition installs no handler.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

/// Standard output with the error behavior of C's stdio, through which the C programs printed.
/// On a terminal, stdout is line-buffered, so a failed write failed the `printf` of its line.
/// Anything else is fully buffered until `exit` flushes it, which ignores a failure, so a failed
/// write is dropped as if it succeeded.
pub(crate) struct Stdout {
    terminal: bool,
}

impl Stdout {
    /// Returns the process's standard output.
    pub(crate) fn new() -> Self {
        // SAFETY: isatty takes any descriptor.
        let terminal = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
        Self { terminal }
    }
}

impl Write for Stdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: write reads at most `bytes.len()` bytes of `bytes`.
        let count = unsafe { libc::write(libc::STDOUT_FILENO, bytes.as_ptr().cast(), bytes.len()) };
        if count > 0 || bytes.is_empty() {
            return Ok(count.max(0) as usize);
        }
        let error = match count {
            0 => io::ErrorKind::WriteZero.into(),
            _ => io::Error::last_os_error(),
        };
        if self.terminal || error.kind() == io::ErrorKind::Interrupted {
            return Err(error);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes the concatenation of `parts` to `stream` in one write, as C's unbuffered `stderr` did,
/// and ignores a failure, as the C programs did.
pub(crate) fn report(stream: &mut dyn Write, parts: &[&[u8]]) {
    let _ = stream.write_all(&parts.concat());
}

/// Writes `bytes` to `stream` and flushes it.
pub(crate) fn print(stream: &mut dyn Write, bytes: &[u8]) -> Result<(), Errno> {
    stream
        .write_all(bytes)
        .and_then(|()| stream.flush())
        .map_err(|error| Errno::of(&error))
}

/// Calls `operation` again while it fails with `EINTR`, as the C programs' retry loops did, and
/// returns its first other result. `errno` still holds the error of a failed result.
pub(crate) fn retry<T: Copy + Ord + Default>(mut operation: impl FnMut() -> T) -> T {
    loop {
        let result = operation();
        if result >= T::default() || Errno::last() != Errno(libc::EINTR) {
            return result;
        }
    }
}

/// Closes `descriptor`, and returns `errno` if `close` fails.
pub(crate) fn close(descriptor: libc::c_int) -> Result<(), Errno> {
    // SAFETY: the caller owns the descriptor and does not use it again.
    if unsafe { libc::close(descriptor) } == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{self, Write};

    use super::*;

    /// A stream whose writes fail with an `errno`.
    pub(crate) struct Failing(pub(crate) libc::c_int);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn text_is_the_c_library_message_without_the_rust_suffix() {
        for code in [
            libc::ENOENT,
            libc::EACCES,
            libc::EIO,
            libc::ENOTTY,
            libc::EBUSY,
        ] {
            let rust = io::Error::from_raw_os_error(code).to_string();
            let expected = rust
                .strip_suffix(&format!(" (os error {code})"))
                .expect("Rust appends the errno");
            assert_eq!(Errno(code).text(), expected.as_bytes(), "errno {code}");
        }
    }

    #[test]
    fn of_takes_the_os_error_or_eio() {
        let error = io::Error::from_raw_os_error(libc::ENOSPC);
        assert_eq!(Errno::of(&error), Errno(libc::ENOSPC));
        assert_eq!(
            Errno::of(&io::ErrorKind::WriteZero.into()),
            Errno(libc::EIO)
        );
    }

    #[test]
    fn report_concatenates_and_ignores_failures() {
        let mut stream = Vec::new();
        report(&mut stream, &[b"a: ", b"b", b"\n"]);
        assert_eq!(stream, b"a: b\n");
        report(&mut Failing(libc::EIO), &[b"lost\n"]);
    }

    #[test]
    fn print_returns_the_errno_of_a_failed_write() {
        let mut stream = Vec::new();
        assert_eq!(print(&mut stream, b"7\n"), Ok(()));
        assert_eq!(stream, b"7\n");
        assert_eq!(
            print(&mut Failing(libc::EPIPE), b"7\n"),
            Err(Errno(libc::EPIPE))
        );
    }

    /// Sets `errno`, as a failed system call does.
    fn set_errno(errno: libc::c_int) {
        // SAFETY: errno is thread-local.
        unsafe { *libc::__errno_location() = errno };
    }

    #[test]
    fn retry_repeats_only_after_eintr() {
        let mut results = vec![(-1, libc::EINTR), (-1, libc::EINTR), (3, 0)].into_iter();
        let mut calls = 0;
        let result = retry(|| {
            calls += 1;
            let (result, errno) = results.next().unwrap();
            set_errno(errno);
            result
        });
        assert_eq!((result, calls), (3, 3));

        let mut calls = 0;
        let result = retry(|| {
            calls += 1;
            set_errno(libc::EIO);
            -1_isize
        });
        assert_eq!((result, calls, Errno::last()), (-1, 1, Errno(libc::EIO)));
    }

    #[test]
    fn close_reports_errno() {
        assert_eq!(close(-1), Err(Errno(libc::EBADF)));
    }
}
