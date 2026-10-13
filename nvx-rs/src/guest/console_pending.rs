//! `nvx-console-pending DEVICE`: prints the number of bytes waiting to be read from a device, such
//! as a console, which the console-snapshot test reads from `/dev/hvc1`.

use std::ffi::CString;
use std::io::{self, Write};
use std::process::ExitCode;

use super::sys::{self, Errno};

/// Runs `nvx-console-pending` with the process's arguments. It exits with 0, 1 when an operation
/// fails, or 2 for a usage error.
pub fn main() -> ExitCode {
    sys::restore_sigpipe();
    ExitCode::from(run(
        &sys::args(),
        &mut sys::Stdout::new(),
        &mut io::stderr(),
    ))
}

fn run(args: &[CString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let [_, device] = args else {
        sys::report(err, &[b"usage: nvx-console-pending DEVICE\n"]);
        return 2;
    };
    let fail = |err: &mut dyn Write, operation: &[u8], errno: Errno| {
        let device = device.as_bytes();
        let text = errno.text();
        sys::report(
            err,
            &[
                b"nvx-console-pending: ",
                operation,
                b" ",
                device,
                b": ",
                &text,
                b"\n",
            ],
        );
    };

    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK;
    // SAFETY: the path is a NUL-terminated string.
    let descriptor = unsafe { libc::open(device.as_ptr(), flags) };
    if descriptor < 0 {
        fail(err, b"open", Errno::last());
        return 1;
    }
    let mut pending: libc::c_int = 0;
    // SAFETY: FIONREAD stores an int through the pointer, which outlives the call.
    if unsafe { libc::ioctl(descriptor, libc::FIONREAD, &mut pending) } != 0 {
        fail(err, b"ioctl", Errno::last());
        // SAFETY: closes the descriptor that open returned, once.
        unsafe { libc::close(descriptor) };
        return 1;
    }
    // SAFETY: closes the descriptor that open returned, once.
    if unsafe { libc::close(descriptor) } != 0 {
        fail(err, b"close", Errno::last());
        return 1;
    }
    if let Err(errno) = sys::print(out, format!("{pending}\n").as_bytes()) {
        let text = errno.text();
        sys::report(err, &[b"nvx-console-pending: write: ", &text, b"\n"]);
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use super::*;
    use crate::guest::sys::tests::Failing;

    fn console_pending(arguments: &[&[u8]]) -> (u8, Vec<u8>, Vec<u8>) {
        let mut args = vec![CString::new("nvx-console-pending").unwrap()];
        args.extend(
            arguments
                .iter()
                .map(|argument| CString::new(*argument).unwrap()),
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(&args, &mut out, &mut err);
        (status, out, err)
    }

    fn message(operation: &str, path: &Path, errno: libc::c_int) -> Vec<u8> {
        let mut message = format!("nvx-console-pending: {operation} ").into_bytes();
        message.extend_from_slice(path.as_os_str().as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(&Errno(errno).text());
        message.push(b'\n');
        message
    }

    #[test]
    fn usage_takes_exactly_one_device() {
        let usage = b"usage: nvx-console-pending DEVICE\n".to_vec();
        for arguments in [&[][..], &[&b"a"[..], b"b"]] {
            assert_eq!(console_pending(arguments), (2, Vec::new(), usage.clone()));
        }
    }

    #[test]
    fn prints_the_bytes_waiting_in_a_fifo() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("console");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the path is a NUL-terminated string.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let path = fifo.as_os_str().as_bytes();
        assert_eq!(console_pending(&[path]), (0, b"0\n".to_vec(), Vec::new()));

        // Opening a FIFO's reader without blocking lets the writer open it.
        let reader = fs::File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        fs::write(&fifo, b"twelve bytes").unwrap();
        assert_eq!(console_pending(&[path]), (0, b"12\n".to_vec(), Vec::new()));
        drop(reader);
    }

    #[test]
    fn prints_the_unread_size_of_a_regular_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"12345").unwrap();
        let path = file.path().as_os_str().as_bytes();
        assert_eq!(console_pending(&[path]), (0, b"5\n".to_vec(), Vec::new()));
    }

    #[test]
    fn reports_failures_with_strerror() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        assert_eq!(
            console_pending(&[missing.as_os_str().as_bytes()]),
            (1, Vec::new(), message("open", &missing, libc::ENOENT))
        );
        // A directory opens, but has no FIONREAD.
        assert_eq!(
            console_pending(&[directory.path().as_os_str().as_bytes()]),
            (
                1,
                Vec::new(),
                message("ioctl", directory.path(), libc::ENOTTY)
            )
        );
    }

    #[test]
    fn reports_a_failed_write() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let args = [
            CString::new("nvx-console-pending").unwrap(),
            CString::new(file.path().as_os_str().as_bytes()).unwrap(),
        ];
        let mut err = Vec::new();
        assert_eq!(run(&args, &mut Failing(libc::EIO), &mut err), 1);
        let mut expected = b"nvx-console-pending: write: ".to_vec();
        expected.extend_from_slice(&Errno(libc::EIO).text());
        expected.push(b'\n');
        assert_eq!(err, expected);
    }
}
