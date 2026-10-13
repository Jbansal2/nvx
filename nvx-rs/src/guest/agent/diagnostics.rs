use std::ffi::CString;
use std::io;

use super::seam::System;

pub(crate) fn error(system: &mut impl System, stage: &str, status: i32) {
    let message = format!("NVX-MANAGED-ERROR: stage={stage} status={status}\n");
    let _ = system.write_diagnostic(message.as_bytes());
}

pub(crate) fn mapping_error(system: &mut impl System, status: i32, entry: u32) {
    error(system, "host-mapping", status);
    let message = format!("NVX-MANAGED-ERROR: stage=host-mapping status={status} entry={entry}\n");
    write_stderr(message.as_bytes());
}

pub(crate) fn write_stderr(message: &[u8]) {
    let _ = write_all(libc::STDERR_FILENO, message);
}

pub(crate) fn strerror(status: i32) -> Vec<u8> {
    // SAFETY: strerror returns a process-global NUL-terminated message. The agent is
    // single-threaded, and this copies it before another call can reuse the buffer.
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(status)) }
        .to_bytes()
        .to_vec()
}

pub(crate) fn c_string(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

pub(crate) fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

pub(crate) fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub(crate) fn read_exact(fd: libc::c_int, mut output: &mut [u8]) -> io::Result<()> {
    while !output.is_empty() {
        // SAFETY: `output` is writable for its reported length.
        let count = unsafe { libc::read(fd, output.as_mut_ptr().cast(), output.len()) };
        if count > 0 {
            output = &mut output[count as usize..];
        } else if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    Ok(())
}

pub(crate) fn write_all(fd: libc::c_int, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        // SAFETY: `input` is readable for its reported length.
        let count = unsafe { libc::write(fd, input.as_ptr().cast(), input.len()) };
        if count > 0 {
            input = &input[count as usize..];
        } else {
            let error = if count == 0 {
                io::ErrorKind::WriteZero.into()
            } else {
                io::Error::last_os_error()
            };
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    Ok(())
}

pub(crate) fn close(fd: libc::c_int) {
    if fd >= 0 {
        // SAFETY: callers relinquish the descriptor and never use it again.
        unsafe { libc::close(fd) };
    }
}
