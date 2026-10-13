use std::ffi::CStr;
use std::io;
use std::time::Duration;

use super::seam::System;

const OPEN_ATTEMPTS: usize = 600;
const OPEN_DELAY: Duration = Duration::from_millis(50);

pub(crate) fn open(path: &CStr) -> io::Result<libc::c_int> {
    for attempt in 0..OPEN_ATTEMPTS {
        // SAFETY: `path` is NUL-terminated and open takes no variadic mode without O_CREAT.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            return Ok(fd);
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOENT | libc::ENXIO | libc::ENODEV | libc::EIO)
        ) {
            return Err(error);
        }
        if attempt + 1 != OPEN_ATTEMPTS {
            std::thread::sleep(OPEN_DELAY);
        }
    }
    Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
}

pub(crate) fn configure(system: &mut impl System, fd: libc::c_int) -> io::Result<()> {
    system.configure_tty(fd)
}

pub(crate) fn drain(system: &mut impl System, fd: libc::c_int) {
    let _ = system.drain_tty(fd);
}

pub(crate) fn make_nonblocking(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: fcntl accepts any open descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the command consumes the integer flag value.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
