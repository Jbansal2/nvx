use std::ffi::CStr;
use std::time::Duration;

use crate::guest::sys::{self, Errno, FileDescriptor, Mode, OpenFlags};

use super::seam::System;

/// Number of attempts allowed while the control terminal is still appearing.
const OPEN_ATTEMPTS: usize = 600;
/// Delay between retryable control-terminal open failures.
const OPEN_DELAY: Duration = Duration::from_millis(50);

/// Opens the control terminal, retrying transient boot-time failures.
pub(crate) fn open(path: &CStr) -> Result<FileDescriptor, Errno> {
    for attempt in 0..OPEN_ATTEMPTS {
        match sys::open(
            path,
            OpenFlags::O_RDWR | OpenFlags::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => return Ok(descriptor),
            Err(Errno::ENOENT | Errno::ENXIO | Errno::ENODEV | Errno::EIO) => {}
            Err(error) => return Err(error),
        }
        if attempt + 1 != OPEN_ATTEMPTS {
            std::thread::sleep(OPEN_DELAY);
        }
    }
    Err(Errno::ETIMEDOUT)
}

/// Applies raw local-terminal settings through the replaceable seam.
pub(crate) fn configure(
    system: &mut impl System,
    descriptor: &FileDescriptor,
) -> Result<(), Errno> {
    system.configure_tty(descriptor)
}

/// Best-effort drains queued control-terminal output.
pub(crate) fn drain(system: &mut impl System, descriptor: &FileDescriptor) {
    let _ = system.drain_tty(descriptor);
}
