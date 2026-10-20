//! Signal dispositions, masks, descriptors, and queued signals.

use std::os::fd::{AsFd, BorrowedFd};
use std::time::Duration;

use nix::sys::signal::{SigHandler, SigSet, SigmaskHow, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};

use super::{Errno, Pollable, ProcessId, poll};

/// One signal read from a [`SignalDescriptor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignalEvent {
    /// The signal, or `None` for a number that `Signal` cannot represent, such as a real-time
    /// signal.
    pub(crate) signal: Option<Signal>,
    /// Whether `sigqueue` sent the signal, with [`value`](Self::value).
    pub(crate) queued: bool,
    /// The integer that `sigqueue` sent with the signal, in its low 32 bits.
    pub(crate) value: u32,
}

/// Opens a close-on-exec, nonblocking signal descriptor that reads `mask`'s signals.
fn signal_descriptor(mask: &SigSet) -> Result<SignalFd, Errno> {
    SignalFd::with_flags(mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
}

/// An owned signal descriptor that reads signals that the calling thread blocks. Dropping it
/// closes the descriptor, and leaves the signals blocked.
#[derive(Debug)]
pub(crate) struct SignalDescriptor(SignalFd);

impl SignalDescriptor {
    /// Blocks `signals` in the calling thread, and opens a descriptor that reads them.
    ///
    /// A process that blocks signals before it starts threads blocks them in every thread.
    pub(crate) fn new(signals: &[Signal]) -> Result<Self, Errno> {
        let mask = signals.iter().copied().collect::<SigSet>();
        mask.thread_block()?;
        signal_descriptor(&mask).map(Self)
    }

    /// Reads one pending signal, or returns `None` when no signal is pending.
    pub(crate) fn read(&self) -> Option<SignalEvent> {
        let information = self.0.read_signal().ok()??;
        Some(SignalEvent {
            signal: Signal::try_from(information.ssi_signo as i32).ok(),
            queued: information.ssi_code == nix::libc::SI_QUEUE,
            value: information.ssi_int as u32,
        })
    }

    /// Borrows the descriptor for `poll` in this module tree.
    pub(super) fn borrowed(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Ignores each of `signals` for the rest of the process.
///
/// Like the C programs, it ignores failures, which `signal` reports only for an invalid signal.
pub(crate) fn ignore_signals(signals: &[Signal]) {
    for &signal in signals {
        // SAFETY: `SIG_IGN` installs no Rust callback.
        let _ = unsafe { nix::sys::signal::signal(signal, SigHandler::SigIgn) };
    }
}

/// Restores the default `SIGCHLD` disposition, which an inherited `SIG_IGN` would replace with
/// the kernel's automatic reaping of children, before any `wait` sees them.
pub(crate) fn reset_child_signal() {
    // SAFETY: `SIG_DFL` installs no Rust callback.
    let _ = unsafe { nix::sys::signal::signal(Signal::SIGCHLD, SigHandler::SigDfl) };
}

/// Makes the kernel reap the calling process's children on its own, which the `SIG_IGN`
/// disposition of `SIGCHLD` does when `ignored`, and `SA_NOCLDWAIT` with the default action
/// does otherwise. [`reset_child_signal`] undoes either.
#[cfg(test)]
pub(crate) fn reap_children_automatically(ignored: bool) -> Result<(), Errno> {
    use nix::sys::signal::{SaFlags, SigAction};

    let action = if ignored {
        SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty())
    } else {
        SigAction::new(SigHandler::SigDfl, SaFlags::SA_NOCLDWAIT, SigSet::empty())
    };
    // SAFETY: neither action installs a Rust callback.
    unsafe { nix::sys::signal::sigaction(Signal::SIGCHLD, &action) }.map(drop)
}

/// Returns whether the calling process has a child, which it has not reaped, without reaping
/// it, whatever its disposition of `SIGCHLD`.
#[cfg(test)]
pub(crate) fn has_child() -> bool {
    use nix::sys::wait::{Id, WaitPidFlag};

    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    nix::sys::wait::waitid(Id::All, flags) != Err(Errno::ECHILD)
}

/// Sends `SIGUSR1` to `process` with `value`, which a [`SignalEvent`] returns.
///
/// `nix` does not wrap `sigqueue`, so this calls it through libc.
pub(crate) fn queue_user_signal(process: ProcessId, value: u32) -> Result<(), Errno> {
    let value = nix::libc::sigval {
        sival_ptr: value as usize as *mut nix::libc::c_void,
    };
    // SAFETY: `sigqueue` passes the integer payload to the kernel and dereferences nothing.
    Errno::result(unsafe { nix::libc::sigqueue(process.raw(), Signal::SIGUSR1 as i32, value) })
        .map(drop)
}

/// A wait for `SIGCHLD`, which blocks the signal in the calling thread while it lives and reads
/// it from a signal descriptor. Dropping it closes the descriptor and restores the thread's
/// previous signal mask.
#[derive(Debug)]
pub(crate) struct ChildSignalWait {
    /// The thread's signal mask before the wait blocked `SIGCHLD`.
    previous: SigSet,
    /// The descriptor that reads `SIGCHLD`.
    descriptor: SignalFd,
}

impl ChildSignalWait {
    /// Blocks `SIGCHLD` in the calling thread before the caller forks the child that it waits
    /// for, so that the signal of a child that ends at once stays pending.
    pub(crate) fn new() -> Result<Self, Errno> {
        let mask = SigSet::from(Signal::SIGCHLD);
        let previous = mask.thread_swap_mask(SigmaskHow::SIG_BLOCK)?;
        match signal_descriptor(&mask) {
            Ok(descriptor) => Ok(Self {
                previous,
                descriptor,
            }),
            Err(error) => {
                let _ = previous.thread_set_mask();
                Err(error)
            }
        }
    }

    /// Waits at most `timeout` for `SIGCHLD`, and consumes every pending one.
    ///
    /// A signal that arrived earlier ends the wait at once. A failed poll ends it too, and the
    /// caller, which checks its child after each wait, treats it as a spurious wakeup.
    pub(crate) fn wait(&self, timeout: Duration) {
        let _ = poll([Pollable::ChildSignal(self)], Some(timeout));
        while let Ok(Some(_)) = self.descriptor.read_signal() {}
    }

    /// Restores the previous signal mask, as a forked child does before it runs, and reports a
    /// failure.
    pub(crate) fn restore(self) -> Result<(), Errno> {
        self.previous.thread_set_mask()
    }

    /// Borrows the descriptor for `poll` in this module tree.
    pub(super) fn borrowed(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl Drop for ChildSignalWait {
    /// Restores the previous signal mask, best effort, if `restore` has not.
    fn drop(&mut self) {
        let _ = self.previous.thread_set_mask();
    }
}

#[cfg(test)]
mod tests {
    //! Checks of signal descriptors in this test's thread.

    use std::time::Instant;

    use super::*;

    #[test]
    fn a_blocked_signal_reaches_the_descriptor() {
        let signals = SignalDescriptor::new(&[Signal::SIGUSR1]).unwrap();
        assert_eq!(signals.read(), None);
        // A signal to the whole test process could reach another test thread, which does not
        // block it, so this test raises it in its own thread.
        nix::sys::signal::raise(Signal::SIGUSR1).unwrap();
        assert_eq!(
            signals.read(),
            Some(SignalEvent {
                signal: Some(Signal::SIGUSR1),
                queued: false,
                value: 0,
            })
        );
        assert_eq!(signals.read(), None);
    }

    #[test]
    fn a_child_signal_wait_times_out_and_restores_the_mask() {
        let before = SigSet::thread_get_mask().unwrap();
        let wait = ChildSignalWait::new().unwrap();
        assert!(SigSet::thread_get_mask().unwrap().contains(Signal::SIGCHLD));
        let start = Instant::now();
        wait.wait(Duration::from_millis(5));
        assert!(start.elapsed() >= Duration::from_millis(5));
        wait.restore().unwrap();
        assert_eq!(
            SigSet::thread_get_mask().unwrap().contains(Signal::SIGCHLD),
            before.contains(Signal::SIGCHLD)
        );
    }
}
