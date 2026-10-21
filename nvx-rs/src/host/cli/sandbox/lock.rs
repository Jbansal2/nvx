//! The lifecycle lock of a state directory, which is the lock of the sandbox's
//! [`SandboxStore`]: its file `sandbox.lock`.
//!
//! - Provision, start, stop, and deprovision hold the lock for their whole transition, and exec
//!   while it finds the running VM. A caller that cannot take the lock retries every 25 ms
//!   within its timeout, and Ctrl-C ends the wait.
//! - The store takes the lock of the file that the path names when the lock is granted: a lock
//!   file that its holder removed meanwhile locks nothing, so the store takes the lock of the
//!   lock file at the path again, which it creates if needed.
//! - Deprovision removes the lock file before the directory. A transition that waited for it then
//!   finds the directory gone, or takes the lock of a new lock file in the directory and finds no
//!   sandbox there. Every transition that leaves the directory without a provisioned sandbox
//!   removes its lock file as it releases the lock, so that the directory empties.

use std::io;
use std::time::Instant;

use super::error_with_cause;
use super::lifecycle::{CONFIG_NAME, LOCK_RETRY_INTERVAL, create_state_directory};
use crate::ErrorKind;
use crate::host::cli::deadline::Deadline;
use crate::host::cli::{Exit, Result};
use crate::host::python::fs::{self, os_error_message};
use crate::host::python::path::PurePath;
use crate::host::store::{LOCK_NAME, LockedStore, SandboxStore};

/// How Python classifies an `OSError`, as far as the lifecycle tells the classes apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsErrorClass {
    /// `FileNotFoundError`: `ENOENT`.
    NotFound,
    /// `PermissionError`: `EACCES` or `EPERM`.
    PermissionDenied,
    /// Any other `OSError`.
    Other,
}

/// Returns the class of the `OSError` that Python raises for `error`. On Windows, Python maps the
/// Win32 error to an `errno` as `winerror_to_errno` does.
pub(crate) fn os_error_class(error: &io::Error) -> OsErrorClass {
    #[cfg(windows)]
    if let Some(code) = error.raw_os_error() {
        return match code {
            2 | 3 | 15 | 18 | 53 | 67 | 161 | 206 => OsErrorClass::NotFound,
            5 | 16 | 19..=36 | 65 | 82 | 83 | 108 | 132 | 158 | 167 => {
                OsErrorClass::PermissionDenied
            }
            _ => OsErrorClass::Other,
        };
    }
    match error.kind() {
        io::ErrorKind::NotFound => OsErrorClass::NotFound,
        io::ErrorKind::PermissionDenied => OsErrorClass::PermissionDenied,
        _ => OsErrorClass::Other,
    }
}

/// Returns the class of the I/O error that caused the store's `error`, if one did.
fn cause_class(error: &crate::Error) -> Option<OsErrorClass> {
    std::error::Error::source(error)?
        .downcast_ref::<io::Error>()
        .map(os_error_class)
}

/// Returns the error of a transition that still waits for another: Python's `TimeoutError`.
pub(crate) fn transition_in_progress() -> Exit {
    Exit::error("another lifecycle transition of the sandbox is still in progress")
}

/// Returns `os.lstat(path)`'s identity, or `None` if the path cannot be examined, as
/// `_directory_status` does.
pub(crate) fn directory_status(path: &PurePath) -> Option<(u64, u128)> {
    fs::lstat(path.as_path())
        .ok()
        .map(|status| status.identity())
}

/// Returns whether `name` is a removed lock file that a handle still keeps, as `_lingers` does:
/// NFS renames a removed file that is still open to `.nfs*`, and Windows file systems without
/// POSIX deletion keep it under its own name, as they keep the lock files that waiting
/// transitions create until they release them.
pub(crate) fn lingers(name: &str) -> bool {
    name == LOCK_NAME || name.starts_with(".nfs")
}

/// Returns whether `error` is how `rmdir` reports a directory that is not empty.
pub(crate) fn directory_not_empty(error: &io::Error) -> bool {
    #[cfg(windows)]
    let not_empty = matches!(error.raw_os_error(), Some(145 | 80 | 183));
    #[cfg(unix)]
    let not_empty = matches!(
        error.raw_os_error(),
        Some(code) if code == nix::errno::Errno::ENOTEMPTY as i32
            || code == nix::errno::Errno::EEXIST as i32
    );
    #[cfg(not(any(windows, unix)))]
    let not_empty = error.kind() == io::ErrorKind::DirectoryNotEmpty;
    not_empty
}

/// Returns the names of the entries of `directory`.
pub(crate) fn entries(directory: &PurePath) -> io::Result<Vec<String>> {
    std::fs::read_dir(directory.as_path())?
        .map(|entry| {
            let name = entry?.file_name();
            name.into_string()
                .map_err(|_| crate::host::python::not_unicode("a file name"))
        })
        .collect()
}

/// The exclusive lock that serializes the lifecycle transitions of a state directory: the lock
/// of its sandbox's store, through which the transition changes the store's records.
pub(crate) struct LifecycleLock {
    /// The state directory.
    state_dir: PurePath,
    /// The sandbox's locked store, until the lock is released.
    locked: Option<LockedStore>,
    /// Whether the holder removed its lock file, after which the path may name another's.
    removed: bool,
}

impl LifecycleLock {
    /// Takes the lock of `state_dir` within `timeout` seconds.
    ///
    /// The directory must be private to the current user, as the store requires of its
    /// directory. A provision whose directory deprovision removed meanwhile creates it again; any
    /// other transition then fails, as for a path that names no directory.
    pub(crate) fn acquire(state_dir: &PurePath, timeout: f64, provision: bool) -> Result<Self> {
        if !(timeout > 0.0 && timeout < f64::INFINITY) {
            return Err(Exit::error(
                "lifecycle timeout must be finite and greater than 0",
            ));
        }
        let deadline = Deadline::after(timeout);
        loop {
            let opened = if provision {
                SandboxStore::create(state_dir.as_path())
            } else {
                SandboxStore::open(state_dir.as_path())
            };
            // The store tries the lock once for a deadline that has passed, so that this wait
            // checks for Ctrl-C between tries.
            let error = match opened.and_then(|store| store.lock(Some(Instant::now()))) {
                Ok(locked) => {
                    return Ok(Self {
                        state_dir: state_dir.clone(),
                        locked: Some(locked),
                        removed: false,
                    });
                }
                Err(error) => error,
            };
            match (error.kind(), cause_class(&error)) {
                (ErrorKind::TimedOut, _) => {}
                // Deprovision removed the state directory meanwhile, which only a provision
                // creates again.
                (_, Some(OsErrorClass::NotFound)) if !provision => {
                    return Err(Exit::error(format!(
                        "sandbox state path is not a plain directory: {state_dir}"
                    )));
                }
                (_, Some(OsErrorClass::NotFound)) => {
                    if deadline.passed() {
                        return Err(transition_in_progress());
                    }
                    create_state_directory(state_dir)?;
                    continue;
                }
                // Without POSIX deletion, Windows denies opening a removed lock file until its
                // last handle closes.
                (_, Some(OsErrorClass::PermissionDenied)) if provision && cfg!(windows) => {}
                _ => return Err(error_with_cause(error)),
            }
            if !deadline.pause(LOCK_RETRY_INTERVAL)? {
                return Err(transition_in_progress());
            }
        }
    }

    /// Returns the sandbox's locked store.
    pub(crate) fn locked(&mut self) -> &mut LockedStore {
        self.locked.as_mut().expect("the lock is held")
    }

    /// Removes the held lock file, as deprovision does before it removes the directory.
    pub(crate) fn remove(&mut self) -> Result {
        let path = self.state_dir.join(LOCK_NAME);
        std::fs::remove_file(path.as_path())
            .map_err(|error| Exit::error(os_error_message(&error, Some(path.as_str()))))?;
        self.removed = true;
        Ok(())
    }

    /// Releases the lock. The lock file of a directory that holds no provisioned sandbox goes
    /// first, unless the holder removed it already, so that the directory can be removed.
    pub(crate) fn release(&mut self) {
        let Some(locked) = self.locked.take() else {
            return;
        };
        if !self.removed && !fs::lexists(self.state_dir.join(CONFIG_NAME).as_path()) {
            let _ = std::fs::remove_file(self.state_dir.join(LOCK_NAME).as_path());
        }
        drop(locked);
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_dir(directory: &tempfile::TempDir) -> PurePath {
        let state = directory.path().join("state");
        SandboxStore::create(&state).unwrap();
        PurePath::native(state.to_str().unwrap())
    }

    #[test]
    fn the_lock_excludes_other_holders_until_released() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_dir(&directory);
        std::fs::write(state.join(CONFIG_NAME).as_path(), "{}").unwrap();
        let mut held = LifecycleLock::acquire(&state, 10.0, false).unwrap();
        let started = std::time::Instant::now();
        let error = LifecycleLock::acquire(&state, 0.1, false).err().unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(100));
        assert_eq!(
            error.message(),
            Some("another lifecycle transition of the sandbox is still in progress")
        );
        held.release();
        drop(LifecycleLock::acquire(&state, 10.0, false).unwrap());
        // A provisioned directory keeps its lock file.
        assert!(state.join(LOCK_NAME).as_path().is_file());
    }

    #[test]
    fn released_locks_leave_no_file_in_unprovisioned_directories() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_dir(&directory);
        drop(LifecycleLock::acquire(&state, 10.0, true).unwrap());
        assert!(!state.join(LOCK_NAME).as_path().exists());
        let missing = state.join("missing");
        let error = LifecycleLock::acquire(&missing, 1.0, false).err().unwrap();
        assert_eq!(
            error.message().unwrap(),
            format!("sandbox state path is not a plain directory: {missing}")
        );
        // A provision creates the directory that deprovision removed meanwhile.
        drop(LifecycleLock::acquire(&missing, 1.0, true).unwrap());
        assert!(missing.as_path().is_dir());
    }

    #[test]
    fn a_removed_lock_file_is_not_removed_again_on_release() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_dir(&directory);
        let mut lock = LifecycleLock::acquire(&state, 10.0, true).unwrap();
        lock.remove().unwrap();
        assert!(!state.join(LOCK_NAME).as_path().exists());
        // A transition that waited takes the lock of a new lock file, which stays its own.
        let other = LifecycleLock::acquire(&state, 1.0, true).unwrap();
        lock.release();
        assert!(state.join(LOCK_NAME).as_path().is_file());
        drop(other);
        assert!(!state.join(LOCK_NAME).as_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn directories_that_others_may_access_are_refused() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let state = state_dir(&directory);
        std::fs::set_permissions(state.as_path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = LifecycleLock::acquire(&state, 1.0, false).err().unwrap();
        assert_eq!(
            error.message().unwrap(),
            format!("the sandbox store {state} is accessible to other users (mode 755)")
        );
    }
}
