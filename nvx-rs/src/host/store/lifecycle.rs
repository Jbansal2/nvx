//! The lifecycle of a sandbox's store beside its caller's files: the locks of a provision and of an
//! existing sandbox, the release of a lock in a directory that holds no provisioned sandbox, and
//! the removal of the store and its directory. The [module documentation](super#lifecycle-locks)
//! describes their rules.

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use super::caller::{is_report_staging, is_store_temporary};
use super::{
    CallerFiles, FILE_NAMES, JOURNAL_NAME, LOCK_NAME, LOCK_RETRY_INTERVAL, LockedStore,
    RUNTIME_NAME, SandboxStore, Taken, absolute,
};
use crate::error::{Error, ErrorKind, Result};
use crate::host::platform;
use crate::host::python::fs::lstat;
use crate::host::python::not_unicode;

#[cfg(test)]
mod tests;

impl SandboxStore {
    /// Takes the lock of the sandbox in `dir` for its provision, by a caller that keeps `files`
    /// in the directory, waiting for it until `deadline`, or for as long as it takes without one.
    ///
    /// The directory, whose parent must exist, is created if needed, private to the current user,
    /// as [`create`](Self::create) creates it, and created again if a concurrent removal deletes
    /// it before the lock is taken. The caller checks under the lock whether its configuration
    /// record exists already, and writes it.
    ///
    /// Fails with [`ErrorKind::TimedOut`] when the deadline passes first, also while Windows
    /// refuses to open a removed lock file, as [`lock_existing`](Self::lock_existing) describes,
    /// with [`ErrorKind::NotFound`] if the parent does not exist, and as [`create`](Self::create)
    /// fails for a directory that is not private.
    pub fn lock_for_provision(
        dir: impl Into<PathBuf>,
        files: &CallerFiles,
        deadline: Option<Instant>,
    ) -> Result<LockedStore> {
        let dir = absolute(dir.into())?;
        loop {
            let store = Self::create(dir.clone())?;
            match store.take_lifecycle_lock(deadline) {
                Ok(Taken::Locked(lock)) => {
                    return Ok(LockedStore::new(store, lock, files.clone()));
                }
                // A removal deleted the lock file, and maybe the directory, while this waited, or
                // the directory after it was created: it is created and locked again.
                Ok(Taken::Replaced) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Takes the lock of the existing sandbox in `dir`, by a caller that keeps `files` in the
    /// directory, waiting for it until `deadline`, or for as long as it takes without one.
    ///
    /// Fails with [`ErrorKind::NotFound`] if the directory does not exist, also once a concurrent
    /// removal deletes it while this waits: a lock file that is removed or replaced meanwhile
    /// locks nothing, so the lock of the lock file at the path is taken again, as
    /// [`lock`](Self::lock) does, which fails once the directory is gone. A directory that exists
    /// is locked even if it holds no provisioned sandbox, as one that was never provisioned, or
    /// that an interrupted removal emptied, or whose removal lingering lock files still keep: the
    /// caller checks its configuration record under the lock, and the release then removes the
    /// lock file again.
    ///
    /// On Windows, a file system without POSIX deletion keeps a removed lock file under its name
    /// until its last handle closes, and refuses to open it until then, so the open is tried
    /// again every 25 ms. Fails with [`ErrorKind::TimedOut`] when the deadline passes first, as
    /// [`lock`](Self::lock) does.
    pub fn lock_existing(
        dir: impl Into<PathBuf>,
        files: &CallerFiles,
        deadline: Option<Instant>,
    ) -> Result<LockedStore> {
        let store = Self::open(dir)?;
        loop {
            if let Taken::Locked(lock) = store.take_lifecycle_lock(deadline)? {
                return Ok(LockedStore::new(store, lock, files.clone()));
            }
        }
    }

    /// Takes the lock as [`take_lock`](Self::take_lock) does, and opens a lock file that Windows
    /// refuses to open again every 25 ms until `deadline`, as a removed one that other handles
    /// still hold, which a file system without POSIX deletion keeps until they close.
    fn take_lifecycle_lock(&self, deadline: Option<Instant>) -> Result<Taken> {
        loop {
            match self.take_lock(deadline) {
                Err(error) if cfg!(windows) && denied(&error) => {
                    if !pause(deadline) {
                        return Err(self.transition_in_progress());
                    }
                }
                taken => return taken,
            }
        }
    }
}

/// Returns whether the store's `error` is an I/O error whose cause is a denied access.
fn denied(error: &Error) -> bool {
    error.kind() == ErrorKind::Io
        && std::error::Error::source(error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some_and(|source| source.kind() == io::ErrorKind::PermissionDenied)
}

/// Waits before the next try of a step that `deadline` bounds: returns `false` at once if the
/// deadline has passed, and otherwise sleeps for [`LOCK_RETRY_INTERVAL`] or the time left,
/// whichever is shorter, and returns `true`.
fn pause(deadline: Option<Instant>) -> bool {
    let left = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
    if left.is_some_and(|left| left.is_zero()) {
        return false;
    }
    thread::sleep(left.map_or(LOCK_RETRY_INTERVAL, |left| left.min(LOCK_RETRY_INTERVAL)));
    true
}

impl Drop for LockedStore {
    /// Releases the lock. A holder that leaves the directory without its caller's configuration
    /// record removes its own lock file first, unless it removed it already, so that a directory
    /// that holds no provisioned sandbox keeps no lock file, and empties.
    fn drop(&mut self) {
        let Some(config) = self.files.config() else {
            return;
        };
        if self.lock_removed
            || !matches!(
                fs::symlink_metadata(self.path(config)),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            )
        {
            return;
        }
        let path = self.path(LOCK_NAME);
        let held = platform::opened_file_identity(&self.lock);
        if matches!((held, platform::file_identity(&path)), (Ok(held), Ok(current)) if held == current)
        {
            let _ = fs::remove_file(&path);
        }
    }
}

impl LockedStore {
    /// Removes the sandbox's store, its caller's files, and its directory, which only a sandbox
    /// that no VMM can run in allows, and releases the lock.
    ///
    /// The removal refuses, and removes nothing, while the store records a VM or a launch: the
    /// caller reattaches to the VM and stops it, or recovers the launch, first, as
    /// [`supervisor::reattach`](crate::host::supervisor::reattach) does. It then removes the
    /// store's files but its lock, the caller's files, its configuration record last, so that an
    /// interrupted removal leaves a provisioned sandbox, which can be removed again, and the
    /// temporary files that the store owns. It refuses the entries that are neither the store's
    /// nor the caller's, which it names in the order in which the directory lists them, and keeps
    /// them and the directory; the lock file goes as the lock is released, since the configuration
    /// record is gone. Otherwise it removes its lock file while it still holds the lock, so that a
    /// transition that waited for the lock finds the sandbox gone rather than halfway removed, and
    /// then the directory.
    ///
    /// Lock files of other transitions can keep the emptied directory: on NFS, a removed lock file
    /// that a handle still holds is renamed to `.nfs*`; a Windows file system without POSIX
    /// deletion keeps one under its own name until its last handle closes; and a transition that
    /// opens the lock file between the removals of the lock file and of the directory creates a
    /// new one. Each of those transitions finds no sandbox, and removes its lock file as it
    /// releases its lock, so the directory empties. The removal then holds the directory's
    /// identity, releases the lock, and returns the [`Lingering`] removal, whose
    /// [`wait`](Lingering::wait) removes the directory once it empties. It returns `None` once the
    /// directory is gone.
    pub fn remove(self) -> std::result::Result<Option<Lingering>, RemovalError> {
        self.remove_contents()?;
        self.remove_directory()
    }

    /// Empties the directory but for the lock file, as [`remove`](Self::remove) does first: it
    /// refuses while the store records a VM or a launch, removes the store's files and the
    /// caller's, and the temporary files that the store owns, and refuses any other entry.
    fn remove_contents(&self) -> std::result::Result<(), RemovalError> {
        for name in [JOURNAL_NAME, RUNTIME_NAME] {
            let path = self.path(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => return Err(RemovalError::Launched),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(RemovalError::Io { path, error }),
            }
        }
        let owned: Vec<PathBuf> = FILE_NAMES
            .into_iter()
            .filter(|&name| name != LOCK_NAME)
            .chain(self.files.names())
            .map(|name| self.path(name))
            .collect();
        for path in owned {
            remove_entry(path)?;
        }
        let listed = entries(self.dir()).map_err(|error| RemovalError::Io {
            path: self.dir().to_owned(),
            error,
        })?;
        let mut foreign = Vec::new();
        for name in listed {
            if name == LOCK_NAME {
                continue;
            }
            if is_store_temporary(&name) || is_report_staging(&name) {
                remove_entry(self.path(&name))?;
            } else {
                foreign.push(name);
            }
        }
        if foreign.is_empty() {
            Ok(())
        } else {
            Err(RemovalError::Foreign(foreign))
        }
    }

    /// Removes the lock file while it still holds the lock, and then the directory, as
    /// [`remove`](Self::remove) does once the directory holds nothing else of the sandbox.
    fn remove_directory(mut self) -> std::result::Result<Option<Lingering>, RemovalError> {
        let dir = self.dir().to_owned();
        let lock = self.path(LOCK_NAME);
        fs::remove_file(&lock).map_err(|error| RemovalError::Io { path: lock, error })?;
        self.lock_removed = true;
        match fs::remove_dir(&dir) {
            Ok(()) => return Ok(None),
            Err(error) if directory_not_empty(&error) => {}
            Err(error) => return Err(RemovalError::Io { path: dir, error }),
        }
        let (identity, held) = hold_directory(&dir).map_err(|error| RemovalError::Io {
            path: dir.clone(),
            error,
        })?;
        let config = self.files.config().map(str::to_owned);
        drop(self);
        Ok(Some(Lingering {
            dir,
            identity,
            _held: held,
            config,
            retried_at_once: false,
        }))
    }
}

/// The removal of a sandbox's directory that lock files of other transitions keep, which
/// [`LockedStore::remove`] returns once it has removed everything else and released the lock.
///
/// It holds the identity of the directory that it removes: on Unix, its open handle keeps a
/// directory that replaces it from reusing its inode number, and NTFS and ReFS do not reuse file
/// IDs. The path may name another directory once this one is gone, such as one that a provision
/// created again, which is not this removal's to remove.
#[derive(Debug)]
pub struct Lingering {
    /// The directory.
    dir: PathBuf,
    /// The identity of the directory, which `lstat` gives.
    identity: (u64, u128),
    /// The open directory on Unix, which keeps its identity.
    _held: Option<File>,
    /// The caller's configuration record, which a provision of the path writes.
    config: Option<String>,
    /// Whether the latest attempt was the one that followed at once a failure without remaining
    /// entries.
    retried_at_once: bool,
}

impl Lingering {
    /// Returns the directory that the removal waits for.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Removes the directory once lingering lock files no longer keep it, trying again every 25
    /// ms until `deadline`, or for as long as it takes without one. A deadline that has passed
    /// still tries once, so a caller that waits on its own, as for an interruption, calls this
    /// again, and a removal that timed out can go on.
    ///
    /// Returns once the directory is gone, whoever removed it, or once the path names another
    /// directory. Fails, and keeps the directory, with [`RemovalError::ProvisionedAgain`] once
    /// the caller's configuration record appears in it, as a provision that took the lock after
    /// the removal released it writes it, with [`RemovalError::Foreign`] for other entries that
    /// are not lingering lock files, sorted, and with [`RemovalError::TimedOut`] once the deadline
    /// passes.
    pub fn wait(&mut self, deadline: Option<Instant>) -> std::result::Result<(), RemovalError> {
        loop {
            let error = match fs::remove_dir(&self.dir) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => error,
            };
            if directory_status(&self.dir) != Some(self.identity) {
                return Ok(());
            }
            let remaining = match entries(&self.dir) {
                Ok(remaining) => remaining,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(RemovalError::Io {
                        path: self.dir.clone(),
                        error,
                    });
                }
            };
            let mut unexpected: Vec<String> = remaining
                .iter()
                .filter(|name| !lingers(name))
                .cloned()
                .collect();
            unexpected.sort();
            // A provision that took the lock after the removal released it, before the directory
            // went, provisions the directory again.
            if self
                .config
                .as_ref()
                .is_some_and(|config| unexpected.contains(config))
            {
                return Err(RemovalError::ProvisionedAgain);
            }
            if !unexpected.is_empty() {
                return Err(RemovalError::Foreign(unexpected));
            }
            if !directory_not_empty(&error) {
                return Err(RemovalError::Io {
                    path: self.dir.clone(),
                    error,
                });
            }
            // Without remaining entries, the last lingering lock file went away after the removal
            // failed, so the next attempt follows at once. Another such failure right after it
            // pauses first, so that a file system that does not report emptiness right away
            // cannot spin.
            if remaining.is_empty() && !self.retried_at_once {
                self.retried_at_once = true;
                continue;
            }
            self.retried_at_once = false;
            if !pause(deadline) {
                return Err(RemovalError::TimedOut(error));
            }
        }
    }
}

/// Why [`LockedStore::remove`] or [`Lingering::wait`] kept a sandbox's directory.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemovalError {
    /// The store records a VM or a launch, so a VMM of the sandbox may still run, and nothing was
    /// removed.
    Launched,
    /// The directory holds entries that are neither the store's nor its caller's, which the
    /// removal keeps, with the directory: their names, in the order in which the directory lists
    /// them, or sorted once the removal waited for lingering lock files.
    Foreign(Vec<String>),
    /// The sandbox was provisioned again while the removal waited for lingering lock files: the
    /// caller's configuration record appeared in the directory, which the removal keeps.
    ProvisionedAgain,
    /// Lingering lock files still kept the directory when the deadline passed: the error with
    /// which the latest attempt to remove it failed.
    TimedOut(io::Error),
    /// An operation on one of the sandbox's files, or on its directory, failed.
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The error of the operation.
        error: io::Error,
    },
}

impl fmt::Display for RemovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launched => {
                formatter.write_str("the sandbox's store records a VM or a launch, which may run")
            }
            Self::Foreign(names) => write!(
                formatter,
                "the sandbox's directory holds entries that are neither the store's nor its \
                 caller's: {}",
                names.join(", ")
            ),
            Self::ProvisionedAgain => formatter
                .write_str("the sandbox was provisioned again while its directory was removed"),
            Self::TimedOut(_) => formatter
                .write_str("lock files of other transitions still keep the sandbox's directory"),
            Self::Io { path, .. } => write!(formatter, "cannot remove {}", path.display()),
        }
    }
}

impl std::error::Error for RemovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TimedOut(error) | Self::Io { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Keeps the message of a removal's error, and its I/O cause: a timeout is of
/// [`ErrorKind::TimedOut`], an I/O failure of [`ErrorKind::Io`], and every other refusal of
/// [`ErrorKind::Other`].
impl From<RemovalError> for Error {
    fn from(error: RemovalError) -> Self {
        let message = error.to_string();
        match error {
            RemovalError::TimedOut(source) => Error::timed_out(message).with_source(source),
            RemovalError::Io { error: source, .. } => Error::io(message).with_source(source),
            _ => Error::other(message),
        }
    }
}

/// Removes the file at `path` if it exists.
fn remove_entry(path: PathBuf) -> std::result::Result<(), RemovalError> {
    match fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(RemovalError::Io { path, error })
        }
        _ => Ok(()),
    }
}

/// Returns whether `name` is a removed lock file that a handle still keeps: NFS renames a removed
/// file that is still open to `.nfs*`, and Windows file systems without POSIX deletion keep it
/// under its own name, as they keep the lock files that waiting transitions create until they
/// release them.
fn lingers(name: &str) -> bool {
    name == LOCK_NAME || name.starts_with(".nfs")
}

/// Returns whether `error` is how the removal of a directory reports one that is not empty.
fn directory_not_empty(error: &io::Error) -> bool {
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

/// Returns the names of the entries of `directory`, in the order in which it lists them.
fn entries(directory: &Path) -> io::Result<Vec<String>> {
    fs::read_dir(directory)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| not_unicode("a file name"))
        })
        .collect()
}

/// Returns the identity of the directory `path`, as `lstat` gives it, and a handle that keeps it:
/// on Unix, the open directory keeps a directory that replaces it from reusing its inode number,
/// and NTFS and ReFS do not reuse file IDs.
fn hold_directory(path: &Path) -> io::Result<((u64, u128), Option<File>)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags((nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits())
            .open(path)?;
        // The open directory's status gives the identity that `lstat` gives for its path.
        let metadata = file.metadata()?;
        Ok(((metadata.dev(), u128::from(metadata.ino())), Some(file)))
    }
    #[cfg(not(unix))]
    {
        Ok((lstat(path)?.identity(), None))
    }
}

/// Returns the identity that `lstat` gives for `path`, or `None` if it cannot be examined.
fn directory_status(path: &Path) -> Option<(u64, u128)> {
    lstat(path).ok().map(|status| status.identity())
}
