//! The kernel interfaces of the root operations, which tests replace.
//!
//! The operations read the kernel's text files and walk directories through the standard
//! library, at the paths of a [`Paths`], so that a test relocates them to a temporary directory.
//! What a test cannot do in a temporary directory, such as a mount, an unmount, or a flush of a
//! block device's buffers, and the writes to the kernel's control files and the check for a
//! mount point, whose effects and answers a test simulates, go through a [`Kernel`].

use std::ffi::CStr;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::guest::sys::{self, Errno, Mode, MountFlags, OpenFlags};

/// The kernel's operations that the root operations perform, other than reads: mounts and
/// unmounts, flushes of a block device's buffers, writes of a control file, and the sleeps
/// between two polls for a block device; and the check for a mount point, which depends on them.
///
/// [`SystemKernel`] performs them. The tests' fake records the operations, simulates the effect
/// of a cgroup's membership file and its own mounts, and fails the operations that a test
/// chooses.
pub(super) trait Kernel: Send + Sync {
    /// Mounts `source` at `target`, as `mount(2)` does, with the file system's own options
    /// `data`.
    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: MountFlags,
        data: Option<&CStr>,
    ) -> Result<(), Errno>;

    /// Unmounts the file system mounted at `target`, without detaching a busy one.
    fn unmount(&mut self, target: &CStr) -> Result<(), Errno>;

    /// Writes the dirty buffers of the block device `device`, then drops its cached ones.
    fn flush(&mut self, device: &CStr) -> Result<(), Errno>;

    /// Writes `value` whole to the existing control file `path`, such as a cgroup's or a
    /// sysctl's, and reports a failure to close it.
    fn write(&mut self, path: &CStr, value: &[u8]) -> Result<(), Errno>;

    /// Returns whether a file system other than its parent directory's is mounted at the
    /// directory `path`.
    fn is_mount_point(&mut self, path: &Path) -> io::Result<bool>;

    /// Sleeps for `duration`.
    fn sleep(&mut self, duration: Duration);
}

/// The kernel itself.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SystemKernel;

impl Kernel for SystemKernel {
    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: MountFlags,
        data: Option<&CStr>,
    ) -> Result<(), Errno> {
        sys::mount_with_options(source, target, filesystem, flags, data)
    }

    fn unmount(&mut self, target: &CStr) -> Result<(), Errno> {
        sys::unmount(target)
    }

    fn flush(&mut self, device: &CStr) -> Result<(), Errno> {
        let descriptor = sys::open(
            device,
            OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
            Mode::empty(),
        )?;
        sys::flush_block_buffers(&descriptor)?;
        descriptor.close()
    }

    fn write(&mut self, path: &CStr, value: &[u8]) -> Result<(), Errno> {
        let descriptor = sys::open(
            path,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
            Mode::empty(),
        )?;
        descriptor.write_all(value)?;
        descriptor.close()
    }

    fn is_mount_point(&mut self, path: &Path) -> io::Result<bool> {
        let parent = path.parent().ok_or(Errno::EINVAL)?;
        Ok(fs::metadata(path)?.dev() != fs::metadata(parent)?.dev())
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// The directories of the kernel's interfaces that the root operations read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Paths {
    /// The mount point of procfs.
    pub(super) proc: PathBuf,
    /// The mount point of sysfs.
    pub(super) sys: PathBuf,
    /// The directory of the device nodes.
    pub(super) dev: PathBuf,
}

impl Default for Paths {
    /// Returns the paths at which the guest mounts the kernel's interfaces.
    fn default() -> Self {
        Self {
            proc: "/proc".into(),
            sys: "/sys".into(),
            dev: "/dev".into(),
        }
    }
}

#[cfg(test)]
pub(super) use fake::{Call, FakeKernel, Operation};

/// The tests' kernel, which records each operation and performs none.
#[cfg(test)]
mod fake {
    use std::ffi::CStr;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use super::Kernel;
    use crate::guest::sys::{Errno, MountFlags};

    /// An operation of the kernel, which a test fails.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::guest::root) enum Operation {
        /// A mount, other than a remount, which its target names.
        Mount,
        /// A remount, which its target names.
        Remount,
        /// An unmount, which its target names.
        Unmount,
        /// A flush of a block device's buffers, which the device names.
        Flush,
        /// A write of a control file, which its path names.
        Write,
    }

    /// One operation that the fake kernel recorded, with its paths and options as text.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(in crate::guest::root) enum Call {
        /// A mount.
        Mount {
            /// The source, if any.
            source: Option<String>,
            /// The target.
            target: String,
            /// The file system type, if any.
            filesystem: Option<String>,
            /// The flags.
            flags: MountFlags,
            /// The file system's own options, if any.
            data: Option<String>,
        },
        /// An unmount of a target.
        Unmount(String),
        /// A flush of a block device's buffers.
        Flush(String),
        /// A write of a value to a control file.
        Write(String, String),
    }

    /// The type of the action that runs after each sleep.
    type SleepAction = Box<dyn FnMut(usize) + Send>;

    /// What the fake kernel recorded and what it fails.
    #[derive(Default)]
    struct State {
        /// The operations, in order.
        calls: Vec<Call>,
        /// The operations that fail, with their error, each at the path that names it.
        failures: Vec<(Operation, PathBuf, Errno)>,
        /// The processes that writes of their ID to a membership file leave where they are, each
        /// with the number of such writes left.
        unmovable: Vec<(u32, usize)>,
        /// The targets of the mounts that no unmount has undone, in mount order.
        mounted: Vec<PathBuf>,
        /// The sleeps so far.
        sleeps: usize,
        /// What happens after each sleep, given the number of sleeps so far.
        on_sleep: Option<SleepAction>,
    }

    /// A kernel that records each operation, performs no mount, unmount, or flush, and fails the
    /// operations that a test chooses.
    ///
    /// A write of a control file writes the regular file at its path, which it creates if
    /// needed, except that a write of a process ID to a cgroup's `cgroup.procs` moves the ID
    /// there from the `cgroup.procs` of the cgroup's parent, as the kernel moves the process.
    /// The mount points that it reports are the targets of its mounts, other than remounts, that
    /// no unmount has undone. Its clones share what they record, so a test keeps one while a
    /// root owns another.
    #[derive(Clone, Default)]
    pub(in crate::guest::root) struct FakeKernel(Arc<Mutex<State>>);

    impl FakeKernel {
        /// Runs `action` on the shared state.
        fn with<T>(&self, action: impl FnOnce(&mut State) -> T) -> T {
            action(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
        }

        /// Makes the operations of kind `operation` at `path` fail with `error`.
        pub(in crate::guest::root) fn fail(
            &self,
            operation: Operation,
            path: impl Into<PathBuf>,
            error: Errno,
        ) {
            self.with(|state| state.failures.push((operation, path.into(), error)));
        }

        /// Makes the next `writes` writes of the ID `process` to a membership file leave the
        /// process where it is, as for a process that reappears as fast as it is moved.
        pub(in crate::guest::root) fn pin(&self, process: u32, writes: usize) {
            self.with(|state| state.unmovable.push((process, writes)));
        }

        /// Runs `action` after each sleep, with the number of sleeps so far.
        pub(in crate::guest::root) fn on_sleep(&self, action: impl FnMut(usize) + Send + 'static) {
            self.with(|state| state.on_sleep = Some(Box::new(action)));
        }

        /// Returns the operations so far, in order.
        pub(in crate::guest::root) fn calls(&self) -> Vec<Call> {
            self.with(|state| state.calls.clone())
        }

        /// Returns the targets of the unmounts so far, in order.
        pub(in crate::guest::root) fn unmounts(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    Call::Unmount(target) => Some(target),
                    _ => None,
                })
                .collect()
        }

        /// Returns the targets of the mounts so far, in order.
        pub(in crate::guest::root) fn mounts(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    Call::Mount { target, .. } => Some(target),
                    _ => None,
                })
                .collect()
        }

        /// Returns the paths and values of the writes so far, in order.
        pub(in crate::guest::root) fn writes(&self) -> Vec<(String, String)> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    Call::Write(path, value) => Some((path, value)),
                    _ => None,
                })
                .collect()
        }

        /// Returns the number of sleeps so far.
        pub(in crate::guest::root) fn sleeps(&self) -> usize {
            self.with(|state| state.sleeps)
        }

        /// Records `call`, and returns the error of the failure of `operation` at `path`, if a
        /// test chose one.
        fn record(&self, call: Call, operation: Operation, path: &CStr) -> Result<(), Errno> {
            let path = text(path);
            self.with(|state| {
                state.calls.push(call);
                state
                    .failures
                    .iter()
                    .find(|(failing, failing_path, _)| {
                        *failing == operation && failing_path.as_os_str() == path.as_str()
                    })
                    .map_or(Ok(()), |&(_, _, error)| Err(error))
            })
        }
    }

    /// Returns `text` as a `String`, replacing what is not UTF-8.
    fn text(text: &CStr) -> String {
        text.to_string_lossy().into_owned()
    }

    /// Moves the ID `process` into the membership file `path`, from that of the parent of
    /// `path`'s cgroup.
    fn move_process(path: &Path, process: u32) -> Result<(), Errno> {
        let source = path
            .parent()
            .and_then(Path::parent)
            .map(|parent| parent.join("cgroup.procs"))
            .ok_or(Errno::EINVAL)?;
        let listed = std::fs::read_to_string(&source).map_err(|_| Errno::ENOENT)?;
        let line = process.to_string();
        let remaining: String = listed
            .lines()
            .filter(|listed| *listed != line)
            .map(|listed| format!("{listed}\n"))
            .collect();
        std::fs::write(&source, remaining).map_err(|_| Errno::EIO)?;
        let mut members = std::fs::read_to_string(path).unwrap_or_default();
        members.push_str(&format!("{process}\n"));
        std::fs::write(path, members).map_err(|_| Errno::EIO)
    }

    impl Kernel for FakeKernel {
        fn mount(
            &mut self,
            source: Option<&CStr>,
            target: &CStr,
            filesystem: Option<&CStr>,
            flags: MountFlags,
            data: Option<&CStr>,
        ) -> Result<(), Errno> {
            let call = Call::Mount {
                source: source.map(text),
                target: text(target),
                filesystem: filesystem.map(text),
                flags,
                data: data.map(text),
            };
            let operation = if flags.contains(MountFlags::MS_REMOUNT) {
                Operation::Remount
            } else {
                Operation::Mount
            };
            self.record(call, operation, target)?;
            if operation == Operation::Mount {
                self.with(|state| state.mounted.push(PathBuf::from(text(target))));
            }
            Ok(())
        }

        fn unmount(&mut self, target: &CStr) -> Result<(), Errno> {
            self.record(Call::Unmount(text(target)), Operation::Unmount, target)?;
            let target = PathBuf::from(text(target));
            self.with(|state| {
                if let Some(last) = state.mounted.iter().rposition(|point| *point == target) {
                    state.mounted.remove(last);
                }
            });
            Ok(())
        }

        fn flush(&mut self, device: &CStr) -> Result<(), Errno> {
            self.record(Call::Flush(text(device)), Operation::Flush, device)
        }

        fn write(&mut self, path: &CStr, value: &[u8]) -> Result<(), Errno> {
            let call = Call::Write(text(path), String::from_utf8_lossy(value).into_owned());
            self.record(call, Operation::Write, path)?;
            let path = PathBuf::from(text(path));
            let process = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.trim_end().parse::<u32>().ok());
            match process {
                Some(process) if path.ends_with("cgroup.procs") => {
                    let pinned = self.with(|state| {
                        state
                            .unmovable
                            .iter_mut()
                            .find(|(pinned, writes)| *pinned == process && *writes > 0)
                            .map(|(_, writes)| *writes -= 1)
                            .is_some()
                    });
                    if pinned {
                        Ok(())
                    } else {
                        move_process(&path, process)
                    }
                }
                _ => std::fs::write(&path, value).map_err(|_| Errno::EIO),
            }
        }

        fn is_mount_point(&mut self, path: &Path) -> std::io::Result<bool> {
            Ok(self.with(|state| state.mounted.iter().any(|point| point == path)))
        }

        fn sleep(&mut self, _duration: Duration) {
            let (sleeps, mut action) = self.with(|state| {
                state.sleeps += 1;
                (state.sleeps, state.on_sleep.take())
            });
            if let Some(action) = action.as_mut() {
                action(sleeps);
            }
            self.with(|state| {
                if state.on_sleep.is_none() {
                    state.on_sleep = action;
                }
            });
        }
    }
}
