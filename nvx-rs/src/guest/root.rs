//! Operations that bootstrap a guest for a layered root, assemble the root, mount live shares in
//! it, and tear it down, for a guest init or agent, whether or not it is PID 1.
//!
//! - [`bootstrap`] prepares the guest once: it creates the agent's and the workload's sibling
//!   cgroups of a [`Layout`](super::cgroup::Layout), moves every process of their parent into the
//!   agent's, applies the agent's and the workload's resource values, and keeps user namespaces
//!   unavailable.
//! - [`assemble`] finds the block devices of an [`Assembly`] by their MMIO windows, checks and
//!   flushes them, and mounts the root: a read-only EROFS image, the `distro` layer, under an
//!   overlay whose upper and work directories are on an ext4 scratch, and which is mounted
//!   `nosuid,nodev`, as the scratch is. It returns the [`Root`] that owns the mounts and holds
//!   the [runtime directory](#runtime-directory).
//! - [`Root::mount_share`] and [`Root::mount_aggregate`] mount the VMM's live shares at targets in
//!   the root, after the checks that [live shares](#live-shares) lists.
//! - [`Root::teardown`] unmounts, in order, the live shares in reverse mount order, the overlay,
//!   the layer, and the scratch. It attempts each, whatever failed before, and reports every
//!   unmount that failed. A root that is dropped tears down the same way, but ignores failures.
//!
//! A failure is an [`Error`] that names what failed. The operations need the guest's root user,
//! in the guest's initial mount and cgroup namespaces. They never collect a child's status,
//! change the caller's root directory or credentials, start an async runtime, or power the VM
//! off, so a caller that is not PID 1 keeps its own reaping, transport, and shutdown.
//!
//! # Runtime directory
//!
//! The root's mounts are below a runtime directory that the caller chooses, such as `/run/nvx`,
//! which holds:
//!
//! - `layers/distro`, the EROFS image;
//! - `scratch`, the scratch, with the overlay's `upper` and `work` directories;
//! - `rootfs`, the overlay, which is the root;
//! - and `shares`, an aggregate live share, whose root lists every child, out of the workload's
//!   reach.
//!
//! A root unmounts its mounts by their paths, so it holds the exclusive lock of its runtime
//! directory, from the start of its assembly until it is torn down. An assembly refuses a runtime
//! directory that another root holds, in this process or another, and one where a file system, or
//! a bind mount of a directory, is mounted already at one of these mount points, such as one that
//! a failed teardown left. The lock is advisory: it keeps out the roots of these operations, not
//! other mounts.
//!
//! # Live shares
//!
//! A live share is a virtio-fs device that the VMM exports from the host: one host directory,
//! mounted at a target in the root, or an aggregate of host directories and files, each of which,
//! a child, is bound at its own target. A root has one aggregate at most. Before it mounts
//! anything for a share, the root checks that each target:
//!
//! - is absolute and canonical: not `/`, without an empty, `.`, or `..` component, and without a
//!   trailing `/`;
//! - holds no `\`, `=`, `,`, or NUL;
//! - is not where a container runtime mounts or binds in the root: `/proc`, `/sys`, `/dev`,
//!   `/.nvx-agent`, `/etc/machine-id`, `/run/nvx/time`, or below them, nor `/etc`, `/run`, or
//!   `/run/nvx`, below which it mounts;
//! - is not another share's target, nor inside one, nor holds one;
//! - crosses no symbolic link in the root;
//! - and is a directory, or a regular file for a child that is a host file.
//!
//! It creates each missing component of a target in the root: a directory with mode 0755, or a
//! file child's file with mode 0644.
//!
//! ```no_run
//! use std::path::Path;
//! use std::time::Duration;
//!
//! use nvx::guest::cgroup::Layout;
//! use nvx::guest::root::{self, Access, Assembly, Device, Resources};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let layout = Layout::new("/sys/fs/cgroup/agent", "/sys/fs/cgroup/container")?;
//! let resources = Resources {
//!     agent_memory_low: Some(16 << 20),
//!     ..Resources::default()
//! };
//! let bootstrap = root::bootstrap(&layout, &resources)?;
//! let mut root = root::assemble(&Assembly {
//!     runtime: "/run/nvx".into(),
//!     distro: Device { mmio: 0xd000_0000, sectors: None },
//!     distro_uuid: None,
//!     scratch: Device { mmio: 0xd000_1000, sectors: None },
//!     timeout: Duration::from_secs(30),
//! })?;
//! root.mount_share("workspace", Path::new("/workspace"), Access::ReadWrite)?;
//! // Run the workload in `bootstrap.workload()`, in the root at `root.path()`; then:
//! root.teardown()?;
//! # Ok(())
//! # }
//! ```

mod block;
mod bootstrap;
mod kernel;
mod share;
#[cfg(test)]
mod tests;

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use self::kernel::{Kernel, Paths, SystemKernel};
use super::sys::{self, Errno, MountFlags};

pub use self::bootstrap::{Bootstrap, BootstrapStep, Resources, bootstrap};
pub use self::share::{Access, ShareChild, ShareKind, ShareRefusal};

/// The EROFS image's mount point, below the runtime directory.
const DISTRO_DIRECTORY: &str = "layers/distro";
/// The scratch's mount point, below the runtime directory.
const SCRATCH_DIRECTORY: &str = "scratch";
/// The overlay's mount point, the root, below the runtime directory.
const ROOT_DIRECTORY: &str = "rootfs";
/// The mount point of an aggregate live share, below the runtime directory and outside the root,
/// which exists once a root has mounted an aggregate.
const AGGREGATE_DIRECTORY: &str = "shares";
/// The overlay's upper directory, below the scratch.
const UPPER_DIRECTORY: &str = "upper";
/// The overlay's work directory, below the scratch.
const WORK_DIRECTORY: &str = "work";
/// The overlay's options other than its directories: metadata-only copy-up, and inode numbers
/// that stay unique across the layers.
const OVERLAY_OPTIONS: &[u8] = b"metacopy=on,xino=on";
/// The characters that a runtime directory may not hold: the separators and escape of the
/// overlay's options, and the C string's terminator.
const RUNTIME_RESERVED: &[u8] = b",:\\=\0";

/// The role of a block device in a layered root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// The read-only EROFS image, the overlay's lower layer.
    Distro,
    /// The writable ext4 scratch, which holds the overlay's upper and work directories.
    Scratch,
}

impl fmt::Display for Role {
    /// Writes `distro` or `scratch`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Distro => "distro",
            Self::Scratch => "scratch",
        })
    }
}

/// A block device that the VMM attaches for a role, which the base address of its MMIO window
/// names, as the VMM declares it on the kernel command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Device {
    /// The base address of the device's MMIO window.
    pub mmio: u64,
    /// The size that the device must have, in 512-byte sectors, if the caller expects one.
    pub sectors: Option<u64>,
}

/// A step on a found block device, which an [`Error::Device`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviceStep {
    /// Reading its size.
    Size,
    /// Flushing its buffers.
    Flush,
    /// Reading its EROFS superblock.
    Superblock,
}

impl fmt::Display for DeviceStep {
    /// Writes the step as the verb phrase of a failure: `failed to {step} the device`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Size => "read the size of",
            Self::Flush => "flush the buffers of",
            Self::Superblock => "read the superblock of",
        })
    }
}

/// What [`assemble`] mounts, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assembly {
    /// The runtime directory: an absolute path without `,`, `:`, `\`, `=`, or NUL, which the
    /// overlay's options reserve.
    pub runtime: PathBuf,
    /// The device of the EROFS image.
    pub distro: Device,
    /// The UUID that the EROFS image's superblock must hold, if the caller expects one.
    pub distro_uuid: Option<[u8; 16]>,
    /// The device of the ext4 scratch.
    pub scratch: Device,
    /// How long to wait for each device to appear.
    pub timeout: Duration,
}

/// Assembles the layered root of `assembly`, as the [module](self) describes, and returns the
/// root that owns its mounts. In order, it:
///
/// 1. checks the runtime directory;
/// 2. creates its `layers/distro`, `scratch`, and `rootfs` directories, as `mkdir -p` does, takes
///    the runtime directory's exclusive lock, which the root then holds, and refuses the runtime
///    directory if another root holds it, or if one of the three, or `shares`, where a root
///    mounts an aggregate live share, is a mount point already, whether of a file system or of a
///    bind mount of a directory;
/// 3. finds the distro device, polling for it every 50 ms until `timeout` passes, checks its
///    size if the caller expects one, and flushes its buffers;
/// 4. checks the expected UUID, if any, in the device's EROFS superblock, and reads nothing else;
/// 5. mounts the device's EROFS image read-only at `layers/distro`;
/// 6. finds, checks, and flushes the scratch device the same way;
/// 7. mounts its ext4 file system at `scratch` with `nosuid` and `nodev`;
/// 8. creates the scratch's `upper` and `work` directories unless they exist;
/// 9. and mounts the overlay at `rootfs`, `nosuid` and `nodev`, with the distro layer as its
///    lower directory, and `metacopy=on,xino=on`.
///
/// A failure unmounts what the assembly mounted, as [`Root::teardown`] does, and reports both.
pub fn assemble(assembly: &Assembly) -> Result<Root, AssemblyError> {
    assemble_with(Box::new(SystemKernel), &Paths::default(), assembly)
}

/// Implements [`assemble`] with `kernel`, and with the kernel's interfaces at `paths`.
fn assemble_with(
    kernel: Box<dyn Kernel>,
    paths: &Paths,
    assembly: &Assembly,
) -> Result<Root, AssemblyError> {
    let runtime = assembly.runtime.as_os_str().as_bytes();
    if !runtime.starts_with(b"/") || runtime.iter().any(|byte| RUNTIME_RESERVED.contains(byte)) {
        return Err(AssemblyError {
            error: Error::Runtime {
                path: assembly.runtime.clone(),
            },
            cleanup: None,
        });
    }
    let mut root = Root {
        kernel,
        runtime: assembly.runtime.clone(),
        path: assembly.runtime.join(ROOT_DIRECTORY),
        overlay: None,
        distro: None,
        scratch: None,
        shares: Vec::new(),
        claimed: Vec::new(),
        reservation: None,
    };
    match root.mount_layers(paths, assembly) {
        Ok(()) => Ok(root),
        Err(error) => Err(AssemblyError {
            error,
            cleanup: root.unmount().err(),
        }),
    }
}

/// The handle of an assembled layered root, which owns its mounts: those of the assembly, and
/// those of its live shares.
///
/// [`teardown`](Self::teardown) unmounts them and reports each failure. Dropping the root
/// unmounts them the same way, and ignores failures. Until then, the root holds the lock of its
/// runtime directory, where no other root assembles.
pub struct Root {
    /// The kernel that mounts and unmounts.
    kernel: Box<dyn Kernel>,
    /// The runtime directory.
    runtime: PathBuf,
    /// The overlay's mount point, which is the root.
    path: PathBuf,
    /// The overlay's mount point, while it is mounted.
    overlay: Option<PathBuf>,
    /// The EROFS image's mount point, while it is mounted.
    distro: Option<PathBuf>,
    /// The scratch's mount point, while it is mounted.
    scratch: Option<PathBuf>,
    /// The live shares' mounts and their mount points, in mount order.
    shares: Vec<(Mount, PathBuf)>,
    /// The targets of the live shares, which another share's target may not overlap.
    claimed: Vec<PathBuf>,
    /// The exclusive lock of the runtime directory, from the start of the assembly; dropping the
    /// root releases it after the unmounts.
    reservation: Option<sys::FileLock>,
}

impl Root {
    /// Returns the root: the overlay's mount point, `rootfs` in the runtime directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the runtime directory.
    pub fn runtime(&self) -> &Path {
        &self.runtime
    }

    /// Unmounts the root's mounts, in order: the live shares in reverse mount order, the overlay,
    /// the EROFS image, and the scratch.
    ///
    /// Each unmount is attempted, whatever failed before, without detaching a busy mount, and
    /// every one that failed is reported, with the mount that it leaves in place.
    pub fn teardown(mut self) -> Result<(), TeardownError> {
        self.unmount()
    }

    /// Implements [`assemble`]'s steps after the first.
    fn mount_layers(&mut self, paths: &Paths, assembly: &Assembly) -> Result<(), Error> {
        let distro = self.runtime.join(DISTRO_DIRECTORY);
        let scratch = self.runtime.join(SCRATCH_DIRECTORY);
        for directory in [&distro, &scratch, &self.path] {
            fs::create_dir_all(directory).map_err(|error| Error::MountPoint {
                path: directory.clone(),
                error,
            })?;
        }
        self.reservation = Some(reserve(&self.runtime)?);
        let shares = self.runtime.join(AGGREGATE_DIRECTORY);
        for directory in [&distro, &scratch, &self.path, &shares] {
            match self.kernel.is_mount_point(directory) {
                Ok(false) => {}
                Ok(true) => {
                    return Err(Error::Occupied {
                        path: directory.clone(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound && *directory == shares => {}
                Err(error) => {
                    return Err(Error::MountPoint {
                        path: directory.clone(),
                        error,
                    });
                }
            }
        }
        let device = block::prepare(
            self.kernel.as_mut(),
            paths,
            Role::Distro,
            assembly.distro,
            assembly.timeout,
        )?;
        if let Some(expected) = assembly.distro_uuid {
            match block::erofs_uuid(&device) {
                Ok(Some(actual)) if actual == expected => {}
                Ok(Some(actual)) => return Err(Error::Uuid { expected, actual }),
                Ok(None) => return Err(Error::NotErofs { device }),
                Err(error) => {
                    return Err(Error::Device {
                        role: Role::Distro,
                        step: DeviceStep::Superblock,
                        device,
                        error,
                    });
                }
            }
        }
        let source = device.as_os_str().as_bytes();
        self.mount_at(
            &Mount::Distro,
            Some(source),
            &distro,
            Some(b"erofs"),
            MountFlags::MS_RDONLY,
            None,
        )?;
        self.distro = Some(distro.clone());
        let device = block::prepare(
            self.kernel.as_mut(),
            paths,
            Role::Scratch,
            assembly.scratch,
            assembly.timeout,
        )?;
        self.mount_at(
            &Mount::Scratch,
            Some(device.as_os_str().as_bytes()),
            &scratch,
            Some(b"ext4"),
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV,
            None,
        )?;
        self.scratch = Some(scratch.clone());
        let upper = scratch.join(UPPER_DIRECTORY);
        let work = scratch.join(WORK_DIRECTORY);
        for directory in [&upper, &work] {
            create_directory(directory).map_err(|error| Error::MountPoint {
                path: directory.clone(),
                error,
            })?;
        }
        let options = [
            b"lowerdir=".as_slice(),
            distro.as_os_str().as_bytes(),
            b",upperdir=",
            upper.as_os_str().as_bytes(),
            b",workdir=",
            work.as_os_str().as_bytes(),
            b",",
            OVERLAY_OPTIONS,
        ]
        .concat();
        let root = self.path.clone();
        // Neither set-ID programs nor device nodes of the image or the upper take effect.
        self.mount_at(
            &Mount::Overlay,
            Some(b"overlay"),
            &root,
            Some(b"overlay"),
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV,
            Some(&options),
        )?;
        self.overlay = Some(root);
        Ok(())
    }

    /// Mounts `source` at `target` with `filesystem`, `flags`, and the file system's own options
    /// `data`, and reports a failure as one to mount `mount`.
    fn mount_at(
        &mut self,
        mount: &Mount,
        source: Option<&[u8]>,
        target: &Path,
        filesystem: Option<&[u8]>,
        flags: MountFlags,
        data: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mounted = (|| {
            let source = source.map(sys::c_string).transpose()?;
            let filesystem = filesystem.map(sys::c_string).transpose()?;
            let data = data.map(sys::c_string).transpose()?;
            let target = sys::path_c_string(target)?;
            self.kernel.mount(
                source.as_deref(),
                &target,
                filesystem.as_deref(),
                flags,
                data.as_deref(),
            )
        })();
        mounted.map_err(|error| Error::Mount {
            mount: mount.clone(),
            error: error.into(),
        })
    }

    /// Unmounts what the root has mounted, as [`teardown`](Self::teardown) describes, and
    /// forgets it, failed unmounts included.
    fn unmount(&mut self) -> Result<(), TeardownError> {
        let assembly = [
            (Mount::Overlay, self.overlay.take()),
            (Mount::Distro, self.distro.take()),
            (Mount::Scratch, self.scratch.take()),
        ];
        let mounts: Vec<(Mount, PathBuf)> = self
            .shares
            .drain(..)
            .rev()
            .chain(
                assembly
                    .into_iter()
                    .filter_map(|(mount, path)| Some((mount, path?))),
            )
            .collect();
        self.claimed.clear();
        let mut failures = Vec::new();
        for (mount, path) in mounts {
            let unmounted =
                sys::path_c_string(&path).and_then(|target| self.kernel.unmount(&target));
            if let Err(error) = unmounted {
                failures.push(Unmount {
                    mount,
                    path,
                    error: error.into(),
                });
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(TeardownError { failures })
        }
    }
}

impl Drop for Root {
    /// Unmounts what the root has mounted, as [`Root::teardown`] does, and ignores failures.
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

impl fmt::Debug for Root {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Root")
            .field("runtime", &self.runtime)
            .field("path", &self.path)
            .field("overlay", &self.overlay)
            .field("distro", &self.distro)
            .field("scratch", &self.scratch)
            .field("shares", &self.shares)
            .finish_non_exhaustive()
    }
}

/// Takes the exclusive lock of the runtime directory `runtime`, without waiting for another root
/// that holds it.
fn reserve(runtime: &Path) -> Result<sys::FileLock, Error> {
    sys::path_c_string(runtime)
        .and_then(|path| sys::try_lock_directory(&path))
        .map_err(|error| match error {
            Errno::EWOULDBLOCK => Error::Reserved {
                path: runtime.to_owned(),
            },
            error => Error::MountPoint {
                path: runtime.to_owned(),
                error: error.into(),
            },
        })
}

/// Creates the directory `path` unless a directory, and not a symbolic link, is there already.
fn create_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path)?.is_dir() {
                Ok(())
            } else {
                Err(Errno::ENOTDIR.into())
            }
        }
        result => result,
    }
}

/// A mount of a layered root.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mount {
    /// The EROFS image, at `layers/distro` in the runtime directory.
    Distro,
    /// The scratch, at `scratch` in the runtime directory.
    Scratch,
    /// The overlay, which is the root, at `rootfs` in the runtime directory.
    Overlay,
    /// A live share, at its target in the root.
    Share {
        /// The share's virtio-fs tag.
        tag: String,
        /// The share's target in the root.
        target: PathBuf,
    },
    /// An aggregate live share, at `shares` in the runtime directory.
    Aggregate {
        /// The aggregate's virtio-fs tag.
        tag: String,
    },
    /// A child of an aggregate live share, bound at its target in the root.
    Child {
        /// The child's name in the aggregate.
        name: String,
        /// The child's target in the root.
        target: PathBuf,
    },
}

impl fmt::Display for Mount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Distro => formatter.write_str("the distro layer"),
            Self::Scratch => formatter.write_str("the scratch"),
            Self::Overlay => formatter.write_str("the overlay"),
            Self::Share { tag, target } => {
                write!(formatter, "the live share {tag} at {}", target.display())
            }
            Self::Aggregate { tag } => write!(formatter, "the aggregate live share {tag}"),
            Self::Child { name, target } => {
                write!(
                    formatter,
                    "the live share child {name} at {}",
                    target.display()
                )
            }
        }
    }
}

/// Why a root operation failed. Its text names what failed, and the system's error, if any.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A step of [`bootstrap`] failed.
    Bootstrap {
        /// The step that failed.
        step: BootstrapStep,
        /// The step's error.
        error: io::Error,
    },
    /// The runtime directory is not an absolute path, or holds a reserved character.
    Runtime {
        /// The runtime directory.
        path: PathBuf,
    },
    /// A mount point or a directory below one could not be created or checked for a mount, or
    /// the runtime directory could not be locked.
    MountPoint {
        /// The path that could not be prepared.
        path: PathBuf,
        /// The error.
        error: io::Error,
    },
    /// Another root holds the runtime directory: one that has not been torn down, or one whose
    /// assembly is in progress, in this process or another.
    Reserved {
        /// The runtime directory.
        path: PathBuf,
    },
    /// A file system, or a bind mount of a directory, is mounted already where the assembly
    /// mounts, such as one that a failed teardown left.
    Occupied {
        /// The mount point.
        path: PathBuf,
    },
    /// The kernel's MMIO windows, or a window's devices, could not be read.
    Lookup {
        /// The role of the device that was looked up.
        role: Role,
        /// The base address of its MMIO window.
        mmio: u64,
        /// The error.
        error: io::Error,
    },
    /// No block device appeared at an MMIO window in time.
    Missing {
        /// The role of the device that did not appear.
        role: Role,
        /// The base address of its MMIO window.
        mmio: u64,
    },
    /// A device's size is not the expected one.
    Size {
        /// The device's role.
        role: Role,
        /// The device's node.
        device: PathBuf,
        /// The expected size, in 512-byte sectors.
        expected: u64,
        /// The device's size, in 512-byte sectors.
        actual: u64,
    },
    /// A step on a device failed.
    Device {
        /// The device's role.
        role: Role,
        /// The step that failed.
        step: DeviceStep,
        /// The device's node.
        device: PathBuf,
        /// The error.
        error: io::Error,
    },
    /// The distro device holds no EROFS superblock, so it has no UUID to check.
    NotErofs {
        /// The device's node.
        device: PathBuf,
    },
    /// The EROFS image's UUID is not the expected one.
    Uuid {
        /// The expected UUID.
        expected: [u8; 16],
        /// The image's UUID.
        actual: [u8; 16],
    },
    /// A mount failed.
    Mount {
        /// The mount that failed.
        mount: Mount,
        /// The error.
        error: io::Error,
    },
    /// A bound child of an aggregate live share could not be restricted to its access, `nosuid`,
    /// and `nodev`. It stays bound, and the root unmounts it when it is torn down.
    Restrict {
        /// The child's mount.
        mount: Mount,
        /// The error.
        error: io::Error,
    },
    /// A live share was refused before anything was mounted for it.
    Share(ShareRefusal),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bootstrap { step, error } => write!(formatter, "failed to {step}: {error}"),
            Self::Runtime { path } => write!(
                formatter,
                "the runtime directory is not an absolute path without `,`, `:`, `\\`, or `=`: {}",
                path.display()
            ),
            Self::MountPoint { path, error } => {
                write!(formatter, "failed to prepare {}: {error}", path.display())
            }
            Self::Reserved { path } => write!(
                formatter,
                "another root holds the runtime directory {}",
                path.display()
            ),
            Self::Occupied { path } => write!(
                formatter,
                "a file system is mounted at {} already",
                path.display()
            ),
            Self::Lookup { role, mmio, error } => write!(
                formatter,
                "failed to look up the {role} device at MMIO {mmio:#x}: {error}"
            ),
            Self::Missing { role, mmio } => write!(
                formatter,
                "the {role} device at MMIO {mmio:#x} did not appear"
            ),
            Self::Size {
                role,
                device,
                expected,
                actual,
            } => write!(
                formatter,
                "the {role} device {} has {actual} sectors, expected {expected}",
                device.display()
            ),
            Self::Device {
                role,
                step,
                device,
                error,
            } => write!(
                formatter,
                "failed to {step} the {role} device {}: {error}",
                device.display()
            ),
            Self::NotErofs { device } => write!(
                formatter,
                "the distro device {} holds no EROFS image",
                device.display()
            ),
            Self::Uuid { expected, actual } => write!(
                formatter,
                "the distro layer's UUID is {}, expected {}",
                Uuid(actual),
                Uuid(expected)
            ),
            Self::Mount { mount, error } => write!(formatter, "failed to mount {mount}: {error}"),
            Self::Restrict { mount, error } => {
                write!(formatter, "failed to restrict {mount}: {error}")
            }
            Self::Share(refusal) => refusal.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {}

/// Why [`assemble`] failed, and how unmounting what it had mounted failed, if it did.
#[derive(Debug)]
pub struct AssemblyError {
    /// The assembly's failure.
    error: Error,
    /// The failures to unmount what the assembly had mounted.
    cleanup: Option<TeardownError>,
}

impl AssemblyError {
    /// Returns the assembly's failure.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Returns the failures to unmount what the assembly had mounted, if any: those mounts stay.
    pub fn cleanup(&self) -> Option<&TeardownError> {
        self.cleanup.as_ref()
    }

    /// Returns the assembly's failure and the cleanup's.
    pub fn into_parts(self) -> (Error, Option<TeardownError>) {
        (self.error, self.cleanup)
    }
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)?;
        match &self.cleanup {
            Some(cleanup) => write!(formatter, "; then {cleanup}"),
            None => Ok(()),
        }
    }
}

impl std::error::Error for AssemblyError {}

/// The unmounts of a teardown that failed, in the order in which they were attempted.
#[derive(Debug)]
pub struct TeardownError {
    /// The failed unmounts, which is never empty.
    failures: Vec<Unmount>,
}

impl TeardownError {
    /// Returns the failed unmounts, in the order in which they were attempted.
    pub fn failures(&self) -> &[Unmount] {
        &self.failures
    }
}

impl fmt::Display for TeardownError {
    /// Writes each failure, separated by `; `.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, failure) in self.failures.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            failure.fmt(formatter)?;
        }
        Ok(())
    }
}

impl std::error::Error for TeardownError {}

/// An unmount that failed, which left its mount in place.
#[derive(Debug)]
pub struct Unmount {
    /// The mount.
    mount: Mount,
    /// Its mount point.
    path: PathBuf,
    /// The error.
    error: io::Error,
}

impl Unmount {
    /// Returns the mount that stays in place.
    pub fn mount(&self) -> &Mount {
        &self.mount
    }

    /// Returns its mount point.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the error of its unmount.
    pub fn error(&self) -> &io::Error {
        &self.error
    }
}

impl fmt::Display for Unmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to unmount {}: {}",
            self.mount, self.error
        )
    }
}

/// A UUID, which displays in its canonical form: 32 lowercase hexadecimal digits, in groups of 8,
/// 4, 4, 4, and 12 that hyphens separate.
struct Uuid<'a>(&'a [u8; 16]);

impl fmt::Display for Uuid<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
