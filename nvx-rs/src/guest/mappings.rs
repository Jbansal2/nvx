//! Bind mounts of host mappings, below roots that a guest init or agent names.
//!
//! A [`Mapping`] names a source below an export root, the directory where the host's shares
//! appear in the guest; a target below a target root, the tree that the mappings go into; and the
//! target's [`Access`]. [`Mapping::apply`] takes both roots explicitly. It gives the target the
//! kind of its source, a directory or a regular file, bind-mounts the source on it, and remounts
//! the bind with `nosuid` and `nodev`, and with `ro` for [`Access::ReadOnly`].
//!
//! The roots are absolute paths that the caller chooses. Each path of a mapping stays below its
//! root: [`Mapping::new`] takes a relative source and a target that is absolute as seen from the
//! target root, and refuses empty, `.`, and `..` components. A mapping is applied by path: the
//! kernel follows symbolic links on the way to the source and the target, as the bind mount does,
//! except that the call reads the kind of the source, and creates or checks a file target, without
//! following a final symbolic link. A caller therefore applies mappings only to trees that no
//! untrusted program can change, such as a root that it is still assembling.
//!
//! The caller orders its mappings and decides what a failure means for the rest. A failed mapping
//! leaves the mappings before it mounted, and what its own earlier stages did: the directories and
//! the file that it created, and, when the remount failed, the bind without its flags.
//! [`MappingFailure::stage`] tells which stage failed. NVX's managed agent is one caller: it
//! applies the host mapping table that its control session receives, in order, with its mount of
//! the host's export as the export root and `/` as the target root. A layered
//! [`Root`](super::root::Root) is another: it binds each child of an aggregate live share from the
//! aggregate's mount into the root, once it has checked that no symbolic link leads through the
//! child's target, and created what is missing of it.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use nvx::guest::mappings::{Access, Mapping};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mapping = Mapping::new("0/workspace", "/workspace", Access::ReadWrite)?;
//! // Mounts /run/export/0/workspace on /newroot/workspace.
//! mapping.apply(Path::new("/run/export"), Path::new("/newroot"))?;
//! # Ok(())
//! # }
//! ```

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::sys::{self, Errno, Mode, MountFlags, OpenFlags};

/// The longest source or target of a [`Mapping`], in bytes: Linux's `PATH_MAX` without its
/// terminating NUL.
pub const MAX_PATH_BYTES: usize = sys::PATH_MAX - 1;

/// The mode of each directory that [`Mapping::apply`] creates, before the umask: `rwxr-xr-x`.
const DIRECTORY_MODE: Mode = Mode::S_IRWXU
    .union(Mode::S_IRGRP)
    .union(Mode::S_IXGRP)
    .union(Mode::S_IROTH)
    .union(Mode::S_IXOTH);
/// The mode of each file target that [`Mapping::apply`] creates, before the umask: `rw-r--r--`.
const FILE_MODE: Mode = Mode::S_IRUSR
    .union(Mode::S_IWUSR)
    .union(Mode::S_IRGRP)
    .union(Mode::S_IROTH);

/// Whether programs can write a mapping's target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Access {
    /// The target is read-only.
    ReadOnly,
    /// The target is writable, as far as the source allows.
    ReadWrite,
}

impl Access {
    /// Returns the flags that restrict a mount with this access: `nosuid` and `nodev`, and `ro`
    /// for [`Access::ReadOnly`].
    pub(crate) fn flags(self) -> MountFlags {
        let flags = MountFlags::MS_NOSUID | MountFlags::MS_NODEV;
        match self {
            Self::ReadOnly => flags | MountFlags::MS_RDONLY,
            Self::ReadWrite => flags,
        }
    }
}

/// The path that [`Mapping::new`] refuses, because it does not name a path below its root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidMapping {
    /// The source is not a relative path of at most [`MAX_PATH_BYTES`] bytes without NUL bytes,
    /// whose components are neither empty, `.`, nor `..`.
    Source,
    /// The target is not an absolute path of at most [`MAX_PATH_BYTES`] bytes without NUL bytes,
    /// whose components after the leading `/` are neither empty, `.`, nor `..`.
    Target,
}

impl fmt::Display for InvalidMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (path, form) = match self {
            Self::Source => ("source", "a relative"),
            Self::Target => ("target", "an absolute"),
        };
        write!(
            formatter,
            "a mapping {path} must be {form} path of at most {MAX_PATH_BYTES} bytes without NUL \
             bytes or empty, `.`, or `..` components"
        )
    }
}

impl std::error::Error for InvalidMapping {}

/// A stage of applying a [`Mapping`]. The variants are in the order of the stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MappingStage {
    /// The kind of the source is read, without following a final symbolic link.
    Source,
    /// The target is created, or an existing one is checked, as the kind of the source.
    Target,
    /// The source is bind-mounted on the target.
    Bind,
    /// The bind is remounted with the mapping's flags.
    Remount,
}

impl MappingStage {
    /// Returns the failure of this stage with `error`.
    fn failure(self, error: Errno) -> MappingFailure {
        MappingFailure {
            stage: self,
            error: error as i32,
        }
    }
}

impl fmt::Display for MappingStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source => "source",
            Self::Target => "target",
            Self::Bind => "bind",
            Self::Remount => "remount",
        })
    }
}

/// The stage at which applying a [`Mapping`] failed, and the `errno` of the failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingFailure {
    /// The stage that failed.
    stage: MappingStage,
    /// The `errno` with which it failed.
    error: i32,
}

impl MappingFailure {
    /// Returns the stage that failed.
    pub fn stage(&self) -> MappingStage {
        self.stage
    }

    /// Returns the `errno` with which the stage failed.
    pub fn raw_os_error(&self) -> i32 {
        self.error
    }
}

impl fmt::Display for MappingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the {} mapping stage failed: {}",
            self.stage,
            io::Error::from_raw_os_error(self.error)
        )
    }
}

impl std::error::Error for MappingFailure {}

/// A host mapping: a source below an export root, which [`apply`](Self::apply) bind-mounts at a
/// target below a target root, with an [`Access`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Mapping {
    /// The source, relative to the export root.
    source: PathBuf,
    /// The target, relative to the target root: the absolute target that [`Mapping::new`] took,
    /// without its leading `/`.
    target: PathBuf,
    /// Whether programs can write the target.
    access: Access,
}

impl Mapping {
    /// Describes the mapping of `source`, a path relative to the export root, at `target`, an
    /// absolute path as seen from the target root, with `access`: for example `0/workspace` at
    /// `/workspace`.
    ///
    /// Each path holds at most [`MAX_PATH_BYTES`] bytes, no NUL byte, and no empty, `.`, or `..`
    /// component, so that it names a path below its root; [`InvalidMapping`] tells which one does
    /// not. Other bytes need not be UTF-8.
    pub fn new(
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        access: Access,
    ) -> Result<Self, InvalidMapping> {
        let source = source.into();
        if below_its_root(&source, false).is_none() {
            return Err(InvalidMapping::Source);
        }
        let target = below_its_root(&target.into(), true)
            .ok_or(InvalidMapping::Target)?
            .to_path_buf();
        Ok(Self {
            source,
            target,
            access,
        })
    }

    /// Returns the source, relative to the export root.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Returns the target, relative to the target root: the target that [`new`](Self::new) took,
    /// without its leading `/`, such as `workspace` for `/workspace`.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Returns whether programs can write the target.
    pub fn access(&self) -> Access {
        self.access
    }

    /// Applies the mapping below `export_root` and `target_root`, the absolute paths of existing
    /// directories. It needs the privilege to mount.
    ///
    /// A directory source gets a directory target: the call creates each missing directory of
    /// the target below the target root, with mode 0755 before the umask, and uses the entries
    /// that exist as they are, so the bind mount follows a symbolic link there. A regular-file
    /// source gets a regular-file target: the call creates the missing directories above it, then
    /// the file, empty and with mode 0644 before the umask, unless a regular file is there
    /// already, without following a symbolic link. The call then bind-mounts the source on the
    /// target, and remounts the bind with `nosuid` and `nodev`, and with `ro` for
    /// [`Access::ReadOnly`].
    ///
    /// A source of any other kind, such as a symbolic link, and a file target that exists as
    /// anything but a regular file fail with `EINVAL`, as does a relative root, at the stage of
    /// their path. A failure leaves what the earlier stages did, as the [module](self)
    /// documentation describes.
    pub fn apply(&self, export_root: &Path, target_root: &Path) -> Result<(), MappingFailure> {
        self.apply_with(export_root, target_root, |source, target, flags| {
            sys::mount(source, target, None, flags, None)
        })
    }

    /// Applies the mapping as [`apply`](Self::apply) does, but makes each mount through `mount`,
    /// which takes the source, if any, the target, and the flags of one `mount` system call
    /// without a filesystem type.
    pub(crate) fn apply_with(
        &self,
        export_root: &Path,
        target_root: &Path,
        mut mount: impl FnMut(Option<&CStr>, &CStr, MountFlags) -> Result<(), Errno>,
    ) -> Result<(), MappingFailure> {
        let (source, c_source) = below(export_root, &self.source)
            .map_err(|error| MappingStage::Source.failure(error))?;
        let (target, c_target) = below(target_root, &self.target)
            .map_err(|error| MappingStage::Target.failure(error))?;
        let kind = std::fs::symlink_metadata(&source)
            .map_err(|error| MappingStage::Source.failure(sys::errno_of(&error)))?
            .file_type();
        let created = if kind.is_dir() {
            create_directories(target_root, &self.target)
        } else if kind.is_file() {
            let parent = self.target.parent().unwrap_or(Path::new(""));
            create_directories(target_root, parent).and_then(|()| file_target(&target, &c_target))
        } else {
            return Err(MappingStage::Source.failure(Errno::EINVAL));
        };
        created.map_err(|error| MappingStage::Target.failure(error))?;
        mount(Some(&c_source), &c_target, MountFlags::MS_BIND)
            .map_err(|error| MappingStage::Bind.failure(error))?;
        let flags = MountFlags::MS_BIND | MountFlags::MS_REMOUNT | self.access.flags();
        mount(None, &c_target, flags).map_err(|error| MappingStage::Remount.failure(error))
    }
}

/// Returns the part of `path` below its root: the whole of a relative path, or what follows the
/// leading `/` of an `absolute` one. It returns `None` unless `path` holds at most
/// [`MAX_PATH_BYTES`] bytes and no NUL byte, starts with `/` exactly when it is `absolute`, and
/// has a part below its root of at least one component, each neither empty, `.`, nor `..`.
pub(crate) fn below_its_root(path: &Path, absolute: bool) -> Option<&Path> {
    let bytes = path.as_os_str().as_bytes();
    let components = if absolute {
        bytes.strip_prefix(b"/")?
    } else {
        bytes
    };
    let valid = bytes.len() <= MAX_PATH_BYTES
        && !bytes.contains(&0)
        && !components.is_empty()
        && components
            .split(|&byte| byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".."));
    valid.then(|| Path::new(OsStr::from_bytes(components)))
}

/// Returns the path that the relative `path` names below `root`, and the same path as a C string,
/// or `EINVAL` if `root` is relative or holds a NUL byte.
fn below(root: &Path, path: &Path) -> Result<(PathBuf, CString), Errno> {
    if !root.is_absolute() {
        return Err(Errno::EINVAL);
    }
    let joined = root.join(path);
    let c_string = sys::path_c_string(&joined)?;
    Ok((joined, c_string))
}

/// Creates each missing directory of the relative `directories` below `root`, outermost first,
/// with [`DIRECTORY_MODE`] before the umask. It uses the entries that exist as they are.
fn create_directories(root: &Path, directories: &Path) -> Result<(), Errno> {
    let mut directory = root.to_path_buf();
    for component in directories {
        directory.push(component);
        match sys::create_directory(&sys::path_c_string(&directory)?, DIRECTORY_MODE) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Checks that the file target `target`, whose C string is `c_target`, is a regular file, or
/// creates it if it is missing, without following a symbolic link.
fn file_target(target: &Path, c_target: &CStr) -> Result<(), Errno> {
    match std::fs::symlink_metadata(target) {
        Ok(existing) if existing.file_type().is_file() => Ok(()),
        Ok(_) => Err(Errno::EINVAL),
        Err(error) => match sys::errno_of(&error) {
            Errno::ENOENT => create_file(c_target),
            error => Err(error),
        },
    }
}

/// Creates the regular file `path`, empty and with [`FILE_MODE`] before the umask, failing if any
/// entry is there, even a symbolic link.
///
/// The new file closes at once, and a failure to close it is ignored.
fn create_file(path: &CStr) -> Result<(), Errno> {
    sys::open(
        path,
        OpenFlags::O_RDONLY
            | OpenFlags::O_CREAT
            | OpenFlags::O_EXCL
            | OpenFlags::O_CLOEXEC
            | OpenFlags::O_NOFOLLOW,
        FILE_MODE,
    )
    .map(|_created| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One recorded mount: the source, if any, the target, and the flags.
    type Mount = (Option<Vec<u8>>, Vec<u8>, MountFlags);

    /// Returns the flags of every remount, without `MS_RDONLY`.
    fn remount() -> MountFlags {
        MountFlags::MS_BIND | MountFlags::MS_REMOUNT | MountFlags::MS_NOSUID | MountFlags::MS_NODEV
    }

    /// Returns the bytes of `path`.
    fn bytes(path: &Path) -> Vec<u8> {
        path.as_os_str().as_bytes().to_vec()
    }

    /// Returns a temporary directory, which the caller keeps, with an export root, `export`, that
    /// holds the directory `0/src` and the file `0/notes.txt`, and an empty target root, `root`.
    fn roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let export = temporary.path().join("export");
        let root = temporary.path().join("root");
        std::fs::create_dir_all(export.join("0/src")).unwrap();
        std::fs::write(export.join("0/notes.txt"), b"notes").unwrap();
        std::fs::create_dir(&root).unwrap();
        (temporary, export, root)
    }

    /// Applies `mapping` below `export` and `root`, records its mounts in `mounts`, and fails
    /// the mount call numbered `fail`, from 1 for the first call of `mounts`, with `ENOENT`.
    fn apply(
        mapping: &Mapping,
        export: &Path,
        root: &Path,
        mounts: &mut Vec<Mount>,
        fail: Option<usize>,
    ) -> Result<(), MappingFailure> {
        mapping.apply_with(export, root, |source, target, flags| {
            mounts.push((
                source.map(|source| source.to_bytes().to_vec()),
                target.to_bytes().to_vec(),
                flags,
            ));
            if fail == Some(mounts.len()) {
                Err(Errno::ENOENT)
            } else {
                Ok(())
            }
        })
    }

    /// Returns the sorted names in `directory`.
    fn entries(directory: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn directory_and_file_mappings_go_below_a_target_root_other_than_slash() {
        let (temporary, export, root) = roots();
        let mut mounts = Vec::new();
        let directory = Mapping::new("0/src", "/srv/data", Access::ReadWrite).unwrap();
        let file = Mapping::new("0/notes.txt", "/etc/app/notes.txt", Access::ReadWrite).unwrap();
        apply(&directory, &export, &root, &mut mounts, None).unwrap();
        apply(&file, &export, &root, &mut mounts, None).unwrap();
        let (data, notes) = (root.join("srv/data"), root.join("etc/app/notes.txt"));
        assert_eq!(
            mounts,
            vec![
                (
                    Some(bytes(&export.join("0/src"))),
                    bytes(&data),
                    MountFlags::MS_BIND
                ),
                (None, bytes(&data), remount()),
                (
                    Some(bytes(&export.join("0/notes.txt"))),
                    bytes(&notes),
                    MountFlags::MS_BIND
                ),
                (None, bytes(&notes), remount()),
            ]
        );
        assert!(data.is_dir());
        assert!(notes.is_file());
        assert_eq!(std::fs::read(&notes).unwrap(), b"");
        // The call creates nothing outside the target root and changes nothing in the export.
        assert_eq!(entries(temporary.path()), ["export", "root"]);
        assert_eq!(entries(&root), ["etc", "srv"]);
        assert_eq!(entries(&export.join("0")), ["notes.txt", "src"]);
        assert_eq!(std::fs::read(export.join("0/notes.txt")).unwrap(), b"notes");
        assert_eq!(
            (directory.source(), directory.target()),
            (Path::new("0/src"), Path::new("srv/data"))
        );
    }

    #[test]
    fn read_only_and_read_write_mappings_remount_with_their_flags() {
        let (_temporary, export, root) = roots();
        for (source, target) in [("0/src", "/directory"), ("0/notes.txt", "/file")] {
            for (access, flags) in [
                (Access::ReadOnly, remount() | MountFlags::MS_RDONLY),
                (Access::ReadWrite, remount()),
            ] {
                let mapping = Mapping::new(source, target, access).unwrap();
                assert_eq!(mapping.access(), access);
                let mut mounts = Vec::new();
                apply(&mapping, &export, &root, &mut mounts, None).unwrap();
                let mounted = bytes(&root.join(&target[1..]));
                assert_eq!(
                    mounts,
                    vec![
                        (
                            Some(bytes(&export.join(source))),
                            mounted.clone(),
                            MountFlags::MS_BIND
                        ),
                        (None, mounted, flags),
                    ],
                    "{source} {access:?}"
                );
            }
        }
    }

    #[test]
    fn sources_and_targets_that_would_leave_their_roots_are_refused() {
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        for source in [
            "",
            "/0/src",
            "..",
            "../0",
            "0/../..",
            "0/..",
            ".",
            "./0",
            "0/.",
            "0//src",
            "0/src/",
            "0/s\0rc",
            long.as_str(),
        ] {
            assert_eq!(
                Mapping::new(source, "/target", Access::ReadOnly),
                Err(InvalidMapping::Source),
                "{source:?}"
            );
        }
        let long_target = format!("/{long}");
        for target in [
            "",
            "target",
            "0/src",
            "/",
            "//target",
            "/target/",
            "/..",
            "/../etc",
            "/target/../../etc",
            "/target/./etc",
            "/./target",
            "/tar\0get",
            long_target.as_str(),
        ] {
            assert_eq!(
                Mapping::new("0/src", target, Access::ReadOnly),
                Err(InvalidMapping::Target),
                "{target:?}"
            );
        }
        // The longest paths and bytes that are not UTF-8 name paths below their roots.
        let longest = "a".repeat(MAX_PATH_BYTES);
        Mapping::new(
            longest.as_str(),
            format!("/{}", &longest[1..]),
            Access::ReadOnly,
        )
        .unwrap();
        Mapping::new(
            OsStr::from_bytes(b"0/\xffsrc"),
            OsStr::from_bytes(b"/\xfe"),
            Access::ReadWrite,
        )
        .unwrap();

        // A root must be absolute, and a target root is never created.
        let (temporary, export, root) = roots();
        let mapping = Mapping::new("0/src", "/srv/data", Access::ReadOnly).unwrap();
        let missing = temporary.path().join("missing");
        let mut mounts = Vec::new();
        for (export_root, target_root, stage, error) in [
            (
                Path::new("export"),
                root.as_path(),
                MappingStage::Source,
                Errno::EINVAL,
            ),
            (
                export.as_path(),
                Path::new("root"),
                MappingStage::Target,
                Errno::EINVAL,
            ),
            (
                export.as_path(),
                missing.as_path(),
                MappingStage::Target,
                Errno::ENOENT,
            ),
        ] {
            let failure = apply(&mapping, export_root, target_root, &mut mounts, None).unwrap_err();
            assert_eq!(
                (failure.stage(), failure.raw_os_error()),
                (stage, error as i32),
                "{export_root:?} {target_root:?}"
            );
        }
        assert!(mounts.is_empty());
        assert_eq!(entries(&root), Vec::<String>::new());
        assert!(!missing.exists());
    }

    #[test]
    fn sources_and_file_targets_of_other_kinds_are_refused() {
        let (temporary, export, root) = roots();
        std::os::unix::fs::symlink("src", export.join("0/link")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(export.join("0/socket")).unwrap();
        std::fs::create_dir(root.join("directory")).unwrap();
        std::fs::write(root.join("plain"), b"plain").unwrap();
        let outside = temporary.path().join("outside");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let mut mounts = Vec::new();
        for (source, target, stage, error) in [
            ("0/link", "/new", MappingStage::Source, Errno::EINVAL),
            ("0/socket", "/new", MappingStage::Source, Errno::EINVAL),
            ("0/missing", "/new", MappingStage::Source, Errno::ENOENT),
            (
                "0/notes.txt",
                "/directory",
                MappingStage::Target,
                Errno::EINVAL,
            ),
            ("0/notes.txt", "/link", MappingStage::Target, Errno::EINVAL),
            ("0/src", "/plain/new", MappingStage::Target, Errno::ENOTDIR),
        ] {
            let mapping = Mapping::new(source, target, Access::ReadWrite).unwrap();
            let failure = apply(&mapping, &export, &root, &mut mounts, None).unwrap_err();
            assert_eq!(
                (failure.stage(), failure.raw_os_error()),
                (stage, error as i32),
                "{source} {target}"
            );
        }
        assert!(mounts.is_empty());
        // Nothing followed the symbolic link out of the target root, or replaced an entry.
        assert!(!outside.exists());
        assert_eq!(entries(&root), ["directory", "link", "plain"]);
        assert_eq!(entries(&root.join("directory")), Vec::<String>::new());
        assert_eq!(std::fs::read(root.join("plain")).unwrap(), b"plain");
    }

    #[test]
    fn existing_targets_are_used_as_they_are() {
        let (_temporary, export, root) = roots();
        std::fs::create_dir_all(root.join("srv/data/kept")).unwrap();
        std::fs::write(root.join("notes.txt"), b"existing").unwrap();
        let mut mounts = Vec::new();
        for (source, target) in [("0/src", "/srv/data"), ("0/notes.txt", "/notes.txt")] {
            let mapping = Mapping::new(source, target, Access::ReadOnly).unwrap();
            apply(&mapping, &export, &root, &mut mounts, None).unwrap();
        }
        assert_eq!(mounts.len(), 4);
        assert!(root.join("srv/data/kept").is_dir());
        assert_eq!(std::fs::read(root.join("notes.txt")).unwrap(), b"existing");
    }

    #[test]
    fn a_failed_bind_or_remount_reports_its_stage_and_leaves_earlier_stages() {
        let (_temporary, export, root) = roots();
        let mapping = Mapping::new("0/src", "/srv/data", Access::ReadOnly).unwrap();
        for (fail, stage) in [(1, MappingStage::Bind), (2, MappingStage::Remount)] {
            let mut mounts = Vec::new();
            let failure = apply(&mapping, &export, &root, &mut mounts, Some(fail)).unwrap_err();
            assert_eq!(
                (failure.stage(), failure.raw_os_error()),
                (stage, Errno::ENOENT as i32)
            );
            assert_eq!(
                failure.to_string(),
                format!(
                    "the {stage} mapping stage failed: {}",
                    io::Error::from_raw_os_error(Errno::ENOENT as i32)
                )
            );
            // The created target stays, and the remount comes only after its bind.
            assert_eq!(mounts.len(), fail);
            assert!(root.join("srv/data").is_dir());
        }
        assert_eq!(
            InvalidMapping::Target.to_string(),
            format!(
                "a mapping target must be an absolute path of at most {MAX_PATH_BYTES} bytes \
                 without NUL bytes or empty, `.`, or `..` components"
            )
        );
    }
}
