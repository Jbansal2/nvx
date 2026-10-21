//! Live shares: virtio-fs devices that the VMM exports from the host, mounted at targets in a
//! layered root after the checks that the [module](super#live-shares) lists, which are the ones
//! that NVX's shell init applies.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{AGGREGATE_DIRECTORY, Error, Mount, Root};
use crate::guest::sys::{self, MountFlags};

/// The targets that the runtime mounts or binds over in the root, each with everything below it.
const RESERVED_TREES: [&[u8]; 6] = [
    b"/proc",
    b"/sys",
    b"/dev",
    b"/.nvx-agent",
    b"/etc/machine-id",
    b"/run/nvx/time",
];
/// The directories that the runtime creates or mounts below, without the paths below them.
const RESERVED_DIRECTORIES: [&[u8]; 3] = [b"/etc", b"/run", b"/run/nvx"];
/// The file system type of a live share.
const VIRTIOFS: &[u8] = b"virtiofs";

/// Whether the workload may write a live share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Access {
    /// The share is mounted read-only.
    ReadOnly,
    /// The share is mounted read-write.
    ReadWrite,
}

impl Access {
    /// Returns the mount flags of a share with this access, without set-user-ID programs or
    /// device nodes.
    fn flags(self) -> MountFlags {
        let flags = MountFlags::MS_NOSUID | MountFlags::MS_NODEV;
        match self {
            Self::ReadOnly => flags | MountFlags::MS_RDONLY,
            Self::ReadWrite => flags,
        }
    }
}

impl fmt::Display for Access {
    /// Writes `ro` or `rw`, as a mount option names the access.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
        })
    }
}

/// What a child of an aggregate share is: a host directory, or a host file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ShareKind {
    /// A directory, bound at a directory of the root.
    #[default]
    Directory,
    /// A regular file, bound at a regular file of the root.
    File,
}

/// A child of an aggregate share: an entry of the aggregate, bound at a target in the root.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShareChild {
    /// The name of the child's entry in the aggregate: letters, digits, `.`, `_`, and `-`, other
    /// than `.` and `..`.
    pub name: String,
    /// The absolute path in the root at which the child is bound.
    pub target: PathBuf,
    /// Whether the workload may write the child.
    pub access: Access,
    /// What the child is.
    pub kind: ShareKind,
}

/// Why a live share was refused before anything was mounted for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ShareRefusal {
    /// The virtio-fs tag is not a nonempty name of letters, digits, `_`, and `-`.
    Tag(String),
    /// An aggregate has no children.
    NoChildren,
    /// A child's name is not a nonempty name of letters, digits, `.`, `_`, and `-`, or is `.` or
    /// `..`.
    ChildName(String),
    /// Two children of an aggregate have this name.
    DuplicateChild(String),
    /// The target is not an absolute path.
    Relative(PathBuf),
    /// The target is `/`, or has an empty, `.`, or `..` component, or a trailing `/`.
    NotCanonical(PathBuf),
    /// The target holds a reserved character: `\`, `=`, `,`, or NUL.
    ReservedCharacter(PathBuf),
    /// The runtime mounts at the target, or below it, or binds over it.
    Reserved(PathBuf),
    /// The target is the target of another share, or one inside it or that holds it.
    Overlap {
        /// The other share's target.
        claimed: PathBuf,
        /// The refused target.
        target: PathBuf,
    },
    /// A component of the target's path in the root is a symbolic link.
    SymbolicLink(PathBuf),
    /// The target, or a component of its path, exists in the root but is not a directory.
    NotDirectory(PathBuf),
    /// A file child's target exists in the root but is not a regular file.
    NotFile(PathBuf),
    /// The root owns an aggregate already, whose children may or may not all be bound: it mounts
    /// every aggregate at the same place.
    SecondAggregate,
}

impl fmt::Display for ShareRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tag(tag) => write!(formatter, "live share tag is invalid: {tag}"),
            Self::NoChildren => formatter.write_str("the aggregate live share has no children"),
            Self::ChildName(name) => write!(formatter, "live share child is invalid: {name}"),
            Self::DuplicateChild(name) => {
                write!(formatter, "live share child is not unique: {name}")
            }
            Self::Relative(target) => write!(
                formatter,
                "live share target must be an absolute path: {}",
                target.display()
            ),
            Self::NotCanonical(target) => write!(
                formatter,
                "live share target is not canonical: {}",
                target.display()
            ),
            Self::ReservedCharacter(target) => write!(
                formatter,
                "live share target contains a reserved character: {}",
                target.display()
            ),
            Self::Reserved(target) => write!(
                formatter,
                "live share target is reserved: {}",
                target.display()
            ),
            Self::Overlap { claimed, target } => write!(
                formatter,
                "live share targets overlap: {} and {}",
                claimed.display(),
                target.display()
            ),
            Self::SymbolicLink(target) => write!(
                formatter,
                "live share target crosses a symbolic link: {}",
                target.display()
            ),
            Self::NotDirectory(target) => write!(
                formatter,
                "live share target is not a directory: {}",
                target.display()
            ),
            Self::NotFile(target) => write!(
                formatter,
                "live share target is not a regular file: {}",
                target.display()
            ),
            Self::SecondAggregate => {
                formatter.write_str("the root has an aggregate live share already")
            }
        }
    }
}

impl Root {
    /// Mounts the virtio-fs device `tag` at `target` in the root, a directory, with `access`,
    /// `nosuid`, and `nodev`.
    ///
    /// The target is checked as the [module](super#live-shares) describes, against the targets
    /// of the root's other shares, then created in the root if it is missing; nothing is mounted
    /// for a refused one. The mount belongs to the root, which unmounts it first when it is torn
    /// down.
    pub fn mount_share(&mut self, tag: &str, target: &Path, access: Access) -> Result<(), Error> {
        check_tag(tag)?;
        check_target(target)?;
        self.check_overlap(target, &[])?;
        let point = mount_point(&self.path, target, ShareKind::Directory)?;
        let mount = Mount::Share {
            tag: tag.to_owned(),
            target: target.to_owned(),
        };
        self.mount_at(
            &mount,
            Some(tag.as_bytes()),
            &point,
            Some(VIRTIOFS),
            access.flags(),
            None,
        )?;
        self.shares.push((mount, point));
        self.claimed.push(target.to_owned());
        Ok(())
    }

    /// Mounts the aggregate virtio-fs device `tag`, with `access`, `nosuid`, and `nodev`, at
    /// `shares` in the runtime directory, outside the root, where the workload cannot list its
    /// children. Then binds each child, in order, at its target in the root, and restricts the
    /// bind to the child's access, `nosuid`, and `nodev`.
    ///
    /// Every child is checked first: its name, which no other child has, and its target, as the
    /// [module](super#live-shares) describes, against the other children's and the root's other
    /// shares' targets. Each target is created in the root if it is missing. Nothing is mounted
    /// unless every child passes. The mounts belong to the root, which unmounts them first when
    /// it is torn down, in reverse mount order, those of an aggregate that failed part of the way
    /// included.
    ///
    /// A root has one aggregate at most, since every aggregate is mounted at the same place: once
    /// the root has mounted one, whether or not its children were all bound, another is refused.
    pub fn mount_aggregate(
        &mut self,
        tag: &str,
        access: Access,
        children: &[ShareChild],
    ) -> Result<(), Error> {
        if self
            .shares
            .iter()
            .any(|(mount, _)| matches!(mount, Mount::Aggregate { .. }))
        {
            return Err(Error::Share(ShareRefusal::SecondAggregate));
        }
        check_tag(tag)?;
        if children.is_empty() {
            return Err(Error::Share(ShareRefusal::NoChildren));
        }
        let mut targets: Vec<PathBuf> = Vec::with_capacity(children.len());
        let mut points = Vec::with_capacity(children.len());
        for (index, child) in children.iter().enumerate() {
            check_name(&child.name)?;
            if children[..index]
                .iter()
                .any(|earlier| earlier.name == child.name)
            {
                return Err(Error::Share(ShareRefusal::DuplicateChild(
                    child.name.clone(),
                )));
            }
            check_target(&child.target)?;
            self.check_overlap(&child.target, &targets)?;
            targets.push(child.target.clone());
            points.push(mount_point(&self.path, &child.target, child.kind)?);
        }
        let directory = self.runtime.join(AGGREGATE_DIRECTORY);
        fs::create_dir_all(&directory).map_err(|error| Error::MountPoint {
            path: directory.clone(),
            error,
        })?;
        let aggregate = Mount::Aggregate {
            tag: tag.to_owned(),
        };
        self.mount_at(
            &aggregate,
            Some(tag.as_bytes()),
            &directory,
            Some(VIRTIOFS),
            access.flags(),
            None,
        )?;
        self.shares.push((aggregate, directory.clone()));
        for (child, point) in children.iter().zip(points) {
            let mount = Mount::Child {
                name: child.name.clone(),
                target: child.target.clone(),
            };
            let source = directory.join(&child.name);
            self.mount_at(
                &mount,
                Some(source.as_os_str().as_bytes()),
                &point,
                None,
                MountFlags::MS_BIND,
                None,
            )?;
            self.shares.push((mount.clone(), point.clone()));
            self.claimed.push(child.target.clone());
            // A bind takes its source's flags; only a remount of the bind changes them.
            let restricted = sys::path_c_string(&point).and_then(|point| {
                self.kernel.mount(
                    None,
                    &point,
                    None,
                    MountFlags::MS_REMOUNT | MountFlags::MS_BIND | child.access.flags(),
                    None,
                )
            });
            restricted.map_err(|error| Error::Restrict {
                mount,
                error: error.into(),
            })?;
        }
        Ok(())
    }

    /// Refuses `target` if it overlaps the target of one of the root's shares, or one of
    /// `pending`.
    fn check_overlap(&self, target: &Path, pending: &[PathBuf]) -> Result<(), Error> {
        let below = |inner: &Path, outer: &Path| {
            let mut inner = inner.as_os_str().as_bytes().to_vec();
            let mut outer = outer.as_os_str().as_bytes().to_vec();
            inner.push(b'/');
            outer.push(b'/');
            inner.starts_with(&outer)
        };
        match self
            .claimed
            .iter()
            .chain(pending)
            .find(|claimed| below(target, claimed) || below(claimed, target))
        {
            Some(claimed) => Err(Error::Share(ShareRefusal::Overlap {
                claimed: claimed.clone(),
                target: target.to_owned(),
            })),
            None => Ok(()),
        }
    }
}

/// Refuses a virtio-fs tag that is not a nonempty name of letters, digits, `_`, and `-`.
fn check_tag(tag: &str) -> Result<(), Error> {
    if tag.is_empty()
        || !tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::Share(ShareRefusal::Tag(tag.to_owned())));
    }
    Ok(())
}

/// Refuses an aggregate child's name that is not a nonempty name of letters, digits, `.`, `_`,
/// and `-`, or that is `.` or `..`.
fn check_name(name: &str) -> Result<(), Error> {
    if matches!(name, "" | "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::Share(ShareRefusal::ChildName(name.to_owned())));
    }
    Ok(())
}

/// Refuses a target that is not canonical and absolute, that holds a reserved character, or that
/// the runtime reserves.
fn check_target(target: &Path) -> Result<(), Error> {
    let bytes = target.as_os_str().as_bytes();
    // A trailing `/` makes `/` itself, and a target that ends in one, `.`, or `..`, a form below.
    let terminated = [bytes, b"/"].concat();
    let refusal = if !bytes.starts_with(b"/") {
        Some(ShareRefusal::Relative(target.to_owned()))
    } else if [b"//".as_slice(), b"/./", b"/../"]
        .iter()
        .any(|form| terminated.windows(form.len()).any(|part| part == *form))
    {
        Some(ShareRefusal::NotCanonical(target.to_owned()))
    } else if bytes
        .iter()
        .any(|byte| matches!(byte, b'\\' | b'=' | b',' | b'\0'))
    {
        Some(ShareRefusal::ReservedCharacter(target.to_owned()))
    } else if RESERVED_DIRECTORIES.contains(&bytes)
        || RESERVED_TREES.iter().any(|tree| {
            bytes == *tree || (bytes.starts_with(tree) && bytes.get(tree.len()) == Some(&b'/'))
        })
    {
        Some(ShareRefusal::Reserved(target.to_owned()))
    } else {
        None
    };
    refusal.map_or(Ok(()), |refusal| Err(Error::Share(refusal)))
}

/// Walks the components of `target` from `root`, creating each that is missing, and returns the
/// target's path below `root`. Each component is a directory, except the last of a file child,
/// which is a regular file, and none is a symbolic link.
fn mount_point(root: &Path, target: &Path, kind: ShareKind) -> Result<PathBuf, Error> {
    let refused = |refusal: fn(PathBuf) -> ShareRefusal| Err(Error::Share(refusal(target.into())));
    let components: Vec<&[u8]> = target.as_os_str().as_bytes()[1..]
        .split(|&byte| byte == b'/')
        .collect();
    let mut path = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        path.push(OsStr::from_bytes(component));
        let file = kind == ShareKind::File && index + 1 == components.len();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return refused(ShareRefusal::SymbolicLink);
            }
            Ok(metadata) if file && !metadata.is_file() => return refused(ShareRefusal::NotFile),
            Ok(metadata) if !file && !metadata.is_dir() => {
                return refused(ShareRefusal::NotDirectory);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create(&path, file).map_err(|error| Error::MountPoint {
                    path: path.clone(),
                    error,
                })?;
            }
            Err(error) => return Err(Error::MountPoint { path, error }),
        }
    }
    Ok(path)
}

/// Creates the missing component `path` of a target: an empty regular file with mode 0644 if
/// `file` is set, and otherwise a directory with mode 0755, whatever the process's umask.
fn create(path: &Path, file: bool) -> io::Result<()> {
    let mode = if file {
        // An exclusive creation follows no symbolic link either.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)?;
        0o644
    } else {
        fs::create_dir(path)?;
        0o755
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the refusal of `target`, if it is refused.
    fn refusal(target: &str) -> Option<ShareRefusal> {
        match check_target(Path::new(target)) {
            Ok(()) => None,
            Err(Error::Share(refusal)) => Some(refusal),
            Err(error) => panic!("{target}: {error}"),
        }
    }

    #[test]
    fn targets_are_canonical_absolute_paths_outside_the_runtime_s_mounts() {
        for target in [
            "/workspace",
            "/opt/hostedtoolcache",
            "/a/b/c",
            "/a/...",
            "/.hidden",
            "/etc/app",
            "/etc/machine-ids",
            "/run/app",
            "/run/nvx/state",
            "/run/nvx/timer",
            "/procs",
            "/devices",
            "/.nvx-agents",
        ] {
            assert_eq!(refusal(target), None, "{target}");
        }
        for target in ["workspace", "", "./a"] {
            assert!(
                matches!(refusal(target), Some(ShareRefusal::Relative(_))),
                "{target}"
            );
        }
        for target in [
            "/", "//a", "/a//b", "/a/", "/a/.", "/a/./b", "/a/..", "/../a",
        ] {
            assert!(
                matches!(refusal(target), Some(ShareRefusal::NotCanonical(_))),
                "{target}"
            );
        }
        for target in ["/a\\b", "/a=b", "/a,b"] {
            assert!(
                matches!(refusal(target), Some(ShareRefusal::ReservedCharacter(_))),
                "{target}"
            );
        }
        for target in [
            "/proc",
            "/proc/self",
            "/sys",
            "/sys/fs/cgroup",
            "/dev",
            "/dev/shm",
            "/.nvx-agent",
            "/.nvx-agent/tool",
            "/etc",
            "/etc/machine-id",
            "/etc/machine-id/x",
            "/run",
            "/run/nvx",
            "/run/nvx/time",
            "/run/nvx/time/state",
        ] {
            assert!(
                matches!(refusal(target), Some(ShareRefusal::Reserved(_))),
                "{target}"
            );
        }
    }

    #[test]
    fn tags_and_child_names_are_plain_names() {
        for tag in ["microvm", "a_b-C9"] {
            assert!(check_tag(tag).is_ok(), "{tag}");
        }
        for tag in ["", "a.b", "a b", "a/b", "é"] {
            assert!(check_tag(tag).is_err(), "{tag}");
        }
        for name in ["0", "a.b_C-9", "..."] {
            assert!(check_name(name).is_ok(), "{name}");
        }
        for name in ["", ".", "..", "a/b", "a b", "a,b"] {
            assert!(check_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn mount_points_are_created_with_fixed_modes_and_never_through_links() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let point = mount_point(root, Path::new("/opt/tools"), ShareKind::Directory).unwrap();
        assert_eq!(point, root.join("opt/tools"));
        let point = mount_point(root, Path::new("/etc/app/config"), ShareKind::File).unwrap();
        for (path, mode, directory) in [
            (root.join("opt"), 0o755, true),
            (root.join("opt/tools"), 0o755, true),
            (root.join("etc/app"), 0o755, true),
            (point.clone(), 0o644, false),
        ] {
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.is_dir(), directory, "{}", path.display());
            assert_eq!(
                metadata.permissions().mode() & 0o7777,
                mode,
                "{}",
                path.display()
            );
        }
        // Existing components of the right kinds are kept.
        mount_point(root, Path::new("/etc/app/config"), ShareKind::File).unwrap();
        mount_point(root, Path::new("/opt"), ShareKind::Directory).unwrap();

        std::os::unix::fs::symlink(root.join("opt"), root.join("link")).unwrap();
        let refused = |target: &str, kind| match mount_point(root, Path::new(target), kind) {
            Err(Error::Share(refusal)) => refusal,
            other => panic!("{target}: {other:?}"),
        };
        assert_eq!(
            refused("/link/new", ShareKind::Directory),
            ShareRefusal::SymbolicLink("/link/new".into())
        );
        assert_eq!(
            refused("/link", ShareKind::File),
            ShareRefusal::SymbolicLink("/link".into())
        );
        assert_eq!(
            refused("/etc/app/config/x", ShareKind::Directory),
            ShareRefusal::NotDirectory("/etc/app/config/x".into())
        );
        assert_eq!(
            refused("/opt/tools", ShareKind::File),
            ShareRefusal::NotFile("/opt/tools".into())
        );
        // Nothing is created through the link.
        assert!(!root.join("opt/new").exists());
    }
}
