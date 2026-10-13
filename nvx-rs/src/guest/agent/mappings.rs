use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::protocol::{self, GuestHostMap};

use super::diagnostics::{c_string, close, errno};
use super::seam::{System, path_c_string};

#[derive(Default)]
pub(crate) struct HostMappings {
    pub(crate) expected: u32,
    pub(crate) applied: u32,
    pub(crate) failed: bool,
}

#[derive(Debug)]
pub(crate) enum MappingError {
    Invalid,
    Mount { status: i32, entry: u32 },
}

pub(crate) fn prepare(system: &mut impl System, mappings: &mut HostMappings) -> io::Result<()> {
    let mut command_line = [0u8; 4096];
    let mut file = std::fs::File::open(&system.paths().proc_cmdline)?;
    let count = file.read(&mut command_line[..4095])?;
    mappings.expected = protocol::parse_host_mapping_count(&command_line[..count])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let hostfs = system.paths().hostfs_dir.clone();
    let root = hostfs.join("root");
    let mounted = match (std::fs::metadata(&hostfs), std::fs::metadata(&root)) {
        (Ok(parent), Ok(export)) => parent.dev() != export.dev(),
        _ => false,
    };
    if mounted {
        let hostfs = path_c_string(&hostfs)?;
        system.chown(&hostfs, 0, 0)?;
        system.chmod(&hostfs, 0o700)?;
    }
    if mappings.expected != 0 && !mounted {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    Ok(())
}

pub(crate) fn apply_request(
    system: &mut impl System,
    mappings: &mut HostMappings,
    payload: &[u8],
) -> Result<(), MappingError> {
    if mappings.failed {
        return Err(MappingError::Invalid);
    }
    let request =
        protocol::decode_guest_maps_payload(payload).map_err(|_| MappingError::Invalid)?;
    let count = u32::try_from(request.maps.len()).map_err(|_| MappingError::Invalid)?;
    if request.first != mappings.applied
        || count == 0
        || mappings.applied > mappings.expected
        || count > mappings.expected - mappings.applied
    {
        return Err(MappingError::Invalid);
    }
    for (offset, mapping) in request.maps.iter().enumerate() {
        if let Err(error) = apply(system, mapping) {
            mappings.failed = true;
            return Err(MappingError::Mount {
                status: errno(&error),
                entry: request.first + offset as u32,
            });
        }
        mappings.applied += 1;
    }
    Ok(())
}

fn apply(system: &mut impl System, mapping: &GuestHostMap) -> io::Result<()> {
    let root = system.paths().hostfs_dir.join("root");
    let source = append_bytes(&root, &mapping.source);
    let target = PathBuf::from(std::ffi::OsStr::from_bytes(&mapping.target));
    let metadata = std::fs::symlink_metadata(&source)?;
    if metadata.file_type().is_dir() {
        make_directories(&target, true)?;
    } else if metadata.file_type().is_file() {
        make_directories(&target, false)?;
        match std::fs::symlink_metadata(&target) {
            Ok(existing) if existing.file_type().is_file() => {}
            Ok(_) => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => create_file(&target)?,
            Err(error) => return Err(error),
        }
    } else {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let source = path_c_string(&source)?;
    let target = path_c_string(&target)?;
    system.mount(Some(&source), &target, None, libc::MS_BIND as libc::c_ulong)?;
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
    if mapping.read_only {
        flags |= libc::MS_RDONLY;
    }
    system.mount(None, &target, None, flags as libc::c_ulong)
}

fn append_bytes(root: &Path, suffix: &[u8]) -> PathBuf {
    let mut bytes = root.as_os_str().as_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(suffix);
    PathBuf::from(std::ffi::OsStr::from_bytes(&bytes))
}

fn make_directories(path: &Path, include_last: bool) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    for index in 1..=bytes.len() {
        if bytes.get(index) == Some(&b'/') || (index == bytes.len() && include_last) {
            let directory = c_string(&bytes[..index])?;
            // SAFETY: `directory` is NUL-terminated.
            let result = unsafe { libc::mkdir(directory.as_ptr(), 0o755) };
            if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn create_file(path: &Path) -> io::Result<()> {
    let path = path_c_string(path)?;
    // SAFETY: `path` is NUL-terminated and the variadic mode accompanies O_CREAT.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o644,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    close(fd);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn setup(expected: u32) -> (tempfile::TempDir, TestSystem, HostMappings) {
        let temporary = tempfile::tempdir().unwrap();
        let hostfs = temporary.path().join("hostfs");
        std::fs::create_dir_all(hostfs.join("root/0/src")).unwrap();
        std::fs::write(hostfs.join("root/0/notes.txt"), b"notes").unwrap();
        std::fs::create_dir(hostfs.join("root/1")).unwrap();
        let paths = Paths {
            hostfs_dir: hostfs,
            ..Paths::default()
        };
        (
            temporary,
            TestSystem::new(paths),
            HostMappings {
                expected,
                ..HostMappings::default()
            },
        )
    }

    fn payload(first: u32, entries: &[(&[u8], &[u8], u16)], count: Option<u32>) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&first.to_le_bytes());
        payload.extend_from_slice(&count.unwrap_or(entries.len() as u32).to_le_bytes());
        for (source, target, flags) in entries {
            payload.extend_from_slice(&flags.to_le_bytes());
            payload.extend_from_slice(&(source.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(target.len() as u16).to_le_bytes());
            payload.extend_from_slice(source);
            payload.extend_from_slice(target);
        }
        payload
    }

    #[test]
    fn mappings_mount_in_order_and_unblock_workloads() {
        let (temporary, mut system, mut mappings) = setup(3);
        let guest = temporary.path().join("guest");
        let source = guest.join("src");
        let notes = guest.join("src/notes.txt");
        let out = guest.join("out");
        let first = payload(
            0,
            &[
                (
                    b"0/src",
                    source.as_os_str().as_bytes(),
                    protocol::MAP_READ_ONLY,
                ),
                (b"0/notes.txt", notes.as_os_str().as_bytes(), 0),
            ],
            None,
        );
        apply_request(&mut system, &mut mappings, &first).unwrap();
        assert_eq!((mappings.applied, mappings.expected), (2, 3));
        let second = payload(2, &[(b"1", out.as_os_str().as_bytes(), 0)], None);
        apply_request(&mut system, &mut mappings, &second).unwrap();
        assert_eq!((mappings.applied, mappings.expected), (3, 3));
        assert_eq!(system.mounts.len(), 6);
        assert_eq!(
            system.mounts[1].2,
            (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_RDONLY)
                as libc::c_ulong
        );
        assert!(source.is_dir());
        assert!(notes.is_file());
        assert!(out.is_dir());
    }

    #[test]
    fn entries_beyond_the_announcement_or_out_of_order_are_refused() {
        let (temporary, mut system, mut mappings) = setup(1);
        let target = temporary.path().join("guest/src");
        let entry = [(b"0/src".as_slice(), target.as_os_str().as_bytes(), 0)];
        for invalid in [payload(1, &entry, None), payload(0, &entry, Some(2))] {
            assert!(matches!(
                apply_request(&mut system, &mut mappings, &invalid),
                Err(MappingError::Invalid)
            ));
        }
        apply_request(&mut system, &mut mappings, &payload(0, &entry, None)).unwrap();
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &payload(1, &entry, None)),
            Err(MappingError::Invalid)
        ));
        assert_eq!(system.mounts.len(), 2);
    }

    #[test]
    fn malformed_tables_mount_nothing() {
        let (temporary, mut system, mut mappings) = setup(2);
        let target = temporary.path().join("guest/x");
        let good = (b"0/src".as_slice(), target.as_os_str().as_bytes(), 0);
        let malformed = [
            payload(
                0,
                &[good, (b"0/../1", target.as_os_str().as_bytes(), 0)],
                None,
            ),
            payload(
                0,
                &[good, (b"/0/src", target.as_os_str().as_bytes(), 0)],
                None,
            ),
            payload(0, &[good, (b"0/src", b"relative", 0)], None),
            payload(0, &[good, (b".", target.as_os_str().as_bytes(), 0)], None),
            payload(
                0,
                &[good, (b"0//src", target.as_os_str().as_bytes(), 0)],
                None,
            ),
            payload(
                0,
                &[good, (b"0/src", target.as_os_str().as_bytes(), 2)],
                None,
            ),
            payload(0, &[], Some(0)),
            vec![0, 0, 0],
        ];
        for payload in malformed {
            assert!(matches!(
                apply_request(&mut system, &mut mappings, &payload),
                Err(MappingError::Invalid)
            ));
        }
        assert!(system.mounts.is_empty());
        assert_eq!(mappings.applied, 0);
    }

    #[test]
    fn without_an_announcement_tables_are_refused() {
        let (temporary, mut system, mut mappings) = setup(0);
        let target = temporary.path().join("guest/src");
        let request = payload(0, &[(b"0/src", target.as_os_str().as_bytes(), 0)], None);
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &request),
            Err(MappingError::Invalid)
        ));
        assert!(system.mounts.is_empty());
    }

    #[test]
    fn a_failed_mount_latches_and_keeps_refusing_tables() {
        let (temporary, mut system, mut mappings) = setup(2);
        system.fail_mount_call = Some(1);
        let target = temporary.path().join("guest/src");
        let request = payload(0, &[(b"0/src", target.as_os_str().as_bytes(), 0)], None);
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &request),
            Err(MappingError::Mount {
                status: libc::ENOENT,
                entry: 0
            })
        ));
        assert!(mappings.failed);
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &request),
            Err(MappingError::Invalid)
        ));
        assert_eq!(mappings.applied, 0);
    }
}
