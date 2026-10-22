//! The block devices that the VMM attaches in the root's roles, which the base addresses of their
//! MMIO windows name.
//!
//! The VMM declares each device on the kernel command line, so the kernel names its MMIO window
//! `virtio-mmio.N` in `/proc/iomem`, and creates its block device below the window's device in
//! `/sys/devices/virtio-mmio-cmdline`.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::kernel::{Kernel, Paths};
use super::{Device, DeviceStep, Error, Role};
use crate::guest::parse::{parse_decimal, parse_hexadecimal};
use crate::guest::sys;
use crate::uuid::Uuid;

/// The interval between two polls for a block device that has not appeared yet.
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// The prefix of the name of a virtio MMIO window in `/proc/iomem`.
const WINDOW_PREFIX: &[u8] = b"virtio-mmio.";
/// The directory, below sysfs, of the virtio MMIO devices that the kernel command line declares.
const WINDOW_DEVICES: &str = "devices/virtio-mmio-cmdline";
/// The byte offset of the EROFS superblock on its device.
const EROFS_SUPERBLOCK: u64 = 1024;
/// The EROFS superblock's magic number, which it starts with, little-endian.
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
/// The range of the file system's UUID in the EROFS superblock.
const EROFS_UUID: std::ops::Range<usize> = 48..64;

/// Finds the block device of `role` that the VMM attached at `device`'s MMIO window, polling
/// until it appears for as long as `timeout` allows, checks its size if the caller expects one,
/// and flushes its buffers, so that later reads come from the device. Returns the path of its
/// node.
pub(super) fn prepare(
    kernel: &mut dyn Kernel,
    paths: &Paths,
    role: Role,
    device: Device,
    timeout: Duration,
) -> Result<PathBuf, Error> {
    let (name, path) = resolve(kernel, paths, role, device.mmio, timeout)?;
    if let Some(expected) = device.sectors {
        let size = paths.sys.join("class/block").join(&name).join("size");
        let actual = fs::read(&size)
            .and_then(|text| parse_count(&text))
            .map_err(|error| Error::Device {
                role,
                step: DeviceStep::Size,
                device: path.clone(),
                error,
            })?;
        if actual != expected {
            return Err(Error::Size {
                role,
                device: path,
                expected,
                actual,
            });
        }
    }
    let flushed = sys::path_c_string(&path).and_then(|device| kernel.flush(&device));
    flushed.map_err(|error| Error::Device {
        role,
        step: DeviceStep::Flush,
        device: path.clone(),
        error: error.into(),
    })?;
    Ok(path)
}

/// Returns the name and the node of the block device that the VMM attached at `mmio`, polling
/// for it every [`POLL_INTERVAL`] while `timeout` allows another poll.
fn resolve(
    kernel: &mut dyn Kernel,
    paths: &Paths,
    role: Role,
    mmio: u64,
    timeout: Duration,
) -> Result<(String, PathBuf), Error> {
    let polls = timeout.as_millis() / POLL_INTERVAL.as_millis() + 1;
    for poll in 0..polls {
        if poll > 0 {
            kernel.sleep(POLL_INTERVAL);
        }
        let found = find(paths, mmio).map_err(|error| Error::Lookup { role, mmio, error })?;
        if let Some(name) = found {
            let node = paths.dev.join(&name);
            // The kernel creates the node right after the device's sysfs directory.
            if fs::symlink_metadata(&node).is_ok() {
                return Ok((name, node));
            }
        }
    }
    Err(Error::Missing { role, mmio })
}

/// Returns the name of the block device below the virtio MMIO window at `mmio`, or `None` while
/// the kernel lists no such window, or has not probed it yet.
fn find(paths: &Paths, mmio: u64) -> io::Result<Option<String>> {
    let windows = fs::read(paths.proc.join("iomem"))?;
    for line in windows.split(|&byte| byte == b'\n') {
        // `START-END : NAME`, indented below the window that holds it.
        let mut fields = line
            .split(|&byte| byte == b' ')
            .filter(|field| !field.is_empty());
        let (Some(range), Some(b":"), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let start = range.split(|&byte| byte == b'-').next().unwrap_or(range);
        if parse_hexadecimal(start) != Some(mmio) || !name.starts_with(WINDOW_PREFIX) {
            continue;
        }
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        if let Some(block) = block_device(&paths.sys.join(WINDOW_DEVICES).join(name))? {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

/// Returns the name of the first block device, in byte order, of the first virtio device of the
/// window device `window`, or `None` while there is none.
fn block_device(window: &Path) -> io::Result<Option<String>> {
    for device in sorted_entries(window)? {
        if !device.starts_with("virtio") {
            continue;
        }
        if let Some(block) = sorted_entries(&window.join(&device).join("block"))?
            .into_iter()
            .next()
        {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

/// Returns the names of the entries of `directory` that are UTF-8, in byte order, or none if it
/// does not exist yet.
fn sorted_entries(directory: &Path) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut names = Vec::new();
    for entry in entries {
        if let Ok(name) = entry?.file_name().into_string() {
            names.push(name);
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// Parses the canonical decimal count of a sysfs attribute and its newline, such as a block
/// device's size in 512-byte sectors.
fn parse_count(text: &[u8]) -> io::Result<u64> {
    text.strip_suffix(b"\n")
        .and_then(parse_decimal)
        .ok_or_else(|| io::Error::from(sys::Errno::EPROTO))
}

/// Reads the UUID of the EROFS file system on the block device `device` from its superblock, and
/// nothing else, or returns `None` if the device holds no EROFS superblock.
pub(super) fn erofs_uuid(device: &Path) -> io::Result<Option<Uuid>> {
    let mut superblock = [0; EROFS_UUID.end];
    match File::open(device)?.read_exact_at(&mut superblock, EROFS_SUPERBLOCK) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let magic = u32::from_le_bytes(superblock[..4].try_into().expect("four bytes"));
    if magic != EROFS_MAGIC {
        return Ok(None);
    }
    Ok(Some(Uuid::from_bytes(
        superblock[EROFS_UUID]
            .try_into()
            .expect("a UUID is 16 bytes"),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_canonical_decimal_counts() {
        assert_eq!(parse_count(b"2048\n").unwrap(), 2048);
        assert_eq!(parse_count(b"0\n").unwrap(), 0);
        for text in [&b"2048"[..], b"", b"\n", b" 1\n", b"0x10\n", b"1\n\n"] {
            assert!(parse_count(text).is_err(), "{}", text.escape_ascii());
        }
    }

    #[test]
    fn the_superblock_names_an_erofs_uuid_or_none() {
        let temporary = tempfile::tempdir().unwrap();
        let device = temporary.path().join("device");
        let uuid: [u8; 16] = std::array::from_fn(|index| index as u8 + 1);
        let mut image = vec![0u8; 4096];
        image[1024..1028].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        image[1024 + 48..1024 + 64].copy_from_slice(&uuid);
        fs::write(&device, &image).unwrap();
        assert_eq!(erofs_uuid(&device).unwrap(), Some(Uuid::from_bytes(uuid)));
        // Another magic number, or a device too short for a superblock, holds no EROFS.
        image[1024] ^= 1;
        fs::write(&device, &image).unwrap();
        assert_eq!(erofs_uuid(&device).unwrap(), None);
        fs::write(&device, &image[..1060]).unwrap();
        assert_eq!(erofs_uuid(&device).unwrap(), None);
        assert_eq!(
            erofs_uuid(&temporary.path().join("missing"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
