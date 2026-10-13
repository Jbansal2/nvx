//! Runs numbered procfs snapshots through the collector.

use std::ffi::{CStr, CString, OsString};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::FIRST_SOURCE_PORT;
use super::collect::{self, Collector, DiagnosticInput};

pub(super) fn run(directory: &CStr, out: &mut dyn Write) -> u8 {
    let mut collector = Collector::new();
    let mut index = 0_u32;
    loop {
        let Some(root) = snapshot_root(directory.to_bytes(), index) else {
            return 1;
        };
        let Some(time_path) = path_with_limit(&root, "/time", 4200) else {
            return 1;
        };
        let now = match read_time(&time_path) {
            TimeFile::Value(now) => now,
            TimeFile::Missing => return u8::from(index == 0),
            TimeFile::Malformed => return 1,
        };
        let ipv6_dual_stack = collect::read_bindv6only(&root, true);
        let payload = collector.collect_files(
            &root,
            DiagnosticInput::Snapshot,
            FIRST_SOURCE_PORT,
            now,
            ipv6_dual_stack,
        );
        let mut line = format!("{now} ").into_bytes();
        for byte in payload {
            line.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        line.push(b'\n');
        super::super::sys::report(out, &[&line]);
        index = index.wrapping_add(1);
    }
}

fn snapshot_root(directory: &[u8], index: u32) -> Option<PathBuf> {
    let index = index.to_string();
    if directory.len() + 1 + index.len() >= 4096 {
        return None;
    }
    let mut root = Vec::with_capacity(directory.len() + 1 + index.len());
    root.extend_from_slice(directory);
    root.push(b'/');
    root.extend_from_slice(index.as_bytes());
    Some(PathBuf::from(OsString::from_vec(root)))
}

fn path_with_limit(root: &Path, suffix: &str, capacity: usize) -> Option<PathBuf> {
    if root.as_os_str().as_bytes().len() + suffix.len() >= capacity {
        None
    } else {
        Some(root.join(suffix.trim_start_matches('/')))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TimeFile {
    Missing,
    Malformed,
    Value(u64),
}

fn read_time(path: &Path) -> TimeFile {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return TimeFile::Missing;
    };
    // SAFETY: both strings are NUL-terminated, and `fopen` retains neither pointer.
    let file = unsafe { libc::fopen(path.as_ptr(), c"re".as_ptr()) };
    if file.is_null() {
        return TimeFile::Missing;
    }
    let mut now: libc::c_ulonglong = 0;
    // SAFETY: `file` is open and `%llu` exactly matches the writable pointer.
    let parsed = unsafe { libc::fscanf(file, c"%llu".as_ptr(), &mut now) };
    // SAFETY: `file` is open and no longer used.
    unsafe { libc::fclose(file) };
    if parsed == 1 {
        TimeFile::Value(now as u64)
    } else {
        TimeFile::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_paths_enforce_the_c_buffers_in_bytes() {
        assert!(snapshot_root(&vec![b'a'; 4093], 0).is_some());
        assert!(snapshot_root(&vec![b'a'; 4094], 0).is_none());
        let root = snapshot_root(b"directory", 12).unwrap();
        assert_eq!(root.as_os_str().as_bytes(), b"directory/12");
    }

    #[test]
    fn time_uses_fscanf_decimal_prefix_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("time");
        std::fs::write(&path, b" \t+123trailing").unwrap();
        assert_eq!(read_time(&path), TimeFile::Value(123));
        std::fs::write(&path, b"-1\n").unwrap();
        assert_eq!(read_time(&path), TimeFile::Value(u64::MAX));
        std::fs::write(&path, b"bad").unwrap();
        assert_eq!(read_time(&path), TimeFile::Malformed);
        assert_eq!(
            read_time(&directory.path().join("missing")),
            TimeFile::Missing
        );
    }
}
