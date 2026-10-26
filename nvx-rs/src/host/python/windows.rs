//! The Win32 calls with which CPython's `nt` module reads links, finds the names of files, and
//! asks for final path names, for the `Path.resolve()` of [`super::fs`].
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::{mem, ptr};

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FindClose,
    FindFirstFileW, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// The reparse tag of a symbolic link.
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// The reparse tag of a junction, or mount point.
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// The control code that reads a reparse point's data (`winioctl.h`).
const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
/// The largest reparse point that `FSCTL_GET_REPARSE_POINT` returns.
const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;

/// Returns the NUL-terminated UTF-16 form of `path`, refusing an embedded NUL as Python does.
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded null character in path",
        ));
    }
    units.push(0);
    Ok(units)
}

/// Returns the calling thread's last Win32 error.
fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

/// Returns the error with Win32 error code `code`.
fn error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Opens `path` with `access`, `share`, and `flags`, or returns the Win32 error code.
fn open(path: &[u16], access: u32, share: u32, flags: u32) -> Result<OwnedHandle, u32> {
    // SAFETY: `path` is NUL-terminated, and the other arguments are plain values or null.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(last_error())
    } else {
        // SAFETY: the handle was just opened, and nothing else owns it.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}

/// Borrows `handle` in the form that `windows-sys` takes.
fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

/// The real name of a file, as `FindFirstFileW` gives it.
struct FindData {
    /// The name of the file as the directory holds it.
    name: Vec<u16>,
}

/// Calls `FindFirstFileW` for `path`, which must be NUL-terminated, or returns the Win32 error.
fn find_first_file(path: &[u16]) -> Result<FindData, u32> {
    // SAFETY: WIN32_FIND_DATAW is plain data, for which all-zero bytes are valid.
    let mut data: WIN32_FIND_DATAW = unsafe { mem::zeroed() };
    // SAFETY: the path is NUL-terminated and the output pointer is valid.
    let handle = unsafe { FindFirstFileW(path.as_ptr(), &mut data) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: the handle is a find handle that was just opened.
    unsafe { FindClose(handle) };
    let length = data
        .cFileName
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(data.cFileName.len());
    Ok(FindData {
        name: data.cFileName[..length].to_vec(),
    })
}

/// Returns `nt._getfinalpathname(path)`: the path that Windows gives for the file, with its
/// `\\?\` prefix.
pub(crate) fn final_path_name(path: &Path) -> io::Result<String> {
    let path = wide(path)?;
    let handle = open(&path, 0, 0, FILE_FLAG_BACKUP_SEMANTICS).map_err(error)?;
    let mut buffer = vec![0u16; 260];
    loop {
        // SAFETY: the handle is open and the buffer holds `buffer.len()` units.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                raw(&handle),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_DOS,
            )
        } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length < buffer.len() {
            buffer.truncate(length);
            break;
        }
        buffer.resize(length, 0);
    }
    String::from_utf16(&buffer).map_err(|_| super::not_unicode("a final path name"))
}

/// Returns `nt._findfirstfile(path)`: the name of the file as its directory holds it.
pub(crate) fn find_first_file_name(path: &Path) -> io::Result<String> {
    let data = find_first_file(&wide(path)?).map_err(error)?;
    String::from_utf16(&data.name).map_err(|_| super::not_unicode("a file name"))
}

/// Returns `nt.readlink(path)`: the substitute name of a symbolic link or junction, with `\??\`
/// turned into `\\?\`, or `None` for another kind of reparse point.
pub(crate) fn read_link(path: &Path) -> io::Result<Option<String>> {
    let path = wide(path)?;
    let handle = open(
        &path,
        0,
        0,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
    )
    .map_err(error)?;
    let mut buffer = vec![0u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    let mut returned = 0u32;
    // SAFETY: the handle is open, there is no input buffer, and the output buffer holds
    // `buffer.len()` bytes.
    let ok = unsafe {
        DeviceIoControl(
            raw(&handle),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let data = &buffer[..(returned as usize).min(buffer.len())];
    let u16_at = |offset: usize| -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(
            data.get(offset..offset + 2)?.try_into().ok()?,
        )))
    };
    let tag = data.get(..4).map_or(0, |bytes| {
        u32::from_le_bytes(bytes.try_into().unwrap_or_default())
    });
    // The substitute name follows the fixed fields of REPARSE_DATA_BUFFER: a symbolic link has
    // flags before its path buffer, and a junction does not.
    let path_buffer = match tag {
        IO_REPARSE_TAG_SYMLINK => 20,
        IO_REPARSE_TAG_MOUNT_POINT => 16,
        _ => return Ok(None),
    };
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed reparse point");
    let (offset, length) = (
        u16_at(8).ok_or_else(malformed)?,
        u16_at(10).ok_or_else(malformed)?,
    );
    let start = path_buffer + offset;
    let bytes = data.get(start..start + length).ok_or_else(malformed)?;
    let mut name: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let nt_prefix = ['\\', '?', '?', '\\'].map(|c| c as u16);
    if name.len() > 4 && name[..4] == nt_prefix {
        name[1] = u16::from(b'\\');
    }
    String::from_utf16(&name)
        .map(Some)
        .map_err(|_| super::not_unicode("a symbolic link's target"))
}
