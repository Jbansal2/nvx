use std::ffi::CStr;
use std::io;

use crate::protocol::{
    EXEC_CWD_PRESENT, EXEC_ENVIRONMENT_PRESENT, EXEC_INHERIT_DEFAULT_ENV, GuestExecPayload,
};

use super::diagnostics::{close, read_exact, write_all};

pub(crate) const EXEC_CWD_ENTERED: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperConfig {
    pub(crate) cwd: Option<Vec<u8>>,
    pub(crate) environment: Option<Vec<Vec<u8>>>,
    pub(crate) inherit_default_env: bool,
    pub(crate) cwd_entered: bool,
}

pub(crate) fn create(execution: &GuestExecPayload, cwd_entered: bool) -> io::Result<libc::c_int> {
    // SAFETY: the name is a static NUL-terminated string.
    let fd = unsafe {
        libc::memfd_create(
            c"nvx-exec-config".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let bytes = encode(execution, cwd_entered)?;
        write_all(fd, &bytes)?;
        // SAFETY: lseek and fcntl operate on the owned memfd.
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if let Err(error) = result {
        close(fd);
        return Err(error);
    }
    Ok(fd)
}

fn encode(execution: &GuestExecPayload, cwd_entered: bool) -> io::Result<Vec<u8>> {
    let mut flags = 0u16;
    let cwd = if cwd_entered {
        flags |= EXEC_CWD_ENTERED;
        None
    } else {
        if execution.cwd.is_some() {
            flags |= EXEC_CWD_PRESENT;
        }
        execution.cwd.as_deref()
    };
    if execution.environment.is_some() {
        flags |= EXEC_ENVIRONMENT_PRESENT;
    }
    if execution.inherit_default_env {
        flags |= EXEC_INHERIT_DEFAULT_ENV;
    }
    let environment = execution.environment.as_deref().unwrap_or_default();
    let count = u16::try_from(environment.len())
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    let cwd_len = u32::try_from(cwd.map_or(0, <[u8]>::len))
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&cwd_len.to_le_bytes());
    if let Some(cwd) = cwd {
        bytes.extend_from_slice(cwd);
    }
    for entry in environment {
        let length = u32::try_from(entry.len())
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(entry);
    }
    Ok(bytes)
}

pub(crate) fn read(fd: libc::c_int) -> io::Result<HelperConfig> {
    let mut header = [0u8; 8];
    read_exact(fd, &mut header)?;
    let flags = u16::from_le_bytes([header[0], header[1]]);
    let environment_count = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let cwd_len = u32::from_le_bytes(header[4..8].try_into().expect("four bytes")) as usize;
    let known =
        EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT | EXEC_INHERIT_DEFAULT_ENV | EXEC_CWD_ENTERED;
    let cwd_entered = flags & EXEC_CWD_ENTERED != 0;
    if flags & !known != 0
        || (cwd_entered && flags & EXEC_CWD_PRESENT != 0)
        || environment_count > crate::protocol::MAX_ENVIRONMENT
        || (flags & EXEC_CWD_PRESENT == 0 && cwd_len != 0)
        || (flags & EXEC_CWD_PRESENT != 0
            && !(1..=crate::protocol::MAX_ARGUMENT_BYTES).contains(&cwd_len))
        || (flags & EXEC_ENVIRONMENT_PRESENT == 0
            && (environment_count != 0 || flags & EXEC_INHERIT_DEFAULT_ENV != 0))
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let cwd = if cwd_len == 0 {
        None
    } else {
        let mut cwd = vec![0; cwd_len];
        read_exact(fd, &mut cwd)?;
        Some(cwd)
    };
    let mut environment = Vec::with_capacity(environment_count);
    for _ in 0..environment_count {
        let mut length = [0u8; 4];
        read_exact(fd, &mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if !(1..=crate::protocol::MAX_ARGUMENT_BYTES).contains(&length) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut entry = vec![0; length];
        read_exact(fd, &mut entry)?;
        if entry.contains(&0) || entry.first() == Some(&b'=') || !entry.contains(&b'=') {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        environment.push(entry);
    }
    Ok(HelperConfig {
        cwd,
        environment: (flags & EXEC_ENVIRONMENT_PRESENT != 0).then_some(environment),
        inherit_default_env: flags & EXEC_INHERIT_DEFAULT_ENV != 0,
        cwd_entered,
    })
}

pub(crate) fn descriptor(text: &CStr) -> io::Result<libc::c_int> {
    let mut end = std::ptr::null_mut();
    // SAFETY: `text` is NUL-terminated, and `end` receives a pointer into it.
    let value = unsafe {
        *libc::__errno_location() = 0;
        libc::strtol(text.as_ptr(), &mut end, 10)
    };
    // SAFETY: errno is thread-local and `end` points into `text`.
    let status = unsafe { *libc::__errno_location() };
    if status != 0
        || end == text.as_ptr().cast_mut()
        || unsafe { *end } != 0
        || value < 0
        || value > i64::from(i32::MAX)
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(value as libc::c_int)
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::os::fd::IntoRawFd;

    use super::*;

    fn execution() -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/true".to_vec()],
            cwd: Some(b"/tmp".to_vec()),
            environment: Some(vec![b"EMPTY=".to_vec(), b"VALUE=space = value".to_vec()]),
            inherit_default_env: false,
        }
    }

    fn file_with(bytes: &[u8]) -> libc::c_int {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.rewind().unwrap();
        file.into_raw_fd()
    }

    #[test]
    fn helper_configuration_round_trips_empty_exact_and_large_environments() {
        for environment in [
            Vec::new(),
            vec![b"EMPTY=".to_vec(), b"VALUE=space = value".to_vec()],
            (0..12)
                .map(|index| {
                    let mut entry = format!("KEY{index}=").into_bytes();
                    entry.extend(std::iter::repeat_n(b'x', 4000));
                    entry
                })
                .collect(),
        ] {
            let mut execution = execution();
            execution.environment = Some(environment.clone());
            let fd = create(&execution, false).unwrap();
            let decoded = read(fd).unwrap();
            assert_eq!(decoded.cwd, execution.cwd);
            assert_eq!(decoded.environment, Some(environment));
            assert!(!decoded.cwd_entered);
            close(fd);
        }
    }

    #[test]
    fn helper_configuration_marks_an_entered_directory_and_is_sealed() {
        let execution = execution();
        let fd = create(&execution, true).unwrap();
        // SAFETY: fcntl reads seals from the valid memfd.
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        let expected =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(seals & expected, expected);
        let decoded = read(fd).unwrap();
        assert!(decoded.cwd_entered);
        assert_eq!(decoded.cwd, None);
        close(fd);
    }

    #[test]
    fn helper_defensively_rejects_unknown_flags_and_malformed_environment() {
        for bytes in [
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&0x4000u16.to_le_bytes());
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&EXEC_ENVIRONMENT_PRESENT.to_le_bytes());
                bytes.extend_from_slice(&1u16.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes.extend_from_slice(&9u32.to_le_bytes());
                bytes.extend_from_slice(b"NO_EQUALS");
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&EXEC_ENVIRONMENT_PRESENT.to_le_bytes());
                bytes.extend_from_slice(&1u16.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes.extend_from_slice(&6u32.to_le_bytes());
                bytes.extend_from_slice(b"=value");
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&EXEC_CWD_ENTERED.to_le_bytes());
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.extend_from_slice(&1u32.to_le_bytes());
                bytes.push(b'/');
                bytes
            },
        ] {
            let fd = file_with(&bytes);
            assert!(read(fd).is_err(), "{bytes:?}");
            close(fd);
        }
    }

    #[test]
    fn helper_descriptor_parser_matches_strtol_boundaries() {
        for (text, expected) in [
            (c"0", Some(0)),
            (c"+7", Some(7)),
            (c" 42", Some(42)),
            (c"2147483647", Some(i32::MAX)),
            (c"-1", None),
            (c"", None),
            (c"1x", None),
            (c"2147483648", None),
        ] {
            assert_eq!(descriptor(text).ok(), expected, "{text:?}");
        }
    }
}
