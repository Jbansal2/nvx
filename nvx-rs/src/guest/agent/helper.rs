use std::ffi::CString;
use std::io;

use super::diagnostics::{c_string, close, errno, strerror, write_stderr};
use super::exec_config;
use super::seam::System;

pub(crate) fn run(system: &mut impl System, arguments: &[CString]) -> u8 {
    match run_inner(system, arguments) {
        Ok(()) => 0,
        Err(()) => 125,
    }
}

fn run_inner(system: &mut impl System, arguments: &[CString]) -> Result<(), ()> {
    if arguments.len() < 5
        || arguments[1].as_bytes() != b"--exec-config-fd"
        || arguments[3].as_bytes() != b"--"
        || arguments[4].as_bytes().first() != Some(&b'/')
    {
        return Err(());
    }
    let descriptor = exec_config::descriptor(&arguments[2]).map_err(|_| ())?;
    let config = exec_config::read(descriptor).map_err(|_| ())?;
    close(descriptor);
    if let Some(cwd) = &config.cwd
        && (cwd.first() != Some(&b'/') || cwd.contains(&0))
    {
        write_stderr(b"nvx-managed-agent: invalid working directory\n");
        return Err(());
    }
    system.unset_env(c"NVX_EXEC_CONFIG_FD").map_err(|_| ())?;
    if !config.cwd_entered {
        let directory = config.cwd.as_deref().unwrap_or(b"/");
        let directory_c = c_string(directory).map_err(|_| ())?;
        // SAFETY: `directory_c` is NUL-terminated.
        if unsafe { libc::chdir(directory_c.as_ptr()) } != 0 {
            let status = super::diagnostics::last_errno();
            let mut message = b"nvx-managed-agent: cannot use working directory ".to_vec();
            message.extend_from_slice(directory);
            message.extend_from_slice(b": ");
            message.extend_from_slice(&strerror(status));
            message.push(b'\n');
            write_stderr(&message);
            return Err(());
        }
        if (config.environment.is_none() || config.inherit_default_env)
            && set_pwd(system, directory).is_err()
        {
            let status = super::diagnostics::last_errno();
            let mut message =
                b"nvx-managed-agent: cannot configure working directory environment: ".to_vec();
            message.extend_from_slice(&strerror(status));
            message.push(b'\n');
            write_stderr(&message);
            return Err(());
        }
    }
    if let Some(environment) = &config.environment {
        if !config.inherit_default_env {
            system.clear_env().map_err(|_| ())?;
        }
        for entry in environment {
            let equals = entry.iter().position(|&byte| byte == b'=').ok_or(())?;
            let name = c_string(&entry[..equals]).map_err(|_| ())?;
            let value = c_string(&entry[equals + 1..]).map_err(|_| ())?;
            system.set_env(&name, &value).map_err(|_| ())?;
        }
    }
    let mut pointers: Vec<*const libc::c_char> = arguments[4..]
        .iter()
        .map(|argument| argument.as_ptr())
        .collect();
    pointers.push(std::ptr::null());
    if let Err(error) = system.exec(&arguments[4], &pointers) {
        let mut message = b"nvx-managed-agent: cannot execute workload: ".to_vec();
        message.extend_from_slice(&strerror(errno(&error)));
        message.push(b'\n');
        write_stderr(&message);
        return Err(());
    }
    Ok(())
}

fn set_pwd(system: &mut impl System, directory: &[u8]) -> io::Result<()> {
    let pwd = if directory == b"/" || safe_path(directory) {
        directory.to_vec()
    } else {
        let mut buffer = vec![0u8; crate::protocol::MAX_ARGUMENT_BYTES];
        // SAFETY: getcwd writes at most the buffer length and NUL-terminates on success.
        let result = unsafe { libc::getcwd(buffer.as_mut_ptr().cast(), buffer.len()) };
        if result.is_null() {
            return Err(io::Error::last_os_error());
        }
        let length = buffer
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ERANGE))?;
        buffer.truncate(length);
        buffer
    };
    system.set_env(c"PWD", &c_string(&pwd)?)
}

pub(crate) fn safe_path(path: &[u8]) -> bool {
    let Some(components) = path.strip_prefix(b"/") else {
        return false;
    };
    !components.is_empty()
        && components
            .split(|&byte| byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".."))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::os::fd::IntoRawFd;

    use crate::protocol::{self, GuestExecPayload};

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn execution(environment: Option<Vec<Vec<u8>>>, inherit: bool) -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/true".to_vec()],
            cwd: None,
            environment,
            inherit_default_env: inherit,
        }
    }

    fn arguments(fd: libc::c_int, workload: &[&[u8]]) -> Vec<CString> {
        let mut arguments = vec![
            c_string(b"nvx-managed-agent").unwrap(),
            c_string(b"--exec-config-fd").unwrap(),
            CString::new(fd.to_string()).unwrap(),
            c_string(b"--").unwrap(),
        ];
        arguments.extend(workload.iter().map(|argument| c_string(argument).unwrap()));
        arguments
    }

    fn file_with(bytes: &[u8]) -> libc::c_int {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.rewind().unwrap();
        file.into_raw_fd()
    }

    #[test]
    fn helper_applies_exact_empty_and_layered_environments() {
        for (environment, inherit, expected_clear) in [
            (Vec::new(), false, 1),
            (vec![b"VALUE=layered".to_vec()], true, 0),
        ] {
            let fd =
                exec_config::create(&execution(Some(environment.clone()), inherit), true).unwrap();
            let mut system = TestSystem::new(Paths::default());
            assert_eq!(run(&mut system, &arguments(fd, &[b"/usr/bin/env"])), 0);
            assert_eq!(system.clear_count, expected_clear);
            assert_eq!(
                system.environment,
                environment
                    .iter()
                    .map(|entry| {
                        let at = entry.iter().position(|&byte| byte == b'=').unwrap();
                        (entry[..at].to_vec(), entry[at + 1..].to_vec())
                    })
                    .collect::<Vec<_>>()
            );
            assert_eq!(system.unset, [b"NVX_EXEC_CONFIG_FD".to_vec()]);
            assert_eq!(system.execs.len(), 1);
        }
    }

    #[test]
    fn helper_rejects_bad_syntax_relative_cwd_and_conflicting_cwd_flags() {
        let mut system = TestSystem::new(Paths::default());
        assert_eq!(run(&mut system, &[c_string(b"agent").unwrap()]), 125);
        assert!(system.execs.is_empty());

        let mut relative = Vec::new();
        relative.extend_from_slice(&protocol::EXEC_CWD_PRESENT.to_le_bytes());
        relative.extend_from_slice(&0u16.to_le_bytes());
        relative.extend_from_slice(&1u32.to_le_bytes());
        relative.push(b'.');
        let fd = file_with(&relative);
        assert_eq!(run(&mut system, &arguments(fd, &[b"/bin/pwd"])), 125);

        let mut conflicting = Vec::new();
        conflicting.extend_from_slice(
            &(protocol::EXEC_CWD_PRESENT | exec_config::EXEC_CWD_ENTERED).to_le_bytes(),
        );
        conflicting.extend_from_slice(&0u16.to_le_bytes());
        conflicting.extend_from_slice(&1u32.to_le_bytes());
        conflicting.push(b'/');
        let fd = file_with(&conflicting);
        assert_eq!(run(&mut system, &arguments(fd, &[b"/bin/pwd"])), 125);
        assert!(system.execs.is_empty());
    }

    #[test]
    fn helper_does_not_exec_when_an_environment_export_fails() {
        let fd = exec_config::create(
            &execution(Some(vec![b"VALUE=layered".to_vec()]), true),
            true,
        )
        .unwrap();
        let mut system = TestSystem::new(Paths::default());
        system.fail_environment = Some(b"VALUE".to_vec());
        assert_eq!(run(&mut system, &arguments(fd, &[b"/bin/true"])), 125);
        assert!(system.execs.is_empty());
    }

    #[test]
    fn helper_keeps_a_directory_that_the_caller_entered() {
        let fd = exec_config::create(&execution(None, false), true).unwrap();
        let mut system = TestSystem::new(Paths::default());
        assert_eq!(run(&mut system, &arguments(fd, &[b"/bin/pwd"])), 0);
        assert!(
            system
                .environment
                .iter()
                .all(|(name, _)| name.as_slice() != b"PWD")
        );
        assert_eq!(system.execs[0].1, [b"/bin/pwd".to_vec()]);
    }

    #[test]
    fn safe_working_directory_names_match_the_c_helper() {
        for path in [b"/".as_slice(), b"/tmp", b"/a/b", b"relative"] {
            assert_eq!(
                safe_path(path),
                path != b"/" && path != b"relative",
                "{path:?}"
            );
        }
        for path in [b"/a//b".as_slice(), b"/a/./b", b"/a/../b", b"/a/"] {
            assert!(!safe_path(path), "{path:?}");
        }
    }
}
