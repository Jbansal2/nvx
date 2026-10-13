use std::ffi::CString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::protocol::GuestExecPayload;

use super::AgentConfig;
use super::diagnostics::{c_string, close};
use super::seam::{Paths, path_c_string};

pub(crate) const LAUNCH_STAGE_CWD: i32 = 1;
pub(crate) const LAUNCH_STAGE_SETUP: i32 = 2;

pub(crate) struct SpawnRequest<'a> {
    pub(crate) config: &'a AgentConfig,
    pub(crate) execution: &'a GuestExecPayload,
    pub(crate) config_fd: libc::c_int,
    pub(crate) stdout_pipe: [libc::c_int; 2],
    pub(crate) stderr_pipe: [libc::c_int; 2],
    pub(crate) launch_pipe: [libc::c_int; 2],
}

struct Plan {
    program: CString,
    _arguments: Vec<CString>,
    argument_pointers: Vec<*const libc::c_char>,
    _environment: Vec<CString>,
    environment_pointers: Vec<*const libc::c_char>,
    physical_pwd: Option<Box<[u8]>>,
    directory: CString,
    uid: libc::uid_t,
    gid: libc::gid_t,
    cgroup_procs: Option<libc::c_int>,
    null_device: CString,
}

pub(crate) fn spawn(paths: &Paths, request: SpawnRequest<'_>) -> io::Result<libc::pid_t> {
    let mut plan = Plan::new(paths, &request)?;
    // SAFETY: all fallible allocation and CString construction happened before fork. The child
    // branch calls only async-signal-safe libc functions and reads already allocated storage.
    let child = unsafe { libc::fork() };
    if child < 0 {
        if let Some(fd) = plan.cgroup_procs {
            close(fd);
        }
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: this is the single-threaded post-fork child; `child_exec` never returns.
        unsafe { child_exec(&mut plan, &request) }
    }
    if let Some(fd) = plan.cgroup_procs {
        close(fd);
    }
    // SAFETY: the child exists; a racing exec or exit does not make setpgid unsafe.
    unsafe { libc::setpgid(child, child) };
    Ok(child)
}

impl Plan {
    fn new(paths: &Paths, request: &SpawnRequest<'_>) -> io::Result<Self> {
        let config_fd = request.config_fd.to_string();
        let config_fd = CString::new(config_fd).expect("a decimal descriptor has no NUL");
        let directory = c_string(request.execution.cwd.as_deref().unwrap_or(b"/"))?;
        let uid = parse_id(request.config.uid.as_bytes())?;
        let gid = parse_id(request.config.gid.as_bytes())?;
        let helper = path_c_string(&paths.helper)?;
        let launcher = path_c_string(&paths.launcher)?;
        let setpriv = path_c_string(&paths.setpriv)?;
        let mut arguments = Vec::new();
        let program;
        let mut environment = inherited_environment()?;
        let mut physical_pwd = None;
        let mut physical_pwd_index = None;
        if request.config.direct {
            program = setpriv;
            for value in [
                b"setpriv".as_slice(),
                b"--reuid",
                request.config.uid.as_bytes(),
                b"--regid",
                request.config.gid.as_bytes(),
                b"--clear-groups",
                b"--no-new-privs",
                b"--bounding-set=-all",
                b"--inh-caps=-all",
                b"--ambient-caps=-all",
                helper.as_bytes(),
                b"--exec-config-fd",
                config_fd.as_bytes(),
                b"--",
            ] {
                arguments.push(c_string(value)?);
            }
            upsert_env(&mut environment, b"HOME", request.config.home.as_bytes())?;
            upsert_env(&mut environment, b"USER", request.config.user.as_bytes())?;
            upsert_env(&mut environment, b"LOGNAME", request.config.user.as_bytes())?;
            if request.execution.environment.is_none() || request.execution.inherit_default_env {
                if directory.to_bytes() == b"/" || super::helper::safe_path(directory.to_bytes()) {
                    upsert_env(&mut environment, b"PWD", directory.to_bytes())?;
                } else {
                    let prefix = b"PWD=";
                    physical_pwd_index = Some(
                        environment
                            .iter()
                            .position(|entry| entry.as_bytes().starts_with(prefix))
                            .map_or(environment.len(), |index| {
                                environment.remove(index);
                                index
                            }),
                    );
                    let mut entry = vec![0u8; prefix.len() + crate::protocol::MAX_ARGUMENT_BYTES]
                        .into_boxed_slice();
                    entry[..prefix.len()].copy_from_slice(prefix);
                    physical_pwd = Some(entry);
                }
            }
        } else {
            program = launcher.clone();
            for value in [
                launcher.as_bytes(),
                paths.barrier.as_os_str().as_bytes(),
                request.config.rootfs.as_bytes(),
                request.config.hostname.as_bytes(),
                request.config.uid.as_bytes(),
                request.config.gid.as_bytes(),
                request.config.user.as_bytes(),
                request.config.home.as_bytes(),
            ] {
                arguments.push(c_string(value)?);
            }
            upsert_env(
                &mut environment,
                b"NVX_EXEC_CONFIG_FD",
                config_fd.as_bytes(),
            )?;
        }
        for argument in &request.execution.argv {
            arguments.push(c_string(argument)?);
        }
        let mut argument_pointers: Vec<_> =
            arguments.iter().map(|argument| argument.as_ptr()).collect();
        argument_pointers.push(std::ptr::null());
        let mut environment_pointers =
            Vec::with_capacity(environment.len() + usize::from(physical_pwd.is_some()) + 1);
        let physical_pwd_pointer = physical_pwd.as_ref().map(|entry| entry.as_ptr().cast());
        for index in 0..=environment.len() {
            if physical_pwd_index == Some(index)
                && let Some(pointer) = physical_pwd_pointer
            {
                environment_pointers.push(pointer);
            }
            if let Some(entry) = environment.get(index) {
                environment_pointers.push(entry.as_ptr());
            }
        }
        environment_pointers.push(std::ptr::null());
        let cgroup_procs = if request.config.direct {
            let path = path_c_string(&paths.cgroup_root.join("nvx-exec/cgroup.procs"))?;
            // SAFETY: `path` is NUL-terminated and O_CREAT is absent.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Some(fd)
        } else {
            None
        };
        Ok(Self {
            program,
            _arguments: arguments,
            argument_pointers,
            _environment: environment,
            environment_pointers,
            physical_pwd,
            directory,
            uid,
            gid,
            cgroup_procs,
            null_device: path_c_string(&paths.null_device)?,
        })
    }
}

unsafe fn child_exec(plan: &mut Plan, request: &SpawnRequest<'_>) -> ! {
    // SAFETY: every call below operates on descriptors owned by the child or immutable,
    // preallocated C strings. None allocates.
    unsafe {
        libc::setpgid(0, 0);
        if libc::fcntl(request.config_fd, libc::F_SETFD, 0) != 0 {
            libc::_exit(125);
        }
        libc::close(request.stdout_pipe[0]);
        libc::close(request.stderr_pipe[0]);
        let null_fd = libc::open(plan.null_device.as_ptr(), libc::O_RDONLY);
        if null_fd >= 0 {
            libc::dup2(null_fd, libc::STDIN_FILENO);
            libc::close(null_fd);
        }
        libc::dup2(request.stdout_pipe[1], libc::STDOUT_FILENO);
        libc::dup2(request.stderr_pipe[1], libc::STDERR_FILENO);
        libc::close(request.stdout_pipe[1]);
        libc::close(request.stderr_pipe[1]);
        if request.config.direct {
            libc::close(request.launch_pipe[0]);
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setegid(plan.gid) != 0
                || libc::seteuid(plan.uid) != 0
            {
                report_failure(request.launch_pipe[1], LAUNCH_STAGE_SETUP, raw_errno());
            }
            if libc::chdir(plan.directory.as_ptr()) != 0 {
                report_failure(request.launch_pipe[1], LAUNCH_STAGE_CWD, raw_errno());
            }
            if libc::seteuid(0) != 0 || libc::setegid(0) != 0 {
                report_failure(request.launch_pipe[1], LAUNCH_STAGE_SETUP, raw_errno());
            }
            if let Some(entry) = plan.physical_pwd.as_deref_mut() {
                let output = &mut entry[b"PWD=".len()..];
                if libc::getcwd(output.as_mut_ptr().cast(), output.len()).is_null() {
                    report_failure(request.launch_pipe[1], LAUNCH_STAGE_SETUP, raw_errno());
                }
            }
            let Some(cgroup) = plan.cgroup_procs else {
                report_failure(request.launch_pipe[1], LAUNCH_STAGE_SETUP, libc::EBADF);
            };
            if !write_decimal(cgroup, libc::getpid()) {
                report_failure(request.launch_pipe[1], LAUNCH_STAGE_SETUP, raw_errno());
            }
            libc::close(cgroup);
        }
        libc::execve(
            plan.program.as_ptr(),
            plan.argument_pointers.as_ptr(),
            plan.environment_pointers.as_ptr(),
        );
        libc::_exit(125);
    }
}

unsafe fn report_failure(fd: libc::c_int, stage: i32, status: i32) -> ! {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&stage.to_ne_bytes());
    bytes[4..].copy_from_slice(&status.to_ne_bytes());
    let _ = raw_write_all(fd, &bytes);
    // SAFETY: this runs only in the post-fork child.
    unsafe { libc::_exit(125) }
}

fn parse_id(text: &[u8]) -> io::Result<u32> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let value = text.iter().try_fold(0u32, |value, &digit| {
        value.checked_mul(10)?.checked_add(u32::from(digit - b'0'))
    });
    value
        .filter(|value| *value != 0 && *value != u32::MAX)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
}

fn inherited_environment() -> io::Result<Vec<CString>> {
    std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            c_string(&entry)
        })
        .collect()
}

fn upsert_env(environment: &mut Vec<CString>, name: &[u8], value: &[u8]) -> io::Result<()> {
    let mut entry = Vec::with_capacity(name.len() + value.len() + 1);
    entry.extend_from_slice(name);
    entry.push(b'=');
    entry.extend_from_slice(value);
    let entry = c_string(&entry)?;
    let prefix = [name, b"="].concat();
    match environment
        .iter_mut()
        .find(|current| current.as_bytes().starts_with(&prefix))
    {
        Some(current) => *current = entry,
        None => environment.push(entry),
    }
    Ok(())
}

fn write_decimal(fd: libc::c_int, value: libc::pid_t) -> bool {
    let mut bytes = [0u8; 32];
    let mut position = bytes.len() - 1;
    bytes[position] = b'\n';
    let mut value = value as u32;
    loop {
        position -= 1;
        bytes[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    raw_write_all(fd, &bytes[position..])
}

fn raw_write_all(fd: libc::c_int, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        // SAFETY: the byte slice remains valid for the call.
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if count > 0 {
            bytes = &bytes[count as usize..];
        } else if count < 0 && raw_errno() == libc::EINTR {
            continue;
        } else {
            return false;
        }
    }
    true
}

fn raw_errno() -> i32 {
    // SAFETY: errno is thread-local.
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use crate::protocol::GuestExecPayload;

    use super::*;

    fn config(direct: bool) -> AgentConfig {
        AgentConfig {
            rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
            hostname: c"sandbox".to_owned(),
            uid: c"1000".to_owned(),
            gid: c"1001".to_owned(),
            user: c"workload".to_owned(),
            home: c"/home/workload".to_owned(),
            direct,
        }
    }

    fn execution() -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/echo".to_vec(), b"ok".to_vec()],
            cwd: Some(b"/work".to_vec()),
            environment: None,
            inherit_default_env: false,
        }
    }

    fn request<'a>(config: &'a AgentConfig, execution: &'a GuestExecPayload) -> SpawnRequest<'a> {
        SpawnRequest {
            config,
            execution,
            config_fd: 42,
            stdout_pipe: [-1; 2],
            stderr_pipe: [-1; 2],
            launch_pipe: [-1; 2],
        }
    }

    #[test]
    fn direct_launch_uses_setpriv_and_clears_every_capability_set() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nvx-exec")).unwrap();
        std::fs::write(temporary.path().join("nvx-exec/cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: temporary.path().to_owned(),
            setpriv: "/test/setpriv".into(),
            helper: "/test/nvx-managed-agent".into(),
            ..Paths::default()
        };
        let config = config(true);
        let execution = execution();
        let plan = Plan::new(&paths, &request(&config, &execution)).unwrap();
        let arguments: Vec<_> = plan
            ._arguments
            .iter()
            .map(|argument| argument.to_bytes())
            .collect();
        assert_eq!(
            arguments,
            [
                b"setpriv".as_slice(),
                b"--reuid",
                b"1000",
                b"--regid",
                b"1001",
                b"--clear-groups",
                b"--no-new-privs",
                b"--bounding-set=-all",
                b"--inh-caps=-all",
                b"--ambient-caps=-all",
                b"/test/nvx-managed-agent",
                b"--exec-config-fd",
                b"42",
                b"--",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert_eq!(plan.program.as_bytes(), b"/test/setpriv");
        let environment: Vec<_> = plan
            ._environment
            .iter()
            .map(|entry| entry.to_bytes())
            .collect();
        for expected in [
            b"HOME=/home/workload".as_slice(),
            b"USER=workload",
            b"LOGNAME=workload",
            b"PWD=/work",
        ] {
            assert!(environment.contains(&expected), "{expected:?}");
        }
        close(plan.cgroup_procs.unwrap());
    }

    #[test]
    fn sandbox_launch_exports_only_the_deliberate_config_descriptor() {
        let paths = Paths {
            launcher: "/test/nvx-container-launch".into(),
            barrier: "/test/start".into(),
            ..Paths::default()
        };
        let config = config(false);
        let execution = execution();
        let plan = Plan::new(&paths, &request(&config, &execution)).unwrap();
        let arguments: Vec<_> = plan
            ._arguments
            .iter()
            .map(|argument| argument.to_bytes())
            .collect();
        assert_eq!(
            arguments,
            [
                b"/test/nvx-container-launch".as_slice(),
                b"/test/start",
                b"/rootfs",
                b"sandbox",
                b"1000",
                b"1001",
                b"workload",
                b"/home/workload",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert!(
            plan._environment
                .iter()
                .any(|entry| entry.as_bytes() == b"NVX_EXEC_CONFIG_FD=42")
        );
        assert!(plan.cgroup_procs.is_none());
    }

    #[test]
    fn workload_ids_are_nonzero_decimal_and_not_the_unchanged_value() {
        for (text, expected) in [
            (b"1".as_slice(), Some(1)),
            (b"1000", Some(1000)),
            (b"4294967294", Some(u32::MAX - 1)),
            (b"0", None),
            (b"4294967295", None),
            (b"4294967296", None),
            (b"+1", None),
            (b"-1", None),
            (b" 1", None),
            (b"1x", None),
        ] {
            assert_eq!(parse_id(text).ok(), expected, "{text:?}");
        }
    }

    #[test]
    fn direct_pwd_is_deferred_only_for_noncanonical_names() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nvx-exec")).unwrap();
        std::fs::write(temporary.path().join("nvx-exec/cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: temporary.path().to_owned(),
            ..Paths::default()
        };
        let config = config(true);
        for cwd in [b"/a/./b".as_slice(), b"/a/../b", b"/a//b", b"/a/b/"] {
            let execution = GuestExecPayload {
                cwd: Some(cwd.to_vec()),
                ..execution()
            };
            let plan = Plan::new(&paths, &request(&config, &execution)).unwrap();
            let slot = plan.physical_pwd.as_deref().expect("PWD is deferred");
            assert_eq!(&slot[..4], b"PWD=");
            assert!(slot[4..].iter().all(|&byte| byte == 0));
            assert!(
                plan._environment
                    .iter()
                    .all(|entry| !entry.as_bytes().starts_with(b"PWD="))
            );
            assert!(plan.environment_pointers.contains(&slot.as_ptr().cast()));
            close(plan.cgroup_procs.unwrap());
        }

        let execution = GuestExecPayload {
            cwd: Some(b"/symlinked/component".to_vec()),
            ..execution()
        };
        let plan = Plan::new(&paths, &request(&config, &execution)).unwrap();
        assert!(plan.physical_pwd.is_none());
        assert!(
            plan._environment
                .iter()
                .any(|entry| entry.as_bytes() == b"PWD=/symlinked/component")
        );
        close(plan.cgroup_procs.unwrap());
    }
}
