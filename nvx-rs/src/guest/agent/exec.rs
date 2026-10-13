use std::io;
use std::time::{Duration, Instant};

use crate::protocol::{
    self, APP_CANCEL, APP_EXIT, APP_STDERR, APP_STDOUT, BUSY, CWD_FAILED, GuestExecPayload,
    LAUNCH_FAILED, OUTER_DATA, OUTER_RESET,
};

use super::AgentConfig;
use super::cgroup;
use super::diagnostics::{c_string, close, errno, strerror};
use super::exec_config;
use super::launch::{LAUNCH_STAGE_CWD, SpawnRequest};
use super::seam::{System, path_c_string};
use super::session::{DataFailureKind, Session};
use super::tty;

const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
const POLL_INTERVAL_MS: libc::c_int = 25;
const BARRIER_ATTEMPTS: usize = 500;

pub(crate) fn run(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    request_id: u64,
    execution: &GuestExecPayload,
) -> io::Result<()> {
    if config.direct {
        if let Err(error) = cgroup::prepare(system) {
            super::diagnostics::error(system, "exec-cgroup", errno(&error));
            return session.send_error(request_id, 125, LAUNCH_FAILED);
        }
        match cgroup::verify_empty(system) {
            Ok(false) => {}
            Ok(true) => {
                super::diagnostics::error(system, "exec-cgroup-verify", libc::EBUSY);
                return session.send_error(request_id, 125, "containment-failed");
            }
            Err(error) => {
                super::diagnostics::error(system, "exec-cgroup-verify", errno(&error));
                return session.send_error(request_id, 125, "containment-failed");
            }
        }
    }
    if let Err(failure) = validate_launch_environment(system, config, execution) {
        match failure {
            EnvironmentFailure::Child(error, diagnostic) => {
                let mut message = diagnostic.to_vec();
                message.extend_from_slice(&strerror(errno(&error)));
                message.push(b'\n');
                session.send_app(APP_STDERR, request_id, 0, &message)?;
                return session.send_app(APP_EXIT, request_id, 125, b"exit");
            }
            EnvironmentFailure::Launch(error) => {
                super::diagnostics::error(system, "exec-launch", errno(&error));
                return session.send_error(request_id, 125, LAUNCH_FAILED);
            }
        }
    }
    if !config.direct && create_barrier(system).is_err() {
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }

    let mut stdout_pipe = [-1; 2];
    let mut stderr_pipe = [-1; 2];
    let mut launch_pipe = [-1; 2];
    let mut config_fd = -1;
    let setup: io::Result<()> = (|| {
        pipe(&mut stdout_pipe)?;
        pipe(&mut stderr_pipe)?;
        config_fd = exec_config::create(execution, config.direct)?;
        if config.direct {
            pipe(&mut launch_pipe)?;
        }
        Ok(())
    })();
    if setup.is_err() {
        cleanup_pipes(&mut stdout_pipe);
        cleanup_pipes(&mut stderr_pipe);
        cleanup_pipes(&mut launch_pipe);
        close(config_fd);
        unlink_barrier(system);
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }

    let child = match system.spawn(SpawnRequest {
        config,
        execution,
        config_fd,
        stdout_pipe,
        stderr_pipe,
        launch_pipe,
    }) {
        Ok(child) => child,
        Err(_) => {
            cleanup_pipes(&mut stdout_pipe);
            cleanup_pipes(&mut stderr_pipe);
            cleanup_pipes(&mut launch_pipe);
            close(config_fd);
            unlink_barrier(system);
            return session.send_error(request_id, 125, LAUNCH_FAILED);
        }
    };
    close(config_fd);
    close(stdout_pipe[1]);
    stdout_pipe[1] = -1;
    close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    if config.direct {
        close(launch_pipe[1]);
        launch_pipe[1] = -1;
    }
    let mut launch_failed = tty::make_nonblocking(stdout_pipe[0]).is_err()
        || tty::make_nonblocking(stderr_pipe[0]).is_err();
    if !launch_failed && !config.direct {
        launch_failed = cgroup::write_container_pid(system, child).is_err()
            || release_barrier(system, child).is_err();
    }
    if launch_failed {
        cgroup::terminate(system, config.direct, child);
        wait(child, std::ptr::null_mut());
        cleanup_pipes(&mut stdout_pipe);
        cleanup_pipes(&mut stderr_pipe);
        cleanup_pipes(&mut launch_pipe);
        unlink_barrier(system);
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }
    unlink_barrier(system);

    let started = Instant::now();
    let mut output_bytes = 0usize;
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut timed_out = false;
    let mut output_limited = false;
    let mut cancelled = false;
    let mut session_lost = false;
    let mut stragglers_killed = false;
    let mut wait_status = 0;
    let mut child_exited = false;

    while !child_exited || stdout_open || stderr_open {
        let mut descriptors = [
            libc::pollfd {
                fd: if stdout_open { stdout_pipe[0] } else { -1 },
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: if stderr_open { stderr_pipe[0] } else { -1 },
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: if session_lost { -1 } else { session.fd },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `descriptors` is valid for all three entries.
        let poll = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                POLL_INTERVAL_MS,
            )
        };
        if poll < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            cgroup::terminate(system, config.direct, child);
        }
        if !session_lost && descriptors[2].revents != 0 {
            let control = match handle_control(system, session, request_id) {
                Ok(control) => control,
                Err(error) => {
                    cgroup::terminate(system, config.direct, child);
                    wait(child, std::ptr::null_mut());
                    cleanup_pipes(&mut stdout_pipe);
                    cleanup_pipes(&mut stderr_pipe);
                    cleanup_pipes(&mut launch_pipe);
                    return Err(error);
                }
            };
            match control {
                ExecControl::None => {}
                ExecControl::Cancel if !child_exited && !cancelled => {
                    cancelled = true;
                    cgroup::terminate(system, config.direct, child);
                }
                ExecControl::Cancel => {}
                ExecControl::SessionLost => {
                    session_lost = true;
                    cgroup::terminate(system, config.direct, child);
                }
            }
        }
        let stdout_result = if stdout_open && descriptors[0].revents != 0 {
            if session_lost {
                drain(stdout_pipe[0])
            } else {
                stream(
                    session,
                    request_id,
                    stdout_pipe[0],
                    APP_STDOUT,
                    &mut output_bytes,
                )
            }
        } else {
            StreamResult::Open
        };
        let stderr_result = if stderr_open && descriptors[1].revents != 0 {
            if session_lost {
                drain(stderr_pipe[0])
            } else {
                stream(
                    session,
                    request_id,
                    stderr_pipe[0],
                    APP_STDERR,
                    &mut output_bytes,
                )
            }
        } else {
            StreamResult::Open
        };
        if stdout_result == StreamResult::Closed {
            close(stdout_pipe[0]);
            stdout_pipe[0] = -1;
            stdout_open = false;
        }
        if stderr_result == StreamResult::Closed {
            close(stderr_pipe[0]);
            stderr_pipe[0] = -1;
            stderr_open = false;
        }
        if stdout_result.is_failure() || stderr_result.is_failure() {
            output_limited =
                stdout_result == StreamResult::Limited || stderr_result == StreamResult::Limited;
            cgroup::terminate(system, config.direct, child);
        }
        cgroup::reap(child, &mut child_exited, &mut wait_status);
        if child_exited && config.direct && !stragglers_killed && (stdout_open || stderr_open) {
            stragglers_killed = true;
            let _ = cgroup::kill(system);
        }
        if !child_exited
            && execution.timeout_ms != 0
            && started.elapsed() >= Duration::from_millis(u64::from(execution.timeout_ms))
        {
            timed_out = true;
            cgroup::terminate(system, config.direct, child);
        }
        if (timed_out || output_limited || cancelled || session_lost)
            && !child_exited
            && wait(child, &mut wait_status) == child
        {
            child_exited = true;
        }
    }

    let launch_report = if config.direct {
        let report = read_launch_failure(launch_pipe[0]);
        cleanup_pipes(&mut launch_pipe);
        report
    } else {
        Ok(None)
    };
    if config.direct
        && let Err(error) = cgroup::settle(system)
    {
        super::diagnostics::error(system, "exec-cgroup-settle", errno(&error));
        return if session_lost {
            Ok(())
        } else {
            session.send_error(request_id, 125, "containment-failed")
        };
    }
    if session_lost {
        return Ok(());
    }
    match launch_report {
        Ok(Some((LAUNCH_STAGE_CWD, status))) => {
            return refuse_cwd(session, request_id, execution, status);
        }
        Ok(Some((_, status))) => {
            super::diagnostics::error(system, "exec-launch", status);
            return session.send_error(request_id, 125, LAUNCH_FAILED);
        }
        Err(error) => {
            super::diagnostics::error(system, "exec-launch-report", errno(&error));
        }
        Ok(None) => {}
    }
    if cancelled {
        session.send_app(APP_EXIT, request_id, 128 + libc::SIGKILL, b"cancelled")
    } else if timed_out {
        session.send_app(APP_EXIT, request_id, 124, b"timeout")
    } else if output_limited {
        session.send_app(APP_EXIT, request_id, 125, b"output-limit")
    } else if libc::WIFEXITED(wait_status) {
        session.send_app(
            APP_EXIT,
            request_id,
            libc::WEXITSTATUS(wait_status),
            b"exit",
        )
    } else if libc::WIFSIGNALED(wait_status) {
        session.send_app(
            APP_EXIT,
            request_id,
            128 + libc::WTERMSIG(wait_status),
            b"signal",
        )
    } else {
        session.send_app(APP_EXIT, request_id, 125, b"failed")
    }
}

#[derive(Debug)]
enum EnvironmentFailure {
    Child(io::Error, &'static [u8]),
    Launch(io::Error),
}

fn validate_launch_environment(
    system: &mut impl System,
    config: &AgentConfig,
    execution: &GuestExecPayload,
) -> Result<(), EnvironmentFailure> {
    if config.direct {
        for (name, value) in [
            (c"HOME", config.home.as_c_str()),
            (c"USER", config.user.as_c_str()),
            (c"LOGNAME", config.user.as_c_str()),
        ] {
            if let Err(error) = system.validate_environment(name, value) {
                return Err(EnvironmentFailure::Child(
                    error,
                    b"nvx-managed-agent: cannot configure workload environment: ",
                ));
            }
        }
        if execution.environment.is_none() || execution.inherit_default_env {
            let pwd = c_string(execution.cwd.as_deref().unwrap_or(b"/"))
                .map_err(EnvironmentFailure::Launch)?;
            system
                .validate_environment(c"PWD", &pwd)
                .map_err(EnvironmentFailure::Launch)?;
        }
    } else if let Err(error) = system.validate_environment(c"NVX_EXEC_CONFIG_FD", c"0") {
        return Err(EnvironmentFailure::Child(
            error,
            b"nvx-managed-agent: cannot export execution configuration: ",
        ));
    }
    Ok(())
}

fn refuse_cwd(
    session: &mut Session,
    request_id: u64,
    execution: &GuestExecPayload,
    status: i32,
) -> io::Result<()> {
    let cwd = execution.cwd.as_deref().unwrap_or(b"/");
    let mut diagnostic = b"nvx-managed-agent: cannot enter working directory ".to_vec();
    diagnostic.extend_from_slice(cwd);
    diagnostic.extend_from_slice(b": ");
    diagnostic.extend_from_slice(&strerror(status));
    diagnostic.push(b'\n');
    session.send_app(APP_STDERR, request_id, 0, &diagnostic)?;
    session.send_error(request_id, status, CWD_FAILED)
}

#[derive(Clone, Copy)]
enum ExecControl {
    None,
    Cancel,
    SessionLost,
}

fn handle_control(
    system: &mut impl System,
    session: &mut Session,
    exec_id: u64,
) -> io::Result<ExecControl> {
    let record = session.read_record().inspect_err(|error| {
        super::diagnostics::error(system, "exec-outer-read", errno(error));
    })?;
    if record.header.record_type == OUTER_RESET {
        session.acknowledge_reset(&record)?;
        return Ok(ExecControl::SessionLost);
    }
    if record.header.record_type != OUTER_DATA {
        super::diagnostics::error(system, "exec-record", i32::from(record.header.record_type));
        return Err(io::Error::from_raw_os_error(libc::EPROTO));
    }
    let request = match session.validate_data(&record) {
        Ok(request) => request,
        Err(failure) => {
            if failure.kind != DataFailureKind::Credit {
                super::diagnostics::error(
                    system,
                    "exec-record",
                    i32::from(record.header.record_type),
                );
            }
            return Err(failure.into_error());
        }
    };
    if request.kind == APP_CANCEL {
        return Ok(
            if request.payload.is_empty() && request.request_id == exec_id {
                ExecControl::Cancel
            } else {
                ExecControl::None
            },
        );
    }
    session.send_error(request.request_id, libc::EBUSY, BUSY)?;
    Ok(ExecControl::None)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamResult {
    Open,
    Closed,
    Failed,
    Limited,
}

impl StreamResult {
    fn is_failure(self) -> bool {
        matches!(self, Self::Failed | Self::Limited)
    }
}

fn stream(
    session: &mut Session,
    request_id: u64,
    fd: libc::c_int,
    kind: u8,
    output_bytes: &mut usize,
) -> StreamResult {
    let mut buffer = [0u8; OUTPUT_CHUNK_BYTES];
    loop {
        // SAFETY: `buffer` is writable for its full length.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count > 0 {
            let count = count as usize;
            if *output_bytes > protocol::MAX_OUTPUT_BYTES - count {
                return StreamResult::Limited;
            }
            *output_bytes += count;
            if session
                .send_app(kind, request_id, 0, &buffer[..count])
                .is_err()
            {
                return StreamResult::Failed;
            }
        } else if count == 0 {
            return StreamResult::Closed;
        } else {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return StreamResult::Open,
                _ => return StreamResult::Failed,
            }
        }
    }
}

fn drain(fd: libc::c_int) -> StreamResult {
    let mut buffer = [0u8; OUTPUT_CHUNK_BYTES];
    loop {
        // SAFETY: `buffer` is writable for its full length.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count > 0 {
            continue;
        }
        if count == 0 {
            return StreamResult::Closed;
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => return StreamResult::Open,
            _ => return StreamResult::Failed,
        }
    }
}

fn read_launch_failure(fd: libc::c_int) -> io::Result<Option<(i32, i32)>> {
    let mut bytes = [0u8; 8];
    let mut length = 0;
    while length < bytes.len() {
        // SAFETY: the unused suffix is writable.
        let count = unsafe {
            libc::read(
                fd,
                bytes[length..].as_mut_ptr().cast(),
                bytes.len() - length,
            )
        };
        if count > 0 {
            length += count as usize;
        } else if count == 0 {
            break;
        } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    match length {
        0 => Ok(None),
        8 => Ok(Some((
            i32::from_ne_bytes(bytes[..4].try_into().expect("four bytes")),
            i32::from_ne_bytes(bytes[4..].try_into().expect("four bytes")),
        ))),
        _ => Err(io::Error::from_raw_os_error(libc::EPROTO)),
    }
}

fn create_barrier(system: &impl System) -> io::Result<()> {
    unlink_barrier(system);
    let path = path_c_string(&system.paths().barrier)?;
    // SAFETY: `path` is NUL-terminated.
    if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_barrier(system: &impl System) {
    if let Ok(path) = path_c_string(&system.paths().barrier) {
        // SAFETY: `path` is NUL-terminated.
        unsafe { libc::unlink(path.as_ptr()) };
    }
}

fn release_barrier(system: &mut impl System, child: libc::pid_t) -> io::Result<()> {
    let path = path_c_string(&system.paths().barrier)?;
    for _ in 0..BARRIER_ATTEMPTS {
        // SAFETY: `path` is NUL-terminated and O_CREAT is absent.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            let result = write_barrier(system, fd);
            close(fd);
            return result;
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::ENXIO | libc::EINTR)) {
            return Err(error);
        }
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: waitid writes `information` and WNOWAIT leaves the child reapable.
        let waited = unsafe {
            libc::waitid(
                libc::P_PID,
                child as libc::id_t,
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if waited != 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        // SAFETY: waitid initialized the Linux siginfo union for a child event.
        if unsafe { information.si_pid() } == child {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
}

fn write_barrier(system: &mut impl System, fd: libc::c_int) -> io::Result<()> {
    // SAFETY: zeroed sigaction values are completed before use.
    unsafe {
        let mut ignored: libc::sigaction = std::mem::zeroed();
        let mut previous: libc::sigaction = std::mem::zeroed();
        ignored.sa_sigaction = libc::SIG_IGN;
        if libc::sigemptyset(&mut ignored.sa_mask) != 0
            || libc::sigaction(libc::SIGPIPE, &ignored, &mut previous) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let result = system.write_barrier(fd, b"start\n");
        let status = result.as_ref().err().map(errno);
        if libc::sigaction(libc::SIGPIPE, &previous, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        match status {
            Some(status) => Err(io::Error::from_raw_os_error(status)),
            None => Ok(()),
        }
    }
}

fn pipe(pipe: &mut [libc::c_int; 2]) -> io::Result<()> {
    // SAFETY: pipe2 writes exactly two descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn cleanup_pipes(pipe: &mut [libc::c_int; 2]) {
    close(pipe[0]);
    close(pipe[1]);
    *pipe = [-1; 2];
}

fn wait(child: libc::pid_t, status: *mut libc::c_int) -> libc::pid_t {
    loop {
        // SAFETY: `status` is null or writable, and the caller owns the child.
        let result = unsafe { libc::waitpid(child, status, 0) };
        if result >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return result;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::net::UnixStream;

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn system() -> (tempfile::TempDir, TestSystem) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = Paths {
            barrier: temporary.path().join("managed-container-start"),
            ..Paths::default()
        };
        (temporary, TestSystem::new(paths))
    }

    #[test]
    fn parent_barrier_release_is_bounded_without_a_child_reader() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        // SAFETY: the child immediately exits, and the parent reaps it after observing it.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: exits the fork child without running destructors.
            unsafe { libc::_exit(125) }
        }
        release_barrier(&mut system, child).unwrap();
        assert_eq!(wait(child, std::ptr::null_mut()), child);
    }

    #[test]
    fn parent_barrier_release_handles_a_reader_closing_during_write() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let path = path_c_string(&system.paths.barrier).unwrap();
        // SAFETY: `path` is NUL-terminated and the FIFO exists.
        let reader = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        assert!(reader >= 0);
        system.close_barrier_reader = Some(reader);
        system.fail_barrier_write = Some(libc::EPIPE);
        let error = release_barrier(&mut system, -1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn parent_barrier_release_preserves_a_live_child_start() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let path = path_c_string(&system.paths.barrier).unwrap();
        // SAFETY: both branches use only raw descriptor operations until child _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: `path` is NUL-terminated and the FIFO exists.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            let mut message = [0u8; 6];
            let success = fd >= 0
                && super::super::diagnostics::read_exact(fd, &mut message).is_ok()
                && message == *b"start\n";
            close(fd);
            // SAFETY: exits the fork child without running destructors.
            unsafe { libc::_exit(if success { 0 } else { 125 }) }
        }
        release_barrier(&mut system, child).unwrap();
        let mut status = 0;
        assert_eq!(wait(child, &mut status), child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn write_barrier_restores_the_sigpipe_disposition() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        let (left, right) = UnixStream::pair().unwrap();
        use std::os::fd::IntoRawFd;
        let writer = left.into_raw_fd();
        let reader = right.into_raw_fd();
        system.close_barrier_reader = Some(reader);
        system.fail_barrier_write = Some(libc::EPIPE);
        // SAFETY: sigaction with a null replacement only reads the disposition.
        let mut before = unsafe { std::mem::zeroed::<libc::sigaction>() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut before) },
            0
        );
        assert_eq!(
            write_barrier(&mut system, writer)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPIPE)
        );
        let mut after = unsafe { std::mem::zeroed::<libc::sigaction>() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(before.sa_sigaction, after.sa_sigaction);
        close(writer);
    }

    #[test]
    fn environment_failures_stop_direct_and_sandbox_launches_before_exec() {
        let config = |direct| AgentConfig {
            rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
            hostname: c"test".to_owned(),
            uid: c"1000".to_owned(),
            gid: c"1000".to_owned(),
            user: c"workload".to_owned(),
            home: c"/home/workload".to_owned(),
            direct,
        };
        let execution = GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/true".to_vec()],
            cwd: None,
            environment: None,
            inherit_default_env: false,
        };
        for (direct, variable, diagnostic) in [
            (
                true,
                b"HOME".as_slice(),
                b"cannot configure workload environment".as_slice(),
            ),
            (
                false,
                b"NVX_EXEC_CONFIG_FD".as_slice(),
                b"cannot export execution configuration".as_slice(),
            ),
        ] {
            let mut system = TestSystem::new(Paths::default());
            system.fail_environment = Some(variable.to_vec());
            let failure =
                validate_launch_environment(&mut system, &config(direct), &execution).unwrap_err();
            let EnvironmentFailure::Child(error, message) = failure else {
                panic!("expected a child environment failure");
            };
            assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
            assert!(
                message
                    .windows(diagnostic.len())
                    .any(|part| part == diagnostic),
                "{message:?}"
            );
            assert!(system.execs.is_empty());
        }

        let mut system = TestSystem::new(Paths::default());
        system.fail_environment = Some(b"PWD".to_vec());
        let failure =
            validate_launch_environment(&mut system, &config(true), &execution).unwrap_err();
        assert!(matches!(
            failure,
            EnvironmentFailure::Launch(ref error)
                if error.raw_os_error() == Some(libc::ENOMEM)
        ));
        assert!(system.execs.is_empty());
    }
}
