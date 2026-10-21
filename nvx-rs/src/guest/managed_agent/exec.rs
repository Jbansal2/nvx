use std::os::unix::process::ExitStatusExt;
use std::time::{Duration, Instant};

use crate::guest::exec::{Event, Execution, KillTarget, Outcome, Pipes, Stream};
use crate::guest::process::Child;
use crate::guest::spawn::{LaunchFailure, LaunchStage, Spawned};
use crate::guest::sys::{self, Errno, FileDescriptor, Mode, OpenFlags, ProcessId, c_string};
use crate::protocol::{
    self, APP_CANCEL, APP_EXIT, APP_STDERR, APP_STDOUT, BUSY, CWD_FAILED, GuestExecPayload,
    LAUNCH_FAILED, OUTER_DATA,
};

use super::AgentConfig;
use super::cgroup;
use super::diagnostics::with_description;
use super::exec_config;
use super::launch::{self, LaunchRequest};
use super::seam::{System, path_c_string};
use super::session::{DataFailureKind, Event as SessionEvent, ReceiveFailure, Session};

/// Maximum bytes read from one output descriptor at a time.
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
/// Readiness-poll interval, in milliseconds.
const POLL_INTERVAL_MS: u16 = 25;
/// Number of bounded attempts to open a sandbox barrier writer.
const BARRIER_ATTEMPTS: usize = 500;

/// Executes one validated workload request and streams its terminal outcome.
///
/// The workload runs as an [`Execution`], which reads its output, ends it, and collects its
/// status, and which the agent drives in the C agent's loop: each turn polls the workload and
/// the control session, serves a control record, forwards the workload's output, collects the
/// statuses of the agent's children, and checks the workload's timeout. The agent keeps the C
/// agent's policy: the output cap, checked for each read of up to 32 KiB, and the precedence of
/// a cancellation, a timeout, and the cap over the workload's own status.
pub(crate) fn run(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    request_id: u64,
    execution: &GuestExecPayload,
) -> Result<(), Errno> {
    if config.direct {
        if let Err(error) = cgroup::prepare(system) {
            super::diagnostics::error(system, "exec-cgroup", error as i32);
            return session.send_error(request_id, 125, LAUNCH_FAILED);
        }
        match cgroup::verify_empty(system) {
            Ok(false) => {}
            Ok(true) => {
                super::diagnostics::error(system, "exec-cgroup-verify", Errno::EBUSY as i32);
                return session.send_error(request_id, 125, "containment-failed");
            }
            Err(error) => {
                super::diagnostics::error(system, "exec-cgroup-verify", error as i32);
                return session.send_error(request_id, 125, "containment-failed");
            }
        }
    }
    if let Err(failure) = validate_launch_environment(system, config, execution) {
        match failure {
            EnvironmentFailure::Child(error, diagnostic) => {
                let message = with_description(diagnostic, error);
                session.send_app(APP_STDERR, request_id, 0, &message)?;
                return session.send_app(APP_EXIT, request_id, 125, b"exit");
            }
            EnvironmentFailure::Launch(error) => {
                super::diagnostics::error(system, "exec-launch", error as i32);
                return session.send_error(request_id, 125, LAUNCH_FAILED);
            }
        }
    }
    let Ok(options) = cgroup::options(system.paths(), config.direct) else {
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    };
    if !config.direct && create_barrier(system).is_err() {
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }

    let Ok((spawned, pipes)) = launch(system, config, execution) else {
        unlink_barrier(system);
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    };
    let process = spawned.process();
    let mut workload = match Execution::new(spawned, pipes, options) {
        Ok(workload) => workload,
        Err(error) => {
            // The execution ended the workload, and its cgroup, before it returned the error.
            super::diagnostics::error(system, "exec-launch", sys::errno_of(&error) as i32);
            if let Err(error) = Child::from_process(process).wait() {
                report_wait_failure(system, &error);
            }
            unlink_barrier(system);
            return session.send_error(request_id, 125, LAUNCH_FAILED);
        }
    };
    if !config.direct
        && (cgroup::write_container_pid(system, process).is_err()
            || release_barrier(system, process).is_err())
    {
        workload.terminate();
        if let Err(error) = workload.wait() {
            report_wait_failure(system, &error);
        }
        unlink_barrier(system);
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }
    unlink_barrier(system);
    workload.grant(Stream::Stdout, usize::MAX);
    workload.grant(Stream::Stderr, usize::MAX);

    let started = Instant::now();
    let mut state = RunState::default();
    let mut buffer = [0u8; OUTPUT_CHUNK_BYTES];
    while state.running(&workload) || workload.has_open_output() {
        let session_ready = match poll(
            &workload,
            (!state.session_lost).then_some(session.descriptor()),
        ) {
            Ok(ready) => ready,
            Err(Errno::EINTR) => false,
            Err(_) => {
                workload.terminate();
                false
            }
        };
        if session_ready {
            match handle_control(system, session, request_id) {
                Ok(ExecControl::None) => {}
                Ok(ExecControl::Cancel) if state.running(&workload) && !state.cancelled => {
                    state.cancelled = true;
                    workload.cancel();
                }
                Ok(ExecControl::Cancel) => {}
                Ok(ExecControl::SessionLost) => {
                    state.session_lost = true;
                    workload.disconnect();
                }
                Err(error) => {
                    workload.terminate();
                    if let Err(failure) = workload.wait() {
                        report_wait_failure(system, &failure);
                    }
                    report_kill_failures(system, &mut workload);
                    return Err(error);
                }
            }
        }
        state.forward(system, session, request_id, &mut workload, &mut buffer)?;
        cgroup::reap(&mut workload);
        if state.running(&workload)
            && execution.timeout_ms != 0
            && started.elapsed() >= Duration::from_millis(u64::from(execution.timeout_ms))
        {
            state.timed_out = true;
            workload.terminate();
        }
        // The outcome is the cause for which the agent ended the workload, so a status that it
        // cannot collect only ends the loop, once the output has closed.
        if (state.timed_out || state.output_limited || state.cancelled || state.session_lost)
            && state.running(&workload)
            && let Err(error) = workload.wait()
        {
            state.lose_status(system, &error);
        }
    }
    let outcome = state.finish(system, session, request_id, &mut workload, &mut buffer)?;

    let launch_report = state.launch.take().unwrap_or(Ok(None));
    if config.direct
        && let Err(error) = cgroup::settle(system)
    {
        super::diagnostics::error(system, "exec-cgroup-settle", error as i32);
        return if state.session_lost {
            Ok(())
        } else {
            session.send_error(request_id, 125, "containment-failed")
        };
    }
    if state.session_lost {
        return Ok(());
    }
    match launch_report {
        Ok(Some(failure)) => match failure.stage() {
            LaunchStage::WorkingDirectory => {
                return refuse_cwd(session, request_id, execution, failure.raw_os_error());
            }
            LaunchStage::Credentials
            | LaunchStage::PhysicalWorkingDirectory
            | LaunchStage::Cgroup => {
                super::diagnostics::error(system, "exec-launch", failure.raw_os_error());
                return session.send_error(request_id, 125, LAUNCH_FAILED);
            }
            // The other stages end the child with status 125 before the workload runs, which
            // the agent reports as the workload's exit status, as the C agent did.
            _ => {}
        },
        Err(error) => {
            super::diagnostics::error(system, "exec-launch-report", sys::errno_of(&error) as i32);
        }
        Ok(None) => {}
    }
    if state.cancelled {
        session.send_app(
            APP_EXIT,
            request_id,
            128 + sys::Signal::SIGKILL as i32,
            b"cancelled",
        )
    } else if state.timed_out {
        session.send_app(APP_EXIT, request_id, 124, b"timeout")
    } else if state.output_limited {
        session.send_app(APP_EXIT, request_id, 125, b"output-limit")
    } else {
        match outcome.map(|outcome| outcome.status()) {
            Some(status) => match (status.code(), status.signal()) {
                (Some(code), _) => session.send_app(APP_EXIT, request_id, code, b"exit"),
                (None, Some(signal)) => {
                    session.send_app(APP_EXIT, request_id, 128 + signal, b"signal")
                }
                (None, None) => session.send_app(APP_EXIT, request_id, 125, b"failed"),
            },
            None => session.send_app(APP_EXIT, request_id, 125, b"failed"),
        }
    }
}

/// What the agent learned of one workload while it ran: the C agent's flags, which decide the
/// outcome that it reports, and the workload's launch report and outcome.
#[derive(Default)]
struct RunState {
    /// Bytes of output forwarded so far, which the 1 MiB cap bounds.
    output_bytes: usize,
    /// Whether the host cancelled the workload while it ran.
    cancelled: bool,
    /// Whether the workload's timeout passed while it ran.
    timed_out: bool,
    /// Whether the workload's output exceeded the cap.
    output_limited: bool,
    /// Whether a reset detached the workload's session, after which its output is discarded.
    session_lost: bool,
    /// Whether the agent cannot collect the workload's status, as when another collector took
    /// it, after which it stops waiting for it.
    status_lost: bool,
    /// The workload's launch report, once it arrived.
    launch: Option<std::io::Result<Option<LaunchFailure>>>,
    /// The workload's outcome, once its execution ended.
    outcome: Option<Outcome>,
}

impl RunState {
    /// Returns whether the workload may still be running: its status is neither known nor lost.
    /// A workload whose status is lost has ended too, so that a cancellation or a timeout after
    /// that, while its output drains, changes its outcome no more than after a known status.
    fn running(&self, workload: &Execution) -> bool {
        workload.status().is_none() && !self.status_lost
    }

    /// Takes the workload's events until it has no step to take, forwarding its output as NVXC
    /// frames, until a read that the agent cannot forward: one beyond the cap, or a failure to
    /// read or send, which ends the workload and the turn, as the C agent's did. A failure to
    /// collect the workload's status, the execution's only one, ends the turn too.
    fn forward(
        &mut self,
        system: &mut impl System,
        session: &mut Session,
        request_id: u64,
        workload: &mut Execution,
        buffer: &mut [u8],
    ) -> Result<(), Errno> {
        loop {
            let event = match workload.next_event(buffer) {
                Ok(Some(event)) => event,
                Ok(None) => return Ok(()),
                Err(error) => {
                    self.lose_status(system, &error);
                    return Ok(());
                }
            };
            match event {
                Event::Output(stream, bytes) => {
                    if self.output_bytes > protocol::MAX_OUTPUT_BYTES - bytes.len() {
                        self.output_limited = true;
                        workload.terminate();
                        return Ok(());
                    }
                    self.output_bytes += bytes.len();
                    let kind = match stream {
                        Stream::Stdout => APP_STDOUT,
                        Stream::Stderr => APP_STDERR,
                    };
                    if session.send_app(kind, request_id, 0, bytes).is_err() {
                        workload.terminate();
                        return Ok(());
                    }
                }
                Event::ReadFailed(..) => {
                    workload.terminate();
                    return Ok(());
                }
                Event::Launch(report) => self.launch = Some(report),
                Event::KillFailed(target, error) => report_kill_failure(system, target, &error),
                Event::Ended(outcome) => self.outcome = Some(outcome),
                Event::Discarded(..) | Event::Closed(_) => {}
            }
        }
    }

    /// Notes that the agent cannot collect the workload's status, and reports it the first time.
    fn lose_status(&mut self, system: &mut impl System, error: &std::io::Error) {
        if !self.status_lost {
            self.status_lost = true;
            report_wait_failure(system, error);
        }
    }

    /// Takes the events that remain once the workload's status is known, or lost, and its
    /// output closed, up to the end of its execution, and returns its outcome, or `None` if its
    /// status is lost.
    fn finish(
        &mut self,
        system: &mut impl System,
        session: &mut Session,
        request_id: u64,
        workload: &mut Execution,
        buffer: &mut [u8],
    ) -> Result<Option<Outcome>, Errno> {
        loop {
            self.forward(system, session, request_id, workload, buffer)?;
            if self.outcome.is_some() || self.status_lost {
                return Ok(self.outcome);
            }
            match poll(workload, None) {
                Ok(_) | Err(Errno::EINTR) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// Waits at most one poll interval until one of the workload's descriptors or the session's,
/// if given, polls ready, and returns whether the session's did.
fn poll(workload: &Execution, session: Option<&FileDescriptor>) -> Result<bool, Errno> {
    let mut descriptors = workload
        .descriptors()
        .map(|(_, descriptor)| descriptor)
        .collect::<Vec<_>>();
    if let Some(session) = session {
        descriptors.push(session.borrowed());
    }
    let ready = sys::readable_or_hung_up(&descriptors, POLL_INTERVAL_MS)?;
    Ok(session.is_some() && ready.last().copied().unwrap_or(false))
}

/// Reports a failure to kill the workload's cgroup, as the C agent did; it signalled the
/// workload's process group without checking the result.
fn report_kill_failure(system: &mut impl System, target: KillTarget, error: &std::io::Error) {
    if target == KillTarget::Cgroup {
        super::diagnostics::error(system, "exec-cgroup-kill", sys::errno_of(error) as i32);
    }
}

/// Reports the kill failures that the workload's execution has yet to report.
fn report_kill_failures(system: &mut impl System, workload: &mut Execution) {
    while let Some(Event::KillFailed(target, error)) = workload.kill_failure() {
        report_kill_failure(system, target, &error);
    }
}

/// Reports a failure to collect the status of a workload, which leaves the agent without it.
fn report_wait_failure(system: &mut impl System, error: &std::io::Error) {
    super::diagnostics::error(system, "exec-wait", sys::errno_of(error) as i32);
}

/// Creates the workload's pipes and sealed configuration, then spawns it, and returns the
/// spawned workload and the execution's ends of its pipes.
///
/// The launch command takes the configuration and the workload's ends of the pipes, which the
/// agent closes once the child exists, as the C agent closed them after `fork`.
fn launch(
    system: &mut impl System,
    config: &AgentConfig,
    execution: &GuestExecPayload,
) -> Result<(Spawned, Pipes), Errno> {
    let (pipes, ends) = Pipes::new(false).map_err(|error| sys::errno_of(&error))?;
    let config_fd = exec_config::create(execution, config.direct)?;
    let command = launch::command(
        system.paths(),
        LaunchRequest {
            config,
            execution,
            config_fd,
            stdout: FileDescriptor::from_owned(ends.stdout),
            stderr: FileDescriptor::from_owned(ends.stderr),
        },
    )?;
    let spawned = system.spawn(command)?;
    Ok((spawned, pipes))
}

/// Failure discovered before the fork boundary.
#[derive(Debug)]
enum EnvironmentFailure {
    /// Failure whose exact stderr text belongs to the would-be child.
    Child(Errno, &'static [u8]),
    /// Parent-side launch validation failure.
    Launch(Errno),
}

/// Validates all environment mutations before allocating child resources.
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

/// Sends the C-compatible stderr and application error for a cwd failure.
fn refuse_cwd(
    session: &mut Session,
    request_id: u64,
    execution: &GuestExecPayload,
    status: i32,
) -> Result<(), Errno> {
    let cwd = execution.cwd.as_deref().unwrap_or(b"/");
    let prefix = [
        b"nvx-managed-agent: cannot enter working directory ".as_slice(),
        cwd,
        b": ",
    ]
    .concat();
    let diagnostic = with_description(&prefix, Errno::from_raw(status));
    session.send_app(APP_STDERR, request_id, 0, &diagnostic)?;
    session.send_error(request_id, status, CWD_FAILED)
}

/// Control action observed while a workload is active.
#[derive(Clone, Copy)]
enum ExecControl {
    /// No action applies to the active workload.
    None,
    /// The host cancelled the active workload.
    Cancel,
    /// A reset detached this workload's session.
    SessionLost,
}

/// Processes one control-console record while a workload runs.
fn handle_control(
    system: &mut impl System,
    session: &mut Session,
    exec_id: u64,
) -> Result<ExecControl, Errno> {
    let payload = match session.next_event() {
        Ok(SessionEvent::Reset) => {
            session.acknowledge()?;
            return Ok(ExecControl::SessionLost);
        }
        Ok(SessionEvent::Data(payload)) => payload,
        Err(failure) => return Err(report_control_failure(system, failure)),
    };
    let request = match session.accept_request(&payload) {
        Ok(request) => request,
        Err(failure) => {
            if failure.kind != DataFailureKind::Credit {
                super::diagnostics::error(system, "exec-record", i32::from(OUTER_DATA));
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
    session.send_error(request.request_id, Errno::EBUSY as i32, BUSY)?;
    Ok(ExecControl::None)
}

/// Reports a control record that ended the session while a workload ran, at the C agent's stage,
/// and returns the error that ends the session.
fn report_control_failure(system: &mut impl System, failure: ReceiveFailure) -> Errno {
    match failure {
        ReceiveFailure::Read(error) => {
            super::diagnostics::error(system, "exec-outer-read", error as i32);
            error
        }
        ReceiveFailure::Type(code) => {
            super::diagnostics::error(system, "exec-record", i32::from(code));
            Errno::EPROTO
        }
        // The C agent reported a RESET that it refused only as the error that ends the session.
        ReceiveFailure::Reset => Errno::EPROTO,
        ReceiveFailure::Data(failure) => {
            super::diagnostics::error(system, "exec-record", i32::from(OUTER_DATA));
            failure.into_error()
        }
    }
}

/// Creates a fresh launch-barrier FIFO after removing a stale entry.
fn create_barrier(system: &impl System) -> Result<(), Errno> {
    unlink_barrier(system);
    let path = path_c_string(&system.paths().barrier)?;
    sys::create_fifo(&path, Mode::from_bits_retain(0o600))
}

/// Best-effort removes the launch-barrier FIFO.
fn unlink_barrier(system: &impl System) {
    if let Ok(path) = path_c_string(&system.paths().barrier) {
        let _ = sys::unlink(&path);
    }
}

/// Opens and releases the sandbox barrier, bounded by child exit and retry count.
fn release_barrier(system: &mut impl System, child: ProcessId) -> Result<(), Errno> {
    let path = path_c_string(&system.paths().barrier)?;
    for _ in 0..BARRIER_ATTEMPTS {
        match sys::open(
            &path,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC | OpenFlags::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => return write_barrier(system, &descriptor),
            Err(Errno::ENXIO | Errno::EINTR) => {}
            Err(error) => return Err(error),
        }
        match sys::has_exited(child) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(Errno::ETIMEDOUT)
}

/// Writes the barrier with SIGPIPE temporarily ignored and exactly restored.
fn write_barrier(system: &mut impl System, descriptor: &FileDescriptor) -> Result<(), Errno> {
    sys::with_sigpipe_ignored(|| system.write_barrier(descriptor, b"start\n"))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::thread;

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
        let mut child = Command::new("/bin/true").spawn().unwrap();
        let process = ProcessId::from_child(&child);
        release_barrier(&mut system, process).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn parent_barrier_release_handles_a_reader_closing_during_write() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let path = path_c_string(&system.paths.barrier).unwrap();
        let reader = sys::open(
            &path,
            OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC | OpenFlags::O_NONBLOCK,
            Mode::empty(),
        )
        .unwrap();
        system.close_barrier_reader = Some(reader);
        system.fail_barrier_write = Some(Errno::EPIPE);
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let error = release_barrier(&mut system, ProcessId::from_child(&child)).unwrap_err();
        assert_eq!(error, Errno::EPIPE);
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn parent_barrier_release_preserves_a_live_child_start() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let path = system.paths.barrier.clone();
        let reader = thread::spawn(move || {
            let mut fifo = std::fs::OpenOptions::new().read(true).open(path).unwrap();
            let mut message = [0u8; 6];
            fifo.read_exact(&mut message).unwrap();
            message
        });
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        release_barrier(&mut system, ProcessId::from_child(&child)).unwrap();
        assert_eq!(reader.join().unwrap(), *b"start\n");
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn write_barrier_restores_the_sigpipe_disposition() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        let (left, right) = UnixStream::pair().unwrap();
        let writer = FileDescriptor::from_owned(left.into());
        let reader = FileDescriptor::from_owned(right.into());
        system.close_barrier_reader = Some(reader);
        system.fail_barrier_write = Some(Errno::EPIPE);
        let before = sys::sigpipe_disposition().unwrap();
        assert_eq!(
            write_barrier(&mut system, &writer).unwrap_err(),
            Errno::EPIPE
        );
        let after = sys::sigpipe_disposition().unwrap();
        assert_eq!(before, after);
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
            assert_eq!(error, Errno::ENOMEM);
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
        assert!(matches!(failure, EnvironmentFailure::Launch(Errno::ENOMEM)));
        assert!(system.execs.is_empty());
    }
}
