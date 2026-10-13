use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::host::platform::Transport;
use crate::protocol::{
    self, OUTER_ACK, OUTER_CREDIT, OUTER_DATA, OUTER_GUEST_ATTACH, OUTER_HEADER_LEN,
    OUTER_HOST_ATTACH, OUTER_READY, OUTER_RESET, OuterHeader,
};

use super::diagnostics::{c_string, close};
use super::launch::SpawnRequest;
use super::seam::{Paths, System, TestSystem};

struct BrokerCore {
    guest: UnixStream,
    host_output: VecDeque<u8>,
    instance_id: [u8; 16],
    epoch: u64,
    initialized: bool,
    active_host: bool,
    host_receive_sequence: u64,
    host_send_sequence: u64,
    guest_send_sequence: u64,
    guest_receive_sequence: u64,
    receive_window: u32,
    receive_credit: u32,
}

impl BrokerCore {
    fn new(guest: UnixStream) -> Self {
        Self {
            guest,
            host_output: VecDeque::new(),
            instance_id: core::array::from_fn(|index| index as u8 + 1),
            epoch: 0,
            initialized: false,
            active_host: false,
            host_receive_sequence: 0,
            host_send_sequence: 0,
            guest_send_sequence: 0,
            guest_receive_sequence: 0,
            receive_window: 0,
            receive_credit: 0,
        }
    }

    fn attach_host(&mut self, header: OuterHeader, payload: &[u8]) -> io::Result<()> {
        if header.record_type != OUTER_HOST_ATTACH
            || header.instance_id != [0; 16]
            || header.epoch != 0
            || header.sequence != 0
            || payload.len() != protocol::CAPABILITY_LEN
            || self.active_host
        {
            return Err(protocol_error());
        }
        self.host_output.clear();
        self.host_receive_sequence = 0;
        self.host_send_sequence = 1;
        if !self.initialized {
            let (attach, payload) = self.read_guest(Some(Duration::from_secs(5)))?;
            if attach.record_type != OUTER_GUEST_ATTACH
                || attach.instance_id != [0; 16]
                || attach.epoch != 0
                || attach.sequence != 0
                || !payload.is_empty()
            {
                return Err(protocol_error());
            }
            self.epoch = 1;
            self.reset_guest()?;
            self.initialized = true;
        }
        self.active_host = true;
        self.queue_host(OUTER_READY, 0, &[])
    }

    fn accept_host_data(&mut self, header: OuterHeader, payload: &[u8]) -> io::Result<()> {
        if !self.active_host
            || header.record_type != OUTER_DATA
            || header.instance_id != self.instance_id
            || header.epoch != self.epoch
            || header.sequence != self.host_receive_sequence
            || payload.is_empty()
            || payload.len() > self.receive_credit as usize
        {
            return Err(protocol_error());
        }
        self.host_receive_sequence = self.host_receive_sequence.wrapping_add(1);
        self.receive_credit -= payload.len() as u32;
        let record = protocol::encode_outer(
            OUTER_DATA,
            &self.instance_id,
            self.epoch,
            self.guest_send_sequence,
            payload,
        )
        .map_err(|_| protocol_error())?;
        self.guest_send_sequence = self.guest_send_sequence.wrapping_add(1);
        self.guest.write_all(&record)
    }

    fn pump_guest(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        loop {
            let (header, payload) = self.read_guest(timeout)?;
            if header.instance_id != self.instance_id
                || header.epoch != self.epoch
                || header.sequence != self.guest_receive_sequence
            {
                return Err(protocol_error());
            }
            self.guest_receive_sequence = self.guest_receive_sequence.wrapping_add(1);
            match header.record_type {
                OUTER_CREDIT => {
                    let credit =
                        protocol::decode_credit_payload(&payload).map_err(|_| protocol_error())?;
                    let available = self
                        .receive_credit
                        .checked_add(credit)
                        .filter(|available| *available <= self.receive_window)
                        .ok_or_else(protocol_error)?;
                    self.receive_credit = available;
                }
                OUTER_DATA => {
                    self.queue_host(OUTER_DATA, self.host_send_sequence, &payload)?;
                    self.host_send_sequence = self.host_send_sequence.wrapping_add(1);
                    return Ok(());
                }
                _ => return Err(protocol_error()),
            }
        }
    }

    fn reset_active_host(&mut self) -> io::Result<()> {
        if !self.initialized {
            return Err(protocol_error());
        }
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        self.host_output.clear();
        self.receive_credit = 0;
        self.reset_guest()?;
        self.queue_host(OUTER_RESET, 0, &[])
    }

    fn reset_guest(&mut self) -> io::Result<()> {
        self.guest_send_sequence = 1;
        self.guest_receive_sequence = 0;
        let reset = protocol::encode_outer(OUTER_RESET, &self.instance_id, self.epoch, 0, &[])
            .map_err(|_| protocol_error())?;
        self.guest.write_all(&reset)?;
        loop {
            let (header, payload) = self.read_guest(Some(Duration::from_secs(5)))?;
            if header.record_type == OUTER_ACK
                && header.instance_id == self.instance_id
                && header.epoch == self.epoch
                && header.sequence == 0
            {
                let window =
                    protocol::decode_ack_payload(&payload).map_err(|_| protocol_error())?;
                self.receive_window = window;
                self.receive_credit = window;
                self.guest_receive_sequence = 1;
                return Ok(());
            }
            // The real broker discards records from the retired epoch while reset drains.
        }
    }

    fn queue_host(&mut self, record_type: u8, sequence: u64, payload: &[u8]) -> io::Result<()> {
        let record = protocol::encode_outer(
            record_type,
            &self.instance_id,
            self.epoch,
            sequence,
            payload,
        )
        .map_err(|_| protocol_error())?;
        self.host_output.extend(record);
        Ok(())
    }

    fn read_guest(&mut self, timeout: Option<Duration>) -> io::Result<(OuterHeader, Vec<u8>)> {
        self.guest.set_read_timeout(timeout)?;
        let mut header = [0u8; OUTER_HEADER_LEN];
        self.guest.read_exact(&mut header).map_err(timeout_error)?;
        let header = protocol::decode_outer_header(&header).map_err(|_| protocol_error())?;
        let mut payload = vec![0; header.length];
        self.guest.read_exact(&mut payload).map_err(timeout_error)?;
        Ok((header, payload))
    }
}

struct BrokerTransport {
    core: Arc<Mutex<BrokerCore>>,
}

impl Drop for BrokerTransport {
    fn drop(&mut self) {
        if let Ok(mut core) = self.core.lock() {
            core.active_host = false;
        }
    }
}

impl Transport for BrokerTransport {
    fn read(&mut self, buffer: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        let mut core = self.core.lock().unwrap();
        if core.host_output.is_empty() {
            core.pump_guest(timeout)?;
        }
        let count = buffer.len().min(core.host_output.len());
        for byte in &mut buffer[..count] {
            *byte = core.host_output.pop_front().expect("the count is bounded");
        }
        Ok(count)
    }

    fn write_all(&mut self, data: &[u8], _timeout: Option<Duration>) -> io::Result<()> {
        if data.len() < OUTER_HEADER_LEN {
            return Err(protocol_error());
        }
        let header = protocol::decode_outer_header(
            data[..OUTER_HEADER_LEN]
                .try_into()
                .map_err(|_| protocol_error())?,
        )
        .map_err(|_| protocol_error())?;
        let payload = data
            .get(OUTER_HEADER_LEN..)
            .filter(|payload| payload.len() == header.length)
            .ok_or_else(protocol_error)?;
        let mut core = self.core.lock().unwrap();
        match header.record_type {
            OUTER_HOST_ATTACH => core.attach_host(header, payload),
            OUTER_DATA => core.accept_host_data(header, payload),
            _ => Err(protocol_error()),
        }
    }
}

#[derive(Clone)]
struct BrokerHandle {
    core: Arc<Mutex<BrokerCore>>,
}

impl BrokerHandle {
    fn transport(&self) -> Box<dyn Transport> {
        Box::new(BrokerTransport {
            core: Arc::clone(&self.core),
        })
    }

    fn reset(&self) {
        self.core.lock().unwrap().reset_active_host().unwrap();
    }
}

struct LoopbackSystem {
    inner: TestSystem,
}

impl System for LoopbackSystem {
    fn paths(&self) -> &Paths {
        self.inner.paths()
    }

    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: libc::c_ulong,
    ) -> io::Result<()> {
        self.inner.mount(source, target, filesystem, flags)
    }

    fn chown(&mut self, path: &CStr, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
        self.inner.chown(path, uid, gid)
    }

    fn chmod(&mut self, path: &CStr, mode: libc::mode_t) -> io::Result<()> {
        self.inner.chmod(path, mode)
    }

    fn configure_tty(&mut self, fd: libc::c_int) -> io::Result<()> {
        self.inner.configure_tty(fd)
    }

    fn drain_tty(&mut self, fd: libc::c_int) -> io::Result<()> {
        self.inner.drain_tty(fd)
    }

    fn write_diagnostic(&mut self, message: &[u8]) -> io::Result<()> {
        self.inner.write_diagnostic(message)
    }

    fn write_barrier(&mut self, fd: libc::c_int, message: &[u8]) -> io::Result<()> {
        self.inner.write_barrier(fd, message)
    }

    fn set_env(&mut self, name: &CStr, value: &CStr) -> io::Result<()> {
        self.inner.set_env(name, value)
    }

    fn validate_environment(&mut self, name: &CStr, value: &CStr) -> io::Result<()> {
        self.inner.validate_environment(name, value)
    }

    fn unset_env(&mut self, name: &CStr) -> io::Result<()> {
        self.inner.unset_env(name)
    }

    fn clear_env(&mut self) -> io::Result<()> {
        self.inner.clear_env()
    }

    fn exec(&mut self, path: &CStr, arguments: &[*const libc::c_char]) -> io::Result<()> {
        self.inner.exec(path, arguments)
    }

    fn spawn(&mut self, request: SpawnRequest<'_>) -> io::Result<libc::pid_t> {
        spawn_unprivileged(request)
    }
}

fn spawn_unprivileged(request: SpawnRequest<'_>) -> io::Result<libc::pid_t> {
    let arguments: Vec<CString> = request
        .execution
        .argv
        .iter()
        .map(|argument| c_string(argument))
        .collect::<io::Result<_>>()?;
    let mut pointers: Vec<_> = arguments.iter().map(|argument| argument.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let directory = c_string(request.execution.cwd.as_deref().unwrap_or(b"/"))?;
    let program = arguments.first().ok_or_else(protocol_error)?;
    // SAFETY: all allocation happened before fork. The child uses only async-signal-safe calls.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: this is the post-fork child and every pointer names retained storage.
        unsafe {
            libc::setpgid(0, 0);
            libc::close(request.stdout_pipe[0]);
            libc::close(request.stderr_pipe[0]);
            libc::close(request.launch_pipe[0]);
            libc::close(request.launch_pipe[1]);
            libc::close(request.config_fd);
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if null >= 0 {
                libc::dup2(null, libc::STDIN_FILENO);
                libc::close(null);
            }
            libc::dup2(request.stdout_pipe[1], libc::STDOUT_FILENO);
            libc::dup2(request.stderr_pipe[1], libc::STDERR_FILENO);
            libc::close(request.stdout_pipe[1]);
            libc::close(request.stderr_pipe[1]);
            if libc::chdir(directory.as_ptr()) != 0 {
                libc::_exit(125);
            }
            libc::execv(program.as_ptr(), pointers.as_ptr());
            libc::_exit(125);
        }
    }
    // SAFETY: the child is ours; a racing exit is harmless.
    unsafe { libc::setpgid(child, child) };
    Ok(child)
}

fn protocol_error() -> io::Error {
    io::Error::from_raw_os_error(libc::EPROTO)
}

fn timeout_error(error: io::Error) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        io::ErrorKind::TimedOut.into()
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Instant;

    use crate::host::session::{ControlSession, ExecEvent, SessionError};
    use crate::protocol::{
        CAPABILITY_LEN, ExitCategory, GuestFeatures, HostMap, Workload, WorkloadEnvironment,
    };

    use super::super::AgentConfig;
    use super::super::dispatch;
    use super::super::mappings::HostMappings;
    use super::super::session::Session;
    use super::*;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    fn run_exec(
        session: &mut ControlSession,
        workload: &Workload<'_>,
    ) -> (Vec<u8>, Vec<u8>, ExecEvent) {
        let id = session.start_exec(workload, deadline()).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            match session.next_exec_event(id, Some(deadline())).unwrap() {
                ExecEvent::Stdout(bytes) => stdout.extend(bytes),
                ExecEvent::Stderr(bytes) => stderr.extend(bytes),
                event @ ExecEvent::Exit { .. } | event @ ExecEvent::Rejected { .. } => {
                    return (stdout, stderr, event);
                }
            }
        }
    }

    #[test]
    fn control_session_broker_and_real_agent_loop_back() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let cgroup = temporary.path().join("cgroup");
        std::fs::create_dir_all(cgroup.join("nvx-exec")).unwrap();
        for (path, contents) in [
            ("cgroup.procs", b"".as_slice()),
            ("cgroup.subtree_control", b""),
            ("nvx-exec/cgroup.procs", b""),
            ("nvx-exec/cgroup.kill", b""),
            ("nvx-exec/pids.current", b"0\n"),
        ] {
            std::fs::write(cgroup.join(path), contents).unwrap();
        }
        let hostfs = temporary.path().join("hostfs");
        std::fs::create_dir_all(hostfs.join("root/0/source")).unwrap();
        let target = temporary.path().join("mapped");
        let paths = Paths {
            cgroup_root: cgroup,
            hostfs_dir: hostfs,
            ..Paths::default()
        };
        let system = LoopbackSystem {
            inner: TestSystem::new(paths),
        };
        let (broker_guest, agent) = UnixStream::pair().unwrap();
        let agent_fd = agent.into_raw_fd();
        let agent_thread = thread::spawn(move || {
            let mut system = system;
            let config = AgentConfig {
                rootfs: c"-".to_owned(),
                hostname: c"loopback".to_owned(),
                uid: c"1000".to_owned(),
                gid: c"1000".to_owned(),
                user: c"workload".to_owned(),
                home: c"/".to_owned(),
                direct: true,
            };
            let mut session = Session::new(agent_fd);
            let mut mappings = HostMappings {
                expected: 1,
                ..HostMappings::default()
            };
            let outcome = dispatch::run(&mut system, &mut session, &config, &mut mappings).unwrap();
            close(agent_fd);
            (outcome, system)
        });
        let core = Arc::new(Mutex::new(BrokerCore::new(broker_guest)));
        let broker = BrokerHandle { core };
        let capability = [0x5a; CAPABILITY_LEN];
        let mut session =
            ControlSession::attach(broker.transport(), &capability, deadline()).unwrap();

        session.ping(deadline()).unwrap();
        assert_eq!(
            session.features(deadline()).unwrap(),
            GuestFeatures::DIRECT_AGENT
        );
        session
            .map_host_paths(
                &[HostMap {
                    source: "0/source".to_owned(),
                    target: target.to_string_lossy().into_owned(),
                    read_only: true,
                }],
                deadline(),
            )
            .unwrap();

        let workload = |script: &str, timeout_ms| Workload {
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
            timeout_ms,
            cwd: None,
            environment: WorkloadEnvironment::Default,
        };
        let (stdout, stderr, exit) = run_exec(
            &mut session,
            &workload("printf out; printf err >&2; exit 7", 0),
        );
        assert_eq!((stdout, stderr), (b"out".to_vec(), b"err".to_vec()));
        assert_eq!(
            exit,
            ExecEvent::Exit {
                category: ExitCategory::Exit,
                status: 7
            }
        );

        let (_, _, signal) = run_exec(&mut session, &workload("kill -TERM $$", 0));
        assert_eq!(
            signal,
            ExecEvent::Exit {
                category: ExitCategory::Signal,
                status: 128 + libc::SIGTERM
            }
        );
        let (_, _, timeout) = run_exec(&mut session, &workload("sleep 10", 25));
        assert_eq!(
            timeout,
            ExecEvent::Exit {
                category: ExitCategory::Timeout,
                status: 124
            }
        );
        let (_, _, limited) = run_exec(&mut session, &workload("head -c 1048577 /dev/zero", 0));
        assert_eq!(
            limited,
            ExecEvent::Exit {
                category: ExitCategory::OutputLimit,
                status: 125
            }
        );

        let cancel_id = session
            .start_exec(&workload("sleep 10", 0), deadline())
            .unwrap();
        session.cancel_exec(cancel_id, deadline()).unwrap();
        assert_eq!(
            session
                .next_exec_event(cancel_id, Some(deadline()))
                .unwrap(),
            ExecEvent::Exit {
                category: ExitCategory::Cancelled,
                status: 128 + libc::SIGKILL
            }
        );

        let reset_id = session
            .start_exec(&workload("sleep 10", 0), deadline())
            .unwrap();
        broker.reset();
        assert!(matches!(
            session.next_exec_event(reset_id, Some(deadline())),
            Err(SessionError::Reset)
        ));
        drop(session);
        let mut session =
            ControlSession::attach(broker.transport(), &capability, deadline()).unwrap();
        session.ping(deadline()).unwrap();
        session.stop(deadline()).unwrap();
        drop(session);

        let (_outcome, system) = agent_thread.join().unwrap();
        assert_eq!(system.inner.mounts.len(), 2);
        assert!(system.inner.diagnostics.is_empty());
    }
}
