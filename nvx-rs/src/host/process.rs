//! Launch and supervision of OpenVMM processes.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::filesystem::{self, FileIdentity};
use super::instance::ProcessIdentity;
use super::platform;
use crate::protocol::CAPABILITY_LEN;

const KILL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// An OpenVMM process this caller launched and has not released yet.
///
/// Release it with [`detach_child`], or terminate it with [`kill_child`].
pub struct Launched {
    #[cfg(not(windows))]
    child: Child,
    #[cfg(windows)]
    process: platform::LaunchedProcess,
    log_handles: [u64; 2],
}

impl Launched {
    /// Returns the process ID.
    pub fn id(&self) -> u32 {
        #[cfg(not(windows))]
        return self.child.id();
        #[cfg(windows)]
        return self.process.id();
    }

    /// Claims the log only after checking the objects held by the child's stdout and stderr.
    ///
    /// The caller retains this process handle on error and must terminate or record the child.
    /// `launch_id` is the caller's unique activation identity, not an application protocol.
    pub fn claim_log(&self, launch_id: &str, path: &Path) -> io::Result<LaunchLogClaim> {
        if launch_id.is_empty() || launch_id.len() > 128 || !launch_id.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid launch identity",
            ));
        }
        let path = filesystem::canonicalize(path)?;
        let (device, index) = platform::file_identity(&path)?;
        let start_time = platform::process_start_time(self.id())?
            .ok_or_else(|| io::Error::other("the launched process already exited"))?;
        let claim = LaunchLogClaim {
            launch_id: launch_id.to_owned(),
            process: ProcessIdentity {
                pid: self.id(),
                start_time,
            },
            path,
            identity: FileIdentity { device, index },
            handles: self.log_handles,
        };
        claim.verify()?;
        Ok(claim)
    }
}

/// An opened-object log claim, suitable for the caller's own recovery record.
///
/// A launch marker or a PID printed in a log is not this proof. Verification checks the live
/// process's inherited handles as well as the log pathname and PID/start-time identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchLogClaim {
    /// Unique caller-selected activation identity.
    pub launch_id: String,
    /// The process that inherited the log.
    pub process: ProcessIdentity,
    /// Canonical log pathname.
    pub path: PathBuf,
    /// Identity of the opened log object.
    pub identity: FileIdentity,
    /// Child stdout/stderr descriptors on Linux or inherited handle values on Windows.
    pub handles: [u64; 2],
}

impl LaunchLogClaim {
    /// Verifies a recovered claim without truncating or taking ownership of an unrelated log.
    pub fn verify(&self) -> io::Result<()> {
        filesystem::check_root(&self.path).map_err(io::Error::other)?;
        if filesystem::canonicalize(&self.path)? != self.path
            || !std::fs::metadata(&self.path)?.is_file()
            || platform::file_identity(&self.path)? != (self.identity.device, self.identity.index)
            || !platform::process_owns_log(
                self.process.pid,
                self.process.start_time,
                self.handles,
                (self.identity.device, self.identity.index),
            )?
        {
            return Err(io::Error::other(
                "the launch log is not owned by the recorded process",
            ));
        }
        Ok(())
    }
}

/// Creates a new private launch log, refusing an existing path instead of truncating it.
///
/// The caller supplies a private state directory and serializes launches. Use a unique path
/// per activation; old logs and another live process's output are never overwritten.
pub fn create_launch_log(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launch log path must be absolute",
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Starts OpenVMM detached from the caller.
///
/// OpenVMM reads its capability from standard input as soon as it starts, so the capability is
/// written into a pipe whose write end is closed before the spawn. The capability never appears
/// in arguments, the environment, or the log. OpenVMM output goes to `log`, and OpenVMM inherits
/// no other handle of the caller, so a caller whose own output is a pipe sees end-of-file when it
/// exits rather than when the VM does.
///
/// On Windows, `breakaway_from_job` starts OpenVMM outside the caller's job object, which must
/// permit breakaway, so that the VM survives the caller.
pub fn spawn(
    openvmm: &Path,
    breakaway_from_job: bool,
    arguments: &[OsString],
    capability: &[u8; CAPABILITY_LEN],
    log: File,
    working_dir: &Path,
) -> io::Result<Launched> {
    let (stdin, mut writer) = io::pipe()?;
    writer.write_all(capability)?;
    drop(writer);
    let stderr = log.try_clone()?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let log_handles = [
            log.as_raw_handle() as usize as u64,
            stderr.as_raw_handle() as usize as u64,
        ];
        platform::spawn_detached(
            openvmm,
            arguments,
            working_dir,
            [stdin.into(), log.into(), stderr.into()],
            breakaway_from_job,
        )
        .map(|process| Launched {
            process,
            log_handles,
        })
    }
    #[cfg(not(windows))]
    {
        // Rust opens its own descriptors close-on-exec, and `platform::detach` marks any other
        // descriptor of the caller, so OpenVMM receives only these.
        let mut command = Command::new(openvmm);
        command
            .args(arguments)
            .current_dir(working_dir)
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr));
        platform::detach(&mut command, breakaway_from_job);
        command.spawn().map(|child| Launched {
            child,
            log_handles: [1, 2],
        })
    }
}

/// Releases a launched process without waiting for it.
///
/// On Unix a background thread reaps the child once it exits so it does not linger as a zombie
/// while this process lives. If that thread cannot start, the child becomes a zombie after it
/// exits; liveness checks treat zombies without threads as exited, so only the process table
/// entry leaks. The OpenVMM process keeps running either way.
pub fn detach_child(launched: Launched) {
    #[cfg(not(windows))]
    {
        let mut child = launched.child;
        let _ = thread::Builder::new()
            .name("nvx-openvmm-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
    #[cfg(windows)]
    drop(launched);
}

/// Kills a launched process that was never recorded, through its handle, which cannot race with
/// process ID reuse. Returns whether it exited within ten seconds.
pub fn kill_child(launched: Launched) -> bool {
    #[cfg(windows)]
    return launched.process.terminate(KILL_TIMEOUT);
    #[cfg(not(windows))]
    {
        let mut child = launched.child;
        if child.kill().is_ok() {
            let deadline = Instant::now() + KILL_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return true,
                    Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                    _ => break,
                }
            }
        }
        detach_child(Launched {
            child,
            log_handles: launched.log_handles,
        });
        false
    }
}

/// Waits until the process with the given identity is gone, returning whether it exited before
/// `deadline`. Inconclusive checks count as still running.
pub fn wait_for_exit(pid: u32, start_time: u64, deadline: Instant) -> bool {
    wait_for_exit_checked(pid, start_time, deadline).is_ok_and(|wait| wait.exited)
}

/// Mechanism used to wait for a recorded process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitWaitMethod {
    /// A Linux pidfd or a Windows process-handle exit event.
    Event,
    /// An identity check at every poll on hosts where an exit event is unavailable.
    IdentityPolling,
}

/// Outcome of an identity-checked process wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitWait {
    /// Whether the recorded process exited before the deadline.
    pub exited: bool,
    /// Event-driven wait or explicitly guarded fallback.
    pub method: ExitWaitMethod,
}

/// Waits on an OS exit event, falling back only when the platform explicitly lacks that event.
///
/// Unlike the legacy boolean wrapper, inconclusive identity or wait errors are returned.
pub fn wait_for_exit_checked(pid: u32, start_time: u64, deadline: Instant) -> io::Result<ExitWait> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process ID must be nonzero",
        ));
    }
    match platform::wait_process_exit(pid, start_time, deadline)? {
        Some(exited) => Ok(ExitWait {
            exited,
            method: ExitWaitMethod::Event,
        }),
        None => poll_exit(start_time, deadline, || platform::process_start_time(pid)),
    }
}

fn poll_exit(
    start_time: u64,
    deadline: Instant,
    mut current: impl FnMut() -> io::Result<Option<u64>>,
) -> io::Result<ExitWait> {
    loop {
        if current()? != Some(start_time) {
            return Ok(ExitWait {
                exited: true,
                method: ExitWaitMethod::IdentityPolling,
            });
        }
        if Instant::now() >= deadline {
            return Ok(ExitWait {
                exited: false,
                method: ExitWaitMethod::IdentityPolling,
            });
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Kills the process and waits up to ten seconds for it to disappear.
pub fn kill(pid: u32, start_time: u64) -> io::Result<bool> {
    platform::kill_process(pid, start_time)?;
    Ok(wait_for_exit_checked(pid, start_time, Instant::now() + KILL_TIMEOUT)?.exited)
}

#[cfg(test)]
mod wait_tests {
    use super::*;

    #[test]
    fn fallback_checks_identity_and_surfaces_inconclusive_checks() {
        let deadline = Instant::now();
        assert!(!poll_exit(7, deadline, || Ok(Some(7))).unwrap().exited);
        for current in [Some(8), None] {
            let wait = poll_exit(7, deadline, || Ok(current)).unwrap();
            assert!(wait.exited);
            assert_eq!(wait.method, ExitWaitMethod::IdentityPolling);
        }
        assert!(poll_exit(7, deadline, || Err(io::Error::other("inconclusive"))).is_err());
        assert!(wait_for_exit_checked(0, 7, deadline).is_err());
    }

    #[test]
    fn launch_logs_never_overwrite_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("launch.log");
        let mut log = create_launch_log(&path).unwrap();
        log.write_all(b"owned").unwrap();
        assert_eq!(
            create_launch_log(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"owned");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;

    use super::*;

    /// Spawns a long-running child while this process holds an inheritable pipe writer, as a
    /// descriptor that the caller's parent or native code left without close-on-exec would be.
    /// Returns whether the child keeps a copy, which shows as the reader not reaching end-of-file
    /// once this process closes its own.
    fn child_keeps_inherited_writer(spawn: impl FnOnce() -> Child) -> bool {
        let (mut reader, writer) = io::pipe().unwrap();
        // SAFETY: clearing FD_CLOEXEC only changes the flags of a descriptor this test owns.
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let mut child = spawn();
        drop(writer);
        let (finished, received) = mpsc::channel();
        let drain = thread::spawn(move || {
            let _ = reader.read_to_end(&mut Vec::new());
            let _ = finished.send(());
        });
        let reached_end = received.recv_timeout(Duration::from_secs(2)).is_ok();
        child.kill().unwrap();
        child.wait().unwrap();
        drain.join().unwrap();
        !reached_end
    }

    fn sleeper() -> Command {
        let mut command = Command::new("sleep");
        command.arg("60").stdin(Stdio::null());
        command
    }

    #[test]
    fn openvmm_inherits_no_descriptor_beyond_its_standard_streams() {
        // A plain child keeps the writer, which shows that the check detects a leak.
        let plain = || sleeper().spawn().unwrap();
        assert!(child_keeps_inherited_writer(plain));

        let directory = tempfile::tempdir().unwrap();
        let openvmm = || {
            let log = File::create(directory.path().join("openvmm.log")).unwrap();
            let arguments = [OsString::from("60")];
            let capability = [1; CAPABILITY_LEN];
            let launched = spawn(
                Path::new("sleep"),
                false,
                &arguments,
                &capability,
                log,
                directory.path(),
            );
            launched.unwrap().child
        };
        assert!(!child_keeps_inherited_writer(openvmm));

        // Kernels without CLOSE_RANGE_CLOEXEC take the /proc/self/fd fallback.
        let fallback = || {
            let mut command = sleeper();
            // SAFETY: the fallback allocates nothing and makes only async-signal-safe calls.
            unsafe { command.pre_exec(platform::mark_listed_descriptors_close_on_exec) };
            command.spawn().unwrap()
        };
        assert!(!child_keeps_inherited_writer(fallback));
    }

    #[test]
    fn zombies_run_while_other_threads_remain() {
        // Field 22 of a stat line, the start time, is 22 here; the command name holds a space
        // and a parenthesis.
        let stat = |state: &str| {
            let fields: Vec<String> = (4..=22).map(|field| field.to_string()).collect();
            format!("7 (open vmm)) {state} {}\n", fields.join(" "))
        };
        let unasked = || -> io::Result<bool> { panic!("only zombies count their threads") };
        let start_time = |state: &str, remain: io::Result<bool>| {
            platform::start_time_from_stat(7, &stat(state), || remain)
        };
        for state in ["R", "S", "D", "T"] {
            assert_eq!(
                platform::start_time_from_stat(7, &stat(state), unasked).unwrap(),
                Some(22)
            );
        }
        assert_eq!(
            platform::start_time_from_stat(7, &stat("X"), unasked).unwrap(),
            None
        );
        assert_eq!(start_time("Z", Ok(true)).unwrap(), Some(22));
        assert_eq!(start_time("Z", Ok(false)).unwrap(), None);
        assert!(start_time("Z", Err(io::Error::other("unreadable"))).is_err());
        assert!(platform::start_time_from_stat(7, "7 (vmm) S 1 2", unasked).is_err());
        assert!(platform::start_time_from_stat(7, "garbage", unasked).is_err());
    }

    /// Kills and reaps a child process when dropped, even when a test fails.
    struct Reaped(Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_process_runs_until_its_last_thread_exits() {
        // The main thread leaves through pthread_exit, which turns it into a zombie, while
        // another thread sleeps. Python is the only portable way to arrange that here.
        let spawned = Command::new("python3")
            .args([
                "-c",
                "import ctypes, threading, time\n\
                 threading.Thread(target=time.sleep, args=(60,)).start()\n\
                 ctypes.CDLL(None).pthread_exit(None)\n",
            ])
            .stdin(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => Reaped(child),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipping: python3 is not installed");
                return;
            }
            Err(error) => panic!("cannot start python3: {error}"),
        };
        let pid = child.0.id();
        let start_time = platform::process_start_time(pid).unwrap().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            if stat[stat.rfind(')').unwrap() + 1..]
                .trim_start()
                .starts_with('Z')
            {
                break;
            }
            assert!(Instant::now() < deadline, "the main thread did not exit");
            thread::sleep(POLL_INTERVAL);
        }
        assert_eq!(platform::process_start_time(pid).unwrap(), Some(start_time));
        assert!(!wait_for_exit(
            pid,
            start_time,
            Instant::now() + Duration::from_millis(100)
        ));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(wait_for_exit(pid, start_time, Instant::now()));
    }
}
