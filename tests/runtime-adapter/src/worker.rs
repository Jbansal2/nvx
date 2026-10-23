//! The adapter's worker: the guest agent of a VM with a layered root. It assembles the root through
//! `nvx::guest::root` in a process of its own, never PID 1, and serves the host program until the
//! host stops it.
//!
//! # PID 1 and the worker
//!
//! In a VM with a layered root, NVX's `/init` runs `/sbin/nvx-init-agent`, which the adapter's
//! initramfs replaces with `runtime-adapter-guest init /dev/hvc2 layered`; see the host side's
//! `initramfs` module. That PID 1, [`supervise`], stays minimal:
//!
//! 1. It starts an unrelated child, `runtime-adapter-guest idle`, which stands for a daemon that a
//!    guest starts before its agent, and which the worker leaves as it is.
//! 2. It starts the worker, `runtime-adapter-guest worker /dev/hvc2 SIBLING`, with the process ID
//!    of the unrelated child, which the worker's probes check.
//! 3. It collects the status of every child, adopted processes included, until the worker ends,
//!    and then ends the VM with the worker's status, through NVX's `/sbin/nvx-exit`.
//!
//! The worker, [`work`], runs the session in this order:
//!
//! 1. It opens the tty and attaches the session.
//! 2. It receives the host's root configuration, a [`RootConfig`], and checks it.
//! 3. It reads the boot layout of the root from the kernel command line with
//!    `nvx::protocol::root::RootLayout::parse`, then bootstraps the guest and assembles the root.
//! 4. It answers `RootReady`, or `RootFailed` with the stage that failed, and then ends.
//! 5. It serves `Ping`, `Echo`, and `Probe`, whose probes the [`probes`] and [`mapping`] modules
//!    run.
//! 6. On `Stop`, it tears the root down, reports a teardown that failed with `RootFailed`,
//!    confirms the stop with `Stopped`, and ends.
//!
//! Before the root configuration, it accepts only the configuration, or a `Stop`, which ends it
//! without a root. It assembles an EROFS image, over an ext4 scratch or over RAM, in the overlay
//! mode that the configuration names, and refuses a GPT image at the layout stage, as it refuses a
//! configuration that configures a scratch for a root over RAM.
//!
//! The worker, and with it the VM, ends with 0 once the host stopped it, after a teardown that
//! succeeded, with the stage's [exit status](RootStage::exit_status) once a stage failed, from 11
//! for the configuration to 15 for the teardown, and with [`SESSION_STATUS`] once its session
//! failed or the broker closed it.

pub mod mapping;
pub mod probes;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{self, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nvx::guest::cgroup::Layout;
use nvx::guest::root::{
    self, Assembly, Bootstrap, Device, Image, Journal, Resources, Root, Upper, UpperKind,
};
use nvx::protocol::root::{
    DISTRO_MMIO_BASE, ImageFormat, RootLayout, RootUpper, SCRATCH_MMIO_BASE,
};

use crate::frame::{MAX_BODY, MAX_TEXT_BODY, Message, truncated};
use crate::guest::{self, Ended, ServeError, Step};
use crate::probe::{Facts, Probe};
use crate::root::{JournalPolicy, OverlayMode, RootConfig, RootFailure, RootStage};

/// The status with which the worker ends once its session failed or the broker closed it, and
/// with which PID 1 ends the VM if a child cannot start or the worker's status cannot be collected.
pub const SESSION_STATUS: u8 = 1;

/// The kernel command line, from which the worker reads the boot layout of the root.
const COMMAND_LINE: &str = "/proc/cmdline";

/// The operations of a layered root that the worker runs: those of `nvx::guest::root` in a VM, in
/// [`LibraryRoot`], and a fake's in tests. Each fails with the problem, as text.
pub trait RootOperations {
    /// Returns the kernel command line, from which the worker reads the boot layout of the root.
    fn command_line(&mut self) -> Result<Vec<u8>, String>;

    /// Bootstraps the guest for the root that `config` configures: its cgroups, and their
    /// resource values.
    fn bootstrap(&mut self, config: &RootConfig) -> Result<(), String>;

    /// Assembles the root of `layout`, which the boot tokens name, as `config` configures it.
    fn assemble(&mut self, config: &RootConfig, layout: &RootLayout) -> Result<(), String>;

    /// Runs `probe` on the assembled root, and returns what it found.
    fn probe(&mut self, probe: &Probe) -> Result<Facts, String>;

    /// Tears the assembled root down.
    fn teardown(&mut self) -> Result<(), String>;
}

/// How the worker's session ended, when it did not fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Worked {
    /// The host stopped the worker, which tore its root down, if it had assembled one.
    Stopped,
    /// A stage of the root failed, which the worker reported to the host.
    Failed(RootFailure),
    /// The broker closed the stream at a record boundary.
    Closed,
}

impl Worked {
    /// Returns the status with which the worker ends: 0 once the host stopped it, the stage's
    /// [exit status](RootStage::exit_status) once a stage failed, and [`SESSION_STATUS`] once the
    /// broker closed the stream.
    pub fn status(&self) -> u8 {
        match self {
            Self::Stopped => 0,
            Self::Failed(failure) => failure.stage().exit_status(),
            Self::Closed => SESSION_STATUS,
        }
    }
}

/// Runs the worker's session on `stream`, the guest's end of the control session, with the root
/// operations `operations`, as the [module documentation](self) describes, until the host stops
/// the worker, a stage of the root fails, or the broker closes the stream.
///
/// A failure of the session, a malformed message, and a message that the worker does not accept
/// in its state end the session with an error, and leave a root that it assembled to
/// `operations`.
pub fn work<S: Read + Write>(
    stream: S,
    operations: &mut dyn RootOperations,
) -> Result<Worked, ServeError> {
    let mut ready = false;
    let ended = guest::session(stream, |message| {
        if ready {
            return serve_root(operations, message);
        }
        let step = configure_root(operations, message)?;
        ready = matches!(step, Step::Continue(_));
        Ok(step)
    })?;
    Ok(match ended {
        Ended::Handled(worked) => worked,
        Ended::Closed => Worked::Closed,
    })
}

/// Handles `message` before the root is ready: a root configuration, whose root it assembles
/// through `operations`, or a `Stop`.
fn configure_root(
    operations: &mut dyn RootOperations,
    message: Message,
) -> Result<Step<Worked>, ServeError> {
    match message {
        Message::RootConfig(body) => Ok(match assemble(operations, &body) {
            Ok(()) => Step::Continue(vec![Message::RootReady]),
            Err(failure) => Step::End(
                vec![Message::RootFailed(failure.encode())],
                Worked::Failed(failure),
            ),
        }),
        Message::Stop => Ok(Step::End(vec![Message::Stopped], Worked::Stopped)),
        message => Err(ServeError::Unexpected(message.kind())),
    }
}

/// Handles `message` once the root is ready, through `operations`.
fn serve_root(
    operations: &mut dyn RootOperations,
    message: Message,
) -> Result<Step<Worked>, ServeError> {
    Ok(match message {
        Message::Ping => Step::Continue(vec![Message::Pong]),
        Message::Echo(body) => Step::Continue(vec![Message::Echo(body)]),
        Message::Probe(body) => Step::Continue(vec![run_probe(operations, &body)]),
        Message::Stop => match operations.teardown() {
            Ok(()) => Step::End(vec![Message::Stopped], Worked::Stopped),
            Err(problem) => {
                let failure = RootFailure::new(RootStage::Teardown, problem);
                Step::End(
                    vec![Message::RootFailed(failure.encode()), Message::Stopped],
                    Worked::Failed(failure),
                )
            }
        },
        message => return Err(ServeError::Unexpected(message.kind())),
    })
}

/// Checks the root configuration `body`, reads the boot layout of the root, bootstraps the guest,
/// and assembles the root, through `operations`, or returns the failure of the stage that failed.
fn assemble(operations: &mut dyn RootOperations, body: &[u8]) -> Result<(), RootFailure> {
    let config = RootConfig::decode(body)
        .map_err(|error| RootFailure::new(RootStage::Configuration, error.problem()))?;
    let layout = layout(operations, &config)
        .map_err(|problem| RootFailure::new(RootStage::Layout, problem))?;
    operations
        .bootstrap(&config)
        .map_err(|problem| RootFailure::new(RootStage::Bootstrap, problem))?;
    operations
        .assemble(&config, &layout)
        .map_err(|problem| RootFailure::new(RootStage::Assembly, problem))
}

/// Reads the boot layout of the root from the kernel command line, through `operations`, and
/// checks that the worker assembles it as `config` configures it: an EROFS image, over an ext4
/// scratch, or over RAM if `config` configures no scratch.
fn layout(operations: &mut dyn RootOperations, config: &RootConfig) -> Result<RootLayout, String> {
    let command_line = operations.command_line()?;
    let layout = RootLayout::parse(&command_line)
        .map_err(|error| format!("the kernel command line has invalid boot tokens: {error}"))?
        .ok_or("the kernel command line names no layered root")?;
    if layout.image.format != ImageFormat::Erofs {
        return Err(format!(
            "the worker assembles only an EROFS image, not a {} image",
            layout.image.format
        ));
    }
    if layout.upper == RootUpper::Ram
        && (config.scratch_sectors.is_some() || config.scratch_journal.is_some())
    {
        return Err(
            "the root configuration configures a scratch, but the boot tokens keep the upper in RAM"
                .to_owned(),
        );
    }
    Ok(layout)
}

/// Runs the probe `body` through `operations`, and returns the worker's answer: a report of what
/// the probe found, or the problem.
fn run_probe(operations: &mut dyn RootOperations, body: &[u8]) -> Message {
    let found = Probe::decode(body)
        .map_err(|error| error.problem().to_owned())
        .and_then(|probe| operations.probe(&probe));
    let problem = match found {
        Ok(facts) => {
            let report = facts.encode();
            if report.len() <= MAX_BODY {
                return Message::Report(report);
            }
            format!(
                "the probe's report takes {} bytes, more than {MAX_BODY}",
                report.len()
            )
        }
        Err(problem) => problem,
    };
    Message::ProbeFailed(truncated(&problem, MAX_TEXT_BODY).as_bytes().to_vec())
}

/// The root operations of `nvx::guest::root` on the guest's kernel, whose probes the [`probes`]
/// module runs.
///
/// Dropping it closes the descriptors that probes keep open, then unmounts a root that it still
/// holds, as `nvx::guest::root::Root` does when it drops, ignoring failures.
pub struct LibraryRoot {
    /// The process ID of PID 1's unrelated child, which the probes check, if PID 1 named one.
    sibling: Option<u32>,
    /// What the bootstrap prepared, once it ran.
    bootstrap: Option<Bootstrap>,
    /// The descriptors that probes keep open until the worker ends, such as those of `hold`.
    /// They close before the root drops.
    held: Vec<File>,
    /// The root, from its assembly until its teardown.
    root: Option<Root>,
}

impl LibraryRoot {
    /// Returns the operations, with the process ID of PID 1's unrelated child, if any.
    pub fn new(sibling: Option<u32>) -> Self {
        Self {
            sibling,
            bootstrap: None,
            held: Vec::new(),
            root: None,
        }
    }
}

impl RootOperations for LibraryRoot {
    /// Reads `/proc/cmdline`.
    fn command_line(&mut self) -> Result<Vec<u8>, String> {
        fs::read(COMMAND_LINE).map_err(|error| format!("cannot read {COMMAND_LINE}: {error}"))
    }

    /// Runs `nvx::guest::root::bootstrap` with the configuration's cgroups and resource values.
    fn bootstrap(&mut self, config: &RootConfig) -> Result<(), String> {
        let layout = Layout::new(&config.agent_cgroup, &config.workload_cgroup)
            .map_err(|error| error.to_string())?;
        let resources = Resources {
            agent_memory_low: config.agent_memory_low,
            workload_memory_max: config.workload_memory_max,
            workload_pids_max: config.workload_pids_max,
        };
        let bootstrap = root::bootstrap(&layout, &resources).map_err(|error| error.to_string())?;
        self.bootstrap = Some(bootstrap);
        Ok(())
    }

    /// Runs `nvx::guest::root::assemble` on the block devices at the MMIO bases of their roles:
    /// the EROFS image, with the identity that the boot tokens expect of it, over the ext4
    /// scratch, with the configuration's journal policy, or over a tmpfs, in the configuration's
    /// overlay mode, with the configuration's runtime directory, device sizes, and timeout. A
    /// policy or a mode that the configuration does not name is the guest's default: a scratch
    /// may have a journal, and the overlay trusts its lowers.
    fn assemble(&mut self, config: &RootConfig, layout: &RootLayout) -> Result<(), String> {
        let upper = match layout.upper {
            RootUpper::Scratch => Upper::Scratch {
                device: Device {
                    mmio: SCRATCH_MMIO_BASE,
                    sectors: config.scratch_sectors,
                },
                journal: match config.scratch_journal {
                    None | Some(JournalPolicy::Allowed) => Journal::Allowed,
                    Some(JournalPolicy::Forbidden) => Journal::Forbidden,
                },
            },
            RootUpper::Ram => Upper::Tmpfs,
        };
        let overlay = match config.overlay_mode {
            None => root::OverlayMode::default(),
            Some(OverlayMode::TrustedLowers) => root::OverlayMode::TrustedLowers,
            Some(OverlayMode::UntrustedLowers) => root::OverlayMode::UntrustedLowers,
        };
        let assembly = Assembly {
            runtime: PathBuf::from(&config.runtime),
            distro: Device {
                mmio: DISTRO_MMIO_BASE,
                sectors: config.distro_sectors,
            },
            image: Image::Erofs {
                uuid: layout.image.identity,
            },
            upper,
            overlay,
            timeout: config.device_timeout,
        };
        let root = root::assemble(&assembly).map_err(|error| error.to_string())?;
        self.root = Some(root);
        Ok(())
    }

    /// Runs one of the [`probes`], or of the [`mapping`] probes, which map beneath the root.
    fn probe(&mut self, probe: &Probe) -> Result<Facts, String> {
        let (Some(bootstrap), Some(root)) = (&self.bootstrap, &mut self.root) else {
            return Err("the worker holds no root to probe".to_owned());
        };
        // The upper's mount point, below the runtime directory, as `nvx::guest::root` names it.
        let upper = match root.upper() {
            UpperKind::Scratch => "scratch",
            UpperKind::Tmpfs => "tmpfs",
            kind => return Err(format!("the worker probes no root over a {kind:?} upper")),
        };
        let (runtime, path) = (root.runtime().to_owned(), root.path().to_owned());
        let upper = runtime.join(upper);
        let lowers = root
            .lowers()
            .iter()
            .map(|lower| lower.path().to_owned())
            .collect::<Vec<_>>();
        let context = probes::Context {
            runtime: &runtime,
            root: &path,
            lowers: &lowers,
            upper: &upper,
            agent: bootstrap.layout().agent(),
            workload: bootstrap.layout().workload(),
            sibling: self.sibling,
        };
        if mapping::PROBES.contains(&probe.name()) {
            return mapping::run(probe, &context, root);
        }
        probes::run(probe, &context, &mut self.held)
    }

    /// Runs `nvx::guest::root::Root::teardown`. A root whose teardown failed keeps its mounts.
    fn teardown(&mut self) -> Result<(), String> {
        match self.root.take() {
            Some(root) => root.teardown().map_err(|error| error.to_string()),
            None => Ok(()),
        }
    }
}

/// Runs PID 1 of a VM with a layered root, as the [module documentation](self) describes, with
/// the worker on the tty `tty`, and returns the worker's status, or [`SESSION_STATUS`] if a child
/// cannot start or the worker's status cannot be collected.
///
/// As PID 1, it leaves the unrelated child to the end of the VM. Elsewhere, as in tests, it then
/// kills the unrelated child and collects its status.
pub fn supervise(tty: &Path) -> u8 {
    let program = match std::env::current_exe() {
        Ok(program) => program,
        Err(error) => {
            eprintln!("runtime-adapter-guest: cannot find its own executable: {error}");
            return SESSION_STATUS;
        }
    };
    let sibling = match start(Command::new(&program).arg(crate::GUEST_IDLE_COMMAND)) {
        Ok(sibling) => sibling,
        Err(error) => {
            eprintln!("runtime-adapter-guest: cannot start PID 1's unrelated child: {error}");
            return SESSION_STATUS;
        }
    };
    let worker = start(
        Command::new(&program)
            .arg(crate::GUEST_WORKER_COMMAND)
            .arg(tty)
            .arg(sibling.to_string()),
    );
    let status = match worker {
        Ok(worker) => collect(worker),
        Err(error) => {
            eprintln!("runtime-adapter-guest: cannot start the worker: {error}");
            SESSION_STATUS
        }
    };
    if std::process::id() != 1 {
        // A child keeps its process ID until its status is collected, so the signal reaches the
        // unrelated child unless `collect` collected its status already.
        let sibling = pid(sibling);
        if wait::waitpid(sibling, Some(WaitPidFlag::WNOHANG)) == Ok(WaitStatus::StillAlive) {
            let _ = signal::kill(sibling, Signal::SIGKILL);
            let _ = wait::waitpid(sibling, None);
        }
    }
    status
}

/// Starts `command` with no standard input, and returns its process ID, whose status the caller
/// collects.
fn start(command: &mut Command) -> std::io::Result<u32> {
    // PID 1 collects the status of every child through `wait`, rather than through the handle.
    #[allow(clippy::zombie_processes)]
    let child = command.stdin(Stdio::null()).spawn()?;
    Ok(child.id())
}

/// Collects the status of every child until the child `worker` ends, and returns the worker's
/// status: its exit status, or 128 plus the signal that ended it, as a shell reports it.
fn collect(worker: u32) -> u8 {
    let worker = pid(worker);
    loop {
        match wait::wait() {
            Ok(WaitStatus::Exited(child, code)) if child == worker => {
                return u8::try_from(code).unwrap_or(SESSION_STATUS);
            }
            Ok(WaitStatus::Signaled(child, signal, _)) if child == worker => {
                return u8::try_from(128 + signal as i32).unwrap_or(SESSION_STATUS);
            }
            Ok(_) | Err(Errno::EINTR) => {}
            Err(error) => {
                eprintln!("runtime-adapter-guest: cannot collect the worker's status: {error}");
                return SESSION_STATUS;
            }
        }
    }
}

/// Returns the process ID `id` as `nix` takes it.
fn pid(id: u32) -> Pid {
    // Linux process IDs are at most 2^22.
    Pid::from_raw(i32::try_from(id).unwrap_or(i32::MAX))
}

/// Runs PID 1's unrelated child, which sleeps until a signal ends it.
pub fn idle() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
