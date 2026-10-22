//! The host program launches a VM of the guest agent through NVX's supervisor, and later processes
//! of it reattach to the VM and stop it, as an orchestrator does after it restarts, on a real
//! hypervisor, through public APIs only.
//!
//! The tests boot VMs, so they are ignored. They read:
//!
//! - `NVX_HYPERVISOR`: the hypervisor, through `nvx::Hypervisor::from_env_or_default`;
//! - `NVX_ARTIFACTS_DIR`: NVX's artifacts, a repository checkout or an extracted release, with
//!   the install metadata from which NVX gives their runtime identity;
//! - `RUNTIME_ADAPTER_GUEST`: the guest agent, a static `x86_64-unknown-linux-musl` build of
//!   `runtime-adapter-guest`.
//!
//! ```text
//! cargo test --locked --features host -- --ignored
//! ```
#![cfg(feature = "host")]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nvx::Hypervisor;
use nvx::host::process::Process;
use nvx::host::store::{RuntimeRecord, SandboxStore};
use nvx::host::supervisor::{self, Reattached, StopOutcome};

/// The variable that names the guest agent.
const GUEST_AGENT: &str = "RUNTIME_ADAPTER_GUEST";
/// The longest that a command of the host program may take.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);
/// How much of the end of the VMM's log a failure shows.
const LOG_TAIL: usize = 8192;

/// A sandbox of a test: a directory of its own, which holds the sandbox's store and the output of
/// each command of the host program that the test runs.
///
/// Dropping it ends a VM that a failed test left running, through its verified identity, and
/// removes the directory once no VM of the sandbox runs. Should that remain uncertain, it keeps
/// the directory, whose store a later reattach needs to end the VM, and prints its path.
struct Sandbox {
    /// The test's directory.
    root: PathBuf,
    /// The sandbox's store, which the launch creates.
    store: PathBuf,
    /// The number of commands that the test ran.
    commands: usize,
}

impl Sandbox {
    /// Creates the directory of the test `name`, in the system's temporary directory, so that the
    /// path of a Linux control socket in it stays short. A directory that an earlier test process
    /// kept stays as it is.
    fn new(name: &str) -> Self {
        let pid = std::process::id();
        let root = (0..)
            .map(|attempt| env::temp_dir().join(format!("runtime-adapter-{name}-{pid}-{attempt}")))
            .find(|root| match fs::create_dir(root) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => panic!("cannot create {}: {error}", root.display()),
            })
            .expect("a directory name is free");
        Self {
            store: root.join("store"),
            root,
            commands: 0,
        }
    }

    /// Launches the VM, and returns what the launch printed.
    fn launch(&mut self) -> BTreeMap<String, String> {
        let hypervisor = Hypervisor::from_env_or_default().expect("NVX_HYPERVISOR is valid");
        let guest_agent = env::var_os(GUEST_AGENT).unwrap_or_else(|| {
            panic!(
                "{GUEST_AGENT} must name a static x86_64-unknown-linux-musl runtime-adapter-guest"
            )
        });
        let options = [
            OsStr::new("--guest-agent"),
            &guest_agent,
            OsStr::new("--hypervisor"),
            OsStr::new(hypervisor.as_str()),
        ];
        let launched = self.run("launch", &options, 0);
        let record = self.record().expect("the launch recorded its VM");
        assert_eq!(launched["pid"], record.process().pid.to_string());
        launched
    }

    /// Runs the host program's `command` on the sandbox's store with `options`, checks that it
    /// exits with `status`, and returns the `KEY=VALUE` lines that it printed.
    fn run(&mut self, command: &str, options: &[&OsStr], status: i32) -> BTreeMap<String, String> {
        self.commands += 1;
        let output = self.root.join(format!("{}-{command}", self.commands));
        let (stdout, stderr) = (output.with_extension("out"), output.with_extension("err"));
        // Files, rather than pipes, take the output, so that nothing waits for a VMM that might
        // hold them.
        let mut child = Command::new(env!("CARGO_BIN_EXE_runtime-adapter-host"))
            .arg(command)
            .arg(&self.store)
            .args(options)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let exit = loop {
            if let Some(exit) = child.try_wait().unwrap() {
                break exit;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{command} did not end in time{}", self.diagnostics(&output));
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(
            exit.code(),
            Some(status),
            "{command} {options:?} ended with {exit}{}",
            self.diagnostics(&output)
        );
        let printed = fs::read_to_string(&stdout).unwrap();
        let mut lines = BTreeMap::new();
        for line in printed.lines() {
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{command} printed {line:?}"));
            let earlier = lines.insert(key.to_owned(), value.to_owned());
            assert!(earlier.is_none(), "{command} printed {key} twice");
        }
        lines
    }

    /// Returns what the command whose output files start with `output` printed, and the end of the
    /// VMM's log.
    fn diagnostics(&self, output: &std::path::Path) -> String {
        let read = |path: PathBuf| {
            let bytes = fs::read(path).unwrap_or_default();
            let tail = bytes.len().saturating_sub(LOG_TAIL);
            String::from_utf8_lossy(&bytes[tail..]).into_owned()
        };
        format!(
            "\nstdout:\n{}\nstderr:\n{}\nthe end of the VMM's log:\n{}",
            read(output.with_extension("out")),
            read(output.with_extension("err")),
            read(self.store.join(nvx::host::store::LOG_NAME)),
        )
    }

    /// Returns the sandbox's runtime record, if it has one.
    fn record(&self) -> Option<RuntimeRecord> {
        SandboxStore::open(&self.store).unwrap().runtime().unwrap()
    }

    /// Returns the VMM of the sandbox's runtime record, if the record names one that runs.
    fn vmm(&self) -> Option<Process> {
        Process::open(self.record()?.process()).unwrap()
    }

    /// Ends the VM that the sandbox's store records, whatever its runtime identity: reattach ends
    /// an interrupted launch, and holds a VM that runs, which the stop then terminates through its
    /// verified identity. Fails with the reason why a VM of the sandbox might still run.
    fn end_vm(&self) -> Result<(), String> {
        if !self.store.exists() {
            return Ok(());
        }
        let failed = |error: nvx::Error| describe(&error);
        let store = SandboxStore::open(&self.store).map_err(failed)?;
        let recorded = (
            store.runtime().map_err(failed)?,
            store.journal().map_err(failed)?,
        );
        let identity = match recorded {
            (Some(record), _) => record.runtime().clone(),
            (None, Some(journal)) => journal.runtime().clone(),
            (None, None) => return Ok(()),
        };
        let mut locked = store
            .lock(Some(Instant::now() + Duration::from_secs(10)))
            .map_err(failed)?;
        let vmm = match supervisor::reattach(&mut locked, &identity).map_err(failed)? {
            Reattached::Live(vmm) | Reattached::Mismatched { vmm, .. } => vmm,
            Reattached::Exited { .. } => return Ok(()),
            Reattached::Indeterminate(reason) => return Err(reason),
        };
        let forced = Some(Duration::from_secs(10));
        let stopped = vmm
            .stop(&mut locked, Instant::now(), forced, |_, _| {
                Ok::<(), Infallible>(())
            })
            .map_err(failed)?;
        match stopped.outcome {
            StopOutcome::Graceful | StopOutcome::Forced => Ok(()),
            StopOutcome::TimedOut => Err(format!(
                "VMM process {} did not exit after it was terminated",
                vmm.record().process().pid
            )),
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        match self.end_vm() {
            Ok(()) => {
                let _ = fs::remove_dir_all(&self.root);
            }
            Err(reason) => eprintln!(
                "kept {} because a VM of its sandbox might still run: {reason}",
                self.root.display()
            ),
        }
    }
}

/// Describes `error`, with its causes.
fn describe(error: &dyn Error) -> String {
    let mut description = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        description = format!("{description}: {cause}");
        source = cause.source();
    }
    description
}

/// Returns the epoch that a command printed.
fn epoch(printed: &BTreeMap<String, String>) -> u64 {
    printed["epoch"].parse().unwrap()
}

/// Checks that a command stopped the VM of `vmm` that `launched` printed, with the guest agent's
/// confirmation, after it attached a session in an epoch after `earlier`'s: the VM exited with
/// a successful outcome, and no runtime record names it.
fn assert_stopped(
    sandbox: &Sandbox,
    stopped: &BTreeMap<String, String>,
    launched: &BTreeMap<String, String>,
    earlier: &BTreeMap<String, String>,
    vmm: &Process,
) {
    assert_eq!(stopped["reattached"], "live");
    assert_eq!(stopped["pid"], launched["pid"]);
    assert_eq!(stopped["instance"], launched["instance"]);
    assert!(epoch(stopped) > epoch(earlier), "{stopped:?} {earlier:?}");
    assert_eq!(stopped["stopped"], "graceful");
    assert_eq!(stopped["outcome"], "success 0");
    assert_eq!(stopped["teardown"], "complete");
    assert!(vmm.has_exited().unwrap());
    assert_eq!(
        sandbox.record(),
        None,
        "the stop cleared the runtime record"
    );
}

#[test]
#[ignore = "boots a VM; see the module documentation for what it needs"]
fn a_restarted_host_program_reattaches_to_the_vm_and_stops_it() {
    let mut sandbox = Sandbox::new("restart");
    // The launching process has exited, and the VM runs on.
    let launched = sandbox.launch();
    let vmm = sandbox
        .vmm()
        .expect("the VM runs after its launcher exited");

    // Another process holds the VM, which is not its child, and attaches a new session, in the
    // session's next epoch.
    let reattached = sandbox.run("reattach", &[], 0);
    assert_eq!(reattached["reattached"], "live");
    assert_eq!(reattached["pid"], launched["pid"]);
    assert_eq!(reattached["instance"], launched["instance"]);
    assert!(epoch(&reattached) > epoch(&launched), "{reattached:?}");
    assert!(!vmm.has_exited().unwrap());

    // A third one stops it.
    let stopped = sandbox.run("stop", &[], 0);
    assert_stopped(&sandbox, &stopped, &launched, &reattached, &vmm);
}

#[test]
#[ignore = "boots a VM; see the module documentation for what it needs"]
fn a_host_program_of_another_runtime_finds_the_vm_mismatched_and_signals_nothing() {
    let mut sandbox = Sandbox::new("identity");
    let launched = sandbox.launch();
    let record = sandbox.record();
    let vmm = sandbox
        .vmm()
        .expect("the VM runs after its launcher exited");

    // A host program that ships another build of the guest agent runs another runtime.
    let options = [OsStr::new("--guest-build"), OsStr::new("another-build")];
    let mismatched = sandbox.run("reattach", &options, 3);
    assert_eq!(mismatched["reattached"], "mismatched");
    assert_eq!(mismatched["differences"], "initramfs");
    assert_eq!(mismatched["pid"], launched["pid"]);
    assert!(!mismatched.contains_key("epoch"), "{mismatched:?}");

    // It signaled nothing: the VM runs on, under the same runtime record, and its guest agent
    // serves the host program of the right runtime, which stops it.
    assert!(!vmm.has_exited().unwrap());
    assert_eq!(sandbox.record(), record);
    let stopped = sandbox.run("stop", &[], 0);
    assert_stopped(&sandbox, &stopped, &launched, &launched, &vmm);
}
