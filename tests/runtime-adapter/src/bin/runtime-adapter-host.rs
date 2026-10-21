//! The runtime adapter's host program.
//!
//! - `runtime-adapter-host` reports the contract that it was built against and whether `nvx`
//!   supports this host.
//! - `runtime-adapter-host launch STORE --guest-agent PATH [--hypervisor NAME]` launches a VM in
//!   the sandbox store STORE, which it creates if needed, through NVX's supervisor, with the guest
//!   agent PATH, a static `x86_64-unknown-linux-musl` build of `runtime-adapter-guest`, in place of
//!   NVX's managed agent; see `runtime_adapter::initramfs`. It attaches to the VM's control
//!   session, exchanges a `Ping` and the longest `Echo` with the guest agent, commits the launch,
//!   and exits, leaving the VM running. The VM runs on the hypervisor NAME, `kvm`, `mshv`, or
//!   `whp`, or else on the one that `nvx::Hypervisor::from_env_or_default` selects.
//! - `runtime-adapter-host reattach STORE` reattaches to the VM of STORE, which an earlier process
//!   launched and which it holds although it is not its child, attaches a new session to it, in
//!   the session's next epoch, and exchanges a `Ping`, leaving the VM running.
//! - `runtime-adapter-host stop STORE` reattaches and attaches as `reattach` does, then stops the
//!   VM: it asks the guest agent to stop, waits for the VM to exit, and checks the VM's outcome
//!   report. A VM whose guest agent does not confirm the stop is terminated.
//!
//! Each command takes NVX's artifacts from the directory that `NVX_ARTIFACTS_DIR` names, a
//! repository checkout or an extracted release, and the VM's runtime identity from their build
//! provenance, with the guest agent's build that `--guest-build BUILD` names, this crate's version
//! by default; see `runtime_adapter::runtime`. Reattach finds a VM that another runtime identity
//! launched mismatched, and then signals nothing: the VM keeps running.
//!
//! The commands print what they find as `KEY=VALUE` lines:
//!
//! - `reattached`: what reattach found: `live`, `mismatched`, `exited`, or `indeterminate`;
//! - `differences`: the parts of the runtime identity in which a mismatched VM differs, separated
//!   by commas;
//! - `pid`: the VMM's process ID;
//! - `instance` and `epoch`: the broker instance, in hexadecimal, and the epoch of the session
//!   that the command attached to;
//! - `stopped`: how the stop ended: `graceful`, `forced`, or `timed-out`;
//! - `outcome`: the category and status code of the VM's outcome report, such as `success 0`;
//! - `teardown`: whether the VM's teardown completed: `complete` or `incomplete`.
//!
//! They exit with 0 once they did what they were asked, with 3 when reattach finds the VM
//! mismatched, and with 1, after a diagnostic on standard error, when they fail. Anything else is
//! a usage error, with status 2.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use nvx::Hypervisor;
use nvx::host::artifacts::Artifacts;
use nvx::host::instance::generate_capability;
use nvx::host::launch::LaunchSpec;
use nvx::host::report;
use nvx::host::session;
use nvx::host::store::{IdentityPart, SandboxStore};
use nvx::host::supervisor::{self, Reattached, StopOutcome, Vmm, VmmCommand};
use nvx::protocol::CAPABILITY_LEN;
use runtime_adapter::frame::MAX_BODY;
use runtime_adapter::host::Client;
use runtime_adapter::initramfs;
use runtime_adapter::runtime::{GUEST_BUILD, Runtime};

/// How long a command waits for the sandbox's lock.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a launch waits for the VM to boot and its guest agent to answer.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long reattach and stop wait to attach a session and for the guest agent's answer.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a stop waits for the guest agent's confirmation and for the VM to exit.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a stop waits for a VM that it terminated to exit.
const FORCED_TIMEOUT: Duration = Duration::from_secs(10);
/// The name of the initramfs that boots the guest agent, which the launch writes into the
/// sandbox's store.
const INITRAMFS_NAME: &str = "runtime-adapter.cpio.gz";
/// The exit status of a command that finds the VM mismatched.
const MISMATCHED: u8 = 3;
/// The command lines that the program accepts.
const USAGE: &str = concat!(
    "usage: runtime-adapter-host\n",
    "       runtime-adapter-host launch STORE --guest-agent PATH [--hypervisor NAME]",
    " [--guest-build BUILD]\n",
    "       runtime-adapter-host (reattach | stop) STORE [--guest-build BUILD]",
);

/// What the program was asked to do.
enum Command {
    /// Report the contract that the program was built against.
    Report,
    /// Launch a VM of the guest agent.
    Launch {
        /// The sandbox's store.
        store: PathBuf,
        /// The guest agent's executable.
        guest_agent: PathBuf,
        /// The hypervisor, unless `nvx::Hypervisor::from_env_or_default` selects it.
        hypervisor: Option<Hypervisor>,
        /// The guest agent's build.
        guest_build: String,
    },
    /// Reattach to the VM, and stop it if asked.
    Reattach {
        /// The sandbox's store.
        store: PathBuf,
        /// The guest agent's build.
        guest_build: String,
        /// Whether to stop the VM.
        stop: bool,
    },
}

fn main() -> ExitCode {
    let command = match parse(env::args_os().skip(1).collect()) {
        Ok(command) => command,
        Err(problem) => {
            eprintln!("runtime-adapter-host: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match command {
        Command::Report => {
            println!(
                "runtime-adapter-host: {}; supported host: {}",
                runtime_adapter::contract(),
                nvx::host::platform::SUPPORTED,
            );
            return ExitCode::SUCCESS;
        }
        Command::Launch {
            store,
            guest_agent,
            hypervisor,
            guest_build,
        } => launch(&store, &guest_agent, hypervisor, &guest_build),
        Command::Reattach {
            store,
            guest_build,
            stop,
        } => reattach(&store, &guest_build, stop),
    };
    result.unwrap_or_else(|problem| {
        eprintln!("runtime-adapter-host: {problem}");
        ExitCode::FAILURE
    })
}

/// Parses the program's arguments, or says why they are not a command.
fn parse(arguments: Vec<OsString>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let Some(name) = arguments.next() else {
        return Ok(Command::Report);
    };
    let name = match name.to_str() {
        Some(name @ ("launch" | "reattach" | "stop")) => name.to_owned(),
        _ => return Err(format!("unknown command {name:?}")),
    };
    let store = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| format!("{name} needs a sandbox store"))?,
    );
    let (mut guest_agent, mut hypervisor, mut guest_build) = (None, None, None);
    while let Some(option) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{option:?} needs a value"))?;
        match (name.as_str(), option.to_str()) {
            ("launch", Some("--guest-agent")) if guest_agent.is_none() => {
                guest_agent = Some(PathBuf::from(value));
            }
            ("launch", Some("--hypervisor")) if hypervisor.is_none() => {
                let value = value
                    .to_str()
                    .ok_or_else(|| format!("unknown hypervisor {value:?}"))?;
                hypervisor = Some(value.parse().map_err(|error| describe(&error))?);
            }
            (_, Some("--guest-build")) if guest_build.is_none() => {
                let value = value
                    .into_string()
                    .map_err(|value| format!("the guest build {value:?} is not Unicode"))?;
                guest_build = Some(value);
            }
            _ => return Err(format!("unexpected option {option:?} of {name}")),
        }
    }
    let guest_build = guest_build.unwrap_or_else(|| GUEST_BUILD.to_owned());
    Ok(match name.as_str() {
        "launch" => Command::Launch {
            store,
            guest_agent: guest_agent.ok_or("launch needs --guest-agent")?,
            hypervisor,
            guest_build,
        },
        "reattach" => Command::Reattach {
            store,
            guest_build,
            stop: false,
        },
        _ => Command::Reattach {
            store,
            guest_build,
            stop: true,
        },
    })
}

/// Launches a VM of the guest agent `guest_agent` in the sandbox store `store`, on `hypervisor`
/// or else the one that `nvx::Hypervisor::from_env_or_default` selects, with the guest agent's
/// build `guest_build`.
fn launch(
    store: &Path,
    guest_agent: &Path,
    hypervisor: Option<Hypervisor>,
    guest_build: &str,
) -> Result<ExitCode, String> {
    let hypervisor = match hypervisor {
        Some(hypervisor) => hypervisor,
        None => Hypervisor::from_env_or_default().map_err(|error| describe(&error))?,
    };
    let runtime = runtime(guest_build)?;
    runtime
        .artifacts
        .probe()
        .map_err(|error| describe(&error))?;
    let store = SandboxStore::create(store).map_err(|error| describe(&error))?;
    let mut locked = store
        .lock(Some(Instant::now() + LOCK_TIMEOUT))
        .map_err(|error| describe(&error))?;
    let capability = generate_capability().map_err(|error| describe(&error))?;
    let initramfs = store.dir().join(INITRAMFS_NAME);
    let spec = LaunchSpec::new(
        Artifacts::new(
            &runtime.artifacts.openvmm,
            &runtime.artifacts.kernel,
            &initramfs,
        ),
        hypervisor,
    );
    let deadline = Instant::now() + START_TIMEOUT;
    let starting = supervisor::launch(&mut locked, &runtime.identity, &capability, |endpoint| {
        // The launch has checked that no VM of the sandbox runs, which could still read the
        // initramfs of an earlier launch.
        initramfs::write(&runtime.artifacts.initrd, guest_agent, &initramfs).map_err(|error| {
            nvx::Error::io("cannot write the initramfs of the guest agent").with_source(error)
        })?;
        let arguments = spec.openvmm_arguments(endpoint, &store.outcome_path())?;
        Ok(VmmCommand::new(&spec.openvmm, arguments, store.dir()))
    })
    .map_err(|error| describe(&error))?;
    let process = starting.process().reference().clone();
    println!("pid={}", process.pid);
    // A launch that fails from here on ends its VM, once `starting` drops.
    let failed = |problem: String| {
        format!(
            "{problem}; see the VMM's log {}",
            store.log_path().display()
        )
    };
    let transport = session::connect(
        starting.endpoint(),
        process.pid,
        process.start_time,
        deadline,
    )
    .map_err(|error| failed(format!("cannot connect to the VM: {}", describe(&error))))?;
    let mut client = attach(transport, &capability, deadline).map_err(failed)?;
    client
        .ping(deadline)
        .and_then(|()| client.echo(&echo_body(), deadline))
        .map_err(|error| {
            failed(format!(
                "the guest agent did not answer: {}",
                describe(&error)
            ))
        })?;
    starting.commit().map_err(|error| describe(&error))?;
    Ok(ExitCode::SUCCESS)
}

/// Returns the body of the launch's `Echo`: the longest that the framing allows, of every byte
/// value, which spans several of the session's records, each way.
fn echo_body() -> Vec<u8> {
    (0..=u8::MAX).cycle().take(MAX_BODY).collect()
}

/// Reattaches to the VM of the sandbox store `store`, with the guest agent's build `guest_build`,
/// attaches a session to it, and exchanges a `Ping`, then stops the VM if `stop` asks.
fn reattach(store: &Path, guest_build: &str, stop: bool) -> Result<ExitCode, String> {
    let runtime = runtime(guest_build)?;
    let store = SandboxStore::open(store).map_err(|error| describe(&error))?;
    let mut locked = store
        .lock(Some(Instant::now() + LOCK_TIMEOUT))
        .map_err(|error| describe(&error))?;
    let reattached =
        supervisor::reattach(&mut locked, &runtime.identity).map_err(|error| describe(&error))?;
    let vmm = match reattached {
        Reattached::Live(vmm) => {
            println!("reattached=live");
            vmm
        }
        Reattached::Mismatched { vmm, differences } => {
            println!("reattached=mismatched");
            println!("differences={}", names(&differences));
            println!("pid={}", vmm.record().process().pid);
            return Ok(ExitCode::from(MISMATCHED));
        }
        Reattached::Exited { .. } => {
            println!("reattached=exited");
            return Err("no VM of the sandbox runs".to_owned());
        }
        Reattached::Indeterminate(reason) => {
            println!("reattached=indeterminate");
            return Err(format!(
                "whether the VM of the sandbox runs cannot be determined: {reason}"
            ));
        }
    };
    println!("pid={}", vmm.record().process().pid);
    let deadline = Instant::now() + SESSION_TIMEOUT;
    let attached = store
        .read_capability()
        .map_err(|error| describe(&error))
        .and_then(|capability| connect(&vmm, &capability, deadline))
        .and_then(|mut client| {
            client
                .ping(deadline)
                .map_err(|error| format!("the guest agent did not answer: {}", describe(&error)))?;
            Ok(client)
        });
    if !stop {
        return attached.map(|_| ExitCode::SUCCESS);
    }
    // A VM whose guest agent cannot confirm the stop is terminated.
    let stopped = vmm
        .stop(
            &mut locked,
            Instant::now() + STOP_TIMEOUT,
            Some(FORCED_TIMEOUT),
            |_, deadline| {
                attached?.stop(deadline).map_err(|error| {
                    format!(
                        "the guest agent did not confirm the stop: {}",
                        describe(&error)
                    )
                })
            },
        )
        .map_err(|error| describe(&error))?;
    println!(
        "stopped={}",
        match stopped.outcome {
            StopOutcome::Graceful => "graceful",
            StopOutcome::Forced => "forced",
            StopOutcome::TimedOut => "timed-out",
        }
    );
    if let Some(problem) = stopped.graceful_error {
        return Err(problem);
    }
    if stopped.outcome != StopOutcome::Graceful {
        return Err("the VM did not exit once the guest agent confirmed the stop".to_owned());
    }
    let outcome = report::read(&store.outcome_path()).ok_or_else(|| {
        format!(
            "the VM left no outcome report {}",
            store.outcome_path().display()
        )
    })?;
    let category = outcome.category.as_deref().unwrap_or("none");
    let status = outcome
        .status_code
        .map_or("none".to_owned(), |code| code.to_string());
    println!("outcome={category} {status}");
    println!(
        "teardown={}",
        match outcome.teardown_complete {
            Some(true) => "complete",
            Some(false) | None => "incomplete",
        }
    );
    if (category, outcome.status_code, outcome.teardown_complete)
        != ("success", Some(0), Some(true))
    {
        return Err("the VM's outcome is not a success with a complete teardown".to_owned());
    }
    Ok(ExitCode::SUCCESS)
}

/// Returns the runtime of NVX's artifacts in the directory that `NVX_ARTIFACTS_DIR` names, with
/// the guest agent's build `guest_build`.
fn runtime(guest_build: &str) -> Result<Runtime, String> {
    let directory = env::var_os(Artifacts::ENV_DIR)
        .filter(|directory| !directory.is_empty())
        .ok_or_else(|| {
            format!(
                "set {} to NVX's artifacts: a repository checkout or an extracted release",
                Artifacts::ENV_DIR
            )
        })?;
    Runtime::from_dir(directory, guest_build).map_err(|error| describe(&error))
}

/// Connects to the control endpoint of the VM `vmm`, and attaches a session with `capability`,
/// by `deadline`.
fn connect(
    vmm: &Vmm,
    capability: &[u8; CAPABILITY_LEN],
    deadline: Instant,
) -> Result<Client, String> {
    let process = vmm.record().process();
    let transport = session::connect(vmm.endpoint(), process.pid, process.start_time, deadline)
        .map_err(|error| format!("cannot connect to the VM: {}", describe(&error)))?;
    attach(transport, capability, deadline)
}

/// Attaches a session over `transport` with `capability` by `deadline`, and prints its identity.
fn attach(
    transport: Box<dyn nvx::host::platform::Transport>,
    capability: &[u8; CAPABILITY_LEN],
    deadline: Instant,
) -> Result<Client, String> {
    let client = Client::attach(transport, capability, deadline)
        .map_err(|error| format!("cannot attach to the VM: {}", describe(&error)))?;
    let identity = client.identity();
    let instance: String = identity
        .instance_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("instance={instance}");
    println!("epoch={}", identity.epoch);
    Ok(client)
}

/// Returns the names of `parts`, separated by commas.
fn names(parts: &[IdentityPart]) -> String {
    parts
        .iter()
        .map(|part| part.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// Describes `error` with the causes that its description does not end with already.
fn describe(error: &dyn Error) -> String {
    let mut description = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_description = cause.to_string();
        if !description.ends_with(&cause_description) {
            description = format!("{description}: {cause_description}");
        }
        source = cause.source();
    }
    description
}
