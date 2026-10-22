//! The lifecycle of a managed sandbox, a port of the former
//! `scripts/nvx_tools/sandbox_lifecycle.py`, which it replaced (microsoft/nvx#359), on the
//! [`store`](crate::host::store), [`supervisor`], and [`session`](crate::host::session) that
//! every host of a sandbox shares.
//!
//! A sandbox lives in its state directory, which is the directory of its store:
//!
//! ```text
//! <state>/
//!   config.json          the launch that provision records, in formats 1 to 6, with the binding
//!                        of its distro layer
//!   sandbox.lock         the store's lock, which serializes the lifecycle transitions
//!   launch.json          the store's journal of a start in progress, or of an interrupted one
//!   runtime.json         the store's runtime record of the running VM, in its format 4
//!   control.capability   the 32-byte capability of the running OpenVMM
//!   control.sock         the control endpoint of the running OpenVMM, on POSIX
//!   openvmm.log          OpenVMM's output, which each start replaces
//!   outcome.json         OpenVMM's outcome report of the latest start
//! ```
//!
//! The CLI keeps its own record, the configuration, in its own formats; the store keeps the
//! runtime records, and reads no other format than its own: a sandbox that an earlier build
//! started must be stopped with that build.
//!
//! [`provision`], [`start`], [`stop`], and [`deprovision`] hold the [`LifecycleLock`] for their
//! whole transition, and [`exec_workload`] only while it finds the running VM, so a long workload
//! cannot delay a stop. `config.json` also records the binding of the distro layer that
//! `provision` verified, which [`start`] checks from metadata alone: it refuses to start a sandbox
//! that `nvx.py` provisioned, which has no binding.
//!
//! Every transition but provision finds the sandbox's VM with [`supervisor::reattach`], as an
//! orchestrator does after it restarts: it ends a start that was interrupted, holds a recorded
//! OpenVMM that still runs through its verified identity, and clears the runtime record of one
//! that exited without a stop, which the first transition to find it reports, or which a start
//! replaces. A VM that another runtime identity than the artifacts' started, as after the
//! artifacts were replaced, is reported, and never driven. [`start`] launches OpenVMM with
//! [`supervisor::launch`], under the runtime identity that the install metadata of the artifacts
//! names, and [`stop`] asks the guest to shut down, waits for OpenVMM to exit, and reports a VM
//! that does not, without ending it otherwise.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};

use super::lock::{
    LifecycleLock, OsErrorClass, directory_not_empty, directory_status, entries, lingers,
    os_error_class,
};
use super::state::{
    CONFIG_FORMATS, RecordedDistro, config_int, config_text, deserialize_binding,
    deserialize_launch, hex, member, random_bytes, read_json, serialize_launch, temporary_path,
    write_json,
};
use super::{Artifacts, error_with_cause};
use crate::ErrorKind;
use crate::host::cli::deadline::{Deadline, RETRY_INTERVAL};
use crate::host::cli::session::{EXIT_CATEGORIES, ExecRequest, ExecResult, Session};
use crate::host::cli::{Exit, Result, check_interrupt};
use crate::host::python::builtins::{Int, repr};
use crate::host::python::dumps::{self, Value, dict};
use crate::host::python::fs::{self, os_error_message};
use crate::host::python::json::{Document, Node};
use crate::host::python::path::PurePath;
use crate::host::python::value::py_str;
use crate::host::sandbox::distro::DISTRO_POLICY_REVISION;
use crate::host::sandbox::{SandboxLaunch, require_file};
use crate::host::store::{
    self, IdentityPart, LOCK_NAME, LockedStore, OUTCOME_NAME, RUNTIME_NAME, Recovery, SandboxStore,
};
use crate::host::supervisor::{self, Launched, Reattached, StopOutcome, Vmm, VmmCommand};
use crate::protocol::{CAPABILITY_LEN, GuestFeatures};

/// The launch configuration, the CLI's own record beside those of the store.
pub(crate) const CONFIG_NAME: &str = "config.json";
/// How often a caller retries a lifecycle lock that another caller holds, and the removal of a
/// state directory that a removed lock file still keeps.
pub(crate) const LOCK_RETRY_INTERVAL: Duration = RETRY_INTERVAL;
/// The version of outcome reports.
pub(crate) const OUTCOME_SCHEMA_VERSION: u64 = 1;

/// The options of a launch, besides the launch itself, that `provision` records.
pub(crate) struct ProvisionConfig<'a> {
    /// `--hypervisor`, resolved.
    pub(crate) hypervisor: &'a str,
    /// `--memory-mib`.
    pub(crate) memory_mib: &'a Int,
    /// `--net`.
    pub(crate) net: Option<&'a str>,
    /// `--network-profile`.
    pub(crate) network_profile: Option<&'a str>,
    /// `--network-egress`.
    pub(crate) network_egress: Option<&'a str>,
    /// `--network-ingress`.
    pub(crate) network_ingress: Option<&'a str>,
    /// The egress allow rules.
    pub(crate) network_egress_allow: &'a [String],
    /// The egress deny rules.
    pub(crate) network_egress_deny: &'a [String],
    /// `--host-loopback`.
    pub(crate) host_loopback: Option<&'a str>,
    /// `--network-proxy`.
    pub(crate) network_proxy: Option<&'a str>,
    /// The `--host-loopback-forward` options.
    pub(crate) host_loopback_forward: &'a [String],
    /// `--cmdline`.
    pub(crate) cmdline: &'a str,
}

/// Returns the error for an `OSError` that an operation on `path` raised.
fn os_error(error: &std::io::Error, path: &PurePath) -> Exit {
    Exit::error(os_error_message(error, Some(path.as_str())))
}

/// Removes `path` unless it is missing, as `Path.unlink(missing_ok=True)` does.
fn unlink_missing_ok(path: &PurePath) -> Result {
    match std::fs::remove_file(path.as_path()) {
        Err(error) if os_error_class(&error) != OsErrorClass::NotFound => {
            Err(os_error(&error, path))
        }
        _ => Ok(()),
    }
}

/// Returns a builder of directories of `mode`, which Windows ignores, as `os.mkdir` does.
fn dir_builder(mode: u32) -> std::fs::DirBuilder {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, mode);
    #[cfg(not(unix))]
    let _ = mode;
    builder
}

/// Creates `path` and its missing parents, as `Path.mkdir(mode, parents=True, exist_ok=True)`
/// does: parents with the default mode, `path` with `mode`, and no error if `path` is a
/// directory already.
fn make_directories(path: &PurePath, mode: u32) -> Result {
    match dir_builder(mode).create(path.as_path()) {
        Ok(()) => Ok(()),
        Err(error) if os_error_class(&error) == OsErrorClass::NotFound => {
            match path.parents().next() {
                Some(parent) if parent != *path => {
                    make_directories(&parent, 0o777)?;
                    make_directories_once(path, mode)
                }
                _ => Err(os_error(&error, path)),
            }
        }
        Err(_) if fs::is_dir(path.as_path()) => Ok(()),
        Err(error) => Err(os_error(&error, path)),
    }
}

/// Creates `path` once its parent exists, as `self.mkdir(mode, parents=False, exist_ok=True)`
/// does.
fn make_directories_once(path: &PurePath, mode: u32) -> Result {
    match dir_builder(mode).create(path.as_path()) {
        Ok(()) => Ok(()),
        Err(_) if fs::is_dir(path.as_path()) => Ok(()),
        Err(error) => Err(os_error(&error, path)),
    }
}

/// Creates the state directory at `path`, as provision does. An existing path keeps the errors of
/// `Path.mkdir(exist_ok=True)`, which an existing directory does not raise, and stays as it is: the
/// store then refuses a directory that is not private to the current user. A new directory is
/// created as the store creates it, private to the current user, below parents that are created
/// as needed.
pub(crate) fn create_state_directory(path: &PurePath) -> Result {
    if fs::lexists(path.as_path()) {
        return make_directories(path, 0o700);
    }
    if let Some(parent) = path.parents().next().filter(|parent| parent != path) {
        make_directories(&parent, 0o777)?;
    }
    SandboxStore::create(path.as_path())
        .map(drop)
        .map_err(error_with_cause)
}

/// Resolves the state directory at `path`, and creates it with `create`, as
/// `_prepare_state_directory` does. It must be a directory and not a symbolic link.
pub(crate) fn prepare_state_directory(path: &str, create: bool) -> Result<PurePath> {
    let resolved = fs::resolve(&PurePath::native(path)).map_err(Exit::from_os_error)?;
    if create {
        create_state_directory(&resolved)?;
    }
    if fs::is_symlink(resolved.as_path()) || !fs::is_dir(resolved.as_path()) {
        return Err(Exit::error(format!(
            "sandbox state path is not a plain directory: {resolved}"
        )));
    }
    Ok(resolved)
}

/// Returns the destination of an outcome report, as `_outcome_destination` does: in a plain
/// directory, with a file name, and new.
fn outcome_destination(path: &str) -> Result<PurePath> {
    let path = PurePath::native(path);
    let candidate = if path.is_absolute() {
        path
    } else {
        fs::cwd().map_err(Exit::from_os_error)?.join(path.as_str())
    };
    let parent = candidate
        .parents()
        .next()
        .unwrap_or_else(|| candidate.clone());
    if fs::is_symlink(parent.as_path()) || !fs::is_dir(parent.as_path()) {
        return Err(Exit::error(format!(
            "outcome report parent is not a plain directory: {parent}"
        )));
    }
    if candidate.name().is_empty() {
        return Err(Exit::error("outcome report path has no filename"));
    }
    let resolved = fs::resolve(&parent)
        .map_err(Exit::from_os_error)?
        .join(candidate.name());
    if fs::lexists(resolved.as_path()) {
        return Err(Exit::error(format!(
            "outcome report already exists: {resolved}"
        )));
    }
    Ok(resolved)
}

/// Checks the destination of an outcome report before a workload runs, as
/// `validate_outcome_destination` does.
pub(crate) fn validate_outcome_destination(path: &str) -> Result {
    outcome_destination(path).map(drop)
}

/// Writes `value` to a new file at `path`, as `_write_new_json` does: through a temporary file of
/// mode 0600, synced, then linked to its name, which must not exist, with `\n` line ends on every
/// host.
fn write_new_json(path: &str, value: &Value) -> Result {
    let resolved = outcome_destination(path)?;
    let temporary = temporary_path(&resolved)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = match options.open(temporary.as_path()) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Exit::error(
                "failed to reserve an outcome report staging file",
            ));
        }
        Err(error) => return Err(os_error(&error, &temporary)),
    };
    let written = (|| -> Result {
        let text = format!("{}\n", dumps::dumps(value));
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(Exit::from_os_error)?;
        match std::fs::hard_link(temporary.as_path(), resolved.as_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(Exit::error(
                format!("outcome report already exists: {resolved}"),
            )),
            Err(_) => Err(Exit::error(format!(
                "failed to publish outcome report: {resolved}"
            ))),
        }
    })();
    drop(file);
    let _ = std::fs::remove_file(temporary.as_path());
    written
}

/// The sections of an OpenVMM outcome report that a reader requires.
const OUTCOME_SECTIONS: [&str; 3] = ["outcome", "network_policy", "teardown"];

/// Reads an OpenVMM outcome report, as `_read_openvmm_outcome` does: of schema version 1, with
/// `outcome`, `network_policy`, and `teardown` objects.
fn read_openvmm_outcome(path: &PurePath) -> Result<Document> {
    let document = read_json(
        path,
        "OpenVMM outcome report",
        "schema_version",
        &[OUTCOME_SCHEMA_VERSION],
    )?;
    for name in OUTCOME_SECTIONS {
        let section = member(&document, document.root(), name);
        if !section.is_some_and(|section| matches!(document.node(section), Node::Object(_))) {
            return Err(Exit::error(format!(
                "OpenVMM outcome report has an invalid {name} section: {path}"
            )));
        }
    }
    Ok(document)
}

/// Writes the outcome report of a managed workload, as `write_exec_outcome` does: its category
/// and status, with a random operation ID, and nothing of its output.
pub(crate) fn write_exec_outcome(path: &str, result: &ExecResult) -> Result {
    if !EXIT_CATEGORIES.contains(&result.category) {
        return Err(Exit::error(
            "managed workload returned an unsupported outcome category",
        ));
    }
    let operation_id = hex(&random_bytes::<16>()?);
    write_new_json(
        path,
        &dict([
            ("schema_version", Value::from(OUTCOME_SCHEMA_VERSION)),
            ("operation_id", Value::from(operation_id)),
            (
                "outcome",
                dict([
                    ("operation", Value::from("exec")),
                    ("category", Value::from(result.category)),
                    ("status_code", Value::from(i64::from(result.returncode))),
                ]),
            ),
        ]),
    )
}

/// Records a launch and its distro layer, at the path at which it was verified, with the layer's
/// binding, in a new state directory, as `provision` does.
pub(crate) fn provision(
    state_path: &str,
    launch: &SandboxLaunch,
    distro: &RecordedDistro,
    config: &ProvisionConfig<'_>,
    timeout: f64,
) -> Result {
    let state_dir = prepare_state_directory(state_path, true)?;
    let config_path = state_dir.join(CONFIG_NAME);
    let runtime_path = state_dir.join(RUNTIME_NAME);
    let _lock = LifecycleLock::acquire(&state_dir, timeout, true)?;
    if fs::exists(config_path.as_path()) || fs::exists(runtime_path.as_path()) {
        return Err(Exit::error("sandbox is already provisioned"));
    }
    launch.validated()?;
    write_json(&config_path, &serialize_launch(launch, distro, config)?)
}

/// What a transition finds of the sandbox's VM, through [`supervisor::reattach`].
enum Found {
    /// No VM is recorded, or a start that was interrupted is over.
    Nothing,
    /// The recorded OpenVMM exited without a stop, and its runtime record is cleared.
    Exited,
    /// The VM runs under the runtime identity of the artifacts.
    Live(Vmm),
    /// The VM runs under another runtime identity, which differs in these parts.
    Mismatched(Vmm, Vec<IdentityPart>),
}

/// Finds the sandbox's VM in the locked store, as an orchestrator does after it restarts within
/// the same host boot: with [`supervisor::reattach`], under the runtime identity of `artifacts`.
///
/// Only a recorded launch needs that identity, so a sandbox that never started, or that stopped,
/// needs no install metadata. Fails for a record that the store does not read, such as one of an
/// earlier format, and when whether the VM runs cannot be determined.
fn find_vm(locked: &mut LockedStore, artifacts: &Artifacts<'_>) -> Result<Found> {
    if locked.journal().map_err(error_with_cause)?.is_none()
        && locked.runtime().map_err(error_with_cause)?.is_none()
    {
        return Ok(Found::Nothing);
    }
    let runtime = artifacts.runtime_identity()?;
    Ok(
        match supervisor::reattach(locked, &runtime).map_err(error_with_cause)? {
            Reattached::Live(vmm) => Found::Live(vmm),
            Reattached::Mismatched { vmm, differences } => Found::Mismatched(vmm, differences),
            Reattached::Exited {
                record: Some(_), ..
            } => Found::Exited,
            Reattached::Exited { record: None, .. } => Found::Nothing,
            Reattached::Indeterminate(reason) => {
                return Err(Exit::error(format!(
                    "cannot determine whether the OpenVMM process of the sandbox runs: {reason}"
                )));
            }
        },
    )
}

/// Returns the error of a VM that another runtime identity than the artifacts' started, which
/// differs in `differences`: the CLI does not drive it, since it may speak other contracts.
fn mismatched(vmm: &Vmm, differences: &[IdentityPart]) -> Exit {
    let parts: Vec<&str> = differences.iter().map(|part| part.name()).collect();
    Exit::error(format!(
        "sandbox runs under another runtime identity than these artifacts, which differ in {}: \
         stop it with the artifacts that started it (OpenVMM process {})",
        parts.join(", "),
        vmm.record().process().pid
    ))
}

/// The running VM of a sandbox, and the capability with which its control session attaches.
struct Running {
    /// The VM.
    vmm: Vmm,
    /// Its control capability.
    capability: [u8; CAPABILITY_LEN],
}

/// Returns the running VM of the sandbox in the locked store, as exec and stop require it.
fn running_vm(locked: &mut LockedStore, artifacts: &Artifacts<'_>) -> Result<Running> {
    let vmm = match find_vm(locked, artifacts)? {
        Found::Live(vmm) => vmm,
        Found::Nothing => return Err(Exit::error("sandbox is not running")),
        Found::Exited => {
            return Err(Exit::error(
                "sandbox runtime state is stale because the OpenVMM process is not running",
            ));
        }
        Found::Mismatched(vmm, differences) => return Err(mismatched(&vmm, &differences)),
    };
    let capability = locked.read_capability().map_err(error_with_cause)?;
    Ok(Running { vmm, capability })
}

/// Connects to the control endpoint of `vmm`, and attaches with `capability`.
fn connect(vmm: &Vmm, capability: &[u8; CAPABILITY_LEN], timeout: f64) -> Result<Session> {
    Session::connect(
        vmm.endpoint(),
        vmm.record().process().pid,
        capability,
        timeout,
    )
}

/// Starts a provisioned sandbox, as `start` does.
pub(crate) fn start(state_path: &str, artifacts: &Artifacts<'_>, timeout: f64) -> Result {
    let state_dir = prepare_state_directory(state_path, false)?;
    let mut lock = LifecycleLock::acquire(&state_dir, timeout, false)?;
    start_locked(&state_dir, lock.locked(), artifacts, timeout)
}

/// The control features that the layered sandbox root must provide for the requests of
/// `nvx-rs sandbox`.
pub(crate) const REQUIRED_FEATURES: GuestFeatures = GuestFeatures::LAYERED_SANDBOX;

/// Starts the sandbox of a locked state directory, as `_start` does, through the launch journal
/// of its store.
fn start_locked(
    state_dir: &PurePath,
    locked: &mut LockedStore,
    artifacts: &Artifacts<'_>,
    timeout: f64,
) -> Result {
    let config_path = state_dir.join(CONFIG_NAME);
    require_file(config_path.as_path(), "sandbox configuration")?;
    let config = read_json(
        &config_path,
        "sandbox configuration",
        "format",
        &CONFIG_FORMATS,
    )?;
    match find_vm(locked, artifacts)? {
        Found::Nothing | Found::Exited => {}
        Found::Live(_) => {
            return Err(Exit::error(
                "sandbox is already running or has stale runtime state",
            ));
        }
        Found::Mismatched(vmm, differences) => return Err(mismatched(&vmm, &differences)),
    }
    let outcome_path = state_dir.join(OUTCOME_NAME);
    unlink_missing_ok(&outcome_path)?;
    let launch = deserialize_launch(&config)?;
    // The check reads no content of the layer or its manifest, and never verifies them again.
    // Its file holds the layer until the start ends: on Windows, it keeps anything from modifying
    // or replacing the layer before OpenVMM, whose read-only open shares it, has opened the layer.
    let binding = deserialize_binding(&config)?;
    let _distro = binding
        .check(launch.distro(), DISTRO_POLICY_REVISION)
        .map_err(distro_error)?;
    // The plan takes the format and identity of the distro layer from its binding.
    let plan = launch.bound_plan(&binding)?;
    let [executable, kernel, initrd] = artifacts.require()?;
    let runtime = artifacts.runtime_identity()?;
    let capability = random_bytes::<CAPABILITY_LEN>()?;
    if capability == [0; CAPABILITY_LEN] {
        return Err(Exit::error(
            "the system returned an all-zero control capability",
        ));
    }
    // The control endpoint, which the launch chooses, goes between these arguments.
    let mut head = vec![executable];
    head.extend(plan.openvmm_arguments()?);
    head.extend(
        [
            "--microvm-lifecycle",
            "managed",
            "--single-process",
            "--hypervisor",
        ]
        .map(str::to_owned),
    );
    head.push(config_text(&config, "hypervisor")?);
    head.push("--memory".to_owned());
    head.push(format!("{}M", config_int(&config, "memory_mib")?));
    head.extend(["--kernel".to_owned(), kernel, "--initrd".to_owned(), initrd]);
    head.push("--cmdline".to_owned());
    head.push(plan.kernel_command_line(&config_text(&config, "cmdline")?)?);
    head.extend(["--virtio-console", "none", "--microvm-control-console"].map(str::to_owned));
    let mut tail = vec![
        "--microvm-control-auth-stdin".to_owned(),
        "--microvm-report".to_owned(),
        outcome_path.as_str().to_owned(),
    ];
    extend_recorded_network_arguments(&mut tail, &config)?;
    let directory = std::env::current_dir().map_err(Exit::from_os_error)?;
    let mut command = Vec::new();
    let mut starting = supervisor::launch(locked, &runtime, &capability, |endpoint| {
        command = head;
        command.push(format!("listen={endpoint}"));
        command.extend(tail);
        let arguments = command[1..].iter().map(OsString::from).collect();
        Ok(VmmCommand::new(&command[0], arguments, directory))
    })
    .map_err(error_with_cause)?;
    let pid = starting.process().reference().pid;
    let Err(error) = check_ready(starting.endpoint(), pid, &capability, timeout) else {
        return starting.commit().map(drop).map_err(error_with_cause);
    };
    // OpenVMM closes the control endpoint as it tears the VM down, before it publishes its
    // outcome report and exits, so only a closed endpoint warrants waiting for it.
    let grace = if matches!(error, Exit::EndpointClosed) {
        timeout
    } else {
        0.0
    };
    let status = end_failed_start(starting.child(), grace, &command)?;
    // OpenVMM has exited, so the launch ends: its capability, control socket, and journal go,
    // and its log and outcome report stay.
    let unended = match starting.abandon() {
        Ok(Recovery::Indeterminate(reason)) => Some(reason),
        Ok(_) => None,
        Err(failure) => Some(failure.message().to_owned()),
    };
    let error = match status {
        Some(status) if !matches!(error, Exit::Interrupted) => {
            Exit::error(startup_exit_message(&outcome_path, status)?)
        }
        _ => error,
    };
    if let Some(reason) = unended
        && let Some(message) = error.message()
    {
        return Err(Exit::error(format!(
            "{message}; the launch could not be ended, and remains for recovery: {reason}"
        )));
    }
    Err(error)
}

/// Returns the error of a start whose distro layer fails the check of its binding: a binding that
/// no longer holds needs a new provision, which verifies the layer again.
fn distro_error(error: crate::Error) -> Exit {
    match error.kind() {
        ErrorKind::Io => error.into(),
        _ => Exit::error(format!(
            "{}; deprovision the sandbox and provision it again",
            error.message()
        )),
    }
}

/// Waits until the guest of a VM that starts answers on `endpoint`, which OpenVMM process `pid`
/// serves, and checks that it provides the features of [`REQUIRED_FEATURES`].
fn check_ready(
    endpoint: &str,
    pid: u32,
    capability: &[u8; CAPABILITY_LEN],
    timeout: f64,
) -> Result {
    let mut session = Session::connect(endpoint, pid, capability, timeout)?;
    session.ping(timeout)?;
    let features = session.features(timeout)?;
    let missing = features.missing(REQUIRED_FEATURES);
    if !missing.is_empty() {
        return Err(Exit::error(format!(
            "the guest image lacks control features that layered sandboxes need ({}); use an \
             NVX release or build that includes them",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// Appends the network options that a configuration records, in the order of `_start`.
fn extend_recorded_network_arguments(command: &mut Vec<String>, config: &Document) -> Result {
    let root = config.root();
    let text =
        |id| py_str(config, id).ok_or_else(|| Exit::error("sandbox configuration is malformed"));
    let present =
        |name| member(config, root, name).filter(|&id| !matches!(config.node(id), Node::Null));
    if let Some(net) = present("net") {
        command.push("--net".to_owned());
        command.push(text(net)?);
        command.push("--network-profile".to_owned());
        command.push(match member(config, root, "network_profile") {
            Some(profile) => text(profile)?,
            None => "None".to_owned(),
        });
    }
    for name in ["network_egress", "network_ingress", "host_loopback"] {
        if let Some(value) = present(name) {
            command.push(format!("--{}", name.replace('_', "-")));
            command.push(text(value)?);
        }
    }
    for name in [
        "network_egress_allow",
        "network_egress_deny",
        "host_loopback_forward",
    ] {
        let Some(values) = member(config, root, name) else {
            continue;
        };
        let Node::Array(items) = config.node(values) else {
            return Err(Exit::error("sandbox configuration is malformed"));
        };
        for &item in items {
            command.push(format!("--{}", name.replace('_', "-")));
            command.push(text(item)?);
        }
    }
    if let Some(proxy) = present("network_proxy") {
        command.push("--network-proxy".to_owned());
        command.push(text(proxy)?);
    }
    Ok(())
}

/// Ends the OpenVMM process of a failed start, as `_end_failed_start` does: returns OpenVMM's
/// status if it exits on its own within `grace` seconds, or terminates it and returns `None`.
/// Terminating OpenVMM while it publishes its outcome report would leave the report's staging
/// file in the state directory, which deprovision refuses to remove.
fn end_failed_start(
    launched: &mut Launched,
    grace: f64,
    command: &[String],
) -> Result<Option<i64>> {
    let waited = if grace > 0.0 {
        wait_interruptibly(launched, Deadline::after(grace))
    } else {
        Ok(())
    };
    let status = launched
        .wait_timeout(Duration::ZERO)
        .map_err(Exit::from_os_error)?;
    if status.is_none() {
        launched.terminate().map_err(Exit::from_os_error)?;
        let exited = launched
            .wait_timeout(Duration::from_secs(5))
            .map_err(Exit::from_os_error)?;
        if exited.is_none() {
            launched.kill().map_err(Exit::from_os_error)?;
            let killed = launched
                .wait_timeout(Duration::from_secs(5))
                .map_err(Exit::from_os_error)?;
            if killed.is_none() {
                let arguments: Vec<String> =
                    command.iter().map(|argument| repr(argument)).collect();
                return Err(Exit::error(format!(
                    "Command '[{}]' timed out after 5 seconds",
                    arguments.join(", ")
                )));
            }
        }
    }
    // Ctrl-C during the grace period ends the start as interrupted, after OpenVMM.
    waited?;
    Ok(status)
}

/// Waits until `launched` exits or `deadline` passes, failing if Ctrl-C arrives.
fn wait_interruptibly(launched: &mut Launched, deadline: Deadline) -> Result {
    loop {
        let slice = deadline
            .remaining()
            .map_or(RETRY_INTERVAL, |left| left.min(RETRY_INTERVAL));
        crate::host::cli::check_interrupt()?;
        if launched
            .wait_timeout(slice)
            .map_err(Exit::from_os_error)?
            .is_some()
            || deadline.passed()
        {
            return Ok(());
        }
    }
}

/// Describes how OpenVMM ended a start, preferring its outcome report, which keeps the guest's
/// own status, as `_startup_exit_message` does.
fn startup_exit_message(outcome_path: &PurePath, status: i64) -> Result<String> {
    let report = match read_openvmm_outcome(outcome_path) {
        Ok(report) => Some(report),
        // A `ValueError` of `json.loads` escapes the `except ScriptError`.
        Err(exit)
            if exit
                .message()
                .is_some_and(|message| message.starts_with("Exceeds the limit")) =>
        {
            return Err(exit);
        }
        Err(_) => None,
    };
    if let Some(report) = &report
        && let Some(outcome) = member(report, report.root(), "outcome")
        && let Some(category) = member(report, outcome, "category")
        && let Some(status_code) = member(report, outcome, "status_code")
        && let Node::String(category) = report.node(category)
        && let Node::Integer(status_code) = report.node(status_code)
    {
        let status_code = Int::parse(status_code).map_err(|_| Exit::error("invalid status"))?;
        return Ok(format!(
            "OpenVMM exited during startup: {} status {status_code}",
            category.render()
        ));
    }
    Ok(format!(
        "OpenVMM exited during startup with status {status}"
    ))
}

/// Runs a workload in a running sandbox, as `exec_workload` does. The lock is held only while the
/// running VM is found, so a long workload cannot delay a stop.
pub(crate) fn exec_workload(
    state_path: &str,
    artifacts: &Artifacts<'_>,
    request: &ExecRequest,
    response_timeout: f64,
) -> Result<ExecResult> {
    let state_dir = prepare_state_directory(state_path, false)?;
    let running = {
        let mut lock = LifecycleLock::acquire(&state_dir, response_timeout, false)?;
        running_vm(lock.locked(), artifacts)?
    };
    let mut session = connect(&running.vmm, &running.capability, response_timeout)?;
    session.exec(request, response_timeout)
}

/// Stops a running sandbox and returns OpenVMM's outcome report, as `stop` does.
///
/// The supervisor's stop runs one graceful step, which asks the guest to shut the VM down and
/// waits up to `timeout` seconds for OpenVMM to exit, so that Ctrl-C ends the wait. A VM whose
/// OpenVMM is still running then is reported, and keeps its runtime record: the stop never takes
/// the forced step.
pub(crate) fn stop(state_path: &str, artifacts: &Artifacts<'_>, timeout: f64) -> Result<Document> {
    let state_dir = prepare_state_directory(state_path, false)?;
    let mut lock = LifecycleLock::acquire(&state_dir, timeout, false)?;
    let locked = lock.locked();
    let Running { vmm, capability } = running_vm(locked, artifacts)?;
    // The graceful step waits for the exit itself, so the stop's own wait, until a deadline that
    // has passed by then, only checks whether OpenVMM has exited.
    let stopped = vmm
        .stop(locked, Instant::now(), None, |vmm, _| {
            {
                let mut session = connect(vmm, &capability, timeout)?;
                session.stop(timeout)?;
            }
            wait_for_exit(vmm, Deadline::after(timeout))
        })
        .map_err(error_with_cause)?;
    if let Some(error) = stopped.graceful_error {
        return Err(error);
    }
    if stopped.outcome == StopOutcome::TimedOut {
        return Err(Exit::error("OpenVMM did not terminate after managed stop"));
    }
    read_openvmm_outcome(&state_dir.join(OUTCOME_NAME))
}

/// Waits until the OpenVMM of `vmm` exits or `deadline` passes, failing if Ctrl-C arrives first.
fn wait_for_exit(vmm: &Vmm, deadline: Deadline) -> Result {
    loop {
        check_interrupt()?;
        let slice = deadline
            .remaining()
            .map_or(RETRY_INTERVAL, |left| left.min(RETRY_INTERVAL));
        if vmm
            .wait(Instant::now() + slice)
            .map_err(Exit::from_os_error)?
            || deadline.passed()
        {
            return Ok(());
        }
    }
}

/// Returns whether `name` is a temporary file that the store leaves beside one of its files when a
/// replacement of the file is interrupted: `.NAME.NUMBER.tmp`.
fn is_store_temporary(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(file, number)| {
            store::FILE_NAMES.contains(&file)
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Removes a stopped sandbox and its state directory, as `deprovision` does.
pub(crate) fn deprovision(state_path: &str, artifacts: &Artifacts<'_>, timeout: f64) -> Result {
    let state_dir = prepare_state_directory(state_path, false)?;
    let mut lock = LifecycleLock::acquire(&state_dir, timeout, false)?;
    match find_vm(lock.locked(), artifacts)? {
        Found::Nothing | Found::Exited => {}
        Found::Live(_) | Found::Mismatched(..) => {
            return Err(Exit::error("sandbox must be stopped before deprovision"));
        }
    }
    // No OpenVMM of the sandbox runs, and a start that was interrupted is over, so every file of
    // the store goes but its lock, which goes last.
    for name in store::FILE_NAMES
        .into_iter()
        .filter(|&name| name != LOCK_NAME)
        .chain([CONFIG_NAME])
    {
        unlink_missing_ok(&state_dir.join(name))?;
    }
    let mut unknown: Vec<String> = entries(&state_dir)
        .map_err(|error| os_error(&error, &state_dir))?
        .into_iter()
        .filter(|name| name != LOCK_NAME)
        .collect();
    for name in unknown.extract_if(.., |name| is_store_temporary(name)) {
        unlink_missing_ok(&state_dir.join(&name))?;
    }
    if !unknown.is_empty() {
        // `iterdir` lists the names in the order of the directory, which the message keeps.
        return Err(Exit::error(format!(
            "sandbox state directory contains files not owned by NVX: {}",
            unknown.join(", ")
        )));
    }
    // Holding the lock until the directory is gone keeps a transition that waits for it from
    // finding the sandbox halfway removed.
    lock.remove()?;
    let lingering = match std::fs::remove_dir(state_dir.as_path()) {
        Ok(()) => false,
        Err(error) if directory_not_empty(&error) => true,
        Err(error) => return Err(os_error(&error, &state_dir)),
    };
    if !lingering {
        return Ok(());
    }
    // A removed lock file that a handle still keeps stays in the directory, as do the lock files of
    // transitions that wait meanwhile. Each of them finds no sandbox, and removes its lock file as
    // it releases the lock, so the directory empties after this call releases its own.
    let (removing, held) = hold_directory(&state_dir)?;
    lock.release();
    let removed = remove_emptied_state_directory(&state_dir, removing, timeout);
    drop(held);
    removed
}

/// Returns the identity of a directory, and a handle that keeps it, as `_hold_directory` does: on
/// POSIX, the open directory keeps a directory that replaces it from reusing its inode number;
/// NTFS and ReFS do not reuse file IDs.
fn hold_directory(path: &PurePath) -> Result<((u64, u128), Option<File>)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = OpenOptions::new()
            .read(true)
            .custom_flags((nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits())
            .open(path.as_path())
            .map_err(|error| os_error(&error, path))?;
        // `os.fstat` gives the identity that `os.lstat` gives for the directory's path.
        let metadata = file.metadata().map_err(Exit::from_os_error)?;
        Ok(((metadata.dev(), u128::from(metadata.ino())), Some(file)))
    }
    #[cfg(not(unix))]
    {
        let status = fs::lstat(path.as_path()).map_err(|error| os_error(&error, path))?;
        Ok((status.identity(), None))
    }
}

/// Removes a state directory once no lingering lock file keeps it, as
/// `_remove_emptied_state_directory` does. A provision that waits for the removal may complete it
/// and provision the path again, which ends this attempt too.
fn remove_emptied_state_directory(
    state_dir: &PurePath,
    removing: (u64, u128),
    timeout: f64,
) -> Result {
    let deadline = Deadline::after(timeout);
    let mut retried_at_once = false;
    loop {
        let error = match std::fs::remove_dir(state_dir.as_path()) {
            Ok(()) => return Ok(()),
            Err(error) if os_error_class(&error) == OsErrorClass::NotFound => return Ok(()),
            Err(error) => error,
        };
        if directory_status(state_dir) != Some(removing) {
            return Ok(());
        }
        let remaining = match entries(state_dir) {
            Ok(remaining) => remaining,
            Err(error) if os_error_class(&error) == OsErrorClass::NotFound => return Ok(()),
            Err(error) => return Err(os_error(&error, state_dir)),
        };
        let mut unexpected: Vec<String> = remaining
            .iter()
            .filter(|name| !lingers(name))
            .cloned()
            .collect();
        unexpected.sort();
        // A provision that starts after this deprovision removed the lock file, and before it
        // removed the directory, provisions it again.
        if unexpected.iter().any(|name| name == CONFIG_NAME) {
            return Err(Exit::error(
                "sandbox was provisioned again while deprovision removed it",
            ));
        }
        if !unexpected.is_empty() {
            return Err(Exit::error(format!(
                "sandbox state directory contains files not owned by NVX: {}",
                unexpected.join(", ")
            )));
        }
        if !directory_not_empty(&error) {
            return Err(os_error(&error, state_dir));
        }
        // Without remaining entries, the last lingering lock file went away after rmdir failed,
        // so the next attempt follows at once. Another such failure right after it pauses first,
        // so that a file system that does not report emptiness right away cannot spin.
        if remaining.is_empty() && !retried_at_once {
            retried_at_once = true;
            if deadline.passed() {
                return Err(os_error(&error, state_dir));
            }
            continue;
        }
        retried_at_once = false;
        if !deadline.pause(LOCK_RETRY_INTERVAL)? {
            return Err(os_error(&error, state_dir));
        }
    }
}
