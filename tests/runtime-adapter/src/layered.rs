//! The host program's VMs with a layered root: an image, on the `distro` block device, under an
//! upper, which the guest agent's worker assembles outside PID 1.
//!
//! The host stages the images of a root, with their bindings, in the sandbox's store before it
//! launches them; see [`crate::staged`]. Staging is where hashing belongs: a launch never hashes.
//!
//! The host plans the VM's block devices and the boot tokens of its root with NVX's typed plan of
//! a cold layered launch for an adapter's own guest, `nvx::host::sandbox::SandboxPlan::adapter`,
//! which names none of the settings of NVX's sandbox profile, such as a workload identity, since
//! the guest agent runs its executions itself. It launches the VM through NVX's supervisor, as it
//! launches VMs without a layered root, but without NVX's managed lifecycle; see
//! [`LayeredLaunch::openvmm_arguments`]. The boot tokens carry only what NVX's boot contract
//! defines: the image's format and the identity that the guest expects of it, and the upper.
//! Everything else that the root needs goes in one root configuration, a [`RootConfig`], which the
//! host sends once it attaches.
//!
//! The host records what it launched in the sandbox's store, beside NVX's runtime records, as a
//! [`LaunchRecord`], with the bindings that the store stages for the launch's images.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

use nvx::host::artifacts::absolute;
use nvx::host::launch::DEFAULT_MEMORY_MIB;
use nvx::host::sandbox::distro::DistroBinding;
use nvx::host::sandbox::scratch::ScratchBinding;
use nvx::host::sandbox::{LayerRole, SandboxDistro, SandboxLayer, SandboxPlan, SandboxUpper};
use nvx::protocol::root::{ImageFormat, RootImage};
use nvx::uuid::Uuid;
use nvx::{Error, Hypervisor, Result};
use serde_json::{Value, json};

use crate::root::RootConfig;

/// The name of the record of a launch in the sandbox's store.
pub const RECORD_NAME: &str = "runtime-adapter.json";
/// The format of the record of a launch that this build writes.
pub const RECORD_FORMAT: u64 = 1;
/// The kernel parameter with which NVX's `/init` hands a VM to NVX's init agent, which the
/// adapter's initramfs replaces with the guest agent; see [`crate::initramfs`]. An adapter's plan
/// renders none of the parameters of NVX's sandbox profile, so the launch passes it as its own.
pub const SANDBOX_TOKEN: &str = "nvx_sandbox=1";
/// The size of a sector of a block device, in bytes.
const SECTOR_SIZE: u64 = 512;

/// A VM with a layered root: the plan of its image, its upper, and their boot tokens, the root
/// configuration that the host sends its guest agent, and the bindings that the sandbox's store
/// stages for its images.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayeredLaunch {
    /// The adapter's plan of the VM's block devices and of the boot tokens of its root.
    pub plan: SandboxPlan,
    /// The root configuration that the host sends the guest agent once it attaches.
    pub config: RootConfig,
    /// The bindings that the sandbox's store stages for the plan's images, as
    /// [`Staged::bindings`](crate::staged::Staged::bindings) finds them, which the launch
    /// records.
    pub bindings: Bindings,
}

impl LayeredLaunch {
    /// Returns the launch of the image at `distro`, in `format`, of which the guest expects the
    /// identity `identity`, over the ext4 scratch image at `scratch`, or over RAM without one,
    /// without bindings.
    ///
    /// The root configuration takes its defaults, with the runtime directory `runtime` instead, if
    /// any, as it is, so that the guest checks it, and with the size of each image, if it is a
    /// whole number of sectors, which the guest checks against its block device.
    ///
    /// Fails with [`ErrorKind::Unsupported`](nvx::ErrorKind::Unsupported) if a path is not
    /// Unicode, and otherwise as `SandboxPlan::validated` does, such as for an image that is not a
    /// regular file.
    pub fn new(
        distro: &Path,
        format: ImageFormat,
        identity: Uuid,
        scratch: Option<&Path>,
        runtime: Option<&str>,
    ) -> Result<Self> {
        let plan = plan(distro, format, identity, scratch)?;
        let mut config = RootConfig {
            distro_sectors: sectors(plan.distro().path())?,
            scratch_sectors: plan
                .upper()
                .scratch_path()
                .map(sectors)
                .transpose()?
                .flatten(),
            ..RootConfig::default()
        };
        if let Some(runtime) = runtime {
            runtime.clone_into(&mut config.runtime);
        }
        Ok(Self {
            plan,
            config,
            bindings: Bindings::default(),
        })
    }

    /// Returns the VM's kernel command line: [`SANDBOX_TOKEN`], then the boot tokens of the
    /// plan's root, without parameters of the caller.
    ///
    /// Fails as `SandboxPlan::kernel_command_line` does.
    pub fn kernel_command_line(&self) -> Result<String> {
        self.plan.kernel_command_line(SANDBOX_TOKEN)
    }

    /// Returns OpenVMM's arguments for the VM: the plan's, which attach its block devices, then
    /// the VM in one process on `hypervisor`, NVX's default memory, the kernel at `kernel`, the
    /// initramfs at `initramfs`, the [kernel command line](Self::kernel_command_line), no virtio
    /// console, the control console listening on `endpoint` with the launch capability on
    /// standard input, and the outcome report at `report`.
    ///
    /// Unlike those of NVX's sandbox start, they name no workload identity, which the adapter's
    /// plan does not hold, and no managed lifecycle: OpenVMM only checks the arguments of the
    /// managed lifecycle and labels its outcome report with it, and only NVX's init agent, which
    /// the guest agent replaces, reads its boot token.
    ///
    /// Fails as `SandboxPlan::openvmm_arguments` and [`kernel_command_line`](Self::kernel_command_line)
    /// do.
    pub fn openvmm_arguments(
        &self,
        hypervisor: Hypervisor,
        kernel: &Path,
        initramfs: &Path,
        endpoint: &str,
        report: &Path,
    ) -> Result<Vec<OsString>> {
        let mut arguments = self
            .plan
            .openvmm_arguments()?
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let memory = format!("{DEFAULT_MEMORY_MIB}M");
        let command_line = self.kernel_command_line()?;
        let control = format!("listen={endpoint}");
        let options = [
            OsStr::new("--single-process"),
            OsStr::new("--hypervisor"),
            OsStr::new(hypervisor.as_str()),
            OsStr::new("--memory"),
            OsStr::new(&memory),
            OsStr::new("--kernel"),
            kernel.as_os_str(),
            OsStr::new("--initrd"),
            initramfs.as_os_str(),
            OsStr::new("--cmdline"),
            OsStr::new(&command_line),
            OsStr::new("--virtio-console"),
            OsStr::new("none"),
            OsStr::new("--microvm-control-console"),
            OsStr::new(&control),
            OsStr::new("--microvm-control-auth-stdin"),
            OsStr::new("--microvm-report"),
            report.as_os_str(),
        ];
        arguments.extend(options.map(OsStr::to_os_string));
        Ok(arguments)
    }
}

/// Returns the adapter's plan of the image at `distro`, in `format`, of which the guest expects
/// the identity `identity`, over the ext4 scratch image at `scratch`, or over RAM without one,
/// checked against the host with `SandboxPlan::validated`.
///
/// OpenVMM runs in the sandbox's store, so the plan names the images by absolute paths, which it
/// normalizes as `pathlib` does.
pub(crate) fn plan(
    distro: &Path,
    format: ImageFormat,
    identity: Uuid,
    scratch: Option<&Path>,
) -> Result<SandboxPlan> {
    let distro = absolute(distro)?;
    let scratch = scratch.map(absolute).transpose()?;
    let upper = match &scratch {
        Some(scratch) => SandboxUpper::scratch(unicode(scratch)?),
        None => SandboxUpper::RAM,
    };
    let image = RootImage {
        format,
        identity: Some(identity),
    };
    let plan = SandboxPlan::adapter(SandboxDistro::new(unicode(&distro)?, image), upper);
    plan.validated()?;
    Ok(plan)
}

/// Returns the distro layer of the image at `path`, in `format`, of which the guest expects the
/// identity `identity`, which NVX's bindings of the image name.
pub(crate) fn layer(path: &Path, format: ImageFormat, identity: Uuid) -> Result<SandboxLayer> {
    let path = unicode(path)?;
    let identity = identity.to_string();
    Ok(match format {
        ImageFormat::Erofs => SandboxLayer::new(LayerRole::Distro, path, identity),
        ImageFormat::Gpt => SandboxLayer::gpt(LayerRole::Distro, path, identity),
    })
}

/// Returns `path` as text, which the plan takes.
pub(crate) fn unicode(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        Error::unsupported(format!("the path {} is not Unicode text", path.display()))
    })
}

/// Returns the size of the file at `path` in sectors, if it is a whole number of them.
fn sectors(path: &Path) -> Result<Option<u64>> {
    let length = fs::metadata(path)
        .map_err(|error| {
            Error::unavailable(format!("cannot read the size of {}", path.display()))
                .with_source(error)
        })?
        .len();
    Ok(length
        .is_multiple_of(SECTOR_SIZE)
        .then_some(length / SECTOR_SIZE))
}

/// The bindings of a launch's images that the sandbox's store stages, as
/// [`Staged::bindings`](crate::staged::Staged::bindings) finds them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bindings {
    /// The binding of the image, if the store stages the launch's image.
    pub distro: Option<DistroBinding>,
    /// The binding of the scratch image, if the launch's upper is on a scratch image that the
    /// store stages.
    pub scratch: Option<ScratchBinding>,
}

impl Bindings {
    /// Returns the bindings as JSON: an object of the serde forms of the image's binding and of the
    /// scratch image's, each `null` without one.
    ///
    /// Fails with [`ErrorKind::Other`](nvx::ErrorKind::Other) if a binding has no JSON form.
    pub fn to_json(&self) -> Result<Value> {
        let distro = self.distro.as_ref().map(serde_json::to_value);
        let scratch = self.scratch.as_ref().map(serde_json::to_value);
        Ok(json!({
            "distro": distro.map(binding_json).transpose()?,
            "scratch": scratch.map(binding_json).transpose()?,
        }))
    }
}

/// Returns the JSON form that `form` holds for a binding.
///
/// Fails with [`ErrorKind::Other`](nvx::ErrorKind::Other) if the binding has none.
pub(crate) fn binding_json(form: serde_json::Result<Value>) -> Result<Value> {
    form.map_err(|error| Error::other("a binding has no JSON form").with_source(error))
}

/// Writes `record` as JSON, with a newline, at `path`, in place of an earlier record.
///
/// Fails with [`ErrorKind::Io`](nvx::ErrorKind::Io) if the record cannot be written.
pub(crate) fn write_record(path: &Path, record: &Value) -> Result<()> {
    let mut text = record.to_string();
    text.push('\n');
    fs::write(path, text)
        .map_err(|error| Error::io(format!("cannot write {}", path.display())).with_source(error))
}

/// What the host program launched in a sandbox, which it records in the sandbox's store, in
/// [`RECORD_NAME`], before it spawns the VMM. The record is JSON in format [`RECORD_FORMAT`]:
///
/// ```json
/// {"format": 1, "mode": "layered", "kernelCommandLine": "nvx_sandbox=1 nvx_layer=...",
///  "plan": PLAN, "bindings": {"distro": DISTRO_BINDING, "scratch": SCRATCH_BINDING},
///  "rootConfiguration": "version=1\nruntime=/run/runtime-adapter\n..."}
/// ```
///
/// The `mode` is `layered`, or `blockless` for a VM without a layered root, whose `plan`,
/// `bindings`, and `rootConfiguration` are `null`. The `plan` is the persisted form of the VM's
/// `SandboxPlan`. The `bindings` are those that the store stages for the plan's images, as
/// [`Staged::bindings`](crate::staged::Staged::bindings) finds them, in the serde forms of NVX's
/// `DistroBinding` and `ScratchBinding`, each `null` unless the store stages it, as for an upper
/// in RAM, which has no scratch image. The `rootConfiguration` is the encoding of the root
/// configuration that the host sends, as it sends it, whether or not the guest accepts it.
#[derive(Clone, Copy, Debug)]
pub struct LaunchRecord<'a> {
    /// The VM's kernel command line.
    pub kernel_command_line: &'a str,
    /// The VM's layered root, if it has one.
    pub layered: Option<&'a LayeredLaunch>,
}

impl LaunchRecord<'_> {
    /// Returns the record as JSON.
    ///
    /// Fails with [`ErrorKind::Other`](nvx::ErrorKind::Other) if the plan or a binding has no
    /// JSON form.
    pub fn to_json(&self) -> Result<Value> {
        let (mode, plan, bindings, config) = match self.layered {
            Some(layered) => {
                let plan = serde_json::to_value(&layered.plan).map_err(|error| {
                    Error::other("the plan of the layered root has no JSON form").with_source(error)
                })?;
                let config = String::from_utf8_lossy(&layered.config.encode()).into_owned();
                (
                    "layered",
                    plan,
                    layered.bindings.to_json()?,
                    Value::String(config),
                )
            }
            None => ("blockless", Value::Null, Value::Null, Value::Null),
        };
        Ok(json!({
            "format": RECORD_FORMAT,
            "mode": mode,
            "kernelCommandLine": self.kernel_command_line,
            "plan": plan,
            "bindings": bindings,
            "rootConfiguration": config,
        }))
    }

    /// Writes the record in `directory`, the sandbox's store, in place of an earlier one.
    ///
    /// Fails as [`to_json`](Self::to_json) does, and with
    /// [`ErrorKind::Io`](nvx::ErrorKind::Io) if the record cannot be written.
    pub fn write(&self, directory: &Path) -> Result<()> {
        write_record(&directory.join(RECORD_NAME), &self.to_json()?)
    }
}
