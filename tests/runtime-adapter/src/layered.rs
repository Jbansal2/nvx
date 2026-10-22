//! The host program's VMs with a layered root: an image, on the `distro` block device, under an
//! upper, which the guest agent's worker assembles outside PID 1.
//!
//! The host plans the VM's block devices and the boot tokens of its root with NVX's typed plan of a
//! cold layered launch, a `nvx::host::sandbox::SandboxPlan`, and launches the VM through NVX's
//! supervisor, as it launches VMs without a layered root, with the OpenVMM arguments that NVX's
//! own sandbox start passes; see [`LayeredLaunch::openvmm_arguments`]. The boot tokens carry only
//! what NVX's boot contract defines: the image's format and the identity that the guest expects of
//! it, and the upper. Everything else that the root needs goes in one root configuration, a
//! [`RootConfig`], which the host sends once it attaches.
//!
//! The host records what it launched in the sandbox's store, beside NVX's runtime records, as a
//! [`LaunchRecord`].

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

use nvx::host::artifacts::absolute;
use nvx::host::launch::DEFAULT_MEMORY_MIB;
use nvx::host::sandbox::{SandboxDistro, SandboxPlan, SandboxSettings, SandboxUpper};
use nvx::protocol::root::RootImage;
use nvx::{Error, Hypervisor, Result};
use serde_json::{Value, json};

use crate::root::RootConfig;

/// The name of the record of a launch in the sandbox's store.
pub const RECORD_NAME: &str = "runtime-adapter.json";
/// The format of the record of a launch that this build writes.
pub const RECORD_FORMAT: u64 = 1;
/// The size of a sector of a block device, in bytes.
const SECTOR_SIZE: u64 = 512;

/// A VM with a layered root: the plan of its image, its upper, and their boot tokens, and the
/// root configuration that the host sends its guest agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayeredLaunch {
    /// The plan of the VM's block devices and of the boot tokens of its root, with NVX's default
    /// launch settings, whose tokens the worker ignores.
    pub plan: SandboxPlan,
    /// The root configuration that the host sends the guest agent once it attaches.
    pub config: RootConfig,
}

impl LayeredLaunch {
    /// Returns the launch of the image at `distro`, in the format and with the expected identity of
    /// `image`, over the ext4 scratch image at `scratch`, or over RAM without one.
    ///
    /// The root configuration takes its defaults, with the runtime directory `runtime` instead, if
    /// any, as it is, so that the guest checks it, and with the size of each image, if it is a
    /// whole number of sectors, which the guest checks against its block device.
    ///
    /// Fails with [`ErrorKind::Unsupported`](nvx::ErrorKind::Unsupported) if a path is not
    /// Unicode, and otherwise as `SandboxPlan::new` and `SandboxPlan::validated` do, such as for an
    /// image that is not a regular file.
    pub fn new(
        distro: &Path,
        image: RootImage,
        scratch: Option<&Path>,
        runtime: Option<&str>,
    ) -> Result<Self> {
        // OpenVMM runs in the sandbox's store, so the plan names the images by absolute paths.
        let distro = absolute(distro)?;
        let scratch = scratch.map(absolute).transpose()?;
        let upper = match &scratch {
            Some(scratch) => SandboxUpper::scratch(unicode(scratch)?),
            None => SandboxUpper::RAM,
        };
        let plan = SandboxPlan::new(
            SandboxDistro::new(unicode(&distro)?, image),
            upper,
            SandboxSettings::default(),
        )?;
        plan.validated()?;
        let mut config = RootConfig {
            distro_sectors: sectors(&distro)?,
            scratch_sectors: scratch.as_deref().map(sectors).transpose()?.flatten(),
            ..RootConfig::default()
        };
        if let Some(runtime) = runtime {
            runtime.clone_into(&mut config.runtime);
        }
        Ok(Self { plan, config })
    }

    /// Returns the VM's kernel command line: the plan's, `nvx_sandbox=1` and the boot tokens of
    /// the root among them, without parameters of the caller.
    ///
    /// Fails as `SandboxPlan::kernel_command_line` does.
    pub fn kernel_command_line(&self) -> Result<String> {
        self.plan.kernel_command_line("")
    }

    /// Returns OpenVMM's arguments for the VM, as NVX's sandbox start composes them: the plan's,
    /// which attach its block devices, then the managed lifecycle in one process on `hypervisor`,
    /// NVX's default memory, the kernel at `kernel`, the initramfs at `initramfs`, the
    /// [kernel command line](Self::kernel_command_line), no virtio console, the control console
    /// listening on `endpoint` with the launch capability on standard input, and the outcome
    /// report at `report`.
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
            OsStr::new("--microvm-lifecycle"),
            OsStr::new("managed"),
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

/// Returns `path` as text, which the plan takes.
fn unicode(path: &Path) -> Result<&str> {
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

/// What the host program launched in a sandbox, which it records in the sandbox's store, in
/// [`RECORD_NAME`], before it spawns the VMM. The record is JSON in format [`RECORD_FORMAT`]:
///
/// ```json
/// {"format": 1, "mode": "layered", "kernelCommandLine": "... nvx_sandbox=1 ...",
///  "plan": PLAN, "rootConfiguration": "version=1\nruntime=/run/runtime-adapter\n..."}
/// ```
///
/// The `mode` is `layered`, or `blockless` for a VM without a layered root, whose `plan` and
/// `rootConfiguration` are `null`. The `plan` is the persisted form of the VM's `SandboxPlan`, and
/// the `rootConfiguration` the encoding of the root configuration that the host sends, as it sends
/// it, whether or not the guest accepts it.
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
    /// Fails with [`ErrorKind::Other`](nvx::ErrorKind::Other) if the plan has no JSON form.
    pub fn to_json(&self) -> Result<Value> {
        let (mode, plan, config) = match self.layered {
            Some(layered) => {
                let plan = serde_json::to_value(&layered.plan).map_err(|error| {
                    Error::other("the plan of the layered root has no JSON form").with_source(error)
                })?;
                let config = String::from_utf8_lossy(&layered.config.encode()).into_owned();
                ("layered", plan, Value::String(config))
            }
            None => ("blockless", Value::Null, Value::Null),
        };
        Ok(json!({
            "format": RECORD_FORMAT,
            "mode": mode,
            "kernelCommandLine": self.kernel_command_line,
            "plan": plan,
            "rootConfiguration": config,
        }))
    }

    /// Writes the record in `directory`, the sandbox's store, in place of an earlier one.
    ///
    /// Fails as [`to_json`](Self::to_json) does, and with
    /// [`ErrorKind::Io`](nvx::ErrorKind::Io) if the record cannot be written.
    pub fn write(&self, directory: &Path) -> Result<()> {
        let path = directory.join(RECORD_NAME);
        let mut text = self.to_json()?.to_string();
        text.push('\n');
        fs::write(&path, text).map_err(|error| {
            Error::io(format!("cannot write {}", path.display())).with_source(error)
        })
    }
}
