//! The prepared launch of a sandbox: the files that the checks of its plan returned, held open
//! until its VMM has them, the descriptors or handles that the VMM inherits, and the OpenVMM
//! arguments and kernel command line that name them.
//!
//! A [`SandboxPlan`] names its block devices by path, and persists. A launch that gave the VMM
//! those paths would let anything that took a path's place after the check, and before the VMM
//! opened the path, take the image's place. A [`PreparedLaunch`] instead takes the files that the
//! checks returned, the [`CheckedDistro`] of
//! [`DistroBinding::check`](super::distro::DistroBinding::check) and, for an upper on scratch,
//! the [`CheckedScratch`] of [`ScratchBinding::check`](super::scratch::ScratchBinding::check), and
//! hands the VMM exactly those objects:
//!
//! - On Linux, the VMM inherits the checked descriptors, through the allowlist of
//!   [`VmmCommand::inherit`](crate::host::supervisor::VmmCommand::inherit), and the OpenVMM
//!   arguments name each `/proc/self/fd/N`, which OpenVMM opens: the link reaches the checked file
//!   whatever later takes its path. No other descriptor of the caller reaches the VMM.
//! - On Windows, the VMM inherits no handle, and the arguments name the checked paths, which the
//!   checked files hold in place until they are closed: the distro layer's file denies other opens
//!   for writing or deleting the layer, and the scratch image's guard denies deleting or renaming
//!   it. OpenVMM's read-only open of the layer, and its open of the scratch image for reading and
//!   writing, share them.
//! - Other hosts cannot check files, so no launch is prepared there.
//!
//! Images are raw: OpenVMM attaches a file's bytes as they are, and the launch never converts an
//! image or reads its footer, as [`SandboxDistro`](super::SandboxDistro) says.
//!
//! The paths of descriptors exist only in the launch: [`PreparedLaunch::openvmm_arguments`]
//! renders them, and the plan, which callers persist, keeps the real paths. The caller adds its own
//! arguments, such as its boot console, CPU profile, and guest control, starts the VMM with
//! [`PreparedLaunch::inherited`] as its allowlist, and holds the prepared launch until the guest
//! reports authenticated Ready, or until it has torn down a launch that failed. Dropping it then
//! closes the checked files, which releases the guards, while the VMM keeps its own opens of the
//! images, and with them the claim of the scratch image.
//!
//! A plan never names a root identity for the workload: [`SandboxPlan::new`] refuses a zero UID
//! or GID, so the VMM's `--microvm-workload-identity` never encodes root.

use std::io;
use std::path::Path;

use super::distro::CheckedDistro;
use super::plan::{self, BlockRole, SandboxPlan};
use super::refused;
use super::scratch::CheckedScratch;
use crate::error::Result;
use crate::host::python::fs;
use crate::host::python::path::PurePath;
use crate::host::supervisor::Inherited;

/// A launch that holds the checked files of its plan, and the OpenVMM arguments and kernel
/// command line that hand them to the VMM.
///
/// [`new`](Self::new) prepares it from a plan and the files that the checks of its block devices
/// returned. The caller then starts the VMM with [`openvmm_arguments`](Self::openvmm_arguments),
/// its own arguments, and [`kernel_command_line`](Self::kernel_command_line), with
/// [`inherited`](Self::inherited) as the allowlist of its
/// [`VmmCommand`](crate::host::supervisor::VmmCommand), and drops the prepared launch once the
/// guest reports authenticated Ready, or once a launch that failed is torn down:
///
/// ```no_run
/// use std::ffi::OsString;
/// use std::fs::File;
/// use std::time::Instant;
///
/// use nvx::host::sandbox::distro::{DISTRO_POLICY_REVISION, DistroBinding};
/// use nvx::host::sandbox::scratch::{CLAIM_RELEASE_WAIT, ScratchBinding};
/// use nvx::host::sandbox::{PreparedLaunch, SandboxLaunch};
/// use nvx::host::supervisor::{self, VmmCommand};
///
/// # fn launch(
/// #     launch: &SandboxLaunch,
/// #     distro_binding: &DistroBinding,
/// #     scratch_binding: &ScratchBinding,
/// #     capability: &[u8; nvx::protocol::CAPABILITY_LEN],
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// // Check the bindings that the caller recorded when it staged the images: from their metadata
/// // alone, and claiming the scratch image for this sandbox.
/// let distro = distro_binding.check(launch.distro(), DISTRO_POLICY_REVISION)?;
/// let scratch = scratch_binding.check(launch.scratch(), Instant::now() + CLAIM_RELEASE_WAIT)?;
/// let prepared = PreparedLaunch::new(launch.bound_plan(distro_binding)?, distro, Some(scratch), "")?;
///
/// let mut arguments: Vec<OsString> =
///     prepared.openvmm_arguments().iter().map(OsString::from).collect();
/// arguments.extend(["--cmdline".into(), prepared.kernel_command_line().into()]);
/// // ... the caller's own arguments: hypervisor, memory, kernel, initrd, and guest control ...
/// let mut command = VmmCommand::new("openvmm", arguments, ".");
/// command.inherit = prepared.inherited();
/// let launched = supervisor::spawn(&command, capability, File::create("openvmm.log")?)?;
/// // ... record the VMM, and wait for the guest's authenticated Ready ...
/// drop(prepared);
/// launched.detach();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PreparedLaunch {
    /// The plan, which names the images by their real paths.
    plan: SandboxPlan,
    /// The checked distro layer.
    distro: CheckedDistro,
    /// The checked scratch image, for an upper on scratch.
    scratch: Option<CheckedScratch>,
    /// The OpenVMM arguments of the plan, which name the checked files.
    openvmm_arguments: Vec<String>,
    /// The kernel command line of the plan.
    kernel_command_line: String,
}

impl PreparedLaunch {
    /// Prepares the launch of `plan` with the checked files of its block devices: `distro`, which
    /// [`DistroBinding::check`](super::distro::DistroBinding::check) returned for the plan's
    /// image, and `scratch`, which [`ScratchBinding::check`](super::scratch::ScratchBinding::check)
    /// returned for the scratch image of an upper on scratch, or `None` for an upper in RAM. It
    /// renders the plan's OpenVMM arguments, naming the checked files, and its kernel command line
    /// with `user_command_line`, as [`SandboxPlan::kernel_command_line`] does.
    ///
    /// The checked files must be those of the plan: the distro layer checked at the path of the
    /// plan's image, with the format and identity of its image, and the scratch image checked at
    /// the path of its upper. Fails with
    /// [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) for files that are not, and as
    /// [`SandboxPlan::openvmm_arguments`] and [`SandboxPlan::kernel_command_line`] fail. It never
    /// opens, reads, or maps a file.
    pub fn new(
        plan: SandboxPlan,
        distro: CheckedDistro,
        scratch: Option<CheckedScratch>,
        user_command_line: &str,
    ) -> Result<Self> {
        Self::new_with(plan, distro, scratch, user_command_line, &fs::cwd)
    }

    /// Implements [`new`](Self::new) with `cwd` as `Path.cwd()`.
    pub(crate) fn new_with(
        plan: SandboxPlan,
        distro: CheckedDistro,
        scratch: Option<CheckedScratch>,
        user_command_line: &str,
        cwd: &dyn Fn() -> io::Result<PurePath>,
    ) -> Result<Self> {
        let planned = plan.distro().path();
        if !same_path(distro.path(), planned) {
            return Err(refused(format!(
                "the checked distro layer {} is not the plan's image {}",
                distro.path().display(),
                planned.display()
            )));
        }
        let (format, identity) = distro.bound();
        if plan::image_of(format, identity)? != plan.distro().image() {
            return Err(refused(format!(
                "the plan's image is not the {format} layer with identity {identity} that the \
                 distro binding of {} names",
                planned.display()
            )));
        }
        match (plan.upper().scratch_path(), &scratch) {
            (Some(planned), Some(checked)) if !same_path(checked.path(), planned) => {
                return Err(refused(format!(
                    "the checked scratch image {} is not the plan's scratch image {}",
                    checked.path().display(),
                    planned.display()
                )));
            }
            (Some(planned), None) => {
                return Err(refused(format!(
                    "the plan's upper is on the scratch image {}, which was not checked",
                    planned.display()
                )));
            }
            (None, Some(checked)) => {
                return Err(refused(format!(
                    "the plan's upper is in RAM, which takes no scratch image, not {}",
                    checked.path().display()
                )));
            }
            _ => {}
        }
        let openvmm_arguments =
            plan.render_arguments(&|role, path| block_path(role, path, &distro, &scratch), cwd)?;
        let kernel_command_line = plan.kernel_command_line(user_command_line)?;
        Ok(Self {
            plan,
            distro,
            scratch,
            openvmm_arguments,
            kernel_command_line,
        })
    }

    /// Returns the plan, which names the images by their real paths.
    pub fn plan(&self) -> &SandboxPlan {
        &self.plan
    }

    /// Returns the checked distro layer.
    pub fn distro(&self) -> &CheckedDistro {
        &self.distro
    }

    /// Returns the checked scratch image, or `None` for an upper in RAM.
    pub fn scratch(&self) -> Option<&CheckedScratch> {
        self.scratch.as_ref()
    }

    /// Returns the OpenVMM arguments of the plan, as [`SandboxPlan::openvmm_arguments`] renders
    /// them, except that on Linux each block device names its checked file as `/proc/self/fd/N`,
    /// which [`inherited`](Self::inherited) passes the VMM under the number `N`.
    ///
    /// They hold for this launch only: never persist them.
    pub fn openvmm_arguments(&self) -> &[String] {
        &self.openvmm_arguments
    }

    /// Returns the kernel command line of the plan, with the user's command line given to
    /// [`new`](Self::new).
    pub fn kernel_command_line(&self) -> &str {
        &self.kernel_command_line
    }

    /// Returns the descriptors that the VMM inherits, for the allowlist of its
    /// [`VmmCommand::inherit`](crate::host::supervisor::VmmCommand::inherit): on Linux, those of
    /// the checked distro layer and of the checked scratch image, if any, which
    /// [`openvmm_arguments`](Self::openvmm_arguments) names; elsewhere none, since the VMM opens
    /// the checked paths.
    pub fn inherited(&self) -> Vec<Inherited<'_>> {
        #[cfg(target_os = "linux")]
        {
            let mut inherited = vec![Inherited::new(self.distro.file())];
            inherited.extend(
                self.scratch
                    .as_ref()
                    .map(|scratch| Inherited::new(scratch.file())),
            );
            inherited
        }
        #[cfg(not(target_os = "linux"))]
        Vec::new()
    }
}

/// Returns whether `checked` and `planned`, two paths normalized as `pathlib.Path` normalizes
/// them, are the same text.
fn same_path(checked: &Path, planned: &Path) -> bool {
    checked.as_os_str() == planned.as_os_str()
}

/// Returns how the OpenVMM arguments name the file of the block device of `role`, at `path` in
/// the plan: on Linux, the checked file of `distro` or `scratch`, as `/proc/self/fd/N`; elsewhere,
/// `path`, which the checked file holds in place.
fn block_path(
    role: BlockRole,
    path: &PurePath,
    distro: &CheckedDistro,
    scratch: &Option<CheckedScratch>,
) -> String {
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        let file = match (role, scratch) {
            (BlockRole::Distro, _) => distro.file(),
            (BlockRole::Scratch, Some(scratch)) => scratch.file(),
            (BlockRole::Scratch, None) => unreachable!("a plan with a scratch block has its file"),
        };
        Inherited::new(file).proc_path().display().to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (role, distro, scratch);
        path.as_str().to_owned()
    }
}

#[cfg(all(test, any(target_os = "linux", windows)))]
mod tests;
