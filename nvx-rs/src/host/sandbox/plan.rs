//! The typed plan of a cold layered launch: its block devices, which image over which upper, and
//! its launch settings, from which come OpenVMM's arguments and the kernel command line.
//!
//! A [`SandboxPlan`] holds:
//!
//! - one read-only `distro` block device, a [`SandboxDistro`]: a raw host image, an EROFS
//!   filesystem or a GPT disk, with the identity that the guest expects of it, if any, as its
//!   [`RootImage`] names them;
//! - an upper, a [`SandboxUpper`]: a whole-device ext4 scratch image on the `scratch` block
//!   device, or RAM, with no scratch block device;
//! - the launch settings, [`SandboxSettings`]: the entrypoint and its arguments, the hostname, the
//!   workload identity, the resource limits, and the live shares.
//!
//! A plan keys its block devices by role, [`BlockRole`], and knows only the `distro` and
//! `scratch` roles. Every combination of format and upper plans and renders:
//! [`openvmm_arguments`](SandboxPlan::openvmm_arguments) attaches the block devices, with no
//! scratch block device for a RAM upper, and [`kernel_command_line`](SandboxPlan::kernel_command_line)
//! describes the root with the boot tokens of [`protocol::root`](crate::protocol::root), within the
//! budget that OpenVMM leaves the profile.

use std::fmt;
use std::io;
use std::path::Path;

use super::distro::{DistroBinding, DistroFormat};
use super::mount::{self, SandboxMount};
use super::{
    SANDBOX_COMMAND_LINE_MAX_SIZE, SandboxSettings, refused, reject_container_path,
    reject_disk_path, require_pure_file, validate_settings,
};
use crate::error::Result;
use crate::host::python::builtins::{repr, split, strip};
use crate::host::python::fs;
use crate::host::python::path::{Flavor, PurePath};
use crate::protocol::root::{
    DISTRO_MMIO_BASE, ImageFormat, RootImage, RootLayout, RootUpper, SCRATCH_MMIO_BASE, Uuid,
};

/// The role of a block device of a plan, which fixes its MMIO base and its access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockRole {
    /// The read-only image.
    Distro,
    /// The writable ext4 upper.
    Scratch,
}

impl BlockRole {
    /// Returns the role's name, which OpenVMM's `--microvm-sandbox-block` takes: `distro` or
    /// `scratch`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Distro => "distro",
            Self::Scratch => "scratch",
        }
    }

    /// Returns the MMIO base of the role's block device: [`DISTRO_MMIO_BASE`] or
    /// [`SCRATCH_MMIO_BASE`].
    pub const fn mmio_base(self) -> u64 {
        match self {
            Self::Distro => DISTRO_MMIO_BASE,
            Self::Scratch => SCRATCH_MMIO_BASE,
        }
    }

    /// Returns whether the role's block device is read-only, as the distro image is.
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::Distro)
    }
}

impl fmt::Display for BlockRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The read-only `distro` block device of a plan: a raw host image, and its format and the
/// identity that the guest expects of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxDistro {
    /// The image, as `pathlib` normalizes it.
    path: PurePath,
    /// The image's format and expected identity.
    image: RootImage,
}

impl SandboxDistro {
    /// Returns the image at `path`, normalized as `pathlib.Path` normalizes it, in the format and
    /// with the expected identity of `image`.
    ///
    /// The image is raw: OpenVMM attaches the file's bytes as they are. An image in a container
    /// format, such as a VHD, is staged as a raw file first, under a name whose extension does not
    /// make OpenVMM read a container, which [`SandboxPlan::validated`] checks.
    pub fn new(path: &str, image: RootImage) -> Self {
        Self::new_in(Flavor::NATIVE, path, image)
    }

    /// Implements [`new`](Self::new) for a path of `flavor`.
    pub(crate) fn new_in(flavor: Flavor, path: &str, image: RootImage) -> Self {
        Self::at(PurePath::new(flavor, path), image)
    }

    /// Returns the image at `path`, which is normalized already.
    pub(crate) fn at(path: PurePath, image: RootImage) -> Self {
        Self { path, image }
    }

    /// Returns the image's path.
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns the image's format and expected identity.
    pub fn image(&self) -> RootImage {
        self.image
    }

    /// Returns how messages name the image: `distro EROFS layer` or `distro GPT image`.
    fn description(&self) -> &'static str {
        match self.image.format {
            ImageFormat::Erofs => "distro EROFS layer",
            ImageFormat::Gpt => "distro GPT image",
        }
    }
}

/// Where a plan keeps the upper of its overlay: in an ext4 scratch image on the `scratch` block
/// device, or in RAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxUpper {
    /// The scratch image, as `pathlib` normalizes it, or `None` for a RAM upper.
    scratch: Option<PurePath>,
}

impl SandboxUpper {
    /// An upper in RAM, with no scratch block device.
    pub const RAM: Self = Self { scratch: None };

    /// Returns an upper on the preformatted ext4 scratch image at `path`, normalized as
    /// `pathlib.Path` normalizes it, whose whole device the guest mounts.
    pub fn scratch(path: &str) -> Self {
        Self::scratch_in(Flavor::NATIVE, path)
    }

    /// Implements [`scratch`](Self::scratch) for a path of `flavor`.
    pub(crate) fn scratch_in(flavor: Flavor, path: &str) -> Self {
        Self::scratch_at(PurePath::new(flavor, path))
    }

    /// Returns an upper on the scratch image at `path`, which is normalized already.
    pub(crate) fn scratch_at(path: PurePath) -> Self {
        Self {
            scratch: Some(path),
        }
    }

    /// Returns where the upper is, as the boot tokens name it.
    pub fn kind(&self) -> RootUpper {
        match self.scratch {
            Some(_) => RootUpper::Scratch,
            None => RootUpper::Ram,
        }
    }

    /// Returns the scratch image, or `None` for a RAM upper.
    pub fn scratch_path(&self) -> Option<&Path> {
        self.scratch.as_ref().map(PurePath::as_path)
    }
}

/// The plan of a cold layered launch: everything that its OpenVMM arguments and kernel command
/// line depend on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxPlan {
    /// The image.
    distro: SandboxDistro,
    /// The upper.
    upper: SandboxUpper,
    /// The launch settings.
    settings: SandboxSettings,
}

impl SandboxPlan {
    /// Returns the plan of `distro` over `upper`, with `settings`.
    ///
    /// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported), checking the settings
    /// in this order: the entrypoint, the arguments, the hostname, a non-root identity, positive
    /// limits, and shares whose targets do not overlap and that have one owner.
    pub fn new(
        distro: SandboxDistro,
        upper: SandboxUpper,
        settings: SandboxSettings,
    ) -> Result<Self> {
        validate_settings(&settings)?;
        Ok(Self {
            distro,
            upper,
            settings,
        })
    }

    /// Returns the image.
    pub fn distro(&self) -> &SandboxDistro {
        &self.distro
    }

    /// Returns the upper.
    pub fn upper(&self) -> &SandboxUpper {
        &self.upper
    }

    /// Returns the launch settings.
    pub fn settings(&self) -> &SandboxSettings {
        &self.settings
    }

    /// Returns the shares.
    pub fn mounts(&self) -> &[SandboxMount] {
        &self.settings.mounts
    }

    /// Returns the layout of the root that the plan boots: its image and its upper.
    pub fn layout(&self) -> RootLayout {
        RootLayout {
            image: self.distro.image,
            upper: self.upper.kind(),
        }
    }

    /// Returns the block devices of the plan in role order: the image, then the scratch image of
    /// an upper on scratch.
    pub fn blocks(&self) -> Vec<(BlockRole, &Path)> {
        self.pure_blocks()
            .into_iter()
            .map(|(role, path)| (role, path.as_path()))
            .collect()
    }

    /// Returns the block devices of the plan in role order, with their pure paths.
    fn pure_blocks(&self) -> Vec<(BlockRole, &PurePath)> {
        let mut blocks = vec![(BlockRole::Distro, &self.distro.path)];
        if let Some(scratch) = &self.upper.scratch {
            blocks.push((BlockRole::Scratch, scratch));
        }
        blocks
    }

    /// Returns the plan with another image, over the same upper and with the same settings.
    pub(crate) fn with_image(&self, image: RootImage) -> Self {
        Self {
            distro: SandboxDistro::at(self.distro.path.clone(), image),
            ..self.clone()
        }
    }

    /// Checks the plan against the host: each image of its block devices must be a regular file
    /// whose path has no comma or semicolon, and whose name, and that of the file to which its
    /// path resolves, as `provision` records it, do not end in `.vhd`, `.vhdx`, `.vmgs`, or
    /// `.iso`, with which OpenVMM would not attach it as a raw image; each share must pass
    /// [`SandboxMount::validated`], and their host paths [`mount::validate_mount_host_paths`].
    ///
    /// Fails with [`ErrorKind::Unavailable`](crate::ErrorKind::Unavailable) for a missing image, as
    /// `distro EROFS layer not found: PATH`, `distro GPT image not found: PATH`, or `ext4 scratch
    /// image not found: PATH`, and otherwise as those checks do.
    pub fn validated(&self) -> Result<()> {
        self.validated_with(&mount::HostQueries::native())
    }

    /// Implements [`validated`](Self::validated) with the given host queries.
    pub(crate) fn validated_with(&self, host: &mount::HostQueries<'_>) -> Result<()> {
        for (role, path) in self.pure_blocks() {
            let description = match role {
                BlockRole::Distro => self.distro.description(),
                BlockRole::Scratch => "ext4 scratch image",
            };
            require_pure_file(path, description)?;
            reject_disk_path(path)?;
            reject_container_path(path, path.as_str())?;
            // OpenVMM reads the extension of the path that it is given, which for a provisioned
            // sandbox is the resolved one: a link must not resolve to a container's name either.
            let resolved = (host.resolve)(path)
                .map_err(|error| mount::os_error(&error, Some(path.as_str())))?;
            if resolved.name() != path.name() {
                let shown = format!("{} resolves to {}", path.as_str(), resolved.as_str());
                reject_container_path(&resolved, &shown)?;
            }
        }
        for mount in &self.settings.mounts {
            mount.validated()?;
        }
        mount::validate_mount_host_paths_with(&self.settings.mounts, host)
    }

    /// Returns the OpenVMM arguments of the plan: the microVM machine, a sandbox block device for
    /// each block device of the plan in role order, `ROLE:file:PATH` with `,ro` for the read-only
    /// image, the workload identity, and the arguments that attach the shares.
    ///
    /// Fails as [`mount::mounts_openvmm_arguments`] does.
    pub fn openvmm_arguments(&self) -> Result<Vec<String>> {
        self.openvmm_arguments_with(&fs::cwd)
    }

    /// Implements [`openvmm_arguments`](Self::openvmm_arguments) with `cwd` as `Path.cwd()`.
    pub(crate) fn openvmm_arguments_with(
        &self,
        cwd: &dyn Fn() -> io::Result<PurePath>,
    ) -> Result<Vec<String>> {
        let mut arguments = vec!["--machine".to_owned(), "microvm".to_owned()];
        for (role, path) in self.pure_blocks() {
            let access = if role.is_read_only() { ",ro" } else { "" };
            arguments.push("--microvm-sandbox-block".to_owned());
            arguments.push(format!("{role}:file:{}{access}", path.as_str()));
        }
        let (uid, gid) = self.settings.workload_identity;
        arguments.extend([
            "--microvm-workload-identity".to_owned(),
            format!("{uid}:{gid}"),
        ]);
        arguments.extend(mount::mounts_openvmm_arguments_with(
            &self.settings.mounts,
            cwd,
        )?);
        Ok(arguments)
    }

    /// Returns the kernel command line of the plan: `user_command_line`, stripped of Python
    /// whitespace, then `nvx_sandbox=1`, the boot tokens of the root's image and upper,
    /// `nvx_entrypoint=`, `nvx_hostname=`, a `nvx_arg=` token for each argument,
    /// `nvx_memory_max=` and `nvx_pids_max=` when set, and the `nvx_share=` tokens of an
    /// aggregate.
    ///
    /// The user's command line may hold no NUL and no `nvx_*` or `virtfs_*` token, which the
    /// profile and OpenVMM own. The command line, the bootstrap tokens that OpenVMM appends for
    /// the shares, and a NUL must fit in [`SANDBOX_COMMAND_LINE_MAX_SIZE`] bytes. Fails with
    /// [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported).
    pub fn kernel_command_line(&self, user_command_line: &str) -> Result<String> {
        if user_command_line.contains('\0') {
            return Err(refused("kernel command line contains an embedded NUL"));
        }
        for token in split(user_command_line) {
            let name = token.split('=').next().unwrap_or(token);
            if token.starts_with("nvx_") {
                return Err(refused(format!("{name} is owned by the sandbox profile")));
            }
            if token.starts_with("virtfs_") {
                return Err(refused(format!(
                    "{name} is owned by the sandbox --mount option"
                )));
            }
        }
        let settings = &self.settings;
        let mut tokens = vec![
            strip(user_command_line).to_owned(),
            "nvx_sandbox=1".to_owned(),
        ];
        tokens.extend(self.layout().tokens());
        tokens.extend([
            format!("nvx_entrypoint={}", settings.entrypoint),
            format!("nvx_hostname={}", settings.hostname),
        ]);
        tokens.extend(
            settings
                .args
                .iter()
                .map(|argument| format!("nvx_arg={argument}")),
        );
        if let Some(memory_max) = &settings.memory_max {
            tokens.push(format!("nvx_memory_max={memory_max}"));
        }
        if let Some(pids_max) = &settings.pids_max {
            tokens.push(format!("nvx_pids_max={}", pids_max.plus_one()));
        }
        if mount::mounts_use_aggregate(&settings.mounts) {
            let shares: Vec<_> = settings
                .mounts
                .iter()
                .map(|mount| (mount.guest_target(), mount.access(), mount.kind()))
                .collect();
            tokens.extend(mount::aggregate_share_tokens(&shares));
        }
        tokens.retain(|token| !token.is_empty());
        let command_line = tokens.join(" ");
        // OpenVMM appends the shares' bootstrap tokens after this command line, so they consume
        // the same x86 budget.
        let fragment = mount::mounts_command_line_fragment(&settings.mounts);
        if command_line.len() + fragment.len() + 1 > SANDBOX_COMMAND_LINE_MAX_SIZE {
            return Err(refused(
                "sandbox kernel command line exceeds its 1024-byte x86 budget; attach fewer \
                 --mount shares or use shorter targets and arguments",
            ));
        }
        Ok(command_line)
    }
}

/// Returns the image that a distro binding records: the staged format, and the identity that the
/// guest expects of the layer.
///
/// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) for an identity that is
/// not a UUID in its canonical text.
pub(crate) fn bound_image(binding: &DistroBinding) -> Result<RootImage> {
    let identity = Uuid::parse(binding.identity()).ok_or_else(|| {
        refused(format!(
            "the distro binding names the identity {}, which is not a UUID in its canonical text",
            repr(binding.identity())
        ))
    })?;
    Ok(match binding.format() {
        DistroFormat::Erofs => RootImage::erofs(Some(identity)),
    })
}

#[cfg(test)]
mod tests;
