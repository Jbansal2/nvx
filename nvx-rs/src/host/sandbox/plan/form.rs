//! The serde form of a [`SandboxPlan`], in which callers persist plans, as the [plan
//! module](super) describes it.

use serde::{Deserialize, Serialize};

use super::{PLAN_VERSION, SandboxDistro, SandboxPlan, SandboxUpper};
use crate::host::python::builtins::{Int, repr};
use crate::host::sandbox::SandboxSettings;
use crate::host::sandbox::mount::{MountAccess, MountKind, MountOwner, MountPolicy, SandboxMount};
use crate::protocol::root::{ImageFormat, RootImage, Uuid};

/// The serde form of a [`SandboxPlan`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlanForm {
    /// [`PLAN_VERSION`].
    version: u32,
    /// The image.
    distro: DistroForm,
    /// The upper.
    upper: UpperForm,
    /// The launch settings.
    settings: SettingsForm,
}

/// The serde form of a [`SandboxDistro`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DistroForm {
    /// The image's path.
    path: String,
    /// The image's format.
    format: FormatForm,
    /// The canonical text of the identity that the guest expects of the image, or `None`, which
    /// the form requires as `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    identity: Option<String>,
}

/// The serde form of an [`ImageFormat`].
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FormatForm {
    /// [`ImageFormat::Erofs`].
    Erofs,
    /// [`ImageFormat::Gpt`].
    Gpt,
}

/// The serde form of a [`SandboxUpper`], tagged with its kind.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum UpperForm {
    /// An upper on a scratch image.
    Scratch {
        /// The scratch image's path.
        path: String,
    },
    /// An upper in RAM, which has no other field.
    Ram {},
}

/// The serde form of [`SandboxSettings`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsForm {
    /// The workload's program.
    entrypoint: String,
    /// The workload's arguments.
    args: Vec<String>,
    /// The workload's hostname.
    hostname: String,
    /// The workload's UID and GID.
    workload_identity: IdentityForm,
    /// The decimal text of the memory limit, or `None`, which the form requires as `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    memory_max: Option<String>,
    /// The decimal text of the process limit, or `None`, which the form requires as `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pids_max: Option<String>,
    /// The live shares, in child order.
    mounts: Vec<MountForm>,
}

/// The serde form of a workload identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityForm {
    /// The UID.
    uid: u32,
    /// The GID.
    gid: u32,
}

/// The serde form of a [`SandboxMount`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MountForm {
    /// The guest directory or file at which the share appears.
    guest_target: String,
    /// The host directory or file.
    host_path: String,
    /// The access mode: `ro` or `rw`.
    access: String,
    /// The access-policy paths.
    policy: PolicyForm,
    /// The identity of the share's file operations: `vmm` or `caller`.
    owner: String,
    /// What the share binds: `directory` or `file`.
    kind: String,
}

/// The serde form of a [`MountPolicy`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyForm {
    /// The denied paths.
    denied: Vec<String>,
    /// The allowed paths.
    allowed: Vec<String>,
    /// The writable paths.
    writable: Vec<String>,
}

impl From<SandboxPlan> for PlanForm {
    fn from(plan: SandboxPlan) -> Self {
        let SandboxPlan {
            distro,
            upper,
            settings,
        } = plan;
        let RootImage { format, identity } = distro.image;
        Self {
            version: PLAN_VERSION,
            distro: DistroForm {
                path: distro.path.as_str().to_owned(),
                format: match format {
                    ImageFormat::Erofs => FormatForm::Erofs,
                    ImageFormat::Gpt => FormatForm::Gpt,
                },
                identity: identity.map(|identity| identity.to_string()),
            },
            upper: match upper.scratch {
                Some(path) => UpperForm::Scratch {
                    path: path.as_str().to_owned(),
                },
                None => UpperForm::Ram {},
            },
            settings: SettingsForm::from(settings),
        }
    }
}

impl TryFrom<PlanForm> for SandboxPlan {
    type Error = String;

    /// Reads a plan, which must be of [`PLAN_VERSION`], hold an identity in its canonical text and
    /// limits in decimal text, and pass the checks of [`SandboxMount::new`] and
    /// [`SandboxPlan::new`].
    fn try_from(form: PlanForm) -> Result<Self, Self::Error> {
        if form.version != PLAN_VERSION {
            return Err(format!(
                "the sandbox plan has version {}, which this build does not read",
                form.version
            ));
        }
        let DistroForm {
            path,
            format,
            identity,
        } = form.distro;
        let identity = identity
            .map(|text| {
                Uuid::parse(&text).ok_or_else(|| {
                    format!(
                        "the distro identity of the sandbox plan, {}, is not a UUID in its \
                         canonical text",
                        repr(&text)
                    )
                })
            })
            .transpose()?;
        let format = match format {
            FormatForm::Erofs => ImageFormat::Erofs,
            FormatForm::Gpt => ImageFormat::Gpt,
        };
        let distro = SandboxDistro::new(&path, RootImage { format, identity });
        let upper = match form.upper {
            UpperForm::Scratch { path } => SandboxUpper::scratch(&path),
            UpperForm::Ram {} => SandboxUpper::RAM,
        };
        let settings = SandboxSettings::try_from(form.settings)?;
        Self::new(distro, upper, settings).map_err(|error| error.to_string())
    }
}

impl From<SandboxSettings> for SettingsForm {
    fn from(settings: SandboxSettings) -> Self {
        let (uid, gid) = settings.workload_identity;
        Self {
            entrypoint: settings.entrypoint,
            args: settings.args,
            hostname: settings.hostname,
            workload_identity: IdentityForm { uid, gid },
            memory_max: settings.memory_max.map(|limit| limit.to_string()),
            pids_max: settings.pids_max.map(|limit| limit.to_string()),
            mounts: settings.mounts.iter().map(MountForm::from).collect(),
        }
    }
}

impl TryFrom<SettingsForm> for SandboxSettings {
    type Error = String;

    /// Reads settings whose limits are positive integers in decimal text, without a sign or
    /// leading zeros, and whose shares pass the checks of [`SandboxMount::new`].
    fn try_from(form: SettingsForm) -> Result<Self, Self::Error> {
        let limit = |name: &str, text: Option<String>| {
            text.map(|text| {
                let decimal = !text.starts_with('0')
                    && !text.is_empty()
                    && text.bytes().all(|byte| byte.is_ascii_digit());
                decimal
                    .then(|| Int::parse(&text).ok())
                    .flatten()
                    .ok_or_else(|| {
                        format!(
                            "the {name} of the sandbox plan, {}, is not a positive integer in \
                             decimal text",
                            repr(&text)
                        )
                    })
            })
            .transpose()
        };
        let IdentityForm { uid, gid } = form.workload_identity;
        Ok(Self {
            entrypoint: form.entrypoint,
            args: form.args,
            hostname: form.hostname,
            workload_identity: (uid, gid),
            memory_max: limit("memoryMax", form.memory_max)?,
            pids_max: limit("pidsMax", form.pids_max)?,
            mounts: form
                .mounts
                .into_iter()
                .map(SandboxMount::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<&SandboxMount> for MountForm {
    fn from(mount: &SandboxMount) -> Self {
        let MountPolicy {
            denied,
            allowed,
            writable,
        } = mount.policy().clone();
        Self {
            guest_target: mount.guest_target().to_owned(),
            // A share's host path is text, which `pathlib` normalized.
            host_path: mount.host_path().to_string_lossy().into_owned(),
            access: mount.access().as_str().to_owned(),
            policy: PolicyForm {
                denied,
                allowed,
                writable,
            },
            owner: mount.owner().as_str().to_owned(),
            kind: mount.kind().as_str().to_owned(),
        }
    }
}

impl TryFrom<MountForm> for SandboxMount {
    type Error = String;

    /// Reads a share as [`SandboxMount::new`] checks it.
    fn try_from(form: MountForm) -> Result<Self, Self::Error> {
        let message = |error: crate::Error| error.to_string();
        let PolicyForm {
            denied,
            allowed,
            writable,
        } = form.policy;
        Self::new(
            &form.guest_target,
            &form.host_path,
            MountAccess::from_name(&form.access).map_err(message)?,
            MountPolicy {
                denied,
                allowed,
                writable,
            },
            MountOwner::from_name(&form.owner).map_err(message)?,
            MountKind::from_name(&form.kind).map_err(message)?,
        )
        .map_err(message)
    }
}
