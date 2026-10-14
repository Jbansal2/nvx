//! Opt-in image-backed launch planning, independent of request models and guest transports.
//!
//! A plan is not a runnable claim about an older VMM. A versioned adapter must lower the boot
//! and filesystem-slot intent and return observations of its actual opened attachments, bound
//! to the authenticated activation. Real handle handoff, lifetime pinning, slot omission and
//! template restore are VMM prerequisites; this module supplies their typed boundary.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::filesystem::{
    AuthorizedExports, ExportPlan, Exposure, GrantAccess, HostObject, ObjectKind, PathGrant,
    PathSemantics, ProtectedRoots,
};
use super::instance::ProcessIdentity;
use super::launch::{LaunchSpec, WorkloadIdentity};
use super::network::{self, NetworkPlan, ProxyService};
use super::process::LaunchLogClaim;
use crate::error::{Error, Result};
use crate::protocol::HostMap;
use crate::{Hypervisor, contract};

/// Version of the opt-in host/VMM attachment and topology adapter contract.
pub const ATTACHMENT_CONTRACT: u32 = 1;
/// Version of the new-profile record block; legacy instance records remain unchanged.
pub const IMAGE_RUNTIME_FORMAT: u32 = 1;

/// Explicit source-bound runtime pins, never discovered by probing a running guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePins {
    /// Caller-verified immutable bundle identity.
    pub bundle: String,
    /// OpenVMM machine/device ABI.
    pub microvm_abi: u64,
    /// Broker protocol.
    pub protocol: u64,
    /// Caller-supported guest/application ABI identity.
    pub guest_abi: String,
}

impl RuntimePins {
    /// Refuses unsupported broker/device pins and missing bundle/guest identities.
    pub fn check(&self) -> Result<()> {
        check_id(&self.bundle)?;
        check_id(&self.guest_abi)?;
        if self.microvm_abi != contract::MICROVM_ABI_VERSION
            || self.protocol != contract::CONTROL_SESSION_PROTOCOL_VERSION
        {
            return Err(Error::unavailable(
                "unsupported pinned runtime ABI/protocol",
            ));
        }
        Ok(())
    }
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Error::unsupported(
            "identity must be a nonempty ASCII label of at most 128 bytes",
        ));
    }
    Ok(())
}

/// Fixed cold-plug filesystem topology requested of the versioned VMM adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FilesystemSlot {
    /// Direct-image cold, zero exports, no reusable template: no filesystem device at all.
    Omit,
    /// Mapped cold or compatible template: retain the fixed aggregate/dormant slot.
    Retain,
}

/// Exact machine identity required when selecting a compatible template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentity {
    /// Selected hypervisor.
    pub hypervisor: Hypervisor,
    /// Fixed memory size.
    pub memory_mib: u32,
    /// Workload identity/account behavior.
    pub workload: WorkloadIdentity,
    /// Guest address and prefix.
    pub guest_network: String,
    /// NIC topology and enforcement, including any proxy endpoint.
    pub network: NetworkPlan,
    /// Cold-plug filesystem slot.
    pub filesystem_slot: FilesystemSlot,
}

/// Caller-verified template metadata; the core neither captures nor restores templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateIdentity {
    /// Immutable template identity.
    pub id: String,
    /// Exact runtime pins under which it was captured.
    pub pins: RuntimePins,
    /// Exact machine/device compatibility.
    pub machine: MachineIdentity,
}

/// Selected template file and its caller-verified identity.
#[derive(Debug, Clone)]
pub struct TemplateInput {
    /// Template file, under a protected root.
    pub path: PathBuf,
    /// Verified template metadata.
    pub identity: TemplateIdentity,
}

/// Image-backed cold versus explicitly compatible template input.
#[derive(Debug, Clone)]
pub enum BootInput {
    /// Direct cold launch, with one immutable image and one private writable scratch disk.
    DirectImage {
        /// Read-only image file.
        image: PathBuf,
        /// Writable scratch file.
        scratch: PathBuf,
    },
    /// Restore from a compatible template; never silently fall back to a cold boot.
    CompatibleTemplate {
        /// Read-only image file.
        image: PathBuf,
        /// Writable scratch file.
        scratch: PathBuf,
        /// Selected template and compatibility metadata.
        template: Box<TemplateInput>,
    },
}

/// Boot identity stored with a running activation, without an application endpoint or codec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum BootIdentity {
    /// Direct image cold.
    DirectImage,
    /// Compatible template restore.
    CompatibleTemplate {
        /// Immutable template identity.
        template: String,
    },
}

/// All caller-owned inputs to a new-profile plan.
#[derive(Debug, Clone)]
pub struct ActivationInput {
    /// Unique activation identity used by the authenticated Ready/receipt exchange.
    pub activation: String,
    /// Exact selected runtime.
    pub pins: RuntimePins,
    /// Reused machine inputs and ordinary network policy. Its filesystem must be unset.
    pub machine: LaunchSpec,
    /// Cold or template input.
    pub boot: BootInput,
    /// Mandatory canonical/pinned runtime/state/cache/image/template roots.
    pub protected: ProtectedRoots,
    /// Explicitly requested exports.
    pub exports: Vec<Exposure>,
    /// Hidden paths, lowered by the existing aggregate planner.
    pub denied: Vec<PathBuf>,
    /// Optional caller-approved HTTP(S) loopback service.
    pub proxy: Option<ProxyService>,
}

/// Caller-owned authorization boundary. Generic validation never grants host access.
pub trait Authorizer {
    /// Approves the selected object, access, and live-name/pinned-object semantics.
    fn path(&mut self, grant: &PathGrant) -> Result<()>;
    /// Approves this exact proxy service; the caller also owns its process/lifetime.
    fn proxy(&mut self, service: &ProxyService) -> Result<()>;
}

/// Stable role in the VMM attachment request/receipt, distinct from a guest bind instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentRole {
    /// Sole immutable image media.
    Image,
    /// Private writable scratch media.
    Scratch,
    /// Selected template state.
    Template,
    /// Aggregate child, in the existing planner's order.
    ExportChild(usize),
    /// Object selected by one mapping, including pinned paths inside a directory child.
    MappedObject(usize),
}

/// Block geometry validated without hashing media on start or exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskGeometry {
    /// Total byte length.
    pub bytes: u64,
    /// Logical sector size.
    pub sector_size: u32,
}

/// Authorized attachment intent for the VMM's actual open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRequest {
    /// Stable media/child/mapped-object role.
    pub role: AttachmentRole,
    /// Caller-approved selected object and access/path semantics.
    pub grant: PathGrant,
    /// Media geometry, or `None` for filesystem/template objects.
    pub geometry: Option<DiskGeometry>,
}

/// VMM observation, made from its attachment handle, not copied from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedAttachment {
    /// Stable attachment role.
    pub role: AttachmentRole,
    /// Access actually enforced by the VMM.
    pub access: GrantAccess,
    /// Actual opened handle observation.
    pub object: HostObject,
    /// Actual admitted block geometry.
    pub geometry: Option<DiskGeometry>,
}

/// Versioned VMM receipt bound by the caller's authenticated activation/Ready exchange.
///
/// A test adapter can simulate this seam, but cannot prove real VMM lifetime pinning or inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentReceipt {
    /// [`ATTACHMENT_CONTRACT`].
    pub contract: u32,
    /// Authenticated activation identity.
    pub activation: String,
    /// Exact bundle/protocol/guest ABI.
    pub pins: RuntimePins,
    /// Actual cold/template identity.
    pub boot: BootIdentity,
    /// Actual filesystem topology.
    pub filesystem_slot: FilesystemSlot,
    /// Exact aggregate policy the VMM admitted, not just guest mount instructions.
    pub filesystem: Option<ExportPlan>,
    /// Exact network enforcement and associated guest settings.
    pub network: NetworkPlan,
    /// One actual observation per requested role; missing/duplicate/unexpected roles fail.
    pub opened: Vec<OpenedAttachment>,
}

/// Adapter-specific CLI extension, acknowledging every required typed intent.
#[derive(Debug, Clone)]
pub struct AdapterArguments {
    /// [`ATTACHMENT_CONTRACT`], supported explicitly rather than probed.
    pub contract: u32,
    /// Boot intent that these arguments implement.
    pub boot: BootIdentity,
    /// Filesystem-slot intent that these arguments implement.
    pub filesystem_slot: FilesystemSlot,
    /// Image/template, pinned-handoff, and topology options of the reviewed VMM revision.
    pub arguments: Vec<OsString>,
}

/// A versioned adapter for the real VMM handoff, or an independent test-seam implementation.
///
/// There is intentionally no old-VMM/default implementation. Lowering must fail if it cannot
/// implement the boot, slot, or pinned-object contract, not silently omit a mount argument.
pub trait VmmAdapter {
    /// Lowers the image/template media, attachment grants and cold-plug topology.
    fn lower(&self, plan: &ActivationPlan) -> Result<AdapterArguments>;
}

/// Validated, caller-authorized plan; it has no registry, persistence path or guest transport.
#[derive(Debug, Clone)]
pub struct ActivationPlan {
    activation: String,
    pins: RuntimePins,
    machine: LaunchSpec,
    boot: BootIdentity,
    protected: ProtectedRoots,
    exports: AuthorizedExports,
    network: NetworkPlan,
    slot: FilesystemSlot,
    runtime: Vec<PathGrant>,
    attachments: Vec<AttachmentRequest>,
}

impl ActivationPlan {
    /// Validates and authorizes a complete plan while retaining existing filesystem/network lowering.
    pub fn new(input: ActivationInput, authorize: &mut impl Authorizer) -> Result<Self> {
        check_id(&input.activation)?;
        input.pins.check()?;
        input.machine.check()?;
        if input.machine.filesystem.is_some() {
            return Err(Error::unsupported(
                "new-profile exports must pass the explicit authorization boundary",
            ));
        }
        input.protected.recheck()?;
        let private = |path: &Path, access, authorize: &mut dyn Authorizer| {
            let grant = PathGrant::inspect(path, access, PathSemantics::ObjectPinned)?;
            if grant.object().kind() != ObjectKind::File {
                return Err(Error::unsupported(
                    "runtime and media inputs must be regular files",
                ));
            }
            input.protected.check_private(grant.object())?;
            authorize.path(&grant)?;
            Ok(grant)
        };
        let runtime = [
            &input.machine.openvmm,
            &input.machine.kernel,
            &input.machine.initrd,
        ]
        .into_iter()
        .map(|path| private(path, GrantAccess::ReadOnly, authorize))
        .collect::<Result<Vec<_>>>()?;
        let exports =
            AuthorizedExports::new(&input.exports, &input.denied, &input.protected, |grant| {
                authorize.path(grant)
            })?;
        if let Some(proxy) = &input.proxy {
            authorize.proxy(proxy)?;
        }
        let network = network::plan(
            input.machine.network.as_ref(),
            input.proxy.as_ref(),
            &input.machine.guest_network,
        )?;
        let slot =
            if exports.plan().is_none() && matches!(input.boot, BootInput::DirectImage { .. }) {
                FilesystemSlot::Omit
            } else {
                FilesystemSlot::Retain
            };
        let (image, scratch, template) = match &input.boot {
            BootInput::DirectImage { image, scratch } => (image, scratch, None),
            BootInput::CompatibleTemplate {
                image,
                scratch,
                template,
            } => (image, scratch, Some(template)),
        };
        let mut attachments = Vec::new();
        for (role, path, access) in [
            (AttachmentRole::Image, image, GrantAccess::ReadOnly),
            (AttachmentRole::Scratch, scratch, GrantAccess::ReadWrite),
        ] {
            let grant = private(path, access, authorize)?;
            let bytes = grant.object().length();
            if bytes == 0 || bytes % 512 != 0 {
                return Err(Error::unsupported(
                    "image and scratch media must have a positive 512-byte-aligned length",
                ));
            }
            attachments.push(AttachmentRequest {
                role,
                grant,
                geometry: Some(DiskGeometry {
                    bytes,
                    sector_size: 512,
                }),
            });
        }
        if attachments[0].grant.object().identity() == attachments[1].grant.object().identity() {
            return Err(Error::unsupported(
                "image and scratch must be different objects",
            ));
        }
        let boot = if let Some(template) = template {
            check_id(&template.identity.id)?;
            let machine = MachineIdentity {
                hypervisor: input.machine.hypervisor,
                memory_mib: input.machine.memory_mib,
                workload: input.machine.identity,
                guest_network: input.machine.guest_network.clone(),
                network: network.clone(),
                filesystem_slot: slot,
            };
            if template.identity.pins != input.pins || template.identity.machine != machine {
                return Err(Error::unavailable(
                    "template does not match the pinned runtime and fixed machine topology",
                ));
            }
            let grant = private(&template.path, GrantAccess::ReadOnly, authorize)?;
            attachments.push(AttachmentRequest {
                role: AttachmentRole::Template,
                grant,
                geometry: None,
            });
            BootIdentity::CompatibleTemplate {
                template: template.identity.id.clone(),
            }
        } else {
            BootIdentity::DirectImage
        };
        for (index, grant) in exports.children().iter().enumerate() {
            attachments.push(AttachmentRequest {
                role: AttachmentRole::ExportChild(index),
                grant: grant.clone(),
                geometry: None,
            });
        }
        for (index, grant) in exports.mappings().iter().enumerate() {
            attachments.push(AttachmentRequest {
                role: AttachmentRole::MappedObject(index),
                grant: grant.clone(),
                geometry: None,
            });
        }
        let mut machine = input.machine;
        machine.openvmm = runtime[0].object().path().to_path_buf();
        machine.kernel = runtime[1].object().path().to_path_buf();
        machine.initrd = runtime[2].object().path().to_path_buf();
        machine.filesystem = exports.plan().cloned();
        let plan = Self {
            activation: input.activation,
            pins: input.pins,
            machine,
            boot,
            protected: input.protected,
            exports,
            network,
            slot,
            runtime,
            attachments,
        };
        plan.recheck()?;
        Ok(plan)
    }

    /// Returns the unique activation identity.
    pub fn activation(&self) -> &str {
        &self.activation
    }
    /// Returns exact runtime pins.
    pub fn pins(&self) -> &RuntimePins {
        &self.pins
    }
    /// Returns the caller-selected, canonical executable path.
    pub fn executable(&self) -> &Path {
        &self.machine.openvmm
    }
    /// Returns the caller's Windows process-job policy.
    pub fn breakaway_from_job(&self) -> bool {
        self.machine.breakaway_from_job
    }
    /// Returns direct cold or compatible template identity.
    pub fn boot(&self) -> &BootIdentity {
        &self.boot
    }
    /// Returns the required filesystem-device topology, not an observed inventory.
    pub fn filesystem_slot(&self) -> FilesystemSlot {
        self.slot
    }
    /// Returns the aggregate enforcement plan.
    pub fn filesystem(&self) -> Option<&ExportPlan> {
        self.exports.plan()
    }
    /// Returns the guest's ordered HostMap table.
    pub fn guest_table(&self) -> Vec<HostMap> {
        self.filesystem()
            .map_or_else(Vec::new, ExportPlan::guest_table)
    }
    /// Returns the exact network options and typed guest settings.
    pub fn network(&self) -> &NetworkPlan {
        &self.network
    }
    /// Returns every role the VMM must receipt from its actual opened objects.
    pub fn attachments(&self) -> &[AttachmentRequest] {
        &self.attachments
    }
    /// Returns the mandatory root constraints the adapter must hand to the VMM.
    pub fn protected_roots(&self) -> &ProtectedRoots {
        &self.protected
    }
    /// Returns internal runtime/media grants whose identities must not be exported through aliases.
    pub fn protected_objects(&self) -> impl Iterator<Item = &PathGrant> {
        self.runtime.iter().chain(
            self.attachments
                .iter()
                .filter(|attachment| {
                    matches!(
                        attachment.role,
                        AttachmentRole::Image | AttachmentRole::Scratch | AttachmentRole::Template
                    )
                })
                .map(|attachment| &attachment.grant),
        )
    }

    /// Rechecks protected roots and authorized objects at start/restore without hashing.
    pub fn recheck(&self) -> Result<()> {
        self.exports.recheck(&self.protected)?;
        for grant in &self.runtime {
            self.protected.check_private(&grant.recheck()?)?;
        }
        for attachment in &self.attachments {
            let opened = attachment.grant.recheck()?;
            if let Some(geometry) = attachment.geometry
                && opened.length() != geometry.bytes
            {
                return Err(Error::unsupported(
                    "media geometry changed before start/restore",
                ));
            }
            self.check_attachment_roots(attachment.role, &opened)?;
        }
        Ok(())
    }

    fn check_attachment_roots(&self, role: AttachmentRole, object: &HostObject) -> Result<()> {
        match role {
            AttachmentRole::ExportChild(_) | AttachmentRole::MappedObject(_) => {
                self.protected.check_export(object)?;
                if self
                    .protected_objects()
                    .any(|private| private.object().identity() == object.identity())
                {
                    return Err(Error::unsupported(
                        "opened export aliases protected runtime/media",
                    ));
                }
                Ok(())
            }
            _ => self.protected.check_private(object),
        }
    }

    /// Builds complete arguments only with an adapter explicitly implementing the typed intent.
    ///
    /// No adapter is shipped for the old VMM. Its absent `--mount` is not a no-filesystem-device
    /// option. Template/receipt handoff arguments belong to the reviewed VMM adapter, not a
    /// duplicate EROFS/scratch CLI or a speculative restore implementation here.
    pub fn openvmm_arguments(
        &self,
        endpoint: &str,
        report: &Path,
        adapter: &impl VmmAdapter,
    ) -> Result<Vec<OsString>> {
        self.recheck()?;
        let extension = adapter.lower(self)?;
        if extension.contract != ATTACHMENT_CONTRACT
            || extension.boot != self.boot
            || extension.filesystem_slot != self.slot
        {
            return Err(Error::unavailable(
                "VMM adapter cannot implement the requested boot/attachment topology",
            ));
        }
        let mut machine = self.machine.clone();
        machine.network = None;
        let mut arguments = machine.openvmm_arguments(endpoint, report)?;
        arguments.extend(self.network.openvmm_arguments().iter().map(OsString::from));
        arguments.extend(extension.arguments);
        machine.fit_process_command_line(&arguments, 0)?;
        Ok(arguments)
    }

    /// Admits a receipt only after checking its binding, exact enforcement, and all opened roles.
    ///
    /// The caller authenticates the receipt/Ready identity and tears down the verified process
    /// on failure. This function neither talks to the VMM nor silently cold-boots after failure.
    pub fn verify_receipt(&self, receipt: &AttachmentReceipt) -> Result<VerifiedAttachments> {
        self.protected.recheck()?;
        if receipt.contract != ATTACHMENT_CONTRACT
            || receipt.activation != self.activation
            || receipt.pins != self.pins
            || receipt.boot != self.boot
            || receipt.filesystem_slot != self.slot
            || receipt.filesystem.as_ref() != self.filesystem()
            || receipt.network != self.network
            || receipt.opened.len() != self.attachments.len()
        {
            return Err(Error::unsupported(
                "VMM receipt does not match the activation and enforcement plan",
            ));
        }
        for requested in &self.attachments {
            let mut opened = receipt
                .opened
                .iter()
                .filter(|opened| opened.role == requested.role);
            let observed = opened
                .next()
                .ok_or_else(|| Error::unsupported("VMM receipt is missing an attachment role"))?;
            if opened.next().is_some() {
                return Err(Error::unsupported(
                    "VMM receipt duplicates an attachment role",
                ));
            }
            requested
                .grant
                .check_opened(&observed.object, observed.access)?;
            if observed.geometry != requested.geometry
                || requested
                    .geometry
                    .is_some_and(|geometry| geometry.bytes != observed.object.length())
            {
                return Err(Error::unsupported(
                    "VMM opened media geometry differs from its grant",
                ));
            }
            self.check_attachment_roots(requested.role, &observed.object)?;
        }
        Ok(VerifiedAttachments {
            binding: self.binding(),
        })
    }

    fn binding(&self) -> PlanBinding {
        PlanBinding {
            activation: self.activation.clone(),
            pins: self.pins.clone(),
            boot: self.boot.clone(),
            slot: self.slot,
            filesystem: self.filesystem().cloned(),
            network: self.network.clone(),
            attachments: self.attachments.clone(),
        }
    }

    /// Creates a new-profile record block only for this plan's admitted receipt and log claim.
    ///
    /// The caller embeds/persists it in its own codec; legacy `RuntimeRecord` stays format 3.
    pub fn runtime_record(
        &self,
        verified: &VerifiedAttachments,
        log: LaunchLogClaim,
    ) -> Result<ImageRuntimeRecord> {
        if verified.binding != self.binding() || log.launch_id != self.activation {
            return Err(Error::unsupported(
                "receipt/log claim belongs to another activation plan",
            ));
        }
        self.protected
            .check_private(&HostObject::inspect(&log.path)?)?;
        log.verify()
            .map_err(|error| Error::io("cannot claim the activation log").with_source(error))?;
        Ok(ImageRuntimeRecord {
            format: IMAGE_RUNTIME_FORMAT,
            activation: self.activation.clone(),
            pins: self.pins.clone(),
            boot: self.boot.clone(),
            filesystem_slot: self.slot,
            process: log.process.clone(),
            log,
        })
    }

    /// Rejects old/unsupported/mismatched running records before selecting any guest protocol.
    pub fn check_runtime_record(&self, record: &ImageRuntimeRecord) -> Result<()> {
        if record.format != IMAGE_RUNTIME_FORMAT
            || record.activation != self.activation
            || record.pins != self.pins
            || record.boot != self.boot
            || record.filesystem_slot != self.slot
            || record.log.launch_id != record.activation
            || record.log.process != record.process
        {
            return Err(Error::unavailable(
                "running activation does not match its pinned profile; no protocol is guessed",
            ));
        }
        record.pins.check()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanBinding {
    activation: String,
    pins: RuntimePins,
    boot: BootIdentity,
    slot: FilesystemSlot,
    filesystem: Option<ExportPlan>,
    network: NetworkPlan,
    attachments: Vec<AttachmentRequest>,
}

/// Admission token created only by [`ActivationPlan::verify_receipt`].
#[derive(Debug, Clone)]
pub struct VerifiedAttachments {
    binding: PlanBinding,
}

/// Versioned opt-in record block. The caller owns its storage, endpoints and outer state format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRuntimeRecord {
    /// [`IMAGE_RUNTIME_FORMAT`].
    pub format: u32,
    /// Unique activation identity.
    pub activation: String,
    /// Exact bundle/protocol/guest ABI.
    pub pins: RuntimePins,
    /// Cold or selected compatible-template identity.
    pub boot: BootIdentity,
    /// Fixed filesystem topology.
    pub filesystem_slot: FilesystemSlot,
    /// Recorded PID/start-time identity.
    pub process: ProcessIdentity,
    /// Verified launch-log ownership.
    pub log: LaunchLogClaim,
}
