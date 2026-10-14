//! Host-only planning and OS supervision. All VMM receipts/topology options here are simulated;
//! no test proves an image guest boot, real VMM opened-handle pinning, or device inventory.
#![cfg(all(feature = "host", any(target_os = "linux", windows)))]

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nvx::host::activation::*;
use nvx::host::filesystem::{
    Exposure, FileIdentity, GrantAccess, HostObject, PathGrant, PathSemantics, ProtectedRootPaths,
    ProtectedRoots,
};
use nvx::host::instance::{self, ProcessIdentity, ProcessState, Supervisor};
use nvx::host::launch::{LaunchSpec, WorkloadIdentity};
use nvx::host::network::{
    self, Access, EgressRule, ForwardProtocol, LoopbackForward, NetworkPolicy, ProxyService,
};
use nvx::host::{platform, process};
use nvx::{Artifacts, Error, ErrorKind, Hypervisor, Result, contract};
use serde::Deserialize;

struct Fixture {
    _directory: tempfile::TempDir,
    base: PathBuf,
    input: ActivationInput,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().to_path_buf();
        for name in [
            "runtime",
            "state",
            "cache",
            "images",
            "templates",
            "share/ro/private",
            "share/rw",
            "other",
        ] {
            fs::create_dir_all(base.join(name)).unwrap();
        }
        for name in [
            "runtime/openvmm",
            "runtime/vmlinux",
            "runtime/initrd",
            "templates/seed",
            "share/config",
        ] {
            fs::write(base.join(name), b"fixture").unwrap();
        }
        for name in ["images/image", "state/scratch"] {
            fs::write(base.join(name), [0; 1024]).unwrap();
        }
        let machine = LaunchSpec::new(
            Artifacts::new(
                base.join("runtime/openvmm"),
                base.join("runtime/vmlinux"),
                base.join("runtime/initrd"),
            ),
            Hypervisor::platform_default().unwrap(),
        );
        let input = ActivationInput {
            activation: "activation-1".to_owned(),
            pins: RuntimePins {
                bundle: "bundle-1".to_owned(),
                microvm_abi: contract::MICROVM_ABI_VERSION,
                protocol: contract::CONTROL_SESSION_PROTOCOL_VERSION,
                guest_abi: "image-guest-1".to_owned(),
            },
            machine,
            boot: BootInput::DirectImage {
                image: base.join("images/image"),
                scratch: base.join("state/scratch"),
            },
            protected: ProtectedRoots::new(&ProtectedRootPaths {
                runtime: base.join("runtime"),
                state: base.join("state"),
                cache: base.join("cache"),
                images: base.join("images"),
                templates: base.join("templates"),
            })
            .unwrap(),
            exports: Vec::new(),
            denied: Vec::new(),
            proxy: None,
        };
        Self {
            _directory: directory,
            base,
            input,
        }
    }

    fn exposure(&self, path: &str, access: GrantAccess, semantics: PathSemantics) -> Exposure {
        Exposure {
            path: self.base.join(path),
            access,
            semantics,
        }
    }

    fn plan(&self) -> ActivationPlan {
        let mut authorize = Approved::new(&self.input);
        ActivationPlan::new(self.input.clone(), &mut authorize).unwrap()
    }

    fn use_template(&mut self) {
        let identity = TemplateIdentity {
            id: "template-1".to_owned(),
            pins: self.input.pins.clone(),
            machine: MachineIdentity {
                hypervisor: self.input.machine.hypervisor,
                memory_mib: self.input.machine.memory_mib,
                workload: self.input.machine.identity,
                guest_network: self.input.machine.guest_network.clone(),
                network: network::plan(
                    self.input.machine.network.as_ref(),
                    self.input.proxy.as_ref(),
                    &self.input.machine.guest_network,
                )
                .unwrap(),
                filesystem_slot: FilesystemSlot::Retain,
            },
        };
        self.input.boot = BootInput::CompatibleTemplate {
            image: self.base.join("images/image"),
            scratch: self.base.join("state/scratch"),
            template: Box::new(TemplateInput {
                path: self.base.join("templates/seed"),
                identity,
            }),
        };
    }
}

struct Approved {
    paths: Vec<(FileIdentity, GrantAccess, PathSemantics)>,
    proxy: Option<ProxyService>,
}

impl Approved {
    fn new(input: &ActivationInput) -> Self {
        let mut paths = [
            &input.machine.openvmm,
            &input.machine.kernel,
            &input.machine.initrd,
        ]
        .into_iter()
        .map(|path| {
            (
                path.clone(),
                GrantAccess::ReadOnly,
                PathSemantics::ObjectPinned,
            )
        })
        .collect::<Vec<_>>();
        let (image, scratch, template) = match &input.boot {
            BootInput::DirectImage { image, scratch } => (image, scratch, None),
            BootInput::CompatibleTemplate {
                image,
                scratch,
                template,
            } => (image, scratch, Some(&template.path)),
        };
        paths.extend([
            (
                image.clone(),
                GrantAccess::ReadOnly,
                PathSemantics::ObjectPinned,
            ),
            (
                scratch.clone(),
                GrantAccess::ReadWrite,
                PathSemantics::ObjectPinned,
            ),
        ]);
        if let Some(path) = template {
            paths.push((
                path.clone(),
                GrantAccess::ReadOnly,
                PathSemantics::ObjectPinned,
            ));
        }
        paths.extend(
            input
                .exports
                .iter()
                .map(|export| (export.path.clone(), export.access, export.semantics)),
        );
        Self {
            paths: paths
                .into_iter()
                .map(|(path, access, semantics)| {
                    (
                        HostObject::inspect(&path).unwrap().identity(),
                        access,
                        semantics,
                    )
                })
                .collect(),
            proxy: input.proxy,
        }
    }
}

impl Authorizer for Approved {
    fn path(&mut self, grant: &PathGrant) -> Result<()> {
        if self
            .paths
            .contains(&(grant.object().identity(), grant.access(), grant.semantics()))
        {
            Ok(())
        } else {
            Err(Error::unsupported(
                "test caller did not authorize this object/access/semantics",
            ))
        }
    }

    fn proxy(&mut self, service: &ProxyService) -> Result<()> {
        if self.proxy == Some(*service) {
            Ok(())
        } else {
            Err(Error::unsupported(
                "test caller did not authorize this proxy service",
            ))
        }
    }
}

struct SimulatedVmm;

impl VmmAdapter for SimulatedVmm {
    fn lower(&self, plan: &ActivationPlan) -> Result<AdapterArguments> {
        assert_eq!(plan.protected_roots().objects().len(), 5);
        assert!(
            plan.protected_objects()
                .all(|grant| grant.semantics() == PathSemantics::ObjectPinned)
        );
        let mut arguments = vec![
            "--simulated-filesystem-slot".into(),
            match plan.filesystem_slot() {
                FilesystemSlot::Omit => "omit",
                FilesystemSlot::Retain => "retain",
            }
            .into(),
        ];
        for attachment in plan.attachments() {
            arguments.push("--simulated-open".into());
            arguments.push(
                format!(
                    "{:?}:{}",
                    attachment.role,
                    attachment.grant.object().path().display()
                )
                .into(),
            );
        }
        Ok(AdapterArguments {
            contract: ATTACHMENT_CONTRACT,
            boot: plan.boot().clone(),
            filesystem_slot: plan.filesystem_slot(),
            arguments,
        })
    }
}

fn simulated_open(plan: &ActivationPlan) -> AttachmentReceipt {
    let opened: Vec<_> = plan
        .attachments()
        .iter()
        .map(|attachment| {
            // Independent open after authorization; never manufacture the observation from the expected ID.
            let path = attachment.grant.object().path();
            let file = platform::open_host_object(path).unwrap();
            OpenedAttachment {
                role: attachment.role,
                access: attachment.grant.access(),
                object: HostObject::from_opened(&file, path).unwrap(),
                geometry: attachment.geometry,
            }
        })
        .collect();
    let mut filesystem = plan.filesystem().cloned();
    if let Some(filesystem) = &mut filesystem {
        for (index, bind) in filesystem.binds.iter_mut().enumerate() {
            if bind.identity.is_some() {
                bind.identity = Some(
                    opened
                        .iter()
                        .find(|attachment| attachment.role == AttachmentRole::MappedObject(index))
                        .unwrap()
                        .object
                        .identity(),
                );
            }
        }
        for child in &mut filesystem.children {
            for (path, expected) in child.denied.iter().zip(&mut child.denied_identities) {
                if expected.is_some() {
                    *expected = Some(HostObject::inspect(path).unwrap().identity());
                }
            }
        }
    }
    AttachmentReceipt {
        contract: ATTACHMENT_CONTRACT,
        activation: plan.activation().to_owned(),
        pins: plan.pins().clone(),
        boot: plan.boot().clone(),
        filesystem_slot: plan.filesystem_slot(),
        filesystem,
        network: plan.network().clone(),
        opened,
    }
}

fn pair(arguments: &[OsString], name: &str, value: &str) -> bool {
    arguments
        .windows(2)
        .any(|pair| pair[0] == name && pair[1] == value)
}

#[test]
fn direct_zero_export_golden_selects_typed_slot_omission_and_no_nic() {
    let mut fixture = Fixture::new();
    fixture.input.machine.network = Some(NetworkPolicy::new(Access::Deny));
    let plan = fixture.plan();
    assert_eq!(plan.filesystem_slot(), FilesystemSlot::Omit);
    assert_eq!(plan.attachments().len(), 2);
    assert!(plan.guest_table().is_empty());
    assert!(plan.network().openvmm_arguments().is_empty());
    let arguments = plan
        .openvmm_arguments("test-endpoint", Path::new("outcome.json"), &SimulatedVmm)
        .unwrap();
    let expected: Vec<OsString> = vec![
        "--machine".into(),
        "microvm".into(),
        "--microvm-workload-identity".into(),
        "65534:65534".into(),
        "--microvm-lifecycle".into(),
        "managed".into(),
        "--single-process".into(),
        "--hypervisor".into(),
        fixture.input.machine.hypervisor.as_str().into(),
        "--memory".into(),
        "256M".into(),
        "--kernel".into(),
        HostObject::inspect(&fixture.input.machine.kernel)
            .unwrap()
            .path()
            .into(),
        "--initrd".into(),
        HostObject::inspect(&fixture.input.machine.initrd)
            .unwrap()
            .path()
            .into(),
        "--cmdline".into(),
        "hostname=nvx-sandbox".into(),
        "--virtio-console".into(),
        "none".into(),
        "--microvm-control-console".into(),
        "listen=test-endpoint".into(),
        "--microvm-control-auth-stdin".into(),
        "--microvm-report".into(),
        "outcome.json".into(),
        "--simulated-filesystem-slot".into(),
        "omit".into(),
        "--simulated-open".into(),
        format!(
            "Image:{}",
            plan.attachments()[0].grant.object().path().display()
        )
        .into(),
        "--simulated-open".into(),
        format!(
            "Scratch:{}",
            plan.attachments()[1].grant.object().path().display()
        )
        .into(),
    ];
    assert_eq!(arguments, expected);
    assert!(
        !arguments
            .iter()
            .any(|argument| argument == "--net" || argument == "--mount-aggregate")
    );
}

#[test]
fn old_or_mismatched_adapter_cannot_silently_drop_required_topology() {
    struct WrongSlot;
    impl VmmAdapter for WrongSlot {
        fn lower(&self, plan: &ActivationPlan) -> Result<AdapterArguments> {
            let mut result = SimulatedVmm.lower(plan)?;
            result.filesystem_slot = FilesystemSlot::Retain;
            Ok(result)
        }
    }
    struct OldVmm;
    impl VmmAdapter for OldVmm {
        fn lower(&self, _: &ActivationPlan) -> Result<AdapterArguments> {
            Err(Error::unavailable(
                "selected VMM has no versioned attachment/slot contract",
            ))
        }
    }
    let fixture = Fixture::new();
    let plan = fixture.plan();
    for error in [
        plan.openvmm_arguments("endpoint", Path::new("report"), &WrongSlot)
            .unwrap_err(),
        plan.openvmm_arguments("endpoint", Path::new("report"), &OldVmm)
            .unwrap_err(),
    ] {
        assert_eq!(error.kind(), ErrorKind::Unavailable);
    }
}

#[test]
fn ro_rw_file_and_denied_exports_reuse_aggregate_and_ordered_guest_table() {
    let mut fixture = Fixture::new();
    fixture.input.exports = vec![
        fixture.exposure(
            "share/rw",
            GrantAccess::ReadWrite,
            PathSemantics::ObjectPinned,
        ),
        fixture.exposure("share/ro", GrantAccess::ReadOnly, PathSemantics::LivePath),
        fixture.exposure(
            "share/config",
            GrantAccess::ReadOnly,
            PathSemantics::ObjectPinned,
        ),
    ];
    fixture.input.denied = vec![fixture.base.join("share/ro/private")];
    let plan = fixture.plan();
    let exports = plan.filesystem().unwrap();
    assert_eq!(plan.filesystem_slot(), FilesystemSlot::Retain);
    assert_eq!(exports.children.len(), 3);
    assert!(
        exports
            .children
            .iter()
            .any(|child| child.file && !child.writable)
    );
    assert!(exports.children.iter().any(|child| child.writable));
    assert_eq!(
        exports
            .children
            .iter()
            .map(|child| child.denied.len())
            .sum::<usize>(),
        1
    );
    assert_eq!(plan.guest_table(), exports.guest_table());
    assert!(
        plan.guest_table()
            .windows(2)
            .all(|pair| pair[0].target <= pair[1].target)
    );
    let arguments = plan
        .openvmm_arguments("endpoint", Path::new("report"), &SimulatedVmm)
        .unwrap();
    assert!(pair(
        &arguments,
        "--mount-aggregate",
        nvx::host::filesystem::GUEST_EXPORT
    ));
    assert!(pair(&arguments, "--simulated-filesystem-slot", "retain"));
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
}

#[test]
fn cross_volume_ro_rw_files_and_denied_paths_remain_independent_children() {
    let Some(volume) = std::env::var_os("NVX_TEST_SECOND_VOLUME") else {
        eprintln!("cross-volume gate not executed: set NVX_TEST_SECOND_VOLUME to another volume");
        return;
    };
    let mut fixture = Fixture::new();
    let other = tempfile::tempdir_in(volume).unwrap();
    assert_ne!(
        HostObject::inspect(&fixture.base)
            .unwrap()
            .identity()
            .device,
        HostObject::inspect(other.path()).unwrap().identity().device,
        "test requires two actual volumes"
    );
    fs::create_dir(other.path().join("rw")).unwrap();
    fs::write(other.path().join("rw/denied"), b"private").unwrap();
    fs::write(other.path().join("file"), b"file").unwrap();
    fixture.input.exports = vec![
        fixture.exposure(
            "share/ro",
            GrantAccess::ReadOnly,
            PathSemantics::ObjectPinned,
        ),
        Exposure {
            path: other.path().join("rw"),
            access: GrantAccess::ReadWrite,
            semantics: PathSemantics::ObjectPinned,
        },
        Exposure {
            path: other.path().join("file"),
            access: GrantAccess::ReadOnly,
            semantics: PathSemantics::LivePath,
        },
    ];
    fixture.input.denied = vec![other.path().join("rw/denied")];
    let plan = fixture.plan();
    assert_eq!(plan.filesystem().unwrap().children.len(), 3);
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
}

#[test]
fn protected_root_overlap_is_rejected_even_with_denied_private_children() {
    for path in [
        "runtime",
        "state",
        "cache",
        "images",
        "templates",
        "runtime/vmlinux",
        ".",
    ] {
        let mut fixture = Fixture::new();
        fixture.input.exports =
            vec![fixture.exposure(path, GrantAccess::ReadOnly, PathSemantics::LivePath)];
        fixture.input.denied = vec![fixture.base.join("state")];
        let mut authorize = Approved::new(&fixture.input);
        let error = ActivationPlan::new(fixture.input, &mut authorize).unwrap_err();
        assert!(
            error.message().contains("protected root"),
            "{path}: {error}"
        );
    }
    let mut fixture = Fixture::new();
    fs::hard_link(
        fixture.base.join("images/image"),
        fixture.base.join("share/image-alias"),
    )
    .unwrap();
    fixture.input.exports = vec![fixture.exposure(
        "share/image-alias",
        GrantAccess::ReadOnly,
        PathSemantics::LivePath,
    )];
    let mut authorize = Approved::new(&fixture.input);
    assert!(
        ActivationPlan::new(fixture.input, &mut authorize)
            .unwrap_err()
            .message()
            .contains("aliases")
    );
}

#[test]
fn authorization_is_explicit_for_paths_and_proxy_services() {
    let fixture = Fixture::new();
    let mut denied = Approved::new(&fixture.input);
    denied.paths.clear();
    assert!(ActivationPlan::new(fixture.input.clone(), &mut denied).is_err());
    let mut input = fixture.input;
    input.machine.network = Some(NetworkPolicy::new(Access::Deny));
    input.proxy = Some(ProxyService::from_url("http://127.0.0.1:3128").unwrap());
    let mut denied = Approved::new(&input);
    denied.proxy = None;
    assert!(
        ActivationPlan::new(input, &mut denied)
            .unwrap_err()
            .message()
            .contains("authorize")
    );
}

#[test]
fn readonly_enforcement_cannot_be_delegated_only_to_guest_binds() {
    let mut fixture = Fixture::new();
    fixture.input.exports = vec![
        fixture.exposure("share", GrantAccess::ReadWrite, PathSemantics::ObjectPinned),
        fixture.exposure(
            "share/ro",
            GrantAccess::ReadOnly,
            PathSemantics::ObjectPinned,
        ),
    ];
    let mut authorize = Approved::new(&fixture.input);
    assert!(ActivationPlan::new(fixture.input, &mut authorize).is_err());
}

#[test]
fn readonly_parent_with_writable_exception_keeps_exact_vmm_write_policy() {
    let mut fixture = Fixture::new();
    fixture.input.exports = vec![
        fixture.exposure("share", GrantAccess::ReadOnly, PathSemantics::ObjectPinned),
        fixture.exposure(
            "share/rw",
            GrantAccess::ReadWrite,
            PathSemantics::ObjectPinned,
        ),
    ];
    let plan = fixture.plan();
    assert_eq!(plan.filesystem().unwrap().children[0].write.len(), 1);
    assert!(plan.guest_table()[0].read_only);
    assert!(!plan.guest_table()[1].read_only);
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
}

#[test]
fn changed_objects_between_authorization_and_simulated_vmm_open_fail_pinned_grants() {
    for (use_template, name) in [
        (false, "images/image"),
        (false, "state/scratch"),
        (false, "share/config"),
        (false, "share/ro"),
        (true, "images/image"),
        (true, "state/scratch"),
        (true, "templates/seed"),
        (true, "share/config"),
        (true, "share/ro"),
    ] {
        let mut fixture = Fixture::new();
        if use_template {
            fixture.use_template();
        }
        fixture.input.exports = vec![
            fixture.exposure(
                "share/config",
                GrantAccess::ReadOnly,
                PathSemantics::ObjectPinned,
            ),
            fixture.exposure(
                "share/ro",
                GrantAccess::ReadOnly,
                PathSemantics::ObjectPinned,
            ),
        ];
        let plan = fixture.plan();
        plan.recheck().unwrap();
        let path = fixture.base.join(name);
        fs::rename(&path, path.with_extension("approved")).unwrap();
        if name == "share/ro" {
            fs::create_dir(&path).unwrap();
        } else {
            fs::write(&path, [1; 1024]).unwrap();
        }
        let receipt = simulated_open(&plan);
        assert!(
            plan.verify_receipt(&receipt).is_err(),
            "{name} replacement reached admission"
        );
        assert!(plan.recheck().is_err());
    }
}

#[test]
fn moved_denied_objects_are_rechecked_and_independently_observed_in_policy_receipts() {
    let mut fixture = Fixture::new();
    let denied = fixture.base.join("share/rw/denied");
    fs::write(&denied, b"private").unwrap();
    fixture.input.exports = vec![fixture.exposure(
        "share/rw",
        GrantAccess::ReadWrite,
        PathSemantics::ObjectPinned,
    )];
    fixture.input.denied = vec![denied.clone()];
    let plan = fixture.plan();
    plan.recheck().unwrap();
    fs::rename(&denied, denied.with_extension("moved")).unwrap();
    fs::write(&denied, b"decoy").unwrap();
    assert!(plan.recheck().is_err());
    assert!(plan.verify_receipt(&simulated_open(&plan)).is_err());
}

#[test]
fn explicit_live_file_grant_accepts_name_replacement_but_not_a_kind_change() {
    let mut fixture = Fixture::new();
    fixture.input.exports = vec![fixture.exposure(
        "share/config",
        GrantAccess::ReadOnly,
        PathSemantics::LivePath,
    )];
    let plan = fixture.plan();
    let path = fixture.base.join("share/config");
    fs::rename(&path, path.with_extension("old")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    plan.recheck().unwrap();
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(plan.verify_receipt(&simulated_open(&plan)).is_err());
}

#[test]
fn explicit_live_nested_rw_mapping_is_not_silently_pinned_by_legacy_checks() {
    let mut fixture = Fixture::new();
    fixture.input.exports = vec![
        fixture.exposure("share", GrantAccess::ReadWrite, PathSemantics::ObjectPinned),
        fixture.exposure(
            "share/config",
            GrantAccess::ReadWrite,
            PathSemantics::LivePath,
        ),
    ];
    let plan = fixture.plan();
    let bindings = &plan.filesystem().unwrap().binds;
    assert!(bindings[0].identity.is_some());
    assert!(bindings[1].identity.is_none());
    let path = fixture.base.join("share/config");
    fs::rename(&path, path.with_extension("old")).unwrap();
    fs::write(&path, b"live replacement").unwrap();
    plan.recheck().unwrap();
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
}

#[test]
fn opened_handle_and_path_cannot_be_joined_after_a_replacement() {
    let fixture = Fixture::new();
    let path = fixture.base.join("images/image");
    let approved = platform::open_host_object(&path).unwrap();
    fs::rename(&path, path.with_extension("old")).unwrap();
    fs::write(&path, [1; 1024]).unwrap();
    assert!(HostObject::from_opened(&approved, &path).is_err());
}

#[test]
fn protected_root_replacement_fails_start_and_simulated_receipt_admission() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let receipt = simulated_open(&plan);
    fs::rename(fixture.base.join("cache"), fixture.base.join("cache-old")).unwrap();
    fs::create_dir(fixture.base.join("cache")).unwrap();
    assert!(plan.recheck().is_err());
    assert!(plan.verify_receipt(&receipt).is_err());
}

#[test]
fn protected_ancestor_replacement_cannot_leave_stale_identity_containment_constraints() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("parent");
    for name in ["runtime", "state", "cache", "images", "templates"] {
        fs::create_dir_all(parent.join(name)).unwrap();
    }
    let paths = ProtectedRootPaths {
        runtime: parent.join("runtime"),
        state: parent.join("state"),
        cache: parent.join("cache"),
        images: parent.join("images"),
        templates: parent.join("templates"),
    };
    let roots = ProtectedRoots::new(&paths).unwrap();
    let original = directory.path().join("original-parent");
    fs::rename(&parent, &original).unwrap();
    fs::create_dir(&parent).unwrap();
    for name in ["runtime", "state", "cache", "images", "templates"] {
        fs::rename(original.join(name), parent.join(name)).unwrap();
    }
    for root in roots.objects() {
        assert_eq!(
            HostObject::inspect(root.path()).unwrap().identity(),
            root.identity()
        );
    }
    assert!(roots.recheck().is_err());
}

#[test]
fn receipts_reject_wrong_activation_policy_roles_access_and_geometry() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let valid = simulated_open(&plan);
    for changed in 0..9 {
        let mut receipt = valid.clone();
        match changed {
            0 => receipt.activation = "other".to_owned(),
            1 => receipt.contract = 0,
            2 => receipt.pins.guest_abi = "other".to_owned(),
            3 => receipt.filesystem_slot = FilesystemSlot::Retain,
            4 => receipt.opened.pop().map(|_| ()).unwrap(),
            5 => receipt.opened[1] = receipt.opened[0].clone(),
            6 => receipt.opened[0].access = GrantAccess::ReadWrite,
            7 => receipt.opened[0].geometry.as_mut().unwrap().bytes += 512,
            8 => {
                receipt.network = network::plan(
                    Some(&NetworkPolicy::new(Access::Allow)),
                    None,
                    "10.0.0.2/24",
                )
                .unwrap()
            }
            _ => unreachable!(),
        }
        assert!(plan.verify_receipt(&receipt).is_err(), "fault {changed}");
    }
}

#[test]
fn templates_retain_slot_and_require_exact_runtime_and_machine_identity() {
    let mut fixture = Fixture::new();
    fixture.use_template();
    let plan = fixture.plan();
    assert_eq!(plan.filesystem_slot(), FilesystemSlot::Retain);
    assert_eq!(
        plan.boot(),
        &BootIdentity::CompatibleTemplate {
            template: "template-1".to_owned()
        }
    );
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
    for mismatch in 0..4 {
        let mut input = fixture.input.clone();
        let BootInput::CompatibleTemplate { template, .. } = &mut input.boot else {
            unreachable!()
        };
        match mismatch {
            0 => template.identity.pins.bundle = "old-bundle".to_owned(),
            1 => template.identity.machine.memory_mib += 1,
            2 => template.identity.machine.filesystem_slot = FilesystemSlot::Omit,
            3 => {
                template.identity.machine.workload = WorkloadIdentity {
                    uid: 1001,
                    gid: 1001,
                    create_account: true,
                }
            }
            _ => unreachable!(),
        }
        let mut authorize = Approved::new(&input);
        assert_eq!(
            ActivationPlan::new(input, &mut authorize)
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
    }
}

#[test]
fn media_geometry_and_conflicting_grants_fail_without_content_hashing() {
    let mut fixture = Fixture::new();
    fs::write(fixture.base.join("images/image"), [0; 513]).unwrap();
    let mut authorize = Approved::new(&fixture.input);
    assert!(ActivationPlan::new(fixture.input.clone(), &mut authorize).is_err());
    fs::write(fixture.base.join("images/image"), [0; 1024]).unwrap();
    fixture.input.exports = vec![
        fixture.exposure(
            "share/config",
            GrantAccess::ReadOnly,
            PathSemantics::LivePath,
        ),
        fixture.exposure(
            "share/config",
            GrantAccess::ReadOnly,
            PathSemantics::ObjectPinned,
        ),
    ];
    let mut authorize = Approved::new(&fixture.input);
    assert!(ActivationPlan::new(fixture.input, &mut authorize).is_err());
}

#[test]
fn proxy_settings_and_enforcement_match_and_conflict_with_direct_or_forward_access() {
    for scheme in ["http", "https"] {
        let policy = NetworkPolicy::new(Access::Deny);
        let proxy = ProxyService::from_url(&format!("{scheme}://127.0.0.1:3128")).unwrap();
        let plan = network::plan(Some(&policy), Some(&proxy), "192.0.2.42/24").unwrap();
        let settings = plan.guest_proxy().unwrap();
        assert_eq!(settings.http_proxy, format!("{scheme}://192.0.2.1:3128"));
        assert_eq!(settings.https_proxy, settings.http_proxy);
        assert!(
            plan.openvmm_arguments()
                .windows(2)
                .any(|pair| pair == ["--network-proxy", "192.0.2.1:3128"])
        );
        assert!(
            plan.openvmm_arguments()
                .windows(2)
                .any(|pair| pair == ["--host-loopback", "deny"])
        );
        let mut forward = NetworkPolicy::new(Access::Deny);
        forward.host_loopback_forwards.push(LoopbackForward {
            protocol: ForwardProtocol::Tcp,
            host_port: 3128,
            guest_port: 80,
        });
        let mut ingress = NetworkPolicy::new(Access::Deny);
        ingress.ingress = Access::Allow;
        let mut loopback = NetworkPolicy::new(Access::Deny);
        loopback.host_loopback = Access::Allow;
        for policy in [
            NetworkPolicy::new(Access::Allow),
            policy.clone().with_allow(EgressRule::to("192.0.2.0/24")),
            policy.with_deny(EgressRule::to("192.0.2.0/24")),
            forward,
            ingress,
            loopback,
        ] {
            assert!(network::plan(Some(&policy), Some(&proxy), "192.0.2.42/24").is_err());
        }
        assert!(network::plan(None, Some(&proxy), "192.0.2.42/24").is_err());
    }
    for url in [
        "http://127.0.0.1:0",
        "http://127.0.0.1:+3128",
        "http://127.0.0.1:3128/path",
        "http://user@127.0.0.1:3128",
        "http://192.0.2.1:3128",
    ] {
        assert!(ProxyService::from_url(url).is_err(), "{url}");
    }
}

#[test]
fn authorized_proxy_is_wired_into_the_complete_plan_and_receipt() {
    let mut fixture = Fixture::new();
    fixture.input.machine.network = Some(NetworkPolicy::new(Access::Deny));
    fixture.input.proxy = Some(ProxyService::from_url("http://127.0.0.1:3128").unwrap());
    let plan = fixture.plan();
    assert_eq!(
        plan.network().guest_proxy().unwrap().http_proxy,
        "http://10.0.0.1:3128"
    );
    let arguments = plan
        .openvmm_arguments("endpoint", Path::new("report"), &SimulatedVmm)
        .unwrap();
    assert!(pair(&arguments, "--network-proxy", "10.0.0.1:3128"));
    assert!(pair(&arguments, "--network-egress", "deny"));
    assert!(pair(&arguments, "--host-loopback", "deny"));
    plan.verify_receipt(&simulated_open(&plan)).unwrap();
}

// These callers deliberately have separate framing/models and do not import one another.
mod json_caller {
    use super::*;
    #[derive(Deserialize)]
    struct Request {
        activation: String,
        image_file: PathBuf,
        scratch_file: PathBuf,
    }
    pub(super) fn plan(
        base: &ActivationInput,
        bytes: &[u8],
        approvals: &mut Approved,
    ) -> Result<ActivationPlan> {
        let request: Request = serde_json::from_slice(bytes).map_err(|error| {
            Error::unsupported("invalid JSON caller request").with_source(error)
        })?;
        let mut input = base.clone();
        input.activation = request.activation;
        input.boot = BootInput::DirectImage {
            image: request.image_file,
            scratch: request.scratch_file,
        };
        ActivationPlan::new(input, approvals)
    }
    pub(super) fn shutdown(_: Instant) -> io::Result<()> {
        let frame = serde_json::to_vec(&serde_json::json!({ "operation": "shutdown" }))?;
        assert_eq!(frame, br#"{"operation":"shutdown"}"#);
        Ok(())
    }
}

mod nul_caller {
    use super::*;
    pub(super) fn plan(
        base: &ActivationInput,
        bytes: &[u8],
        approvals: &mut Approved,
    ) -> Result<ActivationPlan> {
        let fields = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(Error::unsupported("NUL caller needs three fields"));
        }
        let text = |field| {
            std::str::from_utf8(field)
                .map_err(|error| Error::unsupported("invalid NUL caller field").with_source(error))
        };
        let mut input = base.clone();
        input.activation = text(fields[0])?.to_owned();
        input.boot = BootInput::DirectImage {
            image: text(fields[1])?.into(),
            scratch: text(fields[2])?.into(),
        };
        ActivationPlan::new(input, approvals)
    }
    pub(super) fn shutdown(_: Instant) -> io::Result<()> {
        assert_eq!(b"shutdown\0".last(), Some(&0));
        Ok(())
    }
}

struct ChildGuard(Option<process::Launched>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.take() {
            assert!(process::kill_child(child));
        }
    }
}

fn probe(log: &Path, milliseconds: u16) -> ChildGuard {
    let mut capability = [1; nvx::protocol::CAPABILITY_LEN];
    capability[..2].copy_from_slice(&milliseconds.to_le_bytes());
    let child = process::spawn(
        &std::env::current_exe().unwrap(),
        false,
        &[
            "--exact".into(),
            "supervision_child_fixture".into(),
            "--ignored".into(),
            "--nocapture".into(),
        ],
        &capability,
        process::create_launch_log(log).unwrap(),
        log.parent().unwrap(),
    )
    .unwrap();
    ChildGuard(Some(child))
}

#[test]
#[ignore = "subprocess fixture, invoked explicitly by the host supervision tests"]
fn supervision_child_fixture() {
    let mut capability = [0; nvx::protocol::CAPABILITY_LEN];
    io::stdin().read_exact(&mut capability).unwrap();
    std::thread::sleep(Duration::from_millis(
        u16::from_le_bytes([capability[0], capability[1]]).into(),
    ));
}

#[test]
fn two_independent_framed_callers_share_planning_receipts_process_wait_and_supervision() {
    let fixture = Fixture::new();
    let image = fixture.base.join("images/image");
    let scratch = fixture.base.join("state/scratch");
    let json = serde_json::to_vec(&serde_json::json!({
        "activation": "activation-1", "image_file": image, "scratch_file": scratch,
    }))
    .unwrap();
    let nul = format!("activation-1\0{}\0{}", image.display(), scratch.display()).into_bytes();
    let first =
        json_caller::plan(&fixture.input, &json, &mut Approved::new(&fixture.input)).unwrap();
    let second =
        nul_caller::plan(&fixture.input, &nul, &mut Approved::new(&fixture.input)).unwrap();
    assert_eq!(first.attachments(), second.attachments());
    let arguments = first
        .openvmm_arguments("endpoint", Path::new("report"), &SimulatedVmm)
        .unwrap();
    assert_eq!(
        arguments,
        second
            .openvmm_arguments("endpoint", Path::new("report"), &SimulatedVmm)
            .unwrap()
    );
    for (index, plan, shutdown) in [
        (
            0,
            first,
            json_caller::shutdown as fn(Instant) -> io::Result<()>,
        ),
        (
            1,
            second,
            nul_caller::shutdown as fn(Instant) -> io::Result<()>,
        ),
    ] {
        let admitted = plan.verify_receipt(&simulated_open(&plan)).unwrap();
        // The OS probe is not an image VM; it exercises the same core spawn/claim/wait entries.
        let mut child = probe(
            &fixture.base.join(format!("state/caller-{index}.log")),
            1200,
        );
        let log = child
            .0
            .as_ref()
            .unwrap()
            .claim_log(
                plan.activation(),
                &fixture.base.join(format!("state/caller-{index}.log")),
            )
            .unwrap();
        let record = plan.runtime_record(&admitted, log).unwrap();
        let encoded = serde_json::to_vec(&record).unwrap();
        let recovered: ImageRuntimeRecord = serde_json::from_slice(&encoded).unwrap();
        plan.check_runtime_record(&recovered).unwrap();
        process::detach_child(child.0.take().unwrap());
        let supervisor = Supervisor::new(recovered.process.clone());
        supervisor.verify_log(&recovered.log).unwrap();
        assert_eq!(supervisor.reconcile().unwrap(), ProcessState::Running);
        let pending = supervisor
            .wait(Instant::now() + Duration::from_millis(10))
            .unwrap();
        assert!(!pending.exited);
        #[cfg(windows)]
        assert_eq!(pending.method, process::ExitWaitMethod::Event);
        let stopped = supervisor
            .stop(Instant::now() + Duration::from_secs(5), shutdown)
            .unwrap();
        assert!(!stopped.forced && stopped.graceful_error.is_none());
        assert_eq!(supervisor.reconcile().unwrap(), ProcessState::Exited);
    }
}

#[test]
fn recovered_log_and_process_identities_reject_replacement_and_pid_reuse() {
    let fixture = Fixture::new();
    let path = fixture.base.join("state/owned.log");
    let child = probe(&path, 60000);
    let claim = child
        .0
        .as_ref()
        .unwrap()
        .claim_log("activation-1", &path)
        .unwrap();
    let supervisor = Supervisor::new(claim.process.clone());
    supervisor.verify_log(&claim).unwrap();
    let unrelated = fixture.base.join("state/unrelated.log");
    fs::write(&unrelated, b"other").unwrap();
    assert!(
        child
            .0
            .as_ref()
            .unwrap()
            .claim_log("activation-1", &unrelated)
            .is_err()
    );
    let reused = Supervisor::new(ProcessIdentity {
        pid: claim.process.pid,
        start_time: claim.process.start_time + 1,
    });
    assert_eq!(reused.reconcile().unwrap(), ProcessState::Exited);
    assert!(reused.wait(Instant::now()).unwrap().exited);
    assert!(reused.terminate().unwrap());
    assert_eq!(supervisor.reconcile().unwrap(), ProcessState::Running);
    assert!(reused.verify_log(&claim).is_err());
    fs::rename(&path, path.with_extension("original")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert!(supervisor.verify_log(&claim).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    let stopped = supervisor
        .stop(Instant::now() + Duration::from_secs(1), |_| {
            Err(io::Error::other("caller transport failed"))
        })
        .unwrap();
    assert!(stopped.forced);
    assert_eq!(
        stopped.graceful_error.unwrap().to_string(),
        "caller transport failed"
    );
}

#[test]
fn old_or_mismatched_profile_records_do_not_guess_a_running_protocol() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let admitted = plan.verify_receipt(&simulated_open(&plan)).unwrap();
    let path = fixture.base.join("state/record.log");
    let child = probe(&path, 60000);
    let log = child
        .0
        .as_ref()
        .unwrap()
        .claim_log(plan.activation(), &path)
        .unwrap();
    let valid = plan.runtime_record(&admitted, log).unwrap();
    for mismatch in 0..6 {
        let mut record = valid.clone();
        match mismatch {
            0 => record.format = 0,
            1 => record.pins.bundle = "old-bundle".to_owned(),
            2 => record.pins.protocol += 1,
            3 => record.pins.guest_abi = "old-guest".to_owned(),
            4 => record.activation = "other".to_owned(),
            5 => {
                record.boot = BootIdentity::CompatibleTemplate {
                    template: "old-template".to_owned(),
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(
            plan.check_runtime_record(&record).unwrap_err().kind(),
            ErrorKind::Unavailable
        );
    }
    let old = instance::RuntimeRecord {
        format: instance::STATE_FORMAT,
        pid: valid.process.pid,
        start_time: valid.process.start_time,
        endpoint: "legacy-endpoint".to_owned(),
    };
    let encoded = serde_json::to_vec(&old).unwrap();
    assert!(serde_json::from_slice::<ImageRuntimeRecord>(&encoded).is_err());
    assert_eq!(
        serde_json::from_slice::<instance::RuntimeRecord>(&encoded).unwrap(),
        old
    );
}
