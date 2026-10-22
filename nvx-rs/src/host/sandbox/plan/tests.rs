//! Tests of the typed plan: every combination of format and upper, the guest's reading of the
//! command lines that plans render, their budget, their checks, and their persisted form.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::*;
use crate::ErrorKind;
use crate::host::network::{
    Access, Destination, EgressRule, ForwardProtocol, HostLoopback, LoopbackForward, NetworkProxy,
    Protocol, ProxyScheme,
};
use crate::host::python::builtins::Int;
use crate::host::sandbox::distro::DistroBinding;
use crate::host::sandbox::{
    LayerRole, MountAccess, MountKind, MountOwner, MountPolicy, SandboxLaunch, SandboxLayer,
    mount::mounts_command_line_fragment,
};

const EROFS_UUID: &str = "11111111-1111-1111-1111-111111111111";
const GPT_GUID: &str = "fedcba98-7654-3210-fedc-ba9876543210";

fn uuid(text: &str) -> Uuid {
    Uuid::parse(text).unwrap()
}

fn message<T: std::fmt::Debug>(result: Result<T>) -> String {
    result.unwrap_err().to_string()
}

/// Returns the images of every format, with and without an identity.
fn images() -> [RootImage; 4] {
    [
        RootImage::erofs(Some(uuid(EROFS_UUID))),
        RootImage::erofs(None),
        RootImage::gpt(Some(uuid(GPT_GUID))),
        RootImage::gpt(None),
    ]
}

/// Returns the uppers: on `scratch.ext4`, and in RAM.
fn uppers() -> [SandboxUpper; 2] {
    [SandboxUpper::scratch("scratch.ext4"), SandboxUpper::RAM]
}

fn plan(image: RootImage, upper: SandboxUpper, settings: SandboxSettings) -> SandboxPlan {
    SandboxPlan::new(
        SandboxDistro::new("images/distro.img", image),
        upper,
        settings,
    )
    .unwrap()
}

fn share(target: &str, host_path: &str, access: MountAccess) -> SandboxMount {
    SandboxMount::new(
        target,
        host_path,
        access,
        MountPolicy::default(),
        MountOwner::Vmm,
        MountKind::Directory,
    )
    .unwrap()
}

#[test]
fn every_format_and_upper_plans_and_renders() {
    let settings = SandboxSettings {
        entrypoint: "/bin/workload".to_owned(),
        args: vec!["--serve".to_owned()],
        hostname: "example".to_owned(),
        workload_identity: (1000, 1001),
        memory_max: Some(Int::from(268_435_456_u32)),
        pids_max: Some(Int::from(64_u32)),
        mounts: Vec::new(),
    };
    let distro = "nvx_layer=distro,0xd0003000";
    let cases = [
        (
            0,
            0,
            format!("{distro},erofs:{EROFS_UUID} nvx_scratch=0xd0006000,ext4"),
        ),
        (1, 0, format!("{distro},erofs nvx_scratch=0xd0006000,ext4")),
        (
            2,
            0,
            format!("{distro},gpt:{GPT_GUID} nvx_scratch=0xd0006000,ext4"),
        ),
        (3, 0, format!("{distro},gpt nvx_scratch=0xd0006000,ext4")),
        (
            0,
            1,
            format!("{distro},erofs:{EROFS_UUID} nvx_overlay_upper=ramfs"),
        ),
        (1, 1, format!("{distro},erofs nvx_overlay_upper=ramfs")),
        (
            2,
            1,
            format!("{distro},gpt:{GPT_GUID} nvx_overlay_upper=ramfs"),
        ),
        (3, 1, format!("{distro},gpt nvx_overlay_upper=ramfs")),
    ];
    for (image, upper, tokens) in cases {
        let (image, upper) = (images()[image], uppers()[upper].clone());
        let plan = plan(image, upper.clone(), settings.clone());
        assert_eq!(
            plan.layout(),
            RootLayout {
                image,
                upper: upper.kind()
            }
        );
        assert_eq!(
            plan.kernel_command_line("quiet").unwrap(),
            format!(
                "quiet nvx_sandbox=1 {tokens} nvx_entrypoint=/bin/workload nvx_hostname=example \
                 nvx_arg=--serve nvx_memory_max=268435456 nvx_pids_max=65"
            )
        );
        let distro_block = PurePath::native("images/distro.img");
        let mut expected = vec![
            "--machine".to_owned(),
            "microvm".to_owned(),
            "--microvm-sandbox-block".to_owned(),
            format!("distro:file:{},ro", distro_block.as_str()),
        ];
        let mut blocks = vec![(BlockRole::Distro, distro_block.as_path())];
        // A RAM upper has no scratch block device.
        if let Some(scratch) = upper.scratch_path() {
            expected.extend([
                "--microvm-sandbox-block".to_owned(),
                format!("scratch:file:{}", scratch.display()),
            ]);
            blocks.push((BlockRole::Scratch, scratch));
        }
        expected.extend([
            "--microvm-workload-identity".to_owned(),
            "1000:1001".to_owned(),
        ]);
        assert_eq!(plan.openvmm_arguments().unwrap(), expected);
        assert_eq!(plan.blocks(), blocks);
    }
}

#[test]
fn the_guest_reads_the_root_of_every_plan_from_its_command_line() {
    let settings = SandboxSettings {
        args: vec!["-c".to_owned(), "true".to_owned()],
        mounts: vec![
            share("/workspace", "work", MountAccess::ReadWrite),
            share("/srv/cache", "cache", MountAccess::ReadOnly),
        ],
        ..SandboxSettings::default()
    };
    for image in images() {
        for upper in uppers() {
            let plan = plan(image, upper.clone(), settings.clone());
            let command_line = plan.kernel_command_line("console=hvc0 quiet").unwrap();
            assert_eq!(
                RootLayout::parse(command_line.as_bytes()),
                Ok(Some(plan.layout())),
                "{command_line}"
            );
            // OpenVMM appends its own tokens, the discovery of the plan's block devices among
            // them, which the guest reads alike.
            let mut effective =
                format!("{command_line} nr_cpus=1 virtio_mmio.device=0x1000@0xd0003000:4");
            if upper.scratch_path().is_some() {
                effective.push_str(" virtio_mmio.device=0x1000@0xd0006000:11");
            }
            effective.push_str(&mounts_command_line_fragment(plan.mounts()));
            assert_eq!(
                RootLayout::parse(effective.as_bytes()),
                Ok(Some(plan.layout())),
                "{effective}"
            );
        }
    }
}

#[test]
fn plans_refuse_the_command_lines_that_the_guest_refuses() {
    // The user's command line may add a virtio-mmio device, which the guest reads as the kernel
    // does: one at the scratch base conflicts with a RAM upper.
    let conflict = "sandbox kernel command line conflicts with the boot tokens of its root: a RAM \
                    upper takes no scratch block device, but the command line adds a virtio-mmio \
                    device at 0xd0006000";
    for image in images() {
        let plan = plan(image, SandboxUpper::RAM, SandboxSettings::default());
        for user in [
            "virtio_mmio.device=0x1000@0xd0006000:11",
            "quiet virtio-mmio.device=4K@0xd0006000:11:3",
            "\"virtio_mmio.device=0x1000@0xd0006000:11\"",
            "virtio_mmio.device=\"0x1000@ 0xd0006000:11\"",
            "virtio_mmio.device=0x1000@3489685504:11",
        ] {
            let error = plan.kernel_command_line(user).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unsupported, "{user}");
            assert_eq!(error.to_string(), conflict, "{user}");
        }
        for user in [
            // The driver refuses these values, so the kernel adds no device from them.
            "virtio_mmio.device=0x1000@0xd0006000:0",
            "virtio_mmio.device=0x1000@0xd0006000",
            // A device elsewhere, and a token that the kernel reads inside another value.
            "virtio_mmio.device=0x1000@0xd0007000:3",
            "x=\"y virtio_mmio.device=0x1000@0xd0006000:11\"",
        ] {
            let command_line = plan.kernel_command_line(user).unwrap();
            assert_eq!(
                RootLayout::parse(command_line.as_bytes()),
                Ok(Some(plan.layout())),
                "{user}"
            );
        }
    }
}

#[test]
fn the_longest_boot_tokens_fit_the_command_line_budget_to_the_byte() {
    // The tokens of an identified EROFS image over scratch are the longest: they take the most
    // of the budget, which every other plan keeps the rest of.
    let longest = plan(images()[0], uppers()[0].clone(), SandboxSettings::default());
    let longest_base = longest.kernel_command_line("").unwrap().len();
    for mounts in [
        Vec::new(),
        vec![share("/workspace", "work", MountAccess::ReadWrite)],
        vec![
            share("/workspace", "work", MountAccess::ReadWrite),
            share("/srv/cache", "cache", MountAccess::ReadOnly),
        ],
    ] {
        let settings = SandboxSettings {
            mounts,
            ..SandboxSettings::default()
        };
        for image in images() {
            for upper in uppers() {
                let plan = plan(image, upper, settings.clone());
                let base = plan.kernel_command_line("").unwrap();
                let fragment = mounts_command_line_fragment(plan.mounts());
                // The user's command line, a space, the plan's tokens, OpenVMM's share tokens,
                // and a NUL fill the budget exactly.
                let fitting =
                    "x".repeat(SANDBOX_COMMAND_LINE_MAX_SIZE - base.len() - fragment.len() - 2);
                let command_line = plan.kernel_command_line(&fitting).unwrap();
                assert_eq!(
                    command_line.len() + fragment.len() + 1,
                    SANDBOX_COMMAND_LINE_MAX_SIZE
                );
                assert_eq!(
                    RootLayout::parse(command_line.as_bytes()),
                    Ok(Some(plan.layout()))
                );
                assert!(
                    message(plan.kernel_command_line(&format!("{fitting}x"))).contains("1024-byte")
                );
                if plan.mounts().is_empty() {
                    assert!(base.len() <= longest_base, "{base}");
                }
            }
        }
    }
}

#[test]
fn plans_check_their_settings_as_launches_do() {
    let checked = |change: fn(&mut SandboxSettings)| {
        let mut settings = SandboxSettings::default();
        change(&mut settings);
        SandboxPlan::new(
            SandboxDistro::new("d.img", RootImage::gpt(None)),
            SandboxUpper::RAM,
            settings,
        )
    };
    for (change, expected) in [
        (
            (|settings: &mut SandboxSettings| settings.entrypoint = "bin/sh".to_owned())
                as fn(&mut SandboxSettings),
            "sandbox entrypoint must be an absolute path without spaces",
        ),
        (
            |settings| settings.args = vec![String::new()],
            "sandbox arguments must be nonempty and contain no spaces",
        ),
        (
            |settings| settings.hostname = "Invalid".to_owned(),
            "sandbox hostname must be a lowercase RFC 1123 label up to 63 characters",
        ),
        (
            |settings| settings.workload_identity = (0, 1),
            "sandbox workload identity must be a non-root UID:GID",
        ),
        (
            |settings| settings.memory_max = Some(Int::zero()),
            "--memory-max must be positive",
        ),
        (
            |settings| {
                settings.mounts = vec![
                    share("/workspace", "a", MountAccess::ReadWrite),
                    share("/workspace/cache", "b", MountAccess::ReadOnly),
                ];
            },
            "sandbox mount targets /workspace and /workspace/cache overlap; a share cannot hide \
             another",
        ),
    ] {
        let error = checked(change).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(error.to_string(), expected);
    }
    checked(|_| {}).unwrap();
}

#[test]
fn plans_check_the_images_of_their_block_devices_against_the_host() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| {
        PurePath::native(directory.path().to_str().unwrap())
            .join(name)
            .as_str()
            .to_owned()
    };
    let plan = |name: &str, image: RootImage, upper: SandboxUpper| {
        SandboxPlan::new(
            SandboxDistro::new(&path(name), image),
            upper,
            SandboxSettings::default(),
        )
        .unwrap()
    };
    for (image, description) in [
        (RootImage::erofs(None), "distro EROFS layer"),
        (RootImage::gpt(Some(uuid(GPT_GUID))), "distro GPT image"),
    ] {
        let missing = plan("missing.img", image, SandboxUpper::RAM);
        let error = missing.validated().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unavailable);
        assert_eq!(
            error.to_string(),
            format!("{description} not found: {}", path("missing.img"))
        );
    }
    fs::write(path("distro.img"), b"image").unwrap();
    // A RAM upper has no scratch image to check.
    plan("distro.img", RootImage::gpt(None), SandboxUpper::RAM)
        .validated()
        .unwrap();
    let scratch = plan(
        "distro.img",
        RootImage::gpt(None),
        SandboxUpper::scratch(&path("scratch.ext4")),
    );
    assert_eq!(
        message(scratch.validated()),
        format!("ext4 scratch image not found: {}", path("scratch.ext4"))
    );
    fs::write(path("scratch.ext4"), b"scratch").unwrap();
    scratch.validated().unwrap();
    let delimited = path("distro,ro.img");
    fs::write(&delimited, b"image").unwrap();
    assert_eq!(
        message(plan("distro,ro.img", RootImage::gpt(None), SandboxUpper::RAM).validated()),
        format!("disk paths containing commas or semicolons are unsupported: {delimited}")
    );
    // OpenVMM would read a container from a file with one of these extensions.
    for extension in ["vhd", "vhdx", "vmgs", "iso"] {
        let refusal = |name: &str| {
            format!(
                "disk paths ending in .{extension} are unsupported, since OpenVMM would not \
                 attach them as raw images: {}",
                path(name)
            )
        };
        let image = format!("distro.{extension}");
        fs::write(path(&image), b"image").unwrap();
        assert_eq!(
            message(plan(&image, RootImage::gpt(None), SandboxUpper::RAM).validated()),
            refusal(&image)
        );
        let scratch = format!("scratch.{extension}");
        fs::write(path(&scratch), b"scratch").unwrap();
        let upper = SandboxUpper::scratch(&path(&scratch));
        assert_eq!(
            message(plan("distro.img", RootImage::erofs(None), upper).validated()),
            refusal(&scratch)
        );
    }
    // OpenVMM reads the extension of the name alone, case-sensitively, and none of a name that
    // starts with its only dot.
    fs::create_dir(path("images.vhd")).unwrap();
    for name in ["raw.VHD", ".vhd", "distro.vhd.img", "images.vhd/distro.img"] {
        fs::write(path(name), b"image").unwrap();
        plan(name, RootImage::gpt(None), SandboxUpper::RAM)
            .validated()
            .unwrap();
    }
    let resolved = |name: &str| {
        crate::host::python::fs::resolve(&PurePath::native(&path(name)))
            .unwrap()
            .as_str()
            .to_owned()
    };
    // Windows resolves a name to the case of the file's own, which `provision` records.
    #[cfg(windows)]
    {
        assert_eq!(
            message(plan("distro.VHD", RootImage::gpt(None), SandboxUpper::RAM).validated()),
            format!(
                "disk paths ending in .vhd are unsupported, since OpenVMM would not attach them \
                 as raw images: {} resolves to {}",
                path("distro.VHD"),
                resolved("distro.VHD")
            )
        );
    }
    // A provisioned sandbox gives OpenVMM the paths to which its images' paths resolve, so a link
    // to a container's name is refused too, as the distro image or the scratch image.
    let linked = |link: &str, target: &str| {
        let (link, target) = (path(link), path(target));
        move |candidate: &PurePath| {
            if candidate.as_str() == link {
                Ok(PurePath::native(&target))
            } else {
                crate::host::python::fs::resolve(candidate)
            }
        }
    };
    let refusal = |extension: &str, link: &str, target: &str| {
        format!(
            "disk paths ending in .{extension} are unsupported, since OpenVMM would not attach \
             them as raw images: {} resolves to {}",
            path(link),
            path(target)
        )
    };
    let resolve = linked("distro.img", "image.vhd");
    let host = mount::HostQueries {
        resolve: &resolve,
        ..mount::HostQueries::native()
    };
    let raw = plan("distro.img", RootImage::gpt(None), SandboxUpper::RAM);
    assert_eq!(
        message(raw.validated_with(&host)),
        refusal("vhd", "distro.img", "image.vhd")
    );
    let resolve = linked("scratch.ext4", "upper.vhdx");
    let host = mount::HostQueries {
        resolve: &resolve,
        ..mount::HostQueries::native()
    };
    let upper = SandboxUpper::scratch(&path("scratch.ext4"));
    let scratch = plan("distro.img", RootImage::erofs(None), upper);
    assert_eq!(
        message(scratch.validated_with(&host)),
        refusal("vhdx", "scratch.ext4", "upper.vhdx")
    );
    scratch.validated().unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(path("distro.vhd"), path("link.img")).unwrap();
        assert_eq!(
            message(plan("link.img", RootImage::gpt(None), SandboxUpper::RAM).validated()),
            format!(
                "disk paths ending in .vhd are unsupported, since OpenVMM would not attach them \
                 as raw images: {} resolves to {}",
                path("link.img"),
                resolved("link.img")
            )
        );
    }
}

#[test]
fn launches_plan_their_distro_layer_over_their_scratch_image() {
    let launch = SandboxLaunch::new(
        vec![SandboxLayer::new(
            LayerRole::Distro,
            "distro.erofs",
            EROFS_UUID,
        )],
        "scratch.ext4",
        SandboxSettings::default(),
    )
    .unwrap();
    let plan = launch.plan();
    assert_eq!(plan.distro().path(), Path::new("distro.erofs"));
    assert_eq!(
        plan.distro().image(),
        RootImage::erofs(Some(uuid(EROFS_UUID)))
    );
    assert_eq!(plan.upper().kind(), RootUpper::Scratch);
    assert_eq!(plan.upper().scratch_path(), Some(Path::new("scratch.ext4")));
    assert_eq!(launch.scratch(), Path::new("scratch.ext4"));
    assert_eq!(plan.settings(), &SandboxSettings::default());
    // The guest takes the UUID in its canonical text, which `--layer` writes, and nothing else.
    for invalid in ["", "not-a-uuid", "11111111-1111-1111-1111-11111111111A"] {
        let error = SandboxLaunch::new(
            vec![SandboxLayer::new(
                LayerRole::Distro,
                "distro.erofs",
                invalid,
            )],
            "scratch.ext4",
            SandboxSettings {
                entrypoint: "relative".to_owned(),
                ..SandboxSettings::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            format!("distro layer UUID is invalid: '{invalid}'")
        );
    }
}

#[test]
fn launches_plan_the_image_that_the_binding_of_their_distro_layer_records() {
    let directory = tempfile::tempdir().unwrap();
    let layer = directory.path().join("distro.erofs");
    fs::write(&layer, b"layer").unwrap();
    let launch = SandboxLaunch::new(
        vec![SandboxLayer::new(
            LayerRole::Distro,
            layer.to_str().unwrap(),
            EROFS_UUID,
        )],
        "scratch.ext4",
        SandboxSettings::default(),
    )
    .unwrap();
    let binding = DistroBinding::verify(launch.distro()).unwrap();
    let bound = launch.bound_plan(&binding).unwrap();
    assert_eq!(
        bound.distro().image(),
        RootImage::erofs(Some(uuid(EROFS_UUID)))
    );
    assert_eq!(&bound, launch.plan());

    // The binding, not the `--layer` value, names the identity.
    let mut recorded = serde_json::to_value(&binding).unwrap();
    recorded["identity"] = json!(GPT_GUID);
    let other: DistroBinding = serde_json::from_value(recorded.clone()).unwrap();
    assert_eq!(
        launch.bound_plan(&other).unwrap().distro().image(),
        RootImage::erofs(Some(uuid(GPT_GUID)))
    );
    recorded["identity"] = json!("11111111-1111-1111-1111-11111111111A");
    let invalid: DistroBinding = serde_json::from_value(recorded).unwrap();
    assert_eq!(
        message(launch.bound_plan(&invalid)),
        "the distro binding names the identity '11111111-1111-1111-1111-11111111111A', which is \
         not a UUID in its canonical text"
    );
}

/// Returns a plan of every kind of setting, persisted as it records them.
fn persisted() -> (SandboxPlan, Value) {
    let workspace = SandboxMount::new(
        "/workspace",
        "work",
        MountAccess::ReadWrite,
        MountPolicy {
            denied: vec!["secrets".to_owned()],
            allowed: vec!["secrets/public".to_owned()],
            writable: vec!["out".to_owned()],
        },
        MountOwner::Vmm,
        MountKind::Directory,
    )
    .unwrap();
    // The largest limits that the guest's cgroups apply, of which the memory limit exceeds the
    // integers that a JSON number holds exactly.
    let settings = SandboxSettings {
        entrypoint: "/bin/workload".to_owned(),
        args: vec!["--serve".to_owned()],
        hostname: "example".to_owned(),
        workload_identity: (1000, 1001),
        memory_max: Some(Int::parse("18446744073709551615").unwrap()),
        pids_max: Some(Int::from(4_194_303_u32)),
        mounts: vec![
            workspace,
            SandboxMount::new(
                "/etc/app/settings.json",
                "settings.json",
                MountAccess::ReadOnly,
                MountPolicy::default(),
                MountOwner::Vmm,
                MountKind::File,
            )
            .unwrap(),
        ],
    };
    let plan = SandboxPlan::new(
        SandboxDistro::new("/images/distro.img", RootImage::gpt(Some(uuid(GPT_GUID)))),
        SandboxUpper::RAM,
        settings,
    )
    .unwrap()
    .with_network(Some(direct_network()));
    let path = |text: &str| PurePath::native(text).as_str().to_owned();
    let form = json!({
        "version": 2,
        "distro": {"path": path("/images/distro.img"), "format": "gpt", "identity": GPT_GUID},
        "upper": {"kind": "ram"},
        "settings": {
            "entrypoint": "/bin/workload",
            "args": ["--serve"],
            "hostname": "example",
            "workloadIdentity": {"uid": 1000, "gid": 1001},
            "memoryMax": "18446744073709551615",
            "pidsMax": "4194303",
            "mounts": [
                {
                    "guestTarget": "/workspace",
                    "hostPath": "work",
                    "access": "rw",
                    "policy": {
                        "denied": ["secrets"],
                        "allowed": ["secrets/public"],
                        "writable": ["out"],
                    },
                    "owner": "vmm",
                    "kind": "directory",
                },
                {
                    "guestTarget": "/etc/app/settings.json",
                    "hostPath": "settings.json",
                    "access": "ro",
                    "policy": {"denied": [], "allowed": [], "writable": []},
                    "owner": "vmm",
                    "kind": "file",
                },
            ],
        },
        "network": direct_network_form(),
    });
    (plan, form)
}

/// Returns a network with every field of a policy that allows direct egress.
fn direct_network() -> SandboxNetwork {
    let mut policy = NetworkPolicy::new(Access::Allow)
        .with_allow(
            EgressRule {
                to: vec![Destination {
                    cidr: "192.0.2.0/24".to_owned(),
                    except: vec!["192.0.2.128/25".to_owned()],
                }],
                ports: Vec::new(),
            }
            .on_port_range(Protocol::Any, 8000, 8010),
        )
        .with_allow(EgressRule::default().on_port(Protocol::Tcp, 443))
        .with_deny(EgressRule::to("198.51.100.0/24").on_port(Protocol::Udp, 53))
        .with_deny(EgressRule::to("2001:db8::/32").on_protocol(Protocol::Icmp));
    policy.ingress = Access::Allow;
    policy.host_loopback = HostLoopback::Allow;
    policy.host_loopback_forwards = vec![LoopbackForward {
        protocol: ForwardProtocol::Tcp,
        host_port: 18080,
        guest_port: 8080,
    }];
    SandboxNetwork::new("10.0.0.2/24", policy).unwrap()
}

/// Returns the persisted form of [`direct_network`].
fn direct_network_form() -> Value {
    json!({
        "guestNetwork": "10.0.0.2/24",
        "egress": "allow",
        "allow": {
            "name": "egress.allow",
            "rules": [
                {
                    "to": [{"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}],
                    "ports": [{"protocol": "any", "port": 8000, "endPort": 8010}],
                },
                {"to": [], "ports": [{"protocol": "tcp", "port": 443, "endPort": null}]},
            ],
        },
        "deny": {
            "name": "egress.deny",
            "rules": [
                {
                    "to": [{"cidr": "198.51.100.0/24", "except": []}],
                    "ports": [{"protocol": "udp", "port": 53, "endPort": null}],
                },
                {
                    "to": [{"cidr": "2001:db8::/32", "except": []}],
                    "ports": [{"protocol": "icmp", "port": null, "endPort": null}],
                },
            ],
        },
        "ingress": "allow",
        "hostLoopback": "allow",
        "hostLoopbackForwards": [{"protocol": "tcp", "hostPort": 18080, "guestPort": 8080}],
        "proxy": null,
    })
}

/// Returns the network of a guest at `10.0.0.2/24` whose one way out is a proxy at port 3128 of
/// host loopback, with `scheme`.
fn proxy_network(scheme: Option<ProxyScheme>) -> SandboxNetwork {
    let proxy = NetworkProxy { port: 3128, scheme };
    SandboxNetwork::new("10.0.0.2/24", NetworkPolicy::proxy_only(proxy)).unwrap()
}

#[test]
fn plans_persist_in_their_versioned_form() {
    let (plan, form) = persisted();
    assert_eq!(serde_json::to_value(&plan).unwrap(), form);
    assert_eq!(serde_json::from_value::<SandboxPlan>(form).unwrap(), plan);
    // Every combination round-trips, and renders alike after it does.
    for image in images() {
        for upper in uppers() {
            for network in [None, Some(direct_network()), Some(proxy_network(None))] {
                let plan = plan_with(image, upper.clone()).with_network(network);
                let read: SandboxPlan =
                    serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
                assert_eq!(read, plan);
                assert_eq!(
                    read.kernel_command_line("").unwrap(),
                    plan.kernel_command_line("").unwrap()
                );
                assert_eq!(
                    read.openvmm_arguments().unwrap(),
                    plan.openvmm_arguments().unwrap()
                );
                assert_eq!(read.proxy_url(), plan.proxy_url());
            }
        }
    }
    let scratch = serde_json::to_value(plan_with(images()[1], uppers()[0].clone())).unwrap();
    assert_eq!(
        scratch["upper"],
        json!({"kind": "scratch", "path": PurePath::native("scratch.ext4").as_str()})
    );
    assert_eq!(scratch["distro"]["identity"], Value::Null);
    assert_eq!(scratch["network"], Value::Null);
    let proxy = serde_json::to_value(proxy_network(Some(ProxyScheme::Https))).unwrap();
    assert_eq!(
        proxy,
        json!({
            "guestNetwork": "10.0.0.2/24",
            "egress": "deny",
            "allow": {"name": "egress.allow", "rules": []},
            "deny": {"name": "egress.deny", "rules": []},
            "ingress": "deny",
            "hostLoopback": "deny",
            "hostLoopbackForwards": [],
            "proxy": {"port": 3128, "scheme": "https"},
        })
    );
    assert_eq!(PLAN_VERSION, 2);
}

fn plan_with(image: RootImage, upper: SandboxUpper) -> SandboxPlan {
    plan(image, upper, SandboxSettings::default())
}

#[test]
fn persisted_plans_that_break_the_form_or_the_checks_are_refused() {
    let (_, form) = persisted();
    let refused = |change: &dyn Fn(&mut Value), expected: &str| {
        let mut value = form.clone();
        change(&mut value);
        let error = serde_json::from_value::<SandboxPlan>(value)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error} lacks {expected}");
    };
    // Every field is required, nulls included, and no other is accepted.
    for pointer in [
        "/version",
        "/distro",
        "/distro/path",
        "/distro/format",
        "/distro/identity",
        "/upper",
        "/upper/kind",
        "/settings",
        "/settings/entrypoint",
        "/settings/args",
        "/settings/hostname",
        "/settings/workloadIdentity",
        "/settings/workloadIdentity/uid",
        "/settings/memoryMax",
        "/settings/pidsMax",
        "/settings/mounts",
        "/settings/mounts/0/guestTarget",
        "/settings/mounts/0/policy",
        "/settings/mounts/0/policy/writable",
        "/settings/mounts/1/kind",
        "/network",
        "/network/guestNetwork",
        "/network/egress",
        "/network/allow",
        "/network/allow/name",
        "/network/allow/rules",
        "/network/allow/rules/0/to",
        "/network/allow/rules/0/to/0/except",
        "/network/allow/rules/0/ports",
        "/network/allow/rules/0/ports/0/protocol",
        "/network/deny/rules/0/ports/0/endPort",
        "/network/deny",
        "/network/ingress",
        "/network/hostLoopback",
        "/network/hostLoopbackForwards",
        "/network/hostLoopbackForwards/0/guestPort",
        "/network/proxy",
    ] {
        let (parent, name) = pointer.rsplit_once('/').unwrap();
        refused(
            &|value| {
                value
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(name)
                    .unwrap();
            },
            "missing field",
        );
    }
    for pointer in [
        "",
        "/distro",
        "/upper",
        "/settings",
        "/settings/workloadIdentity",
        "/settings/mounts/0",
        "/settings/mounts/0/policy",
        "/network",
        "/network/allow",
        "/network/allow/rules/0",
        "/network/allow/rules/0/to/0",
        "/network/allow/rules/0/ports/0",
        "/network/hostLoopbackForwards/0",
    ] {
        refused(
            &|value| {
                value.pointer_mut(pointer).unwrap()["origin"] = json!("elsewhere");
            },
            "unknown field",
        );
    }
    // A RAM upper has no scratch image.
    refused(
        &|value| value["upper"]["path"] = json!("scratch.ext4"),
        "unknown field `path`",
    );
    refused(
        &|value| value["upper"] = json!({"kind": "scratch"}),
        "missing field `path`",
    );
    refused(
        &|value| value["upper"] = json!({"kind": "tmpfs"}),
        "unknown variant",
    );
    refused(&|value| value["upper"] = json!("ram"), "invalid type");
    refused(
        &|value| value["distro"]["format"] = json!("ext4"),
        "unknown variant",
    );
    for version in [1, 3] {
        refused(
            &|value| value["version"] = json!(version),
            &format!("the sandbox plan has version {version}, which this build does not read"),
        );
    }
    // The form of version 1, which had no network, is not read.
    refused(
        &|value| {
            value["version"] = json!(1);
            value.as_object_mut().unwrap().remove("network");
        },
        "missing field `network`",
    );
    for identity in ["", "FEDCBA98-7654-3210-FEDC-BA9876543210", "{fedcba98}"] {
        refused(
            &|value| value["distro"]["identity"] = json!(identity),
            &format!(
                "the distro identity of the sandbox plan, '{identity}', is not a UUID in its \
                 canonical text"
            ),
        );
    }
    for limit in ["", "0", "01", "+1", "1 ", "-1", "1_000", "\u{0661}", "0x10"] {
        refused(
            &|value| value["settings"]["memoryMax"] = json!(limit),
            "the memoryMax of the sandbox plan",
        );
        refused(
            &|value| value["settings"]["pidsMax"] = json!(limit),
            "is not a positive integer in decimal text",
        );
    }
    refused(
        &|value| value["settings"]["memoryMax"] = json!(268_435_456),
        "invalid type",
    );
    // What the plan and its shares check, reading checks too.
    refused(
        &|value| value["settings"]["memoryMax"] = json!("18446744073709551616"),
        "--memory-max must be at most 18446744073709551615",
    );
    refused(
        &|value| value["settings"]["pidsMax"] = json!("4194304"),
        "--pids-max must be at most 4194303",
    );
    refused(
        &|value| value["settings"]["workloadIdentity"]["uid"] = json!(0),
        "sandbox workload identity must be a non-root UID:GID",
    );
    refused(
        &|value| value["settings"]["entrypoint"] = json!("bin/sh"),
        "sandbox entrypoint must be an absolute path without spaces",
    );
    refused(
        &|value| value["settings"]["mounts"][1]["guestTarget"] = json!("/workspace/settings.json"),
        "overlap",
    );
    refused(
        &|value| value["settings"]["mounts"][0]["guestTarget"] = json!("/etc"),
        "sandbox mount target /etc is reserved",
    );
    refused(
        &|value| value["settings"]["mounts"][0]["access"] = json!("ro"),
        "--mount-write narrows the writes of a read-write share",
    );
    refused(
        &|value| value["settings"]["mounts"][0]["owner"] = json!("root"),
        "unsupported sandbox mount owner",
    );
    refused(
        &|value| value["settings"]["mounts"][1]["kind"] = json!("socket"),
        "unsupported sandbox mount kind 'socket'",
    );
    // The network's values, and what its policy checks.
    refused(
        &|value| value["network"]["egress"] = json!("block"),
        "unknown variant",
    );
    refused(
        &|value| value["network"]["hostLoopback"] = json!(true),
        "invalid type",
    );
    refused(
        &|value| value["network"]["allow"]["rules"][0]["ports"][0]["protocol"] = json!("sctp"),
        "unknown variant",
    );
    refused(
        &|value| value["network"]["allow"]["rules"][0]["ports"][0]["port"] = json!(65536),
        "invalid value",
    );
    refused(
        &|value| value["network"]["hostLoopbackForwards"][0]["protocol"] = json!("icmp"),
        "unknown variant",
    );
    refused(
        &|value| value["network"]["guestNetwork"] = json!("10.0.0.1/24"),
        "guest network '10.0.0.1/24' must be an IPv4 address with a /1 to /30 prefix that is not \
         its network's network, broadcast, or gateway (first) address",
    );
    refused(
        &|value| value["network"]["allow"]["rules"][0]["to"][0]["cidr"] = json!("example.com"),
        "egress.allow[0].to[0].cidr is not a valid IPv4 or IPv6 CIDR: example.com",
    );
    refused(
        &|value| value["network"]["hostLoopback"] = json!("outbound"),
        "host-loopback forwards need host-loopback access allowed",
    );
    // A proxy is the one way out of its network, and its scheme is http or https.
    refused(
        &|value| value["network"]["proxy"] = json!({"port": 3128, "scheme": null}),
        "a network proxy needs egress denied by default",
    );
    let proxy_only = serde_json::to_value(proxy_network(None)).unwrap();
    refused(
        &|value| {
            value["network"] = proxy_only.clone();
            value["network"]["proxy"]["scheme"] = json!("ftp");
        },
        "network proxy scheme \"ftp\" must be http or https",
    );
    refused(
        &|value| {
            value["network"] = proxy_only.clone();
            value["network"]["proxy"]["port"] = json!(0);
        },
        "a network proxy needs a port between 1 and 65535",
    );
    refused(
        &|value| {
            value["network"] = proxy_only.clone();
            value["network"]["proxy"]
                .as_object_mut()
                .unwrap()
                .remove("scheme");
        },
        "missing field `scheme`",
    );
    refused(
        &|value| {
            value["network"] = proxy_only.clone();
            value["network"]["proxy"]["origin"] = json!("elsewhere");
        },
        "unknown field",
    );
}

#[test]
fn plans_render_and_report_their_network() {
    let settings = SandboxSettings {
        mounts: vec![share("/workspace", "work", MountAccess::ReadWrite)],
        ..SandboxSettings::default()
    };
    let without = plan(images()[0], uppers()[0].clone(), settings);
    let shares = without.openvmm_arguments().unwrap();
    assert!(without.network().is_none());
    assert_eq!(without.proxy_url(), None);

    // The network's options follow the plan's other options.
    for network in [direct_network(), proxy_network(None)] {
        let plan = without.clone().with_network(Some(network.clone()));
        let mut expected = shares.clone();
        expected.extend(network.openvmm_arguments().unwrap());
        assert_eq!(plan.openvmm_arguments().unwrap(), expected);
        assert_eq!(plan.network(), Some(&network));
        // The network adds no boot token.
        assert_eq!(
            plan.kernel_command_line("quiet").unwrap(),
            without.kernel_command_line("quiet").unwrap()
        );
    }
    let direct = without.clone().with_network(Some(direct_network()));
    let arguments = direct.openvmm_arguments().unwrap();
    assert_eq!(
        arguments[shares.len()..],
        [
            "--net",
            "10.0.0.2/24",
            "--network-profile",
            "portable",
            "--network-egress",
            "allow",
            "--network-ingress",
            "allow",
            "--host-loopback",
            "allow",
            "--network-egress-allow",
            "0.0.0.0/0:tcp:443",
            "--network-egress-allow",
            "192.0.2.0/25:tcp:8000-8010",
            "--network-egress-allow",
            "192.0.2.0/25:udp:8000-8010",
            "--network-egress-allow",
            "::/0:tcp:443",
            "--network-egress-deny",
            "198.51.100.0/24:udp:53",
            "--network-egress-deny",
            "2001:db8::/32:icmp",
            "--host-loopback-forward",
            "tcp:18080:8080",
        ]
    );
    assert_eq!(direct.proxy_url(), None);

    // A proxy-only network reaches its proxy at the gateway, which its URL names.
    for (scheme, url) in [
        (None, "10.0.0.1:3128"),
        (Some(ProxyScheme::Http), "http://10.0.0.1:3128"),
        (Some(ProxyScheme::Https), "https://10.0.0.1:3128"),
    ] {
        let network = proxy_network(scheme);
        assert_eq!(network.gateway(), std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(network.proxy_url().as_deref(), Some(url));
        let plan = without.clone().with_network(Some(network));
        assert_eq!(plan.proxy_url().as_deref(), Some(url));
        assert_eq!(
            plan.openvmm_arguments().unwrap()[shares.len()..],
            [
                "--net",
                "10.0.0.2/24",
                "--network-profile",
                "portable",
                "--network-egress",
                "deny",
                "--network-ingress",
                "deny",
                "--host-loopback",
                "deny",
                "--network-proxy",
                "10.0.0.1:3128",
            ]
        );
    }
    let narrow = SandboxNetwork::new(
        "192.168.7.6/30",
        NetworkPolicy::proxy_only(NetworkProxy::new(8080).with_scheme(ProxyScheme::Http)),
    )
    .unwrap();
    assert_eq!(
        narrow.proxy_url().as_deref(),
        Some("http://192.168.7.5:8080")
    );

    // A policy that lets nothing through attaches no network device.
    let isolated = SandboxNetwork::new("10.0.0.2/24", NetworkPolicy::new(Access::Deny)).unwrap();
    assert!(isolated.openvmm_arguments().unwrap().is_empty());
    assert_eq!(
        without
            .clone()
            .with_network(Some(isolated))
            .openvmm_arguments()
            .unwrap(),
        shares
    );
}

#[test]
fn networks_check_their_guest_network_and_their_policy() {
    for guest_network in [
        "10.0.0.1/24",
        "10.0.0.0/24",
        "10.0.0.2/31",
        "10.0.0.2",
        "fd00::2/64",
    ] {
        let error =
            SandboxNetwork::new(guest_network, NetworkPolicy::new(Access::Allow)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            format!(
                "guest network '{guest_network}' must be an IPv4 address with a /1 to /30 prefix \
                 that is not its network's network, broadcast, or gateway (first) address"
            )
        );
    }
    // The policy must lower: each way out beside a proxy is refused before launch.
    let mut policy = NetworkPolicy::proxy_only(NetworkProxy::new(3128));
    policy.ingress = Access::Allow;
    let error = SandboxNetwork::new("10.0.0.2/24", policy).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert_eq!(error.to_string(), "a network proxy needs ingress denied");
    let mut policy = NetworkPolicy::new(Access::Allow);
    policy.host_loopback = HostLoopback::Allow;
    assert_eq!(
        message(SandboxNetwork::new("10.0.0.2/30", policy)),
        "host-loopback access needs a guest network prefix of /29 or shorter, which leaves an \
         address at which OpenVMM presents host peers to the guest"
    );
}

#[test]
fn launches_carry_their_network_into_their_plans() {
    let directory = tempfile::tempdir().unwrap();
    let layer = directory.path().join("distro.erofs");
    fs::write(&layer, b"layer").unwrap();
    let launch = SandboxLaunch::new(
        vec![SandboxLayer::new(
            LayerRole::Distro,
            layer.to_str().unwrap(),
            EROFS_UUID,
        )],
        "scratch.ext4",
        SandboxSettings::default(),
    )
    .unwrap();
    assert!(launch.network().is_none());
    let launch = launch.with_network(Some(proxy_network(Some(ProxyScheme::Http))));
    assert_eq!(
        launch.network(),
        Some(&proxy_network(Some(ProxyScheme::Http)))
    );
    assert_eq!(launch.plan().network(), launch.network());
    // The plan of the binding keeps the network.
    let binding = DistroBinding::verify(launch.distro()).unwrap();
    let bound = launch.bound_plan(&binding).unwrap();
    assert_eq!(bound.network(), launch.network());
    assert_eq!(bound.proxy_url().as_deref(), Some("http://10.0.0.1:3128"));
    assert!(launch.with_network(None).plan().network().is_none());
}
