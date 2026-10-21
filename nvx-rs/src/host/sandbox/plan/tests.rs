//! Tests of the typed plan: every combination of format and upper, the guest's reading of the
//! command lines that plans render, their budget, and their checks.

use std::fs;
use std::path::Path;

use serde_json::json;

use super::*;
use crate::ErrorKind;
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
