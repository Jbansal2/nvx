//! The host program plans a VM with a layered root with NVX's typed plan for an adapter's own
//! guest, composes OpenVMM's arguments without NVX's managed lifecycle, records what it launches,
//! with the bindings that the store stages, and refuses options that do not make a command. The
//! tests need no hypervisor.
#![cfg(feature = "host")]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nvx::Hypervisor;
use nvx::host::sandbox::SandboxPlan;
use nvx::protocol::root::{ImageFormat, RootImage, RootLayout, RootUpper};
use nvx::uuid::Uuid;
use runtime_adapter::layered::{Bindings, LaunchRecord, LayeredLaunch, RECORD_NAME, SANDBOX_TOKEN};
use runtime_adapter::root::RootConfig;
use runtime_adapter::staged::Staged;
use serde_json::{Value, json};

/// Returns a directory of the test `name`, empty, below Cargo's temporary directory.
fn directory(name: &str) -> PathBuf {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    directory
}

/// Writes a file of `length` bytes at `path`, and returns the path.
fn image(path: PathBuf, length: usize) -> PathBuf {
    fs::write(&path, vec![0; length]).unwrap();
    path
}

/// Returns the identity that the tests expect of their images.
fn identity() -> Uuid {
    Uuid::parse("0a490905-41be-ed5f-984e-63eb7e5e20b1").unwrap()
}

#[test]
fn a_layered_launch_plans_its_blocks_and_boot_tokens_with_the_adapters_plan() {
    let directory = directory("layered-plan");
    let distro = image(directory.join("distro.erofs"), 3 * 512);
    let scratch = image(directory.join("scratch.ext4"), 8 * 512);
    let launch = LayeredLaunch::new(
        &distro,
        ImageFormat::Erofs,
        identity(),
        Some(&scratch),
        None,
    )
    .unwrap();
    let config = RootConfig {
        distro_sectors: Some(3),
        scratch_sectors: Some(8),
        ..RootConfig::default()
    };
    assert_eq!(launch.config, config);
    assert_eq!(launch.bindings, Bindings::default());
    let layout = RootLayout {
        image: RootImage::erofs(Some(identity())),
        upper: RootUpper::Scratch,
    };
    assert_eq!(launch.plan.layout(), layout);
    // The adapter's plan holds none of the settings of NVX's sandbox profile.
    assert_eq!(launch.plan.settings(), None);

    // The kernel command line hands the VM to the init agent, which the guest agent replaces, and
    // carries the boot tokens of the root, which the guest reads back, and nothing of the
    // profile's.
    let command_line = launch.kernel_command_line().unwrap();
    assert_eq!(
        command_line,
        format!("{SANDBOX_TOKEN} {}", layout.tokens().join(" "))
    );
    assert_eq!(
        RootLayout::parse(command_line.as_bytes()).unwrap(),
        Some(layout)
    );

    // OpenVMM's arguments: the plan's, which attach the image read-only and the scratch, with no
    // workload identity, then the launch's, with no managed lifecycle.
    let (kernel, initramfs) = (directory.join("vmlinux"), directory.join("initramfs"));
    let report = directory.join("outcome.json");
    let arguments = launch
        .openvmm_arguments(
            Hypervisor::Kvm,
            &kernel,
            &initramfs,
            "/run/control.sock",
            &report,
        )
        .unwrap();
    let plan = launch.plan.openvmm_arguments().unwrap();
    let blocks = [
        "--machine",
        "microvm",
        "--microvm-sandbox-block",
        &format!("distro:file:{},ro", distro.display()),
        "--microvm-sandbox-block",
        &format!("scratch:file:{}", scratch.display()),
    ];
    assert_eq!(plan, blocks);
    let (planned, rest) = arguments.split_at(plan.len());
    assert_eq!(planned, plan.iter().map(OsString::from).collect::<Vec<_>>());
    let expected: [OsString; 18] = [
        "--single-process".into(),
        "--hypervisor".into(),
        "kvm".into(),
        "--memory".into(),
        "256M".into(),
        "--kernel".into(),
        kernel.into(),
        "--initrd".into(),
        initramfs.into(),
        "--cmdline".into(),
        command_line.into(),
        "--virtio-console".into(),
        "none".into(),
        "--microvm-control-console".into(),
        "listen=/run/control.sock".into(),
        "--microvm-control-auth-stdin".into(),
        "--microvm-report".into(),
        report.into(),
    ];
    assert_eq!(rest, expected);
}

#[test]
fn a_layered_launch_passes_what_the_guest_checks_as_it_is() {
    let directory = directory("layered-options");
    // An image that is not a whole number of sectors has no size, an upper in RAM no scratch, and
    // a runtime directory replaces the default as it is, so that the guest checks it.
    let distro = image(directory.join("distro.img"), 1000);
    let launch = LayeredLaunch::new(
        &distro,
        ImageFormat::Gpt,
        identity(),
        None,
        Some("run/relative"),
    )
    .unwrap();
    let config = RootConfig {
        runtime: "run/relative".to_owned(),
        ..RootConfig::default()
    };
    assert_eq!(launch.config, config);
    assert_eq!(launch.plan.layout().image, RootImage::gpt(Some(identity())));
    assert_eq!(launch.plan.layout().upper, RootUpper::Ram);
    let arguments = launch.plan.openvmm_arguments().unwrap();
    assert!(
        !arguments
            .iter()
            .any(|argument| argument.starts_with("scratch:")),
        "{arguments:?}"
    );

    // A relative image is planned by its absolute path, since OpenVMM runs in the sandbox's store.
    let relative = distro.strip_prefix(std::env::current_dir().unwrap());
    if let Ok(relative) = relative {
        let launch =
            LayeredLaunch::new(relative, ImageFormat::Gpt, identity(), None, None).unwrap();
        assert_eq!(launch.plan.distro().path(), distro);
    }

    // An image that does not exist is refused.
    let missing = directory.join("missing.erofs");
    let error =
        LayeredLaunch::new(&missing, ImageFormat::Erofs, identity(), None, None).unwrap_err();
    assert!(
        error.to_string().contains("distro EROFS layer not found"),
        "{error}"
    );
}

#[test]
fn a_launch_records_what_it_launched() {
    let directory = directory("layered-record");
    let distro = image(directory.join("distro.erofs"), 512);
    let scratch = image(directory.join("scratch.ext4"), 512);
    let mut launch = LayeredLaunch::new(
        &distro,
        ImageFormat::Erofs,
        identity(),
        Some(&scratch),
        None,
    )
    .unwrap();
    let record = LaunchRecord {
        kernel_command_line: "nvx_sandbox=1",
        layered: Some(&launch),
    };
    let json = record.to_json().unwrap();
    assert_eq!(json["format"], 1);
    assert_eq!(json["mode"], "layered");
    assert_eq!(json["kernelCommandLine"], "nvx_sandbox=1");
    let config = String::from_utf8(launch.config.encode()).unwrap();
    assert_eq!(json["rootConfiguration"], config.as_str());
    let plan: SandboxPlan = serde_json::from_value(json["plan"].clone()).unwrap();
    assert_eq!(plan, launch.plan);
    // Without staged images, the launch has no bindings to record.
    assert_eq!(json["bindings"], json!({"distro": null, "scratch": null}));

    // The record replaces an earlier one in the store.
    fs::write(directory.join(RECORD_NAME), "earlier").unwrap();
    record.write(&directory).unwrap();
    let written = fs::read_to_string(directory.join(RECORD_NAME)).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&written).unwrap(), json);

    // The bindings that the store stages for the launch's images, in their serde forms.
    let staged = Staged::stage(&distro, ImageFormat::Erofs, identity(), Some(&scratch)).unwrap();
    launch.bindings = staged.bindings(&launch.plan);
    let record = LaunchRecord {
        kernel_command_line: "nvx_sandbox=1",
        layered: Some(&launch),
    };
    let expected = json!({
        "distro": serde_json::to_value(&staged.distro.binding).unwrap(),
        "scratch": serde_json::to_value(&staged.scratch.as_ref().unwrap().binding).unwrap(),
    });
    assert_eq!(record.to_json().unwrap()["bindings"], expected);

    let blockless = LaunchRecord {
        kernel_command_line: "hostname=nvx-sandbox",
        layered: None,
    };
    let expected = json!({
        "format": 1,
        "mode": "blockless",
        "kernelCommandLine": "hostname=nvx-sandbox",
        "plan": null,
        "bindings": null,
        "rootConfiguration": null,
    });
    assert_eq!(blockless.to_json().unwrap(), expected);
}

#[test]
fn the_host_program_refuses_options_that_do_not_make_a_command() {
    let launch = ["launch", "store", "--guest-agent", "agent"];
    let uuid = "0a490905-41be-ed5f-984e-63eb7e5e20b1";
    let cases: [(&[&str], &str); 24] = [
        (
            &["--distro", "erofs:image", "--upper", "ram"],
            "--distro needs --distro-identity",
        ),
        (
            &["--distro", "erofs:image", "--distro-identity", uuid],
            "--distro needs --upper",
        ),
        (&["--upper", "ram"], "--upper needs --distro"),
        (
            &["--distro-identity", uuid],
            "--distro-identity needs --distro",
        ),
        (&["--runtime-dir", "/run/a"], "--runtime-dir needs --distro"),
        (
            &["--overlay-mode", "untrusted-lowers"],
            "--overlay-mode needs --distro",
        ),
        (
            &["--scratch-journal", "forbidden"],
            "--scratch-journal needs --distro",
        ),
        (
            &[
                "--distro",
                "erofs:image",
                "--distro-identity",
                uuid,
                "--upper",
                "ram",
                "--scratch-journal",
                "allowed",
            ],
            "--scratch-journal needs --upper scratch:PATH",
        ),
        (
            &["--first-partition-bound", "4096"],
            "--first-partition-bound needs --distro",
        ),
        (
            &[
                "--distro",
                "erofs:image",
                "--distro-identity",
                uuid,
                "--upper",
                "ram",
                "--first-partition-bound",
                "4096",
            ],
            "--first-partition-bound needs --distro gpt:PATH",
        ),
        (
            &["--first-partition-bound", "0"],
            "--first-partition-bound takes a positive number of bytes, not \"0\"",
        ),
        (
            &["--first-partition-bound", "64K"],
            "--first-partition-bound takes a positive number of bytes, not \"64K\"",
        ),
        (
            &["--overlay-mode", "trusted"],
            "--overlay-mode takes trusted-lowers or untrusted-lowers",
        ),
        (
            &["--scratch-journal", "none"],
            "--scratch-journal takes allowed or forbidden",
        ),
        (
            &["--distro", "squashfs:image"],
            "--distro takes FORMAT:PATH",
        ),
        (&["--distro", "erofs:"], "--distro takes FORMAT:PATH"),
        (&["--distro", "image"], "--distro takes FORMAT:PATH"),
        (&["--upper", "tmpfs"], "--upper takes scratch:PATH or ram"),
        (
            &["--upper", "scratch:"],
            "--upper takes scratch:PATH or ram",
        ),
        (
            &["--distro-identity", "identity"],
            "--distro-identity takes a UUID",
        ),
        (
            &["--upper", "ram", "--upper", "ram"],
            "unexpected option \"--upper\"",
        ),
        (&["mounts"], "unexpected argument \"mounts\" of launch"),
        (&["--hypervisor", "qemu"], "qemu"),
        (&["--distro"], "\"--distro\" needs a value"),
    ];
    let mut commands = cases
        .iter()
        .map(|(options, problem)| ([&launch[..], options].concat(), *problem))
        .collect::<Vec<_>>();
    let stage = ["stage", "store", "--distro", "erofs:image"];
    let stage_cases: [(&[&str], &str); 7] = [
        (&[], "stage needs --distro-identity"),
        (
            &["--distro-identity", uuid, "--upper", "ram"],
            "--upper of stage takes scratch:PATH, not \"ram\"",
        ),
        (
            &["--upper", "scratch:"],
            "--upper of stage takes scratch:PATH, not \"scratch:\"",
        ),
        (
            &["--guest-agent", "agent"],
            "unexpected option \"--guest-agent\" of stage",
        ),
        (
            &["--runtime-dir", "/run/a"],
            "unexpected option \"--runtime-dir\" of stage",
        ),
        (
            &["--guest-build", "build"],
            "unexpected option \"--guest-build\" of stage",
        ),
        (&["image"], "unexpected argument \"image\" of stage"),
    ];
    commands.extend(
        stage_cases
            .iter()
            .map(|(options, problem)| ([&stage[..], options].concat(), *problem)),
    );
    commands.extend([
        (vec!["stage"], "stage needs a sandbox store"),
        (vec!["stage", "store"], "stage needs --distro"),
        (vec!["probe", "store"], "probe needs a probe"),
        (
            vec!["probe", "store", "Mounts"],
            "the probe's name \"Mounts\"",
        ),
        (vec!["probe", "store", "mounts "], "is empty"),
        (
            vec!["probe", "store", "mounts", "--guest-agent", "agent"],
            "unexpected option \"--guest-agent\" of probe",
        ),
        (
            vec!["stop", "store", "mounts"],
            "unexpected argument \"mounts\" of stop",
        ),
        (
            vec!["reattach", "store", "--distro", "erofs:image"],
            "unexpected option \"--distro\" of reattach",
        ),
    ]);
    for (arguments, problem) in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_runtime-adapter-host"))
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(problem) && stderr.contains("usage: runtime-adapter-host"),
            "{arguments:?}: {stderr}"
        );
    }
}
