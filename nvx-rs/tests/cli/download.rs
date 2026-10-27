//! The scenarios of `nvx-rs download` and of the download that `run` and `sandbox` start
//! themselves, which reach no network: their roots are no Git checkout, or have a `.git` that is
//! no repository, so a download fails before it queries GitHub.

use std::fs;

use crate::harness::{LAYER, OPENVMM, Root, SCRATCH};

/// The files of a test root that a release installs.
const INSTALLED: [&str; 6] = [
    OPENVMM,
    "build/vmlinux",
    "build/initramfs.cpio.gz",
    "build/openvmm.provenance.json",
    "build/vmlinux.provenance.json",
    "build/initramfs.provenance.json",
];

/// Returns a root that is a checkout of NVX, with its `SOURCE-MANIFEST.json` and a `.git` that is
/// no repository, without the files of `removed`.
fn checkout(removed: &[&str]) -> Root {
    let root = Root::new();
    root.write("SOURCE-MANIFEST.json", "{}\n");
    fs::create_dir(root.below(".git")).unwrap();
    for relative in removed {
        root.remove(relative);
    }
    root
}

/// Asserts that no download left its staging directory in the root's `build/`.
fn assert_no_staging(root: &Root) {
    let Ok(entries) = fs::read_dir(root.below("build")) else {
        return;
    };
    for entry in entries {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().starts_with(".nvx-download-"),
            "{name:?}"
        );
    }
}

#[test]
fn run_downloads_the_release_of_a_checkout_without_artifacts() {
    let root = checkout(&INSTALLED);
    for arguments in [
        vec!["run", "--dry-run"],
        vec!["sandbox", "run", "--layer", LAYER, "--scratch", SCRATCH],
    ] {
        let outcome = root.nvx_rs(&arguments);
        assert_eq!(outcome.status, Some(1), "{}", outcome.describe());
        assert!(outcome.stdout.is_empty(), "{}", outcome.describe());
        let stderr = outcome.stderr();
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{}", outcome.describe());
        assert_eq!(
            lines[0],
            format!(
                ">> {} holds no NVX artifacts, so nvx-rs downloads its release; set \
                 NVX_AUTO_DOWNLOAD=0 to skip that",
                root.text()
            ),
        );
        assert!(
            lines[1].starts_with(
                "error[unavailable]: download needs a Git checkout to find its release: "
            ),
            "{}",
            outcome.describe()
        );
        assert_no_staging(&root);
    }
}

#[test]
fn run_downloads_nothing_over_some_artifacts() {
    let root = checkout(&["build/vmlinux"]);
    let before = root.snapshot();
    for arguments in [
        vec!["run", "--dry-run"],
        vec!["sandbox", "run", "--layer", LAYER, "--scratch", SCRATCH],
    ] {
        let outcome = root.nvx_rs(&arguments);
        assert_eq!(outcome.status, Some(1), "{}", outcome.describe());
        assert!(outcome.stdout.is_empty(), "{}", outcome.describe());
        let stderr = outcome.stderr();
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{}", outcome.describe());
        let kernel = root.below("build/vmlinux");
        assert!(
            lines[0].starts_with(&format!(
                "warning: {} does not exist, but {} holds other NVX artifacts, such as ",
                kernel.display(),
                root.text()
            )) && lines[0].ends_with("`nvx-rs download`"),
            "{}",
            outcome.describe()
        );
        assert!(
            lines[1].starts_with("error[artifact-missing]: ")
                && lines[1].ends_with(&format!("{}", kernel.display())),
            "{}",
            outcome.describe()
        );
        assert_eq!(root.snapshot(), before, "{arguments:?}");
    }
}

#[test]
fn start_downloads_the_release_of_a_checkout_without_artifacts() {
    // A provision runs no artifact, so it needs none.
    let root = checkout(&[]);
    let outcome = root.nvx_rs(&crate::provision(&root, "state", ""));
    assert_eq!(outcome.status, Some(0), "{}", outcome.describe());
    for relative in INSTALLED {
        root.remove(relative);
    }
    let outcome = root.nvx_rs(&crate::lifecycle("start", &root, "state"));
    assert_eq!(outcome.status, Some(1), "{}", outcome.describe());
    let stderr = outcome.stderr();
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{}", outcome.describe());
    assert!(
        lines[0].starts_with(&format!(">> {} holds no NVX artifacts", root.text())),
        "{}",
        outcome.describe()
    );
    assert!(
        lines[1]
            .starts_with("error[unavailable]: download needs a Git checkout to find its release: "),
        "{}",
        outcome.describe()
    );
    assert_no_staging(&root);
}

#[test]
fn the_variable_turns_downloads_off_with_0() {
    let root = checkout(&INSTALLED);
    let outcome = root.nvx_rs_with(&["run", "--dry-run"], &[("NVX_AUTO_DOWNLOAD", "0")]);
    outcome.assert_error("artifact-missing", &["OpenVMM", root.text()]);
    for value in ["no", "true"] {
        let outcome = root.nvx_rs_with(&["run", "--dry-run"], &[("NVX_AUTO_DOWNLOAD", value)]);
        outcome.assert_error(
            "unsupported",
            &["NVX_AUTO_DOWNLOAD must be 0 or 1", &format!("{value:?}")],
        );
    }
    // A checkout that holds its artifacts never reads the variable.
    let root = checkout(&[]);
    let outcome = root.nvx_rs_with(&["run", "--dry-run"], &[("NVX_AUTO_DOWNLOAD", "no")]);
    assert_eq!(outcome.status, Some(0), "{}", outcome.describe());
}

#[test]
fn roots_that_are_no_git_checkout_download_nothing() {
    let root = Root::new();
    for relative in INSTALLED {
        root.remove(relative);
    }
    root.write("SOURCE-MANIFEST.json", "{}\n");
    let outcome = root.nvx_rs(&["run", "--dry-run"]);
    outcome.assert_error("artifact-missing", &["OpenVMM"]);
    // Nor does `artifacts`, which runs nothing.
    let root = checkout(&INSTALLED);
    let outcome = root.nvx_rs(&["artifacts"]);
    outcome.assert_success();
    assert_no_staging(&root);
}

#[test]
fn download_installs_into_git_checkouts_of_nvx_alone() {
    let root = Root::new();
    let outcome = root.nvx_rs(&["download"]);
    outcome.assert_error(
        "unavailable",
        &["is not an NVX repository checkout", "SOURCE-MANIFEST.json"],
    );
    root.write("SOURCE-MANIFEST.json", "{}\n");
    let outcome = root.nvx_rs(&["download"]);
    outcome.assert_error(
        "unavailable",
        &["download needs a Git checkout to find its release"],
    );
    assert_no_staging(&root);
    root.write("bin/openvmm{exe}", "openvmm\n");
    let outcome = root.nvx_rs(&["download"]);
    outcome.assert_error(
        "unsupported",
        &[
            "download installs a release into a repository checkout",
            "extracted release",
        ],
    );
}

#[test]
fn download_installs_the_packages_of_this_host() {
    let root = checkout(&[]);
    let (other, host) = if cfg!(windows) {
        ("kvm", "windows")
    } else {
        ("whp", "linux")
    };
    let outcome = root.nvx_rs(&["download", "--hypervisor", other]);
    outcome.assert_error(
        "unsupported",
        &[&format!("{other} is not supported on {host}")],
    );
}
