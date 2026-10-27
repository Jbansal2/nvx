//! The tests of the installation of a package into a checkout.

use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::contract::{
    CONTROL_CONTRACT_REVISION, CONTROL_SESSION_PROTOCOL_VERSION, MICROVM_ABI_VERSION,
};

/// Returns the manifest of a package that declares the guests of `sections` and, if
/// `compatible`, the contracts that this crate speaks.
fn manifest(sections: &[&str], compatible: bool) -> Value {
    let mut manifest = json!({
        "openvmm": {
            "microvm_abi_version": MICROVM_ABI_VERSION,
            "control_session_protocol_version": CONTROL_SESSION_PROTOCOL_VERSION,
            "control_contract_revision": if compatible { CONTROL_CONTRACT_REVISION } else { "other" },
        },
    });
    for section in sections {
        manifest[*section] = json!({});
    }
    manifest
}

/// Writes a package below `directory` with the guest artifacts of `sections`, which its manifest
/// declares, and returns it. Each file holds `package NAME`.
fn package(directory: &Path, sections: &[&str], compatible: bool) -> PathBuf {
    let root = directory.join("nvx-0.1.0-linux-kvm");
    let write = |relative: &str| {
        let path = relative
            .split('/')
            .fold(root.clone(), |path, part| path.join(part));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("package {relative}")).unwrap();
    };
    write(&format!("bin/{}", openvmm_executable()));
    write("bin/nvx-rs");
    write("provenance/nvx-rs.provenance.json");
    let manifest = manifest(sections, compatible);
    for name in declared_names(&manifest).unwrap() {
        write(&format!("guest/{name}"));
    }
    for name in PROVENANCE {
        write(&format!("provenance/{name}"));
    }
    fs::write(root.join(MANIFEST_NAME), manifest.to_string()).unwrap();
    root
}

/// Returns each file below `directory`, by its path relative to it with `/` separators, and its
/// content.
fn tree(directory: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    while let Some((path, relative)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                pending.push((entry.path(), child));
            } else {
                files.insert(child, fs::read_to_string(entry.path()).unwrap());
            }
        }
    }
    files
}

/// Returns a checkout below `directory` that holds a local build of `nvx-rs`, its provenance, an
/// earlier kernel, and an Azure Linux guest, which packages without its section remove.
fn checkout(directory: &Path) -> ArtifactDir {
    let root = directory.join("checkout");
    for relative in [
        "build/vmlinux",
        "build/initramfs-azurelinux.cpio.gz",
        "build/initramfs-azurelinux.cpio.gz.packages.json",
        "build/nvx-rs.provenance.json",
        "nvx-rs/target/release/nvx-rs",
    ] {
        let path = relative
            .split('/')
            .fold(root.clone(), |path, part| path.join(part));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("checkout {relative}")).unwrap();
    }
    ArtifactDir::repository(&root).unwrap()
}

#[test]
fn packages_install_into_the_layout_of_a_checkout() {
    let directory = tempfile::tempdir().unwrap();
    let package = package(directory.path(), &["linux", "alpine", "ubuntu"], true);
    let dir = checkout(directory.path());
    let plan = plan(&package, &dir).unwrap();
    assert!(plan.compatible());
    assert_eq!(
        commit(&plan, "0123456789abcdef", Mode::Replace).unwrap(),
        Installed::All
    );
    let executable = openvmm_executable();
    let expected: BTreeMap<String, String> = [
        (
            format!("openvmm/target/release/{executable}"),
            format!("package bin/{executable}"),
        ),
        (
            "build/vmlinux".to_owned(),
            "package guest/vmlinux".to_owned(),
        ),
        (
            "build/vmlinux.config".to_owned(),
            "package guest/vmlinux.config".to_owned(),
        ),
        (
            "build/initramfs.cpio.gz".to_owned(),
            "package guest/initramfs.cpio.gz".to_owned(),
        ),
        (
            "build/initramfs.cpio.gz.packages.json".to_owned(),
            "package guest/initramfs.cpio.gz.packages.json".to_owned(),
        ),
        (
            "build/initramfs-ubuntu.cpio.gz".to_owned(),
            "package guest/initramfs-ubuntu.cpio.gz".to_owned(),
        ),
        (
            "build/initramfs-ubuntu.cpio.gz.packages.json".to_owned(),
            "package guest/initramfs-ubuntu.cpio.gz.packages.json".to_owned(),
        ),
        (
            "build/ubuntu-distro.erofs".to_owned(),
            "package guest/ubuntu-distro.erofs".to_owned(),
        ),
        (
            "build/ubuntu-distro.erofs.manifest.json".to_owned(),
            "package guest/ubuntu-distro.erofs.manifest.json".to_owned(),
        ),
        (
            "build/openvmm.provenance.json".to_owned(),
            "package provenance/openvmm.provenance.json".to_owned(),
        ),
        (
            "build/vmlinux.provenance.json".to_owned(),
            "package provenance/vmlinux.provenance.json".to_owned(),
        ),
        (
            "build/initramfs.provenance.json".to_owned(),
            "package provenance/initramfs.provenance.json".to_owned(),
        ),
        // The checkout's own nvx-rs, and its provenance, stay.
        (
            "build/nvx-rs.provenance.json".to_owned(),
            "checkout build/nvx-rs.provenance.json".to_owned(),
        ),
        (
            "nvx-rs/target/release/nvx-rs".to_owned(),
            "checkout nvx-rs/target/release/nvx-rs".to_owned(),
        ),
    ]
    .into();
    assert_eq!(tree(dir.root()), expected);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(dir.openvmm()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}

#[test]
fn a_package_of_other_contracts_installs_but_is_reported() {
    let directory = tempfile::tempdir().unwrap();
    let package = package(directory.path(), &["linux", "alpine"], false);
    let dir = checkout(directory.path());
    assert!(!plan(&package, &dir).unwrap().compatible());
}

#[test]
fn a_package_without_a_file_fails_before_anything_changes() {
    for missing in [
        format!("bin/{}", openvmm_executable()),
        "guest/initramfs.cpio.gz.packages.json".to_owned(),
        "provenance/vmlinux.provenance.json".to_owned(),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), &["linux", "alpine"], true);
        fs::remove_file(
            missing
                .split('/')
                .fold(package.clone(), |path, part| path.join(part)),
        )
        .unwrap();
        let dir = checkout(directory.path());
        let before = tree(dir.root());
        let error = plan(&package, &dir).unwrap_err();
        assert_eq!(error.code(), Some(ErrorCode::Unavailable));
        assert!(
            error.message().unwrap().contains(" not found: "),
            "{missing}: {error:?}"
        );
        assert_eq!(tree(dir.root()), before, "{missing}");
    }
}

#[test]
fn a_failed_installation_restores_the_checkout() {
    let directory = tempfile::tempdir().unwrap();
    let package = package(directory.path(), &["linux", "alpine"], true);
    let dir = checkout(directory.path());
    let before = tree(dir.root());
    let plan = plan(&package, &dir).unwrap();
    // The kernel's own move fails once the checkout's OpenVMM and earlier kernel moved aside.
    let kernel = dir.kernel();
    let error = commit_with(&plan, "0123456789abcdef", Mode::Replace, &mut |from, to| {
        if to == kernel {
            Err(io::Error::other("injected failure"))
        } else {
            fs::rename(from, to)
        }
    })
    .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Io));
    assert!(
        error.message().unwrap().contains("injected failure"),
        "{error:?}"
    );
    assert_eq!(tree(dir.root()), before);
}

#[test]
fn files_that_cannot_move_are_copied() {
    let directory = tempfile::tempdir().unwrap();
    let package = package(directory.path(), &["linux", "alpine"], true);
    let dir = checkout(directory.path());
    let plan = plan(&package, &dir).unwrap();
    // A package on another file system cannot move beside its destination.
    let installed = commit_with(&plan, "0123456789abcdef", Mode::Replace, &mut |from, to| {
        if from.starts_with(&package) {
            Err(io::Error::other("crosses devices"))
        } else {
            fs::rename(from, to)
        }
    });
    assert_eq!(installed.unwrap(), Installed::All);
    assert_eq!(
        fs::read_to_string(dir.kernel()).unwrap(),
        "package guest/vmlinux"
    );
    assert!(package.join("guest").join("vmlinux").is_file());
}

#[test]
fn a_fresh_installation_fills_a_checkout_without_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let package = package(directory.path(), &["linux", "alpine"], true);
    let dir = ArtifactDir::repository(directory.path().join("checkout")).unwrap();
    let plan = plan(&package, &dir).unwrap();
    assert_eq!(
        commit(&plan, "0123456789abcdef", Mode::Fresh).unwrap(),
        Installed::All
    );
    assert_eq!(
        fs::read_to_string(dir.kernel()).unwrap(),
        "package guest/vmlinux"
    );
    assert!(dir.openvmm().is_file());
}

#[test]
fn a_file_that_appears_cancels_a_fresh_installation() {
    // A kernel that a local build wrote while the package downloaded stays, as does a guest
    // artifact that the package does not declare, and nothing of the package is installed.
    for appeared in ["vmlinux", "initramfs-azurelinux.cpio.gz"] {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), &["linux", "alpine"], true);
        let dir = ArtifactDir::repository(directory.path().join("checkout")).unwrap();
        let plan = plan(&package, &dir).unwrap();
        let path = dir.artifact(appeared);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "local build").unwrap();
        let before = tree(dir.root());
        assert_eq!(
            commit(&plan, "0123456789abcdef", Mode::Fresh).unwrap(),
            Installed::Cancelled(path),
            "{appeared}"
        );
        assert_eq!(tree(dir.root()), before, "{appeared}");
    }
}

#[test]
fn only_paths_that_name_nothing_do_not_exist() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("file");
    fs::write(&file, "file").unwrap();
    assert!(exists(&file).unwrap());
    assert!(exists(directory.path()).unwrap());
    assert!(!exists(&directory.path().join("missing")).unwrap());
    // A path below a file names nothing.
    assert!(!exists(&file.join("below")).unwrap());
    #[cfg(unix)]
    {
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path().join("missing"), &link).unwrap();
        assert!(exists(&link).unwrap());
    }
}

#[test]
fn manifests_declare_the_guest_artifacts_of_their_sections() {
    assert_eq!(
        declared_names(&manifest(&["linux", "alpine"], true)).unwrap(),
        [
            "vmlinux",
            "vmlinux.config",
            "initramfs.cpio.gz",
            "initramfs.cpio.gz.packages.json"
        ]
    );
    assert_eq!(
        declared_names(&manifest(&["azurelinux"], true)).unwrap(),
        [
            "initramfs-azurelinux.cpio.gz",
            "initramfs-azurelinux.cpio.gz.packages.json"
        ]
    );
    let error = declared_names(&json!({"openvmm": {}, "linux": "x"})).unwrap_err();
    assert_eq!(
        error.message(),
        Some("packaged source manifest does not declare guest artifacts")
    );
}

#[test]
fn a_package_without_a_manifest_ships_every_guest_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let package = package(
        directory.path(),
        &["linux", "alpine", "ubuntu", "azurelinux"],
        true,
    );
    fs::remove_file(package.join(MANIFEST_NAME)).unwrap();
    let dir = checkout(directory.path());
    let plan = plan(&package, &dir).unwrap();
    assert!(!plan.compatible());
    assert!(plan.removals.is_empty());
    assert_eq!(
        plan.items.len(),
        1 + all_guest_names().len() + PROVENANCE.len()
    );
}

#[test]
fn destinations_name_every_file_that_a_release_installs() {
    let directory = tempfile::tempdir().unwrap();
    let dir = ArtifactDir::repository(directory.path()).unwrap();
    let destinations = destinations(&dir);
    assert_eq!(destinations.len(), 14);
    assert_eq!(destinations[0], dir.openvmm());
    for name in [
        "vmlinux",
        "vmlinux.config",
        "initramfs-ubuntu.cpio.gz",
        "ubuntu-distro.erofs.manifest.json",
        "initramfs-azurelinux.cpio.gz.packages.json",
        "initramfs.provenance.json",
    ] {
        assert!(destinations.contains(&dir.artifact(name)), "{name}");
    }
}
