//! The runtime of the adapter's VMs takes NVX's artifacts from a repository checkout or an
//! extracted release, and their runtime identity from the build provenance beside them.
#![cfg(feature = "host")]

use std::fs;
use std::path::{Path, PathBuf};

use nvx::ErrorKind;
use nvx::host::store::{ArtifactIdentity, IdentityPart, RuntimeIdentity};
use runtime_adapter::runtime::{GUEST_BUILD, Runtime};

/// The digests that the provenance of the test's artifacts records.
const OPENVMM: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
const KERNEL: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const INITRAMFS: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

/// The provenance records, each with its field and digest.
const RECORDS: [(&str, &str, &str); 3] = [
    ("openvmm.provenance.json", "executable_sha256", OPENVMM),
    ("vmlinux.provenance.json", "kernel_sha256", KERNEL),
    ("initramfs.provenance.json", "initramfs_sha256", INITRAMFS),
];

/// Creates an empty directory for the test `name`.
fn directory(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("runtime")
        .join(name);
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    directory
}

/// Lays out NVX's artifacts in `root`: in the release layout if `release`, and otherwise in a
/// repository checkout's, with NVX's manifest, and returns the directory of the provenance.
fn lay_out(root: &Path, release: bool) -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../SOURCE-MANIFEST.json");
    fs::copy(manifest, root.join("SOURCE-MANIFEST.json")).unwrap();
    let provenance = if release {
        // A release is told apart by its built artifacts.
        fs::create_dir_all(root.join("guest")).unwrap();
        fs::write(root.join("guest/vmlinux"), b"kernel").unwrap();
        root.join("provenance")
    } else {
        root.join("build")
    };
    fs::create_dir_all(&provenance).unwrap();
    for (name, field, digest) in RECORDS {
        let record = format!("{{\"format\": 1, \"{field}\": \"{digest}\", \"other\": true}}");
        fs::write(provenance.join(name), record).unwrap();
    }
    provenance
}

/// Returns the identity of the runtime of the test's artifacts with the guest agent's build
/// `guest_build`.
fn identity(guest_build: &str) -> RuntimeIdentity {
    let sha256 = |digest| ArtifactIdentity::sha256(digest).unwrap();
    let initramfs = format!(
        "sha256:{}+runtime-adapter-guest/{guest_build}",
        INITRAMFS.to_ascii_lowercase()
    );
    RuntimeIdentity::new(
        sha256(OPENVMM),
        sha256(KERNEL),
        ArtifactIdentity::new(initramfs).unwrap(),
    )
}

#[test]
fn the_runtime_identity_comes_from_the_build_provenance_of_either_layout() {
    for (name, release, guest) in [("repository", false, "build"), ("release", true, "guest")] {
        let root = directory(name);
        lay_out(&root, release);
        let runtime = Runtime::from_dir(&root, GUEST_BUILD).unwrap();
        assert_eq!(runtime.identity, identity(GUEST_BUILD), "{name}");
        // The VMs boot a copy of NVX's Alpine initramfs.
        let root = fs::canonicalize(&root).unwrap();
        let initrd = fs::canonicalize(runtime.artifacts.initrd.parent().unwrap()).unwrap();
        assert_eq!(initrd, root.join(guest), "{name}");
        assert_eq!(
            runtime.artifacts.initrd.file_name().unwrap(),
            "initramfs.cpio.gz"
        );
    }
}

#[test]
fn another_build_of_the_guest_agent_is_another_runtime() {
    let root = directory("another-build");
    lay_out(&root, false);
    let ours = Runtime::from_dir(&root, GUEST_BUILD).unwrap().identity;
    let theirs = Runtime::from_dir(&root, "another-build").unwrap().identity;
    assert_eq!(theirs, identity("another-build"));
    assert_eq!(ours.differences(&theirs), [IdentityPart::Initramfs]);

    // A build that an artifact identity cannot hold fails.
    for build in ["with space", &"x".repeat(64)] {
        let error = Runtime::from_dir(&root, build).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{build:?}: {error}");
    }
}

#[test]
fn provenance_that_does_not_record_a_digest_fails() {
    let root = directory("invalid");
    let provenance = lay_out(&root, false);
    let path = provenance.join("vmlinux.provenance.json");
    for (record, problem) in [
        (None, "cannot be read"),
        (Some("{\"format\": 1,"), "is not JSON"),
        (Some(r#"{"kernel_sha256": "11"}"#), "is not in format 1"),
        (
            Some(r#"{"format": 2, "kernel_sha256": "11"}"#),
            "is not in format 1",
        ),
        (Some(r#"{"format": 1}"#), "lacks kernel_sha256"),
        (
            Some(r#"{"format": 1, "kernel_sha256": 1}"#),
            "lacks kernel_sha256",
        ),
        (
            Some(r#"{"format": 1, "kernel_sha256": "11"}"#),
            "has an invalid kernel_sha256",
        ),
    ] {
        match record {
            Some(record) => fs::write(&path, record).unwrap(),
            None => fs::remove_file(&path).unwrap(),
        }
        let error = Runtime::from_dir(&root, GUEST_BUILD).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unavailable, "{record:?}: {error}");
        let message = format!("the build provenance {} {problem}", path.display());
        assert_eq!(error.message(), message, "{record:?}");
    }
}
