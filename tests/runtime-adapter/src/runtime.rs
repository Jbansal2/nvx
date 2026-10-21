//! The runtime of the adapter's VMs: NVX's artifacts, whose initramfs boots the guest agent in
//! place of NVX's managed agent, and the runtime identity that NVX's supervisor records for a
//! launch and checks when it reattaches.
//!
//! The identity comes from the build provenance that `nvx.py` records beside NVX's artifacts,
//! never from their contents: the SHA-256 digest of each artifact, from when it was built. A
//! repository checkout keeps the provenance in `build/`, where `nvx.py download` also installs a
//! release's, and an extracted release keeps it in `provenance/`:
//!
//! | Artifact | Provenance | Digest |
//! | --- | --- | --- |
//! | OpenVMM | `openvmm.provenance.json` | `executable_sha256` |
//! | Kernel | `vmlinux.provenance.json` | `kernel_sha256` |
//! | Initramfs | `initramfs.provenance.json` | `initramfs_sha256` |
//!
//! The VMs boot a copy of NVX's initramfs that holds the guest agent; see [`crate::initramfs`].
//! Its identity names both: NVX's initramfs and the guest agent's build,
//! `sha256:DIGEST+runtime-adapter-guest/BUILD`. The guest agent has no provenance of its own, so
//! the caller names its build, which is this crate's version, [`GUEST_BUILD`], unless the caller
//! ships another. A host program that ships another build of the guest agent runs another
//! runtime, so it finds the VMs of this one mismatched.

use std::fs;
use std::path::Path;

use nvx::host::artifacts::{ArtifactDir, Artifacts, Layout};
use nvx::host::store::{ArtifactIdentity, RuntimeIdentity};
use nvx::{Error, Result};
use serde_json::Value;

/// The guest agent's build that a host program ships unless it names another: this crate's
/// version.
pub const GUEST_BUILD: &str = env!("CARGO_PKG_VERSION");

/// The version of the provenance records that this module reads.
const PROVENANCE_FORMAT: u64 = 1;
/// The directory of the provenance records in an extracted release.
const RELEASE_PROVENANCE_DIR: &str = "provenance";

/// An artifact's provenance record: its file name, and the field that holds the artifact's
/// digest.
struct Provenance {
    /// The record's file name.
    name: &'static str,
    /// The field that holds the artifact's SHA-256 digest.
    digest: &'static str,
}

/// The provenance of the OpenVMM executable.
const OPENVMM: Provenance = Provenance {
    name: "openvmm.provenance.json",
    digest: "executable_sha256",
};
/// The provenance of the guest kernel.
const KERNEL: Provenance = Provenance {
    name: "vmlinux.provenance.json",
    digest: "kernel_sha256",
};
/// The provenance of NVX's initramfs.
const INITRAMFS: Provenance = Provenance {
    name: "initramfs.provenance.json",
    digest: "initramfs_sha256",
};

/// NVX's artifacts, and the runtime identity of the adapter's VMs that boot them with the guest
/// agent.
#[derive(Debug, Clone)]
pub struct Runtime {
    /// The OpenVMM executable, the guest kernel, and NVX's initramfs, which the VMs boot a copy
    /// of, with the guest agent in it.
    pub artifacts: Artifacts,
    /// The runtime identity of the VMs.
    pub identity: RuntimeIdentity,
}

impl Runtime {
    /// Returns the runtime of NVX's artifacts in `directory`, a repository checkout or an
    /// extracted release, which [`Artifacts::from_dir`] finds there, with the guest agent's build
    /// `guest_build`, as the [module documentation](self) describes.
    ///
    /// Fails as [`Artifacts::from_dir`] does, with
    /// [`ErrorKind::Unavailable`](nvx::ErrorKind::Unavailable) if a provenance record is missing,
    /// is not JSON in the format that this module reads, or lacks its artifact's digest, and with
    /// [`ErrorKind::Unsupported`](nvx::ErrorKind::Unsupported) if the identity of the initramfs
    /// with `guest_build` is not an artifact identity.
    pub fn from_dir(directory: impl AsRef<Path>, guest_build: &str) -> Result<Self> {
        let directory = directory.as_ref();
        let artifacts = Artifacts::from_dir(directory)?;
        let layout = ArtifactDir::from_dir(directory)?;
        let initramfs = digest(&layout, &INITRAMFS)?;
        let identity = RuntimeIdentity::new(
            digest(&layout, &OPENVMM)?,
            digest(&layout, &KERNEL)?,
            ArtifactIdentity::new(format!("{initramfs}+runtime-adapter-guest/{guest_build}"))?,
        );
        Ok(Self {
            artifacts,
            identity,
        })
    }
}

/// Returns the identity of the artifact whose digest the provenance record `provenance` of the
/// artifacts in `layout` holds.
fn digest(layout: &ArtifactDir, provenance: &Provenance) -> Result<ArtifactIdentity> {
    let path = match layout.layout() {
        Layout::Repository => layout.artifact(provenance.name),
        Layout::Release => layout
            .root()
            .join(RELEASE_PROVENANCE_DIR)
            .join(provenance.name),
    };
    let unavailable = |problem: &str| {
        Error::unavailable(format!("the build provenance {} {problem}", path.display()))
    };
    let text = fs::read_to_string(&path)
        .map_err(|error| unavailable("cannot be read").with_source(error))?;
    let record: Value = serde_json::from_str(&text)
        .map_err(|error| unavailable("is not JSON").with_source(error))?;
    let format = record.get("format").and_then(Value::as_u64);
    if format != Some(PROVENANCE_FORMAT) {
        return Err(unavailable(&format!(
            "is not in format {PROVENANCE_FORMAT}"
        )));
    }
    let digest = record
        .get(provenance.digest)
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable(&format!("lacks {}", provenance.digest)))?;
    ArtifactIdentity::sha256(digest).map_err(|error| {
        unavailable(&format!("has an invalid {}", provenance.digest)).with_source(error)
    })
}
