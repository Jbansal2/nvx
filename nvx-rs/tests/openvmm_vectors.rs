//! Compares the copies of OpenVMM's control-session protocol vectors in `tests/vectors/openvmm/`
//! with the files of the OpenVMM submodule that they come from.
//!
//! The protocol's tests read the copies, because the `nvx-rs` job cannot check out the submodule,
//! whose deploy key fork pull requests lack. This test is ignored by default: the NVX CLI jobs,
//! which check out the submodule, run it, and so does an OpenVMM pin promotion.

use std::fs;
use std::path::Path;

/// The files of OpenVMM's `vm/devices/virtio/virtio_console/test_data/` that
/// `tests/vectors/openvmm/` copies.
const FILES: [&str; 2] = [
    "control_session_protocol_cases.txt",
    "control_session_protocol_vectors.txt",
];

#[test]
#[ignore = "needs the OpenVMM submodule, which the NVX CLI jobs check out"]
fn the_copies_match_the_submodules_files() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let originals = crate_root.join("../openvmm/vm/devices/virtio/virtio_console/test_data");
    let copies = crate_root.join("tests/vectors/openvmm");
    let mut copied: Vec<_> = fs::read_dir(&copies)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    copied.sort();
    assert_eq!(copied, FILES, "tests/vectors/openvmm/ holds other files");
    for file in FILES {
        let original = fs::read(originals.join(file)).unwrap_or_else(|error| {
            panic!(
                "cannot read {file} of the OpenVMM submodule, which `scripts/nvx.py init` checks \
                 out: {error}"
            )
        });
        let copy = fs::read(copies.join(file)).unwrap();
        assert!(
            copy == original,
            "tests/vectors/openvmm/{file} differs from the OpenVMM submodule's: copy the \
             submodule's unchanged, and record its commit in tests/vectors/README.md"
        );
    }
}
