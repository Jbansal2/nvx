//! OpenVMM command lines: their options, each with its values, and the options with which the
//! launches of `nvx-rs` start OpenVMM, as its documentation describes them, from which the tests
//! derive what they expect.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::harness::{HYPERVISOR, Root};

/// The options of OpenVMM that take no value.
const FLAGS: [&str; 2] = ["--single-process", "--microvm-control-auth-stdin"];

/// The kernel command-line tokens with which the sandbox profile selects itself and attaches the
/// distro layer of the tests on the first sandbox block device and the scratch disk on the
/// second.
pub(crate) const SANDBOX: [&str; 3] = [
    "nvx_sandbox=1",
    "nvx_layer=distro,0xd0003000,erofs:11111111-1111-1111-1111-111111111111",
    "nvx_scratch=0xd0006000,ext4",
];

/// The kernel command-line tokens of the default workload of a sandbox: `/bin/sh` as the
/// entrypoint, and `nvx-sandbox` as the hostname.
pub(crate) const WORKLOAD: [&str; 2] = ["nvx_entrypoint=/bin/sh", "nvx_hostname=nvx-sandbox"];

/// The options of an OpenVMM command line, each with its values in the order in which the
/// command line gives them, or with none for a flag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Options(BTreeMap<String, Vec<String>>);

impl Options {
    /// Returns the options of `arguments`, the arguments of OpenVMM after its program, every one
    /// of which is an option or the value of the option before it.
    pub(crate) fn parse(arguments: &[String]) -> Self {
        let mut options = Self::default();
        let mut iterator = arguments.iter();
        while let Some(name) = iterator.next() {
            assert!(
                name.starts_with("--"),
                "OpenVMM takes no positional argument {name:?}: {arguments:?}"
            );
            let values = options.0.entry(name.clone()).or_default();
            if !FLAGS.contains(&name.as_str()) {
                let value = iterator
                    .next()
                    .unwrap_or_else(|| panic!("{name} has no value: {arguments:?}"));
                values.push(value.clone());
            }
        }
        options
    }

    /// Returns these options with `name` given once with each of `values`, in order, in place of
    /// the values that it had, if any.
    pub(crate) fn with<S: Into<String>>(
        mut self,
        name: &str,
        values: impl IntoIterator<Item = S>,
    ) -> Self {
        self.0.insert(
            name.to_owned(),
            values.into_iter().map(Into::into).collect(),
        );
        self
    }

    /// Returns these options with the flag `name`.
    pub(crate) fn flag(self, name: &str) -> Self {
        self.with(name, Vec::<String>::new())
    }

    /// Returns these options with `tokens`, joined by spaces, as the kernel command line.
    pub(crate) fn kernel<S: AsRef<str>>(self, tokens: &[S]) -> Self {
        let tokens: Vec<&str> = tokens.iter().map(AsRef::as_ref).collect();
        self.with("--cmdline", [tokens.join(" ")])
    }

    /// Returns these options with the kernel command line of a sandbox: the user's `--cmdline`,
    /// `user`, if any, then the tokens that select the sandbox profile, then `tokens`, those of
    /// its workload, its limits, and its shares.
    pub(crate) fn sandbox_kernel<S: AsRef<str>>(self, user: &str, tokens: &[S]) -> Self {
        let mut line = user.to_owned();
        for token in SANDBOX
            .iter()
            .copied()
            .chain(tokens.iter().map(AsRef::as_ref))
        {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(token);
        }
        self.with("--cmdline", [line])
    }

    /// Returns these options with the placeholders of each value replaced as `root` replaces
    /// them.
    pub(crate) fn expanded(&self, root: &Root) -> Self {
        Self(
            self.0
                .iter()
                .map(|(name, values)| {
                    (
                        name.clone(),
                        values.iter().map(|value| root.expand(value)).collect(),
                    )
                })
                .collect(),
        )
    }

    /// Asserts that `actual` has these options, with the placeholders of their values replaced as
    /// `root` replaces them, and no other, each with the same values in the same order.
    pub(crate) fn assert_matches(&self, root: &Root, actual: &Self, context: &str) {
        let expected = self.expanded(root);
        if expected == *actual {
            return;
        }
        let names: BTreeSet<&String> = expected.0.keys().chain(actual.0.keys()).collect();
        let mut differences = String::new();
        for name in names {
            let (wanted, got) = (expected.0.get(name), actual.0.get(name));
            if wanted != got {
                writeln!(differences, "  {name}: expected {wanted:?}, got {got:?}").unwrap();
            }
        }
        panic!("{context}: the OpenVMM options differ:\n{differences}");
    }
}

/// Returns the options with which a one-shot run of the minimal sandbox, `sandbox run --layer
/// LAYER --scratch SCRATCH`, starts OpenVMM, with the paths of the images that a dry run shows.
pub(crate) fn one_shot() -> Options {
    Options::default()
        .with("--machine", ["microvm"])
        .with(
            "--microvm-sandbox-block",
            [
                "distro:file:{root/distro.erofs},ro",
                "scratch:file:{root/scratch.ext4}",
            ],
        )
        .with("--microvm-workload-identity", ["65534:65534"])
        .with("--microvm-lifecycle", ["one-shot"])
        .flag("--single-process")
        .with("--hypervisor", [HYPERVISOR])
        .with("--memory", ["256M"])
        .with("--kernel", ["{root/build/vmlinux}"])
        .with("--initrd", ["{root/build/initramfs.cpio.gz}"])
        .sandbox_kernel("", &WORKLOAD)
}

/// Returns the options with which `nvx-rs run` cold-boots its default guest, Alpine Linux.
pub(crate) fn cold_boot() -> Options {
    Options::default()
        .flag("--single-process")
        .with("--machine", ["microvm"])
        .with("--processors", ["1"])
        .with("--hypervisor", [HYPERVISOR])
        .with("--memory", ["128M"])
        .with("--kernel", ["{root/build/vmlinux}"])
        .with("--initrd", ["{root/build/initramfs.cpio.gz}"])
}

/// Returns the options with which `nvx-rs run --restore-snapshot {root/snapshot}` restores the
/// snapshot, without a guest kernel or initramfs.
pub(crate) fn restore() -> Options {
    Options::default()
        .flag("--single-process")
        .with("--machine", ["microvm"])
        .with("--processors", ["1"])
        .with("--hypervisor", [HYPERVISOR])
        .with("--restore-snapshot", ["{root/snapshot}"])
}

/// Returns the name of the aggregate child at `index` that the guest binds at `target`: the
/// index, a hyphen, and the first 32 hexadecimal digits of the SHA-256 digest of the target, which
/// a snapshot pins.
pub(crate) fn child(index: usize, target: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(target.as_bytes());
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{index}-{hex}")
}

/// Returns the `nvx_share=` token that binds the aggregate child at `index` at `target`, with the
/// access `access`, `ro` or `rw`, and as a file if `file`.
pub(crate) fn share_token(index: usize, target: &str, access: &str, file: bool) -> String {
    let suffix = if file { ",file" } else { "" };
    format!(
        "nvx_share={},{target},{access}{suffix}",
        child(index, target)
    )
}
