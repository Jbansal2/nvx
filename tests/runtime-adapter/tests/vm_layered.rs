//! The host program launches VMs with a layered root, which the guest agent's worker assembles
//! through `nvx::guest::root` in a process of its own, never PID 1, on a real hypervisor, through
//! public APIs only.
//!
//! Each scenario of the table that [`scenarios!`] declares is an ignored test, which launches a VM
//! with a [`Root`] and checks what it [`Expect`]s: a root that the guest assembles, which the
//! scenario probes and the stop tears down, or the stage of the root that fails. A new scenario is
//! a new row, with its own checks, through the probes of the worker.
//!
//! The tests boot VMs, so they are ignored. Besides what the `common` module lists, they read the
//! fixtures that NVX's own layered scenarios use, from NVX's artifacts in `NVX_ARTIFACTS_DIR`:
//!
//! - the Ubuntu EROFS image, `ubuntu-distro.erofs`, and its manifest, which holds its UUID;
//! - the scratch template, `ubuntu-smoke-scratch.ext4`, an empty ext4 file system that NVX's CI
//!   makes with the guest artifacts, of which each scenario boots a copy.
//!
//! ```text
//! cargo test --locked --features host --test vm_layered -- --ignored
//! ```
#![cfg(feature = "host")]

mod common;

use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use nvx::host::artifacts::{ArtifactDir, Artifacts, Guest};
use runtime_adapter::layered::RECORD_NAME;
use runtime_adapter::root::{DEFAULT_RUNTIME, JournalPolicy, OverlayMode, RootConfig, RootStage};
use serde_json::{Value, json};

use common::{Printed, Sandbox};

/// The scratch template among NVX's artifacts.
const SCRATCH_TEMPLATE: &str = "ubuntu-smoke-scratch.ext4";
/// The exit status of the host program's command whose guest reported that a stage of the root
/// failed.
const ROOT_FAILED: i32 = 4;
/// The size of the guest's pages, in bytes.
const PAGE: u64 = 4096;
/// How many of the bytes available in an upper a file that fills it may leave, which the file's
/// own blocks of metadata take.
const FULL_SLACK: u64 = 1 << 20;

/// The fixtures of the scenarios, among NVX's artifacts.
struct Fixtures {
    /// NVX's Ubuntu EROFS image.
    distro: PathBuf,
    /// The image's UUID, from its manifest.
    identity: String,
    /// The scratch template.
    scratch: PathBuf,
}

impl Fixtures {
    /// Finds the fixtures among NVX's artifacts in `NVX_ARTIFACTS_DIR`.
    fn find() -> Self {
        let directory = env::var_os(Artifacts::ENV_DIR)
            .unwrap_or_else(|| panic!("{} must name NVX's artifacts", Artifacts::ENV_DIR));
        let artifacts = ArtifactDir::from_dir(directory).unwrap();
        let distro = artifacts.distro_layer(Guest::Ubuntu).unwrap();
        let manifest = artifacts.distro_manifest(Guest::Ubuntu).unwrap();
        let scratch = artifacts.artifact(SCRATCH_TEMPLATE);
        for (path, fixture) in [
            (&distro, "the Ubuntu EROFS image"),
            (&manifest, "the manifest of the Ubuntu EROFS image"),
            (
                &scratch,
                "the scratch template, an empty ext4 file system, which `mkfs.ext4` makes",
            ),
        ] {
            assert!(path.is_file(), "{fixture} is missing: {}", path.display());
        }
        let manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest).unwrap())
            .expect("the manifest is JSON");
        let identity = manifest["uuid"]
            .as_str()
            .expect("the manifest holds the image's UUID")
            .to_owned();
        Self {
            distro,
            identity,
            scratch,
        }
    }
}

/// The image of a scenario's root.
#[derive(Clone, Copy, Debug)]
enum Image {
    /// NVX's Ubuntu EROFS image.
    Erofs,
}

/// The identity that a scenario's launch expects of the image.
#[derive(Clone, Copy, Debug)]
enum Identity {
    /// The image's own, from its manifest.
    Own,
    /// Another, which the image does not have.
    Other,
}

/// The upper of a scenario's root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Upper {
    /// A copy of the scratch template.
    Scratch,
    /// RAM, without a scratch.
    Ram,
}

/// The layered root of a scenario's launch.
#[derive(Clone, Copy, Debug)]
struct Root {
    /// The image.
    image: Image,
    /// The identity that the launch expects of the image.
    identity: Identity,
    /// The upper.
    upper: Upper,
    /// The guest's runtime directory, as the launch passes it, unless the default.
    runtime: Option<&'static str>,
    /// The overlay's mode, as the launch names it, unless the guest's default.
    overlay: Option<OverlayMode>,
    /// The scratch's journal policy, as the launch names it, unless the guest's default.
    journal: Option<JournalPolicy>,
}

/// The root of the scenarios unless they say otherwise: NVX's EROFS image, with its own identity,
/// over a copy of the scratch template, with the guest's defaults.
const ROOT: Root = Root {
    image: Image::Erofs,
    identity: Identity::Own,
    upper: Upper::Scratch,
    runtime: None,
    overlay: None,
    journal: None,
};

impl Root {
    /// Returns the identity that the launch expects of the image of `fixtures`.
    fn identity(&self, fixtures: &Fixtures) -> String {
        match self.identity {
            Identity::Own => fixtures.identity.clone(),
            Identity::Other => other_identity(&fixtures.identity),
        }
    }

    /// Returns the launch's options of the root, with the `fixtures` and the `scratch` image, for a
    /// root over a scratch.
    fn options(&self, fixtures: &Fixtures, scratch: &Path) -> Vec<OsString> {
        let Image::Erofs = self.image;
        let mut distro = OsString::from("erofs:");
        distro.push(&fixtures.distro);
        let identity = self.identity(fixtures);
        let upper = match self.upper {
            Upper::Scratch => {
                let mut upper = OsString::from("scratch:");
                upper.push(scratch);
                upper
            }
            Upper::Ram => "ram".into(),
        };
        let mut options = [
            "--distro".into(),
            distro,
            "--distro-identity".into(),
            identity.into(),
            "--upper".into(),
            upper,
        ]
        .to_vec();
        if let Some(runtime) = self.runtime {
            options.extend(["--runtime-dir".into(), runtime.into()]);
        }
        if let Some(mode) = self.overlay {
            options.extend(["--overlay-mode".into(), mode.as_str().into()]);
        }
        if let Some(policy) = self.journal {
            options.extend(["--scratch-journal".into(), policy.as_str().into()]);
        }
        options
    }

    /// Returns the overlay's mode, the guest's default unless the launch names another.
    fn overlay_mode(&self) -> OverlayMode {
        self.overlay.unwrap_or(OverlayMode::TrustedLowers)
    }
}

/// Returns a UUID other than `identity`, which differs in its last digit.
fn other_identity(identity: &str) -> String {
    let (start, last) = identity.split_at(identity.len() - 1);
    format!("{start}{}", if last == "0" { "1" } else { "0" })
}

/// What a scenario expects of its VM.
enum Expect {
    /// The guest assembles the root, the check probes the VM, and the stop tears the root down,
    /// which leaves a scratch unmounted.
    Ready(fn(&mut Vm<'_>)),
    /// The guest assembles the root, the check keeps it busy, and the stop reports the teardown
    /// that failed with this problem, which leaves a scratch mounted when the VM ends.
    TeardownFails(fn(&mut Vm<'_>), &'static str),
    /// The guest reports that the stage failed with this problem, and the VM ends with its
    /// status, before the guest mounted a scratch.
    Fails(RootStage, &'static str),
}

/// A scenario: a VM with a layered root, and what the scenario expects of it.
struct Scenario {
    /// The root of the VM.
    root: Root,
    /// What the scenario expects.
    expect: Expect,
}

/// A VM of a scenario, whose guest assembled its root.
struct Vm<'a> {
    /// The scenario's sandbox.
    sandbox: &'a mut Sandbox,
    /// What the launch printed.
    launched: Printed,
    /// The guest's runtime directory, below which it assembled the root.
    runtime: &'static str,
    /// The scenario's root.
    root: Root,
    /// The root configuration that the launch sent.
    config: RootConfig,
}

impl Vm<'_> {
    /// Runs `probes` in the VM's root, and returns what they found, each fact as `PROBE.KEY`.
    fn probe(&mut self, probes: &[&str]) -> Printed {
        let probes = probes.iter().map(OsStr::new).collect::<Vec<_>>();
        let printed = self.sandbox.run("probe", &probes, 0);
        assert_eq!(printed["reattached"], "live");
        assert_eq!(printed["pid"], self.launched["pid"]);
        printed
    }
}

/// Declares the table of scenarios: each row, `NAME: SCENARIO;`, is an ignored test, `NAME`, which
/// runs `SCENARIO`.
macro_rules! scenarios {
    ($($(#[doc = $doc:literal])* $name:ident: $scenario:expr;)*) => {
        $(
            $(#[doc = $doc])*
            #[test]
            #[ignore = "boots a VM; see the module documentation for what it needs"]
            fn $name() {
                run(stringify!($name), $scenario);
            }
        )*
    };
}

scenarios! {
    /// An EROFS image over an ext4 scratch, of the identity that the launch expects: the merged
    /// root's contents and mounts, a copy-up of metadata alone, the guest's disks, the agent's and
    /// the workload's cgroups, PID 1's unrelated child, and a clean teardown.
    erofs_over_scratch: Scenario {
        root: ROOT,
        expect: Expect::Ready(check_erofs_over_scratch),
    };
    /// The image over the scratch, in the untrusted-lowers mode, with a journal that the launch
    /// allows: a copy-up of the data too, and a rename of a lower directory that fails.
    erofs_over_scratch_with_untrusted_lowers: Scenario {
        root: Root {
            overlay: Some(OverlayMode::UntrustedLowers),
            journal: Some(JournalPolicy::Allowed),
            ..ROOT
        },
        expect: Expect::Ready(check_root),
    };
    /// The image over a tmpfs in RAM, of the kernel's default size, without a scratch device.
    erofs_over_ram: Scenario {
        root: Root { upper: Upper::Ram, ..ROOT },
        expect: Expect::Ready(check_root),
    };
    /// The image over a tmpfs in RAM, in the untrusted-lowers mode.
    erofs_over_ram_with_untrusted_lowers: Scenario {
        root: Root {
            upper: Upper::Ram,
            overlay: Some(OverlayMode::UntrustedLowers),
            ..ROOT
        },
        expect: Expect::Ready(check_root),
    };
    /// A scratch that a file fills, which then refuses writes until the file is gone.
    full_scratch_refuses_writes: Scenario {
        root: ROOT,
        expect: Expect::Ready(check_full_upper),
    };
    /// A tmpfs that a file fills, at half of the guest's memory, which then refuses writes until
    /// the file is gone.
    full_ram_upper_refuses_writes: Scenario {
        root: Root { upper: Upper::Ram, ..ROOT },
        expect: Expect::Ready(check_full_upper),
    };
    /// A scratch with a journal, which the launch forbids, and the assembly refuses.
    forbidden_journal_fails_the_assembly: Scenario {
        root: Root { journal: Some(JournalPolicy::Forbidden), ..ROOT },
        expect: Expect::Fails(
            RootStage::Assembly,
            "has an ext4 journal, which the assembly forbids",
        ),
    };
    /// An image of another identity than the launch expects, which the assembly refuses.
    other_identity_fails_the_assembly: Scenario {
        root: Root { identity: Identity::Other, ..ROOT },
        expect: Expect::Fails(RootStage::Assembly, "the distro layer's UUID is "),
    };
    /// A relative runtime directory, which the guest refuses with the configuration.
    invalid_configuration_fails_its_stage: Scenario {
        root: Root { runtime: Some("run/runtime-adapter"), ..ROOT },
        expect: Expect::Fails(RootStage::Configuration, "which is not absolute"),
    };
    /// A root that a probe holds open, whose teardown fails.
    busy_root_fails_the_teardown: Scenario {
        root: ROOT,
        expect: Expect::TeardownFails(hold_root, "failed to unmount the overlay: "),
    };
    /// Host paths mapped beneath the assembled root, as an adapter maps them. Through the root:
    /// zero mappings, then a table in order, each with its access, `nosuid`, and `nodev`, on
    /// targets created on the overlay. Through mappers of the adapter's own: the refusal of a
    /// link and of a magic link at each component, of the wrong kinds, of a target that would be
    /// created inside another mapping, and of reserved targets, the runtime's, the container
    /// root's, and the adapter's own; and a read-only mapping that is never writable. The stop
    /// unmounts the root's mappings before the overlay.
    mappings_apply_beneath_the_root: Scenario {
        root: ROOT,
        expect: Expect::Ready(check_mappings),
    };
    /// A mapping through a symbolic link in the root, which the root refuses, and after which it
    /// refuses every mapping.
    a_refused_mapping_latches_the_root: Scenario {
        root: ROOT,
        expect: Expect::Ready(check_refused_mapping),
    };
}

/// Runs the scenario `name`, `scenario`.
fn run(name: &str, scenario: Scenario) {
    let fixtures = Fixtures::find();
    let mut sandbox = Sandbox::new(name);
    let root = scenario.root;
    let scratch = sandbox.root.join("scratch.ext4");
    let over_scratch = root.upper == Upper::Scratch;
    if over_scratch {
        fs::copy(&fixtures.scratch, &scratch).unwrap();
    }
    let options = root.options(&fixtures, &scratch);
    let options = options.iter().map(OsString::as_os_str).collect::<Vec<_>>();
    let (check, failure) = match scenario.expect {
        Expect::Fails(stage, problem) => {
            let launched = sandbox.launch(&options, ROOT_FAILED);
            assert_failed(&launched, stage, problem);
            assert_eq!(launched["stopped"], "graceful");
            // The launch recorded what it launched, with the root configuration that it sent, which
            // the guest refused, or accepted before a later stage failed.
            check_record(&sandbox, &fixtures, &root, &scratch);
            // The launch ended: no runtime record names the VM.
            assert_eq!(sandbox.record(), None);
            assert!(
                !(over_scratch && needs_recovery(&scratch)),
                "the guest mounted the scratch"
            );
            return;
        }
        Expect::Ready(check) => (check, None),
        Expect::TeardownFails(check, problem) => (check, Some(problem)),
    };
    let launched = sandbox.launch(&options, 0);
    assert_eq!(launched["root"], "ready");
    let config = check_record(&sandbox, &fixtures, &root, &scratch);
    let vmm = sandbox
        .vmm()
        .expect("the VM runs after its launcher exited");
    let mut vm = Vm {
        sandbox: &mut sandbox,
        launched: launched.clone(),
        runtime: root.runtime.unwrap_or(DEFAULT_RUNTIME),
        root,
        config,
    };
    check(&mut vm);

    let status = if failure.is_some() { ROOT_FAILED } else { 0 };
    let stopped = sandbox.run("stop", &[], status);
    assert_eq!(stopped["reattached"], "live");
    assert_eq!(stopped["pid"], launched["pid"]);
    assert_eq!(stopped["stopped"], "graceful");
    assert!(vmm.has_exited().unwrap());
    assert_eq!(
        sandbox.record(),
        None,
        "the stop cleared the runtime record"
    );
    match failure {
        None => {
            assert!(!stopped.contains_key("root"), "{stopped:?}");
            assert_eq!(stopped["outcome"], "success 0");
            assert_eq!(stopped["teardown"], "complete");
            assert!(
                !(over_scratch && needs_recovery(&scratch)),
                "the stop left the scratch mounted"
            );
        }
        Some(problem) => {
            assert_failed(&stopped, RootStage::Teardown, problem);
            assert!(
                !over_scratch || needs_recovery(&scratch),
                "the failed teardown unmounted the scratch"
            );
        }
    }
}

/// Checks that a command printed that the guest reported that `stage` failed with `problem`, and
/// that the VM then ended with the stage's status and a complete teardown.
fn assert_failed(printed: &Printed, stage: RootStage, problem: &str) {
    assert_eq!(printed["root"], "failed", "{printed:?}");
    assert_eq!(printed["stage"], stage.as_str(), "{printed:?}");
    assert!(printed["problem"].contains(problem), "{printed:?}");
    let outcome = format!("guest-exit {}", stage.exit_status());
    assert_eq!(printed["outcome"], outcome, "{printed:?}");
    assert_eq!(printed["teardown"], "complete", "{printed:?}");
}

/// Checks what the launch recorded in the sandbox's store: a VM with the layered `root` of
/// `fixtures`, over `scratch` or RAM, the image of the identity that the launch expects, the boot
/// tokens of its plan, and the root configuration that the host sent, whether or not the guest
/// accepted it, which it returns.
fn check_record(sandbox: &Sandbox, fixtures: &Fixtures, root: &Root, scratch: &Path) -> RootConfig {
    let record = fs::read_to_string(sandbox.store.join(RECORD_NAME)).unwrap();
    let record: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["format"], 1);
    assert_eq!(record["mode"], "layered");
    let plan = &record["plan"];
    let identity = root.identity(fixtures);
    assert_eq!(plan["distro"]["format"], "erofs");
    assert_eq!(plan["distro"]["identity"], identity.as_str());
    let path = |value: &Value| PathBuf::from(value.as_str().unwrap());
    assert_eq!(path(&plan["distro"]["path"]), fixtures.distro);
    let upper = match root.upper {
        Upper::Scratch => {
            assert_eq!(plan["upper"]["kind"], "scratch");
            assert_eq!(path(&plan["upper"]["path"]), scratch);
            "nvx_scratch=0xd0006000,ext4"
        }
        Upper::Ram => {
            assert_eq!(plan["upper"], json!({"kind": "ram"}));
            "nvx_overlay_upper=ramfs"
        }
    };
    let tokens = record["kernelCommandLine"]
        .as_str()
        .unwrap()
        .split(' ')
        .collect::<BTreeSet<_>>();
    let layer = format!("nvx_layer=distro,0xd0003000,erofs:{identity}");
    for token in ["nvx_sandbox=1", &layer, upper] {
        assert!(tokens.contains(token), "{token} in {tokens:?}");
    }
    let uppers = tokens
        .iter()
        .filter(|token| {
            token.starts_with("nvx_scratch=") || token.starts_with("nvx_overlay_upper=")
        })
        .count();
    assert_eq!(uppers, 1, "{tokens:?}");
    let sectors = |path: &Path| Some(fs::metadata(path).unwrap().len() / 512);
    let config = RootConfig {
        runtime: root.runtime.unwrap_or(DEFAULT_RUNTIME).to_owned(),
        distro_sectors: sectors(&fixtures.distro),
        scratch_sectors: (root.upper == Upper::Scratch)
            .then(|| sectors(scratch))
            .flatten(),
        overlay_mode: root.overlay,
        scratch_journal: root.journal,
        ..RootConfig::default()
    };
    let sent = String::from_utf8(config.encode()).unwrap();
    assert_eq!(record["rootConfiguration"], sent.as_str());
    config
}

/// Returns whether the ext4 file system at `path` needs its journal recovered: whether a mount
/// left its superblock's `needs_recovery` feature set, which a clean unmount clears.
fn needs_recovery(path: &Path) -> bool {
    let mut superblock = [0; 1024];
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(1024)).unwrap();
    file.read_exact(&mut superblock).unwrap();
    let magic = u16::from_le_bytes([superblock[0x38], superblock[0x39]]);
    assert_eq!(
        magic,
        0xef53,
        "{} holds an ext4 file system",
        path.display()
    );
    let incompatible = u32::from_le_bytes(superblock[0x60..0x64].try_into().unwrap());
    incompatible & 0x4 != 0
}

/// Returns the options of a list of mount options, separated by commas.
fn options(list: &str) -> BTreeSet<&str> {
    list.split(',').collect()
}

/// Checks the root of a scenario's VM, which the guest assembled, as its upper and its overlay
/// mode make it: its mounts, its contents, a copy-up, and the guest's disks.
fn check_root(vm: &mut Vm<'_>) {
    let facts = vm.probe(&[
        "mounts",
        "contents",
        "copy-up usr/lib/os-release",
        "rename mnt",
        "devices",
    ]);
    let runtime = vm.runtime;
    let (upper, kind, other) = match vm.root.upper {
        Upper::Scratch => ("scratch", "ext4", "tmpfs"),
        Upper::Ram => ("tmpfs", "tmpfs", "scratch"),
    };

    // The image, read-only, under the overlay, whose upper and work directories are on the upper,
    // all once, below the runtime directory, where no other upper is mounted.
    for (mount, kind, flags) in [
        ("distro", "erofs", &["ro"][..]),
        (upper, kind, &["rw", "nosuid", "nodev"]),
        ("root", "overlay", &["rw", "nosuid", "nodev"]),
    ] {
        assert_eq!(facts[&format!("mounts.{mount}.count")], "1", "{mount}");
        assert_eq!(facts[&format!("mounts.{mount}.type")], kind, "{mount}");
        let found = options(&facts[&format!("mounts.{mount}.options")]);
        assert!(
            found.is_superset(&flags.iter().copied().collect()),
            "{mount}: {found:?}"
        );
    }
    assert_eq!(facts[&format!("mounts.{other}.count")], "0", "{other}");
    if vm.root.upper == Upper::Ram {
        // A tmpfs of the kernel's default size, whose root directory has mode 0755.
        let tmpfs = options(&facts["mounts.tmpfs.super"]);
        assert!(tmpfs.contains("mode=755"), "{tmpfs:?}");
        let sized = tmpfs.iter().any(|option| option.starts_with("size="));
        assert!(!sized, "{tmpfs:?}");
    }
    let layers = [
        format!("lowerdir={runtime}/layers/distro"),
        format!("upperdir={runtime}/{upper}/upper"),
        format!("workdir={runtime}/{upper}/work"),
    ];
    let overlay = options(&facts["mounts.root.super"]);
    for option in &layers {
        assert!(overlay.contains(option.as_str()), "{option} in {overlay:?}");
    }

    // The overlay's mode. Trusting its lowers, the overlay copies up a file's metadata alone,
    // which leaves the data in the image, and renames a lower directory, with the options that
    // the mode and metadata copy-up set. Otherwise, it copies up the data too, and refuses the
    // rename, with these options off.
    let trusting = ["metacopy=on", "redirect_dir=on", "xino=on"];
    let trusted = vm.root.overlay_mode() == OverlayMode::TrustedLowers;
    for option in trusting {
        assert_eq!(overlay.contains(option), trusted, "{option} in {overlay:?}");
    }
    let (data, rename) = if trusted {
        ("none", "allowed")
    } else {
        ("copied", "refused")
    };
    assert_eq!(facts["copy-up.upper.size"], facts["copy-up.lower.size"]);
    assert_eq!(facts["copy-up.upper.data"], data, "{facts:?}");
    assert_eq!(facts["copy-up.root.data"], "intact");
    assert_eq!(facts["rename.outcome"], rename, "{facts:?}");

    // The merged root: the image's files, and a file that the worker wrote, which reaches the
    // upper and not the image, which refuses writes.
    assert_eq!(facts["contents.os-release.id"], "ubuntu");
    assert_eq!(facts["contents.root.mode"], "755");
    assert_eq!(facts["contents.write.root"], "runtime-adapter");
    assert_eq!(facts["contents.write.upper"], "runtime-adapter");
    assert_eq!(facts["contents.write.lower"], "absent");
    assert_eq!(facts["contents.lower.write"], "refused");

    // The guest's disks, whatever their names: the image's, read-only, and the scratch's,
    // writable, unless the upper is in RAM.
    let mut disks = facts["devices.disks"]
        .split(' ')
        .map(|disk| disk.split_once(':').map_or(disk, |(_, size)| size))
        .collect::<Vec<_>>();
    disks.sort_unstable();
    let distro = format!("{}:ro", vm.config.distro_sectors.unwrap());
    let mut expected = vec![distro];
    expected.extend(
        vm.config
            .scratch_sectors
            .map(|sectors| format!("{sectors}:rw")),
    );
    expected.sort_unstable();
    assert_eq!(disks, expected, "{facts:?}");
}

/// Fills the upper of a scenario's root through the root, and checks that the upper refuses
/// writes once full, until the file that filled it is gone.
fn check_full_upper(vm: &mut Vm<'_>) {
    let facts = vm.probe(&["fill"]);
    let number = |fact: &str| facts[&format!("fill.{fact}")].parse::<u64>().unwrap();
    assert_eq!(facts["fill.error"], "ENOSPC", "{facts:?}");
    let (available, written) = (number("available"), number("written"));
    assert!(
        written <= available && available - written < FULL_SLACK,
        "{facts:?}"
    );
    assert_eq!(facts["fill.after"], "runtime-adapter");
    if vm.root.upper == Upper::Ram {
        // A tmpfs of the kernel's default size: half of the guest's memory, in whole pages.
        let pages = number("memory") / PAGE;
        assert_eq!(number("total"), pages / 2 * PAGE, "{facts:?}");
    }
}

/// Checks the VM of the `erofs_over_scratch` scenario: its root, the agent's and the workload's
/// cgroups, and the guest's processes.
fn check_erofs_over_scratch(vm: &mut Vm<'_>) {
    check_root(vm);
    let facts = vm.probe(&["cgroups", "processes"]);

    // The agent's and the workload's cgroups, siblings in the cgroup v2 hierarchy, with the
    // configuration's resource values, and no user namespaces.
    let config = &vm.config;
    assert_eq!(facts["cgroups.parent.type"], "cgroup2");
    assert_eq!(facts["cgroups.agent.exists"], "yes");
    assert_eq!(facts["cgroups.workload.exists"], "yes");
    let values = [
        ("cgroups.agent.memory.low", config.agent_memory_low),
        ("cgroups.workload.memory.max", config.workload_memory_max),
        ("cgroups.workload.pids.max", config.workload_pids_max),
    ];
    for (fact, value) in values {
        assert_eq!(facts[fact], value.unwrap().to_string(), "{fact}");
    }
    assert_eq!(facts["cgroups.workload.processes"], "0");
    let user_namespaces = facts["cgroups.user-namespaces"].as_str();
    assert!(
        ["0", "unavailable"].contains(&user_namespaces),
        "{user_namespaces}"
    );

    // The worker is not PID 1, but its child. PID 1's unrelated child runs on, untouched: in PID
    // 1's root directory and namespaces, like the worker, and in the agent's cgroup, into which
    // the bootstrap moved every process of the guest.
    let agent = Path::new(&config.agent_cgroup);
    let parent = agent.parent().unwrap();
    let agent = format!("/{}", agent.strip_prefix(parent).unwrap().display());
    assert_ne!(facts["processes.worker.pid"], "1");
    assert_eq!(facts["processes.worker.ppid"], "1");
    assert_eq!(facts["processes.sibling.ppid"], "1");
    let state = facts["processes.sibling.state"].as_str();
    assert!(["S", "R"].contains(&state), "{state}");
    let commands = [
        ("pid1", "init /dev/hvc2 layered"),
        ("worker", "worker /dev/hvc2"),
        ("sibling", "idle"),
    ];
    for (process, command) in commands {
        let found = &facts[&format!("processes.{process}.command")];
        let expected = format!("/sbin/runtime-adapter-guest {command}");
        assert!(found.starts_with(&expected), "{process}: {found}");
        assert_eq!(
            facts[&format!("processes.{process}.root")],
            "/",
            "{process}"
        );
        let namespaces = &facts[&format!("processes.{process}.namespaces")];
        assert_eq!(namespaces, "same", "{process}");
        assert_eq!(
            facts[&format!("processes.{process}.cgroup")],
            agent,
            "{process}"
        );
    }
    let sibling = &facts["processes.sibling.pid"];
    assert!(
        facts["processes.worker.command"].ends_with(&format!(" {sibling}")),
        "{facts:?}"
    );
}

/// Keeps the root of the `busy_root_fails_the_teardown` scenario busy.
fn hold_root(vm: &mut Vm<'_>) {
    let facts = vm.probe(&["hold"]);
    assert_eq!(facts["hold.held"], format!("{}/rootfs", vm.runtime));
}

/// Checks the VM of the `mappings_apply_beneath_the_root` scenario.
fn check_mappings(vm: &mut Vm<'_>) {
    let facts = vm.probe(&["map", "map-checks"]);
    let fact = |key: &str| facts[&format!("map.{key}")].as_str();

    // Zero mappings do no work; a table applies in order.
    assert_eq!((fact("zero"), fact("zero.mounts")), ("applied", "0"));
    assert_eq!(fact("table"), "applied");
    assert_eq!(
        fact("mounts"),
        "/srv/maps/dir,/srv/maps/dir/inner,/srv/maps/file.txt,/srv/maps/out"
    );
    // Each mapping has its access, `nosuid`, and `nodev`, and writes reach the sources of the
    // writable ones only, the one inside a read-only mapping included.
    for (name, access) in [
        ("dir", "ro"),
        ("inner", "rw"),
        ("file", "ro"),
        ("out", "rw"),
    ] {
        let found = options(fact(&format!("{name}.options")));
        for flag in [access, "nosuid", "nodev"] {
            assert!(found.contains(flag), "{name}: {found:?}");
        }
    }
    assert_eq!((fact("dir.read"), fact("dir.write")), ("source", "refused"));
    assert_eq!((fact("file.read"), fact("file.write")), ("file", "refused"));
    for name in ["inner", "out"] {
        let written = (
            fact(&format!("{name}.write")),
            fact(&format!("{name}.source")),
        );
        assert_eq!(written, ("allowed", "runtime-adapter"), "{name}");
    }
    // The missing targets were created on the overlay, in its upper.
    assert_eq!(
        (fact("upper.directory"), fact("upper.file")),
        ("yes", "yes")
    );
    assert_eq!(fact("latched"), "no");

    let check = |key: &str| facts[&format!("map-checks.{key}")].as_str();
    // No link or magic link at any component leads a mapping anywhere.
    for key in [
        "link.a",
        "link.b",
        "link.new",
        "link.up",
        "magic.self",
        "magic.thread-self",
        "magic.root",
        "magic.cwd",
        "magic.fd",
    ] {
        assert_eq!(check(key), "link", "{key}");
    }
    assert_eq!(check("kind.directory"), "target-kind");
    assert_eq!(check("kind.file"), "target-kind");
    // A mapping may go onto what an earlier one shows, but creates nothing inside it.
    assert_eq!(check("nested.onto"), "applied");
    assert_eq!(check("nested.create"), "foreign /srv/checks/m/new");
    assert_eq!(check("nested.source"), "absent");
    assert_eq!(check("nested.teardown"), "complete");
    // The runtime's, the container root's, and the adapter's own reserved targets, and the
    // ancestors of reserved trees, but not what is below a reserved path.
    for key in [
        "run",
        "run-nvx",
        "time",
        "time-below",
        "proc",
        "sys",
        "dev",
        "agent",
        "machine-id",
        "etc",
        "adapter-tree",
        "adapter-ancestor",
        "adapter-path",
    ] {
        assert_eq!(check(&format!("reserved.{key}")), "reserved", "{key}");
    }
    assert_eq!(check("reserved.adapter-below"), "applied");
    assert_eq!(check("reserved.created"), "absent");
    // A read-only mapping is restricted before it is attached, so never writable.
    assert_eq!(check("read-only.attaches"), "200");
    assert_eq!(check("read-only.flags"), "ro,nosuid,nodev");
    assert_eq!(check("read-only.writable"), "never");
    assert_eq!(check("read-only.source"), "source");
    // Nothing went outside the root, and the checks unmounted what they mapped.
    assert_eq!(check("outside.entries"), "0");
    assert_eq!(check("outside.mounts"), "0");
    assert_eq!(check("left"), "0");
}

/// Checks the VM of the `a_refused_mapping_latches_the_root` scenario.
fn check_refused_mapping(vm: &mut Vm<'_>) {
    let facts = vm.probe(&["map-refused"]);
    let fact = |key: &str| facts[&format!("map-refused.{key}")].as_str();
    assert_eq!(fact("through-link"), "link /srv/link");
    assert_eq!(fact("latched"), "yes");
    assert_eq!(fact("later"), "latched");
    assert_eq!(fact("later.target"), "absent");
    assert_eq!(fact("mounts"), "0");
    assert_eq!(fact("outside"), "0");
}
