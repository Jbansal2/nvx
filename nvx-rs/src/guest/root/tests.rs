//! Tests of the root operations with the fake kernel, and with the kernel's interfaces, a cgroup
//! hierarchy, and the runtime directory in a temporary directory.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::kernel::{Call, FakeKernel, Operation, Paths};
use super::*;
use crate::guest::cgroup::Layout;

/// The base address of the distro device's MMIO window.
const DISTRO: u64 = 0xd000_0000;
/// The base address of the scratch device's MMIO window.
const SCRATCH: u64 = 0x1_d000_1000;
/// The UUID of the test's EROFS image.
const UUID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

/// A guest in a temporary directory, and the fake kernel that the operations get clones of.
struct Guest {
    /// The temporary directory.
    directory: tempfile::TempDir,
    /// The kernel's interfaces, below the temporary directory.
    paths: Paths,
    /// The fake kernel.
    kernel: FakeKernel,
}

impl Guest {
    /// Returns a guest with the distro device at window 0 and the scratch at window 1, both
    /// attached, and nothing else.
    fn new() -> Self {
        let guest = Self::bare();
        attach(guest.directory.path(), 0, "vda", 4096);
        attach(guest.directory.path(), 1, "vdb", 8192);
        guest
    }

    /// Returns a guest whose `/proc/iomem` declares the distro device's window 0 and the
    /// scratch's window 1, without their devices.
    fn bare() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths {
            proc: directory.path().join("proc"),
            sys: directory.path().join("sys"),
            dev: directory.path().join("dev"),
        };
        fs::create_dir_all(&paths.dev).unwrap();
        write(
            &paths.proc.join("iomem"),
            format!(
                "00000000-00000fff : Reserved\n  {DISTRO:08x}-{:08x} : virtio-mmio.0\n\
                 {SCRATCH:016x}-{:016x} : virtio-mmio.1\n",
                DISTRO + 0x1ff,
                SCRATCH + 0x1ff,
            ),
        );
        Self {
            directory,
            paths,
            kernel: FakeKernel::default(),
        }
    }

    /// Returns `relative`'s path below the temporary directory.
    fn path(&self, relative: &str) -> PathBuf {
        self.directory.path().join(relative)
    }

    /// Returns `relative`'s path below the temporary directory, as the fake kernel records it.
    fn text(&self, relative: &str) -> String {
        self.path(relative).display().to_string()
    }

    /// Returns an assembly of the guest's devices, in its runtime directory, `run/nvx`.
    fn assembly(&self) -> Assembly {
        Assembly {
            runtime: self.path("run/nvx"),
            distro: Device {
                mmio: DISTRO,
                sectors: None,
            },
            distro_uuid: None,
            scratch: Device {
                mmio: SCRATCH,
                sectors: None,
            },
            timeout: Duration::from_millis(100),
        }
    }

    /// Assembles `assembly` with a clone of the guest's kernel.
    fn assemble(&self, assembly: &Assembly) -> Result<Root, AssemblyError> {
        assemble_with(Box::new(self.kernel.clone()), &self.paths, assembly)
    }
}

/// Writes `contents` to `path`, after creating its parent directories.
fn write(path: &Path, contents: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// Attaches the block device `name`, of `sectors` sectors, below the MMIO window `index` of the
/// guest in `root`: its sysfs directory, its size, and its node.
fn attach(root: &Path, index: usize, name: &str, sectors: u64) {
    probe(root, index, name, sectors);
    write(&root.join("dev").join(name), "");
}

/// Creates the sysfs directory and size of the block device `name` below the MMIO window
/// `index` of the guest in `root`, without its node.
fn probe(root: &Path, index: usize, name: &str, sectors: u64) {
    let window = format!("sys/devices/virtio-mmio-cmdline/virtio-mmio.{index}");
    fs::create_dir_all(
        root.join(window)
            .join(format!("virtio{index}/block/{name}")),
    )
    .unwrap();
    write(
        &root.join("sys/class/block").join(name).join("size"),
        format!("{sectors}\n"),
    );
}

/// Returns an EROFS image's first 4 KiB, whose superblock holds `uuid`.
fn erofs_image(uuid: [u8; 16]) -> Vec<u8> {
    let mut image = vec![0; 4096];
    image[1024..1028].copy_from_slice(&0xE0F5_E1E2_u32.to_le_bytes());
    image[1024 + 48..1024 + 64].copy_from_slice(&uuid);
    image
}

/// Returns the error of a failed system call, as an operation reports it.
fn os_error(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

/// Returns a recorded mount.
fn mount_call(
    source: Option<&str>,
    target: &str,
    filesystem: Option<&str>,
    flags: MountFlags,
    data: Option<&str>,
) -> Call {
    Call::Mount {
        source: source.map(str::to_owned),
        target: target.to_owned(),
        filesystem: filesystem.map(str::to_owned),
        flags,
        data: data.map(str::to_owned),
    }
}

#[test]
fn assembly_mounts_the_image_and_the_scratch_under_the_overlay() {
    let guest = Guest::new();
    let root = guest.assemble(&guest.assembly()).unwrap();
    let runtime = guest.text("run/nvx");
    let options = format!(
        "lowerdir={runtime}/layers/distro,upperdir={runtime}/scratch/upper,\
         workdir={runtime}/scratch/work,metacopy=on,xino=on"
    );
    assert_eq!(
        guest.kernel.calls(),
        [
            Call::Flush(guest.text("dev/vda")),
            mount_call(
                Some(&guest.text("dev/vda")),
                &format!("{runtime}/layers/distro"),
                Some("erofs"),
                MountFlags::MS_RDONLY,
                None,
            ),
            Call::Flush(guest.text("dev/vdb")),
            mount_call(
                Some(&guest.text("dev/vdb")),
                &format!("{runtime}/scratch"),
                Some("ext4"),
                MountFlags::MS_NOSUID | MountFlags::MS_NODEV,
                None,
            ),
            mount_call(
                Some("overlay"),
                &format!("{runtime}/rootfs"),
                Some("overlay"),
                MountFlags::MS_NOSUID | MountFlags::MS_NODEV,
                Some(&options),
            ),
        ]
    );
    for directory in ["layers/distro", "scratch/upper", "scratch/work", "rootfs"] {
        assert!(
            guest.path("run/nvx").join(directory).is_dir(),
            "{directory}"
        );
    }
    assert_eq!(root.path(), guest.path("run/nvx/rootfs"));
    assert_eq!(root.runtime(), guest.path("run/nvx"));
    root.teardown().unwrap();
}

#[test]
fn devices_are_found_when_they_appear_and_missing_ones_time_out() {
    let guest = Guest::bare();
    attach(guest.directory.path(), 1, "vdb", 8192);
    let root_directory = guest.directory.path().to_owned();
    // The kernel probes the device first, then creates its node.
    guest.kernel.on_sleep(move |sleeps| match sleeps {
        1 => probe(&root_directory, 0, "vda", 4096),
        2 => write(&root_directory.join("dev/vda"), ""),
        _ => {}
    });
    let mut assembly = guest.assembly();
    assembly.timeout = Duration::from_secs(1);
    guest.assemble(&assembly).unwrap().teardown().unwrap();
    assert_eq!(guest.kernel.sleeps(), 2);

    // A timeout of 100 ms allows two more polls, 50 ms apart.
    let guest = Guest::bare();
    attach(guest.directory.path(), 0, "vda", 4096);
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert!(
        matches!(
            error.error(),
            Error::Missing {
                role: Role::Scratch,
                mmio: SCRATCH,
            }
        ),
        "{error:?}"
    );
    assert!(error.cleanup().is_none());
    assert_eq!(guest.kernel.sleeps(), 2);
    assert_eq!(
        error.to_string(),
        "the scratch device at MMIO 0x1d0001000 did not appear"
    );
    // The distro layer, which was mounted, is unmounted again.
    assert_eq!(
        guest.kernel.unmounts(),
        [guest.text("run/nvx/layers/distro")]
    );
}

#[test]
fn a_device_of_another_size_is_refused_before_it_is_flushed() {
    let guest = Guest::new();
    let mut assembly = guest.assembly();
    assembly.distro.sectors = Some(2048);
    let error = guest.assemble(&assembly).unwrap_err().into_parts().0;
    assert!(
        matches!(
            &error,
            Error::Size {
                role: Role::Distro,
                device,
                expected: 2048,
                actual: 4096,
            } if *device == guest.path("dev/vda")
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "the distro device {} has 4096 sectors, expected 2048",
            guest.text("dev/vda")
        )
    );
    assert!(guest.kernel.calls().is_empty());

    assembly.distro.sectors = Some(4096);
    assembly.scratch.sectors = Some(8192);
    guest.assemble(&assembly).unwrap().teardown().unwrap();
}

#[test]
fn the_expected_uuid_is_checked_in_the_superblock_before_the_mount() {
    let guest = Guest::new();
    fs::write(guest.path("dev/vda"), erofs_image(UUID)).unwrap();
    let mut assembly = guest.assembly();
    assembly.distro_uuid = Some(UUID);
    guest.assemble(&assembly).unwrap().teardown().unwrap();

    let guest = Guest::new();
    fs::write(guest.path("dev/vda"), erofs_image(UUID)).unwrap();
    let mut expected = UUID;
    expected[15] = 0xff;
    assembly = guest.assembly();
    assembly.distro_uuid = Some(expected);
    let error = guest.assemble(&assembly).unwrap_err();
    assert!(
        matches!(error.error(), Error::Uuid { expected: e, actual: UUID } if *e == expected),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the distro layer's UUID is 01020304-0506-0708-090a-0b0c0d0e0f10, \
         expected 01020304-0506-0708-090a-0b0c0d0e0fff"
    );
    assert!(guest.kernel.mounts().is_empty());
    assert!(guest.kernel.unmounts().is_empty());

    // A device without the EROFS magic number has no UUID to check.
    let guest = Guest::new();
    fs::write(guest.path("dev/vda"), vec![0; 4096]).unwrap();
    let error = guest.assemble(&assembly).unwrap_err();
    assert!(
        matches!(error.error(), Error::NotErofs { device } if *device == guest.path("dev/vda")),
        "{error:?}"
    );
    assert!(guest.kernel.mounts().is_empty());
}

#[test]
fn a_failed_assembly_unmounts_what_it_mounted_and_reports_what_stays() {
    let guest = Guest::new();
    guest.kernel.fail(
        Operation::Mount,
        guest.path("run/nvx/rootfs"),
        Errno::EINVAL,
    );
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert!(
        matches!(
            error.error(),
            Error::Mount { mount: Mount::Overlay, error } if error.raw_os_error() == Some(Errno::EINVAL as i32)
        ),
        "{error:?}"
    );
    assert!(error.cleanup().is_none());
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch")
        ]
    );

    // A failed unmount of the cleanup is reported too, and the next one still attempted.
    let guest = Guest::new();
    guest.kernel.fail(
        Operation::Mount,
        guest.path("run/nvx/rootfs"),
        Errno::EINVAL,
    );
    guest.kernel.fail(
        Operation::Unmount,
        guest.path("run/nvx/layers/distro"),
        Errno::EBUSY,
    );
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "failed to mount the overlay: {}; then failed to unmount the distro layer: {}",
            os_error(Errno::EINVAL),
            os_error(Errno::EBUSY)
        )
    );
    let (_, cleanup) = error.into_parts();
    let failures = cleanup.unwrap();
    let [failure] = failures.failures() else {
        panic!("{failures:?}");
    };
    assert_eq!(failure.mount(), &Mount::Distro);
    assert_eq!(failure.path(), guest.path("run/nvx/layers/distro"));
    assert_eq!(failure.error().raw_os_error(), Some(Errno::EBUSY as i32));
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch")
        ]
    );
}

#[test]
fn a_runtime_directory_that_the_overlay_options_reserve_is_refused() {
    let guest = Guest::new();
    for runtime in ["run/nvx", "/run/a,b", "/run/a:b", "/run/a\\b", "/run/a=b"] {
        let mut assembly = guest.assembly();
        assembly.runtime = runtime.into();
        let error = guest.assemble(&assembly).unwrap_err();
        assert!(
            matches!(error.error(), Error::Runtime { path } if *path == Path::new(runtime)),
            "{runtime}: {error:?}"
        );
    }
    assert!(guest.kernel.calls().is_empty());
}

/// Returns a child of an aggregate share.
fn child(name: &str, target: &str, access: Access, kind: ShareKind) -> ShareChild {
    ShareChild {
        name: name.to_owned(),
        target: target.into(),
        access,
        kind,
    }
}

#[test]
fn shares_are_mounted_restricted_and_torn_down_first_in_reverse_order() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    let assembled = guest.kernel.calls().len();
    root.mount_share("one", Path::new("/srv/one"), Access::ReadOnly)
        .unwrap();
    root.mount_aggregate(
        "all",
        Access::ReadWrite,
        &[
            child("a", "/data/a", Access::ReadWrite, ShareKind::Directory),
            child("b", "/etc/app/config", Access::ReadOnly, ShareKind::File),
        ],
    )
    .unwrap();
    let rootfs = guest.text("run/nvx/rootfs");
    let shares = guest.text("run/nvx/shares");
    let restricted = MountFlags::MS_NOSUID | MountFlags::MS_NODEV;
    let remount = MountFlags::MS_REMOUNT | MountFlags::MS_BIND | restricted;
    assert_eq!(
        guest.kernel.calls()[assembled..],
        [
            mount_call(
                Some("one"),
                &format!("{rootfs}/srv/one"),
                Some("virtiofs"),
                restricted | MountFlags::MS_RDONLY,
                None,
            ),
            mount_call(Some("all"), &shares, Some("virtiofs"), restricted, None),
            mount_call(
                Some(&format!("{shares}/a")),
                &format!("{rootfs}/data/a"),
                None,
                MountFlags::MS_BIND,
                None,
            ),
            mount_call(None, &format!("{rootfs}/data/a"), None, remount, None),
            mount_call(
                Some(&format!("{shares}/b")),
                &format!("{rootfs}/etc/app/config"),
                None,
                MountFlags::MS_BIND,
                None,
            ),
            mount_call(
                None,
                &format!("{rootfs}/etc/app/config"),
                None,
                remount | MountFlags::MS_RDONLY,
                None,
            ),
        ]
    );
    assert!(guest.path("run/nvx/rootfs/srv/one").is_dir());
    assert!(guest.path("run/nvx/rootfs/etc/app/config").is_file());

    root.teardown().unwrap();
    assert_eq!(
        guest.kernel.unmounts(),
        [
            format!("{rootfs}/etc/app/config"),
            format!("{rootfs}/data/a"),
            shares,
            format!("{rootfs}/srv/one"),
            rootfs,
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
        ]
    );
}

#[test]
fn refused_shares_mount_nothing() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    root.mount_share("srv", Path::new("/srv"), Access::ReadWrite)
        .unwrap();
    let mounts = guest.kernel.mounts().len();
    let refusal = |result: Result<(), Error>| match result {
        Err(Error::Share(refusal)) => refusal,
        other => panic!("{other:?}"),
    };
    let directory = ShareKind::Directory;
    let rw = Access::ReadWrite;
    assert_eq!(
        refusal(root.mount_share("a b", Path::new("/a"), rw)),
        ShareRefusal::Tag("a b".into())
    );
    assert_eq!(
        refusal(root.mount_share("t", Path::new("/proc/x"), rw)),
        ShareRefusal::Reserved("/proc/x".into())
    );
    assert_eq!(
        refusal(root.mount_share("t", Path::new("/"), rw)),
        ShareRefusal::NotCanonical("/".into())
    );
    assert_eq!(
        refusal(root.mount_share("t", Path::new("/srv/inner"), rw)),
        ShareRefusal::Overlap {
            claimed: "/srv".into(),
            target: "/srv/inner".into()
        }
    );
    assert_eq!(
        refusal(root.mount_aggregate("t", rw, &[])),
        ShareRefusal::NoChildren
    );
    assert_eq!(
        refusal(root.mount_aggregate("t", rw, &[child("..", "/a", rw, directory)])),
        ShareRefusal::ChildName("..".into())
    );
    assert_eq!(
        refusal(root.mount_aggregate(
            "t",
            rw,
            &[
                child("x", "/a", rw, directory),
                child("x", "/b", rw, directory)
            ]
        )),
        ShareRefusal::DuplicateChild("x".into())
    );
    assert_eq!(
        refusal(root.mount_aggregate(
            "t",
            rw,
            &[
                child("x", "/b/c", rw, directory),
                child("y", "/b", rw, directory)
            ]
        )),
        ShareRefusal::Overlap {
            claimed: "/b/c".into(),
            target: "/b".into()
        }
    );
    assert_eq!(
        refusal(root.mount_aggregate("t", rw, &[child("x", "/", rw, directory)])),
        ShareRefusal::NotCanonical("/".into())
    );
    assert_eq!(guest.kernel.mounts().len(), mounts);

    // A share that fails to mount claims no target.
    guest.kernel.fail(
        Operation::Mount,
        guest.path("run/nvx/rootfs/opt"),
        Errno::ENODEV,
    );
    let error = root.mount_share("opt", Path::new("/opt"), rw).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "failed to mount the live share opt at /opt: {}",
            os_error(Errno::ENODEV)
        )
    );
    assert_eq!(root.claimed, [PathBuf::from("/srv")]);
}

#[test]
fn a_child_that_cannot_be_restricted_stays_mounted_until_teardown() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    guest.kernel.fail(
        Operation::Remount,
        guest.path("run/nvx/rootfs/data/a"),
        Errno::EPERM,
    );
    let error = root
        .mount_aggregate(
            "all",
            Access::ReadOnly,
            &[
                child("a", "/data/a", Access::ReadOnly, ShareKind::Directory),
                child("b", "/data/b", Access::ReadOnly, ShareKind::Directory),
            ],
        )
        .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Restrict { mount: Mount::Child { name, target }, .. }
                if name == "a" && *target == Path::new("/data/a")
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to restrict the live share child a at /data/a: {}",
            os_error(Errno::EPERM)
        )
    );
    root.teardown().unwrap();
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/rootfs/data/a"),
            guest.text("run/nvx/shares"),
            guest.text("run/nvx/rootfs"),
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
        ]
    );
}

#[test]
fn a_failed_unmount_is_reported_and_the_later_ones_still_attempted() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    root.mount_share("srv", Path::new("/srv"), Access::ReadWrite)
        .unwrap();
    guest.kernel.fail(
        Operation::Unmount,
        guest.path("run/nvx/rootfs/srv"),
        Errno::EBUSY,
    );
    guest.kernel.fail(
        Operation::Unmount,
        guest.path("run/nvx/rootfs"),
        Errno::EBUSY,
    );
    let error = root.teardown().unwrap_err();
    let failures: Vec<_> = error
        .failures()
        .iter()
        .map(|failure| (failure.mount().clone(), failure.path().to_owned()))
        .collect();
    assert_eq!(
        failures,
        [
            (
                Mount::Share {
                    tag: "srv".into(),
                    target: "/srv".into()
                },
                guest.path("run/nvx/rootfs/srv")
            ),
            (Mount::Overlay, guest.path("run/nvx/rootfs")),
        ]
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to unmount the live share srv at /srv: {busy}; \
             failed to unmount the overlay: {busy}",
            busy = os_error(Errno::EBUSY)
        )
    );
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/rootfs/srv"),
            guest.text("run/nvx/rootfs"),
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
        ]
    );
}

#[test]
fn a_dropped_root_is_torn_down_once() {
    let guest = Guest::new();
    let root = guest.assemble(&guest.assembly()).unwrap();
    guest.kernel.fail(
        Operation::Unmount,
        guest.path("run/nvx/rootfs"),
        Errno::EBUSY,
    );
    drop(root);
    let unmounts = [
        guest.text("run/nvx/rootfs"),
        guest.text("run/nvx/layers/distro"),
        guest.text("run/nvx/scratch"),
    ];
    assert_eq!(guest.kernel.unmounts(), unmounts);

    // A root that was torn down has nothing left to unmount when it is dropped.
    let guest = Guest::new();
    guest
        .assemble(&guest.assembly())
        .unwrap()
        .teardown()
        .unwrap();
    assert_eq!(guest.kernel.unmounts().len(), 3);
}

/// A process of the bootstrap's parent cgroup.
enum Process {
    /// A process, which the bootstrap moves.
    User(u32),
    /// A kernel thread, which stays.
    Kernel(u32),
    /// A process that ended after the cgroup listed it, which has no `/proc` entry.
    Ended(u32),
}

/// Prepares a cgroup hierarchy at `cgroup` in `guest`, whose root, already a cgroup if
/// `mounted`, holds `processes`, and returns the layout of its `agent` and `container` cgroups.
fn hierarchy(guest: &Guest, mounted: bool, processes: &[Process]) -> Layout {
    let cgroup = guest.path("cgroup");
    write(
        &guest.paths.proc.join("sys/user/max_user_namespaces"),
        "15019\n",
    );
    if mounted {
        write(&cgroup.join("cgroup.controllers"), "cpu io memory pids\n");
    }
    write(&cgroup.join("cgroup.subtree_control"), "");
    let mut members = String::new();
    for process in processes {
        let (id, flags) = match *process {
            Process::User(id) => (id, Some(0x0040_0100)),
            Process::Kernel(id) => (id, Some(0x0020_8040)),
            Process::Ended(id) => (id, None),
        };
        members.push_str(&format!("{id}\n"));
        if let Some(flags) = flags {
            let stat = format!("{id} (p {id}) S 0 {id} {id} 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 1\n");
            write(&guest.paths.proc.join(id.to_string()).join("stat"), stat);
        }
    }
    write(&cgroup.join("cgroup.procs"), members);
    Layout::new(cgroup.join("agent"), cgroup.join("container")).unwrap()
}

/// Bootstraps `layout` with `resources` and a clone of `guest`'s kernel.
fn bootstrap_in(guest: &Guest, layout: &Layout, resources: &Resources) -> Result<Bootstrap, Error> {
    bootstrap::bootstrap_with(&mut guest.kernel.clone(), &guest.paths, layout, resources)
}

#[test]
fn bootstrap_moves_every_process_but_kernel_threads_and_applies_the_resources() {
    let guest = Guest::bare();
    let processes = [
        Process::User(1),
        Process::Kernel(2),
        Process::User(45),
        Process::Ended(99),
    ];
    let layout = hierarchy(&guest, true, &processes);
    let resources = Resources {
        agent_memory_low: Some(16 << 20),
        workload_memory_max: Some(512 << 20),
        workload_pids_max: Some(65),
    };
    let bootstrap = bootstrap_in(&guest, &layout, &resources).unwrap();
    assert_eq!(bootstrap.moved(), [1, 45]);
    assert_eq!(bootstrap.layout(), &layout);
    assert_eq!(bootstrap.workload().path(), layout.workload());
    let writes: Vec<(String, String)> = [
        ("proc/sys/user/max_user_namespaces", "0"),
        ("cgroup/agent/cgroup.procs", "1"),
        ("cgroup/agent/cgroup.procs", "45"),
        ("cgroup/cgroup.subtree_control", "+pids +memory"),
        ("cgroup/agent/memory.low", "16777216"),
        ("cgroup/container/memory.max", "536870912"),
        ("cgroup/container/pids.max", "65"),
    ]
    .into_iter()
    .map(|(path, value)| (guest.text(path), value.to_owned()))
    .collect();
    assert_eq!(guest.kernel.writes(), writes);
    assert!(guest.kernel.mounts().is_empty());
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/cgroup.procs")).unwrap(),
        "2\n99\n"
    );
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/cgroup.procs")).unwrap(),
        "1\n45\n"
    );
    assert!(guest.path("cgroup/container").is_dir());
}

#[test]
fn bootstrap_mounts_the_hierarchy_unless_the_parent_is_a_cgroup() {
    let guest = Guest::bare();
    let layout = hierarchy(&guest, false, &[Process::User(1)]);
    bootstrap_in(&guest, &layout, &Resources::default()).unwrap();
    assert_eq!(
        guest.kernel.calls()[1],
        mount_call(
            Some("cgroup2"),
            &guest.text("cgroup"),
            Some("cgroup2"),
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC,
            None,
        )
    );
    // Without a memory value, only the `pids` controller is enabled, and nothing else written.
    let writes = guest.kernel.writes();
    assert_eq!(
        writes[2..],
        [(guest.text("cgroup/cgroup.subtree_control"), "+pids".into())]
    );
}

#[test]
fn bootstrap_names_the_failed_step_and_keeps_the_earlier_changes() {
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1)]);
    guest.kernel.fail(
        Operation::Write,
        guest.path("cgroup/container/memory.max"),
        Errno::EINVAL,
    );
    let resources = Resources {
        agent_memory_low: Some(1 << 20),
        workload_memory_max: Some(1),
        workload_pids_max: Some(8),
    };
    let error = bootstrap_in(&guest, &layout, &resources).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Bootstrap { step: BootstrapStep::WorkloadMemoryMax, error }
                if error.raw_os_error() == Some(Errno::EINVAL as i32)
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to set the workload's memory limit: {}",
            os_error(Errno::EINVAL)
        )
    );
    let writes = guest.kernel.writes();
    assert_eq!(
        writes.last().unwrap().0,
        guest.text("cgroup/container/memory.max")
    );
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/memory.low")).unwrap(),
        "1048576"
    );

    // Cgroups that are not siblings are refused before anything changes.
    let guest = Guest::bare();
    hierarchy(&guest, true, &[Process::User(1)]);
    let cgroup = guest.path("cgroup");
    let layout = Layout::new(cgroup.join("agent"), cgroup.join("workloads/container")).unwrap();
    let error = bootstrap_in(&guest, &layout, &Resources::default()).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Bootstrap { step: BootstrapStep::Layout, error }
                if error.raw_os_error() == Some(Errno::EINVAL as i32)
        ),
        "{error:?}"
    );
    assert!(guest.kernel.calls().is_empty());
}

#[test]
fn bootstrap_fails_while_a_process_keeps_returning_to_the_parent() {
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1), Process::User(7)]);
    guest.kernel.pin(7);
    let error = bootstrap_in(&guest, &layout, &Resources::default()).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Bootstrap { step: BootstrapStep::Placement, error }
                if error.raw_os_error() == Some(Errno::EBUSY as i32)
        ),
        "{error:?}"
    );
    let attempts = guest
        .kernel
        .writes()
        .into_iter()
        .filter(|(path, value)| path.ends_with("agent/cgroup.procs") && value == "7")
        .count();
    assert_eq!(attempts, 16);
}
