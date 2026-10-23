//! Tests of the root operations with the fake kernel, and with the kernel's interfaces, a cgroup
//! hierarchy, and the runtime directory in a temporary directory, and of the kernel's own check
//! for a mount point.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::kernel::{Call, FakeKernel, Operation, Paths};
use super::*;
use crate::guest::cgroup::Layout;
use crate::guest::mappings::{Access, SourceRoot};
use crate::guest::sys::MountAttributes;

/// The base address of the distro device's MMIO window.
const DISTRO: u64 = 0xd000_0000;
/// The base address of the scratch device's MMIO window.
const SCRATCH: u64 = 0x1_d000_1000;
/// The UUID of the test's EROFS image.
const UUID: Uuid = Uuid::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

/// A guest in a temporary directory, and the fake kernel that the operations get clones of.
struct Guest {
    /// The temporary directory, which the guest holds only so that dropping it removes the
    /// directory.
    _directory: tempfile::TempDir,
    /// The temporary directory's canonical path, which no symbolic link leads through, as none
    /// may lead through a runtime directory.
    base: PathBuf,
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
        attach(&guest.base, 0, "vda", 4096);
        attach(&guest.base, 1, "vdb", 8192);
        guest
    }

    /// Returns a guest whose `/proc/iomem` declares the distro device's window 0 and the
    /// scratch's window 1, without their devices.
    fn bare() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().canonicalize().unwrap();
        let paths = Paths {
            proc: base.join("proc"),
            sys: base.join("sys"),
            dev: base.join("dev"),
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
            _directory: directory,
            base,
            paths,
            kernel: FakeKernel::default(),
        }
    }

    /// Returns `relative`'s path below the temporary directory.
    fn path(&self, relative: &str) -> PathBuf {
        self.base.join(relative)
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
fn erofs_image(uuid: Uuid) -> Vec<u8> {
    let mut image = vec![0; 4096];
    image[1024..1028].copy_from_slice(&0xE0F5_E1E2_u32.to_le_bytes());
    image[1024 + 48..1024 + 64].copy_from_slice(uuid.as_bytes());
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
    attach(&guest.base, 1, "vdb", 8192);
    let root_directory = guest.base.clone();
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
    attach(&guest.base, 0, "vda", 4096);
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
    let mut bytes = *UUID.as_bytes();
    bytes[15] = 0xff;
    let expected = Uuid::from_bytes(bytes);
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

#[test]
fn a_runtime_directory_whose_path_is_not_canonical_is_refused() {
    // Once the scratch hid `probe`, the last path would lead nowhere, and the image and the
    // scratch could not be unmounted.
    let guest = Guest::new();
    fs::create_dir_all(guest.path("run/nvx/scratch/probe")).unwrap();
    let parent = guest.text("run/nvx/scratch/probe/../..");
    let forms = [
        "/",
        "/run/nvx/",
        "/run//nvx",
        "/run/./nvx",
        "/run/nvx/.",
        "/run/nvx/..",
    ];
    for runtime in forms.into_iter().chain([parent.as_str()]) {
        let mut assembly = guest.assembly();
        assembly.runtime = runtime.into();
        let error = guest.assemble(&assembly).unwrap_err();
        assert!(
            matches!(error.error(), Error::Runtime { path } if path.as_os_str() == runtime),
            "{runtime}: {error:?}"
        );
        assert!(error.cleanup().is_none());
    }
    assert!(guest.kernel.calls().is_empty());
    assert!(!guest.path("run/nvx/layers").exists());
    let mut assembly = guest.assembly();
    assembly.runtime = parent.clone().into();
    assert_eq!(
        guest.assemble(&assembly).unwrap_err().to_string(),
        format!(
            "the runtime directory is not a canonical absolute path without `,`, `:`, `\\`, `=`, \
             or a symbolic link: {parent}"
        )
    );
}

#[test]
fn a_root_mounts_nothing_through_a_symbolic_link() {
    // A runtime directory that a link leads through, whether the link names it, one of its
    // parents, or a path through the scratch's mount point.
    let guest = Guest::new();
    fs::create_dir_all(guest.path("run/nvx/scratch/probe")).unwrap();
    std::os::unix::fs::symlink("nvx", guest.path("run/link")).unwrap();
    std::os::unix::fs::symlink("run", guest.path("alias")).unwrap();
    std::os::unix::fs::symlink("nvx/scratch/probe/../..", guest.path("run/up")).unwrap();
    for runtime in ["run/link", "alias/nvx", "run/up"].map(|relative| guest.path(relative)) {
        let mut assembly = guest.assembly();
        assembly.runtime = runtime.clone();
        let error = guest.assemble(&assembly).unwrap_err();
        assert!(
            matches!(error.error(), Error::Runtime { path } if *path == runtime),
            "{}: {error:?}",
            runtime.display()
        );
    }
    assert!(guest.kernel.calls().is_empty());
    assert!(!guest.path("run/nvx/layers").exists());

    // A link at one of the assembly's mount points, or at the directory above the image's.
    for name in ["layers", "layers/distro", "scratch", "rootfs"] {
        let guest = Guest::new();
        let link = guest.path("run/nvx").join(name);
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        fs::create_dir(guest.path("elsewhere")).unwrap();
        std::os::unix::fs::symlink(guest.path("elsewhere"), &link).unwrap();
        let error = guest.assemble(&guest.assembly()).unwrap_err();
        assert!(
            matches!(error.error(), Error::MountPoint { path, error: cause }
                if *path == link && cause.raw_os_error() == Some(Errno::ENOTDIR as i32)),
            "{name}: {error:?}"
        );
        assert!(guest.kernel.calls().is_empty(), "{name}");
    }

    // A link at an aggregate's mount point, which the aggregate refuses.
    let guest = Guest::new();
    let shares = guest.path("run/nvx/shares");
    fs::create_dir_all(guest.path("run/nvx")).unwrap();
    fs::create_dir(guest.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink(guest.path("elsewhere"), &shares).unwrap();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    let mounts = guest.kernel.mounts();
    let rw = Access::ReadWrite;
    let error = root
        .mount_aggregate("all", rw, &[child("a", "/a", rw, ShareKind::Directory)])
        .unwrap_err();
    assert!(
        matches!(&error, Error::MountPoint { path, error: cause }
            if *path == shares && cause.raw_os_error() == Some(Errno::ENOTDIR as i32)),
        "{error:?}"
    );
    assert_eq!(guest.kernel.mounts(), mounts);
    root.teardown().unwrap();
}

#[test]
fn new_upper_and_work_directories_have_mode_0755_whatever_the_umask() {
    // The umask is the process's, so the test runs alone in a process of its own.
    if crate::guest::managed_agent::isolate_process_test(
        "NVX_ROOT_UMASK_TEST_CHILD",
        "guest::root::tests::new_upper_and_work_directories_have_mode_0755_whatever_the_umask",
    ) {
        return;
    }
    nix::sys::stat::umask(sys::Mode::from_bits_truncate(0o077));
    let mode = |path: &Path| fs::metadata(path).unwrap().mode() & 0o7777;
    // The overlay's root directory takes the upper's mode, which a workload that is not root
    // must be able to enter.
    let guest = Guest::new();
    guest
        .assemble(&guest.assembly())
        .unwrap()
        .teardown()
        .unwrap();
    assert_eq!(mode(&guest.path("run/nvx/scratch/upper")), 0o755);
    assert_eq!(mode(&guest.path("run/nvx/scratch/work")), 0o755);

    // A directory that the scratch holds already, from an earlier boot, keeps its mode.
    let guest = Guest::new();
    let upper = guest.path("run/nvx/scratch/upper");
    fs::create_dir_all(&upper).unwrap();
    fs::set_permissions(&upper, fs::Permissions::from_mode(0o700)).unwrap();
    guest
        .assemble(&guest.assembly())
        .unwrap()
        .teardown()
        .unwrap();
    assert_eq!(mode(&upper), 0o700);
    assert_eq!(mode(&guest.path("run/nvx/scratch/work")), 0o755);
}

#[test]
fn a_runtime_directory_that_another_root_holds_is_refused() {
    let guest = Guest::new();
    let first = guest.assemble(&guest.assembly()).unwrap();
    let calls = guest.kernel.calls();
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert!(
        matches!(error.error(), Error::Reserved { path } if *path == guest.path("run/nvx")),
        "{error:?}"
    );
    assert!(error.cleanup().is_none());
    assert_eq!(
        error.to_string(),
        format!(
            "another root holds the runtime directory {}",
            guest.text("run/nvx")
        )
    );
    // The refused assembly touched none of the mounts, which the first root still owns.
    assert_eq!(guest.kernel.calls(), calls);
    first.teardown().unwrap();
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/rootfs"),
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
        ]
    );
    // A root that is torn down or dropped holds the runtime directory no longer.
    drop(guest.assemble(&guest.assembly()).unwrap());
    guest
        .assemble(&guest.assembly())
        .unwrap()
        .teardown()
        .unwrap();

    // An assembly that starts while another one waits for its distro device is refused before
    // it checks or mounts anything, and the first one goes on.
    let guest = Guest::bare();
    attach(&guest.base, 1, "vdb", 8192);
    let refused = Arc::new(Mutex::new(None));
    let (kernel, paths, assembly) = (guest.kernel.clone(), guest.paths.clone(), guest.assembly());
    let (directory, outcome) = (guest.base.clone(), Arc::clone(&refused));
    guest.kernel.on_sleep(move |sleeps| {
        if sleeps == 1 {
            attach(&directory, 0, "vda", 4096);
            let calls = kernel.calls().len();
            let result = assemble_with(Box::new(kernel.clone()), &paths, &assembly);
            *outcome.lock().unwrap() = Some((result.map(drop), kernel.calls().len() - calls));
        }
    });
    let mut assembly = guest.assembly();
    assembly.timeout = Duration::from_secs(1);
    let first = guest.assemble(&assembly).unwrap();
    let (result, calls) = refused.lock().unwrap().take().unwrap();
    let error = result.unwrap_err();
    assert!(
        matches!(error.error(), Error::Reserved { path } if *path == guest.path("run/nvx")),
        "{error:?}"
    );
    assert!(error.cleanup().is_none());
    assert_eq!(calls, 0);
    assert_eq!(
        guest.kernel.mounts(),
        [
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
            guest.text("run/nvx/rootfs"),
        ]
    );
    first.teardown().unwrap();
}

#[test]
fn a_runtime_directory_where_a_file_system_is_mounted_is_refused() {
    // A file system that no root mounted, at the distro layer's mount point.
    let guest = Guest::new();
    let distro = guest.path("run/nvx/layers/distro");
    guest
        .kernel
        .clone()
        .mount(
            Some(c"tmpfs"),
            &sys::path_c_string(&distro).unwrap(),
            Some(c"tmpfs"),
            MountFlags::empty(),
            None,
        )
        .unwrap();
    let calls = guest.kernel.calls();
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert!(
        matches!(error.error(), Error::Occupied { path } if *path == distro),
        "{error:?}"
    );
    assert!(error.cleanup().is_none());
    assert_eq!(
        error.to_string(),
        format!("a file system is mounted at {} already", distro.display())
    );
    assert_eq!(guest.kernel.calls(), calls);

    // An overlay that a failed unmount left in place keeps the runtime directory occupied.
    let guest = Guest::new();
    guest.kernel.fail(
        Operation::Unmount,
        guest.path("run/nvx/rootfs"),
        Errno::EBUSY,
    );
    guest
        .assemble(&guest.assembly())
        .unwrap()
        .teardown()
        .unwrap_err();
    let mounts = guest.kernel.mounts().len();
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert!(
        matches!(error.error(), Error::Occupied { path } if *path == guest.path("run/nvx/rootfs")),
        "{error:?}"
    );
    assert_eq!(guest.kernel.mounts().len(), mounts);

    // So does an aggregate share whose unmount alone failed: it is mounted outside the overlay,
    // which, like the image and the scratch, was unmounted.
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    export(&guest, &[("a", ShareKind::Directory)]);
    let rw = Access::ReadWrite;
    root.mount_aggregate("all", rw, &[child("a", "/a", rw, ShareKind::Directory)])
        .unwrap();
    let shares = guest.path("run/nvx/shares");
    guest
        .kernel
        .fail(Operation::Unmount, shares.clone(), Errno::EBUSY);
    let error = root.teardown().unwrap_err();
    let failed: Vec<&Path> = error.failures().iter().map(Unmount::path).collect();
    assert_eq!(failed, [shares.as_path()]);
    let mounts = guest.kernel.mounts().len();
    let error = guest.assemble(&guest.assembly()).unwrap_err();
    assert!(
        matches!(error.error(), Error::Occupied { path } if *path == shares),
        "{error:?}"
    );
    assert_eq!(guest.kernel.mounts().len(), mounts);
}

#[test]
fn the_kernel_finds_its_mount_points() {
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = SystemKernel;
    assert!(kernel.is_mount_point(Path::new("/proc")).unwrap());
    assert!(!kernel.is_mount_point(directory.path()).unwrap());
    let error = kernel
        .is_mount_point(&directory.path().join("missing"))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
}

/// The variable that gives the bind-mount test's inner run the runtime directory where the outer
/// run bound a directory at the distro layer's mount point.
const BOUND_RUNTIME: &str = "NVX_ROOT_TEST_BOUND_RUNTIME";

#[test]
fn a_runtime_directory_where_a_directory_is_bound_is_refused() {
    // A directory of the same file system, bound at the distro layer's mount point, shows the
    // device of the directory's parent, so only their mounts tell it apart. The outer run binds
    // it in a user and mount namespace of its own, where it runs the test again, which assembles
    // a root there with the kernel itself.
    if let Some(runtime) = std::env::var_os(BOUND_RUNTIME) {
        let runtime = PathBuf::from(runtime);
        let distro = runtime.join(DISTRO_DIRECTORY);
        let device = |path: &Path| fs::metadata(path).unwrap().dev();
        assert_eq!(device(&distro), device(distro.parent().unwrap()));
        let guest = Guest::new();
        let assembly = Assembly {
            runtime,
            ..guest.assembly()
        };
        let error = assemble_with(Box::new(SystemKernel), &guest.paths, &assembly).unwrap_err();
        assert!(
            matches!(error.error(), Error::Occupied { path } if *path == distro),
            "{error:?}"
        );
        assert!(error.cleanup().is_none());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().canonicalize().unwrap();
    let source = base.join("source");
    let runtime = base.join("run/nvx");
    let distro = runtime.join(DISTRO_DIRECTORY);
    fs::create_dir(&source).unwrap();
    fs::create_dir_all(&distro).unwrap();
    let test = "guest::root::tests::a_runtime_directory_where_a_directory_is_bound_is_refused";
    let output = std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "--propagation"])
        .args(["private", "sh", "-c"])
        .arg(r#"mount --bind "$1" "$2" || exit 77; shift 2; exec "$@""#)
        .arg("sh")
        .args([&source, &distro])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(BOUND_RUNTIME, &runtime)
        .output();
    let output = match output {
        Ok(output) => output,
        // Without `unshare`, the test stops here.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => panic!("cannot run unshare: {error}"),
    };
    // So it does where the namespaces cannot be created, which fails `unshare` with 1, or where
    // they cannot bind a directory, which the script reports with 77.
    if matches!(output.status.code(), Some(1 | 77)) {
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
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

/// Returns the absolute targets of the live shares and mappings that `root`'s mapper tracks.
fn targets(root: &Root) -> Vec<String> {
    root.mapper
        .iter()
        .flat_map(Mapper::targets)
        .map(|target| format!("/{}", target.display()))
        .collect()
}

/// Creates the entries that an aggregate mounted at `shares` in `guest`'s runtime directory
/// shows, which the fake kernel does not mount: a directory or a regular file for each child.
fn export(guest: &Guest, children: &[(&str, ShareKind)]) {
    let shares = guest.path("run/nvx/shares");
    for &(name, kind) in children {
        match kind {
            ShareKind::Directory => fs::create_dir_all(shares.join(name)).unwrap(),
            ShareKind::File => write(&shares.join(name), "host file"),
        }
    }
}

#[test]
fn what_a_share_s_target_lacks_is_created_with_its_mode_whatever_the_umask_or_a_default_acl() {
    // A workload that is not root must be able to enter the directories that the root creates
    // for a share, whatever the umask of the process that mounts it, or a default ACL of the
    // overlay's root, which withholds permissions in the umask's stead.
    for restricted in [false, true] {
        sys::with_thread_umask(0o077, || {
            let guest = Guest::new();
            let mut root = guest.assemble(&guest.assembly()).unwrap();
            if restricted && !sys::restrict_new_entries(&guest.path("run/nvx/rootfs")) {
                root.teardown().unwrap();
                return;
            }
            export(&guest, &[("b", ShareKind::File)]);
            root.mount_share("one", Path::new("/srv/new/share"), Access::ReadOnly)
                .unwrap();
            root.mount_aggregate(
                "all",
                Access::ReadOnly,
                &[child(
                    "b",
                    "/opt/app/config",
                    Access::ReadOnly,
                    ShareKind::File,
                )],
            )
            .unwrap();
            let mode = |relative: &str| fs::metadata(guest.path(relative)).unwrap().mode() & 0o7777;
            for (relative, expected) in [
                ("run/nvx/rootfs/srv", 0o755),
                ("run/nvx/rootfs/srv/new", 0o755),
                ("run/nvx/rootfs/srv/new/share", 0o755),
                ("run/nvx/rootfs/opt", 0o755),
                ("run/nvx/rootfs/opt/app", 0o755),
                ("run/nvx/rootfs/opt/app/config", 0o644),
            ] {
                assert_eq!(mode(relative), expected, "{relative} {restricted}");
            }
            assert_eq!(sys::thread_umask(), 0o077);
            root.teardown().unwrap();
        });
    }
}

#[test]
fn shares_are_mounted_restricted_and_torn_down_first_in_reverse_order() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    let assembled = guest.kernel.calls().len();
    export(
        &guest,
        &[("a", ShareKind::Directory), ("b", ShareKind::File)],
    );
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
    let staging = guest.text("run/nvx/staging");
    let restricted = MountFlags::MS_NOSUID | MountFlags::MS_NODEV;
    // The share's device is mounted out of the root with its flags, then moved onto its target;
    // each child is a copy of its entry's mount, restricted before it is attached.
    let mut expected = vec![
        mount_call(
            Some("one"),
            &staging,
            Some("virtiofs"),
            restricted | MountFlags::MS_RDONLY,
            None,
        ),
        Call::OpenTree {
            source: staging.clone(),
            clone: false,
        },
        Call::SetAttributes {
            source: staging.clone(),
            set: MountAttributes::READ_ONLY
                | MountAttributes::NO_SET_ID
                | MountAttributes::NO_DEVICES,
            clear: MountAttributes::empty(),
        },
        Call::MoveMount {
            source: staging.clone(),
            target: format!("{rootfs}/srv/one"),
        },
        mount_call(Some("all"), &shares, Some("virtiofs"), restricted, None),
    ];
    expected.extend(attach_calls(
        &guest.path("run/nvx/shares/a"),
        &guest.path("run/nvx/rootfs/data/a"),
        Access::ReadWrite,
    ));
    expected.extend(attach_calls(
        &guest.path("run/nvx/shares/b"),
        &guest.path("run/nvx/rootfs/etc/app/config"),
        Access::ReadOnly,
    ));
    assert_eq!(guest.kernel.calls()[assembled..], expected);
    let mode = |relative: &str| fs::metadata(guest.path(relative)).unwrap().mode() & 0o7777;
    assert!(guest.path("run/nvx/rootfs/srv/one").is_dir());
    assert!(guest.path("run/nvx/rootfs/etc/app/config").is_file());
    assert_eq!(mode("run/nvx/rootfs/etc/app"), 0o755);
    assert_eq!(mode("run/nvx/rootfs/etc/app/config"), 0o644);
    assert_eq!(guest.kernel.mount_at(&guest.path("run/nvx/staging")), None);
    assert!(!root.is_latched());

    root.teardown().unwrap();
    assert_eq!(
        guest.kernel.unmounts(),
        [
            format!("{rootfs}/etc/app/config"),
            format!("{rootfs}/data/a"),
            format!("{rootfs}/srv/one"),
            shares,
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
    // The refusals of requests latch nothing.
    assert!(!root.is_latched());

    // A share that fails to mount claims no target, and latches the root.
    guest.kernel.fail(
        Operation::Mount,
        guest.path("run/nvx/staging"),
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
    assert_eq!(targets(&root), ["/srv"]);
    assert!(root.is_latched());
    let error = root.mount_share("t", Path::new("/t"), rw).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Mapping { mount: Mount::Share { tag, .. }, error: MappingError::Latched }
                if tag == "t"
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "failed to mount the live share t at /t: an earlier mapping failed"
    );
}

#[test]
fn a_root_has_one_aggregate_and_one_that_failed_part_of_the_way_latches_it() {
    let rw = Access::ReadWrite;
    let directory = ShareKind::Directory;
    let rootfs = |guest: &Guest, target: &str| guest.text(&format!("run/nvx/rootfs{target}"));
    for bound in [&["/a", "/b"][..], &["/a"]] {
        let guest = Guest::new();
        let mut root = guest.assemble(&guest.assembly()).unwrap();
        export(&guest, &[("a", directory), ("b", directory)]);
        if bound.len() == 1 {
            guest.kernel.fail(
                Operation::MoveMount,
                guest.path("run/nvx/rootfs/b"),
                Errno::ENOENT,
            );
        }
        let first = root.mount_aggregate(
            "all",
            rw,
            &[
                child("a", "/a", rw, directory),
                child("b", "/b", rw, directory),
            ],
        );
        assert_eq!(first.is_ok(), bound.len() == 2, "{first:?}");
        assert_eq!(root.is_latched(), bound.len() == 1);
        let mounts = guest.kernel.mounts().len();
        let error = root
            .mount_aggregate("more", rw, &[child("c", "/c", rw, directory)])
            .unwrap_err();
        if bound.len() == 2 {
            assert!(
                matches!(error, Error::Share(ShareRefusal::SecondAggregate)),
                "{error:?}"
            );
            assert_eq!(
                error.to_string(),
                "the root has an aggregate live share already"
            );
        } else {
            assert!(
                matches!(
                    error,
                    Error::Mapping {
                        error: MappingError::Latched,
                        ..
                    }
                ),
                "{error:?}"
            );
        }
        assert_eq!(guest.kernel.mounts().len(), mounts);
        assert!(!guest.path("run/nvx/rootfs/c").exists());
        // The teardown unmounts the bound children, then the one aggregate.
        root.teardown().unwrap();
        let mut unmounts: Vec<String> = bound
            .iter()
            .rev()
            .map(|target| rootfs(&guest, target))
            .collect();
        unmounts.extend([
            guest.text("run/nvx/shares"),
            guest.text("run/nvx/rootfs"),
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
        ]);
        assert_eq!(guest.kernel.unmounts(), unmounts);
    }
}

#[test]
fn a_child_whose_restriction_fails_is_never_attached() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    export(
        &guest,
        &[("a", ShareKind::Directory), ("b", ShareKind::Directory)],
    );
    guest.kernel.fail(
        Operation::SetAttributes,
        guest.path("run/nvx/shares/a"),
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
            Error::Mapping { mount: Mount::Child { name, target }, error }
                if name == "a" && *target == Path::new("/data/a")
                    && error.raw_os_error() == Errno::EPERM as i32
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to mount the live share child a at /data/a: failed to restrict the mount: {}",
            os_error(Errno::EPERM)
        )
    );
    assert!(guest.kernel.moves().is_empty());
    root.teardown().unwrap();
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/shares"),
            guest.text("run/nvx/rootfs"),
            guest.text("run/nvx/layers/distro"),
            guest.text("run/nvx/scratch"),
        ]
    );
}

#[test]
fn a_child_that_the_aggregate_lacks_or_holds_as_another_kind_binds_nothing() {
    for (exported, errno, cause) in [
        (
            None,
            Errno::ENOENT,
            format!("failed to open the source: {}", os_error(Errno::ENOENT)),
        ),
        (
            Some(ShareKind::File),
            Errno::EINVAL,
            "the source is not a directory or a regular file of the mapping's kind".to_owned(),
        ),
    ] {
        let guest = Guest::new();
        let mut root = guest.assemble(&guest.assembly()).unwrap();
        if let Some(kind) = exported {
            export(&guest, &[("a", kind)]);
        }
        let mounts = guest.kernel.mounts().len();
        let error = root
            .mount_aggregate(
                "all",
                Access::ReadOnly,
                &[child(
                    "a",
                    "/data/a",
                    Access::ReadOnly,
                    ShareKind::Directory,
                )],
            )
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::Mapping { mount: Mount::Child { name, .. }, error }
                    if name == "a" && error.raw_os_error() == errno as i32
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!("failed to mount the live share child a at /data/a: {cause}")
        );
        // Only the aggregate is mounted, and the child claims no target.
        assert_eq!(
            guest.kernel.mounts()[mounts..],
            [guest.text("run/nvx/shares")]
        );
        assert!(targets(&root).is_empty());
        assert!(!guest.path("run/nvx/rootfs/data").exists());
        root.teardown().unwrap();
        assert_eq!(guest.kernel.unmounts()[0], guest.text("run/nvx/shares"));
    }
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
fn a_share_through_a_link_or_onto_another_mount_is_refused_and_latches_the_root() {
    let rw = Access::ReadWrite;
    // A link in the root, which the mapper's walk refuses after the device was mounted at
    // `staging`, which it unmounts then.
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    fs::create_dir(guest.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink(guest.path("elsewhere"), guest.path("run/nvx/rootfs/link")).unwrap();
    let error = root
        .mount_share("t", Path::new("/link/new"), rw)
        .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Mapping { mount: Mount::Share { tag, .. }, error: MappingError::Link { path } }
                if tag == "t" && *path == Path::new("/link")
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "failed to mount the live share t at /link/new: /link is a symbolic link or a magic link"
    );
    assert_eq!(guest.kernel.unmounts(), [guest.text("run/nvx/staging")]);
    assert!(!guest.path("elsewhere/new").exists());
    assert!(root.is_latched());
    root.teardown().unwrap();

    // Another mount in the root, where nothing is created.
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    let foreign = guest.path("run/nvx/rootfs/foreign");
    fs::create_dir(&foreign).unwrap();
    guest.kernel.add_mount(&foreign);
    let error = root
        .mount_share("t", Path::new("/foreign/new"), rw)
        .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Mapping { error: MappingError::Foreign { path }, .. }
                if *path == Path::new("/foreign/new")
        ),
        "{error:?}"
    );
    assert!(!foreign.join("new").exists());

    // A device that stays at `staging`, because its unmount failed too, is the teardown's.
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    std::os::unix::fs::symlink("/", guest.path("run/nvx/rootfs/link")).unwrap();
    let staging = guest.path("run/nvx/staging");
    guest
        .kernel
        .fail(Operation::Unmount, staging.clone(), Errno::EBUSY);
    root.mount_share("t", Path::new("/link/new"), rw)
        .unwrap_err();
    let error = root.teardown().unwrap_err();
    let failed: Vec<_> = error
        .failures()
        .iter()
        .map(|failure| (failure.mount().clone(), failure.path().to_owned()))
        .collect();
    assert_eq!(
        failed,
        [(
            Mount::Share {
                tag: "t".into(),
                target: "/link/new".into()
            },
            staging.clone()
        )]
    );

    // A `staging` where a file system is mounted already is refused before the device mounts.
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    let staging = guest.path("run/nvx/staging");
    fs::create_dir(&staging).unwrap();
    guest.kernel.add_mount(&staging);
    let mounts = guest.kernel.mounts().len();
    let error = root.mount_share("t", Path::new("/t"), rw).unwrap_err();
    assert!(
        matches!(&error, Error::Occupied { path } if *path == staging),
        "{error:?}"
    );
    assert_eq!(guest.kernel.mounts().len(), mounts);
}

#[test]
fn a_share_or_a_mapping_that_a_rename_moved_and_that_stays_is_the_teardown_s() {
    for (share, detach) in [
        (true, Ok(())),
        (true, Err(Errno::EBUSY)),
        (false, Err(Errno::EBUSY)),
    ] {
        let guest = Guest::new();
        let mut root = guest.assemble(&guest.assembly()).unwrap();
        let rootfs = guest.path("run/nvx/rootfs");
        fs::create_dir_all(rootfs.join("data/x")).unwrap();
        let export = guest.path("hostfs/root");
        fs::create_dir_all(export.join("0/src")).unwrap();
        guest.kernel.add_mount(&export);
        // A rename between the walk and the attach moves the target's directory, and the detach
        // of what went there fails.
        let renamed = rootfs.clone();
        guest.kernel.on_move(move |_| {
            fs::rename(renamed.join("data"), renamed.join("moved")).unwrap();
        });
        let moved = rootfs.join("moved/x");
        guest
            .kernel
            .fail(Operation::Detach, moved.clone(), Errno::EBUSY);
        let (error, mount) = if share {
            let error = root
                .mount_share("t", Path::new("/data/x"), Access::ReadWrite)
                .unwrap_err();
            let mount = Mount::Share {
                tag: "t".into(),
                target: "/data/x".into(),
            };
            (error, mount)
        } else {
            let source = SourceRoot::open(&export).unwrap();
            let mapping =
                crate::guest::mappings::Mapping::new("0/src", "/data/x", Access::ReadOnly).unwrap();
            let error = root.map(&source, &[mapping]).unwrap_err();
            let mount = Mount::Mapping {
                target: "/data/x".into(),
            };
            (error, mount)
        };
        assert!(
            matches!(
                &error,
                Error::Mapping {
                    error: MappingError::Moved { mounted: true },
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(root.is_latched());
        assert!(guest.kernel.mount_at(&moved).is_some());
        assert_eq!(guest.kernel.mount_at(&guest.path("run/nvx/staging")), None);
        // The teardown detaches it first, wherever it is, or reports it.
        if detach.is_ok() {
            guest.kernel.restore(Operation::Detach, &moved);
        }
        let calls = guest.kernel.calls().len();
        let torn = root.teardown();
        assert_eq!(
            guest.kernel.calls()[calls],
            Call::Detach(moved.display().to_string())
        );
        assert_eq!(guest.kernel.mount_at(&moved).is_some(), detach.is_err());
        match detach {
            Ok(()) => torn.unwrap(),
            Err(busy) => {
                let error = torn.unwrap_err();
                let failures: Vec<_> = error
                    .failures()
                    .iter()
                    .map(|failure| (failure.mount().clone(), failure.path().to_owned()))
                    .collect();
                assert_eq!(failures, [(mount, rootfs.join("data/x"))]);
                assert_eq!(
                    error.failures()[0].error().raw_os_error(),
                    Some(busy as i32)
                );
            }
        }
    }
}

#[test]
fn mappings_apply_beneath_the_overlay_in_order_and_go_first_at_the_teardown() {
    let guest = Guest::new();
    let mut root = guest.assemble(&guest.assembly()).unwrap();
    let export = guest.path("hostfs/root");
    fs::create_dir_all(export.join("0/src")).unwrap();
    fs::write(export.join("0/notes.txt"), b"notes").unwrap();
    guest.kernel.add_mount(&export);
    let source = SourceRoot::open(&export).unwrap();
    let calls = guest.kernel.calls().len();
    // Zero mappings do no work.
    root.map(&source, &[]).unwrap();
    assert_eq!(guest.kernel.calls().len(), calls);
    let mapping = |source: &str, target: &str, access| {
        crate::guest::mappings::Mapping::new(source, target, access).unwrap()
    };
    root.map(
        &source,
        &[
            mapping("0/src", "/workspace", Access::ReadWrite),
            mapping("0/notes.txt", "/home/user/notes", Access::ReadOnly),
        ],
    )
    .unwrap();
    let mut expected = attach_calls(
        &export.join("0/src"),
        &guest.path("run/nvx/rootfs/workspace"),
        Access::ReadWrite,
    );
    expected.extend(attach_calls(
        &export.join("0/notes.txt"),
        &guest.path("run/nvx/rootfs/home/user/notes"),
        Access::ReadOnly,
    ));
    assert_eq!(guest.kernel.calls()[calls..], expected);
    assert_eq!(targets(&root), ["/workspace", "/home/user/notes"]);
    // A share may not shadow a mapping, nor be inside one.
    let error = root
        .mount_share("t", Path::new("/workspace/inner"), Access::ReadWrite)
        .unwrap_err();
    assert!(
        matches!(&error, Error::Share(ShareRefusal::Overlap { claimed, .. })
            if *claimed == Path::new("/workspace")),
        "{error:?}"
    );
    // NVX's container root reserves its runtime's targets; the refusal latches the root.
    let error = root
        .map(&source, &[mapping("0/src", "/etc", Access::ReadOnly)])
        .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Mapping { mount: Mount::Mapping { target }, error: MappingError::Reserved }
                if *target == Path::new("/etc")
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "failed to mount the mapping at /etc: the runtime reserves the target"
    );
    let error = root
        .map(&source, &[mapping("0/src", "/srv", Access::ReadOnly)])
        .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Mapping {
                error: MappingError::Latched,
                ..
            }
        ),
        "{error:?}"
    );
    root.map(&source, &[]).unwrap();
    assert!(!guest.path("run/nvx/rootfs/srv").exists());
    root.teardown().unwrap();
    assert_eq!(
        guest.kernel.unmounts(),
        [
            guest.text("run/nvx/rootfs/home/user/notes"),
            guest.text("run/nvx/rootfs/workspace"),
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

/// Creates the interface files `files` of the workload cgroup, `cgroup/container`, in `guest`,
/// as the kernel shows them once its parent enables their controllers, which a hierarchy of
/// regular files does not.
fn interface_files(guest: &Guest, files: &[&str]) {
    for file in files {
        write(&guest.path("cgroup/container").join(file), "");
    }
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
    interface_files(&guest, &["pids.current", "memory.max", "pids.max"]);
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
        ("cgroup/agent/memory.low", "16777216"),
    ]
    .into_iter()
    .map(|(path, value)| (guest.text(path), value.to_owned()))
    .collect();
    assert_eq!(guest.kernel.writes(), writes);
    assert!(guest.kernel.mounts().is_empty());
    // The agent's `memory.low` enabled the `memory` controller. The workload cgroup has every
    // file already, so its preparation enabled nothing, and wrote its values.
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/cgroup.subtree_control")).unwrap(),
        "+memory"
    );
    for (file, value) in [("memory.max", "536870912"), ("pids.max", "65")] {
        assert_eq!(
            fs::read_to_string(guest.path("cgroup/container").join(file)).unwrap(),
            value,
            "{file}"
        );
    }
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/cgroup.procs")).unwrap(),
        "2\n99\n"
    );
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/cgroup.procs")).unwrap(),
        "1\n45\n"
    );
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
    // Without a value, the bootstrap writes only the placement, and the preparation of the new
    // workload cgroup enables only the `pids` controller.
    assert_eq!(guest.kernel.writes().len(), 2);
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/cgroup.subtree_control")).unwrap(),
        "+pids"
    );
    assert!(guest.path("cgroup/container").is_dir());
}

#[test]
fn bootstrap_names_the_failed_step_and_keeps_the_earlier_changes() {
    // The workload cgroup's `memory.max` cannot be written: a directory takes its place.
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1)]);
    interface_files(&guest, &["pids.current", "pids.max"]);
    fs::create_dir(guest.path("cgroup/container/memory.max")).unwrap();
    let resources = Resources {
        agent_memory_low: Some(1 << 20),
        workload_memory_max: Some(1),
        workload_pids_max: Some(8),
    };
    let error = bootstrap_in(&guest, &layout, &resources).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Bootstrap { step: BootstrapStep::WorkloadCgroup, error }
                if error.raw_os_error() == Some(Errno::EISDIR as i32)
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to prepare the workload cgroup: {}",
            os_error(Errno::EISDIR)
        )
    );
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/memory.low")).unwrap(),
        "1048576"
    );

    // The agent's value is refused before the workload cgroup is prepared.
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1)]);
    guest.kernel.fail(
        Operation::Write,
        guest.path("cgroup/agent/memory.low"),
        Errno::EINVAL,
    );
    let error = bootstrap_in(&guest, &layout, &resources).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Bootstrap { step: BootstrapStep::AgentMemoryLow, error }
                if error.raw_os_error() == Some(Errno::EINVAL as i32)
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to set the agent's memory reservation: {}",
            os_error(Errno::EINVAL)
        )
    );
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/cgroup.procs")).unwrap(),
        "1\n"
    );
    assert!(!guest.path("cgroup/container").exists());

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
fn bootstrap_accepts_a_missing_sysctl_only_without_user_namespaces() {
    // A kernel without sysctls lacks the limit, which one without user namespaces needs no more.
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1)]);
    guest.kernel.fail(
        Operation::Write,
        guest.path("proc/sys/user/max_user_namespaces"),
        Errno::ENOENT,
    );
    bootstrap_in(&guest, &layout, &Resources::default()).unwrap();
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/cgroup.procs")).unwrap(),
        "1\n"
    );

    // One with user namespaces cannot be limited, so nothing else changes.
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1)]);
    guest.kernel.fail(
        Operation::Write,
        guest.path("proc/sys/user/max_user_namespaces"),
        Errno::ENOENT,
    );
    write(&guest.paths.proc.join("self/ns/user"), "");
    let error = bootstrap_in(&guest, &layout, &Resources::default()).unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Bootstrap { step: BootstrapStep::UserNamespaces, error }
                if error.raw_os_error() == Some(Errno::ENOENT as i32)
        ),
        "{error:?}"
    );
    assert_eq!(guest.kernel.calls().len(), 1);
    assert!(!guest.path("cgroup/agent").exists());
}

#[test]
fn bootstrap_fails_while_a_process_keeps_returning_to_the_parent() {
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1), Process::User(7)]);
    guest.kernel.pin(7, usize::MAX);
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

#[test]
fn bootstrap_succeeds_when_the_last_pass_empties_the_parent() {
    let guest = Guest::bare();
    let layout = hierarchy(&guest, true, &[Process::User(1), Process::User(7)]);
    // The sixteenth pass is the first that moves the process.
    guest.kernel.pin(7, 15);
    let bootstrap = bootstrap_in(&guest, &layout, &Resources::default()).unwrap();
    assert_eq!(bootstrap.moved()[0], 1);
    assert_eq!(bootstrap.moved()[1..], [7; 16]);
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/cgroup.procs")).unwrap(),
        ""
    );
    assert_eq!(
        fs::read_to_string(guest.path("cgroup/agent/cgroup.procs")).unwrap(),
        "1\n7\n"
    );
}
