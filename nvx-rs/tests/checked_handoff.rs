//! The checked handoff of a prepared launch, through the public API of `nvx::host::sandbox` and
//! `nvx::host::supervisor`, as an orchestrator uses them: it stages and binds a distro layer and a
//! scratch image, checks them, prepares the launch, and spawns the VMM with the prepared launch's
//! arguments and allowlist.
//!
//! The VMM is this test executable, run again as a fixture. It reads the capability that
//! `nvx::host::supervisor::spawn` passes on its standard input, as OpenVMM does, reports its
//! descriptors on Linux and that it started, and, once a file named `go` appears in its working
//! directory, opens each block device that an argument names as OpenVMM opens it, a layer
//! read-only and the scratch image for reading and writing, reads each whole, writes the scratch
//! image, and reports what each held. It holds them until a file named `exit` appears in its
//! working directory.
#![cfg(all(feature = "host", any(target_os = "linux", windows)))]

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nvx::host::sandbox::distro::{DISTRO_POLICY_REVISION, DistroBinding};
use nvx::host::sandbox::scratch::{CLAIM_RELEASE_WAIT, ScratchBinding};
use nvx::host::sandbox::{LayerRole, PreparedLaunch, SandboxLaunch, SandboxLayer, SandboxSettings};
use nvx::host::supervisor::{self, Launched, VmmCommand};
use nvx::protocol::CAPABILITY_LEN;

/// File whose presence in its working directory marks a VMM fixture. Without it, the fixture
/// returns at once, as it does when `cargo test -- --ignored` runs it.
const VMM_MARKER: &str = "vmm-fixture";
/// File whose appearance in its working directory lets a VMM fixture open its block devices.
const GO_MARKER: &str = "go";
/// File that a VMM fixture writes once it has started, after its report of its descriptors.
const STARTED_REPORT: &str = "started";
/// File whose appearance in its working directory ends a VMM fixture.
const EXIT_MARKER: &str = "exit";
/// File in which a VMM fixture reports what its block devices held, a line for each: its role
/// and its content, escaped.
const BLOCKS_REPORT: &str = "blocks";
/// File in which a VMM fixture reports its descriptors on Linux, a line for each: its number and
/// the object that it holds.
#[cfg(target_os = "linux")]
const DESCRIPTORS_REPORT: &str = "descriptors";
/// Prefix of an argument of a VMM fixture that holds the value of a `--microvm-sandbox-block`
/// option of the prepared launch. Libtest takes the argument for a test name that matches no
/// test.
const BLOCK_PREFIX: &str = "block=";
/// The capability of the VMMs of these tests.
const CAPABILITY: [u8; CAPABILITY_LEN] = [0x5a; CAPABILITY_LEN];
/// Longest wait for a fixture to answer.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Longest life of a VMM fixture that nothing ends, so that a failed test leaves no process.
const VMM_LIFETIME: Duration = Duration::from_secs(180);
/// The UUID of the staged layer.
const UUID: &str = "11111111-1111-1111-1111-111111111111";
/// The content of the staged distro layer.
const DISTRO: &str = "distro layer\n";
/// The content of the staged scratch image.
const SCRATCH: &str = "scratch image\n";

/// The VMM fixture: reads its capability as OpenVMM does, reports its descriptors on Linux, then,
/// once [`GO_MARKER`] appears, opens and reads each block device that an argument names, writes
/// the scratch image, reports what each held, and runs until [`EXIT_MARKER`] appears.
#[test]
#[ignore = "fixture that the handoff tests run as a VMM"]
fn vmm_fixture() {
    let directory = env::current_dir().unwrap();
    if !directory.join(VMM_MARKER).exists() {
        return;
    }
    let mut capability = [0; CAPABILITY_LEN];
    io::stdin().read_exact(&mut capability).unwrap();
    assert_eq!(capability, CAPABILITY);
    #[cfg(target_os = "linux")]
    report_descriptors(&directory);
    write_whole(&directory.join(STARTED_REPORT), "");
    if !wait_for(&directory.join(GO_MARKER), VMM_LIFETIME) {
        return;
    }
    let mut held = Vec::new();
    let mut report = String::new();
    for argument in env::args() {
        let Some(block) = argument.strip_prefix(BLOCK_PREFIX) else {
            continue;
        };
        let (role, rest) = block.split_once(":file:").unwrap();
        let (path, read_only) = match rest.strip_suffix(",ro") {
            Some(path) => (path, true),
            None => (rest, false),
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)
            .unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        if !read_only {
            file.write_all(b"written by the VMM\n").unwrap();
        }
        report.push_str(&format!("{role} {}\n", content.escape_default()));
        held.push(file);
    }
    write_whole(&directory.join(BLOCKS_REPORT), &report);
    wait_for(&directory.join(EXIT_MARKER), VMM_LIFETIME);
}

/// Writes `text` to the file at `path`, which appears whole.
fn write_whole(path: &Path, text: &str) {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, text).unwrap();
    fs::rename(&temporary, path).unwrap();
}

/// Waits until the file at `path` exists, for at most `timeout`, and returns whether it does.
fn wait_for(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
    true
}

/// Writes the descriptors of this VMM fixture, but for the one that lists them, to the file
/// [`DESCRIPTORS_REPORT`] in `directory`.
#[cfg(target_os = "linux")]
fn report_descriptors(directory: &Path) {
    // The descriptor that lists the others holds this directory.
    let listing = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
    let mut descriptors: Vec<(usize, PathBuf)> = fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let number = entry.file_name().to_str().unwrap().parse().unwrap();
            let object = fs::read_link(entry.path()).ok()?;
            (object != listing).then_some((number, object))
        })
        .collect();
    descriptors.sort();
    let report: String = descriptors
        .iter()
        .map(|(number, object)| format!("{number} {}\n", object.display()))
        .collect();
    write_whole(&directory.join(DESCRIPTORS_REPORT), &report);
}

/// Returns the arguments that run only the fixture `name` of this test executable.
fn fixture_arguments(name: &str) -> Vec<OsString> {
    [
        "--exact",
        name,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(OsString::from)
    .to_vec()
}

/// The working directory of a VMM fixture. Dropping it ends the fixture, and the launched VMM
/// that it holds, so that a failed test leaves no process behind.
struct VmmDirectory {
    /// The launched VMM, once the test spawned it.
    launched: Option<Launched>,
    /// The directory, which is removed after the VMM exits.
    directory: tempfile::TempDir,
}

impl VmmDirectory {
    /// Creates a directory that marks a VMM fixture.
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        File::create(directory.path().join(VMM_MARKER)).unwrap();
        Self {
            launched: None,
            directory,
        }
    }

    /// Returns the path of the directory.
    fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Waits for the VMM's report `name`, and returns it.
    fn report(&self, name: &str) -> String {
        let path = self.path().join(name);
        assert!(wait_for(&path, TIMEOUT), "the VMM did not report {name}");
        fs::read_to_string(path).unwrap()
    }
}

impl Drop for VmmDirectory {
    fn drop(&mut self) {
        let _ = File::create(self.path().join(EXIT_MARKER));
        if let Some(launched) = self.launched.take() {
            if let Ok(process) = launched.process() {
                let _ = process.wait(Instant::now() + TIMEOUT);
            }
            launched.kill_and_wait();
        }
    }
}

/// A distro layer and a scratch image, staged in a temporary directory.
struct Staged {
    /// The temporary directory.
    directory: tempfile::TempDir,
}

impl Staged {
    /// Stages a distro layer and a scratch image.
    fn new() -> Self {
        let staged = Self {
            directory: tempfile::tempdir().unwrap(),
        };
        fs::write(staged.distro(), DISTRO).unwrap();
        fs::write(staged.scratch(), SCRATCH).unwrap();
        staged
    }

    /// Returns the path of the distro layer.
    fn distro(&self) -> PathBuf {
        self.directory.path().join("distro.erofs")
    }

    /// Returns the path of the scratch image.
    fn scratch(&self) -> PathBuf {
        self.directory.path().join("scratch.ext4")
    }

    /// Returns the launch of the distro layer over the scratch image.
    fn launch(&self) -> SandboxLaunch {
        SandboxLaunch::new(
            vec![SandboxLayer::new(
                LayerRole::Distro,
                self.distro().to_str().unwrap(),
                UUID,
            )],
            self.scratch().to_str().unwrap(),
            SandboxSettings::default(),
        )
        .unwrap()
    }
}

/// Spawns processes through `std::process` until `done`, as other threads of an orchestrator do,
/// and counts them in `spawned`. Returns, on Linux, those that held a descriptor of an object of
/// `checked`, which no process but the VMM may inherit.
fn spawn_others(done: &AtomicBool, spawned: &AtomicUsize, checked: &[PathBuf]) -> Vec<String> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut leaks = Vec::new();
    while !done.load(Ordering::SeqCst) {
        let mut child = sleeper().spawn().unwrap();
        #[cfg(target_os = "linux")]
        for entry in fs::read_dir(format!("/proc/{}/fd", child.id())).unwrap() {
            if let Ok(object) = fs::read_link(entry.unwrap().path())
                && checked.contains(&object)
            {
                leaks.push(format!("process {} held {}", child.id(), object.display()));
            }
        }
        #[cfg(windows)]
        let _ = checked;
        let _ = child.kill();
        child.wait().unwrap();
        spawned.fetch_add(1, Ordering::SeqCst);
    }
    leaks
}

/// Returns a command that runs for a few seconds, without standard streams.
fn sleeper() -> Command {
    let mut command = if cfg!(windows) {
        let mut command = Command::new("ping");
        command.args(["-n", "5", "127.0.0.1"]);
        command
    } else {
        let mut command = Command::new("sleep");
        command.arg("5");
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Returns the object that the descriptor `number` of this process holds, as its link in `/proc`
/// names it.
#[cfg(target_os = "linux")]
fn this_object(number: i32) -> PathBuf {
    fs::read_link(format!("/proc/self/fd/{number}")).unwrap()
}

/// Makes `pipe` inheritable, or not, as code that spawns without an allowlist does around its
/// spawns.
#[cfg(target_os = "linux")]
fn set_inheritable(pipe: &io::PipeWriter, inheritable: bool) {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    let flags = if inheritable {
        FdFlag::empty()
    } else {
        FdFlag::FD_CLOEXEC
    };
    fcntl(pipe, FcntlArg::F_SETFD(flags)).unwrap();
}

/// Makes `pipe` inheritable, or not, as code that spawns without an allowlist does around its
/// spawns.
#[cfg(windows)]
fn set_inheritable(pipe: &io::PipeWriter, inheritable: bool) {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};

    let flags = if inheritable { HANDLE_FLAG_INHERIT } else { 0 };
    // SAFETY: the handle is open.
    let set =
        unsafe { SetHandleInformation(pipe.as_raw_handle() as HANDLE, HANDLE_FLAG_INHERIT, flags) };
    assert_ne!(set, 0, "{}", io::Error::last_os_error());
}

/// Returns whether the handle `value` of process `pid` refers to the object of this process's
/// handle `value`, as a handle that the process inherited from this one does.
#[cfg(windows)]
fn holds(pid: u32, value: usize) -> bool {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
    };

    let ours = value as HANDLE;
    // SAFETY: OpenProcess has no memory-safety preconditions.
    let process = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    assert!(
        !process.is_null(),
        "cannot open process {pid}: {}",
        io::Error::last_os_error()
    );
    // SAFETY: the handle is new, and nothing else owns it.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut copy = ptr::null_mut();
    // SAFETY: the process handle may duplicate the process's handles, the value is looked up in
    // that process only, and the output pointer is valid.
    let duplicated = unsafe {
        DuplicateHandle(
            process.as_raw_handle(),
            ours,
            GetCurrentProcess(),
            &mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } != 0;
    // A value that names no handle of the process names none of ours.
    if !duplicated {
        return false;
    }
    // SAFETY: the copy is new, and nothing else owns it.
    let copy = unsafe { OwnedHandle::from_raw_handle(copy) };
    // SAFETY: both handles are open.
    unsafe { CompareObjectHandles(copy.as_raw_handle(), ours) != 0 }
}

#[test]
fn a_prepared_launch_hands_the_vmm_its_checked_images_alone() {
    let staged = Staged::new();
    let launch = staged.launch();
    // Staging binds the images, where hashing belongs; the launch checks them from their metadata
    // alone, and claims the scratch image.
    let binding = DistroBinding::verify(launch.distro()).unwrap();
    let scratch_binding = ScratchBinding::bind(launch.scratch()).unwrap();
    let distro = binding
        .check(launch.distro(), DISTRO_POLICY_REVISION)
        .unwrap();
    let scratch = scratch_binding
        .check(launch.scratch(), Instant::now() + CLAIM_RELEASE_WAIT)
        .unwrap();
    let prepared = PreparedLaunch::new(
        launch.bound_plan(&binding).unwrap(),
        distro,
        Some(scratch),
        "",
    )
    .unwrap();

    // Something replaces both images between the checks and the VMM's opens: on Linux it can,
    // and the VMM opens the checked files anyway; on Windows the checked files keep it from
    // doing so.
    for (path, replacement) in [
        (staged.distro(), "replaced distro\n"),
        (staged.scratch(), "replaced scratch\n"),
    ] {
        let new = path.with_extension("new");
        fs::write(&new, replacement).unwrap();
        let replaced = fs::rename(&new, &path);
        assert_eq!(
            replaced.is_ok(),
            cfg!(target_os = "linux"),
            "{}: {replaced:?}",
            path.display()
        );
    }

    #[cfg(target_os = "linux")]
    let checked: Vec<PathBuf> = {
        use std::os::fd::{AsFd, AsRawFd};

        prepared
            .inherited()
            .iter()
            .map(|inherited| this_object(inherited.as_fd().as_raw_fd()))
            .collect()
    };
    #[cfg(windows)]
    let checked: Vec<PathBuf> = Vec::new();
    let mut vmm = VmmDirectory::new();
    let mut arguments = fixture_arguments("vmm_fixture");
    let blocks: Vec<&String> = prepared
        .openvmm_arguments()
        .windows(2)
        .filter(|pair| pair[0] == "--microvm-sandbox-block")
        .map(|pair| &pair[1])
        .collect();
    assert_eq!(blocks.len(), 2);
    arguments.extend(
        blocks
            .iter()
            .map(|block| OsString::from(format!("{BLOCK_PREFIX}{block}"))),
    );
    let mut command = VmmCommand::new(env::current_exe().unwrap(), arguments, vmm.path());
    command.inherit = prepared.inherited();
    // A descriptor or handle that this process leaves inheritable, as code that spawns without an
    // allowlist does, while another thread spawns processes.
    let (_unrelated_reader, unrelated) = io::pipe().unwrap();
    let done = AtomicBool::new(false);
    let spawned = AtomicUsize::new(0);
    let leaks = thread::scope(|scope| {
        let spawner = scope.spawn(|| spawn_others(&done, &spawned, &checked));
        let deadline = Instant::now() + TIMEOUT;
        while spawned.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline && !spawner.is_finished(),
                "the other thread spawned nothing"
            );
            thread::sleep(Duration::from_millis(10));
        }
        set_inheritable(&unrelated, true);
        let log = File::create(vmm.path().join("vmm.log")).unwrap();
        let launched = supervisor::spawn(&command, &CAPABILITY, log);
        set_inheritable(&unrelated, false);
        vmm.launched = Some(launched.unwrap());
        // The other thread spawns throughout the VMM's start.
        vmm.report(STARTED_REPORT);
        done.store(true, Ordering::SeqCst);
        spawner.join().unwrap()
    });
    assert!(spawned.load(Ordering::SeqCst) > 0);
    assert!(leaks.is_empty(), "{leaks:?}");
    let pid = vmm.launched.as_ref().unwrap().id();

    // The VMM holds its standard streams and the checked files under their numbers, and nothing
    // else of this process's: on Linux, the checked descriptors, which the arguments name; on
    // Windows, no handle of this process at all.
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsFd, AsRawFd};

        let _ = pid;
        let reported = vmm.report(DESCRIPTORS_REPORT);
        let mut expected: Vec<String> = prepared
            .inherited()
            .iter()
            .map(|inherited| {
                let number = inherited.as_fd().as_raw_fd();
                format!("{number} {}", this_object(number).display())
            })
            .collect();
        let log = fs::canonicalize(vmm.path().join("vmm.log")).unwrap();
        let lines: Vec<&str> = reported.lines().collect();
        assert_eq!(lines.len(), 5, "{reported}");
        assert!(lines[0].starts_with("0 pipe:"), "{reported}");
        assert_eq!(lines[1], format!("1 {}", log.display()));
        assert_eq!(lines[2], format!("2 {}", log.display()));
        expected.sort();
        let mut inherited: Vec<String> = lines[3..].iter().map(|line| (*line).to_owned()).collect();
        inherited.sort();
        assert_eq!(inherited, expected);
        for object in &checked {
            assert!(
                object.to_string_lossy().ends_with(" (deleted)"),
                "the checked file was not replaced at its path: {}",
                object.display()
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        assert!(prepared.inherited().is_empty());
        let mut ours = vec![
            prepared.distro().file().as_raw_handle() as usize,
            unrelated.as_raw_handle() as usize,
        ];
        ours.extend(
            prepared
                .scratch()
                .map(|scratch| scratch.file().as_raw_handle() as usize),
        );
        for value in ours {
            assert!(!holds(pid, value), "the VMM holds handle {value:#x}");
        }
    }

    // The VMM opens its block devices as OpenVMM does, and finds the objects that the launch
    // checked.
    File::create(vmm.path().join(GO_MARKER)).unwrap();
    let report = vmm.report(BLOCKS_REPORT);
    assert_eq!(
        report,
        format!(
            "distro {}\nscratch {}\n",
            DISTRO.escape_default(),
            SCRATCH.escape_default()
        )
    );

    // On Windows, while the launch holds the checked files, nothing writes the distro layer, and
    // nothing removes or renames either image, while the VMM reads and writes the scratch image.
    // Once the guest is ready, the launch releases them, and the VMM's own opens share renames.
    #[cfg(windows)]
    {
        let moved = |path: &Path| path.with_extension("moved");
        assert!(
            OpenOptions::new()
                .append(true)
                .open(staged.distro())
                .is_err()
        );
        for path in [staged.distro(), staged.scratch()] {
            assert!(fs::rename(&path, moved(&path)).is_err());
            assert!(fs::remove_file(&path).is_err());
        }
        drop(prepared);
        for path in [staged.distro(), staged.scratch()] {
            fs::rename(&path, moved(&path)).unwrap();
            fs::rename(moved(&path), &path).unwrap();
        }
    }
    #[cfg(target_os = "linux")]
    drop(prepared);

    // The VMM wrote the checked scratch image, whatever has its path now.
    File::create(vmm.path().join(EXIT_MARKER)).unwrap();
    let launched = vmm.launched.take().unwrap();
    assert!(
        launched
            .process()
            .unwrap()
            .wait(Instant::now() + TIMEOUT)
            .unwrap()
    );
    launched.kill_and_wait();
    let scratch = fs::read_to_string(staged.scratch()).unwrap();
    if cfg!(windows) {
        assert_eq!(scratch, format!("{SCRATCH}written by the VMM\n"));
    } else {
        assert_eq!(scratch, "replaced scratch\n");
    }
}
