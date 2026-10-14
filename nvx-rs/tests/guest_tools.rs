//! Runs the guest binaries as programs: their command lines, exit statuses, and output.
//!
//! The tests run the binaries that Cargo builds for them, or, when `NVX_GUEST_BINARIES` names a
//! directory, the binaries there, such as the `guest`-profile builds that CI checks.
#![cfg(all(target_os = "linux", feature = "guest"))]

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const PORT_IO_USAGE: &[u8] = b"usage: nvx-port-io read-generation-id DATA_PORT SELECT_PORT \
[OUTPUT] | read-u8 PORT | write-u8 PORT VALUE\n";

/// Returns the path of the guest binary `name`.
fn binary(name: &str) -> PathBuf {
    if let Some(directory) = std::env::var_os("NVX_GUEST_BINARIES") {
        return Path::new(&directory).join(name);
    }
    PathBuf::from(match name {
        "nvx-console-pending" => env!("CARGO_BIN_EXE_nvx-console-pending"),
        "nvx-mmio-write" => env!("CARGO_BIN_EXE_nvx-mmio-write"),
        "nvx-port-io" => env!("CARGO_BIN_EXE_nvx-port-io"),
        "nvx-reseed" => env!("CARGO_BIN_EXE_nvx-reseed"),
        "nvx-managed-agent" => env!("CARGO_BIN_EXE_nvx-managed-agent"),
        "nvx-ingress" => env!("CARGO_BIN_EXE_nvx-ingress"),
        "nvx-time" => env!("CARGO_BIN_EXE_nvx-time"),
        "nvx-time-probe" => env!("CARGO_BIN_EXE_nvx-time-probe"),
        "nvx-exit" => env!("CARGO_BIN_EXE_nvx-exit"),
        "nvx-device-io" => env!("CARGO_BIN_EXE_nvx-device-io"),
        _ => panic!("no guest binary {name}"),
    })
}

/// Runs the guest binary `name` with `arguments`, and returns its exit status, stdout, and
/// stderr.
fn run<I, S>(name: &str, arguments: I) -> (Option<i32>, Vec<u8>, Vec<u8>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(binary(name))
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {name}: {error}"));
    (status.code(), stdout, stderr)
}

/// Returns the C library's `strerror` text for `errno`, as the binaries print it.
fn strerror(errno: i32) -> String {
    let text = io::Error::from_raw_os_error(errno).to_string();
    text.strip_suffix(&format!(" (os error {errno})"))
        .expect("Rust appends the errno")
        .to_owned()
}

/// Returns `parts` joined, with the bytes of a path where it occurs.
fn bytes(parts: &[&dyn AsRef<OsStr>]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|part| part.as_ref().as_bytes().to_vec())
        .collect()
}

/// Returns whether the tests run as root, with which the binaries would reach the host's real
/// devices.
fn is_root() -> bool {
    fs::metadata("/proc/self").map_or(true, |metadata| metadata.uid() == 0)
}

/// Returns the `errno` with which this process fails to open the device at `path`, as an
/// unprivileged guest binary does, or `None` when the tests run as root or the device opens: the
/// binaries would then reach the host's real devices.
fn device_error(path: &str, read: bool, write: bool) -> Option<i32> {
    if is_root() {
        return None;
    }
    fs::File::options()
        .read(read)
        .write(write)
        .open(path)
        .err()
        .map(|error| error.raw_os_error().expect("an OS error"))
}

#[test]
fn console_pending_usage() {
    for arguments in [&[][..], &["a", "b"]] {
        assert_eq!(
            run("nvx-console-pending", arguments),
            (
                Some(2),
                Vec::new(),
                b"usage: nvx-console-pending DEVICE\n".to_vec()
            )
        );
    }
}

/// Runs the guest binary `name` with `arguments` and its stdout on `stdout`, and returns how it
/// ended and its stderr.
fn run_to<I, S>(
    name: &str,
    arguments: I,
    stdout: impl Into<std::process::Stdio>,
) -> (std::process::ExitStatus, Vec<u8>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(binary(name))
        .args(arguments)
        .stdout(stdout)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {name}: {error}"));
    (output.status, output.stderr)
}

/// Returns a pipe whose reader is closed, so that a write to it raises `SIGPIPE`.
fn broken_pipe() -> io::PipeWriter {
    let (reader, writer) = io::pipe().unwrap();
    drop(reader);
    writer
}

#[test]
fn console_pending_handles_failed_writes_as_c_stdio() {
    use std::os::unix::process::ExitStatusExt;

    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("console");
    fs::write(&file, b"pending").unwrap();
    // C's stdio buffers a file's stdout until exit, which ignores the failure.
    let (status, stderr) = run_to(
        "nvx-console-pending",
        [&file],
        fs::File::create("/dev/full").unwrap(),
    );
    assert_eq!((status.code(), stderr), (Some(0), Vec::new()));
    // The default SIGPIPE disposition ends the program at a closed pipe.
    let (status, stderr) = run_to("nvx-console-pending", [&file], broken_pipe());
    assert_eq!((status.signal(), stderr), (Some(13), Vec::new()));
}

#[test]
fn console_pending_reports_the_unread_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("console");
    fs::write(&file, b"pending").unwrap();
    assert_eq!(
        run("nvx-console-pending", [&file]),
        (Some(0), b"7\n".to_vec(), Vec::new())
    );

    let missing = directory.path().join("missing");
    let message = bytes(&[
        &"nvx-console-pending: open ",
        &missing,
        &format!(": {}\n", strerror(ENOENT)),
    ]);
    assert_eq!(
        run("nvx-console-pending", [&missing]),
        (Some(1), Vec::new(), message)
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn mmio_write_usage_and_page_boundary() {
    let usage = b"usage: nvx-mmio-write ADDRESS VALUE\n".to_vec();
    for arguments in [
        &[][..],
        &["0x1000"],
        &["0x1000", "1", "2"],
        &["0x", "1"],
        &["0x1000", "4294967296"],
        &["0x1000", "-1"],
    ] {
        assert_eq!(
            run("nvx-mmio-write", arguments),
            (Some(2), Vec::new(), usage.clone()),
            "{arguments:?}"
        );
    }
    // Guests have 4 KiB pages.
    assert_eq!(
        run("nvx-mmio-write", ["0xffd", "1"]),
        (
            Some(1),
            Vec::new(),
            b"MMIO write crosses a page boundary\n".to_vec()
        )
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn mmio_write_reports_an_inaccessible_dev_mem() {
    let Some(errno) = device_error("/dev/mem", true, true) else {
        return;
    };
    assert_eq!(
        run("nvx-mmio-write", ["0x1000", "1"]),
        (
            Some(1),
            Vec::new(),
            format!("open /dev/mem: {}\n", strerror(errno)).into_bytes()
        )
    );
}

#[test]
fn port_io_usage() {
    for arguments in [
        &[][..],
        &["read-u8"],
        &["read-u8", "0x10000"],
        &["write-u8", "1", "256"],
        &["read-generation-id", "1"],
        &["read-generation-id", "1", "2", "out", "extra"],
    ] {
        assert_eq!(
            run("nvx-port-io", arguments),
            (Some(2), Vec::new(), PORT_IO_USAGE.to_vec()),
            "{arguments:?}"
        );
    }
}

#[test]
fn port_io_reports_an_inaccessible_dev_port() {
    for (arguments, read, write) in [
        (&["read-u8", "0x70"][..], true, false),
        (&["write-u8", "0x70", "0"], false, true),
    ] {
        let Some(errno) = device_error("/dev/port", read, write) else {
            return;
        };
        assert_eq!(
            run("nvx-port-io", arguments),
            (
                Some(1),
                Vec::new(),
                format!("nvx-port-io: open /dev/port: {}\n", strerror(errno)).into_bytes()
            )
        );
    }
}

#[test]
fn reseed_usage_and_sample() {
    let usage = b"usage: nvx-reseed --sample | [--generation-only] SEED_FILE \
[PREVIOUS_GENERATION_ID]\n";
    for arguments in [&[][..], &["a", "b", "c"]] {
        assert_eq!(
            run("nvx-reseed", arguments),
            (Some(2), Vec::new(), usage.to_vec())
        );
    }
    let (status, sample, err) = run("nvx-reseed", ["--sample"]);
    assert_eq!((status, err), (Some(0), Vec::new()));
    let (digits, newline) = sample.split_at(64);
    assert!(digits.iter().all(u8::is_ascii_hexdigit), "{sample:?}");
    assert_eq!(newline, b"\n");
    // C's stdio buffers a file's stdout until exit, which ignores the failure.
    let (status, stderr) = run_to(
        "nvx-reseed",
        ["--sample"],
        fs::File::create("/dev/full").unwrap(),
    );
    assert_eq!((status.code(), stderr), (Some(0), Vec::new()));
}

#[test]
fn reseed_checks_the_generation_id() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("seed");
    fs::write(&seed, [0x5a; 64]).unwrap();
    let previous = "00000000000000000000000000000000";
    assert_eq!(
        run(
            "nvx-reseed",
            [
                OsStr::new("--generation-only"),
                seed.as_os_str(),
                OsStr::new(previous)
            ]
        ),
        (
            Some(0),
            format!("{}\n", "5a".repeat(16)).into_bytes(),
            Vec::new()
        )
    );
    assert_eq!(
        run(
            "nvx-reseed",
            [seed.as_os_str(), OsStr::new(&"5A".repeat(16))]
        ),
        (
            Some(1),
            Vec::new(),
            b"nvx-reseed: VM generation ID did not change\n".to_vec()
        )
    );
}

#[test]
fn reseed_needs_privileges_to_reseed() {
    if is_root() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("seed");
    fs::write(&seed, [0x5a; 64]).unwrap();
    // Anyone may open /dev/random for writing, but RNDADDENTROPY takes CAP_SYS_ADMIN.
    assert_eq!(
        run("nvx-reseed", [&seed]),
        (
            Some(1),
            Vec::new(),
            format!("nvx-reseed: random ioctl: {}\n", strerror(EPERM)).into_bytes()
        )
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn exit_fails_silently_without_dev_port() {
    if device_error("/dev/port", false, true).is_none() {
        return;
    }
    for arguments in [&["0"][..], &[], &["256", "extra"]] {
        assert_eq!(
            run("nvx-exit", arguments),
            (Some(1), Vec::new(), Vec::new()),
            "{arguments:?}"
        );
    }
}

/// Runs `nvx-device-io` with `arguments`, and returns its exit status and result line, which
/// must be the only output.
#[cfg(target_arch = "x86_64")]
fn device_io<I, S>(arguments: I) -> (Option<i32>, Option<serde_json::Value>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (status, stdout, stderr) = run("nvx-device-io", arguments);
    assert_eq!(stderr, b"");
    if stdout.is_empty() {
        return (status, None);
    }
    let line = String::from_utf8(stdout).unwrap();
    let keys = [
        r#"{"device":""#,
        r#"","operation":""#,
        r#"","operations":"#,
        r#","bytes_per_operation":"#,
        r#","elapsed_ns":"#,
        "}\n",
    ];
    let mut rest = line.as_str();
    for key in keys {
        let position = rest.find(key).unwrap_or_else(|| panic!("{key} in {line}"));
        rest = &rest[position + key.len()..];
    }
    assert_eq!(rest, "", "{line}");
    (status, Some(serde_json::from_str(&line).unwrap()))
}

#[test]
#[cfg(target_arch = "x86_64")]
fn device_io_usage() {
    for arguments in [
        &[][..],
        &["file"],
        &["disk", "x"],
        &["file", "f", "read", "0", "4096", "buffered", "create"],
        &["file", "f", "read", "1", "4095", "buffered", "create"],
        &["file", "f", "copy", "1", "4096", "buffered", "create"],
        &["file", "f", "read", "1", "4096", "cached", "create"],
        &[
            "file", "f", "read", "1", "4096", "buffered", "create", "extra",
        ],
        &["network", "127.0.0.1", "0", "1"],
        &["network", "127.0.0.1", "65536", "1"],
        &["network", "127.0.0.256", "1", "1"],
        &["network", "127.0.0.1", "1", "0"],
    ] {
        assert_eq!(device_io(arguments), (Some(2), None), "{arguments:?}");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn device_io_measures_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("disk");
    let arguments = |operation: &str, creation: &str| {
        let path = file.to_str().unwrap();
        ["file", path, operation, "50", "65536", "buffered", creation].map(str::to_owned)
    };
    for (operation, creation) in [("write", "create"), ("read", "existing")] {
        let (status, result) = device_io(arguments(operation, creation));
        let result = result.unwrap();
        assert_eq!(status, Some(0), "{result}");
        assert_eq!(result["device"], "file");
        assert_eq!(result["operation"], operation);
        assert_eq!(result["bytes_per_operation"], 4096);
        assert!(result["operations"].as_u64().unwrap() > 0, "{result}");
        assert!(
            result["elapsed_ns"].as_u64().unwrap() >= 50_000_000,
            "{result}"
        );
    }
    assert_eq!(fs::metadata(&file).unwrap().len(), 65536);
    let contents = fs::read(&file).unwrap();
    let pattern: Vec<u8> = (0..4096_usize)
        .map(|index| (index * 31 + 17) as u8)
        .collect();
    // The first offset of a 64 KiB file is its first block.
    assert_eq!(&contents[..4096], pattern);

    // A missing file cannot open, and an empty one cannot transfer a block.
    let missing = directory.path().join("missing");
    let mut arguments = arguments("read", "existing");
    arguments[1] = missing.to_str().unwrap().to_owned();
    assert_eq!(device_io(&arguments), (Some(3), None));
    fs::write(&missing, b"").unwrap();
    arguments[4] = "4096".to_owned();
    assert_eq!(device_io(&arguments), (Some(4), None));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn device_io_measures_a_network_round_trip() {
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let (first, received) = mpsc::channel();
    let echo = thread::spawn(move || {
        let mut buffer = [0; 128];
        let mut count = 0;
        // The benchmark sends until its duration passes and stops when its socket closes, so
        // the echo stops at the first silence.
        while let Ok((length, peer)) = socket.recv_from(&mut buffer) {
            if count == 0 {
                first.send(buffer[..length].to_vec()).unwrap();
            }
            count += 1;
            socket.send_to(&buffer[..length], peer).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
        }
    });
    let port = port.to_string();
    let (status, result) = device_io(["network", "127.0.0.1", &port, "100"]);
    let result = result.unwrap();
    assert_eq!(status, Some(0), "{result}");
    assert_eq!(result["device"], "network");
    assert_eq!(result["operation"], "roundtrip");
    assert_eq!(result["bytes_per_operation"], 64);
    assert!(result["operations"].as_u64().unwrap() > 0, "{result}");
    assert!(
        result["elapsed_ns"].as_u64().unwrap() >= 100_000_000,
        "{result}"
    );
    let payload: Vec<u8> = (1..=64).collect();
    assert_eq!(received.recv().unwrap(), payload);
    echo.join().unwrap();
}

#[test]
#[cfg(target_arch = "x86_64")]
fn device_io_exits_255_when_it_cannot_print() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("disk");
    let output = Command::new(binary("nvx-device-io"))
        .args([
            "file",
            file.to_str().unwrap(),
            "write",
            "1",
            "4096",
            "buffered",
        ])
        .arg("create")
        .stdout(fs::File::create("/dev/full").unwrap())
        .output()
        .unwrap();
    assert_eq!(
        (output.status.code(), output.stderr),
        (Some(255), Vec::new())
    );
    // A closed pipe raises SIGPIPE, whose default disposition the program keeps.
    use std::os::unix::process::ExitStatusExt;
    let path = file.to_str().unwrap();
    let arguments = ["file", path, "read", "1", "4096", "buffered", "existing"];
    let (status, stderr) = run_to("nvx-device-io", arguments, broken_pipe());
    assert_eq!((status.signal(), stderr), (Some(13), Vec::new()));
}

fn helper_config(flags: u16, cwd: &[u8], environment: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&(environment.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(cwd.len() as u32).to_le_bytes());
    bytes.extend_from_slice(cwd);
    for entry in environment {
        bytes.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        bytes.extend_from_slice(entry);
    }
    bytes
}

fn run_agent_helper(
    config: &[u8],
    workload: &[&OsStr],
    directory: Option<&Path>,
    environment: &[(&str, &str)],
) -> Output {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(config).unwrap();
    file.rewind().unwrap();
    let fd = file.as_raw_fd();
    // SAFETY: the test owns the descriptor. The helper deliberately inherits it, then closes it
    // before it executes the workload.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let mut command = Command::new(binary("nvx-managed-agent"));
    command
        .arg("--exec-config-fd")
        .arg(fd.to_string())
        .arg("--")
        .args(workload)
        .env_clear();
    for (name, value) in environment {
        command.env(name, value);
    }
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    command.output().unwrap()
}

#[test]
fn managed_agent_helper_round_trips_environment_and_cwd() {
    const CWD_PRESENT: u16 = 1;
    const ENVIRONMENT_PRESENT: u16 = 2;
    const INHERIT_DEFAULT_ENV: u16 = 4;
    let env = OsStr::new("/usr/bin/env");
    let pwd = OsStr::new("/bin/pwd");

    let output = run_agent_helper(
        &helper_config(0, &[], &[]),
        &[env],
        None,
        &[("BASE", "inherited"), ("NVX_EXEC_CONFIG_FD", "synthetic")],
    );
    assert_eq!((output.status.code(), output.stderr), (Some(0), Vec::new()));
    let lines: std::collections::BTreeSet<_> = output.stdout.split(|&byte| byte == b'\n').collect();
    assert!(lines.contains(b"BASE=inherited".as_slice()));
    assert!(lines.contains(b"PWD=/".as_slice()));
    assert!(
        !output
            .stdout
            .windows(b"NVX_EXEC_CONFIG_FD".len())
            .any(|window| window == b"NVX_EXEC_CONFIG_FD")
    );

    let output = run_agent_helper(
        &helper_config(ENVIRONMENT_PRESENT, &[], &[]),
        &[env],
        None,
        &[("BASE", "inherited"), ("NVX_EXEC_CONFIG_FD", "synthetic")],
    );
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), Vec::new(), Vec::new())
    );

    let output = run_agent_helper(
        &helper_config(CWD_PRESENT | ENVIRONMENT_PRESENT, b"/tmp", &[]),
        &[pwd],
        None,
        &[],
    );
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"/tmp\n".to_vec(), Vec::new())
    );

    let output = run_agent_helper(
        &helper_config(
            ENVIRONMENT_PRESENT | INHERIT_DEFAULT_ENV,
            &[],
            &[b"VALUE=layered"],
        ),
        &[env],
        None,
        &[("BASE", "inherited"), ("NVX_EXEC_CONFIG_FD", "synthetic")],
    );
    assert_eq!(output.status.code(), Some(0));
    let lines: std::collections::BTreeSet<_> = output.stdout.split(|&byte| byte == b'\n').collect();
    assert!(lines.contains(b"BASE=inherited".as_slice()));
    assert!(lines.contains(b"VALUE=layered".as_slice()));
    assert!(
        !output
            .stdout
            .windows(b"NVX_EXEC_CONFIG_FD".len())
            .any(|window| window == b"NVX_EXEC_CONFIG_FD")
    );

    let output = run_agent_helper(
        &helper_config(
            CWD_PRESENT | ENVIRONMENT_PRESENT,
            b"/tmp",
            &[b"PWD=/caller"],
        ),
        &[env],
        None,
        &[],
    );
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"PWD=/caller\n".to_vec(), Vec::new())
    );
}

#[test]
fn managed_agent_helper_keeps_requested_pwd_and_reports_unusable_cwd() {
    const CWD_PRESENT: u16 = 1;
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("a/b");
    let second = directory.path().join("a/c");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir(&second).unwrap();
    std::os::unix::fs::symlink(directory.path().join("a"), directory.path().join("link")).unwrap();
    let cases = [
        (directory.path().join("a/b/."), first.clone()),
        (directory.path().join("a/b/../c"), second),
        (directory.path().join("a//b"), first.clone()),
        (PathBuf::from(format!("{}/", first.display())), first),
        (
            directory.path().join("link/b"),
            directory.path().join("link/b"),
        ),
    ];
    for (requested, expected) in cases {
        let output = run_agent_helper(
            &helper_config(CWD_PRESENT, requested.as_os_str().as_bytes(), &[]),
            &[OsStr::new("/usr/bin/env")],
            None,
            &[],
        );
        assert_eq!(output.status.code(), Some(0), "{requested:?}");
        let expected = [b"PWD=".as_slice(), expected.as_os_str().as_bytes()].concat();
        assert!(
            output
                .stdout
                .split(|&byte| byte == b'\n')
                .any(|line| line == expected),
            "{requested:?}: {:?}",
            output.stdout
        );
    }

    let missing = directory.path().join("missing");
    let output = run_agent_helper(
        &helper_config(CWD_PRESENT, missing.as_os_str().as_bytes(), &[]),
        &[OsStr::new("/bin/true")],
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stdout.is_empty());
    assert!(
        output
            .stderr
            .windows(b"cannot use working directory".len())
            .any(|window| window == b"cannot use working directory")
    );
}

#[test]
fn managed_agent_helper_accepts_large_exact_environment() {
    const ENVIRONMENT_PRESENT: u16 = 2;
    let entries: Vec<Vec<u8>> = (0..12)
        .map(|index| {
            let mut entry = format!("KEY{index}=").into_bytes();
            entry.extend(std::iter::repeat_n(b'x', 4000));
            entry
        })
        .collect();
    let references: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    let output = run_agent_helper(
        &helper_config(ENVIRONMENT_PRESENT, &[], &references),
        &[OsStr::new("/usr/bin/env")],
        None,
        &[],
    );
    assert_eq!((output.status.code(), output.stderr), (Some(0), Vec::new()));
    let expected: Vec<u8> = entries
        .iter()
        .flat_map(|entry| entry.iter().copied().chain(std::iter::once(b'\n')))
        .collect();
    assert_eq!(output.stdout, expected);
}

#[test]
fn managed_agent_helper_defensively_rejects_bad_configuration() {
    const CWD_PRESENT: u16 = 1;
    const ENVIRONMENT_PRESENT: u16 = 2;
    const CWD_ENTERED: u16 = 0x8000;
    let workload = [OsStr::new("/bin/pwd")];
    for config in [
        helper_config(CWD_PRESENT, b".", &[]),
        helper_config(CWD_PRESENT | CWD_ENTERED, b"/", &[]),
        helper_config(ENVIRONMENT_PRESENT, &[], &[b"NO_EQUALS"]),
        helper_config(ENVIRONMENT_PRESENT, &[], &[b"=value"]),
        helper_config(ENVIRONMENT_PRESENT, &[], &[b"KEY=embedded\0nul"]),
    ] {
        let output = run_agent_helper(&config, &workload, None, &[]);
        assert_eq!(output.status.code(), Some(125), "{config:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn managed_agent_helper_keeps_an_entered_directory() {
    const CWD_ENTERED: u16 = 0x8000;
    let directory = tempfile::tempdir().unwrap();
    let output = run_agent_helper(
        &helper_config(CWD_ENTERED, &[], &[]),
        &[OsStr::new("/bin/pwd")],
        Some(directory.path()),
        &[("BASE", "inherited")],
    );
    let expected = [directory.path().as_os_str().as_bytes(), b"\n"].concat();
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), expected, Vec::new())
    );
}

#[test]
fn managed_agent_helper_closes_its_internal_descriptor() {
    const CWD_ENTERED: u16 = 0x8000;
    let script = OsStr::new(r#"test ! -e "/proc/self/fd/$1""#);
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&helper_config(CWD_ENTERED, &[], &[]))
        .unwrap();
    file.rewind().unwrap();
    let fd = file.as_raw_fd();
    // SAFETY: this descriptor is intentionally inherited by the helper.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let output = Command::new(binary("nvx-managed-agent"))
        .args([
            OsStr::new("--exec-config-fd"),
            OsStr::new(&fd.to_string()),
            OsStr::new("--"),
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            script,
            OsStr::new("sh"),
            OsStr::new(&fd.to_string()),
        ])
        .output()
        .unwrap();
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), Vec::new(), Vec::new())
    );
}

#[test]
fn managed_agent_bad_helper_syntax_exits_125() {
    for arguments in [
        &[][..],
        &["--exec-config-fd"],
        &["--exec-config-fd", "-1", "--", "/bin/true"],
        &["--exec-config-fd", "0", "--", "bin/true"],
    ] {
        assert_eq!(
            run("nvx-managed-agent", arguments).0,
            Some(125),
            "{arguments:?}"
        );
    }
}

const INGRESS_TABLE_HEADER: &str =
    "  sl  local_address rem_address st tx rx tr tm retr uid timeout inode\n";

fn ingress_kernel_address(address: std::net::IpAddr) -> String {
    let octets = match address {
        std::net::IpAddr::V4(address) => address.octets().to_vec(),
        std::net::IpAddr::V6(address) => address.octets().to_vec(),
    };
    octets
        .chunks_exact(4)
        .map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().unwrap())))
        .collect()
}

fn ingress_row(index: usize, address: &str, port: u16, state: u8, inode: u64) -> String {
    let address: std::net::IpAddr = address.parse().unwrap();
    let remote: std::net::IpAddr = match address {
        std::net::IpAddr::V4(_) => "0.0.0.0".parse().unwrap(),
        std::net::IpAddr::V6(_) => "::".parse().unwrap(),
    };
    format!(
        "{index:4}: {}:{port:04X} {}:0000 {state:02X} \
         00000000:00000000 00:00000000 00000000 0 0 {inode} \
         2 0000000000000000\n",
        ingress_kernel_address(address),
        ingress_kernel_address(remote),
    )
}

fn write_ingress_snapshot(directory: &Path, index: u32, time: &[u8], rows: &[(&str, String)]) {
    let root = directory.join(index.to_string());
    fs::create_dir_all(root.join("net")).unwrap();
    fs::write(root.join("time"), time).unwrap();
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        let mut contents = INGRESS_TABLE_HEADER.to_owned();
        for (_, row) in rows.iter().filter(|(name, _)| *name == table) {
            contents.push_str(row);
        }
        fs::write(root.join("net").join(table), contents).unwrap();
    }
}

#[test]
fn ingress_test_mode_prints_the_golden_vector_from_prebuilt_binaries() {
    let directory = tempfile::tempdir().unwrap();
    write_ingress_snapshot(
        directory.path(),
        0,
        b"0\n",
        &[
            ("tcp", ingress_row(0, "0.0.0.0", 8080, 0x0a, 1)),
            ("tcp6", ingress_row(1, "fd00::a00:2", 8443, 0x0a, 2)),
        ],
    );
    assert_eq!(
        run(
            "nvx-ingress",
            [OsStr::new("test"), directory.path().as_os_str()]
        ),
        (
            Some(0),
            b"0 4e56584c0100000206011f90060220fb\n".to_vec(),
            Vec::new(),
        )
    );
}

#[test]
fn ingress_test_mode_preserves_udp_settling_between_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let rows = [("udp", ingress_row(0, "0.0.0.0", 7201, 0x07, 10))];
    write_ingress_snapshot(directory.path(), 0, b"0\n", &rows);
    write_ingress_snapshot(directory.path(), 1, b"1000\n", &rows);
    assert_eq!(
        run(
            "nvx-ingress",
            [OsStr::new("test"), directory.path().as_os_str()]
        ),
        (
            Some(0),
            [
                b"0 4e56584c01000000\n".as_slice(),
                b"1000 4e56584c0100000111011c21\n",
            ]
            .concat(),
            Vec::new(),
        )
    );
}

#[test]
fn ingress_rejects_bad_invocations_and_test_snapshots() {
    let usage = b"usage: nvx-ingress GATEWAY_IPV4\n".to_vec();
    assert_eq!(
        run("nvx-ingress", std::iter::empty::<&str>()),
        (Some(2), Vec::new(), usage.clone())
    );
    assert_eq!(
        run("nvx-ingress", ["not-an-ipv4-address"]),
        (Some(2), Vec::new(), usage)
    );

    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        run(
            "nvx-ingress",
            [OsStr::new("test"), directory.path().as_os_str()]
        ),
        (Some(1), Vec::new(), Vec::new())
    );
    write_ingress_snapshot(directory.path(), 0, b"bad\n", &[]);
    assert_eq!(
        run(
            "nvx-ingress",
            [OsStr::new("test"), directory.path().as_os_str()]
        ),
        (Some(1), Vec::new(), Vec::new())
    );
    write_ingress_snapshot(directory.path(), 0, b"7\n", &[]);
    write_ingress_snapshot(directory.path(), 1, b"bad\n", &[]);
    assert_eq!(
        run(
            "nvx-ingress",
            [OsStr::new("test"), directory.path().as_os_str()]
        ),
        (Some(1), b"7 4e56584c01000000\n".to_vec(), Vec::new(),)
    );

    let overlong = std::ffi::OsString::from_vec(vec![b'a'; 4094]);
    assert_eq!(
        run("nvx-ingress", [OsStr::new("test"), &overlong]),
        (Some(1), Vec::new(), Vec::new())
    );
}

const TIME_UTC_NS: u64 = 1_790_841_600_123_456_789;

fn time_packet(
    flags: u8,
    online: u8,
    ranges: &[(u64, u64)],
    generation: u32,
    rate_deviation: i32,
    downtime_ns: u64,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32 + ranges.len() * 16 + 64);
    packet.extend_from_slice(b"OVR");
    packet.extend_from_slice(&[4, flags, online, ranges.len() as u8, 0]);
    packet.extend_from_slice(&generation.to_le_bytes());
    packet.extend_from_slice(&rate_deviation.to_le_bytes());
    packet.extend_from_slice(&downtime_ns.to_le_bytes());
    packet.extend_from_slice(&TIME_UTC_NS.to_le_bytes());
    for &(start, length) in ranges {
        packet.extend_from_slice(&start.to_le_bytes());
        packet.extend_from_slice(&length.to_le_bytes());
    }
    packet.extend(0_u8..64);
    packet
}

fn time_fixture(directory: &Path, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn time_test_mode_decodes_packets_samples_and_arithmetic() {
    let directory = tempfile::tempdir().unwrap();
    let packet = time_fixture(
        directory.path(),
        "packet",
        time_packet(0x0d, 4, &[], 3, -13_107_200, 30_000_000_000),
    );
    assert_eq!(
        run(
            "nvx-time",
            [
                OsStr::new("test"),
                OsStr::new("packet"),
                packet.as_os_str(),
                OsStr::new("2"),
                OsStr::new("ffffffffffffffffffffffffffffffff"),
            ]
        ),
        (
            Some(0),
            concat!(
                "ok flags=13 online=4 ranges=0 generation=3 ",
                "rate_deviation=-13107200 frequency=13107200 ",
                "downtime_ns=30000000000 utc_ns=1790841600123456789 ",
                "generation_id=000102030405060708090a0b0c0d0e0f\n"
            )
            .as_bytes()
            .to_vec(),
            Vec::new(),
        )
    );

    let ranges = time_fixture(
        directory.path(),
        "ranges",
        time_packet(
            0x02,
            0,
            &[(0x8000_0000, 0x0800_0000), (0x1_0000_0000, 0x1000_0000)],
            1,
            0,
            0,
        ),
    );
    let output = run(
        "nvx-time",
        [
            OsStr::new("test"),
            OsStr::new("packet"),
            ranges.as_os_str(),
            OsStr::new("0"),
            OsStr::new("ffffffffffffffffffffffffffffffff"),
        ],
    );
    assert_eq!(output.0, Some(0));
    assert!(
        output
            .1
            .ends_with(b" range=2147483648:134217728 range=4294967296:268435456\n")
    );

    let mut sample = Vec::new();
    sample.extend_from_slice(&[1, 8]);
    sample.extend_from_slice(&0_u16.to_le_bytes());
    sample.extend_from_slice(&4_u32.to_le_bytes());
    sample.extend_from_slice(&TIME_UTC_NS.to_le_bytes());
    let sample = time_fixture(directory.path(), "sample", sample);
    assert_eq!(
        run(
            "nvx-time",
            [
                OsStr::new("test"),
                OsStr::new("sample"),
                sample.as_os_str(),
                OsStr::new("4")
            ]
        ),
        (
            Some(0),
            b"ok flags=8 generation=4 utc_ns=1790841600123456789\n".to_vec(),
            Vec::new(),
        )
    );
    assert_eq!(
        run("nvx-time", ["test", "pair", "1000", "3000", "5000"]),
        (
            Some(0),
            b"theta_ns=3000 epsilon_ns=1000\n".to_vec(),
            Vec::new()
        )
    );
    assert_eq!(
        run("nvx-time", ["test", "frequency", "-40000000"]),
        (
            Some(0),
            b"frequency=32768000 ppb=500000\n".to_vec(),
            Vec::new()
        )
    );
    assert_eq!(
        run(
            "nvx-time",
            ["test", "correction", "-1128000000", "10", "slow"]
        ),
        (
            Some(0),
            b"step modes=0x2100 sec=-2 nsec=872000000\n".to_vec(),
            Vec::new()
        )
    );
}

#[test]
fn time_test_mode_checks_logs_timer_state_and_status() {
    let directory = tempfile::tempdir().unwrap();
    let boot = time_fixture(
        directory.path(),
        "boot",
        concat!(
            "Hypervisor detected: Microsoft Hyper-V\n",
            "Hyper-V: privilege flags low 0x8860, high 0x0\n",
            "Hyper-V: LAPIC Timer Frequency: 0x1e8480\n",
            "clocksource: Switched to clocksource tsc-early\n",
            "clocksource: Switched to clocksource tsc\n"
        ),
    );
    assert_eq!(
        run(
            "nvx-time",
            [OsStr::new("test"), OsStr::new("boot-log"), boot.as_os_str()]
        ),
        (Some(0), b"ok\n".to_vec(), Vec::new())
    );
    let kmsg = time_fixture(
        directory.path(),
        "kmsg",
        concat!(
            "tsc: Marking TSC unstable due to watchdog\n",
            "clocksource: tsc: mask: 0xffff\n"
        ),
    );
    assert_eq!(
        run(
            "nvx-time",
            [OsStr::new("test"), OsStr::new("kmsg"), kmsg.as_os_str()]
        ),
        (Some(0), b"G_TSC_UNSTABLE\nnone\n".to_vec(), Vec::new())
    );

    let timer = time_fixture(
        directory.path(),
        "timer",
        concat!(
            "Tick Device: mode:     1\n",
            "Broadcast device\n",
            "Clock Event Device: <NULL>\n",
            "Tick Device: mode:     1\n",
            "Per CPU device: 0\n",
            "Clock Event Device: lapic\n",
            " mode:           3\n",
            " event_handler:  hrtimer_interrupt\n"
        ),
    );
    assert_eq!(
        run(
            "nvx-time",
            [
                OsStr::new("test"),
                OsStr::new("timer-list"),
                timer.as_os_str(),
                OsStr::new("0"),
            ]
        ),
        (Some(0), b"ok\n".to_vec(), Vec::new())
    );

    let state_text = concat!(
        "version=1\n",
        "generation=2\n",
        "boot_status=ok\n",
        "boot_cpus=8\n",
        "boot_elapsed_us=2400\n",
        "boot_cpu_us=1900\n",
        "tsc_hz=2194843000\n",
        "lapic_hz=200000000\n",
        "synchronized=1\n",
        "offset_ns=-42\n",
        "uncertainty_ns=1800\n",
        "last_sample_error=none\n"
    );
    let state = time_fixture(directory.path(), "state", state_text);
    assert_eq!(
        run(
            "nvx-time",
            [OsStr::new("test"), OsStr::new("state"), state.as_os_str()]
        )
        .1,
        concat!(
            "version=1\ngeneration=2\nboot_status=ok\nboot_cpus=8\n",
            "boot_elapsed_us=2400\nboot_cpu_us=1900\n",
            "tsc_hz=2194843000\nlapic_hz=200000000\n",
            "discontinuities=0\nlast_discontinuity=none\nlast_step_ns=0\n",
            "last_step_realtime_ns=0\nlast_downtime_ns=0\n",
            "last_downtime_source=none\nsynchronized=1\noffset_ns=-42\n",
            "uncertainty_ns=1800\nfrequency_ppb=0\nsamples=0\n",
            "rejected_samples=0\nlast_sample_error=none\nviolations=0\n"
        )
        .as_bytes()
    );
    let status = run(
        "nvx-time",
        [
            OsStr::new("test"),
            OsStr::new("status"),
            state.as_os_str(),
            OsStr::new("enforcing"),
        ],
    );
    assert_eq!(status.0, Some(0));
    assert!(
        status
            .1
            .starts_with(b"NVX-TIME-ABI: v=1 phase=boot status=ok cpus=8 tsc_hz=2194843000 ")
    );
    assert!(status.1.ends_with(b"last_sample_error=none\nok=1\n"));
}

#[test]
fn time_test_mode_preserves_parser_and_usage_failures() {
    let usage = concat!(
        "usage: nvx-time [--report-only] COMMAND\n",
        "  boot\n",
        "  check --phase capture|restore [--new-cpus LIST]\n",
        "  pre-capture\n",
        "  capture 0|1 GENERATION_ID ENTROPY_FILE [--finish]\n",
        "  cancel-capture\n",
        "  restore-finish [--ack] [--new-cpus LIST]\n",
        "  status\n",
        "  sample\n",
        "  generation-id\n",
        "  exhaustive\n",
        "  test NAME ARGUMENTS...\n"
    )
    .as_bytes()
    .to_vec();
    assert_eq!(
        run("nvx-time", std::iter::empty::<&str>()),
        (Some(2), Vec::new(), usage)
    );
    assert_eq!(
        run("nvx-time", ["test", "deferral"]),
        (
            Some(0),
            b"deferred_start_ms=150 idle_bound_ms=100\n".to_vec(),
            Vec::new()
        )
    );
    assert_eq!(
        run(
            "nvx-time",
            [
                "test",
                "exhaustive-leaf",
                "0x40000081",
                "1",
                "2",
                "3",
                "4",
                "1",
                "2",
                "3",
                "4"
            ]
        )
        .1,
        concat!(
            "fail leaf 0x40000081 is 00000001 00000002 00000003 00000004 ",
            "(signature \"............\"), expected zero\n"
        )
        .as_bytes()
    );
}

fn run_time_packet(
    directory: &Path,
    name: &str,
    packet: &[u8],
    recorded: &str,
    previous: &str,
) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let path = time_fixture(directory, name, packet);
    run(
        "nvx-time",
        [
            OsStr::new("test"),
            OsStr::new("packet"),
            path.as_os_str(),
            OsStr::new(recorded),
            OsStr::new(previous),
        ],
    )
}

#[test]
fn time_test_mode_checks_packet_and_sample_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let previous = "ffffffffffffffffffffffffffffffff";
    let base = time_packet(0, 0, &[], 1, 0, 0);
    let mut rejected = Vec::new();
    let mutate = |offset: usize, bytes: &[u8]| {
        let mut packet = base.clone();
        packet[offset..offset + bytes.len()].copy_from_slice(bytes);
        packet
    };
    rejected.push(mutate(0, b"OVX"));
    rejected.push(mutate(3, &[3]));
    rejected.push(mutate(4, &[0x10]));
    rejected.push(mutate(5, &[3]));
    rejected.push(mutate(6, &[1]));
    rejected.push(mutate(7, &[1]));
    rejected.push(mutate(8, &0_u32.to_le_bytes()));
    rejected.push(mutate(12, &16_384_001_i32.to_le_bytes()));
    rejected.push(mutate(12, &(-16_384_001_i32).to_le_bytes()));
    rejected.push(mutate(
        16,
        &(2_592_000_u64 * 1_000_000_000 + 1).to_le_bytes(),
    ));
    rejected.push(mutate(24, &0_u64.to_le_bytes()));
    rejected.push(time_packet(0x02, 0, &[(0, 0)], 1, 0, 0));
    rejected.push(time_packet(0x02, 0, &[(u64::MAX - 4095, 8192)], 1, 0, 0));
    for (index, packet) in rejected.iter().enumerate() {
        let output = run_time_packet(
            directory.path(),
            &format!("rejected-{index}"),
            packet,
            "0",
            previous,
        );
        assert_eq!(output.0, Some(0));
        assert!(
            output.1.starts_with(b"error G_REPAIR_PACKET "),
            "case {index}: {:?}",
            String::from_utf8_lossy(&output.1)
        );
    }

    for (index, packet) in [
        time_packet(0, 8, &[], 1, 16_384_000, 2_592_000 * 1_000_000_000),
        time_packet(0, 0, &[], 1, -16_384_000, 0),
    ]
    .iter()
    .enumerate()
    {
        assert!(
            run_time_packet(
                directory.path(),
                &format!("accepted-{index}"),
                packet,
                "0",
                previous
            )
            .1
            .starts_with(b"ok ")
        );
    }
    assert_eq!(
        run_time_packet(directory.path(), "stale", &base, "1", previous).1,
        b"stale\n"
    );
    assert!(
        run_time_packet(directory.path(), "skipped", &base, "2", previous)
            .1
            .starts_with(b"error G_REPAIR_GENERATION ")
    );
    assert!(
        run_time_packet(
            directory.path(),
            "unchanged",
            &base,
            "0",
            "000102030405060708090a0b0c0d0e0f"
        )
        .1
        .starts_with(b"error G_REPAIR_GENERATION ")
    );

    let sample_path =
        |name: &str, version: u8, flags: u8, reserved: u16, generation: u32, utc: u64| {
            let mut sample = vec![version, flags];
            sample.extend_from_slice(&reserved.to_le_bytes());
            sample.extend_from_slice(&generation.to_le_bytes());
            sample.extend_from_slice(&utc.to_le_bytes());
            time_fixture(directory.path(), name, sample)
        };
    let good = sample_path("sample-good", 1, 8, 0, 4, TIME_UTC_NS);
    assert_eq!(
        run(
            "nvx-time",
            [
                OsStr::new("test"),
                OsStr::new("sample"),
                good.as_os_str(),
                OsStr::new("4")
            ]
        )
        .1,
        b"ok flags=8 generation=4 utc_ns=1790841600123456789\n"
    );
    for (index, path) in [
        sample_path("sample-version", 2, 0, 0, 0, TIME_UTC_NS),
        sample_path("sample-flags", 1, 1, 0, 0, TIME_UTC_NS),
        sample_path("sample-reserved", 1, 0, 1, 0, TIME_UTC_NS),
        sample_path("sample-utc", 1, 0, 0, 0, 0),
        sample_path("sample-generation", 1, 0, 0, 3, TIME_UTC_NS),
    ]
    .iter()
    .enumerate()
    {
        let output = run(
            "nvx-time",
            [
                OsStr::new("test"),
                OsStr::new("sample"),
                path.as_os_str(),
                OsStr::new("0"),
            ],
        );
        assert!(
            output.1.starts_with(b"error "),
            "sample case {index}: {:?}",
            String::from_utf8_lossy(&output.1)
        );
    }
}

#[test]
fn time_test_mode_covers_checks_events_records_and_workers() {
    let directory = tempfile::tempdir().unwrap();
    let good_flags = concat!(
        "tsc msr pae constant_tsc rdtscp nonstop_tsc tsc_known_freq ",
        "tsc_reliable hypervisor arat x2apic"
    );
    let cpuinfo = format!(
        "processor : 0\ncpu MHz : 2194.843\nflags : {good_flags}\n\n\
         processor : 1\ncpu MHz : 2194.843\nflags : {good_flags}\n"
    );
    let cpuinfo = time_fixture(directory.path(), "cpuinfo", cpuinfo);
    assert_eq!(
        run(
            "nvx-time",
            [
                OsStr::new("test"),
                OsStr::new("cpuinfo"),
                cpuinfo.as_os_str(),
                OsStr::new("0-1"),
            ]
        )
        .1,
        b"ok cpu0_khz=2194843 cpu1_khz=2194843\n"
    );
    for token in [
        "tsc_early_khz=2194843",
        "lapic_timer_hz=200000000",
        "notsc",
        "nolapic",
        "nolapic_timer",
        "tsc=unstable",
        "hpet=force",
        "clocksource=kvm-clock",
    ] {
        let cmdline = format!("earlycon=xe9 clocksource=tsc {token}");
        assert!(
            run("nvx-time", ["test", "cmdline", &cmdline])
                .1
                .windows(b"code=G_CONFORMANCE_C9".len())
                .any(|window| window == b"code=G_CONFORMANCE_C9")
        );
    }
}

#[test]
fn time_probe_cli_and_small_diagnostics_run() {
    let usage = concat!(
        "usage: nvx-time-probe COMMAND [OPTIONS]\n",
        "\n",
        "Commands:\n",
        "  latency [--iterations N] [--batch B] [--cpu C] [--tsc-hz HZ]\n",
        "      Per-operation cost (p50/p99/min/mean ns) of rdtsc, rdtscp,\n",
        "      lfence;rdtsc, clock_gettime(MONOTONIC/REALTIME) through the vDSO,\n",
        "      and syscall controls. Default: 2000 timed batches of 50 operations\n",
        "      on the current CPU.\n",
        "  warp [--duration-ms N] [--cpus LIST] [--bound-ns N] [--tsc-hz HZ]\n",
        "      Pairwise cross-CPU TSC checks: a check_tsc_warp-style spinlock test\n",
        "      and a ping-pong offset estimate, each running N ms per pair\n",
        "      (default 100). LIST looks like 0-3,6 (default: every CPU in the\n",
        "      affinity mask). The bound defaults to 1000 ns.\n",
        "  clock [--measure-ms N] [--tsc-hz HZ] [--msr]\n",
        "      Clocks, clocksources, TSC flags, CPUID time leaves, hypervisor and\n",
        "      time kernel messages, and the /proc/timer_list clock event summary.\n",
        "      --msr also reads the TSC, Hyper-V time, and kvmclock MSRs on CPU 0\n",
        "      through /dev/cpu/0/msr (a #GP is reported, not raised).\n",
        "  version\n",
        "\n",
        "The TSC rate comes from --tsc-hz, sysfs tsc_freq_khz, the kernel log, or\n",
        "/proc/cpuinfo, in that order, and is measured as a last resort.\n",
        "Exit status: 0 success, 1 warp FAIL, 2 usage error, 3 runtime error.\n"
    )
    .as_bytes()
    .to_vec();
    assert_eq!(
        run("nvx-time-probe", std::iter::empty::<&str>()),
        (Some(2), Vec::new(), usage.clone())
    );
    assert_eq!(
        run("nvx-time-probe", ["version"]),
        (Some(0), b"nvx-time-probe 1.1\n".to_vec(), Vec::new())
    );
    assert_eq!(
        run("nvx-time-probe", ["--help"]),
        (Some(0), usage, Vec::new())
    );
    assert_eq!(
        run("nvx-time-probe", ["latency", "--iterations=0"]),
        (
            Some(2),
            Vec::new(),
            b"nvx-time-probe latency: invalid option or value: --iterations=0\n".to_vec()
        )
    );

    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: sched_getaffinity initializes the local set.
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &raw mut affinity) },
        0
    );
    let cpu = (0..libc::CPU_SETSIZE as usize)
        .find(|cpu| unsafe { libc::CPU_ISSET(*cpu, &affinity) })
        .unwrap();
    let cpu = cpu.to_string();
    let latency = run(
        "nvx-time-probe",
        [
            "latency",
            "--iterations",
            "16",
            "--batch",
            "2",
            "--cpu",
            &cpu,
            "--tsc-hz",
            "2500000000",
        ],
    );
    assert_eq!(latency.0, Some(0));
    assert!(latency.2.is_empty());
    assert!(
        latency
            .1
            .starts_with(format!("nvx-time-probe 1.1 latency: cpu={cpu} ").as_bytes())
    );
    assert_eq!(
        latency
            .1
            .windows(b"NVX-TIME-PROBE latency method=".len())
            .filter(|window| *window == b"NVX-TIME-PROBE latency method=")
            .count(),
        8
    );

    let warp = run(
        "nvx-time-probe",
        [
            "warp",
            "--duration-ms",
            "1",
            "--cpus",
            &cpu,
            "--bound-ns",
            "1000",
            "--tsc-hz",
            "2500000000",
        ],
    );
    assert_eq!(warp.0, Some(0));
    assert!(warp.2.is_empty());
    assert!(
        warp.1.ends_with(
            format!(
                "NVX-TIME-PROBE warp-detail max_abs_offset_cycles=0.0 \
                 max_uncertainty_ns=0 max_skew_bound_ns=0 total_warps=0 \
                 inconsistent_pairs=0 stalled_pairs=0 cpus={cpu} duration_ms=1 \
                 tsc_hz=2500000000 tsc_hz_source=option conclusive=1\n"
            )
            .as_bytes()
        )
    );

    let clock = run(
        "nvx-time-probe",
        ["clock", "--measure-ms", "0", "--tsc-hz", "2500000000"],
    );
    assert_eq!(clock.0, Some(0));
    assert!(clock.2.is_empty());
    assert!(
        clock
            .1
            .starts_with(b"nvx-time-probe 1.1 clock\n== clocks\n")
    );
    assert!(
        clock
            .1
            .windows(b"\nNVX-TIME-PROBE clock ".len())
            .any(|window| window == b"\nNVX-TIME-PROBE clock ")
    );
}

#[test]
fn time_test_mode_covers_remaining_events_records_and_workers() {
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        run(
            "nvx-time",
            [
                "test",
                "clocksource",
                "tsc\n",
                "tsc refined-jiffies jiffies\n"
            ]
        )
        .1,
        b"ok\n"
    );
    for (current, available) in [
        ("tsc-early\n", "tsc-early \n"),
        ("tsc\n", "tsc kvm-clock \n"),
        ("refined-jiffies\n", "refined-jiffies \n"),
    ] {
        assert!(
            run("nvx-time", ["test", "clocksource", current, available])
                .1
                .windows(b"code=G_CONFORMANCE_C6".len())
                .any(|window| window == b"code=G_CONFORMANCE_C6")
        );
    }

    assert_eq!(
        run(
            "nvx-time",
            [
                "test",
                "event",
                "G_UNCHECKED_MSR",
                "watcher",
                "runtime",
                "3",
                "123456789",
                "unchecked \"MSR\"\\ access\u{1}",
            ]
        )
        .1,
        concat!(
            "NVX-TIME-ABI-VIOLATION: v=1 code=G_UNCHECKED_MSR source=watcher ",
            "phase=runtime generation=3 boottime_ns=123456789 ",
            "detail=\"unchecked \\\"MSR\\\"\\\\ access\\x01\"\n"
        )
        .as_bytes()
    );
    let long_event = run(
        "nvx-time",
        [
            OsStr::new("test"),
            OsStr::new("event"),
            OsStr::new("G_HUNG_TASK"),
            OsStr::new("watcher"),
            OsStr::new("runtime"),
            OsStr::new("0"),
            OsStr::new("1"),
            &std::ffi::OsString::from_vec(vec![2; 400]),
        ],
    )
    .1;
    assert!(long_event.len() <= 512 && long_event.ends_with(b"\\x02\"\n"));

    for (name, record, expected) in [
        (
            "restore-cpus",
            "generation=3\nnew_cpus=4-6,9\n",
            "generation=3 new_cpus=4,5,6,9 count=4\n",
        ),
        (
            "restore-none",
            "generation=3\nnew_cpus=none\n",
            "generation=3 new_cpus=none count=0\n",
        ),
        (
            "restore-absent",
            "generation=3\n",
            "generation=3 new_cpus=none count=0\n",
        ),
    ] {
        let record = time_fixture(directory.path(), name, record);
        assert_eq!(
            run(
                "nvx-time",
                [
                    OsStr::new("test"),
                    OsStr::new("restore-record"),
                    record.as_os_str()
                ]
            )
            .1,
            expected.as_bytes()
        );
    }

    // These exercise the same thread promotion, affinity merge, and at-fork CPU accounting
    // paths as the production deferred boot and restore workers.
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: sched_getaffinity initializes the local set.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &raw mut affinity) }
        == 0
        && let Some(cpu) = (0..64).find(|cpu| unsafe { libc::CPU_ISSET(*cpu, &affinity) })
    {
        let output = run("nvx-time", ["test", "parallel", &cpu.to_string()]);
        assert_eq!(output.0, Some(0));
        assert!(output.1.ends_with(b"failures=7\n"));
    }
    let promoted = run("nvx-time", ["test", "promote"]);
    assert_eq!(promoted.0, Some(0));
    assert!(promoted.1.starts_with(b"promoted caller="));
    assert!(
        promoted
            .1
            .windows(b"\nstopped caller=".len())
            .any(|window| window == b"\nstopped caller=")
    );
    let idle = run("nvx-time", ["test", "idle-priority"]);
    assert_eq!(idle.0, Some(0));
    assert!(idle.1.starts_with(b"idle=5 normal="));
    let cpu = run("nvx-time", ["test", "step13-cpu", "20", "30", "10"]);
    assert_eq!(cpu.0, Some(0));
    assert!(cpu.1.starts_with(b"prior_ms="));
    assert!(
        cpu.1
            .windows(b" total_ms=".len())
            .any(|window| window == b" total_ms=")
    );
}
