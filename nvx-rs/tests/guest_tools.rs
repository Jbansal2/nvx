//! Runs the guest binaries as programs: their command lines, exit statuses, and output.
//!
//! The tests run the binaries that Cargo builds for them, or, when `NVX_GUEST_BINARIES` names a
//! directory, the binaries there, such as the `guest`-profile builds that CI checks.
#![cfg(all(target_os = "linux", feature = "guest"))]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
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
