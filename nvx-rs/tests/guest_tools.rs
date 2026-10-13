//! Runs the guest binaries as programs: their command lines, exit statuses, and output.
//!
//! The tests run the binaries that Cargo builds for them, or, when `NVX_GUEST_BINARIES` names a
//! directory, the binaries there, such as the `guest`-profile builds that CI checks.
#![cfg(all(target_os = "linux", feature = "guest"))]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ENOENT: i32 = 2;

/// Returns the path of the guest binary `name`.
fn binary(name: &str) -> PathBuf {
    if let Some(directory) = std::env::var_os("NVX_GUEST_BINARIES") {
        return Path::new(&directory).join(name);
    }
    PathBuf::from(match name {
        "nvx-console-pending" => env!("CARGO_BIN_EXE_nvx-console-pending"),
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
