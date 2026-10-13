//! `nvx-port-io`: reads and writes x86 I/O ports through `/dev/port`, and reads the VM generation
//! ID that OpenVMM exposes behind a selector port.
//!
//! - `read-u8 PORT` prints the byte at PORT in decimal.
//! - `write-u8 PORT VALUE` writes the byte VALUE to PORT.
//! - `read-generation-id DATA_PORT SELECT_PORT [OUTPUT]` checks the availability bit of the
//!   status byte at SELECT_PORT, selects the generation ID, reads its 16 bytes from DATA_PORT, and
//!   prints them in hexadecimal or writes them to OUTPUT. It holds the lock of the time ABI's
//!   selector transactions meanwhile.

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::process::ExitCode;

use super::parse::parse_u64;
use super::sys::{self, Errno};

const USAGE: &[u8] = b"usage: nvx-port-io read-generation-id DATA_PORT SELECT_PORT [OUTPUT] \
| read-u8 PORT | write-u8 PORT VALUE\n";
const PORT_MAX: u64 = 0xffff;
const GENERATION_ID_SELECT: u8 = 0xa6;
const GENERATION_ID_SIZE: usize = 16;
const STATUS_GENERATION_ID_AVAILABLE: u8 = 32;

/// The files that the program uses.
struct Paths<'a> {
    /// The I/O port device, `/dev/port`.
    port: &'a CStr,
    /// The directory of the lock, `/run/nvx`.
    lock_directory: &'a CStr,
    /// The lock that serializes selector transactions with the time ABI, `/run/nvx/portb.lock`.
    lock: &'a CStr,
}

const PATHS: Paths<'static> = Paths {
    port: c"/dev/port",
    lock_directory: c"/run/nvx",
    lock: c"/run/nvx/portb.lock",
};

/// Runs `nvx-port-io` with the process's arguments. It exits with 0, 1 when an operation fails,
/// or 2 for a usage error.
pub fn main() -> ExitCode {
    sys::restore_sigpipe();
    ExitCode::from(run(
        &sys::args(),
        &PATHS,
        &mut sys::Stdout::new(),
        &mut io::stderr(),
    ))
}

fn run(args: &[CString], paths: &Paths<'_>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let port = |index: usize| parse_u64(args[index].as_bytes()).filter(|&port| port <= PORT_MAX);
    if args.len() >= 3
        && let Some(offset) = port(2)
    {
        let command = args[1].as_bytes();
        if args.len() == 3 && command == b"read-u8" {
            return read_u8(paths, offset, out, err);
        }
        if args.len() == 4
            && command == b"write-u8"
            && let Some(value) =
                parse_u64(args[3].as_bytes()).filter(|&value| value <= u64::from(u8::MAX))
        {
            return write_u8(paths, offset, value as u8, err);
        }
        if (args.len() == 4 || args.len() == 5)
            && command == b"read-generation-id"
            && let Some(select_offset) = port(3)
        {
            return read_generation_id(paths, offset, select_offset, args.get(4), out, err);
        }
    }
    sys::report(err, &[USAGE]);
    2
}

fn read_u8(paths: &Paths<'_>, offset: u64, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let Some(port) = open(paths.port, libc::O_RDONLY | libc::O_CLOEXEC, 0, err) else {
        return 1;
    };
    let Some(value) = read_port_byte(port, offset, err) else {
        let _ = sys::close(port);
        return 1;
    };
    if close_port(paths, port, err).is_none() {
        return 1;
    }
    // The C program ignored the result of its printf.
    let _ = sys::print(out, format!("{value}\n").as_bytes());
    0
}

fn write_u8(paths: &Paths<'_>, offset: u64, value: u8, err: &mut dyn Write) -> u8 {
    let Some(port) = open(paths.port, libc::O_WRONLY | libc::O_CLOEXEC, 0, err) else {
        return 1;
    };
    if write_port_byte(port, offset, value, err).is_none() {
        let _ = sys::close(port);
        return 1;
    }
    if close_port(paths, port, err).is_none() {
        return 1;
    }
    0
}

fn read_generation_id(
    paths: &Paths<'_>,
    data_offset: u64,
    select_offset: u64,
    output: Option<&CString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let Some(lock) = lock_portb(paths, err) else {
        return 1;
    };
    let Some(port) = open(paths.port, libc::O_RDWR | libc::O_CLOEXEC, 0, err) else {
        let _ = sys::close(lock);
        return 1;
    };
    let release = |port, lock| {
        let _ = sys::close(port);
        let _ = sys::close(lock);
        1
    };
    let Some(status) = read_port_byte(port, select_offset, err) else {
        return release(port, lock);
    };
    if status & STATUS_GENERATION_ID_AVAILABLE == 0 {
        let message =
            format!("nvx-port-io: VM generation ID is unavailable on port {select_offset:#x}\n");
        sys::report(err, &[message.as_bytes()]);
        return release(port, lock);
    }
    let mut generation_id = [0; GENERATION_ID_SIZE];
    if write_port_byte(port, select_offset, GENERATION_ID_SELECT, err).is_none()
        || !read_port_bytes(port, data_offset, &mut generation_id, err)
    {
        return release(port, lock);
    }
    let _ = sys::close(lock);
    if close_port(paths, port, err).is_none() {
        return 1;
    }

    let Some(path) = output else {
        let mut line: String = generation_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        line.push('\n');
        if sys::print(out, line.as_bytes()).is_err() {
            sys::report(err, &[b"nvx-port-io: write output failed\n"]);
            return 1;
        }
        return 0;
    };
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let Some(descriptor) = open(path, flags, 0o600, err) else {
        return 1;
    };
    if !write_all(descriptor, &generation_id, err) {
        let _ = sys::close(descriptor);
        return 1;
    }
    if let Err(errno) = sys::close(descriptor) {
        report(err, b"close", path, errno);
        return 1;
    }
    0
}

/// Takes the lock that serializes selector transactions on portb with the time ABI.
fn lock_portb(paths: &Paths<'_>, err: &mut dyn Write) -> Option<libc::c_int> {
    // SAFETY: the path is a NUL-terminated string.
    if unsafe { libc::mkdir(paths.lock_directory.as_ptr(), 0o755) } != 0 {
        let errno = Errno::last();
        if errno != Errno(libc::EEXIST) {
            report(err, b"mkdir", paths.lock_directory, errno);
            return None;
        }
    }
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC;
    let lock = open(paths.lock, flags, 0o600, err)?;
    // SAFETY: flock takes an open descriptor.
    if sys::retry(|| unsafe { libc::flock(lock, libc::LOCK_EX) }) != 0 {
        report(err, b"flock", paths.lock, Errno::last());
        let _ = sys::close(lock);
        return None;
    }
    Some(lock)
}

/// Opens `path`, and reports a failure.
fn open(
    path: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
    err: &mut dyn Write,
) -> Option<libc::c_int> {
    // SAFETY: the path is a NUL-terminated string.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags, libc::c_uint::from(mode)) };
    if descriptor < 0 {
        report(err, b"open", path, Errno::last());
        return None;
    }
    Some(descriptor)
}

/// Closes the port device, and reports a failure.
fn close_port(paths: &Paths<'_>, port: libc::c_int, err: &mut dyn Write) -> Option<()> {
    if let Err(errno) = sys::close(port) {
        report(err, b"close", paths.port, errno);
        return None;
    }
    Some(())
}

/// Reads the byte at `offset` of the port device, retrying after `EINTR`.
fn read_port_byte(port: libc::c_int, offset: u64, err: &mut dyn Write) -> Option<u8> {
    let mut value = 0_u8;
    // SAFETY: pread stores at most one byte in `value`.
    let count = sys::retry(|| unsafe {
        libc::pread(port, (&raw mut value).cast(), 1, offset as libc::off_t)
    });
    if count == 1 {
        return Some(value);
    }
    let reason = match count {
        0 => b"unexpected end of file".to_vec(),
        _ => Errno::last().text(),
    };
    let message = format!("nvx-port-io: read port {offset:#x}: ");
    sys::report(err, &[message.as_bytes(), &reason, b"\n"]);
    None
}

/// Writes `value` at `offset` of the port device, retrying after `EINTR`.
fn write_port_byte(port: libc::c_int, offset: u64, value: u8, err: &mut dyn Write) -> Option<()> {
    // SAFETY: pwrite reads one byte from `value`.
    let count = sys::retry(|| unsafe {
        libc::pwrite(port, (&raw const value).cast(), 1, offset as libc::off_t)
    });
    if count == 1 {
        return Some(());
    }
    let reason = match count {
        0 => b"no byte written".to_vec(),
        _ => Errno::last().text(),
    };
    let message = format!("nvx-port-io: write port {offset:#x}: ");
    sys::report(err, &[message.as_bytes(), &reason, b"\n"]);
    None
}

/// Reads each byte of `buffer` from the same port.
fn read_port_bytes(port: libc::c_int, offset: u64, buffer: &mut [u8], err: &mut dyn Write) -> bool {
    for byte in buffer {
        let Some(value) = read_port_byte(port, offset, err) else {
            return false;
        };
        *byte = value;
    }
    true
}

/// Writes all of `bytes`, retrying after `EINTR` and short writes.
fn write_all(descriptor: libc::c_int, bytes: &[u8], err: &mut dyn Write) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        // SAFETY: write reads at most `rest.len()` bytes of `rest`.
        let count =
            sys::retry(|| unsafe { libc::write(descriptor, rest.as_ptr().cast(), rest.len()) });
        if count > 0 {
            offset += count as usize;
            continue;
        }
        let reason = match count {
            0 => b"no byte written".to_vec(),
            _ => Errno::last().text(),
        };
        sys::report(err, &[b"nvx-port-io: write output: ", &reason, b"\n"]);
        return false;
    }
    true
}

/// Reports a failed operation on `path`, as `nvx-port-io: OPERATION PATH: TEXT`.
fn report(err: &mut dyn Write, operation: &[u8], path: &CStr, errno: Errno) {
    let text = errno.text();
    sys::report(
        err,
        &[
            b"nvx-port-io: ",
            operation,
            b" ",
            path.to_bytes(),
            b": ",
            &text,
            b"\n",
        ],
    );
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::guest::sys::tests::Failing;

    /// A regular file that stands for `/dev/port`, and a lock below a temporary directory.
    struct Fixture {
        directory: tempfile::TempDir,
        port: PathBuf,
        lock_directory: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let port = directory.path().join("port");
            fs::write(&port, [0; 0x100]).unwrap();
            let lock_directory = directory.path().join("run");
            Self {
                directory,
                port,
                lock_directory,
            }
        }

        fn run_with(&self, arguments: &[&str], out: &mut dyn Write) -> (u8, Vec<u8>) {
            let mut args = vec![CString::new("nvx-port-io").unwrap()];
            args.extend(
                arguments
                    .iter()
                    .map(|argument| CString::new(*argument).unwrap()),
            );
            let c_path = |path: &Path| CString::new(path.as_os_str().as_bytes()).unwrap();
            let (port, lock_directory) = (c_path(&self.port), c_path(&self.lock_directory));
            let lock = c_path(&self.lock_directory.join("portb.lock"));
            let paths = Paths {
                port: &port,
                lock_directory: &lock_directory,
                lock: &lock,
            };
            let mut err = Vec::new();
            let status = run(&args, &paths, out, &mut err);
            (status, err)
        }

        fn run(&self, arguments: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
            let mut out = Vec::new();
            let (status, err) = self.run_with(arguments, &mut out);
            (status, out, err)
        }

        fn set(&self, offset: usize, value: u8) {
            let mut bytes = fs::read(&self.port).unwrap();
            bytes[offset] = value;
            fs::write(&self.port, bytes).unwrap();
        }

        fn byte(&self, offset: usize) -> u8 {
            fs::read(&self.port).unwrap()[offset]
        }
    }

    fn message(operation: &str, path: &Path, errno: libc::c_int) -> Vec<u8> {
        let mut message = format!("nvx-port-io: {operation} ").into_bytes();
        message.extend_from_slice(path.as_os_str().as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(&Errno(errno).text());
        message.push(b'\n');
        message
    }

    #[test]
    fn usage_names_every_command() {
        let fixture = Fixture::new();
        for arguments in [
            &[][..],
            &["read-u8"],
            &["read-u8", "1", "2"],
            &["read-u8", "0x10000"],
            &["read-u8", "-1"],
            &["read-u8", "1 "],
            &["write-u8", "1"],
            &["write-u8", "1", "256"],
            &["write-u8", "1", "0x"],
            &["read-generation-id", "1"],
            &["read-generation-id", "1", "65536"],
            &["read-generation-id", "1", "2", "out", "extra"],
            &["read", "1"],
        ] {
            assert_eq!(
                fixture.run(arguments),
                (2, Vec::new(), USAGE.to_vec()),
                "{arguments:?}"
            );
        }
        assert_eq!(
            USAGE,
            b"usage: nvx-port-io read-generation-id DATA_PORT SELECT_PORT [OUTPUT] | \
read-u8 PORT | write-u8 PORT VALUE\n"
        );
    }

    #[test]
    fn reads_and_writes_a_byte() {
        let fixture = Fixture::new();
        fixture.set(0x70, 42);
        assert_eq!(
            fixture.run(&["read-u8", "0x70"]),
            (0, b"42\n".to_vec(), Vec::new())
        );
        assert_eq!(
            fixture.run(&["write-u8", "0161", "255"]),
            (0, Vec::new(), Vec::new())
        );
        assert_eq!(fixture.byte(0x71), 255);
        // The C program ignored a failure to print the byte.
        let mut out = Failing(libc::EIO);
        assert_eq!(
            fixture.run_with(&["read-u8", "0x70"], &mut out),
            (0, Vec::new())
        );
    }

    #[test]
    fn reports_a_read_past_the_end_and_a_missing_device() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.run(&["read-u8", "0x200"]),
            (
                1,
                Vec::new(),
                b"nvx-port-io: read port 0x200: unexpected end of file\n".to_vec()
            )
        );
        fs::remove_file(&fixture.port).unwrap();
        for arguments in [&["read-u8", "1"][..], &["write-u8", "1", "1"]] {
            assert_eq!(
                fixture.run(arguments),
                (1, Vec::new(), message("open", &fixture.port, libc::ENOENT))
            );
        }
    }

    #[test]
    fn reads_the_generation_id() {
        let fixture = Fixture::new();
        fixture.set(0x50, STATUS_GENERATION_ID_AVAILABLE | 1);
        fixture.set(0x51, 0x5c);
        let mut expected = "5c".repeat(GENERATION_ID_SIZE).into_bytes();
        expected.push(b'\n');
        assert_eq!(
            fixture.run(&["read-generation-id", "0x51", "0x50"]),
            (0, expected, Vec::new())
        );
        assert_eq!(fixture.byte(0x50), GENERATION_ID_SELECT);
        assert!(fixture.lock_directory.join("portb.lock").is_file());

        fixture.set(0x50, STATUS_GENERATION_ID_AVAILABLE);
        let output = fixture.directory.path().join("generation-id");
        let arguments = ["read-generation-id", "81", "80", output.to_str().unwrap()];
        assert_eq!(fixture.run(&arguments), (0, Vec::new(), Vec::new()));
        assert_eq!(fs::read(&output).unwrap(), [0x5c; GENERATION_ID_SIZE]);

        fixture.set(0x50, STATUS_GENERATION_ID_AVAILABLE);
        let mut out = Failing(libc::EIO);
        assert_eq!(
            fixture.run_with(&["read-generation-id", "0x51", "0x50"], &mut out),
            (1, b"nvx-port-io: write output failed\n".to_vec())
        );
    }

    #[test]
    fn reports_an_unavailable_generation_id() {
        let fixture = Fixture::new();
        fixture.set(0x50, !STATUS_GENERATION_ID_AVAILABLE);
        assert_eq!(
            fixture.run(&["read-generation-id", "0x51", "0x50"]),
            (
                1,
                Vec::new(),
                b"nvx-port-io: VM generation ID is unavailable on port 0x50\n".to_vec()
            )
        );
        assert_eq!(fixture.byte(0x50), !STATUS_GENERATION_ID_AVAILABLE);
    }

    #[test]
    fn refuses_to_follow_an_output_symlink() {
        let fixture = Fixture::new();
        fixture.set(0x50, STATUS_GENERATION_ID_AVAILABLE);
        let link = fixture.directory.path().join("link");
        std::os::unix::fs::symlink(fixture.directory.path().join("target"), &link).unwrap();
        let arguments = ["read-generation-id", "0x51", "0x50", link.to_str().unwrap()];
        assert_eq!(
            fixture.run(&arguments),
            (1, Vec::new(), message("open", &link, libc::ELOOP))
        );
    }

    #[test]
    fn reports_a_lock_directory_that_cannot_exist() {
        let mut fixture = Fixture::new();
        fixture.lock_directory = fixture.port.join("run");
        assert_eq!(
            fixture.run(&["read-generation-id", "0x51", "0x50"]),
            (
                1,
                Vec::new(),
                message("mkdir", &fixture.lock_directory, libc::ENOTDIR)
            )
        );
    }
}
