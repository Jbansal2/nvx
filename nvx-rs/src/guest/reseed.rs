//! `nvx-reseed`: reseeds the kernel's random number generator from a seed file, such as the one
//! that `nvx-snapshot` reads after a restore, and checks the VM generation ID in the seed.
//!
//! - `nvx-reseed SEED_FILE [PREVIOUS_GENERATION_ID]` adds the 64-byte seed to the entropy pool
//!   with full credit and reseeds the CRNG. With a previous generation ID, it first checks that
//!   the seed's generation ID, its first 16 bytes, differs, and afterwards prints it in
//!   hexadecimal.
//! - `nvx-reseed --generation-only SEED_FILE PREVIOUS_GENERATION_ID` only checks and prints the
//!   generation ID.
//! - `nvx-reseed --sample` prints 32 bytes from `getrandom` in hexadecimal.

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::process::ExitCode;

use super::sys::{self, Errno};

const SEED_BYTES: usize = 64;
const GENERATION_ID_BYTES: usize = 16;
const RANDOM_SAMPLE_BYTES: usize = 32;
const USAGE: &[u8] =
    b"usage: nvx-reseed --sample | [--generation-only] SEED_FILE [PREVIOUS_GENERATION_ID]\n";

// The ioctls of <linux/random.h>, which the libc crate lacks: _IOW('R', 0x03, int[2]) and
// _IO('R', 0x07).
const RNDADDENTROPY: libc::Ioctl = 0x4008_5203;
const RNDRESEEDCRNG: libc::Ioctl = 0x5207;

/// The `struct rand_pool_info` that `RNDADDENTROPY` takes, with room for the seed.
#[repr(C)]
struct SeedPayload {
    entropy_count: libc::c_int,
    buf_size: libc::c_int,
    bytes: [u8; SEED_BYTES],
}

/// Runs `nvx-reseed` with the process's arguments. It exits with 0, 1 when an operation or a
/// check fails, or 2 for a usage error.
pub fn main() -> ExitCode {
    sys::restore_sigpipe();
    ExitCode::from(run(
        &sys::args(),
        c"/dev/random",
        &mut sys::Stdout::new(),
        &mut io::stderr(),
    ))
}

/// Runs the program with `random` standing for `/dev/random`.
fn run(args: &[CString], random: &CStr, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if let [_, flag] = args
        && flag.as_bytes() == b"--sample"
    {
        return status(print_random_sample(out, err));
    }
    // As in the C program, a first argument of `--generation-only` names the seed file unless
    // three arguments follow the program name.
    let (generation_only, seed_path, previous) = match args {
        [_, seed] => (false, seed, None),
        [_, seed, previous] => (false, seed, Some(previous)),
        [_, flag, seed, previous] if flag.as_bytes() == b"--generation-only" => {
            (true, seed, Some(previous))
        }
        _ => {
            sys::report(err, &[USAGE]);
            return 2;
        }
    };

    let mut seed = SeedPayload {
        entropy_count: (SEED_BYTES * 8) as libc::c_int,
        buf_size: SEED_BYTES as libc::c_int,
        bytes: [0; SEED_BYTES],
    };
    if !read_seed(seed_path, &mut seed.bytes, err) {
        return 1;
    }
    let generation_id = &seed.bytes[..GENERATION_ID_BYTES];
    if let Some(previous) = previous
        && !validate_generation_change(previous.as_bytes(), generation_id, err)
    {
        return 1;
    }
    if generation_only {
        return status(print_hex(generation_id, out, err));
    }

    // SAFETY: the path is a NUL-terminated string.
    let descriptor = unsafe { libc::open(random.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if descriptor < 0 {
        let text = Errno::last().text();
        let path = random.to_bytes();
        sys::report(err, &[b"nvx-reseed: open ", path, b": ", &text, b"\n"]);
        return 1;
    }
    // SAFETY: RNDADDENTROPY reads the payload, which outlives the call, and RNDRESEEDCRNG takes
    // no argument.
    let reseeded = unsafe {
        libc::ioctl(descriptor, RNDADDENTROPY, &raw const seed) == 0
            && libc::ioctl(descriptor, RNDRESEEDCRNG, 0) == 0
    };
    if !reseeded {
        let text = Errno::last().text();
        sys::report(err, &[b"nvx-reseed: random ioctl: ", &text, b"\n"]);
        let _ = sys::close(descriptor);
        return 1;
    }
    let _ = sys::close(descriptor);
    if previous.is_some() && !print_hex(&seed.bytes[..GENERATION_ID_BYTES], out, err) {
        return 1;
    }
    0
}

fn status(succeeded: bool) -> u8 {
    if succeeded { 0 } else { 1 }
}

/// Reads exactly `bytes.len()` bytes from the file at `path`. Like the C program, it does not
/// retry after `EINTR`.
fn read_seed(path: &CStr, bytes: &mut [u8], err: &mut dyn Write) -> bool {
    let fail = |err: &mut dyn Write, operation: &[u8], reason: &[u8]| {
        let path = path.to_bytes();
        sys::report(
            err,
            &[b"nvx-reseed: ", operation, b" ", path, b": ", reason, b"\n"],
        );
    };
    // SAFETY: the path is a NUL-terminated string.
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if descriptor < 0 {
        fail(err, b"open", &Errno::last().text());
        return false;
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &mut bytes[offset..];
        // SAFETY: read stores at most `rest.len()` bytes in `rest`.
        let count = unsafe { libc::read(descriptor, rest.as_mut_ptr().cast(), rest.len()) };
        if count <= 0 {
            let reason = match count {
                0 => b"unexpected end of file".to_vec(),
                _ => Errno::last().text(),
            };
            fail(err, b"read", &reason);
            let _ = sys::close(descriptor);
            return false;
        }
        offset += count as usize;
    }
    let _ = sys::close(descriptor);
    true
}

/// Checks that `previous` is 32 hexadecimal digits that differ from `generation_id`.
fn validate_generation_change(previous: &[u8], generation_id: &[u8], err: &mut dyn Write) -> bool {
    if previous.len() != GENERATION_ID_BYTES * 2 {
        sys::report(
            err,
            &[b"nvx-reseed: previous VM generation ID is not 32 hex digits\n"],
        );
        return false;
    }
    let mut previous_bytes = [0; GENERATION_ID_BYTES];
    for (byte, digits) in previous_bytes.iter_mut().zip(previous.chunks_exact(2)) {
        let (Some(high), Some(low)) = (hex_value(digits[0]), hex_value(digits[1])) else {
            sys::report(
                err,
                &[b"nvx-reseed: previous VM generation ID is not hexadecimal\n"],
            );
            return false;
        };
        *byte = (high << 4) | low;
    }
    if previous_bytes == generation_id {
        sys::report(err, &[b"nvx-reseed: VM generation ID did not change\n"]);
        return false;
    }
    true
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Prints `bytes` in lowercase hexadecimal and a newline.
fn print_hex(bytes: &[u8], out: &mut dyn Write, err: &mut dyn Write) -> bool {
    let mut line: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    line.push('\n');
    if sys::print(out, line.as_bytes()).is_err() {
        sys::report(err, &[b"nvx-reseed: write output failed\n"]);
        return false;
    }
    true
}

/// Prints `RANDOM_SAMPLE_BYTES` bytes from `getrandom`, retrying after `EINTR` and short reads.
fn print_random_sample(out: &mut dyn Write, err: &mut dyn Write) -> bool {
    let mut sample = [0; RANDOM_SAMPLE_BYTES];
    let mut offset = 0;
    while offset < sample.len() {
        let rest = &mut sample[offset..];
        // SAFETY: getrandom stores at most `rest.len()` bytes in `rest`.
        let count =
            sys::retry(|| unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) });
        if count > 0 {
            offset += count as usize;
            continue;
        }
        let reason = match count {
            0 => b"no bytes returned".to_vec(),
            _ => Errno::last().text(),
        };
        sys::report(err, &[b"nvx-reseed: getrandom: ", &reason, b"\n"]);
        return false;
    }
    print_hex(&sample, out, err)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::*;
    use crate::guest::sys::tests::Failing;

    /// A seed whose bytes count up from 0, so its generation ID is 000102...0f.
    const GENERATION_ID: &str = "000102030405060708090a0b0c0d0e0f";

    struct Fixture {
        directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let seed: Vec<u8> = (0..SEED_BYTES as u8).collect();
            fs::write(directory.path().join("seed"), seed).unwrap();
            fs::write(directory.path().join("random"), b"").unwrap();
            Self { directory }
        }

        fn path(&self, name: &str) -> String {
            self.directory
                .path()
                .join(name)
                .to_str()
                .unwrap()
                .to_owned()
        }

        fn run_with(&self, arguments: &[&str], out: &mut dyn Write) -> (u8, Vec<u8>) {
            let mut args = vec![CString::new("nvx-reseed").unwrap()];
            args.extend(
                arguments
                    .iter()
                    .map(|argument| CString::new(*argument).unwrap()),
            );
            let random = CString::new(self.path("random")).unwrap();
            let mut err = Vec::new();
            let status = run(&args, &random, out, &mut err);
            (status, err)
        }

        fn run(&self, arguments: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
            let mut out = Vec::new();
            let (status, err) = self.run_with(arguments, &mut out);
            (status, out, err)
        }
    }

    fn message(operation: &str, path: &Path, reason: &[u8]) -> Vec<u8> {
        let mut message = format!("nvx-reseed: {operation} ").into_bytes();
        message.extend_from_slice(path.as_os_str().as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(reason);
        message.push(b'\n');
        message
    }

    #[test]
    fn usage_takes_one_to_three_arguments() {
        let fixture = Fixture::new();
        for arguments in [
            &[][..],
            &["a", "b", "c"],
            &["--generation-only", "a", "b", "c"],
            &["--sample", "a", "b"],
        ] {
            assert_eq!(
                fixture.run(arguments),
                (2, Vec::new(), USAGE.to_vec()),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn options_name_the_seed_file_with_fewer_arguments() {
        let fixture = Fixture::new();
        for (arguments, path) in [
            (
                &["--generation-only", GENERATION_ID][..],
                "--generation-only",
            ),
            (&["--sample", GENERATION_ID], "--sample"),
        ] {
            let reason = Errno(libc::ENOENT).text();
            assert_eq!(
                fixture.run(arguments),
                (1, Vec::new(), message("open", Path::new(path), &reason))
            );
        }
    }

    #[test]
    fn prints_a_random_sample() {
        let fixture = Fixture::new();
        let (status, first, err) = fixture.run(&["--sample"]);
        assert_eq!((status, err.as_slice()), (0, &b""[..]));
        assert_eq!(first.len(), RANDOM_SAMPLE_BYTES * 2 + 1);
        assert!(
            first[..first.len() - 1]
                .iter()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_eq!(first.last(), Some(&b'\n'));
        assert_ne!(fixture.run(&["--sample"]).1, first);
    }

    #[test]
    fn checks_and_prints_the_generation_id() {
        let fixture = Fixture::new();
        let seed = fixture.path("seed");
        let expected = format!("{GENERATION_ID}\n").into_bytes();
        for previous in [
            "ffffffffffffffffffffffffffffffff",
            "000102030405060708090A0B0C0D0E0E",
        ] {
            assert_eq!(
                fixture.run(&["--generation-only", &seed, previous]),
                (0, expected.clone(), Vec::new())
            );
        }
        let cases: &[(&str, &[u8])] = &[
            (
                "0001020304050607",
                b"nvx-reseed: previous VM generation ID is not 32 hex digits\n",
            ),
            (
                "000102030405060708090a0b0c0d0e0f0",
                b"nvx-reseed: previous VM generation ID is not 32 hex digits\n",
            ),
            (
                "000102030405060708090a0b0c0d0e0g",
                b"nvx-reseed: previous VM generation ID is not hexadecimal\n",
            ),
            (
                "000102030405060708090A0B0C0D0E0F",
                b"nvx-reseed: VM generation ID did not change\n",
            ),
        ];
        for &(previous, error) in cases {
            for arguments in [
                &["--generation-only", &seed, previous][..],
                &[&seed, previous],
            ] {
                assert_eq!(
                    fixture.run(arguments),
                    (1, Vec::new(), error.to_vec()),
                    "{arguments:?}"
                );
            }
        }
        let mut out = Failing(libc::EIO);
        let arguments = [
            "--generation-only",
            &seed,
            "ffffffffffffffffffffffffffffffff",
        ];
        assert_eq!(
            fixture.run_with(&arguments, &mut out),
            (1, b"nvx-reseed: write output failed\n".to_vec())
        );
    }

    #[test]
    fn reports_seeds_that_cannot_be_read() {
        let fixture = Fixture::new();
        let missing = fixture.directory.path().join("missing");
        assert_eq!(
            fixture.run(&[missing.to_str().unwrap()]),
            (
                1,
                Vec::new(),
                message("open", &missing, &Errno(libc::ENOENT).text())
            )
        );
        let short = fixture.directory.path().join("short");
        fs::write(&short, [0; SEED_BYTES - 1]).unwrap();
        assert_eq!(
            fixture.run(&[short.to_str().unwrap()]),
            (
                1,
                Vec::new(),
                message("read", &short, b"unexpected end of file")
            )
        );
        let directory = fixture.directory.path();
        assert_eq!(
            fixture.run(&[directory.to_str().unwrap()]),
            (
                1,
                Vec::new(),
                message("read", directory, &Errno(libc::EISDIR).text())
            )
        );
    }

    #[test]
    fn reports_a_failed_reseed() {
        let fixture = Fixture::new();
        let seed = fixture.path("seed");
        // A regular file stands for /dev/random, and has no random ioctls.
        let mut expected = b"nvx-reseed: random ioctl: ".to_vec();
        expected.extend_from_slice(&Errno(libc::ENOTTY).text());
        expected.push(b'\n');
        assert_eq!(fixture.run(&[&seed]), (1, Vec::new(), expected));

        fs::remove_file(fixture.path("random")).unwrap();
        let random = fixture.directory.path().join("random");
        assert_eq!(
            fixture.run(&[&seed, "ffffffffffffffffffffffffffffffff"]),
            (
                1,
                Vec::new(),
                message("open", &random, &Errno(libc::ENOENT).text())
            )
        );
    }

    #[test]
    fn ioctl_numbers_match_linux() {
        // _IOC(direction, type, number, size) on x86 and most other architectures.
        let ioc = |direction: u32, number: u32, size: u32| {
            (direction << 30) | (size << 16) | (u32::from(b'R') << 8) | number
        };
        assert_eq!(RNDADDENTROPY as u32, ioc(1, 0x03, 2 * 4));
        assert_eq!(RNDRESEEDCRNG as u32, ioc(0, 0x07, 0));
        assert_eq!(size_of::<SeedPayload>(), 8 + SEED_BYTES);
    }
}
