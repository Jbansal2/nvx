//! `nvx-exit [CODE]`: stops the VM with an 8-bit exit code by writing one byte to OpenVMM's
//! control port 0x604 through `/dev/port`. CODE defaults to 1, and any CODE that is not a decimal
//! number from 0 to 255 becomes 1; further arguments are ignored. It prints nothing, and exits
//! with status 1 if the write fails.
//!
//! A restored guest's first command is usually `nvx-exit`, and every page that its startup
//! touches first costs time after a restore, so the `guest` profile builds it freestanding.

use super::args::Arg;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::args::Args;

/// Returns the exit code that `argument` selects: its value when it is a decimal number from 0 to
/// 255, which may have leading zeros, and 1 otherwise, including when it is absent or empty.
pub(crate) fn exit_code(argument: Option<Arg<'_>>) -> u8 {
    let Some(argument) = argument else {
        return 1;
    };
    let mut value = 0_u32;
    let mut digits = 0_usize;
    for byte in argument.bytes() {
        if !byte.is_ascii_digit() {
            return 1;
        }
        // The value never exceeds 2559, so it cannot wrap.
        value = value * 10 + u32::from(byte - b'0');
        if value > 255 {
            return 1;
        }
        digits += 1;
    }
    if digits == 0 { 1 } else { value as u8 }
}

/// Runs the program, and returns its exit status.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg_attr(
    test,
    allow(dead_code, reason = "the tests write to a file instead of /dev/port")
)]
pub(crate) fn run(args: Args<'_>) -> i32 {
    write_code(c"/dev/port", exit_code(args.get(1)))
}

/// Writes `code` at offset 0x604 of `device` and returns the exit status: 0 when it wrote the
/// byte, 1 otherwise. It opens the device without `O_CLOEXEC` and leaves it open.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn write_code(device: &core::ffi::CStr, code: u8) -> i32 {
    use super::syscall::syscall;

    const SYS_PWRITE64: usize = 18;
    const SYS_OPENAT: usize = 257;
    const AT_FDCWD: isize = -100;
    const O_WRONLY: usize = 1;
    const EXIT_PORT: usize = 0x604;

    // SAFETY: openat reads the NUL-terminated path.
    let port = unsafe {
        syscall(
            SYS_OPENAT,
            [
                AT_FDCWD as usize,
                device.as_ptr() as usize,
                O_WRONLY,
                0,
                0,
                0,
            ],
        )
    };
    if port < 0 {
        return 1;
    }
    // SAFETY: pwrite64 reads one byte from `code`.
    let written = unsafe {
        syscall(
            SYS_PWRITE64,
            [port as usize, &raw const code as usize, 1, EXIT_PORT, 0, 0],
        )
    };
    if written == 1 { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::super::args::tests::with_args;
    use super::*;

    #[test]
    fn exit_code_takes_a_decimal_number_up_to_255() {
        let cases: &[(&[&[u8]], u8)] = &[
            (&[], 1),
            (&[b""], 1),
            (&[b"0"], 0),
            (&[b"37"], 37),
            (&[b"255"], 255),
            (&[b"256"], 1),
            (&[b"-1"], 1),
            (&[b"+5"], 1),
            (&[b" 7"], 1),
            (&[b"7 "], 1),
            (&[b"12a"], 1),
            (&[b"99999999999999999999"], 1),
            // Out of range after any digit, so the value never wraps.
            (&[b"4294967296"], 1),
            (&[b"4294967551"], 1),
            (&[b"00000000000000000255"], 255),
            // Decimal: a shell's printf would read a leading zero as octal.
            (&[b"010"], 10),
            (&[b"7", b"9"], 7),
        ];
        for &(arguments, expected) in cases {
            let mut all: Vec<&[u8]> = vec![b"nvx-exit"];
            all.extend_from_slice(arguments);
            let code = with_args(&all, |args| exit_code(args.get(1)));
            assert_eq!(code, expected, "{arguments:?}");
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn writes_one_byte_at_the_control_port() {
        let directory = tempfile::tempdir().unwrap();
        let device = directory.path().join("port");
        std::fs::write(&device, b"").unwrap();
        let path = std::ffi::CString::new(device.to_str().unwrap()).unwrap();
        assert_eq!(write_code(&path, 37), 0);
        let mut expected = vec![0; 0x604];
        expected.push(37);
        assert_eq!(std::fs::read(&device).unwrap(), expected);

        let missing = std::ffi::CString::new(device.join("port").to_str().unwrap()).unwrap();
        assert_eq!(write_code(&missing, 0), 1);
    }
}
