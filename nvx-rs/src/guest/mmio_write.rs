//! `nvx-mmio-write ADDRESS VALUE`: stores a 32-bit value at a physical address through
//! `/dev/mem`, as `nvx-virtio-restore-probe` does to kick a virtio queue.

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::process::ExitCode;
use std::ptr;

use super::parse::parse_u64;
use super::sys::{self, Errno};

/// Runs `nvx-mmio-write` with the process's arguments. It exits with 0, 1 when an operation
/// fails, or 2 for a usage error, and prints nothing on success.
pub fn main() -> ExitCode {
    sys::restore_sigpipe();
    ExitCode::from(run(&sys::args(), c"/dev/mem", &mut io::stderr()))
}

/// Runs the program with `memory` standing for `/dev/mem`, which its messages name regardless.
fn run(args: &[CString], memory: &CStr, err: &mut dyn Write) -> u8 {
    let parsed = match args {
        [_, address, value] => parse_u64(address.as_bytes()).zip(parse_u64(value.as_bytes())),
        _ => None,
    };
    let Some((address, value)) = parsed.filter(|&(_, value)| value <= u64::from(u32::MAX)) else {
        sys::report(err, &[b"usage: nvx-mmio-write ADDRESS VALUE\n"]);
        return 2;
    };
    let value = value as u32;

    // SAFETY: sysconf has no preconditions.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 || page_size & (page_size - 1) != 0 {
        sys::report(err, &[b"invalid page size\n"]);
        return 1;
    }
    let page_size = page_size as u64;
    let page_base = address & !(page_size - 1);
    let page_offset = address - page_base;
    if page_offset > page_size.wrapping_sub(4) {
        sys::report(err, &[b"MMIO write crosses a page boundary\n"]);
        return 1;
    }

    // SAFETY: the path is a NUL-terminated string.
    let descriptor = unsafe { libc::open(memory.as_ptr(), libc::O_RDWR | libc::O_SYNC) };
    if descriptor < 0 {
        perror(err, b"open /dev/mem");
        return 1;
    }
    // SAFETY: maps a page of the device at a page-aligned offset; mmap validates the rest.
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            descriptor,
            page_base as libc::off_t,
        )
    };
    if mapping == libc::MAP_FAILED {
        perror(err, b"mmap /dev/mem");
        let _ = sys::close(descriptor);
        return 1;
    }
    // SAFETY: the four bytes at the offset lie within the mapped page. The asm is a single 32-bit
    // store, aligned or not, which the C program's volatile `uint32_t` store compiled to.
    unsafe {
        core::arch::asm!(
            "mov dword ptr [{target}], {value:e}",
            target = in(reg) mapping.cast::<u8>().add(page_offset as usize),
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: unmaps the mapping above, which nothing uses afterwards.
    if unsafe { libc::munmap(mapping, page_size as usize) } != 0 {
        perror(err, b"munmap /dev/mem");
        let _ = sys::close(descriptor);
        return 1;
    }
    if sys::close(descriptor).is_err() {
        perror(err, b"close /dev/mem");
        return 1;
    }
    0
}

/// Reports `errno` as C's `perror(prefix)` does.
fn perror(err: &mut dyn Write, prefix: &[u8]) {
    let text = Errno::last().text();
    sys::report(err, &[prefix, b": ", &text, b"\n"]);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::*;

    fn page_size() -> u64 {
        // SAFETY: sysconf has no preconditions.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
    }

    fn mmio_write(memory: &Path, arguments: &[&str]) -> (u8, Vec<u8>) {
        let mut args = vec![CString::new("nvx-mmio-write").unwrap()];
        args.extend(
            arguments
                .iter()
                .map(|argument| CString::new(*argument).unwrap()),
        );
        let memory = CString::new(memory.as_os_str().as_bytes()).unwrap();
        let mut err = Vec::new();
        let status = run(&args, &memory, &mut err);
        (status, err)
    }

    fn perror_text(prefix: &str, errno: libc::c_int) -> Vec<u8> {
        let mut text = format!("{prefix}: ").into_bytes();
        text.extend_from_slice(&Errno(errno).text());
        text.push(b'\n');
        text
    }

    #[test]
    fn usage_requires_an_address_and_a_32_bit_value() {
        let directory = tempfile::tempdir().unwrap();
        let memory = directory.path().join("mem");
        let usage = b"usage: nvx-mmio-write ADDRESS VALUE\n".to_vec();
        for arguments in [
            &[][..],
            &["0x1000"],
            &["0x1000", "1", "2"],
            &["", "1"],
            &["0x1000", ""],
            &["0x", "1"],
            &["08", "1"],
            &["1 ", "1"],
            &["0x1g", "1"],
            &["18446744073709551616", "1"],
            &["0x1000", "4294967296"],
            &["0x1000", "-1"],
        ] {
            assert_eq!(
                mmio_write(&memory, arguments),
                (2, usage.clone()),
                "{arguments:?}"
            );
        }
        assert!(!memory.exists());
    }

    #[test]
    fn refuses_a_store_that_crosses_a_page() {
        let directory = tempfile::tempdir().unwrap();
        let memory = directory.path().join("mem");
        let address = format!("{}", page_size() - 3);
        assert_eq!(
            mmio_write(&memory, &[&address, "1"]),
            (1, b"MMIO write crosses a page boundary\n".to_vec())
        );
    }

    #[test]
    fn stores_the_value_in_native_byte_order() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let page = page_size();
        fs::write(file.path(), vec![0; 2 * page as usize]).unwrap();
        for (address, value, offset) in [
            (format!("{:#x}", page + 4), "0xdeadbeef", page as usize + 4),
            (format!("0{:o}", page + 9), "305419896", page as usize + 9),
            (format!("{}", page - 4), "4294967295", page as usize - 4),
        ] {
            assert_eq!(mmio_write(file.path(), &[&address, value]), (0, Vec::new()));
            let stored = parse_u64(value.as_bytes()).unwrap() as u32;
            let contents = fs::read(file.path()).unwrap();
            assert_eq!(&contents[offset..offset + 4], &stored.to_ne_bytes());
        }
    }

    #[test]
    fn reports_failures_as_perror() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            mmio_write(&directory.path().join("missing"), &["0", "0"]),
            (1, perror_text("open /dev/mem", libc::ENOENT))
        );
        // A FIFO opens for reading and writing, but has no mmap.
        let fifo = directory.path().join("fifo");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the path is a NUL-terminated string.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            mmio_write(&fifo, &["0", "0"]),
            (1, perror_text("mmap /dev/mem", libc::ENODEV))
        );
    }
}
