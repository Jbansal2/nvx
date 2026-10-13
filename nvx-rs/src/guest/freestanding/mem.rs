//! The memory functions to which LLVM may emit calls, such as `memcpy` for a copy loop.
//!
//! Without libc, the freestanding binaries must define them: `compiler_builtins` exports them
//! only on targets without a libc. Each is assembly, which LLVM cannot turn back into a call to
//! itself, and the linker drops the ones that nothing calls. The library compiles them under
//! mangled names, to test them.

/// Copies `count` bytes from `source` to `destination`, which do not overlap.
///
/// # Safety
///
/// Both ranges must be valid for `count` bytes.
#[unsafe(naked)]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub(crate) unsafe extern "C" fn memcpy(
    destination: *mut u8,
    source: *const u8,
    count: usize,
) -> *mut u8 {
    core::arch::naked_asm!("mov rax, rdi", "mov rcx, rdx", "rep movsb", "ret")
}

/// Copies `count` bytes from `source` to `destination`, which may overlap.
///
/// # Safety
///
/// Both ranges must be valid for `count` bytes.
#[unsafe(naked)]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub(crate) unsafe extern "C" fn memmove(
    destination: *mut u8,
    source: *const u8,
    count: usize,
) -> *mut u8 {
    // A destination above the source copies backward, from the last byte, with the direction
    // flag set; the ABI requires it clear again on return.
    core::arch::naked_asm!(
        "mov rax, rdi",
        "mov rcx, rdx",
        "cmp rdi, rsi",
        "jbe 2f",
        "lea rsi, [rsi + rcx - 1]",
        "lea rdi, [rdi + rcx - 1]",
        "std",
        "rep movsb",
        "cld",
        "ret",
        "2:",
        "rep movsb",
        "ret",
    )
}

/// Sets `count` bytes at `destination` to the low byte of `value`.
///
/// # Safety
///
/// The range must be valid for `count` bytes.
#[unsafe(naked)]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub(crate) unsafe extern "C" fn memset(destination: *mut u8, value: i32, count: usize) -> *mut u8 {
    core::arch::naked_asm!(
        "mov r8, rdi",
        "mov eax, esi",
        "mov rcx, rdx",
        "rep stosb",
        "mov rax, r8",
        "ret",
    )
}

/// Compares `count` bytes, and returns the difference of the first pair that differs, or 0.
///
/// # Safety
///
/// Both ranges must be valid for `count` bytes.
#[unsafe(naked)]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub(crate) unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    core::arch::naked_asm!(
        "xor eax, eax",
        "test rdx, rdx",
        "jz 3f",
        "2:",
        "movzx eax, byte ptr [rdi]",
        "movzx ecx, byte ptr [rsi]",
        "sub eax, ecx",
        "jnz 3f",
        "inc rdi",
        "inc rsi",
        "dec rdx",
        "jnz 2b",
        "3:",
        "ret",
    )
}

/// Returns 0 when `count` bytes are equal, as `memcmp` does.
///
/// # Safety
///
/// Both ranges must be valid for `count` bytes.
#[unsafe(naked)]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub(crate) unsafe extern "C" fn bcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    core::arch::naked_asm!("jmp {memcmp}", memcmp = sym memcmp)
}

/// Returns the length of a NUL-terminated string.
///
/// # Safety
///
/// The string must be NUL-terminated.
#[unsafe(naked)]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub(crate) unsafe extern "C" fn strlen(string: *const u8) -> usize {
    core::arch::naked_asm!(
        "mov rax, rdi",
        "2:",
        "cmp byte ptr [rax], 0",
        "je 3f",
        "inc rax",
        "jmp 2b",
        "3:",
        "sub rax, rdi",
        "ret",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 7 + 1) as u8).collect()
    }

    #[test]
    fn memcpy_and_memset() {
        for length in [0, 1, 7, 64, 4096] {
            let source = pattern(length);
            let mut destination = vec![0; length + 1];
            // SAFETY: both buffers hold `length` bytes.
            let returned = unsafe { memcpy(destination.as_mut_ptr(), source.as_ptr(), length) };
            assert_eq!(returned, destination.as_mut_ptr());
            assert_eq!(&destination[..length], source);
            assert_eq!(destination[length], 0);
            // SAFETY: the buffer holds `length` bytes.
            let returned = unsafe { memset(destination.as_mut_ptr(), 0x1a5, length) };
            assert_eq!(returned, destination.as_mut_ptr());
            assert!(destination[..length].iter().all(|&byte| byte == 0xa5));
            assert_eq!(destination[length], 0);
        }
    }

    #[test]
    fn memmove_copies_overlapping_ranges() {
        for (from, to, length) in [(0, 3, 10), (3, 0, 10), (0, 1, 0), (2, 2, 5), (0, 9, 1)] {
            let mut buffer = pattern(20);
            let mut expected = buffer.clone();
            expected.copy_within(from..from + length, to);
            let base = buffer.as_mut_ptr();
            // SAFETY: both ranges lie within the buffer.
            let returned = unsafe { memmove(base.add(to), base.add(from), length) };
            assert_eq!(returned, base.wrapping_add(to));
            assert_eq!(buffer, expected, "{from} -> {to}, {length}");
        }
        // The direction flag is clear again, so the forward copy still works.
        let source = pattern(8);
        let mut destination = [0; 8];
        // SAFETY: both buffers hold 8 bytes.
        unsafe { memcpy(destination.as_mut_ptr(), source.as_ptr(), 8) };
        assert_eq!(destination[..], source[..]);
    }

    #[test]
    fn memcmp_bcmp_and_strlen() {
        let compare = |left: &[u8], right: &[u8]| {
            // SAFETY: both slices hold the compared length.
            unsafe {
                let length = left.len().min(right.len());
                (
                    memcmp(left.as_ptr(), right.as_ptr(), length).signum(),
                    bcmp(left.as_ptr(), right.as_ptr(), length) == 0,
                )
            }
        };
        assert_eq!(compare(b"", b""), (0, true));
        assert_eq!(compare(b"abc", b"abc"), (0, true));
        assert_eq!(compare(b"abc", b"abd"), (-1, false));
        assert_eq!(compare(b"\xffbc", b"abc"), (1, false));
        // SAFETY: the strings are NUL-terminated.
        unsafe {
            assert_eq!(strlen(c"".as_ptr().cast()), 0);
            assert_eq!(strlen(c"nvx-exit".as_ptr().cast()), 8);
        }
    }
}
