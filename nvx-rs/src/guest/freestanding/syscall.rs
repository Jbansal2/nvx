//! Raw Linux system calls on x86_64, without libc.

/// Makes system call `number` with six arguments, and returns the kernel's result: a negative
/// `errno` on failure. Unused arguments are 0.
///
/// # Safety
///
/// The arguments must be valid for the system call, such as pointers to memory that it may read
/// or write.
#[inline]
pub(crate) unsafe fn syscall(number: usize, arguments: [usize; 6]) -> isize {
    let result: isize;
    // SAFETY: the caller passes valid arguments. The kernel clobbers only rcx and r11, and the
    // instruction does not touch the stack.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") arguments[0],
            in("rsi") arguments[1],
            in("rdx") arguments[2],
            in("r10") arguments[3],
            in("r8") arguments[4],
            in("r9") arguments[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}
