//! Shared x86-64 primitives used by the guest time tools.
#![allow(dead_code)]

use core::arch::asm;
use core::arch::x86_64::{__cpuid_count, CpuidResult};

/// Runs CPUID with `leaf` and `subleaf`.
#[allow(unused_unsafe)] // The intrinsic became safe after the crate's minimum Rust version.
pub(super) fn cpuid(leaf: u32, subleaf: u32) -> [u32; 4] {
    // SAFETY: CPUID is available in x86-64 user mode and has no memory operands.
    let CpuidResult { eax, ebx, ecx, edx } = unsafe { __cpuid_count(leaf, subleaf) };
    [eax, ebx, ecx, edx]
}

/// Reads the TSC without a fence.
#[inline]
pub(super) fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: RDTSC is an unprivileged x86-64 instruction.
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Reads the TSC with RDTSCP.
#[inline]
pub(super) fn rdtscp() -> u64 {
    let low: u32;
    let high: u32;
    let auxiliary: u32;
    // SAFETY: callers check the architectural RDTSCP feature before using this primitive.
    unsafe {
        asm!(
            "rdtscp",
            out("eax") low,
            out("edx") high,
            out("ecx") auxiliary,
            options(nomem, nostack)
        );
    }
    let _ = auxiliary;
    (u64::from(high) << 32) | u64::from(low)
}

/// Reads the TSC after an LFENCE, matching Linux's `rdtsc_ordered`.
#[inline]
pub(super) fn rdtsc_lfence() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: LFENCE and RDTSC are unprivileged x86-64 instructions.
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Reads the TSC between LFENCE instructions for a timing bracket.
#[inline]
pub(super) fn rdtsc_fenced() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: LFENCE and RDTSC are unprivileged x86-64 instructions.
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") low,
            out("edx") high,
            options(nostack)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Hints that the caller is in a spin loop.
#[inline]
pub(super) fn pause() {
    // SAFETY: PAUSE is an unprivileged x86-64 instruction.
    unsafe { asm!("pause", options(nomem, nostack, preserves_flags)) };
}

/// Reads one byte from an I/O port after the caller obtained I/O permission.
#[inline]
pub(super) unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees that the process has permission for `port`.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Reads four bytes from an I/O port after the caller obtained I/O permission.
#[inline]
pub(super) unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: the caller guarantees that the process has permission for `port..=port + 3`.
    unsafe {
        asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Writes one byte to an I/O port after the caller obtained I/O permission.
#[inline]
pub(super) unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller guarantees that the process has permission for `port`.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}
