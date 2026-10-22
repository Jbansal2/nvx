//! Safe, operation-specific wrappers for the Linux ioctls of the guest tools.

use std::ffi::c_int;
use std::mem::size_of;

use super::{Errno, FileDescriptor};

/// Number of bytes that `nvx-reseed` adds to the entropy pool.
const SEED_BYTES: usize = 64;

/// C layout required by `RNDADDENTROPY`.
#[repr(C)]
struct SeedPayload {
    /// Number of entropy bits credited to the payload.
    entropy_count: c_int,
    /// Number of following seed bytes.
    buf_size: c_int,
    /// Seed bytes added to the kernel pool.
    bytes: [u8; SEED_BYTES],
}

nix::ioctl_read_bad!(
    /// Reads the number of bytes waiting to be read: Linux `FIONREAD`, whose number `nix`
    /// takes from its `libc` dependency because it defines no constant of its own.
    fionread,
    nix::libc::FIONREAD,
    c_int
);

nix::ioctl_write_ptr_bad!(
    /// Adds entropy to the kernel pool: Linux `RNDADDENTROPY`, `_IOW('R', 0x03, int[2])`.
    rnd_add_entropy,
    nix::request_code_write!(b'R', 0x03, size_of::<[c_int; 2]>()),
    SeedPayload
);

nix::ioctl_none!(
    /// Reseeds the kernel's CRNG: Linux `RNDRESEEDCRNG`, `_IO('R', 0x07)`.
    rnd_reseed_crng,
    b'R',
    0x07
);

nix::ioctl_none!(
    /// Writes a block device's dirty buffers and drops its cached ones: Linux `BLKFLSBUF`,
    /// `_IO(0x12, 97)`.
    blkflsbuf,
    0x12,
    97
);

/// Returns the number of bytes available for reading from `descriptor`.
///
/// The local integer outlives `ioctl`, and the wrapper returns it only after the kernel reports
/// success, so callers never handle the raw pointer or descriptor.
pub(crate) fn console_pending(descriptor: &FileDescriptor) -> Result<c_int, Errno> {
    let mut pending = 0;
    // SAFETY: `pending` is writable for one C integer and outlives the `FIONREAD` call.
    unsafe { fionread(descriptor.raw(), &raw mut pending) }?;
    Ok(pending)
}

/// Adds a 64-byte seed with full entropy credit and asks Linux to reseed the CRNG.
///
/// The payload owns the exact C layout consumed synchronously by `RNDADDENTROPY`.
/// `RNDRESEEDCRNG` takes no argument. If either request fails, the error of the failing request
/// is returned exactly as the C `||` expression did.
pub(crate) fn reseed_random(
    descriptor: &FileDescriptor,
    seed: &[u8; SEED_BYTES],
) -> Result<(), Errno> {
    let payload = SeedPayload {
        entropy_count: (SEED_BYTES * 8) as c_int,
        buf_size: SEED_BYTES as c_int,
        bytes: *seed,
    };
    // SAFETY: `payload` has the kernel ABI's layout and outlives this synchronous ioctl.
    unsafe { rnd_add_entropy(descriptor.raw(), &raw const payload) }?;
    // SAFETY: `RNDRESEEDCRNG` reads no argument.
    unsafe { rnd_reseed_crng(descriptor.raw()) }?;
    Ok(())
}

/// Writes the dirty buffers of the block device that `descriptor` opened, then drops its cached
/// buffers, as `blockdev --flushbufs` does, so that later reads come from the device. It needs
/// `CAP_SYS_ADMIN`.
pub(crate) fn flush_block_buffers(descriptor: &FileDescriptor) -> Result<(), Errno> {
    // SAFETY: `BLKFLSBUF` reads no argument.
    unsafe { blkflsbuf(descriptor.raw()) }?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! ABI checks for the ioctls.

    use super::*;

    #[test]
    fn random_ioctl_numbers_match_linux() {
        // `_IOC(direction, type, number, size)` on x86 and most other architectures.
        let ioc = |direction: u32, number: u32, size: u32| {
            (direction << 30) | (size << 16) | (u32::from(b'R') << 8) | number
        };
        let add_entropy = nix::request_code_write!(b'R', 0x03, size_of::<[c_int; 2]>());
        assert_eq!(add_entropy as u32, ioc(1, 0x03, 2 * 4));
        assert_eq!(nix::request_code_none!(b'R', 0x07) as u32, ioc(0, 0x07, 0));
        assert_eq!(size_of::<SeedPayload>(), 8 + SEED_BYTES);
    }

    #[test]
    fn the_buffer_flush_ioctl_number_matches_linux() {
        // `BLKFLSBUF` in linux/fs.h.
        assert_eq!(nix::request_code_none!(0x12, 97) as u32, 0x1261);
    }
}
