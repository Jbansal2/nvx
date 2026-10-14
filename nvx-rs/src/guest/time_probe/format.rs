//! C-library floating-point formatting used by the diagnostics ABI.

use std::ffi::CStr;

fn snprintf(format: &CStr, value: f64) -> String {
    let mut buffer = [0_u8; 128];
    // SAFETY: `format` is NUL-terminated, expects one double, and `buffer` is writable.
    let written = unsafe {
        libc::snprintf(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            format.as_ptr(),
            value,
        )
    };
    let length = usize::try_from(written)
        .unwrap_or_default()
        .min(buffer.len() - 1);
    String::from_utf8_lossy(&buffer[..length]).into_owned()
}

pub(super) fn f0(value: f64) -> String {
    snprintf(c"%.0f", value)
}

pub(super) fn f1(value: f64) -> String {
    snprintf(c"%.1f", value)
}

pub(super) fn f9(value: f64) -> String {
    snprintf(c"%.9f", value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_with_libc_rounding_and_spelling() {
        assert_eq!(f0(12.5), "12");
        assert_eq!(f1(12.25), "12.2");
        assert_eq!(f9(1.5), "1.500000000");
    }
}
