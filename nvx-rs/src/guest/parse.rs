//! C's `strtoull(text, &end, 0)`, with which the guest programs parse their numbers.

/// The result of `strtoull(text, &end, 0)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Strtoull {
    /// The value: `ULLONG_MAX` after an overflow, and negated modulo 2^64 after a minus sign.
    pub(crate) value: u64,
    /// The number of bytes before `end`: 0 when nothing converts, since `end` is then `text`.
    pub(crate) end: usize,
    /// Whether the number overflowed, for which `strtoull` sets `errno` to `ERANGE`.
    pub(crate) overflow: bool,
}

/// Converts the number at the start of `text` as `strtoull(text, &end, 0)` does. It skips
/// leading white space and an optional sign; then `0x` or `0X` selects hexadecimal when a
/// hexadecimal digit follows, a leading `0` octal, and anything else decimal. A minus sign
/// negates the value modulo 2^64, so `-1` converts to `ULLONG_MAX`.
pub(crate) fn strtoull(text: &[u8]) -> Strtoull {
    let mut index = text.iter().take_while(|&&byte| is_space(byte)).count();
    let negative = match text.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut radix = 10;
    if text.get(index) == Some(&b'0') {
        // The `0` is an octal digit; without a hexadecimal digit after `0x`, only the `0`
        // converts.
        radix = 8;
        if matches!(text.get(index + 1), Some(b'x' | b'X'))
            && text
                .get(index + 2)
                .is_some_and(|&byte| digit(byte, 16).is_some())
        {
            radix = 16;
            index += 2;
        }
    }
    let start = index;
    let mut value = 0_u64;
    let mut overflow = false;
    while let Some(digit) = text.get(index).and_then(|&byte| digit(byte, radix)) {
        match value
            .checked_mul(radix)
            .and_then(|value| value.checked_add(digit))
        {
            Some(next) => value = next,
            None => overflow = true,
        }
        index += 1;
    }
    if index == start {
        return Strtoull {
            value: 0,
            end: 0,
            overflow: false,
        };
    }
    let value = match (overflow, negative) {
        (true, _) => u64::MAX,
        (false, true) => value.wrapping_neg(),
        (false, false) => value,
    };
    Strtoull {
        value,
        end: index,
        overflow,
    }
}

/// Parses a number with the guest CLI's base-0 contract: `strtoull(text, &end, 0)` must convert
/// the whole, non-empty text without overflowing.
pub(crate) fn parse_u64(text: &[u8]) -> Option<u64> {
    let result = strtoull(text);
    (!result.overflow && result.end != 0 && result.end == text.len()).then_some(result.value)
}

/// Returns whether `byte` is white space in the C locale.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Returns the value of `byte` as a digit in `radix`, up to 16.
fn digit(byte: u8, radix: u64) -> Option<u64> {
    let value = match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => return None,
    };
    (u64::from(value) < radix).then_some(u64::from(value))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use super::*;

    /// Inputs that cover every rule of `strtoull` base 0.
    const CORPUS: &[&[u8]] = &[
        b"",
        b"0",
        b"1",
        b"00",
        b"0x",
        b"0X",
        b"0x10",
        b"0X10",
        b"0xFfFf",
        b"0x1g",
        b"0x+1",
        b"010",
        b"08",
        b"0b1",
        b"-1",
        b"+1",
        b"-",
        b"+",
        b"-0",
        b"-0x",
        b"--1",
        b"+-1",
        b" 1",
        b"1 ",
        b" \t\n\x0b\x0c\r42",
        b"\xa01",
        b"x1",
        b"abc",
        b"1a",
        b"1e3",
        b"255",
        b"256",
        b"65535",
        b"65536",
        b"4294967295",
        b"4294967296",
        b"18446744073709551615",
        b"18446744073709551616",
        b"99999999999999999999999999",
        b"-18446744073709551615",
        b"-18446744073709551616",
        b"0xffffffffffffffff",
        b"0x10000000000000000",
        b"01777777777777777777777",
        b"02000000000000000000000",
        b"  -0x10",
    ];

    #[test]
    fn matches_the_c_library() {
        for &text in CORPUS {
            let c_text = CString::new(text).unwrap();
            let mut end = ptr::null_mut();
            // SAFETY: errno is thread-local, and strtoull reads the NUL-terminated text and
            // stores a pointer into it through `end`.
            let (value, errno) = unsafe {
                *libc::__errno_location() = 0;
                let value = libc::strtoull(c_text.as_ptr(), &mut end, 0);
                (value, *libc::__errno_location())
            };
            let end = end as usize - c_text.as_ptr() as usize;
            assert_eq!(
                strtoull(text),
                Strtoull {
                    value,
                    end,
                    overflow: errno == libc::ERANGE
                },
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn parse_u64_takes_whole_numbers_without_overflow() {
        let cases: &[(&[u8], Option<u64>)] = &[
            (b"", None),
            (b"0x", None),
            (b"0X10", Some(16)),
            (b"010", Some(8)),
            (b"08", None),
            (b"-1", Some(u64::MAX)),
            (b"+1", Some(1)),
            (b" 1", Some(1)),
            (b"1 ", None),
            (b"0x1g", None),
            (b"18446744073709551615", Some(u64::MAX)),
            (b"18446744073709551616", None),
            (b"4294967296", Some(1 << 32)),
        ];
        for &(text, expected) in cases {
            assert_eq!(
                parse_u64(text),
                expected,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
    }
}
