//! GUIDs as GPT stores them.

use std::fmt;
use std::str::FromStr;

/// A GUID as GPT stores it: 16 bytes, whose first three fields are little-endian.
///
/// It displays, and parses from, the canonical form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, which
/// tools such as `blkid` print in lowercase. Parsing also accepts uppercase digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    /// The nil GUID, all of whose bits are zero, which marks an unused partition entry.
    pub const NIL: Self = Self([0; 16]);

    /// Returns the GUID that GPT stores as `bytes`.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes that GPT stores for the GUID.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Returns whether this is the nil GUID.
    pub fn is_nil(self) -> bool {
        self == Self::NIL
    }

    /// Returns the GUID's bytes in the order of its canonical form: the stored ones, with the
    /// first three fields reversed to big-endian. The order is its own inverse.
    fn canonical_bytes(self) -> [u8; 16] {
        let mut bytes = self.0;
        bytes[0..4].reverse();
        bytes[4..6].reverse();
        bytes[6..8].reverse();
        bytes
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.canonical_bytes().iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl FromStr for Guid {
    type Err = ParseGuidError;

    /// Parses the canonical form, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in either case, without
    /// braces or whitespace.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.as_bytes();
        if text.len() != 36 || [8, 13, 18, 23].iter().any(|&dash| text[dash] != b'-') {
            return Err(ParseGuidError(()));
        }
        let mut digits = text
            .iter()
            .enumerate()
            .filter(|(index, _)| ![8, 13, 18, 23].contains(index))
            .map(|(_, digit)| char::from(*digit).to_digit(16));
        let mut canonical = [0; 16];
        for byte in &mut canonical {
            let (Some(Some(high)), Some(Some(low))) = (digits.next(), digits.next()) else {
                return Err(ParseGuidError(()));
            };
            // Two hexadecimal digits make one byte.
            *byte = (high * 16 + low) as u8;
        }
        // The canonical order is its own inverse.
        Ok(Self(Self(canonical).canonical_bytes()))
    }
}

/// Why a string is not a GUID in canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseGuidError(());

impl fmt::Display for ParseGuidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("not a GUID of the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    }
}

impl std::error::Error for ParseGuidError {}
