//! The boot tokens of a layered root: the kernel command-line tokens through which the host tells
//! the guest which image its layered root assembles, and where the root keeps its upper.
//!
//! A layered root overlays one read-only image, on the `distro` block device, with a writable
//! upper. Two tokens describe it, which [`RootLayout::tokens`] renders:
//!
//! - `nvx_layer=distro,0xd0003000,FORMAT[:IDENTITY]` names the image's format, `erofs` for an
//!   EROFS filesystem or `gpt` for a GPT disk, and the identity that the guest expects of the
//!   image, if any: an EROFS filesystem's UUID, or a GPT disk's GUID. No token names a partition's
//!   GUID.
//! - `nvx_scratch=0xd0006000,ext4` keeps the upper on the `scratch` block device, a whole-device
//!   ext4 filesystem, and `nvx_overlay_upper=ramfs` keeps it in RAM, with no scratch block device.
//!
//! The addresses are the MMIO bases of the two block devices, [`DISTRO_MMIO_BASE`] and
//! [`SCRATCH_MMIO_BASE`], which the microVM fixes for their roles, and identities take the
//! canonical text of a [`Uuid`].
//!
//! Guests read the tokens with [`RootLayout::parse`], which accepts exactly these forms and
//! refuses every other, with no fallback that probes the image or the devices.

use std::fmt;
use std::str::FromStr;

use super::{ProtocolError, violation};

/// The MMIO base of the `distro` block device, which holds a layered root's image.
pub const DISTRO_MMIO_BASE: u64 = 0xd000_3000;

/// The MMIO base of the `scratch` block device, which holds the ext4 upper of a layered root.
pub const SCRATCH_MMIO_BASE: u64 = 0xd000_6000;

/// Prefix of the token that names a layered root's image, `nvx_layer=`.
pub const LAYER_TOKEN: &str = "nvx_layer=";

/// Prefix of the token that keeps a layered root's upper on its scratch block device,
/// `nvx_scratch=`.
pub const SCRATCH_TOKEN: &str = "nvx_scratch=";

/// The token that keeps a layered root's upper in RAM.
pub const RAM_UPPER_TOKEN: &str = "nvx_overlay_upper=ramfs";

/// The name of the kernel parameter that names the image.
const LAYER: &str = "nvx_layer";
/// The name of the kernel parameter that keeps the upper on the scratch block device.
const SCRATCH: &str = "nvx_scratch";
/// The name of the kernel parameter that keeps the upper in RAM.
const OVERLAY_UPPER: &str = "nvx_overlay_upper";
/// The value of the kernel parameter that keeps the upper in RAM.
const RAM_UPPER: &str = "ramfs";
/// The role of the image's block device.
const DISTRO_ROLE: &str = "distro";
/// The filesystem of the scratch block device.
const SCRATCH_FILESYSTEM: &str = "ext4";
/// The kernel parameter that adds a virtio-mmio device, `SIZE@BASE:IRQ[:ID]`, whose dashes and
/// underscores the kernel takes for each other.
const VIRTIO_MMIO_DEVICE: &str = "virtio_mmio.device";
/// The offsets of the hyphens in the canonical text of a UUID.
const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];
/// The length of the canonical text of a UUID.
const UUID_TEXT_LEN: usize = 36;

/// A UUID, such as a GPT GUID, in its canonical text: 32 lowercase hexadecimal digits in groups
/// of 8, 4, 4, 4, and 12, joined by hyphens, as in `0123abcd-4567-89ef-0123-456789abcdef`.
///
/// Its bytes are those of its digits, in the order of the text. GPT stores the first three groups
/// of a GUID little-endian, so the bytes that a disk stores differ from these.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Returns the UUID whose bytes, in the order of its text, are `bytes`.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the UUID's bytes, in the order of its text.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parses the canonical text of a UUID, and no other form: not uppercase digits, braces, a
    /// prefix, or other groups.
    pub fn parse(text: impl AsRef<[u8]>) -> Option<Self> {
        let text = text.as_ref();
        if text.len() != UUID_TEXT_LEN || UUID_HYPHENS.iter().any(|&offset| text[offset] != b'-') {
            return None;
        }
        let mut digits = text
            .iter()
            .enumerate()
            .filter(|(offset, _)| !UUID_HYPHENS.contains(offset))
            .map(|(_, &digit)| match digit {
                b'0'..=b'9' => Some(digit - b'0'),
                b'a'..=b'f' => Some(digit - b'a' + 10),
                _ => None,
            });
        let mut bytes = [0; 16];
        for byte in &mut bytes {
            let high = digits.next()??;
            let low = digits.next()??;
            *byte = (high << 4) | low;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Uuid({self})")
    }
}

impl FromStr for Uuid {
    type Err = ProtocolError;

    /// Parses the canonical text of a UUID, as [`Uuid::parse`] does.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text).ok_or_else(|| {
            violation(format!(
                "'{}' is not a UUID in its canonical text",
                text.escape_default()
            ))
        })
    }
}

/// The format of a layered root's image, which its token names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImageFormat {
    /// An EROFS filesystem, whose identity is its filesystem UUID.
    Erofs,
    /// A GPT disk, whose identity is its disk GUID.
    Gpt,
}

impl ImageFormat {
    /// Every format.
    const ALL: [Self; 2] = [Self::Erofs, Self::Gpt];

    /// Returns the format's name in the token: `erofs` or `gpt`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Erofs => "erofs",
            Self::Gpt => "gpt",
        }
    }

    /// Returns the format that `name` names in the token, if any.
    pub fn from_name(name: impl AsRef<[u8]>) -> Option<Self> {
        let name = name.as_ref();
        Self::ALL
            .into_iter()
            .find(|format| format.as_str().as_bytes() == name)
    }

    /// Returns what the format calls the identity of an image.
    const fn identity_name(self) -> &'static str {
        match self {
            Self::Erofs => "EROFS filesystem UUID",
            Self::Gpt => "GPT disk GUID",
        }
    }
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The image of a layered root: its format, and the identity that the guest expects of it, which
/// the guest checks before it uses the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootImage {
    /// The image's format.
    pub format: ImageFormat,
    /// The identity that the guest expects of the image, if any: the UUID of an EROFS
    /// filesystem, or the disk GUID of a GPT disk.
    pub identity: Option<Uuid>,
}

impl RootImage {
    /// Returns an EROFS image, with the filesystem UUID that the guest expects, if any.
    pub const fn erofs(identity: Option<Uuid>) -> Self {
        Self {
            format: ImageFormat::Erofs,
            identity,
        }
    }

    /// Returns a GPT image, with the disk GUID that the guest expects, if any.
    pub const fn gpt(identity: Option<Uuid>) -> Self {
        Self {
            format: ImageFormat::Gpt,
            identity,
        }
    }
}

/// Where a layered root keeps the upper of its overlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RootUpper {
    /// A whole-device ext4 filesystem on the `scratch` block device.
    Scratch,
    /// RAM, with no `scratch` block device.
    Ram,
}

impl RootUpper {
    /// Returns the upper's name: `scratch` or `ram`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scratch => "scratch",
            Self::Ram => "ram",
        }
    }
}

impl fmt::Display for RootUpper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The layout of a layered root: its image, on the `distro` block device, and its upper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootLayout {
    /// The read-only image.
    pub image: RootImage,
    /// The upper.
    pub upper: RootUpper,
}

impl RootLayout {
    /// Returns the layout's boot tokens: the image's, `nvx_layer=distro,0xd0003000,FORMAT`, with
    /// `:IDENTITY` when the image has an identity, then the upper's, `nvx_scratch=0xd0006000,ext4`
    /// or `nvx_overlay_upper=ramfs`.
    pub fn tokens(&self) -> [String; 2] {
        let RootImage { format, identity } = self.image;
        let layer = format!("{LAYER_TOKEN}{DISTRO_ROLE},{DISTRO_MMIO_BASE:#x},{format}");
        let layer = match identity {
            Some(identity) => format!("{layer}:{identity}"),
            None => layer,
        };
        let upper = match self.upper {
            RootUpper::Scratch => {
                format!("{SCRATCH_TOKEN}{SCRATCH_MMIO_BASE:#x},{SCRATCH_FILESYSTEM}")
            }
            RootUpper::Ram => RAM_UPPER_TOKEN.to_owned(),
        };
        [layer, upper]
    }

    /// Reads the layout of a layered root from the boot tokens of a kernel command line, such as
    /// the guest's `/proc/cmdline`, or returns `None` if the command line has none of them, as
    /// that of a blockless root has none.
    ///
    /// The command line splits at spaces, tabs, and newlines, without quoting, as the guest's init
    /// splits it, and its tokens may come in any order. Each boot token must take one of the forms
    /// of the [module](self), with a value and at most once. The image needs one upper, and each
    /// upper the image. A RAM upper also refuses a scratch block device: the kernel adds a
    /// microVM's virtio-mmio devices from the `virtio_mmio.device=SIZE@BASE:IRQ` parameters that
    /// the VMM appends, and none may sit at [`SCRATCH_MMIO_BASE`]. The parser finds and reads those
    /// parameters as the kernel does, which splits its command line at more whitespace than init,
    /// honors double quotes, and stops at `--`, and reads a base with a sign or past 64 bits. Other
    /// tokens are ignored, as are the devices that the layout uses, which the guest resolves
    /// itself.
    ///
    /// Fails with a [`ProtocolError`] that names the first token that breaks these rules, or the
    /// tokens that conflict.
    pub fn parse(command_line: &[u8]) -> Result<Option<Self>, ProtocolError> {
        let mut image = None;
        let mut scratch = false;
        let mut ram = false;
        for token in command_line.split(|byte| matches!(byte, b' ' | b'\t' | b'\n')) {
            let (name, value) = match token.iter().position(|&byte| byte == b'=') {
                Some(equals) => (&token[..equals], Some(&token[equals + 1..])),
                None => (token, None),
            };
            let Some(parameter) = [LAYER, SCRATCH, OVERLAY_UPPER]
                .into_iter()
                .find(|parameter| parameter.as_bytes() == name)
            else {
                continue;
            };
            let Some(value) = value else {
                return Err(violation(format!(
                    "the {parameter} kernel parameter has no value"
                )));
            };
            let seen = match parameter {
                LAYER => image.is_some(),
                SCRATCH => scratch,
                _ => ram,
            };
            if seen {
                return Err(violation(format!(
                    "the {parameter} kernel parameter is repeated"
                )));
            }
            match parameter {
                LAYER => image = Some(parse_image(value)?),
                SCRATCH => {
                    let expected = format!("{SCRATCH_MMIO_BASE:#x},{SCRATCH_FILESYSTEM}");
                    if value != expected.as_bytes() {
                        return Err(violation(format!(
                            "the {SCRATCH} kernel parameter must be {expected}, not '{}'",
                            value.escape_ascii()
                        )));
                    }
                    scratch = true;
                }
                _ => {
                    if value != RAM_UPPER.as_bytes() {
                        return Err(violation(format!(
                            "the {OVERLAY_UPPER} kernel parameter must be {RAM_UPPER}, not '{}'",
                            value.escape_ascii()
                        )));
                    }
                    ram = true;
                }
            }
        }
        let upper = match (scratch, ram) {
            (true, true) => {
                return Err(violation(format!(
                    "a layered root has one upper, but the command line names both {SCRATCH} and \
                     {OVERLAY_UPPER}"
                )));
            }
            (false, true) if adds_scratch_device(command_line) => {
                return Err(violation(format!(
                    "a RAM upper takes no scratch block device, but the command line adds a \
                     virtio-mmio device at {SCRATCH_MMIO_BASE:#x}"
                )));
            }
            (true, false) => Some(RootUpper::Scratch),
            (false, true) => Some(RootUpper::Ram),
            (false, false) => None,
        };
        match (image, upper) {
            (Some(image), Some(upper)) => Ok(Some(Self { image, upper })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(violation(format!(
                "the {LAYER} kernel parameter needs an upper, {SCRATCH} or {OVERLAY_UPPER}"
            ))),
            (None, Some(upper)) => {
                let parameter = match upper {
                    RootUpper::Scratch => SCRATCH,
                    RootUpper::Ram => OVERLAY_UPPER,
                };
                Err(violation(format!(
                    "the {parameter} kernel parameter needs an image, which {LAYER} names"
                )))
            }
        }
    }
}

/// Parses the value of the image's token, `distro,0xd0003000,FORMAT[:IDENTITY]`.
fn parse_image(value: &[u8]) -> Result<RootImage, ProtocolError> {
    let fields: Vec<&[u8]> = value.split(|&byte| byte == b',').collect();
    let [role, address, image] = fields[..] else {
        return Err(violation(format!(
            "the {LAYER} kernel parameter must be \
             {DISTRO_ROLE},{DISTRO_MMIO_BASE:#x},FORMAT[:IDENTITY], not '{}'",
            value.escape_ascii()
        )));
    };
    if role != DISTRO_ROLE.as_bytes() {
        return Err(violation(format!(
            "the {LAYER} kernel parameter names the block device '{}', but a layered root has only \
             the {DISTRO_ROLE} one",
            role.escape_ascii()
        )));
    }
    if address != format!("{DISTRO_MMIO_BASE:#x}").as_bytes() {
        return Err(violation(format!(
            "the {LAYER} kernel parameter places the {DISTRO_ROLE} block device at '{}', not at \
             {DISTRO_MMIO_BASE:#x}",
            address.escape_ascii()
        )));
    }
    let (format, identity) = match image.iter().position(|&byte| byte == b':') {
        Some(colon) => (&image[..colon], Some(&image[colon + 1..])),
        None => (image, None),
    };
    let Some(format) = ImageFormat::from_name(format) else {
        // The form without a format, `distro,MMIO,UUID`, names an identity in its place.
        if format.is_empty() || Uuid::parse(format).is_some() {
            return Err(violation(format!(
                "the {LAYER} kernel parameter names no image format, erofs or gpt: '{}'",
                value.escape_ascii()
            )));
        }
        return Err(violation(format!(
            "the {LAYER} kernel parameter names the unsupported image format '{}'",
            format.escape_ascii()
        )));
    };
    let identity = match identity {
        None => None,
        Some(text) => Some(Uuid::parse(text).ok_or_else(|| {
            violation(format!(
                "the {LAYER} kernel parameter names an invalid {}: '{}'",
                format.identity_name(),
                text.escape_ascii()
            ))
        })?),
    };
    Ok(RootImage { format, identity })
}

/// Returns whether the kernel adds a virtio-mmio device at [`SCRATCH_MMIO_BASE`] from a
/// `virtio_mmio.device` parameter of `command_line`, as [`kernel_parameters`] finds the
/// parameters and [`device_base`] reads their values.
fn adds_scratch_device(command_line: &[u8]) -> bool {
    kernel_parameters(command_line)
        .into_iter()
        .any(|(name, value)| {
            is_virtio_mmio_device(name) && value.and_then(device_base) == Some(SCRATCH_MMIO_BASE)
        })
}

/// Returns whether the kernel takes `byte` for whitespace, as its `isspace` does: the space, tab,
/// newline, vertical tab, form feed, carriage return, and Latin-1's no-break space, 0xa0.
const fn is_kernel_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0xa0)
}

/// Returns the parameters, `(NAME, VALUE)`, into which the kernel splits a command line, as its
/// `parse_args` and `next_arg` split it.
///
/// A parameter ends at whitespace outside double quotes, which it may open anywhere to hold
/// whitespace. The kernel drops a quote that starts the parameter or its value, and then a quote
/// that ends the parameter. The name ends at the first `=` after the parameter's first byte, and a
/// parameter without one has no value. The kernel stops at a NUL, and at a `--` without a value,
/// after which it leaves every parameter to init.
fn kernel_parameters(command_line: &[u8]) -> Vec<(&[u8], Option<&[u8]>)> {
    let end = command_line
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(command_line.len());
    let mut rest = &command_line[..end];
    let mut parameters = Vec::new();
    loop {
        let start = rest
            .iter()
            .position(|&byte| !is_kernel_space(byte))
            .unwrap_or(rest.len());
        rest = &rest[start..];
        let Some(&first) = rest.first() else {
            return parameters;
        };
        let quoted = first == b'"';
        let text = if quoted { &rest[1..] } else { rest };
        let mut in_quote = quoted;
        let mut equals = None;
        let mut length = 0;
        while let Some(&byte) = text.get(length) {
            if is_kernel_space(byte) && !in_quote {
                break;
            }
            if equals.is_none() && byte == b'=' && length > 0 {
                equals = Some(length);
            }
            if byte == b'"' {
                in_quote = !in_quote;
            }
            length += 1;
        }
        let parameter = &text[..length];
        rest = &text[length..];
        let closing = parameter.last() == Some(&b'"');
        let Some(equals) = equals else {
            let name = if quoted && closing {
                &parameter[..length - 1]
            } else {
                parameter
            };
            if name == b"--" {
                return parameters;
            }
            parameters.push((name, None));
            continue;
        };
        let value = &parameter[equals + 1..];
        let value = match value.strip_prefix(b"\"") {
            Some(value) if closing => &value[..value.len().saturating_sub(1)],
            Some(value) => value,
            // The parameter's closing quote ends its value.
            None if quoted && closing => &value[..value.len() - 1],
            None => value,
        };
        parameters.push((&parameter[..equals], Some(value)));
    }
}

/// Returns whether `name` is the kernel parameter that adds a virtio-mmio device,
/// `virtio_mmio.device`, in which the kernel takes dashes and underscores for each other.
fn is_virtio_mmio_device(name: &[u8]) -> bool {
    name.len() == VIRTIO_MMIO_DEVICE.len()
        && name
            .iter()
            .zip(VIRTIO_MMIO_DEVICE.bytes())
            .all(|(&byte, expected)| byte == expected || (expected == b'_' && byte == b'-'))
}

/// Returns the base address of the virtio-mmio device that the kernel adds from a
/// `virtio_mmio.device` value, `SIZE@BASE:IRQ[:ID]`, or `None` if it adds none from the value.
///
/// The kernel reads SIZE as its `memparse` does, an integer with an optional suffix such as `K`.
/// It then needs `@`, and reads BASE as `sscanf`'s `%lli` does: after any whitespace, an optional
/// minus sign and an integer, which the sign negates at 64 bits. It then needs `:`. Its integers
/// take C's prefixes, as [`kernel_integer`] reads them. The kernel may still refuse the value for
/// its IRQ or ID, which this does not read, so a device at the base is one that it may add.
fn device_base(value: &[u8]) -> Option<u64> {
    let (_, size) = kernel_integer(value);
    let mut rest = &value[size..];
    if size > 0
        && rest
            .first()
            .is_some_and(|suffix| b"KkMmGgTtPpEe".contains(suffix))
    {
        rest = &rest[1..];
    }
    let rest = rest.strip_prefix(b"@")?;
    let start = rest
        .iter()
        .position(|&byte| !is_kernel_space(byte))
        .unwrap_or(rest.len());
    let rest = &rest[start..];
    let (negative, rest) = match rest.strip_prefix(b"-") {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    if !rest.first().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let (base, length) = kernel_integer(rest);
    (rest.get(length) == Some(&b':')).then_some(if negative { base.wrapping_neg() } else { base })
}

/// Reads the integer that starts `text` as the kernel's `simple_strtoull` reads it with base 0:
/// hexadecimal after `0x` or `0X` and a hexadecimal digit, octal after any other leading `0`, and
/// decimal otherwise, wrapping at 64 bits. Returns the integer and the length of its text, 0 if
/// `text` starts with no digit.
fn kernel_integer(text: &[u8]) -> (u64, usize) {
    let (radix, start) = match text {
        [b'0', b'x' | b'X', digit, ..] if digit.is_ascii_hexdigit() => (16, 2),
        [b'0', ..] => (8, 0),
        _ => (10, 0),
    };
    let mut integer = 0_u64;
    let mut end = start;
    while let Some(digit) = text
        .get(end)
        .and_then(|&byte| char::from(byte).to_digit(radix))
    {
        integer = integer
            .wrapping_mul(u64::from(radix))
            .wrapping_add(u64::from(digit));
        end += 1;
    }
    (integer, end)
}

#[cfg(test)]
mod tests;
