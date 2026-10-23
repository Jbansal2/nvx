//! Guest images: content identities, how a host establishes them, and registrations.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};
use crate::hex;

/// Content identity of a registered guest image: the SHA-256 digest of the image file as it was
/// registered, such as a fixed VHD with its footer, which a raw copy that a host stages of it keeps.
///
/// An ID displays and parses as `sha256:` followed by 64 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImageId([u8; 32]);

impl ImageId {
    const PREFIX: &'static str = "sha256:";

    /// Returns the ID of image content with this SHA-256 digest.
    pub const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the SHA-256 digest of the image content.
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses an ID, returning
    /// [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest) unless it is `sha256:`
    /// followed by 64 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self> {
        value
            .strip_prefix(Self::PREFIX)
            .and_then(hex::decode_sha256)
            .map(Self)
            .ok_or_else(|| {
                Error::malformed_request(format!(
                    "image ID {value:?} must be sha256: followed by 64 lowercase hexadecimal \
                     digits"
                ))
            })
    }
}

impl fmt::Display for ImageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}{}", Self::PREFIX, hex::encode(&self.0))
    }
}

impl fmt::Debug for ImageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ImageId({self})")
    }
}

impl FromStr for ImageId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for ImageId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ImageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|error| serde::de::Error::custom(error.message()))
    }
}

/// How a host establishes the content digest of an image that it registers.
///
/// It serializes as `"compute"`, `{"expect": "<digest>"}`, or `{"trusted": "<digest>"}`, with
/// digests as 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ImageDigest {
    /// Hashes the registered file.
    #[default]
    Compute,
    /// Hashes the registered file and requires this SHA-256 digest.
    Expect(#[serde(with = "hex::sha256")] [u8; 32]),
    /// Records this SHA-256 digest of the registered file without hashing it.
    ///
    /// Use it only for content that the caller's own policy has verified and protects from
    /// writers, for example a file that an installer hashed before making it read-only.
    Trusted(#[serde(with = "hex::sha256")] [u8; 32]),
}

impl ImageDigest {
    /// Returns whether this is [`ImageDigest::Compute`].
    pub fn is_compute(&self) -> bool {
        *self == Self::Compute
    }
}

/// A registered guest image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RegisteredImage {
    /// Content identity: the SHA-256 digest of the file that was registered.
    pub id: ImageId,
    /// Absolute path of the file that sandboxes attach: the host's own staged copy of the image,
    /// for a host that stages images. A raw copy lacks the container format of the registered
    /// file, such as a fixed VHD's footer, but keeps its ID.
    pub path: PathBuf,
    /// Length in bytes of the file at [`path`](Self::path).
    pub length: u64,
    /// Whether the caller supplied the digest instead of the host hashing the image.
    pub trusted: bool,
    /// Whether the file still matches its registration. A sandbox whose image changed does not
    /// start until the image is registered again.
    pub intact: bool,
}

impl RegisteredImage {
    /// Describes a registration.
    pub fn new(id: ImageId, path: PathBuf, length: u64, trusted: bool, intact: bool) -> Self {
        Self {
            id,
            path,
            length,
            trusted,
            intact,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    #[test]
    fn ids_round_trip_and_reject_other_spellings() {
        let id = ImageId::from_sha256([0xab; 32]);
        let text = id.to_string();
        assert_eq!(text, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(ImageId::parse(&text).unwrap(), id);
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{text}\""));
        for bad in [
            "",
            "ab",
            &text.to_uppercase(),
            &text.replace("sha256:", "sha512:"),
        ] {
            assert_eq!(
                ImageId::parse(bad).unwrap_err().code(),
                ErrorCode::MalformedRequest,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn digest_modes_serialize_compactly() {
        assert_eq!(
            serde_json::to_string(&ImageDigest::Compute).unwrap(),
            r#""compute""#
        );
        let trusted = ImageDigest::Trusted([1; 32]);
        let json = serde_json::to_string(&trusted).unwrap();
        assert_eq!(json, format!(r#"{{"trusted":"{}"}}"#, "01".repeat(32)));
        assert_eq!(serde_json::from_str::<ImageDigest>(&json).unwrap(), trusted);
        assert!(serde_json::from_str::<ImageDigest>(r#"{"expect":"01"}"#).is_err());
    }
}
