//! Per-sandbox creation settings outside the provision request.
//!
//! [`ProvisionRequest`](crate::ProvisionRequest) carries the contract's policies. A
//! [`SandboxSpec`] carries what a backend needs to create one sandbox beyond them: the image, the
//! guest's resources and network identity, and forwarded ports. Every field is optional; unset
//! fields take the backend's defaults, and nothing here is specific to one VMM.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::image::ImageId;
use crate::model::HostLoopbackForward;

pub use nvx::net::{is_valid_guest_network, is_valid_hostname};

/// Per-sandbox creation settings outside the provision request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SandboxSpec {
    /// The guest image; `None` selects the backend's default image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageSource>,
    /// Guest resources; unset values take the backend's defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    /// The guest's `ADDRESS/PREFIX` on its private network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_network: Option<String>,
    /// The guest's hostname: a lowercase RFC 1123 label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Host loopback ports that each reach one guest port. Forwarded ports need
    /// `network.ingress.hostLoopback: allow`, which also lets the guest reach host loopback
    /// services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_loopback_forwards: Vec<HostLoopbackForward>,
}

impl SandboxSpec {
    /// Creates a spec that takes every backend default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether the spec sets nothing, including through resources that set no value.
    pub fn is_empty(&self) -> bool {
        let Self {
            image,
            resources,
            guest_network,
            hostname,
            host_loopback_forwards,
        } = self;
        image.is_none()
            && resources.is_none_or(|resources| resources == Resources::default())
            && guest_network.is_none()
            && hostname.is_none()
            && host_loopback_forwards.is_empty()
    }

    /// Selects the guest image.
    #[must_use]
    pub fn with_image(mut self, image: ImageSource) -> Self {
        self.image = Some(image);
        self
    }

    /// Sets the guest memory size.
    #[must_use]
    pub fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.resources
            .get_or_insert_with(Resources::default)
            .memory_mib = Some(memory_mib);
        self
    }

    /// Sets the number of virtual processors.
    #[must_use]
    pub fn with_vcpus(mut self, vcpus: u32) -> Self {
        self.resources.get_or_insert_with(Resources::default).vcpus = Some(vcpus);
        self
    }

    /// Sets the guest's `ADDRESS/PREFIX`.
    #[must_use]
    pub fn with_guest_network(mut self, guest_network: impl Into<String>) -> Self {
        self.guest_network = Some(guest_network.into());
        self
    }

    /// Sets the guest's hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Publishes a guest port on a host loopback port.
    #[must_use]
    pub fn with_host_loopback_forward(mut self, forward: HostLoopbackForward) -> Self {
        self.host_loopback_forwards.push(forward);
        self
    }
}

/// Where a sandbox's guest image comes from.
///
/// It serializes as `{"reference": "registry/repository:tag"}`, `{"digest": "sha256:…"}`, or
/// `{"path": "…"}`.
///
/// A backend that registers images provisions only images registered with it: a path or a
/// reference that it has not registered fails, and provisioning never pulls, copies, or hashes an
/// image. The setup's default image is registered when the backend opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum ImageSource {
    /// A container image reference, such as `registry/repository:tag` or
    /// `registry/repository@sha256:…`. A host that pulls references registers each one by its
    /// text, pulling it once, and does not check a tag again; see
    /// [`ReferenceSettings`](crate::ReferenceSettings).
    Reference(String),
    /// An image already registered with the backend, by content.
    Digest(ImageId),
    /// A local GPT disk image, by the absolute path from which it was registered.
    Path(PathBuf),
}

impl ImageSource {
    /// Checks the source's structure, reporting
    /// [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest) for `field`.
    pub fn validate(&self, field: &str) -> Result<()> {
        match self {
            Self::Reference(reference) => {
                validate_reference(reference, &format!("{field}.reference"))
            }
            Self::Digest(_) => Ok(()),
            Self::Path(path) => validate_path(path, &format!("{field}.path")),
        }
    }
}

/// Checks an image reference, which must be nonempty and hold no whitespace or control
/// characters, reporting [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest) for
/// `field`.
pub(crate) fn validate_reference(reference: &str, field: &str) -> Result<()> {
    if reference.is_empty()
        || reference
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(Error::malformed_request(format!(
            "{field} must be a nonempty image reference without whitespace or control characters"
        )));
    }
    Ok(())
}

/// Checks the path of a local image, which must be absolute and valid UTF-8 without NUL
/// characters, reporting [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest) for
/// `field`.
pub(crate) fn validate_path(path: &Path, field: &str) -> Result<()> {
    if !path.is_absolute() || path.to_str().is_none_or(|value| value.contains('\0')) {
        return Err(Error::malformed_request(format!(
            "{field} must be an absolute valid UTF-8 path without NUL characters"
        )));
    }
    Ok(())
}

/// Guest resources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Resources {
    /// Number of virtual processors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u32>,
    /// Guest memory in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,
}

impl Resources {
    /// Creates resources with both values set.
    pub fn new(vcpus: u32, memory_mib: u32) -> Self {
        Self {
            vcpus: Some(vcpus),
            memory_mib: Some(memory_mib),
        }
    }

    /// Checks that set values are positive, reporting
    /// [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest) for `field`.
    pub fn validate(&self, field: &str) -> Result<()> {
        if self.vcpus == Some(0) {
            return Err(Error::malformed_request(format!(
                "{field}.vcpus must be positive"
            )));
        }
        if self.memory_mib == Some(0) {
            return Err(Error::malformed_request(format!(
                "{field}.memoryMib must be positive"
            )));
        }
        Ok(())
    }
}

pub(crate) fn hostname(value: &str, field: &str) -> Result<()> {
    if is_valid_hostname(value) {
        Ok(())
    } else {
        Err(Error::malformed_request(format!(
            "{field} {value:?} must be a lowercase RFC 1123 label of up to 63 characters"
        )))
    }
}

pub(crate) fn guest_network(value: &str, field: &str) -> Result<()> {
    if is_valid_guest_network(value) {
        Ok(())
    } else {
        Err(Error::malformed_request(format!(
            "{field} {value:?} must be an IPv4 address with a /1 to /30 prefix that is not its \
             network's network, broadcast, or gateway (first) address"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ForwardProtocol;

    #[test]
    fn specs_parse_their_wire_form() {
        let spec: SandboxSpec = serde_json::from_str(
            r#"{
                "image": {"path": "/images/python.vhd"},
                "resources": {"memoryMib": 512},
                "guestNetwork": "10.0.0.2/24",
                "hostname": "worker-1",
                "hostLoopbackForwards": [{"protocol": "tcp", "hostPort": 8080, "guestPort": 80}]
            }"#,
        )
        .unwrap();
        assert_eq!(
            spec,
            SandboxSpec::new()
                .with_image(ImageSource::Path("/images/python.vhd".into()))
                .with_memory_mib(512)
                .with_guest_network("10.0.0.2/24")
                .with_hostname("worker-1")
                .with_host_loopback_forward(HostLoopbackForward::new(
                    ForwardProtocol::Tcp,
                    8080,
                    80
                ))
        );
        assert!(!spec.is_empty());
        assert!(SandboxSpec::new().is_empty());
        // Resources that set no value set nothing.
        let unset: SandboxSpec = serde_json::from_str(r#"{"resources": {}}"#).unwrap();
        assert!(unset.is_empty());
        assert!(!SandboxSpec::new().with_vcpus(1).is_empty());
        assert!(serde_json::from_str::<SandboxSpec>(r#"{"scratch": "/s"}"#).is_err());
    }

    #[test]
    fn image_references_have_no_whitespace_or_control_characters() {
        let reference = |text: &str| ImageSource::Reference(text.to_owned()).validate("image");
        reference("mcr.microsoft.com/a/b:1").unwrap();
        reference("registry/repository@sha256:0123").unwrap();
        for invalid in [
            "",
            " ",
            "repo name",
            "repo\tname",
            "repo\nname",
            "repo\rname",
            "repo\u{b}name",
            "repo\u{c}name",
            "repo\u{a0}name",
            "repo\u{3000}name",
            "repo\0name",
            "repo\u{7f}name",
        ] {
            let error = reference(invalid).unwrap_err();
            assert_eq!(
                error.code(),
                crate::ErrorCode::MalformedRequest,
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn image_sources_use_one_key() {
        for (source, json) in [
            (
                ImageSource::Reference("mcr.microsoft.com/a/b:1".into()),
                r#"{"reference":"mcr.microsoft.com/a/b:1"}"#.to_owned(),
            ),
            (
                ImageSource::Digest(ImageId::from_sha256([2; 32])),
                format!(r#"{{"digest":"sha256:{}"}}"#, "02".repeat(32)),
            ),
        ] {
            assert_eq!(serde_json::to_string(&source).unwrap(), json);
            assert_eq!(serde_json::from_str::<ImageSource>(&json).unwrap(), source);
        }
    }
}
