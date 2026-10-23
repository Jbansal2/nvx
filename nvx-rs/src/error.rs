//! Errors of NVX operations and their classification.

use std::fmt;

/// Result type of NVX operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Classification of an [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A runtime dependency is missing or unusable: an artifact, the hypervisor, a release or
    /// guest image without the control contract or features that this crate needs, or a host
    /// that NVX does not support.
    Unavailable,
    /// The request is well formed, but NVX cannot represent or enforce it, for example because it
    /// exceeds a limit of OpenVMM or the guest agent.
    Unsupported,
    /// The OpenVMM process of a VM exited.
    Exited,
    /// A host I/O operation failed, or state that NVX recorded on the host is unreadable or
    /// malformed.
    Io,
    /// The state that an operation names does not exist on the host, such as the store of a
    /// sandbox that was never created or that a removal deleted.
    NotFound,
    /// The control session failed: the peer violated the protocol, closed or reset the session,
    /// or refused a request.
    Protocol,
    /// A deadline passed.
    TimedOut,
    /// Any other failure.
    Other,
}

impl ErrorKind {
    /// Returns the lowercase name of this kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Exited => "exited",
            Self::Io => "io",
            Self::NotFound => "not-found",
            Self::Protocol => "protocol",
            Self::TimedOut => "timed-out",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error of an NVX operation: its [`ErrorKind`], a description, and an optional cause.
///
/// The description is a complete sentence fragment that callers can show as is, so callers map
/// errors onto their own classifications by [`kind`](Self::kind) alone.
#[derive(Debug)]
pub struct Error {
    /// Stable classification that callers use when mapping the failure.
    kind: ErrorKind,
    /// Complete, user-facing description without a trailing period.
    message: String,
    /// Underlying implementation error, when retaining it aids diagnostics.
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// Creates an error with the given kind and description.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    /// Creates an [`ErrorKind::Unavailable`] error.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unavailable, message)
    }

    /// Creates an [`ErrorKind::Unsupported`] error.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, message)
    }

    /// Creates an [`ErrorKind::Exited`] error.
    pub fn exited(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Exited, message)
    }

    /// Creates an [`ErrorKind::Io`] error.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    /// Creates an [`ErrorKind::NotFound`] error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    /// Creates an [`ErrorKind::Protocol`] error.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }

    /// Creates an [`ErrorKind::TimedOut`] error.
    pub fn timed_out(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::TimedOut, message)
    }

    /// Creates an [`ErrorKind::Other`] error.
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Other, message)
    }

    /// Attaches an underlying cause to this error.
    #[must_use]
    pub fn with_source(
        mut self,
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Returns the classification of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the description of this error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Splits the error into its kind, description, and cause, so that a caller can rebuild it
    /// as an error of its own without adding a level to the chain of causes.
    pub fn into_parts(
        self,
    ) -> (
        ErrorKind,
        String,
        Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) {
        (self.kind, self.message, self.source)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_their_kind_message_and_cause() {
        let cause = std::io::Error::other("disk full");
        let error = Error::io("cannot write /state/runtime.json").with_source(cause);
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.to_string(), "cannot write /state/runtime.json");
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "disk full"
        );
        let (kind, message, source) = error.into_parts();
        assert_eq!(kind, ErrorKind::Io);
        assert_eq!(message, "cannot write /state/runtime.json");
        assert_eq!(source.unwrap().to_string(), "disk full");
        assert_eq!(ErrorKind::TimedOut.to_string(), "timed-out");
    }
}
