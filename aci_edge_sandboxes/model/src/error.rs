//! Errors and their stable classification.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Result type used throughout the edge sandbox crates.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Boxed error type accepted as the source of an [`Error`].
type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Stable classification of an [`Error`].
///
/// Codes follow the state-aware sandbox error model. [`ErrorCode::wire_code`] returns the wire code
/// for each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request is structurally invalid.
    MalformedRequest,
    /// The sandbox ID is structurally invalid.
    MalformedId,
    /// The sandbox ID is well formed but no longer refers to a provisioned sandbox.
    StaleId,
    /// The operation requires a running sandbox, but the sandbox is only provisioned.
    NotStarted,
    /// The sandbox is already running.
    AlreadyStarted,
    /// The sandbox is already stopped.
    AlreadyStopped,
    /// The request is well formed, but the backend cannot represent or enforce it.
    PolicyValidation,
    /// A runtime dependency of the backend is missing or unusable.
    BackendUnavailable,
    /// The backend does not implement the requested operation.
    Unsupported,
    /// Any other backend failure.
    BackendError,
}

impl ErrorCode {
    /// Returns the snake_case wire spelling of this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::MalformedId => "malformed_id",
            Self::StaleId => "stale_id",
            Self::NotStarted => "not_started",
            Self::AlreadyStarted => "already_started",
            Self::AlreadyStopped => "already_stopped",
            Self::PolicyValidation => "policy_validation",
            Self::BackendUnavailable => "backend_unavailable",
            Self::Unsupported => "unsupported",
            Self::BackendError => "backend_error",
        }
    }

    /// Returns the state-aware wire code for this code.
    ///
    /// The wire model has no separate "unsupported" code, so [`ErrorCode::Unsupported`] maps to
    /// `backend_error`.
    pub const fn wire_code(self) -> &'static str {
        self.on_wire().as_str()
    }

    /// Returns the code that represents this one on the wire.
    const fn on_wire(self) -> Self {
        match self {
            Self::Unsupported => Self::BackendError,
            other => other,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned by every fallible edge sandbox operation.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Error {
    code: ErrorCode,
    message: String,
    #[source]
    source: Option<BoxedSource>,
    /// The code of the NVX error that this error converts, if it converts one.
    nvx_code: Option<nvx::ErrorCode>,
}

impl Error {
    /// Creates an error with the given code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
            nvx_code: None,
        }
    }

    /// Converts an NVX error as [`From`] does, but with `code`, for a backend that classifies a
    /// failure by the operation that met it, as an exec that finds the sandbox's VM gone. The
    /// message, the cause, and the NVX code stay the same.
    pub fn from_nvx(code: ErrorCode, error: nvx::Error) -> Self {
        let nvx_code = error.code();
        let (_, message, source) = error.into_parts();
        Self {
            code,
            message,
            source,
            nvx_code: Some(nvx_code),
        }
    }

    /// Attaches an underlying cause to this error.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<BoxedSource>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Returns the stable classification of this error.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the stable code of the NVX error that this error converts, if it converts one,
    /// which tells apart failures that share this error's [`code`](Self::code), such as a
    /// runtime record of another format and a VM of another runtime identity. The wire body does
    /// not carry it.
    pub fn nvx_code(&self) -> Option<nvx::ErrorCode> {
        self.nvx_code
    }

    /// Returns the human-readable description of this error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the contract's serializable `{ "code", "message" }` error body.
    ///
    /// The body carries the wire classification, so [`ErrorCode::Unsupported`] becomes
    /// [`ErrorCode::BackendError`], as in [`ErrorCode::wire_code`].
    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code.on_wire(),
            message: self.message.clone(),
        }
    }
}

/// Constructors for each [`ErrorCode`].
impl Error {
    /// Creates an error for a structurally invalid request.
    pub fn malformed_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::MalformedRequest, message)
    }

    /// Creates an error for a structurally invalid sandbox ID.
    pub fn malformed_id(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::MalformedId, message)
    }

    /// Creates an error for an ID that no longer refers to a provisioned sandbox.
    pub fn stale_id(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::StaleId, message)
    }

    /// Creates an error for an operation that needs a running sandbox.
    pub fn not_started(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotStarted, message)
    }

    /// Creates an error for a sandbox that is already running.
    pub fn already_started(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AlreadyStarted, message)
    }

    /// Creates an error for a sandbox that is already stopped.
    pub fn already_stopped(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AlreadyStopped, message)
    }

    /// Creates an error for a request the backend cannot represent or enforce.
    pub fn policy_validation(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PolicyValidation, message)
    }

    /// Creates an error for a missing or unusable runtime dependency.
    pub fn backend_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BackendUnavailable, message)
    }

    /// Creates an error for an operation the backend does not implement.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, message)
    }

    /// Creates an error for any other backend failure.
    pub fn backend_error(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BackendError, message)
    }
}

/// Classifies an error of NVX: [`nvx::ErrorKind::Unavailable`] becomes
/// [`ErrorCode::BackendUnavailable`], [`nvx::ErrorKind::Unsupported`] becomes
/// [`ErrorCode::PolicyValidation`], and every other kind becomes [`ErrorCode::BackendError`]. The
/// message and the cause stay the same, and [`Error::nvx_code`] keeps the NVX error's code.
impl From<nvx::Error> for Error {
    fn from(error: nvx::Error) -> Self {
        let code = match error.kind() {
            nvx::ErrorKind::Unavailable => ErrorCode::BackendUnavailable,
            nvx::ErrorKind::Unsupported => ErrorCode::PolicyValidation,
            _ => ErrorCode::BackendError,
        };
        Self::from_nvx(code, error)
    }
}

/// Serializable error body: `{ "code": ..., "message": ... }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable error classification.
    pub code: ErrorCode,
    /// Human-readable description.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_use_contract_spelling() {
        let body = Error::new(ErrorCode::PolicyValidation, "nope").body();
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(json, r#"{"code":"policy_validation","message":"nope"}"#);
        assert_eq!(serde_json::from_str::<ErrorBody>(&json).unwrap(), body);
    }

    #[test]
    fn unsupported_maps_to_wire_backend_error() {
        assert_eq!(ErrorCode::Unsupported.wire_code(), "backend_error");
        assert_eq!(ErrorCode::StaleId.wire_code(), "stale_id");
        assert_eq!(
            ErrorCode::BackendUnavailable.wire_code(),
            "backend_unavailable"
        );
    }

    #[test]
    fn bodies_of_unsupported_errors_serialize_the_wire_code() {
        let error = Error::unsupported("cancellation is not supported");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        let body = error.body();
        assert_eq!(body.code, ErrorCode::BackendError);
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"code":"backend_error","message":"cancellation is not supported"}"#
        );
    }

    #[test]
    fn nvx_errors_keep_their_message_and_cause() {
        for (kind, code) in [
            (nvx::ErrorKind::Unavailable, ErrorCode::BackendUnavailable),
            (nvx::ErrorKind::Unsupported, ErrorCode::PolicyValidation),
            (nvx::ErrorKind::Exited, ErrorCode::BackendError),
            (nvx::ErrorKind::Io, ErrorCode::BackendError),
            (nvx::ErrorKind::Protocol, ErrorCode::BackendError),
            (nvx::ErrorKind::TimedOut, ErrorCode::BackendError),
            (nvx::ErrorKind::Other, ErrorCode::BackendError),
        ] {
            let cause = std::io::Error::other("disk full");
            let error = Error::from(nvx::Error::new(kind, "cannot write state").with_source(cause));
            assert_eq!(error.code(), code, "{kind}");
            assert_eq!(error.nvx_code(), Some(nvx::ErrorCode::from(kind)));
            assert_eq!(error.message(), "cannot write state");
            let source = std::error::Error::source(&error).unwrap();
            assert_eq!(source.to_string(), "disk full");
        }
        assert_eq!(Error::backend_error("x").nvx_code(), None);
    }

    #[test]
    fn nvx_errors_keep_their_code_through_their_kind_and_any_classification() {
        // The kind classifies the error, and the finer code tells apart failures that share it.
        let error = Error::from(nvx::Error::new(
            nvx::ErrorCode::FormatUnsupported,
            "the sandbox runtime record has the unsupported format 3",
        ));
        assert_eq!(error.code(), ErrorCode::BackendError);
        assert_eq!(error.nvx_code(), Some(nvx::ErrorCode::FormatUnsupported));
        let gone = Error::from_nvx(
            ErrorCode::NotStarted,
            nvx::Error::new(
                nvx::ErrorCode::SandboxExited,
                "sandbox x stopped unexpectedly",
            ),
        );
        assert_eq!(gone.code(), ErrorCode::NotStarted);
        assert_eq!(gone.nvx_code(), Some(nvx::ErrorCode::SandboxExited));
        assert_eq!(gone.message(), "sandbox x stopped unexpectedly");
        // The wire body carries the classification alone.
        assert_eq!(
            serde_json::to_string(&gone.body()).unwrap(),
            r#"{"code":"not_started","message":"sandbox x stopped unexpectedly"}"#
        );
    }

    #[test]
    fn display_includes_code_and_message() {
        let error = Error::stale_id("sandbox aci-edge-sandboxes:00 was deprovisioned");
        assert_eq!(
            error.to_string(),
            "stale_id: sandbox aci-edge-sandboxes:00 was deprovisioned"
        );
    }
}
