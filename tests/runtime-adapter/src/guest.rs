//! The adapter's guest agent: it serves the host program over the guest's end of the control
//! session between the host and the guest, with the adapter's own [framing](crate::frame), through
//! `nvx::guest::nvxs`, and on a tty through `nvx::guest::terminal`.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;

use nvx::guest::nvxs::{GuestConnection, GuestConnectionError};
use nvx::guest::terminal::Terminal;
use nvx::protocol::OUTER_MIN_RECEIVE_WINDOW;
use nvx::protocol::nvxs::GuestEvent;

use crate::frame::{Decoder, FrameError, Message};

/// The receive window that the guest acknowledges each epoch with: the smallest that the session
/// allows, so that the rest of a longer message arrives only as the guest credits what it took.
pub const RECEIVE_WINDOW: u32 = OUTER_MIN_RECEIVE_WINDOW;

/// How serving ended, when nothing failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    /// The host asked the guest to stop, and the guest confirmed.
    Stopped,
    /// The broker closed the stream at a record boundary.
    Closed,
}

/// A failure that ended serving.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServeError {
    /// The control session failed.
    Session(GuestConnectionError),
    /// The host sent a malformed message.
    Frame(FrameError),
    /// The host sent a message of a kind that only the guest sends.
    Unexpected(u8),
    /// The tty of the session could not be opened or put in raw mode.
    Terminal(io::Error),
}

impl fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => error.fmt(formatter),
            Self::Frame(error) => error.fmt(formatter),
            Self::Unexpected(kind) => {
                write!(
                    formatter,
                    "the host sent a message of kind {kind}, which only the guest sends"
                )
            }
            Self::Terminal(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Unexpected(_) => None,
            Self::Terminal(error) => Some(error),
        }
    }
}

impl From<GuestConnectionError> for ServeError {
    fn from(error: GuestConnectionError) -> Self {
        Self::Session(error)
    }
}

impl From<FrameError> for ServeError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

/// Serves the host program on `stream`, the guest's end of the control session, until the host
/// stops the guest or the broker closes the stream.
///
/// The guest attaches, then:
///
/// - It acknowledges each reset of the session with [`RECEIVE_WINDOW`], once it dropped the
///   earlier epoch's partial message: a new epoch starts with a new message.
/// - It credits each payload back once it holds the payload, so that a message longer than the
///   window arrives whole.
/// - It answers [`Message::Ping`] with [`Message::Pong`], sends each [`Message::Echo`] back, and
///   answers [`Message::Stop`] with [`Message::Stopped`], then returns without reading further.
///
/// A failure of the session, a malformed message, and a message that only the guest sends end
/// serving with an error.
pub fn serve<S: Read + Write>(stream: S) -> Result<Served, ServeError> {
    let mut connection = GuestConnection::new(stream);
    connection.attach()?;
    let mut decoder = Decoder::new();
    loop {
        let payload = match connection.next_event() {
            Ok(GuestEvent::Reset(_)) => {
                decoder.clear();
                connection.acknowledge(RECEIVE_WINDOW)?;
                continue;
            }
            Ok(GuestEvent::Data(payload)) => payload,
            Err(GuestConnectionError::Closed) => return Ok(Served::Closed),
            Err(error) => return Err(error.into()),
        };
        // A DATA payload has at most `OUTER_MAX_PAYLOAD` bytes, so its length fits a `u32`.
        connection.credit(payload.len() as u32)?;
        let mut rest = payload.as_slice();
        while !rest.is_empty() {
            let (consumed, message) = decoder.push(rest)?;
            rest = &rest[consumed..];
            let reply = match message {
                None => continue,
                Some(Message::Ping) => Message::Pong,
                Some(Message::Echo(body)) => Message::Echo(body),
                Some(Message::Stop) => {
                    connection.send(&Message::Stopped.encode()?)?;
                    return Ok(Served::Stopped);
                }
                Some(message) => return Err(ServeError::Unexpected(message.kind())),
            };
            connection.send(&reply.encode()?)?;
        }
    }
}

/// Serves the host program on the tty at `path`, the guest's end of the control session, as
/// [`serve`] does, in place of NVX's managed agent on a VM's control tty.
///
/// It opens the tty with NVX's [`Terminal`], as NVX's managed agent does: waiting while the kernel
/// sets the tty up during boot, and in raw mode, so that the tty passes the session's bytes as they
/// are. Once serving ends, it waits until the tty has sent what serving wrote, such as the
/// [`Message::Stopped`] that confirms a stop.
///
/// It fails with [`ServeError::Terminal`] if the tty cannot be opened or put in raw mode, and
/// otherwise as [`serve`] does.
pub fn serve_terminal(path: &Path) -> Result<Served, ServeError> {
    let failed = |action: String| {
        move |error: io::Error| {
            ServeError::Terminal(io::Error::new(error.kind(), format!("{action}: {error}")))
        }
    };
    let mut terminal =
        Terminal::open(path).map_err(failed(format!("cannot open {}", path.display())))?;
    terminal
        .configure_raw()
        .map_err(failed(format!("cannot put {} in raw mode", path.display())))?;
    let served = serve(&mut terminal)?;
    // As NVX's managed agent does, a drain that fails is no failure of serving, which ended.
    let _ = terminal.drain();
    Ok(served)
}
