//! The adapter's guest agent serves the control session between the host and the guest with the
//! adapter's own framing, through public APIs only.
//!
//! A test broker plays the broker's end of the guest's session over a Unix socket pair, with the
//! public record API of `nvx`: for the guest agent's `serve` in a thread, and for the
//! `runtime-adapter-guest` binary, whose standard input and output are the socket. The tests cover
//! messages that span records, partial records, resets in the middle of a message, disconnects,
//! record lengths, bootstrap identity, ERROR payloads, sequence and identity errors, and the
//! bounded buffer of the adapter's decoder. Through a relay to a pseudo-terminal, they also cover
//! the guest agent on a tty, which it puts in raw mode, as it serves a VM's control tty.
#![cfg(all(feature = "guest", target_os = "linux"))]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::pty;
use nvx::guest::nvxs::GuestConnectionError;
use nvx::protocol::OUTER_MAX_PAYLOAD;
use nvx::protocol::nvxs::{
    ErrorCode, Identity, Record, RecordError, RecordParser, RecordType, SessionError, encode_record,
};
use runtime_adapter::frame::{Decoder, FrameError, HEADER_LEN, MAX_BODY, Message};
use runtime_adapter::guest::{self, RECEIVE_WINDOW, ServeError, Served};

/// Identity of the broker's first epoch.
const FIRST: Identity = Identity {
    instance_id: [0x5c; 16],
    epoch: 1,
};

/// Longest wait for a record from the guest, or for the guest to end.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Offset of the protocol version in a record's header.
const VERSION_OFFSET: usize = 4;
/// Offset of the record type in a record's header.
const TYPE_OFFSET: usize = 6;
/// Offset of the flags in a record's header.
const FLAGS_OFFSET: usize = 7;
/// Offset of the instance ID in a record's header.
const INSTANCE_OFFSET: usize = 8;
/// Offset of the payload length in a record's header.
const LENGTH_OFFSET: usize = 40;

/// The broker's end of the guest's session. It resets the guest once the guest attaches, numbers
/// its records to the guest from 0 in each epoch, and sends DATA only while the guest's receive
/// window has room. It checks the identity and sequence number of each of the guest's records,
/// and panics on any record that the protocol does not allow.
struct Broker {
    /// Stream to the guest.
    stream: UnixStream,
    /// The guest's records, which a thread reads as they arrive, so that the guest never waits to
    /// write while the broker writes; then `None`, once the guest closed its stream at a record
    /// boundary.
    records: Receiver<Option<Record>>,
    /// Identity of the current epoch.
    identity: Identity,
    /// Sequence number of the broker's next record.
    send_sequence: u64,
    /// Sequence number of the guest's next record.
    receive_sequence: u64,
    /// Bytes for which the guest's receive window has room.
    room: usize,
    /// Decoder of the guest's messages.
    decoder: Decoder,
}

impl Broker {
    /// Creates the broker on its end of a socket pair.
    fn new(stream: UnixStream) -> Self {
        let reader = stream.try_clone().unwrap();
        let (sender, records) = mpsc::channel();
        thread::spawn(move || read_records(reader, &sender));
        Self {
            stream,
            records,
            identity: FIRST,
            send_sequence: 0,
            receive_sequence: 0,
            room: 0,
            decoder: Decoder::new(),
        }
    }

    /// Takes the guest's attachment, then starts the epoch of `identity`.
    fn attach(&mut self, identity: Identity) {
        let record = self.read().expect("the guest attaches");
        assert_eq!(record.record_type(), RecordType::GuestAttach);
        let header = (record.instance_id(), record.epoch(), record.sequence());
        assert_eq!(header, ([0; 16], 0, 0));
        self.reset(identity);
    }

    /// Starts the epoch of `identity` with a RESET, and takes the guest's acknowledgement.
    fn reset(&mut self, identity: Identity) {
        self.identity = identity;
        self.send_sequence = 0;
        self.receive_sequence = 0;
        self.room = 0;
        self.send(RecordType::Reset, &[]);
        let ack = self.expect();
        assert_eq!(ack.record_type(), RecordType::Ack);
        assert_eq!(ack.window(), Some(RECEIVE_WINDOW));
        self.room = RECEIVE_WINDOW as usize;
    }

    /// Sends a record of the current epoch at the broker's next sequence number.
    fn send(&mut self, record_type: RecordType, payload: &[u8]) {
        let record = record(record_type, self.identity, self.send_sequence, payload);
        self.send_sequence += 1;
        self.write(&record);
    }

    /// Writes bytes to the guest. A guest that stops reading fails the test once `TIMEOUT` passes,
    /// instead of hanging it: the socket's buffer can fill before the guest's receive window does.
    fn write(&mut self, mut bytes: &[u8]) {
        let deadline = Instant::now() + TIMEOUT;
        while !bytes.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "the guest reads the broker's bytes in time"
            );
            self.stream.set_write_timeout(Some(remaining)).unwrap();
            match self.stream.write(bytes) {
                Ok(count) => bytes = &bytes[count..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("cannot write to the guest: {error}"),
            }
        }
    }

    /// Ends the broker's stream to the guest.
    fn close(&self) {
        self.stream.shutdown(Shutdown::Write).unwrap();
    }

    /// Returns the guest's next record, or `None` once the guest closed its stream at a record
    /// boundary.
    fn read(&mut self) -> Option<Record> {
        self.records
            .recv_timeout(TIMEOUT)
            .expect("the guest sends a record or ends its stream in time")
    }

    /// Reads the guest's next record, and checks that it carries the epoch's identity and the
    /// guest's next sequence number.
    fn expect(&mut self) -> Record {
        let record = self.read().expect("the guest sends a record");
        let header = (record.instance_id(), record.epoch(), record.sequence());
        let expected = (
            self.identity.instance_id,
            self.identity.epoch,
            self.receive_sequence,
        );
        assert_eq!(header, expected, "{record:?}");
        self.receive_sequence += 1;
        record
    }

    /// Takes the guest's next record: a CREDIT, which makes room in its window, or DATA, whose
    /// complete messages it returns.
    fn take(&mut self) -> Vec<Message> {
        let record = self.expect();
        match record.record_type() {
            RecordType::Credit => {
                self.room += record.credit().unwrap() as usize;
                assert!(
                    self.room <= RECEIVE_WINDOW as usize,
                    "the guest credited more than it received"
                );
                Vec::new()
            }
            RecordType::Data => decode(&mut self.decoder, record.payload()),
            record_type => panic!("the guest sent {record_type} in an active epoch"),
        }
    }

    /// Sends the host's `bytes` in DATA records of at most `size` bytes, each once the guest's
    /// window has room for it, and returns the messages that the guest sent meanwhile.
    fn send_data(&mut self, bytes: &[u8], size: usize) -> Vec<Message> {
        let mut messages = Vec::new();
        for chunk in bytes.chunks(size) {
            while self.room < chunk.len() {
                messages.extend(self.take());
            }
            self.room -= chunk.len();
            self.send(RecordType::Data, chunk);
        }
        messages
    }

    /// Sends `messages` in DATA records of at most `size` bytes, and returns the guest's next
    /// `replies` messages.
    fn exchange(&mut self, messages: &[Message], size: usize, replies: usize) -> Vec<Message> {
        let mut received = self.send_data(&encode(messages), size);
        while received.len() < replies {
            received.extend(self.take());
        }
        assert_eq!(received.len(), replies, "{received:?}");
        received
    }

    /// Takes the guest's credit for everything that the broker sent, so that no record of the
    /// epoch is in flight.
    fn settle(&mut self) {
        while self.room < RECEIVE_WINDOW as usize {
            assert_eq!(self.take(), [], "the guest sent no message");
        }
    }
}

/// Reads the guest's records from `stream` and sends them, then `None` once the guest closed its
/// stream at a record boundary.
fn read_records(mut stream: UnixStream, records: &Sender<Option<Record>>) {
    let mut parser = RecordParser::new();
    let mut buffer = [0; 4096];
    loop {
        let wanted = parser.needed().min(buffer.len());
        let count = match stream.read(&mut buffer[..wanted]) {
            Ok(count) => count,
            // The guest closed its end before it read everything that the broker wrote, as after
            // a record that it refused. Linux returns what the guest wrote first.
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => 0,
            Err(error) => panic!("cannot read the guest's stream: {error}"),
        };
        if count == 0 {
            assert_eq!(
                parser.buffered(),
                0,
                "the guest ended its stream inside a record"
            );
            let _ = records.send(None);
            return;
        }
        let (consumed, record) = parser.push(&buffer[..count]).unwrap();
        assert_eq!(consumed, count);
        // A test that ended takes no more records.
        if record.is_some_and(|record| records.send(Some(record)).is_err()) {
            return;
        }
    }
}

/// Encodes a valid record.
fn record(record_type: RecordType, identity: Identity, sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    let (instance, epoch) = (identity.instance_id, identity.epoch);
    encode_record(
        record_type,
        &instance,
        epoch,
        sequence,
        payload,
        &mut record,
    )
    .unwrap();
    record
}

/// Returns the encodings of `messages`, one after the other.
fn encode(messages: &[Message]) -> Vec<u8> {
    messages
        .iter()
        .flat_map(|message| message.encode().unwrap())
        .collect()
}

/// Returns the messages that `bytes` complete.
fn decode(decoder: &mut Decoder, mut bytes: &[u8]) -> Vec<Message> {
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        let (consumed, message) = decoder.push(bytes).unwrap();
        bytes = &bytes[consumed..];
        messages.extend(message);
    }
    messages
}

/// Returns an echo of the longest body: with its header, the message spans five records.
fn longest() -> Message {
    Message::Echo((0..=u8::MAX).cycle().take(MAX_BODY).collect())
}

/// Starts the guest agent's `serve` in a thread, on one end of a socket pair, and returns the
/// broker on the other end with the thread.
fn start() -> (Broker, JoinHandle<Result<Served, ServeError>>) {
    let (broker, guest) = UnixStream::pair().unwrap();
    let serving = thread::spawn(move || guest::serve(guest));
    (Broker::new(broker), serving)
}

/// Returns how the guest agent's `serve` ended, and fails the test if it does not end in time, so
/// that a guest that keeps serving fails the test instead of hanging it.
fn joined(serving: JoinHandle<Result<Served, ServeError>>) -> Result<Served, ServeError> {
    let deadline = Instant::now() + TIMEOUT;
    while !serving.is_finished() {
        assert!(Instant::now() < deadline, "the guest agent ends in time");
        thread::sleep(Duration::from_millis(10));
    }
    serving.join().unwrap()
}

/// Starts the guest agent, attaches it in the first epoch, sends it `bytes`, and returns the
/// error that ended serving.
fn refused(bytes: &[u8]) -> ServeError {
    let (mut broker, serving) = start();
    broker.attach(FIRST);
    broker.write(bytes);
    let error = joined(serving).unwrap_err();
    // The guest ended its stream.
    while let Some(record) = broker.read() {
        assert_eq!(record.record_type(), RecordType::Credit, "{error:?}");
    }
    error
}

#[test]
fn the_guest_agent_answers_messages_that_span_records() {
    let (mut broker, serving) = start();
    broker.attach(FIRST);
    let replies = broker.exchange(&[Message::Ping], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::Pong]);

    // Messages in records of several sizes. The longest spans five records each way, and the
    // guest's window holds a quarter of it, so the rest arrives as the guest credits it.
    let messages = [
        Message::Ping,
        Message::Echo(b"two".to_vec()),
        longest(),
        Message::Echo(Vec::new()),
        Message::Ping,
    ];
    let expected = [
        Message::Pong,
        Message::Echo(b"two".to_vec()),
        longest(),
        Message::Echo(Vec::new()),
        Message::Pong,
    ];
    for size in [7, 4096, OUTER_MAX_PAYLOAD] {
        let replies = broker.exchange(&messages, size, expected.len());
        assert_eq!(replies, expected, "records of {size} bytes");
    }

    // A record whose bytes arrive one at a time.
    broker.settle();
    let ping = Message::Ping.encode().unwrap();
    let bytes = record(RecordType::Data, FIRST, broker.send_sequence, &ping);
    broker.send_sequence += 1;
    broker.room -= ping.len();
    for byte in bytes {
        broker.write(&[byte]);
        thread::sleep(Duration::from_millis(1));
    }
    let mut replies = Vec::new();
    while replies.is_empty() {
        replies = broker.take();
    }
    assert_eq!(replies, [Message::Pong]);

    let replies = broker.exchange(&[Message::Stop], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::Stopped]);
    assert_eq!(joined(serving).unwrap(), Served::Stopped);
    assert!(broker.read().is_none());
}

#[test]
fn a_reset_starts_the_new_epoch_with_a_new_message() {
    let (mut broker, serving) = start();
    broker.attach(FIRST);
    let echo = Message::Echo(vec![1; 1000]).encode().unwrap();

    // Half of a message, then the host's connection drops, which starts the instance's next
    // epoch. The guest drops the partial message.
    assert_eq!(broker.send_data(&echo[..500], OUTER_MAX_PAYLOAD), []);
    broker.settle();
    broker.reset(Identity { epoch: 2, ..FIRST });
    let after = Message::Echo(b"after".to_vec());
    let replies = broker.exchange(std::slice::from_ref(&after), OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [after]);

    // A broker restored from a snapshot has a new instance, which starts at epoch 1, here in
    // the middle of a header.
    assert_eq!(
        broker.send_data(&echo[..HEADER_LEN - 1], OUTER_MAX_PAYLOAD),
        []
    );
    broker.settle();
    broker.reset(Identity {
        instance_id: [0x7e; 16],
        epoch: 1,
    });
    let replies = broker.exchange(&[Message::Ping, Message::Stop], OUTER_MAX_PAYLOAD, 2);
    assert_eq!(replies, [Message::Pong, Message::Stopped]);
    assert_eq!(joined(serving).unwrap(), Served::Stopped);
}

#[test]
fn the_guest_agent_ends_with_its_stream() {
    // A stream that ends at a record boundary closes the session.
    let (mut broker, serving) = start();
    broker.attach(FIRST);
    let replies = broker.exchange(&[Message::Ping], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::Pong]);
    broker.close();
    assert_eq!(joined(serving).unwrap(), Served::Closed);
    assert!(broker.read().is_none());

    // One that ends inside a record fails it.
    let (mut broker, serving) = start();
    broker.attach(FIRST);
    let ping = record(RecordType::Data, FIRST, 1, &Message::Ping.encode().unwrap());
    broker.write(&ping[..ping.len() - 1]);
    broker.close();
    let error = joined(serving).unwrap_err();
    let truncated = matches!(
        &error,
        ServeError::Session(GuestConnectionError::Protocol(SessionError::Truncated { buffered }))
            if *buffered == ping.len() - 1
    );
    assert!(truncated, "{error:?}");
}

#[test]
fn the_guest_agent_fails_on_records_that_the_protocol_does_not_allow() {
    let ping = Message::Ping.encode().unwrap();
    let data = |identity, sequence| record(RecordType::Data, identity, sequence, &ping);
    let next_epoch = Identity { epoch: 2, ..FIRST };
    let other_instance = Identity {
        instance_id: [0x7e; 16],
        ..FIRST
    };
    let patched = |mut bytes: Vec<u8>, offset: usize, patch: &[u8]| {
        bytes[offset..offset + patch.len()].copy_from_slice(patch);
        bytes
    };
    // A RESET with a payload, an empty DATA record, and a GUEST_ATTACH with an identity, which
    // the record API cannot encode.
    let mut reset_with_payload = patched(
        record(RecordType::Reset, next_epoch, 1, &[]),
        LENGTH_OFFSET,
        &4u32.to_le_bytes(),
    );
    reset_with_payload.extend_from_slice(&[0; 4]);
    let mut empty_data = patched(data(FIRST, 1), LENGTH_OFFSET, &0u32.to_le_bytes());
    empty_data.truncate(empty_data.len() - ping.len());
    let attach_with_identity = patched(
        record(
            RecordType::GuestAttach,
            Identity {
                instance_id: [0; 16],
                epoch: 0,
            },
            0,
            &[],
        ),
        INSTANCE_OFFSET,
        &[1],
    );
    let error_record = |code: u32| {
        let payload = ErrorCode::Authentication.code().to_le_bytes();
        patched(
            record(RecordType::Error, FIRST, 1, &payload),
            LENGTH_OFFSET + 4,
            &code.to_le_bytes(),
        )
    };
    let wrong_magic = patched(data(FIRST, 1), 0, b"NVXT");
    let cases = [
        (
            "a skipped sequence number",
            data(FIRST, 2),
            SessionError::Sequence {
                expected: 1,
                actual: 2,
            },
        ),
        (
            "a repeated sequence number",
            data(FIRST, 0),
            SessionError::Sequence {
                expected: 1,
                actual: 0,
            },
        ),
        (
            "DATA of another epoch",
            data(next_epoch, 1),
            SessionError::Epoch {
                expected: 1,
                actual: 2,
            },
        ),
        (
            "DATA of another instance",
            data(other_instance, 1),
            SessionError::Instance {
                expected: FIRST.instance_id,
                actual: other_instance.instance_id,
            },
        ),
        (
            "a RESET that repeats the epoch",
            record(RecordType::Reset, FIRST, 1, &[]),
            SessionError::StaleEpoch {
                current: 1,
                actual: 1,
            },
        ),
        (
            "a RESET without an identity",
            record(
                RecordType::Reset,
                Identity {
                    instance_id: [0; 16],
                    epoch: 0,
                },
                1,
                &[],
            ),
            SessionError::MissingIdentity(RecordType::Reset),
        ),
        (
            "a RESET with a payload",
            reset_with_payload,
            SessionError::Record(RecordError::Length {
                record_type: RecordType::Reset,
                length: 4,
            }),
        ),
        (
            "an empty DATA record",
            empty_data,
            SessionError::Record(RecordError::Length {
                record_type: RecordType::Data,
                length: 0,
            }),
        ),
        (
            "a bootstrap record with an identity",
            attach_with_identity,
            SessionError::Record(RecordError::BootstrapIdentity(RecordType::GuestAttach)),
        ),
        (
            "an ERROR record with an unknown code",
            error_record(2),
            SessionError::Record(RecordError::ErrorCode(2)),
        ),
        (
            "an ERROR record",
            error_record(ErrorCode::Authentication.code()),
            SessionError::Unexpected(RecordType::Error),
        ),
        (
            "an ACK record",
            record(RecordType::Ack, FIRST, 1, &RECEIVE_WINDOW.to_le_bytes()),
            SessionError::Unexpected(RecordType::Ack),
        ),
        (
            "an unknown record type",
            patched(data(FIRST, 1), TYPE_OFFSET, &[0x7f]),
            SessionError::Record(RecordError::Type(0x7f)),
        ),
        (
            "nonzero flags",
            patched(data(FIRST, 1), FLAGS_OFFSET, &[1]),
            SessionError::Record(RecordError::Flags(1)),
        ),
        (
            "another protocol version",
            patched(data(FIRST, 1), VERSION_OFFSET, &2u16.to_le_bytes()),
            SessionError::Record(RecordError::Version(2)),
        ),
        (
            "a wrong magic",
            wrong_magic,
            SessionError::Record(RecordError::Magic(*b"NVXT")),
        ),
    ];
    for (name, bytes, expected) in cases {
        let error = refused(&bytes);
        let failed = matches!(
            &error,
            ServeError::Session(GuestConnectionError::Protocol(error)) if *error == expected
        );
        assert!(failed, "{name}: {error:?}");
    }
}

#[test]
fn the_guest_agent_refuses_messages_that_its_framing_does_not_allow() {
    // A message is refused at its header, before its body arrives: the decoder never buffers a
    // body beyond the limit.
    let too_long = u32::try_from(MAX_BODY + 1).unwrap().to_le_bytes();
    let header = |length: [u8; 4], kind: u8| {
        let mut header = length.to_vec();
        header.push(kind);
        header
    };
    let cases = [
        (header([0; 4], 0), FrameError::Kind(0)),
        (header([0; 4], 9), FrameError::Kind(9)),
        (
            header(too_long, 3),
            FrameError::Length {
                kind: 3,
                length: MAX_BODY + 1,
            },
        ),
        (
            header(1u32.to_le_bytes(), 1),
            FrameError::Length { kind: 1, length: 1 },
        ),
    ];
    for (message, expected) in cases {
        let error = refused(&record(RecordType::Data, FIRST, 1, &message));
        let failed = matches!(&error, ServeError::Frame(error) if *error == expected);
        assert!(failed, "{message:?}: {error:?}");
    }

    // The guest agent answers requests, and refuses the messages that only it sends.
    for message in [Message::Pong, Message::Stopped] {
        let bytes = record(RecordType::Data, FIRST, 1, &message.encode().unwrap());
        let error = refused(&bytes);
        let failed = matches!(&error, ServeError::Unexpected(kind) if *kind == message.kind());
        assert!(failed, "{message:?}: {error:?}");
    }
}

/// Starts the guest binary's `serve` with one end of a socket pair as its standard input and
/// output, and returns the broker on the other end with the process.
fn start_binary() -> (Broker, GuestProcess) {
    let (broker, guest) = UnixStream::pair().unwrap();
    let output = guest.try_clone().unwrap();
    let child = GuestProcess::spawn(
        Command::new(env!("CARGO_BIN_EXE_runtime-adapter-guest"))
            .arg(runtime_adapter::GUEST_SERVE_COMMAND)
            .stdin(Stdio::from(OwnedFd::from(guest)))
            .stdout(Stdio::from(OwnedFd::from(output)))
            .stderr(Stdio::piped()),
    );
    (Broker::new(broker), child)
}

/// A guest binary that a test started. Dropping it kills and reaps the process, so that a test
/// that fails while the process runs does not leave it running.
struct GuestProcess(Option<Child>);

impl GuestProcess {
    /// Starts the guest binary with `command`.
    fn spawn(command: &mut Command) -> Self {
        Self(Some(command.spawn().unwrap()))
    }

    /// Returns the guest binary's output once it exits. If it does not exit in time, kills and
    /// reaps it, and fails the test instead of hanging it.
    fn finished(mut self) -> Output {
        let deadline = Instant::now() + TIMEOUT;
        let child = self.0.as_mut().expect("the process was not reaped");
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = self.0.take().unwrap().wait_with_output().unwrap();
                panic!("the guest binary did not exit in time: {output:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for GuestProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn the_guest_binary_serves_the_session_on_its_standard_streams() {
    // The host stops the guest.
    let (mut broker, child) = start_binary();
    broker.attach(FIRST);
    let echo = Message::Echo(vec![0x42; OUTER_MAX_PAYLOAD]);
    let messages = [Message::Ping, echo.clone(), Message::Stop];
    let replies = broker.exchange(&messages, OUTER_MAX_PAYLOAD, 3);
    assert_eq!(replies, [Message::Pong, echo, Message::Stopped]);
    let output = child.finished();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    // The broker closes the stream at a record boundary.
    let (mut broker, child) = start_binary();
    broker.attach(FIRST);
    broker.close();
    let output = child.finished();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    // The host sends a malformed message.
    let (mut broker, child) = start_binary();
    broker.attach(FIRST);
    broker.send_data(&[0, 0, 0, 0, 9], OUTER_MAX_PAYLOAD);
    let output = child.finished();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        diagnostic,
        "runtime-adapter-guest: unknown message kind 9\n"
    );
}

/// A pseudo-terminal whose tty the guest agent serves, opening it by its path, and whose master
/// end a relay joins to a socket pair, on whose other end the broker plays its end of the session,
/// as for the other tests.
struct Terminal {
    /// The path of the tty.
    path: PathBuf,
    /// The test's own descriptor of the tty. Reads of the master end fail once no descriptor of
    /// the tty is open, so it keeps the relay up until the guest agent opens the tty.
    _tty: OwnedFd,
}

/// Opens a pseudo-terminal, and returns it with the broker at the other end of its relay.
///
/// Its descriptors are closed on exec, so that no process that a test starts holds its master
/// end, which would keep the tty from hanging up once the test ends.
fn terminal() -> (Broker, Terminal) {
    let master = pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
    pty::grantpt(&master).unwrap();
    pty::unlockpt(&master).unwrap();
    let path = PathBuf::from(pty::ptsname_r(&master).unwrap());
    // The standard library opens files, and duplicates descriptors, close-on-exec.
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OFlag::O_NOCTTY.bits())
        .open(&path)
        .unwrap();
    let (broker, relay) = UnixStream::pair().unwrap();
    let (mut from_broker, mut to_broker) = (relay.try_clone().unwrap(), relay);
    let master = File::from(OwnedFd::from(master));
    let (mut to_guest, mut from_guest) = (master.try_clone().unwrap(), master);
    thread::spawn(move || io::copy(&mut from_broker, &mut to_guest));
    thread::spawn(move || {
        let _ = io::copy(&mut from_guest, &mut to_broker);
        let _ = to_broker.shutdown(Shutdown::Write);
    });
    let terminal = Terminal {
        path,
        _tty: OwnedFd::from(tty),
    };
    (Broker::new(broker), terminal)
}

#[test]
fn the_guest_agent_serves_a_tty_in_raw_mode() {
    let (mut broker, terminal) = terminal();
    let path = terminal.path.clone();
    let serving = thread::spawn(move || guest::serve_terminal(&path));
    broker.attach(FIRST);
    // Every byte value, which a tty that was not in raw mode would translate or act on: carriage
    // returns and newlines, and the characters of signals, flow control, line editing, and the end
    // of a file. The confirmation of the stop reaches the broker before serving returns.
    let replies = broker.exchange(&[longest(), Message::Stop], OUTER_MAX_PAYLOAD, 2);
    assert_eq!(replies, [longest(), Message::Stopped]);
    assert_eq!(joined(serving).unwrap(), Served::Stopped);
}

#[test]
fn the_guest_binary_serves_a_tty_in_place_of_the_managed_agent() {
    // Unless it is PID 1, `init` exits with the status with which PID 1 would end the VM.
    let (mut broker, terminal) = terminal();
    let child = GuestProcess::spawn(
        Command::new(env!("CARGO_BIN_EXE_runtime-adapter-guest"))
            .arg(runtime_adapter::GUEST_INIT_COMMAND)
            .arg(&terminal.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    broker.attach(FIRST);
    let replies = broker.exchange(&[Message::Ping, Message::Stop], OUTER_MAX_PAYLOAD, 2);
    assert_eq!(replies, [Message::Pong, Message::Stopped]);
    let output = child.finished();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    // A path that is no tty fails at once: one that cannot be opened, and one that has no
    // terminal settings.
    for (path, diagnostic, error) in [
        ("/", "cannot open /", 21),
        ("/dev/null", "cannot put /dev/null in raw mode", 25),
    ] {
        let child = GuestProcess::spawn(
            Command::new(env!("CARGO_BIN_EXE_runtime-adapter-guest"))
                .args([runtime_adapter::GUEST_INIT_COMMAND, path])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
        let output = child.finished();
        assert_eq!(output.status.code(), Some(1), "{path}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.starts_with(&format!("runtime-adapter-guest: {diagnostic}: "))
                && stderr.ends_with(&format!(" (os error {error})\n")),
            "{path}: {stderr}"
        );
    }
}
