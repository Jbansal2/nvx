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
//!
//! The worker of a layered root runs its session with fake root operations, which record the
//! worker's calls and fail as a test asks: the tests cover the order of its stages, each stage
//! that fails, the requests that it serves once the root is ready, its stop, and the messages that
//! it refuses. The binary's PID 1 of a layered root, and its worker, run on a pseudo-terminal too,
//! on the test's host, whose kernel command line names no layered root.
#![cfg(all(feature = "guest", target_os = "linux"))]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::pty;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{self, Id, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nvx::guest::nvxs::GuestConnectionError;
use nvx::protocol::OUTER_MAX_PAYLOAD;
use nvx::protocol::nvxs::{
    ErrorCode, Identity, Record, RecordError, RecordParser, RecordType, SessionError, encode_record,
};
use nvx::protocol::root::{RootImage, RootLayout, RootUpper};
use nvx::uuid::Uuid;
use runtime_adapter::frame::{Decoder, FrameError, HEADER_LEN, MAX_BODY, Message};
use runtime_adapter::guest::{self, NO_ROOT, RECEIVE_WINDOW, ServeError, Served};
use runtime_adapter::probe::{Facts, Probe};
use runtime_adapter::root::{RootConfig, RootFailure, RootStage};
use runtime_adapter::worker::{self, RootOperations, Worked};

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

/// Returns what `thread` returned, and fails the test if it does not end in time, so that a guest
/// that keeps serving fails the test instead of hanging it.
fn joined<T>(thread: JoinHandle<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    while !thread.is_finished() {
        assert!(Instant::now() < deadline, "the guest agent ends in time");
        thread::sleep(Duration::from_millis(10));
    }
    thread.join().unwrap()
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
        (header([0; 4], 12), FrameError::Kind(12)),
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

    // The guest agent answers requests, and refuses the messages that only it sends, and the
    // configuration of a layered root, which its VM does not have.
    let refused_messages = [
        Message::Pong,
        Message::Stopped,
        Message::RootReady,
        Message::RootFailed(vec![1]),
        Message::Report(Vec::new()),
        Message::ProbeFailed(Vec::new()),
        Message::RootConfig(RootConfig::default().encode()),
    ];
    for message in refused_messages {
        let bytes = record(RecordType::Data, FIRST, 1, &message.encode().unwrap());
        let error = refused(&bytes);
        let failed = matches!(&error, ServeError::Unexpected(kind) if *kind == message.kind());
        assert!(failed, "{message:?}: {error:?}");
    }
}

#[test]
fn the_guest_agent_of_a_vm_without_a_layered_root_answers_probes_with_a_failure() {
    let (mut broker, serving) = start();
    broker.attach(FIRST);
    let messages = [
        Message::Probe(b"mounts".to_vec()),
        Message::Ping,
        Message::Stop,
    ];
    let replies = broker.exchange(&messages, OUTER_MAX_PAYLOAD, 3);
    let expected = [
        Message::ProbeFailed(NO_ROOT.as_bytes().to_vec()),
        Message::Pong,
        Message::Stopped,
    ];
    assert_eq!(replies, expected);
    assert_eq!(joined(serving).unwrap(), Served::Stopped);
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

/// A guest binary that a test started, in a process group of its own, which also holds the
/// processes that the binary starts, such as those of PID 1 of a layered root. The binary's status
/// is collected only once its group has been killed: until then, the binary keeps its process ID,
/// even after it exits, and the group keeps that ID, which no other process can take. Dropping it
/// kills the group and reaps the binary, so that a test that fails while they run leaves none of
/// them running, even if the binary exited first.
struct GuestProcess(Option<Child>);

/// How a guest binary that a test started failed to finish, with what it wrote. Either way, its
/// process group was killed, and its status collected.
#[derive(Debug)]
enum Unfinished {
    /// The binary did not exit in time.
    Late(Output),
    /// The binary exited, but left these processes of its group running.
    Orphans(Output, Vec<u32>),
}

impl GuestProcess {
    /// Starts the guest binary with `command`, in a process group of its own.
    fn spawn(command: &mut Command) -> Self {
        Self(Some(command.process_group(0).spawn().unwrap()))
    }

    /// Returns the guest binary's process ID, which is the ID of its process group.
    fn id(&self) -> u32 {
        self.0.as_ref().expect("the process was not reaped").id()
    }

    /// Returns whether the guest binary has exited, without collecting its status.
    fn exited(&self) -> bool {
        let pid = Pid::from_raw(i32::try_from(self.id()).unwrap());
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
        !matches!(
            wait::waitid(Id::Pid(pid), flags).unwrap(),
            WaitStatus::StillAlive
        )
    }

    /// Returns the guest binary's output once it exits, and every process that it started with
    /// it. Otherwise kills its process group, and fails the test instead of hanging it.
    fn finished(self) -> Output {
        self.finished_within(TIMEOUT)
            .unwrap_or_else(|unfinished| panic!("the guest binary did not finish: {unfinished:?}"))
    }

    /// Returns the guest binary's output once it exits within `timeout`, and no other process of
    /// its group outlives it. Otherwise kills its process group, whose processes may all hold the
    /// binary's output open, and fails with what the binary wrote.
    fn finished_within(mut self, timeout: Duration) -> Result<Output, Unfinished> {
        let deadline = Instant::now() + timeout;
        while !self.exited() {
            if Instant::now() >= deadline {
                self.kill();
                return Err(Unfinished::Late(self.reaped()));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let orphans = running_in_group(self.id());
        self.kill();
        let output = self.reaped();
        if orphans.is_empty() {
            Ok(output)
        } else {
            Err(Unfinished::Orphans(output, orphans))
        }
    }

    /// Kills the guest binary's process group, which is still the binary's, because its status
    /// has not been collected.
    fn kill(&self) {
        let group = Pid::from_raw(i32::try_from(self.id()).unwrap());
        let _ = signal::killpg(group, Signal::SIGKILL);
    }

    /// Collects the guest binary's status, and its output, which ends once every process that
    /// holds it has ended.
    fn reaped(&mut self) -> Output {
        let child = self.0.take().expect("the process was not reaped");
        child.wait_with_output().unwrap()
    }
}

impl Drop for GuestProcess {
    fn drop(&mut self) {
        if self.0.is_some() {
            self.kill();
            let _ = self.0.take().unwrap().wait();
        }
    }
}

/// Returns the processes of the process group `group` that have not exited: all but zombies.
fn running_in_group(group: u32) -> Vec<u32> {
    let group = group.to_string();
    let mut running = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        // A process may end while the scan reads it.
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // The fields after the command's name, which may hold spaces and parentheses, start
        // after its last `)`: the state, the parent's process ID, then the process group.
        let Some((_, fields)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = fields.split_whitespace();
        let state = fields.next();
        if fields.nth(1) == Some(group.as_str()) && !matches!(state, Some("Z" | "X")) {
            running.push(pid);
        }
    }
    running
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
    broker.send_data(&[0, 0, 0, 0, 12], OUTER_MAX_PAYLOAD);
    let output = child.finished();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        diagnostic,
        "runtime-adapter-guest: unknown message kind 12\n"
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

/// An operation of a layered root, which a [`FakeRoot`] fails when a test asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    /// Reading the kernel command line.
    CommandLine,
    /// The bootstrap.
    Bootstrap,
    /// The assembly.
    Assemble,
    /// A probe.
    Probe,
    /// The teardown.
    Teardown,
}

/// A call of a [`FakeRoot`]'s operations, with what the worker passed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    /// The kernel command line was read.
    CommandLine,
    /// The bootstrap ran with the configuration.
    Bootstrap(RootConfig),
    /// The assembly ran with the configuration and the layout.
    Assemble(RootConfig, RootLayout),
    /// The probe ran.
    Probe(Probe),
    /// The teardown ran.
    Teardown,
}

/// Root operations that record the worker's calls, and fail as a test asks.
#[derive(Debug)]
struct FakeRoot {
    /// The kernel command line that the operations read.
    command_line: Vec<u8>,
    /// The operation that fails, and its problem, if any.
    failing: Option<(Operation, &'static str)>,
    /// The worker's calls, in order.
    calls: Vec<Call>,
}

impl FakeRoot {
    /// Returns operations whose kernel command line names `layout`.
    fn booting(layout: &RootLayout) -> Self {
        let command_line = format!("console=hvc0 nvx_sandbox=1 {}", layout.tokens().join(" "));
        Self::reading(command_line.as_bytes())
    }

    /// Returns operations whose kernel command line is `command_line`.
    fn reading(command_line: &[u8]) -> Self {
        Self {
            command_line: command_line.to_vec(),
            failing: None,
            calls: Vec::new(),
        }
    }

    /// Returns operations of the layout that the worker assembles, whose `operation` fails with
    /// `problem`.
    fn failing(operation: Operation, problem: &'static str) -> Self {
        Self {
            failing: Some((operation, problem)),
            ..Self::booting(&layout())
        }
    }

    /// Fails if `operation` fails.
    fn result(&self, operation: Operation) -> Result<(), String> {
        match self.failing {
            Some((failing, problem)) if failing == operation => Err(problem.to_owned()),
            _ => Ok(()),
        }
    }
}

impl RootOperations for FakeRoot {
    fn command_line(&mut self) -> Result<Vec<u8>, String> {
        self.calls.push(Call::CommandLine);
        self.result(Operation::CommandLine)?;
        Ok(self.command_line.clone())
    }

    fn bootstrap(&mut self, config: &RootConfig) -> Result<(), String> {
        self.calls.push(Call::Bootstrap(config.clone()));
        self.result(Operation::Bootstrap)
    }

    fn assemble(&mut self, config: &RootConfig, layout: &RootLayout) -> Result<(), String> {
        self.calls.push(Call::Assemble(config.clone(), *layout));
        self.result(Operation::Assemble)
    }

    fn probe(&mut self, probe: &Probe) -> Result<Facts, String> {
        self.calls.push(Call::Probe(probe.clone()));
        self.result(Operation::Probe)?;
        Ok(found(probe))
    }

    fn teardown(&mut self) -> Result<(), String> {
        self.calls.push(Call::Teardown);
        self.result(Operation::Teardown)
    }
}

/// Returns the facts that a [`FakeRoot`] finds with `probe`.
fn found(probe: &Probe) -> Facts {
    let mut facts = Facts::new();
    facts.push("name", probe.name());
    facts.push("arguments", probe.arguments().join(" "));
    facts
}

/// Returns the layout that the worker assembles: an EROFS image, with the identity that the guest
/// expects of it, over an ext4 scratch.
fn layout() -> RootLayout {
    RootLayout {
        image: RootImage::erofs(Uuid::parse("0a490905-41be-ed5f-984e-63eb7e5e20b1")),
        upper: RootUpper::Scratch,
    }
}

/// The thread of a worker's session, which returns its root operations, with how the session
/// ended.
type Working = JoinHandle<(FakeRoot, Result<Worked, ServeError>)>;

/// Starts the worker's session in a thread, with the root operations `root`, on one end of a
/// socket pair, and returns the broker on the other end with the thread.
fn start_worker(root: FakeRoot) -> (Broker, Working) {
    let (broker, guest) = UnixStream::pair().unwrap();
    let working = thread::spawn(move || {
        let mut root = root;
        let worked = worker::work(guest, &mut root);
        (root, worked)
    });
    (Broker::new(broker), working)
}

/// Returns the default root configuration's message.
fn configuration() -> Message {
    Message::RootConfig(RootConfig::default().encode())
}

/// Returns the probe that `text` names.
fn probe(text: &str) -> Probe {
    Probe::parse(text).unwrap()
}

#[test]
fn the_worker_assembles_the_root_serves_it_and_tears_it_down_on_stop() {
    let (mut broker, working) = start_worker(FakeRoot::booting(&layout()));
    broker.attach(FIRST);
    let replies = broker.exchange(&[configuration()], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::RootReady]);

    // It serves pings, echoes, and probes, in records of several sizes.
    let messages = [Message::Ping, longest(), Message::Probe(b"mounts".to_vec())];
    let expected = [
        Message::Pong,
        longest(),
        Message::Report(found(&probe("mounts")).encode()),
    ];
    for size in [7, OUTER_MAX_PAYLOAD] {
        let replies = broker.exchange(&messages, size, expected.len());
        assert_eq!(replies, expected, "records of {size} bytes");
    }

    // Its root outlives a reset of the session, as when the host reattaches. A probe that the
    // framing of probes refuses, or that fails, is answered with its problem.
    broker.settle();
    broker.reset(Identity { epoch: 2, ..FIRST });
    let messages = [
        Message::Probe(b"hold /run".to_vec()),
        Message::Probe(b"Mounts".to_vec()),
    ];
    let replies = broker.exchange(&messages, OUTER_MAX_PAYLOAD, 2);
    assert_eq!(
        replies[0],
        Message::Report(found(&probe("hold /run")).encode())
    );
    let Message::ProbeFailed(problem) = &replies[1] else {
        panic!("{replies:?}");
    };
    let problem = String::from_utf8_lossy(problem);
    assert!(problem.contains("the probe's name \"Mounts\""), "{problem}");

    let replies = broker.exchange(&[Message::Stop], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::Stopped]);
    let (root, worked) = joined(working);
    let worked = worked.unwrap();
    assert_eq!((&worked, worked.status()), (&Worked::Stopped, 0));
    assert!(broker.read().is_none(), "the worker ended its stream");
    let config = RootConfig::default();
    let mut expected = vec![
        Call::CommandLine,
        Call::Bootstrap(config.clone()),
        Call::Assemble(config, layout()),
    ];
    expected.extend([probe("mounts"), probe("mounts"), probe("hold /run")].map(Call::Probe));
    expected.push(Call::Teardown);
    assert_eq!(root.calls, expected);
}

#[test]
fn the_worker_reports_the_stage_that_failed_and_ends_with_its_status() {
    let config = RootConfig::default();
    let read = || vec![Call::CommandLine];
    let bootstrapped = || vec![Call::CommandLine, Call::Bootstrap(config.clone())];
    let gpt = RootLayout {
        image: RootImage::gpt(None),
        upper: RootUpper::Scratch,
    };
    let ram = RootLayout {
        upper: RootUpper::Ram,
        ..layout()
    };
    let cases = [
        (
            "a configuration of another version",
            FakeRoot::booting(&layout()),
            b"version=2\n".to_vec(),
            RootStage::Configuration,
            "the root configuration has version \"2\"",
            Vec::new(),
        ),
        (
            "a relative runtime directory",
            FakeRoot::booting(&layout()),
            RootConfig {
                runtime: "run/relative".to_owned(),
                ..RootConfig::default()
            }
            .encode(),
            RootStage::Configuration,
            "names the runtime \"run/relative\", which is not absolute",
            Vec::new(),
        ),
        (
            "a kernel command line that cannot be read",
            FakeRoot::failing(Operation::CommandLine, "cannot read /proc/cmdline"),
            config.encode(),
            RootStage::Layout,
            "cannot read /proc/cmdline",
            read(),
        ),
        (
            "no layered root",
            FakeRoot::reading(b"console=hvc0 quiet"),
            config.encode(),
            RootStage::Layout,
            "the kernel command line names no layered root",
            read(),
        ),
        (
            "invalid boot tokens",
            FakeRoot::reading(b"nvx_layer=distro,0xd0003000,erofs"),
            config.encode(),
            RootStage::Layout,
            "the kernel command line has invalid boot tokens: ",
            read(),
        ),
        (
            "a GPT image",
            FakeRoot::booting(&gpt),
            config.encode(),
            RootStage::Layout,
            "assembles only an EROFS image over an ext4 scratch, not gpt over scratch",
            read(),
        ),
        (
            "a RAM upper",
            FakeRoot::booting(&ram),
            config.encode(),
            RootStage::Layout,
            "not erofs over ram",
            read(),
        ),
        (
            "a bootstrap that failed",
            FakeRoot::failing(Operation::Bootstrap, "failed to create the agent's cgroup"),
            config.encode(),
            RootStage::Bootstrap,
            "failed to create the agent's cgroup",
            bootstrapped(),
        ),
        (
            "an assembly that failed",
            FakeRoot::failing(Operation::Assemble, "the distro layer's UUID is wrong"),
            config.encode(),
            RootStage::Assembly,
            "the distro layer's UUID is wrong",
            [
                bootstrapped(),
                vec![Call::Assemble(config.clone(), layout())],
            ]
            .concat(),
        ),
    ];
    for (name, root, body, stage, problem, calls) in cases {
        let (mut broker, working) = start_worker(root);
        broker.attach(FIRST);
        let replies = broker.exchange(&[Message::RootConfig(body)], OUTER_MAX_PAYLOAD, 1);
        let [Message::RootFailed(reported)] = replies.as_slice() else {
            panic!("{name}: {replies:?}");
        };
        let reported = RootFailure::decode(reported).unwrap();
        assert_eq!(reported.stage(), stage, "{name}: {reported}");
        assert!(reported.problem().contains(problem), "{name}: {reported}");
        // It ends its stream after the failure.
        assert!(broker.read().is_none(), "{name}");
        let (root, worked) = joined(working);
        let worked = worked.unwrap();
        assert_eq!(worked, Worked::Failed(reported), "{name}");
        assert_eq!(worked.status(), stage.exit_status(), "{name}");
        assert_eq!(root.calls, calls, "{name}");
    }
}

#[test]
fn the_worker_reports_a_teardown_that_failed_before_it_confirms_the_stop() {
    let problem = "failed to unmount the overlay: Device or resource busy (os error 16)";
    let (mut broker, working) = start_worker(FakeRoot::failing(Operation::Teardown, problem));
    broker.attach(FIRST);
    let replies = broker.exchange(&[configuration(), Message::Stop], OUTER_MAX_PAYLOAD, 3);
    let failure = RootFailure::new(RootStage::Teardown, problem);
    let expected = [
        Message::RootReady,
        Message::RootFailed(failure.encode()),
        Message::Stopped,
    ];
    assert_eq!(replies, expected);
    let (root, worked) = joined(working);
    let worked = worked.unwrap();
    assert_eq!(worked, Worked::Failed(failure));
    assert_eq!(worked.status(), 15);
    assert_eq!(root.calls.last(), Some(&Call::Teardown));
}

#[test]
fn the_worker_accepts_only_its_configuration_or_a_stop_before_its_root() {
    // A stop ends the worker without a root.
    let (mut broker, working) = start_worker(FakeRoot::booting(&layout()));
    broker.attach(FIRST);
    let replies = broker.exchange(&[Message::Stop], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::Stopped]);
    let (root, worked) = joined(working);
    assert_eq!(worked.unwrap(), Worked::Stopped);
    assert_eq!(root.calls, []);

    // Any other message ends it with an error, as do the messages that only the guest sends.
    let refused = [
        Message::Ping,
        Message::Echo(b"early".to_vec()),
        Message::Probe(b"mounts".to_vec()),
        Message::Pong,
        Message::RootReady,
        Message::Report(Vec::new()),
    ];
    for message in refused {
        let (mut broker, working) = start_worker(FakeRoot::booting(&layout()));
        broker.attach(FIRST);
        broker.send_data(&message.encode().unwrap(), OUTER_MAX_PAYLOAD);
        let (root, worked) = joined(working);
        let failed =
            matches!(&worked, Err(ServeError::Unexpected(kind)) if *kind == message.kind());
        assert!(failed, "{message:?}: {worked:?}");
        assert_eq!(root.calls, [], "{message:?}");
    }

    // Once the root is ready, a second configuration ends it with an error too, and the worker
    // leaves the root that it assembled to its operations.
    let (mut broker, working) = start_worker(FakeRoot::booting(&layout()));
    broker.attach(FIRST);
    let replies = broker.exchange(&[configuration()], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::RootReady]);
    broker.send_data(&configuration().encode().unwrap(), OUTER_MAX_PAYLOAD);
    let (root, worked) = joined(working);
    let failed = matches!(&worked, Err(ServeError::Unexpected(6)));
    assert!(failed, "{worked:?}");
    assert!(!root.calls.contains(&Call::Teardown), "{:?}", root.calls);

    // So does a broker that closes the stream.
    let (mut broker, working) = start_worker(FakeRoot::booting(&layout()));
    broker.attach(FIRST);
    let replies = broker.exchange(&[configuration()], OUTER_MAX_PAYLOAD, 1);
    assert_eq!(replies, [Message::RootReady]);
    broker.close();
    let (root, worked) = joined(working);
    let worked = worked.unwrap();
    assert_eq!((&worked, worked.status()), (&Worked::Closed, 1));
    assert!(!root.calls.contains(&Call::Teardown), "{:?}", root.calls);
}

/// Starts the guest binary with `arguments`, its standard input closed and its output piped.
fn spawn_binary(arguments: &[&std::ffi::OsStr]) -> GuestProcess {
    GuestProcess::spawn(
        Command::new(env!("CARGO_BIN_EXE_runtime-adapter-guest"))
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
}

#[test]
fn the_guest_binary_runs_pid_1_and_the_worker_of_a_layered_root() {
    use std::ffi::OsStr;

    let init = OsStr::new(runtime_adapter::GUEST_INIT_COMMAND);
    let layered = OsStr::new(runtime_adapter::GUEST_LAYERED_MODE);
    let worker = OsStr::new(runtime_adapter::GUEST_WORKER_COMMAND);

    // PID 1 starts the worker on the tty, which reports that the test's host boots no layered
    // root. Unless it is PID 1, PID 1 then ends its unrelated child, and exits with the worker's
    // status, with which PID 1 would end the VM.
    let (mut broker, pty) = terminal();
    let child = spawn_binary(&[init, pty.path.as_os_str(), layered]);
    broker.attach(FIRST);
    let replies = broker.exchange(&[configuration()], OUTER_MAX_PAYLOAD, 1);
    let [Message::RootFailed(reported)] = replies.as_slice() else {
        panic!("{replies:?}");
    };
    let reported = RootFailure::decode(reported).unwrap();
    assert_eq!(reported.stage(), RootStage::Layout, "{reported}");
    let output = child.finished();
    assert_eq!(output.status.code(), Some(12), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("runtime-adapter-guest: {reported}\n")
    );

    // The worker alone, with and without the unrelated child's process ID, stops before it
    // configures a root.
    for sibling in [None, Some(OsStr::new("1"))] {
        let (mut broker, pty) = terminal();
        let mut arguments = vec![worker, pty.path.as_os_str()];
        arguments.extend(sibling);
        let child = spawn_binary(&arguments);
        broker.attach(FIRST);
        let replies = broker.exchange(&[Message::Stop], OUTER_MAX_PAYLOAD, 1);
        assert_eq!(replies, [Message::Stopped]);
        let output = child.finished();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    // A worker that cannot open its tty fails at once, and PID 1 exits with its status.
    for arguments in [
        [init, OsStr::new("/"), layered],
        [worker, OsStr::new("/"), OsStr::new("7")],
    ] {
        let output = spawn_binary(&arguments).finished();
        assert_eq!(output.status.code(), Some(1), "{arguments:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.starts_with("runtime-adapter-guest: cannot open /: "),
            "{arguments:?}: {stderr}"
        );
    }

    // The unrelated child sleeps until a signal ends it.
    let idle = spawn_binary(&[OsStr::new(runtime_adapter::GUEST_IDLE_COMMAND)]);
    thread::sleep(Duration::from_millis(200));
    assert!(!idle.exited());
    drop(idle);

    // Anything else is a usage error.
    let usage: [&[&str]; 5] = [
        &["init", "/dev/null", "blockless"],
        &["worker"],
        &["worker", "/dev/null", "sibling"],
        &["worker", "/dev/null", "1", "2"],
        &["idle", "now"],
    ];
    for arguments in usage {
        let arguments = arguments.iter().map(OsStr::new).collect::<Vec<_>>();
        let output = spawn_binary(&arguments).finished();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
    }
}

/// Starts PID 1 of a layered root on the tty of `pty`, and waits until its unrelated child and
/// its worker, which waits for the broker, run too, all of them with the binary's output. Returns
/// the binary, and the processes of its group.
fn layered_pid_1(pty: &Terminal) -> (GuestProcess, Vec<u32>) {
    use std::ffi::OsStr;

    let child = spawn_binary(&[
        OsStr::new(runtime_adapter::GUEST_INIT_COMMAND),
        pty.path.as_os_str(),
        OsStr::new(runtime_adapter::GUEST_LAYERED_MODE),
    ]);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let running = running_in_group(child.id());
        if running.len() == 3 {
            return (child, running);
        }
        assert!(
            Instant::now() < deadline,
            "PID 1 did not start its children: {running:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Ends PID 1 of a layered root, which `layered_pid_1` started, before its children, as a crash
/// would, and waits until it exited.
fn crash(pid_1: &GuestProcess) {
    signal::kill(
        Pid::from_raw(i32::try_from(pid_1.id()).unwrap()),
        Signal::SIGKILL,
    )
    .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    while !pid_1.exited() {
        assert!(Instant::now() < deadline, "PID 1 did not end");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Waits until no process of the process group `group` runs.
fn ended(group: u32) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let running = running_in_group(group);
        if running.is_empty() {
            return;
        }
        assert!(Instant::now() < deadline, "{running:?} still run");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_test_that_gives_up_on_pid_1_ends_every_process_that_it_started() {
    // Giving up kills the whole group, so that the output, which every process of the group
    // holds, ends, and none of the processes runs on.
    let (_broker, pty) = terminal();
    let (child, _) = layered_pid_1(&pty);
    let group = child.id();
    let unfinished = child.finished_within(Duration::from_millis(100));
    let Err(Unfinished::Late(output)) = unfinished else {
        panic!("{unfinished:?}");
    };
    assert_eq!(
        output.status.signal(),
        Some(Signal::SIGKILL as i32),
        "{output:?}"
    );
    ended(group);
}

#[test]
fn a_test_ends_every_process_that_outlives_pid_1() {
    // PID 1 ends before its children, which hold its output. The test fails, and kills them,
    // rather than wait for the output to end.
    let (_broker, pty) = terminal();
    let (child, mut children) = layered_pid_1(&pty);
    let group = child.id();
    crash(&child);
    let unfinished = child.finished_within(TIMEOUT);
    let Err(Unfinished::Orphans(output, mut orphans)) = unfinished else {
        panic!("{unfinished:?}");
    };
    assert_eq!(
        output.status.signal(),
        Some(Signal::SIGKILL as i32),
        "{output:?}"
    );
    children.retain(|&pid| pid != group);
    children.sort_unstable();
    orphans.sort_unstable();
    assert_eq!(orphans, children);
    ended(group);

    // A test that fails once PID 1 ended kills them too.
    let (_broker, pty) = terminal();
    let (child, _) = layered_pid_1(&pty);
    let group = child.id();
    crash(&child);
    drop(child);
    ended(group);
}
