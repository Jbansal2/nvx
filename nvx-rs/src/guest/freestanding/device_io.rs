//! `nvx-device-io`: the benchmark helper that measures a guest's block and network devices.
//!
//! - `nvx-device-io file PATH read|write DURATION_MS SIZE_BYTES direct|buffered
//!   create|existing` reads or writes 4096-byte blocks at pseudo-random offsets of PATH, a file
//!   of SIZE_BYTES, for DURATION_MS milliseconds. `direct` opens it with `O_DIRECT`, and `create`
//!   creates it and sets its size.
//! - `nvx-device-io network IPV4 PORT DURATION_MS` sends 64-byte UDP datagrams to a peer that
//!   echoes them, for DURATION_MS milliseconds, and counts the echoes that arrive within 100 ms.
//!
//! It prints one JSON line, such as
//! `{"device":"file","operation":"read","operations":N,"bytes_per_operation":4096,"elapsed_ns":T}`,
//! and exits with 2 for a usage error, 3 when it cannot open the file or socket or read the
//! clock, 4 when a transfer fails, and 255 when it cannot print the line.

use super::args::{Arg, Args};

/// The size of a file benchmark's transfers, and the alignment of the I/O buffer.
pub(crate) const BLOCK_SIZE: usize = 4096;
/// The size of the result line's buffer, which truncates longer lines.
pub(crate) const OUTPUT_SIZE: usize = 384;
/// The size of a network benchmark's datagrams.
pub(crate) const PAYLOAD_SIZE: usize = 64;

const LCG_SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
const LCG_INCREMENT: u64 = 1_442_695_040_888_963_407;

/// The I/O buffer: one block, page-aligned for `O_DIRECT`.
#[repr(C, align(4096))]
pub(crate) struct IoBuffer(pub(crate) [u8; BLOCK_SIZE]);

impl IoBuffer {
    /// Returns a zeroed buffer.
    pub(crate) const fn new() -> Self {
        Self([0; BLOCK_SIZE])
    }
}

/// The result line, built in a fixed buffer with the interface's truncation behavior.
pub(crate) struct Output {
    bytes: [u8; OUTPUT_SIZE],
    length: usize,
}

impl Output {
    /// Returns an empty line.
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; OUTPUT_SIZE],
            length: 0,
        }
    }

    /// Builds the result line, and returns it.
    pub(crate) fn result(
        &mut self,
        device: &[u8],
        operation: &[u8],
        operations: u64,
        bytes_per_operation: u64,
        elapsed_ns: u64,
    ) -> &[u8] {
        self.length = 0;
        self.append_text(br#"{"device":""#);
        self.append_text(device);
        self.append_text(br#"","operation":""#);
        self.append_text(operation);
        self.append_text(br#"","operations":"#);
        self.append_u64(operations);
        self.append_text(br#","bytes_per_operation":"#);
        self.append_u64(bytes_per_operation);
        self.append_text(br#","elapsed_ns":"#);
        self.append_u64(elapsed_ns);
        self.append_text(b"}\n");
        &self.bytes[..self.length]
    }

    fn append_text(&mut self, text: &[u8]) {
        for &byte in text {
            self.push(byte);
        }
    }

    /// Appends `value` in decimal, its most significant digits first while room remains.
    fn append_u64(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            self.push(digits[count]);
        }
    }

    fn push(&mut self, byte: u8) {
        if self.length < OUTPUT_SIZE {
            self.bytes[self.length] = byte;
            self.length += 1;
        }
    }
}

/// `file PATH read|write DURATION_MS SIZE_BYTES direct|buffered create|existing`.
pub(crate) struct FileBenchmark<'a> {
    /// The file.
    pub(crate) path: Arg<'a>,
    /// Whether it writes rather than reads.
    pub(crate) writing: bool,
    /// How long it runs.
    pub(crate) duration_ms: u64,
    /// The size of the file, at least one block.
    pub(crate) size_bytes: u64,
    /// Whether it opens the file with `O_DIRECT`.
    pub(crate) direct: bool,
    /// Whether it creates the file and sets its size.
    pub(crate) create: bool,
}

/// `network IPV4 PORT DURATION_MS`.
pub(crate) struct NetworkBenchmark {
    /// The peer's address, in network byte order.
    pub(crate) address: u32,
    /// The peer's port.
    pub(crate) port: u16,
    /// How long it runs.
    pub(crate) duration_ms: u64,
}

/// The benchmark that the command line selects.
pub(crate) enum Benchmark<'a> {
    /// A file benchmark.
    File(FileBenchmark<'a>),
    /// A network benchmark.
    Network(NetworkBenchmark),
}

/// Parses the command line, or returns `None` for a usage error.
pub(crate) fn parse(args: Args<'_>) -> Option<Benchmark<'_>> {
    let mode = args.get(1)?;
    if mode.equals(b"file") {
        let [_, _, path, operation, duration, size, access, creation] = args.exactly()?;
        let duration_ms = parse_decimal(duration)?;
        let size_bytes = parse_decimal(size)?;
        if duration_ms == 0 || size_bytes < BLOCK_SIZE as u64 {
            return None;
        }
        let writing = operation.equals(b"write");
        if !writing && !operation.equals(b"read") {
            return None;
        }
        let direct = access.equals(b"direct");
        let create = creation.equals(b"create");
        if (!direct && !access.equals(b"buffered")) || (!create && !creation.equals(b"existing")) {
            return None;
        }
        return Some(Benchmark::File(FileBenchmark {
            path,
            writing,
            duration_ms,
            size_bytes,
            direct,
            create,
        }));
    }
    if mode.equals(b"network") {
        let [_, _, address, port, duration] = args.exactly()?;
        let address = parse_ipv4(address)?;
        let port = parse_decimal(port).filter(|&port| port != 0 && port <= u64::from(u16::MAX))?;
        let duration_ms = parse_decimal(duration).filter(|&duration| duration != 0)?;
        return Some(Benchmark::Network(NetworkBenchmark {
            address,
            port: port as u16,
            duration_ms,
        }));
    }
    None
}

/// Parses a decimal number of at least one digit and wraps around on overflow.
pub(crate) fn parse_decimal(text: Arg<'_>) -> Option<u64> {
    let mut value = 0_u64;
    let mut digits = 0_usize;
    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.wrapping_mul(10).wrapping_add(u64::from(byte - b'0'));
        digits += 1;
    }
    (digits != 0).then_some(value)
}

/// Parses a dotted-quad IPv4 address into the network-order `s_addr` of a `sockaddr_in`: four
/// decimal parts from 0 to 255, each of at least one digit.
pub(crate) fn parse_ipv4(text: Arg<'_>) -> Option<u32> {
    let mut octets = [0_u32; 4];
    let mut index = 0;
    let mut digits = 0_usize;
    for byte in text.bytes() {
        match byte {
            b'.' => {
                if digits == 0 || index == 3 {
                    return None;
                }
                index += 1;
                digits = 0;
            }
            b'0'..=b'9' => {
                octets[index] = octets[index] * 10 + u32::from(byte - b'0');
                if octets[index] > 255 {
                    return None;
                }
                digits += 1;
            }
            _ => return None,
        }
    }
    if index != 3 || digits == 0 {
        return None;
    }
    Some(octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24))
}

/// The pseudo-random block offsets of a file benchmark: a 64-bit linear congruential generator
/// whose state, modulo the number of blocks, selects each block.
pub(crate) struct Offsets {
    state: u64,
    blocks: u64,
}

impl Offsets {
    /// Returns the offsets in a file of `blocks` blocks, at least one.
    pub(crate) fn new(blocks: u64) -> Self {
        Self {
            state: LCG_SEED,
            blocks,
        }
    }

    /// Returns the next offset.
    pub(crate) fn next_offset(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        (self.state % self.blocks) * BLOCK_SIZE as u64
    }
}

/// Fills `buffer` with the file benchmark's pattern: byte `i` is the low byte of `i * 31 + 17`.
pub(crate) fn fill_pattern(buffer: &mut [u8; BLOCK_SIZE]) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = (index * 31 + 17) as u8;
    }
}

/// Fills `payload` with the network benchmark's datagram: the bytes 1 to 64.
pub(crate) fn fill_payload(payload: &mut [u8; PAYLOAD_SIZE]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = index as u8 + 1;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
/// The benchmarks themselves, on raw system calls.
pub(crate) mod linux {
    use super::super::args::Args;
    use super::super::syscall::syscall;
    use super::{
        BLOCK_SIZE, Benchmark, FileBenchmark, IoBuffer, NetworkBenchmark, Offsets, Output,
        PAYLOAD_SIZE, fill_pattern, fill_payload, parse,
    };

    const SYS_READ: usize = 0;
    const SYS_WRITE: usize = 1;
    const SYS_CLOSE: usize = 3;
    const SYS_POLL: usize = 7;
    const SYS_PREAD64: usize = 17;
    const SYS_PWRITE64: usize = 18;
    const SYS_SOCKET: usize = 41;
    const SYS_CONNECT: usize = 42;
    const SYS_FSYNC: usize = 74;
    const SYS_FTRUNCATE: usize = 77;
    const SYS_CLOCK_GETTIME: usize = 228;
    const SYS_OPENAT: usize = 257;

    const AT_FDCWD: isize = -100;
    const O_RDONLY: usize = 0;
    const O_RDWR: usize = 2;
    const O_CREAT: usize = 0o100;
    const O_DIRECT: usize = 0o40000;
    const O_CLOEXEC: usize = 0o2000000;
    const AF_INET: u16 = 2;
    const SOCK_DGRAM: usize = 2;
    const SOCK_CLOEXEC: usize = 0o2000000;
    const POLLIN: i16 = 1;
    const CLOCK_MONOTONIC: usize = 1;
    const EINTR: isize = 4;
    /// How long a network benchmark waits for each echo.
    const POLL_TIMEOUT_MS: usize = 100;

    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        address: u32,
        padding: [u8; 8],
    }

    #[repr(C)]
    struct PollFd {
        descriptor: i32,
        events: i16,
        returned_events: i16,
    }

    /// Runs the benchmark that `args` select, and returns the exit status.
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the integration tests run the binary")
    )]
    pub(crate) fn run(args: Args<'_>, io: &mut IoBuffer, output: &mut Output) -> i32 {
        match parse(args) {
            None => 2,
            Some(Benchmark::File(benchmark)) => run_file(&benchmark, io, output),
            Some(Benchmark::Network(benchmark)) => run_network(&benchmark, io, output),
        }
    }

    fn run_file(benchmark: &FileBenchmark<'_>, io: &mut IoBuffer, output: &mut Output) -> i32 {
        let mut flags = if benchmark.writing { O_RDWR } else { O_RDONLY } | O_CLOEXEC;
        if benchmark.direct {
            flags |= O_DIRECT;
        }
        if benchmark.create {
            flags |= O_CREAT;
        }
        let path = benchmark.path.as_ptr() as usize;
        // SAFETY: openat reads the NUL-terminated path.
        let descriptor =
            unsafe { syscall(SYS_OPENAT, [AT_FDCWD as usize, path, flags, 0o600, 0, 0]) };
        if descriptor < 0 {
            return 3;
        }
        let descriptor = descriptor as usize;
        let size = benchmark.size_bytes as usize;
        // SAFETY: ftruncate takes a descriptor and a length.
        if benchmark.create && unsafe { syscall(SYS_FTRUNCATE, [descriptor, size, 0, 0, 0, 0]) } < 0
        {
            close(descriptor);
            return 3;
        }
        fill_pattern(&mut io.0);
        let mut offsets = Offsets::new(benchmark.size_bytes / BLOCK_SIZE as u64);
        let started = monotonic_ns();
        if started == 0 {
            close(descriptor);
            return 3;
        }
        let duration_ns = benchmark.duration_ms.wrapping_mul(1_000_000);
        let transfer = if benchmark.writing {
            SYS_PWRITE64
        } else {
            SYS_PREAD64
        };
        let mut ended = started;
        let mut operations = 0_u64;
        while ended.wrapping_sub(started) < duration_ns {
            let offset = offsets.next_offset() as usize;
            let buffer = io.0.as_mut_ptr() as usize;
            // SAFETY: pread64 fills, and pwrite64 reads, at most one block of the buffer.
            let transferred =
                unsafe { syscall(transfer, [descriptor, buffer, BLOCK_SIZE, offset, 0, 0]) };
            if transferred != BLOCK_SIZE as isize {
                close(descriptor);
                return 4;
            }
            operations = operations.wrapping_add(1);
            // The clock is read every 64 transfers.
            if operations & 63 == 0 {
                ended = monotonic_ns();
            }
        }
        ended = monotonic_ns();
        if benchmark.writing {
            // SAFETY: fsync takes a descriptor; this interface intentionally ignores the result.
            unsafe { syscall(SYS_FSYNC, [descriptor, 0, 0, 0, 0, 0]) };
        }
        close(descriptor);
        let operation: &[u8] = if benchmark.writing { b"write" } else { b"read" };
        let elapsed_ns = ended.wrapping_sub(started);
        emit(output.result(
            b"file",
            operation,
            operations,
            BLOCK_SIZE as u64,
            elapsed_ns,
        ))
    }

    fn run_network(benchmark: &NetworkBenchmark, io: &mut IoBuffer, output: &mut Output) -> i32 {
        // SAFETY: socket takes no pointers.
        let descriptor = unsafe {
            syscall(
                SYS_SOCKET,
                [AF_INET.into(), SOCK_DGRAM | SOCK_CLOEXEC, 0, 0, 0, 0],
            )
        };
        if descriptor < 0 {
            return 3;
        }
        let descriptor = descriptor as usize;
        let peer = SockaddrIn {
            family: AF_INET,
            port: benchmark.port.swap_bytes(),
            address: benchmark.address,
            padding: [0; 8],
        };
        let peer_size = size_of::<SockaddrIn>();
        // SAFETY: connect reads the address, which outlives the call.
        let connected = unsafe {
            syscall(
                SYS_CONNECT,
                [descriptor, &raw const peer as usize, peer_size, 0, 0, 0],
            )
        };
        if connected < 0 {
            close(descriptor);
            return 3;
        }
        let payload =
            io.0.first_chunk_mut::<PAYLOAD_SIZE>()
                .expect("a block holds a payload");
        fill_payload(payload);
        let mut poll = PollFd {
            descriptor: descriptor as i32,
            events: POLLIN,
            returned_events: 0,
        };
        let started = monotonic_ns();
        if started == 0 {
            close(descriptor);
            return 3;
        }
        let duration_ns = benchmark.duration_ms.wrapping_mul(1_000_000);
        let buffer = payload.as_mut_ptr() as usize;
        let mut ended = started;
        let mut operations = 0_u64;
        while ended.wrapping_sub(started) < duration_ns {
            // SAFETY: write reads the payload. The benchmark sends whatever the last echo left
            // in the buffer.
            let sent = unsafe { syscall(SYS_WRITE, [descriptor, buffer, PAYLOAD_SIZE, 0, 0, 0]) };
            if sent != PAYLOAD_SIZE as isize {
                close(descriptor);
                return 4;
            }
            poll.returned_events = 0;
            let poll_address = &raw mut poll as usize;
            // SAFETY: poll updates the one descriptor entry, which outlives the call.
            let ready = unsafe { syscall(SYS_POLL, [poll_address, 1, POLL_TIMEOUT_MS, 0, 0, 0]) };
            if ready > 0 && poll.returned_events & POLLIN != 0 {
                // SAFETY: read fills at most the payload.
                let received =
                    unsafe { syscall(SYS_READ, [descriptor, buffer, PAYLOAD_SIZE, 0, 0, 0]) };
                if received == PAYLOAD_SIZE as isize {
                    operations = operations.wrapping_add(1);
                }
            }
            ended = monotonic_ns();
        }
        close(descriptor);
        let elapsed_ns = ended.wrapping_sub(started);
        emit(output.result(
            b"network",
            b"roundtrip",
            operations,
            PAYLOAD_SIZE as u64,
            elapsed_ns,
        ))
    }

    /// Returns the monotonic clock in nanoseconds, or 0 when it cannot be read.
    fn monotonic_ns() -> u64 {
        let mut now = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        let address = &raw mut now as usize;
        // SAFETY: clock_gettime fills the timespec, which outlives the call.
        if unsafe { syscall(SYS_CLOCK_GETTIME, [CLOCK_MONOTONIC, address, 0, 0, 0, 0]) } < 0 {
            return 0;
        }
        (now.seconds as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(now.nanoseconds as u64)
    }

    fn close(descriptor: usize) {
        // SAFETY: close takes a descriptor, which the program does not use again.
        unsafe { syscall(SYS_CLOSE, [descriptor, 0, 0, 0, 0, 0]) };
    }

    /// Writes the result line to stdout, and returns the exit status: 0, or -1 when the write
    /// fails, which exits with 255.
    fn emit(line: &[u8]) -> i32 {
        let mut rest = line;
        while !rest.is_empty() {
            let (address, length) = (rest.as_ptr() as usize, rest.len());
            // SAFETY: write reads at most the rest of the line.
            let written = unsafe { syscall(SYS_WRITE, [1, address, length, 0, 0, 0]) };
            if written == -EINTR {
                continue;
            }
            if written <= 0 {
                return -1;
            }
            rest = rest.get(written as usize..).unwrap_or_default();
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::super::args::tests::with_args;
    use super::*;

    fn benchmark(arguments: &[&str], check: impl FnOnce(Option<Benchmark<'_>>)) {
        let arguments: Vec<&[u8]> = arguments
            .iter()
            .map(|argument| argument.as_bytes())
            .collect();
        with_args(&arguments, |args| check(parse(args)));
    }

    fn decimal(text: &str) -> Option<u64> {
        with_args(&[text.as_bytes()], |args| {
            parse_decimal(args.get(0).unwrap())
        })
    }

    fn ipv4(text: &str) -> Option<u32> {
        with_args(&[text.as_bytes()], |args| parse_ipv4(args.get(0).unwrap()))
    }

    #[test]
    fn parses_decimals_that_wrap_around() {
        assert_eq!(decimal(""), None);
        assert_eq!(decimal("0"), Some(0));
        assert_eq!(decimal("0042"), Some(42));
        assert_eq!(decimal("18446744073709551615"), Some(u64::MAX));
        assert_eq!(decimal("18446744073709551616"), Some(0));
        assert_eq!(decimal("18446744073709551617"), Some(1));
        for invalid in ["+1", "-1", " 1", "1 ", "0x10", "1a"] {
            assert_eq!(decimal(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn parses_dotted_quads() {
        assert_eq!(ipv4("127.0.0.1"), Some(u32::from_ne_bytes([127, 0, 0, 1])));
        assert_eq!(ipv4("10.0.2.2"), Some(u32::from_ne_bytes([10, 0, 2, 2])));
        assert_eq!(ipv4("255.255.255.255"), Some(u32::MAX));
        assert_eq!(
            ipv4("010.0.0.0001"),
            Some(u32::from_ne_bytes([10, 0, 0, 1]))
        );
        for invalid in [
            "",
            "1",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            ".1.2.3",
            "1.2.3.",
            "256.0.0.1",
            "1.2.3.4a",
            "1.2.3.-4",
            " 1.2.3.4",
        ] {
            assert_eq!(ipv4(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn parses_file_benchmarks() {
        let file = [
            "nvx-device-io",
            "file",
            "/f",
            "write",
            "250",
            "8192",
            "direct",
            "create",
        ];
        benchmark(&file, |parsed| {
            let Some(Benchmark::File(file)) = parsed else {
                panic!("not a file benchmark");
            };
            assert!(file.path.equals(b"/f"));
            assert_eq!(
                (
                    file.writing,
                    file.duration_ms,
                    file.size_bytes,
                    file.direct,
                    file.create
                ),
                (true, 250, 8192, true, true)
            );
        });
        let read = [
            "nvx-device-io",
            "file",
            "/f",
            "read",
            "1",
            "4096",
            "buffered",
            "existing",
        ];
        benchmark(&read, |parsed| {
            let Some(Benchmark::File(file)) = parsed else {
                panic!("not a file benchmark");
            };
            assert_eq!(
                (
                    file.writing,
                    file.duration_ms,
                    file.size_bytes,
                    file.direct,
                    file.create
                ),
                (false, 1, 4096, false, false)
            );
        });
        for (position, invalid) in [
            (4, "0"),
            (4, "-1"),
            (4, ""),
            (5, "4095"),
            (3, "readwrite"),
            (3, "Read"),
            (6, "cached"),
            (7, "new"),
            (1, "x"),
        ] {
            let mut arguments = read;
            arguments[position] = invalid;
            benchmark(&arguments, |parsed| {
                assert!(parsed.is_none(), "{arguments:?}")
            });
        }
        benchmark(&read[..7], |parsed| assert!(parsed.is_none()));
        benchmark(&[&read[..], &["extra"]].concat(), |parsed| {
            assert!(parsed.is_none());
        });
    }

    #[test]
    fn parses_network_benchmarks() {
        let network = [
            "nvx-device-io",
            "network",
            "10.0.2.2",
            "18446744073709551617",
            "50",
        ];
        benchmark(&network, |parsed| {
            let Some(Benchmark::Network(network)) = parsed else {
                panic!("not a network benchmark");
            };
            // The interface's wrapping parser makes the port wrap around to 1.
            assert_eq!(
                (network.address, network.port, network.duration_ms),
                (u32::from_ne_bytes([10, 0, 2, 2]), 1, 50)
            );
        });
        for (position, invalid) in [(2, "10.0.2"), (3, "0"), (3, "65536"), (4, "0"), (1, "net")] {
            let mut arguments = network;
            arguments[position] = invalid;
            benchmark(&arguments, |parsed| {
                assert!(parsed.is_none(), "{arguments:?}")
            });
        }
        benchmark(&["nvx-device-io"], |parsed| assert!(parsed.is_none()));
        benchmark(&network[..4], |parsed| assert!(parsed.is_none()));
    }

    #[test]
    fn offsets_follow_the_contract_generator() {
        // The first blocks of a 1 MiB file, using the benchmark's wrapping arithmetic.
        let mut offsets = Offsets::new(256);
        let first: Vec<u64> = (0..4).map(|_| offsets.next_offset()).collect();
        assert_eq!(first, [0, 79 * 4096, 50 * 4096, 25 * 4096]);
        let mut offsets = Offsets::new(1);
        assert!((0..100).all(|_| offsets.next_offset() == 0));
    }

    #[test]
    fn fills_the_patterns() {
        let mut buffer = IoBuffer::new();
        fill_pattern(&mut buffer.0);
        assert_eq!(&buffer.0[..4], &[17, 48, 79, 110]);
        assert_eq!(buffer.0[4095], (4095 * 31 + 17) as u8);
        let mut payload = [0; PAYLOAD_SIZE];
        fill_payload(&mut payload);
        assert_eq!(payload[0], 1);
        assert_eq!(payload[63], 64);
        assert_eq!(align_of::<IoBuffer>(), BLOCK_SIZE);
    }

    #[test]
    fn formats_and_truncates_the_result_line() {
        let mut output = Output::new();
        assert_eq!(
            output.result(b"file", b"read", 12, 4096, 1_000_000_007),
            br#"{"device":"file","operation":"read","operations":12,"bytes_per_operation":4096,"elapsed_ns":1000000007}"#
                .iter()
                .chain(b"\n")
                .copied()
                .collect::<Vec<u8>>()
        );
        assert_eq!(
            output.result(b"network", b"roundtrip", 0, 64, u64::MAX),
            [
                &br#"{"device":"network","operation":"roundtrip","operations":0,"#[..],
                br#""bytes_per_operation":64,"elapsed_ns":18446744073709551615}"#,
                b"\n"
            ]
            .concat()
        );
        let long = [b'x'; OUTPUT_SIZE];
        let line = output.result(b"file", &long, 1, 2, 3);
        assert_eq!(line.len(), OUTPUT_SIZE);
        assert!(line.starts_with(br#"{"device":"file","operation":"xxx"#));
    }
}
