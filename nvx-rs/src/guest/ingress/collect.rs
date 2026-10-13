//! Scans the four socket tables, settles UDP sockets, and builds an announcement.

use std::ffi::CString;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::address::AddressContext;
use super::diag::{self, WildcardListener};
use super::encode::{self, ListenerTable};
use super::{PROTOCOL_TCP, PROTOCOL_UDP, UDP_SETTLE_MS, UdpSocket};

pub(super) enum DiagnosticInput {
    Live,
    Snapshot,
}

#[derive(Clone, Copy)]
struct UdpState {
    port: u16,
    announced: bool,
    inode: libc::c_ulong,
    first_seen_ms: u64,
}

pub(super) struct Collector {
    udp_states: Vec<UdpState>,
}

struct ScanState<'a> {
    addresses: AddressContext<'a>,
    listeners: ListenerTable,
    udp_sockets: Vec<UdpSocket>,
}

impl<'a> ScanState<'a> {
    fn new(ipv6_dual_stack: bool, wildcard_tcp: &'a [WildcardListener]) -> Self {
        Self {
            addresses: AddressContext {
                ipv6_dual_stack,
                wildcard_tcp,
            },
            listeners: ListenerTable::default(),
            udp_sockets: Vec::new(),
        }
    }

    fn scan(&mut self, reader: impl std::io::Read, protocol: u8, ipv6: bool, own_port: u16) {
        super::table::scan(
            reader,
            protocol,
            ipv6,
            own_port,
            &self.addresses,
            &mut self.listeners,
            &mut self.udp_sockets,
        );
    }
}

impl Collector {
    pub(super) fn new() -> Self {
        Self {
            udp_states: Vec::new(),
        }
    }

    pub(super) fn collect_files(
        &mut self,
        root: &Path,
        diagnostics: DiagnosticInput,
        own_port: u16,
        now: u64,
        ipv6_dual_stack: bool,
    ) -> Vec<u8> {
        let wildcard_tcp = match diagnostics {
            DiagnosticInput::Live => diag::query_live(),
            DiagnosticInput::Snapshot => diag::query_snapshot(root),
        };
        let mut scan = ScanState::new(ipv6_dual_stack, &wildcard_tcp);
        for (name, protocol, ipv6) in [
            ("tcp", PROTOCOL_TCP, false),
            ("tcp6", PROTOCOL_TCP, true),
            ("udp", PROTOCOL_UDP, false),
            ("udp6", PROTOCOL_UDP, true),
        ] {
            let Some(path) = proc_path(root, &format!("/net/{name}")) else {
                continue;
            };
            let Ok(file) = File::open(path) else {
                continue;
            };
            scan.scan(file, protocol, ipv6, own_port);
        }
        self.finish(scan, now)
    }

    fn finish(&mut self, mut scan: ScanState<'_>, now: u64) -> Vec<u8> {
        let mut next = Vec::with_capacity(scan.udp_sockets.len());
        for socket in scan.udp_sockets {
            let previous = self
                .udp_states
                .iter()
                .find(|state| state.port == socket.port && state.inode == socket.inode);
            let first_seen_ms = previous.map_or(now, |state| state.first_seen_ms);
            let announced = if previous.is_some_and(|state| state.announced) {
                true
            } else if socket.connected {
                continue;
            } else {
                now.wrapping_sub(first_seen_ms) >= UDP_SETTLE_MS
            };
            next.push(UdpState {
                port: socket.port,
                announced,
                inode: socket.inode,
                first_seen_ms,
            });
            if announced {
                scan.listeners
                    .add(PROTOCOL_UDP, socket.port, socket.families);
            }
        }
        self.udp_states = next;
        encode::encode(scan.listeners)
    }
}

fn proc_path(root: &Path, suffix: &str) -> Option<PathBuf> {
    if root.as_os_str().as_bytes().len() + suffix.len() >= 4096 {
        return None;
    }
    Some(root.join(suffix.trim_start_matches('/')))
}

pub(super) fn read_bindv6only(root: &Path, default: bool) -> bool {
    let Some(path) = proc_path(root, "/sys/net/ipv6/bindv6only") else {
        return default;
    };
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return default;
    };
    // SAFETY: both strings are NUL-terminated, and `fopen` retains neither pointer.
    let file = unsafe { libc::fopen(path.as_ptr(), c"re".as_ptr()) };
    if file.is_null() {
        return default;
    }
    let mut value: libc::c_int = 0;
    // SAFETY: `file` is open and `%d` exactly matches the writable int pointer.
    let parsed = unsafe { libc::fscanf(file, c"%d".as_ptr(), &mut value) };
    // SAFETY: `file` is open and no longer used.
    unsafe { libc::fclose(file) };
    if parsed == 1 { value == 0 } else { default }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::guest::ingress::{
        FAMILY_IPV4, FAMILY_IPV6, FIRST_SOURCE_PORT, MAX_ANNOUNCED, MAX_TRACKED, TCP_LISTEN,
        UDP_CONNECTED, UDP_UNCONNECTED,
    };

    const BOTH: u8 = FAMILY_IPV4 | FAMILY_IPV6;
    const TCP_ESTABLISHED: u32 = 1;
    const TABLE_HEADER: &[u8] = b"  sl  local_address rem_address st tx rx tr tm retr uid \
timeout inode\n";

    #[derive(Clone)]
    struct Socket {
        protocol: u8,
        address: IpAddr,
        port: u16,
        inode: u64,
        state: u32,
        peer: Option<(IpAddr, u16)>,
    }

    impl Socket {
        fn table(&self) -> usize {
            match (self.protocol, self.address) {
                (PROTOCOL_TCP, IpAddr::V4(_)) => 0,
                (PROTOCOL_TCP, IpAddr::V6(_)) => 1,
                (PROTOCOL_UDP, IpAddr::V4(_)) => 2,
                (PROTOCOL_UDP, IpAddr::V6(_)) => 3,
                _ => unreachable!(),
            }
        }

        fn line(&self, index: usize) -> Vec<u8> {
            let unspecified = match self.address {
                IpAddr::V4(_) => "0.0.0.0".parse().unwrap(),
                IpAddr::V6(_) => "::".parse().unwrap(),
            };
            let (remote, remote_port) = self.peer.unwrap_or((unspecified, 0));
            format!(
                "{index:4}: {}:{:04X} {}:{remote_port:04X} {:02X} \
                 00000000:00000000 00:00000000 00000000 0 0 {} \
                 2 0000000000000000\n",
                kernel_address(self.address),
                self.port,
                kernel_address(remote),
                self.state,
                self.inode,
            )
            .into_bytes()
        }
    }

    fn tcp_listener(address: &str, port: u16, inode: u64) -> Socket {
        Socket {
            protocol: PROTOCOL_TCP,
            address: address.parse().unwrap(),
            port,
            inode,
            state: TCP_LISTEN,
            peer: None,
        }
    }

    fn udp_socket(address: &str, port: u16, inode: u64) -> Socket {
        Socket {
            protocol: PROTOCOL_UDP,
            address: address.parse().unwrap(),
            port,
            inode,
            state: UDP_UNCONNECTED,
            peer: None,
        }
    }

    fn connected(mut socket: Socket, remote: &str, port: u16) -> Socket {
        socket.state = UDP_CONNECTED;
        socket.peer = Some((remote.parse().unwrap(), port));
        socket
    }

    fn kernel_address(address: IpAddr) -> String {
        let octets = match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        octets
            .chunks_exact(4)
            .map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().unwrap())))
            .collect()
    }

    struct Snapshot {
        time_ms: u64,
        sockets: Vec<Socket>,
        bindv6only: Option<i32>,
        diag: Option<Vec<u8>>,
    }

    impl Snapshot {
        fn new(time_ms: u64, sockets: Vec<Socket>) -> Self {
            Self {
                time_ms,
                sockets,
                bindv6only: None,
                diag: None,
            }
        }

        fn tables(&self) -> [Vec<u8>; 4] {
            let mut tables = std::array::from_fn(|_| TABLE_HEADER.to_vec());
            for (index, socket) in self.sockets.iter().enumerate() {
                tables[socket.table()].extend(socket.line(index));
            }
            tables
        }
    }

    fn diag_listener(port: u16, ipv6_only: bool, address: &str) -> Vec<u8> {
        let mut message = vec![0_u8; 72];
        message[0] = libc::AF_INET6 as u8;
        message[1] = TCP_LISTEN as u8;
        message[4..6].copy_from_slice(&port.to_be_bytes());
        let IpAddr::V6(address) = address.parse().unwrap() else {
            unreachable!()
        };
        message[8..24].copy_from_slice(&address.octets());
        message.extend_from_slice(&5_u16.to_ne_bytes());
        message.extend_from_slice(&11_u16.to_ne_bytes());
        message.extend_from_slice(&[u8::from(ipv6_only), 0, 0, 0]);
        let mut record = Vec::new();
        record.extend_from_slice(&(16_u32 + message.len() as u32).to_ne_bytes());
        record.extend_from_slice(&20_u16.to_ne_bytes());
        record.extend_from_slice(&2_u16.to_ne_bytes());
        record.extend_from_slice(&1_u32.to_ne_bytes());
        record.extend_from_slice(&0_u32.to_ne_bytes());
        record.extend(message);
        record
    }

    fn diag_done() -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&20_u32.to_ne_bytes());
        record.extend_from_slice(&3_u16.to_ne_bytes());
        record.extend_from_slice(&2_u16.to_ne_bytes());
        record.extend_from_slice(&1_u32.to_ne_bytes());
        record.extend_from_slice(&0_u32.to_ne_bytes());
        record.extend_from_slice(&[0; 4]);
        record
    }

    #[derive(Debug)]
    struct Announcement {
        payload: Vec<u8>,
        truncated: bool,
        listeners: std::collections::BTreeMap<(u8, u16), u8>,
        order: Vec<(u8, u16)>,
    }

    fn decode(payload: Vec<u8>) -> Announcement {
        assert_eq!(&payload[..5], b"NVXL\x01");
        let count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
        assert_eq!(payload.len(), 8 + 4 * count);
        let entries: Vec<_> = payload[8..]
            .chunks_exact(4)
            .map(|entry| {
                (
                    (entry[0], u16::from_be_bytes([entry[2], entry[3]])),
                    entry[1],
                )
            })
            .collect();
        Announcement {
            truncated: payload[5] & 1 != 0,
            listeners: entries.iter().copied().collect(),
            order: entries.iter().map(|(key, _)| *key).collect(),
            payload,
        }
    }

    fn announce(collector: &mut Collector, snapshot: &Snapshot) -> Announcement {
        let mut wildcard = Vec::new();
        if let Some(diag) = &snapshot.diag {
            diag::parse_wildcard_tcp(diag, &mut wildcard);
        }
        let dual_stack = snapshot.bindv6only.is_none_or(|value| value == 0);
        let mut scan = ScanState::new(dual_stack, &wildcard);
        for (index, table) in snapshot.tables().iter().enumerate() {
            let (protocol, ipv6) = match index {
                0 => (PROTOCOL_TCP, false),
                1 => (PROTOCOL_TCP, true),
                2 => (PROTOCOL_UDP, false),
                3 => (PROTOCOL_UDP, true),
                _ => unreachable!(),
            };
            scan.scan(table.as_slice(), protocol, ipv6, FIRST_SOURCE_PORT);
        }
        decode(collector.finish(scan, snapshot.time_ms))
    }

    #[test]
    fn announcement_golden_vector() {
        let mut collector = Collector::new();
        let announcement = announce(
            &mut collector,
            &Snapshot::new(
                0,
                vec![
                    tcp_listener("0.0.0.0", 8080, 1),
                    tcp_listener("fd00::a00:2", 8443, 2),
                ],
            ),
        );
        assert_eq!(
            hex(&announcement.payload),
            "4e56584c0100000206011f90060220fb"
        );
    }

    #[test]
    fn only_listeners_reachable_through_the_gateway_are_announced() {
        let mut sockets = vec![
            tcp_listener("0.0.0.0", 8080, 1),
            tcp_listener("192.0.2.2", 8081, 2),
            tcp_listener("127.0.0.1", 8082, 3),
            tcp_listener("127.0.0.53", 8083, 4),
            tcp_listener("::", 8084, 5),
            tcp_listener("fd00::a00:2", 8085, 6),
            tcp_listener("::1", 8086, 7),
            tcp_listener("fe80::1", 8087, 8),
            tcp_listener("::ffff:127.0.0.1", 8088, 9),
            tcp_listener("::ffff:192.0.2.2", 8089, 10),
            tcp_listener("0.0.0.0", 8090, 11),
            tcp_listener("fd00::a00:2", 8090, 12),
        ];
        let mut established = tcp_listener("192.0.2.2", 8091, 13);
        established.state = TCP_ESTABLISHED;
        established.peer = Some(("192.0.2.1".parse().unwrap(), 40_000));
        sockets.push(established);
        let announcement = announce(&mut Collector::new(), &Snapshot::new(0, sockets));
        assert_eq!(
            announcement.listeners,
            [
                ((PROTOCOL_TCP, 8080), FAMILY_IPV4),
                ((PROTOCOL_TCP, 8081), FAMILY_IPV4),
                ((PROTOCOL_TCP, 8084), BOTH),
                ((PROTOCOL_TCP, 8085), FAMILY_IPV6),
                ((PROTOCOL_TCP, 8089), FAMILY_IPV4),
                ((PROTOCOL_TCP, 8090), BOTH),
            ]
            .into_iter()
            .collect()
        );
        assert!(!announcement.truncated);
    }

    #[test]
    fn ipv6_only_tcp_listeners_follow_socket_diagnostics() {
        let sockets = (7001..=7005)
            .map(|port| tcp_listener("::", port, u64::from(port)))
            .collect::<Vec<_>>();
        let mut dump = diag_listener(7001, true, "::");
        dump.extend(diag_listener(7002, false, "::"));
        dump.extend(diag_listener(7003, true, "::"));
        dump.extend(diag_listener(7003, false, "::"));
        dump.extend(diag_listener(7004, true, "fd00::a00:2"));
        dump.extend(diag_done());
        dump.extend(diag_listener(7005, true, "::"));
        let mut first = Snapshot::new(0, sockets.clone());
        first.diag = Some(dump);
        let mut second = Snapshot::new(100, sockets);
        second.bindv6only = Some(1);
        second.diag = Some(diag_listener(7002, false, "::"));

        let mut collector = Collector::new();
        assert_eq!(
            announce(&mut collector, &first).listeners,
            [
                ((PROTOCOL_TCP, 7001), FAMILY_IPV6),
                ((PROTOCOL_TCP, 7002), BOTH),
                ((PROTOCOL_TCP, 7003), BOTH),
                ((PROTOCOL_TCP, 7004), BOTH),
                ((PROTOCOL_TCP, 7005), BOTH),
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            announce(&mut collector, &second).listeners,
            [
                ((PROTOCOL_TCP, 7001), FAMILY_IPV6),
                ((PROTOCOL_TCP, 7002), BOTH),
                ((PROTOCOL_TCP, 7003), FAMILY_IPV6),
                ((PROTOCOL_TCP, 7004), FAMILY_IPV6),
                ((PROTOCOL_TCP, 7005), FAMILY_IPV6),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn malformed_socket_diagnostics_are_ignored() {
        let valid = diag_listener(7101, true, "::");
        let attribute = 16 + 72;
        let mut short_attribute = valid.clone();
        short_attribute[attribute..attribute + 2].copy_from_slice(&2_u16.to_ne_bytes());
        let mut long_attribute = valid.clone();
        long_attribute[attribute..attribute + 2].copy_from_slice(&200_u16.to_ne_bytes());
        for dump in [
            (0_u8..37).collect(),
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&8_u32.to_ne_bytes());
                bytes.extend_from_slice(&20_u16.to_ne_bytes());
                bytes.extend_from_slice(&[0; 10]);
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&4096_u32.to_ne_bytes());
                bytes.extend_from_slice(&20_u16.to_ne_bytes());
                bytes.extend_from_slice(&[0; 10]);
                bytes
            },
            valid[..40].to_vec(),
            short_attribute,
            long_attribute,
        ] {
            let mut snapshot = Snapshot::new(0, vec![tcp_listener("::", 7101, 1)]);
            snapshot.diag = Some(dump);
            assert_eq!(
                announce(&mut Collector::new(), &snapshot).listeners,
                [((PROTOCOL_TCP, 7101), BOTH)].into_iter().collect()
            );
        }
    }

    #[test]
    fn udp_sockets_settle_before_they_are_announced() {
        let sockets = vec![
            udp_socket("0.0.0.0", 7201, 10),
            udp_socket("::", 7202, 11),
            udp_socket("0.0.0.0", FIRST_SOURCE_PORT, 12),
            udp_socket("127.0.0.1", 7203, 13),
        ];
        let mut snapshots = [
            Snapshot::new(0, sockets.clone()),
            Snapshot::new(UDP_SETTLE_MS - 1, sockets.clone()),
            Snapshot::new(UDP_SETTLE_MS, sockets.clone()),
            Snapshot::new(UDP_SETTLE_MS + 100, sockets),
        ];
        snapshots[3].bindv6only = Some(1);
        let mut collector = Collector::new();
        assert!(announce(&mut collector, &snapshots[0]).listeners.is_empty());
        assert!(announce(&mut collector, &snapshots[1]).listeners.is_empty());
        assert_eq!(
            announce(&mut collector, &snapshots[2]).listeners,
            [
                ((PROTOCOL_UDP, 7201), FAMILY_IPV4),
                ((PROTOCOL_UDP, 7202), BOTH),
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            announce(&mut collector, &snapshots[3]).listeners,
            [
                ((PROTOCOL_UDP, 7201), FAMILY_IPV4),
                ((PROTOCOL_UDP, 7202), FAMILY_IPV6),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn udp_ports_follow_the_identity_of_their_sockets() {
        let server = udp_socket("0.0.0.0", 7301, 20);
        let replacement = udp_socket("0.0.0.0", 7301, 21);
        let connected_server = connected(replacement.clone(), "198.51.100.7", 5353);
        let client = connected(udp_socket("192.0.2.2", 7301, 22), "192.0.2.1", 53);
        let timeline = [
            (0, vec![server.clone()], None),
            (UDP_SETTLE_MS, vec![server], Some(FAMILY_IPV4)),
            (UDP_SETTLE_MS + 100, vec![replacement.clone()], None),
            (2 * UDP_SETTLE_MS + 99, vec![replacement.clone()], None),
            (
                2 * UDP_SETTLE_MS + 100,
                vec![replacement],
                Some(FAMILY_IPV4),
            ),
            (
                2 * UDP_SETTLE_MS + 200,
                vec![connected_server.clone()],
                Some(FAMILY_IPV4),
            ),
            (5 * UDP_SETTLE_MS, vec![connected_server], Some(FAMILY_IPV4)),
            (5 * UDP_SETTLE_MS + 100, vec![client.clone()], None),
            (9 * UDP_SETTLE_MS, vec![client], None),
        ];
        let mut collector = Collector::new();
        for (time, sockets, families) in timeline {
            let listeners = announce(&mut collector, &Snapshot::new(time, sockets)).listeners;
            let expected = families.map_or_else(std::collections::BTreeMap::new, |families| {
                [((PROTOCOL_UDP, 7301), families)].into_iter().collect()
            });
            assert_eq!(listeners, expected, "time {time}");
        }
    }

    #[test]
    fn udp_ports_announce_the_families_of_their_sockets() {
        let ipv4 = udp_socket("0.0.0.0", 7401, 30);
        let ipv6 = udp_socket("::", 7401, 31);
        let ipv4_connected = connected(ipv4.clone(), "198.51.100.7", 4000);
        let ipv6_connected = connected(ipv6.clone(), "fd12::7", 4000);
        let timeline = [
            (0, vec![ipv4.clone(), ipv6.clone()], None),
            (UDP_SETTLE_MS, vec![ipv4, ipv6.clone()], Some(BOTH)),
            (
                UDP_SETTLE_MS + 100,
                vec![ipv4_connected.clone(), ipv6.clone()],
                Some(BOTH),
            ),
            (
                UDP_SETTLE_MS + 200,
                vec![ipv4_connected, ipv6_connected.clone()],
                Some(BOTH),
            ),
            (UDP_SETTLE_MS + 300, vec![ipv6_connected], Some(FAMILY_IPV6)),
            (UDP_SETTLE_MS + 400, Vec::new(), None),
        ];
        let mut collector = Collector::new();
        for (time, sockets, families) in timeline {
            let mut snapshot = Snapshot::new(time, sockets);
            snapshot.bindv6only = Some(1);
            let listeners = announce(&mut collector, &snapshot).listeners;
            let expected = families.map_or_else(std::collections::BTreeMap::new, |families| {
                [((PROTOCOL_UDP, 7401), families)].into_iter().collect()
            });
            assert_eq!(listeners, expected, "time {time}");
        }
    }

    #[test]
    fn announcements_carry_the_lowest_64_listeners() {
        let sockets = (2000..=2069)
            .rev()
            .map(|port| tcp_listener("0.0.0.0", port, u64::from(port)))
            .collect::<Vec<_>>();
        let announcement = announce(&mut Collector::new(), &Snapshot::new(0, sockets.clone()));
        assert!(announcement.truncated);
        assert_eq!(
            announcement.order,
            (2000..2000 + MAX_ANNOUNCED as u16)
                .map(|port| (PROTOCOL_TCP, port))
                .collect::<Vec<_>>()
        );
        let complete = announce(
            &mut Collector::new(),
            &Snapshot::new(0, sockets[sockets.len() - MAX_ANNOUNCED..].to_vec()),
        );
        assert!(!complete.truncated);
        assert_eq!(complete.order.len(), MAX_ANNOUNCED);
    }

    #[test]
    fn udp_settling_wraps_time_and_tracks_only_the_first_1024_rows() {
        let sockets = (0..=MAX_TRACKED)
            .map(|index| udp_socket("0.0.0.0", 10_000 + index as u16, 100_000 + index as u64))
            .collect::<Vec<_>>();
        let mut collector = Collector::new();
        assert!(
            announce(
                &mut collector,
                &Snapshot::new(u64::MAX - 500, sockets.clone())
            )
            .listeners
            .is_empty()
        );
        let announcement = announce(&mut collector, &Snapshot::new(500, sockets));
        assert!(announcement.truncated);
        assert_eq!(collector.udp_states.len(), MAX_TRACKED);
        assert_eq!(announcement.order[0], (PROTOCOL_UDP, 10_000));
    }

    #[test]
    fn bindv6only_defaults_and_parses_like_fscanf() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_bindv6only(directory.path(), true));
        let path = directory.path().join("sys/net/ipv6");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("bindv6only"), b" \t0trailing").unwrap();
        assert!(read_bindv6only(directory.path(), false));
        std::fs::write(path.join("bindv6only"), b"1\n").unwrap();
        assert!(!read_bindv6only(directory.path(), true));
        std::fs::write(path.join("bindv6only"), b"bad").unwrap();
        assert!(!read_bindv6only(directory.path(), false));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
