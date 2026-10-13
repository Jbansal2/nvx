//! Queries and parses Linux socket diagnostics for wildcard IPv6 TCP listeners.

use std::io::Read;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::{MAX_TRACKED, SCAN_INTERVAL_MS, TCP_LISTEN};

const NETLINK_SOCK_DIAG_PROTOCOL: libc::c_int = 4;
const NETLINK_REQUEST: u16 = 0x01;
const NETLINK_DUMP: u16 = 0x300;
const NETLINK_ERROR: u16 = 2;
const NETLINK_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_SKV6ONLY: u16 = 11;
const DIAG_BUFFER_LENGTH: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WildcardListener {
    pub(super) port: u16,
    pub(super) dual_stack: bool,
    pub(super) ipv6_only: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NetlinkHeader {
    length: u32,
    kind: u16,
    flags: u16,
    sequence: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NetlinkAddress {
    family: libc::sa_family_t,
    pad: u16,
    pid: u32,
    groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct InetDiagSocketId {
    source_port: u16,
    destination_port: u16,
    source: [u32; 4],
    destination: [u32; 4],
    interface: u32,
    cookie: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct InetDiagRequest {
    family: u8,
    protocol: u8,
    extensions: u8,
    pad: u8,
    states: u32,
    id: InetDiagSocketId,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct InetDiagMessage {
    family: u8,
    state: u8,
    timer: u8,
    retransmits: u8,
    id: InetDiagSocketId,
    expires: u32,
    receive_queue: u32,
    write_queue: u32,
    uid: u32,
    inode: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Query {
    header: NetlinkHeader,
    request: InetDiagRequest,
}

fn native_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn native_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn align4(length: usize) -> usize {
    (length + 3) & !3
}

fn note_wildcard_tcp(message: &[u8], listeners: &mut Vec<WildcardListener>) {
    if message.len() < size_of::<InetDiagMessage>()
        || message[0] != libc::AF_INET6 as u8
        || u32::from(message[1]) != TCP_LISTEN
        || message[8..24].iter().any(|byte| *byte != 0)
    {
        return;
    }
    let port = u16::from_be_bytes([message[4], message[5]]);
    let mut offset = size_of::<InetDiagMessage>();
    while offset + 4 <= message.len() {
        let length = usize::from(native_u16(&message[offset..]));
        let kind = native_u16(&message[offset + 2..]);
        if length < 4 || length > message.len() - offset {
            return;
        }
        if kind == INET_DIAG_SKV6ONLY && length > 4 {
            let ipv6_only = message[offset + 4] != 0;
            if let Some(listener) = listeners.iter_mut().find(|listener| listener.port == port) {
                listener.dual_stack |= !ipv6_only;
                listener.ipv6_only |= ipv6_only;
            } else if listeners.len() < MAX_TRACKED {
                listeners.push(WildcardListener {
                    port,
                    dual_stack: !ipv6_only,
                    ipv6_only,
                });
            }
            return;
        }
        offset += align4(length);
    }
}

/// Parses one received part of a netlink diagnostics dump.
///
/// It returns false when DONE, ERROR, or malformed framing ends the dump.
pub(super) fn parse_wildcard_tcp(buffer: &[u8], listeners: &mut Vec<WildcardListener>) -> bool {
    let mut offset = 0;
    while offset + size_of::<NetlinkHeader>() <= buffer.len() {
        let header = &buffer[offset..];
        let length = native_u32(header) as usize;
        let kind = native_u16(&header[4..]);
        if length < size_of::<NetlinkHeader>()
            || length > buffer.len() - offset
            || kind == NETLINK_DONE
            || kind == NETLINK_ERROR
        {
            return false;
        }
        if kind == SOCK_DIAG_BY_FAMILY {
            note_wildcard_tcp(
                &buffer[offset + size_of::<NetlinkHeader>()..offset + length],
                listeners,
            );
        }
        offset += align4(length);
    }
    true
}

pub(super) fn query_snapshot(root: &Path) -> Vec<WildcardListener> {
    let mut listeners = Vec::new();
    if root.as_os_str().as_bytes().len() + b"/diag".len() >= 4096 {
        return listeners;
    }
    let Ok(file) = std::fs::File::open(root.join("diag")) else {
        return listeners;
    };
    let mut dump = Vec::with_capacity(DIAG_BUFFER_LENGTH);
    let _ = file.take(DIAG_BUFFER_LENGTH as u64).read_to_end(&mut dump);
    parse_wildcard_tcp(&dump, &mut listeners);
    listeners
}

pub(super) fn query_live() -> Vec<WildcardListener> {
    let mut listeners = Vec::new();
    // SAFETY: socket is called with a supported Linux netlink family and no pointers.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG_PROTOCOL,
        )
    };
    if descriptor < 0 {
        return listeners;
    }

    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: (SCAN_INTERVAL_MS * 1_000) as _,
    };
    let mut query = Query::default();
    query.header.length = size_of::<Query>() as u32;
    query.header.kind = SOCK_DIAG_BY_FAMILY;
    query.header.flags = NETLINK_REQUEST | NETLINK_DUMP;
    query.request.family = libc::AF_INET6 as u8;
    query.request.protocol = libc::IPPROTO_TCP as u8;
    query.request.states = 1_u32 << TCP_LISTEN;
    let kernel = NetlinkAddress {
        family: libc::AF_NETLINK as libc::sa_family_t,
        ..NetlinkAddress::default()
    };

    // SAFETY: both pointers name initialized values for the lengths supplied.
    let configured = unsafe {
        libc::setsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } == 0;
    if !configured {
        // SAFETY: descriptor is open and no longer used.
        unsafe { libc::close(descriptor) };
        return listeners;
    }
    // SAFETY: sendto reads the initialized query and address for their exact C-layout sizes.
    let sent = unsafe {
        libc::sendto(
            descriptor,
            std::ptr::addr_of!(query).cast(),
            size_of::<Query>(),
            0,
            std::ptr::addr_of!(kernel).cast::<libc::sockaddr>(),
            size_of::<NetlinkAddress>() as libc::socklen_t,
        )
    };
    if sent != size_of::<Query>() as isize {
        // SAFETY: descriptor is open and no longer used.
        unsafe { libc::close(descriptor) };
        return listeners;
    }

    let mut buffer = [0_u8; DIAG_BUFFER_LENGTH];
    loop {
        // SAFETY: recv writes at most `buffer.len()` initialized bytes into the buffer.
        let received =
            unsafe { libc::recv(descriptor, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received <= 0 || !parse_wildcard_tcp(&buffer[..received as usize], &mut listeners) {
            break;
        }
    }
    // SAFETY: descriptor is open and no longer used.
    unsafe { libc::close(descriptor) };
    listeners
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag_listener(port: u16, ipv6_only: bool, address: [u8; 16]) -> Vec<u8> {
        let mut message = vec![0_u8; size_of::<InetDiagMessage>()];
        message[0] = libc::AF_INET6 as u8;
        message[1] = TCP_LISTEN as u8;
        message[4..6].copy_from_slice(&port.to_be_bytes());
        message[8..24].copy_from_slice(&address);
        message.extend_from_slice(&5_u16.to_ne_bytes());
        message.extend_from_slice(&INET_DIAG_SKV6ONLY.to_ne_bytes());
        message.extend_from_slice(&[u8::from(ipv6_only), 0, 0, 0]);

        let mut record = Vec::new();
        record.extend_from_slice(
            &((size_of::<NetlinkHeader>() + message.len()) as u32).to_ne_bytes(),
        );
        record.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        record.extend_from_slice(&2_u16.to_ne_bytes());
        record.extend_from_slice(&1_u32.to_ne_bytes());
        record.extend_from_slice(&0_u32.to_ne_bytes());
        record.extend_from_slice(&message);
        record
    }

    fn terminal(kind: u16) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&20_u32.to_ne_bytes());
        record.extend_from_slice(&kind.to_ne_bytes());
        record.extend_from_slice(&2_u16.to_ne_bytes());
        record.extend_from_slice(&1_u32.to_ne_bytes());
        record.extend_from_slice(&0_u32.to_ne_bytes());
        record.extend_from_slice(&[0; 4]);
        record
    }

    #[test]
    fn explicit_layouts_match_the_linux_abi() {
        assert_eq!(size_of::<NetlinkHeader>(), 16);
        assert_eq!(size_of::<NetlinkAddress>(), 12);
        assert_eq!(size_of::<InetDiagSocketId>(), 48);
        assert_eq!(size_of::<InetDiagRequest>(), 56);
        assert_eq!(size_of::<InetDiagMessage>(), 72);
        assert_eq!(size_of::<Query>(), 72);
    }

    #[test]
    fn diagnostics_merge_dual_stack_and_stop_at_done() {
        let mut dump = diag_listener(7001, true, [0; 16]);
        dump.extend_from_slice(&diag_listener(7001, false, [0; 16]));
        dump.extend_from_slice(&diag_listener(7002, true, [1; 16]));
        dump.extend_from_slice(&terminal(NETLINK_DONE));
        dump.extend_from_slice(&diag_listener(7003, true, [0; 16]));
        let mut listeners = Vec::new();
        assert!(!parse_wildcard_tcp(&dump, &mut listeners));
        assert_eq!(
            listeners,
            vec![WildcardListener {
                port: 7001,
                dual_stack: true,
                ipv6_only: true,
            }]
        );
    }

    #[test]
    fn malformed_headers_and_attributes_end_or_ignore_the_record() {
        let valid = diag_listener(7101, true, [0; 16]);
        for mut dump in [
            vec![0; 37],
            {
                let mut value = valid.clone();
                value[..4].copy_from_slice(&8_u32.to_ne_bytes());
                value
            },
            {
                let mut value = valid.clone();
                value[..4].copy_from_slice(&4096_u32.to_ne_bytes());
                value
            },
            valid[..40].to_vec(),
        ] {
            let mut listeners = Vec::new();
            let _ = parse_wildcard_tcp(&dump, &mut listeners);
            assert!(listeners.is_empty());
            dump.clear();
        }

        for length in [2_u16, 200] {
            let mut dump = valid.clone();
            let offset = size_of::<NetlinkHeader>() + size_of::<InetDiagMessage>();
            dump[offset..offset + 2].copy_from_slice(&length.to_ne_bytes());
            let mut listeners = Vec::new();
            assert!(parse_wildcard_tcp(&dump, &mut listeners));
            assert!(listeners.is_empty());
        }
    }
}
