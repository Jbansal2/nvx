//! Reads the kernel's TCP and UDP tables with the C program's bounded-line parsing.

use std::io::{BufRead, BufReader, Read};

use super::address::AddressContext;
use super::encode::ListenerTable;
use super::{MAX_TRACKED, PROTOCOL_TCP, TCP_LISTEN, UDP_CONNECTED, UDP_UNCONNECTED, UdpSocket};

fn read_c_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<usize> {
    line.clear();
    while line.len() < 511 {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let remaining = 511 - line.len();
        let newline = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|position| position + 1);
        let count = remaining.min(newline.unwrap_or(available.len()));
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline == Some(count) {
            break;
        }
    }
    Ok(line.len())
}

fn c_token(buffer: &[libc::c_char]) -> &[u8] {
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    // SAFETY: c_char and u8 have the same size and the returned slice stays within `buffer`.
    unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), length) }
}

fn parse_ulong(text: &[u8], base: libc::c_int) -> libc::c_ulong {
    let mut terminated = [0_u8; 65];
    let count = text.len().min(terminated.len() - 1);
    terminated[..count].copy_from_slice(&text[..count]);
    // SAFETY: `terminated` is NUL-terminated; no end pointer is requested.
    unsafe { libc::strtoul(terminated.as_ptr().cast(), std::ptr::null_mut(), base) }
}

fn parse_row(line: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u32, libc::c_ulong)> {
    let mut terminated = Vec::with_capacity(line.len() + 1);
    terminated.extend_from_slice(line);
    terminated.push(0);
    let mut local = [0 as libc::c_char; 64];
    let mut remote = [0 as libc::c_char; 64];
    let mut state: libc::c_uint = 0;
    let mut inode: libc::c_ulong = 0;
    // SAFETY: the format's four non-suppressed conversions exactly match the four writable
    // pointers. Both string destinations have the 64 bytes required by `%63s`.
    let converted = unsafe {
        libc::sscanf(
            terminated.as_ptr().cast(),
            c" %*u: %63s %63s %x %*s %*s %*s %*u %*u %lu".as_ptr(),
            local.as_mut_ptr(),
            remote.as_mut_ptr(),
            &mut state,
            &mut inode,
        )
    };
    if converted != 4 {
        return None;
    }
    Some((
        c_token(&local).to_vec(),
        c_token(&remote).to_vec(),
        state,
        inode,
    ))
}

pub(super) fn scan(
    reader: impl Read,
    protocol: u8,
    ipv6: bool,
    own_port: u16,
    addresses: &AddressContext<'_>,
    listeners: &mut ListenerTable,
    udp_sockets: &mut Vec<UdpSocket>,
) {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::with_capacity(511);
    match read_c_line(&mut reader, &mut line) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }
    loop {
        match read_c_line(&mut reader, &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some((mut local, remote, state, inode)) = parse_row(&line) else {
            continue;
        };
        let Some(local_separator) = local.iter().rposition(|byte| *byte == b':') else {
            continue;
        };
        let Some(remote_separator) = remote.iter().rposition(|byte| *byte == b':') else {
            continue;
        };
        let port = parse_ulong(&local[local_separator + 1..], 16);
        if port == 0 || port > u16::MAX.into() {
            continue;
        }
        local.truncate(local_separator);
        let remote_port = &remote[remote_separator + 1..];
        let remote_address = &remote[..remote_separator];

        let connected = if protocol == PROTOCOL_TCP {
            if state != TCP_LISTEN {
                continue;
            }
            false
        } else if state == UDP_CONNECTED {
            true
        } else {
            if state != UDP_UNCONNECTED
                || parse_ulong(remote_port, 16) != 0
                || remote_address.iter().any(|byte| *byte != b'0')
                || port == libc::c_ulong::from(own_port)
            {
                continue;
            }
            false
        };
        let port = port as u16;
        let families = addresses.reachable_families(&local, ipv6, protocol, port);
        if families == 0 {
            continue;
        }
        if protocol == PROTOCOL_TCP {
            listeners.add(protocol, port, families);
        } else if udp_sockets.len() < MAX_TRACKED {
            udp_sockets.push(UdpSocket {
                port,
                families,
                connected,
                inode,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::ingress::{FAMILY_IPV4, PROTOCOL_UDP, UDP_CONNECTED, UDP_UNCONNECTED};

    const HEADER: &[u8] = b"header\n";

    fn context() -> AddressContext<'static> {
        AddressContext {
            ipv6_dual_stack: true,
            wildcard_tcp: &[],
        }
    }

    fn scan_rows(
        rows: &[u8],
        protocol: u8,
        ipv6: bool,
        own_port: u16,
    ) -> (ListenerTable, Vec<UdpSocket>) {
        let mut input = HEADER.to_vec();
        input.extend_from_slice(rows);
        let mut listeners = ListenerTable::default();
        let mut udp = Vec::new();
        scan(
            input.as_slice(),
            protocol,
            ipv6,
            own_port,
            &context(),
            &mut listeners,
            &mut udp,
        );
        (listeners, udp)
    }

    fn row(local: &str, remote: &str, state: u32, inode: &str) -> Vec<u8> {
        format!(
            "  7: {local} {remote} {state:02X} 00000000:00000000 00:00000000 \
             00000000 0 0 {inode} trailing\n"
        )
        .into_bytes()
    }

    #[test]
    fn parses_odd_spacing_prefixes_and_ignores_trailing_fields() {
        let mut input = b"\t+7: 00000000:1F90 00000000:0000 0x0a a b c +0 -0 42 suffix\n".to_vec();
        input.extend_from_slice(b" 8: 00000000:1F91 00000000:0000 0A a b c 0 0 43\n");
        let (listeners, udp) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert!(udp.is_empty());
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x02\x06\x01\x1f\x90\x06\x01\x1f\x91"
        );
    }

    #[test]
    fn rejects_bad_states_zero_and_extreme_ports_and_addresses() {
        let mut input = Vec::new();
        input.extend(row("00000000:0000", "00000000:0000", TCP_LISTEN, "1"));
        input.extend(row("00000000:10000", "00000000:0000", TCP_LISTEN, "2"));
        input.extend(row("0000000G:1F90", "00000000:0000", TCP_LISTEN, "3"));
        input.extend(row("00000000:1F91", "00000000:0000", 1, "4"));
        let (listeners, udp) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert!(udp.is_empty());
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x00"
        );
    }

    #[test]
    fn udp_requires_an_unconnected_zero_peer_but_keeps_connected_rows() {
        let mut input = Vec::new();
        input.extend(row("00000000:1C21", "00000000:0000", UDP_UNCONNECTED, "10"));
        input.extend(row("00000000:1C22", "0100007F:0035", UDP_CONNECTED, "11"));
        input.extend(row("00000000:1C23", "00000000:0001", UDP_UNCONNECTED, "12"));
        input.extend(row("00000000:03FF", "00000000:0000", UDP_UNCONNECTED, "13"));
        let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
        assert_eq!(
            udp,
            vec![
                UdpSocket {
                    port: 7201,
                    families: FAMILY_IPV4,
                    connected: false,
                    inode: 10,
                },
                UdpSocket {
                    port: 7202,
                    families: FAMILY_IPV4,
                    connected: true,
                    inode: 11,
                },
            ]
        );
    }

    #[test]
    fn an_overlong_physical_line_is_split_like_fgets() {
        let mut input = vec![b'x'; 511];
        input.push(b'\n');
        input.extend_from_slice(&row("00000000:1F90", "00000000:0000", TCP_LISTEN, "1"));
        let (listeners, _) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x01\x06\x01\x1f\x90"
        );
    }

    #[test]
    fn buffered_reader_boundaries_do_not_split_short_lines() {
        let mut input = Vec::new();
        for index in 0..100 {
            input.extend(row(
                &format!("00000000:{:04X}", 20_000 + index),
                "00000000:0000",
                UDP_UNCONNECTED,
                &index.to_string(),
            ));
        }
        assert!(input.len() > 8 * 1024);
        let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
        assert_eq!(udp.len(), 100);
    }
}
