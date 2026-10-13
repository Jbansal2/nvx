//! Announces the guest's TCP and UDP listeners to the gateway of the portable
//! network profile, which publishes them to the host's private networks or,
//! for host-loopback ingress alone, on host loopback. The init system starts
//! it, as root, when the kernel command line carries `virtnet_ingress=allow`
//! or `virtnet_ingress=host-loopback`.
//!
//! Every 100 ms it reads the kernel's socket tables. A TCP socket in the
//! LISTEN state is a listener, and so is an unconnected UDP socket that
//! persists for a second, which skips short-lived client sockets, such as
//! those of DNS queries. Each UDP socket settles on its own, identified by the
//! kernel's inode for it, and stays announced while it exists, even once a
//! server connects it to its client; another socket that reuses a port, such
//! as a client's, settles anew, and a port announces the families of its
//! announced sockets. Sockets bound to loopback addresses, or to IPv6
//! link-local ones, are unreachable through the gateway. A TCP listener on
//! the unspecified IPv6 address also takes IPv4 connections unless the
//! kernel's socket diagnostics report it IPv6-only; a UDP socket there, which
//! the guest kernel's diagnostics do not cover, follows
//! `net.ipv6.bindv6only`. It sends the canonical set of listeners to UDP port
//! 1021 of the IPv4 gateway from a privileged port, which only root can bind,
//! whenever the set changes and at least every two seconds.
//!
//! An announcement is the magic `NVXL`, version 1, a flags byte whose bit 0
//! marks omitted listeners, a big-endian count, and that many entries in
//! increasing order of protocol and port: the IP protocol number, a family
//! mask (1 for IPv4, 2 for IPv6), and the big-endian port.
//!
//! `nvx-ingress test DIRECTORY` runs the numbered snapshots in `DIRECTORY`,
//! from 0, as successive scans instead, and prints each scan's time and
//! announcement in hexadecimal. A snapshot holds the socket tables under
//! `net/`, optionally `sys/net/ipv6/bindv6only`, optionally a socket
//! diagnostics dump in `diag`, and the scan time in milliseconds in `time`.

use std::io;
use std::process::ExitCode;

mod address;
mod collect;
mod diag;
mod encode;
mod sender;
mod table;
mod test_mode;

const ANNOUNCEMENT_PORT: u16 = 1021;
const FIRST_SOURCE_PORT: u16 = 1023;
const LAST_SOURCE_PORT: u16 = 512;
const MAX_ANNOUNCED: usize = 64;
const MAX_TRACKED: usize = 1024;
const SCAN_INTERVAL_MS: u64 = 100;
const REFRESH_INTERVAL_MS: u64 = 2_000;
const UDP_SETTLE_MS: u64 = 1_000;

const FAMILY_IPV4: u8 = 1;
const FAMILY_IPV6: u8 = 2;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const TCP_LISTEN: u32 = 0x0a;
const UDP_CONNECTED: u32 = 0x01;
const UDP_UNCONNECTED: u32 = 0x07;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Listener {
    protocol: u8,
    families: u8,
    port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UdpSocket {
    port: u16,
    families: u8,
    connected: bool,
    inode: libc::c_ulong,
}

/// Runs `nvx-ingress`.
pub fn main() -> ExitCode {
    super::sys::restore_sigpipe();
    let arguments = super::sys::args();
    let status = match arguments.as_slice() {
        [_, mode, directory] if mode.as_bytes() == b"test" => {
            test_mode::run(directory, &mut super::sys::Stdout::new())
        }
        [_, gateway] => sender::run(gateway, &mut io::stderr()),
        _ => usage(&mut io::stderr()),
    };
    ExitCode::from(status)
}

fn usage(err: &mut dyn io::Write) -> u8 {
    super::sys::report(err, &[b"usage: nvx-ingress GATEWAY_IPV4\n"]);
    2
}
