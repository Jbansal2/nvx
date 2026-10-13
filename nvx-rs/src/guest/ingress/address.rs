//! Parses the kernel's hexadecimal socket addresses and classifies their reachability.

use super::diag::WildcardListener;
use super::{FAMILY_IPV4, FAMILY_IPV6, PROTOCOL_TCP};

pub(super) struct AddressContext<'a> {
    pub(super) ipv6_dual_stack: bool,
    pub(super) wildcard_tcp: &'a [WildcardListener],
}

impl AddressContext<'_> {
    fn wildcard_families(&self, protocol: u8, port: u16) -> u8 {
        if protocol == PROTOCOL_TCP
            && let Some(listener) = self
                .wildcard_tcp
                .iter()
                .find(|listener| listener.port == port)
        {
            return if listener.dual_stack {
                FAMILY_IPV4 | FAMILY_IPV6
            } else {
                FAMILY_IPV6
            };
        }
        if self.ipv6_dual_stack {
            FAMILY_IPV4 | FAMILY_IPV6
        } else {
            FAMILY_IPV6
        }
    }

    /// Returns the families through which the kernel-rendered address is reachable.
    pub(super) fn reachable_families(
        &self,
        address: &[u8],
        ipv6: bool,
        protocol: u8,
        port: u16,
    ) -> u8 {
        if !ipv6 {
            let Some(value) = parse_hex_u32(address) else {
                return 0;
            };
            return if value.to_ne_bytes()[0] == 127 {
                0
            } else {
                FAMILY_IPV4
            };
        }

        if address.len() != 32 {
            return 0;
        }
        let mut bytes = [0_u8; 16];
        for (word, output) in address.chunks_exact(8).zip(bytes.chunks_exact_mut(4)) {
            let Some(value) = parse_hex_u32(word) else {
                return 0;
            };
            output.copy_from_slice(&value.to_ne_bytes());
        }
        if bytes.iter().all(|byte| *byte == 0) {
            return self.wildcard_families(protocol, port);
        }
        if bytes[..15].iter().all(|byte| *byte == 0) && bytes[15] == 1 {
            return 0;
        }
        if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
            return 0;
        }
        if bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
            return if bytes[12] == 127 { 0 } else { FAMILY_IPV4 };
        }
        FAMILY_IPV6
    }
}

fn parse_hex_u32(text: &[u8]) -> Option<u32> {
    if text.len() != 8 {
        return None;
    }
    let mut digits = [0_u8; 9];
    digits[..8].copy_from_slice(text);
    let mut end = std::ptr::null_mut();
    // SAFETY: errno is thread-local, `digits` is NUL-terminated, and `end` receives a pointer
    // into it.
    let parsed = unsafe {
        *libc::__errno_location() = 0;
        libc::strtoul(digits.as_ptr().cast(), &mut end, 16)
    };
    // SAFETY: the one-past pointer remains within `digits`.
    let expected_end = unsafe { digits.as_mut_ptr().add(8).cast() };
    if super::super::sys::Errno::last().0 != 0 || end != expected_end {
        None
    } else {
        Some(parsed as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::ingress::PROTOCOL_UDP;

    fn context<'a>(
        ipv6_dual_stack: bool,
        wildcard_tcp: &'a [WildcardListener],
    ) -> AddressContext<'a> {
        AddressContext {
            ipv6_dual_stack,
            wildcard_tcp,
        }
    }

    fn kernel_address(address: std::net::IpAddr) -> String {
        let octets = match address {
            std::net::IpAddr::V4(address) => address.octets().to_vec(),
            std::net::IpAddr::V6(address) => address.octets().to_vec(),
        };
        octets
            .chunks(4)
            .map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().unwrap())))
            .collect()
    }

    #[test]
    fn ipv4_requires_eight_hex_digits_and_excludes_loopback() {
        let context = context(true, &[]);
        assert_eq!(
            context.reachable_families(b"00000000", false, PROTOCOL_TCP, 80),
            FAMILY_IPV4
        );
        assert_eq!(
            context.reachable_families(b"010200C0", false, PROTOCOL_TCP, 80),
            FAMILY_IPV4
        );
        assert_eq!(
            context.reachable_families(b"0100007F", false, PROTOCOL_TCP, 80),
            0
        );
        for malformed in [b"0".as_slice(), b"000000000", b"0000000g"] {
            assert_eq!(
                context.reachable_families(malformed, false, PROTOCOL_TCP, 80),
                0
            );
        }
    }

    #[test]
    fn ipv6_excludes_loopback_link_local_and_mapped_loopback() {
        let context = context(true, &[]);
        for excluded in ["::1", "fe80::1", "febf::abcd", "::ffff:127.0.0.1"] {
            let address = kernel_address(excluded.parse().unwrap());
            assert_eq!(
                context.reachable_families(address.as_bytes(), true, PROTOCOL_TCP, 80),
                0,
                "{excluded}"
            );
        }
        let mapped = kernel_address("::ffff:192.0.2.2".parse().unwrap());
        assert_eq!(
            context.reachable_families(mapped.as_bytes(), true, PROTOCOL_TCP, 80),
            FAMILY_IPV4
        );
        let specific = kernel_address("fd00::a00:2".parse().unwrap());
        assert_eq!(
            context.reachable_families(specific.as_bytes(), true, PROTOCOL_TCP, 80),
            FAMILY_IPV6
        );
    }

    #[test]
    fn wildcard_tcp_uses_diagnostics_then_the_sysctl_default() {
        let listeners = [
            WildcardListener {
                port: 80,
                dual_stack: false,
                ipv6_only: true,
            },
            WildcardListener {
                port: 81,
                dual_stack: true,
                ipv6_only: true,
            },
        ];
        let wildcard = kernel_address("::".parse().unwrap());
        let context = context(false, &listeners);
        assert_eq!(
            context.reachable_families(wildcard.as_bytes(), true, PROTOCOL_TCP, 80),
            FAMILY_IPV6
        );
        assert_eq!(
            context.reachable_families(wildcard.as_bytes(), true, PROTOCOL_TCP, 81),
            FAMILY_IPV4 | FAMILY_IPV6
        );
        assert_eq!(
            context.reachable_families(wildcard.as_bytes(), true, PROTOCOL_TCP, 82),
            FAMILY_IPV6
        );
        assert_eq!(
            context.reachable_families(wildcard.as_bytes(), true, PROTOCOL_UDP, 81),
            FAMILY_IPV6
        );
    }
}
