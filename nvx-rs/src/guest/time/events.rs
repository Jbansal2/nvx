//! Time-ABI output records and their byte-exact escaping.

use super::Phase;

pub(crate) const EVENT_MAX: usize = 512;
pub(crate) const DETAIL_MAX: usize = 384;

/// Escapes a diagnostic as the time ABI does, without splitting an escape at `limit`.
pub(crate) fn escape_text(text: &[u8], limit: usize) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(text.len().min(limit));
    for &byte in text {
        if byte == 0 {
            break;
        }
        let piece: &[u8] = match byte {
            b'"' => br#"\""#,
            b'\\' => br#"\\"#,
            0x20..=0x7e => {
                if escaped.len() == limit {
                    break;
                }
                escaped.push(byte);
                continue;
            }
            _ => &[],
        };
        if piece.is_empty() {
            if escaped.len() + 4 > limit {
                break;
            }
            const HEX: &[u8; 16] = b"0123456789abcdef";
            escaped.extend_from_slice(b"\\x");
            escaped.push(HEX[usize::from(byte >> 4)]);
            escaped.push(HEX[usize::from(byte & 0x0f)]);
        } else {
            if escaped.len() + piece.len() > limit {
                break;
            }
            escaped.extend_from_slice(piece);
        }
    }
    escaped
}

/// Formats one conformance or report-only violation event.
pub(crate) fn format_event(
    report_only: bool,
    code: &[u8],
    source: &[u8],
    phase: Phase,
    generation: u32,
    boottime_ns: i64,
    detail: &[u8],
) -> Vec<u8> {
    let prefix_name = if report_only {
        b"NVX-TIME-REPORT".as_slice()
    } else {
        b"NVX-TIME-ABI".as_slice()
    };
    let mut line = Vec::with_capacity(EVENT_MAX + 1);
    line.extend_from_slice(prefix_name);
    line.extend_from_slice(b"-VIOLATION: v=1 code=");
    line.extend_from_slice(code);
    line.extend_from_slice(b" source=");
    line.extend_from_slice(source);
    line.extend_from_slice(b" phase=");
    line.extend_from_slice(phase.name().as_bytes());
    line.extend_from_slice(b" generation=");
    line.extend_from_slice(generation.to_string().as_bytes());
    line.extend_from_slice(b" boottime_ns=");
    line.extend_from_slice(boottime_ns.to_string().as_bytes());
    line.extend_from_slice(b" detail=\"");
    let available = EVENT_MAX.saturating_sub(line.len() + 2);
    line.extend_from_slice(&escape_text(detail, available));
    line.extend_from_slice(b"\"\n");
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_is_byte_oriented_and_never_splits_an_escape() {
        assert_eq!(escape_text(b"a\"\\\x01\xff", 32), br#"a\"\\\x01\xff"#);
        assert_eq!(escape_text(b"\x01\x02", 7), br#"\x01"#);
    }

    #[test]
    fn event_has_the_abi_limit() {
        let line = format_event(
            false,
            b"G_HUNG_TASK",
            b"watcher",
            Phase::Runtime,
            0,
            1,
            &[2; 400],
        );
        assert!(line.len() <= EVENT_MAX);
        assert!(line.ends_with(b"\\x02\"\n"));
    }
}
