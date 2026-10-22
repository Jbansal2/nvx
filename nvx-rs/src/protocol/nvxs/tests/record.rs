//! Records against the broker's golden vectors and every payload rule, the sequence numbers that a
//! direction's records take, and the parser across partial reads and record boundaries.

use super::*;

// The broker's language-neutral vectors from OpenVMM's control-session protocol tests: one record
// of each type, with the instance ID 00..0f, epoch 7, and sequence 9 after the bootstrap. Both
// implementations must agree on every byte.
const GOLDEN: [(RecordType, &str); 9] = [
    (
        RecordType::GuestAttach,
        "4e56585301000100000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        RecordType::HostAttach,
        concat!(
            "4e56585301000200000000000000000000000000000000000000000000000000000000000000000020000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
    ),
    (
        RecordType::Reset,
        "4e56585301000300000102030405060708090a0b0c0d0e0f0700000000000000090000000000000000000000",
    ),
    (
        RecordType::Ack,
        concat!(
            "4e56585301000400000102030405060708090a0b0c0d0e0f0700000000000000090000000000000004000000",
            "0a004000",
        ),
    ),
    (
        RecordType::Data,
        concat!(
            "4e56585301000500000102030405060708090a0b0c0d0e0f0700000000000000090000000000000008000000",
            "4e5658534e565853",
        ),
    ),
    (
        RecordType::Wait,
        "4e56585301000600000102030405060708090a0b0c0d0e0f0700000000000000090000000000000000000000",
    ),
    (
        RecordType::Ready,
        "4e56585301000700000102030405060708090a0b0c0d0e0f0700000000000000090000000000000000000000",
    ),
    (
        RecordType::Error,
        concat!(
            "4e56585301000800000102030405060708090a0b0c0d0e0f0700000000000000090000000000000004000000",
            "01000000",
        ),
    ),
    (
        RecordType::Credit,
        concat!(
            "4e56585301000900000102030405060708090a0b0c0d0e0f0700000000000000090000000000000004000000",
            "00000100",
        ),
    ),
];

#[test]
fn records_match_the_brokers_golden_vectors() {
    let instance: [u8; 16] = core::array::from_fn(|index| index as u8);
    for (record_type, vector) in GOLDEN {
        let encoded = bytes(vector);
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed.record_type(), record_type);
        assert_eq!(RecordType::from_code(record_type.code()), Some(record_type));
        let identity = (parsed.instance_id(), parsed.epoch(), parsed.sequence());
        if record_type.is_bootstrap() {
            assert_eq!(identity, ([0; 16], 0, 0));
        } else {
            assert_eq!(identity, (instance, 7, 9));
        }
        match record_type {
            RecordType::HostAttach => {
                let capability: [u8; CAPABILITY_LEN] = core::array::from_fn(|i| i as u8);
                assert_eq!(parsed.payload(), capability);
            }
            RecordType::Ack => assert_eq!(parsed.window(), Some(OUTER_MAX_RECEIVE_WINDOW)),
            RecordType::Data => assert_eq!(parsed.payload(), b"NVXSNVXS"),
            RecordType::Error => assert_eq!(parsed.error_code(), Some(ErrorCode::Authentication)),
            RecordType::Credit => assert_eq!(parsed.credit(), Some(OUTER_MIN_RECEIVE_WINDOW)),
            _ => assert!(parsed.payload().is_empty()),
        }
        let mut output = Vec::new();
        encode_record(
            record_type,
            &parsed.instance_id(),
            parsed.epoch(),
            parsed.sequence(),
            parsed.payload(),
            &mut output,
        )
        .unwrap();
        assert_eq!(hex(&output), vector, "{record_type}");
    }
    assert_eq!(RecordType::from_code(0), None);
    assert_eq!(RecordType::from_code(10), None);
}

/// A valid payload of `length` bytes for `record_type`: the smallest window of an ACK, one byte of
/// a CREDIT, the authentication code of an ERROR, and zeros otherwise.
fn valid_payload(record_type: RecordType, length: usize) -> Vec<u8> {
    match record_type {
        RecordType::Ack => OUTER_MIN_RECEIVE_WINDOW.to_le_bytes().to_vec(),
        RecordType::Credit => 1u32.to_le_bytes().to_vec(),
        RecordType::Error => ErrorCode::Authentication.code().to_le_bytes().to_vec(),
        _ => vec![0; length],
    }
}

#[test]
fn each_record_type_allows_only_its_payload_lengths() {
    let cases: [(RecordType, &[usize], &[usize]); 9] = [
        (RecordType::GuestAttach, &[0], &[1, 4, CAPABILITY_LEN]),
        (
            RecordType::HostAttach,
            &[CAPABILITY_LEN],
            &[0, 4, CAPABILITY_LEN - 1, CAPABILITY_LEN + 1],
        ),
        (RecordType::Reset, &[0], &[1, 4]),
        (RecordType::Ack, &[4], &[0, 3, 5]),
        (
            RecordType::Data,
            &[1, 2, OUTER_MAX_PAYLOAD - 1, OUTER_MAX_PAYLOAD],
            &[0, OUTER_MAX_PAYLOAD + 1],
        ),
        (RecordType::Wait, &[0], &[1, 4]),
        (RecordType::Ready, &[0], &[1, 4]),
        (RecordType::Error, &[4], &[0, 3, 5]),
        (RecordType::Credit, &[4], &[0, 3, 5]),
    ];
    for (record_type, valid, invalid) in cases {
        let identity = if record_type.is_bootstrap() {
            NONE
        } else {
            IDENTITY
        };
        for &length in valid {
            assert!(record_type.allows_length(length), "{record_type} {length}");
            let payload = valid_payload(record_type, length);
            let parsed = parse(&record(record_type, identity, 0, &payload)).unwrap();
            assert_eq!(parsed.record_type(), record_type);
            assert_eq!(parsed.payload(), payload);
        }
        for &length in invalid {
            assert!(!record_type.allows_length(length), "{record_type} {length}");
            let expected = RecordError::Length {
                record_type,
                length,
            };
            let mut output = vec![0xee];
            let encoded = encode_record(
                record_type,
                &identity.instance_id,
                identity.epoch,
                0,
                &vec![1; length],
                &mut output,
            );
            assert_eq!(encoded, Err(expected.clone()));
            assert_eq!(output, [0xee], "a failed encoding leaves the output alone");
            // The parser refuses the header before any payload byte arrives, and allocates no
            // payload buffer.
            let header = raw_header(record_type.code(), identity, 0, length as u32);
            let mut parser = RecordParser::new();
            let last = OUTER_HEADER_LEN - 1;
            assert_eq!(parser.push(&header[..last]), Ok((last, None)));
            assert_eq!(parser.push(&header[last..]), Err(expected));
            assert_eq!((parser.buffered(), parser.payload_capacity()), (0, 0));
        }
    }
    // So is a DATA header that declares the largest length that the field holds.
    let mut parser = RecordParser::new();
    let header = raw_header(RecordType::Data.code(), IDENTITY, 0, u32::MAX);
    let expected = RecordError::Length {
        record_type: RecordType::Data,
        length: u32::MAX as usize,
    };
    assert_eq!(parser.push(&header), Err(expected));
    assert_eq!(parser.payload_capacity(), 0);
}

#[test]
fn headers_are_checked_before_any_payload_byte() {
    let valid = record(RecordType::Data, IDENTITY, 0, b"x");
    let cases = [
        (0, b'X', RecordError::Magic(*b"XVXS")),
        (3, 0, RecordError::Magic(*b"NVX\0")),
        (4, 2, RecordError::Version(2)),
        (5, 1, RecordError::Version(0x0101)),
        (6, 0, RecordError::Type(0)),
        (6, 10, RecordError::Type(10)),
        (6, 0xff, RecordError::Type(0xff)),
        (7, 1, RecordError::Flags(1)),
        (7, 0x80, RecordError::Flags(0x80)),
    ];
    for (offset, value, expected) in cases {
        let mut malformed = valid.clone();
        malformed[offset] = value;
        let mut parser = RecordParser::new();
        assert_eq!(parser.push(&malformed[..OUTER_HEADER_LEN]), Err(expected));
        assert_eq!(parser.payload_capacity(), 0);
    }
}

#[test]
fn bootstrap_records_carry_no_identity() {
    let mut last_byte = [0; 16];
    last_byte[15] = 1;
    let identities = [
        ([1; 16], 0, 0),
        (last_byte, 0, 0),
        ([0; 16], 1, 0),
        ([0; 16], 0, 1),
        ([0; 16], 0, u64::MAX),
    ];
    for record_type in [RecordType::GuestAttach, RecordType::HostAttach] {
        let payload = if record_type == RecordType::HostAttach {
            vec![1; CAPABILITY_LEN]
        } else {
            Vec::new()
        };
        let expected = RecordError::BootstrapIdentity(record_type);
        for (instance_id, epoch, sequence) in identities {
            let mut output = Vec::new();
            let encoded = encode_record(
                record_type,
                &instance_id,
                epoch,
                sequence,
                &payload,
                &mut output,
            );
            assert_eq!(encoded, Err(expected.clone()));
            assert!(output.is_empty());
            let identity = Identity { instance_id, epoch };
            let mut stream =
                raw_header(record_type.code(), identity, sequence, payload.len() as u32);
            stream.extend_from_slice(&payload);
            assert_eq!(RecordParser::new().push(&stream), Err(expected.clone()));
        }
    }
}

#[test]
fn error_records_carry_the_authentication_code() {
    let parsed = parse(&record(RecordType::Error, IDENTITY, 0, &1u32.to_le_bytes())).unwrap();
    assert_eq!(parsed.error_code(), Some(ErrorCode::Authentication));
    assert_eq!(ErrorCode::from_code(1), Some(ErrorCode::Authentication));
    assert_eq!(ErrorCode::Authentication.code(), 1);
    for code in [0, 2, 3, 4, 5, 6, u32::MAX] {
        assert_eq!(ErrorCode::from_code(code), None);
        let mut output = Vec::new();
        let encoded = encode_record(
            RecordType::Error,
            &INSTANCE,
            1,
            0,
            &code.to_le_bytes(),
            &mut output,
        );
        assert_eq!(encoded, Err(RecordError::ErrorCode(code)));
        let mut stream = raw_header(RecordType::Error.code(), IDENTITY, 0, 4);
        stream.extend_from_slice(&code.to_le_bytes());
        let expected = Err(RecordError::ErrorCode(code));
        assert_eq!(RecordParser::new().push(&stream), expected);
    }
    // Only an ERROR carries a code, only an ACK a window, and only a CREDIT a byte count.
    let ack = parse(&sample(RecordType::Ack, IDENTITY, 0)).unwrap();
    assert_eq!((ack.error_code(), ack.credit()), (None, None));
    let credit = parse(&sample(RecordType::Credit, IDENTITY, 0)).unwrap();
    assert_eq!((credit.error_code(), credit.window()), (None, None));
    assert_eq!(parsed.window(), None);
}

#[test]
fn acks_and_credits_stay_within_the_window_bounds() {
    let cases = [
        (RecordType::Ack, 0, false),
        (RecordType::Ack, OUTER_MIN_RECEIVE_WINDOW - 1, false),
        (RecordType::Ack, OUTER_MIN_RECEIVE_WINDOW, true),
        (RecordType::Ack, OUTER_MAX_RECEIVE_WINDOW, true),
        (RecordType::Ack, OUTER_MAX_RECEIVE_WINDOW + 1, false),
        (RecordType::Credit, 0, false),
        (RecordType::Credit, 1, true),
        (RecordType::Credit, OUTER_MAX_RECEIVE_WINDOW, true),
        (RecordType::Credit, OUTER_MAX_RECEIVE_WINDOW + 1, false),
        (RecordType::Credit, u32::MAX, false),
    ];
    for (record_type, value, valid) in cases {
        let error = if record_type == RecordType::Ack {
            RecordError::ReceiveWindow(value)
        } else {
            RecordError::Credit(value)
        };
        let mut output = Vec::new();
        let encoded = encode_record(
            record_type,
            &INSTANCE,
            1,
            0,
            &value.to_le_bytes(),
            &mut output,
        );
        let mut stream = raw_header(record_type.code(), IDENTITY, 0, 4);
        stream.extend_from_slice(&value.to_le_bytes());
        let parsed = RecordParser::new().push(&stream);
        if valid {
            assert_eq!(encoded, Ok(()));
            let parsed = parsed.unwrap().1.unwrap();
            assert_eq!(parsed.window().or(parsed.credit()), Some(value));
        } else {
            assert_eq!(encoded, Err(error.clone()));
            assert_eq!(parsed, Err(error));
        }
    }
}

#[test]
fn a_direction_advances_its_sequence_only_past_the_records_that_it_encodes() {
    let mut output = Vec::new();
    let mut sequence = 7;
    let taken = encode_data(&IDENTITY, &mut sequence, b"xy", &mut output);
    assert_eq!(taken, Ok(2));
    assert_eq!((records(&output)[0].sequence(), sequence), (7, 8));
    // A malformed record, or one that would take the last sequence number, takes none.
    let malformed = encode_data(&IDENTITY, &mut sequence, &[], &mut output);
    let length = RecordError::Length {
        record_type: RecordType::Data,
        length: 0,
    };
    assert_eq!(malformed, Err(SessionError::Record(length)));
    let mut last = u64::MAX;
    let overflowed = encode_data(&IDENTITY, &mut last, b"x", &mut output);
    let overflow = SessionError::SequenceOverflow(RecordType::Data);
    assert_eq!(overflowed, Err(overflow));
    assert_eq!((sequence, last, records(&output).len()), (8, u64::MAX, 1));
}

#[test]
fn the_parser_returns_the_same_records_for_every_split_of_a_stream() {
    let stream = host_stream();
    let expected = records(&stream);
    assert_eq!(expected.len(), 6);
    for cut in 0..=stream.len() {
        let mut parser = RecordParser::new();
        let parsed = feed(
            |piece| parser.push(piece).map_err(SessionError::from),
            &stream,
            &[cut],
        )
        .unwrap();
        assert_eq!(parsed, expected, "split at {cut}");
    }
    let mut parser = RecordParser::new();
    let cuts: Vec<usize> = (1..stream.len()).collect();
    let parsed = feed(
        |piece| parser.push(piece).map_err(SessionError::from),
        &stream,
        &cuts,
    )
    .unwrap();
    assert_eq!(parsed, expected, "one byte at a time");
}

#[test]
fn the_parser_stops_at_each_record_boundary() {
    let first = record(RecordType::Credit, IDENTITY, 0, &17u32.to_le_bytes());
    let second = record(RecordType::Data, IDENTITY, 1, b"xNVXSy");
    let stream = [first.as_slice(), &second].concat();
    let mut parser = RecordParser::new();
    let (consumed, parsed) = parser.push(&stream).unwrap();
    assert_eq!(consumed, first.len());
    assert_eq!(parsed.unwrap().credit(), Some(17));
    let (consumed, parsed) = parser.push(&stream[first.len()..]).unwrap();
    assert_eq!(consumed, second.len());
    assert_eq!(parsed.unwrap().payload(), b"xNVXSy");
    assert_eq!(parser.push(&[]), Ok((0, None)));
}

#[test]
fn the_parser_holds_at_most_one_record() {
    let encoded = record(RecordType::Data, IDENTITY, 0, &[7; OUTER_MAX_PAYLOAD]);
    let mut parser = RecordParser::new();
    assert_eq!((parser.needed(), parser.buffered()), (OUTER_HEADER_LEN, 0));
    assert_eq!(parser.push(&encoded[..10]), Ok((10, None)));
    assert_eq!(
        (
            parser.needed(),
            parser.buffered(),
            parser.payload_capacity()
        ),
        (OUTER_HEADER_LEN - 10, 10, 0)
    );
    let header_rest = OUTER_HEADER_LEN - 10;
    assert_eq!(
        parser.push(&encoded[10..OUTER_HEADER_LEN]),
        Ok((header_rest, None))
    );
    // The payload buffer has exactly the length that the validated header declares.
    assert_eq!(
        (
            parser.needed(),
            parser.buffered(),
            parser.payload_capacity()
        ),
        (OUTER_MAX_PAYLOAD, OUTER_HEADER_LEN, OUTER_MAX_PAYLOAD)
    );
    let last = encoded.len() - 1;
    assert_eq!(
        parser.push(&encoded[OUTER_HEADER_LEN..last]),
        Ok((last - OUTER_HEADER_LEN, None))
    );
    assert_eq!((parser.needed(), parser.buffered()), (1, last));
    // Bytes after the record stay with the caller.
    let rest = [&encoded[last..], &[0xab; 100][..]].concat();
    let (consumed, parsed) = parser.push(&rest).unwrap();
    assert_eq!(consumed, 1);
    assert_eq!(parsed.unwrap().payload(), [7; OUTER_MAX_PAYLOAD]);
    assert_eq!(
        (
            parser.needed(),
            parser.buffered(),
            parser.payload_capacity()
        ),
        (OUTER_HEADER_LEN, 0, 0)
    );
}

#[test]
fn a_malformed_record_ends_the_stream() {
    let valid = record(RecordType::Data, IDENTITY, 0, b"NVXS");
    // The parser does not look for the magic of a later record.
    let stream = [&[0; OUTER_HEADER_LEN][..], &valid].concat();
    let mut parser = RecordParser::new();
    assert_eq!(parser.push(&stream), Err(RecordError::Magic([0; 4])));
    assert_eq!((parser.needed(), parser.buffered()), (OUTER_HEADER_LEN, 0));
    assert_eq!(parser.push(&valid), Err(RecordError::Magic([0; 4])));
    // A payload with an invalid value ends it once the payload completes.
    let mut parser = RecordParser::new();
    let mut stream = raw_header(RecordType::Credit.code(), IDENTITY, 0, 4);
    stream.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(parser.push(&stream[..46]), Ok((46, None)));
    assert_eq!(parser.push(&stream[46..]), Err(RecordError::Credit(0)));
    assert_eq!(parser.push(&valid), Err(RecordError::Credit(0)));
}

#[test]
fn debug_output_shows_no_payload_bytes() {
    let capability = *b"NVX-CAPABILITY-SECRET-0123456789";
    let encoded = record(RecordType::HostAttach, NONE, 0, &capability);
    let parsed = parse(&encoded).unwrap();
    let mut parser = RecordParser::new();
    parser.push(&encoded[..OUTER_HEADER_LEN + 8]).unwrap();
    let decimal = format!("{:?}", &capability[..4]);
    for debug in [format!("{parsed:?}"), format!("{parser:?}")] {
        assert!(!debug.contains("CAPABILITY"), "{debug}");
        assert!(!debug.contains(decimal.trim_matches(['[', ']'])), "{debug}");
    }
}

#[test]
fn errors_describe_the_violation() {
    let cases = [
        (
            SessionError::from(RecordError::Magic(*b"XVXS")),
            "NVXS record has an invalid magic, 0x58565853",
        ),
        (
            RecordError::Length {
                record_type: RecordType::Data,
                length: 0,
            }
            .into(),
            "NVXS DATA record has an invalid payload length of 0 bytes",
        ),
        (
            SessionError::Sequence {
                expected: 2,
                actual: 1,
            },
            "NVXS record has sequence 1 instead of 2",
        ),
        (
            SessionError::Unexpected(RecordType::GuestAttach),
            "unexpected NVXS GUEST_ATTACH record",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
    let error = SessionError::from(RecordError::Version(2));
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "NVXS record has an unsupported version 2"
    );
}
