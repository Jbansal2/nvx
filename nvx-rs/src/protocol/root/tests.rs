//! Tests of the boot tokens of a layered root. `tests/fixtures/root-tokens.json` holds the command
//! lines that every reader of the tokens must agree on, which the tests of the shell init replay
//! too.

use serde_json::Value;

use super::*;

/// The command lines that every reader of the boot tokens agrees on.
const FIXTURE: &str = include_str!("../../../tests/fixtures/root-tokens.json");
/// The filesystem UUID of the tests' EROFS images.
const EROFS_UUID: &str = "0123abcd-4567-89ef-0123-456789abcdef";
/// The disk GUID of the tests' GPT images.
const GPT_GUID: &str = "fedcba98-7654-3210-fedc-ba9876543210";

fn uuid(text: &str) -> Uuid {
    Uuid::parse(text).unwrap()
}

fn layout(image: RootImage, upper: RootUpper) -> RootLayout {
    RootLayout { image, upper }
}

fn parse(command_line: &str) -> Result<Option<RootLayout>, String> {
    RootLayout::parse(command_line.as_bytes()).map_err(ProtocolError::into_message)
}

/// Returns the layout of a case of the fixture, or `None` for its `null`.
fn recorded_layout(value: &Value) -> Option<RootLayout> {
    if value.is_null() {
        return None;
    }
    let format = ImageFormat::from_name(value["format"].as_str().unwrap()).unwrap();
    let identity = value["identity"].as_str().map(uuid);
    let upper = match value["upper"].as_str().unwrap() {
        "scratch" => RootUpper::Scratch,
        "ram" => RootUpper::Ram,
        other => panic!("the fixture names the unknown upper {other}"),
    };
    Some(layout(RootImage { format, identity }, upper))
}

#[test]
fn wire_values_keep_their_literals() {
    assert_eq!(DISTRO_MMIO_BASE, 0xd000_3000);
    assert_eq!(SCRATCH_MMIO_BASE, 0xd000_6000);
    assert_eq!(LAYER_TOKEN, "nvx_layer=");
    assert_eq!(SCRATCH_TOKEN, "nvx_scratch=");
    assert_eq!(RAM_UPPER_TOKEN, "nvx_overlay_upper=ramfs");
    assert_eq!(format!("{LAYER}="), LAYER_TOKEN);
    assert_eq!(format!("{SCRATCH}="), SCRATCH_TOKEN);
    assert_eq!(format!("{OVERLAY_UPPER}={RAM_UPPER}"), RAM_UPPER_TOKEN);
    assert_eq!(ImageFormat::Erofs.as_str(), "erofs");
    assert_eq!(ImageFormat::Gpt.to_string(), "gpt");
    assert_eq!(RootUpper::Scratch.as_str(), "scratch");
    assert_eq!(RootUpper::Ram.to_string(), "ram");
    for format in ImageFormat::ALL {
        assert_eq!(ImageFormat::from_name(format.as_str()), Some(format));
    }
    for name in ["", "EROFS", "Gpt", "erofs ", "ext4", "squashfs"] {
        assert_eq!(ImageFormat::from_name(name), None, "{name}");
    }
}

#[test]
fn every_layout_renders_its_tokens_and_reads_them_back() {
    let (erofs, gpt) = (Some(uuid(EROFS_UUID)), Some(uuid(GPT_GUID)));
    let scratch = "nvx_scratch=0xd0006000,ext4";
    let ram = "nvx_overlay_upper=ramfs";
    let cases = [
        (
            layout(RootImage::erofs(erofs), RootUpper::Scratch),
            format!("nvx_layer=distro,0xd0003000,erofs:{EROFS_UUID}"),
            scratch,
        ),
        (
            layout(RootImage::erofs(None), RootUpper::Scratch),
            "nvx_layer=distro,0xd0003000,erofs".to_owned(),
            scratch,
        ),
        (
            layout(RootImage::gpt(gpt), RootUpper::Scratch),
            format!("nvx_layer=distro,0xd0003000,gpt:{GPT_GUID}"),
            scratch,
        ),
        (
            layout(RootImage::gpt(None), RootUpper::Scratch),
            "nvx_layer=distro,0xd0003000,gpt".to_owned(),
            scratch,
        ),
        (
            layout(RootImage::erofs(erofs), RootUpper::Ram),
            format!("nvx_layer=distro,0xd0003000,erofs:{EROFS_UUID}"),
            ram,
        ),
        (
            layout(RootImage::erofs(None), RootUpper::Ram),
            "nvx_layer=distro,0xd0003000,erofs".to_owned(),
            ram,
        ),
        (
            layout(RootImage::gpt(gpt), RootUpper::Ram),
            format!("nvx_layer=distro,0xd0003000,gpt:{GPT_GUID}"),
            ram,
        ),
        (
            layout(RootImage::gpt(None), RootUpper::Ram),
            "nvx_layer=distro,0xd0003000,gpt".to_owned(),
            ram,
        ),
    ];
    for (expected, layer, upper) in cases {
        assert_eq!(expected.tokens(), [layer.clone(), upper.to_owned()]);
        // The guest reads the tokens in either order, among others.
        for command_line in [
            format!("{layer} {upper}"),
            format!("{upper} {layer}"),
            format!("quiet nvx_sandbox=1 {layer}\t{upper}\nnvx_entrypoint=/bin/sh"),
        ] {
            assert_eq!(parse(&command_line), Ok(Some(expected)), "{command_line}");
        }
    }
}

#[test]
fn the_longest_tokens_are_those_of_an_identified_image_over_scratch() {
    // The command-line budgets of launches count these bytes: the image's token takes at most 70
    // bytes, and the upper's 27.
    let longest = layout(RootImage::erofs(Some(uuid(EROFS_UUID))), RootUpper::Scratch).tokens();
    assert_eq!([longest[0].len(), longest[1].len()], [70, 27]);
    for format in ImageFormat::ALL {
        for identity in [None, Some(uuid(GPT_GUID))] {
            for upper in [RootUpper::Scratch, RootUpper::Ram] {
                let tokens = layout(RootImage { format, identity }, upper).tokens();
                assert!(tokens[0].len() <= longest[0].len(), "{tokens:?}");
                assert!(tokens[1].len() <= longest[1].len(), "{tokens:?}");
            }
        }
    }
}

#[test]
fn every_reader_parses_the_recorded_command_lines_alike() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    let mut names = std::collections::HashSet::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        assert!(names.insert(name), "the fixture repeats the case {name}");
        let command_line = case["command_line"].as_str().unwrap();
        let actual = parse(command_line);
        match case.get("error") {
            Some(error) => assert_eq!(actual, Err(error.as_str().unwrap().to_owned()), "{name}"),
            None => {
                let expected = recorded_layout(&case["layout"]);
                assert_eq!(actual, Ok(expected), "{name}");
                // What the guest reads, the host renders.
                if let Some(expected) = expected {
                    assert_eq!(
                        parse(&expected.tokens().join(" ")),
                        Ok(Some(expected)),
                        "{name}"
                    );
                }
            }
        }
    }
    // The corpus holds every combination of format, identity, and upper.
    for format in ["erofs", "gpt"] {
        for identity in [true, false] {
            for upper in ["scratch", "ram"] {
                assert!(
                    cases.iter().any(|case| {
                        let layout = &case["layout"];
                        layout["format"] == format
                            && layout["identity"].is_string() == identity
                            && layout["upper"] == upper
                    }),
                    "the fixture lacks {format} with identity {identity} over {upper}"
                );
            }
        }
    }
}

#[test]
fn parsing_reports_bytes_that_are_not_text() {
    assert_eq!(
        parse("nvx_layer=distro,0xd0003000,erofs:\u{e9} nvx_scratch=0xd0006000,ext4"),
        Err(
            "the nvx_layer kernel parameter names an invalid EROFS filesystem UUID: '\\xc3\\xa9'"
                .to_owned()
        )
    );
    assert_eq!(
        RootLayout::parse(b"nvx_layer=distro,0xd0003000,\xff nvx_scratch=0xd0006000,ext4")
            .unwrap_err()
            .message(),
        "the nvx_layer kernel parameter names the unsupported image format '\\xff'"
    );
    // Other tokens may hold any bytes.
    assert_eq!(
        RootLayout::parse(
            b"\xff\xfe=\x00 nvx_layer=distro,0xd0003000,erofs nvx_scratch=0xd0006000,ext4"
        )
        .unwrap(),
        Some(layout(RootImage::erofs(None), RootUpper::Scratch))
    );
}

#[test]
fn device_tokens_name_their_base_as_the_kernel_reads_it() {
    for (value, base) in [
        ("0x1000@0xd0006000:11", Some(SCRATCH_MMIO_BASE)),
        ("4K@0XD0006000:11:3", Some(SCRATCH_MMIO_BASE)),
        ("4k@0xd0006000:11", Some(SCRATCH_MMIO_BASE)),
        ("4096@3489685504:11", Some(SCRATCH_MMIO_BASE)),
        ("4096@032000060000:11", Some(SCRATCH_MMIO_BASE)),
        ("@0xd0006000:11", Some(SCRATCH_MMIO_BASE)),
        ("0x1000@ \t0xd0006000:11", Some(SCRATCH_MMIO_BASE)),
        // The kernel negates a base after a minus sign, and wraps one past 64 bits.
        ("0x1000@-0xffffffff2fffa000:11", Some(SCRATCH_MMIO_BASE)),
        ("0x1000@0x100000000d0006000:11", Some(SCRATCH_MMIO_BASE)),
        ("0x1000@0x10000000000000000:11", Some(0)),
        ("0x1000@-1:11", Some(u64::MAX)),
        ("0x1000@0:1", Some(0)),
        ("0x1000@0xd0003000:4", Some(DISTRO_MMIO_BASE)),
        ("0x1000@0xd0006000", None),
        ("0xd0006000:11", None),
        ("0x1000@:11", None),
        ("0x1000@0x:11", None),
        ("0x1000@-:11", None),
        ("0x1000@--1:11", None),
        ("0x1000@+3489685504:11", None),
        ("0x1000@0xd0006000x:11", None),
        ("0x1000@0xd0006000 :11", None),
        ("0x1000@09:11", None),
        ("4KB@0xd0006000:11", None),
        ("K@0xd0006000:11", None),
        ("x@0xd0006000:11", None),
    ] {
        assert_eq!(device_base(value.as_bytes()), base, "{value}");
    }
    for name in ["virtio_mmio.device", "virtio-mmio.device"] {
        assert!(is_virtio_mmio_device(name.as_bytes()), "{name}");
    }
    for name in [
        "virtio_mmio_device",
        "virtio_mmio.devices",
        "virtio.mmio.device",
        "",
    ] {
        assert!(!is_virtio_mmio_device(name.as_bytes()), "{name}");
    }
}

/// Checks that the kernel splits `command_line` into the parameters `expected`.
fn assert_parameters(command_line: &[u8], expected: &[(&str, Option<&str>)]) {
    let expected: Vec<_> = expected
        .iter()
        .map(|&(name, value)| (name.as_bytes(), value.map(str::as_bytes)))
        .collect();
    assert_eq!(
        kernel_parameters(command_line),
        expected,
        "{}",
        command_line.escape_ascii()
    );
}

#[test]
fn command_lines_split_into_parameters_as_the_kernel_splits_them() {
    assert_parameters(b"a b=c", &[("a", None), ("b", Some("c"))]);
    assert_parameters(
        b" a\x0bb\x0cc\rd\xa0e\tf\ng=h ",
        &[
            ("a", None),
            ("b", None),
            ("c", None),
            ("d", None),
            ("e", None),
            ("f", None),
            ("g", Some("h")),
        ],
    );
    assert_parameters(b"\"a b\" c", &[("a b", None), ("c", None)]);
    assert_parameters(b"\"a=b c\" d", &[("a", Some("b c")), ("d", None)]);
    assert_parameters(b"a=\"b c\" d", &[("a", Some("b c")), ("d", None)]);
    assert_parameters(b"a=\"b c", &[("a", Some("b c"))]);
    assert_parameters(b"a=\"\" b=c\"", &[("a", Some("")), ("b", Some("c\""))]);
    assert_parameters(b"x=\"a b=c\"", &[("x", Some("a b=c"))]);
    assert_parameters(b"=a=b", &[("=a", Some("b"))]);
    assert_parameters(b"\"", &[("", None)]);
    // The kernel stops at a NUL, and at a `--` without a value.
    assert_parameters(b"a\0b", &[("a", None)]);
    assert_parameters(b"a -- b", &[("a", None)]);
    assert_parameters(b"a \"--\" b", &[("a", None)]);
    assert_parameters(b"a --=1 b", &[("a", None), ("--", Some("1")), ("b", None)]);
}

#[test]
fn uuids_take_only_their_canonical_text() {
    let parsed = uuid(EROFS_UUID);
    assert_eq!(
        parsed.as_bytes(),
        &[
            0x01, 0x23, 0xab, 0xcd, 0x45, 0x67, 0x89, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ]
    );
    assert_eq!(parsed.to_string(), EROFS_UUID);
    assert_eq!(format!("{parsed:?}"), format!("Uuid({EROFS_UUID})"));
    assert_eq!(Uuid::from_bytes(*parsed.as_bytes()), parsed);
    assert_eq!(EROFS_UUID.parse::<Uuid>(), Ok(parsed));
    assert_eq!(
        Uuid::from_bytes([0; 16]).to_string(),
        "00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(
        Uuid::from_bytes([0xff; 16]).to_string(),
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    );
    for text in [
        "",
        "0123ABCD-4567-89EF-0123-456789ABCDEF",
        "0123abcd-4567-89ef-0123-456789abcdeF",
        "{0123abcd-4567-89ef-0123-456789abcdef}",
        "urn:uuid:0123abcd-4567-89ef-0123-456789abcdef",
        "0123abcd456789ef0123456789abcdef",
        "0123abcd-4567-89ef-0123-456789abcde",
        "0123abcd-4567-89ef-0123-456789abcdef0",
        "0123abcd-4567-89ef-0123-456789abcdeg",
        "0123abcd-4567-89ef-0123+456789abcdef",
        "0123abcd-4567-89ef-01234-56789abcdef",
        "0123abcd-4567-89ef-0123-456789abcd-f",
        " 123abcd-4567-89ef-0123-456789abcdef",
        "-123abcd-4567-89ef-0123-456789abcdef",
    ] {
        assert_eq!(Uuid::parse(text), None, "{text}");
        assert_eq!(
            text.parse::<Uuid>().unwrap_err().message(),
            format!("'{text}' is not a UUID in its canonical text")
        );
    }
    assert_eq!(
        Uuid::parse(b"0123abcd-4567-89ef-0123-456789abcd\xff\xff"),
        None
    );
}
