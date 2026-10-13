//! Pure decoders, parsers, and arithmetic of the guest time ABI.

use std::fmt::Write as _;
use std::io::Write as _;

use super::MAX_CPUS;

pub(crate) const PACKET_HEADER_SIZE: usize = 32;
pub(crate) const PACKET_RANGE_SIZE: usize = 16;
pub(crate) const PACKET_ENTROPY_SIZE: usize = 64;
pub(crate) const PACKET_MAX_RANGES: usize = 255;
pub(crate) const PACKET_MAX_SIZE: usize =
    PACKET_HEADER_SIZE + PACKET_MAX_RANGES * PACKET_RANGE_SIZE + PACKET_ENTROPY_SIZE;
pub(crate) const SAMPLE_SIZE: usize = 16;
pub(crate) const GENERATION_ID_SIZE: usize = 16;

const PACKET_MEMORY_TARGET: u8 = 0x02;
const PACKET_KNOWN_FLAGS: u8 = 0x0f;
const SAMPLE_TEST_HOOKS: u8 = 0x08;
const RATE_DEVIATION_LIMIT: i32 = 16_384_000;
const FREQUENCY_LIMIT: i64 = 500 << 16;
const DOWNTIME_LIMIT_NS: u64 = 2_592_000 * 1_000_000_000;
const STEP_THRESHOLD_NS: i64 = 128_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestorePacket {
    pub(crate) flags: u8,
    pub(crate) online_vp_count: u8,
    pub(crate) range_count: u8,
    pub(crate) generation: u32,
    pub(crate) rate_deviation: i32,
    pub(crate) downtime_ns: u64,
    pub(crate) utc_ns: u64,
    pub(crate) ranges: Vec<(u64, u64)>,
    pub(crate) entropy: [u8; PACKET_ENTROPY_SIZE],
}

impl RestorePacket {
    pub(crate) fn parse_header(bytes: &[u8]) -> Result<Self, String> {
        let bytes = bytes
            .get(..PACKET_HEADER_SIZE)
            .ok_or_else(|| "restore packet magic is 000000".to_owned())?;
        if &bytes[..3] != b"OVR" {
            return Err(format!(
                "restore packet magic is {:02x}{:02x}{:02x}",
                bytes[0], bytes[1], bytes[2]
            ));
        }
        if bytes[3] != 4 {
            return Err(format!("restore packet version is {}", bytes[3]));
        }
        let flags = bytes[4];
        let online_vp_count = bytes[5];
        let range_count = bytes[6];
        let generation = read_le32(&bytes[8..]);
        let rate_deviation = read_le32(&bytes[12..]) as i32;
        let downtime_ns = read_le64(&bytes[16..]);
        let utc_ns = read_le64(&bytes[24..]);
        if flags & !PACKET_KNOWN_FLAGS != 0 {
            return Err(format!(
                "restore packet flags 0x{flags:02x} set reserved bits"
            ));
        }
        if !matches!(online_vp_count, 0 | 1 | 2 | 4 | 8) {
            return Err(format!(
                "restore packet online VP count is {online_vp_count}"
            ));
        }
        if flags & PACKET_MEMORY_TARGET == 0 && range_count != 0 {
            return Err(format!(
                "restore packet has {range_count} memory ranges without a memory target"
            ));
        }
        if bytes[7] != 0 {
            return Err(format!("restore packet reserved byte is {}", bytes[7]));
        }
        if generation == 0 {
            return Err("restore packet generation is 0".to_owned());
        }
        if !(-RATE_DEVIATION_LIMIT..=RATE_DEVIATION_LIMIT).contains(&rate_deviation) {
            return Err(format!(
                "restore packet rate deviation {rate_deviation} exceeds the 250 ppm tolerance"
            ));
        }
        if downtime_ns > DOWNTIME_LIMIT_NS {
            return Err(format!(
                "restore packet downtime {downtime_ns} ns exceeds 30 days"
            ));
        }
        if utc_ns == 0 || utc_ns > i64::MAX as u64 {
            return Err(format!("restore packet UTC {utc_ns} is invalid"));
        }
        Ok(Self {
            flags,
            online_vp_count,
            range_count,
            generation,
            rate_deviation,
            downtime_ns,
            utc_ns,
            ranges: Vec::with_capacity(usize::from(range_count)),
            entropy: [0; PACKET_ENTROPY_SIZE],
        })
    }

    pub(crate) fn body_size(&self) -> usize {
        usize::from(self.range_count) * PACKET_RANGE_SIZE + PACKET_ENTROPY_SIZE
    }

    pub(crate) fn parse_body(&mut self, bytes: &[u8]) -> Result<(), String> {
        let Some(bytes) = bytes.get(..self.body_size()) else {
            return Err("restore packet body is incomplete".to_owned());
        };
        self.ranges.clear();
        for index in 0..usize::from(self.range_count) {
            let offset = index * PACKET_RANGE_SIZE;
            let start = read_le64(&bytes[offset..]);
            let length = read_le64(&bytes[offset + 8..]);
            if length == 0 || start.checked_add(length).is_none() {
                return Err(format!("restore memory range {index} is invalid"));
            }
            self.ranges.push((start, length));
        }
        let entropy = usize::from(self.range_count) * PACKET_RANGE_SIZE;
        self.entropy
            .copy_from_slice(&bytes[entropy..entropy + PACKET_ENTROPY_SIZE]);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TimeSample {
    pub(crate) flags: u8,
    pub(crate) generation: u32,
    pub(crate) utc_ns: u64,
    pub(crate) t0: i64,
    pub(crate) t1: i64,
}

impl TimeSample {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let Some(bytes) = bytes.get(..SAMPLE_SIZE) else {
            return Err("time sample version is 0".to_owned());
        };
        let flags = bytes[1];
        let reserved = u16::from_le_bytes([bytes[2], bytes[3]]);
        let generation = read_le32(&bytes[4..]);
        let utc_ns = read_le64(&bytes[8..]);
        if bytes[0] != 1 {
            return Err(format!("time sample version is {}", bytes[0]));
        }
        if flags & !SAMPLE_TEST_HOOKS != 0 || reserved != 0 {
            return Err(format!(
                "time sample flags 0x{flags:02x} or reserved 0x{reserved:04x}"
            ));
        }
        if utc_ns == 0 || utc_ns > i64::MAX as u64 {
            return Err(format!("time sample UTC {utc_ns} is invalid"));
        }
        Ok(Self {
            flags,
            generation,
            utc_ns,
            t0: 0,
            t1: 0,
        })
    }
}

pub(crate) fn read_le32(bytes: &[u8]) -> u32 {
    let mut value = [0; 4];
    let count = bytes.len().min(value.len());
    value[..count].copy_from_slice(&bytes[..count]);
    u32::from_le_bytes(value)
}

pub(crate) fn read_le64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    let count = bytes.len().min(value.len());
    value[..count].copy_from_slice(&bytes[..count]);
    u64::from_le_bytes(value)
}

pub(crate) fn format_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn parse_hex(text: &[u8], size: usize) -> Option<Vec<u8>> {
    if text.len() != size * 2 {
        return None;
    }
    let mut bytes = vec![0; size];
    for (index, pair) in text.chunks_exact(2).enumerate() {
        bytes[index] = hex_digit(pair[0])?.checked_mul(16)? + hex_digit(pair[1])?;
    }
    Some(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses the C helper's CPU-list syntax. Repeated CPUs count once.
pub(crate) fn parse_cpu_list(text: &[u8]) -> Option<([bool; MAX_CPUS], usize)> {
    let mut selected = [false; MAX_CPUS];
    let mut count = 0;
    let mut cursor = 0;
    while cursor < text.len() && !matches!(text[cursor], b'\n' | 0) {
        let (first, end) = decimal_prefix(text, cursor)?;
        if first < 0 {
            return None;
        }
        cursor = end;
        let mut last = first;
        if text.get(cursor) == Some(&b'-') {
            let parsed = decimal_prefix(text, cursor + 1)?;
            last = parsed.0;
            cursor = parsed.1;
            if last < first {
                return None;
            }
        }
        if last >= MAX_CPUS as i64 {
            return None;
        }
        for cpu in first..=last {
            let cpu = cpu as usize;
            if !selected[cpu] {
                selected[cpu] = true;
                count += 1;
            }
        }
        match text.get(cursor).copied() {
            Some(b',') => cursor += 1,
            Some(b'\n' | 0) | None => {}
            _ => return None,
        }
    }
    Some((selected, count))
}

fn decimal_prefix(text: &[u8], mut cursor: usize) -> Option<(i64, usize)> {
    while text
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    let mut negative = false;
    match text.get(cursor) {
        Some(b'-') => {
            negative = true;
            cursor += 1;
        }
        Some(b'+') => cursor += 1,
        _ => {}
    }
    let start = cursor;
    let limit = if negative {
        i64::MAX as u64 + 1
    } else {
        i64::MAX as u64
    };
    let mut value = 0_u64;
    while let Some(digit @ b'0'..=b'9') = text.get(cursor).copied() {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
        if value > limit {
            return None;
        }
        cursor += 1;
    }
    if cursor == start {
        return None;
    }
    let value = if negative {
        if value == i64::MAX as u64 + 1 {
            i64::MIN
        } else {
            -(value as i64)
        }
    } else {
        value as i64
    };
    Some((value, cursor))
}

pub(crate) fn parse_i64_lossy(text: &[u8]) -> i64 {
    let mut cursor = 0;
    while text
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    let negative = match text.get(cursor) {
        Some(b'-') => {
            cursor += 1;
            true
        }
        Some(b'+') => {
            cursor += 1;
            false
        }
        _ => false,
    };
    let start = cursor;
    let limit = if negative {
        i64::MAX as u64 + 1
    } else {
        i64::MAX as u64
    };
    let mut value = 0_u64;
    while let Some(digit @ b'0'..=b'9') = text.get(cursor).copied() {
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(digit - b'0'))
            .min(limit);
        cursor += 1;
    }
    if cursor == start {
        0
    } else if negative && value == i64::MAX as u64 + 1 {
        i64::MIN
    } else if negative {
        -(value as i64)
    } else {
        value as i64
    }
}

pub(crate) fn parse_i64_exact(text: &[u8]) -> Option<i64> {
    let text = c_text(text);
    let (value, mut cursor) = decimal_prefix(text, 0)?;
    while matches!(text.get(cursor), Some(b'\n' | b' ')) {
        cursor += 1;
    }
    (cursor == text.len()).then_some(value)
}

pub(crate) fn parse_u64_lossy(text: &[u8]) -> u64 {
    u64_prefix_lossy(text, 0).map_or(0, |value| value.0)
}

fn u64_prefix_lossy(text: &[u8], mut cursor: usize) -> Option<(u64, usize)> {
    while text
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    let negative = match text.get(cursor) {
        Some(b'-') => {
            cursor += 1;
            true
        }
        Some(b'+') => {
            cursor += 1;
            false
        }
        _ => false,
    };
    let mut value = 0_u64;
    let mut overflow = false;
    let mut converted = false;
    while let Some(digit @ b'0'..=b'9') = text.get(cursor).copied() {
        converted = true;
        let next = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')));
        if let Some(next) = next {
            value = next;
        } else {
            value = u64::MAX;
            overflow = true;
        }
        cursor += 1;
    }
    if !converted {
        None
    } else if overflow {
        Some((u64::MAX, cursor))
    } else if negative {
        Some((value.wrapping_neg(), cursor))
    } else {
        Some((value, cursor))
    }
}

pub(crate) fn pair_clocks(t0: i64, t1: i64, utc_ns: u64) -> (i64, i64) {
    let epsilon = t1.wrapping_sub(t0) / 2;
    (
        (utc_ns as i64).wrapping_sub(t0.wrapping_add(epsilon)),
        epsilon,
    )
}

pub(crate) fn restore_frequency(rate_deviation: i32) -> i64 {
    (-i64::from(rate_deviation)).clamp(-FREQUENCY_LIMIT, FREQUENCY_LIMIT)
}

pub(crate) fn frequency_to_ppb(frequency: i64) -> i64 {
    let scaled = frequency * 1000;
    (scaled + if scaled >= 0 { 32_768 } else { -32_768 }) / 65_536
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Correction {
    Step {
        modes: u32,
        seconds: i64,
        nanoseconds: i64,
    },
    Slew {
        modes: u32,
        offset: i64,
        status: i32,
        constant: i64,
        maxerror: i64,
        esterror: i64,
    },
}

pub(crate) fn plan_correction(theta: i64, epsilon: i64, fast: bool) -> Correction {
    let magnitude = theta.wrapping_abs();
    if magnitude >= STEP_THRESHOLD_NS {
        let mut seconds = theta / 1_000_000_000;
        let mut nanoseconds = theta % 1_000_000_000;
        if nanoseconds < 0 {
            seconds -= 1;
            nanoseconds += 1_000_000_000;
        }
        return Correction::Step {
            modes: 0x2100,
            seconds,
            nanoseconds,
        };
    }
    let ceil_us = |nanoseconds: i64| nanoseconds.wrapping_add(999) / 1000;
    Correction::Slew {
        modes: 0x203d,
        offset: theta,
        status: 0x2001,
        constant: if fast { 4 } else { 6 },
        maxerror: ceil_us(magnitude.wrapping_add(epsilon)),
        esterror: ceil_us(epsilon),
    }
}

struct WatchRule {
    code: &'static str,
    all: &'static [&'static str],
    any: &'static [&'static str],
}

const WATCH_RULES: &[WatchRule] = &[
    WatchRule {
        code: "G_TSC_UNSTABLE",
        all: &["Marking TSC unstable due to "],
        any: &[],
    },
    WatchRule {
        code: "G_CLOCKSOURCE_UNSTABLE",
        all: &[
            "timekeeping watchdog on CPU",
            "as unstable because the skew is too large",
        ],
        any: &[],
    },
    WatchRule {
        code: "G_CLOCKSOURCE_SWITCH",
        all: &["clocksource: Switched to clocksource "],
        any: &[],
    },
    WatchRule {
        code: "G_CLOCKSOURCE_SKEW",
        all: &["clocksource: "],
        any: &[" ahead of CPU ", " behind CPU "],
    },
    WatchRule {
        code: "G_TSC_WARP",
        all: &[],
        any: &[
            "TSC synchronization [CPU#",
            "cycles TSC warp between CPUs",
            "TSC warped randomly between CPUs",
        ],
    },
    WatchRule {
        code: "G_TSC_ADJUST",
        all: &["TSC ADJUST"],
        any: &[],
    },
    WatchRule {
        code: "G_RCU_STALL",
        all: &["rcu: INFO: "],
        any: &[
            " detected stalls on CPUs/tasks",
            " self-detected stall on CPU",
            " detected expedited stalls",
        ],
    },
    WatchRule {
        code: "G_RCU_STARVED",
        all: &["rcu: "],
        any: &[
            " kthread starved for ",
            " kthread timer wakeup didn't happen for ",
        ],
    },
    WatchRule {
        code: "G_SOFT_LOCKUP",
        all: &["watchdog: BUG: soft lockup - CPU#"],
        any: &[],
    },
    WatchRule {
        code: "G_HARD_LOCKUP",
        all: &["Watchdog detected hard LOCKUP"],
        any: &[],
    },
    WatchRule {
        code: "G_HUNG_TASK",
        all: &["INFO: task ", " blocked for more than "],
        any: &[],
    },
    WatchRule {
        code: "G_UNCHECKED_MSR",
        all: &["unchecked MSR access error"],
        any: &[],
    },
    WatchRule {
        code: "G_APIC_ID_MISMATCH",
        all: &["APIC ID mismatch"],
        any: &[],
    },
];

pub(crate) fn match_watch_rule(message: &[u8]) -> Option<&'static str> {
    let message = c_text(message);
    if message.starts_with(b"NVX-TIME-") {
        return None;
    }
    WATCH_RULES.iter().find_map(|rule| {
        let all = rule
            .all
            .iter()
            .all(|part| contains_bytes(message, part.as_bytes()));
        let any = rule.any.is_empty()
            || rule
                .any
                .iter()
                .any(|part| contains_bytes(message, part.as_bytes()));
        (all && any).then_some(rule.code)
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BootLog {
    hypervisor: bool,
    privileges: bool,
    lapic: bool,
    last_switch: Vec<u8>,
    problem: Vec<u8>,
    pub(crate) wx: Vec<u8>,
}

impl BootLog {
    pub(crate) fn add(&mut self, message: &[u8]) {
        const FORBIDDEN: &[&[u8]] = &[
            b"Fast TSC calibration",
            b"Refined TSC clocksource calibration",
            b"kvm-clock",
            b"APIC timer: using supplied frequency",
        ];
        let message = c_text(message);
        if self.wx.is_empty()
            && !message.starts_with(b"NVX-TIME-")
            && contains_bytes(message, b"Found insecure W+X mapping")
        {
            self.wx
                .extend_from_slice(&message[..message.len().min(300)]);
        }
        self.hypervisor |= contains_bytes(message, b"Hypervisor detected: Microsoft Hyper-V");
        self.privileges |= contains_bytes(message, b"Hyper-V: privilege flags low 0x8860,");
        self.lapic |= message.ends_with(b"Hyper-V: LAPIC Timer Frequency: 0x989680")
            || message.ends_with(b"Hyper-V: LAPIC Timer Frequency: 0x1e8480");
        const SWITCHED: &[u8] = b"clocksource: Switched to clocksource ";
        if let Some(name) = find_bytes(message, SWITCHED) {
            let name = &message[name + SWITCHED.len()..];
            let end = name
                .iter()
                .position(|byte| matches!(byte, b' ' | b'\n'))
                .unwrap_or(name.len())
                .min(47);
            self.last_switch.clear();
            self.last_switch.extend_from_slice(&name[..end]);
        }
        if !self.problem.is_empty() {
            return;
        }
        if let Some(code) = match_watch_rule(message)
            && code != "G_CLOCKSOURCE_SWITCH"
        {
            let _ = write!(&mut self.problem, "{code}: ");
            self.problem
                .extend_from_slice(&message[..message.len().min(300)]);
            return;
        }
        if !message.starts_with(b"NVX-TIME-")
            && FORBIDDEN
                .iter()
                .any(|record| contains_bytes(message, record))
        {
            self.problem.extend_from_slice(b"forbidden record: ");
            self.problem
                .extend_from_slice(&message[..message.len().min(300)]);
        }
    }

    pub(crate) fn verdict(&self) -> Result<(), Vec<u8>> {
        if !self.problem.is_empty() {
            Err(self.problem.clone())
        } else if !self.hypervisor {
            Err(b"no 'Hypervisor detected: Microsoft Hyper-V'".to_vec())
        } else if !self.privileges {
            Err(b"no 'Hyper-V: privilege flags low 0x8860,'".to_vec())
        } else if !self.lapic {
            Err(b"no 'Hyper-V: LAPIC Timer Frequency' of 1 GHz or 200 MHz".to_vec())
        } else if self.last_switch != b"tsc" {
            let mut detail = b"last clocksource switch is to '".to_vec();
            detail.extend_from_slice(&self.last_switch);
            detail.extend_from_slice(b"', not tsc");
            Err(detail)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn syslog_message(line: &[u8]) -> &[u8] {
    let mut cursor = 0;
    if line.first() == Some(&b'<')
        && let Some(end) = line.iter().position(|byte| *byte == b'>')
    {
        cursor = end + 1;
    }
    if line.get(cursor) != Some(&b'[') {
        return &line[cursor..];
    }
    let start = cursor;
    cursor += 1;
    while line.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    while line.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    if line.get(cursor) != Some(&b'.') {
        return &line[start..];
    }
    cursor += 1;
    while line.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    if line.get(cursor) != Some(&b']') {
        return &line[start..];
    }
    cursor += 1;
    if line.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    &line[cursor..]
}

fn c_text(text: &[u8]) -> &[u8] {
    text.split(|byte| *byte == 0).next().unwrap_or_default()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        Some(0)
    } else {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes(haystack, needle).is_some()
}

fn has_word(list: &[u8], word: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(found) = find_bytes(&list[offset..], word) {
        let start = offset + found;
        let end = start + word.len();
        let starts = start == 0 || matches!(list[start - 1], b' ' | b'\t');
        let ends = end == list.len() || matches!(list[end], 0 | b' ' | b'\n');
        if starts && ends {
            return true;
        }
        offset = end;
    }
    false
}

pub(crate) fn scan_boot_log(text: &[u8], syslog: bool) -> BootLog {
    let mut log = BootLog::default();
    for line in c_text(text).split(|byte| *byte == b'\n') {
        if !line.is_empty() {
            log.add(if syslog { syslog_message(line) } else { line });
        }
    }
    log
}

pub(crate) fn explicit_zero_leaf(leaf: u32) -> bool {
    (0x4000_0006..=0x4000_000f).contains(&leaf) || (0x4000_0080..=0x4000_0082).contains(&leaf)
}

pub(crate) fn exhaustive_leaf_ok(
    leaf: u32,
    value: [u32; 4],
    out_of_range: [u32; 4],
) -> Result<(), String> {
    if value == [0; 4] || (!explicit_zero_leaf(leaf) && value == out_of_range) {
        return Ok(());
    }
    let mut signature = [0; 12];
    signature[..4].copy_from_slice(&value[1].to_ne_bytes());
    signature[4..8].copy_from_slice(&value[2].to_ne_bytes());
    signature[8..].copy_from_slice(&value[3].to_ne_bytes());
    for byte in &mut signature {
        if !(0x20..=0x7e).contains(byte) {
            *byte = b'.';
        }
    }
    let signature = String::from_utf8_lossy(&signature);
    Err(format!(
        "leaf 0x{leaf:08x} is {:08x} {:08x} {:08x} {:08x} \
         (signature \"{signature}\"), expected zero{}",
        value[0],
        value[1],
        value[2],
        value[3],
        if explicit_zero_leaf(leaf) {
            ""
        } else {
            " or the highest basic leaf"
        }
    ))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TickSection {
    seen: bool,
    mode: i32,
    state: i32,
    device: Vec<u8>,
    handler: Vec<u8>,
}

fn scan_prefix(line: &[u8], pattern: &[u8]) -> Option<usize> {
    let mut input = 0;
    let mut format = 0;
    while format < pattern.len() {
        if pattern[format].is_ascii_whitespace() {
            while pattern.get(format).is_some_and(u8::is_ascii_whitespace) {
                format += 1;
            }
            while line.get(input).is_some_and(u8::is_ascii_whitespace) {
                input += 1;
            }
        } else {
            if line.get(input) != pattern.get(format) {
                return None;
            }
            input += 1;
            format += 1;
        }
    }
    Some(input)
}

fn scan_i32(line: &[u8], pattern: &[u8]) -> Option<i32> {
    let start = scan_prefix(line, pattern)?;
    let (value, _) = decimal_prefix(line, start)?;
    Some(value as i32)
}

fn scan_word(line: &[u8], pattern: &[u8]) -> Option<Vec<u8>> {
    let mut start = scan_prefix(line, pattern)?;
    while line.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let end = line[start..]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || *byte == 0)
        .map_or(line.len(), |length| start + length);
    (end > start).then(|| line[start..end.min(start + 47)].to_vec())
}

pub(crate) fn timer_list_verdict(text: &[u8], selected: &[bool; MAX_CPUS]) -> Result<(), Vec<u8>> {
    let mut cpus: [TickSection; MAX_CPUS] = std::array::from_fn(|_| TickSection {
        mode: -1,
        state: -1,
        ..TickSection::default()
    });
    let mut broadcast = TickSection {
        mode: -1,
        state: -1,
        ..TickSection::default()
    };
    enum Current {
        None,
        Cpu(usize),
        Broadcast,
    }
    let mut current = Current::None;
    let mut tick_mode = -1;
    for line in c_text(text).split(|byte| *byte == b'\n') {
        if let Some(value) = scan_i32(line, b"Tick Device: mode: ") {
            tick_mode = value;
            current = Current::None;
        } else if line.starts_with(b"Broadcast device") {
            broadcast.seen = true;
            broadcast.mode = tick_mode;
            current = Current::Broadcast;
        } else if let Some(value) = scan_i32(line, b"Per CPU device: ") {
            current = usize::try_from(value)
                .ok()
                .filter(|cpu| *cpu < MAX_CPUS)
                .map_or(Current::None, |cpu| {
                    cpus[cpu].seen = true;
                    cpus[cpu].mode = tick_mode;
                    Current::Cpu(cpu)
                });
        } else {
            let section = match current {
                Current::None => None,
                Current::Cpu(cpu) => Some(&mut cpus[cpu]),
                Current::Broadcast => Some(&mut broadcast),
            };
            let Some(section) = section else {
                continue;
            };
            if let Some(value) = scan_word(line, b"Clock Event Device: ") {
                section.device = value;
            } else if let Some(value) = scan_i32(line, b" mode: ") {
                section.state = value;
            } else if let Some(value) = scan_word(line, b" event_handler: ") {
                section.handler = value;
            }
        }
    }
    if broadcast.seen && broadcast.device != b"<NULL>" {
        let mut detail = b"broadcast clock event device is ".to_vec();
        detail.extend_from_slice(&broadcast.device);
        return Err(detail);
    }
    for cpu in 0..MAX_CPUS {
        if !selected[cpu] {
            continue;
        }
        let section = &cpus[cpu];
        if !section.seen
            || section.device != b"lapic"
            || section.handler != b"hrtimer_interrupt"
            || section.mode != 1
            || !matches!(section.state, 3 | 4)
        {
            let mut detail = Vec::new();
            let _ = write!(&mut detail, "cpu {cpu} tick device ");
            if section.seen {
                detail.extend_from_slice(&section.device);
            } else {
                detail.extend_from_slice(b"missing");
            }
            detail.extend_from_slice(b" handler ");
            if section.handler.is_empty() {
                detail.extend_from_slice(b"none");
            } else {
                detail.extend_from_slice(&section.handler);
            }
            let _ = write!(
                &mut detail,
                " tick mode {} state {}",
                section.mode, section.state
            );
            return Err(detail);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CpuInfo {
    pub(crate) khz: [u64; MAX_CPUS],
    pub(crate) known: [bool; MAX_CPUS],
}

impl Default for CpuInfo {
    fn default() -> Self {
        Self {
            khz: [0; MAX_CPUS],
            known: [false; MAX_CPUS],
        }
    }
}

pub(crate) fn check_cpuinfo(
    text: &[u8],
    selected: &[bool; MAX_CPUS],
    flags: bool,
) -> (CpuInfo, Result<(), String>) {
    const REQUIRED: &[&str] = &[
        "tsc",
        "constant_tsc",
        "nonstop_tsc",
        "tsc_known_freq",
        "tsc_reliable",
        "rdtscp",
        "hypervisor",
        "arat",
    ];
    const FORBIDDEN: &[&str] = &["tsc_deadline_timer", "tsc_adjust"];
    let mut result = CpuInfo::default();
    let mut cpu = None;
    let mut failure = None;
    let mut seen = [false; MAX_CPUS];
    for raw in c_text(text).split(|byte| *byte == b'\n') {
        if failure.is_some() {
            break;
        }
        let Some(colon) = raw.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if raw.starts_with(b"processor") {
            let number = parse_i64_lossy(&raw[colon + 1..]);
            cpu = usize::try_from(number).ok().filter(|cpu| *cpu < MAX_CPUS);
            if let Some(cpu) = cpu {
                seen[cpu] = true;
            }
        } else if raw.starts_with(b"cpu MHz") {
            let Some(cpu) = cpu else {
                continue;
            };
            let value = &raw[colon + 1..];
            let whole = parse_u64_lossy(value);
            let mut fraction = [b'0'; 3];
            if let Some(dot) = value.iter().position(|byte| *byte == b'.') {
                for (target, &digit) in fraction.iter_mut().zip(&value[dot + 1..]) {
                    if digit.is_ascii_digit() {
                        *target = digit;
                    } else {
                        break;
                    }
                }
            }
            let fraction = u64::from(fraction[0] - b'0') * 100
                + u64::from(fraction[1] - b'0') * 10
                + u64::from(fraction[2] - b'0');
            result.khz[cpu] = whole.wrapping_mul(1000).wrapping_add(fraction);
            result.known[cpu] = true;
        } else if flags && raw.starts_with(b"flags") {
            let Some(cpu) = cpu.filter(|cpu| selected[*cpu]) else {
                continue;
            };
            let words = &raw[colon + 1..];
            if let Some(required) = REQUIRED
                .iter()
                .find(|flag| !has_word(words, flag.as_bytes()))
            {
                failure = Some(format!("cpu {cpu} lacks the {required} flag"));
            } else if let Some(forbidden) = FORBIDDEN
                .iter()
                .find(|flag| has_word(words, flag.as_bytes()))
            {
                failure = Some(format!("cpu {cpu} has the {forbidden} flag"));
            }
        }
    }
    if failure.is_none()
        && flags
        && let Some(cpu) = (0..MAX_CPUS).find(|cpu| selected[*cpu] && !seen[*cpu])
    {
        failure = Some(format!("cpu {cpu} is not in /proc/cpuinfo"));
    }
    let verdict = failure.map_or(Ok(()), Err);
    (result, verdict)
}

pub(crate) fn check_cmdline(text: &[u8]) -> Result<(), Vec<u8>> {
    const PREFIXES: &[&[u8]] = &[b"tsc_early_khz=", b"lapic_timer_hz="];
    const TOKENS: &[&[u8]] = &[
        b"notsc",
        b"nolapic",
        b"nolapic_timer",
        b"tsc=unstable",
        b"hpet=force",
    ];
    for token in c_text(text)
        .split(|byte| matches!(byte, b' ' | b'\t' | b'\n'))
        .filter(|token| !token.is_empty())
    {
        let bad_clocksource = token
            .strip_prefix(b"clocksource=")
            .is_some_and(|value| value != b"tsc");
        if bad_clocksource
            || PREFIXES.iter().any(|prefix| token.starts_with(prefix))
            || TOKENS.contains(&token)
        {
            let mut detail = b"command line contains ".to_vec();
            detail.extend_from_slice(&token[..token.len().min(120)]);
            return Err(detail);
        }
    }
    Ok(())
}

pub(crate) fn check_clocksource(current: &[u8], available: &[u8]) -> Result<(), Vec<u8>> {
    let current_name = c_text(current)
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if current_name != b"tsc" {
        let mut detail = b"current clocksource is ".to_vec();
        detail.extend_from_slice(current_name);
        return Err(detail);
    }
    let mut tsc = false;
    for token in c_text(available)
        .split(|byte| matches!(byte, b' ' | b'\n'))
        .filter(|token| !token.is_empty())
    {
        match token {
            b"tsc" => tsc = true,
            b"refined-jiffies" | b"jiffies" => {}
            _ => {
                let mut detail = b"clocksource ".to_vec();
                detail.extend_from_slice(&token[..token.len().min(64)]);
                detail.extend_from_slice(b" is available");
                return Err(detail);
            }
        }
    }
    if !tsc {
        return Err(b"tsc is not an available clocksource".to_vec());
    }
    Ok(())
}

pub(crate) fn parse_restore_record(text: &[u8]) -> Option<(u64, [bool; MAX_CPUS], usize)> {
    let text = c_text(text);
    let rest = text.strip_prefix(b"generation=")?;
    let (generation, end) = u64_prefix_lossy(rest, 0)?;
    let mut cursor = end;
    while rest.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let cpus = rest[cursor..]
        .strip_prefix(b"new_cpus=")
        .and_then(|value| {
            let value = value
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map(|start| &value[start..])
                .unwrap_or_default();
            let value = value
                .split(u8::is_ascii_whitespace)
                .next()
                .unwrap_or_default();
            (!value.is_empty()).then_some(&value[..value.len().min(127)])
        })
        .unwrap_or(b"none");
    let (selected, count) = if cpus.is_empty() || cpus == b"none" {
        ([false; MAX_CPUS], 0)
    } else {
        parse_cpu_list(cpus)?
    };
    Some((generation, selected, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_sample_decoders_check_bounds() {
        let mut bytes = [0_u8; PACKET_HEADER_SIZE + PACKET_ENTROPY_SIZE];
        bytes[..3].copy_from_slice(b"OVR");
        bytes[3] = 4;
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&1_u64.to_le_bytes());
        let mut packet = RestorePacket::parse_header(&bytes).unwrap();
        packet.parse_body(&bytes[PACKET_HEADER_SIZE..]).unwrap();
        assert_eq!(packet.entropy, [0; PACKET_ENTROPY_SIZE]);

        let mut sample = [0_u8; SAMPLE_SIZE];
        sample[0] = 1;
        sample[8] = 1;
        assert_eq!(TimeSample::parse(&sample).unwrap().utc_ns, 1);
    }

    #[test]
    fn cpu_lists_deduplicate_and_check_the_limit() {
        let (cpus, count) = parse_cpu_list(b"0-3,2,5\n").unwrap();
        assert_eq!(count, 5);
        assert!(cpus[0] && cpus[5] && !cpus[4]);
        assert!(parse_cpu_list(b"64").is_none());
    }

    #[test]
    fn correction_boundary_matches_the_abi() {
        assert!(matches!(
            plan_correction(128_000_000, 10, true),
            Correction::Step { .. }
        ));
        assert!(matches!(
            plan_correction(127_999_999, 10, true),
            Correction::Slew { .. }
        ));
    }

    #[test]
    fn watcher_ignores_its_own_event() {
        assert_eq!(
            match_watch_rule(b"unchecked MSR access error"),
            Some("G_UNCHECKED_MSR")
        );
        assert_eq!(
            match_watch_rule(b"NVX-TIME-ABI-VIOLATION: unchecked MSR access error"),
            None
        );
    }

    #[test]
    fn decimal_parsers_match_the_c_extrema() {
        assert_eq!(parse_i64_lossy(b"-9223372036854775808"), i64::MIN);
        assert_eq!(parse_i64_lossy(b"9223372036854775808"), i64::MAX);
        assert_eq!(parse_u64_lossy(b"-1"), u64::MAX);
        assert_eq!(parse_u64_lossy(b"-18446744073709551616"), u64::MAX);
        assert_eq!(parse_i64_exact(b"\t-9223372036854775808 "), Some(i64::MIN));
        assert_eq!(parse_i64_exact(b"1\t"), None);
    }

    #[test]
    fn extreme_clock_arithmetic_wraps_without_panicking() {
        assert_eq!(pair_clocks(i64::MIN, i64::MAX, 0), (i64::MIN, 0));
        assert_eq!(
            plan_correction(i64::MIN, 0, true),
            Correction::Slew {
                modes: 0x203d,
                offset: i64::MIN,
                status: 0x2001,
                constant: 4,
                maxerror: -9_223_372_036_854_774,
                esterror: 0,
            }
        );
    }

    #[test]
    fn restore_record_follows_scanf_field_adjacency() {
        assert_eq!(
            parse_restore_record(b"generation=18446744073709551615 new_cpus=1")
                .map(|value| (value.0, value.2)),
            Some((u64::MAX, 1))
        );
        assert_eq!(
            parse_restore_record(b"generation=3 ignored new_cpus=1").map(|value| value.2),
            Some(0)
        );
        assert_eq!(
            parse_restore_record(b"generation=3 new_cpus= 1-2").map(|value| value.2),
            Some(2)
        );
        assert!(parse_restore_record(b"generation=3 new_cpus=\ntrailing=value").is_none());
    }
}
