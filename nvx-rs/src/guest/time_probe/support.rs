//! Parsing, affinity, kernel-log access, and TSC-rate discovery.

use std::ffi::CString;
use std::io::Write;
use std::sync::OnceLock;

use crate::guest::{parse, sys};

use super::MAX_CPUS;

const KMSG_RECORD_MAX: usize = 8192;
const CLOCKSOURCE_DIR: &str = "/sys/devices/system/clocksource/clocksource0";

#[derive(Clone, Copy)]
pub(super) struct TscRate {
    pub(super) hz: f64,
    pub(super) source: &'static str,
}

pub(super) fn parse_u64(text: &[u8]) -> Option<u64> {
    parse::parse_u64(text)
}

pub(super) fn parse_f64(text: &[u8]) -> Option<f64> {
    let value = CString::new(text).ok()?;
    let mut end = std::ptr::null_mut();
    // SAFETY: errno is thread-local; strtod reads `value` and stores a pointer into it.
    let (number, errno) = unsafe {
        *libc::__errno_location() = 0;
        let number = libc::strtod(value.as_ptr(), &raw mut end);
        (number, *libc::__errno_location())
    };
    let consumed = end as usize - value.as_ptr() as usize;
    (errno == 0 && consumed != 0 && consumed == text.len()).then_some(number)
}

pub(super) fn option_value<'a>(
    arguments: &'a [&'a [u8]],
    index: &mut usize,
    name: &[u8],
) -> Option<&'a [u8]> {
    let argument = arguments[*index];
    if !argument.starts_with(name) {
        return None;
    }
    if argument.get(name.len()) == Some(&b'=') {
        return Some(&argument[name.len() + 1..]);
    }
    if argument.len() == name.len() && *index + 1 < arguments.len() {
        *index += 1;
        return Some(arguments[*index]);
    }
    None
}

pub(super) fn bad_option(command: &[u8], argument: &[u8], err: &mut dyn Write) -> u8 {
    sys::report(
        err,
        &[
            b"nvx-time-probe ",
            command,
            b": invalid option or value: ",
            argument,
            b"\n",
        ],
    );
    2
}

pub(super) fn pin_self(cpu: usize) -> Result<(), sys::Errno> {
    // SAFETY: CPU_ZERO and CPU_SET initialize a local CPU set.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) != 0 {
            return Err(sys::Errno::last());
        }
        if libc::sched_getcpu() != cpu as i32 {
            return Err(sys::Errno(libc::EINVAL));
        }
    }
    Ok(())
}

pub(super) fn affinity_cpus() -> Result<Vec<usize>, sys::Errno> {
    // SAFETY: sched_getaffinity initializes the local CPU set.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of_val(&set), &raw mut set) != 0 {
            return Err(sys::Errno::last());
        }
        Ok((0..libc::CPU_SETSIZE as usize)
            .filter(|cpu| libc::CPU_ISSET(*cpu, &set))
            .take(MAX_CPUS)
            .collect())
    }
}

pub(super) fn check_cpus_allowed(command: &[u8], cpus: &[usize], err: &mut dyn Write) -> bool {
    // SAFETY: sched_getaffinity initializes the local CPU set.
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&allowed), &raw mut allowed) } != 0
    {
        sys::report(
            err,
            &[
                b"nvx-time-probe ",
                command,
                b": sched_getaffinity: ",
                &sys::Errno::last().text(),
                b"\n",
            ],
        );
        return false;
    }
    for &cpu in cpus {
        // SAFETY: only an in-range CPU is queried.
        let present = cpu < libc::CPU_SETSIZE as usize && unsafe { libc::CPU_ISSET(cpu, &allowed) };
        if !present {
            sys::report(
                err,
                &[
                    b"nvx-time-probe ",
                    command,
                    format!(": cpu {cpu} is not in the affinity mask (offline or excluded)\n")
                        .as_bytes(),
                ],
            );
            return false;
        }
    }
    true
}

pub(super) fn parse_cpu_list(text: &[u8]) -> Option<Vec<usize>> {
    let text = CString::new(text).ok()?;
    let base = text.as_ptr();
    let mut cpus = Vec::new();
    let mut cursor = 0;
    while cursor < text.as_bytes().len() {
        let mut end = std::ptr::null_mut();
        // SAFETY: `cursor` points into the NUL-terminated string and strtol stores an
        // interior pointer in `end`.
        let first = unsafe { libc::strtol(base.add(cursor), &raw mut end, 10) };
        let next = end as usize - base as usize;
        if next == cursor || first < 0 || first >= MAX_CPUS as libc::c_long {
            return None;
        }
        cursor = next;
        let mut last = first;
        if text.as_bytes().get(cursor) == Some(&b'-') {
            let start = cursor + 1;
            // SAFETY: `start` points into the same NUL-terminated string.
            last = unsafe { libc::strtol(base.add(start), &raw mut end, 10) };
            let next = end as usize - base as usize;
            if next == start || last < first || last >= MAX_CPUS as libc::c_long {
                return None;
            }
            cursor = next;
        }
        for cpu in first..=last {
            let cpu = cpu as usize;
            if cpus.contains(&cpu) || cpus.len() >= MAX_CPUS {
                return None;
            }
            cpus.push(cpu);
        }
        match text.as_bytes().get(cursor) {
            Some(b',') => cursor += 1,
            None => {}
            _ => return None,
        }
    }
    Some(cpus)
}

pub(super) fn format_cpu_list(cpus: &[usize]) -> String {
    let mut output = String::new();
    let mut index = 0;
    while index < cpus.len() {
        let first = cpus[index];
        let mut last = first;
        while index + 1 < cpus.len() && cpus[index + 1] == last + 1 {
            index += 1;
            last = cpus[index];
        }
        if !output.is_empty() {
            output.push(',');
        }
        output.push_str(&first.to_string());
        if last != first {
            output.push('-');
            output.push_str(&last.to_string());
        }
        index += 1;
    }
    if output.len() > 255 {
        output.truncate(255);
    }
    output
}

pub(super) fn read_first_line(path: &str, limit: usize) -> Result<Vec<u8>, sys::Errno> {
    let bytes = std::fs::read(path)
        .map_err(|error| sys::Errno(error.raw_os_error().unwrap_or(libc::EIO)))?;
    let line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    Ok(line[..line.len().min(limit.saturating_sub(1))].to_vec())
}

fn kmsg_from_dev(mut consume: impl FnMut(u64, &[u8])) -> Result<(), sys::Errno> {
    // SAFETY: the path is NUL-terminated.
    let descriptor = unsafe {
        libc::open(
            c"/dev/kmsg".as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(sys::Errno::last());
    }
    let mut count = 0;
    let mut record = [0_u8; KMSG_RECORD_MAX];
    loop {
        // SAFETY: read initializes at most `record.len() - 1` bytes.
        let read = unsafe { libc::read(descriptor, record.as_mut_ptr().cast(), record.len() - 1) };
        if read < 0 {
            let error = sys::Errno::last();
            if matches!(error.0, libc::EINTR | libc::EPIPE) {
                continue;
            }
            break;
        }
        if read == 0 {
            break;
        }
        let record = &record[..read as usize];
        let Some(semi) = record.iter().position(|byte| *byte == b';') else {
            continue;
        };
        let mut commas = 0;
        let mut timestamp = 0;
        for (index, &byte) in record[..semi].iter().enumerate() {
            if byte == b',' {
                commas += 1;
                if commas == 2 {
                    timestamp = parse_decimal_prefix(&record[index + 1..semi]);
                    break;
                }
            }
        }
        let message = &record[semi + 1..];
        let end = message
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(message.len());
        consume(timestamp, &message[..end]);
        count += 1;
    }
    let _ = sys::close(descriptor);
    if count > 0 {
        Ok(())
    } else {
        Err(sys::Errno::last())
    }
}

fn parse_decimal_prefix(text: &[u8]) -> u64 {
    let mut value = 0_u64;
    for &byte in text {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'));
    }
    value
}

fn kmsg_from_syslog(mut consume: impl FnMut(u64, &[u8])) -> Result<(), sys::Errno> {
    // SAFETY: action 10 reports the buffer size.
    let mut size = unsafe { libc::klogctl(10, std::ptr::null_mut(), 0) };
    if size <= 0 {
        size = 1 << 20;
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size as usize + 1)
        .map_err(|_| sys::Errno(libc::ENOMEM))?;
    buffer.resize(size as usize + 1, 0);
    // SAFETY: the buffer has `size + 1` writable bytes.
    let count = unsafe { libc::klogctl(3, buffer.as_mut_ptr().cast(), size) };
    if count < 0 {
        return Err(sys::Errno::last());
    }
    for line in buffer[..count as usize].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut message = line;
        if message.first() == Some(&b'<')
            && let Some(close) = message.iter().position(|byte| *byte == b'>')
        {
            message = &message[close + 1..];
        }
        let mut usec = 0;
        if message.first() == Some(&b'[')
            && let Some(close) = message.iter().position(|byte| *byte == b']')
        {
            if let Some(seconds) = parse_f64_prefix(&message[1..close]) {
                usec = (seconds * 1e6 + 0.5) as u64;
            }
            message = &message[close + 1..];
            if message.first() == Some(&b' ') {
                message = &message[1..];
            }
        }
        consume(usec, message);
    }
    Ok(())
}

pub(super) fn kmsg_foreach(mut consume: impl FnMut(u64, &[u8])) -> Result<(), sys::Errno> {
    if kmsg_from_dev(&mut consume).is_ok() {
        Ok(())
    } else {
        kmsg_from_syslog(consume)
    }
}

fn parse_f64_prefix(text: &[u8]) -> Option<f64> {
    let value = CString::new(text).ok()?;
    let mut end = std::ptr::null_mut();
    // SAFETY: strtod reads the NUL-terminated value and stores an interior pointer.
    let number = unsafe { libc::strtod(value.as_ptr(), &raw mut end) };
    (end != value.as_ptr().cast_mut()).then_some(number)
}

fn cpuinfo() -> Vec<u8> {
    std::fs::read("/proc/cpuinfo").unwrap_or_default()
}

fn cpu_flags() -> &'static Vec<Vec<u8>> {
    static FLAGS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    FLAGS.get_or_init(|| {
        for line in cpuinfo().split(|byte| *byte == b'\n') {
            if line.starts_with(b"flags")
                && let Some(colon) = line.iter().position(|byte| *byte == b':')
            {
                return line[colon + 1..]
                    .split(u8::is_ascii_whitespace)
                    .filter(|word| !word.is_empty())
                    .map(<[u8]>::to_vec)
                    .collect();
            }
        }
        Vec::new()
    })
}

pub(super) fn cpuinfo_has_flag(flag: &[u8]) -> bool {
    cpu_flags().iter().any(|word| word == flag)
}

fn cpuinfo_mhz() -> f64 {
    for line in cpuinfo().split(|byte| *byte == b'\n') {
        if line.starts_with(b"cpu MHz")
            && let Some(colon) = line.iter().position(|byte| *byte == b':')
        {
            return parse_f64_prefix(&line[colon + 1..]).unwrap_or(0.0);
        }
    }
    0.0
}

fn mhz_after(text: &[u8], prefix: &[u8], suffix: &[u8]) -> f64 {
    let Some(start) = find(text, prefix).map(|start| start + prefix.len()) else {
        return 0.0;
    };
    let value = &text[start..];
    let Some(number) = parse_f64_prefix(value) else {
        return 0.0;
    };
    let c_value = match CString::new(value) {
        Ok(value) => value,
        Err(_) => return 0.0,
    };
    let mut end = std::ptr::null_mut();
    // SAFETY: strtod stores an interior pointer into `c_value`.
    unsafe { libc::strtod(c_value.as_ptr(), &raw mut end) };
    let consumed = end as usize - c_value.as_ptr() as usize;
    if value
        .get(consumed..)
        .is_some_and(|rest| rest.starts_with(suffix))
    {
        number
    } else {
        0.0
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn mhz_to_hz(mhz: f64) -> f64 {
    (mhz * 1000.0 + 0.5) as u64 as f64 * 1000.0
}

pub(super) fn measure_tsc_hz(milliseconds: u64) -> f64 {
    let mut first = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut second = first;
    let pause = libc::timespec {
        tv_sec: (milliseconds / 1000) as _,
        tv_nsec: ((milliseconds % 1000) * 1_000_000) as _,
    };
    // SAFETY: clock_gettime initializes the timespecs and nanosleep reads `pause`.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut first) };
    let t0 = super::super::x86::rdtsc_fenced();
    // SAFETY: sleeping with no remainder output is valid.
    unsafe { libc::nanosleep(&pause, std::ptr::null_mut()) };
    // SAFETY: clock_gettime initializes `second`.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut second) };
    let t1 = super::super::x86::rdtsc_fenced();
    let ns = (second.tv_sec - first.tv_sec) as f64 * 1e9 + (second.tv_nsec - first.tv_nsec) as f64;
    if ns > 0.0 {
        t1.wrapping_sub(t0) as f64 * 1e9 / ns
    } else {
        0.0
    }
}

pub(super) fn detect_tsc_rate(override_hz: f64) -> TscRate {
    if override_hz > 0.0 {
        return TscRate {
            hz: override_hz,
            source: "option",
        };
    }
    if let Ok(line) = read_first_line("/sys/devices/system/cpu/cpu0/tsc_freq_khz", 64)
        && let Some(khz) = parse_u64(&line).filter(|value| *value > 0)
    {
        return TscRate {
            hz: khz as f64 * 1000.0,
            source: "sysfs-tsc_freq_khz",
        };
    }
    let mut refined = 0.0;
    let mut detected_tsc = 0.0;
    let mut detected_cpu = 0.0;
    let _ = kmsg_foreach(|_, text| {
        let value = mhz_after(text, b"Refined TSC clocksource calibration: ", b" MHz");
        if value > 0.0 {
            refined = value;
            return;
        }
        let value = mhz_after(text, b"tsc: Detected ", b" MHz TSC");
        if value > 0.0 {
            detected_tsc = value;
            return;
        }
        let value = mhz_after(text, b"tsc: Detected ", b" MHz processor");
        if value > 0.0 {
            detected_cpu = value;
        }
    });
    for (mhz, source) in [
        (refined, "kmsg-refined"),
        (detected_tsc, "kmsg-detected-tsc"),
        (detected_cpu, "kmsg-detected-processor"),
    ] {
        if mhz > 0.0 {
            return TscRate {
                hz: mhz_to_hz(mhz),
                source,
            };
        }
    }
    let mhz = cpuinfo_mhz();
    if !cpuinfo_has_flag(b"aperfmperf") && mhz > 0.0 {
        return TscRate {
            hz: mhz_to_hz(mhz),
            source: "cpuinfo-cpu-mhz",
        };
    }
    TscRate {
        hz: measure_tsc_hz(200),
        source: "measured-monotonic-raw",
    }
}

pub(super) fn current_clocksource() -> Vec<u8> {
    read_first_line(&format!("{CLOCKSOURCE_DIR}/current_clocksource"), 64)
        .unwrap_or_else(|_| b"unknown".to_vec())
}

pub(super) fn cycles_to_ns(cycles: f64, rate: TscRate) -> f64 {
    if rate.hz > 0.0 {
        cycles * 1e9 / rate.hz
    } else {
        0.0
    }
}

pub(super) fn round_ll(value: f64) -> i64 {
    (if value >= 0.0 {
        value + 0.5
    } else {
        value - 0.5
    }) as i64
}

pub(super) fn strerror(error: i32) -> Vec<u8> {
    sys::Errno(error).text()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_lists_reject_duplicates_and_format_ranges() {
        assert_eq!(parse_cpu_list(b"0-3,6"), Some(vec![0, 1, 2, 3, 6]));
        assert_eq!(format_cpu_list(&[0, 1, 2, 3, 6]), "0-3,6");
        assert!(parse_cpu_list(b"0,0").is_none());
        assert!(parse_cpu_list(b"3-1").is_none());
        assert!(parse_cpu_list(b"1024").is_none());
    }

    #[test]
    fn numeric_options_use_c_parsing() {
        assert_eq!(parse_u64(b"0x10"), Some(16));
        assert_eq!(parse_u64(b"010"), Some(8));
        assert!(parse_u64(b"1x").is_none());
        assert_eq!(parse_f64(b"2.5"), Some(2.5));
        assert!(parse_f64(b"2.5x").is_none());
    }

    #[test]
    fn nearest_integer_rounding_matches_the_probe() {
        assert_eq!(round_ll(1.49), 1);
        assert_eq!(round_ll(1.5), 2);
        assert_eq!(round_ll(-1.5), -2);
    }
}
