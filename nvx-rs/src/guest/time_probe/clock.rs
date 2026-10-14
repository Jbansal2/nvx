//! Clock, CPU, hypervisor, kernel-log, timer, and optional MSR diagnostics.

use std::io::Write;

use super::format::{f0, f9};
use super::support::{
    bad_option, cpuinfo_has_flag, current_clocksource, detect_tsc_rate, kmsg_foreach,
    measure_tsc_hz, option_value, parse_f64, parse_u64, read_first_line, round_ll, strerror,
};

const TSC_FLAGS: &[&str] = &[
    "tsc",
    "rdtscp",
    "constant_tsc",
    "nonstop_tsc",
    "nonstop_tsc_s3",
    "tsc_known_freq",
    "tsc_reliable",
    "tsc_deadline_timer",
    "tsc_adjust",
    "art",
    "hypervisor",
    "arat",
    "aperfmperf",
    "hwp",
    "x2apic",
];
const HYPERVISOR_PATTERNS: &[&[u8]] = &[
    b"Hypervisor detected",
    b"Hyper-V",
    b"Booting paravirtualized kernel",
    b"kvm-guest",
];
const TIME_PATTERNS: &[&[u8]] = &[
    b"tsc",
    b"TSC",
    b"clocksource",
    b"clockevent",
    b"kvm-clock",
    b"APIC timer",
    b"LAPIC",
    b"lapic",
    b"calibrat",
    b"Calibrat",
    b"unchecked MSR",
    b"hpet",
    b"HPET",
    b"timekeeping",
    b"sched_clock",
    b"detected stall",
    b"watchdog",
    b"lockup",
    b"hung_task",
    b"jiffies",
    b"rtc",
    b"RTC",
];
const PARAM_FILES: &[&str] = &[
    "/sys/module/rcupdate/parameters/rcu_cpu_stall_suppress",
    "/sys/module/rcupdate/parameters/rcu_cpu_stall_timeout",
    "/proc/sys/kernel/watchdog",
    "/proc/sys/kernel/soft_watchdog",
    "/proc/sys/kernel/nmi_watchdog",
    "/proc/sys/kernel/watchdog_thresh",
    "/proc/sys/kernel/hung_task_timeout_secs",
];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn add_unique(list: &mut String, item: &str, limit: usize) {
    if list.split(',').any(|existing| existing == item) {
        return;
    }
    if !list.is_empty() && list.len() < limit.saturating_sub(1) {
        list.push(',');
    }
    let available = limit.saturating_sub(1).saturating_sub(list.len());
    list.extend(item.chars().take(available));
}

fn sanitize_token(text: &mut [u8]) {
    for byte in text {
        if !(byte.is_ascii_alphanumeric() || matches!(*byte, b'#' | b'-' | b'.')) {
            *byte = b'_';
        }
    }
}

fn print_clock(
    output: &mut dyn Write,
    name: &str,
    clock: libc::clockid_t,
) -> Option<libc::timespec> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes `time`.
    if unsafe { libc::clock_gettime(clock, &raw mut time) } != 0 {
        let _ = writeln!(
            output,
            "{name:<20} unavailable ({})",
            String::from_utf8_lossy(&strerror(crate::guest::sys::Errno::last().0))
        );
        return None;
    }
    let _ = write!(output, "{name:<20} {}.{:09}", time.tv_sec, time.tv_nsec);
    if clock == libc::CLOCK_REALTIME {
        // SAFETY: gmtime_r and strftime initialize their output structures and buffer.
        unsafe {
            let seconds = time.tv_sec;
            let mut broken: libc::tm = std::mem::zeroed();
            let mut iso = [0_u8; 32];
            libc::gmtime_r(&seconds, &raw mut broken);
            let length = libc::strftime(
                iso.as_mut_ptr().cast(),
                iso.len(),
                c"%Y-%m-%dT%H:%M:%S".as_ptr(),
                &broken,
            );
            let _ = write!(
                output,
                "  ({}.{:09}Z)",
                String::from_utf8_lossy(&iso[..length]),
                time.tv_nsec
            );
        }
    }
    let _ = writeln!(output);
    Some(time)
}

#[derive(Default)]
struct Filter {
    matches: i32,
    tsc_unstable: i32,
    unchecked_msr: i32,
}

fn print_kmsg(
    output: &mut dyn Write,
    patterns: &[&[u8]],
    filter: &mut Filter,
) -> Result<(), crate::guest::sys::Errno> {
    kmsg_foreach(|usec, text| {
        if contains(text, b"Marking TSC unstable") || contains(text, b"TSC unstable") {
            filter.tsc_unstable += 1;
        }
        if contains(text, b"unchecked MSR access") {
            filter.unchecked_msr += 1;
        }
        if patterns.iter().any(|pattern| contains(text, pattern)) {
            let _ = write!(output, "[{:5}.{:06}] ", usec / 1_000_000, usec % 1_000_000);
            let _ = output.write_all(text);
            let _ = output.write_all(b"\n");
            filter.matches += 1;
        }
    })
}

#[derive(Clone)]
struct TickInfo {
    seen: bool,
    tick_mode: i32,
    state: i32,
    hres_active: i32,
    nohz: i32,
    device: String,
    handler: String,
}

impl Default for TickInfo {
    fn default() -> Self {
        Self {
            seen: false,
            tick_mode: -1,
            state: -1,
            hres_active: -1,
            nohz: -1,
            device: String::new(),
            handler: String::new(),
        }
    }
}

fn scan_i32(line: &[u8], prefix: &[u8]) -> Option<i32> {
    let value = line.strip_prefix(prefix)?;
    let value = value
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    (!value.is_empty())
        .then(|| std::str::from_utf8(&value).ok()?.parse().ok())
        .flatten()
}

fn scan_word(line: &[u8], prefix: &[u8]) -> Option<String> {
    let value = line.strip_prefix(prefix)?;
    let value = value
        .split(u8::is_ascii_whitespace)
        .next()
        .unwrap_or_default();
    (!value.is_empty()).then(|| String::from_utf8_lossy(&value[..value.len().min(63)]).into_owned())
}

fn timer_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let newline = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|length| start + length);
        let end = newline.unwrap_or(bytes.len());
        let mut chunk = start;
        while chunk < end {
            let next = (chunk + 511).min(end);
            lines.push(&bytes[chunk..next]);
            chunk = next;
        }
        if chunk == start {
            lines.push(&[]);
        }
        start = newline.map_or(bytes.len(), |newline| newline + 1);
    }
    lines
}

fn tick_mode_name(mode: i32) -> &'static str {
    match mode {
        0 => "periodic",
        1 => "oneshot",
        _ => "unknown",
    }
}

fn state_name(state: i32) -> &'static str {
    [
        "detached",
        "shutdown",
        "periodic",
        "oneshot",
        "oneshot_stopped",
    ]
    .get(state as usize)
    .copied()
    .unwrap_or("unknown")
}

fn alternate_hex_width_10(value: u32) -> String {
    if value == 0 {
        "0000000000".to_owned()
    } else {
        format!("{value:#010x}")
    }
}

fn print_timer_list(output: &mut dyn Write) -> String {
    let text = match std::fs::read("/proc/timer_list") {
        Ok(text) => text,
        Err(error) => {
            let reason = strerror(error.raw_os_error().unwrap_or(libc::EIO));
            let _ = writeln!(
                output,
                "timer_list: unavailable ({})",
                String::from_utf8_lossy(&reason)
            );
            return "clockevents=unavailable".to_owned();
        }
    };
    let mut cpus = vec![TickInfo::default(); super::MAX_CPUS];
    let mut broadcast = TickInfo::default();
    let mut current = None;
    let mut high_resolution_cpu = None;
    let mut tick_mode = -1;
    for line in timer_lines(&text) {
        if let Some(value) = scan_i32(line, b"cpu: ") {
            high_resolution_cpu = usize::try_from(value)
                .ok()
                .filter(|cpu| *cpu < super::MAX_CPUS);
            current = None;
        } else if line.starts_with(b"Tick Device: mode:") {
            tick_mode = scan_i32(line, b"Tick Device: mode:").unwrap_or(0);
            high_resolution_cpu = None;
            current = None;
        } else if line.starts_with(b"Broadcast device") {
            broadcast.seen = true;
            broadcast.tick_mode = tick_mode;
            current = Some(super::MAX_CPUS);
        } else if let Some(value) = scan_i32(line, b"Per CPU device: ") {
            current = usize::try_from(value)
                .ok()
                .filter(|cpu| *cpu < super::MAX_CPUS);
            if let Some(cpu) = current {
                cpus[cpu].seen = true;
                cpus[cpu].tick_mode = tick_mode;
            }
        } else if let Some(section) = current {
            let target = if section == super::MAX_CPUS {
                &mut broadcast
            } else {
                &mut cpus[section]
            };
            if let Some(value) = scan_word(line, b"Clock Event Device: ") {
                target.device = value;
            } else if let Some(value) = scan_i32(line, b" mode: ") {
                target.state = value;
            } else if let Some(value) = scan_word(line, b" event_handler: ") {
                target.handler = value;
            }
        } else if let Some(cpu) = high_resolution_cpu {
            if let Some(value) = scan_i32(line, b" .hres_active : ") {
                cpus[cpu].hres_active = value;
            } else if let Some(value) =
                scan_i32(line, b" .nohz_mode : ").or_else(|| scan_i32(line, b" .nohz : "))
            {
                cpus[cpu].nohz = value;
            }
        }
    }
    if broadcast.seen {
        let _ = writeln!(
            output,
            "broadcast: device={} state={} tick_mode={} handler={}",
            if broadcast.device.is_empty() {
                "none"
            } else {
                &broadcast.device
            },
            state_name(broadcast.state),
            tick_mode_name(broadcast.tick_mode),
            if broadcast.handler.is_empty() {
                "none"
            } else {
                &broadcast.handler
            }
        );
    }
    let mut count = 0;
    let mut devices = String::new();
    let mut modes = String::new();
    let mut states = String::new();
    for (cpu, info) in cpus.iter().enumerate().filter(|(_, info)| info.seen) {
        count += 1;
        let device = if info.device.is_empty() {
            "none"
        } else {
            &info.device
        };
        let handler = if info.handler.is_empty() {
            "none"
        } else {
            &info.handler
        };
        let _ = writeln!(
            output,
            "cpu{cpu}: device={device} state={} tick_mode={} handler={handler} \
             hres_active={} nohz={}",
            state_name(info.state),
            tick_mode_name(info.tick_mode),
            info.hres_active,
            info.nohz
        );
        add_unique(&mut devices, device, 256);
        add_unique(&mut modes, tick_mode_name(info.tick_mode), 64);
        add_unique(&mut states, state_name(info.state), 128);
    }
    if !broadcast.seen && count == 0 {
        let _ = writeln!(
            output,
            "timer_list: no tick devices found (file empty or masked)"
        );
    }
    format!(
        "clockevent_cpus={count} clockevent_devices={} tick_modes={} clockevent_states={} \
         broadcast={}:{}",
        if devices.is_empty() { "none" } else { &devices },
        if modes.is_empty() { "none" } else { &modes },
        if states.is_empty() { "none" } else { &states },
        if broadcast.seen && !broadcast.device.is_empty() {
            &broadcast.device
        } else {
            "none"
        },
        if broadcast.seen {
            state_name(broadcast.state)
        } else {
            "none"
        }
    )
}

#[derive(Default)]
struct CpuidSummary {
    vendor: Vec<u8>,
    max_leaf: u32,
    features_eax: u32,
    features_edx: u32,
    hypervisor: bool,
}

fn print_cpuid(output: &mut dyn Write) -> CpuidSummary {
    let basic = super::super::x86::cpuid(0, 0)[0];
    let extended = super::super::x86::cpuid(0x8000_0000, 0)[0];
    let leaf1 = super::super::x86::cpuid(1, 0);
    let mut family = (leaf1[0] >> 8) & 0xf;
    let mut model = (leaf1[0] >> 4) & 0xf;
    if matches!(family, 0x6 | 0xf) {
        model |= (leaf1[0] >> 12) & 0xf0;
    }
    if family == 0xf {
        family += (leaf1[0] >> 20) & 0xff;
    }
    let mut summary = CpuidSummary {
        hypervisor: (leaf1[2] >> 31) & 1 != 0,
        ..CpuidSummary::default()
    };
    let _ = writeln!(
        output,
        "cpuid.1: family={family} model={model} stepping={} edx.tsc={} \
         ecx.tsc_deadline={} ecx.hypervisor={}",
        leaf1[0] & 0xf,
        (leaf1[3] >> 4) & 1,
        (leaf1[2] >> 24) & 1,
        u8::from(summary.hypervisor)
    );
    if basic >= 6 {
        let value = super::super::x86::cpuid(6, 0);
        let _ = writeln!(
            output,
            "cpuid.6: eax.arat={} eax.hwp={} ecx.aperfmperf={}",
            (value[0] >> 2) & 1,
            (value[0] >> 7) & 1,
            value[2] & 1
        );
    }
    if basic >= 7 {
        let value = super::super::x86::cpuid(7, 0);
        let _ = writeln!(output, "cpuid.7.0: ebx.tsc_adjust={}", (value[1] >> 1) & 1);
    }
    if basic >= 0x0a {
        let value = super::super::x86::cpuid(0x0a, 0);
        let _ = writeln!(
            output,
            "cpuid.0xa: eax={} (pmu_version={})",
            alternate_hex_width_10(value[0]),
            value[0] & 0xff
        );
    }
    if basic >= 0x15 {
        let value = super::super::x86::cpuid(0x15, 0);
        let _ = write!(
            output,
            "cpuid.0x15: eax.denominator={} ebx.numerator={} ecx.crystal_hz={}",
            value[0], value[1], value[2]
        );
        if value[0] != 0 && value[1] != 0 && value[2] != 0 {
            let _ = write!(
                output,
                " (tsc_hz={})",
                f0(value[2] as f64 * value[1] as f64 / value[0] as f64)
            );
        }
        let _ = writeln!(output);
    }
    if basic >= 0x16 {
        let value = super::super::x86::cpuid(0x16, 0);
        let _ = writeln!(
            output,
            "cpuid.0x16: eax.base_mhz={} ebx.max_mhz={} ecx.bus_mhz={}",
            value[0] & 0xffff,
            value[1] & 0xffff,
            value[2] & 0xffff
        );
    }
    if extended >= 0x8000_0001 {
        let value = super::super::x86::cpuid(0x8000_0001, 0);
        let _ = writeln!(
            output,
            "cpuid.0x80000001: edx.rdtscp={}",
            (value[3] >> 27) & 1
        );
    }
    if extended >= 0x8000_0007 {
        let value = super::super::x86::cpuid(0x8000_0007, 0);
        let _ = writeln!(
            output,
            "cpuid.0x80000007: edx.invariant_tsc={}",
            (value[3] >> 8) & 1
        );
    }
    if !summary.hypervisor {
        let _ = writeln!(
            output,
            "cpuid.0x40000000: not queried (hypervisor bit clear)"
        );
        summary.vendor = b"none".to_vec();
        return summary;
    }
    let value = super::super::x86::cpuid(0x4000_0000, 0);
    summary.max_leaf = value[0];
    summary.vendor.extend_from_slice(&value[1].to_ne_bytes());
    summary.vendor.extend_from_slice(&value[2].to_ne_bytes());
    summary.vendor.extend_from_slice(&value[3].to_ne_bytes());
    for byte in &mut summary.vendor {
        if !(0x20..=0x7e).contains(byte) {
            *byte = b'.';
        }
    }
    let _ = writeln!(
        output,
        "cpuid.0x40000000: eax.max_leaf={:#x} vendor=\"{}\"",
        summary.max_leaf,
        String::from_utf8_lossy(&summary.vendor)
    );
    for leaf in 0x4000_0001..=summary.max_leaf.min(0x4000_0010) {
        let value = super::super::x86::cpuid(leaf, 0);
        let _ = writeln!(
            output,
            "cpuid.{leaf:#x}: eax={} ebx={} ecx={} edx={}",
            alternate_hex_width_10(value[0]),
            alternate_hex_width_10(value[1]),
            alternate_hex_width_10(value[2]),
            alternate_hex_width_10(value[3])
        );
        if leaf == 0x4000_0003 {
            summary.features_eax = value[0];
            summary.features_edx = value[3];
        }
    }
    if summary.vendor == b"Microsoft Hv" && summary.max_leaf >= 0x4000_0003 {
        let _ = writeln!(
            output,
            "hyperv.features: hypercall={} vp_index={} access_frequency_msrs={} \
             access_tsc_invariant={} frequency_msrs_available={}",
            (summary.features_eax >> 5) & 1,
            (summary.features_eax >> 6) & 1,
            (summary.features_eax >> 11) & 1,
            (summary.features_eax >> 15) & 1,
            (summary.features_edx >> 8) & 1
        );
    }
    summary
}

fn print_msrs(output: &mut dyn Write) {
    let msrs = [
        (0x10_u32, "IA32_TSC"),
        (0x3b, "IA32_TSC_ADJUST"),
        (0x4000_0002, "HV_X64_MSR_VP_INDEX"),
        (0x4000_0022, "HV_X64_MSR_TSC_FREQUENCY"),
        (0x4000_0023, "HV_X64_MSR_APIC_FREQUENCY"),
        (0x4000_0118, "HV_X64_MSR_TSC_INVARIANT_CONTROL"),
        (0x4b56_4d01, "MSR_KVM_SYSTEM_TIME_NEW"),
    ];
    // SAFETY: the path is NUL-terminated.
    let descriptor =
        unsafe { libc::open(c"/dev/cpu/0/msr".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if descriptor < 0 {
        let _ = writeln!(
            output,
            "msr: /dev/cpu/0/msr unavailable ({})",
            String::from_utf8_lossy(&strerror(crate::guest::sys::Errno::last().0))
        );
        return;
    }
    for (index, name) in msrs {
        let mut value = 0_u64;
        // SAFETY: pread initializes one u64.
        let count = unsafe {
            libc::pread(
                descriptor,
                (&raw mut value).cast(),
                std::mem::size_of::<u64>(),
                libc::off_t::from(index),
            )
        };
        if count == std::mem::size_of::<u64>() as isize {
            let _ = writeln!(
                output,
                "msr {index:#010x} {name:<34} = {value:#x} ({value})"
            );
        } else {
            let errno = crate::guest::sys::Errno::last();
            let reason = if errno.0 == libc::EIO {
                b"read faulted (#GP)".to_vec()
            } else {
                errno.text()
            };
            let _ = writeln!(
                output,
                "msr {index:#010x} {name:<34} : {}",
                String::from_utf8_lossy(&reason)
            );
        }
    }
    let _ = crate::guest::sys::close(descriptor);
}

fn cpuinfo_summary(output: &mut dyn Write) {
    let text = std::fs::read("/proc/cpuinfo").unwrap_or_default();
    let mut processors = 0;
    let mut model_printed = false;
    let mut mhz = String::new();
    for line in text.split(|byte| *byte == b'\n') {
        let colon = line.iter().position(|byte| *byte == b':');
        if line.starts_with(b"processor") {
            processors += 1;
        } else if !model_printed && line.starts_with(b"model name") {
            if let Some(colon) = colon {
                let _ = write!(output, "model name:");
                let _ = output.write_all(&line[colon + 1..]);
                let _ = writeln!(output);
                model_printed = true;
            }
        } else if line.starts_with(b"cpu MHz")
            && let Some(colon) = colon
        {
            let start = (colon + 2).min(line.len());
            add_unique(&mut mhz, &String::from_utf8_lossy(&line[start..]), 512);
        }
    }
    let _ = writeln!(
        output,
        "processors: {processors}\ncpu MHz: {}",
        if mhz.is_empty() { "unknown" } else { &mhz }
    );
}

pub(super) fn run(arguments: &[&[u8]], output: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut measure_ms = 200_u64;
    let mut override_hz = 0.0;
    let mut read_msrs = false;
    let mut index = 0;
    while index < arguments.len() {
        if let Some(value) = option_value(arguments, &mut index, b"--measure-ms") {
            if let Some(value) = parse_u64(value).filter(|value| *value <= 60_000) {
                measure_ms = value;
            } else {
                return bad_option(b"clock", arguments[index], err);
            }
        } else if let Some(value) = option_value(arguments, &mut index, b"--tsc-hz") {
            if let Some(value) = parse_f64(value).filter(|value| *value > 0.0) {
                override_hz = value;
            } else {
                return bad_option(b"clock", arguments[index], err);
            }
        } else if arguments[index] == b"--msr" {
            read_msrs = true;
        } else {
            return bad_option(b"clock", arguments[index], err);
        }
        index += 1;
    }
    let rate = detect_tsc_rate(override_hz);
    let _ = writeln!(output, "nvx-time-probe {} clock\n== clocks", super::VERSION);
    // SAFETY: sched_getcpu has no arguments.
    let cpu = unsafe { libc::sched_getcpu() };
    let tsc = super::super::x86::rdtsc_fenced();
    print_clock(output, "CLOCK_REALTIME", libc::CLOCK_REALTIME);
    let monotonic =
        print_clock(output, "CLOCK_MONOTONIC", libc::CLOCK_MONOTONIC).unwrap_or(libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        });
    print_clock(output, "CLOCK_MONOTONIC_RAW", libc::CLOCK_MONOTONIC_RAW);
    print_clock(output, "CLOCK_BOOTTIME", libc::CLOCK_BOOTTIME);
    let _ = write!(output, "{:<20} {tsc} on cpu {cpu}", "TSC");
    if rate.hz > 0.0 {
        let seconds = tsc as f64 / rate.hz;
        let difference =
            tsc as f64 * 1e9 / rate.hz - (monotonic.tv_sec as f64 * 1e9 + monotonic.tv_nsec as f64);
        let _ = write!(
            output,
            " ({} s; tsc_minus_monotonic_ns={})",
            f9(seconds),
            round_ll(difference)
        );
    }
    let _ = writeln!(
        output,
        "\ntsc_hz={} tsc_hz_source={}",
        f0(rate.hz),
        rate.source
    );
    if measure_ms > 0 {
        let _ = writeln!(
            output,
            "tsc_hz_measured={} (over {measure_ms} ms against CLOCK_MONOTONIC_RAW)",
            f0(measure_tsc_hz(measure_ms))
        );
    }

    let _ = writeln!(output, "== clocksource");
    let clocksource = current_clocksource();
    let mut available = String::new();
    if let Ok(line) = read_first_line(
        "/sys/devices/system/clocksource/clocksource0/available_clocksource",
        4096,
    ) {
        for token in line
            .split(|byte| *byte == b' ')
            .filter(|token| !token.is_empty())
        {
            add_unique(&mut available, &String::from_utf8_lossy(token), 256);
        }
    }
    let _ = writeln!(
        output,
        "current: {}\navailable: {}",
        String::from_utf8_lossy(&clocksource),
        if available.is_empty() {
            "unknown"
        } else {
            &available
        }
    );

    let _ = writeln!(output, "== cpuinfo");
    cpuinfo_summary(output);
    let mut present = String::new();
    let mut absent = String::new();
    for flag in TSC_FLAGS {
        if cpuinfo_has_flag(flag.as_bytes()) {
            add_unique(&mut present, flag, 256);
        } else {
            add_unique(&mut absent, flag, 256);
        }
    }
    let _ = writeln!(
        output,
        "time flags present: {}\ntime flags absent: {}",
        if present.is_empty() { "none" } else { &present },
        if absent.is_empty() { "none" } else { &absent }
    );
    let _ = writeln!(output, "== cpuid");
    let mut ids = print_cpuid(output);
    if read_msrs {
        let _ = writeln!(output, "== msr (cpu 0)");
        print_msrs(output);
    }

    let _ = writeln!(output, "== kernel");
    if let Ok(line) = read_first_line("/proc/cmdline", 4096) {
        let _ = write!(output, "cmdline: ");
        let _ = output.write_all(&line);
        let _ = writeln!(output);
    }
    if let Ok(line) = read_first_line("/sys/devices/system/cpu/online", 4096) {
        let _ = write!(output, "online cpus: ");
        let _ = output.write_all(&line);
        let _ = writeln!(output);
    }
    for path in PARAM_FILES {
        match read_first_line(path, 4096) {
            Ok(line) => {
                let _ = write!(output, "{path} = ");
                let _ = output.write_all(&line);
                let _ = writeln!(output);
            }
            Err(_) => {
                let _ = writeln!(output, "{path}: absent");
            }
        }
    }

    let _ = writeln!(output, "== kmsg: hypervisor");
    let mut hypervisor = Filter::default();
    match print_kmsg(output, HYPERVISOR_PATTERNS, &mut hypervisor) {
        Err(error) => {
            let _ = writeln!(
                output,
                "(kernel log unavailable: {})",
                String::from_utf8_lossy(&error.text())
            );
        }
        Ok(()) if hypervisor.matches == 0 => {
            let _ = writeln!(output, "(none)");
        }
        Ok(()) => {}
    }
    let _ = writeln!(output, "== kmsg: time");
    let mut time = Filter::default();
    match print_kmsg(output, TIME_PATTERNS, &mut time) {
        Err(error) => {
            let _ = writeln!(
                output,
                "(kernel log unavailable: {})",
                String::from_utf8_lossy(&error.text())
            );
        }
        Ok(()) if time.matches == 0 => {
            let _ = writeln!(output, "(none)");
        }
        Ok(()) => {}
    }
    let _ = writeln!(output, "== timer_list");
    let timer_summary = print_timer_list(output);
    sanitize_token(&mut ids.vendor);
    let _ = writeln!(
        output,
        "NVX-TIME-PROBE clock clocksource={} available={} tsc_hz={} tsc_hz_source={} \
         hv_vendor={} hv_max_leaf={:#x} hv_features_eax={:#x} hv_features_edx={:#x} \
         flags={} missing_flags={} tsc_unstable_msgs={} unchecked_msr_msgs={} {}",
        String::from_utf8_lossy(&clocksource),
        if available.is_empty() {
            "unknown"
        } else {
            &available
        },
        f0(rate.hz),
        rate.source,
        String::from_utf8_lossy(&ids.vendor),
        ids.max_leaf,
        ids.features_eax,
        ids.features_edx,
        if present.is_empty() { "none" } else { &present },
        if absent.is_empty() { "none" } else { &absent },
        time.tsc_unstable,
        time.unchecked_msr,
        timer_summary
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_sanitizing_keeps_only_marker_safe_bytes() {
        let mut value = b"Microsoft Hv/x".to_vec();
        sanitize_token(&mut value);
        assert_eq!(value, b"Microsoft_Hv_x");
    }

    #[test]
    fn unique_lists_do_not_match_substrings() {
        let mut list = String::new();
        add_unique(&mut list, "tsc", 256);
        add_unique(&mut list, "constant_tsc", 256);
        add_unique(&mut list, "tsc", 256);
        assert_eq!(list, "tsc,constant_tsc");
    }
}
