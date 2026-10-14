//! Conformance checks C1 through C11 and the CI-only exhaustive check.

use std::ffi::{CStr, CString};
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::Duration;

use super::decoders::{self, CpuInfo};
use super::events::{DETAIL_MAX, escape_text};
use super::state::TimeState;
use super::system::{
    self, DAEMON_PID_PATH, HUNG_TASK_TIMEOUT, RCU_STALL_COUNT, RCU_STALL_SUPPRESS,
    RCU_STALL_TIMEOUT, Runtime, SOFT_WATCHDOG, clock_ns, rates_load, read_i64, read_text,
    state_apply, state_load, strerror,
};
use super::{MAX_CPUS, NSEC_PER_MSEC, Phase};
use crate::guest::sys::Errno;

const TIMER_LIST_WAIT_NS: i64 = 200 * NSEC_PER_MSEC;
const STATUS_WAIT_NS: i64 = 30 * system::NSEC_PER_SEC;
const STATUS_POLL_NS: i64 = 10 * NSEC_PER_MSEC;
const CLOCKSOURCE_DIR: &str = "/sys/devices/system/clocksource/clocksource0";

#[derive(Clone)]
pub(crate) struct Checks {
    pub(crate) phase: Phase,
    pub(crate) failures: i32,
    pub(crate) possible: usize,
    pub(crate) online_count: usize,
    pub(crate) online: [bool; MAX_CPUS],
    pub(crate) cpuinfo: CpuInfo,
    pub(crate) tsc_hz: u64,
    pub(crate) lapic_hz: u64,
}

impl Checks {
    pub(crate) fn empty(phase: Phase) -> Self {
        Self {
            phase,
            failures: 0,
            possible: 0,
            online_count: 0,
            online: [false; MAX_CPUS],
            cpuinfo: CpuInfo::default(),
            tsc_hz: 0,
            lapic_hz: 0,
        }
    }

    pub(crate) fn load(phase: Phase) -> Result<Self, Errno> {
        let possible = read_text(c"/sys/devices/system/cpu/possible", 256)?;
        let online = read_text(c"/sys/devices/system/cpu/online", 256)?;
        let (_, possible_count) = decoders::parse_cpu_list(&possible).ok_or(Errno(libc::EINVAL))?;
        let (online, online_count) =
            decoders::parse_cpu_list(&online).ok_or(Errno(libc::EINVAL))?;
        if possible_count == 0 || online_count == 0 {
            return Err(Errno(libc::EINVAL));
        }
        Ok(Self {
            possible: possible_count,
            online_count,
            online,
            ..Self::empty(phase)
        })
    }

    pub(crate) fn fail_code(
        &mut self,
        runtime: &Runtime<'_>,
        code: &[u8],
        detail: impl AsRef<[u8]>,
    ) -> bool {
        self.failures = self.failures.saturating_add(1);
        runtime.conformance_failure(code, self.phase, detail.as_ref());
        false
    }

    pub(crate) fn fail(
        &mut self,
        runtime: &Runtime<'_>,
        id: &str,
        detail: impl AsRef<[u8]>,
    ) -> bool {
        self.fail_code(runtime, format!("G_CONFORMANCE_{id}").as_bytes(), detail)
    }
}

pub(crate) fn record_check(
    runtime: &Runtime<'_>,
    checks: &Checks,
    status: &[u8],
    elapsed_us: i64,
    cpu_us: i64,
    tsc_hz: u64,
    lapic_hz: u64,
) -> Result<(), Errno> {
    let Some(index) = checks.phase.check_index() else {
        return Err(Errno(libc::EINVAL));
    };
    state_apply(|state| {
        let check = &mut state.checks[index];
        check.status = status.to_vec();
        check.cpus = checks.online_count as u64;
        check.elapsed_us = elapsed_us;
        check.cpu_us = cpu_us;
        check.generation = if checks.phase == Phase::Boot {
            0
        } else {
            state.generation
        };
        check.failures = -1;
        if runtime.report_only() {
            check.failures = i64::from(checks.failures);
            if checks.failures > 0 && check.status == b"ok" {
                check.status = b"fail".to_vec();
            }
        }
        if tsc_hz != 0 {
            state.tsc_hz = tsc_hz;
        }
        if lapic_hz != 0 {
            state.lapic_hz = lapic_hz;
        }
    })
}

pub(crate) fn pin_to_cpu(cpu: usize) -> Result<(), Errno> {
    // SAFETY: the CPU macros initialize and update a local CPU set.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) != 0
            || libc::sched_getcpu() != cpu as i32
        {
            return Err(Errno::last());
        }
    }
    Ok(())
}

fn check_identity(runtime: &Runtime<'_>, checks: &mut Checks, cpu: usize) -> bool {
    let capacity = checks.possible as u32;
    let expected = [
        [0x4000_0005, 0x7263_694d, 0x666f_736f, 0x7648_2074],
        [0x3123_7648, 0, 0, 0],
        [0x0058_564e, 0x0001_0000, 0, 0],
        [0x0000_8860, 0, 0, 0x0000_0100],
        [0, 0xffff_ffff, 0, 0],
        [capacity, capacity, 0, 0],
    ];
    for (index, expected) in expected.iter().enumerate() {
        let leaf = 0x4000_0000 + index as u32;
        let value = super::super::x86::cpuid(leaf, 0);
        if value != *expected {
            return checks.fail(
                runtime,
                "C1",
                format!(
                    "cpu {cpu} leaf 0x{leaf:08x} is {:08x}:{:08x}:{:08x}:{:08x}, \
                     expected {:08x}:{:08x}:{:08x}:{:08x}",
                    value[0],
                    value[1],
                    value[2],
                    value[3],
                    expected[0],
                    expected[1],
                    expected[2],
                    expected[3]
                ),
            );
        }
    }
    for (first, last) in [(0x4000_0006, 0x4000_000f), (0x4000_0080, 0x4000_0082)] {
        for leaf in first..=last {
            let value = super::super::x86::cpuid(leaf, 0);
            if value != [0; 4] {
                return checks.fail(
                    runtime,
                    "C1",
                    format!(
                        "cpu {cpu} leaf 0x{leaf:08x} is {:08x}:{:08x}:{:08x}:{:08x}, expected zero",
                        value[0], value[1], value[2], value[3]
                    ),
                );
            }
        }
    }
    true
}

fn check_bit(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    cpu: usize,
    name: &str,
    register: u32,
    bit: u32,
    expected: bool,
) -> bool {
    if ((register >> bit) & 1) == u32::from(expected) {
        true
    } else {
        checks.fail(
            runtime,
            "C2",
            format!(
                "cpu {cpu} {name} is {}",
                if expected { "clear" } else { "set" }
            ),
        )
    }
}

fn check_leaf(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    cpu: usize,
    leaf: u32,
    expected: [u32; 4],
) -> bool {
    let value = super::super::x86::cpuid(leaf, 0);
    if value == expected {
        true
    } else {
        checks.fail(
            runtime,
            "C2",
            format!(
                "cpu {cpu} leaf 0x{leaf:08x} is {:08x}:{:08x}:{:08x}:{:08x}, \
                 expected {:08x}:{:08x}:{:08x}:{:08x}",
                value[0],
                value[1],
                value[2],
                value[3],
                expected[0],
                expected[1],
                expected[2],
                expected[3]
            ),
        )
    }
}

fn check_time_bits(runtime: &Runtime<'_>, checks: &mut Checks, cpu: usize) -> bool {
    let maximum = super::super::x86::cpuid(0, 0)[0];
    let leaf1 = super::super::x86::cpuid(1, 0);
    if !(check_bit(
        runtime,
        checks,
        cpu,
        "CPUID.1:ECX[31] (hypervisor)",
        leaf1[2],
        31,
        true,
    ) && check_bit(
        runtime,
        checks,
        cpu,
        "CPUID.1:ECX[24] (TSC-deadline)",
        leaf1[2],
        24,
        false,
    ) && check_bit(
        runtime,
        checks,
        cpu,
        "CPUID.1:ECX[15] (PDCM)",
        leaf1[2],
        15,
        false,
    ) && check_bit(
        runtime,
        checks,
        cpu,
        "CPUID.1:EDX[4] (TSC)",
        leaf1[3],
        4,
        true,
    )) {
        return false;
    }
    if maximum < 6 {
        return checks.fail(runtime, "C2", format!("cpu {cpu} lacks leaf 0x6 (ARAT)"));
    }
    if !check_leaf(runtime, checks, cpu, 6, [4, 0, 0, 0]) {
        return false;
    }
    if maximum >= 7 {
        let value = super::super::x86::cpuid(7, 0);
        if !check_bit(
            runtime,
            checks,
            cpu,
            "CPUID.7.0:EBX[1] (TSC_ADJUST)",
            value[1],
            1,
            false,
        ) {
            return false;
        }
    }
    for leaf in [0x0a, 0x15, 0x16] {
        if maximum >= leaf && !check_leaf(runtime, checks, cpu, leaf, [0; 4]) {
            return false;
        }
    }
    if super::super::x86::cpuid(0x8000_0000, 0)[0] < 0x8000_0007 {
        return checks.fail(runtime, "C2", format!("cpu {cpu} lacks leaf 0x80000007"));
    }
    let extended = super::super::x86::cpuid(0x8000_0001, 0);
    if !check_bit(
        runtime,
        checks,
        cpu,
        "CPUID.80000001:EDX[27] (RDTSCP)",
        extended[3],
        27,
        true,
    ) {
        return false;
    }
    check_leaf(runtime, checks, cpu, 0x8000_0007, [0, 0, 0, 0x100])
}

fn check_msrs(runtime: &Runtime<'_>, checks: &mut Checks, cpu: usize, full: bool) -> bool {
    let descriptor = match runtime.ops.open_msr(cpu, false) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return checks.fail(
                runtime,
                "C3",
                format!(
                    "cpu {cpu}: open /dev/cpu/{cpu}/msr: {}",
                    String::from_utf8_lossy(&error.text())
                ),
            );
        }
    };
    let mut ok = true;
    if full {
        let result = runtime.ops.read_msr(descriptor, 0x4000_0002);
        let (value, error) = match result {
            Ok(value) => (value, 0),
            Err(error) => (0, error),
        };
        if error != 0 || value != cpu as u64 {
            ok = checks.fail(
                runtime,
                "C3",
                format!("cpu {cpu}: MSR 0x40000002 (VP index) is {value} (error {error})"),
            );
        }
    }
    if cpu != 0 {
        system::close(descriptor);
        return ok;
    }
    if ok {
        match runtime.ops.read_msr(descriptor, 0x4000_0022) {
            Err(error) => {
                ok = checks.fail(
                    runtime,
                    "C3",
                    format!(
                        "cpu {cpu}: MSR 0x40000022 read: {}",
                        String::from_utf8_lossy(&strerror(-error))
                    ),
                );
            }
            Ok(value) if checks.tsc_hz != 0 && value != checks.tsc_hz => {
                ok = checks.fail(
                    runtime,
                    "C3",
                    format!(
                        "cpu {cpu}: MSR 0x40000022 is {value} Hz, expected {} Hz",
                        checks.tsc_hz
                    ),
                );
            }
            Ok(value) => checks.tsc_hz = value,
        }
    }
    if ok && full {
        let result = runtime.ops.read_msr(descriptor, 0x4000_0023);
        let (value, error) = match result {
            Ok(value) => (value, 0),
            Err(error) => (0, error),
        };
        if error != 0
            || !matches!(value, 1_000_000_000 | 200_000_000)
            || (checks.lapic_hz != 0 && value != checks.lapic_hz)
        {
            ok = checks.fail(
                runtime,
                "C3",
                format!("cpu {cpu}: MSR 0x40000023 (LAPIC rate) is {value} (error {error})"),
            );
        } else {
            checks.lapic_hz = value;
        }
    }
    if ok && full {
        let result = runtime.ops.read_msr(descriptor, 0x4000_0118);
        let (value, error) = match result {
            Ok(value) => (value, 0),
            Err(error) => (0, error),
        };
        if error != 0 || value != 1 {
            ok = checks.fail(
                runtime,
                "C3",
                format!("cpu {cpu}: MSR 0x40000118 is {value} (error {error})"),
            );
        }
    }
    for msr in [0x4000_0000, 0x4000_0001, 0x4000_0020] {
        if ok && full {
            let error = runtime.ops.read_msr(descriptor, msr).err().unwrap_or(0);
            if error != -libc::EIO {
                ok = checks.fail(
                    runtime,
                    "C3",
                    format!(
                        "cpu {cpu}: MSR 0x{msr:08x} read did not fail with EIO (error {error})"
                    ),
                );
            }
        }
    }
    system::close(descriptor);
    ok
}

fn read_file(path: &str) -> Result<Vec<u8>, Errno> {
    std::fs::read(path).map_err(|error| Errno(error.raw_os_error().unwrap_or(libc::EIO)))
}

fn check_cpuinfo(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    selected: &[bool; MAX_CPUS],
    flags: bool,
) -> bool {
    let text = match read_file("/proc/cpuinfo") {
        Ok(text) => text,
        Err(error) => {
            return checks.fail(
                runtime,
                "C5",
                format!(
                    "read /proc/cpuinfo: {}",
                    String::from_utf8_lossy(&error.text())
                ),
            );
        }
    };
    let (info, result) = decoders::check_cpuinfo(&text, selected, flags);
    checks.cpuinfo = info;
    match result {
        Ok(()) => true,
        Err(detail) => checks.fail(runtime, "C5", detail),
    }
}

fn check_clocksource(runtime: &Runtime<'_>, checks: &mut Checks) -> bool {
    let current = read_file(&format!("{CLOCKSOURCE_DIR}/current_clocksource"));
    let available = read_file(&format!("{CLOCKSOURCE_DIR}/available_clocksource"));
    let (Ok(current), Ok(available)) = (current, available) else {
        return checks.fail(
            runtime,
            "C6",
            format!(
                "clocksource sysfs: {}",
                String::from_utf8_lossy(&Errno::last().text())
            ),
        );
    };
    match decoders::check_clocksource(&current, &available) {
        Ok(()) => true,
        Err(detail) => checks.fail(runtime, "C6", detail),
    }
}

pub(crate) fn check_timer_list(runtime: &Runtime<'_>, checks: &mut Checks, wait_ns: i64) -> bool {
    let deadline = clock_ns(libc::CLOCK_MONOTONIC).wrapping_add(wait_ns);
    loop {
        let text = match read_file("/proc/timer_list") {
            Ok(text) => text,
            Err(error) => {
                return checks.fail(
                    runtime,
                    "C7",
                    format!(
                        "read /proc/timer_list: {}",
                        String::from_utf8_lossy(&error.text())
                    ),
                );
            }
        };
        match decoders::timer_list_verdict(&text, &checks.online) {
            Ok(()) => return true,
            Err(detail) if clock_ns(libc::CLOCK_MONOTONIC) >= deadline => {
                return checks.fail(runtime, "C7", detail);
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn exists(path: &CStr) -> bool {
    // SAFETY: path is NUL-terminated.
    (unsafe { libc::access(path.as_ptr(), libc::F_OK) }) == 0
}

fn check_platform(runtime: &Runtime<'_>, checks: &mut Checks) -> bool {
    if Path::new("/sys/bus/vmbus").exists() {
        return checks.fail(runtime, "C8", "/sys/bus/vmbus exists");
    }
    if Path::new("/sys/devices/system/cpu/cpufreq/policy0").exists() {
        return checks.fail(runtime, "C8", "cpufreq policy0 exists");
    }
    let suppress = read_i64(RCU_STALL_SUPPRESS).unwrap_or(-1);
    if suppress != 0 {
        return checks.fail(
            runtime,
            "C8",
            format!("rcu_cpu_stall_suppress is {suppress}"),
        );
    }
    let timeout = read_i64(RCU_STALL_TIMEOUT).unwrap_or(-1);
    if timeout != 21 {
        return checks.fail(runtime, "C8", format!("rcu_cpu_stall_timeout is {timeout}"));
    }
    true
}

fn check_cmdline(runtime: &Runtime<'_>, checks: &mut Checks) -> bool {
    let text = match read_text(c"/proc/cmdline", 4096) {
        Ok(text) => text,
        Err(error) => {
            return checks.fail(
                runtime,
                "C9",
                format!(
                    "read /proc/cmdline: {}",
                    String::from_utf8_lossy(&error.text())
                ),
            );
        }
    };
    match decoders::check_cmdline(&text) {
        Ok(()) => true,
        Err(detail) => checks.fail(runtime, "C9", detail),
    }
}

pub(crate) fn daemon_pid() -> Option<libc::pid_t> {
    let pid = read_i64(DAEMON_PID_PATH).ok()?;
    if !(2..=i64::from(i32::MAX)).contains(&pid) {
        return None;
    }
    // SAFETY: kill with signal zero probes the process.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
        return None;
    }
    let path = CString::new(format!("/proc/{pid}/comm")).ok()?;
    (read_text(&path, 32).ok()?.as_slice() == b"nvx-time\n").then_some(pid as libc::pid_t)
}

fn check_daemon(runtime: &Runtime<'_>, checks: &mut Checks) -> bool {
    if daemon_pid().is_none() {
        return checks.fail(runtime, "C10", "the time daemon is not running");
    }
    let state = match state_load() {
        Ok(state) => state,
        Err(_) => return checks.fail(runtime, "C10", "time state is unreadable"),
    };
    if state.violations != 0 {
        return checks.fail(
            runtime,
            "C10",
            format!("the time daemon recorded {} violations", state.violations),
        );
    }
    let stalls = read_i64(RCU_STALL_COUNT).unwrap_or(-1);
    if stalls != 0 {
        return checks.fail(runtime, "C10", format!("rcu_stall_count is {stalls}"));
    }
    true
}

fn check_debug_watchdogs(runtime: &Runtime<'_>, checks: &mut Checks) -> bool {
    let soft = exists(SOFT_WATCHDOG);
    let hung = exists(HUNG_TASK_TIMEOUT);
    if !soft && !hung {
        return true;
    }
    let value = if soft {
        read_i64(SOFT_WATCHDOG).unwrap_or(-1)
    } else {
        -1
    };
    if !soft || value != 1 {
        return checks.fail(runtime, "C11", format!("soft_watchdog is {value}"));
    }
    let value = if hung {
        read_i64(HUNG_TASK_TIMEOUT).unwrap_or(-1)
    } else {
        -1
    };
    if !hung || value == 0 {
        return checks.fail(runtime, "C11", format!("hung_task_timeout_secs is {value}"));
    }
    true
}

fn check_one_cpu(
    runtime: &Runtime<'_>,
    base: &Checks,
    cpu: usize,
    identity: bool,
    msrs: bool,
) -> Checks {
    let mut checks = base.clone();
    checks.failures = 0;
    if let Err(error) = pin_to_cpu(cpu) {
        checks.fail(
            runtime,
            "C1",
            format!(
                "cannot run on cpu {cpu}: {}",
                String::from_utf8_lossy(&error.text())
            ),
        );
        return checks;
    }
    if identity {
        check_identity(runtime, &mut checks, cpu);
        check_time_bits(runtime, &mut checks, cpu);
    }
    if msrs {
        check_msrs(runtime, &mut checks, cpu, true);
    }
    checks
}

fn restore_affinity(original: &libc::cpu_set_t) {
    // SAFETY: `original` came from sched_getaffinity.
    unsafe {
        libc::sched_setaffinity(0, std::mem::size_of_val(original), original);
    }
}

fn check_cpus(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    selected: &[bool; MAX_CPUS],
    identity: bool,
    msrs: bool,
) -> bool {
    // SAFETY: sched_getaffinity initializes the local CPU set.
    let mut original: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&original), &raw mut original) }
        != 0
    {
        return checks.fail(
            runtime,
            "C1",
            format!(
                "sched_getaffinity: {}",
                String::from_utf8_lossy(&Errno::last().text())
            ),
        );
    }
    let mut ok = true;
    for (cpu, selected) in selected.iter().copied().enumerate() {
        if !selected || !ok {
            continue;
        }
        let child = check_one_cpu(runtime, checks, cpu, identity, msrs);
        checks.failures += child.failures;
        if cpu == 0 && msrs {
            checks.tsc_hz = child.tsc_hz;
            checks.lapic_hz = child.lapic_hz;
        }
        ok = child.failures == 0;
    }
    restore_affinity(&original);
    ok
}

fn boot_log(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    read_log: bool,
    size: i32,
    buffer: Option<&mut [u8]>,
) {
    if !read_log {
        return;
    }
    let Some(buffer) = buffer else {
        checks.fail(
            runtime,
            "C4",
            format!("no buffer for the {size}-byte kernel log"),
        );
        return;
    };
    // SAFETY: the buffer has `size + 1` writable bytes.
    let count = unsafe { libc::klogctl(3, buffer.as_mut_ptr().cast(), size) };
    if count < 0 {
        checks.fail(
            runtime,
            "C4",
            format!(
                "read the kernel log: {}",
                String::from_utf8_lossy(&Errno::last().text())
            ),
        );
        return;
    }
    let log = decoders::scan_boot_log(&buffer[..count as usize], true);
    if let Err(detail) = log.verdict() {
        checks.fail(runtime, "C4", detail);
    }
    if !log.wx.is_empty() {
        checks.fail_code(runtime, b"G_KERNEL_WX", &log.wx);
    }
}

/// Runs every boot check except C12 in the same per-CPU and side-job parallel shape as C.
pub(crate) fn run_boot_checks(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    read_log: bool,
    log_size: i32,
    log_buffer: Option<&mut [u8]>,
) {
    let base = checks.clone();
    let selected = checks.online;
    if checks.online_count <= 1 {
        check_cmdline(runtime, checks);
        check_platform(runtime, checks);
        check_clocksource(runtime, checks);
        check_debug_watchdogs(runtime, checks);
        let mut side = base.clone();
        side.failures = 0;
        boot_log(runtime, &mut side, read_log, log_size, log_buffer);
        checks.failures += side.failures;
        let mut side = base.clone();
        side.failures = 0;
        check_timer_list(runtime, &mut side, TIMER_LIST_WAIT_NS);
        checks.failures += side.failures;
        let mut side = base.clone();
        side.failures = 0;
        check_cpuinfo(runtime, &mut side, &selected, true);
        checks.failures += side.failures;
        checks.cpuinfo = side.cpuinfo;
        check_cpus(runtime, checks, &selected, true, true);
        compare_cpu_rate(runtime, checks);
        return;
    }
    thread::scope(|scope| {
        let log_base = base.clone();
        let log = scope.spawn(move || {
            let mut side = log_base;
            side.failures = 0;
            boot_log(runtime, &mut side, read_log, log_size, log_buffer);
            side
        });
        let timer_base = base.clone();
        let timer = scope.spawn(move || {
            let mut side = timer_base;
            side.failures = 0;
            check_timer_list(runtime, &mut side, TIMER_LIST_WAIT_NS);
            side
        });
        let cpuinfo_base = base.clone();
        let cpuinfo = scope.spawn(move || {
            let mut side = cpuinfo_base;
            side.failures = 0;
            check_cpuinfo(runtime, &mut side, &selected, true);
            side
        });
        let mut cpus = Vec::new();
        for (cpu, selected) in selected.iter().copied().enumerate() {
            if selected {
                let cpu_base = base.clone();
                cpus.push((
                    cpu,
                    scope.spawn(move || check_one_cpu(runtime, &cpu_base, cpu, true, true)),
                ));
            }
        }

        check_cmdline(runtime, checks);
        check_platform(runtime, checks);
        check_clocksource(runtime, checks);
        check_debug_watchdogs(runtime, checks);

        for side in [log.join(), timer.join()] {
            match side {
                Ok(side) => checks.failures += side.failures,
                Err(_) => {
                    checks.fail(runtime, "C10", "a boot side job crashed");
                }
            }
        }
        match cpuinfo.join() {
            Ok(side) => {
                checks.failures += side.failures;
                checks.cpuinfo = side.cpuinfo;
            }
            Err(_) => {
                checks.fail(runtime, "C10", "the cpuinfo side job crashed");
            }
        }
        for (cpu, handle) in cpus {
            match handle.join() {
                Ok(child) => {
                    checks.failures += child.failures;
                    if cpu == 0 {
                        checks.tsc_hz = child.tsc_hz;
                        checks.lapic_hz = child.lapic_hz;
                    }
                }
                Err(_) => {
                    checks.fail(runtime, "C1", format!("the cpu {cpu} job crashed"));
                }
            }
        }
    });
    compare_cpu_rate(runtime, checks);
}

fn compare_cpu_rate(runtime: &Runtime<'_>, checks: &mut Checks) {
    if checks.tsc_hz != 0
        && checks.cpuinfo.known[0]
        && checks.tsc_hz / 1000 != checks.cpuinfo.khz[0]
    {
        checks.fail(
            runtime,
            "C3",
            format!(
                "cpu 0: floor(F / 1000) is {} kHz but cpu MHz is {} kHz",
                checks.tsc_hz / 1000,
                checks.cpuinfo.khz[0]
            ),
        );
    }
}

pub(crate) fn run_capture_checks(runtime: &Runtime<'_>, checks: &mut Checks) {
    if let Ok((tsc, lapic)) = rates_load() {
        checks.tsc_hz = tsc;
        checks.lapic_hz = lapic;
    }
    check_clocksource(runtime, checks);
    check_timer_list(runtime, checks, 0);
    check_daemon(runtime, checks);
}

pub(crate) fn run_restore_checks(
    runtime: &Runtime<'_>,
    checks: &mut Checks,
    new_cpus: &[bool; MAX_CPUS],
    new_count: usize,
) {
    match rates_load() {
        Ok((tsc, lapic)) => {
            checks.tsc_hz = tsc;
            checks.lapic_hz = lapic;
        }
        Err(_) => {
            checks.fail(runtime, "C3", "the boot rates are unavailable");
        }
    }
    if new_count > 0 {
        check_cpus(runtime, checks, new_cpus, true, false);
        check_cpuinfo(runtime, checks, new_cpus, true);
    }
    check_msrs(runtime, checks, 0, false);
    check_clocksource(runtime, checks);
    check_daemon(runtime, checks);
}

pub(crate) fn wait_for_checks(boot_only: bool) -> (TimeState, bool) {
    let deadline = clock_ns(libc::CLOCK_MONOTONIC).wrapping_add(STATUS_WAIT_NS);
    loop {
        let state = state_load().unwrap_or_default();
        let count = if boot_only { 1 } else { Phase::CHECKS.len() };
        let pending = state.checks[..count]
            .iter()
            .any(|check| check.status == b"pending");
        if !pending {
            return (state, true);
        }
        if clock_ns(libc::CLOCK_MONOTONIC) >= deadline {
            return (state, false);
        }
        thread::sleep(Duration::from_nanos(STATUS_POLL_NS as u64));
    }
}

struct Exhaustive {
    failures: i32,
    tsc_hz: u64,
    lapic_hz: u64,
    cpuinfo: CpuInfo,
}

fn exhaustive_report(
    output: &mut dyn Write,
    state: &mut Exhaustive,
    id: &str,
    cpu: usize,
    passed: bool,
    detail: &[u8],
) {
    let escaped = escape_text(detail, DETAIL_MAX - 1);
    let _ = write!(
        output,
        "NVX-TIME-ABI-EXHAUSTIVE: v=1 check={id} cpu={cpu} status={} detail=\"",
        if passed { "pass" } else { "fail" }
    );
    let _ = output.write_all(&escaped);
    let _ = output.write_all(b"\"\n");
    if !passed {
        state.failures += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn exhaustive_leaves(
    output: &mut dyn Write,
    state: &mut Exhaustive,
    id: &str,
    cpu: usize,
    first: u32,
    last: u32,
    step: usize,
    out_of_range: [u32; 4],
) {
    let mut first_detail = String::new();
    let mut failing = 0;
    let mut count = 0;
    for leaf in (first..=last).step_by(step) {
        count += 1;
        if let Err(detail) =
            decoders::exhaustive_leaf_ok(leaf, super::super::x86::cpuid(leaf, 0), out_of_range)
        {
            if failing == 0 {
                first_detail = detail;
            }
            failing += 1;
        }
    }
    let detail = if failing == 0 {
        format!(
            "{count} {} read zero or the highest basic leaf",
            if step == 1 { "leaves" } else { "bases" }
        )
    } else if failing > 1 {
        format!("{first_detail}; {failing} of {count} fail")
    } else {
        first_detail
    };
    exhaustive_report(output, state, id, cpu, failing == 0, detail.as_bytes());
}

fn read_msr(runtime: &Runtime<'_>, descriptor: i32, msr: u32) -> (u64, i32) {
    runtime
        .ops
        .read_msr(descriptor, msr)
        .map_or_else(|error| (0, error), |value| (value, 0))
}

fn exhaustive_x3(
    runtime: &Runtime<'_>,
    output: &mut dyn Write,
    state: &mut Exhaustive,
    descriptor: i32,
    cpu: usize,
) {
    let (index, mut error) = read_msr(runtime, descriptor, 0x4000_0002);
    let mut detail;
    let mut ok = false;
    let mut tsc = 0;
    let mut lapic = 0;
    if error != 0 || index != cpu as u64 {
        detail = format!("MSR 0x40000002 (VP index) is {index} (error {error})");
    } else {
        (tsc, error) = read_msr(runtime, descriptor, 0x4000_0022);
        if error != 0 || tsc == 0 || (state.tsc_hz != 0 && tsc != state.tsc_hz) {
            detail = format!(
                "MSR 0x40000022 (TSC rate) is {tsc} (error {error}; first CPU {})",
                state.tsc_hz
            );
        } else if state.cpuinfo.known[cpu] && tsc / 1000 != state.cpuinfo.khz[cpu] {
            detail = format!(
                "floor(F / 1000) is {} kHz but cpu MHz is {} kHz",
                tsc / 1000,
                state.cpuinfo.khz[cpu]
            );
        } else {
            (lapic, error) = read_msr(runtime, descriptor, 0x4000_0023);
            if error != 0
                || !matches!(lapic, 1_000_000_000 | 200_000_000)
                || (state.lapic_hz != 0 && lapic != state.lapic_hz)
            {
                detail = format!(
                    "MSR 0x40000023 (LAPIC rate) is {lapic} (error {error}; first CPU {})",
                    state.lapic_hz
                );
            } else {
                let (control, control_error) = read_msr(runtime, descriptor, 0x4000_0118);
                error = control_error;
                if error != 0 || control != 1 {
                    detail = format!("MSR 0x40000118 is {control} (error {error})");
                } else {
                    detail = String::new();
                    ok = true;
                }
            }
        }
    }
    for msr in [0x4000_0000, 0x4000_0001, 0x4000_0020] {
        if ok {
            let error = runtime.ops.read_msr(descriptor, msr).err().unwrap_or(0);
            if error != -libc::EIO {
                ok = false;
                detail = format!("MSR 0x{msr:08x} read did not fail with EIO (error {error})");
            }
        }
    }
    if ok {
        detail = format!("vp_index={cpu} tsc_hz={tsc} lapic_hz={lapic} invariant_control=1");
        if state.tsc_hz == 0 {
            state.tsc_hz = tsc;
            state.lapic_hz = lapic;
        }
    }
    exhaustive_report(output, state, "X3", cpu, ok, detail.as_bytes());
}

fn exhaustive_x4(
    runtime: &Runtime<'_>,
    output: &mut dyn Write,
    state: &mut Exhaustive,
    descriptor: i32,
    cpu: usize,
) {
    let mut detail = "0 and 1 accepted, 2 rejected, left at 1".to_owned();
    let mut ok = true;
    for written in 0..=1 {
        let error = runtime
            .ops
            .write_msr(descriptor, 0x4000_0118, written)
            .err()
            .unwrap_or(0);
        let (value, read_error) = read_msr(runtime, descriptor, 0x4000_0118);
        let error = if error != 0 { error } else { read_error };
        if error != 0 || value != written {
            ok = false;
            detail = format!("after writing {written}, MSR 0x40000118 is {value} (error {error})");
            break;
        }
    }
    if ok {
        let error = runtime
            .ops
            .write_msr(descriptor, 0x4000_0118, 2)
            .err()
            .unwrap_or(0);
        if error != -libc::EIO {
            ok = false;
            detail = format!("write of 2 to MSR 0x40000118 did not fail with EIO (error {error})");
        }
    }
    let _ = runtime.ops.write_msr(descriptor, 0x4000_0118, 1);
    if ok {
        let (value, error) = read_msr(runtime, descriptor, 0x4000_0118);
        if error != 0 || value != 1 {
            ok = false;
            detail = format!("MSR 0x40000118 is {value} after the check");
        }
    }
    exhaustive_report(output, state, "X4", cpu, ok, detail.as_bytes());
}

fn exhaustive_faults(
    runtime: &Runtime<'_>,
    output: &mut dyn Write,
    state: &mut Exhaustive,
    descriptor: i32,
    cpu: usize,
    writes: bool,
) {
    let list: &[u32] = if writes {
        &[
            0x4000_0000,
            0x4000_0001,
            0x4000_0002,
            0x4000_0020,
            0x4000_0022,
            0x4000_0023,
        ]
    } else {
        &[0x3b, 0x6e0]
    };
    let mut detail = format!(
        "{} {} fail with EIO",
        list.len(),
        if writes { "writes" } else { "reads" }
    );
    let mut ok = true;
    for &msr in list {
        let error = if writes {
            runtime.ops.write_msr(descriptor, msr, 0).err().unwrap_or(0)
        } else {
            runtime.ops.read_msr(descriptor, msr).err().unwrap_or(0)
        };
        if error != -libc::EIO {
            ok = false;
            detail = format!(
                "{} MSR 0x{msr:x} did not fail with EIO (error {error})",
                if writes { "write of 0 to" } else { "read of" }
            );
            break;
        }
    }
    exhaustive_report(
        output,
        state,
        if writes { "X5" } else { "X6" },
        cpu,
        ok,
        detail.as_bytes(),
    );
}

pub(crate) fn exhaustive(runtime: &Runtime<'_>, output: &mut dyn Write) -> u8 {
    let mut state = Exhaustive {
        failures: 0,
        tsc_hz: 0,
        lapic_hz: 0,
        cpuinfo: CpuInfo::default(),
    };
    let online = read_text(c"/sys/devices/system/cpu/online", 256)
        .ok()
        .and_then(|text| decoders::parse_cpu_list(&text));
    let Some((cpus, online_count)) = online.filter(|(_, count)| *count > 0) else {
        let _ = writeln!(
            output,
            "NVX-TIME-ABI-EXHAUSTIVE: v=1 status=fail cpus=0 failures=1"
        );
        return 1;
    };
    if let Ok(text) = read_file("/proc/cpuinfo") {
        state.cpuinfo = decoders::check_cpuinfo(&text, &cpus, false).0;
    }
    // SAFETY: sched_getaffinity initializes the local CPU set.
    let mut original: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let original_valid =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&original), &raw mut original) }
            == 0;
    for (cpu, online) in cpus.iter().copied().enumerate() {
        if !online {
            continue;
        }
        if pin_to_cpu(cpu).is_err() {
            for id in ["X1", "X2", "X3", "X4", "X5", "X6"] {
                exhaustive_report(
                    output,
                    &mut state,
                    id,
                    cpu,
                    false,
                    b"cannot run on this CPU",
                );
            }
            continue;
        }
        let basic = super::super::x86::cpuid(0, 0);
        let out_of_range = super::super::x86::cpuid(basic[0], 0);
        exhaustive_leaves(
            output,
            &mut state,
            "X1",
            cpu,
            0x4000_0006,
            0x4000_00ff,
            1,
            out_of_range,
        );
        exhaustive_leaves(
            output,
            &mut state,
            "X2",
            cpu,
            0x4000_0100,
            0x4000_ff00,
            0x100,
            out_of_range,
        );
        match runtime.ops.open_msr(cpu, true) {
            Ok(descriptor) => {
                exhaustive_x3(runtime, output, &mut state, descriptor, cpu);
                exhaustive_x4(runtime, output, &mut state, descriptor, cpu);
                exhaustive_faults(runtime, output, &mut state, descriptor, cpu, true);
                exhaustive_faults(runtime, output, &mut state, descriptor, cpu, false);
                system::close(descriptor);
            }
            Err(error) => {
                let detail = format!(
                    "open /dev/cpu/{cpu}/msr: {}",
                    String::from_utf8_lossy(&error.text())
                );
                for id in ["X3", "X4", "X5", "X6"] {
                    exhaustive_report(output, &mut state, id, cpu, false, detail.as_bytes());
                }
            }
        }
    }
    if original_valid {
        restore_affinity(&original);
    }
    let status = if state.failures == 0 { "ok" } else { "fail" };
    let _ = writeln!(
        output,
        "NVX-TIME-ABI-EXHAUSTIVE: v=1 status={status} cpus={online_count} failures={}",
        state.failures
    );
    u8::from(state.failures != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_timeout_math_uses_the_abi_constants() {
        assert_eq!(STATUS_WAIT_NS, 30_000_000_000);
        assert_eq!(STATUS_POLL_NS, 10_000_000);
        assert_eq!(TIMER_LIST_WAIT_NS, 200_000_000);
    }
}
