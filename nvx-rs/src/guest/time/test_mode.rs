//! The `nvx-time test` compatibility interface.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::decoders::{
    self, Correction, GENERATION_ID_SIZE, PACKET_HEADER_SIZE, PACKET_MAX_SIZE, RestorePacket,
    SAMPLE_SIZE, TimeSample,
};
use super::events::{DETAIL_MAX, escape_text, format_event};
use super::state::TimeState;
use super::{DEFERRED_START_NS, IDLE_BOUND_NS, MAX_CPUS, NSEC_PER_MSEC, Phase};

const TEXT_MAX: usize = 65_536;

/// Runs a named pure-logic test. The C interface exits 0 for a decoded failure and 2 only when
/// the test invocation itself is malformed.
pub(super) fn run(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    let Some((&name, arguments)) = arguments.split_first() else {
        return 2;
    };
    match name {
        b"packet" => test_packet(arguments, out),
        b"sample" => test_sample(arguments, out),
        b"pair" => test_pair(arguments, out),
        b"kmsg" => test_lines(arguments, LineMode::Kmsg, out),
        b"boot-log" => test_lines(arguments, LineMode::BootLog, out),
        b"syslog" => test_lines(arguments, LineMode::Syslog, out),
        b"console" => test_console(arguments, out),
        b"exhaustive-leaf" => test_exhaustive_leaf(arguments, out),
        b"exhaustive-report" => test_exhaustive_report(arguments, out),
        b"exhaustive-summary" => test_exhaustive_summary(arguments, out),
        b"timer-list" => test_timer_list(arguments, out),
        b"correction" => test_correction(arguments, out),
        b"frequency" => test_frequency(arguments, out),
        b"event" => test_event(arguments, out),
        b"state" => test_state(arguments, out),
        b"status" => test_status(arguments, out),
        b"restore-record" => test_restore_record(arguments, out),
        b"step13-cpu" => test_step13_cpu(arguments, out),
        b"deferral" if arguments.is_empty() => {
            let _ = writeln!(
                out,
                "deferred_start_ms={} idle_bound_ms={}",
                DEFERRED_START_NS / NSEC_PER_MSEC,
                IDLE_BOUND_NS / NSEC_PER_MSEC
            );
            0
        }
        b"parallel" => test_parallel(arguments, out),
        b"promote" if arguments.is_empty() => test_promote(out),
        b"idle-priority" if arguments.is_empty() => test_idle_priority(out),
        b"cpuinfo" => test_cpuinfo(arguments, out),
        b"cmdline" => test_cmdline(arguments, out),
        b"clocksource" => test_clocksource(arguments, out),
        _ => 2,
    }
}

fn read_file(path: &[u8], size: usize, zero_fill: bool) -> Option<Vec<u8>> {
    let path = OsStr::from_bytes(path);
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(size);
    use std::io::Read as _;
    file.take(size as u64).read_to_end(&mut bytes).ok()?;
    if zero_fill {
        bytes.resize(size, 0);
    } else if bytes.len() == size {
        bytes.truncate(size.saturating_sub(1));
    }
    Some(bytes)
}

fn test_packet(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 3 {
        return 2;
    }
    let Some(bytes) = read_file(arguments[0], PACKET_MAX_SIZE, true) else {
        return 2;
    };
    let Some(previous) = decoders::parse_hex(arguments[2], GENERATION_ID_SIZE) else {
        return 2;
    };
    let recorded = decoders::parse_u64_lossy(arguments[1]);
    let mut packet = match RestorePacket::parse_header(&bytes) {
        Ok(packet) => packet,
        Err(detail) => {
            let _ = writeln!(out, "error G_REPAIR_PACKET {detail}");
            return 0;
        }
    };
    if u64::from(packet.generation) == recorded {
        let _ = writeln!(out, "stale");
        return 0;
    }
    if u64::from(packet.generation) != recorded.wrapping_add(1) {
        let _ = writeln!(
            out,
            "error G_REPAIR_GENERATION generation {}",
            packet.generation
        );
        return 0;
    }
    if let Err(detail) = packet.parse_body(&bytes[PACKET_HEADER_SIZE..]) {
        let _ = writeln!(out, "error G_REPAIR_PACKET {detail}");
        return 0;
    }
    if packet.entropy[..GENERATION_ID_SIZE] == previous {
        let _ = writeln!(out, "error G_REPAIR_GENERATION generation ID unchanged");
        return 0;
    }
    let _ = write!(
        out,
        "ok flags={} online={} ranges={} generation={} rate_deviation={} \
         frequency={} downtime_ns={} utc_ns={} generation_id={}",
        packet.flags,
        packet.online_vp_count,
        packet.range_count,
        packet.generation,
        packet.rate_deviation,
        decoders::restore_frequency(packet.rate_deviation),
        packet.downtime_ns,
        packet.utc_ns,
        decoders::format_hex(&packet.entropy[..GENERATION_ID_SIZE])
    );
    for (start, length) in packet.ranges {
        let _ = write!(out, " range={start}:{length}");
    }
    let _ = writeln!(out);
    0
}

fn test_sample(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    let Some(bytes) = read_file(arguments[0], SAMPLE_SIZE, true) else {
        return 2;
    };
    match TimeSample::parse(&bytes) {
        Err(detail) => {
            let _ = writeln!(out, "error {detail}");
        }
        Ok(sample) if u64::from(sample.generation) != decoders::parse_u64_lossy(arguments[1]) => {
            let _ = writeln!(out, "error generation {}", sample.generation);
        }
        Ok(sample) => {
            let _ = writeln!(
                out,
                "ok flags={} generation={} utc_ns={}",
                sample.flags, sample.generation, sample.utc_ns
            );
        }
    }
    0
}

fn test_pair(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 3 {
        return 2;
    }
    let (theta, epsilon) = decoders::pair_clocks(
        decoders::parse_i64_lossy(arguments[0]),
        decoders::parse_i64_lossy(arguments[1]),
        decoders::parse_u64_lossy(arguments[2]),
    );
    let _ = writeln!(out, "theta_ns={theta} epsilon_ns={epsilon}");
    0
}

#[derive(Clone, Copy)]
enum LineMode {
    Kmsg,
    BootLog,
    Syslog,
}

fn test_lines(arguments: &[&[u8]], mode: LineMode, out: &mut dyn Write) -> u8 {
    if arguments.len() != 1 {
        return 2;
    }
    let Some(text) = read_file(arguments[0], TEXT_MAX, false) else {
        return 2;
    };
    if matches!(mode, LineMode::Kmsg) {
        let text = text.split(|byte| *byte == 0).next().unwrap_or_default();
        for line in text
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let code = decoders::match_watch_rule(line).unwrap_or("none");
            let _ = writeln!(out, "{code}");
        }
        return 0;
    }
    let log = decoders::scan_boot_log(&text, matches!(mode, LineMode::Syslog));
    match log.verdict() {
        Ok(()) => {
            let _ = writeln!(out, "ok");
        }
        Err(detail) => {
            let _ = out.write_all(b"fail ");
            let _ = out.write_all(&detail);
            let _ = out.write_all(b"\n");
        }
    }
    if !log.wx.is_empty() {
        let _ = out.write_all(b"wx ");
        let _ = out.write_all(&log.wx);
        let _ = out.write_all(b"\n");
    }
    0
}

fn test_console(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    if arguments[1] == b"async" {
        let _ = out.write_all(b"\n");
    }
    let _ = out.write_all(arguments[0]);
    0
}

fn base0_u32(text: &[u8]) -> u32 {
    super::super::parse::parse_u64(text).unwrap_or(0) as u32
}

fn test_exhaustive_leaf(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 9 {
        return 2;
    }
    let mut value = [0; 4];
    let mut out_of_range = [0; 4];
    for index in 0..4 {
        value[index] = base0_u32(arguments[index + 1]);
        out_of_range[index] = base0_u32(arguments[index + 5]);
    }
    match decoders::exhaustive_leaf_ok(base0_u32(arguments[0]), value, out_of_range) {
        Ok(()) => {
            let _ = writeln!(out, "pass");
        }
        Err(detail) => {
            let _ = writeln!(out, "fail {detail}");
        }
    }
    0
}

fn test_exhaustive_report(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 4 {
        return 2;
    }
    let passed = arguments[2] == b"pass";
    let escaped = escape_text(arguments[3], DETAIL_MAX - 1);
    let _ = write!(
        out,
        "NVX-TIME-ABI-EXHAUSTIVE: v=1 check={} cpu={} status={} detail=\"",
        String::from_utf8_lossy(arguments[0]),
        decoders::parse_i64_lossy(arguments[1]),
        if passed { "pass" } else { "fail" }
    );
    let _ = out.write_all(&escaped);
    let _ = writeln!(out, "\"");
    let _ = writeln!(out, "failures={}", usize::from(!passed));
    0
}

fn test_exhaustive_summary(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    let online = decoders::parse_i64_lossy(arguments[0]);
    let failures = decoders::parse_i64_lossy(arguments[1]);
    let status = if failures == 0 { "ok" } else { "fail" };
    let _ = writeln!(
        out,
        "NVX-TIME-ABI-EXHAUSTIVE: v=1 status={status} cpus={online} failures={failures}"
    );
    let _ = writeln!(out, "exit={}", i32::from(failures != 0));
    0
}

fn test_timer_list(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    let Some(text) = read_file(arguments[0], TEXT_MAX, false) else {
        return 2;
    };
    let Some((cpus, count)) = decoders::parse_cpu_list(arguments[1]) else {
        return 2;
    };
    if count == 0 {
        return 2;
    }
    match decoders::timer_list_verdict(&text, &cpus) {
        Ok(()) => {
            let _ = writeln!(out, "ok");
        }
        Err(detail) => {
            let _ = out.write_all(b"fail ");
            let _ = out.write_all(&detail);
            let _ = out.write_all(b"\n");
        }
    }
    0
}

fn test_correction(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 3 {
        return 2;
    }
    let correction = decoders::plan_correction(
        decoders::parse_i64_lossy(arguments[0]),
        decoders::parse_i64_lossy(arguments[1]),
        arguments[2] == b"fast",
    );
    match correction {
        Correction::Step {
            modes,
            seconds,
            nanoseconds,
        } => {
            let _ = writeln!(
                out,
                "step modes=0x{modes:x} sec={seconds} nsec={nanoseconds}"
            );
        }
        Correction::Slew {
            modes,
            offset,
            status,
            constant,
            maxerror,
            esterror,
        } => {
            let _ = writeln!(
                out,
                "slew modes=0x{modes:x} offset={offset} status=0x{status:x} \
                 constant={constant} maxerror={maxerror} esterror={esterror}"
            );
        }
    }
    0
}

fn test_frequency(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 1 {
        return 2;
    }
    let frequency = decoders::restore_frequency(decoders::parse_i64_lossy(arguments[0]) as i32);
    let _ = writeln!(
        out,
        "frequency={frequency} ppb={}",
        decoders::frequency_to_ppb(frequency)
    );
    0
}

fn test_event(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 6 {
        return 2;
    }
    let phase = match arguments[2] {
        b"boot" => Phase::Boot,
        b"capture" => Phase::Capture,
        b"restore" => Phase::Restore,
        _ => Phase::Runtime,
    };
    let line = format_event(
        false,
        arguments[0],
        arguments[1],
        phase,
        decoders::parse_u64_lossy(arguments[3]) as u32,
        decoders::parse_i64_lossy(arguments[4]),
        arguments[5],
    );
    let _ = out.write_all(&line);
    0
}

fn test_state(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 1 {
        return 2;
    }
    let Some(text) = read_file(arguments[0], 4096, false) else {
        return 2;
    };
    let Some(state) = TimeState::parse(&text) else {
        let _ = writeln!(out, "error");
        return 0;
    };
    let _ = out.write_all(&state.format());
    0
}

fn test_status(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    let Some(text) = read_file(arguments[0], 4096, false) else {
        return 2;
    };
    let Some(state) = TimeState::parse(&text) else {
        return 2;
    };
    let (text, ok) = state.format_status(arguments[1] == b"report-only");
    let _ = out.write_all(&text);
    let _ = writeln!(out, "ok={}", u8::from(ok));
    0
}

fn test_restore_record(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 1 {
        return 2;
    }
    let Some(text) = read_file(arguments[0], 4096, false) else {
        return 2;
    };
    let Some((generation, cpus, count)) = decoders::parse_restore_record(&text) else {
        let _ = writeln!(out, "error");
        return 0;
    };
    let _ = write!(out, "generation={generation} new_cpus=");
    let mut separator = "";
    for (cpu, selected) in cpus.iter().copied().enumerate() {
        if selected {
            let _ = write!(out, "{separator}{cpu}");
            separator = ",";
        }
    }
    if count == 0 {
        let _ = write!(out, "none");
    }
    let _ = writeln!(out, " count={count}");
    0
}

fn boottime_ns() -> i64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes `now`.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut now) };
    now.tv_sec * 1_000_000_000 + now.tv_nsec
}

fn failure_event(id: &str, detail: &[u8]) -> Vec<u8> {
    let code = format!("G_CONFORMANCE_{id}");
    format_event(
        true,
        code.as_bytes(),
        b"conformance",
        Phase::Boot,
        0,
        boottime_ns(),
        detail,
    )
}

fn test_cpuinfo(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    let Some(text) = read_file(arguments[0], TEXT_MAX, false) else {
        return 2;
    };
    let Some((selected, count)) = decoders::parse_cpu_list(arguments[1]) else {
        return 2;
    };
    if count == 0 {
        return 2;
    }
    let (cpuinfo, verdict) = decoders::check_cpuinfo(&text, &selected, true);
    match verdict {
        Ok(()) => {
            let _ = write!(out, "ok");
            for cpu in 0..MAX_CPUS {
                if cpuinfo.known[cpu] {
                    let _ = write!(out, " cpu{cpu}_khz={}", cpuinfo.khz[cpu]);
                }
            }
            let _ = writeln!(out);
        }
        Err(detail) => {
            let _ = out.write_all(&failure_event("C5", detail.as_bytes()));
        }
    }
    0
}

fn test_cmdline(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 1 {
        return 2;
    }
    match decoders::check_cmdline(arguments[0]) {
        Ok(()) => {
            let _ = writeln!(out, "ok");
        }
        Err(detail) => {
            let _ = out.write_all(&failure_event("C9", &detail));
        }
    }
    0
}

fn test_clocksource(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 2 {
        return 2;
    }
    match decoders::check_clocksource(arguments[0], arguments[1]) {
        Ok(()) => {
            let _ = writeln!(out, "ok");
        }
        Err(detail) => {
            let _ = out.write_all(&failure_event("C6", &detail));
        }
    }
    0
}

fn set_idle_priority(tid: libc::pid_t, idle: bool) {
    // musl exposes its deadline-scheduler extension fields in `sched_param`; zero is the
    // SCHED_IDLE/SCHED_OTHER parameter in both libc layouts.
    let parameter: libc::sched_param = unsafe { std::mem::zeroed() };
    // SAFETY: the syscall reads `parameter`; tid 0 means the calling thread.
    unsafe {
        libc::syscall(
            libc::SYS_sched_setscheduler,
            tid,
            if idle {
                libc::SCHED_IDLE
            } else {
                libc::SCHED_OTHER
            },
            &raw const parameter,
        );
    }
}

fn scheduler(tid: libc::pid_t) -> libc::c_long {
    // SAFETY: sched_getscheduler has no pointer arguments.
    unsafe { libc::syscall(libc::SYS_sched_getscheduler, tid) }
}

fn pin_current(cpu: usize) -> Result<(), i32> {
    // SAFETY: CPU_ZERO/CPU_SET initialize a local cpu_set_t and sched_setaffinity reads it.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) != 0
            || libc::sched_getcpu() != cpu as i32
        {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL));
        }
    }
    Ok(())
}

fn test_parallel(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 1 {
        return 2;
    }
    let Some((selected, count)) = decoders::parse_cpu_list(arguments[0]) else {
        return 2;
    };
    if count == 0 {
        return 2;
    }
    let mut failures = 0;
    for side in 1..=3 {
        for index in 1..=side {
            let detail = format!("side job failure {index}");
            let _ = out.write_all(&failure_event("C4", detail.as_bytes()));
            failures += 1;
        }
    }
    let _ = out.write_all(&failure_event("C9", b"foreground failure"));
    failures += 1;
    for (cpu, selected) in selected.iter().copied().enumerate() {
        if !selected {
            continue;
        }
        let result = std::thread::spawn(move || pin_current(cpu)).join();
        let errno = match result {
            Ok(Ok(())) => continue,
            Ok(Err(errno)) => errno,
            Err(_) => libc::EINVAL,
        };
        let detail = format!(
            "cannot run on cpu {cpu}: {}",
            String::from_utf8_lossy(&super::super::sys::Errno(errno).text())
        );
        let _ = out.write_all(&failure_event("C1", detail.as_bytes()));
        failures += 1;
        break;
    }
    let _ = writeln!(out, "failures={failures}");
    0
}

fn promote_all_threads() {
    for _ in 0..2 {
        let Ok(tasks) = fs::read_dir("/proc/self/task") else {
            return;
        };
        for task in tasks.flatten() {
            if let Ok(name) = task.file_name().to_string_lossy().parse::<libc::pid_t>()
                && name > 0
            {
                set_idle_priority(name, false);
            }
        }
    }
}

fn test_promote(out: &mut dyn Write) -> u8 {
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let promoter_stop = Arc::clone(&stop);
    let promoter = std::thread::spawn(move || {
        let (lock, changed) = &*promoter_stop;
        let stopped = match lock.lock() {
            Ok(stopped) => stopped,
            Err(_) => return,
        };
        let result =
            changed.wait_timeout_while(stopped, Duration::from_millis(50), |value| !*value);
        if result.is_ok_and(|(_, timeout)| timeout.timed_out()) {
            promote_all_threads();
        }
    });
    set_idle_priority(0, true);
    let (tid_sender, tid_receiver) = mpsc::channel();
    let worker_stop = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_wait = Arc::clone(&worker_stop);
    let worker = std::thread::spawn(move || {
        // SAFETY: gettid has no arguments.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
        let _ = tid_sender.send(tid);
        let (lock, changed) = &*worker_wait;
        if let Ok(done) = lock.lock() {
            drop(changed.wait_while(done, |value| !*value));
        }
    });
    let Some(tid) = tid_receiver.recv().ok() else {
        return 1;
    };
    if promoter.join().is_err() {
        return 1;
    }
    let caller = scheduler(0);
    let started = scheduler(tid);
    {
        let (lock, changed) = &*worker_stop;
        if let Ok(mut done) = lock.lock() {
            *done = true;
            changed.notify_all();
        }
    }
    if worker.join().is_err() {
        return 1;
    }
    let _ = writeln!(out, "promoted caller={caller} thread={started}");

    let started = Instant::now();
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let promoter_stop = Arc::clone(&stop);
    let promoter = std::thread::spawn(move || {
        let (lock, changed) = &*promoter_stop;
        if let Ok(stopped) = lock.lock() {
            let result =
                changed.wait_timeout_while(stopped, Duration::from_secs(10), |value| !*value);
            if result.is_ok_and(|(_, timeout)| timeout.timed_out()) {
                promote_all_threads();
            }
        }
    });
    set_idle_priority(0, true);
    {
        let (lock, changed) = &*stop;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
            changed.notify_one();
        }
    }
    if promoter.join().is_err() {
        return 1;
    }
    let _ = writeln!(
        out,
        "stopped caller={} stop_ms={}",
        scheduler(0),
        started.elapsed().as_millis()
    );
    0
}

fn test_idle_priority(out: &mut dyn Write) -> u8 {
    set_idle_priority(0, true);
    let idle = scheduler(0);
    set_idle_priority(0, false);
    let _ = writeln!(out, "idle={idle} normal={}", scheduler(0));
    0
}

static FORK_BURN_MS: AtomicI64 = AtomicI64::new(0);

fn process_cpu_ns() -> i64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes `now`.
    unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &raw mut now) };
    now.tv_sec * 1_000_000_000 + now.tv_nsec
}

fn burn_cpu(milliseconds: i64) {
    let deadline = process_cpu_ns() + milliseconds * NSEC_PER_MSEC;
    while process_cpu_ns() < deadline {
        std::hint::spin_loop();
    }
}

extern "C" fn fork_burn() {
    burn_cpu(FORK_BURN_MS.load(Ordering::Relaxed));
}

fn test_step13_cpu(arguments: &[&[u8]], out: &mut dyn Write) -> u8 {
    if arguments.len() != 3 {
        return 2;
    }
    FORK_BURN_MS.store(decoders::parse_i64_lossy(arguments[1]), Ordering::Relaxed);
    // SAFETY: the registered parent hook has C ABI, touches only atomics and the process clock,
    // and the process is single-threaded at this test's fork.
    if unsafe { libc::pthread_atfork(None, Some(fork_burn), None) } != 0 {
        return 1;
    }
    let cpu_start = process_cpu_ns();
    burn_cpu(decoders::parse_i64_lossy(arguments[0]));
    let mut pipes = [-1; 2];
    // SAFETY: pipe2 initializes both descriptors.
    if unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        pipes = [-1; 2];
    }
    set_idle_priority(0, true);
    let prior = process_cpu_ns() - cpu_start;
    // SAFETY: the process is single-threaded here. The child performs the same stdio work as the
    // C test and exits without running inherited destructors.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if pipes[1] >= 0 {
            // SAFETY: the child owns this descriptor.
            unsafe { libc::close(pipes[1]) };
        }
        burn_cpu(decoders::parse_i64_lossy(arguments[2]));
        let mut share = 0_i64;
        if pipes[0] >= 0 {
            // SAFETY: `share` is a valid output buffer for one i64.
            let read = unsafe {
                libc::read(
                    pipes[0],
                    (&raw mut share).cast(),
                    std::mem::size_of::<i64>(),
                )
            };
            if read != std::mem::size_of::<i64>() as isize || share < 0 {
                share = 0;
            }
        }
        let total = prior + process_cpu_ns() + share;
        let line = format!(
            "prior_ms={} total_ms={}\n",
            prior / NSEC_PER_MSEC,
            total / NSEC_PER_MSEC
        );
        // SAFETY: write reads `line`; _exit terminates only the child.
        unsafe {
            libc::write(libc::STDOUT_FILENO, line.as_ptr().cast(), line.len());
            libc::_exit(0);
        }
    }
    set_idle_priority(0, false);
    if pipes[0] >= 0 {
        // SAFETY: the parent owns this descriptor.
        unsafe { libc::close(pipes[0]) };
    }
    if pipes[1] >= 0 {
        let share = process_cpu_ns() - cpu_start - prior;
        if pid > 0 {
            // SAFETY: write reads one initialized i64.
            unsafe {
                libc::write(
                    pipes[1],
                    (&raw const share).cast(),
                    std::mem::size_of::<i64>(),
                );
            }
        }
        // SAFETY: the parent owns this descriptor.
        unsafe { libc::close(pipes[1]) };
    }
    if pid < 0 {
        return 1;
    }
    let mut status = 0;
    // SAFETY: `status` is a valid wait status output.
    if unsafe { libc::waitpid(pid, &raw mut status, 0) } != pid {
        return 1;
    }
    let _ = out;
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) as u8
    } else {
        1
    }
}
