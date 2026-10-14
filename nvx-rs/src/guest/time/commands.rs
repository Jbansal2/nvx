//! `nvx-time` command implementations and the restore packet transaction.

use std::ffi::{CStr, CString};
use std::io::Write;

use super::checks::{self, Checks};
use super::daemon::{self, Promoter};
use super::decoders::{self, GENERATION_ID_SIZE, PACKET_HEADER_SIZE, RestorePacket};
use super::state::TimeState;
use super::system::{
    self, NSEC_PER_USEC, PORT_SNAPSHOT, PORTB_DATA, PORTB_GENERATION_ID_AVAILABLE,
    PORTB_PACKET_AVAILABLE, PORTB_STATUS, RESTORE_PATH, RESTORE_TEMP_PATH, Runtime,
    SELECT_GENERATION_ID, SELECT_PACKET, STATUS_REPAIR, clock_ns, cpu_time_ns, current_frequency,
    initial_sample, portb_read, set_frequency, state_apply, state_load, state_store, step_clock,
    suppression_restore, suppression_save,
};
use super::{DEFERRED_START_NS, MAX_CPUS, Phase, USAGE};
use crate::guest::sys::{self, Errno};

const PACKET_ACK_REQUIRED: u8 = 0x04;
const PACKET_DOWNTIME_UTC: u8 = 0x01;
const PACKET_MEMORY_TARGET: u8 = 0x02;
const REPAIR_BOUND_NS: i64 = 1_000_000;

fn report(err: &mut dyn Write, parts: &[&[u8]]) {
    sys::report(err, parts);
}

fn usage(err: &mut dyn Write, line: &[u8]) -> u8 {
    report(err, &[line]);
    2
}

fn load_generation(runtime: &Runtime<'_>) {
    if let Ok(state) = state_load() {
        runtime.set_generation(state.generation as u32);
    }
}

fn sleep_until(deadline_ns: i64) {
    let when = libc::timespec {
        tv_sec: deadline_ns / system::NSEC_PER_SEC,
        tv_nsec: deadline_ns % system::NSEC_PER_SEC,
    };
    // SAFETY: clock_nanosleep reads `when`.
    while unsafe {
        libc::clock_nanosleep(
            libc::CLOCK_MONOTONIC,
            libc::TIMER_ABSTIME,
            &when,
            std::ptr::null_mut(),
        )
    } == libc::EINTR
    {}
}

struct BootSample {
    theta: i64,
    epsilon: i64,
    accepted_ns: i64,
}

fn open_kernel_log(runtime: &Runtime<'_>, checks: &mut Checks) -> libc::c_int {
    let descriptor = system::open(
        c"/dev/kmsg",
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    );
    // SAFETY: lseek positions the readable kernel-log descriptor.
    if descriptor < 0 || unsafe { libc::lseek(descriptor, 0, libc::SEEK_END) } < 0 {
        checks.fail(
            runtime,
            "C4",
            format!(
                "open /dev/kmsg: {}",
                String::from_utf8_lossy(&Errno::last().text())
            ),
        );
        if descriptor >= 0 {
            system::close(descriptor);
        }
        -1
    } else {
        descriptor
    }
}

fn boot_checker(
    runtime: &Runtime<'_>,
    sample: &BootSample,
    c12_ns: i64,
    c12_cpu_ns: i64,
    c12_failures: i32,
) -> ! {
    let start = clock_ns(libc::CLOCK_MONOTONIC).wrapping_add(DEFERRED_START_NS);
    let cpu_start = cpu_time_ns();
    let null = system::open(c"/dev/null", libc::O_RDWR | libc::O_CLOEXEC, 0);
    runtime.set_async_output(true);
    // SAFETY: this detached child intentionally starts a new session and redirects stdio.
    unsafe {
        libc::setsid();
        if null >= 0 {
            libc::dup2(null, libc::STDIN_FILENO);
            libc::dup2(null, libc::STDOUT_FILENO);
            libc::dup2(null, libc::STDERR_FILENO);
            libc::close(null);
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            libc::_exit(1);
        }
    }
    let promoter = Promoter::start(start);
    daemon::set_idle_priority(0, true);
    sleep_until(start);
    let mut checks = match Checks::load(Phase::Boot) {
        Ok(checks) => checks,
        Err(_) => {
            let mut checks = Checks::empty(Phase::Boot);
            checks.fail(runtime, "C1", "cannot read the CPU sets");
            // SAFETY: this boot-check child must not run inherited destructors.
            unsafe { libc::_exit(1) };
        }
    };
    checks.failures = c12_failures;
    // SAFETY: klogctl action 10 reports the whole-log buffer size.
    let log_size = unsafe { libc::klogctl(10, std::ptr::null_mut(), 0) };
    let mut log_buffer = Vec::new();
    let buffer_ready = log_size > 0 && log_buffer.try_reserve_exact(log_size as usize + 1).is_ok();
    if buffer_ready {
        log_buffer.resize(log_size as usize + 1, 0);
    }
    let kmsg = open_kernel_log(runtime, &mut checks);
    checks::run_boot_checks(
        runtime,
        &mut checks,
        kmsg >= 0,
        log_size,
        buffer_ready.then_some(log_buffer.as_mut_slice()),
    );
    if let Some(promoter) = promoter {
        promoter.stop();
    }
    let daemon = if kmsg >= 0 {
        match daemon::become_daemon(kmsg, sample.accepted_ns) {
            Ok(daemon) => Some(daemon),
            Err(error) => {
                checks.fail(
                    runtime,
                    "C10",
                    format!(
                        "cannot start the time daemon: {}",
                        String::from_utf8_lossy(&error.text())
                    ),
                );
                None
            }
        }
    } else {
        None
    };
    if let Err(error) = checks::record_check(
        runtime,
        &checks,
        b"ok",
        c12_ns.wrapping_add(clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(start)) / NSEC_PER_USEC,
        c12_cpu_ns.wrapping_add(cpu_time_ns().wrapping_sub(cpu_start)) / NSEC_PER_USEC,
        checks.tsc_hz,
        checks.lapic_hz,
    ) {
        checks.fail(
            runtime,
            "C10",
            format!(
                "cannot publish the time state: {}",
                String::from_utf8_lossy(&error.text())
            ),
        );
    }
    if let Some(daemon) = daemon {
        daemon::daemon_loop(runtime, daemon);
    }
    // SAFETY: this boot-check child must not run inherited destructors.
    unsafe { libc::_exit(1) }
}

fn cmd_boot(runtime: &Runtime<'_>) -> u8 {
    let start = clock_ns(libc::CLOCK_MONOTONIC);
    let cpu_start = cpu_time_ns();
    let mut sample = BootSample {
        theta: 0,
        epsilon: 0,
        accepted_ns: 0,
    };
    runtime.set_generation(0);
    system::make_runtime_directories();
    let mut checks = Checks::empty(Phase::Boot);
    match initial_sample(runtime) {
        Ok(initial) => {
            sample.theta = initial.theta;
            sample.epsilon = initial.epsilon;
            sample.accepted_ns = clock_ns(libc::CLOCK_MONOTONIC);
        }
        Err(detail) => {
            checks.fail(runtime, "C12", detail);
        }
    }
    let accepted = u64::from(sample.accepted_ns != 0);
    let mut state = TimeState {
        synchronized: accepted,
        samples: accepted,
        ..TimeState::default()
    };
    if sample.accepted_ns != 0 {
        state.offset_ns = sample.theta;
        state.uncertainty_ns = sample.epsilon;
    }
    state.frequency_ppb = decoders::frequency_to_ppb(current_frequency(runtime));
    if let Err(error) = state_store(&state) {
        checks.fail(
            runtime,
            "C10",
            format!(
                "cannot publish the time state: {}",
                String::from_utf8_lossy(&error.text())
            ),
        );
        return 1;
    }
    // SAFETY: flushing before fork matches the C helper and avoids duplicated buffers.
    unsafe { libc::fflush(std::ptr::null_mut()) };
    let c12_cpu = cpu_time_ns().wrapping_sub(cpu_start);
    // SAFETY: the process is single-threaded at the boot fork.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        boot_checker(
            runtime,
            &sample,
            clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(start),
            c12_cpu,
            checks.failures,
        );
    }
    if pid < 0 {
        checks.fail(
            runtime,
            "C10",
            format!(
                "cannot start the boot checks: {}",
                String::from_utf8_lossy(&Errno::last().text())
            ),
        );
        return 1;
    }
    0
}

fn parse_new_cpus(text: &[u8]) -> Option<([bool; MAX_CPUS], usize)> {
    if text.is_empty() || text == b"none" {
        Some(([false; MAX_CPUS], 0))
    } else {
        decoders::parse_cpu_list(text)
    }
}

fn cmd_check(runtime: &Runtime<'_>, arguments: &[&[u8]], err: &mut dyn Write) -> u8 {
    let start = clock_ns(libc::CLOCK_MONOTONIC);
    let cpu_start = cpu_time_ns();
    let mut phase = None;
    let mut new_cpus = [false; MAX_CPUS];
    let mut new_count = 0_i32;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index] {
            b"--phase" if index + 1 < arguments.len() => {
                index += 1;
                phase = match arguments[index] {
                    b"capture" => Some(Phase::Capture),
                    b"restore" => Some(Phase::Restore),
                    _ => None,
                };
            }
            b"--new-cpus" if index + 1 < arguments.len() => {
                index += 1;
                let Some((cpus, count)) = parse_new_cpus(arguments[index]) else {
                    new_count = -1;
                    index += 1;
                    continue;
                };
                new_cpus = cpus;
                new_count = count as i32;
            }
            _ => new_count = -1,
        }
        index += 1;
    }
    let Some(phase) = phase.filter(|_| new_count >= 0) else {
        return usage(
            err,
            b"usage: nvx-time check --phase capture|restore [--new-cpus LIST]\n",
        );
    };
    load_generation(runtime);
    let mut checks = match Checks::load(phase) {
        Ok(checks) => checks,
        Err(_) => {
            let mut checks = Checks::empty(phase);
            checks.fail(runtime, "C6", "cannot read the CPU sets");
            return 1;
        }
    };
    if phase == Phase::Capture {
        checks::run_capture_checks(runtime, &mut checks);
    } else {
        checks::run_restore_checks(runtime, &mut checks, &new_cpus, new_count as usize);
    }
    let _ = checks::record_check(
        runtime,
        &checks,
        b"ok",
        clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(start) / NSEC_PER_USEC,
        cpu_time_ns().wrapping_sub(cpu_start) / NSEC_PER_USEC,
        0,
        0,
    );
    u8::from(checks.failures != 0)
}

fn cmd_pre_capture(runtime: &Runtime<'_>, err: &mut dyn Write) -> u8 {
    let (state, completed) = checks::wait_for_checks(true);
    if !completed {
        let mut checks = Checks::empty(Phase::Capture);
        checks.fail(runtime, "C10", "the boot checks are still pending");
        return 1;
    }
    let start = clock_ns(libc::CLOCK_MONOTONIC);
    let cpu_start = cpu_time_ns();
    runtime.set_generation(state.generation as u32);
    let mut checks = match Checks::load(Phase::Capture) {
        Ok(checks) => checks,
        Err(_) => {
            let mut checks = Checks::empty(Phase::Capture);
            checks.fail(runtime, "C6", "cannot read the CPU sets");
            return 1;
        }
    };
    checks::run_capture_checks(runtime, &mut checks);
    let elapsed = clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(start);
    let cpu = cpu_time_ns().wrapping_sub(cpu_start);
    if let Err(error) = suppression_save() {
        if error != Errno(libc::EEXIST) {
            let _ = suppression_restore(false);
        }
        let reason = if error == Errno(libc::EEXIST) {
            b"a capture is already pending".to_vec()
        } else {
            error.text()
        };
        report(
            err,
            &[
                b"nvx-time: cannot suppress the stall detectors: ",
                &reason,
                b"\n",
            ],
        );
        return 1;
    }
    if let Err(error) = checks::record_check(
        runtime,
        &checks,
        b"ok",
        elapsed / NSEC_PER_USEC,
        cpu / NSEC_PER_USEC,
        0,
        0,
    ) {
        checks.fail(
            runtime,
            "C10",
            format!(
                "cannot record the capture check: {}",
                String::from_utf8_lossy(&error.text())
            ),
        );
    }
    0
}

fn cmd_cancel_capture(err: &mut dyn Write) -> u8 {
    match suppression_restore(false) {
        Ok(()) => 0,
        Err(detail) => {
            report(err, &[b"nvx-time: ", &detail, b"\n"]);
            1
        }
    }
}

fn unlink(path: &CStr) {
    // SAFETY: path is NUL-terminated.
    unsafe { libc::unlink(path.as_ptr()) };
}

fn write_entropy(descriptor: i32, path: &CStr, entropy: &[u8]) -> Result<(), Vec<u8>> {
    // SAFETY: pwrite reads the initialized entropy bytes.
    let count = sys::retry(|| unsafe {
        libc::pwrite(descriptor, entropy.as_ptr().cast(), entropy.len(), 0)
    });
    let close = sys::close(descriptor);
    if count == entropy.len() as isize && close.is_ok() {
        Ok(())
    } else {
        let error = if count < 0 {
            Errno::last()
        } else {
            close.err().unwrap_or(Errno(libc::EIO))
        };
        let mut detail = b"write ".to_vec();
        detail.extend_from_slice(&path.to_bytes()[..path.to_bytes().len().min(200)]);
        detail.extend_from_slice(b": ");
        detail.extend_from_slice(&error.text());
        Err(detail)
    }
}

fn apply_repair(
    state: &mut TimeState,
    packet: &RestorePacket,
    theta: i64,
    epsilon: i64,
    step_realtime_ns: i64,
    frequency: i64,
    elapsed_us: i64,
) {
    state.generation = u64::from(packet.generation);
    state.discontinuities = state.discontinuities.wrapping_add(1);
    state.last_discontinuity = b"restore".to_vec();
    state.last_step_ns = theta;
    state.last_step_realtime_ns = step_realtime_ns;
    state.last_downtime_ns = packet.downtime_ns;
    state.last_downtime_source = if packet.flags & PACKET_DOWNTIME_UTC != 0 {
        b"utc".to_vec()
    } else {
        b"monotonic".to_vec()
    };
    state.synchronized = 1;
    state.offset_ns = theta;
    state.uncertainty_ns = epsilon;
    state.frequency_ppb = decoders::frequency_to_ppb(frequency);
    state.samples = state.samples.wrapping_add(1);
    state.last_sample_error = b"none".to_vec();
    let restore = &mut state.checks[2];
    restore.status = b"pending".to_vec();
    restore.cpus = 0;
    restore.elapsed_us = elapsed_us;
    restore.cpu_us = 0;
    restore.generation = state.generation;
    restore.failures = -1;
}

fn repair_failed(runtime: &Runtime<'_>, code: &[u8], detail: &[u8]) -> u8 {
    runtime.fail_fatal(STATUS_REPAIR, code, b"repair", Phase::Restore, detail);
    1
}

#[allow(clippy::too_many_arguments)]
fn repair_restore(
    runtime: &Runtime<'_>,
    previous_id: &[u8],
    entropy_path: &CStr,
    entropy_fd: i32,
    start_ns: i64,
    finish: bool,
    daemon_pid: libc::pid_t,
    out: &mut dyn Write,
) -> u8 {
    let t0 = clock_ns(libc::CLOCK_REALTIME);
    runtime.ops.outb(PORTB_STATUS, SELECT_PACKET);
    let t1 = clock_ns(libc::CLOCK_REALTIME);
    let mut header = [0_u8; PACKET_HEADER_SIZE];
    portb_read(runtime, PORTB_DATA, &mut header);
    let mut packet = match RestorePacket::parse_header(&header) {
        Ok(packet) => packet,
        Err(detail) => return repair_failed(runtime, b"G_REPAIR_PACKET", detail.as_bytes()),
    };
    if packet.generation == runtime.generation() {
        system::close(entropy_fd);
        unlink(entropy_path);
        let _ = out.write_all(b"0\n");
        return 0;
    }
    if u64::from(packet.generation) != u64::from(runtime.generation()) + 1 {
        return repair_failed(
            runtime,
            b"G_REPAIR_GENERATION",
            format!(
                "restore packet generation {} does not follow recorded generation {}",
                packet.generation,
                runtime.generation()
            )
            .as_bytes(),
        );
    }
    let mut body = vec![0_u8; packet.body_size()];
    portb_read(runtime, PORTB_DATA, &mut body);
    if let Err(detail) = packet.parse_body(&body) {
        return repair_failed(runtime, b"G_REPAIR_PACKET", detail.as_bytes());
    }
    if packet.entropy[..GENERATION_ID_SIZE] == *previous_id {
        return repair_failed(
            runtime,
            b"G_REPAIR_GENERATION",
            b"the VM generation ID did not change",
        );
    }
    runtime.set_generation(packet.generation);
    let (mut theta, mut epsilon) = decoders::pair_clocks(t0, t1, packet.utc_ns);
    if epsilon > REPAIR_BOUND_NS {
        match system::best_sample(runtime, 2, REPAIR_BOUND_NS, packet.generation) {
            Err((-2, detail)) => {
                return repair_failed(runtime, b"G_REPAIR_GENERATION", &detail);
            }
            Ok((_, sample)) if sample.epsilon < epsilon => {
                theta = sample.theta;
                epsilon = sample.epsilon;
            }
            _ => {}
        }
        if epsilon > REPAIR_BOUND_NS {
            return repair_failed(
                runtime,
                b"G_REPAIR_SAMPLE",
                format!("UTC pairing uncertainty {epsilon} ns exceeds 1 ms").as_bytes(),
            );
        }
    }
    let frequency = decoders::restore_frequency(packet.rate_deviation);
    if let Err(error) = step_clock(runtime, theta).and_then(|()| set_frequency(runtime, frequency))
    {
        return repair_failed(
            runtime,
            b"G_REPAIR_CLOCK",
            format!("adjtimex: {}", String::from_utf8_lossy(&error.text())).as_bytes(),
        );
    }
    let step_realtime_ns = clock_ns(libc::CLOCK_REALTIME);
    let elapsed_us = clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(start_ns) / NSEC_PER_USEC;
    let finishing = finish
        && daemon_pid > 0
        && packet.online_vp_count == 0
        && packet.range_count == 0
        && packet.flags & PACKET_MEMORY_TARGET == 0;
    if let Err(detail) = write_entropy(entropy_fd, entropy_path, &packet.entropy) {
        return repair_failed(runtime, b"G_REPAIR_PACKET", &detail);
    }
    if let Err(error) = state_apply(|state| {
        apply_repair(
            state,
            &packet,
            theta,
            epsilon,
            step_realtime_ns,
            frequency,
            elapsed_us,
        );
    }) {
        return repair_failed(
            runtime,
            b"G_REPAIR_CLOCK",
            format!(
                "record the restore: {}",
                String::from_utf8_lossy(&error.text())
            )
            .as_bytes(),
        );
    }
    let finished = if finishing {
        let result = daemon::signal_restore(
            runtime,
            daemon_pid,
            packet.flags & PACKET_ACK_REQUIRED != 0,
            start_ns,
        );
        if result > 0 {
            let mut checks = Checks::empty(Phase::Restore);
            checks.fail(runtime, "C10", "the time daemon is not running");
        }
        Some(result)
    } else {
        None
    };
    let mut line = format!(
        "{} {} {} {} {}",
        if finished.is_some_and(|result| result >= 0) {
            2
        } else {
            1
        },
        packet.flags,
        packet.online_vp_count,
        packet.range_count,
        decoders::format_hex(&packet.entropy[..GENERATION_ID_SIZE])
    );
    for (start, length) in &packet.ranges {
        line.push_str(&format!(" {start} {length}"));
    }
    line.push('\n');
    let _ = out.write_all(line.as_bytes());
    0
}

fn cmd_capture(
    runtime: &Runtime<'_>,
    arguments: &[&[u8]],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if !matches!(
        arguments,
        [b"0" | b"1", _, _] | [b"0" | b"1", _, _, b"--finish"]
    ) {
        return usage(
            err,
            b"usage: nvx-time capture 0|1 GENERATION_ID ENTROPY_FILE [--finish]\n",
        );
    }
    let request = arguments[0][0] - b'0';
    let Some(previous_id) = decoders::parse_hex(arguments[1], GENERATION_ID_SIZE) else {
        return usage(
            err,
            b"usage: nvx-time capture 0|1 GENERATION_ID ENTROPY_FILE [--finish]\n",
        );
    };
    let Ok(entropy_path) = CString::new(arguments[2]) else {
        return usage(
            err,
            b"usage: nvx-time capture 0|1 GENERATION_ID ENTROPY_FILE [--finish]\n",
        );
    };
    if state_load().is_err() {
        report(err, &[b"nvx-time: the time state is unavailable\n"]);
        return 1;
    }
    load_generation(runtime);
    if let Err(error) = runtime.enable_ports() {
        report(err, &[b"nvx-time: ioperm: ", &error.text(), b"\n"]);
        return 1;
    }
    let daemon_pid = if arguments.len() == 4 {
        checks::daemon_pid().unwrap_or(-1)
    } else {
        -1
    };
    let entropy_fd = system::open(
        &entropy_path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    );
    if entropy_fd < 0 {
        report(
            err,
            &[
                b"nvx-time: open ",
                entropy_path.to_bytes(),
                b": ",
                &Errno::last().text(),
                b"\n",
            ],
        );
        return 1;
    }
    let lock = match system::lock_portb() {
        Ok(lock) => lock,
        Err(detail) => {
            report(err, &[b"nvx-time: ", &detail, b"\n"]);
            system::close(entropy_fd);
            unlink(&entropy_path);
            return 1;
        }
    };
    runtime.ops.outb(PORT_SNAPSHOT, request);
    let start = clock_ns(libc::CLOCK_MONOTONIC);
    let status = runtime.ops.inb(PORTB_STATUS);
    if status & PORTB_PACKET_AVAILABLE == 0 {
        system::close(lock);
        system::close(entropy_fd);
        unlink(&entropy_path);
        let _ = out.write_all(b"0\n");
        return 0;
    }
    let result = repair_restore(
        runtime,
        &previous_id,
        &entropy_path,
        entropy_fd,
        start,
        arguments.len() == 4,
        daemon_pid,
        out,
    );
    system::close(lock);
    result
}

fn cmd_restore_finish(runtime: &Runtime<'_>, arguments: &[&[u8]], err: &mut dyn Write) -> u8 {
    let mut acknowledge = false;
    let mut new_list = b"none".as_slice();
    let mut new_cpus = [false; MAX_CPUS];
    let mut new_count = 0_i32;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index] {
            b"--ack" => acknowledge = true,
            b"--new-cpus" if index + 1 < arguments.len() => {
                index += 1;
                new_list = arguments[index];
                let Some((cpus, count)) = parse_new_cpus(new_list) else {
                    new_count = -1;
                    index += 1;
                    continue;
                };
                new_cpus = cpus;
                new_count = count as i32;
            }
            _ => new_count = -1,
        }
        index += 1;
    }
    if new_count < 0 || new_list.len() > 127 {
        return usage(
            err,
            b"usage: nvx-time restore-finish [--ack] [--new-cpus LIST]\n",
        );
    }
    let state = match state_load() {
        Ok(state) => state,
        Err(_) => {
            return repair_failed(runtime, b"G_REPAIR_CLOCK", b"the time state is unreadable");
        }
    };
    runtime.set_generation(state.generation as u32);
    let cpus = if new_count > 0 { new_list } else { b"none" };
    let mut record = format!("generation={}\nnew_cpus=", state.generation).into_bytes();
    record.extend_from_slice(cpus);
    record.push(b'\n');
    if let Err(error) = system::replace_file(RESTORE_PATH, RESTORE_TEMP_PATH, &record) {
        return repair_failed(
            runtime,
            b"G_REPAIR_CLOCK",
            format!(
                "record the restore: {}",
                String::from_utf8_lossy(&error.text())
            )
            .as_bytes(),
        );
    }
    if acknowledge && let Err(error) = runtime.enable_ports() {
        report(err, &[b"nvx-time: ioperm: ", &error.text(), b"\n"]);
        return 1;
    }
    let start = clock_ns(libc::CLOCK_MONOTONIC)
        .wrapping_sub(clock_ns(libc::CLOCK_REALTIME).wrapping_sub(state.last_step_realtime_ns))
        .wrapping_sub(state.checks[2].elapsed_us * NSEC_PER_USEC);
    let signaled = daemon::signal_restore(
        runtime,
        checks::daemon_pid().unwrap_or(-1),
        acknowledge,
        start,
    );
    if signaled == 0 {
        return 0;
    }
    if signaled > 0 || !runtime.report_only() {
        let mut checks = Checks::empty(Phase::Restore);
        checks.fail(runtime, "C10", "the time daemon is not running");
        return 1;
    }
    if acknowledge {
        runtime
            .ops
            .outb(PORT_SNAPSHOT, system::SNAPSHOT_ACKNOWLEDGE);
    }
    let timing = daemon::inline_restore_timing(start);
    let _ = daemon::restore_work(runtime, &new_cpus, new_count as usize, true, &timing);
    0
}

fn cmd_status(runtime: &Runtime<'_>, out: &mut dyn Write) -> u8 {
    let (state, completed) = checks::wait_for_checks(false);
    let (text, ok) = state.format_status(runtime.report_only());
    let _ = out.write_all(&text);
    u8::from(!completed || !ok)
}

fn cmd_sample(runtime: &Runtime<'_>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if let Err(error) = runtime.enable_ports() {
        report(err, &[b"nvx-time: ioperm: ", &error.text(), b"\n"]);
        return 1;
    }
    let status = runtime.ops.inb(PORTB_STATUS);
    if status & system::PORTB_TIME_WINDOW == 0 {
        report(
            err,
            &[format!("nvx-time: portb status 0x{status:02x} has no time window\n").as_bytes()],
        );
        return 1;
    }
    let lock = match system::lock_portb() {
        Ok(lock) => lock,
        Err(detail) => {
            report(err, &[b"nvx-time: ", &detail, b"\n"]);
            return 1;
        }
    };
    let mut sample = decoders::TimeSample {
        flags: 0,
        generation: 0,
        utc_ns: 0,
        t0: 0,
        t1: 0,
    };
    let result = system::take_sample(runtime, &mut sample);
    system::close(lock);
    if let Err(detail) = result {
        report(err, &[b"nvx-time: ", detail.as_bytes(), b"\n"]);
        return 1;
    }
    let (theta, epsilon) = decoders::pair_clocks(sample.t0, sample.t1, sample.utc_ns);
    let line = format!(
        "flags=0x{:02x} generation={} utc_ns={} t0={} t1={} theta_ns={} epsilon_ns={}\n",
        sample.flags, sample.generation, sample.utc_ns, sample.t0, sample.t1, theta, epsilon
    );
    let _ = out.write_all(line.as_bytes());
    0
}

fn cmd_generation_id(runtime: &Runtime<'_>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if let Err(error) = runtime.enable_ports() {
        report(err, &[b"nvx-time: ioperm: ", &error.text(), b"\n"]);
        return 1;
    }
    if runtime.ops.inb(PORTB_STATUS) & PORTB_GENERATION_ID_AVAILABLE == 0 {
        report(err, &[b"nvx-time: the VM generation ID is unavailable\n"]);
        return 1;
    }
    let lock = match system::lock_file(system::PORTB_LOCK_PATH) {
        Ok(lock) => lock,
        Err(error) => {
            report(err, &[b"nvx-time: portb lock: ", &error.text(), b"\n"]);
            return 1;
        }
    };
    runtime.ops.outb(PORTB_STATUS, SELECT_GENERATION_ID);
    let mut id = [0_u8; GENERATION_ID_SIZE];
    portb_read(runtime, PORTB_DATA, &mut id);
    system::close(lock);
    let mut text = decoders::format_hex(&id).into_bytes();
    text.push(b'\n');
    let _ = out.write_all(&text);
    0
}

fn cmdline_requests_report_only() -> bool {
    let Ok(text) = system::read_text(c"/proc/cmdline", 4096) else {
        return false;
    };
    text.split(|byte| matches!(byte, b' ' | b'\t' | b'\n'))
        .any(|token| token == b"nvx_time_abi=report-only")
}

pub(super) fn run(
    arguments: &[&[u8]],
    report_only: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let ops = system::RealOps;
    let runtime = Runtime::new(&ops, report_only || cmdline_requests_report_only());
    // An inherited SIG_IGN would let the kernel reap children before waitpid sees them.
    // SAFETY: SIG_DFL installs no function pointer.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let Some((&command, rest)) = arguments.split_first() else {
        return usage(err, USAGE);
    };
    match (command, rest) {
        (b"boot", []) => cmd_boot(&runtime),
        (b"check", arguments) => cmd_check(&runtime, arguments, err),
        (b"pre-capture", []) => cmd_pre_capture(&runtime, err),
        (b"capture", arguments) => cmd_capture(&runtime, arguments, out, err),
        (b"cancel-capture", []) => cmd_cancel_capture(err),
        (b"restore-finish", arguments) => cmd_restore_finish(&runtime, arguments, err),
        (b"status", []) => cmd_status(&runtime, out),
        (b"sample", []) => cmd_sample(&runtime, out, err),
        (b"generation-id", []) => cmd_generation_id(&runtime, out, err),
        (b"exhaustive", []) => checks::exhaustive(&runtime, out),
        _ => usage(err, USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cpu_parser_keeps_none_and_ranges_distinct() {
        assert_eq!(parse_new_cpus(b"none").unwrap().1, 0);
        assert_eq!(parse_new_cpus(b"").unwrap().1, 0);
        assert_eq!(parse_new_cpus(b"1-3,5").unwrap().1, 4);
        assert!(parse_new_cpus(b"64").is_none());
    }
}
