//! Linux interfaces, persistent state, events, port I/O, and clock adjustment.

use std::ffi::{CStr, CString};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::decoders::{self, Correction, SAMPLE_SIZE, TimeSample};
use super::events::format_event;
use super::state::TimeState;
use super::{NSEC_PER_MSEC, Phase};
use crate::guest::sys::{self, Errno};

pub(crate) const NSEC_PER_SEC: i64 = 1_000_000_000;
pub(crate) const NSEC_PER_USEC: i64 = 1_000;
pub(crate) const STATUS_CONFORMANCE: u8 = 193;
pub(crate) const STATUS_VIOLATION: u8 = 194;
pub(crate) const STATUS_REPAIR: u8 = 195;

pub(crate) const PORTB_DATA: u16 = 0xe9;
pub(crate) const PORTB_STATUS: u16 = 0xea;
pub(crate) const PORTB_WINDOW: u16 = 0xeb;
const PORT_SHUTDOWN: u16 = 0x604;
pub(crate) const PORT_SNAPSHOT: u16 = 0x605;
pub(crate) const SELECT_PACKET: u8 = 0xa5;
pub(crate) const SELECT_GENERATION_ID: u8 = 0xa6;
pub(crate) const SELECT_TIME_SAMPLE: u8 = 0xa7;
pub(crate) const PORTB_PACKET_AVAILABLE: u8 = 0x02;
pub(crate) const PORTB_GENERATION_ID_AVAILABLE: u8 = 0x20;
pub(crate) const PORTB_TIME_WINDOW: u8 = 0x40;
pub(crate) const SNAPSHOT_ACKNOWLEDGE: u8 = 2;

pub(crate) const RUN_DIR: &CStr = c"/run/nvx";
pub(crate) const TIME_DIR: &CStr = c"/run/nvx/time";
pub(crate) const STATE_PATH: &CStr = c"/run/nvx/time/state";
const STATE_TEMP_PATH: &CStr = c"/run/nvx/time/.state";
const STATE_LOCK_PATH: &CStr = c"/run/nvx/time/state.lock";
pub(crate) const DAEMON_PID_PATH: &CStr = c"/run/nvx/time/daemon.pid";
pub(crate) const DAEMON_PID_TEMP_PATH: &CStr = c"/run/nvx/time/daemon.pid.tmp";
pub(crate) const SUPPRESSION_PATH: &CStr = c"/run/nvx/time/suppression";
const SUPPRESSION_LOCK_PATH: &CStr = c"/run/nvx/time/suppression.lock";
pub(crate) const RESTORE_PATH: &CStr = c"/run/nvx/time/restore";
pub(crate) const RESTORE_TEMP_PATH: &CStr = c"/run/nvx/time/restore.tmp";
pub(crate) const PORTB_LOCK_PATH: &CStr = c"/run/nvx/portb.lock";
pub(crate) const RCU_SYNC_PATH: &CStr = c"/run/nvx/rcu-sync";

pub(crate) const RCU_STALL_SUPPRESS: &CStr =
    c"/sys/module/rcupdate/parameters/rcu_cpu_stall_suppress";
pub(crate) const RCU_STALL_TIMEOUT: &CStr =
    c"/sys/module/rcupdate/parameters/rcu_cpu_stall_timeout";
pub(crate) const RCU_NORMAL: &CStr = c"/sys/kernel/rcu_normal";
pub(crate) const RCU_STALL_COUNT: &CStr = c"/sys/kernel/rcu_stall_count";
pub(crate) const SOFT_WATCHDOG: &CStr = c"/proc/sys/kernel/soft_watchdog";
pub(crate) const HUNG_TASK_TIMEOUT: &CStr = c"/proc/sys/kernel/hung_task_timeout_secs";

const SAMPLE_ATTEMPTS: usize = 3;
const FREQUENCY_STATUS: libc::c_int = 0x2001;

/// Privileged operations have an injectable seam so their retry and failure paths are testable.
pub(crate) trait PrivilegedOps: Sync {
    fn ioperm(&self) -> Result<(), Errno>;
    fn inb(&self, port: u16) -> u8;
    fn inl(&self, port: u16) -> u32;
    fn outb(&self, port: u16, value: u8);
    fn open_msr(&self, cpu: usize, write: bool) -> Result<libc::c_int, Errno>;
    fn read_msr(&self, descriptor: libc::c_int, msr: u32) -> Result<u64, i32>;
    fn write_msr(&self, descriptor: libc::c_int, msr: u32, value: u64) -> Result<(), i32>;
    fn adjtimex(&self, value: &mut libc::timex) -> Result<libc::c_int, Errno>;
    fn power_off(&self, status: u8);
}

pub(crate) struct RealOps;

impl PrivilegedOps for RealOps {
    fn ioperm(&self) -> Result<(), Errno> {
        // SAFETY: the process requests only the ABI's port ranges.
        let enabled = unsafe {
            libc::ioperm(
                libc::c_ulong::from(PORTB_DATA),
                libc::c_ulong::from(PORTB_WINDOW + 4 - PORTB_DATA),
                1,
            ) == 0
                && libc::ioperm(libc::c_ulong::from(PORT_SHUTDOWN), 2, 1) == 0
        };
        if enabled { Ok(()) } else { Err(Errno::last()) }
    }

    fn inb(&self, port: u16) -> u8 {
        // SAFETY: `Runtime::enable_ports` obtained permission for this port.
        unsafe { super::super::x86::inb(port) }
    }

    fn inl(&self, port: u16) -> u32 {
        // SAFETY: `Runtime::enable_ports` obtained permission for this four-byte range.
        unsafe { super::super::x86::inl(port) }
    }

    fn outb(&self, port: u16, value: u8) {
        // SAFETY: `Runtime::enable_ports` obtained permission for this port.
        unsafe { super::super::x86::outb(port, value) };
    }

    fn open_msr(&self, cpu: usize, write: bool) -> Result<libc::c_int, Errno> {
        let path = CString::new(format!("/dev/cpu/{cpu}/msr")).map_err(|_| Errno(libc::EINVAL))?;
        // SAFETY: `path` is NUL-terminated.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                (if write { libc::O_RDWR } else { libc::O_RDONLY }) | libc::O_CLOEXEC,
            )
        };
        if descriptor >= 0 {
            Ok(descriptor)
        } else {
            Err(Errno::last())
        }
    }

    fn read_msr(&self, descriptor: libc::c_int, msr: u32) -> Result<u64, i32> {
        let mut value = 0_u64;
        // SAFETY: pread writes one initialized u64 and does not change the file offset.
        let count = unsafe {
            libc::pread(
                descriptor,
                (&raw mut value).cast(),
                std::mem::size_of::<u64>(),
                libc::off_t::from(msr),
            )
        };
        if count == std::mem::size_of::<u64>() as isize {
            Ok(value)
        } else if count < 0 {
            Err(-Errno::last().0)
        } else {
            Err(-libc::EIO)
        }
    }

    fn write_msr(&self, descriptor: libc::c_int, msr: u32, value: u64) -> Result<(), i32> {
        // SAFETY: pwrite reads one initialized u64 and does not change the file offset.
        let count = unsafe {
            libc::pwrite(
                descriptor,
                (&raw const value).cast(),
                std::mem::size_of::<u64>(),
                libc::off_t::from(msr),
            )
        };
        if count == std::mem::size_of::<u64>() as isize {
            Ok(())
        } else if count < 0 {
            Err(-Errno::last().0)
        } else {
            Err(-libc::EIO)
        }
    }

    fn adjtimex(&self, value: &mut libc::timex) -> Result<libc::c_int, Errno> {
        // SAFETY: adjtimex reads and writes the initialized structure.
        let result = unsafe { libc::adjtimex(value) };
        if result >= 0 {
            Ok(result)
        } else {
            Err(Errno::last())
        }
    }

    fn power_off(&self, status: u8) {
        // SAFETY: flushing every libc stream preserves output before terminating the VM.
        unsafe { libc::fflush(std::ptr::null_mut()) };
        if self.ioperm().is_ok() {
            // SAFETY: ioperm succeeded for the shutdown port.
            unsafe { super::super::x86::outb(PORT_SHUTDOWN, status) };
        } else {
            // SAFETY: the path is NUL-terminated.
            let descriptor =
                unsafe { libc::open(c"/dev/port".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if descriptor >= 0 {
                // SAFETY: pwrite reads one byte from `status`.
                unsafe {
                    libc::pwrite(
                        descriptor,
                        (&raw const status).cast(),
                        1,
                        libc::off_t::from(PORT_SHUTDOWN),
                    );
                    libc::close(descriptor);
                }
            }
        }
        loop {
            // SAFETY: pause waits for a signal; the VM should already be terminating.
            unsafe { libc::pause() };
        }
    }
}

pub(crate) struct Runtime<'a> {
    pub(crate) ops: &'a dyn PrivilegedOps,
    report_only: AtomicBool,
    generation: AtomicU32,
    ports: AtomicBool,
    async_output: AtomicBool,
    report_lock: Mutex<()>,
}

impl<'a> Runtime<'a> {
    pub(crate) fn new(ops: &'a dyn PrivilegedOps, report_only: bool) -> Self {
        Self {
            ops,
            report_only: AtomicBool::new(report_only),
            generation: AtomicU32::new(0),
            ports: AtomicBool::new(false),
            async_output: AtomicBool::new(false),
            report_lock: Mutex::new(()),
        }
    }

    pub(crate) fn report_only(&self) -> bool {
        self.report_only.load(Ordering::Relaxed)
    }

    pub(crate) fn generation(&self) -> u32 {
        self.generation.load(Ordering::Relaxed)
    }

    pub(crate) fn set_generation(&self, value: u32) {
        self.generation.store(value, Ordering::Relaxed);
    }

    pub(crate) fn set_async_output(&self, value: bool) {
        self.async_output.store(value, Ordering::Relaxed);
    }

    pub(crate) fn enable_ports(&self) -> Result<(), Errno> {
        if self.ports.load(Ordering::Acquire) {
            return Ok(());
        }
        self.ops.ioperm()?;
        self.ports.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn emit_event(&self, code: &[u8], source: &[u8], phase: Phase, detail: &[u8]) {
        let _guard = self.report_lock.lock().ok();
        self.emit_event_unlocked(code, source, phase, detail);
    }

    fn emit_event_unlocked(&self, code: &[u8], source: &[u8], phase: Phase, detail: &[u8]) {
        let line = format_event(
            self.report_only(),
            code,
            source,
            phase,
            self.generation(),
            clock_ns(libc::CLOCK_BOOTTIME),
            detail,
        );
        let descriptor = open(c"/dev/kmsg", libc::O_WRONLY | libc::O_CLOEXEC, 0);
        if descriptor >= 0 {
            let mut record = Vec::with_capacity(line.len() + 3);
            record.extend_from_slice(b"<2>");
            record.extend_from_slice(&line);
            let _ = write_all_fd(descriptor, &record);
            let _ = sys::close(descriptor);
        }
        if self.enable_ports().is_ok() {
            if self.async_output.load(Ordering::Relaxed) {
                self.ops.outb(PORTB_DATA, b'\n');
            }
            for &byte in &line {
                self.ops.outb(PORTB_DATA, byte);
            }
        }
        self.console_write(&line);
        let _ = count_violation();
    }

    pub(crate) fn conformance_failure(&self, code: &[u8], phase: Phase, detail: &[u8]) {
        let _guard = self.report_lock.lock().ok();
        self.emit_event_unlocked(code, b"conformance", phase, detail);
        if !self.report_only() {
            self.ops.power_off(STATUS_CONFORMANCE);
        }
    }

    pub(crate) fn fail_fatal(
        &self,
        status: u8,
        code: &[u8],
        source: &[u8],
        phase: Phase,
        detail: &[u8],
    ) {
        self.emit_event(code, source, phase, detail);
        if !self.report_only() {
            self.ops.power_off(status);
        }
    }

    fn console_write(&self, line: &[u8]) {
        let descriptor = open(
            c"/dev/console",
            libc::O_WRONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        );
        let output = if descriptor >= 0 {
            descriptor
        } else {
            libc::STDERR_FILENO
        };
        if self.async_output.load(Ordering::Relaxed) {
            let _ = write_all_fd(output, b"\n");
        }
        let _ = write_all_fd(output, line);
        if descriptor >= 0 {
            let _ = sys::close(descriptor);
        }
    }
}

pub(crate) fn clock_ns(clock: libc::clockid_t) -> i64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes `value`; these clocks are always available on Linux.
    unsafe { libc::clock_gettime(clock, &raw mut value) };
    value
        .tv_sec
        .wrapping_mul(NSEC_PER_SEC)
        .wrapping_add(value.tv_nsec)
}

pub(crate) fn cpu_time_ns() -> i64 {
    clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)
}

pub(crate) fn make_runtime_directories() {
    // SAFETY: paths are NUL-terminated; EEXIST is intentionally ignored.
    unsafe {
        libc::mkdir(RUN_DIR.as_ptr(), 0o755);
        libc::mkdir(TIME_DIR.as_ptr(), 0o755);
    }
}

pub(crate) fn open(path: &CStr, flags: libc::c_int, mode: libc::mode_t) -> libc::c_int {
    // SAFETY: `path` is NUL-terminated.
    unsafe { libc::open(path.as_ptr(), flags, libc::c_uint::from(mode)) }
}

pub(crate) fn write_all_fd(descriptor: libc::c_int, mut bytes: &[u8]) -> Result<(), Errno> {
    while !bytes.is_empty() {
        // SAFETY: write reads at most `bytes.len()` initialized bytes.
        let count =
            sys::retry(|| unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) });
        if count <= 0 {
            return Err(if count == 0 {
                Errno(libc::EIO)
            } else {
                Errno::last()
            });
        }
        bytes = &bytes[count as usize..];
    }
    Ok(())
}

pub(crate) fn read_bytes(path: &CStr, buffer: &mut [u8]) -> Result<usize, Errno> {
    let descriptor = open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0);
    if descriptor < 0 {
        return Err(Errno::last());
    }
    let mut total = 0;
    while total < buffer.len() {
        // SAFETY: read initializes the remaining part of `buffer`.
        let count = sys::retry(|| unsafe {
            libc::read(
                descriptor,
                buffer[total..].as_mut_ptr().cast(),
                buffer.len() - total,
            )
        });
        if count < 0 {
            let error = Errno::last();
            let _ = sys::close(descriptor);
            return Err(error);
        }
        if count == 0 {
            break;
        }
        total += count as usize;
    }
    let close = sys::close(descriptor);
    close.map(|()| total)
}

pub(crate) fn read_text(path: &CStr, limit: usize) -> Result<Vec<u8>, Errno> {
    let mut text = vec![0; limit.saturating_sub(1)];
    let count = read_bytes(path, &mut text)?;
    text.truncate(count);
    Ok(text)
}

pub(crate) fn read_i64(path: &CStr) -> Result<i64, Errno> {
    let text = read_text(path, 64)?;
    decoders::parse_i64_exact(&text).ok_or(Errno(libc::EINVAL))
}

pub(crate) fn write_text(path: &CStr, text: &[u8]) -> Result<(), Errno> {
    let descriptor = open(path, libc::O_WRONLY | libc::O_CLOEXEC, 0);
    if descriptor < 0 {
        return Err(Errno::last());
    }
    if let Err(error) = write_all_fd(descriptor, text) {
        let _ = sys::close(descriptor);
        return Err(error);
    }
    sys::close(descriptor)
}

pub(crate) fn write_i64(path: &CStr, value: i64) -> Result<(), Errno> {
    write_text(path, format!("{value}\n").as_bytes())
}

pub(crate) fn replace_file(path: &CStr, temporary: &CStr, text: &[u8]) -> Result<(), Errno> {
    let descriptor = open(
        temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
        0o644,
    );
    if descriptor < 0 {
        return Err(Errno::last());
    }
    let mut result = write_all_fd(descriptor, text);
    if result.is_ok() {
        // SAFETY: fsync operates on the open temporary file.
        if unsafe { libc::fsync(descriptor) } != 0 {
            result = Err(Errno::last());
        }
    }
    if let Err(error) = sys::close(descriptor)
        && result.is_ok()
    {
        result = Err(error);
    }
    if result.is_ok() {
        // SAFETY: both paths are NUL-terminated and in the same directory.
        if unsafe { libc::rename(temporary.as_ptr(), path.as_ptr()) } != 0 {
            result = Err(Errno::last());
        }
    }
    if result.is_err() {
        // SAFETY: `temporary` is NUL-terminated.
        unsafe { libc::unlink(temporary.as_ptr()) };
    }
    result
}

pub(crate) fn lock_file(path: &CStr) -> Result<libc::c_int, Errno> {
    make_runtime_directories();
    let descriptor = open(path, libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
    if descriptor < 0 {
        return Err(Errno::last());
    }
    // SAFETY: flock takes an open descriptor.
    if sys::retry(|| unsafe { libc::flock(descriptor, libc::LOCK_EX) }) != 0 {
        let error = Errno::last();
        let _ = sys::close(descriptor);
        return Err(error);
    }
    Ok(descriptor)
}

pub(crate) fn state_load() -> Result<TimeState, Errno> {
    let text = read_text(STATE_PATH, 2048)?;
    TimeState::parse(&text).ok_or(Errno(libc::EINVAL))
}

pub(crate) fn state_store(state: &TimeState) -> Result<(), Errno> {
    replace_file(STATE_PATH, STATE_TEMP_PATH, &state.format())
}

pub(crate) fn state_apply(update: impl FnOnce(&mut TimeState)) -> Result<(), Errno> {
    let lock = lock_file(STATE_LOCK_PATH)?;
    let mut state = state_load().unwrap_or_default();
    update(&mut state);
    let result = state_store(&state);
    let _ = sys::close(lock);
    result
}

fn count_violation() -> Result<(), Errno> {
    // SAFETY: access reads the NUL-terminated path.
    if unsafe { libc::access(STATE_PATH.as_ptr(), libc::F_OK) } != 0 {
        return Ok(());
    }
    state_apply(|state| state.violations = state.violations.wrapping_add(1))
}

pub(crate) fn rates_load() -> Result<(u64, u64), Errno> {
    let state = state_load()?;
    if state.tsc_hz == 0 || state.lapic_hz == 0 {
        Err(Errno(libc::EINVAL))
    } else {
        Ok((state.tsc_hz, state.lapic_hz))
    }
}

fn path_exists(path: &CStr) -> bool {
    // SAFETY: `path` is NUL-terminated.
    (unsafe { libc::access(path.as_ptr(), libc::F_OK) }) == 0
}

pub(crate) fn suppression_save() -> Result<(), Errno> {
    let suppressed = [RCU_STALL_SUPPRESS, SOFT_WATCHDOG, HUNG_TASK_TIMEOUT];
    let values = [1_i64, 0, 0];
    let mut saved = Vec::with_capacity(512);
    for (index, path) in suppressed.iter().copied().enumerate() {
        if !path_exists(path) {
            if index == 0 {
                return Err(Errno::last());
            }
            continue;
        }
        let value = read_i64(path)?;
        saved.extend_from_slice(path.to_bytes());
        saved.extend_from_slice(format!("={value}\n").as_bytes());
    }
    let descriptor = open(
        SUPPRESSION_PATH,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    );
    if descriptor < 0 {
        return Err(Errno::last());
    }
    if let Err(error) = write_all_fd(descriptor, &saved) {
        let _ = sys::close(descriptor);
        // SAFETY: the path is NUL-terminated.
        unsafe { libc::unlink(SUPPRESSION_PATH.as_ptr()) };
        return Err(error);
    }
    let _ = sys::close(descriptor);
    for (path, value) in suppressed.into_iter().zip(values) {
        if path_exists(path) {
            write_i64(path, value)?;
        }
    }
    Ok(())
}

pub(crate) fn suppression_restore(missing_ok: bool) -> Result<(), Vec<u8>> {
    let lock = lock_file(SUPPRESSION_LOCK_PATH).map_err(|error| {
        let mut detail = b"lock /run/nvx/time/suppression.lock: ".to_vec();
        detail.extend_from_slice(&error.text());
        detail
    })?;
    let text = match read_text(SUPPRESSION_PATH, 512) {
        Ok(text) => text,
        Err(error) if missing_ok && error == Errno(libc::ENOENT) => {
            let _ = sys::close(lock);
            return Ok(());
        }
        Err(error) => {
            let mut detail = b"read /run/nvx/time/suppression: ".to_vec();
            detail.extend_from_slice(&error.text());
            let _ = sys::close(lock);
            return Err(detail);
        }
    };
    for line in text
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(equal) = line.iter().position(|byte| *byte == b'=') else {
            break;
        };
        let path = match CString::new(&line[..equal]) {
            Ok(path) => path,
            Err(_) => break,
        };
        if let Err(error) = write_text(&path, &line[equal + 1..]) {
            let mut detail = b"restore ".to_vec();
            detail.extend_from_slice(&line[..equal.min(200)]);
            detail.extend_from_slice(b": ");
            detail.extend_from_slice(&error.text());
            let _ = sys::close(lock);
            return Err(detail);
        }
    }
    // SAFETY: the path is NUL-terminated.
    if unsafe { libc::unlink(SUPPRESSION_PATH.as_ptr()) } != 0 {
        let error = Errno::last();
        let _ = sys::close(lock);
        let mut detail = b"remove /run/nvx/time/suppression: ".to_vec();
        detail.extend_from_slice(&error.text());
        return Err(detail);
    }
    let _ = sys::close(lock);
    Ok(())
}

pub(crate) fn portb_read(runtime: &Runtime<'_>, port: u16, buffer: &mut [u8]) {
    for chunk in buffer.chunks_mut(4) {
        let bytes = runtime.ops.inl(port).to_ne_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

pub(crate) fn lock_portb() -> Result<libc::c_int, Vec<u8>> {
    lock_file(PORTB_LOCK_PATH).map_err(|error| {
        let mut detail = b"portb lock: ".to_vec();
        detail.extend_from_slice(&error.text());
        detail
    })
}

pub(crate) fn take_sample(runtime: &Runtime<'_>, sample: &mut TimeSample) -> Result<(), String> {
    let mut bytes = [0_u8; SAMPLE_SIZE];
    sample.t0 = clock_ns(libc::CLOCK_REALTIME);
    runtime.ops.outb(PORTB_STATUS, SELECT_TIME_SAMPLE);
    sample.t1 = clock_ns(libc::CLOCK_REALTIME);
    portb_read(runtime, PORTB_WINDOW, &mut bytes);
    *sample = TimeSample {
        t0: sample.t0,
        t1: sample.t1,
        ..TimeSample::parse(&bytes)?
    };
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct BestSample {
    pub(crate) theta: i64,
    pub(crate) epsilon: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SampleResult {
    Accepted,
    Wide,
}

pub(crate) fn best_sample(
    runtime: &Runtime<'_>,
    attempts: usize,
    bound_ns: i64,
    generation: u32,
) -> Result<(SampleResult, BestSample), (i32, Vec<u8>)> {
    runtime.enable_ports().map_err(|error| {
        let mut detail = b"ioperm: ".to_vec();
        detail.extend_from_slice(&error.text());
        (-1, detail)
    })?;
    let status = runtime.ops.inb(PORTB_STATUS);
    if status & PORTB_TIME_WINDOW == 0 {
        return Err((
            -1,
            format!("portb status 0x{status:02x} has no time-sample window").into_bytes(),
        ));
    }
    let mut best = None;
    let mut detail = b"no valid time sample".to_vec();
    for _ in 0..attempts {
        let mut sample = TimeSample {
            flags: 0,
            generation: 0,
            utc_ns: 0,
            t0: 0,
            t1: 0,
        };
        if let Err(error) = take_sample(runtime, &mut sample) {
            detail = error.into_bytes();
            continue;
        }
        if sample.generation != generation {
            return Err((
                -2,
                format!(
                    "time sample generation {}, expected {generation}",
                    sample.generation
                )
                .into_bytes(),
            ));
        }
        let (theta, epsilon) = decoders::pair_clocks(sample.t0, sample.t1, sample.utc_ns);
        let candidate = BestSample { theta, epsilon };
        if best
            .as_ref()
            .is_none_or(|current: &BestSample| epsilon < current.epsilon)
        {
            best = Some(candidate);
        }
        if epsilon <= bound_ns {
            return Ok((SampleResult::Accepted, candidate));
        }
        detail = format!("time sample uncertainty {epsilon} ns exceeds {bound_ns} ns").into_bytes();
    }
    best.map(|best| (SampleResult::Wide, best))
        .ok_or((-1, detail))
}

fn offset_to_timeval(offset_ns: i64) -> libc::timeval {
    let mut seconds = offset_ns / NSEC_PER_SEC;
    let mut nanoseconds = offset_ns % NSEC_PER_SEC;
    if nanoseconds < 0 {
        seconds -= 1;
        nanoseconds += NSEC_PER_SEC;
    }
    libc::timeval {
        tv_sec: seconds as _,
        tv_usec: nanoseconds as _,
    }
}

pub(crate) fn correction_timex(correction: Correction) -> libc::timex {
    // SAFETY: zero is the defined baseline for every timex field.
    let mut value: libc::timex = unsafe { std::mem::zeroed() };
    match correction {
        Correction::Step {
            modes,
            seconds,
            nanoseconds,
        } => {
            value.modes = modes;
            value.time = libc::timeval {
                tv_sec: seconds as _,
                tv_usec: nanoseconds as _,
            };
        }
        Correction::Slew {
            modes,
            offset,
            status,
            constant,
            maxerror,
            esterror,
        } => {
            value.modes = modes;
            value.offset = offset as libc::c_long;
            value.status = status;
            value.constant = constant as libc::c_long;
            value.maxerror = maxerror as libc::c_long;
            value.esterror = esterror as libc::c_long;
        }
    }
    value
}

pub(crate) fn step_clock(runtime: &Runtime<'_>, offset_ns: i64) -> Result<(), Errno> {
    // SAFETY: zero is the defined baseline for every timex field.
    let mut value: libc::timex = unsafe { std::mem::zeroed() };
    value.modes = 0x2100;
    value.time = offset_to_timeval(offset_ns);
    runtime.ops.adjtimex(&mut value).map(|_| ())
}

pub(crate) fn set_frequency(runtime: &Runtime<'_>, frequency: i64) -> Result<(), Errno> {
    // SAFETY: zero is the defined baseline for every timex field.
    let mut value: libc::timex = unsafe { std::mem::zeroed() };
    value.modes = 0x0002 | 0x0010;
    value.freq = frequency as libc::c_long;
    value.status = FREQUENCY_STATUS;
    runtime.ops.adjtimex(&mut value).map(|_| ())
}

pub(crate) fn current_frequency(runtime: &Runtime<'_>) -> i64 {
    // SAFETY: zero is the defined baseline for every timex field.
    let mut value: libc::timex = unsafe { std::mem::zeroed() };
    runtime
        .ops
        .adjtimex(&mut value)
        .map_or(0, |_| value.freq as i64)
}

pub(crate) fn initial_sample(runtime: &Runtime<'_>) -> Result<BestSample, Vec<u8>> {
    let lock = lock_portb()?;
    let result = best_sample(
        runtime,
        SAMPLE_ATTEMPTS,
        NSEC_PER_MSEC,
        runtime.generation(),
    );
    let _ = sys::close(lock);
    let (_, sample) = result.map_err(|(_, detail)| detail)?;
    step_clock(runtime, sample.theta).map_err(|error| {
        let mut detail = b"adjtimex step: ".to_vec();
        detail.extend_from_slice(&error.text());
        detail
    })?;
    Ok(sample)
}

pub(crate) fn strerror(errno: i32) -> Vec<u8> {
    Errno(errno).text()
}

pub(crate) fn close(descriptor: libc::c_int) {
    let _ = sys::close(descriptor);
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct FakeOps {
        ioperm: Result<(), Errno>,
        input: Mutex<VecDeque<u32>>,
        output: Mutex<Vec<(u16, u8)>>,
        adjustments: Mutex<Vec<libc::timex>>,
        ioperm_calls: AtomicUsize,
        power: AtomicUsize,
    }

    impl FakeOps {
        fn new(input: impl IntoIterator<Item = u32>) -> Self {
            Self {
                ioperm: Ok(()),
                input: Mutex::new(input.into_iter().collect()),
                output: Mutex::new(Vec::new()),
                adjustments: Mutex::new(Vec::new()),
                ioperm_calls: AtomicUsize::new(0),
                power: AtomicUsize::new(0),
            }
        }
    }

    impl PrivilegedOps for FakeOps {
        fn ioperm(&self) -> Result<(), Errno> {
            self.ioperm_calls.fetch_add(1, Ordering::Relaxed);
            self.ioperm
        }
        fn inb(&self, _: u16) -> u8 {
            self.input.lock().unwrap().pop_front().unwrap_or_default() as u8
        }
        fn inl(&self, _: u16) -> u32 {
            self.input.lock().unwrap().pop_front().unwrap_or_default()
        }
        fn outb(&self, port: u16, value: u8) {
            self.output.lock().unwrap().push((port, value));
        }
        fn open_msr(&self, _: usize, _: bool) -> Result<libc::c_int, Errno> {
            Ok(1)
        }
        fn read_msr(&self, _: libc::c_int, _: u32) -> Result<u64, i32> {
            Err(-libc::EIO)
        }
        fn write_msr(&self, _: libc::c_int, _: u32, _: u64) -> Result<(), i32> {
            Err(-libc::EIO)
        }
        fn adjtimex(&self, value: &mut libc::timex) -> Result<libc::c_int, Errno> {
            self.adjustments.lock().unwrap().push(*value);
            Ok(0)
        }
        fn power_off(&self, status: u8) {
            self.power.store(usize::from(status), Ordering::Relaxed);
        }
    }

    #[test]
    fn port_reader_uses_one_four_byte_read_per_chunk() {
        let ops = FakeOps::new([0x0403_0201, 0x0807_0605]);
        let runtime = Runtime::new(&ops, false);
        let mut bytes = [0; 7];
        portb_read(&runtime, PORTB_DATA, &mut bytes);
        assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7]);
        assert!(ops.input.lock().unwrap().is_empty());
    }

    #[test]
    fn packet_without_ranges_costs_exactly_twenty_four_data_reads() {
        let ops = FakeOps::new(0..24);
        let runtime = Runtime::new(&ops, false);
        let mut header = [0; 32];
        let mut entropy = [0; 64];
        portb_read(&runtime, PORTB_DATA, &mut header);
        portb_read(&runtime, PORTB_DATA, &mut entropy);
        assert!(ops.input.lock().unwrap().is_empty());
    }

    #[test]
    fn ioperm_is_injected_and_cached() {
        let ops = FakeOps::new([]);
        let runtime = Runtime::new(&ops, false);
        runtime.enable_ports().unwrap();
        runtime.enable_ports().unwrap();
        assert_eq!(ops.ioperm_calls.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.ops.read_msr(1, 0x4000_0000), Err(-libc::EIO));
        assert_eq!(runtime.ops.write_msr(1, 0x4000_0000, 0), Err(-libc::EIO));
    }

    #[test]
    fn ioperm_failure_reaches_the_sample_diagnostic() {
        let mut ops = FakeOps::new([]);
        ops.ioperm = Err(Errno(libc::EPERM));
        let runtime = Runtime::new(&ops, false);
        let error = best_sample(&runtime, 3, NSEC_PER_MSEC, 0).unwrap_err();
        assert_eq!(error.0, -1);
        let mut expected = b"ioperm: ".to_vec();
        expected.extend_from_slice(&Errno(libc::EPERM).text());
        assert_eq!(error.1, expected);
    }

    #[test]
    fn privileged_adjustment_and_power_paths_are_injectable() {
        let ops = FakeOps::new([]);
        let runtime = Runtime::new(&ops, false);
        step_clock(&runtime, -1_128_000_000).unwrap();
        set_frequency(&runtime, 65_536).unwrap();
        let adjustments = ops.adjustments.lock().unwrap();
        assert_eq!(adjustments[0].modes, 0x2100);
        assert_eq!(adjustments[0].time.tv_sec, -2);
        assert_eq!(adjustments[0].time.tv_usec, 872_000_000);
        assert_eq!(adjustments[1].freq, 65_536);
        drop(adjustments);
        runtime.ops.power_off(195);
        assert_eq!(ops.power.load(Ordering::Relaxed), 195);
    }
}
