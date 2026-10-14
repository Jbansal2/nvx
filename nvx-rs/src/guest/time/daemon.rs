//! Deferred work, violation watching, wall-clock discipline, and restore step 13.

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use super::checks::{self, Checks};
use super::decoders::{self, Correction};
use super::state::TimeState;
use super::system::{
    self, DAEMON_PID_PATH, DAEMON_PID_TEMP_PATH, NSEC_PER_SEC, NSEC_PER_USEC, RCU_NORMAL,
    RCU_STALL_COUNT, RCU_STALL_TIMEOUT, RCU_SYNC_PATH, RESTORE_PATH, Runtime, STATUS_REPAIR,
    STATUS_VIOLATION, SampleResult, clock_ns, correction_timex, cpu_time_ns, current_frequency,
    read_i64, read_text, set_frequency, state_apply, state_load, suppression_restore, write_i64,
    write_text,
};
use super::{DEFERRED_START_NS, IDLE_BOUND_NS, MAX_CPUS, NSEC_PER_MSEC, Phase};
use crate::guest::sys::{self, Errno};

const POLL_BOUND_NS: i64 = 50_000;
const SAMPLE_ATTEMPTS: usize = 3;
const SYNCHRONIZED_AGE_NS: i64 = 128 * NSEC_PER_SEC;
const FAST_PERIOD_S: i64 = 16;
const SLOW_PERIOD_S: i64 = 64;
const FAST_POLLS: i32 = 4;
const TIMER_LIST_WAIT_NS: i64 = 200 * NSEC_PER_MSEC;
const DEFAULT_STALL_TIMEOUT_S: i64 = 21;

pub(crate) fn set_idle_priority(tid: libc::pid_t, idle: bool) {
    // SAFETY: zero is the only scheduler parameter for SCHED_IDLE and SCHED_OTHER.
    let parameter: libc::sched_param = unsafe { std::mem::zeroed() };
    // SAFETY: the raw syscall supports SCHED_IDLE on musl; tid 0 means this thread.
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

fn promote_threads() {
    for _ in 0..2 {
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return;
        };
        for task in tasks.flatten() {
            if let Ok(tid) = task.file_name().to_string_lossy().parse::<libc::pid_t>()
                && tid > 0
            {
                set_idle_priority(tid, false);
            }
        }
    }
}

pub(crate) struct Promoter {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Promoter {
    pub(crate) fn start(start_ns: i64) -> Option<Self> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let child = Arc::clone(&stop);
        let deadline = start_ns.wrapping_add(IDLE_BOUND_NS);
        let thread = thread::Builder::new()
            .name("nvx-time-promote".to_owned())
            .spawn(move || {
                let remaining = deadline.wrapping_sub(clock_ns(libc::CLOCK_MONOTONIC));
                let timeout = Duration::from_nanos(remaining.max(0) as u64);
                let (lock, changed) = &*child;
                let Ok(stopped) = lock.lock() else {
                    return;
                };
                let Ok((stopped, result)) =
                    changed.wait_timeout_while(stopped, timeout, |stopped| !*stopped)
                else {
                    return;
                };
                if !*stopped && result.timed_out() {
                    promote_threads();
                }
            })
            .ok()?;
        Some(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub(crate) fn stop(mut self) {
        {
            let (lock, changed) = &*self.stop;
            if let Ok(mut stopped) = lock.lock() {
                *stopped = true;
                changed.notify_one();
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn kmsg_drain(descriptor: libc::c_int, mut consume: impl FnMut(&[u8])) -> Result<(), i32> {
    let mut record = [0_u8; 8192];
    loop {
        // SAFETY: read initializes at most `record.len() - 1` bytes.
        let count = sys::retry(|| unsafe {
            libc::read(descriptor, record.as_mut_ptr().cast(), record.len() - 1)
        });
        if count < 0 {
            let errno = Errno::last().0;
            return if errno == libc::EAGAIN {
                Ok(())
            } else {
                Err(-errno)
            };
        }
        if count == 0 {
            return Ok(());
        }
        let record = &record[..count as usize];
        let Some(separator) = record.iter().position(|byte| *byte == b';') else {
            continue;
        };
        let message = &record[separator + 1..];
        let end = message
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(message.len());
        consume(&message[..end]);
    }
}

struct PollOutcome {
    accepted: bool,
    stepped: bool,
    synchronized: bool,
    theta: i64,
    epsilon: i64,
    step_realtime_ns: i64,
    frequency: i64,
}

fn apply_poll(state: &mut TimeState, outcome: &PollOutcome) {
    if outcome.accepted {
        state.samples = state.samples.wrapping_add(1);
        state.offset_ns = outcome.theta;
        state.uncertainty_ns = outcome.epsilon;
        state.frequency_ppb = decoders::frequency_to_ppb(outcome.frequency);
        state.last_sample_error = b"none".to_vec();
        if outcome.stepped {
            state.discontinuities = state.discontinuities.wrapping_add(1);
            state.last_discontinuity = b"step".to_vec();
            state.last_step_ns = outcome.theta;
            state.last_step_realtime_ns = outcome.step_realtime_ns;
        }
    } else {
        state.rejected_samples = state.rejected_samples.wrapping_add(1);
        state.last_sample_error = b"G_SAMPLE_UNCERTAIN".to_vec();
    }
    state.synchronized = u64::from(outcome.synchronized);
}

pub(crate) struct Daemon {
    kmsg: libc::c_int,
    signals: libc::c_int,
    timer: libc::c_int,
    polls: i32,
    last_accepted_ns: i64,
    worker_pid: libc::pid_t,
    worker_promote_ns: i64,
    worker_deadline_ns: i64,
    suppression_released: bool,
    restore_pending: bool,
    restore_due_ns: i64,
    readiness_us: i64,
}

fn arm_timer(daemon: &Daemon) -> Result<(), Errno> {
    let mut period = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: if daemon.polls < FAST_POLLS {
                FAST_PERIOD_S
            } else {
                SLOW_PERIOD_S
            },
            tv_nsec: 0,
        },
    };
    // SAFETY: timerfd_settime reads `period`.
    if unsafe { libc::timerfd_settime(daemon.timer, 0, &raw mut period, std::ptr::null_mut()) } == 0
    {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

fn watch_kernel_log(runtime: &Runtime<'_>, daemon: &Daemon) {
    let result = kmsg_drain(daemon.kmsg, |message| {
        if let Some(code) = decoders::match_watch_rule(message) {
            runtime.fail_fatal(
                STATUS_VIOLATION,
                code.as_bytes(),
                b"watcher",
                Phase::Runtime,
                &message[..message.len().min(400)],
            );
        }
    });
    if result == Err(-libc::EPIPE) {
        runtime.fail_fatal(
            STATUS_VIOLATION,
            b"G_KMSG_OVERRUN",
            b"watcher",
            Phase::Runtime,
            b"kernel log records were lost (EPIPE)",
        );
    }
}

fn discipline_poll(runtime: &Runtime<'_>, daemon: &mut Daemon) {
    let stalls = read_i64(RCU_STALL_COUNT).unwrap_or(0);
    if stalls != 0 {
        runtime.fail_fatal(
            STATUS_VIOLATION,
            b"G_RCU_STALL",
            b"watcher",
            Phase::Runtime,
            format!("rcu_stall_count is {stalls}").as_bytes(),
        );
    }
    let fast = daemon.polls < FAST_POLLS;
    daemon.polls += 1;
    let mut outcome = PollOutcome {
        accepted: false,
        stepped: false,
        synchronized: false,
        theta: 0,
        epsilon: 0,
        step_realtime_ns: 0,
        frequency: 0,
    };
    let lock = system::lock_portb();
    let result = if lock.is_ok() {
        Some(system::best_sample(
            runtime,
            SAMPLE_ATTEMPTS,
            POLL_BOUND_NS,
            runtime.generation(),
        ))
    } else {
        None
    };
    match result {
        Some(Ok((SampleResult::Accepted, sample))) => {
            outcome.theta = sample.theta;
            outcome.epsilon = sample.epsilon;
            let frequency = current_frequency(runtime);
            let correction = decoders::plan_correction(sample.theta, sample.epsilon, fast);
            outcome.stepped = matches!(correction, Correction::Step { .. });
            let mut adjustment = correction_timex(correction);
            outcome.accepted = runtime.ops.adjtimex(&mut adjustment).is_ok()
                && (!outcome.stepped || set_frequency(runtime, frequency).is_ok());
            outcome.step_realtime_ns = clock_ns(libc::CLOCK_REALTIME);
            outcome.frequency = current_frequency(runtime);
            if outcome.accepted {
                daemon.last_accepted_ns = clock_ns(libc::CLOCK_MONOTONIC);
            }
        }
        Some(Err((-2, _))) => {
            if let Ok(lock) = lock {
                system::close(lock);
            }
            return;
        }
        _ => {}
    }
    outcome.synchronized = daemon.last_accepted_ns != 0
        && clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(daemon.last_accepted_ns)
            <= SYNCHRONIZED_AGE_NS;
    let _ = state_apply(|state| apply_poll(state, &outcome));
    if let Ok(lock) = lock {
        system::close(lock);
    }
}

fn grace_period_release() -> i32 {
    let normal = read_i64(RCU_NORMAL);
    let saved = normal.is_ok() && write_i64(RCU_NORMAL, 1).is_ok();
    let normal = normal.unwrap_or(0);
    let mut status = 1;
    // SAFETY: the child creates and modifies only its private mount namespace.
    if saved
        && unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0
        && unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } == 0
    {
        // SAFETY: paths and mount strings are NUL-terminated.
        unsafe {
            libc::mkdir(RCU_SYNC_PATH.as_ptr(), 0o700);
            if libc::mount(
                c"nvx-rcu-sync".as_ptr(),
                RCU_SYNC_PATH.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=4k".as_ptr().cast(),
            ) == 0
                && libc::umount2(RCU_SYNC_PATH.as_ptr(), 0) == 0
            {
                status = 0;
            }
            libc::rmdir(RCU_SYNC_PATH.as_ptr());
        }
    }
    if saved && write_i64(RCU_NORMAL, normal).is_err() {
        status = 1;
    }
    status
}

fn release_with_deadline(timeout_s: i64) -> bool {
    let deadline = clock_ns(libc::CLOCK_MONOTONIC).wrapping_add(timeout_s * NSEC_PER_SEC);
    // SAFETY: sigset functions initialize local sets and fork duplicates this single thread.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut mask);
        libc::sigaddset(&raw mut mask, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, &raw mut previous);
        let pid = libc::fork();
        if pid == 0 {
            libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            libc::_exit(grace_period_release());
        }
        let mut released = false;
        if pid > 0 {
            loop {
                let mut status = 0;
                let done = libc::waitpid(pid, &raw mut status, libc::WNOHANG);
                let remaining = deadline.wrapping_sub(clock_ns(libc::CLOCK_MONOTONIC));
                if done == pid {
                    released = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
                    break;
                }
                if done < 0 && Errno::last() != Errno(libc::EINTR) {
                    break;
                }
                if remaining <= 0 {
                    released = true;
                    break;
                }
                let timeout = libc::timespec {
                    tv_sec: remaining / NSEC_PER_SEC,
                    tv_nsec: remaining % NSEC_PER_SEC,
                };
                libc::sigtimedwait(&mask, std::ptr::null_mut(), &timeout);
            }
        }
        libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        released
    }
}

pub(crate) struct RestoreTiming {
    pub(crate) start_ns: i64,
    pub(crate) readiness_us: i64,
    prior_cpu_ns: i64,
    cpu_base_ns: i64,
    fork_fd: libc::c_int,
}

fn step13_cpu_ns(timing: &RestoreTiming) -> i64 {
    let mut cpu = timing
        .prior_cpu_ns
        .wrapping_add(cpu_time_ns())
        .wrapping_sub(timing.cpu_base_ns);
    let mut fork_share = 0_i64;
    if timing.fork_fd >= 0 {
        // SAFETY: read initializes one i64.
        let count = unsafe {
            libc::read(
                timing.fork_fd,
                (&raw mut fork_share).cast(),
                std::mem::size_of::<i64>(),
            )
        };
        if count == std::mem::size_of::<i64>() as isize && fork_share > 0 {
            cpu = cpu.wrapping_add(fork_share);
        }
    }
    cpu
}

fn fork_step13(cpu_start_ns: i64, timing: &mut RestoreTiming) -> libc::pid_t {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe2 initializes both descriptors.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        descriptors = [-1; 2];
    }
    timing.fork_fd = descriptors[0];
    timing.cpu_base_ns = 0;
    set_idle_priority(0, true);
    timing.prior_cpu_ns = cpu_time_ns().wrapping_sub(cpu_start_ns);
    // SAFETY: the daemon is single-threaded at this fork.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if descriptors[1] >= 0 {
            system::close(descriptors[1]);
        }
        return 0;
    }
    set_idle_priority(0, false);
    if descriptors[0] >= 0 {
        system::close(descriptors[0]);
    }
    timing.fork_fd = -1;
    if descriptors[1] >= 0 {
        let share = cpu_time_ns()
            .wrapping_sub(cpu_start_ns)
            .wrapping_sub(timing.prior_cpu_ns);
        if pid > 0 {
            let _ = system::write_all_fd(descriptors[1], &share.to_ne_bytes());
        }
        system::close(descriptors[1]);
    }
    pid
}

pub(crate) fn restore_work(
    runtime: &Runtime<'_>,
    new_cpus: &[bool; MAX_CPUS],
    new_count: usize,
    with_deadline: bool,
    timing: &RestoreTiming,
) -> u8 {
    let mut checks = match Checks::load(Phase::Restore) {
        Ok(checks) => checks,
        Err(_) => {
            let mut checks = Checks::empty(Phase::Restore);
            checks.fail(runtime, "C6", "cannot read the CPU sets");
            checks
        }
    };
    if checks.online_count > 0 {
        checks::run_restore_checks(runtime, &mut checks, new_cpus, new_count);
    }
    let elapsed = clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(timing.start_ns);
    let cpu = step13_cpu_ns(timing);
    let timeout = read_i64(RCU_STALL_TIMEOUT).unwrap_or(DEFAULT_STALL_TIMEOUT_S);
    let released = if with_deadline {
        release_with_deadline(timeout)
    } else {
        grace_period_release() == 0
    };
    if !released {
        runtime.fail_fatal(
            STATUS_REPAIR,
            b"G_REPAIR_SUPPRESSION",
            b"repair",
            Phase::Restore,
            b"the RCU grace-period release failed",
        );
    }
    if let Err(detail) = suppression_restore(true) {
        runtime.fail_fatal(
            STATUS_REPAIR,
            b"G_REPAIR_SUPPRESSION",
            b"repair",
            Phase::Restore,
            &detail,
        );
    }
    checks::check_timer_list(runtime, &mut checks, TIMER_LIST_WAIT_NS);
    if checks::record_check(
        runtime,
        &checks,
        b"ok",
        timing.readiness_us.wrapping_add(elapsed / NSEC_PER_USEC),
        cpu / NSEC_PER_USEC,
        0,
        0,
    )
    .is_err()
    {
        checks.fail(
            runtime,
            "C10",
            format!(
                "cannot record the restore check: {}",
                String::from_utf8_lossy(&Errno::last().text())
            ),
        );
    }
    u8::from(!released)
}

fn parse_restore_state() -> Result<([bool; MAX_CPUS], usize, u64), Vec<u8>> {
    let state = state_load().map_err(|_| b"the time state is unreadable".to_vec())?;
    let text = match read_text(RESTORE_PATH, 256) {
        Ok(text) => text,
        Err(_) => return Ok(([false; MAX_CPUS], 0, state.generation)),
    };
    let (generation, mut cpus, mut count) = decoders::parse_restore_record(&text)
        .ok_or_else(|| b"the restore record is malformed".to_vec())?;
    if generation != state.generation {
        cpus = [false; MAX_CPUS];
        count = 0;
    }
    Ok((cpus, count, state.generation))
}

fn start_restore(runtime: &Runtime<'_>, daemon: &mut Daemon) {
    if daemon.worker_pid > 0 {
        return;
    }
    let cpu_start = cpu_time_ns();
    let (new_cpus, new_count, generation) = match parse_restore_state() {
        Ok(value) => value,
        Err(detail) => {
            runtime.fail_fatal(
                STATUS_REPAIR,
                b"G_REPAIR_SUPPRESSION",
                b"repair",
                Phase::Restore,
                &detail,
            );
            return;
        }
    };
    runtime.set_generation(generation as u32);
    let timeout = read_i64(RCU_STALL_TIMEOUT).unwrap_or(DEFAULT_STALL_TIMEOUT_S);
    let mut timing = RestoreTiming {
        start_ns: daemon.restore_due_ns,
        readiness_us: daemon.readiness_us,
        prior_cpu_ns: 0,
        cpu_base_ns: 0,
        fork_fd: -1,
    };
    let pid = fork_step13(cpu_start, &mut timing);
    if pid == 0 {
        // SAFETY: this is the daemon's single-threaded child and exits without destructors.
        unsafe {
            libc::_exit(i32::from(restore_work(
                runtime, &new_cpus, new_count, false, &timing,
            )))
        };
    }
    if pid < 0 {
        runtime.fail_fatal(
            STATUS_REPAIR,
            b"G_REPAIR_SUPPRESSION",
            b"repair",
            Phase::Restore,
            format!(
                "cannot start the restore work: {}",
                String::from_utf8_lossy(&Errno::last().text())
            )
            .as_bytes(),
        );
        return;
    }
    daemon.worker_pid = pid;
    daemon.worker_promote_ns = daemon.restore_due_ns.wrapping_add(IDLE_BOUND_NS);
    daemon.worker_deadline_ns =
        clock_ns(libc::CLOCK_MONOTONIC).wrapping_add(timeout * NSEC_PER_SEC);
    daemon.suppression_released = false;
}

fn release_suppression(runtime: &Runtime<'_>, daemon: &mut Daemon) {
    daemon.suppression_released = true;
    if let Err(detail) = suppression_restore(true) {
        runtime.fail_fatal(
            STATUS_REPAIR,
            b"G_REPAIR_SUPPRESSION",
            b"repair",
            Phase::Restore,
            &detail,
        );
    }
}

fn reap_children(runtime: &Runtime<'_>, daemon: &mut Daemon) {
    loop {
        let mut status = 0;
        // SAFETY: waitpid writes one wait status.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
        if pid != daemon.worker_pid {
            continue;
        }
        daemon.worker_pid = 0;
        daemon.worker_promote_ns = 0;
        if !libc::WIFEXITED(status) {
            release_suppression(runtime, daemon);
            runtime.fail_fatal(
                STATUS_REPAIR,
                b"G_REPAIR_SUPPRESSION",
                b"repair",
                Phase::Restore,
                format!(
                    "the restore work ended with signal {}",
                    libc::WTERMSIG(status)
                )
                .as_bytes(),
            );
        }
        daemon.polls = 0;
        let _ = arm_timer(daemon);
    }
}

fn handle_signals(runtime: &Runtime<'_>, daemon: &mut Daemon) {
    loop {
        // SAFETY: zero is a valid initial representation; read fills the whole structure.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        // SAFETY: read initializes `info`.
        let count = unsafe {
            libc::read(
                daemon.signals,
                (&raw mut info).cast(),
                std::mem::size_of_val(&info),
            )
        };
        if count != std::mem::size_of_val(&info) as isize {
            break;
        }
        if info.ssi_signo == libc::SIGTERM as u32 {
            // SAFETY: the daemon intentionally exits without running inherited destructors.
            unsafe { libc::_exit(0) };
        }
        if info.ssi_signo == libc::SIGUSR1 as u32 {
            daemon.restore_pending = true;
            daemon.last_accepted_ns = clock_ns(libc::CLOCK_MONOTONIC);
            daemon.restore_due_ns = daemon.last_accepted_ns.wrapping_add(DEFERRED_START_NS);
            daemon.readiness_us = if info.ssi_code == libc::SI_QUEUE {
                (info.ssi_ptr & u64::from(u32::MAX)) as i64
            } else {
                0
            };
        }
    }
    reap_children(runtime, daemon);
}

fn setup_daemon(kmsg: libc::c_int, last_accepted_ns: i64) -> Result<Daemon, Errno> {
    // SAFETY: signal-set functions initialize and consume the local set.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut mask);
        libc::sigaddset(&raw mut mask, libc::SIGUSR1);
        libc::sigaddset(&raw mut mask, libc::SIGTERM);
        libc::sigaddset(&raw mut mask, libc::SIGCHLD);
        if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
            return Err(Errno::last());
        }
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        let signals = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if signals < 0 {
            return Err(Errno::last());
        }
        let timer = libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        );
        if timer < 0 {
            system::close(signals);
            return Err(Errno::last());
        }
        let daemon = Daemon {
            kmsg,
            signals,
            timer,
            polls: 0,
            last_accepted_ns,
            worker_pid: 0,
            worker_promote_ns: 0,
            worker_deadline_ns: 0,
            suppression_released: false,
            restore_pending: false,
            restore_due_ns: 0,
            readiness_us: 0,
        };
        if write_text(c"/proc/self/oom_score_adj", b"-1000").is_err() || arm_timer(&daemon).is_err()
        {
            system::close(signals);
            system::close(timer);
            return Err(Errno::last());
        }
        Ok(daemon)
    }
}

pub(crate) fn become_daemon(kmsg: libc::c_int, last_accepted_ns: i64) -> Result<Daemon, Errno> {
    set_idle_priority(0, false);
    let daemon = setup_daemon(kmsg, last_accepted_ns)?;
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    system::replace_file(
        DAEMON_PID_PATH,
        DAEMON_PID_TEMP_PATH,
        format!("{pid}\n").as_bytes(),
    )?;
    Ok(daemon)
}

fn timeout_until(deadline_ns: i64) -> i32 {
    if deadline_ns == 0 {
        return -1;
    }
    let remaining = deadline_ns.wrapping_sub(clock_ns(libc::CLOCK_MONOTONIC));
    if remaining <= 0 {
        0
    } else {
        ((remaining + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC).min(i64::from(i32::MAX)) as i32
    }
}

fn earlier(first: i32, second: i32) -> i32 {
    match (first, second) {
        (-1, value) | (value, -1) => value,
        _ => first.min(second),
    }
}

pub(crate) fn daemon_loop(runtime: &Runtime<'_>, mut daemon: Daemon) -> ! {
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: daemon.kmsg,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: daemon.signals,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: daemon.timer,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let waiting = daemon.worker_pid > 0 && !daemon.suppression_released;
        let idle = daemon.worker_pid > 0 && daemon.worker_promote_ns != 0;
        let due = daemon.restore_pending && daemon.worker_pid == 0;
        let timeout = earlier(
            earlier(
                timeout_until(if idle { daemon.worker_promote_ns } else { 0 }),
                timeout_until(if waiting {
                    daemon.worker_deadline_ns
                } else {
                    0
                }),
            ),
            timeout_until(if due { daemon.restore_due_ns } else { 0 }),
        );
        // SAFETY: poll updates the three local descriptors.
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 3, timeout) };
        if result < 0 && Errno::last() != Errno(libc::EINTR) {
            thread::sleep(Duration::from_secs(1));
            continue;
        }
        if descriptors[0].revents & (libc::POLLIN | libc::POLLERR) != 0 {
            watch_kernel_log(runtime, &daemon);
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            handle_signals(runtime, &mut daemon);
        }
        if descriptors[2].revents & libc::POLLIN != 0 {
            let mut expirations = 0_u64;
            // SAFETY: read initializes one u64.
            unsafe {
                libc::read(
                    daemon.timer,
                    (&raw mut expirations).cast(),
                    std::mem::size_of::<u64>(),
                );
            }
            discipline_poll(runtime, &mut daemon);
            let _ = arm_timer(&daemon);
        }
        let mut now = clock_ns(libc::CLOCK_MONOTONIC);
        if daemon.restore_pending && daemon.worker_pid == 0 && now >= daemon.restore_due_ns {
            daemon.restore_pending = false;
            start_restore(runtime, &mut daemon);
            now = clock_ns(libc::CLOCK_MONOTONIC);
        }
        if daemon.worker_pid > 0 && daemon.worker_promote_ns != 0 && now >= daemon.worker_promote_ns
        {
            daemon.worker_promote_ns = 0;
            set_idle_priority(daemon.worker_pid, false);
        }
        if daemon.worker_pid > 0 && !daemon.suppression_released && now >= daemon.worker_deadline_ns
        {
            release_suppression(runtime, &mut daemon);
        }
    }
}

pub(crate) fn signal_restore(
    runtime: &Runtime<'_>,
    daemon: libc::pid_t,
    acknowledge: bool,
    start_ns: i64,
) -> i32 {
    // SAFETY: signal zero probes whether the daemon still exists.
    if daemon <= 0 || unsafe { libc::kill(daemon, 0) } != 0 {
        return -1;
    }
    if acknowledge {
        runtime
            .ops
            .outb(system::PORT_SNAPSHOT, system::SNAPSHOT_ACKNOWLEDGE);
    }
    let elapsed = clock_ns(libc::CLOCK_MONOTONIC).wrapping_sub(start_ns) / NSEC_PER_USEC;
    // libc's sigval binding differs by target, so issue rt_sigqueueinfo through sigqueue.
    let value = libc::sigval {
        sival_ptr: elapsed.clamp(0, i64::from(u32::MAX)) as usize as *mut libc::c_void,
    };
    // SAFETY: daemon was just probed; SIGUSR1 is blocked and consumed through signalfd.
    if unsafe { libc::sigqueue(daemon, libc::SIGUSR1, value) } == 0 {
        0
    } else {
        1
    }
}

pub(crate) fn inline_restore_timing(start_ns: i64) -> RestoreTiming {
    let now = clock_ns(libc::CLOCK_MONOTONIC);
    RestoreTiming {
        start_ns: now,
        readiness_us: now.wrapping_sub(start_ns) / NSEC_PER_USEC,
        prior_cpu_ns: 0,
        cpu_base_ns: cpu_time_ns(),
        fork_fd: -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_timing_constants_match_the_abi() {
        assert_eq!(POLL_BOUND_NS, 50_000);
        assert_eq!(SYNCHRONIZED_AGE_NS, 128_000_000_000);
        assert_eq!((FAST_PERIOD_S, SLOW_PERIOD_S, FAST_POLLS), (16, 64, 4));
    }

    #[test]
    fn poll_deadlines_round_up_to_milliseconds() {
        assert_eq!(earlier(-1, 4), 4);
        assert_eq!(earlier(7, 4), 4);
    }
}
