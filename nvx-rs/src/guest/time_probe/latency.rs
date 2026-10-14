//! The single-CPU instruction and clock latency probe.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use super::format::{f0, f1};
use super::support::{
    TscRate, bad_option, check_cpus_allowed, current_clocksource, cycles_to_ns, detect_tsc_rate,
    option_value, parse_f64, parse_u64, pin_self, strerror,
};

static SINK: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Rdtsc,
    Rdtscp,
    LfenceRdtsc,
    ClockMonotonic,
    ClockRealtime,
    SyscallMonotonic,
    SyscallGetpid,
    SchedYield,
}

const METHODS: &[(Method, &str)] = &[
    (Method::Rdtsc, "rdtsc"),
    (Method::Rdtscp, "rdtscp"),
    (Method::LfenceRdtsc, "lfence_rdtsc"),
    (Method::ClockMonotonic, "clock_gettime_monotonic"),
    (Method::ClockRealtime, "clock_gettime_realtime"),
    (Method::SyscallMonotonic, "syscall_clock_gettime_monotonic"),
    (Method::SyscallGetpid, "syscall_getpid"),
    (Method::SchedYield, "sched_yield"),
];

#[derive(Clone, Copy, Default)]
struct ResultRow {
    p50: f64,
    p99: f64,
    min: f64,
    mean: f64,
    samples: usize,
}

fn cpu_has_rdtscp() -> bool {
    let maximum = super::super::x86::cpuid(0x8000_0000, 0)[0];
    maximum >= 0x8000_0001 && (super::super::x86::cpuid(0x8000_0001, 0)[3] >> 27) & 1 != 0
}

fn run_batch(method: Method, batch: u32) -> u64 {
    let mut sink = 0_u64;
    for _ in 0..batch {
        let value = match method {
            Method::Rdtsc => super::super::x86::rdtsc(),
            Method::Rdtscp => super::super::x86::rdtscp(),
            Method::LfenceRdtsc => super::super::x86::rdtsc_lfence(),
            Method::ClockMonotonic | Method::ClockRealtime | Method::SyscallMonotonic => {
                let mut time = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                match method {
                    Method::ClockMonotonic => {
                        // SAFETY: clock_gettime initializes `time`.
                        unsafe {
                            libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut time);
                        }
                    }
                    Method::ClockRealtime => {
                        // SAFETY: clock_gettime initializes `time`.
                        unsafe {
                            libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut time);
                        }
                    }
                    Method::SyscallMonotonic => {
                        // SAFETY: the raw syscall initializes `time`.
                        unsafe {
                            libc::syscall(
                                libc::SYS_clock_gettime,
                                libc::CLOCK_MONOTONIC,
                                &raw mut time,
                            );
                        }
                    }
                    _ => {}
                }
                time.tv_nsec as u64
            }
            Method::SyscallGetpid => {
                // SAFETY: getpid has no arguments.
                unsafe { libc::syscall(libc::SYS_getpid) as u64 }
            }
            Method::SchedYield => {
                // SAFETY: sched_yield has no arguments.
                unsafe { libc::sched_yield() as u64 }
            }
        };
        sink = sink.wrapping_add(value);
    }
    sink
}

fn nearest_rank(sorted: &[f64], percentile: f64) -> f64 {
    let exact = percentile * sorted.len() as f64;
    let mut rank = exact as usize;
    if (rank as f64) < exact {
        rank += 1;
    }
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn bracket_overhead(iterations: usize) -> Result<f64, ()> {
    let mut samples = Vec::new();
    samples.try_reserve_exact(iterations).map_err(|_| ())?;
    for _ in 0..iterations {
        let t0 = super::super::x86::rdtsc_fenced();
        let t1 = super::super::x86::rdtsc_fenced();
        samples.push(t1.wrapping_sub(t0) as f64);
    }
    samples.sort_unstable_by(f64::total_cmp);
    Ok(nearest_rank(&samples, 0.50))
}

fn measure(
    method: Method,
    iterations: usize,
    batch: u32,
    overhead: f64,
    rate: TscRate,
) -> Result<ResultRow, ()> {
    let mut per_op = Vec::new();
    per_op.try_reserve_exact(iterations).map_err(|_| ())?;
    SINK.fetch_add(run_batch(method, batch), Ordering::Relaxed);
    let mut sum = 0.0;
    for _ in 0..iterations {
        let t0 = super::super::x86::rdtsc_fenced();
        let sink = run_batch(method, batch);
        let t1 = super::super::x86::rdtsc_fenced();
        let cycles = (t1.wrapping_sub(t0) as f64 - overhead).max(0.0);
        SINK.fetch_add(sink, Ordering::Relaxed);
        let value = cycles_to_ns(cycles, rate) / f64::from(batch);
        per_op.push(value);
        sum += value;
    }
    per_op.sort_unstable_by(f64::total_cmp);
    Ok(ResultRow {
        p50: nearest_rank(&per_op, 0.50),
        p99: nearest_rank(&per_op, 0.99),
        min: per_op[0],
        mean: sum / iterations as f64,
        samples: iterations,
    })
}

pub(super) fn run(arguments: &[&[u8]], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut iterations = 2000_u64;
    let mut batch = 50_u64;
    let mut cpu = None;
    let mut override_hz = 0.0;
    let mut index = 0;
    while index < arguments.len() {
        if let Some(value) = option_value(arguments, &mut index, b"--iterations") {
            if let Some(parsed) = parse_u64(value).filter(|value| (1..=10_000_000).contains(value))
            {
                iterations = parsed;
            } else {
                return bad_option(b"latency", arguments[index], err);
            }
        } else if let Some(value) = option_value(arguments, &mut index, b"--batch") {
            if let Some(parsed) = parse_u64(value).filter(|value| (1..=1_000_000).contains(value)) {
                batch = parsed;
            } else {
                return bad_option(b"latency", arguments[index], err);
            }
        } else if let Some(value) = option_value(arguments, &mut index, b"--cpu") {
            if let Some(parsed) = parse_u64(value).filter(|value| *value < super::MAX_CPUS as u64) {
                cpu = Some(parsed as usize);
            } else {
                return bad_option(b"latency", arguments[index], err);
            }
        } else if let Some(value) = option_value(arguments, &mut index, b"--tsc-hz") {
            if let Some(parsed) = parse_f64(value).filter(|value| *value > 0.0) {
                override_hz = parsed;
            } else {
                return bad_option(b"latency", arguments[index], err);
            }
        } else {
            return bad_option(b"latency", arguments[index], err);
        }
        index += 1;
    }

    // SAFETY: sched_getcpu has no arguments.
    let cpu = cpu.map_or_else(|| unsafe { libc::sched_getcpu() }, |cpu| cpu as i32);
    if cpu >= 0 && !check_cpus_allowed(b"latency", &[cpu as usize], err) {
        return 2;
    }
    let pinned = if cpu < 0 {
        Err(crate::guest::sys::Errno::last())
    } else {
        pin_self(cpu as usize)
    };
    if let Err(error) = pinned {
        super::report(
            err,
            &[
                format!("nvx-time-probe latency: cannot pin to cpu {cpu}: ").as_bytes(),
                &strerror(error.0),
                b"\n",
            ],
        );
        return 3;
    }
    let rate = detect_tsc_rate(override_hz);
    if rate.hz <= 0.0 {
        super::report(
            err,
            &[b"nvx-time-probe latency: unknown TSC rate; pass --tsc-hz\n"],
        );
        return 3;
    }
    let clocksource = current_clocksource();
    let overhead = match bracket_overhead(iterations as usize) {
        Ok(overhead) => overhead,
        Err(()) => {
            super::report(err, &[b"nvx-time-probe latency: out of memory\n"]);
            return 3;
        }
    };
    // SAFETY: getauxval reads the process auxiliary vector.
    let vdso = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) != 0 };
    let _ = writeln!(
        out,
        "nvx-time-probe {} latency: cpu={cpu} iterations={iterations} batch={batch} \
         tsc_hz={} tsc_hz_source={} clocksource={} vdso={} bracket_overhead_ns={}",
        super::VERSION,
        f0(rate.hz),
        rate.source,
        String::from_utf8_lossy(&clocksource),
        u8::from(vdso),
        f1(cycles_to_ns(overhead, rate))
    );
    let _ = writeln!(
        out,
        "{:<32} {:>10} {:>10} {:>10} {:>10}",
        "method", "p50_ns", "p99_ns", "min_ns", "mean_ns"
    );
    let mut results = [ResultRow::default(); METHODS.len()];
    let rdtscp = cpu_has_rdtscp();
    for (index, &(method, name)) in METHODS.iter().enumerate() {
        if method == Method::Rdtscp && !rdtscp {
            let _ = writeln!(
                out,
                "{name:<32} unsupported (CPUID.80000001H:EDX[27] clear)"
            );
            continue;
        }
        let row = match measure(method, iterations as usize, batch as u32, overhead, rate) {
            Ok(row) => row,
            Err(()) => {
                super::report(err, &[b"nvx-time-probe latency: out of memory\n"]);
                return 3;
            }
        };
        results[index] = row;
        let _ = writeln!(
            out,
            "{name:<32} {:>10} {:>10} {:>10} {:>10}",
            f1(row.p50),
            f1(row.p99),
            f1(row.min),
            f1(row.mean)
        );
        let _ = out.flush();
    }
    for (index, &(_, name)) in METHODS.iter().enumerate() {
        let row = results[index];
        if row.samples == 0 {
            let _ = writeln!(out, "NVX-TIME-PROBE latency method={name} unsupported=1");
            continue;
        }
        let _ = writeln!(
            out,
            "NVX-TIME-PROBE latency method={name} p50_ns={} p99_ns={} min_ns={} \
             mean_ns={} samples={} batch={batch} cpu={cpu} clocksource={}",
            f1(row.p50),
            f1(row.p99),
            f1(row.min),
            f1(row.mean),
            row.samples,
            String::from_utf8_lossy(&clocksource)
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_uses_the_harness_definition() {
        let values = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(nearest_rank(&values, 0.50), 2.0);
        assert_eq!(nearest_rank(&values, 0.99), 4.0);
    }
}
