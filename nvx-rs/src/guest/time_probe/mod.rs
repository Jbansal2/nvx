//! `nvx-time-probe`, the guest-side diagnostics for the NVX time ABI.

mod clock;
mod format;
mod latency;
mod support;
mod warp;

use std::ffi::CString;
use std::io::{self, Write};
use std::process::ExitCode;

pub(super) const VERSION: &str = "1.1";
pub(super) const MAX_CPUS: usize = 1024;

const USAGE: &[u8] = br#"usage: nvx-time-probe COMMAND [OPTIONS]

Commands:
  latency [--iterations N] [--batch B] [--cpu C] [--tsc-hz HZ]
      Per-operation cost (p50/p99/min/mean ns) of rdtsc, rdtscp,
      lfence;rdtsc, clock_gettime(MONOTONIC/REALTIME) through the vDSO,
      and syscall controls. Default: 2000 timed batches of 50 operations
      on the current CPU.
  warp [--duration-ms N] [--cpus LIST] [--bound-ns N] [--tsc-hz HZ]
      Pairwise cross-CPU TSC checks: a check_tsc_warp-style spinlock test
      and a ping-pong offset estimate, each running N ms per pair
      (default 100). LIST looks like 0-3,6 (default: every CPU in the
      affinity mask). The bound defaults to 1000 ns.
  clock [--measure-ms N] [--tsc-hz HZ] [--msr]
      Clocks, clocksources, TSC flags, CPUID time leaves, hypervisor and
      time kernel messages, and the /proc/timer_list clock event summary.
      --msr also reads the TSC, Hyper-V time, and kvmclock MSRs on CPU 0
      through /dev/cpu/0/msr (a #GP is reported, not raised).
  version

The TSC rate comes from --tsc-hz, sysfs tsc_freq_khz, the kernel log, or
/proc/cpuinfo, in that order, and is measured as a last resort.
Exit status: 0 success, 1 warp FAIL, 2 usage error, 3 runtime error.
"#;

pub(super) fn report(stream: &mut dyn Write, parts: &[&[u8]]) {
    crate::guest::sys::report(stream, parts);
}

/// Runs `nvx-time-probe`.
pub fn main() -> ExitCode {
    crate::guest::sys::restore_sigpipe();
    let arguments = crate::guest::sys::args();
    ExitCode::from(run(
        &arguments,
        &mut crate::guest::sys::Stdout::new(),
        &mut io::stderr(),
    ))
}

fn run(arguments: &[CString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let arguments = arguments
        .iter()
        .skip(1)
        .map(CString::as_bytes)
        .collect::<Vec<_>>();
    let Some((&command, rest)) = arguments.split_first() else {
        report(err, &[USAGE]);
        return 2;
    };
    match command {
        b"latency" => latency::run(rest, out, err),
        b"warp" => warp::run(rest, out, err),
        b"clock" => clock::run(rest, out, err),
        b"version" | b"--version" => {
            let _ = writeln!(out, "nvx-time-probe {VERSION}");
            0
        }
        b"help" | b"--help" | b"-h" => {
            let _ = out.write_all(USAGE);
            0
        }
        _ => {
            report(err, &[USAGE]);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&[u8]]) -> Vec<CString> {
        std::iter::once(CString::new("nvx-time-probe").unwrap())
            .chain(values.iter().map(|value| CString::new(*value).unwrap()))
            .collect()
    }

    #[test]
    fn version_help_and_usage_are_byte_exact() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run(&args(&[b"version"]), &mut out, &mut err), 0);
        assert_eq!(out, b"nvx-time-probe 1.1\n");
        assert!(err.is_empty());

        out.clear();
        assert_eq!(run(&args(&[b"--help"]), &mut out, &mut err), 0);
        assert_eq!(out, USAGE);

        err.clear();
        assert_eq!(run(&args(&[]), &mut out, &mut err), 2);
        assert_eq!(err, USAGE);
    }
}
