//! `nvx-time`, the guest component of NVX time ABI v1.

mod decoders;
mod events;
mod state;
mod test_mode;

use std::ffi::CString;
use std::io::{self, Write};
use std::process::ExitCode;

pub(crate) const NSEC_PER_MSEC: i64 = 1_000_000;
pub(crate) const MAX_CPUS: usize = 64;
pub(crate) const DEFERRED_START_NS: i64 = 150 * NSEC_PER_MSEC;
pub(crate) const IDLE_BOUND_NS: i64 = 100 * NSEC_PER_MSEC;

/// The phase in which a check or event occurs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Boot,
    Capture,
    Restore,
    Runtime,
}

impl Phase {
    pub(crate) const CHECKS: [Self; 3] = [Self::Boot, Self::Capture, Self::Restore];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Capture => "capture",
            Self::Restore => "restore",
            Self::Runtime => "runtime",
        }
    }
}

const USAGE: &[u8] = br#"usage: nvx-time [--report-only] COMMAND
  boot
  check --phase capture|restore [--new-cpus LIST]
  pre-capture
  capture 0|1 GENERATION_ID ENTROPY_FILE [--finish]
  cancel-capture
  restore-finish [--ack] [--new-cpus LIST]
  status
  sample
  generation-id
  exhaustive
  test NAME ARGUMENTS...
"#;

/// Runs `nvx-time` with the process's arguments.
pub fn main() -> ExitCode {
    super::sys::restore_sigpipe();
    let args = super::sys::args();
    ExitCode::from(run(&args, &mut io::stdout(), &mut io::stderr()))
}

fn run(args: &[CString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut arguments = Vec::with_capacity(args.len().min(32));
    let mut report_only = false;
    for argument in args.iter().skip(1) {
        if argument.as_bytes() == b"--report-only" {
            report_only = true;
        } else if arguments.len() < 32 {
            arguments.push(argument.as_bytes());
        } else {
            super::sys::report(err, &[USAGE]);
            return 2;
        }
    }
    let Some((&command, rest)) = arguments.split_first() else {
        super::sys::report(err, &[USAGE]);
        return 2;
    };
    if command == b"test" {
        return test_mode::run(rest, out);
    }

    // M2 fills in the privileged commands after the pure logic and test mode are established.
    let _ = report_only;
    super::sys::report(err, &[USAGE]);
    2
}
