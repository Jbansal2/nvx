//! `nvx-time`, the guest component of NVX time ABI v1.

mod checks;
mod commands;
mod daemon;
mod decoders;
mod events;
mod state;
mod system;
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

    pub(crate) fn check_index(self) -> Option<usize> {
        match self {
            Self::Boot => Some(0),
            Self::Capture => Some(1),
            Self::Restore => Some(2),
            Self::Runtime => None,
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
    ExitCode::from(run(
        &args,
        &mut super::sys::Stdout::new(),
        &mut io::stderr(),
    ))
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
    commands::run(&arguments, report_only, out, err)
}
