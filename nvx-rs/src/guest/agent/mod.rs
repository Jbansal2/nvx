//! The managed guest agent that serves NVX's authenticated control session.
//!
//! The binary runs either as the long-lived direct or sandbox agent, or as the short-lived
//! `--exec-config-fd` helper after the workload identity has been applied. Privileged operations
//! and production paths are behind an internal seam so tests can run without privileges.

use std::ffi::CString;
use std::process::ExitCode;

mod cgroup;
mod diagnostics;
mod dispatch;
mod exec;
mod exec_config;
mod helper;
mod launch;
#[cfg(all(test, feature = "host"))]
mod loopback;
mod mappings;
mod seam;
mod session;
mod tty;

use diagnostics::{close, write_stderr};
use mappings::HostMappings;
use seam::{Paths, RealSystem, System, path_c_string};
use session::Session;

#[cfg(test)]
pub(crate) static PROCESS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) struct AgentConfig {
    rootfs: CString,
    hostname: CString,
    uid: CString,
    gid: CString,
    user: CString,
    home: CString,
    direct: bool,
}

/// Runs `nvx-managed-agent`.
pub fn main() -> ExitCode {
    super::sys::restore_sigpipe();
    let arguments = super::sys::args();
    let mut system = RealSystem::new(Paths::default());
    ExitCode::from(run(&mut system, &arguments))
}

fn run(system: &mut impl System, arguments: &[CString]) -> u8 {
    if arguments
        .get(1)
        .is_some_and(|argument| argument.as_bytes() == b"--exec-config-fd")
    {
        return helper::run(system, arguments);
    }
    if arguments.len() != 8 {
        return 125;
    }
    let config = AgentConfig {
        rootfs: arguments[2].clone(),
        hostname: arguments[3].clone(),
        uid: arguments[4].clone(),
        gid: arguments[5].clone(),
        user: arguments[6].clone(),
        home: arguments[7].clone(),
        direct: arguments[2].as_bytes() == b"-",
    };
    let fd = match tty::open(&arguments[1]) {
        Ok(fd) => fd,
        Err(error) => {
            report_fatal(system, "control-open", diagnostics::errno(&error));
            return finish(system, &config, 125);
        }
    };
    let mut mappings = HostMappings::default();
    if config.direct
        && let Err(error) = mappings::prepare(system, &mut mappings)
    {
        report_fatal(system, "host-mappings", diagnostics::errno(&error));
        close(fd);
        return finish(system, &config, 125);
    }
    if let Err(error) = tty::configure(system, fd) {
        report_fatal(system, "control-tty", diagnostics::errno(&error));
        close(fd);
        return finish(system, &config, 125);
    }
    let mut session = Session::new(fd);
    match dispatch::run(system, &mut session, &config, &mut mappings) {
        Ok(dispatch::Outcome::Stopped) => {
            close(fd);
            finish(system, &config, 0)
        }
        Err(error) => {
            report_fatal(system, "control-session", diagnostics::errno(&error));
            close(fd);
            finish(system, &config, 125)
        }
    }
}

fn report_fatal(system: &mut impl System, stage: &str, status: i32) {
    diagnostics::error(system, stage, status);
    let message = format!("NVX-MANAGED-ERROR: stage={stage} status={status}\n");
    write_stderr(message.as_bytes());
}

fn finish(system: &mut impl System, config: &AgentConfig, status: u8) -> u8 {
    if !config.direct {
        return status;
    }
    let path = match path_c_string(&system.paths().exit) {
        Ok(path) => path,
        Err(_) => return status,
    };
    let code = CString::new(status.to_string()).expect("a decimal status has no NUL");
    let arguments = [c"nvx-exit".as_ptr(), code.as_ptr(), std::ptr::null()];
    let _ = system.exec(&path, &arguments);
    status
}
