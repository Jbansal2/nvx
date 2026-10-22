//! The runtime adapter's guest agent, a static `x86_64-unknown-linux-musl` executable.
//!
//! - `runtime-adapter-guest` reports the contract that it was built against.
//! - `runtime-adapter-guest serve` serves the host program with the adapter's own framing on its
//!   standard input and output, which connect to the guest's end of the control session between
//!   the host and the guest, such as a control console in raw mode. It exits with 0 once the host
//!   stopped it or the broker closed the stream, and with 1, after a diagnostic on standard error,
//!   once serving failed.
//! - `runtime-adapter-guest init TTY` serves the host program on the tty TTY, which it puts in raw
//!   mode itself, in place of NVX's managed agent, whose initramfs runs it on the VM's control tty
//!   as PID 1; see `runtime_adapter::initramfs`. It then ends with 0 once the host stopped it, and
//!   with 1, after a diagnostic on standard error, once serving failed or the broker closed the
//!   tty. As PID 1, which must not exit, it ends the VM with that status instead, through NVX's
//!   `/sbin/nvx-exit`, as NVX's managed agent does.
//!
//! Anything else is a usage error, with status 2.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => {
            println!("runtime-adapter-guest: {}", runtime_adapter::contract());
            ExitCode::SUCCESS
        }
        [command] if command == runtime_adapter::GUEST_SERVE_COMMAND => serve(),
        [command, tty] if command == runtime_adapter::GUEST_INIT_COMMAND => {
            init(std::path::Path::new(tty))
        }
        _ => {
            eprintln!(
                "usage: runtime-adapter-guest [{} | {} TTY]",
                runtime_adapter::GUEST_SERVE_COMMAND,
                runtime_adapter::GUEST_INIT_COMMAND,
            );
            ExitCode::from(2)
        }
    }
}

/// Serves the session on standard input and output.
#[cfg(target_os = "linux")]
fn serve() -> ExitCode {
    let stdio = Stdio {
        input: std::io::stdin().lock(),
        output: std::io::stdout().lock(),
    };
    match runtime_adapter::guest::serve(stdio) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runtime-adapter-guest: {error}");
            ExitCode::FAILURE
        }
    }
}

/// NVX's program that ends the VM with an exit status, which its initramfs provides.
#[cfg(target_os = "linux")]
const NVX_EXIT: &str = "/sbin/nvx-exit";

/// Serves the session on the tty `tty` in place of NVX's managed agent, then ends with the status
/// of serving: as PID 1, by ending the VM through [`NVX_EXIT`].
#[cfg(target_os = "linux")]
fn init(tty: &std::path::Path) -> ExitCode {
    use runtime_adapter::guest::{self, Served};

    let status: u8 = match guest::serve_terminal(tty) {
        Ok(Served::Stopped) => 0,
        Ok(Served::Closed) => {
            eprintln!("runtime-adapter-guest: the broker closed {}", tty.display());
            1
        }
        Err(error) => {
            eprintln!("runtime-adapter-guest: {error}");
            1
        }
    };
    if std::process::id() != 1 {
        return ExitCode::from(status);
    }
    // PID 1 must not exit, or the kernel panics: `nvx-exit` replaces it and ends the VM. Should
    // it fail to start, PID 1 waits, and the host stops the VM.
    let error = std::os::unix::process::CommandExt::exec(
        std::process::Command::new(NVX_EXIT).arg(status.to_string()),
    );
    eprintln!("runtime-adapter-guest: cannot run {NVX_EXIT}: {error}");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Standard input and output as one stream, which carries nothing but the session's records.
#[cfg(target_os = "linux")]
struct Stdio {
    /// Standard input, from the broker.
    input: std::io::StdinLock<'static>,
    /// Standard output, to the broker.
    output: std::io::StdoutLock<'static>,
}

#[cfg(target_os = "linux")]
impl std::io::Read for Stdio {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

#[cfg(target_os = "linux")]
impl std::io::Write for Stdio {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

// The guest agent runs only in Linux guests. Elsewhere this stub fails, so that every target still
// builds with every feature.
#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("runtime-adapter-guest runs only in Linux guests");
    ExitCode::FAILURE
}
