//! The `nvx-rs` command-line interface, which runs NVX's microVMs and sandboxes.
//!
//! ```text
//! nvx-rs [-h] [--root PATH] [--prog PROG] artifacts
//! nvx-rs [-h] [--root PATH] [--prog PROG] egress compile PATH
//! nvx-rs [-h] [--root PATH] [--prog PROG] run [OPTIONS]
//! nvx-rs [-h] [--root PATH] [--prog PROG] sandbox [run|provision|start|exec|stop|deprovision] [OPTIONS]
//! ```
//!
//! - `artifacts` prints the paths of the artifacts of the artifact root as JSON.
//! - `egress compile PATH` compiles an egress policy file of `--network-egress-policy-file` and
//!   prints its native rules as JSON.
//! - `run` boots or restores a microVM on the terminal, with the options, checks, outputs, and
//!   exit statuses of the `nvx.py run` that it replaced.
//! - `sandbox` runs or manages a sandbox, with the options, outputs, exit statuses, outcome
//!   reports, and state directories of the `nvx.py sandbox` that it replaced.
//!
//! The artifact root is `--root`, or else the release or repository checkout that holds the
//! executable, and the `NVX_OPENVMM` environment variable names another OpenVMM executable.
//! `--prog` names the program in usage and error messages, `nvx-rs` by default. A name with square
//! brackets or control characters, which could read as the code of an error or end its line, is
//! refused.
//!
//! Errors print `error[CODE]: MESSAGE` to standard error and exit with status 1, as `nvx.py`
//! reports a `ScriptError`, with the stable [`ErrorCode`] of the failure. Usage errors print the
//! usage and `PROG: error[CODE]: MESSAGE`, with one of the `argument-*` codes, and exit with
//! status 2, as `argparse` does. Each error is one line: a line break in a value that its message
//! names, such as a path, prints as `\n` or `\r`. Ctrl-C prints `Interrupted` and exits with
//! status 130. Text ends its lines as Python's `print` ends them: `\r\n` on Windows, and `\n`
//! elsewhere.

mod args;
mod artifacts;
mod cpu_profile;
mod deadline;
mod egress;
mod network;
mod output;
mod run;
mod sandbox;
mod session;

use std::borrow::Cow;
use std::ffi::OsString;

use self::args::{Parser, Receiver, Spec, Stop, Syntax};
use crate::ErrorCode;
use crate::host::platform;
use crate::host::python::builtins::repr;
use crate::host::python::fs::os_error_message;

/// The name of the program in usage messages unless `--prog` names another.
const PROGRAM: &str = "nvx-rs";
/// The commands, in the order in which usage messages list them.
const COMMANDS: [&str; 4] = ["artifacts", "egress", "run", "sandbox"];
/// The usage and help of the top-level parser.
const SYNTAX: Syntax = Syntax {
    command: "",
    optionals: &["[-h]", "[--root PATH]", "[--prog PROG]"],
    positionals: &["{artifacts,egress,run,sandbox} ..."],
    help: "\
Run NVX microVMs and sandboxes, look up NVX artifacts, and compile egress
policies.

positional arguments:
  {artifacts,egress,run,sandbox}
    artifacts           print the paths of the NVX artifacts as JSON
    egress              compile egress policy files
    run                 run an OpenVMM microVM
    sandbox             run or manage workloads over EROFS layers and private
                        ext4 scratch

options:
  -h, --help            show this help message and exit
  --root PATH           the NVX repository checkout or extracted release whose
                        artifacts to use (default: the release or checkout
                        that holds this executable)
  --prog PROG           the program name that usage and error messages show
                        (default: nvx-rs)

environment:
  NVX_OPENVMM           the OpenVMM executable to run instead of the one of the
                        artifact root",
};

/// How a command ends other than by succeeding.
#[derive(Debug)]
pub(crate) enum Exit {
    /// `error[CODE]: MESSAGE` on standard error, and status 1: what `nvx.py` does for a
    /// `ScriptError`, an `OSError`, a `RuntimeError`, or a `ValueError`.
    Error {
        /// The code of the failure.
        code: ErrorCode,
        /// The message.
        message: String,
    },
    /// OpenVMM closed the control endpoint, as it does when it shuts down: Python's
    /// `ControlEndpointClosed`, which `nvx.py` reports as any other error, and whose code is
    /// [`ErrorCode::EndpointClosed`].
    EndpointClosed,
    /// A usage error of the parser `prog`: its usage, then `PROG: error[CODE]: MESSAGE`, and
    /// status 2.
    Usage {
        /// The parser's usage.
        usage: String,
        /// The parser's name, such as `nvx-rs sandbox`.
        prog: String,
        /// The code of the usage error, one of the `argument-*` codes.
        code: ErrorCode,
        /// The message.
        message: String,
    },
    /// Help on standard output, and status 0.
    Help(String),
    /// Ctrl-C: `Interrupted` on standard error, and status 130.
    Interrupted,
    /// `SystemExit(status)`: the status of OpenVMM or of a managed workload.
    Status(i32),
}

/// The message of [`Exit::EndpointClosed`], `str(ControlEndpointClosed())`.
pub(crate) const ENDPOINT_CLOSED: &str = "managed control endpoint closed";

impl Exit {
    /// Returns the error of `code` that prints `message`.
    pub(crate) fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }

    /// Returns the usage error `message` of `code` of the parser of `syntax` for the program
    /// `program`.
    pub(crate) fn usage(syntax: &Syntax, program: &str, code: ErrorCode, message: String) -> Self {
        Self::Usage {
            usage: syntax.usage(program),
            prog: syntax.prog(program),
            code,
            message,
        }
    }

    /// Returns the end of a parse that `stop` ended, for the parser of `syntax` and the program
    /// `program`.
    pub(crate) fn from_stop(stop: Stop, syntax: &Syntax, program: &str) -> Self {
        match stop {
            Stop::Usage(code, message) => Self::usage(syntax, program, code, message),
            Stop::Help => Self::Help(syntax.help(program)),
        }
    }

    /// Returns the error of an `OSError` that names no file, which prints `str(error)` as
    /// [`os_error_message`] formats it, such as `[Errno 32] Broken pipe` for a write to a
    /// standard stream whose reader has gone, with the code [`ErrorCode::Io`].
    pub(crate) fn from_os_error(error: std::io::Error) -> Self {
        Self::error(ErrorCode::Io, os_error_message(&error, None))
    }

    /// Returns the message that the end prints after its code, if it is an error.
    pub(crate) fn message(&self) -> Option<&str> {
        match self {
            Self::Error { message, .. } | Self::Usage { message, .. } => Some(message),
            Self::EndpointClosed => Some(ENDPOINT_CLOSED),
            _ => None,
        }
    }

    /// Returns the code that the end prints, if it is an error or a usage error.
    pub(crate) fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Error { code, .. } | Self::Usage { code, .. } => Some(*code),
            Self::EndpointClosed => Some(ErrorCode::EndpointClosed),
            _ => None,
        }
    }

    /// Reports the end on the standard streams and returns the exit status.
    fn report(self) -> i32 {
        match self {
            Self::Error { .. } | Self::EndpointClosed => {
                output::print_stderr(&format!(
                    "error[{}]: {}",
                    self.code().unwrap_or(ErrorCode::Other),
                    one_line(self.message().unwrap_or_default())
                ));
                1
            }
            Self::Usage {
                usage,
                prog,
                code,
                message,
            } => {
                output::print_stderr(&format!(
                    "{usage}\n{prog}: error[{code}]: {}",
                    one_line(&message)
                ));
                2
            }
            Self::Help(text) => match output::print_stdout(&text) {
                Ok(()) => 0,
                // Ctrl-C ends a help that waits for its reader, as `KeyboardInterrupt` ends it.
                Err(_) if platform::interrupted() => Self::Interrupted.report(),
                Err(error) => Self::from_os_error(error).report(),
            },
            Self::Interrupted => {
                output::print_stderr("Interrupted");
                130
            }
            Self::Status(status) => status,
        }
    }
}

/// Keeps the code and the message of a library error.
impl From<crate::Error> for Exit {
    fn from(error: crate::Error) -> Self {
        Self::error(error.code(), error.message())
    }
}

/// Returns `message` as one line: a line break in it, which only a value that it names holds, such
/// as a path, prints as `\r` or `\n`, so that each error is the one line that callers look for,
/// and no line of a message reads as another error.
fn one_line(message: &str) -> Cow<'_, str> {
    if message.contains(['\r', '\n']) {
        Cow::Owned(message.replace('\r', "\\r").replace('\n', "\\n"))
    } else {
        Cow::Borrowed(message)
    }
}

/// The result of a command.
pub(crate) type Result<T = ()> = std::result::Result<T, Exit>;

/// Fails with [`Exit::Interrupted`] if Ctrl-C arrived.
pub(crate) fn check_interrupt() -> Result {
    if platform::interrupted() {
        Err(Exit::Interrupted)
    } else {
        Ok(())
    }
}

/// Runs `nvx-rs` with the process's arguments and returns its exit status.
///
/// The CLI runs on the calling thread, which should be the main thread of the process, and from
/// here on, Ctrl-C ends the command that runs, with status 130, instead of the process.
pub fn main() -> i32 {
    // Like Python, which installs its handler as it starts, run on without one if that fails.
    let _ = platform::watch_interrupts();
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = run(&arguments);
    // Python raises KeyboardInterrupt wherever Ctrl-C finds its command, so a command that Ctrl-C
    // reached ends as interrupted even if it finished meanwhile, as a run does whose OpenVMM the
    // same Ctrl-C ended.
    if platform::interrupted() {
        return Exit::Interrupted.report();
    }
    match result {
        Ok(()) => 0,
        Err(exit) => exit.report(),
    }
}

/// A parsed command.
enum Command {
    /// `artifacts`.
    Artifacts,
    /// `egress compile PATH`.
    EgressCompile(String),
    /// `run ...`.
    Run(Box<run::Options>),
    /// `sandbox ...`.
    Sandbox(Box<sandbox::Options>),
}

/// The top-level options.
#[derive(Default)]
struct TopLevel {
    /// `--root`, if given.
    root: Option<String>,
    /// `--prog`, if given.
    prog: Option<String>,
}

impl Receiver for TopLevel {
    fn take(&mut self, name: &'static str, value: Option<&str>) -> std::result::Result<(), String> {
        let value = value.map(str::to_owned);
        match name {
            "--root" => self.root = value,
            _ => {
                // A usage error names the program before its code, so the name may hold nothing
                // that reads as a code or ends the error's line.
                if value.as_deref().is_some_and(|program| {
                    program.contains(['[', ']']) || program.contains(char::is_control)
                }) {
                    return Err(
                        "the program name may hold no square brackets or control characters"
                            .to_owned(),
                    );
                }
                self.prog = value;
            }
        }
        Ok(())
    }
}

/// Parses the arguments, reports the unrecognized ones, and runs the command.
fn run(arguments: &[OsString]) -> Result {
    let mut strings = Vec::with_capacity(arguments.len());
    for (index, argument) in arguments.iter().enumerate() {
        let text = argument.to_str().ok_or_else(|| {
            Exit::usage(
                &SYNTAX,
                PROGRAM,
                ErrorCode::ArgumentInvalid,
                format!(
                    "argument {} is not valid Unicode: {}",
                    index + 1,
                    repr(&argument.to_string_lossy())
                ),
            )
        })?;
        strings.push(text.to_owned());
    }
    let parser = Parser::new(
        &[Spec::one("--root"), Spec::one("--prog")],
        &[Spec::one("command")],
    );
    let mut top = TopLevel::default();
    let split = parser.split_command(&strings, &mut top);
    // A usage error names the program that the options before it named.
    let program = top.prog.clone().unwrap_or_else(|| PROGRAM.to_owned());
    let usage = |code, message: String| Exit::usage(&SYNTAX, &program, code, message);
    let (index, mut extras) = split.map_err(|stop| Exit::from_stop(stop, &SYNTAX, &program))?;
    let rest = &strings[index + 1..];
    let (command, unrecognized) = match strings[index].as_str() {
        "artifacts" => (Command::Artifacts, artifacts::parse(rest, &program)?),
        "egress" => {
            let (path, unrecognized) = egress::parse(rest, &program)?;
            (Command::EgressCompile(path), unrecognized)
        }
        "run" => {
            let (options, unrecognized) = run::parse(rest, &program)?;
            (Command::Run(Box::new(options)), unrecognized)
        }
        "sandbox" => {
            let (options, unrecognized) = sandbox::parse(rest, &program)?;
            (Command::Sandbox(Box::new(options)), unrecognized)
        }
        other => {
            return Err(usage(
                ErrorCode::ArgumentInvalid,
                format!(
                    "argument command: {}",
                    args::invalid_choice(other, &COMMANDS)
                ),
            ));
        }
    };
    extras.extend(unrecognized);
    if !extras.is_empty() {
        return Err(usage(
            ErrorCode::ArgumentUnrecognized,
            format!("unrecognized arguments: {}", extras.join(" ")),
        ));
    }
    let root = top.root.as_deref();
    match command {
        Command::Artifacts => artifacts::run(root),
        Command::EgressCompile(path) => egress::run(&path),
        Command::Run(options) => run::run(root, *options),
        Command::Sandbox(options) => sandbox::run(root, *options),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_print_on_one_line() {
        assert!(matches!(one_line("plain"), Cow::Borrowed("plain")));
        assert_eq!(
            one_line("not found: /tmp/\nerror[unsupported]: openvmm"),
            "not found: /tmp/\\nerror[unsupported]: openvmm"
        );
        assert_eq!(one_line("a\r\nb\rc"), "a\\r\\nb\\rc");
    }

    #[test]
    fn program_names_that_could_read_as_codes_or_end_lines_are_refused() {
        for program in [
            "error[io]: wrapper",
            "wrapper: error[io]: alias",
            "a]",
            "a\nb",
            "a\tb",
        ] {
            let arguments = ["--prog", program, "egress", "compile"].map(OsString::from);
            let Err(Exit::Usage {
                prog,
                code,
                message,
                ..
            }) = run(&arguments)
            else {
                panic!("{program:?} was accepted");
            };
            assert_eq!(prog, PROGRAM, "{program:?}");
            assert_eq!(code, ErrorCode::ArgumentInvalid, "{program:?}");
            assert_eq!(
                message,
                "argument --prog: the program name may hold no square brackets or control \
                 characters"
            );
        }
    }

    #[test]
    fn os_errors_without_a_file_read_as_python_formats_them() {
        let error = std::fs::metadata("definitely/missing/path").unwrap_err();
        let expected = os_error_message(&error, None);
        let exit = Exit::from_os_error(error);
        assert_eq!(exit.code(), Some(ErrorCode::Io));
        let message = exit.message().unwrap();
        assert_eq!(message, expected);
        let label = if cfg!(windows) {
            "[WinError 3] "
        } else {
            "[Errno 2] "
        };
        assert!(message.starts_with(label), "{message}");
        assert!(!message.contains("os error"), "{message}");
        assert!(!message.contains("missing"), "{message}");
        let error = std::io::Error::other("closed");
        assert_eq!(Exit::from_os_error(error).message(), Some("closed"));
    }

    #[test]
    fn errors_keep_the_codes_of_library_errors() {
        let exit = Exit::from(crate::Error::new(
            ErrorCode::SandboxBusy,
            "another lifecycle transition is still in progress",
        ));
        assert_eq!(exit.code(), Some(ErrorCode::SandboxBusy));
        assert_eq!(
            exit.message(),
            Some("another lifecycle transition is still in progress")
        );
        assert_eq!(Exit::EndpointClosed.code(), Some(ErrorCode::EndpointClosed));
        assert_eq!(Exit::Interrupted.code(), None);
        assert_eq!(Exit::Status(3).code(), None);
    }
}
