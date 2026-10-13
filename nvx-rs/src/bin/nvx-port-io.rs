//! `nvx-port-io`; see `nvx::guest::port_io`.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    nvx::guest::port_io::main()
}

// The guest programs run only in Linux guests. Elsewhere this stub fails, so that every target
// that CI checks with `--all-features` still builds.
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
