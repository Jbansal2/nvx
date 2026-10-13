//! `nvx-managed-agent`; see `nvx::guest::agent`.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    nvx::guest::agent::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
