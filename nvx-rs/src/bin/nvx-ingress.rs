//! `nvx-ingress`; see `nvx::guest::ingress`.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    nvx::guest::ingress::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
