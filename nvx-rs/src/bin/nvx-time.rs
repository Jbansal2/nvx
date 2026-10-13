//! `nvx-time`; see `nvx::guest::time`.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    nvx::guest::time::main()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
