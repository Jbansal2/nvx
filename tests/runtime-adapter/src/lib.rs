//! An independent adapter of the NVX runtime, with a host program and a guest agent. NVX's CI
//! builds it against `nvx` the way an adapter outside the repository would: as a path dependency
//! with default features off, with a lockfile of its own, and through the public API alone.
//!
//! Each configuration enables one side of `nvx`:
//!
//! - protocol-only, without features: the control protocol, the contract versions, and the other
//!   items that `nvx` has without features, with the adapter's own [`frame`]s;
//! - host-only, with the `host` feature: the host API too, and the host program, in the `host`,
//!   `runtime`, and `initramfs` modules and the `runtime-adapter-host` binary;
//! - guest-only, with the `guest` feature: the guest API too, and the guest agent, in the `guest`
//!   module and the `runtime-adapter-guest` binary, a static `x86_64-unknown-linux-musl`
//!   executable.
//!
//! The adapter brings its own framing to the control session between the host and the guest, in
//! place of NVX's `NVXC` frames. The guest agent serves requests in that framing, and
//! `runtime-adapter-guest serve` runs it on its standard input and output. The host program's
//! client attaches to the session with the launch capability and sends those requests.
//!
//! The host program runs the guest agent in VMs of NVX's artifacts, in place of NVX's managed
//! agent, through NVX's supervisor: `runtime-adapter-host launch` starts a VM, and later
//! processes reattach to it and stop it with `runtime-adapter-host reattach` and `stop`, as an
//! orchestrator does after it restarts. The `runtime` module takes the VMs' runtime identity from
//! the build provenance of NVX's artifacts, and the `initramfs` module writes the initramfs that
//! puts the guest agent in place of the managed agent, where `runtime-adapter-guest init` serves
//! the VM's control tty.

pub mod frame;
#[cfg(all(feature = "guest", target_os = "linux"))]
pub mod guest;
#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "host")]
pub mod initramfs;
#[cfg(feature = "host")]
pub mod runtime;

/// Command that starts the guest agent on the runtime adapter's standard streams.
pub const GUEST_SERVE_COMMAND: &str = "serve";

/// Command that starts the guest agent on the tty that follows it, in place of NVX's managed agent.
pub const GUEST_INIT_COMMAND: &str = "init";

/// Describes the runtime contract that this build speaks: the control contract revision, and the
/// versions of the microVM ABI, the NVXS records, and the NVXC frames.
pub fn contract() -> String {
    format!(
        "control contract {} (microVM ABI {}, NVXS v{}, NVXC v{})",
        nvx::contract::CONTROL_CONTRACT_REVISION,
        nvx::contract::MICROVM_ABI_VERSION,
        nvx::protocol::OUTER_VERSION,
        nvx::protocol::APP_VERSION,
    )
}
