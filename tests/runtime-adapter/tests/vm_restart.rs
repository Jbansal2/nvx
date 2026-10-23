//! The host program launches a VM of the guest agent through NVX's supervisor, and later processes
//! of it reattach to the VM and stop it, as an orchestrator does after it restarts, on a real
//! hypervisor, through public APIs only.
//!
//! The tests boot VMs, so they are ignored. They read what the `common` module lists.
//!
//! ```text
//! cargo test --locked --features host -- --ignored
//! ```
#![cfg(feature = "host")]

mod common;

use std::ffi::OsStr;

use nvx::host::process::Process;

use common::{Printed, Sandbox, epoch};

/// Checks that a command stopped the VM of `vmm` that `launched` printed, with the guest agent's
/// confirmation, after it attached a session in an epoch after `earlier`'s: the VM exited with
/// a successful outcome, and no runtime record names it.
fn assert_stopped(
    sandbox: &Sandbox,
    stopped: &Printed,
    launched: &Printed,
    earlier: &Printed,
    vmm: &Process,
) {
    assert_eq!(stopped["reattached"], "live");
    assert_eq!(stopped["pid"], launched["pid"]);
    assert_eq!(stopped["instance"], launched["instance"]);
    assert!(epoch(stopped) > epoch(earlier), "{stopped:?} {earlier:?}");
    assert_eq!(stopped["stopped"], "graceful");
    assert_eq!(stopped["outcome"], "success 0");
    assert_eq!(stopped["teardown"], "complete");
    assert!(vmm.has_exited().unwrap());
    assert_eq!(
        sandbox.record(),
        None,
        "the stop cleared the runtime record"
    );
}

#[test]
#[ignore = "boots a VM; see the module documentation for what it needs"]
fn a_restarted_host_program_reattaches_to_the_vm_and_stops_it() {
    let mut sandbox = Sandbox::new("restart");
    // The launching process has exited, and the VM runs on.
    let launched = sandbox.launch(&[], 0);
    let vmm = sandbox
        .vmm()
        .expect("the VM runs after its launcher exited");

    // Another process holds the VM, which is not its child, and attaches a new session, in the
    // session's next epoch.
    let reattached = sandbox.run("reattach", &[], 0);
    assert_eq!(reattached["reattached"], "live");
    assert_eq!(reattached["pid"], launched["pid"]);
    assert_eq!(reattached["instance"], launched["instance"]);
    assert!(epoch(&reattached) > epoch(&launched), "{reattached:?}");
    assert!(!vmm.has_exited().unwrap());

    // A third one stops it.
    let stopped = sandbox.run("stop", &[], 0);
    assert_stopped(&sandbox, &stopped, &launched, &reattached, &vmm);
}

#[test]
#[ignore = "boots a VM; see the module documentation for what it needs"]
fn a_host_program_of_another_runtime_finds_the_vm_mismatched_and_signals_nothing() {
    let mut sandbox = Sandbox::new("identity");
    let launched = sandbox.launch(&[], 0);
    let record = sandbox.record();
    let vmm = sandbox
        .vmm()
        .expect("the VM runs after its launcher exited");

    // A host program that ships another build of the guest agent runs another runtime.
    let options = [OsStr::new("--guest-build"), OsStr::new("another-build")];
    let mismatched = sandbox.run("reattach", &options, 3);
    assert_eq!(mismatched["reattached"], "mismatched");
    assert_eq!(mismatched["differences"], "initramfs");
    assert_eq!(mismatched["pid"], launched["pid"]);
    assert!(!mismatched.contains_key("epoch"), "{mismatched:?}");

    // It signaled nothing: the VM runs on, under the same runtime record, and its guest agent
    // serves the host program of the right runtime, which stops it.
    assert!(!vmm.has_exited().unwrap());
    assert_eq!(sandbox.record(), record);
    let stopped = sandbox.run("stop", &[], 0);
    assert_stopped(&sandbox, &stopped, &launched, &launched, &vmm);
}
