# nvx-rs

`nvx-rs` is the Rust crate that holds the NVX mechanics: the OpenVMM
control protocol, and the launch, policy lowering, and supervision of NVX
microVMs. Its library is called `nvx`. The
[`aci_edge_sandboxes` crate](../aci_edge_sandboxes/README.md) builds on it and
re-exports it as `aci_edge_sandboxes::nvx`, and later phases of
[microsoft/nvx#356](https://github.com/microsoft/nvx/issues/356) add the guest
programs and a host CLI to it.

An NVX sandbox is a microVM that OpenVMM runs with the managed lifecycle: the
guest's init starts a managed agent, which runs the workloads that the host
sends it over an authenticated control console. The crate is not published to
a registry, and has a `Cargo.lock` of its own; a workspace at the repository
root would interact with the nested `openvmm/` workspace.

## Layout

```text
nvx-rs/
├── src/
│   ├── protocol/    NVXS records, NVXC frames, EXEC and MAPS payloads, guest features, and
│   │                kernel command-line tokens; no dependencies, shared by the host and the guest
│   ├── contract.rs  control-contract versions and release-manifest compatibility
│   ├── net/         CIDR parsing and subtraction, and hostname and guest-network forms
│   ├── hypervisor.rs
│   ├── error.rs     nvx::Error and its ErrorKind
│   ├── host/        feature `host` (default): artifacts, launch, network, filesystem, session,
│   │                process, platform, VM instances, and outcome reports
│   ├── testing/     feature `testing`: the fake OpenVMM
│   └── bin/         nvx-fake-openvmm
├── build.rs         bundled-release staging
└── artifacts.json   the NVX release that the `bundled` feature stages
```

| Module | Contents |
| --- | --- |
| `nvx::protocol` | The codec of the control console: `NVXS` outer records, `NVXC` application frames, the `EXEC` payload that the host encodes and the guest agent decodes, the `MAPS` payloads of the host mapping table, `GuestFeatures`, and the `nvx_maps=` and `nvx_workload_account=create` tokens. Golden byte fixtures pin every record independently of the codec, which the host and the fake OpenVMM share |
| `nvx::contract` | The OpenVMM microVM ABI, broker protocol, and control-contract revision that the crate speaks, and `manifest_is_compatible` for a release's `SOURCE-MANIFEST.json` |
| `nvx::net` | `Cidr`: IPv4 and IPv6 networks and their subtraction; `is_valid_hostname` and `is_valid_guest_network`, the forms of a VM's hostname and guest address |
| `nvx::Hypervisor` | KVM, MSHV, or WHP, with its serde form behind the `serde` feature |
| `nvx::host::artifacts` | `Artifacts` (also `nvx::Artifacts`): the OpenVMM executable, guest kernel, and Alpine initramfs, from a release, a repository checkout, the environment, a directory next to the executable, or the bundle |
| `nvx::host::launch` | `LaunchSpec` and OpenVMM's command line: the managed lifecycle, the `WorkloadIdentity`, the 1024-byte kernel command line, its reserved parameters, the 32,767-character limit of a Windows command line, and `LaunchSpec::check`, which every command line applies to the memory size, the non-root identity, the hostname, the guest network, and the kernel parameters |
| `nvx::host::activation` | Opt-in `ActivationInput`/`ActivationPlan`, direct-image or compatible-template inputs, caller authorization, exact runtime pins, typed filesystem-slot intent, opened-attachment receipts and a separately versioned runtime record block |
| `nvx::host::network` | Egress rules and their exact expansion into OpenVMM's IPv4 and IPv6 rules: exceptions, protocol-only rules, and port ranges, with at most 256 rules for each action |
| `nvx::host::filesystem` | The `ExportPlan` of host paths through OpenVMM's aggregate virtio-fs device, the host-mapping table, the reserved guest targets, and `guest_path` and `resolve_guest_path` (also at `nvx::`) |
| `nvx::host::instance` | `Instance`: a VM in a directory of its own. It starts OpenVMM with a fresh capability and waits until the guest is ready and has mounted the mapped paths, reconciles recorded state, recovers interrupted launches, runs workloads and pumps their output, and stops the VM with a forced fallback |
| `nvx::host::session`, `process`, `platform`, `report` | The authenticated control session, OpenVMM processes, Linux and Windows primitives, and OpenVMM's outcome report |
| `nvx::testing::fake_openvmm` | A fake OpenVMM that serves the control console and runs scripted workloads without a VM |

Lowering functions take the names by which messages refer to their inputs, such
as `EgressRules::name` and `PathList::name`, so callers' messages name their own
fields.

## Image-backed host foundation (opt-in)

`ActivationPlan::new` requires all five caller-owned protected roots
(runtime, state, cache, images and templates), explicit `Authorizer` decisions
for selected paths and proxy services, and pinned bundle, broker protocol,
machine ABI and guest ABI identities. It reuses `filesystem::ExportPlan` and
its parent-before-child `HostMap` table, and `network`'s existing rule/forward
lowering. `network::plan` adds optional HTTP(S) proxy-only enforcement and
matching `GuestProxySettings`; without a proxy, deny-all/no-network still
omits the NIC. The core does not start or authorize a proxy service.

Every `Exposure` declares `PathSemantics::LivePath` or `ObjectPinned`.
New-profile prestart bind identities follow those explicit semantics, rather
than silently pinning live mappings through legacy movable-object checks;
the existing movable-denied-path guards remain in force.
Protected-root checks use canonical paths and ancestor object identities in
both directions; exporting a protected parent with denied children is still
refused. Known runtime/media hard-link aliases are also refused. New profiles
reject read-only mappings whose host enforcement would rely solely on a
guest bind. Existing public profiles and format-3 instance/export records
keep their behavior and serialized form.

The VMM-facing API is `VmmAdapter::lower(&ActivationPlan) ->
AdapterArguments`, followed by `ActivationPlan::verify_receipt` on an
`AttachmentReceipt` received through the caller's authenticated
activation/Ready exchange. The request supplies stable image, scratch,
template, aggregate-child and mapped-object roles, access/path semantics,
media geometry, and the exact filesystem/network plan. `protected_roots` and
`protected_objects` expose the mandatory canonical/identity constraints to
the adapter, including internal runtime/media alias identities. Observations use
`HostObject::from_opened` on the VMM's actual opened handles, not expected
identities copied from the request. The VMM must retain pinned objects for
their attachment lifetime. A rejected receipt must terminate the verified
process; a rejected template never silently cold-boots.

Zero-export direct-image cold plans require `FilesystemSlot::Omit`; mapped
cold plans and all compatible templates require `Retain`. **No adapter for
the old VMM is provided.** The real filesystem-device opt-out is
[microsoft/nvx#547](https://github.com/microsoft/nvx/issues/547), and the real
opened-handle handoff/receipt and post-Ready pinning are
[microsoft/nvx#548](https://github.com/microsoft/nvx/issues/548).
`openvmm_arguments` requires an explicitly versioned adapter and checks its
boot/slot acknowledgement. Simulated options/receipts and a missing mount
argument are not evidence of device omission, pinning, guest readiness or
[microsoft/nvx#541](https://github.com/microsoft/nvx/issues/541) acceptance.
Template input compatibility here does not implement capture or restore.

For transport-neutral lifecycle mechanics, use `process::spawn`,
`Launched::claim_log`, and `instance::Supervisor`. A log claim verifies the
recorded PID/start time and the file objects held by the process's inherited
stdout/stderr handles; a marker or log pathname alone is not ownership.
`create_launch_log` refuses existing files instead of truncating them.
`Supervisor` reconciles without changing caller state, waits on Linux pidfd
or Windows process-handle exit events (with identity-checked Linux fallback
when unavailable), and accepts the caller's graceful-shutdown callback before
verified forced termination. Graceful errors remain available to the caller.

After admitting a receipt and claiming the log, `runtime_record` produces an
`ImageRuntimeRecord` format-1 block for the caller's own state codec.
`check_runtime_record` requires the original bundle/protocol/guest ABI,
activation and template identity, rather than guessing a protocol for an old
running VM. No registry, authorization policy, transport, storage layout,
runtime capability probe, or per-start/exec content hashing is added.

A consumer can remove its duplicated detached-spawn/handle-inheritance,
PID/start-time reconciliation, exit polling, log recovery, aggregate export/
HostMap construction, CIDR rule expansion and proxy endpoint lowering in
favor of these shared APIs. Request-to-policy conversion, application
framing, image registration, persistence, authorization and error translation
remain with that consumer. `tests/host_foundation.rs` exercises independent
JSON and NUL-framed test callers plus actual local process supervision; its
independent simulated VMM opens do not substitute for real VMM acceptance.

## Features

| Feature | Contents |
| --- | --- |
| `host` (default) | The `host` module. It enables `serde` |
| `bundled` | Stages a release at build time; see [Bundled artifacts](#bundled-artifacts) |
| `testing` | The fake OpenVMM and the `nvx-fake-openvmm` binary |
| `serde` | The serde form of `Hypervisor` |

Without default features, the crate has only `protocol`, `contract`, `net`,
`Hypervisor`, and `Error`, and depends on nothing but `serde` when `serde` is
enabled; `aci_edge_sandboxes_model` uses it that way.

## Example

```rust,no_run
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use nvx::host::instance::{self, Instance};
use nvx::host::launch::LaunchSpec;
use nvx::protocol::{Workload, WorkloadEnvironment};
use nvx::{Artifacts, Hypervisor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec = LaunchSpec::new(Artifacts::discover()?, Hypervisor::from_env_or_default()?);
    let directory = std::env::temp_dir().join("nvx-example");
    instance::create_private_dir(&directory)?;
    let instance = Instance::new(&directory, "example");
    let started = instance.start(&spec, Duration::from_secs(60))?;

    let workload = Workload {
        argv: vec!["/bin/echo".to_owned(), "hello".to_owned()],
        timeout_ms: 0,
        cwd: None,
        environment: WorkloadEnvironment::Default,
    };
    let timeout = Duration::from_secs(60);
    let capability = instance.read_capability()?;
    let execution = instance.exec(&started.runtime, &capability, &workload, timeout, timeout)?;
    let mut stdout = Vec::new();
    let outcome = execution.pump(
        &mut |chunk: &[u8]| {
            stdout.extend_from_slice(chunk);
            Ok(())
        },
        &mut |_: &[u8]| Ok(()),
        &AtomicBool::new(false),
    )?;
    println!("{outcome:?}: {}", String::from_utf8_lossy(&stdout));
    instance.stop(&started.runtime, Duration::from_secs(30))?;
    Ok(())
}
```

## Errors

Every fallible operation returns `nvx::Error`: a message that callers can show
as is, an `ErrorKind`, and an optional cause.

| `ErrorKind` | Meaning |
| --- | --- |
| `Unavailable` | A missing or unusable artifact, hypervisor, or release, a guest image without a required control feature, or an unsupported host |
| `Unsupported` | A well-formed request that NVX cannot represent or enforce, such as a policy beyond a limit of OpenVMM or the guest agent |
| `Exited` | The VM's OpenVMM process exited |
| `Io` | A host I/O failure, or state that NVX recorded on the host and cannot read |
| `Protocol` | A control session that failed, or a request that the guest agent refused |
| `TimedOut` | A deadline that passed |
| `Other` | Any other failure |

Messages call an instance `sandbox NAME`, after the name that `Instance::new`
gives it. `aci_edge_sandboxes` maps the kinds onto its error codes; see its
[error mapping](../aci_edge_sandboxes/README.md#error-mapping).

## Bundled artifacts

With the `bundled` feature, the build script stages the OpenVMM executable,
guest kernel, and Alpine initramfs of a release, with its
`SOURCE-MANIFEST.json` and `SHA256SUMS`, in its output directory, and
`Artifacts::bundled` returns them. `Artifacts::discover` uses the bundle when no
other source is present.

| Build variable | Effect |
| --- | --- |
| `NVX_BUNDLE_DIR` | Stages the extracted release in this directory, for offline builds or local artifacts |
| `NVX_BUNDLE_HYPERVISOR` | `kvm` (default) or `mshv`: the Linux package to download |
| `NVX_BUNDLE=skip` | Stages nothing, as when the feature is disabled; CI sets it for `--all-features` builds |

Without `NVX_BUNDLE_DIR`, the build script downloads the release package that
[`artifacts.json`](artifacts.json) pins with `curl` and extracts it with `tar`;
Windows packages are ZIP archives, which need bsdtar (Windows' own `tar`) or
`unzip`. Every staged file must match the source's `SHA256SUMS`, a download
must match its pinned digest, and the release must declare the control contract
of `nvx::contract`. The build scripts of dependents receive the staged
directory as `DEP_NVX_ARTIFACTS_DIR` and can ship it next to their executables
as `nvx/`.

## Testing

```bash
cd nvx-rs
NVX_BUNDLE=skip cargo test --all-features   # unit, golden-fixture, and fake-OpenVMM tests
```

The tests need no hypervisor. The fake-OpenVMM test drives `Instance` end to end
against `nvx-fake-openvmm`, and the protocol tests compare the wire constants
with the guest agent's source in `guest/common/nvx-managed-agent.c`. The
[`check-nvx-rs`](../.github/actions/check-nvx-rs/action.yml) action runs
rustfmt, Clippy with warnings denied for every feature and for the library
without default features, the tests, a synthetic-release `bundled` test,
rustdoc with warnings denied, the minimum supported Rust version (1.89), and a
macOS check. `python3 scripts/nvx.py test-aci-edge-sandboxes --backend kvm`
exercises the crate on a real hypervisor through `aci_edge_sandboxes`.
