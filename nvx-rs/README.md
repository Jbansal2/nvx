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
│   ├── guest/       feature `guest`: the programs that run in Linux guests; freestanding/
│   │                holds the `core`-only logic of nvx-exit and nvx-device-io
│   └── bin/         nvx-fake-openvmm and the guest binaries
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
| `nvx::host::network` | Egress rules and their exact expansion into OpenVMM's IPv4 and IPv6 rules: exceptions, protocol-only rules, and port ranges, with at most 256 rules for each action |
| `nvx::host::filesystem` | The `ExportPlan` of host paths through OpenVMM's aggregate virtio-fs device, the host-mapping table, the reserved guest targets, and `guest_path` and `resolve_guest_path` (also at `nvx::`) |
| `nvx::host::instance` | `Instance`: a VM in a directory of its own. It starts OpenVMM with a fresh capability and waits until the guest is ready and has mounted the mapped paths, reconciles recorded state, recovers interrupted launches, runs workloads and pumps their output, and stops the VM with a forced fallback |
| `nvx::host::session`, `process`, `platform`, `report` | The authenticated control session, OpenVMM processes, Linux and Windows primitives, and OpenVMM's outcome report |
| `nvx::testing::fake_openvmm` | A fake OpenVMM that serves the control console and runs scripted workloads without a VM |
| `nvx::guest` | The programs that run in Linux guests; see [Guest binaries](#guest-binaries) |

Lowering functions take the names by which messages refer to their inputs, such
as `EgressRules::name` and `PathList::name`, so callers' messages name their own
fields.

## Features

| Feature | Contents |
| --- | --- |
| `host` (default) | The `host` module. It enables `serde` |
| `bundled` | Stages a release at build time; see [Bundled artifacts](#bundled-artifacts) |
| `testing` | The fake OpenVMM and the `nvx-fake-openvmm` binary |
| `serde` | The serde form of `Hypervisor` |
| `guest` | The `guest` module and the guest binaries; see [Guest binaries](#guest-binaries) |

Without default features, the crate has only `protocol`, `contract`, `net`,
`Hypervisor`, and `Error`, and depends on nothing but `serde` when `serde` is
enabled and `libc` when `guest` is; `aci_edge_sandboxes_model` uses it that way.

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

## Guest binaries

The `guest` feature adds the programs that run in NVX's Linux guests: the
`nvx::guest` module and one binary per program. They replace the C programs in
[`guest/common/`](../guest/common), which the guests ship as `/sbin/nvx-*`
until their build switches to the Rust binaries
([microsoft/nvx#358](https://github.com/microsoft/nvx/issues/358)); until then,
CI only builds, lints, tests, and checks them.

| Binary | Program |
| --- | --- |
| `nvx-console-pending DEVICE` | Prints the number of bytes waiting to be read from a device, such as a console |
| `nvx-mmio-write ADDRESS VALUE` | Stores a 32-bit value at a physical address through `/dev/mem` (x86_64) |
| `nvx-port-io COMMAND ...` | Reads or writes an I/O port through `/dev/port`, or reads the VM generation ID |
| `nvx-reseed [--generation-only] SEED_FILE [PREVIOUS]`, `nvx-reseed --sample` | Reseeds the kernel's random number generator from a seed file and checks its VM generation ID, or prints a random sample |
| `nvx-exit [CODE]` | Stops the VM with an 8-bit exit code through OpenVMM's control port 0x604 (x86_64, freestanding) |
| `nvx-device-io file ...`, `nvx-device-io network ...` | The benchmark helper that measures file and UDP round-trip I/O and prints one JSON line (x86_64, freestanding) |

Each binary keeps the command line, exit statuses, and output of its C program
byte for byte. Error messages carry the C library's `strerror` text, never the
` (os error N)` suffix of Rust's `io::Error`. The programs restore the default
`SIGPIPE` disposition that Rust's runtime replaces, and handle a failed write to
standard output as C's stdio did: they report it on a terminal and ignore it
elsewhere, where stdio deferred it to `exit`.

Guests run static `x86_64-unknown-linux-musl` executables built with the
`guest` profile, which optimizes for size with fat LTO and one codegen unit,
aborts on panic, and strips symbols. The guest build enables only the `guest`
feature, so it pulls in neither the host code nor serde. It takes one `cargo
build` for the `std` binaries and one `cargo rustc` for each freestanding one:

```bash
cd nvx-rs
rustup target add x86_64-unknown-linux-musl
guest=(--locked --profile guest --target x86_64-unknown-linux-musl
  --no-default-features --features guest)
cargo build "${guest[@]}" --bin nvx-console-pending --bin nvx-mmio-write \
  --bin nvx-port-io --bin nvx-reseed
for bin in nvx-exit nvx-device-io; do
  cargo rustc "${guest[@]}" --bin "${bin}" -- \
    -C relocation-model=static -C link-self-contained=no \
    -C link-arg=-nostartfiles -C link-arg=-nostdlib -C link-arg=-static \
    -C link-arg=-no-pie -C link-arg=-Wl,--build-id=none \
    -C link-arg=-Wl,-z,noexecstack
done
```

The binaries land in `target/x86_64-unknown-linux-musl/guest/`, and the build
needs a C compiler driver, `cc`, as every musl build of Rust does. On other
operating systems, and on other architectures for the x86-specific programs,
each binary is a stub that exits with status 1, so that `--all-features` builds
still work on every host.

### Freestanding binaries

`nvx-exit` and `nvx-device-io` have neither `std` nor libc, as the C programs
had neither stdio nor, for `nvx-device-io`, a libc: `nvx-exit` is a restored
guest's usual first command, so every page that its startup touches costs time
after a restore, and `nvx-device-io` measures device I/O. Their `core`-only
logic lives in `src/guest/freestanding/`, which the binaries include by path,
so that the library's unit tests run it on every host. On x86_64 Linux:

- The `guest` profile's `panic = "abort"` makes them `no_std` and `no_main`,
  through `cfg(panic = "abort")`. Their own `_start` aligns the stack, passes
  `argc` and `argv` to the program, and calls `exit_group`; raw `syscall`
  instructions replace libc; a panic, which only a defect can cause, executes
  `ud2`; and assembly defines the `memcpy`, `memmove`, `memset`, `memcmp`,
  `bcmp`, and `strlen` to which LLVM may emit calls, such as `memcpy` for a
  copy loop. `compiler_builtins` exports those only on targets without a libc.
- Unwinding profiles cannot build a `no_std` executable on stable Rust, and
  `cargo test` always builds the binaries that integration tests run with
  unwinding. Those profiles build the same program behind `std`'s `main`, so
  the tests exercise its logic and system calls.

A plain `cargo build` of them with the `guest` profile fails, with a
`multiple definition of '_start'` from the C runtime start files: Rust's
self-contained musl linking always adds musl's `rcrt1.o` or `crt1.o`. Hence the
`cargo rustc` flags, which only a command line can apply to one binary: build
scripts can pass neither `-C link-self-contained` nor `-C relocation-model`, and
their link arguments would also reach the `std` form that tests build. The
flags link without the start files and libc, as the C program's `-nostdlib`
did, and make a static, non-PIE `ET_EXEC`, whose addresses need no relocation
at startup, without a build ID.

## Testing

```bash
cd nvx-rs
NVX_BUNDLE=skip cargo test --all-features   # unit, golden-fixture, and fake-OpenVMM tests
```

The tests need no hypervisor. The fake-OpenVMM test drives `Instance` end to end
against `nvx-fake-openvmm`, and the protocol tests compare the wire constants
with the guest agent's source in `guest/common/nvx-managed-agent.c`. On Linux,
`tests/guest_tools.rs` runs the guest binaries that Cargo builds for the tests,
or, when `NVX_GUEST_BINARIES` names a directory, the binaries there, such as the
freestanding `guest`-profile builds:

```bash
NVX_GUEST_BINARIES="${PWD}/target/x86_64-unknown-linux-musl/guest" \
  cargo test --locked --target x86_64-unknown-linux-musl \
  --no-default-features --features guest --test guest_tools
```

The tests that would reach the real `/dev/mem`, `/dev/port`, or a reseed of
`/dev/random` only check that an unprivileged user cannot, and skip as root.
The
[`check-nvx-rs`](../.github/actions/check-nvx-rs/action.yml) action runs
rustfmt, Clippy with warnings denied for every feature and for the library
without default features, the tests, a synthetic-release `bundled` test,
rustdoc with warnings denied, the minimum supported Rust version (1.89), and a
macOS check. `python3 scripts/nvx.py test-aci-edge-sandboxes --backend kvm`
exercises the crate on a real hypervisor through `aci_edge_sandboxes`.
