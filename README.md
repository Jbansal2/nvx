# NVX: An Ultra-Light Micro-VM Sandbox

NVX is an ultra-light micro-VM sandbox for running untrusted workloads with hardware-enforced
isolation. It is built on top of OpenVMM and runs Linux as a guest.

NVX was jointly developed by the [MSR Systems Research Group][msr-systems] and
[Azure Research - Systems][azure-systems], building on research results from the
[Nanvix](https://github.com/nanvix) system.

[msr-systems]: https://www.microsoft.com/en-us/research/group/systems-research-group-redmond/
[azure-systems]: https://www.microsoft.com/en-us/research/group/azure-research-systems/

This repository includes version pins for Linux, OpenVMM, and the Rust guest
toolchain, along with the patches, guest source files, build tools, and
benchmarks needed to use NVX. Alpine, Ubuntu, and Azure Linux ship the nine
static guest binaries from [`nvx-rs`](nvx-rs/README.md#guest-binaries) at
their common `/sbin/nvx-*` paths.

## Quick Start

Python 3.10 or newer and Git are required. The commands below download the prebuilt NVX package
for the selected platform from the cloned revision's release when available, or from its nearest
released first-parent ancestor otherwise, so the guest and OpenVMM need no build.

NVX runs its microVMs with [`nvx-rs`](doc/usage.md#nvx-rs), the Rust command-line interface at
`nvx-rs/target/release/nvx-rs`, which `download` installs only from a release built from the
checkout's `nvx-rs` sources. Otherwise, the commands below build it with Cargo, so install Rust
with [rustup](https://rustup.rs/). A clone of the latest `dev` often needs this build, because
`nvx-rs` may have changed since its nearest release. To run without Rust, check out the tag of a
[development release](https://github.com/microsoft/nvx/releases) before `download`.

A successful boot prints `NVX-GUEST-BOOT-OK: alpine` and opens a root shell. The package also
includes the Ubuntu and Azure Linux userlands: boot either with the same NVX kernel by adding
`--guest ubuntu` or `--guest azurelinux` to `nvx-rs run`. Exit cleanly from the guest with
`/sbin/nvx-exit 0`. See the [setup](doc/setup.md) and [run](doc/run.md) guides for detailed
prerequisites and runtime options. To build NVX from source instead, first
[initialize](doc/setup.md#initialize) the `openvmm` submodule, which the clone below omits.

> ℹ️ For direct OpenVMM integration without `nvx-rs`, see
[Run OpenVMM directly](doc/run.md#run-openvmm-directly).

### Linux / KVM

Requires [KVM configured with read/write access to `/dev/kvm`](doc/setup.md#linux--kvm).

```bash
git clone https://github.com/microsoft/nvx.git && cd nvx
python3 scripts/nvx.py download
test -x nvx-rs/target/release/nvx-rs ||
  cargo build --release --locked --features cli \
    --manifest-path nvx-rs/Cargo.toml --target-dir nvx-rs/target
nvx-rs/target/release/nvx-rs run
```

### Linux / MSHV

Requires [MSHV configured with read/write access to `/dev/mshv`](doc/setup.md#linux--mshv).

```bash
git clone https://github.com/microsoft/nvx.git && cd nvx
python3 scripts/nvx.py download --hypervisor mshv
test -x nvx-rs/target/release/nvx-rs ||
  cargo build --release --locked --features cli \
    --manifest-path nvx-rs/Cargo.toml --target-dir nvx-rs/target
nvx-rs/target/release/nvx-rs run --hypervisor mshv
```

### Windows / WHP

Requires [Windows Hypervisor Platform enabled](doc/setup.md#windows--whp).

```powershell
git clone https://github.com/microsoft/nvx.git; Set-Location nvx
python scripts\nvx.py download
if (-not (Test-Path nvx-rs\target\release\nvx-rs.exe)) {
    cargo build --release --locked --features cli `
        --manifest-path nvx-rs/Cargo.toml --target-dir nvx-rs/target
}
nvx-rs\target\release\nvx-rs.exe run
```

## Documentation

### Usage

- [Setup](doc/setup.md) - Instructions for setting up your environment.
- [Build](doc/build.md) - Instructions for building NVX.
- [Run](doc/run.md) - Instructions for running NVX.
- [Benchmark](doc/benchmarks.md) - Instructions for benchmarking NVX.
- [Command-line reference](doc/usage.md) - Complete `nvx-rs` and `scripts/nvx.py` command and option
  reference.
- [Rust API](aci_edge_sandboxes/README.md) - The `aci_edge_sandboxes` crate for driving the sandbox
  lifecycle from Rust.
- [NVX Rust crate](nvx-rs/README.md) - The `nvx` crate that holds the NVX mechanics: the OpenVMM
  control protocol and the launch, policy lowering, and supervision of NVX microVMs.

### Development

- [Design](doc/design/README.md) - Architecture of the NVX microVM and its single-workload guest
  runtime.
- [Ubuntu guest support](doc/guests/ubuntu-guest.md) - How NVX runs Ubuntu userland on its own
  kernel.
- [Azure Linux guest support](doc/guests/azurelinux-guest.md) - How NVX runs Azure Linux userland
  on its own kernel.
- [Project structure](doc/project-structure.md) - Overview of the NVX repository layout.
- [Continuous integration](doc/ci.md) - Instructions for running and maintaining NVX CI.
- [Copilot-driven adversarial testing](doc/adversarial-testing.md) - Bounded adaptive stress and
  containment campaigns.
- [Package and source delivery](doc/distribution.md) - Instructions for packaging and distributing
  NVX.
- [Contributing](doc/contribute.md) - Guidelines for contributing to NVX.
- [OpenVMM upstream roadmap](doc/openvmm-upstream-roadmap.md) - Plan for upstreaming the OpenVMM
  fork's microVM commits.
