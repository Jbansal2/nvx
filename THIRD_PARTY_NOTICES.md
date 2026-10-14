# Third-party notices

This distribution combines independently licensed components. It is an
aggregate; the Linux kernel license does not change the license of OpenVMM or
the distribution tooling.

| Component | Location | License and source |
| --- | --- | --- |
| Linux 6.18.38 | Generated under `.cache/linux` | GPL-2.0-only; the upstream archive and patch series are pinned in `SOURCE-MANIFEST.json` and `kernel/patches`. Each build exports its exact config, and `collect-sources` emits the complete patched tree. |
| OpenVMM | `openvmm` | MIT; see `openvmm/LICENSE`. Source is a private Git submodule and is available only to authorized users. |
| NVX guest/build sources | `guest`, `nvx-rs`, `ubuntu`, `kernel`, `scripts/nvx_tools` | MIT; see `LICENSE`. |
| Rust core and standard libraries | `core` is linked into all ten Rust guest binaries; `std` is linked into the eight binaries listed in the musl row | MIT OR Apache-2.0; the exact release is pinned by `rust-toolchain.toml`. Source and license files are under [`rust-lang/rust/library`](https://github.com/rust-lang/rust/tree/master/library), with `LICENSE-MIT` and `LICENSE-APACHE` at the repository root. |
| Rust `compiler_builtins` | Rust target runtime routines used by the guest binaries | MIT OR Apache-2.0 for `rust-lang/compiler-builtins`; routines derived from LLVM compiler-rt are Apache-2.0 WITH LLVM-exception. Source is the revision bundled by the pinned Rust release under [`rust-lang/compiler-builtins`](https://github.com/rust-lang/compiler-builtins) and its [`llvm-project/compiler-rt`](https://github.com/llvm/llvm-project/tree/main/compiler-rt) sources. |
| Rust `libc` crate 0.2.189 | linked into the eight `std` guest binaries | MIT OR Apache-2.0; the exact crate checksum is pinned in `nvx-rs/Cargo.lock`, and source and license files are at [`rust-lang/libc` tag 0.2.189](https://github.com/rust-lang/libc/tree/0.2.189). |
| musl libc | statically linked into `/sbin/nvx-console-pending`, `/sbin/nvx-mmio-write`, `/sbin/nvx-port-io`, `/sbin/nvx-reseed`, `/sbin/nvx-managed-agent`, `/sbin/nvx-ingress`, `/sbin/nvx-time`, and `/sbin/nvx-time-probe` in every generated initramfs | MIT; Copyright © 2005-2020 Rich Felker, et al. The exact implementation is supplied by the pinned Rust release's `x86_64-unknown-linux-musl` target. Upstream source and the full copyright notice are at [musl libc](https://musl.libc.org/). |
| Alpine Linux packages | generated initramfs images | Per-package licenses. Every build emits `*.packages.json`; retain that manifest and collect the corresponding aports recipes and upstream sources before distributing an image. |
| Azure Linux 3.0 packages | generated Azure Linux initramfs | Per-package licenses, including GPLv2 BusyBox. The base image is digest-pinned in `SOURCE-MANIFEST.json`, every supplemental RPM is SHA-256 pinned in `azurelinux/packages.lock.json`, and every build emits `initramfs-azurelinux.cpio.gz.packages.json`. `collect-sources` does not collect this corresponding source yet, so `--include-source` packages omit the Azure Linux initramfs; publish the matching source before distributing a binary-only package that contains it. |
| Ubuntu Base 26.04.1 LTS and supplemental packages | generated Ubuntu initramfs and EROFS images | Per-package licenses. The base archive and every supplemental `.deb` are SHA-256 pinned. Retain the generated Ubuntu manifests and publish the matching `.dsc` plus all referenced source members before distributing an image. Ubuntu artifacts contain Ubuntu userland with the NVX kernel, not the Ubuntu kernel. |

The source manifest records pinned versions, commits, and the upstream Linux
archive digest. A binary release made with `scripts/nvx.py package
--include-source` includes separate project, patched Linux, Alpine, and Ubuntu
source archives and excludes the Azure Linux guest artifacts. OpenVMM source is
intentionally excluded; its MIT license notice is included in the binary
release.

Run `scripts/nvx.py collect-sources` before creating a source-inclusive
release. It saves the patched Linux source archive under `build/sources/linux`
and exact aports recipes plus `abuild verify`-checked upstream source files
under `build/sources/alpine`. Ubuntu source packages are stored under
`build/sources/ubuntu` with their verified source-index and `.dsc` metadata.
