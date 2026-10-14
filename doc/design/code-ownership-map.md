# Component responsibility map

[Design index](../design.md)

This map assigns each design area to the architectural component responsible
for it. It is a navigation aid, not an implementation index: the components
own their internal structure, and the other design chapters define the
contracts between them.

| Area | Responsible component |
| --- | --- |
| Machine-profile selection, ABI constants, machine validation, and command-line ownership | OpenVMM machine-profile definitions shared by every launcher and the VM worker |
| CLI options, host-attachment construction, restore preparation, capture orchestration, portb output drain, and outcome reports | OpenVMM command-line entry layer and its VM controller |
| Management-RPC microVM creation, capture, restore, readiness, and guest-exit reporting | OpenVMM management-RPC service |
| Worker composition, fixed virtio placement, snapshot boundaries, management exclusion, clock contracts, and restore sequencing | OpenVMM VM worker |
| Restore-time VP materialization and saved-VP inventory validation | OpenVMM partition unit |
| Restore-time RAM capacity, range selection, split backing, and private copy-on-write mapping | Snapshot machine contract, OpenVMM memory-layout engine, and guest-memory manager |
| Linux direct MP-table loading | OpenVMM Linux direct loader and MP-table builder |
| Base-chipset allowlist and memory-layout defaults | OpenVMM base-chipset manifest builder |
| portb, shutdown, and snapshot PMIO; RTC, PIT, and IOAPIC save and restore | OpenVMM chipset devices |
| Virtio transport, shared interrupt status, and device-private saved state | OpenVMM virtio transport and device models |
| Control-session protocol, authenticated broker, and local peer identity | OpenVMM virtio-console broker and serial socket and named-pipe backends |
| Portable networking, egress policy, and endpoint quiesce | OpenVMM Consomme endpoint, egress policy, and virtio-net device |
| HostFs profile on the single virtio-fs slot: one host directory, or named directory or regular-file children under a read-only synthetic root; per-child access modes, directory-only denied, allowed, and writable paths, file exports that exclude their parent directories, and filesystem saved state | [OpenVMM microVM virtio-fs profile](../../openvmm/vm/devices/virtio/virtiofs/src/microvm/) and [virtio-fs aggregate](../../openvmm/vm/devices/virtio/virtiofs/src/aggregate.rs) |
| State-unit quiesce, start, rollback, inventory, and downtime advance | OpenVMM state-unit framework |
| Snapshot format, machine contract, publication, and artifact validation | OpenVMM snapshot helpers and platform file primitives |
| Backend CPU contracts and snapshot clocks | KVM, MSHV, and WHP backends |
| Guest-visible CPU profiles: the pinned catalog, `--cpu-profile` selection, host profiles and the `auto` fallback, backend support and restore checks, and CPU fingerprints | OpenVMM CPU-profile catalog, with the shared time-ABI layer that builds each VM's effective CPUID |
| Layered sandbox launch and kernel features | NVX sandbox launcher and microVM kernel configuration |
| Managed `sandbox` lifecycle of the NVX CLI: per-sandbox state, fail-closed provision, start, stop, and deprovision transitions that take effect one at a time per sandbox while `exec` runs beside them, the control capability that each start generates and hands to OpenVMM, and identification of the running OpenVMM process | NVX managed sandbox lifecycle and its control-session client |
| Host shares of `run` and `sandbox`: one directory attached directly, or an aggregate for multiple shares or a single regular file; pre-launch checks and the `nvx_share=` tokens that place each child in the guest | [NVX launcher](../../scripts/nvx_tools/sandbox.py) |
| Structured egress-policy files and their translation to OpenVMM egress rules | NVX launcher's egress-policy compiler |
| Edge sandbox lifecycle API, request validation, backend capabilities, and the serializable contract model | NVX `aci_edge_sandboxes` crate and its data-model crate |
| Host side of the control protocol, artifact discovery, blockless managed launch, VM-instance supervision (OpenVMM process reconciliation, interrupted-launch recovery, readiness, the exec pump, and stop), host-path export as aggregate children and their access policy, delivery of the host-mapping table, egress-rule translation, and the fake OpenVMM | [`nvx-rs`](../../nvx-rs/README.md) crate, library `nvx` |
| Durable sandbox records, conversion of contract requests into `nvx` calls, and the mapping of `nvx` errors onto contract error codes | `aci_edge_sandboxes` default OpenVMM backend |
| Image-backed edge sandboxes | `aci_edge_sandboxes` optional agent backend, which delegates to a separately supplied native library |
| Workload namespace and root construction | NVX guest container launch and entry helpers |
| Live share mounts and the bind of each aggregate child at its target | NVX guest init, host-mount helper, and init agent |
| Guest workload and scratch quiesce | NVX guest init-agent and snapshot scripts |
| Post-restore CPU/RAM repair and restore entropy | `nvx-rs` guest binaries `nvx-time` and `nvx-reseed` |
| Guest time-ABI obligations: conformance checks, violation watcher, wall-clock discipline, and snapshot time steps | `nvx-rs` `nvx-time` and `nvx-time-probe` modules |
| Blockless managed workloads, host-mapping table checks and binds, and workload account creation | NVX guest init and the `nvx-rs` managed agent |
| Static guest-binary build, source identity, executable checks, and installation into every guest image | `nvx-rs` guest profile and `scripts/nvx_tools/guest_binaries.py` |
| Host qualification for the time ABI | NVX host doctor, a subset of which CI's runner validation runs |
| OpenVMM control-plane and guest-artifact integration tests | OpenVMM microVM and management-RPC VMM tests |
| NVX Linux and device integration tests | NVX microVM process tests and guest test scripts |
| Edge sandbox contract, fake-OpenVMM, and real-hypervisor lifecycle tests | `aci_edge_sandboxes` crate tests |
| Control-protocol golden fixtures, guest-binary tests, NVX mechanics unit tests, and fake-OpenVMM instance tests | `nvx-rs` crate tests |
| Copilot adversarial controller and typed broker | NVX adversarial controller and broker |
| Credential-free adversarial executor and independent oracles | NVX adversarial executor and oracle watchdog |
