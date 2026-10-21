# Runtime adapter

The runtime adapter is an independent adapter of the NVX runtime, with a host
program and a guest agent. It lives in this repository so that NVX's own CI
builds and runs it, and it depends on [`nvx`](../../nvx-rs/README.md) the way
an adapter outside the repository does:

- as a path dependency with default features off;
- with a `Cargo.lock` of its own, outside any other workspace;
- through the public API alone, with unsafe code forbidden;
- with the minimum supported Rust version of `nvx`.

The adapter brings its own application framing to the control session between
the host and the guest, in place of NVX's `NVXC` frames. Its host program sends
requests in that framing, and its guest agent serves them. The host program
also runs the guest agent in VMs of NVX's artifacts, in place of NVX's managed
agent, through NVX's supervisor, and finds a VM again after it restarts, as an
orchestrator does.

## Configurations

Each configuration enables one side of `nvx`:

| Configuration | Cargo options | `nvx` features | Modules | Binary |
| --- | --- | --- | --- | --- |
| Protocol-only | none | none | `frame` | none |
| Host-only | `--features host` | `host` | `frame`, `host`, `runtime`, `initramfs` | `runtime-adapter-host` |
| Guest-only | `--features guest --target x86_64-unknown-linux-musl` | `guest` | `frame`, `guest` | `runtime-adapter-guest`, a static executable |

## Framing

The `frame` module is the adapter's application framing, which its host program
and guest agent exchange over the control session in place of NVX's `NVXC`
frames. A message is a 5-byte header, then a body. The header holds the body's
length, a little-endian `u32`, then the message's kind:

| Kind | Message | Body |
| --- | --- | --- |
| 1 | `Ping`: asks the guest to answer with `Pong` | none |
| 2 | `Pong`: the guest's answer to `Ping` | none |
| 3 | `Echo`: bytes that the guest sends back in an `Echo` of its own | at most 256 KiB, what four of the session's largest records carry |
| 4 | `Stop`: asks the guest to stop serving | none |
| 5 | `Stopped`: the guest's confirmation of `Stop`, its last message | none |

The session keeps no message boundaries, so a message may span several of its
records, and one record may end a message and start the next. `Decoder`
reassembles the messages. It checks each header before it takes any byte of
the body, and holds at most one partial message. A malformed message ends the
stream, because the framing cannot find the next message after it.

## Guest agent

`guest::serve` serves the host program on a stream to the guest's end of the
control session, through `nvx::guest::nvxs`. It attaches, then:

- acknowledges each reset of the session with the smallest receive window that
  the session allows, once it dropped the earlier epoch's partial message,
  because a new epoch starts with a new message;
- credits each payload back once it holds the payload, so that a message
  longer than the window still arrives whole;
- answers each `Ping` with `Pong`, sends each `Echo` back, and answers `Stop`
  with `Stopped`, then returns.

A failure of the session, a malformed message, and a message that only the
guest sends end serving with an error.

`runtime-adapter-guest serve` runs the guest agent on its standard input and
output, which connect to the guest's end of the session, such as a control
console in raw mode. It exits with 0 once the host stopped it or the broker
closed the stream, and with 1, after a diagnostic on standard error, once
serving failed. Without arguments, it reports the contract that it was built
against.

`guest::serve_terminal` serves a tty, such as a VM's control tty, as `serve`
does. It opens the tty, waiting up to 30 seconds while the tty is not there
yet, and puts it in raw mode itself, as NVX's managed agent does, so that the
tty passes the session's bytes as they are. Once serving ends, it waits until
the tty has sent what serving wrote, such as the confirmation of a stop.

`runtime-adapter-guest init TTY` runs `serve_terminal` on the tty TTY in place
of NVX's managed agent, as a VM's PID 1; see [VMs](#vms). It ends with 0 once
the host stopped it, and with 1, after a diagnostic on standard error, once
serving failed or the broker closed the tty. As PID 1, which must not exit, it
ends the VM with that status instead, through NVX's `/sbin/nvx-exit`, as the
managed agent does.

## Host program

`host::Client` is the host program's client of the guest agent. It runs over
the host's end of the control session, through `nvx::host::nvxs`, on any
transport to the session's host endpoint, such as the one that
`nvx::host::session::connect` opens to a VM's control endpoint:

- `Client::attach` attaches with the VM's launch capability, waits while the
  broker waits for the guest, and reports the identity of the session's epoch
  that the broker attached it to;
- `send` sends a message in as many of the session's records as it takes, and
  `receive` returns the guest agent's next message, whether it spans records
  or shares one with the next message;
- `ping`, `echo` and `stop` each send a request and check its answer: `Pong`,
  an `Echo` of the same bytes, and `Stopped`.

Besides the session's own buffers, the client holds at most the rest of one of
the guest's records and one partial message. A reset of the session ends the
attachment, and its partial message with it, because the next epoch starts
with a new message, in a new attachment.

A failure of the session, a send that fails or times out, a malformed message,
and a message that only the host program sends end the client, and its later
calls fail. A receive that times out doesn't: it keeps what arrived. A request
ends the client on any failure after the framing accepted it, a timeout
included, because an answer that arrived later would answer the wrong request.

## VMs

The host program runs the guest agent in VMs of NVX's artifacts, through NVX's
supervisor, `nvx::host::supervisor`, each in a sandbox store of
`nvx::host::store`.

### The guest agent in place of the managed agent

NVX's initramfs hands a VM of the managed lifecycle to NVX's managed agent: its
`/init` runs
`exec /sbin/nvx-managed-agent /dev/hvc2 - nvx-managed UID GID NAME HOME` as
PID 1. `initramfs::write` copies that initramfs, and appends to the copy a
second archive, in the `newc` format, which Linux unpacks over the first:

- the guest agent, at `/sbin/runtime-adapter-guest`;
- a script, `/sbin/runtime-adapter-init`, that runs
  `runtime-adapter-guest init "$1"`, with the control tty, the first of the
  arguments that `/init` passes the managed agent;
- a symbolic link from `/sbin/nvx-managed-agent` to the script. Linux removes a
  file whose type an archive changes before it creates the new one, so the
  link replaces the managed agent without writing to its file, which could
  have other names.

The second archive starts at a multiple of 4 bytes, as Linux requires of an
uncompressed archive, after zeros that Linux skips. NVX's own images don't
change.

### The runtime identity

The supervisor records the runtime identity of each launch, and its reattach
compares the recorded identity with the caller's. `runtime::Runtime::from_dir`
takes NVX's artifacts from a repository checkout or an extracted release, with
`nvx::host::artifacts::Artifacts::from_dir`, and their identities from the
build provenance that `nvx.py` records beside them, never from their contents:
the SHA-256 digest of each artifact, from when it was built. A checkout keeps
the provenance in `build/`, where `nvx.py download` also installs a release's,
and a release keeps it in `provenance/`:

| Artifact | Provenance | Digest |
| --- | --- | --- |
| OpenVMM | `openvmm.provenance.json` | `executable_sha256` |
| Kernel | `vmlinux.provenance.json` | `kernel_sha256` |
| Initramfs | `initramfs.provenance.json` | `initramfs_sha256` |

The VMs boot a copy of NVX's initramfs with the guest agent in it, so the
identity of their initramfs names both:
`sha256:DIGEST+runtime-adapter-guest/BUILD`. The guest agent has no provenance
of its own, so the caller names its build, BUILD, which is the crate's version
unless the caller names another. A host program that ships another build of the
guest agent runs another runtime, and finds a VM of this one mismatched.

### Commands

`runtime-adapter-host` takes NVX's artifacts from the directory that
`NVX_ARTIFACTS_DIR` names. Each command takes the guest agent's build from
`--guest-build BUILD`, the crate's version by default:

- `launch STORE --guest-agent PATH [--hypervisor NAME]` launches a VM in the
  sandbox store STORE, which it creates if needed, with the guest agent PATH, a
  static `x86_64-unknown-linux-musl` build of `runtime-adapter-guest`, on the
  hypervisor NAME, or else on the one that
  `nvx::Hypervisor::from_env_or_default` selects. Once the launch has checked
  that no VM of the sandbox runs, it writes the VM's initramfs into the store.
  It connects to the VM's control endpoint with `nvx::host::session::connect`,
  attaches with the launch's capability, exchanges a `Ping` and the longest
  `Echo` with the guest agent, commits the launch, and exits, leaving the VM
  running. A launch that fails ends its VM.
- `reattach STORE` takes the sandbox's lock, and reattaches to its VM, which
  another process launched, and which it holds, although the VM is not its
  child, through its verified process identity. It reads the capability from
  the store, attaches a new session, in the session's next epoch, exchanges a
  `Ping`, and exits, leaving the VM running.
- `stop STORE` reattaches and attaches as `reattach` does, then stops the VM:
  the adapter's `Stop`, which the guest agent confirms with `Stopped` before it
  ends the VM, is the stop's graceful step. It waits for the VM to exit, and
  checks the VM's outcome report: a success, with status 0 and a complete
  teardown. A VM whose guest agent does not confirm the stop is terminated, and
  the stop fails.

`reattach` and `stop` find a VM that another runtime identity launched
mismatched, and then signal nothing: the VM keeps running. The commands print
what they find as `KEY=VALUE` lines: `reattached` (`live`, `mismatched`,
`exited`, or `indeterminate`), `differences` (the parts of the runtime identity
in which a mismatched VM differs), `pid` (the VMM's process ID), `instance` and
`epoch` (the identity of the session that they attached to), `stopped`
(`graceful`, `forced`, or `timed-out`), `outcome` (such as `success 0`), and
`teardown` (`complete` or `incomplete`). They exit with 0 once they did what
they were asked, with 3 when they find the VM mismatched, and with 1, after a
diagnostic on standard error, when they fail. Without arguments, the program
reports the contract that it was built against.

## Tests

`tests/independent_build.rs` checks that every configuration builds as an
independent adapter's does:

- The adapter is a workspace of its own with its own lockfile, and declares
  the minimum supported Rust version of `nvx`.
- The protocol-only build depends on `nvx` alone, without features. The
  host-only build enables the host side of `nvx` and not its guest side. The
  guest-only build enables only the guest side, and pulls in neither Tokio nor
  a dependency that only the host side of `nvx` declares. The tests read
  these dependency trees from `cargo tree`, which downloads the packages of the
  musl target the first time, on Windows too.
- Each binary runs and reports the contract that it was built against, and the
  guest binary is a static executable: it has no program interpreter, needs no
  shared library, and keeps its stack non-executable.

The unit tests of `frame` run in every configuration. They cover each kind's
encoding, messages in pieces of any size and split at every byte, and the
headers that the framing refuses before their body arrives.

`tests/guest_session.rs` checks, in the guest-only configuration, that the
guest agent serves the control session with the adapter's own framing. A test
broker plays the broker's end of the guest's session over a Unix socket pair
with the public record API of `nvx`, for `guest::serve` and for
`runtime-adapter-guest serve`. It covers messages that span records both ways
and fill the receive window, a record whose bytes arrive one at a time, resets
in the middle of a message, with the next epoch of the instance and with a new
instance, streams that end at and inside a record, and the records and
messages that the guest agent refuses: sequence, epoch, and instance errors,
stale and identity-less resets, record lengths, bootstrap identity, ERROR
payloads, and malformed headers.

`tests/host_session.rs` checks, in the host-only configuration, that the host
program's client attaches to the control session and exchanges the adapter's
own framing with the guest agent. A test broker plays the broker's host-facing
end of the session, and the guest agent behind it, with the public record API
of `nvx`, over an in-memory transport, so that the tests run on Linux and
Windows. They cover:

- the attachment: its bootstrap record with the launch capability, waits for
  the guest, a deadline that passes meanwhile, and refusals, with an ERROR or
  by the end of the stream;
- messages that span records both ways, records that end a message and start
  the next, and records whose bytes arrive in pieces down to one byte;
- a receive that times out inside a message, then returns the whole message;
- a send that times out after it wrote part of a record, and a send whose
  transport fails, each of which ends the client with the message that it
  held;
- resets and disconnects in the middle of a message, with the next epoch of
  the instance and with a new instance, and streams that end inside a record;
- the records that the client refuses: sequence, epoch, and instance errors,
  stale and identity-less resets, record lengths, bootstrap identity, ERROR
  payloads, a payload beyond the session's limit, which fails at its header,
  and header faults;
- the messages that it refuses: malformed headers, which fail before their
  body arrives, and messages that only the host program sends; and a message
  beyond the framing's limit, which it refuses to send;
- the answers that its requests check, and a request whose answer arrives too
  late.

Through a relay between its test broker and a pseudo-terminal,
`tests/guest_session.rs` also checks that `guest::serve_terminal` and
`runtime-adapter-guest init` serve a tty in raw mode, with an `Echo` of every
byte value, and that `init` fails at once on a path that is no tty.

`tests/initramfs.rs` and `tests/runtime.rs` check, in the host-only
configuration, on Linux and Windows:

- the archive that puts the guest agent in place of the managed agent: its
  entries, their owners and modes, and the padding of its headers and data,
  for guest agents of every length modulo 4;
- the copy of NVX's initramfs, which stays as it is, of every length modulo 4,
  with the archive after it at a multiple of 4 bytes, and the files that a
  failure names;
- the runtime identity from the build provenance of a checkout and of a
  release, another build of the guest agent, which differs in the initramfs
  alone, and the provenance that fails: missing, not JSON, in another format,
  or without a valid digest.

`tests/vm_restart.rs` checks the restart of an orchestrator, on a real
hypervisor, in the host-only configuration:

- `runtime-adapter-host launch` launches a VM, and exits;
- another process's `reattach` holds the VM, which is not its child, and
  attaches a new session, in a later epoch of the same broker instance;
- a third process's `stop` stops the VM: gracefully, with a successful outcome,
  and with no runtime record left.

In another test, a host program that ships another build of the guest agent
finds the VM mismatched in its initramfs, and signals nothing: the VM runs on,
under the same runtime record, until the host program of the right runtime
stops it. A test that fails ends the VM that it left running, and keeps the
sandbox's directory, whose path it prints, unless it can confirm that the VM
ended. The tests boot VMs, so they are ignored. They read the hypervisor from
`NVX_HYPERVISOR`, through `nvx::Hypervisor::from_env_or_default`, NVX's
artifacts, with their provenance, from `NVX_ARTIFACTS_DIR`, and the guest agent
from `RUNTIME_ADAPTER_GUEST`. In a checkout where
`python3 scripts/nvx.py download` installed NVX's artifacts, run them in this
directory with:

```bash
cargo build --locked --release --features guest \
  --target x86_64-unknown-linux-musl --bin runtime-adapter-guest
NVX_HYPERVISOR=kvm NVX_ARTIFACTS_DIR="$(cd ../.. && pwd)" \
  RUNTIME_ADAPTER_GUEST="$PWD/target/x86_64-unknown-linux-musl/release/runtime-adapter-guest" \
  cargo test --locked --features host -- --ignored
```

On Windows, take the guest agent from a Linux build.

Run the checks of each configuration in this directory. The guest-only
configuration needs Linux and the musl target, which
`rustup target add x86_64-unknown-linux-musl` installs:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --all-targets --features host -- -D warnings
cargo test --locked --features host
cargo clippy --locked --all-targets --features guest \
  --target x86_64-unknown-linux-musl -- -D warnings
cargo test --locked --features guest --target x86_64-unknown-linux-musl
```

## CI

The [`check-nvx-rs`](../../.github/actions/check-nvx-rs/action.yml) action
runs these checks with `cargo build`, and `cargo check` with the minimum
supported Rust version, on Linux and Windows, where it skips the guest-only
configuration. A change to the adapter is a test input of CI's
[change classification](../../doc/ci.md#change-classification), so it runs the
NVX microVM tests. Their
[workflow](../../.github/workflows/run-nvx-microvm-tests.yml) builds the
host-only configuration on each backend and runs its ignored tests, the
adapter's VM scenarios, with `NVX_HYPERVISOR` naming the backend,
`NVX_ARTIFACTS_DIR` the checkout, into which the job downloaded NVX's artifacts
and their provenance, and `RUNTIME_ADAPTER_GUEST` the guest agent. The Linux
jobs build the guest agent first, and the Windows jobs take the one that CI's
shared artifacts job builds on Linux.
