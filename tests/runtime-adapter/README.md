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
also runs the guest agent in VMs of NVX's artifacts, in place of NVX's agents,
through NVX's supervisor, and finds a VM again after it restarts, as an
orchestrator does.

A VM may have a layered root: an image under an upper, which the guest agent's
worker assembles through `nvx::guest::root`, in a process of its own rather
than PID 1, as the host program's root configuration asks. The host program
then checks the root from inside the VM with the worker's probes, in a
[table of scenarios](#layered-scenarios), to which each new check adds a row.

## Configurations

Each configuration enables one side of `nvx`:

| Configuration | Cargo options | `nvx` features | Modules | Binary |
| --- | --- | --- | --- | --- |
| Protocol-only | none | none | `frame`, `root`, `probe` | none |
| Host-only | `--features host` | `host` | `frame`, `root`, `probe`, `host`, `runtime`, `initramfs`, `layered` | `runtime-adapter-host` |
| Guest-only | `--features guest --target x86_64-unknown-linux-musl` | `guest` | `frame`, `root`, `probe`, `guest`, `worker` | `runtime-adapter-guest`, a static executable |

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
| 6 | `RootConfig`: the host's [root configuration](#root-configurations) of a layered root, which the guest answers with `RootReady` or `RootFailed` | the configuration, at most 4 KiB |
| 7 | `RootReady`: the guest assembled the root | none |
| 8 | `RootFailed`: a stage of the root failed: the guest's answer to `RootConfig`, or its report of a failed teardown before it confirms a `Stop` | the stage, then the problem, at most 4 KiB |
| 9 | `Probe`: asks the guest to run a [probe](#probes) on its root | the probe, at most 4 KiB |
| 10 | `Report`: the guest's answer to `Probe`: the facts that the probe found | at most 256 KiB |
| 11 | `ProbeFailed`: the guest's answer to a `Probe` that it does not know, or that failed | the problem, at most 4 KiB |

The session keeps no message boundaries, so a message may span several of its
records, and one record may end a message and start the next. `Decoder`
reassembles the messages. It checks each header before it takes any byte of
the body, and holds at most one partial message. A malformed message ends the
stream, because the framing cannot find the next message after it.

The framing carries each body as bytes, within its kind's limit. The bodies of
kinds 6 and 8 to 11 have encodings of their own, which the `root` and `probe`
modules write and read. A body that does not decode leaves the stream intact,
at the start of the next message. The guest answers a root configuration that
does not decode with `RootFailed`, as a configuration that it refuses, and a
probe with `ProbeFailed`. The host program's client ends on an answer that does
not decode, since it cannot tell what the guest did.

### Root configurations

The boot tokens of `nvx::protocol::root` carry what NVX's boot contract
defines: the image's format, the identity that the guest expects of it, and
the upper. A root configuration, `root::RootConfig`, carries the rest that the
root needs, which only the adapter defines, once the host attaches. It is
UTF-8 text: one `NAME=VALUE` line per field, each ended by a newline, in any
order, and each at most once. Numbers are decimal, without a sign or leading
zeros:

| Name | Value | Required |
| --- | --- | --- |
| `version` | 1 | yes |
| `runtime` | The runtime directory, below which the guest assembles the root | yes |
| `agent-cgroup` | The agent's cgroup, which holds the guest's own processes | yes |
| `workload-cgroup` | The workload cgroup, the agent's sibling | yes |
| `device-timeout-ms` | How long the guest waits for each block device, at most 600,000 | yes |
| `agent-memory-low` | The agent's `memory.low`, in bytes | no |
| `workload-memory-max` | The workload cgroup's `memory.max`, in bytes | no |
| `workload-pids-max` | The workload cgroup's `pids.max` | no |
| `distro-sectors` | The size of the image's block device, in 512-byte sectors | no |
| `scratch-sectors` | The size of the scratch block device, in 512-byte sectors | no |

The paths are absolute and canonical guest paths of at most 4,095 bytes,
without a NUL or a newline: not `/`, and without an empty, `.`, or `..`
component, or a trailing `/`. The runtime directory holds no `,`, `:`, `\`, or
`=`, which the overlay's options reserve, and the two cgroups are siblings,
whose parent is not `/`. The optional numbers are positive. The host program
and the guest agent ship together, so the guest refuses every other
configuration, one with an unknown field included, rather than ignore what it
does not know. `RootConfig::default()` holds the values that the host program
sends unless its caller names others: the runtime directory
`/run/runtime-adapter`, the cgroups `/sys/fs/cgroup/agent` and
`/sys/fs/cgroup/workload`, a wait of 30 seconds, an agent's `memory.low` of
16 MiB, as NVX's own guest reserves, and a workload's `memory.max` of 128 MiB
and `pids.max` of 128.

A stage of the root that fails is a `root::RootFailure`: the stage's code, one
byte, then the problem, as UTF-8 text. The guest's worker, and with it the VM,
then ends with the stage's status:

| Code | Stage | What failed | Status |
| --- | --- | --- | --- |
| 1 | `configuration` | Receiving and checking the root configuration | 11 |
| 2 | `layout` | Reading the boot layout of the root from the kernel command line, and checking that the worker assembles it | 12 |
| 3 | `bootstrap` | Bootstrapping the guest for the root: its cgroups and their resource values | 13 |
| 4 | `assembly` | Assembling the root, such as from an image of another identity than the boot tokens expect | 14 |
| 5 | `teardown` | Tearing the root down, such as while a process holds it open | 15 |

### Probes

A probe, `probe::Probe`, is a named check that the host asks the guest's
worker to run on its layered root. It is UTF-8 text: the probe's name, which
starts with a lowercase ASCII letter, and holds lowercase ASCII letters,
digits, and `-`, then each of its arguments after one space, each without
whitespace or control characters. The worker answers with the facts that the
probe found, `probe::Facts`, also UTF-8 text: one `KEY=VALUE` line per fact,
each ended by a newline, in the order in which the probe found them, and each
key at most once. A key holds lowercase ASCII letters, digits, `.`, and `-`,
and a value escapes `\`, newlines, and carriage returns as `\\`, `\n`, and
`\r`.

The worker runs the probes of `worker::probes`, none of which takes arguments:

| Probe | Facts |
| --- | --- |
| `mounts` | For the image's mount, `distro`, the scratch's, `scratch`, and the overlay's, `root`: the number of mounts at its mount point, `NAME.count`, and of the topmost, its `NAME.type`, `NAME.source`, `NAME.options`, and `NAME.super`, the file system's own options |
| `contents` | The root's `os-release.id` and `root.mode`. It writes `.runtime-adapter-probe` at the top of the root, and reports what the root, `write.root`, the upper, `write.upper`, and the image, `write.lower`, hold at that name, and whether the image refuses a new file, `lower.write` |
| `cgroups` | The file system at the cgroups' parent, `parent.type`, and its `parent.subtree-control`; whether each cgroup exists, `agent.exists` and `workload.exists`; `agent.memory.low`, `workload.memory.max`, and `workload.pids.max`; the number of processes in each, `agent.processes` and `workload.processes`; and `user-namespaces`, the guest's limit of user namespaces, or `unavailable` without them |
| `processes` | For PID 1, `pid1`, the worker, `worker`, and PID 1's unrelated child, `sibling`: `NAME.pid`, and while the process exists, `NAME.state`, `NAME.ppid`, `NAME.root`, `NAME.cgroup`, `NAME.command`, and `NAME.namespaces`: `same` if it shares PID 1's, or the ones that differ |
| `hold` | It opens the root, and keeps it open until the worker ends, so that the teardown finds the root busy: `held`, the path that it holds |

A value that a probe cannot read is `absent` if its file does not exist, and
otherwise `unreadable: PROBLEM`. A new check of a root is a new probe in this
table.

## Guest agent

`guest::serve` serves the host program on a stream to the guest's end of the
control session, through `nvx::guest::nvxs`. It attaches, then:

- acknowledges each reset of the session with the smallest receive window that
  the session allows, once it dropped the earlier epoch's partial message,
  because a new epoch starts with a new message;
- credits each payload back once it holds the payload, so that a message
  longer than the window still arrives whole;
- answers each `Ping` with `Pong`, sends each `Echo` back, answers each
  `Probe` with `ProbeFailed`, since the VM has no layered root to probe, and
  answers `Stop` with `Stopped`, then returns.

A failure of the session, a malformed message, a root configuration, which
only the worker of a VM with a layered root accepts, and a message that only
the guest sends end serving with an error.

`runtime-adapter-guest serve` runs the guest agent on its standard input and
output, which connect to the guest's end of the session, such as a control
console in raw mode. It exits with 0 once the host stopped it or the broker
closed the stream, and with 1, after a diagnostic on standard error, once
serving failed. Without arguments, it reports the contract that it was built
against.

`guest::serve_terminal` serves a tty, such as a VM's control tty, as `serve`
does. It opens the tty with `nvx::guest::terminal`, as NVX's managed agent
does: it waits up to 30 seconds while the kernel sets the tty up, and puts it
in raw mode, so that the tty passes the session's bytes as they are. Once
serving ends, it waits until the tty has sent what serving wrote, such as the
confirmation of a stop.

`runtime-adapter-guest init TTY` runs `serve_terminal` on the tty TTY in place
of NVX's managed agent, as a VM's PID 1; see [VMs](#vms). It ends with 0 once
the host stopped it, and with 1, after a diagnostic on standard error, once
serving failed or the broker closed the tty. As PID 1, which must not exit, it
ends the VM with that status instead, through NVX's `/sbin/nvx-exit`, as the
managed agent does.

### PID 1 and the worker of a layered root

`runtime-adapter-guest init TTY layered` runs PID 1 of a VM with a layered
root, in place of NVX's init agent; see [VMs](#vms). PID 1,
`worker::supervise`, stays minimal:

1. It starts an unrelated child, `runtime-adapter-guest idle`, which sleeps
   until a signal ends it, and stands for a daemon that a guest starts before
   its agent.
2. It starts the worker, `runtime-adapter-guest worker TTY SIBLING`, with the
   process ID of the unrelated child, which the worker's probes check, since
   the guest's kernel does not list a process's children.
3. It collects the status of every child, adopted processes included, until
   the worker ends, and then ends the VM with the worker's status, through
   `/sbin/nvx-exit`.

The worker, `worker::work`, is a process of its own, never PID 1. It opens the
tty with `nvx::guest::terminal`, as `serve_terminal` does, and then:

1. attaches the session;
2. receives the host's root configuration, and checks it;
3. reads the boot layout of the root from the kernel command line, with
   `nvx::protocol::root::RootLayout::parse`, then bootstraps the guest's
   cgroups with `nvx::guest::root::bootstrap`, which moves the guest's
   processes into the agent's cgroup, and assembles the root with
   `nvx::guest::root::assemble`;
4. answers `RootReady`, or `RootFailed` with the stage that failed, and then
   ends;
5. serves `Ping`, `Echo`, and `Probe`;
6. on `Stop`, tears the root down, reports a teardown that failed with
   `RootFailed`, confirms the stop with `Stopped`, and ends.

Before the root configuration, the worker accepts only the configuration, or a
`Stop`, which ends it without a root. It assembles an EROFS image over an ext4
scratch, and refuses the other layouts that the boot tokens can name at the
layout stage. It ends with 0 once the host stopped it, after a teardown that
succeeded, with the stage's status, from 11 to 15, once a stage failed, and
with 1 once its session failed or the broker closed the tty, each but the
first after a diagnostic on standard error. Before it exits, it closes what its
probes hold, then unmounts a root that it still holds, as
`nvx::guest::root::Root` does when it drops, ignoring failures. A teardown that
failed leaves the root mounted until the VM ends. The worker runs the root's
operations through `worker::RootOperations`, so that tests run it against a
fake root.

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
  an `Echo` of the same bytes, and `Stopped`. `stop` also returns the failure
  of a layered root's teardown, which the guest reports before it confirms;
- `configure_root` sends a root configuration, and returns how the guest
  answered: `RootReady`, or the stage of the root that failed;
- `probe` sends a probe, and returns the facts that it found, or the problem.

Besides the session's own buffers, the client holds at most the rest of one of
the guest's records and one partial message. A reset of the session ends the
attachment, and its partial message with it, because the next epoch starts
with a new message, in a new attachment.

A failure of the session, a send that fails or times out, a malformed message,
an answer whose body does not decode, and a message that only the host program
sends end the client, and its later calls fail. A receive that times out
doesn't: it keeps what arrived. A request ends the client on any failure after
the framing accepted it, a timeout included, because an answer that arrived
later would answer the wrong request.

## VMs

The host program runs the guest agent in VMs of NVX's artifacts, through NVX's
supervisor, `nvx::host::supervisor`, each in a sandbox store of
`nvx::host::store`.

### The guest agent in place of NVX's agents

NVX's initramfs hands a VM of the managed lifecycle to NVX's managed agent: its
`/init` runs
`exec /sbin/nvx-managed-agent /dev/hvc2 - nvx-managed UID GID NAME HOME` as
PID 1. A VM with a layered root, whose kernel command line has
`nvx_sandbox=1`, goes to NVX's init agent instead, which assembles the root:
`/init` runs `exec /sbin/nvx-init-agent`, without arguments.
`initramfs::write` copies that initramfs, and appends to the copy a second
archive, in the `newc` format, which Linux unpacks over the first:

- the guest agent, at `/sbin/runtime-adapter-guest`;
- a script, `/sbin/runtime-adapter-init`, that runs
  `runtime-adapter-guest init "$1"`, with the control tty, the first of the
  arguments that `/init` passes the managed agent;
- a symbolic link from `/sbin/nvx-managed-agent` to that script;
- a script, `/sbin/runtime-adapter-layered`, that runs
  `runtime-adapter-guest init /dev/hvc2 layered`, which names the control tty
  itself, since `/init` passes NVX's init agent none;
- a symbolic link from `/sbin/nvx-init-agent` to that script, so that NVX's
  init agent never assembles the root in the adapter's VMs.

Linux removes a file whose type an archive changes before it creates the new
one, so each link replaces NVX's agent without writing to its file, which could
have other names. The second archive starts at a multiple of 4 bytes, as Linux
requires of an uncompressed archive, after zeros that Linux skips. NVX's own
images don't change.

### The runtime identity

The supervisor records the runtime identity of each launch, and its reattach
compares the recorded identity with the caller's. `runtime::Runtime::from_dir`
takes NVX's artifacts from a repository checkout or an extracted release, with
`nvx::host::artifacts::Artifacts::from_dir`, and their runtime identity from
`nvx::host::artifacts::ArtifactDir::runtime_identity`, which names each
artifact by the SHA-256 digest that the install metadata beside it records,
never from its contents: a release's `SHA256SUMS`, or the build provenance in a
checkout's `build/`, where `nvx.py download` also installs a release's.

The VMs boot a copy of NVX's initramfs with the guest agent in it, so the
identity of their initramfs names both:
`sha256:DIGEST+runtime-adapter-guest/BUILD`. The guest agent has no install
metadata of its own, so the caller names its build, BUILD, which is the crate's
version unless the caller names another. A host program that ships another
build of the guest agent runs another runtime, and finds a VM of this one
mismatched.

### Layered roots

`layered::LayeredLaunch` plans a VM with a layered root with NVX's typed plan
of a cold layered launch, `nvx::host::sandbox::SandboxPlan`, with NVX's default
sandbox settings, and checks it with `SandboxPlan::validated`. The plan names
the images by absolute paths, since OpenVMM runs in the sandbox's store. The
VM's kernel command line is the plan's, without parameters of the caller:
`nvx_sandbox=1`, the image's token, such as
`nvx_layer=distro,0xd0003000,erofs:UUID`, the upper's, such as
`nvx_scratch=0xd0006000,ext4`, and those of the settings, which the worker
ignores. OpenVMM's arguments are those that NVX's own sandbox start passes:
the plan's, which attach the image and the scratch as block devices, then the
managed lifecycle in one process, NVX's default memory, the kernel, the
initramfs, that command line, no virtio console, the control console with the
launch capability on standard input, and the outcome report.

The boot tokens carry only what NVX's boot contract defines. The launch sends
the rest in the [root configuration](#root-configurations), once it attaches:
the defaults, with the runtime directory that the caller names, as it is, so
that the guest checks it, and the size of each image in sectors, if it is a
whole number of them, which the guest checks against its block device.

The launch records what it launched in the sandbox's store, beside NVX's
runtime records, in `runtime-adapter.json`, before it spawns the VMM:

```json
{"format": 1, "mode": "layered", "kernelCommandLine": "nvx_sandbox=1 ...",
 "plan": PLAN, "rootConfiguration": "version=1\nruntime=/run/runtime-adapter\n..."}
```

`mode` is `layered`, or `blockless` for a VM without a layered root, whose
`plan` and `rootConfiguration` are `null`. `plan` is the persisted form of the
VM's `SandboxPlan`, and `rootConfiguration` the root configuration that the
launch sends, whether or not the guest accepts it.

### Commands

`runtime-adapter-host` takes NVX's artifacts from the directory that
`NVX_ARTIFACTS_DIR` names. Each command takes the guest agent's build from
`--guest-build BUILD`, the crate's version by default:

- `launch STORE --guest-agent PATH [--hypervisor NAME] [LAYERED]` launches a VM
  in the sandbox store STORE, which it creates if needed, with the guest agent
  PATH, a static `x86_64-unknown-linux-musl` build of `runtime-adapter-guest`,
  on the hypervisor NAME, or else on the one that
  `nvx::Hypervisor::from_env_or_default` selects. Once the launch has checked
  that no VM of the sandbox runs, it writes the VM's initramfs and its
  [record](#layered-roots) into the store. It connects to the VM's control
  endpoint with `nvx::host::session::connect`, attaches with the launch's
  capability, exchanges a `Ping` and the longest `Echo` with the guest agent,
  commits the launch, and exits, leaving the VM running. A launch that fails
  ends its VM.

  LAYERED,
  `--distro FORMAT:PATH [--distro-identity UUID] --upper (scratch:PATH | ram) [--runtime-dir DIR]`,
  gives the VM a [layered root](#layered-roots). Its image is the file PATH, an
  EROFS file system, `erofs`, or a GPT disk, `gpt`, of which the guest expects
  the identity UUID, if given. Its upper is the ext4 scratch image PATH, or
  RAM. The guest assembles the root below its runtime directory DIR,
  `/run/runtime-adapter` by default. Once attached, the launch sends the root
  configuration, and exchanges the `Ping` and the `Echo` once the guest
  assembled the root. If the guest reports that a stage of the root failed
  instead, the launch waits for the VM to end, abandons the launch, and checks
  that the VM ended with the stage's status. The worker assembles only an
  EROFS image over a scratch, and fails the other layouts at the layout stage.
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
  the stop fails. The worker of a layered root tears the root down before it
  confirms, and reports a teardown that failed first: the stop then checks
  that the VM ended with the teardown's status instead.
- `probe STORE PROBE...` reattaches and attaches as `reattach` does, then runs
  each PROBE in the VM's layered root, in order, and prints the facts that it
  found. A PROBE is the text of a [probe](#probes): its name, then its
  arguments, each after one space. A probe that fails fails the command.

`reattach`, `stop`, and `probe` find a VM that another runtime identity
launched mismatched, and then signal nothing: the VM keeps running. The
commands print what they find as `KEY=VALUE` lines: `reattached` (`live`,
`mismatched`, `exited`, or `indeterminate`), `differences` (the parts of the
runtime identity in which a mismatched VM differs), `pid` (the VMM's process
ID), `instance` and `epoch` (the identity of the session that they attached
to), `root` (`ready` or `failed`: how the guest answered the root
configuration, or `failed` when a stop finds that the root's teardown failed),
`stage` and `problem` (the stage of the root that failed, such as `assembly`,
and the problem), `PROBE.KEY` (the fact KEY that the probe named PROBE found),
`stopped` (`graceful`, `forced`, or `timed-out`), `outcome` (such as
`success 0`, or `guest-exit 14` once the assembly failed), and `teardown`
(`complete` or `incomplete`: whether the VMM's teardown of the VM completed,
which the outcome report records apart from the root's). Values escape `\`, newlines, and
carriage returns as `\\`, `\n`, and `\r`. The commands exit with 0 once they
did what they were asked, with 3 when they find the VM mismatched, with 4 when
the guest reported that a stage of the root failed, and the VM ended with the
stage's status and a complete teardown, and with 1, after a diagnostic on
standard error, when they fail. Without arguments, the program reports the
contract that it was built against.

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

The unit tests of `frame`, `root`, and `probe` run in every configuration. They
cover each kind's encoding, messages in pieces of any size and split at every
byte, the headers that the framing refuses before their body arrives, and the
root configurations, failures, probes, and facts that decode, and those that
don't. In the guest-only configuration, the unit tests of `worker::probes`
cover what the probes read: the mount table with its escapes, the kernel's
records of a process, and `os-release`, and the probes that the worker
refuses.

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
payloads, and malformed headers. It also checks that the guest agent of a VM
without a layered root answers probes with a failure, and refuses root
configurations.

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
  late;
- a layered root: the configuration that the client sends, the guest's
  answers, ready or the stage that failed, probes and their facts, a stop
  that learns that the teardown failed, and answers whose bodies do not
  decode, which end the client.

Through a relay between its test broker and a pseudo-terminal,
`tests/guest_session.rs` also checks that `guest::serve_terminal` and
`runtime-adapter-guest init` serve a tty in raw mode, with an `Echo` of every
byte value, and that `init` fails at once on a path that is no tty.

`tests/guest_session.rs` also runs the worker against a fake root, behind its
test broker: a root that the worker assembles, probes, and tears down on a
stop, across a reset of the session; the failure of each stage, which the
worker reports before it ends with the stage's status, without the operations
of the later stages; a teardown that fails; before the root, the configuration
and the `Stop` that it accepts, and the messages that it refuses; and a second
configuration and a broker that closes the stream, which leave the root that
it assembled to its operations. Through the binary, it checks that
`runtime-adapter-guest init TTY layered`, which is not PID 1 there, starts the
worker, which fails at the layout stage on a kernel command line without a
layered root, and ends with its status, and checks `worker`, `idle`, and the
usage errors. Each guest binary that a test starts runs in a process group of
its own, with the processes that it starts, and keeps its process ID, and with
it the group's, until the test has killed the group. A binary that exits but
leaves processes of its group running fails its test. A test that fails, or
gives up on the binary, kills the whole group, even once the binary exited, so
that none of them outlives the test or holds its output open, which tests check
too.

`tests/initramfs.rs` and `tests/runtime.rs` check, in the host-only
configuration, on Linux and Windows:

- the archive that puts the guest agent in place of NVX's agents: its entries,
  their owners and modes, both launchers, and the padding of its headers and
  data, for guest agents of every length modulo 4;
- the copy of NVX's initramfs, which stays as it is, of every length modulo 4,
  with the archive after it at a multiple of 4 bytes, and the files that a
  failure names;
- the runtime identity of a checkout and of a release, which differs from
  NVX's in the initramfs alone, another build of the guest agent, which differs
  in the initramfs too, and missing install metadata, which fails as NVX
  reports it.

`tests/layered_launch.rs` checks, in the host-only configuration, on Linux and
Windows, the plan of a layered launch: its block devices and boot tokens, the
OpenVMM arguments of NVX's sandbox start, and the sizes of the images; the
options that it passes on as they are, for the guest to check; the record of
a launch, with and without a layered root; and the command lines that the host
program refuses, each with status 2.

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
stops it.

### Layered scenarios

`tests/vm_layered.rs` launches VMs with a layered root on a real hypervisor, in
the host-only configuration, through the host program's commands, and checks
that the guest's worker, outside PID 1, assembles the root, or reports the
stage that failed, and that the VM still ends cleanly. Each scenario is a row
of the table that its `scenarios!` macro declares, and an ignored test of its
own:

| Scenario | Root | Expects |
| --- | --- | --- |
| `erofs_over_scratch` | NVX's Ubuntu EROFS image, with its own identity, over a copy of the scratch template | A root that the worker assembled: the image, read-only, under the overlay, whose upper and work directories are on the scratch, each mounted once below the runtime directory; the merged root's contents, with a file that reaches the upper and not the image; the agent's and the workload's cgroups, with their resource values; a worker that is PID 1's child, and PID 1's unrelated child, untouched; and a teardown that unmounts the scratch cleanly |
| `other_identity_fails_the_assembly` | The image, of which the launch expects another identity | The assembly's failure, which the launch reports, and a VM that ends with 14 before the guest mounts the scratch |
| `invalid_configuration_fails_its_stage` | A relative runtime directory | The configuration's failure, which the launch reports, and a VM that ends with 11 |
| `busy_root_fails_the_teardown` | The image over the scratch, which the `hold` probe keeps open | The teardown's failure, which the stop reports, and a VM that ends with 15, leaving the scratch mounted |

A row names the root, the image, the identity that the launch expects of it,
the upper, and the runtime directory, and what the scenario expects: a root
that the guest assembles, with a check that probes it, a teardown that fails
after a check, or the stage that fails, with its problem. Each scenario checks
the launch's record, and whether the VM left the scratch's journal to recover,
which tells whether the guest unmounted the scratch.

The scenarios use the fixtures of NVX's own layered scenarios, from NVX's
artifacts: the Ubuntu EROFS image, `ubuntu-distro.erofs`, its manifest, which
holds its UUID, and the scratch template, `ubuntu-smoke-scratch.ext4`, an
empty ext4 file system that the guest-artifact build makes, of which each
scenario boots a copy. Downloaded packages do not include the template, so make
it beside the image as the guest-artifact build does:

```bash
truncate --size 64M ../../build/ubuntu-smoke-scratch.ext4
mkfs.ext4 -q -F -m 0 -U 4f3c8bf7-1959-47b4-8811-62b17bbddaf4 \
  -E lazy_itable_init=0,lazy_journal_init=0 ../../build/ubuntu-smoke-scratch.ext4
```

### Running the VM tests

The VM tests, `tests/vm_restart.rs` and `tests/vm_layered.rs`, share their
sandboxes through `tests/common`. A test that fails ends the VM that it left
running, and keeps the sandbox's directory, whose path it prints, unless it can
confirm that the VM ended. The tests boot VMs, so they are ignored. They read
the hypervisor from `NVX_HYPERVISOR`, through
`nvx::Hypervisor::from_env_or_default`, NVX's artifacts, with their install
metadata and the fixtures, from `NVX_ARTIFACTS_DIR`, and the guest agent from
`RUNTIME_ADAPTER_GUEST`. In a checkout where `python3 scripts/nvx.py download`
installed NVX's artifacts, and with the scratch template, run them in this
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
host-only configuration on each backend, in the jobs that run the guest and
sandbox steps, and runs its ignored tests, the adapter's VM scenarios, with
`NVX_HYPERVISOR` naming the backend, `NVX_ARTIFACTS_DIR` the checkout, into
which the job downloaded NVX's artifacts, their provenance, and the fixtures
of the layered scenarios with the guest artifacts, as NVX's own layered
scenarios take them, and `RUNTIME_ADAPTER_GUEST` the guest agent. The Linux
jobs build the guest agent first, and the Windows job takes the one that CI's
`distro-artifacts` job builds on Linux.
