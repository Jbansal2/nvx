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
requests in that framing, and its guest agent serves them. The host program's
binary reports the contract that it was built against.

## Configurations

Each configuration enables one side of `nvx`:

| Configuration | Cargo options | `nvx` features | Modules | Binary |
| --- | --- | --- | --- | --- |
| Protocol-only | none | none | `frame` | none |
| Host-only | `--features host` | `host` | `frame`, `host` | `runtime-adapter-host` |
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
host-only configuration on each backend and runs any ignored tests that it
declares, the adapter's hypervisor scenarios, with `NVX_HYPERVISOR` naming the
backend, which `nvx::Hypervisor::from_env_or_default` reads.
