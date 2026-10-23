# Conformance vectors

These files hold the conformance vectors of NVX's wire formats: bytes that every
implementation must produce and accept, including those that share no code with
`nvx`, such as OpenVMM's broker and gateway and the guest agents of released
guests, some of which run the C agent. The host, the guest agent, and the fake
OpenVMM share one codec, so a change to it passes every round trip among them,
yet breaks those peers. Only bytes that no codec produced catch such a change.

| File | Vectors |
| --- | --- |
| [`nvxc-v1.txt`](nvxc-v1.txt) | Version 1 of the control protocol: `NVXC` frames, their `EXEC`, `MAPS`, and features payloads, and `NVXS` records of NVX's host and guest |
| [`nvxl-v1.txt`](nvxl-v1.txt) | Version 1 of the `NVXL` listener announcement |

[4.4 Host-Guest Control Interface](../../../doc/design/4.4-host-guest-control-interface.md)
and
[3.5.4 Host-Local Access and Ingress](../../../doc/design/3.5-network.md#354-host-local-access-and-ingress)
describe the protocols.

## Line format

`nvxc-v1.txt` and `nvxl-v1.txt` share one line format. A line that starts with
`#` is a comment, and an empty line is ignored. Every other line is one vector,
whose fields `|` separates:

```text
KIND|NAME|BYTES|VALUE|...
```

- `KIND` names what the bytes encode, one of the kinds that the file's header
  lists with their values.
- `NAME` names the vector, uniquely among the vectors of its kind.
- `BYTES` is the encoding, with two lowercase hexadecimal digits per byte.
- The values are what the bytes encode, in the order that the kind lists them:
  - A number is decimal, or hexadecimal after `0x`, and a negative one starts
    with `-`.
  - A byte string is hexadecimal, as `BYTES` is; an empty field is an empty one.
  - A text stands for bytes: a printable ASCII character other than `%` and `|`
    for itself, and `%` followed by two hexadecimal digits for any byte.
  - A word in capitals is one of those that the kind lists.
  - `-` stands for an absent value, where the kind allows one.
  - A list is its number of items, followed by the values of each item in turn.

A decoder must decode the bytes of each vector to its values, and an encoder
must encode the values to exactly its bytes. A kind whose name starts with
`INVALID_` has no values: every decoder must refuse the bytes of its vectors.

## Rules

- A vector changes only with a protocol version. A new version gets files of
  its own, such as `nvxc-v2.txt` for the exec v2 of
  [microsoft/nvx#623](https://github.com/microsoft/nvx/issues/623), and the
  bytes of an earlier version that it refuses become its rejection vectors.
- The bytes come from the protocol's definition, never from the code that they
  check, and so do the values of each vector.
