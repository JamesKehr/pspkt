# SSH Parser Reference

This document describes the SSH output produced at every parsing level. The field model and
message names follow Wireshark 3.6.2's SSH dissector
(`epan/dissectors/packet-ssh.c`) and RFC 4253.

## Scope

The parser is a stateless, single-packet subset of Wireshark's conversation-aware dissector:

- SSHv1 and SSHv2 identification strings.
- SSHv1 binary packet framing and message codes 0-4.
- SSHv2 packet length, padding length, message code, payload, and padding.
- SSHv2 KEXINIT cookie, ten algorithm name-lists, `first_kex_packet_follows`, and reserved.
- Generic message names from Wireshark, generic key-exchange codes 30-39, generic
  authentication-method codes 60-79, and `Unknown (n)` for other valid codes.

It does not maintain per-connection negotiation state, select a DH/GEX/ECDH decoder, reassemble
TCP segments, read key logs, or decrypt packets after NEWKEYS. Implausible framing is displayed
as `SSH Encrypted or unparsed payload`; this is a heuristic because a selected packet alone
cannot prove whether its bytes are encrypted. Conversely, encrypted bytes can rarely satisfy
the cleartext plausibility checks and appear as a cleartext frame.

## Detection

- A complete printable-ASCII `SSH-<protoversion>-<softwareversion>` line at payload offset 0
  is recognized on any TCP port. The line must end in LF or CRLF and must not exceed the
  RFC 4253 limit of 255 bytes including CRLF.
- Binary payloads are considered SSH only on TCP ports 22 and 29418.
- UDP is never parsed as SSH.

## Display levels

### Minimal

Minimal shows the TCP tuple only. It does not add a port-only `SSH` label.

### Default and Analysis Text Box

- Identification: `SSH Protocol: SSH-2.0-OpenSSH_9.6`
- SSHv1 binary: `SSH Version 1: User`
- SSHv2 binary: `SSH Version 2: Key Exchange Init`
- Truncated framing: `SSH Version 2: Truncated packet`
- Opaque bytes: `SSH Encrypted or unparsed payload`

Payloadless ACK/FIN segments render as plain TCP. Generic key-exchange and authentication
messages, and unknown SSHv2 codes, include their numeric code exactly as the Details root does.

### Detailed

Detailed uses the same SSH summary as Default beneath the TCP detail line.

## Analysis tree

### Identification string

```
+SSH Protocol: SSH-2.0-OpenSSH_9.6 comment
    Protocol Version: 2.0
    SSH Version: 2
    Software Version: OpenSSH_9.6
    Comments: comment
    Flow direction (by service port): client-to-server
```

The flow-direction leaf appears only when exactly one endpoint uses port 22 or 29418.
`SSH-1.99-...` is classified as SSHv2.

### SSHv2 packet

```
+SSH Version 2: New Keys
  +Binary Packet
      Packet Length: 12
      Padding Length: 10
      Message Code: New Keys (21)
    Padding: 10 bytes; Data: ...
```

A plausible cleartext packet has a packet length no greater than `0xffff`, padding of at least
4 bytes but less than the packet length, at least one message byte, and total size
`4 + packet_length` divisible by 8. Message codes 1-255 are structurally valid; symbolic-name
coverage does not determine framing validity.

### SSHv2 KEXINIT

```
+SSH Version 2: Key Exchange Init
  +Binary Packet
      Packet Length: [n]
      Padding Length: [n]
      Message Code: Key Exchange Init (20)
  +Key Exchange Init
      Cookie: [32 hex characters]
    +Key Exchange Algorithms (len [n]): [bounded preview]
        Algorithms: [full comma-separated value]
    +Server Host Key Algorithms (len [n]): [bounded preview]
        Algorithms: [full comma-separated value]
      ...
      First KEX Packet Follows: [False|True] ([0|1])
      Reserved: [n]
    Padding: [n] bytes; Data: [bounded hex preview]
```

All ten RFC 4253 name-lists are emitted in wire order. Empty lists display `Algorithms:
(empty)`. A field whose declared length exceeds the remaining SSH payload produces a
field-specific `Truncated:` leaf without reading beyond the payload.

### SSHv1 packet

```
+SSH Version 1: User
  +Binary Packet
      Packet Length: [n]
      Padding Length: [n]
      Message Code: User (4)
    Payload: [n] bytes; Data: [bounded hex preview]
    Padding: [n] bytes; Data: [bounded hex preview]
```

An explicit SSHv1 banner selects SSHv1 framing. For an independently selected binary packet
without its banner, pspkt additionally accepts a strict SSHv1 frame only when the calculated
frame length consumes the entire TCP payload and the message code is 1-4. This standalone
inference is a pspkt extension; Wireshark normally obtains the version from conversation state.

## Truncation

Analysis retains one captured packet and parses it on selection. A binary frame that begins
plausibly but extends beyond the captured payload displays a `Truncated packet` node with the
declared and captured lengths. No cross-segment SSH reassembly is performed.
