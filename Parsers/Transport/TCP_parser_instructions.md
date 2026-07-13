# TCP Parser Reference

This document describes the `TCP` output produced by the pspkt parsers across every parsing
level. It reflects what the code actually emits.

## Notation used in this document

- `[value]` marks a parsed value that is substituted at runtime. The square brackets are
  **not** printed.
- A pipe inside brackets (`[Set|Not set]`) is a conditional: the first word is used when the
  flag bit is set (1), the second when it is clear (0).
- In the flags bit templates, a capital `B` is replaced by the actual bit value (`0` or `1`)
  at that position; `.`, `0`, and `1` are printed verbatim.
- `[+|-]` in the tree examples marks a collapsible node: `+` when collapsed, `-` when expanded.

## Value formatting

- Hex (`0x`): checksum, flags hex string, header-length data-offset value.
- Decimal is used for all values where hex is not explicitly defined (ports, sequence/ack
  numbers, window, length, urgent pointer).

## TCP flag single-char map (tcpdump / pktmon format)

TCP flags are summarized with one character per set flag, in this fixed order:

| Bit    | Flag | Char |
|--------|------|------|
| `0x80` | CWR  | `W`  |
| `0x40` | ECE  | `E`  |
| `0x20` | URG  | `U`  |
| `0x10` | ACK  | `.`  |
| `0x08` | PSH  | `P`  |
| `0x04` | RST  | `R`  |
| `0x02` | SYN  | `S`  |
| `0x01` | FIN  | `F`  |

Only set flags are printed; when no flag is set the summary is `none`. Example: SYN+ACK → `.S`.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

**Special note:** the Minimal/Default/Detailed one-liners combine the Addressing (IPv4/IPv6)
and Transport (TCP/UDP) layers; those layers share the same one-line format.

## Minimal

```
[Address protocol].[Transport protocol]: [src addr].[src port] > [dst addr].[dst port]:
```

## Default

The transport segment shows the TCP flags in the single-char format above, e.g.
`TCP [.S], seq [n], ack [n], win [n], len [n]`, joined after the address prefix:

```
[src addr].[src port] > [dst addr].[dst port]: TCP [[flags]], seq [n], ack [n], win [n], len [n]
```

(When a well-known application protocol is detected for the port, its hint/summary is shown
in place of / ahead of the TCP segment.)

## Detailed

Same as Default; the transport sub-line reads:

```
TCP [[flags]] - Src: [src port], Dst: [dst port]; seq: [n], ack: [n], win: [n], len: [n][; Opts: ...]
```

## Analysis

### Text Box

```
[src addr].[src port] > [dst addr].[dst port]:
```

### Details: Collapsed

The TCP node's fixed header (the `[+|-]` is the tree expand/collapse marker):

```
[+|-]TCP [[flags]] - Src Port: [src port], Dst Port: [dst port], Seq: [seq], Ack: [ack], Len: [payload length]
```

### Details: Expanded

The header is unchanged when expanded. The `Flags` child is itself a collapsible node,
**collapsed by default**; the other fields are leaves:

```
-TCP [[flags]] - Src Port: [src port], Dst Port: [dst port], Seq: [seq], Ack: [ack], Len: [payload length]
  Source Port: [src port]
  Destination Port: [dst port]
  Sequence Number: [seq]
  Acknowledgment number: [ack]
  +Flags: 0x[12-bit flags hex] ([tcpdump flags])
  [data-offset bits] .... = Header Length: [n] bytes (0x[data-offset words])
  Window: [window size]
  Checksum: 0x[checksum]
  Urgent Pointer: [urgent pointer]
  TCP payload ([payload length] bytes)
```

#### Flags (expanded)

The `Flags` node is a Wireshark-style breakdown of the 12-bit flags field (3 reserved bits,
Accurate ECN, then the 8 standard flags):

```
-Flags: 0x[12-bit flags hex] ([tcpdump flags])
  000. .... .... = Reserved: Not set
  ...B .... .... = Accurate ECN: [Set|Not set]
  .... B... .... = Congestion Window Reduced: [Set|Not set]
  .... .B.. .... = ECN-Echo: [Set|Not set]
  .... ..B. .... = Urgent: [Set|Not set]
  .... ...B .... = Acknowledgment: [Set|Not set]
  .... .... B... = Push: [Set|Not set]
  .... .... .B.. = Reset: [Set|Not set]
  .... .... ..B. = Syn: [Set|Not set]
  .... .... ...B = Fin: [Set|Not set]
```

Example header for a SYN+ACK segment: `Flags: 0x012 (.S)`.

**Default expand state:** the TCP node is expanded by default (like the IPv4/UDP nodes); its
`Flags` child is collapsed by default.
