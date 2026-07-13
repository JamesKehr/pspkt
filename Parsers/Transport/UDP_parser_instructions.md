# UDP Parser Reference

This document describes the `UDP` output produced by the pspkt parsers across every parsing
level. It reflects what the code actually emits.

## Notation used in this document

- `[value]` marks a parsed value that is substituted at runtime. The square brackets are
  **not** printed.
- `[+|-]` in the tree examples marks a collapsible node: `+` when collapsed, `-` when expanded.

## Value formatting

- Hex (`0x`): checksum (in application-layer detail where shown).
- Decimal is used for all values where hex is not explicitly defined (ports, length).

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

**Special note:** the Minimal/Default/Detailed one-liners combine the Addressing (IPv4/IPv6)
and Transport (TCP/UDP) layers; those layers share the same one-line format. Only TCP adds a
`[flags]` element (see the TCP reference); UDP does not.

## Minimal

```
[Address protocol].[Transport protocol]: [src addr].[src port] > [dst addr].[dst port]:
```

## Default

The transport segment for UDP reads `UDP, len [n]` (or the detected application protocol
summary for well-known ports), joined after the address prefix:

```
[src addr].[src port] > [dst addr].[dst port]: UDP, len [n]
```

## Detailed

Same as Default; the transport sub-line reads:

```
UDP - Src: [src port], Dst: [dst port]; len: [n]
```

## Analysis

### Text Box

```
[src addr].[src port] > [dst addr].[dst port]:
```

### Details: Collapsed

The UDP node's fixed header (the `[+|-]` is the tree expand/collapse marker):

```
[+|-]UDP - Src Port: [src port], Dst Port: [dst port], Len: [datagram payload length]
```

### Details: Expanded

The header is unchanged when expanded; expanding reveals the child fields:

```
-UDP - Src Port: [src port], Dst Port: [dst port], Len: [datagram payload length]
  Source Port: [src port]
  Destination Port: [dst port]
  UDP payload ([datagram payload length])
```

**Default expand state:** the UDP node is **collapsed by default** in Analysis mode (it shows
its collapsed one-line header). Expand state persists across packets.

`[datagram payload length]` is the UDP length header field minus the 8-byte UDP header.
