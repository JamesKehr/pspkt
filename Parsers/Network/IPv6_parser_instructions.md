# IPv6 Parser Reference

This document describes the `IPv6` output produced by the pspkt parsers across every parsing 
level. It reflects what the code actually emits.

## Notation used in this document

- `[value]` marks a parsed value that is substituted at runtime. The square brackets are
  **not** printed.
- A pipe inside brackets (`[true|false]`) is a conditional: the first word is used when the
  flag bit is set (1), the second when it is clear (0). Example: `[Do|Do not]` prints `Do`
  when the bit is 1 and `Do not` when it is 0.
- In the flags bit templates, a capital `B` is replaced by the actual bit value (`0` or `1`)
  at that position; `.`, `0`, and `1` are printed verbatim.
- `[+|-]` in the tree examples marks a collapsible node: `+` when collapsed, `-` when expanded.

## Value formatting

- Hex (`0x`): Traffic Class, Flow Label.
- Decimal: DSCP value, ECN value, Payload Length, Next Header number, Hop Limit.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

`IPv6`

## Default

Parsed in conjunction with the transport parsers. The network 4-tuple is always prefixed with
the network-layer name, whether or not a transport (TCP/UDP) is present:

```
IPv6 [Src addr].[Src port] > [Dst addr].[Dst port]: ...     (TCP/UDP)
IPv6 [Src addr] > [Dst addr]                                (no transport / other IP proto)
```

**Exception:** ICMPv6 does **not** carry the `IPv6` prefix — its line is `[Src addr] > [Dst addr]: ICMPv6 ...`.

## Detailed

`IPv6 - Src: [Src addr], Dst: [Dst addr]`

## Analysis

### Text Box

Same as `Detailed`.

### Details: Collapsed

Same as `Detailed` — the collapsed node header is `IPv6 - Src: [Src addr], Dst: [Dst addr]`.
IPv6 is **collapsed by default** in Analysis mode.

### Details: Expanded

IPv6 extension headers/options are currently not parsed. `Traffic Class` is a collapsible
sub-node (collapsed by default) containing the DSCP and ECN breakdown.

```
IPv6 - Src: [Src addr], Dst: [Dst addr]
  0110 .... = Version: 6
[Traffic Class]
  [+|-].... 0000 0000 .... .... .... .... .... = Traffic Class: 0x[h] ([DSCP string])
      .... BBBB BB.. .... .... .... .... .... = Differentiated Services Codepoint: [DSCP string] ([n])
      .... .... ..BB .... .... .... .... .... = Explicit Congestion Notification: [See `ECN Table`] ([n])
[/Traffic Class]
  .... 0010 1111 1111 1111 1000 = Flow Label: 0x2fff8
  Payload Length: [n]
  Next Header: [Protocol] ([n])
  Hop Limit: [n]
  Source Address: [Src addr]
  Destination Address: [Dst addr]
```

#### ECN table

00 – Not ECN-Capable Transport, Not-ECT
01 – ECN Capable Transport(1), ECT(1)
10 – ECN Capable Transport(0), ECT(0)
11 – Congestion Experienced, CE.