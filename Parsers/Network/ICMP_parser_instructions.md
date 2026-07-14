# ICMP Parser Reference

This document describes the `ICMP` output produced by the pspkt parsers across every parsing 
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

- Hex (`0x`): Checksum, ID hex, seq hex
- Decimal: ID dec, seq dec, Data length, Code int

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

`ICMP`

## Default

The canonical summary forms are shown below; these are also the collapsed Analysis Details
node headers. The live Text Box one-liner additionally retains extra context fields (e.g.
`; TTL: [n]` for Echo) — Destination Unreachable code strings are surfaced additively.

### Echo

`ICMP.Echo [Request|Reply]: [src IP] > [dst IP], id [ID dec], seq [seq dec]`

### Destination Unreachable

`ICMP.Destination Unreachable -  [Code string] ([Code int])`


0		Destination network unreachable
1		Destination host unreachable
2		Destination protocol unreachable
3		Destination port unreachable
4		Fragmentation required, and DF flag set
5		Source route failed
6		Destination network unknown
7		Destination host unknown
8		Source host isolated
9		Network administratively prohibited
10		Host administratively prohibited
11		Network unreachable for ToS
12		Host unreachable for ToS
13		Communication administratively prohibited
14		Host Precedence Violation
15		Precedence cutoff in effect

## Detailed

Same as `Default`.

## Analysis

### Text Box

#### Echo

Same as `Default`.

#### Destination Unreachable

Same as `Default`.

### Details: Collapsed

#### Echo

Same as `Default`.

#### Destination Unreachable

Same as `Default`.


### Details: Expanded

#### Echo

```
ICMP
  Type       : Echo (ping) [request|reply] ([8|0])
  Code       : 0
  Checksum   : 0x[Checksum]
  Identifier : [ID dec] (0x[ID hex])
  Sequence   : [seq dec] (0x[seq hex])
  Data ([Data length] bytes)
```

#### Destination Unreachable

The collapsed header is the Default one-liner; the expanded node shows Type/Code/Checksum
with the code string resolved. (Wireshark also dissects the embedded original datagram; pspkt
does not currently descend into it.)

```
ICMP.Destination Unreachable -  [Code string] ([Code int])
  Type       : Destination Unreachable ([Type int])
  Code       : [Code string] ([Code int])
  Checksum   : 0x[Checksum]
```

Code strings (Type 3):

https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-icmp.c?ref_type=heads