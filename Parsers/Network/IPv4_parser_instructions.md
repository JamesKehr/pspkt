# IPv4 Parser Reference

This document describes the `IPv4` output produced by the pspkt parsers across every parsing 
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

- Hex (`0x`): Identification, Flags value, Header Checksum.
- Decimal: Header Length, Total Length, Identification (parenthetical), Fragment Offset,
  Time to Live, Protocol number.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

`IPv4`

## Default

Parsed in conjunction with `TCP` parsers.

## Detailed

`IPv4 - Src: [Src addr], Dst: [Dst addr]`

## Analysis

### Text Box

Same as `Detailed`.

### Details: Collapsed

Same as `Detailed` — the collapsed node header is `IPv4 - Src: [Src addr], Dst: [Dst addr]`.
IPv4 is **collapsed by default** in Analysis mode.

### Details: Expanded

The node header (first line) stays `IPv4 - Src: [Src addr], Dst: [Dst addr]`; the fields
below are its children. `Flags` is a collapsible sub-node (collapsed by default) and its
hex value is the flag bits in the high byte (e.g. `0x40` when Don't fragment is set); the
comma-separated string names the set flags (`Don't fragment`, `More fragments`) and is
omitted when none are set.

```
IPv4 - Src: [Src addr], Dst: [Dst addr]
  0100 .... = Version: 4
  .... 0101 = Header Length: 20 bytes (5)
  DSCP: [DSCP string], ECN: [ECT|Not-ECT]
  Total Length: [n]
  Identification: 0x[h] ([n])
[Flags]
  [+|-]010. .... = Flags: 0x[h], [Flags string comma separated]
    0... .... = Reserved bit: Not set
    .B.. .... = Don't fragment: [Set|Not set]
    ..B. .... = More fragments: [Set|Not set]
[/Flags]
  ...B BBBB BBBB BBBB = Fragment Offset: [n]
  Time to Live: [n]
  Protocol: [Protocol] ([n])
  Header Checksum: 0x[Checksum]
  Source Address: [Src addr]
  Destination Address: [Dst addr]
```
