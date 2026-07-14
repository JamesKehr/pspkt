# Ethernet Parser Reference

This document describes the Ethernet output produced by the pspkt parsers across every parsing
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

- Hex (`0x`): EtherType value (e.g. `0x0800`), shown in the Details `Type` field.
- Decimal: frame length.

## Address / type formatting

- MAC addresses use lowercase hyphen-separated octets, e.g. `68-bf-6c-64-f6-00`.
- The EtherType is shown by name (`IPv4`, `IPv6`, `ARP`, ...) with the hex value in
  parentheses in the Details `Type` field. Unknown types fall back to `0x[hex]`.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

```
Eth:
```

## Default

The data-link segment (the trailing `:` shown here is the separator to the next layer, added
by the caller — it is not part of the Ethernet segment itself). The EtherType is **not** shown
at the Default/Detailed one-liner level (it remains in the Analysis Details node):

```
[src MAC addr] > [dst MAC addr], len [frame length]:
```

## Detailed

Same as `Default`.

## Analysis

### Text Box

```
Eth:
```

### Details: Collapsed

The Ethernet node is **collapsed by default** in Analysis mode (like the Component node; the
network/transport/application nodes are expanded). Its fixed header (the `[+|-]` is the tree
expand/collapse marker) is:

```
+Eth: [src MAC addr] > [dst MAC addr], type [EtherType], len [frame length]
```

### Details: Expanded

The user can expand the node to reveal the child fields (that expand state then persists across
packets). The header is unchanged when expanded — a tree node's text is fixed. Child labels are
padded so every value aligns at the same column:

```
-Eth: [src MAC addr] > [dst MAC addr], type [EtherType], len [frame length]
  Source:      [src MAC addr]
  Destination: [dst MAC addr]
  Type:        [EtherType] (0x[ethertype hex])
  Length:      [frame length]
```
