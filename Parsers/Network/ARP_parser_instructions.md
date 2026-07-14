# ARP Parser Reference

This document describes the `ARP` output produced by the pspkt parsers across every parsing 
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

- Hex (`0x`): 
- Decimal: 

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

`ARP`

## Default

ARP request:

`ARP, Request who-has [Target IP] tell [Sender IP]`

ARP reply:

`ARP, Reply [Sender IP] is-at [Sender MAC]`

> The reply advertises the **sender's** IP → MAC mapping (tcpdump convention): the host that
> answers puts its own address in the sender fields, so the useful learned mapping is
> `[Sender IP] is-at [Sender MAC]`.


## Detailed

Same as `Default`.


## Analysis

### Text Box

Same as `Default`.

### Details: Collapsed

Same as `Default` — the collapsed node header is the Default one-liner.

### Details: Expanded

Labels are padded so the colons align.

```
[+|-]ARP, Request who-has [Target IP] tell [Sender IP]
  Operation  : [Request|Reply]
  Sender MAC : [Sender MAC]
  Sender IP  : [Sender IP]
  Target MAC : [Target MAC]
  Target IP  : [Target IP]
```