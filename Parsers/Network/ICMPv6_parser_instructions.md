# ICMPv6 Parser Reference

This document describes the `ICMPv6` output produced by the pspkt parsers across every parsing 
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

- Hex (`0x`): Checksum, ID hex
- Decimal: Seq, Data len, ID dec, seq dec

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

`ICMPv6`

## Default

The canonical summary forms are shown below; these are also the collapsed Analysis Details
node headers. The live Text Box one-liner retains extra context fields (e.g. `; TTL: [n]` for
Echo, or the parsed NDP option/field tail at Detailed) additively. NDP messages (RS/RA/NS/NA)
and Destination Unreachable code strings are surfaced per the formats below.

### Echo

`ICMPv6.Echo [Request|Reply]: [src IP] > [dst IP], id [ID dec], seq [seq dec]`

### Destination Unreachable

`ICMPv6.Destination Unreachable -  [Code string] ([Code int])`

0	No route to destination
1	Communication with destination administratively prohibited
2	Beyond scope of source address
3	Address unreachable
4	Port unreachable
5	Source address failed ingress/egress policy
6	Reject route to destination
7	Error in Source Routing Header


###	Router Solicitation

`ICMPv6.Router Solicitation from [Sender MAC]`


###	Router Advertisement

`ICMPv6.Router Advertisement from [Router MAC]`


###	Neighbor Solicitation

`ICMPv6.Neighbor Solicitation for [Target addr] from [Sender MAC]`


###	Neighbor Advertisement

`ICMPv6.Neighbor Advertisement [Target addr] ([NA Flags, comma separated]) is at [Target MAC]`

#### NA Flags

Router = rtr
Solicited = sol
Override = ovr


## Detailed

Same as `Default`.

## Analysis

### Text Box

Same as `Default`.

### Details: Collapsed

Same as `Default`.

### Details: Expanded

#### Echo

```
ICMPv6
  Type: Echo (ping) [request|reply] ([128|129])
  Code: 0
  Checksum: 0x[Checksum]
  Identifier: 0x[ID hex]
  Sequence: [seq dec]
  Data ([Data len] bytes)
```

#### Destination Unreachable

The collapsed header is the Default one-liner; the expanded node shows Type/Code/Checksum
with the code string resolved.

```
ICMPv6.Destination Unreachable -  [Code string] ([Code int])
  Type       : Destination Unreachable ([Type int])
  Code       : [Code string] ([Code int])
  Checksum   : 0x[Checksum]
```

https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-icmpv6.c?ref_type=heads


####	Router Solicitation, Router Advertisement, Neighbor Solicitation, Neighbor Advertisement (Network Discovery Protocol)

The Analysis Details root is `ICMPv6`. It expands to Type/Code/Checksum, message-specific
fields, Wireshark-style flag subtrees, and one direct node per ICMPv6 option. Flag and option
nodes are collapsed by default.
Source/Target Link-layer addresses remain folded into the Text Box one-liner and also appear
as full option nodes in Details.

```
ICMPv6
  Type: Neighbor Advertisement (136)
  Code: [n]
  Checksum: 0x[Checksum]
  +Flags: 0x[8 hex digits][, Router][, Solicited][, Override]
      B... .... .... .... .... .... .... .... = Router: [Set|Not set]
      .B.. .... .... .... .... .... .... .... = Solicited: [Set|Not set]
      ..B. .... .... .... .... .... .... .... = Override: [Set|Not set]
      ...B BBBB BBBB BBBB BBBB BBBB BBBB BBBB = Reserved: [n]
  Target Address: [Target addr]
  +ICMPv6 Option (Target link-layer address : [colon MAC])
      Type: Target link-layer address (2)
      Length: 1 (8 bytes)
      Link-layer address: [colon MAC]
```

Router Advertisement options are direct children:

```
ICMPv6
  Type: Router Advertisement (134)
  Code: [n]
  Checksum: 0x[Checksum]
  Current Hop Limit: [n]
  +Flags: 0x[2 hex digits], Router Preference [name]
      B... .... = Managed address configuration: [Set|Not set]
      .B.. .... = Other configuration: [Set|Not set]
      ..B. .... = Home Agent: [Set|Not set]
      ...B B... = Router Preference: [name]
      .... .B.. = Proxy: [Set|Not set]
      .... ..B. = Reserved: [n]
  Router Lifetime: [n]s
  Reachable Time: [n]ms
  Retrans Timer: [n]ms
  +ICMPv6 Option (Prefix information : [prefix]/[length])
      Type: Prefix information (3)
      Length: 4 (32 bytes)
      Prefix Length: [n]
      +Flags: 0x[2 hex digits]
          B... .... = On-link: [Set|Not set]
          .B.. .... = Autonomous address configuration: [Set|Not set]
          ..B. .... = Router address: [Set|Not set]
          ...B BBBB = Reserved: [n]
      Valid Lifetime: [value]
      Preferred Lifetime: [value]
      Reserved: [n]
      Prefix: [prefix]
  +ICMPv6 Option (MTU : [n])
      Type: MTU (5)
      Length: 1 (8 bytes)
      Reserved: [n]
      MTU: [n]
  +ICMPv6 Option (Recursive DNS server)
      Type: Recursive DNS server (25)
      Length: [units] ([bytes] bytes)
      Reserved: [n]
      Lifetime: [value]
      Recursive DNS Server: [address]
```

Supported option nodes include Source/Target Link-Layer Address, Prefix Information,
Redirected Header, MTU, Route Information, RDNSS, DNSSL, and an unknown-option fallback.
Malformed zero-length and truncated options stop safely; malformed option content is isolated
so later valid options can still be decoded.

Deeper option/protocol dissection follows the Wireshark ICMPv6 dissector:

https://gitlab.com/wireshark/wireshark/-/blob/v3.6.2/epan/dissectors/packet-icmpv6.c?ref_type=tags