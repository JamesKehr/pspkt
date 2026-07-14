# DHCP / DHCPv6 Parser Reference

This document describes the `DHCP` and `DHCPv6` output produced by the pspkt parsers across
every parsing level. It reflects what the code actually emits.

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

- Hex (`0x`): Transaction ID / XID (v4 8 hex digits, v6 6 hex digits), Hardware type, Bootp flags.
- Decimal: message-type numbers, hardware address length, hops, seconds elapsed, lease/renew/rebind
  times (suffixed `s`), elapsed time (suffixed `ms`), option codes.
- **XID** is rendered `0x`-prefixed for **both** families in the one-liners (matching the
  Analysis Details `Transaction ID: 0x[h]`).
- **CID** (DHCPv6 Client Identifier / DUID) is rendered as hyphen-separated lowercase hex bytes
  (e.g. `00-01-00-01-2a-bb-...`); `?` is shown when the option is absent.
- Message-type names use the **uppercase** spelling from the tables below (DISCOVER, OFFER,
  SOLICIT, ADVERTISE, ...).

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Special Notes

- The parser, except for `Minimal`, must read DHCP `Option 53` to get an accurate DHCP message type ([Type]).
- The DHCP message type table:

+-------+-------------------+
| Value | Message Type      |
+-------+-------------------+
| 1     | DISCOVER          |
| 2     | OFFER             |
| 3     | REQUEST           |
| 4     | DECLINE           |
| 5     | ACK               |
| 6     | NAK               |
| 7     | RELEASE           |
| 8     | INFORM            |
+-------+-------------------+


- The parser, except for `Minimal`, must read DHCPv6 message type ([Type]).
- The DHCPv6 message type table:

+-------+---------------------------+
| Value | DHCPv6 Message Type       |
+-------+---------------------------+
|     1 | SOLICIT                   |
|     2 | ADVERTISE                 |
|     3 | REQUEST                   |
|     4 | CONFIRM                   |
|     5 | RENEW                     |
|     6 | REBIND                    |
|     7 | REPLY                     |
|     8 | RELEASE                   |
|     9 | DECLINE                   |
|    10 | RECONFIGURE               |
|    11 | INFORMATION-REQUEST       |
|    12 | RELAY-FORW                |
|    13 | RELAY-REPL                |
|    14 | LEASEQUERY                |
|    15 | LEASEQUERY-REPLY          |
|    16 | LEASEQUERY-DONE           |
|    17 | LEASEQUERY-DATA           |
|    18 | RECONFIGURE-REQUEST       |
|    19 | RECONFIGURE-REPLY         |
|    20 | DHCPV4-QUERY              |
|    21 | DHCPV4-RESPONSE           |
|    22 | ACTIVELEASEQUERY          |
|    23 | STARTTLS                  |
|    24 | BNDUPD                    |
|    25 | BNDREPLY                  |
|    26 | POOLREQ                   |
|    27 | POOLRESP                  |
|    28 | UPDREQ                    |
|    29 | UPDREQALL                 |
|    30 | UPDDONE                   |
|    31 | CONNECT                   |
|    32 | CONNECTREPLY              |
|    33 | DISCONNECT                |
|    34 | STATE                     |
|    35 | CONTACT                   |
+-------+---------------------------+

- Only a single message type per packet.


# Levels

## Minimal

### DHCPv4

`DHCP`

### DHCPv6

`DHCPv6`


## Default

### DHCPv4

`DHCP [Type], XID: [Transaction ID], chaddr: [Client MAC address]`

### DHCPv6

`DHCPv6 [Type], XID: 0x[Transaction ID], CID: [Client Identifier]`


## Detailed

### DHCPv4

#### DISCOVER

`DHCP DISCOVER, XID: [Transaction ID], chaddr: [Client MAC address], [IF "OPTION 50" is present, THEN print "Requested: [Requested IP address]"]`

#### OFFER

`DHCP OFFER, XID: [Transaction ID], chaddr: [Client MAC address], yiaddr: [yiaddr]`

#### REQUEST

`DHCP REQUEST, XID: [Transaction ID], chaddr: [Client MAC address], Requested: [Requested IP address]`

#### ACK

`DHCP ACK, XID: [Transaction ID], chaddr: [Client MAC address], yiaddr: [yiaddr]`


### DHCPv6

#### SOLICIT

`DHCPv6 SOLICIT, XID: [Transaction ID], CID: [Client Identifier]`

#### ADVERTISE

`DHCPv6 ADVERTISE, XID: [Transaction ID], CID: [Client Identifier], IAA: [IA Address]`

#### REQUEST

`DHCPv6 REQUEST, XID: [Transaction ID], CID: [Client Identifier], IAA: [IA Address]`

#### REPLY

`DHCPv6 REPLY, XID: [Transaction ID], CID: [Client Identifier], IAA: [IA Address]`

## Analysis

### Text Box

Same as `Detailed`.

### Details: Collapsed

Same as `Detailed`.

### Details: Expanded

#### DHCPv4

```
DHCP [Message Type from option 53]
  [See `DHCPv4: COMMON`]
  [See `OPTIONS`]
```

#### DHCPv4: COMMON

This is the common format for DHCP's base parsing.

```
  Message type: [Message type] ([n])
  Hardware type: [Hardware type] (0x[h])
  Hardware address length: [n]
  Hops: [n]
  Transaction ID: 0x[h]
  Seconds elapsed: [n]
  Bootp flags: 0x[h] ([Bootp flags as string])
  Client IP address: [addr]
  Your (client) IP address: [addr]
  Next server IP address: [addr]
  Relay agent IP address: [addr]
  Client MAC address: [MAC]
```

#### DHCPv6

```
DHCPv6 [Message Type]
  [See `DHCPv6: COMMON`]
  [See `OPTIONS`]
```

#### DHCPv6: COMMON



```
DHCPv6
    Message type: [Message Type] ([Message Type ID])
    Transaction ID: 0x[h]
```

#### OPTIONS

For both DHCP and DHCPv6 the options are rendered under a single expandable `Options` node
(one child leaf per option), inspired by the Wireshark dissectors. Common options are decoded
to a named, typed value; unrecognized options fall back to `[name] ([code]): len [n]`.

Each child leaf is formatted `[Option name] ([code]): [value]`, e.g.:

```
[+|-]Options
  DHCP Message Type (53): OFFER (2)
  DHCP Server Identifier (54): 192.168.1.1
  IP Address Lease Time (51): 3600s
  Router (3): 192.168.1.1
  Domain Name Server (6): 8.8.8.8
  End (255)
```

```
[+|-]Options
  Client Identifier (1): 00-01-00-01-2a-bb-cc-dd-aa-bb-cc-dd-ee-ff
  Identity Association for Non-temporary Address (3): IAADDR 2001:db8::5
```

Full per-option dissection follows the Wireshark dissectors:

DHCP dissector: https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dhcp.c?ref_type=heads

DHCPv6 dissector: https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dhcpv6.c?ref_type=heads