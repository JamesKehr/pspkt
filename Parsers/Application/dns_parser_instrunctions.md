# DNS Parser Reference

This document describes the **final** DNS output produced by the pspkt DNS parsers
(`Parsers/Application/dns.cs`), across every parsing level. It reflects what the code
actually emits.

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

- Hex (`0x`): Transaction ID, Flags, Class value, OPT extended-RCODE, OPT Z.
- Decimal: RR counts (Question / Answer / Authority / Additional), RR type number, TTL,
  OPT UDP payload size, EDNS0 version, MX preference, SRV priority/weight/port, SOA numeric
  fields.
- The one-line RR count triple is **Answer/Authority/Additional** (`[An]/[Ns]/[Ar]`).
- mDNS (port 5353) uses the prefix `mDNS` in place of `DNS`.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Levels

## Minimal

Protocol name only:

```
DNS
```

## Default

One line. Answer/Authority/Additional counts; no trailing byte-count suffix:

```
DNS: [Transaction ID] [An]/[Ns]/[Ar] [Query name] [Answer type] [Answer data]
```

- Query (no answer — the question type fills the answer-type slot):

  ```
  DNS: 0x1234 0/0/0 example.com. A
  ```

- Response:

  ```
  DNS: 0x1234 1/0/0 example.com. A 93.184.216.34
  ```

- Error response (RCODE != 0): the response code name is inserted before the answer:

  ```
  DNS: 0x1234 0/0/0 NXDomain example.com. A
  ```

## Detailed

Same fields as Default but with the ` - ` separator (matching the other Detailed
sub-lines, e.g. `IPv4 - ...`, `UDP - ...`):

```
DNS - [Transaction ID] [An]/[Ns]/[Ar] [Query name] [Answer type] [Answer data]
```

## Analysis

### Text Box

DNS is parsed at the **Default** level (`DNS: ...`).

### Details: collapsed

When the DNS node is collapsed it shows the **Detailed** one-liner:

```
DNS - [Transaction ID] [An]/[Ns]/[Ar] [Query name] [Answer type] [Answer data]
```

### Details: default expanded view

The DNS node is expanded, the verbose `Flags` node and every resource-record one-liner are
**collapsed** by default, and the section nodes (`Queries`, `Answers`, ...) are expanded:

```
-DNS - 0xe309 1/0/0 microsoft.com. A 150.171.109.115
      Transaction ID: 0xe309
    +Flags: 0x8180 Query response, No error
      RR Count - Qry: 1, Ans: 1, Auth: 0, Adtl: 0
    -Queries
      +microsoft.com.: type A, class IN
    -Answers
      +microsoft.com.: type A, class IN, 150.171.109.115
```

### Details: fully expanded

```
-DNS - [Detailed one-liner]
      Transaction ID: 0x[hex ID]
    -Flags: 0x[hex] [Query | Query response, [Error string]]
        [flag bit lines — see Flags sections]
      RR Count - Qry: [Question], Ans: [Answer], Auth: [Authority], Adtl: [Additional]
    -Queries
      [one node per question — see RR: Queries]
    -Answers
      [one node per answer — see RR: Answers]
    -Authoritative nameservers
      [one node per authority record — same shape as Answers]
    -Additional records
      [one node per additional record — same shape as Answers; OPT is special]
```

Section nodes are only emitted when their count is non-zero.

#### RR: Queries

One collapsible node per question:

```
-[Query name]: type [RR type string], class [Class string]
    Name: [Query name]
    Type: [RR type string] ([RR type number])
    Class: [Class string] (0x[Class hex])
```

#### RR: Answers

One collapsible node per answer. The node header appends a short summary of the parsed
RDATA:

```
-[RR name]: type [RR type string], class [Class string], [Parsed summary]
    Name: [RR name]
    Type: [RR type string] ([RR type number])
    Class: [Class string] (0x[Class hex])
    Time to live: [TTL in seconds]
    [Parsed RDATA leaves]
```

Parsed RDATA leaves by record type:

| Type | Leaves |
|------|--------|
| A (1) | `Address: [IPv4]` |
| AAAA (28) | `Address: [IPv6]` |
| CNAME (5) | `CNAME: [name]` |
| NS (2) | `Name Server: [name]` |
| PTR (12) | `Domain Name: [name]` |
| MX (15) | `Preference: [n]`, `Mail Exchange: [name]` |
| TXT (16) | `TXT: [string]` (repeated per character-string) |
| SOA (6) | `Primary name server: [name]`, `Responsible authority's mailbox: [name]`, `Serial number: [n]`, `Refresh interval: [n]`, `Retry interval: [n]`, `Expire limit: [n]`, `Minimum TTL: [n]` |
| SRV (33) | `Priority: [n]`, `Weight: [n]`, `Port: [n]`, `Target: [name]` |
| CAA (257) | `Flags: 0x[hex]`, `Tag: [tag]`, `Value: [value]` |
| any other | `Data: [hex stream of the RDATA]` |

#### RR: Authority

Same node shape as **Answers**, under the `Authoritative nameservers` section.

#### RR: Additional

Same node shape as **Answers**, under the `Additional records` section, except for the
EDNS0 OPT pseudo-record.

**OPT (type 41) / EDNS0:**

```
-<Root>: type OPT
    Name: <Root>
    Type: OPT (41)
    UDP payload size: [payload size]
    Higher bits in extended RCODE: 0x[hex]
    EDNS0 version: [version]
    -Z: 0x[hex]
        B... .... .... .... = DO bit: [Accepts|Does not accept] DNSSEC security RRs
        .BBB BBBB BBBB BBBB = Reserved: 0x[hex]
    Data length: [length]
```

Any unrecognised record type falls back to the generic `Data: [hex]` leaf shown above.

#### Flags: Query

```
-Flags: 0x[hex] Query
    0... .... .... .... = Response: Query
    .BBB B... .... .... = Opcode: [opcode string] ([opcode])
    .... ..B. .... .... = Truncated: Message is [truncated|not truncated]
    .... ...B .... .... = Recursion desired: [Do|Do not] query recursively
    .... .... .B.. .... = Z: reserved (0)
    .... .... ...B .... = Non-authenticated data: [Acceptable|Unacceptable]
```

#### Flags: Response

```
-Flags: 0x[hex] Query response, [Error string]
    1... .... .... .... = Response: Response
    .BBB B... .... .... = Opcode: [opcode string] ([opcode])
    .... .B.. .... .... = Authoritative: Server [is|is not] an authority for domain
    .... ..B. .... .... = Truncated: Message [is|is not] truncated
    .... ...B .... .... = Recursion desired: [Do|Do not] query recursively
    .... .... B... .... = Recursion available: Server [can|cannot] do recursive queries
    .... .... .B.. .... = Z: reserved (0)
    .... .... ..B. .... = Answer authenticated: Answer/authority portion [was|was not] authenticated by the server
    .... .... ...B .... = Non-authenticated data: [Acceptable|Unacceptable]
    .... .... .... BBBB = Reply code: [Error string] ([Error code])
```

**Opcode strings:** 0 = `Standard query`, 1 = `Inverse query`, 2 = `Server status request`,
4 = `Notify`, 5 = `Dynamic update`, otherwise `Unknown`.

**Error strings (RCODE):** 0 = `No error`, 1 = `Format error`, 2 = `Server failure`,
3 = `No such name`, 4 = `Not implemented`, 5 = `Refused`, otherwise `Reply code [n]`.
