# TLS Parser Reference

This document describes the `TLS` output produced by the pspkt parsers across every parsing
level. It reflects what the code actually emits. The record/handshake/extension field naming
follows Wireshark's TLS dissector (`epan/dissectors/packet-tls.c`).

## Notation used in this document

- `[value]` marks a parsed value that is substituted at runtime. The square brackets are
  **not** printed.
- `[a|b]` is a conditional: the first word when the condition holds, the second otherwise.
- `[+|-]` in the tree examples marks a collapsible node: `+` when collapsed, `-` when expanded.

## What is parsed

The parser reads the **TLS record layer** directly off the TCP stream, so it applies to *any*
TCP connection carrying real TLS records — HTTPS (443), IMAPS (993), POP3S (995), SMTPS (465),
LDAPS (636), a STARTTLS-upgraded connection, or a TLS service on any arbitrary port. Detection
is **content-based** (`TlsParser.LooksLikeTls`: content type 20–23 and record version
0x0300–0x0304), not port-based, at the Default, Detailed, and Analysis levels.

Fields decoded:

- **Record layer:** content type, version, length. One record per node; a TCP segment may carry
  several records (each gets its own node).
- **Handshake:** message type + length. `ClientHello` and `ServerHello` bodies are decoded
  (legacy version, random, session id, cipher suites, compression methods, extensions). Other
  handshake types show type + length only.
- **Extensions:** every extension shows its type + length; `server_name` (SNI),
  `supported_versions`, and `application_layer_protocol_negotiation` (ALPN) have their inner
  values decoded. `supported_versions` is the reliable source of the *true* negotiated version
  (the record-layer version stays 0x0303 on the wire even for TLS 1.3).
- **Alert:** level + description (symbolic names).
- **ChangeCipherSpec / ApplicationData:** a single summary line (AppData is encrypted, so only
  its byte length is shown).

## Value formatting

- Decimal: record length, handshake length, extension length, cipher-suite / compression counts.
- Hex: version (`0x0303`), cipher suite (`0x1301`), extension type in the unknown fallback,
  `Random` / `Session ID` byte previews (lowercase, no separators, truncated with `...`).
- Cipher suites and extensions use their IANA symbolic names; unknown codes fall back to
  `Unknown` (cipher) or `unknown (0x####)` (extension). GREASE values render as `GREASE`.

## Notes

- **SNI is only in ClientHello.** ServerHello and later handshake messages don't carry it.
- **The Analysis Details collapsed line carries the SNI** so it is visible without expanding
  (per the pspkt Analysis convention). The Analysis Text Box uses the Default one-liner
  (level 0), which does not include the SNI.
- **Encrypted traffic is not decrypted.** Only the cleartext record framing and the
  ClientHello / ServerHello handshakes (which precede key establishment) are parsed;
  ApplicationData records show length only.
- **Payload-less segments render as plain TCP.** Because TLS is content-detected, a TCP
  segment on a TLS-wrapped port (443, 8443, 993, 995, 465, 636, 853, 5986) that carries no TLS
  record — an ACK, FIN, or bare handshake segment (`len 0`) — is a pure transport event and
  renders as a normal `TCP [flags] ...` segment, not `HTTPS: TCP ...` / `IMAPS: TCP ...`. The
  port number already identifies the tunneled service. (Same convention as HTTP, SMB2, and
  DNS-over-TCP, whose ports are likewise not hinted. WinRM on 5985 stays hinted because it is
  cleartext HTTP, not TLS.)

## Cross-segment handshake reassembly

A TLS record can span several TCP segments. Modern ClientHellos (post-quantum key shares + ECH
+ ALPN) routinely exceed one segment, so the record's **tail** segment starts mid-record — and,
parsed per-segment, would be invisible (it doesn't begin with a record header, so it renders as
plain TCP).

The parser reassembles a split **handshake** record (ContentType 22) per directional flow:

- The **head** segment (record start that overflows the segment) shows
  `TLS [Version] [HandshakeName] [reassembling]`.
- Intermediate segments show the same `[reassembling]` marker.
- The **completing** segment shows the full parse of the reassembled record — e.g. at the
  Detailed tier, `TLS ClientHello; ver: [Version]; len: [RecordLen]; SNI: [Sni]` — so the SNI
  from a split ClientHello is visible.

Only handshake records are reassembled (Alert/ChangeCipherSpec are tiny; ApplicationData is
encrypted, so there is nothing to parse beyond length). Reassembly is bounded (max one TLS
record, 16389 bytes; capped concurrent flows) and abandoned on a TCP sequence gap (the segment
then falls back to plain TCP). State is cleared at capture start.

**Requires full-payload capture.** A record can only be reassembled when *every* segment that
carries it was captured in full — the sequence number advances by the on-wire payload length, so
a truncated segment (a small `-PacketSize`) both loses bytes and breaks the sequence math.
Reassembly therefore engages only for segments whose captured length equals their IP
total-length payload; a truncated head shows the normal partial parse and starts no reassembly.
The `Analysis` level auto-raises `-PacketSize` to a **1600-byte** floor — enough to capture a full
standard-MTU Ethernet frame (1514 bytes for a 1500-byte IP packet, up to 1518 with a VLAN tag),
which a full-MSS ClientHello head needs; `-PacketSize 0` (full capture) always works. Live Default
captures keep the small default `-PacketSize`, so reassembly there needs an explicit larger
`-PacketSize`. Rare unsupported cases: a ClientHello carried in TCP Fast Open SYN data (the SYN
consumes a sequence number, so the follow-on segment looks like a gap) falls back to plain TCP;
a handshake spanning the 32-bit sequence-number wrap may retain a stale `[reassembling]` state
(the wrap can look like a retransmit) until the flow is evicted.

**Scope / limitations (current):** reassembly is applied to the **Default one-liner** — which is
what the live Default capture *and* the Analysis Text Box render. The **`-pl Detailed` one-liner**
and the **Analysis Details tree** (JIT-parsed from a single retained packet) do **not** yet
reassemble across segments; selecting the *head* segment still shows the (partial) ClientHello
tree. Full Detailed / Details-tree reassembly is tracked as future work.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (available behind the opt-in `TreeFlattener.UseConnectors` flag). Child leaves are
indented two spaces under their parent.

---

# Levels

## Minimal

Minimal shows only the packet framing, network/transport protocol, and addresses — **no
application-layer marker**, the same as the other parsed TCP protocols (HTTP, SMB2,
DNS-over-TCP). TLS is identified by the transport and the `.443` port (or whatever port the
record was seen on):

`Eth: IPv4.TCP: [src].[sport] > [dst].[dport]`

(Content-based TLS identification — the `TLS ...` line — begins at the Default level.)

## Default

Handshake record with a recognised message type:

`TLS [Version] [HandshakeName]`  — e.g. `TLS 1.2 ClientHello`

Any other record:

`TLS [Version] [ContentType], len [segmentLen]`  — e.g. `TLS 1.2 ApplicationData, len 1240`

## Detailed

`TLS [HandshakeName|ContentType]; ver: [Version]; len: [RecordLen][; SNI: [Sni]]`

Examples:

```
TLS ClientHello; ver: TLS 1.2; len: 512; SNI: www.example.com
TLS ApplicationData; ver: TLS 1.2; len: 1240
TLS Alert; ver: TLS 1.2; len: 2
```

## Analysis

### Text Box

Same as `Default` (the Text Box is rendered at level 0).

### Details: Collapsed

The record node header is the Detailed one-liner, so the collapsed view already shows the
version, length, and — for a ClientHello — the SNI:

`[+]TLS ClientHello; ver: TLS 1.2; len: 512; SNI: www.example.com`

### Details: Expanded

The record node expands to the Record Layer sub-node plus the record body (handshake / alert /
etc.). One root node is emitted per TLS record in the segment.

#### ClientHello

```
[+|-]TLS ClientHello; ver: [Version]; len: [RecordLen]; SNI: [Sni]
  [+|-]Record Layer: Handshake Protocol, Version [Version]
      Content Type: Handshake (22)
      Version: [Version] (0x[h])
      Length: [RecordLen]
  [+|-]Handshake Protocol: ClientHello
      Handshake Type: ClientHello (1)
      Length: [HandshakeLen]
      Version: [LegacyVersion] (0x[h])
      Random: [64 hex chars]
      Session ID Length: [n]
      [Session ID: [hex] — only when n > 0]
    [+|-]Cipher Suites ([n] suites)
        Cipher Suite: [Name] (0x[h])
        ...
    [+|-]Compression Methods ([n] methods)
        Compression Method: [null|n] ([n])
    [+|-]Extensions
      [+|-]Extension: server_name (len [n])
          Type: server_name (0)
          Length: [n]
          Server Name: [Sni]
      [+|-]Extension: supported_versions (len [n])
          Type: supported_versions (43)
          Length: [n]
          Supported Version: [Version] (0x[h])
      [+|-]Extension: application_layer_protocol_negotiation (len [n])
          Type: application_layer_protocol_negotiation (16)
          Length: [n]
          ALPN Protocol: [proto]
```

#### ServerHello

Same shape as ClientHello but with a single selected `Cipher Suite:` and
`Compression Method:` (no lists), and its own extensions block (the `supported_versions`
extension carries a single selected version — the true negotiated TLS version).

#### Alert

```
[+|-]TLS Alert; ver: [Version]; len: 2
  [+|-]Record Layer: Alert Protocol, Version [Version]
      Content Type: Alert (21)
      Version: [Version] (0x[h])
      Length: 2
  [+|-]Alert Message: [Level], [Description]
      Level: [Warning|Fatal] ([n])
      Description: [Name] ([n])
```

#### ApplicationData / ChangeCipherSpec

```
[+|-]TLS ApplicationData; ver: [Version]; len: [RecordLen]
  [+|-]Record Layer: ApplicationData Protocol, Version [Version]
      ...
  Encrypted Application Data: [n] bytes
```

---

# Future work - QUIC

The parser deliberately covers only **TLS records carried directly over TCP**. QUIC is out of
scope for this parser:

- **QUIC (HTTP/3, UDP 443):** QUIC negotiates TLS 1.3, but the handshake is carried inside
  QUIC's own UDP packet format. The `Initial` packet is header-protected and payload-encrypted
  with keys derived from the connection ID, so reaching the embedded TLS `ClientHello` requires
  a full QUIC long-header parse plus AEAD removal of the Initial protection. This is a separate,
  much larger effort than the TLS-over-TCP record parser and is **not** implemented. A QUIC
  parser would live alongside this one and reuse `TlsParser.BuildTlsDetailTree` for the CRYPTO
  frame contents once the QUIC layer is stripped.
SSH is also not TLS and does not match `LooksLikeTls`. Analysis mode now routes SSH
identification strings and TCP 22/29418 binary payloads to the dedicated `SshParser`; see
`SSH_parser_instructions.md`.
