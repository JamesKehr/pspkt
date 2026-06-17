# Application Filters — TLS / SNI

This page documents the TLS application-layer display filter parameters on `Start-Pspkt`. See [Application-Filters](./Application-Filters.md) for the cross-protocol overview, including scope, requirements, and pcapng semantics.

TLS filters are evaluated against each individual TLS record. Records below the recognised TLS ports (443, 8443, 993, 995, 465, 636) are inspected; other TCP traffic passes through without filtering — see *Standard ports only* below.

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-TlsSni` | `string[]` | Regex pattern(s), matched case-insensitively against the ClientHello SNI hostname. Multiple values are OR-combined. **SNI is only present in ClientHello records**; non-ClientHello traffic (ServerHello, Certificate, AppData, Alert, ChangeCipherSpec) is rejected when this is set. Implies the `-HTTPS` quick filter (TCP 443) when no other capture filter is configured. |
| `-TlsVersion` | `string[]` | TLS record version filter. Accepts short forms (`1.0`, `1.1`, `1.2`, `1.3`), long forms (`TLS1.2`, `SSL3.0`), integers (`770`), or hex strings (`0x0303`). Multiple values are OR-combined. **Note:** the record-layer version stays `0x0303` (TLS 1.2) on the wire even for TLS 1.3 traffic — true 1.3 negotiation lives in the `supported_versions` extension. Use `-TlsHandshakeType ClientHello -TlsSni ...` plus packet-level inspection for genuine 1.3 detection. |
| `-TlsContentType` | `string[]` | TLS record content type. Accepts names (`ChangeCipherSpec`, `Alert`, `Handshake`, `ApplicationData` / `AppData`) or integers (20-23). Multiple values are OR-combined. |
| `-TlsHandshakeType` | `string[]` | TLS handshake message type. Accepts names (`ClientHello`, `ServerHello`, `Certificate`, `Finished`, `ServerKeyExchange`, `ClientKeyExchange`, `CertificateVerify`, `CertificateRequest`, `EncryptedExtensions`, `NewSessionTicket`, `ServerHelloDone`, `HelloRequest`) or integers. Multiple values are OR-combined. **Implicitly restricts to Handshake records** (ContentType 22). |
| `-TlsMatchTruncated` | `switch` | When set, ClientHello records whose SNI extension couldn't be reached because the packet was truncated still match the `-TlsSni` filter. Default is to drop truncated records so a partial-match false negative isn't silent. |

## Auto-bumps

When any of the parameters above is supplied:

1. **`-ParsingLevel` is auto-bumped to `Detailed`** if currently `Minimal` or `Default`. The new value is printed as a `Write-Warning`.
2. **`-PacketSize` is auto-bumped to 2048 bytes** if the user-supplied value is below that. (Modern ClientHellos with ALPN + supported_versions + key_share + post-quantum + ECH extensions routinely exceed 1500.) `-PacketSize 0` (full-packet capture) is preserved.
3. **The `-HTTPS` quick filter is implied** *unless an existing capture filter already covers TCP 443*. So combining `-DNSoverHTTPS` (which adds TCP 443 already) with a `-TlsSni` predicate doesn't add a redundant filter, but combining with `-ARP` / `-Ping` / `-DNSoverTLS` does add `-HTTPS` (those don't cover TCP 443). When auto-implied, the filter is named `QF-HTTPS-TLS` in the capture summary.

Pass `-NoWarning` to silence the auto-bump warnings without affecting operational warnings.

## Standard ports only

The TLS predicate only fires for packets on the recognised TLS ports — **443, 8443, 993, 995, 465, 636**. Packets on other TCP ports (e.g. a TLS service on port 9999) bypass the predicate and are displayed unfiltered. To narrow the capture to a non-standard TLS port, add a kernel capture filter:

```powershell
$f = New-PspktFilter -Name 'TLS-9999' -TransportProtocol TCP -Port1 9999
$session = New-PspktSession -Name 'tls-custom'
Add-PspktFilter -Session $session -Filter $f
Start-Pspkt -Session $session -pl Detailed
```

This v1 limitation is documented; a future revision may expose a `-TlsPort` parameter to extend the predicate's known-port set.

## Examples

### Filter by SNI

```powershell
# All TLS handshakes naming example.com or any subdomain.
pspkt -TlsSni '\.?example\.com$'

# Anchored alternation — only github.com or githubusercontent.com.
pspkt -TlsSni '^github\.com$','^githubusercontent\.com$'

# Wildcard — any handshake that has an SNI (excludes non-ClientHello records).
pspkt -TlsSni '.+'
```

### Filter by handshake type

```powershell
# Only ClientHello and ServerHello records — useful for cert/cipher debugging.
pspkt -TlsHandshakeType ClientHello,ServerHello

# Show only Certificate records.
pspkt -TlsHandshakeType Certificate
```

### Filter by record type

```powershell
# Skip the noisy AppData records, keep handshake + alerts.
pspkt -TlsContentType Handshake,Alert

# Only Alert records — useful when investigating TLS failures.
pspkt -TlsContentType Alert
```

### Filter by version

```powershell
# Only TLS 1.2 records.
pspkt -TlsVersion 1.2

# Multiple versions via numeric form.
pspkt -TlsVersion 0x0303,0x0304
```

### Combine fields (AND)

```powershell
# ClientHellos for *.contoso.com running on TLS 1.2.
pspkt -TlsSni '\.contoso\.com$' -TlsVersion 1.2
```

### Combine with the IPAddress quick filter

```powershell
# TLS handshakes for *.example.com against a specific server.
pspkt -TlsSni '\.example\.com$' -i 203.0.113.10
```

### Pair with a non-standard TLS port

```powershell
# Capture only port 8443; predicate matches normally since 8443 is a known TLS port.
pspkt -DnsName '\.example\.com$' -PacketSize 0  # add an explicit -TlsSni instead if needed
```

### Allow truncated SNI matches

```powershell
# Match a ClientHello even when its extension block ran past -PacketSize.
pspkt -TlsSni '.*' -TlsMatchTruncated
```

### Quiet mode

```powershell
# Suppress the "auto-bumping" warnings on a long-running script.
pspkt -TlsSni '\.contoso\.com$' -NoWarning
```

## How it works

- The kernel capture filter (added automatically by the implied `-HTTPS` when no other filter is set) keeps only TCP/443 traffic.
- For each surviving TCP packet on a recognised TLS port, the consumer thread calls `TlsParser.TryParseTls` once. The parsed `TlsContext` includes ContentType, Version, RecordLen, HandshakeType (for Handshake records), and SNI (for ClientHello records).
- `TlsAppPredicate.Evaluate` runs against the parsed context. On reject, the consumer returns `false` and `FormatBatch` rolls back the partial StringBuilder content so no line is emitted.
- On accept, the parsed context is reused by the formatter — only one parse per matching packet.
- The pcapng writer is unaffected; the file contains every packet the driver filter accepted.

## Performance notes

- When no `-Tls*` parameter is set, the only hot-path cost is a single null-check on the predicate field, which is branch-predicted false and effectively free.
- When a predicate is active and rejects a packet on the IPv4 fast path, the entire detailed-format pipeline is skipped for that packet. High rejection rates can run slightly faster than no-filter.
- The SNI regex is compiled once with `RegexOptions.Compiled | RegexOptions.IgnoreCase` and reused for the lifetime of the capture.

## See also

- [Application-Filters](./Application-Filters.md) — cross-protocol overview
- [Application-Filters-DNS](./Application-Filters-DNS.md) — sibling predicate, same architecture
- [Start-Pspkt](./Start-Pspkt.md) — full command reference
