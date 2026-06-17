# Application Filters — DNS

This page documents the DNS application-layer display filter parameters on `Start-Pspkt`. See [Application-Filters](./Application-Filters.md) for the cross-protocol overview, including scope, requirements, and pcapng semantics.

DNS filters are evaluated against the **first question** of each UDP DNS or mDNS packet (ports 53 and 5353). All non-empty parameters are **AND-combined**; within a multi-value parameter (e.g. `-DnsType A,AAAA`) any matching value satisfies that parameter.

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-DnsName` | `string[]` | Regex pattern(s), matched case-insensitively against the question QNAME with the trailing dot stripped. Multiple values are OR-combined (each is wrapped in a non-capturing group then joined with `\|`). Implies the `-DNS` quick filter so DNS packets actually reach the consumer. |
| `-DnsType` | `string[]` | QTYPE filter. Accepts names (`A`, `AAAA`, `CNAME`, `MX`, `SRV`, `TXT`, `SOA`, `NS`, `PTR`, `HTTPS`, `ANY`, `CAA`, `OPT`, `NAPTR`, `DS`, `RRSIG`, `NSEC`, `DNSKEY`), integers (`1`, `28`, `15`), or hex strings (`0x1c`). Multiple values are OR-combined. |
| `-DnsRcode` | `string[]` | RCODE filter on responses. Accepts names (`NoError`, `FormErr`, `ServFail`, `NXDomain`, `NotImp`, `Refused`) or integers. Multiple values are OR-combined. **Queries (QR=0) are not filtered by this** — the field is consulted only for responses. |
| `-DnsId` | `int[]` | DNS transaction ID(s). Multiple values are OR-combined. |
| `-DnsQR` | `string` | Restrict to one side of the exchange. `Query`, `Response`, or `Any` (default). |
| `-DnsMatchTruncated` | `switch` | When set, packets whose DNS parse couldn't be completed (header missing, or name truncated mid-label by `-PacketSize`) match the predicate anyway. Default is to drop truncated packets so partial-match false negatives don't surprise the user. |

## Auto-bumps

When any of the parameters above is supplied:

1. **`-ParsingLevel` is auto-bumped to `Detailed`** if currently `Minimal` or `Default`. The new value is printed as a `Write-Warning`.
2. **`-PacketSize` is auto-bumped to 1500 bytes** if the user-supplied value is below that. `-PacketSize 0` (full-packet capture) is preserved.
3. **The `-DNS` quick filter is implied.** UDP and TCP port-53 capture filters are added so DNS traffic actually reaches the consumer. (Without these, the driver would silently drop DNS packets and the display filter would match nothing.) An explicit `-DNS` continues to work; it just doesn't add the filters twice.

Pass `-NoWarning` to silence the auto-bump warnings without affecting operational warnings (such as pcapng data-loss notices).

## Examples

### Filter by name

```powershell
# Show only DNS traffic that mentions 'example.com' anywhere in the name.
pspkt -DnsName 'example\.com'

# Anchored: only the apex and direct subdomains of contoso.com.
pspkt -DnsName '^([^.]+\.)?contoso\.com$'

# Multiple patterns — OR-combined.
pspkt -DnsName 'github\.com','githubusercontent\.com'
```

### Filter by type

```powershell
# Only A or AAAA queries/responses.
pspkt -DnsType A,AAAA

# By number — equivalent to -DnsType A.
pspkt -DnsType 1

# Hex form (RFC-style).
pspkt -DnsType 0x1c          # AAAA
```

### Filter by response code

```powershell
# Only responses indicating a failure.
pspkt -DnsRcode NXDomain,ServFail
```

### Combine fields (AND)

```powershell
# AAAA queries for any .corp.contoso.com host. Both -DnsType AND -DnsName must match.
pspkt -DnsType AAAA -DnsName '\.corp\.contoso\.com$'
```

### Restrict to one side

```powershell
# Queries only.
pspkt -DnsName 'github\.com' -DnsQR Query

# Responses only — useful to see NXDomain bursts without the originating queries.
pspkt -DnsRcode NXDomain -DnsQR Response
```

### Combine with the IPAddress quick filter

The `-IPAddress` parameter AND-merges into every capture filter, so it composes naturally with display filters:

```powershell
# DNS to/from 1.1.1.1 only, narrowed on the display side to AAAA queries.
pspkt -DnsType AAAA -i 1.1.1.1
```

### Capture more payload when names are long

```powershell
# Active Directory queries can exceed 1500 bytes; ask for the full packet.
pspkt -DnsName '_msdcs\.' -PacketSize 0
```

### Allow partial / truncated matches

```powershell
# Show every DNS packet, even those whose name couldn't be fully decoded
# because -PacketSize cut off the question section.
pspkt -DnsName '.*' -DnsMatchTruncated
```

### Quiet mode (suppress setup warnings)

```powershell
# Same as above, but without the "auto-bumping -ParsingLevel" / "auto-bumping
# -PacketSize" warnings. Pcapng-drop and writer-error warnings are unaffected.
pspkt -DnsType AAAA -NoWarning
```

## How it works

- The driver-level capture filter (added automatically by the implied `-DNS`) keeps only DNS port traffic.
- For each surviving UDP DNS packet, the consumer thread calls `DnsParser.TryParseDns` once to extract the header, first-question name and type, response code, and a pre-formatted first-answer string.
- The predicate (`DnsAppPredicate.Evaluate`) is called against the parsed `DnsContext`. On reject, the consumer returns `false` from `FormatSinglePacketInto`, and `FormatBatch` rolls back the partial StringBuilder content so nothing is emitted.
- On match, the parsed context is reused by the formatter — only one parse per matching packet.
- The pcapng writer is unaffected; the file contains every packet the driver filter accepted.

## Performance notes

- When no `-Dns*` parameter is set, the only hot-path cost is a single null-check on the predicate field, which is branch-predicted false and effectively free.
- When a predicate is active and rejects a packet, the entire detailed-format pipeline is skipped for that packet (IPv4 path) or rolled back (IPv6 path). High rejection rates can actually run slightly faster than no-filter.
- The QNAME regex is compiled once with `RegexOptions.Compiled | RegexOptions.IgnoreCase` and reused for the lifetime of the capture.

## See also

- [Application-Filters](./Application-Filters.md) — cross-protocol overview
- [Start-Pspkt](./Start-Pspkt.md) — full command reference
- [Quick Filters](./Quick-Filters.md) — `-DNS`/`-SMB`/etc.
