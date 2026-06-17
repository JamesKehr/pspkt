# Application Filters — HTTP

This page documents the HTTP application-layer display filter parameters on `Start-Pspkt`. See [Application-Filters](./Application-Filters.md) for the cross-protocol overview, including scope, requirements, and pcapng semantics.

HTTP filters are evaluated against each packet whose first bytes look like an HTTP/1.x request line or status line, on the recognised HTTP ports — **80, 8080, 8000, 8888**. Modern web traffic is overwhelmingly HTTPS (TLS-wrapped), which appears encrypted to pspkt — use [Application-Filters-TLS](./Application-Filters-TLS.md) (`-TlsSni`) for that. HTTP filtering applies only to cleartext HTTP/1.x traffic.

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-HttpMethod` | `string[]` | HTTP method names. Standard names (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`) are recognised; custom verbs (e.g. WebDAV's `PROPFIND`) are also accepted as-is. Case-insensitive on input, normalised to uppercase. Multiple values are OR-combined. **Implies request-only matching** — response packets are rejected. |
| `-HttpHost` | `string[]` | Regex pattern(s) matched case-insensitively against the request `Host:` header. Multiple values are OR-combined. **Implies request-only matching.** |
| `-HttpPath` | `string[]` | Regex pattern(s) matched case-insensitively against the request path (URI + optional query string). Multiple values are OR-combined. **Implies request-only matching.** |
| `-HttpStatus` | `string[]` | HTTP response status. Accepts exact codes (`200`, `404`, `503`), class patterns (`1xx`, `2xx`, `3xx`, `4xx`, `5xx`), or hex strings (`0x1f4`). Multiple values are OR-combined. **Implies response-only matching.** |
| `-HttpContentType` | `string[]` | Regex pattern(s) matched case-insensitively against the `Content-Type:` header on either side. Multiple values are OR-combined. |
| `-HttpMatchTruncated` | `switch` | When set, packets whose HTTP header section couldn't be reached (typically because `-PacketSize` cut the payload mid-headers) match the predicate anyway. Default is to drop truncated packets so a partial-match false negative isn't silent. |

## Request vs response

The predicate enforces a strict request/response split:

- `-HttpMethod`, `-HttpHost`, `-HttpPath` — **request side**. Response packets that don't carry these fields are rejected as soon as any one of them is set.
- `-HttpStatus` — **response side**. Request packets are rejected.
- `-HttpContentType` — **either side**. Matches against the `Content-Type` header on requests AND responses.
- Setting *both* a request-side and a response-side filter simultaneously rejects every packet (since no packet is both). This is intentional — if you genuinely want "GET requests OR 404 responses" you must run two captures, or use `Get-PspktSession`'s pipeline.

## Auto-bumps

When any of the parameters above is supplied:

1. **`-ParsingLevel` is auto-bumped to `Detailed`** if currently `Minimal` or `Default`. The new value is printed as a `Write-Warning`.
2. **`-PacketSize` is auto-bumped to 2048 bytes** if the user-supplied value is below that. HTTP requests with cookies, bearer tokens, or many headers routinely exceed 1500. `-PacketSize 0` (full-packet capture) is preserved.
3. **The `-HTTP` quick filter (TCP 80) is implied** *unless an existing capture filter already covers TCP 80*. Combining with an unrelated filter (e.g. `-ARP`, `-Ping`, `-DNS`) does NOT suppress the auto-imply — the implied filter widens capture so the HTTP predicate has packets to evaluate, while pktmon's OR-combined filtering still passes the user's other selections through. When auto-implied, the filter is named `QF-HTTP-AUTO` in the capture summary.

Pass `-NoWarning` to silence the auto-bump warnings without affecting operational warnings.

## Cleartext only

HTTP filtering applies to **cleartext HTTP/1.x** on the recognised ports. The predicate has no visibility into:

- **HTTPS / TLS-wrapped HTTP** — payload is encrypted. Use `-TlsSni` to filter on the SNI hostname instead.
- **HTTP/2** — binary framing (HPACK-compressed headers). The predicate's first-line check rejects HTTP/2 client preface (`PRI * HTTP/2.0`) immediately, so HTTP/2 connections produce no matches.
- **HTTP/3 (QUIC)** — encrypted application-layer protocol over UDP.

To filter on a non-standard cleartext HTTP port (e.g. 5000, 5500, 9000), add a manual capture filter:

```powershell
$f = New-PspktFilter -Name 'HTTP-5000' -TransportProtocol TCP -Port1 5000
$session = New-PspktSession -Name 'http-custom'
Add-PspktFilter -Session $session -Filter $f
Start-Pspkt -Session $session -pl Detailed
```

The capture is then constrained to the port via the kernel filter; the predicate still requires the payload to look like HTTP/1.x for the fast path to apply on that port.

## Examples

### Filter by method

```powershell
# Only GET requests.
pspkt -HttpMethod GET

# Mutations only (state-changing requests).
pspkt -HttpMethod POST,PUT,DELETE,PATCH

# WebDAV — custom verb works without modification.
pspkt -HttpMethod PROPFIND,MKCOL,COPY,MOVE
```

### Filter by host

```powershell
# Anything routed at api.example.com.
pspkt -HttpHost '^api\.example\.com$'

# Multiple hosts via OR-combined patterns.
pspkt -HttpHost 'github\.com$','githubusercontent\.com$'
```

### Filter by path

```powershell
# Any request under /api/v1/.
pspkt -HttpPath '^/api/v1/'

# Health-check probes.
pspkt -HttpPath '^/health$','^/ping$','^/_ready$'
```

### Filter by status code or class

```powershell
# Server errors.
pspkt -HttpStatus 5xx

# Specific failure codes.
pspkt -HttpStatus 401,403,404,429,503

# Combined: any 4xx OR 503.
pspkt -HttpStatus 4xx,503
```

### Filter by content type

```powershell
# Only JSON payloads (both requests and responses).
pspkt -HttpContentType 'application/json'

# Any image content.
pspkt -HttpContentType '^image/'
```

### Combine fields (AND)

```powershell
# GET requests for /api/* on the api host.
pspkt -HttpMethod GET -HttpPath '^/api/' -HttpHost 'api\.example\.com$'

# DELETE requests with JSON bodies.
pspkt -HttpMethod DELETE -HttpContentType 'application/json'
```

### Combine with -IPAddress

```powershell
# Requests for api.example.com against a specific server IP.
pspkt -HttpHost 'api\.example\.com$' -i 203.0.113.10
```

### Capture full packets for headers that don't fit in 2048 bytes

```powershell
# Large session cookies / Authorization: Bearer tokens.
pspkt -HttpHost '\.example\.com$' -PacketSize 0
```

### Allow truncated matches

```powershell
# Treat truncated header blocks as matching anyway.
pspkt -HttpMethod POST -HttpMatchTruncated
```

### Quiet mode

```powershell
# Suppress the "auto-bumping" setup warnings.
pspkt -HttpStatus 5xx -NoWarning
```

## How it works

- The kernel capture filter (added automatically by the implied `-HTTP` when no other filter is set) keeps only TCP/80 traffic.
- For each surviving TCP packet on a recognised HTTP port, the consumer thread calls `HttpParser.TryParseHttp` once. The parsed `HttpContext` includes request-line (method, path, version) **or** status-line (code, reason, version) fields, plus the `Host`, `Content-Type`, and `Content-Length` headers when they fit within the first ~1 KiB of payload.
- `HttpAppPredicate.Evaluate` runs against the parsed context. On reject, the consumer returns `false` and `FormatBatch` rolls back the partial StringBuilder content so no line is emitted.
- On accept, the parsed context is reused by the formatter — only one parse per matching packet.
- The pcapng writer is unaffected; the file contains every packet the driver filter accepted.

## Performance notes

- When no `-Http*` parameter is set, the only hot-path cost is a single null-check on the predicate field, which is branch-predicted false and effectively free.
- When a predicate is active and rejects a packet on the IPv4 fast path, the entire detailed-format pipeline is skipped for that packet. High rejection rates can run slightly faster than no-filter.
- All regexes are compiled once with `RegexOptions.Compiled | RegexOptions.IgnoreCase` and reused for the lifetime of the capture.
- Header parsing is capped at the first 1 KiB of payload to prevent pathological packets from causing arbitrary scan distances.

## See also

- [Application-Filters](./Application-Filters.md) — cross-protocol overview
- [Application-Filters-DNS](./Application-Filters-DNS.md) — sibling predicate, same architecture
- [Application-Filters-TLS](./Application-Filters-TLS.md) — for HTTPS / encrypted HTTP, filter by SNI instead
- [Start-Pspkt](./Start-Pspkt.md) — full command reference
