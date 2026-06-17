# Application Filters — SMB2

This page documents the SMB2 application-layer display filter parameters on `Start-Pspkt`. See [Application-Filters](./Application-Filters.md) for the cross-protocol overview, including scope, requirements, and pcapng semantics.

SMB2 filters apply to TCP port 445 (Direct-TCP SMB2/SMB3). SMB1/CIFS is intentionally not supported — the parser rejects everything except the SMB2/SMB3 magic byte sequences (`\xFE SMB` and the encrypted `\xFD SMB` Transform header).

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-SmbCommand` | `string[]` | SMB2 command filter. Accepts names (`Negotiate`, `SessionSetup`, `Logoff`, `TreeConnect`, `TreeDisconnect`, `Create`, `Close`, `Flush`, `Read`, `Write`, `Lock`, `Ioctl`, `Cancel`, `Echo`, `QueryDirectory`, `ChangeNotify`, `QueryInfo`, `SetInfo`, `OplockBreak`) or integers (`0`-`18`) or hex (`0x05`). Multiple values are OR-combined. |
| `-SmbDirection` | `string` | `Request` = client→server only, `Response` = server→client only, `Any` (default) = either. |
| `-SmbStatus` | `string[]` | NT status filter. Accepts class names (`Success`, `Informational`/`Info`, `Warning`, `Error`), exact status names (`ACCESS_DENIED`, `NO_SUCH_FILE`, `OBJECT_NAME_NOT_FOUND`, `LOGON_FAILURE`, `SHARING_VIOLATION`, `BAD_NETWORK_NAME`, `NETWORK_ACCESS_DENIED`, ...), hex strings (`0xC0000022`), or integers. Multiple values are OR-combined. |
| `-SmbFilename` | `string[]` | Regex pattern(s) matched case-insensitively against the SMB2 Create request filename. Multiple values are OR-combined. **Implies request-only and Create-only matching** — other commands carry no filename. |
| `-SmbTreePath` | `string[]` | Regex pattern(s) matched case-insensitively against the SMB2 TreeConnect request share path (e.g. `\\server\share`). Multiple values are OR-combined. **Implies request-only and TreeConnect-only matching.** |
| `-SmbMatchEncrypted` | `switch` | When set, encrypted (SMB2 Transform header) packets match even when other filter fields are configured. Default is to drop encrypted packets as soon as any content-bearing filter is set, because those fields aren't visible in encrypted packets. |
| `-SmbMatchTruncated` | `switch` | When set, packets whose per-command body extraction (filename / tree path) couldn't be reached because `-PacketSize` truncated the payload still match. Default is to drop truncated packets so a partial-match false negative isn't silent. |

## Auto-bumps

When any of the parameters above is supplied:

1. **`-ParsingLevel` is auto-bumped to `Detailed`** if currently `Minimal` or `Default`. The new value is printed as a `Write-Warning`.
2. **`-PacketSize` is auto-bumped to 1500 bytes** if the user-supplied value is below that. SMB2 Create filenames and TreeConnect share paths can be `MAX_PATH` (260 UTF-16 chars = 520 bytes), and Direct-TCP framing + SMB2 header + Create body adds ~120 bytes. `-PacketSize 0` (full-packet capture) is preserved.
3. **The `-SMB` quick filter is implied** *unless an existing capture filter already covers TCP 445*. Unlike the built-in `-SMB` switch (which adds both TCP 445 + Kerberos 88), the auto-imply only adds TCP 445 — Kerberos packets wouldn't match an SMB2 predicate anyway. Combining with an unrelated filter (e.g. `-ARP`, `-Ping`) does NOT suppress the auto-imply. When auto-implied, the filter is named `QF-SMB2-AUTO` in the capture summary.

Pass `-NoWarning` to silence the auto-bump warnings without affecting operational warnings.

## NT status semantics

NT status codes are 32-bit values with the top 2 bits encoding the class:

| Class bits | Range          | `-SmbStatus` name |
|------------|----------------|-------------------|
| `00`       | `0x00000000`–`0x3FFFFFFF` | `Success` |
| `01`       | `0x40000000`–`0x7FFFFFFF` | `Informational` / `Info` |
| `10`       | `0x80000000`–`0xBFFFFFFF` | `Warning` |
| `11`       | `0xC0000000`–`0xFFFFFFFF` | `Error` |

Status filters apply to both requests and responses, but requests almost always carry `0x00000000` (`SUCCESS`) — so a status filter naturally narrows to responses without you having to also set `-SmbDirection Response`.

## v1 limitations

- **First chained message only.** SMB2 supports compounded requests (multiple messages in one packet linked by `NextCommand`). The predicate evaluates only the first chained message. Documented; matches the existing legacy formatter behavior.
- **Encrypted (Transform) packets carry no per-command fields.** When any content-bearing filter (`-SmbCommand`, `-SmbStatus`, `-SmbFilename`, `-SmbTreePath`) is set, encrypted packets are rejected. Use `-SmbMatchEncrypted` to let them through anyway — typically only useful alongside `-SmbDirection` alone or no other filter.
- **Mid-stream TCP segments don't parse.** SMB2 messages can span multiple TCP packets; only the first segment carries the SMB2 magic. Subsequent segments without the magic are rejected (use `-SmbMatchTruncated` to keep them).
- **SMB1/CIFS not parsed.** The parser only recognises SMB2/SMB3 magic; SMB1 traffic doesn't match any predicate.
- **No Dialect filter.** SMB dialect is only emitted on Negotiate responses, so a dedicated parameter would be very narrow. Filter on `-SmbCommand Negotiate` and read the dialect from the display output instead.

## Examples

### Filter by command

```powershell
# All Create requests/responses.
pspkt -SmbCommand Create

# State-changing commands.
pspkt -SmbCommand Create,Write,SetInfo,Close

# Negotiate handshake and SessionSetup auth — useful for SMB connection debugging.
pspkt -SmbCommand Negotiate,SessionSetup
```

### Filter by direction

```powershell
# Only client→server requests.
pspkt -SmbDirection Request

# Only server→client responses.
pspkt -SmbDirection Response
```

### Filter by status

```powershell
# Any error response.
pspkt -SmbStatus Error

# Specific failures.
pspkt -SmbStatus ACCESS_DENIED,SHARING_VIOLATION

# Hex form for codes not in the built-in name list.
pspkt -SmbStatus 0xC00000BA          # FILE_IS_A_DIRECTORY
```

### Filter by filename (Create requests)

```powershell
# Every Create for an .docx file.
pspkt -SmbFilename '\.docx$'

# Multiple extensions OR-combined.
pspkt -SmbFilename '\.docx?$','\.xlsx?$','\.pptx?$'

# A specific path under a share.
pspkt -SmbFilename '^profiles\\[^\\]+\\NTUSER\.DAT$'
```

### Filter by share path (TreeConnect)

```powershell
# Any tree connect to \\server\sysvol.
pspkt -SmbTreePath '\\\\server\\sysvol$'

# Connections to admin shares.
pspkt -SmbTreePath '\\\\[^\\]+\\(C\$|ADMIN\$|IPC\$)$'
```

### Combine fields (AND)

```powershell
# Failed Create requests for files under \profiles.
pspkt -SmbCommand Create -SmbStatus Error -SmbFilename '^profiles\\'

# All authentication failures.
pspkt -SmbCommand SessionSetup -SmbStatus LOGON_FAILURE,USER_SESSION_DELETED
```

### Combine with -IPAddress

```powershell
# Reads against a specific file server.
pspkt -SmbCommand Read,Write -i 10.0.0.5
```

### Capture full packets for long paths

```powershell
# Some Active Directory paths exceed 1500 bytes; ask for full packets.
pspkt -SmbFilename '_msdcs' -PacketSize 0
```

### Pass encrypted packets through

```powershell
# Show every SMB2 frame including encrypted ones — useful when you just want
# to see the volume of activity without inspecting individual messages.
pspkt -SmbCommand Create -SmbMatchEncrypted
```

### Quiet mode

```powershell
# Suppress the "auto-bumping" setup warnings.
pspkt -SmbFilename '\.docx?$' -NoWarning
```

## How it works

- The kernel capture filter (added automatically by the implied `-SMB` when no other filter is set) keeps only TCP/445 traffic.
- For each surviving TCP packet, the consumer thread calls `Smb2Parser.TryParseSmb2Header` once. The parsed `Smb2Context` includes header fields (Command, Status, MessageId, SessionId, TreeId, IsResponse, IsCompounded, IsEncrypted) plus Filename for Create requests and TreePath for TreeConnect requests.
- `Smb2AppPredicate.Evaluate` runs against the parsed context. On reject, the consumer returns `false` and `FormatBatch` rolls back the partial StringBuilder content so no line is emitted.
- On accept, the legacy `Smb2Parser.FormatSmb2Segment` / `FormatSmb2Detailed` formatter runs against the same payload. The header re-parse this entails is ~200 ns per matching packet — a deliberate trade-off to avoid refactoring the large per-command formatter functions.
- The pcapng writer is unaffected; the file contains every packet the driver filter accepted.

## Performance notes

- When no `-Smb*` parameter is set, the only hot-path cost is a single null-check on the predicate field, which is branch-predicted false and effectively free.
- When a predicate is active and rejects a packet on the IPv4 fast path, the entire detailed-format pipeline is skipped for that packet.
- All regexes are compiled once with `RegexOptions.Compiled | RegexOptions.IgnoreCase` and reused for the lifetime of the capture.
- Filename / tree-path extraction reads UTF-16 directly from the packet using `System.Text.Encoding.Unicode.GetString` — bounded by the value length in the SMB2 body.

## See also

- [Application-Filters](./Application-Filters.md) — cross-protocol overview
- [Start-Pspkt](./Start-Pspkt.md) — full command reference
- [Application-Filters-HTTP](./Application-Filters-HTTP.md) — sibling predicate, same request/response split pattern
