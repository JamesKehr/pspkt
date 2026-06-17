# Application Filters — DHCP

This page documents the DHCP application-layer display filter parameters on `Start-Pspkt`. See [Application-Filters](./Application-Filters.md) for the cross-protocol overview, including scope, requirements, and pcapng semantics.

DHCP filters apply to DHCPv4 (BOOTP — UDP ports 67/68) and DHCPv6 (UDP ports 546/547). The two protocols use distinct, overlapping numeric spaces for message types: type 1 is `Discover` in v4 and `Solicit` in v6, type 7 is `Release` in v4 and `Reply` in v6, etc. The predicate keeps separate per-family arrays internally and the PowerShell resolver routes each value to the right family based on name.

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-DhcpMessageType` | `string[]` | Message-type filter. Accepts DHCPv4 names (`Discover`, `Offer`, `Request`, `Decline`, `Ack`, `Nak`, `Release`, `Inform`), DHCPv6 names (`Solicit`, `Advertise`, `Request`, `Confirm`, `Renew`, `Rebind`, `Reply`, `Release`, `Decline`, `Reconfigure`, `Information-request`, `Relay-forward`, `Relay-reply`), or integers / hex (`1`, `0x05`). Names unique to one family resolve to that family only; names shared by both families (e.g. `Request`, `Release`, `Decline`) and integers apply to both. Multiple values are OR-combined. |
| `-DhcpClientMac` | `string[]` | Regex pattern(s) matched case-insensitively against the DHCPv4 client hardware address (`chaddr`) in canonical `aa-bb-cc-dd-ee-ff` form. Multiple values are OR-combined. **Always rejects DHCPv6** because the v1 parser doesn't decode DHCPv6 DUIDs. |
| `-DhcpFamily` | `string` | Restrict to one address family. `V4` = DHCPv4 (ports 67/68) only, `V6` = DHCPv6 (ports 546/547) only, `Any` (default) = either. Also controls which capture filters are auto-implied. |
| `-DhcpMatchTruncated` | `switch` | When set, DHCPv4 packets whose option block couldn't be walked to reach the option-53 message type (typically because `-PacketSize` cut the payload mid-options) match the predicate anyway. Default is to drop truncated packets so a partial-match false negative isn't silent. |

## v4 vs v6 message-type semantics

Because the two families share numeric values:

- **`-DhcpMessageType Discover`** — matches DHCPv4 type 1 only (v6 has no `Discover`).
- **`-DhcpMessageType Solicit`** — matches DHCPv6 type 1 only.
- **`-DhcpMessageType Request`** — matches DHCPv4 type 3 **and** DHCPv6 type 3 (name shared by both families).
- **`-DhcpMessageType 1`** — matches DHCPv4 type 1 (`Discover`) **and** DHCPv6 type 1 (`Solicit`). Use a name instead if you only want one.
- **`-DhcpMessageType Discover,Solicit`** — explicit cross-family combination. Matches both v4 Discover and v6 Solicit.

When a filter is configured for only one family (e.g. `-DhcpMessageType Discover` → V4 only), the other family is implicitly rejected by the predicate — equivalent to `-DhcpFamily V4`.

## Auto-bumps

When any of the parameters above is supplied:

1. **`-ParsingLevel` is auto-bumped to `Detailed`** if currently `Minimal` or `Default`. The new value is printed as a `Write-Warning`.
2. **`-PacketSize` is auto-bumped to 590 bytes** if the user-supplied value is below that. 590 covers DHCPv4 (BOOTP fixed 236 + magic 4 + common options) for option-53 lookup. `-PacketSize 0` (full-packet capture) is preserved.
3. **DHCP quick filters are implied** *per port, unless an existing capture filter already covers that port*. `DhcpFamily Any` (default) adds both v4 (67/68) and v6 (546/547) capture filters; `V4` adds only v4; `V6` adds only v6. Auto-implied filter names are suffixed `-AUTO` in the capture summary. Combining with an unrelated capture filter (e.g. `-ARP`, `-Ping`) does NOT suppress the auto-imply — only filters that actually cover the DHCP ports do.

Pass `-NoWarning` to silence the auto-bump warnings without affecting operational warnings.

## v1 limitations

- **No DHCPv6 client identification.** The DHCPv6 client identifier is a variable-length DUID transported as an option, not at a fixed offset like DHCPv4's `chaddr`. v1 doesn't decode it. `-DhcpClientMac` is therefore DHCPv4-only and always rejects DHCPv6 packets.
- **Option-53 only for v4 message type.** DHCPv4 message type comes from option 53, which sits in the variable-length options block. If `-PacketSize` cuts the packet before option 53, the predicate has no message type to compare against and rejects the packet (use `-DhcpMatchTruncated` to relax this).
- **No DHCPv6 options parsed.** Beyond the first message-type byte and the 3-byte transaction ID, v1 reads no DHCPv6 options. `-DhcpMessageType` is the only filter that works against DHCPv6.

## Examples

### Filter by message type

```powershell
# All Discover/Offer/Ack on the v4 side.
pspkt -DhcpMessageType Discover,Offer,Ack

# All v6 Solicit/Advertise/Reply.
pspkt -DhcpMessageType Solicit,Advertise,Reply

# Mixed: v4 Discover + v6 Solicit.
pspkt -DhcpMessageType Discover,Solicit

# Numeric — matches both families' message type 1 (Discover OR Solicit).
pspkt -DhcpMessageType 1
```

### Filter by family

```powershell
# Restrict to DHCPv4 only.
pspkt -DhcpFamily V4

# Restrict to DHCPv6 only.
pspkt -DhcpFamily V6
```

### Filter by client MAC (v4 only)

```powershell
# A specific device.
pspkt -DhcpClientMac '^aa-bb-cc-dd-ee-ff$'

# A vendor OUI prefix.
pspkt -DhcpClientMac '^aa-bb-cc-'
```

### Combine fields (AND)

```powershell
# Only Discover messages from a specific MAC.
pspkt -DhcpMessageType Discover -DhcpClientMac '^aa-bb-cc-'

# Only v6 traffic, restricted to Solicit/Request.
pspkt -DhcpMessageType Solicit,Request -DhcpFamily V6
```

### Capture full packets for long option blocks

```powershell
# PXE / DOCSIS / option-43 packets can exceed 590 bytes; ask for the full packet.
pspkt -DhcpMessageType Discover,Ack -PacketSize 0
```

### Allow truncated matches

```powershell
# Treat truncated option blocks as matching anyway.
pspkt -DhcpMessageType Discover -DhcpMatchTruncated
```

### Quiet mode

```powershell
# Suppress the "auto-bumping" setup warnings.
pspkt -DhcpMessageType Ack -NoWarning
```

## How it works

- Capture filters added automatically by `-DhcpFamily` (when no other filter is configured) constrain the kernel-side capture to ports 67/68 and/or 546/547.
- For each surviving UDP packet on a DHCP port, the consumer thread calls `DhcpParser.TryParseDhcp` once. The parsed `DhcpContext` includes:
  - **v4**: `Op`, `TransactionId`, `ClientMacAddress`, `MessageType` (from option 53 walk), `Truncated` flag.
  - **v6**: `MessageType` (first payload byte), `TransactionId` (3 bytes).
- `DhcpAppPredicate.Evaluate` runs against the parsed context. On reject, the consumer returns `false` and `FormatBatch` rolls back the partial StringBuilder content so no line is emitted.
- On accept, the parsed context is reused by the formatter — only one parse per matching packet.
- The pcapng writer is unaffected; the file contains every packet the driver filter accepted.

## Performance notes

- When no `-Dhcp*` parameter is set, the only hot-path cost is a single null-check on the predicate field, which is branch-predicted false and effectively free.
- When a predicate is active and rejects a packet on the IPv4 fast path, the entire detailed-format pipeline is skipped for that packet.
- The client-MAC regex is compiled once with `RegexOptions.Compiled | RegexOptions.IgnoreCase` and reused for the lifetime of the capture.
- Option-walk for v4 message-type extraction is bounded by `data.Length`; pathological packets cannot cause arbitrary scan distances.

## See also

- [Application-Filters](./Application-Filters.md) — cross-protocol overview
- [Application-Filters-DNS](./Application-Filters-DNS.md) — sibling predicate, same architecture
- [Start-Pspkt](./Start-Pspkt.md) — full command reference
