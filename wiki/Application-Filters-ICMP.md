# Application Filters — ICMP / ICMPv6 / NDP

This page documents the ICMP, ICMPv6, and NDP application-layer display filter parameters on `Start-Pspkt`. See [Application-Filters](./Application-Filters.md) for the cross-protocol overview, including scope, requirements, and pcapng semantics.

These filters narrow ICMP traffic by type (per family) or by the NDP target address (NS / NA only). Non-ICMP packets are unaffected — the predicate is intentionally protocol-scoped. To also drop non-ICMP traffic, combine with a transport / IP capture filter (the auto-imply behavior handles the common case automatically).

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-IcmpType` | `string[]` | IPv4 ICMP type filter. Accepts [`ICMP4_TYPE`](https://github.com/JamesKehr/pspkt/blob/main/class/pspktEnum.psm1) enum names (full `ICMP4_ECHO_REQUEST` or short `EchoRequest` / `ECHO_REQUEST`), integers (`0`-`255`), or hex strings (`0x08`). Multiple values are OR-combined. **Implicitly v4-only** — IPv6 packets are rejected unless `-Icmpv6Type` or `-Icmpv6NdpTarget` is also set. |
| `-Icmpv6Type` | `string[]` | ICMPv6 type filter. Accepts names (see table below), integers, or hex strings. Multiple values are OR-combined. **Implicitly v6-only** — IPv4 packets are rejected unless `-IcmpType` is also set. |
| `-Icmpv6NdpTarget` | `string[]` | Regex pattern(s) matched case-insensitively against the NDP target address (canonical IPv6 string form) on Neighbor Solicitation (135) and Neighbor Advertisement (136) packets. Multiple values are OR-combined. **Rejects every non-NS/NA packet** (including IPv4 ICMP, Router Advertisement, Router Solicitation, Redirect). |

## ICMPv4 type names

Defined by the `[ICMP4_TYPE]` enum. Both full (`ICMP4_ECHO_REQUEST`) and short (`EchoRequest`, `ECHO_REQUEST`) forms are accepted, case-insensitive.

| Type | Long name             | Short name        |
|------|-----------------------|-------------------|
| 0    | ICMP4_ECHO_REPLY      | EchoReply         |
| 3    | ICMP4_DST_UNREACH     | DstUnreach        |
| 4    | ICMP4_SOURCE_QUENCH   | SourceQuench      |
| 5    | ICMP4_REDIRECT        | Redirect          |
| 8    | ICMP4_ECHO_REQUEST    | EchoRequest       |
| 9    | ICMP4_ROUTER_ADVERT   | RouterAdvert      |
| 10   | ICMP4_ROUTER_SOLICIT  | RouterSolicit     |
| 11   | ICMP4_TIME_EXCEEDED   | TimeExceeded      |
| 12   | ICMP4_PARAM_PROB      | ParamProb         |
| 13   | ICMP4_TIMESTAMP_REQUEST | TimestampRequest |
| 14   | ICMP4_TIMESTAMP_REPLY  | TimestampReply  |
| 17   | ICMP4_MASK_REQUEST     | MaskRequest     |
| 18   | ICMP4_MASK_REPLY       | MaskReply       |

## ICMPv6 type names

| Type | Name(s) accepted |
|------|------------------|
| 1    | `DestinationUnreachable`, `DestUnreach` |
| 2    | `PacketTooBig` |
| 3    | `TimeExceeded` |
| 4    | `ParameterProblem` |
| 128  | `EchoRequest` |
| 129  | `EchoReply` |
| 130  | `MulticastListenerQuery` |
| 131  | `MulticastListenerReport` |
| 132  | `MulticastListenerDone` |
| 133  | `RouterSolicitation`, `RouterSolicit`, `RS` |
| 134  | `RouterAdvertisement`, `RouterAdvert`, `RA` |
| 135  | `NeighborSolicitation`, `NeighborSolicit`, `NS` |
| 136  | `NeighborAdvertisement`, `NeighborAdvert`, `NA` |
| 137  | `RedirectMessage`, `Redirect` |
| 138  | `RouterRenumbering` |
| 141  | `InverseND_Solicit` |
| 142  | `InverseND_Advert` |
| 143  | `MLDv2Report` |

## Auto-bumps

When any of the parameters above is supplied:

1. **`-ParsingLevel` is auto-bumped to `Detailed`** if currently `Minimal` or `Default`. The new value is printed as a `Write-Warning`.
2. **`-PacketSize` is NOT bumped.** ICMP / ICMPv6 / NDP packets are small (typical < 100 bytes); the default `-PacketSize 128` already covers the ICMP header + NDP target address.
3. **Capture filters are auto-implied** *per family, unless an existing capture filter already covers that family*:
   - `-IcmpType` set → `QF-ICMPv4-AUTO` (EtherType IPv4, transport ICMP).
   - `-Icmpv6Type` or `-Icmpv6NdpTarget` set → `QF-ICMPv6-AUTO` (EtherType IPv6, transport IPv6_ICMP).
   - Both families filtered → both capture filters are added.

Pass `-NoWarning` to silence the auto-bump warning.

## Interaction with `-Ping` / `-Ping4` / `-Ping6` / `-NDP`

These existing switches are kernel-side (producer thread) filters that drop non-echo / non-NDP ICMP traffic before it reaches the consumer. The new `-IcmpType` / `-Icmpv6Type` / `-Icmpv6NdpTarget` parameters are consumer-side display filters that run after the kernel-side drop. If both are active, the producer-side drop fires first, then the display predicate filters the survivors.

For most users, the new typed parameters supersede the switches — they're strictly more expressive — but the switches stay for backwards compatibility and because they also create the appropriate kernel capture filter.

## v1 limitations

- **NDP target address is NS/NA only.** Redirect messages (type 137) also carry a target address but aren't filterable in v1.
- **ICMP code is not filterable.** Only type. Code filtering can be added later if requested.
- **No ICMP body inspection beyond the type byte and (for NS/NA) the target address.** Echo request/reply identifiers, sequence numbers, embedded original-packet bytes, etc. are visible in the formatter output but not filterable.

## Examples

### Filter by IPv4 ICMP type

```powershell
# Show only ICMP echo requests (pings sent out).
pspkt -IcmpType EchoRequest

# Replies only.
pspkt -IcmpType EchoReply

# Failures.
pspkt -IcmpType DstUnreach,TimeExceeded,ParamProb

# Numeric form.
pspkt -IcmpType 8

# Multiple types together.
pspkt -IcmpType 0,8       # Echo request + reply
```

### Filter by ICMPv6 type

```powershell
# Only neighbor solicitation / advertisement.
pspkt -Icmpv6Type NS,NA

# All router-discovery traffic.
pspkt -Icmpv6Type RS,RA

# Failure messages.
pspkt -Icmpv6Type DestinationUnreachable,PacketTooBig,TimeExceeded,ParameterProblem
```

### Filter by NDP target address

```powershell
# All NS / NA traffic for a specific target.
pspkt -Icmpv6NdpTarget '^fe80::a1b2:c3d4:e5f6:7890$'

# Anchor on a prefix.
pspkt -Icmpv6NdpTarget '^fe80::'

# Multiple targets OR-combined.
pspkt -Icmpv6NdpTarget '^fe80::1$','^fe80::dead'
```

### Combine v4 and v6 in one capture

```powershell
# Echo requests on both families.
pspkt -IcmpType EchoRequest -Icmpv6Type EchoRequest

# Mix of types across families.
pspkt -IcmpType DstUnreach -Icmpv6Type DestinationUnreachable
```

### Combine ICMPv6 type with NDP target

```powershell
# Only Neighbor Advertisements for a specific MAC's link-local address.
pspkt -Icmpv6Type NA -Icmpv6NdpTarget '^fe80::1234'
```

### Combine with -IPAddress

```powershell
# Pings to/from a specific peer.
pspkt -IcmpType EchoRequest,EchoReply -i 10.0.0.5
```

### Quiet mode

```powershell
# Suppress the auto-bump setup warning.
pspkt -Icmpv6Type NS,NA -NoWarning
```

## How it works

- The kernel capture filter (added automatically by the implied `-ICMPv4` / `-ICMPv6` quick filters when no other filter is set) keeps only ICMP traffic.
- For each surviving packet, the consumer thread runs a small inline gate inside `FormatSinglePacketInto`:
  - IPv4 ICMP: `icmpType` and `icmpCode` were already extracted by the IPv4 transport switch; populate an `IcmpContext` and evaluate.
  - IPv6: walk extension headers via `FindIPv6UpperLayer` to find the ICMPv6 type byte. For NS (135) and NA (136), read the 16-byte target address at body offset 8 and format it as a canonical IPv6 string.
- `IcmpAppPredicate.Evaluate` runs against the parsed context. On reject, the consumer returns `false` and `FormatBatch` rolls back the partial StringBuilder content so no line is emitted.
- The pcapng writer is unaffected; the file contains every packet the driver filter accepted.

## Performance notes

- When no `-Icmp*` / `-Icmpv6*` parameter is set, the only hot-path cost is a single null-check on the predicate field, which is branch-predicted false and effectively free.
- For IPv4 ICMP packets, the predicate adds ~10 ns (a couple of array compares).
- For IPv6 ICMPv6 packets, the predicate adds the cost of `FindIPv6UpperLayer` (already paid by the existing ICMPv6 echo / NDP drop logic when those are active) plus ~10 ns of compares. NDP-target packets pay an additional ~100 ns for the IPAddress allocation.
- The NDP target regex is compiled once with `RegexOptions.Compiled | RegexOptions.IgnoreCase` and reused for the lifetime of the capture.

## See also

- [Application-Filters](./Application-Filters.md) — cross-protocol overview
- [Quick Filters](./Quick-Filters.md) — `-Ping`, `-Ping4`, `-Ping6`, `-NDP`, `-ARP` switches
- [Start-Pspkt](./Start-Pspkt.md) — full command reference
