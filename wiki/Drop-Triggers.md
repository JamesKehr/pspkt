# Drop Triggers

Drop triggers cause [`Start-Pspkt`](./Start-Pspkt.md) to **pause** or **stop** capture when packets are dropped by the Windows network stack. This is useful for catching transient failures — set the trigger, reproduce the problem, and you get the buffered context up to the point of the drop without having to scrub through thousands of normal packets.

When a drop happens, pktmon reports two values on the dropped packet:
- **DropReason** — *why* it was dropped (e.g. `INET_EndpointNotFound`, `Misc_FwIp`)
- **DropLocation** — *where* in the stack it was dropped (e.g. `TCPIP_TL_RCV_TCP_MATCH`)

Both are enums with hundreds of possible values. Triggers can match on either or on "any drop at all".

## Trigger checks

All trigger checks happen in C# on the bulk-format hot path — no PowerShell overhead per packet. Stop triggers take precedence over pause triggers.

## Parameters

| Parameter | Alias | Type | Behavior |
|---|---|---|---|
| `-Pause` | — | switch | Enables **interactive** pause/resume: `p`=pause, `r`=resume, `q`=quit. Independent of drop triggers. |
| `-PauseOnDrop` | `-pod` | switch | Auto-pause on **any** DROP. |
| `-PauseOnReason` | `-por` | string | Auto-pause on DROP with matching `DropReason`. |
| `-PauseOnLocation` | `-pol` | string | Auto-pause on DROP with matching `DropLocation`. |
| `-StopOnDrop` | `-sod` | switch | Stop capture on **any** DROP. |
| `-StopOnReason` | `-sor` | string | Stop capture on DROP with matching `DropReason`. |
| `-StopOnLocation` | `-sol` | string | Stop capture on DROP with matching `DropLocation`. |
| `-StopDelay` | — | uint32 | Milliseconds to keep capturing after a stop trigger fires. `0` (default) = stop immediately. Console output and the pcapng writer both keep running during the delay so you see the packets that follow the trigger. Subsequent stop triggers within the delay window are ignored (deadline isn't reset); pause triggers remain active. |

`-PauseOnReason` / `-PauseOnLocation` / `-StopOnReason` / `-StopOnLocation` accept three forms of value:

- **Enum name** (case-insensitive): `'INET_EndpointNotFound'`
- **Integer**: `1204`
- **Hex string**: `'0x4B4'`

Enum names are stripped of their pktmon prefix — supply `'INET_EndpointNotFound'` not `'PktmonDrop_INET_EndpointNotFound'`.

## DROP line format

When a packet is reported as dropped, the formatter renders it like this (drop color):

```
035:026 (TCP/IPv4 - L3/L4    ): DROP - Reason: INET_EndpointNotFound (0x000004B4); Location: TCPIP_TL_RCV_TCP_MATCH (0xE0004500); IPv4 src: 72.147.140.126.443, dst: 100.96.161.13.55626
```

The hex code in parens is the underlying numeric value — handy for filing bug reports.

## Interactive pause flow

With `-Pause`, key handling runs on the consumer loop alongside packet processing:

| Key | Effect |
|---|---|
| `p` | Pause (drain remaining ring buffer, then suspend display) |
| `r` | Resume |
| `q` | Quit (only valid while paused) |

When an auto-pause trigger fires, the loop drains and formats the rest of the current batch, then enters the paused state — so you see the drop in context, not in the middle of the screen scroll.

## Examples

```powershell
# Pause on any drop
pspkt -PauseOnDrop

# Stop the capture the first time INET_EndpointNotFound is seen
pspkt -StopOnReason 'INET_EndpointNotFound'

# Pause on a specific drop location (hex form)
pspkt -PauseOnLocation '0xE0004500'

# Combined: pause on any drop, also allow manual pause/resume
pspkt -Pause -PauseOnDrop

# Stop on a drop reason in numeric form
pspkt -StopOnReason 1204

# Stop on any drop but keep capturing 5 seconds of trailing context (handy when you want
# to see what happens AFTER the drop — retries, RSTs, late ACKs, etc.).
pspkt -StopOnDrop -StopDelay 5000

# Same idea but with a specific reason and writing to a pcapng for post-mortem.
pspkt -StopOnReason 'INET_EndpointNotFound' -StopDelay 2000 -WriteFile drop.pcapng -RealTime
```

## Listing all reasons / locations

The full enum lists live in `class\pspktEnum.psm1`:

```powershell
# All drop reasons (262 values)
[Enum]::GetNames([PKTMON_DROP_REASON])

# All drop locations (612 values)
[Enum]::GetNames([PKTMON_DROP_LOCATION])

# Lookup a specific reason value
[PKTMON_DROP_REASON]'INET_EndpointNotFound'

# Map a numeric value to a name
[PKTMON_DROP_REASON]1204
```

## See also

- [Start-Pspkt](./Start-Pspkt.md)
- [Examples](./Examples.md)
