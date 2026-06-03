# Start-Pspkt

`Start-Pspkt` is the primary entry point for the pspkt module. It activates a pktmon session, starts the real-time stream, and runs a high-throughput C# bulk-format loop that parses every packet (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, NDP, ARP, DNS, DHCP, HTTP, TLS, SMB2) and writes colored output to the console.

The module exports the alias **`pspkt`** for this command.

## Synopsis

```powershell
Start-Pspkt [-Name <string>] [-CaptureType <PspktCaptureType>] [-PacketSize <uint32>]
            [-BufferSizeMultiplier <uint16>] [-TruncationSize <uint16>] [-PollingIntervalMs <int>]
            [-ParsingLevel <PspktParsingLevel>] [-Component <string[]>] [-VM <object>] [-VMName <string>]
            [-IPAddress <string>] [-Spaced] [-Timestamp]
            [-ARP] [-NDP] [-AA] [-AAv4] [-AAv6] [-DHCP] [-DHCPv6] [-DNS] [-DNSoverHTTPS] [-DNSoverTLS]
            [-SMB] [-SMBoverQUIC] [-SMBoverQuicAltPort <uint16>] [-SSH] [-RDP] [-RPC] [-RCP]
            [-HTTP] [-HTTPS] [-WinRM] [-WinRMS] [-Ping] [-Ping4] [-Ping6]
            [-Pause] [-PauseOnDrop] [-PauseOnLocation <string>] [-PauseOnReason <string>]
            [-StopOnDrop] [-StopOnLocation <string>] [-StopOnReason <string>]
            [-WriteFile <string>] [-RealTime] [-FileSize <uint32>] [-FlushDisk] [-NumFiles <int>]
            [-WriteEtl <string>]

Start-Pspkt -Session <pspktSession> [common parameters]
```

Press **Ctrl+C** to stop the capture. When the `-Pause` switch is set, press `p` to pause / `r` to resume / `q` to quit while paused.

## Description

`Start-Pspkt` is the primary entry point for the pspkt module. It activates a pktmon session, starts the real-time stream, and runs a high-throughput C# bulk-format loop that parses every packet and writes colored output to the console.

Recent (post-perf) behavior:

- All real-time formatting happens in C# (no per-packet PowerShell). The producer is a native pktmon callback that enqueues into a lock-free SPSC ring buffer; the consumer is a single PS loop that drains the ring and writes a batched colored string to the console.
- Packet `byte[]` arrays are pooled when no file writer is attached (zero-allocation receive on the callback thread).
- The pcapng writer always runs in async mode on a dedicated writer thread — file I/O never blocks the pktmon callback. `-FlushDisk` only controls whether the writer flushes after every batch (durability) or only at stop (throughput).
- `-FileSize` + `-NumFiles` together enable pcapng file rotation (`foo.001.pcapng` → `foo.002.pcapng` → ... → wrap). Rotation is no longer tied to `-FlushDisk`.
- `-BufferSizeMultiplier` scales both the pktmon driver buffer **and** the user-mode SPSC ring (base 1M entries × N).

Quick filters (`-DNS`, `-SMB`, `-Ping`, etc.) create one or more pktmon capture filters automatically. When combined with `-IPAddress`, the IP is **AND-merged** into every quick filter (so `-DNS -i 1.1.1.1` becomes "DNS to/from 1.1.1.1" rather than "DNS OR 1.1.1.1"). With `-VM`/`-VMName`, a MAC filter is added per vmNIC so capture is constrained to the VM's traffic.

## Parameter sets

| Set | Required |
|---|---|
| `Default` | (none — auto-creates a session) |
| `WithSession` | `-Session` (pipeline-bindable) |

## Parameters

### Session / configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | — | Pre-configured session (from `New-PspktSession`). Pipeline-bindable. When supplied, takes precedence over `-Name`, `-CaptureType`, `-PacketSize`. |
| `-Name` | `string` | `pspkt` | Name for the auto-created session when `-Session` is not supplied. |
| `-CaptureType` | `PspktCaptureType` | `All` | Capture scope: `All` (flow + drop), `Flow` (successful only), `Drop` (drops only). |
| `-PacketSize` | `uint32` | `128` | Max bytes captured per packet (driver-side truncation). 0 = full packet. Auto-bumps for protocols that need more payload (e.g. `-DNS` → 512, `-DHCP` → 590). |

### Performance tuning

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-BufferSizeMultiplier` | `uint16` | `4` | Scales both the pktmon driver buffer **and** the user-mode SPSC ring (base 1,048,576 entries). Range 1-65535. Effective ring capacity is capped at 64M entries. |
| `-TruncationSize` | `uint16` | `0` | Stream-level packet truncation in bytes. 0 means derive from `-PacketSize`. |
| `-PollingIntervalMs` | `int` | `50` | Upper bound (ms) on the consumer wait when no packets are available. Range 10-5000. With AutoResetEvent signaling, the consumer wakes immediately on the first packet — this value is now a timeout safety net, not the steady-state interval. |

### Display

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ParsingLevel` (`-pl`) | `PspktParsingLevel` | `Default` | Display detail: `Minimal`, `Default`, `Detailed`, or `VeryDetailed`. |
| `-Spaced` | `switch` | — | Adds a blank line between formatted packet lines. |
| `-Timestamp` (`-t`) | `switch` | — | Prefixes each line with the high-resolution local timestamp. |

### Capture scope

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Component` (`-comp`) | `string[]` | `@('All')` | Components to capture from. Accepts `'All'`, `'NICs'`, or numeric IDs. |
| `-VM` | `object` | — | Hyper-V VM object (from `Get-VM`). Overrides `-Component`. Also adds one MAC capture filter per vmNIC. |
| `-VMName` | `string` | — | Hyper-V VM name (string). Same behavior as `-VM` including per-vmNIC MAC filters. |
| `-IPAddress` (`-i`) | `string` | — | Quick IP filter. Accepts an IPv4 or IPv6 address. When supplied alongside quick filters or `-VM`/`-VMName`, the IP is AND-merged into each generated filter. Alone, creates a standalone IP filter. |
| `-DumpInterfaces` (`-D`) | `switch` | — | Prints the NIC component table (`Id`, `Name`) and exits without starting a capture. Wrapper for `Get-PspktComponent -NIC \| Select Id, Name \| Format-Table`. |

### Quick filters

See [Quick Filters](./Quick-Filters.md) for the full reference. Briefly:

| Switch | Filter created |
|---|---|
| `-ARP` | EtherType ARP |
| `-NDP` | IPv6 ICMPv6 (post-capture filtered to NDP types 133-137 only) |
| `-AA` | NDP + DHCP + DHCPv6 (NDP post-capture filtered to types 133-137) |
| `-AAv4` | IPv4 auto-address (DHCP) |
| `-AAv6` | NDP + DHCPv6 (NDP post-capture filtered to types 133-137) |
| `-DHCP` | UDP/IPv4 ports 67+68 |
| `-DHCPv6` | UDP/IPv6 ports 546+547 |
| `-DNS` | TCP+UDP port 53 |
| `-DNSoverHTTPS` (`-DoH`) | TCP port 443 |
| `-DNSoverTLS` (`-DoT`) | TCP port 853 |
| `-SMB` | TCP 445 + Kerberos 88 |
| `-SMBoverQUIC` (`-SoQ`) | UDP 443 (or `-SMBoverQuicAltPort`) |
| `-SMBoverQuicAltPort` | Alternate UDP port for SMB-over-QUIC |
| `-SSH` | TCP 22 |
| `-RDP` | TCP 3389 |
| `-RPC` | TCP 135 |
| `-RCP` | TCP+UDP 3343 |
| `-HTTP` | TCP 80 |
| `-HTTPS` | TCP 443 |
| `-WinRM` | TCP 5985 |
| `-WinRMS` | TCP 5986 |
| `-Ping` | ICMPv4 + ICMPv6 (post-capture filtered to echo types only: 0/8, 128/129) |
| `-Ping4` | ICMPv4 (post-capture filtered to echo types 0/8) |
| `-Ping6` | ICMPv6 (post-capture filtered to echo types 128/129) |

### Drop triggers

See [Drop Triggers](./Drop-Triggers.md) for full details.

| Parameter | Alias | Description |
|---|---|---|
| `-Pause` | — | Interactive pause/resume: `p` to pause, `r` to resume, `q` to quit. |
| `-PauseOnDrop` | `-pod` | Auto-pause on any pktmon DROP. |
| `-PauseOnLocation` | `-pol` | Auto-pause on DROP with matching location (enum name, integer, or hex string). |
| `-PauseOnReason` | `-por` | Auto-pause on DROP with matching reason. |
| `-StopOnDrop` | `-sod` | Stop capture on any DROP. |
| `-StopOnLocation` | `-sol` | Stop capture on DROP with matching location. |
| `-StopOnReason` | `-sor` | Stop capture on DROP with matching reason. |
| `-StopDelay` | — | Milliseconds (uint32) to keep capturing after a stop trigger fires. Default `0` (stop immediately). Console + pcapng writer continue during the delay; subsequent stop triggers are ignored so the deadline isn't reset. |

### File output

| Parameter | Alias | Type | Default | Description |
|---|---|---|---|---|
| `-WriteFile` | `-w` | `string` | — | Path to a pcapng file. `.pcapng` is appended if missing. Always runs in async mode (writer thread + ring buffer). |
| `-RealTime` | `-rt` | `switch` | — | With `-WriteFile`, also write live colored output to the console. Without this, file writes silently. |
| `-FileSize` | — | `uint32` | `512` | Max MiB per pcapng file before rotating. Effective only with `-NumFiles > 1`. Range 1-65535. |
| `-FlushDisk` | `-fd` | `switch` | — | Flushes the BinaryWriter after every drained batch (durability). Without this, flushes only at stop (throughput). |
| `-NumFiles` | — | `int` | `2` | Number of files in circular rotation: `foo.001.pcapng` → `foo.002.pcapng` → ... → `foo.NNN.pcapng` → wrap. Range 2-100. |
| `-WriteEtl` | `-etl` | `string` | — | Path to an ETL file via pktmon CLI native writer. Mutually exclusive with `-WriteFile` and `-RealTime`. |

## Output

None. Output is streamed to the console in real time. When `-WriteFile` or `-WriteEtl` is set, the corresponding file path and packet count are reported at stop.

When the capture stops, a status line is shown:

```
Stopping capture... [Captured: N; Drops: N; Missed: N; BufferOverflow: N]
```

- **Captured** — packets formatted and emitted
- **Drops** — packets with a non-zero pktmon DropReason
- **Missed** — packets the pktmon driver couldn't deliver to the stream
- **BufferOverflow** — packets the user-mode SPSC ring dropped due to consumer not keeping up

If any components saw traffic, they are listed below the status line; same for active capture filters.

## Examples

```powershell
# Default capture on all components
pspkt
```

```powershell
# DNS traffic to/from 1.1.1.1 (filters AND-combine)
pspkt -DNS -i 1.1.1.1
```

```powershell
# SMB constrained to a single VM's vmNIC MAC addresses
pspkt -VMName 'Win11-Dev' -SMB
```

```powershell
# Auto-pause when packets are dropped with a specific reason
pspkt -Ping -Pause -PauseOnReason 'INET_EndpointNotFound'
```

```powershell
# Rotating pcapng: 5 files of 100 MiB each
pspkt -WriteFile capture.pcapng -FileSize 100 -NumFiles 5
```

```powershell
# Detailed multi-line output with timestamps
pspkt -pl Detailed -t
```

```powershell
# Pre-configured session via pipeline
New-PspktSession -Name 'forensics' |
    Add-PspktFilter -Filter (New-PspktFilter -Name 'tls' -TransportProtocol TCP -Port1 443) |
    Start-Pspkt -pl Detailed
```

## See also

- [Sessions](./Sessions.md)
- [Filters](./Filters.md)
- [Components](./Components.md)
- [Quick Filters](./Quick-Filters.md)
- [Drop Triggers](./Drop-Triggers.md)
- [Examples](./Examples.md)
