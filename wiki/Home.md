# pspkt Wiki

**pspkt** is a PowerShell module wrapping the Windows Packet Monitor (`pktmon`) native API via P/Invoke. It captures real-time network packets, parses them in C# at line rate, and prints color-coded output to the console — with optional pcapng file write.

## Highlights

- **Real-time parsing** of Ethernet, IPv4/IPv6, TCP/UDP/ICMP/ICMPv6/NDP/ARP, DNS, DHCP, HTTP, TLS, and SMB2.
- **Zero per-packet PowerShell overhead.** A native callback writes into a lock-free SPSC ring buffer; a single PS consumer loop calls a C# bulk formatter and `[Console]::Write`s the result.
- **Pooled packet buffers**, **AutoResetEvent signaling**, and **cache-line padded** ring indices keep allocation rate and lock contention low.
- **Quick filters** (`-DNS`, `-SMB`, `-Ping`, etc.) plus a single `-IPAddress` AND-merge that combines into every filter.
- **VM-scoped capture** via `-VM` / `-VMName` (auto-adds MAC filters per vmNIC).
- **Drop triggers** (pause/stop on drop reason or location).
- **pcapng file write** in async mode with optional **rotation** (`-FileSize` + `-NumFiles`).

## Requirements

- Windows 10 / Server 2019 or newer (must include `pktmonapi.dll`)
- **PowerShell 5.1** (Windows PowerShell, Desktop edition) **or PowerShell 7+** (Core edition)
- **Administrator** elevation (the module declares `#Requires -RunAsAdministrator`)

## Install

Drop the module into your modules path:

```powershell
$dest = "$HOME\Documents\PowerShell\Modules\pspkt"  # or WindowsPowerShell for PS 5.1
Copy-Item -Recurse .\pspkt $dest
Import-Module pspkt
```

## Quick start

```powershell
# Default capture (all components, default formatting) — Ctrl+C to stop
pspkt

# Detailed mode with timestamps
pspkt -pl Detailed -t

# Only DNS traffic to/from 1.1.1.1
pspkt -DNS -i 1.1.1.1

# Capture a single Hyper-V VM's SMB traffic
pspkt -VMName 'Win11-Dev' -SMB

# Write to pcapng with 5x100 MiB rotation
pspkt -WriteFile capture.pcapng -FileSize 100 -NumFiles 5
```

## Pages

| Page | What's in it |
|---|---|
| [Getting Started](./Getting-Started.md) | Install, first capture, where to look next |
| [Start-Pspkt](./Start-Pspkt.md) | Full reference for the main capture command |
| [Sessions](./Sessions.md) | `New-`/`Get-`/`Set-`/`Stop-PspktSession` |
| [Filters](./Filters.md) | `New-`/`Get-`/`Set-`/`Add-`/`Remove-PspktFilter`, `ConvertTo-PspktIpAddress` |
| [Components](./Components.md) | `Get-`/`Set-`/`Add-`/`Remove-PspktComponent`, group/NIC helpers |
| [Display](./Display.md) | Detail level, spacing, timestamps, component map, capture header |
| [Color Profiles](./Color-Profiles.md) | Manage and preview ANSI color schemes |
| [Quick Filters](./Quick-Filters.md) | Reference of all `-DNS`/`-SMB`/`-Ping`/etc. switches |
| [Drop Triggers](./Drop-Triggers.md) | Pause/stop on drop reason or location |
| [Architecture](./Architecture.md) | How pspkt works internally |
| [Examples](./Examples.md) | Common workflows and recipes |

## Command index

### Sessions
[`New-PspktSession`](./Sessions.md#new-pspktsession) · [`Get-PspktSession`](./Sessions.md#get-pspktsession) · [`Set-PspktSession`](./Sessions.md#set-pspktsession) · [`Start-Pspkt`](./Start-Pspkt.md) · [`Stop-Pspkt`](./Sessions.md#stop-pspkt)

### Filters
[`New-PspktFilter`](./Filters.md#new-pspktfilter) · [`Get-PspktFilter`](./Filters.md#get-pspktfilter) · [`Set-PspktFilter`](./Filters.md#set-pspktfilter) · [`Add-PspktFilter`](./Filters.md#add-pspktfilter) · [`Remove-PspktFilter`](./Filters.md#remove-pspktfilter) · [`ConvertTo-PspktIpAddress`](./Filters.md#convertto-pspktipaddress)

### Components
[`Get-PspktComponent`](./Components.md#get-pspktcomponent) · [`Get-PspktComponentGroupName`](./Components.md#get-pspktcomponentgroupname) · [`Get-PspktComponentNICName`](./Components.md#get-pspktcomponentnicname) · [`Set-PspktComponent`](./Components.md#set-pspktcomponent) · [`Add-PspktComponent`](./Components.md#add-pspktcomponent) · [`Remove-PspktComponent`](./Components.md#remove-pspktcomponent)

### Display
[`Set-PspktDetailLevel`](./Display.md#set-pspktdetaillevel) · [`Get-PspktDetailLevel`](./Display.md#get-pspktdetaillevel) · [`Set-PspktDetailSpacing`](./Display.md#set-pspktdetailspacing) · [`Get-PspktDetailSpacing`](./Display.md#get-pspktdetailspacing) · [`Set-PspktShowTimestamp`](./Display.md#set-pspktshowtimestamp) · [`Get-PspktShowTimestamp`](./Display.md#get-pspktshowtimestamp) · [`Register-PspktComponentMap`](./Display.md#register-pspktcomponentmap) · [`Clear-PspktComponentMap`](./Display.md#clear-pspktcomponentmap) · [`Get-PspktCaptureHeader`](./Display.md#get-pspktcaptureheader)

### Color profiles
[`Get-PspktParserColorProfile`](./Color-Profiles.md#get-pspktparsercolorprofile) · [`Import-PspktParserColorProfile`](./Color-Profiles.md#import-pspktparsercolorprofile) · [`Set-PspktParserColorProfile`](./Color-Profiles.md#set-pspktparsercolorprofile) · [`New-PspktParserColorProfile`](./Color-Profiles.md#new-pspktparsercolorprofile) · [`Test-PspktParserColorProfile`](./Color-Profiles.md#test-pspktparsercolorprofile) · [`Save-PspktParserColorProfile`](./Color-Profiles.md#save-pspktparsercolorprofile)
