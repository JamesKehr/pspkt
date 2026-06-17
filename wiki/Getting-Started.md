# Getting Started

## Prerequisites

- Windows 10 1809 / Server 2019 or newer (anything that ships with `pktmonapi.dll`)
- PowerShell **5.1** (Desktop) or **7+** (Core)
- An **elevated** shell — the module declares `#Requires -RunAsAdministrator`

## Install

The module is plain-file: copy the `pspkt` folder into one of your `$env:PSModulePath` entries.

```powershell
# PowerShell 7+ (Core)
$dest = "$HOME\Documents\PowerShell\Modules\pspkt"

# Windows PowerShell 5.1
$dest = "$HOME\Documents\WindowsPowerShell\Modules\pspkt"

Copy-Item -Recurse .\pspkt $dest
Import-Module pspkt -Force
```

Confirm it loaded:

```powershell
Get-Command -Module pspkt | Sort-Object Name
```

## Your first capture

Open an **elevated** PowerShell (Run as Administrator):

```powershell
Import-Module pspkt
pspkt
```

You should see a colored header row and packet lines flowing as traffic is captured. Press **Ctrl+C** to stop.

`pspkt` is an alias for `Start-Pspkt -CaptureType All`. With no arguments it captures from **all** components.

## Useful first commands

```powershell
# Default capture with timestamps
pspkt -t

# Minimal one-line output
pspkt -pl Minimal

# Detailed per-layer breakdown
pspkt -pl Detailed

# Capture only one protocol family (quick filter)
pspkt -DNS
pspkt -SMB
pspkt -Ping
```

## Capturing a specific IP

```powershell
# Filter alone: all traffic to/from 8.8.8.8
pspkt -i 8.8.8.8

# AND-combined with quick filter: DNS only, only with 1.1.1.1
pspkt -DNS -i 1.1.1.1

# IPv6 works the same
pspkt -i 2606:4700:4700::1111
```

## Capturing a Hyper-V VM

```powershell
# By name — auto-adds a MAC filter per vmNIC to capture all VM traffic.
pspkt -VMName 'Win11-Dev'

# By VM object
pspkt -VM (Get-VM 'Win11-Dev')

# Constrain further with quick filters. Each quick filter is AND-combined with
# each vmNIC MAC, so only "(MAC=vmNIC AND TCP/445 AND IP=10.0.0.5)" matches.
pspkt -VMName 'Win11-Dev' -SMB -i 10.0.0.5
```

## Writing to a file

```powershell
# Single pcapng file, write-on-stop (best throughput)
pspkt -WriteFile capture.pcapng

# Pcapng with periodic flush (durability)
pspkt -WriteFile capture.pcapng -FlushDisk

# Rotating pcapng: 5 files of 100 MiB each
pspkt -WriteFile capture.pcapng -FileSize 100 -NumFiles 5

# Native pktmon ETL (no real-time output)
pspkt -WriteEtl capture.etl
```

## Where to look next

- **[Start-Pspkt](./Start-Pspkt.md)** — every parameter explained
- **[Quick Filters](./Quick-Filters.md)** — list of all `-DNS`/`-SMB`/etc. switches
- **[Drop Triggers](./Drop-Triggers.md)** — auto-pause / auto-stop when packets are dropped
- **[Color Profiles](./Color-Profiles.md)** — change the colors
- **[Architecture](./Architecture.md)** — how it all fits together
- **[Examples](./Examples.md)** — workflows for common tasks
