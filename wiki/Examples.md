# Examples

Common workflows for the pspkt module. Most assume `Import-Module pspkt` and an elevated session.

## Basic captures

```powershell
# Default — capture everything until Ctrl+C
pspkt

# Minimal output (one line per packet)
pspkt -pl Minimal

# Detailed multi-line per-packet
pspkt -pl Detailed

# Detailed with timestamps + blank-line spacing
pspkt -pl Detailed -t -Spaced
```

## Filter on a specific protocol

```powershell
pspkt -DNS
pspkt -SMB
pspkt -HTTP
pspkt -Ping            # ICMPv4 + ICMPv6
pspkt -DoH             # DNS over HTTPS (TCP/443)
pspkt -DoT             # DNS over TLS  (TCP/853)
```

## Filter on a specific IP

```powershell
# All traffic to/from 8.8.8.8
pspkt -i 8.8.8.8

# IPv6
pspkt -i 2606:4700:4700::1111

# DNS only, only with 1.1.1.1
pspkt -DNS -i 1.1.1.1

# SMB to a single share host (combines with port 445 filter)
pspkt -SMB -i 10.0.0.10
```

## Capture a Hyper-V VM

```powershell
# By name — also auto-adds MAC filters for every vmNIC on the VM
pspkt -VMName 'Win11-Dev'

# By VM object
pspkt -VM (Get-VM 'Win11-Dev')

# All HTTPS to/from a VM
pspkt -VMName 'Win11-Dev' -HTTPS

# A specific destination IP inside the VM's traffic
pspkt -VMName 'Win11-Dev' -i 10.0.0.5
```

## Catch drops

```powershell
# Auto-pause on any drop (resume with 'r')
pspkt -PauseOnDrop

# Stop the capture the first time INET_EndpointNotFound shows up
pspkt -StopOnReason 'INET_EndpointNotFound'

# Pause on a specific drop location
pspkt -PauseOnLocation 'TCPIP_TL_RCV_TCP_MATCH'

# Hex form works too
pspkt -PauseOnLocation '0xE0004500'

# Combined: interactive pause + auto-pause on drops
pspkt -Pause -PauseOnDrop
```

## Write to file

```powershell
# Single pcapng file (write-on-stop, max throughput)
pspkt -WriteFile capture.pcapng

# With per-batch flush (better durability if process is killed)
pspkt -WriteFile capture.pcapng -FlushDisk

# Real-time console + file
pspkt -WriteFile capture.pcapng -RealTime

# Rotating pcapng: 5 files × 100 MiB each (circular)
pspkt -WriteFile capture.pcapng -FileSize 100 -NumFiles 5

# Capture only specific protocol to file
pspkt -WriteFile dns.pcapng -DNS -i 1.1.1.1

# Native pktmon ETL (no real-time output, uses pktmon's writer)
pspkt -WriteEtl capture.etl
```

## Tune performance

```powershell
# Larger user-mode ring (4x default = 4M entries; helps for traffic bursts)
pspkt -BufferSizeMultiplier 16

# Smaller polling timeout (faster shutdown after Ctrl+C; default 50ms)
pspkt -PollingIntervalMs 25

# Larger packet capture size (full packet)
pspkt -PacketSize 0
```

## Build a custom session

When you need full control, build the session yourself and pass it to `Start-Pspkt`:

```powershell
$s = New-PspktSession -Name 'forensics'

# Add filters manually
New-PspktFilter -Name 'tls' -TransportProtocol TCP -Port1 443 | Add-PspktFilter -Session $s
New-PspktFilter -Name 'dns-udp' -TransportProtocol UDP -Port1 53 | Add-PspktFilter -Session $s

# Add specific components
Get-PspktComponent -NIC -NICName 'Ethernet' -Exact | Add-PspktComponent -Session $s

# Run it
$s | Start-Pspkt -pl Detailed
```

## Tear down a leftover session

```powershell
# Check whether pktmon is currently active (even from a previous PS session)
Get-PspktSession

# If your last capture didn't clean up, this kills pktmon
pktmon stop

# Or, if you still have the session object
$s | Stop-Pspkt -Teardown
```

## Manage color profiles

```powershell
# List installed profiles (* = active)
Get-PspktParserColorProfile

# Preview every profile side by side
Test-PspktParserColorProfile

# Switch the default
Set-PspktParserColorProfile -Name 'high-contrast'

# Try a profile in this session only
Import-PspktParserColorProfile -Name 'high-contrast'
```

## Build a custom color profile

```powershell
$profile = New-PspktParserColorProfile `
    -ComponentBright '95'   -ComponentMuted '38;5;134' `
    -DataLinkBright  '94'   -DataLinkMuted  '38;5;26'  `
    -NetworkBright   '92'   -NetworkMuted   '38;5;22'  `
    -TransportBright '93'   -TransportMuted '38;5;94'  `
    -ApplicationBright '96' -ApplicationMuted '38;5;30'

# Preview before saving
Test-PspktParserColorProfile -Profile $profile

# Save and make active
Save-PspktParserColorProfile -Name 'mytheme' -Profile $profile
Set-PspktParserColorProfile mytheme
```

## Common debugging scenarios

### "Why is this connection timing out?"
```powershell
pspkt -StopOnDrop -i <remote-ip>
# reproduce the connection
```

### "Is this DNS lookup going to my expected resolver?"
```powershell
pspkt -DNS -t
```

### "Is SMB traffic actually flowing on the VM's NIC?"
```powershell
pspkt -VMName 'AppServer' -SMB
```

### "What component is dropping these packets?"
```powershell
pspkt -PauseOnDrop -pl Detailed
# inspect the DROP - Reason / Location and the component prefix
```

### "Capture a long-running scenario without filling disk"
```powershell
# 1 GiB total across 10 × 100 MiB rotating files
pspkt -WriteFile longcap.pcapng -FileSize 100 -NumFiles 10
```

## See also

- [Start-Pspkt](./Start-Pspkt.md) — full parameter reference
- [Quick Filters](./Quick-Filters.md)
- [Drop Triggers](./Drop-Triggers.md)
