using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

[CmdletBinding()]
param ()

<#
.SYNOPSIS
Applies bound values to an existing pspktSession.

.DESCRIPTION
Internal helper used by Set-PspktSession.

.PARAMETER Session
Session object to update.
#>
function Update-PspktSessionInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [bool]
        $Active,

        [Parameter(Mandatory = $false)]
        [PspktCaptureType]
        $CaptureType,

        [Parameter(Mandatory = $false)]
        [PspktLogMode]
        $LogMode,

        [Parameter(Mandatory = $false)]
        [uint32]
        $EventFlags,

        [Parameter(Mandatory = $false)]
        [uint32]
        $PacketSize,

        [Parameter(Mandatory = $false)]
        [uint32]
        $FileSize,

        [Parameter(Mandatory = $false)]
        [string]
        $FileName,

        [Parameter(Mandatory = $false)]
        [bool]
        $CountersOnly
    )

    if ($PSBoundParameters.ContainsKey('Name')) {
        $Session.Name = $Name
    }

    if ($PSBoundParameters.ContainsKey('Active')) {
        $Session.SetSessionActive($Active)
    }

    if ($PSBoundParameters.ContainsKey('CaptureType')) {
        $Session.CaptureType = $CaptureType
    }

    if ($PSBoundParameters.ContainsKey('LogMode')) {
        $Session.LogMode = $LogMode
    }

    if ($PSBoundParameters.ContainsKey('EventFlags')) {
        $Session.EventFlags = $EventFlags
    }

    if ($PSBoundParameters.ContainsKey('PacketSize')) {
        $Session.PacketSize = $PacketSize
    }

    if ($PSBoundParameters.ContainsKey('FileSize')) {
        $Session.FileSize = $FileSize
    }

    if ($PSBoundParameters.ContainsKey('FileName')) {
        $Session.FileName = $FileName
    }

    if ($PSBoundParameters.ContainsKey('CountersOnly')) {
        $Session.CountersOnly = $CountersOnly
    }

    return $Session
}

<#
.SYNOPSIS
Creates a new live packet monitor session.

.DESCRIPTION
Initializes a pspkt instance, creates a live session, and returns it.
The pspkt instance is stored on the session for lifecycle management.
The caller is responsible for storing the returned session object.

.PARAMETER Name
Name for the new session.

.OUTPUTS
pspktSession
#>
function New-PspktSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
    )

    $pspktInstance = [pspkt]::new()
    $pspktInstance.PacketMonitorInitialize()

    $session = $pspktInstance.PacketMonitorCreateLiveSession($Name)
    $session.Pspkt = $pspktInstance

    return $session
}

<#
.SYNOPSIS
Gets the current packet monitor status.

.DESCRIPTION
Parses the output of 'pktmon status' to report whether pktmon is actively
capturing, what filters are configured, and what components are being monitored.
This detects any active pktmon session, including sessions not created by pspkt
or orphaned from a previous run.

.OUTPUTS
PSCustomObject with properties: Active, CaptureType, MonitoredComponents, Filters
#>
function Get-PspktSession {
    [CmdletBinding()]
    param()

    $statusOutput = pktmon status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "pktmon status failed with exit code $LASTEXITCODE"
    }

    $raw = $statusOutput | Out-String
    $lines = $raw -split "`r?`n"

    $captureType = $null
    $monitoredComponents = $null
    $filters = [System.Collections.ArrayList]::new()

    $section = 'header'
    $inFilterTable = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        # Parse "key:value" lines where value may be on the same line or the next
        if ($line -match '^\s*Capture Type:(.*)') {
            $val = $Matches[1].Trim()
            if ([string]::IsNullOrEmpty($val) -and ($i + 1) -lt $lines.Count) {
                $val = $lines[$i + 1].Trim()
                $i++
            }
            $captureType = $val
            continue
        }

        if ($line -match '^\s*Monitored Components:(.*)') {
            $val = $Matches[1].Trim()
            if ([string]::IsNullOrEmpty($val) -and ($i + 1) -lt $lines.Count) {
                $val = $lines[$i + 1].Trim()
                $i++
            }
            $monitoredComponents = $val
            continue
        }

        if ($line -match '^\s*Packet Filters:') {
            $inFilterTable = $true
            continue
        }

        if ($inFilterTable) {
            # Skip header and separator lines
            if ($line -match '^\s*#\s+Name' -or $line -match '^\s*-+\s+-+') {
                continue
            }

            # Parse filter rows: number followed by data columns
            if ($line -match '^\s*(\d+)\s+(.+)') {
                $parts = $line.Trim() -split '\s{2,}'
                $filterObj = [PSCustomObject]@{
                    Number     = $parts[0].Trim()
                    Name       = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
                    MACAddress = if ($parts.Count -gt 2) { $parts[2].Trim() } else { '' }
                    EtherType  = if ($parts.Count -gt 3) { $parts[3].Trim() } else { '' }
                    Protocol   = if ($parts.Count -gt 4) { $parts[4].Trim() } else { '' }
                }
                $null = $filters.Add($filterObj)
            }
        }
    }

    $isActive = -not [string]::IsNullOrEmpty($captureType)

    [PSCustomObject]@{
        Active              = $isActive
        CaptureType         = $captureType
        MonitoredComponents = $monitoredComponents
        Filters             = $filters
    }
}

<#
.SYNOPSIS
Updates an existing session.

.DESCRIPTION
Accepts a session via parameter or pipeline and applies bound values
including capture configuration (CaptureType, LogMode, PacketSize, etc.).

.PARAMETER Session
Session to update.

.PARAMETER Name
New name for the session.

.PARAMETER Active
Set session active state directly.

.PARAMETER CaptureType
Capture type: All, Flow, or Drop.

.PARAMETER LogMode
Logging mode: Circular, MultiFile, Memory, or RealTime.

.PARAMETER EventFlags
Event flags bitmask (0x032 default).

.PARAMETER PacketSize
Maximum bytes to log per packet. 0 means full packet.

.PARAMETER FileSize
Maximum log file size in MB.

.PARAMETER FileName
Log file name.

.PARAMETER CountersOnly
Capture counters only without packet logging.

.OUTPUTS
pspktSession
#>
function Set-PspktSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [bool]
        $Active,

        [Parameter(Mandatory = $false)]
        [PspktCaptureType]
        $CaptureType,

        [Parameter(Mandatory = $false)]
        [PspktLogMode]
        $LogMode,

        [Parameter(Mandatory = $false)]
        [uint32]
        $EventFlags,

        [Parameter(Mandatory = $false)]
        [uint32]
        $PacketSize,

        [Parameter(Mandatory = $false)]
        [uint32]
        $FileSize,

        [Parameter(Mandatory = $false)]
        [string]
        $FileName,

        [Parameter(Mandatory = $false)]
        [bool]
        $CountersOnly
    )

    process {
        Update-PspktSessionInternal @PSBoundParameters
    }
}

<#
.SYNOPSIS
Starts a real-time pktmon packet capture with parsed, color-coded console output and optional pcapng file write.

.DESCRIPTION
Start-Pspkt is the primary entry point for the pspkt module. It activates a pktmon session, starts the real-time
stream, and runs a high-throughput C# bulk-format loop that parses every packet (Ethernet, IPv4, IPv6, TCP, UDP,
ICMP, ICMPv6, NDP, ARP, DNS, DHCP, HTTP, TLS, SMB2) and writes colored output to the console.

Press Ctrl+C to stop the capture. When the -Pause switch is set, press 'p' to pause / 'r' to resume / 'q' to quit
while paused.

Recent (post-perf) behavior:
* All real-time formatting happens in C# (no per-packet PowerShell). The producer is a native pktmon callback that
  enqueues into a lock-free SPSC ring buffer; the consumer is a single PS loop that drains the ring and writes a
  batched colored string to the console.
* Packet byte[] arrays are pooled when no file writer is attached (zero-allocation receive on the callback thread).
* The pcapng writer always runs in async mode on a dedicated writer thread — file I/O never blocks the pktmon
  callback. -FlushDisk only controls whether the writer flushes after every batch (durability) or only at stop
  (throughput).
* -FileSize + -NumFiles together enable pcapng file rotation (foo.001.pcapng -> foo.002.pcapng -> ... -> wrap).
  Rotation is no longer tied to -FlushDisk.
* -BufferSizeMultiplier scales both the pktmon driver buffer AND the user-mode SPSC ring (base 1M entries x N).

Quick filters (-DNS, -SMB, -Ping, etc.) create one or more pktmon capture filters automatically. When combined
with -IPAddress, the IP is AND-merged into every quick filter (so `-DNS -i 1.1.1.1` becomes "DNS to/from 1.1.1.1"
rather than "DNS OR 1.1.1.1"). With -VM/-VMName, a MAC filter is added per vmNIC so capture is constrained to
the VM's traffic.

.PARAMETER Session
A pre-configured pspktSession (from New-PspktSession). Accepts pipeline input. Mutually exclusive with -Name /
-CaptureType / -PacketSize: when -Session is supplied, those properties are taken from the session.

.PARAMETER Name
Name for the auto-created session when -Session is not supplied. Default 'pspkt'.

.PARAMETER CaptureType
Capture scope: All (flow + drop), Flow (successful only), or Drop (drops only). Default All.

.PARAMETER PacketSize
Max bytes captured per packet (driver-side truncation). 0 = full packet. Default 128.
Quick filters that need more payload (e.g. -DNS bumps to 512, -DHCP bumps to 590) auto-increase this if you
haven't set it explicitly.

.PARAMETER BufferSizeMultiplier
Multiplier applied to both the pktmon driver-side buffer AND the user-mode SPSC ring buffer (base 1,048,576
entries). Higher values reduce drops during traffic bursts at the cost of memory. Range 1-65535, default 4.
Effective ring capacity is clamped to a 64M-entry maximum.

.PARAMETER TruncationSize
Stream-level packet truncation in bytes. 0 (default) means derive from PacketSize.

.PARAMETER PollingIntervalMs
Upper bound (in ms) on the consumer wait when no packets are available. Range 10-5000, default 50.
With AutoResetEvent signaling from the producer, the consumer wakes immediately on the first packet — this value
is now a timeout safety net, not the steady-state polling interval.

.PARAMETER ParsingLevel
Display detail level. Alias: -pl.
* Minimal — single-line port/protocol summary
* Default — packet header summary (link/network/transport/app)
* Detailed — multi-line per-layer breakdown
* VeryDetailed — Detailed plus blank line between packets

.PARAMETER Component
Components to capture from. Alias: -comp.
* 'All' (default) — all NIC, protocol, and driver components
* 'NICs' — NIC components only
* Comma-separated numeric IDs (e.g. -comp 1,5,33) — specific component IDs

.PARAMETER VM
Hyper-V VM object (from Get-VM) whose virtual network data path should be captured. Overrides -Component.
Also adds one MAC capture filter per vmNIC so console output and pcapng file contain only the VM's traffic.

.PARAMETER VMName
Hyper-V VM name (string). Same behavior as -VM including per-vmNIC MAC filters. Overrides -Component.

.PARAMETER IPAddress
Quick IP filter. Alias: -i. Accepts an IPv4 or IPv6 address string. When supplied alongside quick filters or
-VM/-VMName, the IP is AND-merged into each generated filter (single-filter combined match). When supplied
alone, creates a standalone IP filter.

.PARAMETER Spaced
Adds a blank line between each formatted packet line on the console.

.PARAMETER Timestamp
Prefixes each line with the high-resolution local timestamp (yyyy-MM-dd HH:mm:ss.fffffff). Alias: -t.

.PARAMETER ARP
Quick filter: EtherType ARP.

.PARAMETER NDP
Quick filter: IPv6 ICMPv6. Post-capture filtered to NDP types 133-137 only (Router Sol/Adv,
Neighbor Sol/Adv, Redirect). Other ICMPv6 types are dropped on the producer thread before
they reach the ring buffer, so they appear in neither console output nor pcapng output.

.PARAMETER AA
Quick filter: auto-address protocols (NDP + DHCP + DHCPv6). NDP packets are post-capture
filtered to types 133-137 only.

.PARAMETER AAv4
Quick filter: IPv4 auto-address (DHCP only).

.PARAMETER AAv6
Quick filter: IPv6 auto-address (NDP + DHCPv6). NDP packets are post-capture filtered to
types 133-137 only.

.PARAMETER DHCP
Quick filter: UDP/IPv4 ports 67+68.

.PARAMETER DHCPv6
Quick filter: UDP/IPv6 ports 546+547.

.PARAMETER DNS
Quick filter: TCP+UDP port 53.

.PARAMETER DNSoverHTTPS
Quick filter: TCP port 443. Alias: -DoH.

.PARAMETER DNSoverTLS
Quick filter: TCP port 853. Alias: -DoT.

.PARAMETER SMB
Quick filter: TCP ports 445 (SMB) + 88 (Kerberos).

.PARAMETER SMBoverQUIC
Quick filter: UDP port 443 (or -SMBoverQuicAltPort). Alias: -SoQ.

.PARAMETER SMBoverQuicAltPort
Alternate UDP port for SMB-over-QUIC. Only meaningful with -SMBoverQUIC.

.PARAMETER SSH
Quick filter: TCP port 22.

.PARAMETER RDP
Quick filter: TCP port 3389.

.PARAMETER RPC
Quick filter: TCP port 135.

.PARAMETER RCP
Quick filter: TCP+UDP port 3343 (Cluster RCP).

.PARAMETER HTTP
Quick filter: TCP port 80.

.PARAMETER HTTPS
Quick filter: TCP port 443.

.PARAMETER WinRM
Quick filter: TCP port 5985.

.PARAMETER WinRMS
Quick filter: TCP port 5986.

.PARAMETER Ping
Quick filter: ICMPv4 + ICMPv6. Post-capture filtered to echo types only (ICMPv4 0/8,
ICMPv6 128/129). Non-echo ICMP packets are dropped on the producer thread before they
reach the ring buffer, so they appear in neither console output nor pcapng output.

.PARAMETER Ping4
Quick filter: ICMPv4 only, post-capture filtered to echo types (0/8) only.

.PARAMETER Ping6
Quick filter: ICMPv6 only, post-capture filtered to echo types (128/129) only.

.PARAMETER Pause
Enables interactive pause/resume: press 'p' to pause, 'r' to resume, 'q' to quit.

.PARAMETER PauseOnDrop
Auto-pause when any pktmon DROP is detected. Alias: -pod.

.PARAMETER PauseOnLocation
Auto-pause when a DROP with matching location is detected. Accepts enum name, integer, or hex string. Alias: -pol.

.PARAMETER PauseOnReason
Auto-pause when a DROP with matching reason is detected. Accepts enum name, integer, or hex string. Alias: -por.

.PARAMETER StopOnDrop
Stop capture when any pktmon DROP is detected. Alias: -sod.

.PARAMETER StopOnLocation
Stop capture when a DROP with matching location is detected. Alias: -sol.

.PARAMETER StopOnReason
Stop capture when a DROP with matching reason is detected. Alias: -sor.

.PARAMETER StopDelay
Milliseconds (uint32) to keep capturing after a stop trigger (-StopOnDrop / -StopOnReason /
-StopOnLocation) fires. 0 (default) stops immediately. Real-time console output and the
pcapng writer both continue during the delay window. Subsequent stop triggers are
suppressed so the deadline isn't reset; pause triggers remain active.

.PARAMETER WriteFile
Path to a pcapng file to write captured packets to. Alias: -w. The .pcapng extension is appended automatically
if missing. Writing always runs in async mode (writer thread + ring buffer) so file I/O does not block the
pktmon callback thread.

.PARAMETER RealTime
When -WriteFile is set, also write live colored output to the console. Alias: -rt. Without this switch, file
writes silently with a single status line (unless quick filters are active, which implicitly enable real-time).

.PARAMETER FileSize
Max bytes per pcapng file in MiB before rotating. Range 1-65535, default 512. Effective only with -NumFiles
greater than 1.

.PARAMETER FlushDisk
Flushes the pcapng BinaryWriter after every drained batch (durability mode). Without this switch, the writer
flushes only at session stop (throughput mode). Alias: -fd. Note: this switch no longer controls writer mode;
the writer is always async.

.PARAMETER NumFiles
Number of files in the rotation. When greater than 1, enables circular pcapng rotation: foo.001.pcapng ->
foo.002.pcapng -> ... -> foo.NNN.pcapng -> back to foo.001.pcapng (overwrite). Range 2-100. Default 2.

.PARAMETER WriteEtl
Path to an ETL file to write via the pktmon CLI native writer. Alias: -etl. Mutually exclusive with -WriteFile
and -RealTime.

.PARAMETER DumpInterfaces
Switch. Alias: -D. Prints the list of NIC components (Id + Name only) and exits without starting a capture.
Wrapper for `Get-PspktComponent -NIC | Select-Object Id, Name | Format-Table`.

.OUTPUTS
None. Output is streamed to the console in real time. When -WriteFile or -WriteEtl is set, the corresponding
file path and packet count are reported on stop.

.EXAMPLE
PS> pspkt
Capture all packets on all components with default formatting until Ctrl+C.

.EXAMPLE
PS> pspkt -DNS -i 1.1.1.1
Capture DNS traffic to/from 1.1.1.1 (filters AND-combine).

.EXAMPLE
PS> pspkt -VMName 'Win11-Dev' -SMB
Capture SMB (port 445 + Kerberos 88) constrained to the named VM's vmNIC MAC addresses.

.EXAMPLE
PS> pspkt -Ping -Pause -PauseOnReason 'INET_EndpointNotFound'
Capture ICMP and auto-pause when a packet is dropped with the INET_EndpointNotFound reason.

.EXAMPLE
PS> pspkt -WriteFile capture.pcapng -FileSize 100 -NumFiles 5
Write rotating pcapng files of 100 MiB each, cycling through capture.001.pcapng .. capture.005.pcapng.

.EXAMPLE
PS> pspkt -pl Detailed -t
Capture all traffic with detailed per-layer output and high-resolution timestamps.

.EXAMPLE
PS> pspkt -D
Print the NIC component table (Id + Name) without starting a capture.
#>
function Start-Pspkt {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'WithSession')]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name = 'pspkt',

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [PspktCaptureType]
        $CaptureType = [PspktCaptureType]::All,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [uint32]
        $PacketSize = 128,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [uint16]
        $BufferSizeMultiplier = 4,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 65535)]
        [uint16]
        $TruncationSize = 0,

        [Parameter(Mandatory = $false)]
        [ValidateRange(10, 5000)]
        [int]
        $PollingIntervalMs = 50,

        [Parameter(Mandatory = $false)]
        [Alias('pl')]
        [PspktParsingLevel]
        $ParsingLevel = [PspktParsingLevel]::Default,

        [Parameter(Mandatory = $false)]
        [Alias('comp')]
        [string[]]
        $Component = @('All'),

        [Parameter(Mandatory = $false)]
        [object]
        $VM,

        [Parameter(Mandatory = $false)]
        [string]
        $VMName,

        [Parameter(Mandatory = $false)]
        [Alias('i')]
        [string]
        $IPAddress,

        [Parameter(Mandatory = $false)]
        [switch]
        $Spaced,

        [Parameter(Mandatory = $false)]
        [Alias('t')]
        [switch]
        $Timestamp,

        # Quick filters — switch parameters that auto-create common capture filters.
        [Parameter(Mandatory = $false)]
        [switch]
        $ARP,

        [Parameter(Mandatory = $false)]
        [switch]
        $NDP,

        [Parameter(Mandatory = $false)]
        [switch]
        $AA,

        [Parameter(Mandatory = $false)]
        [switch]
        $AAv4,

        [Parameter(Mandatory = $false)]
        [switch]
        $AAv6,

        [Parameter(Mandatory = $false)]
        [switch]
        $DHCP,

        [Parameter(Mandatory = $false)]
        [switch]
        $DHCPv6,

        [Parameter(Mandatory = $false)]
        [switch]
        $DNS,

        [Parameter(Mandatory = $false)]
        [Alias('DoH')]
        [switch]
        $DNSoverHTTPS,

        [Parameter(Mandatory = $false)]
        [Alias('DoT')]
        [switch]
        $DNSoverTLS,

        [Parameter(Mandatory = $false)]
        [switch]
        $SMB,

        [Parameter(Mandatory = $false)]
        [Alias('SoQ')]
        [switch]
        $SMBoverQUIC,

        [Parameter(Mandatory = $false)]
        [uint16]
        $SMBoverQuicAltPort,

        [Parameter(Mandatory = $false)]
        [switch]
        $SSH,

        [Parameter(Mandatory = $false)]
        [switch]
        $RDP,

        [Parameter(Mandatory = $false)]
        [switch]
        $RPC,

        [Parameter(Mandatory = $false)]
        [switch]
        $RCP,

        [Parameter(Mandatory = $false)]
        [switch]
        $HTTP,

        [Parameter(Mandatory = $false)]
        [switch]
        $HTTPS,

        [Parameter(Mandatory = $false)]
        [switch]
        $WinRM,

        [Parameter(Mandatory = $false)]
        [switch]
        $WinRMS,

        [Parameter(Mandatory = $false)]
        [switch]
        $Ping,

        [Parameter(Mandatory = $false)]
        [switch]
        $Ping4,

        [Parameter(Mandatory = $false)]
        [switch]
        $Ping6,

        # Pause control — enables 'p' to pause / 'r' to resume during capture.
        [Parameter(Mandatory = $false)]
        [switch]
        $Pause,

        # Auto-pause when any pktmon DROP is detected.
        [Parameter(Mandatory = $false)]
        [Alias('pod')]
        [switch]
        $PauseOnDrop,

        # Auto-pause when a DROP with matching location is detected.
        [Parameter(Mandatory = $false)]
        [Alias('pol')]
        [string]
        $PauseOnLocation,

        # Auto-pause when a DROP with matching reason is detected.
        [Parameter(Mandatory = $false)]
        [Alias('por')]
        [string]
        $PauseOnReason,

        # Stop capture when any pktmon DROP is detected.
        [Parameter(Mandatory = $false)]
        [Alias('sod')]
        [switch]
        $StopOnDrop,

        # Stop capture when a DROP with matching location is detected.
        [Parameter(Mandatory = $false)]
        [Alias('sol')]
        [string]
        $StopOnLocation,

        # Stop capture when a DROP with matching reason is detected.
        [Parameter(Mandatory = $false)]
        [Alias('sor')]
        [string]
        $StopOnReason,

        # Milliseconds to keep capturing after a stop trigger fires (StopOnDrop / StopOnReason
        # / StopOnLocation). 0 (default) = stop immediately. Real-time console output and the
        # pcapng writer both continue during the delay window; subsequent stop triggers are
        # suppressed so the deadline isn't reset. Pause triggers remain active.
        [Parameter(Mandatory = $false)]
        [uint32]
        $StopDelay = 0,

        # Write captured packets to an ETL file.
        [Parameter(Mandatory = $false)]
        [Alias('w')]
        [string]
        $WriteFile,

        # Enable real-time console output alongside file write.
        [Parameter(Mandatory = $false)]
        [Alias('rt')]
        [switch]
        $RealTime,

        # Maximum capture file size in MiB (default 512). File wraps circularly when exceeded.
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [uint32]
        $FileSize = 512,

        # Enable continuous flush-to-disk mode (default is write-on-stop).
        [Parameter(Mandatory = $false)]
        [Alias('fd')]
        [switch]
        $FlushDisk,

        # Number of chained files for FlushDisk mode (min/default 2). Only valid with -FlushDisk.
        [Parameter(Mandatory = $false)]
        [ValidateRange(2, 100)]
        [int]
        $NumFiles = 2,

        # Write to ETL file using pktmon CLI. Cannot be used with real-time capture.
        [Parameter(Mandatory = $false)]
        [Alias('etl')]
        [string]
        $WriteEtl,

        # Dump the list of NIC components and exit — wrapper for Get-PspktComponent -NIC.
        # Outputs a table of just Id and Name. No capture is started.
        [Parameter(Mandatory = $false)]
        [Alias('D')]
        [switch]
        $DumpInterfaces
    )

    process {
        # --- DumpInterfaces: print NIC table and return without starting capture ---
        if ($DumpInterfaces.IsPresent) {
            return Get-PspktComponent -NIC | Sort-Object Id | Select-Object Id, Name | Format-Table -AutoSize
        }

        $createdSession = $false

        # Create a session if one was not provided.
        if ($PSCmdlet.ParameterSetName -eq 'Default') {
            $Session = New-PspktSession -Name $Name
            $Session.CaptureType = $CaptureType
            $Session.PacketSize  = $PacketSize
            $Session.LogMode     = [PspktLogMode]::RealTime
            $createdSession = $true
        }

        # Parse IPAddress early so it can be combined with quick filters and VM MAC filters.
        $parsedIP = $null
        if ($PSBoundParameters.ContainsKey('IPAddress') -and -not [string]::IsNullOrEmpty($IPAddress)) {
            $parsedIP = [System.Net.IPAddress]::Parse($IPAddress)
        }

        # Apply quick filters — create and add filters for each active switch.
        $quickFilters = [System.Collections.ArrayList]::new()

        if ($ARP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP'))
        }

        if ($NDP.IsPresent -or $AA.IsPresent -or $AAv6.IsPresent) {
            # NDP uses ICMPv6 types 133-137. Filter on ICMPv6 protocol (58).
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-NDP' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
        }

        if ($DHCP.IsPresent -or $AA.IsPresent -or $AAv4.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-Client' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 68))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-Server' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 67))
        }

        if ($DHCPv6.IsPresent -or $AA.IsPresent -or $AAv6.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-Client' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 546))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-Server' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 547))
        }

        if ($DNS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-UDP' -TransportProtocol 'UDP' -Port1 53))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-TCP' -TransportProtocol 'TCP' -Port1 53))
        }

        if ($DNSoverHTTPS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DoH' -TransportProtocol 'TCP' -Port1 443))
        }

        if ($DNSoverTLS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DoT' -TransportProtocol 'TCP' -Port1 853))
        }

        if ($SMB.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SMB' -TransportProtocol 'TCP' -Port1 445))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-Kerberos' -TransportProtocol 'TCP' -Port1 88))
        }

        if ($SMBoverQUIC.IsPresent) {
            $soqPort = if ($PSBoundParameters.ContainsKey('SMBoverQuicAltPort')) { $SMBoverQuicAltPort } else { 443 }
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SMBoverQUIC' -TransportProtocol 'UDP' -Port1 $soqPort))
        }

        if ($SSH.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SSH' -TransportProtocol 'TCP' -Port1 22))
        }

        if ($RDP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RDP' -TransportProtocol 'TCP' -Port1 3389))
        }

        if ($RPC.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RPC' -TransportProtocol 'TCP' -Port1 135))
        }

        if ($RCP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RCP-TCP' -TransportProtocol 'TCP' -Port1 3343))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RCP-UDP' -TransportProtocol 'UDP' -Port1 3343))
        }

        if ($HTTP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTP' -TransportProtocol 'TCP' -Port1 80))
        }

        if ($HTTPS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTPS' -TransportProtocol 'TCP' -Port1 443))
        }

        if ($WinRM.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-WinRM' -TransportProtocol 'TCP' -Port1 5985))
        }

        if ($WinRMS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-WinRMS' -TransportProtocol 'TCP' -Port1 5986))
        }

        if ($Ping.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
        }

        if ($Ping4.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
        }

        if ($Ping6.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
        }

        # Apply -IPAddress to all quick filters (AND logic within each filter).
        # If no quick filters exist and no VM, create a standalone IP filter.
        if ($null -ne $parsedIP) {
            if ($quickFilters.Count -gt 0) {
                foreach ($qf in $quickFilters) {
                    $qf.SetIp1($parsedIP)
                }
            } elseif (-not $PSBoundParameters.ContainsKey('VM') -and -not $PSBoundParameters.ContainsKey('VMName')) {
                if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $null = $quickFilters.Add((New-PspktFilter -Name "QF-IP-$IPAddress" -EtherType 'IPv4' -Ip1 $parsedIP))
                } else {
                    $null = $quickFilters.Add((New-PspktFilter -Name "QF-IP-$IPAddress" -EtherType 'IPv6' -Ip1 $parsedIP))
                }
            }
        }

        # Add all quick filters to the session.
        foreach ($qf in $quickFilters) {
            Add-PspktFilter -Filter $qf -Session $Session
        }

        # Determine real-time mode.
        # Real-time is enabled when: no -WriteFile (default), or -WriteFile + quick filter, or -WriteFile + -RealTime.
        $hasWriteFile = $PSBoundParameters.ContainsKey('WriteFile') -and -not [string]::IsNullOrEmpty($WriteFile)
        $hasWriteEtl = $PSBoundParameters.ContainsKey('WriteEtl') -and -not [string]::IsNullOrEmpty($WriteEtl)
        $useRealTime = $true
        if ($hasWriteFile) {
            $useRealTime = $RealTime.IsPresent -or ($quickFilters.Count -gt 0)
        }

        # -WriteEtl cannot be combined with real-time capture (pktmon only allows one session).
        if ($hasWriteEtl) {
            if ($hasWriteFile) {
                throw "-WriteEtl cannot be used with -WriteFile. Use one or the other."
            }
            if ($RealTime.IsPresent) {
                throw "-WriteEtl cannot be used with -RealTime. ETL capture uses pktmon's native session."
            }
            $useRealTime = $false
        }

        # Auto-increase PacketSize for protocols that need more payload (e.g., DHCP options at byte 240+).
        # Only bump if the user did not explicitly specify a larger PacketSize.
        if ($quickFilters.Count -gt 0 -and -not $PSBoundParameters.ContainsKey('PacketSize')) {
            $needsDHCP = $DHCP.IsPresent -or $DHCPv6.IsPresent -or $AA.IsPresent -or $AAv4.IsPresent -or $AAv6.IsPresent
            if ($needsDHCP -and $Session.PacketSize -lt 590) {
                $Session.PacketSize = 590
            } elseif ($DNS.IsPresent -and $Session.PacketSize -lt 512) {
                $Session.PacketSize = 512
            }
        }

        if ($Session.Active) {
            throw "Session '$($Session.Name)' is already active. Stop it before starting again."
        }
        if ($Session.Handle -eq [IntPtr]::Zero) {
            throw "Session '$($Session.Name)' has a null handle. It may have been torn down."
        }
        if ($null -eq $Session.Pspkt) {
            throw "Session '$($Session.Name)' has no associated pspkt instance."
        }

        # Reuse an existing valid stream if one is already attached.
        $hasValidStream = $false
        $createdStream = $null
        if ($useRealTime) {
            foreach ($existingStream in $Session.OutputStream) {
                if ($null -ne $existingStream -and $existingStream.Handle -ne [IntPtr]::Zero) {
                    $hasValidStream = $true
                    break
                }
            }

            if (-not $hasValidStream) {
                # Use session's PacketSize as stream truncation to get enough data for parsers.
                # PacketSize 0 means full packet; map to 65535 for the stream (max uint16).
                $streamTruncation = $TruncationSize
                if ($streamTruncation -eq 0 -and $Session.PacketSize -gt 0) {
                    $streamTruncation = [uint16][Math]::Min($Session.PacketSize, 65535)
                } elseif ($streamTruncation -eq 0) {
                    $streamTruncation = [uint16]65535
                }

                # Scale the user-mode SPSC ring buffer with BufferSizeMultiplier as well.
                # Base ring size is 1M entries; multiplier scales linearly with a sane cap.
                $baseRingCap = 1048576
                $targetRingCap = [int]($baseRingCap * $BufferSizeMultiplier)
                if ($targetRingCap -lt $baseRingCap) { $targetRingCap = $baseRingCap }
                if ($targetRingCap -gt 67108864) { $targetRingCap = 67108864 } # cap at 64M entries
                $appliedRingCap = [PktMonApi]::ConfigureRingBuffer($targetRingCap)
                Write-Verbose "Ring buffer capacity: $appliedRingCap entries (multiplier=$BufferSizeMultiplier)"

                $createdStream = $Session.Pspkt.CreateRealtimeStream($BufferSizeMultiplier, $streamTruncation)
                $Session.AttachOutputToSession($createdStream)
            }
        }

        # Add components based on -Component / -VM / -VMName parameters.
        # Only applies when the session has no components already added.
        if ($Session.Components.Count -eq 0) {
            $componentsToAdd = $null

            if ($PSBoundParameters.ContainsKey('VM')) {
                # VM object — resolve components via Get-PspktComponent -VM.
                $componentsToAdd = Get-PspktComponent -VM $VM
                # Add MAC filters for each vmNIC to focus on VM traffic only.
                # When -IPAddress is also specified, combine IP into each MAC filter (AND logic).
                $vmObj = $VM
                $vmAdapters = Get-VMNetworkAdapter -VM $vmObj -ErrorAction SilentlyContinue
                foreach ($adapter in $vmAdapters) {
                    $rawMac = "$($adapter.MacAddress)"
                    # Hyper-V returns "000000000000" when a dynamic MAC hasn't been assigned yet
                    # (e.g., VM has never started). Treat that as "no MAC" and skip — otherwise
                    # we'd add a 00:00:00:00:00:00 filter that matches essentially no traffic.
                    if ([string]::IsNullOrEmpty($rawMac) -or $rawMac -eq '000000000000') {
                        Write-Warning "VM '$($vmObj.Name)' vmNIC '$($adapter.Name)' has no assigned MAC address (VM not yet started?). Skipping per-NIC MAC filter."
                        continue
                    }
                    $macStr = $rawMac -replace '(.{2})(?=.)', '$1-'
                    $filterParams = @{ Name = "QF-VM-MAC-$macStr"; Mac1 = $macStr }
                    if ($null -ne $parsedIP) {
                        $filterParams['Ip1'] = $parsedIP
                        if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                            $filterParams['EtherType'] = 'IPv4'
                        } else {
                            $filterParams['EtherType'] = 'IPv6'
                        }
                    }
                    $macFilter = New-PspktFilter @filterParams
                    Add-PspktFilter -Filter $macFilter -Session $Session
                }
            } elseif ($PSBoundParameters.ContainsKey('VMName') -and -not [string]::IsNullOrEmpty($VMName)) {
                # VM name string — resolve via Get-PspktComponent -VMName.
                $componentsToAdd = Get-PspktComponent -VMName $VMName
                # Add MAC filters for each vmNIC to focus on VM traffic only.
                # When -IPAddress is also specified, combine IP into each MAC filter (AND logic).
                $vmAdapters = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
                foreach ($adapter in $vmAdapters) {
                    $rawMac = "$($adapter.MacAddress)"
                    if ([string]::IsNullOrEmpty($rawMac) -or $rawMac -eq '000000000000') {
                        Write-Warning "VM '$VMName' vmNIC '$($adapter.Name)' has no assigned MAC address (VM not yet started?). Skipping per-NIC MAC filter."
                        continue
                    }
                    $macStr = $rawMac -replace '(.{2})(?=.)', '$1-'
                    $filterParams = @{ Name = "QF-VM-MAC-$macStr"; Mac1 = $macStr }
                    if ($null -ne $parsedIP) {
                        $filterParams['Ip1'] = $parsedIP
                        if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                            $filterParams['EtherType'] = 'IPv4'
                        } else {
                            $filterParams['EtherType'] = 'IPv6'
                        }
                    }
                    $macFilter = New-PspktFilter @filterParams
                    Add-PspktFilter -Filter $macFilter -Session $Session
                }
            } elseif ($Component.Count -eq 1 -and $Component[0] -eq 'NICs') {
                # NICs keyword — capture from NIC components only.
                $componentsToAdd = $Session.Pspkt.EnumPktmonDataSources($true, 1)
            } elseif ($Component.Count -eq 1 -and $Component[0] -eq 'All') {
                # All keyword (default) — capture from all components.
                $allSources = $Session.Pspkt.EnumPktmonDataSources($true, 0)
                $nicSources = $Session.Pspkt.EnumPktmonDataSources($true, 1)
                $componentsToAdd = [System.Collections.ArrayList]::new()
                if ($null -ne $nicSources) { $null = $componentsToAdd.AddRange($nicSources) }
                if ($null -ne $allSources) { $null = $componentsToAdd.AddRange($allSources) }
            } else {
                # Treat values as component IDs — enumerate all and filter by ID.
                $allSources = $Session.Pspkt.EnumPktmonDataSources($true, 0)
                $nicSources = $Session.Pspkt.EnumPktmonDataSources($true, 1)
                $all = [System.Collections.ArrayList]::new()
                if ($null -ne $nicSources) { $null = $all.AddRange($nicSources) }
                if ($null -ne $allSources) { $null = $all.AddRange($allSources) }

                [int[]]$ids = @()
                foreach ($c in $Component) {
                    $parsed = 0
                    if ([int]::TryParse($c, [ref]$parsed)) {
                        $ids += $parsed
                    } else {
                        Write-Warning "Ignoring non-numeric component value: '$c'"
                    }
                }

                $componentsToAdd = $all | Where-Object { $_.Id -in $ids }
            }

            if ($null -ne $componentsToAdd) {
                foreach ($comp in $componentsToAdd) {
                    if ($null -ne $comp -and $comp.Pointer -ne [IntPtr]::Zero) {
                        $Session.AddSingleDataSourceToSession($comp)
                    }
                }
            }
            Write-Verbose "Total components added to session: $($Session.Components.Count)"
        }

        try {
            $Session.SetSessionActive($true)
        }
        catch {
            # Roll back the stream we just created if activation fails.
            if ($null -ne $createdStream) {
                $Session.Pspkt.PacketMonitorCloseRealtimeStream($createdStream)
            }
            # If we created the session, tear it down on failure.
            if ($createdSession) {
                if ($Session.Handle -ne [IntPtr]::Zero) {
                    $Session.Pspkt.PacketMonitorCloseSessionHandle($Session)
                }
                $Session.Pspkt.PacketMonitorUninitialize()
            }
            throw
        }

        # Real-time blocking read loop. Ctrl+C triggers the finally block for cleanup.
        $packetCount = 0
        $droppedCount = 0
        [PktMonApi]::ClearPacketBuffer()
        [PktMonApi]::ResetDroppedCount()
        [PktMonApi]::ClearSeenComponentIds()
        [PktMonApi]::InitTimestampBaseline()
        Reset-PspktLineCounter

        # Set detail level based on ParsingLevel enum.
        Set-PspktDetailLevel -Level ([int]$ParsingLevel)
        Set-PspktDetailSpacing -Enabled ($ParsingLevel -ge [PspktParsingLevel]::Detailed -and $Spaced.IsPresent)
        Set-PspktShowTimestamp -Enabled $Timestamp.IsPresent

        # Populate component name lookup from pktmon.
        try {
            $components = Get-PspktComponent
            Register-PspktComponentMap -Components $components
        } catch {
            Write-Verbose "Could not enumerate components: $_"
        }

        # --- Pcapng file writer setup ---
        $pcapngWriter = $null
        if ($PSBoundParameters.ContainsKey('WriteFile') -and -not [string]::IsNullOrEmpty($WriteFile)) {
            # Resolve the file path to absolute.
            $pcapngPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WriteFile)
            if (-not $pcapngPath.EndsWith('.pcapng', [StringComparison]::OrdinalIgnoreCase)) {
                $pcapngPath = $pcapngPath + '.pcapng'
            }

            # Start pcapng writer (async mode for non-blocking writes from callback).
            $pcapngWriter = [PcapngWriter]::new()

            # Register components for enriched packet comments.
            if ($null -ne $components) {
                foreach ($comp in $components) {
                    if ($null -ne $comp.Id) {
                        $pcapngWriter.RegisterComponent([int]$comp.Id, $comp.Name, $comp.Group, [int]$comp.ParentId)
                        if ($null -ne $comp.SecondaryId -and [int]$comp.SecondaryId -ne [int]$comp.Id) {
                            $pcapngWriter.RegisterComponent([int]$comp.SecondaryId, $comp.Name, $comp.Group, [int]$comp.ParentId)
                        }
                    }
                }
            }

            # Always run the pcapng writer in async (writer thread) mode so file I/O never
            # blocks the pktmon callback. -FlushDisk controls flush frequency only:
            # true = Flush() after every batch (durability), false = flush only on stop (throughput).
            # -FileSize (MiB) + -NumFiles control circular rotation.
            $useAsync = $true
            $ringCap = 65536
            # FileSize parameter is in MiB; convert to bytes. NumFiles > 1 enables rotation.
            [long]$maxBytes = if ($NumFiles -gt 1) { [long]$FileSize * 1MB } else { 0 }
            $pcapngWriter.Start($pcapngPath, $useAsync, $ringCap, $FlushDisk.IsPresent, $maxBytes, [int]$NumFiles)

            # Register with the callback so packets are captured to file.
            [PktMonApi]::FileWriter = $pcapngWriter

            if ($FlushDisk.IsPresent) { $modeLabel = "FlushDisk" } else { $modeLabel = "WriteOnStop" }
            $rotInfo = if ($NumFiles -gt 1) { " [rotation: $NumFiles x $($FileSize)MiB]" } else { '' }
            Write-Host "File writer started: $pcapngPath ($modeLabel)$rotInfo" -ForegroundColor DarkCyan
        }

        try {
          if ($useRealTime) {
            # Determine if pause/stop features are active.
            $pauseEnabled = $Pause.IsPresent -or $PauseOnDrop.IsPresent -or
                $PSBoundParameters.ContainsKey('PauseOnLocation') -or
                $PSBoundParameters.ContainsKey('PauseOnReason') -or
                $StopOnDrop.IsPresent -or
                $PSBoundParameters.ContainsKey('StopOnLocation') -or
                $PSBoundParameters.ContainsKey('StopOnReason')

            # Resolve trigger values at capture start for fast comparison in loop.
            [int]$pauseLocValue = 0
            [int]$pauseReasonValue = 0
            [int]$stopLocValue = 0
            [int]$stopReasonValue = 0
            if ($PSBoundParameters.ContainsKey('PauseOnLocation') -and $PauseOnLocation) {
                $pauseLocValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_LOCATION]) -Value $PauseOnLocation)
            }
            if ($PSBoundParameters.ContainsKey('PauseOnReason') -and $PauseOnReason) {
                $pauseReasonValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_REASON]) -Value $PauseOnReason)
            }
            if ($PSBoundParameters.ContainsKey('StopOnLocation') -and $StopOnLocation) {
                $stopLocValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_LOCATION]) -Value $StopOnLocation)
            }
            if ($PSBoundParameters.ContainsKey('StopOnReason') -and $StopOnReason) {
                $stopReasonValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_REASON]) -Value $StopOnReason)
            }

            $pauseHint = if ($pauseEnabled -and $Pause.IsPresent) { " Press 'p' to pause." } else { '' }
            Write-Host "Capturing packets in real-time. Press Ctrl+C to stop...$pauseHint" -ForegroundColor Cyan
            Write-Host (Get-PspktCaptureHeader)
            # Lock component refresh during capture to prevent stalling the consumer.
            $script:ComponentRefreshLocked = $true
            $sb = [System.Text.StringBuilder]::new(16384)
            $stream = $Session.OutputStream[0]
            $paused = $false
            $stopRequested = $false

            # Use the high-throughput C# bulk-format path for all detail levels.
            # Drop triggers are handled in C# FormatBatch.
            $useBulkFormat = $true
            $bulkLineCounter = 0

            # Configure C# drop triggers for the bulk-format path.
            [PacketLineFormatter]::SetDropTriggers(
                $StopOnDrop.IsPresent,
                $PauseOnDrop.IsPresent,
                $stopReasonValue,
                $stopLocValue,
                $pauseReasonValue,
                $pauseLocValue
            )

            # StopDelay support: when a stop trigger fires we record a deadline and let
            # capture continue normally until it expires. Console + pcapng writer keep
            # running because both run on their own threads and the consumer loop continues
            # to drain/format. We disable further stop triggers in C# so they don't reset
            # the deadline (pause triggers stay active).
            $stopDelayMs = [int]$StopDelay
            $stopDelayActive = $false
            $stopDelayWatch = [System.Diagnostics.Stopwatch]::new()

            # Configure ICMP display filter. pktmon driver filters can't constrain on ICMP type,
            # so -Ping (echo only) and -NDP (types 133-137 only) are enforced at display time.
            $icmpEchoOnly = $Ping.IsPresent -or $Ping4.IsPresent -or $Ping6.IsPresent
            $icmpNdpOnly  = $NDP.IsPresent -or $AA.IsPresent -or $AAv6.IsPresent
            [PacketLineFormatter]::SetIcmpDisplayFilter($icmpEchoOnly, $icmpNdpOnly)

            # Mark capture active so the C# ring buffer wakes its waiter on stop.
            [PktMonApi]::SetCaptureActive($true)

            while ($Session.Active -and -not $stopRequested) {
                # --- Key press handling (non-blocking) ---
                if ($pauseEnabled -and [Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    $ch = [char]::ToLower($key.KeyChar)
                    if (-not $paused -and $ch -eq 'p' -and $Pause.IsPresent) {
                        $paused = $true
                        # Drain remaining ring buffer before showing pause message.
                        $drainCount = $Session.DrainAllRawPackets()
                        if ($drainCount -gt 0) {
                            try {
                                $result = [PacketLineFormatter]::FormatBatch($stream.PacketBuffer, $drainCount, $bulkLineCounter)
                                if ($null -ne $result) {
                                    $bulkLineCounter = $result.LineCounter
                                    $packetCount += $result.PacketCount
                                    $droppedCount += $result.DroppedCount
                                    if ($null -ne $result.Output) { [Console]::Write($result.Output) }
                                }
                            } finally {
                                [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $drainCount)
                            }
                        }
                        Write-Host "=====  Real-time mode is Paused. Press 'r' to resume or 'q' to quit... =====" -ForegroundColor Yellow
                        continue
                    }
                    if ($paused -and $ch -eq 'r') {
                        $paused = $false
                        Write-Host "  Resumed." -ForegroundColor Green
                        continue
                    }
                    if ($paused -and $ch -eq 'q') {
                        $stopRequested = $true
                        continue
                    }
                }

                # --- Paused state: discard packets without counting ---
                if ($paused) {
                    $discarded = $Session.DrainAllRawPackets()
                    if ($discarded -gt 0) {
                        # Return pooled buffers even on discard to prevent pool leak.
                        [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $discarded)
                    } else {
                        # Use the signaled wait (wakes on next packet or timeout).
                        $null = [PktMonApi]::WaitForPackets($PollingIntervalMs)
                    }
                    continue
                }

                # --- Active capture: process packets ---
                # === HIGH-THROUGHPUT C# BULK-FORMAT PATH ===
                # Drains raw PSPacketData and formats entirely in C#.
                # Drop triggers are checked in C# and reported via TriggerAction.
                $pktCount = $Session.DrainAllRawPackets()
                if ($pktCount -gt 0) {
                    try {
                        $result = [PacketLineFormatter]::FormatBatch($stream.PacketBuffer, $pktCount, $bulkLineCounter)
                        if ($null -ne $result) {
                            $bulkLineCounter = $result.LineCounter
                            $packetCount += $result.PacketCount
                            $droppedCount += $result.DroppedCount
                            if ($null -ne $result.Output) {
                                [Console]::Write($result.Output)
                            }

                            # Handle drop trigger actions from C#.
                            if ($result.TriggerAction -eq 2) {
                                if ($stopDelayMs -gt 0 -and -not $stopDelayActive) {
                                    # Stop trigger fired with -StopDelay set — keep capturing.
                                    # Disable further stop triggers in C# so the same packet
                                    # type doesn't restart the deadline; pause triggers stay.
                                    [PacketLineFormatter]::SetDropTriggers(
                                        $false,
                                        $PauseOnDrop.IsPresent,
                                        0,
                                        0,
                                        $pauseReasonValue,
                                        $pauseLocValue
                                    )
                                    $stopDelayWatch.Restart()
                                    $stopDelayActive = $true
                                    Write-Host "Stop trigger fired; continuing capture for $stopDelayMs ms before stopping..." -ForegroundColor Yellow
                                } elseif (-not $stopDelayActive) {
                                    # No StopDelay — original behavior, stop immediately.
                                    $stopRequested = $true
                                }
                                # If $stopDelayActive is already true, ignore further stop triggers
                                # (the deadline check below will end the capture when it expires).
                            } elseif ($result.TriggerAction -eq 1 -and -not $paused) {
                                # Pause trigger fired — drain remaining and enter pause.
                                $paused = $true
                                $drainCount = $Session.DrainAllRawPackets()
                                if ($drainCount -gt 0) {
                                    try {
                                        $drainResult = [PacketLineFormatter]::FormatBatch($stream.PacketBuffer, $drainCount, $bulkLineCounter)
                                        if ($null -ne $drainResult) {
                                            $bulkLineCounter = $drainResult.LineCounter
                                            $packetCount += $drainResult.PacketCount
                                            $droppedCount += $drainResult.DroppedCount
                                            if ($null -ne $drainResult.Output) { [Console]::Write($drainResult.Output) }
                                        }
                                    } finally {
                                        [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $drainCount)
                                    }
                                }
                                Write-Host "=====  Real-time mode is Paused. Press 'r' to resume or 'q' to quit... =====" -ForegroundColor Yellow
                            }
                        }
                    } finally {
                        # Always return pooled buffers, even on exception or trigger.
                        [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $pktCount)
                    }
                } else {
                    # No packets available — wait for the producer to signal or timeout.
                    # This eliminates the fixed PollingIntervalMs latency floor and idle CPU usage.
                    $null = [PktMonApi]::WaitForPackets($PollingIntervalMs)
                }

                # StopDelay deadline check — runs every iteration regardless of packet count
                # so an idle delay-period still terminates promptly.
                if ($stopDelayActive -and $stopDelayWatch.ElapsedMilliseconds -ge $stopDelayMs) {
                    $stopRequested = $true
                }
            }
          } elseif ($hasWriteEtl) {
            # --- ETL file mode: use pktmon CLI ---
            $etlPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WriteEtl)
            if (-not $etlPath.EndsWith('.etl', [StringComparison]::OrdinalIgnoreCase)) {
                $etlPath = $etlPath + '.etl'
            }

            # Build pktmon start arguments.
            $pktmonArgs = @('start', '--capture')
            $pktmonArgs += '--file-name', $etlPath
            $pktmonArgs += '--file-size', $FileSize.ToString()
            $pktmonArgs += '--pkt-size', $Session.PacketSize.ToString()
            $pktmonArgs += '--log-mode', 'circular'

            # Add component filter if specific components were selected.
            if ($PSBoundParameters.ContainsKey('Component') -and $Component.Count -ge 1 -and $Component[0] -ne 'All') {
                $pktmonArgs += '--comp'
                $pktmonArgs += $Component
            }

            # Stop any existing pktmon session before starting.
            $null = pktmon stop 2>$null

            # We don't need the pspkt session for ETL mode — tear it down.
            Stop-Pspkt -Session $Session -Teardown

            Write-Host "Starting ETL capture: $etlPath" -ForegroundColor Cyan
            $pktmonOutput = & pktmon @pktmonArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "pktmon start failed (exit $LASTEXITCODE): $pktmonOutput"
            }
            Write-Host "ETL capture active. Use 'pktmon stop' to stop and save the file." -ForegroundColor Cyan
            Write-Host $pktmonOutput -ForegroundColor DarkGray
            return
          } else {
            # --- File-only mode (pcapng): return session to console ---
            Write-Host "Capturing to file: $pcapngPath" -ForegroundColor Cyan
            Write-Host "Use Stop-Pspkt to stop capture and save the file." -ForegroundColor Cyan
            return $Session
          }
        }
        finally {
            $script:ComponentRefreshLocked = $false

            # Mark capture inactive (wakes any consumer/writer waiters).
            [PktMonApi]::SetCaptureActive($false)

            # Stop pcapng file writer if active.
            if ($null -ne $pcapngWriter -and $pcapngWriter.IsActive) {
                [PktMonApi]::FileWriter = $null
                $pcapngWriter.Stop()
                $fileDrops = $pcapngWriter.FileDroppedCount
                $dropSuffix = if ($fileDrops -gt 0) { "; FileDrops: $fileDrops" } else { '' }
                Write-Host "File saved: $($pcapngWriter.FileName) ($($pcapngWriter.PacketCount) packets$dropSuffix)" -ForegroundColor DarkCyan
                if ($fileDrops -gt 0) {
                    Write-Warning "Pcapng file writer dropped $fileDrops packet(s) because the writer thread couldn't keep up. The file is missing data - consider a faster disk, larger -BufferSizeMultiplier, or remove -FlushDisk."
                }
                $lastErr = $pcapngWriter.LastError
                if (-not [string]::IsNullOrEmpty($lastErr)) {
                    Write-Warning "Pcapng writer reported an error: $lastErr"
                }
            }

            if ($useRealTime) {
                $missedWrite = [PacketData]::MissedPacketWriteCount
                $missedRead  = [PacketData]::MissedPacketReadCount
                $missedTotal = $missedWrite + $missedRead
                $bufferDropped = [PktMonApi]::DroppedCount
                Write-Host "`nStopping capture... [Captured: $packetCount; Drops: $droppedCount; Missed: $missedTotal; BufferOverflow: $bufferDropped]" -ForegroundColor Cyan

                # Session summary: list components that appeared in capture.
                $seenIds = [PktMonApi]::GetSeenComponentIds()
                if ($seenIds.Count -gt 0 -and $null -ne $components) {
                    Write-Host "`nComponents:" -ForegroundColor DarkGray
                    foreach ($comp in $components) {
                        if ([int]$comp.Id -in $seenIds) {
                            $compLine = "  {0}:{1} {2}" -f [int]$comp.ParentId, [int]$comp.Id, $comp.Name
                            Write-Host $compLine -ForegroundColor DarkGray
                        }
                    }
                }

                # List filters used in this session.
                if ($Session.Filters.Count -gt 0) {
                    Write-Host "Filters:" -ForegroundColor DarkGray
                    foreach ($f in $Session.Filters) {
                        Write-Host "  $($f.Name)" -ForegroundColor DarkGray
                    }
                }
            } else {
                Write-Host "`nStopping capture..." -ForegroundColor Cyan
            }
            Stop-Pspkt -Session $Session -Teardown
        }
    }
}

<#
.SYNOPSIS
Stops a packet monitor session.

.DESCRIPTION
Deactivates the session. With -Teardown, also closes all real-time streams,
the session handle, and uninitializes the pktmon API.

Without -Teardown the session can be restarted with Start-Pspkt.
With -Teardown the session object is no longer usable.

.PARAMETER Session
The pspktSession to stop.

.PARAMETER Teardown
Fully close the session and release all native resources. The session
object cannot be reused after teardown.

.OUTPUTS
pspktSession (without -Teardown) or nothing (with -Teardown).
#>
function Stop-Pspkt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false)]
        [switch]
        $Teardown
    )

    process {
        if ($Teardown) {
            # Deactivate if still active.
            if ($Session.Active -and $Session.Handle -ne [IntPtr]::Zero) {
                $Session.SetSessionActive($false)
            }

            # Close all attached real-time streams (snapshot to avoid mutation during enumeration).
            if ($null -ne $Session.Pspkt) {
                $streams = @($Session.OutputStream)
                foreach ($stream in $streams) {
                    if ($null -ne $stream -and $stream.Handle -ne [IntPtr]::Zero) {
                        $Session.Pspkt.PacketMonitorCloseRealtimeStream($stream)
                    }
                }
            }

            # Reset the SPSC ring buffer dropped counter for a clean next session.
            [PktMonApi]::ResetDroppedCount()

            # Close the session handle.
            if ($Session.Handle -ne [IntPtr]::Zero) {
                if ($null -ne $Session.Pspkt) {
                    $Session.Pspkt.PacketMonitorCloseSessionHandle($Session)
                } else {
                    $Session.CloseSessionHandle()
                }
            }

            # Uninitialize the pktmon API.
            if ($null -ne $Session.Pspkt) {
                $Session.Pspkt.PacketMonitorUninitialize()
                $Session.Pspkt = $null
            }

            return
        }

        # Simple stop — deactivate only.
        if (-not $Session.Active) {
            Write-Verbose "Session '$($Session.Name)' is already inactive."
            return $Session
        }

        if ($Session.Handle -eq [IntPtr]::Zero) {
            throw "Session '$($Session.Name)' has a null handle."
        }

        $Session.SetSessionActive($false)

        # Stop pcapng file writer if still active.
        $fw = [PktMonApi]::FileWriter
        if ($null -ne $fw -and $fw.IsActive) {
            [PktMonApi]::FileWriter = $null
            $fw.Stop()
            $fileDrops = $fw.FileDroppedCount
            $dropSuffix = if ($fileDrops -gt 0) { "; FileDrops: $fileDrops" } else { '' }
            Write-Host "File saved: $($fw.FileName) ($($fw.PacketCount) packets$dropSuffix)" -ForegroundColor DarkCyan
            if ($fileDrops -gt 0) {
                Write-Warning "Pcapng file writer dropped $fileDrops packet(s) because the writer thread couldn't keep up."
            }
            $lastErr = $fw.LastError
            if (-not [string]::IsNullOrEmpty($lastErr)) {
                Write-Warning "Pcapng writer reported an error: $lastErr"
            }
        }

        return $Session
    }
}

Set-Alias -Name pspkt -Value Start-Pspkt
Export-ModuleMember -Function New-PspktSession, Get-PspktSession, Set-PspktSession, Start-Pspkt, Stop-Pspkt -Alias pspkt
