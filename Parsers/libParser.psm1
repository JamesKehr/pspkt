# libParser.psm1 - Shared utilities for pspkt real-time packet formatters.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ESC = [char]27
$script:LineCounter = 0
$script:ColorScheme = $null
$script:AnsiCache = @{}
$script:AnsiReset = ''
$script:ProfilesDir = Join-Path $PSScriptRoot 'ColorProfiles'
$script:ComponentMap = @{}
$script:ComponentMisses = @{}  # IDs we already tried to refresh and still couldn't find.
$script:DetailLevel = 0  # -1 = Minimal, 0 = Default, 1 = Detailed (-v), 2 = VeryDetailed (-vv)
$script:DetailSpacing = $false  # When true, adds blank line between packets in detailed mode.
$script:ShowTimestamp = $false  # When true, prepends packet timestamp to output.
$script:DetailIndent = " $([char]0x2514)"
$script:ColoredIndent1 = "$([char]0x1b)[97m$($script:DetailIndent)$([char]0x1b)[0m"
$script:ColoredIndent2 = "$([char]0x1b)[97m $($script:DetailIndent)$([char]0x1b)[0m"
$script:ColoredIndent3 = "$([char]0x1b)[97m  $($script:DetailIndent)$([char]0x1b)[0m"
$script:ComponentRefreshLocked = $false  # When true, prevents mid-capture component map refresh.

# Load sub-parsers.
Import-Module (Join-Path $PSScriptRoot 'DataLink\ethernet.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Network\ipv4.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Network\ipv6.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Network\icmp.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Network\ndp.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Network\arp.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Transport\tcp.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Application\dns.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Application\dhcp.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Application\http.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'Application\smb2.psm1') -Force -Global

# --------------------------------------------------------------------------
# Register drop reason/location enum names into C# formatter for display.
# --------------------------------------------------------------------------
foreach ($name in [PKTMON_DROP_REASON].GetEnumNames()) {
    $val = [int][PKTMON_DROP_REASON]::$name
    $displayName = $name -replace '^PktMonDrop_', ''
    [PacketLineFormatter]::RegisterDropReason($val, $displayName)
}
foreach ($name in [PKTMON_DROP_LOCATION].GetEnumNames()) {
    $val = [int][PKTMON_DROP_LOCATION]::$name
    $displayName = $name -replace '^PMLOC_', ''
    [PacketLineFormatter]::RegisterDropLocation($val, $displayName)
}

# --------------------------------------------------------------------------
# Color Profile Management
# --------------------------------------------------------------------------

# Ensures the loaded color scheme has all required layer keys.
# Injects a default Component entry if missing (supports older custom profiles).
<#
.SYNOPSIS
Ensures the loaded color scheme has all required layer keys.
#>
function Repair-PspktColorScheme {
    if ($null -eq $script:ColorScheme) { return }
    if ($null -eq $script:ColorScheme['Component']) {
        $script:ColorScheme['Component'] = @{
            Bright = '38;2;255;140;90'
            Muted  = '38;2;180;100;65'
        }
    }
    if ($null -eq $script:ColorScheme['Drop']) {
        $script:ColorScheme['Drop'] = @{
            Bright = '38;2;255;60;60'
            Muted  = '38;2;180;40;40'
        }
    }
}

<#
.SYNOPSIS
Gets the path to the ColorProfiles directory.
#>
function Get-PspktProfilePath {
    [CmdletBinding()]
    param()
    return $script:ProfilesDir
}

<#
.SYNOPSIS
Lists all available color profiles.

.DESCRIPTION
Returns the names of all .psd1 files in the ColorProfiles directory.
The active profile is indicated with an asterisk (*).
#>
function Get-PspktParserColorProfile {
    [CmdletBinding()]
    param()

    $activeFile = Join-Path $script:ProfilesDir 'active.txt'
    $activeName = 'default'
    if (Test-Path $activeFile) {
        $activeName = (Get-Content $activeFile -Raw).Trim()
    }

    $profiles = Get-ChildItem -Path $script:ProfilesDir -Filter '*.psd1' | ForEach-Object {
        $name = $_.BaseName
        $isActive = ($name -eq $activeName)
        [PSCustomObject]@{
            Name   = $name
            Active = $isActive
            Path   = $_.FullName
        }
    }
    return $profiles
}

# Syncs the current PS color scheme to the C# PacketFormatter for fast colorization.
<#
.SYNOPSIS
Syncs the current PS color scheme to the C# PacketFormatter for fast colorization.
#>
function Sync-PspktFormatterColors {
    $scheme = $script:ColorScheme
    if ($null -eq $scheme) { return }
    $layers = @('Component', 'DataLink', 'Network', 'Transport', 'Application', 'Drop')
    $sgrs = [string[]]::new(12)
    for ($i = 0; $i -lt $layers.Count; $i++) {
        $layer = $scheme[$layers[$i]]
        if ($null -ne $layer) {
            $sgrs[$i * 2] = $layer['Bright']
            $sgrs[$i * 2 + 1] = $layer['Muted']
        } else {
            $sgrs[$i * 2] = '0'
            $sgrs[$i * 2 + 1] = '0'
        }
    }
    $resetSgr = '0'
    if ($null -ne $scheme['Reset']) { $resetSgr = $scheme['Reset'] }
    [PacketFormatter]::InitColorScheme($sgrs, $resetSgr)
}

<#
.SYNOPSIS
Imports (activates in memory) a color profile by name or path.

.DESCRIPTION
Loads the specified color profile into the active color scheme used for formatting.
If no name is given, loads the default profile set in active.txt.

.PARAMETER Name
Profile name (basename of a .psd1 in ColorProfiles). Mutually exclusive with -Path.

.PARAMETER Path
Full path to a .psd1 color profile file. Mutually exclusive with -Name.
#>
function Import-PspktParserColorProfile {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'ByName', Position = 0)]
        [string]
        $Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]
        $Path
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
        if (-not (Test-Path $Path)) {
            throw "Color profile not found: $Path"
        }
        $script:ColorScheme = Import-PowerShellDataFile -Path $Path
        Repair-PspktColorScheme
        $script:AnsiReset = "$($script:ESC)[$($script:ColorScheme.Reset)m"
        $script:AnsiCache = @{}
        Sync-PspktFormatterColors
        return
    }

    # ByName (or default)
    if ([string]::IsNullOrEmpty($Name)) {
        $activeFile = Join-Path $script:ProfilesDir 'active.txt'
        if (Test-Path $activeFile) {
            $Name = (Get-Content $activeFile -Raw).Trim()
        } else {
            $Name = 'default'
        }
    }

    $profilePath = Join-Path $script:ProfilesDir "$Name.psd1"
    if (-not (Test-Path $profilePath)) {
        throw "Color profile '$Name' not found at: $profilePath"
    }
    $script:ColorScheme = Import-PowerShellDataFile -Path $profilePath
    Repair-PspktColorScheme
    $script:AnsiReset = "$($script:ESC)[$($script:ColorScheme.Reset)m"
    $script:AnsiCache = @{}
    Sync-PspktFormatterColors
}

<#
.SYNOPSIS
Sets the default color profile used on module load.

.DESCRIPTION
Writes the profile name to active.txt and imports it into memory.

.PARAMETER Name
The profile name to set as default.
#>
function Set-PspktParserColorProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Name
    )

    $profilePath = Join-Path $script:ProfilesDir "$Name.psd1"
    if (-not (Test-Path $profilePath)) {
        throw "Color profile '$Name' not found at: $profilePath"
    }

    $activeFile = Join-Path $script:ProfilesDir 'active.txt'
    Set-Content -Path $activeFile -Value $Name -NoNewline
    Import-PspktParserColorProfile -Name $Name
    Write-Host "Default color profile set to '$Name'." -ForegroundColor Green
}

<#
.SYNOPSIS
Creates a new color profile hashtable in memory.

.DESCRIPTION
Returns a hashtable with the four layer colors (DataLink, Network, Transport, Application)
populated with the specified ANSI SGR color parameters. Use Save-PspktParserColorProfile to persist.

.PARAMETER DataLinkBright
ANSI SGR params for DataLink bright lines (e.g. '38;2;100;200;255').

.PARAMETER DataLinkMuted
ANSI SGR params for DataLink muted lines.

.PARAMETER NetworkBright
ANSI SGR params for Network bright lines.

.PARAMETER NetworkMuted
ANSI SGR params for Network muted lines.

.PARAMETER TransportBright
ANSI SGR params for Transport bright lines.

.PARAMETER TransportMuted
ANSI SGR params for Transport muted lines.

.PARAMETER ApplicationBright
ANSI SGR params for Application bright lines.

.PARAMETER ApplicationMuted
ANSI SGR params for Application muted lines.
#>
function New-PspktParserColorProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ComponentBright,

        [Parameter(Mandatory = $true)]
        [string] $ComponentMuted,

        [Parameter(Mandatory = $true)]
        [string] $DataLinkBright,

        [Parameter(Mandatory = $true)]
        [string] $DataLinkMuted,

        [Parameter(Mandatory = $true)]
        [string] $NetworkBright,

        [Parameter(Mandatory = $true)]
        [string] $NetworkMuted,

        [Parameter(Mandatory = $true)]
        [string] $TransportBright,

        [Parameter(Mandatory = $true)]
        [string] $TransportMuted,

        [Parameter(Mandatory = $true)]
        [string] $ApplicationBright,

        [Parameter(Mandatory = $true)]
        [string] $ApplicationMuted
    )

    return @{
        Component = @{
            Bright = $ComponentBright
            Muted  = $ComponentMuted
        }
        DataLink = @{
            Bright = $DataLinkBright
            Muted  = $DataLinkMuted
        }
        Network = @{
            Bright = $NetworkBright
            Muted  = $NetworkMuted
        }
        Transport = @{
            Bright = $TransportBright
            Muted  = $TransportMuted
        }
        Application = @{
            Bright = $ApplicationBright
            Muted  = $ApplicationMuted
        }
        Reset = '0'
    }
}

<#
.SYNOPSIS
Displays sample output lines using a color profile to preview terminal appearance.

.DESCRIPTION
Prints sample lines (one bright, one muted) showing all layers. When no arguments
are given, shows samples for every available profile. Accepts a profile name string
or a hashtable directly.

.PARAMETER Name
Profile name (basename of a .psd1 in ColorProfiles).

.PARAMETER Profile
A color profile hashtable (from New-PspktParserColorProfile or Import-PowerShellDataFile).
#>
function Test-PspktParserColorProfile {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'ByName', Position = 0)]
        [string]
        $Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByHashtable')]
        [hashtable]
        $Profile
    )

    $prevScheme = $script:ColorScheme
    $prevCounter = $script:LineCounter

    # Determine which profiles to preview.
    if ($PSCmdlet.ParameterSetName -eq 'ByHashtable') {
        $profilesToTest = @(@{ Name = '(custom)'; Scheme = $Profile })
    } elseif (-not [string]::IsNullOrEmpty($Name)) {
        $profilePath = Join-Path $script:ProfilesDir "$Name.psd1"
        if (-not (Test-Path $profilePath)) {
            throw "Color profile '$Name' not found at: $profilePath"
        }
        $scheme = Import-PowerShellDataFile -Path $profilePath
        $profilesToTest = @(@{ Name = $Name; Scheme = $scheme })
    } else {
        # No argument — show all available profiles.
        $profilesToTest = @()
        $profileFiles = Get-ChildItem -Path $script:ProfilesDir -Filter '*.psd1' | Sort-Object Name
        foreach ($pf in $profileFiles) {
            $scheme = Import-PowerShellDataFile -Path $pf.FullName
            $profilesToTest += @{ Name = $pf.BaseName; Scheme = $scheme }
        }
    }

    foreach ($entry in $profilesToTest) {
        $testScheme = $entry.Scheme
        $script:ColorScheme = $testScheme
        Repair-PspktColorScheme
        $script:AnsiReset = "$($script:ESC)[$($testScheme.Reset)m"
        $script:AnsiCache = @{}
        Sync-PspktFormatterColors

        Write-Host "`n  Profile: $($entry.Name)" -ForegroundColor White
        Write-Host ('  ' + ('-' * 98))

        # Bright line (even counter)
        $script:LineCounter = 0
        $compSample = Add-PspktColor -Text '001:005 (Networking:TCP/IPv4 -)' -Layer Component
        $dlSample  = Add-PspktColor -Text 'a4-3f-68-1e-d9-68 > 7c-1e-52-97-b1-46, type IPv4, len 74' -Layer DataLink
        $netSample = Add-PspktColor -Text '10.0.0.1.443 > 10.0.0.2.52341' -Layer Network
        $trSample  = Add-PspktColor -Text 'TCP [.P], seq 1234, ack 5678, win 251, len 20' -Layer Transport
        $appSample = Add-PspktColor -Text 'DNS 12345+ A? www.example.com. (35)' -Layer Application
        [Console]::WriteLine("    ${compSample}: ${dlSample}: ${netSample}: ${trSample}")
        [Console]::WriteLine("    ${compSample}: ${dlSample}: ${netSample}: ${appSample}")

        # Muted line (odd counter)
        $script:LineCounter = 1
        $compSample = Add-PspktColor -Text '001:012 (Networking:Intel(R) W)' -Layer Component
        $dlSample  = Add-PspktColor -Text 'a4-3f-68-1e-d9-68 > 7c-1e-52-97-b1-46, type ARP, len 42' -Layer DataLink
        $netSample = Add-PspktColor -Text 'ARP, Request who-has 10.0.0.1 tell 10.0.0.2, len 28' -Layer Network
        [Console]::WriteLine("    ${compSample}: ${dlSample}: ${netSample}")

        $script:LineCounter = 1
        $compSample = Add-PspktColor -Text '001:005 (Networking:TCP/IPv4 -)' -Layer Component
        $dlSample  = Add-PspktColor -Text '7c-1e-52-97-b1-46 > a4-3f-68-1e-d9-68, type IPv4, len 60' -Layer DataLink
        $netSample = Add-PspktColor -Text '10.0.0.2.52341 > 10.0.0.1.443' -Layer Network
        $trSample  = Add-PspktColor -Text 'TCP [.S], seq 9999, ack 1235, win 65535, len 0' -Layer Transport
        [Console]::WriteLine("    ${compSample}: ${dlSample}: ${netSample}: ${trSample}")

        Write-Host ('  ' + ('-' * 98))
    }

    Write-Host ''

    # Restore previous state.
    $script:ColorScheme = $prevScheme
    $script:LineCounter = $prevCounter
    if ($null -ne $prevScheme) {
        $script:AnsiReset = "$($script:ESC)[$($prevScheme.Reset)m"
        $script:AnsiCache = @{}
        Sync-PspktFormatterColors
    }
}

<#
.SYNOPSIS
Saves a color profile hashtable to a .psd1 file in the ColorProfiles directory.

.DESCRIPTION
Persists a profile hashtable (from New-PspktParserColorProfile) as a named .psd1 file.
Use Set-PspktParserColorProfile to make it the active default.

.PARAMETER Name
The name for the profile (becomes the filename without extension).

.PARAMETER Profile
The color profile hashtable to save.

.PARAMETER Force
Overwrite an existing profile with the same name.
#>
function Save-PspktParserColorProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Name,

        [Parameter(Mandatory = $true, Position = 1)]
        [hashtable]
        $Profile,

        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    $destPath = Join-Path $script:ProfilesDir "$Name.psd1"
    if ((Test-Path $destPath) -and -not $Force) {
        throw "Profile '$Name' already exists. Use -Force to overwrite."
    }

    # Validate required keys.
    $requiredLayers = @('Component', 'DataLink', 'Network', 'Transport', 'Application')
    foreach ($layer in $requiredLayers) {
        if (-not $Profile.ContainsKey($layer)) {
            throw "Profile is missing required layer: $layer"
        }
        if (-not $Profile[$layer].ContainsKey('Bright') -or -not $Profile[$layer].ContainsKey('Muted')) {
            throw "Layer '$layer' must have both 'Bright' and 'Muted' keys."
        }
    }

    # Build the .psd1 content.
    $lines = [System.Collections.ArrayList]::new()
    $null = $lines.Add('@{')
    $null = $lines.Add("    # Color profile: $Name")
    $null = $lines.Add('')

    foreach ($layer in $requiredLayers) {
        $null = $lines.Add("    $layer = @{")
        $null = $lines.Add("        Bright = '$($Profile[$layer]['Bright'])'")
        $null = $lines.Add("        Muted  = '$($Profile[$layer]['Muted'])'")
        $null = $lines.Add('    }')
        $null = $lines.Add('')
    }

    $resetVal = '0'
    if ($Profile.ContainsKey('Reset')) { $resetVal = $Profile['Reset'] }
    $null = $lines.Add("    # Reset sequence (appended at end of each line).")
    $null = $lines.Add("    Reset = '$resetVal'")
    $null = $lines.Add('}')

    Set-Content -Path $destPath -Value ($lines -join "`n") -Encoding UTF8
    Write-Host "Color profile '$Name' saved to: $destPath" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# Legacy wrappers (backward-compatible)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
Loads or reloads the color scheme from a .psd1 file (legacy wrapper).
#>
function Import-PspktColorScheme {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Path
    )

    if ([string]::IsNullOrEmpty($Path)) {
        Import-PspktParserColorProfile
    } else {
        Import-PspktParserColorProfile -Path $Path
    }
}

<#
.SYNOPSIS
Gets the current color scheme. Loads from disk if not yet loaded.
#>
function Get-PspktColorScheme {
    [CmdletBinding()]
    param()

    if ($null -eq $script:ColorScheme) {
        Import-PspktParserColorProfile
        # Initialize cached reset sequence.
        $script:AnsiReset = "$($script:ESC)[$($script:ColorScheme.Reset)m"
        $script:AnsiCache = @{}
    }
    return $script:ColorScheme
}

<#
.SYNOPSIS
Sets individual color values in the active color scheme (in memory only).

.PARAMETER Layer
Layer name: DataLink, Network, Transport, or Application.

.PARAMETER Bright
ANSI SGR parameters for bright (even) lines.

.PARAMETER Muted
ANSI SGR parameters for muted (odd) lines.
#>
function Set-PspktColor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Component', 'DataLink', 'Network', 'Transport', 'Application', 'Drop')]
        [string]
        $Layer,

        [Parameter(Mandatory = $false)]
        [string]
        $Bright,

        [Parameter(Mandatory = $false)]
        [string]
        $Muted
    )

    $scheme = Get-PspktColorScheme
    if ($PSBoundParameters.ContainsKey('Bright')) {
        $scheme[$Layer]['Bright'] = $Bright
    }
    if ($PSBoundParameters.ContainsKey('Muted')) {
        $scheme[$Layer]['Muted'] = $Muted
    }
}

# --------------------------------------------------------------------------
# Line Counter & Color Helpers
# --------------------------------------------------------------------------

<#
.SYNOPSIS
Resets the line counter used for alternating colors.
#>
function Reset-PspktLineCounter {
    param()
    $script:LineCounter = 0
}

<#
.SYNOPSIS
Wraps a string segment in ANSI color for the given layer and current line parity.
#>
function Add-PspktColor {
    param(
        [string] $Text,
        [string] $Layer
    )

    return [PacketFormatter]::Colorize($Text, $Layer, $script:LineCounter)
}

<#
.SYNOPSIS
Advances the line counter (call once per packet output).
#>
function Step-PspktLineCounter {
    param()
    $script:LineCounter++
}

<#
.SYNOPSIS
Sets the detail level for real-time packet output.
#>
function Set-PspktDetailLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(-1, 2)]
        [int]
        $Level
    )
    $script:DetailLevel = $Level
    [PacketLineFormatter]::SetOptions($script:ShowTimestamp, $Level)
}

<#
.SYNOPSIS
Gets the current detail level for real-time packet output.
#>
function Get-PspktDetailLevel {
    [CmdletBinding()]
    param()
    return $script:DetailLevel
}

<#
.SYNOPSIS
Enables or disables blank-line spacing between packets in detailed mode.
#>
function Set-PspktDetailSpacing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]
        $Enabled
    )
    $script:DetailSpacing = $Enabled
}

<#
.SYNOPSIS
Gets whether blank-line spacing between packets is enabled.
#>
function Get-PspktDetailSpacing {
    [CmdletBinding()]
    param()
    return $script:DetailSpacing
}

<#
.SYNOPSIS
Enables or disables timestamp display on packet output.
#>
function Set-PspktShowTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]
        $Enabled
    )
    $script:ShowTimestamp = $Enabled
    [PacketLineFormatter]::SetOptions($Enabled, $script:DetailLevel)
}

<#
.SYNOPSIS
Gets whether timestamp display is enabled.
#>
function Get-PspktShowTimestamp {
    [CmdletBinding()]
    param()
    return $script:ShowTimestamp
}

# --------------------------------------------------------------------------
# Packet Formatting
# --------------------------------------------------------------------------

<#
.SYNOPSIS
Formats the network and transport layer segments of a parsed packet.

.DESCRIPTION
Determines the protocol and produces the colored Network + Transport string.
For ICMP echo: [src] > [dst]: ICMP echo request|reply, id X, seq Y, length Z
For TCP/UDP:   [src].[srcPort] > [dst].[dstPort]: TCP|UDP, len: N
#>
function Format-NetworkSegment {
    param(
        $ParsedPacket,
        [byte[]] $RawPacketData
    )

    $ipData = $ParsedPacket.IPv4Data
    $protoData = $ParsedPacket.ProtocolData
    $link = $ParsedPacket.LinkLayerData
    $lc = $script:LineCounter

    # --- IPv6 handling (no IPv4Data but EtherType 0x86DD) ---
    if ($null -eq $ipData -and $null -ne $link -and $link.EtherType -eq 0x86DD -and $null -ne $RawPacketData) {
        $ipv6Offset = 14
        if ($ParsedPacket.LinkKind -eq 2) {
            $ipv6Offset = $link.PayloadOffset
        }
        $src = $null
        $dst = $null
        if (-not [PacketFormatter]::ParseIPv6Addresses($RawPacketData, $ipv6Offset, [ref]$src, [ref]$dst)) {
            return $null
        }

        $nextHeader = $RawPacketData[$ipv6Offset + 6]

        if ($nextHeader -eq 58) {
            # ICMPv6 — check NDP and echo.
            if (Test-NdpPacket -RawPacketData $RawPacketData -IPv6Offset $ipv6Offset) {
                $ndpStr = Format-NdpSegment -RawPacketData $RawPacketData -IPv6Offset $ipv6Offset
                return [PacketFormatter]::FormatNetworkOnly("$src > $dst`: $ndpStr", $lc)
            }
            if ($RawPacketData.Count -ge ($ipv6Offset + 41)) {
                $icmpv6Type = [int]$RawPacketData[$ipv6Offset + 40]
                if ($icmpv6Type -eq 128 -or $icmpv6Type -eq 129) {
                    $dir = if ($icmpv6Type -eq 128) { 'request' } else { 'reply' }
                    return [PacketFormatter]::FormatNetworkOnly("$src > $dst`: ICMPv6 echo $dir", $lc)
                }
                return [PacketFormatter]::FormatNetworkOnly("$src > $dst`: ICMPv6 type $icmpv6Type", $lc)
            }
        } elseif ($nextHeader -eq 6 -or $nextHeader -eq 17) {
            # TCP/UDP over IPv6.
            $transOff = $ipv6Offset + 40
            if ($RawPacketData.Count -ge ($transOff + 4)) {
                $sp = [PacketParseHelper]::ReadUInt16BE($RawPacketData, $transOff)
                $dp = [PacketParseHelper]::ReadUInt16BE($RawPacketData, $transOff + 2)
                $protoName = if ($nextHeader -eq 6) { 'TCP' } else { 'UDP' }
                return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $protoName, 3, $lc)
            }
        }

        return [PacketFormatter]::FormatNetworkOnly("$src > $dst", $lc)
    }

    if ($null -eq $ipData) {
        return $null
    }

    $src = $ipData.SourceAddress
    $dst = $ipData.DestinationAddress

    # Dispatch by ProtoKind (int): 0=None, 1=ICMP, 2=TCP, 3=UDP, 4=Other
    $pk = $ParsedPacket.ProtoKind

    # ICMP echo - special format, all colored as Network.
    if ($pk -eq 1) {
        if (Test-ICMPEcho -ProtocolData $protoData) {
            $icmpStr = Format-ICMPEcho -ProtocolData $protoData
            return [PacketFormatter]::FormatNetworkOnly("$src > $dst`: $icmpStr", $lc)
        }
        # Non-echo ICMP - show type/code.
        return [PacketFormatter]::FormatNetworkOnly("$src > $dst`: ICMP type $([int]$protoData.Type) code $([int]$protoData.Code)", $lc)
    }

    # TCP
    if ($pk -eq 2) {
        $sp = $protoData.SourcePort
        $dp = $protoData.DestinationPort

        # SMB2 - application layer (port 445).
        if (Test-Smb2Packet -ProtocolData $protoData) {
            $smb2Str = Format-Smb2Segment -ProtocolData $protoData
            return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $smb2Str, 4, $lc)
        }

        # HTTP - application layer.
        if (Test-HttpPacket -ProtocolData $protoData) {
            $httpStr = Format-HttpSegment -ProtocolData $protoData
            return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $httpStr, 4, $lc)
        }

        # TLS/HTTPS - application layer.
        if (Test-TlsPacket -ProtocolData $protoData) {
            $tlsStr = Format-TlsSegment -ProtocolData $protoData
            return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $tlsStr, 4, $lc)
        }

        $transStr = Format-TcpSegment -ProtocolData $protoData
        return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $transStr, 3, $lc)
    }

    # UDP
    if ($pk -eq 3) {
        $sp = $protoData.SourcePort
        $dp = $protoData.DestinationPort

        # DNS / mDNS - application layer.
        if (Test-DnsPacket -ProtocolData $protoData) {
            $dnsStr = Format-DnsSegment -ProtocolData $protoData
            return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $dnsStr, 4, $lc)
        }

        # DHCP / DHCPv6 - application layer.
        if (Test-DhcpPacket -ProtocolData $protoData) {
            if (Test-Dhcpv6Packet -ProtocolData $protoData) {
                $dhcpStr = Format-Dhcpv6Segment -ProtocolData $protoData
            } else {
                $dhcpStr = Format-DhcpSegment -ProtocolData $protoData
            }
            return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, $dhcpStr, 4, $lc)
        }

        $segLen = 0
        if ($null -ne $protoData.Data) { $segLen = $protoData.Data.Count }
        return [PacketFormatter]::FormatTransportLine($src, $sp, $dst, $dp, "UDP, len $segLen", 3, $lc)
    }

    # Fallback: just show addresses and protocol name.
    $protoName = $ipData.Protocol.ToString()
    return [PacketFormatter]::FormatNetworkOnly("$src > $dst`: $protoName", $lc)
}

<#
.SYNOPSIS
Registers a component ID-to-name mapping for packet output.

.DESCRIPTION
Populates the internal lookup table used by Format-PacketLine to display component names.
Call this with the output of Get-PspktComponent before starting a capture.

.PARAMETER Components
An array of pspktComponent objects (or any object with Id and Name properties).
#>
function Register-PspktComponentMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Components
    )

    $script:ComponentMap = @{}
    $script:ComponentMisses = @{}
    [PacketFormatter]::ClearComponentCache()
    [PacketLineFormatter]::ClearComponents()
    foreach ($comp in $Components) {
        if ($null -ne $comp.Id) {
            $script:ComponentMap[[int]$comp.Id] = @{
                Name     = $comp.Name
                ParentId = [int]$comp.ParentId
                Group    = $comp.Group
            }
            [PacketLineFormatter]::RegisterComponent([int]$comp.Id, $comp.Name, [int]$comp.ParentId, $comp.Group)
            # Also map by SecondaryId if it differs from Id.
            if ($null -ne $comp.SecondaryId -and [int]$comp.SecondaryId -ne [int]$comp.Id) {
                if (-not $script:ComponentMap.ContainsKey([int]$comp.SecondaryId)) {
                    $script:ComponentMap[[int]$comp.SecondaryId] = @{
                        Name     = $comp.Name
                        ParentId = [int]$comp.ParentId
                        Group    = $comp.Group
                    }
                    [PacketLineFormatter]::RegisterComponent([int]$comp.SecondaryId, $comp.Name, [int]$comp.ParentId, $comp.Group)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Clears the component ID-to-name mapping.
#>
function Clear-PspktComponentMap {
    [CmdletBinding()]
    param()
    $script:ComponentMap = @{}
    [PacketLineFormatter]::ClearComponents()
}

<#
.SYNOPSIS
Formats the component prefix for a packet line.
#>
function Format-ComponentPrefix {
    param(
        $Packet
    )

    $compId = 0
    $edgeId = 0
    if ($null -ne $Packet.PktmonMetaData) {
        $compId = [int]$Packet.PktmonMetaData.ComponentId
        $edgeId = [int]$Packet.PktmonMetaData.EdgeId
    }

    $compName = ''
    $parentId = 0

    if ($script:ComponentMap.ContainsKey($compId)) {
        $entry = $script:ComponentMap[$compId]
        $compName = $entry.Name
        $parentId = $entry.ParentId
    } elseif ($compId -ne 0 -and -not $script:ComponentMisses.ContainsKey($compId) -and -not $script:ComponentRefreshLocked) {
        # Component not in map — refresh from pktmonapi and pktmon.exe.
        # Locked during active capture to prevent stalling the consumer thread.
        try {
            $components = Get-PspktComponent
            Register-PspktComponentMap -Components $components
        } catch {
            # Silently ignore — map stays as-is.
        }
        # If still not found, try raw pktmon JSON which may have sub-components by SecondaryId.
        if (-not $script:ComponentMap.ContainsKey($compId)) {
            try {
                $rawJson = pktmon comp list --json 2>$null | ConvertFrom-Json
                foreach ($grp in $rawJson) {
                    foreach ($comp in $grp.Components) {
                        $cid = [int]$comp.Id
                        if (-not $script:ComponentMap.ContainsKey($cid)) {
                            $script:ComponentMap[$cid] = @{
                                Name     = $comp.Name
                                ParentId = 0
                                Group    = $grp.Group
                            }
                        }
                        if ($null -ne $comp.SecondaryId) {
                            $sid = [int]$comp.SecondaryId
                            if (-not $script:ComponentMap.ContainsKey($sid)) {
                                $script:ComponentMap[$sid] = @{
                                    Name     = $comp.Name
                                    ParentId = 0
                                    Group    = $grp.Group
                                }
                            }
                        }
                    }
                }
            } catch {
                # Silently ignore.
            }
        }
        if ($script:ComponentMap.ContainsKey($compId)) {
            $entry = $script:ComponentMap[$compId]
            $compName = $entry.Name
            $parentId = $entry.ParentId
        } else {
            $script:ComponentMisses[$compId] = $true
        }
    }

    # Use C# formatter for cached, fast prefix generation.
    return [PacketFormatter]::FormatComponentPrefix($parentId, $compId, $compName, $script:LineCounter, $edgeId)
}

<#
.SYNOPSIS
Formats the drop message text for a dropped packet.

.PARAMETER Packet
A PacketData object with PktmonMetaData containing drop info.
#>
function Format-DropLine {
    param(
        $Packet
    )

    $meta = $Packet.PktmonMetaData
    $reasonStr = $meta.DropReason.ToString() -replace '^PktMonDrop_', ''
    $reasonHex = '0x{0:X8}' -f [uint32][int]$meta.DropReason
    $locInt = [int]$meta.DropLocation
    $locationStr = $meta.DropLocation.ToString() -replace '^PMLOC_', ''
    if ($locationStr -eq $locInt.ToString()) {
        $locationStr = "Location_$locInt"
    }
    $locationHex = '0x{0:X8}' -f [uint32]$locInt

    # Try to parse IP src/dst from raw packet data.
    $addrInfo = ''
    $raw = $Packet.RawPacketData
    if ($null -ne $raw -and $raw.Count -ge 20) {
        $version = ($raw[0] -shr 4) -band 0xF
        if ($version -eq 4 -and $raw.Count -ge 20) {
            $ihl = ($raw[0] -band 0xF) * 4
            $srcIp = "$($raw[12]).$($raw[13]).$($raw[14]).$($raw[15])"
            $dstIp = "$($raw[16]).$($raw[17]).$($raw[18]).$($raw[19])"
            $proto = [int]$raw[9]
            $srcPort = 0
            $dstPort = 0
            if (($proto -eq 6 -or $proto -eq 17) -and $raw.Count -ge ($ihl + 4)) {
                $srcPort = [PacketParseHelper]::ReadUInt16BE($raw, $ihl)
                $dstPort = [PacketParseHelper]::ReadUInt16BE($raw, $ihl + 2)
            }
            if ($srcPort -gt 0) {
                $addrInfo = " IPv4 src: ${srcIp}.${srcPort}, dst: ${dstIp}.${dstPort}"
            } else {
                $addrInfo = " IPv4 src: ${srcIp}, dst: ${dstIp}"
            }
        } elseif ($version -eq 6 -and $raw.Count -ge 40) {
            $srcParts = for ($i = 8; $i -lt 24; $i += 2) {
                '{0:x4}' -f [PacketParseHelper]::ReadUInt16BE($raw, $i)
            }
            $dstParts = for ($i = 24; $i -lt 40; $i += 2) {
                '{0:x4}' -f [PacketParseHelper]::ReadUInt16BE($raw, $i)
            }
            $srcIp6 = ($srcParts -join ':') -replace '(:0000)+:', '::'
            $dstIp6 = ($dstParts -join ':') -replace '(:0000)+:', '::'
            $nextHdr = [int]$raw[6]
            $srcPort = 0
            $dstPort = 0
            if (($nextHdr -eq 6 -or $nextHdr -eq 17) -and $raw.Count -ge 44) {
                $srcPort = [PacketParseHelper]::ReadUInt16BE($raw, 40)
                $dstPort = [PacketParseHelper]::ReadUInt16BE($raw, 42)
            }
            if ($srcPort -gt 0) {
                $addrInfo = " IPv6 src: ${srcIp6}.${srcPort}, dst: ${dstIp6}.${dstPort}"
            } else {
                $addrInfo = " IPv6 src: ${srcIp6}, dst: ${dstIp6}"
            }
        }
    }

    return "DROP - Reason: $reasonStr ($reasonHex); Location: $locationStr ($locationHex);$addrInfo"
}

<#
.SYNOPSIS
Formats a packet timestamp using 24-hour time with high precision.
#>
function Format-PspktTimestamp {
    param(
        $Packet
    )

    if (-not $script:ShowTimestamp) { return '' }

    $fileTime = $Packet.StreamTimestamp
    if ($null -eq $fileTime -or $fileTime -le 0) { return '' }

    $dt = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
    # 24-hour format: yyyy-MM-dd HH:mm:ss.fffffff
    return "$($dt.ToString('yyyy-MM-dd HH:mm:ss.fffffff')) "
}

<#
.SYNOPSIS
Formats a packet in Minimal mode: condensed single-line output.
Format: DL: Net.Trans: src.port > dst.port: [app/protocol details]
#>
function Format-MinimalLine {
    param(
        $Packet
    )

    $parsed = $Packet.ParsedPacket
    if ($null -eq $parsed) { return $null }

    $link = $parsed.LinkLayerData
    $ipData = $parsed.IPv4Data
    $protoData = $parsed.ProtocolData

    # Data Link protocol name.
    $dlName = ''
    if ($null -ne $link) {
        if ($parsed.LinkKind -eq 1) { $dlName = 'Eth' }
        elseif ($parsed.LinkKind -eq 2) { $dlName = '802.11' }
        else { $dlName = 'L2' }
    }

    # Network + Transport protocol names. No application layer in Minimal mode.
    $netProto = ''
    $transProto = ''
    $src = ''
    $dst = ''
    $srcPort = ''
    $dstPort = ''
    $appStr = ''

    if ($null -ne $ipData) {
        $netProto = 'IPv4'
        $src = $ipData.SourceAddress
        $dst = $ipData.DestinationAddress

        if ($null -ne $protoData) {
            if ($parsed.ProtoKind -eq 2) {
                $transProto = 'TCP'
                $srcPort = ".$($protoData.SourcePort)"
                $dstPort = ".$($protoData.DestinationPort)"
            } elseif ($parsed.ProtoKind -eq 3) {
                $transProto = 'UDP'
                $srcPort = ".$($protoData.SourcePort)"
                $dstPort = ".$($protoData.DestinationPort)"
            } elseif ($parsed.ProtoKind -eq 1) {
                $transProto = 'ICMP'
                if ($protoData.Type -eq 8 -or $protoData.Type -eq 0) {
                    $dir = if ($protoData.Type -eq 8) { 'req' } else { 'rpl' }
                    $icmpId = [PacketParseHelper]::ReadUInt16BE($protoData.UnparsedHeaders, 0)
                    $icmpSeq = [PacketParseHelper]::ReadUInt16BE($protoData.UnparsedHeaders, 2)
                    $appStr = "$dir id=$icmpId seq=$icmpSeq"
                } else {
                    $appStr = "t$([int]$protoData.Type)/c$([int]$protoData.Code)"
                }
            }
        }
    } elseif ($null -ne $link -and $link.EtherType -eq 0x86DD) {
        $netProto = 'IPv6'
        $raw = $Packet.RawPacketData
        $ipv6Offset = if ($parsed.LinkKind -eq 2) { $link.PayloadOffset } else { 14 }
        if ($raw.Count -ge ($ipv6Offset + 40)) {
            $srcBytes = $raw[($ipv6Offset + 8)..($ipv6Offset + 23)]
            $src = ([System.Net.IPAddress]::new($srcBytes)).ToString()
            $dstBytes = $raw[($ipv6Offset + 24)..($ipv6Offset + 39)]
            $dst = ([System.Net.IPAddress]::new($dstBytes)).ToString()
            $nextHeader = $raw[$ipv6Offset + 6]
            if ($nextHeader -eq 58) {
                $transProto = 'ICMPv6'
                if ($raw.Count -ge ($ipv6Offset + 41)) {
                    $icmpv6Type = [int]$raw[$ipv6Offset + 40]
                    if ($icmpv6Type -eq 128 -or $icmpv6Type -eq 129) {
                        $dir = if ($icmpv6Type -eq 128) { 'req' } else { 'rpl' }
                        $appStr = $dir
                    } else {
                        $appStr = "t$icmpv6Type"
                    }
                }
            } elseif ($nextHeader -eq 6) {
                $transProto = 'TCP'
                $tcpOff = $ipv6Offset + 40
                if ($raw.Count -ge ($tcpOff + 4)) {
                    $srcPort = ".$([PacketParseHelper]::ReadUInt16BE($raw, $tcpOff))"
                    $dstPort = ".$([PacketParseHelper]::ReadUInt16BE($raw, $tcpOff + 2))"
                }
            } elseif ($nextHeader -eq 17) {
                $transProto = 'UDP'
                $udpOff = $ipv6Offset + 40
                if ($raw.Count -ge ($udpOff + 4)) {
                    $srcPort = ".$([PacketParseHelper]::ReadUInt16BE($raw, $udpOff))"
                    $dstPort = ".$([PacketParseHelper]::ReadUInt16BE($raw, $udpOff + 2))"
                }
            }
        }
    }

    # Build output via single C# call for all coloring.
    return [PacketFormatter]::FormatMinimalColors($dlName, $netProto, $transProto, $src, $srcPort, $dst, $dstPort, $appStr, $script:LineCounter)
}

<#
.SYNOPSIS
Formats a complete packet into a single colored line for real-time display.

.PARAMETER Packet
A PacketData object from ReadPacketsFromBuffer().
#>
function Format-PacketLine {
    param(
        $Packet
    )

    $parsed = $Packet.ParsedPacket
    $meta = $Packet.PktmonMetaData

    # --- Fast path: Default (level 0) and Minimal (level -1) modes via C# ---
    if ($script:DetailLevel -le 0) {
        $script:LineCounter++

        # Extract fields for C# formatter
        $compId = 0; $edgeId = 0; $dropReason = 0; $dropLocation = 0
        if ($null -ne $meta) {
            $compId = [int]$meta.ComponentId
            $edgeId = [int]$meta.EdgeId
            $dropReason = [int]$meta.DropReason
            $dropLocation = [int]$meta.DropLocation
        }

        # Component refresh for unknown IDs (rare path)
        if ($compId -ne 0 -and -not [PacketLineFormatter]::HasComponent($compId) -and
            -not [PacketLineFormatter]::IsComponentMiss($compId) -and
            -not $script:ComponentRefreshLocked) {
            try {
                $components = Get-PspktComponent
                Register-PspktComponentMap -Components $components
            } catch { }
            if (-not [PacketLineFormatter]::HasComponent($compId)) {
                try {
                    $rawJson = pktmon comp list --json 2>$null | ConvertFrom-Json
                    foreach ($grp in $rawJson) {
                        foreach ($comp in $grp.Components) {
                            $cid = [int]$comp.Id
                            if (-not [PacketLineFormatter]::HasComponent($cid)) {
                                [PacketLineFormatter]::RegisterComponent($cid, $comp.Name, 0, $grp.Group)
                                $script:ComponentMap[$cid] = @{ Name = $comp.Name; ParentId = 0; Group = $grp.Group }
                            }
                            if ($null -ne $comp.SecondaryId) {
                                $sid = [int]$comp.SecondaryId
                                if (-not [PacketLineFormatter]::HasComponent($sid)) {
                                    [PacketLineFormatter]::RegisterComponent($sid, $comp.Name, 0, $grp.Group)
                                    $script:ComponentMap[$sid] = @{ Name = $comp.Name; ParentId = 0; Group = $grp.Group }
                                }
                            }
                        }
                    }
                } catch { }
                if (-not [PacketLineFormatter]::HasComponent($compId)) {
                    [PacketLineFormatter]::MarkComponentMiss($compId)
                }
            }
        }

        # Extract link layer info
        $linkKind = 0; $srcMac = $null; $dstMac = $null; $etherType = 0
        if ($null -ne $parsed) {
            $linkKind = $parsed.LinkKind
            $link = $parsed.LinkLayerData
            if ($null -ne $link) {
                $etherType = [int]$link.EtherType
                if ($linkKind -eq 1) {
                    if ($link.SourceMacAddress) { $srcMac = ($link.SourceMacAddress -replace ':', '-').ToLower() }
                    if ($link.DestinationMacAddress) { $dstMac = ($link.DestinationMacAddress -replace ':', '-').ToLower() }
                }
            }
        }

        # Extract network/transport info
        $protoKind = 0; $srcAddr = $null; $dstAddr = $null
        $srcPort = 0; $dstPort = 0
        $tcpFlags = [byte]0; $tcpSeq = [uint32]0; $tcpAck = [uint32]0; $tcpWin = [uint16]0
        $dataLen = 0
        $icmpType = 0; $icmpCode = 0; $icmpId = 0; $icmpSeq = 0
        [byte[]]$udpData = $null

        if ($null -ne $parsed) {
            $protoKind = $parsed.ProtoKind
            $ipData = $parsed.IPv4Data
            if ($null -ne $ipData) {
                $srcAddr = $ipData.SourceAddress
                $dstAddr = $ipData.DestinationAddress
            }
            $protoData = $parsed.ProtocolData
            if ($null -ne $protoData) {
                if ($protoKind -eq 2) {
                    # TCP
                    $srcPort = [int]$protoData.SourcePort
                    $dstPort = [int]$protoData.DestinationPort
                    $tcpFlags = [byte]$protoData.Flags
                    $tcpSeq = [uint32]$protoData.SequenceNumber
                    $tcpAck = [uint32]$protoData.AcknowledgementNumber
                    $tcpWin = [uint16]$protoData.Window
                    if ($null -ne $protoData.Data) {
                        $dataLen = $protoData.Data.Count
                        $udpData = $protoData.Data  # reuse for HTTP/TLS detection
                    }
                } elseif ($protoKind -eq 3) {
                    # UDP
                    $srcPort = [int]$protoData.SourcePort
                    $dstPort = [int]$protoData.DestinationPort
                    if ($null -ne $protoData.Data) {
                        $dataLen = $protoData.Data.Count
                        $udpData = $protoData.Data
                    }
                } elseif ($protoKind -eq 1) {
                    # ICMP
                    $icmpType = [int]$protoData.Type
                    $icmpCode = [int]$protoData.Code
                    if ($null -ne $protoData.Data) { $dataLen = $protoData.Data.Count }
                    if ($null -ne $protoData.UnparsedHeaders -and $protoData.UnparsedHeaders.Count -ge 4) {
                        $icmpId = [int][PacketParseHelper]::ReadUInt16BE($protoData.UnparsedHeaders, 0)
                        $icmpSeq = [int][PacketParseHelper]::ReadUInt16BE($protoData.UnparsedHeaders, 2)
                    }
                }
            }
        }

        $rawLen = 0
        if ($null -ne $Packet.RawPacketData) { $rawLen = $Packet.RawPacketData.Count }

        if ($script:DetailLevel -eq -1) {
            return [PacketLineFormatter]::FormatMinimalLine(
                $script:LineCounter,
                $Packet.StreamTimestamp,
                $compId, $edgeId,
                $dropReason, $dropLocation,
                $linkKind, $etherType, $rawLen,
                $protoKind, $srcAddr, $dstAddr,
                $srcPort, $dstPort,
                $tcpFlags, $tcpSeq, $tcpAck, $tcpWin,
                $dataLen,
                $icmpType, $icmpCode, $icmpId, $icmpSeq,
                $udpData,
                $Packet.RawPacketData)
        }

        return [PacketLineFormatter]::FormatDefaultLine(
            $script:LineCounter,
            $Packet.StreamTimestamp,
            $compId, $edgeId,
            $dropReason, $dropLocation,
            $linkKind, $srcMac, $dstMac, $etherType, $rawLen,
            $protoKind, $srcAddr, $dstAddr,
            $srcPort, $dstPort,
            $tcpFlags, $tcpSeq, $tcpAck, $tcpWin,
            $dataLen,
            $icmpType, $icmpCode, $icmpId, $icmpSeq,
            $udpData,
            $Packet.RawPacketData)
    }

    # --- Slow path: Detailed mode (level >= 1) — keep existing PS logic ---

    # Inline timestamp logic for performance.
    $ts = ''
    if ($script:ShowTimestamp) {
        $fileTime = $Packet.StreamTimestamp
        if ($null -ne $fileTime -and $fileTime -gt 0) {
            $dt = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
            $ts = "$($dt.ToString('yyyy-MM-dd HH:mm:ss.fffffff')) "
        } else {
            if ($null -ne $parsed -and $null -ne $parsed.TimeStamp -and $parsed.TimeStamp -ne [DateTime]::MinValue) {
                $ts = "$($parsed.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss.fffffff')) "
            }
        }
    }

    # Check for dropped packet first.
    if ($null -ne $meta -and
        $meta.DropReason -ne [PKTMON_DROP_REASON]::PktMonDrop_Unknown) {
        $script:LineCounter++
        $compPrefix = Format-ComponentPrefix -Packet $Packet
        $dropLine = Format-DropLine -Packet $Packet
        $coloredDrop = Add-PspktColor -Text $dropLine -Layer Drop
        return "${ts}${compPrefix}: $coloredDrop"
    }

    if ($null -eq $parsed) {
        $script:LineCounter++
        return $null
    }

    $script:LineCounter++
    $rawLen = $Packet.RawPacketData.Count

    # --- Component prefix ---
    $compPrefix = "${ts}$(Format-ComponentPrefix -Packet $Packet)"

    # --- ARP ---
    if (Test-ArpPacket -ParsedPacket $parsed) {
        $dlSegment = Format-DataLinkSegment -ParsedPacket $parsed -RawLength $rawLen
        $arpStr = Format-ArpSegment -RawPacketData $Packet.RawPacketData -ParsedPacket $parsed
        $coloredDL = ''
        if ($dlSegment) {
            $coloredDL = Add-PspktColor -Text $dlSegment -Layer DataLink
        }
        $coloredArp = Add-PspktColor -Text $arpStr -Layer Network
        if ($coloredDL) {
            return "${compPrefix}: $coloredDL`: $coloredArp"
        }
        return "${compPrefix}: $coloredArp"
    }

    # --- Data Link segment ---
    $dlSegment = Format-DataLinkSegment -ParsedPacket $parsed -RawLength $rawLen
    $coloredDL = ''
    if ($dlSegment) {
        $coloredDL = Add-PspktColor -Text $dlSegment -Layer DataLink
    }

    # --- Detailed output (level >= 1): line 1 = Component + DataLink only ---
    if ($coloredDL) {
        $line = "${compPrefix}: $coloredDL"
    } else {
        $line = "${compPrefix}:"
    }

    $detailLines = [System.Collections.Generic.List[string]]::new(4)

    # Network detail line
    if ($null -ne $parsed.IPv4Data) {
        $ipDetail = Format-IPv4Detailed -IPv4Data $parsed.IPv4Data
        if ($null -ne $ipDetail) {
            $coloredIndent = $script:ColoredIndent1
            $coloredText = Add-PspktColor -Text $ipDetail -Layer Network
            $null = $detailLines.Add("${coloredIndent}${coloredText}")
        }
    } elseif ($null -ne $parsed.LinkLayerData -and $parsed.LinkLayerData.EtherType -eq 0x86DD) {
        $ipv6Offset = 14
        if ($parsed.LinkKind -eq 2) {
            $ipv6Offset = $parsed.LinkLayerData.PayloadOffset
        }
        $ipv6Detail = Format-IPv6Detailed -RawPacketData $Packet.RawPacketData -IPv6Offset $ipv6Offset
        if ($null -ne $ipv6Detail) {
            $coloredIndent = $script:ColoredIndent1
            $coloredText = Add-PspktColor -Text $ipv6Detail -Layer Network
            $null = $detailLines.Add("${coloredIndent}${coloredText}")
        }
        # ICMPv6 NDP / Echo
        if (Test-NdpPacket -RawPacketData $Packet.RawPacketData -IPv6Offset $ipv6Offset) {
            $ndpStr = Format-NdpSegment -RawPacketData $Packet.RawPacketData -IPv6Offset $ipv6Offset
            $coloredIndent = $script:ColoredIndent2
            $coloredText = Add-PspktColor -Text $ndpStr -Layer Network
            $null = $detailLines.Add("${coloredIndent}${coloredText}")
        } elseif ($rawLen -ge ($ipv6Offset + 41) -and $Packet.RawPacketData[$ipv6Offset + 6] -eq 58) {
            $icmpv6Type = [int]$Packet.RawPacketData[$ipv6Offset + 40]
            if ($icmpv6Type -eq 128 -or $icmpv6Type -eq 129) {
                $dir = if ($icmpv6Type -eq 128) { 'request' } else { 'reply' }
                $coloredIndent = $script:ColoredIndent2
                $coloredText = Add-PspktColor -Text "ICMPv6 echo $dir" -Layer Network
                $null = $detailLines.Add("${coloredIndent}${coloredText}")
            }
        }
    }

    # Transport detail line
    if ($parsed.ProtoKind -eq 2) {
        $tcpDetail = Format-TcpDetailed -ProtocolData $parsed.ProtocolData
        if ($null -ne $tcpDetail) {
            $coloredIndent = $script:ColoredIndent2
            $coloredText = Add-PspktColor -Text $tcpDetail -Layer Transport
            $null = $detailLines.Add("${coloredIndent}${coloredText}")
        }

        # SMB2 application detail
        if (Test-Smb2Packet -ProtocolData $parsed.ProtocolData) {
            $smb2Detail = Format-Smb2Detailed -ProtocolData $parsed.ProtocolData
            if ($null -ne $smb2Detail) {
                $coloredIndent = $script:ColoredIndent3
                $coloredText = Add-PspktColor -Text $smb2Detail -Layer Application
                $null = $detailLines.Add("${coloredIndent}${coloredText}")
            }
        # HTTP application detail
        } elseif (Test-HttpPacket -ProtocolData $parsed.ProtocolData) {
            $httpDetail = Format-HttpDetailed -ProtocolData $parsed.ProtocolData
            if ($null -ne $httpDetail) {
                $coloredIndent = $script:ColoredIndent3
                $coloredText = Add-PspktColor -Text $httpDetail -Layer Application
                $null = $detailLines.Add("${coloredIndent}${coloredText}")
            }
        } elseif (Test-TlsPacket -ProtocolData $parsed.ProtocolData) {
            $tlsDetail = Format-TlsDetailed -ProtocolData $parsed.ProtocolData
            if ($null -ne $tlsDetail) {
                $coloredIndent = $script:ColoredIndent3
                $coloredText = Add-PspktColor -Text $tlsDetail -Layer Application
                $null = $detailLines.Add("${coloredIndent}${coloredText}")
            }
        }
    } elseif ($parsed.ProtoKind -eq 3) {
        $segLen = 0
        if ($null -ne $parsed.ProtocolData.Data) { $segLen = $parsed.ProtocolData.Data.Count }
        $udpStr = "UDP - Src: $($parsed.ProtocolData.SourcePort), Dst: $($parsed.ProtocolData.DestinationPort); len: $segLen"
        $coloredIndent = $script:ColoredIndent2
        $coloredText = Add-PspktColor -Text $udpStr -Layer Transport
        $null = $detailLines.Add("${coloredIndent}${coloredText}")

        # DNS/mDNS application detail
        if (Test-DnsPacket -ProtocolData $parsed.ProtocolData) {
            $dnsDetail = Format-DnsDetailed -ProtocolData $parsed.ProtocolData
            if ($null -ne $dnsDetail) {
                $coloredIndent = $script:ColoredIndent3
                $coloredText = Add-PspktColor -Text $dnsDetail -Layer Application
                $null = $detailLines.Add("${coloredIndent}${coloredText}")
            }
        } elseif (Test-DhcpPacket -ProtocolData $parsed.ProtocolData) {
            if (Test-Dhcpv6Packet -ProtocolData $parsed.ProtocolData) {
                $dhcpDetail = Format-Dhcpv6Detailed -ProtocolData $parsed.ProtocolData
            } else {
                $dhcpDetail = Format-DhcpDetailed -ProtocolData $parsed.ProtocolData
            }
            if ($null -ne $dhcpDetail) {
                $coloredIndent = $script:ColoredIndent3
                $coloredText = Add-PspktColor -Text $dhcpDetail -Layer Application
                $null = $detailLines.Add("${coloredIndent}${coloredText}")
            }
        }
    } elseif ($parsed.ProtoKind -eq 1) {
        if (Test-ICMPEcho -ProtocolData $parsed.ProtocolData) {
            $icmpStr = Format-ICMPEcho -ProtocolData $parsed.ProtocolData
            $coloredIndent = $script:ColoredIndent2
            $coloredText = Add-PspktColor -Text $icmpStr -Layer Network
            $null = $detailLines.Add("${coloredIndent}${coloredText}")
        } else {
            $icmpStr = "ICMP type $([int]$parsed.ProtocolData.Type) code $([int]$parsed.ProtocolData.Code)"
            $coloredIndent = $script:ColoredIndent2
            $coloredText = Add-PspktColor -Text $icmpStr -Layer Network
            $null = $detailLines.Add("${coloredIndent}${coloredText}")
        }
    }

    if ($detailLines.Count -gt 0) {
        $line += "`n" + ($detailLines -join "`n")
    }

    if ($script:DetailSpacing) {
        $line += "`n"
    }

    return $line
}

<#
.SYNOPSIS
Returns a color-correlated header line for real-time capture output.
.DESCRIPTION
Outputs a tab-separated header with each column label colored using the Bright
variant of its corresponding layer color: Group:Component, Data Link, Network,
Transport, Application.
#>
function Get-PspktCaptureHeader {
    [CmdletBinding()]
    param()

    $scheme = Get-PspktColorScheme
    $reset = "$($script:ESC)[$($scheme.Reset)m"

    # The component prefix is fixed at 36 characters:
    # "227:235 (TCP/IPv4 - L2       )[ In]: " = 36 + ": " separator
    # Pad "Group:Component" to 38 chars (36 content + 2 for ": ") so "Data Link"
    # starts exactly where the data-link segment begins in packet output.
    $layers = @(
        @{ Label = 'Group:Component'; Layer = 'Component'; Width = 37 }
        @{ Label = 'Data Link';       Layer = 'DataLink';  Width = 16 }
        @{ Label = 'Network';         Layer = 'Network';   Width = 16 }
        @{ Label = 'Transport';       Layer = 'Transport'; Width = 16 }
        @{ Label = 'Application';     Layer = 'Application'; Width = 0 }
    )

    $parts = @()
    foreach ($item in $layers) {
        $layerScheme = $scheme[$item.Layer]
        $label = $item.Label
        if ($item.Width -gt 0 -and $label.Length -lt $item.Width) {
            $label = $label + (' ' * ($item.Width - $label.Length))
        }
        if ($null -ne $layerScheme) {
            $sgr = $layerScheme['Bright']
            $parts += "$($script:ESC)[$($sgr)m$label$reset"
        } else {
            $parts += $label
        }
    }

    return ($parts -join '')
}

Export-ModuleMember -Function Import-PspktColorScheme, Get-PspktColorScheme, Set-PspktColor,
    Reset-PspktLineCounter, Add-PspktColor, Step-PspktLineCounter,
    Set-PspktDetailLevel, Get-PspktDetailLevel,
    Set-PspktDetailSpacing, Get-PspktDetailSpacing,
    Set-PspktShowTimestamp, Get-PspktShowTimestamp, Format-PspktTimestamp,
    Format-NetworkSegment, Format-MinimalLine, Format-PacketLine, Format-ComponentPrefix, Format-DropLine,
    Register-PspktComponentMap, Clear-PspktComponentMap,
    Get-PspktProfilePath, Get-PspktParserColorProfile, Import-PspktParserColorProfile,
    Set-PspktParserColorProfile, New-PspktParserColorProfile, Test-PspktParserColorProfile,
    Save-PspktParserColorProfile, Get-PspktCaptureHeader
