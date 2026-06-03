# ndp.psm1 - ICMPv6 Neighbor Discovery Protocol formatter.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NdpTypeNames = @{
    133 = 'Router Solicitation'
    134 = 'Router Advertisement'
    135 = 'Neighbor Solicitation'
    136 = 'Neighbor Advertisement'
    137 = 'Redirect'
}

<#
.SYNOPSIS
Tests whether raw packet bytes contain an ICMPv6 NDP message.

.PARAMETER RawPacketData
The full raw packet byte array (starting from link layer).

.PARAMETER IPv6Offset
Byte offset where the IPv6 header starts.
#>
function Test-NdpPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $RawPacketData,

        [Parameter(Mandatory = $false)]
        [int]
        $IPv6Offset = 14
    )

    # Need at least 40-byte IPv6 header + 4 bytes ICMPv6 header.
    if ($RawPacketData.Count -lt ($IPv6Offset + 44)) { return $false }

    # Next Header must be ICMPv6 (58).
    $nextHeader = $RawPacketData[$IPv6Offset + 6]
    if ($nextHeader -ne 58) { return $false }

    # ICMPv6 type must be 133-137 (NDP).
    $icmpv6Type = $RawPacketData[$IPv6Offset + 40]
    return ($icmpv6Type -ge 133 -and $icmpv6Type -le 137)
}

<#
.SYNOPSIS
Formats an ICMPv6 NDP message for display.

.DESCRIPTION
Returns a string describing the NDP message type and relevant target/address.

.PARAMETER RawPacketData
The full raw packet byte array.

.PARAMETER IPv6Offset
Byte offset where the IPv6 header starts.
#>
function Format-NdpSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $RawPacketData,

        [Parameter(Mandatory = $false)]
        [int]
        $IPv6Offset = 14
    )

    if ($RawPacketData.Count -lt ($IPv6Offset + 44)) { return $null }

    $icmpOffset = $IPv6Offset + 40
    $icmpv6Type = [int]$RawPacketData[$icmpOffset]
    $icmpv6Code = [int]$RawPacketData[$icmpOffset + 1]

    $typeName = "ICMPv6 type $icmpv6Type"
    if ($script:NdpTypeNames.ContainsKey($icmpv6Type)) {
        $typeName = $script:NdpTypeNames[$icmpv6Type]
    }

    # Neighbor Solicitation (135) and Neighbor Advertisement (136) have a target address
    # at offset +8 from ICMPv6 header (16 bytes).
    if (($icmpv6Type -eq 135 -or $icmpv6Type -eq 136) -and
        $RawPacketData.Count -ge ($icmpOffset + 24)) {
        $targetBytes = $RawPacketData[($icmpOffset + 8)..($icmpOffset + 23)]
        $targetAddr = ([System.Net.IPAddress]::new($targetBytes)).ToString()
        return "NDP $typeName, target $targetAddr"
    }

    return "NDP $typeName"
}

Export-ModuleMember -Function Test-NdpPacket, Format-NdpSegment
