# ipv6.psm1 - IPv6 network layer formatter.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Formats an IPv6 address.port string for TCP/UDP, or just the address for ICMPv6/other.

.PARAMETER SourceAddress
Source IPv6 address string.

.PARAMETER DestinationAddress
Destination IPv6 address string.

.PARAMETER IncludePorts
If true, appends .port to each address.

.PARAMETER SrcPort
Source port number.

.PARAMETER DstPort
Destination port number.
#>
function Format-IPv6Addresses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $SourceAddress,

        [Parameter(Mandatory = $true)]
        [string]
        $DestinationAddress,

        [Parameter(Mandatory = $false)]
        [switch]
        $IncludePorts,

        [Parameter(Mandatory = $false)]
        [int]
        $SrcPort = 0,

        [Parameter(Mandatory = $false)]
        [int]
        $DstPort = 0
    )

    if ($IncludePorts) {
        return "$SourceAddress.$SrcPort > $DestinationAddress.$DstPort"
    }

    return "$SourceAddress > $DestinationAddress"
}

<#
.SYNOPSIS
Formats a detailed IPv6 line for verbose output.

.DESCRIPTION
Returns a string with full IPv6 header details:
  IPv6 - Src: [addr], Dst: [addr]; TC: [DSCP]; FL: [hex]; len: [payload]; TTL: [hop limit]; Next: [proto]

.PARAMETER RawPacketData
The raw packet byte array.

.PARAMETER IPv6Offset
The byte offset where the IPv6 header begins (typically 14 for Ethernet).
#>
function Format-IPv6Detailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $RawPacketData,

        [Parameter(Mandatory = $false)]
        [int]
        $IPv6Offset = 14
    )

    if ($RawPacketData.Count -lt ($IPv6Offset + 40)) {
        return $null
    }

    $i = $IPv6Offset

    # Bytes 0-3: Version(4) | Traffic Class(8) | Flow Label(20)
    $vtcfl = [PacketParseHelper]::ReadUInt32BE($RawPacketData, $i)
    $trafficClass = ($vtcfl -shr 20) -band 0xFF
    $flowLabel = $vtcfl -band 0xFFFFF

    # DSCP from traffic class upper 6 bits
    $dscpVal = $trafficClass -shr 2
    if ([Enum]::IsDefined([DSCP], [int]$dscpVal)) {
        $tcStr = ([DSCP]$dscpVal).ToString()
    } else {
        $tcStr = "$dscpVal"
    }

    $flStr = '0x{0:x5}' -f $flowLabel

    # Payload length (bytes 4-5)
    $payloadLen = [PacketParseHelper]::ReadUInt16BE($RawPacketData, ($i + 4))

    # Next header (byte 6)
    $nextHeader = $RawPacketData[$i + 6]
    if ([Enum]::IsDefined([IPv4Protocol], [int]$nextHeader)) {
        $nextStr = ([IPv4Protocol]$nextHeader).ToString()
    } else {
        $nextStr = "$nextHeader"
    }

    # Hop limit (byte 7)
    $hopLimit = $RawPacketData[$i + 7]

    # Source address (bytes 8-23)
    $srcBytes = $RawPacketData[($i + 8)..($i + 23)]
    $srcAddr = ([System.Net.IPAddress]::new($srcBytes)).ToString()

    # Destination address (bytes 24-39)
    $dstBytes = $RawPacketData[($i + 24)..($i + 39)]
    $dstAddr = ([System.Net.IPAddress]::new($dstBytes)).ToString()

    return "IPv6 - Src: $srcAddr, Dst: $dstAddr; TC: $tcStr; FL: $flStr; len: $payloadLen; TTL: $hopLimit; Next: $nextStr"
}

Export-ModuleMember -Function Format-IPv6Addresses, Format-IPv6Detailed
