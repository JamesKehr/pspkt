# icmp.psm1 - ICMP and ICMPv6 echo formatter.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Formats an ICMP or ICMPv6 echo request/reply line segment.

.DESCRIPTION
Returns a string in the format:
  ICMP echo [request|reply], id [id], seq [seq], length [dataLen]

.PARAMETER ProtocolData
An ICMPData object from the parsed packet.

.PARAMETER IsIPv6
If true, labels as ICMPv6 instead of ICMP.
#>
function Format-ICMPEcho {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData,

        [Parameter(Mandatory = $false)]
        [switch]
        $IsIPv6
    )

    $label = if ($IsIPv6) { 'ICMPv6' } else { 'ICMP' }

    # Determine request vs reply from ICMP type.
    # ICMP: type 8 = echo request, type 0 = echo reply
    # ICMPv6: type 128 = echo request, type 129 = echo reply
    $direction = 'request'
    $icmpType = [int]$ProtocolData.Type
    if ($IsIPv6) {
        if ($icmpType -eq 129) { $direction = 'reply' }
    } else {
        if ($icmpType -eq 0) { $direction = 'reply' }
    }

    # Id and Sequence are packed in UnparsedHeaders (4 bytes: 2 for Id, 2 for Seq).
    $id  = 0
    $seq = 0
    if ($null -ne $ProtocolData.UnparsedHeaders -and $ProtocolData.UnparsedHeaders.Count -ge 4) {
        $id  = [PacketParseHelper]::ReadUInt16BE($ProtocolData.UnparsedHeaders, 0)
        $seq = [PacketParseHelper]::ReadUInt16BE($ProtocolData.UnparsedHeaders, 2)
    }

    $len = 0
    if ($null -ne $ProtocolData.Data) {
        $len = $ProtocolData.Data.Count
    }

    return "$label echo $direction, id $id, seq $seq, len $len"
}

<#
.SYNOPSIS
Tests whether an ICMPData object represents an echo request or reply.

.PARAMETER ProtocolData
An ICMPData object.

.PARAMETER IsIPv6
If true, checks ICMPv6 echo types (128/129).
#>
function Test-ICMPEcho {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData,

        [Parameter(Mandatory = $false)]
        [switch]
        $IsIPv6
    )

    $icmpType = [int]$ProtocolData.Type
    if ($IsIPv6) {
        return ($icmpType -eq 128 -or $icmpType -eq 129)
    }
    return ($icmpType -eq 0 -or $icmpType -eq 8)
}

Export-ModuleMember -Function Format-ICMPEcho, Test-ICMPEcho
