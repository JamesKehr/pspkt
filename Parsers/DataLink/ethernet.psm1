# ethernet.psm1 - Ethernet II data link layer formatter.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# EtherType display names for common values.
$script:EtherTypeNames = @{
    0x0800 = 'IPv4'
    0x0806 = 'ARP'
    0x86DD = 'IPv6'
    0x8100 = '802.1Q'
    0x88CC = 'LLDP'
    0x8035 = 'RARP'
    0x888E = '802.1X'
    0x88A8 = '802.1ad'
}

<#
.SYNOPSIS
Converts a colon-separated MAC string to dash-separated.
#>
function ConvertTo-DashMac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Mac
    )

    return ($Mac -replace ':', '-').ToLower()
}

<#
.SYNOPSIS
Formats the data link layer segment of a parsed packet.

.DESCRIPTION
Returns a string in the format:
  [SrcMAC] > [DstMAC], type [etherType], length [frameLen]

.PARAMETER ParsedPacket
A ParsedPacket object.

.PARAMETER RawLength
Total frame length in bytes.
#>
function Format-DataLinkSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ParsedPacket,

        [Parameter(Mandatory = $true)]
        [int]
        $RawLength
    )

    $link = $ParsedPacket.LinkLayerData
    if ($null -eq $link) {
        return $null
    }

    $srcMac = '??-??-??-??-??-??'
    $dstMac = '??-??-??-??-??-??'

    # LinkKind 1=EthernetII (has SourceMacAddress/DestinationMacAddress as dash-separated)
    if ($ParsedPacket.LinkKind -eq 1) {
        if ($link.SourceMacAddress) {
            $srcMac = ConvertTo-DashMac -Mac $link.SourceMacAddress
        }
        if ($link.DestinationMacAddress) {
            $dstMac = ConvertTo-DashMac -Mac $link.DestinationMacAddress
        }
    }

    # Resolve EtherType to a friendly name.
    $etherType = $link.EtherType
    $etherTypeName = $null
    if ($script:EtherTypeNames.ContainsKey([int]$etherType)) {
        $etherTypeName = $script:EtherTypeNames[[int]$etherType]
    } else {
        $etherTypeName = '0x{0:X4}' -f [int]$etherType
    }

    return "$srcMac > $dstMac, type $etherTypeName, len $RawLength"
}

Export-ModuleMember -Function Format-DataLinkSegment, ConvertTo-DashMac
