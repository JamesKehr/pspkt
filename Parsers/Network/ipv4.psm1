# ipv4.psm1 - IPv4 network layer formatter.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Formats an IPv4 address.port string for TCP/UDP, or just the address for ICMP/other.

.PARAMETER IPv4Data
An IPv4Data object from the parsed packet.

.PARAMETER IncludePorts
If true, appends .port to each address.

.PARAMETER SrcPort
Source port number.

.PARAMETER DstPort
Destination port number.
#>
function Format-IPv4Addresses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $IPv4Data,

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

    $src = $IPv4Data.SourceAddress.ToString()
    $dst = $IPv4Data.DestinationAddress.ToString()

    if ($IncludePorts) {
        return "$src.$SrcPort > $dst.$DstPort"
    }

    return "$src > $dst"
}

<#
.SYNOPSIS
Formats a detailed IPv4 line for verbose output.

.DESCRIPTION
Returns a string with full IPv4 header details:
  IPv4 - Src: [addr], Dst: [addr]; DSCP: [value]; len: [total]; id: [hex]; flg: [flags]; TTL: [ttl]; Next: [proto]

.PARAMETER IPv4Data
An IPv4Data object from the parsed packet.
#>
function Format-IPv4Detailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $IPv4Data
    )

    $src = $IPv4Data.SourceAddress
    $dst = $IPv4Data.DestinationAddress

    # DSCP: upper 6 bits of TOS
    $dscpVal = $IPv4Data.TOS -shr 2
    if ([Enum]::IsDefined([DSCP], [int]$dscpVal)) {
        $dscpStr = ([DSCP]$dscpVal).ToString()
    } else {
        $dscpStr = "$dscpVal"
    }

    $len = $IPv4Data.TotalLength
    $id = '0x{0:x4}' -f $IPv4Data.Identification

    # Flags: bits 1=DF, 2=MF (bit 0 is reserved)
    $flagList = @()
    if ($IPv4Data.Flags -band 0x40) { $flagList += 'DF' }
    if ($IPv4Data.Flags -band 0x20) { $flagList += 'MF' }
    if ($flagList.Count -eq 0) { $flagList += 'none' }
    $flgStr = $flagList -join ','

    $ttl = $IPv4Data.TTL
    $next = $IPv4Data.Protocol.ToString()

    return "IPv4 - Src: $src, Dst: $dst; DSCP: $dscpStr; len: $len; id: $id; flg: $flgStr; TTL: $ttl; Next: $next"
}

Export-ModuleMember -Function Format-IPv4Addresses, Format-IPv4Detailed
