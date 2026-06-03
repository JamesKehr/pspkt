# arp.psm1 - ARP protocol formatter for pspkt real-time output.
# tcpdump style: ARP, Request who-has 10.0.0.1 tell 10.0.0.2, length 28
#                ARP, Reply 10.0.0.1 is-at aa-bb-cc-dd-ee-ff, length 28

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ARP operation codes.
$script:ArpOpcodes = @{
    1 = 'Request'
    2 = 'Reply'
    3 = 'RARP Request'
    4 = 'RARP Reply'
}

<#
.SYNOPSIS
Tests whether a ParsedPacket is an ARP frame (EtherType 0x0806).
#>
function Test-ArpPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ParsedPacket
    )

    $link = $ParsedPacket.LinkLayerData
    if ($null -eq $link) { return $false }
    if ($link.EtherType -eq 0x0806) { return $true }
    return $false
}

<#
.SYNOPSIS
Formats an ARP packet from raw bytes into a tcpdump-style string.

.DESCRIPTION
Parses the ARP header starting after the Ethernet header (offset 14, or 18 with VLAN).
Returns: ARP, Request who-has [target IP] tell [sender IP], length [N]
     or: ARP, Reply [sender IP] is-at [sender MAC], length [N]

.PARAMETER RawPacketData
The full raw packet bytes including the Ethernet header.

.PARAMETER ParsedPacket
The ParsedPacket object (used for VLAN offset detection).
#>
function Format-ArpSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $RawPacketData,

        [Parameter(Mandatory = $true)]
        $ParsedPacket
    )

    # Determine ARP header offset (after Ethernet header).
    $offset = 14
    if ($null -ne $ParsedPacket.LinkLayerData -and $ParsedPacket.LinkLayerData.VlanTag) {
        $offset = 18
    }

    # ARP header: HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2) SHA(6) SPA(4) THA(6) TPA(4) = 28 bytes
    $arpLen = $RawPacketData.Count - $offset
    if ($arpLen -lt 28) {
        return "ARP, len $arpLen (truncated)"
    }

    $opcode = [PacketParseHelper]::ReadUInt16BE($RawPacketData, $offset + 6)
    $opName = 'op ' + $opcode.ToString()
    if ($script:ArpOpcodes.ContainsKey([int]$opcode)) {
        $opName = $script:ArpOpcodes[[int]$opcode]
    }

    # Sender hardware address (MAC) - 6 bytes at offset+8
    $shaMac = [PacketParseHelper]::FormatMac($RawPacketData, $offset + 8)
    # Sender protocol address (IPv4) - 4 bytes at offset+14
    $spaIp = "$($RawPacketData[$offset + 14]).$($RawPacketData[$offset + 15]).$($RawPacketData[$offset + 16]).$($RawPacketData[$offset + 17])"
    # Target protocol address (IPv4) - 4 bytes at offset+24
    $tpaIp = "$($RawPacketData[$offset + 24]).$($RawPacketData[$offset + 25]).$($RawPacketData[$offset + 26]).$($RawPacketData[$offset + 27])"

    if ($opcode -eq 1) {
        # Request
        return "ARP, Request who-has $tpaIp tell $spaIp, len $arpLen"
    } elseif ($opcode -eq 2) {
        # Reply
        return "ARP, Reply $spaIp is-at $shaMac, len $arpLen"
    } else {
        return "ARP, $opName $spaIp > $tpaIp, len $arpLen"
    }
}

Export-ModuleMember -Function Test-ArpPacket, Format-ArpSegment
