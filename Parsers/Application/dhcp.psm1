# dhcp.psm1 - DHCP and DHCPv6 application layer parsers.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# DHCP message types (option 53).
$script:DhcpMessageTypes = @{
    1 = 'DISCOVER'
    2 = 'OFFER'
    3 = 'REQUEST'
    4 = 'DECLINE'
    5 = 'ACK'
    6 = 'NACK'
    7 = 'RELEASE'
    8 = 'INFORM'
}

# DHCPv6 message types.
$script:Dhcpv6MessageTypes = @{
    1  = 'SOLICIT'
    2  = 'ADVERTISE'
    3  = 'REQUEST'
    4  = 'CONFIRM'
    5  = 'RENEW'
    6  = 'REBIND'
    7  = 'REPLY'
    8  = 'RELEASE'
    9  = 'DECLINE'
    10 = 'RECONFIGURE'
    11 = 'INFORMATION-REQUEST'
    12 = 'RELAY-FORW'
    13 = 'RELAY-REPLY'
}

# Common DHCP option numbers.
$script:DhcpOptionNames = @{
    1   = 'Subnet Mask'
    3   = 'Router'
    6   = 'DNS'
    12  = 'Hostname'
    15  = 'Domain Name'
    50  = 'Requested IP'
    51  = 'Lease Time'
    53  = 'Message Type'
    54  = 'Server ID'
    55  = 'Parameter List'
    58  = 'Renewal Time'
    59  = 'Rebinding Time'
    61  = 'Client ID'
}

<#
.SYNOPSIS
Tests whether a UDP packet is DHCP (ports 67/68) or DHCPv6 (ports 546/547).

.PARAMETER ProtocolData
A UDPData object from the parsed packet.
#>
function Test-DhcpPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    if ($null -eq $ProtocolData) { return $false }
    $sp = $ProtocolData.SourcePort
    $dp = $ProtocolData.DestinationPort
    # DHCP: client 68, server 67.
    if ($sp -eq 67 -or $dp -eq 67 -or $sp -eq 68 -or $dp -eq 68) { return $true }
    # DHCPv6: client 546, server 547.
    if ($sp -eq 546 -or $dp -eq 546 -or $sp -eq 547 -or $dp -eq 547) { return $true }
    return $false
}

<#
.SYNOPSIS
Tests whether a UDP packet is DHCPv6 specifically.

.PARAMETER ProtocolData
A UDPData object.
#>
function Test-Dhcpv6Packet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    if ($null -eq $ProtocolData) { return $false }
    $sp = $ProtocolData.SourcePort
    $dp = $ProtocolData.DestinationPort
    return ($sp -eq 546 -or $dp -eq 546 -or $sp -eq 547 -or $dp -eq 547)
}

<#
.SYNOPSIS
Formats a DHCP packet for Default (single-line) output.

.DESCRIPTION
Returns a string like: DHCP Discover, xid 0x12345678, ciaddr 0.0.0.0
Similar to tcpdump/pktmon default format.

.PARAMETER ProtocolData
A UDPData object whose .Data contains the DHCP payload.
#>
function Format-DhcpSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    # Need at least 28 bytes for basic BOOTP header fields (op through giaddr).
    if ($null -eq $data -or $data.Count -lt 28) {
        return "DHCP (truncated)"
    }

    # BOOTP/DHCP header: op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
    # ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)
    # magic cookie(4) options...
    $op = $data[0]
    $xid = [PacketParseHelper]::ReadUInt32BE($data, 4)
    $xidHex = '0x{0:x8}' -f $xid
    $ciaddr = "$($data[12]).$($data[13]).$($data[14]).$($data[15])"
    $yiaddr = "$($data[16]).$($data[17]).$($data[18]).$($data[19])"

    # Parse message type from options (after 236 byte header + 4 byte magic cookie).
    $msgType = $null
    if ($data.Count -ge 240) {
        $msgType = Get-DhcpMessageType -Data $data
    }

    if ($null -ne $msgType -and $script:DhcpMessageTypes.ContainsKey([int]$msgType)) {
        $msgName = $script:DhcpMessageTypes[[int]$msgType]
    } else {
        # Options truncated — infer direction from op field.
        if ($op -eq 1) { $msgName = 'REQUEST*' }
        elseif ($op -eq 2) { $msgName = 'REPLY*' }
        else { $msgName = "op $op" }
    }

    # Build output similar to tcpdump: DHCP DISCOVER, xid 0x..., [ciaddr|yiaddr]
    $result = "DHCP $msgName, xid $xidHex"
    if ($yiaddr -ne '0.0.0.0') {
        $result += ", yiaddr $yiaddr"
    } elseif ($ciaddr -ne '0.0.0.0') {
        $result += ", ciaddr $ciaddr"
    }

    return $result
}

<#
.SYNOPSIS
Formats a DHCPv6 packet for Default (single-line) output.

.DESCRIPTION
Returns a string like: DHCPv6 Solicit, xid 0x123456
Similar to Wireshark summary format.

.PARAMETER ProtocolData
A UDPData object whose .Data contains the DHCPv6 payload.
#>
function Format-Dhcpv6Segment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 4) {
        return "DHCPv6 (truncated)"
    }

    # DHCPv6 header: msg-type(1) transaction-id(3).
    $msgType = [int]$data[0]
    $xid = ([int]$data[1] -shl 16) -bor ([int]$data[2] -shl 8) -bor [int]$data[3]
    $xidHex = '0x{0:x6}' -f $xid

    $msgName = "type $msgType"
    if ($script:Dhcpv6MessageTypes.ContainsKey($msgType)) {
        $msgName = $script:Dhcpv6MessageTypes[$msgType]
    }

    return "DHCPv6 $msgName, xid $xidHex"
}

<#
.SYNOPSIS
Formats a DHCP packet for Detailed (multi-line) output.

.DESCRIPTION
Returns a detailed string with message type, transaction ID, addresses, and key options.

.PARAMETER ProtocolData
A UDPData object whose .Data contains the DHCP payload.
#>
function Format-DhcpDetailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 28) {
        return "DHCP (truncated)"
    }

    $op = $data[0]
    $xid = [PacketParseHelper]::ReadUInt32BE($data, 4)
    $xidHex = '0x{0:x8}' -f $xid
    $ciaddr = "$($data[12]).$($data[13]).$($data[14]).$($data[15])"
    $yiaddr = "$($data[16]).$($data[17]).$($data[18]).$($data[19])"
    $siaddr = "$($data[20]).$($data[21]).$($data[22]).$($data[23])"

    # Client hardware address (first 6 bytes of chaddr at offset 28).
    $hlen = [int]$data[2]
    if ($hlen -gt 16) { $hlen = 6 }
    if ($hlen -lt 1) { $hlen = 6 }
    $chaddr = ''
    if ($data.Count -ge (28 + $hlen)) {
        $chaddr = ($data[28..(28 + $hlen - 1)] | ForEach-Object { $_.ToString('x2') }) -join ':'
    }

    $msgType = $null
    if ($data.Count -ge 240) {
        $msgType = Get-DhcpMessageType -Data $data
    }
    if ($null -ne $msgType -and $script:DhcpMessageTypes.ContainsKey([int]$msgType)) {
        $msgName = $script:DhcpMessageTypes[[int]$msgType]
    } else {
        if ($op -eq 1) { $msgName = 'REQUEST*' }
        elseif ($op -eq 2) { $msgName = 'REPLY*' }
        else { $msgName = "op $op" }
    }

    $parts = [System.Collections.ArrayList]::new()
    $null = $parts.Add("DHCP $msgName - xid: $xidHex; chaddr: $chaddr")

    # Addresses (only show non-zero).
    $addrParts = [System.Collections.ArrayList]::new()
    if ($ciaddr -ne '0.0.0.0') { $null = $addrParts.Add("ci: $ciaddr") }
    if ($yiaddr -ne '0.0.0.0') { $null = $addrParts.Add("yi: $yiaddr") }
    if ($siaddr -ne '0.0.0.0') { $null = $addrParts.Add("si: $siaddr") }
    if ($addrParts.Count -gt 0) {
        $null = $parts.Add($addrParts -join ', ')
    }

    # Parse key options (only if we have enough data).
    if ($data.Count -ge 240) {
        $opts = Get-DhcpOptions -Data $data
        $optParts = [System.Collections.ArrayList]::new()
        if ($opts.ContainsKey(50)) { $null = $optParts.Add("Requested: $($opts[50])") }
        if ($opts.ContainsKey(54)) { $null = $optParts.Add("Server: $($opts[54])") }
        if ($opts.ContainsKey(51)) { $null = $optParts.Add("Lease: $($opts[51])s") }
        if ($opts.ContainsKey(12)) { $null = $optParts.Add("Host: $($opts[12])") }
        if ($opts.ContainsKey(15)) { $null = $optParts.Add("Domain: $($opts[15])") }
        if ($optParts.Count -gt 0) {
            $null = $parts.Add($optParts -join '; ')
        }
    }

    return $parts -join '; '
}

<#
.SYNOPSIS
Formats a DHCPv6 packet for Detailed (multi-line) output.

.PARAMETER ProtocolData
A UDPData object whose .Data contains the DHCPv6 payload.
#>
function Format-Dhcpv6Detailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 4) {
        return "DHCPv6 (truncated)"
    }

    $msgType = [int]$data[0]
    $xid = ([int]$data[1] -shl 16) -bor ([int]$data[2] -shl 8) -bor [int]$data[3]
    $xidHex = '0x{0:x6}' -f $xid

    $msgName = "type $msgType"
    if ($script:Dhcpv6MessageTypes.ContainsKey($msgType)) {
        $msgName = $script:Dhcpv6MessageTypes[$msgType]
    }

    # Parse DHCPv6 options.
    $optParts = [System.Collections.ArrayList]::new()
    $pos = 4
    while ($pos + 4 -le $data.Count) {
        $optCode = [PacketParseHelper]::ReadUInt16BE($data, $pos)
        $optLen = [PacketParseHelper]::ReadUInt16BE($data, $pos + 2)
        $pos += 4
        if ($pos + $optLen -gt $data.Count) { break }

        switch ([int]$optCode) {
            1 {
                # Client Identifier (DUID).
                $null = $optParts.Add("Client-ID")
            }
            2 {
                # Server Identifier (DUID).
                $null = $optParts.Add("Server-ID")
            }
            3 {
                # IA_NA (Identity Association for Non-temporary Addresses).
                if ($optLen -ge 12) {
                    $iaId = [PacketParseHelper]::ReadUInt32BE($data, $pos)
                    $null = $optParts.Add("IA_NA id: 0x$($iaId.ToString('x8'))")
                }
            }
            5 {
                # IA Address.
                if ($optLen -ge 24) {
                    $addrBytes = $data[$pos..($pos + 15)]
                    $addr = ([System.Net.IPAddress]::new($addrBytes)).ToString()
                    $null = $optParts.Add("Addr: $addr")
                }
            }
            6 {
                # Option Request.
                $null = $optParts.Add("ORO")
            }
            23 {
                # DNS Recursive Name Server.
                if ($optLen -ge 16) {
                    $dnsBytes = $data[$pos..($pos + 15)]
                    $dnsAddr = ([System.Net.IPAddress]::new($dnsBytes)).ToString()
                    $null = $optParts.Add("DNS: $dnsAddr")
                }
            }
        }

        $pos += $optLen
    }

    $result = "DHCPv6 $msgName - xid: $xidHex"
    if ($optParts.Count -gt 0) {
        $result += "; $($optParts -join '; ')"
    }

    return $result
}

<#
.SYNOPSIS
Extracts the DHCP message type (option 53) from DHCP payload.

.PARAMETER Data
The raw DHCP payload bytes.
#>
function Get-DhcpMessageType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $Data
    )

    # Options start after 236-byte BOOTP header + 4-byte magic cookie (0x63825363).
    if ($Data.Count -lt 240) { return $null }

    # Verify magic cookie.
    if ($Data[236] -ne 0x63 -or $Data[237] -ne 0x82 -or
        $Data[238] -ne 0x53 -or $Data[239] -ne 0x63) {
        return $null
    }

    $pos = 240
    while ($pos -lt $Data.Count) {
        $opt = [int]$Data[$pos]
        if ($opt -eq 255) { break }  # End option.
        if ($opt -eq 0) { $pos++; continue }  # Pad.
        $pos++
        if ($pos -ge $Data.Count) { break }
        $len = [int]$Data[$pos]
        $pos++
        if ($opt -eq 53 -and $len -ge 1 -and $pos -lt $Data.Count) {
            return [int]$Data[$pos]
        }
        $pos += $len
    }

    return $null
}

<#
.SYNOPSIS
Parses key DHCP options into a hashtable.

.PARAMETER Data
The raw DHCP payload bytes.
#>
function Get-DhcpOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $Data
    )

    $opts = @{}
    if ($Data.Count -lt 240) { return $opts }

    # Verify magic cookie.
    if ($Data[236] -ne 0x63 -or $Data[237] -ne 0x82 -or
        $Data[238] -ne 0x53 -or $Data[239] -ne 0x63) {
        return $opts
    }

    $pos = 240
    while ($pos -lt $Data.Count) {
        $opt = [int]$Data[$pos]
        if ($opt -eq 255) { break }
        if ($opt -eq 0) { $pos++; continue }
        $pos++
        if ($pos -ge $Data.Count) { break }
        $len = [int]$Data[$pos]
        $pos++
        if ($pos + $len -gt $Data.Count) { break }

        switch ($opt) {
            50 {
                # Requested IP Address.
                if ($len -ge 4) {
                    $opts[50] = "$($Data[$pos]).$($Data[$pos+1]).$($Data[$pos+2]).$($Data[$pos+3])"
                }
            }
            51 {
                # Lease Time.
                if ($len -ge 4) {
                    $opts[51] = [PacketParseHelper]::ReadUInt32BE($Data, $pos)
                }
            }
            54 {
                # Server Identifier.
                if ($len -ge 4) {
                    $opts[54] = "$($Data[$pos]).$($Data[$pos+1]).$($Data[$pos+2]).$($Data[$pos+3])"
                }
            }
            12 {
                # Hostname.
                $opts[12] = [System.Text.Encoding]::ASCII.GetString($Data, $pos, $len)
            }
            15 {
                # Domain Name.
                $opts[15] = [System.Text.Encoding]::ASCII.GetString($Data, $pos, $len)
            }
        }

        $pos += $len
    }

    return $opts
}

Export-ModuleMember -Function Test-DhcpPacket, Test-Dhcpv6Packet, Format-DhcpSegment, Format-Dhcpv6Segment, Format-DhcpDetailed, Format-Dhcpv6Detailed
