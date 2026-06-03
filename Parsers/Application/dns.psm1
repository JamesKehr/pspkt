# dns.psm1 - DNS/mDNS application layer formatter for pspkt real-time output.
# tcpdump style queries:   12345+ A? www.example.com. (32)
# tcpdump style responses: 12345 1/0/0 A 93.184.216.34 (49)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# DNS record type names.
$script:DnsTypeNames = @{
    1   = 'A'
    2   = 'NS'
    5   = 'CNAME'
    6   = 'SOA'
    12  = 'PTR'
    15  = 'MX'
    16  = 'TXT'
    28  = 'AAAA'
    33  = 'SRV'
    35  = 'NAPTR'
    41  = 'OPT'
    43  = 'DS'
    46  = 'RRSIG'
    47  = 'NSEC'
    48  = 'DNSKEY'
    65  = 'HTTPS'
    255 = 'ANY'
    257 = 'CAA'
}

# DNS class names.
$script:DnsClassNames = @{
    1   = 'IN'
    3   = 'CH'
    4   = 'HS'
    255 = 'ANY'
}

# DNS response codes.
$script:DnsRcodes = @{
    0 = 'NoError'
    1 = 'FormErr'
    2 = 'ServFail'
    3 = 'NXDomain'
    4 = 'NotImp'
    5 = 'Refused'
}

<#
.SYNOPSIS
Tests whether a UDP packet is DNS (port 53) or mDNS (port 5353).
#>
function Test-DnsPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    if ($null -eq $ProtocolData) { return $false }
    if ($ProtocolData.SourcePort -eq 53 -or $ProtocolData.DestinationPort -eq 53) { return $true }
    if ($ProtocolData.SourcePort -eq 5353 -or $ProtocolData.DestinationPort -eq 5353) { return $true }
    return $false
}

<#
.SYNOPSIS
Reads a DNS domain name from a byte array at the given offset, handling compression pointers.

.OUTPUTS
A hashtable with 'Name' (string) and 'BytesRead' (int).
#>
function Read-DnsName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $Data,

        [Parameter(Mandatory = $true)]
        [int]
        $Offset
    )

    $labels = [System.Collections.ArrayList]::new()
    $bytesRead = 0
    $followed = $false
    $pos = $Offset
    $maxIterations = 64

    while ($maxIterations -gt 0) {
        $maxIterations--
        if ($pos -ge $Data.Count) { break }

        $labelLen = [int]$Data[$pos]
        if ($labelLen -eq 0) {
            if (-not $followed) { $bytesRead++ }
            break
        }

        # Compression pointer (top 2 bits set).
        if (($labelLen -band 0xC0) -eq 0xC0) {
            if ($pos + 1 -ge $Data.Count) { break }
            $pointer = (([int]$labelLen -band 0x3F) -shl 8) -bor [int]$Data[$pos + 1]
            if (-not $followed) { $bytesRead += 2 }
            $followed = $true
            $pos = $pointer
            continue
        }

        $pos++
        if (-not $followed) { $bytesRead += 1 + $labelLen }

        if ($pos + $labelLen -gt $Data.Count) { break }
        $label = [System.Text.Encoding]::ASCII.GetString($Data, $pos, $labelLen)
        $null = $labels.Add($label)
        $pos += $labelLen
    }

    if ($labels.Count -eq 0) {
        return @{ Name = '.'; BytesRead = $bytesRead }
    }
    return @{ Name = ($labels -join '.') + '.'; BytesRead = $bytesRead }
}

<#
.SYNOPSIS
Formats a DNS packet payload into a tcpdump-style single line.

.DESCRIPTION
Query format:   [txid]+ [type]? [name] ([udp payload size])
Response format: [txid] [rcode] [ancount]/[nscount]/[arcount] [first answer type] [first answer data] ([udp payload size])
mDNS is indicated by prefixing with "mDNS" instead of "DNS" label (but we don't show a label prefix, tcpdump-style).

.PARAMETER ProtocolData
The UDPData object whose .Data property contains the DNS payload.
#>
function Format-DnsSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 12) {
        return "DNS, len $($data.Count) (truncated)"
    }

    # Use high-performance C# parser for the default real-time one-liner.
    $result = [DnsParser]::FormatDnsSegment($data, [int]$ProtocolData.SourcePort, [int]$ProtocolData.DestinationPort)
    if ($null -ne $result) {
        return $result
    }
    return "DNS, len $($data.Count) (truncated)"
}

<#
.SYNOPSIS
Extracts the first answer record data from DNS response bytes.
#>
function Get-DnsFirstAnswer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $Data,

        [Parameter(Mandatory = $true)]
        [int]
        $Offset
    )

    $pos = $Offset
    if ($pos -ge $Data.Count) { return '' }

    # Read answer name.
    $nameResult = Read-DnsName -Data $Data -Offset $pos
    $rrName = $nameResult.Name
    $pos += $nameResult.BytesRead

    if ($pos + 10 -gt $Data.Count) { return '' }
    $rType = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
    $pos += 2  # TYPE
    $pos += 2  # CLASS
    $pos += 4  # TTL
    $rdLength = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
    $pos += 2

    $typeName = "TYPE$rType"
    if ($script:DnsTypeNames.ContainsKey([int]$rType)) {
        $typeName = $script:DnsTypeNames[[int]$rType]
    }

    if ($pos + $rdLength -gt $Data.Count) {
        return "$rrName $typeName (truncated)"
    }

    # Format RDATA based on type.
    switch ([int]$rType) {
        1 {
            # A record - 4 bytes IPv4
            if ($rdLength -ge 4) {
                $ip = "$($Data[$pos]).$($Data[$pos+1]).$($Data[$pos+2]).$($Data[$pos+3])"
                return "$rrName $typeName $ip"
            }
        }
        28 {
            # AAAA record - 16 bytes IPv6
            if ($rdLength -ge 16) {
                $parts = for ($i = 0; $i -lt 16; $i += 2) {
                    '{0:x4}' -f [PacketParseHelper]::ReadUInt16BE($Data, $pos + $i)
                }
                $ip6 = ($parts -join ':') -replace '(:0000)+:', '::'
                return "$rrName $typeName $ip6"
            }
        }
        5 {
            # CNAME
            $cnameResult = Read-DnsName -Data $Data -Offset $pos
            return "$rrName $typeName $($cnameResult.Name)"
        }
        12 {
            # PTR
            $ptrResult = Read-DnsName -Data $Data -Offset $pos
            return "$rrName $typeName $($ptrResult.Name)"
        }
        2 {
            # NS
            $nsResult = Read-DnsName -Data $Data -Offset $pos
            return "$rrName $typeName $($nsResult.Name)"
        }
    }

    return "$rrName $typeName"
}

<#
.SYNOPSIS
Formats a single DNS resource record as "name: type TYPE, class CLASS".
Returns hashtable with Text, BytesRead, and RType for post-processing.
#>
function Format-DnsRR {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $Data,

        [Parameter(Mandatory = $true)]
        [int]
        $Offset
    )

    if ($Offset -ge $Data.Count) {
        return @{ Text = $null; BytesRead = 0; RType = 0 }
    }

    $nameResult = Read-DnsName -Data $Data -Offset $Offset
    $pos = $Offset + $nameResult.BytesRead

    if ($pos + 10 -gt $Data.Count) {
        return @{ Text = $null; BytesRead = ($pos - $Offset); RType = 0 }
    }

    $rType = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
    $rClass = [PacketParseHelper]::ReadUInt16BE($Data, $pos + 2)
    $pos += 4  # TYPE + CLASS
    $pos += 4  # TTL
    $rdLength = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
    $pos += 2  # RDLENGTH

    $typeName = "TYPE$rType"
    if ($script:DnsTypeNames.ContainsKey([int]$rType)) {
        $typeName = $script:DnsTypeNames[[int]$rType]
    }

    $className = "CLASS$rClass"
    # For mDNS, bit 15 of class is cache-flush flag; mask it.
    $classLookup = [int]($rClass -band 0x7FFF)
    if ($script:DnsClassNames.ContainsKey($classLookup)) {
        $className = $script:DnsClassNames[$classLookup]
    }

    # Extract RDATA for IP types.
    $rdataStr = $null
    if ($pos + $rdLength -le $Data.Count) {
        switch ([int]$rType) {
            1 {
                # A record
                if ($rdLength -ge 4) {
                    $rdataStr = "$($Data[$pos]).$($Data[$pos+1]).$($Data[$pos+2]).$($Data[$pos+3])"
                }
            }
            28 {
                # AAAA record
                if ($rdLength -ge 16) {
                    $parts = for ($i = 0; $i -lt 16; $i += 2) {
                        '{0:x4}' -f [PacketParseHelper]::ReadUInt16BE($Data, $pos + $i)
                    }
                    $rdataStr = ($parts -join ':') -replace '(:0000)+:', '::'
                }
            }
            5 {
                # CNAME
                $cnameResult = Read-DnsName -Data $Data -Offset $pos
                $rdataStr = $cnameResult.Name
            }
        }
    }

    $rrName = $nameResult.Name
    $text = "${rrName}: type $typeName, class $className"
    if ($null -ne $rdataStr) {
        switch ([int]$rType) {
            1  { $text += ", addr $rdataStr" }
            28 { $text += ", addr $rdataStr" }
            5  { $text += ", cname $rdataStr" }
        }
    }
    $totalRead = ($pos + $rdLength) - $Offset

    return @{ Text = $text; BytesRead = $totalRead; RType = [int]$rType; RData = $rdataStr }
}

<#
.SYNOPSIS
Formats a DNS/mDNS packet into a detailed one-liner showing flags, queries, answers, authority, and additional records.

.PARAMETER ProtocolData
The UDPData object whose .Data property contains the DNS payload.
#>
function Format-DnsDetailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 12) { return $null }

    $isMdns = ($ProtocolData.SourcePort -eq 5353 -or $ProtocolData.DestinationPort -eq 5353)

    # Header fields.
    $txId = [PacketParseHelper]::ReadUInt16BE($data, 0)
    $flags = [PacketParseHelper]::ReadUInt16BE($data, 2)
    $qdCount = [PacketParseHelper]::ReadUInt16BE($data, 4)
    $anCount = [PacketParseHelper]::ReadUInt16BE($data, 6)
    $nsCount = [PacketParseHelper]::ReadUInt16BE($data, 8)
    $arCount = [PacketParseHelper]::ReadUInt16BE($data, 10)

    # Parse flags.
    $qr     = ($flags -shr 15) -band 1
    $opcode = ($flags -shr 11) -band 0xF
    $aa     = ($flags -shr 10) -band 1
    $tc     = ($flags -shr 9) -band 1
    $rd     = ($flags -shr 8) -band 1
    $ra     = ($flags -shr 7) -band 1
    $rcode  = $flags -band 0xF

    $flagList = [System.Collections.ArrayList]::new()
    if ($qr -eq 0) { $null = $flagList.Add('QR') } else { $null = $flagList.Add('R') }
    if ($aa) { $null = $flagList.Add('AA') }
    if ($tc) { $null = $flagList.Add('TC') }
    if ($rd) { $null = $flagList.Add('RD') }
    if ($ra) { $null = $flagList.Add('RA') }
    if ($rcode -ne 0) {
        $rcodeName = "RCODE$rcode"
        if ($script:DnsRcodes.ContainsKey([int]$rcode)) {
            $rcodeName = $script:DnsRcodes[[int]$rcode]
        }
        $null = $flagList.Add($rcodeName)
    }
    $flagStr = $flagList -join ','

    $prefix = if ($isMdns) { 'mDNS' } else { 'DNS' }
    $txIdHex = '0x{0:x4}' -f $txId

    $pos = 12

    # Parse questions.
    $queries = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $qdCount; $i++) {
        if ($pos -ge $data.Count) { break }
        $nameResult = Read-DnsName -Data $data -Offset $pos
        $pos += $nameResult.BytesRead
        if ($pos + 4 -le $data.Count) {
            $qType = [PacketParseHelper]::ReadUInt16BE($data, $pos)
            $qClass = [PacketParseHelper]::ReadUInt16BE($data, $pos + 2)
            $pos += 4

            $typeName = "TYPE$qType"
            if ($script:DnsTypeNames.ContainsKey([int]$qType)) {
                $typeName = $script:DnsTypeNames[[int]$qType]
            }
            $className = "CLASS$qClass"
            $classLookup = [int]($qClass -band 0x7FFF)
            if ($script:DnsClassNames.ContainsKey($classLookup)) {
                $className = $script:DnsClassNames[$classLookup]
            }
            $null = $queries.Add("$($nameResult.Name): type $typeName, class $className")
        }
    }

    # Parse answer RRs — collapse CNAME chains and group IPs.
    $rawAnswers = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $anCount; $i++) {
        if ($pos -ge $data.Count) { break }
        $rr = Format-DnsRR -Data $data -Offset $pos
        $null = $rawAnswers.Add($rr)
        $pos += $rr.BytesRead
    }

    $answers = [System.Collections.ArrayList]::new()
    $cnameCount = 0
    $firstCname = $null
    foreach ($rr in $rawAnswers) {
        if ($null -eq $rr.Text) { continue }
        if ($rr.RType -eq 5) {
            # CNAME — keep only the first.
            $cnameCount++
            if ($cnameCount -eq 1) { $firstCname = $rr.Text }
        } else {
            $null = $answers.Add($rr.Text)
        }
    }
    # Emit collapsed CNAME.
    if ($null -ne $firstCname) {
        if ($cnameCount -gt 1) {
            $null = $answers.Add("$firstCname ...")
        } else {
            $null = $answers.Add($firstCname)
        }
    }

    # Parse authority RRs.
    $authority = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $nsCount; $i++) {
        if ($pos -ge $data.Count) { break }
        $rr = Format-DnsRR -Data $data -Offset $pos
        if ($null -ne $rr.Text) { $null = $authority.Add($rr.Text) }
        $pos += $rr.BytesRead
    }

    # Parse additional RRs.
    $additional = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $arCount; $i++) {
        if ($pos -ge $data.Count) { break }
        $rr = Format-DnsRR -Data $data -Offset $pos
        if ($null -ne $rr.Text) { $null = $additional.Add($rr.Text) }
        $pos += $rr.BytesRead
    }

    # Build output — only include sections with data.
    $parts = [System.Collections.ArrayList]::new()
    $null = $parts.Add("$prefix [$flagStr] - Id: $txIdHex")
    if ($queries.Count -gt 0) {
        $null = $parts.Add("Qry: $($queries -join ', ')")
    }
    if ($answers.Count -gt 0) {
        $null = $parts.Add("Ans: $($answers -join ', ')")
    }
    if ($authority.Count -gt 0) {
        $null = $parts.Add("Auth: $($authority -join ', ')")
    }
    if ($additional.Count -gt 0) {
        $null = $parts.Add("Add: $($additional -join ', ')")
    }

    return $parts -join '; '
}

Export-ModuleMember -Function Test-DnsPacket, Format-DnsSegment, Read-DnsName, Get-DnsFirstAnswer, Format-DnsRR, Format-DnsDetailed
