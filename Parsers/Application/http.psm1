# http.psm1 - HTTP and TLS (HTTPS) application layer parsers.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# HTTP methods for detection.
$script:HttpMethods = @('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE')

# Port arrays cached at script scope for -in lookup (avoids per-call array allocation).
$script:HttpPorts = @(80, 8080, 8000, 8888)
$script:TlsPorts = @(443, 8443, 993, 995, 465, 636)

# TLS content types.
$script:TlsContentTypes = @{
    20 = 'ChangeCipherSpec'
    21 = 'Alert'
    22 = 'Handshake'
    23 = 'ApplicationData'
}

# TLS handshake types.
$script:TlsHandshakeTypes = @{
    0  = 'HelloRequest'
    1  = 'ClientHello'
    2  = 'ServerHello'
    4  = 'NewSessionTicket'
    11 = 'Certificate'
    12 = 'ServerKeyExchange'
    13 = 'CertificateRequest'
    14 = 'ServerHelloDone'
    15 = 'CertificateVerify'
    16 = 'ClientKeyExchange'
    20 = 'Finished'
}

# TLS version mapping.
$script:TlsVersions = @{
    0x0300 = 'SSL 3.0'
    0x0301 = 'TLS 1.0'
    0x0302 = 'TLS 1.1'
    0x0303 = 'TLS 1.2'
    0x0304 = 'TLS 1.3'
}

<#
.SYNOPSIS
Tests whether a TCP packet contains HTTP data (ports 80, 8080, 8000, 8443).

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Test-HttpPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    if ($null -eq $ProtocolData) { return $false }
    if ($null -eq $ProtocolData.Data -or $ProtocolData.Data.Count -lt 4) { return $false }

    $sp = $ProtocolData.SourcePort
    $dp = $ProtocolData.DestinationPort

    # Check if on an HTTP port (cached script-scope array).
    if ($sp -notin $script:HttpPorts -and $dp -notin $script:HttpPorts) { return $false }

    # Verify it looks like HTTP (starts with method or response).
    $data = $ProtocolData.Data
    if ($data.Count -lt 4) { return $false }

    # Check for HTTP response: "HTTP"
    if ($data[0] -eq 0x48 -and $data[1] -eq 0x54 -and
        $data[2] -eq 0x54 -and $data[3] -eq 0x50) {
        return $true
    }

    # Check for HTTP methods.
    $firstLine = ''
    $lineEnd = [Math]::Min($data.Count, 16)
    for ($i = 0; $i -lt $lineEnd; $i++) {
        if ($data[$i] -eq 0x20) { break }  # space
        $firstLine += [char]$data[$i]
    }
    if ($firstLine -in $script:HttpMethods) { return $true }

    return $false
}

<#
.SYNOPSIS
Tests whether a TCP packet contains TLS/HTTPS data (port 443 or TLS record header).

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Test-TlsPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    if ($null -eq $ProtocolData) { return $false }
    if ($null -eq $ProtocolData.Data -or $ProtocolData.Data.Count -lt 5) { return $false }

    $sp = $ProtocolData.SourcePort
    $dp = $ProtocolData.DestinationPort

    # Must be on a TLS port (cached script-scope array).
    if ($sp -notin $script:TlsPorts -and $dp -notin $script:TlsPorts) { return $false }

    # Verify TLS record header: content type (20-23), version (0x0300-0x0304).
    $contentType = [int]$ProtocolData.Data[0]
    if ($contentType -lt 20 -or $contentType -gt 23) { return $false }

    $version = [PacketParseHelper]::ReadUInt16BE($ProtocolData.Data, 1)
    if ($version -lt 0x0300 -or $version -gt 0x0304) { return $false }

    return $true
}

<#
.SYNOPSIS
Formats an HTTP packet for Default (single-line) output.

.DESCRIPTION
Returns a string like: HTTP GET /path or HTTP 200 OK

.PARAMETER ProtocolData
A TCPData object whose .Data contains the HTTP payload.
#>
function Format-HttpSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 4) {
        return "HTTP"
    }

    # Extract first line up to CRLF or max 128 chars.
    $maxLen = [Math]::Min($data.Count, 128)
    $firstLine = ''
    for ($i = 0; $i -lt $maxLen; $i++) {
        if ($data[$i] -eq 0x0D -or $data[$i] -eq 0x0A) { break }
        $firstLine += [char]$data[$i]
    }

    if ($firstLine.Length -eq 0) { return "HTTP" }

    # HTTP Response: "HTTP/1.1 200 OK"
    if ($firstLine.StartsWith('HTTP/')) {
        $parts = $firstLine -split '\s+', 3
        if ($parts.Count -ge 2) {
            $status = $parts[1]
            $reason = if ($parts.Count -ge 3) { " $($parts[2])" } else { '' }
            return "HTTP $status$reason"
        }
        return "HTTP response"
    }

    # HTTP Request: "GET /path HTTP/1.1"
    $parts = $firstLine -split '\s+', 3
    if ($parts.Count -ge 2) {
        $method = $parts[0]
        $path = $parts[1]
        # Truncate long paths.
        if ($path.Length -gt 60) { $path = $path.Substring(0, 57) + '...' }
        return "HTTP $method $path"
    }

    return "HTTP"
}

<#
.SYNOPSIS
Formats a TLS/HTTPS packet for Default (single-line) output.

.DESCRIPTION
Returns a string like: TLS ClientHello [example.com] or TLS ApplicationData

.PARAMETER ProtocolData
A TCPData object whose .Data contains the TLS record.
#>
function Format-TlsSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 5) {
        return "TLS"
    }

    $contentType = [int]$data[0]
    $version = [PacketParseHelper]::ReadUInt16BE($data, 1)
    $recordLen = [PacketParseHelper]::ReadUInt16BE($data, 3)

    $versionStr = ''
    if ($script:TlsVersions.ContainsKey([int]$version)) {
        $versionStr = $script:TlsVersions[[int]$version]
    }

    # Handshake record — parse handshake type.
    if ($contentType -eq 22 -and $data.Count -ge 6) {
        $hsType = [int]$data[5]
        $hsName = "Handshake"
        if ($script:TlsHandshakeTypes.ContainsKey($hsType)) {
            $hsName = $script:TlsHandshakeTypes[$hsType]
        }

        # For ClientHello, try to extract SNI.
        if ($hsType -eq 1) {
            $sni = Get-TlsSni -Data $data
            if ($null -ne $sni -and $sni.Length -gt 0) {
                return "TLS $hsName [$sni]"
            }
        }

        return "TLS $hsName"
    }

    # Other record types.
    if ($script:TlsContentTypes.ContainsKey($contentType)) {
        $typeName = $script:TlsContentTypes[$contentType]
        $lenStr = "len $recordLen"
        return "TLS $typeName, $lenStr"
    }

    return "TLS"
}

<#
.SYNOPSIS
Formats an HTTP packet for Detailed output.

.PARAMETER ProtocolData
A TCPData object whose .Data contains the HTTP payload.
#>
function Format-HttpDetailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 4) {
        return "HTTP (no payload)"
    }

    # Extract first line.
    $maxLen = [Math]::Min($data.Count, 256)
    $firstLine = ''
    $lineEndPos = 0
    for ($i = 0; $i -lt $maxLen; $i++) {
        if ($data[$i] -eq 0x0D -or $data[$i] -eq 0x0A) { $lineEndPos = $i; break }
        $firstLine += [char]$data[$i]
    }
    if ($lineEndPos -eq 0) { $lineEndPos = $firstLine.Length }

    $parts = [System.Collections.ArrayList]::new()
    $null = $parts.Add("HTTP - $firstLine")

    # Extract key headers (Host, Content-Type, Content-Length).
    $headerText = ''
    $hdrStart = $lineEndPos
    # Skip CRLF.
    while ($hdrStart -lt $maxLen -and ($data[$hdrStart] -eq 0x0D -or $data[$hdrStart] -eq 0x0A)) { $hdrStart++ }
    $hdrEnd = [Math]::Min($data.Count, 512)
    for ($i = $hdrStart; $i -lt $hdrEnd; $i++) {
        if ($data[$i] -eq 0x0D -or $data[$i] -eq 0x0A) {
            $headerText += "`n"
        } else {
            $headerText += [char]$data[$i]
        }
    }

    $headers = $headerText -split "`n"
    $keyHeaders = [System.Collections.ArrayList]::new()
    foreach ($hdr in $headers) {
        if ($hdr.Length -eq 0) { break }  # End of headers.
        if ($hdr -match '^(Host|Content-Type|Content-Length):\s*(.+)$') {
            $null = $keyHeaders.Add("$($Matches[1]): $($Matches[2])")
        }
    }
    if ($keyHeaders.Count -gt 0) {
        $null = $parts.Add($keyHeaders -join '; ')
    }

    return $parts -join '; '
}

<#
.SYNOPSIS
Formats a TLS/HTTPS packet for Detailed output.

.PARAMETER ProtocolData
A TCPData object whose .Data contains the TLS record.
#>
function Format-TlsDetailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $data = $ProtocolData.Data
    if ($null -eq $data -or $data.Count -lt 5) {
        return "TLS (truncated)"
    }

    $contentType = [int]$data[0]
    $version = [PacketParseHelper]::ReadUInt16BE($data, 1)
    $recordLen = [PacketParseHelper]::ReadUInt16BE($data, 3)

    $versionStr = "0x$($version.ToString('x4'))"
    if ($script:TlsVersions.ContainsKey([int]$version)) {
        $versionStr = $script:TlsVersions[[int]$version]
    }

    $parts = [System.Collections.ArrayList]::new()

    if ($contentType -eq 22 -and $data.Count -ge 6) {
        $hsType = [int]$data[5]
        $hsName = "type $hsType"
        if ($script:TlsHandshakeTypes.ContainsKey($hsType)) {
            $hsName = $script:TlsHandshakeTypes[$hsType]
        }
        $null = $parts.Add("TLS Handshake: $hsName; ver: $versionStr; len: $recordLen")

        # ClientHello — show SNI and supported versions.
        if ($hsType -eq 1) {
            $sni = Get-TlsSni -Data $data
            if ($null -ne $sni) {
                $null = $parts.Add("SNI: $sni")
            }
        }
    } elseif ($script:TlsContentTypes.ContainsKey($contentType)) {
        $typeName = $script:TlsContentTypes[$contentType]
        $null = $parts.Add("TLS $typeName; ver: $versionStr; len: $recordLen")
    } else {
        $null = $parts.Add("TLS type $contentType; ver: $versionStr; len: $recordLen")
    }

    return $parts -join '; '
}

<#
.SYNOPSIS
Extracts the Server Name Indication (SNI) from a TLS ClientHello.

.PARAMETER Data
The raw TLS record bytes (starting at content type byte).
#>
function Get-TlsSni {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $Data
    )

    # TLS record: type(1) version(2) length(2) = 5 bytes
    # Handshake: type(1) length(3) = 4 bytes -> starts at offset 5
    # ClientHello: version(2) random(32) session_id_len(1) ...
    if ($Data.Count -lt 44) { return $null }

    $pos = 5 + 4  # past TLS record header + handshake header
    # Skip client version (2) + random (32).
    $pos += 34
    if ($pos -ge $Data.Count) { return $null }

    # Session ID.
    $sessionIdLen = [int]$Data[$pos]
    $pos += 1 + $sessionIdLen
    if ($pos + 2 -ge $Data.Count) { return $null }

    # Cipher suites.
    $cipherLen = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
    $pos += 2 + $cipherLen
    if ($pos + 1 -ge $Data.Count) { return $null }

    # Compression methods.
    $compLen = [int]$Data[$pos]
    $pos += 1 + $compLen
    if ($pos + 2 -ge $Data.Count) { return $null }

    # Extensions length.
    $extTotalLen = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
    $pos += 2
    $extEnd = $pos + $extTotalLen

    # Walk extensions looking for SNI (type 0x0000).
    while ($pos + 4 -le $extEnd -and $pos + 4 -le $Data.Count) {
        $extType = [PacketParseHelper]::ReadUInt16BE($Data, $pos)
        $extLen = [PacketParseHelper]::ReadUInt16BE($Data, $pos + 2)
        $pos += 4

        if ($extType -eq 0 -and $extLen -gt 0) {
            # SNI extension: list_length(2) type(1) name_length(2) name(...)
            if ($pos + 5 -le $Data.Count) {
                $nameLen = [PacketParseHelper]::ReadUInt16BE($Data, $pos + 3)
                $nameStart = $pos + 5
                if ($nameStart + $nameLen -le $Data.Count -and $nameLen -gt 0 -and $nameLen -lt 256) {
                    return [System.Text.Encoding]::ASCII.GetString($Data, $nameStart, $nameLen)
                }
            }
            return $null
        }

        $pos += $extLen
    }

    return $null
}

Export-ModuleMember -Function Test-HttpPacket, Test-TlsPacket, Format-HttpSegment, Format-TlsSegment, Format-HttpDetailed, Format-TlsDetailed
