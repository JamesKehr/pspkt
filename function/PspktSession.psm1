using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

[CmdletBinding()]
param ()

# --------------------------------------------------------------------------
# DNS QTYPE / RCODE name lookup tables (private helpers).
# Used by Start-Pspkt's -DnsType / -DnsRcode parameter resolution.
# --------------------------------------------------------------------------

# QTYPE names supported by the in-tree DnsParser. Names match the DnsParser.GetTypeName
# return values so users can reuse what they see on screen.
$script:DnsTypeNameToNumber = @{
    'A'      = 1
    'NS'     = 2
    'CNAME'  = 5
    'SOA'    = 6
    'PTR'    = 12
    'MX'     = 15
    'TXT'    = 16
    'AAAA'   = 28
    'SRV'    = 33
    'NAPTR'  = 35
    'OPT'    = 41
    'DS'     = 43
    'RRSIG'  = 46
    'NSEC'   = 47
    'DNSKEY' = 48
    'HTTPS'  = 65
    'ANY'    = 255
    'CAA'    = 257
}

$script:DnsRcodeNameToNumber = @{
    'NoError'  = 0
    'FormErr'  = 1
    'ServFail' = 2
    'NXDomain' = 3
    'NotImp'   = 4
    'Refused'  = 5
}

<#
.SYNOPSIS
Resolves a DNS QTYPE value supplied to -DnsType (name, integer, or hex string)
to its numeric QTYPE.

.OUTPUTS
System.Int32
#>
function Resolve-PspktDnsType {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "DnsType value cannot be empty."
    }

    # Hex prefix.
    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    # Plain integer.
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    # Name lookup (case-insensitive via uppercase key).
    $upper = $key.ToUpperInvariant()
    if ($script:DnsTypeNameToNumber.ContainsKey($upper)) {
        return [int]$script:DnsTypeNameToNumber[$upper]
    }
    throw "Unknown DNS QTYPE '$Value'. Use a name (A, AAAA, MX, SRV, HTTPS, PTR, CNAME, TXT, SOA, NS, ANY, CAA, OPT, NAPTR, DS, RRSIG, NSEC, DNSKEY), an integer (e.g. 1), or a hex string (e.g. 0x1c)."
}

<#
.SYNOPSIS
Resolves a DNS RCODE value supplied to -DnsRcode (name or integer) to its
numeric RCODE.

.OUTPUTS
System.Int32
#>
function Resolve-PspktDnsRcode {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "DnsRcode value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    # Case-insensitive name lookup.
    foreach ($name in $script:DnsRcodeNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [int]$script:DnsRcodeNameToNumber[$name]
        }
    }
    throw "Unknown DNS RCODE '$Value'. Use a name (NoError, FormErr, ServFail, NXDomain, NotImp, Refused) or an integer."
}

# --------------------------------------------------------------------------
# TLS version / content-type / handshake-type name lookup tables (private helpers).
# Used by Start-Pspkt's -TlsVersion / -TlsContentType / -TlsHandshakeType
# parameter resolution. Names mirror TlsParser.Get*Name output.
# --------------------------------------------------------------------------

# Versions: accept short forms ("1.2"), long forms ("TLS1.2", "TLS 1.2"), and
# numeric / hex inputs (770, 0x0303). Internally stored as the 16-bit wire value.
$script:TlsVersionNameToNumber = @{
    'SSL3.0' = 0x0300
    'TLS1.0' = 0x0301
    'TLS1.1' = 0x0302
    'TLS1.2' = 0x0303
    'TLS1.3' = 0x0304
    '1.0'    = 0x0301
    '1.1'    = 0x0302
    '1.2'    = 0x0303
    '1.3'    = 0x0304
}

$script:TlsContentTypeNameToNumber = @{
    'ChangeCipherSpec' = 20
    'Alert'            = 21
    'Handshake'        = 22
    'ApplicationData'  = 23
    'AppData'          = 23
}

$script:TlsHandshakeTypeNameToNumber = @{
    'HelloRequest'        = 0
    'ClientHello'         = 1
    'ServerHello'         = 2
    'NewSessionTicket'    = 4
    'EncryptedExtensions' = 8
    'Certificate'         = 11
    'ServerKeyExchange'   = 12
    'CertificateRequest'  = 13
    'ServerHelloDone'     = 14
    'CertificateVerify'   = 15
    'ClientKeyExchange'   = 16
    'Finished'            = 20
}

<#
.SYNOPSIS
Resolves a TLS version value supplied to -TlsVersion (e.g. '1.2', 'TLS1.2', '0x0303', 770).

.OUTPUTS
System.Int32
#>
function Resolve-PspktTlsVersion {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "TlsVersion value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    # Normalize: strip spaces, uppercase.
    $norm = ($key -replace '\s+', '').ToUpperInvariant()
    if ($script:TlsVersionNameToNumber.ContainsKey($norm)) {
        return [int]$script:TlsVersionNameToNumber[$norm]
    }
    throw "Unknown TLS version '$Value'. Use a short form ('1.0','1.1','1.2','1.3'), a long form ('TLS1.2','SSL3.0'), an integer (770), or a hex string ('0x0303')."
}

<#
.SYNOPSIS
Resolves a TLS content-type value supplied to -TlsContentType
('Handshake', 'Alert', 'ChangeCipherSpec', 'ApplicationData'/'AppData', integer 20-23).

.OUTPUTS
System.Int32
#>
function Resolve-PspktTlsContentType {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "TlsContentType value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    foreach ($name in $script:TlsContentTypeNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [int]$script:TlsContentTypeNameToNumber[$name]
        }
    }
    throw "Unknown TLS content type '$Value'. Use a name (ChangeCipherSpec, Alert, Handshake, ApplicationData/AppData) or an integer (20-23)."
}

<#
.SYNOPSIS
Resolves a TLS handshake-type value supplied to -TlsHandshakeType
('ClientHello', 'ServerHello', 'Certificate', 'Finished', etc., or integer).

.OUTPUTS
System.Int32
#>
function Resolve-PspktTlsHandshakeType {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "TlsHandshakeType value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    foreach ($name in $script:TlsHandshakeTypeNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [int]$script:TlsHandshakeTypeNameToNumber[$name]
        }
    }
    throw "Unknown TLS handshake type '$Value'. Use a name (ClientHello, ServerHello, Certificate, ServerKeyExchange, ServerHelloDone, ClientKeyExchange, CertificateVerify, CertificateRequest, EncryptedExtensions, NewSessionTicket, Finished, HelloRequest) or an integer."
}

# --------------------------------------------------------------------------
# HTTP method / status helpers used by Start-Pspkt's -HttpMethod / -HttpStatus.
# --------------------------------------------------------------------------

# Standard HTTP/1.1 methods (RFC 7231) plus PATCH (RFC 5789). Used only as a
# soft sanity-check for -HttpMethod values; non-standard methods are still
# accepted (uppercased) so users can filter on custom verbs (e.g. WebDAV).
$script:HttpStandardMethods = @{
    'GET'     = $true
    'POST'    = $true
    'PUT'     = $true
    'DELETE'  = $true
    'HEAD'    = $true
    'OPTIONS' = $true
    'PATCH'   = $true
    'CONNECT' = $true
    'TRACE'   = $true
}

<#
.SYNOPSIS
Normalises an HTTP method value supplied to -HttpMethod. Returns the uppercased
method name. Non-standard methods are accepted (no validation against the
known set) since users may need to filter on custom verbs.

.OUTPUTS
System.String
#>
function Resolve-PspktHttpMethod {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "HttpMethod value cannot be empty."
    }
    if ($key -match '\s') {
        throw "HttpMethod value cannot contain whitespace: '$Value'."
    }
    return $key.ToUpperInvariant()
}

<#
.SYNOPSIS
Resolves an HTTP status value supplied to -HttpStatus. Accepts exact codes
(200, 404), class patterns ('1xx'..'5xx'), or hex strings.

Returns a PSCustomObject with -Code (or 0 if class match) and -Class (1-5,
or 0 if exact-code match).

.OUTPUTS
PSCustomObject
#>
function Resolve-PspktHttpStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "HttpStatus value cannot be empty."
    }

    # Class pattern: "1xx", "2xx", ... "5xx" (case insensitive).
    if ($key -match '^([1-5])[xX][xX]$') {
        return [PSCustomObject]@{ Code = 0; Class = [int]$Matches[1] }
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [PSCustomObject]@{ Code = [Convert]::ToInt32($key.Substring(2), 16); Class = 0 }
    }

    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        if ($parsed -lt 100 -or $parsed -gt 599) {
            throw "HttpStatus '$Value' is out of range (100-599)."
        }
        return [PSCustomObject]@{ Code = $parsed; Class = 0 }
    }

    throw "Unknown HTTP status '$Value'. Use a 3-digit code (200, 404, 503), a class pattern ('2xx','4xx','5xx'), or a hex string."
}

# --------------------------------------------------------------------------
# DHCP message-type helpers used by Start-Pspkt's -DhcpMessageType.
# DHCPv4 and DHCPv6 use overlapping numeric spaces. A name unique to one
# family resolves to that family only; a name shared by both (e.g. "Request")
# resolves to both; an integer also resolves to both.
# --------------------------------------------------------------------------

# DHCPv4 message types (option 53 values).
$script:DhcpV4MessageTypeNameToNumber = @{
    'Discover' = 1
    'Offer'    = 2
    'Request'  = 3
    'Decline'  = 4
    'Ack'      = 5
    'Nak'      = 6
    'Release'  = 7
    'Inform'   = 8
}

# DHCPv6 message types (first payload byte).
$script:DhcpV6MessageTypeNameToNumber = @{
    'Solicit'             = 1
    'Advertise'           = 2
    'Request'             = 3
    'Confirm'             = 4
    'Renew'               = 5
    'Rebind'              = 6
    'Reply'               = 7
    'Release'             = 8
    'Decline'             = 9
    'Reconfigure'         = 10
    'Information-request' = 11
    'InformationRequest'  = 11
    'Relay-forward'       = 12
    'RelayForward'        = 12
    'Relay-reply'         = 13
    'RelayReply'          = 13
}

<#
.SYNOPSIS
Resolves a DHCP message-type value supplied to -DhcpMessageType. Returns a
PSCustomObject with -V4 and -V6 properties; each is null when the value
doesn't apply to that family or a numeric value when it does.

A name unique to one family (e.g. 'Discover') sets only that family's
property. A name shared by both (e.g. 'Request') sets both. An integer
or hex value sets both because the same number means different messages
in each family.

.OUTPUTS
PSCustomObject
#>
function Resolve-PspktDhcpMessageType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "DhcpMessageType value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        $n = [Convert]::ToInt32($key.Substring(2), 16)
        return [PSCustomObject]@{ V4 = $n; V6 = $n }
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return [PSCustomObject]@{ V4 = $parsed; V6 = $parsed }
    }

    $v4 = $null
    foreach ($name in $script:DhcpV4MessageTypeNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            $v4 = [int]$script:DhcpV4MessageTypeNameToNumber[$name]
            break
        }
    }
    $v6 = $null
    foreach ($name in $script:DhcpV6MessageTypeNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            $v6 = [int]$script:DhcpV6MessageTypeNameToNumber[$name]
            break
        }
    }
    if ($null -eq $v4 -and $null -eq $v6) {
        throw "Unknown DHCP message type '$Value'. Use a DHCPv4 name (Discover, Offer, Request, Decline, Ack, Nak, Release, Inform), a DHCPv6 name (Solicit, Advertise, Request, Confirm, Renew, Rebind, Reply, Release, Decline, Reconfigure, Information-request, Relay-forward, Relay-reply), or an integer / hex value."
    }
    return [PSCustomObject]@{ V4 = $v4; V6 = $v6 }
}

# --------------------------------------------------------------------------
# SMB2 helpers used by Start-Pspkt's -SmbCommand / -SmbStatus.
# --------------------------------------------------------------------------

# SMB2 command codes (per [MS-SMB2] section 2.2.1).
$script:Smb2CommandNameToNumber = @{
    'Negotiate'       = 0x00
    'SessionSetup'    = 0x01
    'Logoff'          = 0x02
    'TreeConnect'     = 0x03
    'TreeDisconnect'  = 0x04
    'Create'          = 0x05
    'Close'           = 0x06
    'Flush'           = 0x07
    'Read'            = 0x08
    'Write'           = 0x09
    'Lock'            = 0x0A
    'Ioctl'           = 0x0B
    'Cancel'          = 0x0C
    'Echo'            = 0x0D
    'QueryDirectory'  = 0x0E
    'ChangeNotify'    = 0x0F
    'QueryInfo'       = 0x10
    'SetInfo'         = 0x11
    'OplockBreak'     = 0x12
}

# Common NT status codes most useful as SMB2 filter values. Names match
# Smb2Parser.StatusNames; full list is too long for the resolver — users can
# always pass hex (0xC0000022) or integer values for codes not listed here.
$script:Smb2StatusNameToCode = @{
    'SUCCESS'                = 0x00000000
    'PENDING'                = 0x00000103
    'BUFFER_OVERFLOW'        = 0x80000005
    'NO_MORE_FILES'          = 0x80000006
    'UNSUCCESSFUL'           = 0xC0000001
    'NOT_IMPLEMENTED'        = 0xC0000002
    'INVALID_PARAMETER'      = 0xC000000D
    'NO_SUCH_FILE'           = 0xC000000F
    'END_OF_FILE'            = 0xC0000011
    'MORE_PROCESSING_REQUIRED' = 0xC0000016
    'ACCESS_DENIED'          = 0xC0000022
    'BUFFER_TOO_SMALL'       = 0xC0000023
    'OBJECT_NAME_INVALID'    = 0xC0000033
    'OBJECT_NAME_NOT_FOUND'  = 0xC0000034
    'OBJECT_NAME_COLLISION'  = 0xC0000035
    'OBJECT_PATH_NOT_FOUND'  = 0xC000003A
    'OBJECT_PATH_SYNTAX_BAD' = 0xC000003B
    'SHARING_VIOLATION'      = 0xC0000043
    'LOGON_FAILURE'          = 0xC000006D
    'FILE_IS_A_DIRECTORY'    = 0xC00000BA
    'NOT_SUPPORTED'          = 0xC00000BB
    'BAD_NETWORK_NAME'       = 0xC00000CC
    'NETWORK_ACCESS_DENIED'  = 0xC00000D5
    'DIRECTORY_NOT_EMPTY'    = 0xC0000101
    'CANCELLED'              = 0xC0000120
    'FILE_CLOSED'            = 0xC0000128
    'USER_SESSION_DELETED'   = 0xC0000203
    'CONNECTION_DISCONNECTED' = 0xC000020C
    'NETWORK_SESSION_EXPIRED' = 0xC000035C
}

# NT status code class names (top 2 bits of the 32-bit code).
$script:Smb2StatusClassNameToNumber = @{
    'Success'        = 0
    'Informational'  = 1
    'Info'           = 1
    'Warning'        = 2
    'Error'          = 3
}

<#
.SYNOPSIS
Resolves an SMB2 command value supplied to -SmbCommand (name, integer, or hex).

.OUTPUTS
System.Int32
#>
function Resolve-PspktSmb2Command {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "SmbCommand value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    foreach ($name in $script:Smb2CommandNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [int]$script:Smb2CommandNameToNumber[$name]
        }
    }
    throw "Unknown SMB2 command '$Value'. Use a name (Negotiate, SessionSetup, Logoff, TreeConnect, TreeDisconnect, Create, Close, Flush, Read, Write, Lock, Ioctl, Cancel, Echo, QueryDirectory, ChangeNotify, QueryInfo, SetInfo, OplockBreak) or an integer / hex value."
}

<#
.SYNOPSIS
Resolves an SMB2 status value supplied to -SmbStatus. Returns a PSCustomObject
with -Code (or 0 for a class match) and -Class (0-3 for class-only inputs,
-1 for exact-code inputs).

Accepts:
- Class names: 'Success', 'Informational' / 'Info', 'Warning', 'Error'
- Status names: 'ACCESS_DENIED', 'NO_SUCH_FILE', etc. (case-insensitive)
- Hex strings: '0xC0000022'
- Integers: 3221225506

.OUTPUTS
PSCustomObject
#>
function Resolve-PspktSmb2Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "SmbStatus value cannot be empty."
    }

    foreach ($name in $script:Smb2StatusClassNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [PSCustomObject]@{ Code = ([uint32]0); Class = [int]$script:Smb2StatusClassNameToNumber[$name] }
        }
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [PSCustomObject]@{ Code = [Convert]::ToUInt32($key.Substring(2), 16); Class = -1 }
    }
    $parsedUInt = [uint32]0
    if ([uint32]::TryParse($key, [ref]$parsedUInt)) {
        return [PSCustomObject]@{ Code = $parsedUInt; Class = -1 }
    }

    foreach ($name in $script:Smb2StatusNameToCode.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [PSCustomObject]@{ Code = [uint32]$script:Smb2StatusNameToCode[$name]; Class = -1 }
        }
    }

    throw "Unknown SMB2 status '$Value'. Use a class name (Success, Informational, Warning, Error), a status name (ACCESS_DENIED, NO_SUCH_FILE, OBJECT_NAME_NOT_FOUND, LOGON_FAILURE, SHARING_VIOLATION, BAD_NETWORK_NAME, NETWORK_ACCESS_DENIED, ...), or an integer / hex value."
}

# --------------------------------------------------------------------------
# ICMP / ICMPv6 type-name resolvers used by Start-Pspkt's -IcmpType /
# -Icmpv6Type. ICMPv4 uses the existing [ICMP4_TYPE] enum; ICMPv6 has its
# own (extensible) hashtable since the codebase doesn't define a v6 enum yet.
# --------------------------------------------------------------------------

# ICMPv6 type names — short and long forms accepted, case-insensitive on input.
# Sources: RFC 4443 (core), RFC 4861 (NDP), RFC 2710 (MLD).
$script:Icmpv6TypeNameToNumber = @{
    'DestinationUnreachable'   = 1
    'DestUnreach'              = 1
    'PacketTooBig'             = 2
    'TimeExceeded'             = 3
    'ParameterProblem'         = 4
    'EchoRequest'              = 128
    'EchoReply'                = 129
    'MulticastListenerQuery'   = 130
    'MulticastListenerReport'  = 131
    'MulticastListenerDone'    = 132
    'RouterSolicitation'       = 133
    'RouterSolicit'            = 133
    'RS'                       = 133
    'RouterAdvertisement'      = 134
    'RouterAdvert'             = 134
    'RA'                       = 134
    'NeighborSolicitation'     = 135
    'NeighborSolicit'          = 135
    'NS'                       = 135
    'NeighborAdvertisement'    = 136
    'NeighborAdvert'           = 136
    'NA'                       = 136
    'RedirectMessage'          = 137
    'Redirect'                 = 137
    'RouterRenumbering'        = 138
    'InverseND_Solicit'        = 141
    'InverseND_Advert'         = 142
    'MLDv2Report'              = 143
}

<#
.SYNOPSIS
Resolves an ICMPv4 type value supplied to -IcmpType. Accepts ICMP4_TYPE enum
names (full 'ICMP4_ECHO_REQUEST' or short 'EchoRequest' / 'ECHO_REQUEST'),
integers, or hex strings.

.OUTPUTS
System.Int32
#>
function Resolve-PspktIcmp4Type {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "IcmpType value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }

    # Match against ICMP4_TYPE enum names. Accept ICMP4_<NAME>, <NAME>, or the
    # CamelCase short form (EchoRequest <-> ICMP4_ECHO_REQUEST).
    $normalized = $key.ToUpperInvariant() -replace '[\s_-]', ''
    foreach ($name in [ICMP4_TYPE].GetEnumNames()) {
        $nameNoUnder = $name -replace '_', ''
        $shortNoUnder = ($name -replace '^ICMP4_', '') -replace '_', ''
        if ($normalized -eq $nameNoUnder.ToUpperInvariant() -or $normalized -eq $shortNoUnder.ToUpperInvariant()) {
            return [int][ICMP4_TYPE]::$name
        }
    }

    throw "Unknown ICMPv4 type '$Value'. Use an ICMP4_TYPE name (ICMP4_ECHO_REQUEST or EchoRequest, ICMP4_DST_UNREACH or DstUnreach, ICMP4_REDIRECT, ICMP4_TIME_EXCEEDED, ...), or an integer / hex value."
}

<#
.SYNOPSIS
Resolves an ICMPv6 type value supplied to -Icmpv6Type. Accepts long names
('NeighborSolicitation'), short names ('NS','NA','RA','RS','Redirect',
'EchoRequest', etc.), integers, or hex strings.

.OUTPUTS
System.Int32
#>
function Resolve-PspktIcmpv6Type {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $key = $Value.Trim()
    if ([string]::IsNullOrEmpty($key)) {
        throw "Icmpv6Type value cannot be empty."
    }

    if ($key -match '^0[xX][0-9A-Fa-f]+$') {
        return [Convert]::ToInt32($key.Substring(2), 16)
    }
    $parsed = 0
    if ([int]::TryParse($key, [ref]$parsed)) {
        return $parsed
    }
    foreach ($name in $script:Icmpv6TypeNameToNumber.Keys) {
        if ([string]::Equals($name, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [int]$script:Icmpv6TypeNameToNumber[$name]
        }
    }
    throw "Unknown ICMPv6 type '$Value'. Use a name (EchoRequest, EchoReply, RouterSolicitation/RS, RouterAdvertisement/RA, NeighborSolicitation/NS, NeighborAdvertisement/NA, Redirect, DestinationUnreachable, PacketTooBig, TimeExceeded, ParameterProblem, ...), or an integer / hex value."
}

# --------------------------------------------------------------------------
# Quick-filter coverage check used by application-layer predicate auto-imply.
# --------------------------------------------------------------------------

<#
.SYNOPSIS
Returns $true when at least one filter in $Filters already lets packets matching
(EtherType, TransportProtocol, Port) reach the consumer.

.DESCRIPTION
Used by Start-Pspkt's predicate auto-imply blocks to decide whether to add a
capture filter for the predicate's target protocol. A filter "covers" the target
when each of EtherType / TransportProtocol / Port1 is either unset on the
filter (meaning "no constraint") OR equal to the target value.

Pktmon's kernel-side filters OR-combine across the filter list, so as long as
one filter would let the target through, the auto-imply is redundant. When no
filter covers the target — for example combining -ARP (EtherType=ARP only)
with -Icmpv6Type (needs IPv6 ICMPv6) — the auto-imply must fire so the
predicate has packets to evaluate.

.PARAMETER Filters
The quick-filter ArrayList being assembled.

.PARAMETER EtherType
Target EtherType name (e.g. 'IPv4', 'IPv6') or empty string for "any".

.PARAMETER TransportProtocol
Target IPv4Protocol name (e.g. 'TCP', 'UDP', 'ICMP', 'IPv6_ICMP') or empty string for "any".

.PARAMETER Port
Target port number (1-65535) or 0 for "any".

.OUTPUTS
System.Boolean
#>
function Test-PspktQuickFilterCoverage {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Filters,

        [Parameter(Mandatory = $false)]
        [string]
        $EtherType = '',

        [Parameter(Mandatory = $false)]
        [string]
        $TransportProtocol = '',

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port = 0
    )

    if ($null -eq $Filters -or $Filters.Count -eq 0) { return $false }

    $expectedEt = if ([string]::IsNullOrEmpty($EtherType)) { [uint16]0 }
                  else { [uint16][ETHERTYPE]::$EtherType }
    $expectedTp = if ([string]::IsNullOrEmpty($TransportProtocol)) { [int16][IPv4Protocol]::ANY }
                  else { [int16][IPv4Protocol]::$TransportProtocol }
    $expectedPort = [uint16]$Port
    $anyTp = [int16][IPv4Protocol]::ANY

    foreach ($f in $Filters) {
        if ($null -eq $f) { continue }
        # Coverage relation: T ⊆ F. A filter F covers target T if every T-packet
        # satisfies F's constraints. So when F constrains an axis but T leaves
        # it open (= "any"), F EXCLUDES most T-packets and therefore does NOT
        # cover T — the early-skip below catches that case via the
        # `$expectedX -eq <unset>` clause. When both F and T constrain an axis,
        # they must agree.
        if ($f.EtherType -ne 0 -and ($expectedEt -eq 0 -or $f.EtherType -ne $expectedEt)) {
            continue
        }
        if ($f.TransportProtocol -ne $anyTp -and ($expectedTp -eq $anyTp -or $f.TransportProtocol -ne $expectedTp)) {
            continue
        }
        if ($f.Port1 -ne 0 -and ($expectedPort -eq 0 -or $f.Port1 -ne $expectedPort)) {
            continue
        }
        return $true
    }
    return $false
}

# --------------------------------------------------------------------------
# Hyper-V VM scoping helpers used by Start-Pspkt's -VM / -VMName parameters.
# --------------------------------------------------------------------------

<#
.SYNOPSIS
Returns the list of MAC addresses for a Hyper-V VM's vmNICs, including
VMs that are powered off, saved, or paused.

.DESCRIPTION
Used by Start-Pspkt to AND-combine each vmNIC MAC with every quick / app-
imply filter when -VM / -VMName is supplied. The Hyper-V cmdlets used
here read MACs directly from the VM configuration (not from pktmon), so
the lookup succeeds regardless of the VM's power state — Off, Saved,
Paused, Running, or Starting all work.

Layered fallbacks are attempted in order until one returns adapters:
    1. Get-VMNetworkAdapter -VM <obj> / -VMName <string>      (primary)
    2. <vmObject> | Get-VMNetworkAdapter                       (works when
       the parameter form fails due to remoting / cluster quirks; matches
       the canonical Hyper-V usage: Get-VM Foo | Get-VMNetworkAdapter |
       ForEach-Object MacAddress)
    3. <vmObject>.NetworkAdapters                              (last resort
       — read the property directly off the VM object)

When -VMName is supplied the function first resolves the name to a VM
object via Get-VM so fallbacks 2 and 3 are available.

Hyper-V returns '000000000000' for dynamic MACs that have never been
allocated (a brand-new VM that has never been started); those NICs are
skipped with a warning (suppress via -NoWarning) so callers don't add a
useless all-zeroes filter.

If the Hyper-V PowerShell module is not installed on the host the function
throws — pspkt cannot scope to a VM that the host cannot enumerate.

When neither -VM nor -VMName is supplied the function returns an empty
array.

.PARAMETER VM
Hyper-V VM object (from Get-VM).

.PARAMETER VMName
Hyper-V VM name string.

.PARAMETER NoWarning
Suppress the per-NIC "no assigned MAC" warning.

.OUTPUTS
System.String[]
#>
function Get-PspktVMMacList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [object]
        $VM,

        [Parameter(Mandatory = $false)]
        [string]
        $VMName,

        [Parameter(Mandatory = $false)]
        [switch]
        $NoWarning
    )

    $macs = [System.Collections.ArrayList]::new()

    # Early-out: caller didn't ask for VM scoping at all.
    if ($null -eq $VM -and [string]::IsNullOrEmpty($VMName)) {
        return @()
    }

    # Hyper-V module sanity check. Get-VMNetworkAdapter is the canonical
    # source for vmNIC MAC addresses across all VM power states.
    if (-not (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue)) {
        throw "The Hyper-V PowerShell module is not installed. Install RSAT-Hyper-V-Tools or enable the Hyper-V role to use -VM / -VMName."
    }

    # Resolve the VM object up front so the fallback chain can use it
    # regardless of whether the caller passed -VM or -VMName.
    $vmObj  = $null
    $label  = $null

    if ($null -ne $VM) {
        $vmObj = $VM
        $label = "$($VM.Name)"
    } else {
        $label = $VMName
        try {
            $vmObj = Get-VM -Name $VMName -ErrorAction Stop
        } catch {
            throw "Failed to resolve VM '$VMName' via Get-VM. Verify the VM name is spelled correctly and accessible to the current user."
        }
    }

    # Fallback chain. Each step is independent — we stop on the first one
    # that yields adapters (even adapters with all-zero MACs count: those
    # still tell us "the VM has a vmNIC, the MAC just isn't allocated").
    $adapters = $null

    # Step 1: parameter-form Get-VMNetworkAdapter.
    if ($null -ne $vmObj) {
        $adapters = Get-VMNetworkAdapter -VM $vmObj -ErrorAction SilentlyContinue
    }
    if (($null -eq $adapters -or @($adapters).Count -eq 0) -and -not [string]::IsNullOrEmpty($VMName)) {
        $adapters = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
    }

    # Step 2: pipeline form (matches the user-facing example
    # `Get-VM Foo | Get-VMNetworkAdapter | ForEach-Object MacAddress`).
    # Some remoting / cluster configurations surface adapters only via the
    # pipeline binder, so try that explicitly before giving up.
    if (($null -eq $adapters -or @($adapters).Count -eq 0) -and $null -ne $vmObj) {
        $adapters = $vmObj | Get-VMNetworkAdapter -ErrorAction SilentlyContinue
    }

    # Step 3: read the NetworkAdapters collection directly off the VM
    # object. Works even when the cmdlet path fails entirely (eg. partial
    # WMI namespace damage), provided the VM object is a real Hyper-V
    # VirtualMachine PSObject.
    if (($null -eq $adapters -or @($adapters).Count -eq 0) -and $null -ne $vmObj -and $null -ne $vmObj.NetworkAdapters) {
        $adapters = @($vmObj.NetworkAdapters)
    }

    if ($null -eq $adapters -or @($adapters).Count -eq 0) {
        if (-not $NoWarning.IsPresent) {
            Write-Warning "VM '$label' has no virtual network adapters discoverable via Get-VMNetworkAdapter. No per-NIC MAC filter will be applied."
        }
        return @()
    }

    foreach ($adapter in $adapters) {
        $rawMac = "$($adapter.MacAddress)"
        if ([string]::IsNullOrEmpty($rawMac) -or $rawMac -eq '000000000000') {
            if (-not $NoWarning.IsPresent) {
                Write-Warning "VM '$label' vmNIC '$($adapter.Name)' has no assigned MAC address (dynamic-MAC VM that has never been started?). Skipping per-NIC MAC filter."
            }
            continue
        }
        $macStr = $rawMac -replace '(.{2})(?=.)', '$1-'
        $null = $macs.Add($macStr)
    }

    return ,([string[]]$macs.ToArray())
}

<#
.SYNOPSIS
Returns a new pspktFilter that is a deep copy of the supplied filter.

.DESCRIPTION
Used by Start-Pspkt to expand quick / app-imply filters across each VM-NIC
MAC when -VM / -VMName is active. Pktmon filters OR-combine across the
session's filter list, so AND-combining the VM MAC scope with a quick
filter's protocol scope must happen inside a single filter object — which
in turn means we need a clone per (filter, MAC) pair instead of mutating the
original.

.PARAMETER Filter
The pspktFilter to clone.

.PARAMETER NameSuffix
Optional string appended to the clone's Name property for traceability
(e.g. '-VM-AA-BB-CC-DD-EE-FF').

.OUTPUTS
pspktFilter
#>
function Copy-PspktFilter {
    [CmdletBinding()]
    [OutputType([pspktFilter])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pspktFilter]
        $Filter,

        [Parameter(Mandatory = $false)]
        [string]
        $NameSuffix
    )

    $clone = [pspktFilter]::new()
    $clone.Name              = if ([string]::IsNullOrEmpty($NameSuffix)) { $Filter.Name } else { "$($Filter.Name)$NameSuffix" }
    if ($null -ne $Filter.Mac1) { $clone.Mac1 = [byte[]]$Filter.Mac1.Clone() }
    if ($null -ne $Filter.Mac2) { $clone.Mac2 = [byte[]]$Filter.Mac2.Clone() }
    $clone.VlanId            = $Filter.VlanId
    $clone.EtherType         = $Filter.EtherType
    $clone.DSCP              = $Filter.DSCP
    $clone.TransportProtocol = $Filter.TransportProtocol
    if ($null -ne $Filter.Ip1) { $clone.Ip1 = $Filter.Ip1 }
    if ($null -ne $Filter.Ip2) { $clone.Ip2 = $Filter.Ip2 }
    $clone.PrefixLength1     = $Filter.PrefixLength1
    $clone.PrefixLength2     = $Filter.PrefixLength2
    $clone.Port1             = $Filter.Port1
    $clone.Port2             = $Filter.Port2
    $clone.TCPFlags          = $Filter.TCPFlags
    $clone.VxLanPort         = $Filter.VxLanPort
    $clone.EncapType         = $Filter.EncapType
    return $clone
}

<#
.SYNOPSIS
Applies bound values to an existing pspktSession.

.DESCRIPTION
Internal helper used by Set-PspktSession.

.PARAMETER Session
Session object to update.
#>
function Update-PspktSessionInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [bool]
        $Active,

        [Parameter(Mandatory = $false)]
        [PspktCaptureType]
        $CaptureType,

        [Parameter(Mandatory = $false)]
        [PspktLogMode]
        $LogMode,

        [Parameter(Mandatory = $false)]
        [uint32]
        $EventFlags,

        [Parameter(Mandatory = $false)]
        [uint32]
        $PacketSize,

        [Parameter(Mandatory = $false)]
        [uint32]
        $FileSize,

        [Parameter(Mandatory = $false)]
        [string]
        $FileName,

        [Parameter(Mandatory = $false)]
        [bool]
        $CountersOnly
    )

    if ($PSBoundParameters.ContainsKey('Name')) {
        $Session.Name = $Name
    }

    if ($PSBoundParameters.ContainsKey('Active')) {
        $Session.SetSessionActive($Active)
    }

    if ($PSBoundParameters.ContainsKey('CaptureType')) {
        $Session.CaptureType = $CaptureType
    }

    if ($PSBoundParameters.ContainsKey('LogMode')) {
        $Session.LogMode = $LogMode
    }

    if ($PSBoundParameters.ContainsKey('EventFlags')) {
        $Session.EventFlags = $EventFlags
    }

    if ($PSBoundParameters.ContainsKey('PacketSize')) {
        $Session.PacketSize = $PacketSize
    }

    if ($PSBoundParameters.ContainsKey('FileSize')) {
        $Session.FileSize = $FileSize
    }

    if ($PSBoundParameters.ContainsKey('FileName')) {
        $Session.FileName = $FileName
    }

    if ($PSBoundParameters.ContainsKey('CountersOnly')) {
        $Session.CountersOnly = $CountersOnly
    }

    return $Session
}

<#
.SYNOPSIS
Creates a new live packet monitor session.

.DESCRIPTION
Initializes a pspkt instance, creates a live session, and returns it.
The pspkt instance is stored on the session for lifecycle management.
The caller is responsible for storing the returned session object.

.PARAMETER Name
Name for the new session.

.OUTPUTS
pspktSession
#>
function New-PspktSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
    )

    $pspktInstance = [pspkt]::new()
    $pspktInstance.PacketMonitorInitialize()

    $session = $pspktInstance.PacketMonitorCreateLiveSession($Name)
    $session.Pspkt = $pspktInstance

    return $session
}

<#
.SYNOPSIS
Gets the current packet monitor status.

.DESCRIPTION
Parses the output of 'pktmon status' to report whether pktmon is actively
capturing, what filters are configured, and what components are being monitored.
This detects any active pktmon session, including sessions not created by pspkt
or orphaned from a previous run.

.OUTPUTS
PSCustomObject with properties: Active, CaptureType, MonitoredComponents, Filters
#>
function Get-PspktSession {
    [CmdletBinding()]
    param()

    $statusOutput = pktmon status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "pktmon status failed with exit code $LASTEXITCODE"
    }

    $raw = $statusOutput | Out-String
    $lines = $raw -split "`r?`n"

    $captureType = $null
    $monitoredComponents = $null
    $filters = [System.Collections.ArrayList]::new()

    $section = 'header'
    $inFilterTable = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        # Parse "key:value" lines where value may be on the same line or the next
        if ($line -match '^\s*Capture Type:(.*)') {
            $val = $Matches[1].Trim()
            if ([string]::IsNullOrEmpty($val) -and ($i + 1) -lt $lines.Count) {
                $val = $lines[$i + 1].Trim()
                $i++
            }
            $captureType = $val
            continue
        }

        if ($line -match '^\s*Monitored Components:(.*)') {
            $val = $Matches[1].Trim()
            if ([string]::IsNullOrEmpty($val) -and ($i + 1) -lt $lines.Count) {
                $val = $lines[$i + 1].Trim()
                $i++
            }
            $monitoredComponents = $val
            continue
        }

        if ($line -match '^\s*Packet Filters:') {
            $inFilterTable = $true
            continue
        }

        if ($inFilterTable) {
            # Skip header and separator lines
            if ($line -match '^\s*#\s+Name' -or $line -match '^\s*-+\s+-+') {
                continue
            }

            # Parse filter rows: number followed by data columns
            if ($line -match '^\s*(\d+)\s+(.+)') {
                $parts = $line.Trim() -split '\s{2,}'
                $filterObj = [PSCustomObject]@{
                    Number     = $parts[0].Trim()
                    Name       = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
                    MACAddress = if ($parts.Count -gt 2) { $parts[2].Trim() } else { '' }
                    EtherType  = if ($parts.Count -gt 3) { $parts[3].Trim() } else { '' }
                    Protocol   = if ($parts.Count -gt 4) { $parts[4].Trim() } else { '' }
                }
                $null = $filters.Add($filterObj)
            }
        }
    }

    $isActive = -not [string]::IsNullOrEmpty($captureType)

    [PSCustomObject]@{
        Active              = $isActive
        CaptureType         = $captureType
        MonitoredComponents = $monitoredComponents
        Filters             = $filters
    }
}

<#
.SYNOPSIS
Updates an existing session.

.DESCRIPTION
Accepts a session via parameter or pipeline and applies bound values
including capture configuration (CaptureType, LogMode, PacketSize, etc.).

.PARAMETER Session
Session to update.

.PARAMETER Name
New name for the session.

.PARAMETER Active
Set session active state directly.

.PARAMETER CaptureType
Capture type: All, Flow, or Drop.

.PARAMETER LogMode
Logging mode: Circular, MultiFile, Memory, or RealTime.

.PARAMETER EventFlags
Event flags bitmask (0x032 default).

.PARAMETER PacketSize
Maximum bytes to log per packet. 0 means full packet.

.PARAMETER FileSize
Maximum log file size in MB.

.PARAMETER FileName
Log file name.

.PARAMETER CountersOnly
Capture counters only without packet logging.

.OUTPUTS
pspktSession
#>
function Set-PspktSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [bool]
        $Active,

        [Parameter(Mandatory = $false)]
        [PspktCaptureType]
        $CaptureType,

        [Parameter(Mandatory = $false)]
        [PspktLogMode]
        $LogMode,

        [Parameter(Mandatory = $false)]
        [uint32]
        $EventFlags,

        [Parameter(Mandatory = $false)]
        [uint32]
        $PacketSize,

        [Parameter(Mandatory = $false)]
        [uint32]
        $FileSize,

        [Parameter(Mandatory = $false)]
        [string]
        $FileName,

        [Parameter(Mandatory = $false)]
        [bool]
        $CountersOnly
    )

    process {
        Update-PspktSessionInternal @PSBoundParameters
    }
}

<#
.SYNOPSIS
Starts a real-time pktmon packet capture with parsed, color-coded console output and optional pcapng file write.

.DESCRIPTION
Start-Pspkt is the primary entry point for the pspkt module. It activates a pktmon session, starts the real-time
stream, and runs a high-throughput C# bulk-format loop that parses every packet (Ethernet, IPv4, IPv6, TCP, UDP,
ICMP, ICMPv6, NDP, ARP, DNS, DHCP, HTTP, TLS, SMB2) and writes colored output to the console.

Press Ctrl+C to stop the capture. When the -Pause switch is set, press 'p' to pause / 'r' to resume / 'q' to quit
while paused.

Recent (post-perf) behavior:
* All real-time formatting happens in C# (no per-packet PowerShell). The producer is a native pktmon callback that
  enqueues into a lock-free SPSC ring buffer; the consumer is a single PS loop that drains the ring and writes a
  batched colored string to the console.
* Packet byte[] arrays are pooled when no file writer is attached (zero-allocation receive on the callback thread).
* The pcapng writer always runs in async mode on a dedicated writer thread — file I/O never blocks the pktmon
  callback. -FlushDisk only controls whether the writer flushes after every batch (durability) or only at stop
  (throughput).
* -FileSize + -NumFiles together enable pcapng file rotation (foo.001.pcapng -> foo.002.pcapng -> ... -> wrap).
  Rotation is no longer tied to -FlushDisk.
* -BufferSizeMultiplier scales both the pktmon driver buffer AND the user-mode SPSC ring (base 1M entries x N).

Quick filters (-DNS, -SMB, -Ping, etc.) create one or more pktmon capture filters automatically. When combined
with -IPAddress, the IP is AND-merged into every quick filter (so `-DNS -i 1.1.1.1` becomes "DNS to/from 1.1.1.1"
rather than "DNS OR 1.1.1.1"). With -VM/-VMName, every quick filter and every application-layer auto-imply
filter is also AND-combined with each vmNIC MAC (one filter per quick-filter x vmNIC pair) so all capture is
constrained to the VM's network data path — for example `pspkt -VM <vm> -SmbCommand Create` only matches SMB
packets traversing the VM's vmNICs. When -VM/-VMName is used alone (no quick filter, no app-layer predicate),
a standalone MAC filter per vmNIC is added so all VM traffic is captured.

.PARAMETER Session
A pre-configured pspktSession (from New-PspktSession). Accepts pipeline input. Mutually exclusive with -Name /
-CaptureType / -PacketSize: when -Session is supplied, those properties are taken from the session.

.PARAMETER Name
Name for the auto-created session when -Session is not supplied. Default 'pspkt'.

.PARAMETER CaptureType
Capture scope: All (flow + drop), Flow (successful only), or Drop (drops only). Default All.

.PARAMETER PacketSize
Max bytes captured per packet (driver-side truncation). 0 = full packet. Default 128.
Quick filters that need more payload (e.g. -DNS bumps to 512, -DHCP bumps to 590) auto-increase this if you
haven't set it explicitly.

.PARAMETER BufferSizeMultiplier
Multiplier applied to both the pktmon driver-side buffer AND the user-mode SPSC ring buffer (base 1,048,576
entries). Higher values reduce drops during traffic bursts at the cost of memory. Range 1-65535, default 4.
Effective ring capacity is clamped to a 64M-entry maximum.

.PARAMETER TruncationSize
Stream-level packet truncation in bytes. 0 (default) means derive from PacketSize.

.PARAMETER PollingIntervalMs
Upper bound (in ms) on the consumer wait when no packets are available. Range 10-5000, default 50.
With AutoResetEvent signaling from the producer, the consumer wakes immediately on the first packet — this value
is now a timeout safety net, not the steady-state polling interval.

.PARAMETER ParsingLevel
Display detail level. Alias: -pl.
* Minimal — single-line port/protocol summary
* Default — packet header summary (link/network/transport/app)
* Detailed — multi-line per-layer breakdown
* VeryDetailed — Detailed plus blank line between packets

.PARAMETER Component
Components to capture from. Alias: -comp.
* 'All' (default) — all NIC, protocol, and driver components
* 'NICs' — NIC components only
* Comma-separated numeric IDs (e.g. -comp 1,5,33) — specific component IDs

.PARAMETER VM
Hyper-V VM object (from Get-VM) whose virtual network data path should be captured. Overrides -Component.
Every quick filter and application-layer auto-imply filter is AND-combined with each vmNIC MAC, so all
capture is constrained to the VM's traffic. When used alone (no quick filter or predicate), a standalone
MAC filter per vmNIC is added instead.

.PARAMETER VMName
Hyper-V VM name (string). Same behavior as -VM: every quick / app-imply filter is AND-combined with each
vmNIC MAC. Overrides -Component.

.PARAMETER IPAddress
Quick IP filter. Alias: -i. Accepts an IPv4 or IPv6 address string. When supplied alongside quick filters or
-VM/-VMName, the IP is AND-merged into each generated filter (single-filter combined match). With
-VM/-VMName + quick filter, the result is MAC AND IP AND protocol within each expanded filter. When supplied
alone, creates a standalone IP filter.

.PARAMETER Spaced
Adds a blank line between each formatted packet line on the console.

.PARAMETER Timestamp
Prefixes each line with the high-resolution local timestamp (yyyy-MM-dd HH:mm:ss.fffffff). Alias: -t.

.PARAMETER ARP
Quick filter: EtherType ARP.

.PARAMETER NDP
Quick filter: IPv6 ICMPv6. Post-capture filtered to NDP types 133-137 only (Router Sol/Adv,
Neighbor Sol/Adv, Redirect). Other ICMPv6 types are dropped on the producer thread before
they reach the ring buffer, so they appear in neither console output nor pcapng output.

.PARAMETER AA
Quick filter: auto-address protocols (NDP + DHCP + DHCPv6). NDP packets are post-capture
filtered to types 133-137 only.

.PARAMETER AAv4
Quick filter: IPv4 auto-address (DHCP only).

.PARAMETER AAv6
Quick filter: IPv6 auto-address (NDP + DHCPv6). NDP packets are post-capture filtered to
types 133-137 only.

.PARAMETER DHCP
Quick filter: UDP/IPv4 ports 67+68.

.PARAMETER DHCPv6
Quick filter: UDP/IPv6 ports 546+547.

.PARAMETER DNS
Quick filter: TCP+UDP port 53.

.PARAMETER DNSoverHTTPS
Quick filter: TCP port 443. Alias: -DoH.

.PARAMETER DNSoverTLS
Quick filter: TCP port 853. Alias: -DoT.

.PARAMETER SMB
Quick filter: TCP ports 445 (SMB) + 88 (Kerberos).

.PARAMETER SMBoverQUIC
Quick filter: UDP port 443 (or -SMBoverQuicAltPort). Alias: -SoQ.

.PARAMETER SMBoverQuicAltPort
Alternate UDP port for SMB-over-QUIC. Only meaningful with -SMBoverQUIC.

.PARAMETER SSH
Quick filter: TCP port 22.

.PARAMETER RDP
Quick filter: TCP port 3389.

.PARAMETER RPC
Quick filter: TCP port 135.

.PARAMETER RCP
Quick filter: TCP+UDP port 3343 (Cluster RCP).

.PARAMETER HTTP
Quick filter: TCP port 80.

.PARAMETER HTTPS
Quick filter: TCP port 443.

.PARAMETER WinRM
Quick filter: TCP port 5985.

.PARAMETER WinRMS
Quick filter: TCP port 5986.

.PARAMETER Ping
Quick filter: ICMPv4 + ICMPv6. Post-capture filtered to echo types only (ICMPv4 0/8,
ICMPv6 128/129). Non-echo ICMP packets are dropped on the producer thread before they
reach the ring buffer, so they appear in neither console output nor pcapng output.

.PARAMETER Ping4
Quick filter: ICMPv4 only, post-capture filtered to echo types (0/8) only.

.PARAMETER Ping6
Quick filter: ICMPv6 only, post-capture filtered to echo types (128/129) only.

.PARAMETER Pause
Enables interactive pause/resume: press 'p' to pause, 'r' to resume, 'q' to quit.

.PARAMETER PauseOnDrop
Auto-pause when any pktmon DROP is detected. Alias: -pod.

.PARAMETER PauseOnLocation
Auto-pause when a DROP with matching location is detected. Accepts enum name, integer, or hex string. Alias: -pol.

.PARAMETER PauseOnReason
Auto-pause when a DROP with matching reason is detected. Accepts enum name, integer, or hex string. Alias: -por.

.PARAMETER StopOnDrop
Stop capture when any pktmon DROP is detected. Alias: -sod.

.PARAMETER StopOnLocation
Stop capture when a DROP with matching location is detected. Alias: -sol.

.PARAMETER StopOnReason
Stop capture when a DROP with matching reason is detected. Alias: -sor.

.PARAMETER StopDelay
Milliseconds (uint32) to keep capturing after a stop trigger (-StopOnDrop / -StopOnReason /
-StopOnLocation) fires. 0 (default) stops immediately. Real-time console output and the
pcapng writer both continue during the delay window. Subsequent stop triggers are
suppressed so the deadline isn't reset; pause triggers remain active.

.PARAMETER WriteFile
Path to a pcapng file to write captured packets to. Alias: -w. The .pcapng extension is appended automatically
if missing. Writing always runs in async mode (writer thread + ring buffer) so file I/O does not block the
pktmon callback thread.

.PARAMETER RealTime
When -WriteFile is set, also write live colored output to the console. Alias: -rt. Without this switch, file
writes silently with a single status line (unless quick filters are active, which implicitly enable real-time).

.PARAMETER FileSize
Max bytes per pcapng file in MiB before rotating. Range 1-65535, default 512. Effective only with -NumFiles
greater than 1.

.PARAMETER FlushDisk
Flushes the pcapng BinaryWriter after every drained batch (durability mode). Without this switch, the writer
flushes only at session stop (throughput mode). Alias: -fd. Note: this switch no longer controls writer mode;
the writer is always async.

.PARAMETER NumFiles
Number of files in the rotation. When greater than 1, enables circular pcapng rotation: foo.001.pcapng ->
foo.002.pcapng -> ... -> foo.NNN.pcapng -> back to foo.001.pcapng (overwrite). Range 2-100. Default 2.

.PARAMETER WriteEtl
Path to an ETL file to write via the pktmon CLI native writer. Alias: -etl. Mutually exclusive with -WriteFile
and -RealTime.

.PARAMETER DumpInterfaces
Switch. Alias: -D. Prints the list of NIC components (Id + Name only) and exits without starting a capture.
Wrapper for `Get-PspktComponent -NIC | Select-Object Id, Name | Format-Table`.

.PARAMETER DnsName
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against the first
DNS question QNAME (without trailing dot). Multiple values are OR-combined. Implies the -DNS quick filter so
DNS packets actually reach the consumer. Setting any -Dns* parameter auto-bumps -ParsingLevel to Detailed
(with a warning) and -PacketSize to at least 1500 bytes (with a warning).
See wiki/Application-Filters-DNS.md.

.PARAMETER DnsType
Application-layer display filter (Detailed+). QTYPE filter. Accepts type names ('A', 'AAAA', 'CNAME', 'MX',
'SRV', 'TXT', 'SOA', 'NS', 'PTR', 'HTTPS', 'ANY', 'CAA', 'OPT', 'NAPTR', 'DS', 'RRSIG', 'NSEC', 'DNSKEY'),
integers (1, 28, 15), or hex strings ('0x1c'). Multiple values are OR-combined.

.PARAMETER DnsRcode
Application-layer display filter (Detailed+). DNS RCODE filter on responses. Accepts rcode names
('NoError', 'FormErr', 'ServFail', 'NXDomain', 'NotImp', 'Refused') or integers. Multiple values are
OR-combined. Queries are unaffected by this filter; only responses (QR=1) are tested.

.PARAMETER DnsId
Application-layer display filter (Detailed+). DNS transaction ID(s). Multiple values are OR-combined.

.PARAMETER DnsQR
Application-layer display filter (Detailed+). Restrict to 'Query', 'Response', or 'Any' (default).

.PARAMETER DnsMatchTruncated
Application-layer display filter (Detailed+). When set, packets whose DNS parse couldn't be completed
(header missing, or name truncated mid-label by -PacketSize) match the predicate anyway. Default is to
drop truncated packets so partial-match false negatives don't surprise the user.

.PARAMETER TlsSni
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against the
ClientHello SNI. Multiple values are OR-combined. Implies the `-HTTPS` quick filter (TCP 443) when no
other TCP quick filter is set. SNI filtering only matches ClientHello records — non-ClientHello traffic
is rejected. See wiki/Application-Filters-TLS.md.

.PARAMETER TlsVersion
Application-layer display filter (Detailed+). TLS record version filter. Accepts short forms ('1.0',
'1.1', '1.2', '1.3'), long forms ('TLS1.2', 'SSL3.0'), integers (770), or hex strings ('0x0303').
Multiple values are OR-combined.

.PARAMETER TlsContentType
Application-layer display filter (Detailed+). TLS record content type. Accepts names
('ChangeCipherSpec', 'Alert', 'Handshake', 'ApplicationData'/'AppData') or integers (20-23). Multiple
values are OR-combined.

.PARAMETER TlsHandshakeType
Application-layer display filter (Detailed+). TLS handshake message type. Accepts names ('ClientHello',
'ServerHello', 'Certificate', 'Finished', 'ServerKeyExchange', 'ClientKeyExchange', 'CertificateVerify',
'CertificateRequest', 'EncryptedExtensions', 'NewSessionTicket', 'ServerHelloDone', 'HelloRequest') or
integers. Multiple values are OR-combined. Implicitly restricts to Handshake records.

.PARAMETER TlsMatchTruncated
Application-layer display filter (Detailed+). When set, ClientHello records whose SNI extension couldn't
be reached because the packet was truncated still match the SNI filter. Default is to drop truncated
records.

.PARAMETER HttpMethod
Application-layer display filter (Detailed+). HTTP method (request side). Accepts standard names
('GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH','CONNECT','TRACE') or any custom verb.
Case-insensitive on input. Multiple values are OR-combined. Implies request-only matching.
See wiki/Application-Filters-HTTP.md.

.PARAMETER HttpPath
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against the
request path (URI + optional query string). Multiple values are OR-combined. Implies request-only matching.

.PARAMETER HttpHost
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against the
request Host: header. Multiple values are OR-combined. Implies request-only matching.

.PARAMETER HttpStatus
Application-layer display filter (Detailed+). HTTP response status filter. Accepts exact codes (200, 404,
503), class patterns ('1xx','2xx','3xx','4xx','5xx'), or hex strings. Multiple values are OR-combined.
Implies response-only matching.

.PARAMETER HttpContentType
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against the
Content-Type: header on either side. Multiple values are OR-combined.

.PARAMETER HttpMatchTruncated
Application-layer display filter (Detailed+). When set, packets whose HTTP header section couldn't be
reached because the packet was truncated still match. Default is to drop truncated packets so partial-
match false negatives don't surprise the user.

.PARAMETER DhcpMessageType
Application-layer display filter (Detailed+). DHCP message-type filter. Accepts DHCPv4 names
('Discover','Offer','Request','Decline','Ack','Nak','Release','Inform'), DHCPv6 names ('Solicit',
'Advertise','Request','Confirm','Renew','Rebind','Reply','Release','Decline','Reconfigure',
'Information-request','Relay-forward','Relay-reply'), or integers / hex. Names unique to one family
resolve to that family only; names shared by both families ('Request') and numeric values apply to
both. Multiple values are OR-combined. See wiki/Application-Filters-DHCP.md.

.PARAMETER DhcpClientMac
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against the
DHCPv4 client hardware address (chaddr) in canonical aa-bb-cc-dd-ee-ff form. Multiple values are
OR-combined. DHCPv6 packets are always rejected when this is set (v1 doesn't decode DHCPv6 DUIDs).

.PARAMETER DhcpFamily
Application-layer display filter (Detailed+). Restrict to one address family. 'V4' = DHCPv4 (ports
67/68) only, 'V6' = DHCPv6 (ports 546/547) only, 'Any' (default) = either.

.PARAMETER DhcpMatchTruncated
Application-layer display filter (Detailed+). When set, DHCPv4 packets whose option block couldn't
be walked to reach option-53 (typically because -PacketSize cut the payload mid-options) still match
the predicate. Default is to drop truncated packets so a partial-match false negative isn't silent.

.PARAMETER SmbCommand
Application-layer display filter (Detailed+). SMB2 command filter. Accepts names ('Negotiate',
'SessionSetup','Logoff','TreeConnect','TreeDisconnect','Create','Close','Flush','Read','Write','Lock',
'Ioctl','Cancel','Echo','QueryDirectory','ChangeNotify','QueryInfo','SetInfo','OplockBreak') or
integers (0-18). Multiple values are OR-combined. See wiki/Application-Filters-SMB2.md.

.PARAMETER SmbDirection
Application-layer display filter (Detailed+). Restrict to 'Request', 'Response', or 'Any' (default).

.PARAMETER SmbStatus
Application-layer display filter (Detailed+). NT status filter. Accepts class names ('Success',
'Informational','Info','Warning','Error'), exact status names ('ACCESS_DENIED','NO_SUCH_FILE',
'OBJECT_NAME_NOT_FOUND','LOGON_FAILURE','SHARING_VIOLATION', etc.), hex strings ('0xC0000022'), or
integers. Multiple values are OR-combined.

.PARAMETER SmbFilename
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against
the SMB2 Create request filename. Multiple values are OR-combined. Implies request-only and
Create-only matching.

.PARAMETER SmbTreePath
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against
the SMB2 TreeConnect request share path. Multiple values are OR-combined. Implies request-only and
TreeConnect-only matching.

.PARAMETER SmbMatchEncrypted
Application-layer display filter (Detailed+). When set, encrypted (SMB2 Transform header) packets
match even when other filter fields are configured. Default is to drop encrypted packets as soon as
any command/status/filename/tree-path filter is set.

.PARAMETER SmbMatchTruncated
Application-layer display filter (Detailed+). When set, packets whose per-command body extraction
(filename / tree path) couldn't be reached because -PacketSize truncated the payload still match.
Default is to drop truncated packets so a partial-match false negative isn't silent.

.PARAMETER IcmpType
Application-layer display filter (Detailed+). IPv4 ICMP type filter. Accepts ICMP4_TYPE names
(full 'ICMP4_ECHO_REQUEST' or short 'EchoRequest'), integers (0-255), or hex strings (0x08).
Multiple values are OR-combined. Implicitly v4-only — IPv6 packets are rejected unless -Icmpv6Type
or -Icmpv6NdpTarget is also set. Non-ICMP packets are unaffected by the predicate.
See wiki/Application-Filters-ICMP.md.

.PARAMETER Icmpv6Type
Application-layer display filter (Detailed+). ICMPv6 type filter. Accepts names
('NeighborSolicitation'/'NS', 'NeighborAdvertisement'/'NA', 'RouterSolicitation'/'RS',
'RouterAdvertisement'/'RA', 'Redirect', 'EchoRequest', 'EchoReply', 'DestinationUnreachable',
'PacketTooBig', 'TimeExceeded', 'ParameterProblem', 'MulticastListenerQuery', ...), integers, or
hex strings. Multiple values are OR-combined. Implicitly v6-only — IPv4 packets are rejected
unless -IcmpType is also set. Non-ICMP packets are unaffected.

.PARAMETER Icmpv6NdpTarget
Application-layer display filter (Detailed+). Regex pattern(s) matched case-insensitively against
the NDP target address (canonical IPv6 form) on Neighbor Solicitation (135) and Neighbor
Advertisement (136) packets. Multiple values are OR-combined. Rejects every non-NS/NA packet
(including IPv4 ICMP, RA, RS, Redirect).

.PARAMETER NoWarning
Suppresses non-fatal setup warnings such as the -ParsingLevel / -PacketSize auto-bumps triggered by
application-layer filters, the "VM vmNIC has no MAC" skip notice, and the "ignoring non-numeric component
value" notice. Does NOT suppress operational warnings about pcapng data loss or writer errors — those
indicate actual data loss and always fire. For full suppression of every Write-Warning use the standard
PowerShell -WarningAction SilentlyContinue.

.OUTPUTS
None. Output is streamed to the console in real time. When -WriteFile or -WriteEtl is set, the corresponding
file path and packet count are reported on stop.

.EXAMPLE
PS> pspkt
Capture all packets on all components with default formatting until Ctrl+C.

.EXAMPLE
PS> pspkt -DNS -i 1.1.1.1
Capture DNS traffic to/from 1.1.1.1 (filters AND-combine).

.EXAMPLE
PS> pspkt -VMName 'Win11-Dev' -SMB
Capture SMB (port 445 + Kerberos 88) constrained to the named VM's vmNIC MAC addresses.

.EXAMPLE
PS> pspkt -Ping -Pause -PauseOnReason 'INET_EndpointNotFound'
Capture ICMP and auto-pause when a packet is dropped with the INET_EndpointNotFound reason.

.EXAMPLE
PS> pspkt -WriteFile capture.pcapng -FileSize 100 -NumFiles 5
Write rotating pcapng files of 100 MiB each, cycling through capture.001.pcapng .. capture.005.pcapng.

.EXAMPLE
PS> pspkt -pl Detailed -t
Capture all traffic with detailed per-layer output and high-resolution timestamps.

.EXAMPLE
PS> pspkt -D
Print the NIC component table (Id + Name) without starting a capture.

.EXAMPLE
PS> pspkt -DnsName '\.contoso\.com$' -DnsType AAAA -DnsQR Query
DNS application-layer filter: show only AAAA queries for *.contoso.com names. Auto-bumps -ParsingLevel
to Detailed and -PacketSize to 1500. See wiki/Application-Filters-DNS.md for the full reference.

.EXAMPLE
PS> pspkt -TlsSni '\.contoso\.com$'
TLS application-layer filter: show only ClientHello records for any subdomain of contoso.com.
Auto-bumps -ParsingLevel to Detailed, -PacketSize to 2048, and implies -HTTPS (TCP 443).
See wiki/Application-Filters-TLS.md for the full reference.

.EXAMPLE
PS> pspkt -HttpMethod GET,POST -HttpPath '^/api/'
HTTP application-layer filter: show only GET/POST requests to paths under /api/. Auto-bumps
-ParsingLevel to Detailed, -PacketSize to 2048, and implies -HTTP (TCP 80).
See wiki/Application-Filters-HTTP.md for the full reference.

.EXAMPLE
PS> pspkt -DhcpMessageType Discover,Offer,Ack -DhcpClientMac '^aa-bb-cc'
DHCP application-layer filter: show only v4 Discover/Offer/Ack messages from the matching MAC.
Auto-bumps -ParsingLevel to Detailed, -PacketSize to 590, and implies the -DHCP / -DHCPv6 quick
filters when no other capture filter is set. See wiki/Application-Filters-DHCP.md.

.EXAMPLE
PS> pspkt -SmbCommand Create -SmbFilename '\.docx?$'
SMB2 application-layer filter: show only Create requests for .doc/.docx files. Auto-bumps
-ParsingLevel to Detailed, -PacketSize to 1500, and implies -SMB (TCP 445) when no other capture
filter is set. See wiki/Application-Filters-SMB2.md.

.EXAMPLE
PS> pspkt -IcmpType EchoRequest -Icmpv6Type EchoRequest
ICMP application-layer filter: show only echo requests on both IPv4 and IPv6. Auto-bumps
-ParsingLevel to Detailed and implies both ICMPv4 and ICMPv6 capture filters when no other
capture filter is set. See wiki/Application-Filters-ICMP.md.
#>
function Start-Pspkt {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'WithSession', Position = 0)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name = 'pspkt',

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [PspktCaptureType]
        $CaptureType = [PspktCaptureType]::All,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [uint32]
        $PacketSize = 128,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [uint16]
        $BufferSizeMultiplier = 4,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 65535)]
        [uint16]
        $TruncationSize = 0,

        [Parameter(Mandatory = $false)]
        [ValidateRange(10, 5000)]
        [int]
        $PollingIntervalMs = 50,

        [Parameter(Mandatory = $false)]
        [Alias('pl')]
        [PspktParsingLevel]
        $ParsingLevel = [PspktParsingLevel]::Default,

        [Parameter(Mandatory = $false)]
        [Alias('comp')]
        [string[]]
        $Component = @('All'),

        [Parameter(Mandatory = $false)]
        [object]
        $VM,

        [Parameter(Mandatory = $false)]
        [string]
        $VMName,

        [Parameter(Mandatory = $false)]
        [Alias('i')]
        [string]
        $IPAddress,

        [Parameter(Mandatory = $false)]
        [switch]
        $Spaced,

        [Parameter(Mandatory = $false)]
        [Alias('t')]
        [switch]
        $Timestamp,

        # Quick filters — switch parameters that auto-create common capture filters.
        [Parameter(Mandatory = $false)]
        [switch]
        $ARP,

        [Parameter(Mandatory = $false)]
        [switch]
        $NDP,

        [Parameter(Mandatory = $false)]
        [switch]
        $AA,

        [Parameter(Mandatory = $false)]
        [switch]
        $AAv4,

        [Parameter(Mandatory = $false)]
        [switch]
        $AAv6,

        [Parameter(Mandatory = $false)]
        [switch]
        $DHCP,

        [Parameter(Mandatory = $false)]
        [switch]
        $DHCPv6,

        [Parameter(Mandatory = $false)]
        [switch]
        $DNS,

        [Parameter(Mandatory = $false)]
        [Alias('DoH')]
        [switch]
        $DNSoverHTTPS,

        [Parameter(Mandatory = $false)]
        [Alias('DoT')]
        [switch]
        $DNSoverTLS,

        [Parameter(Mandatory = $false)]
        [switch]
        $SMB,

        [Parameter(Mandatory = $false)]
        [Alias('SoQ')]
        [switch]
        $SMBoverQUIC,

        [Parameter(Mandatory = $false)]
        [uint16]
        $SMBoverQuicAltPort,

        [Parameter(Mandatory = $false)]
        [switch]
        $SSH,

        [Parameter(Mandatory = $false)]
        [switch]
        $RDP,

        [Parameter(Mandatory = $false)]
        [switch]
        $RPC,

        [Parameter(Mandatory = $false)]
        [switch]
        $RCP,

        [Parameter(Mandatory = $false)]
        [switch]
        $HTTP,

        [Parameter(Mandatory = $false)]
        [switch]
        $HTTPS,

        [Parameter(Mandatory = $false)]
        [switch]
        $WinRM,

        [Parameter(Mandatory = $false)]
        [switch]
        $WinRMS,

        [Parameter(Mandatory = $false)]
        [switch]
        $Ping,

        [Parameter(Mandatory = $false)]
        [switch]
        $Ping4,

        [Parameter(Mandatory = $false)]
        [switch]
        $Ping6,

        # Pause control — enables 'p' to pause / 'r' to resume during capture.
        [Parameter(Mandatory = $false)]
        [switch]
        $Pause,

        # Auto-pause when any pktmon DROP is detected.
        [Parameter(Mandatory = $false)]
        [Alias('pod')]
        [switch]
        $PauseOnDrop,

        # Auto-pause when a DROP with matching location is detected.
        [Parameter(Mandatory = $false)]
        [Alias('pol')]
        [string]
        $PauseOnLocation,

        # Auto-pause when a DROP with matching reason is detected.
        [Parameter(Mandatory = $false)]
        [Alias('por')]
        [string]
        $PauseOnReason,

        # Stop capture when any pktmon DROP is detected.
        [Parameter(Mandatory = $false)]
        [Alias('sod')]
        [switch]
        $StopOnDrop,

        # Stop capture when a DROP with matching location is detected.
        [Parameter(Mandatory = $false)]
        [Alias('sol')]
        [string]
        $StopOnLocation,

        # Stop capture when a DROP with matching reason is detected.
        [Parameter(Mandatory = $false)]
        [Alias('sor')]
        [string]
        $StopOnReason,

        # Milliseconds to keep capturing after a stop trigger fires (StopOnDrop / StopOnReason
        # / StopOnLocation). 0 (default) = stop immediately. Real-time console output and the
        # pcapng writer both continue during the delay window; subsequent stop triggers are
        # suppressed so the deadline isn't reset. Pause triggers remain active.
        [Parameter(Mandatory = $false)]
        [uint32]
        $StopDelay = 0,

        # Write captured packets to an ETL file.
        [Parameter(Mandatory = $false)]
        [Alias('w')]
        [string]
        $WriteFile,

        # Enable real-time console output alongside file write.
        [Parameter(Mandatory = $false)]
        [Alias('rt')]
        [switch]
        $RealTime,

        # Maximum capture file size in MiB (default 512). File wraps circularly when exceeded.
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [uint32]
        $FileSize = 512,

        # Enable continuous flush-to-disk mode (default is write-on-stop).
        [Parameter(Mandatory = $false)]
        [Alias('fd')]
        [switch]
        $FlushDisk,

        # Number of chained files for FlushDisk mode (min/default 2). Only valid with -FlushDisk.
        [Parameter(Mandatory = $false)]
        [ValidateRange(2, 100)]
        [int]
        $NumFiles = 2,

        # Write to ETL file using pktmon CLI. Cannot be used with real-time capture.
        [Parameter(Mandatory = $false)]
        [Alias('etl')]
        [string]
        $WriteEtl,

        # Dump the list of NIC components and exit — wrapper for Get-PspktComponent -NIC.
        # Outputs a table of just Id and Name. No capture is started.
        [Parameter(Mandatory = $false)]
        [Alias('D')]
        [switch]
        $DumpInterfaces,

        # --- Application-layer display filters (Detailed/+) ---
        # See wiki/Application-Filters-DNS.md for full reference.
        # Any of these parameters auto-bump -ParsingLevel to Detailed and -PacketSize
        # to a value large enough to hold a complete DNS message, with a warning.

        # Regex pattern(s) matched (case-insensitive) against the DNS QNAME of the
        # first question, with the trailing dot stripped. Multiple values are OR-combined.
        # Implies -DNS quick filter when neither -DNS nor a matching capture filter
        # is already present.
        [Parameter(Mandatory = $false)]
        [string[]]
        $DnsName,

        # DNS QTYPE filter. Accepts type names ('A','AAAA','MX','SRV','HTTPS','PTR',
        # 'CNAME','TXT','SOA','NS','ANY','CAA','OPT'), numeric values (1, 28),
        # or hex strings ('0x1c'). Multiple values are OR-combined.
        [Parameter(Mandatory = $false)]
        [string[]]
        $DnsType,

        # DNS RCODE filter on responses. Accepts rcode names ('NoError','FormErr',
        # 'ServFail','NXDomain','NotImp','Refused') or numeric values. Multiple
        # values are OR-combined. Queries (QR=0) are unaffected by this filter.
        [Parameter(Mandatory = $false)]
        [string[]]
        $DnsRcode,

        # Transaction-ID filter. Multiple values are OR-combined.
        [Parameter(Mandatory = $false)]
        [int[]]
        $DnsId,

        # Restrict to queries, responses, or either. Default 'Any'.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Query', 'Response', 'Any')]
        [string]
        $DnsQR = 'Any',

        # When set, packets whose DNS parse couldn't complete (header missing or
        # name truncated mid-label by -PacketSize) match the predicate anyway.
        # Default is to drop truncated packets so partial-match false negatives
        # don't surprise the user.
        [Parameter(Mandatory = $false)]
        [switch]
        $DnsMatchTruncated,

        # --- TLS / SNI application-layer filters (Detailed/+) ---
        # See wiki/Application-Filters-TLS.md for full reference.

        # Regex pattern(s) matched case-insensitively against the ClientHello SNI.
        # Multiple values are OR-combined. SNI is only present in ClientHello; non-
        # ClientHello traffic is rejected when this is set. Implies the -HTTPS quick
        # filter (TCP 443) when no other TCP capture filter is configured.
        [Parameter(Mandatory = $false)]
        [string[]]
        $TlsSni,

        # TLS record version filter. Accepts short forms ('1.0','1.1','1.2','1.3'),
        # long forms ('TLS1.2','SSL3.0'), integers, or hex strings.
        [Parameter(Mandatory = $false)]
        [string[]]
        $TlsVersion,

        # TLS record content type. Accepts names ('ChangeCipherSpec','Alert',
        # 'Handshake','ApplicationData'/'AppData') or integers (20-23).
        [Parameter(Mandatory = $false)]
        [string[]]
        $TlsContentType,

        # TLS handshake message type. Accepts names ('ClientHello','ServerHello',
        # 'Certificate', etc.) or integers. Implicitly restricts to Handshake records.
        [Parameter(Mandatory = $false)]
        [string[]]
        $TlsHandshakeType,

        # When set, ClientHello records whose SNI extension couldn't be reached
        # because the packet was truncated still match the SNI filter. Default
        # is to drop truncated records.
        [Parameter(Mandatory = $false)]
        [switch]
        $TlsMatchTruncated,

        # --- HTTP application-layer filters (Detailed/+) ---
        # See wiki/Application-Filters-HTTP.md for full reference.

        # HTTP method filter (request side). Accepts standard names ('GET','POST',
        # 'PUT','DELETE','HEAD','OPTIONS','PATCH','CONNECT','TRACE') or any custom
        # verb. Case-insensitive on input; normalized to uppercase. Multiple values
        # are OR-combined. Implies request-only matching (responses are rejected).
        [Parameter(Mandatory = $false)]
        [string[]]
        $HttpMethod,

        # Regex pattern(s) matched (case-insensitive) against the request path
        # (URI + optional query string). Multiple values are OR-combined. Implies
        # request-only matching.
        [Parameter(Mandatory = $false)]
        [string[]]
        $HttpPath,

        # Regex pattern(s) matched (case-insensitive) against the request Host:
        # header. Multiple values are OR-combined. Implies request-only matching.
        [Parameter(Mandatory = $false)]
        [string[]]
        $HttpHost,

        # HTTP response status filter. Accepts exact codes (200, 404, 503),
        # class patterns ('1xx','2xx','3xx','4xx','5xx'), or hex strings.
        # Multiple values are OR-combined. Implies response-only matching.
        [Parameter(Mandatory = $false)]
        [string[]]
        $HttpStatus,

        # Regex pattern(s) matched (case-insensitive) against the Content-Type:
        # header on either side. Multiple values are OR-combined.
        [Parameter(Mandatory = $false)]
        [string[]]
        $HttpContentType,

        # When set, packets whose HTTP header section couldn't be reached because
        # the packet was truncated still match. Default is to drop truncated
        # packets so partial-match false negatives don't surprise the user.
        [Parameter(Mandatory = $false)]
        [switch]
        $HttpMatchTruncated,

        # --- DHCP application-layer filters (Detailed/+) ---
        # See wiki/Application-Filters-DHCP.md for full reference.

        # DHCP message-type filter. Accepts DHCPv4 names ('Discover','Offer',
        # 'Request','Decline','Ack','Nak','Release','Inform'), DHCPv6 names
        # ('Solicit','Advertise','Request','Confirm','Renew','Rebind','Reply',
        # 'Release','Decline','Reconfigure','Information-request','Relay-forward',
        # 'Relay-reply'), or integers / hex. Names unique to one family resolve
        # to that family only; names shared by both families (e.g. 'Request')
        # and numeric values apply to both. Multiple values are OR-combined.
        [Parameter(Mandatory = $false)]
        [string[]]
        $DhcpMessageType,

        # Regex pattern(s) matched (case-insensitive) against the DHCPv4 client
        # hardware address (chaddr) in canonical aa-bb-cc-dd-ee-ff form. Multiple
        # values are OR-combined. DHCPv6 packets are always rejected when this
        # is set (v1 doesn't decode DHCPv6 DUIDs).
        [Parameter(Mandatory = $false)]
        [string[]]
        $DhcpClientMac,

        # Restrict to one address family. 'V4' = DHCPv4 (ports 67/68) only,
        # 'V6' = DHCPv6 (ports 546/547) only, 'Any' (default) = either.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Any', 'V4', 'V6')]
        [string]
        $DhcpFamily = 'Any',

        # When set, DHCPv4 packets whose option block couldn't be walked to
        # reach option-53 (typically because -PacketSize cut the payload mid-
        # options) still match the predicate. Default is to drop truncated
        # packets so a partial-match false negative isn't silent.
        [Parameter(Mandatory = $false)]
        [switch]
        $DhcpMatchTruncated,

        # --- SMB2 application-layer filters (Detailed/+) ---
        # See wiki/Application-Filters-SMB2.md for full reference.

        # SMB2 command filter. Accepts names ('Negotiate','SessionSetup','Logoff',
        # 'TreeConnect','TreeDisconnect','Create','Close','Flush','Read','Write',
        # 'Lock','Ioctl','Cancel','Echo','QueryDirectory','ChangeNotify','QueryInfo',
        # 'SetInfo','OplockBreak') or integers (0-18). Multiple values are OR-combined.
        [Parameter(Mandatory = $false)]
        [string[]]
        $SmbCommand,

        # Direction restriction. 'Request' = client→server only, 'Response' =
        # server→client only, 'Any' (default) = either.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Any', 'Request', 'Response')]
        [string]
        $SmbDirection = 'Any',

        # NT status filter. Accepts class names ('Success','Informational','Info',
        # 'Warning','Error'), exact status names ('ACCESS_DENIED','NO_SUCH_FILE',
        # 'OBJECT_NAME_NOT_FOUND','LOGON_FAILURE','SHARING_VIOLATION', etc.),
        # hex strings ('0xC0000022'), or integers. Multiple values are OR-combined.
        [Parameter(Mandatory = $false)]
        [string[]]
        $SmbStatus,

        # Regex pattern(s) matched (case-insensitive) against the SMB2 Create
        # request filename. Multiple values are OR-combined. Implies request-only
        # matching and Create-only matching (other commands carry no filename).
        [Parameter(Mandatory = $false)]
        [string[]]
        $SmbFilename,

        # Regex pattern(s) matched (case-insensitive) against the SMB2 TreeConnect
        # request share path (e.g. \\server\share). Multiple values are OR-combined.
        # Implies request-only matching and TreeConnect-only matching.
        [Parameter(Mandatory = $false)]
        [string[]]
        $SmbTreePath,

        # When set, encrypted (SMB2 Transform header) packets match even when
        # other filter fields are configured. Default is to drop encrypted
        # packets as soon as any command/status/filename/tree-path filter is
        # set, because those fields aren't visible in encrypted packets.
        [Parameter(Mandatory = $false)]
        [switch]
        $SmbMatchEncrypted,

        # When set, packets whose per-command body extraction (filename / tree
        # path) couldn't be reached because -PacketSize truncated the payload
        # still match. Default is to drop truncated packets so a partial-match
        # false negative isn't silent.
        [Parameter(Mandatory = $false)]
        [switch]
        $SmbMatchTruncated,

        # --- ICMP / ICMPv6 / NDP application-layer filters (Detailed/+) ---
        # See wiki/Application-Filters-ICMP.md for full reference.

        # IPv4 ICMP type filter. Accepts ICMP4_TYPE names (full 'ICMP4_ECHO_REQUEST'
        # or short 'EchoRequest'), integers (0-255), or hex strings. Multiple values
        # are OR-combined. Implicitly v4-only — IPv6 packets are rejected unless
        # -Icmpv6Type or -Icmpv6NdpTarget is also set.
        [Parameter(Mandatory = $false)]
        [string[]]
        $IcmpType,

        # ICMPv6 type filter. Accepts names ('NeighborSolicitation'/'NS',
        # 'NeighborAdvertisement'/'NA', 'RouterSolicitation'/'RS',
        # 'RouterAdvertisement'/'RA', 'Redirect', 'EchoRequest', 'EchoReply',
        # 'DestinationUnreachable', 'PacketTooBig', 'TimeExceeded',
        # 'ParameterProblem', 'MulticastListenerQuery', ...), integers, or hex
        # strings. Multiple values are OR-combined. Implicitly v6-only — IPv4
        # packets are rejected unless -IcmpType is also set.
        [Parameter(Mandatory = $false)]
        [string[]]
        $Icmpv6Type,

        # Regex pattern(s) matched (case-insensitive) against the NDP target
        # address (canonical IPv6 form) on Neighbor Solicitation (135) and
        # Neighbor Advertisement (136) packets. Multiple values are OR-combined.
        # Rejects every non-NS/NA packet (including IPv4 ICMP, RA, RS, Redirect).
        [Parameter(Mandatory = $false)]
        [string[]]
        $Icmpv6NdpTarget,

        # Suppress non-fatal setup warnings (auto-bumps, missing-MAC vmNIC skip,
        # non-numeric component value). Operational warnings about pcapng data
        # loss and writer errors are unaffected. For full suppression use the
        # standard -WarningAction SilentlyContinue.
        [Parameter(Mandatory = $false)]
        [switch]
        $NoWarning
    )

    process {
        # --- DumpInterfaces: print NIC table and return without starting capture ---
        if ($DumpInterfaces.IsPresent) {
            return Get-PspktComponent -NIC | Sort-Object Id | Select-Object Id, Name | Format-Table -AutoSize
        }

        # --- DNS application-layer predicate detection + auto-bumps ---
        # Detect *before* session creation so PacketSize bump propagates into the
        # session. ParsingLevel bump must also happen before Set-PspktDetailLevel.
        $dnsPredicateActive =
            $PSBoundParameters.ContainsKey('DnsName') -or
            $PSBoundParameters.ContainsKey('DnsType') -or
            $PSBoundParameters.ContainsKey('DnsRcode') -or
            $PSBoundParameters.ContainsKey('DnsId') -or
            $PSBoundParameters.ContainsKey('DnsQR') -or
            $DnsMatchTruncated.IsPresent

        # --- TLS application-layer predicate detection + auto-bumps ---
        $tlsPredicateActive =
            $PSBoundParameters.ContainsKey('TlsSni') -or
            $PSBoundParameters.ContainsKey('TlsVersion') -or
            $PSBoundParameters.ContainsKey('TlsContentType') -or
            $PSBoundParameters.ContainsKey('TlsHandshakeType') -or
            $TlsMatchTruncated.IsPresent

        # --- HTTP application-layer predicate detection + auto-bumps ---
        $httpPredicateActive =
            $PSBoundParameters.ContainsKey('HttpMethod') -or
            $PSBoundParameters.ContainsKey('HttpPath') -or
            $PSBoundParameters.ContainsKey('HttpHost') -or
            $PSBoundParameters.ContainsKey('HttpStatus') -or
            $PSBoundParameters.ContainsKey('HttpContentType') -or
            $HttpMatchTruncated.IsPresent

        # --- DHCP application-layer predicate detection + auto-bumps ---
        $dhcpPredicateActive =
            $PSBoundParameters.ContainsKey('DhcpMessageType') -or
            $PSBoundParameters.ContainsKey('DhcpClientMac') -or
            $PSBoundParameters.ContainsKey('DhcpFamily') -or
            $DhcpMatchTruncated.IsPresent

        # --- SMB2 application-layer predicate detection + auto-bumps ---
        $smbPredicateActive =
            $PSBoundParameters.ContainsKey('SmbCommand') -or
            $PSBoundParameters.ContainsKey('SmbDirection') -or
            $PSBoundParameters.ContainsKey('SmbStatus') -or
            $PSBoundParameters.ContainsKey('SmbFilename') -or
            $PSBoundParameters.ContainsKey('SmbTreePath') -or
            $SmbMatchEncrypted.IsPresent -or
            $SmbMatchTruncated.IsPresent

        # --- ICMP / ICMPv6 / NDP predicate detection ---
        # ICMP packets are small (typical < 100 bytes), so no -PacketSize bump
        # is needed even when -Icmpv6NdpTarget extracts the 16-byte target
        # address — it always fits in the default capture.
        $icmpV4PredicateActive = $PSBoundParameters.ContainsKey('IcmpType')
        $icmpV6PredicateActive = $PSBoundParameters.ContainsKey('Icmpv6Type') -or
                                 $PSBoundParameters.ContainsKey('Icmpv6NdpTarget')
        $icmpPredicateActive   = $icmpV4PredicateActive -or $icmpV6PredicateActive

        $appPredicateActive = $dnsPredicateActive -or $tlsPredicateActive -or $httpPredicateActive -or $dhcpPredicateActive -or $smbPredicateActive -or $icmpPredicateActive

        if ($appPredicateActive) {
            # Auto-bump ParsingLevel to Detailed. Application-layer parsing only
            # runs at Detailed/VeryDetailed; a predicate on a lower level would
            # silently match nothing because the parser is never invoked.
            if ([int]$ParsingLevel -lt [int][PspktParsingLevel]::Detailed) {
                $previousLevel = $ParsingLevel
                $ParsingLevel = [PspktParsingLevel]::Detailed
                if (-not $NoWarning.IsPresent) {
                    Write-Warning "Application-layer filter requires -ParsingLevel Detailed or higher; auto-bumping from '$previousLevel' to 'Detailed'."
                }
            }
        }

        if ($dnsPredicateActive) {
            # Auto-bump PacketSize to a value that comfortably holds a complete DNS
            # message. -PacketSize 0 (full packet) is left alone — user already opted
            # in to maximum payload. Below the floor, bump to 1500 and warn.
            $dnsPacketSizeFloor = 1500
            if ($PacketSize -ne 0 -and $PacketSize -lt $dnsPacketSizeFloor) {
                $previousSize = $PacketSize
                $PacketSize = [uint32]$dnsPacketSizeFloor
                if (-not $NoWarning.IsPresent) {
                    Write-Warning "DNS name filter benefits from a larger -PacketSize; auto-bumping from $previousSize to $PacketSize bytes (use -PacketSize 0 to capture full packets)."
                }
            }
        }

        if ($tlsPredicateActive) {
            # ClientHello with extensions (ALPN, SNI, signature_algorithms, key_share,
            # supported_versions, ...) routinely exceeds 1500 bytes on modern stacks
            # — bump higher than DNS so SNI parsing doesn't silently fail on long
            # extension blocks. -PacketSize 0 (full packet) is preserved.
            $tlsPacketSizeFloor = 2048
            if ($PacketSize -ne 0 -and $PacketSize -lt $tlsPacketSizeFloor) {
                $previousSize = $PacketSize
                $PacketSize = [uint32]$tlsPacketSizeFloor
                if (-not $NoWarning.IsPresent) {
                    Write-Warning "TLS SNI filter benefits from a larger -PacketSize; auto-bumping from $previousSize to $PacketSize bytes (use -PacketSize 0 to capture full packets)."
                }
            }
        }

        if ($httpPredicateActive) {
            # HTTP requests with large cookies, bearer tokens, or many headers
            # routinely exceed 1500 bytes — bump to 2048 so the Host: /
            # Content-Type: / Content-Length: headers are reliably reachable.
            # -PacketSize 0 (full packet) is preserved.
            $httpPacketSizeFloor = 2048
            if ($PacketSize -ne 0 -and $PacketSize -lt $httpPacketSizeFloor) {
                $previousSize = $PacketSize
                $PacketSize = [uint32]$httpPacketSizeFloor
                if (-not $NoWarning.IsPresent) {
                    Write-Warning "HTTP header filter benefits from a larger -PacketSize; auto-bumping from $previousSize to $PacketSize bytes (use -PacketSize 0 to capture full packets)."
                }
            }
        }

        if ($dhcpPredicateActive) {
            # DHCPv4 minimum is 240 (BOOTP fixed) + 4 (magic) = 244 bytes, plus
            # options. Option-53 (message type) is typically among the first few
            # options so 590 is enough for the common case — matching the existing
            # -DHCP quick-filter auto-bump. Bumping further would be wasteful for
            # the typical DHCPv4 packet (~340 bytes on the wire).
            # -PacketSize 0 (full packet) is preserved.
            $dhcpPacketSizeFloor = 590
            if ($PacketSize -ne 0 -and $PacketSize -lt $dhcpPacketSizeFloor) {
                $previousSize = $PacketSize
                $PacketSize = [uint32]$dhcpPacketSizeFloor
                if (-not $NoWarning.IsPresent) {
                    Write-Warning "DHCP message-type filter benefits from a larger -PacketSize; auto-bumping from $previousSize to $PacketSize bytes (use -PacketSize 0 to capture full packets)."
                }
            }
        }

        if ($smbPredicateActive) {
            # SMB2 Create filenames and TreeConnect share paths can be long
            # (MAX_PATH = 260 UTF-16 chars = 520 bytes), and Direct-TCP framing
            # + SMB2 header + Create body adds ~120 bytes. 1500 covers the
            # common case; SMB2 over the wire is sized to fit MTU anyway.
            # -PacketSize 0 (full packet) is preserved.
            $smbPacketSizeFloor = 1500
            if ($PacketSize -ne 0 -and $PacketSize -lt $smbPacketSizeFloor) {
                $previousSize = $PacketSize
                $PacketSize = [uint32]$smbPacketSizeFloor
                if (-not $NoWarning.IsPresent) {
                    Write-Warning "SMB2 filter benefits from a larger -PacketSize; auto-bumping from $previousSize to $PacketSize bytes (use -PacketSize 0 to capture full packets)."
                }
            }
        }

        $createdSession = $false

        # Create a session if one was not provided.
        if ($PSCmdlet.ParameterSetName -eq 'Default') {
            $Session = New-PspktSession -Name $Name
            $Session.CaptureType = $CaptureType
            $Session.PacketSize  = $PacketSize
            $Session.LogMode     = [PspktLogMode]::RealTime
            $createdSession = $true
        }

        # Parse IPAddress early so it can be combined with quick filters and VM MAC filters.
        $parsedIP = $null
        if ($PSBoundParameters.ContainsKey('IPAddress') -and -not [string]::IsNullOrEmpty($IPAddress)) {
            $parsedIP = [System.Net.IPAddress]::Parse($IPAddress)
        }

        # Resolve VM MAC list up front. When -VM / -VMName is supplied, every
        # quick filter and app-imply filter built below will be AND-combined
        # with the VM-NIC MAC list (one filter per (filter, MAC) pair), so all
        # capture is constrained to the VM's network data path. The resolved
        # list is also reused later to skip the standalone QF-VM-MAC-* filters
        # when quick filters already provide the scope.
        $vmMacList = @()
        if ($PSBoundParameters.ContainsKey('VM') -or ($PSBoundParameters.ContainsKey('VMName') -and -not [string]::IsNullOrEmpty($VMName))) {
            $vmMacList = Get-PspktVMMacList -VM $VM -VMName $VMName -NoWarning:$NoWarning.IsPresent
        }
        $vmScopingActive = ($vmMacList.Count -gt 0)
        $vmExpansionApplied = $false

        # Persist VM scoping on the session object so any subsequent Add-PspktFilter
        # calls (outside Start-Pspkt) also auto-MAC-stamp their filters.
        if ($vmScopingActive) {
            $vmLabel = if ($PSBoundParameters.ContainsKey('VM')) { "$($VM.Name)" } else { $VMName }
            $Session.VMName = $vmLabel
            $Session.VMMacAddresses = $vmMacList
        }

        # Apply quick filters — create and add filters for each active switch.
        $quickFilters = [System.Collections.ArrayList]::new()

        if ($ARP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP'))
        }

        if ($NDP.IsPresent -or $AA.IsPresent -or $AAv6.IsPresent) {
            # NDP uses ICMPv6 types 133-137. Filter on ICMPv6 protocol (58).
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-NDP' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
        }

        if ($DHCP.IsPresent -or $AA.IsPresent -or $AAv4.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-Client' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 68))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-Server' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 67))
        }

        if ($DHCPv6.IsPresent -or $AA.IsPresent -or $AAv6.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-Client' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 546))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-Server' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 547))
        }

        if ($DNS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-UDP' -TransportProtocol 'UDP' -Port1 53))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-TCP' -TransportProtocol 'TCP' -Port1 53))
        } elseif ($dnsPredicateActive) {
            # Auto-add DNS port capture filters when a -Dns* predicate is set so
            # DNS traffic actually reaches the consumer where the predicate runs.
            # Per-port coverage check so combining with another unrelated filter
            # (e.g. -ARP, -Ping) still adds the DNS capture, while combining with
            # an explicit -DNS (handled above) doesn't double-add.
            if (-not (Test-PspktQuickFilterCoverage -Filters $quickFilters -TransportProtocol 'UDP' -Port 53)) {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-UDP-AUTO' -TransportProtocol 'UDP' -Port1 53))
            }
            if (-not (Test-PspktQuickFilterCoverage -Filters $quickFilters -TransportProtocol 'TCP' -Port 53)) {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-TCP-AUTO' -TransportProtocol 'TCP' -Port1 53))
            }
        }

        if ($DNSoverHTTPS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DoH' -TransportProtocol 'TCP' -Port1 443))
        }

        if ($DNSoverTLS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DoT' -TransportProtocol 'TCP' -Port1 853))
        }

        if ($SMB.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SMB' -TransportProtocol 'TCP' -Port1 445))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-Kerberos' -TransportProtocol 'TCP' -Port1 88))
        }

        if ($SMBoverQUIC.IsPresent) {
            $soqPort = if ($PSBoundParameters.ContainsKey('SMBoverQuicAltPort')) { $SMBoverQuicAltPort } else { 443 }
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SMBoverQUIC' -TransportProtocol 'UDP' -Port1 $soqPort))
        }

        if ($SSH.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SSH' -TransportProtocol 'TCP' -Port1 22))
        }

        if ($RDP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RDP' -TransportProtocol 'TCP' -Port1 3389))
        }

        if ($RPC.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RPC' -TransportProtocol 'TCP' -Port1 135))
        }

        if ($RCP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RCP-TCP' -TransportProtocol 'TCP' -Port1 3343))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RCP-UDP' -TransportProtocol 'UDP' -Port1 3343))
        }

        if ($HTTP.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTP' -TransportProtocol 'TCP' -Port1 80))
        }

        if ($HTTPS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTPS' -TransportProtocol 'TCP' -Port1 443))
        }

        if ($WinRM.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-WinRM' -TransportProtocol 'TCP' -Port1 5985))
        }

        if ($WinRMS.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-WinRMS' -TransportProtocol 'TCP' -Port1 5986))
        }

        if ($Ping.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
        }

        if ($Ping4.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
        }

        if ($Ping6.IsPresent) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
        }

        # Auto-imply HTTPS (TCP 443) for TLS predicates unless an existing capture
        # filter already covers TCP 443. Coverage-based suppression replaces the
        # earlier "no other filter at all" guard, so combining a TLS predicate
        # with an unrelated capture filter (e.g. -ARP, -Ping) no longer hides
        # the TLS traffic the predicate is supposed to evaluate.
        if ($tlsPredicateActive -and -not (Test-PspktQuickFilterCoverage -Filters $quickFilters -TransportProtocol 'TCP' -Port 443)) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTPS-TLS' -TransportProtocol 'TCP' -Port1 443))
        }

        # Auto-imply HTTP (TCP 80) for HTTP predicates unless covered.
        if ($httpPredicateActive -and -not (Test-PspktQuickFilterCoverage -Filters $quickFilters -TransportProtocol 'TCP' -Port 80)) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTP-AUTO' -TransportProtocol 'TCP' -Port1 80))
        }

        # Auto-imply DHCP quick filters per family, suppressed per port when an
        # existing filter already covers that port. -DhcpFamily narrows which
        # families get auto-implied; coverage is checked port-by-port.
        if ($dhcpPredicateActive) {
            if ($DhcpFamily -ne 'V6') {
                if (-not (Test-PspktQuickFilterCoverage -Filters $quickFilters -EtherType 'IPv4' -TransportProtocol 'UDP' -Port 68)) {
                    $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-CLIENT-AUTO' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 68))
                }
                if (-not (Test-PspktQuickFilterCoverage -Filters $quickFilters -EtherType 'IPv4' -TransportProtocol 'UDP' -Port 67)) {
                    $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-SERVER-AUTO' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 67))
                }
            }
            if ($DhcpFamily -ne 'V4') {
                if (-not (Test-PspktQuickFilterCoverage -Filters $quickFilters -EtherType 'IPv6' -TransportProtocol 'UDP' -Port 546)) {
                    $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-CLIENT-AUTO' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 546))
                }
                if (-not (Test-PspktQuickFilterCoverage -Filters $quickFilters -EtherType 'IPv6' -TransportProtocol 'UDP' -Port 547)) {
                    $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-SERVER-AUTO' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 547))
                }
            }
        }

        # Auto-imply SMB2 (TCP 445) for SMB2 predicates unless covered. Unlike
        # the built-in -SMB switch (which adds TCP 445 + Kerberos 88), the
        # auto-imply only adds TCP 445 — Kerberos packets wouldn't match an
        # SMB2 predicate anyway.
        if ($smbPredicateActive -and -not (Test-PspktQuickFilterCoverage -Filters $quickFilters -TransportProtocol 'TCP' -Port 445)) {
            $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SMB2-AUTO' -TransportProtocol 'TCP' -Port1 445))
        }

        # Auto-imply ICMPv4 / ICMPv6 capture filters per family, suppressed
        # when an existing filter already covers that family (e.g. -Ping covers
        # both, -NDP covers ICMPv6).
        if ($icmpPredicateActive) {
            if ($icmpV4PredicateActive -and -not (Test-PspktQuickFilterCoverage -Filters $quickFilters -EtherType 'IPv4' -TransportProtocol 'ICMP')) {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4-AUTO' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
            }
            if ($icmpV6PredicateActive -and -not (Test-PspktQuickFilterCoverage -Filters $quickFilters -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP')) {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6-AUTO' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
            }
        }

        # Apply -IPAddress to all quick filters (AND logic within each filter).
        # If no quick filters exist and no VM, create a standalone IP filter.
        if ($null -ne $parsedIP) {
            if ($quickFilters.Count -gt 0) {
                foreach ($qf in $quickFilters) {
                    $qf.SetIp1($parsedIP)
                }
            } elseif (-not $vmScopingActive) {
                if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $null = $quickFilters.Add((New-PspktFilter -Name "QF-IP-$IPAddress" -EtherType 'IPv4' -Ip1 $parsedIP))
                } else {
                    $null = $quickFilters.Add((New-PspktFilter -Name "QF-IP-$IPAddress" -EtherType 'IPv6' -Ip1 $parsedIP))
                }
            }
        }

        # VM scoping: when -VM / -VMName is active and the user supplied any
        # quick filter or any application-layer predicate auto-implied one,
        # AND-combine each filter with each VM-NIC MAC. Pktmon filters
        # OR-combine across the session-level filter list, so the only way to
        # express "(VM MAC) AND (protocol scope)" is to bake both into a
        # single filter object — expanded across the cartesian product of
        # quick filters x VM MACs. The standalone QF-VM-MAC-* filters added
        # later in the component-setup block are suppressed in this case
        # (otherwise pktmon would OR them in, defeating the AND scoping).
        # The original quickFilters list is replaced in-place.
        if ($vmScopingActive -and $quickFilters.Count -gt 0) {
            $expanded = [System.Collections.ArrayList]::new()
            foreach ($qf in $quickFilters) {
                foreach ($macStr in $vmMacList) {
                    $clone = Copy-PspktFilter -Filter $qf -NameSuffix "-VM-$macStr"
                    $clone.SetMac1($macStr)
                    $null = $expanded.Add($clone)
                }
            }

            # pktmon supports a maximum of 32 filters per session. The
            # cartesian expansion (N quick filters × M vmNICs) can exceed
            # this limit when many quick filters combine with a multi-NIC VM.
            # Fail fast with a clear message rather than letting the native
            # API return a cryptic error at session activation.
            if ($expanded.Count -gt 32) {
                throw "VM AND-scoping expanded $($quickFilters.Count) quick filter(s) x $($vmMacList.Count) vmNIC(s) into $($expanded.Count) filters, exceeding pktmon's 32-filter limit. Reduce the number of quick filters or application-layer predicates, or use fewer vmNICs."
            }

            $quickFilters = $expanded
            $vmExpansionApplied = $true
        }

        # Add all quick filters to the session.
        foreach ($qf in $quickFilters) {
            Add-PspktFilter -Filter $qf -Session $Session
        }

        # Determine real-time mode.
        # Real-time is enabled when: no -WriteFile (default), or -WriteFile + quick filter, or -WriteFile + -RealTime.
        $hasWriteFile = $PSBoundParameters.ContainsKey('WriteFile') -and -not [string]::IsNullOrEmpty($WriteFile)
        $hasWriteEtl = $PSBoundParameters.ContainsKey('WriteEtl') -and -not [string]::IsNullOrEmpty($WriteEtl)
        $useRealTime = $true
        if ($hasWriteFile) {
            $useRealTime = $RealTime.IsPresent -or ($quickFilters.Count -gt 0)
        }

        # -WriteEtl cannot be combined with real-time capture (pktmon only allows one session).
        if ($hasWriteEtl) {
            if ($hasWriteFile) {
                throw "-WriteEtl cannot be used with -WriteFile. Use one or the other."
            }
            if ($RealTime.IsPresent) {
                throw "-WriteEtl cannot be used with -RealTime. ETL capture uses pktmon's native session."
            }
            $useRealTime = $false
        }

        # Auto-increase PacketSize for protocols that need more payload (e.g., DHCP options at byte 240+).
        # Only bump if the user did not explicitly specify a larger PacketSize.
        if ($quickFilters.Count -gt 0 -and -not $PSBoundParameters.ContainsKey('PacketSize')) {
            $needsDHCP = $DHCP.IsPresent -or $DHCPv6.IsPresent -or $AA.IsPresent -or $AAv4.IsPresent -or $AAv6.IsPresent
            if ($needsDHCP -and $Session.PacketSize -lt 590) {
                $Session.PacketSize = 590
            } elseif ($DNS.IsPresent -and $Session.PacketSize -lt 512) {
                $Session.PacketSize = 512
            }
        }

        if ($Session.Active) {
            throw "Session '$($Session.Name)' is already active. Stop it before starting again."
        }
        if ($Session.Handle -eq [IntPtr]::Zero) {
            throw "Session '$($Session.Name)' has a null handle. It may have been torn down."
        }
        if ($null -eq $Session.Pspkt) {
            throw "Session '$($Session.Name)' has no associated pspkt instance."
        }

        # Reuse an existing valid stream if one is already attached.
        $hasValidStream = $false
        $createdStream = $null
        if ($useRealTime) {
            foreach ($existingStream in $Session.OutputStream) {
                if ($null -ne $existingStream -and $existingStream.Handle -ne [IntPtr]::Zero) {
                    $hasValidStream = $true
                    break
                }
            }

            if (-not $hasValidStream) {
                # Use session's PacketSize as stream truncation to get enough data for parsers.
                # PacketSize 0 means full packet; map to 65535 for the stream (max uint16).
                $streamTruncation = $TruncationSize
                if ($streamTruncation -eq 0 -and $Session.PacketSize -gt 0) {
                    $streamTruncation = [uint16][Math]::Min($Session.PacketSize, 65535)
                } elseif ($streamTruncation -eq 0) {
                    $streamTruncation = [uint16]65535
                }

                # Scale the user-mode SPSC ring buffer with BufferSizeMultiplier as well.
                # Base ring size is 1M entries; multiplier scales linearly with a sane cap.
                $baseRingCap = 1048576
                $targetRingCap = [int]($baseRingCap * $BufferSizeMultiplier)
                if ($targetRingCap -lt $baseRingCap) { $targetRingCap = $baseRingCap }
                if ($targetRingCap -gt 67108864) { $targetRingCap = 67108864 } # cap at 64M entries
                $appliedRingCap = [PktMonApi]::ConfigureRingBuffer($targetRingCap)
                Write-Verbose "Ring buffer capacity: $appliedRingCap entries (multiplier=$BufferSizeMultiplier)"

                $createdStream = $Session.Pspkt.CreateRealtimeStream($BufferSizeMultiplier, $streamTruncation)
                $Session.AttachOutputToSession($createdStream)
            }
        }

        # Add components based on -Component / -VM / -VMName parameters.
        # Only applies when the session has no components already added.
        if ($Session.Components.Count -eq 0) {
            $componentsToAdd = $null

            $isVmBranch = $PSBoundParameters.ContainsKey('VM') -or ($PSBoundParameters.ContainsKey('VMName') -and -not [string]::IsNullOrEmpty($VMName))

            if ($isVmBranch) {
                # Resolve the user-facing label up front so error/warning
                # messages name the right VM.
                $vmLabel = if ($PSBoundParameters.ContainsKey('VM')) { "$($VM.Name)" } else { $VMName }

                # Primary path: ask Get-PspktComponent for live vmNIC + data-
                # path components. This goes through pktmon and only finds
                # components for VMs whose vmNICs are currently bound to a
                # vmSwitch (typically Running / Starting / Paused VMs).
                if ($PSBoundParameters.ContainsKey('VM')) {
                    $componentsToAdd = Get-PspktComponent -VM $VM
                } else {
                    $componentsToAdd = Get-PspktComponent -VMName $VMName
                }

                # OFF / Saved VM fallback. pktmon does not enumerate vmNICs
                # whose VM is in an Off / Saved state (the NDIS filter isn't
                # attached), so Get-PspktComponent returns nothing. When we
                # *do* have a MAC list for the VM (from the Hyper-V cmdlets
                # in Get-PspktVMMacList, which work in any power state), we
                # can still capture by attaching to the parent NIC
                # components and letting the AND-combined MAC filter scope
                # the capture. As soon as the VM starts and its traffic
                # appears on the host NIC, the filter matches.
                if ($null -eq $componentsToAdd -or @($componentsToAdd).Count -eq 0) {
                    if ($vmMacList.Count -gt 0) {
                        if (-not $NoWarning.IsPresent) {
                            Write-Warning "VM '$vmLabel' has no live pktmon vmNIC components (VM is Off / Saved?). Falling back to host NIC components; capture starts matching as soon as VM traffic appears on the wire."
                        }
                        $componentsToAdd = $Session.Pspkt.EnumPktmonDataSources($true, 1)
                    } else {
                        # No MACs, no live components — refuse to proceed
                        # rather than silently capture nothing or (worse)
                        # capture all host traffic without VM scoping.
                        # Common causes: dynamic-MAC VM that has never been
                        # started, VM with zero vmNICs.
                        throw "VM '$vmLabel' has no live pktmon components and no discoverable vmNIC MAC addresses (dynamic-MAC VM that has never been started? VM has no vmNIC?). Start the VM at least once to allocate a MAC, assign a static MAC via Set-VMNetworkAdapter -StaticMacAddress, or capture without -VM."
                    }
                }

                # Standalone QF-VM-MAC-* filters per vmNIC — only added when
                # no quick / app-imply filter took the VM scoping via
                # cartesian expansion. With expansion, every filter already
                # AND-combines MAC + protocol; a standalone MAC filter here
                # would OR-combine at the kernel and capture all VM traffic,
                # defeating `-SmbCommand Create` etc.
                if (-not $vmExpansionApplied) {
                    foreach ($macStr in $vmMacList) {
                        $filterParams = @{ Name = "QF-VM-MAC-$macStr"; Mac1 = $macStr }
                        if ($null -ne $parsedIP) {
                            $filterParams['Ip1'] = $parsedIP
                            if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                                $filterParams['EtherType'] = 'IPv4'
                            } else {
                                $filterParams['EtherType'] = 'IPv6'
                            }
                        }
                        $macFilter = New-PspktFilter @filterParams
                        Add-PspktFilter -Filter $macFilter -Session $Session
                    }
                }
            } elseif ($Component.Count -eq 1 -and $Component[0] -eq 'NICs') {
                # NICs keyword — capture from NIC components only.
                $componentsToAdd = $Session.Pspkt.EnumPktmonDataSources($true, 1)
            } elseif ($Component.Count -eq 1 -and $Component[0] -eq 'All') {
                # All keyword (default) — capture from all components.
                $allSources = $Session.Pspkt.EnumPktmonDataSources($true, 0)
                $nicSources = $Session.Pspkt.EnumPktmonDataSources($true, 1)
                $componentsToAdd = [System.Collections.ArrayList]::new()
                if ($null -ne $nicSources) { $null = $componentsToAdd.AddRange($nicSources) }
                if ($null -ne $allSources) { $null = $componentsToAdd.AddRange($allSources) }
            } else {
                # Treat values as component IDs — enumerate all and filter by ID.
                $allSources = $Session.Pspkt.EnumPktmonDataSources($true, 0)
                $nicSources = $Session.Pspkt.EnumPktmonDataSources($true, 1)
                $all = [System.Collections.ArrayList]::new()
                if ($null -ne $nicSources) { $null = $all.AddRange($nicSources) }
                if ($null -ne $allSources) { $null = $all.AddRange($allSources) }

                [int[]]$ids = @()
                foreach ($c in $Component) {
                    $parsed = 0
                    if ([int]::TryParse($c, [ref]$parsed)) {
                        $ids += $parsed
                    } else {
                        if (-not $NoWarning.IsPresent) {
                            Write-Warning "Ignoring non-numeric component value: '$c'"
                        }
                    }
                }

                $componentsToAdd = $all | Where-Object { $_.Id -in $ids }
            }

            if ($null -ne $componentsToAdd) {
                foreach ($comp in $componentsToAdd) {
                    if ($null -ne $comp -and $comp.Pointer -ne [IntPtr]::Zero) {
                        $Session.AddSingleDataSourceToSession($comp)
                    }
                }
            }
            Write-Verbose "Total components added to session: $($Session.Components.Count)"
        }

        try {
            $Session.SetSessionActive($true)
        }
        catch {
            # Roll back the stream we just created if activation fails.
            if ($null -ne $createdStream) {
                $Session.Pspkt.PacketMonitorCloseRealtimeStream($createdStream)
            }
            # If we created the session, tear it down on failure.
            if ($createdSession) {
                if ($Session.Handle -ne [IntPtr]::Zero) {
                    $Session.Pspkt.PacketMonitorCloseSessionHandle($Session)
                }
                $Session.Pspkt.PacketMonitorUninitialize()
            }
            throw
        }

        # Real-time blocking read loop. Ctrl+C triggers the finally block for cleanup.
        $packetCount = 0
        $droppedCount = 0
        [PktMonApi]::ClearPacketBuffer()
        [PktMonApi]::ResetDroppedCount()
        [PktMonApi]::ClearSeenComponentIds()
        [PktMonApi]::InitTimestampBaseline()
        Reset-PspktLineCounter

        # Set detail level based on ParsingLevel enum.
        Set-PspktDetailLevel -Level ([int]$ParsingLevel)
        Set-PspktDetailSpacing -Enabled ($ParsingLevel -ge [PspktParsingLevel]::Detailed -and $Spaced.IsPresent)
        Set-PspktShowTimestamp -Enabled $Timestamp.IsPresent

        # --- Application-layer display predicates ---
        # Always clear first so a predicate left over from a prior capture in the
        # same PS session can't silently filter this one.
        [PacketLineFormatter]::ClearAppPredicates()
        if ($dnsPredicateActive) {
            $dnsPredicate = [DnsAppPredicate]::new()

            if ($PSBoundParameters.ContainsKey('DnsName') -and $DnsName) {
                # Combine multiple regex patterns with OR. Each pattern is wrapped
                # in a non-capturing group so user alternation operators don't
                # change semantics. Compile once for the lifetime of the capture.
                $combined = ($DnsName | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                             [System.Text.RegularExpressions.RegexOptions]::Compiled
                $dnsPredicate.QNameRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            if ($PSBoundParameters.ContainsKey('DnsType') -and $DnsType) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($t in $DnsType) {
                    $null = $resolved.Add((Resolve-PspktDnsType -Value $t))
                }
                $dnsPredicate.QTypes = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('DnsRcode') -and $DnsRcode) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($r in $DnsRcode) {
                    $null = $resolved.Add((Resolve-PspktDnsRcode -Value $r))
                }
                $dnsPredicate.Rcodes = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('DnsId') -and $DnsId) {
                $dnsPredicate.TxIds = [int[]]$DnsId
            }

            switch ($DnsQR) {
                'Query'    { $dnsPredicate.Qr = 0 }
                'Response' { $dnsPredicate.Qr = 1 }
                default    { $dnsPredicate.Qr = -1 }
            }

            $dnsPredicate.MatchTruncated = $DnsMatchTruncated.IsPresent

            [PacketLineFormatter]::SetDnsPredicate($dnsPredicate)
            Write-Verbose "DNS predicate active: QName='$($dnsPredicate.QNameRegex)'; QTypes=$($dnsPredicate.QTypes -join ','); Rcodes=$($dnsPredicate.Rcodes -join ','); TxIds=$($dnsPredicate.TxIds -join ','); Qr=$($dnsPredicate.Qr); MatchTruncated=$($dnsPredicate.MatchTruncated)"
        }

        if ($tlsPredicateActive) {
            $tlsPredicate = [TlsAppPredicate]::new()

            if ($PSBoundParameters.ContainsKey('TlsSni') -and $TlsSni) {
                $combined = ($TlsSni | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                             [System.Text.RegularExpressions.RegexOptions]::Compiled
                $tlsPredicate.SniRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            if ($PSBoundParameters.ContainsKey('TlsVersion') -and $TlsVersion) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($v in $TlsVersion) {
                    $null = $resolved.Add((Resolve-PspktTlsVersion -Value $v))
                }
                $tlsPredicate.Versions = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('TlsContentType') -and $TlsContentType) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($t in $TlsContentType) {
                    $null = $resolved.Add((Resolve-PspktTlsContentType -Value $t))
                }
                $tlsPredicate.ContentTypes = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('TlsHandshakeType') -and $TlsHandshakeType) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($t in $TlsHandshakeType) {
                    $null = $resolved.Add((Resolve-PspktTlsHandshakeType -Value $t))
                }
                $tlsPredicate.HandshakeTypes = $resolved.ToArray()
            }

            $tlsPredicate.MatchTruncated = $TlsMatchTruncated.IsPresent

            [PacketLineFormatter]::SetTlsPredicate($tlsPredicate)
            Write-Verbose "TLS predicate active: Sni='$($tlsPredicate.SniRegex)'; Versions=$($tlsPredicate.Versions -join ','); ContentTypes=$($tlsPredicate.ContentTypes -join ','); HandshakeTypes=$($tlsPredicate.HandshakeTypes -join ','); MatchTruncated=$($tlsPredicate.MatchTruncated)"
        }

        if ($httpPredicateActive) {
            $httpPredicate = [HttpAppPredicate]::new()

            if ($PSBoundParameters.ContainsKey('HttpMethod') -and $HttpMethod) {
                $resolved = [System.Collections.Generic.List[string]]::new()
                foreach ($m in $HttpMethod) {
                    $null = $resolved.Add((Resolve-PspktHttpMethod -Value $m))
                }
                $httpPredicate.Methods = $resolved.ToArray()
            }

            $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                         [System.Text.RegularExpressions.RegexOptions]::Compiled

            if ($PSBoundParameters.ContainsKey('HttpPath') -and $HttpPath) {
                $combined = ($HttpPath | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $httpPredicate.PathRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            if ($PSBoundParameters.ContainsKey('HttpHost') -and $HttpHost) {
                $combined = ($HttpHost | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $httpPredicate.HostRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            if ($PSBoundParameters.ContainsKey('HttpContentType') -and $HttpContentType) {
                $combined = ($HttpContentType | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $httpPredicate.ContentTypeRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            if ($PSBoundParameters.ContainsKey('HttpStatus') -and $HttpStatus) {
                $codes   = [System.Collections.Generic.List[int]]::new()
                $classes = [System.Collections.Generic.List[int]]::new()
                foreach ($s in $HttpStatus) {
                    $r = Resolve-PspktHttpStatus -Value $s
                    if ($r.Code -ne 0)  { $null = $codes.Add($r.Code) }
                    if ($r.Class -ne 0) { $null = $classes.Add($r.Class) }
                }
                if ($codes.Count   -gt 0) { $httpPredicate.StatusCodes   = $codes.ToArray() }
                if ($classes.Count -gt 0) { $httpPredicate.StatusClasses = $classes.ToArray() }
            }

            $httpPredicate.MatchTruncated = $HttpMatchTruncated.IsPresent

            [PacketLineFormatter]::SetHttpPredicate($httpPredicate)
            Write-Verbose "HTTP predicate active: Methods=$($httpPredicate.Methods -join ','); Path='$($httpPredicate.PathRegex)'; Host='$($httpPredicate.HostRegex)'; ContentType='$($httpPredicate.ContentTypeRegex)'; StatusCodes=$($httpPredicate.StatusCodes -join ','); StatusClasses=$($httpPredicate.StatusClasses -join ','); MatchTruncated=$($httpPredicate.MatchTruncated)"
        }

        if ($dhcpPredicateActive) {
            $dhcpPredicate = [DhcpAppPredicate]::new()

            switch ($DhcpFamily) {
                'V4'    { $dhcpPredicate.Family = 4 }
                'V6'    { $dhcpPredicate.Family = 6 }
                default { $dhcpPredicate.Family = 0 }
            }

            if ($PSBoundParameters.ContainsKey('DhcpMessageType') -and $DhcpMessageType) {
                $v4 = [System.Collections.Generic.List[int]]::new()
                $v6 = [System.Collections.Generic.List[int]]::new()
                foreach ($m in $DhcpMessageType) {
                    $r = Resolve-PspktDhcpMessageType -Value $m
                    if ($null -ne $r.V4) { $null = $v4.Add([int]$r.V4) }
                    if ($null -ne $r.V6) { $null = $v6.Add([int]$r.V6) }
                }
                if ($v4.Count -gt 0) { $dhcpPredicate.V4MessageTypes = $v4.ToArray() }
                if ($v6.Count -gt 0) { $dhcpPredicate.V6MessageTypes = $v6.ToArray() }
            }

            if ($PSBoundParameters.ContainsKey('DhcpClientMac') -and $DhcpClientMac) {
                $combined = ($DhcpClientMac | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                             [System.Text.RegularExpressions.RegexOptions]::Compiled
                $dhcpPredicate.ClientMacRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            $dhcpPredicate.MatchTruncated = $DhcpMatchTruncated.IsPresent

            [PacketLineFormatter]::SetDhcpPredicate($dhcpPredicate)
            Write-Verbose "DHCP predicate active: Family=$($dhcpPredicate.Family); V4MessageTypes=$($dhcpPredicate.V4MessageTypes -join ','); V6MessageTypes=$($dhcpPredicate.V6MessageTypes -join ','); ClientMac='$($dhcpPredicate.ClientMacRegex)'; MatchTruncated=$($dhcpPredicate.MatchTruncated)"
        }

        if ($smbPredicateActive) {
            $smbPredicate = [Smb2AppPredicate]::new()

            switch ($SmbDirection) {
                'Request'  { $smbPredicate.Direction = 0 }
                'Response' { $smbPredicate.Direction = 1 }
                default    { $smbPredicate.Direction = -1 }
            }

            if ($PSBoundParameters.ContainsKey('SmbCommand') -and $SmbCommand) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($c in $SmbCommand) {
                    $null = $resolved.Add((Resolve-PspktSmb2Command -Value $c))
                }
                $smbPredicate.Commands = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('SmbStatus') -and $SmbStatus) {
                $codes   = [System.Collections.Generic.List[uint32]]::new()
                $classes = [System.Collections.Generic.List[int]]::new()
                foreach ($s in $SmbStatus) {
                    $r = Resolve-PspktSmb2Status -Value $s
                    if ($r.Class -ge 0) { $null = $classes.Add([int]$r.Class) }
                    else                { $null = $codes.Add([uint32]$r.Code)  }
                }
                if ($codes.Count   -gt 0) { $smbPredicate.StatusCodes   = $codes.ToArray() }
                if ($classes.Count -gt 0) { $smbPredicate.StatusClasses = $classes.ToArray() }
            }

            $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                         [System.Text.RegularExpressions.RegexOptions]::Compiled

            if ($PSBoundParameters.ContainsKey('SmbFilename') -and $SmbFilename) {
                $combined = ($SmbFilename | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $smbPredicate.FilenameRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            if ($PSBoundParameters.ContainsKey('SmbTreePath') -and $SmbTreePath) {
                $combined = ($SmbTreePath | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $smbPredicate.TreePathRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            $smbPredicate.MatchEncrypted = $SmbMatchEncrypted.IsPresent
            $smbPredicate.MatchTruncated = $SmbMatchTruncated.IsPresent

            [PacketLineFormatter]::SetSmb2Predicate($smbPredicate)
            Write-Verbose "SMB2 predicate active: Direction=$($smbPredicate.Direction); Commands=$($smbPredicate.Commands -join ','); StatusCodes=$($smbPredicate.StatusCodes -join ','); StatusClasses=$($smbPredicate.StatusClasses -join ','); Filename='$($smbPredicate.FilenameRegex)'; TreePath='$($smbPredicate.TreePathRegex)'; MatchEncrypted=$($smbPredicate.MatchEncrypted); MatchTruncated=$($smbPredicate.MatchTruncated)"
        }

        if ($icmpPredicateActive) {
            $icmpPredicate = [IcmpAppPredicate]::new()

            if ($PSBoundParameters.ContainsKey('IcmpType') -and $IcmpType) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($t in $IcmpType) {
                    $null = $resolved.Add((Resolve-PspktIcmp4Type -Value $t))
                }
                $icmpPredicate.V4Types = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('Icmpv6Type') -and $Icmpv6Type) {
                $resolved = [System.Collections.Generic.List[int]]::new()
                foreach ($t in $Icmpv6Type) {
                    $null = $resolved.Add((Resolve-PspktIcmpv6Type -Value $t))
                }
                $icmpPredicate.V6Types = $resolved.ToArray()
            }

            if ($PSBoundParameters.ContainsKey('Icmpv6NdpTarget') -and $Icmpv6NdpTarget) {
                $combined = ($Icmpv6NdpTarget | ForEach-Object { '(?:' + $_ + ')' }) -join '|'
                $regexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                             [System.Text.RegularExpressions.RegexOptions]::Compiled
                $icmpPredicate.NdpTargetRegex = [System.Text.RegularExpressions.Regex]::new($combined, $regexOpts)
            }

            [PacketLineFormatter]::SetIcmpPredicate($icmpPredicate)
            Write-Verbose "ICMP predicate active: V4Types=$($icmpPredicate.V4Types -join ','); V6Types=$($icmpPredicate.V6Types -join ','); NdpTarget='$($icmpPredicate.NdpTargetRegex)'"
        }

        # Populate component name lookup from pktmon.
        try {
            $components = Get-PspktComponent
            Register-PspktComponentMap -Components $components
        } catch {
            Write-Verbose "Could not enumerate components: $_"
        }

        # --- Pcapng file writer setup ---
        $pcapngWriter = $null
        if ($PSBoundParameters.ContainsKey('WriteFile') -and -not [string]::IsNullOrEmpty($WriteFile)) {
            # Resolve the file path to absolute.
            $pcapngPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WriteFile)
            if (-not $pcapngPath.EndsWith('.pcapng', [StringComparison]::OrdinalIgnoreCase)) {
                $pcapngPath = $pcapngPath + '.pcapng'
            }

            # Start pcapng writer (async mode for non-blocking writes from callback).
            $pcapngWriter = [PcapngWriter]::new()

            # Register components for enriched packet comments.
            if ($null -ne $components) {
                foreach ($comp in $components) {
                    if ($null -ne $comp.Id) {
                        $pcapngWriter.RegisterComponent([int]$comp.Id, $comp.Name, $comp.Group, [int]$comp.ParentId)
                        if ($null -ne $comp.SecondaryId -and [int]$comp.SecondaryId -ne [int]$comp.Id) {
                            $pcapngWriter.RegisterComponent([int]$comp.SecondaryId, $comp.Name, $comp.Group, [int]$comp.ParentId)
                        }
                    }
                }
            }

            # Always run the pcapng writer in async (writer thread) mode so file I/O never
            # blocks the pktmon callback. -FlushDisk controls flush frequency only:
            # true = Flush() after every batch (durability), false = flush only on stop (throughput).
            # -FileSize (MiB) + -NumFiles control circular rotation.
            $useAsync = $true
            $ringCap = 65536
            # FileSize parameter is in MiB; convert to bytes. NumFiles > 1 enables rotation.
            [long]$maxBytes = if ($NumFiles -gt 1) { [long]$FileSize * 1MB } else { 0 }
            $pcapngWriter.Start($pcapngPath, $useAsync, $ringCap, $FlushDisk.IsPresent, $maxBytes, [int]$NumFiles)

            # Register with the callback so packets are captured to file.
            [PktMonApi]::FileWriter = $pcapngWriter

            if ($FlushDisk.IsPresent) { $modeLabel = "FlushDisk" } else { $modeLabel = "WriteOnStop" }
            $rotInfo = if ($NumFiles -gt 1) { " [rotation: $NumFiles x $($FileSize)MiB]" } else { '' }
            Write-Host "File writer started: $pcapngPath ($modeLabel)$rotInfo" -ForegroundColor DarkCyan
        }

        try {
          if ($useRealTime) {
            # Determine if pause/stop features are active.
            $pauseEnabled = $Pause.IsPresent -or $PauseOnDrop.IsPresent -or
                $PSBoundParameters.ContainsKey('PauseOnLocation') -or
                $PSBoundParameters.ContainsKey('PauseOnReason') -or
                $StopOnDrop.IsPresent -or
                $PSBoundParameters.ContainsKey('StopOnLocation') -or
                $PSBoundParameters.ContainsKey('StopOnReason')

            # Resolve trigger values at capture start for fast comparison in loop.
            [int]$pauseLocValue = 0
            [int]$pauseReasonValue = 0
            [int]$stopLocValue = 0
            [int]$stopReasonValue = 0
            if ($PSBoundParameters.ContainsKey('PauseOnLocation') -and $PauseOnLocation) {
                $pauseLocValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_LOCATION]) -Value $PauseOnLocation)
            }
            if ($PSBoundParameters.ContainsKey('PauseOnReason') -and $PauseOnReason) {
                $pauseReasonValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_REASON]) -Value $PauseOnReason)
            }
            if ($PSBoundParameters.ContainsKey('StopOnLocation') -and $StopOnLocation) {
                $stopLocValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_LOCATION]) -Value $StopOnLocation)
            }
            if ($PSBoundParameters.ContainsKey('StopOnReason') -and $StopOnReason) {
                $stopReasonValue = [int](Resolve-PspktEnumValue -EnumType ([PKTMON_DROP_REASON]) -Value $StopOnReason)
            }

            $pauseHint = if ($pauseEnabled -and $Pause.IsPresent) { " Press 'p' to pause." } else { '' }
            Write-Host "Capturing packets in real-time. Press Ctrl+C to stop...$pauseHint" -ForegroundColor Cyan
            Write-Host (Get-PspktCaptureHeader)
            # Lock component refresh during capture to prevent stalling the consumer.
            $script:ComponentRefreshLocked = $true
            $sb = [System.Text.StringBuilder]::new(16384)
            $stream = $Session.OutputStream[0]
            $paused = $false
            $stopRequested = $false

            # Use the high-throughput C# bulk-format path for all detail levels.
            # Drop triggers are handled in C# FormatBatch.
            $useBulkFormat = $true
            $bulkLineCounter = 0

            # Configure C# drop triggers for the bulk-format path.
            [PacketLineFormatter]::SetDropTriggers(
                $StopOnDrop.IsPresent,
                $PauseOnDrop.IsPresent,
                $stopReasonValue,
                $stopLocValue,
                $pauseReasonValue,
                $pauseLocValue
            )

            # StopDelay support: when a stop trigger fires we record a deadline and let
            # capture continue normally until it expires. Console + pcapng writer keep
            # running because both run on their own threads and the consumer loop continues
            # to drain/format. We disable further stop triggers in C# so they don't reset
            # the deadline (pause triggers stay active).
            $stopDelayMs = [int]$StopDelay
            $stopDelayActive = $false
            $stopDelayWatch = [System.Diagnostics.Stopwatch]::new()

            # Configure ICMP display filter. pktmon driver filters can't constrain on ICMP type,
            # so -Ping (echo only) and -NDP (types 133-137 only) are enforced at display time.
            $icmpEchoOnly = $Ping.IsPresent -or $Ping4.IsPresent -or $Ping6.IsPresent
            $icmpNdpOnly  = $NDP.IsPresent -or $AA.IsPresent -or $AAv6.IsPresent
            [PacketLineFormatter]::SetIcmpDisplayFilter($icmpEchoOnly, $icmpNdpOnly)

            # Mark capture active so the C# ring buffer wakes its waiter on stop.
            [PktMonApi]::SetCaptureActive($true)

            while ($Session.Active -and -not $stopRequested) {
                # --- Key press handling (non-blocking) ---
                if ($pauseEnabled -and [Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    $ch = [char]::ToLower($key.KeyChar)
                    if (-not $paused -and $ch -eq 'p' -and $Pause.IsPresent) {
                        $paused = $true
                        # Drain remaining ring buffer before showing pause message.
                        $drainCount = $Session.DrainAllRawPackets()
                        if ($drainCount -gt 0) {
                            try {
                                $result = [PacketLineFormatter]::FormatBatch($stream.PacketBuffer, $drainCount, $bulkLineCounter)
                                if ($null -ne $result) {
                                    $bulkLineCounter = $result.LineCounter
                                    $packetCount += $result.PacketCount
                                    $droppedCount += $result.DroppedCount
                                    if ($null -ne $result.Output) { [Console]::Write($result.Output) }
                                }
                            } finally {
                                [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $drainCount)
                            }
                        }
                        Write-Host "=====  Real-time mode is Paused. Press 'r' to resume or 'q' to quit... =====" -ForegroundColor Yellow
                        continue
                    }
                    if ($paused -and $ch -eq 'r') {
                        $paused = $false
                        Write-Host "  Resumed." -ForegroundColor Green
                        continue
                    }
                    if ($paused -and $ch -eq 'q') {
                        $stopRequested = $true
                        continue
                    }
                }

                # --- Paused state: discard packets without counting ---
                if ($paused) {
                    $discarded = $Session.DrainAllRawPackets()
                    if ($discarded -gt 0) {
                        # Return pooled buffers even on discard to prevent pool leak.
                        [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $discarded)
                    } else {
                        # Use the signaled wait (wakes on next packet or timeout).
                        $null = [PktMonApi]::WaitForPackets($PollingIntervalMs)
                    }
                    continue
                }

                # --- Active capture: process packets ---
                # === HIGH-THROUGHPUT C# BULK-FORMAT PATH ===
                # Drains raw PSPacketData and formats entirely in C#.
                # Drop triggers are checked in C# and reported via TriggerAction.
                $pktCount = $Session.DrainAllRawPackets()
                if ($pktCount -gt 0) {
                    try {
                        $result = [PacketLineFormatter]::FormatBatch($stream.PacketBuffer, $pktCount, $bulkLineCounter)
                        if ($null -ne $result) {
                            $bulkLineCounter = $result.LineCounter
                            $packetCount += $result.PacketCount
                            $droppedCount += $result.DroppedCount
                            if ($null -ne $result.Output) {
                                [Console]::Write($result.Output)
                            }

                            # Handle drop trigger actions from C#.
                            if ($result.TriggerAction -eq 2) {
                                if ($stopDelayMs -gt 0 -and -not $stopDelayActive) {
                                    # Stop trigger fired with -StopDelay set — keep capturing.
                                    # Disable further stop triggers in C# so the same packet
                                    # type doesn't restart the deadline; pause triggers stay.
                                    [PacketLineFormatter]::SetDropTriggers(
                                        $false,
                                        $PauseOnDrop.IsPresent,
                                        0,
                                        0,
                                        $pauseReasonValue,
                                        $pauseLocValue
                                    )
                                    $stopDelayWatch.Restart()
                                    $stopDelayActive = $true
                                    Write-Host "Stop trigger fired; continuing capture for $stopDelayMs ms before stopping..." -ForegroundColor Yellow
                                } elseif (-not $stopDelayActive) {
                                    # No StopDelay — original behavior, stop immediately.
                                    $stopRequested = $true
                                }
                                # If $stopDelayActive is already true, ignore further stop triggers
                                # (the deadline check below will end the capture when it expires).
                            } elseif ($result.TriggerAction -eq 1 -and -not $paused) {
                                # Pause trigger fired — drain remaining and enter pause.
                                $paused = $true
                                $drainCount = $Session.DrainAllRawPackets()
                                if ($drainCount -gt 0) {
                                    try {
                                        $drainResult = [PacketLineFormatter]::FormatBatch($stream.PacketBuffer, $drainCount, $bulkLineCounter)
                                        if ($null -ne $drainResult) {
                                            $bulkLineCounter = $drainResult.LineCounter
                                            $packetCount += $drainResult.PacketCount
                                            $droppedCount += $drainResult.DroppedCount
                                            if ($null -ne $drainResult.Output) { [Console]::Write($drainResult.Output) }
                                        }
                                    } finally {
                                        [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $drainCount)
                                    }
                                }
                                Write-Host "=====  Real-time mode is Paused. Press 'r' to resume or 'q' to quit... =====" -ForegroundColor Yellow
                            }
                        }
                    } finally {
                        # Always return pooled buffers, even on exception or trigger.
                        [PktMonApi]::ReturnPacketBuffers($stream.PacketBuffer, $pktCount)
                    }
                } else {
                    # No packets available — wait for the producer to signal or timeout.
                    # This eliminates the fixed PollingIntervalMs latency floor and idle CPU usage.
                    $null = [PktMonApi]::WaitForPackets($PollingIntervalMs)
                }

                # StopDelay deadline check — runs every iteration regardless of packet count
                # so an idle delay-period still terminates promptly.
                if ($stopDelayActive -and $stopDelayWatch.ElapsedMilliseconds -ge $stopDelayMs) {
                    $stopRequested = $true
                }
            }
          } elseif ($hasWriteEtl) {
            # --- ETL file mode: use pktmon CLI ---
            $etlPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WriteEtl)
            if (-not $etlPath.EndsWith('.etl', [StringComparison]::OrdinalIgnoreCase)) {
                $etlPath = $etlPath + '.etl'
            }

            # Build pktmon start arguments.
            $pktmonArgs = @('start', '--capture')
            $pktmonArgs += '--file-name', $etlPath
            $pktmonArgs += '--file-size', $FileSize.ToString()
            $pktmonArgs += '--pkt-size', $Session.PacketSize.ToString()
            $pktmonArgs += '--log-mode', 'circular'

            # Add component filter if specific components were selected.
            if ($PSBoundParameters.ContainsKey('Component') -and $Component.Count -ge 1 -and $Component[0] -ne 'All') {
                $pktmonArgs += '--comp'
                $pktmonArgs += $Component
            }

            # Stop any existing pktmon session before starting.
            $null = pktmon stop 2>$null

            # We don't need the pspkt session for ETL mode — tear it down.
            Stop-Pspkt -Session $Session -Teardown

            Write-Host "Starting ETL capture: $etlPath" -ForegroundColor Cyan
            $pktmonOutput = & pktmon @pktmonArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "pktmon start failed (exit $LASTEXITCODE): $pktmonOutput"
            }
            Write-Host "ETL capture active. Use 'pktmon stop' to stop and save the file." -ForegroundColor Cyan
            Write-Host $pktmonOutput -ForegroundColor DarkGray
            return
          } else {
            # --- File-only mode (pcapng): return session to console ---
            Write-Host "Capturing to file: $pcapngPath" -ForegroundColor Cyan
            Write-Host "Use Stop-Pspkt to stop capture and save the file." -ForegroundColor Cyan
            return $Session
          }
        }
        finally {
            $script:ComponentRefreshLocked = $false

            # Clear any application-layer predicate so it can't leak into a later capture.
            [PacketLineFormatter]::ClearAppPredicates()

            # Mark capture inactive (wakes any consumer/writer waiters).
            [PktMonApi]::SetCaptureActive($false)

            # Stop pcapng file writer if active.
            if ($null -ne $pcapngWriter -and $pcapngWriter.IsActive) {
                [PktMonApi]::FileWriter = $null
                $pcapngWriter.Stop()
                $fileDrops = $pcapngWriter.FileDroppedCount
                $dropSuffix = if ($fileDrops -gt 0) { "; FileDrops: $fileDrops" } else { '' }
                Write-Host "File saved: $($pcapngWriter.FileName) ($($pcapngWriter.PacketCount) packets$dropSuffix)" -ForegroundColor DarkCyan
                if ($fileDrops -gt 0) {
                    Write-Warning "Pcapng file writer dropped $fileDrops packet(s) because the writer thread couldn't keep up. The file is missing data - consider a faster disk, larger -BufferSizeMultiplier, or remove -FlushDisk."
                }
                $lastErr = $pcapngWriter.LastError
                if (-not [string]::IsNullOrEmpty($lastErr)) {
                    Write-Warning "Pcapng writer reported an error: $lastErr"
                }
            }

            if ($useRealTime) {
                $missedWrite = [PacketData]::MissedPacketWriteCount
                $missedRead  = [PacketData]::MissedPacketReadCount
                $missedTotal = $missedWrite + $missedRead
                $bufferDropped = [PktMonApi]::DroppedCount
                Write-Host "`nStopping capture... [Captured: $packetCount; Drops: $droppedCount; Missed: $missedTotal; BufferOverflow: $bufferDropped]" -ForegroundColor Cyan

                # Session summary: list components that appeared in capture.
                $seenIds = [PktMonApi]::GetSeenComponentIds()
                if ($seenIds.Count -gt 0 -and $null -ne $components) {
                    Write-Host "`nComponents:" -ForegroundColor DarkGray
                    foreach ($comp in $components) {
                        if ([int]$comp.Id -in $seenIds) {
                            $compLine = "  {0}:{1} {2}" -f [int]$comp.ParentId, [int]$comp.Id, $comp.Name
                            Write-Host $compLine -ForegroundColor DarkGray
                        }
                    }
                }

                # List filters used in this session.
                if ($Session.Filters.Count -gt 0) {
                    Write-Host "Filters:" -ForegroundColor DarkGray
                    foreach ($f in $Session.Filters) {
                        Write-Host "  $($f.Name)" -ForegroundColor DarkGray
                    }
                }
            } else {
                Write-Host "`nStopping capture..." -ForegroundColor Cyan
            }
            Stop-Pspkt -Session $Session -Teardown
        }
    }
}

<#
.SYNOPSIS
Stops a packet monitor session.

.DESCRIPTION
Deactivates the session. With -Teardown, also closes all real-time streams,
the session handle, and uninitializes the pktmon API.

Without -Teardown the session can be restarted with Start-Pspkt.
With -Teardown the session object is no longer usable.

.PARAMETER Session
The pspktSession to stop.

.PARAMETER Teardown
Fully close the session and release all native resources. The session
object cannot be reused after teardown.

.OUTPUTS
pspktSession (without -Teardown) or nothing (with -Teardown).
#>
function Stop-Pspkt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $false)]
        [switch]
        $Teardown
    )

    process {
        if ($Teardown) {
            # Deactivate if still active.
            if ($Session.Active -and $Session.Handle -ne [IntPtr]::Zero) {
                $Session.SetSessionActive($false)
            }

            # Close all attached real-time streams (snapshot to avoid mutation during enumeration).
            if ($null -ne $Session.Pspkt) {
                $streams = @($Session.OutputStream)
                foreach ($stream in $streams) {
                    if ($null -ne $stream -and $stream.Handle -ne [IntPtr]::Zero) {
                        $Session.Pspkt.PacketMonitorCloseRealtimeStream($stream)
                    }
                }
            }

            # Reset the SPSC ring buffer dropped counter for a clean next session.
            [PktMonApi]::ResetDroppedCount()

            # Close the session handle.
            if ($Session.Handle -ne [IntPtr]::Zero) {
                if ($null -ne $Session.Pspkt) {
                    $Session.Pspkt.PacketMonitorCloseSessionHandle($Session)
                } else {
                    $Session.CloseSessionHandle()
                }
            }

            # Uninitialize the pktmon API.
            if ($null -ne $Session.Pspkt) {
                $Session.Pspkt.PacketMonitorUninitialize()
                $Session.Pspkt = $null
            }

            return
        }

        # Simple stop — deactivate only.
        if (-not $Session.Active) {
            Write-Verbose "Session '$($Session.Name)' is already inactive."
            return $Session
        }

        if ($Session.Handle -eq [IntPtr]::Zero) {
            throw "Session '$($Session.Name)' has a null handle."
        }

        $Session.SetSessionActive($false)

        # Stop pcapng file writer if still active.
        $fw = [PktMonApi]::FileWriter
        if ($null -ne $fw -and $fw.IsActive) {
            [PktMonApi]::FileWriter = $null
            $fw.Stop()
            $fileDrops = $fw.FileDroppedCount
            $dropSuffix = if ($fileDrops -gt 0) { "; FileDrops: $fileDrops" } else { '' }
            Write-Host "File saved: $($fw.FileName) ($($fw.PacketCount) packets$dropSuffix)" -ForegroundColor DarkCyan
            if ($fileDrops -gt 0) {
                Write-Warning "Pcapng file writer dropped $fileDrops packet(s) because the writer thread couldn't keep up."
            }
            $lastErr = $fw.LastError
            if (-not [string]::IsNullOrEmpty($lastErr)) {
                Write-Warning "Pcapng writer reported an error: $lastErr"
            }
        }

        return $Session
    }
}

Set-Alias -Name pspkt -Value Start-Pspkt

# --------------------------------------------------------------------------
# Get-PspktQuickFilter — discovery cmdlet for quick filters and app predicates
# --------------------------------------------------------------------------

<#
.SYNOPSIS
Displays all available quick filters and their associated application-layer
filter parameters in a tree view.

.DESCRIPTION
Get-PspktQuickFilter outputs a formatted tree showing every quick filter
switch available on Start-Pspkt, grouped by protocol family. Under each
quick filter that has associated application-layer predicate parameters,
the predicate parameters are listed as child nodes.

This is a discovery / help tool — it does not modify any session state.

.PARAMETER Protocol
Optional filter to show only a specific protocol family. Accepts one or
more names (e.g. 'DNS', 'SMB', 'ICMP'). When omitted, all protocols are
shown.

.EXAMPLE
Get-PspktQuickFilter

Shows the full tree of all quick filters and app-layer predicates.

.EXAMPLE
Get-PspktQuickFilter -Protocol DNS, TLS

Shows only the DNS and TLS quick filters with their predicates.

.OUTPUTS
System.String
Formatted tree-view text written to the output stream.
#>
function Get-PspktQuickFilter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet('ARP','NDP','AA','AAv4','AAv6','DHCP','DHCPv6','DNS','DNSoverHTTPS','DNSoverTLS','SMB','SMBoverQUIC','SSH','RDP','RPC','RCP','HTTP','HTTPS','WinRM','WinRMS','Ping','Ping4','Ping6','TLS','ICMP')]
        [string[]]
        $Protocol
    )

    # Define the complete tree structure. Each entry is a hashtable:
    #   Name, Desc, Alias, Tags, Params (array of PSCustomObjects with .N .T .D)
    # PSCustomObject avoids PS array-flattening that destroys nested arrays.
    $tree = [ordered]@{
        'Network Layer' = @(
            @{
                Name   = '-ARP'
                Desc   = 'EtherType ARP'
                Alias  = $null
                Params = @()
                Tags   = @('ARP')
            }
        )

        'ICMPv4 / ICMPv6 / NDP' = @(
            @{
                Name   = '-Ping'
                Desc   = 'ICMPv4 + ICMPv6 (echo types only)'
                Alias  = $null
                Params = @()
                Tags   = @('Ping','ICMP')
            }
            @{
                Name   = '-Ping4'
                Desc   = 'ICMPv4 echo only'
                Alias  = $null
                Params = @()
                Tags   = @('Ping4','ICMP')
            }
            @{
                Name   = '-Ping6'
                Desc   = 'ICMPv6 echo only'
                Alias  = $null
                Params = @()
                Tags   = @('Ping6','ICMP')
            }
            @{
                Name   = '-NDP'
                Desc   = 'IPv6 ICMPv6 (NDP types 133-137 only)'
                Alias  = $null
                Params = @()
                Tags   = @('NDP','ICMP')
            }
            @{
                Name   = '(ICMP app filters)'
                Desc   = 'Application-layer predicates for ICMP/ICMPv6/NDP'
                Alias  = $null
                Params = @(
                    [pscustomobject]@{ N = '-IcmpType';        T = 'string[]'; D = 'ICMPv4 type name, hex, or int (arrays OK)' }
                    [pscustomobject]@{ N = '-Icmpv6Type';      T = 'string[]'; D = 'ICMPv6 type name, hex, or int (arrays OK)' }
                    [pscustomobject]@{ N = '-Icmpv6NdpTarget'; T = 'string';   D = 'IPv6 target address in NS/NA frames' }
                )
                Tags   = @('ICMP','NDP','Ping','Ping4','Ping6')
            }
        )

        'Address Resolution' = @(
            @{
                Name   = '-AA'
                Desc   = 'NDP + DHCP + DHCPv6'
                Alias  = $null
                Params = @()
                Tags   = @('AA')
            }
            @{
                Name   = '-AAv4'
                Desc   = 'DHCP (IPv4 only)'
                Alias  = $null
                Params = @()
                Tags   = @('AAv4')
            }
            @{
                Name   = '-AAv6'
                Desc   = 'NDP + DHCPv6'
                Alias  = $null
                Params = @()
                Tags   = @('AAv6')
            }
            @{
                Name   = '-DHCP'
                Desc   = 'UDP/IPv4 ports 67+68'
                Alias  = $null
                Params = @(
                    [pscustomobject]@{ N = '-DhcpMessageType';    T = 'string[]'; D = 'DHCP message type name or number (v4 and/or v6)' }
                    [pscustomobject]@{ N = '-DhcpClientMac';      T = 'string';   D = 'Client hardware address (chaddr) regex' }
                    [pscustomobject]@{ N = '-DhcpFamily';         T = 'string';   D = 'V4, V6, or Both (default: Both)' }
                    [pscustomobject]@{ N = '-DhcpMatchTruncated'; T = 'switch';   D = 'Include packets too short to fully parse' }
                )
                Tags   = @('DHCP','AA','AAv4')
            }
            @{
                Name   = '-DHCPv6'
                Desc   = 'UDP/IPv6 ports 546+547'
                Alias  = $null
                Params = @()
                Tags   = @('DHCPv6','AA','AAv6')
            }
        )

        'DNS' = @(
            @{
                Name   = '-DNS'
                Desc   = 'TCP+UDP port 53'
                Alias  = $null
                Params = @(
                    [pscustomobject]@{ N = '-DnsName';           T = 'string';   D = 'Query/response name regex' }
                    [pscustomobject]@{ N = '-DnsType';           T = 'string[]'; D = 'DNS RR type name or number (arrays OK)' }
                    [pscustomobject]@{ N = '-DnsRcode';          T = 'string[]'; D = 'Response code name or number (arrays OK)' }
                    [pscustomobject]@{ N = '-DnsId';             T = 'uint16[]'; D = 'Transaction ID(s)' }
                    [pscustomobject]@{ N = '-DnsQR';             T = 'string';   D = 'Query or Response' }
                    [pscustomobject]@{ N = '-DnsMatchTruncated'; T = 'switch';   D = 'Include packets too short to fully parse' }
                )
                Tags   = @('DNS')
            }
            @{
                Name   = '-DNSoverHTTPS'
                Desc   = 'TCP port 443'
                Alias  = '-DoH'
                Params = @()
                Tags   = @('DNSoverHTTPS')
            }
            @{
                Name   = '-DNSoverTLS'
                Desc   = 'TCP port 853'
                Alias  = '-DoT'
                Params = @()
                Tags   = @('DNSoverTLS')
            }
        )

        'TLS / HTTPS' = @(
            @{
                Name   = '-HTTPS'
                Desc   = 'TCP port 443'
                Alias  = $null
                Params = @(
                    [pscustomobject]@{ N = '-TlsSni';             T = 'string';   D = 'Server Name Indication regex' }
                    [pscustomobject]@{ N = '-TlsVersion';         T = 'string[]'; D = 'TLS version (e.g. TLS12, TLS13)' }
                    [pscustomobject]@{ N = '-TlsContentType';     T = 'string[]'; D = 'Record content type name or number' }
                    [pscustomobject]@{ N = '-TlsHandshakeType';   T = 'string[]'; D = 'Handshake message type name or number' }
                    [pscustomobject]@{ N = '-TlsMatchTruncated';  T = 'switch';   D = 'Include packets too short to fully parse' }
                )
                Tags   = @('HTTPS','TLS')
            }
        )

        'HTTP' = @(
            @{
                Name   = '-HTTP'
                Desc   = 'TCP port 80'
                Alias  = $null
                Params = @(
                    [pscustomobject]@{ N = '-HttpMethod';         T = 'string[]'; D = 'HTTP method (GET, POST, etc.)' }
                    [pscustomobject]@{ N = '-HttpHost';           T = 'string';   D = 'Host header regex' }
                    [pscustomobject]@{ N = '-HttpPath';           T = 'string';   D = 'Request path regex' }
                    [pscustomobject]@{ N = '-HttpStatus';         T = 'int[]';    D = 'Response status code(s)' }
                    [pscustomobject]@{ N = '-HttpContentType';    T = 'string';   D = 'Content-Type header regex' }
                    [pscustomobject]@{ N = '-HttpMatchTruncated'; T = 'switch';   D = 'Include packets too short to fully parse' }
                )
                Tags   = @('HTTP')
            }
        )

        'SMB / File Sharing' = @(
            @{
                Name   = '-SMB'
                Desc   = 'TCP ports 445 (SMB) + 88 (Kerberos)'
                Alias  = $null
                Params = @(
                    [pscustomobject]@{ N = '-SmbCommand';        T = 'string[]'; D = 'SMB2 command name or number (arrays OK)' }
                    [pscustomobject]@{ N = '-SmbDirection';      T = 'string';   D = 'Request or Response' }
                    [pscustomobject]@{ N = '-SmbStatus';         T = 'string[]'; D = 'NT status code, hex, or class name (arrays OK)' }
                    [pscustomobject]@{ N = '-SmbFilename';       T = 'string';   D = 'Filename regex (from Create requests)' }
                    [pscustomobject]@{ N = '-SmbTreePath';       T = 'string';   D = 'Tree path regex (from TreeConnect)' }
                    [pscustomobject]@{ N = '-SmbMatchEncrypted'; T = 'switch';   D = 'Include encrypted (SMB 3.x) packets' }
                    [pscustomobject]@{ N = '-SmbMatchTruncated'; T = 'switch';   D = 'Include packets too short to fully parse' }
                )
                Tags   = @('SMB')
            }
            @{
                Name   = '-SMBoverQUIC'
                Desc   = 'UDP port 443 (or -SMBoverQuicAltPort)'
                Alias  = '-SoQ'
                Params = @()
                Tags   = @('SMBoverQUIC')
            }
        )

        'Remote Access' = @(
            @{
                Name   = '-SSH'
                Desc   = 'TCP port 22'
                Alias  = $null
                Params = @()
                Tags   = @('SSH')
            }
            @{
                Name   = '-RDP'
                Desc   = 'TCP port 3389'
                Alias  = $null
                Params = @()
                Tags   = @('RDP')
            }
            @{
                Name   = '-WinRM'
                Desc   = 'TCP port 5985'
                Alias  = $null
                Params = @()
                Tags   = @('WinRM')
            }
            @{
                Name   = '-WinRMS'
                Desc   = 'TCP port 5986'
                Alias  = $null
                Params = @()
                Tags   = @('WinRMS')
            }
        )

        'Infrastructure' = @(
            @{
                Name   = '-RPC'
                Desc   = 'TCP port 135'
                Alias  = $null
                Params = @()
                Tags   = @('RPC')
            }
            @{
                Name   = '-RCP'
                Desc   = 'TCP+UDP port 3343 (Cluster RCP)'
                Alias  = $null
                Params = @()
                Tags   = @('RCP')
            }
        )
    }

    # Filter by -Protocol if specified.
    $filteredTree = [ordered]@{}
    foreach ($group in $tree.Keys) {
        $entries = $tree[$group]
        if ($null -ne $Protocol -and $Protocol.Count -gt 0) {
            $matched = @()
            foreach ($entry in $entries) {
                foreach ($tag in $entry.Tags) {
                    if ($tag -in $Protocol) {
                        $matched += $entry
                        break
                    }
                }
            }
            if ($matched.Count -gt 0) {
                $filteredTree[$group] = $matched
            }
        } else {
            $filteredTree[$group] = $entries
        }
    }

    if ($filteredTree.Count -eq 0) {
        Write-Host "No quick filters match the specified protocol filter." -ForegroundColor Yellow
        return
    }

    # Render the tree.
    $lines = [System.Collections.ArrayList]::new()
    $null = $lines.Add('')
    $null = $lines.Add("  $([char]0x250C)$([char]0x2500) Quick Filters and Application-Layer Predicates")
    $null = $lines.Add("  $([char]0x2502)")

    $groupKeys = @($filteredTree.Keys)
    for ($gi = 0; $gi -lt $groupKeys.Count; $gi++) {
        $groupName = $groupKeys[$gi]
        $entries   = $filteredTree[$groupName]
        $isLastGroup = ($gi -eq $groupKeys.Count - 1)
        $groupPrefix = if ($isLastGroup) { [char]0x2514 } else { [char]0x251C }  # └ or ├
        $groupLine   = if ($isLastGroup) { ' ' } else { [char]0x2502 }           # │ or space

        $null = $lines.Add("  $groupPrefix$([char]0x2500)$([char]0x2500) $groupName")

        for ($ei = 0; $ei -lt $entries.Count; $ei++) {
            $entry = $entries[$ei]
            $isLastEntry = ($ei -eq $entries.Count - 1)
            $entryPrefix = if ($isLastEntry) { [char]0x2514 } else { [char]0x251C }
            $entryLine   = if ($isLastEntry) { ' ' } else { [char]0x2502 }

            $aliasStr = if ($entry.Alias) { " (alias: $($entry.Alias))" } else { '' }
            $nameStr  = "$($entry.Name)$aliasStr"
            $null = $lines.Add("  $groupLine   $entryPrefix$([char]0x2500)$([char]0x2500) $nameStr  $([char]0x2500)$([char]0x2500) $($entry.Desc)")

            if ($entry.Params.Count -gt 0) {
                $null = $lines.Add("  $groupLine   $entryLine       Application-layer filters:")
                for ($pi = 0; $pi -lt $entry.Params.Count; $pi++) {
                    $p = $entry.Params[$pi]
                    $isLastParam = ($pi -eq $entry.Params.Count - 1)
                    $paramPrefix = if ($isLastParam) { [char]0x2514 } else { [char]0x251C }
                    $paramName = $p.N
                    $paramType = $p.T
                    $paramDesc = $p.D
                    $null = $lines.Add("  $groupLine   $entryLine       $paramPrefix$([char]0x2500) $paramName <$paramType>  $([char]0x2500) $paramDesc")
                }
            }
        }
    }

    $null = $lines.Add('')
    $null = $lines.Add("  Tip: Application-layer filters auto-imply the parent quick filter if")
    $null = $lines.Add("  not already covered. Use 'Get-Help Start-Pspkt -Parameter Dns*' for")
    $null = $lines.Add("  full parameter documentation, or see wiki/Application-Filters.md.")
    $null = $lines.Add('')

    $output = $lines -join "`n"
    $output
}

Export-ModuleMember -Function New-PspktSession, Get-PspktSession, Set-PspktSession, Start-Pspkt, Stop-Pspkt, Get-PspktQuickFilter -Alias pspkt
