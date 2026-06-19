using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

[CmdletBinding()]
param ()

<#
.SYNOPSIS
Resolves a string, enum, or numeric value to the target enum type.

.DESCRIPTION
Accepts enum instances, enum name strings (case-insensitive), decimal integers, and hex strings (0x prefix).
Returns the resolved enum value. Throws on unrecognized input.

.PARAMETER Value
The input value to resolve.

.PARAMETER EnumType
The target enum type (e.g., [ETHERTYPE]).
#>
function Resolve-PspktEnumValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]
        $Value,

        [Parameter(Mandatory = $true)]
        [type]
        $EnumType
    )

    # already the target enum
    if ($Value.GetType() -eq $EnumType) {
        return $Value
    }

    if ($Value -is [string]) {
        # try enum name parse (case-insensitive)
        try {
            return [Enum]::Parse($EnumType, $Value, $true)
        } catch {}

        # try with common pktmon prefixes (allows e.g. 'INET_EndpointNotFound' instead of 'PktMonDrop_INET_EndpointNotFound')
        $prefixes = @('PktMonDrop_', 'PMLOC_')
        foreach ($prefix in $prefixes) {
            try {
                return [Enum]::Parse($EnumType, $prefix + $Value, $true)
            } catch {}
        }

        # try numeric string — PS LanguagePrimitives handles decimal and 0x hex
        try {
            $numeric = [System.Management.Automation.LanguagePrimitives]::ConvertTo($Value, [int])
            return [Enum]::ToObject($EnumType, $numeric)
        } catch {}

        $names = [Enum]::GetNames($EnumType) -join ', '
        throw "Cannot convert '$Value' to [$($EnumType.Name)]. Valid names: $names"
    }

    # numeric input
    try {
        return [Enum]::ToObject($EnumType, $Value)
    } catch {
        throw "Cannot convert '$Value' (type: $($Value.GetType().Name)) to [$($EnumType.Name)]."
    }
}

<#
.SYNOPSIS
Applies bound filter parameters to an existing pspktFilter object.

.DESCRIPTION
Internal helper used by New-PspktFilter and Set-PspktFilter.

.PARAMETER Filter
The filter instance to update.
#>
function Update-PspktFilterInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pspktFilter]
        $Filter,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac2,

        [Parameter(Mandatory = $false)]
        [uint16]
        $VlanId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $EtherType,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $DSCP,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $TransportProtocol,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Net.IPAddress]
        $Ip1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Net.IPAddress]
        $Ip2,

        [Parameter(Mandatory = $false)]
        [byte]
        $PrefixLength1,

        [Parameter(Mandatory = $false)]
        [byte]
        $PrefixLength2,

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port1,

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port2,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $TCPFlags,

        [Parameter(Mandatory = $false)]
        [uint16]
        $VxLanPort,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $EncapType
    )

    if ($PSBoundParameters.ContainsKey('Name')) {
        $Filter.Name = $Name
    }

    if ($PSBoundParameters.ContainsKey('Mac1')) {
        if ($null -eq $Mac1) { throw "Mac1 cannot be null when specified." }
        if ($Mac1 -is [byte[]]) {
            $Filter.SetMac1([byte[]]$Mac1)
        }
        elseif ($Mac1 -is [string]) {
            $Filter.SetMac1([string]$Mac1)
        }
        else {
            throw "Mac1 must be a byte[] or string."
        }
    }

    if ($PSBoundParameters.ContainsKey('Mac2')) {
        if ($null -eq $Mac2) { throw "Mac2 cannot be null when specified." }
        if ($Mac2 -is [byte[]]) {
            $Filter.SetMac2([byte[]]$Mac2)
        }
        elseif ($Mac2 -is [string]) {
            $Filter.SetMac2([string]$Mac2)
        }
        else {
            throw "Mac2 must be a byte[] or string."
        }
    }

    if ($PSBoundParameters.ContainsKey('VlanId')) {
        $Filter.SetVlanId([uint16]$VlanId)
    }

    if ($PSBoundParameters.ContainsKey('EtherType')) {
        if ($null -eq $EtherType) { throw "EtherType cannot be null when specified." }
        $resolved = Resolve-PspktEnumValue -Value $EtherType -EnumType ([ETHERTYPE])
        $Filter.SetEtherType([ETHERTYPE]$resolved)
    }

    if ($PSBoundParameters.ContainsKey('DSCP')) {
        if ($null -eq $DSCP) { throw "DSCP cannot be null when specified." }
        $resolved = Resolve-PspktEnumValue -Value $DSCP -EnumType ([DSCP])
        $Filter.SetDSCP([DSCP]$resolved)
    }

    if ($PSBoundParameters.ContainsKey('TransportProtocol')) {
        if ($null -eq $TransportProtocol) { throw "TransportProtocol cannot be null when specified." }
        $resolved = Resolve-PspktEnumValue -Value $TransportProtocol -EnumType ([IPv4Protocol])
        $Filter.SetTransportProtocol([IPv4Protocol]$resolved)
    }

    if ($PSBoundParameters.ContainsKey('Ip1')) {
        $Filter.SetIp1([System.Net.IPAddress]$Ip1)
    }

    if ($PSBoundParameters.ContainsKey('Ip2')) {
        $Filter.SetIp2([System.Net.IPAddress]$Ip2)
    }

    if ($PSBoundParameters.ContainsKey('PrefixLength1')) {
        $Filter.SetPrefixLength1([byte]$PrefixLength1)
    }

    if ($PSBoundParameters.ContainsKey('PrefixLength2')) {
        $Filter.SetPrefixLength2([byte]$PrefixLength2)
    }

    if ($PSBoundParameters.ContainsKey('Port1')) {
        $Filter.SetPort1([uint16]$Port1)
    }

    if ($PSBoundParameters.ContainsKey('Port2')) {
        $Filter.SetPort2([uint16]$Port2)
    }

    if ($PSBoundParameters.ContainsKey('TCPFlags')) {
        if ($null -eq $TCPFlags) { throw "TCPFlags cannot be null when specified." }
        $resolved = Resolve-PspktEnumValue -Value $TCPFlags -EnumType ([TCPFLAGS])
        $Filter.SetTCPFlags([TCPFLAGS]$resolved)
    }

    if ($PSBoundParameters.ContainsKey('VxLanPort')) {
        $Filter.SetVxLanPort([uint16]$VxLanPort)
    }

    if ($PSBoundParameters.ContainsKey('EncapType')) {
        if ($null -eq $EncapType) { throw "EncapType cannot be null when specified." }
        $resolved = Resolve-PspktEnumValue -Value $EncapType -EnumType ([PKTMON_FILTER_ENCAPTYPE])
        $Filter.SetEncapType([PKTMON_FILTER_ENCAPTYPE]$resolved)
    }

    return $Filter
}

<#
.SYNOPSIS
Creates a new pspktFilter instance.

.DESCRIPTION
Constructs a filter object and sets only the properties specified via parameters.

.OUTPUTS
pspktFilter
#>
function New-PspktFilter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac2,

        [Parameter(Mandatory = $false)]
        [uint16]
        $VlanId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $EtherType,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $DSCP,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $TransportProtocol,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Net.IPAddress]
        $Ip1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Net.IPAddress]
        $Ip2,

        [Parameter(Mandatory = $false)]
        [byte]
        $PrefixLength1,

        [Parameter(Mandatory = $false)]
        [byte]
        $PrefixLength2,

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port1,

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port2,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $TCPFlags,

        [Parameter(Mandatory = $false)]
        [uint16]
        $VxLanPort,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $EncapType
    )

    $filter = [pspktFilter]::new()

    return (Update-PspktFilterInternal @PSBoundParameters -Filter $filter)
}

<#
.SYNOPSIS
Updates an existing pspktFilter.

.DESCRIPTION
Accepts a filter from parameter or pipeline and applies any bound filter fields.

.PARAMETER Filter
The filter to modify.

.OUTPUTS
pspktFilter
#>
function Set-PspktFilter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktFilter]
        $Filter,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac2,

        [Parameter(Mandatory = $false)]
        [uint16]
        $VlanId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $EtherType,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $DSCP,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $TransportProtocol,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Net.IPAddress]
        $Ip1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Net.IPAddress]
        $Ip2,

        [Parameter(Mandatory = $false)]
        [byte]
        $PrefixLength1,

        [Parameter(Mandatory = $false)]
        [byte]
        $PrefixLength2,

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port1,

        [Parameter(Mandatory = $false)]
        [uint16]
        $Port2,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $TCPFlags,

        [Parameter(Mandatory = $false)]
        [uint16]
        $VxLanPort,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $EncapType
    )

    process {
        Update-PspktFilterInternal @PSBoundParameters
    }
}

<#
.SYNOPSIS
Adds a filter to a session.

.DESCRIPTION
Attaches one or more pspktFilter objects to a pspktSession. Accepts either a
pre-built filter via -Filter (pipeline-bindable) or one or more quick-filter
switches (-DNS, -SMB, -ARP, etc.) that auto-create the corresponding capture
filters — the same ones Start-Pspkt generates.

When the session has VM scoping set (VMName/VMMacAddresses), all added filters
are automatically AND-combined with each vmNIC MAC.

.PARAMETER Session
Session that receives the filter(s).

.PARAMETER Filter
Pre-built pspktFilter to add (accepts pipeline input).

.PARAMETER ARP
Quick filter: EtherType ARP.

.PARAMETER NDP
Quick filter: IPv6 ICMPv6 (NDP types 133-137).

.PARAMETER DHCP
Quick filter: UDP/IPv4 ports 67+68.

.PARAMETER DHCPv6
Quick filter: UDP/IPv6 ports 546+547.

.PARAMETER DNS
Quick filter: TCP+UDP port 53.

.PARAMETER DNSoverHTTPS
Quick filter: TCP port 443.

.PARAMETER DNSoverTLS
Quick filter: TCP port 853.

.PARAMETER SMB
Quick filter: TCP ports 445+88.

.PARAMETER HTTP
Quick filter: TCP port 80.

.PARAMETER HTTPS
Quick filter: TCP port 443.

.PARAMETER SSH
Quick filter: TCP port 22.

.PARAMETER RDP
Quick filter: TCP port 3389.

.PARAMETER RPC
Quick filter: TCP port 135.

.PARAMETER Ping
Quick filter: ICMPv4+ICMPv6.

.PARAMETER Ping4
Quick filter: ICMPv4 only.

.PARAMETER Ping6
Quick filter: ICMPv6 only.

.PARAMETER WinRM
Quick filter: TCP port 5985.

.PARAMETER WinRMS
Quick filter: TCP port 5986.

.PARAMETER IPAddress
Quick IP filter. AND-merged into each generated filter.

.PARAMETER PassThru
Returns the session object.
#>
function Add-PspktFilter {
    [CmdletBinding(DefaultParameterSetName = 'ByFilter')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ByFilter')]
        [ValidateNotNull()]
        [pspktFilter]
        $Filter,

        # Quick-filter switches
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$ARP,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$NDP,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$DHCP,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$DHCPv6,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$DNS,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$DNSoverHTTPS,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$DNSoverTLS,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$SMB,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$HTTP,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$HTTPS,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$SSH,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$RDP,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$RPC,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$Ping,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$Ping4,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$Ping6,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$WinRM,
        [Parameter(ParameterSetName = 'QuickFilter')][switch]$WinRMS,

        [Parameter(ParameterSetName = 'QuickFilter')]
        [Alias('i')]
        [string]$IPAddress,

        [Parameter(Mandatory = $false)]
        [switch]
        $PassThru
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByFilter') {
            $Session.AddFilter($Filter)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'QuickFilter') {
            $quickFilters = [System.Collections.ArrayList]::new()

            if ($ARP.IsPresent)         { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP')) }
            if ($NDP.IsPresent)         { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-NDP' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP')) }
            if ($DHCP.IsPresent)        {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-Client' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 68))
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCP-Server' -TransportProtocol 'UDP' -EtherType 'IPv4' -Port1 67))
            }
            if ($DHCPv6.IsPresent)      {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-Client' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 546))
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DHCPv6-Server' -TransportProtocol 'UDP' -EtherType 'IPv6' -Port1 547))
            }
            if ($DNS.IsPresent)         {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-UDP' -TransportProtocol 'UDP' -Port1 53))
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DNS-TCP' -TransportProtocol 'TCP' -Port1 53))
            }
            if ($DNSoverHTTPS.IsPresent) { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DoH' -TransportProtocol 'TCP' -Port1 443)) }
            if ($DNSoverTLS.IsPresent)   { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-DoT' -TransportProtocol 'TCP' -Port1 853)) }
            if ($SMB.IsPresent)         {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SMB' -TransportProtocol 'TCP' -Port1 445))
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-Kerberos' -TransportProtocol 'TCP' -Port1 88))
            }
            if ($HTTP.IsPresent)        { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTP' -TransportProtocol 'TCP' -Port1 80)) }
            if ($HTTPS.IsPresent)       { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-HTTPS' -TransportProtocol 'TCP' -Port1 443)) }
            if ($SSH.IsPresent)         { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-SSH' -TransportProtocol 'TCP' -Port1 22)) }
            if ($RDP.IsPresent)         { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RDP' -TransportProtocol 'TCP' -Port1 3389)) }
            if ($RPC.IsPresent)         { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-RPC' -TransportProtocol 'TCP' -Port1 135)) }
            if ($Ping.IsPresent)        {
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
                $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
            }
            if ($Ping4.IsPresent)       { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP')) }
            if ($Ping6.IsPresent)       { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP')) }
            if ($WinRM.IsPresent)       { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-WinRM' -TransportProtocol 'TCP' -Port1 5985)) }
            if ($WinRMS.IsPresent)      { $null = $quickFilters.Add((New-PspktFilter -Name 'QF-WinRMS' -TransportProtocol 'TCP' -Port1 5986)) }

            # AND-merge IP address into each filter.
            if (-not [string]::IsNullOrEmpty($IPAddress)) {
                $parsedIP = [System.Net.IPAddress]::Parse($IPAddress)
                foreach ($qf in $quickFilters) {
                    $qf.SetIp1($parsedIP)
                }
            }

            # Add all filters to the session (VM MAC expansion happens inside AddFilter).
            foreach ($qf in $quickFilters) {
                $Session.AddFilter($qf)
            }
        }

        if ($PassThru.IsPresent) {
            return $Session
        }
    }
}

<#
.SYNOPSIS
Removes a filter from a session.

.DESCRIPTION
Removes a filter by object reference or by index from the session filter collection.

.PARAMETER Session
Session to remove filter from.

.OUTPUTS
System.Boolean or pspktSession when PassThru is used.
#>
function Remove-PspktFilter {
    [CmdletBinding(DefaultParameterSetName = 'ByFilter')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByFilter')]
        [ValidateNotNull()]
        [pspktFilter]
        $Filter,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByIndex')]
        [ValidateRange(0, 2147483647)]
        [int]
        $Index,

        [Parameter(Mandatory = $false)]
        [switch]
        $PassThru
    )

    process {
        $removed = $false

        if ($PSCmdlet.ParameterSetName -eq 'ByFilter') {
            $removed = $Session.RemoveFilter($Filter)
        }
        else {
            $removed = $Session.RemoveFilterAt($Index)
        }

        if ($PassThru.IsPresent) {
            return $Session
        }

        return $removed
    }
}

<#
.SYNOPSIS
Gets filters associated with a session.

.DESCRIPTION
Emits each filter currently tracked in the session Filters collection.

.PARAMETER Session
Session to read filters from.

.OUTPUTS
pspktFilter
#>
function Get-PspktFilter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session
    )

    process {
        if ($null -eq $Session.Filters -or $Session.Filters.Count -eq 0) {
            return
        }

        foreach ($filter in $Session.Filters) {
            $filter
        }
    }
}

Export-ModuleMember -Function New-PspktFilter, Set-PspktFilter, Add-PspktFilter, Remove-PspktFilter, Get-PspktFilter, Resolve-PspktEnumValue
