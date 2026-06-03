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
        [object]
        $Mac1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac2,

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

    if ($PSBoundParameters.ContainsKey('EtherType')) {
        if ($null -eq $EtherType) { throw "EtherType cannot be null when specified." }
        if ($EtherType -is [ETHERTYPE]) {
            $Filter.SetEtherType([ETHERTYPE]$EtherType)
        }
        else {
            $Filter.SetEtherType([uint16]$EtherType)
        }
    }

    if ($PSBoundParameters.ContainsKey('DSCP')) {
        if ($null -eq $DSCP) { throw "DSCP cannot be null when specified." }
        if ($DSCP -is [DSCP]) {
            $Filter.SetDSCP([DSCP]$DSCP)
        }
        else {
            $Filter.SetDSCP([uint16]$DSCP)
        }
    }

    if ($PSBoundParameters.ContainsKey('TransportProtocol')) {
        if ($null -eq $TransportProtocol) { throw "TransportProtocol cannot be null when specified." }
        if ($TransportProtocol -is [IPv4Protocol]) {
            $Filter.SetTransportProtocol([IPv4Protocol]$TransportProtocol)
        }
        else {
            $Filter.SetTransportProtocol([byte]$TransportProtocol)
        }
    }

    if ($PSBoundParameters.ContainsKey('Ip1')) {
        $Filter.SetIp1([System.Net.IPAddress]$Ip1)
    }

    if ($PSBoundParameters.ContainsKey('Ip2')) {
        $Filter.SetIp2([System.Net.IPAddress]$Ip2)
    }

    if ($PSBoundParameters.ContainsKey('Port1')) {
        $Filter.SetPort1([uint16]$Port1)
    }

    if ($PSBoundParameters.ContainsKey('Port2')) {
        $Filter.SetPort2([uint16]$Port2)
    }

    if ($PSBoundParameters.ContainsKey('TCPFlags')) {
        if ($null -eq $TCPFlags) { throw "TCPFlags cannot be null when specified." }
        if ($TCPFlags -is [TCPFLAGS]) {
            $Filter.SetTCPFlags([TCPFLAGS]$TCPFlags)
        }
        else {
            $Filter.SetTCPFlags([byte]$TCPFlags)
        }
    }

    if ($PSBoundParameters.ContainsKey('VxLanPort')) {
        $Filter.SetVxLanPort([uint16]$VxLanPort)
    }

    if ($PSBoundParameters.ContainsKey('EncapType')) {
        $Filter.SetEncapType([PKTMON_FILTER_ENCAPTYPE]$EncapType)
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
        [object]
        $Mac1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac2,

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
        [object]
        $Mac1,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]
        $Mac2,

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
Attaches a pspktFilter to a pspktSession via the session AddFilter method.

.PARAMETER Session
Session that receives the filter.

.PARAMETER Filter
Filter to add.
#>
function Add-PspktFilter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktFilter]
        $Filter,

        [Parameter(Mandatory = $false)]
        [switch]
        $PassThru
    )

    process {
        $Session.AddFilter($Filter)

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

Export-ModuleMember -Function New-PspktFilter, Set-PspktFilter, Add-PspktFilter, Remove-PspktFilter, Get-PspktFilter
