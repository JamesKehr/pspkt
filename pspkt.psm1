#Requires -Version 5.1
#Requires -RunAsAdministrator

using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

# enables verbose and debug streams
[CmdletBinding()]
param ()


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# load the classes via loader.psm1
Import-Module "$PSScriptRoot\class\loader.psm1"

# load the rest of the modules now that the C# type is added
# load in this order to prevent dependency errors

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!! DO NOT use Get-ChildItem (dir or gci) as this does not guarantee that the modules are loaded in the correct order !!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Write-Verbose "Loading modules in specific order to ensure dependencies are met."
[array]$loadList = "class\pspktEnum.psm1",
                    "class\pspktUtil.psm1",
                    "class\pspktTypes.psm1",
                    "class\pspktPacketParser.psm1",
                    "class\pspktClass.psm1",
                    "Parsers\libParser.psm1",
                    "function\PspktFilter.psm1",
                    "function\PspktComponent.psm1",
                    "function\PspktSession.psm1"

foreach ($mod in $loadList) {
    Write-Verbose "Loading: $mod"
    Import-Module "$PSScriptRoot\$mod" -Force -Global
}


## UTILITY FUNCTIONS ##
#region UTIL
<#
.SYNOPSIS
Converts a System.Net.IPAddress into a PACKETMONITOR_IP_ADDRESS struct.

.DESCRIPTION
Builds the native packet monitor address structure used by filter/session APIs.
Supports both IPv4 and IPv6 addresses.

.PARAMETER Address
The IP address to convert.

.OUTPUTS
PACKETMONITOR_IP_ADDRESS
#>
function ConvertTo-PspktIpAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$Address
    )

    $ip    = [PACKETMONITOR_IP_ADDRESS]::new()
    $bytes = $Address.GetAddressBytes()

    switch ($Address.AddressFamily) {
        'InterNetwork' {           # IPv4 -> 4 bytes
            $ip.IPv4 = [BitConverter]::ToUInt32($bytes, 0)
        }
        'InterNetworkV6' {         # IPv6 -> 16 bytes, two ulongs
            $ip.IPv6_low  = [BitConverter]::ToUInt64($bytes, 0)
            $ip.IPv6_high = [BitConverter]::ToUInt64($bytes, 8)
        }
        default { throw "Unsupported address family: $($Address.AddressFamily)" }
    }

    ,$ip   # comma keeps PowerShell from unrolling the struct
}

#endregion UTIL

Export-ModuleMember -Function ConvertTo-PspktIpAddress, New-PspktFilter, Set-PspktFilter, Add-PspktFilter, Remove-PspktFilter, Get-PspktFilter, Get-PspktComponent, Get-PspktComponentGroupName, Get-PspktComponentNICName, Set-PspktComponent, Add-PspktComponent, Remove-PspktComponent, New-PspktSession, Get-PspktSession, Set-PspktSession, Start-Pspkt, Stop-Pspkt, Get-PspktParserColorProfile, Import-PspktParserColorProfile, Set-PspktParserColorProfile, New-PspktParserColorProfile, Test-PspktParserColorProfile, Save-PspktParserColorProfile, Register-PspktComponentMap, Clear-PspktComponentMap, Get-PspktCaptureHeader, Set-PspktDetailLevel, Get-PspktDetailLevel, Set-PspktDetailSpacing, Get-PspktDetailSpacing, Set-PspktShowTimestamp, Get-PspktShowTimestamp -Alias pspkt