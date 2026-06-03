# smb2.psm1 - MS-SMB2 application layer parser for pspkt real-time output.
# Parses SMB2/SMB3 over Direct TCP (port 445) only. Ignores SMB1/CIFS.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Tests whether a TCP packet contains SMB2 data (port 445).

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Test-Smb2Packet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    if ($null -eq $ProtocolData) { return $false }
    if ($null -eq $ProtocolData.Data -or $ProtocolData.Data.Count -lt 8) { return $false }

    $sp = $ProtocolData.SourcePort
    $dp = $ProtocolData.DestinationPort

    return [Smb2Parser]::IsSmb2Packet($ProtocolData.Data, $sp, $dp)
}

<#
.SYNOPSIS
Formats an SMB2 one-line summary segment for real-time display.

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Format-Smb2Segment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    return [Smb2Parser]::FormatSmb2Segment($ProtocolData.Data, $ProtocolData.SourcePort, $ProtocolData.DestinationPort)
}

<#
.SYNOPSIS
Formats detailed SMB2 information for verbose output.

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Format-Smb2Detailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    return [Smb2Parser]::FormatSmb2Detailed($ProtocolData.Data, $ProtocolData.SourcePort, $ProtocolData.DestinationPort)
}

Export-ModuleMember -Function Test-Smb2Packet, Format-Smb2Segment, Format-Smb2Detailed
