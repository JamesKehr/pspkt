# tcp.psm1 - TCP transport layer formatter.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# TCP flag bit positions (from TCPData.Flags byte).
# Byte layout: CWR ECE URG ACK PSH RST SYN FIN
$script:TcpFlagMap = @(
    @{ Bit = 0x80; Char = 'W' }   # CWR
    @{ Bit = 0x40; Char = 'E' }   # ECE
    @{ Bit = 0x20; Char = 'U' }   # URG
    @{ Bit = 0x10; Char = '.' }   # ACK
    @{ Bit = 0x08; Char = 'P' }   # PSH
    @{ Bit = 0x04; Char = 'R' }   # RST
    @{ Bit = 0x02; Char = 'S' }   # SYN
    @{ Bit = 0x01; Char = 'F' }   # FIN
)

<#
.SYNOPSIS
Formats TCP flags byte into a compact string of set flag characters.

.DESCRIPTION
Only prints characters for flags that are set (1). Order: W E U . P R S F

.PARAMETER Flags
The TCP flags byte value.
#>
function Format-TcpFlags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte]
        $Flags
    )

    return [PacketParseHelper]::FormatTcpFlags($Flags)
}

<#
.SYNOPSIS
Formats the TCP transport segment for default real-time display.

.DESCRIPTION
Returns a string in the format:
  TCP [flags], seq [seq], ack [ack], win [window], length [dataLen]

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Format-TcpSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $len = 0
    if ($null -ne $ProtocolData.Data) {
        $len = $ProtocolData.Data.Count
    }

    return [PacketParseHelper]::FormatTcpSegment(
        $ProtocolData.Flags,
        $ProtocolData.SequenceNumber,
        $ProtocolData.AcknowledgementNumber,
        $ProtocolData.Window,
        $len
    )
}

<#
.SYNOPSIS
Parses TCP options bytes into a human-readable string.

.DESCRIPTION
Supports common options: MSS, Window Scale, SACK Permitted, SACK blocks, Timestamps, NOP, EOL.

.PARAMETER Options
The raw TCP options byte array.
#>
function Format-TcpOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]
        $Options
    )

    if ($null -eq $Options -or $Options.Count -eq 0) {
        return $null
    }

    return [TcpParser]::FormatTcpOptions($Options)
}

<#
.SYNOPSIS
Formats a detailed TCP line for verbose output.

.DESCRIPTION
Returns a string with full TCP header details:
  TCP [flags] - Src: [port], Dst: [port]; seq: [num], ack: [num], win: [size]; Opts: [options]
Options are only printed when present (handshake, SACK, etc.).

.PARAMETER ProtocolData
A TCPData object from the parsed packet.
#>
function Format-TcpDetailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolData
    )

    $flags = Format-TcpFlags -Flags $ProtocolData.Flags
    $srcPort = $ProtocolData.SourcePort
    $dstPort = $ProtocolData.DestinationPort
    $seq = $ProtocolData.SequenceNumber
    $ack = $ProtocolData.AcknowledgementNumber
    $win = $ProtocolData.Window
    $len = 0
    if ($null -ne $ProtocolData.Data) {
        $len = $ProtocolData.Data.Count
    }

    $base = "TCP [$flags] - Src: $srcPort, Dst: $dstPort; seq: $seq, ack: $ack, win: $win, len: $len"

    $opts = Format-TcpOptions -Options $ProtocolData.Options
    if ($null -ne $opts) {
        $base += "; Opts: $opts"
    }

    return $base
}

Export-ModuleMember -Function Format-TcpFlags, Format-TcpSegment, Format-TcpOptions, Format-TcpDetailed
