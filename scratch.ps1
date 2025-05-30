[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $DNS,

    [Parameter()]
    [switch]
    $DNSoverTCP,

    [Parameter()]
    [switch]
    $Ping4,

    [Parameter()]
    [switch]
    $Ping6,

    [Parameter()]
    [switch]
    $Ping,

    [Parameter()]
    [switch]
    $HTTPS,

    [Parameter()]
    [switch]
    $SMB,

    [Parameter()]
    [switch]
    $SMBoverQUIC,

    [Parameter()]
    [switch]
    $DHCP,

    [Parameter()]
    [switch]
    $DHCPv6,

    [Parameter()]
    [switch]
    $NDP
)


begin{
    if ($Ping.IsPresent) {
        $null = $PSBoundParameters.TryAdd("Ping4", $true)
        $null = $PSBoundParameters.TryAdd("Ping6", $true)
    }
}

process {
    Write-Verbose "params type: $($PSBoundParameters | gm | Out-String)"
    Write-Verbose "params:`n`n$($PSBoundParameters | fl | Out-String)"

    switch ($PSBoundParameters.Keys) {
        "DNS" {
            Write-Host "Adding DNS to pktmon."
        }

        "SMB" {
            Write-Host "Adding SMB to pktmon."
        }

        "Ping4" {
            Write-Host "Adding Ping4 to pktmon."
        }

        "Ping6" {
            Write-Host "Adding Ping6 to pktmon."
        }

        default {
            Write-Host "Unknown or unused parameter: $_"
        }
    }
}

end {

}