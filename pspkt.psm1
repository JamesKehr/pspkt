# turns pktmon into a basic tcpdump-like real-time packet monitoring tool.
#requires -RunAsAdministrator
#requires -Version 7.4

using namespace System.Collections.Generic

<#
TO-DO:
    - Add VPN interfaces.
    - Speed up NIC detection.
      - Get-NetIPAddress | Where-Object {$_.InterfaceAlias -notmatch "Loopback" -and $_.InterfaceAlias -notmatch "Bluetooth"}
#>

function pspkt {
    [CmdletBinding()]
    param (
        ### INTERFACES ###

        [Parameter()]
        [switch]
        [Alias("D")]
        $DumpInterfaces,

        [Parameter()]
        [int[]]
        [Alias("int")]
        [ValidateRange(1, 255)]
        $Interface = $null,

        ### QUICK CAPTURE ###

        ## PING ##
        [Parameter()]
        [switch]
        [Alias("AllPing")]
        $Ping,

        [Parameter()]
        [switch]
        [Alias("Pingv4", "p4")]
        $Ping4,

        [Parameter()]
        [switch]
        [Alias("Pingv6", "p6")]
        $Ping6,
        ##

        ## SMB ##
        [Parameter()]
        [switch]
        $SMB,

        [Parameter()]
        [switch]
        [Alias("SoQ")]
        $SMBoverQUIC,

        [Parameter()]
        [int]
        [ValidateRange(1,65535)]
        [Alias("SMBoverQUICAltPort", "SoQAltPort")]
        $SMBAltPort = $null,
        ##

        ## DNS ##
        [Parameter()]
        [switch]
        $DNS,

        [Parameter()]
        [switch]
        $DNSoverTCP,

        ## DATA LINK ##
        [Parameter()]
        [switch]
        $ARP,

        [Parameter()]
        [switch]
        $NDP,

        ### GLOBAL ###

        [Parameter()]
        [ipaddress[]]
        [Alias("ip", "i")]
        $IPAddress = $null,

        [Parameter()]
        [switch]
        $Force
    )

    
    begin {
        if (-NOT $DumpInterfaces.IsPresent) {
            Write-Verbose "Collecting pktmon component list."
            # get all the pktmon components
            $components = pktmon list --json | ConvertFrom-Json

            # get a list of all local IP addresses (excluding loopback)
            Write-Verbose "Collecting IP details."
            #[array]$lclIpAddr = Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq "Up"}
            [array]$lclIpAddr = Get-NetIPAddress | Where-Object {$_.InterfaceAlias -notmatch "Loopback" -and $_.InterfaceAlias -notmatch "Bluetooth"}

            ## get a list of NICs with an IP address - source NICs
            Write-Verbose "Collecting source network adapters."
            [array]$intIdx = $lclIpAddr | Select-Object InterfaceIndex -Unique | ForEach-Object InterfaceIndex

            # collect all the miniport components
            # this is uses to match the interfaceIndex selected to the component ID
            if ($Interface) {
                # there is an ifIndex value inside the components that will be used to find the Interface
                # get all on the components with an ifIndex property
                $allInterfaces = [List[object]]::new()
                :flatten foreach ($comp in $components.Components) {
                    # only miniport components matter
                    if ($comp.Type -ne "Miniport" -and $comp.Type -ne "Host vNic") {
                        continue flatten
                    }

                    # save the miniport component
                    $tmp = $comp
                    Write-Verbose "pspkt - Found miniport: $($tmp.Name)"

                    # add the ifIndex to the main object to make searching easier
                    $ifIdx = $comp.Properties | Where-Object Name -eq "ifIndex" | ForEach-Object Value

                    if ($ifIdx) {
                        Write-Debug "pspkt - Adding ifIdx: $ifIdx"
                        $tmp | Add-Member -MemberType NoteProperty -Name "ifIndex" -Value $ifIdx -Force
                    }

                    # save the miniport component
                    if ($tmp) {
                        Write-Verbose "pspkt - Adding component to allInterfaces: $($tmp.Id)"
                        $allInterfaces.Add($tmp)
                    }
                }
            }

            # enable both Ping4 and Ping6 if Ping is set.
            if ($Ping.IsPresent) {
                $null = $PSBoundParameters.TryAdd("Ping4", $true)
                $null = $PSBoundParameters.TryAdd("Ping6", $true)
            }

            # tracks whether a filter has been added
            $firstFiltAdded = $false

            # Ping4 and Ping6 use the same console filter, track so it doesn't get double added
            #$pingFiltAdded = $false

            # place holder for the console filter string
            $strSwitch = ""

            # this enables filtering the output 
            <#

Write-Debug "loop: $PSItem"
switch -Regex ($PSItem) {  

                | Foreach-Object -Process {
                    Write-Debug "loop: $PSItem"
                    switch -Regex ($PSItem) {           
            
                | &{ process {
                    Write-Debug "loop: $PSItem"
                    switch -Regex ($PSItem) { 
            #>
            $strSwitchStart = @'
 | &{ process {
        $line = $_
        Write-Debug "loop: $line"
        
        switch -Regex -CaseSensitive ($line) { 
'@

            # add the ending part
            $strSwitchEnd = @'

        # write hidden lines to Verbose for funzies
        default {Write-Verbose "$PSItem"}
    }
}}
'@
        }
    }

    process {
        Write-Debug "pspkt - PSBoundParameters:`n`n$($PSBoundParameters | ConvertTo-Json -Depth 3)"
        ## DumpInterfaces ##
        # return the interface list and exit
        if ($DumpInterfaces.IsPresent) {
            return (Out-InterfaceList)
        }
        ##

        ## START ##
        #region START
        # the base command
        $cmd = "pktmon start --capture --flags 0x010"

        ## do NIC work to limit the output ##
        # add the NIC component filter
        $first = $true
        foreach ($int in $Interface) {
            # get the interface based on the -D index number, subtract 1 to zero index
            $tmpIdx = $intIdx[($int-1)]
            $tmpNic = $lclIpAddr | Where-Object interfaceIndex -eq $tmpIdx | Select-Object InterfaceAlias, InterfaceIndex -Unique
            Write-Verbose "pspkt - Selected NIC: $($tmpNic.InterfaceAlias) [$($tmpNic.InterfaceIndex)]"

            # hard fail if there is a mismatch
            if (-NOT $tmpNic) {
                throw "Failed to find a NIC matching interface number $int."
            }

            # get the miniport match
            $compID = $allInterfaces | Where-Object ifIndex -eq $tmpNic.InterfaceIndex | ForEach-Object Id | Select-Object -Unique

            # add the component to the start command
            if ($compID) {
                Write-Verbose "pspkt - Component ID is $compID."
                if ($first) {
                    Write-Verbose "pspkt - Initial component add."
                    $cmd = [string]::Concat($cmd, " --comp $compID")

                    # disable first
                    $first = $false
                } else {
                    Write-Verbose "pspkt - Add component."
                    $cmd = [string]::Concat($cmd, " $compID")
                }
            }
        }

        # the end of the command to add real-time
        $cmd = [string]::Concat($cmd, " --log-mode real-time")
        Write-Verbose "pspkt - cmd: $cmd"

        # stop and clear existing filter - Force does so without mercy
        Reset-Pktmon -Force:$($Force.IsPresent)
        #endregion START
        ##
        

        ## FILTER ##
        switch -Regex ($PSBoundParameters.Keys) {
            "^DNS$" {
                Write-Verbose "Adding DNS to pspkt."

                # add the pktmon filter for UDP 53
                $filtSplat = @{ 
                    Name = "DNS"
                    Port = 53
                    Protocol = "UDP"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                # add the console filter
                $tmpStr = @'

            # DNS
            "(\.53: |\.53 >)" { [System.Console]::WriteLine("$PSItem") }
'@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)

                #done - don't break or the switch-loop ends
            }

            "DNSoverTCP" {
                Write-Verbose "Adding DNS over TCP to pspkt."

                # add the pktmon filter for UDP 53
                $filtSplat = @{ 
                    Name = "DNSoverTCP"
                    Port = 53
                    Protocol = "TCP"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                # add the console filter
                $tmpStr = @'

            # DNS
            "(\.53: |\.53 >)" { [System.Console]::WriteLine("$PSItem") }
'@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)

                #done - don't break or the switch-loop ends
            }

            "Ping4" {
                Write-Verbose "Adding Ping4 to pspkt."

                # add the pktmon filter for ICMP
                $filtSplat = @{ 
                    Name = "Ping4"
                    Protocol = "ICMP"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                $tmpStr = @'

            # ping4 (ICMP Echo)
            "(?:ICMP echo)" { [System.Console]::WriteLine("$PSItem") }
'@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)
                Write-Verbose "pspkt - Added echo filter to strSwitch: $strSwitch"

                #done - don't break or the switch-loop ends
            }

            "Ping6" {
                Write-Verbose "Adding Ping6 to pspkt."

                # add the pktmon filter for ICMP
                $filtSplat = @{ 
                    Name = "Ping6"
                    Protocol = "ICMPv6"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                $tmpStr = @'

            # ping6 (ICMPv6 Echo)
            "(?:ICMP6, echo)" { [System.Console]::WriteLine("$PSItem") }
'@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)
                Write-Verbose "pspkt - Added echo filter to strSwitch: $strSwitch"
            
                #done - don't break or the switch-loop ends
            }

            "NDP" {
                Write-Verbose "Adding NDP to pspkt."

                # add the pktmon filter for ICMP
                $filtSplat = @{ 
                    Name = "NDP"
                    Protocol = "ICMPv6"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                $tmpStr = @'

            # NDP (ICMPv6 neighbor)
            "ICMP6, (?:router|neighbor) (?:solicitation|advertisement)" { [System.Console]::WriteLine("$PSItem") }
'@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)
                Write-Verbose "pspkt - Added echo filter to strSwitch: $strSwitch"
            
                #done - don't break or the switch-loop ends
            }

            "SMBoverQUIC" {
                Write-Verbose "Adding SMB over QUIC to pspkt."

                $SmbPort = 443
                # support for alternate ports
                if ($SMBAltPort) {
                    $SmbPort = $SMBAltPort
                }

                # add the pktmon filter 
                $filtSplat = @{ 
                    Name = "SMB"
                    Port = $SmbPort
                    Protocol = "UDP"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                # add the console filter
                $tmpStr = @"

            # SMB over QUIC
            "(\.$SmbPort`: |\.$SmbPort >)" { [System.Console]::WriteLine("`$PSItem") }
"@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)

                #done - don't break or the switch-loop ends
            }

            "^SMB$" {
                Write-Verbose "Adding SMB over TCP to pspkt."

                $SmbPort = 445
                # SMB over TCP does not support alternative listener ports (yet) but does support the client using an alternate port
                if ($SMBAltPort) {
                    $SmbPort = $SMBAltPort
                }

                # add the pktmon filter 
                $filtSplat = @{ 
                    Name = "SMB"
                    Port = $SmbPort
                    Protocol = "TCP"
                }

                # add the IP address(es)
                if ($IPAddress) {
                    $filtSplat += @{ IPAddress = $IPAddress }
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                # add the console filter
                $tmpStr = @"

            # SMB
            "(\.$SmbPort`: |\.$SmbPort >)" { [System.Console]::WriteLine("`$PSItem") }
"@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)

                #done - don't break or the switch-loop ends
            }

            "ARP" {
                 Write-Verbose "Adding ARP to pspkt."

                # add the pktmon filter for ICMP
                $filtSplat = @{ 
                    Name = "ARP"
                    Protocol = "ARP"
                }

                # create the filter
                Write-Debug "filtSplat:`n`n$($filtSplat | Out-String)`n"
                Add-PspktFilter @filtSplat

                # check whether the filter string is started
                if (-NOT $firstFiltAdded) {
                    $firstFiltAdded = $true

                    # create the attach to the command
                    $strSwitch = $strSwitchStart
                }

                $tmpStr = @'

            # ping4 (ICMP Echo)
            "ARP.*(?:Request who-has|Reply .* is-at)" { [System.Console]::WriteLine("$PSItem") }
'@
                $strSwitch = [string]::Concat($strSwitch, $tmpStr)
                Write-Verbose "pspkt - Added echo filter to strSwitch: $strSwitch"

            }

            default {
                Write-Verbose "Unknown or non-filter parameter: $_"
            }
        }
        ##


        ##

        ## RUN TIME! ##
        $strSwitch = [string]::Concat($strSwitch, $strSwitchEnd)
        Write-Verbose "pspkt - Final strSwitch: $strSwitch"

        $cmd = [string]::Concat($cmd, $strSwitch)
        Write-Verbose "pspkt - Final cmd: $cmd"

        # convert the string to a scriptblock
        Write-Verbose "pspkt - Convert to scriptblock."
        $sbCmd = [scriptblock]::Create($cmd)
        #$sbProcess = [scriptblock]::Create($strSwitch)


        Write-Verbose "pspkt - Running pktmon in real-time mode."
        Write-Host -ForegroundColor Green "Press Ctrl+C to stop."
        Invoke-Command -ScriptBlock $sbCmd
        #Invoke-Command -ScriptBlock $sbCmd | ForEach-Object -Process $sbProcess
        #Invoke-Expression $cmd #| Out-Host | ForEach-Object -Process $sbProcess

        <# encode the command
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        Write-Verbose "encoded command: $encodedCommand"

        Start-Process pwsh -ArgumentList "-NoLogo -NoProfile -EncodedCommand $encodedCommand" -NoNewWindow -Wait
        #>
        ##

    }

    end {

    }

    clean {
        if (-NOT $DumpInterfaces.IsPresent -or $Force.IsPresent) {
            # stop and remove filters
            #Reset-Pktmon -Force
        }
    }
}

#############
## UTILITY ##
#############

# returns a console printable list of interfaces (equal to tcpdump -D; except PowerShell is not case sensitive)
function Out-InterfaceList {
    [CmdletBinding()]
    param ()

    # get a list of all local IP addresses (excluding loopback)
    [array]$lclIpAddr = Get-NetIPAddress | Where-Object {$_.InterfaceAlias -notmatch "Loopback" -and $_.InterfaceAlias -notmatch "Bluetooth"}

    # the unique list of interface indexes
    [array]$IfIdx = $lclIpAddr | Select-Object InterfaceIndex -Unique | ForEach-Object InterfaceIndex

    # the number of interface digits plus 2 for the padding
    [int]$pad = [int]([string]($IfIdx.Count).Length) + 1

    # get longest interface alias
    [int]$longest = $lclIpAddr | ForEach-Object {$_.InterfaceAlias.Length} | Sort-Object -Descending | Select-Object -First 1

    # console width
    $cWidth = [System.Console]::WindowWidth

    # only show interfaces that are Up and have an IP address - which are interfaces in ifIdx
    $c = 1
    $txt = [List[string]]::new()
    foreach ($idx in $IfIdx) {
        # get all addresses with this index
        [array]$addr = $lclIpAddr | Where-Object {$_.InterfaceIndex -eq $idx}

        # collect IPs minus FE80:: (IPv6 WellKnown)
        [string[]]$ip4 = $addr | Where-Object AddressFamily -eq "IPv4" | ForEach-Object IPAddress
        [string[]]$ip6 = $addr | Where-Object {$_.AddressFamily -eq "IPv6" -and $_.PrefixOrigin -ne "WellKnown"} | ForEach-Object IPAddress

        # combine
        [string]$tmpAll = ""
        if (-NOT [string]::IsNullOrEmpty($ip4)) { 
            $tmpAll = $ip4 -join ', '

            if ($ip6) {
                $tmpAll = [string]::Concat($tmpAll, ", $($ip6 -join ', ')")
            }
        } elseif (-NOT [string]::IsNullOrEmpty($ip6)) { 
            $tmpAll = $ip6 -join ', '
        }
        
        if ($tmpAll) {
            # trim by console width
            $len = 4 + $pad + $longest

            Write-Verbose "Out-InterfaceList - (($len + $($tmpAll.Length)) -gt $cWidth) == $(($len + $tmpAll.Length) -gt $cWidth)"
            if (($len + $tmpAll.Length) -gt $cWidth) {
                $tmpAll = $tmpAll.Substring(0, ($cWidth-$len-3))
                $tmpAll = [string]::Concat($tmpAll, "...")
            }
        }

        $tmp = "$("$c`.".ToString().PadRight($pad, ' ')) $($addr[0].InterfaceAlias.PadRight($longest, ' ')) $(if ($tmpAll) { "[$tmpAll]" })"
        $txt.Add($tmp)

        # increment the number
        $c++
    }

    # output the result
    return $txt
}


# get the current pktmon state
function Get-PktmonState {
    $state = [PSCustomObject]@{
        Running        = $false
        FiltersPresent = $false
        Filters        = [List[string]]::new()
    }

    $run = pktmon status
    if ($run -notmatch "Packet Monitor is not running.") {
        # pktmon is running
        $state.Running = $true

        # collect filters
        $filters = Get-PktmonFilters

        if ($filters) {
            $state.FiltersPresent = $true
            $state.Filters = $filters
        }
    }

    return $state
}


function Get-PktmonFilters {
    # get the filters
    $txtFilter = (pktmon filter list) -split "\r?\n"

    # stores filter string
    $filters = [List[string]]::new()

    # a count
    $i = 0

    # controls when to start recording filters
    $startRecording = $false
    switch -Regex ( $txtFilter) {
        "^\s*-+\s+-+\s+-+.*$" {
            Write-Verbose "Get-PktmonFilters - Start recording filters."
            $startRecording = $true

            # add the header
            $filters.Add($txtFilter[($i-1)])
            $filters.Add($txtFilter[($i)])

            $i++
        }
        
        default {
            Write-Verbose "Get-PktmonFilters - Line: $_"
            if ($startRecording) {
                $filters.Add($PSItem)
            }

            $i++
        }
    }

    if ($filters.Count -gt 0) {
        return $filters
    } else {
        return $null
    }

}

# resets pktmon filters and stop any existing traces
function Reset-Pktmon {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]
        $Force
    )

    # no need to collect state when Force is present
    if (-NOT $Force.IsPresent) {
        $state = Get-PktmonState

        if ( $state.Running ) {
           Write-Warning @"
pktmon is currently active.

Running : $($state.Running)
Filters : 
$($state.Filters -join "`t`n")
"@

            do {
                Write-Host "`nWould you like to stop pktmon? [Y]es or [n]o : " -NoNewline
                $prompt = [System.Console]::ReadKey($false)
            } until ($prompt.Key -eq 'y' -or $prompt.Key -eq 'n')

            if ($prompt.Key -eq 'y') {
                $reset = $true
            } else {
                $reset = $false
            }
        } else {
            $reset = $true
        }
    }

    if ($Force.IsPresent -or $reset) {
        pktmon stop *> $null
        pktmon filter remove *> $null
    }
}

function Add-PspktFilter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [string]
        $Protocol,

        [Parameter()]
        [int]
        [ValidateRange(1,65535)]
        $Port,

        [Parameter()]
        [ipaddress[]]
        $IPAddress = $null
    )

    Write-Verbose "Add-PspktFilter - Adding $Name filter(s)."

    # validate the protocol.
    # Can be TCP, UDP, ICMP, ICMPv6, or a protocol number.
    # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    # 
    # The valid protocol numbers are 0-147 as of 29 May 2025.
    #
    # Yes, I know ARP is a data link protocol and not a transport protocol, but I'm simplifying things here
    #
    [string[]]$validProtNames = "TCP", "UDP", "ICMP", "ICMPv6", "ARP"
    [int[]]$validProtNums = 0..147

    # valid protocol tracker
    $isProtValid = $false

    # is the protocol a number?
    $protNum = 256
    if ([int]::TryParse($Protocol, [ref]$protNum)) {
        # the protocol is a number
        # is it in the valid range?
        if ($protNum -in $validProtNums) {
            $isProtValid = $true
        }

    } elseif ($Protocol -in $validProtNames) {
        # the protocol is a well-known string
        $isProtValid = $true
    }

    # fail if the protocol is invalid
    if (-NOT $isProtValid) {
        Write-Warning "The protocol ($Protocol) is invalid. The protocol must be TCP, UDP, ICMP, ICMPv6, or an IANA protocol number."
        return
    }

    Write-Verbose "Add-PspktFilter - Name: $Name; Protocol: $Protocol; Port: $Port; IPAddress: $($IPAddress.IPAddressToString -join ", ")"

    if ($Protocol -eq "ARP") {
        Write-Verbose "Add-PspktFilter - Adding ARP filter."
        pktmon filter add "$Name" -d $Protocol *> $null
    } elseif ($IPAddress) {
        $i = 1
        foreach ($ip in $IPAddress) {
            $strIP = $ip.IPAddressToString
            Write-Verbose "Add-PspktFilter - Adding filter for IP address: $strIP"
            # TCP and UDP can also be represented by the protocol numbers 6 (TCP) and 17 (UDP)
            if ($Protocol -eq "TCP" -or $Protocol -eq "UDP" -or $Protocol -eq 6 -or $Protocol -eq 17) {
                pktmon filter add "$Name`_$i" -i $strIP -t $Protocol -p $Port *> $null
            } else {
                pktmon filter add "$Name`_$i" -i $strIP -t $Protocol *> $null
            }
            $i++
        }
    } else {
        Write-Verbose "Add-PspktFilter - Adding filter with no IP address filter."
        # TCP and UDP can also be represented by the protocol numbers 6 (TCP) and 17 (UDP)
        if ($Protocol -eq "TCP" -or $Protocol -eq "UDP" -or $Protocol -eq 6 -or $Protocol -eq 17) {
            pktmon filter add "$Name" -t $Protocol -p $Port *> $null
        # ignore the port when not UDP or TCP or the filter won't work
        } else {
            pktmon filter add "$Name" -t $Protocol *> $null
        }
    }
}

# exports
Export-ModuleMember pspkt


<#


        ## PING ##
        #region PING
        if ($Ping4.IsPresent -or $Ping.IsPresent) {
            Write-Debug "Adding Ping4 filter."
            if ($IPAddress) {
                $i = 1
                foreach ($ip in $IPAddress) {
                    $strIP = $ip.IPAddressToString
                    pktmon filter add "Ping4_$i" -i $strIP -t ICMP *> $null
                    $i++
                }
            } else {
                pktmon filter add Ping4 -t ICMP *> $null
            }
        }

        if ($Ping6.IsPresent -or $Ping.IsPresent) {
            Write-Debug "pspkt - Adding Ping6 filter."
            if ($IPAddress) {
                $i = 1
                foreach ($ip in $IPAddress) {
                    $strIP = $ip.IPAddressToString
                    pktmon filter add "Ping6_$i" -i $strIP -t ICMPv6 *> $null
                    $i++
                }
            } else {
                pktmon filter add Ping6 -t ICMPv6 *> $null
            }
        }
        #endregion PING
        ##

        ## SMB ##
        #region SMB

        # only one type of SMB, on a single port, is allowed at a time
        # determine the SMB port
        [int]$port = $SMBAltPort
        if ($port -eq 0 -and $SMB.IsPresent) {
            $port = 445
            Write-Verbose "pspkt - Using the default SMB port (TCP 445)."
        } elseif ($port -eq 0 -and $SMBoverQUIC.IsPresent) {
            $port = 443
            Write-Verbose "pspkt - Using the default SMB over QUIC port (UDP 443)."
        }

        if ($SMB.IsPresent) {
            Write-Debug "pspkt - Adding SMB filter."
            
            if ($IPAddress) {
                $i = 1
                foreach ($ip in $IPAddress) {
                    $strIP = $ip.IPAddressToString
                    pktmon filter add "SMB_$i" -i $strIP -t TCP -p $port *> $null
                    $i++
                }
            } else {
                pktmon filter add "SMB" -t TCP -p $port *> $null
            }
        } elseif ($SMBoverQUIC.IsPresent) {
            Write-Debug "pspkt - Adding SMB over QUIC filter."
            
            if ($IPAddress) {
                $i = 1
                foreach ($ip in $IPAddress) {
                    $strIP = $ip.IPAddressToString
                    pktmon filter add "SoQ_$i" -i $strIP -t UDP -p $port *> $null
                    $i++
                }
            } else {
                pktmon filter add "SoQ" -t UDP -p $port *> $null
            }
        }

        #endregion SMB
        ##

        ## DNS ##
        #region DNS
        if ($DNS.IsPresent) {
            Write-Debug "pspkt - Adding DNS over UDP filter."
            
            if ($IPAddress) {
                $i = 1
                foreach ($ip in $IPAddress) {
                    $strIP = $ip.IPAddressToString
                    pktmon filter add "DNS_$i" -i $strIP -t UDP -p 53 *> $null
                    $i++
                }
            } else {
                pktmon filter add "DNS" -t UDP -p 53 *> $null
            }
        }

        if ($DNS.IsPresent) {
            Write-Debug "pspkt - Adding DNS over TCP filter."
            
            if ($IPAddress) {
                $i = 1
                foreach ($ip in $IPAddress) {
                    $strIP = $ip.IPAddressToString
                    pktmon filter add "DNSoTCP_$i" -i $strIP -t TCP -p 53 *> $null
                    $i++
                }
            } else {
                pktmon filter add "DNSoTCP" -t TCP -p 53 *> $null
            }
        }
        #endregion DNS



 ## CONSOLE FILTER ##
        

        Write-Verbose "pspkt - strSwitch: $strSwitch"

        # loop through switches and add statements to the switch
        if ($Ping.IsPresent -or $Ping4.IsPresent -or $Ping6.IsPresent) {
            $tmpStr = @"

            # ping (ICMP Echo)
            "echo" { "`$_" }
"@
            $strSwitch = [string]::Concat($strSwitch, $tmpStr)
            Write-Verbose "pspkt - Added echo filter to strSwitch: $strSwitch"
        }

        if ($SMB.IsPresent -or $SMBoverQUIC.IsPresent) {
            $tmpStr = @"

            # SMB
            "(\.$port`: |\.$port >)" { "`$_" }
"@
            $strSwitch = [string]::Concat($strSwitch, $tmpStr)
            Write-Verbose "pspkt - Added SMB filter to strSwitch: $strSwitch"
        }

        if ($DNS.IsPresent -or $DNSoverTCP.IsPresent) {
            $tmpStr = @"

            # DNS
            "(\.53`: |\.53 >)" { "`$_" }
"@
            $strSwitch = [string]::Concat($strSwitch, $tmpStr)
            Write-Verbose "pspkt - Added SMB filter to strSwitch: $strSwitch"
        }

        # add the ending part
        $strSwitchEnd = @"

            # write hidden lines to Verbose for funzies
            default {Write-Verbose "`$_"}
        }
    }}
"@


#>