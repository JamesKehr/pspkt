using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

[CmdletBinding()]
param ()

# returns pktmon components
# can filter by: NIC, VM, VMName, Group, Type, Name
<#
.SYNOPSIS
Gets packet monitor components.

.DESCRIPTION
Returns pspktComponent instances and supports filtering by NIC, VM, group, type, and name.

.OUTPUTS
pspktComponent
#>
function Get-PspktComponent {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        # Returns only NIC components.
        [Parameter(Mandatory = $true, ParameterSetName = 'NIC')]
        [switch]
        $NIC,

        # Filters NIC by Name. This uses regex matching. The NIC name is not the same as the Windows network adapter name. Use Get-PspktComponentNICName to get a list of pktmon NIC names.
        [Parameter(Mandatory = $false, ParameterSetName = 'NIC', Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $NICName,

        # Generates a list of all components in a VM's virtual network data path, based on a VM object (Get-VM).
        [Parameter(Mandatory = $true, ParameterSetName = 'VM')]
        [ValidateNotNull()]
        [object]
        $VM,

        # Generates a list of all components in a VM's virtual network data path, based on VM name. Only exact matches allowed.
        [Parameter(Mandatory = $true, ParameterSetName = 'VMName')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName,

        # Filters components by the Group property. This is a literal equal operation. Use Get-PspktComponentGroupName to get a list of valid pktmon group names.
        [Parameter(Mandatory = $true, ParameterSetName = 'Group', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByType')]
        [AllowNull()]
        [AllowEmptyString()]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $GroupName,

        # Filters components by Type. This is a regex match, not a literal equal, to allow for complex matching.
        # Can be used with GroupName as a second layer filter.
        [Parameter(Mandatory = $true, ParameterSetName = 'ByType', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Type,

        # Filters components by Name. This is a regex match, not a literal equal, to allow for complex matching.
        # Can be used with GroupName as a second layer filter.
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        # Uses an exact match (equal/-eq) instead of a regex match.
        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByType')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NIC')]
        [switch]
        $Exact
    )

    begin {
        
    }

    process {
        Write-Verbose "PSBoundParameters:`n$($PSBoundParameters | Format-List | Out-String)"
        Write-Verbose "ParameterSetName:`n$($PSCmdlet.ParameterSetName)"

        switch -Regex ($PSCmdlet.ParameterSetName) {
            # filter components by NICs or NIC name
            "NIC" {
                # get all the NICs
                [array]$NICs = [pspktComponent]::GetPktmonNicList()

                # return all NICs if no NICName
                if ([string]::IsNullOrEmpty($NICName)) {
                    return $NICs
                } else {
                    # this is a regex match, not an exact match (-eq)
                    if ($Exact.IsPresent) {
                        return ($NICs | Where-Object Name -eq $NICName)
                    } else {
                        return ($NICs | Where-Object Name -match $NICName)
                    }
                }

                break
            }

            # returns a list of all components in a VM's network data path
            "VM(Name)?" {
                # silently fail if Hyper-V is not installed
                if ( -NOT (Get-Command Get-VMHost -EA Ignore)) {
                    Write-Verbose "The Hyper-V role is not installed. Silently failing."
                    return
                }

                # convert a VM name to a VM object
                $vmObj = $null
                if (-NOT [string]::IsNullOrEmpty($VMName)) {
                    try {
                        $vmObj = Get-VM $VMName -EA Stop
                    } catch {
                        Write-Error "Failed to find a VM named: $VMName"
                        return
                    }
                } elseif ($VM -is [Microsoft.HyperV.PowerShell.VirtualMachine]) {
                    # put VM in vmObj, which is the common variable for doing work
                    $vmObj = $VM
                } else {
                    Write-Warning "Unknown fault with the $($PSCmdlet.ParameterSetName) parameter set.`n$($PSBoundParameters | Format-List | Out-String)"
                    return
                }

                # final check
                if (-NOT $vmObj) {
                    Write-Warning "Unknown fault with VM discovery.`n$($PSBoundParameters | Format-List | Out-String)"
                    return
                }

                ## down to business
                # grab all the components
                [System.Collections.Generic.List[pspktComponent]]$allComps = [pspktComponent]::GetAllComponents()

                # stores all the data path components
                $results = [List[pspktComponent]]::new()

                # get the VM NIC component - there can be more than one!
                [array]$vmNICs = $allComps.Where({$_.Name -eq $vmObj.Name})

                # loop through each NIC to add components
                :outer foreach ($vmNIC in $vmNICs) {
                    # add the vmNIC to results
                    $results.Add($vmNIC)

                    ## vmNIC path ##
                    # get the Ext ifIndex
                    $extIf = $vmNIC.Properties.Where({$_.Name -eq 'Ext ifIndex'}).Value

                    # get all interfaces with the extIf number - which should only be one, the VMS External Miniport (VMS ExtMp)
                    :inner foreach ($comp in $allComps) {
                        # get ifIndex
                        $ifIdx = $comp.Properties.Where({$_.Name -eq 'ifIndex'}).Value

                        # go to next when there is no match
                        if ($ifIdx -ne $extIf) {
                            continue inner
                        }

                        # add the component to results
                        $results.Add($comp)
                    }

                    ## vmSwitch path ##
                    # get the vmSwitch
                    $swName = $vmNIC.Properties.Where({$_.Name -eq 'Switch name'}).Value
                    Write-Verbose "swName: $swName"
                    
                    $vmSwitch = Get-VMSwitch -Name $swName
                    Write-Verbose "vmSwitch:`n$($vmSwitch | Format-List | Out-String)"

                    # get the ptNIC(s) used by the vmSwitch
                    switch ($vmSwitch.SwitchType) {
                        "Internal" {
                            # there is no external NIC associated with Private or Internal vmSwitches ... so just ignore this step unless this is the default switch, which can have an associated ptNIC
                            if ($vmSwitch.Name -eq 'Default Switch') {
                                [array]$ptNICs = Get-NetAdapter -Name "*Default Switch*" 
                                Write-Verbose "Default Switch ptNICs:`n$($ptNICs | Format-List | Out-String)"
                            } else {
                                Write-Verbose "Internal vmSwitch. Skipping ptNIC search."
                                [array]$ptNICs = $null
                            }
                        }

                        "External" {
                            # this can be one of more ptNIC
                            # one for a normal vmSwitch
                            # one or more for a SET vmSwitch
                            # but the logic here looks the same for either one...
                            [array]$ptNICs = $vmSwitch.NetAdapterInterfaceDescriptions | ForEach-Object {Get-NetAdapter -InterfaceDescription $_}
                            Write-Verbose "ptNICs:`n$($ptNICs | Format-List | Out-String)"
                        }

                        "Private" {
                            # there is no external NIC associated with Private or Internal vmSwitches ... so just ignore this step
                            Write-Verbose "Private vmSwitch. Skipping ptNIC search."
                            [array]$ptNICs = $null
                        }
                    }

                    # process the ptNIC path
                    :inner2 foreach ($pnic in $ptNICs) {
                        # find the matching component
                        [array]$pComp = $allComps | Where-Object {$_.Properties.Where({$_.Name -eq 'ifIndex'}).Value -eq $pnic.InterfaceIndex}
                        Write-Verbose "pComp:`n$($pComp | Format-List | Out-String)"

                        # add it
                        if ($pComp) {
                            foreach ($p in $pComp) {
                                Write-Verbose "Adding pNIC component: $($p | Format-List | Out-String)"
                                $results.Add($p)
                            }
                        } else {
                            Write-Warning "Well this is embarassing. A pNIC component was not found.`n$($pnic | Format-List | Out-String)"
                            continue inner2
                        }

                        # now get the child components
                        [array]$kids = $allComps | Where-Object {$_.Properties.Where({$_.Name -match '(Miniport|IP|Nic) ifIndex'}).Value -eq $pnic.InterfaceIndex}
                        Write-Verbose "kids:`n$($kids | Format-List | Out-String)"

                        # add them
                        if ($kids) {
                            foreach ($kid in $kids) {
                                $results.Add($kid)
                            }
                        } else {
                            Write-Verbose "No child components were found.`n$($pnic | Format-List | Out-String)"
                            continue inner2
                        }
                    }
                }

                # all done! return the virtual data path components
                return $results
            }

            # filters components by group
            "Group" {
                # get everything grouped by Group
                $allComps = [pspktComponent]::GetAllComponents() 

                # check if the group exists
                $grpNames = [pspktComponent]::GetComponentGroupNames()

                if ($GroupName -notin $grpNames) {
                    return (Write-Error "The group, $GroupName, was not found. The valid group names are: $($grpNames -join ', ')" -EA Stop)
                }

                return ($allComps | Where-Object Group -eq $GroupName)
            }

            # all components of a specific type
            # can be filtered by GroupName
            "ByType" {
                # get all components
                $allComps = [pspktComponent]::GetAllComponents()

                # filter by type, which is just a string.
                # this is a regex match!
                if ($Exact.IsPresent) {
                    $results = $allComps | Where-Object Type -eq $Type
                } else {
                    $results = $allComps | Where-Object Type -match $Type
                }

                # filter by group name
                if (-NOT [string]::IsNullOrEmpty($GroupName)) {
                    $results = $results | Where-Object Group -eq $GroupName
                }

                return $results
            }

            "ByName" {
                # get all components
                $allComps = [pspktComponent]::GetAllComponents()

                # filter by name, which is just a string.
                # this is a regex match unless -Exact is set.
                if ($Exact.IsPresent) {
                    $results = $allComps | Where-Object Name -eq $Name
                } else {
                    $results = $allComps | Where-Object Name -match $Name
                }

                if (-NOT [string]::IsNullOrEmpty($GroupName)) {
                    $results = $results | Where-Object Group -eq $GroupName
                }

                return $results
            }

            default {
                # return all components
                return ([pspktComponent]::GetAllComponents())
            }
        }
        
    }

    end {

    }

}


# returns an array of pktmon group names
# no parameters
<#
.SYNOPSIS
Gets available component group names.

.OUTPUTS
System.String
#>
function Get-PspktComponentGroupName {
    [CmdletBinding()]
    param ()

    return ([pspktComponent]::GetComponentGroupNames())
}

# returns an array of NICs, as seen by pktmon
# no parameters
<#
.SYNOPSIS
Gets packet monitor NIC component names.

.OUTPUTS
System.String
#>
function Get-PspktComponentNICName {
     [CmdletBinding()]
    param ()

    return ([pspktComponent]::GetPktmonNicList() | Select-Object -ExpandProperty Name)
}

<#
.SYNOPSIS
Applies bound component fields to an existing pspktComponent object.

.DESCRIPTION
Internal helper used by Set-PspktComponent.

.PARAMETER Component
The component instance to update.
#>
function Update-PspktComponentInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pspktComponent]
        $Component,

        [Parameter(Mandatory = $false)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [string]
        $DriverName,

        [Parameter(Mandatory = $false)]
        [int]
        $Id,

        [Parameter(Mandatory = $false)]
        [int]
        $SecondaryId,

        [Parameter(Mandatory = $false)]
        [int]
        $ParentId,

        [Parameter(Mandatory = $false)]
        [string]
        $Group,

        [Parameter(Mandatory = $false)]
        [string]
        $Type,

        [Parameter(Mandatory = $false)]
        [int]
        $TypeId,

        [Parameter(Mandatory = $false)]
        [bool]
        $IsNetworkAdapter,

        [Parameter(Mandatory = $false)]
        [string]
        $MacAddress
    )

    if ($PSBoundParameters.ContainsKey('Name')) {
        $Component.Name = $Name
    }

    if ($PSBoundParameters.ContainsKey('DriverName')) {
        $Component.DriverName = $DriverName
    }

    if ($PSBoundParameters.ContainsKey('Id')) {
        $Component.Id = $Id
    }

    if ($PSBoundParameters.ContainsKey('SecondaryId')) {
        $Component.SecondaryId = $SecondaryId
    }

    if ($PSBoundParameters.ContainsKey('ParentId')) {
        $Component.ParentId = $ParentId
    }

    if ($PSBoundParameters.ContainsKey('Group')) {
        $Component.Group = $Group
    }

    if ($PSBoundParameters.ContainsKey('Type')) {
        $Component.Type = $Type
    }

    if ($PSBoundParameters.ContainsKey('TypeId')) {
        $Component.TypeId = $TypeId
    }

    if ($PSBoundParameters.ContainsKey('IsNetworkAdapter')) {
        $Component.IsNetworkAdapter = $IsNetworkAdapter
    }

    if ($PSBoundParameters.ContainsKey('MacAddress')) {
        $Component.MacAddress = $MacAddress
    }

    return $Component
}

<#
.SYNOPSIS
Updates an existing pspktComponent.

.DESCRIPTION
Accepts a component from parameter or pipeline and updates bound fields.

.PARAMETER Component
Component to update.

.OUTPUTS
pspktComponent
#>
function Set-PspktComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktComponent]
        $Component,

        [Parameter(Mandatory = $false)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [string]
        $DriverName,

        [Parameter(Mandatory = $false)]
        [int]
        $Id,

        [Parameter(Mandatory = $false)]
        [int]
        $SecondaryId,

        [Parameter(Mandatory = $false)]
        [int]
        $ParentId,

        [Parameter(Mandatory = $false)]
        [string]
        $Group,

        [Parameter(Mandatory = $false)]
        [string]
        $Type,

        [Parameter(Mandatory = $false)]
        [int]
        $TypeId,

        [Parameter(Mandatory = $false)]
        [bool]
        $IsNetworkAdapter,

        [Parameter(Mandatory = $false)]
        [string]
        $MacAddress
    )

    process {
        Update-PspktComponentInternal @PSBoundParameters
    }
}

<#
.SYNOPSIS
Adds a component to a session.

.DESCRIPTION
Adds data source components to a pspktSession. When -VM or -VMName is supplied,
resolves all VM data-path components and sets the session's VM scoping (VMName +
VMMacAddresses) so all current and future filters on the session are automatically
AND-combined with the VM's MAC addresses.

Accepts pspktComponent objects from the pipeline. When piped components contain
vmNIC objects (components with a non-zero MAC address), VM scoping is automatically
set on the session from the vmNIC data — no need to specify -VMName separately.

.PARAMETER Session
Session that receives the component.

.PARAMETER Component
Component to add (accepts pipeline input).

.PARAMETER VM
Hyper-V VM object (from Get-VM). Resolves all data-path components and sets VM
scoping on the session.

.PARAMETER VMName
Hyper-V VM name string. Same behavior as -VM.

.PARAMETER PassThru
Returns the session object.

.EXAMPLE
$s = New-PspktSession -Name 'vm'
Get-PspktComponent -VMName 'Win11Dev' | Add-PspktComponent $s
# Session now has VM components added and VM scoping (VMName + VMMacAddresses) set.

.EXAMPLE
Add-PspktComponent -Session $s -VMName 'Win11Dev'
# Resolves VM data-path components and sets VM scoping in one call.
#>
function Add-PspktComponent {
    [CmdletBinding(DefaultParameterSetName = 'ByComponent')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ByComponent')]
        [ValidateNotNull()]
        [pspktComponent]
        $Component,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByVM')]
        [object]
        $VM,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByVMName')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName,

        [Parameter(Mandatory = $false)]
        [switch]
        $PassThru
    )

    begin {
        # Collect vmNIC MACs from piped components to auto-set VM scoping.
        $script:pipedVmName = $null
        $script:pipedVmMacs = [System.Collections.ArrayList]::new()

        if ($PSCmdlet.ParameterSetName -eq 'ByVM' -or $PSCmdlet.ParameterSetName -eq 'ByVMName') {
            # Direct -VM / -VMName invocation (no pipeline). Resolve components + VM scoping now.
            $vmComps = $null
            if ($PSCmdlet.ParameterSetName -eq 'ByVM') {
                $vmComps = Get-PspktComponent -VM $VM
            } else {
                $vmComps = Get-PspktComponent -VMName $VMName
            }

            # Resolve MAC addresses and set VM scoping on the session.
            $subMod = Get-Module PspktSession
            $macList = & $subMod {
                param($vmParam, $vmNameParam)
                Get-PspktVMMacList -VM $vmParam -VMName $vmNameParam
            } $VM $VMName

            $vmLabel = if ($PSCmdlet.ParameterSetName -eq 'ByVM') { "$($VM.Name)" } else { $VMName }
            $Session.VMName = $vmLabel
            $Session.VMMacAddresses = $macList

            # Add components.
            if ($null -ne $vmComps) {
                foreach ($comp in $vmComps) {
                    if ($null -ne $comp -and $comp.Pointer -ne [IntPtr]::Zero) {
                        $Session.AddSingleDataSourceToSession($comp)
                    }
                }
            } elseif ($macList.Count -gt 0) {
                # OFF/Saved VM fallback.
                $nicComps = $Session.Pspkt.EnumPktmonDataSources($true, 1)
                if ($null -ne $nicComps) {
                    foreach ($comp in $nicComps) {
                        if ($null -ne $comp -and $comp.Pointer -ne [IntPtr]::Zero) {
                            $Session.AddSingleDataSourceToSession($comp)
                        }
                    }
                }
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByComponent') {
            $Session.AddSingleDataSourceToSession($Component)

            # Detect vmNIC components by their non-zero MAC address. pktmon vmNIC
            # components carry the VM name in $Component.Name and the vmNIC MAC in
            # $Component.MacAddress. Collect these so end{} can set VM scoping.
            if ($null -ne $Component.MacAddress) {
                $macBytes = $Component.MacAddress.GetAddressBytes()
                $nonZero = $false
                foreach ($b in $macBytes) { if ($b -ne 0) { $nonZero = $true; break } }
                if ($nonZero -and $macBytes.Length -ge 6) {
                    $macStr = ($macBytes | ForEach-Object { $_.ToString('X2') }) -join '-'
                    $null = $script:pipedVmMacs.Add($macStr)
                    # The vmNIC component's Name is the VM name.
                    if ($null -eq $script:pipedVmName) {
                        $script:pipedVmName = $Component.Name
                    }
                }
            }
        }
    }

    end {
        # Auto-set VM scoping from piped vmNIC components.
        if ($PSCmdlet.ParameterSetName -eq 'ByComponent' -and $script:pipedVmMacs.Count -gt 0) {
            $Session.VMName = $script:pipedVmName
            $Session.VMMacAddresses = [string[]]$script:pipedVmMacs.ToArray()
        }

        if ($PassThru.IsPresent) {
            return $Session
        }
    }
}

<#
.SYNOPSIS
Removes a component from a session.

.DESCRIPTION
Removes a component by object reference or by index from the session component collection.

.PARAMETER Session
Session to remove component from.

.OUTPUTS
System.Boolean or pspktSession when PassThru is used.
#>
function Remove-PspktComponent {
    [CmdletBinding(DefaultParameterSetName = 'ByComponent')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [pspktSession]
        $Session,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByComponent')]
        [ValidateNotNull()]
        [pspktComponent]
        $Component,

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

        if ($PSCmdlet.ParameterSetName -eq 'ByComponent') {
            $removed = $Session.RemoveComponent($Component)
        }
        else {
            $removed = $Session.RemoveComponentAt($Index)
        }

        if ($PassThru.IsPresent) {
            return $Session
        }

        return $removed
    }
}

Export-ModuleMember -Function Get-PspktComponent, Get-PspktComponentGroupName, Get-PspktComponentNICName, Set-PspktComponent, Add-PspktComponent, Remove-PspktComponent