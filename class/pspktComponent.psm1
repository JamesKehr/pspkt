using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/pktmondefk/ne-pktmondefk-pktmon_component_type
# Let's Windows sort out this mess for us.

class pspktComponentProperty {
    [string]
    $Name

    [string]
    $Value

    pspktComponentProperty() {
        $this.Name = ""
        $this.Value = ""
    }

    AddName([string]$n) {
        $this.Name($n)
    }

    AddValue([string]$v) {
        $this.Value($v)
    }

    # this only accepts PSCustomObject from component properties converted from JSON (pktmon comp list --json | ConvertFrom-Json)
    AddObject([PSCustomObject]$obj) {
        try {
            $this.Name = $obj.Name
            $this.Value = $obj.Value    
        } catch {
            throw "Failed to convert the object to class pspktComponentProperty."
        }
    }


    [string]
    ToString() {
        return "$($this.Name): $($this.Value)"
    }
}

class pspktComponentCounter {
    [string]
    $Name

    [string]
    $Value

    pspktComponentProperty() {
        $this.Name = ""
        $this.Value = ""
    }

    AddName([string]$n) {
        $this.Name($n)
    }

    AddValue([string]$v) {
        $this.Value($v)
    }

    # this only accepts PSCustomObject from component properties converted from JSON (pktmon comp list --json | ConvertFrom-Json)
    AddObject([PSCustomObject]$obj) {
        try {
            $this.Name = $obj.Name
            $this.Value = $obj.Value    
        } catch {
            throw "Failed to convert the object to class pspktComponentProperty."
        }
    }

    [string]
    ToString() {
        return "$($this.Name): $($this.Value)"
    }
}


class pspktComponent {
    # Basic properties
    [string]
    $Name

    [string]
    $DriverName
    
    [int]
    $Id

    [int]
    $SecondaryId

    # Group should be the name of the component of ParentId
    [int]
    $ParentId

    [string]
    $Group

    # Type comes from pktmon.exe and TypeId from pktmonapi
    [string]
    $Type

    [int]
    $TypeId

    # Properties and Counters come from pktmon.exe
    [List[pspktComponentProperty]]
    $Properties

    [List[pspktComponentCounter]]
    $Counters

    # Set to $true when pktmonapi kind if NIC
    [bool]
    $IsNetworkAdapter

    # this will eventually be it's own class
    [PhysicalAddress]
    $MacAddress

    # a couple of hidden properties needed for pktmonapi
    hidden
    [int]
    $Length

    hidden
    [IntPtr]
    $Pointer

    pspktComponent() {
        $this.IsNetworkAdapter = $false
        $this.ParentId         = -1
        $this.Properties       = [List[pspktComponentProperty]]::new()
        $this.Counters         = [List[pspktComponentCounter]]::new()
    }

    static
    [array]
    GetAllComponents() {
        # grab all the pktmon components, using pktmon (which is easier than trying to use the Win32 APIs)
        $rawComp = [pspktComponent]::GetPktmonComponentList()

        # get the pktmonapi components for parentid and NIC details
        [array]$apiAll = [pspktComponent]::GetPktmonApiComponents()

        # grab the NIC list from pktmonapi
        [array]$NICs = [pspktComponent]::GetPktmonApiNics()

        # process components by group
        [array]$allComps = foreach ($grp in $rawComp) {
            # save the group name
            [string]$grpName = $grp.Group
            #Write-Host "Processing group: $grpName"

            # find the parent comp
            # the group name
            #$parent = $apiAll | Where-Object Description -match $grpName

            # loop through components
            foreach ($comp in $grp.Components) {
                #Write-Host "Comp:`n$($comp | Format-List | Out-String)"
                # look for a matching API version
                $tmpAPI = $apiAll | Where-Object {$_.Id -eq $comp.Id -and ($_.SecondaryId -eq $comp.SecondaryId -or ($null -eq $comp.SecondaryId -and $_.Id -eq $_.SecondaryId)) }
                #Write-Host "tmpAPI:`n$($tmpAPI | Format-List | Out-String)"

                ### FIX: Find the right object and don't return a 


                # the primary NIC object from pktmon.exe has an ID and no secondaryId
                if ($comp.Id -in $NICs.Id -and 
                    $null -eq $comp.SecondaryId) 
                {
                    $isNIC = $true
                } else {
                    $isNIC = $false
                }

                [pspktComponent]::MergeComponents($tmpAPI, $comp, $grpName, $isNIC)
            }
        }

        return $allComps
    }

    ## returns only pktmon NIC components as an array of pspktComponent
    static
    [array]
    GetPktmonNicList() {
        # grab all the pktmon components, using pktmon (which is easier than trying to use the Win32 APIs)
        [array]$rawComp = [pspktComponent]::GetPktmonComponentList()

        # grab the NIC list from pktmonapi
        [array]$NICs = [pspktComponent]::GetPktmonApiNics()

        # format the component list as 
        $nicList = [List[pspktComponent]]::new()
        
        :nic foreach ($nic in $NICs) {
            # find the component
            :grp foreach ($grp in $rawComp) {
                $grpName = $grp.Group

                # ignore any group with "WAN Miniport" or "HTTP Message" or "IPSEC" - no pktmon NIC will be in any of these groups
                if ($grpName -match "^WAN Miniport \(.*\)$" -or
                    $grpName -eq "HTTP Message" -or $grpName -eq "IPSEC") 
                {
                    continue grp
                }

                # look for a component match
                # Id and SecondaryId must match
                $comp = $null
                :comp foreach ($itm in $grp.Components) {
                    if ($itm.Id -ne $nic.Id) { continue comp }

                    # match found when secondaryId matches, or itm.SecondaryId is null and the API NIC Id == SecondaryId (making it the primary component object)
                    if ($itm.SecondaryId -eq $nic.SecondaryId -or
                        ($null -eq $itm.SecondaryId -and $nic.Id -eq $nic.SecondaryId))
                    {
                        $comp = $itm
                        break comp
                    }
                }

                if ($comp) {
                    $tmp = [pspktComponent]::MergeComponents($nic, $comp, $grpName, $true)
                    if ($tmp) { $nicList.Add($tmp) }
                    continue nic
                }
            }
        }

        return $nicList
    }

    ## UTIL ##
    #region UTIL
    ## merges an API object with a pktmon pscustom object into a pspktComponent object
    # INPUTS: pktmonApi [PktmonDataSource] object, pktmon [PSCustomObject] from ConvertFrom-Json, the group name
    static
    [pspktComponent]
    MergeComponents([PktmonDataSource]$src, [PSCustomObject]$obj, [string]$grpName, [bool]$IsNIC) {
        # create an object
        $tmp = [pspktComponent]::new()

        # add details
        # obj > src
        $tmp.ID = $obj.ID
        $tmp.Type = $obj.Type
        $tmp.Group = $grpName
        $tmp.Name = $obj.Name
        $tmp.DriverName = $obj.DriverName
        # add missing secondary ID
        if ($null -eq $obj.SecondaryId) {
            $tmp.SecondaryId = $tmp.Id
        } else {
            $tmp.SecondaryId = $obj.SecondaryId
        }

        # update parent ID
        if ($src.Description -contains $obj.Name ) {
            [int]$parId = $src | Where-Object Description -eq $obj.Name | ForEach-Object ParentId | Select-Object -First 1
            $tmp.ParentId = $parId
        } else {
            $tmp.ParentId = 0
        }

        # update IsNetworkAdapter and MacAddress
        if ($IsNIC) { 
            $tmp.IsNetworkAdapter = $true 
        }

        if ($src.MacAddress) {
            $tmp.MacAddress = [PAUtils]::ConvertString2PhysicalAddress($src.MacAddress)
        } else {
            $tmp.MacAddress = [PhysicalAddress]::new(0)
        }

        # add properties and counters
        $tmp.Properties = $obj.Properties
        $tmp.Counters = $obj.Counters

        # pushes the component to $comps
        return $tmp
    }
    

    ## returns all pktmon components as an array of PSCustomObjects 
    static
    [array]
    GetPktmonComponentList() {
        return (pktmon comp list --json | ConvertFrom-Json)
    }
    
    ## returns the raw pktmon NIC component names from pktmonapi.dll
    static
    [array]
    GetPktmonApiNics() {
        # create a temp pktmon session
        $tmpSession = [pspkt]::new()
        $tmpSession.PacketMonitorInitialize()    

        # enum the NICs
        [array]$NICs = ($tmpSession.PacketMonitorEnumDataSources($true,1))

        # cleanup
        $tmpSession.PacketMonitorUninitialize()

        return $NICs
    }

    ## returns all the raw pktmon components from pktmonapi.dll
    static
    [array]
    GetPktmonApiComponents() {
        # create a temp pktmon session
        $tmpSession = [pspkt]::new()
        $tmpSession.PacketMonitorInitialize()    

        # enum the NICs
        [array]$all = ($tmpSession.PacketMonitorEnumDataSources($true,0))

        # cleanup
        $tmpSession.PacketMonitorUninitialize()

        return $all
    }

    [string]
    ReadWCharStringAtOffset([int] $Offset) {
        $chars = @()
        for ($i = $Offset; $i -lt $this.Length; $i += 2) {
            if ($i + 1 -ge $this.Length) { break }

            $char = $this.ReadWCharAtOffset($i)

            if ($char -eq 0) { break }

            $chars += $char
        }

        return -join $chars
    }

    [char]
    ReadWCharAtOffset([int]$Offset) {

        if ($Offset -lt 0 -or $Offset + 1 -ge $this.length) {
            throw "Offset out of bounds"
        }

        $lo = [System.Runtime.InteropServices.Marshal]::ReadByte($this.pointer, $offset)
        $hi = [System.Runtime.InteropServices.Marshal]::ReadByte($this.pointer, $offset + 1)


        $charCode = ($hi -shl 8) -bor $lo

        return [char]$charCode
    }

    #endregion UTIL


    ## LISTS ##
    #region LISTS

    ## returns a list of NIC names from pktmonapi.dll
    static
    [string[]]
    GetComponentNicNames() {
        # create a temp pktmon session
        $tmpSession = [pspkt]::new()
        $tmpSession.PacketMonitorInitialize()    

        # enum the NICs
        [array]$NICs = ($tmpSession.PacketMonitorEnumDataSources($true,1))

        # cleanup
        $tmpSession.PacketMonitorUninitialize()

        return ($NICs.Description)
    }

    ## returns a list of pktmon group names from 'pktmon comp list'
    static
    [string[]]
    GetComponentGroupNames() {
        # grab all the pktmon components, using pktmon (which is easier than trying to use the Win32 APIs)
        $rawComp = [pspktComponent]::GetPktmonComponentList()

        # return the group names
        return [string[]]($rawComp.Group)
    }
    #endregion LISTS

    ## ADD ##
    #region ADD

    # adds the component based on a pointer to a PACKETMONITOR_DATA_SOURCE_SPECIFICATION struct
    AddPktmonDataSource([IntPtr] $pointer) {
        $this.Pointer = $pointer
        $this.Length = 424
        $this.type = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 0)
        $this.name = $this.ReadWCharStringAtOffset(4)
        $this.description = $this.ReadWCharStringAtOffset(132)
        $this.id = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 388)
        $this.secondaryId = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 392)
        $this.parentId = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 396)
        $this.macAddress = ""
        for($j = 0; $j -lt 6; $j++)
        {
            $b = [System.Runtime.InteropServices.Marshal]::ReadByte($this.pointer, 408+$j)
            $this.macAddress +=  "{0:X2}" -f $b
            if($j -lt 5)
            {
                $this.macAddress += ":"
            }
        }
        
    }

    #endregion ADD
    
}

# create the type accelerator
$ExportableTypes = @(
    [pspktComponentProperty]
    [pspktComponentCounter]
    [pspktComponent]
)

# Get the internal TypeAccelerators class to use its static methods.
$TypeAcceleratorsClass = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)

# Ensure none of the types would clobber an existing type accelerator.
# If a type accelerator with the same name exists, throw an exception.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
foreach ($Type in $ExportableTypes) {
    if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
        # silently throw a message to the verbose stream
        Write-Verbose @"
Unable to register type accelerator[$($Type.FullName)]. The Accelerator already exists.
"@

    } else {
        $TypeAcceleratorsClass::Add($Type.FullName, $Type)
    }
}

# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach($Type in $ExportableTypes) {
        $TypeAcceleratorsClass::Remove($Type.FullName)
    }
}.GetNewClosure()