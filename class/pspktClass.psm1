# Credit: https://github.com/Ekky-PS/PSPktmon
# Modified for performance and to fit the needs of this project.
# A huge thank you to Ekky for sharing his implementation of pktmonapi using PowerShell!!!

using namespace System.Collections.Generic
using namespace System.Collections.Concurrent


class pspkt {
    [List[System.IntPtr]] $OpenPktmonPointers;
    [List[pspktSession]] $OpenPktmonSessions;
    [List[PktmonRealTimeStream]] $OpenPktmonRealTimeStreams;
    [IntPtr] $PktmonHandle;
    hidden [IPspktNativeApi] $NativeApi;

    pspkt()
    {
        $this.InitializeManagedState([PspktNativeApi]::new())
    }

    hidden pspkt([IPspktNativeApi] $nativeApi)
    {
        $this.InitializeManagedState($nativeApi)
    }

    hidden [void] InitializeManagedState([IPspktNativeApi] $nativeApi)
    {
        if ($null -eq $nativeApi) { throw "Native API cannot be null." }
        $this.OpenPktmonPointers = [List[System.IntPtr]]::new()
        $this.OpenPktmonSessions = [List[pspktSession]]::new()
        $this.OpenPktmonRealTimeStreams = [List[PktmonRealTimeStream]]::new()
        $this.PktmonHandle = [IntPtr]::Zero
        $this.NativeApi = $nativeApi
    }

    [void] PacketMonitorInitialize()
    {
        [UInt32]$ApiVersion = 0x00010000
        if ($this.PktmonHandle -ne [IntPtr]::Zero) { return }
        [IntPtr] $handle = [IntPtr]::Zero
        $result = $this.NativeApi.PacketMonitorInitialize($ApiVersion, [IntPtr]::Zero, [ref]$handle)
        if ($result -ne 0) { throw "Failed to initialize PktMon: 0x{0:X}" -f $result }
        if ($handle -eq [IntPtr]::Zero) { throw "Failed to initialize PktMon: native handle is null." }
        $this.PktmonHandle = $handle
        [PacketData]::MissedPacketWriteCount = 0
        [PacketData]::MissedPacketReadCount = 0
    }

    [void] PacketMonitorUninitialize()
    {
        if (
            $this.PktmonHandle -eq [IntPtr]::Zero -and
            $this.OpenPktmonPointers.Count -eq 0 -and
            $this.OpenPktmonSessions.Count -eq 0 -and
            $this.OpenPktmonRealTimeStreams.Count -eq 0
        ) {
            return
        }
        foreach ($openSession in $this.OpenPktmonSessions) {
            if (
                $openSession.CaptureCleanupPending -or
                [PktMonApi]::IsCaptureOwner($openSession.Handle)
            ) {
                throw "Owned captures must be stopped through Stop-Pspkt -Teardown before pktmon can be uninitialized."
            }
        }
        $cleanupErrors = [System.Collections.ArrayList]::new()
        $nativeUninitializeSucceeded = $this.PktmonHandle -eq [IntPtr]::Zero
        try {
            try {
                $this.FreeAllMemoryPointers()
            } catch {
                $null = $cleanupErrors.Add($_.Exception.Message)
            }

            foreach ($session in @($this.OpenPktmonSessions)) {
                if ($session.Active) {
                    try {
                        $session.SetSessionActive($false)
                    } catch {
                        $null = $cleanupErrors.Add($_.Exception.Message)
                    }
                }
                try {
                    $this.PacketMonitorCloseSessionHandle($session)
                } catch {
                    $null = $cleanupErrors.Add($_.Exception.Message)
                }
            }

            foreach ($realTimeStream in @($this.OpenPktmonRealTimeStreams)) {
                try {
                    $this.PacketMonitorCloseRealtimeStream($realTimeStream)
                } catch {
                    $null = $cleanupErrors.Add($_.Exception.Message)
                }
            }

            if ($this.PktmonHandle -ne [IntPtr]::Zero) {
                try {
                    $this.NativeApi.PacketMonitorUninitialize($this.PktmonHandle)
                    $nativeUninitializeSucceeded = $true
                } catch {
                    $null = $cleanupErrors.Add($_.Exception.Message)
                }
            }
        } finally {
            $this.OpenPktmonSessions.Clear()
            $this.OpenPktmonRealTimeStreams.Clear()
            if ($nativeUninitializeSucceeded) {
                $this.PktmonHandle = [IntPtr]::Zero
            }
        }

        if ($cleanupErrors.Count -gt 0) {
            throw "Pktmon cleanup failed: $($cleanupErrors -join '; ')"
        }
    }

    [pspktSession] PacketMonitorCreateLiveSession([string] $name)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        $session = [IntPtr]::Zero
        $res = $this.NativeApi.PacketMonitorCreateLiveSession($this.PktMonHandle, $Name, [ref]$session)
        if ($res -ne 0) {
            if ($session -ne [IntPtr]::Zero) {
                try {
                    $this.NativeApi.PacketMonitorCloseSessionHandle($session)
                } catch {
                    throw "Failed to create session: 0x{0:X}. Cleanup failed: $($_.Exception.Message)" -f $res
                }
            }
            throw "Failed to create session: 0x{0:X}" -f $res
        }
        if ($session -eq [IntPtr]::Zero) { throw "Failed to create session: native handle is null." }
        #[PktmonUtils]::WriteInformation("Live session created: $Name, handle = $session")

        $pktmonSession = [pspktSession]::new($name, $session, $this.NativeApi)
        $pktmonSession.Pspkt = $this
        $null = $this.OpenPktmonSessions.Add($pktmonSession)
        return $pktmonSession;
    }
    
    [void] PacketMonitorCloseSessionHandle([string] $name)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        $this.PacketMonitorCloseSessionHandle($this.GetSession($name))
    }


    [void] PacketMonitorCloseSessionHandle([pspktSession] $pktmonSession)
    {
        if ($null -eq $pktmonSession) { return }
        if (
            $pktmonSession.CaptureCleanupPending -or
            [PktMonApi]::IsCaptureOwner($pktmonSession.Handle)
        ) {
            throw "An owned capture must be closed through Stop-Pspkt -Teardown."
        }
        try {
            $pktmonSession.CloseSessionHandleCore()
        } finally {
            $null = $this.OpenPktmonSessions.Remove($pktmonSession)
        }
    }

    [pspktSession] GetSession([string] $name)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        foreach($session in $this.OpenPktmonSessions)
        {
            if($session.name -eq $name)
            {
                return $session
            }
        }
        return $null   
    }
    [pspktSession] GetSession([IntPtr] $handle)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        foreach($session in $this.OpenPktmonSessions)
        {
            if($session.handle -eq $handle)
            {
                return $session
            }
        }
        return $null   
    }


    [void] FreeAllMemoryPointers()
    {
        $freeErrors = [System.Collections.ArrayList]::new()
        $pointers = @($this.OpenPktmonPointers)
        $this.OpenPktmonPointers.Clear()
        foreach($pointer in $pointers) {
            try {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
            } catch {
                $null = $this.OpenPktmonPointers.Add($pointer)
                $null = $freeErrors.Add($_.Exception.Message)
            }
        }
        if ($freeErrors.Count -gt 0) {
            throw "Failed to free native memory pointers: $($freeErrors -join '; ')"
        }
    }

    [PktmonRealTimeStream] CreateRealtimeStream([uint16] $BufferSizeMultiplier, [uint16] $TruncationSize)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        
        #$id =  $this.OpenPktmonRealTimeStreams.Count
        $config = [PACKETMONITOR_REALTIME_STREAM_CONFIGURATION]::new()
        $config.UserContext = [IntPtr] [PktmonRealTimeStream]::Index
        $config.EventCallback = [IntPtr]::Zero
        $config.DataCallback = [IntPtr]::Zero
        $config.BufferSizeMultiplier = [uint16] $BufferSizeMultiplier
        $config.TruncationSize = [uint16] $TruncationSize
        [PktMonApi]::PrepareRealtimeStreamConfiguration([ref]$config)
        
        $streamHandle = [IntPtr]::Zero
        $result = $this.NativeApi.PacketMonitorCreateRealtimeStream(
            $this.PktmonHandle,
            [ref]$config,
            [ref]$streamHandle
        )
        if ($result -ne 0 -or $streamHandle -eq [IntPtr]::Zero) {
            $cleanupError = $null
            if ($streamHandle -ne [IntPtr]::Zero) {
                try {
                    $this.NativeApi.PacketMonitorCloseRealtimeStream($streamHandle)
                } catch {
                    $cleanupError = $_.Exception.Message
                }
            }
            $message = "Failed to create realtime stream: status=0x{0:X}, handle={1}." -f $result, $streamHandle
            if ($null -ne $cleanupError) {
                $message += " Cleanup failed: $cleanupError"
            }
            throw $message
        }

        try {
            $realTimeStream = [PktmonRealTimeStream]::new(
                $BufferSizeMultiplier,
                $TruncationSize,
                $streamHandle,
                $this
            )
            $null = $this.OpenPktmonRealTimeStreams.Add($realTimeStream)
            return $realTimeStream
        } catch {
            $primaryError = $_
            try {
                $this.NativeApi.PacketMonitorCloseRealtimeStream($streamHandle)
            } catch {
                throw "$($primaryError.Exception.Message) Cleanup failed: $($_.Exception.Message)"
            }
            throw $primaryError
        }
    }

    [void] PacketMonitorCloseRealtimeStream([PktmonRealTimeStream] $realTimeStream)
    {
        if ($null -eq $realTimeStream) { return }
        $closeError = $null
        try {
            if ($realTimeStream.Handle -ne [IntPtr]::Zero) {
                $this.NativeApi.PacketMonitorCloseRealtimeStream($realTimeStream.Handle)
            }
        } catch {
            $closeError = $_
        } finally {
            $realTimeStream.InvalidateAfterClose()
            foreach ($session in @($this.OpenPktmonSessions)) {
                $session.RemoveOutputFromSession($realTimeStream)
            }
            $null = $this.OpenPktmonRealTimeStreams.Remove($realTimeStream)
        }

        if ($null -ne $closeError) {
            throw $closeError
        }
    }

    [List[pspktComponent]]
    EnumPktmonDataSources([bool] $ShowHidden, [int] $SourceKind) {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        
        $bytesNeeded = [uint64]::Zero
        $res = $this.NativeApi.PacketMonitorEnumDataSources(
            $this.PktmonHandle,
            $SourceKind,
            $ShowHidden,
            [UIntPtr]::Zero,
            [ref]$bytesNeeded,
            [IntPtr]::Zero
        )
        if ($res -ne 0) { throw "EnumDataSources failed: 0x{0:X}" -f $res }
        if ($bytesNeeded -eq [uint64]::Zero) { return $null }

        $DataSourceMemoryPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytesNeeded)
        $this.OpenPktmonPointers.Add($DataSourceMemoryPointer)
        $bytesReturned = [UIntPtr]::Zero
        $res = $this.NativeApi.PacketMonitorEnumDataSources(
            $this.PktmonHandle,
            $SourceKind,
            $ShowHidden,
            $bytesNeeded,
            [ref]$bytesReturned,
            $DataSourceMemoryPointer
        )
        if ($res -ne 0) { throw "EnumDataSources failed: 0x{0:X}" -f $res }

        [int]$ItemSize   = 424 
        $basePtr = $DataSourceMemoryPointer;
        $length = $bytesNeeded

        if ($BasePtr -eq [IntPtr]::Zero) {
            throw "BasePtr cannot be zero."
        }

        [int] $itemCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($basePtr, 0)
        [int] $HeaderSize = (16 + $itemCount * 8)
        $dataSize = $length - $HeaderSize
        if ($dataSize -le 0) 
        {
            throw "BytesReturned is smaller or equal to headersize"
        }

        $i = 0
        $pktmonSources = [List[pspktComponent]]::new()

        for ($i = 0; $i -lt $itemCount; $i++) {

            $offset = $HeaderSize + ($i * $ItemSize)
            $ptrVal = $BasePtr.ToInt64() + $offset

            $itemPtr = [IntPtr]$ptrVal

            $tmp = [pspktComponent]::new()
            $tmp.AddPktmonDataSource($itemPtr)
            $pktmonSources.Add($tmp)
        }

        return $pktmonSources
    }

    [System.Collections.ArrayList] GetAllPackets()
    {
        $returnArray = [System.Collections.ArrayList]::new()
        foreach($session in $this.OpenPktmonSessions)
        {
            $returnArray.AddRange($session.ReadPacketsFromBuffer())
        }
        return $returnArray;
    }
}

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
    [string]
    $MacAddress

    # VM scoping: populated by Get-PspktComponent -VM/-VMName so downstream
    # cmdlets (Add-PspktComponent) can set session VM scoping from the pipeline.
    [string]
    $VMName

    [string]
    $VMMacAddress

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
    # INPUTS: pktmonApi [pspktComponent] object, pktmon [PSCustomObject] from ConvertFrom-Json, the group name
    static
    [pspktComponent]
    MergeComponents([pspktComponent]$src, [PSCustomObject]$obj, [string]$grpName, [bool]$IsNIC) {
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

        # update parent ID from the API source
        if ($null -ne $src -and $src.ParentId -gt 0) {
            $tmp.ParentId = $src.ParentId
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
        [array]$NICs = ($tmpSession.EnumPktmonDataSources($true,1))

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
        [array]$all = ($tmpSession.EnumPktmonDataSources($true,0))

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
        [array]$NICs = ($tmpSession.EnumPktmonDataSources($true,1))

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
        $this.TypeId = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 0)
        $this.DriverName = $this.ReadWCharStringAtOffset(4)
        $this.Name = $this.ReadWCharStringAtOffset(132)
        $this.Id = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 388)
        $this.SecondaryId = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 392)
        $this.ParentId = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pointer, 396)
        $this.MacAddress = ''
        
        for($j = 0; $j -lt 6; $j++) {
            $b = [System.Runtime.InteropServices.Marshal]::ReadByte($this.pointer, 408+$j)
            $this.macAddress +=  "{0:X2}" -f $b
        }
        
    }

    #endregion ADD
    
}


<#
https://learn.microsoft.com/en-us/windows/win32/pktmon/packetmonitor/nf-packetmonitor-packetmonitoraddcaptureconstraint

DA RULEZ!

    Add a filter to control which packets are reported. 
    
    For a packet to be reported, it must match all conditions specified in at least one filter.
    
    Up to 32 filters can be active at once.

    When two MACs (-m), IPs (-i), or ports (-p) are specified, the filter
    matches packets that contain both. It will not distinguish between source
    or destination for this purpose.


[byte[]]Mac1                  – Mac Address of Source if IsPresent.Mac1 is TRUE.
[byte[]]Mac2                  – Mac Address of Destination if IsPresent.Mac2 is TRUE.
[uint16]EtherType             – Ethernet Type Value if IsPresent.EtherType is TRUE.
[uint16]DSCP                  – Field in the IP header if IsPresent.DSCP is TRUE.
[byte]TransportProtocol       – Type of Protocol (UDP – 17, TCP – 6, etc.)
[PACKETMONITOR_IP_ADDRESS]Ip1 – Ip Address of Source if IsPresent.Ip1 is TRUE.
[PACKETMONITOR_IP_ADDRESS]Ip2 – Ip Address of Destination if IsPresent.Ip2 is TRUE.
[uint16]Port1                 – Source Port Number if IsPresent.Port1 is TRUE.
[uint16]Port2                 – Destination Port Number if IsPresent.Port1 is TRUE.
[byte]TCPFlags                – TCP Flags if IsPresent.TCPFlags is TRUE.
[uint16]VxLanPort             – VxLanPort if IsPresent. VxLanPort is TRUE
[uint]EncapType                     – Encapsulation type for packets. Supported Values are:
   0x00 – No Encapsulation (Default)
   0x01 – VxLan Encapsulation
   0x02 – GRE(Generic Routing Encapsulation) encapsulation
   0x04 – IP inside IP packet Encapsulation
   0xFF – All Encapsulation supported.
[uint64]Packets              - Not Implemented 
[uint64]Bytes                - Not Implemented


| PowerShell Type | Type Accelerator        | C# / .NET Type   |
| --------------- | ----------------------- | ---------------- |
| `string`        | `[string]`              | `System.String`  |
| `char`          | `[char]`                | `System.Char`    |
| `bool`          | `[bool]`                | `System.Boolean` |
| `byte`          | `[byte]`                | `System.Byte`    |
| `sbyte`         | `[sbyte]`               | `System.SByte`   |
| `int16`         | `[int16]` / `[short]`   | `System.Int16`   |
| `int32`         | `[int]` / `[int32]`     | `System.Int32`   |
| `int64`         | `[long]` / `[int64]`    | `System.Int64`   |
| `uint16`        | `[uint16]` / `[ushort]` | `System.UInt16`  |
| `uint32`        | `[uint32]` / `[uint]`   | `System.UInt32`  |
| `uint64`        | `[uint64]` / `[ulong]`  | `System.UInt64`  |
| `float`         | `[float]` / `[single]`  | `System.Single`  |
| `double`        | `[double]`              | `System.Double`  |
| `decimal`       | `[decimal]`             | `System.Decimal` |

| PowerShell Type   | C# / .NET Type                                       |
| ----------------- | ---------------------------------------------------- |
| `List[T]`         | `System.Collections.Generic.List<T>`                 |
| `Dictionary[K,V]` | `System.Collections.Generic.Dictionary<TKey,TValue>` |
| `Queue[T]`        | `System.Collections.Generic.Queue<T>`                |
| `Stack[T]`        | `System.Collections.Generic.Stack<T>`                |

| PowerShell Type | C# / .NET Type                         |
| --------------- | -------------------------------------- |
| `datetime`      | `System.DateTime`                      |
| `timespan`      | `System.TimeSpan`                      |
| `guid`          | `System.Guid`                          |
| `version`       | `System.Version`                       |
| `regex`         | `System.Text.RegularExpressions.Regex` |


| PowerShell Type  | C# Equivalent                              |
| ---------------- | ------------------------------------------ |
| `pscustomobject` | Typically `PSObject` (dynamic object)      |
| `securestring`   | `System.Security.SecureString`             |
| `xml`            | `System.Xml.XmlDocument`                   |
| `scriptblock`    | `System.Management.Automation.ScriptBlock` |



#>

class pspktFilter {
    [string]$Name
    [byte[]]$Mac1
    [byte[]]$Mac2
    [uint16]$VlanId
    [uint16]$EtherType
    [uint16]$DSCP                 
    [int16]$TransportProtocol      
    [ipaddress]$Ip1
    [ipaddress]$Ip2
    [byte]$PrefixLength1
    [byte]$PrefixLength2
    [uint16]$Port1
    [uint16]$Port2
    [byte]$TCPFlags
    [uint16]$VxLanPort
    [PKTMON_FILTER_ENCAPTYPE]$EncapType
    
    # Packets and Bytes are needed for the struct, but aren't used
    hidden static
    [uint64]$Packets = 0

    hidden static
    [uint64]$Bytes = 0
    
    # the object that pktmonapi uses
    hidden
    [PACKETMONITOR_PROTOCOL_CONSTRAINT]
    $Filter
    hidden [bool] $RawConstraintMode
    hidden [PACKETMONITOR_PROTOCOL_CONSTRAINT] $RawConstraint
    hidden [bool] $Committed
    hidden [guid] $Identity
    hidden [string] $CommittedViewFingerprint

    pspktFilter() {
        # set defaults as needed
        $this.Name = ""
        $this.Mac1 = $null
        $this.Mac2 = $null
        $this.TransportProtocol = [int16][IPv4Protocol]::ANY
        $this.Ip1 = [ipaddress]::new(0)
        $this.Ip2 = [ipaddress]::new(0)
        $this.Filter = [PACKETMONITOR_PROTOCOL_CONSTRAINT]::new()
        $this.RawConstraintMode = $false
        $this.Committed = $false
        $this.Identity = [guid]::NewGuid()
    }

    hidden [PACKETMONITOR_PROTOCOL_CONSTRAINT] CopyProtocolConstraint(
        [PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint
    ) {
        $copy = $constraint
        $copy.Mac1 = if ($null -eq $constraint.Mac1) { $null } else { [byte[]]$constraint.Mac1.Clone() }
        $copy.Mac2 = if ($null -eq $constraint.Mac2) { $null } else { [byte[]]$constraint.Mac2.Clone() }
        return $copy
    }

    [bool] IsRawConstraint() {
        return $this.RawConstraintMode
    }

    hidden [ipaddress] ConvertConstraintIpAddress(
        [PACKETMONITOR_IP_ADDRESS] $address,
        [bool] $isIpv6
    ) {
        if ($isIpv6) {
            $addressBytes = [byte[]]::new(16)
            [BitConverter]::GetBytes($address.IPv6_low).CopyTo($addressBytes, 0)
            [BitConverter]::GetBytes($address.IPv6_high).CopyTo($addressBytes, 8)
            return [ipaddress]::new($addressBytes)
        }
        return [ipaddress]::new([BitConverter]::GetBytes($address.IPv4))
    }

    [void] SetRawConstraint([PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint) {
        $this.ThrowIfCommitted()
        $this.Mac1 = $null
        $this.Mac2 = $null
        $this.VlanId = 0
        $this.EtherType = 0
        $this.DSCP = 0
        $this.TransportProtocol = [int16][IPv4Protocol]::ANY
        $this.Ip1 = [ipaddress]::new(0)
        $this.Ip2 = [ipaddress]::new(0)
        $this.PrefixLength1 = 0
        $this.PrefixLength2 = 0
        $this.Port1 = 0
        $this.Port2 = 0
        $this.TCPFlags = 0
        $this.VxLanPort = 0
        $this.EncapType = [PKTMON_FILTER_ENCAPTYPE]0
        $this.RawConstraint = $this.CopyProtocolConstraint($constraint)
        $this.Filter = $this.CopyProtocolConstraint($constraint)
        $this.Name = $constraint.Name
        $present = [uint32]$constraint.IsPresent
        $this.Mac1 = if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Mac1) -ne 0) {
            [byte[]]$constraint.Mac1.Clone()
        } else {
            [byte[]](0)
        }
        $this.Mac2 = if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Mac2) -ne 0) {
            [byte[]]$constraint.Mac2.Clone()
        } else {
            [byte[]](0)
        }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::VlanId) -ne 0) { $this.VlanId = $constraint.VlanId }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::EtherType) -ne 0) { $this.EtherType = $constraint.EtherType }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::DSCP) -ne 0) { $this.DSCP = $constraint.DSCP }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::TransportProtocol) -ne 0) {
            $this.TransportProtocol = [int16]$constraint.TransportProtocol
        }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::PrefixLength1) -ne 0) { $this.PrefixLength1 = $constraint.PrefixLength1 }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::PrefixLength2) -ne 0) { $this.PrefixLength2 = $constraint.PrefixLength2 }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Port1) -ne 0) { $this.Port1 = $constraint.Port1 }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Port2) -ne 0) { $this.Port2 = $constraint.Port2 }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::TCPFlags) -ne 0) { $this.TCPFlags = $constraint.TCPFlags }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::VxLanPort) -ne 0) { $this.VxLanPort = $constraint.VxLanPort }
        if (($present -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::EncapType) -ne 0) {
            $this.EncapType = [PKTMON_FILTER_ENCAPTYPE]$constraint.EncapType
        }
        $isIpv6 = (
            [uint32]$constraint.IsPresent -band
            [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::IPv6
        ) -ne 0
        if ((
            [uint32]$constraint.IsPresent -band
            [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Ip1
        ) -ne 0) {
            $this.Ip1 = $this.ConvertConstraintIpAddress($constraint.Ip1, $isIpv6)
        }
        if ((
            [uint32]$constraint.IsPresent -band
            [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Ip2
        ) -ne 0) {
            $this.Ip2 = $this.ConvertConstraintIpAddress($constraint.Ip2, $isIpv6)
        }
        $this.RawConstraintMode = $true
    }

    hidden [void] ThrowIfRawConstraint() {
        if ($this.RawConstraintMode) {
            throw "Raw protocol constraints cannot be modified through typed filter setters."
        }
    }

    hidden [void] ThrowIfCommitted() {
        if ($this.Committed) {
            throw "Committed filters cannot be modified. Recreate the session."
        }
    }

    hidden [void] MarkCommitted() {
        $this.Committed = $true
        $this.CommittedViewFingerprint = $this.GetViewFingerprint()
    }

    hidden [string] GetViewFingerprint() {
        return @(
            $this.Name,
            [PAUtils]::FormatPhysicalAddress([byte[]]$this.Mac1),
            [PAUtils]::FormatPhysicalAddress([byte[]]$this.Mac2),
            $this.VlanId,
            $this.EtherType,
            $this.DSCP,
            $this.TransportProtocol,
            "$($this.Ip1)",
            "$($this.Ip2)",
            $this.PrefixLength1,
            $this.PrefixLength2,
            $this.Port1,
            $this.Port2,
            $this.TCPFlags,
            $this.VxLanPort,
            [int]$this.EncapType
        ) -join '|'
    }

    hidden [bool] HasValidCommittedView() {
        return -not $this.Committed -or $this.CommittedViewFingerprint -eq $this.GetViewFingerprint()
    }

    hidden [pspktFilter] CloneForSession() {
        $clone = [pspktFilter]::new()
        $clone.Identity = $this.Identity
        if ($this.RawConstraintMode) {
            $clone.SetRawConstraint($this.ToProtocolConstraint())
            return $clone
        }

        $clone.Name = $this.Name
        $clone.Mac1 = if ($null -eq $this.Mac1) { $null } else { [byte[]]$this.Mac1.Clone() }
        $clone.Mac2 = if ($null -eq $this.Mac2) { $null } else { [byte[]]$this.Mac2.Clone() }
        $clone.VlanId = $this.VlanId
        $clone.EtherType = $this.EtherType
        $clone.DSCP = $this.DSCP
        $clone.TransportProtocol = $this.TransportProtocol
        $clone.Ip1 = $this.Ip1
        $clone.Ip2 = $this.Ip2
        $clone.PrefixLength1 = $this.PrefixLength1
        $clone.PrefixLength2 = $this.PrefixLength2
        $clone.Port1 = $this.Port1
        $clone.Port2 = $this.Port2
        $clone.TCPFlags = $this.TCPFlags
        $clone.VxLanPort = $this.VxLanPort
        $clone.EncapType = $this.EncapType
        $null = $clone.ToProtocolConstraint()
        return $clone
    }

    ## GET ##
    [string]GetMac1String() {
        if ($this.RawConstraintMode) {
            if (([uint32]$this.RawConstraint.IsPresent -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Mac1) -eq 0) {
                return ''
            }
            return [PAUtils]::FormatPhysicalAddress([byte[]]$this.RawConstraint.Mac1)
        }
        return [PAUtils]::FormatPhysicalAddress([byte[]]$this.Mac1)
    }

    [string]GetMac2String() {
        if ($this.RawConstraintMode) {
            if (([uint32]$this.RawConstraint.IsPresent -band [uint32][PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Mac2) -eq 0) {
                return ''
            }
            return [PAUtils]::FormatPhysicalAddress([byte[]]$this.RawConstraint.Mac2)
        }
        return [PAUtils]::FormatPhysicalAddress([byte[]]$this.Mac2)
    }

    [string]GetIp1String() {return "$($this.Ip1.IPAddressToString)"}
    [string]GetIp2String() {return "$($this.Ip2.IPAddressToString)"}

    [string]GetDSCPString() { return "$([DSCP]$this.DSCP)" }

    [string]GetTransportProtocolString() { return "$([IPv4Protocol]$this.TransportProtocol)" }
    
    [string]GetEncapTypeString() { return "$([PKTMON_FILTER_ENCAPTYPE]$this.EncapType)" }

    [string]GetTCPFlagsString() { return "$([TCPFLAGS]$this.TCPFlags)"}

    [string]GetEtherTypeString([int]$et) { 
        try {
            [string]$str = [ETHERTYPE]$et
            
            # this catches an oddity where ETHERTYPE will return the string version of $et
            if ([string]$et -eq $str) {
                return $null
            }

            return $str
        } catch {
            return $null
        }
    }


    ## SET/ADD ##
    #region SET/ADD

    [void] SetMac1([byte[]]$mac) {
        $this.ThrowIfCommitted()
        $this.ThrowIfRawConstraint()
        if ($null -eq $mac -or $mac.Length -ne 6) { throw "Mac1 must be exactly 6 bytes." }
        $this.Mac1 = [byte[]]$mac.Clone()
    }

    [void] SetMac1([string]$mac) {
        $this.ThrowIfCommitted()
        $this.ThrowIfRawConstraint()
        $macBytes = ([PAUtils]::ConvertString2PhysicalAddress($mac)).GetAddressBytes()
        if ($macBytes.Length -ne 6) { throw "Mac1 is not a valid MAC address." }
        $this.Mac1 = $macBytes
    }

    [void] SetMac2([byte[]]$mac) {
        $this.ThrowIfCommitted()
        $this.ThrowIfRawConstraint()
        if ($null -eq $mac -or $mac.Length -ne 6) { throw "Mac2 must be exactly 6 bytes." }
        $this.Mac2 = [byte[]]$mac.Clone()
    }

    [void] SetMac2([string]$mac) {
        $this.ThrowIfCommitted()
        $this.ThrowIfRawConstraint()
        $macBytes = ([PAUtils]::ConvertString2PhysicalAddress($mac)).GetAddressBytes()
        if ($macBytes.Length -ne 6) { throw "Mac2 is not a valid MAC address." }
        $this.Mac2 = $macBytes
    }

    [void] SetVlanId([uint16]$vlanId) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.VlanId = $vlanId }

    [void] SetEtherType([uint16]$etherType)    { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.EtherType = $etherType }
    [void] SetEtherType([ETHERTYPE]$etherType) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.EtherType = [uint16]$etherType }

    [void] SetDSCP([uint16]$dscp) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.DSCP = $dscp }
    [void] SetDSCP([DSCP]$dscp)   { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.DSCP = [uint16]$dscp }

    [void] SetTransportProtocol([int16]$protocol)        { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.TransportProtocol = $protocol }
    [void] SetTransportProtocol([IPv4Protocol]$protocol) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.TransportProtocol = [int16]$protocol }

    [void] SetIp1([ipaddress]$ip) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.Ip1 = $ip }
    [void] SetIp1([string]$ip)    { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.Ip1 = [ipaddress]::Parse($ip) }

    [void] SetIp2([ipaddress]$ip) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.Ip2 = $ip }
    [void] SetIp2([string]$ip)    { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.Ip2 = [ipaddress]::Parse($ip) }

    [void] SetPrefixLength1([byte]$len) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.PrefixLength1 = $len }

    [void] SetPrefixLength2([byte]$len) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.PrefixLength2 = $len }

    [void] SetPort1([uint16]$port) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.Port1 = $port }

    [void] SetPort2([uint16]$port) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.Port2 = $port }

    [void] SetTCPFlags([byte]$flags)     { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.TCPFlags = $flags }
    [void] SetTCPFlags([TCPFLAGS]$flags) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.TCPFlags = [byte]$flags }

    [void] SetVxLanPort([uint16]$port) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.VxLanPort = $port }

    [void] SetEncapType([PKTMON_FILTER_ENCAPTYPE]$encapType) { $this.ThrowIfCommitted(); $this.ThrowIfRawConstraint(); $this.EncapType = $encapType }

    #endregion SET/ADD

    
    ## UTIL ##
    [PACKETMONITOR_IP_ADDRESS]
    ConvertIp2PspktIpAddress([ipaddress]$addr) {
        $ip    = [PACKETMONITOR_IP_ADDRESS]::new()
        $rbytes = $addr.GetAddressBytes()

        switch ($addr.AddressFamily) {
            'InterNetwork' {           # IPv4 -> 4 bytes
                $ip.IPv4 = [BitConverter]::ToUInt32($rbytes, 0)
            }
            'InterNetworkV6' {         # IPv6 -> 16 bytes, two ulongs
                $ip.IPv6_low  = [BitConverter]::ToUInt64($rbytes, 0)
                $ip.IPv6_high = [BitConverter]::ToUInt64($rbytes, 8)
            }
            default { throw "Unsupported address family: $($addr.AddressFamily)" }
        }

        return $ip
    }

    [PACKETMONITOR_PROTOCOL_CONSTRAINT]
    ToProtocolConstraint() {
        if ($this.RawConstraintMode) {
            return $this.CopyProtocolConstraint($this.RawConstraint)
        }

        $constraint = [PACKETMONITOR_PROTOCOL_CONSTRAINT]::new()
        $flags = [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::None

        # Name is optional for API usage.
        $constraint.Name = if ([string]::IsNullOrEmpty($this.Name)) { "" } else { $this.Name }

        if ($this.Mac1 -and $this.Mac1.Length -gt 0) {
            if ($this.Mac1.Length -ne 6) { throw "Mac1 must be exactly 6 bytes." }
            $constraint.Mac1 = [byte[]]$this.Mac1.Clone()
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Mac1
        } else {
            $constraint.Mac1 = [byte[]](0,0,0,0,0,0)
        }

        if ($this.Mac2 -and $this.Mac2.Length -gt 0) {
            if ($this.Mac2.Length -ne 6) { throw "Mac2 must be exactly 6 bytes." }
            $constraint.Mac2 = [byte[]]$this.Mac2.Clone()
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Mac2
        } else {
            $constraint.Mac2 = [byte[]](0,0,0,0,0,0)
        }

        if ($this.VlanId -ne 0) {
            $constraint.VlanId = $this.VlanId
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::VlanId
        }

        if ($this.EtherType -ne 0) {
            $constraint.EtherType = $this.EtherType
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::EtherType
        }

        if ($this.DSCP -ne 0) {
            $constraint.DSCP = $this.DSCP
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::DSCP
        }

        if ($this.TransportProtocol -ne [int16][IPv4Protocol]::ANY) {
            $constraint.TransportProtocol = [byte]$this.TransportProtocol
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::TransportProtocol
        }

        $hasIp1 = $null -ne $this.Ip1 -and $this.Ip1 -ne [IPAddress]::Any -and $this.Ip1 -ne [IPAddress]::IPv6Any
        $hasIp2 = $null -ne $this.Ip2 -and $this.Ip2 -ne [IPAddress]::Any -and $this.Ip2 -ne [IPAddress]::IPv6Any

        $ipVersionIsV6 = $false
        if ($hasIp1 -or $hasIp2) {
            if ($hasIp1 -and $hasIp2 -and $this.Ip1.AddressFamily -ne $this.Ip2.AddressFamily) {
                throw "Ip1 and Ip2 must use the same address family (both IPv4 or both IPv6)."
            }

            if ($hasIp1) {
                $constraint.Ip1 = $this.ConvertIp2PspktIpAddress($this.Ip1)
                $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Ip1
                $ipVersionIsV6 = $this.Ip1.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
            }

            if ($hasIp2) {
                $constraint.Ip2 = $this.ConvertIp2PspktIpAddress($this.Ip2)
                $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Ip2
                if (-not $hasIp1) {
                    $ipVersionIsV6 = $this.Ip2.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
                }
            }

            if ($ipVersionIsV6) {
                $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::IPv6
            }

            if ($this.PrefixLength1 -ne 0 -and $hasIp1) {
                $constraint.PrefixLength1 = $this.PrefixLength1
                $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::PrefixLength1
            }

            if ($this.PrefixLength2 -ne 0 -and $hasIp2) {
                $constraint.PrefixLength2 = $this.PrefixLength2
                $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::PrefixLength2
            }
        }

        if ($this.Port1 -ne 0) {
            $constraint.Port1 = $this.Port1
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Port1
        }

        if ($this.Port2 -ne 0) {
            $constraint.Port2 = $this.Port2
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::Port2
        }

        if ($this.TCPFlags -ne 0) {
            $constraint.TCPFlags = $this.TCPFlags
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::TCPFlags
        }

        if ($this.VxLanPort -ne 0) {
            $constraint.VxLanPort = $this.VxLanPort
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::VxLanPort
        }

        if ([uint32]$this.EncapType -ne 0) {
            $constraint.EncapType = [uint32]$this.EncapType
            $flags = $flags -bor [PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS]::EncapType
        }

        # Present in native struct but currently not used by the API.
        $constraint.Packets = [pspktFilter]::Packets
        $constraint.Bytes   = [pspktFilter]::Bytes

        $constraint.IsPresent = $flags
        $this.Filter = $constraint
        return $constraint
    }

}



class pspktSession {
    hidden static [int] $MaxFilterCount = 32
    [string]
    $Name

    hidden
    [IntPtr] 
    $Handle
    
    [System.Collections.ArrayList]
    $Components

    [System.Collections.ArrayList]
    $Filters

    hidden
    [System.Collections.ArrayList]
    $OutputStream

    # Tracks which components/filters have been committed to the native API.
    hidden [System.Collections.Generic.HashSet[int]] $CommittedComponents
    hidden [System.Collections.Generic.HashSet[int]] $CommittedFilters
    hidden [System.Collections.Generic.Dictionary[int, IntPtr]] $CommittedComponentPointers
    hidden [System.Collections.Generic.Dictionary[int, guid]] $CommittedFilterIdentities

    [Bool] $Active

    # Session configuration properties (matching pktmon start options).
    [PspktCaptureType] $CaptureType
    [PspktLogMode]     $LogMode
    [uint32]           $EventFlags
    [uint32]           $PacketSize
    [uint32]           $FileSize
    [string]           $FileName
    [bool]             $CountersOnly

    # VM scoping: when set, every filter added to this session is AND-combined
    # with each vmNIC MAC address so capture stays in the VM's network data path.
    [string]   $VMName
    [string[]] $VMMacAddresses
    hidden [string] $CanonicalVMName
    hidden [string[]] $CanonicalVMMacAddresses
    hidden [string] $VmScopeFingerprint

    hidden
    [pspkt] $Pspkt

    hidden [IPspktNativeApi] $NativeApi
    hidden [bool] $Faulted
    hidden [string] $FaultOperation
    hidden [string] $FaultMessage
    hidden [int[]] $FaultCommittedComponentIndexes
    hidden [int[]] $FaultCommittedFilterIndexes
    hidden [int] $FaultComponentCount
    hidden [int] $FaultFilterCount
    hidden [int] $FaultOutputCount
    hidden [bool] $FaultActive
    hidden [bool] $FaultNativeStateUncertain
    hidden [bool] $VmScopeOnlyFiltersMaterialized
    hidden [bool] $VmScopeOnlyFiltersPending
    hidden [bool] $Closed
    hidden [object] $CaptureFileWriter
    hidden [bool] $CaptureCleanupPending

    pspktSession([string] $name, [intptr]$handle)
    {
        $this.InitializeManagedState($name, $handle, [PspktNativeApi]::new())
    }

    hidden pspktSession([string] $name, [intptr]$handle, [IPspktNativeApi] $nativeApi)
    {
        $this.InitializeManagedState($name, $handle, $nativeApi)
    }

    hidden [void] InitializeManagedState(
        [string] $name,
        [intptr] $handle,
        [IPspktNativeApi] $nativeApi
    )
    {
        if ($null -eq $nativeApi) { throw "Native API cannot be null." }
        $this.name = $name
        $this.handle = $handle
        $this.NativeApi = $nativeApi
        $this.Components = [System.Collections.ArrayList]::new()
        $this.Filters = [System.Collections.ArrayList]::new()
        $this.OutputStream = [System.Collections.ArrayList]::new()
        $this.CommittedComponents = [System.Collections.Generic.HashSet[int]]::new()
        $this.CommittedFilters = [System.Collections.Generic.HashSet[int]]::new()
        $this.CommittedComponentPointers = [System.Collections.Generic.Dictionary[int, IntPtr]]::new()
        $this.CommittedFilterIdentities = [System.Collections.Generic.Dictionary[int, guid]]::new()

        # Defaults matching pktmon start defaults.
        $this.CaptureType  = [PspktCaptureType]::All
        $this.LogMode      = [PspktLogMode]::RealTime
        $this.EventFlags   = 0x032
        $this.PacketSize   = 128
        $this.FileSize     = 512
        $this.FileName     = 'PktMon.etl'
        $this.CountersOnly = $false
        $this.VmScopeOnlyFiltersMaterialized = $false
        $this.VmScopeOnlyFiltersPending = $false
        $this.CaptureFileWriter = $null
        $this.CaptureCleanupPending = $false
        $this.Closed = $false
        $this.ClearFaultState()
    }

    hidden [int[]] CopyIndexes([System.Collections.Generic.HashSet[int]] $indexes)
    {
        $copy = [int[]]::new($indexes.Count)
        $indexes.CopyTo($copy)
        return $copy
    }

    hidden [void] ClearFaultState()
    {
        $this.Faulted = $false
        $this.FaultOperation = ''
        $this.FaultMessage = ''
        $this.FaultCommittedComponentIndexes = [int[]]::new(0)
        $this.FaultCommittedFilterIndexes = [int[]]::new(0)
        $this.FaultComponentCount = 0
        $this.FaultFilterCount = 0
        $this.FaultOutputCount = 0
        $this.FaultActive = $false
        $this.FaultNativeStateUncertain = $false
    }

    hidden [void] MarkFaulted(
        [string] $operation,
        [string] $message,
        [bool] $nativeStateUncertain
    )
    {
        if ($this.Faulted) { return }
        $this.Faulted = $true
        $this.FaultOperation = $operation
        $this.FaultMessage = $message
        $this.FaultCommittedComponentIndexes = $this.CopyIndexes($this.CommittedComponents)
        $this.FaultCommittedFilterIndexes = $this.CopyIndexes($this.CommittedFilters)
        $this.FaultComponentCount = $this.Components.Count
        $this.FaultFilterCount = $this.Filters.Count
        $this.FaultOutputCount = $this.OutputStream.Count
        $this.FaultActive = $this.Active
        $this.FaultNativeStateUncertain = $nativeStateUncertain
    }

    hidden [pscustomobject] GetFaultSnapshot()
    {
        if (-not $this.Faulted) { return $null }
        return [pscustomobject]@{
            Operation = $this.FaultOperation
            Message = $this.FaultMessage
            CommittedComponentIndexes = [int[]]$this.FaultCommittedComponentIndexes.Clone()
            CommittedFilterIndexes = [int[]]$this.FaultCommittedFilterIndexes.Clone()
            ComponentCount = $this.FaultComponentCount
            FilterCount = $this.FaultFilterCount
            OutputCount = $this.FaultOutputCount
            Active = $this.FaultActive
            NativeStateUncertain = $this.FaultNativeStateUncertain
        }
    }

    hidden [void] ThrowIfFaultedForForwardOperation()
    {
        if ($this.Closed) {
            throw "Session '$($this.Name)' has been torn down and cannot be reused."
        }
        if ($this.Faulted) {
            throw "Session '$($this.Name)' is faulted after '$($this.FaultOperation)'. Tear it down and create a new session."
        }
        $this.ValidateVmScopeMirrors()
    }

    hidden [string[]] NormalizeVmMacAddresses([string[]] $macAddresses)
    {
        if ($null -eq $macAddresses -or $macAddresses.Count -eq 0) {
            throw "VM scope requires at least one valid MAC address."
        }

        $normalizedSet = [System.Collections.Generic.SortedSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($macAddress in $macAddresses) {
            $physicalAddress = [PAUtils]::ConvertString2PhysicalAddress($macAddress)
            $addressBytes = $physicalAddress.GetAddressBytes()
            if ($addressBytes.Length -ne 6) {
                throw "VM scope contains an invalid MAC address: '$macAddress'."
            }

            $allZero = $true
            foreach ($addressByte in $addressBytes) {
                if ($addressByte -ne 0) {
                    $allZero = $false
                    break
                }
            }
            if ($allZero) {
                throw "VM scope requires at least one valid non-zero MAC address."
            }

            $null = $normalizedSet.Add([PAUtils]::FormatPhysicalAddress($addressBytes))
        }

        if ($normalizedSet.Count -eq 0) {
            throw "VM scope requires at least one valid MAC address."
        }

        $normalized = [string[]]::new($normalizedSet.Count)
        $normalizedSet.CopyTo($normalized)
        return $normalized
    }

    hidden [string] GetVmScopeFingerprint([string] $vmName, [string[]] $macAddresses)
    {
        if ([string]::IsNullOrWhiteSpace($vmName)) {
            throw "VM scope requires a VM name."
        }
        $normalized = $this.NormalizeVmMacAddresses($macAddresses)
        return $vmName.Trim().ToUpperInvariant() + '|' + ($normalized -join ',')
    }

    hidden [void] ValidateVmScopeMirrors()
    {
        if ([string]::IsNullOrEmpty($this.VmScopeFingerprint)) {
            if (
                -not [string]::IsNullOrEmpty($this.VMName) -or
                ($null -ne $this.VMMacAddresses -and $this.VMMacAddresses.Count -gt 0)
            ) {
                throw "VM scope was modified directly. Use Start-Pspkt or Add-PspktComponent VM parameters."
            }
            return
        }

        try {
            $mirrorFingerprint = $this.GetVmScopeFingerprint($this.VMName, $this.VMMacAddresses)
        } catch {
            throw "VM scope was modified directly. Use Start-Pspkt or Add-PspktComponent VM parameters."
        }
        if ($mirrorFingerprint -ne $this.VmScopeFingerprint) {
            throw "VM scope was modified directly. Use Start-Pspkt or Add-PspktComponent VM parameters."
        }
    }

    hidden [void] SetVmScope([string] $vmName, [string[]] $macAddresses)
    {
        $this.ThrowIfFaultedForForwardOperation()

        $normalized = $this.NormalizeVmMacAddresses($macAddresses)
        $fingerprint = $this.GetVmScopeFingerprint($vmName, $normalized)
        if ($fingerprint -eq $this.VmScopeFingerprint) {
            $this.VMName = $this.CanonicalVMName
            $this.VMMacAddresses = [string[]]$this.CanonicalVMMacAddresses.Clone()
            return
        }

        $scopeLocked = (
            $this.Components.Count -gt 0 -or
            $this.Filters.Count -gt 0 -or
            $this.OutputStream.Count -gt 0 -or
            $this.CommittedComponents.Count -gt 0 -or
            $this.CommittedFilters.Count -gt 0 -or
            $this.Active
        )
        if ($scopeLocked) {
            throw "VM scope cannot change after session configuration has started."
        }

        $this.CanonicalVMName = $vmName.Trim()
        $this.CanonicalVMMacAddresses = [string[]]$normalized.Clone()
        $this.VmScopeFingerprint = $fingerprint
        $this.VMName = $this.CanonicalVMName
        $this.VMMacAddresses = [string[]]$normalized.Clone()
    }

    hidden [pscustomobject] GetVmScopeSnapshot()
    {
        return [pscustomobject]@{
            CanonicalVMName = $this.CanonicalVMName
            CanonicalVMMacAddresses = if ($null -eq $this.CanonicalVMMacAddresses) {
                $null
            } else {
                [string[]]$this.CanonicalVMMacAddresses.Clone()
            }
            VmScopeFingerprint = $this.VmScopeFingerprint
            VMName = $this.VMName
            VMMacAddresses = if ($null -eq $this.VMMacAddresses) {
                $null
            } else {
                [string[]]$this.VMMacAddresses.Clone()
            }
            VmScopeOnlyFiltersMaterialized = $this.VmScopeOnlyFiltersMaterialized
            VmScopeOnlyFiltersPending = $this.VmScopeOnlyFiltersPending
        }
    }

    hidden [void] RestoreVmScopeSnapshot([pscustomobject] $snapshot)
    {
        $this.CanonicalVMName = [string]$snapshot.CanonicalVMName
        $this.CanonicalVMMacAddresses = if ($null -eq $snapshot.CanonicalVMMacAddresses) {
            $null
        } else {
            [string[]]$snapshot.CanonicalVMMacAddresses.Clone()
        }
        $this.VmScopeFingerprint = [string]$snapshot.VmScopeFingerprint
        $this.VMName = [string]$snapshot.VMName
        $this.VMMacAddresses = if ($null -eq $snapshot.VMMacAddresses) {
            $null
        } else {
            [string[]]$snapshot.VMMacAddresses.Clone()
        }
        $this.VmScopeOnlyFiltersMaterialized = [bool]$snapshot.VmScopeOnlyFiltersMaterialized
        $this.VmScopeOnlyFiltersPending = [bool]$snapshot.VmScopeOnlyFiltersPending
    }

    hidden [void] RollbackConfiguration(
        [int] $componentCount,
        [int] $filterCount,
        [pscustomobject] $vmScopeSnapshot
    )
    {
        while ($this.Filters.Count -gt $filterCount) {
            $index = $this.Filters.Count - 1
            if ($this.CommittedFilters.Contains($index)) {
                throw "Cannot roll back a committed filter."
            }
            $this.Filters.RemoveAt($index)
            $this.ReindexCommittedSet($this.CommittedFilters, $index)
            $this.ReindexCommittedFilterIdentities($index)
        }
        while ($this.Components.Count -gt $componentCount) {
            $index = $this.Components.Count - 1
            if ($this.CommittedComponents.Contains($index)) {
                throw "Cannot roll back a committed component."
            }
            $this.Components.RemoveAt($index)
            $this.ReindexCommittedSet($this.CommittedComponents, $index)
        }
        $this.RestoreVmScopeSnapshot($vmScopeSnapshot)
    }

    # Converts the current session state to a PACKETMONITOR_SESSION struct
    # suitable for serialization or native interop.
    [PACKETMONITOR_SESSION] ToSessionConfiguration()
    {
        $config = [PACKETMONITOR_SESSION]::new()
        $config.Name            = $this.Name
        $config.CaptureType     = [PACKETMONITOR_CAPTURE_TYPE]([int]$this.CaptureType)
        $config.LogMode         = [PACKETMONITOR_LOG_MODE]([int]$this.LogMode)
        $config.EventFlags      = [PACKETMONITOR_EVENT_FLAGS]$this.EventFlags
        $config.PacketSize      = $this.PacketSize
        $config.FileSize        = $this.FileSize
        $config.FileName        = $this.FileName
        $config.CountersOnly    = $this.CountersOnly
        $config.Active          = $this.Active
        $config.DataSourceCount = [uint32]$this.Components.Count
        $config.ConstraintCount = [uint32]$this.Filters.Count
        $config.StreamCount     = [uint32]$this.OutputStream.Count
        return $config
    }

    [void] SetSessionActive([bool] $active)
    {
        if ($active) { $this.ThrowIfFaultedForForwardOperation() }
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }

        if ($active) {
            $this.CommitSessionConfiguration()
        }

        try {
            $res = $this.NativeApi.PacketMonitorSetSessionActive($this.handle, $active)
            if ($res -ne 0) {
                if ($active) {
                    $this.MarkFaulted('SetSessionActive', ("Native status 0x{0:X}" -f $res), $true)
                }
                throw "Failed to set session active state: 0x{0:X}" -f $res
            }
        } catch {
            if ($active) {
                $this.MarkFaulted('SetSessionActive', $_.Exception.Message, $true)
            }
            throw
        }
        $this.active = $active
        if ($active -and $this.VmScopeOnlyFiltersPending) {
            $this.VmScopeOnlyFiltersPending = $false
            $this.VmScopeOnlyFiltersMaterialized = $true
        }
    }

    # Stores a component for later commit. No native API call until the session is activated.
    hidden [void] ValidateComponentBatch([pspktComponent[]] $components)
    {
        $this.ThrowIfFaultedForForwardOperation()
        foreach ($component in $components) {
            if ($null -eq $component) { throw "DataSource cannot be null." }
            if ($this.Active -and $component.Pointer -eq [IntPtr]::Zero) {
                throw "DataSource pointer is null for component '$($component.Name)'."
            }
        }
    }

    [void] AddSingleDataSourceToSession([pspktComponent] $DataSource)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($null -eq $DataSource) { throw "DataSource cannot be null." }
        if ($this.Active -and $DataSource.Pointer -eq [IntPtr]::Zero) {
            throw "DataSource pointer is null for component '$($DataSource.Name)'."
        }

        $null = $this.Components.Add($DataSource)

        # If the session is already active, commit the new component immediately.
        if ($this.Active) {
            $this.CommitComponent($DataSource, $this.Components.Count - 1)
        }
    }

    hidden [int] GetRequiredFilterSlots([pspktFilter] $filter)
    {
        if (
            $null -ne $this.CanonicalVMMacAddresses -and
            $this.CanonicalVMMacAddresses.Count -gt 0 -and
            ($null -eq $filter.Mac1 -or $filter.Mac1.Length -lt 6)
        ) {
            return $this.CanonicalVMMacAddresses.Count
        }
        return 1
    }

    hidden [bool] IsCanonicalVmMac([byte[]] $macAddress)
    {
        if (
            $null -eq $macAddress -or
            $macAddress.Length -ne 6 -or
            $null -eq $this.CanonicalVMMacAddresses -or
            $this.CanonicalVMMacAddresses.Count -eq 0
        ) {
            return $false
        }

        $normalizedAddress = [PAUtils]::FormatPhysicalAddress($macAddress)
        return $this.CanonicalVMMacAddresses -contains $normalizedAddress
    }

    hidden [void] ValidateFilterBatchCapacity([pspktFilter[]] $filters)
    {
        $this.ThrowIfFaultedForForwardOperation()
        $requiredSlots = $this.Filters.Count
        $identities = [System.Collections.Generic.HashSet[guid]]::new()
        foreach ($existingFilter in $this.Filters) {
            $null = $identities.Add($existingFilter.Identity)
        }
        foreach ($candidateFilter in $filters) {
            if ($null -eq $candidateFilter) { throw "Filter cannot be null." }
            if (-not $identities.Add($candidateFilter.Identity)) {
                throw "The same filter object cannot be added to a session more than once."
            }
            if (
                $candidateFilter.IsRawConstraint() -and
                $null -ne $this.CanonicalVMMacAddresses -and
                $this.CanonicalVMMacAddresses.Count -gt 0
            ) {
                throw "Raw protocol constraints cannot be added to a VM-scoped session."
            }

            $candidateConstraint = $candidateFilter.ToProtocolConstraint()
            $this.ValidateConstraintMarshalability($candidateConstraint)
            if (
                $null -ne $this.CanonicalVMMacAddresses -and
                $this.CanonicalVMMacAddresses.Count -gt 0 -and
                $null -ne $candidateFilter.Mac1 -and
                $candidateFilter.Mac1.Length -eq 6 -and
                -not $this.IsCanonicalVmMac($candidateFilter.Mac1)
            ) {
                throw "Filter Mac1 must match a MAC address in VM scope '$($this.CanonicalVMName)'."
            }
            $requiredSlots += $this.GetRequiredFilterSlots($candidateFilter)
        }
        if ($requiredSlots -gt [pspktSession]::MaxFilterCount) {
            throw "A session supports at most $([pspktSession]::MaxFilterCount) filters."
        }
    }

    hidden [void] ValidateFilterForCommit([pspktFilter] $filter)
    {
        if ($null -eq $filter) { throw "Filter cannot be null." }
        $null = $filter.ToProtocolConstraint()
        if ($null -ne $this.CanonicalVMMacAddresses -and $this.CanonicalVMMacAddresses.Count -gt 0) {
            if ($filter.IsRawConstraint()) {
                throw "Raw protocol constraints cannot be added to a VM-scoped session."
            }
            if (-not $this.IsCanonicalVmMac($filter.Mac1)) {
                throw "Filter Mac1 must match a MAC address in VM scope '$($this.CanonicalVMName)'."
            }
        }

    }

    hidden [void] ValidateConstraintMarshalability([PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint)
    {
        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][PACKETMONITOR_PROTOCOL_CONSTRAINT])
        $constraintPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        try {
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($constraint, $constraintPtr, $false)
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($constraintPtr)
        }
    }

    # Stores a filter for later commit. Validates the filter can produce a constraint.
    # When VM scoping is active (VMMacAddresses is populated), expands the filter into
    # one clone per vmNIC MAC with Mac1 set, so the pktmon OR-combined filter set
    # effectively AND-combines "VM MAC" with the filter's protocol scope.
    [void] AddFilter([pspktFilter] $filter)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($null -eq $filter) { throw "Filter cannot be null." }
        if ($this.VmScopeOnlyFiltersMaterialized) {
            throw "Filters cannot be added after a VM-scoped session starts with broad MAC-only filters. Recreate the session with filters configured before activation."
        }
        foreach ($existingFilter in $this.Filters) {
            if ($existingFilter.Identity -eq $filter.Identity) {
                throw "The same filter object cannot be added to a session more than once."
            }
        }

        $this.ValidateFilterBatchCapacity([pspktFilter[]]@($filter))
        $storedFilter = $filter.CloneForSession()
        if ($storedFilter.IsRawConstraint()) {
            if ($null -ne $this.CanonicalVMMacAddresses -and $this.CanonicalVMMacAddresses.Count -gt 0) {
                throw "Raw protocol constraints cannot be added to a VM-scoped session."
            }
            $null = $this.Filters.Add($storedFilter)
            if ($this.Active) {
                $this.CommitFilter($storedFilter, $this.Filters.Count - 1)
            }
            return
        }

        if ($null -ne $this.CanonicalVMMacAddresses -and $this.CanonicalVMMacAddresses.Count -gt 0 -and
            ($null -eq $filter.Mac1 -or $filter.Mac1.Length -lt 6))
        {
            foreach ($macStr in $this.CanonicalVMMacAddresses)
            {
                $clone = [pspktFilter]::new()
                $clone.Identity = $filter.Identity
                $clone.Name              = "$($filter.Name)-VM-$macStr"
                if ($null -ne $filter.Mac1) { $clone.Mac1 = [byte[]]$filter.Mac1.Clone() }
                if ($null -ne $filter.Mac2) { $clone.Mac2 = [byte[]]$filter.Mac2.Clone() }
                $clone.VlanId            = $filter.VlanId
                $clone.EtherType         = $filter.EtherType
                $clone.DSCP              = $filter.DSCP
                $clone.TransportProtocol = $filter.TransportProtocol
                if ($null -ne $filter.Ip1) { $clone.Ip1 = $filter.Ip1 }
                if ($null -ne $filter.Ip2) { $clone.Ip2 = $filter.Ip2 }
                $clone.PrefixLength1     = $filter.PrefixLength1
                $clone.PrefixLength2     = $filter.PrefixLength2
                $clone.Port1             = $filter.Port1
                $clone.Port2             = $filter.Port2
                $clone.TCPFlags          = $filter.TCPFlags
                $clone.VxLanPort         = $filter.VxLanPort
                $clone.EncapType         = $filter.EncapType
                $clone.SetMac1($macStr)

                $storedClone = $clone.CloneForSession()
                $null = $this.Filters.Add($storedClone)

                if ($this.Active) {
                    $this.CommitFilter($storedClone, $this.Filters.Count - 1)
                }
            }
        }
        else
        {
            $null = $this.Filters.Add($storedFilter)

            # If the session is already active, commit the new filter immediately.
            if ($this.Active) {
                $this.CommitFilter($storedFilter, $this.Filters.Count - 1)
            }
        }
    }

    [void] AddFilter([PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($this.VmScopeOnlyFiltersMaterialized) {
            throw "Filters cannot be added after a VM-scoped session starts with broad MAC-only filters. Recreate the session with filters configured before activation."
        }
        if ($null -ne $this.CanonicalVMMacAddresses -and $this.CanonicalVMMacAddresses.Count -gt 0) {
            throw "Raw protocol constraints cannot be added to a VM-scoped session."
        }
        if ($this.Filters.Count + 1 -gt [pspktSession]::MaxFilterCount) {
            throw "A session supports at most $([pspktSession]::MaxFilterCount) filters."
        }
        $filter = [pspktFilter]::new()
        $filter.SetRawConstraint($constraint)
        $null = $this.Filters.Add($filter)

        if ($this.Active) {
            $this.CommitFilter($filter, $this.Filters.Count - 1)
        }
    }

    [bool] RemoveComponent([pspktComponent] $DataSource)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($this.Active) { throw "Components cannot be removed while the session is active." }
        if ($null -eq $DataSource) { return $false }
        $idx = $this.Components.IndexOf($DataSource)
        if ($idx -lt 0) { return $false }
        if ($this.CommittedComponents.Contains($idx)) {
            throw "Committed components cannot be removed. Recreate the session."
        }
        $this.CommittedComponents.Remove($idx) | Out-Null
        $this.Components.RemoveAt($idx)
        # Re-index committed set after removal.
        $this.ReindexCommittedSet($this.CommittedComponents, $idx)
        $this.ReindexCommittedComponentPointers($idx)
        return $true
    }

    [bool] RemoveComponentAt([int] $Index)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($this.Active) { throw "Components cannot be removed while the session is active." }
        if ($Index -lt 0 -or $Index -ge $this.Components.Count) { return $false }
        if ($this.CommittedComponents.Contains($Index)) {
            throw "Committed components cannot be removed. Recreate the session."
        }
        $this.CommittedComponents.Remove($Index) | Out-Null
        $this.Components.RemoveAt($Index)
        $this.ReindexCommittedSet($this.CommittedComponents, $Index)
        $this.ReindexCommittedComponentPointers($Index)
        return $true
    }

    [bool] RemoveFilter([pspktFilter] $Filter)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($this.Active) { throw "Filters cannot be removed while the session is active." }
        if ($null -eq $Filter) { return $false }
        $matchingIndexes = [System.Collections.ArrayList]::new()
        for ($index = 0; $index -lt $this.Filters.Count; $index++) {
            if ($this.Filters[$index].Identity -eq $Filter.Identity) {
                $null = $matchingIndexes.Add($index)
            }
        }
        if ($matchingIndexes.Count -eq 0) { return $false }
        foreach ($matchingIndex in $matchingIndexes) {
            if ($this.CommittedFilters.Contains([int]$matchingIndex)) {
                throw "Committed filters cannot be removed. Recreate the session."
            }
        }
        for ($matchOffset = $matchingIndexes.Count - 1; $matchOffset -ge 0; $matchOffset--) {
            $idx = [int]$matchingIndexes[$matchOffset]
            $this.Filters.RemoveAt($idx)
            $this.ReindexCommittedSet($this.CommittedFilters, $idx)
            $this.ReindexCommittedFilterIdentities($idx)
        }
        return $true
    }

    [bool] RemoveFilterAt([int] $Index)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($this.Active) { throw "Filters cannot be removed while the session is active." }
        if ($Index -lt 0 -or $Index -ge $this.Filters.Count) { return $false }
        if ($this.CommittedFilters.Contains($Index)) {
            throw "Committed filters cannot be removed. Recreate the session."
        }
        $identity = $this.Filters[$Index].Identity
        $identityCount = 0
        foreach ($existingFilter in $this.Filters) {
            if ($existingFilter.Identity -eq $identity) { $identityCount++ }
        }
        if ($identityCount -gt 1) {
            throw "VM-expanded filters must be removed by filter object so the whole identity group is removed."
        }
        $this.CommittedFilters.Remove($Index) | Out-Null
        $this.Filters.RemoveAt($Index)
        $this.ReindexCommittedSet($this.CommittedFilters, $Index)
        $this.ReindexCommittedFilterIdentities($Index)
        return $true
    }

    # Shifts indices in a committed set down by one for all entries above the removed index.
    hidden [void] ReindexCommittedSet([System.Collections.Generic.HashSet[int]] $set, [int] $removedIndex)
    {
        $newSet = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($i in $set) {
            if ($i -lt $removedIndex) {
                $newSet.Add($i) | Out-Null
            } elseif ($i -gt $removedIndex) {
                $newSet.Add($i - 1) | Out-Null
            }

            # $i -eq $removedIndex is dropped (already removed above)
        }
        $set.Clear()
        foreach ($i in $newSet) {
            $set.Add($i) | Out-Null
        }
    }

    hidden [void] ReindexCommittedComponentPointers([int] $removedIndex)
    {
        $reindexed = [System.Collections.Generic.Dictionary[int, IntPtr]]::new()
        foreach ($entry in $this.CommittedComponentPointers.GetEnumerator()) {
            if ($entry.Key -lt $removedIndex) {
                $reindexed[$entry.Key] = $entry.Value
            } elseif ($entry.Key -gt $removedIndex) {
                $reindexed[$entry.Key - 1] = $entry.Value
            }

        }
        $this.CommittedComponentPointers = $reindexed
    }

    hidden [void] ReindexCommittedFilterIdentities([int] $removedIndex)
    {
        $reindexed = [System.Collections.Generic.Dictionary[int, guid]]::new()
        foreach ($entry in $this.CommittedFilterIdentities.GetEnumerator()) {
            if ($entry.Key -lt $removedIndex) {
                $reindexed[$entry.Key] = $entry.Value
            } elseif ($entry.Key -gt $removedIndex) {
                $reindexed[$entry.Key - 1] = $entry.Value
            }
        }
        $this.CommittedFilterIdentities = $reindexed
    }

    # Commits all uncommitted components and filters to the native pktmon session.
    hidden [void] CommitSessionConfiguration()
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }
        $filterCountBeforeVmMaterialization = $this.Filters.Count
        $vmPendingBeforeCommit = $this.VmScopeOnlyFiltersPending
        $this.EnsureVmScopeFilters()

        try {
        if ($this.Filters.Count -gt [pspktSession]::MaxFilterCount) {
            throw "A session supports at most $([pspktSession]::MaxFilterCount) filters."
        }
        foreach ($committedFilterIndex in $this.CommittedFilters) {
            if (
                $committedFilterIndex -lt 0 -or
                $committedFilterIndex -ge $this.Filters.Count -or
                -not $this.CommittedFilterIdentities.ContainsKey($committedFilterIndex) -or
                $this.Filters[$committedFilterIndex].Identity -ne
                    $this.CommittedFilterIdentities[$committedFilterIndex] -or
                -not $this.Filters[$committedFilterIndex].Committed -or
                -not $this.Filters[$committedFilterIndex].HasValidCommittedView()
            ) {
                throw "The committed filter collection was modified directly. Recreate the session."
            }
        }
        foreach ($committedComponentIndex in $this.CommittedComponents) {
            if (
                $committedComponentIndex -lt 0 -or
                $committedComponentIndex -ge $this.Components.Count -or
                -not $this.CommittedComponentPointers.ContainsKey($committedComponentIndex) -or
                $this.Components[$committedComponentIndex].Pointer -ne
                    $this.CommittedComponentPointers[$committedComponentIndex]
            ) {
                throw "The committed component collection was modified directly. Recreate the session."
            }
        }

        # Resolve any components with stale/null pointers by re-enumerating
        # from the session's active pspkt instance.
        $needsResolve = $false
        for ($i = 0; $i -lt $this.Components.Count; $i++) {
            if (-not $this.CommittedComponents.Contains($i) -and
                $this.Components[$i].Pointer -eq [IntPtr]::Zero) {
                $needsResolve = $true
                break
            }
        }

        if ($needsResolve) {
            $this.ResolveComponentPointers()
        }

        for ($i = 0; $i -lt $this.Components.Count; $i++) {
            if (
                -not $this.CommittedComponents.Contains($i) -and
                $this.Components[$i].Pointer -eq [IntPtr]::Zero
            ) {
                throw "DataSource pointer is null for component '$($this.Components[$i].Name)'. The component may not have been properly enumerated."
            }
        }

        for ($i = 0; $i -lt $this.Filters.Count; $i++) {
            if (-not $this.CommittedFilters.Contains($i)) {
                $this.ValidateFilterForCommit($this.Filters[$i])
                $this.ValidateConstraintMarshalability($this.Filters[$i].ToProtocolConstraint())
            }
        }

        for ($i = 0; $i -lt $this.Components.Count; $i++) {
            if (-not $this.CommittedComponents.Contains($i)) {
                $this.CommitComponent($this.Components[$i], $i)
            }
        }

        for ($i = 0; $i -lt $this.Filters.Count; $i++) {
            if (-not $this.CommittedFilters.Contains($i)) {
                $this.CommitFilter($this.Filters[$i], $i)
            }
        }
        } catch {
            if (-not $this.Faulted) {
                while ($this.Filters.Count -gt $filterCountBeforeVmMaterialization) {
                    $this.Filters.RemoveAt($this.Filters.Count - 1)
                }
                $this.VmScopeOnlyFiltersPending = $vmPendingBeforeCommit
            }
            throw
        }
    }

    hidden [void] EnsureVmScopeFilters()
    {
        if (
            $this.Filters.Count -gt 0 -or
            $null -eq $this.CanonicalVMMacAddresses -or
            $this.CanonicalVMMacAddresses.Count -eq 0
        ) {
            return
        }
        if ($this.CanonicalVMMacAddresses.Count -gt [pspktSession]::MaxFilterCount) {
            throw "VM scope requires more than $([pspktSession]::MaxFilterCount) MAC filters."
        }

        $scopeFilters = [pspktFilter[]]::new($this.CanonicalVMMacAddresses.Count)
        for ($index = 0; $index -lt $this.CanonicalVMMacAddresses.Count; $index++) {
            $scopeFilter = [pspktFilter]::new()
            $scopeFilter.Name = "QF-VM-MAC-$($this.CanonicalVMMacAddresses[$index])"
            $scopeFilter.SetMac1($this.CanonicalVMMacAddresses[$index])
            $scopeFilters[$index] = $scopeFilter
        }
        $this.ValidateFilterBatchCapacity($scopeFilters)
        foreach ($scopeFilter in $scopeFilters) {
            $null = $this.Filters.Add($scopeFilter.CloneForSession())
        }
        $this.VmScopeOnlyFiltersPending = $true
    }

    hidden [void] ResolveComponentPointers()
    {
        if ($null -eq $this.Pspkt) { return }

        # Enumerate all data sources (non-NIC + NIC) from the live pspkt handle.
        $allSources = $this.Pspkt.EnumPktmonDataSources($true, 0)
        $nicSources = $this.Pspkt.EnumPktmonDataSources($true, 1)

        $lookup = @{}
        if ($null -ne $allSources) {
            foreach ($s in $allSources) {
                if ($null -ne $s -and $s.Pointer -ne [IntPtr]::Zero) {
                    $lookup["$($s.Id):$($s.SecondaryId)"] = $s.Pointer
                }
            }
        }
        if ($null -ne $nicSources) {
            foreach ($s in $nicSources) {
                if ($null -ne $s -and $s.Pointer -ne [IntPtr]::Zero) {
                    $lookup["$($s.Id):$($s.SecondaryId)"] = $s.Pointer
                }
            }
        }

        for ($i = 0; $i -lt $this.Components.Count; $i++) {
            $comp = $this.Components[$i]
            if ($comp.Pointer -eq [IntPtr]::Zero) {
                $key = "$($comp.Id):$($comp.SecondaryId)"
                if ($lookup.ContainsKey($key)) {
                    $comp.Pointer = $lookup[$key]
                }
            }
        }
    }

    hidden [void] CommitComponent([pspktComponent] $DataSource, [int] $index)
    {
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }
        if ($DataSource.Pointer -eq [IntPtr]::Zero) { throw "DataSource pointer is null for component '$($DataSource.Name)'. The component may not have been properly enumerated." }
        try {
            $res = $this.NativeApi.PacketMonitorAddSingleDataSourceToSession($this.handle, $DataSource.Pointer)
            if ($res -ne 0) {
                $this.MarkFaulted('AddSingleDataSource', ("Native status 0x{0:X}" -f $res), $true)
                throw "Failed to add data source '$($DataSource.Name)': 0x{0:X}" -f $res
            }
        } catch {
            $this.MarkFaulted('AddSingleDataSource', $_.Exception.Message, $true)
            throw
        }
        $this.CommittedComponents.Add($index) | Out-Null
        $this.CommittedComponentPointers[$index] = $DataSource.Pointer
    }

    hidden [void] CommitFilter([pspktFilter] $filter, [int] $index)
    {
        $this.ValidateFilterForCommit($filter)
        $constraint = $filter.ToProtocolConstraint()
        $this.CommitRawConstraint($constraint, $index)
        $snapshot = [pspktFilter]::new()
        $snapshot.SetRawConstraint($constraint)
        $snapshot.Identity = $filter.Identity
        $snapshot.MarkCommitted()
        $this.Filters[$index] = $snapshot
        $this.CommittedFilterIdentities[$index] = $snapshot.Identity
    }

    hidden [void] CommitRawConstraint([PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint, [int] $index)
    {
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }

        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][PACKETMONITOR_PROTOCOL_CONSTRAINT])
        $constraintPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

        try {
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($constraint, $constraintPtr, $false)
            try {
                $res = $this.NativeApi.PacketMonitorAddCaptureConstraint($this.handle, $constraintPtr)
                if ($res -ne 0) {
                    $this.MarkFaulted('AddCaptureConstraint', ("Native status 0x{0:X}" -f $res), $true)
                    throw "Failed to add capture constraint '$($constraint.Name)': 0x{0:X}" -f $res
                }
            } catch {
                $this.MarkFaulted('AddCaptureConstraint', $_.Exception.Message, $true)
                throw
            }
            $this.CommittedFilters.Add($index) | Out-Null
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($constraintPtr)
        }
    }
    
    [void] AttachOutputToSession([PktmonRealTimeStream] $realTimeStream)
    {
        $this.ThrowIfFaultedForForwardOperation()
        if ($null -eq $realTimeStream) { throw "Realtime stream cannot be null." }
        if ($realTimeStream.Handle -eq [IntPtr]::Zero) { throw "Realtime stream handle is null." }
        if ($this.OutputStream.Contains($realTimeStream)) { throw "Realtime stream is already attached." }

        $null = $this.OutputStream.Add($realTimeStream)
        try {
            $res = $this.NativeApi.PacketMonitorAttachOutputToSession($this.handle, $realTimeStream.Handle)
            if ($res -ne 0) {
                throw "Failed to attach realtime stream to session: 0x{0:X}" -f $res
            }
        } catch {
            $null = $this.OutputStream.Remove($realTimeStream)
            $this.MarkFaulted('AttachOutput', $_.Exception.Message, $true)
            throw
        }
    }

    [void] RemoveOutputFromSession([PktmonRealTimeStream] $realTimeStream)
    {
        if($this.OutputStream.Contains($realTimeStream))
        {
            $this.OutputStream.Remove($realTimeStream)
        }
    }
    
    [void] CloseSessionHandle()
    {
        if ($this.CaptureCleanupPending -or [PktMonApi]::IsCaptureOwner($this.handle)) {
            throw "An owned capture must be closed through Stop-Pspkt -Teardown."
        }
        if ($this.handle -eq [IntPtr]::Zero) { return }
        if ($null -ne $this.Pspkt) {
            $this.Pspkt.PacketMonitorCloseSessionHandle($this)
            return
        }

        $this.CloseSessionHandleCore()
    }

    hidden [void] CloseSessionHandleCore()
    {
        if ($this.handle -eq [IntPtr]::Zero) {
            $this.InvalidateAfterClose()
            return
        }

        $cleanupErrors = [System.Collections.ArrayList]::new()
        foreach ($outputStream in @($this.OutputStream)) {
            try {
                if ($null -ne $this.Pspkt) {
                    $this.Pspkt.PacketMonitorCloseRealtimeStream($outputStream)
                } else {
                    $outputStream.PacketMonitorCloseRealtimeStream()
                }
            } catch {
                $null = $cleanupErrors.Add($_.Exception.Message)
            }
        }

        try {
            $this.NativeApi.PacketMonitorCloseSessionHandle($this.handle)
        } catch {
            $null = $cleanupErrors.Add($_.Exception.Message)
        } finally {
            $this.InvalidateAfterClose()
        }

        if ($cleanupErrors.Count -gt 0) {
            throw "Session cleanup failed: $($cleanupErrors -join '; ')"
        }
    }

    hidden [void] InvalidateAfterClose()
    {
        $this.handle = [IntPtr]::Zero
        $this.Components.Clear()
        $this.Filters.Clear()
        $this.OutputStream.Clear()
        $this.CommittedComponents.Clear()
        $this.CommittedFilters.Clear()
        $this.CommittedComponentPointers.Clear()
        $this.CommittedFilterIdentities.Clear()
        $this.Active = $false
        $this.CanonicalVMName = ''
        $this.CanonicalVMMacAddresses = $null
        $this.VmScopeFingerprint = ''
        $this.VMName = ''
        $this.VMMacAddresses = $null
        $this.VmScopeOnlyFiltersMaterialized = $false
        $this.VmScopeOnlyFiltersPending = $false
        $this.CaptureFileWriter = $null
        $this.CaptureCleanupPending = $false
        $this.Closed = $true
        $this.ClearFaultState()
    }

    [System.Collections.ArrayList] ReadPacketsFromBuffer()
    {
        $returnArray = [System.Collections.ArrayList]::new()
        foreach($outputStream in $this.OutputStream)
        {
            $count = $outputStream.DrainPackets()
            for ($i = 0; $i -lt $count; $i++) {
                $null = $returnArray.Add($outputStream.PacketDataCache[$i])
            }
        }
        return $returnArray;
    }

    # Returns count of packets drained; access via $this.OutputStream[0].PacketDataCache[0..n-1]
    [int] DrainAllPackets()
    {
        $total = 0
        foreach($outputStream in $this.OutputStream)
        {
            $total += $outputStream.DrainPackets()
        }
        return $total
    }

    # Returns count of raw packets drained; access via $this.OutputStream[0].PacketBuffer[0..n-1]
    # Skips PS PacketData creation for C# bulk-format path.
    [int] DrainAllRawPackets()
    {
        $total = 0
        foreach($outputStream in $this.OutputStream)
        {
            $total += $outputStream.DrainRawPackets()
        }
        return $total
    }
}

class PktmonRealTimeStream
{
    static [int] $Index
    static [int] $PacketBufferSize = 10240
    [Int] $Id
    [uint16] $BufferSizeMultiplier;
    [uint16] $TruncationSize;
    [IntPtr] $Handle;
    [PSPacketData[]] $PacketBuffer
    [PacketData[]] $PacketDataCache
    hidden [pspkt] $Owner

    PktmonRealTimeStream([uint16] $BufferSizeMultiplier, [uint16] $TruncationSize, [IntPtr] $pointer)
    {
        $this.InitializeStandaloneStream(
            $BufferSizeMultiplier,
            $TruncationSize,
            $pointer,
            [PspktNativeApi]::new()
        )
    }

    hidden PktmonRealTimeStream(
        [uint16] $BufferSizeMultiplier,
        [uint16] $TruncationSize,
        [IntPtr] $pointer,
        [IPspktNativeApi] $nativeApi
    )
    {
        $this.InitializeStandaloneStream(
            $BufferSizeMultiplier,
            $TruncationSize,
            $pointer,
            $nativeApi
        )
    }

    hidden PktmonRealTimeStream(
        [uint16] $BufferSizeMultiplier,
        [uint16] $TruncationSize,
        [IntPtr] $pointer,
        [pspkt] $owner
    )
    {
        $this.InitializeManagedState($BufferSizeMultiplier, $TruncationSize, $pointer, $owner)
    }

    hidden [void] InitializeStandaloneStream(
        [uint16] $BufferSizeMultiplier,
        [uint16] $TruncationSize,
        [IntPtr] $pointer,
        [IPspktNativeApi] $nativeApi
    )
    {
        $standaloneOwner = [pspkt]::new($nativeApi)
        $this.InitializeManagedState($BufferSizeMultiplier, $TruncationSize, $pointer, $standaloneOwner)
        $null = $standaloneOwner.OpenPktmonRealTimeStreams.Add($this)
    }

    hidden [void] InitializeManagedState(
        [uint16] $BufferSizeMultiplier,
        [uint16] $TruncationSize,
        [IntPtr] $pointer,
        [pspkt] $owner
    )
    {
        $this.BufferSizeMultiplier = $BufferSizeMultiplier
        $this.TruncationSize = $TruncationSize
        $this.Handle = $pointer
        $this.Owner = $owner
        $this.Id = [PktmonRealTimeStream]::Index
        [PktmonRealTimeStream]::Index += 1;
        $this.PacketBuffer = [PSPacketData[]]::new([PktmonRealTimeStream]::PacketBufferSize)
        $this.PacketDataCache = [PacketData[]]::new([PktmonRealTimeStream]::PacketBufferSize)
    }

    [void] PacketMonitorCloseRealtimeStream()
    {
        if ($this.Handle -eq [IntPtr]::Zero) { return }
        if ($null -eq $this.Owner) { throw "Realtime stream has no owner." }
        $this.Owner.PacketMonitorCloseRealtimeStream($this)
    }

    hidden [void] InvalidateAfterClose()
    {
        $this.Handle = [IntPtr]::Zero
        [System.Array]::Clear($this.PacketBuffer, 0, $this.PacketBuffer.Length)
        [System.Array]::Clear($this.PacketDataCache, 0, $this.PacketDataCache.Length)
    }

    # Drains packets from ring buffer into reusable PacketDataCache.
    # Returns the count of packets drained. Access via $this.PacketDataCache[0..count-1].
    [int] DrainPackets()
    {
        $packetCount = [PktMonApi]::GetPacketData($this.PacketBuffer);
        for($i = 0; $i -lt $packetCount; $i++)
        {
            $this.PacketDataCache[$i] = [PacketData]::new($this.PacketBuffer[$i])
        }
        return $packetCount
    }

    # Drains raw packets from ring buffer WITHOUT PS PacketData parsing.
    # Returns the count drained. Access raw PSPacketData via $this.PacketBuffer[0..count-1].
    # Used by the C# bulk-format path for maximum throughput.
    [int] DrainRawPackets()
    {
        return [PktMonApi]::GetPacketData($this.PacketBuffer)
    }

    [PacketData[]] ReadPacketsFromBuffer()
    {
        $packetCount = [PktMonApi]::GetPacketData($this.PacketBuffer);
        [PacketData[]] $packetData = [PacketData[]]::new($packetCount)
        
        for($i = 0; $i -lt $packetData.Count; $i++)
        {
            $packetData[$i] = [PacketData]::new($this.PacketBuffer[$i])
        }

        return $packetData
    }

}

# create the type accelerator
$ExportableTypes = @(
    [pspkt]
    [pspktComponentProperty]
    [pspktComponentCounter]
    [pspktComponent]
    [pspktFilter]
    [pspktSession]
    [PktmonRealTimeStream]
)

# Get the internal TypeAccelerators class to use its static methods.
$TypeAcceleratorsClass = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)

# Ensure none of the types would clobber an existing type accelerator.
# If a type accelerator with the same name exists, throw an exception.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
$RegisteredTypeAccelerators = [System.Collections.ArrayList]::new()
$PspktOwnedAcceleratorTypes = [AppDomain]::CurrentDomain.GetData('pspkt-owned-accelerators')
if ($null -eq $PspktOwnedAcceleratorTypes) { $PspktOwnedAcceleratorTypes = [hashtable]::Synchronized(@{}); [AppDomain]::CurrentDomain.SetData('pspkt-owned-accelerators', $PspktOwnedAcceleratorTypes) }
foreach ($Type in $ExportableTypes) {
    if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
        if (-not $PspktOwnedAcceleratorTypes.ContainsKey($Type.FullName) -or -not [object]::ReferenceEquals($PspktOwnedAcceleratorTypes[$Type.FullName], $ExistingTypeAccelerators[$Type.FullName])) {
            throw "Type accelerator '$($Type.FullName)' is already registered to a different type."
        }
        # silently throw a message to the verbose stream
        Write-Verbose @"
Unable to register type accelerator[$($Type.FullName)]. The Accelerator already exists.
"@

    } else {
        $TypeAcceleratorsClass::Add($Type.FullName, $Type)
        $PspktOwnedAcceleratorTypes[$Type.FullName] = $Type
        $null = $RegisteredTypeAccelerators.Add($Type)
    }
}

# Add ScriptProperty members to pspktFilter for friendly console display.
# The underlying numeric properties (EtherType, DSCP, TransportProtocol, TCPFlags)
# remain intact for ToProtocolConstraint().
Update-TypeData -TypeName 'pspktFilter' -MemberName 'EtherTypeName' -MemberType ScriptProperty -Value {
    $this.GetEtherTypeString($this.EtherType)
} -Force

Update-TypeData -TypeName 'pspktFilter' -MemberName 'DSCPName' -MemberType ScriptProperty -Value {
    $this.GetDSCPString()
} -Force

Update-TypeData -TypeName 'pspktFilter' -MemberName 'TransportProtocolName' -MemberType ScriptProperty -Value {
    $this.GetTransportProtocolString()
} -Force

Update-TypeData -TypeName 'pspktFilter' -MemberName 'TCPFlagsName' -MemberType ScriptProperty -Value {
    $this.GetTCPFlagsString()
} -Force

Update-TypeData -TypeName 'pspktFilter' -DefaultDisplayPropertySet @(
    'Name',
    'Mac1', 'Mac2',
    'VlanId',
    'EtherTypeName',
    'DSCPName',
    'TransportProtocolName',
    'Ip1', 'Ip2',
    'PrefixLength1', 'PrefixLength2',
    'Port1', 'Port2',
    'TCPFlagsName',
    'VxLanPort',
    'EncapType'
) -Force

# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    $CurrentTypeAccelerators = $TypeAcceleratorsClass::Get
    foreach($Type in $RegisteredTypeAccelerators) {
        if (
            $CurrentTypeAccelerators.ContainsKey($Type.FullName) -and
            [object]::ReferenceEquals($CurrentTypeAccelerators[$Type.FullName], $Type)
        ) {
            $null = $TypeAcceleratorsClass::Remove($Type.FullName)
            $null = $PspktOwnedAcceleratorTypes.Remove($Type.FullName)
        }
    }
}.GetNewClosure()