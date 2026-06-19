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

    pspkt()
    {
        $this.OpenPktmonPointers = [List[System.IntPtr]]::new()
        $this.OpenPktmonSessions = [List[pspktSession]]::new()
        $this.OpenPktmonRealTimeStreams = [List[PktmonRealTimeStream]]::new()
        $this.PktmonHandle = [IntPtr]::Zero 
    }

    [void] PacketMonitorInitialize()
    {
        [UInt32]$ApiVersion = 0x00010000
        if ($this.PktmonHandle -ne [IntPtr]::Zero) { return }
        [IntPtr] $handle = [IntPtr]::Zero
        $result = [PktMonApi]::PacketMonitorInitialize($ApiVersion, [IntPtr]::Zero, [ref]$handle)
        if ($result -ne 0) { throw "Failed to initialize PktMon: 0x{0:X}" -f $result }
        $this.PktmonHandle = $handle
        [PacketData]::MissedPacketWriteCount = 0
        [PacketData]::MissedPacketReadCount = 0
    }

    [void] PacketMonitorUninitialize()
    {
        if ($this.PktmonHandle -eq [IntPtr]::Zero) { return }
        $this.FreeAllMemoryPointers()
        foreach($session in $this.OpenPktmonSessions)
        {
            if($session.Active)
            {
                $session.SetSessionActive($false)
            }
            if($session.Handle -ne [IntPtr]::Zero)
            {
                $session.CloseSessionHandle()
            }
        }
        $this.OpenPktmonSessions.Clear()
        foreach($realTimeStream in $this.OpenPktmonRealTimeStreams)
        {
            if($realTimeStream.Handle -ne [IntPtr]::Zero)
            {
                $realTimeStream.PacketMonitorCloseRealtimeStream()
            }
        }
        $this.OpenPktmonRealTimeStreams.Clear()
        [PktMonApi]::PacketMonitorUninitialize($this.PktmonHandle)
        $this.PktmonHandle = [IntPtr]::Zero
    }

    [pspktSession] PacketMonitorCreateLiveSession([string] $name)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        $session = [IntPtr]::Zero
        $res = [PktMonApi]::PacketMonitorCreateLiveSession($this.PktMonHandle, $Name, [ref]$session)
        if ($res -ne 0) { throw "Failed to create session: 0x{0:X}" -f $res }
        #[PktmonUtils]::WriteInformation("Live session created: $Name, handle = $session")

        $pktmonSession = [pspktSession]::new($name, $session)
        $null = $this.OpenPktmonSessions.Add($pktmonSession)
        return $pktmonSession;
    }
    
    [void] PacketMonitorCloseSessionHandle([string] $name)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        $this.CloseSession($this.GetSession($name))
    }


    [void] PacketMonitorCloseSessionHandle([pspktSession] $pktmonSession)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        $pktmonSession.CloseSessionHandle()
        $this.OpenPktmonSessions.Remove($pktmonSession)
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
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        foreach($pointer in $this.OpenPktmonPointers)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
        }
        $this.OpenPktmonPointers.Clear()
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
        
        $RSPtr = [PktMonApi]::CreateRealtimeStream($this.PktmonHandle, [PACKETMONITOR_REALTIME_STREAM_CONFIGURATION]$config)
        if ($RSPtr  -eq [IntPtr]::Zero) { throw "Failed to create realtime stream."}

        $realTimeStream = [PktmonRealTimeStream]::new($BufferSizeMultiplier, $TruncationSize, $RSPtr)
        #[PktmonUtils]::WriteInformation("Real time stream created: handle = $($realTimeStream.Handle)") 

        $null = $this.OpenPktmonRealTimeStreams.Add($realTimeStream);
        return $realTimeStream
    }

    [void] PacketMonitorCloseRealtimeStream([PktmonRealTimeStream] $realTimeStream)
    {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        $tmpHandle = $realTimeStream.Handle
        $realTimeStream.PacketMonitorCloseRealtimeStream()
        #[PktmonUtils]::WriteInformation("Real time stream closed: handle = $($tmpHandle)")
        foreach($session in $this.OpenPktmonSessions)
        {
            $session.RemoveOutputFromSession($realTimeStream)
        }
        $this.OpenPktmonRealTimeStreams.Remove($realTimeStream)
    }

    [List[pspktComponent]]
    EnumPktmonDataSources([bool] $ShowHidden, [int] $SourceKind) {
        if ($this.PktMonHandle -eq [IntPtr]::Zero) { throw "Pktmon not initialized" }
        
        $bytesNeeded = [uint64]::Zero
        $res = [PktMonApi]::PacketMonitorEnumDataSources(
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
        $res = [PktMonApi]::PacketMonitorEnumDataSources(
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

    pspktFilter() {
        # set defaults as needed
        $this.Name = ""
        $this.Mac1 = 0
        $this.Mac2 = 0
        $this.TransportProtocol = [int16][IPv4Protocol]::ANY
        $this.Ip1 = [ipaddress]::new(0)
        $this.Ip2 = [ipaddress]::new(0)
        $this.Filter = [PACKETMONITOR_PROTOCOL_CONSTRAINT]::new()
    }

    ## GET ##
    [string]GetMac1String() { return [PAUtils]::FormatPhysicalAddress($this.Mac1) }
    [string]GetMac2String() { return [PAUtils]::FormatPhysicalAddress($this.Mac2) }

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

    [void] SetMac1([byte[]]$mac)   { $this.Mac1 = $mac }
    [void] SetMac1([string]$mac)   { $this.Mac1 = ([PAUtils]::ConvertString2PhysicalAddress($mac)).GetAddressBytes() }

    [void] SetMac2([byte[]]$mac)   { $this.Mac2 = $mac }
    [void] SetMac2([string]$mac)   { $this.Mac2 = ([PAUtils]::ConvertString2PhysicalAddress($mac)).GetAddressBytes() }

    [void] SetVlanId([uint16]$vlanId) { $this.VlanId = $vlanId }

    [void] SetEtherType([uint16]$etherType)    { $this.EtherType = $etherType }
    [void] SetEtherType([ETHERTYPE]$etherType) { $this.EtherType = [uint16]$etherType }

    [void] SetDSCP([uint16]$dscp) { $this.DSCP = $dscp }
    [void] SetDSCP([DSCP]$dscp)   { $this.DSCP = [uint16]$dscp }

    [void] SetTransportProtocol([int16]$protocol)           { $this.TransportProtocol = $protocol }
    [void] SetTransportProtocol([IPv4Protocol]$protocol)    { $this.TransportProtocol = [int16]$protocol }

    [void] SetIp1([ipaddress]$ip) { $this.Ip1 = $ip }
    [void] SetIp1([string]$ip)    { $this.Ip1 = [ipaddress]::Parse($ip) }

    [void] SetIp2([ipaddress]$ip) { $this.Ip2 = $ip }
    [void] SetIp2([string]$ip)    { $this.Ip2 = [ipaddress]::Parse($ip) }

    [void] SetPrefixLength1([byte]$len) { $this.PrefixLength1 = $len }

    [void] SetPrefixLength2([byte]$len) { $this.PrefixLength2 = $len }

    [void] SetPort1([uint16]$port) { $this.Port1 = $port }

    [void] SetPort2([uint16]$port) { $this.Port2 = $port }

    [void] SetTCPFlags([byte]$flags)        { $this.TCPFlags = $flags }
    [void] SetTCPFlags([TCPFLAGS]$flags)    { $this.TCPFlags = [byte]$flags }

    [void] SetVxLanPort([uint16]$port) { $this.VxLanPort = $port }

    [void] SetEncapType([PKTMON_FILTER_ENCAPTYPE]$encapType) { $this.EncapType = $encapType }

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

    hidden
    [pspkt] $Pspkt

    pspktSession([string] $name, [intptr]$handle)
    {
        $this.name = $name
        $this.handle = $handle
        $this.Components = [System.Collections.ArrayList]::new()
        $this.Filters = [System.Collections.ArrayList]::new()
        $this.OutputStream = [System.Collections.ArrayList]::new()
        $this.CommittedComponents = [System.Collections.Generic.HashSet[int]]::new()
        $this.CommittedFilters = [System.Collections.Generic.HashSet[int]]::new()

        # Defaults matching pktmon start defaults.
        $this.CaptureType  = [PspktCaptureType]::All
        $this.LogMode      = [PspktLogMode]::RealTime
        $this.EventFlags   = 0x032
        $this.PacketSize   = 128
        $this.FileSize     = 512
        $this.FileName     = 'PktMon.etl'
        $this.CountersOnly = $false
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
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }

        if ($active) {
            $this.CommitSessionConfiguration()
        }

        $res = [PktMonApi]::PacketMonitorSetSessionActive($this.handle, $active)
        if ($res -ne 0) { throw "Failed to set session active state: 0x{0:X}" -f $res }
        $this.active = $active
    }

    # Stores a component for later commit. No native API call until the session is activated.
    [void] AddSingleDataSourceToSession([pspktComponent] $DataSource)
    {
        if ($null -eq $DataSource) { throw "DataSource cannot be null." }

        $null = $this.Components.Add($DataSource)

        # If the session is already active, commit the new component immediately.
        if ($this.Active) {
            $this.CommitComponent($DataSource, $this.Components.Count - 1)
        }
    }

    # Stores a filter for later commit. Validates the filter can produce a constraint.
    # When VM scoping is active (VMMacAddresses is populated), expands the filter into
    # one clone per vmNIC MAC with Mac1 set, so the pktmon OR-combined filter set
    # effectively AND-combines "VM MAC" with the filter's protocol scope.
    [void] AddFilter([pspktFilter] $filter)
    {
        if ($null -eq $filter) { throw "Filter cannot be null." }

        # Validate the filter can produce a valid constraint now, fail early.
        $null = $filter.ToProtocolConstraint()

        if ($null -ne $this.VMMacAddresses -and $this.VMMacAddresses.Count -gt 0 -and
            ($null -eq $filter.Mac1 -or $filter.Mac1.Length -lt 6))
        {
            # VM-scoped session: expand filter × MAC list.
            # Skip expansion if the filter already has a 6-byte MAC set (caller pre-stamped).
            foreach ($macStr in $this.VMMacAddresses)
            {
                $clone = [pspktFilter]::new()
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

                $null = $clone.ToProtocolConstraint()
                $null = $this.Filters.Add($clone)

                if ($this.Active) {
                    $this.CommitFilter($clone, $this.Filters.Count - 1)
                }
            }
        }
        else
        {
            $null = $this.Filters.Add($filter)

            # If the session is already active, commit the new filter immediately.
            if ($this.Active) {
                $this.CommitFilter($filter, $this.Filters.Count - 1)
            }
        }
    }

    [void] AddFilter([PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint)
    {
        # Wrap the raw constraint in a pspktFilter for uniform deferred handling.
        $filter = [pspktFilter]::new()
        $filter.Filter = $constraint
        $filter.Name = $constraint.Name
        $null = $this.Filters.Add($filter)

        if ($this.Active) {
            $this.CommitRawConstraint($constraint, $this.Filters.Count - 1)
        }
    }

    [bool] RemoveComponent([pspktComponent] $DataSource)
    {
        if ($null -eq $DataSource) { return $false }
        $idx = $this.Components.IndexOf($DataSource)
        if ($idx -lt 0) { return $false }
        $this.CommittedComponents.Remove($idx) | Out-Null
        $this.Components.RemoveAt($idx)
        # Re-index committed set after removal.
        $this.ReindexCommittedSet($this.CommittedComponents, $idx)
        return $true
    }

    [bool] RemoveComponentAt([int] $Index)
    {
        if ($Index -lt 0 -or $Index -ge $this.Components.Count) { return $false }
        $this.CommittedComponents.Remove($Index) | Out-Null
        $this.Components.RemoveAt($Index)
        $this.ReindexCommittedSet($this.CommittedComponents, $Index)
        return $true
    }

    [bool] RemoveFilter([pspktFilter] $Filter)
    {
        if ($null -eq $Filter) { return $false }
        $idx = $this.Filters.IndexOf($Filter)
        if ($idx -lt 0) { return $false }
        $this.CommittedFilters.Remove($idx) | Out-Null
        $this.Filters.RemoveAt($idx)
        $this.ReindexCommittedSet($this.CommittedFilters, $idx)
        return $true
    }

    [bool] RemoveFilterAt([int] $Index)
    {
        if ($Index -lt 0 -or $Index -ge $this.Filters.Count) { return $false }
        $this.CommittedFilters.Remove($Index) | Out-Null
        $this.Filters.RemoveAt($Index)
        $this.ReindexCommittedSet($this.CommittedFilters, $Index)
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

    # Commits all uncommitted components and filters to the native pktmon session.
    hidden [void] CommitSessionConfiguration()
    {
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }

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
            if (-not $this.CommittedComponents.Contains($i)) {
                $this.CommitComponent($this.Components[$i], $i)
            }
        }

        for ($i = 0; $i -lt $this.Filters.Count; $i++) {
            if (-not $this.CommittedFilters.Contains($i)) {
                $this.CommitFilter($this.Filters[$i], $i)
            }
        }
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
        $res = [PktMonApi]::PacketMonitorAddSingleDataSourceToSession($this.handle, $DataSource.Pointer)
        if ($res -ne 0) { throw "Failed to add data source '$($DataSource.Name)': 0x{0:X}" -f $res }
        $this.CommittedComponents.Add($index) | Out-Null
    }

    hidden [void] CommitFilter([pspktFilter] $filter, [int] $index)
    {
        $constraint = $filter.ToProtocolConstraint()
        $this.CommitRawConstraint($constraint, $index)
    }

    hidden [void] CommitRawConstraint([PACKETMONITOR_PROTOCOL_CONSTRAINT] $constraint, [int] $index)
    {
        if ($this.handle -eq [IntPtr]::Zero) { throw "Session handle is null." }

        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][PACKETMONITOR_PROTOCOL_CONSTRAINT])
        $constraintPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

        try {
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($constraint, $constraintPtr, $false)
            $res = [PktMonApi]::PacketMonitorAddCaptureConstraint($this.handle, $constraintPtr)
            if ($res -ne 0) { throw "Failed to add capture constraint '$($constraint.Name)': 0x{0:X}" -f $res }
            $this.CommittedFilters.Add($index) | Out-Null
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($constraintPtr)
        }
    }
    
    [void] AttachOutputToSession([PktmonRealTimeStream] $realTimeStream)
    {
        $res = [PktMonApi]::PacketMonitorAttachOutputToSession($this.handle, $realTimeStream.Handle)
        if ($res -ne 0) { throw "Failed to attach realtime stream to session: 0x{0:X}" -f $res }
        $null = $this.OutputStream.Add($realTimeStream)
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
        if($this.handle -eq [IntPtr]::Zero){Throw "Null pointer"}
        [PktMonApi]::PacketMonitorCloseSessionHandle($this.handle)
        $this.handle = [IntPtr]::Zero
        $this.Components.Clear()
        $this.Filters.Clear()
        $this.OutputStream.Clear()
        $this.CommittedComponents.Clear()
        $this.CommittedFilters.Clear()
        $this.Active = $false
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



    PktmonRealTimeStream([uint16] $BufferSizeMultiplier, [uint16] $TruncationSize, [IntPtr] $pointer)
    {
        $this.BufferSizeMultiplier = $BufferSizeMultiplier
        $this.TruncationSize = $TruncationSize
        $this.Handle = $pointer
        $this.Id = [PktmonRealTimeStream]::Index
        [PktmonRealTimeStream]::Index += 1;
        $this.PacketBuffer = [PSPacketData[]]::new([PktmonRealTimeStream]::PacketBufferSize)
        $this.PacketDataCache = [PacketData[]]::new([PktmonRealTimeStream]::PacketBufferSize)
    }

    [void] PacketMonitorCloseRealtimeStream()
    {
        if($this.Handle -eq [IntPtr]::Zero){Throw "Null pointer"}
        [PktMonApi]::PacketMonitorCloseRealtimeStream($this.Handle)
        $this.Handle = [IntPtr]::Zero
        # Clear buffers to prevent stale data leaking into a subsequent session.
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
    foreach($Type in $ExportableTypes) {
        $TypeAcceleratorsClass::Remove($Type.FullName)
    }
}.GetNewClosure()