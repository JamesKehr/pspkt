
class PktmonMetaData
{
    [uint64]  $PktGroupId;         
    [uint16]  $PktCount;           
    [uint16]  $AppearanceCount;    
    [PKTMON_DIRECTION_TAG]  $DirectionName;      
    [PKTMON_PACKET_TYPE]  $PacketType;         
    [uint16]  $ComponentId;        
    [uint16]  $EdgeId;             
    [uint16]  $Reserved;           
    [PKTMON_DROP_REASON]  $DropReason;         
    [PKTMON_DROP_LOCATION]  $DropLocation;       
    [uint16]  $Processor;          
    [Int64] $TimeStamp; 

    PktmonMetaData([long[]] $fields)
    {
        $this.PktGroupId = [uint64]$fields[0]
        $this.PktCount = [uint16]$fields[1]
        $this.AppearanceCount = [uint16]$fields[2]
        $this.DirectionName = [PKTMON_DIRECTION_TAG][uint16]$fields[3]
        $this.PacketType = [PKTMON_PACKET_TYPE][uint16]$fields[4]
        $this.ComponentId = [uint16]$fields[5]
        $this.EdgeId = [uint16]$fields[6]
        $this.Reserved = [uint16]$fields[7]
        $this.DropReason = [PKTMON_DROP_REASON][uint32]$fields[8]
        $this.DropLocation = [PKTMON_DROP_LOCATION][uint32]$fields[9]
        $this.Processor = [uint16]$fields[10]
        $this.TimeStamp = $fields[11]
    }

    PktmonMetaData([Byte[]] $byteArr)
    {   
        $this.PktGroupId = [BitConverter]::ToUInt64($byteArr, 0);
        $this.PktCount = [BitConverter]::ToUInt16($byteArr, 8)
        $this.AppearanceCount = [BitConverter]::ToUInt16($byteArr, 10)
        $this.DirectionName = [PKTMON_DIRECTION_TAG][BitConverter]::ToUInt16($byteArr, 12)
        $this.PacketType = [PKTMON_PACKET_TYPE][BitConverter]::ToUInt16($byteArr, 14)
        $this.ComponentId = [BitConverter]::ToUInt16($byteArr, 16)
        $this.EdgeId = [BitConverter]::ToUInt16($byteArr, 18)
        $this.Reserved = [BitConverter]::ToUInt16($byteArr, 20)
        $this.DropReason = [PKTMON_DROP_REASON][BitConverter]::ToUInt32($byteArr, 22)
        $this.DropLocation = [PKTMON_DROP_LOCATION][BitConverter]::ToUInt32($byteArr, 26)
        $this.Processor = [BitConverter]::ToUInt16($byteArr, 30)
        $this.TimeStamp = [BitConverter]::ToInt64($byteArr, 32)

    }
}


class IEEE80211
{
    [UInt16] $FrameControl
    [UInt16] $Duration
    [String] $ReceiverAddress
    [String] $TransmitterAddress
    [String] $SourceAddress
    [UInt16] $SequenceControl
    [UInt16] $QoSControl
    [UInt16] $HTControl
    [UInt16] $PayloadOffset

    [Byte]  $DSAP
    [Byte]  $SSAP
    [Byte]  $LLCControl
    [Byte[]] $OUI = [Byte[]]::new(3)
    [UInt16] $EtherType

    IEEE80211([Byte[]] $ByteArray)
    {
        $this.FrameControl = [BitConverter]::ToUInt16($ByteArray, 0)
        $this.Duration = [BitUtils]::ToUInt16BigEndian($ByteArray, 2)
        $this.ReceiverAddress = ($ByteArray[4..9] | ForEach-Object { $_.ToString("X2") }) -join ":"
        $this.TransmitterAddress = ($ByteArray[10..15] | ForEach-Object { $_.ToString("X2") }) -join ":"
        $this.SourceAddress = ($ByteArray[16..21] | ForEach-Object { $_.ToString("X2") }) -join ":"
        $this.SequenceControl = [BitUtils]::ToUInt16BigEndian($ByteArray, 22)
        $type = ($this.FrameControl -shr 2) -band 0x3
        $subtype = ($this.FrameControl -shr 4) -band 0xF
        $hasQoS = ($type -eq 2 -and ($subtype -band 0x08))
        $offset = 24

        if ($hasQoS) 
        {
            $this.QoSControl = [BitUtils]::ToUInt16BigEndian($ByteArray, $offset)
            $offset += 2
        }

        $hasHT = (($this.FrameControl -shr 10) -band 1) -eq 1
        if ($hasHT) 
        {
            $this.HTControl = [BitUtils]::ToUInt16BigEndian($ByteArray, $offset)
            $offset += 2
        }
        
        $this.PayloadOffset = $offset 
        if ($ByteArray.Length -ge ($offset + 8)) 
        {
            $this.DSAP = $ByteArray[$offset]
            $this.SSAP = $ByteArray[$offset + 1]
            $this.LLCControl = $ByteArray[$offset + 2]
            $snapStart = $offset + 3
            $this.OUI = $ByteArray[$snapStart..($snapStart + 2)]
            $this.EtherType = [BitUtils]::ToUInt16BigEndian($ByteArray, $snapStart + 3)
            $this.PayloadOffset = $offset + 8
        }
    }

    static [bool] IsIEEE80211([Byte[]]$ByteArray)
    {
        if ($ByteArray.Length -lt 10) { return $false }

        $fc = [BitConverter]::ToUInt16($ByteArray, 0)
        $version = $fc -band 0x3
        if ($version -ne 0) { return $false }

        $type = ($fc -shr 2) -band 0x3
        if ($type -gt 2) { return $false }

        return $true
    }
}

Class UnhandledData
{
    [Byte[]] $RawBytes

    UnhandledData([Byte[]] $ByteArray)
    {
        $this.RawBytes = $ByteArray
    }
}

Class ICMPData
{
    [Byte] $Type
    [ICMP4_TYPE] $Code
    [uint16] $CheckSum
    [Byte[]] $UnparsedHeaders
    [Byte[]] $Data

    ICMPData([Byte[]] $ByteArray)
    {
        if($ByteArray.Count -lt 8){return}
        $this.Type = [ICMP4_TYPE]$ByteArray[0]
        $this.Code = $ByteArray[1]
        $this.CheckSum = [PacketParseHelper]::ReadUInt16BE($ByteArray, 2)
        $this.UnparsedHeaders = $ByteArray[4..7]

        $length = $ByteArray.Count - 8
        $this.Data = [byte[]]::new($length)
        [Array]::Copy($ByteArray, 8, $this.Data, 0, $length)
    }
}

Class TCPData
{
    [int] $Size
    [uint16] $SourcePort
    [uint16] $DestinationPort
    [uint32] $SequenceNumber
    [uint32] $AcknowledgementNumber
    [byte] $DataOffset
    [byte] $Reserved
    [byte] $Flags
    [uint16] $Window
    [uint16] $Checksum
    [uint16] $UrgentPointer
    [Byte[]] $Options
    [Byte[]] $Data


    TCPData([Byte[]] $ByteArray)
    {
        if($ByteArray.Count -lt 20) {return}
        $this.SourcePort = [PacketParseHelper]::ReadUInt16BE($ByteArray, 0)
        $this.DestinationPort = [PacketParseHelper]::ReadUInt16BE($ByteArray, 2)
        $this.SequenceNumber = [PacketParseHelper]::ReadUInt32BE($ByteArray, 4)
        $this.AcknowledgementNumber = [PacketParseHelper]::ReadUInt32BE($ByteArray, 8)
        $this.DataOffset = $ByteArray[12] -shr 4
        $this.size = $this.DataOffset * 4
        $this.Reserved = $ByteArray[12] -band 0x0F
        $this.Flags = $ByteArray[13]
        $this.Window = [PacketParseHelper]::ReadUInt16BE($ByteArray, 14)
        $this.Checksum = [PacketParseHelper]::ReadUInt16BE($ByteArray, 16)
        $this.UrgentPointer = [PacketParseHelper]::ReadUInt16BE($ByteArray, 18)
        if($this.size -lt 20){return}

        $length = [Math]::Min($this.size - 20, $ByteArray.Count - 20)
        $this.Options = [byte[]]::new($length)
        [Array]::Copy($ByteArray, 20, $this.Options, 0, $length)
        
        if($ByteArray.Count - $this.Size -lt 0){ return }

        $length = $ByteArray.Count - $this.Size
        $this.Data = [byte[]]::new($length)
        [Array]::Copy($ByteArray, $this.Size, $this.Data, 0, $length)

    }
}

class UDPData
{
    [uint16] $SourcePort
    [uint16] $DestinationPort
    [uint16] $Length
    [uint16] $CheckSum
    [Byte[]] $Data

    UDPData([Byte[]] $ByteArray)
    {
        if($ByteArray.Length -lt 8) {return}
        $this.SourcePort = [PacketParseHelper]::ReadUInt16BE($ByteArray, 0)
        $this.DestinationPort = [PacketParseHelper]::ReadUInt16BE($ByteArray, 2)
        $this.Length = [PacketParseHelper]::ReadUInt16BE($ByteArray, 4)
        $this.CheckSum = [PacketParseHelper]::ReadUInt16BE($ByteArray, 6)
        $dataLen = [Math]::Min($this.Length - 8, $ByteArray.Count - 8)
        $this.Data = [Byte[]]::new($dataLen)
        [Array]::Copy($ByteArray, 8, $this.Data, 0, $dataLen)
    }
}


class IPv4Data
{
    [int] $StartByteIndex;
    [int] $size;
    [byte] $Version
    [byte] $IHL
    [byte] $TOS
    [uint16] $TotalLength
    [uint16] $Identification
    [byte] $Flags
    [Byte[]] $FragmentOffset
    [byte] $TTL
    [IPv4Protocol] $Protocol
    [uint16] $HeaderChecksum
    [string] $SourceAddress
    [string] $DestinationAddress
    [byte[]] $Options

    IPv4Data([Byte[]] $byteArray)
    {
        $index = $this.FindIPv4HeaderIndex($byteArray)
        $this.ParseIPV4Data($byteArray, $index)
    }

    IPv4Data([Byte[]] $byteArray, [int] $index)
    {
        $this.ParseIPV4Data($byteArray, $index)
    }

    [void] ParseIPV4Data([Byte[]] $byteArray, [int] $index)
    {
        if($index -eq 0 -or $byteArray.Count - $index -lt 20) {return}
        $this.startByteIndex = $index
        $this.Version = ($byteArray[$index] -shr 4)
        $this.IHL = $byteArray[$index] -band 0x0F
        $this.size = $this.IHL * 4
        $this.TOS = $byteArray[$index + 1]
        $this.TotalLength = [PacketParseHelper]::ReadUInt16BE($byteArray, ($index + 2))
        $this.Identification = [PacketParseHelper]::ReadUInt16BE($byteArray, ($index + 4))
        $this.Flags = $byteArray[6] -band 0x1F
        $this.FragmentOffset = [Byte[]]::new(2);
        $this.FragmentOffset[0] = $byteArray[$index + 6] -band 0xE0
        $this.FragmentOffset[1] = $byteArray[$index + 7]
        $this.TTL = $byteArray[8]
        if(([Enum]::IsDefined([IPv4Protocol], [int]$byteArray[$index + 9])))
        {
            $this.Protocol = [IPv4Protocol][int]$byteArray[$index + 9]
        }
        else
        {
            $this.Protocol = [IPv4Protocol]-1
        }
        $this.HeaderChecksum = [PacketParseHelper]::ReadUInt16BE($byteArray, ($index + 10))
        $this.SourceAddress = [PacketParseHelper]::FormatIPv4($byteArray, $index + 12)
        $this.DestinationAddress = [PacketParseHelper]::FormatIPv4($byteArray, $index + 16)
        
        $optLen = $this.size - 20
        $this.Options = [Byte[]]::new($optLen)
        if ($optLen -gt 0) {
            [Array]::Copy($byteArray, $index + 20, $this.Options, 0, $optLen)
        }
    }
    
    [int] FindIPv4HeaderIndex ([byte[]]$PacketBytes)
    {
        $result = [PacketParseHelper]::FindIPv4HeaderIndex($PacketBytes)
        if ($result -lt 0) { return 0 }
        return $result
    }

}

Class EthernetII
{
    [String] $DestinationMacAddress
    [String] $SourceMacAddress
    [uint16] $EtherType
    [bool] $VlanTag
    [uint16] $TPID
    [uint16] $TCI


    EthernetII([Byte[]]$ByteArray)
    {
        $this.DestinationMacAddress = [PacketParseHelper]::FormatMac($ByteArray, 0)
        $this.SourceMacAddress = [PacketParseHelper]::FormatMac($ByteArray, 6)
        $tmp = [PacketParseHelper]::ReadUInt16BE($ByteArray, 12)
        if($tmp -eq 0x8100)
        {
            $this.VlanTag = $true
            $this.TPID = $tmp 
            $this.TCI = [PacketParseHelper]::ReadUInt16BE($ByteArray, 14)
            $this.EtherType = [PacketParseHelper]::ReadUInt16BE($ByteArray, 16)
        }
        else
        {
            $this.EtherType = $tmp
        }
    }
}

# create the type accelerator
$ExportableTypes = @(
    [PktmonMetaData]
    [IEEE80211]
    [UnhandledData]
    [ICMPData]
    [TCPData]
    [UDPData]
    [IPv4Data]
    [EthernetII]
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