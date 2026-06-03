
#region ENUM
enum ICMP4_TYPE {
  ICMP4_ECHO_REPLY = 0
  ICMP4_DST_UNREACH = 3
  ICMP4_SOURCE_QUENCH = 4
  ICMP4_REDIRECT = 5
  ICMP4_ECHO_REQUEST = 8
  ICMP4_ROUTER_ADVERT = 9
  ICMP4_ROUTER_SOLICIT = 10
  ICMP4_TIME_EXCEEDED = 11
  ICMP4_PARAM_PROB = 12
  ICMP4_TIMESTAMP_REQUEST = 13
  ICMP4_TIMESTAMP_REPLY = 14
  ICMP4_MASK_REQUEST = 17
  ICMP4_MASK_REPLY = 18
}

enum PacketDirection {
    Outgoing = 0
    Incoming = 1
    Unknown = 2
}

# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
enum IPProtocol {
    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPv4 = 4
    ST = 5
    TCP = 6
    CBT = 7
    EGP = 8
    IGP = 9
    BBN_RCC_MON = 10
    NVP_II = 11
    PUP = 12
    ARGUS = 13
    EMCON = 14
    XNET = 15
    CHAOS = 16
    UDP = 17
    MUX = 18
    DCN_MEAS = 19
    HMP = 20
    PRM = 21
    XNS_IDP = 22
    TRUNK1 = 23
    TRUNK2 = 24
    LEAF1 = 25
    LEAF2 = 26
    RDP = 27
    IRTP = 28
    ISO_TP4 = 29
    NETBLT = 30
    MFE_NSP = 31
    MERIT_INP = 32
    DCCP = 33
    THIRD_PARTY_CONNECT = 34
    IDPR = 35
    XTP = 36
    DDP = 37
    IDPR_CMTP = 38
    TP_PLUS_PLUS = 39
    IL = 40
    IPv6 = 41
    SDRP = 42
    IPv6_ROUTE = 43
    IPv6_FRAG = 44
    IDRP = 45
    RSVP = 46
    GRE = 47
    DSR = 48
    BNA = 49
    ESP = 50
    AH = 51
    I_NLSP = 52
    SWIPE = 53
    NARP = 54
    MOBILE = 55
    TLSP = 56
    SKIP = 57
    ICMPv6 = 58
    IPv6_NONXT = 59
    IPv6_OPTS = 60
    HOST_INTERNAL = 61
    CFTP = 62
    LOCAL_NETWORK = 63
    SAT_EXPAK = 64
    KRYPTOLAN = 65
    RVD = 66
    IPPC = 67
    DISTRIBUTED_FS = 68
    SAT_MON = 69
    VISA = 70
    IPCV = 71
    CPNX = 72
    CPHB = 73
    WSN = 74
    PVP = 75
    BR_SAT_MON = 76
    SUN_ND = 77
    WB_MON = 78
    WB_EXPAK = 79
    ISO_IP = 80
    VMTP = 81
    SECURE_VMTP = 82
    VINES = 83
    TTP = 84
    IPTM = 84
    NSFNET_IGP = 85
    DGP = 86
    TCF = 87
    EIGRP = 88
    OSPF = 89
    SPRITE_RPC = 90
    LARP = 91
    MTP = 92
    AX25 = 93
    IPIP = 94
    MICP = 95
    SCC_SP = 96
    ETHERIP = 97
    ENCAP = 98
    PRIVATE_ENCRYPTION = 99
    GMTP = 100
    IFMP = 101
    PNNI = 102
    PIM = 103
    ARIS = 104
    SCPS = 105
    QNX = 106
    A_N = 107
    IPComp = 108
    SNP = 109
    COMPAQ_PEER = 110
    IPX_IN_IP = 111
    VRRP = 112
    PGM = 113
    ZERO_HOP = 114
    L2TP = 115
    DDX = 116
    IATP = 117
    STP = 118
    SRP = 119
    UTI = 120
    SMP = 121
    SM = 122
    PTP = 123
    ISIS_OVER_IPV4 = 124
    FIRE = 125
    CRTP = 126
    CRUDP = 127
    SSCOPMCE = 128
    IPLT = 129
    SPS = 130
    PIPE = 131
    SCTP = 132
    FC = 133
    RSVP_E2E_IGNORE = 134
    MOBILITY = 135
    UDPLite = 136
    MPLS_IN_IP = 137
    MANET = 138
    HIP = 139
    Shim6 = 140
    WESP = 141
    ROHC = 142
    Reserved = 255
}

#endregion ENUM

class PacketData
{
    static [uint32] $MissedPacketWriteCount = 0;
    static [uint32] $MissedPacketReadCount = 0;
    static [bool] $ParsePackets = $true
    [PktmonMetaData] $PktmonMetaData;
    [ParsedPacket] $ParsedPacket;
    [Byte[]] $RawPacketData;
    [Int64] $StreamTimestamp;
    
    
    PacketData([PSPacketData] $packetData)
    {
        [PacketData]::MissedPacketWriteCount = $packetData.MissedPacketWriteCount
        [PacketData]::MissedPacketReadCount = $packetData.MissedPacketReadCount
        
        # Use C# helper to extract metadata and raw packet in one shot.
        [long[]] $metaFields = $null
        [byte[]] $rawPkt = $null
        [long] $ts = 0
        [PacketParseHelper]::ExtractPacketParts(
            $packetData.Data, $packetData.MetadataOffset, $packetData.PacketOffset,
            [ref]$metaFields, [ref]$rawPkt, [ref]$ts
        )

        if ($null -ne $metaFields) {
            $this.PktmonMetaData = [PktmonMetaData]::new($metaFields)
        }

        # Use QPC-based timestamp for per-packet precision; fall back to metadata FILETIME.
        if ($packetData.QpcTimestamp -ne 0) {
            $this.StreamTimestamp = [PktMonApi]::QpcToFiletime($packetData.QpcTimestamp)
        } else {
            $this.StreamTimestamp = $ts
        }
        $this.RawPacketData = $rawPkt

        if([PacketData]::ParsePackets -and $this.RawPacketData.Count -ge 14)
        {
            $this.ParsedPacket = [ParsedPacket]::new($this.RawPacketData, $this.PktmonMetaData)
        }
    }
}


Class ParsedPacket
{
    $LinkLayerData;
    [IPv4Data] $IPv4Data;
    $ProtocolData
    [PacketDirection] $PacketDirection
    [DateTime] $TimeStamp
    # Protocol kind for fast dispatch: 0=None, 1=ICMP, 2=TCP, 3=UDP, 4=Other
    [int] $ProtoKind
    # Link layer kind: 0=None, 1=EthernetII, 2=IEEE80211
    [int] $LinkKind

    ParsedPacket([Byte[]] $PacketByteArray, [PktmonMetaData] $ptkmonMetaData)
    {
        $this.IPv4Data = $null
        $this.LinkLayerData = $null
        $etherType = $null
        $ipv4Tmp = $null
        $this.TimeStamp = [DateTime]::FromFileTimeUtc($ptkmonMetaData.TimeStamp).ToLocalTime()

        if($ptkmonMetaData.DirectionName -eq [PKTMON_DIRECTION_TAG]::PktMonDirTag_In`
        -or $ptkmonMetaData.DirectionName -eq [PKTMON_DIRECTION_TAG]::PktMonDirTag_Rx`
        -or $ptkmonMetaData.DirectionName -eq [PKTMON_DIRECTION_TAG]::PktMonDirTag_Ingress)
        {
            $this.PacketDirection = [PacketDirection]::Incoming 
        }
        elseif($ptkmonMetaData.DirectionName -eq [PKTMON_DIRECTION_TAG]::PktMonDirTag_Out`
        -or $ptkmonMetaData.DirectionName -eq [PKTMON_DIRECTION_TAG]::PktMonDirTag_Tx`
        -or $ptkmonMetaData.DirectionName -eq [PKTMON_DIRECTION_TAG]::PktMonDirTag_Egress)
        {
            $this.PacketDirection = [PacketDirection]::Outgoing 
        }
        else
        {
            $this.PacketDirection = [PacketDirection]::Unknown 
        }

        if($ptkmonMetaData.PacketType -eq [PKTMON_PACKET_TYPE]::PktMonPayload_WiFi)
        {
            $this.LinkLayerData = [IEEE80211]::new($PacketByteArray);
            $this.LinkKind = 2
            $etherType = $this.LinkLayerData.EtherType
            if($this.LinkLayerData -and $etherType -eq 0x0800 `
            -and $PacketByteArray.Count -gt $this.LinkLayerData.PayloadOffset `
            -and $PacketByteArray[$this.LinkLayerData.PayloadOffset] -eq 0x45)
            {
                $ipv4Tmp = [IPv4Data]::new($PacketByteArray, $this.LinkLayerData.PayloadOffset)
            }
        }
        elseif ($ptkmonMetaData.PacketType -eq [PKTMON_PACKET_TYPE]::PktMonPayload_Ethernet)
        {

            $this.LinkLayerData = [EthernetII]::new($PacketByteArray);
            $this.LinkKind = 1
            $etherType = $this.LinkLayerData.EtherType


            if($this.LinkLayerData -and $etherType -eq 0x0800 -and `
                $PacketByteArray.Count -ge 15 -and $PacketByteArray[14] -eq 0x45)
            {
                if($this.LinkLayerData.VlanTag)
                {
                    $ipv4Tmp = [IPv4Data]::new($PacketByteArray, 18)
                }
                else
                {
                    $ipv4Tmp = [IPv4Data]::new($PacketByteArray, 14)
                }
            }
        }
        
        if(-not $ipv4Tmp)
        {
            $ipv4Tmp = [IPv4Data]::new($PacketByteArray)
        }

        if($ipv4Tmp.StartByteIndex -ne 0)
        {
            $this.IPv4Data = $ipv4Tmp
            $this.ProtocolData = $null
            $StartByteIndex = $this.IPv4Data.StartByteIndex + $this.IPv4Data.size
            if($this.IPv4Data.TotalLength - $this.IPv4Data.Size -gt 0)
            {
                $EndByteIndex = $StartByteIndex + ($this.IPv4Data.TotalLength - $this.IPv4Data.Size)
            }
            else
            {
                $EndByteIndex = $PacketByteArray.Count - 1
            }
            if($EndByteIndex -gt $PacketByteArray.Count - 1)
            {
                $EndByteIndex  = $PacketByteArray.Count - 1;
            }

            $length = $EndByteIndex - $StartByteIndex + 1
            $ProtocolByteArray = [byte[]]::new($length)
            [Array]::Copy($PacketByteArray, $StartByteIndex, $ProtocolByteArray, 0, $length)


            if($this.IPv4Data.Protocol -eq [IPProtocol]::ICMP)
            {
                $this.ProtocolData = [ICMPData]::new($ProtocolByteArray)
                $this.ProtoKind = 1
            }
            elseif($this.IPv4Data.Protocol -eq [IPProtocol]::TCP)
            {
                $this.ProtocolData = [TCPData]::new($ProtocolByteArray)
                $this.ProtoKind = 2
            }
            elseif($this.IPv4Data.Protocol -eq [IPProtocol]::UDP)
            {
                $this.ProtocolData = [UDPData]::new($ProtocolByteArray)
                $this.ProtoKind = 3
            }
            else
            {
                $this.ProtocolData = [UnhandledData]::new($ProtocolByteArray)
                $this.ProtoKind = 4
            }

        }
    }
}


# create the type accelerator
$ExportableTypes = @(
    [ICMP4_TYPE]
    [PacketDirection]
    [IPProtocol]
    [PacketData]
    [ParsedPacket]
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