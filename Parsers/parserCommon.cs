// parserCommon.cs - Parser common code: helpers, formatters, and utilities.
// Shared across all protocol-specific parsers.

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

/// <summary>
/// Low-level packet parsing helpers: byte reading, MAC/IP formatting, metadata extraction.
/// All methods are static for zero-allocation hot-path usage.
/// </summary>
public static class PacketParseHelper
{
    // Pre-computed hex lookup for MAC formatting.
    private static readonly string[] HexBytes = new string[256];
    // Pre-computed decimal lookup for IPv4 octet formatting (eliminates per-octet ToString allocations).
    private static readonly string[] DecBytes = new string[256];

    static PacketParseHelper()
    {
        for (int i = 0; i < 256; i++)
        {
            HexBytes[i] = i.ToString("x2");
            DecBytes[i] = i.ToString();
        }
    }

    /// <summary>
    /// Formats 6 bytes starting at offset into a MAC address string (lowercase, dash-separated).
    /// Uses string.Concat to avoid intermediate string allocations from chained + operators.
    /// </summary>
    public static string FormatMac(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 6) return "";
        return string.Concat(HexBytes[data[offset]], "-", HexBytes[data[offset+1]], "-",
               HexBytes[data[offset+2]], "-", HexBytes[data[offset+3]], "-",
               HexBytes[data[offset+4]], "-", HexBytes[data[offset+5]]);
    }

    /// <summary>
    /// Reads a big-endian UInt16 from byte array.
    /// </summary>
    public static ushort ReadUInt16BE(byte[] data, int offset)
    {
        return (ushort)((data[offset] << 8) | data[offset + 1]);
    }

    /// <summary>
    /// Reads a big-endian UInt32 from byte array.
    /// </summary>
    public static uint ReadUInt32BE(byte[] data, int offset)
    {
        return (uint)((data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]);
    }

    /// <summary>
    /// Formats an IPv4 address from 4 bytes at the given offset.
    /// Uses a precomputed decimal lookup to avoid per-octet ToString allocations.
    /// </summary>
    public static string FormatIPv4(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 4) return "";
        return string.Concat(DecBytes[data[offset]], ".", DecBytes[data[offset+1]], ".",
               DecBytes[data[offset+2]], ".", DecBytes[data[offset+3]]);
    }

    // Pre-computed hex word lookup for IPv6 formatting (0000-ffff).
    // Lazy-initialized on first FormatIPv6 call to save ~2.5 MB when captures
    // never encounter IPv6 traffic.
    private static string[] HexWords;

    /// <summary>
    /// Formats an IPv6 address from 16 bytes at the given offset using RFC 5952 compressed
    /// notation, without allocating any temporary byte[] or IPAddress objects.
    /// </summary>
    public static string FormatIPv6(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 16) return "";

        // Lazy-init the lookup table. Single-threaded consumer means no lock needed;
        // worst case on a race is double-init (harmless, same data).
        if (HexWords == null)
        {
            var table = new string[65536];
            for (int i = 0; i < 65536; i++)
                table[i] = i.ToString("x");
            HexWords = table;
        }

        // Read 8 groups as 16-bit words.
        int g0 = (data[offset]     << 8) | data[offset + 1];
        int g1 = (data[offset + 2] << 8) | data[offset + 3];
        int g2 = (data[offset + 4] << 8) | data[offset + 5];
        int g3 = (data[offset + 6] << 8) | data[offset + 7];
        int g4 = (data[offset + 8] << 8) | data[offset + 9];
        int g5 = (data[offset + 10] << 8) | data[offset + 11];
        int g6 = (data[offset + 12] << 8) | data[offset + 13];
        int g7 = (data[offset + 14] << 8) | data[offset + 15];

        // Find the longest run of consecutive zero groups for :: compression.
        int bestStart = -1, bestLen = 0;
        int curStart = -1, curLen = 0;
        int[] groups = { g0, g1, g2, g3, g4, g5, g6, g7 };
        for (int i = 0; i < 8; i++)
        {
            if (groups[i] == 0)
            {
                if (curStart < 0) curStart = i;
                curLen++;
                if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
            }
            else
            {
                curStart = -1;
                curLen = 0;
            }
        }
        // RFC 5952: only compress runs of length >= 2.
        if (bestLen < 2) { bestStart = -1; bestLen = 0; }

        // Build the string. Worst case is "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" = 39 chars.
        var sb = new StringBuilder(39);
        for (int i = 0; i < 8; i++)
        {
            if (i == bestStart)
            {
                sb.Append("::");
                i += bestLen - 1;
                continue;
            }
            if (i > 0 && !(i == bestStart + bestLen && bestStart >= 0)) sb.Append(':');
            sb.Append(HexWords[groups[i]]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Walks IPv6 extension headers and returns the upper-layer protocol number plus the
    /// offset of its first byte. Handles Hop-by-Hop Options (0), Routing (43), Fragment (44),
    /// ESP (50 — opaque, returns false), Authentication (51), Destination Options (60), and
    /// No Next Header (59 — returns false). Capped at 8 chained headers.
    ///
    /// This is required because Windows can emit IPv6 packets (notably MLDv2 reports and some
    /// outbound NDP / echo flows) with a Hop-by-Hop Options header preceding the upper layer.
    /// A naive check of `raw[ipOff + 6] == 58` would miss those packets entirely.
    /// </summary>
    /// <param name="data">Packet bytes.</param>
    /// <param name="ipOffset">Offset of the IPv6 header start in data.</param>
    /// <param name="dataLen">Number of valid bytes available in data (use DataSize, not Data.Length).</param>
    /// <param name="upperProto">Output: upper-layer protocol number (e.g. 58 ICMPv6, 6 TCP, 17 UDP).</param>
    /// <param name="upperOffset">Output: offset of the upper-layer header's first byte.</param>
    /// <returns>True when upper layer was identified, false on truncation / opaque header / depth cap.</returns>
    public static bool FindIPv6UpperLayer(byte[] data, int ipOffset, int dataLen,
        out int upperProto, out int upperOffset)
    {
        upperProto = 0;
        upperOffset = 0;
        if (data == null || dataLen < ipOffset + 40) return false;

        int hdr = data[ipOffset + 6];
        int off = ipOffset + 40;
        for (int safety = 0; safety < 8; safety++)
        {
            switch (hdr)
            {
                case 0:   // Hop-by-Hop Options
                case 60:  // Destination Options
                case 43:  // Routing
                    if (off + 2 > dataLen) return false;
                    int nextOpt = data[off];
                    int optLen = (data[off + 1] + 1) * 8;
                    off += optLen;
                    hdr = nextOpt;
                    break;
                case 44:  // Fragment (fixed 8 bytes)
                    if (off + 8 > dataLen) return false;
                    hdr = data[off];
                    off += 8;
                    break;
                case 51:  // Authentication Header (length in 4-octet units, total = (len+2)*4)
                    if (off + 2 > dataLen) return false;
                    int nextAh = data[off];
                    int ahLen = (data[off + 1] + 2) * 4;
                    off += ahLen;
                    hdr = nextAh;
                    break;
                case 50:  // ESP — encrypted payload, can't see inside
                case 59:  // No Next Header
                    return false;
                default:
                    upperProto = hdr;
                    upperOffset = off;
                    return off < dataLen;
            }
        }
        return false;
    }

    /// <summary>
    /// Scans for the IPv4 header start index by looking for EtherType 0x0800 or SNAP header.
    /// Returns the offset of the IPv4 header, or -1 if not found.
    /// </summary>
    public static int FindIPv4HeaderIndex(byte[] pkt)
    {
        if (pkt == null) return -1;
        int limit = pkt.Length - 20;
        
        for (int i = 0; i < limit; i++)
        {
            int candidateIndex = -1;
            
            // Check EtherType (0x08, 0x00)
            if (i + 1 < pkt.Length && pkt[i] == 0x08 && pkt[i+1] == 0x00)
            {
                candidateIndex = i + 2;
            }
            // Check SNAP (AA AA 03 00 00 00 08 00)
            else if (i + 7 < pkt.Length &&
                     pkt[i] == 0xAA && pkt[i+1] == 0xAA && pkt[i+2] == 0x03 &&
                     pkt[i+3] == 0x00 && pkt[i+4] == 0x00 && pkt[i+5] == 0x00 &&
                     pkt[i+6] == 0x08 && pkt[i+7] == 0x00)
            {
                candidateIndex = i + 8;
            }

            if (candidateIndex >= 0 && candidateIndex + 20 <= pkt.Length)
            {
                int ver = pkt[candidateIndex] >> 4;
                int ihlWords = pkt[candidateIndex] & 0x0F;
                int ihlBytes = ihlWords * 4;
                int totalLen = (pkt[candidateIndex+2] << 8) | pkt[candidateIndex+3];
                int ttl = pkt[candidateIndex+8];
                if (ver == 4 && ihlBytes >= 20 && totalLen >= ihlBytes &&
                    totalLen <= (pkt.Length - candidateIndex) && ttl > 0)
                {
                    return candidateIndex;
                }
            }
        }
        return -1;
    }

    /// <summary>
    /// Parses PktmonMetaData fields from a byte array in one shot.
    /// Returns: [PktGroupId(8), PktCount(2), AppearanceCount(2), Direction(2), PacketType(2),
    ///           ComponentId(2), EdgeId(2), Reserved(2), DropReason(4), DropLocation(4),
    ///           Processor(2), TimeStamp(8)] = 40 bytes total output.
    /// This avoids 12+ BitConverter calls in PowerShell.
    /// </summary>
    public static long[] ParseMetadata(byte[] data, int metaOffset, int metaLength)
    {
        if (data == null || data.Length < metaOffset + metaLength || metaLength < 40) return null;
        long[] result = new long[12];
        result[0] = BitConverter.ToInt64(data, metaOffset);       // PktGroupId
        result[1] = BitConverter.ToUInt16(data, metaOffset + 8);  // PktCount
        result[2] = BitConverter.ToUInt16(data, metaOffset + 10); // AppearanceCount
        result[3] = BitConverter.ToUInt16(data, metaOffset + 12); // DirectionName
        result[4] = BitConverter.ToUInt16(data, metaOffset + 14); // PacketType
        result[5] = BitConverter.ToUInt16(data, metaOffset + 16); // ComponentId
        result[6] = BitConverter.ToUInt16(data, metaOffset + 18); // EdgeId
        result[7] = BitConverter.ToUInt16(data, metaOffset + 20); // Reserved
        result[8] = BitConverter.ToUInt32(data, metaOffset + 22); // DropReason
        result[9] = BitConverter.ToUInt32(data, metaOffset + 26); // DropLocation
        result[10] = BitConverter.ToUInt16(data, metaOffset + 30); // Processor
        result[11] = BitConverter.ToInt64(data, metaOffset + 32); // TimeStamp
        return result;
    }

    /// <summary>
    /// Fast extraction of PacketData essentials: metadata + raw packet bytes in one call.
    /// Avoids multiple Array.Copy calls in PowerShell.
    /// </summary>
    public static void ExtractPacketParts(byte[] data, uint metaOffset, uint packetOffset,
        out long[] metadata, out byte[] rawPacket, out long timestamp)
    {
        // Parse metadata directly from the source buffer (always 40 bytes).
        metadata = ParseMetadata(data, (int)metaOffset, 40);
        timestamp = (metadata != null) ? metadata[11] : 0;
        
        // Extract raw packet bytes.
        int pktLen = data.Length - (int)packetOffset;
        if (pktLen > 0)
        {
            rawPacket = new byte[pktLen];
            Buffer.BlockCopy(data, (int)packetOffset, rawPacket, 0, pktLen);
        }
        else
        {
            rawPacket = new byte[0];
        }
    }

    // TCP flag characters indexed by bit position (MSB first): CWR ECE URG ACK PSH RST SYN FIN
    private static readonly char[] TcpFlagChars = new char[] { 'W', 'E', 'U', '.', 'P', 'R', 'S', 'F' };

    /// <summary>
    /// Formats a TCP flags byte into a compact string of set flag characters.
    /// </summary>
    public static string FormatTcpFlags(byte flags)
    {
        if (flags == 0) return "none";
        char[] buf = new char[8];
        int len = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((flags & (0x80 >> i)) != 0)
            {
                buf[len++] = TcpFlagChars[i];
            }
        }
        return new string(buf, 0, len);
    }

    /// <summary>
    /// Formats a TCP segment summary line: TCP [flags], seq N, ack N, win N, len N
    /// </summary>
    public static string FormatTcpSegment(byte flags, uint seq, uint ack, ushort win, int dataLen)
    {
        string f = FormatTcpFlags(flags);
        return string.Concat("TCP [", f, "], seq ", seq.ToString(),
            ", ack ", ack.ToString(), ", win ", win.ToString(), ", len ", dataLen.ToString());
    }
}

/// <summary>
/// High-performance ANSI colorizer and component prefix cache for real-time packet formatting.
/// Eliminates per-packet PowerShell string interpolation and hashtable lookups.
/// </summary>
public static class PacketFormatter
{
    // Layer indices for fast array lookup instead of dictionary.
    private const int LAYER_COMPONENT = 0;
    private const int LAYER_DATALINK = 1;
    private const int LAYER_NETWORK = 2;
    private const int LAYER_TRANSPORT = 3;
    private const int LAYER_APPLICATION = 4;
    private const int LAYER_DROP = 5;
    private const int LAYER_COUNT = 6;

    // [layer][variant] → ANSI prefix string. variant 0=Bright, 1=Muted.
    private static string[,] _prefixes = new string[LAYER_COUNT, 2];
    private static string _reset = "\x1b[0m";

    // Component prefix cache: compId → [bright, muted] formatted strings.
    private static Dictionary<int, string[]> _compCache = new Dictionary<int, string[]>();

    /// <summary>
    /// Initializes the color scheme. Call once at capture start with the resolved ANSI SGR params.
    /// layerSgrs: array of 12 strings [CompBright, CompMuted, DLBright, DLMuted, NetBright, NetMuted, 
    ///            TransBright, TransMuted, AppBright, AppMuted, DropBright, DropMuted].
    /// resetSgr: the reset SGR param (usually "0").
    /// </summary>
    public static void InitColorScheme(string[] layerSgrs, string resetSgr)
    {
        _reset = "\x1b[" + resetSgr + "m";
        for (int i = 0; i < LAYER_COUNT; i++)
        {
            int idx = i * 2;
            _prefixes[i, 0] = "\x1b[" + layerSgrs[idx] + "m";       // Bright
            _prefixes[i, 1] = "\x1b[" + layerSgrs[idx + 1] + "m";   // Muted
        }
        _compCache.Clear();
    }

    /// <summary>
    /// Returns the layer index for a layer name string.
    /// </summary>
    private static int GetLayerIndex(string layer)
    {
        if (layer == null) return -1;
        switch (layer)
        {
            case "Component": return LAYER_COMPONENT;
            case "DataLink": return LAYER_DATALINK;
            case "Network": return LAYER_NETWORK;
            case "Transport": return LAYER_TRANSPORT;
            case "Application": return LAYER_APPLICATION;
            case "Drop": return LAYER_DROP;
            default: return -1;
        }
    }

    /// <summary>
    /// Wraps text in ANSI color for the given layer and line counter.
    /// </summary>
    public static string Colorize(string text, string layer, int lineCounter)
    {
        int li = GetLayerIndex(layer);
        if (li < 0) return text;
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string prefix = _prefixes[li, variant];
        if (prefix == null) return text;
        return string.Concat(prefix, text, _reset);
    }

    /// <summary>
    /// Colorize using pre-resolved layer index (faster for repeated calls in same function).
    /// layerIndex: 0=Component, 1=DataLink, 2=Network, 3=Transport, 4=Application, 5=Drop
    /// </summary>
    public static string ColorizeByIndex(string text, int layerIndex, int lineCounter)
    {
        if (layerIndex < 0 || layerIndex >= LAYER_COUNT) return text;
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string prefix = _prefixes[layerIndex, variant];
        if (prefix == null) return text;
        return string.Concat(prefix, text, _reset);
    }

    /// <summary>
    /// Append a colorized segment directly to the supplied StringBuilder. Saves the
    /// intermediate string allocation that ColorizeByIndex would otherwise create.
    /// </summary>
    public static void AppendColorized(StringBuilder sb, string text, int layerIndex, int lineCounter)
    {
        if (text == null) return;
        if (layerIndex < 0 || layerIndex >= LAYER_COUNT) { sb.Append(text); return; }
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string prefix = _prefixes[layerIndex, variant];
        if (prefix == null) { sb.Append(text); return; }
        sb.Append(prefix).Append(text).Append(_reset);
    }

    /// <summary>
    /// Formats and caches the component prefix string for a given component ID.
    /// Returns the ANSI-colored prefix like "001:005 (ComponentName     )[ In]".
    /// </summary>
    public static string FormatComponentPrefix(int parentId, int compId, string compName, int lineCounter, int edgeId)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        int cacheKey = (compId << 3) | (edgeId << 1) | variant;
        string[] cached;
        if (_compCache.TryGetValue(cacheKey, out cached))
        {
            return cached[0];
        }

        // Format: "PPP:CCC (Name                )[ In|Out]"
        if (compName == null) compName = "";
        if (compName.Length > 20) compName = compName.Substring(0, 20);
        else if (compName.Length < 20) compName = compName.PadRight(20);

        // Edge suffix after closing paren: 1=Ingress→[ In], 2=Egress→[Out]
        string edgeSuffix = "";
        if (edgeId == 1) edgeSuffix = "[ In]";
        else if (edgeId == 2) edgeSuffix = "[Out]";

        string raw = parentId.ToString("D3") + ":" + compId.ToString("D3") + " (" + compName + ")" + edgeSuffix;
        string prefix = _prefixes[LAYER_COMPONENT, variant];
        string result;
        if (prefix != null)
        {
            result = string.Concat(prefix, raw, _reset);
        }
        else
        {
            result = raw;
        }

        _compCache[cacheKey] = new string[] { result };
        return result;
    }

    /// <summary>
    /// Overload for backward compatibility (edgeId defaults to 0).
    /// </summary>
    public static string FormatComponentPrefix(int parentId, int compId, string compName, int lineCounter)
    {
        return FormatComponentPrefix(parentId, compId, compName, lineCounter, 0);
    }

    /// <summary>
    /// Clears the component prefix cache. Call when component map changes.
    /// </summary>
    public static void ClearComponentCache()
    {
        _compCache.Clear();
    }

    /// <summary>
    /// Gets the reset sequence.
    /// </summary>
    public static string GetReset()
    {
        return _reset;
    }

    /// <summary>
    /// Builds the colored "src.srcPort > dst.dstPort" address prefix for TCP/UDP packets.
    /// </summary>
    public static string FormatAddressPrefix(string src, int srcPort, string dst, int dstPort, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string netPfx = _prefixes[LAYER_NETWORK, variant];
        string trPfx = _prefixes[LAYER_TRANSPORT, variant];
        
        return string.Concat(
            netPfx, src, _reset,
            trPfx, ".", srcPort.ToString(), _reset,
            netPfx, " > ", dst, _reset,
            trPfx, ".", dstPort.ToString(), _reset
        );
    }

    /// <summary>
    /// Builds the full colored line for a TCP/UDP packet with a protocol suffix.
    /// pattern: "src.srcPort > dst.dstPort: [coloredSuffix]"
    /// suffixLayer: which layer to color the suffix with (3=Transport, 4=Application)
    /// </summary>
    public static string FormatTransportLine(string src, int srcPort, string dst, int dstPort, string suffix, int suffixLayer, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string netPfx = _prefixes[LAYER_NETWORK, variant];
        string trPfx = _prefixes[LAYER_TRANSPORT, variant];
        string suffPfx = _prefixes[suffixLayer, variant];

        return string.Concat(
            netPfx, src, _reset,
            trPfx, ".", srcPort.ToString(), _reset,
            netPfx, " > ", dst, _reset,
            trPfx, ".", dstPort.ToString(), _reset,
            ": ",
            suffPfx, suffix, _reset
        );
    }

    /// <summary>
    /// Formats a simple "src > dst: text" line, all in Network color.
    /// Used for ICMP, ICMPv6, and fallback paths.
    /// </summary>
    public static string FormatNetworkOnly(string text, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string pfx = _prefixes[LAYER_NETWORK, variant];
        if (pfx == null) return text;
        return string.Concat(pfx, text, _reset);
    }

    /// <summary>
    /// Parses IPv6 source and destination addresses from raw packet data.
    /// Returns true if successful, with src and dst set.
    /// </summary>
    public static bool ParseIPv6Addresses(byte[] raw, int ipv6Offset, out string src, out string dst)
    {
        src = null;
        dst = null;
        if (raw == null || raw.Length < ipv6Offset + 40) return false;
        
        byte[] srcBytes = new byte[16];
        byte[] dstBytes = new byte[16];
        Buffer.BlockCopy(raw, ipv6Offset + 8, srcBytes, 0, 16);
        Buffer.BlockCopy(raw, ipv6Offset + 24, dstBytes, 0, 16);
        src = new System.Net.IPAddress(srcBytes).ToString();
        dst = new System.Net.IPAddress(dstBytes).ToString();
        return true;
    }

    /// <summary>
    /// Formats the minimal-mode colored output line.
    /// Joins non-empty colored segments with ": "
    /// </summary>
    public static string FormatMinimalColors(string dlName, string netProto, string transProto,
        string src, string srcPort, string dst, string dstPort, string appStr, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string dlPfx = _prefixes[LAYER_DATALINK, variant];
        string netPfx = _prefixes[LAYER_NETWORK, variant];
        string trPfx = _prefixes[LAYER_TRANSPORT, variant];
        string appPfx = _prefixes[LAYER_APPLICATION, variant];

        string coloredDL = null;
        if (dlName != null && dlName.Length > 0 && dlPfx != null)
            coloredDL = string.Concat(dlPfx, dlName, _reset);
        else if (dlName != null && dlName.Length > 0)
            coloredDL = dlName;

        string protoLabel = null;
        if (netProto != null && netProto.Length > 0)
        {
            if (transProto != null && transProto.Length > 0)
            {
                string cNet = (netPfx != null) ? string.Concat(netPfx, netProto, _reset) : netProto;
                string cTr = (trPfx != null) ? string.Concat(trPfx, ".", transProto, _reset) : "." + transProto;
                protoLabel = string.Concat(cNet, cTr);
            }
            else
            {
                protoLabel = (netPfx != null) ? string.Concat(netPfx, netProto, _reset) : netProto;
            }
        }

        string addrStr = null;
        if (src != null && src.Length > 0 && dst != null && dst.Length > 0)
        {
            string cSrc = (netPfx != null) ? string.Concat(netPfx, src, _reset) : src;
            string cSrcPort = "";
            if (srcPort != null && srcPort.Length > 0)
                cSrcPort = (trPfx != null) ? string.Concat(trPfx, srcPort, _reset) : srcPort;
            string cDst = (netPfx != null) ? string.Concat(netPfx, " > ", dst, _reset) : " > " + dst;
            string cDstPort = "";
            if (dstPort != null && dstPort.Length > 0)
                cDstPort = (trPfx != null) ? string.Concat(trPfx, dstPort, _reset) : dstPort;
            addrStr = string.Concat(cSrc, cSrcPort, cDst, cDstPort);
        }

        string coloredApp = null;
        if (appStr != null && appStr.Length > 0)
            coloredApp = (appPfx != null) ? string.Concat(appPfx, appStr, _reset) : appStr;

        // Join non-null parts with ": "
        int partCount = 0;
        if (coloredDL != null) partCount++;
        if (protoLabel != null) partCount++;
        if (addrStr != null) partCount++;
        if (coloredApp != null) partCount++;
        if (partCount == 0) return null;

        StringBuilder sb = new StringBuilder(256);
        bool first = true;
        if (coloredDL != null) { sb.Append(coloredDL); first = false; }
        if (protoLabel != null) { if (!first) sb.Append(": "); sb.Append(protoLabel); first = false; }
        if (addrStr != null) { if (!first) sb.Append(": "); sb.Append(addrStr); first = false; }
        if (coloredApp != null) { if (!first) sb.Append(": "); sb.Append(coloredApp); }
        return sb.ToString();
    }
}
