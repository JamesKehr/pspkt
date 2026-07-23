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

    internal static string FormatHexPreview(byte[] data, int offset, int count, int maximumBytes)
    {
        if (data == null || offset < 0 || offset >= data.Length || count <= 0 || maximumBytes <= 0) return "";
        int available = Math.Min(count, data.Length - offset);
        int shown = Math.Min(available, maximumBytes);
        StringBuilder builder = new StringBuilder(shown * 2 + 3);
        for (int i = 0; i < shown; i++) builder.Append(HexBytes[data[offset + i]]);
        if (shown < available) builder.Append("...");
        return builder.ToString();
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

    // Lowercase hex nibbles for direct IPv6 word formatting (no per-word string lookup).
    private static readonly char[] HexNibble = new char[]
        { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

    // Reusable per-thread scratch (single consumer thread) so FormatIPv6 allocates only its
    // returned string — no per-call int[8] groups array and no per-call StringBuilder.
    [ThreadStatic] private static int[] _v6Groups;
    [ThreadStatic] private static StringBuilder _v6Sb;

    /// <summary>
    /// Formats an IPv6 address from 16 bytes at the given offset using RFC 5952 compressed
    /// notation, without allocating any temporary byte[] or IPAddress objects.
    /// </summary>
    public static string FormatIPv6(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 16) return "";

        int[] groups = _v6Groups;
        if (groups == null) { groups = new int[8]; _v6Groups = groups; }
        for (int i = 0; i < 8; i++)
            groups[i] = (data[offset + i * 2] << 8) | data[offset + i * 2 + 1];

        // Find the longest run of consecutive zero groups for :: compression.
        int bestStart = -1, bestLen = 0;
        int curStart = -1, curLen = 0;
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

        StringBuilder sb = _v6Sb;
        if (sb == null) { sb = new StringBuilder(39); _v6Sb = sb; }
        else sb.Length = 0;
        for (int i = 0; i < 8; i++)
        {
            if (i == bestStart)
            {
                sb.Append("::");
                i += bestLen - 1;
                continue;
            }
            if (i > 0 && !(i == bestStart + bestLen && bestStart >= 0)) sb.Append(':');
            AppendHexWord(sb, groups[i]);
        }
        return sb.ToString();
    }

    // Appends a 16-bit word as lowercase hex with no leading zeros (RFC 5952), matching
    // word.ToString("x") but without the intermediate string.
    private static void AppendHexWord(StringBuilder sb, int word)
    {
        if (word == 0) { sb.Append('0'); return; }
        int n0 = (word >> 12) & 0xF;
        int n1 = (word >> 8) & 0xF;
        int n2 = (word >> 4) & 0xF;
        int n3 = word & 0xF;
        bool started = false;
        if (n0 != 0) { sb.Append(HexNibble[n0]); started = true; }
        if (started || n1 != 0) { sb.Append(HexNibble[n1]); started = true; }
        if (started || n2 != 0) { sb.Append(HexNibble[n2]); }
        sb.Append(HexNibble[n3]);
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
        StringBuilder sb = new StringBuilder(48);
        AppendTcpSegmentInto(sb, flags, seq, ack, win, dataLen);
        return sb.ToString();
    }

    /// <summary>
    /// Append-only variant of <see cref="FormatTcpSegment"/>: writes the segment summary
    /// directly into sb with no char[] flag buffer, no int/uint.ToString() strings and no
    /// concat (StringBuilder's numeric overloads write digits directly). Byte-for-byte
    /// identical to FormatTcpSegment.
    /// </summary>
    public static void AppendTcpSegmentInto(StringBuilder sb, byte flags, uint seq, uint ack, ushort win, int dataLen)
    {
        sb.Append("TCP [");
        AppendTcpFlagsInto(sb, flags);
        sb.Append("], seq ").Append(seq).Append(", ack ").Append(ack)
          .Append(", win ").Append(win).Append(", len ").Append(dataLen);
    }

    /// <summary>Append-only variant of <see cref="FormatTcpFlags"/> (appends set flag chars, or "none").</summary>
    public static void AppendTcpFlagsInto(StringBuilder sb, byte flags)
    {
        if (flags == 0) { sb.Append("none"); return; }
        for (int i = 0; i < 8; i++)
        {
            if ((flags & (0x80 >> i)) != 0)
            {
                sb.Append(TcpFlagChars[i]);
            }
        }
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
    /// Appends the colored data-link segment directly into <paramref name="sb"/> — an append-only
    /// formatter that builds no intermediate per-packet string. Text-box mode uses the compact
    /// "Eth" / "802.11" label; full mode uses "src &gt; dst, len N". Returns false (appending
    /// nothing) when there is no data-link segment (linkKind 0, or an unknown linkKind in text-box
    /// mode). Color handling matches <see cref="AppendColorized"/> exactly, including the uncolored
    /// case (a null layer prefix yields no prefix AND no reset).
    /// </summary>
    public static bool AppendDataLinkInto(StringBuilder sb, bool textBoxMode, int linkKind, string srcMac, string dstMac, int rawLen, int lineCounter)
    {
        if (linkKind == 0) return false;
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string prefix = _prefixes[LAYER_DATALINK, variant];

        if (textBoxMode)
        {
            string label = linkKind == 1 ? "Eth" : (linkKind == 2 ? "802.11" : null);
            if (label == null) return false;
            if (prefix == null) { sb.Append(label); return true; }
            sb.Append(prefix).Append(label).Append(_reset);
            return true;
        }

        string src = srcMac ?? "??-??-??-??-??-??";
        string dst = dstMac ?? "??-??-??-??-??-??";
        if (prefix != null) sb.Append(prefix);
        sb.Append(src).Append(" > ").Append(dst).Append(", len ").Append(rawLen);
        if (prefix != null) sb.Append(_reset);
        return true;
    }

    /// </summary>
    public static string FormatComponentPrefix(int parentId, int compId, string compName, int lineCounter, int edgeId)
    {
        return FormatComponentPrefix(parentId, compId, compName, lineCounter, edgeId, 0);
    }

    /// <summary>
    /// Formats the component prefix with Unicode arrow indicators for direction and edge.
    /// Format: "GGG:CCC[↑←](CompName        ):" — CompName is always padded/truncated to a
    /// fixed width so the prefix length (and therefore where Data Link content starts) is
    /// identical for every packet, regardless of component name length.
    ///   Direction: ↑ = In (1), ↓ = Out (2), space = unspecified
    ///   Edge: → = Ingress (1), ← = Egress (2), space = unspecified
    /// </summary>
    public static string FormatComponentPrefix(int parentId, int compId, string compName, int lineCounter, int edgeId, int direction)
    {
        return FormatComponentPrefix(parentId, compId, compName, lineCounter, edgeId, direction, true);
    }

    /// <summary>
    /// Component prefix cache-key bit layout (fields must not overlap — direction/edgeId come
    /// straight from raw pktmon metadata and can carry values beyond the documented 1/2, so
    /// each gets a full 4-bit field). Overlapping bits previously caused different
    /// (direction, edgeId, compId) combinations to collide and return the wrong cached prefix.
    ///   bit 0    : variant (0-1)
    ///   bit 1    : includeName
    ///   bits 2-5 : direction (0-15)
    ///   bits 6-9 : edgeId    (0-15)
    ///   bits 10+ : compId
    /// </summary>
    private static int ComponentCacheKey(int compId, int variant, int edgeId, int direction, bool includeName)
    {
        return variant | ((includeName ? 1 : 0) << 1) | ((direction & 0xF) << 2) | ((edgeId & 0xF) << 6) | (compId << 10);
    }

    /// <summary>
    /// Fast path for the steady state: returns the cached component prefix without needing the
    /// component name / parent id (which are only required to BUILD the string on a miss). Lets
    /// the caller skip the per-packet component-map lookup on cache hits. Returns false on a
    /// miss — the caller then resolves name/parent and calls <see cref="FormatComponentPrefix"/>.
    /// </summary>
    public static bool TryGetCachedComponentPrefix(int compId, int lineCounter, int edgeId, int direction, bool includeName, out string result)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        int cacheKey = ComponentCacheKey(compId, variant, edgeId, direction, includeName);
        string[] cached;
        if (_compCache.TryGetValue(cacheKey, out cached))
        {
            result = cached[0];
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>
    /// Formats the component prefix with Unicode arrow indicators for direction and edge.
    /// Full form:  "GGG:CCC[↑←](CompName        )" — CompName padded/truncated to a fixed
    /// width so the prefix length is identical for every packet (column alignment).
    /// Text-box form (includeName=false): "GGG:CCC[↑←]" — the component name is omitted for
    /// the compact BoxyBox Text Box scrolling line.
    ///   Direction: ↑ = In (1/3/5), ↓ = Out (2/4/6), space = unspecified
    ///   Edge: → = Ingress (1), ← = Egress (2), space = unspecified
    /// </summary>
    public static string FormatComponentPrefix(int parentId, int compId, string compName, int lineCounter, int edgeId, int direction, bool includeName)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        int cacheKey = ComponentCacheKey(compId, variant, edgeId, direction, includeName);
        string[] cached;
        if (_compCache.TryGetValue(cacheKey, out cached))
        {
            return cached[0];
        }

        // Fixed-width component name field (20 chars) so the prefix is always the same
        // length regardless of the actual component name — required for column alignment.
        const int nameWidth = 20;
        if (compName == null) compName = "";
        if (compName.Length > nameWidth) compName = compName.Substring(0, nameWidth);
        else if (compName.Length < nameWidth) compName = compName.PadRight(nameWidth);

        // Direction arrow (from PKTMON_DIRECTION_TAG at metadata offset 12):
        //   Incoming  = In(1) / Rx(3) / Ingress(5)  -> ↑
        //   Outgoing  = Out(2) / Tx(4) / Egress(6)  -> ↓
        //   Unspecified(0) or unknown                -> space
        // pktmon reports the direction tag as Ingress/Egress for many WFP and NIC
        // components rather than the plain In/Out tags, so all three incoming and all
        // three outgoing tags must be handled — checking only In(1)/Out(2) left the
        // arrow blank for those components.
        char dirArrow = ' ';
        if (direction == 1 || direction == 3 || direction == 5) dirArrow = '\u2191';       // ↑ In
        else if (direction == 2 || direction == 4 || direction == 6) dirArrow = '\u2193';  // ↓ Out

        // Edge arrow (from EdgeId at metadata offset 18): →=Ingress(1), ←=Egress(2)
        char edgeArrow = ' ';
        if (edgeId == 1) edgeArrow = '\u2192';         // →
        else if (edgeId == 2) edgeArrow = '\u2190';    // ←

        // Note: no trailing ':' here — callers append ": " after the prefix.
        string raw;
        if (includeName)
        {
            raw = string.Concat(
                parentId.ToString("D3"), ":", compId.ToString("D3"),
                "[", dirArrow.ToString(), edgeArrow.ToString(), "]",
                "(", compName, ")");
        }
        else
        {
            raw = string.Concat(
                parentId.ToString("D3"), ":", compId.ToString("D3"),
                "[", dirArrow.ToString(), edgeArrow.ToString(), "]");
        }

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
    /// Overload for backward compatibility (edgeId and direction default to 0).
    /// </summary>
    public static string FormatComponentPrefix(int parentId, int compId, string compName, int lineCounter)
    {
        return FormatComponentPrefix(parentId, compId, compName, lineCounter, 0, 0);
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
        StringBuilder sb = new StringBuilder(96);
        AppendTransportLineInto(sb, src, srcPort, dst, dstPort, suffix, suffixLayer, lineCounter);
        return sb.ToString();
    }

    /// <summary>
    /// Append-only variant of <see cref="FormatTransportLine"/>: writes the colored
    /// "src.srcPort > dst.dstPort: suffix" line directly into <paramref name="sb"/> with no
    /// intermediate concat string and no port int.ToString() allocations (StringBuilder's int
    /// overload writes digits directly). Byte-for-byte identical to FormatTransportLine.
    /// </summary>
    public static void AppendTransportLineInto(StringBuilder sb, string src, int srcPort, string dst, int dstPort, string suffix, int suffixLayer, int lineCounter)
    {
        AppendTransportAddrPrefixInto(sb, src, srcPort, dst, dstPort, lineCounter);
        // Suffix, colored by its layer (append(null) is a no-op, matching string.Concat).
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        sb.Append(_prefixes[suffixLayer, variant]).Append(suffix).Append(_reset);
    }

    /// <summary>
    /// Appends the colored "src.srcPort > dst.dstPort: " address prefix (no suffix) into sb.
    /// Callers then append the suffix themselves — either a string (via a colored append) or
    /// directly (e.g. the alloc-free TCP segment), avoiding a throwaway suffix string.
    /// </summary>
    public static void AppendTransportAddrPrefixInto(StringBuilder sb, string src, int srcPort, string dst, int dstPort, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string netPfx = _prefixes[LAYER_NETWORK, variant];
        string trPfx = _prefixes[LAYER_TRANSPORT, variant];

        sb.Append(netPfx).Append(src).Append(_reset)
          .Append(trPfx).Append('.').Append(srcPort).Append(_reset)
          .Append(netPfx).Append(" > ").Append(dst).Append(_reset)
          .Append(trPfx).Append('.').Append(dstPort).Append(_reset)
          .Append(": ");
    }

    /// <summary>Appends the ANSI color prefix for a layer (or nothing when uncolored).</summary>
    public static void AppendColorStart(StringBuilder sb, int layerIndex, int lineCounter)
    {
        if (layerIndex < 0 || layerIndex >= LAYER_COUNT) return;
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        sb.Append(_prefixes[layerIndex, variant]);
    }

    /// <summary>Appends the ANSI reset sequence.</summary>
    public static void AppendColorReset(StringBuilder sb)
    {
        sb.Append(_reset);
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

    /// <summary>Append-only variant of <see cref="FormatNetworkOnly"/>.</summary>
    public static void AppendNetworkOnlyInto(StringBuilder sb, string text, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string pfx = _prefixes[LAYER_NETWORK, variant];
        if (pfx == null) { sb.Append(text); return; }
        sb.Append(pfx).Append(text).Append(_reset);
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

        // Use the allocation-light FormatIPv6 (RFC 5952) directly on the source range instead
        // of copying two byte[16] buffers into IPAddress objects. This also makes the Default
        // one-liner's IPv6 rendering consistent with the Analysis Details tree, which already
        // uses FormatIPv6.
        src = PacketParseHelper.FormatIPv6(raw, ipv6Offset + 8);
        dst = PacketParseHelper.FormatIPv6(raw, ipv6Offset + 24);
        return true;
    }

    /// <summary>
    /// Formats the minimal-mode colored output line.
    /// Joins non-empty colored segments with ": "
    /// </summary>
    public static string FormatMinimalColors(string dlName, string netProto, string transProto,
        string src, string srcPort, string dst, string dstPort, string appStr, int lineCounter)
    {
        StringBuilder sb = new StringBuilder(256);
        if (!FormatMinimalColorsInto(sb, dlName, netProto, transProto, src, srcPort, dst, dstPort, appStr, lineCounter))
            return null;
        return sb.ToString();
    }

    /// <summary>
    /// Append-only variant of <see cref="FormatMinimalColors"/>: writes the colored minimal
    /// line directly into <paramref name="sb"/> with no intermediate per-segment strings and no
    /// inner StringBuilder/ToString. Returns false (appending nothing) when there is no content.
    /// Output is byte-for-byte identical to FormatMinimalColors.
    /// </summary>
    public static bool FormatMinimalColorsInto(StringBuilder sb, string dlName, string netProto, string transProto,
        string src, string srcPort, string dst, string dstPort, string appStr, int lineCounter)
    {
        int variant = (lineCounter % 2 == 0) ? 0 : 1;
        string dlPfx = _prefixes[LAYER_DATALINK, variant];
        string netPfx = _prefixes[LAYER_NETWORK, variant];
        string trPfx = _prefixes[LAYER_TRANSPORT, variant];
        string appPfx = _prefixes[LAYER_APPLICATION, variant];

        bool hasDL = dlName != null && dlName.Length > 0;
        bool hasProto = netProto != null && netProto.Length > 0;
        bool hasAddr = src != null && src.Length > 0 && dst != null && dst.Length > 0;
        bool hasApp = appStr != null && appStr.Length > 0;
        if (!hasDL && !hasProto && !hasAddr && !hasApp) return false;

        bool first = true;

        if (hasDL)
        {
            // DL is the first segment and is never preceded by ": ".
            if (dlPfx != null) sb.Append(dlPfx).Append(dlName).Append(_reset);
            else sb.Append(dlName);
            first = false;
        }

        if (hasProto)
        {
            if (!first) sb.Append(": ");
            if (netPfx != null) sb.Append(netPfx).Append(netProto).Append(_reset);
            else sb.Append(netProto);
            if (transProto != null && transProto.Length > 0)
            {
                if (trPfx != null) sb.Append(trPfx).Append('.').Append(transProto).Append(_reset);
                else sb.Append('.').Append(transProto);
            }
            first = false;
        }

        if (hasAddr)
        {
            if (!first) sb.Append(": ");
            if (netPfx != null) sb.Append(netPfx).Append(src).Append(_reset);
            else sb.Append(src);
            if (srcPort != null && srcPort.Length > 0)
            {
                if (trPfx != null) sb.Append(trPfx).Append(srcPort).Append(_reset);
                else sb.Append(srcPort);
            }
            if (netPfx != null) sb.Append(netPfx).Append(" > ").Append(dst).Append(_reset);
            else sb.Append(" > ").Append(dst);
            if (dstPort != null && dstPort.Length > 0)
            {
                if (trPfx != null) sb.Append(trPfx).Append(dstPort).Append(_reset);
                else sb.Append(dstPort);
            }
            first = false;
        }

        if (hasApp)
        {
            if (!first) sb.Append(": ");
            if (appPfx != null) sb.Append(appPfx).Append(appStr).Append(_reset);
            else sb.Append(appStr);
        }

        return true;
    }
}
