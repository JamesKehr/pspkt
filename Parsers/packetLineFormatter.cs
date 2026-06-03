// packetLineFormatter.cs - High-performance packet line formatter.
// Eliminates per-packet PowerShell function call overhead by doing all
// protocol dispatch and string formatting in a single C# call.

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Component info stored in the C# component map.
/// </summary>
public class ComponentInfo
{
    public string Name;
    public int ParentId;
    public string Group;
}

/// <summary>
/// High-performance packet line formatter for real-time display.
/// Combines protocol detection, formatting, and ANSI colorization into a single call
/// to eliminate PowerShell function invocation overhead (~5 calls per packet).
/// </summary>
public static class PacketLineFormatter
{
    // Component map: componentId → ComponentInfo
    private static Dictionary<int, ComponentInfo> _componentMap = new Dictionary<int, ComponentInfo>();
    private static HashSet<int> _componentMisses = new HashSet<int>();

    // Thread-static scratch StringBuilder to eliminate per-packet `+` concat allocations
    // in line assembly. The callback/format threads are well-defined (PS consumer + pcapng writer),
    // so [ThreadStatic] is appropriate.
    [ThreadStatic]
    private static StringBuilder _scratch;
    private static StringBuilder Scratch()
    {
        StringBuilder sb = _scratch;
        if (sb == null)
        {
            sb = new StringBuilder(512);
            _scratch = sb;
        }
        else
        {
            sb.Length = 0;
        }
        return sb;
    }

    // Thread-static StringBuilder used by FormatBatch for the entire drain cycle's output.
    // Distinct from Scratch(): Scratch() is reset and reused inside individual helpers
    // (per-packet or per-line), while _batchSb accumulates all of a batch's formatted
    // packets and is reset only on the next FormatBatch call. This keeps the per-batch
    // `new StringBuilder(count * 120)` allocation out of the hot path entirely.
    [ThreadStatic]
    private static StringBuilder _batchSb;
    private static StringBuilder BatchSb(int estimatedCapacity)
    {
        StringBuilder sb = _batchSb;
        if (sb == null)
        {
            // First call on this thread — size for the current batch but at least 4KB so
            // a steady stream of small batches doesn't repeatedly grow the buffer.
            int cap = estimatedCapacity < 4096 ? 4096 : estimatedCapacity;
            sb = new StringBuilder(cap);
            _batchSb = sb;
        }
        else
        {
            sb.Length = 0;
            // Grow capacity if we know the new batch will be much larger than the current
            // buffer. Avoids many small EnsureCapacity calls during the per-packet appends.
            if (estimatedCapacity > sb.Capacity)
            {
                sb.EnsureCapacity(estimatedCapacity);
            }
        }
        return sb;
    }

    // State
    private static bool _showTimestamp = false;
    private static int _detailLevel = 0; // -1=Minimal, 0=Default, 1+=Detailed
    private static readonly string _indent1 = "\x1b[97m \u2514\x1b[0m";
    private static readonly string _indent2 = "\x1b[97m  \u2514\x1b[0m";
    private static readonly string _indent3 = "\x1b[97m   \u2514\x1b[0m";

    /// <summary>
    /// Registers a component in the C# component map.
    /// </summary>
    public static void RegisterComponent(int id, string name, int parentId, string group)
    {
        _componentMap[id] = new ComponentInfo { Name = name, ParentId = parentId, Group = group };
        _componentMisses.Remove(id);
    }

    /// <summary>
    /// Clears the component map.
    /// </summary>
    public static void ClearComponents()
    {
        _componentMap.Clear();
        _componentMisses.Clear();
        PacketFormatter.ClearComponentCache();
    }

    /// <summary>
    /// Checks if a component ID exists in the map.
    /// </summary>
    public static bool HasComponent(int id)
    {
        return _componentMap.ContainsKey(id);
    }

    /// <summary>
    /// Marks a component ID as a miss (tried to refresh, still not found).
    /// </summary>
    public static void MarkComponentMiss(int id)
    {
        _componentMisses.Add(id);
    }

    // ICMP display filter state. Set by Start-Pspkt based on -Ping/-Ping4/-Ping6 (echoOnly)
    // and -NDP/-AA/-AAv6 (ndpOnly). When neither is true, all ICMP/ICMPv6 packets pass.
    // When either is true, ICMP/ICMPv6 packets must match at least one active filter to be
    // displayed (other protocols are unaffected).
    private static bool _icmpEchoOnly;
    private static bool _icmpNdpOnly;

    /// <summary>
    /// Configures display-level filtering for ICMP/ICMPv6 packets. pktmon driver filters
    /// cannot constrain on ICMP type, so this is applied in FormatSinglePacket.
    /// echoOnly=true  → show only ICMPv4 echo (type 0/8) and ICMPv6 echo (type 128/129).
    /// ndpOnly=true   → show only ICMPv6 NDP types 133-137.
    /// Both can be true; passes if the packet matches EITHER condition.
    /// Pass (false, false) to disable filtering.
    /// </summary>
    public static void SetIcmpDisplayFilter(bool echoOnly, bool ndpOnly)
    {
        _icmpEchoOnly = echoOnly;
        _icmpNdpOnly = ndpOnly;
    }

    /// <summary>
    /// True when the ICMP display filter is active. Producer thread checks this to skip
    /// inspection entirely on the fast path when no filter is configured.
    /// </summary>
    public static bool IsIcmpFilterActive
    {
        get { return _icmpEchoOnly || _icmpNdpOnly; }
    }

    /// <summary>
    /// Producer-thread ICMP filter check. Returns true if the packet should be dropped
    /// entirely (no ring enqueue, no file write). Mirrors the display-side check but
    /// operates on the raw stream byte[] before any per-packet parsing.
    /// Only Ethernet link layer is recognized for early filtering — WiFi packets pass
    /// here and rely on the display-side filter as a fallback for console output.
    /// </summary>
    /// <param name="data">The packet stream buffer.</param>
    /// <param name="packetOffset">Offset into data where the Ethernet header starts.</param>
    /// <param name="dataSize">Valid bytes in data.</param>
    public static bool ShouldDropForIcmpFilter(byte[] data, int packetOffset, int dataSize)
    {
        // Fast-path: no filter configured.
        if (!_icmpEchoOnly && !_icmpNdpOnly) return false;

        if (data == null || dataSize < packetOffset + 14) return false;

        int etherTypeOff = packetOffset + 12;
        int etherType = (data[etherTypeOff] << 8) | data[etherTypeOff + 1];
        int ipOff = packetOffset + 14;

        // VLAN tag (0x8100): shift IP header offset by 4.
        if (etherType == 0x8100 && dataSize >= ipOff + 4)
        {
            etherType = (data[ipOff + 2] << 8) | data[ipOff + 3];
            ipOff += 4;
        }

        // IPv4 — only ICMP echo can pass when echoOnly is set; otherwise drop ICMP.
        if (etherType == 0x0800 && dataSize >= ipOff + 20)
        {
            byte versionIHL = data[ipOff];
            if ((versionIHL >> 4) != 4) return false;
            if (data[ipOff + 9] != 1) return false; // not ICMP — non-ICMP packets always pass

            int ihl = (versionIHL & 0x0F) * 4;
            int transportOff = ipOff + ihl;
            if (dataSize < transportOff + 1) return false;

            int icmpType = data[transportOff];
            bool isEcho = (icmpType == 0 || icmpType == 8);
            // NDP doesn't apply to IPv4 — only an active echo filter can keep IPv4 ICMP.
            return !(_icmpEchoOnly && isEcho);
        }

        // IPv6 — only ICMPv6 echo (with echoOnly) or NDP types 133-137 (with ndpOnly) pass.
        // Walks extension headers (Hop-by-Hop, etc.) since Windows commonly prefixes MLDv2
        // and some NDP/echo packets with an HBH header.
        if (etherType == 0x86DD && dataSize >= ipOff + 40)
        {
            if ((data[ipOff] >> 4) != 6) return false;
            int upperProto, upperOff;
            if (!PacketParseHelper.FindIPv6UpperLayer(data, ipOff, dataSize, out upperProto, out upperOff))
                return false;
            if (upperProto != 58) return false; // not ICMPv6 — pass

            if (dataSize < upperOff + 1) return false;
            int icmpv6Type = data[upperOff];
            bool isEcho = (icmpv6Type == 128 || icmpv6Type == 129);
            bool isNdp = (icmpv6Type >= 133 && icmpv6Type <= 137);
            bool keep = (_icmpEchoOnly && isEcho) || (_icmpNdpOnly && isNdp);
            return !keep;
        }

        // Non-ICMP / non-IP packet — never dropped by the ICMP filter.
        return false;
    }

    /// <summary>
    /// Returns true if the component ID is an unresolved miss.
    /// </summary>
    public static bool IsComponentMiss(int id)
    {
        return _componentMisses.Contains(id);
    }

    /// <summary>
    /// Sets display options.
    /// </summary>
    public static void SetOptions(bool showTimestamp, int detailLevel)
    {
        _showTimestamp = showTimestamp;
        _detailLevel = detailLevel;
    }

    // -----------------------------------------------------------------------
    // Timestamp formatting helpers — avoid per-packet string + format-string
    // allocations from DateTime.ToString("yyyy-MM-dd HH:mm:ss.fffffff") when
    // -t is enabled. Direct digit appends are allocation-free.
    // ToLocalTime() is preserved here for DST correctness across long captures.
    // -----------------------------------------------------------------------
    private static void AppendDigits2(StringBuilder sb, int value)
    {
        sb.Append((char)('0' + (value / 10) % 10));
        sb.Append((char)('0' + value % 10));
    }
    private static void AppendDigits4(StringBuilder sb, int value)
    {
        sb.Append((char)('0' + (value / 1000) % 10));
        sb.Append((char)('0' + (value / 100) % 10));
        sb.Append((char)('0' + (value / 10) % 10));
        sb.Append((char)('0' + value % 10));
    }
    private static void AppendDigits7(StringBuilder sb, int value)
    {
        sb.Append((char)('0' + (value / 1000000) % 10));
        sb.Append((char)('0' + (value / 100000) % 10));
        sb.Append((char)('0' + (value / 10000) % 10));
        sb.Append((char)('0' + (value / 1000) % 10));
        sb.Append((char)('0' + (value / 100) % 10));
        sb.Append((char)('0' + (value / 10) % 10));
        sb.Append((char)('0' + value % 10));
    }

    /// <summary>
    /// Appends the FILETIME-as-local-time formatted as "yyyy-MM-dd HH:mm:ss.fffffff"
    /// directly into sb. Returns true on success; false if streamTimestamp is invalid
    /// (in which case nothing was appended).
    /// </summary>
    private static bool AppendLocalTimestamp(StringBuilder sb, long streamTimestamp)
    {
        DateTime dt;
        try { dt = DateTime.FromFileTimeUtc(streamTimestamp).ToLocalTime(); }
        catch { return false; }
        AppendDigits4(sb, dt.Year);  sb.Append('-');
        AppendDigits2(sb, dt.Month); sb.Append('-');
        AppendDigits2(sb, dt.Day);   sb.Append(' ');
        AppendDigits2(sb, dt.Hour);  sb.Append(':');
        AppendDigits2(sb, dt.Minute);sb.Append(':');
        AppendDigits2(sb, dt.Second);sb.Append('.');
        AppendDigits7(sb, (int)(dt.Ticks % 10000000));
        return true;
    }

    /// <summary>
    /// Formats a complete packet line for Default mode (level 0).
    /// Takes pre-extracted fields from the PowerShell PacketData object.
    /// Returns the fully ANSI-colored string, or null if the packet cannot be formatted.
    /// 
    /// Parameters:
    ///   lineCounter - current line counter for color alternation
    ///   streamTimestamp - QPC-based file time (Int64), 0 if unavailable
    ///   compId - component ID from metadata
    ///   edgeId - edge ID from metadata
    ///   dropReason - drop reason enum value (0 = not dropped)
    ///   dropLocation - drop location enum value
    ///   linkKind - 0=None, 1=EthernetII, 2=IEEE80211
    ///   srcMac - source MAC (dash-separated) or null
    ///   dstMac - destination MAC (dash-separated) or null
    ///   etherType - EtherType value
    ///   rawLen - raw packet length
    ///   protoKind - 0=None, 1=ICMP, 2=TCP, 3=UDP, 4=Other
    ///   srcAddr - source IP string
    ///   dstAddr - destination IP string
    ///   srcPort - source port (TCP/UDP)
    ///   dstPort - destination port (TCP/UDP)
    ///   tcpFlags - TCP flags byte
    ///   tcpSeq - TCP sequence number
    ///   tcpAck - TCP acknowledgement number
    ///   tcpWin - TCP window size
    ///   dataLen - payload data length
    ///   icmpType - ICMP type byte
    ///   icmpCode - ICMP code byte
    ///   icmpId - ICMP identifier
    ///   icmpSeq - ICMP sequence number
    ///   udpData - UDP payload bytes (for DNS/DHCP detection)
    ///   rawPacketData - full raw packet bytes (for IPv6/ARP fallback)
    /// </summary>
    public static string FormatDefaultLine(
        int lineCounter,
        long streamTimestamp,
        int compId, int edgeId,
        int dropReason, int dropLocation,
        int linkKind, string srcMac, string dstMac, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData,
        byte[] rawPacketData)
    {
        // String-returning wrapper retained for slow-path callers (Parsers/libParser.psm1).
        // The hot path goes through FormatDefaultLineInto via FormatBatch / FormatSinglePacketInto.
        StringBuilder sb = new StringBuilder(256);
        if (!FormatDefaultLineInto(sb, lineCounter, streamTimestamp,
            compId, edgeId, dropReason, dropLocation,
            linkKind, srcMac, dstMac, etherType, rawLen,
            protoKind, srcAddr, dstAddr, srcPort, dstPort,
            tcpFlags, tcpSeq, tcpAck, tcpWin, dataLen,
            icmpType, icmpCode, icmpId, icmpSeq, udpData, rawPacketData))
        {
            return null;
        }
        return sb.ToString();
    }

    /// <summary>
    /// Append-style variant of FormatDefaultLine: writes the formatted line directly into
    /// the supplied StringBuilder and returns true on success. On a non-formattable packet
    /// returns false; the caller must reset the SB's length back to whatever it was before
    /// the call (this method may have appended a prefix before deciding to bail).
    /// </summary>
    public static bool FormatDefaultLineInto(
        StringBuilder sb,
        int lineCounter,
        long streamTimestamp,
        int compId, int edgeId,
        int dropReason, int dropLocation,
        int linkKind, string srcMac, string dstMac, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData,
        byte[] rawPacketData)
    {
        return FormatDefaultLineInto(sb, lineCounter, streamTimestamp,
            compId, edgeId, dropReason, dropLocation,
            linkKind, srcMac, dstMac, etherType, rawLen,
            protoKind, srcAddr, dstAddr, srcPort, dstPort,
            tcpFlags, tcpSeq, tcpAck, tcpWin, dataLen,
            icmpType, icmpCode, icmpId, icmpSeq, udpData,
            rawPacketData, 0, rawPacketData == null ? 0 : rawPacketData.Length);
    }

    /// <summary>
    /// Range-based variant: rawPacketData[rawOffset..rawOffset+rawLength] is the packet bytes.
    /// Lets the hot path pass the source array directly without first copying out the packet
    /// into its own byte[]. Internal accesses do `data[rawOffset + N]` and treat `rawLength`
    /// as the valid packet length.
    /// </summary>
    public static bool FormatDefaultLineInto(
        StringBuilder sb,
        int lineCounter,
        long streamTimestamp,
        int compId, int edgeId,
        int dropReason, int dropLocation,
        int linkKind, string srcMac, string dstMac, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData,
        byte[] rawPacketData, int rawOffset, int rawLength)
    {
        // --- Timestamp + Component prefix ---
        // Snapshot length so we can rewind the timestamp if it fails to format.
        int beforeTs = sb.Length;
        if (_showTimestamp && streamTimestamp > 0)
        {
            if (AppendLocalTimestamp(sb, streamTimestamp))
            {
                sb.Append(' ');
            }
            else
            {
                sb.Length = beforeTs;
            }
        }
        string compPrefix = FormatComponentPrefixInternal(compId, edgeId, lineCounter);
        sb.Append(compPrefix).Append(": ");

        // --- Drop handling ---
        if (dropReason != 0)
        {
            string dropLine = FormatDropInternal(dropReason, dropLocation, rawPacketData, rawOffset, rawLength);
            PacketFormatter.AppendColorized(sb, dropLine, 5, lineCounter); // LAYER_DROP=5
            return true;
        }

        // --- ARP detection (EtherType 0x0806, no IPv4 data) ---
        if (etherType == 0x0806 && protoKind == 0 && rawPacketData != null && rawLength >= 28)
        {
            string dlSeg = FormatDataLinkInternal(linkKind, srcMac, dstMac, etherType, rawLen);
            string arpSeg = FormatArpInternal(rawPacketData, rawOffset, rawLength, linkKind);
            if (dlSeg != null)
            {
                PacketFormatter.AppendColorized(sb, dlSeg, 1, lineCounter);
                sb.Append(": ");
            }
            PacketFormatter.AppendColorized(sb, arpSeg, 2, lineCounter);
            return true;
        }

        // --- Data Link segment ---
        string dlSegment = FormatDataLinkInternal(linkKind, srcMac, dstMac, etherType, rawLen);

        // --- IPv6 handling (no IPv4 data, EtherType 0x86DD) ---
        if (protoKind == 0 && etherType == 0x86DD && rawPacketData != null)
        {
            string ipv6Seg = FormatIPv6Segment(rawPacketData, rawOffset, rawLength, linkKind, lineCounter);
            if (ipv6Seg != null)
            {
                if (dlSegment != null)
                {
                    PacketFormatter.AppendColorized(sb, dlSegment, 1, lineCounter);
                    sb.Append(": ");
                }
                sb.Append(ipv6Seg);
                return true;
            }
            if (dlSegment != null)
            {
                PacketFormatter.AppendColorized(sb, dlSegment, 1, lineCounter);
                return true;
            }
            return false;
        }

        // --- Network + Transport segment ---
        string ntSegment = null;
        if (srcAddr != null && dstAddr != null)
        {
            ntSegment = FormatNetworkTransportInternal(
                lineCounter, protoKind, srcAddr, dstAddr, srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin, dataLen,
                icmpType, icmpCode, icmpId, icmpSeq, udpData);
        }

        if (dlSegment != null && ntSegment != null)
        {
            PacketFormatter.AppendColorized(sb, dlSegment, 1, lineCounter);
            sb.Append(": ").Append(ntSegment);
            return true;
        }
        if (dlSegment != null)
        {
            PacketFormatter.AppendColorized(sb, dlSegment, 1, lineCounter);
            return true;
        }
        if (ntSegment != null) { sb.Append(ntSegment); return true; }
        return false;
    }

    /// <summary>
    /// Formats a minimal-mode packet line (detail level -1).
    /// </summary>
    public static string FormatMinimalLine(
        int lineCounter,
        long streamTimestamp,
        int compId, int edgeId,
        int dropReason, int dropLocation,
        int linkKind, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData,
        byte[] rawPacketData)
    {
        // String-returning wrapper for slow-path callers; hot path uses FormatMinimalLineInto.
        StringBuilder sb = new StringBuilder(128);
        if (!FormatMinimalLineInto(sb, lineCounter, streamTimestamp,
            compId, edgeId, dropReason, dropLocation,
            linkKind, etherType, rawLen,
            protoKind, srcAddr, dstAddr, srcPort, dstPort,
            tcpFlags, tcpSeq, tcpAck, tcpWin, dataLen,
            icmpType, icmpCode, icmpId, icmpSeq, udpData, rawPacketData))
        {
            return null;
        }
        return sb.ToString();
    }

    /// <summary>
    /// Append-style variant of FormatMinimalLine. Returns true on success; on false the
    /// caller must reset sb.Length to whatever it was before the call.
    /// </summary>
    public static bool FormatMinimalLineInto(
        StringBuilder sb,
        int lineCounter,
        long streamTimestamp,
        int compId, int edgeId,
        int dropReason, int dropLocation,
        int linkKind, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData,
        byte[] rawPacketData)
    {
        return FormatMinimalLineInto(sb, lineCounter, streamTimestamp,
            compId, edgeId, dropReason, dropLocation,
            linkKind, etherType, rawLen,
            protoKind, srcAddr, dstAddr, srcPort, dstPort,
            tcpFlags, tcpSeq, tcpAck, tcpWin, dataLen,
            icmpType, icmpCode, icmpId, icmpSeq, udpData,
            rawPacketData, 0, rawPacketData == null ? 0 : rawPacketData.Length);
    }

    /// <summary>
    /// Range-based variant of FormatMinimalLineInto.
    /// </summary>
    public static bool FormatMinimalLineInto(
        StringBuilder sb,
        int lineCounter,
        long streamTimestamp,
        int compId, int edgeId,
        int dropReason, int dropLocation,
        int linkKind, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData,
        byte[] rawPacketData, int rawOffset, int rawLength)
    {
        int beforeTs = sb.Length;
        if (_showTimestamp && streamTimestamp > 0)
        {
            if (AppendLocalTimestamp(sb, streamTimestamp))
            {
                sb.Append(' ');
            }
            else
            {
                sb.Length = beforeTs;
            }
        }

        string compPrefix = FormatComponentPrefixInternal(compId, edgeId, lineCounter);
        sb.Append(compPrefix).Append(": ");

        // Drop
        if (dropReason != 0)
        {
            string dropLine = FormatDropInternal(dropReason, dropLocation, rawPacketData, rawOffset, rawLength);
            PacketFormatter.AppendColorized(sb, dropLine, 5, lineCounter);
            return true;
        }

        // Build minimal segments
        string dlName = "";
        if (linkKind == 1) dlName = "Eth";
        else if (linkKind == 2) dlName = "802.11";

        string netProto = "";
        string transProto = "";
        string appStr = "";
        string spStr = "";
        string dpStr = "";

        if (srcAddr != null && dstAddr != null)
        {
            netProto = "IPv4";
            if (protoKind == 2) // TCP
            {
                transProto = "TCP";
                spStr = "." + srcPort.ToString();
                dpStr = "." + dstPort.ToString();
            }
            else if (protoKind == 3) // UDP
            {
                transProto = "UDP";
                spStr = "." + srcPort.ToString();
                dpStr = "." + dstPort.ToString();
            }
            else if (protoKind == 1) // ICMP
            {
                transProto = "ICMP";
                if (icmpType == 8 || icmpType == 0)
                {
                    string dir = (icmpType == 8) ? "req" : "rpl";
                    appStr = dir + " id=" + icmpId + " seq=" + icmpSeq;
                }
                else
                {
                    appStr = "t" + icmpType + "/c" + icmpCode;
                }
            }
        }
        else if (etherType == 0x86DD && rawPacketData != null)
        {
            netProto = "IPv6";
            int ipv6Off = (linkKind == 2) ? GetWifiPayloadOffset(rawPacketData, rawOffset, rawLength) : 14;
            if (rawLength >= ipv6Off + 40)
            {
                byte[] srcB = new byte[16];
                byte[] dstB = new byte[16];
                Buffer.BlockCopy(rawPacketData, rawOffset + ipv6Off + 8, srcB, 0, 16);
                Buffer.BlockCopy(rawPacketData, rawOffset + ipv6Off + 24, dstB, 0, 16);
                srcAddr = new System.Net.IPAddress(srcB).ToString();
                dstAddr = new System.Net.IPAddress(dstB).ToString();
                int nextHdr, transOff;
                // Absolute coordinates: feed FindIPv6UpperLayer the absolute IPv6 header
                // offset (rawOffset+ipv6Off) and the absolute end-of-valid-bytes
                // (rawOffset+rawLength). The returned transOff is also absolute.
                if (PacketParseHelper.FindIPv6UpperLayer(rawPacketData, rawOffset + ipv6Off, rawOffset + rawLength, out nextHdr, out transOff))
                {
                    if (nextHdr == 58)
                    {
                        transProto = "ICMPv6";
                        if (rawOffset + rawLength > transOff)
                        {
                            int v6type = rawPacketData[transOff];
                            if (v6type == 128 || v6type == 129)
                            {
                                appStr = (v6type == 128) ? "req" : "rpl";
                            }
                            else
                            {
                                appStr = "t" + v6type;
                            }
                        }
                    }
                    else if (nextHdr == 6)
                    {
                        transProto = "TCP";
                        if (rawOffset + rawLength >= transOff + 4)
                        {
                            spStr = "." + PacketParseHelper.ReadUInt16BE(rawPacketData, transOff).ToString();
                            dpStr = "." + PacketParseHelper.ReadUInt16BE(rawPacketData, transOff + 2).ToString();
                        }
                    }
                    else if (nextHdr == 17)
                    {
                        transProto = "UDP";
                        if (rawOffset + rawLength >= transOff + 4)
                        {
                            spStr = "." + PacketParseHelper.ReadUInt16BE(rawPacketData, transOff).ToString();
                            dpStr = "." + PacketParseHelper.ReadUInt16BE(rawPacketData, transOff + 2).ToString();
                        }
                    }
                }
            }
        }

        string line = PacketFormatter.FormatMinimalColors(dlName, netProto, transProto,
            srcAddr ?? "", spStr, dstAddr ?? "", dpStr, appStr, lineCounter);
        if (line == null) return false;
        sb.Append(line);
        return true;
    }

    /// <summary>
    /// Append-style variant of FormatDetailedLine: writes the formatted multi-line
    /// detailed output directly into sb. Returns false if the packet cannot be
    /// formatted; on false, caller must restore sb.Length to its pre-call value.
    /// rawPacketData[rawOffset..rawOffset+rawLength] is the packet bytes (no copy required).
    /// </summary>
    private static bool FormatDetailedLineInto(
        StringBuilder sb,
        int lineCounter, long streamTimestamp,
        int compId, int edgeId, int dropReason, int dropLocation,
        int linkKind, string srcMac, string dstMac, int etherType, int rawLen,
        int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] transportPayload, byte[] rawPacketData, int rawOffset, int rawLength,
        byte ipTos, int ipTotalLength, ushort ipId, byte ipFlags, byte ipTtl, byte ipProtocol,
        int ipOffset, int transportOffset, int tcpDataOffset)
    {
        if (dropReason != 0)
        {
            if (!FormatDefaultLineInto(sb,
                lineCounter, streamTimestamp,
                compId, edgeId, dropReason, dropLocation,
                linkKind, srcMac, dstMac, etherType, rawLen,
                protoKind, srcAddr, dstAddr,
                srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin,
                dataLen,
                icmpType, icmpCode, icmpId, icmpSeq,
                transportPayload, rawPacketData, rawOffset, rawLength)) return false;
            if (_detailLevel >= 2) sb.Append('\n');
            return true;
        }

        if (etherType == 0x0806 && protoKind == 0 && rawPacketData != null && rawLength >= 28)
        {
            if (!FormatDefaultLineInto(sb,
                lineCounter, streamTimestamp,
                compId, edgeId, dropReason, dropLocation,
                linkKind, srcMac, dstMac, etherType, rawLen,
                protoKind, srcAddr, dstAddr,
                srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin,
                dataLen,
                icmpType, icmpCode, icmpId, icmpSeq,
                transportPayload, rawPacketData, rawOffset, rawLength)) return false;
            if (_detailLevel >= 2) sb.Append('\n');
            return true;
        }

        // Build dlSegment FIRST so we can fall back without having appended anything to sb.
        string dlSegment = FormatDataLinkInternal(linkKind, srcMac, dstMac, etherType, rawLen);
        if (dlSegment == null)
        {
            if (!FormatDefaultLineInto(sb,
                lineCounter, streamTimestamp,
                compId, edgeId, dropReason, dropLocation,
                linkKind, srcMac, dstMac, etherType, rawLen,
                protoKind, srcAddr, dstAddr,
                srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin,
                dataLen,
                icmpType, icmpCode, icmpId, icmpSeq,
                transportPayload, rawPacketData, rawOffset, rawLength)) return false;
            if (_detailLevel >= 2) sb.Append('\n');
            return true;
        }

        string networkDetail = null;
        string transportDetail = null;
        string appDetail = null;
        int transportLayerIndex = 3;

        if (etherType == 0x0800 && srcAddr != null && dstAddr != null)
        {
            StringBuilder nsb = new StringBuilder(128);
            nsb.Append("IPv4 - Src: ").Append(srcAddr).Append(", Dst: ").Append(dstAddr)
               .Append("; DSCP: ").Append(GetDscpName(ipTos >> 2))
               .Append("; len: ").Append(ipTotalLength)
               .Append("; id: 0x").Append(ipId.ToString("x4"))
               .Append("; flg: ").Append(GetIpv4FlagsText(ipFlags))
               .Append("; TTL: ").Append(ipTtl)
               .Append("; Next: ").Append(GetProtocolName(ipProtocol));
            networkDetail = nsb.ToString();

            if (protoKind == 1)
            {
                if (icmpType == 0 || icmpType == 8)
                {
                    string dir = (icmpType == 8) ? "request" : "reply";
                    transportDetail = "ICMP echo " + dir + " - id: " + icmpId.ToString() + ", seq: " + icmpSeq.ToString() + "; TTL: " + ipTtl.ToString();
                }
                else
                {
                    transportDetail = "ICMP type " + icmpType.ToString() + " code " + icmpCode.ToString();
                }
            }
            else if (protoKind == 2)
            {
                // Use range-based TCP options accessor to avoid per-packet byte[] slice allocation.
                // transportOffset is relative to packet start; convert to absolute for the parser.
                int optOffset = -1, optLen = 0;
                if (rawPacketData != null && transportOffset >= 0 && tcpDataOffset > 20 && transportOffset + tcpDataOffset <= rawLength)
                {
                    optOffset = rawOffset + transportOffset + 20;
                    optLen = tcpDataOffset - 20;
                }
                transportDetail = TcpParser.FormatTcpDetailed(tcpFlags, (ushort)srcPort, (ushort)dstPort, tcpSeq, tcpAck, tcpWin, dataLen, rawPacketData, optOffset >= 0 ? optOffset : 0, optLen);
                appDetail = DetectTcpAppDetailed(srcPort, dstPort, transportPayload);
            }
            else if (protoKind == 3)
            {
                transportDetail = "UDP - Src: " + srcPort.ToString() + ", Dst: " + dstPort.ToString() + "; len: " + dataLen.ToString();
                appDetail = DetectUdpAppDetailed(srcPort, dstPort, transportPayload);
            }
            else if (protoKind == 4)
            {
                transportDetail = "IP payload - protocol: " + GetProtocolName(ipProtocol);
            }
        }
        else if (etherType == 0x86DD && rawPacketData != null && ipOffset >= 0 && rawLength >= ipOffset + 40)
        {
            // Absolute IPv6 header offset in rawPacketData.
            int ipv6AbsOff = rawOffset + ipOffset;
            uint firstWord = PacketParseHelper.ReadUInt32BE(rawPacketData, ipv6AbsOff);
            byte trafficClass = (byte)((firstWord >> 20) & 0xFF);
            int flowLabel = (int)(firstWord & 0xFFFFF);
            int payloadLength = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6AbsOff + 4);
            int nextHeader = rawPacketData[ipv6AbsOff + 6];
            int hopLimit = rawPacketData[ipv6AbsOff + 7];
            string ipv6Src = FormatIPv6Address(rawPacketData, ipv6AbsOff + 8);
            string ipv6Dst = FormatIPv6Address(rawPacketData, ipv6AbsOff + 24);
            StringBuilder nsb = new StringBuilder(128);
            nsb.Append("IPv6 - Src: ").Append(ipv6Src).Append(", Dst: ").Append(ipv6Dst)
               .Append("; TC: ").Append(GetDscpName(trafficClass >> 2))
               .Append("; FL: 0x").Append(flowLabel.ToString("x5"))
               .Append("; len: ").Append(payloadLength)
               .Append("; TTL: ").Append(hopLimit)
               .Append("; Next: ").Append(GetProtocolName((byte)nextHeader));
            networkDetail = nsb.ToString();

            // Walk extension headers to find the real upper-layer protocol + offset.
            // Pass absolute coordinates; the returned ipv6TransportOffset is also absolute.
            int rawEnd = rawOffset + rawLength;
            int upperProto, ipv6TransportOffset;
            bool haveUpper = PacketParseHelper.FindIPv6UpperLayer(rawPacketData, ipv6AbsOff, rawEnd, out upperProto, out ipv6TransportOffset);
            int ipv6TransportLength = haveUpper ? Math.Max(0, rawEnd - ipv6TransportOffset) : 0;

            if (haveUpper && upperProto == 58 && ipv6TransportLength >= 4)
            {
                int icmpv6Type = rawPacketData[ipv6TransportOffset];
                int icmpv6Code = rawPacketData[ipv6TransportOffset + 1];
                transportLayerIndex = 2;
                if (icmpv6Type >= 133 && icmpv6Type <= 137)
                {
                    transportDetail = FormatNdpBasic(icmpv6Type);
                }
                else if ((icmpv6Type == 128 || icmpv6Type == 129) && ipv6TransportLength >= 8)
                {
                    string dir = (icmpv6Type == 128) ? "request" : "reply";
                    int echoId = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset + 4);
                    int echoSeq = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset + 6);
                    transportDetail = "ICMPv6 echo " + dir + " - id: " + echoId.ToString() + ", seq: " + echoSeq.ToString() + "; TTL: " + hopLimit.ToString();
                }
                else
                {
                    transportDetail = "ICMPv6 type " + icmpv6Type.ToString() + " code " + icmpv6Code.ToString();
                }
            }
            else if (haveUpper && upperProto == 6 && ipv6TransportLength >= 20)
            {
                int ipv6SrcPort = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset);
                int ipv6DstPort = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset + 2);
                uint ipv6Seq = PacketParseHelper.ReadUInt32BE(rawPacketData, ipv6TransportOffset + 4);
                uint ipv6Ack = PacketParseHelper.ReadUInt32BE(rawPacketData, ipv6TransportOffset + 8);
                byte ipv6DataOffset = (byte)((rawPacketData[ipv6TransportOffset + 12] >> 4) * 4);
                byte ipv6Flags = rawPacketData[ipv6TransportOffset + 13];
                ushort ipv6Win = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset + 14);
                int ipv6DataLen = Math.Max(0, ipv6TransportLength - ipv6DataOffset);
                int ipv6OptOffset = -1, ipv6OptLen = 0;
                if (ipv6DataOffset > 20 && ipv6TransportOffset + ipv6DataOffset <= rawEnd)
                {
                    ipv6OptOffset = ipv6TransportOffset + 20;
                    ipv6OptLen = ipv6DataOffset - 20;
                }
                transportDetail = TcpParser.FormatTcpDetailed(ipv6Flags, (ushort)ipv6SrcPort, (ushort)ipv6DstPort, ipv6Seq, ipv6Ack, ipv6Win, ipv6DataLen, rawPacketData, ipv6OptOffset >= 0 ? ipv6OptOffset : 0, ipv6OptLen);
                byte[] ipv6Payload = null;
                if (ipv6DataLen > 0 && ipv6TransportOffset + ipv6DataOffset < rawEnd
                    && NeedsTcpPayload(ipv6SrcPort, ipv6DstPort))
                {
                    int payloadLen = Math.Min(ipv6DataLen, rawEnd - ipv6TransportOffset - ipv6DataOffset);
                    ipv6Payload = new byte[payloadLen];
                    Buffer.BlockCopy(rawPacketData, ipv6TransportOffset + ipv6DataOffset, ipv6Payload, 0, payloadLen);
                }
                appDetail = DetectTcpAppDetailed(ipv6SrcPort, ipv6DstPort, ipv6Payload);
            }
            else if (haveUpper && upperProto == 17 && ipv6TransportLength >= 8)
            {
                int ipv6SrcPort = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset);
                int ipv6DstPort = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset + 2);
                int udpLength = PacketParseHelper.ReadUInt16BE(rawPacketData, ipv6TransportOffset + 4);
                int ipv6DataLen = Math.Max(0, udpLength - 8);
                transportDetail = "UDP - Src: " + ipv6SrcPort.ToString() + ", Dst: " + ipv6DstPort.ToString() + "; len: " + ipv6DataLen.ToString();
                byte[] ipv6Payload = null;
                if (ipv6DataLen > 0 && ipv6TransportOffset + 8 < rawEnd
                    && NeedsUdpPayload(ipv6SrcPort, ipv6DstPort))
                {
                    int payloadLen = Math.Min(ipv6DataLen, rawEnd - ipv6TransportOffset - 8);
                    ipv6Payload = new byte[payloadLen];
                    Buffer.BlockCopy(rawPacketData, ipv6TransportOffset + 8, ipv6Payload, 0, payloadLen);
                }
                appDetail = DetectUdpAppDetailed(ipv6SrcPort, ipv6DstPort, ipv6Payload);
            }
        }

        if (networkDetail == null)
        {
            if (!FormatDefaultLineInto(sb,
                lineCounter, streamTimestamp,
                compId, edgeId, dropReason, dropLocation,
                linkKind, srcMac, dstMac, etherType, rawLen,
                protoKind, srcAddr, dstAddr,
                srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin,
                dataLen,
                icmpType, icmpCode, icmpId, icmpSeq,
                transportPayload, rawPacketData, rawOffset, rawLength)) return false;
            if (_detailLevel >= 2) sb.Append('\n');
            return true;
        }

        // Compute timestamp + component prefix lazily (only when we know we'll emit output).
        int beforeTs = sb.Length;
        if (_showTimestamp && streamTimestamp > 0)
        {
            if (AppendLocalTimestamp(sb, streamTimestamp))
            {
                sb.Append(' ');
            }
            else
            {
                sb.Length = beforeTs;
            }
        }
        sb.Append(FormatComponentPrefixInternal(compId, edgeId, lineCounter));
        sb.Append(": ");
        PacketFormatter.AppendColorized(sb, dlSegment, 1, lineCounter);
        sb.Append('\n');
        sb.Append(_indent1);
        PacketFormatter.AppendColorized(sb, networkDetail, 2, lineCounter);

        if (transportDetail != null)
        {
            sb.Append('\n');
            sb.Append(_indent2);
            PacketFormatter.AppendColorized(sb, transportDetail, transportLayerIndex, lineCounter);
        }

        if (appDetail != null)
        {
            sb.Append('\n');
            sb.Append(_indent3);
            PacketFormatter.AppendColorized(sb, appDetail, 4, lineCounter);
        }

        if (_detailLevel >= 2)
            sb.Append('\n');

        return true;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private static string FormatComponentPrefixInternal(int compId, int edgeId, int lineCounter)
    {
        string compName = "";
        int parentId = 0;

        ComponentInfo info;
        if (_componentMap.TryGetValue(compId, out info))
        {
            compName = info.Name;
            parentId = info.ParentId;
        }

        return PacketFormatter.FormatComponentPrefix(parentId, compId, compName, lineCounter, edgeId);
    }

    private static string FormatDataLinkInternal(int linkKind, string srcMac, string dstMac, int etherType, int rawLen)
    {
        if (linkKind == 0) return null;

        string src = srcMac ?? "??-??-??-??-??-??";
        string dst = dstMac ?? "??-??-??-??-??-??";
        string etName = GetEtherTypeName(etherType);
        StringBuilder sb = new StringBuilder(64);
        sb.Append(src).Append(" > ").Append(dst).Append(", type ").Append(etName)
          .Append(", len ").Append(rawLen);
        return sb.ToString();
    }

    private static readonly Dictionary<int, string> EtherTypeNames = new Dictionary<int, string>
    {
        { 0x0800, "IPv4" }, { 0x0806, "ARP" }, { 0x86DD, "IPv6" },
        { 0x8100, "802.1Q" }, { 0x88CC, "LLDP" }, { 0x8035, "RARP" },
        { 0x888E, "802.1X" }, { 0x88A8, "802.1ad" }
    };

    private static string GetEtherTypeName(int etherType)
    {
        string name;
        if (EtherTypeNames.TryGetValue(etherType, out name)) return name;
        return "0x" + etherType.ToString("X4");
    }

    private static string FormatNetworkTransportInternal(
        int lineCounter, int protoKind, string srcAddr, string dstAddr,
        int srcPort, int dstPort,
        byte tcpFlags, uint tcpSeq, uint tcpAck, ushort tcpWin,
        int dataLen,
        int icmpType, int icmpCode, int icmpId, int icmpSeq,
        byte[] udpData)
    {
        // ICMP
        if (protoKind == 1)
        {
            StringBuilder sb = new StringBuilder(96);
            sb.Append(srcAddr).Append(" > ").Append(dstAddr).Append(": ");
            if (icmpType == 0 || icmpType == 8)
            {
                sb.Append("ICMP echo ").Append(icmpType == 8 ? "request" : "reply")
                  .Append(", id ").Append(icmpId)
                  .Append(", seq ").Append(icmpSeq)
                  .Append(", len ").Append(dataLen);
            }
            else
            {
                sb.Append("ICMP type ").Append(icmpType).Append(" code ").Append(icmpCode);
            }
            return PacketFormatter.FormatNetworkOnly(sb.ToString(), lineCounter);
        }

        // TCP
        if (protoKind == 2)
        {
            // Detect application layer protocol by port
            string suffix = null;
            int appLayer = 3; // Transport layer by default

            // SMB2 detection (port 445)
            if (srcPort == 445 || dstPort == 445)
            {
                if (Smb2Parser.IsSmb2Packet(udpData, srcPort, dstPort))
                {
                    suffix = Smb2Parser.FormatSmb2Segment(udpData, srcPort, dstPort);
                    if (suffix != null) appLayer = 4;
                }
            }

            if (suffix == null && (IsHttpPort(srcPort) || IsHttpPort(dstPort)))
            {
                suffix = DetectHttpContent(udpData, dataLen, srcPort, dstPort);
                if (suffix != null) appLayer = 4;
            }
            if (suffix == null && (IsTlsPort(srcPort) || IsTlsPort(dstPort)))
            {
                suffix = DetectTlsContent(udpData, dataLen);
                if (suffix != null) appLayer = 4;
            }

            if (suffix == null)
            {
                suffix = PacketParseHelper.FormatTcpSegment(tcpFlags, tcpSeq, tcpAck, tcpWin, dataLen);
            }

            return PacketFormatter.FormatTransportLine(srcAddr, srcPort, dstAddr, dstPort, suffix, appLayer, lineCounter);
        }

        // UDP
        if (protoKind == 3)
        {
            // DNS detection
            if (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353)
            {
                string dnsStr = DnsParser.FormatDnsSegment(udpData, srcPort, dstPort);
                if (dnsStr != null)
                    return PacketFormatter.FormatTransportLine(srcAddr, srcPort, dstAddr, dstPort, dnsStr, 4, lineCounter);
            }

            // DHCP detection
            if ((srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) ||
                (srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547))
            {
                string dhcpStr = FormatDhcpBasic(udpData, srcPort, dstPort);
                if (dhcpStr != null)
                    return PacketFormatter.FormatTransportLine(srcAddr, srcPort, dstAddr, dstPort, dhcpStr, 4, lineCounter);
            }

            StringBuilder usb = new StringBuilder(16);
            usb.Append("UDP, len ").Append(dataLen);
            return PacketFormatter.FormatTransportLine(srcAddr, srcPort, dstAddr, dstPort, usb.ToString(), 3, lineCounter);
        }

        // Fallback
        StringBuilder fsb = new StringBuilder(64);
        fsb.Append(srcAddr).Append(" > ").Append(dstAddr);
        return PacketFormatter.FormatNetworkOnly(fsb.ToString(), lineCounter);
    }

    private static string FormatIPv6Segment(byte[] raw, int linkKind, int lineCounter)
    {
        return FormatIPv6Segment(raw, 0, raw == null ? 0 : raw.Length, linkKind, lineCounter);
    }

    // Range-based overload: the hot path supplies (data, packetOffset, pktLen) so the
    // per-packet packet-buffer copy can be eliminated. DNS detection for UDP-over-IPv6
    // still requires a small per-packet payload copy since DnsParser.FormatDnsSegment
    // takes a byte[].
    private static string FormatIPv6Segment(byte[] data, int rawOffset, int rawLength, int linkKind, int lineCounter)
    {
        int ipv6Off = (linkKind == 2) ? GetWifiPayloadOffset(data, rawOffset, rawLength) : 14;
        if (rawLength < ipv6Off + 40) return null;

        string src, dst;
        if (!PacketFormatter.ParseIPv6Addresses(data, rawOffset + ipv6Off, out src, out dst)) return null;

        // Walk extension headers (HBH, Routing, Fragment, AH, Dest Options) to find the
        // upper-layer protocol. Required for MLDv2 reports and some outbound echo/NDP packets
        // that Windows prefixes with a Hop-by-Hop Options header.
        int nextHeader, transOff;
        if (!PacketParseHelper.FindIPv6UpperLayer(data, rawOffset + ipv6Off, rawOffset + rawLength, out nextHeader, out transOff))
        {
            // Undecipherable (ESP, truncated, or chain too deep) — emit addresses only.
            return PacketFormatter.FormatNetworkOnly(src + " > " + dst, lineCounter);
        }
        // transOff from FindIPv6UpperLayer is an absolute offset into `data` because we
        // gave it rawOffset+ipv6Off as the starting point and rawOffset+rawLength as the
        // bound. Use it directly below.

        // ICMPv6
        if (nextHeader == 58)
        {
            if (rawOffset + rawLength > transOff)
            {
                int icmpv6Type = data[transOff];
                // NDP types
                if (icmpv6Type >= 133 && icmpv6Type <= 137)
                {
                    string ndpStr = FormatNdpBasic(icmpv6Type);
                    return PacketFormatter.FormatNetworkOnly(src + " > " + dst + ": " + ndpStr, lineCounter);
                }
                if (icmpv6Type == 128 || icmpv6Type == 129)
                {
                    string dir = (icmpv6Type == 128) ? "request" : "reply";
                    return PacketFormatter.FormatNetworkOnly(src + " > " + dst + ": ICMPv6 echo " + dir, lineCounter);
                }
                return PacketFormatter.FormatNetworkOnly(src + " > " + dst + ": ICMPv6 type " + icmpv6Type, lineCounter);
            }
        }
        // TCP/UDP over IPv6
        else if (nextHeader == 6 || nextHeader == 17)
        {
            if (rawOffset + rawLength >= transOff + 4)
            {
                int sp = PacketParseHelper.ReadUInt16BE(data, transOff);
                int dp = PacketParseHelper.ReadUInt16BE(data, transOff + 2);
                string protoName = (nextHeader == 6) ? "TCP" : "UDP";

                // For UDP, try DNS detection
                if (nextHeader == 17 && (sp == 53 || dp == 53 || sp == 5353 || dp == 5353))
                {
                    if (rawOffset + rawLength >= transOff + 8)
                    {
                        int udpDataLen = (rawOffset + rawLength) - transOff - 8;
                        if (udpDataLen > 0)
                        {
                            byte[] udpPayload = new byte[udpDataLen];
                            Buffer.BlockCopy(data, transOff + 8, udpPayload, 0, udpDataLen);
                            string dnsStr = DnsParser.FormatDnsSegment(udpPayload, sp, dp);
                            if (dnsStr != null)
                                return PacketFormatter.FormatTransportLine(src, sp, dst, dp, dnsStr, 4, lineCounter);
                        }
                    }
                }

                return PacketFormatter.FormatTransportLine(src, sp, dst, dp, protoName, 3, lineCounter);
            }
        }

        return PacketFormatter.FormatNetworkOnly(src + " > " + dst, lineCounter);
    }

    private static string FormatArpInternal(byte[] raw, int linkKind)
    {
        return FormatArpInternal(raw, 0, raw == null ? 0 : raw.Length, linkKind);
    }

    // Range-based overload: lets the hot path pass (data, packetOffset, pktLen) without
    // first copying the packet bytes into a fresh byte[].
    private static string FormatArpInternal(byte[] data, int rawOffset, int rawLength, int linkKind)
    {
        // ARP starts at offset 14 for Ethernet
        int offset = (linkKind == 1) ? 14 : 0;
        if (rawLength < offset + 28) return "ARP (truncated)";

        int op = PacketParseHelper.ReadUInt16BE(data, rawOffset + offset + 6);
        string senderIp = PacketParseHelper.FormatIPv4(data, rawOffset + offset + 14);
        string targetIp = PacketParseHelper.FormatIPv4(data, rawOffset + offset + 24);

        if (op == 1) // Request
            return "ARP, Request who-has " + targetIp + " tell " + senderIp;
        if (op == 2) // Reply
            return "ARP, Reply " + senderIp + " is-at " + PacketParseHelper.FormatMac(data, rawOffset + offset + 8);

        return "ARP op " + op;
    }

    // Drop reason/location name lookup (populated from PS enum at module load)
    private static Dictionary<int, string> _dropReasonNames = new Dictionary<int, string>();
    private static Dictionary<int, string> _dropLocationNames = new Dictionary<int, string>();

    /// <summary>
    /// Registers a drop reason name for display formatting.
    /// Called from PS at module load to sync enum values into C#.
    /// </summary>
    public static void RegisterDropReason(int value, string name)
    {
        _dropReasonNames[value] = name;
    }

    /// <summary>
    /// Registers a drop location name for display formatting.
    /// Called from PS at module load to sync enum values into C#.
    /// </summary>
    public static void RegisterDropLocation(int value, string name)
    {
        _dropLocationNames[value] = name;
    }

    private static string FormatDropInternal(int dropReason, int dropLocation, byte[] raw)
    {
        return FormatDropInternal(dropReason, dropLocation, raw, 0, raw == null ? 0 : raw.Length);
    }

    // Range-based overload: lets the hot path pass (data, packetOffset, pktLen).
    private static string FormatDropInternal(int dropReason, int dropLocation, byte[] data, int rawOffset, int rawLength)
    {
        string reasonName;
        if (!_dropReasonNames.TryGetValue(dropReason, out reasonName))
            reasonName = null;

        string locationName;
        if (!_dropLocationNames.TryGetValue(dropLocation, out locationName))
            locationName = null;

        StringBuilder sb = new StringBuilder(128);
        sb.Append("DROP - Reason: ");
        if (reasonName != null) sb.Append(reasonName);
        else sb.Append("Reason_").Append(dropReason);
        sb.Append(" (0x").Append(((uint)dropReason).ToString("X8")).Append("); Location: ");
        if (locationName != null) sb.Append(locationName);
        else sb.Append("Location_").Append(dropLocation);
        sb.Append(" (0x").Append(((uint)dropLocation).ToString("X8")).Append(");");

        if (data != null && rawLength >= 20)
        {
            int version = (data[rawOffset] >> 4) & 0xF;
            if (version == 4 && rawLength >= 20)
            {
                string srcIp = PacketParseHelper.FormatIPv4(data, rawOffset + 12);
                string dstIp = PacketParseHelper.FormatIPv4(data, rawOffset + 16);
                int proto = data[rawOffset + 9];
                int ihl = (data[rawOffset] & 0xF) * 4;
                if ((proto == 6 || proto == 17) && rawLength >= ihl + 4)
                {
                    int sp = PacketParseHelper.ReadUInt16BE(data, rawOffset + ihl);
                    int dp = PacketParseHelper.ReadUInt16BE(data, rawOffset + ihl + 2);
                    sb.Append(" IPv4 src: ").Append(srcIp).Append('.').Append(sp)
                      .Append(", dst: ").Append(dstIp).Append('.').Append(dp);
                }
                else
                {
                    sb.Append(" IPv4 src: ").Append(srcIp).Append(", dst: ").Append(dstIp);
                }
            }
        }

        return sb.ToString();
    }

    private static string FormatNdpBasic(int icmpv6Type)
    {
        switch (icmpv6Type)
        {
            case 133: return "NDP Router Solicitation";
            case 134: return "NDP Router Advertisement";
            case 135: return "NDP Neighbor Solicitation";
            case 136: return "NDP Neighbor Advertisement";
            case 137: return "NDP Redirect";
            default: return "NDP type " + icmpv6Type;
        }
    }

    // HTTP port detection
    private static bool IsHttpPort(int port)
    {
        return port == 80 || port == 8080 || port == 8000 || port == 8888;
    }

    // TLS port detection
    private static bool IsTlsPort(int port)
    {
        return port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 || port == 636;
    }

    // True when a TCP src/dst pair could match an app-layer detector (SMB2/HTTP/TLS).
    // Used to skip the per-packet transport-payload allocation when no detector will use it.
    private static bool NeedsTcpPayload(int srcPort, int dstPort)
    {
        if (srcPort == 445 || dstPort == 445) return true;
        if (IsHttpPort(srcPort) || IsHttpPort(dstPort)) return true;
        if (IsTlsPort(srcPort) || IsTlsPort(dstPort)) return true;
        return false;
    }

    // True when a UDP src/dst pair could match an app-layer detector (DNS/mDNS/DHCPv4/DHCPv6).
    private static bool NeedsUdpPayload(int srcPort, int dstPort)
    {
        if (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353) return true;
        if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) return true;
        if (srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547) return true;
        return false;
    }

    private static string DetectHttpContent(byte[] data, int dataLen, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4) return null;

        // Check for HTTP response: "HTTP"
        if (data[0] == 0x48 && data[1] == 0x54 && data[2] == 0x54 && data[3] == 0x50)
        {
            // Extract status line
            int end = Math.Min(data.Length, 32);
            for (int i = 4; i < end; i++)
            {
                if (data[i] == 0x0D || data[i] == 0x0A)
                {
                    end = i;
                    break;
                }
            }
            return System.Text.Encoding.ASCII.GetString(data, 0, end);
        }

        // Check for HTTP methods
        string method = DetectHttpMethod(data);
        if (method != null)
        {
            // Extract first line (method + path)
            int end = Math.Min(data.Length, 64);
            for (int i = 0; i < end; i++)
            {
                if (data[i] == 0x0D || data[i] == 0x0A)
                {
                    end = i;
                    break;
                }
            }
            return System.Text.Encoding.ASCII.GetString(data, 0, end);
        }

        return null;
    }

    private static string DetectHttpMethod(byte[] data)
    {
        if (data == null || data.Length < 3) return null;
        // GET
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data.Length > 3 && data[3] == ' ') return "GET";
        // POST
        if (data.Length >= 4 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return "POST";
        // PUT
        if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data.Length > 3 && data[3] == ' ') return "PUT";
        // DELETE
        if (data.Length >= 6 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L') return "DELETE";
        // HEAD
        if (data.Length >= 4 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return "HEAD";
        return null;
    }

    private static string DetectTlsContent(byte[] data, int dataLen)
    {
        if (data == null || data.Length < 5) return null;
        int contentType = data[0];
        if (contentType < 20 || contentType > 23) return null;
        int major = data[1];
        int minor = data[2];
        if (major != 3 || minor > 4) return null;

        string typeName;
        switch (contentType)
        {
            case 20: typeName = "ChangeCipherSpec"; break;
            case 21: typeName = "Alert"; break;
            case 22: typeName = "Handshake"; break;
            case 23: typeName = "ApplicationData"; break;
            default: typeName = "Type" + contentType; break;
        }

        int ver = (major << 8) | minor;
        string verName;
        switch (ver)
        {
            case 0x0301: verName = "TLS 1.0"; break;
            case 0x0302: verName = "TLS 1.1"; break;
            case 0x0303: verName = "TLS 1.2"; break;
            case 0x0304: verName = "TLS 1.3"; break;
            default: verName = "TLS " + major + "." + minor; break;
        }

        // For Handshake, try to identify the handshake type
        if (contentType == 22 && data.Length >= 6)
        {
            int hsType = data[5];
            string hsName;
            switch (hsType)
            {
                case 1: hsName = "ClientHello"; break;
                case 2: hsName = "ServerHello"; break;
                case 11: hsName = "Certificate"; break;
                case 12: hsName = "ServerKeyExchange"; break;
                case 14: hsName = "ServerHelloDone"; break;
                case 16: hsName = "ClientKeyExchange"; break;
                case 20: hsName = "Finished"; break;
                default: hsName = null; break;
            }
            if (hsName != null)
                return verName + " " + hsName;
        }

        return verName + " " + typeName + ", len " + dataLen;
    }

    private static string DetectTcpApp(int srcPort, int dstPort, byte[] data, int dataLen)
    {
        // SMB2 (port 445)
        if (srcPort == 445 || dstPort == 445)
        {
            if (Smb2Parser.IsSmb2Packet(data, srcPort, dstPort))
            {
                string smb = Smb2Parser.FormatSmb2Segment(data, srcPort, dstPort);
                if (smb != null) return smb;
            }
        }
        if (IsHttpPort(srcPort) || IsHttpPort(dstPort))
        {
            string http = DetectHttpContent(data, dataLen, srcPort, dstPort);
            if (http != null) return http;
        }
        if (IsTlsPort(srcPort) || IsTlsPort(dstPort))
        {
            string tls = DetectTlsContent(data, dataLen);
            if (tls != null) return tls;
        }
        return "";
    }

    private static string DetectUdpApp(int srcPort, int dstPort, byte[] data)
    {
        if (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353)
        {
            string dns = DnsParser.FormatDnsSegment(data, srcPort, dstPort);
            if (dns != null) return dns;
        }
        if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68 ||
            srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547)
        {
            string dhcp = FormatDhcpBasic(data, srcPort, dstPort);
            if (dhcp != null) return dhcp;
        }
        return "";
    }

    private static string FormatDhcpBasic(byte[] data, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4) return null;
        // DHCPv6
        if (srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547)
        {
            int msgType = data[0];
            string typeName;
            switch (msgType)
            {
                case 1: typeName = "Solicit"; break;
                case 2: typeName = "Advertise"; break;
                case 3: typeName = "Request"; break;
                case 7: typeName = "Reply"; break;
                case 11: typeName = "Information-request"; break;
                default: typeName = "type " + msgType; break;
            }
            return "DHCPv6 " + typeName;
        }
        // DHCPv4 - minimum 240 bytes for valid DHCP
        if (data.Length < 240) return null;
        int op = data[0];
        string opName = (op == 1) ? "Discover/Request" : (op == 2) ? "Offer/Ack" : "op" + op;
        return "DHCP " + opName;
    }

    private static int GetWifiPayloadOffset(byte[] raw)
    {
        return GetWifiPayloadOffset(raw, 0, raw == null ? 0 : raw.Length);
    }

    // Range-based overload: avoids needing a slice byte[] for the per-packet WiFi probe.
    private static int GetWifiPayloadOffset(byte[] data, int rawOffset, int rawLength)
    {
        // Simplified: typical QoS Data frame payload starts at offset ~36.
        // For accurate offset, we'd need to parse 802.11 header which is done in PS.
        if (data == null || rawLength < 26) return 14;
        int fc = data[rawOffset] | (data[rawOffset + 1] << 8);
        int type = (fc >> 2) & 0x3;
        int subtype = (fc >> 4) & 0xF;
        bool hasQoS = (type == 2 && (subtype & 0x08) != 0);
        int offset = 24;
        if (hasQoS) offset += 2;
        bool hasHT = ((fc >> 10) & 1) == 1;
        if (hasHT) offset += 2;
        // Skip LLC/SNAP header (8 bytes)
        offset += 8;
        return offset;
    }

    private static string DetectTcpAppDetailed(int srcPort, int dstPort, byte[] data)
    {
        if (data == null || data.Length == 0)
            return null;

        if ((srcPort == 445 || dstPort == 445) && Smb2Parser.IsSmb2Packet(data, srcPort, dstPort))
            return Smb2Parser.FormatSmb2Detailed(data, srcPort, dstPort);

        if (LooksLikeHttp(data))
            return FormatHttpDetailed(data);

        if (LooksLikeTls(data))
            return FormatTlsDetailed(data);

        return null;
    }

    private static string DetectUdpAppDetailed(int srcPort, int dstPort, byte[] data)
    {
        if (data == null || data.Length == 0)
            return null;

        if (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353)
            return DnsParser.FormatDnsSegment(data, srcPort, dstPort);

        if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68 ||
            srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547)
            return FormatDhcpDetailed(data, srcPort, dstPort);

        return null;
    }

    private static bool LooksLikeHttp(byte[] data)
    {
        if (data == null || data.Length < 4)
            return false;

        if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') return true;
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return true;
        if (data.Length >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') return true;
        if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return true;
        if (data.Length >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ') return true;
        if (data.Length >= 5 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E') return true;
        if (data.Length >= 5 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I') return true;
        if (data.Length >= 5 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C') return true;
        return false;
    }

    private static string FormatHttpDetailed(byte[] data)
    {
        if (data == null || data.Length == 0)
            return null;

        int textLen = Math.Min(data.Length, 1024);
        string text = Encoding.ASCII.GetString(data, 0, textLen);
        string[] lines = text.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None);
        if (lines.Length == 0 || string.IsNullOrEmpty(lines[0]))
            return null;

        StringBuilder sb = new StringBuilder(128);
        sb.Append("HTTP - ");
        sb.Append(lines[0].TrimEnd('\0'));

        AppendHttpHeader(sb, lines, "Host");
        AppendHttpHeader(sb, lines, "Content-Type");
        AppendHttpHeader(sb, lines, "Content-Length");
        return sb.ToString();
    }

    private static void AppendHttpHeader(StringBuilder sb, string[] lines, string name)
    {
        string prefix = name + ":";
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            if (string.IsNullOrEmpty(line))
                break;
            if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("; ");
                sb.Append(name);
                sb.Append(": ");
                sb.Append(line.Substring(prefix.Length).Trim());
                return;
            }
        }
    }

    private static bool LooksLikeTls(byte[] data)
    {
        if (data == null || data.Length < 5)
            return false;
        int contentType = data[0];
        if (contentType < 20 || contentType > 23)
            return false;
        int version = (data[1] << 8) | data[2];
        return version >= 0x0300 && version <= 0x0304;
    }

    private static string FormatTlsDetailed(byte[] data)
    {
        if (!LooksLikeTls(data))
            return null;

        int contentType = data[0];
        int version = (data[1] << 8) | data[2];
        int recordLen = PacketParseHelper.ReadUInt16BE(data, 3);
        string versionName = GetTlsVersionName(version);

        if (contentType == 22 && data.Length >= 6)
        {
            string handshakeName = GetTlsHandshakeName(data[5]);
            if (handshakeName != null)
            {
                StringBuilder sb = new StringBuilder(96);
                sb.Append("TLS ");
                sb.Append(handshakeName);
                sb.Append("; ver: ");
                sb.Append(versionName);
                sb.Append("; len: ");
                sb.Append(recordLen.ToString());
                if (data[5] == 1)
                {
                    string sni = ExtractTlsSni(data);
                    if (!string.IsNullOrEmpty(sni))
                    {
                        sb.Append("; SNI: ");
                        sb.Append(sni);
                    }
                }
                return sb.ToString();
            }
        }

        return "TLS " + GetTlsContentTypeName(contentType) + "; ver: " + versionName + "; len: " + recordLen.ToString();
    }

    private static string ExtractTlsSni(byte[] data)
    {
        if (data == null || data.Length < 43 || data[0] != 22 || data[5] != 1)
            return null;

        int recordLen = PacketParseHelper.ReadUInt16BE(data, 3);
        int recordEnd = Math.Min(data.Length, 5 + recordLen);
        int pos = 9;
        if (recordEnd < pos + 34)
            return null;

        pos += 2;
        pos += 32;
        if (pos >= recordEnd)
            return null;

        int sessionIdLen = data[pos];
        pos += 1;
        if (pos + sessionIdLen + 2 > recordEnd)
            return null;
        pos += sessionIdLen;

        int cipherLen = PacketParseHelper.ReadUInt16BE(data, pos);
        pos += 2;
        if (pos + cipherLen + 1 > recordEnd)
            return null;
        pos += cipherLen;

        int compressionLen = data[pos];
        pos += 1;
        if (pos + compressionLen + 2 > recordEnd)
            return null;
        pos += compressionLen;

        int extLen = PacketParseHelper.ReadUInt16BE(data, pos);
        pos += 2;
        int extEnd = Math.Min(recordEnd, pos + extLen);

        while (pos + 4 <= extEnd)
        {
            int extType = PacketParseHelper.ReadUInt16BE(data, pos);
            int itemLen = PacketParseHelper.ReadUInt16BE(data, pos + 2);
            pos += 4;
            if (pos + itemLen > extEnd)
                break;

            if (extType == 0 && itemLen >= 5)
            {
                int listLen = PacketParseHelper.ReadUInt16BE(data, pos);
                int listPos = pos + 2;
                int listEnd = Math.Min(pos + itemLen, listPos + listLen);
                while (listPos + 3 <= listEnd)
                {
                    int nameType = data[listPos];
                    int nameLen = PacketParseHelper.ReadUInt16BE(data, listPos + 1);
                    listPos += 3;
                    if (listPos + nameLen > listEnd)
                        break;
                    if (nameType == 0)
                        return Encoding.ASCII.GetString(data, listPos, nameLen);
                    listPos += nameLen;
                }
            }

            pos += itemLen;
        }

        return null;
    }

    private static string FormatDhcpDetailed(byte[] data, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4)
            return null;

        if (srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547)
        {
            int msgType = data[0];
            int txid = (data[1] << 16) | (data[2] << 8) | data[3];
            return "DHCPv6 " + GetDhcpV6MessageTypeName(msgType) + " - txid: 0x" + txid.ToString("x6");
        }

        if (data.Length < 240)
            return null;

        uint xid = PacketParseHelper.ReadUInt32BE(data, 4);
        string chaddr = PacketParseHelper.FormatMac(data, 28);
        string msgName = (data[0] == 1) ? "Request" : (data[0] == 2) ? "Reply" : "op " + data[0].ToString();
        if (data.Length >= 244 && data[236] == 0x63 && data[237] == 0x82 && data[238] == 0x53 && data[239] == 0x63)
        {
            int pos = 240;
            while (pos < data.Length)
            {
                int code = data[pos++];
                if (code == 0)
                    continue;
                if (code == 255)
                    break;
                if (pos >= data.Length)
                    break;
                int len = data[pos++];
                if (pos + len > data.Length)
                    break;
                if (code == 53 && len >= 1)
                {
                    msgName = GetDhcpV4MessageTypeName(data[pos]);
                    break;
                }
                pos += len;
            }
        }

        return "DHCP " + msgName + " - xid: 0x" + xid.ToString("x8") + "; chaddr: " + chaddr;
    }

    private static string GetDhcpV4MessageTypeName(int msgType)
    {
        switch (msgType)
        {
            case 1: return "Discover";
            case 2: return "Offer";
            case 3: return "Request";
            case 4: return "Decline";
            case 5: return "Ack";
            case 6: return "Nak";
            case 7: return "Release";
            case 8: return "Inform";
            default: return "type " + msgType.ToString();
        }
    }

    private static string GetDhcpV6MessageTypeName(int msgType)
    {
        switch (msgType)
        {
            case 1: return "Solicit";
            case 2: return "Advertise";
            case 3: return "Request";
            case 4: return "Confirm";
            case 5: return "Renew";
            case 7: return "Reply";
            case 11: return "Information-request";
            default: return "type " + msgType.ToString();
        }
    }

    private static string GetDscpName(int dscp)
    {
        switch (dscp)
        {
            case 0: return "BE";
            case 10: return "AF11";
            case 12: return "AF12";
            case 14: return "AF13";
            case 18: return "AF21";
            case 20: return "AF22";
            case 22: return "AF23";
            case 26: return "AF31";
            case 28: return "AF32";
            case 30: return "AF33";
            case 34: return "AF41";
            case 36: return "AF42";
            case 38: return "AF43";
            case 46: return "EF";
            case 48: return "CS6";
            case 56: return "CS7";
            default: return dscp.ToString();
        }
    }

    private static string GetProtocolName(byte protocol)
    {
        switch (protocol)
        {
            case 1: return "ICMP";
            case 2: return "IGMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 47: return "GRE";
            case 50: return "ESP";
            case 58: return "ICMPv6";
            default: return protocol.ToString();
        }
    }

    private static string GetIpv4FlagsText(byte flags)
    {
        bool df = (flags & 0x40) != 0;
        bool mf = (flags & 0x20) != 0;
        if (df && mf) return "DF,MF";
        if (df) return "DF";
        if (mf) return "MF";
        return "none";
    }

    private static string FormatIPv6Address(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 16)
            return string.Empty;
        byte[] addr = new byte[16];
        Buffer.BlockCopy(data, offset, addr, 0, 16);
        return new System.Net.IPAddress(addr).ToString();
    }

    private static string GetTlsVersionName(int version)
    {
        switch (version)
        {
            case 0x0300: return "SSL 3.0";
            case 0x0301: return "TLS 1.0";
            case 0x0302: return "TLS 1.1";
            case 0x0303: return "TLS 1.2";
            case 0x0304: return "TLS 1.3";
            default: return "0x" + version.ToString("x4");
        }
    }

    private static string GetTlsContentTypeName(int contentType)
    {
        switch (contentType)
        {
            case 20: return "ChangeCipherSpec";
            case 21: return "Alert";
            case 22: return "Handshake";
            case 23: return "ApplicationData";
            default: return "type " + contentType.ToString();
        }
    }

    private static string GetTlsHandshakeName(int handshakeType)
    {
        switch (handshakeType)
        {
            case 1: return "ClientHello";
            case 2: return "ServerHello";
            case 11: return "Certificate";
            case 12: return "ServerKeyExchange";
            case 14: return "ServerHelloDone";
            case 16: return "ClientKeyExchange";
            case 20: return "Finished";
            default: return null;
        }
    }

    // =========================================================================
    // BULK FORMAT: Parse + format a batch of raw PSPacketData in pure C#.
    // Eliminates ALL per-packet PowerShell overhead.
    // =========================================================================

    /// <summary>
    /// Result from FormatBatch: formatted output + statistics.
    /// </summary>
    public class BatchResult
    {
        public string Output;
        public int PacketCount;
        public int DroppedCount;
        public int LineCounter;
        /// <summary>0 = no trigger, 1 = pause triggered, 2 = stop triggered.</summary>
        public int TriggerAction;
    }

    // Drop trigger configuration (set from PS before capture loop)
    private static bool _stopOnDrop = false;
    private static bool _pauseOnDrop = false;
    private static int _stopOnReason = 0;
    private static int _stopOnLocation = 0;
    private static int _pauseOnReason = 0;
    private static int _pauseOnLocation = 0;

    /// <summary>
    /// Configures drop triggers for the C# bulk-format path.
    /// Pass 0 for reason/location values to disable that trigger.
    /// </summary>
    public static void SetDropTriggers(bool stopOnDrop, bool pauseOnDrop,
        int stopOnReason, int stopOnLocation, int pauseOnReason, int pauseOnLocation)
    {
        _stopOnDrop = stopOnDrop;
        _pauseOnDrop = pauseOnDrop;
        _stopOnReason = stopOnReason;
        _stopOnLocation = stopOnLocation;
        _pauseOnReason = pauseOnReason;
        _pauseOnLocation = pauseOnLocation;
    }

    /// <summary>Returns true if any drop trigger is configured.</summary>
    public static bool HasDropTriggers()
    {
        return _stopOnDrop || _pauseOnDrop ||
               _stopOnReason != 0 || _stopOnLocation != 0 ||
               _pauseOnReason != 0 || _pauseOnLocation != 0;
    }

    /// <summary>
    /// Formats a batch of raw PSPacketData into a single ready-to-write string.
    /// Performs all packet parsing (metadata, Ethernet, IPv4, TCP/UDP/ICMP) and
    /// line formatting in C# without any PowerShell round-trips.
    /// 
    /// Returns a BatchResult containing the formatted output and statistics.
    /// The caller should update its line counter and packet/drop counts.
    /// </summary>
    /// <param name="buffer">Array of PSPacketData from ring buffer drain.</param>
    /// <param name="count">Number of valid items in buffer.</param>
    /// <param name="startLineCounter">Starting line counter value.</param>
    /// <returns>BatchResult with output string and stats, or null if no output.</returns>
    public static BatchResult FormatBatch(PSPacketData[] buffer, int count, int startLineCounter)
    {
        if (buffer == null || count <= 0) return null;

        // Use the thread-static batch SB instead of allocating per drain cycle. The
        // estimated capacity (count * 120) keeps amortized growth cheap for the common
        // case where this is the first call on the thread or the cap has been resized
        // downward by GC pressure.
        var sb = BatchSb(count * 120);
        int lineCounter = startLineCounter;
        int droppedCount = 0;
        int triggerAction = 0;
        bool checkTriggers = _stopOnDrop || _pauseOnDrop ||
                             _stopOnReason != 0 || _stopOnLocation != 0 ||
                             _pauseOnReason != 0 || _pauseOnLocation != 0;

        for (int i = 0; i < count; i++)
        {
            lineCounter++;
            // Snapshot the buffer position so we can roll back on skip. FormatSinglePacketInto
            // (and its inner *Into helpers) may append a partial line before deciding to bail
            // — they leave whatever they wrote in place and return false; we truncate.
            int lenBefore = sb.Length;
            if (FormatSinglePacketInto(sb, ref buffer[i], lineCounter))
            {
                sb.Append('\n');
            }
            else if (sb.Length > lenBefore)
            {
                sb.Length = lenBefore;
            }

            // Walk metadata once per packet for: (1) seen-component-ID tracking, moved
            // off the producer callback to avoid a per-packet lock; and (2) drop counts /
            // drop-trigger checks. Single read, single bounds check, both on the consumer
            // thread.
            int metaOffset = (int)buffer[i].MetadataOffset;
            // Use DataSize (valid length) instead of Data.Length to avoid reading pool slack.
            byte[] mdata = buffer[i].Data;
            if (mdata != null && (int)buffer[i].DataSize >= metaOffset + 30)
            {
                // Inline LE UInt16 read for component ID — avoids BitConverter and a
                // method-call frame per packet.
                int compId = mdata[metaOffset + 16] | (mdata[metaOffset + 17] << 8);
                if (compId != 0) PktMonApi.NoteComponentId(compId);

                int dropReason = (int)BitConverter.ToUInt32(mdata, metaOffset + 22);
                if (dropReason != 0)
                {
                    droppedCount++;

                    if (checkTriggers)
                    {
                        int dropLocation = (int)BitConverter.ToUInt32(mdata, metaOffset + 26);

                        // Stop triggers — highest priority
                        if (_stopOnDrop ||
                            (_stopOnReason != 0 && dropReason == _stopOnReason) ||
                            (_stopOnLocation != 0 && dropLocation == _stopOnLocation))
                        {
                            triggerAction = 2;
                            break;
                        }

                        // Pause triggers
                        if (triggerAction == 0 &&
                            (_pauseOnDrop ||
                             (_pauseOnReason != 0 && dropReason == _pauseOnReason) ||
                             (_pauseOnLocation != 0 && dropLocation == _pauseOnLocation)))
                        {
                            triggerAction = 1;
                            // Continue formatting remaining packets in this batch before pausing
                        }
                    }
                }
            }
        }

        // Materializing sb to a string here is unavoidable — Console.Write(SB) is not
        // available on .NET Framework 4.x. The materialized string is then handed to the
        // caller, which passes it straight to [Console]::Write.
        return new BatchResult
        {
            Output = sb.Length > 0 ? sb.ToString() : null,
            PacketCount = count,
            DroppedCount = droppedCount,
            LineCounter = lineCounter,
            TriggerAction = triggerAction
        };
    }

    /// <summary>
    /// Parse and format a single PSPacketData into a display line.
    /// All parsing (metadata extraction, Ethernet, IPv4, transport) done in C#.
    /// Appends the formatted output directly into <paramref name="batchSb"/>.
    /// Returns true if a line was emitted; false on skip — caller is responsible
    /// for truncating batchSb back to its pre-call Length if false is returned
    /// (the inner *Into helpers may have appended partial content).
    /// </summary>
    private static bool FormatSinglePacketInto(StringBuilder batchSb, ref PSPacketData pkt, int lineCounter)
    {
        byte[] data = pkt.Data;
        // Use the packet's valid DataSize (not Data.Length) to avoid leaking pool slack
        // when Data is an oversized buffer rented from PacketBytePool.
        int pktDataSize = (int)pkt.DataSize;
        if (data == null || pktDataSize < 14) return false;

        int metaOffset = (int)pkt.MetadataOffset;
        int packetOffset = (int)pkt.PacketOffset;

        // --- Extract metadata ---
        int compId = 0, edgeId = 0, dropReason = 0, dropLocation = 0;
        int packetType = 0; // 0=Ethernet, 1=WiFi
        long metaTimestamp = 0;

        if (pktDataSize >= metaOffset + 40)
        {
            compId = BitConverter.ToUInt16(data, metaOffset + 16);
            edgeId = BitConverter.ToUInt16(data, metaOffset + 18);
            dropReason = (int)BitConverter.ToUInt32(data, metaOffset + 22);
            dropLocation = (int)BitConverter.ToUInt32(data, metaOffset + 26);
            packetType = BitConverter.ToUInt16(data, metaOffset + 14);
            metaTimestamp = BitConverter.ToInt64(data, metaOffset + 32);
        }

        // --- Compute timestamp ---
        long streamTimestamp;
        if (pkt.QpcTimestamp != 0)
        {
            streamTimestamp = PktMonApi.QpcToFiletime(pkt.QpcTimestamp);
        }
        else
        {
            streamTimestamp = metaTimestamp;
        }

        // --- Extract raw packet bytes ---
        int pktLen = pktDataSize - packetOffset;
        if (pktLen < 14) return false;

        // Treat (data, packetOffset, pktLen) as our packet "view". The previous code copied
        // these bytes into a fresh byte[] every packet so downstream parsers could use
        // raw.Length safely — that copy is now eliminated. Downstream calls use the range
        // overloads that take (rawPacketData, rawOffset, rawLength) so they index into the
        // original source array without ever walking into pool slack or metadata bytes.
        byte[] raw = data;
        int rawOffset = packetOffset;
        int rawLength = pktLen;

        // --- Determine link layer offset and EtherType ---
        int linkKind = 0;
        string srcMac = null, dstMac = null;
        int etherType = 0;
        int ipOffset = 14; // default Ethernet header length

        if (packetType == 4) // WiFi
        {
            linkKind = 2;
            ipOffset = GetWifiPayloadOffset(raw, rawOffset, rawLength);
            if (rawLength > ipOffset + 2)
            {
                etherType = (raw[rawOffset + ipOffset - 2] << 8) | raw[rawOffset + ipOffset - 1]; // last 2 bytes before payload are EtherType in LLC/SNAP
                // Actually for WiFi with LLC/SNAP, EtherType is at offset-2 before payload
                // Re-read: LLC/SNAP has 0xAA 0xAA 0x03 + 3 OUI + 2 EtherType before payload
                int snapEtherOffset = ipOffset - 2;
                if (snapEtherOffset >= 0 && rawLength > snapEtherOffset + 1)
                    etherType = (raw[rawOffset + snapEtherOffset] << 8) | raw[rawOffset + snapEtherOffset + 1];
            }
        }
        else // Ethernet (default)
        {
            linkKind = 1;
            // Only format MAC addresses for Default mode (Minimal doesn't display them)
            if (_detailLevel >= 0)
            {
                srcMac = PacketParseHelper.FormatMac(raw, rawOffset + 6);
                dstMac = PacketParseHelper.FormatMac(raw, rawOffset + 0);
            }
            etherType = (raw[rawOffset + 12] << 8) | raw[rawOffset + 13];
            if (etherType == 0x8100) // VLAN
            {
                if (rawLength >= 18)
                {
                    etherType = (raw[rawOffset + 16] << 8) | raw[rawOffset + 17];
                    ipOffset = 18;
                }
            }
        }

        // --- Parse IPv4 if EtherType 0x0800 ---
        int protoKind = 0;
        string srcAddr = null, dstAddr = null;
        int srcPort = 0, dstPort = 0;
        byte tcpFlags = 0;
        uint tcpSeq = 0, tcpAck = 0;
        ushort tcpWin = 0;
        int dataLen = 0;
        int icmpType = 0, icmpCode = 0, icmpId = 0, icmpSeq = 0;
        byte[] transportPayload = null;
        byte ipTos = 0;
        int ipTotalLength = 0;
        ushort ipId = 0;
        byte ipFlags = 0;
        byte ipTtl = 0;
        byte ipProtocol = 0;
        int transportOffset = -1;
        int tcpDataOffset = 0;

        if (etherType == 0x0800 && rawLength > ipOffset + 20)
        {
            byte versionIHL = raw[rawOffset + ipOffset];
            if ((versionIHL >> 4) == 4) // IPv4
            {
                int ihl = (versionIHL & 0x0F) * 4;
                int totalLength = (raw[rawOffset + ipOffset + 2] << 8) | raw[rawOffset + ipOffset + 3];
                int protocol = raw[rawOffset + ipOffset + 9];
                ipTos = raw[rawOffset + ipOffset + 1];
                ipTotalLength = totalLength;
                ipId = (ushort)((raw[rawOffset + ipOffset + 4] << 8) | raw[rawOffset + ipOffset + 5]);
                ipFlags = raw[rawOffset + ipOffset + 6];
                ipTtl = raw[rawOffset + ipOffset + 8];
                ipProtocol = (byte)protocol;
                srcAddr = PacketParseHelper.FormatIPv4(raw, rawOffset + ipOffset + 12);
                dstAddr = PacketParseHelper.FormatIPv4(raw, rawOffset + ipOffset + 16);

                transportOffset = ipOffset + ihl;
                int transportLen = Math.Min(totalLength - ihl, rawLength - transportOffset);
                if (transportLen < 0) transportLen = 0;

                switch (protocol)
                {
                    case 1: // ICMP
                        protoKind = 1;
                        if (transportLen >= 8)
                        {
                            icmpType = raw[rawOffset + transportOffset];
                            icmpCode = raw[rawOffset + transportOffset + 1];
                            icmpId = (raw[rawOffset + transportOffset + 4] << 8) | raw[rawOffset + transportOffset + 5];
                            icmpSeq = (raw[rawOffset + transportOffset + 6] << 8) | raw[rawOffset + transportOffset + 7];
                            dataLen = transportLen - 8;
                        }
                        break;

                    case 6: // TCP
                        protoKind = 2;
                        if (transportLen >= 20)
                        {
                            srcPort = (raw[rawOffset + transportOffset] << 8) | raw[rawOffset + transportOffset + 1];
                            dstPort = (raw[rawOffset + transportOffset + 2] << 8) | raw[rawOffset + transportOffset + 3];
                            if (_detailLevel >= 0)
                            {
                                // Default mode needs seq/ack/win/flags for TCP segment display
                                tcpSeq = PacketParseHelper.ReadUInt32BE(raw, rawOffset + transportOffset + 4);
                                tcpAck = PacketParseHelper.ReadUInt32BE(raw, rawOffset + transportOffset + 8);
                                tcpFlags = raw[rawOffset + transportOffset + 13];
                                tcpWin = PacketParseHelper.ReadUInt16BE(raw, rawOffset + transportOffset + 14);
                                tcpDataOffset = (raw[rawOffset + transportOffset + 12] >> 4) * 4;
                                dataLen = Math.Max(0, transportLen - tcpDataOffset);
                                // Only allocate the transport payload if an app-layer detector
                                // (SMB2/HTTP/TLS) can actually consume it. Saves a per-packet
                                // BlockCopy of the full TCP payload for the vast majority of
                                // traffic that doesn't hit a known port.
                                if (dataLen > 0 && NeedsTcpPayload(srcPort, dstPort))
                                {
                                    int payloadStart = transportOffset + tcpDataOffset;
                                    if (payloadStart < rawLength)
                                    {
                                        int copyLen = Math.Min(dataLen, rawLength - payloadStart);
                                        transportPayload = new byte[copyLen];
                                        Buffer.BlockCopy(raw, rawOffset + payloadStart, transportPayload, 0, copyLen);
                                    }
                                }
                            }
                            // Minimal mode: ports only, skip everything else
                        }
                        break;

                    case 17: // UDP
                        protoKind = 3;
                        if (transportLen >= 8)
                        {
                            srcPort = (raw[rawOffset + transportOffset] << 8) | raw[rawOffset + transportOffset + 1];
                            dstPort = (raw[rawOffset + transportOffset + 2] << 8) | raw[rawOffset + transportOffset + 3];
                            dataLen = Math.Max(0, transportLen - 8);
                            // Only allocate the transport payload for Default mode AND when
                            // a UDP app-layer detector (DNS/mDNS/DHCP) might consume it.
                            if (_detailLevel >= 0 && dataLen > 0 && transportOffset + 8 < rawLength
                                && NeedsUdpPayload(srcPort, dstPort))
                            {
                                int copyLen = Math.Min(dataLen, rawLength - transportOffset - 8);
                                transportPayload = new byte[copyLen];
                                Buffer.BlockCopy(raw, rawOffset + transportOffset + 8, transportPayload, 0, copyLen);
                            }
                        }
                        break;

                    default:
                        protoKind = 4;
                        break;
                }
            }
        }

        if (_detailLevel == -1)
        {
            // Display-side ICMP fallback (WiFi packets only — Ethernet is handled at the
            // producer level in PacketDataCallBack).
            if ((_icmpEchoOnly || _icmpNdpOnly) && IsIcmpFiltered(etherType, protoKind, icmpType, raw, rawOffset, rawLength, ipOffset))
            {
                return false;
            }
            return FormatMinimalLineInto(batchSb,
                lineCounter, streamTimestamp,
                compId, edgeId, dropReason, dropLocation,
                linkKind, etherType, rawLength,
                protoKind, srcAddr, dstAddr,
                srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin,
                dataLen,
                icmpType, icmpCode, icmpId, icmpSeq,
                transportPayload, raw, rawOffset, rawLength);
        }
        if (_detailLevel >= 1)
        {
            if ((_icmpEchoOnly || _icmpNdpOnly) && IsIcmpFiltered(etherType, protoKind, icmpType, raw, rawOffset, rawLength, ipOffset))
            {
                return false;
            }
            return FormatDetailedLineInto(batchSb,
                lineCounter, streamTimestamp,
                compId, edgeId, dropReason, dropLocation,
                linkKind, srcMac, dstMac, etherType, rawLength,
                protoKind, srcAddr, dstAddr,
                srcPort, dstPort,
                tcpFlags, tcpSeq, tcpAck, tcpWin,
                dataLen,
                icmpType, icmpCode, icmpId, icmpSeq,
                transportPayload, raw, rawOffset, rawLength,
                ipTos, ipTotalLength, ipId, ipFlags, ipTtl, ipProtocol,
                ipOffset, transportOffset, tcpDataOffset);
        }

        if ((_icmpEchoOnly || _icmpNdpOnly) && IsIcmpFiltered(etherType, protoKind, icmpType, raw, rawOffset, rawLength, ipOffset))
        {
            return false;
        }
        return FormatDefaultLineInto(batchSb,
            lineCounter, streamTimestamp,
            compId, edgeId, dropReason, dropLocation,
            linkKind, srcMac, dstMac, etherType, rawLength,
            protoKind, srcAddr, dstAddr,
            srcPort, dstPort,
            tcpFlags, tcpSeq, tcpAck, tcpWin,
            dataLen,
            icmpType, icmpCode, icmpId, icmpSeq,
            transportPayload, raw, rawOffset, rawLength);
    }

    /// <summary>
    /// Returns true if this packet should be dropped by the ICMP display filter
    /// (used to implement -Ping echo-only and -NDP types-133..137-only behavior).
    /// Assumes caller has already verified at least one of _icmpEchoOnly/_icmpNdpOnly is true.
    /// Non-ICMP packets always pass (returns false).
    /// </summary>
    private static bool IsIcmpFiltered(int etherType, int protoKind, int icmpType, byte[] raw, int ipOffset)
    {
        return IsIcmpFiltered(etherType, protoKind, icmpType, raw, 0, raw == null ? 0 : raw.Length, ipOffset);
    }

    // Range-based overload: lets the hot path pass (data, packetOffset, pktLen) without
    // first copying the packet bytes into a fresh byte[].
    private static bool IsIcmpFiltered(int etherType, int protoKind, int icmpType, byte[] raw, int rawOffset, int rawLength, int ipOffset)
    {
        // IPv4 ICMP: protoKind == 1 means ICMP was identified in the IPv4 switch.
        if (etherType == 0x0800 && protoKind == 1)
        {
            // Echo request (8) / Echo reply (0) — only pass if echoOnly is active.
            bool isEcho = (icmpType == 0 || icmpType == 8);
            return !(_icmpEchoOnly && isEcho);
        }

        // IPv6 ICMPv6: walk extension headers to find the ICMPv6 type byte.
        if (etherType == 0x86DD && raw != null && rawLength >= ipOffset + 40)
        {
            int upperProto, upperOff;
            // Absolute coordinates: pass rawOffset+ipOffset as IPv6 header start and
            // rawOffset+rawLength as the valid-bytes bound; upperOff is then absolute too.
            if (PacketParseHelper.FindIPv6UpperLayer(raw, rawOffset + ipOffset, rawOffset + rawLength, out upperProto, out upperOff)
                && upperProto == 58 && rawOffset + rawLength > upperOff)
            {
                int icmpv6Type = raw[upperOff];
                bool isEcho = (icmpv6Type == 128 || icmpv6Type == 129);
                bool isNdp = (icmpv6Type >= 133 && icmpv6Type <= 137);
                bool keep = (_icmpEchoOnly && isEcho) || (_icmpNdpOnly && isNdp);
                return !keep;
            }
        }

        // Non-ICMP packet — filter doesn't apply.
        return false;
    }
}
