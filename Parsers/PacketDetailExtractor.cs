// PacketDetailExtractor + PacketDetailStore
//
// Supports the BoxyBox Analysis Details box. The scrolling Text Box keeps only formatted
// summary strings, so to render the Wireshark-style detail tree for a *selected* packet we
// must retain that packet's raw bytes and parse them just-in-time on selection.
//
//   * PacketDetailStore  — a bounded ring of raw packet-byte copies keyed by absolute
//                          sequence number (matching TextBox sequencing). Oldest entries are
//                          overwritten once capacity is reached.
//   * PacketDetailExtractor.BuildTree — parses a stored packet into a List<BoxyBox.TreeNode>
//                          (Component + Eth collapsed by default; network/transport/app
//                          expanded), reusing the shared PacketParseHelper primitives.

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Bounded ring buffer of raw packet copies keyed by absolute sequence number. Used by the
/// Analysis Details box to reparse a selected packet on demand. O(1) store/lookup; the oldest
/// packet is silently evicted when a slot is reused. Each slot's backing byte[] is reused (grown
/// on demand) across evictions, so a steady capture allocates nothing per packet after warmup;
/// only the stored valid length (DataSize) is read back and every reader bounds by it. All access
/// is on the single Analysis-loop thread (drain/store, detail navigation, and save are sequential).
/// </summary>
public sealed class PacketDetailStore
{
    private struct Record
    {
        public long Seq;       // -1 = empty slot
        public byte[] Data;    // full descriptor copy (metadata + packet), length = DataSize
        public int DataSize;
        public int MetaOffset;
        public int PktOffset;
        public int PktLength;
        public long Qpc;       // QPC timestamp captured at the pktmon callback
        public int CompId;
        public int EdgeId;
        public int Direction;
    }

    private readonly Record[] _ring;
    private readonly int _capacity;

    public PacketDetailStore(int capacity)
    {
        _capacity = capacity < 16 ? 16 : capacity;
        _ring = new Record[_capacity];
        for (int i = 0; i < _capacity; i++) _ring[i].Seq = -1;
    }

    public int Capacity { get { return _capacity; } }

    /// <summary>
    /// Stores a copy of the full packet descriptor (metadata + packet bytes) for sequence
    /// <paramref name="seq"/>. Retaining the whole descriptor — plus the QPC timestamp and the
    /// metadata/packet offsets — lets the Analysis Details box reparse the packet on demand AND
    /// lets <see cref="WritePcapng"/> emit a faithful pcapng (real timestamps + comments).
    /// </summary>
    public void Store(long seq, byte[] data, int dataSize, int metaOffset, int pktOffset, int pktLength, long qpc, int compId, int edgeId, int direction)
    {
        if (data == null || dataSize <= 0 || dataSize > data.Length) return;
        if (pktOffset < 0 || pktLength <= 0 || pktOffset + pktLength > dataSize) return;
        int slot = (int)((seq % _capacity + _capacity) % _capacity);
        // Reuse the slot's existing buffer when it's large enough. The ring overwrites the oldest
        // packet in this slot regardless, so growing-then-reusing avoids a fresh byte[] (and the
        // garbage from the evicted one) on every store once each slot reaches its high-water size.
        // Only DataSize bytes are valid; every reader (TryGet, WritePcapng -> WritePacketDirect)
        // bounds by DataSize / PktOffset+PktLength, so the oversized tail is never read.
        byte[] buf = _ring[slot].Data;
        if (buf == null || buf.Length < dataSize) buf = new byte[dataSize];
        Buffer.BlockCopy(data, 0, buf, 0, dataSize);
        _ring[slot].Seq = seq;
        _ring[slot].Data = buf;
        _ring[slot].DataSize = dataSize;
        _ring[slot].MetaOffset = metaOffset;
        _ring[slot].PktOffset = pktOffset;
        _ring[slot].PktLength = pktLength;
        _ring[slot].Qpc = qpc;
        _ring[slot].CompId = compId;
        _ring[slot].EdgeId = edgeId;
        _ring[slot].Direction = direction;
    }

    /// <summary>
    /// Retrieves the retained packet bytes (packet only, metadata stripped) for
    /// <paramref name="seq"/>. Returns false when that sequence has been evicted (scrolled
    /// beyond the retention window) or was never stored. Allocates a packet-only slice on
    /// demand — called only when the user navigates to a packet, not on the capture hot path.
    /// </summary>
    public bool TryGet(long seq, out byte[] packet, out int compId, out int edgeId, out int direction)
    {
        int slot = (int)((seq % _capacity + _capacity) % _capacity);
        if (_ring[slot].Seq == seq && _ring[slot].Data != null)
        {
            int off = _ring[slot].PktOffset;
            int len = _ring[slot].PktLength;
            if (off + len > _ring[slot].DataSize) len = _ring[slot].DataSize - off;
            if (len < 0) len = 0;
            byte[] pkt = new byte[len];
            if (len > 0) Buffer.BlockCopy(_ring[slot].Data, off, pkt, 0, len);
            packet = pkt;
            compId = _ring[slot].CompId;
            edgeId = _ring[slot].EdgeId;
            direction = _ring[slot].Direction;
            return true;
        }
        packet = null;
        compId = 0;
        edgeId = 0;
        direction = 0;
        return false;
    }

    /// <summary>
    /// Writes every currently retained packet (oldest sequence first) to a pcapng file at
    /// <paramref name="path"/>, reusing the same serialization as a live -WriteFile capture
    /// (real QPC timestamps + per-packet metadata comments). Returns the number of packets
    /// written. Retention is bounded by <see cref="Capacity"/>, so only the most recent
    /// packets are saved.
    /// </summary>
    public int WritePcapng(string path)
    {
        // Snapshot valid records, ordered by ascending sequence (oldest first).
        List<Record> recs = new List<Record>(_capacity);
        for (int i = 0; i < _capacity; i++)
        {
            if (_ring[i].Seq >= 0 && _ring[i].Data != null) recs.Add(_ring[i]);
        }
        if (recs.Count == 0) return 0;
        recs.Sort(delegate (Record a, Record b) { return a.Seq.CompareTo(b.Seq); });

        PcapngWriter writer = new PcapngWriter();
        // Enrich packet comments with component names where the formatter knows them.
        HashSet<int> registered = new HashSet<int>();
        for (int i = 0; i < recs.Count; i++)
        {
            int cid = recs[i].CompId;
            if (cid != 0 && registered.Add(cid))
            {
                string name, group; int parentId;
                if (PacketLineFormatter.TryGetComponentInfo(cid, out name, out parentId, out group))
                {
                    writer.RegisterComponent(cid, name, group, parentId);
                }
            }
        }

        // Synchronous mode (no writer thread): WritePacket serializes immediately.
        writer.Start(path, false, 0, false);
        int written = 0;
        try
        {
            for (int i = 0; i < recs.Count; i++)
            {
                Record r = recs[i];
                PSPacketData p = new PSPacketData(r.Data, (uint)r.DataSize, (uint)r.MetaOffset,
                    (uint)r.PktOffset, (uint)r.PktLength, 0, 0);
                p.QpcTimestamp = r.Qpc;
                writer.WritePacket(p);
                written++;
            }
        }
        finally
        {
            writer.Stop();
        }
        return written;
    }

    /// <summary>Clears all retained packets.</summary>
    public void Clear()
    {
        for (int i = 0; i < _capacity; i++)
        {
            _ring[i].Seq = -1;
            _ring[i].Data = null;
        }
    }
}

/// <summary>
/// Builds a Wireshark-style detail tree (<see cref="BoxyBox.TreeNode"/>) for a single packet.
/// Component and Ethernet nodes are collapsed by default; network/transport/application nodes
/// are expanded. Each node carries a stable Key (protocol name) so the Details box can persist
/// expand/collapse state across packets.
/// </summary>
public static class PacketDetailExtractor
{
    /// <summary>
    /// Parses <paramref name="packet"/> (an Ethernet or 802.11-less Ethernet frame starting at
    /// offset 0) into a list of top-level detail nodes.
    /// </summary>
    public static List<BoxyBox.TreeNode> BuildTree(byte[] packet, int length, int compId, int edgeId, int direction)
    {
        var roots = new List<BoxyBox.TreeNode>();
        if (packet == null || length < 14)
        {
            var bad = new BoxyBox.TreeNode("(packet too short to parse)", "Error", true);
            roots.Add(bad);
            return roots;
        }

        roots.Add(BuildComponentNode(compId, edgeId, direction));

        // --- Ethernet ---
        string dstMac = PacketParseHelper.FormatMac(packet, 0);
        string srcMac = PacketParseHelper.FormatMac(packet, 6);
        int etherType = PacketParseHelper.ReadUInt16BE(packet, 12);
        string etherName = EtherName(etherType);

        var eth = new BoxyBox.TreeNode(
            "Eth: " + srcMac + " > " + dstMac + ", type " + etherName + ", len " + length,
            "Eth", false);
        // Aligned labels (value column at 12) per Ethernet_parser_instructions.md.
        eth.AddLeaf("Source:".PadRight(12) + " " + srcMac);
        eth.AddLeaf("Destination:".PadRight(12) + " " + dstMac);
        eth.AddLeaf("Type:".PadRight(12) + " " + etherName + " (0x" + etherType.ToString("x4") + ")");
        eth.AddLeaf("Length:".PadRight(12) + " " + length);
        roots.Add(eth);

        int ipOffset = 14;

        if (etherType == 0x0806)
        {
            roots.Add(BuildArpNode(packet, ipOffset, length));
        }
        else if (etherType == 0x0800)
        {
            BuildIPv4(packet, ipOffset, length, roots);
        }
        else if (etherType == 0x86DD)
        {
            BuildIPv6(packet, ipOffset, length, roots);
        }

        // Colorize each section (header + children) by its protocol layer so the Details box
        // matches the parsing color scheme. Component=0, DataLink=1, Network=2, Transport=3,
        // Application=4 (see PacketFormatter layer indices).
        for (int i = 0; i < roots.Count; i++)
        {
            ColorizeSubtree(roots[i], LayerForKey(roots[i].Key));
        }

        return roots;
    }

    /// <summary>Maps a section key to its parsing-color layer index (-1 = no color).</summary>
    private static int LayerForKey(string key)
    {
        switch (key)
        {
            case "Component": return 0; // LAYER_COMPONENT
            case "Eth":       return 1; // LAYER_DATALINK
            case "IPv4":
            case "IPv6":
            case "ARP":       return 2; // LAYER_NETWORK
            case "TCP":
            case "UDP":
            case "ICMP":
            case "ICMPv6":    return 3; // LAYER_TRANSPORT
            case "DNS":
            case "mDNS":
            case "DHCP":
            case "HTTP":
            case "SMB2":
            case "TLS":        return 4; // LAYER_APPLICATION
            default:          return -1;
        }
    }

    /// <summary>Recursively wraps a node and its children in the given layer's color.</summary>
    private static void ColorizeSubtree(BoxyBox.TreeNode node, int layer)
    {
        if (node == null || layer < 0) return;
        node.Text = PacketFormatter.ColorizeByIndex(node.Text, layer, 0);
        if (node.Children != null)
        {
            for (int i = 0; i < node.Children.Count; i++)
            {
                ColorizeSubtree(node.Children[i], layer);
            }
        }
    }

    private static BoxyBox.TreeNode BuildComponentNode(int compId, int edgeId, int direction)
    {
        string name; int parentId; string group;
        if (!PacketLineFormatter.TryGetComponentInfo(compId, out name, out parentId, out group))
        {
            name = compId.ToString();
            parentId = 0;
            group = null;
        }
        string parentName;
        int pn; string pg;
        if (parentId == 0) parentName = "Root";
        else if (PacketLineFormatter.TryGetComponentInfo(parentId, out parentName, out pn, out pg)) { }
        else parentName = parentId.ToString();

        string dirArrow = (direction == 1 || direction == 3 || direction == 5) ? "\u2191"
                        : (direction == 2 || direction == 4 || direction == 6) ? "\u2193" : " ";
        string edgeArrow = (edgeId == 1) ? "\u2192" : (edgeId == 2) ? "\u2190" : " ";
        string dirBracket = "[" + dirArrow + "]";
        string edgeBracket = "[" + edgeArrow + "]";

        string groupName = !string.IsNullOrEmpty(group) ? group : parentName;
        string compName = name ?? compId.ToString();

        // Header: [dir]Group Name (Group ID):[edge]Component Name (Component ID)
        string header = dirBracket + groupName + " (" + parentId + "):"
                      + edgeBracket + compName + " (" + compId + ")";

        var node = new BoxyBox.TreeNode(header, "Component", false);
        node.AddLeaf("Direction".PadRight(9) + " : " + DirectionName(direction) + " " + dirBracket);
        node.AddLeaf("Group".PadRight(9) + " : " + groupName + " (" + parentId + ")");
        node.AddLeaf("Component".PadRight(9) + " : " + compName + " (" + compId + ")");
        node.AddLeaf("Edge".PadRight(9) + " : " + EdgeName(edgeId) + " " + edgeBracket);
        return node;
    }

    private static BoxyBox.TreeNode BuildArpNode(byte[] p, int off, int len)
    {
        if (len < off + 28)
        {
            var t = new BoxyBox.TreeNode("ARP", "ARP", true);
            t.AddLeaf("(truncated)");
            return t;
        }
        int op = PacketParseHelper.ReadUInt16BE(p, off + 6);
        string senderMac = PacketParseHelper.FormatMac(p, off + 8);
        string senderIp = PacketParseHelper.FormatIPv4(p, off + 14);
        string targetMac = PacketParseHelper.FormatMac(p, off + 18);
        string targetIp = PacketParseHelper.FormatIPv4(p, off + 24);

        // Collapsed header matches the Default one-liner. The reply advertises the sender's
        // IP -> MAC mapping (tcpdump-style), so it reads "Reply <senderIp> is-at <senderMac>".
        string header;
        if (op == 1) header = "ARP, Request who-has " + targetIp + " tell " + senderIp;
        else if (op == 2) header = "ARP, Reply " + senderIp + " is-at " + senderMac;
        else header = "ARP op " + op;

        var arp = new BoxyBox.TreeNode(header, "ARP", true);
        arp.AddLeaf("Operation".PadRight(10) + " : " + (op == 1 ? "Request" : op == 2 ? "Reply" : op.ToString()));
        arp.AddLeaf("Sender MAC".PadRight(10) + " : " + senderMac);
        arp.AddLeaf("Sender IP".PadRight(10) + " : " + senderIp);
        arp.AddLeaf("Target MAC".PadRight(10) + " : " + targetMac);
        arp.AddLeaf("Target IP".PadRight(10) + " : " + targetIp);
        return arp;
    }

    private static void BuildIPv4(byte[] p, int off, int len, List<BoxyBox.TreeNode> roots)
    {
        if (len < off + 20) { roots.Add(new BoxyBox.TreeNode("IPv4 (truncated)", "IPv4", true)); return; }
        int verIhlByte = p[off];
        int ihlWords = verIhlByte & 0x0F;
        int ihl = ihlWords * 4;
        int tos = p[off + 1];
        int dscp = tos >> 2;
        int ecn = tos & 0x3;
        int total = PacketParseHelper.ReadUInt16BE(p, off + 2);
        int id = PacketParseHelper.ReadUInt16BE(p, off + 4);
        int flagsFrag = PacketParseHelper.ReadUInt16BE(p, off + 6);
        byte flagsHigh = (byte)(flagsFrag >> 8);
        int fragOffset = flagsFrag & 0x1FFF;
        int ttl = p[off + 8];
        int proto = p[off + 9];
        int checksum = PacketParseHelper.ReadUInt16BE(p, off + 10);
        string src = PacketParseHelper.FormatIPv4(p, off + 12);
        string dst = PacketParseHelper.FormatIPv4(p, off + 16);

        // Collapsed by default in Analysis mode; the header carries the Detailed one-liner.
        var ip = new BoxyBox.TreeNode("IPv4 - Src: " + src + ", Dst: " + dst, "IPv4", false);
        ip.AddLeaf(RenderBits(verIhlByte, 8, "BBBB ....") + " = Version: 4");
        ip.AddLeaf(RenderBits(verIhlByte, 8, ".... BBBB") + " = Header Length: " + ihl + " bytes (" + ihlWords + ")");
        ip.AddLeaf("DSCP: " + DscpName(dscp) + ", ECN: " + (ecn != 0 ? "ECT" : "Not-ECT"));
        ip.AddLeaf("Total Length: " + total);
        ip.AddLeaf("Identification: 0x" + id.ToString("x4") + " (" + id + ")");

        string flagNames = Ipv4FlagNames(flagsHigh);
        var flags = new BoxyBox.TreeNode(
            RenderBits(flagsHigh, 8, "BBB. ....") + " = Flags: 0x" + (flagsHigh & 0xE0).ToString("x2")
                + (flagNames.Length > 0 ? ", " + flagNames : ""),
            "IPv4.Flags", false);
        flags.AddLeaf(RenderBits(flagsHigh, 8, "0... ....") + " = Reserved bit: Not set");
        flags.AddLeaf(RenderBits(flagsHigh, 8, ".B.. ....") + " = Don't fragment: " + SetState((flagsHigh & 0x40) != 0));
        flags.AddLeaf(RenderBits(flagsHigh, 8, "..B. ....") + " = More fragments: " + SetState((flagsHigh & 0x20) != 0));
        ip.Add(flags);

        ip.AddLeaf(RenderBits(flagsFrag, 16, "...B BBBB BBBB BBBB") + " = Fragment Offset: " + fragOffset);
        ip.AddLeaf("Time to Live: " + ttl);
        ip.AddLeaf("Protocol: " + ProtoName(proto) + " (" + proto + ")");
        ip.AddLeaf("Header Checksum: 0x" + checksum.ToString("x4"));
        ip.AddLeaf("Source Address: " + src);
        ip.AddLeaf("Destination Address: " + dst);
        roots.Add(ip);

        int transOff = off + ihl;
        int transLen = len - transOff;
        BuildTransport(p, transOff, transLen, proto, src, dst, roots);
    }

    private static void BuildIPv6(byte[] p, int off, int len, List<BoxyBox.TreeNode> roots)
    {
        if (len < off + 40) { roots.Add(new BoxyBox.TreeNode("IPv6 (truncated)", "IPv6", true)); return; }
        uint firstWord = PacketParseHelper.ReadUInt32BE(p, off);
        int trafficClass = (int)((firstWord >> 20) & 0xFF);
        int dscp = trafficClass >> 2;
        int ecn = trafficClass & 0x3;
        int flowLabel = (int)(firstWord & 0xFFFFF);
        int payloadLen = PacketParseHelper.ReadUInt16BE(p, off + 4);
        int hopLimit = p[off + 7];
        string src = PacketParseHelper.FormatIPv6(p, off + 8);
        string dst = PacketParseHelper.FormatIPv6(p, off + 24);

        // Collapsed by default in Analysis mode; the header carries the Detailed one-liner.
        var ip = new BoxyBox.TreeNode("IPv6 - Src: " + src + ", Dst: " + dst, "IPv6", false);
        ip.AddLeaf(RenderBits(p[off], 8, "BBBB ....") + " = Version: 6");

        var tc = new BoxyBox.TreeNode(
            RenderBits((int)firstWord, 32, ".... BBBB BBBB .... .... .... .... ....")
                + " = Traffic Class: 0x" + trafficClass.ToString("x2") + " (" + DscpName(dscp) + ")",
            "IPv6.TrafficClass", false);
        tc.AddLeaf(RenderBits((int)firstWord, 32, ".... BBBB BB.. .... .... .... .... ....")
            + " = Differentiated Services Codepoint: " + DscpName(dscp) + " (" + dscp + ")");
        tc.AddLeaf(RenderBits((int)firstWord, 32, ".... .... ..BB .... .... .... .... ....")
            + " = Explicit Congestion Notification: " + EcnName(ecn) + " (" + ecn + ")");
        ip.Add(tc);

        ip.AddLeaf(RenderBits((int)(firstWord & 0xFFFFFF), 24, ".... BBBB BBBB BBBB BBBB BBBB")
            + " = Flow Label: 0x" + flowLabel.ToString("x5"));
        ip.AddLeaf("Payload Length: " + payloadLen);

        int nextHdr, transOff;
        if (PacketParseHelper.FindIPv6UpperLayer(p, off, len, out nextHdr, out transOff))
        {
            ip.AddLeaf("Next Header: " + ProtoName(nextHdr) + " (" + nextHdr + ")");
            ip.AddLeaf("Hop Limit: " + hopLimit);
            ip.AddLeaf("Source Address: " + src);
            ip.AddLeaf("Destination Address: " + dst);
            roots.Add(ip);
            BuildTransport(p, transOff, len - transOff, nextHdr, src, dst, roots);
        }
        else
        {
            ip.AddLeaf("Next Header: " + ProtoName(p[off + 6]) + " (" + p[off + 6] + ")");
            ip.AddLeaf("Hop Limit: " + hopLimit);
            ip.AddLeaf("Source Address: " + src);
            ip.AddLeaf("Destination Address: " + dst);
            roots.Add(ip);
        }
    }

    private static void BuildTransport(byte[] p, int off, int len, int proto, string src, string dst, List<BoxyBox.TreeNode> roots)
    {
        if (len < 0) len = 0;
        if (proto == 6 && len >= 20) // TCP
        {
            int sp = PacketParseHelper.ReadUInt16BE(p, off);
            int dp = PacketParseHelper.ReadUInt16BE(p, off + 2);
            uint seq = PacketParseHelper.ReadUInt32BE(p, off + 4);
            uint ack = PacketParseHelper.ReadUInt32BE(p, off + 8);
            int offByte = p[off + 12];              // data offset (high nibble) + reserved/AE (low nibble)
            int dataOffWords = offByte >> 4;
            int dataOff = dataOffWords * 4;
            byte flags = p[off + 13];               // 8 standard flags (tcpdump uses this byte)
            int flags12 = ((offByte & 0x0F) << 8) | flags;  // 12-bit flags field (AE + reserved + 8 flags)
            int win = PacketParseHelper.ReadUInt16BE(p, off + 14);
            int checksum = PacketParseHelper.ReadUInt16BE(p, off + 16);
            int urgptr = PacketParseHelper.ReadUInt16BE(p, off + 18);
            int payloadLen = Math.Max(0, len - dataOff);
            string flagStr = PacketParseHelper.FormatTcpFlags(flags);

            // Collapsed by default in Analysis mode; the header carries the one-line summary.
            var tcp = new BoxyBox.TreeNode(
                "TCP [" + flagStr + "] - Src Port: " + sp + ", Dst Port: " + dp +
                ", Seq: " + seq + ", Ack: " + ack + ", Len: " + payloadLen,
                "TCP", false);
            tcp.AddLeaf("Source Port: " + sp);
            tcp.AddLeaf("Destination Port: " + dp);
            tcp.AddLeaf("Sequence Number: " + seq);
            tcp.AddLeaf("Acknowledgment number: " + ack);
            tcp.Add(BuildTcpFlagsNode(offByte, flags));
            tcp.AddLeaf(TcpBits(offByte, "BBBB ....") + " = Header Length: " + dataOff + " bytes (0x" + dataOffWords.ToString("x") + ")");
            tcp.AddLeaf("Window: " + win);
            tcp.AddLeaf("Checksum: 0x" + checksum.ToString("x4"));
            tcp.AddLeaf("Urgent Pointer: " + urgptr);
            tcp.AddLeaf("TCP payload (" + payloadLen + " bytes)");
            roots.Add(tcp);

            BuildAppNode(p, off + dataOff, payloadLen, sp, dp, false, src, dst, roots);
        }
        else if (proto == 17 && len >= 8) // UDP
        {
            int sp = PacketParseHelper.ReadUInt16BE(p, off);
            int dp = PacketParseHelper.ReadUInt16BE(p, off + 2);
            int ulen = PacketParseHelper.ReadUInt16BE(p, off + 4);
            int payloadLen = Math.Max(0, ulen - 8);

            // Collapsed by default in Analysis mode; the header carries the one-line summary.
            var udp = new BoxyBox.TreeNode(
                "UDP - Src Port: " + sp + ", Dst Port: " + dp + ", Len: " + payloadLen,
                "UDP", false);
            udp.AddLeaf("Source Port: " + sp);
            udp.AddLeaf("Destination Port: " + dp);
            udp.AddLeaf("UDP payload (" + payloadLen + ")");
            roots.Add(udp);

            BuildAppNode(p, off + 8, Math.Min(payloadLen, len - 8), sp, dp, true, src, dst, roots);
        }
        else if ((proto == 1 || proto == 58) && len >= 2) // ICMP / ICMPv6
        {
            roots.Add(BuildIcmpNode(p, off, len, proto, src, dst));
        }
    }

    // ---- ICMP / ICMPv6 Details node ----
    // Renders the Analysis Details tree for ICMP (proto 1) and ICMPv6 (proto 58) per the
    // ICMP/ICMPv6 parser specs: Echo gets the full field breakdown, Destination Unreachable
    // gets a code-string breakdown, and ICMPv6 NDP (types 133-137) gets a message + option
    // breakdown. The collapsed header mirrors the Default one-liner.
    private static BoxyBox.TreeNode BuildIcmpNode(byte[] p, int off, int len, int proto, string src, string dst)
    {
        bool v6 = proto == 58;
        string label = v6 ? "ICMPv6" : "ICMP";
        int type = p[off];
        int code = p[off + 1];
        int checksum = len >= 4 ? PacketParseHelper.ReadUInt16BE(p, off + 2) : 0;

        bool isEcho = v6 ? (type == 128 || type == 129) : (type == 0 || type == 8);
        bool isRequest = v6 ? (type == 128) : (type == 8);
        bool isUnreachable = v6 ? (type == 1) : (type == 3);

        if (isEcho)
        {
            int id = len >= 8 ? PacketParseHelper.ReadUInt16BE(p, off + 4) : 0;
            int seq = len >= 8 ? PacketParseHelper.ReadUInt16BE(p, off + 6) : 0;
            int dataLen = Math.Max(0, len - 8);
            string dir = isRequest ? "Request" : "Reply";

            var node = new BoxyBox.TreeNode(
                label + ".Echo " + dir + ": " + src + " > " + dst + ", id " + id + ", seq " + seq,
                label, true);
            node.AddLeaf("Type".PadRight(10) + " : Echo (ping) " + (isRequest ? "request" : "reply") + " (" + type + ")");
            node.AddLeaf("Code".PadRight(10) + " : " + code);
            node.AddLeaf("Checksum".PadRight(10) + " : 0x" + checksum.ToString("x4"));
            node.AddLeaf("Identifier".PadRight(10) + " : " + id + " (0x" + id.ToString("x4") + ")");
            node.AddLeaf("Sequence".PadRight(10) + " : " + seq + " (0x" + seq.ToString("x4") + ")");
            node.AddLeaf("Data (" + dataLen + " bytes)");
            return node;
        }

        if (isUnreachable)
        {
            string codeStr = v6 ? Icmp6UnreachableCode(code) : Icmp4UnreachableCode(code);
            var node = new BoxyBox.TreeNode(
                label + ".Destination Unreachable -  " + codeStr + " (" + code + ")",
                label, true);
            node.AddLeaf("Type".PadRight(10) + " : Destination Unreachable (" + type + ")");
            node.AddLeaf("Code".PadRight(10) + " : " + codeStr + " (" + code + ")");
            node.AddLeaf("Checksum".PadRight(10) + " : 0x" + checksum.ToString("x4"));
            return node;
        }

        if (v6 && type >= 133 && type <= 137)
        {
            return BuildNdpNode(p, off, len, code, checksum, src);
        }

        // Fallback: generic type/code breakdown.
        var generic = new BoxyBox.TreeNode(label + " type " + type + " code " + code, label, true);
        generic.AddLeaf("Type".PadRight(10) + " : " + type);
        generic.AddLeaf("Code".PadRight(10) + " : " + code);
        generic.AddLeaf("Checksum".PadRight(10) + " : 0x" + checksum.ToString("x4"));
        return generic;
    }

    // Builds the ICMPv6 NDP (types 133-137) Details node: the spec one-liner header plus
    // Type/Code/Checksum and the message-specific fields + options extracted by NdpParser.
    private static BoxyBox.TreeNode BuildNdpNode(byte[] p, int off, int len, int code, int checksum, string src)
    {
        int type = p[off];
        string name = NdpTypeName(type);
        string header = NdpParser.FormatNdpSpec(p, off, len, false);
        string targetAddr = (type == 135 || type == 136) && len >= 24 ? PacketParseHelper.FormatIPv6(p, off + 8) : null;

        var node = new BoxyBox.TreeNode(header, "ICMPv6", true);
        node.AddLeaf("Type".PadRight(10) + " : " + name + " (" + type + ")");
        node.AddLeaf("Code".PadRight(10) + " : " + code);
        node.AddLeaf("Checksum".PadRight(10) + " : 0x" + checksum.ToString("x4"));

        if (type == 134 && len >= 16) // Router Advertisement
        {
            byte flags = p[off + 5];
            node.AddLeaf("Cur Hop Limit".PadRight(16) + " : " + p[off + 4]);
            node.AddLeaf("Flags".PadRight(16) + " : M=" + ((flags >> 7) & 1) + " O=" + ((flags >> 6) & 1));
            node.AddLeaf("Router Lifetime".PadRight(16) + " : " + PacketParseHelper.ReadUInt16BE(p, off + 6) + "s");
            node.AddLeaf("Reachable Time".PadRight(16) + " : " + PacketParseHelper.ReadUInt32BE(p, off + 8) + "ms");
            node.AddLeaf("Retrans Timer".PadRight(16) + " : " + PacketParseHelper.ReadUInt32BE(p, off + 12) + "ms");
        }
        else if ((type == 135 || type == 136) && targetAddr != null)
        {
            node.AddLeaf("Target Address : " + targetAddr);
            if (type == 136)
            {
                byte naFlags = p[off + 4];
                node.AddLeaf("Router".PadRight(9) + " : " + SetState(((naFlags >> 7) & 1) != 0));
                node.AddLeaf("Solicited".PadRight(9) + " : " + SetState(((naFlags >> 6) & 1) != 0));
                node.AddLeaf("Override".PadRight(9) + " : " + SetState(((naFlags >> 5) & 1) != 0));
            }
        }

        // NDP options (Prefix/MTU/RDNSS/etc.): rendered as an expandable "Options" node whose
        // header carries the one-liner summary and whose children break out each option.
        List<string> optSegs = NdpOptionSegments(p, off, len);
        if (optSegs.Count > 0)
        {
            var opts = new BoxyBox.TreeNode("Options : " + string.Join(", ", optSegs.ToArray()), "ICMPv6.Options", true);
            for (int i = 0; i < optSegs.Count; i++) opts.AddLeaf(optSegs[i]);
            node.Add(opts);
        }
        return node;
    }

    // Extracts the parsed NDP option segments (Prefix/MTU/RDNSS/DNSSL/Route/etc.) from the
    // NdpParser one-liner, dropping the message-specific fields that are broken out
    // structurally (and the Source/Target Link-layer addresses folded into the header).
    private static List<string> NdpOptionSegments(byte[] p, int off, int len)
    {
        var kept = new List<string>();
        string detail = NdpParser.FormatNdpDetailed(p, off, len);
        if (string.IsNullOrEmpty(detail)) return kept;
        string[] segs = detail.Split(';');
        for (int i = 1; i < segs.Length; i++)
        {
            string seg = segs[i].Trim();
            if (seg.StartsWith("Prefix") || seg.StartsWith("MTU") || seg.StartsWith("RDNSS")
                || seg.StartsWith("DNSSL") || seg.StartsWith("Route") || seg.StartsWith("RedirHdr")
                || seg.StartsWith("Opt"))
            {
                kept.Add(seg);
            }
        }
        return kept;
    }


    private static void BuildAppNode(byte[] p, int off, int len, int sp, int dp, bool udp, string src, string dst, List<BoxyBox.TreeNode> roots)
    {
        if (len <= 0 || off < 0 || off + len > p.Length) return;

        // Copy the payload once so the app parsers (which take a byte[] starting at offset 0)
        // see a clean buffer.
        byte[] payload = new byte[len];
        Buffer.BlockCopy(p, off, payload, 0, len);

        // TLS is content-based (not port-based) and is checked FIRST for TCP so a TLS stream on a
        // port that also matches a port-based parser (e.g. 53/80/445) still parses as TLS. Real
        // HTTP request lines (ASCII) and the SMB2 NetBIOS header (0x00) can't match LooksLikeTls;
        // a DNS-over-TCP length-prefix collision is possible but rare (needs a ~5120-6143 byte
        // message) and affects only the detail dispatch, so the port-based branches keep working.
        // (QUIC embeds TLS 1.3 in its own UDP packet format and SSH is not TLS — neither is
        // handled here; see TLS_parser_instructions.md "Future work".)
        if (!udp && TlsParser.LooksLikeTls(payload, len))
        {
            List<BoxyBox.TreeNode> tlsRoots = TlsParser.BuildTlsDetailTree(payload, len, sp, dp);
            for (int i = 0; i < tlsRoots.Count; i++) roots.Add(tlsRoots[i]);
        }
        else if (sp == 53 || dp == 53 || sp == 5353 || dp == 5353)
        {
            byte[] dnsMsg = payload;
            int dnsLen = len;
            if (!udp)
            {
                // DNS over TCP (RFC 1035 §4.2.2): the DNS message is prefixed by a 2-byte
                // big-endian length. Skip it before parsing. (mDNS/5353 is UDP-only, so only
                // the port-53 case realistically reaches here.)
                if (len < 2) return;
                int msgLen = PacketParseHelper.ReadUInt16BE(payload, 0);
                int avail = len - 2;
                dnsLen = Math.Min(msgLen, avail);
                if (dnsLen <= 0) return;
                dnsMsg = new byte[dnsLen];
                Buffer.BlockCopy(payload, 2, dnsMsg, 0, dnsLen);
            }
            List<BoxyBox.TreeNode> dnsRoots = DnsParser.BuildDnsDetailTree(dnsMsg, dnsLen, sp, dp);
            for (int i = 0; i < dnsRoots.Count; i++) roots.Add(dnsRoots[i]);
        }
        else if (udp && DhcpParser.IsDhcpPort(sp, dp))
        {
            List<BoxyBox.TreeNode> dhcpRoots = DhcpParser.BuildDhcpDetailTree(payload, sp, dp);
            for (int i = 0; i < dhcpRoots.Count; i++) roots.Add(dhcpRoots[i]);
        }
        else if (!udp && (HttpParser.IsHttpPort(sp) || HttpParser.IsHttpPort(dp)))
        {
            List<BoxyBox.TreeNode> httpRoots = HttpParser.BuildHttpDetailTree(payload, HttpParser.BuildConnKey(src, sp, dst, dp));
            for (int i = 0; i < httpRoots.Count; i++) roots.Add(httpRoots[i]);
        }
        else if (!udp && (sp == 445 || dp == 445))
        {
            List<BoxyBox.TreeNode> smbRoots = Smb2Parser.BuildSmb2DetailTree(payload, len, sp, dp, Smb2Parser.ConnKey(src, sp, dst, dp));
            for (int i = 0; i < smbRoots.Count; i++) roots.Add(smbRoots[i]);
        }
    }

    // ---- naming helpers ----

    private static string EtherName(int et)
    {
        switch (et)
        {
            case 0x0800: return "IPv4";
            case 0x0806: return "ARP";
            case 0x86DD: return "IPv6";
            case 0x8100: return "802.1Q";
            default: return "0x" + et.ToString("x4");
        }
    }

    private static string ProtoName(int proto)
    {
        switch (proto)
        {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 58: return "IPv6-ICMP";
            case 2: return "IGMP";
            case 41: return "IPv6";
            case 50: return "ESP";
            case 51: return "AH";
            default: return proto.ToString();
        }
    }

    // Renders a Wireshark-style flag bit line from a template over the 12-bit TCP flags field
    // (bits 11..0 = 3 reserved, AE, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN). A 'B' in the
    // template is replaced by the actual bit at that position (MSB first); '.', digits and
    // spaces are copied verbatim. For the Header Length line the template's 'B's map to the
    // data-offset nibble (the high 4 of the offset byte).
    private static string TcpBits(int offByte, string template)
    {
        // Header Length uses the offset byte's high nibble as the 4 leading bits.
        int value = (offByte >> 4) & 0x0F;
        var sb = new StringBuilder(template.Length);
        int bitIndex = 0;
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == ' ') { sb.Append(' '); continue; }
            if (c == 'B')
            {
                int bit = 3 - bitIndex; // 4-bit nibble, MSB first
                sb.Append(bit >= 0 && ((value >> bit) & 1) == 1 ? '1' : '0');
            }
            else { sb.Append(c); }
            bitIndex++;
        }
        return sb.ToString();
    }

    private static string TcpFlagBits(int flags12, string template)
    {
        var sb = new StringBuilder(template.Length);
        int bitIndex = 0;
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == ' ') { sb.Append(' '); continue; }
            if (c == 'B')
            {
                int bit = 11 - bitIndex; // 12-bit field, MSB first
                sb.Append(bit >= 0 && ((flags12 >> bit) & 1) == 1 ? '1' : '0');
            }
            else { sb.Append(c); }
            bitIndex++;
        }
        return sb.ToString();
    }

    private static string SetState(bool set) { return set ? "Set" : "Not set"; }

    /// <summary>
    /// Renders a Wireshark-style bit line from a template. A 'B' is replaced by the actual
    /// bit at that position (MSB first over <paramref name="totalBits"/> bits, counting only
    /// non-space template slots); '.', digits and spaces are copied verbatim.
    /// </summary>
    private static string RenderBits(int value, int totalBits, string template)
    {
        var sb = new StringBuilder(template.Length);
        int bitIndex = 0;
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == ' ') { sb.Append(' '); continue; }
            if (c == 'B')
            {
                int bit = (totalBits - 1) - bitIndex;
                sb.Append(bit >= 0 && ((value >> bit) & 1) == 1 ? '1' : '0');
            }
            else { sb.Append(c); }
            bitIndex++;
        }
        return sb.ToString();
    }

    /// <summary>Comma-separated human-readable IPv4 flag names (empty when none set).</summary>
    private static string Ipv4FlagNames(byte flagsHigh)
    {
        bool df = (flagsHigh & 0x40) != 0;
        bool mf = (flagsHigh & 0x20) != 0;
        if (df && mf) return "Don't fragment, More fragments";
        if (df) return "Don't fragment";
        if (mf) return "More fragments";
        return "";
    }

    /// <summary>2-bit ECN codepoint name (RFC 3168), used by IPv6 Traffic Class breakdown.</summary>
    private static string EcnName(int ecn)
    {
        switch (ecn & 0x3)
        {
            case 0: return "Not ECN-Capable Transport, Not-ECT";
            case 1: return "ECN Capable Transport(1), ECT(1)";
            case 2: return "ECN Capable Transport(0), ECT(0)";
            default: return "Congestion Experienced, CE";
        }
    }

    /// <summary>ICMPv4 Destination Unreachable code strings (RFC 792 / IANA).</summary>
    internal static string Icmp4UnreachableCode(int code)
    {
        switch (code)
        {
            case 0: return "Destination network unreachable";
            case 1: return "Destination host unreachable";
            case 2: return "Destination protocol unreachable";
            case 3: return "Destination port unreachable";
            case 4: return "Fragmentation required, and DF flag set";
            case 5: return "Source route failed";
            case 6: return "Destination network unknown";
            case 7: return "Destination host unknown";
            case 8: return "Source host isolated";
            case 9: return "Network administratively prohibited";
            case 10: return "Host administratively prohibited";
            case 11: return "Network unreachable for ToS";
            case 12: return "Host unreachable for ToS";
            case 13: return "Communication administratively prohibited";
            case 14: return "Host Precedence Violation";
            case 15: return "Precedence cutoff in effect";
            default: return "Unknown";
        }
    }

    /// <summary>ICMPv6 Destination Unreachable code strings (RFC 4443).</summary>
    internal static string Icmp6UnreachableCode(int code)
    {
        switch (code)
        {
            case 0: return "No route to destination";
            case 1: return "Communication with destination administratively prohibited";
            case 2: return "Beyond scope of source address";
            case 3: return "Address unreachable";
            case 4: return "Port unreachable";
            case 5: return "Source address failed ingress/egress policy";
            case 6: return "Reject route to destination";
            case 7: return "Error in Source Routing Header";
            default: return "Unknown";
        }
    }

    /// <summary>Human-readable ICMPv6 NDP message name (types 133-137).</summary>
    internal static string NdpTypeName(int type)
    {
        switch (type)
        {
            case 133: return "Router Solicitation";
            case 134: return "Router Advertisement";
            case 135: return "Neighbor Solicitation";
            case 136: return "Neighbor Advertisement";
            case 137: return "Redirect";
            default: return "NDP type " + type;
        }
    }

    /// <summary>
    /// Builds the collapsible TCP "Flags" node per the parser spec: a header of
    /// "Flags: 0x[12-bit hex] ([tcpdump flags])" and a Wireshark-style bit breakdown of each
    /// flag. Collapsed by default.
    /// </summary>
    private static BoxyBox.TreeNode BuildTcpFlagsNode(int offByte, byte flags)
    {
        int flags12 = ((offByte & 0x0F) << 8) | flags;
        string tcpdump = PacketParseHelper.FormatTcpFlags(flags);
        var node = new BoxyBox.TreeNode("Flags: 0x" + flags12.ToString("x3") + " (" + tcpdump + ")", "TCP.Flags", false);
        node.AddLeaf(TcpFlagBits(flags12, "000. .... ....") + " = Reserved: Not set");
        node.AddLeaf(TcpFlagBits(flags12, "...B .... ....") + " = Accurate ECN: " + SetState((flags12 & 0x100) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... B... ....") + " = Congestion Window Reduced: " + SetState((flags & 0x80) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... .B.. ....") + " = ECN-Echo: " + SetState((flags & 0x40) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... ..B. ....") + " = Urgent: " + SetState((flags & 0x20) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... ...B ....") + " = Acknowledgment: " + SetState((flags & 0x10) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... .... B...") + " = Push: " + SetState((flags & 0x08) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... .... .B..") + " = Reset: " + SetState((flags & 0x04) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... .... ..B.") + " = Syn: " + SetState((flags & 0x02) != 0));
        node.AddLeaf(TcpFlagBits(flags12, ".... .... ...B") + " = Fin: " + SetState((flags & 0x01) != 0));
        return node;
    }

    private static string DscpName(int dscp)
    {
        switch (dscp)
        {
            case 0: return "BE";
            case 46: return "EF";
            case 8: return "CS1";
            case 16: return "CS2";
            case 24: return "CS3";
            case 32: return "CS4";
            case 40: return "CS5";
            case 48: return "CS6";
            case 56: return "CS7";
            default: return dscp.ToString();
        }
    }

    private static string EdgeName(int edgeId)
    {
        switch (edgeId)
        {
            case 1: return "Ingress";
            case 2: return "Egress";
            default: return edgeId == 0 ? "(unspecified)" : edgeId.ToString();
        }
    }

    private static string DirectionName(int direction)
    {
        switch (direction)
        {
            case 1: return "In";
            case 2: return "Out";
            case 3: return "Rx";
            case 4: return "Tx";
            case 5: return "Ingress";
            case 6: return "Egress";
            default: return "(unspecified)";
        }
    }
}
