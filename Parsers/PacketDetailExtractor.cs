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
/// packet is silently evicted when a slot is reused.
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
        byte[] copy = new byte[dataSize];
        Buffer.BlockCopy(data, 0, copy, 0, dataSize);
        _ring[slot].Seq = seq;
        _ring[slot].Data = copy;
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
            case "mDNS":      return 4; // LAYER_APPLICATION
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

        string header = "[" + dirArrow + "]" + parentName + " [" + parentId.ToString("D3") + "]:"
                      + "[" + edgeArrow + "]" + (name ?? compId.ToString()) + " [" + compId.ToString("D3") + "]";

        var node = new BoxyBox.TreeNode(header, "Component", false);
        if (!string.IsNullOrEmpty(group)) node.AddLeaf("Group: " + group);
        node.AddLeaf("Component: " + (name ?? compId.ToString()) + " (" + compId + ")");
        node.AddLeaf("Edge: " + EdgeName(edgeId));
        node.AddLeaf("Direction: " + DirectionName(direction));
        return node;
    }

    private static BoxyBox.TreeNode BuildArpNode(byte[] p, int off, int len)
    {
        var arp = new BoxyBox.TreeNode("ARP", "ARP", true);
        if (len < off + 28) { arp.AddLeaf("(truncated)"); return arp; }
        int op = PacketParseHelper.ReadUInt16BE(p, off + 6);
        string senderMac = PacketParseHelper.FormatMac(p, off + 8);
        string senderIp = PacketParseHelper.FormatIPv4(p, off + 14);
        string targetMac = PacketParseHelper.FormatMac(p, off + 18);
        string targetIp = PacketParseHelper.FormatIPv4(p, off + 24);
        arp.AddLeaf("Operation: " + (op == 1 ? "Request" : op == 2 ? "Reply" : op.ToString()));
        arp.AddLeaf("Sender MAC: " + senderMac);
        arp.AddLeaf("Sender IP: " + senderIp);
        arp.AddLeaf("Target MAC: " + targetMac);
        arp.AddLeaf("Target IP: " + targetIp);
        return arp;
    }

    private static void BuildIPv4(byte[] p, int off, int len, List<BoxyBox.TreeNode> roots)
    {
        if (len < off + 20) { roots.Add(new BoxyBox.TreeNode("IPv4 (truncated)", "IPv4", true)); return; }
        int ihl = (p[off] & 0x0F) * 4;
        int tos = p[off + 1];
        int total = PacketParseHelper.ReadUInt16BE(p, off + 2);
        int id = PacketParseHelper.ReadUInt16BE(p, off + 4);
        int flagsFrag = PacketParseHelper.ReadUInt16BE(p, off + 6);
        int ttl = p[off + 8];
        int proto = p[off + 9];
        string src = PacketParseHelper.FormatIPv4(p, off + 12);
        string dst = PacketParseHelper.FormatIPv4(p, off + 16);

        var ip = new BoxyBox.TreeNode("IPv4", "IPv4", true);
        ip.AddLeaf("Src: " + src);
        ip.AddLeaf("Dst: " + dst);
        ip.AddLeaf("Flags: " + Ipv4Flags((byte)(flagsFrag >> 8)));
        ip.AddLeaf("DSCP: " + DscpName(tos >> 2));
        ip.AddLeaf("len: " + total);
        ip.AddLeaf("TTL: " + ttl);
        ip.AddLeaf("Protocol: " + ProtoName(proto) + " (" + proto + ")");
        ip.AddLeaf("id: 0x" + id.ToString("x4"));
        roots.Add(ip);

        int transOff = off + ihl;
        int transLen = len - transOff;
        BuildTransport(p, transOff, transLen, proto, roots);
    }

    private static void BuildIPv6(byte[] p, int off, int len, List<BoxyBox.TreeNode> roots)
    {
        if (len < off + 40) { roots.Add(new BoxyBox.TreeNode("IPv6 (truncated)", "IPv6", true)); return; }
        int payloadLen = PacketParseHelper.ReadUInt16BE(p, off + 4);
        int hopLimit = p[off + 7];
        string src = PacketParseHelper.FormatIPv6(p, off + 8);
        string dst = PacketParseHelper.FormatIPv6(p, off + 24);

        var ip = new BoxyBox.TreeNode("IPv6", "IPv6", true);
        ip.AddLeaf("Src: " + src);
        ip.AddLeaf("Dst: " + dst);
        ip.AddLeaf("Payload len: " + payloadLen);
        ip.AddLeaf("Hop Limit: " + hopLimit);

        int nextHdr, transOff;
        if (PacketParseHelper.FindIPv6UpperLayer(p, off, len, out nextHdr, out transOff))
        {
            ip.AddLeaf("Next Header: " + ProtoName(nextHdr) + " (" + nextHdr + ")");
            roots.Add(ip);
            BuildTransport(p, transOff, len - transOff, nextHdr, roots);
        }
        else
        {
            ip.AddLeaf("Next Header: " + p[off + 6]);
            roots.Add(ip);
        }
    }

    private static void BuildTransport(byte[] p, int off, int len, int proto, List<BoxyBox.TreeNode> roots)
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

            // Collapsed header carries the one-line summary (tcpdump flags + ports/seq/ack/len).
            var tcp = new BoxyBox.TreeNode(
                "TCP [" + flagStr + "] - Src Port: " + sp + ", Dst Port: " + dp +
                ", Seq: " + seq + ", Ack: " + ack + ", Len: " + payloadLen,
                "TCP", true);
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

            BuildAppNode(p, off + dataOff, payloadLen, sp, dp, false, roots);
        }
        else if (proto == 17 && len >= 8) // UDP
        {
            int sp = PacketParseHelper.ReadUInt16BE(p, off);
            int dp = PacketParseHelper.ReadUInt16BE(p, off + 2);
            int ulen = PacketParseHelper.ReadUInt16BE(p, off + 4);
            int payloadLen = Math.Max(0, ulen - 8);

            var udp = new BoxyBox.TreeNode("UDP", "UDP", true);
            udp.AddLeaf("Src: " + sp);
            udp.AddLeaf("Dst: " + dp);
            udp.AddLeaf("len: " + payloadLen);
            roots.Add(udp);

            BuildAppNode(p, off + 8, Math.Min(payloadLen, len - 8), sp, dp, true, roots);
        }
        else if ((proto == 1 || proto == 58) && len >= 2) // ICMP / ICMPv6
        {
            int type = p[off];
            int code = p[off + 1];
            string label = proto == 1 ? "ICMP" : "ICMPv6";
            var icmp = new BoxyBox.TreeNode(label, label, true);
            icmp.AddLeaf("Type: " + type);
            icmp.AddLeaf("Code: " + code);
            if ((proto == 1 && (type == 0 || type == 8)) || (proto == 58 && (type == 128 || type == 129)))
            {
                if (len >= 8)
                {
                    icmp.AddLeaf("Id: " + PacketParseHelper.ReadUInt16BE(p, off + 4));
                    icmp.AddLeaf("Seq: " + PacketParseHelper.ReadUInt16BE(p, off + 6));
                }
            }
            roots.Add(icmp);
        }
    }

    private static void BuildAppNode(byte[] p, int off, int len, int sp, int dp, bool udp, List<BoxyBox.TreeNode> roots)
    {
        if (len <= 0 || off < 0 || off + len > p.Length) return;

        // Copy the payload once so the app parsers (which take a byte[] starting at offset 0)
        // see a clean buffer.
        byte[] payload = new byte[len];
        Buffer.BlockCopy(p, off, payload, 0, len);

        if (udp && (sp == 53 || dp == 53 || sp == 5353 || dp == 5353))
        {
            List<BoxyBox.TreeNode> dnsRoots = DnsParser.BuildDnsDetailTree(payload, len, sp, dp);
            for (int i = 0; i < dnsRoots.Count; i++) roots.Add(dnsRoots[i]);
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

    private static string Ipv4Flags(byte flagsHigh)
    {
        bool df = (flagsHigh & 0x40) != 0;
        bool mf = (flagsHigh & 0x20) != 0;
        if (df && mf) return "DF,MF";
        if (df) return "DF";
        if (mf) return "MF";
        return "none";
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
