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
        public long Seq;      // -1 = empty slot
        public byte[] Packet; // copy of the packet bytes (no metadata)
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
    /// Stores a copy of the packet bytes for sequence <paramref name="seq"/>. The copy is
    /// exactly <paramref name="length"/> bytes taken from <paramref name="data"/> at
    /// <paramref name="offset"/>.
    /// </summary>
    public void Store(long seq, byte[] data, int offset, int length, int compId, int edgeId, int direction)
    {
        if (data == null || length <= 0 || offset < 0 || offset + length > data.Length) return;
        int slot = (int)((seq % _capacity + _capacity) % _capacity);
        byte[] copy = new byte[length];
        Buffer.BlockCopy(data, offset, copy, 0, length);
        _ring[slot].Seq = seq;
        _ring[slot].Packet = copy;
        _ring[slot].CompId = compId;
        _ring[slot].EdgeId = edgeId;
        _ring[slot].Direction = direction;
    }

    /// <summary>
    /// Retrieves the retained packet for <paramref name="seq"/>. Returns false when that
    /// sequence has been evicted (scrolled beyond the retention window) or was never stored.
    /// </summary>
    public bool TryGet(long seq, out byte[] packet, out int compId, out int edgeId, out int direction)
    {
        int slot = (int)((seq % _capacity + _capacity) % _capacity);
        if (_ring[slot].Seq == seq && _ring[slot].Packet != null)
        {
            packet = _ring[slot].Packet;
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

    /// <summary>Clears all retained packets.</summary>
    public void Clear()
    {
        for (int i = 0; i < _capacity; i++)
        {
            _ring[i].Seq = -1;
            _ring[i].Packet = null;
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
        eth.AddLeaf("Source: " + srcMac);
        eth.AddLeaf("Destination: " + dstMac);
        eth.AddLeaf("Type: " + etherName + " (0x" + etherType.ToString("x4") + ")");
        eth.AddLeaf("Length: " + length);
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

        return roots;
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
            int dataOff = (p[off + 12] >> 4) * 4;
            byte flags = p[off + 13];
            int win = PacketParseHelper.ReadUInt16BE(p, off + 14);
            int payloadLen = Math.Max(0, len - dataOff);

            var tcp = new BoxyBox.TreeNode("TCP", "TCP", true);
            tcp.AddLeaf("Src: " + sp);
            tcp.AddLeaf("Dst: " + dp);
            tcp.AddLeaf("Seq: " + seq);
            tcp.AddLeaf("Ack: " + ack);
            tcp.AddLeaf("Flags: " + TcpFlags(flags));
            tcp.AddLeaf("Window: " + win);
            tcp.AddLeaf("len: " + payloadLen);
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
            DnsContext ctx;
            if (DnsParser.TryParseDns(payload, len, sp, dp, out ctx))
            {
                var dns = new BoxyBox.TreeNode(ctx.IsMdns ? "mDNS" : "DNS", "DNS", true);
                dns.AddLeaf("Transaction: 0x" + ctx.TxId.ToString("x4"));
                dns.AddLeaf("Type: " + (ctx.Qr == 0 ? "Query" : "Response"));
                if (ctx.Qr == 0)
                {
                    dns.AddLeaf("Query: " + DnsParser.GetTypeName(ctx.QType) + "? " + ctx.QName);
                }
                else
                {
                    dns.AddLeaf("Rcode: " + DnsParser.GetRcodeName(ctx.Rcode));
                    dns.AddLeaf("Counts: " + ctx.AnCount + "/" + ctx.NsCount + "/" + ctx.ArCount);
                    if (ctx.FirstAnswer != null) dns.AddLeaf("Answer: " + ctx.FirstAnswer);
                }
                roots.Add(dns);
            }
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

    private static string TcpFlags(byte flags)
    {
        var sb = new StringBuilder(16);
        if ((flags & 0x02) != 0) sb.Append("S");
        if ((flags & 0x10) != 0) sb.Append("A");
        if ((flags & 0x01) != 0) sb.Append("F");
        if ((flags & 0x04) != 0) sb.Append("R");
        if ((flags & 0x08) != 0) sb.Append("P");
        if ((flags & 0x20) != 0) sb.Append("U");
        return sb.Length == 0 ? "none" : sb.ToString();
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
