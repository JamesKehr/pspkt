// dns.cs - High-performance DNS packet parsing for real-time display.
// Handles name decompression, query/response formatting in tcpdump style.

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Parsed DNS packet snapshot. Populated by <see cref="DnsParser.TryParseDns"/>
/// and consumed both by the formatter (<see cref="DnsParser.FormatDnsFromContext"/>)
/// and by application-layer display predicates (<see cref="DnsAppPredicate"/>).
///
/// Storing parsed fields in a struct (rather than re-parsing for the predicate
/// and again for the formatter) keeps the consumer hot path to a single DNS
/// parse per matching packet.
/// </summary>
public struct DnsContext
{
    /// <summary>True when the DNS header was parsed successfully (>= 12 bytes).</summary>
    public bool   Valid;
    /// <summary>True when the source/dest port indicates mDNS (5353).</summary>
    public bool   IsMdns;
    /// <summary>True when the question section couldn't be fully read (packet truncation).</summary>
    public bool   Truncated;
    /// <summary>DNS transaction ID.</summary>
    public ushort TxId;
    /// <summary>0 = query, 1 = response.</summary>
    public int    Qr;
    /// <summary>Raw 16-bit flags word (host order) for detailed flag breakdowns.</summary>
    public ushort Flags;
    /// <summary>OPCODE (bits 14-11): 0 = standard query, 1 = inverse, 2 = status, 4 = notify, 5 = update.</summary>
    public int    Opcode;
    /// <summary>Authoritative Answer bit (response only).</summary>
    public bool   Aa;
    /// <summary>Truncated bit.</summary>
    public bool   Tc;
    /// <summary>Recursion Desired bit.</summary>
    public bool   Rd;
    /// <summary>Recursion Available bit (response only).</summary>
    public bool   Ra;
    /// <summary>Answer authenticated (AD) bit.</summary>
    public bool   Ad;
    /// <summary>Checking Disabled / non-authenticated data acceptable (CD) bit.</summary>
    public bool   Cd;
    /// <summary>RCODE from the response flags. 0 (NoError) for queries.</summary>
    public int    Rcode;
    /// <summary>First-question QTYPE (e.g. 1 = A, 28 = AAAA). 0 when no question.</summary>
    public int    QType;
    /// <summary>First-question QNAME with trailing dot, e.g. "example.com.".</summary>
    public string QName;
    /// <summary>Question/answer/authority/additional counts.</summary>
    public ushort QdCount;
    /// <summary>Question/answer/authority/additional counts.</summary>
    public ushort AnCount;
    /// <summary>Question/answer/authority/additional counts.</summary>
    public ushort NsCount;
    /// <summary>Question/answer/authority/additional counts.</summary>
    public ushort ArCount;
    /// <summary>Pre-formatted first-answer string (e.g. "host.example.com. A 1.2.3.4"); null if none.</summary>
    public string FirstAnswer;
}

/// <summary>
/// DNS protocol parser. Provides fast C# parsing of DNS headers, name decompression,
/// and tcpdump-style formatting for real-time packet display.
/// </summary>
public static class DnsParser
{
    // DNS record type name lookup.
    private static readonly string[] TypeNames;
    private static readonly string[] RcodeNames = new string[] {
        "NoError", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused"
    };

    static DnsParser()
    {
        TypeNames = new string[258];
        TypeNames[1]   = "A";
        TypeNames[2]   = "NS";
        TypeNames[5]   = "CNAME";
        TypeNames[6]   = "SOA";
        TypeNames[12]  = "PTR";
        TypeNames[15]  = "MX";
        TypeNames[16]  = "TXT";
        TypeNames[28]  = "AAAA";
        TypeNames[33]  = "SRV";
        TypeNames[35]  = "NAPTR";
        TypeNames[41]  = "OPT";
        TypeNames[43]  = "DS";
        TypeNames[46]  = "RRSIG";
        TypeNames[47]  = "NSEC";
        TypeNames[48]  = "DNSKEY";
        TypeNames[65]  = "HTTPS";
        TypeNames[255] = "ANY";
        TypeNames[257] = "CAA";
    }

    /// <summary>
    /// Gets the display name for a DNS record type, or "TYPEn" if unknown.
    /// </summary>
    public static string GetTypeName(int rtype)
    {
        if (rtype >= 0 && rtype < TypeNames.Length && TypeNames[rtype] != null)
            return TypeNames[rtype];
        return "TYPE" + rtype.ToString();
    }

    /// <summary>
    /// Gets the display name for a DNS response code.
    /// </summary>
    public static string GetRcodeName(int rcode)
    {
        if (rcode >= 0 && rcode < RcodeNames.Length)
            return RcodeNames[rcode];
        return "RCODE" + rcode.ToString();
    }

    /// <summary>
    /// Reads a DNS domain name with compression pointer support.
    /// Returns the name string and the number of bytes consumed from the original offset.
    /// </summary>
    public static string ReadName(byte[] data, int offset, out int bytesRead)
    {
        bytesRead = 0;
        if (data == null || offset >= data.Length) return ".";

        StringBuilder sb = new StringBuilder(64);
        int pos = offset;
        bool followed = false;
        int maxIter = 64;

        while (maxIter-- > 0)
        {
            if (pos >= data.Length) break;
            int labelLen = data[pos];

            if (labelLen == 0)
            {
                if (!followed) bytesRead++;
                break;
            }

            // Compression pointer (top 2 bits set).
            if ((labelLen & 0xC0) == 0xC0)
            {
                if (pos + 1 >= data.Length) break;
                int pointer = ((labelLen & 0x3F) << 8) | data[pos + 1];
                if (!followed) bytesRead += 2;
                followed = true;
                pos = pointer;
                continue;
            }

            pos++;
            if (!followed) bytesRead += 1 + labelLen;
            if (pos + labelLen > data.Length) break;

            if (sb.Length > 0) sb.Append('.');
            // Append label chars directly — DNS labels are ASCII-only so
            // (char)byte is sufficient and avoids Encoding.GetString allocation.
            for (int i = 0; i < labelLen; i++)
            {
                byte b = data[pos + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '?');
            }
            pos += labelLen;
        }

        if (sb.Length == 0) return ".";
        sb.Append('.');
        return sb.ToString();
    }

    /// <summary>
    /// Tests whether a UDP port indicates DNS (53) or mDNS (5353).
    /// </summary>
    public static bool IsDnsPort(int srcPort, int dstPort)
    {
        return srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353;
    }

    /// <summary>
    /// Parses a DNS packet payload into a structured <see cref="DnsContext"/>.
    /// Performs header decode, first-question name+type extraction (with compression
    /// pointer support), and — for responses — first-answer formatting.
    /// Returns false when the buffer is too short to contain a DNS header.
    /// On a partial parse (truncated question section), returns true and sets
    /// <see cref="DnsContext.Truncated"/>.
    /// </summary>
    public static bool TryParseDns(byte[] data, int srcPort, int dstPort, out DnsContext ctx)
    {
        return TryParseDns(data, data != null ? data.Length : 0, srcPort, dstPort, out ctx);
    }

    /// <summary>
    /// Overload accepting an explicit data length, allowing callers to pass a reusable
    /// buffer larger than the actual payload without the parser reading past valid bytes.
    /// </summary>
    public static bool TryParseDns(byte[] data, int dataLength, int srcPort, int dstPort, out DnsContext ctx)
    {
        ctx = default(DnsContext);
        if (data == null || dataLength < 12) return false;

        ctx.IsMdns  = (srcPort == 5353 || dstPort == 5353);
        ctx.TxId    = PacketParseHelper.ReadUInt16BE(data, 0);
        ushort flags = PacketParseHelper.ReadUInt16BE(data, 2);
        ctx.Flags   = flags;
        ctx.Qr      = (flags >> 15) & 1;
        ctx.Opcode  = (flags >> 11) & 0xF;
        ctx.Aa      = ((flags >> 10) & 1) == 1;
        ctx.Tc      = ((flags >> 9) & 1) == 1;
        ctx.Rd      = ((flags >> 8) & 1) == 1;
        ctx.Ra      = ((flags >> 7) & 1) == 1;
        ctx.Ad      = ((flags >> 5) & 1) == 1;
        ctx.Cd      = ((flags >> 4) & 1) == 1;
        ctx.Rcode   = flags & 0xF;
        ctx.QdCount = PacketParseHelper.ReadUInt16BE(data, 4);
        ctx.AnCount = PacketParseHelper.ReadUInt16BE(data, 6);
        ctx.NsCount = PacketParseHelper.ReadUInt16BE(data, 8);
        ctx.ArCount = PacketParseHelper.ReadUInt16BE(data, 10);

        int pos = 12;
        if (ctx.QdCount > 0 && pos < dataLength)
        {
            int nameBytes;
            ctx.QName = ReadName(data, pos, out nameBytes);
            pos += nameBytes;
            if (pos + 4 <= dataLength)
            {
                ctx.QType = PacketParseHelper.ReadUInt16BE(data, pos);
                pos += 4; // skip QTYPE + QCLASS
            }
            else
            {
                ctx.Truncated = true;
            }
        }
        else
        {
            ctx.QName = ".";
        }

        // For responses, try to extract the first answer record for display.
        if (ctx.Qr == 1 && ctx.AnCount > 0 && pos < dataLength)
        {
            ctx.FirstAnswer = ExtractFirstAnswer(data, pos);
        }

        ctx.Valid = true;
        return true;
    }

    /// <summary>
    /// Formats a previously parsed <see cref="DnsContext"/> into the compact one-line DNS
    /// summary. <paramref name="detailed"/> selects the Detailed-tier separator ("DNS - ...")
    /// versus the Default-tier separator ("DNS: ..."). Counts are Answer/Authority/Additional.
    /// </summary>
    public static string FormatDnsFromContext(ref DnsContext ctx, bool detailed)
    {
        if (!ctx.Valid) return null;
        string prefix = ctx.IsMdns ? "mDNS" : "DNS";
        string sep = detailed ? " - " : ": ";
        string qTypeName = GetTypeName(ctx.QType);
        string txIdHex = "0x" + ctx.TxId.ToString("x4");
        string counts = ctx.AnCount.ToString() + "/" + ctx.NsCount.ToString() + "/" + ctx.ArCount.ToString();

        if (ctx.Qr == 0)
        {
            // Query: no answer record, so the question type fills the answer-type slot.
            return string.Concat(prefix, sep, txIdHex, " ", counts, " ", ctx.QName, " ", qTypeName);
        }

        string rcodePart = (ctx.Rcode != 0) ? GetRcodeName(ctx.Rcode) + " " : "";
        if (ctx.FirstAnswer != null)
        {
            return string.Concat(prefix, sep, txIdHex, " ", counts, " ", rcodePart, ctx.FirstAnswer);
        }
        return string.Concat(prefix, sep, txIdHex, " ", counts, " ", rcodePart, ctx.QName, " ", qTypeName);
    }

    /// <summary>
    /// Formats a DNS packet payload into the compact one-line summary.
    /// Default:  "DNS: 0x1234 0/0/0 www.example.com. A"
    /// Response: "DNS: 0x1234 1/0/0 www.example.com. A 93.184.216.34"
    /// Returns null if data is too short. <paramref name="detailed"/> uses the "DNS - " separator.
    /// </summary>
    public static string FormatDnsSegment(byte[] data, int srcPort, int dstPort, bool detailed)
    {
        DnsContext ctx;
        if (!TryParseDns(data, srcPort, dstPort, out ctx)) return null;
        return FormatDnsFromContext(ref ctx, detailed);
    }

    /// <summary>Default-tier convenience overload (separator "DNS: ...").</summary>
    public static string FormatDnsSegment(byte[] data, int srcPort, int dstPort)
    {
        return FormatDnsSegment(data, srcPort, dstPort, false);
    }

    // ==================================================================================
    // Analysis Details tree (JIT — built on packet selection, not on the capture hot path)
    // ==================================================================================

    private static readonly string[] OpcodeNames = new string[] {
        "Standard query", "Inverse query", "Server status request", null, "Notify", "Dynamic update"
    };
    private static readonly string[] RcodeDescriptions = new string[] {
        "No error", "Format error", "Server failure", "No such name", "Not implemented", "Refused"
    };

    private static string GetOpcodeName(int op)
    {
        if (op >= 0 && op < OpcodeNames.Length && OpcodeNames[op] != null) return OpcodeNames[op];
        return "Unknown";
    }

    private static string GetRcodeDescription(int rc)
    {
        if (rc >= 0 && rc < RcodeDescriptions.Length) return RcodeDescriptions[rc];
        return "Reply code " + rc.ToString();
    }

    private static string GetClassName(int cls)
    {
        switch (cls & 0x7FFF) // mask off the mDNS cache-flush bit for the name lookup
        {
            case 1:   return "IN";
            case 3:   return "CH";
            case 4:   return "HS";
            case 254: return "NONE";
            case 255: return "ANY";
            default:  return "CLASS" + cls.ToString();
        }
    }

    private static string AsciiString(byte[] data, int off, int length)
    {
        if (length <= 0 || off < 0 || off + length > data.Length) return "";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            byte b = data[off + i];
            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
        }
        return sb.ToString();
    }

    private static string HexDump(byte[] data, int off, int length)
    {
        if (length <= 0 || off < 0 || off + length > data.Length) return "";
        StringBuilder sb = new StringBuilder(length * 3);
        for (int i = 0; i < length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(data[off + i].ToString("x2"));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Renders a Wireshark-style flag bit line from a template: 'B' characters are replaced by
    /// the actual bit value at that position (MSB first, 16 bits over four nibble groups); '.',
    /// '0', '1' and spaces are copied verbatim.
    /// </summary>
    private static string RenderFlagBits(ushort flags, string template)
    {
        StringBuilder sb = new StringBuilder(template.Length);
        int bitIndex = 0;
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == ' ') { sb.Append(' '); continue; }
            if (c == 'B')
            {
                int bit = 15 - bitIndex;
                sb.Append(((flags >> bit) & 1) == 1 ? '1' : '0');
            }
            else
            {
                sb.Append(c);
            }
            bitIndex++;
        }
        return sb.ToString();
    }

    private static BoxyBox.TreeNode BuildFlagsNode(ref DnsContext ctx)
    {
        ushort f = ctx.Flags;
        string flagsHex = "0x" + f.ToString("x4");
        if (ctx.Qr == 0)
        {
            BoxyBox.TreeNode node = new BoxyBox.TreeNode("Flags: " + flagsHex + " Query", "DNS.Flags", false);
            node.AddLeaf(RenderFlagBits(f, "0... .... .... ....") + " = Response: Query");
            node.AddLeaf(RenderFlagBits(f, ".BBB B... .... ....") + " = Opcode: " + GetOpcodeName(ctx.Opcode) + " (" + ctx.Opcode + ")");
            node.AddLeaf(RenderFlagBits(f, ".... ..B. .... ....") + " = Truncated: Message is " + (ctx.Tc ? "truncated" : "not truncated"));
            node.AddLeaf(RenderFlagBits(f, ".... ...B .... ....") + " = Recursion desired: " + (ctx.Rd ? "Do" : "Do not") + " query recursively");
            node.AddLeaf(RenderFlagBits(f, ".... .... .B.. ....") + " = Z: reserved (0)");
            node.AddLeaf(RenderFlagBits(f, ".... .... ...B ....") + " = Non-authenticated data: " + (ctx.Cd ? "Acceptable" : "Unacceptable"));
            return node;
        }

        BoxyBox.TreeNode rnode = new BoxyBox.TreeNode("Flags: " + flagsHex + " Query response, " + GetRcodeDescription(ctx.Rcode), "DNS.Flags", false);
        rnode.AddLeaf(RenderFlagBits(f, "1... .... .... ....") + " = Response: Response");
        rnode.AddLeaf(RenderFlagBits(f, ".BBB B... .... ....") + " = Opcode: " + GetOpcodeName(ctx.Opcode) + " (" + ctx.Opcode + ")");
        rnode.AddLeaf(RenderFlagBits(f, ".... .B.. .... ....") + " = Authoritative: Server " + (ctx.Aa ? "is" : "is not") + " an authority for domain");
        rnode.AddLeaf(RenderFlagBits(f, ".... ..B. .... ....") + " = Truncated: Message " + (ctx.Tc ? "is" : "is not") + " truncated");
        rnode.AddLeaf(RenderFlagBits(f, ".... ...B .... ....") + " = Recursion desired: " + (ctx.Rd ? "Do" : "Do not") + " query recursively");
        rnode.AddLeaf(RenderFlagBits(f, ".... .... B... ....") + " = Recursion available: Server " + (ctx.Ra ? "can" : "cannot") + " do recursive queries");
        rnode.AddLeaf(RenderFlagBits(f, ".... .... .B.. ....") + " = Z: reserved (0)");
        rnode.AddLeaf(RenderFlagBits(f, ".... .... ..B. ....") + " = Answer authenticated: Answer/authority portion " + (ctx.Ad ? "was" : "was not") + " authenticated by the server");
        rnode.AddLeaf(RenderFlagBits(f, ".... .... ...B ....") + " = Non-authenticated data: " + (ctx.Cd ? "Acceptable" : "Unacceptable"));
        rnode.AddLeaf(RenderFlagBits(f, ".... .... .... BBBB") + " = Reply code: " + GetRcodeDescription(ctx.Rcode) + " (" + ctx.Rcode + ")");
        return rnode;
    }

    // Parses a resource record's RDATA into detail leaves and returns a short summary string
    // for the RR node header. Handles the common record types; unknown types fall back to hex.
    private static string ParseRrData(byte[] data, int rtype, int off, int rdlen, List<string> leaves)
    {
        switch (rtype)
        {
            case 1: // A
                if (rdlen >= 4) { string ip = PacketParseHelper.FormatIPv4(data, off); leaves.Add("Address: " + ip); return ip; }
                break;
            case 28: // AAAA
                if (rdlen >= 16) { string ip6 = PacketParseHelper.FormatIPv6(data, off); leaves.Add("Address: " + ip6); return ip6; }
                break;
            case 5: { int nb; string t = ReadName(data, off, out nb); leaves.Add("CNAME: " + t); return t; }
            case 2: { int nb; string t = ReadName(data, off, out nb); leaves.Add("Name Server: " + t); return t; }
            case 12: { int nb; string t = ReadName(data, off, out nb); leaves.Add("Domain Name: " + t); return t; }
            case 15: // MX
                if (rdlen >= 3)
                {
                    int pref = PacketParseHelper.ReadUInt16BE(data, off);
                    int nb; string mx = ReadName(data, off + 2, out nb);
                    leaves.Add("Preference: " + pref);
                    leaves.Add("Mail Exchange: " + mx);
                    return pref + " " + mx;
                }
                break;
            case 16: // TXT (one or more character-strings)
            {
                StringBuilder sb = new StringBuilder();
                int p = off; int end = off + rdlen;
                while (p < end)
                {
                    int l = data[p++];
                    if (p + l > end) break;
                    string s = AsciiString(data, p, l);
                    leaves.Add("TXT: " + s);
                    if (sb.Length > 0) sb.Append(' ');
                    sb.Append(s);
                    p += l;
                }
                return sb.ToString();
            }
            case 6: // SOA
            {
                int nb; string mname = ReadName(data, off, out nb); int p = off + nb;
                int nb2; string rname = ReadName(data, p, out nb2); p += nb2;
                if (p + 20 <= off + rdlen)
                {
                    uint serial  = PacketParseHelper.ReadUInt32BE(data, p);
                    uint refresh = PacketParseHelper.ReadUInt32BE(data, p + 4);
                    uint retry   = PacketParseHelper.ReadUInt32BE(data, p + 8);
                    uint expire  = PacketParseHelper.ReadUInt32BE(data, p + 12);
                    uint minimum = PacketParseHelper.ReadUInt32BE(data, p + 16);
                    leaves.Add("Primary name server: " + mname);
                    leaves.Add("Responsible authority's mailbox: " + rname);
                    leaves.Add("Serial number: " + serial);
                    leaves.Add("Refresh interval: " + refresh);
                    leaves.Add("Retry interval: " + retry);
                    leaves.Add("Expire limit: " + expire);
                    leaves.Add("Minimum TTL: " + minimum);
                    return mname;
                }
                break;
            }
            case 33: // SRV
                if (rdlen >= 7)
                {
                    int prio   = PacketParseHelper.ReadUInt16BE(data, off);
                    int weight = PacketParseHelper.ReadUInt16BE(data, off + 2);
                    int port   = PacketParseHelper.ReadUInt16BE(data, off + 4);
                    int nb; string target = ReadName(data, off + 6, out nb);
                    leaves.Add("Priority: " + prio);
                    leaves.Add("Weight: " + weight);
                    leaves.Add("Port: " + port);
                    leaves.Add("Target: " + target);
                    return target + ":" + port;
                }
                break;
            case 257: // CAA
                if (rdlen >= 2)
                {
                    int caaFlags = data[off];
                    int tagLen = data[off + 1];
                    if (2 + tagLen <= rdlen)
                    {
                        string tag = AsciiString(data, off + 2, tagLen);
                        string value = AsciiString(data, off + 2 + tagLen, rdlen - 2 - tagLen);
                        leaves.Add("Flags: 0x" + caaFlags.ToString("x2"));
                        leaves.Add("Tag: " + tag);
                        leaves.Add("Value: " + value);
                        return tag + " " + value;
                    }
                }
                break;
        }
        // Unknown / unhandled record type: hex dump per the spec's fallback.
        string hex = HexDump(data, off, rdlen);
        leaves.Add("Data: " + hex);
        return rdlen > 0 ? "(" + rdlen + " bytes)" : "";
    }

    // Builds the EDNS0 OPT pseudo-record node (Additional section) per the spec template.
    private static BoxyBox.TreeNode BuildOptNode(byte[] data, string name, int udpSize, uint ttl, int rdlen)
    {
        string dispName = (name == ".") ? "<Root>" : name;
        BoxyBox.TreeNode opt = new BoxyBox.TreeNode(dispName + ": type OPT", null, true);
        opt.AddLeaf("Name: " + dispName);
        opt.AddLeaf("Type: OPT (41)");
        opt.AddLeaf("UDP payload size: " + udpSize);
        int extRcode = (int)((ttl >> 24) & 0xFF);
        int version  = (int)((ttl >> 16) & 0xFF);
        ushort z = (ushort)(ttl & 0xFFFF);
        opt.AddLeaf("Higher bits in extended RCODE: 0x" + extRcode.ToString("x2"));
        opt.AddLeaf("EDNS0 version: " + version);
        BoxyBox.TreeNode zNode = new BoxyBox.TreeNode("Z: 0x" + z.ToString("x4"), null, true);
        bool doBit = ((z >> 15) & 1) == 1;
        zNode.AddLeaf(RenderFlagBits(z, "B... .... .... ....") + " = DO bit: " + (doBit ? "Accepts" : "Does not accept") + " DNSSEC security RRs");
        zNode.AddLeaf(RenderFlagBits(z, ".BBB BBBB BBBB BBBB") + " = Reserved: 0x" + (z & 0x7FFF).ToString("x4"));
        opt.Add(zNode);
        opt.AddLeaf("Data length: " + rdlen);
        return opt;
    }

    // Parses one resource record starting at pos and adds a node to section.
    // Returns the number of bytes consumed, or -1 on a bounds error.
    private static int BuildOneRr(byte[] data, int len, int pos, BoxyBox.TreeNode section)
    {
        int start = pos;
        int nameBytes;
        string name = ReadName(data, pos, out nameBytes);
        pos += nameBytes;
        if (pos + 10 > len) return -1;
        int rtype  = PacketParseHelper.ReadUInt16BE(data, pos);
        int rclass = PacketParseHelper.ReadUInt16BE(data, pos + 2);
        uint ttl   = PacketParseHelper.ReadUInt32BE(data, pos + 4);
        int rdlen  = PacketParseHelper.ReadUInt16BE(data, pos + 8);
        pos += 10;
        if (pos + rdlen > len) return -1;
        int rdOffset = pos;

        if (rtype == 41) // OPT (EDNS0): class = UDP payload size, ttl = extended RCODE/version/Z
        {
            section.Add(BuildOptNode(data, name, rclass, ttl, rdlen));
            return (pos + rdlen) - start;
        }

        string dispName = (name == ".") ? "<Root>" : name;
        string typeStr = GetTypeName(rtype);
        string className = GetClassName(rclass);

        List<string> leaves = new List<string>();
        string summary = ParseRrData(data, rtype, rdOffset, rdlen, leaves);

        string header = dispName + ": type " + typeStr + ", class " + className;
        if (!string.IsNullOrEmpty(summary)) header += ", " + summary;
        BoxyBox.TreeNode rr = new BoxyBox.TreeNode(header, null, true);
        rr.AddLeaf("Name: " + dispName);
        rr.AddLeaf("Type: " + typeStr + " (" + rtype + ")");
        rr.AddLeaf("Class: " + className + " (0x" + rclass.ToString("x4") + ")");
        rr.AddLeaf("Time to live: " + ttl);
        for (int i = 0; i < leaves.Count; i++) rr.AddLeaf(leaves[i]);
        section.Add(rr);
        return (pos + rdlen) - start;
    }

    // Builds an Answers/Authority/Additional section node from count records starting at pos.
    // Returns the new position after the section.
    private static int BuildRrSection(byte[] data, int len, int pos, int count, string heading, string key, BoxyBox.TreeNode parent)
    {
        if (count <= 0) return pos;
        BoxyBox.TreeNode section = new BoxyBox.TreeNode(heading, key, true);
        for (int i = 0; i < count; i++)
        {
            if (pos >= len) break;
            int consumed = BuildOneRr(data, len, pos, section);
            if (consumed <= 0) break;
            pos += consumed;
        }
        if (section.HasChildren) parent.Add(section);
        return pos;
    }

    /// <summary>
    /// Builds the Wireshark-style DNS detail tree for the Analysis Details box. Returns a list
    /// containing a single collapsible DNS root whose collapsed text is the Detailed one-liner
    /// and whose children are Transaction ID, the Flags bit breakdown, RR counts, and the
    /// Queries / Answers / Authoritative nameservers / Additional records sections. Runs
    /// just-in-time on packet selection, so full-message parsing here is off the capture hot path.
    /// </summary>
    public static List<BoxyBox.TreeNode> BuildDnsDetailTree(byte[] data, int len, int srcPort, int dstPort)
    {
        List<BoxyBox.TreeNode> roots = new List<BoxyBox.TreeNode>();
        DnsContext ctx;
        if (!TryParseDns(data, len, srcPort, dstPort, out ctx)) return roots;

        BoxyBox.TreeNode dns = new BoxyBox.TreeNode(FormatDnsFromContext(ref ctx, true), "DNS", true);
        dns.AddLeaf("Transaction ID: 0x" + ctx.TxId.ToString("x4"));
        dns.Add(BuildFlagsNode(ref ctx));
        dns.AddLeaf("RR Count - Qry: " + ctx.QdCount + ", Ans: " + ctx.AnCount + ", Auth: " + ctx.NsCount + ", Adtl: " + ctx.ArCount);

        int pos = 12;
        if (ctx.QdCount > 0)
        {
            BoxyBox.TreeNode q = new BoxyBox.TreeNode("Queries", "DNS.Queries", true);
            for (int i = 0; i < ctx.QdCount; i++)
            {
                if (pos >= len) break;
                int nb; string name = ReadName(data, pos, out nb); pos += nb;
                if (pos + 4 > len) { pos = len; break; }
                int qtype  = PacketParseHelper.ReadUInt16BE(data, pos);
                int qclass = PacketParseHelper.ReadUInt16BE(data, pos + 2);
                pos += 4;
                BoxyBox.TreeNode qn = new BoxyBox.TreeNode(name + ": type " + GetTypeName(qtype) + ", class " + GetClassName(qclass), null, true);
                qn.AddLeaf("Name: " + name);
                qn.AddLeaf("Type: " + GetTypeName(qtype) + " (" + qtype + ")");
                qn.AddLeaf("Class: " + GetClassName(qclass) + " (0x" + qclass.ToString("x4") + ")");
                q.Add(qn);
            }
            if (q.HasChildren) dns.Add(q);
        }

        pos = BuildRrSection(data, len, pos, ctx.AnCount, "Answers", "DNS.Answers", dns);
        pos = BuildRrSection(data, len, pos, ctx.NsCount, "Authoritative nameservers", "DNS.Authority", dns);
        pos = BuildRrSection(data, len, pos, ctx.ArCount, "Additional records", "DNS.Additional", dns);

        roots.Add(dns);
        return roots;
    }

    /// <summary>
    /// Walks the answer section and extracts a display string. When the first
    /// answer is a CNAME, continues walking to find a following A/AAAA record
    /// so the resolved IP is shown alongside the alias chain.
    /// Example: "www.example.com. CNAME cdn.example.net. A 93.184.216.34"
    /// Cap: walks at most 16 answer records to bound loop time.
    /// </summary>
    private static string ExtractFirstAnswer(byte[] data, int offset)
    {
        int pos = offset;
        int dataLength = data.Length;
        if (pos >= dataLength) return null;

        string cnameResult = null;
        int maxRecords = 16;

        while (maxRecords-- > 0 && pos < dataLength)
        {
            int nameBytes;
            string rrName = ReadName(data, pos, out nameBytes);
            pos += nameBytes;

            if (pos + 10 > dataLength) break;
            ushort rType = PacketParseHelper.ReadUInt16BE(data, pos);
            pos += 2; // TYPE
            pos += 2; // CLASS
            pos += 4; // TTL
            ushort rdLength = PacketParseHelper.ReadUInt16BE(data, pos);
            pos += 2;

            string typeName = GetTypeName(rType);
            if (pos + rdLength > dataLength)
            {
                string truncResult = rrName + " " + typeName + " (truncated)";
                return cnameResult != null ? cnameResult + " " + truncResult : truncResult;
            }

            switch (rType)
            {
                case 1: // A record
                    if (rdLength >= 4)
                    {
                        string ip = PacketParseHelper.FormatIPv4(data, pos);
                        string aResult = rrName + " " + typeName + " " + ip;
                        return cnameResult != null ? cnameResult + " " + aResult : aResult;
                    }
                    break;

                case 28: // AAAA record
                    if (rdLength >= 16)
                    {
                        string ip6 = PacketParseHelper.FormatIPv6(data, pos);
                        string aaaaResult = rrName + " " + typeName + " " + ip6;
                        return cnameResult != null ? cnameResult + " " + aaaaResult : aaaaResult;
                    }
                    break;

                case 5: // CNAME — record it and keep walking for the A/AAAA that follows
                    int cnameBytes;
                    string target = ReadName(data, pos, out cnameBytes);
                    cnameResult = rrName + " " + typeName + " " + target;
                    pos += rdLength;
                    continue;

                case 12: // PTR
                case 2:  // NS
                    int ptrBytes;
                    string ptrTarget = ReadName(data, pos, out ptrBytes);
                    string ptrResult = rrName + " " + typeName + " " + ptrTarget;
                    return cnameResult != null ? cnameResult + " " + ptrResult : ptrResult;
            }

            // For non-CNAME types we didn't handle, return what we have.
            string fallback = rrName + " " + typeName;
            return cnameResult != null ? cnameResult + " " + fallback : fallback;
        }

        return cnameResult;
    }
}
