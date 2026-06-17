// dns.cs - High-performance DNS packet parsing for real-time display.
// Handles name decompression, query/response formatting in tcpdump style.

using System;
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
            sb.Append(Encoding.ASCII.GetString(data, pos, labelLen));
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
        ctx = default(DnsContext);
        if (data == null || data.Length < 12) return false;

        ctx.IsMdns  = (srcPort == 5353 || dstPort == 5353);
        ctx.TxId    = PacketParseHelper.ReadUInt16BE(data, 0);
        ushort flags = PacketParseHelper.ReadUInt16BE(data, 2);
        ctx.Qr      = (flags >> 15) & 1;
        ctx.Rcode   = flags & 0xF;
        ctx.QdCount = PacketParseHelper.ReadUInt16BE(data, 4);
        ctx.AnCount = PacketParseHelper.ReadUInt16BE(data, 6);
        ctx.NsCount = PacketParseHelper.ReadUInt16BE(data, 8);
        ctx.ArCount = PacketParseHelper.ReadUInt16BE(data, 10);

        int pos = 12;
        if (ctx.QdCount > 0 && pos < data.Length)
        {
            int nameBytes;
            ctx.QName = ReadName(data, pos, out nameBytes);
            pos += nameBytes;
            if (pos + 4 <= data.Length)
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
        if (ctx.Qr == 1 && ctx.AnCount > 0 && pos < data.Length)
        {
            ctx.FirstAnswer = ExtractFirstAnswer(data, pos);
        }

        ctx.Valid = true;
        return true;
    }

    /// <summary>
    /// Formats a previously parsed <see cref="DnsContext"/> into a tcpdump-style
    /// one-liner. Equivalent to <see cref="FormatDnsSegment"/> but avoids re-parsing.
    /// </summary>
    public static string FormatDnsFromContext(ref DnsContext ctx, int payloadLen)
    {
        if (!ctx.Valid) return null;
        string prefix = ctx.IsMdns ? "mDNS" : "DNS";
        string qTypeName = GetTypeName(ctx.QType);

        if (ctx.Qr == 0)
        {
            return string.Concat(prefix, " ", ctx.TxId.ToString(), "+ ", qTypeName, "? ", ctx.QName, " (", payloadLen.ToString(), ")");
        }

        string rcodePart = (ctx.Rcode != 0) ? GetRcodeName(ctx.Rcode) + " " : "";
        string counts = ctx.AnCount.ToString() + "/" + ctx.NsCount.ToString() + "/" + ctx.ArCount.ToString();

        if (ctx.FirstAnswer != null)
        {
            return string.Concat(prefix, " ", ctx.TxId.ToString(), " ", rcodePart, counts, " ", ctx.FirstAnswer, " (", payloadLen.ToString(), ")");
        }
        return string.Concat(prefix, " ", ctx.TxId.ToString(), " ", rcodePart, counts, " ", qTypeName, " ", ctx.QName, " (", payloadLen.ToString(), ")");
    }

    /// <summary>
    /// Formats a DNS packet payload into a tcpdump-style one-liner.
    /// Query:    "DNS 1234+ A? www.example.com. (45)"
    /// Response: "DNS 1234 1/0/0 A 93.184.216.34 (62)"
    /// Returns null if data is too short.
    ///
    /// Kept as a single-call convenience wrapper around
    /// <see cref="TryParseDns"/> + <see cref="FormatDnsFromContext"/> so the
    /// Default-tier formatters that don't need access to the parsed context
    /// can continue to use one call.
    /// </summary>
    public static string FormatDnsSegment(byte[] data, int srcPort, int dstPort)
    {
        DnsContext ctx;
        if (!TryParseDns(data, srcPort, dstPort, out ctx)) return null;
        return FormatDnsFromContext(ref ctx, data.Length);
    }

    /// <summary>
    /// Extracts the first answer record type and data from a DNS response.
    /// </summary>
    private static string ExtractFirstAnswer(byte[] data, int offset)
    {
        int pos = offset;
        if (pos >= data.Length) return null;

        int nameBytes;
        string rrName = ReadName(data, pos, out nameBytes);
        pos += nameBytes;

        if (pos + 10 > data.Length) return null;
        ushort rType = PacketParseHelper.ReadUInt16BE(data, pos);
        pos += 2; // TYPE
        pos += 2; // CLASS
        pos += 4; // TTL
        ushort rdLength = PacketParseHelper.ReadUInt16BE(data, pos);
        pos += 2;

        string typeName = GetTypeName(rType);
        if (pos + rdLength > data.Length) return rrName + " " + typeName + " (truncated)";

        // Format RDATA for common types.
        switch (rType)
        {
            case 1: // A record
                if (rdLength >= 4)
                {
                    string ip = data[pos].ToString() + "." + data[pos + 1].ToString() + "." +
                                data[pos + 2].ToString() + "." + data[pos + 3].ToString();
                    return rrName + " " + typeName + " " + ip;
                }
                break;

            case 28: // AAAA record
                if (rdLength >= 16)
                {
                    StringBuilder sb = new StringBuilder(40);
                    for (int i = 0; i < 16; i += 2)
                    {
                        if (i > 0) sb.Append(':');
                        sb.AppendFormat("{0:x4}", PacketParseHelper.ReadUInt16BE(data, pos + i));
                    }
                    // Simple zero compression: replace longest run of :0000 groups.
                    string ip6 = sb.ToString();
                    ip6 = CompressIPv6(ip6);
                    return rrName + " " + typeName + " " + ip6;
                }
                break;

            case 5: // CNAME
            case 12: // PTR
            case 2: // NS
                int cnameBytes;
                string target = ReadName(data, pos, out cnameBytes);
                return rrName + " " + typeName + " " + target;
        }

        return rrName + " " + typeName;
    }

    /// <summary>
    /// Simple IPv6 zero compression: replaces longest run of ":0000" with "::".
    /// </summary>
    private static string CompressIPv6(string fullAddr)
    {
        // Split by ':' and find longest run of "0000" groups.
        string[] groups = fullAddr.Split(':');
        int bestStart = -1, bestLen = 0;
        int curStart = -1, curLen = 0;

        for (int i = 0; i < groups.Length; i++)
        {
            if (groups[i] == "0000")
            {
                if (curStart < 0) curStart = i;
                curLen++;
                if (curLen > bestLen)
                {
                    bestStart = curStart;
                    bestLen = curLen;
                }
            }
            else
            {
                curStart = -1;
                curLen = 0;
            }
        }

        if (bestLen < 2) return fullAddr;

        // Rebuild with :: at bestStart.
        StringBuilder sb = new StringBuilder(40);
        for (int i = 0; i < groups.Length; i++)
        {
            if (i == bestStart)
            {
                if (i == 0) sb.Append("::");
                else sb.Append(':');
                i += bestLen - 1;
                if (i == groups.Length - 1) { /* trailing :: already appended */ }
            }
            else
            {
                if (sb.Length > 0 && sb[sb.Length - 1] != ':') sb.Append(':');
                // Strip leading zeros from group.
                string g = groups[i].TrimStart('0');
                if (g.Length == 0) g = "0";
                sb.Append(g);
            }
        }
        return sb.ToString();
    }
}
