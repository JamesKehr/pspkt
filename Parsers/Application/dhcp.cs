// dhcp.cs - High-performance DHCPv4 (BOOTP) and DHCPv6 parsing for real-time display.
// Extracts message type, transaction ID, and (for v4) client hardware address so the
// formatter and an app-layer display predicate can both consume the parsed shape
// without re-decoding the same byte buffer.
//
// Architecture mirrors dns.cs / tls.cs / http.cs: TryParseDhcp / FormatDhcpFromContext
// split. Recognises the standard DHCP ports (UDP 67/68 for v4, UDP 546/547 for v6).

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Parsed DHCPv4 (BOOTP) or DHCPv6 packet snapshot. Populated by
/// <see cref="DhcpParser.TryParseDhcp"/> and consumed both by the formatter
/// (<see cref="DhcpParser.FormatDhcpFromContext"/>) and by application-layer
/// display predicates (<see cref="DhcpAppPredicate"/>).
/// </summary>
public struct DhcpContext
{
    /// <summary>True when the DHCP header was parsed successfully (4-byte minimum for v6, 240 bytes for v4).</summary>
    public bool   Valid;
    /// <summary>True for DHCPv6 packets (ports 546/547). False for DHCPv4 (ports 67/68).</summary>
    public bool   IsV6;
    /// <summary>True when option parsing for the v4 message type couldn't be completed within data.Length.</summary>
    public bool   Truncated;
    /// <summary>
    /// DHCP message type. For v4: extracted from option 53 (1=Discover, 2=Offer, 3=Request,
    /// 4=Decline, 5=Ack, 6=Nak, 7=Release, 8=Inform). For v6: byte 0 of the payload
    /// (1=Solicit, 2=Advertise, 3=Request, 4=Confirm, 5=Renew, 6=Rebind, 7=Reply,
    /// 11=Information-request, ...). 0 when message type couldn't be determined.
    /// </summary>
    public int    MessageType;
    /// <summary>BOOTP op code (1=BOOTREQUEST, 2=BOOTREPLY). 0 for v6.</summary>
    public int    Op;
    /// <summary>Transaction ID — 32-bit xid for v4, 24-bit txid for v6. Stored as uint with high bits zero for v6.</summary>
    public uint   TransactionId;
    /// <summary>Client hardware address (MAC) from BOOTP chaddr. Null for v6 — DHCPv6 uses variable DUIDs not parsed in v1.</summary>
    public string ClientMacAddress;
    /// <summary>DHCPv4 "your" (assigned) IP address (yiaddr). Null for v6.</summary>
    public string Yiaddr;
    /// <summary>DHCPv4 requested IP address from option 50. Null when the option is absent or for v6.</summary>
    public string RequestedIp;
    /// <summary>DHCPv6 Client Identifier (DUID) from option 1, formatted as hyphen-separated hex. Null for v4 or when absent.</summary>
    public string ClientId;
    /// <summary>DHCPv6 IA Address (from an IA_NA/IA_TA option's nested IAADDR). Null for v4 or when absent.</summary>
    public string IaAddress;
}

/// <summary>
/// DHCP protocol parser. Provides fast C# parsing of DHCPv4 (BOOTP) and DHCPv6
/// headers plus DHCPv4 option-53 message-type lookup.
/// </summary>
public static class DhcpParser
{
    // DHCPv4 magic cookie bytes immediately preceding the options block.
    private const byte Magic0 = 0x63;
    private const byte Magic1 = 0x82;
    private const byte Magic2 = 0x53;
    private const byte Magic3 = 0x63;

    /// <summary>Returns true for standard DHCPv4 (67/68) or DHCPv6 (546/547) UDP ports.</summary>
    public static bool IsDhcpPort(int srcPort, int dstPort)
    {
        return srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68
            || srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547;
    }

    /// <summary>True when either port is a DHCPv6 port (546 or 547).</summary>
    public static bool IsDhcpV6Port(int srcPort, int dstPort)
    {
        return srcPort == 546 || srcPort == 547 || dstPort == 546 || dstPort == 547;
    }

    /// <summary>
    /// Parses a DHCP packet payload into a structured <see cref="DhcpContext"/>.
    /// Returns false when the buffer is too short to hold a valid header.
    /// For DHCPv4 with a magic cookie, walks the option block to extract the
    /// message type from option 53. Sets <see cref="DhcpContext.Truncated"/>
    /// when the option block ran off the end of the available data.
    /// </summary>
    public static bool TryParseDhcp(byte[] data, int srcPort, int dstPort, out DhcpContext ctx)
    {
        return TryParseDhcp(data, data != null ? data.Length : 0, srcPort, dstPort, out ctx);
    }

    /// <summary>
    /// Length-bounded overload: parsing only reads the first <paramref name="dataLength"/>
    /// bytes (the valid payload), so stale bytes past the real payload in a pooled/over-sized
    /// buffer never influence the parse result or an app-layer predicate.
    /// </summary>
    public static bool TryParseDhcp(byte[] data, int dataLength, int srcPort, int dstPort, out DhcpContext ctx)
    {
        ctx = default(DhcpContext);
        if (data == null) return false;
        int len = dataLength;
        if (len > data.Length) len = data.Length;

        if (IsDhcpV6Port(srcPort, dstPort))
        {
            if (len < 4) return false;
            ctx.IsV6 = true;
            ctx.MessageType = data[0];
            // 3-byte transaction ID.
            ctx.TransactionId = (uint)((data[1] << 16) | (data[2] << 8) | data[3]);
            // Walk the DHCPv6 option block (starts at byte 4) for the Client Identifier
            // (option 1) and the first IA Address (IA_NA/IA_TA option 3/4 -> nested IAADDR 5).
            ParseV6Options(data, 4, len, ref ctx);
            ctx.Valid = true;
            return true;
        }

        // DHCPv4 / BOOTP — minimum fixed portion is 240 bytes.
        if (len < 240) return false;
        ctx.IsV6 = false;
        ctx.Op = data[0];
        ctx.TransactionId = PacketParseHelper.ReadUInt32BE(data, 4);
        ctx.Yiaddr = PacketParseHelper.FormatIPv4(data, 16);
        ctx.ClientMacAddress = PacketParseHelper.FormatMac(data, 28);

        // Walk options to extract the message type (option 53) and requested IP (option 50).
        // Requires the magic cookie at bytes 236-239 immediately before the options block.
        // We've already verified len >= 240, so reading the cookie is safe; the option
        // walk itself handles any truncation that follows.
        if (data[236] == Magic0 && data[237] == Magic1
            && data[238] == Magic2 && data[239] == Magic3)
        {
            int pos = 240;
            while (pos < len)
            {
                int code = data[pos++];
                if (code == 0) continue;          // pad
                if (code == 255) break;           // end
                if (pos >= len) { ctx.Truncated = true; break; }
                int optlen = data[pos++];
                if (pos + optlen > len) { ctx.Truncated = true; break; }
                if (code == 53 && optlen >= 1)
                {
                    ctx.MessageType = data[pos];
                }
                else if (code == 50 && optlen >= 4)
                {
                    ctx.RequestedIp = PacketParseHelper.FormatIPv4(data, pos);
                }
                pos += optlen;
            }
        }

        ctx.Valid = true;
        return true;
    }

    // Walks a DHCPv6 option block to capture the Client Identifier (option 1) and the first
    // IA Address (IAADDR, option 5, nested in an IA_NA (3) or IA_TA (4) option). Bounded by
    // dataLen so a truncated packet can only produce a partial context, never an over-read.
    private static void ParseV6Options(byte[] data, int off, int dataLen, ref DhcpContext ctx)
    {
        int pos = off;
        int safety = 64;
        while (pos + 4 <= dataLen && safety-- > 0)
        {
            int code = (data[pos] << 8) | data[pos + 1];
            int len = (data[pos + 2] << 8) | data[pos + 3];
            int body = pos + 4;
            if (body + len > dataLen) break;

            if (code == 1 && ctx.ClientId == null && len > 0)          // CLIENTID (DUID)
            {
                ctx.ClientId = FormatHexBytes(data, body, len);
            }
            else if ((code == 3 || code == 4) && ctx.IaAddress == null) // IA_NA / IA_TA
            {
                // IA_NA header is 12 bytes (IAID + T1 + T2); IA_TA is 4 bytes (IAID). Nested
                // options follow. Scan them for the first IAADDR (5).
                int inner = body + (code == 3 ? 12 : 4);
                int innerEnd = body + len;
                int isafety = 32;
                while (inner + 4 <= innerEnd && isafety-- > 0)
                {
                    int icode = (data[inner] << 8) | data[inner + 1];
                    int ilen = (data[inner + 2] << 8) | data[inner + 3];
                    int ibody = inner + 4;
                    if (ibody + ilen > innerEnd) break;
                    if (icode == 5 && ilen >= 16)   // IAADDR
                    {
                        ctx.IaAddress = PacketParseHelper.FormatIPv6(data, ibody);
                        break;
                    }
                    inner = ibody + ilen;
                }
            }
            pos = body + len;
        }
    }

    // Formats a byte range as a continuous lowercase hex string (e.g. "000100012abb...").
    private static string FormatHexBytes(byte[] data, int off, int len)
    {
        var sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++)
        {
            sb.Append(data[off + i].ToString("x2"));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Formats a previously parsed <see cref="DhcpContext"/> using the Detailed one-liner form
    /// (per DHCP_parser_instructions.md). This is the Default form plus per-message-type extras:
    ///   v4 DISCOVER: "DHCP DISCOVER, XID: 0x.., chaddr: .. [, Requested: ..]"
    ///   v4 OFFER/ACK: ".., yiaddr: .."   v4 REQUEST: ".., Requested: .."
    ///   v6 ADVERTISE/REQUEST/REPLY: ".., IAA: [IA Address]"
    /// </summary>
    public static string FormatDhcpFromContext(ref DhcpContext ctx)
    {
        if (!ctx.Valid) return null;

        string baseLine = FormatDhcpDefaultFromContext(ref ctx);
        if (baseLine == null) return null;

        if (ctx.IsV6)
        {
            switch (ctx.MessageType)
            {
                case 2: // Advertise
                case 3: // Request
                case 7: // Reply
                    return baseLine + ", IAA: " + (ctx.IaAddress ?? "?");
                default:
                    return baseLine;
            }
        }

        switch (ctx.MessageType)
        {
            case 1: // Discover
                return ctx.RequestedIp != null ? baseLine + ", Requested: " + ctx.RequestedIp : baseLine;
            case 3: // Request
                return baseLine + ", Requested: " + (ctx.RequestedIp ?? "?");
            case 2: // Offer
            case 5: // Ack
                return baseLine + ", yiaddr: " + ctx.Yiaddr;
            default:
                return baseLine;
        }
    }

    /// <summary>
    /// Default one-liner formatter from a parsed context (per DHCP_parser_instructions.md):
    ///   v4: "DHCP [TYPE], XID: 0x[xid], chaddr: [mac]"
    ///   v6: "DHCPv6 [TYPE], XID: 0x[txid], CID: [Client Identifier]"
    /// XID is rendered 0x-prefixed for both families (matching the Analysis Details tree).
    /// </summary>
    public static string FormatDhcpDefaultFromContext(ref DhcpContext ctx)
    {
        if (!ctx.Valid) return null;

        if (ctx.IsV6)
        {
            return "DHCPv6 " + GetV6MessageTypeName(ctx.MessageType)
                + ", XID: 0x" + ctx.TransactionId.ToString("x6")
                + ", CID: " + (ctx.ClientId ?? "?");
        }

        string msgName = (ctx.MessageType != 0)
            ? GetV4MessageTypeName(ctx.MessageType)
            : (ctx.Op == 1 ? "BOOTREQUEST" : ctx.Op == 2 ? "BOOTREPLY" : "op " + ctx.Op.ToString());

        return "DHCP " + msgName
            + ", XID: 0x" + ctx.TransactionId.ToString("x8")
            + ", chaddr: " + ctx.ClientMacAddress;
    }

    /// <summary>
    /// Default-tier formatter for a raw DHCP payload. Parses the payload (option 53 message type
    /// for v4, message byte for v6) and renders the Default one-liner. Returns null on a payload
    /// too short to be DHCP.
    /// </summary>
    public static string FormatDhcpSegment(byte[] data, int srcPort, int dstPort)
    {
        return FormatDhcpSegment(data, data != null ? data.Length : 0, srcPort, dstPort);
    }

    /// <summary>Length-bounded overload: parsing is limited to the valid payload length.</summary>
    public static string FormatDhcpSegment(byte[] data, int dataLen, int srcPort, int dstPort)
    {
        DhcpContext ctx;
        if (!TryParseDhcp(data, dataLen, srcPort, dstPort, out ctx)) return null;
        return FormatDhcpDefaultFromContext(ref ctx);
    }

    /// <summary>Returns a display name for a DHCPv4 option-53 message type (spec table, uppercase).</summary>
    public static string GetV4MessageTypeName(int msgType)
    {
        switch (msgType)
        {
            case 1: return "DISCOVER";
            case 2: return "OFFER";
            case 3: return "REQUEST";
            case 4: return "DECLINE";
            case 5: return "ACK";
            case 6: return "NAK";
            case 7: return "RELEASE";
            case 8: return "INFORM";
            default: return "type " + msgType.ToString();
        }
    }

    /// <summary>Returns a display name for a DHCPv6 message type byte (spec table, uppercase).</summary>
    public static string GetV6MessageTypeName(int msgType)
    {
        switch (msgType)
        {
            case 1:  return "SOLICIT";
            case 2:  return "ADVERTISE";
            case 3:  return "REQUEST";
            case 4:  return "CONFIRM";
            case 5:  return "RENEW";
            case 6:  return "REBIND";
            case 7:  return "REPLY";
            case 8:  return "RELEASE";
            case 9:  return "DECLINE";
            case 10: return "RECONFIGURE";
            case 11: return "INFORMATION-REQUEST";
            case 12: return "RELAY-FORW";
            case 13: return "RELAY-REPL";
            case 14: return "LEASEQUERY";
            case 15: return "LEASEQUERY-REPLY";
            case 16: return "LEASEQUERY-DONE";
            case 17: return "LEASEQUERY-DATA";
            case 18: return "RECONFIGURE-REQUEST";
            case 19: return "RECONFIGURE-REPLY";
            case 20: return "DHCPV4-QUERY";
            case 21: return "DHCPV4-RESPONSE";
            case 22: return "ACTIVELEASEQUERY";
            case 23: return "STARTTLS";
            case 24: return "BNDUPD";
            case 25: return "BNDREPLY";
            case 26: return "POOLREQ";
            case 27: return "POOLRESP";
            case 28: return "UPDREQ";
            case 29: return "UPDREQALL";
            case 30: return "UPDDONE";
            case 31: return "CONNECT";
            case 32: return "CONNECTREPLY";
            case 33: return "DISCONNECT";
            case 34: return "STATE";
            case 35: return "CONTACT";
            default: return "type " + msgType.ToString();
        }
    }

    // ==================== Analysis Details tree ====================

    /// <summary>
    /// Builds the Analysis Details tree for a DHCP payload (per DHCP_parser_instructions.md):
    /// a "DHCP [TYPE]" / "DHCPv6 [TYPE]" header, the COMMON header fields, and an expandable
    /// "Options" node with one child per parsed option. Returns an empty list if the payload is
    /// too short to be DHCP.
    /// </summary>
    public static List<BoxyBox.TreeNode> BuildDhcpDetailTree(byte[] data, int srcPort, int dstPort)
    {
        var roots = new List<BoxyBox.TreeNode>();
        DhcpContext ctx;
        if (!TryParseDhcp(data, srcPort, dstPort, out ctx)) return roots;

        if (ctx.IsV6)
        {
            var node = new BoxyBox.TreeNode("DHCPv6 " + GetV6MessageTypeName(ctx.MessageType), "DHCP", true);
            node.AddLeaf("Message type: " + GetV6MessageTypeName(ctx.MessageType) + " (" + ctx.MessageType + ")");
            node.AddLeaf("Transaction ID: 0x" + ctx.TransactionId.ToString("x6"));
            AddV6OptionsNode(node, data, 4, data.Length);
            roots.Add(node);
            return roots;
        }

        // DHCPv4 / BOOTP.
        string typeName = (ctx.MessageType != 0) ? GetV4MessageTypeName(ctx.MessageType)
                        : (ctx.Op == 1 ? "BOOTREQUEST" : ctx.Op == 2 ? "BOOTREPLY" : "op " + ctx.Op);
        int htype = data[1];
        int hlen = data[2];
        int hops = data[3];
        int secs = PacketParseHelper.ReadUInt16BE(data, 8);
        int flags = PacketParseHelper.ReadUInt16BE(data, 10);

        var v4 = new BoxyBox.TreeNode("DHCP " + typeName, "DHCP", true);
        v4.AddLeaf("Message type: " + (ctx.MessageType != 0 ? GetV4MessageTypeName(ctx.MessageType) : "(from BOOTP op)") + " (" + ctx.MessageType + ")");
        v4.AddLeaf("Hardware type: " + HardwareTypeName(htype) + " (0x" + htype.ToString("x2") + ")");
        v4.AddLeaf("Hardware address length: " + hlen);
        v4.AddLeaf("Hops: " + hops);
        v4.AddLeaf("Transaction ID: 0x" + ctx.TransactionId.ToString("x8"));
        v4.AddLeaf("Seconds elapsed: " + secs);
        v4.AddLeaf("Bootp flags: 0x" + flags.ToString("x4") + " (" + ((flags & 0x8000) != 0 ? "Broadcast" : "Unicast") + ")");
        v4.AddLeaf("Client IP address: " + PacketParseHelper.FormatIPv4(data, 12));
        v4.AddLeaf("Your (client) IP address: " + PacketParseHelper.FormatIPv4(data, 16));
        v4.AddLeaf("Next server IP address: " + PacketParseHelper.FormatIPv4(data, 20));
        v4.AddLeaf("Relay agent IP address: " + PacketParseHelper.FormatIPv4(data, 24));
        v4.AddLeaf("Client MAC address: " + ctx.ClientMacAddress);
        AddV4OptionsNode(v4, data);
        roots.Add(v4);
        return roots;
    }

    // Appends the expandable "Options" node for a DHCPv4 payload (options start after the magic
    // cookie at byte 240). Each option is rendered as a child leaf.
    private static void AddV4OptionsNode(BoxyBox.TreeNode parent, byte[] data)
    {
        if (data.Length < 240 || !(data[236] == Magic0 && data[237] == Magic1
            && data[238] == Magic2 && data[239] == Magic3)) return;

        var opts = new BoxyBox.TreeNode("Options", "DHCP.Options", true);
        int pos = 240;
        int safety = 128;
        while (pos < data.Length && safety-- > 0)
        {
            int code = data[pos++];
            if (code == 0) continue;       // pad
            if (code == 255) { opts.AddLeaf("End (255)"); break; }
            if (pos >= data.Length) break;
            int len = data[pos++];
            if (pos + len > data.Length) break;
            opts.AddLeaf(FormatV4Option(code, data, pos, len));
            pos += len;
        }
        if (opts.Children.Count > 0) parent.Add(opts);
    }

    // Appends the expandable "Options" node for a DHCPv6 payload (options start at byte 4).
    private static void AddV6OptionsNode(BoxyBox.TreeNode parent, byte[] data, int off, int dataLen)
    {
        var opts = new BoxyBox.TreeNode("Options", "DHCP.Options", true);
        int pos = off;
        int safety = 128;
        while (pos + 4 <= dataLen && safety-- > 0)
        {
            int code = (data[pos] << 8) | data[pos + 1];
            int len = (data[pos + 2] << 8) | data[pos + 3];
            int body = pos + 4;
            if (body + len > dataLen) break;
            opts.AddLeaf(FormatV6Option(code, data, body, len));
            pos = body + len;
        }
        if (opts.Children.Count > 0) parent.Add(opts);
    }

    private static string FormatV4Option(int code, byte[] data, int off, int len)
    {
        string name = V4OptionName(code);
        switch (code)
        {
            case 1:  // Subnet Mask
            case 28: // Broadcast Address
            case 32: // Router Solicitation Address
            case 50: // Requested IP
            case 54: // Server Identifier
                if (len >= 4) return name + " (" + code + "): " + PacketParseHelper.FormatIPv4(data, off);
                break;
            case 3:  // Router
            case 6:  // DNS
            case 42: // NTP
                return name + " (" + code + "): " + FormatIpList(data, off, len);
            case 12: // Host Name
            case 15: // Domain Name
            case 56: // Message
                return name + " (" + code + "): " + FormatAscii(data, off, len);
            case 51: // Lease Time
            case 58: // Renewal (T1)
            case 59: // Rebinding (T2)
                if (len >= 4) return name + " (" + code + "): " + PacketParseHelper.ReadUInt32BE(data, off) + "s";
                break;
            case 53: // Message Type
                if (len >= 1) return name + " (" + code + "): " + GetV4MessageTypeName(data[off]) + " (" + data[off] + ")";
                break;
            case 55: // Parameter Request List
                return name + " (" + code + "): " + FormatByteList(data, off, len);
            case 61: // Client Identifier
                return name + " (" + code + "): " + FormatHexBytes(data, off, len);
        }
        return name + " (" + code + "): len " + len;
    }

    private static string FormatV6Option(int code, byte[] data, int off, int len)
    {
        string name = V6OptionName(code);
        switch (code)
        {
            case 1: // Client Identifier
            case 2: // Server Identifier
                return name + " (" + code + "): " + FormatHexBytes(data, off, len);
            case 3: // IA_NA
            case 4: // IA_TA
            {
                string s = name + " (" + code + ")";
                int inner = off + (code == 3 ? 12 : 4);
                int innerEnd = off + len;
                while (inner + 4 <= innerEnd)
                {
                    int icode = (data[inner] << 8) | data[inner + 1];
                    int ilen = (data[inner + 2] << 8) | data[inner + 3];
                    int ibody = inner + 4;
                    if (ibody + ilen > innerEnd) break;
                    if (icode == 5 && ilen >= 16) { s += ": IAADDR " + PacketParseHelper.FormatIPv6(data, ibody); break; }
                    inner = ibody + ilen;
                }
                return s;
            }
            case 5: // IA Address
                if (len >= 16) return name + " (" + code + "): " + PacketParseHelper.FormatIPv6(data, off);
                break;
            case 8: // Elapsed Time (hundredths of a second)
                if (len >= 2) return name + " (" + code + "): " + (PacketParseHelper.ReadUInt16BE(data, off) * 10) + "ms";
                break;
            case 23: // DNS Recursive Name Server
                return name + " (" + code + "): " + FormatIpv6List(data, off, len);
        }
        return name + " (" + code + "): len " + len;
    }

    // ---- option-name / value helpers ----

    private static string HardwareTypeName(int htype)
    {
        return htype == 1 ? "Ethernet" : "type " + htype;
    }

    private static string FormatIpList(byte[] data, int off, int len)
    {
        var sb = new StringBuilder();
        for (int i = 0; i + 4 <= len; i += 4)
        {
            if (sb.Length > 0) sb.Append(", ");
            sb.Append(PacketParseHelper.FormatIPv4(data, off + i));
        }
        return sb.ToString();
    }

    private static string FormatIpv6List(byte[] data, int off, int len)
    {
        var sb = new StringBuilder();
        for (int i = 0; i + 16 <= len; i += 16)
        {
            if (sb.Length > 0) sb.Append(", ");
            sb.Append(PacketParseHelper.FormatIPv6(data, off + i));
        }
        return sb.ToString();
    }

    private static string FormatByteList(byte[] data, int off, int len)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < len; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append(data[off + i]);
        }
        return sb.ToString();
    }

    private static string FormatAscii(byte[] data, int off, int len)
    {
        var sb = new StringBuilder(len);
        for (int i = 0; i < len; i++)
        {
            byte b = data[off + i];
            sb.Append(b >= 0x20 && b < 0x7f ? (char)b : '.');
        }
        return sb.ToString();
    }

    private static string V4OptionName(int code)
    {
        switch (code)
        {
            case 1:  return "Subnet Mask";
            case 3:  return "Router";
            case 6:  return "Domain Name Server";
            case 12: return "Host Name";
            case 15: return "Domain Name";
            case 28: return "Broadcast Address";
            case 42: return "Network Time Protocol Servers";
            case 50: return "Requested IP Address";
            case 51: return "IP Address Lease Time";
            case 53: return "DHCP Message Type";
            case 54: return "DHCP Server Identifier";
            case 55: return "Parameter Request List";
            case 56: return "Message";
            case 58: return "Renewal Time Value";
            case 59: return "Rebinding Time Value";
            case 61: return "Client Identifier";
            default: return "Option";
        }
    }

    private static string V6OptionName(int code)
    {
        switch (code)
        {
            case 1:  return "Client Identifier";
            case 2:  return "Server Identifier";
            case 3:  return "Identity Association for Non-temporary Address";
            case 4:  return "Identity Association for Temporary Address";
            case 5:  return "IA Address";
            case 6:  return "Option Request";
            case 8:  return "Elapsed Time";
            case 23: return "DNS Recursive Name Server";
            case 24: return "Domain Search List";
            case 25: return "Identity Association for Prefix Delegation";
            case 39: return "Client FQDN";
            default: return "Option";
        }
    }
}
