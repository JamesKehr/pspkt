// dhcp.cs - High-performance DHCPv4 (BOOTP) and DHCPv6 parsing for real-time display.
// Extracts message type, transaction ID, and (for v4) client hardware address so the
// formatter and an app-layer display predicate can both consume the parsed shape
// without re-decoding the same byte buffer.
//
// Architecture mirrors dns.cs / tls.cs / http.cs: TryParseDhcp / FormatDhcpFromContext
// split. Recognises the standard DHCP ports (UDP 67/68 for v4, UDP 546/547 for v6).

using System;
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
        ctx = default(DhcpContext);
        if (data == null) return false;

        if (IsDhcpV6Port(srcPort, dstPort))
        {
            if (data.Length < 4) return false;
            ctx.IsV6 = true;
            ctx.MessageType = data[0];
            // 3-byte transaction ID.
            ctx.TransactionId = (uint)((data[1] << 16) | (data[2] << 8) | data[3]);
            ctx.Valid = true;
            return true;
        }

        // DHCPv4 / BOOTP — minimum fixed portion is 240 bytes.
        if (data.Length < 240) return false;
        ctx.IsV6 = false;
        ctx.Op = data[0];
        ctx.TransactionId = PacketParseHelper.ReadUInt32BE(data, 4);
        ctx.ClientMacAddress = PacketParseHelper.FormatMac(data, 28);

        // Walk options to extract message type (option 53). Requires the magic
        // cookie at bytes 236-239 immediately before the options block. We've
        // already verified data.Length >= 240, so reading the cookie is safe;
        // the option walk itself handles any truncation that follows.
        if (data[236] == Magic0 && data[237] == Magic1
            && data[238] == Magic2 && data[239] == Magic3)
        {
            int pos = 240;
            while (pos < data.Length)
            {
                int code = data[pos++];
                if (code == 0) continue;          // pad
                if (code == 255) break;           // end
                if (pos >= data.Length) { ctx.Truncated = true; break; }
                int len = data[pos++];
                if (pos + len > data.Length) { ctx.Truncated = true; break; }
                if (code == 53 && len >= 1)
                {
                    ctx.MessageType = data[pos];
                    break;
                }
                pos += len;
            }
        }

        ctx.Valid = true;
        return true;
    }

    /// <summary>
    /// Formats a previously parsed <see cref="DhcpContext"/> using the detailed
    /// tcpdump-style format. Equivalent to the legacy <c>FormatDhcpDetailed</c>:
    ///   v4: "DHCP Discover - xid: 0xdeadbeef; chaddr: aa-bb-cc-dd-ee-ff"
    ///   v6: "DHCPv6 Solicit - txid: 0xabc123"
    /// </summary>
    public static string FormatDhcpFromContext(ref DhcpContext ctx)
    {
        if (!ctx.Valid) return null;

        if (ctx.IsV6)
        {
            return "DHCPv6 " + GetV6MessageTypeName(ctx.MessageType)
                + " - txid: 0x" + ctx.TransactionId.ToString("x6");
        }

        string msgName = (ctx.MessageType != 0)
            ? GetV4MessageTypeName(ctx.MessageType)
            : (ctx.Op == 1 ? "Request" : ctx.Op == 2 ? "Reply" : "op " + ctx.Op.ToString());

        return "DHCP " + msgName
            + " - xid: 0x" + ctx.TransactionId.ToString("x8")
            + "; chaddr: " + ctx.ClientMacAddress;
    }

    /// <summary>
    /// Default-tier formatter for a DHCP payload (short form, no option walk on v4).
    /// Equivalent to the legacy <c>FormatDhcpBasic</c>:
    ///   v4: "DHCP Discover/Request" or "DHCP Offer/Ack"
    ///   v6: "DHCPv6 Solicit"
    /// </summary>
    public static string FormatDhcpSegment(byte[] data, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4) return null;
        if (IsDhcpV6Port(srcPort, dstPort))
        {
            return "DHCPv6 " + GetV6MessageTypeName(data[0]);
        }
        if (data.Length < 240) return null;
        int op = data[0];
        string opName = (op == 1) ? "Discover/Request" : (op == 2) ? "Offer/Ack" : "op" + op.ToString();
        return "DHCP " + opName;
    }

    /// <summary>Returns a display name for a DHCPv4 option-53 message type.</summary>
    public static string GetV4MessageTypeName(int msgType)
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

    /// <summary>Returns a display name for a DHCPv6 message type byte.</summary>
    public static string GetV6MessageTypeName(int msgType)
    {
        switch (msgType)
        {
            case 1:  return "Solicit";
            case 2:  return "Advertise";
            case 3:  return "Request";
            case 4:  return "Confirm";
            case 5:  return "Renew";
            case 6:  return "Rebind";
            case 7:  return "Reply";
            case 8:  return "Release";
            case 9:  return "Decline";
            case 10: return "Reconfigure";
            case 11: return "Information-request";
            case 12: return "Relay-forward";
            case 13: return "Relay-reply";
            default: return "type " + msgType.ToString();
        }
    }
}
