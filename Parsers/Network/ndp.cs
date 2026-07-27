// IPv6 Neighbor Discovery one-line formatters and bounded Analysis detail trees (RFC 4861).

using System;
using System.Text;

/// <summary>Formats NDP one-liners and builds Analysis detail trees for ICMPv6 types 133-137.</summary>
public static class NdpParser
{
    // RFC 4861 NDP option type codes.
    private const int OPT_SOURCE_LINK_ADDR = 1;
    private const int OPT_TARGET_LINK_ADDR = 2;
    private const int OPT_PREFIX_INFO      = 3;
    private const int OPT_REDIRECTED_HDR   = 4;
    private const int OPT_MTU              = 5;
    private const int OPT_ROUTE_INFO       = 24;
    private const int OPT_RDNSS            = 25;
    private const int OPT_DNSSL            = 31;

    private const int OPTION_VALID = 0;
    private const int OPTION_ZERO_LENGTH = 1;
    private const int OPTION_TRUNCATED = 2;

    internal static BoxyBox.TreeNode BuildNdpDetailNode(byte[] data, int icmpv6Off, int icmpv6Len)
    {
        if (data == null || icmpv6Off < 0 || icmpv6Len < 4
            || icmpv6Off + icmpv6Len > data.Length)
        {
            return null;
        }

        int type = data[icmpv6Off];
        int code = data[icmpv6Off + 1];
        int checksum = PacketParseHelper.ReadUInt16BE(data, icmpv6Off + 2);
        int end = icmpv6Off + icmpv6Len;

        BoxyBox.TreeNode root = new BoxyBox.TreeNode("ICMPv6", "ICMPv6", true);
        root.AddLeaf("Type: " + NdpTypeName(type) + " (" + type + ")");
        root.AddLeaf("Code: " + code);
        root.AddLeaf("Checksum: 0x" + checksum.ToString("x4"));

        int optionOffset = end;
        switch (type)
        {
            case 133:
                if (icmpv6Len >= 8)
                {
                    root.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt32BE(data, icmpv6Off + 4));
                    optionOffset = icmpv6Off + 8;
                }
                break;

            case 134:
                if (icmpv6Len >= 16)
                {
                    byte flags = data[icmpv6Off + 5];
                    root.AddLeaf("Current Hop Limit: " + data[icmpv6Off + 4]);
                    root.Add(BuildRouterAdvertisementFlagsNode(flags));
                    root.AddLeaf("Router Lifetime: " + PacketParseHelper.ReadUInt16BE(data, icmpv6Off + 6) + "s");
                    root.AddLeaf("Reachable Time: " + PacketParseHelper.ReadUInt32BE(data, icmpv6Off + 8) + "ms");
                    root.AddLeaf("Retrans Timer: " + PacketParseHelper.ReadUInt32BE(data, icmpv6Off + 12) + "ms");
                    optionOffset = icmpv6Off + 16;
                }
                break;

            case 135:
                if (icmpv6Len >= 24)
                {
                    root.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt32BE(data, icmpv6Off + 4));
                    root.AddLeaf("Target Address: " + PacketParseHelper.FormatIPv6(data, icmpv6Off + 8));
                    optionOffset = icmpv6Off + 24;
                }
                break;

            case 136:
                if (icmpv6Len >= 24)
                {
                    uint flags = PacketParseHelper.ReadUInt32BE(data, icmpv6Off + 4);
                    root.Add(BuildNeighborAdvertisementFlagsNode(flags));
                    root.AddLeaf("Target Address: " + PacketParseHelper.FormatIPv6(data, icmpv6Off + 8));
                    optionOffset = icmpv6Off + 24;
                }
                break;

            case 137:
                if (icmpv6Len >= 40)
                {
                    root.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt32BE(data, icmpv6Off + 4));
                    root.AddLeaf("Target Address: " + PacketParseHelper.FormatIPv6(data, icmpv6Off + 8));
                    root.AddLeaf("Destination Address: " + PacketParseHelper.FormatIPv6(data, icmpv6Off + 24));
                    optionOffset = icmpv6Off + 40;
                }
                break;
        }

        AppendOptionNodes(root, data, optionOffset, end);
        return root;
    }

    private static BoxyBox.TreeNode BuildRouterAdvertisementFlagsNode(byte flags)
    {
        StringBuilder summary = new StringBuilder("Flags: 0x");
        summary.Append(flags.ToString("x2"));
        if ((flags & 0x80) != 0) summary.Append(", Managed");
        if ((flags & 0x40) != 0) summary.Append(", Other");
        if ((flags & 0x20) != 0) summary.Append(", Home Agent");
        summary.Append(", Router Preference ").Append(PrefName((flags >> 3) & 0x3));
        if ((flags & 0x04) != 0) summary.Append(", Proxy");
        if ((flags & 0x02) != 0) summary.Append(", Reserved");

        BoxyBox.TreeNode node = new BoxyBox.TreeNode(summary.ToString(), null, false);
        node.AddLeaf(FormatBitPattern(flags, 0x80, 8) + " = Managed address configuration: " + SetState((flags & 0x80) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x40, 8) + " = Other configuration: " + SetState((flags & 0x40) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x20, 8) + " = Home Agent: " + SetState((flags & 0x20) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x18, 8) + " = Router Preference: " + PrefName((flags >> 3) & 0x3));
        node.AddLeaf(FormatBitPattern(flags, 0x04, 8) + " = Proxy: " + SetState((flags & 0x04) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x02, 8) + " = Reserved: " + (flags & 0x02));
        return node;
    }

    private static BoxyBox.TreeNode BuildNeighborAdvertisementFlagsNode(uint flags)
    {
        StringBuilder summary = new StringBuilder("Flags: 0x");
        summary.Append(flags.ToString("x8"));
        if ((flags & 0x80000000u) != 0) summary.Append(", Router");
        if ((flags & 0x40000000u) != 0) summary.Append(", Solicited");
        if ((flags & 0x20000000u) != 0) summary.Append(", Override");

        BoxyBox.TreeNode node = new BoxyBox.TreeNode(summary.ToString(), null, false);
        node.AddLeaf(FormatBitPattern(flags, 0x80000000u, 32) + " = Router: " + SetState((flags & 0x80000000u) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x40000000u, 32) + " = Solicited: " + SetState((flags & 0x40000000u) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x20000000u, 32) + " = Override: " + SetState((flags & 0x20000000u) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x1FFFFFFFu, 32) + " = Reserved: " + (flags & 0x1FFFFFFFu));
        return node;
    }

    private static void AppendOptionNodes(BoxyBox.TreeNode root, byte[] data, int optionOffset, int optionEnd)
    {
        int position = optionOffset;
        int guard = 0;
        while (position < optionEnd && guard++ < 64)
        {
            NdpOptionFrame option;
            if (!TryReadOption(data, ref position, optionEnd, out option)) break;

            if (option.Status == OPTION_ZERO_LENGTH)
            {
                BoxyBox.TreeNode malformed = new BoxyBox.TreeNode("ICMPv6 Option (Malformed: Length 0)", null, false);
                malformed.AddLeaf("Type: " + NdpOptionName(option.Type) + " (" + option.Type + ")");
                malformed.AddLeaf("Length: 0 (0 bytes)");
                root.Add(malformed);
                break;
            }
            if (option.Status == OPTION_TRUNCATED)
            {
                BoxyBox.TreeNode truncated = new BoxyBox.TreeNode(
                    "ICMPv6 Option (Truncated: " + NdpOptionName(option.Type) + ")", null, false);
                truncated.AddLeaf("Type: " + NdpOptionName(option.Type) + " (" + option.Type + ")");
                if (option.LengthUnits >= 0)
                    truncated.AddLeaf("Length: " + option.LengthUnits + " (" + option.LengthBytes + " bytes)");
                truncated.AddLeaf("Captured Bytes: " + option.AvailableBytes);
                root.Add(truncated);
                break;
            }

            root.Add(BuildOptionNode(data, option));
        }
    }

    private static BoxyBox.TreeNode BuildOptionNode(byte[] data, NdpOptionFrame option)
    {
        switch (option.Type)
        {
            case OPT_SOURCE_LINK_ADDR:
                return BuildLinkLayerOption(data, option, true);
            case OPT_TARGET_LINK_ADDR:
                return BuildLinkLayerOption(data, option, false);
            case OPT_PREFIX_INFO:
                return BuildPrefixOption(data, option);
            case OPT_REDIRECTED_HDR:
                return BuildRedirectedHeaderOption(data, option);
            case OPT_MTU:
                return BuildMtuOption(data, option);
            case OPT_ROUTE_INFO:
                return BuildRouteOption(data, option);
            case OPT_RDNSS:
                return BuildRdnssOption(data, option);
            case OPT_DNSSL:
                return BuildDnsslOption(data, option);
            default:
                return BuildUnknownOption(data, option);
        }
    }

    private static BoxyBox.TreeNode BuildLinkLayerOption(byte[] data, NdpOptionFrame option, bool source)
    {
        string name = source ? "Source link-layer address" : "Target link-layer address";
        string address = FormatColonBytes(data, option.PayloadOffset, option.LengthBytes - 2);
        BoxyBox.TreeNode node = CreateOptionNode("ICMPv6 Option (" + name + " : " + address + ")",
            name, option);
        node.AddLeaf("Link-layer address: " + address);
        return node;
    }

    private static BoxyBox.TreeNode BuildPrefixOption(byte[] data, NdpOptionFrame option)
    {
        if (option.LengthBytes != 32)
            return BuildMalformedContentOption("Prefix information", option, "Expected 32 bytes");

        int prefixLength = data[option.PayloadOffset];
        byte flags = data[option.PayloadOffset + 1];
        string prefix = PacketParseHelper.FormatIPv6(data, option.PayloadOffset + 14);
        BoxyBox.TreeNode node = CreateOptionNode(
            "ICMPv6 Option (Prefix information : " + prefix + "/" + prefixLength + ")",
            "Prefix information", option);
        node.AddLeaf("Prefix Length: " + prefixLength);
        node.Add(BuildPrefixFlagsNode(flags));
        node.AddLeaf("Valid Lifetime: " + FormatLifetime(PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 2)));
        node.AddLeaf("Preferred Lifetime: " + FormatLifetime(PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 6)));
        node.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 10));
        node.AddLeaf("Prefix: " + prefix);
        return node;
    }

    private static BoxyBox.TreeNode BuildPrefixFlagsNode(byte flags)
    {
        StringBuilder summary = new StringBuilder("Flags: 0x");
        summary.Append(flags.ToString("x2"));
        if ((flags & 0x80) != 0) summary.Append(", On-link");
        if ((flags & 0x40) != 0) summary.Append(", Autonomous");
        if ((flags & 0x20) != 0) summary.Append(", Router address");

        BoxyBox.TreeNode node = new BoxyBox.TreeNode(summary.ToString(), null, false);
        node.AddLeaf(FormatBitPattern(flags, 0x80, 8) + " = On-link: " + SetState((flags & 0x80) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x40, 8) + " = Autonomous address configuration: " + SetState((flags & 0x40) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x20, 8) + " = Router address: " + SetState((flags & 0x20) != 0));
        node.AddLeaf(FormatBitPattern(flags, 0x1F, 8) + " = Reserved: " + (flags & 0x1F));
        return node;
    }

    private static BoxyBox.TreeNode BuildRedirectedHeaderOption(byte[] data, NdpOptionFrame option)
    {
        if (option.LengthBytes < 8)
            return BuildMalformedContentOption("Redirected header", option, "Expected at least 8 bytes");
        BoxyBox.TreeNode node = CreateOptionNode("ICMPv6 Option (Redirected header)",
            "Redirected header", option);
        node.AddLeaf("Reserved: " + PacketParseHelper.FormatHexPreview(data, option.PayloadOffset, 6, 6));
        int dataLength = option.LengthBytes - 8;
        node.AddLeaf("Redirected packet: " + dataLength + " bytes; Data: "
            + PacketParseHelper.FormatHexPreview(data, option.PayloadOffset + 6, dataLength, 32));
        return node;
    }

    private static BoxyBox.TreeNode BuildMtuOption(byte[] data, NdpOptionFrame option)
    {
        if (option.LengthBytes != 8)
            return BuildMalformedContentOption("MTU", option, "Expected 8 bytes");
        uint mtu = PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 2);
        BoxyBox.TreeNode node = CreateOptionNode("ICMPv6 Option (MTU : " + mtu + ")", "MTU", option);
        node.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt16BE(data, option.PayloadOffset));
        node.AddLeaf("MTU: " + mtu);
        return node;
    }

    private static BoxyBox.TreeNode BuildRouteOption(byte[] data, NdpOptionFrame option)
    {
        if (option.LengthUnits < 1 || option.LengthUnits > 3)
            return BuildMalformedContentOption("Route information", option, "Expected length 1, 2, or 3");

        int prefixLength = data[option.PayloadOffset];
        byte flags = data[option.PayloadOffset + 1];
        uint lifetime = PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 2);
        int prefixBytes = option.LengthBytes - 8;
        byte[] prefixBuffer = new byte[16];
        if (prefixBytes > 0) Buffer.BlockCopy(data, option.PayloadOffset + 6, prefixBuffer, 0, prefixBytes);
        string prefix = PacketParseHelper.FormatIPv6(prefixBuffer, 0);
        BoxyBox.TreeNode node = CreateOptionNode(
            "ICMPv6 Option (Route information : " + prefix + "/" + prefixLength + ")",
            "Route information", option);
        node.AddLeaf("Prefix Length: " + prefixLength);
        node.Add(BuildRouteFlagsNode(flags));
        node.AddLeaf("Route Lifetime: " + FormatLifetime(lifetime));
        node.AddLeaf("Prefix: " + prefix);
        return node;
    }

    private static BoxyBox.TreeNode BuildRouteFlagsNode(byte flags)
    {
        int preference = (flags >> 3) & 0x3;
        BoxyBox.TreeNode node = new BoxyBox.TreeNode(
            "Flags: 0x" + flags.ToString("x2") + ", Route Preference " + PrefName(preference),
            null, false);
        node.AddLeaf(FormatBitPattern(flags, 0x18, 8) + " = Route Preference: " + PrefName(preference));
        node.AddLeaf(FormatBitPattern(flags, 0xE7, 8) + " = Reserved: " + (flags & 0xE7));
        return node;
    }

    private static BoxyBox.TreeNode BuildRdnssOption(byte[] data, NdpOptionFrame option)
    {
        int addressBytes = option.LengthBytes - 8;
        if (option.LengthBytes < 24 || addressBytes % 16 != 0)
            return BuildMalformedContentOption("Recursive DNS server", option,
                "Expected 8-byte header plus one or more 16-byte addresses");

        uint lifetime = PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 2);
        BoxyBox.TreeNode node = CreateOptionNode("ICMPv6 Option (Recursive DNS server)",
            "Recursive DNS server", option);
        node.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt16BE(data, option.PayloadOffset));
        node.AddLeaf("Lifetime: " + FormatLifetime(lifetime));
        int serverOffset = option.PayloadOffset + 6;
        for (int i = 0; i < addressBytes / 16; i++)
            node.AddLeaf("Recursive DNS Server: " + PacketParseHelper.FormatIPv6(data, serverOffset + i * 16));
        return node;
    }

    private static BoxyBox.TreeNode BuildDnsslOption(byte[] data, NdpOptionFrame option)
    {
        if (option.LengthBytes < 16)
            return BuildMalformedContentOption("DNS search list", option, "Expected at least 16 bytes");

        BoxyBox.TreeNode node = CreateOptionNode("ICMPv6 Option (DNS search list)",
            "DNS search list", option);
        node.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt16BE(data, option.PayloadOffset));
        node.AddLeaf("Lifetime: " + FormatLifetime(
            PacketParseHelper.ReadUInt32BE(data, option.PayloadOffset + 2)));
        AppendDnsslDomains(node, data, option.PayloadOffset + 6, option.End);
        return node;
    }

    private static void AppendDnsslDomains(BoxyBox.TreeNode node, byte[] data, int start, int end)
    {
        int position = start;
        int domainCount = 0;
        while (position < end && domainCount++ < 32)
        {
            if (data[position] == 0) break;
            StringBuilder domain = new StringBuilder();
            int labelCount = 0;
            bool malformed = false;
            bool terminated = false;
            while (position < end && labelCount++ < 64)
            {
                int labelLength = data[position++];
                if (labelLength == 0)
                {
                    terminated = true;
                    break;
                }
                if ((labelLength & 0xC0) != 0 || position + labelLength > end)
                {
                    malformed = true;
                    break;
                }
                if (domain.Length > 0) domain.Append('.');
                for (int i = 0; i < labelLength; i++)
                {
                    byte value = data[position + i];
                    domain.Append(value >= 0x20 && value <= 0x7E ? (char)value : '?');
                }
                position += labelLength;
            }
            if (malformed || !terminated)
            {
                node.AddLeaf("Malformed Domain Name");
                return;
            }
            if (domain.Length > 0) node.AddLeaf("Domain Name: " + domain.ToString());
        }
        if (position < end && data[position] != 0) node.AddLeaf("Malformed Domain Name");
    }

    private static BoxyBox.TreeNode BuildUnknownOption(byte[] data, NdpOptionFrame option)
    {
        BoxyBox.TreeNode node = CreateOptionNode(
            "ICMPv6 Option (Unknown : " + option.Type + ")", "Unknown", option);
        node.AddLeaf("Data: " + PacketParseHelper.FormatHexPreview(
            data, option.PayloadOffset, option.LengthBytes - 2, 32));
        return node;
    }

    private static BoxyBox.TreeNode BuildMalformedContentOption(
        string name, NdpOptionFrame option, string reason)
    {
        BoxyBox.TreeNode node = CreateOptionNode(
            "ICMPv6 Option (" + name + ", malformed)", name, option);
        node.AddLeaf("Malformed: " + reason);
        return node;
    }

    private static BoxyBox.TreeNode CreateOptionNode(
        string summary, string name, NdpOptionFrame option)
    {
        BoxyBox.TreeNode node = new BoxyBox.TreeNode(summary, null, false);
        node.AddLeaf("Type: " + name + " (" + option.Type + ")");
        node.AddLeaf("Length: " + option.LengthUnits + " (" + option.LengthBytes + " bytes)");
        return node;
    }

    private static bool TryReadOption(
        byte[] data, ref int position, int end, out NdpOptionFrame option)
    {
        option = new NdpOptionFrame();
        option.Offset = position;
        option.LengthUnits = -1;
        option.AvailableBytes = end - position;
        if (position >= end) return false;

        option.Type = data[position];
        if (position + 2 > end)
        {
            option.Status = OPTION_TRUNCATED;
            position = end;
            return true;
        }

        option.LengthUnits = data[position + 1];
        if (option.LengthUnits == 0)
        {
            option.Status = OPTION_ZERO_LENGTH;
            position = end;
            return true;
        }

        option.LengthBytes = option.LengthUnits * 8;
        option.PayloadOffset = position + 2;
        option.End = position + option.LengthBytes;
        if (option.End > end)
        {
            option.Status = OPTION_TRUNCATED;
            position = end;
            return true;
        }

        option.Status = OPTION_VALID;
        option.AvailableBytes = option.LengthBytes;
        position = option.End;
        return true;
    }

    private static string FormatColonBytes(byte[] data, int offset, int count)
    {
        StringBuilder builder = new StringBuilder(count * 3);
        for (int i = 0; i < count; i++)
        {
            if (i > 0) builder.Append(':');
            builder.Append(data[offset + i].ToString("x2"));
        }
        return builder.ToString();
    }

    private static string FormatBitPattern(ulong value, ulong mask, int bitCount)
    {
        StringBuilder builder = new StringBuilder(bitCount + bitCount / 4);
        for (int bit = bitCount - 1; bit >= 0; bit--)
        {
            ulong bitMask = 1UL << bit;
            builder.Append((mask & bitMask) == 0 ? '.'
                : ((value & bitMask) == 0 ? '0' : '1'));
            if (bit > 0 && bit % 4 == 0) builder.Append(' ');
        }
        return builder.ToString();
    }

    private static string SetState(bool set)
    {
        return set ? "Set" : "Not set";
    }

    private static string NdpTypeName(int type)
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

    private static string NdpOptionName(int type)
    {
        switch (type)
        {
            case OPT_SOURCE_LINK_ADDR: return "Source link-layer address";
            case OPT_TARGET_LINK_ADDR: return "Target link-layer address";
            case OPT_PREFIX_INFO: return "Prefix information";
            case OPT_REDIRECTED_HDR: return "Redirected header";
            case OPT_MTU: return "MTU";
            case OPT_ROUTE_INFO: return "Route information";
            case OPT_RDNSS: return "Recursive DNS server";
            case OPT_DNSSL: return "DNS search list";
            default: return "Unknown";
        }
    }

    /// <summary>
    /// Formats an NDP message (types 133-137) into a single Detailed-tier line.
    /// <paramref name="icmpv6Off"/> points at the ICMPv6 type byte; the parser
    /// reads up to <paramref name="icmpv6Len"/> bytes from there.
    /// </summary>
    public static string FormatNdpDetailed(byte[] data, int icmpv6Off, int icmpv6Len)
    {
        if (data == null || icmpv6Off < 0 || icmpv6Len < 4
            || icmpv6Off + icmpv6Len > data.Length)
        {
            return null;
        }

        int icmpv6Type = data[icmpv6Off];
        switch (icmpv6Type)
        {
            case 133: return FormatRouterSolicitation(data, icmpv6Off, icmpv6Len);
            case 134: return FormatRouterAdvertisement(data, icmpv6Off, icmpv6Len);
            case 135: return FormatNeighborSolicitation(data, icmpv6Off, icmpv6Len);
            case 136: return FormatNeighborAdvertisement(data, icmpv6Off, icmpv6Len);
            case 137: return FormatRedirect(data, icmpv6Off, icmpv6Len);
            default:  return "NDP type " + icmpv6Type.ToString();
        }
    }

    /// <summary>
    /// Formats an NDP message (types 133-137) in the ICMPv6 parser spec's one-liner form
    /// (e.g. "ICMPv6.Router Solicitation from &lt;mac&gt;"). When <paramref name="detailed"/> is
    /// true the rich option/field tail from <see cref="FormatNdpDetailed"/> is appended so no
    /// information is lost at the Detailed level.
    /// </summary>
    public static string FormatNdpSpec(byte[] data, int icmpv6Off, int icmpv6Len, bool detailed)
    {
        if (data == null || icmpv6Off < 0 || icmpv6Len < 4 || icmpv6Off + icmpv6Len > data.Length)
        {
            return null;
        }

        int type = data[icmpv6Off];
        int end = icmpv6Off + icmpv6Len;
        string lead;
        switch (type)
        {
            case 133: // Router Solicitation
            {
                string srcLL = FindLinkLayerAddr(data, icmpv6Off + 8, end, OPT_SOURCE_LINK_ADDR);
                lead = "ICMPv6.Router Solicitation" + (srcLL != null ? " from " + srcLL : "");
                break;
            }
            case 134: // Router Advertisement
            {
                string srcLL = icmpv6Len >= 16 ? FindLinkLayerAddr(data, icmpv6Off + 16, end, OPT_SOURCE_LINK_ADDR) : null;
                lead = "ICMPv6.Router Advertisement" + (srcLL != null ? " from " + srcLL : "");
                break;
            }
            case 135: // Neighbor Solicitation
            {
                string target = icmpv6Len >= 24 ? FormatIPv6(data, icmpv6Off + 8) : "?";
                string srcLL = icmpv6Len >= 24 ? FindLinkLayerAddr(data, icmpv6Off + 24, end, OPT_SOURCE_LINK_ADDR) : null;
                lead = "ICMPv6.Neighbor Solicitation for " + target + (srcLL != null ? " from " + srcLL : "");
                break;
            }
            case 136: // Neighbor Advertisement
            {
                string target = icmpv6Len >= 24 ? FormatIPv6(data, icmpv6Off + 8) : "?";
                string tgtLL = icmpv6Len >= 24 ? FindLinkLayerAddr(data, icmpv6Off + 24, end, OPT_TARGET_LINK_ADDR) : null;
                byte naFlags = icmpv6Len >= 5 ? data[icmpv6Off + 4] : (byte)0;
                lead = "ICMPv6.Neighbor Advertisement " + target + " (" + NaFlags(naFlags) + ")"
                     + (tgtLL != null ? " is at " + tgtLL : "");
                break;
            }
            case 137: // Redirect
            {
                string target = icmpv6Len >= 40 ? FormatIPv6(data, icmpv6Off + 8) : "?";
                string dest = icmpv6Len >= 40 ? FormatIPv6(data, icmpv6Off + 24) : "?";
                lead = "ICMPv6.Redirect for " + dest + " to " + target;
                break;
            }
            default:
                lead = "ICMPv6.NDP type " + type;
                break;
        }

        if (!detailed) return lead;

        string full = FormatNdpDetailed(data, icmpv6Off, icmpv6Len);
        if (string.IsNullOrEmpty(full)) return lead;
        // Append the option/field tail, dropping the Source/Target Link-layer segments already
        // represented in the "from" / "is at" lead.
        string[] segs = full.Split(';');
        StringBuilder tail = new StringBuilder(full.Length);
        for (int i = 1; i < segs.Length; i++)
        {
            string seg = segs[i].Trim();
            if (seg.StartsWith("SrcLL") || seg.StartsWith("TgtLL")) continue;
            tail.Append("; ").Append(seg);
        }
        return lead + tail.ToString();
    }

    // NA flag summary (rtr/sol/ovr) per the ICMPv6 parser spec.
    private static string NaFlags(byte naFlags)
    {
        StringBuilder sb = new StringBuilder(16);
        if (((naFlags >> 7) & 1) != 0) sb.Append("rtr");
        if (((naFlags >> 6) & 1) != 0) { if (sb.Length > 0) sb.Append(", "); sb.Append("sol"); }
        if (((naFlags >> 5) & 1) != 0) { if (sb.Length > 0) sb.Append(", "); sb.Append("ovr"); }
        return sb.ToString();
    }

    // Scans an NDP option block for a Source/Target Link-layer Address option and returns its MAC.
    private static string FindLinkLayerAddr(byte[] data, int optOff, int optEnd, int wantType)
    {
        if (optOff < 0 || optEnd > data.Length) return null;
        int pos = optOff;
        int safety = 32;
        while (pos + 2 <= optEnd && safety-- > 0)
        {
            int optType = data[pos];
            int optLen8 = data[pos + 1];
            if (optLen8 == 0) break;
            int optBytes = optLen8 * 8;
            if (pos + optBytes > optEnd) break;
            if (optType == wantType && optBytes >= 8) return FormatMac(data, pos + 2);
            pos += optBytes;
        }
        return null;
    }

    // ---- Router Solicitation (RS, RFC 4861 §4.1) ----
    // Body: Type(1) Code(1) Checksum(2) Reserved(4); options follow.
    private static string FormatRouterSolicitation(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(64);
        sb.Append("NDP RouterSolicitation");
        if (len >= 8)
        {
            AppendOptions(sb, data, off + 8, off + len);
        }
        return sb.ToString();
    }

    // ---- Router Advertisement (RA, RFC 4861 §4.2) ----
    // Body: Type(1) Code(1) Checksum(2) CurHopLimit(1) Flags(1)
    //       RouterLifetime(2 BE) ReachableTime(4 BE) RetransTimer(4 BE);
    //       options follow at offset 16.
    private static string FormatRouterAdvertisement(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(160);
        sb.Append("NDP RouterAdvertisement");
        if (len >= 16)
        {
            int hopLim     = data[off + 4];
            byte flags     = data[off + 5];
            int routerLife = (data[off + 6] << 8) | data[off + 7];
            uint reachMs   = ReadUInt32BE(data, off + 8);
            uint retransMs = ReadUInt32BE(data, off + 12);

            // Flag bits (per RFC 4861 + RFC 4191): M (0x80), O (0x40), H (0x20),
            // Prf (0x18, 2 bits — 00 medium, 01 high, 10 reserved, 11 low),
            // P (0x04, RFC 4389).
            int m   = (flags >> 7) & 1;
            int o   = (flags >> 6) & 1;
            int h   = (flags >> 5) & 1;
            int prf = (flags >> 3) & 0x3;

            sb.Append("; HopLim ").Append(hopLim);
            sb.Append("; M=").Append(m).Append(" O=").Append(o);
            if (h != 0) sb.Append(" H=1");
            sb.Append(" Pref=").Append(PrefName(prf));
            sb.Append("; Lifetime ").Append(routerLife).Append("s");
            sb.Append("; ReachTime ").Append(reachMs).Append("ms");
            sb.Append("; RetransTimer ").Append(retransMs).Append("ms");

            AppendOptions(sb, data, off + 16, off + len);
        }
        return sb.ToString();
    }

    // ---- Neighbor Solicitation (NS, RFC 4861 §4.3) ----
    // Body: Type(1) Code(1) Checksum(2) Reserved(4) TargetAddress(16);
    //       options at offset 24.
    private static string FormatNeighborSolicitation(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(96);
        sb.Append("NDP NeighborSolicitation");
        if (len >= 24)
        {
            sb.Append("; Target ").Append(FormatIPv6(data, off + 8));
            AppendOptions(sb, data, off + 24, off + len);
        }
        return sb.ToString();
    }

    // ---- Neighbor Advertisement (NA, RFC 4861 §4.4) ----
    // Body: Type(1) Code(1) Checksum(2) Flags(4 — only top 3 bits used)
    //       TargetAddress(16); options at offset 24.
    private static string FormatNeighborAdvertisement(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(96);
        sb.Append("NDP NeighborAdvertisement");
        if (len >= 24)
        {
            byte naFlags = data[off + 4];
            int r = (naFlags >> 7) & 1;
            int s = (naFlags >> 6) & 1;
            int o = (naFlags >> 5) & 1;
            sb.Append("; Target ").Append(FormatIPv6(data, off + 8));
            sb.Append("; R=").Append(r).Append(" S=").Append(s).Append(" O=").Append(o);
            AppendOptions(sb, data, off + 24, off + len);
        }
        return sb.ToString();
    }

    // ---- Redirect (RFC 4861 §4.5) ----
    // Body: Type(1) Code(1) Checksum(2) Reserved(4) TargetAddress(16)
    //       DestinationAddress(16); options at offset 40.
    private static string FormatRedirect(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(96);
        sb.Append("NDP Redirect");
        if (len >= 40)
        {
            sb.Append("; Target ").Append(FormatIPv6(data, off + 8));
            sb.Append("; Dest ").Append(FormatIPv6(data, off + 24));
            AppendOptions(sb, data, off + 40, off + len);
        }
        return sb.ToString();
    }

    // ---- Option walker ----
    // RFC 4861 §4.6: every option is Type(1) Length(1, in 8-byte units including
    // these two bytes) followed by (Length*8 - 2) payload bytes. Walks the
    // option block until the end-of-buffer or a length=0 (malformed) entry.
    private static void AppendOptions(StringBuilder sb, byte[] data, int optOff, int optEnd)
    {
        if (optOff < 0 || optEnd > data.Length || optOff >= optEnd) return;

        int pos = optOff;
        int safety = 32;
        while (pos < optEnd && safety-- > 0)
        {
            NdpOptionFrame option;
            if (!TryReadOption(data, ref pos, optEnd, out option)
                || option.Status != OPTION_VALID)
            {
                break;
            }
            int optType = option.Type;
            int optBytes = option.LengthBytes;
            int optionStart = option.Offset;

            switch (optType)
            {
                case OPT_SOURCE_LINK_ADDR:
                    if (optBytes >= 8)
                    {
                        sb.Append("; SrcLL ").Append(FormatMac(data, optionStart + 2));
                    }
                    break;

                case OPT_TARGET_LINK_ADDR:
                    if (optBytes >= 8)
                    {
                        sb.Append("; TgtLL ").Append(FormatMac(data, optionStart + 2));
                    }
                    break;

                case OPT_MTU:
                    if (optBytes >= 8)
                    {
                        uint mtu = ReadUInt32BE(data, optionStart + 4);
                        sb.Append("; MTU ").Append(mtu);
                    }
                    break;

                case OPT_PREFIX_INFO:
                    if (optBytes >= 32)
                    {
                        int prefLen      = data[optionStart + 2];
                        byte prefixFlags = data[optionStart + 3];
                        int onLink       = (prefixFlags >> 7) & 1; // L
                        int autoConf     = (prefixFlags >> 6) & 1; // A
                        uint validLife   = ReadUInt32BE(data, optionStart + 4);
                        uint preferLife  = ReadUInt32BE(data, optionStart + 8);
                        string prefix    = FormatIPv6(data, optionStart + 16);
                        sb.Append("; Prefix ").Append(prefix).Append('/').Append(prefLen);
                        sb.Append(" L=").Append(onLink).Append(" A=").Append(autoConf);
                        sb.Append(" Valid ").Append(FormatLifetime(validLife));
                        sb.Append(" Pref ").Append(FormatLifetime(preferLife));
                    }
                    break;

                case OPT_RDNSS:
                    if (optBytes >= 8 + 16)
                    {
                        uint life = ReadUInt32BE(data, optionStart + 4);
                        int addrBytes = optBytes - 8;
                        int nServers = addrBytes / 16;
                        sb.Append("; RDNSS Lifetime ").Append(FormatLifetime(life));
                        for (int i = 0; i < nServers && i < 4; i++)
                        {
                            sb.Append(' ').Append(FormatIPv6(data, optionStart + 8 + i * 16));
                        }
                        if (nServers > 4) sb.Append(" +").Append(nServers - 4).Append(" more");
                    }
                    break;

                case OPT_DNSSL:
                    if (optBytes >= 8)
                    {
                        uint life = ReadUInt32BE(data, optionStart + 4);
                        sb.Append("; DNSSL Lifetime ").Append(FormatLifetime(life));
                    }
                    break;

                case OPT_REDIRECTED_HDR:
                    sb.Append("; RedirHdr (").Append(optBytes - 8).Append("B)");
                    break;

                case OPT_ROUTE_INFO:
                    // 1-byte prefix length + flags + 4-byte route lifetime + variable prefix bytes.
                    if (optBytes >= 8)
                    {
                        int rPrefLen = data[optionStart + 2];
                        uint rLife   = ReadUInt32BE(data, optionStart + 4);
                        sb.Append("; Route /").Append(rPrefLen).Append(" Lifetime ").Append(FormatLifetime(rLife));
                    }
                    break;

                default:
                    sb.Append("; Opt").Append(optType).Append(" (").Append(optBytes).Append("B)");
                    break;
            }

        }
    }

    // ---- Helpers (kept private to avoid colliding with the formatter's helpers) ----

    private static string PrefName(int prf)
    {
        switch (prf)
        {
            case 0: return "Medium";
            case 1: return "High";
            case 2: return "Reserved";
            case 3: return "Low";
            default: return prf.ToString();
        }
    }

    // 0xFFFFFFFF lifetime means "infinite" in NDP semantics.
    private static string FormatLifetime(uint seconds)
    {
        if (seconds == 0xFFFFFFFFu) return "Infinite";
        return seconds.ToString() + "s";
    }

    private static uint ReadUInt32BE(byte[] data, int offset)
    {
        return (uint)((data[offset] << 24) | (data[offset + 1] << 16) |
                      (data[offset + 2] << 8) | data[offset + 3]);
    }

    private static string FormatIPv6(byte[] data, int offset)
    {
        return PacketParseHelper.FormatIPv6(data, offset);
    }

    private static string FormatMac(byte[] data, int offset)
    {
        return PacketParseHelper.FormatMac(data, offset);
    }

    private struct NdpOptionFrame
    {
        public int Offset;
        public int Type;
        public int LengthUnits;
        public int LengthBytes;
        public int PayloadOffset;
        public int End;
        public int Status;
        public int AvailableBytes;
    }
}
