using System;
using System.Collections.Generic;
using System.Text;

public static class SshParser
{
    private const int MaximumIdentificationLength = 255;
    private const int SshPort = 22;
    private const int GerritSshPort = 29418;

    public static bool LooksLikeSsh(byte[] data, int len, int srcPort, int dstPort)
    {
        int dataLength = ClampLength(data, len);
        if (dataLength == 0) return false;

        int identificationEnd;
        string protocolVersion;
        string softwareVersion;
        string comments;
        if (TryParseIdentification(data, dataLength, out identificationEnd, out protocolVersion, out softwareVersion, out comments))
        {
            return true;
        }

        return IsSshPort(srcPort) || IsSshPort(dstPort);
    }

    public static string FormatSshSegment(byte[] data, int len, int srcPort, int dstPort)
    {
        int dataLength = ClampLength(data, len);
        if (dataLength == 0) return null;

        int identificationEnd;
        string protocolVersion;
        string softwareVersion;
        string comments;
        if (TryParseIdentification(data, dataLength, out identificationEnd, out protocolVersion, out softwareVersion, out comments))
        {
            int lineEnd = identificationEnd;
            while (lineEnd > 0 && (data[lineEnd - 1] == 0x0A || data[lineEnd - 1] == 0x0D)) lineEnd--;
            return "SSH Protocol: " + Encoding.ASCII.GetString(data, 0, lineEnd);
        }

        if (!IsSshPort(srcPort) && !IsSshPort(dstPort)) return null;
        if (LooksLikeCompleteSsh2Packet(data, dataLength))
        {
            int messageCode = data[5];
            if (messageCode == 0) return "SSH Encrypted or unparsed payload";
            return "SSH Version 2: " + GetSsh2DisplayName(messageCode);
        }
        if (LooksLikeStandaloneSsh1Packet(data, dataLength))
        {
            int packetLength = (int)PacketParseHelper.ReadUInt32BE(data, 0);
            int paddingLength = 8 - (packetLength % 8);
            return "SSH Version 1: " + GetSsh1MessageName(data[4 + paddingLength]);
        }
        if (LooksLikeTruncatedSsh2Packet(data, dataLength)) return "SSH Version 2: Truncated packet";
        return "SSH Encrypted or unparsed payload";
    }

    internal static bool LooksLikeSshIdentification(byte[] data, int offset, int len)
    {
        int contentEnd;
        int identificationEnd;
        int versionEnd;
        int softwareEnd;
        return TryFindIdentification(data, offset, len, out contentEnd, out identificationEnd,
            out versionEnd, out softwareEnd);
    }

    public static List<BoxyBox.TreeNode> BuildSshDetailTree(byte[] data, int len, int srcPort, int dstPort)
    {
        List<BoxyBox.TreeNode> roots = new List<BoxyBox.TreeNode>();
        int dataLength = ClampLength(data, len);
        if (dataLength == 0) return roots;

        int identificationEnd;
        string protocolVersion;
        string softwareVersion;
        string comments;
        if (TryParseIdentification(data, dataLength, out identificationEnd, out protocolVersion, out softwareVersion, out comments))
        {
            roots.Add(BuildIdentificationNode(data, identificationEnd, protocolVersion, softwareVersion,
                comments, srcPort, dstPort));
            if (identificationEnd < dataLength)
            {
                if (GetSshVersion(protocolVersion) == 2)
                    AppendSsh2Packets(data, identificationEnd, dataLength, roots);
                else
                    AppendSsh1Packet(data, identificationEnd, dataLength, roots);
            }
            return roots;
        }

        if (IsSshPort(srcPort) || IsSshPort(dstPort))
        {
            if (!LooksLikeCompleteSsh2Packet(data, dataLength) && LooksLikeStandaloneSsh1Packet(data, dataLength))
                AppendSsh1Packet(data, 0, dataLength, roots);
            else
                AppendSsh2Packets(data, 0, dataLength, roots);
        }
        return roots;
    }

    private static BoxyBox.TreeNode BuildIdentificationNode(byte[] data, int identificationEnd,
        string protocolVersion, string softwareVersion, string comments, int srcPort, int dstPort)
    {
        int lineEnd = identificationEnd;
        while (lineEnd > 0 && (data[lineEnd - 1] == 0x0A || data[lineEnd - 1] == 0x0D)) lineEnd--;
        string identification = Encoding.ASCII.GetString(data, 0, lineEnd);
        BoxyBox.TreeNode root = new BoxyBox.TreeNode("SSH Protocol: " + identification, "SSH", false);
        root.AddLeaf("Protocol Version: " + protocolVersion);
        root.AddLeaf("SSH Version: " + GetSshVersion(protocolVersion));
        root.AddLeaf("Software Version: " + softwareVersion);
        if (!string.IsNullOrEmpty(comments)) root.AddLeaf("Comments: " + comments);

        string flowDirection = GetFlowDirection(srcPort, dstPort);
        if (flowDirection != null) root.AddLeaf("Flow direction (by service port): " + flowDirection);
        return root;
    }

    private static void AppendSsh1Packet(byte[] data, int start, int end, List<BoxyBox.TreeNode> roots)
    {
        int remaining = end - start;
        if (remaining < 4)
        {
            roots.Add(BuildUnparsedNode(data, start, remaining));
            return;
        }

        uint declaredLength = PacketParseHelper.ReadUInt32BE(data, start);
        if (declaredLength < 1 || declaredLength >= 0xFFFF)
        {
            roots.Add(BuildUnparsedNode(data, start, remaining));
            return;
        }

        int packetLength = (int)declaredLength;
        int paddingLength = 8 - (packetLength % 8);
        int totalLength = 4 + paddingLength + packetLength;
        if (totalLength > remaining)
        {
            BoxyBox.TreeNode truncated = new BoxyBox.TreeNode("SSH Version 1: Truncated packet", "SSH", false);
            truncated.AddLeaf("Packet Length: " + packetLength);
            truncated.AddLeaf("Captured Bytes: " + remaining + " of " + totalLength);
            roots.Add(truncated);
            return;
        }

        int messageOffset = start + 4 + paddingLength;
        int messageCode = data[messageOffset];
        string messageName = GetSsh1MessageName(messageCode);
        BoxyBox.TreeNode root = new BoxyBox.TreeNode("SSH Version 1: " + messageName, "SSH", false);
        BoxyBox.TreeNode packet = new BoxyBox.TreeNode("Binary Packet", "SSH.Packet", false);
        packet.AddLeaf("Packet Length: " + packetLength);
        packet.AddLeaf("Padding Length: " + paddingLength);
        packet.AddLeaf("Message Code: " + messageName + " (" + messageCode + ")");
        root.Add(packet);

        int payloadLength = packetLength - 1;
        if (payloadLength > 0)
        {
            root.AddLeaf("Payload: " + payloadLength + " bytes; Data: "
                + PacketParseHelper.FormatHexPreview(data, messageOffset + 1, payloadLength, 32));
        }
        root.AddLeaf("Padding: " + paddingLength + " bytes; Data: "
            + PacketParseHelper.FormatHexPreview(data, start + 4, paddingLength, 16));
        roots.Add(root);
    }

    private static void AppendSsh2Packets(byte[] data, int start, int end, List<BoxyBox.TreeNode> roots)
    {
        int position = start;
        int packetCount = 0;
        while (position < end && packetCount++ < 64)
        {
            int remaining = end - position;
            if (remaining < 5)
            {
                roots.Add(BuildUnparsedNode(data, position, remaining));
                break;
            }

            uint declaredLength = PacketParseHelper.ReadUInt32BE(data, position);
            if (declaredLength > 0xFFFF)
            {
                roots.Add(BuildUnparsedNode(data, position, remaining));
                break;
            }

            int packetLength = (int)declaredLength;
            int paddingLength = data[position + 4];
            if (packetLength < 6 || paddingLength < 4 || packetLength - paddingLength - 1 < 1
                || ((4 + packetLength) % 8) != 0)
            {
                roots.Add(BuildUnparsedNode(data, position, remaining));
                break;
            }

            int totalLength = 4 + packetLength;
            if (totalLength > remaining)
            {
                BoxyBox.TreeNode truncated = new BoxyBox.TreeNode("SSH Version 2: Truncated packet", "SSH", false);
                BoxyBox.TreeNode framing = new BoxyBox.TreeNode("Binary Packet", "SSH.Packet", false);
                framing.AddLeaf("Packet Length: " + packetLength);
                framing.AddLeaf("Padding Length: " + paddingLength);
                framing.AddLeaf("Captured Bytes: " + remaining + " of " + totalLength);
                truncated.Add(framing);
                roots.Add(truncated);
                break;
            }

            int payloadLength = packetLength - paddingLength - 1;

            int payloadStart = position + 5;
            int messageCode = data[payloadStart];
            if (messageCode == 0)
            {
                roots.Add(BuildUnparsedNode(data, position, remaining));
                break;
            }
            string messageName = GetSsh2MessageName(messageCode);
            string rootMessageName = GetSsh2DisplayName(messageCode);
            BoxyBox.TreeNode root = new BoxyBox.TreeNode("SSH Version 2: " + rootMessageName, "SSH", false);
            BoxyBox.TreeNode packet = new BoxyBox.TreeNode("Binary Packet", "SSH.Packet", false);
            packet.AddLeaf("Packet Length: " + packetLength);
            packet.AddLeaf("Padding Length: " + paddingLength);
            packet.AddLeaf("Message Code: " + messageName + " (" + messageCode + ")");
            root.Add(packet);

            int messageBodyStart = payloadStart + 1;
            int payloadEnd = payloadStart + payloadLength;
            if (messageCode == 20)
            {
                root.Add(BuildKexInitNode(data, messageBodyStart, payloadEnd));
            }
            else if (payloadEnd > messageBodyStart)
            {
                root.AddLeaf("Payload: " + (payloadEnd - messageBodyStart) + " bytes; Data: "
                    + PacketParseHelper.FormatHexPreview(data, messageBodyStart, payloadEnd - messageBodyStart, 32));
            }

            int paddingStart = payloadEnd;
            root.AddLeaf("Padding: " + paddingLength + " bytes; Data: "
                + PacketParseHelper.FormatHexPreview(data, paddingStart, paddingLength, 16));
            roots.Add(root);
            position += totalLength;
        }
    }

    private static BoxyBox.TreeNode BuildKexInitNode(byte[] data, int start, int end)
    {
        BoxyBox.TreeNode node = new BoxyBox.TreeNode("Key Exchange Init", "SSH.KexInit", false);
        int position = start;
        if (position + 16 > end)
        {
            node.AddLeaf("Truncated: Cookie");
            return node;
        }

        node.AddLeaf("Cookie: " + PacketParseHelper.FormatHexPreview(data, position, 16, 16));
        position += 16;

        string[] labels = new string[]
        {
            "Key Exchange Algorithms",
            "Server Host Key Algorithms",
            "Encryption Algorithms Client to Server",
            "Encryption Algorithms Server to Client",
            "MAC Algorithms Client to Server",
            "MAC Algorithms Server to Client",
            "Compression Algorithms Client to Server",
            "Compression Algorithms Server to Client",
            "Languages Client to Server",
            "Languages Server to Client"
        };
        string[] keys = new string[]
        {
            "SSH.KexInit.KexAlgorithms",
            "SSH.KexInit.HostKeyAlgorithms",
            "SSH.KexInit.EncryptionClientToServer",
            "SSH.KexInit.EncryptionServerToClient",
            "SSH.KexInit.MacClientToServer",
            "SSH.KexInit.MacServerToClient",
            "SSH.KexInit.CompressionClientToServer",
            "SSH.KexInit.CompressionServerToClient",
            "SSH.KexInit.LanguagesClientToServer",
            "SSH.KexInit.LanguagesServerToClient"
        };

        for (int i = 0; i < labels.Length; i++)
        {
            if (position + 4 > end)
            {
                node.AddLeaf("Truncated: " + labels[i] + " Length");
                return node;
            }

            uint declaredLength = PacketParseHelper.ReadUInt32BE(data, position);
            position += 4;
            if (declaredLength > (uint)(end - position))
            {
                node.AddLeaf("Truncated: " + labels[i] + " (" + declaredLength
                    + " bytes declared, " + (end - position) + " available)");
                return node;
            }

            int valueLength = (int)declaredLength;
            string value = valueLength == 0 ? "" : Encoding.ASCII.GetString(data, position, valueLength);
            string displayValue = valueLength == 0 ? "(empty)" : LimitText(value, 80);
            BoxyBox.TreeNode list = new BoxyBox.TreeNode(labels[i] + " (len " + valueLength + "): "
                + displayValue, keys[i], false);
            list.AddLeaf("Algorithms: " + (valueLength == 0 ? "(empty)" : value));
            node.Add(list);
            position += valueLength;
        }

        if (position >= end)
        {
            node.AddLeaf("Truncated: First KEX Packet Follows");
            return node;
        }
        int follows = data[position++];
        node.AddLeaf("First KEX Packet Follows: " + (follows == 0 ? "False" : "True") + " (" + follows + ")");

        if (position + 4 > end)
        {
            node.AddLeaf("Truncated: Reserved");
            return node;
        }
        node.AddLeaf("Reserved: " + PacketParseHelper.ReadUInt32BE(data, position));
        return node;
    }

    private static BoxyBox.TreeNode BuildUnparsedNode(byte[] data, int start, int length)
    {
        BoxyBox.TreeNode root = new BoxyBox.TreeNode("SSH Encrypted or unparsed payload", "SSH", false);
        root.AddLeaf("Data: " + length + " bytes; Preview: "
            + PacketParseHelper.FormatHexPreview(data, start, length, 32));
        return root;
    }

    private static string GetSsh2MessageName(int messageCode)
    {
        switch (messageCode)
        {
            case 1: return "Disconnect";
            case 2: return "Ignore";
            case 3: return "Unimplemented";
            case 4: return "Debug";
            case 5: return "Service Request";
            case 6: return "Service Accept";
            case 20: return "Key Exchange Init";
            case 21: return "New Keys";
            case 50: return "User Authentication Request";
            case 51: return "User Authentication Failure";
            case 52: return "User Authentication Success";
            case 53: return "User Authentication Banner";
            case 80: return "Global Request";
            case 81: return "Request Success";
            case 82: return "Request Failure";
            case 90: return "Channel Open";
            case 91: return "Channel Open Confirmation";
            case 92: return "Channel Open Failure";
            case 93: return "Channel Window Adjust";
            case 94: return "Channel Data";
            case 95: return "Channel Extended Data";
            case 96: return "Channel EOF";
            case 97: return "Channel Close";
            case 98: return "Channel Request";
            case 99: return "Channel Success";
            case 100: return "Channel Failure";
        }
        if (messageCode >= 30 && messageCode <= 39)
            return "Key exchange method-specific";
        if (messageCode >= 60 && messageCode <= 79)
            return "Authentication method-specific";
        return "Unknown";
    }

    private static string GetSsh2DisplayName(int messageCode)
    {
        string messageName = GetSsh2MessageName(messageCode);
        if ((messageCode >= 30 && messageCode <= 39) || (messageCode >= 60 && messageCode <= 79)
            || messageName == "Unknown")
        {
            return messageName + " (" + messageCode + ")";
        }
        return messageName;
    }

    private static string GetSsh1MessageName(int messageCode)
    {
        switch (messageCode)
        {
            case 0: return "No Message";
            case 1: return "Disconnect";
            case 2: return "Public Key";
            case 3: return "Session Key";
            case 4: return "User";
            default: return "Unknown (" + messageCode + ")";
        }
    }

    private static string LimitText(string value, int maximumLength)
    {
        if (value.Length <= maximumLength) return value;
        return value.Substring(0, maximumLength - 3) + "...";
    }

    private static int ClampLength(byte[] data, int len)
    {
        if (data == null || len <= 0) return 0;
        return len < data.Length ? len : data.Length;
    }

    private static string GetFlowDirection(int srcPort, int dstPort)
    {
        bool sourceIsService = IsSshPort(srcPort);
        bool destinationIsService = IsSshPort(dstPort);
        if (sourceIsService == destinationIsService) return null;
        return sourceIsService ? "server-to-client" : "client-to-server";
    }

    internal static bool IsSshPort(int port)
    {
        return port == SshPort || port == GerritSshPort;
    }

    private static bool LooksLikeCompleteSsh2Packet(byte[] data, int len)
    {
        if (len < 6) return false;
        uint declaredLength = PacketParseHelper.ReadUInt32BE(data, 0);
        if (declaredLength > 0xFFFF) return false;
        int packetLength = (int)declaredLength;
        int paddingLength = data[4];
        return packetLength >= 6 && paddingLength >= 4 && packetLength - paddingLength - 1 >= 1
            && ((4 + packetLength) % 8) == 0 && 4 + packetLength <= len;
    }

    private static bool LooksLikeTruncatedSsh2Packet(byte[] data, int len)
    {
        if (len < 5) return false;
        uint declaredLength = PacketParseHelper.ReadUInt32BE(data, 0);
        if (declaredLength > 0xFFFF) return false;
        int packetLength = (int)declaredLength;
        int paddingLength = data[4];
        return packetLength >= 6 && paddingLength >= 4 && packetLength - paddingLength - 1 >= 1
            && ((4 + packetLength) % 8) == 0 && 4 + packetLength > len;
    }

    private static bool LooksLikeStandaloneSsh1Packet(byte[] data, int len)
    {
        if (len < 6) return false;
        uint declaredLength = PacketParseHelper.ReadUInt32BE(data, 0);
        if (declaredLength < 1 || declaredLength >= 0xFFFF) return false;
        int packetLength = (int)declaredLength;
        int paddingLength = 8 - (packetLength % 8);
        int totalLength = 4 + paddingLength + packetLength;
        if (totalLength != len) return false;
        int messageCode = data[4 + paddingLength];
        return messageCode >= 1 && messageCode <= 4;
    }

    private static int GetSshVersion(string protocolVersion)
    {
        return protocolVersion == "1.99" || protocolVersion.StartsWith("2.", StringComparison.Ordinal) ? 2 : 1;
    }

    private static bool TryParseIdentification(byte[] data, int len, out int identificationEnd,
        out string protocolVersion, out string softwareVersion, out string comments)
    {
        identificationEnd = 0;
        protocolVersion = null;
        softwareVersion = null;
        comments = null;
        int contentEnd;
        int versionEnd;
        int softwareEnd;
        if (!TryFindIdentification(data, 0, len, out contentEnd, out identificationEnd,
            out versionEnd, out softwareEnd)) return false;

        protocolVersion = Encoding.ASCII.GetString(data, 4, versionEnd - 4);
        softwareVersion = Encoding.ASCII.GetString(data, versionEnd + 1, softwareEnd - versionEnd - 1);
        if (softwareEnd < contentEnd)
        {
            comments = Encoding.ASCII.GetString(data, softwareEnd + 1, contentEnd - softwareEnd - 1);
        }
        return true;
    }

    private static bool TryFindIdentification(byte[] data, int offset, int len, out int contentEnd,
        out int identificationEnd, out int versionEnd, out int softwareEnd)
    {
        contentEnd = 0;
        identificationEnd = 0;
        versionEnd = 0;
        softwareEnd = 0;
        if (data == null || offset < 0 || len < 8 || offset > data.Length - len
            || data[offset] != (byte)'S' || data[offset + 1] != (byte)'S'
            || data[offset + 2] != (byte)'H' || data[offset + 3] != (byte)'-')
        {
            return false;
        }

        int limit = offset + Math.Min(len, MaximumIdentificationLength);
        int lf = -1;
        for (int i = offset + 4; i < limit; i++)
        {
            if (data[i] == 0x0A)
            {
                lf = i;
                break;
            }
        }
        if (lf < 0 || lf - offset + 1 > MaximumIdentificationLength) return false;

        contentEnd = lf;
        if (contentEnd > offset && data[contentEnd - 1] == 0x0D) contentEnd--;
        for (int i = offset; i < contentEnd; i++)
        {
            if (data[i] < 0x20 || data[i] > 0x7E) return false;
        }

        versionEnd = IndexOf(data, (byte)'-', offset + 4, contentEnd);
        if (versionEnd <= offset + 4 || versionEnd + 1 >= contentEnd) return false;
        softwareEnd = IndexOf(data, (byte)' ', versionEnd + 1, contentEnd);
        if (softwareEnd < 0) softwareEnd = contentEnd;
        if (softwareEnd == versionEnd + 1) return false;
        identificationEnd = lf + 1;
        return true;
    }

    private static int IndexOf(byte[] data, byte value, int start, int end)
    {
        for (int i = start; i < end; i++)
        {
            if (data[i] == value) return i;
        }
        return -1;
    }
}
