// smb2.cs - High-performance MS-SMB2 protocol parser.
// Parses SMB2/SMB3 packets only (ignores SMB1/CIFS).
// Reference: [MS-SMB2] Server Message Block Protocol Versions 2 and 3

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// High-performance MS-SMB2 parser. All methods are static for zero-allocation hot-path usage.
/// Handles compounded requests, async responses, and extracts key fields per command type.
/// </summary>
public static class Smb2Parser
{
    // SMB2 magic: 0xFE 'S' 'M' 'B'
    private const uint SMB2_MAGIC = 0x424D53FE;

    // SMB2 Transform header magic: 0xFD 'S' 'M' 'B'
    private const uint SMB2_TRANSFORM_MAGIC = 0x424D53FD;

    // --- Command codes ---
    private static readonly string[] CommandNames = new string[]
    {
        "Negotiate",        // 0x0000
        "SessionSetup",     // 0x0001
        "Logoff",           // 0x0002
        "TreeConnect",      // 0x0003
        "TreeDisconnect",   // 0x0004
        "Create",           // 0x0005
        "Close",            // 0x0006
        "Flush",            // 0x0007
        "Read",             // 0x0008
        "Write",            // 0x0009
        "Lock",             // 0x000A
        "Ioctl",            // 0x000B
        "Cancel",           // 0x000C
        "Echo",             // 0x000D
        "QueryDirectory",   // 0x000E
        "ChangeNotify",     // 0x000F
        "QueryInfo",        // 0x0010
        "SetInfo",          // 0x0011
        "OplockBreak"       // 0x0012
    };

    // --- NT Status codes (common ones for display) ---
    private static readonly Dictionary<uint, string> StatusNames = new Dictionary<uint, string>
    {
        { 0x00000000, "SUCCESS" },
        { 0x00000103, "PENDING" },
        { 0x00000001, "STATUS_WAIT_1" },
        { 0x80000005, "BUFFER_OVERFLOW" },
        { 0x80000006, "NO_MORE_FILES" },
        { 0xC0000001, "UNSUCCESSFUL" },
        { 0xC0000002, "NOT_IMPLEMENTED" },
        { 0xC0000003, "INVALID_INFO_CLASS" },
        { 0xC0000004, "INFO_LENGTH_MISMATCH" },
        { 0xC0000005, "ACCESS_VIOLATION" },
        { 0xC0000008, "INVALID_HANDLE" },
        { 0xC000000D, "INVALID_PARAMETER" },
        { 0xC000000F, "NO_SUCH_FILE" },
        { 0xC0000010, "INVALID_DEVICE_REQUEST" },
        { 0xC0000011, "END_OF_FILE" },
        { 0xC0000016, "MORE_PROCESSING_REQUIRED" },
        { 0xC0000022, "ACCESS_DENIED" },
        { 0xC0000023, "BUFFER_TOO_SMALL" },
        { 0xC0000033, "OBJECT_NAME_INVALID" },
        { 0xC0000034, "OBJECT_NAME_NOT_FOUND" },
        { 0xC0000035, "OBJECT_NAME_COLLISION" },
        { 0xC000003A, "OBJECT_PATH_NOT_FOUND" },
        { 0xC000003B, "OBJECT_PATH_SYNTAX_BAD" },
        { 0xC000003C, "DATA_OVERRUN" },
        { 0xC0000043, "SHARING_VIOLATION" },
        { 0xC000006D, "LOGON_FAILURE" },
        { 0xC000006E, "ACCOUNT_RESTRICTION" },
        { 0xC0000070, "INVALID_LOGON_HOURS" },
        { 0xC0000071, "PASSWORD_EXPIRED" },
        { 0xC0000072, "ACCOUNT_DISABLED" },
        { 0xC00000BA, "FILE_IS_A_DIRECTORY" },
        { 0xC00000BB, "NOT_SUPPORTED" },
        { 0xC00000CC, "BAD_NETWORK_NAME" },
        { 0xC00000D5, "NETWORK_ACCESS_DENIED" },
        { 0xC0000101, "DIRECTORY_NOT_EMPTY" },
        { 0xC0000120, "CANCELLED" },
        { 0xC0000128, "FILE_CLOSED" },
        { 0xC000015B, "LOGON_TYPE_NOT_GRANTED" },
        { 0xC000018D, "TRUSTED_RELATIONSHIP_FAILURE" },
        { 0xC0000203, "USER_SESSION_DELETED" },
        { 0xC0000205, "INSUFF_SERVER_RESOURCES" },
        { 0xC000020C, "CONNECTION_DISCONNECTED" },
        { 0xC000035C, "NETWORK_SESSION_EXPIRED" },
    };

    // --- IOCTL codes (common) ---
    private static readonly Dictionary<uint, string> IoctlNames = new Dictionary<uint, string>
    {
        { 0x00060194, "DFS_GET_REFERRALS" },
        { 0x000601B0, "DFS_GET_REFERRALS_EX" },
        { 0x00090000, "SET_COMPRESSION" },
        { 0x000900A4, "SET_REPARSE_POINT" },
        { 0x000900A8, "GET_REPARSE_POINT" },
        { 0x0009009C, "FSCTL_GET_OBJECT_ID" },
        { 0x000900C0, "CREATE_OR_GET_OBJECT_ID" },
        { 0x00094264, "SET_SPARSE" },
        { 0x000940CF, "QUERY_ALLOCATED_RANGES" },
        { 0x000980C8, "SET_ZERO_DATA" },
        { 0x0011C017, "PIPE_TRANSCEIVE" },
        { 0x00110018, "PIPE_PEEK" },
        { 0x00140078, "SRV_ENUMERATE_SNAPSHOTS" },
        { 0x001401D4, "SRV_REQUEST_RESUME_KEY" },
        { 0x001440F2, "SRV_COPYCHUNK" },
        { 0x001441BB, "SRV_READ_HASH" },
        { 0x00144064, "SRV_COPYCHUNK_WRITE" },
        { 0x001401FC, "VALIDATE_NEGOTIATE_INFO" },
        { 0x00140200, "QUERY_NETWORK_INTERFACE_INFO" },
        { 0x00140204, "SRV_NOTIFY_TRANSACTION" },
    };

    // --- Oplock levels ---
    private static readonly string[] OplockLevels = new string[]
    {
        "None", "II", "Exclusive", null, null, null, null, null,
        "Batch", "Lease"
    };

    // --- Create disposition names ---
    private static readonly string[] CreateDispositions = new string[]
    {
        "Supersede", "Open", "Create", "OpenIf", "Overwrite", "OverwriteIf"
    };

    // --- InfoType names (QueryInfo/SetInfo) ---
    private static readonly string[] InfoTypeNames = new string[]
    {
        null, "File", "FileSystem", "Security", "Quota"
    };

    // --- File Information Class names (common) ---
    private static readonly Dictionary<int, string> FileInfoClassNames = new Dictionary<int, string>
    {
        { 1, "Basic" }, { 2, "Standard" }, { 4, "Ea" }, { 5, "Access" },
        { 6, "NameInfo" }, { 7, "Rename" }, { 8, "Link" }, { 9, "Names" },
        { 10, "Disposition" }, { 11, "Position" }, { 12, "FullEa" },
        { 13, "Mode" }, { 14, "Alignment" }, { 16, "Internal" },
        { 18, "AllInfo" }, { 21, "Allocation" }, { 22, "EndOfFile" },
        { 25, "Stream" }, { 34, "Compression" }, { 35, "NetworkOpen" },
        { 37, "AttributeTag" }, { 40, "IdBothDirectory" },
        { 44, "IdFullDirectory" }, { 60, "NormalizedName" },
    };

    // --- FS Information Class names ---
    private static readonly Dictionary<int, string> FsInfoClassNames = new Dictionary<int, string>
    {
        { 1, "Volume" }, { 2, "LabelInfo" }, { 3, "Size" },
        { 4, "Device" }, { 5, "Attribute" }, { 6, "Control" },
        { 7, "FullSize" }, { 8, "ObjectId" }, { 11, "SectorSize" },
    };

    /// <summary>
    /// Tests whether TCP payload data contains an SMB2 packet.
    /// SMB2 runs over Direct TCP (port 445) with a 4-byte length-prefixed framing:
    ///   [0x00][3-byte BE length][SMB2 message]
    /// </summary>
    public static bool IsSmb2Packet(byte[] data, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4) return false;
        if (srcPort != 445 && dstPort != 445) return false;

        // Check for direct SMB2 magic at offset 0 (unlikely but possible in reassembled segments)
        uint magic = (uint)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
        if (magic == SMB2_MAGIC || magic == SMB2_TRANSFORM_MAGIC) return true;

        // Direct TCP framing: first byte 0x00, next 3 bytes = big-endian length, then SMB2 magic
        if (data.Length >= 8 && data[0] == 0x00)
        {
            magic = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
            if (magic == SMB2_MAGIC || magic == SMB2_TRANSFORM_MAGIC) return true;
        }

        return false;
    }

    /// <summary>
    /// Formats a one-line summary of an SMB2 packet for real-time display.
    /// Returns null if the data is not a valid SMB2 packet.
    /// </summary>
    public static string FormatSmb2Segment(byte[] data, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4) return null;

        int offset = 0;

        // Skip Direct TCP framing header (4 bytes: 0x00 + 3-byte BE length) if present
        if (data[0] == 0x00 && data.Length >= 8)
        {
            uint probe = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
            if (probe == SMB2_MAGIC || probe == SMB2_TRANSFORM_MAGIC)
            {
                offset = 4;
            }
        }

        // Check magic at current offset
        if (data.Length < offset + 4) return null;
        uint headerMagic = (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));

        // Encrypted (transform header)
        if (headerMagic == SMB2_TRANSFORM_MAGIC)
        {
            if (data.Length < offset + 52) return "SMB2 Encrypted";
            uint msgSize = ReadUInt32LE(data, offset + 4);
            ulong sessId = ReadUInt64LE(data, offset + 44);
            return "SMB2 Encrypted, SessId 0x" + sessId.ToString("x") + ", len " + msgSize.ToString();
        }

        if (headerMagic != SMB2_MAGIC) return null;
        if (data.Length < offset + 64) return null;

        // Parse header
        ushort structSize = ReadUInt16LE(data, offset + 4);
        if (structSize != 64) return null;

        ushort command = ReadUInt16LE(data, offset + 12);
        uint flags = ReadUInt32LE(data, offset + 16);
        uint status = ReadUInt32LE(data, offset + 8);
        uint nextCommand = ReadUInt32LE(data, offset + 20);
        ulong messageId = ReadUInt64LE(data, offset + 24);
        ulong sessionId = ReadUInt64LE(data, offset + 40);
        uint treeId = ReadUInt32LE(data, offset + 36);

        bool isResponse = (flags & 0x00000001) != 0;
        bool isAsync = (flags & 0x00000002) != 0;
        bool isSigned = (flags & 0x00000008) != 0;

        // Build summary
        StringBuilder sb = new StringBuilder(96);
        sb.Append("SMB2 ");

        // Command name
        if (command < CommandNames.Length)
            sb.Append(CommandNames[command]);
        else
            sb.Append("Cmd_0x").Append(command.ToString("X4"));

        // Request/Response
        if (isResponse)
        {
            sb.Append(" Response");
            // Status for responses
            if (status != 0)
            {
                sb.Append(", ");
                AppendStatus(sb, status);
            }
        }
        else
        {
            sb.Append(" Request");
        }

        // Command-specific details
        int bodyOffset = offset + 64;
        int bodyLen = data.Length - bodyOffset;

        if (bodyLen >= 2)
        {
            AppendCommandDetails(sb, data, bodyOffset, bodyLen, command, isResponse, offset);
        }

        // Compounded indicator
        if (nextCommand != 0)
        {
            sb.Append(" [+]");
            // Count compounded messages
            int compCount = CountCompounded(data, offset, nextCommand);
            if (compCount > 0)
                sb.Append(compCount.ToString());
        }

        // Signing indicator
        if (isSigned) sb.Append(" {S}");

        return sb.ToString();
    }

    /// <summary>
    /// Formats a detailed multi-line string for SMB2 packets (used in verbose mode).
    /// </summary>
    public static string FormatSmb2Detailed(byte[] data, int srcPort, int dstPort)
    {
        if (data == null || data.Length < 4) return null;

        int offset = 0;
        if (data[0] == 0x00 && data.Length >= 8)
        {
            uint probe = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
            if (probe == SMB2_MAGIC || probe == SMB2_TRANSFORM_MAGIC)
                offset = 4;
        }

        if (data.Length < offset + 4) return null;
        uint headerMagic = (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));

        if (headerMagic == SMB2_TRANSFORM_MAGIC)
        {
            if (data.Length < offset + 52) return "SMB2 Transform (Encrypted)";
            uint msgSize = ReadUInt32LE(data, offset + 4);
            ulong sessId = ReadUInt64LE(data, offset + 44);
            return "SMB2 Encrypted - SessionId: 0x" + sessId.ToString("x16") +
                   ", OrigMsgSize: " + msgSize.ToString() + ", Nonce: " +
                   FormatHexBytes(data, offset + 20, 16);
        }

        if (headerMagic != SMB2_MAGIC || data.Length < offset + 64) return null;

        ushort command = ReadUInt16LE(data, offset + 12);
        uint flags = ReadUInt32LE(data, offset + 16);
        uint status = ReadUInt32LE(data, offset + 8);
        ushort creditCharge = ReadUInt16LE(data, offset + 6);
        ushort credits = ReadUInt16LE(data, offset + 14);
        uint nextCommand = ReadUInt32LE(data, offset + 20);
        ulong messageId = ReadUInt64LE(data, offset + 24);
        ulong sessionId = ReadUInt64LE(data, offset + 40);
        uint treeId = ReadUInt32LE(data, offset + 36);

        bool isResponse = (flags & 0x00000001) != 0;
        bool isAsync = (flags & 0x00000002) != 0;
        bool isSigned = (flags & 0x00000008) != 0;

        StringBuilder sb = new StringBuilder(256);

        // Header summary
        string cmdName = (command < CommandNames.Length) ? CommandNames[command] : "Cmd_0x" + command.ToString("X4");
        sb.Append("SMB2 ").Append(cmdName);
        sb.Append(isResponse ? " Response" : " Request");
        if (isResponse && status != 0)
        {
            sb.Append(", ");
            AppendStatus(sb, status);
        }

        sb.Append(" - MsgId: ").Append(messageId.ToString());
        sb.Append(", SessId: 0x").Append(sessionId.ToString("x"));
        if (treeId != 0) sb.Append(", TreeId: 0x").Append(treeId.ToString("x"));
        sb.Append(", Credits: ").Append(credits.ToString());
        if (creditCharge > 1) sb.Append("/").Append(creditCharge.ToString());

        // Flags
        sb.Append(", Flags: [");
        bool first = true;
        if (isResponse) { sb.Append("R"); first = false; }
        if (isAsync) { if (!first) sb.Append(","); sb.Append("A"); first = false; }
        if (isSigned) { if (!first) sb.Append(","); sb.Append("S"); first = false; }
        if ((flags & 0x00000004) != 0) { if (!first) sb.Append(","); sb.Append("Rel"); first = false; }
        if ((flags & 0x10000000) != 0) { if (!first) sb.Append(","); sb.Append("DFS"); }
        sb.Append("]");

        // Command body details
        int bodyOffset = offset + 64;
        int bodyLen = data.Length - bodyOffset;
        if (bodyLen >= 2)
        {
            string details = GetDetailedCommandInfo(data, bodyOffset, bodyLen, command, isResponse, offset);
            if (details != null)
            {
                sb.Append("; ").Append(details);
            }
        }

        return sb.ToString();
    }

    // -----------------------------------------------------------------------
    // Command-specific detail appenders (segment/summary line)
    // -----------------------------------------------------------------------

    private static void AppendCommandDetails(StringBuilder sb, byte[] data, int bodyOff, int bodyLen,
        ushort command, bool isResponse, int headerStart)
    {
        switch (command)
        {
            case 0x0000: // NEGOTIATE
                AppendNegotiateDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x0001: // SESSION_SETUP
                AppendSessionSetupDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x0003: // TREE_CONNECT
                AppendTreeConnectDetails(sb, data, bodyOff, bodyLen, isResponse, headerStart);
                break;
            case 0x0005: // CREATE
                AppendCreateDetails(sb, data, bodyOff, bodyLen, isResponse, headerStart);
                break;
            case 0x0008: // READ
                AppendReadDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x0009: // WRITE
                AppendWriteDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x000B: // IOCTL
                AppendIoctlDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x000E: // QUERY_DIRECTORY
                AppendQueryDirectoryDetails(sb, data, bodyOff, bodyLen, isResponse, headerStart);
                break;
            case 0x0010: // QUERY_INFO
                AppendQueryInfoDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x0011: // SET_INFO
                AppendSetInfoDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
            case 0x0006: // CLOSE
                break;
            case 0x0012: // OPLOCK_BREAK
                AppendOplockBreakDetails(sb, data, bodyOff, bodyLen, isResponse);
                break;
        }
    }

    private static void AppendNegotiateDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (isResponse)
        {
            // Response: dialect at offset 4 (2 bytes)
            if (len >= 6)
            {
                ushort dialect = ReadUInt16LE(data, off + 4);
                sb.Append(", Dialect ");
                AppendDialect(sb, dialect);
            }
        }
        else
        {
            // Request: dialect count at offset 2, dialects start at offset 36
            if (len >= 4)
            {
                ushort dialectCount = ReadUInt16LE(data, off + 2);
                sb.Append(", ").Append(dialectCount).Append(" dialects");
                // Show highest dialect offered
                if (len >= 36 + dialectCount * 2)
                {
                    ushort maxDialect = 0;
                    for (int i = 0; i < dialectCount; i++)
                    {
                        ushort d = ReadUInt16LE(data, off + 36 + i * 2);
                        if (d > maxDialect) maxDialect = d;
                    }
                    sb.Append(" (max ");
                    AppendDialect(sb, maxDialect);
                    sb.Append(")");
                }
            }
        }
    }

    private static void AppendSessionSetupDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (!isResponse && len >= 24)
        {
            // Request: SecurityBufferOffset at off+12, SecurityBufferLength at off+14
            ushort secLen = ReadUInt16LE(data, off + 14);
            sb.Append(", SecBuf len ").Append(secLen);
        }
    }

    private static void AppendTreeConnectDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse, int headerStart)
    {
        if (!isResponse && len >= 8)
        {
            // Request: PathOffset at off+4, PathLength at off+6
            ushort pathOffset = ReadUInt16LE(data, off + 4);
            ushort pathLength = ReadUInt16LE(data, off + 6);
            string path = ExtractUnicodeString(data, headerStart + pathOffset, pathLength);
            if (path != null)
            {
                if (path.Length > 60) path = path.Substring(0, 57) + "...";
                sb.Append(", ").Append(path);
            }
        }
        else if (isResponse && len >= 8)
        {
            // Response: ShareType at off+2
            byte shareType = data[off + 2];
            switch (shareType)
            {
                case 0x01: sb.Append(", Disk"); break;
                case 0x02: sb.Append(", Pipe"); break;
                case 0x03: sb.Append(", Print"); break;
            }
        }
    }

    private static void AppendCreateDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse, int headerStart)
    {
        if (!isResponse && len >= 56)
        {
            // Request: NameOffset at off+44, NameLength at off+46
            ushort nameOffset = ReadUInt16LE(data, off + 44);
            ushort nameLength = ReadUInt16LE(data, off + 46);
            string filename = ExtractUnicodeString(data, headerStart + nameOffset, nameLength);
            if (filename != null)
            {
                if (filename.Length > 60) filename = filename.Substring(0, 57) + "...";
                sb.Append(", \\").Append(filename);
            }

            // CreateDisposition at off+36
            uint disp = ReadUInt32LE(data, off + 36);
            if (disp < CreateDispositions.Length)
                sb.Append(" (").Append(CreateDispositions[disp]).Append(")");
        }
        else if (isResponse && len >= 88)
        {
            // Response: CreateAction at off+4, FileId at off+64 (16 bytes)
            uint createAction = ReadUInt32LE(data, off + 4);
            switch (createAction)
            {
                case 0: sb.Append(", Superseded"); break;
                case 1: sb.Append(", Opened"); break;
                case 2: sb.Append(", Created"); break;
                case 3: sb.Append(", Overwritten"); break;
            }

            // EndOfFile at off+56 (8 bytes)
            ulong fileSize = ReadUInt64LE(data, off + 56);
            if (fileSize > 0) sb.Append(", Size ").Append(FormatSize(fileSize));
        }
    }

    private static void AppendReadDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (!isResponse && len >= 48)
        {
            // Request: Length at off+4, Offset at off+8
            uint readLen = ReadUInt32LE(data, off + 4);
            ulong readOff = ReadUInt64LE(data, off + 8);
            sb.Append(", ").Append(FormatSize(readLen)).Append(" @ ").Append(FormatOffset(readOff));
        }
        else if (isResponse && len >= 16)
        {
            // Response: DataOffset at off+2, DataLength at off+4
            uint dataLength = ReadUInt32LE(data, off + 4);
            sb.Append(", ").Append(FormatSize(dataLength));
        }
    }

    private static void AppendWriteDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (!isResponse && len >= 48)
        {
            // Request: DataOffset at off+2, Length at off+4, Offset at off+8
            uint writeLen = ReadUInt32LE(data, off + 4);
            ulong writeOff = ReadUInt64LE(data, off + 8);
            sb.Append(", ").Append(FormatSize(writeLen)).Append(" @ ").Append(FormatOffset(writeOff));
        }
        else if (isResponse && len >= 4)
        {
            // Response: Count at off+4
            if (len >= 8)
            {
                uint count = ReadUInt32LE(data, off + 4);
                sb.Append(", ").Append(FormatSize(count)).Append(" written");
            }
        }
    }

    private static void AppendIoctlDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (len >= 8)
        {
            // CtlCode at off+4
            uint ctlCode = ReadUInt32LE(data, off + 4);
            sb.Append(", ");
            string ctlName;
            if (IoctlNames.TryGetValue(ctlCode, out ctlName))
                sb.Append(ctlName);
            else
                sb.Append("0x").Append(ctlCode.ToString("X8"));
        }
    }

    private static void AppendQueryDirectoryDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse, int headerStart)
    {
        if (!isResponse && len >= 32)
        {
            // FileInformationClass at off+2, FileNameOffset at off+24, FileNameLength at off+26
            byte infoClass = data[off + 2];
            ushort nameOffset = ReadUInt16LE(data, off + 24);
            ushort nameLength = ReadUInt16LE(data, off + 26);
            string pattern = ExtractUnicodeString(data, headerStart + nameOffset, nameLength);
            if (pattern != null)
            {
                if (pattern.Length > 40) pattern = pattern.Substring(0, 37) + "...";
                sb.Append(", \"").Append(pattern).Append("\"");
            }
        }
    }

    private static void AppendQueryInfoDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (!isResponse && len >= 8)
        {
            // InfoType at off+2, FileInfoClass at off+3
            byte infoType = data[off + 2];
            byte infoClass = data[off + 3];
            AppendInfoTypeClass(sb, infoType, infoClass);
        }
    }

    private static void AppendSetInfoDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (!isResponse && len >= 8)
        {
            // InfoType at off+2, FileInfoClass at off+3
            byte infoType = data[off + 2];
            byte infoClass = data[off + 3];
            AppendInfoTypeClass(sb, infoType, infoClass);
        }
    }

    private static void AppendOplockBreakDetails(StringBuilder sb, byte[] data, int off, int len, bool isResponse)
    {
        if (len >= 4)
        {
            ushort structSize = ReadUInt16LE(data, off);
            if (structSize == 24)
            {
                // Oplock break notification/ack
                byte level = data[off + 2];
                string levelName = (level < OplockLevels.Length && OplockLevels[level] != null) ?
                    OplockLevels[level] : "0x" + level.ToString("X2");
                sb.Append(", Level ").Append(levelName);
            }
            else if (structSize == 36 || structSize == 44)
            {
                // Lease break
                sb.Append(", Lease");
                if (len >= 36)
                {
                    uint curState = ReadUInt32LE(data, off + 20);
                    uint newState = ReadUInt32LE(data, off + 24);
                    sb.Append(" ").Append(FormatLeaseState(curState)).Append("→").Append(FormatLeaseState(newState));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Detailed mode command info
    // -----------------------------------------------------------------------

    private static string GetDetailedCommandInfo(byte[] data, int off, int len, ushort command, bool isResponse, int headerStart)
    {
        switch (command)
        {
            case 0x0000: return GetNegotiateDetail(data, off, len, isResponse);
            case 0x0003: return GetTreeConnectDetail(data, off, len, isResponse, headerStart);
            case 0x0005: return GetCreateDetail(data, off, len, isResponse, headerStart);
            case 0x0008: return GetReadWriteDetail(data, off, len, isResponse, "Read");
            case 0x0009: return GetReadWriteDetail(data, off, len, isResponse, "Write");
            case 0x000B: return GetIoctlDetail(data, off, len, isResponse);
            case 0x0010: return GetQuerySetInfoDetail(data, off, len, isResponse);
            case 0x0011: return GetQuerySetInfoDetail(data, off, len, isResponse);
            default: return null;
        }
    }

    private static string GetNegotiateDetail(byte[] data, int off, int len, bool isResponse)
    {
        if (isResponse && len >= 64)
        {
            ushort dialect = ReadUInt16LE(data, off + 4);
            uint caps = ReadUInt32LE(data, off + 8);
            uint maxTransact = ReadUInt32LE(data, off + 12);
            uint maxRead = ReadUInt32LE(data, off + 16);
            uint maxWrite = ReadUInt32LE(data, off + 20);
            StringBuilder sb = new StringBuilder(128);
            sb.Append("Dialect ");
            AppendDialect(sb, dialect);
            sb.Append(", MaxTransact ").Append(FormatSize(maxTransact));
            sb.Append(", MaxRead ").Append(FormatSize(maxRead));
            sb.Append(", MaxWrite ").Append(FormatSize(maxWrite));
            if ((caps & 0x01) != 0) sb.Append(", DFS");
            if ((caps & 0x02) != 0) sb.Append(", Leasing");
            if ((caps & 0x04) != 0) sb.Append(", LargeMTU");
            if ((caps & 0x08) != 0) sb.Append(", MultiChannel");
            if ((caps & 0x10) != 0) sb.Append(", Persistent");
            if ((caps & 0x20) != 0) sb.Append(", DirLeasing");
            if ((caps & 0x40) != 0) sb.Append(", Encryption");
            return sb.ToString();
        }
        return null;
    }

    private static string GetTreeConnectDetail(byte[] data, int off, int len, bool isResponse, int headerStart)
    {
        if (!isResponse && len >= 8)
        {
            ushort pathOffset = ReadUInt16LE(data, off + 4);
            ushort pathLength = ReadUInt16LE(data, off + 6);
            string path = ExtractUnicodeString(data, headerStart + pathOffset, pathLength);
            if (path != null) return "Path: " + path;
        }
        else if (isResponse && len >= 8)
        {
            byte shareType = data[off + 2];
            uint shareFlags = ReadUInt32LE(data, off + 4);
            string type = (shareType == 1) ? "Disk" : (shareType == 2) ? "Pipe" : (shareType == 3) ? "Print" : "Type" + shareType;
            return "ShareType: " + type + ", Flags: 0x" + shareFlags.ToString("X8");
        }
        return null;
    }

    private static string GetCreateDetail(byte[] data, int off, int len, bool isResponse, int headerStart)
    {
        if (!isResponse && len >= 56)
        {
            ushort nameOffset = ReadUInt16LE(data, off + 44);
            ushort nameLength = ReadUInt16LE(data, off + 46);
            string filename = ExtractUnicodeString(data, headerStart + nameOffset, nameLength);
            uint desiredAccess = ReadUInt32LE(data, off + 24);
            uint disp = ReadUInt32LE(data, off + 36);
            uint options = ReadUInt32LE(data, off + 40);
            StringBuilder sb = new StringBuilder(128);
            if (filename != null) sb.Append("File: \\").Append(filename);
            if (disp < CreateDispositions.Length)
                sb.Append(", Disp: ").Append(CreateDispositions[disp]);
            sb.Append(", Access: 0x").Append(desiredAccess.ToString("X8"));
            if ((options & 0x00000001) != 0) sb.Append(", Directory");
            if ((options & 0x00000040) != 0) sb.Append(", NonDir");
            if ((options & 0x00000004) != 0) sb.Append(", WriteThrough");
            if ((options & 0x00000020) != 0) sb.Append(", SeqOnly");
            if ((options & 0x00001000) != 0) sb.Append(", DeleteOnClose");
            return sb.ToString();
        }
        else if (isResponse && len >= 88)
        {
            uint createAction = ReadUInt32LE(data, off + 4);
            ulong fileSize = ReadUInt64LE(data, off + 56);
            uint fileAttr = ReadUInt32LE(data, off + 64);
            StringBuilder sb = new StringBuilder(64);
            switch (createAction)
            {
                case 0: sb.Append("Action: Superseded"); break;
                case 1: sb.Append("Action: Opened"); break;
                case 2: sb.Append("Action: Created"); break;
                case 3: sb.Append("Action: Overwritten"); break;
                default: sb.Append("Action: ").Append(createAction); break;
            }
            sb.Append(", Size: ").Append(FormatSize(fileSize));
            if ((fileAttr & 0x10) != 0) sb.Append(", Dir");
            if ((fileAttr & 0x04) != 0) sb.Append(", System");
            if ((fileAttr & 0x02) != 0) sb.Append(", Hidden");
            if ((fileAttr & 0x01) != 0) sb.Append(", ReadOnly");
            return sb.ToString();
        }
        return null;
    }

    private static string GetReadWriteDetail(byte[] data, int off, int len, bool isResponse, string verb)
    {
        if (!isResponse && len >= 48)
        {
            uint ioLen = ReadUInt32LE(data, off + 4);
            ulong ioOff = ReadUInt64LE(data, off + 8);
            return verb + " " + FormatSize(ioLen) + " @ offset " + FormatOffset(ioOff);
        }
        else if (isResponse)
        {
            if (verb == "Read" && len >= 8)
            {
                uint dataLen = ReadUInt32LE(data, off + 4);
                return verb + " " + FormatSize(dataLen) + " returned";
            }
            else if (verb == "Write" && len >= 8)
            {
                uint count = ReadUInt32LE(data, off + 4);
                return verb + " " + FormatSize(count) + " confirmed";
            }
        }
        return null;
    }

    private static string GetIoctlDetail(byte[] data, int off, int len, bool isResponse)
    {
        if (len >= 8)
        {
            uint ctlCode = ReadUInt32LE(data, off + 4);
            string name;
            if (!IoctlNames.TryGetValue(ctlCode, out name))
                name = "0x" + ctlCode.ToString("X8");
            return "CtlCode: " + name;
        }
        return null;
    }

    private static string GetQuerySetInfoDetail(byte[] data, int off, int len, bool isResponse)
    {
        if (!isResponse && len >= 8)
        {
            byte infoType = data[off + 2];
            byte infoClass = data[off + 3];
            string typeName = (infoType < InfoTypeNames.Length && InfoTypeNames[infoType] != null)
                ? InfoTypeNames[infoType] : "Type" + infoType;
            string className = GetInfoClassName(infoType, infoClass);
            return "InfoType: " + typeName + ", Class: " + className;
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Utility methods
    // -----------------------------------------------------------------------

    private static void AppendStatus(StringBuilder sb, uint status)
    {
        string name;
        if (StatusNames.TryGetValue(status, out name))
            sb.Append(name);
        else
            sb.Append("0x").Append(status.ToString("X8"));
    }

    private static void AppendDialect(StringBuilder sb, ushort dialect)
    {
        switch (dialect)
        {
            case 0x0202: sb.Append("2.0.2"); break;
            case 0x0210: sb.Append("2.1"); break;
            case 0x0300: sb.Append("3.0"); break;
            case 0x0302: sb.Append("3.0.2"); break;
            case 0x0311: sb.Append("3.1.1"); break;
            case 0x02FF: sb.Append("2.???"); break;
            default: sb.Append("0x").Append(dialect.ToString("X4")); break;
        }
    }

    private static void AppendInfoTypeClass(StringBuilder sb, byte infoType, byte infoClass)
    {
        string typeName = (infoType < InfoTypeNames.Length && InfoTypeNames[infoType] != null)
            ? InfoTypeNames[infoType] : "Type" + infoType;
        string className = GetInfoClassName(infoType, infoClass);
        sb.Append(", ").Append(typeName).Append("/").Append(className);
    }

    private static string GetInfoClassName(byte infoType, byte infoClass)
    {
        if (infoType == 1) // File
        {
            string name;
            if (FileInfoClassNames.TryGetValue(infoClass, out name)) return name;
        }
        else if (infoType == 2) // FileSystem
        {
            string name;
            if (FsInfoClassNames.TryGetValue(infoClass, out name)) return name;
        }
        else if (infoType == 3) // Security
        {
            return "SecurityDesc";
        }
        return "Class" + infoClass;
    }

    private static string FormatLeaseState(uint state)
    {
        if (state == 0) return "None";
        StringBuilder sb = new StringBuilder(8);
        if ((state & 0x01) != 0) sb.Append("R");
        if ((state & 0x02) != 0) sb.Append("H");
        if ((state & 0x04) != 0) sb.Append("W");
        return sb.ToString();
    }

    private static int CountCompounded(byte[] data, int firstOffset, uint nextCommand)
    {
        int count = 0;
        int pos = firstOffset + (int)nextCommand;
        while (pos + 64 <= data.Length && count < 20)
        {
            uint magic = (uint)(data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24));
            if (magic != SMB2_MAGIC) break;
            count++;
            uint next = ReadUInt32LE(data, pos + 20);
            if (next == 0) break;
            pos += (int)next;
        }
        return count;
    }

    private static string ExtractUnicodeString(byte[] data, int offset, int length)
    {
        if (offset < 0 || length <= 0 || offset + length > data.Length) return null;
        try
        {
            return Encoding.Unicode.GetString(data, offset, length);
        }
        catch
        {
            return null;
        }
    }

    private static string FormatSize(ulong bytes)
    {
        if (bytes < 1024) return bytes.ToString() + "B";
        if (bytes < 1048576) return (bytes / 1024).ToString() + "KB";
        if (bytes < 1073741824) return (bytes / 1048576).ToString() + "MB";
        return (bytes / 1073741824).ToString() + "GB";
    }

    private static string FormatOffset(ulong offset)
    {
        if (offset < 0x10000) return offset.ToString();
        return "0x" + offset.ToString("x");
    }

    private static string FormatHexBytes(byte[] data, int offset, int count)
    {
        if (offset + count > data.Length) count = data.Length - offset;
        StringBuilder sb = new StringBuilder(count * 2);
        for (int i = 0; i < count; i++)
            sb.Append(data[offset + i].ToString("x2"));
        return sb.ToString();
    }

    // Fast little-endian readers
    private static ushort ReadUInt16LE(byte[] data, int offset)
    {
        return (ushort)(data[offset] | (data[offset + 1] << 8));
    }

    private static uint ReadUInt32LE(byte[] data, int offset)
    {
        return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
    }

    private static ulong ReadUInt64LE(byte[] data, int offset)
    {
        return (ulong)data[offset] | ((ulong)data[offset + 1] << 8) |
               ((ulong)data[offset + 2] << 16) | ((ulong)data[offset + 3] << 24) |
               ((ulong)data[offset + 4] << 32) | ((ulong)data[offset + 5] << 40) |
               ((ulong)data[offset + 6] << 48) | ((ulong)data[offset + 7] << 56);
    }
}
