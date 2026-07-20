// smb2.cs - High-performance MS-SMB2 protocol parser.
// Parses SMB2/SMB3 packets only (ignores SMB1/CIFS).
// Reference: [MS-SMB2] Server Message Block Protocol Versions 2 and 3

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Parsed SMB2 header snapshot used by application-layer display predicates
/// (<see cref="Smb2AppPredicate"/>). Populated by
/// <see cref="Smb2Parser.TryParseSmb2Header"/>.
///
/// Only header fields plus per-command Filename (Create) / TreePath
/// (TreeConnect) are extracted; everything else needed for display continues
/// to come from the legacy <see cref="Smb2Parser.FormatSmb2Segment"/> /
/// <see cref="Smb2Parser.FormatSmb2Detailed"/> formatters.
/// </summary>
public struct Smb2Context
{
    /// <summary>True when the SMB2 header (or Transform header) was parsed successfully.</summary>
    public bool   Valid;
    /// <summary>True when the per-command body extraction (filename / tree path) was started but couldn't be completed within the valid payload length.</summary>
    public bool   Truncated;
    /// <summary>True for SMB2 Transform-header (encrypted) packets. Other fields are largely unavailable when set.</summary>
    public bool   IsEncrypted;
    /// <summary>True when the FLAGS field has SMB2_FLAGS_SERVER_TO_REDIR set.</summary>
    public bool   IsResponse;
    /// <summary>True when this packet starts a compounded chain (NextCommand &gt; 0).</summary>
    public bool   IsCompounded;
    /// <summary>SMB2 command code (e.g. 0x05 = Create, 0x09 = Write).</summary>
    public int    Command;
    /// <summary>NT status code from the header. 0 = SUCCESS.</summary>
    public uint   Status;
    /// <summary>SMB2 MessageId (informational, not filtered).</summary>
    public ulong  MessageId;
    /// <summary>Session ID from the header.</summary>
    public ulong  SessionId;
    /// <summary>Tree ID from the header.</summary>
    public uint   TreeId;
    /// <summary>Filename extracted from a Create request body. Null otherwise.</summary>
    public string Filename;
    /// <summary>Share path extracted from a TreeConnect request body. Null otherwise.</summary>
    public string TreePath;
}

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

    // NT STATUS_PENDING: an interim response that must not consume request-correlation state.
    private const uint STATUS_PENDING = 0x00000103;

    // --- Command codes ---
    // --- Command names (MS-SMB2 command table; the "SMB2 " prefix is added by the caller) ---
    private static readonly string[] CommandNames = new string[]
    {
        "NEGOTIATE",        // 0x0000
        "SESSION_SETUP",    // 0x0001
        "LOGOFF",           // 0x0002
        "TREE_CONNECT",     // 0x0003
        "TREE_DISCONNECT",  // 0x0004
        "CREATE",           // 0x0005
        "CLOSE",            // 0x0006
        "FLUSH",            // 0x0007
        "READ",             // 0x0008
        "WRITE",            // 0x0009
        "LOCK",             // 0x000A
        "IOCTL",            // 0x000B
        "CANCEL",           // 0x000C
        "ECHO",             // 0x000D
        "QUERY_DIRECTORY",  // 0x000E
        "CHANGE_NOTIFY",    // 0x000F
        "QUERY_INFO",       // 0x0010
        "SET_INFO",         // 0x0011
        "OPLOCK_BREAK"      // 0x0012
    };

    // --- NT Status codes (MS-ERREF 2.3.1; STATUS_-prefixed for display). Common SMB2 subset;
    //     unknown codes fall back to their hex value. ---
    private static readonly Dictionary<uint, string> StatusNames = new Dictionary<uint, string>
    {
        { 0x00000000, "STATUS_SUCCESS" },
        { 0x00000103, "STATUS_PENDING" },
        { 0x0000010B, "STATUS_NOTIFY_CLEANUP" },
        { 0x0000010C, "STATUS_NOTIFY_ENUM_DIR" },
        { 0x80000005, "STATUS_BUFFER_OVERFLOW" },
        { 0x80000006, "STATUS_NO_MORE_FILES" },
        { 0x8000002D, "STATUS_STOPPED_ON_SYMLINK" },
        { 0xC0000001, "STATUS_UNSUCCESSFUL" },
        { 0xC0000002, "STATUS_NOT_IMPLEMENTED" },
        { 0xC0000003, "STATUS_INVALID_INFO_CLASS" },
        { 0xC0000004, "STATUS_INFO_LENGTH_MISMATCH" },
        { 0xC0000005, "STATUS_ACCESS_VIOLATION" },
        { 0xC0000008, "STATUS_INVALID_HANDLE" },
        { 0xC000000D, "STATUS_INVALID_PARAMETER" },
        { 0xC000000F, "STATUS_NO_SUCH_FILE" },
        { 0xC0000010, "STATUS_INVALID_DEVICE_REQUEST" },
        { 0xC0000011, "STATUS_END_OF_FILE" },
        { 0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED" },
        { 0xC000001C, "STATUS_INVALID_DEVICE_STATE" },
        { 0xC0000022, "STATUS_ACCESS_DENIED" },
        { 0xC0000023, "STATUS_BUFFER_TOO_SMALL" },
        { 0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND" },
        { 0xC0000033, "STATUS_OBJECT_NAME_INVALID" },
        { 0xC0000035, "STATUS_OBJECT_NAME_COLLISION" },
        { 0xC0000039, "STATUS_OBJECT_PATH_INVALID" },
        { 0xC000003A, "STATUS_OBJECT_PATH_NOT_FOUND" },
        { 0xC000003B, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
        { 0xC000003C, "STATUS_DATA_OVERRUN" },
        { 0xC0000043, "STATUS_SHARING_VIOLATION" },
        { 0xC0000054, "STATUS_FILE_LOCK_CONFLICT" },
        { 0xC0000055, "STATUS_LOCK_NOT_GRANTED" },
        { 0xC0000056, "STATUS_DELETE_PENDING" },
        { 0xC000006D, "STATUS_LOGON_FAILURE" },
        { 0xC000006E, "STATUS_ACCOUNT_RESTRICTION" },
        { 0xC000006F, "STATUS_INVALID_LOGON_HOURS" },
        { 0xC0000070, "STATUS_INVALID_WORKSTATION" },
        { 0xC0000071, "STATUS_PASSWORD_EXPIRED" },
        { 0xC0000072, "STATUS_ACCOUNT_DISABLED" },
        { 0xC00000AC, "STATUS_PIPE_NOT_AVAILABLE" },
        { 0xC00000B5, "STATUS_IO_TIMEOUT" },
        { 0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY" },
        { 0xC00000BB, "STATUS_NOT_SUPPORTED" },
        { 0xC00000C9, "STATUS_NETWORK_NAME_DELETED" },
        { 0xC00000CC, "STATUS_BAD_NETWORK_NAME" },
        { 0xC00000D0, "STATUS_REQUEST_NOT_ACCEPTED" },
        { 0xC00000D5, "STATUS_NETWORK_ACCESS_DENIED" },
        { 0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY" },
        { 0xC0000120, "STATUS_CANCELLED" },
        { 0xC0000128, "STATUS_FILE_CLOSED" },
        { 0xC000015B, "STATUS_LOGON_TYPE_NOT_GRANTED" },
        { 0xC000018D, "STATUS_TRUSTED_RELATIONSHIP_FAILURE" },
        { 0xC0000203, "STATUS_USER_SESSION_DELETED" },
        { 0xC0000205, "STATUS_INSUFF_SERVER_RESOURCES" },
        { 0xC000020C, "STATUS_CONNECTION_DISCONNECTED" },
        { 0xC0000225, "STATUS_NOT_FOUND" },
        { 0xC000035C, "STATUS_NETWORK_SESSION_EXPIRED" },
    };

    // --- IOCTL / FSCTL control codes (MS-FSCC 2.3 values; FSCTL_-prefixed names) ---
    private static readonly Dictionary<uint, string> IoctlNames = new Dictionary<uint, string>
    {
        { 0x00060194, "FSCTL_DFS_GET_REFERRALS" },
        { 0x000601B0, "FSCTL_DFS_GET_REFERRALS_EX" },
        { 0x00090000, "FSCTL_REQUEST_OPLOCK_LEVEL_1" },
        { 0x0009009C, "FSCTL_GET_OBJECT_ID" },
        { 0x000900A4, "FSCTL_SET_REPARSE_POINT" },
        { 0x000900A8, "FSCTL_GET_REPARSE_POINT" },
        { 0x000900C0, "FSCTL_CREATE_OR_GET_OBJECT_ID" },
        { 0x0009C040, "FSCTL_SET_COMPRESSION" },
        { 0x00098208, "FSCTL_GET_INTEGRITY_INFORMATION" },
        { 0x0009C280, "FSCTL_SET_INTEGRITY_INFORMATION" },
        { 0x000980C8, "FSCTL_SET_ZERO_DATA" },
        { 0x000940CF, "FSCTL_QUERY_ALLOCATED_RANGES" },
        { 0x000900C4, "FSCTL_SET_SPARSE" },
        { 0x0011400C, "FSCTL_PIPE_PEEK" },
        { 0x00110018, "FSCTL_PIPE_WAIT" },
        { 0x0011C017, "FSCTL_PIPE_TRANSCEIVE" },
        { 0x00140078, "FSCTL_SRV_ENUMERATE_SNAPSHOTS" },
        { 0x001401D4, "FSCTL_SRV_REQUEST_RESUME_KEY" },
        { 0x001441BB, "FSCTL_SRV_READ_HASH" },
        { 0x001440F2, "FSCTL_SRV_COPYCHUNK" },
        { 0x001480F2, "FSCTL_SRV_COPYCHUNK_WRITE" },
        { 0x001401FC, "FSCTL_LMR_REQUEST_RESILIENCY" },
        { 0x001401D0, "FSCTL_LMR_SET_LINK_TRACKING_INFORMATION" },
        { 0x00140200, "FSCTL_QUERY_NETWORK_INTERFACE_INFO" },
        { 0x00140204, "FSCTL_QUERY_NETWORK_INTERFACE_INFO" },
        { 0x00140194, "FSCTL_VALIDATE_NEGOTIATE_INFO" },
        { 0x00140210, "FSCTL_VALIDATE_NEGOTIATE_INFO" },
        { 0x001401EC, "FSCTL_FILE_LEVEL_TRIM" },
        { 0x00140244, "FSCTL_QUERY_ALLOCATED_RANGES" },
        { 0x00140264, "FSCTL_SET_ZERO_DATA" },
        { 0x00140168, "FSCTL_OFFLOAD_READ" },
        { 0x0014416C, "FSCTL_OFFLOAD_WRITE" },
        { 0x0014028C, "FSCTL_QUERY_FILE_REGIONS" },
    };

    // --- Oplock level names (MS-SMB2 OplockLevel; sparse index keyed by byte value) ---
    private static readonly Dictionary<int, string> OplockLevelNames = new Dictionary<int, string>
    {
        { 0x00, "SMB2_OPLOCK_LEVEL_NONE" },
        { 0x01, "SMB2_OPLOCK_LEVEL_II" },
        { 0x08, "SMB2_OPLOCK_LEVEL_EXCLUSIVE" },
        { 0x09, "SMB2_OPLOCK_LEVEL_BATCH" },
        { 0xFF, "SMB2_OPLOCK_LEVEL_LEASE" },
    };

    // --- Create disposition names (MS-SMB2 2.2.13 CreateDisposition, request) ---
    private static readonly string[] CreateDispositions = new string[]
    {
        "FILE_SUPERSEDE", "FILE_OPEN", "FILE_CREATE", "FILE_OPEN_IF", "FILE_OVERWRITE", "FILE_OVERWRITE_IF"
    };

    // --- Create action names (MS-SMB2 2.2.14 CreateAction, response) ---
    private static readonly string[] CreateActions = new string[]
    {
        "FILE_SUPERSEDED", "FILE_OPENED", "FILE_CREATED", "FILE_OVERWRITTEN"
    };

    // --- InfoType names (QueryInfo/SetInfo) ---
    private static readonly string[] InfoTypeNames = new string[]
    {
        null, "INFO_FILE", "INFO_FILESYSTEM", "INFO_SECURITY", "INFO_QUOTA"
    };

    // --- FileInformationClass names (union of QUERY_INFO / SET_INFO / directory classes;
    //     full MS-FSCC / MS-SMB2 names) ---
    private static readonly Dictionary<int, string> FileInfoClassNames = new Dictionary<int, string>
    {
        { 0x01, "FileDirectoryInformation" }, { 0x02, "FileFullDirectoryInformation" },
        { 0x03, "FileBothDirectoryInformation" }, { 0x04, "FileBasicInformation" },
        { 0x05, "FileStandardInformation" }, { 0x06, "FileInternalInformation" },
        { 0x07, "FileEaInformation" }, { 0x08, "FileAccessInformation" },
        { 0x0A, "FileRenameInformation" }, { 0x0B, "FileLinkInformation" },
        { 0x0C, "FileNamesInformation" }, { 0x0D, "FileDispositionInformation" },
        { 0x0E, "FilePositionInformation" }, { 0x0F, "FileFullEaInformation" },
        { 0x10, "FileModeInformation" }, { 0x11, "FileAlignmentInformation" },
        { 0x12, "FileAllInformation" }, { 0x13, "FileAllocationInformation" },
        { 0x14, "FileEndOfFileInformation" }, { 0x15, "FileAlternateNameInformation" },
        { 0x16, "FileStreamInformation" }, { 0x17, "FilePipeInformation" },
        { 0x18, "FilePipeLocalInformation" }, { 0x19, "FilePipeRemoteInformation" },
        { 0x1C, "FileCompressionInformation" }, { 0x22, "FileNetworkOpenInformation" },
        { 0x23, "FileAttributeTagInformation" }, { 0x25, "FileIdBothDirectoryInformation" },
        { 0x26, "FileIdFullDirectoryInformation" }, { 0x27, "FileValidDataLengthInformation" },
        { 0x28, "FileShortNameInformation" }, { 0x30, "FileNormalizedNameInformation" },
        { 0x3B, "FileIdInformation" }, { 0x3C, "FileIdExtdDirectoryInformation" },
        { 0x4E, "FileId64ExtdDirectoryInformation" }, { 0x4F, "FileId64ExtdBothDirectoryInformation" },
        { 0x50, "FileIdAllExtdDirectoryInformation" }, { 0x51, "FileIdAllExtdBothDirectoryInformation" },
        { 0x64, "FileInformationClass_Reserved" },
    };

    // --- FS Information Class names (InfoType = INFO_FILESYSTEM) ---
    private static readonly Dictionary<int, string> FsInfoClassNames = new Dictionary<int, string>
    {
        { 0x01, "FileFsVolumeInformation" }, { 0x02, "FileFsLabelInformation" },
        { 0x03, "FileFsSizeInformation" }, { 0x04, "FileFsDeviceInformation" },
        { 0x05, "FileFsAttributeInformation" }, { 0x06, "FileFsControlInformation" },
        { 0x07, "FileFsFullSizeInformation" }, { 0x08, "FileFsObjectIdInformation" },
        { 0x0B, "FileFsSectorSizeInformation" },
    };

    // --- CHANGE_NOTIFY completion filter flags (bit -> name) ---
    private static readonly KeyValuePair<uint, string>[] ChangeNotifyFilters = new KeyValuePair<uint, string>[]
    {
        new KeyValuePair<uint, string>(0x00000001, "FILE_NAME"),
        new KeyValuePair<uint, string>(0x00000002, "DIR_NAME"),
        new KeyValuePair<uint, string>(0x00000004, "ATTRIBUTES"),
        new KeyValuePair<uint, string>(0x00000008, "SIZE"),
        new KeyValuePair<uint, string>(0x00000010, "LAST_WRITE"),
        new KeyValuePair<uint, string>(0x00000020, "LAST_ACCESS"),
        new KeyValuePair<uint, string>(0x00000040, "CREATION"),
        new KeyValuePair<uint, string>(0x00000080, "EA"),
        new KeyValuePair<uint, string>(0x00000100, "SECURITY"),
        new KeyValuePair<uint, string>(0x00000200, "STREAM_NAME"),
        new KeyValuePair<uint, string>(0x00000400, "STREAM_SIZE"),
        new KeyValuePair<uint, string>(0x00000800, "STREAM_WRITE"),
    };

    // --- Negotiate capability flags (bit -> name) ---
    private static readonly KeyValuePair<uint, string>[] NegotiateCaps = new KeyValuePair<uint, string>[]
    {
        new KeyValuePair<uint, string>(0x00000001, "DFS"),
        new KeyValuePair<uint, string>(0x00000002, "LEASING"),
        new KeyValuePair<uint, string>(0x00000004, "LARGE_MTU"),
        new KeyValuePair<uint, string>(0x00000008, "MULTI_CHANNEL"),
        new KeyValuePair<uint, string>(0x00000010, "PERSISTENT_HANDLES"),
        new KeyValuePair<uint, string>(0x00000020, "DIRECTORY_LEASING"),
        new KeyValuePair<uint, string>(0x00000040, "ENCRYPTION"),
    };

    // -----------------------------------------------------------------------
    // Stateful TID -> tree-name and FID -> file-name tables (see the "Special
    // Notes" section of SMB2_parser_instructions.md).
    //
    // Names ride on *requests* (TreeConnect path, Create filename) while the
    // server-assigned IDs come back on the matching *responses* (TreeId in the
    // TreeConnect response header, FileId in the Create response body). We
    // correlate the two by (SessionId, MessageId) via a short-lived _pending
    // map, then record the resolved name in _treeNames / _fileNames.
    //
    // Populated on the consumer thread as packets are formatted; read on the
    // consumer thread (live one-liner) and, in Analysis mode, on the UI thread
    // (JIT detail tree). All access is guarded by _stateLock. Reset at capture
    // start via ResetState(); each table is capped so a long capture that never
    // sees the closing packet can't grow without bound.
    // -----------------------------------------------------------------------
    private static readonly object _stateLock = new object();
    private const int StateCap = 100000;

    private struct U64Pair : IEquatable<U64Pair>
    {
        public ulong A;
        public ulong B;
        public U64Pair(ulong a, ulong b) { A = a; B = b; }
        public bool Equals(U64Pair other) { return A == other.A && B == other.B; }
        public override bool Equals(object obj) { return obj is U64Pair && Equals((U64Pair)obj); }
        public override int GetHashCode()
        {
            ulong h = A * 1099511628211UL ^ B;
            return (int)(h ^ (h >> 32));
        }
    }

    private struct PendingName
    {
        public byte Kind;    // 1 = Tree (name is a UNC path), 2 = File (name is a filename)
        public string Name;
    }

    // (SessionId, MessageId) -> pending request name awaiting its response.
    private static readonly Dictionary<U64Pair, PendingName> _pending = new Dictionary<U64Pair, PendingName>();
    // (SessionId, TreeId) -> UNC path. Populated in Phase 1; consumed by the Phase 2 Analysis
    // detail tree (collapsed "SMB2 <cmd> - <tree>" header and the SMB header Tree Id line).
    private static readonly Dictionary<U64Pair, string> _treeNames = new Dictionary<U64Pair, string>();
    // (FileId persistent, FileId volatile) -> filename.
    private static readonly Dictionary<U64Pair, string> _fileNames = new Dictionary<U64Pair, string>();

    /// <summary>
    /// Clears all stateful TID/FID name tables. Called at capture start so discovered
    /// tree/file names never leak across captures.
    /// </summary>
    public static void ResetState()
    {
        lock (_stateLock)
        {
            _pending.Clear();
            _treeNames.Clear();
            _fileNames.Clear();
        }
    }

    private static void RecordPending(ulong sessionId, ulong messageId, byte kind, string name)
    {
        if (name == null) return;
        lock (_stateLock)
        {
            U64Pair key = new U64Pair(sessionId, messageId);
            // Safety valve: _pending should stay small (entries are consumed by the matching
            // response), but if it ever fills — e.g. a flood of requests whose responses were
            // dropped — clear it rather than permanently rejecting all new correlations.
            if (_pending.Count >= StateCap && !_pending.ContainsKey(key)) _pending.Clear();
            PendingName p; p.Kind = kind; p.Name = name;
            _pending[key] = p;
        }
    }

    private static void DiscardPending(ulong sessionId, ulong messageId)
    {
        lock (_stateLock) { _pending.Remove(new U64Pair(sessionId, messageId)); }
    }

    private static void ResolveTree(ulong sessionId, ulong messageId, uint treeId)
    {
        lock (_stateLock)
        {
            U64Pair mkey = new U64Pair(sessionId, messageId);
            PendingName p;
            if (_pending.TryGetValue(mkey, out p))
            {
                _pending.Remove(mkey);
                if (p.Kind == 1)
                {
                    U64Pair tkey = new U64Pair(sessionId, treeId);
                    // Allow updating an existing (reused) TreeId even at capacity; only block
                    // brand-new keys once full.
                    if (_treeNames.Count < StateCap || _treeNames.ContainsKey(tkey))
                        _treeNames[tkey] = p.Name;
                }
            }
        }
    }

    private static void ResolveFile(ulong sessionId, ulong messageId, ulong fidPersistent, ulong fidVolatile)
    {
        lock (_stateLock)
        {
            U64Pair mkey = new U64Pair(sessionId, messageId);
            PendingName p;
            if (_pending.TryGetValue(mkey, out p))
            {
                _pending.Remove(mkey);
                if (p.Kind == 2)
                {
                    U64Pair fkey = new U64Pair(fidPersistent, fidVolatile);
                    if (_fileNames.Count < StateCap || _fileNames.ContainsKey(fkey))
                        _fileNames[fkey] = p.Name;
                }
            }
        }
    }

    private static string LookupFile(ulong fidPersistent, ulong fidVolatile)
    {
        lock (_stateLock)
        {
            string name;
            return _fileNames.TryGetValue(new U64Pair(fidPersistent, fidVolatile), out name) ? name : null;
        }
    }

    /// <summary>
    /// Tests whether TCP payload data contains an SMB2 packet.
    /// SMB2 runs over Direct TCP (port 445) with a 4-byte length-prefixed framing:
    ///   [0x00][3-byte BE length][SMB2 message]
    /// </summary>
    public static bool IsSmb2Packet(byte[] data, int srcPort, int dstPort)
    {
        return IsSmb2Packet(data, data != null ? data.Length : 0, srcPort, dstPort);
    }

    public static bool IsSmb2Packet(byte[] data, int dataLen, int srcPort, int dstPort)
    {
        int len = dataLen;
        if (data == null) len = 0;
        else if (len > data.Length) len = data.Length;

        if (data == null || len < 4) return false;
        if (srcPort != 445 && dstPort != 445) return false;

        // Check for direct SMB2 magic at offset 0 (unlikely but possible in reassembled segments)
        uint magic = (uint)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
        if (magic == SMB2_MAGIC || magic == SMB2_TRANSFORM_MAGIC) return true;

        // Direct TCP framing: first byte 0x00, next 3 bytes = big-endian length, then SMB2 magic
        if (len >= 8 && data[0] == 0x00)
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
        return FormatSmb2Segment(data, data != null ? data.Length : 0, srcPort, dstPort);
    }

    public static string FormatSmb2Segment(byte[] data, int dataLen, int srcPort, int dstPort)
    {
        int len = dataLen;
        if (data == null) len = 0;
        else if (len > data.Length) len = data.Length;
        if (data == null || len < 4) return null;

        int offset = 0;
        // Skip Direct TCP framing header (4 bytes: 0x00 + 3-byte BE length) if present.
        if (data[0] == 0x00 && len >= 8)
        {
            uint probe = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
            if (probe == SMB2_MAGIC || probe == SMB2_TRANSFORM_MAGIC) offset = 4;
        }

        if (len < offset + 4) return null;
        uint headerMagic = (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));

        // Encrypted (Transform header): only the session id is reachable.
        if (headerMagic == SMB2_TRANSFORM_MAGIC)
        {
            if (len < offset + 52) return "SMB2 Encrypted";
            uint msgSize = ReadUInt32LE(data, offset + 4);
            ulong sessId = ReadUInt64LE(data, offset + 44);
            return "SMB2 Encrypted, SessId 0x" + sessId.ToString("x") + ", len " + msgSize.ToString();
        }

        if (headerMagic != SMB2_MAGIC) return null;

        // Walk the (possibly compounded) command chain, emitting one spec line per command
        // joined by " | ". State population (TID/FID name tables) is a side effect of the walk.
        StringBuilder sb = new StringBuilder(160);
        int cmdOffset = offset;
        bool firstCmd = true;
        int guard = 0;
        while (cmdOffset + 64 <= len && guard++ < 64)
        {
            uint magic = (uint)(data[cmdOffset] | (data[cmdOffset + 1] << 8) | (data[cmdOffset + 2] << 16) | (data[cmdOffset + 3] << 24));
            if (magic != SMB2_MAGIC) break;
            ushort structSize = ReadUInt16LE(data, cmdOffset + 4);
            if (structSize != 64) break;

            uint status      = ReadUInt32LE(data, cmdOffset + 8);
            ushort command   = ReadUInt16LE(data, cmdOffset + 12);
            uint flags       = ReadUInt32LE(data, cmdOffset + 16);
            uint nextCommand = ReadUInt32LE(data, cmdOffset + 20);
            ulong messageId  = ReadUInt64LE(data, cmdOffset + 24);
            uint treeId      = ReadUInt32LE(data, cmdOffset + 36);
            ulong sessionId  = ReadUInt64LE(data, cmdOffset + 40);
            bool isResponse  = (flags & 0x00000001) != 0;

            if (!firstCmd) sb.Append(" | ");
            firstCmd = false;

            sb.Append("SMB2 ");
            if (command < CommandNames.Length) sb.Append(CommandNames[command]);
            else sb.Append("CMD_0x").Append(command.ToString("X4"));
            sb.Append(isResponse ? " Response" : " Request");

            // Status is only meaningful on responses (the field is ChannelSequence/Reserved in
            // requests). Shown only when it isn't STATUS_SUCCESS.
            if (isResponse && status != 0)
                sb.Append(", ").Append(StatusName(status)).Append(" (0x").Append(status.ToString("X8")).Append(")");

            int bodyOff = cmdOffset + 64;
            // Validate NextCommand to bound this command's body and to prevent integer overflow
            // when advancing — a malformed NextCommand must not wrap cmdOffset negative and slip
            // past the loop's bounds check into an out-of-range index.
            int cmdEnd = len;
            if (nextCommand != 0)
            {
                if (nextCommand < 64 || nextCommand > (uint)(len - cmdOffset))
                    nextCommand = 0;                    // malformed / truncated chain length
                else
                    cmdEnd = cmdOffset + (int)nextCommand;
            }
            int bodyLen = cmdEnd - bodyOff;
            if (bodyLen < 0) bodyLen = 0;

            // cmdEnd (not len) bounds per-command field reads so a malformed offset can't decode
            // into the following chained command.
            AppendCommandLine(sb, data, cmdEnd, cmdOffset, bodyOff, bodyLen, command, isResponse, status, sessionId, messageId, treeId);

            if (nextCommand == 0) break;
            cmdOffset += (int)nextCommand;              // bounded above by len
        }

        return sb.Length == 0 ? null : sb.ToString();
    }

    // -----------------------------------------------------------------------
    // Per-command spec formatters (Default == Detailed per SMB2_parser_instructions.md).
    // Each appends ", <detail>" to the running header line and populates the TID/FID name
    // tables as a side effect (requests stash the name; responses resolve the assigned id).
    // -----------------------------------------------------------------------

    private static void AppendCommandLine(StringBuilder sb, byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        ushort command, bool isResponse, uint status, ulong sessionId, ulong messageId, uint treeId)
    {
        switch (command)
        {
            case 0x0000: AppendNegotiate(sb, data, off, bodyLen, isResponse); break;
            case 0x0001: AppendSessionSetup(sb, data, off, bodyLen, isResponse); break;
            case 0x0003: AppendTreeConnect(sb, data, cmdEnd, hdr, off, bodyLen, isResponse, status, sessionId, messageId, treeId); break;
            case 0x0005: AppendCreate(sb, data, cmdEnd, hdr, off, bodyLen, isResponse, status, sessionId, messageId); break;
            case 0x0006: // CLOSE — FileId@8 (request); response is header-only. Response never
                         // echoes, so the request must not stash an echo entry.
                if (!isResponse) { sb.Append(", "); AppendReqFile(sb, data, off, bodyLen, 8, sessionId, messageId, false); }
                break;
            case 0x0007: // FLUSH — FileId@8 (request); response header-only, no echo.
                if (!isResponse) { sb.Append(", "); AppendReqFile(sb, data, off, bodyLen, 8, sessionId, messageId, false); }
                break;
            case 0x0008: AppendReadWrite(sb, data, off, bodyLen, isResponse, true, status, sessionId, messageId); break;
            case 0x0009: AppendReadWrite(sb, data, off, bodyLen, isResponse, false, status, sessionId, messageId); break;
            case 0x000A: // LOCK — FileId@8; response echoes the request's handle name.
                sb.Append(", ");
                if (isResponse) { if (!AppendRespFile(sb, status, sessionId, messageId)) sb.Length -= 2; }
                else AppendReqFile(sb, data, off, bodyLen, 8, sessionId, messageId, true);
                break;
            case 0x000B: AppendIoctl(sb, data, off, bodyLen); break;
            case 0x000E: AppendQueryDirectory(sb, data, cmdEnd, hdr, off, bodyLen, isResponse, status, sessionId, messageId); break;
            case 0x000F: AppendChangeNotify(sb, data, off, bodyLen, isResponse, sessionId, messageId); break;
            case 0x0010: AppendQuerySetInfo(sb, data, off, bodyLen, isResponse, true, status, sessionId, messageId); break;
            case 0x0011: AppendQuerySetInfo(sb, data, off, bodyLen, isResponse, false, status, sessionId, messageId); break;
            case 0x0012: AppendOplockBreak(sb, data, off, bodyLen, isResponse); break;
            // NEGOTIATE handled above; LOGOFF / TREE_DISCONNECT / CANCEL / ECHO: header only.
        }
    }

    private static void AppendNegotiate(StringBuilder sb, byte[] data, int off, int bodyLen, bool isResponse)
    {
        if (isResponse)
        {
            if (bodyLen < 24) return;
            ushort dialect = ReadUInt16LE(data, off + 4);
            uint caps       = ReadUInt32LE(data, off + 8);
            uint maxTransact = ReadUInt32LE(data, off + 12);
            uint maxRead     = ReadUInt32LE(data, off + 16);
            uint maxWrite    = ReadUInt32LE(data, off + 20);
            sb.Append(", Dialect ").Append(DialectName(dialect));
            sb.Append("; ").Append(maxTransact).Append('\\').Append(maxRead).Append('\\').Append(maxWrite);
            AppendCaps(sb, caps);
        }
        else
        {
            if (bodyLen < 4) return;
            ushort dialectCount = ReadUInt16LE(data, off + 2);
            uint caps = (bodyLen >= 12) ? ReadUInt32LE(data, off + 8) : 0;
            sb.Append(", Requested Dialects ");
            int shown = 0;
            for (int i = 0; i < dialectCount; i++)
            {
                int d = off + 36 + i * 2;
                if (d + 2 > off + bodyLen) break;
                if (shown > 0) sb.Append(", ");
                sb.Append(DialectName(ReadUInt16LE(data, d)));
                shown++;
            }
            // NOTE: an SMB2 NEGOTIATE request carries no MaxTransaction/Read/Write sizes
            // (those are server-only response fields), so they are omitted here.
            AppendCaps(sb, caps);
        }
    }

    private static void AppendSessionSetup(StringBuilder sb, byte[] data, int off, int bodyLen, bool isResponse)
    {
        // Response: header-only per spec.
        if (isResponse || bodyLen < 4) return;
        byte securityMode = data[off + 3];       // SecurityMode is the byte at body+3.
        uint caps = (bodyLen >= 8) ? ReadUInt32LE(data, off + 4) : 0;
        bool required = (securityMode & 0x02) != 0;
        sb.Append(", Signing ").Append(required ? "required" : "enabled");
        AppendCaps(sb, caps);
    }

    private static void AppendTreeConnect(StringBuilder sb, byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        bool isResponse, uint status, ulong sessionId, ulong messageId, uint treeId)
    {
        if (isResponse)
        {
            // The assigned TreeId is in the response header; resolve the pending path to it only
            // on success (a failed tree connect returns TreeId 0 and must not be recorded).
            if (status == 0) ResolveTree(sessionId, messageId, treeId);
            else DiscardPending(sessionId, messageId);
            return; // header-only body
        }
        if (bodyLen < 8) return;
        ushort pathOffset = ReadUInt16LE(data, off + 4);
        ushort pathLength = ReadUInt16LE(data, off + 6);
        string path = ExtractName(data, hdr + pathOffset, pathLength, off, cmdEnd);
        if (path != null)
        {
            RecordPending(sessionId, messageId, 1, path);
            sb.Append(", ").Append(path);
        }
    }

    private static void AppendCreate(StringBuilder sb, byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        bool isResponse, uint status, ulong sessionId, ulong messageId)
    {
        if (!isResponse)
        {
            if (bodyLen < 56) return;
            ushort nameOffset = ReadUInt16LE(data, off + 44);
            ushort nameLength = ReadUInt16LE(data, off + 46);
            uint disp = ReadUInt32LE(data, off + 36);
            string name = ExtractName(data, hdr + nameOffset, nameLength, off, cmdEnd);
            if (name == null) name = "";
            RecordPending(sessionId, messageId, 2, name);
            sb.Append(", File: ").Append(name.Length == 0 ? "<root>" : name);
            sb.Append("; Disposition: ").Append(disp < (uint)CreateDispositions.Length
                ? CreateDispositions[disp] : "0x" + disp.ToString("X"));
        }
        else
        {
            // Interim async response: keep the pending filename for the final response and
            // render the header line only (no FileId body present).
            if (status == STATUS_PENDING) return;
            // Terminal failure (or a too-short body): the generic SMB2 ERROR body is NOT a CREATE
            // response, so don't parse it. Discard the correlation; the header already shows the
            // status.
            if (status != 0 || bodyLen < 80) { DiscardPending(sessionId, messageId); return; }
            AppendCreateRespTail(sb, data, off, bodyLen, sessionId, messageId);
        }
    }

    private static void AppendCreateRespTail(StringBuilder sb, byte[] data, int off, int bodyLen,
        ulong sessionId, ulong messageId)
    {
        uint action = ReadUInt32LE(data, off + 4);
        ulong fidP = ReadUInt64LE(data, off + 64);
        ulong fidV = ReadUInt64LE(data, off + 72);
        ResolveFile(sessionId, messageId, fidP, fidV);
        sb.Append(", File: ").Append(FileIdDisplay(data, off + 64, fidP, fidV));
        sb.Append("; Action: ").Append(action < (uint)CreateActions.Length
            ? CreateActions[action] : "0x" + action.ToString("X"));
    }

    private static void AppendReadWrite(StringBuilder sb, byte[] data, int off, int bodyLen,
        bool isResponse, bool isRead, uint status, ulong sessionId, ulong messageId)
    {
        if (!isResponse)
        {
            if (bodyLen < 32) return;
            uint length = ReadUInt32LE(data, off + 4);
            ulong fileOff = ReadUInt64LE(data, off + 8);
            sb.Append(", Len: ").Append(length).Append("; Off: ").Append(fileOff).Append("; ");
            AppendReqFile(sb, data, off, bodyLen, 16, sessionId, messageId, true);
        }
        else
        {
            // Response frames carry no FileId; echo the request's resolved handle name.
            uint n = (bodyLen >= 8) ? ReadUInt32LE(data, off + 4) : 0; // DataLength (read) / Count (write)
            sb.Append(", ");
            if (AppendRespFile(sb, status, sessionId, messageId)) sb.Append("; ");
            sb.Append("Len: ").Append(n);
        }
    }

    private static void AppendIoctl(StringBuilder sb, byte[] data, int off, int bodyLen)
    {
        if (bodyLen < 8) return;
        uint ctl = ReadUInt32LE(data, off + 4);
        string name;
        sb.Append(", ");
        if (IoctlNames.TryGetValue(ctl, out name)) sb.Append(name).Append(" (0x").Append(ctl.ToString("x8")).Append(")");
        else sb.Append("0x").Append(ctl.ToString("x8"));
    }

    private static void AppendQueryDirectory(StringBuilder sb, byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        bool isResponse, uint status, ulong sessionId, ulong messageId)
    {
        if (isResponse)
        {
            sb.Append(", ");
            if (!AppendRespFile(sb, status, sessionId, messageId)) sb.Length -= 2;
            return;
        }
        if (bodyLen < 32) return;
        byte infoClass = data[off + 2];
        ushort nameOffset = ReadUInt16LE(data, off + 24);
        ushort nameLength = ReadUInt16LE(data, off + 26);
        string pattern = ExtractName(data, hdr + nameOffset, nameLength, off, cmdEnd);
        sb.Append(", ");
        AppendReqFile(sb, data, off, bodyLen, 8, sessionId, messageId, true);
        sb.Append("; ").Append(FileInfoClassName(infoClass)).Append(" (0x").Append(infoClass.ToString("x2")).Append(')');
        sb.Append(", Pattern: ").Append(string.IsNullOrEmpty(pattern) ? "*" : pattern);
    }

    private static void AppendChangeNotify(StringBuilder sb, byte[] data, int off, int bodyLen,
        bool isResponse, ulong sessionId, ulong messageId)
    {
        if (isResponse) return; // header-only, no echo
        if (bodyLen < 28) return;
        uint filter = ReadUInt32LE(data, off + 24);
        sb.Append(", ");
        AppendReqFile(sb, data, off, bodyLen, 8, sessionId, messageId, false);
        sb.Append("; Completion Filter: 0x").Append(filter.ToString("x8")).Append(", ");
        AppendFlagList(sb, filter, ChangeNotifyFilters);
    }

    private static void AppendQuerySetInfo(StringBuilder sb, byte[] data, int off, int bodyLen,
        bool isResponse, bool isQuery, uint status, ulong sessionId, ulong messageId)
    {
        if (isResponse)
        {
            sb.Append(", ");
            if (!AppendRespFile(sb, status, sessionId, messageId)) sb.Length -= 2;
            return;
        }
        if (bodyLen < 4) return;
        byte infoType = data[off + 2];
        byte infoClass = data[off + 3];
        int fidOff = isQuery ? 24 : 16; // QUERY_INFO FileId@24, SET_INFO FileId@16
        sb.Append(", ").Append(InfoTypeName(infoType)).Append('\\').Append(InfoClassName(infoType, infoClass));
        sb.Append(isQuery ? ", " : "; ");
        AppendReqFile(sb, data, off, bodyLen, fidOff, sessionId, messageId, true);
    }

    private static void AppendOplockBreak(StringBuilder sb, byte[] data, int off, int bodyLen, bool isResponse)
    {
        if (bodyLen < 2) return;
        ushort structSize = ReadUInt16LE(data, off);
        if (structSize == 24)
        {
            // Oplock break notification / acknowledgment / response.
            if (bodyLen < 24) return;
            byte level = data[off + 2];
            ulong fidP = ReadUInt64LE(data, off + 8);
            ulong fidV = ReadUInt64LE(data, off + 16);
            string levelName;
            if (!OplockLevelNames.TryGetValue(level, out levelName)) levelName = "0x" + level.ToString("x2");
            sb.Append(", Oplock ").Append(isResponse ? "Response" : "Break");
            sb.Append(": Level ").Append(levelName).Append(" (0x").Append(level.ToString("x2")).Append(')');
            sb.Append("; FileId: ").Append(FileIdDisplay(data, off + 8, fidP, fidV));
        }
        else if (structSize == 44 && bodyLen >= 32)
        {
            // Lease break.
            uint cur = ReadUInt32LE(data, off + 24);
            uint nw  = ReadUInt32LE(data, off + 28);
            sb.Append(", Lease Break: ").Append(LeaseStateStr(cur)).Append(" -> ").Append(LeaseStateStr(nw));
            sb.Append("; LeaseKey: ").Append(FormatGuid(data, off + 8));
        }
        else if (structSize == 36 && bodyLen >= 28)
        {
            // Lease break acknowledgment (client) / response (server).
            uint state = ReadUInt32LE(data, off + 24);
            sb.Append(isResponse ? ", Lease Response: " : ", Lease Ack: ").Append(LeaseStateStr(state));
            sb.Append("; LeaseKey: ").Append(FormatGuid(data, off + 8));
        }
    }

    // ---- resolution / display helpers ----

    // Resolves and displays the file for a request that carries a FileId at body+fidOff. When
    // <paramref name="stashEcho"/> is set (only for commands whose response echoes the handle:
    // READ, WRITE, LOCK, QUERY_DIRECTORY, QUERY_INFO, SET_INFO) the resolved "name (0xhex)" text
    // is stashed keyed by (SessionId, MessageId) so the response can echo it (response frames
    // carry no FileId). Commands with header-only responses (CLOSE, FLUSH, CHANGE_NOTIFY) pass
    // stashEcho=false so their entries can't leak.
    private static void AppendReqFile(StringBuilder sb, byte[] data, int off, int bodyLen, int fidOff,
        ulong sessionId, ulong messageId, bool stashEcho)
    {
        if (bodyLen < fidOff + 16) { sb.Append("File: ?"); return; }
        ulong p = ReadUInt64LE(data, off + fidOff);
        ulong v = ReadUInt64LE(data, off + fidOff + 8);
        string shown = FileIdDisplay(data, off + fidOff, p, v);
        sb.Append("File: ").Append(shown);
        if (stashEcho) RecordPending(sessionId, messageId, 3, shown);
    }

    // Builds the "File:" display value for a 16-byte FileId located at data[fidByteOffset..]:
    // the resolved name (when known) plus the FileId rendered as a GUID string. An unknown
    // handle shows just the GUID, so it's still uniquely identifiable (e.g. to cross-reference
    // with Wireshark).
    private static string FileIdDisplay(byte[] data, int fidByteOffset, ulong persistent, ulong volatil)
    {
        string guid = FormatGuid(data, fidByteOffset);
        string name = LookupFile(persistent, volatil);
        if (name != null && name.Length > 0) return name + " (" + guid + ")";
        return guid;
    }

    private static bool AppendRespFile(StringBuilder sb, uint status, ulong sessionId, ulong messageId)
    {
        // An interim STATUS_PENDING response must not consume the stashed echo — the final
        // response still needs it. Peek in that case; otherwise take (and remove).
        string echo = TakeHandleEcho(sessionId, messageId, status == STATUS_PENDING);
        if (echo == null) return false;
        sb.Append("File: ").Append(echo);
        return true;
    }

    private static string TakeHandleEcho(ulong sessionId, ulong messageId, bool peek)
    {
        lock (_stateLock)
        {
            U64Pair key = new U64Pair(sessionId, messageId);
            PendingName pn;
            if (_pending.TryGetValue(key, out pn) && pn.Kind == 3)
            {
                if (!peek) _pending.Remove(key);
                return pn.Name;
            }
        }
        return null;
    }

    // Bounded UTF-16LE decode: the string must lie fully inside [rangeStart, rangeEnd) so a
    // malformed offset can't read into the packet header or the next chained command.
    private static string ExtractName(byte[] data, int start, int length, int rangeStart, int rangeEnd)
    {
        if (length <= 0 || start < rangeStart || start + length > rangeEnd || rangeEnd > data.Length) return null;
        try { return Encoding.Unicode.GetString(data, start, length & ~1); }
        catch { return null; }
    }

    private static string StatusName(uint status)
    {
        string name;
        return StatusNames.TryGetValue(status, out name) ? name : "0x" + status.ToString("X8");
    }

    private static string DialectName(ushort dialect)
    {
        switch (dialect)
        {
            case 0x0202: return "2.0.2";
            case 0x0210: return "2.1";
            case 0x0222: return "2.2.2";
            case 0x0224: return "2.2.4";
            case 0x0300: return "3.0";
            case 0x0302: return "3.0.2";
            case 0x0311: return "3.1.1";
            case 0x02FF: return "2.wildcard";
            default:     return "0x" + dialect.ToString("X4");
        }
    }

    private static void AppendCaps(StringBuilder sb, uint caps)
    {
        if (caps == 0) return;
        bool first = true;
        for (int i = 0; i < NegotiateCaps.Length; i++)
        {
            if ((caps & NegotiateCaps[i].Key) != 0)
            {
                sb.Append(first ? "; " : ", ").Append(NegotiateCaps[i].Value);
                first = false;
            }
        }
    }

    private static void AppendFlagList(StringBuilder sb, uint flags, KeyValuePair<uint, string>[] table)
    {
        bool first = true;
        for (int i = 0; i < table.Length; i++)
        {
            if ((flags & table[i].Key) != 0)
            {
                if (!first) sb.Append(", ");
                sb.Append(table[i].Value);
                first = false;
            }
        }
        if (first) sb.Append("(none)");
    }

    private static string InfoTypeName(byte infoType)
    {
        return (infoType < InfoTypeNames.Length && InfoTypeNames[infoType] != null)
            ? InfoTypeNames[infoType] : "Type0x" + infoType.ToString("x2");
    }

    private static string InfoClassName(byte infoType, byte infoClass)
    {
        if (infoType == 2) // FILESYSTEM
        {
            string fs;
            if (FsInfoClassNames.TryGetValue(infoClass, out fs)) return fs;
        }
        else if (infoType == 3) return "SecurityDescriptor";
        return FileInfoClassName(infoClass);
    }

    private static string FileInfoClassName(int infoClass)
    {
        string name;
        return FileInfoClassNames.TryGetValue(infoClass, out name) ? name : "Class0x" + infoClass.ToString("x2");
    }

    private static string LeaseStateStr(uint state)
    {
        if (state == 0) return "None";
        StringBuilder sb = new StringBuilder(3);
        if ((state & 0x01) != 0) sb.Append('R');
        if ((state & 0x02) != 0) sb.Append('H');
        if ((state & 0x04) != 0) sb.Append('W');
        return sb.Length == 0 ? "None" : sb.ToString();
    }

    // Formats a 16-byte SMB2 GUID (LeaseKey / ClientGuid) as a standard GUID string.
    private static string FormatGuid(byte[] data, int off)
    {
        if (off + 16 > data.Length) return "";
        byte[] g = new byte[16];
        Buffer.BlockCopy(data, off, g, 0, 16);
        try { return new Guid(g).ToString(); }
        catch { return ""; }
    }

    /// <summary>
    /// Detailed-level SMB2 line. Per SMB2_parser_instructions.md the Detailed output is
    /// identical to Default, so this delegates to <see cref="FormatSmb2Segment"/>.
    /// </summary>
    public static string FormatSmb2Detailed(byte[] data, int srcPort, int dstPort)
    {
        return FormatSmb2Segment(data, data != null ? data.Length : 0, srcPort, dstPort);
    }

    public static string FormatSmb2Detailed(byte[] data, int dataLen, int srcPort, int dstPort)
    {
        return FormatSmb2Segment(data, dataLen, srcPort, dstPort);
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

    /// <summary>
    /// Parses just the SMB2 (or Transform) header plus the minimum body needed
    /// by the application-layer predicate: filename for Create requests, share
    /// path for TreeConnect requests. Returns false when the payload isn't a
    /// recognisable SMB2 packet for the given ports.
    ///
    /// Designed to be cheap enough to run on every TCP/445 packet when an SMB2
    /// predicate is configured. The legacy <see cref="FormatSmb2Segment"/> /
    /// <see cref="FormatSmb2Detailed"/> formatters take the byte buffer directly
    /// and re-do their own per-command extraction; the small re-parse cost on
    /// matching packets is a deliberate trade-off to avoid refactoring the
    /// large per-command formatter functions.
    /// </summary>
    public static bool TryParseSmb2Header(byte[] data, int srcPort, int dstPort, out Smb2Context ctx)
    {
        return TryParseSmb2Header(data, data != null ? data.Length : 0, srcPort, dstPort, out ctx);
    }

    public static bool TryParseSmb2Header(byte[] data, int dataLen, int srcPort, int dstPort, out Smb2Context ctx)
    {
        int len = dataLen;
        if (data == null) len = 0;
        else if (len > data.Length) len = data.Length;

        ctx = default(Smb2Context);
        if (!IsSmb2Packet(data, len, srcPort, dstPort)) return false;

        // Same Direct TCP framing skip as the formatters.
        int offset = 0;
        if (data[0] == 0x00 && len >= 8)
        {
            uint probe = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
            if (probe == SMB2_MAGIC || probe == SMB2_TRANSFORM_MAGIC)
                offset = 4;
        }
        if (len < offset + 4) return false;
        uint headerMagic = (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));

        // Transform header — only the session ID is reachable; everything else
        // is encrypted. Mark IsEncrypted and stop.
        if (headerMagic == SMB2_TRANSFORM_MAGIC)
        {
            ctx.IsEncrypted = true;
            if (len >= offset + 52)
            {
                ctx.SessionId = ReadUInt64LE(data, offset + 44);
            }
            ctx.Valid = true;
            return true;
        }

        if (headerMagic != SMB2_MAGIC) return false;
        if (len < offset + 64) return false;
        ushort structSize = ReadUInt16LE(data, offset + 4);
        if (structSize != 64) return false;

        ctx.Status       = ReadUInt32LE(data, offset + 8);
        ctx.Command      = ReadUInt16LE(data, offset + 12);
        uint flags       = ReadUInt32LE(data, offset + 16);
        uint nextCommand = ReadUInt32LE(data, offset + 20);
        ctx.MessageId    = ReadUInt64LE(data, offset + 24);
        ctx.TreeId       = ReadUInt32LE(data, offset + 36);
        ctx.SessionId    = ReadUInt64LE(data, offset + 40);
        ctx.IsResponse   = (flags & 0x00000001) != 0;
        ctx.IsCompounded = nextCommand != 0;

        int bodyOff = offset + 64;
        int bodyLen = len - bodyOff;

        // Per-command extraction for the only two predicate-relevant fields.
        // Layouts mirror the existing formatter extractions verbatim so behavior
        // stays consistent.
        if (!ctx.IsResponse)
        {
            if (ctx.Command == 0x0005 && bodyLen >= 56) // CREATE request
            {
                ushort nameOffset = ReadUInt16LE(data, bodyOff + 44);
                ushort nameLength = ReadUInt16LE(data, bodyOff + 46);
                int absStart = offset + nameOffset;
                if (nameLength > 0 && absStart >= 0 && absStart + nameLength <= len)
                {
                    ctx.Filename = DecodeUtf16Le(data, len, absStart, nameLength);
                }
                else if (nameLength > 0)
                {
                    ctx.Truncated = true;
                }
            }
            else if (ctx.Command == 0x0003 && bodyLen >= 8) // TREE_CONNECT request
            {
                ushort pathOffset = ReadUInt16LE(data, bodyOff + 4);
                ushort pathLength = ReadUInt16LE(data, bodyOff + 6);
                int absStart = offset + pathOffset;
                if (pathLength > 0 && absStart >= 0 && absStart + pathLength <= len)
                {
                    ctx.TreePath = DecodeUtf16Le(data, len, absStart, pathLength);
                }
                else if (pathLength > 0)
                {
                    ctx.Truncated = true;
                }
            }
        }

        ctx.Valid = true;
        return true;
    }

    // Standalone UTF-16LE decoder — does not require access to ExtractUnicodeString's
    // private state. Stops on first NUL pair to match the existing formatter behavior.
    private static string DecodeUtf16Le(byte[] data, int dataLen, int offset, int length)
    {
        if (data == null || length <= 0) return null;
        if (offset < 0 || offset + length > dataLen) return null;
        // Length is in bytes; ensure even.
        int byteLen = length & ~1;
        if (byteLen == 0) return string.Empty;
        try
        {
            return Encoding.Unicode.GetString(data, offset, byteLen);
        }
        catch
        {
            return null;
        }
    }
}
