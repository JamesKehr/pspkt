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

    // SMB1 header magic: 0xFF 'S' 'M' 'B' (only the Negotiate Protocol request is parsed).
    private const uint SMB1_MAGIC = 0x424D53FF;

    // NT STATUS_PENDING: an interim response that must not consume request-correlation state.
    private const uint STATUS_PENDING = 0x00000103;
    // Nonzero statuses that still carry a command-specific response body (not a generic ERROR),
    // per MS-SMB2 3.3.4.4 "Sending an Error Response".
    private const uint STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
    private const uint STATUS_BUFFER_OVERFLOW = 0x80000005;
    private const uint STATUS_INVALID_PARAMETER = 0xC000000D;
    private const uint STATUS_NOTIFY_ENUM_DIR = 0x0000010C;

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
    // (SessionId, MessageId) -> packed (InfoType << 8 | FileInfoClass) recorded from a
    // QUERY_DIRECTORY / QUERY_INFO request, so the Analysis detail tree can parse the matching
    // response output buffer (whose structure depends on the requested class).
    private static readonly Dictionary<U64Pair, int> _pendingInfo = new Dictionary<U64Pair, int>();

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
            _pendingInfo.Clear();
        }
    }

    // Records the (InfoType, FileInfoClass) of a QUERY_DIRECTORY / QUERY_INFO request so the
    // matching response's output buffer can be parsed. Not consumed on read (the detail tree may
    // re-parse the response as the user navigates); bounded + cleared with the other state.
    private static void RecordInfoClass(ulong sessionId, ulong messageId, byte infoType, byte infoClass)
    {
        lock (_stateLock)
        {
            U64Pair key = new U64Pair(sessionId, messageId);
            if (_pendingInfo.Count >= StateCap && !_pendingInfo.ContainsKey(key)) return;
            _pendingInfo[key] = (infoType << 8) | infoClass;
        }
    }

    // Returns true and outputs (infoType, infoClass) when a request's class was recorded.
    private static bool LookupInfoClass(ulong sessionId, ulong messageId, out byte infoType, out byte infoClass)
    {
        infoType = 0; infoClass = 0;
        lock (_stateLock)
        {
            int packed;
            if (!_pendingInfo.TryGetValue(new U64Pair(sessionId, messageId), out packed)) return false;
            infoType = (byte)((packed >> 8) & 0xFF);
            infoClass = (byte)(packed & 0xFF);
            return true;
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

    private static string LookupTree(ulong sessionId, uint treeId)
    {
        lock (_stateLock)
        {
            string name;
            return _treeNames.TryGetValue(new U64Pair(sessionId, treeId), out name) ? name : null;
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

        // Encrypted (Transform header): only the OriginalMessageSize and SessionId are in the
        // clear. Layout (MS-SMB2 2.2.41): ProtocolId@0, Signature@4, Nonce@20,
        // OriginalMessageSize@36, Reserved@40, Flags@42, SessionId@44.
        if (headerMagic == SMB2_TRANSFORM_MAGIC)
        {
            if (len < offset + 52) return "SMB2 Encrypted";
            uint msgSize = ReadUInt32LE(data, offset + 36);
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
            // Response layout: SecurityMode@2, DialectRevision@4, NegotiateContextCount@6,
            // ServerGuid@8 (16), Capabilities@24, MaxTransact@28, MaxRead@32, MaxWrite@36.
            if (bodyLen < 40) return;
            ushort dialect = ReadUInt16LE(data, off + 4);
            uint caps        = ReadUInt32LE(data, off + 24);
            uint maxTransact = ReadUInt32LE(data, off + 28);
            uint maxRead     = ReadUInt32LE(data, off + 32);
            uint maxWrite    = ReadUInt32LE(data, off + 36);
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
            sb.Append(", Disposition: ").Append(disp < (uint)CreateDispositions.Length
                ? CreateDispositions[disp] : "0x" + disp.ToString("X"));
            sb.Append("; File: ").Append(name.Length == 0 ? "<root>" : name);
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
        sb.Append(", Action: ").Append(action < (uint)CreateActions.Length
            ? CreateActions[action] : "0x" + action.ToString("X"));
        sb.Append("; File: ").Append(FileIdDisplay(data, off + 64, fidP, fidV));
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
        RecordInfoClass(sessionId, messageId, 0, infoClass);
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
        if (isQuery) RecordInfoClass(sessionId, messageId, infoType, infoClass);
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
    // the resolved name when known, otherwise the FileId rendered as a GUID string. The GUID is
    // shown only when the FID table has no matching name (so a known handle reads cleanly as just
    // its path; an unknown one stays uniquely identifiable, e.g. to cross-reference with Wireshark).
    private static string FileIdDisplay(byte[] data, int fidByteOffset, ulong persistent, ulong volatil)
    {
        string name = LookupFile(persistent, volatil);
        if (name != null && name.Length > 0) return name;
        return FormatGuid(data, fidByteOffset);
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

    // =======================================================================
    // Analysis "Details" tree (Phase 2a: collapsed header + expanded SMB header).
    // Builds a Wireshark-style hierarchical view on demand for a selected packet.
    // Per-command body subtrees (2b) and FileInfo result parsing (2c) follow.
    // =======================================================================

    /// <summary>
    /// Builds the Analysis Details tree for an SMB2 packet: one root node per message in the
    /// (possibly compounded) chain. Each root's collapsed text is
    /// "SMB2 &lt;Command&gt; - &lt;tree&gt;[; Status: ...]" and expands to the SMB header subtree.
    /// Transform (encrypted) and SMB1 Negotiate headers get their own single-root form.
    /// </summary>
    public static List<BoxyBox.TreeNode> BuildSmb2DetailTree(byte[] data, int len, int srcPort, int dstPort)
    {
        var roots = new List<BoxyBox.TreeNode>();
        if (data == null) return roots;
        if (len > data.Length) len = data.Length;
        if (len < 4) return roots;

        int offset = 0;
        if (len >= 8 && data[0] == 0x00)
        {
            uint probe = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
            if (probe == SMB2_MAGIC || probe == SMB2_TRANSFORM_MAGIC || probe == SMB1_MAGIC) offset = 4;
        }
        if (len < offset + 4) return roots;
        uint magic = (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));

        if (magic == SMB2_TRANSFORM_MAGIC) { roots.Add(BuildTransformNode(data, len, offset)); return roots; }
        if (magic == SMB1_MAGIC)           { roots.Add(BuildSmb1NegotiateNode(data, len, offset)); return roots; }
        if (magic != SMB2_MAGIC)           return roots;

        int cmdOffset = offset;
        int guard = 0;
        while (cmdOffset + 64 <= len && guard++ < 64)
        {
            uint m = (uint)(data[cmdOffset] | (data[cmdOffset + 1] << 8) | (data[cmdOffset + 2] << 16) | (data[cmdOffset + 3] << 24));
            if (m != SMB2_MAGIC) break;
            if (ReadUInt16LE(data, cmdOffset + 4) != 64) break;
            uint nextCommand = ReadUInt32LE(data, cmdOffset + 20);
            roots.Add(BuildSmb2CommandNode(data, len, cmdOffset));
            if (nextCommand == 0 || nextCommand < 64 || nextCommand > (uint)(len - cmdOffset)) break;
            cmdOffset += (int)nextCommand;
        }
        return roots;
    }

    private static BoxyBox.TreeNode BuildSmb2CommandNode(byte[] data, int len, int hdr)
    {
        uint status     = ReadUInt32LE(data, hdr + 8);
        ushort command  = ReadUInt16LE(data, hdr + 12);
        uint flags      = ReadUInt32LE(data, hdr + 16);
        uint nextCommand = ReadUInt32LE(data, hdr + 20);
        ulong messageId = ReadUInt64LE(data, hdr + 24);
        uint treeId     = ReadUInt32LE(data, hdr + 36);
        ulong sessionId = ReadUInt64LE(data, hdr + 40);
        bool isResponse = (flags & 0x00000001) != 0;
        bool isAsync    = (flags & 0x00000002) != 0;
        string cmdName  = command < CommandNames.Length ? CommandNames[command] : "CMD_0x" + command.ToString("X4");

        // Collapsed root text: "SMB2 <cmd> - <tree>[; Status: ...]".
        string tree;
        if (isAsync) tree = "(async)";
        else { string t = LookupTree(sessionId, treeId); tree = t != null ? t : "TID 0x" + treeId.ToString("x"); }
        var sb = new StringBuilder(96);
        sb.Append("SMB2 ").Append(cmdName).Append(" - ").Append(tree);
        if (isResponse && status != 0)
            sb.Append("; Status: ").Append(StatusName(status)).Append(" (0x").Append(status.ToString("X8")).Append(")");

        var root = new BoxyBox.TreeNode(sb.ToString(), "SMB2", true);
        root.Add(BuildSmb2HeaderNode(data, len, hdr, command, cmdName, flags, status, isResponse, isAsync, treeId, sessionId));

        // Command body range: [hdr+64, cmdEnd) where cmdEnd is bounded by a valid NextCommand.
        int bodyOff = hdr + 64;
        int cmdEnd = len;
        if (nextCommand != 0 && nextCommand >= 64 && nextCommand <= (uint)(len - hdr)) cmdEnd = hdr + (int)nextCommand;
        int bodyLen = cmdEnd - bodyOff;
        if (bodyLen < 0) bodyLen = 0;
        root.Add(BuildSmb2CommandBodyNode(data, cmdEnd, hdr, bodyOff, bodyLen, command, cmdName, isResponse, status, sessionId, messageId));
        return root;
    }

    private static BoxyBox.TreeNode BuildSmb2HeaderNode(byte[] data, int len, int hdr, ushort command, string cmdName,
        uint flags, uint status, bool isResponse, bool isAsync, uint treeId, ulong sessionId)
    {
        // Collapsed summary line: "SMB2 Header - Cmd: <cmd> (0x<h>) <Request|Response>, TID: <tree>[, Status: ...]".
        string tid = isAsync ? "(async)" : (LookupTree(sessionId, treeId) ?? "0x" + treeId.ToString("x"));
        var hdrText = new StringBuilder(80);
        hdrText.Append("SMB2 Header - Cmd: ").Append(cmdName).Append(" (0x").Append(command.ToString("x4")).Append(") ")
               .Append(isResponse ? "Response" : "Request").Append(", TID: ").Append(tid);
        if (isResponse && status != 0)
            hdrText.Append(", Status: ").Append(StatusName(status)).Append(" (0x").Append(status.ToString("X8")).Append(")");
        var h = new BoxyBox.TreeNode(hdrText.ToString(), "SMB2.Header", false);
        h.AddLeaf("ProtocolId: 0x" + HexBytes(data, hdr, 4, len));
        h.AddLeaf("Header Length: " + ReadUInt16LE(data, hdr + 4));
        h.AddLeaf("Credit Charge: " + ReadUInt16LE(data, hdr + 6));
        if (isResponse)
        {
            h.AddLeaf("NT Status: " + StatusName(status) + " (0x" + status.ToString("X8") + ")");
        }
        else
        {
            h.AddLeaf("Channel Sequence: " + ReadUInt16LE(data, hdr + 8));
            h.AddLeaf("Reserved: " + HexBytes(data, hdr + 10, 2, len));
        }
        h.AddLeaf("Command: " + cmdName + " (" + command + ")");
        h.AddLeaf((isResponse ? "Credits granted: " : "Credits requested: ") + ReadUInt16LE(data, hdr + 14));
        h.Add(BuildSmb2FlagsNode(flags, isResponse));
        h.AddLeaf("Chain Offset: 0x" + ReadUInt32LE(data, hdr + 20).ToString("x"));
        h.AddLeaf("Message ID: " + ReadUInt64LE(data, hdr + 24));
        if (isAsync)
        {
            h.AddLeaf("Async Id: 0x" + ReadUInt64LE(data, hdr + 32).ToString("x"));
        }
        else
        {
            h.AddLeaf("Reserved: 0x" + ReadUInt32LE(data, hdr + 32).ToString("x"));
            string t = LookupTree(sessionId, treeId);
            string treeLine = "Tree Id: 0x" + treeId.ToString("x");
            if (t != null) treeLine += "  " + t;
            h.AddLeaf(treeLine);
        }
        h.AddLeaf("Session Id: 0x" + ReadUInt64LE(data, hdr + 40).ToString("x"));
        h.AddLeaf("Signature: " + HexBytes(data, hdr + 48, 16, len));
        return h;
    }

    // -----------------------------------------------------------------------
    // Per-command body subtree (Phase 2b). Field selection follows the Wireshark
    // SMB2 dissector. FileInfo result parsing (QUERY_DIRECTORY / QUERY_INFO /
    // SET_INFO output buffers) is deferred to Phase 2c.
    // -----------------------------------------------------------------------
    private static BoxyBox.TreeNode BuildSmb2CommandBodyNode(byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        ushort command, string cmdName, bool isResponse, uint status, ulong sessionId, ulong messageId)
    {
        var node = new BoxyBox.TreeNode(cmdName + (isResponse ? " Response" : " Request"), "SMB2.Command", true);
        if (bodyLen >= 2) node.AddLeaf("Structure Size: " + ReadUInt16LE(data, off));

        // A generic SMB2 ERROR response (StructureSize 9) has no command-specific fields. Detect
        // it by status: a nonzero status means a generic error body EXCEPT for the few
        // "body-bearing" statuses (SESSION_SETUP + MORE_PROCESSING_REQUIRED during auth, and
        // BUFFER_OVERFLOW for READ/IOCTL/QUERY_INFO which still return a partial body).
        if (isResponse && !ResponseHasCommandBody(command, status))
        {
            if (bodyLen >= 8) node.AddLeaf("Byte Count: " + ReadUInt32LE(data, off + 4));
            return node;
        }

        switch (command)
        {
            case 0x0000: BuildNegotiateBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            case 0x0001: BuildSessionSetupBody(node, data, off, bodyLen, isResponse); break;
            case 0x0003: BuildTreeConnectBody(node, data, cmdEnd, hdr, off, bodyLen, isResponse); break;
            case 0x0005: BuildCreateBody(node, data, cmdEnd, hdr, off, bodyLen, isResponse); break;
            case 0x0006: BuildCloseBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            case 0x0007: if (!isResponse) node.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd)); break; // FLUSH
            case 0x0008: BuildReadBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            case 0x0009: BuildWriteBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            case 0x000A: if (bodyLen >= 24) node.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd)); break; // LOCK
            case 0x000B: BuildIoctlBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            case 0x000E: BuildQueryDirectoryBody(node, data, cmdEnd, hdr, off, bodyLen, isResponse, sessionId, messageId); break;
            case 0x000F: BuildChangeNotifyBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            case 0x0010: BuildQueryInfoBody(node, data, cmdEnd, hdr, off, bodyLen, isResponse, true, sessionId, messageId); break;
            case 0x0011: BuildQueryInfoBody(node, data, cmdEnd, hdr, off, bodyLen, isResponse, false, sessionId, messageId); break;
            case 0x0012: BuildOplockBreakBody(node, data, cmdEnd, off, bodyLen, isResponse); break;
            // LOGOFF / TREE_DISCONNECT / CANCEL / ECHO: structure size only.
        }
        return node;
    }

    private static void BuildNegotiateBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 36) return;
            ushort dialectCount = ReadUInt16LE(data, off + 2);
            n.AddLeaf("Dialect Count: " + dialectCount);
            n.AddLeaf("Security Mode: 0x" + ReadUInt16LE(data, off + 4).ToString("x4") + SigningSummary(ReadUInt16LE(data, off + 4)));
            n.AddLeaf("Capabilities: 0x" + ReadUInt32LE(data, off + 8).ToString("x8") + CapSummary(ReadUInt32LE(data, off + 8)));
            n.AddLeaf("Client GUID: " + FormatGuid(data, off + 12));
            var d = new BoxyBox.TreeNode("Dialects", "SMB2.Dialects", false);
            for (int i = 0; i < dialectCount; i++)
            {
                int p = off + 36 + i * 2;
                if (p + 2 > cmdEnd) break;
                d.AddLeaf(DialectName(ReadUInt16LE(data, p)) + " (0x" + ReadUInt16LE(data, p).ToString("x4") + ")");
            }
            n.Add(d);
        }
        else
        {
            if (bodyLen < 64) return;
            n.AddLeaf("Security Mode: 0x" + ReadUInt16LE(data, off + 2).ToString("x4") + SigningSummary(ReadUInt16LE(data, off + 2)));
            ushort dialect = ReadUInt16LE(data, off + 4);
            n.AddLeaf("Dialect: " + DialectName(dialect) + " (0x" + dialect.ToString("x4") + ")");
            n.AddLeaf("Server GUID: " + FormatGuid(data, off + 8));
            n.AddLeaf("Capabilities: 0x" + ReadUInt32LE(data, off + 24).ToString("x8") + CapSummary(ReadUInt32LE(data, off + 24)));
            n.AddLeaf("Max Transaction Size: " + ReadUInt32LE(data, off + 28));
            n.AddLeaf("Max Read Size: " + ReadUInt32LE(data, off + 32));
            n.AddLeaf("Max Write Size: " + ReadUInt32LE(data, off + 36));
            n.AddLeaf("System Time: " + FileTime(data, off + 40, cmdEnd));
            n.AddLeaf("Server Start Time: " + FileTime(data, off + 48, cmdEnd));
        }
    }

    private static void BuildSessionSetupBody(BoxyBox.TreeNode n, byte[] data, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 24) return;
            n.AddLeaf("Flags: 0x" + data[off + 2].ToString("x2") + (((data[off + 2] & 0x01) != 0) ? " (BINDING)" : ""));
            n.AddLeaf("Security Mode: 0x" + data[off + 3].ToString("x2") + SigningSummary(data[off + 3]));
            n.AddLeaf("Capabilities: 0x" + ReadUInt32LE(data, off + 4).ToString("x8") + CapSummary(ReadUInt32LE(data, off + 4)));
            n.AddLeaf("Previous Session Id: 0x" + ReadUInt64LE(data, off + 16).ToString("x"));
            n.AddLeaf("Security Buffer Length: " + ReadUInt16LE(data, off + 14));
        }
        else
        {
            if (bodyLen < 8) return;
            ushort sf = ReadUInt16LE(data, off + 2);
            var parts = new List<string>(3);
            if ((sf & 0x1) != 0) parts.Add("IS_GUEST");
            if ((sf & 0x2) != 0) parts.Add("IS_NULL");
            if ((sf & 0x4) != 0) parts.Add("ENCRYPT_DATA");
            n.AddLeaf("Session Flags: 0x" + sf.ToString("x4") + (parts.Count > 0 ? " (" + string.Join(", ", parts) + ")" : ""));
            n.AddLeaf("Security Buffer Length: " + ReadUInt16LE(data, off + 6));
        }
    }

    private static void BuildTreeConnectBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int hdr, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 8) return;
            ushort po = ReadUInt16LE(data, off + 4);
            ushort pl = ReadUInt16LE(data, off + 6);
            string path = ExtractName(data, hdr + po, pl, off, cmdEnd);
            if (path != null) n.AddLeaf("Path: " + path);
        }
        else
        {
            if (bodyLen < 16) return;
            byte st = data[off + 2];
            string stn = st == 1 ? "DISK" : st == 2 ? "PIPE" : st == 3 ? "PRINT" : "0x" + st.ToString("x2");
            n.AddLeaf("Share Type: " + stn + " (0x" + st.ToString("x2") + ")");
            n.AddLeaf("Share Flags: 0x" + ReadUInt32LE(data, off + 4).ToString("x8"));
            n.AddLeaf("Capabilities: 0x" + ReadUInt32LE(data, off + 8).ToString("x8"));
            n.AddLeaf("Maximal Access: 0x" + ReadUInt32LE(data, off + 12).ToString("x8"));
        }
    }

    private static void BuildCreateBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int hdr, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 56) return;
            byte oplock = data[off + 3];
            n.AddLeaf("Requested Oplock Level: " + OplockLevelName(oplock) + " (0x" + oplock.ToString("x2") + ")");
            n.AddLeaf("Impersonation Level: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf("Desired Access: 0x" + ReadUInt32LE(data, off + 24).ToString("x8"));
            n.AddLeaf("File Attributes: 0x" + ReadUInt32LE(data, off + 28).ToString("x8") + FileAttrSummary(ReadUInt32LE(data, off + 28)));
            n.AddLeaf("Share Access: 0x" + ReadUInt32LE(data, off + 32).ToString("x8") + ShareAccessSummary(ReadUInt32LE(data, off + 32)));
            uint disp = ReadUInt32LE(data, off + 36);
            n.AddLeaf("Create Disposition: " + (disp < (uint)CreateDispositions.Length ? CreateDispositions[disp] : "0x" + disp.ToString("x")) + " (" + disp + ")");
            n.AddLeaf("Create Options: 0x" + ReadUInt32LE(data, off + 40).ToString("x8") + CreateOptionsSummary(ReadUInt32LE(data, off + 40)));
            ushort no = ReadUInt16LE(data, off + 44);
            ushort nl = ReadUInt16LE(data, off + 46);
            string name = ExtractName(data, hdr + no, nl, off, cmdEnd);
            n.AddLeaf("Name: " + (string.IsNullOrEmpty(name) ? "<root>" : name));
        }
        else
        {
            if (bodyLen < 80) return;
            byte oplock = data[off + 2];
            n.AddLeaf("Oplock Level: " + OplockLevelName(oplock) + " (0x" + oplock.ToString("x2") + ")");
            uint action = ReadUInt32LE(data, off + 4);
            n.AddLeaf("Create Action: " + (action < (uint)CreateActions.Length ? CreateActions[action] : "0x" + action.ToString("x")) + " (" + action + ")");
            n.AddLeaf("Creation Time: " + FileTime(data, off + 8, cmdEnd));
            n.AddLeaf("Last Access Time: " + FileTime(data, off + 16, cmdEnd));
            n.AddLeaf("Last Write Time: " + FileTime(data, off + 24, cmdEnd));
            n.AddLeaf("Change Time: " + FileTime(data, off + 32, cmdEnd));
            n.AddLeaf("Allocation Size: " + ReadUInt64LE(data, off + 40));
            n.AddLeaf("End of File: " + ReadUInt64LE(data, off + 48));
            n.AddLeaf("File Attributes: 0x" + ReadUInt32LE(data, off + 56).ToString("x8") + FileAttrSummary(ReadUInt32LE(data, off + 56)));
            n.AddLeaf(FileIdTreeLine(data, off + 64, cmdEnd));
        }
    }

    private static void BuildCloseBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 24) return;
            ushort f = ReadUInt16LE(data, off + 2);
            n.AddLeaf("Flags: 0x" + f.ToString("x4") + (((f & 0x1) != 0) ? " (POSTQUERY_ATTRIB)" : ""));
            n.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd));
        }
        else
        {
            if (bodyLen < 60) return;
            n.AddLeaf("Flags: 0x" + ReadUInt16LE(data, off + 2).ToString("x4"));
            n.AddLeaf("Creation Time: " + FileTime(data, off + 8, cmdEnd));
            n.AddLeaf("Last Access Time: " + FileTime(data, off + 16, cmdEnd));
            n.AddLeaf("Last Write Time: " + FileTime(data, off + 24, cmdEnd));
            n.AddLeaf("Change Time: " + FileTime(data, off + 32, cmdEnd));
            n.AddLeaf("Allocation Size: " + ReadUInt64LE(data, off + 40));
            n.AddLeaf("End of File: " + ReadUInt64LE(data, off + 48));
            n.AddLeaf("File Attributes: 0x" + ReadUInt32LE(data, off + 56).ToString("x8") + FileAttrSummary(ReadUInt32LE(data, off + 56)));
        }
    }

    private static void BuildReadBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 48) return;
            n.AddLeaf("Length: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf("Offset: " + ReadUInt64LE(data, off + 8));
            n.AddLeaf(FileIdTreeLine(data, off + 16, cmdEnd));
            n.AddLeaf("Minimum Count: " + ReadUInt32LE(data, off + 32));
        }
        else
        {
            if (bodyLen < 16) return;
            n.AddLeaf("Data Offset: " + data[off + 2]);
            n.AddLeaf("Data Length: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf("Data Remaining: " + ReadUInt32LE(data, off + 8));
        }
    }

    private static void BuildWriteBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 48) return;
            n.AddLeaf("Data Offset: " + ReadUInt16LE(data, off + 2));
            n.AddLeaf("Length: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf("Offset: " + ReadUInt64LE(data, off + 8));
            n.AddLeaf(FileIdTreeLine(data, off + 16, cmdEnd));
        }
        else
        {
            if (bodyLen < 16) return;
            n.AddLeaf("Count: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf("Remaining: " + ReadUInt32LE(data, off + 8));
        }
    }

    private static void BuildIoctlBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (bodyLen < 8) return;
        uint ctl = ReadUInt32LE(data, off + 4);
        n.AddLeaf("Control Code: " + IoctlName(ctl) + " (0x" + ctl.ToString("x8") + ")");
        if (bodyLen < 48) return;
        n.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd));
        n.AddLeaf("Input Offset: " + ReadUInt32LE(data, off + 24));
        n.AddLeaf("Input Count: " + ReadUInt32LE(data, off + 28));
        if (isResponse)
        {
            // IOCTL Response (StructureSize 49): OutputOffset@32, OutputCount@36.
            n.AddLeaf("Output Offset: " + ReadUInt32LE(data, off + 32));
            n.AddLeaf("Output Count: " + ReadUInt32LE(data, off + 36));
        }
        else if (bodyLen >= 56)
        {
            // IOCTL Request (StructureSize 57): OutputOffset@36, OutputCount@40.
            n.AddLeaf("Output Offset: " + ReadUInt32LE(data, off + 36));
            n.AddLeaf("Output Count: " + ReadUInt32LE(data, off + 40));
        }
    }

    // A response's body is command-specific when the status is success, or one of the few
    // nonzero statuses that still carry a valid (possibly partial) command body. Every other
    // nonzero status is a generic SMB2 ERROR response.
    private static bool ResponseHasCommandBody(ushort command, uint status)
    {
        if (status == 0) return true;
        // Per MS-SMB2 3.3.4.4, only these command/status pairs return a command-specific body
        // instead of a generic ERROR response. (The IOCTL cases are actually restricted to
        // specific FSCTLs — PIPE_TRANSCEIVE/PEEK/DFS_GET_REFERRALS for overflow, SRV_COPYCHUNK
        // for invalid-parameter — but gating at command+status granularity is close enough for
        // a display aid.)
        switch (command)
        {
            case 0x0001: return status == STATUS_MORE_PROCESSING_REQUIRED;   // SESSION_SETUP
            case 0x0008:                                                     // READ (named pipe)
            case 0x0010: return status == STATUS_BUFFER_OVERFLOW;            // QUERY_INFO
            case 0x000B: return status == STATUS_BUFFER_OVERFLOW             // IOCTL
                             || status == STATUS_INVALID_PARAMETER;
            case 0x000F: return status == STATUS_NOTIFY_ENUM_DIR;            // CHANGE_NOTIFY
            default:     return false;
        }
    }

    private static void BuildQueryDirectoryBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        bool isResponse, ulong sessionId, ulong messageId)
    {
        if (!isResponse)
        {
            if (bodyLen < 32) return;
            byte ic = data[off + 2];
            n.AddLeaf("File Information Class: " + FileInfoClassName(ic) + " (0x" + ic.ToString("x2") + ")");
            n.AddLeaf("Flags: 0x" + data[off + 3].ToString("x2"));
            n.AddLeaf("File Index: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd));
            ushort no = ReadUInt16LE(data, off + 24);
            ushort nl = ReadUInt16LE(data, off + 26);
            string pat = ExtractName(data, hdr + no, nl, off, cmdEnd);
            n.AddLeaf("Search Pattern: " + (string.IsNullOrEmpty(pat) ? "*" : pat));
            n.AddLeaf("Output Buffer Length: " + ReadUInt32LE(data, off + 28));
        }
        else
        {
            if (bodyLen < 8) return;
            ushort obOff = ReadUInt16LE(data, off + 2);
            uint obLen = ReadUInt32LE(data, off + 4);
            n.AddLeaf("Output Buffer Offset: 0x" + obOff.ToString("x4"));
            n.AddLeaf("Output Buffer Length: " + obLen);
            int bufStart = hdr + obOff;
            int bufEnd = bufStart + (int)obLen;
            if (bufEnd > cmdEnd) bufEnd = cmdEnd;
            if (obLen == 0 || bufStart < off || bufStart >= bufEnd) return;
            byte infoType, infoClass;
            if (LookupInfoClass(sessionId, messageId, out infoType, out infoClass))
                BuildDirEntries(n, data, bufStart, bufEnd, infoClass);
            else
                n.AddLeaf("Directory Entries: (request not captured — information class unknown)");
        }
    }

    // Parses the NextEntryOffset-linked list of directory entries in a QUERY_DIRECTORY response
    // output buffer, per the FileInformationClass requested. Entry count is capped for display.
    private static void BuildDirEntries(BoxyBox.TreeNode parent, byte[] data, int start, int end, byte infoClass)
    {
        const int MaxEntries = 500;
        int pos = start;
        int shown = 0;
        int total = 0;
        int guard = 0;
        var entries = new BoxyBox.TreeNode("Directory Entries", "SMB2.DirEntries", false);
        // `pos <= end - 4` (not `pos + 4 <= end`) so a pos near Int32.MaxValue can't overflow the
        // loop condition; NextEntryOffset math is done in long to avoid wrap-around.
        while (pos >= start && pos <= end - 4 && guard++ < 200000)
        {
            uint next = ReadUInt32LE(data, pos);
            long entryEndL = (next == 0) ? end : (long)pos + next;
            int entryEnd = (entryEndL > end || entryEndL <= pos) ? end : (int)entryEndL;
            total++;
            if (shown < MaxEntries) { if (BuildOneDirEntry(entries, data, pos, entryEnd, infoClass, total)) shown++; }
            if (next == 0) break;
            long nextPos = (long)pos + next;
            if (nextPos <= pos || nextPos > end) break;
            pos = (int)nextPos;
        }
        entries.Text = "Directory Entries (" + total + ")" + (total > shown ? " — showing first " + shown : "");
        parent.Add(entries);
    }

    private static bool BuildOneDirEntry(BoxyBox.TreeNode parent, byte[] data, int pos, int end, byte infoClass, int index)
    {
        // FileNamesInformation: NextEntryOffset(4), FileIndex(4), FileNameLength(4), FileName.
        if (infoClass == 0x0C)
        {
            if (pos + 12 > end) return false;
            uint nl0 = ReadUInt32LE(data, pos + 8);
            string nm = ExtractName(data, pos + 12, (int)nl0, pos + 12, end);
            parent.Add(new BoxyBox.TreeNode("[" + index + "] " + (string.IsNullOrEmpty(nm) ? "?" : nm), null, false));
            return true;
        }
        // Common FileXxxDirectoryInformation layout (timestamps at +8..+32, EndOfFile@40,
        // FileAttributes@56, FileNameLength@60; FileName offset varies by class).
        if (pos + 64 > end) return false;
        int fnOff;
        switch (infoClass)
        {
            case 0x01: fnOff = 64;  break; // FileDirectoryInformation
            case 0x02: fnOff = 68;  break; // FileFullDirectoryInformation (+EaSize)
            case 0x03: fnOff = 94;  break; // FileBothDirectoryInformation (+EaSize+ShortName)
            case 0x25: fnOff = 104; break; // FileIdBothDirectoryInformation (+FileId)
            case 0x26: fnOff = 80;  break; // FileIdFullDirectoryInformation (+FileId)
            default:   fnOff = 64;  break;
        }
        ulong eof = ReadUInt64LE(data, pos + 40);
        uint attr = ReadUInt32LE(data, pos + 56);
        uint nameLen = ReadUInt32LE(data, pos + 60);
        string name = ExtractName(data, pos + fnOff, (int)nameLen, pos + fnOff, end);
        var e = new BoxyBox.TreeNode("[" + index + "] " + (string.IsNullOrEmpty(name) ? "?" : name), null, false);
        e.AddLeaf("End of File: " + eof);
        e.AddLeaf("File Attributes: 0x" + attr.ToString("x8") + FileAttrSummary(attr));
        e.AddLeaf("Last Write Time: " + FileTime(data, pos + 24, end));
        if (infoClass == 0x25 || infoClass == 0x26)
        {
            int idOff = (infoClass == 0x25) ? 96 : 72;
            if (pos + idOff + 8 <= end) e.AddLeaf("File Id: 0x" + ReadUInt64LE(data, pos + idOff).ToString("x"));
        }
        parent.Add(e);
        return true;
    }

    private static void BuildChangeNotifyBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (!isResponse)
        {
            if (bodyLen < 28) return;
            n.AddLeaf("Flags: 0x" + ReadUInt16LE(data, off + 2).ToString("x4") + (((ReadUInt16LE(data, off + 2) & 0x1) != 0) ? " (WATCH_TREE)" : ""));
            n.AddLeaf("Output Buffer Length: " + ReadUInt32LE(data, off + 4));
            n.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd));
            uint filter = ReadUInt32LE(data, off + 24);
            var fn = new BoxyBox.TreeNode("Completion Filter: 0x" + filter.ToString("x8"), "SMB2.Filter", false);
            for (int i = 0; i < ChangeNotifyFilters.Length; i++)
                if ((filter & ChangeNotifyFilters[i].Key) != 0) fn.AddLeaf(ChangeNotifyFilters[i].Value);
            n.Add(fn);
        }
        else
        {
            if (bodyLen < 8) return;
            n.AddLeaf("Output Buffer Offset: 0x" + ReadUInt16LE(data, off + 2).ToString("x4"));
            n.AddLeaf("Output Buffer Length: " + ReadUInt32LE(data, off + 4));
        }
    }

    private static void BuildQueryInfoBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int hdr, int off, int bodyLen,
        bool isResponse, bool isQuery, ulong sessionId, ulong messageId)
    {
        if (!isResponse)
        {
            if (bodyLen < 4) return;
            byte it = data[off + 2];
            byte ic = data[off + 3];
            n.AddLeaf("Info Type: " + InfoTypeName(it) + " (0x" + it.ToString("x2") + ")");
            n.AddLeaf("File Info Class: " + InfoClassName(it, ic) + " (0x" + ic.ToString("x2") + ")");
            int fidOff = isQuery ? 24 : 16; // QUERY_INFO FileId@24, SET_INFO FileId@16
            n.AddLeaf(FileIdTreeLine(data, off + fidOff, cmdEnd));
            // SET_INFO request: the class AND the buffer being set are both in the request.
            if (!isQuery && bodyLen >= 32)
            {
                uint bufLen = ReadUInt32LE(data, off + 4);
                ushort bufOff = ReadUInt16LE(data, off + 8);
                int bs = hdr + bufOff;
                int be = bs + (int)bufLen;
                if (be > cmdEnd) be = cmdEnd;
                if (bufLen > 0 && bs >= off && bs < be) BuildInfoResult(n, data, bs, be, it, ic);
            }
        }
        else if (isQuery) // QUERY_INFO response carries the output buffer; SET_INFO response is structure-only.
        {
            if (bodyLen < 8) return;
            ushort obOff = ReadUInt16LE(data, off + 2);
            uint obLen = ReadUInt32LE(data, off + 4);
            n.AddLeaf("Output Buffer Offset: 0x" + obOff.ToString("x4"));
            n.AddLeaf("Output Buffer Length: " + obLen);
            if (obLen == 0) return;
            int bs = hdr + obOff;
            int be = bs + (int)obLen;
            if (be > cmdEnd) be = cmdEnd;
            if (bs < off || bs >= be) return;
            byte it, ic;
            if (LookupInfoClass(sessionId, messageId, out it, out ic)) BuildInfoResult(n, data, bs, be, it, ic);
            else n.AddLeaf("Info: (request not captured — information class unknown)");
        }
    }

    // Parses a single QUERY_INFO / SET_INFO info structure (file or filesystem) into a subtree.
    private static void BuildInfoResult(BoxyBox.TreeNode parent, byte[] data, int start, int end, byte infoType, byte infoClass)
    {
        var node = new BoxyBox.TreeNode(InfoTypeName(infoType) + "\\" + InfoClassName(infoType, infoClass), "SMB2.Info", false);
        if (infoType == 2) BuildFsInfo(node, data, start, end, infoClass);
        else BuildFileInfo(node, data, start, end, infoClass);
        parent.Add(node);
    }

    private static void BuildFileInfo(BoxyBox.TreeNode node, byte[] data, int start, int end, byte infoClass)
    {
        switch (infoClass)
        {
            case 0x04: // FileBasicInformation
                if (start + 36 > end) break;
                node.AddLeaf("Creation Time: " + FileTime(data, start, end));
                node.AddLeaf("Last Access Time: " + FileTime(data, start + 8, end));
                node.AddLeaf("Last Write Time: " + FileTime(data, start + 16, end));
                node.AddLeaf("Change Time: " + FileTime(data, start + 24, end));
                node.AddLeaf("File Attributes: 0x" + ReadUInt32LE(data, start + 32).ToString("x8") + FileAttrSummary(ReadUInt32LE(data, start + 32)));
                break;
            case 0x05: // FileStandardInformation
                if (start + 22 > end) break;
                node.AddLeaf("Allocation Size: " + ReadUInt64LE(data, start));
                node.AddLeaf("End of File: " + ReadUInt64LE(data, start + 8));
                node.AddLeaf("Number of Links: " + ReadUInt32LE(data, start + 16));
                node.AddLeaf("Delete Pending: " + (data[start + 20] != 0));
                node.AddLeaf("Directory: " + (data[start + 21] != 0));
                break;
            case 0x06: // FileInternalInformation
                if (start + 8 > end) break;
                node.AddLeaf("Index Number: 0x" + ReadUInt64LE(data, start).ToString("x"));
                break;
            case 0x07: // FileEaInformation
                if (start + 4 > end) break;
                node.AddLeaf("Ea Size: " + ReadUInt32LE(data, start));
                break;
            case 0x0E: // FilePositionInformation
                if (start + 8 > end) break;
                node.AddLeaf("Current Byte Offset: " + ReadUInt64LE(data, start));
                break;
            case 0x22: // FileNetworkOpenInformation
                if (start + 56 > end) break;
                node.AddLeaf("Creation Time: " + FileTime(data, start, end));
                node.AddLeaf("Last Access Time: " + FileTime(data, start + 8, end));
                node.AddLeaf("Last Write Time: " + FileTime(data, start + 16, end));
                node.AddLeaf("Change Time: " + FileTime(data, start + 24, end));
                node.AddLeaf("Allocation Size: " + ReadUInt64LE(data, start + 32));
                node.AddLeaf("End of File: " + ReadUInt64LE(data, start + 40));
                node.AddLeaf("File Attributes: 0x" + ReadUInt32LE(data, start + 48).ToString("x8") + FileAttrSummary(ReadUInt32LE(data, start + 48)));
                break;
            case 0x15: // FileAlternateNameInformation
            case 0x30: // FileNormalizedNameInformation
            {
                if (start + 4 > end) break;
                uint nl = ReadUInt32LE(data, start);
                node.AddLeaf("Name: " + (ExtractName(data, start + 4, (int)nl, start + 4, end) ?? "?"));
                break;
            }
            case 0x12: // FileAllInformation — composite
                if (start + 40 > end) break;
                node.AddLeaf("Creation Time: " + FileTime(data, start, end));
                node.AddLeaf("Last Write Time: " + FileTime(data, start + 16, end));
                node.AddLeaf("File Attributes: 0x" + ReadUInt32LE(data, start + 32).ToString("x8") + FileAttrSummary(ReadUInt32LE(data, start + 32)));
                if (start + 64 <= end)
                {
                    node.AddLeaf("Allocation Size: " + ReadUInt64LE(data, start + 40));
                    node.AddLeaf("End of File: " + ReadUInt64LE(data, start + 48));
                }
                if (start + 100 <= end)
                {
                    uint anl = ReadUInt32LE(data, start + 96);
                    node.AddLeaf("Name: " + (ExtractName(data, start + 100, (int)anl, start + 100, end) ?? "?"));
                }
                break;
            // --- SET_INFO classes ---
            case 0x0A: // FileRenameInformation
                if (start + 20 > end) break;
                node.AddLeaf("Replace If Exists: " + (data[start] != 0));
                node.AddLeaf("Root Directory: 0x" + ReadUInt64LE(data, start + 8).ToString("x"));
                uint rnl = ReadUInt32LE(data, start + 16);
                node.AddLeaf("New Name: " + (ExtractName(data, start + 20, (int)rnl, start + 20, end) ?? "?"));
                break;
            case 0x0D: // FileDispositionInformation
                if (start + 1 > end) break;
                node.AddLeaf("Delete Pending: " + (data[start] != 0));
                break;
            case 0x13: // FileAllocationInformation
                if (start + 8 > end) break;
                node.AddLeaf("Allocation Size: " + ReadUInt64LE(data, start));
                break;
            case 0x14: // FileEndOfFileInformation
                if (start + 8 > end) break;
                node.AddLeaf("End of File: " + ReadUInt64LE(data, start));
                break;
            default:
                node.AddLeaf("(class 0x" + infoClass.ToString("x2") + " not decoded; " + (end - start) + " bytes)");
                break;
        }
    }

    private static void BuildFsInfo(BoxyBox.TreeNode node, byte[] data, int start, int end, byte infoClass)
    {
        switch (infoClass)
        {
            case 0x01: // FileFsVolumeInformation
                if (start + 18 > end) break;
                node.AddLeaf("Volume Creation Time: " + FileTime(data, start, end));
                node.AddLeaf("Volume Serial Number: 0x" + ReadUInt32LE(data, start + 8).ToString("x8"));
                uint vll = ReadUInt32LE(data, start + 12);
                node.AddLeaf("Volume Label: " + (ExtractName(data, start + 18, (int)vll, start + 18, end) ?? ""));
                break;
            case 0x03: // FileFsSizeInformation
                if (start + 24 > end) break;
                node.AddLeaf("Total Allocation Units: " + ReadUInt64LE(data, start));
                node.AddLeaf("Available Allocation Units: " + ReadUInt64LE(data, start + 8));
                node.AddLeaf("Sectors Per Allocation Unit: " + ReadUInt32LE(data, start + 16));
                node.AddLeaf("Bytes Per Sector: " + ReadUInt32LE(data, start + 20));
                break;
            case 0x04: // FileFsDeviceInformation
                if (start + 8 > end) break;
                node.AddLeaf("Device Type: " + ReadUInt32LE(data, start));
                node.AddLeaf("Characteristics: 0x" + ReadUInt32LE(data, start + 4).ToString("x8"));
                break;
            case 0x05: // FileFsAttributeInformation
                if (start + 12 > end) break;
                node.AddLeaf("FS Attributes: 0x" + ReadUInt32LE(data, start).ToString("x8"));
                node.AddLeaf("Max Component Name Length: " + ReadUInt32LE(data, start + 4));
                uint fsnl = ReadUInt32LE(data, start + 8);
                node.AddLeaf("File System Name: " + (ExtractName(data, start + 12, (int)fsnl, start + 12, end) ?? ""));
                break;
            case 0x07: // FileFsFullSizeInformation
                if (start + 32 > end) break;
                node.AddLeaf("Total Allocation Units: " + ReadUInt64LE(data, start));
                node.AddLeaf("Caller Available Units: " + ReadUInt64LE(data, start + 8));
                node.AddLeaf("Actual Available Units: " + ReadUInt64LE(data, start + 16));
                node.AddLeaf("Sectors Per Allocation Unit: " + ReadUInt32LE(data, start + 24));
                node.AddLeaf("Bytes Per Sector: " + ReadUInt32LE(data, start + 28));
                break;
            default:
                node.AddLeaf("(FS class 0x" + infoClass.ToString("x2") + " not decoded; " + (end - start) + " bytes)");
                break;
        }
    }

    private static void BuildOplockBreakBody(BoxyBox.TreeNode n, byte[] data, int cmdEnd, int off, int bodyLen, bool isResponse)
    {
        if (bodyLen < 2) return;
        ushort ss = ReadUInt16LE(data, off);
        if (ss == 24 && bodyLen >= 24)
        {
            byte level = data[off + 2];
            n.AddLeaf("Oplock Level: " + OplockLevelName(level) + " (0x" + level.ToString("x2") + ")");
            n.AddLeaf(FileIdTreeLine(data, off + 8, cmdEnd));
        }
        else if (ss == 44 && bodyLen >= 32)
        {
            n.AddLeaf("Lease Key: " + FormatGuid(data, off + 8));
            n.AddLeaf("Current Lease State: " + LeaseStateStr(ReadUInt32LE(data, off + 24)));
            n.AddLeaf("New Lease State: " + LeaseStateStr(ReadUInt32LE(data, off + 28)));
        }
        else if (ss == 36 && bodyLen >= 28)
        {
            n.AddLeaf("Lease Key: " + FormatGuid(data, off + 8));
            n.AddLeaf("Lease State: " + LeaseStateStr(ReadUInt32LE(data, off + 24)));
        }
    }

    // ---- detail-tree value helpers ----

    private static string FileIdTreeLine(byte[] data, int fidOff, int len)
    {
        if (fidOff + 16 > len) return "File Id: (truncated)";
        ulong p = ReadUInt64LE(data, fidOff);
        ulong v = ReadUInt64LE(data, fidOff + 8);
        string name = LookupFile(p, v);
        string s = "File Id: " + FormatGuid(data, fidOff);
        if (name != null && name.Length > 0) s += "  " + name;
        return s;
    }

    private static string FileTime(byte[] data, int off, int len)
    {
        if (off + 8 > len) return "(truncated)";
        ulong ft = ReadUInt64LE(data, off);
        if (ft == 0) return "No time specified (0)";
        if (ft == 0xFFFFFFFFFFFFFFFF) return "Infinity (-1)";
        try { return DateTime.FromFileTimeUtc((long)ft).ToString("yyyy-MM-dd HH:mm:ss.fff") + " UTC"; }
        catch { return "0x" + ft.ToString("x"); }
    }

    private static string OplockLevelName(byte level)
    {
        string s;
        return OplockLevelNames.TryGetValue(level, out s) ? s : "0x" + level.ToString("x2");
    }

    private static string IoctlName(uint ctl)
    {
        string s;
        return IoctlNames.TryGetValue(ctl, out s) ? s : "0x" + ctl.ToString("x8");
    }

    private static string SigningSummary(int mode)
    {
        var parts = new List<string>(2);
        if ((mode & 0x1) != 0) parts.Add("SIGNING_ENABLED");
        if ((mode & 0x2) != 0) parts.Add("SIGNING_REQUIRED");
        return parts.Count > 0 ? " (" + string.Join(", ", parts) + ")" : "";
    }

    private static string CapSummary(uint caps)
    {
        if (caps == 0) return "";
        var parts = new List<string>(7);
        for (int i = 0; i < NegotiateCaps.Length; i++)
            if ((caps & NegotiateCaps[i].Key) != 0) parts.Add(NegotiateCaps[i].Value);
        return parts.Count > 0 ? " (" + string.Join(", ", parts) + ")" : "";
    }

    private static string FileAttrSummary(uint attr)
    {
        if (attr == 0) return "";
        var parts = new List<string>(6);
        if ((attr & 0x00000001) != 0) parts.Add("READONLY");
        if ((attr & 0x00000002) != 0) parts.Add("HIDDEN");
        if ((attr & 0x00000004) != 0) parts.Add("SYSTEM");
        if ((attr & 0x00000010) != 0) parts.Add("DIRECTORY");
        if ((attr & 0x00000020) != 0) parts.Add("ARCHIVE");
        if ((attr & 0x00000080) != 0) parts.Add("NORMAL");
        if ((attr & 0x00000400) != 0) parts.Add("REPARSE_POINT");
        if ((attr & 0x00000800) != 0) parts.Add("COMPRESSED");
        if ((attr & 0x00004000) != 0) parts.Add("ENCRYPTED");
        return parts.Count > 0 ? " (" + string.Join(", ", parts) + ")" : "";
    }

    private static string ShareAccessSummary(uint sa)
    {
        if (sa == 0) return " (none)";
        var parts = new List<string>(3);
        if ((sa & 0x1) != 0) parts.Add("READ");
        if ((sa & 0x2) != 0) parts.Add("WRITE");
        if ((sa & 0x4) != 0) parts.Add("DELETE");
        return " (" + string.Join(", ", parts) + ")";
    }

    private static string CreateOptionsSummary(uint opt)
    {
        var parts = new List<string>(4);
        if ((opt & 0x00000001) != 0) parts.Add("DIRECTORY_FILE");
        if ((opt & 0x00000002) != 0) parts.Add("WRITE_THROUGH");
        if ((opt & 0x00000004) != 0) parts.Add("SEQUENTIAL_ONLY");
        if ((opt & 0x00000040) != 0) parts.Add("NON_DIRECTORY_FILE");
        if ((opt & 0x00000200) != 0) parts.Add("SYNCHRONOUS_IO_NONALERT");
        if ((opt & 0x00001000) != 0) parts.Add("DELETE_ON_CLOSE");
        if ((opt & 0x00004000) != 0) parts.Add("NO_EA_KNOWLEDGE");
        if ((opt & 0x00100000) != 0) parts.Add("OPEN_REPARSE_POINT");
        return parts.Count > 0 ? " (" + string.Join(", ", parts) + ")" : "";
    }

    private static BoxyBox.TreeNode BuildSmb2FlagsNode(uint flags, bool isResponse)
    {
        var f = new BoxyBox.TreeNode("Flags: 0x" + flags.ToString("x8") + Smb2FlagSummary(flags), "SMB2.Flags", false);
        f.AddLeaf(RenderFlagBits(flags, ".... .... .... .... .... .... .... ...B", 32) + " = Response: This is a " + (isResponse ? "RESPONSE" : "REQUEST"));
        f.AddLeaf(RenderFlagBits(flags, ".... .... .... .... .... .... .... ..B.", 32) + " = Async command: This is a " + ((flags & 0x2) != 0 ? "ASYNC" : "SYNC") + " command");
        f.AddLeaf(RenderFlagBits(flags, ".... .... .... .... .... .... .... .B..", 32) + " = Chained: This pdu " + ((flags & 0x4) != 0 ? "is" : "is NOT") + " a chained command");
        f.AddLeaf(RenderFlagBits(flags, ".... .... .... .... .... .... .... B...", 32) + " = Signing: This pdu " + ((flags & 0x8) != 0 ? "is" : "is NOT") + " SIGNED");
        f.AddLeaf(RenderFlagBits(flags, ".... .... .... .... .... .... .BBB ....", 32) + " = Priority: This pdu contains a PRIORITY (" + ((flags >> 4) & 0x7) + ")");
        f.AddLeaf(RenderFlagBits(flags, "...B .... .... .... .... .... .... ....", 32) + " = DFS operation: This is a " + ((flags & 0x10000000) != 0 ? "DFS" : "normal") + " operation");
        f.AddLeaf(RenderFlagBits(flags, "..B. .... .... .... .... .... .... ....", 32) + " = Replay operation: This " + ((flags & 0x20000000) != 0 ? "is" : "is NOT") + " a replay operation");
        return f;
    }

    private static string Smb2FlagSummary(uint flags)
    {
        var parts = new List<string>(6);
        if ((flags & 0x1) != 0) parts.Add("RESPONSE");
        if ((flags & 0x2) != 0) parts.Add("ASYNC");
        if ((flags & 0x4) != 0) parts.Add("CHAINED");
        if ((flags & 0x8) != 0) parts.Add("SIGNED");
        if ((flags & 0x10000000) != 0) parts.Add("DFS");
        if ((flags & 0x20000000) != 0) parts.Add("REPLAY");
        return parts.Count > 0 ? ", " + string.Join(", ", parts) : "";
    }

    private static BoxyBox.TreeNode BuildTransformNode(byte[] data, int len, int off)
    {
        uint msgSize = (len >= off + 40) ? ReadUInt32LE(data, off + 36) : 0;
        ulong sessId = (len >= off + 52) ? ReadUInt64LE(data, off + 44) : 0;
        var root = new BoxyBox.TreeNode("SMB2 Encrypted - SessId 0x" + sessId.ToString("x") + ", len " + msgSize, "SMB2", true);
        var h = new BoxyBox.TreeNode("SMB2 Transform Header", "SMB2.Header", false);
        h.AddLeaf("ProtocolId: 0x" + HexBytes(data, off, 4, len));
        h.AddLeaf("Signature: " + HexBytes(data, off + 4, 16, len));
        h.AddLeaf("Nonce: " + HexBytes(data, off + 20, 16, len));
        h.AddLeaf("Original Message Size: " + msgSize);
        if (len >= off + 44) h.AddLeaf("Flags/EncryptionAlgorithm: 0x" + ReadUInt16LE(data, off + 42).ToString("x4"));
        h.AddLeaf("Session Id: 0x" + sessId.ToString("x"));
        root.Add(h);
        return root;
    }

    private static BoxyBox.TreeNode BuildSmb1NegotiateNode(byte[] data, int len, int off)
    {
        var root = new BoxyBox.TreeNode("SMB1 Negotiate Protocol Request", "SMB2", true);
        var h = new BoxyBox.TreeNode("SMB Header", "SMB2.Header", false);
        h.AddLeaf("Server Component: SMB");
        byte cmd = (len > off + 4) ? data[off + 4] : (byte)0;
        h.AddLeaf("SMB Command: Negotiate Protocol (0x" + cmd.ToString("x2") + ")");
        uint status = (len >= off + 9) ? ReadUInt32LE(data, off + 5) : 0;
        h.AddLeaf("NT Status: " + StatusName(status) + " (0x" + status.ToString("X8") + ")");
        byte flags = (len > off + 9) ? data[off + 9] : (byte)0;
        h.Add(BuildSmb1FlagsNode(flags));
        ushort flags2 = (len >= off + 12) ? ReadUInt16LE(data, off + 10) : (ushort)0;
        h.Add(BuildSmb1Flags2Node(flags2));
        h.AddLeaf("Process ID High: " + ((len >= off + 14) ? ReadUInt16LE(data, off + 12) : 0));
        h.AddLeaf("Signature: " + HexBytes(data, off + 14, 8, len));
        h.AddLeaf("Reserved: " + HexBytes(data, off + 22, 2, len));
        h.AddLeaf("Tree ID: " + ((len >= off + 26) ? ReadUInt16LE(data, off + 24) : 0));
        h.AddLeaf("Process ID: " + ((len >= off + 28) ? ReadUInt16LE(data, off + 26) : 0));
        h.AddLeaf("User ID: " + ((len >= off + 30) ? ReadUInt16LE(data, off + 28) : 0));
        h.AddLeaf("Multiplex ID: " + ((len >= off + 32) ? ReadUInt16LE(data, off + 30) : 0));
        root.Add(h);
        return root;
    }

    private static BoxyBox.TreeNode BuildSmb1FlagsNode(byte flags)
    {
        var f = new BoxyBox.TreeNode("Flags: 0x" + flags.ToString("x2"), "SMB1.Flags", false);
        f.AddLeaf(RenderFlagBits(flags, "0... ....", 8) + " = Request/Response: Message is a request to the server");
        f.AddLeaf(RenderFlagBits(flags, ".0.. ....", 8) + " = Notify: Notify client only on open");
        f.AddLeaf(RenderFlagBits(flags, "..0. ....", 8) + " = Oplocks: OpLock not requested/granted");
        f.AddLeaf(RenderFlagBits(flags, "...B ....", 8) + " = Canonicalized Pathnames: Pathnames " + ((flags & 0x10) != 0 ? "are" : "are not") + " canonicalized");
        f.AddLeaf(RenderFlagBits(flags, ".... B...", 8) + " = Case Sensitivity: Path names " + ((flags & 0x08) != 0 ? "are" : "are not") + " caseless");
        f.AddLeaf(RenderFlagBits(flags, ".... ..B.", 8) + " = Receive Buffer Posted: Receive buffer " + ((flags & 0x02) != 0 ? "has" : "has not") + " been posted");
        f.AddLeaf(RenderFlagBits(flags, ".... ...B", 8) + " = Lock and Read: Lock&Read, Write&Unlock " + ((flags & 0x01) != 0 ? "are" : "are not") + " supported");
        return f;
    }

    private static BoxyBox.TreeNode BuildSmb1Flags2Node(ushort flags2)
    {
        var f = new BoxyBox.TreeNode("Flags2: 0x" + flags2.ToString("x4"), "SMB1.Flags2", false);
        f.AddLeaf(RenderFlagBits(flags2, "B... .... .... ....", 16) + " = Unicode Strings: Strings " + ((flags2 & 0x8000) != 0 ? "are" : "are not") + " Unicode");
        f.AddLeaf(RenderFlagBits(flags2, ".B.. .... .... ....", 16) + " = Error Code Type: Error codes " + ((flags2 & 0x4000) != 0 ? "are" : "are not") + " NT error codes");
        f.AddLeaf(RenderFlagBits(flags2, "..B. .... .... ....", 16) + " = Execute-only Reads: " + ((flags2 & 0x2000) != 0 ? "Do" : "Don't") + " permit reads if execute-only");
        f.AddLeaf(RenderFlagBits(flags2, "...B .... .... ....", 16) + " = Dfs: " + ((flags2 & 0x1000) != 0 ? "Do" : "Don't") + " resolve pathnames with Dfs");
        f.AddLeaf(RenderFlagBits(flags2, ".... B... .... ....", 16) + " = Extended Security Negotiation: Extended security negotiation is " + ((flags2 & 0x0800) != 0 ? "supported" : "not supported"));
        f.AddLeaf(RenderFlagBits(flags2, ".... .B.. .... ....", 16) + " = Reparse Path: The request " + ((flags2 & 0x0400) != 0 ? "does" : "does not") + " use a @GMT reparse path");
        f.AddLeaf(RenderFlagBits(flags2, ".... .... .B.. ....", 16) + " = Long Names Used: Path names in request " + ((flags2 & 0x0040) != 0 ? "are" : "are not") + " long file names");
        f.AddLeaf(RenderFlagBits(flags2, ".... .... ...B ....", 16) + " = Security Signatures Required: Security signatures " + ((flags2 & 0x0010) != 0 ? "are" : "are not") + " required");
        f.AddLeaf(RenderFlagBits(flags2, ".... .... .... B...", 16) + " = Compressed: Compression " + ((flags2 & 0x0008) != 0 ? "is" : "is not") + " requested");
        f.AddLeaf(RenderFlagBits(flags2, ".... .... .... .B..", 16) + " = Security Signatures: Security signatures " + ((flags2 & 0x0004) != 0 ? "are" : "are not") + " supported");
        f.AddLeaf(RenderFlagBits(flags2, ".... .... .... ..B.", 16) + " = Extended Attributes: Extended attributes " + ((flags2 & 0x0002) != 0 ? "are" : "are not") + " supported");
        f.AddLeaf(RenderFlagBits(flags2, ".... .... .... ...B", 16) + " = Long Names Allowed: Long file names " + ((flags2 & 0x0001) != 0 ? "are" : "are not") + " allowed in the response");
        return f;
    }

    // Renders a Wireshark-style flag bit line: 'B' -> the actual bit (MSB first over <width>
    // bits), space -> space, any other char (. 0 1) copied verbatim.
    private static string RenderFlagBits(uint flags, string template, int width)
    {
        var sb = new StringBuilder(template.Length);
        int bitIndex = 0;
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == ' ') { sb.Append(' '); continue; }
            if (c == 'B') { int bit = (width - 1) - bitIndex; sb.Append(((flags >> bit) & 1) == 1 ? '1' : '0'); }
            else sb.Append(c);
            bitIndex++;
        }
        return sb.ToString();
    }

    private static string HexBytes(byte[] data, int off, int count, int len)
    {
        if (off + count > len) count = Math.Max(0, len - off);
        if (count <= 0) return "";
        var sb = new StringBuilder(count * 2);
        for (int i = 0; i < count; i++) sb.Append(data[off + i].ToString("x2"));
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
