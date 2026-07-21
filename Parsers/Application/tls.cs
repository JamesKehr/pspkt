// tls.cs - High-performance TLS record parsing for real-time display.
// Extracts ContentType, Version, RecordLength, and (for ClientHello) SNI.
//
// Architecture mirrors dns.cs: a TryParseTls/FormatFromContext split so the
// app-layer predicate (TlsAppPredicate) can evaluate against a pre-parsed
// struct without forcing the formatter to re-parse the same record.

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Parsed TLS record snapshot. Populated by <see cref="TlsParser.TryParseTls"/>
/// and consumed both by the formatter (<see cref="TlsParser.FormatTlsFromContext"/>)
/// and by application-layer display predicates (<see cref="TlsAppPredicate"/>).
///
/// Storing the parsed fields in a struct (rather than re-parsing for the
/// predicate and again for the formatter) keeps the consumer hot path to a
/// single TLS parse per matching packet.
/// </summary>
public struct TlsContext
{
    /// <summary>True when the TLS record header passed sanity checks (Content-Type 20..23, version 0x0300..0x0304).</summary>
    public bool Valid;
    /// <summary>TLS record content type: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData.</summary>
    public int ContentType;
    /// <summary>TLS record version as a 16-bit number (e.g. 0x0303 = TLS 1.2). For TLS 1.3 the record version remains 0x0303 on wire.</summary>
    public int Version;
    /// <summary>TLS record body length from the 5-byte header.</summary>
    public int RecordLen;
    /// <summary>Handshake message type when <see cref="ContentType"/> == 22 and the body byte was readable. 0 otherwise.</summary>
    public int HandshakeType;
    /// <summary>Extracted SNI hostname for ClientHello records; null for everything else and when the extension wasn't present.</summary>
    public string Sni;
    /// <summary>True when ClientHello parsing for SNI couldn't reach the extensions block before <c>data.Length</c>.</summary>
    public bool Truncated;
}

/// <summary>
/// TLS protocol parser. Provides fast C# parsing of the TLS record header,
/// handshake type identification, and ClientHello SNI extraction.
/// </summary>
public static class TlsParser
{
    /// <summary>
    /// Standard TLS-bearing TCP ports recognised by the in-tree dispatcher
    /// (HTTPS, HTTPS-alt, IMAPS, POP3S, SMTPS, LDAPS).
    /// </summary>
    public static bool IsTlsPort(int port)
    {
        return port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 || port == 636;
    }

    /// <summary>
    /// Lightweight sanity check on the 5-byte TLS record header. Returns true
    /// when ContentType is 20..23 and the version is 0x0300..0x0304. Designed
    /// to skip the full parse on non-TLS payloads at zero allocation cost.
    /// </summary>
    public static bool LooksLikeTls(byte[] data)
    {
        return LooksLikeTls(data, data != null ? data.Length : 0);
    }

    public static bool LooksLikeTls(byte[] data, int dataLength)
    {
        if (data == null || dataLength < 5) return false;
        int contentType = data[0];
        if (contentType < 20 || contentType > 23) return false;
        int version = (data[1] << 8) | data[2];
        return version >= 0x0300 && version <= 0x0304;
    }

    /// <summary>
    /// Range-based sanity check used to decide, at zero allocation cost, whether a not-yet-copied
    /// TCP payload sitting at <paramref name="offset"/> in a larger raw buffer looks like a TLS
    /// record. Lets the capture path allocate/copy the payload only for streams that actually
    /// carry TLS, so content-based TLS detection works on any TCP port without a per-packet
    /// BlockCopy of all traffic. Reads at most 3 bytes; never past <paramref name="length"/>.
    /// </summary>
    public static bool LooksLikeTls(byte[] data, int offset, int length)
    {
        // Overflow-safe range check: length>=5 guarantees the 3-byte header read stays in-buffer
        // (offset+3 < offset+5 <= data.Length) without ever computing offset+3 directly.
        if (data == null || offset < 0 || length < 5
            || offset > data.Length || length > data.Length - offset) return false;
        int contentType = data[offset];
        if (contentType < 20 || contentType > 23) return false;
        int version = (data[offset + 1] << 8) | data[offset + 2];
        return version >= 0x0300 && version <= 0x0304;
    }

    /// <summary>
    /// Parses a TLS record (and, for ClientHello, the SNI extension) into a
    /// <see cref="TlsContext"/>. Returns false when the buffer is too short to
    /// hold a valid record header or the header fails sanity checks. On
    /// success may still set <see cref="TlsContext.Truncated"/> when the
    /// ClientHello couldn't be fully decoded.
    /// </summary>
    public static bool TryParseTls(byte[] data, out TlsContext ctx)
    {
        return TryParseTls(data, data != null ? data.Length : 0, out ctx);
    }

    /// <summary>
    /// Overload accepting explicit data length for reusable-buffer callers.
    /// </summary>
    public static bool TryParseTls(byte[] data, int dataLength, out TlsContext ctx)
    {
        ctx = default(TlsContext);
        if (!LooksLikeTls(data, dataLength)) return false;

        ctx.ContentType = data[0];
        ctx.Version     = (data[1] << 8) | data[2];
        ctx.RecordLen   = PacketParseHelper.ReadUInt16BE(data, 3);
        ctx.Valid       = true;

        // Handshake — pull the first byte of the body to identify the message type.
        if (ctx.ContentType == 22 && dataLength >= 6)
        {
            ctx.HandshakeType = data[5];
            if (ctx.HandshakeType == 1) // ClientHello — try SNI extraction.
            {
                bool truncated;
                ctx.Sni = ExtractSni(data, dataLength, out truncated);
                ctx.Truncated = truncated;
            }
        }
        return true;
    }

    /// <summary>
    /// Formats a previously parsed <see cref="TlsContext"/> using the detailed
    /// tcpdump-style format. Equivalent to the legacy
    /// <c>FormatTlsDetailed</c> output.
    /// </summary>
    public static string FormatTlsFromContext(ref TlsContext ctx, int payloadLen)
    {
        if (!ctx.Valid) return null;
        string versionName = GetVersionName(ctx.Version);

        if (ctx.ContentType == 22 && ctx.HandshakeType > 0)
        {
            string handshakeName = GetHandshakeName(ctx.HandshakeType);
            if (handshakeName != null)
            {
                StringBuilder sb = new StringBuilder(96);
                sb.Append("TLS ").Append(handshakeName)
                  .Append("; ver: ").Append(versionName)
                  .Append("; len: ").Append(ctx.RecordLen);
                if (!string.IsNullOrEmpty(ctx.Sni))
                {
                    sb.Append("; SNI: ").Append(ctx.Sni);
                }
                return sb.ToString();
            }
        }

        return "TLS " + GetContentTypeName(ctx.ContentType) + "; ver: " + versionName + "; len: " + ctx.RecordLen.ToString();
    }

    /// <summary>
    /// Default-tier formatter for a TLS payload (short form, no SNI extraction).
    /// Equivalent to the legacy <c>DetectTlsContent</c>:
    ///   Handshake (known type): "TLS 1.2 ClientHello"
    ///   Otherwise:               "TLS 1.2 ApplicationData, len 1234"
    /// </summary>
    public static string FormatTlsSegment(byte[] data, int dataLen)
    {
        TlsContext ctx;
        if (!TryParseTls(data, dataLen, out ctx)) return null;
        string versionName = GetVersionName(ctx.Version);
        if (ctx.ContentType == 22 && ctx.HandshakeType > 0)
        {
            string handshakeName = GetHandshakeName(ctx.HandshakeType);
            if (handshakeName != null)
            {
                return versionName + " " + handshakeName;
            }
        }
        return versionName + " " + GetContentTypeName(ctx.ContentType) + ", len " + dataLen.ToString();
    }

    /// <summary>Returns a display name for a TLS record content type (e.g. 22 → "Handshake").</summary>
    public static string GetContentTypeName(int contentType)
    {
        switch (contentType)
        {
            case 20: return "ChangeCipherSpec";
            case 21: return "Alert";
            case 22: return "Handshake";
            case 23: return "ApplicationData";
            default: return "Type" + contentType;
        }
    }

    /// <summary>Returns a display name for a TLS record version (e.g. 0x0303 → "TLS 1.2").</summary>
    public static string GetVersionName(int version)
    {
        switch (version)
        {
            case 0x0301: return "TLS 1.0";
            case 0x0302: return "TLS 1.1";
            case 0x0303: return "TLS 1.2";
            case 0x0304: return "TLS 1.3";
            default:
                int major = (version >> 8) & 0xFF;
                int minor = version & 0xFF;
                return "TLS " + major + "." + minor;
        }
    }

    /// <summary>Returns a display name for a TLS handshake message type, or null when not recognised.</summary>
    public static string GetHandshakeName(int hsType)
    {
        switch (hsType)
        {
            case 1:  return "ClientHello";
            case 2:  return "ServerHello";
            case 4:  return "NewSessionTicket";
            case 8:  return "EncryptedExtensions";
            case 11: return "Certificate";
            case 12: return "ServerKeyExchange";
            case 13: return "CertificateRequest";
            case 14: return "ServerHelloDone";
            case 15: return "CertificateVerify";
            case 16: return "ClientKeyExchange";
            case 20: return "Finished";
            default: return null;
        }
    }

    // ---- ClientHello SNI extraction ----
    // Walks the ClientHello body: version(2) + random(32) + sessionID(1+var) +
    // cipherSuites(2+var) + compression(1+var) + extensions(2+var). The SNI
    // extension (type 0) carries a name list whose first host_name entry (type 0)
    // is returned. Truncation at any stage is reported via the out parameter.
    private static string ExtractSni(byte[] data, out bool truncated)
    {
        return ExtractSni(data, data != null ? data.Length : 0, out truncated);
    }

    private static string ExtractSni(byte[] data, int dataLength, out bool truncated)
    {
        truncated = false;
        // Minimum viable ClientHello with SNI: 5+4+34+1+2+1+2+... ~43 bytes.
        if (data == null || dataLength < 43 || data[0] != 22 || data[5] != 1)
        {
            return null;
        }

        int recordLen = PacketParseHelper.ReadUInt16BE(data, 3);
        int recordEnd = Math.Min(dataLength, 5 + recordLen);
        // Skip TLS record header (5) + handshake type (1) + handshake length (3) = 9.
        // Then ClientHello body starts: protocol version (2) + random (32).
        int pos = 9;
        if (recordEnd < pos + 34) { truncated = true; return null; }

        pos += 2;   // legacy_version
        pos += 32;  // random
        if (pos >= recordEnd) { truncated = true; return null; }

        int sessionIdLen = data[pos];
        pos += 1;
        if (pos + sessionIdLen + 2 > recordEnd) { truncated = true; return null; }
        pos += sessionIdLen;

        int cipherLen = PacketParseHelper.ReadUInt16BE(data, pos);
        pos += 2;
        if (pos + cipherLen + 1 > recordEnd) { truncated = true; return null; }
        pos += cipherLen;

        int compressionLen = data[pos];
        pos += 1;
        if (pos + compressionLen + 2 > recordEnd) { truncated = true; return null; }
        pos += compressionLen;

        int extLen = PacketParseHelper.ReadUInt16BE(data, pos);
        pos += 2;
        int extEnd = Math.Min(recordEnd, pos + extLen);

        while (pos + 4 <= extEnd)
        {
            int extType = PacketParseHelper.ReadUInt16BE(data, pos);
            int itemLen = PacketParseHelper.ReadUInt16BE(data, pos + 2);
            pos += 4;
            if (pos + itemLen > extEnd) { truncated = true; break; }

            if (extType == 0 && itemLen >= 5)
            {
                int listLen = PacketParseHelper.ReadUInt16BE(data, pos);
                int listPos = pos + 2;
                int listEnd = Math.Min(pos + itemLen, listPos + listLen);
                while (listPos + 3 <= listEnd)
                {
                    int nameType = data[listPos];
                    int nameLen = PacketParseHelper.ReadUInt16BE(data, listPos + 1);
                    listPos += 3;
                    if (listPos + nameLen > listEnd) { truncated = true; break; }
                    if (nameType == 0)
                    {
                        return Encoding.ASCII.GetString(data, listPos, nameLen);
                    }
                    listPos += nameLen;
                }
            }
            pos += itemLen;
        }
        return null;
    }

    // ==================== Analysis detail tree ====================
    //
    // On-demand (JIT) parse for the Analysis Details box. Unlike the hot-path formatters above,
    // this may allocate freely: it runs only when a user selects a packet, not per captured
    // packet. A single TCP segment can carry several TLS records (and a handshake record several
    // messages), so the builder emits one collapsed root node per record. Each root's collapsed
    // line carries the ClientHello SNI so it is visible without expanding.

    /// <summary>
    /// Builds the Analysis Details tree for a TLS-bearing TCP payload. Returns one collapsed
    /// root node per TLS record found in the segment. Stops at the first byte that doesn't look
    /// like a TLS record header (segment ends mid-record, or carries trailing non-TLS bytes).
    /// Bounded to 64 records to cap loop time on malformed input.
    /// </summary>
    public static List<BoxyBox.TreeNode> BuildTlsDetailTree(byte[] data, int len, int srcPort, int dstPort)
    {
        var roots = new List<BoxyBox.TreeNode>();
        if (data == null) return roots;
        if (len > data.Length) len = data.Length;

        int pos = 0;
        int guard = 0;
        while (pos + 5 <= len && guard++ < 64)
        {
            int contentType = data[pos];
            int version = (data[pos + 1] << 8) | data[pos + 2];
            if (contentType < 20 || contentType > 23 || version < 0x0300 || version > 0x0304) break;
            int recLen = PacketParseHelper.ReadUInt16BE(data, pos + 3);
            int bodyOff = pos + 5;
            int bodyEnd = Math.Min(len, bodyOff + recLen);
            roots.Add(BuildTlsRecordNode(data, bodyOff, bodyEnd, contentType, version, recLen));
            pos = bodyOff + recLen;   // advances >= 5 (record header) even for a zero-length record
        }
        return roots;
    }

    private static BoxyBox.TreeNode BuildTlsRecordNode(byte[] data, int bodyOff, int bodyEnd,
        int contentType, int version, int recLen)
    {
        string versionName = GetVersionName(version);
        string primary = GetContentTypeName(contentType);
        string sni = null;

        // Build the record body child nodes first so the collapsed root can surface the SNI /
        // first handshake name.
        var childNodes = new List<BoxyBox.TreeNode>();
        if (contentType == 22)
        {
            if (bodyOff < bodyEnd)
            {
                string hn = GetHandshakeName(data[bodyOff]);
                if (hn != null) primary = hn;
            }
            AppendHandshakeNodes(data, bodyOff, bodyEnd, childNodes, out sni);
        }
        else if (contentType == 21)
        {
            childNodes.Add(BuildAlertNode(data, bodyOff, bodyEnd));
        }
        else if (contentType == 20)
        {
            childNodes.Add(new BoxyBox.TreeNode("Change Cipher Spec Message", "TLS.CCS", false));
        }
        else if (contentType == 23)
        {
            int adLen = Math.Max(0, bodyEnd - bodyOff);
            childNodes.Add(new BoxyBox.TreeNode("Encrypted Application Data: " + adLen + " bytes", "TLS.AppData", false));
        }

        var summary = new StringBuilder(96);
        summary.Append("TLS ").Append(primary).Append("; ver: ").Append(versionName).Append("; len: ").Append(recLen);
        if (!string.IsNullOrEmpty(sni)) summary.Append("; SNI: ").Append(sni);

        var root = new BoxyBox.TreeNode(summary.ToString(), "TLS", false);   // collapsed by default

        var rec = new BoxyBox.TreeNode("Record Layer: " + GetContentTypeName(contentType) + " Protocol, Version " + versionName, "TLS.Record", false);
        rec.AddLeaf("Content Type: " + GetContentTypeName(contentType) + " (" + contentType + ")");
        rec.AddLeaf("Version: " + versionName + " (0x" + version.ToString("x4") + ")");
        rec.AddLeaf("Length: " + recLen);
        root.Add(rec);

        for (int i = 0; i < childNodes.Count; i++) root.Add(childNodes[i]);
        return root;
    }

    // Walks the handshake messages inside a Handshake record body [start, end). A single record
    // can chain several messages (e.g. ServerHello + EncryptedExtensions + Certificate). Returns
    // the SNI of the first ClientHello seen via firstSni.
    private static void AppendHandshakeNodes(byte[] data, int start, int end, List<BoxyBox.TreeNode> outNodes, out string firstSni)
    {
        firstSni = null;
        int pos = start;
        int guard = 0;
        while (pos + 4 <= end && guard++ < 32)
        {
            int hsType = data[pos];
            int hsLen = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
            int msgBody = pos + 4;
            int msgEnd = Math.Min(end, msgBody + hsLen);
            string hsName = GetHandshakeName(hsType);
            var node = new BoxyBox.TreeNode("Handshake Protocol: " + (hsName != null ? hsName : "Unknown (" + hsType + ")"), "TLS.Handshake", false);
            node.AddLeaf("Handshake Type: " + (hsName != null ? hsName : "Unknown") + " (" + hsType + ")");
            node.AddLeaf("Length: " + hsLen);

            string sni = null;
            if (hsType == 1) BuildClientHelloBody(data, msgBody, msgEnd, node, out sni);
            else if (hsType == 2) BuildServerHelloBody(data, msgBody, msgEnd, node);
            if (firstSni == null && sni != null) firstSni = sni;

            outNodes.Add(node);
            pos = msgBody + hsLen;   // advances >= 4 (handshake header) even for a zero-length message
        }
    }

    // ClientHello body: version(2) random(32) sessionId(1+var) cipherSuites(2+var)
    // compression(1+var) extensions(2+var).
    private static void BuildClientHelloBody(byte[] data, int off, int end, BoxyBox.TreeNode parent, out string sni)
    {
        sni = null;
        int pos = off;
        if (pos + 34 > end) return;
        int legacyVer = (data[pos] << 8) | data[pos + 1];
        parent.AddLeaf("Version: " + GetVersionName(legacyVer) + " (0x" + legacyVer.ToString("x4") + ")");
        pos += 2;
        parent.AddLeaf("Random: " + HexPreview(data, pos, 32, 32));
        pos += 32;

        if (pos + 1 > end) return;
        int sidLen = data[pos]; pos += 1;
        parent.AddLeaf("Session ID Length: " + sidLen);
        if (pos + sidLen > end) return;
        if (sidLen > 0) parent.AddLeaf("Session ID: " + HexPreview(data, pos, sidLen, 32));
        pos += sidLen;

        if (pos + 2 > end) return;
        int csLen = PacketParseHelper.ReadUInt16BE(data, pos); pos += 2;
        int csEnd = Math.Min(end, pos + csLen);
        var csNode = new BoxyBox.TreeNode("Cipher Suites (" + (csLen / 2) + " suites)", "TLS.CipherSuites", false);
        int cp = pos; int cguard = 0;
        while (cp + 2 <= csEnd && cguard++ < 512)
        {
            int cs = PacketParseHelper.ReadUInt16BE(data, cp);
            csNode.AddLeaf("Cipher Suite: " + CipherSuiteName(cs) + " (0x" + cs.ToString("x4") + ")");
            cp += 2;
        }
        parent.Add(csNode);
        pos = csEnd;

        if (pos + 1 > end) return;
        int compLen = data[pos]; pos += 1;
        int compEnd = Math.Min(end, pos + compLen);
        var compNode = new BoxyBox.TreeNode("Compression Methods (" + compLen + " methods)", "TLS.Compression", false);
        for (int i = pos; i < compEnd; i++)
            compNode.AddLeaf("Compression Method: " + (data[i] == 0 ? "null" : data[i].ToString()) + " (" + data[i] + ")");
        parent.Add(compNode);
        pos = compEnd;

        if (pos + 2 > end) return;
        int extLen = PacketParseHelper.ReadUInt16BE(data, pos); pos += 2;
        int extEnd = Math.Min(end, pos + extLen);
        var extParent = new BoxyBox.TreeNode("Extensions", "TLS.Extensions", false);
        BuildExtensions(data, pos, extEnd, true, extParent, out sni);
        if (extParent.HasChildren) parent.Add(extParent);
    }

    // ServerHello body: version(2) random(32) sessionId(1+var) cipherSuite(2)
    // compressionMethod(1) extensions(2+var).
    private static void BuildServerHelloBody(byte[] data, int off, int end, BoxyBox.TreeNode parent)
    {
        int pos = off;
        if (pos + 34 > end) return;
        int legacyVer = (data[pos] << 8) | data[pos + 1];
        parent.AddLeaf("Version: " + GetVersionName(legacyVer) + " (0x" + legacyVer.ToString("x4") + ")");
        pos += 2;
        parent.AddLeaf("Random: " + HexPreview(data, pos, 32, 32));
        pos += 32;

        if (pos + 1 > end) return;
        int sidLen = data[pos]; pos += 1;
        parent.AddLeaf("Session ID Length: " + sidLen);
        if (pos + sidLen > end) return;
        if (sidLen > 0) parent.AddLeaf("Session ID: " + HexPreview(data, pos, sidLen, 32));
        pos += sidLen;

        if (pos + 2 > end) return;
        int cs = PacketParseHelper.ReadUInt16BE(data, pos); pos += 2;
        parent.AddLeaf("Cipher Suite: " + CipherSuiteName(cs) + " (0x" + cs.ToString("x4") + ")");

        if (pos + 1 > end) return;
        int comp = data[pos]; pos += 1;
        parent.AddLeaf("Compression Method: " + (comp == 0 ? "null" : comp.ToString()) + " (" + comp + ")");

        if (pos + 2 > end) return;
        int extLen = PacketParseHelper.ReadUInt16BE(data, pos); pos += 2;
        int extEnd = Math.Min(end, pos + extLen);
        var extParent = new BoxyBox.TreeNode("Extensions", "TLS.Extensions", false);
        string sni;
        BuildExtensions(data, pos, extEnd, false, extParent, out sni);
        if (extParent.HasChildren) parent.Add(extParent);
    }

    // Iterates the extension block [start, end): each entry is type(2) len(2) data(len). SNI,
    // supported_versions, and ALPN get their inner values decoded; the rest show type + length.
    private static void BuildExtensions(byte[] data, int start, int end, bool isClient, BoxyBox.TreeNode parent, out string sni)
    {
        sni = null;
        int pos = start;
        int guard = 0;
        while (pos + 4 <= end && guard++ < 64)
        {
            int extType = PacketParseHelper.ReadUInt16BE(data, pos);
            int extDataLen = PacketParseHelper.ReadUInt16BE(data, pos + 2);
            int extBody = pos + 4;
            int extBodyEnd = Math.Min(end, extBody + extDataLen);
            var ext = new BoxyBox.TreeNode("Extension: " + ExtensionName(extType) + " (len " + extDataLen + ")", null, false);
            ext.AddLeaf("Type: " + ExtensionName(extType) + " (" + extType + ")");
            ext.AddLeaf("Length: " + extDataLen);

            if (extType == 0 && isClient)   // server_name (SNI)
            {
                string s = ParseSniExtension(data, extBody, extBodyEnd);
                if (s != null) { ext.AddLeaf("Server Name: " + s); if (sni == null) sni = s; }
            }
            else if (extType == 43)   // supported_versions (reveals true TLS 1.3)
            {
                if (isClient)
                {
                    if (extBody < extBodyEnd)
                    {
                        int listLen = data[extBody];
                        int vp = extBody + 1; int vend = Math.Min(extBodyEnd, vp + listLen);
                        while (vp + 2 <= vend)
                        {
                            int v = PacketParseHelper.ReadUInt16BE(data, vp);
                            ext.AddLeaf("Supported Version: " + GetVersionName(v) + " (0x" + v.ToString("x4") + ")");
                            vp += 2;
                        }
                    }
                }
                else if (extBody + 2 <= extBodyEnd)
                {
                    int v = PacketParseHelper.ReadUInt16BE(data, extBody);
                    ext.AddLeaf("Supported Version: " + GetVersionName(v) + " (0x" + v.ToString("x4") + ")");
                }
            }
            else if (extType == 16)   // application_layer_protocol_negotiation (ALPN)
            {
                if (extBody + 2 <= extBodyEnd)
                {
                    int alpnLen = PacketParseHelper.ReadUInt16BE(data, extBody);
                    int ap = extBody + 2; int aend = Math.Min(extBodyEnd, ap + alpnLen);
                    while (ap + 1 <= aend)
                    {
                        int nlen = data[ap]; ap += 1;
                        if (ap + nlen > aend) break;
                        ext.AddLeaf("ALPN Protocol: " + Encoding.ASCII.GetString(data, ap, nlen));
                        ap += nlen;
                    }
                }
            }
            parent.Add(ext);
            pos = extBody + extDataLen;
        }
    }

    // server_name extension body: server_name_list length(2) then entries of
    // name_type(1) name_length(2) name. Returns the first host_name (type 0).
    private static string ParseSniExtension(byte[] data, int start, int end)
    {
        if (start + 2 > end) return null;
        int listLen = PacketParseHelper.ReadUInt16BE(data, start);
        int p = start + 2; int listEnd = Math.Min(end, p + listLen);
        while (p + 3 <= listEnd)
        {
            int nameType = data[p];
            int nameLen = PacketParseHelper.ReadUInt16BE(data, p + 1);
            p += 3;
            if (p + nameLen > listEnd) break;
            if (nameType == 0) return Encoding.ASCII.GetString(data, p, nameLen);
            p += nameLen;
        }
        return null;
    }

    // Alert body: level(1) description(1).
    private static BoxyBox.TreeNode BuildAlertNode(byte[] data, int off, int end)
    {
        var node = new BoxyBox.TreeNode("Alert Message", "TLS.Alert", false);
        if (off + 2 <= end)
        {
            int level = data[off]; int desc = data[off + 1];
            node.Text = "Alert Message: " + AlertLevelName(level) + ", " + AlertDescName(desc);
            node.AddLeaf("Level: " + AlertLevelName(level) + " (" + level + ")");
            node.AddLeaf("Description: " + AlertDescName(desc) + " (" + desc + ")");
        }
        else
        {
            node.AddLeaf("(encrypted or truncated)");
        }
        return node;
    }

    // Lowercase hex of up to maxBytes bytes; appends "..." when the field is longer.
    private static string HexPreview(byte[] data, int off, int count, int maxBytes)
    {
        if (count < 0) count = 0;
        int show = Math.Min(count, maxBytes);
        var sb = new StringBuilder(show * 2 + 4);
        for (int i = 0; i < show && off + i < data.Length; i++) sb.Append(data[off + i].ToString("x2"));
        if (count > show) sb.Append("...");
        return sb.ToString();
    }

    /// <summary>Returns a display name for a TLS extension type, or a hex form when unknown.</summary>
    public static string ExtensionName(int extType)
    {
        switch (extType)
        {
            case 0:  return "server_name";
            case 1:  return "max_fragment_length";
            case 5:  return "status_request";
            case 10: return "supported_groups";
            case 11: return "ec_point_formats";
            case 13: return "signature_algorithms";
            case 14: return "use_srtp";
            case 15: return "heartbeat";
            case 16: return "application_layer_protocol_negotiation";
            case 18: return "signed_certificate_timestamp";
            case 21: return "padding";
            case 22: return "encrypt_then_mac";
            case 23: return "extended_master_secret";
            case 27: return "compress_certificate";
            case 28: return "record_size_limit";
            case 35: return "session_ticket";
            case 41: return "pre_shared_key";
            case 42: return "early_data";
            case 43: return "supported_versions";
            case 44: return "cookie";
            case 45: return "psk_key_exchange_modes";
            case 50: return "signature_algorithms_cert";
            case 51: return "key_share";
            case 65037: return "encrypted_client_hello";
            case 65281: return "renegotiation_info";
            default: return "unknown (0x" + extType.ToString("x4") + ")";
        }
    }

    /// <summary>Returns a display name for a TLS alert level (1=Warning, 2=Fatal).</summary>
    public static string AlertLevelName(int level)
    {
        switch (level)
        {
            case 1: return "Warning";
            case 2: return "Fatal";
            default: return "Level" + level;
        }
    }

    /// <summary>Returns a display name for a TLS alert description code.</summary>
    public static string AlertDescName(int desc)
    {
        switch (desc)
        {
            case 0:   return "close_notify";
            case 10:  return "unexpected_message";
            case 20:  return "bad_record_mac";
            case 21:  return "decryption_failed";
            case 22:  return "record_overflow";
            case 30:  return "decompression_failure";
            case 40:  return "handshake_failure";
            case 41:  return "no_certificate";
            case 42:  return "bad_certificate";
            case 43:  return "unsupported_certificate";
            case 44:  return "certificate_revoked";
            case 45:  return "certificate_expired";
            case 46:  return "certificate_unknown";
            case 47:  return "illegal_parameter";
            case 48:  return "unknown_ca";
            case 49:  return "access_denied";
            case 50:  return "decode_error";
            case 51:  return "decrypt_error";
            case 70:  return "protocol_version";
            case 71:  return "insufficient_security";
            case 80:  return "internal_error";
            case 86:  return "inappropriate_fallback";
            case 90:  return "user_canceled";
            case 100: return "no_renegotiation";
            case 109: return "missing_extension";
            case 110: return "unsupported_extension";
            case 112: return "unrecognized_name";
            case 113: return "bad_certificate_status_response";
            case 115: return "unknown_psk_identity";
            case 116: return "certificate_required";
            case 120: return "no_application_protocol";
            default:  return "alert_" + desc;
        }
    }

    /// <summary>
    /// Returns a display name for a cipher suite code. Covers the TLS 1.3 suites and the common
    /// TLS 1.2 ECDHE suites; unknown codes fall back to a hex form.
    /// </summary>
    public static string CipherSuiteName(int suite)
    {
        switch (suite)
        {
            // TLS 1.3
            case 0x1301: return "TLS_AES_128_GCM_SHA256";
            case 0x1302: return "TLS_AES_256_GCM_SHA384";
            case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
            case 0x1304: return "TLS_AES_128_CCM_SHA256";
            case 0x1305: return "TLS_AES_128_CCM_8_SHA256";
            // Common TLS 1.2 ECDHE
            case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
            case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
            case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
            case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
            case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
            case 0xC013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
            case 0xC014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
            case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
            case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
            case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
            case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
            case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
            case 0x00FF: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
            case 0x5600: return "TLS_FALLBACK_SCSV";
            case 0x0A0A:
            case 0x1A1A:
            case 0x2A2A:
            case 0x3A3A:
            case 0x4A4A:
            case 0x5A5A:
            case 0x6A6A:
            case 0x7A7A:
            case 0x8A8A:
            case 0x9A9A:
            case 0xAAAA:
            case 0xBABA:
            case 0xCACA:
            case 0xDADA:
            case 0xEAEA:
            case 0xFAFA: return "GREASE";
            default:     return "Unknown";
        }
    }
}
