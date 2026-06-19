// tls.cs - High-performance TLS record parsing for real-time display.
// Extracts ContentType, Version, RecordLength, and (for ClientHello) SNI.
//
// Architecture mirrors dns.cs: a TryParseTls/FormatFromContext split so the
// app-layer predicate (TlsAppPredicate) can evaluate against a pre-parsed
// struct without forcing the formatter to re-parse the same record.

using System;
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
        if (!TryParseTls(data, out ctx)) return null;
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
}
