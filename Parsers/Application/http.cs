// http.cs - High-performance HTTP/1.x request and response parsing for real-time display.
// Extracts method, path, version, status code, and key headers (Host, Content-Type,
// Content-Length) so the formatter and an app-layer display predicate can both
// consume the parsed shape without re-decoding the same byte buffer.
//
// Architecture mirrors dns.cs / tls.cs: TryParseHttp/FormatHttpFromContext split.

using System;
using System.Text;

/// <summary>
/// Parsed HTTP/1.x request or response snapshot. Populated by
/// <see cref="HttpParser.TryParseHttp"/> and consumed both by the formatter
/// (<see cref="HttpParser.FormatHttpFromContext"/>) and by application-layer
/// display predicates (<see cref="HttpAppPredicate"/>).
/// </summary>
public struct HttpContext
{
    /// <summary>True when the first line of the HTTP message was parsed successfully.</summary>
    public bool   Valid;
    /// <summary>True when this is an HTTP request (method + path on first line). False = response.</summary>
    public bool   IsRequest;
    /// <summary>True when the header parse couldn't reach the empty header-terminator line before <c>data.Length</c>.</summary>
    public bool   Truncated;

    // --- Request fields (populated when IsRequest = true) ---
    /// <summary>HTTP method, uppercased ("GET", "POST", ...). Null for responses.</summary>
    public string Method;
    /// <summary>Request-URI (path + optional query). Null for responses.</summary>
    public string Path;

    // --- Response fields (populated when IsRequest = false) ---
    /// <summary>3-digit response status code (e.g. 200, 404). 0 for requests.</summary>
    public int    StatusCode;
    /// <summary>Reason phrase from the status line (e.g. "OK", "Not Found"). Null for requests.</summary>
    public string StatusText;

    // --- Common ---
    /// <summary>Protocol version from the first line (e.g. "HTTP/1.1"). Null when not parseable.</summary>
    public string ProtocolVersion;
    /// <summary>The HTTP message's first line verbatim (after stripping CR/LF). Used by the formatter.</summary>
    public string FirstLine;
    /// <summary>Value of the Host: header on requests. Null when absent / on responses.</summary>
    public string Host;
    /// <summary>Value of the Content-Type: header on either side. Null when absent.</summary>
    public string ContentType;
    /// <summary>Value of the Content-Length: header on either side. -1 when absent or unparseable.</summary>
    public int    ContentLength;
}

/// <summary>
/// HTTP/1.x protocol parser. Provides fast C# parsing of the request/response
/// first line plus the Host, Content-Type, and Content-Length headers.
/// Bodies are intentionally not parsed — the predicate operates only on fields
/// available in the packet's first MTU.
/// </summary>
public static class HttpParser
{
    // Header scan caps so a malformed/pathological packet can't make the parser walk
    // arbitrary distances. 1 KiB covers a realistic mix of method + path + Host +
    // Content-Type + Content-Length on the first packet.
    private const int MaxScanBytes = 1024;
    private const int MaxFirstLine = 256;

    /// <summary>
    /// Standard HTTP-bearing TCP ports recognised by the in-tree dispatcher.
    /// </summary>
    public static bool IsHttpPort(int port)
    {
        return port == 80 || port == 8080 || port == 8000 || port == 8888;
    }

    /// <summary>
    /// Lightweight sanity check on the first few bytes. Returns true for any
    /// recognised request method or for "HTTP" response prefix. Designed to
    /// skip the full parse on non-HTTP payloads at zero allocation cost.
    /// </summary>
    public static bool LooksLikeHttp(byte[] data)
    {
        if (data == null || data.Length < 4) return false;
        // HTTP response: "HTTP"
        if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') return true;
        // Requests: <METHOD>' ' prefix.
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return true;
        if (data.Length >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') return true;
        if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return true;
        if (data.Length >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ') return true;
        if (data.Length >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ') return true;
        if (data.Length >= 8 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ') return true;
        if (data.Length >= 6 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H' && data[5] == ' ') return true;
        if (data.Length >= 8 && data[0] == 'C' && data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[4] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ') return true;
        if (data.Length >= 6 && data[0] == 'T' && data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'E' && data[5] == ' ') return true;
        return false;
    }

    /// <summary>
    /// Parses an HTTP/1.x request or response. Returns false when
    /// <see cref="LooksLikeHttp"/> rejects the buffer. On success the
    /// <see cref="HttpContext"/> describes the first line plus any of the
    /// Host / Content-Type / Content-Length headers that fit within the
    /// first ~1 KiB of payload.
    /// </summary>
    public static bool TryParseHttp(byte[] data, out HttpContext ctx)
    {
        ctx = default(HttpContext);
        ctx.ContentLength = -1;
        if (!LooksLikeHttp(data)) return false;

        int scanEnd = Math.Min(data.Length, MaxScanBytes);

        // --- First line (request line or status line) ---
        int firstLineEnd = FindLineEnd(data, 0, Math.Min(scanEnd, MaxFirstLine));
        if (firstLineEnd < 0)
        {
            // No line terminator within the cap; the message header is truncated.
            ctx.Truncated = true;
            return false;
        }
        ctx.FirstLine = AsciiSafeSubstring(data, 0, firstLineEnd);

        // Response: "HTTP/M.N SSS reason"
        if (firstLineEnd >= 12 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && data[4] == '/')
        {
            ctx.IsRequest = false;
            int firstSpace = IndexOfByte(data, (byte)' ', 0, firstLineEnd);
            if (firstSpace > 0)
            {
                ctx.ProtocolVersion = AsciiSafeSubstring(data, 0, firstSpace);
                int secondSpace = IndexOfByte(data, (byte)' ', firstSpace + 1, firstLineEnd);
                int codeEnd = (secondSpace > 0) ? secondSpace : firstLineEnd;
                if (codeEnd > firstSpace + 1)
                {
                    int code = 0;
                    bool codeOk = true;
                    for (int i = firstSpace + 1; i < codeEnd; i++)
                    {
                        byte b = data[i];
                        if (b < '0' || b > '9') { codeOk = false; break; }
                        code = code * 10 + (b - '0');
                    }
                    if (codeOk) ctx.StatusCode = code;
                }
                if (secondSpace > 0 && secondSpace + 1 < firstLineEnd)
                {
                    ctx.StatusText = AsciiSafeSubstring(data, secondSpace + 1, firstLineEnd);
                }
            }
        }
        else
        {
            // Request line: "<METHOD> <path> <version>"
            ctx.IsRequest = true;
            int firstSpace = IndexOfByte(data, (byte)' ', 0, firstLineEnd);
            if (firstSpace > 0)
            {
                ctx.Method = AsciiSafeSubstring(data, 0, firstSpace).ToUpperInvariant();
                int secondSpace = IndexOfByte(data, (byte)' ', firstSpace + 1, firstLineEnd);
                int pathEnd = (secondSpace > 0) ? secondSpace : firstLineEnd;
                if (pathEnd > firstSpace + 1)
                {
                    ctx.Path = AsciiSafeSubstring(data, firstSpace + 1, pathEnd);
                }
                if (secondSpace > 0 && secondSpace + 1 < firstLineEnd)
                {
                    ctx.ProtocolVersion = AsciiSafeSubstring(data, secondSpace + 1, firstLineEnd);
                }
            }
        }

        ctx.Valid = true;

        // --- Header scan (Host, Content-Type, Content-Length) ---
        int pos = SkipLineTerminator(data, firstLineEnd, scanEnd);
        bool reachedTerminator = false;
        while (pos < scanEnd)
        {
            int lineEnd = FindLineEnd(data, pos, scanEnd);
            if (lineEnd < 0)
            {
                ctx.Truncated = true;
                break;
            }
            // Empty line → end of headers.
            if (lineEnd == pos)
            {
                reachedTerminator = true;
                break;
            }
            int colon = IndexOfByte(data, (byte)':', pos, lineEnd);
            if (colon > pos)
            {
                if (MatchesHeader(data, pos, colon, "Host"))
                {
                    ctx.Host = TrimmedHeaderValue(data, colon + 1, lineEnd);
                }
                else if (MatchesHeader(data, pos, colon, "Content-Type"))
                {
                    ctx.ContentType = TrimmedHeaderValue(data, colon + 1, lineEnd);
                }
                else if (MatchesHeader(data, pos, colon, "Content-Length"))
                {
                    string v = TrimmedHeaderValue(data, colon + 1, lineEnd);
                    int parsed;
                    if (!string.IsNullOrEmpty(v) && int.TryParse(v, out parsed)) ctx.ContentLength = parsed;
                }
            }
            pos = SkipLineTerminator(data, lineEnd, scanEnd);
        }
        // "Truncated" here means the header section wasn't terminated within the
        // packet payload — typically because -PacketSize cut the data off mid-headers
        // (or before the empty-line terminator). The scan-cap case (scanEnd < data.Length
        // with no terminator) is *not* truncation — the packet is long enough but headers
        // ran past our 1 KiB scan cap; that's a "structurally weird" packet rather than
        // a capture-side truncation.
        if (!reachedTerminator && pos >= data.Length) ctx.Truncated = true;

        return true;
    }

    /// <summary>
    /// Formats a previously parsed <see cref="HttpContext"/> using the detailed
    /// "HTTP - &lt;first line&gt;; Host: ...; Content-Type: ...; Content-Length: ..."
    /// format equivalent to the legacy <c>FormatHttpDetailed</c>.
    /// </summary>
    public static string FormatHttpFromContext(ref HttpContext ctx)
    {
        if (!ctx.Valid || string.IsNullOrEmpty(ctx.FirstLine)) return null;

        StringBuilder sb = new StringBuilder(160);
        sb.Append("HTTP - ").Append(ctx.FirstLine);
        if (!string.IsNullOrEmpty(ctx.Host))
        {
            sb.Append("; Host: ").Append(ctx.Host);
        }
        if (!string.IsNullOrEmpty(ctx.ContentType))
        {
            sb.Append("; Content-Type: ").Append(ctx.ContentType);
        }
        if (ctx.ContentLength >= 0)
        {
            sb.Append("; Content-Length: ").Append(ctx.ContentLength);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Default-tier formatter for an HTTP payload (short form, first line only).
    /// Equivalent to the legacy <c>DetectHttpContent</c>.
    /// </summary>
    public static string FormatHttpSegment(byte[] data, int dataLen)
    {
        HttpContext ctx;
        if (!TryParseHttp(data, out ctx)) return null;
        return ctx.FirstLine;
    }

    // ---- Helpers ----

    private static int FindLineEnd(byte[] data, int start, int end)
    {
        for (int i = start; i < end; i++)
        {
            if (data[i] == 0x0D || data[i] == 0x0A) return i;
        }
        return -1;
    }

    // Returns the index just past the CR / LF / CRLF starting at position lineEnd.
    private static int SkipLineTerminator(byte[] data, int lineEnd, int end)
    {
        if (lineEnd >= end) return end;
        int p = lineEnd;
        if (data[p] == 0x0D) p++;
        if (p < end && data[p] == 0x0A) p++;
        return p;
    }

    private static int IndexOfByte(byte[] data, byte target, int start, int end)
    {
        for (int i = start; i < end; i++)
        {
            if (data[i] == target) return i;
        }
        return -1;
    }

    private static bool MatchesHeader(byte[] data, int start, int colon, string name)
    {
        int nameLen = colon - start;
        if (nameLen != name.Length) return false;
        for (int i = 0; i < nameLen; i++)
        {
            byte b = data[start + i];
            char c = name[i];
            // Case-insensitive ASCII match.
            byte cb = (byte)c;
            if (b == cb) continue;
            // Equivalent if differs only by 0x20 case bit and both are letters.
            byte lo = (byte)(b | 0x20);
            byte cLo = (byte)(cb | 0x20);
            if (lo >= 'a' && lo <= 'z' && lo == cLo) continue;
            return false;
        }
        return true;
    }

    private static string TrimmedHeaderValue(byte[] data, int start, int end)
    {
        int s = start;
        int e = end;
        while (s < e && (data[s] == ' ' || data[s] == '\t')) s++;
        while (e > s && (data[e - 1] == ' ' || data[e - 1] == '\t' || data[e - 1] == '\r')) e--;
        if (e <= s) return string.Empty;
        return AsciiSafeSubstring(data, s, e);
    }

    private static string AsciiSafeSubstring(byte[] data, int start, int end)
    {
        // Trim a trailing CR if the caller passed FindLineEnd's index (which points to
        // CR or LF); the formatter expects no CR/LF in the captured string.
        while (end > start && (data[end - 1] == '\r' || data[end - 1] == '\n')) end--;
        if (end <= start) return string.Empty;
        return Encoding.ASCII.GetString(data, start, end - start);
    }
}
