// HttpAppPredicate.cs - HTTP/1.x application-layer display predicate.
// Evaluated on the consumer thread when ParsingLevel >= Detailed. Designed
// to allocate nothing per packet (all regexes are pre-compiled, all
// comparisons run against the pre-parsed HttpContext fields).

using System;
using System.Text.RegularExpressions;

/// <summary>
/// HTTP application-layer display predicate. Evaluated against a pre-parsed
/// <see cref="HttpContext"/> on the consumer thread when
/// <c>ParsingLevel &gt;= Detailed</c>. Non-null fields are AND-combined;
/// within a multi-value field any matching value satisfies that field.
///
/// Request vs response: <see cref="Methods"/> / <see cref="HostRegex"/> /
/// <see cref="PathRegex"/> only match requests; <see cref="StatusCodes"/> /
/// <see cref="StatusClasses"/> only match responses. When both kinds of
/// constraints are configured, only a packet that satisfies the right side
/// passes — effectively a hard request-vs-response split.
/// </summary>
public sealed class HttpAppPredicate
{
    /// <summary>Allowed request methods, uppercase (e.g. "GET", "POST"). Null = any.</summary>
    public string[] Methods;

    /// <summary>Pre-compiled, case-insensitive regex matched against the request path. Null = any.</summary>
    public Regex PathRegex;

    /// <summary>Pre-compiled, case-insensitive regex matched against the Host: header. Null = any.</summary>
    public Regex HostRegex;

    /// <summary>Pre-compiled, case-insensitive regex matched against the Content-Type: header. Null = any.</summary>
    public Regex ContentTypeRegex;

    /// <summary>Allowed exact response status codes (e.g. 404, 503). Null = any.</summary>
    public int[] StatusCodes;

    /// <summary>Allowed response status code classes (1-5, e.g. 4 matches 400-499). Null = any.</summary>
    public int[] StatusClasses;

    /// <summary>
    /// When true, packets whose HTTP header section couldn't be reached because
    /// the packet was truncated still match. Default false — truncated packets
    /// are dropped so partial-match false negatives don't surprise the user.
    /// </summary>
    public bool MatchTruncated = false;

    /// <summary>
    /// Returns true when the packet matches the predicate. Designed for the
    /// hot path: no allocations, all comparisons against the pre-parsed struct.
    /// </summary>
    public bool Evaluate(ref HttpContext ctx)
    {
        if (!ctx.Valid) return MatchTruncated;
        if (ctx.Truncated && !MatchTruncated) return false;

        // Request-side filters: any of these set forces request-only matching.
        bool needRequest = Methods != null || PathRegex != null || HostRegex != null;
        // Response-side filters: any of these set forces response-only matching.
        bool needResponse = StatusCodes != null || StatusClasses != null;

        if (needRequest && needResponse)
        {
            // Pathological: filters require both sides simultaneously. No packet
            // is both a request and a response, so always reject.
            return false;
        }
        if (needRequest && !ctx.IsRequest) return false;
        if (needResponse && ctx.IsRequest) return false;

        if (Methods != null)
        {
            string m = ctx.Method;
            if (string.IsNullOrEmpty(m)) return false;
            bool ok = false;
            for (int i = 0; i < Methods.Length; i++)
            {
                if (string.Equals(Methods[i], m, StringComparison.OrdinalIgnoreCase))
                {
                    ok = true; break;
                }
            }
            if (!ok) return false;
        }

        if (PathRegex != null)
        {
            string p = ctx.Path;
            if (string.IsNullOrEmpty(p)) return false;
            if (!PathRegex.IsMatch(p)) return false;
        }

        if (HostRegex != null)
        {
            string h = ctx.Host;
            if (string.IsNullOrEmpty(h)) return false;
            if (!HostRegex.IsMatch(h)) return false;
        }

        if (StatusCodes != null)
        {
            bool ok = false;
            for (int i = 0; i < StatusCodes.Length; i++)
            {
                if (StatusCodes[i] == ctx.StatusCode) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (StatusClasses != null)
        {
            int klass = ctx.StatusCode / 100;
            bool ok = false;
            for (int i = 0; i < StatusClasses.Length; i++)
            {
                if (StatusClasses[i] == klass) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (ContentTypeRegex != null)
        {
            string ct = ctx.ContentType;
            if (string.IsNullOrEmpty(ct)) return false;
            if (!ContentTypeRegex.IsMatch(ct)) return false;
        }

        return true;
    }
}
