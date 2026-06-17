// TlsAppPredicate.cs - TLS application-layer display predicate.
// Evaluated on the consumer thread when ParsingLevel >= Detailed. Designed
// to allocate nothing per packet (regex is pre-compiled, all comparisons
// run against the pre-parsed TlsContext fields).

using System;
using System.Text.RegularExpressions;

/// <summary>
/// TLS application-layer display predicate. Evaluated against a pre-parsed
/// <see cref="TlsContext"/> on the consumer thread when
/// <c>ParsingLevel &gt;= Detailed</c>. Non-null fields are AND-combined;
/// within a multi-value field (e.g. <see cref="Versions"/>) any matching
/// value satisfies that field (OR within field).
///
/// SNI semantics: when <see cref="SniRegex"/> is set, only ClientHello
/// records that carry an SNI extension can match — every other TLS record
/// (Alert, AppData, ServerHello, etc.) is rejected because there is no SNI
/// to compare against. This is the intuitive behavior: "show me TLS for
/// example.com" naturally means the ClientHello that named example.com.
/// </summary>
public sealed class TlsAppPredicate
{
    /// <summary>
    /// Pre-compiled, case-insensitive regex matched against the ClientHello SNI.
    /// Null = match any record (no SNI requirement).
    /// </summary>
    public Regex SniRegex;

    /// <summary>Allowed TLS record versions (e.g. 0x0303 = TLS 1.2). Null = any.</summary>
    public int[] Versions;

    /// <summary>Allowed TLS record content types (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData). Null = any.</summary>
    public int[] ContentTypes;

    /// <summary>Allowed TLS handshake message types (1=ClientHello, 2=ServerHello, 11=Certificate, ...). Null = any. Only consulted for Handshake records.</summary>
    public int[] HandshakeTypes;

    /// <summary>
    /// When true, ClientHello records whose SNI extension couldn't be reached
    /// because the packet was truncated still match. Default false — truncated
    /// records are dropped when an SNI filter is active.
    /// </summary>
    public bool MatchTruncated = false;

    /// <summary>
    /// Returns true when the packet matches the predicate. Designed for the
    /// hot path: no allocations, all comparisons against the pre-parsed struct.
    /// </summary>
    public bool Evaluate(ref TlsContext ctx)
    {
        if (!ctx.Valid) return MatchTruncated;

        if (Versions != null)
        {
            bool ok = false;
            for (int i = 0; i < Versions.Length; i++)
            {
                if (Versions[i] == ctx.Version) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (ContentTypes != null)
        {
            bool ok = false;
            for (int i = 0; i < ContentTypes.Length; i++)
            {
                if (ContentTypes[i] == ctx.ContentType) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (HandshakeTypes != null)
        {
            // Only Handshake records (ContentType=22) can match a handshake-type filter.
            if (ctx.ContentType != 22) return false;
            bool ok = false;
            for (int i = 0; i < HandshakeTypes.Length; i++)
            {
                if (HandshakeTypes[i] == ctx.HandshakeType) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (SniRegex != null)
        {
            // SNI filter implies ClientHello (HandshakeType=1). Other record
            // types can't carry an SNI, so reject them outright.
            if (ctx.ContentType != 22 || ctx.HandshakeType != 1)
            {
                return false;
            }
            if (string.IsNullOrEmpty(ctx.Sni))
            {
                // ClientHello reached but SNI absent or unparseable.
                // Honor MatchTruncated only when the parse actually ran out of bytes.
                return ctx.Truncated && MatchTruncated;
            }
            if (!SniRegex.IsMatch(ctx.Sni)) return false;
        }

        return true;
    }
}
