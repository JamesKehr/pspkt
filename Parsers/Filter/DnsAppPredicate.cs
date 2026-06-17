// DnsAppPredicate.cs - DNS application-layer display predicate.
// Evaluated on the consumer thread when ParsingLevel >= Detailed. Designed
// to allocate nothing per packet (the regex is pre-compiled, all comparisons
// run against the pre-parsed DnsContext fields).

using System;
using System.Text.RegularExpressions;

/// <summary>
/// DNS application-layer display predicate. Evaluated against a pre-parsed
/// <see cref="DnsContext"/> on the consumer thread when
/// <c>ParsingLevel &gt;= Detailed</c>. Non-null fields are AND-combined;
/// within a multi-value field (e.g. <see cref="QTypes"/>) any matching value
/// satisfies that field (OR within field).
///
/// Constructed and configured from PowerShell during <c>Start-Pspkt</c>
/// setup. Cleared in the <c>finally</c> block via
/// <see cref="PacketLineFormatter.ClearAppPredicates"/>.
/// </summary>
public sealed class DnsAppPredicate
{
    /// <summary>
    /// Pre-compiled, case-insensitive regex matched against the first-question
    /// QNAME (without trailing dot). Null = match any name.
    /// </summary>
    public Regex QNameRegex;

    /// <summary>Allowed QTYPE numeric values (e.g. 1 = A, 28 = AAAA). Null = any.</summary>
    public int[] QTypes;

    /// <summary>Allowed response RCODE numeric values. Only consulted for responses. Null = any.</summary>
    public int[] Rcodes;

    /// <summary>Allowed transaction IDs. Null = any.</summary>
    public int[] TxIds;

    /// <summary>0 = query only, 1 = response only, -1 = either. Default -1.</summary>
    public int Qr = -1;

    /// <summary>
    /// When true, packets whose DNS parse couldn't be completed (header missing
    /// or question section truncated mid-label) match the predicate anyway.
    /// Default false — truncated packets are dropped.
    /// </summary>
    public bool MatchTruncated = false;

    /// <summary>
    /// Returns true when the packet matches the predicate. Designed for the
    /// hot path: no allocations, all comparisons against the pre-parsed struct.
    /// </summary>
    public bool Evaluate(ref DnsContext ctx)
    {
        if (!ctx.Valid) return MatchTruncated;
        if (ctx.Truncated && !MatchTruncated) return false;

        if (Qr >= 0 && ctx.Qr != Qr) return false;

        if (QTypes != null)
        {
            bool ok = false;
            for (int i = 0; i < QTypes.Length; i++)
            {
                if (QTypes[i] == ctx.QType) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (Rcodes != null && ctx.Qr == 1)
        {
            bool ok = false;
            for (int i = 0; i < Rcodes.Length; i++)
            {
                if (Rcodes[i] == ctx.Rcode) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (TxIds != null)
        {
            int id = ctx.TxId;
            bool ok = false;
            for (int i = 0; i < TxIds.Length; i++)
            {
                if (TxIds[i] == id) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (QNameRegex != null)
        {
            string name = ctx.QName;
            if (string.IsNullOrEmpty(name) || name == ".") return false;
            // Strip trailing dot so user patterns like 'example\.com$' work without
            // having to anticipate the FQDN form ("example.com.").
            if (name.Length > 1 && name[name.Length - 1] == '.')
            {
                name = name.Substring(0, name.Length - 1);
            }
            if (!QNameRegex.IsMatch(name)) return false;
        }

        return true;
    }
}
