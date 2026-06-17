// Smb2AppPredicate.cs - SMB2 application-layer display predicate.
// Evaluated on the consumer thread when ParsingLevel >= Detailed. Designed
// to allocate nothing per packet (regexes are pre-compiled, all comparisons
// run against the pre-parsed Smb2Context fields).

using System;
using System.Text.RegularExpressions;

/// <summary>
/// SMB2 application-layer display predicate. Evaluated against a pre-parsed
/// <see cref="Smb2Context"/> on the consumer thread when
/// <c>ParsingLevel &gt;= Detailed</c>. Non-null fields are AND-combined;
/// within a multi-value field (e.g. <see cref="Commands"/>) any matching
/// value satisfies that field.
///
/// Encrypted (Transform-header) packets carry no per-command fields, so any
/// command/status/filename/tree-path filter rejects them. Pass
/// <see cref="MatchEncrypted"/>=true to let encrypted packets through anyway
/// (typically only useful with <see cref="Direction"/> alone, or no other
/// filter at all).
///
/// Compounded packets (NextCommand &gt; 0) are evaluated against the first
/// chained message only — a v1 limitation matching the legacy formatter.
/// </summary>
public sealed class Smb2AppPredicate
{
    /// <summary>Allowed SMB2 command codes (0..0x12). Null = any.</summary>
    public int[] Commands;

    /// <summary>Direction restriction. 0 = Request only, 1 = Response only, -1 = either. Default -1.</summary>
    public int Direction = -1;

    /// <summary>Allowed exact NT status codes (e.g. 0xC0000022 = STATUS_ACCESS_DENIED). Null = any.</summary>
    public uint[] StatusCodes;

    /// <summary>
    /// Allowed NT status classes (0 = Success, 1 = Informational, 2 = Warning, 3 = Error).
    /// Derived from the top 2 bits of the status code. Null = any.
    /// </summary>
    public int[] StatusClasses;

    /// <summary>Pre-compiled, case-insensitive regex matched against the Create-request filename. Null = match any.</summary>
    public Regex FilenameRegex;

    /// <summary>Pre-compiled, case-insensitive regex matched against the TreeConnect-request share path. Null = match any.</summary>
    public Regex TreePathRegex;

    /// <summary>
    /// When true, encrypted (Transform-header) packets match even when other
    /// filter fields are set (those fields are unavailable in encrypted packets).
    /// Default false — encrypted packets are dropped as soon as any field
    /// beyond <see cref="Direction"/> is configured, since there's nothing to
    /// compare against.
    /// </summary>
    public bool MatchEncrypted = false;

    /// <summary>
    /// When true, packets whose per-command body extraction (filename / tree
    /// path) couldn't be completed because the packet was truncated still
    /// match. Default false — truncated packets are dropped so partial-match
    /// false negatives don't surprise the user.
    /// </summary>
    public bool MatchTruncated = false;

    /// <summary>
    /// Returns true when the packet matches the predicate. Designed for the
    /// hot path: no allocations, all comparisons against the pre-parsed struct.
    /// </summary>
    public bool Evaluate(ref Smb2Context ctx)
    {
        if (!ctx.Valid) return MatchTruncated;

        // Encrypted handling — only Direction can ever match for these packets,
        // and even that is informational because the IsResponse flag is faked
        // (the Transform header itself doesn't carry direction; we leave it
        // false). Reject as soon as any per-content field is set.
        if (ctx.IsEncrypted)
        {
            bool hasContentField = Commands != null || StatusCodes != null
                || StatusClasses != null || FilenameRegex != null || TreePathRegex != null;
            if (hasContentField && !MatchEncrypted) return false;
            // Direction filter is allowed but typically meaningless on encrypted; honor as-is.
            if (Direction == 0 && ctx.IsResponse) return false;
            if (Direction == 1 && !ctx.IsResponse) return false;
            return true;
        }

        if (Direction == 0 && ctx.IsResponse) return false;
        if (Direction == 1 && !ctx.IsResponse) return false;

        if (Commands != null)
        {
            bool ok = false;
            for (int i = 0; i < Commands.Length; i++)
            {
                if (Commands[i] == ctx.Command) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (StatusCodes != null)
        {
            uint s = ctx.Status;
            bool ok = false;
            for (int i = 0; i < StatusCodes.Length; i++)
            {
                if (StatusCodes[i] == s) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (StatusClasses != null)
        {
            // NT status class is the top 2 bits: 0=Success, 1=Info, 2=Warning, 3=Error.
            int klass = (int)((ctx.Status >> 30) & 0x3);
            bool ok = false;
            for (int i = 0; i < StatusClasses.Length; i++)
            {
                if (StatusClasses[i] == klass) { ok = true; break; }
            }
            if (!ok) return false;
        }

        if (FilenameRegex != null)
        {
            // Filename only exists on Create requests. Honor MatchTruncated when
            // the body said "name length > 0" but the bytes ran past the packet.
            string name = ctx.Filename;
            if (string.IsNullOrEmpty(name))
            {
                if (ctx.Truncated && MatchTruncated) return true;
                return false;
            }
            if (!FilenameRegex.IsMatch(name)) return false;
        }

        if (TreePathRegex != null)
        {
            string path = ctx.TreePath;
            if (string.IsNullOrEmpty(path))
            {
                if (ctx.Truncated && MatchTruncated) return true;
                return false;
            }
            if (!TreePathRegex.IsMatch(path)) return false;
        }

        // Honor MatchTruncated globally when nothing else was set.
        if (ctx.Truncated && !MatchTruncated
            && FilenameRegex == null && TreePathRegex == null)
        {
            return false;
        }

        return true;
    }
}
