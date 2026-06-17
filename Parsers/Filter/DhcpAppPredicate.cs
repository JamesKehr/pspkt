// DhcpAppPredicate.cs - DHCP application-layer display predicate.
// Evaluated on the consumer thread when ParsingLevel >= Detailed. Designed
// to allocate nothing per packet (all regexes are pre-compiled, all
// comparisons run against the pre-parsed DhcpContext fields).

using System;
using System.Text.RegularExpressions;

/// <summary>
/// DHCP application-layer display predicate. Evaluated against a pre-parsed
/// <see cref="DhcpContext"/> on the consumer thread when
/// <c>ParsingLevel &gt;= Detailed</c>. Non-null fields are AND-combined;
/// within a multi-value field any matching value satisfies that field.
///
/// DHCPv4 and DHCPv6 use distinct, overlapping message-type number spaces
/// (e.g. type 3 is "Request" in v4 and "Request" in v6, but type 1 is
/// "Discover" in v4 and "Solicit" in v6). To keep the predicate
/// unambiguous, message-type filters are stored per-family. The PowerShell
/// resolver populates both arrays when a numeric value or a name that
/// exists in both families is supplied.
/// </summary>
public sealed class DhcpAppPredicate
{
    /// <summary>Allowed DHCPv4 message-type values (e.g. 1=Discover, 5=Ack). Null = any.</summary>
    public int[] V4MessageTypes;

    /// <summary>Allowed DHCPv6 message-type values (e.g. 1=Solicit, 7=Reply). Null = any.</summary>
    public int[] V6MessageTypes;

    /// <summary>
    /// Pre-compiled, case-insensitive regex matched against the DHCPv4 client
    /// hardware address (canonical aa-bb-cc-dd-ee-ff form). Null = match any.
    /// Always rejects DHCPv6 packets when set (DHCPv6 uses variable DUIDs that
    /// the v1 parser doesn't decode).
    /// </summary>
    public Regex ClientMacRegex;

    /// <summary>
    /// Address family restriction. 4 = DHCPv4 only, 6 = DHCPv6 only, 0 = either.
    /// Default 0.
    /// </summary>
    public int Family = 0;

    /// <summary>
    /// When true, packets whose DHCPv4 option block couldn't be fully walked
    /// (typically because <c>-PacketSize</c> truncated the payload before the
    /// option-53 message type was found) still match the predicate. Default
    /// false — truncated packets are dropped when a message-type filter is
    /// active so a partial-match false negative isn't silent.
    /// </summary>
    public bool MatchTruncated = false;

    /// <summary>
    /// Returns true when the packet matches the predicate. Designed for the
    /// hot path: no allocations, all comparisons against the pre-parsed struct.
    /// </summary>
    public bool Evaluate(ref DhcpContext ctx)
    {
        if (!ctx.Valid) return MatchTruncated;

        if (Family == 4 && ctx.IsV6) return false;
        if (Family == 6 && !ctx.IsV6) return false;

        if (ctx.IsV6)
        {
            if (V6MessageTypes != null)
            {
                bool ok = false;
                for (int i = 0; i < V6MessageTypes.Length; i++)
                {
                    if (V6MessageTypes[i] == ctx.MessageType) { ok = true; break; }
                }
                if (!ok) return false;
            }
            // A V4-only message-type filter rejects every v6 packet. This makes
            // -DhcpMessageType Discover (v4-only) implicitly v4-only without the
            // user having to also pass -DhcpFamily V4.
            else if (V4MessageTypes != null)
            {
                return false;
            }
        }
        else
        {
            if (V4MessageTypes != null)
            {
                // option-53 truncation is honored here per MatchTruncated.
                if (ctx.MessageType == 0)
                {
                    if (!ctx.Truncated || !MatchTruncated) return false;
                }
                else
                {
                    bool ok = false;
                    for (int i = 0; i < V4MessageTypes.Length; i++)
                    {
                        if (V4MessageTypes[i] == ctx.MessageType) { ok = true; break; }
                    }
                    if (!ok) return false;
                }
            }
            // Symmetric: a V6-only message-type filter rejects every v4 packet.
            else if (V6MessageTypes != null)
            {
                return false;
            }
        }

        if (ClientMacRegex != null)
        {
            string mac = ctx.ClientMacAddress;
            if (string.IsNullOrEmpty(mac)) return false;
            if (!ClientMacRegex.IsMatch(mac)) return false;
        }

        // Honor MatchTruncated globally for v4 when a v4 option-53 wasn't reached
        // and no message-type filter was set (above branch already covered that).
        if (!ctx.IsV6 && ctx.Truncated && !MatchTruncated && V4MessageTypes == null)
        {
            return false;
        }

        return true;
    }
}
