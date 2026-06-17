// IcmpAppPredicate.cs - ICMP / ICMPv6 / NDP application-layer display predicate.
// Evaluated on the consumer thread when ParsingLevel >= Detailed. Designed to
// allocate nothing per packet (regex is pre-compiled, all comparisons run
// against the pre-parsed IcmpContext fields).

using System;
using System.Text.RegularExpressions;

/// <summary>
/// ICMP / ICMPv6 / NDP application-layer display predicate. Evaluated against
/// a pre-parsed <see cref="IcmpContext"/> on the consumer thread when
/// <c>ParsingLevel &gt;= Detailed</c>.
///
/// IPv4 ICMP and ICMPv6 use distinct, overlapping numeric spaces (type 3 is
/// "Destination Unreachable" in both, but type 8 is "Echo Request" in v4
/// and "Multicast Listener Query 2" in v6). Per-family arrays keep the
/// predicate unambiguous and let a v4-only filter implicitly reject v6
/// packets (and vice versa) — matching the DHCP pattern.
///
/// Non-ICMP packets always pass — the predicate's job is only to narrow
/// ICMP traffic. Use a transport / IP filter if you also want to drop
/// non-ICMP traffic.
/// </summary>
public sealed class IcmpAppPredicate
{
    /// <summary>Allowed IPv4 ICMP type values (e.g. 8 = Echo Request). Null = any.</summary>
    public int[] V4Types;

    /// <summary>Allowed ICMPv6 type values (e.g. 128 = Echo Request, 135 = Neighbor Solicitation). Null = any.</summary>
    public int[] V6Types;

    /// <summary>
    /// Pre-compiled, case-insensitive regex matched against the NDP target
    /// address for Neighbor Solicitation (type 135) and Neighbor Advertisement
    /// (type 136) packets. Null = match any. Always rejects non-NS/NA packets
    /// (including non-ICMPv6) when set.
    /// </summary>
    public Regex NdpTargetRegex;

    /// <summary>
    /// Returns true when the packet matches the predicate. Designed for the
    /// hot path: no allocations, all comparisons against the pre-parsed struct.
    /// </summary>
    public bool Evaluate(ref IcmpContext ctx)
    {
        if (!ctx.Valid)
        {
            // Unparseable ICMP/ICMPv6 — only let it through if no field-specific
            // filter is configured.
            return V4Types == null && V6Types == null && NdpTargetRegex == null;
        }

        if (ctx.IsV6)
        {
            // V4-only filter implicitly rejects v6 packets.
            if (V4Types != null && V6Types == null && NdpTargetRegex == null) return false;

            if (V6Types != null)
            {
                bool ok = false;
                for (int i = 0; i < V6Types.Length; i++)
                {
                    if (V6Types[i] == ctx.Type) { ok = true; break; }
                }
                if (!ok) return false;
            }

            if (NdpTargetRegex != null)
            {
                // NDP target is only present on Neighbor Solicitation / Advertisement.
                if (ctx.Type != 135 && ctx.Type != 136) return false;
                string t = ctx.NdpTarget;
                if (string.IsNullOrEmpty(t)) return false;
                if (!NdpTargetRegex.IsMatch(t)) return false;
            }
        }
        else
        {
            // V6-only filter (V6Types or NdpTargetRegex set, V4Types null) rejects v4.
            if (V4Types == null && (V6Types != null || NdpTargetRegex != null)) return false;

            if (V4Types != null)
            {
                bool ok = false;
                for (int i = 0; i < V4Types.Length; i++)
                {
                    if (V4Types[i] == ctx.Type) { ok = true; break; }
                }
                if (!ok) return false;
            }
        }

        return true;
    }
}
