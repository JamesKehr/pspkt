// icmp.cs - Lightweight ICMP / ICMPv6 / NDP context struct for the
// application-layer display predicate.
//
// Unlike the other protocols, ICMP doesn't get its own TryParse helper —
// the ICMP type / code are already extracted by FormatSinglePacketInto's
// IPv4 transport switch, and the IPv6 ICMPv6 type / NDP target are
// extracted inline in the consumer gate using FindIPv6UpperLayer. The
// struct exists purely to give IcmpAppPredicate.Evaluate a uniform shape.

using System;

/// <summary>
/// Parsed ICMP / ICMPv6 snapshot used by the application-layer display
/// predicate (<see cref="IcmpAppPredicate"/>). Populated by the IPv4 and
/// IPv6 fast-path gates in <c>FormatSinglePacketInto</c>.
/// </summary>
public struct IcmpContext
{
    /// <summary>True when the ICMP / ICMPv6 type byte was successfully read.</summary>
    public bool   Valid;
    /// <summary>True for ICMPv6 (IPv6 next-header 58). False for IPv4 ICMP (protocol 1).</summary>
    public bool   IsV6;
    /// <summary>ICMP / ICMPv6 type byte.</summary>
    public int    Type;
    /// <summary>ICMP / ICMPv6 code byte.</summary>
    public int    Code;
    /// <summary>
    /// NDP target address (canonical IPv6 string form) for Neighbor Solicitation
    /// (type 135) and Neighbor Advertisement (type 136) packets. Null for every
    /// other ICMPv6 type and for all IPv4 ICMP packets.
    /// </summary>
    public string NdpTarget;
}
