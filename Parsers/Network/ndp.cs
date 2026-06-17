// ndp.cs - Detailed parsers for IPv6 Neighbor Discovery Protocol messages
// (RFC 4861): Router Solicitation, Router Advertisement, Neighbor
// Solicitation, Neighbor Advertisement, Redirect.
//
// Replaces the one-line FormatNdpBasic for Detailed-tier output. Default-tier
// callers continue to use FormatNdpBasic which just returns the message name.
// All parsing is bounded by the supplied icmpv6Len so a truncated packet can
// only produce a partial line, never an out-of-range read.

using System;
using System.Text;

/// <summary>
/// Detailed NDP message parser. Each per-type formatter reads the message-
/// specific fields from the ICMPv6 body plus any well-known options
/// (Source/Target Link-layer address, MTU, Prefix Information, RDNSS, DNSSL).
/// </summary>
public static class NdpParser
{
    // RFC 4861 NDP option type codes.
    private const int OPT_SOURCE_LINK_ADDR = 1;
    private const int OPT_TARGET_LINK_ADDR = 2;
    private const int OPT_PREFIX_INFO      = 3;
    private const int OPT_REDIRECTED_HDR   = 4;
    private const int OPT_MTU              = 5;
    private const int OPT_ROUTE_INFO       = 24;
    private const int OPT_RDNSS            = 25;
    private const int OPT_DNSSL            = 31;

    /// <summary>
    /// Formats an NDP message (types 133-137) into a single Detailed-tier line.
    /// <paramref name="icmpv6Off"/> points at the ICMPv6 type byte; the parser
    /// reads up to <paramref name="icmpv6Len"/> bytes from there.
    /// </summary>
    public static string FormatNdpDetailed(byte[] data, int icmpv6Off, int icmpv6Len)
    {
        if (data == null || icmpv6Off < 0 || icmpv6Len < 4
            || icmpv6Off + icmpv6Len > data.Length)
        {
            return null;
        }

        int icmpv6Type = data[icmpv6Off];
        switch (icmpv6Type)
        {
            case 133: return FormatRouterSolicitation(data, icmpv6Off, icmpv6Len);
            case 134: return FormatRouterAdvertisement(data, icmpv6Off, icmpv6Len);
            case 135: return FormatNeighborSolicitation(data, icmpv6Off, icmpv6Len);
            case 136: return FormatNeighborAdvertisement(data, icmpv6Off, icmpv6Len);
            case 137: return FormatRedirect(data, icmpv6Off, icmpv6Len);
            default:  return "NDP type " + icmpv6Type.ToString();
        }
    }

    // ---- Router Solicitation (RS, RFC 4861 §4.1) ----
    // Body: Type(1) Code(1) Checksum(2) Reserved(4); options follow.
    private static string FormatRouterSolicitation(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(64);
        sb.Append("NDP RouterSolicitation");
        if (len >= 8)
        {
            AppendOptions(sb, data, off + 8, off + len);
        }
        return sb.ToString();
    }

    // ---- Router Advertisement (RA, RFC 4861 §4.2) ----
    // Body: Type(1) Code(1) Checksum(2) CurHopLimit(1) Flags(1)
    //       RouterLifetime(2 BE) ReachableTime(4 BE) RetransTimer(4 BE);
    //       options follow at offset 16.
    private static string FormatRouterAdvertisement(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(160);
        sb.Append("NDP RouterAdvertisement");
        if (len >= 16)
        {
            int hopLim     = data[off + 4];
            byte flags     = data[off + 5];
            int routerLife = (data[off + 6] << 8) | data[off + 7];
            uint reachMs   = ReadUInt32BE(data, off + 8);
            uint retransMs = ReadUInt32BE(data, off + 12);

            // Flag bits (per RFC 4861 + RFC 4191): M (0x80), O (0x40), H (0x20),
            // Prf (0x18, 2 bits — 00 medium, 01 high, 10 reserved, 11 low),
            // P (0x04, RFC 4389).
            int m   = (flags >> 7) & 1;
            int o   = (flags >> 6) & 1;
            int h   = (flags >> 5) & 1;
            int prf = (flags >> 3) & 0x3;

            sb.Append("; HopLim ").Append(hopLim);
            sb.Append("; M=").Append(m).Append(" O=").Append(o);
            if (h != 0) sb.Append(" H=1");
            sb.Append(" Pref=").Append(PrefName(prf));
            sb.Append("; Lifetime ").Append(routerLife).Append("s");
            sb.Append("; ReachTime ").Append(reachMs).Append("ms");
            sb.Append("; RetransTimer ").Append(retransMs).Append("ms");

            AppendOptions(sb, data, off + 16, off + len);
        }
        return sb.ToString();
    }

    // ---- Neighbor Solicitation (NS, RFC 4861 §4.3) ----
    // Body: Type(1) Code(1) Checksum(2) Reserved(4) TargetAddress(16);
    //       options at offset 24.
    private static string FormatNeighborSolicitation(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(96);
        sb.Append("NDP NeighborSolicitation");
        if (len >= 24)
        {
            sb.Append("; Target ").Append(FormatIPv6(data, off + 8));
            AppendOptions(sb, data, off + 24, off + len);
        }
        return sb.ToString();
    }

    // ---- Neighbor Advertisement (NA, RFC 4861 §4.4) ----
    // Body: Type(1) Code(1) Checksum(2) Flags(4 — only top 3 bits used)
    //       TargetAddress(16); options at offset 24.
    private static string FormatNeighborAdvertisement(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(96);
        sb.Append("NDP NeighborAdvertisement");
        if (len >= 24)
        {
            byte naFlags = data[off + 4];
            int r = (naFlags >> 7) & 1;
            int s = (naFlags >> 6) & 1;
            int o = (naFlags >> 5) & 1;
            sb.Append("; Target ").Append(FormatIPv6(data, off + 8));
            sb.Append("; R=").Append(r).Append(" S=").Append(s).Append(" O=").Append(o);
            AppendOptions(sb, data, off + 24, off + len);
        }
        return sb.ToString();
    }

    // ---- Redirect (RFC 4861 §4.5) ----
    // Body: Type(1) Code(1) Checksum(2) Reserved(4) TargetAddress(16)
    //       DestinationAddress(16); options at offset 40.
    private static string FormatRedirect(byte[] data, int off, int len)
    {
        StringBuilder sb = new StringBuilder(96);
        sb.Append("NDP Redirect");
        if (len >= 40)
        {
            sb.Append("; Target ").Append(FormatIPv6(data, off + 8));
            sb.Append("; Dest ").Append(FormatIPv6(data, off + 24));
            AppendOptions(sb, data, off + 40, off + len);
        }
        return sb.ToString();
    }

    // ---- Option walker ----
    // RFC 4861 §4.6: every option is Type(1) Length(1, in 8-byte units including
    // these two bytes) followed by (Length*8 - 2) payload bytes. Walks the
    // option block until the end-of-buffer or a length=0 (malformed) entry.
    private static void AppendOptions(StringBuilder sb, byte[] data, int optOff, int optEnd)
    {
        if (optOff < 0 || optEnd > data.Length || optOff >= optEnd) return;

        int pos = optOff;
        // Safety cap: at most 32 options per packet — defensive against pathological
        // packets that report length=0 inside an otherwise valid-looking buffer.
        int safety = 32;
        while (pos + 2 <= optEnd && safety-- > 0)
        {
            int optType = data[pos];
            int optLen8 = data[pos + 1];
            if (optLen8 == 0) break;                  // malformed
            int optBytes = optLen8 * 8;
            if (pos + optBytes > optEnd) break;       // truncated

            switch (optType)
            {
                case OPT_SOURCE_LINK_ADDR:
                    if (optBytes >= 8)
                    {
                        sb.Append("; SrcLL ").Append(FormatMac(data, pos + 2));
                    }
                    break;

                case OPT_TARGET_LINK_ADDR:
                    if (optBytes >= 8)
                    {
                        sb.Append("; TgtLL ").Append(FormatMac(data, pos + 2));
                    }
                    break;

                case OPT_MTU:
                    if (optBytes >= 8)
                    {
                        // 2 reserved + 4-byte MTU.
                        uint mtu = ReadUInt32BE(data, pos + 4);
                        sb.Append("; MTU ").Append(mtu);
                    }
                    break;

                case OPT_PREFIX_INFO:
                    if (optBytes >= 32)
                    {
                        int prefLen      = data[pos + 2];
                        byte prefixFlags = data[pos + 3];
                        int onLink       = (prefixFlags >> 7) & 1; // L
                        int autoConf     = (prefixFlags >> 6) & 1; // A
                        uint validLife   = ReadUInt32BE(data, pos + 4);
                        uint preferLife  = ReadUInt32BE(data, pos + 8);
                        string prefix    = FormatIPv6(data, pos + 16);
                        sb.Append("; Prefix ").Append(prefix).Append('/').Append(prefLen);
                        sb.Append(" L=").Append(onLink).Append(" A=").Append(autoConf);
                        sb.Append(" Valid ").Append(FormatLifetime(validLife));
                        sb.Append(" Pref ").Append(FormatLifetime(preferLife));
                    }
                    break;

                case OPT_RDNSS:
                    if (optBytes >= 8 + 16)
                    {
                        // 2 reserved + 4 lifetime + N x 16-byte addrs.
                        uint life = ReadUInt32BE(data, pos + 4);
                        int addrBytes = optBytes - 8;
                        int nServers = addrBytes / 16;
                        sb.Append("; RDNSS Lifetime ").Append(FormatLifetime(life));
                        for (int i = 0; i < nServers && i < 4; i++)
                        {
                            sb.Append(' ').Append(FormatIPv6(data, pos + 8 + i * 16));
                        }
                        if (nServers > 4) sb.Append(" +").Append(nServers - 4).Append(" more");
                    }
                    break;

                case OPT_DNSSL:
                    if (optBytes >= 8)
                    {
                        uint life = ReadUInt32BE(data, pos + 4);
                        sb.Append("; DNSSL Lifetime ").Append(FormatLifetime(life));
                    }
                    break;

                case OPT_REDIRECTED_HDR:
                    sb.Append("; RedirHdr (").Append(optBytes - 8).Append("B)");
                    break;

                case OPT_ROUTE_INFO:
                    // 1-byte prefix length + flags + 4-byte route lifetime + variable prefix bytes.
                    if (optBytes >= 8)
                    {
                        int rPrefLen = data[pos + 2];
                        uint rLife   = ReadUInt32BE(data, pos + 4);
                        sb.Append("; Route /").Append(rPrefLen).Append(" Lifetime ").Append(FormatLifetime(rLife));
                    }
                    break;

                default:
                    sb.Append("; Opt").Append(optType).Append(" (").Append(optBytes).Append("B)");
                    break;
            }

            pos += optBytes;
        }
    }

    // ---- Helpers (kept private to avoid colliding with the formatter's helpers) ----

    private static string PrefName(int prf)
    {
        switch (prf)
        {
            case 0: return "Medium";
            case 1: return "High";
            case 2: return "Reserved";
            case 3: return "Low";
            default: return prf.ToString();
        }
    }

    // 0xFFFFFFFF lifetime means "infinite" in NDP semantics.
    private static string FormatLifetime(uint seconds)
    {
        if (seconds == 0xFFFFFFFFu) return "Infinite";
        return seconds.ToString() + "s";
    }

    private static uint ReadUInt32BE(byte[] data, int offset)
    {
        return (uint)((data[offset] << 24) | (data[offset + 1] << 16) |
                      (data[offset + 2] << 8) | data[offset + 3]);
    }

    private static string FormatIPv6(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 16) return string.Empty;
        byte[] addr = new byte[16];
        Buffer.BlockCopy(data, offset, addr, 0, 16);
        return new System.Net.IPAddress(addr).ToString();
    }

    private static string FormatMac(byte[] data, int offset)
    {
        if (data == null || data.Length < offset + 6) return string.Empty;
        return string.Concat(
            data[offset].ToString("x2"), "-",
            data[offset + 1].ToString("x2"), "-",
            data[offset + 2].ToString("x2"), "-",
            data[offset + 3].ToString("x2"), "-",
            data[offset + 4].ToString("x2"), "-",
            data[offset + 5].ToString("x2"));
    }
}
