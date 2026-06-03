// tcp.cs - TCP protocol parsing helpers (options parsing, detailed formatting).

using System;
using System.Text;

/// <summary>
/// High-performance TCP options and header parsing in C#.
/// Replaces PowerShell Format-TcpOptions for significant performance gain on high-throughput captures.
/// </summary>
public static class TcpParser
{
    /// <summary>
    /// Parses TCP options bytes into a compact human-readable string.
    /// Supports: MSS, Window Scale, SACK Permitted, SACK blocks, Timestamps, NOP, EOL.
    /// <summary>
    /// Returns null if no options present.
    /// </summary>
    public static string FormatTcpOptions(byte[] options)
    {
        if (options == null) return null;
        return FormatTcpOptions(options, 0, options.Length);
    }

    /// <summary>
    /// Range-based overload — avoids slice/byte[] allocation in detailed-mode formatting.
    /// </summary>
    public static string FormatTcpOptions(byte[] options, int offset, int length)
    {
        if (options == null || length == 0) return null;
        int end = offset + length;
        if (end > options.Length) end = options.Length;

        StringBuilder sb = new StringBuilder(64);
        int i = offset;
        bool first = true;

        while (i < end)
        {
            byte kind = options[i];
            switch (kind)
            {
                case 0: // EOL
                    i = end;
                    break;

                case 1: // NOP
                    if (!first) sb.Append(',');
                    sb.Append("nop");
                    first = false;
                    i++;
                    break;

                case 2: // MSS (length=4)
                    if (i + 3 < end)
                    {
                        ushort mss = PacketParseHelper.ReadUInt16BE(options, i + 2);
                        if (!first) sb.Append(',');
                        sb.Append("mss ");
                        sb.Append(mss.ToString());
                        first = false;
                    }
                    i += 4;
                    break;

                case 3: // Window Scale (length=3)
                    if (i + 2 < end)
                    {
                        byte scale = options[i + 2];
                        if (!first) sb.Append(',');
                        sb.Append("wscale ");
                        sb.Append(scale.ToString());
                        first = false;
                    }
                    i += 3;
                    break;

                case 4: // SACK Permitted (length=2)
                    if (!first) sb.Append(',');
                    sb.Append("sackOK");
                    first = false;
                    i += 2;
                    break;

                case 5: // SACK blocks
                    if (i + 1 < end)
                    {
                        int optLen = options[i + 1];
                        int blockCount = (optLen - 2) / 8;
                        if (!first) sb.Append(',');
                        sb.Append("sack ");
                        first = false;
                        bool firstBlock = true;
                        for (int b = 0; b < blockCount; b++)
                        {
                            int blockOffset = i + 2 + (b * 8);
                            if (blockOffset + 7 < end)
                            {
                                uint left = PacketParseHelper.ReadUInt32BE(options, blockOffset);
                                uint right = PacketParseHelper.ReadUInt32BE(options, blockOffset + 4);
                                if (!firstBlock) sb.Append(',');
                                sb.Append(left.ToString());
                                sb.Append('-');
                                sb.Append(right.ToString());
                                firstBlock = false;
                            }
                        }
                        i += optLen;
                    }
                    else
                    {
                        i = end;
                    }
                    break;

                case 8: // Timestamps (length=10)
                    if (i + 9 < end)
                    {
                        uint tsVal = PacketParseHelper.ReadUInt32BE(options, i + 2);
                        uint tsEcr = PacketParseHelper.ReadUInt32BE(options, i + 6);
                        if (!first) sb.Append(',');
                        sb.Append("TS val ");
                        sb.Append(tsVal.ToString());
                        sb.Append(" ecr ");
                        sb.Append(tsEcr.ToString());
                        first = false;
                    }
                    i += 10;
                    break;

                default:
                    // Unknown option — skip using length field.
                    if (i + 1 < end)
                    {
                        int optLen = options[i + 1];
                        if (optLen < 2) optLen = 2;
                        i += optLen;
                    }
                    else
                    {
                        i = end;
                    }
                    break;
            }
        }

        if (sb.Length == 0) return null;
        return sb.ToString();
    }

    /// <summary>
    /// Formats a detailed TCP line for verbose output:
    /// TCP [flags] - Src: port, Dst: port; seq: N, ack: N, win: N, len: N[; Opts: ...]
    /// </summary>
    public static string FormatTcpDetailed(byte flags, ushort srcPort, ushort dstPort,
        uint seq, uint ack, ushort win, int dataLen, byte[] options)
    {
        if (options == null) return FormatTcpDetailed(flags, srcPort, dstPort, seq, ack, win, dataLen, null, 0, 0);
        return FormatTcpDetailed(flags, srcPort, dstPort, seq, ack, win, dataLen, options, 0, options.Length);
    }

    /// <summary>
    /// Range-based overload — avoids slice allocation for TCP options bytes.
    /// </summary>
    public static string FormatTcpDetailed(byte flags, ushort srcPort, ushort dstPort,
        uint seq, uint ack, ushort win, int dataLen, byte[] options, int optOffset, int optLen)
    {
        string f = PacketParseHelper.FormatTcpFlags(flags);
        StringBuilder sb = new StringBuilder(128);
        sb.Append("TCP [");
        sb.Append(f);
        sb.Append("] - Src: ");
        sb.Append(srcPort.ToString());
        sb.Append(", Dst: ");
        sb.Append(dstPort.ToString());
        sb.Append("; seq: ");
        sb.Append(seq.ToString());
        sb.Append(", ack: ");
        sb.Append(ack.ToString());
        sb.Append(", win: ");
        sb.Append(win.ToString());
        sb.Append(", len: ");
        sb.Append(dataLen.ToString());

        string opts = (options != null && optLen > 0) ? FormatTcpOptions(options, optOffset, optLen) : null;
        if (opts != null)
        {
            sb.Append("; Opts: ");
            sb.Append(opts);
        }

        return sb.ToString();
    }
}
