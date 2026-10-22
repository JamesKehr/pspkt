using System;
using System.IO;

namespace Pspkt.Certification.EvidenceRuntime
{
    internal sealed class EvidenceTlvCursor
    {
        private readonly byte[] _bytes;
        private int _position;

        internal EvidenceTlvCursor(byte[] bytes)
        {
            _bytes = bytes;
        }

        internal int Position { get { return _position; } }
        internal bool AtEnd { get { return _position == _bytes.Length; } }

        internal byte[] ReadField(ushort expectedTag)
        {
            return ReadField(expectedTag, 0, _bytes.Length);
        }

        internal byte[] ReadField(ushort expectedTag, int minimumLength, int maximumLength)
        {
            if (_bytes.Length - _position < 6) { throw new InvalidDataException("tlv-header: Truncated field."); }
            ushort tag = (ushort)((_bytes[_position] << 8) | _bytes[_position + 1]);
            uint length = ReadUInt32(_bytes, _position + 2);
            if (tag != expectedTag) { throw new InvalidDataException("tlv-tag: Unexpected field."); }
            if (length > (uint)(_bytes.Length - _position - 6)) { throw new InvalidDataException("tlv-length: Field exceeds remaining bytes."); }
            if (length < minimumLength || length > maximumLength) { throw new InvalidDataException("tlv-value-bound: Field length violates its declared bounds."); }
            byte[] value = new byte[(int)length];
            Buffer.BlockCopy(_bytes, _position + 6, value, 0, value.Length);
            _position += 6 + value.Length;
            return value;
        }

        internal static uint ReadUInt32(byte[] bytes, int offset)
        {
            if (offset < 0 || bytes.Length - offset < 4) { throw new InvalidDataException("integer-length: Truncated unsigned integer."); }
            return ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) |
                ((uint)bytes[offset + 2] << 8) | bytes[offset + 3];
        }

        internal static void WriteUInt32(byte[] bytes, int offset, uint value)
        {
            bytes[offset] = (byte)(value >> 24);
            bytes[offset + 1] = (byte)(value >> 16);
            bytes[offset + 2] = (byte)(value >> 8);
            bytes[offset + 3] = (byte)value;
        }

        internal static void WriteField(Stream stream, ushort tag, byte[] value)
        {
            byte[] header = new byte[6];
            header[0] = (byte)(tag >> 8);
            header[1] = (byte)tag;
            WriteUInt32(header, 2, (uint)value.Length);
            stream.Write(header, 0, header.Length);
            stream.Write(value, 0, value.Length);
        }
    }
}
