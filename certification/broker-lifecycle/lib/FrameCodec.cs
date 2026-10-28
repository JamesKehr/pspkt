using System;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal static class FrameCodec
    {
        internal const int HeaderBytes = 24;
        internal const int SignatureBytes = 384;
        internal const int FrameOverhead = HeaderBytes + SignatureBytes;
        private const int VersionOffset = 4;
        private const int KindOffset = 6;
        private const int FlagsOffset = 8;
        private const int ReservedOffset = 10;
        private const int SequenceOffset = 12;
        private const int PayloadLengthOffset = 20;

        internal static DecodedControlFrame Decode(BrokerLifecycleProtocol owner, string channel, string direction, byte profile, byte[] frameBytes)
        {
            if (channel == null || direction == null || frameBytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (channel != "BrokerControl" && channel != "LocalIpc")
            {
                throw BrokerLifecycleFailure.Reject("frame:channel-unavailable");
            }
            if (profile != 2)
            {
                throw BrokerLifecycleFailure.Reject("frame:profile");
            }
            if (frameBytes.Length < FrameOverhead || frameBytes.Length > LifecyclePolicy.MaximumFrameBytes)
            {
                throw BrokerLifecycleFailure.Reject("frame:length");
            }
            if (CompleteLengthFromHeader(frameBytes) != frameBytes.Length)
            {
                throw BrokerLifecycleFailure.Reject("frame:length");
            }
            ushort kind = (ushort)ReadUnsigned(frameBytes, KindOffset, 2);
            string payloadRoot = owner.Authority.ResolvePayloadRoot(channel, direction, kind);
            ulong length = ReadUnsigned(frameBytes, PayloadLengthOffset, 4);
            ValidateCompleteFrameLength(length, (ulong)frameBytes.Length);
            byte[] payload = new byte[(int)length];
            byte[] signature = new byte[SignatureBytes];
            Buffer.BlockCopy(frameBytes, HeaderBytes, payload, 0, payload.Length);
            Buffer.BlockCopy(frameBytes, HeaderBytes + payload.Length, signature, 0, signature.Length);
            ProtocolPayloadCodec.Validate(owner.Authority, payloadRoot, payload);
            return new DecodedControlFrame(owner, channel, direction, kind, ReadUnsigned(frameBytes, SequenceOffset, 8),
                payloadRoot, payload, signature, frameBytes);
        }

        internal static byte[] Encode(BrokerLifecycleProtocol owner, string channel, string direction, byte profile,
            ushort kind, ulong sequence, byte[] payload, byte[] signature)
        {
            if (channel == null || direction == null || payload == null || signature == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (channel != "BrokerControl" && channel != "LocalIpc")
            {
                throw BrokerLifecycleFailure.Reject("frame:channel-unavailable");
            }
            if (profile != 2)
            {
                throw BrokerLifecycleFailure.Reject("frame:profile");
            }
            if (signature.Length != SignatureBytes)
            {
                throw BrokerLifecycleFailure.Reject("frame:signature-width");
            }
            ValidateCompleteFrameLength((ulong)payload.Length, (ulong)payload.Length + FrameOverhead);
            string root = owner.Authority.ResolvePayloadRoot(channel, direction, kind);
            ProtocolPayloadCodec.Validate(owner.Authority, root, payload);
            byte[] result = new byte[payload.Length + FrameOverhead];
            result[0] = 80;
            result[1] = 83;
            result[2] = 80;
            result[3] = 52;
            result[VersionOffset + 1] = 1;
            Buffer.BlockCopy(WriteUnsigned(kind, 2), 0, result, KindOffset, 2);
            Buffer.BlockCopy(WriteUnsigned(sequence, 8), 0, result, SequenceOffset, 8);
            Buffer.BlockCopy(WriteUnsigned((ulong)payload.Length, 4), 0, result, PayloadLengthOffset, 4);
            Buffer.BlockCopy(payload, 0, result, HeaderBytes, payload.Length);
            Buffer.BlockCopy(signature, 0, result, HeaderBytes + payload.Length, signature.Length);
            return result;
        }

        internal static int CompleteLengthFromHeader(byte[] header)
        {
            if (header == null || header.Length < HeaderBytes)
            {
                throw BrokerLifecycleFailure.Reject("frame:length");
            }
            if (header[0] != 80 || header[1] != 83 || header[2] != 80 || header[3] != 52)
            {
                throw BrokerLifecycleFailure.Reject("frame:header");
            }
            if (ReadUnsigned(header, VersionOffset, 2) != 1)
            {
                throw BrokerLifecycleFailure.Reject("frame:version");
            }
            if (ReadUnsigned(header, FlagsOffset, 2) != 0)
            {
                throw BrokerLifecycleFailure.Reject("frame:flags");
            }
            if (ReadUnsigned(header, ReservedOffset, 2) != 0)
            {
                throw BrokerLifecycleFailure.Reject("frame:reserved");
            }
            ulong payload = ReadUnsigned(header, PayloadLengthOffset, 4);
            ValidateCompleteFrameLength(payload, payload + FrameOverhead);
            return (int)payload + FrameOverhead;
        }

        internal static ulong ReadUnsigned(byte[] bytes, int offset, int width)
        {
            if (bytes == null || width < 1 || width > 8 || offset < 0 || offset > bytes.Length - width)
            {
                throw BrokerLifecycleFailure.Reject("frame:length");
            }
            ulong result = 0;
            for (int index = 0; index < width; index++)
            {
                result = (result << 8) | bytes[offset + index];
            }
            return result;
        }

        internal static void ValidateCompleteFrameLength(ulong payloadLength, ulong completeFrameLength)
        {
            if (payloadLength > (ulong)(LifecyclePolicy.MaximumFrameBytes - FrameOverhead) ||
                completeFrameLength > LifecyclePolicy.MaximumFrameBytes ||
                completeFrameLength != payloadLength + FrameOverhead)
            {
                throw BrokerLifecycleFailure.Reject("frame:length");
            }
        }

        internal static byte[] WriteUnsigned(ulong value, int width)
        {
            if (width < 1 || width > 8)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            byte[] bytes = new byte[width];
            for (int index = width - 1; index >= 0; index--)
            {
                bytes[index] = (byte)(value & 255);
                value >>= 8;
            }
            if (value != 0)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            return bytes;
        }
    }
}
