namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class TlvCursor
    {
        private readonly byte[] _bytes;
        private readonly int _end;
        private int _position;

        internal TlvCursor(byte[] bytes, int offset, int length)
        {
            if (bytes == null || offset < 0 || length < 0 || offset > bytes.Length - length)
            {
                throw BrokerLifecycleFailure.Reject("payload:length");
            }
            _bytes = bytes;
            _position = offset;
            _end = offset + length;
        }

        internal int Remaining
        {
            get { return _end - _position; }
        }

        internal void ReadField(ushort expectedIdentifier, out int offset, out int length)
        {
            if (Remaining < 6)
            {
                throw BrokerLifecycleFailure.Reject("payload:length");
            }
            ushort identifier = (ushort)FrameCodec.ReadUnsigned(_bytes, _position, 2);
            if (identifier != expectedIdentifier)
            {
                throw BrokerLifecycleFailure.Reject("payload:tag");
            }
            ulong encodedLength = FrameCodec.ReadUnsigned(_bytes, _position + 2, 4);
            _position += 6;
            if (encodedLength > (ulong)Remaining)
            {
                throw BrokerLifecycleFailure.Reject("payload:length");
            }
            offset = _position;
            length = (int)encodedLength;
            _position += length;
        }
    }
}
