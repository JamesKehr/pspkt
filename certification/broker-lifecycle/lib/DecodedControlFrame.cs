namespace Pspkt.Certification.BrokerLifecycle
{
    public sealed class DecodedControlFrame
    {
        private readonly string _channel;
        private readonly byte[] _complete;
        private readonly string _direction;
        private readonly ushort _kind;
        private readonly BrokerLifecycleProtocol _owner;
        private readonly byte[] _payload;
        private readonly string _payloadRoot;
        private readonly ulong _sequence;
        private readonly byte[] _signature;

        internal DecodedControlFrame(BrokerLifecycleProtocol owner, string channel, string direction,
            ushort kind, ulong sequence, string payloadRoot, byte[] payload, byte[] signature, byte[] complete)
        {
            _owner = owner;
            _channel = channel;
            _direction = direction;
            _kind = kind;
            _sequence = sequence;
            _payloadRoot = payloadRoot;
            _payload = (byte[])payload.Clone();
            _signature = (byte[])signature.Clone();
            _complete = (byte[])complete.Clone();
        }

        public byte[] CanonicalPayload
        {
            get { return (byte[])_payload.Clone(); }
        }

        public string Channel
        {
            get { return _channel; }
        }

        public byte[] CompleteSignedFrame
        {
            get { return (byte[])_complete.Clone(); }
        }

        public string Direction
        {
            get { return _direction; }
        }

        public ushort Kind
        {
            get { return _kind; }
        }

        public uint PayloadLength
        {
            get { return (uint)_payload.Length; }
        }

        public string RequiredKeyPurpose
        {
            get
            {
                if (_direction == "HostToBroker")
                {
                    return "Host";
                }
                if (_direction == "WorkerToBroker")
                {
                    return "WorkerSession";
                }
                return _kind == 4353 ? "CheckpointMaster" : "BrokerSession";
            }
        }

        public byte RequiredSignerRole
        {
            get { return _direction == "HostToBroker" ? (byte)1 : _direction == "WorkerToBroker" ? (byte)2 : (byte)3; }
        }

        public byte SelectedProfile
        {
            get { return 2; }
        }

        public ulong Sequence
        {
            get { return _sequence; }
        }

        public byte[] Signature
        {
            get { return (byte[])_signature.Clone(); }
        }

        public string[] UncheckedSemantics
        {
            get { return BrokerLifecycleFailure.CopyUncheckedSemantics(); }
        }

        internal byte[] CopyField(params ushort[] path)
        {
            if (path == null || path.Length == 0)
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            int rangeOffset = 0;
            int rangeLength = _payload.Length;
            for (int level = 0; level < path.Length; level++)
            {
                int position = rangeOffset;
                int end = rangeOffset + rangeLength;
                bool found = false;
                while (position < end)
                {
                    if (position > end - 6)
                    {
                        throw BrokerLifecycleFailure.Reject("context:binding-shape");
                    }
                    ushort identifier = (ushort)FrameCodec.ReadUnsigned(_payload, position, 2);
                    ulong length = FrameCodec.ReadUnsigned(_payload, position + 2, 4);
                    position += 6;
                    if (length > (ulong)(end - position))
                    {
                        throw BrokerLifecycleFailure.Reject("context:binding-shape");
                    }
                    if (identifier == path[level])
                    {
                        rangeOffset = position;
                        rangeLength = (int)length;
                        found = true;
                        break;
                    }
                    position += (int)length;
                }
                if (!found)
                {
                    throw BrokerLifecycleFailure.Reject("context:binding-shape");
                }
            }
            byte[] result = new byte[rangeLength];
            System.Buffer.BlockCopy(_payload, rangeOffset, result, 0, rangeLength);
            return result;
        }

        internal BrokerLifecycleProtocol Owner
        {
            get { return _owner; }
        }

        internal string PayloadRoot
        {
            get { return _payloadRoot; }
        }
    }
}
