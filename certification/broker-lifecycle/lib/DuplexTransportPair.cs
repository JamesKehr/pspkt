namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class DuplexTransportPair
    {
        private readonly InMemoryDuplexTransport _local;
        private readonly InMemoryDuplexTransport _peer;
        private bool _closed;

        internal DuplexTransportPair(RunGenerationId generation)
        {
            _local = new InMemoryDuplexTransport(generation);
            _peer = new InMemoryDuplexTransport(generation);
            _local.Connect(_peer);
            _peer.Connect(_local);
        }

        internal IBoundedDuplexTransport Local { get { return _local; } }
        internal IBoundedDuplexTransport Peer { get { return _peer; } }
        internal bool Closed { get { return _closed; } }

        internal void Close()
        {
            if (_closed)
            {
                return;
            }
            _local.CloseStorage();
            _peer.CloseStorage();
            _closed = true;
        }
    }
}
