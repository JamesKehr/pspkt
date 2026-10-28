using System;
using System.Numerics;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class InMemoryDuplexTransport : IBoundedDuplexTransport
    {
        private readonly RunGenerationId _generation;
        private byte[] _incoming;
        private InMemoryDuplexTransport _peer;
        private int _head;
        private int _count;
        private bool _endOfStream;
        private bool _closed;

        internal InMemoryDuplexTransport(RunGenerationId generation)
        {
            _generation = generation;
            _incoming = new byte[LifecyclePolicy.MaximumQueueBytes];
        }

        public int AvailableBytes { get { return _count; } }
        public int WritableBytes { get { return _closed || _peer == null || _peer._closed ? 0 : _peer._incoming.Length - _peer._count; } }
        public bool EndOfStream { get { return _endOfStream && _count == 0; } }
        public bool Closed { get { return _closed; } }

        internal void Connect(InMemoryDuplexTransport peer)
        {
            if (_peer != null || peer == null || !object.ReferenceEquals(_generation, peer._generation))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:stale-generation");
            }
            _peer = peer;
        }

        public int Read(byte[] destination, int offset, int count)
        {
            CheckRange(destination, offset, count);
            if (_closed)
            {
                return 0;
            }
            int taken = Math.Min(count, _count);
            int first = Math.Min(taken, _incoming.Length - _head);
            Buffer.BlockCopy(_incoming, _head, destination, offset, first);
            if (taken > first)
            {
                Buffer.BlockCopy(_incoming, 0, destination, offset + first, taken - first);
            }
            _head = (_head + taken) % _incoming.Length;
            _count -= taken;
            return taken;
        }

        public int Write(byte[] source, int offset, int count)
        {
            CheckRange(source, offset, count);
            if (_closed || _peer == null || _peer._closed || _peer._endOfStream)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            int written = Math.Min(count, WritableBytes);
            int tail = (_peer._head + _peer._count) % _peer._incoming.Length;
            int first = Math.Min(written, _peer._incoming.Length - tail);
            Buffer.BlockCopy(source, offset, _peer._incoming, tail, first);
            if (written > first)
            {
                Buffer.BlockCopy(source, offset + first, _peer._incoming, 0, written - first);
            }
            _peer._count += written;
            return written;
        }

        public void SignalEof()
        {
            if (!_closed && _peer != null)
            {
                _peer._endOfStream = true;
            }
        }

        internal void CloseStorage()
        {
            _closed = true;
            _incoming = null;
            _peer = null;
            _head = 0;
            _count = 0;
        }

        internal static void ValidateQueueCapacity(int queuedFrames, ulong queuedBytes, int additionalFrameBytes)
        {
            if (queuedFrames < 0 || additionalFrameBytes < 0)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            if (queuedFrames >= LifecyclePolicy.MaximumQueueFrames ||
                new BigInteger(queuedBytes) + additionalFrameBytes > LifecyclePolicy.MaximumQueueBytes)
            {
                throw BrokerLifecycleFailure.Reject("transport:capacity");
            }
        }

        private static void CheckRange(byte[] bytes, int offset, int count)
        {
            if (bytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (offset < 0 || count < 0 || offset > bytes.Length - count)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
        }
    }
}
