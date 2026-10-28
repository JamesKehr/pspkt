namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class FrameWriteEpisode
    {
        private readonly RunGenerationId _generation;
        private readonly DecodedControlFrame _frame;
        private readonly AbsoluteDeadline _deadline;
        private byte[] _bytes;
        private int _offset;
        private bool _started;
        private bool _retired;
        private string _retirementReason = string.Empty;

        internal FrameWriteEpisode(RunGenerationId generation, DecodedControlFrame frame, AbsoluteDeadline deadline)
        {
            _generation = generation;
            _frame = frame;
            _deadline = deadline;
            _bytes = frame.CompleteSignedFrame;
        }

        internal RunGenerationId Generation { get { return _generation; } }
        internal DecodedControlFrame Frame { get { return _frame; } }
        internal AbsoluteDeadline Deadline { get { return _deadline; } }
        internal int Length { get { return (int)_frame.PayloadLength + FrameCodec.FrameOverhead; } }
        internal int Offset { get { return _offset; } }
        internal bool HasStarted { get { return _started; } }
        internal bool Retired { get { return _retired; } }
        internal string RetirementReason { get { return _retirementReason; } }

        internal int Advance(IBoundedDuplexTransport transport, int maximumBytes)
        {
            if (_retired)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            if (transport.WritableBytes == 0)
            {
                return 0;
            }
            _started = true;
            int written = transport.Write(_bytes, _offset, System.Math.Min(maximumBytes, _bytes.Length - _offset));
            if (written < 0 || written > _bytes.Length - _offset)
            {
                throw BrokerLifecycleFailure.Reject("transport:indeterminate-write");
            }
            _offset += written;
            return written;
        }

        internal void BeginAttempt()
        {
            if (_retired)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            _started = true;
        }

        internal byte[] CopyBytes()
        {
            return _frame.CompleteSignedFrame;
        }

        internal void Retire(string reason)
        {
            if (_retired)
            {
                return;
            }
            _retired = true;
            _retirementReason = reason;
            _bytes = null;
        }
    }
}
