using System.Collections.Generic;
using System.Threading;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class PendingTransportOperation
    {
        private readonly RunGenerationId _generation;
        private readonly ulong _operationNumber;
        private readonly string _channel;
        private readonly string _direction;
        private readonly AbsoluteDeadline _deadline;
        private readonly FrameWriteEpisode _episode;
        private readonly DispatchLease _lease;
        private bool _retired;
        private bool _abortSignaled;
        private string _retirementReason = string.Empty;
        private WriteCompletion _held;
        private TransportOutcomeScript.OutcomeKind[] _outcomes;
        private int[] _increments;
        private int _cursor;
        private int _deliveryCount;
        private readonly List<TransportOutcomeScript.OutcomeKind> _consumed = new List<TransportOutcomeScript.OutcomeKind>();

        internal PendingTransportOperation(RunGenerationId generation, ulong operationNumber, string channel,
            string direction, AbsoluteDeadline deadline, FrameWriteEpisode episode, DispatchLease lease)
        {
            _generation = generation;
            _operationNumber = operationNumber;
            _channel = channel;
            _direction = direction;
            _deadline = deadline;
            _episode = episode;
            _lease = lease;
        }

        internal RunGenerationId Generation { get { return _generation; } }
        internal ulong OperationNumber { get { return _operationNumber; } }
        internal string Channel { get { return _channel; } }
        internal string Direction { get { return _direction; } }
        internal int FrameLength { get { return _episode == null ? 0 : _episode.Length; } }
        internal bool HasHeldCompletion { get { return _held != null; } }
        internal string RetirementReason { get { return _retirementReason; } }
        internal AbsoluteDeadline Deadline { get { return _deadline; } }
        internal FrameWriteEpisode Episode { get { return _episode; } }
        internal bool Retired { get { return _retired; } }
        internal bool HasOutstandingDelivery { get { return Volatile.Read(ref _deliveryCount) != 0; } }

        internal void BindOutcomeScript(TransportOutcomeScript script)
        {
            if (script == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (_retired || _episode == null || _episode.HasStarted || _held != null || _outcomes != null)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            TransportOutcomeScript.OutcomeKind[] outcomes = script.CopyOutcomes();
            int[] increments = script.CopyByteIncrements();
            int planned = 0;
            for (int index = 0; index < outcomes.Length; index++)
            {
                if (outcomes[index] == TransportOutcomeScript.OutcomeKind.KnownShortWriteIncrement)
                {
                    if (increments[index] >= FrameLength - planned)
                    {
                        throw BrokerLifecycleFailure.Argument("argument:range");
                    }
                    planned += increments[index];
                }
            }
            _outcomes = outcomes;
            _increments = increments;
        }

        internal TransportOutcomeScript.OutcomeKind[] CopyConsumedOutcomes()
        {
            return _consumed.ToArray();
        }

        internal bool TryConsumeFailure(out bool byteCountKnown)
        {
            byteCountKnown = false;
            if (_retired || _outcomes == null || _cursor == _outcomes.Length)
            {
                return false;
            }
            TransportOutcomeScript.OutcomeKind next = _outcomes[_cursor];
            if (next != TransportOutcomeScript.OutcomeKind.IndeterminateWrite && next != TransportOutcomeScript.OutcomeKind.FaultedWrite)
            {
                return false;
            }
            byteCountKnown = next == TransportOutcomeScript.OutcomeKind.FaultedWrite;
            _episode.BeginAttempt();
            Consume();
            return true;
        }

        internal int AdvanceBytes(IBoundedDuplexTransport transport)
        {
            bool scripted = _outcomes != null && _cursor < _outcomes.Length &&
                _outcomes[_cursor] == TransportOutcomeScript.OutcomeKind.KnownShortWriteIncrement;
            int requested = scripted ? _increments[_cursor] : FrameLength - _episode.Offset;
            if (scripted && transport.WritableBytes < requested)
            {
                return 0;
            }
            int written = _episode.Advance(transport, requested);
            if (scripted && written != 0)
            {
                if (written != requested)
                {
                    throw BrokerLifecycleFailure.Reject("transport:indeterminate-write");
                }
                Consume();
            }
            return written;
        }

        internal bool HoldPreparedCompletion(WriteCompletion completion)
        {
            if (_outcomes != null && _cursor < _outcomes.Length &&
                _outcomes[_cursor] == TransportOutcomeScript.OutcomeKind.DelayCompletionDelivery)
            {
                Consume();
                _held = completion;
                return true;
            }
            return false;
        }

        internal bool SignalAbort()
        {
            if (_retired || _abortSignaled)
            {
                return false;
            }
            _abortSignaled = true;
            return true;
        }

        internal void Retire(string reason)
        {
            if (_retired)
            {
                return;
            }
            _retired = true;
            _retirementReason = reason;
            if (_outcomes != null)
            {
                _cursor = _outcomes.Length;
            }
            _lease.Release();
        }

        internal byte[] CopyFrameBytes()
        {
            if (_episode == null)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            return _episode.CopyBytes();
        }

        internal WriteCompletion ClaimHeldCompletion()
        {
            if (_held == null)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            if (!_retired && _outcomes != null && _cursor < _outcomes.Length)
            {
                if (_outcomes[_cursor] != TransportOutcomeScript.OutcomeKind.ForeignGenerationReferenceDelivery)
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:state");
                }
                Consume();
            }
            WriteCompletion completion = _held;
            _held = null;
            return completion;
        }

        private void Consume()
        {
            _consumed.Add(_outcomes[_cursor++]);
        }

        internal sealed class WriteCompletion
        {
            private readonly PendingTransportOperation _operation;
            private readonly TransportOperationStatus _status;
            private readonly bool _byteCountKnown;
            private readonly int _byteIncrement;
            private readonly int _totalCopiedBytes;
            private readonly DispatchLease _deliveryLease;
            private int _deliveryRetired;

            internal WriteCompletion(PendingTransportOperation operation, TransportOperationStatus status,
                bool byteCountKnown, int byteIncrement, int totalCopiedBytes, DispatchLease deliveryLease)
            {
                _operation = operation;
                _status = status;
                _byteCountKnown = byteCountKnown;
                _byteIncrement = byteIncrement;
                _totalCopiedBytes = totalCopiedBytes;
                _deliveryLease = deliveryLease;
                Interlocked.Increment(ref operation._deliveryCount);
            }

            internal RunGenerationId Generation { get { return _operation.Generation; } }
            internal PendingTransportOperation Operation { get { return _operation; } }
            internal ulong OperationNumber { get { return _operation.OperationNumber; } }
            internal string Channel { get { return _operation.Channel; } }
            internal string Direction { get { return _operation.Direction; } }
            internal TransportOperationStatus Status { get { return _status; } }
            internal bool ByteCountKnown { get { return _byteCountKnown; } }
            internal int ByteIncrement { get { return _byteIncrement; } }
            internal int TotalCopiedBytes { get { return _totalCopiedBytes; } }

            internal void RetireDelivery()
            {
                if (Interlocked.CompareExchange(ref _deliveryRetired, 1, 0) == 0)
                {
                    _deliveryLease.Release();
                    if (Interlocked.Decrement(ref _operation._deliveryCount) < 0)
                    {
                        throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
                    }
                }
            }
        }
    }
}
