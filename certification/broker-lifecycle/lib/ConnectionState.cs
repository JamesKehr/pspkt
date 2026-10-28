using System;
using System.Collections.Generic;
using System.Numerics;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class ConnectionState
    {
        private readonly string _channel;
        private readonly Dictionary<string, DirectionLedger> _directions = new Dictionary<string, DirectionLedger>(StringComparer.Ordinal);
        private readonly List<DecodedControlFrame> _brokerBootstrap = new List<DecodedControlFrame>();
        private BrokerHelloProgress _brokerProgress;
        private LocalHelloProgress _localProgress;
        private ConnectionPhase _phase = ConnectionPhase.TransportNotOpened;

        internal ConnectionState(string channel)
        {
            _channel = channel;
            if (channel == "BrokerControl")
            {
                _directions.Add("HostToBroker", new DirectionLedger());
                _directions.Add("BrokerToHost", new DirectionLedger());
                _brokerProgress = BrokerHelloProgress.BrokerBootstrapNotStarted;
            }
            else if (channel == "LocalIpc")
            {
                _directions.Add("WorkerToBroker", new DirectionLedger());
                _directions.Add("BrokerToWorker", new DirectionLedger());
                _brokerProgress = BrokerHelloProgress.BrokerBootstrapNotApplicableToRole;
            }
            else
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            _localProgress = LocalHelloProgress.LocalBootstrapNotStarted;
        }

        internal BrokerHelloProgress BrokerProgress
        {
            get { return _brokerProgress; }
        }

        internal string Channel
        {
            get { return _channel; }
        }

        internal LocalHelloProgress LocalProgress
        {
            get { return _localProgress; }
        }

        internal ConnectionPhase Phase
        {
            get { return _phase; }
        }

        internal uint AbortWakeCount(string direction)
        {
            return Direction(direction).AbortWakes;
        }

        internal ulong FullFrameBytes(string direction)
        {
            return Direction(direction).FullBytes;
        }

        internal ulong LastSequence(string direction)
        {
            return Direction(direction).LastSequence;
        }

        internal uint RecordCount(string direction)
        {
            return Direction(direction).Records;
        }

        internal ulong WrapperBytes(string direction)
        {
            return Direction(direction).WrapperBytes;
        }

        internal bool IsTerminal(string direction)
        {
            return Direction(direction).Terminal;
        }

        internal void Terminalize(string direction)
        {
            Direction(direction).Terminal = true;
        }

        internal void RecordAbortWake(string direction)
        {
            DirectionLedger ledger = Direction(direction);
            if (ledger.AbortWakes == uint.MaxValue)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
            }
            ledger.AbortWakes++;
        }

        internal void SetPhase(ConnectionPhase phase)
        {
            if (_phase == ConnectionPhase.TransportClosedUnverified && phase != _phase)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            _phase = phase;
        }

        internal void Observe(DecodedControlFrame frame)
        {
            ValidateAdmission(frame, 0);
            ValidateCardinality(frame, 0);
            DirectionLedger ledger = Direction(frame.Direction);
            ulong full = frame.PayloadLength + (ulong)FrameCodec.FrameOverhead;
            uint records;
            ulong fullBytes;
            ulong wrapperBytes;
            try
            {
                records = checked(ledger.Records + 1);
                fullBytes = checked(ledger.FullBytes + full);
                wrapperBytes = checked(ledger.WrapperBytes + full + TranscriptCodec.RecordOverhead);
            }
            catch (OverflowException)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
            if (_channel == "LocalIpc")
            {
                ValidateLocalQuota(records, fullBytes, wrapperBytes);
            }
            else
            {
                ValidateBrokerQuota(records, wrapperBytes, ledger.OrdinaryRecords + (frame.Owner.Authority.IsOrdinary(frame) ? 1UL : 0UL),
                    ledger.OrdinaryWrapperBytes + (frame.Owner.Authority.IsOrdinary(frame) ? full + TranscriptCodec.RecordOverhead : 0));
            }
            ledger.LastSequence = frame.Sequence;
            ledger.Records = records;
            ledger.FullBytes = fullBytes;
            ledger.WrapperBytes = wrapperBytes;
            if (frame.Kind == 4372 || frame.Kind == 4626)
            {
                ledger.Keepalives++;
            }
            if (frame.Kind == 4373 || frame.Kind == 4627)
            {
                ledger.Failures++;
                ledger.Terminal = true;
            }
            if (frame.Owner.Authority.IsOrdinary(frame))
            {
                ledger.OrdinaryRecords++;
                ledger.OrdinaryWrapperBytes += full + TranscriptCodec.RecordOverhead;
            }
            if (_channel == "BrokerControl" && frame.Kind >= 4353 && frame.Kind <= 4355)
            {
                _brokerBootstrap.Add(frame);
            }
            else if (frame.Kind == 4356)
            {
                _brokerBootstrap.Clear();
            }
            switch (frame.Kind)
            {
                case 4353: _brokerProgress = BrokerHelloProgress.BrokerHelloObservedUnverified; break;
                case 4354: _brokerProgress = BrokerHelloProgress.BrokerHostHelloObservedUnverified; break;
                case 4355: _brokerProgress = BrokerHelloProgress.BrokerContextObservedUnverified; break;
                case 4356: _brokerProgress = BrokerHelloProgress.BrokerBootstrapObservedUnverified; break;
                case 4609: _localProgress = LocalHelloProgress.LocalWorkerHelloObservedUnverified; break;
                case 4610: _localProgress = LocalHelloProgress.LocalBootstrapObservedUnverified; break;
            }
            if (_phase < ConnectionPhase.TransportDrainingUnverified)
            {
                if (frame.Kind == 4356 || frame.Kind == 4610)
                {
                    _phase = ConnectionPhase.BootstrapObservedUnverified;
                }
                else if (frame.Sequence != 0 && frame.Kind != 4373 && frame.Kind != 4627)
                {
                    _phase = ConnectionPhase.ApplicationObservedUnverified;
                }
            }
        }

        internal void ValidateQuota(DecodedControlFrame frame, int pendingFrames, ulong pendingFullBytes,
            int pendingOrdinaryRecords, ulong pendingOrdinaryWrapperBytes)
        {
            DirectionLedger ledger = Direction(frame.Direction);
            ulong records = (ulong)ledger.Records + (ulong)pendingFrames + 1;
            ulong full = ledger.FullBytes + pendingFullBytes + frame.PayloadLength + (ulong)FrameCodec.FrameOverhead;
            ulong wrapped = full + records * TranscriptCodec.RecordOverhead;
            if (_channel == "LocalIpc")
            {
                ValidateLocalQuota(records, full, wrapped);
            }
            else
            {
                bool ordinary = frame.Owner.Authority.IsOrdinary(frame);
                ValidateBrokerQuota(records, wrapped,
                    ledger.OrdinaryRecords + (ulong)pendingOrdinaryRecords + (ordinary ? 1UL : 0UL),
                    ledger.OrdinaryWrapperBytes + pendingOrdinaryWrapperBytes +
                    (ordinary ? frame.PayloadLength + (ulong)FrameCodec.FrameOverhead + TranscriptCodec.RecordOverhead : 0));
            }
        }

        internal void ValidateCardinality(DecodedControlFrame frame, int pendingSameKind)
        {
            DirectionLedger ledger = Direction(frame.Direction);
            if ((frame.Kind == 4372 && (ulong)ledger.Keepalives + (ulong)pendingSameKind >= LifecyclePolicy.MaximumBrokerKeepalives) ||
                (frame.Kind == 4626 && (ulong)ledger.Keepalives + (ulong)pendingSameKind >= LifecyclePolicy.MaximumLocalKeepalives) ||
                ((frame.Kind == 4373 || frame.Kind == 4627) && (ulong)ledger.Failures + (ulong)pendingSameKind >= 1))
            {
                throw BrokerLifecycleFailure.Reject("quota:per-kind");
            }
        }

        internal void ValidateAdmission(DecodedControlFrame frame, int pendingFrames)
        {
            DirectionLedger ledger = Direction(frame.Direction);
            if (ledger.Terminal)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:traffic-after-terminal");
            }
            bool broker = _channel == "BrokerControl";
            bool bootstrap = broker ? frame.Kind >= 4353 && frame.Kind <= 4356 : frame.Kind == 4609 || frame.Kind == 4610;
            bool complete = broker ? _brokerProgress == BrokerHelloProgress.BrokerBootstrapObservedUnverified :
                _localProgress == LocalHelloProgress.LocalBootstrapObservedUnverified;
            if (!complete)
            {
                if (!bootstrap)
                {
                    throw BrokerLifecycleFailure.Reject("context:bootstrap-incomplete");
                }
                ushort expectedKind;
                string expectedDirection;
                if (broker)
                {
                    expectedKind = (ushort)(4353 + (int)_brokerProgress - 1);
                    expectedDirection = expectedKind == 4354 ? "HostToBroker" : "BrokerToHost";
                }
                else
                {
                    expectedKind = _localProgress == LocalHelloProgress.LocalBootstrapNotStarted ? (ushort)4609 : (ushort)4610;
                    expectedDirection = expectedKind == 4609 ? "WorkerToBroker" : "BrokerToWorker";
                }
                if (frame.Kind != expectedKind || frame.Direction != expectedDirection)
                {
                    throw BrokerLifecycleFailure.Reject("context:ordering");
                }
                if (frame.Sequence != 0)
                {
                    throw BrokerLifecycleFailure.Reject("context:sequence");
                }
                if (pendingFrames != 0)
                {
                    throw BrokerLifecycleFailure.Reject("quota:per-kind");
                }
                if (frame.Kind == 4356)
                {
                    if (_brokerBootstrap.Count != 3 ||
                        BrokerLifecycleFailure.Hex(frame.Owner.ComputeBootstrapBrokerFinishedDigest(_brokerBootstrap.ToArray())) !=
                        BrokerLifecycleFailure.Hex(frame.CopyField(1)))
                    {
                        throw BrokerLifecycleFailure.Reject("context:binding-shape");
                    }
                }
                return;
            }
            if (bootstrap)
            {
                throw BrokerLifecycleFailure.Reject("context:ordering");
            }
            BigInteger expected = new BigInteger(ledger.LastSequence) + pendingFrames + 1;
            if (expected > ulong.MaxValue || new BigInteger(frame.Sequence) != expected)
            {
                throw BrokerLifecycleFailure.Reject("context:sequence");
            }
        }

        internal void RetireRetainedFrames()
        {
            _brokerBootstrap.Clear();
        }

        internal static void ValidateLocalQuota(ulong recordCount, ulong fullFrameBytes, ulong wrapperInclusiveBytes)
        {
            if (recordCount > LifecyclePolicy.MaximumLocalRecords)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
            if (fullFrameBytes > LifecyclePolicy.MaximumLocalFullBytes)
            {
                throw BrokerLifecycleFailure.Reject("quota:full-frame-bytes");
            }
            if (wrapperInclusiveBytes > LifecyclePolicy.MaximumLocalWrapperBytes)
            {
                throw BrokerLifecycleFailure.Reject("quota:wrapper-bytes");
            }
            if (new BigInteger(wrapperInclusiveBytes) !=
                new BigInteger(fullFrameBytes) + new BigInteger(recordCount) * TranscriptCodec.RecordOverhead)
            {
                throw BrokerLifecycleFailure.Reject("quota:counter-consistency");
            }
        }

        private static void ValidateBrokerQuota(ulong records, ulong wrapperBytes, ulong ordinaryRecords, ulong ordinaryWrapperBytes)
        {
            if (records > LifecyclePolicy.MaximumBrokerRecords)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
            if (wrapperBytes > LifecyclePolicy.MaximumBrokerWrapperBytes)
            {
                throw BrokerLifecycleFailure.Reject("quota:wrapper-bytes");
            }
            if (ordinaryRecords > LifecyclePolicy.MaximumBrokerOrdinaryRecords ||
                ordinaryWrapperBytes > LifecyclePolicy.MaximumBrokerOrdinaryWrapperBytes)
            {
                throw BrokerLifecycleFailure.Reject("quota:ordinary");
            }
        }

        private DirectionLedger Direction(string direction)
        {
            DirectionLedger ledger;
            if (!_directions.TryGetValue(direction, out ledger))
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            return ledger;
        }

        private sealed class DirectionLedger
        {
            internal uint AbortWakes;
            internal ulong FullBytes;
            internal ulong LastSequence;
            internal uint Records;
            internal ulong WrapperBytes;
            internal bool Terminal;
            internal uint Keepalives;
            internal uint Failures;
            internal ulong OrdinaryRecords;
            internal ulong OrdinaryWrapperBytes;
        }
    }
}
