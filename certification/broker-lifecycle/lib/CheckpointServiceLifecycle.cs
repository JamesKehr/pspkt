using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace Pspkt.Certification.BrokerLifecycle
{
    public sealed class CheckpointServiceLifecycle : IDisposable
    {
        private readonly RunGenerationId _generation;
        private readonly BrokerLifecycleProtocol _protocol;
        private readonly ServiceRole _role;
        private readonly ConnectionState _broker;
        private readonly ConnectionState _local;
        private readonly List<ChannelRuntime> _channels = new List<ChannelRuntime>();
        private readonly HashSet<DispatchLease> _leases = new HashSet<DispatchLease>();
        private readonly DeterministicScheduler _scheduler;
        private readonly int _ownerThreadId;
        private StopRequest _stopRequest;
        private bool _stopObserved;
        private bool _admissionOpen;
        private bool _closing;
        private bool _disposed;
        private bool _cleanupComplete;
        private bool _hasTime;
        private int _cleanupStage;
        private int _ownerEntry;
        private ulong _lastNow;
        private ulong _nextOperationNumber;
        private AbsoluteDeadline _setupDeadline;
        private string _primaryReason = string.Empty;
        private ServicePhase _phase = ServicePhase.ControllerCreated;

        private CheckpointServiceLifecycle(BrokerLifecycleProtocol protocol, ServiceRole role)
        {
            _generation = protocol.IssueGeneration();
            _protocol = protocol;
            _role = role;
            _ownerThreadId = Environment.CurrentManagedThreadId;
            _scheduler = new DeterministicScheduler(_generation);
            if (role == ServiceRole.Broker)
            {
                _broker = new ConnectionState("BrokerControl");
                _channels.Add(new ChannelRuntime(_broker, "HostToBroker", "BrokerToHost"));
            }
            _local = new ConnectionState("LocalIpc");
            _channels.Add(new ChannelRuntime(_local,
                role == ServiceRole.Broker ? "WorkerToBroker" : "BrokerToWorker",
                role == ServiceRole.Broker ? "BrokerToWorker" : "WorkerToBroker"));
        }

        public static CheckpointServiceLifecycle CreateInMemory(
            BrokerLifecycleProtocol protocol, string serviceRole, byte[] lifecyclePolicyBytes)
        {
            if (protocol == null || serviceRole == null || lifecyclePolicyBytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            ServiceRole role;
            if (string.Equals(serviceRole, "Broker", StringComparison.Ordinal))
            {
                role = ServiceRole.Broker;
            }
            else if (string.Equals(serviceRole, "Worker", StringComparison.Ordinal))
            {
                role = ServiceRole.Worker;
            }
            else
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            LifecyclePolicy.Admit(lifecyclePolicyBytes);
            return new CheckpointServiceLifecycle(protocol, role);
        }

        public void Start(ulong nowTicks, ulong absoluteDeadlineTicks)
        {
            EnterOwner();
            try
            {
                ValidateTime(nowTicks, absoluteDeadlineTicks);
                RequireNotDisposed();
                if (_phase != ServicePhase.ControllerCreated || _closing)
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:state");
                }
                StampTime(nowTicks);
                _setupDeadline = new AbsoluteDeadline(absoluteDeadlineTicks);
                _phase = ServicePhase.ControllerStarting;
                if (_role == ServiceRole.Broker)
                {
                    _scheduler.Schedule(1);
                }
                _scheduler.Schedule(2);
                _scheduler.Schedule(3);
                if (_role == ServiceRole.Broker)
                {
                    _scheduler.Schedule(4);
                }
                _scheduler.Schedule(5);
            }
            finally
            {
                ExitOwner();
            }
        }

        public void FeedPeerBytes(string channel, byte[] bytes, ulong nowTicks, ulong absoluteDeadlineTicks)
        {
            if (bytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            ChannelRuntime runtime = ResolveChannel(channel);
            if (bytes.Length > LifecyclePolicy.MaximumChunkBytes)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            EnterOwner();
            try
            {
                ValidateTime(nowTicks, absoluteDeadlineTicks);
                RequireNewTraffic(runtime, runtime.Inbound);
                if (runtime.Pair == null || bytes.Length > runtime.Pair.Peer.WritableBytes)
                {
                    throw BrokerLifecycleFailure.Reject("transport:capacity");
                }
                StampTime(nowTicks);
                if (runtime.Assembly == null && runtime.Pair.Local.AvailableBytes == 0 &&
                    (bytes.Length != 0 || runtime.Read == null))
                {
                    runtime.InputDeadline = new AbsoluteDeadline(absoluteDeadlineTicks);
                }
                if (runtime.Read == null)
                {
                    RegisterRead(runtime);
                }
                int written = runtime.Pair.Peer.Write(bytes, 0, bytes.Length);
                if (written != bytes.Length)
                {
                    LatchFault("transport:indeterminate-write");
                    throw BrokerLifecycleFailure.Reject("transport:indeterminate-write");
                }
            }
            finally
            {
                ExitOwner();
            }
        }

        public void QueueFrame(string channel, byte[] completeFrameBytes, ulong nowTicks, ulong absoluteDeadlineTicks)
        {
            if (completeFrameBytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            ChannelRuntime runtime = ResolveChannel(channel);
            if (completeFrameBytes.Length < FrameCodec.FrameOverhead || completeFrameBytes.Length > LifecyclePolicy.MaximumFrameBytes)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            EnterOwner();
            try
            {
                ValidateTime(nowTicks, absoluteDeadlineTicks);
                RequireNewTraffic(runtime, runtime.Outbound);
                InMemoryDuplexTransport.ValidateQueueCapacity(runtime.Writes.Count, runtime.QueuedBytes, completeFrameBytes.Length);
                DecodedControlFrame frame = _protocol.Decode(channel, runtime.Outbound, 2, completeFrameBytes);
                StampTime(nowTicks);
                RequireHandled(frame);
                try
                {
                    int pendingSameKind = 0;
                    int pendingOrdinary = 0;
                    ulong pendingOrdinaryBytes = 0;
                    foreach (FrameWriteEpisode pending in runtime.Writes)
                    {
                        if (pending.Frame.Kind == frame.Kind)
                        {
                            pendingSameKind++;
                        }
                        if (_protocol.Authority.IsOrdinary(pending.Frame))
                        {
                            pendingOrdinary++;
                            pendingOrdinaryBytes += (ulong)pending.Length + TranscriptCodec.RecordOverhead;
                        }
                    }
                    runtime.State.ValidateAdmission(frame, runtime.Writes.Count);
                    runtime.State.ValidateCardinality(frame, pendingSameKind);
                    runtime.State.ValidateQuota(frame, runtime.Writes.Count, runtime.QueuedBytes, pendingOrdinary, pendingOrdinaryBytes);
                }
                catch (InvalidDataException failure)
                {
                    LatchFault(failure.Message);
                    throw;
                }
                FrameWriteEpisode episode = new FrameWriteEpisode(_generation, frame, new AbsoluteDeadline(absoluteDeadlineTicks));
                runtime.Writes.Enqueue(episode);
                runtime.QueuedBytes += (ulong)episode.Length;
            }
            finally
            {
                ExitOwner();
            }
        }

        public byte[] ReadPeerBytes(string channel, int maximumBytes, ulong nowTicks)
        {
            ChannelRuntime runtime = ResolveChannel(channel);
            if (maximumBytes < 1 || maximumBytes > LifecyclePolicy.MaximumChunkBytes)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            EnterOwner();
            try
            {
                ValidateNow(nowTicks);
                StampTime(nowTicks);
                if (runtime.Pair == null || runtime.Pair.Closed)
                {
                    return new byte[0];
                }
                int count = Math.Min(maximumBytes, runtime.Pair.Peer.AvailableBytes);
                byte[] result = new byte[count];
                if (runtime.Pair.Peer.Read(result, 0, count) != count)
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
                }
                return result;
            }
            finally
            {
                ExitOwner();
            }
        }

        public void ObservePeerEof(string channel, ulong nowTicks)
        {
            ChannelRuntime runtime = ResolveChannel(channel);
            EnterOwner();
            try
            {
                ValidateNow(nowTicks);
                if (runtime.Pair == null)
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:state");
                }
                StampTime(nowTicks);
                if (runtime.Pair.Closed)
                {
                    return;
                }
                runtime.Pair.Peer.SignalEof();
                if (_closing && runtime.State.Phase == ConnectionPhase.LocalObservationSealedUnverified &&
                    !HasOutstandingOwnership())
                {
                    return;
                }
                LatchFault("transport:premature-eof");
                throw BrokerLifecycleFailure.Reject("transport:premature-eof");
            }
            finally
            {
                ExitOwner();
            }
        }

        public void Pump(ulong nowTicks, int maximumSteps)
        {
            if (maximumSteps < 1 || maximumSteps > LifecyclePolicy.MaximumSchedulerItems)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            for (int step = 0; step < maximumSteps; step++)
            {
                PendingTransportOperation.WriteCompletion completion = null;
                bool progressed;
                EnterOwner();
                try
                {
                    ValidateNow(nowTicks);
                    RequireNotDisposed();
                    StampTime(nowTicks);
                    try
                    {
                        progressed = Advance(nowTicks, out completion);
                    }
                    catch (InvalidDataException failure)
                    {
                        LatchFault(failure.Message);
                        throw;
                    }
                }
                finally
                {
                    ExitOwner();
                }
                if (completion != null)
                {
                    ApplyWriteCompletion(completion);
                }
                if (!progressed)
                {
                    break;
                }
            }
        }

        public void RequestStop(ulong nowTicks, ulong absoluteDeadlineTicks)
        {
            if (absoluteDeadlineTicks < nowTicks || nowTicks < Volatile.Read(ref _lastNow))
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            StopRequest request = new StopRequest(nowTicks, new AbsoluteDeadline(absoluteDeadlineTicks));
            StopRequest previous = Interlocked.CompareExchange(ref _stopRequest, request, null);
            if (previous != null)
            {
                return;
            }
        }

        public BrokerLifecycleSnapshot GetSnapshot()
        {
            EnterOwner();
            try
            {
                return new BrokerLifecycleSnapshot(_role.ToString(), _generation.Value, _phase.ToString(),
                    _broker, _local, _leases.Count, PendingOperationCount(), _primaryReason, _cleanupComplete);
            }
            finally
            {
                ExitOwner();
            }
        }

        public void Dispose()
        {
            EnterOwner();
            try
            {
                if (_disposed)
                {
                    return;
                }
                if (!_cleanupComplete && (_phase != ServicePhase.ControllerCreated || HasOutstandingOwnership()))
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:dispose-before-quiescence");
                }
                _disposed = true;
                _cleanupComplete = true;
                if (_primaryReason.Length == 0)
                {
                    _phase = ServicePhase.ControllerStoppedUnverified;
                }
            }
            finally
            {
                ExitOwner();
            }
        }

        internal void EnterOwner()
        {
            if (Environment.CurrentManagedThreadId != _ownerThreadId ||
                Interlocked.CompareExchange(ref _ownerEntry, 1, 0) != 0)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:concurrent-entry");
            }
        }

        internal void ExitOwner()
        {
            if (Interlocked.Exchange(ref _ownerEntry, 0) != 1)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
            }
        }

        internal PendingTransportOperation GetPendingWrite(string channel)
        {
            if (Volatile.Read(ref _ownerEntry) != 1 || Environment.CurrentManagedThreadId != _ownerThreadId)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:concurrent-entry");
            }
            PendingTransportOperation operation = ResolveChannel(channel).Write;
            if (operation == null || operation.Retired || !_admissionOpen ||
                operation.Deadline.IsExpired(_lastNow) || ResolveChannel(channel).State.IsTerminal(operation.Direction))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            return operation;
        }

        internal void ApplyWriteCompletion(PendingTransportOperation.WriteCompletion completion)
        {
            EnterOwner();
            try
            {
                ChannelRuntime runtime = ResolveChannel(completion.Channel);
                RunGenerationId currentGeneration = _generation;
                PendingTransportOperation registeredOperation = runtime.Write;
                if (registeredOperation != null &&
                    (registeredOperation.OperationNumber != completion.OperationNumber ||
                        registeredOperation.Direction != completion.Direction))
                {
                    registeredOperation = null;
                }
                if (!object.ReferenceEquals(completion.Generation, currentGeneration) ||
                    !object.ReferenceEquals(completion.Generation.OwnerIdentity, currentGeneration.OwnerIdentity) ||
                    (registeredOperation != null &&
                     !object.ReferenceEquals(completion.Operation, registeredOperation)))
                {
                    throw new System.IO.InvalidDataException("lifecycle:stale-generation");
                }
                if (registeredOperation == null || registeredOperation.Retired)
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:state");
                }
                if (EffectiveDeadline(registeredOperation.Deadline).IsExpired(_lastNow) ||
                    completion.Status == TransportOperationStatus.TimedOut)
                {
                    FailWrite(runtime, "transport:deadline");
                    throw BrokerLifecycleFailure.Reject("transport:deadline");
                }
                if (completion.Status != TransportOperationStatus.Completed || !completion.ByteCountKnown ||
                    completion.TotalCopiedBytes != registeredOperation.FrameLength ||
                    registeredOperation.Episode.Offset != registeredOperation.FrameLength)
                {
                    FailWrite(runtime, "transport:indeterminate-write");
                    throw BrokerLifecycleFailure.Reject("transport:indeterminate-write");
                }
                DecodedControlFrame observed = registeredOperation.Episode.Frame;
                runtime.State.Observe(observed);
                RetireWrite(runtime, string.Empty);
                if (IsFailureFrame(observed))
                {
                    LatchFault("lifecycle:local-failure-emitted");
                }
            }
            finally
            {
                completion.RetireDelivery();
                ExitOwner();
            }
        }

        internal void ReleaseDispatchLease(DispatchLease lease)
        {
            bool entered = false;
            if (Volatile.Read(ref _ownerEntry) == 0)
            {
                EnterOwner();
                entered = true;
            }
            try
            {
                if (Environment.CurrentManagedThreadId != _ownerThreadId ||
                    !object.ReferenceEquals(lease.Generation, _generation) || !_leases.Remove(lease))
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
                }
            }
            finally
            {
                if (entered)
                {
                    ExitOwner();
                }
            }
        }

        private bool Advance(ulong now, out PendingTransportOperation.WriteCompletion completion)
        {
            completion = null;
            StopRequest stop = Volatile.Read(ref _stopRequest);
            if (stop != null && !_stopObserved)
            {
                if (now < stop.PublishedAt)
                {
                    throw BrokerLifecycleFailure.Argument("argument:range");
                }
                _stopObserved = true;
                if (stop.Deadline.IsExpired(now) && _primaryReason.Length == 0)
                {
                    LatchFault("transport:deadline");
                    throw BrokerLifecycleFailure.Reject("transport:deadline");
                }
                if (_primaryReason.Length == 0)
                {
                    _phase = ServicePhase.ControllerStopRequested;
                }
                return true;
            }
            if (_stopObserved && !_closing)
            {
                if (_broker != null && ResolveChannel("BrokerControl").Pair != null)
                {
                    LatchFault("lifecycle:base-broker-terminal-unavailable");
                }
                else
                {
                    BeginClosing();
                }
                return true;
            }
            if (_closing)
            {
                return AdvanceClosing(now, out completion);
            }
            int work;
            if (_scheduler.TryTake(_generation, out work))
            {
                if (_setupDeadline.IsExpired(now))
                {
                    LatchFault("transport:deadline");
                    throw BrokerLifecycleFailure.Reject("transport:deadline");
                }
                if (work == 1 || work == 2)
                {
                    ChannelRuntime runtime = ResolveChannel(work == 1 ? "BrokerControl" : "LocalIpc");
                    runtime.Pair = new DuplexTransportPair(_generation);
                    runtime.InputDeadline = _setupDeadline;
                    runtime.State.SetPhase(ConnectionPhase.TransportOpenUnverified);
                }
                else if (work == 3)
                {
                    _admissionOpen = true;
                    _phase = ServicePhase.ControllerActiveUnverified;
                }
                else
                {
                    RegisterRead(ResolveChannel(work == 4 ? "BrokerControl" : "LocalIpc"));
                }
                return true;
            }
            foreach (ChannelRuntime runtime in _channels)
            {
                if (runtime.Pair == null)
                {
                    continue;
                }
                if (runtime.Read != null && runtime.Read.Deadline.Earlier(runtime.InputDeadline).IsExpired(now))
                {
                    RetireRead(runtime, "transport:deadline");
                    LatchFault("transport:deadline");
                    throw BrokerLifecycleFailure.Reject("transport:deadline");
                }
                if (runtime.Pair.Local.AvailableBytes != 0)
                {
                    if (runtime.Read == null)
                    {
                        RegisterRead(runtime);
                        return true;
                    }
                    return AdvanceRead(runtime);
                }
                if (runtime.Write == null && runtime.Writes.Count != 0)
                {
                    RegisterWrite(runtime);
                    return true;
                }
                if (runtime.Write != null)
                {
                    if (AdvanceWrite(runtime, now, out completion))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private bool AdvanceRead(ChannelRuntime runtime)
        {
            if (runtime.Assembly == null)
            {
                runtime.Assembly = new byte[FrameCodec.HeaderBytes];
                runtime.AssembledBytes = 0;
            }
            int count = Math.Min(runtime.Pair.Local.AvailableBytes, runtime.Assembly.Length - runtime.AssembledBytes);
            int read = runtime.Pair.Local.Read(runtime.Assembly, runtime.AssembledBytes, count);
            runtime.AssembledBytes += read;
            if (runtime.AssembledBytes != runtime.Assembly.Length)
            {
                return read != 0;
            }
            if (runtime.Assembly.Length == FrameCodec.HeaderBytes)
            {
                int length = FrameCodec.CompleteLengthFromHeader(runtime.Assembly);
                byte[] complete = new byte[length];
                Buffer.BlockCopy(runtime.Assembly, 0, complete, 0, runtime.Assembly.Length);
                runtime.Assembly = complete;
                return true;
            }
            RequireNewTraffic(runtime, runtime.Inbound);
            DecodedControlFrame frame = _protocol.Decode(runtime.State.Channel, runtime.Inbound, 2, runtime.Assembly);
            RequireHandled(frame);
            runtime.State.Observe(frame);
            RetireRead(runtime, string.Empty);
            if (IsFailureFrame(frame))
            {
                LatchFault("lifecycle:peer-failure-observed");
                if (runtime.Pair.Local.AvailableBytes != 0)
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:traffic-after-terminal");
                }
            }
            return true;
        }

        private bool AdvanceWrite(ChannelRuntime runtime, ulong now, out PendingTransportOperation.WriteCompletion completion)
        {
            completion = null;
            PendingTransportOperation operation = runtime.Write;
            if (EffectiveDeadline(operation.Deadline).IsExpired(now))
            {
                completion = new PendingTransportOperation.WriteCompletion(operation, TransportOperationStatus.TimedOut,
                    true, 0, operation.Episode.Offset, AcquireDispatchLease());
                return true;
            }
            bool byteCountKnown;
            if (operation.HasHeldCompletion)
            {
                if (operation.TryConsumeFailure(out byteCountKnown))
                {
                    completion = new PendingTransportOperation.WriteCompletion(operation, TransportOperationStatus.Faulted,
                        byteCountKnown, 0, operation.Episode.Offset, AcquireDispatchLease());
                    return true;
                }
                return false;
            }
            if (runtime.Pair.Local.WritableBytes != 0 && operation.TryConsumeFailure(out byteCountKnown))
            {
                completion = new PendingTransportOperation.WriteCompletion(operation, TransportOperationStatus.Faulted,
                    byteCountKnown, 0, operation.Episode.Offset, AcquireDispatchLease());
                return true;
            }
            int increment = operation.AdvanceBytes(runtime.Pair.Local);
            if (increment == 0)
            {
                return false;
            }
            if (operation.Episode.Offset == operation.FrameLength)
            {
                completion = new PendingTransportOperation.WriteCompletion(operation, TransportOperationStatus.Completed,
                    true, increment, operation.Episode.Offset, AcquireDispatchLease());
                if (operation.HoldPreparedCompletion(completion))
                {
                    completion = null;
                }
            }
            return true;
        }

        private bool AdvanceClosing(ulong now, out PendingTransportOperation.WriteCompletion completion)
        {
            completion = null;
            int ignored;
            if (_scheduler.TryTake(_generation, out ignored))
            {
                return true;
            }
            foreach (ChannelRuntime runtime in _channels)
            {
                if (runtime.Read != null)
                {
                    RetireRead(runtime, "lifecycle:state");
                    return true;
                }
                if (runtime.Write != null)
                {
                    if (AdvanceWrite(runtime, now, out completion))
                    {
                        return true;
                    }
                }
            }
            if (PendingOperationCount() != 0)
            {
                return false;
            }
            StopRequest stop = Volatile.Read(ref _stopRequest);
            if (!_cleanupComplete && _primaryReason.Length == 0 && stop != null && stop.Deadline.IsExpired(now))
            {
                LatchFault("transport:deadline");
                throw BrokerLifecycleFailure.Reject("transport:deadline");
            }
            if (_cleanupStage == 0)
            {
                foreach (ChannelRuntime runtime in _channels)
                {
                    runtime.State.RetireRetainedFrames();
                }
                ChannelRuntime local = ResolveChannel("LocalIpc");
                if (local.Pair != null)
                {
                    local.State.SetPhase(ConnectionPhase.LocalObservationSealedUnverified);
                }
                _cleanupStage = 1;
                return true;
            }
            if (HasOutstandingOwnership())
            {
                return false;
            }
            if (!_cleanupComplete)
            {
                foreach (ChannelRuntime runtime in _channels)
                {
                    if (runtime.Pair != null)
                    {
                        runtime.Pair.Close();
                        runtime.State.SetPhase(ConnectionPhase.TransportClosedUnverified);
                    }
                }
                _cleanupComplete = true;
                if (_primaryReason.Length == 0)
                {
                    _phase = ServicePhase.ControllerStoppedUnverified;
                }
                return true;
            }
            return false;
        }

        private void BeginClosing()
        {
            if (_closing)
            {
                return;
            }
            _closing = true;
            _admissionOpen = false;
            _cleanupComplete = false;
            if (_primaryReason.Length == 0)
            {
                _phase = ServicePhase.ControllerQuiescing;
            }
            foreach (ChannelRuntime runtime in _channels)
            {
                if (runtime.Pair != null && !runtime.Pair.Closed)
                {
                    runtime.State.SetPhase(ConnectionPhase.TransportDrainingUnverified);
                }
                if (runtime.Read != null && runtime.Read.SignalAbort())
                {
                    runtime.State.RecordAbortWake(runtime.Inbound);
                }
                if (runtime.Write != null && runtime.Write.SignalAbort())
                {
                    runtime.State.RecordAbortWake(runtime.Outbound);
                }
                int queued = runtime.Writes.Count;
                for (int index = 0; index < queued; index++)
                {
                    FrameWriteEpisode episode = runtime.Writes.Dequeue();
                    if (episode.HasStarted)
                    {
                        runtime.Writes.Enqueue(episode);
                    }
                    else
                    {
                        if (runtime.Write != null && object.ReferenceEquals(runtime.Write.Episode, episode))
                        {
                            runtime.Write.Retire("lifecycle:state");
                            runtime.Write = null;
                        }
                        episode.Retire("lifecycle:state");
                        runtime.QueuedBytes -= (ulong)episode.Length;
                    }
                }
            }
        }

        private void FailWrite(ChannelRuntime runtime, string reason)
        {
            bool started = runtime.Write.Episode.HasStarted;
            RetireWrite(runtime, reason);
            if (started)
            {
                runtime.State.Terminalize(runtime.Outbound);
            }
            LatchFault(reason);
        }

        private void LatchFault(string reason)
        {
            if (_primaryReason.Length == 0)
            {
                _primaryReason = BrokerLifecycleFailure.Reject(reason).Message;
            }
            _phase = ServicePhase.ControllerFaultedUnverified;
            BeginClosing();
        }

        private void RegisterRead(ChannelRuntime runtime)
        {
            if (runtime.Read != null)
            {
                return;
            }
            runtime.Read = new PendingTransportOperation(_generation, 0, runtime.State.Channel, runtime.Inbound,
                runtime.InputDeadline, null, AcquireDispatchLease());
        }

        private void RegisterWrite(ChannelRuntime runtime)
        {
            if (_nextOperationNumber == ulong.MaxValue)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
            }
            FrameWriteEpisode episode = runtime.Writes.Peek();
            runtime.Write = new PendingTransportOperation(_generation, ++_nextOperationNumber, runtime.State.Channel,
                runtime.Outbound, episode.Deadline, episode, AcquireDispatchLease());
        }

        private void RetireRead(ChannelRuntime runtime, string reason)
        {
            if (runtime.Read != null)
            {
                runtime.Read.Retire(reason);
                runtime.Read = null;
            }
            runtime.Assembly = null;
            runtime.AssembledBytes = 0;
        }

        private void RetireWrite(ChannelRuntime runtime, string reason)
        {
            PendingTransportOperation operation = runtime.Write;
            if (operation == null || runtime.Writes.Count == 0 ||
                !object.ReferenceEquals(runtime.Writes.Peek(), operation.Episode))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
            }
            operation.Retire(reason);
            runtime.Writes.Dequeue();
            runtime.QueuedBytes -= (ulong)operation.FrameLength;
            operation.Episode.Retire(reason);
            runtime.Write = null;
        }

        private DispatchLease AcquireDispatchLease()
        {
            if (_leases.Count >= LifecyclePolicy.MaximumDispatchLeases)
            {
                throw BrokerLifecycleFailure.Reject("transport:capacity");
            }
            DispatchLease lease = new DispatchLease(this, _generation);
            if (!_leases.Add(lease))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:lease-invariant");
            }
            return lease;
        }

        private AbsoluteDeadline EffectiveDeadline(AbsoluteDeadline original)
        {
            StopRequest stop = Volatile.Read(ref _stopRequest);
            return _stopObserved && stop != null ? original.Earlier(stop.Deadline) : original;
        }

        private bool HasOutstandingOwnership()
        {
            if (_leases.Count != 0 || _scheduler.Count != 0 || PendingOperationCount() != 0)
            {
                return true;
            }
            foreach (ChannelRuntime runtime in _channels)
            {
                if (runtime.Writes.Count != 0 || runtime.QueuedBytes != 0 || runtime.Assembly != null)
                {
                    return true;
                }
            }
            return false;
        }

        private int PendingOperationCount()
        {
            int count = 0;
            foreach (ChannelRuntime runtime in _channels)
            {
                if (runtime.Read != null && !runtime.Read.Retired)
                {
                    count++;
                }
                if (runtime.Write != null && !runtime.Write.Retired)
                {
                    count++;
                }
            }
            return count;
        }

        private ChannelRuntime ResolveChannel(string channel)
        {
            if (channel == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            foreach (ChannelRuntime runtime in _channels)
            {
                if (string.Equals(runtime.State.Channel, channel, StringComparison.Ordinal))
                {
                    return runtime;
                }
            }
            throw BrokerLifecycleFailure.Argument("argument:context");
        }

        private void RequireNewTraffic(ChannelRuntime runtime, string direction)
        {
            if (runtime.State.IsTerminal(direction))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:traffic-after-terminal");
            }
            if (!_admissionOpen)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
        }

        private static bool IsFailureFrame(DecodedControlFrame frame)
        {
            return frame.Kind == 4373 || frame.Kind == 4627;
        }

        private void RequireHandled(DecodedControlFrame frame)
        {
            switch (frame.Kind)
            {
                case 4353: case 4354: case 4355: case 4356: case 4372: case 4373:
                case 4609: case 4610: case 4626: case 4627:
                    return;
                default:
                    LatchFault("lifecycle:dispatch-out-of-scope");
                    throw BrokerLifecycleFailure.Reject("lifecycle:dispatch-out-of-scope");
            }
        }

        private void RequireNotDisposed()
        {
            if (_disposed)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:disposed");
            }
        }

        private void ValidateNow(ulong now)
        {
            StopRequest stop = Volatile.Read(ref _stopRequest);
            if ((_hasTime && now < _lastNow) || (stop != null && now < stop.PublishedAt))
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
        }

        private void ValidateTime(ulong now, ulong deadline)
        {
            ValidateNow(now);
            if (deadline < now)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
        }

        private void StampTime(ulong now)
        {
            Volatile.Write(ref _lastNow, now);
            _hasTime = true;
        }

        private sealed class StopRequest
        {
            internal readonly ulong PublishedAt;
            internal readonly AbsoluteDeadline Deadline;

            internal StopRequest(ulong now, AbsoluteDeadline deadline)
            {
                PublishedAt = now;
                Deadline = deadline;
            }
        }

        private sealed class ChannelRuntime
        {
            internal readonly ConnectionState State;
            internal readonly string Inbound;
            internal readonly string Outbound;
            internal readonly Queue<FrameWriteEpisode> Writes = new Queue<FrameWriteEpisode>();
            internal DuplexTransportPair Pair;
            internal PendingTransportOperation Read;
            internal PendingTransportOperation Write;
            internal AbsoluteDeadline InputDeadline;
            internal ulong QueuedBytes;
            internal byte[] Assembly;
            internal int AssembledBytes;

            internal ChannelRuntime(ConnectionState state, string inbound, string outbound)
            {
                State = state;
                Inbound = inbound;
                Outbound = outbound;
            }
        }
    }
}
