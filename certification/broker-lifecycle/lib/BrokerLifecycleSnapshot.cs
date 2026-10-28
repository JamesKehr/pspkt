namespace Pspkt.Certification.BrokerLifecycle
{
    public sealed class BrokerLifecycleSnapshot
    {
        private readonly string _role;
        private readonly ulong _generation;
        private readonly string _servicePhase;
        private readonly string _brokerPhase;
        private readonly string _localPhase;
        private readonly string _brokerProgress;
        private readonly string _localProgress;
        private readonly int _dispatchLeases;
        private readonly int _transportOperations;
        private readonly string _primaryReason;
        private readonly bool _cleanupComplete;
        private readonly ulong _hostToBrokerSequence;
        private readonly uint _hostToBrokerRecords;
        private readonly ulong _hostToBrokerFullBytes;
        private readonly ulong _hostToBrokerWrapperBytes;
        private readonly uint _hostToBrokerAbortWakes;
        private readonly ulong _brokerToHostSequence;
        private readonly uint _brokerToHostRecords;
        private readonly ulong _brokerToHostFullBytes;
        private readonly ulong _brokerToHostWrapperBytes;
        private readonly uint _brokerToHostAbortWakes;
        private readonly ulong _workerToBrokerSequence;
        private readonly uint _workerToBrokerRecords;
        private readonly ulong _workerToBrokerFullBytes;
        private readonly ulong _workerToBrokerWrapperBytes;
        private readonly uint _workerToBrokerAbortWakes;
        private readonly ulong _brokerToWorkerSequence;
        private readonly uint _brokerToWorkerRecords;
        private readonly ulong _brokerToWorkerFullBytes;
        private readonly ulong _brokerToWorkerWrapperBytes;
        private readonly uint _brokerToWorkerAbortWakes;

        internal BrokerLifecycleSnapshot(string role, ulong generation, string servicePhase,
            ConnectionState broker, ConnectionState local, int dispatchLeases, int transportOperations,
            string primaryReason, bool cleanupComplete)
        {
            _role = role;
            _generation = generation;
            _servicePhase = servicePhase;
            _brokerPhase = broker == null ? "TransportNotApplicableToRole" : broker.Phase.ToString();
            _localPhase = local.Phase.ToString();
            _brokerProgress = broker == null ? "BrokerBootstrapNotApplicableToRole" : broker.BrokerProgress.ToString();
            _localProgress = local.LocalProgress.ToString();
            _dispatchLeases = dispatchLeases;
            _transportOperations = transportOperations;
            _primaryReason = primaryReason;
            _cleanupComplete = cleanupComplete;
            _hostToBrokerSequence = broker == null ? 0 : broker.LastSequence("HostToBroker");
            _hostToBrokerRecords = broker == null ? 0 : broker.RecordCount("HostToBroker");
            _hostToBrokerFullBytes = broker == null ? 0 : broker.FullFrameBytes("HostToBroker");
            _hostToBrokerWrapperBytes = broker == null ? 0 : broker.WrapperBytes("HostToBroker");
            _hostToBrokerAbortWakes = broker == null ? 0 : broker.AbortWakeCount("HostToBroker");
            _brokerToHostSequence = broker == null ? 0 : broker.LastSequence("BrokerToHost");
            _brokerToHostRecords = broker == null ? 0 : broker.RecordCount("BrokerToHost");
            _brokerToHostFullBytes = broker == null ? 0 : broker.FullFrameBytes("BrokerToHost");
            _brokerToHostWrapperBytes = broker == null ? 0 : broker.WrapperBytes("BrokerToHost");
            _brokerToHostAbortWakes = broker == null ? 0 : broker.AbortWakeCount("BrokerToHost");
            _workerToBrokerSequence = local.LastSequence("WorkerToBroker");
            _workerToBrokerRecords = local.RecordCount("WorkerToBroker");
            _workerToBrokerFullBytes = local.FullFrameBytes("WorkerToBroker");
            _workerToBrokerWrapperBytes = local.WrapperBytes("WorkerToBroker");
            _workerToBrokerAbortWakes = local.AbortWakeCount("WorkerToBroker");
            _brokerToWorkerSequence = local.LastSequence("BrokerToWorker");
            _brokerToWorkerRecords = local.RecordCount("BrokerToWorker");
            _brokerToWorkerFullBytes = local.FullFrameBytes("BrokerToWorker");
            _brokerToWorkerWrapperBytes = local.WrapperBytes("BrokerToWorker");
            _brokerToWorkerAbortWakes = local.AbortWakeCount("BrokerToWorker");
        }

        public string ServiceRole { get { return _role; } }
        public ulong RunGenerationId { get { return _generation; } }
        public string ServicePhase { get { return _servicePhase; } }
        public string TrustCeiling { get { return BrokerLifecycleFailure.TrustCeiling; } }
        public string BrokerConnectionPhase { get { return _brokerPhase; } }
        public string LocalConnectionPhase { get { return _localPhase; } }
        public string BrokerHelloProgress { get { return _brokerProgress; } }
        public string LocalHelloProgress { get { return _localProgress; } }
        public string BrokerTailAuthorityStatus { get { return _role == "Worker" ? "NotApplicableToRole" : LifecyclePolicy.TailAuthorityUnavailable; } }
        public string LocalTailAuthorityStatus { get { return LifecyclePolicy.TailAuthorityUnavailable; } }
        public int OutstandingDispatchLeases { get { return _dispatchLeases; } }
        public int PendingTransportOperations { get { return _transportOperations; } }
        public string PrimaryReasonCode { get { return _primaryReason; } }
        public bool CleanupComplete { get { return _cleanupComplete; } }
        public ulong BrokerControlHostToBrokerLastObservedSequence { get { return _hostToBrokerSequence; } }
        public uint BrokerControlHostToBrokerObservedRecordCount { get { return _hostToBrokerRecords; } }
        public ulong BrokerControlHostToBrokerObservedFullSignedFrameBytes { get { return _hostToBrokerFullBytes; } }
        public ulong BrokerControlHostToBrokerObservedWrapperInclusiveBytes { get { return _hostToBrokerWrapperBytes; } }
        public uint BrokerControlHostToBrokerAbortWakeCount { get { return _hostToBrokerAbortWakes; } }
        public ulong BrokerControlBrokerToHostLastObservedSequence { get { return _brokerToHostSequence; } }
        public uint BrokerControlBrokerToHostObservedRecordCount { get { return _brokerToHostRecords; } }
        public ulong BrokerControlBrokerToHostObservedFullSignedFrameBytes { get { return _brokerToHostFullBytes; } }
        public ulong BrokerControlBrokerToHostObservedWrapperInclusiveBytes { get { return _brokerToHostWrapperBytes; } }
        public uint BrokerControlBrokerToHostAbortWakeCount { get { return _brokerToHostAbortWakes; } }
        public ulong LocalIpcWorkerToBrokerLastObservedSequence { get { return _workerToBrokerSequence; } }
        public uint LocalIpcWorkerToBrokerObservedRecordCount { get { return _workerToBrokerRecords; } }
        public ulong LocalIpcWorkerToBrokerObservedFullSignedFrameBytes { get { return _workerToBrokerFullBytes; } }
        public ulong LocalIpcWorkerToBrokerObservedWrapperInclusiveBytes { get { return _workerToBrokerWrapperBytes; } }
        public uint LocalIpcWorkerToBrokerAbortWakeCount { get { return _workerToBrokerAbortWakes; } }
        public ulong LocalIpcBrokerToWorkerLastObservedSequence { get { return _brokerToWorkerSequence; } }
        public uint LocalIpcBrokerToWorkerObservedRecordCount { get { return _brokerToWorkerRecords; } }
        public ulong LocalIpcBrokerToWorkerObservedFullSignedFrameBytes { get { return _brokerToWorkerFullBytes; } }
        public ulong LocalIpcBrokerToWorkerObservedWrapperInclusiveBytes { get { return _brokerToWorkerWrapperBytes; } }
        public uint LocalIpcBrokerToWorkerAbortWakeCount { get { return _brokerToWorkerAbortWakes; } }
        public string[] UncheckedSemantics { get { return BrokerLifecycleFailure.CopyUncheckedSemantics(); } }
    }
}
