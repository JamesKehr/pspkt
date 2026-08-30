using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Pspkt.Certification
{
    public enum ProcessLaunchRole
    {
        CompatibilityRun = 0,
        SchemaChild = 1,
        GateProbeChild = 2,
        PauseReleaseChild = 3,
        GateMissingChild = 4,
        GateWrongNameChild = 5,
        GateTimeoutChild = 6,
        GateDelayedSignalChild = 7,
        AssignmentFailureChild = 8,
        WatchdogChild = 9,
        DescendantHangChild = 10,
        OverflowChild = 11,
        ParentLossLauncher = 12,
        ParentLossProbeChild = 13,
        PostAssignmentLauncher = 14,
        PostAssignmentProbeChild = 15,
        Worker = 16,
        PrelaunchProbe = 17,
        FailFastProbe = 18,
        NestedCapabilityChild = 19,
        WorkerLeavesDescendantChild = 20,
        GeneratorHost = 21
    }

    public enum PreNativeRejectReason
    {
        CombinedSeam = 0,
        Basic = 1,
        EventName = 2,
        EmptyCorrelation = 3,
        PauseConfig = 4,
        Environment = 5
    }

    public enum PauseReason
    {
        AckTimeout = 1,
        ReleaseTimeout = 2,
        EventFailure = 3,
        IdentityFailure = 4,
        WaitFailure = 5,
        MembershipFailure = 6
    }

    public enum LauncherKind
    {
        CompatibilityRun = 0,
        TypedRun = 1,
        ContainedValidatorWorker = 2,
        ContainedProbe = 3,
        HelperDirectLaunch = 4,
        ContainedGeneratorHost = 5
    }

    public enum EventAccessMode
    {
        WaitOnly = 1,
        SetOnly = 2,
        WaitAndSet = 3
    }

    public enum ProbeEventDaclKind
    {
        SynchronizeOnly = 1,
        ModifyStateOnly = 2
    }

    public enum EventRole
    {
        Generic = 0,
        Gate = 1,
        Readiness = 2,
        ObserverAck = 3,
        ReleaseWaitArmed = 4,
        Release = 5,
        WaiterReady = 6,
        MembershipReady = 7,
        SupervisorGate = 8,
        NestedReady = 9,
        NestedRelease = 10,
        NestedEvidenceReady = 11,
        NestedReleaseAuthorized = 12,
        NestedChildExited = 13,
        NestedProofComplete = 14,
        Descendant = 15,
        DescendantWaiterReady = 16,
        Probe = 17,
        WorkerTimeoutReady = 18
    }

    public enum NativeWaitStatus
    {
        Object0 = 0,
        Timeout = 1,
        Abandoned = 2,
        Failed = 3,
        Other = 4
    }

    public enum ContainedWorkerScenario
    {
        Normal = 0,
        SimulateAssignFailure = 1,
        ResumeFailureZero = 2,
        ResumeFailureNative = 3,
        ResumeFailureMultiple = 4,
        WorkerGateTimeout = 5,
        WorkerGateOpenFailure = 6,
        WorkerTimeout = 7,
        WorkerLeavesDescendant = 8,
        WorkerNonzeroExit = 9,
        MalformedWorkerResult = 10
    }

    internal enum WorkerResultMutation
    {
        NonceMismatch = 0,
        VersionMismatch = 1,
        MissingCheck = 2,
        UnknownCheck = 3,
        DuplicateCheck = 4,
        OutOfOrderCheck = 5,
        SkipStatus = 6,
        FailStatus = 7,
        BadOrdinal = 8,
        BadSummaryCount = 9,
        BadSummaryStatus = 10,
        MissingSummary = 11,
        ExtraBytes = 12,
        Oversize = 13,
        MalformedUtf8 = 14,
        Bom = 15
    }

    public enum GeneratorScenario
    {
        Normal = 0,
        ContainedFalse = 1,
        GateWithheld = 2
    }

    public enum ContainedWorkerState
    {
        Created = 0,
        StartedSuspended = 1,
        Assigned = 2,
        Resumed = 3,
        ResumeFailed = 4,
        Released = 5,
        Failed = 6,
        Exited = 7,
        Cleaned = 8
    }

    public enum HostPackagingKind
    {
        Unpackaged = 0,
        Packaged = 1
    }

    public sealed class InvalidPreAssignmentConfigurationException : Exception
    {
        public InvalidPreAssignmentConfigurationException(string message) : base(message) { }
        public InvalidPreAssignmentConfigurationException(string message, Exception inner) : base(message, inner) { }
    }

    public sealed class ProcessLaunchConfigurationException : Exception
    {
        private readonly ProcessLaunchRole _role;

        public ProcessLaunchConfigurationException(ProcessLaunchRole role, string message) : base(message)
        {
            _role = role;
        }

        public ProcessLaunchRole Role { get { return _role; } }
    }

    public sealed class EventNameGrammarException : Exception
    {
        private readonly string _eventName;

        public EventNameGrammarException(string eventName, string message) : base(message)
        {
            _eventName = eventName;
        }

        public string EventName { get { return _eventName; } }
    }

    public sealed class CorrelationIdRequiredException : Exception
    {
        public CorrelationIdRequiredException(string message) : base(message) { }
    }

    public sealed class InvalidPauseConfigurationException : Exception
    {
        public InvalidPauseConfigurationException(string message) : base(message) { }
    }

    public sealed class EnvironmentConfigurationException : Exception
    {
        private readonly string _offendingName;

        public EnvironmentConfigurationException(string offendingName, string message) : base(message)
        {
            _offendingName = offendingName;
        }

        public string OffendingName { get { return _offendingName; } }
    }

    internal sealed class NativeCommandLineException : Exception
    {
        internal NativeCommandLineException(string message) : base(message) { }
    }

    internal sealed class LaunchPathIdentityException : Exception
    {
        private readonly string _path;

        internal LaunchPathIdentityException(string path, string message) : base(message)
        {
            _path = path;
        }

        internal LaunchPathIdentityException(string path, string message, Exception inner) : base(message, inner)
        {
            _path = path;
        }

        public string Path { get { return _path; } }
    }

    internal sealed class ReceiptGrammarException : Exception
    {
        private readonly string _leaf;

        internal ReceiptGrammarException(string leaf, string message) : base(message)
        {
            _leaf = leaf;
        }

        public string Leaf { get { return _leaf; } }
    }

    internal sealed class ChildTerminationException : Exception
    {
        private readonly int _childProcessId;

        internal ChildTerminationException(int childProcessId, string message) : base(message)
        {
            _childProcessId = childProcessId;
        }

        internal ChildTerminationException(int childProcessId, string message, Exception inner) : base(message, inner)
        {
            _childProcessId = childProcessId;
        }

        public int ChildProcessId { get { return _childProcessId; } }
    }

    internal sealed class NestedMembershipException : Exception
    {
        private readonly int _childProcessId;
        private readonly bool _observedMembership;

        internal NestedMembershipException(int childProcessId, bool observedMembership, string message) : base(message)
        {
            _childProcessId = childProcessId;
            _observedMembership = observedMembership;
        }

        public int ChildProcessId { get { return _childProcessId; } }
        public bool ObservedMembership { get { return _observedMembership; } }
    }

    public sealed class EventSquatException : Exception
    {
        private readonly string _eventName;
        private readonly int _win32Error;

        public EventSquatException(string eventName, int win32Error, string message) : base(message)
        {
            _eventName = eventName;
            _win32Error = win32Error;
        }

        public string EventName { get { return _eventName; } }
        public int Win32Error { get { return _win32Error; } }
    }

    public sealed class EventOpenException : Exception
    {
        private readonly string _eventName;
        private readonly int _win32Error;

        public EventOpenException(string eventName, int win32Error, string message) : base(message)
        {
            _eventName = eventName;
            _win32Error = win32Error;
        }

        public string EventName { get { return _eventName; } }
        public int Win32Error { get { return _win32Error; } }
    }

    internal sealed class NativeWaitException : Exception
    {
        private readonly int _win32Error;

        internal NativeWaitException(int win32Error, string message) : base(message)
        {
            _win32Error = win32Error;
        }

        public int Win32Error { get { return _win32Error; } }
    }

    internal sealed class ContainedWorkerException : Exception
    {
        internal ContainedWorkerException(string message) : base(message) { }
        internal ContainedWorkerException(string message, Exception inner) : base(message, inner) { }
    }

    internal sealed class ContainedLaunchOwnershipQuarantinedException : Exception
    {
        internal ContainedLaunchOwnershipQuarantinedException(string message) : base(message) { }
    }

    internal sealed class ContainedWorkerStateException : Exception
    {
        internal ContainedWorkerStateException(string message) : base(message) { }
    }

    internal sealed class UnsupportedCertificationHostException : Exception
    {
        internal UnsupportedCertificationHostException(string message) : base(message) { }
    }

    public sealed class PreAssignmentPauseException : Exception
    {
        private readonly int _childProcessId;
        private readonly long _childStartTimeFileTimeUtc;
        private readonly PauseReason _pauseReason;
        private readonly Exception _primaryCause;

        public PreAssignmentPauseException(PauseReason pauseReason, int childProcessId, long childStartTimeFileTimeUtc, string message)
            : base(message)
        {
            _pauseReason = pauseReason;
            _childProcessId = childProcessId;
            _childStartTimeFileTimeUtc = childStartTimeFileTimeUtc;
            _primaryCause = null;
        }

        public PreAssignmentPauseException(PauseReason pauseReason, int childProcessId, long childStartTimeFileTimeUtc, string message, Exception cause)
            : base(message, cause)
        {
            _pauseReason = pauseReason;
            _childProcessId = childProcessId;
            _childStartTimeFileTimeUtc = childStartTimeFileTimeUtc;
            _primaryCause = cause;
        }

        public PreAssignmentPauseException(PauseReason pauseReason, int childProcessId, long childStartTimeFileTimeUtc, Exception primaryCause, Exception inner)
            : base(BuildMessage(pauseReason, childProcessId), inner)
        {
            _pauseReason = pauseReason;
            _childProcessId = childProcessId;
            _childStartTimeFileTimeUtc = childStartTimeFileTimeUtc;
            _primaryCause = primaryCause;
        }

        private static string BuildMessage(PauseReason pauseReason, int childProcessId)
        {
            return "pre-assignment pause failed (" + pauseReason.ToString() + ") for child " + childProcessId.ToString(CultureInfo.InvariantCulture) + ".";
        }

        public int ChildProcessId { get { return _childProcessId; } }
        public long ChildStartTimeFileTimeUtc { get { return _childStartTimeFileTimeUtc; } }
        public PauseReason PauseReason { get { return _pauseReason; } }
        public Exception PrimaryCause { get { return _primaryCause; } }
    }

    public sealed class PostAssignmentEvidenceException : Exception
    {
        private readonly int _childProcessId;
        private readonly long _childStartTimeFileTimeUtc;
        private readonly Guid _correlationId;
        private readonly Exception _evidenceCause;
        private readonly Exception _primaryCause;

        public PostAssignmentEvidenceException(int childProcessId, long childStartTimeFileTimeUtc, Guid correlationId, Exception evidenceCause)
            : base(BuildMessage(childProcessId, correlationId), evidenceCause)
        {
            _childProcessId = childProcessId;
            _childStartTimeFileTimeUtc = childStartTimeFileTimeUtc;
            _correlationId = correlationId;
            _evidenceCause = evidenceCause;
            _primaryCause = null;
        }

        public PostAssignmentEvidenceException(int childProcessId, long childStartTimeFileTimeUtc, Guid correlationId, Exception evidenceCause, Exception primaryCause, Exception inner)
            : base(BuildMessage(childProcessId, correlationId), inner)
        {
            _childProcessId = childProcessId;
            _childStartTimeFileTimeUtc = childStartTimeFileTimeUtc;
            _correlationId = correlationId;
            _evidenceCause = evidenceCause;
            _primaryCause = primaryCause;
        }

        private static string BuildMessage(int childProcessId, Guid correlationId)
        {
            return "post-assignment evidence write failed for child " + childProcessId.ToString(CultureInfo.InvariantCulture) + " correlation " + correlationId.ToString("N") + ".";
        }

        public int ChildProcessId { get { return _childProcessId; } }
        public long ChildStartTimeFileTimeUtc { get { return _childStartTimeFileTimeUtc; } }
        public Guid CorrelationId { get { return _correlationId; } }
        public Exception EvidenceCause { get { return _evidenceCause; } }
        public Exception PrimaryCause { get { return _primaryCause; } }
    }

    public sealed class PauseConfiguration
    {
        private readonly Guid _correlationId;
        private readonly string _identityDirectory;
        private readonly string _readinessEventName;
        private readonly string _observerAckEventName;
        private readonly string _releaseWaitArmedEventName;
        private readonly string _releaseEventName;
        private readonly int _ackTimeoutMilliseconds;
        private readonly int _releaseTimeoutMilliseconds;

        public PauseConfiguration(
            Guid correlationId,
            string identityDirectory,
            string readinessEventName,
            string observerAckEventName,
            string releaseWaitArmedEventName,
            string releaseEventName,
            int ackTimeoutMilliseconds,
            int releaseTimeoutMilliseconds)
        {
            _correlationId = correlationId;
            _identityDirectory = identityDirectory;
            _readinessEventName = readinessEventName;
            _observerAckEventName = observerAckEventName;
            _releaseWaitArmedEventName = releaseWaitArmedEventName;
            _releaseEventName = releaseEventName;
            _ackTimeoutMilliseconds = ackTimeoutMilliseconds;
            _releaseTimeoutMilliseconds = releaseTimeoutMilliseconds;
        }

        public Guid CorrelationId { get { return _correlationId; } }
        public string IdentityDirectory { get { return _identityDirectory; } }
        public string ReadinessEventName { get { return _readinessEventName; } }
        public string ObserverAckEventName { get { return _observerAckEventName; } }
        public string ReleaseWaitArmedEventName { get { return _releaseWaitArmedEventName; } }
        public string ReleaseEventName { get { return _releaseEventName; } }
        public int AckTimeoutMilliseconds { get { return _ackTimeoutMilliseconds; } }
        public int ReleaseTimeoutMilliseconds { get { return _releaseTimeoutMilliseconds; } }
    }

    public sealed class ProbeEvidence
    {
        private readonly string _evidenceDirectory;
        private readonly Guid _correlationId;

        public ProbeEvidence(string evidenceDirectory, Guid correlationId)
        {
            _evidenceDirectory = evidenceDirectory;
            _correlationId = correlationId;
        }

        public string EvidenceDirectory { get { return _evidenceDirectory; } }
        public Guid CorrelationId { get { return _correlationId; } }
    }

    public sealed class ParentLossMembership
    {
        private readonly string _parentNonce;
        private readonly string _receiptRoot;
        private readonly string _receiptLeaf;
        private readonly string _membershipReadyEventName;
        private readonly Guid _correlationId;

        public ParentLossMembership(
            string parentNonce,
            string receiptRoot,
            string receiptLeaf,
            string membershipReadyEventName,
            Guid correlationId)
        {
            _parentNonce = parentNonce;
            _receiptRoot = receiptRoot;
            _receiptLeaf = receiptLeaf;
            _membershipReadyEventName = membershipReadyEventName;
            _correlationId = correlationId;
        }

        public string ParentNonce { get { return _parentNonce; } }
        public string ReceiptRoot { get { return _receiptRoot; } }
        public string ReceiptLeaf { get { return _receiptLeaf; } }
        public string MembershipReadyEventName { get { return _membershipReadyEventName; } }
        public Guid CorrelationId { get { return _correlationId; } }
    }

    public sealed class NestedProof
    {
        private readonly string _nonce;
        private readonly string _controlRoot;
        private readonly Guid _correlationId;
        private readonly string _nestedEvidenceReadyEventName;
        private readonly string _nestedReadyEventName;
        private readonly string _nestedReleaseEventName;

        public NestedProof(
            string nonce,
            string controlRoot,
            Guid correlationId,
            string nestedEvidenceReadyEventName,
            string nestedReadyEventName,
            string nestedReleaseEventName)
        {
            _nonce = nonce;
            _controlRoot = controlRoot;
            _correlationId = correlationId;
            _nestedEvidenceReadyEventName = nestedEvidenceReadyEventName;
            _nestedReadyEventName = nestedReadyEventName;
            _nestedReleaseEventName = nestedReleaseEventName;
        }

        public string Nonce { get { return _nonce; } }
        public string ControlRoot { get { return _controlRoot; } }
        public Guid CorrelationId { get { return _correlationId; } }
        public string NestedEvidenceReadyEventName { get { return _nestedEvidenceReadyEventName; } }
        public string NestedReadyEventName { get { return _nestedReadyEventName; } }
        public string NestedReleaseEventName { get { return _nestedReleaseEventName; } }
    }

    public sealed class GeneratorBinding
    {
        private readonly GeneratorScenario _scenario;
        private readonly string _bootstrapScriptPath;
        private readonly string _generatorScriptPath;

        public GeneratorBinding(GeneratorScenario scenario, string generatorScriptPath)
            : this(scenario, null, generatorScriptPath)
        {
        }

        public GeneratorBinding(GeneratorScenario scenario, string bootstrapScriptPath, string generatorScriptPath)
        {
            _scenario = scenario;
            _bootstrapScriptPath = bootstrapScriptPath;
            _generatorScriptPath = generatorScriptPath;
        }

        public GeneratorScenario Scenario { get { return _scenario; } }
        public string BootstrapScriptPath { get { return _bootstrapScriptPath; } }
        public string GeneratorScriptPath { get { return _generatorScriptPath; } }
    }

    public sealed class ProcessLaunchConfiguration
    {
        private readonly ProcessLaunchRole _role;
        private readonly bool _typed;
        private readonly string _executablePath;
        private readonly string[] _arguments;
        private readonly string _gateEventName;
        private readonly string _gateEnvironmentVariable;
        private readonly string[] _extraEnvironmentNames;
        private readonly string[] _extraEnvironmentValues;
        private readonly string[] _reservedEnvironmentNames;
        private readonly string[] _reservedEnvironmentValues;
        private readonly int _waitTimeoutMilliseconds;
        private readonly int _terminateGraceMilliseconds;
        private readonly int _drainDeadlineMilliseconds;
        private readonly int _retainCapBytes;
        private readonly bool _simulateAssignFailure;
        private readonly Guid _correlationId;
        private readonly string _workingDirectory;
        private readonly PauseConfiguration _pauseConfiguration;
        private readonly ProbeEvidence _probeEvidence;
        private readonly ParentLossMembership _parentLossMembership;
        private readonly NestedProof _nestedProof;
        private readonly GeneratorBinding _generatorBinding;

        internal ProcessLaunchConfiguration(
            ProcessLaunchRole role,
            bool typed,
            string executablePath,
            string[] arguments,
            string gateEventName,
            string gateEnvironmentVariable,
            string[] extraEnvironmentNames,
            string[] extraEnvironmentValues,
            string[] reservedEnvironmentNames,
            string[] reservedEnvironmentValues,
            int waitTimeoutMilliseconds,
            int terminateGraceMilliseconds,
            int drainDeadlineMilliseconds,
            int retainCapBytes,
            bool simulateAssignFailure,
            Guid correlationId,
            string workingDirectory,
            PauseConfiguration pauseConfiguration,
            ProbeEvidence probeEvidence,
            ParentLossMembership parentLossMembership,
            NestedProof nestedProof,
            GeneratorBinding generatorBinding)
        {
            _role = role;
            _typed = typed;
            _executablePath = executablePath;
            _arguments = CloneOrNull(arguments);
            _gateEventName = gateEventName;
            _gateEnvironmentVariable = gateEnvironmentVariable;
            _extraEnvironmentNames = CloneOrNull(extraEnvironmentNames);
            _extraEnvironmentValues = CloneOrNull(extraEnvironmentValues);
            _reservedEnvironmentNames = CloneOrNull(reservedEnvironmentNames);
            _reservedEnvironmentValues = CloneOrNull(reservedEnvironmentValues);
            _waitTimeoutMilliseconds = waitTimeoutMilliseconds;
            _terminateGraceMilliseconds = terminateGraceMilliseconds;
            _drainDeadlineMilliseconds = drainDeadlineMilliseconds;
            _retainCapBytes = retainCapBytes;
            _simulateAssignFailure = simulateAssignFailure;
            _correlationId = correlationId;
            _workingDirectory = workingDirectory;
            _pauseConfiguration = pauseConfiguration;
            _probeEvidence = probeEvidence;
            _parentLossMembership = parentLossMembership;
            _nestedProof = nestedProof;
            _generatorBinding = generatorBinding;
        }

        private static string[] CloneOrNull(string[] source)
        {
            if (source == null)
            {
                return null;
            }
            string[] copy = new string[source.Length];
            Array.Copy(source, copy, source.Length);
            return copy;
        }

        public ProcessLaunchRole Role { get { return _role; } }
        public bool IsTypedLaunch { get { return _typed; } }
        public string ExecutablePath { get { return _executablePath; } }
        public string[] Arguments { get { return CloneOrNull(_arguments); } }
        public string GateEventName { get { return _gateEventName; } }
        public string GateEnvironmentVariable { get { return _gateEnvironmentVariable; } }
        public string[] ExtraEnvironmentNames { get { return CloneOrNull(_extraEnvironmentNames); } }
        public string[] ExtraEnvironmentValues { get { return CloneOrNull(_extraEnvironmentValues); } }
        public string[] ReservedEnvironmentNames { get { return CloneOrNull(_reservedEnvironmentNames); } }
        public string[] ReservedEnvironmentValues { get { return CloneOrNull(_reservedEnvironmentValues); } }
        public int WaitTimeoutMilliseconds { get { return _waitTimeoutMilliseconds; } }
        public int TerminateGraceMilliseconds { get { return _terminateGraceMilliseconds; } }
        public int DrainDeadlineMilliseconds { get { return _drainDeadlineMilliseconds; } }
        public int RetainCapBytes { get { return _retainCapBytes; } }
        public bool SimulateAssignFailure { get { return _simulateAssignFailure; } }
        public Guid CorrelationId { get { return _correlationId; } }
        public string WorkingDirectory { get { return _workingDirectory; } }
        public PauseConfiguration PauseConfiguration { get { return _pauseConfiguration; } }
        public ProbeEvidence ProbeEvidence { get { return _probeEvidence; } }
        public ParentLossMembership ParentLossMembership { get { return _parentLossMembership; } }
        public NestedProof NestedProof { get { return _nestedProof; } }
        public GeneratorBinding GeneratorBinding { get { return _generatorBinding; } }

        internal string[] ArgumentsInternal { get { return _arguments; } }
        internal string[] ExtraEnvironmentNamesInternal { get { return _extraEnvironmentNames; } }
        internal string[] ExtraEnvironmentValuesInternal { get { return _extraEnvironmentValues; } }
        internal string[] ReservedEnvironmentNamesInternal { get { return _reservedEnvironmentNames; } }
        internal string[] ReservedEnvironmentValuesInternal { get { return _reservedEnvironmentValues; } }
    }

    public sealed class AccessLogEntry
    {
        private readonly long _sequence;
        private readonly Guid _correlationId;
        private readonly EventRole _role;
        private readonly string _eventName;
        private readonly uint _desiredAccess;

        internal AccessLogEntry(long sequence, Guid correlationId, EventRole role, string eventName, uint desiredAccess)
        {
            _sequence = sequence;
            _correlationId = correlationId;
            _role = role;
            _eventName = eventName;
            _desiredAccess = desiredAccess;
        }

        public long Sequence { get { return _sequence; } }
        public Guid CorrelationId { get { return _correlationId; } }
        public EventRole Role { get { return _role; } }
        public string EventName { get { return _eventName; } }
        public uint DesiredAccess { get { return _desiredAccess; } }
    }

    public sealed class BoundedProcessDiagnosticsSnapshot
    {
        private readonly long _jobCreate;
        private readonly long _eventCreate;
        private readonly long _eventOpen;
        private readonly long _processStart;
        private readonly long _assignmentAttempt;
        private readonly long _rejectCombinedSeam;
        private readonly long _rejectBasic;
        private readonly long _rejectEventName;
        private readonly long _rejectEmptyCorrelation;
        private readonly long _rejectPauseConfig;
        private readonly long _rejectEnvironment;
        private readonly long _accessLogHighWater;
        private readonly bool _accessLogOverflow;
        private readonly long _snapshotAccess;
        private readonly long _pathIdentityReject;
        private readonly int _pendingManagedSessionCount;
        private readonly int _quarantinedLaunchCount;
        private readonly AccessLogEntry[] _entries;

        internal BoundedProcessDiagnosticsSnapshot(
            long jobCreate, long eventCreate, long eventOpen, long processStart, long assignmentAttempt,
            long rejectCombinedSeam, long rejectBasic, long rejectEventName, long rejectEmptyCorrelation,
            long rejectPauseConfig, long rejectEnvironment, long accessLogHighWater, bool accessLogOverflow,
            long snapshotAccess, long pathIdentityReject, int pendingManagedSessionCount,
            int quarantinedLaunchCount, AccessLogEntry[] entries)
        {
            _jobCreate = jobCreate;
            _eventCreate = eventCreate;
            _eventOpen = eventOpen;
            _processStart = processStart;
            _assignmentAttempt = assignmentAttempt;
            _rejectCombinedSeam = rejectCombinedSeam;
            _rejectBasic = rejectBasic;
            _rejectEventName = rejectEventName;
            _rejectEmptyCorrelation = rejectEmptyCorrelation;
            _rejectPauseConfig = rejectPauseConfig;
            _rejectEnvironment = rejectEnvironment;
            _accessLogHighWater = accessLogHighWater;
            _accessLogOverflow = accessLogOverflow;
            _snapshotAccess = snapshotAccess;
            _pathIdentityReject = pathIdentityReject;
            _pendingManagedSessionCount = pendingManagedSessionCount;
            _quarantinedLaunchCount = quarantinedLaunchCount;
            _entries = entries;
        }

        public long JobCreateCount { get { return _jobCreate; } }
        public long EventCreateCount { get { return _eventCreate; } }
        public long EventOpenCount { get { return _eventOpen; } }
        public long ProcessStartCount { get { return _processStart; } }
        public long AssignmentAttemptCount { get { return _assignmentAttempt; } }
        public long RejectCombinedSeamCount { get { return _rejectCombinedSeam; } }
        public long RejectBasicCount { get { return _rejectBasic; } }
        public long RejectEventNameCount { get { return _rejectEventName; } }
        public long RejectEmptyCorrelationCount { get { return _rejectEmptyCorrelation; } }
        public long RejectPauseConfigCount { get { return _rejectPauseConfig; } }
        public long RejectEnvironmentCount { get { return _rejectEnvironment; } }
        public long AccessLogHighWater { get { return _accessLogHighWater; } }
        public bool AccessLogOverflow { get { return _accessLogOverflow; } }
        public long SnapshotAccessCount { get { return _snapshotAccess; } }
        public long PathIdentityRejectCount { get { return _pathIdentityReject; } }
        public int PendingManagedSessionCount { get { return _pendingManagedSessionCount; } }
        public int QuarantinedLaunchCount { get { return _quarantinedLaunchCount; } }

        public AccessLogEntry[] GetEntries()
        {
            AccessLogEntry[] copy = new AccessLogEntry[_entries.Length];
            Array.Copy(_entries, copy, _entries.Length);
            return copy;
        }

        public long CountFor(PreNativeRejectReason reason)
        {
            switch (reason)
            {
                case PreNativeRejectReason.CombinedSeam: return _rejectCombinedSeam;
                case PreNativeRejectReason.Basic: return _rejectBasic;
                case PreNativeRejectReason.EventName: return _rejectEventName;
                case PreNativeRejectReason.EmptyCorrelation: return _rejectEmptyCorrelation;
                case PreNativeRejectReason.PauseConfig: return _rejectPauseConfig;
                case PreNativeRejectReason.Environment: return _rejectEnvironment;
                default: throw new ArgumentOutOfRangeException("reason");
            }
        }
    }

    public sealed class ResumeFailureOutcome
    {
        private readonly uint _resumeReturn;
        private readonly int _nativeResumeInvocationCount;
        private readonly int _lastWin32Error;
        private readonly bool _gateSignaled;
        private readonly int _activeProcesses;

        internal ResumeFailureOutcome(uint resumeReturn, int nativeResumeInvocationCount, int lastWin32Error, bool gateSignaled, int activeProcesses)
        {
            _resumeReturn = resumeReturn;
            _nativeResumeInvocationCount = nativeResumeInvocationCount;
            _lastWin32Error = lastWin32Error;
            _gateSignaled = gateSignaled;
            _activeProcesses = activeProcesses;
        }

        public uint ResumeReturn { get { return _resumeReturn; } }
        public int NativeResumeInvocationCount { get { return _nativeResumeInvocationCount; } }
        public int LastWin32Error { get { return _lastWin32Error; } }
        public bool GateSignaled { get { return _gateSignaled; } }
        public int ActiveProcesses { get { return _activeProcesses; } }
    }

    public sealed class ContainedWorkerLaunchDiagnostic
    {
        private readonly ContainedWorkerScenario _scenario;
        private readonly ProcessLaunchRole _role;
        private readonly bool _isGeneratorHost;
        private readonly GeneratorScenario _generatorScenario;
        private readonly string _commandLine;
        private readonly int _processId;
        private readonly long _startTimeFileTimeUtc;
        private readonly bool _membershipVerified;
        private readonly bool _assignFailed;

        internal ContainedWorkerLaunchDiagnostic(
            ContainedWorkerScenario scenario,
            ProcessLaunchRole role,
            bool isGeneratorHost,
            GeneratorScenario generatorScenario,
            string commandLine,
            int processId,
            long startTimeFileTimeUtc,
            bool membershipVerified,
            bool assignFailed)
        {
            _scenario = scenario;
            _role = role;
            _isGeneratorHost = isGeneratorHost;
            _generatorScenario = generatorScenario;
            _commandLine = commandLine;
            _processId = processId;
            _startTimeFileTimeUtc = startTimeFileTimeUtc;
            _membershipVerified = membershipVerified;
            _assignFailed = assignFailed;
        }

        public ContainedWorkerScenario Scenario { get { return _scenario; } }
        public ProcessLaunchRole Role { get { return _role; } }
        public bool IsGeneratorHost { get { return _isGeneratorHost; } }
        public GeneratorScenario GeneratorScenario { get { return _generatorScenario; } }
        public string CommandLine { get { return _commandLine; } }
        public int ProcessId { get { return _processId; } }
        public long StartTimeFileTimeUtc { get { return _startTimeFileTimeUtc; } }
        public bool MembershipVerified { get { return _membershipVerified; } }
        public bool AssignFailed { get { return _assignFailed; } }
    }

    public sealed class ContainedProbeResult
    {
        private readonly int _processId;
        private readonly long _startTimeFileTimeUtc;
        private readonly bool _exited;
        private readonly int _exitCode;
        private readonly bool _timedOut;
        private readonly long _activeProcessesAfter;

        internal ContainedProbeResult(int processId, long startTimeFileTimeUtc, bool exited, int exitCode, bool timedOut, long activeProcessesAfter)
        {
            _processId = processId;
            _startTimeFileTimeUtc = startTimeFileTimeUtc;
            _exited = exited;
            _exitCode = exitCode;
            _timedOut = timedOut;
            _activeProcessesAfter = activeProcessesAfter;
        }

        public int ProcessId { get { return _processId; } }
        public long StartTimeFileTimeUtc { get { return _startTimeFileTimeUtc; } }
        public bool Exited { get { return _exited; } }
        public int ExitCode { get { return _exitCode; } }
        public bool TimedOut { get { return _timedOut; } }
        public long ActiveProcessesAfter { get { return _activeProcessesAfter; } }
    }

    public sealed class PreNativeRejectProbeResult
    {
        private readonly string _probeId;
        private readonly PreNativeRejectReason _expectedReason;
        private readonly string _observedExceptionTypeName;
        private readonly long _elapsedMilliseconds;
        private readonly BoundedProcessDiagnosticsSnapshot _before;
        private readonly BoundedProcessDiagnosticsSnapshot _after;

        internal PreNativeRejectProbeResult(
            string probeId,
            PreNativeRejectReason expectedReason,
            string observedExceptionTypeName,
            long elapsedMilliseconds,
            BoundedProcessDiagnosticsSnapshot before,
            BoundedProcessDiagnosticsSnapshot after)
        {
            _probeId = probeId;
            _expectedReason = expectedReason;
            _observedExceptionTypeName = observedExceptionTypeName;
            _elapsedMilliseconds = elapsedMilliseconds;
            _before = before;
            _after = after;
        }

        public string ProbeId { get { return _probeId; } }
        public PreNativeRejectReason ExpectedReason { get { return _expectedReason; } }
        public string ObservedExceptionTypeName { get { return _observedExceptionTypeName; } }
        public long ElapsedMilliseconds { get { return _elapsedMilliseconds; } }
        public BoundedProcessDiagnosticsSnapshot Before { get { return _before; } }
        public BoundedProcessDiagnosticsSnapshot After { get { return _after; } }
    }

    public sealed class DrainerProbeResult
    {
        private readonly int _stream1Disposals;
        private readonly int _stream2Disposals;
        private readonly bool _thread1Started;
        private readonly bool _thread2Started;
        private readonly bool _thread1Joined;
        private readonly bool _thread2Joined;
        private readonly bool _drainCompleted;
        private readonly bool _anyThreadAliveAfter;
        private readonly long _snapshotAccessBefore;
        private readonly long _snapshotAccessAfter;
        private readonly bool _forcedClose;
        private readonly string _injectedStartFailureTypeName;

        internal DrainerProbeResult(
            int stream1Disposals, int stream2Disposals, bool thread1Started, bool thread2Started,
            bool thread1Joined, bool thread2Joined, bool drainCompleted, bool anyThreadAliveAfter,
            long snapshotAccessBefore, long snapshotAccessAfter, bool forcedClose, string injectedStartFailureTypeName)
        {
            _stream1Disposals = stream1Disposals;
            _stream2Disposals = stream2Disposals;
            _thread1Started = thread1Started;
            _thread2Started = thread2Started;
            _thread1Joined = thread1Joined;
            _thread2Joined = thread2Joined;
            _drainCompleted = drainCompleted;
            _anyThreadAliveAfter = anyThreadAliveAfter;
            _snapshotAccessBefore = snapshotAccessBefore;
            _snapshotAccessAfter = snapshotAccessAfter;
            _forcedClose = forcedClose;
            _injectedStartFailureTypeName = injectedStartFailureTypeName;
        }

        public int Stream1Disposals { get { return _stream1Disposals; } }
        public int Stream2Disposals { get { return _stream2Disposals; } }
        public bool Thread1Started { get { return _thread1Started; } }
        public bool Thread2Started { get { return _thread2Started; } }
        public bool Thread1Joined { get { return _thread1Joined; } }
        public bool Thread2Joined { get { return _thread2Joined; } }
        public bool DrainCompleted { get { return _drainCompleted; } }
        public bool AnyThreadAliveAfter { get { return _anyThreadAliveAfter; } }
        public long SnapshotAccessBefore { get { return _snapshotAccessBefore; } }
        public long SnapshotAccessAfter { get { return _snapshotAccessAfter; } }
        public bool ForcedClose { get { return _forcedClose; } }
        public string InjectedStartFailureTypeName { get { return _injectedStartFailureTypeName; } }
    }

    public sealed class FrozenEnvironmentSnapshot
    {
        private readonly ProcessLaunchRole _role;
        private readonly string[] _names;
        private readonly string[] _values;
        private readonly int _blockLength;
        private readonly bool _runtimeInjectionScrubbed;
        private readonly bool _psModulePathCanonicalized;

        internal FrozenEnvironmentSnapshot(ProcessLaunchRole role, string[] names, string[] values, int blockLength, bool runtimeInjectionScrubbed, bool psModulePathCanonicalized)
        {
            _role = role;
            _names = names;
            _values = values;
            _blockLength = blockLength;
            _runtimeInjectionScrubbed = runtimeInjectionScrubbed;
            _psModulePathCanonicalized = psModulePathCanonicalized;
        }

        public ProcessLaunchRole Role { get { return _role; } }
        public int Count { get { return _names.Length; } }
        public int BlockLength { get { return _blockLength; } }
        public bool RuntimeInjectionScrubbed { get { return _runtimeInjectionScrubbed; } }
        public bool PSModulePathCanonicalized { get { return _psModulePathCanonicalized; } }

        public string[] GetNames()
        {
            string[] copy = new string[_names.Length];
            Array.Copy(_names, copy, _names.Length);
            return copy;
        }

        public string[] GetValues()
        {
            string[] copy = new string[_values.Length];
            Array.Copy(_values, copy, _values.Length);
            return copy;
        }

        public string GetValue(string name)
        {
            for (int index = 0; index < _names.Length; index++)
            {
                if (string.Equals(_names[index], name, StringComparison.OrdinalIgnoreCase))
                {
                    return _values[index];
                }
            }
            return null;
        }

        public bool Contains(string name)
        {
            for (int index = 0; index < _names.Length; index++)
            {
                if (string.Equals(_names[index], name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
    }

    public sealed class LauncherRoleAcceptance
    {
        private readonly LauncherKind _launcher;
        private readonly ProcessLaunchRole _role;
        private readonly bool _accepted;

        internal LauncherRoleAcceptance(LauncherKind launcher, ProcessLaunchRole role, bool accepted)
        {
            _launcher = launcher;
            _role = role;
            _accepted = accepted;
        }

        public LauncherKind Launcher { get { return _launcher; } }
        public ProcessLaunchRole Role { get { return _role; } }
        public bool Accepted { get { return _accepted; } }
    }

    public sealed class DirectLaunchSession : IDisposable
    {
        private const int DisposeTerminateTimeoutMilliseconds = 15000;

        private readonly object _sync = new object();
        private readonly ProcessLaunchRole _role;
        private readonly int _processId;
        private readonly long _startTimeFileTimeUtc;
        private readonly string _commandLine;
        private readonly string _workingDirectory;

        private Process _process;
        private LaunchPathBinding _pathBinding;
        private long _processGeneration;
        private bool _exitCodeKnown;
        private int _exitCode;
        private bool _disposed;

        internal DirectLaunchSession(ProcessLaunchRole role, Process process, int processId, long startTimeFileTimeUtc, string commandLine, string workingDirectory)
        {
            _role = role;
            _process = process;
            _processId = processId;
            _startTimeFileTimeUtc = startTimeFileTimeUtc;
            _commandLine = commandLine;
            _workingDirectory = workingDirectory;
            _processGeneration = 1;
        }

        internal void AttachPathBinding(LaunchPathBinding binding)
        {
            lock (_sync)
            {
                _pathBinding = binding;
            }
        }

        public Exception[] ReleasePathBinding()
        {
            lock (_sync)
            {
                if (_pathBinding == null)
                {
                    return new Exception[0];
                }
                if (_process == null || !_process.HasExited)
                {
                    throw new ContainedWorkerStateException("direct-launch child " + _processId.ToString(CultureInfo.InvariantCulture) + " path binding cannot be released before the process is proven exited.");
                }
                List<Exception> errors = new List<Exception>();
                LaunchPathBinding binding = _pathBinding;
                _pathBinding = null;
                binding.ReleaseAndCleanup(errors);
                return errors.ToArray();
            }
        }

        public ProcessLaunchRole Role { get { return _role; } }
        public int ProcessId { get { return _processId; } }
        public long StartTimeFileTimeUtc { get { return _startTimeFileTimeUtc; } }
        public string CommandLine { get { return _commandLine; } }
        public string WorkingDirectory { get { return _workingDirectory; } }

        public bool HasExited
        {
            get
            {
                lock (_sync)
                {
                    RequireLiveLocked();
                    return _process.HasExited;
                }
            }
        }

        public bool WaitForExit(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            Process process;
            long processGeneration;
            IntPtr retainedProcessHandle;
            lock (_sync)
            {
                RequireLiveLocked();
                process = _process;
                processGeneration = _processGeneration;
                retainedProcessHandle = BoundedProcessHost.DuplicateProcessWaitHandle(process.Handle);
            }

            NativeWaitStatus waitStatus = NativeWaitStatus.Other;
            int exitCode = -1;
            Exception waitFailure = null;
            try
            {
                waitStatus = BoundedProcessHost.WaitForRetainedProcessHandle(
                    retainedProcessHandle,
                    timeoutMilliseconds,
                    _processId,
                    out exitCode);
            }
            catch (Exception error)
            {
                waitFailure = error;
            }
            Exception releaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                ref retainedProcessHandle,
                "direct-launch process");
            if (waitFailure != null || releaseFailure != null)
            {
                throw BoundedProcessHost.ComposeCleanupException(
                    waitFailure,
                    releaseFailure == null ? new Exception[0] : new Exception[] { releaseFailure });
            }

            if (waitStatus == NativeWaitStatus.Object0)
            {
                lock (_sync)
                {
                    if (!_disposed &&
                        _processGeneration == processGeneration &&
                        object.ReferenceEquals(_process, process))
                    {
                        _exitCode = exitCode;
                        _exitCodeKnown = true;
                    }
                }
            }
            return waitStatus == NativeWaitStatus.Object0;
        }

        public int GetExitCode()
        {
            lock (_sync)
            {
                if (!_exitCodeKnown)
                {
                    RequireLiveLocked();
                    if (!_process.HasExited)
                    {
                        throw new ContainedWorkerStateException("direct-launch child " + _processId.ToString(CultureInfo.InvariantCulture) + " has not exited.");
                    }
                    _exitCode = _process.ExitCode;
                    _exitCodeKnown = true;
                }
                return _exitCode;
            }
        }

        public void TerminateAndWait(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            Process process;
            long processGeneration;
            IntPtr retainedProcessHandle;
            Exception terminationFailure = null;
            lock (_sync)
            {
                RequireLiveLocked();
                process = _process;
                processGeneration = _processGeneration;
                retainedProcessHandle = BoundedProcessHost.DuplicateProcessWaitHandle(process.Handle);
                try
                {
                    if (!process.HasExited)
                    {
                        try { process.Kill(); }
                        catch (InvalidOperationException)
                        {
                            if (!process.HasExited) { throw; }
                        }
                        catch (Win32Exception)
                        {
                            if (!process.HasExited) { throw; }
                        }
                    }
                }
                catch (Exception error)
                {
                    terminationFailure = error;
                }
            }

            if (terminationFailure != null)
            {
                Exception releaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                    ref retainedProcessHandle,
                    "direct-launch process");
                throw BoundedProcessHost.ComposeCleanupException(
                    terminationFailure,
                    releaseFailure == null ? new Exception[0] : new Exception[] { releaseFailure });
            }

            NativeWaitStatus waitStatus = NativeWaitStatus.Other;
            int exitCode = -1;
            Exception waitFailure = null;
            try
            {
                waitStatus = BoundedProcessHost.WaitForRetainedProcessHandle(
                    retainedProcessHandle,
                    BoundedProcessHost.GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds),
                    _processId,
                    out exitCode);
                if (waitStatus == NativeWaitStatus.Timeout)
                {
                    waitFailure = new ChildTerminationException(
                        _processId,
                        "process " + _processId.ToString(CultureInfo.InvariantCulture) +
                        " did not exit within " + timeoutMilliseconds.ToString(CultureInfo.InvariantCulture) +
                        " ms of termination.");
                }
            }
            catch (Exception error)
            {
                waitFailure = error;
            }
            Exception retainedHandleReleaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                ref retainedProcessHandle,
                "direct-launch process");
            if (waitFailure != null || retainedHandleReleaseFailure != null)
            {
                throw BoundedProcessHost.ComposeCleanupException(
                    waitFailure,
                    retainedHandleReleaseFailure == null
                        ? new Exception[0]
                        : new Exception[] { retainedHandleReleaseFailure });
            }

            lock (_sync)
            {
                if (!_disposed &&
                    _processGeneration == processGeneration &&
                    object.ReferenceEquals(_process, process))
                {
                    _exitCode = exitCode;
                    _exitCodeKnown = true;
                }
            }
        }

        private void RequireLiveLocked()
        {
            if (_disposed || _process == null)
            {
                throw new ObjectDisposedException("DirectLaunchSession");
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }
                List<Exception> errors = new List<Exception>();
                bool exited = BoundedProcessHost.ProveManagedProcessExit(
                    _process, _processId, DisposeTerminateTimeoutMilliseconds, errors);
                if (!exited)
                {
                    BoundedProcessHost.RetainPendingSession(this);
                    Exception primary = new ChildTerminationException(
                        _processId,
                        "direct-launch session cleanup could not prove process exit; ownership was retained for retry.");
                    throw BoundedProcessHost.ComposeCleanupException(primary, errors.ToArray());
                }

                BoundedProcessHost.ReleasePendingSession(this);
                if (_pathBinding != null)
                {
                    LaunchPathBinding binding = _pathBinding;
                    binding.ReleaseAndCleanup(errors);
                    _pathBinding = null;
                }

                if (_process != null)
                {
                    try { _process.Dispose(); }
                    catch (Exception disposeError)
                    {
                        errors.Add(disposeError);
                        BoundedProcessHost.QuarantineManagedOwner(_process);
                    }
                    _processGeneration++;
                    _process = null;
                }

                _disposed = true;

                Exception composed = BoundedProcessHost.ComposeCleanupException(null, errors.ToArray());
                if (composed != null)
                {
                    throw composed;
                }
            }
        }
    }

    public sealed class SchemaChildWatchdog
    {
        public const int WatchdogExitCode = 6;

        private readonly Timer _timer;
        private readonly int _timeoutMilliseconds;
        private int _terminal;

        public SchemaChildWatchdog(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 1)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            _timeoutMilliseconds = timeoutMilliseconds;
            _terminal = 0;
            _timer = new Timer(new TimerCallback(OnElapsed), null, timeoutMilliseconds, Timeout.Infinite);
        }

        public int TimeoutMilliseconds
        {
            get { return _timeoutMilliseconds; }
        }

        private void OnElapsed(object state)
        {
            if (Interlocked.CompareExchange(ref _terminal, 1, 0) == 0)
            {
                Environment.Exit(WatchdogExitCode);
            }
        }

        public bool Complete()
        {
            return Interlocked.CompareExchange(ref _terminal, 1, 0) == 0;
        }

        public bool DisposeBounded(int quiesceMilliseconds)
        {
            if (quiesceMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("quiesceMilliseconds");
            }
            ManualResetEvent done = new ManualResetEvent(false);
            try
            {
                if (!_timer.Dispose(done))
                {
                    return true;
                }
                return done.WaitOne(quiesceMilliseconds);
            }
            finally
            {
                done.Close();
            }
        }
    }

    public sealed class BoundedProcessResult
    {
        private readonly int _exitCode;
        private readonly bool _started;
        private readonly bool _exited;
        private readonly bool _timedOut;
        private readonly bool _terminated;
        private readonly bool _assignFailed;
        private readonly int _assignError;
        private readonly bool _stdOutOverflow;
        private readonly bool _stdErrOverflow;
        private readonly long _stdOutBytes;
        private readonly long _stdErrBytes;
        private readonly string _stdOutText;
        private readonly string _stdErrText;
        private readonly bool _drainCompleted;
        private readonly long _activeProcessesAfterTerminate;
        private readonly Guid _correlationId;

        internal BoundedProcessResult(int exitCode, bool started, bool exited, bool timedOut, bool terminated,
            bool assignFailed, int assignError, bool stdOutOverflow, bool stdErrOverflow, long stdOutBytes,
            long stdErrBytes, string stdOutText, string stdErrText, bool drainCompleted, long activeProcessesAfterTerminate)
            : this(exitCode, started, exited, timedOut, terminated, assignFailed, assignError, stdOutOverflow,
                stdErrOverflow, stdOutBytes, stdErrBytes, stdOutText, stdErrText, drainCompleted, activeProcessesAfterTerminate, Guid.Empty)
        {
        }

        internal BoundedProcessResult(int exitCode, bool started, bool exited, bool timedOut, bool terminated,
            bool assignFailed, int assignError, bool stdOutOverflow, bool stdErrOverflow, long stdOutBytes,
            long stdErrBytes, string stdOutText, string stdErrText, bool drainCompleted, long activeProcessesAfterTerminate,
            Guid correlationId)
        {
            _exitCode = exitCode;
            _started = started;
            _exited = exited;
            _timedOut = timedOut;
            _terminated = terminated;
            _assignFailed = assignFailed;
            _assignError = assignError;
            _stdOutOverflow = stdOutOverflow;
            _stdErrOverflow = stdErrOverflow;
            _stdOutBytes = stdOutBytes;
            _stdErrBytes = stdErrBytes;
            _stdOutText = stdOutText;
            _stdErrText = stdErrText;
            _drainCompleted = drainCompleted;
            _activeProcessesAfterTerminate = activeProcessesAfterTerminate;
            _correlationId = correlationId;
        }

        public int ExitCode { get { return _exitCode; } }
        public bool Started { get { return _started; } }
        public bool Exited { get { return _exited; } }
        public bool TimedOut { get { return _timedOut; } }
        public bool Terminated { get { return _terminated; } }
        public bool AssignFailed { get { return _assignFailed; } }
        public int AssignError { get { return _assignError; } }
        public bool StdOutOverflow { get { return _stdOutOverflow; } }
        public bool StdErrOverflow { get { return _stdErrOverflow; } }
        public long StdOutBytes { get { return _stdOutBytes; } }
        public long StdErrBytes { get { return _stdErrBytes; } }
        public string StdOutText { get { return _stdOutText; } }
        public string StdErrText { get { return _stdErrText; } }
        public bool DrainCompleted { get { return _drainCompleted; } }
        public long ActiveProcessesAfterTerminate { get { return _activeProcessesAfterTerminate; } }
        public Guid CorrelationId { get { return _correlationId; } }
    }

    public sealed class NamedEvent : IDisposable
    {
        private const uint SDDL_REVISION_1 = 1;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint EVENT_MODIFY_STATE = 0x00000002;
        private const uint EVENT_ALL_ACCESS = 0x001F0003;
        private const uint ERROR_ALREADY_EXISTS = 183;
        private const uint ERROR_ACCESS_DENIED = 5;
        private const uint ERROR_FILE_NOT_FOUND = 2;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_ABANDONED = 0x00000080;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint WAIT_FAILED = 0xFFFFFFFF;
        private const string SystemSid = "S-1-5-18";

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateEventW(IntPtr lpEventAttributes, [MarshalAs(UnmanagedType.Bool)] bool bManualReset, [MarshalAs(UnmanagedType.Bool)] bool bInitialState, string lpName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenEventW(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetEvent(IntPtr hEvent);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SignalObjectAndWait(IntPtr hObjectToSignal, IntPtr hObjectToWaitOn, uint dwMilliseconds, [MarshalAs(UnmanagedType.Bool)] bool bAlertable);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSDRevision, out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        private IntPtr _handle;
        private readonly string _name;
        private readonly EventRole _role;

        private NamedEvent(IntPtr handle, string name, EventRole role)
        {
            _handle = handle;
            _name = name;
            _role = role;
        }

        public string Name { get { return _name; } }
        public EventRole Role { get { return _role; } }
        internal IntPtr Handle { get { return _handle; } }

        public static NamedEvent CreateNewManualReset(string name, EventRole role, Guid correlationId)
        {
            BoundedProcessHost.ValidateEventNameGrammar(name);
            string userSid = CurrentUserSid();
            string sddl = "D:(A;;0x00100002;;;" + userSid + ")(A;;GA;;;SY)";
            return CreateWithDacl(name, role, correlationId, sddl, SYNCHRONIZE | EVENT_MODIFY_STATE);
        }

        public static NamedEvent CreateNewManualResetForProbe(string name, ProbeEventDaclKind kind, EventRole role, Guid correlationId)
        {
            BoundedProcessHost.ValidateEventNameGrammar(name);
            RequireNonSystemHost();
            string userSid = CurrentUserSid();
            string sddl;
            uint grantedMask;
            if (kind == ProbeEventDaclKind.SynchronizeOnly)
            {
                sddl = "D:(A;;0x00100000;;;" + userSid + ")(A;;GA;;;SY)";
                grantedMask = SYNCHRONIZE;
            }
            else if (kind == ProbeEventDaclKind.ModifyStateOnly)
            {
                sddl = "D:(A;;0x00000002;;;" + userSid + ")(A;;GA;;;SY)";
                grantedMask = EVENT_MODIFY_STATE;
            }
            else
            {
                throw new ArgumentOutOfRangeException("kind");
            }
            return CreateWithDacl(name, role, correlationId, sddl, grantedMask);
        }

        public static NamedEvent CreateNewManualResetAllAccessForProbe(string name, EventRole role, Guid correlationId)
        {
            BoundedProcessHost.ValidateEventNameGrammar(name);
            RequireNonSystemHost();
            string userSid = CurrentUserSid();
            string sddl = "D:(A;;GA;;;" + userSid + ")(A;;GA;;;SY)";
            return CreateWithDacl(name, role, correlationId, sddl, EVENT_ALL_ACCESS);
        }

        public static NamedEvent OpenExisting(string name, EventAccessMode mode, EventRole role, Guid correlationId)
        {
            BoundedProcessHost.ValidateEventNameGrammar(name);
            uint desiredAccess = MaskForMode(mode);
            IntPtr handle = OpenEventW(desiredAccess, false, name);
            int error = Marshal.GetLastWin32Error();
            BoundedProcessHost.RecordEventOpen(correlationId, role, name, desiredAccess);
            if (handle == IntPtr.Zero)
            {
                if ((uint)error == ERROR_FILE_NOT_FOUND)
                {
                    throw new EventOpenException(name, error, "named event '" + name + "' does not exist.");
                }
                throw new EventOpenException(name, error, "OpenEventW failed for '" + name + "'.");
            }
            return new NamedEvent(handle, name, role);
        }

        private static NamedEvent CreateWithDacl(string name, EventRole role, Guid correlationId, string sddl, uint grantedMask)
        {
            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            try
            {
                saBuffer = BuildSecurityAttributes(sddl, out securityDescriptor);
                IntPtr handle = CreateEventW(saBuffer, true, false, name);
                int error = Marshal.GetLastWin32Error();
                BoundedProcessHost.RecordEventCreate(correlationId, role, name, grantedMask);
                if (handle == IntPtr.Zero)
                {
                    if ((uint)error == ERROR_ACCESS_DENIED)
                    {
                        throw new EventSquatException(name, error, "event '" + name + "' creation denied; a restricted object already owns the name.");
                    }
                    throw new Win32Exception(error, "CreateEventW failed for '" + name + "'.");
                }
                if ((uint)error == ERROR_ALREADY_EXISTS)
                {
                    if (!CloseHandle(handle))
                    {
                        int closeError = Marshal.GetLastWin32Error();
                        BoundedProcessHost.QuarantineRawHandle(handle);
                        EventSquatException primary = new EventSquatException(
                            name, error, "event '" + name + "' already existed; refusing to reuse a squatted name.");
                        Win32Exception cleanup = new Win32Exception(
                            closeError, "the rejected handle for event '" + name + "' failed to close and was quarantined.");
                        throw BoundedProcessHost.ComposeCleanupException(primary, new Exception[] { cleanup });
                    }
                    throw new EventSquatException(name, error, "event '" + name + "' already existed; refusing to reuse a squatted name.");
                }
                return new NamedEvent(handle, name, role);
            }
            finally
            {
                if (securityDescriptor != IntPtr.Zero)
                {
                    LocalFree(securityDescriptor);
                    securityDescriptor = IntPtr.Zero;
                }
                if (saBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(saBuffer);
                    saBuffer = IntPtr.Zero;
                }
            }
        }

        private static IntPtr BuildSecurityAttributes(string sddl, out IntPtr securityDescriptor)
        {
            IntPtr descriptor;
            uint descriptorSize;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, out descriptor, out descriptorSize))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "ConvertStringSecurityDescriptorToSecurityDescriptorW failed.");
            }
            securityDescriptor = descriptor;
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.lpSecurityDescriptor = descriptor;
            attributes.bInheritHandle = 0;
            IntPtr buffer = Marshal.AllocHGlobal(attributes.nLength);
            Marshal.StructureToPtr(attributes, buffer, false);
            return buffer;
        }

        private static uint MaskForMode(EventAccessMode mode)
        {
            switch (mode)
            {
                case EventAccessMode.WaitOnly: return SYNCHRONIZE;
                case EventAccessMode.SetOnly: return EVENT_MODIFY_STATE;
                case EventAccessMode.WaitAndSet: return SYNCHRONIZE | EVENT_MODIFY_STATE;
                default: throw new ArgumentOutOfRangeException("mode");
            }
        }

        private static string CurrentUserSid()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity.User == null)
                {
                    throw new UnsupportedCertificationHostException("the current Windows identity does not expose a user SID.");
                }
                return identity.User.Value;
            }
        }

        private static void RequireNonSystemHost()
        {
            if (string.Equals(CurrentUserSid(), SystemSid, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnsupportedCertificationHostException("restricted-DACL event probes require a non-SYSTEM interactive user; SYSTEM full-access would invalidate least-rights negatives.");
            }
        }

        public void SetEvent()
        {
            if (_handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("NamedEvent");
            }
            if (!SetEvent(_handle))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "SetEvent failed for '" + _name + "'.");
            }
        }

        public NativeWaitStatus Wait(int timeoutMilliseconds)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("NamedEvent");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            uint raw = WaitForSingleObject(_handle, (uint)timeoutMilliseconds);
            return ResolveWait(raw, "WaitForSingleObject");
        }

        public bool IsSignaledNow()
        {
            if (_handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("NamedEvent");
            }
            uint raw = WaitForSingleObject(_handle, 0);
            if (raw == WAIT_OBJECT_0)
            {
                return true;
            }
            if (raw == WAIT_TIMEOUT)
            {
                return false;
            }
            int error = Marshal.GetLastWin32Error();
            throw new NativeWaitException(error, "zero-timeout state query returned unexpected status 0x" + raw.ToString("X8", CultureInfo.InvariantCulture) + ".");
        }

        public NativeWaitStatus SignalObjectAndWaitOn(NamedEvent objectToWaitOn, int timeoutMilliseconds)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("NamedEvent");
            }
            if (objectToWaitOn == null)
            {
                throw new ArgumentNullException("objectToWaitOn");
            }
            if (objectToWaitOn._handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("objectToWaitOn");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            uint raw = SignalObjectAndWait(_handle, objectToWaitOn._handle, (uint)timeoutMilliseconds, false);
            return ResolveWait(raw, "SignalObjectAndWait");
        }

        private NativeWaitStatus ResolveWait(uint raw, string api)
        {
            if (raw == WAIT_OBJECT_0)
            {
                return NativeWaitStatus.Object0;
            }
            if (raw == WAIT_TIMEOUT)
            {
                return NativeWaitStatus.Timeout;
            }
            if (raw == WAIT_FAILED)
            {
                int error = Marshal.GetLastWin32Error();
                throw new NativeWaitException(error, api + " failed for '" + _name + "'.");
            }
            if (raw == WAIT_ABANDONED)
            {
                throw new NativeWaitException(0, api + " returned WAIT_ABANDONED for '" + _name + "'.");
            }
            throw new NativeWaitException(0, api + " returned unexpected status 0x" + raw.ToString("X8", CultureInfo.InvariantCulture) + " for '" + _name + "'.");
        }

        public void Close()
        {
            if (_handle != IntPtr.Zero)
            {
                IntPtr current = _handle;
                _handle = IntPtr.Zero;
                if (!CloseHandle(current))
                {
                    int error = Marshal.GetLastWin32Error();
                    BoundedProcessHost.QuarantineRawHandle(current);
                    throw new Win32Exception(error, "CloseHandle failed for '" + _name + "'.");
                }
            }
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                IntPtr current = _handle;
                _handle = IntPtr.Zero;
                if (!CloseHandle(current))
                {
                    BoundedProcessHost.QuarantineRawHandle(current);
                }
            }
        }
    }

    public struct JobProcessMember : IEquatable<JobProcessMember>
    {
        private readonly int _processId;
        private readonly int _parentProcessId;
        private readonly long _creationFileTimeUtc;
        private readonly string _canonicalImagePath;

        public JobProcessMember(int processId, int parentProcessId, long creationFileTimeUtc, string canonicalImagePath)
        {
            _processId = processId;
            _parentProcessId = parentProcessId;
            _creationFileTimeUtc = creationFileTimeUtc;
            _canonicalImagePath = canonicalImagePath == null ? string.Empty : canonicalImagePath;
        }

        public int ProcessId { get { return _processId; } }
        public int ParentProcessId { get { return _parentProcessId; } }
        public long CreationFileTimeUtc { get { return _creationFileTimeUtc; } }
        public string CanonicalImagePath { get { return _canonicalImagePath == null ? string.Empty : _canonicalImagePath; } }

        public bool Equals(JobProcessMember other)
        {
            return _processId == other._processId
                && _parentProcessId == other._parentProcessId
                && _creationFileTimeUtc == other._creationFileTimeUtc
                && string.Equals(CanonicalImagePath, other.CanonicalImagePath, StringComparison.OrdinalIgnoreCase);
        }

        public override bool Equals(object obj)
        {
            if (!(obj is JobProcessMember))
            {
                return false;
            }
            return Equals((JobProcessMember)obj);
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = (hash * 31) + _processId;
            hash = (hash * 31) + _parentProcessId;
            hash = (hash * 31) + _creationFileTimeUtc.GetHashCode();
            hash = (hash * 31) + StringComparer.OrdinalIgnoreCase.GetHashCode(CanonicalImagePath);
            return hash;
        }

        public override string ToString()
        {
            return "pid=" + _processId.ToString(CultureInfo.InvariantCulture)
                + " ppid=" + _parentProcessId.ToString(CultureInfo.InvariantCulture)
                + " creation=" + _creationFileTimeUtc.ToString(CultureInfo.InvariantCulture)
                + " image=" + CanonicalImagePath;
        }
    }

    public struct JobAccountingSnapshot : IEquatable<JobAccountingSnapshot>
    {
        private readonly long _totalProcesses;
        private readonly long _activeProcesses;
        private readonly long _totalTerminatedProcesses;

        public JobAccountingSnapshot(long totalProcesses, long activeProcesses, long totalTerminatedProcesses)
        {
            _totalProcesses = totalProcesses;
            _activeProcesses = activeProcesses;
            _totalTerminatedProcesses = totalTerminatedProcesses;
        }

        public long TotalProcesses { get { return _totalProcesses; } }
        public long ActiveProcesses { get { return _activeProcesses; } }
        public long TotalTerminatedProcesses { get { return _totalTerminatedProcesses; } }

        public bool Equals(JobAccountingSnapshot other)
        {
            return _totalProcesses == other._totalProcesses
                && _activeProcesses == other._activeProcesses
                && _totalTerminatedProcesses == other._totalTerminatedProcesses;
        }

        public override bool Equals(object obj)
        {
            if (!(obj is JobAccountingSnapshot))
            {
                return false;
            }
            return Equals((JobAccountingSnapshot)obj);
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = (hash * 31) + _totalProcesses.GetHashCode();
            hash = (hash * 31) + _activeProcesses.GetHashCode();
            hash = (hash * 31) + _totalTerminatedProcesses.GetHashCode();
            return hash;
        }

        public override string ToString()
        {
            return "total=" + _totalProcesses.ToString(CultureInfo.InvariantCulture)
                + " active=" + _activeProcesses.ToString(CultureInfo.InvariantCulture)
                + " terminated=" + _totalTerminatedProcesses.ToString(CultureInfo.InvariantCulture);
        }
    }

    public sealed class JobProcessSnapshot : IDisposable
    {
        private readonly object _sync = new object();
        private readonly JobProcessMember[] _members;
        private IntPtr[] _handles;
        private bool _disposed;
        private bool _closeAttempted;
        private readonly List<Exception> _closeErrors = new List<Exception>();

        internal JobProcessSnapshot(JobProcessMember[] members, IntPtr[] handles)
        {
            if (members == null) { throw new ArgumentNullException("members"); }
            if (handles == null) { throw new ArgumentNullException("handles"); }
            if (members.Length != handles.Length)
            {
                throw new ArgumentException("member and handle arrays must be index-aligned.");
            }
            _members = members;
            _handles = handles;
        }

        public int Count { get { return _members.Length; } }

        public JobProcessMember[] Members
        {
            get { return (JobProcessMember[])_members.Clone(); }
        }

        internal JobProcessMember GetMember(int index)
        {
            if (index < 0 || index >= _members.Length)
            {
                throw new ArgumentOutOfRangeException("index");
            }
            return _members[index];
        }

        public bool RevalidateLive()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException("JobProcessSnapshot");
                }
                for (int index = 0; index < _members.Length; index++)
                {
                    int pid;
                    long creation;
                    string image;
                    bool live;
                    if (!BoundedProcessHost.TryQueryRetainedIdentity(_handles[index], out pid, out creation, out image, out live))
                    {
                        return false;
                    }
                    if (!live)
                    {
                        return false;
                    }
                    JobProcessMember member = _members[index];
                    if (pid != member.ProcessId || creation != member.CreationFileTimeUtc)
                    {
                        return false;
                    }
                    if (image != null && !string.Equals(image, member.CanonicalImagePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        public bool MatchRetainedIdentityAllowExited()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException("JobProcessSnapshot");
                }
                for (int index = 0; index < _members.Length; index++)
                {
                    int pid;
                    long creation;
                    string image;
                    bool live;
                    if (!BoundedProcessHost.TryQueryRetainedIdentity(_handles[index], out pid, out creation, out image, out live))
                    {
                        return false;
                    }
                    JobProcessMember member = _members[index];
                    if (pid != member.ProcessId || creation != member.CreationFileTimeUtc)
                    {
                        return false;
                    }
                    if (image != null && !string.Equals(image, member.CanonicalImagePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        public bool MembersEqual(JobProcessSnapshot other)
        {
            if (other == null)
            {
                return false;
            }
            JobProcessMember[] left = _members;
            JobProcessMember[] right = other._members;
            if (left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; index++)
            {
                if (!left[index].Equals(right[index]))
                {
                    return false;
                }
            }
            return true;
        }

        public bool DisposeSucceeded
        {
            get { lock (_sync) { return _closeAttempted && _closeErrors.Count == 0; } }
        }

        public Exception[] GetCloseErrors()
        {
            lock (_sync)
            {
                return _closeErrors.ToArray();
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }
                _disposed = true;
                _closeAttempted = true;
                if (_handles != null)
                {
                    for (int index = 0; index < _handles.Length; index++)
                    {
                        IntPtr handle = _handles[index];
                        if (handle == IntPtr.Zero)
                        {
                            continue;
                        }
                        _handles[index] = IntPtr.Zero;
                        Exception closeError;
                        if (!BoundedProcessHost.CloseRetainedHandle(handle, out closeError))
                        {
                            _closeErrors.Add(closeError);
                        }
                    }
                    _handles = null;
                }
                if (_closeErrors.Count > 0)
                {
                    throw BoundedProcessHost.ComposeSnapshotCloseException(_closeErrors.ToArray());
                }
            }
        }
    }

    internal sealed class ContainedRootIdentity
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int GetPackageFullName(IntPtr hProcess, ref uint packageFullNameLength, StringBuilder packageFullName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int GetPackagePathByFullName(string packageFullName, ref uint pathLength, StringBuilder path);

        private const int PackageQuerySuccess = 0;
        private const int PackageQueryInsufficientBuffer = 122;
        private const int PackageQueryNoPackage = 15700;
        private const int MaxPackageFullNameLength = 1024;
        private const int MaxPackagePathLength = 32768;

        private readonly int _processId;
        private readonly long _startFileTime;
        private readonly string _rootImagePath;
        private readonly HostPackagingKind _packagingKind;
        private readonly string _packageFullName;
        private readonly string _packageRootPath;

        private ContainedRootIdentity(
            int processId,
            long startFileTime,
            string rootImagePath,
            HostPackagingKind packagingKind,
            string packageFullName,
            string packageRootPath)
        {
            if (processId <= 0)
            {
                throw new ContainedWorkerException("a pinned root identity requires a positive process id.");
            }
            if (startFileTime <= 0)
            {
                throw new ContainedWorkerException("a pinned root identity for process " + processId.ToString(CultureInfo.InvariantCulture) + " requires a positive creation time.");
            }
            if (rootImagePath == null || rootImagePath.Length == 0)
            {
                throw new ContainedWorkerException("a pinned root identity for process " + processId.ToString(CultureInfo.InvariantCulture) + " requires a non-empty canonical root image path.");
            }
            string normalizedFullName = packageFullName == null ? string.Empty : packageFullName;
            string normalizedRootPath = packageRootPath == null ? string.Empty : packageRootPath;
            if (packagingKind == HostPackagingKind.Packaged)
            {
                if (normalizedFullName.Length == 0 || normalizedRootPath.Length == 0)
                {
                    throw new ContainedWorkerException("a Packaged root identity for process " + processId.ToString(CultureInfo.InvariantCulture) + " requires a package full name and root path.");
                }
            }
            else
            {
                if (normalizedFullName.Length != 0 || normalizedRootPath.Length != 0)
                {
                    throw new ContainedWorkerException("an Unpackaged root identity for process " + processId.ToString(CultureInfo.InvariantCulture) + " must carry an empty package full name and root path.");
                }
            }
            _processId = processId;
            _startFileTime = startFileTime;
            _rootImagePath = rootImagePath;
            _packagingKind = packagingKind;
            _packageFullName = normalizedFullName;
            _packageRootPath = normalizedRootPath;
        }

        internal static ContainedRootIdentity Capture(IntPtr processHandle, int processId, long startFileTime)
        {
            if (processHandle == IntPtr.Zero)
            {
                throw new ContainedWorkerException("the root identity for process " + processId.ToString(CultureInfo.InvariantCulture) + " cannot be pinned from a null create handle.");
            }
            string capturedImage;
            if (!BoundedProcessHost.TryQueryImagePathFromHandle(processHandle, out capturedImage) || capturedImage == null || capturedImage.Length == 0)
            {
                throw new ContainedWorkerException("the root image path could not be pinned from the retained create handle for process " + processId.ToString(CultureInfo.InvariantCulture) + "; refusing to transfer a contained session without a pinned root identity.");
            }
            HostPackagingKind derivedKind;
            string derivedFullName;
            string derivedRootPath;
            DeriveHostPackaging(processHandle, capturedImage, out derivedKind, out derivedFullName, out derivedRootPath);
            return new ContainedRootIdentity(processId, startFileTime, capturedImage, derivedKind, derivedFullName, derivedRootPath);
        }

        internal int ProcessId { get { return _processId; } }
        internal long StartFileTimeUtc { get { return _startFileTime; } }
        internal string RootImagePath { get { return _rootImagePath; } }
        internal HostPackagingKind PackagingKind { get { return _packagingKind; } }
        internal string PackageFullName { get { return _packageFullName; } }
        internal string PackageRootPath { get { return _packageRootPath; } }

        private static void DeriveHostPackaging(
            IntPtr processHandle,
            string canonicalRootImagePath,
            out HostPackagingKind kind,
            out string packageFullName,
            out string packageRootPath)
        {
            kind = HostPackagingKind.Unpackaged;
            packageFullName = string.Empty;
            packageRootPath = string.Empty;

            string image = CanonicalizePackagingPath(canonicalRootImagePath);
            if (image.Length == 0)
            {
                throw new ContainedWorkerException("the retained root image path was empty; host packaging identity could not be derived.");
            }

            uint nameLength = 0;
            int nameStatus = GetPackageFullName(processHandle, ref nameLength, null);
            if (nameStatus == PackageQueryNoPackage)
            {
                string windowsAppsRoot = GetCanonicalWindowsAppsRoot();
                if (windowsAppsRoot.Length != 0 && PathIsWithinDirectory(windowsAppsRoot, image))
                {
                    throw new ContainedWorkerException("GetPackageFullName reported APPMODEL_ERROR_NO_PACKAGE, but the retained root image '" + image + "' resides under the packaged application root '" + windowsAppsRoot + "'.");
                }
                kind = HostPackagingKind.Unpackaged;
                packageFullName = string.Empty;
                packageRootPath = string.Empty;
                return;
            }
            if (nameStatus != PackageQueryInsufficientBuffer)
            {
                throw new ContainedWorkerException("GetPackageFullName returned unexpected status " + nameStatus.ToString(CultureInfo.InvariantCulture) + " while deriving host packaging identity.");
            }
            if (nameLength == 0 || nameLength > MaxPackageFullNameLength)
            {
                throw new ContainedWorkerException("GetPackageFullName reported an out-of-range package full name length of " + nameLength.ToString(CultureInfo.InvariantCulture) + ".");
            }
            StringBuilder nameBuffer = new StringBuilder((int)nameLength);
            int nameResolve = GetPackageFullName(processHandle, ref nameLength, nameBuffer);
            if (nameResolve != PackageQuerySuccess)
            {
                throw new ContainedWorkerException("GetPackageFullName returned status " + nameResolve.ToString(CultureInfo.InvariantCulture) + " when resolving the package full name.");
            }
            string fullName = nameBuffer.ToString();
            if (fullName.Length == 0)
            {
                throw new ContainedWorkerException("GetPackageFullName returned success with an empty package full name.");
            }

            uint pathLength = 0;
            int pathStatus = GetPackagePathByFullName(fullName, ref pathLength, null);
            if (pathStatus != PackageQueryInsufficientBuffer)
            {
                throw new ContainedWorkerException("GetPackagePathByFullName returned unexpected status " + pathStatus.ToString(CultureInfo.InvariantCulture) + " for package '" + fullName + "'.");
            }
            if (pathLength == 0 || pathLength > MaxPackagePathLength)
            {
                throw new ContainedWorkerException("GetPackagePathByFullName reported an out-of-range path length of " + pathLength.ToString(CultureInfo.InvariantCulture) + " for package '" + fullName + "'.");
            }
            StringBuilder pathBuffer = new StringBuilder((int)pathLength);
            int pathResolve = GetPackagePathByFullName(fullName, ref pathLength, pathBuffer);
            if (pathResolve != PackageQuerySuccess)
            {
                throw new ContainedWorkerException("GetPackagePathByFullName returned status " + pathResolve.ToString(CultureInfo.InvariantCulture) + " when resolving the package root for '" + fullName + "'.");
            }
            string root = CanonicalizePackagingPath(pathBuffer.ToString());
            if (root.Length == 0)
            {
                throw new ContainedWorkerException("GetPackagePathByFullName returned an empty package root for '" + fullName + "'.");
            }
            if (!PathIsWithinDirectory(root, image) && !string.Equals(root, image, StringComparison.OrdinalIgnoreCase))
            {
                throw new ContainedWorkerException("the retained root image '" + image + "' is not contained within the canonical package root '" + root + "' for package '" + fullName + "'.");
            }
            kind = HostPackagingKind.Packaged;
            packageFullName = fullName;
            packageRootPath = root;
        }

        private static string CanonicalizePackagingPath(string path)
        {
            if (path == null)
            {
                return string.Empty;
            }
            string full;
            try { full = Path.GetFullPath(path); }
            catch (ArgumentException) { return string.Empty; }
            catch (NotSupportedException) { return string.Empty; }
            catch (PathTooLongException) { return string.Empty; }
            catch (System.Security.SecurityException) { return string.Empty; }
            if (full.Length > 3)
            {
                char last = full[full.Length - 1];
                if (last == Path.DirectorySeparatorChar || last == Path.AltDirectorySeparatorChar)
                {
                    full = full.Substring(0, full.Length - 1);
                }
            }
            return full;
        }

        private static string GetCanonicalWindowsAppsRoot()
        {
            string programFiles;
            try { programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles); }
            catch (ArgumentException) { programFiles = null; }
            if (string.IsNullOrEmpty(programFiles))
            {
                return string.Empty;
            }
            return CanonicalizePackagingPath(Path.Combine(programFiles, "WindowsApps"));
        }

        private static bool PathIsWithinDirectory(string directory, string candidate)
        {
            if (directory.Length == 0 || candidate.Length == 0)
            {
                return false;
            }
            string prefix = directory;
            char last = prefix[prefix.Length - 1];
            if (last != Path.DirectorySeparatorChar && last != Path.AltDirectorySeparatorChar)
            {
                prefix = prefix + Path.DirectorySeparatorChar;
            }
            return candidate.Length > prefix.Length &&
                candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }
    }

    public sealed class ContainedWorkerSession : IDisposable
    {
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint WAIT_FAILED = 0xFFFFFFFF;
        private const uint STILL_ACTIVE = 259;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private readonly object _sync = new object();
        private readonly ContainedWorkerScenario _scenario;
        private readonly ProcessLaunchRole _role;
        private readonly bool _isGeneratorHost;
        private readonly GeneratorScenario _generatorScenario;
        private readonly int _processId;
        private readonly long _startFileTime;
        private readonly ContainedWorkerLaunchDiagnostic _diagnostic;
        private readonly string _resultRoot;
        private readonly string _controlRoot;
        private readonly ResumeFailureOutcome _resumeOutcome;
        private readonly List<Exception> _disposeErrors = new List<Exception>();
        private LaunchPathBinding _pathBinding;
        private string _rootImagePath;
        private readonly bool _packagingKnown;
        private readonly HostPackagingKind _packagingKind;
        private readonly string _packageFullName;
        private readonly string _packageRootPath;

        private IntPtr _processHandle;
        private long _processHandleGeneration;
        private IntPtr _threadHandle;
        private IntPtr _jobHandle;
        private long _jobHandleGeneration;
        private NamedEvent _gate;
        private ContainedWorkerState _state;
        private bool _exitCodeKnown;
        private int _exitCode;

        internal ContainedWorkerSession(
            ContainedWorkerScenario scenario,
            ProcessLaunchRole role,
            bool isGeneratorHost,
            GeneratorScenario generatorScenario,
            ContainedRootIdentity rootIdentity,
            IntPtr processHandle,
            IntPtr threadHandle,
            IntPtr jobHandle,
            NamedEvent gate,
            string resultRoot,
            string controlRoot,
            ContainedWorkerState state,
            ResumeFailureOutcome resumeOutcome,
            ContainedWorkerLaunchDiagnostic diagnostic)
        {
            if (rootIdentity == null)
            {
                throw new ContainedWorkerException("a contained session cannot be constructed without a pinned root identity captured while the process was suspended.");
            }
            if (rootIdentity.ProcessId <= 0)
            {
                throw new ContainedWorkerException("the pinned root identity carried a non-positive process id.");
            }
            if (rootIdentity.StartFileTimeUtc <= 0)
            {
                throw new ContainedWorkerException("the pinned root identity for process " + rootIdentity.ProcessId.ToString(CultureInfo.InvariantCulture) + " carried a non-positive creation time.");
            }
            if (rootIdentity.RootImagePath == null || rootIdentity.RootImagePath.Length == 0)
            {
                throw new ContainedWorkerException("the pinned root identity for process " + rootIdentity.ProcessId.ToString(CultureInfo.InvariantCulture) + " carried an empty canonical root image path.");
            }
            if (rootIdentity.PackagingKind == HostPackagingKind.Packaged)
            {
                if (string.IsNullOrEmpty(rootIdentity.PackageFullName) || string.IsNullOrEmpty(rootIdentity.PackageRootPath))
                {
                    throw new ContainedWorkerException("the pinned root identity for process " + rootIdentity.ProcessId.ToString(CultureInfo.InvariantCulture) + " reported Packaged without a package full name and root path.");
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(rootIdentity.PackageFullName) || !string.IsNullOrEmpty(rootIdentity.PackageRootPath))
                {
                    throw new ContainedWorkerException("the pinned root identity for process " + rootIdentity.ProcessId.ToString(CultureInfo.InvariantCulture) + " reported Unpackaged with a non-empty package full name or root path.");
                }
            }
            _scenario = scenario;
            _role = role;
            _isGeneratorHost = isGeneratorHost;
            _generatorScenario = generatorScenario;
            _processId = rootIdentity.ProcessId;
            _startFileTime = rootIdentity.StartFileTimeUtc;
            _processHandle = processHandle;
            _processHandleGeneration = 1;
            _threadHandle = threadHandle;
            _jobHandle = jobHandle;
            _jobHandleGeneration = 1;
            _gate = gate;
            _resultRoot = resultRoot;
            _controlRoot = controlRoot;
            _state = state;
            _resumeOutcome = resumeOutcome;
            _diagnostic = diagnostic;
            _rootImagePath = rootIdentity.RootImagePath;
            _packagingKind = rootIdentity.PackagingKind;
            _packageFullName = rootIdentity.PackageFullName;
            _packageRootPath = rootIdentity.PackageRootPath;
            _packagingKnown = true;
        }

        public ContainedWorkerScenario Scenario { get { return _scenario; } }
        public ProcessLaunchRole LaunchRole { get { return _role; } }
        public bool IsGeneratorHost { get { return _isGeneratorHost; } }
        public GeneratorScenario GeneratorScenario
        {
            get
            {
                if (!_isGeneratorHost)
                {
                    throw new ContainedWorkerStateException("this session is not a GeneratorHost launch; GeneratorScenario is unavailable.");
                }
                return _generatorScenario;
            }
        }
        public int ProcessId { get { return _processId; } }
        public long StartTimeFileTimeUtc { get { return _startFileTime; } }
        public int RootProcessId { get { return _processId; } }
        public long RootStartTimeFileTimeUtc { get { return _startFileTime; } }
        public bool HasRootImagePath
        {
            get { lock (_sync) { return _rootImagePath != null; } }
        }
        public string RootImagePath
        {
            get
            {
                lock (_sync)
                {
                    if (_rootImagePath == null)
                    {
                        throw new ContainedWorkerStateException("the root image path was not captured from the retained create handle for this session.");
                    }
                    return _rootImagePath;
                }
            }
        }
        public bool HasPackagingIdentity
        {
            get { return _packagingKind == HostPackagingKind.Packaged; }
        }
        public HostPackagingKind PackagingKind
        {
            get
            {
                if (!_packagingKnown)
                {
                    throw new ContainedWorkerStateException("the host packaging identity was not captured from the retained create handle for this session.");
                }
                return _packagingKind;
            }
        }
        public string PackageFullName
        {
            get
            {
                if (!_packagingKnown)
                {
                    throw new ContainedWorkerStateException("the host packaging identity was not captured from the retained create handle for this session.");
                }
                return _packageFullName == null ? string.Empty : _packageFullName;
            }
        }
        public string PackageRootPath
        {
            get
            {
                if (!_packagingKnown)
                {
                    throw new ContainedWorkerStateException("the host packaging identity was not captured from the retained create handle for this session.");
                }
                return _packageRootPath == null ? string.Empty : _packageRootPath;
            }
        }
        public string ResultRoot { get { return _resultRoot; } }
        public string ControlRoot { get { return _controlRoot; } }
        public ContainedWorkerLaunchDiagnostic LaunchDiagnostic { get { return _diagnostic; } }

        public Exception[] GetDisposeErrors()
        {
            lock (_sync)
            {
                return _disposeErrors.ToArray();
            }
        }

        internal void AttachPathBinding(LaunchPathBinding binding)
        {
            lock (_sync)
            {
                _pathBinding = binding;
            }
        }

        public string ExecutableFullPath
        {
            get
            {
                lock (_sync)
                {
                    if (_pathBinding == null)
                    {
                        throw new ContainedWorkerStateException("the launch path binding has already been released.");
                    }
                    return _pathBinding.ExecutableFullPath;
                }
            }
        }

        public string WorkingDirectoryFullPath
        {
            get
            {
                lock (_sync)
                {
                    if (_pathBinding == null)
                    {
                        throw new ContainedWorkerStateException("the launch path binding has already been released.");
                    }
                    return _pathBinding.WorkingDirectoryFullPath;
                }
            }
        }

        public bool DisposeSucceeded
        {
            get { lock (_sync) { return _state == ContainedWorkerState.Cleaned && _disposeErrors.Count == 0; } }
        }

        public ContainedWorkerState State
        {
            get { lock (_sync) { return _state; } }
        }

        public bool HasGate { get { return _gate != null; } }

        public void SignalWorkerGate()
        {
            lock (_sync)
            {
                if (_state != ContainedWorkerState.Resumed)
                {
                    throw new ContainedWorkerStateException("SignalWorkerGate is legal only in the Resumed state; current state is " + _state.ToString() + ".");
                }
                if (_isGeneratorHost && _generatorScenario != Pspkt.Certification.GeneratorScenario.Normal)
                {
                    throw new ContainedWorkerStateException("GeneratorHost scenario " + _generatorScenario.ToString() + " withholds the supervisor gate; signaling is illegal.");
                }
                if (_gate == null)
                {
                    throw new ContainedWorkerStateException("this session has no supervisor gate handle; signaling is illegal.");
                }
                _gate.SetEvent();
                _state = ContainedWorkerState.Released;
            }
        }

        public NativeWaitStatus WaitWorker(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            IntPtr processHandle;
            long processHandleGeneration;
            IntPtr retainedProcessHandle;
            lock (_sync)
            {
                if (_state != ContainedWorkerState.Resumed && _state != ContainedWorkerState.Released && _state != ContainedWorkerState.Failed)
                {
                    throw new ContainedWorkerStateException("WaitWorker is legal only from Resumed, Released, or Failed; current state is " + _state.ToString() + ".");
                }
                processHandle = _processHandle;
                processHandleGeneration = _processHandleGeneration;
                retainedProcessHandle = BoundedProcessHost.DuplicateProcessWaitHandle(processHandle);
            }

            NativeWaitStatus waitStatus = NativeWaitStatus.Other;
            int exitCode = -1;
            Exception waitFailure = null;
            try
            {
                waitStatus = BoundedProcessHost.WaitForRetainedProcessHandle(
                    retainedProcessHandle,
                    timeoutMilliseconds,
                    _processId,
                    out exitCode);
            }
            catch (Exception error)
            {
                waitFailure = error;
            }
            Exception releaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                ref retainedProcessHandle,
                "contained worker process");
            if (waitFailure != null || releaseFailure != null)
            {
                throw BoundedProcessHost.ComposeCleanupException(
                    waitFailure,
                    releaseFailure == null ? new Exception[0] : new Exception[] { releaseFailure });
            }

            if (waitStatus == NativeWaitStatus.Object0)
            {
                lock (_sync)
                {
                    if (_state != ContainedWorkerState.Cleaned &&
                        _processHandleGeneration == processHandleGeneration &&
                        _processHandle == processHandle)
                    {
                        _exitCode = exitCode;
                        _exitCodeKnown = true;
                        _state = ContainedWorkerState.Exited;
                    }
                }
            }
            return waitStatus;
        }

        public long QueryActiveProcesses()
        {
            lock (_sync)
            {
                if (_state == ContainedWorkerState.Created || _state == ContainedWorkerState.StartedSuspended || _state == ContainedWorkerState.Cleaned)
                {
                    throw new ContainedWorkerStateException("QueryActiveProcesses is legal from Assigned through Failed/Exited; current state is " + _state.ToString() + ".");
                }
                return BoundedProcessHost.QueryJobActiveProcesses(_jobHandle);
            }
        }

        public JobAccountingSnapshot QueryJobAccounting()
        {
            lock (_sync)
            {
                if (_state == ContainedWorkerState.Created || _state == ContainedWorkerState.StartedSuspended || _state == ContainedWorkerState.Cleaned)
                {
                    throw new ContainedWorkerStateException("QueryJobAccounting is legal from Assigned through Failed/Exited; current state is " + _state.ToString() + ".");
                }
                return BoundedProcessHost.QueryJobAccountingInfo(_jobHandle);
            }
        }

        public JobProcessSnapshot CaptureActiveProcessSnapshot()
        {
            lock (_sync)
            {
                if (_state == ContainedWorkerState.Created || _state == ContainedWorkerState.StartedSuspended || _state == ContainedWorkerState.Cleaned)
                {
                    throw new ContainedWorkerStateException("CaptureActiveProcessSnapshot is legal from Assigned through Failed/Exited; current state is " + _state.ToString() + ".");
                }
                return BoundedProcessHost.CaptureJobProcessSnapshot(_jobHandle, _processId, _startFileTime, _rootImagePath);
            }
        }

        public ResumeFailureOutcome GetResumeFailureOutcome()
        {
            lock (_sync)
            {
                if (_state != ContainedWorkerState.Exited)
                {
                    throw new ContainedWorkerStateException("GetResumeFailureOutcome is legal only in the Exited state for resume scenarios; current state is " + _state.ToString() + ".");
                }
                if (_resumeOutcome == null)
                {
                    throw new ContainedWorkerStateException("this session did not record a resume-failure outcome.");
                }
                return _resumeOutcome;
            }
        }

        public int GetExitCode()
        {
            lock (_sync)
            {
                if (!_exitCodeKnown)
                {
                    throw new ContainedWorkerStateException("worker exit code is not yet known.");
                }
                return _exitCode;
            }
        }

        public long TerminateAndWait(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            IntPtr processHandle;
            long processHandleGeneration;
            IntPtr jobHandle;
            long jobHandleGeneration;
            IntPtr retainedProcessHandle = IntPtr.Zero;
            IntPtr retainedJobHandle = IntPtr.Zero;
            Exception terminationFailure = null;
            lock (_sync)
            {
                if (_state == ContainedWorkerState.Cleaned)
                {
                    throw new ContainedWorkerStateException("TerminateAndWait is illegal after the session is Cleaned.");
                }
                if (_processHandle == IntPtr.Zero)
                {
                    throw new ContainedWorkerStateException("the contained worker process handle is already closed.");
                }
                processHandle = _processHandle;
                processHandleGeneration = _processHandleGeneration;
                jobHandle = _jobHandle;
                jobHandleGeneration = _jobHandleGeneration;
                try
                {
                    retainedProcessHandle = BoundedProcessHost.DuplicateProcessWaitHandle(processHandle);
                    if (jobHandle != IntPtr.Zero)
                    {
                        retainedJobHandle = BoundedProcessHost.DuplicateJobQueryHandle(jobHandle);
                        if (!BoundedProcessHost.TerminateJob(jobHandle))
                        {
                            int jobError = Marshal.GetLastWin32Error();
                            throw new Win32Exception(jobError, "TerminateJobObject failed for contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
                        }
                    }
                    else if (!ProcessAlreadyExitedLocked())
                    {
                        if (!TerminateProcess(processHandle, 1))
                        {
                            int processError = Marshal.GetLastWin32Error();
                            throw new Win32Exception(processError, "TerminateProcess failed for contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
                        }
                    }
                }
                catch (Exception error)
                {
                    terminationFailure = error;
                }
            }

            if (terminationFailure != null)
            {
                List<Exception> releaseFailures = new List<Exception>();
                Exception processReleaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                    ref retainedProcessHandle,
                    "contained worker process");
                if (processReleaseFailure != null) { releaseFailures.Add(processReleaseFailure); }
                Exception jobReleaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                    ref retainedJobHandle,
                    "contained worker job");
                if (jobReleaseFailure != null) { releaseFailures.Add(jobReleaseFailure); }
                throw BoundedProcessHost.ComposeCleanupException(
                    terminationFailure,
                    releaseFailures.ToArray());
            }

            int exitCode = -1;
            long active = 0;
            Exception waitFailure = null;
            try
            {
                NativeWaitStatus waitStatus = BoundedProcessHost.WaitForRetainedProcessHandle(
                    retainedProcessHandle,
                    BoundedProcessHost.GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds),
                    _processId,
                    out exitCode);
                if (waitStatus == NativeWaitStatus.Timeout)
                {
                    throw new NativeWaitException(
                        0,
                        "contained worker " + _processId.ToString(CultureInfo.InvariantCulture) +
                        " did not exit within the termination deadline.");
                }
                if (retainedJobHandle != IntPtr.Zero)
                {
                    active = BoundedProcessHost.PollJobActiveProcessesToZero(
                        retainedJobHandle,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                    if (active != 0)
                    {
                        throw new ContainedWorkerException(
                            "contained worker job still reports " +
                            active.ToString(CultureInfo.InvariantCulture) +
                            " active processes after termination.");
                    }
                }
            }
            catch (Exception error)
            {
                waitFailure = error;
            }

            List<Exception> retainedHandleReleaseFailures = new List<Exception>();
            Exception retainedProcessReleaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                ref retainedProcessHandle,
                "contained worker process");
            if (retainedProcessReleaseFailure != null)
            {
                retainedHandleReleaseFailures.Add(retainedProcessReleaseFailure);
            }
            Exception retainedJobReleaseFailure = BoundedProcessHost.ReleaseRetainedWaitHandle(
                ref retainedJobHandle,
                "contained worker job");
            if (retainedJobReleaseFailure != null)
            {
                retainedHandleReleaseFailures.Add(retainedJobReleaseFailure);
            }
            if (waitFailure != null || retainedHandleReleaseFailures.Count != 0)
            {
                throw BoundedProcessHost.ComposeCleanupException(
                    waitFailure,
                    retainedHandleReleaseFailures.ToArray());
            }

            lock (_sync)
            {
                if (_state != ContainedWorkerState.Cleaned &&
                    _processHandleGeneration == processHandleGeneration &&
                    _processHandle == processHandle &&
                    _jobHandleGeneration == jobHandleGeneration &&
                    _jobHandle == jobHandle)
                {
                    _exitCode = exitCode;
                    _exitCodeKnown = true;
                    _state = ContainedWorkerState.Exited;
                }
            }
            return active;
        }

        private long TerminateToZeroLocked(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            if (_processHandle == IntPtr.Zero)
            {
                throw new ContainedWorkerStateException("the contained worker process handle is already closed.");
            }
            if (_jobHandle != IntPtr.Zero)
            {
                if (!BoundedProcessHost.TerminateJob(_jobHandle))
                {
                    int jobError = Marshal.GetLastWin32Error();
                    throw new Win32Exception(jobError, "TerminateJobObject failed for contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
                }
            }
            else if (!ProcessAlreadyExitedLocked())
            {
                if (!TerminateProcess(_processHandle, 1))
                {
                    int processError = Marshal.GetLastWin32Error();
                    throw new Win32Exception(processError, "TerminateProcess failed for contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
                }
            }
            WaitExactlyLocked(BoundedProcessHost.GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds));
            CaptureExitCodeLocked();
            long active = 0;
            if (_jobHandle != IntPtr.Zero)
            {
                active = BoundedProcessHost.PollJobActiveProcessesToZero(
                    _jobHandle,
                    timeoutStopwatch,
                    timeoutMilliseconds);
                if (active != 0)
                {
                    throw new ContainedWorkerException("contained worker job still reports " + active.ToString(CultureInfo.InvariantCulture) + " active processes after termination.");
                }
            }
            _state = ContainedWorkerState.Exited;
            return active;
        }

        private void WaitExactlyLocked(int timeoutMilliseconds)
        {
            uint raw = WaitForSingleObject(_processHandle, (uint)timeoutMilliseconds);
            if (raw == WAIT_OBJECT_0)
            {
                return;
            }
            if (raw == WAIT_FAILED)
            {
                int error = Marshal.GetLastWin32Error();
                throw new NativeWaitException(error, "WaitForSingleObject failed while terminating contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            if (raw == WAIT_TIMEOUT)
            {
                throw new NativeWaitException(0, "contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + " did not exit within the termination deadline.");
            }
            throw new NativeWaitException(0, "WaitForSingleObject returned unexpected status 0x" + raw.ToString("X8", CultureInfo.InvariantCulture) + " while terminating contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
        }

        private bool ProcessAlreadyExitedLocked()
        {
            uint code;
            if (!GetExitCodeProcess(_processHandle, out code))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "GetExitCodeProcess failed for contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            return code != STILL_ACTIVE;
        }

        private void CaptureExitCodeLocked()
        {
            uint code;
            if (!GetExitCodeProcess(_processHandle, out code))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "GetExitCodeProcess failed for contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            if (code == STILL_ACTIVE)
            {
                throw new ContainedWorkerException("contained worker " + _processId.ToString(CultureInfo.InvariantCulture) + " still reports STILL_ACTIVE after a completed wait.");
            }
            _exitCode = unchecked((int)code);
            _exitCodeKnown = true;
        }

        public void Close(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            lock (_sync)
            {
                CloseLocked(timeoutMilliseconds, true);
            }
        }

        private void CloseLocked(int timeoutMilliseconds, bool throwOnFailure)
        {
            if (_state == ContainedWorkerState.Cleaned)
            {
                return;
            }
            List<Exception> errors = new List<Exception>();
            try
            {
                if (_state != ContainedWorkerState.Exited)
                {
                    TerminateToZeroLocked(timeoutMilliseconds);
                }
                else if (_jobHandle != IntPtr.Zero)
                {
                    long active = BoundedProcessHost.QueryJobActiveProcesses(_jobHandle);
                    if (active != 0)
                    {
                        TerminateToZeroLocked(timeoutMilliseconds);
                    }
                }
            }
            catch (Exception terminationError)
            {
                errors.Add(terminationError);
            }

            if (errors.Count > 0)
            {
                BoundedProcessHost.RetainPendingSession(this);
                _disposeErrors.Clear();
                _disposeErrors.AddRange(errors);
                if (throwOnFailure)
                {
                    Exception primary = new ContainedWorkerException(
                        "contained worker cleanup could not prove process exit and job quiescence; ownership was retained for retry.");
                    throw BoundedProcessHost.ComposeCleanupException(primary, errors.ToArray());
                }
                return;
            }

            BoundedProcessHost.ReleasePendingSession(this);
            _disposeErrors.Clear();
            if (_gate != null)
            {
                try { _gate.Close(); }
                catch (Exception gateError) { errors.Add(gateError); }
                _gate = null;
            }
            if (_threadHandle != IntPtr.Zero)
            {
                IntPtr thread = _threadHandle;
                _threadHandle = IntPtr.Zero;
                if (!CloseHandle(thread))
                {
                    errors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(primary thread) failed."));
                    BoundedProcessHost.QuarantineRawHandle(thread);
                }
            }
            if (_processHandle != IntPtr.Zero)
            {
                IntPtr process = _processHandle;
                _processHandle = IntPtr.Zero;
                _processHandleGeneration++;
                if (!CloseHandle(process))
                {
                    errors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(process) failed."));
                    BoundedProcessHost.QuarantineRawHandle(process);
                }
            }
            if (_jobHandle != IntPtr.Zero)
            {
                IntPtr job = _jobHandle;
                _jobHandle = IntPtr.Zero;
                _jobHandleGeneration++;
                if (!CloseHandle(job))
                {
                    errors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(job) failed."));
                    BoundedProcessHost.QuarantineRawHandle(job);
                }
            }
            if (_pathBinding != null)
            {
                LaunchPathBinding binding = _pathBinding;
                binding.ReleaseAndCleanup(errors);
                _pathBinding = null;
            }
            _state = ContainedWorkerState.Cleaned;
            if (errors.Count > 0)
            {
                _disposeErrors.AddRange(errors);
                if (throwOnFailure)
                {
                    if (errors.Count == 1)
                    {
                        throw errors[0];
                    }
                    throw new AggregateException("contained worker session cleanup failed.", errors.ToArray());
                }
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                CloseLocked(15000, false);
            }
        }
    }

    public sealed class RetainedPathIdentity : IDisposable
    {
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const int FileIdInfo = 0x12;

        [StructLayout(LayoutKind.Sequential)]
        private struct NATIVE_FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public NATIVE_FILETIME ftCreationTime;
            public NATIVE_FILETIME ftLastAccessTime;
            public NATIVE_FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ID_128
        {
            public byte Identifier0;
            public byte Identifier1;
            public byte Identifier2;
            public byte Identifier3;
            public byte Identifier4;
            public byte Identifier5;
            public byte Identifier6;
            public byte Identifier7;
            public byte Identifier8;
            public byte Identifier9;
            public byte Identifier10;
            public byte Identifier11;
            public byte Identifier12;
            public byte Identifier13;
            public byte Identifier14;
            public byte Identifier15;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ID_INFO
        {
            public ulong VolumeSerialNumber;
            public FILE_ID_128 FileId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, int fileInformationClass, out FILE_ID_INFO lpFileInformation, uint dwBufferSize);

        private FileStream _stream;
        private readonly string _fullPath;
        private readonly long _length;
        private readonly uint _volumeSerialNumber;
        private readonly ulong _fileIndex;
        private readonly long _creationFileTimeUtc;
        private readonly long _lastWriteFileTimeUtc;

        private RetainedPathIdentity(FileStream stream, string fullPath, long length, uint volumeSerialNumber, ulong fileIndex, long creationFileTimeUtc, long lastWriteFileTimeUtc)
        {
            _stream = stream;
            _fullPath = fullPath;
            _length = length;
            _volumeSerialNumber = volumeSerialNumber;
            _fileIndex = fileIndex;
            _creationFileTimeUtc = creationFileTimeUtc;
            _lastWriteFileTimeUtc = lastWriteFileTimeUtc;
        }

        public string FullPath { get { return _fullPath; } }
        public long Length { get { return _length; } }
        public uint VolumeSerialNumber { get { return _volumeSerialNumber; } }
        public ulong FileIndex { get { return _fileIndex; } }
        public long CreationTimeFileTimeUtc { get { return _creationFileTimeUtc; } }
        public long LastWriteTimeFileTimeUtc { get { return _lastWriteFileTimeUtc; } }

        public static RetainedPathIdentity OpenAndRetain(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new LaunchPathIdentityException(path, "a launch path is null or empty.");
            }
            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch (ArgumentException pathError) { throw new LaunchPathIdentityException(path, "launch path could not be canonicalized.", pathError); }
            catch (NotSupportedException pathError) { throw new LaunchPathIdentityException(path, "launch path could not be canonicalized.", pathError); }
            catch (PathTooLongException pathError) { throw new LaunchPathIdentityException(path, "launch path could not be canonicalized.", pathError); }

            FileInfo info = new FileInfo(fullPath);
            if (!info.Exists)
            {
                throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' does not exist as a regular file.");
            }
            FileAttributes attributes = info.Attributes;
            if ((attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' is a reparse point.");
            }
            if ((attributes & FileAttributes.Directory) == FileAttributes.Directory)
            {
                throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' is a directory, not a regular file.");
            }

            FileStream stream;
            try { stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch (IOException openError) { throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' could not be opened without write/delete sharing.", openError); }
            catch (UnauthorizedAccessException openError) { throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' could not be opened for read.", openError); }

            try
            {
                BY_HANDLE_FILE_INFORMATION handleInfo = QueryHandleInformation(stream, fullPath);
                if ((handleInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT)
                {
                    throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' resolved to a reparse point.");
                }
                if ((handleInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
                {
                    throw new LaunchPathIdentityException(fullPath, "launch path '" + fullPath + "' resolved to a directory.");
                }
                long length = ((long)handleInfo.nFileSizeHigh << 32) | (long)handleInfo.nFileSizeLow;
                ulong fileIndex = ((ulong)handleInfo.nFileIndexHigh << 32) | (ulong)handleInfo.nFileIndexLow;
                long creation = ToFileTime(handleInfo.ftCreationTime);
                long lastWrite = ToFileTime(handleInfo.ftLastWriteTime);
                return new RetainedPathIdentity(stream, fullPath, length, handleInfo.dwVolumeSerialNumber, fileIndex, creation, lastWrite);
            }
            catch (Exception)
            {
                stream.Dispose();
                throw;
            }
        }

        private static BY_HANDLE_FILE_INFORMATION QueryHandleInformation(FileStream stream, string fullPath)
        {
            Microsoft.Win32.SafeHandles.SafeFileHandle handle = GetValidatedHandle(stream, fullPath);
            BY_HANDLE_FILE_INFORMATION handleInfo;
            if (!GetFileInformationByHandle(handle, out handleInfo))
            {
                int error = Marshal.GetLastWin32Error();
                throw new LaunchPathIdentityException(fullPath, "GetFileInformationByHandle failed for '" + fullPath + "'.", new Win32Exception(error));
            }
            return handleInfo;
        }

        internal static string QueryFileId48(FileStream stream, string fullPath)
        {
            Microsoft.Win32.SafeHandles.SafeFileHandle handle = GetValidatedHandle(stream, fullPath);
            FILE_ID_INFO information;
            uint size = (uint)Marshal.SizeOf(typeof(FILE_ID_INFO));
            if (!GetFileInformationByHandleEx(handle, FileIdInfo, out information, size))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "GetFileInformationByHandleEx(FileIdInfo) failed for '" + fullPath + "'.");
            }

            StringBuilder builder = new StringBuilder(48);
            builder.Append(information.VolumeSerialNumber.ToString("x16", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier0.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier1.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier2.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier3.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier4.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier5.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier6.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier7.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier8.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier9.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier10.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier11.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier12.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier13.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier14.ToString("x2", CultureInfo.InvariantCulture));
            builder.Append(information.FileId.Identifier15.ToString("x2", CultureInfo.InvariantCulture));
            return builder.ToString();
        }

        private static Microsoft.Win32.SafeHandles.SafeFileHandle GetValidatedHandle(FileStream stream, string fullPath)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }
            if (fullPath == null)
            {
                throw new ArgumentNullException("fullPath");
            }
            if (fullPath.Length == 0)
            {
                throw new ArgumentException("A non-empty path is required.", "fullPath");
            }

            Microsoft.Win32.SafeHandles.SafeFileHandle handle;
            try
            {
                handle = stream.SafeFileHandle;
            }
            catch (ObjectDisposedException)
            {
                throw new ObjectDisposedException("stream");
            }
            if (handle.IsClosed)
            {
                throw new ObjectDisposedException("stream");
            }
            return handle;
        }

        private static long ToFileTime(NATIVE_FILETIME value)
        {
            return ((long)value.dwHighDateTime << 32) | (long)(uint)value.dwLowDateTime;
        }

        public void Revalidate()
        {
            if (_stream == null)
            {
                throw new ObjectDisposedException("RetainedPathIdentity");
            }
            BY_HANDLE_FILE_INFORMATION retained = QueryHandleInformation(_stream, _fullPath);
            ulong retainedIndex = ((ulong)retained.nFileIndexHigh << 32) | (ulong)retained.nFileIndexLow;
            if (retained.dwVolumeSerialNumber != _volumeSerialNumber || retainedIndex != _fileIndex)
            {
                throw new LaunchPathIdentityException(_fullPath, "the retained handle for '" + _fullPath + "' no longer reports its original file identity.");
            }
            long retainedLength = ((long)retained.nFileSizeHigh << 32) | (long)retained.nFileSizeLow;
            if (retainedLength != _length || ToFileTime(retained.ftLastWriteTime) != _lastWriteFileTimeUtc)
            {
                throw new LaunchPathIdentityException(_fullPath, "the retained file '" + _fullPath + "' changed length or last-write time during the launch.");
            }

            FileStream reopened;
            try { reopened = new FileStream(_fullPath, FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch (IOException reopenError) { throw new LaunchPathIdentityException(_fullPath, "launch path '" + _fullPath + "' could not be reopened for identity revalidation.", reopenError); }
            catch (UnauthorizedAccessException reopenError) { throw new LaunchPathIdentityException(_fullPath, "launch path '" + _fullPath + "' could not be reopened for identity revalidation.", reopenError); }
            try
            {
                BY_HANDLE_FILE_INFORMATION current = QueryHandleInformation(reopened, _fullPath);
                ulong currentIndex = ((ulong)current.nFileIndexHigh << 32) | (ulong)current.nFileIndexLow;
                if (current.dwVolumeSerialNumber != _volumeSerialNumber || currentIndex != _fileIndex)
                {
                    throw new LaunchPathIdentityException(_fullPath, "the path '" + _fullPath + "' now resolves to a different file than the retained identity.");
                }
            }
            finally
            {
                reopened.Dispose();
            }
        }

        public void Dispose()
        {
            if (_stream != null)
            {
                FileStream current = _stream;
                _stream = null;
                try { current.Dispose(); }
                catch
                {
                    BoundedProcessHost.QuarantineManagedOwner(current);
                    throw;
                }
            }
        }
    }

    internal sealed class RetainedDirectoryIdentity
    {
        private readonly string _fullPath;
        private readonly long _creationFileTimeUtc;
        private readonly bool _owned;

        internal RetainedDirectoryIdentity(string fullPath, long creationFileTimeUtc, bool owned)
        {
            _fullPath = fullPath;
            _creationFileTimeUtc = creationFileTimeUtc;
            _owned = owned;
        }

        public string FullPath { get { return _fullPath; } }
        public long CreationTimeFileTimeUtc { get { return _creationFileTimeUtc; } }
        public bool IsHelperOwned { get { return _owned; } }

        public void Revalidate()
        {
            DirectoryInfo info = new DirectoryInfo(_fullPath);
            if (!info.Exists)
            {
                throw new LaunchPathIdentityException(_fullPath, "working directory '" + _fullPath + "' no longer exists.");
            }
            FileAttributes attributes = info.Attributes;
            if ((attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                throw new LaunchPathIdentityException(_fullPath, "working directory '" + _fullPath + "' became a reparse point.");
            }
            if ((attributes & FileAttributes.Directory) != FileAttributes.Directory)
            {
                throw new LaunchPathIdentityException(_fullPath, "working directory '" + _fullPath + "' is no longer an ordinary directory.");
            }
            if (info.CreationTimeUtc.ToFileTimeUtc() != _creationFileTimeUtc)
            {
                throw new LaunchPathIdentityException(_fullPath, "working directory '" + _fullPath + "' was replaced during the launch.");
            }
        }
    }

    internal sealed class LaunchPathBinding
    {
        private readonly RetainedPathIdentity _executable;
        private readonly RetainedPathIdentity[] _sources;
        private readonly RetainedDirectoryIdentity _workingDirectory;
        private bool _released;

        internal LaunchPathBinding(RetainedPathIdentity executable, RetainedPathIdentity[] sources, RetainedDirectoryIdentity workingDirectory)
        {
            _executable = executable;
            _sources = sources;
            _workingDirectory = workingDirectory;
        }

        internal string ExecutableFullPath { get { return _executable.FullPath; } }
        internal string WorkingDirectoryFullPath { get { return _workingDirectory.FullPath; } }
        internal RetainedPathIdentity Executable { get { return _executable; } }
        internal RetainedDirectoryIdentity WorkingDirectory { get { return _workingDirectory; } }

        internal void ReleaseAndCleanup(List<Exception> cleanupErrors)
        {
            if (_released)
            {
                return;
            }

            try { _executable.Revalidate(); }
            catch (Exception identityError) { cleanupErrors.Add(identityError); }
            for (int index = 0; index < _sources.Length; index++)
            {
                try { _sources[index].Revalidate(); }
                catch (Exception identityError) { cleanupErrors.Add(identityError); }
            }
            bool workingDirectoryValidated = false;
            try
            {
                _workingDirectory.Revalidate();
                workingDirectoryValidated = true;
            }
            catch (Exception identityError) { cleanupErrors.Add(identityError); }

            try { _executable.Dispose(); }
            catch (Exception disposeError) { cleanupErrors.Add(disposeError); }
            for (int index = 0; index < _sources.Length; index++)
            {
                try { _sources[index].Dispose(); }
                catch (Exception disposeError) { cleanupErrors.Add(disposeError); }
            }

            if (_workingDirectory.IsHelperOwned && workingDirectoryValidated)
            {
                try { Directory.Delete(_workingDirectory.FullPath, true); }
                catch (Exception deleteError) { cleanupErrors.Add(deleteError); }
            }
            _released = true;
        }

    }

    public static class BoundedProcessHost
    {
        public const string Version = "pspkt-phase4-bounded-process-2";
        public const int ResumeFailureNativePinnedError = 0x00000005;

        public const string GateEventVariable = "PSPKT_PHASE4_GATE_EVENT";
        public const string SupervisorGateEventVariable = "PSPKT_PHASE4_SUPERVISOR_GATE_EVENT";
        public const string DescendantGateEventVariable = "PSPKT_PHASE4_DESCENDANT_GATE_EVENT";

        private const string ReservedPrefix = "PSPKT_PHASE4_";

        private const uint ERROR_ALREADY_EXISTS = 183;
        private const int ERROR_ACCESS_DENIED = 5;
        private const uint SDDL_REVISION_1 = 1;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint JOB_OBJECT_QUERY = 0x00000004;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint ContainedNativeCreationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint WAIT_FAILED = 0xFFFFFFFF;
        private const uint RESUME_THREAD_FAILED = 0xFFFFFFFF;
        private const uint STILL_ACTIVE_STATUS = 259;
        private const int MaxCommandLineLength = 32767;
        private const int MaxEnvironmentValueLength = 32767;
        private const int MaxEnvironmentBlockLength = 32767;
        private const int MaxReceiptLeafLength = 64;
        private const int ReceiptCapBytes = 320;
        private const int IdentityCapBytes = 320;
        private const int DescendantReceiptCapBytes = 256;
        private const int FailFastSentinelCapBytes = 2048;
        private const int CleanupBudgetProbeDeadlineMilliseconds = 300;
        private const int CleanupBudgetProbeSchedulerToleranceMilliseconds = 500;
        private const int DrainerForcedCloseReserveMilliseconds = 500;
        private const int ProbeReadEntryDeadlineMilliseconds = 5000;
        private const int WaitPreemptionProbeCleanupDeadlineMilliseconds = 3000;
        private const int WaitPreemptionProbeLongWaitMilliseconds = 5000;
        private const int WaitPreemptionProbeRepeatCount = 4;
        private const int WaitPreemptionProbeSettleMilliseconds = 200;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public IntPtr MinimumWorkingSetSize;
            public IntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public IntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public IntPtr ProcessMemoryLimit;
            public IntPtr JobMemoryLimit;
            public IntPtr PeakProcessMemoryUsed;
            public IntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(IntPtr hJob, int JobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength, out uint lpReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessInJob(IntPtr ProcessHandle, IntPtr JobHandle, [MarshalAs(UnmanagedType.Bool)] out bool Result);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSDRevision, out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string lpApplicationName,
            IntPtr lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(IntPtr hProcess, out long lpCreationTime, out long lpExitTime, out long lpKernelTime, out long lpUserTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetProcessId(IntPtr Process);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint PROCESS_TERMINATE = 0x00000001;
        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const int JobObjectBasicProcessIdList = 3;
        private const int ERROR_MORE_DATA = 234;
        private const int ERROR_NO_MORE_FILES = 18;
        private const int MaxJobProcessMembers = 64;
        private const int MaxToolhelpEntries = 65536;
        private const int MaxOutOfJobDescendants = 64;
        private const int MaxParentGraphDepth = 64;
        private const int JobProcessIdListResizeRetryLimit = 8;
        private const int JobProcessSnapshotCaptureRetryLimit = 8;
        private const int OutOfJobTerminationTimeoutMilliseconds = 15000;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32W
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_PROCESS_ID_LIST_HEADER
        {
            public uint NumberOfAssignedProcesses;
            public uint NumberOfProcessIdsInList;
        }

        private static readonly object _diagSync = new object();
        private static readonly object _ownershipSync = new object();
        private static readonly List<object> _pendingSessions = new List<object>();
        private static readonly List<QuarantinedLaunch> _quarantinedLaunches = new List<QuarantinedLaunch>();
        private static long _jobCreate;
        private static long _eventCreate;
        private static long _eventOpen;
        private static long _processStart;
        private static long _assignmentAttempt;
        private static long _snapshotAccess;
        private static long _rejectCombinedSeam;
        private static long _rejectBasic;
        private static long _rejectEventName;
        private static long _rejectEmptyCorrelation;
        private static long _rejectPauseConfig;
        private static long _rejectEnvironment;
        private static long _rejectPathIdentity;
        private static long _retainedWaitCapabilityCount;
        private static long _accessLogHighWater;
        private static long _accessLogNextSequence = 1;
        private static bool _accessLogOverflow;
        private static readonly List<AccessLogEntry> _accessLog = new List<AccessLogEntry>();
        private const int AccessLogCapacity = 4096;

        private sealed class CleanupProof
        {
            internal bool OwnsStartedProcess;
            internal bool ProcessExited;
            internal bool OwnsAssignedJob;
            internal bool JobZeroProven;
            internal bool OwnsDrainerResources;
            internal bool DrainersQuiesced;

            internal bool CanRelease
            {
                get
                {
                    return (!OwnsStartedProcess || ProcessExited)
                        && (!OwnsAssignedJob || JobZeroProven)
                        && (!OwnsDrainerResources || DrainersQuiesced);
                }
            }
        }

        private sealed class QuarantinedLaunch
        {
            private readonly object[] _managedOwners;
            private readonly IntPtr[] _rawHandles;

            internal QuarantinedLaunch(object[] managedOwners, IntPtr[] rawHandles)
            {
                _managedOwners = managedOwners;
                _rawHandles = rawHandles;
            }
        }

        internal static void RetainPendingSession(object session)
        {
            lock (_ownershipSync)
            {
                if (!_pendingSessions.Contains(session))
                {
                    _pendingSessions.Add(session);
                }
            }
        }

        internal static void ReleasePendingSession(object session)
        {
            lock (_ownershipSync)
            {
                _pendingSessions.Remove(session);
            }
        }

        internal static void QuarantineRawHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return;
            }
            QuarantineLaunch(new object[0], new IntPtr[] { handle });
        }

        internal static void QuarantineManagedOwner(object owner)
        {
            if (owner == null)
            {
                return;
            }
            QuarantineLaunch(new object[] { owner }, new IntPtr[0]);
        }

        private static void QuarantineLaunch(object[] managedOwners, IntPtr[] rawHandles)
        {
            lock (_ownershipSync)
            {
                _quarantinedLaunches.Add(new QuarantinedLaunch(managedOwners, rawHandles));
            }
        }

        internal static void RecordJobCreate()
        {
            lock (_diagSync) { _jobCreate++; }
        }

        internal static void RecordProcessStart()
        {
            lock (_diagSync) { _processStart++; }
        }

        internal static void RecordAssignmentAttempt()
        {
            lock (_diagSync) { _assignmentAttempt++; }
        }

        internal static void RecordSnapshotAccess()
        {
            lock (_diagSync) { _snapshotAccess++; }
        }

        internal static void RecordPathIdentityReject()
        {
            lock (_diagSync) { _rejectPathIdentity++; }
        }

        internal static long GetAssignmentAttemptCount()
        {
            lock (_diagSync) { return _assignmentAttempt; }
        }

        internal static void RecordReject(PreNativeRejectReason reason)
        {
            lock (_diagSync)
            {
                switch (reason)
                {
                    case PreNativeRejectReason.CombinedSeam: _rejectCombinedSeam++; break;
                    case PreNativeRejectReason.Basic: _rejectBasic++; break;
                    case PreNativeRejectReason.EventName: _rejectEventName++; break;
                    case PreNativeRejectReason.EmptyCorrelation: _rejectEmptyCorrelation++; break;
                    case PreNativeRejectReason.PauseConfig: _rejectPauseConfig++; break;
                    case PreNativeRejectReason.Environment: _rejectEnvironment++; break;
                    default: throw new ArgumentOutOfRangeException("reason");
                }
            }
        }

        internal static void RecordEventCreate(Guid correlationId, EventRole role, string eventName, uint desiredAccess)
        {
            lock (_diagSync)
            {
                _eventCreate++;
                AppendAccessLocked(correlationId, role, eventName, desiredAccess);
            }
        }

        internal static void RecordEventOpen(Guid correlationId, EventRole role, string eventName, uint desiredAccess)
        {
            lock (_diagSync)
            {
                _eventOpen++;
                AppendAccessLocked(correlationId, role, eventName, desiredAccess);
            }
        }

        private static void AppendAccessLocked(Guid correlationId, EventRole role, string eventName, uint desiredAccess)
        {
            if (_accessLog.Count >= AccessLogCapacity)
            {
                _accessLogOverflow = true;
                return;
            }
            long sequence = _accessLogNextSequence;
            _accessLogNextSequence++;
            _accessLogHighWater = sequence;
            _accessLog.Add(new AccessLogEntry(sequence, correlationId, role, eventName, desiredAccess));
        }

        public static BoundedProcessDiagnosticsSnapshot GetDiagnosticsSnapshot()
        {
            lock (_ownershipSync)
            {
                lock (_diagSync)
                {
                    AccessLogEntry[] entries = new AccessLogEntry[_accessLog.Count];
                    _accessLog.CopyTo(entries);
                    return new BoundedProcessDiagnosticsSnapshot(
                        _jobCreate, _eventCreate, _eventOpen, _processStart, _assignmentAttempt,
                        _rejectCombinedSeam, _rejectBasic, _rejectEventName, _rejectEmptyCorrelation,
                        _rejectPauseConfig, _rejectEnvironment, _accessLogHighWater, _accessLogOverflow,
                        _snapshotAccess, _rejectPathIdentity, _pendingSessions.Count,
                        _quarantinedLaunches.Count, entries);
                }
            }
        }

        internal static void ValidateEventNameGrammar(string name)
        {
            if (name == null)
            {
                throw new EventNameGrammarException(null, "event name is null.");
            }
            const string prefix = "Local\\PspktPhase4";
            if (!name.StartsWith(prefix, StringComparison.Ordinal))
            {
                throw new EventNameGrammarException(name, "event name must begin with the exact prefix 'Local\\PspktPhase4'.");
            }
            if (name.Length > 112)
            {
                throw new EventNameGrammarException(name, "event name exceeds 112 characters.");
            }
            string suffix = name.Substring(prefix.Length);
            if (suffix.Length < 1 || suffix.Length > 95)
            {
                throw new EventNameGrammarException(name, "event name suffix length must be between 1 and 95 characters.");
            }
            for (int index = 0; index < suffix.Length; index++)
            {
                char c = suffix[index];
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
                if (!ok)
                {
                    throw new EventNameGrammarException(name, "event name suffix contains an illegal character.");
                }
            }
        }

        private static bool IsValidEnvironmentName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return false;
            }
            if (name.Length > 64)
            {
                return false;
            }
            char first = name[0];
            bool firstOk = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_';
            if (!firstOk)
            {
                return false;
            }
            for (int index = 1; index < name.Length; index++)
            {
                char c = name[index];
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
                if (!ok)
                {
                    return false;
                }
            }
            return true;
        }

        private static bool IsValidEnvironmentValue(string value)
        {
            if (value == null)
            {
                return false;
            }
            if (value.Length > MaxEnvironmentValueLength)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                if (value[index] == '\0')
                {
                    return false;
                }
            }
            return true;
        }

        private static Win32Exception Win32(string api)
        {
            return new Win32Exception(Marshal.GetLastWin32Error(), api + " failed.");
        }

        public static string QuoteWindowsCommandLineArgument(string argument)
        {
            if (argument == null)
            {
                throw new ArgumentNullException("argument");
            }
            if (argument.Length > 0 && argument.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            {
                return argument;
            }
            StringBuilder builder = new StringBuilder();
            builder.Append('"');
            for (int index = 0; ; index++)
            {
                int backslashes = 0;
                while (index < argument.Length && argument[index] == '\\')
                {
                    index++;
                    backslashes++;
                }
                if (index == argument.Length)
                {
                    builder.Append('\\', backslashes * 2);
                    break;
                }
                if (argument[index] == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                    builder.Append('"');
                }
                else
                {
                    builder.Append('\\', backslashes);
                    builder.Append(argument[index]);
                }
            }
            builder.Append('"');
            return builder.ToString();
        }

        internal static string BuildCommandLine(string[] arguments)
        {
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }
            StringBuilder builder = new StringBuilder();
            for (int index = 0; index < arguments.Length; index++)
            {
                if (index > 0)
                {
                    builder.Append(' ');
                }
                builder.Append(QuoteWindowsCommandLineArgument(arguments[index]));
            }
            return builder.ToString();
        }

        public static string BuildNativeCommandLine(string fullExecutablePath, string[] arguments)
        {
            if (fullExecutablePath == null)
            {
                throw new ArgumentNullException("fullExecutablePath");
            }
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }
            RequireNoNul(fullExecutablePath, "executable path");
            StringBuilder builder = new StringBuilder();
            builder.Append(QuoteWindowsCommandLineArgument(fullExecutablePath));
            for (int index = 0; index < arguments.Length; index++)
            {
                string argument = arguments[index];
                if (argument == null)
                {
                    throw new NativeCommandLineException("argument at index " + index.ToString(CultureInfo.InvariantCulture) + " is null.");
                }
                RequireNoNul(argument, "argument");
                builder.Append(' ');
                builder.Append(QuoteWindowsCommandLineArgument(argument));
            }
            if (builder.Length + 1 > MaxCommandLineLength)
            {
                throw new NativeCommandLineException("effective command line exceeds the 32767 code-unit limit including the terminating NUL.");
            }
            return builder.ToString();
        }

        internal static void ValidateEffectiveCommandLine(string fullExecutablePath, string[] arguments)
        {
            if (fullExecutablePath == null)
            {
                throw new ArgumentNullException("fullExecutablePath");
            }
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }
            RequireNoNul(fullExecutablePath, "executable path");
            StringBuilder builder = new StringBuilder();
            builder.Append(QuoteWindowsCommandLineArgument(fullExecutablePath));
            for (int index = 0; index < arguments.Length; index++)
            {
                string argument = arguments[index];
                if (argument == null)
                {
                    throw new NativeCommandLineException("argument at index " + index.ToString(CultureInfo.InvariantCulture) + " is null.");
                }
                RequireNoNul(argument, "argument");
                builder.Append(' ');
                builder.Append(QuoteWindowsCommandLineArgument(argument));
            }
            if (builder.Length + 1 > MaxCommandLineLength)
            {
                throw new NativeCommandLineException("effective command line exceeds the 32767 code-unit limit including the terminating NUL.");
            }
        }

        private static void RequireNoNul(string value, string label)
        {
            for (int index = 0; index < value.Length; index++)
            {
                if (value[index] == '\0')
                {
                    throw new NativeCommandLineException(label + " contains an embedded NUL character.");
                }
            }
        }

        public static int SecurityAttributesSize()
        {
            return Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        }

        public static int AccountingInformationSize()
        {
            return Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        }

        private static IntPtr BuildJobSecurityAttributes(out IntPtr securityDescriptor)
        {
            string userSid;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity.User == null)
                {
                    throw new UnsupportedCertificationHostException("the current Windows identity does not expose a user SID.");
                }
                userSid = identity.User.Value;
            }
            string sddl = "D:(A;;GA;;;" + userSid + ")(A;;GA;;;SY)";
            IntPtr descriptor;
            uint descriptorSize;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, out descriptor, out descriptorSize))
            {
                throw Win32("ConvertStringSecurityDescriptorToSecurityDescriptor");
            }
            securityDescriptor = descriptor;
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.lpSecurityDescriptor = descriptor;
            attributes.bInheritHandle = 0;
            IntPtr buffer = Marshal.AllocHGlobal(attributes.nLength);
            Marshal.StructureToPtr(attributes, buffer, false);
            return buffer;
        }

        private static IntPtr CreateConfiguredJob(IntPtr jobSecurityAttributes)
        {
            RecordJobCreate();
            IntPtr job = CreateJobObjectW(jobSecurityAttributes, null);
            if (job == IntPtr.Zero)
            {
                throw Win32("CreateJobObject");
            }
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
                {
                    Win32Exception failure = Win32("SetInformationJobObject(kill-on-close)");
                    if (!CloseHandle(job))
                    {
                        Win32Exception closeFailure = Win32("CloseHandle(unconfigured job)");
                        QuarantineRawHandle(job);
                        throw ComposeCleanupException(failure, new Exception[] { closeFailure });
                    }
                    throw failure;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return job;
        }

        internal static long QueryJobActiveProcesses(IntPtr job)
        {
            int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, buffer, (uint)size, out returned))
                {
                    throw Win32("QueryInformationJobObject");
                }
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info =
                    (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(buffer, typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
                return info.ActiveProcesses;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        internal static long PollJobActiveProcessesToZero(IntPtr job, int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            Stopwatch stopwatch = Stopwatch.StartNew();
            return PollJobActiveProcessesToZero(job, stopwatch, timeoutMilliseconds);
        }

        internal static long PollJobActiveProcessesToZero(IntPtr job, Stopwatch stopwatch, int timeoutMilliseconds)
        {
            if (stopwatch == null)
            {
                throw new ArgumentNullException("stopwatch");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            long active = QueryJobActiveProcesses(job);
            while (active > 0)
            {
                int remainingMilliseconds = GetRemainingTimeoutMilliseconds(stopwatch, timeoutMilliseconds);
                if (remainingMilliseconds == 0)
                {
                    break;
                }
                Thread.Sleep(Math.Min(10, remainingMilliseconds));
                active = QueryJobActiveProcesses(job);
            }
            return active;
        }

        internal static int GetRemainingTimeoutMilliseconds(Stopwatch stopwatch, int timeoutMilliseconds)
        {
            if (stopwatch == null)
            {
                throw new ArgumentNullException("stopwatch");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            long elapsedMilliseconds = stopwatch.ElapsedMilliseconds;
            if (elapsedMilliseconds < 0)
            {
                throw new OverflowException("the monotonic timeout clock reported a negative elapsed duration.");
            }
            if (elapsedMilliseconds >= timeoutMilliseconds)
            {
                return 0;
            }
            long remainingMilliseconds = checked((long)timeoutMilliseconds - elapsedMilliseconds);
            if (remainingMilliseconds < 0 || remainingMilliseconds > int.MaxValue)
            {
                throw new OverflowException("the remaining timeout is outside the supported Int32 range.");
            }
            return checked((int)remainingMilliseconds);
        }

        internal static IntPtr DuplicateProcessWaitHandle(IntPtr processHandle)
        {
            return DuplicateRetainedWaitHandle(
                processHandle,
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                "process");
        }

        internal static IntPtr DuplicateJobQueryHandle(IntPtr jobHandle)
        {
            return DuplicateRetainedWaitHandle(
                jobHandle,
                JOB_OBJECT_QUERY,
                "job");
        }

        private static IntPtr DuplicateRetainedWaitHandle(
            IntPtr sourceHandle,
            uint desiredAccess,
            string handleKind)
        {
            if (sourceHandle == IntPtr.Zero)
            {
                throw new ArgumentException("a retained " + handleKind + " wait handle cannot be duplicated from a null source handle.");
            }
            IntPtr retainedHandle;
            using (Process currentProcess = Process.GetCurrentProcess())
            {
                if (!DuplicateHandle(
                    currentProcess.Handle,
                    sourceHandle,
                    currentProcess.Handle,
                    out retainedHandle,
                    desiredAccess,
                    false,
                    0))
                {
                    throw Win32("DuplicateHandle(retained " + handleKind + " wait capability)");
                }
            }
            Interlocked.Increment(ref _retainedWaitCapabilityCount);
            return retainedHandle;
        }

        internal static NativeWaitStatus WaitForRetainedProcessHandle(
            IntPtr retainedProcessHandle,
            int timeoutMilliseconds,
            int processId,
            out int exitCode)
        {
            if (retainedProcessHandle == IntPtr.Zero)
            {
                throw new ArgumentException("a retained process wait handle is required.");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            exitCode = -1;
            uint raw = WaitForSingleObject(retainedProcessHandle, (uint)timeoutMilliseconds);
            if (raw == WAIT_TIMEOUT)
            {
                return NativeWaitStatus.Timeout;
            }
            if (raw == WAIT_FAILED)
            {
                throw new NativeWaitException(
                    Marshal.GetLastWin32Error(),
                    "WaitForSingleObject failed for retained process " +
                    processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            if (raw != WAIT_OBJECT_0)
            {
                throw new NativeWaitException(
                    0,
                    "WaitForSingleObject returned unexpected status 0x" +
                    raw.ToString("X8", CultureInfo.InvariantCulture) +
                    " for retained process " +
                    processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            uint nativeExitCode;
            if (!GetExitCodeProcess(retainedProcessHandle, out nativeExitCode))
            {
                throw Win32("GetExitCodeProcess(retained process wait capability)");
            }
            if (nativeExitCode == STILL_ACTIVE_STATUS)
            {
                throw new NativeWaitException(
                    0,
                    "retained process " +
                    processId.ToString(CultureInfo.InvariantCulture) +
                    " still reports STILL_ACTIVE after a completed wait.");
            }
            exitCode = unchecked((int)nativeExitCode);
            return NativeWaitStatus.Object0;
        }

        internal static Exception ReleaseRetainedWaitHandle(
            ref IntPtr retainedHandle,
            string handleDescription)
        {
            if (retainedHandle == IntPtr.Zero)
            {
                return null;
            }
            IntPtr ownedHandle = retainedHandle;
            retainedHandle = IntPtr.Zero;
            if (!CloseHandle(ownedHandle))
            {
                Exception closeFailure = Win32(
                    "CloseHandle(retained " + handleDescription + " wait capability)");
                QuarantineRawHandle(ownedHandle);
                return closeFailure;
            }
            Interlocked.Decrement(ref _retainedWaitCapabilityCount);
            return null;
        }

        internal static bool TerminateJob(IntPtr job)
        {
            return TerminateJobObject(job, 1);
        }

        internal static JobAccountingSnapshot QueryJobAccountingInfo(IntPtr job)
        {
            int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, buffer, (uint)size, out returned))
                {
                    throw Win32("QueryInformationJobObject(accounting)");
                }
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info =
                    (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(buffer, typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
                return new JobAccountingSnapshot((long)info.TotalProcesses, (long)info.ActiveProcesses, (long)info.TotalTerminatedProcesses);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        internal static bool TryQueryImagePathFromHandle(IntPtr handle, out string imagePath)
        {
            imagePath = null;
            if (handle == IntPtr.Zero)
            {
                return false;
            }
            uint capacity = 1024;
            StringBuilder builder = new StringBuilder((int)capacity);
            uint size = capacity;
            if (QueryFullProcessImageNameW(handle, 0, builder, ref size))
            {
                imagePath = builder.ToString();
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (error == 122)
            {
                capacity = 32768;
                builder = new StringBuilder((int)capacity);
                size = capacity;
                if (QueryFullProcessImageNameW(handle, 0, builder, ref size))
                {
                    imagePath = builder.ToString();
                    return true;
                }
            }
            return false;
        }

        internal static bool TryQueryRetainedIdentity(IntPtr handle, out int processId, out long creationFileTime, out string imagePath, out bool live)
        {
            processId = 0;
            creationFileTime = 0;
            imagePath = null;
            live = false;
            if (handle == IntPtr.Zero)
            {
                return false;
            }
            int pid = GetProcessId(handle);
            if (pid == 0)
            {
                return false;
            }
            long creation;
            long exit;
            long kernel;
            long user;
            if (!GetProcessTimes(handle, out creation, out exit, out kernel, out user))
            {
                return false;
            }
            uint code;
            if (!GetExitCodeProcess(handle, out code))
            {
                return false;
            }
            processId = pid;
            creationFileTime = creation;
            live = (code == STILL_ACTIVE_STATUS);
            string image;
            if (TryQueryImagePathFromHandle(handle, out image))
            {
                imagePath = image;
            }
            else
            {
                imagePath = null;
            }
            return true;
        }

        internal static bool CloseRetainedHandle(IntPtr handle, out Exception closeError)
        {
            closeError = null;
            if (handle == IntPtr.Zero)
            {
                return true;
            }
            if (CloseHandle(handle))
            {
                return true;
            }
            closeError = new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(retained snapshot process handle) failed.");
            QuarantineRawHandle(handle);
            return false;
        }

        private static Exception[] CloseRetainedHandles(IList<IntPtr> handles)
        {
            List<Exception> closeErrors = new List<Exception>();
            for (int index = 0; index < handles.Count; index++)
            {
                Exception closeError;
                if (!CloseRetainedHandle(handles[index], out closeError))
                {
                    closeErrors.Add(closeError);
                }
            }
            return closeErrors.ToArray();
        }

        internal static Exception ComposeSnapshotCloseException(Exception[] errors)
        {
            if (errors == null || errors.Length == 0)
            {
                return new ContainedWorkerException("job process snapshot disposal failed.");
            }
            if (errors.Length == 1)
            {
                return errors[0];
            }
            return new AggregateException("job process snapshot disposal failed to close one or more retained handles.", errors);
        }

        internal static int[] QueryJobProcessIdList(IntPtr job)
        {
            int capacity = 8;
            for (int attempt = 0; attempt <= JobProcessIdListResizeRetryLimit; attempt++)
            {
                int bufferSize = checked(8 + (capacity * IntPtr.Size));
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    uint returned;
                    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)bufferSize, out returned))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ERROR_MORE_DATA)
                        {
                            if (capacity >= MaxJobProcessMembers)
                            {
                                throw new ContainedWorkerException("the job process id list exceeds the 64-member cap.");
                            }
                            capacity = Math.Min(capacity * 2, MaxJobProcessMembers);
                            continue;
                        }
                        throw Win32("QueryInformationJobObject(process id list)");
                    }
                    uint assigned = (uint)Marshal.ReadInt32(buffer, 0);
                    uint inList = (uint)Marshal.ReadInt32(buffer, 4);
                    if (assigned > MaxJobProcessMembers)
                    {
                        throw new ContainedWorkerException("the job reports more than 64 assigned processes.");
                    }
                    if (inList < assigned)
                    {
                        if (capacity >= MaxJobProcessMembers)
                        {
                            throw new ContainedWorkerException("the job process id list exceeds the 64-member cap.");
                        }
                        capacity = Math.Min(capacity * 2, MaxJobProcessMembers);
                        continue;
                    }
                    List<int> ids = new List<int>((int)inList);
                    for (int index = 0; index < (int)inList; index++)
                    {
                        IntPtr raw = Marshal.ReadIntPtr(buffer, 8 + (index * IntPtr.Size));
                        ids.Add(unchecked((int)raw.ToInt64()));
                    }
                    ids.Sort();
                    for (int index = 1; index < ids.Count; index++)
                    {
                        if (ids[index] == ids[index - 1])
                        {
                            throw new ContainedWorkerException("the job process id list contains a duplicate process id.");
                        }
                    }
                    return ids.ToArray();
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            throw new ContainedWorkerException("the job process id list could not be read within the resize-retry bound.");
        }

        internal static Dictionary<int, int> ToolhelpParentMap()
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                throw Win32("CreateToolhelp32Snapshot");
            }
            try
            {
                Dictionary<int, int> map = new Dictionary<int, int>();
                PROCESSENTRY32W entry = new PROCESSENTRY32W();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
                if (!Process32FirstW(snapshot, ref entry))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ERROR_NO_MORE_FILES)
                    {
                        return map;
                    }
                    throw Win32("Process32FirstW");
                }
                int count = 0;
                do
                {
                    count++;
                    if (count > MaxToolhelpEntries)
                    {
                        throw new ContainedWorkerException("the Toolhelp process walk exceeded the 65536-entry cap.");
                    }
                    map[unchecked((int)entry.th32ProcessID)] = unchecked((int)entry.th32ParentProcessID);
                }
                while (Process32NextW(snapshot, ref entry));
                int nextError = Marshal.GetLastWin32Error();
                if (nextError != ERROR_NO_MORE_FILES)
                {
                    throw new Win32Exception(nextError, "Process32NextW failed.");
                }
                return map;
            }
            finally
            {
                CloseHandle(snapshot);
            }
        }

        internal static JobProcessSnapshot CaptureJobProcessSnapshot(IntPtr job, int rootProcessId, long rootCreationFileTime, string rootImagePath)
        {
            for (int attempt = 0; attempt < JobProcessSnapshotCaptureRetryLimit; attempt++)
            {
                JobProcessSnapshot snapshot = TryCaptureJobProcessSnapshotOnce(job, rootProcessId, rootCreationFileTime, rootImagePath);
                if (snapshot != null)
                {
                    return snapshot;
                }
            }
            throw new ContainedWorkerException("the job process snapshot could not be captured stably within the retry bound.");
        }

        private static JobProcessSnapshot TryCaptureJobProcessSnapshotOnce(IntPtr job, int rootProcessId, long rootCreationFileTime, string rootImagePath)
        {
            int[] jobPids = QueryJobProcessIdList(job);
            List<IntPtr> handles = new List<IntPtr>(jobPids.Length);
            List<JobProcessMember> members = new List<JobProcessMember>(jobPids.Length);
            bool transferred = false;
            bool cleanupAttempted = false;
            try
            {
                Dictionary<int, int> parentMap = ToolhelpParentMap();
                for (int index = 0; index < jobPids.Length; index++)
                {
                    int pid = jobPids[index];
                    IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, (uint)pid);
                    if (handle == IntPtr.Zero)
                    {
                        return null;
                    }
                    handles.Add(handle);
                    int actualPid;
                    long creation;
                    string image;
                    bool live;
                    if (!TryQueryRetainedIdentity(handle, out actualPid, out creation, out image, out live))
                    {
                        return null;
                    }
                    if (actualPid != pid || image == null)
                    {
                        return null;
                    }
                    int parentPid;
                    if (!parentMap.TryGetValue(pid, out parentPid))
                    {
                        return null;
                    }
                    members.Add(new JobProcessMember(pid, parentPid, creation, image));
                }

                if (rootProcessId != 0 && rootImagePath != null)
                {
                    for (int index = 0; index < members.Count; index++)
                    {
                        if (members[index].ProcessId != rootProcessId)
                        {
                            continue;
                        }
                        if (members[index].CreationFileTimeUtc != rootCreationFileTime)
                        {
                            throw new UnsupportedCertificationHostException("the retained root creation time does not match the live job member; identity drift.");
                        }
                        if (!string.Equals(members[index].CanonicalImagePath, rootImagePath, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new UnsupportedCertificationHostException("the retained root image path does not match the live job member; identity drift.");
                        }
                        break;
                    }
                }
                else if (rootProcessId != 0)
                {
                    for (int index = 0; index < members.Count; index++)
                    {
                        if (members[index].ProcessId != rootProcessId)
                        {
                            continue;
                        }
                        if (members[index].CreationFileTimeUtc != rootCreationFileTime)
                        {
                            throw new UnsupportedCertificationHostException("the retained root creation time does not match the live job member; identity drift.");
                        }
                        throw new UnsupportedCertificationHostException("the root member is present in the live job but no pinned root image path was supplied; refusing null-bypass identity validation.");
                    }
                }

                Dictionary<int, bool> jobSet = BuildIntSet(jobPids);
                List<int> outOfJob = FindOutOfJobDescendants(parentMap, jobSet, rootProcessId, jobPids);

                int[] jobPidsSecond = QueryJobProcessIdList(job);
                if (!IntArraysEqual(jobPids, jobPidsSecond))
                {
                    return null;
                }
                Dictionary<int, int> parentMapSecond = ToolhelpParentMap();
                List<int> outOfJobSecond = FindOutOfJobDescendants(parentMapSecond, BuildIntSet(jobPidsSecond), rootProcessId, jobPidsSecond);
                if (!IntListSetEqual(outOfJob, outOfJobSecond))
                {
                    return null;
                }
                if (!OutOfJobParentChainsEqual(outOfJob, parentMap, parentMapSecond))
                {
                    return null;
                }

                if (outOfJob.Count > 0)
                {
                    HandleStableOutOfJobSubtree(job, outOfJob, parentMap, members, rootProcessId, rootCreationFileTime, rootImagePath);
                    return null;
                }

                for (int index = 0; index < handles.Count; index++)
                {
                    int actualPid;
                    long creation;
                    string image;
                    bool live;
                    if (!TryQueryRetainedIdentity(handles[index], out actualPid, out creation, out image, out live))
                    {
                        return null;
                    }
                    JobProcessMember member = members[index];
                    if (!live || actualPid != member.ProcessId || creation != member.CreationFileTimeUtc)
                    {
                        return null;
                    }
                    if (image != null && !string.Equals(image, member.CanonicalImagePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }
                }

                int[] jobPidsThird = QueryJobProcessIdList(job);
                if (!IntArraysEqual(jobPids, jobPidsThird))
                {
                    return null;
                }

                JobProcessMember[] memberArray = members.ToArray();
                IntPtr[] handleArray = handles.ToArray();
                JobProcessSnapshot snapshot = new JobProcessSnapshot(memberArray, handleArray);
                transferred = true;
                return snapshot;
            }
            catch (Exception primary)
            {
                cleanupAttempted = true;
                Exception[] cleanupErrors = CloseRetainedHandles(handles);
                if (cleanupErrors.Length > 0)
                {
                    throw ComposeCleanupException(primary, cleanupErrors);
                }
                throw;
            }
            finally
            {
                if (!transferred && !cleanupAttempted)
                {
                    Exception[] cleanupErrors = CloseRetainedHandles(handles);
                    if (cleanupErrors.Length > 0)
                    {
                        throw ComposeSnapshotCloseException(cleanupErrors);
                    }
                }
            }
        }

        private static List<int> FindOutOfJobDescendants(Dictionary<int, int> parentMap, Dictionary<int, bool> jobSet, int rootProcessId, int[] jobPids)
        {
            Dictionary<int, List<int>> children = new Dictionary<int, List<int>>();
            foreach (KeyValuePair<int, int> pair in parentMap)
            {
                int childPid = pair.Key;
                int parentPid = pair.Value;
                List<int> list;
                if (!children.TryGetValue(parentPid, out list))
                {
                    list = new List<int>();
                    children[parentPid] = list;
                }
                list.Add(childPid);
            }

            List<int> roots = new List<int>();
            if (jobSet.ContainsKey(rootProcessId) || parentMap.ContainsKey(rootProcessId))
            {
                roots.Add(rootProcessId);
            }
            for (int index = 0; index < jobPids.Length; index++)
            {
                roots.Add(jobPids[index]);
            }

            Dictionary<int, bool> visited = new Dictionary<int, bool>();
            Dictionary<int, bool> outOfJob = new Dictionary<int, bool>();
            Queue<KeyValuePair<int, int>> frontier = new Queue<KeyValuePair<int, int>>();
            for (int index = 0; index < roots.Count; index++)
            {
                frontier.Enqueue(new KeyValuePair<int, int>(roots[index], 0));
            }
            while (frontier.Count > 0)
            {
                KeyValuePair<int, int> node = frontier.Dequeue();
                int pid = node.Key;
                int depth = node.Value;
                if (!TryAddInt(visited, pid))
                {
                    continue;
                }
                if (depth > MaxParentGraphDepth)
                {
                    throw new UnsupportedCertificationHostException("the out-of-job parent graph exceeded the depth-64 bound.");
                }
                List<int> childList;
                if (!children.TryGetValue(pid, out childList))
                {
                    continue;
                }
                for (int index = 0; index < childList.Count; index++)
                {
                    int childPid = childList[index];
                    if (childPid == pid)
                    {
                        continue;
                    }
                    if (!jobSet.ContainsKey(childPid))
                    {
                        if (!outOfJob.ContainsKey(childPid))
                        {
                            outOfJob[childPid] = true;
                            if (outOfJob.Count > MaxOutOfJobDescendants)
                            {
                                throw new UnsupportedCertificationHostException("more than 64 out-of-job descendants were discovered.");
                            }
                        }
                    }
                    frontier.Enqueue(new KeyValuePair<int, int>(childPid, depth + 1));
                }
            }
            List<int> result = new List<int>(outOfJob.Keys);
            result.Sort();
            return result;
        }

        private static void HandleStableOutOfJobSubtree(IntPtr job, List<int> outOfJob, Dictionary<int, int> parentMap, List<JobProcessMember> jobMembers, int rootProcessId, long rootCreationFileTime, string rootImagePath)
        {
            List<IntPtr> candidateHandles = new List<IntPtr>();
            List<int> candidatePids = new List<int>();
            List<long> candidateCreation = new List<long>();
            bool[] terminationProven = null;
            bool killAttempted = false;
            bool cleanupAttempted = false;
            try
            {
                for (int index = 0; index < outOfJob.Count; index++)
                {
                    int pid = outOfJob[index];
                    IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, false, (uint)pid);
                    if (handle == IntPtr.Zero)
                    {
                        return;
                    }
                    candidateHandles.Add(handle);
                    candidatePids.Add(pid);
                    bool inJob;
                    if (!IsProcessInJob(handle, job, out inJob))
                    {
                        return;
                    }
                    if (inJob)
                    {
                        return;
                    }
                    int actualPid;
                    long creation;
                    string image;
                    bool live;
                    if (!TryQueryRetainedIdentity(handle, out actualPid, out creation, out image, out live))
                    {
                        return;
                    }
                    if (actualPid != pid || !live)
                    {
                        return;
                    }
                    candidateCreation.Add(creation);
                }

                for (int index = 0; index < candidatePids.Count; index++)
                {
                    int pid = candidatePids[index];
                    int parentPid;
                    if (!parentMap.TryGetValue(pid, out parentPid))
                    {
                        return;
                    }
                    long parentCreation;
                    if (!TryFindAncestorCreation(parentPid, jobMembers, candidatePids, candidateCreation, out parentCreation))
                    {
                        return;
                    }
                    if (candidateCreation[index] < parentCreation)
                    {
                        return;
                    }
                }

                if (!RevalidateAttributionAncestorsStable(job, rootProcessId, rootCreationFileTime, rootImagePath, jobMembers, outOfJob, parentMap))
                {
                    return;
                }

                killAttempted = true;
                List<Exception> terminationFailures = new List<Exception>();
                terminationProven = TerminateOutOfJobLeavesFirst(candidateHandles, candidatePids, parentMap, terminationFailures);
                bool allProven = true;
                for (int index = 0; index < terminationProven.Length; index++)
                {
                    if (!terminationProven[index])
                    {
                        allProven = false;
                        break;
                    }
                }
                if (!allProven)
                {
                    throw ComposeCleanupException(
                        new ContainedLaunchOwnershipQuarantinedException("a live process escaped the certification job boundary and its exit could not be proven after leaves-first termination; surviving candidate handles were quarantined."),
                        terminationFailures.ToArray());
                }
                if (terminationFailures.Count > 0)
                {
                    throw ComposeCleanupException(
                        new UnsupportedCertificationHostException("a live process escaped the certification job boundary; fail-closed after leaves-first termination."),
                        terminationFailures.ToArray());
                }
                throw new UnsupportedCertificationHostException("a live process escaped the certification job boundary; fail-closed after leaves-first termination.");
            }
            catch (Exception primary)
            {
                cleanupAttempted = true;
                Exception[] cleanupErrors = ReleaseOutOfJobCandidateHandles(
                    candidateHandles,
                    killAttempted,
                    terminationProven);
                if (cleanupErrors.Length > 0)
                {
                    throw ComposeCleanupException(primary, cleanupErrors);
                }
                throw;
            }
            finally
            {
                if (!cleanupAttempted)
                {
                    Exception[] cleanupErrors = ReleaseOutOfJobCandidateHandles(
                        candidateHandles,
                        killAttempted,
                        terminationProven);
                    if (cleanupErrors.Length > 0)
                    {
                        throw ComposeSnapshotCloseException(cleanupErrors);
                    }
                }
            }
        }

        private static Exception[] ReleaseOutOfJobCandidateHandles(
            IList<IntPtr> candidateHandles,
            bool killAttempted,
            bool[] terminationProven)
        {
            List<Exception> closeErrors = new List<Exception>();
            for (int index = 0; index < candidateHandles.Count; index++)
            {
                if (killAttempted &&
                    terminationProven != null &&
                    index < terminationProven.Length &&
                    !terminationProven[index])
                {
                    QuarantineRawHandle(candidateHandles[index]);
                }
                else
                {
                    Exception closeError;
                    if (!CloseRetainedHandle(candidateHandles[index], out closeError))
                    {
                        closeErrors.Add(closeError);
                    }
                }
            }
            return closeErrors.ToArray();
        }

        private static bool RevalidateAttributionAncestorsStable(IntPtr job, int rootProcessId, long rootCreationFileTime, string rootImagePath, List<JobProcessMember> jobMembers, List<int> outOfJob, Dictionary<int, int> parentMap)
        {
            int[] freshJobPids;
            try
            {
                freshJobPids = QueryJobProcessIdList(job);
            }
            catch (ContainedWorkerException)
            {
                return false;
            }
            int[] attributionJobPids = new int[jobMembers.Count];
            for (int index = 0; index < jobMembers.Count; index++)
            {
                attributionJobPids[index] = jobMembers[index].ProcessId;
            }
            Array.Sort(attributionJobPids);
            int[] freshSorted = (int[])freshJobPids.Clone();
            Array.Sort(freshSorted);
            if (!IntArraysEqual(attributionJobPids, freshSorted))
            {
                return false;
            }

            List<IntPtr> memberHandles = new List<IntPtr>(jobMembers.Count);
            bool cleanupAttempted = false;
            try
            {
                for (int index = 0; index < jobMembers.Count; index++)
                {
                    JobProcessMember member = jobMembers[index];
                    IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, (uint)member.ProcessId);
                    if (handle == IntPtr.Zero)
                    {
                        return false;
                    }
                    memberHandles.Add(handle);
                    int actualPid;
                    long creation;
                    string image;
                    bool live;
                    if (!TryQueryRetainedIdentity(handle, out actualPid, out creation, out image, out live))
                    {
                        return false;
                    }
                    if (actualPid != member.ProcessId || !live)
                    {
                        return false;
                    }
                    if (creation != member.CreationFileTimeUtc)
                    {
                        return false;
                    }
                    if (image != null && !string.Equals(image, member.CanonicalImagePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                    if (member.ProcessId == rootProcessId)
                    {
                        if (creation != rootCreationFileTime)
                        {
                            return false;
                        }
                        if (rootImagePath != null && image != null && !string.Equals(image, rootImagePath, StringComparison.OrdinalIgnoreCase))
                        {
                            return false;
                        }
                    }
                }
            }
            catch (Exception primary)
            {
                cleanupAttempted = true;
                Exception[] cleanupErrors = CloseRetainedHandles(memberHandles);
                if (cleanupErrors.Length > 0)
                {
                    throw ComposeCleanupException(primary, cleanupErrors);
                }
                throw;
            }
            finally
            {
                if (!cleanupAttempted)
                {
                    Exception[] cleanupErrors = CloseRetainedHandles(memberHandles);
                    if (cleanupErrors.Length > 0)
                    {
                        throw ComposeSnapshotCloseException(cleanupErrors);
                    }
                }
            }

            Dictionary<int, int> parentMapRevalidate = ToolhelpParentMap();
            List<int> outOfJobRevalidate = FindOutOfJobDescendants(parentMapRevalidate, BuildIntSet(freshJobPids), rootProcessId, freshJobPids);
            if (!IntListSetEqual(outOfJob, outOfJobRevalidate))
            {
                return false;
            }
            if (!OutOfJobParentChainsEqual(outOfJob, parentMap, parentMapRevalidate))
            {
                return false;
            }
            return true;
        }

        private static bool OutOfJobParentChainsEqual(List<int> outOfJob, Dictionary<int, int> parentMapFirst, Dictionary<int, int> parentMapSecond)
        {
            for (int index = 0; index < outOfJob.Count; index++)
            {
                int pid = outOfJob[index];
                List<int> chainFirst = BuildParentChain(pid, parentMapFirst);
                List<int> chainSecond = BuildParentChain(pid, parentMapSecond);
                if (chainFirst.Count != chainSecond.Count)
                {
                    return false;
                }
                for (int depth = 0; depth < chainFirst.Count; depth++)
                {
                    if (chainFirst[depth] != chainSecond[depth])
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private static List<int> BuildParentChain(int pid, Dictionary<int, int> parentMap)
        {
            List<int> chain = new List<int>();
            int current = pid;
            Dictionary<int, bool> guard = new Dictionary<int, bool>();
            TryAddInt(guard, current);
            chain.Add(current);
            int steps = 0;
            while (steps < MaxParentGraphDepth)
            {
                int parent;
                if (!parentMap.TryGetValue(current, out parent))
                {
                    break;
                }
                if (parent == current)
                {
                    break;
                }
                if (!TryAddInt(guard, parent))
                {
                    break;
                }
                chain.Add(parent);
                current = parent;
                steps++;
            }
            return chain;
        }

        private static bool TryFindAncestorCreation(int parentPid, List<JobProcessMember> jobMembers, List<int> candidatePids, List<long> candidateCreation, out long creation)
        {
            creation = 0;
            for (int index = 0; index < jobMembers.Count; index++)
            {
                if (jobMembers[index].ProcessId == parentPid)
                {
                    creation = jobMembers[index].CreationFileTimeUtc;
                    return true;
                }
            }
            for (int index = 0; index < candidatePids.Count; index++)
            {
                if (candidatePids[index] == parentPid)
                {
                    creation = candidateCreation[index];
                    return true;
                }
            }
            return false;
        }

        private static bool[] TerminateOutOfJobLeavesFirst(List<IntPtr> handles, List<int> pids, Dictionary<int, int> parentMap, List<Exception> failures)
        {
            int count = pids.Count;
            bool[] proven = new bool[count];
            int[] order = new int[count];
            int[] depth = new int[count];
            for (int index = 0; index < count; index++)
            {
                order[index] = index;
                depth[index] = ComputeChainDepth(pids[index], parentMap);
            }
            Array.Sort(depth, order);
            for (int position = count - 1; position >= 0; position--)
            {
                int index = order[position];
                IntPtr handle = handles[index];
                int pid = pids[index];
                bool exitProven = false;
                if (!TerminateProcess(handle, 1))
                {
                    int terminateError = Marshal.GetLastWin32Error();
                    uint earlyCode;
                    if (GetExitCodeProcess(handle, out earlyCode) && earlyCode != STILL_ACTIVE_STATUS)
                    {
                        exitProven = true;
                    }
                    else
                    {
                        failures.Add(new Win32Exception(terminateError, "TerminateProcess failed for out-of-job process " + pid.ToString(CultureInfo.InvariantCulture) + "."));
                    }
                }
                if (!exitProven)
                {
                    uint raw = WaitForSingleObject(handle, (uint)OutOfJobTerminationTimeoutMilliseconds);
                    if (raw == WAIT_OBJECT_0)
                    {
                        exitProven = true;
                    }
                    else if (raw == WAIT_FAILED)
                    {
                        failures.Add(new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed while terminating out-of-job process " + pid.ToString(CultureInfo.InvariantCulture) + "."));
                    }
                    else if (raw == WAIT_TIMEOUT)
                    {
                        failures.Add(new NativeWaitException(0, "out-of-job process " + pid.ToString(CultureInfo.InvariantCulture) + " did not exit within the termination deadline."));
                    }
                    else
                    {
                        failures.Add(new NativeWaitException(0, "WaitForSingleObject returned unexpected status 0x" + raw.ToString("X8", CultureInfo.InvariantCulture) + " while terminating out-of-job process " + pid.ToString(CultureInfo.InvariantCulture) + "."));
                    }
                }
                if (exitProven)
                {
                    uint confirmCode;
                    if (!GetExitCodeProcess(handle, out confirmCode))
                    {
                        exitProven = false;
                        failures.Add(new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed while confirming exit of out-of-job process " + pid.ToString(CultureInfo.InvariantCulture) + "."));
                    }
                    else if (confirmCode == STILL_ACTIVE_STATUS)
                    {
                        exitProven = false;
                        failures.Add(new ContainedWorkerException("out-of-job process " + pid.ToString(CultureInfo.InvariantCulture) + " still reports STILL_ACTIVE after a completed termination wait."));
                    }
                }
                proven[index] = exitProven;
            }
            return proven;
        }

        private static int ComputeChainDepth(int pid, Dictionary<int, int> parentMap)
        {
            int depth = 0;
            int current = pid;
            Dictionary<int, bool> guard = new Dictionary<int, bool>();
            while (TryAddInt(guard, current) && depth < MaxParentGraphDepth)
            {
                int parent;
                if (!parentMap.TryGetValue(current, out parent))
                {
                    break;
                }
                if (parent == current)
                {
                    break;
                }
                depth++;
                current = parent;
            }
            return depth;
        }

        private static bool IntArraysEqual(int[] left, int[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; index++)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }

        private static Dictionary<int, bool> BuildIntSet(int[] values)
        {
            Dictionary<int, bool> set = new Dictionary<int, bool>();
            for (int index = 0; index < values.Length; index++)
            {
                set[values[index]] = true;
            }
            return set;
        }

        private static bool TryAddInt(Dictionary<int, bool> set, int value)
        {
            if (set.ContainsKey(value))
            {
                return false;
            }
            set[value] = true;
            return true;
        }

        private static bool IntListSetEqual(List<int> left, List<int> right)
        {
            if (left.Count != right.Count)
            {
                return false;
            }
            for (int index = 0; index < left.Count; index++)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }

        public static int BasicProcessIdListHeaderSize()
        {
            return Marshal.SizeOf(typeof(JOBOBJECT_BASIC_PROCESS_ID_LIST_HEADER));
        }

        public static int ProcessEntry32Size()
        {
            return Marshal.SizeOf(typeof(PROCESSENTRY32W));
        }

        public static int MaxJobProcessMemberCap()
        {
            return MaxJobProcessMembers;
        }

        public static int ToolhelpEntryCap()
        {
            return MaxToolhelpEntries;
        }

        public static ContainedWorkerSession StartCertificationSnapshotProbe(
            string hostExecutablePath,
            string workingDirectory,
            string gateEventName,
            int childWaitMilliseconds)
        {
            if (hostExecutablePath == null) { throw new ArgumentNullException("hostExecutablePath"); }
            if (workingDirectory == null) { throw new ArgumentNullException("workingDirectory"); }
            if (gateEventName == null) { throw new ArgumentNullException("gateEventName"); }
            if (childWaitMilliseconds < 0) { throw new ArgumentOutOfRangeException("childWaitMilliseconds"); }

            string fullHost = Path.GetFullPath(hostExecutablePath);
            if (!File.Exists(fullHost))
            {
                throw new LaunchPathIdentityException(fullHost, "the certification snapshot probe host image does not exist.");
            }
            string fullWorkingDirectory = Path.GetFullPath(workingDirectory);
            if (!Directory.Exists(fullWorkingDirectory))
            {
                throw new LaunchPathIdentityException(fullWorkingDirectory, "the certification snapshot probe working directory does not exist.");
            }

            string script =
                "$ErrorActionPreference='Stop';" +
                "$gate=[System.Threading.EventWaitHandle]::OpenExisting('" + gateEventName + "');" +
                "[void]$gate.WaitOne(" + childWaitMilliseconds.ToString(CultureInfo.InvariantCulture) + ");" +
                "$gate.Dispose();" +
                "exit 0";
            string[] argv = new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script };
            string commandLine = BuildNativeCommandLine(fullHost, argv);

            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            NamedEvent gate = null;
            LaunchPathBinding paths = null;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            bool processCreated = false;
            bool assignedToJob = false;
            bool transferred = false;
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
                if (cleanupErrors.Count > 0)
                {
                    throw new ContainedWorkerException("certification snapshot probe job security cleanup failed before process creation.");
                }
                gate = NamedEvent.CreateNewManualReset(gateEventName, EventRole.SupervisorGate, Guid.Empty);
                processInfo = CreateSuspendedProcessInheritingEnvironment(fullHost, commandLine, fullWorkingDirectory);
                processCreated = true;
                long startFileTime = GetCreationFileTime(processInfo.hProcess);
                ContainedRootIdentity rootIdentity = ContainedRootIdentity.Capture(processInfo.hProcess, processInfo.dwProcessId, startFileTime);
                RecordAssignmentAttempt();
                bool assigned = AssignProcessToJobObject(job, processInfo.hProcess);
                int assignError = assigned ? 0 : Marshal.GetLastWin32Error();
                if (!assigned)
                {
                    throw new ContainedWorkerException("certification snapshot probe assignment failed.", new Win32Exception(assignError));
                }
                assignedToJob = true;
                bool inJob;
                if (!IsProcessInJob(processInfo.hProcess, job, out inJob))
                {
                    throw new ContainedWorkerException("IsProcessInJob(snapshot probe) failed.", new Win32Exception(Marshal.GetLastWin32Error()));
                }
                if (!inJob)
                {
                    throw new ContainedWorkerException("snapshot probe job membership could not be verified.");
                }
                uint resumeReturn = ResumeThread(processInfo.hThread);
                if (resumeReturn != 1)
                {
                    int resumeError = (resumeReturn == RESUME_THREAD_FAILED) ? Marshal.GetLastWin32Error() : 0;
                    Exception resumePrimary = new ContainedWorkerException(
                        "certification snapshot probe resume failed with return value " + resumeReturn.ToString(CultureInfo.InvariantCulture) + ".");
                    TerminateNativeForOutcome(processInfo.hProcess, processInfo.dwProcessId, true, job, 15000, resumePrimary);
                    throw new ContainedWorkerException("certification snapshot probe resume failed.", new Win32Exception(resumeError));
                }
                ContainedWorkerSession session = new ContainedWorkerSession(
                    ContainedWorkerScenario.Normal, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal,
                    rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                    null, null, ContainedWorkerState.Resumed, null,
                    new ContainedWorkerLaunchDiagnostic(ContainedWorkerScenario.Normal, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal, commandLine, processInfo.dwProcessId, startFileTime, true, false));
                transferred = true;
                return session;
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }
            ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
            if (!transferred)
            {
                CleanupProof proof = ProveNativeLaunchQuiescence(processCreated, processInfo, assignedToJob, job, 15000, cleanupErrors);
                if (proof.CanRelease)
                {
                    ReleasePartialNativeLaunch(ref processInfo, ref job, ref gate, ref paths, cleanupErrors);
                }
                else
                {
                    Exception invariant = new ContainedLaunchOwnershipQuarantinedException(
                        "certification snapshot probe cleanup could not prove process exit and job quiescence; ownership was quarantined.");
                    if (primary == null) { primary = invariant; }
                    else { cleanupErrors.Add(invariant); }
                    QuarantineNativeLaunch(ref processInfo, ref job, ref gate, ref paths);
                }
            }
            if (primary != null)
            {
                throw ComposeCleanupException(primary, cleanupErrors.ToArray());
            }
            primary = new ContainedWorkerException("certification snapshot probe completed without returning a session or surfacing a fault.");
            throw ComposeCleanupException(primary, cleanupErrors.ToArray());
        }

        private static PROCESS_INFORMATION CreateSuspendedProcessInheritingEnvironment(string hostExecutablePath, string commandLine, string workingDirectory)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            IntPtr commandBuffer = Marshal.StringToHGlobalUni(commandLine);
            try
            {
                PROCESS_INFORMATION processInfo;
                uint flags = CREATE_SUSPENDED;
                RecordProcessStart();
                bool created = CreateProcessW(hostExecutablePath, commandBuffer, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, workingDirectory, ref startupInfo, out processInfo);
                if (!created)
                {
                    throw Win32("CreateProcessW(snapshot probe)");
                }
                return processInfo;
            }
            finally
            {
                Marshal.FreeHGlobal(commandBuffer);
            }
        }

        public static bool CreatedJobConfiguresKillOnClose()
        {
            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            try
            {
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint returned;
                    if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size, out returned))
                    {
                        throw Win32("QueryInformationJobObject(extended)");
                    }
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info =
                        (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(buffer, typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                    return (info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                ReleaseJob(ref job, ref securityDescriptor, ref saBuffer);
            }
        }

        public static bool CreatedJobOmitsKillOnClose()
        {
            return !CreatedJobConfiguresKillOnClose();
        }

        public static bool AddressesHandlesNonInheritable()
        {
            return CreatedHandlesNonInheritable();
        }

        public static bool CreatedHandlesNonInheritable()
        {
            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            NamedEvent gate = null;
            try
            {
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                string name = "Local\\PspktPhase4HandleProbe" + Guid.NewGuid().ToString("N");
                gate = NamedEvent.CreateNewManualReset(name, EventRole.Gate, Guid.Empty);
                uint jobFlags;
                uint gateFlags;
                if (!GetHandleInformation(job, out jobFlags))
                {
                    throw Win32("GetHandleInformation(job)");
                }
                if (!GetHandleInformation(gate.Handle, out gateFlags))
                {
                    throw Win32("GetHandleInformation(gate)");
                }
                bool jobInherit = (jobFlags & HANDLE_FLAG_INHERIT) == HANDLE_FLAG_INHERIT;
                bool gateInherit = (gateFlags & HANDLE_FLAG_INHERIT) == HANDLE_FLAG_INHERIT;
                return (!jobInherit) && (!gateInherit);
            }
            finally
            {
                if (gate != null)
                {
                    gate.Dispose();
                }
                ReleaseJob(ref job, ref securityDescriptor, ref saBuffer);
            }
        }

        private static void ReleaseJob(ref IntPtr job, ref IntPtr securityDescriptor, ref IntPtr securityAttributes)
        {
            if (job != IntPtr.Zero)
            {
                IntPtr current = job;
                job = IntPtr.Zero;
                CloseHandle(current);
            }
            if (securityDescriptor != IntPtr.Zero)
            {
                IntPtr current = securityDescriptor;
                securityDescriptor = IntPtr.Zero;
                LocalFree(current);
            }
            if (securityAttributes != IntPtr.Zero)
            {
                IntPtr current = securityAttributes;
                securityAttributes = IntPtr.Zero;
                Marshal.FreeHGlobal(current);
            }
        }

        private const string EnvSnapshotRoot = "PSPKT_PHASE4_SNAPSHOT_ROOT";
        private const string EnvRepositoryRoot = "PSPKT_PHASE4_REPOSITORY_ROOT";
        private const string EnvHelperPath = "PSPKT_PHASE4_HELPER_PATH";
        private const string EnvHelperSha256 = "PSPKT_PHASE4_HELPER_SHA256";
        private const string EnvHelperVersion = "PSPKT_PHASE4_HELPER_VERSION";
        private const string EnvWorkerResultPath = "PSPKT_PHASE4_WORKER_RESULT_PATH";
        private const string EnvWorkerNonce = "PSPKT_PHASE4_WORKER_NONCE";
        private const string EnvWorkerTimeoutReady = "PSPKT_PHASE4_WORKER_TIMEOUT_READY";
        private const string EnvSchemaResultPath = "PSPKT_PHASE4_SCHEMA_RESULT_PATH";
        private const string EnvSchemaResultNonce = "PSPKT_PHASE4_SCHEMA_RESULT_NONCE";
        private const string EnvGateTimeoutMs = "PSPKT_PHASE4_GATE_TIMEOUT_MS";
        private const string EnvWatchdogTimeoutMs = "PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS";
        private const string EnvParentNonce = "PSPKT_PHASE4_PARENT_NONCE";
        private const string EnvParentIdentityRoot = "PSPKT_PHASE4_PARENT_IDENTITY_ROOT";
        private const string EnvParentCorrelationId = "PSPKT_PHASE4_PARENT_CORRELATION_ID";
        private const string EnvParentReadinessEvent = "PSPKT_PHASE4_PARENT_READINESS_EVENT";
        private const string EnvParentAckEvent = "PSPKT_PHASE4_PARENT_ACK_EVENT";
        private const string EnvParentReleaseArmedEvent = "PSPKT_PHASE4_PARENT_RELEASE_ARMED_EVENT";
        private const string EnvParentReleaseEvent = "PSPKT_PHASE4_PARENT_RELEASE_EVENT";
        private const string EnvParentMembershipReadyEvent = "PSPKT_PHASE4_PARENT_MEMBERSHIP_READY_EVENT";
        private const string EnvWaiterReadyEvent = "PSPKT_PHASE4_WAITER_READY_EVENT";
        private const string EnvProbeGateTimeoutMs = "PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS";
        private const string EnvProbeTimeoutExitCode = "PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE";
        private const string EnvPostAssignIdentityRoot = "PSPKT_PHASE4_POSTASSIGN_IDENTITY_ROOT";
        private const string EnvPostAssignCorrelationId = "PSPKT_PHASE4_POSTASSIGN_CORRELATION_ID";
        private const string EnvPostAssignMarkerPath = "PSPKT_PHASE4_POSTASSIGN_MARKER_PATH";
        private const string EnvPostAssignBlockMs = "PSPKT_PHASE4_POSTASSIGN_BLOCK_MS";
        private const string EnvNestedControlRoot = "PSPKT_PHASE4_NESTED_CONTROL_ROOT";
        private const string EnvNestedNonce = "PSPKT_PHASE4_NESTED_NONCE";
        private const string EnvNestedEvidenceReady = "PSPKT_PHASE4_NESTED_EVIDENCE_READY";
        private const string EnvNestedReleaseAuthorized = "PSPKT_PHASE4_NESTED_RELEASE_AUTHORIZED";
        private const string EnvNestedReadyEvent = "PSPKT_PHASE4_NESTED_READY_EVENT";
        private const string EnvNestedReleaseEvent = "PSPKT_PHASE4_NESTED_RELEASE_EVENT";
        private const string EnvNestedChildExited = "PSPKT_PHASE4_NESTED_CHILD_EXITED";
        private const string EnvNestedProofComplete = "PSPKT_PHASE4_NESTED_PROOF_COMPLETE";
        private const string EnvPrelaunchResultPath = "PSPKT_PHASE4_PRELAUNCH_RESULT_PATH";
        private const string EnvPrelaunchResultNonce = "PSPKT_PHASE4_PRELAUNCH_RESULT_NONCE";
        private const string EnvPrelaunchProbeId = "PSPKT_PHASE4_PRELAUNCH_PROBE_ID";
        private const string EnvDescendantGateEvent = "PSPKT_PHASE4_DESCENDANT_GATE_EVENT";
        private const string EnvDescendantWaiterReady = "PSPKT_PHASE4_DESCENDANT_WAITER_READY";
        private const string EnvDescendantResultPath = "PSPKT_PHASE4_DESCENDANT_RESULT_PATH";
        private const string EnvDescendantNonce = "PSPKT_PHASE4_DESCENDANT_NONCE";
        private const string EnvGeneratorResultPath = "PSPKT_PHASE4_GENERATOR_RESULT_PATH";
        private const string EnvGeneratorNonce = "PSPKT_PHASE4_GENERATOR_NONCE";
        private const string EnvGeneratorSourceSha256 = "PSPKT_PHASE4_GENERATOR_SOURCE_SHA256";
        private const string EnvGeneratorHardlinkRoot = "PSPKT_PHASE4_GENERATOR_HARDLINK_ROOT";
        private const string EnvGeneratorTargetRoot = "PSPKT_PHASE4_GENERATOR_TARGET_ROOT";
        private const string EnvGeneratorGatePrepared = "PSPKT_PHASE4_GENERATOR_GATE_PREPARED";
        private const string EnvGeneratorGateAuthorize = "PSPKT_PHASE4_GENERATOR_GATE_AUTHORIZE";
        private const string EnvGeneratorGateWaitArmed = "PSPKT_PHASE4_GENERATOR_GATE_WAIT_ARMED";
        private const string EnvGeneratorHardlinkPrepared = "PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED";
        private const string EnvGeneratorHardlinkAuthorized = "PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED";
        private const string EnvGeneratorHardlinkPreResult = "PSPKT_PHASE4_GENERATOR_HARDLINK_PRE_RESULT";
        private const string EnvProbeMode = "PSPKT_PHASE4_PROBE_MODE";
        private const string EnvProbeNonce = "PSPKT_PHASE4_PROBE_NONCE";
        private const string EnvProbeMarkerPath = "PSPKT_PHASE4_PROBE_MARKER_PATH";
        private const string EnvProbePidPath = "PSPKT_PHASE4_PROBE_PID_PATH";
        private const string EnvFailFastSentinelPath = "PSPKT_PHASE4_FAILFAST_SENTINEL_PATH";
        private const string EnvFailFastResultPath = "PSPKT_PHASE4_FAILFAST_RESULT_PATH";

        private static readonly string[] RuntimeInjectionPrefixes = new string[]
        {
            "DOTNET_", "CORECLR_", "COR_", "COMPLUS_", "APPDOMAIN_MANAGER_"
        };

        public static string GetRoleGateVariable(ProcessLaunchRole role)
        {
            switch (role)
            {
                case ProcessLaunchRole.CompatibilityRun:
                case ProcessLaunchRole.SchemaChild:
                case ProcessLaunchRole.GateProbeChild:
                case ProcessLaunchRole.PauseReleaseChild:
                case ProcessLaunchRole.GateWrongNameChild:
                case ProcessLaunchRole.GateTimeoutChild:
                case ProcessLaunchRole.GateDelayedSignalChild:
                case ProcessLaunchRole.AssignmentFailureChild:
                case ProcessLaunchRole.WatchdogChild:
                case ProcessLaunchRole.DescendantHangChild:
                case ProcessLaunchRole.OverflowChild:
                case ProcessLaunchRole.ParentLossProbeChild:
                case ProcessLaunchRole.PostAssignmentProbeChild:
                case ProcessLaunchRole.NestedCapabilityChild:
                    return GateEventVariable;
                case ProcessLaunchRole.GateMissingChild:
                    return null;
                case ProcessLaunchRole.ParentLossLauncher:
                case ProcessLaunchRole.PostAssignmentLauncher:
                case ProcessLaunchRole.Worker:
                case ProcessLaunchRole.PrelaunchProbe:
                case ProcessLaunchRole.FailFastProbe:
                case ProcessLaunchRole.GeneratorHost:
                    return SupervisorGateEventVariable;
                case ProcessLaunchRole.WorkerLeavesDescendantChild:
                    return DescendantGateEventVariable;
                default:
                    throw new ProcessLaunchConfigurationException(role, "unknown role has no gate-variable mapping.");
            }
        }

        public static string[] GetRoleReservedAuthority(ProcessLaunchRole role)
        {
            switch (role)
            {
                case ProcessLaunchRole.CompatibilityRun:
                    return new string[] { GateEventVariable };
                case ProcessLaunchRole.SchemaChild:
                    return new string[] { GateEventVariable, EnvSnapshotRoot, EnvRepositoryRoot, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvSchemaResultPath, EnvSchemaResultNonce, EnvGateTimeoutMs, EnvWatchdogTimeoutMs };
                case ProcessLaunchRole.GateProbeChild:
                    return new string[] { GateEventVariable, EnvGateTimeoutMs, EnvProbeMode, EnvProbeNonce, EnvProbeMarkerPath };
                case ProcessLaunchRole.PauseReleaseChild:
                    return new string[] { GateEventVariable, EnvProbeMode, EnvProbeNonce, EnvProbeMarkerPath };
                case ProcessLaunchRole.GateMissingChild:
                    return new string[] { EnvProbeMode, EnvProbeNonce };
                case ProcessLaunchRole.GateWrongNameChild:
                    return new string[] { GateEventVariable, EnvProbeMode, EnvProbeNonce };
                case ProcessLaunchRole.GateTimeoutChild:
                    return new string[] { GateEventVariable, EnvGateTimeoutMs, EnvProbeMode, EnvProbeNonce };
                case ProcessLaunchRole.GateDelayedSignalChild:
                    return new string[] { GateEventVariable, EnvGateTimeoutMs, EnvProbeMode, EnvProbeNonce };
                case ProcessLaunchRole.AssignmentFailureChild:
                    return new string[] { GateEventVariable, EnvProbeMode, EnvProbeNonce, EnvProbeMarkerPath };
                case ProcessLaunchRole.WatchdogChild:
                    return new string[] { GateEventVariable, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvWatchdogTimeoutMs, EnvProbeMode, EnvProbeNonce };
                case ProcessLaunchRole.DescendantHangChild:
                    return new string[] { GateEventVariable, EnvProbeMode, EnvProbeNonce, EnvProbePidPath };
                case ProcessLaunchRole.OverflowChild:
                    return new string[] { GateEventVariable, EnvProbeMode, EnvProbeNonce };
                case ProcessLaunchRole.ParentLossLauncher:
                    return new string[] { SupervisorGateEventVariable, EnvSnapshotRoot, EnvRepositoryRoot, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvParentNonce, EnvParentIdentityRoot, EnvParentCorrelationId, EnvParentReadinessEvent, EnvParentAckEvent, EnvParentReleaseArmedEvent, EnvParentReleaseEvent, EnvParentMembershipReadyEvent, EnvWaiterReadyEvent, EnvProbeGateTimeoutMs, EnvProbeTimeoutExitCode };
                case ProcessLaunchRole.ParentLossProbeChild:
                    return new string[] { GateEventVariable, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvWaiterReadyEvent, EnvProbeGateTimeoutMs, EnvProbeTimeoutExitCode };
                case ProcessLaunchRole.PostAssignmentLauncher:
                    return new string[] { SupervisorGateEventVariable, EnvSnapshotRoot, EnvRepositoryRoot, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvPostAssignIdentityRoot, EnvPostAssignCorrelationId, EnvPostAssignMarkerPath, EnvPostAssignBlockMs };
                case ProcessLaunchRole.PostAssignmentProbeChild:
                    return new string[] { GateEventVariable, EnvPostAssignMarkerPath, EnvPostAssignBlockMs };
                case ProcessLaunchRole.Worker:
                    return new string[] { SupervisorGateEventVariable, EnvSnapshotRoot, EnvRepositoryRoot, EnvWorkerResultPath, EnvWorkerNonce, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvWorkerTimeoutReady, EnvNestedControlRoot, EnvNestedNonce, EnvNestedEvidenceReady, EnvNestedReleaseAuthorized, EnvNestedReadyEvent, EnvNestedReleaseEvent, EnvNestedChildExited, EnvNestedProofComplete, EnvDescendantGateEvent, EnvDescendantWaiterReady, EnvDescendantResultPath, EnvDescendantNonce };
                case ProcessLaunchRole.PrelaunchProbe:
                    return new string[] { SupervisorGateEventVariable, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvPrelaunchResultPath, EnvPrelaunchResultNonce, EnvPrelaunchProbeId };
                case ProcessLaunchRole.FailFastProbe:
                    return new string[] { SupervisorGateEventVariable, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvProbeMode, EnvProbeNonce, EnvFailFastSentinelPath, EnvFailFastResultPath };
                case ProcessLaunchRole.NestedCapabilityChild:
                    return new string[] { GateEventVariable, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvNestedReadyEvent, EnvNestedReleaseEvent };
                case ProcessLaunchRole.WorkerLeavesDescendantChild:
                    return new string[] { DescendantGateEventVariable, EnvDescendantWaiterReady, EnvHelperPath, EnvHelperSha256, EnvHelperVersion, EnvProbeGateTimeoutMs, EnvProbeTimeoutExitCode };
                case ProcessLaunchRole.GeneratorHost:
                    return new string[] { SupervisorGateEventVariable, EnvSnapshotRoot, EnvRepositoryRoot, EnvGeneratorResultPath, EnvGeneratorNonce, EnvGeneratorSourceSha256, EnvGeneratorHardlinkRoot, EnvGeneratorTargetRoot, EnvGeneratorGatePrepared, EnvGeneratorGateAuthorize, EnvGeneratorGateWaitArmed, EnvGeneratorHardlinkPrepared, EnvGeneratorHardlinkAuthorized, EnvGeneratorHardlinkPreResult };
                default:
                    throw new ProcessLaunchConfigurationException(role, "unknown role has no reserved-authority mapping.");
            }
        }

        public static string[] GetGeneratorReservedAuthority(GeneratorScenario scenario)
        {
            switch (scenario)
            {
                case GeneratorScenario.Normal:
                case GeneratorScenario.GateWithheld:
                    return GetRoleReservedAuthority(ProcessLaunchRole.GeneratorHost);
                case GeneratorScenario.ContainedFalse:
                    return new string[0];
                default:
                    throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost, "unknown GeneratorScenario value.");
            }
        }

        public static string GetGeneratorGateVariable(GeneratorScenario scenario)
        {
            switch (scenario)
            {
                case GeneratorScenario.Normal:
                case GeneratorScenario.GateWithheld:
                    return SupervisorGateEventVariable;
                case GeneratorScenario.ContainedFalse:
                    return null;
                default:
                    throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost, "unknown GeneratorScenario value.");
            }
        }

        public static string[] GetRequiredReservedNames(ProcessLaunchRole role)
        {
            return RequiredReservedNames(GetRoleReservedAuthority(role), GetRoleGateVariable(role));
        }

        public static string[] GetRequiredGeneratorReservedNames(GeneratorScenario scenario)
        {
            return RequiredReservedNames(GetGeneratorReservedAuthority(scenario), GetGeneratorGateVariable(scenario));
        }

        private static string[] RequiredReservedNames(string[] authority, string gateVariable)
        {
            List<string> required = new List<string>();
            for (int index = 0; index < authority.Length; index++)
            {
                if (gateVariable != null && string.Equals(authority[index], gateVariable, StringComparison.Ordinal))
                {
                    continue;
                }
                required.Add(authority[index]);
            }
            return required.ToArray();
        }

        private static ProcessLaunchRole[] GetLauncherAcceptedRoles(LauncherKind launcher)
        {
            switch (launcher)
            {
                case LauncherKind.CompatibilityRun:
                    return new ProcessLaunchRole[] { ProcessLaunchRole.CompatibilityRun };
                case LauncherKind.TypedRun:
                    return new ProcessLaunchRole[]
                    {
                        ProcessLaunchRole.SchemaChild,
                        ProcessLaunchRole.GateProbeChild,
                        ProcessLaunchRole.PauseReleaseChild,
                        ProcessLaunchRole.AssignmentFailureChild,
                        ProcessLaunchRole.WatchdogChild,
                        ProcessLaunchRole.DescendantHangChild,
                        ProcessLaunchRole.OverflowChild,
                        ProcessLaunchRole.ParentLossProbeChild,
                        ProcessLaunchRole.PostAssignmentProbeChild,
                        ProcessLaunchRole.NestedCapabilityChild
                    };
                case LauncherKind.ContainedValidatorWorker:
                    return new ProcessLaunchRole[] { ProcessLaunchRole.Worker };
                case LauncherKind.ContainedProbe:
                    return new ProcessLaunchRole[] { ProcessLaunchRole.PrelaunchProbe, ProcessLaunchRole.FailFastProbe };
                case LauncherKind.HelperDirectLaunch:
                    return new ProcessLaunchRole[]
                    {
                        ProcessLaunchRole.GateMissingChild,
                        ProcessLaunchRole.GateWrongNameChild,
                        ProcessLaunchRole.GateTimeoutChild,
                        ProcessLaunchRole.GateDelayedSignalChild,
                        ProcessLaunchRole.ParentLossLauncher,
                        ProcessLaunchRole.PostAssignmentLauncher,
                        ProcessLaunchRole.WorkerLeavesDescendantChild
                    };
                case LauncherKind.ContainedGeneratorHost:
                    return new ProcessLaunchRole[] { ProcessLaunchRole.GeneratorHost };
                default:
                    throw new ArgumentOutOfRangeException("launcher");
            }
        }

        public static bool IsLauncherRoleAccepted(LauncherKind launcher, ProcessLaunchRole role)
        {
            if (!Enum.IsDefined(typeof(LauncherKind), launcher))
            {
                throw new ArgumentOutOfRangeException("launcher");
            }
            if (!Enum.IsDefined(typeof(ProcessLaunchRole), role))
            {
                throw new ProcessLaunchConfigurationException(role, "unknown ProcessLaunchRole value.");
            }
            ProcessLaunchRole[] accepted = GetLauncherAcceptedRoles(launcher);
            for (int index = 0; index < accepted.Length; index++)
            {
                if (accepted[index] == role)
                {
                    return true;
                }
            }
            return false;
        }

        public static LauncherRoleAcceptance[] GetLauncherRoleCrossProduct()
        {
            Array launchers = Enum.GetValues(typeof(LauncherKind));
            Array roles = Enum.GetValues(typeof(ProcessLaunchRole));
            List<LauncherRoleAcceptance> rows = new List<LauncherRoleAcceptance>();
            for (int launcherIndex = 0; launcherIndex < launchers.Length; launcherIndex++)
            {
                LauncherKind launcher = (LauncherKind)launchers.GetValue(launcherIndex);
                for (int roleIndex = 0; roleIndex < roles.Length; roleIndex++)
                {
                    ProcessLaunchRole role = (ProcessLaunchRole)roles.GetValue(roleIndex);
                    rows.Add(new LauncherRoleAcceptance(launcher, role, IsLauncherRoleAccepted(launcher, role)));
                }
            }
            return rows.ToArray();
        }

        private static void RequireLauncherRole(LauncherKind launcher, ProcessLaunchRole role)
        {
            if (!Enum.IsDefined(typeof(ProcessLaunchRole), role))
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new ProcessLaunchConfigurationException(role, "unknown ProcessLaunchRole value.");
            }
            if (!IsLauncherRoleAccepted(launcher, role))
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new ProcessLaunchConfigurationException(role, "role " + role.ToString() + " is not accepted by launcher " + launcher.ToString() + ".");
            }
        }

        public static string[] GetRuntimeInjectionPrefixes()
        {
            string[] copy = new string[RuntimeInjectionPrefixes.Length];
            Array.Copy(RuntimeInjectionPrefixes, copy, RuntimeInjectionPrefixes.Length);
            return copy;
        }

        public static bool IsPowerShellOrCscImage(string executablePath)
        {
            if (string.IsNullOrEmpty(executablePath))
            {
                return false;
            }
            string leaf;
            try { leaf = Path.GetFileName(executablePath); }
            catch (ArgumentException) { return false; }
            if (leaf == null)
            {
                return false;
            }
            return string.Equals(leaf, "powershell.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(leaf, "pwsh.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(leaf, "csc.exe", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsPowerShellImage(string executablePath)
        {
            if (string.IsNullOrEmpty(executablePath))
            {
                return false;
            }
            string leaf;
            try { leaf = Path.GetFileName(executablePath); }
            catch (ArgumentException) { return false; }
            if (leaf == null)
            {
                return false;
            }
            return string.Equals(leaf, "powershell.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(leaf, "pwsh.exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsPowerShellRole(ProcessLaunchRole role)
        {
            return role != ProcessLaunchRole.CompatibilityRun;
        }

        private static bool RequiresRuntimeInjectionScrub(ProcessLaunchRole role, string executablePath)
        {
            return IsPowerShellRole(role) || IsPowerShellOrCscImage(executablePath);
        }

        private static bool IsRuntimeInjectionName(string name)
        {
            if (string.Equals(name, "DEVPATH", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            for (int index = 0; index < RuntimeInjectionPrefixes.Length; index++)
            {
                if (name.StartsWith(RuntimeInjectionPrefixes[index], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool IsReservedName(string name)
        {
            return name != null && name.StartsWith(ReservedPrefix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool RoleAuthorizesReserved(ProcessLaunchRole role, string name)
        {
            string[] authority = GetRoleReservedAuthority(role);
            for (int index = 0; index < authority.Length; index++)
            {
                if (string.Equals(authority[index], name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool RoleAuthorizesReservedName(ProcessLaunchRole role, string name)
        {
            if (name == null) { throw new ArgumentNullException("name"); }
            return RoleAuthorizesReserved(role, name);
        }

        private static void ValidateReservedSetEquality(
            ProcessLaunchRole role,
            string[] requiredNames,
            string gateVariable,
            string[] reservedNames,
            string[] reservedValues)
        {
            if (reservedNames == null) { throw new EnvironmentConfigurationException(null, "reserved environment names array is null."); }
            if (reservedValues == null) { throw new EnvironmentConfigurationException(null, "reserved environment values array is null."); }
            if (reservedNames.Length != reservedValues.Length)
            {
                throw new EnvironmentConfigurationException(null, "reserved environment name/value arrays differ in length.");
            }

            for (int index = 0; index < reservedNames.Length; index++)
            {
                string name = reservedNames[index];
                if (!IsValidEnvironmentName(name))
                {
                    throw new EnvironmentConfigurationException(name, "reserved environment name has invalid grammar.");
                }
                if (gateVariable != null && string.Equals(name, gateVariable, StringComparison.OrdinalIgnoreCase))
                {
                    throw new EnvironmentConfigurationException(name, "reserved environment name collides with the gate variable, which is supplied separately.");
                }
                string canonical = FindCanonicalReservedName(requiredNames, name);
                if (canonical == null)
                {
                    throw new EnvironmentConfigurationException(name, "reserved environment name '" + name + "' is not authorized for role " + role.ToString() + ".");
                }
                if (!string.Equals(canonical, name, StringComparison.Ordinal))
                {
                    throw new EnvironmentConfigurationException(name, "reserved environment name '" + name + "' differs in case from the authorized name '" + canonical + "' for role " + role.ToString() + ".");
                }
                if (!IsValidEnvironmentValue(reservedValues[index]))
                {
                    throw new EnvironmentConfigurationException(name, "reserved environment value is null, contains NUL, or exceeds 32767 code units.");
                }
                for (int other = index + 1; other < reservedNames.Length; other++)
                {
                    if (string.Equals(name, reservedNames[other], StringComparison.OrdinalIgnoreCase))
                    {
                        throw new EnvironmentConfigurationException(name, "reserved environment names must be pairwise unique under OrdinalIgnoreCase.");
                    }
                }
            }

            for (int index = 0; index < requiredNames.Length; index++)
            {
                string required = requiredNames[index];
                bool present = false;
                for (int supplied = 0; supplied < reservedNames.Length; supplied++)
                {
                    if (string.Equals(reservedNames[supplied], required, StringComparison.Ordinal))
                    {
                        present = true;
                        break;
                    }
                }
                if (!present)
                {
                    throw new EnvironmentConfigurationException(required, "reserved environment name '" + required + "' is required for role " + role.ToString() + " but was omitted.");
                }
            }
        }

        private static string FindCanonicalReservedName(string[] requiredNames, string name)
        {
            for (int index = 0; index < requiredNames.Length; index++)
            {
                if (string.Equals(requiredNames[index], name, StringComparison.OrdinalIgnoreCase))
                {
                    return requiredNames[index];
                }
            }
            return null;
        }

        internal static Dictionary<string, string> BuildFrozenEnvironment(
            ProcessLaunchRole role,
            string executablePath,
            string gateEnvironmentVariable,
            string gateEventName,
            string[] reservedNames,
            string[] reservedValues,
            string[] extraNames,
            string[] extraValues)
        {
            bool scrubRuntimeInjection;
            bool canonicalizeModulePath;
            return BuildFrozenEnvironmentCore(
                role, executablePath, gateEnvironmentVariable, gateEventName,
                reservedNames, reservedValues, extraNames, extraValues,
                out scrubRuntimeInjection, out canonicalizeModulePath);
        }

        private static Dictionary<string, string> BuildFrozenEnvironmentCore(
            ProcessLaunchRole role,
            string executablePath,
            string gateEnvironmentVariable,
            string gateEventName,
            string[] reservedNames,
            string[] reservedValues,
            string[] extraNames,
            string[] extraValues,
            out bool scrubRuntimeInjection,
            out bool canonicalizeModulePath)
        {
            scrubRuntimeInjection = RequiresRuntimeInjectionScrub(role, executablePath);
            canonicalizeModulePath = IsPowerShellRole(role) || IsPowerShellImage(executablePath);
            bool removeModulePath = scrubRuntimeInjection || canonicalizeModulePath;

            Dictionary<string, string> frozen = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                string name = entry.Key as string;
                if (name == null)
                {
                    continue;
                }
                if (IsReservedName(name))
                {
                    continue;
                }
                if (scrubRuntimeInjection && IsRuntimeInjectionName(name))
                {
                    continue;
                }
                if (removeModulePath && string.Equals(name, "PSModulePath", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                string value = entry.Value as string;
                if (value == null)
                {
                    value = string.Empty;
                }
                frozen[name] = value;
            }

            if (gateEnvironmentVariable != null)
            {
                frozen[gateEnvironmentVariable] = gateEventName;
            }

            if (reservedNames != null)
            {
                for (int index = 0; index < reservedNames.Length; index++)
                {
                    frozen[reservedNames[index]] = reservedValues[index];
                }
            }

            if (extraNames != null)
            {
                for (int index = 0; index < extraNames.Length; index++)
                {
                    frozen[extraNames[index]] = extraValues[index];
                }
            }

            if (canonicalizeModulePath)
            {
                string hostDirectory = null;
                try { hostDirectory = Path.GetDirectoryName(executablePath); }
                catch (ArgumentException) { hostDirectory = null; }
                if (string.IsNullOrEmpty(hostDirectory))
                {
                    throw new EnvironmentConfigurationException("PSModulePath", "the PowerShell host executable directory could not be derived for the canonical module path.");
                }
                frozen["PSModulePath"] = Path.Combine(hostDirectory, "Modules");
            }

            RequireFrozenEnvironmentBlockCap(frozen);
            return frozen;
        }

        private static int ComputeFrozenEnvironmentBlockLength(Dictionary<string, string> frozen)
        {
            long total = 1;
            foreach (KeyValuePair<string, string> pair in frozen)
            {
                total += (long)pair.Key.Length + 1L + (long)pair.Value.Length + 1L;
                if (total > (long)int.MaxValue)
                {
                    return int.MaxValue;
                }
            }
            return (int)total;
        }

        private static void RequireFrozenEnvironmentBlockCap(Dictionary<string, string> frozen)
        {
            int blockLength = ComputeFrozenEnvironmentBlockLength(frozen);
            if (blockLength > MaxEnvironmentBlockLength)
            {
                throw new EnvironmentConfigurationException(null, "frozen environment block is " + blockLength.ToString(CultureInfo.InvariantCulture) + " UTF-16 code units and exceeds the 32767 limit.");
            }
        }

        private sealed class EnvironmentBlockComparer : IComparer<string>
        {
            public int Compare(string x, string y)
            {
                int primary = string.Compare(x, y, StringComparison.OrdinalIgnoreCase);
                if (primary != 0)
                {
                    return primary;
                }
                return string.CompareOrdinal(x, y);
            }
        }

        private static string BuildNativeEnvironmentBlock(Dictionary<string, string> frozen)
        {
            List<string> names = new List<string>(frozen.Keys);
            names.Sort(new EnvironmentBlockComparer());
            StringBuilder builder = new StringBuilder();
            for (int index = 0; index < names.Count; index++)
            {
                string name = names[index];
                builder.Append(name);
                builder.Append('=');
                builder.Append(frozen[name]);
                builder.Append('\0');
            }
            builder.Append('\0');
            if (builder.Length > MaxEnvironmentBlockLength)
            {
                throw new EnvironmentConfigurationException(null, "frozen environment block exceeds the 32767 code-unit limit.");
            }
            return builder.ToString();
        }

        public static FrozenEnvironmentSnapshot BuildFrozenEnvironmentSnapshot(ProcessLaunchConfiguration configuration)
        {
            if (configuration == null) { throw new ArgumentNullException("configuration"); }
            bool scrubbed;
            bool canonicalized;
            Dictionary<string, string> frozen = BuildFrozenEnvironmentCore(
                configuration.Role, configuration.ExecutablePath, configuration.GateEnvironmentVariable, configuration.GateEventName,
                configuration.ReservedEnvironmentNamesInternal, configuration.ReservedEnvironmentValuesInternal,
                configuration.ExtraEnvironmentNamesInternal, configuration.ExtraEnvironmentValuesInternal,
                out scrubbed, out canonicalized);
            List<string> names = new List<string>(frozen.Keys);
            names.Sort(new EnvironmentBlockComparer());
            string[] nameArray = names.ToArray();
            string[] valueArray = new string[nameArray.Length];
            for (int index = 0; index < nameArray.Length; index++)
            {
                valueArray[index] = frozen[nameArray[index]];
            }
            return new FrozenEnvironmentSnapshot(configuration.Role, nameArray, valueArray, ComputeFrozenEnvironmentBlockLength(frozen), scrubbed, canonicalized);
        }

        public static ProcessLaunchConfiguration CreateProcessLaunchConfiguration(
            ProcessLaunchRole role,
            string executablePath,
            string[] arguments,
            string gateEventName,
            string gateEnvironmentVariable,
            string[] extraEnvironmentNames,
            string[] extraEnvironmentValues,
            string[] reservedEnvironmentNames,
            string[] reservedEnvironmentValues,
            int waitTimeoutMilliseconds,
            int terminateGraceMilliseconds,
            int drainDeadlineMilliseconds,
            int retainCapBytes,
            bool simulateAssignFailure,
            Guid correlationId,
            string workingDirectory,
            PauseConfiguration pauseConfiguration,
            ProbeEvidence probeEvidence,
            ParentLossMembership parentLossMembership,
            NestedProof nestedProof)
        {
            return CreateProcessLaunchConfiguration(
                role, executablePath, arguments, gateEventName, gateEnvironmentVariable,
                extraEnvironmentNames, extraEnvironmentValues, reservedEnvironmentNames, reservedEnvironmentValues,
                waitTimeoutMilliseconds, terminateGraceMilliseconds, drainDeadlineMilliseconds, retainCapBytes,
                simulateAssignFailure, correlationId, workingDirectory,
                pauseConfiguration, probeEvidence, parentLossMembership, nestedProof, null);
        }

        public static ProcessLaunchConfiguration CreateProcessLaunchConfiguration(
            ProcessLaunchRole role,
            string executablePath,
            string[] arguments,
            string gateEventName,
            string gateEnvironmentVariable,
            string[] extraEnvironmentNames,
            string[] extraEnvironmentValues,
            string[] reservedEnvironmentNames,
            string[] reservedEnvironmentValues,
            int waitTimeoutMilliseconds,
            int terminateGraceMilliseconds,
            int drainDeadlineMilliseconds,
            int retainCapBytes,
            bool simulateAssignFailure,
            Guid correlationId,
            string workingDirectory,
            PauseConfiguration pauseConfiguration,
            ProbeEvidence probeEvidence,
            ParentLossMembership parentLossMembership,
            NestedProof nestedProof,
            GeneratorBinding generatorBinding)
        {
            if (!Enum.IsDefined(typeof(ProcessLaunchRole), role))
            {
                throw new ProcessLaunchConfigurationException(role, "unknown ProcessLaunchRole value.");
            }
            if (generatorBinding != null && !Enum.IsDefined(typeof(GeneratorScenario), generatorBinding.Scenario))
            {
                throw new ProcessLaunchConfigurationException(role, "unknown GeneratorScenario value in the supplied GeneratorBinding.");
            }
            return new ProcessLaunchConfiguration(
                role, true, executablePath, arguments, gateEventName, gateEnvironmentVariable,
                extraEnvironmentNames, extraEnvironmentValues, reservedEnvironmentNames, reservedEnvironmentValues,
                waitTimeoutMilliseconds, terminateGraceMilliseconds, drainDeadlineMilliseconds, retainCapBytes,
                simulateAssignFailure, correlationId, workingDirectory,
                pauseConfiguration, probeEvidence, parentLossMembership, nestedProof, generatorBinding);
        }

        private static ProcessLaunchConfiguration CreateCompatibilityConfiguration(
            string executablePath,
            string[] arguments,
            string gateEventName,
            string gateEnvironmentVariable,
            string[] extraEnvironmentNames,
            string[] extraEnvironmentValues,
            int waitTimeoutMilliseconds,
            int terminateGraceMilliseconds,
            int drainDeadlineMilliseconds,
            int retainCapBytes,
            bool simulateAssignFailure)
        {
            return new ProcessLaunchConfiguration(
                ProcessLaunchRole.CompatibilityRun, false, executablePath, arguments, gateEventName, gateEnvironmentVariable,
                extraEnvironmentNames, extraEnvironmentValues, new string[0], new string[0],
                waitTimeoutMilliseconds, terminateGraceMilliseconds, drainDeadlineMilliseconds, retainCapBytes,
                simulateAssignFailure, Guid.Empty, null, null, null, null, null, null);
        }

        private static bool IsTypedRunRole(ProcessLaunchRole role)
        {
            switch (role)
            {
                case ProcessLaunchRole.SchemaChild:
                case ProcessLaunchRole.GateProbeChild:
                case ProcessLaunchRole.PauseReleaseChild:
                case ProcessLaunchRole.AssignmentFailureChild:
                case ProcessLaunchRole.WatchdogChild:
                case ProcessLaunchRole.DescendantHangChild:
                case ProcessLaunchRole.OverflowChild:
                case ProcessLaunchRole.ParentLossProbeChild:
                case ProcessLaunchRole.PostAssignmentProbeChild:
                case ProcessLaunchRole.NestedCapabilityChild:
                    return true;
                default:
                    return false;
            }
        }

        private static Dictionary<string, string> ValidateConfiguration(ProcessLaunchConfiguration cfg, LauncherKind launcher)
        {
            ValidateStep1RoleCapability(cfg, launcher);

            try { ValidateStep2Basic(cfg); }
            catch (NativeCommandLineException) { RecordReject(PreNativeRejectReason.Basic); throw; }
            catch (ArgumentException) { RecordReject(PreNativeRejectReason.Basic); throw; }

            try { ValidateStep3EventNames(cfg); }
            catch (EventNameGrammarException) { RecordReject(PreNativeRejectReason.EventName); throw; }

            if (launcher == LauncherKind.TypedRun)
            {
                try { ValidateStep4Correlation(cfg); }
                catch (CorrelationIdRequiredException) { RecordReject(PreNativeRejectReason.EmptyCorrelation); throw; }

                try { ValidateStep5PauseEvidence(cfg); }
                catch (InvalidPauseConfigurationException) { RecordReject(PreNativeRejectReason.PauseConfig); throw; }
            }

            Dictionary<string, string> frozen;
            try { frozen = ValidateStep6Environment(cfg); }
            catch (EnvironmentConfigurationException) { RecordReject(PreNativeRejectReason.Environment); throw; }

            if (launcher != LauncherKind.CompatibilityRun)
            {
                try
                {
                    ValidateStep7GateFirstHost(cfg);
                    ValidatePowerShellEntryArguments(cfg.Role, cfg.ExecutablePath, cfg.ArgumentsInternal);
                }
                catch (ProcessLaunchConfigurationException) { RecordReject(PreNativeRejectReason.Environment); throw; }
            }

            return frozen;
        }

        private static void ValidateStep1RoleCapability(ProcessLaunchConfiguration cfg, LauncherKind launcher)
        {
            RequireLauncherRole(launcher, cfg.Role);

            if (launcher == LauncherKind.CompatibilityRun)
            {
                if (cfg.IsTypedLaunch)
                {
                    RecordReject(PreNativeRejectReason.CombinedSeam);
                    throw new ProcessLaunchConfigurationException(cfg.Role, "the compatibility launcher cannot accept a factory-issued typed configuration.");
                }
            }
            else if (!cfg.IsTypedLaunch)
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new ProcessLaunchConfigurationException(cfg.Role, "launcher " + launcher.ToString() + " requires a configuration minted by CreateProcessLaunchConfiguration.");
            }

            bool pause = cfg.PauseConfiguration != null;
            bool evidence = cfg.ProbeEvidence != null;
            bool parent = cfg.ParentLossMembership != null;
            bool nested = cfg.NestedProof != null;
            bool generator = cfg.GeneratorBinding != null;
            bool matrixOk;
            switch (cfg.Role)
            {
                case ProcessLaunchRole.PauseReleaseChild:
                    matrixOk = pause && evidence && !parent && !nested;
                    break;
                case ProcessLaunchRole.ParentLossProbeChild:
                    matrixOk = pause && !evidence && parent && !nested;
                    break;
                case ProcessLaunchRole.PostAssignmentProbeChild:
                    matrixOk = !pause && evidence && !parent && !nested;
                    break;
                case ProcessLaunchRole.NestedCapabilityChild:
                    matrixOk = !pause && !evidence && !parent && nested;
                    break;
                default:
                    matrixOk = !pause && !evidence && !parent && !nested;
                    break;
            }
            if (!matrixOk)
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new ProcessLaunchConfigurationException(cfg.Role, "typed-Run capability matrix violation for role " + cfg.Role.ToString() + ".");
            }

            bool generatorOk = (cfg.Role == ProcessLaunchRole.GeneratorHost) ? generator : !generator;
            if (!generatorOk)
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new ProcessLaunchConfigurationException(cfg.Role, "a GeneratorBinding is required for GeneratorHost and forbidden for role " + cfg.Role.ToString() + ".");
            }

            if (pause && cfg.SimulateAssignFailure)
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new InvalidPreAssignmentConfigurationException("pause configuration combined with simulateAssignFailure is rejected before native work.");
            }

            if (cfg.SimulateAssignFailure && launcher != LauncherKind.TypedRun && launcher != LauncherKind.CompatibilityRun)
            {
                RecordReject(PreNativeRejectReason.CombinedSeam);
                throw new ProcessLaunchConfigurationException(cfg.Role, "simulateAssignFailure is legal only on the Run launchers.");
            }
        }

        private static string ExpectedGateVariable(ProcessLaunchConfiguration cfg)
        {
            if (cfg.Role == ProcessLaunchRole.GeneratorHost)
            {
                return GetGeneratorGateVariable(cfg.GeneratorBinding.Scenario);
            }
            return GetRoleGateVariable(cfg.Role);
        }

        private static void ValidateStep2Basic(ProcessLaunchConfiguration cfg)
        {
            if (cfg.ExecutablePath == null) { throw new ArgumentNullException("executablePath"); }
            if (cfg.ArgumentsInternal == null) { throw new ArgumentNullException("arguments"); }
            if (cfg.ExtraEnvironmentNamesInternal == null) { throw new ArgumentNullException("extraEnvironmentNames"); }
            if (cfg.ExtraEnvironmentValuesInternal == null) { throw new ArgumentNullException("extraEnvironmentValues"); }
            if (cfg.ExtraEnvironmentNamesInternal.Length != cfg.ExtraEnvironmentValuesInternal.Length)
            {
                throw new ArgumentException("extra environment name/value arrays differ in length.");
            }
            if (cfg.ReservedEnvironmentNamesInternal == null) { throw new ArgumentNullException("reservedEnvironmentNames"); }
            if (cfg.ReservedEnvironmentValuesInternal == null) { throw new ArgumentNullException("reservedEnvironmentValues"); }
            if (cfg.ReservedEnvironmentNamesInternal.Length != cfg.ReservedEnvironmentValuesInternal.Length)
            {
                throw new ArgumentException("reserved environment name/value arrays differ in length.");
            }
            if (cfg.WaitTimeoutMilliseconds < 1) { throw new ArgumentOutOfRangeException("waitTimeoutMilliseconds"); }
            if (cfg.TerminateGraceMilliseconds < 1) { throw new ArgumentOutOfRangeException("terminateGraceMilliseconds"); }
            if (cfg.DrainDeadlineMilliseconds < 1) { throw new ArgumentOutOfRangeException("drainDeadlineMilliseconds"); }
            if (cfg.RetainCapBytes < 1) { throw new ArgumentOutOfRangeException("retainCapBytes"); }
            ValidateEffectiveCommandLine(cfg.ExecutablePath, cfg.ArgumentsInternal);
            if (cfg.Role == ProcessLaunchRole.CompatibilityRun && IsPowerShellImage(cfg.ExecutablePath))
            {
                GetValidatedPowerShellFileSourcePath(cfg.ExecutablePath, cfg.ArgumentsInternal);
            }
        }

        private static void ValidateStep3EventNames(ProcessLaunchConfiguration cfg)
        {
            List<string> names = new List<string>();
            string expectedGateVariable = ExpectedGateVariable(cfg);
            if (expectedGateVariable == null)
            {
                if (cfg.GateEventName != null)
                {
                    throw new EventNameGrammarException(cfg.GateEventName, "role " + cfg.Role.ToString() + " must not supply a gate event name.");
                }
            }
            else
            {
                ValidateEventNameGrammar(cfg.GateEventName);
                names.Add(cfg.GateEventName);
            }
            if (cfg.PauseConfiguration != null)
            {
                PauseConfiguration pause = cfg.PauseConfiguration;
                ValidateEventNameGrammar(pause.ReadinessEventName); names.Add(pause.ReadinessEventName);
                ValidateEventNameGrammar(pause.ObserverAckEventName); names.Add(pause.ObserverAckEventName);
                ValidateEventNameGrammar(pause.ReleaseWaitArmedEventName); names.Add(pause.ReleaseWaitArmedEventName);
                ValidateEventNameGrammar(pause.ReleaseEventName); names.Add(pause.ReleaseEventName);
            }
            if (cfg.ParentLossMembership != null)
            {
                ValidateEventNameGrammar(cfg.ParentLossMembership.MembershipReadyEventName);
                names.Add(cfg.ParentLossMembership.MembershipReadyEventName);
            }
            if (cfg.NestedProof != null)
            {
                NestedProof nested = cfg.NestedProof;
                ValidateEventNameGrammar(nested.NestedEvidenceReadyEventName); names.Add(nested.NestedEvidenceReadyEventName);
                ValidateEventNameGrammar(nested.NestedReadyEventName); names.Add(nested.NestedReadyEventName);
                ValidateEventNameGrammar(nested.NestedReleaseEventName); names.Add(nested.NestedReleaseEventName);
            }
            for (int i = 0; i < names.Count; i++)
            {
                for (int j = i + 1; j < names.Count; j++)
                {
                    if (string.Equals(names[i], names[j], StringComparison.OrdinalIgnoreCase))
                    {
                        throw new EventNameGrammarException(names[i], "event names must be unique under OrdinalIgnoreCase; duplicate '" + names[i] + "'.");
                    }
                }
            }
        }

        private static void ValidateStep4Correlation(ProcessLaunchConfiguration cfg)
        {
            if (cfg.CorrelationId == Guid.Empty)
            {
                throw new CorrelationIdRequiredException("the typed certification overload requires a nonempty correlation id.");
            }
        }

        private static void ValidateStep5PauseEvidence(ProcessLaunchConfiguration cfg)
        {
            if (cfg.PauseConfiguration != null)
            {
                PauseConfiguration pause = cfg.PauseConfiguration;
                if (string.IsNullOrEmpty(pause.IdentityDirectory)) { throw new InvalidPauseConfigurationException("pause configuration identity directory is required."); }
                if (pause.ReadinessEventName == null || pause.ObserverAckEventName == null || pause.ReleaseWaitArmedEventName == null || pause.ReleaseEventName == null)
                {
                    throw new InvalidPauseConfigurationException("pause configuration event names are required.");
                }
                if (pause.AckTimeoutMilliseconds < 1) { throw new InvalidPauseConfigurationException("pause ack timeout must be at least 1 ms."); }
                if (pause.ReleaseTimeoutMilliseconds < 1) { throw new InvalidPauseConfigurationException("pause release timeout must be at least 1 ms."); }
                if (pause.CorrelationId != cfg.CorrelationId) { throw new InvalidPauseConfigurationException("pause correlation id must match the launch correlation id."); }
            }
            if (cfg.ProbeEvidence != null)
            {
                if (string.IsNullOrEmpty(cfg.ProbeEvidence.EvidenceDirectory)) { throw new InvalidPauseConfigurationException("probe evidence directory is required."); }
                if (cfg.ProbeEvidence.CorrelationId != cfg.CorrelationId) { throw new InvalidPauseConfigurationException("probe evidence correlation id must match the launch correlation id."); }
            }
            if (cfg.ParentLossMembership != null)
            {
                ParentLossMembership membership = cfg.ParentLossMembership;
                if (string.IsNullOrEmpty(membership.ParentNonce) || string.IsNullOrEmpty(membership.ReceiptRoot) || string.IsNullOrEmpty(membership.ReceiptLeaf) || string.IsNullOrEmpty(membership.MembershipReadyEventName))
                {
                    throw new InvalidPauseConfigurationException("parent-loss membership fields are required.");
                }
                if (!IsLowercaseGuidN(membership.ParentNonce))
                {
                    throw new InvalidPauseConfigurationException("parent-loss parent nonce must be a lowercase 32-character GUID 'N' value.");
                }
                if (!IsLegalReceiptLeaf(membership.ReceiptLeaf))
                {
                    throw new InvalidPauseConfigurationException("parent-loss receipt leaf '" + membership.ReceiptLeaf + "' is not a legal bounded leaf name.");
                }
                if (membership.CorrelationId != cfg.CorrelationId) { throw new InvalidPauseConfigurationException("parent-loss correlation id must match the launch correlation id."); }
            }
            if (cfg.NestedProof != null)
            {
                NestedProof nested = cfg.NestedProof;
                if (string.IsNullOrEmpty(nested.Nonce) || string.IsNullOrEmpty(nested.ControlRoot) || string.IsNullOrEmpty(nested.NestedEvidenceReadyEventName))
                {
                    throw new InvalidPauseConfigurationException("nested-proof fields are required.");
                }
                if (!IsLowercaseGuidN(nested.Nonce))
                {
                    throw new InvalidPauseConfigurationException("nested-proof nonce must be a lowercase 32-character GUID 'N' value.");
                }
                if (nested.CorrelationId != cfg.CorrelationId) { throw new InvalidPauseConfigurationException("nested-proof correlation id must match the launch correlation id."); }
            }
        }

        private static bool IsLowercaseGuidN(string value)
        {
            if (value == null || value.Length != 32)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char c = value[index];
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!ok)
                {
                    return false;
                }
            }
            return true;
        }

        private static bool IsLegalReceiptLeaf(string leaf)
        {
            if (string.IsNullOrEmpty(leaf) || leaf.Length > MaxReceiptLeafLength)
            {
                return false;
            }
            char first = leaf[0];
            bool firstOk = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9');
            if (!firstOk)
            {
                return false;
            }
            for (int index = 1; index < leaf.Length; index++)
            {
                char c = leaf[index];
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok)
                {
                    return false;
                }
            }
            if (leaf.IndexOf("..", StringComparison.Ordinal) >= 0)
            {
                return false;
            }
            return true;
        }

        private static Dictionary<string, string> ValidateStep6Environment(ProcessLaunchConfiguration cfg)
        {
            string expectedGateVariable = ExpectedGateVariable(cfg);
            string gateVar = cfg.GateEnvironmentVariable;
            if (cfg.Role == ProcessLaunchRole.CompatibilityRun)
            {
                ValidateCompatibilityGateEnvironmentVariable(gateVar);
            }
            else if (expectedGateVariable == null)
            {
                if (gateVar != null)
                {
                    throw new EnvironmentConfigurationException(gateVar, "role " + cfg.Role.ToString() + " must not supply a gate environment variable.");
                }
            }
            else if (!string.Equals(gateVar, expectedGateVariable, StringComparison.Ordinal))
            {
                throw new EnvironmentConfigurationException(gateVar, "gate environment variable must equal the exact constant " + expectedGateVariable + " under ordinal comparison.");
            }

            string[] extraNames = cfg.ExtraEnvironmentNamesInternal;
            string[] extraValues = cfg.ExtraEnvironmentValuesInternal;
            if (extraNames.Length > 0 && cfg.Role != ProcessLaunchRole.CompatibilityRun)
            {
                throw new EnvironmentConfigurationException(extraNames[0], "public environment extras are legal only for the CompatibilityRun role.");
            }
            for (int index = 0; index < extraNames.Length; index++)
            {
                string name = extraNames[index];
                if (!IsValidEnvironmentName(name))
                {
                    throw new EnvironmentConfigurationException(name, "extra environment name has invalid grammar.");
                }
                if (IsReservedName(name))
                {
                    throw new EnvironmentConfigurationException(name, "extra environment names may not use the reserved PSPKT_PHASE4_ prefix.");
                }
                if (IsRuntimeInjectionName(name))
                {
                    throw new EnvironmentConfigurationException(name, "extra environment names may not use a runtime-injection prefix or DEVPATH.");
                }
                if (string.Equals(name, "PSModulePath", StringComparison.OrdinalIgnoreCase))
                {
                    throw new EnvironmentConfigurationException(name, "extra environment names may not set PSModulePath under any casing.");
                }
                if (gateVar != null && string.Equals(name, gateVar, StringComparison.OrdinalIgnoreCase))
                {
                    throw new EnvironmentConfigurationException(name, "extra environment name collides with the gate variable.");
                }
                if (!IsValidEnvironmentValue(extraValues[index]))
                {
                    throw new EnvironmentConfigurationException(name, "extra environment value is null, contains NUL, or exceeds 32767 code units.");
                }
                for (int other = index + 1; other < extraNames.Length; other++)
                {
                    if (string.Equals(name, extraNames[other], StringComparison.OrdinalIgnoreCase))
                    {
                        throw new EnvironmentConfigurationException(name, "extra environment names must be pairwise unique under OrdinalIgnoreCase.");
                    }
                }
            }

            string[] requiredReserved;
            if (cfg.Role == ProcessLaunchRole.GeneratorHost)
            {
                requiredReserved = GetRequiredGeneratorReservedNames(cfg.GeneratorBinding.Scenario);
            }
            else
            {
                requiredReserved = GetRequiredReservedNames(cfg.Role);
            }
            ValidateReservedSetEquality(cfg.Role, requiredReserved, expectedGateVariable, cfg.ReservedEnvironmentNamesInternal, cfg.ReservedEnvironmentValuesInternal);

            bool scrubbed;
            bool canonicalized;
            return BuildFrozenEnvironmentCore(
                cfg.Role, cfg.ExecutablePath, gateVar, cfg.GateEventName,
                cfg.ReservedEnvironmentNamesInternal, cfg.ReservedEnvironmentValuesInternal,
                extraNames, extraValues, out scrubbed, out canonicalized);
        }

        private static void ValidateCompatibilityGateEnvironmentVariable(string name)
        {
            if (!string.Equals(name, GateEventVariable, StringComparison.Ordinal))
            {
                throw new EnvironmentConfigurationException(name, "the compatibility gate environment variable must equal the exact constant " + GateEventVariable + " under ordinal comparison.");
            }
        }

        private const string OwnedWorkingDirectoryRootLeaf = "pspkt-phase4-cwd";

        public static string CreateOwnedWorkingDirectory()
        {
            string tempRoot;
            try { tempRoot = Path.GetFullPath(Path.GetTempPath()); }
            catch (ArgumentException pathError) { throw new LaunchPathIdentityException(null, "the owner temp root could not be canonicalized.", pathError); }
            catch (NotSupportedException pathError) { throw new LaunchPathIdentityException(null, "the owner temp root could not be canonicalized.", pathError); }
            catch (PathTooLongException pathError) { throw new LaunchPathIdentityException(null, "the owner temp root could not be canonicalized.", pathError); }

            string ownerRoot = Path.Combine(tempRoot, OwnedWorkingDirectoryRootLeaf);
            DirectoryInfo ownerInfo = new DirectoryInfo(ownerRoot);
            if (!ownerInfo.Exists)
            {
                Directory.CreateDirectory(ownerRoot);
                ownerInfo = new DirectoryInfo(ownerRoot);
            }
            if ((ownerInfo.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                throw new LaunchPathIdentityException(ownerRoot, "the owner temp root '" + ownerRoot + "' is a reparse point.");
            }

            string unique = Path.Combine(ownerRoot, Guid.NewGuid().ToString("N"));
            if (Directory.Exists(unique) || File.Exists(unique))
            {
                throw new LaunchPathIdentityException(unique, "the unique working directory name already exists.");
            }
            Directory.CreateDirectory(unique);
            return Path.GetFullPath(unique);
        }

        private static RetainedDirectoryIdentity BindWorkingDirectory(string workingDirectory, bool requireEmptyDirectory)
        {
            bool owned = string.IsNullOrEmpty(workingDirectory);
            string candidate = owned ? CreateOwnedWorkingDirectory() : workingDirectory;
            string fullPath = RequireOrdinaryNonReparseDirectory(candidate);
            DirectoryInfo info = new DirectoryInfo(fullPath);
            if (requireEmptyDirectory)
            {
                FileSystemInfo[] entries = info.GetFileSystemInfos();
                if (entries.Length != 0)
                {
                    throw new LaunchPathIdentityException(fullPath, "the launch working directory '" + fullPath + "' must be a unique empty directory.");
                }
            }
            return new RetainedDirectoryIdentity(fullPath, info.CreationTimeUtc.ToFileTimeUtc(), owned);
        }

        private static LaunchPathBinding BindLaunchPaths(string executablePath, string[] arguments, string workingDirectory)
        {
            return BindLaunchPaths(executablePath, arguments, workingDirectory, true);
        }

        private static LaunchPathBinding BindLaunchPaths(
            string executablePath,
            string[] arguments,
            string workingDirectory,
            bool requireEmptyWorkingDirectory)
        {
            RetainedPathIdentity executable = RetainedPathIdentity.OpenAndRetain(executablePath);
            List<RetainedPathIdentity> sources = new List<RetainedPathIdentity>();
            try
            {
                if (IsPowerShellImage(executable.FullPath))
                {
                    string sourcePath = GetValidatedPowerShellFileSourcePath(executable.FullPath, arguments);
                    if (sourcePath != null)
                    {
                        sources.Add(RetainedPathIdentity.OpenAndRetain(sourcePath));
                    }
                }
                if (IsCscImage(executable.FullPath) && arguments.Length > 0)
                {
                    string last = arguments[arguments.Length - 1];
                    if (last != null && last.Length > 0 && last[0] != '-' && last[0] != '/')
                    {
                        sources.Add(RetainedPathIdentity.OpenAndRetain(last));
                    }
                }
                RetainedDirectoryIdentity directory = BindWorkingDirectory(workingDirectory, requireEmptyWorkingDirectory);
                return new LaunchPathBinding(executable, sources.ToArray(), directory);
            }
            catch (Exception)
            {
                executable.Dispose();
                for (int index = 0; index < sources.Count; index++)
                {
                    sources[index].Dispose();
                }
                throw;
            }
        }

        private static string GetValidatedPowerShellFileSourcePath(
            string executablePath,
            string[] arguments)
        {
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }
            int entryMode = 0;
            string sourcePath = null;
            for (int index = 0; index < arguments.Length; index++)
            {
                string argument = arguments[index];
                if (argument == null)
                {
                    throw new NativeCommandLineException(
                        "PowerShell argument at index " +
                        index.ToString(CultureInfo.InvariantCulture) +
                        " is null.");
                }

                int currentEntryMode = GetPowerShellEntryMode(argument);
                if (currentEntryMode != 0)
                {
                    if (entryMode != 0)
                    {
                        throw new NativeCommandLineException(
                            "PowerShell launches may specify only one file or command entry mode.");
                    }
                    if (currentEntryMode == 1)
                    {
                        if (index + 1 >= arguments.Length ||
                            string.IsNullOrEmpty(arguments[index + 1]) ||
                            string.Equals(arguments[index + 1], "-", StringComparison.Ordinal) ||
                            IsPowerShellSwitchToken(arguments[index + 1]))
                        {
                            throw new NativeCommandLineException(
                                "PowerShell file launches require a nonempty script path.");
                        }
                        sourcePath = arguments[index + 1];
                    }
                    else if (
                        index + 1 >= arguments.Length ||
                        string.IsNullOrEmpty(arguments[index + 1]))
                    {
                        throw new NativeCommandLineException(
                            "PowerShell command launches require a nonempty command payload.");
                    }
                    entryMode = currentEntryMode;
                    index++;
                    continue;
                }

                if (entryMode != 0)
                {
                    continue;
                }

                bool consumesValue;
                if (IsPowerShellSwitchToken(argument))
                {
                    if (!TryGetPowerShellHostOption(
                        executablePath,
                        argument,
                        out consumesValue))
                    {
                        throw new NativeCommandLineException(
                            "PowerShell host option '" +
                            argument +
                            "' is unknown or ambiguous.");
                    }
                    if (consumesValue)
                    {
                        if (index + 1 >= arguments.Length ||
                            string.IsNullOrEmpty(arguments[index + 1]) ||
                            IsPowerShellSwitchToken(arguments[index + 1]))
                        {
                            throw new NativeCommandLineException(
                                "PowerShell host option '" +
                                argument +
                                "' requires a value.");
                        }
                        index++;
                    }
                    continue;
                }

                if (!argument.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                {
                    throw new NativeCommandLineException(
                        "PowerShell positional entry must be a .ps1 script path.");
                }
                sourcePath = argument;
                entryMode = 1;
            }
            return sourcePath;
        }

        private static int GetPowerShellEntryMode(string argument)
        {
            string optionName;
            if (!TryGetPowerShellOptionName(argument, true, out optionName))
            {
                return 0;
            }
            if (string.Equals(optionName, "f", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "fi", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "fil", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "file", StringComparison.OrdinalIgnoreCase))
            {
                return 1;
            }
            if (string.Equals(optionName, "c", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "co", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "com", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "comm", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "comma", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "comman", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "command", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "cwa", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "commandwithargs", StringComparison.OrdinalIgnoreCase))
            {
                return 2;
            }
            if (string.Equals(optionName, "e", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "ec", StringComparison.OrdinalIgnoreCase) ||
                "EncodedCommand".StartsWith(
                    optionName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return 3;
            }
            return 0;
        }

        private static bool IsPowerShellSwitchToken(string argument)
        {
            return argument != null &&
                argument.Length > 1 &&
                (argument[0] == '-' || argument[0] == '/');
        }

        private static bool TryGetPowerShellOptionName(
            string argument,
            bool allowSlash,
            out string optionName)
        {
            optionName = null;
            if (!IsPowerShellSwitchToken(argument))
            {
                return false;
            }
            if (argument[0] == '/' && !allowSlash)
            {
                return false;
            }
            optionName = argument.Substring(1);
            return optionName.Length != 0;
        }

        private static bool TryGetPowerShellHostOption(
            string executablePath,
            string argument,
            out bool consumesValue)
        {
            consumesValue = false;
            string optionName;
            if (!TryGetPowerShellOptionName(argument, true, out optionName))
            {
                return false;
            }

            if (string.Equals(optionName, "?", StringComparison.Ordinal) ||
                string.Equals(optionName, "h", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "help", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "mta", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "sta", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "noexit", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "noe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "nologo", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "nol", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "noninteractive", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "noni", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "noprofile", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "nop", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(optionName, "version", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "v", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "inputformat", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "inp", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "if", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "outputformat", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "o", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "of", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "windowstyle", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "w", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "executionpolicy", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "ex", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "ep", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "configurationname", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "config", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "workingdirectory", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "wd", StringComparison.OrdinalIgnoreCase))
            {
                consumesValue = true;
                return true;
            }

            if (IsWindowsPowerShellImage(executablePath))
            {
                if (string.Equals(
                    optionName,
                    "psconsolefile",
                    StringComparison.OrdinalIgnoreCase))
                {
                    consumesValue = true;
                    return true;
                }
                return false;
            }

            if (string.Equals(optionName, "interactive", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "i", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "login", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "l", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "noprofileloadtime", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "sshservermode", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "sshs", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(optionName, "configurationfile", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "custompipename", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "settingsfile", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "settings", StringComparison.OrdinalIgnoreCase))
            {
                consumesValue = true;
                return true;
            }
            return false;
        }

        private static bool IsWindowsPowerShellImage(string executablePath)
        {
            if (string.IsNullOrEmpty(executablePath))
            {
                return false;
            }
            string leaf;
            try { leaf = Path.GetFileName(executablePath); }
            catch (ArgumentException) { return false; }
            return string.Equals(
                leaf,
                "powershell.exe",
                StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsCscImage(string executablePath)
        {
            if (string.IsNullOrEmpty(executablePath))
            {
                return false;
            }
            string leaf;
            try { leaf = Path.GetFileName(executablePath); }
            catch (ArgumentException) { return false; }
            return string.Equals(leaf, "csc.exe", StringComparison.OrdinalIgnoreCase);
        }

        public static BoundedProcessResult Run(
            string executablePath,
            string[] arguments,
            string gateEventName,
            string gateEnvironmentVariable,
            string[] extraEnvironmentNames,
            string[] extraEnvironmentValues,
            int waitTimeoutMilliseconds,
            int terminateGraceMilliseconds,
            int drainDeadlineMilliseconds,
            int retainCapBytes,
            bool simulateAssignFailure)
        {
            try
            {
                if (executablePath == null) { throw new ArgumentNullException("executablePath"); }
                if (arguments == null) { throw new ArgumentNullException("arguments"); }
                if (extraEnvironmentNames == null) { throw new ArgumentNullException("extraEnvironmentNames"); }
                if (extraEnvironmentValues == null) { throw new ArgumentNullException("extraEnvironmentValues"); }
                if (extraEnvironmentNames.Length != extraEnvironmentValues.Length)
                {
                    throw new ArgumentException("environment name/value arrays differ in length.");
                }
            }
            catch (ArgumentException)
            {
                RecordReject(PreNativeRejectReason.Basic);
                throw;
            }
            ProcessLaunchConfiguration cfg = CreateCompatibilityConfiguration(
                executablePath, arguments, gateEventName, gateEnvironmentVariable,
                extraEnvironmentNames, extraEnvironmentValues,
                waitTimeoutMilliseconds, terminateGraceMilliseconds, drainDeadlineMilliseconds, retainCapBytes,
                simulateAssignFailure);
            return RunCore(cfg, LauncherKind.CompatibilityRun);
        }

        public static BoundedProcessResult Run(ProcessLaunchConfiguration configuration)
        {
            if (configuration == null) { throw new ArgumentNullException("configuration"); }
            return RunCore(configuration, LauncherKind.TypedRun);
        }

        private static BoundedProcessResult RunCore(ProcessLaunchConfiguration cfg, LauncherKind launcher)
        {
            Dictionary<string, string> frozen = ValidateConfiguration(cfg, launcher);

            LaunchPathBinding paths;
            try
            {
                paths = BindLaunchPaths(cfg.ExecutablePath, cfg.ArgumentsInternal, cfg.WorkingDirectory);
            }
            catch (LaunchPathIdentityException)
            {
                RecordPathIdentityReject();
                throw;
            }

            long runEntryAssignmentCount = GetAssignmentAttemptCount();

            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            NamedEvent gate = null;
            Process process = null;
            bool started = false;
            bool assignedToJob = false;
            ManualResetEvent overflowSignal = null;
            StreamDrainer outDrainer = null;
            StreamDrainer errDrainer = null;
            bool outStarted = false;
            bool errStarted = false;
            int childPid = 0;
            long childStart = 0;
            BoundedProcessResult result = null;
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();

            try
            {
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
                gate = NamedEvent.CreateNewManualReset(cfg.GateEventName, EventRole.Gate, Guid.Empty);

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = paths.ExecutableFullPath;
                startInfo.Arguments = BuildCommandLine(cfg.ArgumentsInternal);
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.RedirectStandardInput = false;
                startInfo.WorkingDirectory = paths.WorkingDirectoryFullPath;
                startInfo.EnvironmentVariables.Clear();
                foreach (KeyValuePair<string, string> pair in frozen)
                {
                    startInfo.EnvironmentVariables[pair.Key] = pair.Value;
                }

                process = new Process();
                process.StartInfo = startInfo;
                RecordProcessStart();
                process.Start();
                started = true;
                childPid = process.Id;
                childStart = ReadStartFileTime(process);

                overflowSignal = new ManualResetEvent(false);
                outDrainer = new StreamDrainer(process.StandardOutput.BaseStream, cfg.RetainCapBytes, overflowSignal, false);
                errDrainer = new StreamDrainer(process.StandardError.BaseStream, cfg.RetainCapBytes, overflowSignal, false);
                outDrainer.Start();
                outStarted = true;
                errDrainer.Start();
                errStarted = true;

                if (cfg.PauseConfiguration != null)
                {
                    RunPauseSeam(cfg, process, childPid, childStart, job, runEntryAssignmentCount, cleanupErrors);
                }

                long assignBefore = GetAssignmentAttemptCount();
                bool assignFailed = false;
                int assignError = 0;
                if (cfg.SimulateAssignFailure)
                {
                    assignFailed = true;
                }
                else
                {
                    RecordAssignmentAttempt();
                    if (!AssignProcessToJobObject(job, process.Handle))
                    {
                        assignFailed = true;
                        assignError = Marshal.GetLastWin32Error();
                    }
                    else
                    {
                        assignedToJob = true;
                    }
                }

                if (assignFailed)
                {
                    Stopwatch terminationStopwatch = Stopwatch.StartNew();
                    StopStartedProcess(
                        process,
                        assignedToJob,
                        job,
                        terminationStopwatch,
                        cfg.TerminateGraceMilliseconds,
                        childPid,
                        cleanupErrors);
                    DrainCleanupOutcome assignDrain = CleanupDrainers(outDrainer, outStarted, errDrainer, errStarted, cfg.DrainDeadlineMilliseconds, false, cleanupErrors);
                    int assignExit = -1;
                    bool assignExited = false;
                    if (process.HasExited) { assignExited = true; assignExit = process.ExitCode; }
                    result = new BoundedProcessResult(assignExit, started, assignExited, false, false,
                        true, assignError, assignDrain.Overflow1, assignDrain.Overflow2, assignDrain.TotalBytes1,
                        assignDrain.TotalBytes2, assignDrain.RetainedText1, assignDrain.RetainedText2, assignDrain.DrainCompleted, -1, cfg.CorrelationId);
                }
                else
                {
                    if (cfg.ProbeEvidence != null)
                    {
                        long assignAfter = GetAssignmentAttemptCount();
                        WriteAssignmentEvidenceOrThrow(cfg, process, childPid, childStart, assignBefore, assignAfter, job);
                    }
                    if (cfg.NestedProof != null)
                    {
                        WriteNestedMembershipAndSignal(cfg, process, childPid, childStart, job);
                    }

                    gate.SetEvent();

                    Stopwatch waitClock = Stopwatch.StartNew();
                    bool exited = false;
                    bool overflowStop = false;
                    while (waitClock.ElapsedMilliseconds < cfg.WaitTimeoutMilliseconds)
                    {
                        if (process.HasExited) { exited = true; break; }
                        if (overflowSignal.WaitOne(100)) { overflowStop = true; break; }
                    }
                    if (!exited && process.HasExited) { exited = true; }

                    bool timedOut = false;
                    bool terminated = false;
                    long activeAfter = -1;
                    Stopwatch terminationStopwatch = Stopwatch.StartNew();
                    if (exited)
                    {
                        long active = -1;
                        try
                        {
                            active = PollJobActiveProcessesToZero(
                                job,
                                terminationStopwatch,
                                cfg.TerminateGraceMilliseconds);
                        }
                        catch (Exception proofError)
                        {
                            cleanupErrors.Add(proofError);
                        }
                        if (active != 0)
                        {
                            terminated = CleanupManagedProcessAndJob(
                                process,
                                childPid,
                                job,
                                terminationStopwatch,
                                cfg.TerminateGraceMilliseconds,
                                "TerminateJobObject failed while cleaning up the completed bounded process.",
                                cleanupErrors,
                                out active);
                        }
                        activeAfter = active;
                    }
                    else
                    {
                        if (!overflowStop) { timedOut = true; }
                        terminated = CleanupManagedProcessAndJob(
                            process,
                            childPid,
                            job,
                            terminationStopwatch,
                            cfg.TerminateGraceMilliseconds,
                            "TerminateJobObject failed while stopping the bounded process.",
                            cleanupErrors,
                            out activeAfter);
                    }

                    DrainCleanupOutcome drain = CleanupDrainers(outDrainer, outStarted, errDrainer, errStarted, cfg.DrainDeadlineMilliseconds, false, cleanupErrors);

                    int exitCode = -1;
                    bool reallyExited = false;
                    if (process.HasExited)
                    {
                        reallyExited = true;
                        exitCode = process.ExitCode;
                    }

                    result = new BoundedProcessResult(exitCode, started, reallyExited, timedOut, terminated,
                        false, 0, drain.Overflow1, drain.Overflow2, drain.TotalBytes1,
                        drain.TotalBytes2, drain.RetainedText1, drain.RetainedText2, drain.DrainCompleted, activeAfter, cfg.CorrelationId);
                }
            }
            catch (PreAssignmentPauseException pauseException)
            {
                primary = pauseException;
            }
            catch (PostAssignmentEvidenceException evidenceException)
            {
                primary = evidenceException;
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }

            CleanupProof cleanupProof = ProveManagedLaunchQuiescence(
                process, started, assignedToJob, job, cfg.TerminateGraceMilliseconds, childPid,
                outDrainer, outStarted, errDrainer, errStarted, cfg.DrainDeadlineMilliseconds, cleanupErrors);
            if (!cleanupProof.CanRelease)
            {
                Exception invariant = new ContainedLaunchOwnershipQuarantinedException(
                    "bounded process cleanup could not prove process, job, and drainer quiescence; ownership was quarantined.");
                if (primary == null)
                {
                    primary = invariant;
                }
                else
                {
                    cleanupErrors.Add(invariant);
                }
                QuarantineManagedLaunch(
                    ref process, ref job, ref gate, ref paths,
                    ref outDrainer, ref errDrainer, ref overflowSignal);
                throw ComposeCleanupException(primary, cleanupErrors.ToArray());
            }

            if (process != null)
            {
                try { process.Dispose(); }
                catch (Exception disposeError) { cleanupErrors.Add(disposeError); }
            }
            if (overflowSignal != null)
            {
                try { overflowSignal.Close(); }
                catch (Exception closeError) { cleanupErrors.Add(closeError); }
            }
            ReleaseNativeResources(gate, ref job, ref securityDescriptor, ref saBuffer, cleanupErrors);
            if (paths != null)
            {
                paths.ReleaseAndCleanup(cleanupErrors);
            }

            Exception composed = ComposeCleanupException(primary, cleanupErrors.ToArray());
            if (composed != null)
            {
                throw composed;
            }
            return result;
        }

        private static long ReadStartFileTime(Process process)
        {
            return process.StartTime.ToFileTimeUtc();
        }

        private static void RunPauseSeam(ProcessLaunchConfiguration cfg, Process process, int childPid, long childStart, IntPtr job, long runEntryAssignmentCount, List<Exception> cleanupErrors)
        {
            PauseConfiguration pause = cfg.PauseConfiguration;
            Guid correlationId = cfg.CorrelationId;

            try
            {
                WriteIdentityFiles(pause.IdentityDirectory, childPid, childStart, cfg.GateEventName);
            }
            catch (IOException identityError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, identityError.Message, identityError);
            }
            catch (UnauthorizedAccessException identityAccessError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, identityAccessError.Message, identityAccessError);
            }
            catch (LaunchPathIdentityException identityPathError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, identityPathError.Message, identityPathError);
            }
            catch (ReceiptGrammarException identityGrammarError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, identityGrammarError.Message, identityGrammarError);
            }

            NamedEvent readiness = null;
            NamedEvent ack = null;
            NamedEvent membership = null;
            NamedEvent releaseWaitArmed = null;
            NamedEvent release = null;
            try
            {
                readiness = NamedEvent.OpenExisting(pause.ReadinessEventName, EventAccessMode.SetOnly, EventRole.Readiness, correlationId);
                readiness.SetEvent();

                ack = NamedEvent.OpenExisting(pause.ObserverAckEventName, EventAccessMode.WaitOnly, EventRole.ObserverAck, correlationId);
                NativeWaitStatus ackStatus = ack.Wait(pause.AckTimeoutMilliseconds);
                if (ackStatus == NativeWaitStatus.Timeout)
                {
                    StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                    throw new PreAssignmentPauseException(PauseReason.AckTimeout, childPid, childStart, "observer acknowledgement timed out before assignment.");
                }

                if (cfg.ParentLossMembership != null)
                {
                    bool inJob;
                    if (!IsProcessInJob(process.Handle, job, out inJob))
                    {
                        int membershipError = Marshal.GetLastWin32Error();
                        Win32Exception membershipFailure = new Win32Exception(membershipError, "IsProcessInJob(parent-loss) failed.");
                        StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                        throw new PreAssignmentPauseException(PauseReason.MembershipFailure, childPid, childStart, membershipFailure.Message, membershipFailure);
                    }
                    long assignmentDelta = GetAssignmentAttemptCount() - runEntryAssignmentCount;
                    WriteParentLossReceipt(cfg.ParentLossMembership, childPid, childStart, inJob, assignmentDelta);
                    membership = NamedEvent.OpenExisting(cfg.ParentLossMembership.MembershipReadyEventName, EventAccessMode.SetOnly, EventRole.MembershipReady, correlationId);
                    membership.SetEvent();
                }

                releaseWaitArmed = NamedEvent.OpenExisting(pause.ReleaseWaitArmedEventName, EventAccessMode.SetOnly, EventRole.ReleaseWaitArmed, correlationId);
                release = NamedEvent.OpenExisting(pause.ReleaseEventName, EventAccessMode.WaitOnly, EventRole.Release, correlationId);
                NativeWaitStatus releaseStatus = releaseWaitArmed.SignalObjectAndWaitOn(release, pause.ReleaseTimeoutMilliseconds);
                if (releaseStatus == NativeWaitStatus.Timeout)
                {
                    StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                    throw new PreAssignmentPauseException(PauseReason.ReleaseTimeout, childPid, childStart, "release wait timed out before assignment.");
                }
                if (releaseStatus != NativeWaitStatus.Object0)
                {
                    StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                    throw new PreAssignmentPauseException(PauseReason.WaitFailure, childPid, childStart, "SignalObjectAndWait returned unexpected status " + releaseStatus.ToString() + " before assignment.");
                }
            }
            catch (PreAssignmentPauseException)
            {
                throw;
            }
            catch (EventOpenException openError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.EventFailure, childPid, childStart, openError.Message, openError);
            }
            catch (EventSquatException squatError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.EventFailure, childPid, childStart, squatError.Message, squatError);
            }
            catch (EventNameGrammarException grammarError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.EventFailure, childPid, childStart, grammarError.Message, grammarError);
            }
            catch (NativeWaitException waitError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.WaitFailure, childPid, childStart, waitError.Message, waitError);
            }
            catch (ObjectDisposedException disposedError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.EventFailure, childPid, childStart, disposedError.Message, disposedError);
            }
            catch (Win32Exception nativeError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.EventFailure, childPid, childStart, nativeError.Message, nativeError);
            }
            catch (ReceiptGrammarException receiptGrammarError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, receiptGrammarError.Message, receiptGrammarError);
            }
            catch (LaunchPathIdentityException receiptPathError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, receiptPathError.Message, receiptPathError);
            }
            catch (UnauthorizedAccessException receiptAccessError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, receiptAccessError.Message, receiptAccessError);
            }
            catch (IOException receiptError)
            {
                StopGatedChild(process, cfg.TerminateGraceMilliseconds, childPid, cleanupErrors);
                throw new PreAssignmentPauseException(PauseReason.IdentityFailure, childPid, childStart, receiptError.Message, receiptError);
            }
            finally
            {
                DisposeEventQuietly(readiness, cleanupErrors);
                DisposeEventQuietly(ack, cleanupErrors);
                DisposeEventQuietly(membership, cleanupErrors);
                DisposeEventQuietly(releaseWaitArmed, cleanupErrors);
                DisposeEventQuietly(release, cleanupErrors);
            }
        }

        private static void DisposeEventQuietly(NamedEvent namedEvent, List<Exception> cleanupErrors)
        {
            if (namedEvent == null)
            {
                return;
            }
            try { namedEvent.Close(); }
            catch (Win32Exception closeError) { cleanupErrors.Add(closeError); }
        }

        private static void WriteAssignmentEvidenceOrThrow(ProcessLaunchConfiguration cfg, Process process, int childPid, long childStart, long assignBefore, long assignAfter, IntPtr job)
        {
            if (assignAfter != assignBefore + 1)
            {
                ReceiptGrammarException deltaFailure = new ReceiptGrammarException("assignment-evidence.txt",
                    "assignment evidence requires after == before + 1; observed before=" + assignBefore.ToString(CultureInfo.InvariantCulture) +
                    " after=" + assignAfter.ToString(CultureInfo.InvariantCulture) + ".");
                HandleEvidenceFailure(cfg, process, childPid, childStart, job, deltaFailure);
                return;
            }
            byte[] bytes = BuildAssignmentEvidenceRecord(cfg.CorrelationId, childPid, childStart, assignBefore, assignAfter);
            try
            {
                WriteBoundedReceipt(cfg.ProbeEvidence.EvidenceDirectory, "assignment-evidence.txt", bytes, ReceiptCapBytes);
            }
            catch (IOException evidenceError)
            {
                HandleEvidenceFailure(cfg, process, childPid, childStart, job, evidenceError);
            }
            catch (UnauthorizedAccessException evidenceAccessError)
            {
                HandleEvidenceFailure(cfg, process, childPid, childStart, job, evidenceAccessError);
            }
            catch (LaunchPathIdentityException evidencePathError)
            {
                HandleEvidenceFailure(cfg, process, childPid, childStart, job, evidencePathError);
            }
            catch (ReceiptGrammarException evidenceGrammarError)
            {
                HandleEvidenceFailure(cfg, process, childPid, childStart, job, evidenceGrammarError);
            }
        }

        private static void HandleEvidenceFailure(ProcessLaunchConfiguration cfg, Process process, int childPid, long childStart, IntPtr job, Exception evidenceCause)
        {
            List<Exception> terminationErrors = new List<Exception>();
            Stopwatch terminationStopwatch = Stopwatch.StartNew();
            if (job == IntPtr.Zero)
            {
                terminationErrors.Add(new ChildTerminationException(childPid, "no inner job handle was available to terminate after assignment-evidence failure."));
            }
            long active;
            CleanupManagedProcessAndJob(
                process,
                childPid,
                job,
                terminationStopwatch,
                cfg.TerminateGraceMilliseconds,
                "TerminateJobObject failed after assignment-evidence failure.",
                terminationErrors,
                out active);
            if (job != IntPtr.Zero && active > 0)
            {
                terminationErrors.Add(new ChildTerminationException(childPid,
                    "inner job still reports " + active.ToString(CultureInfo.InvariantCulture) + " active processes after assignment-evidence failure."));
            }
            if (terminationErrors.Count == 0)
            {
                throw new PostAssignmentEvidenceException(childPid, childStart, cfg.CorrelationId, evidenceCause);
            }
            AggregateException aggregate = new AggregateException("post-assignment evidence termination failures.", terminationErrors.ToArray());
            throw new PostAssignmentEvidenceException(childPid, childStart, cfg.CorrelationId, evidenceCause, evidenceCause, aggregate);
        }

        private static void WriteNestedMembershipAndSignal(ProcessLaunchConfiguration cfg, Process process, int childPid, long childStart, IntPtr job)
        {
            NestedProof nested = cfg.NestedProof;
            bool inJob;
            if (!IsProcessInJob(process.Handle, job, out inJob))
            {
                throw Win32("IsProcessInJob(nested)");
            }
            byte[] bytes = BuildNestedMembershipRecord(nested.Nonce, cfg.CorrelationId, childPid, childStart, inJob);
            WriteBoundedReceipt(nested.ControlRoot, "nested-membership.txt", bytes, ReceiptCapBytes);
            NamedEvent evidenceReady = NamedEvent.OpenExisting(nested.NestedEvidenceReadyEventName, EventAccessMode.SetOnly, EventRole.NestedEvidenceReady, cfg.CorrelationId);
            try { evidenceReady.SetEvent(); }
            finally { evidenceReady.Dispose(); }
            if (!inJob)
            {
                throw new NestedMembershipException(childPid, false, "nested inner-job membership receipt recorded false; nested Job capability is unsupported on this host.");
            }
        }

        private static void WriteParentLossReceipt(ParentLossMembership membership, int childPid, long childStart, bool inJob, long assignmentAttemptDelta)
        {
            byte[] bytes = BuildParentLossMembershipRecord(membership.ParentNonce, membership.CorrelationId, childPid, childStart, inJob, assignmentAttemptDelta);
            WriteBoundedReceipt(membership.ReceiptRoot, membership.ReceiptLeaf, bytes, ReceiptCapBytes);
        }

        private static void WriteIdentityFiles(string identityDirectory, int childPid, long childStart, string gateEventName)
        {
            string childIdentity = ((uint)childPid).ToString(CultureInfo.InvariantCulture) + "\t" + childStart.ToString(CultureInfo.InvariantCulture) + "\n";
            WriteBoundedReceipt(identityDirectory, "child-identity.txt", EncodeStrictAscii(childIdentity), IdentityCapBytes);
            string gateFile = gateEventName + "\n";
            WriteBoundedReceipt(identityDirectory, "gate-name.txt", EncodeStrictAscii(gateFile), IdentityCapBytes);
        }

        public static byte[] BuildAssignmentEvidenceRecord(Guid correlationId, int childProcessId, long childStartTimeFileTimeUtc, long assignmentCountBefore, long assignmentCountAfter)
        {
            string record = "pspkt-phase4-assignment-v1\t" + correlationId.ToString("N") + "\t" +
                ((uint)childProcessId).ToString(CultureInfo.InvariantCulture) + "\t" +
                childStartTimeFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "\t" +
                assignmentCountBefore.ToString(CultureInfo.InvariantCulture) + "\t" +
                assignmentCountAfter.ToString(CultureInfo.InvariantCulture) + "\n";
            return EncodeStrictAscii(record);
        }

        public static byte[] BuildNestedMembershipRecord(string nonce, Guid correlationId, int childProcessId, long childStartTimeFileTimeUtc, bool inJob)
        {
            RequireLowercaseGuidN(nonce, "nested nonce");
            string record = "pspkt-phase4-nested-membership-v1\t" + nonce + "\t" +
                correlationId.ToString("N") + "\t" +
                ((uint)childProcessId).ToString(CultureInfo.InvariantCulture) + "\t" +
                childStartTimeFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "\t" +
                (inJob ? "true" : "false") + "\n";
            return EncodeStrictAscii(record);
        }

        public static byte[] BuildNestedChildExitRecord(string nonce, Guid correlationId, int childProcessId, long childStartTimeFileTimeUtc, int exitCode)
        {
            RequireLowercaseGuidN(nonce, "nested nonce");
            string record = "pspkt-phase4-nested-exit-v1\t" + nonce + "\t" +
                correlationId.ToString("N") + "\t" +
                ((uint)childProcessId).ToString(CultureInfo.InvariantCulture) + "\t" +
                childStartTimeFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "\t" +
                exitCode.ToString(CultureInfo.InvariantCulture) + "\n";
            return EncodeStrictAscii(record);
        }

        public static byte[] BuildParentLossMembershipRecord(string parentNonce, Guid correlationId, int childProcessId, long childStartTimeFileTimeUtc, bool inJob, long assignmentAttemptDelta)
        {
            RequireLowercaseGuidN(parentNonce, "parent nonce");
            string record = "pspkt-phase4-parent-loss-membership-v1\t" + parentNonce + "\t" +
                correlationId.ToString("N") + "\t" +
                ((uint)childProcessId).ToString(CultureInfo.InvariantCulture) + "\t" +
                childStartTimeFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "\t" +
                (inJob ? "true" : "false") + "\t" +
                assignmentAttemptDelta.ToString(CultureInfo.InvariantCulture) + "\n";
            return EncodeStrictAscii(record);
        }

        public static byte[] BuildWorkerDescendantReadyRecord(string workerNonce, int childProcessId, long childStartTimeFileTimeUtc)
        {
            RequireLowercaseGuidN(workerNonce, "worker nonce");
            string record = "pspkt-phase4-worker-descendant-v1\t" + workerNonce + "\t" +
                ((uint)childProcessId).ToString(CultureInfo.InvariantCulture) + "\t" +
                childStartTimeFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "\n";
            return EncodeStrictAscii(record);
        }

        public static byte[] BuildPostGateReadyRecord(int childProcessId, long childStartTimeFileTimeUtc)
        {
            string record = "pspkt-phase4-post-gate-v1\t" +
                ((uint)childProcessId).ToString(CultureInfo.InvariantCulture) + "\t" +
                childStartTimeFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "\n";
            return EncodeStrictAscii(record);
        }

        public static byte[] BuildFailFastSentinelRecord(string helperVersion, string probeNonce, long snapshotAccessCount)
        {
            if (helperVersion == null) { throw new ArgumentNullException("helperVersion"); }
            RequireLowercaseGuidN(probeNonce, "probe nonce");
            string record = "pspkt-phase4-failfast-sentinel-v1\t" + helperVersion + "\t" + probeNonce + "\t" +
                snapshotAccessCount.ToString(CultureInfo.InvariantCulture) + "\n";
            return EncodeStrictAscii(record);
        }

        public static void WriteNestedChildExitReceipt(string controlRoot, string nonce, Guid correlationId, int childProcessId, long childStartTimeFileTimeUtc, int exitCode, string childExitedEventName)
        {
            if (childExitedEventName == null) { throw new ArgumentNullException("childExitedEventName"); }
            byte[] bytes = BuildNestedChildExitRecord(nonce, correlationId, childProcessId, childStartTimeFileTimeUtc, exitCode);
            WriteBoundedReceipt(controlRoot, "nested-child-exit.txt", bytes, ReceiptCapBytes);
            NamedEvent childExited = NamedEvent.OpenExisting(childExitedEventName, EventAccessMode.SetOnly, EventRole.NestedChildExited, correlationId);
            try { childExited.SetEvent(); }
            finally { childExited.Dispose(); }
        }

        public static void WriteWorkerDescendantReceipt(string resultRoot, string resultLeaf, string workerNonce, int childProcessId, long childStartTimeFileTimeUtc)
        {
            byte[] bytes = BuildWorkerDescendantReadyRecord(workerNonce, childProcessId, childStartTimeFileTimeUtc);
            WriteBoundedReceipt(resultRoot, resultLeaf, bytes, DescendantReceiptCapBytes);
        }

        public static void WriteCertificationReceipt(string root, string leaf, byte[] bytes, int capBytes)
        {
            WriteBoundedReceipt(root, leaf, bytes, capBytes);
        }

        public static byte[] ReadBoundedReceipt(string root, string leaf, int capBytes)
        {
            if (capBytes < 1) { throw new ArgumentOutOfRangeException("capBytes"); }
            string fullPath = ResolveContainedLeaf(root, leaf);
            using (FileStream stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (stream.Length > (long)capBytes)
                {
                    throw new ReceiptGrammarException(leaf, "receipt '" + leaf + "' is " + stream.Length.ToString(CultureInfo.InvariantCulture) + " bytes and exceeds the " + capBytes.ToString(CultureInfo.InvariantCulture) + "-byte cap.");
                }
                byte[] buffer = new byte[(int)stream.Length];
                int offset = 0;
                while (offset < buffer.Length)
                {
                    int read = stream.Read(buffer, offset, buffer.Length - offset);
                    if (read <= 0)
                    {
                        throw new IOException("bounded read of '" + fullPath + "' returned fewer bytes than the reported length.");
                    }
                    offset += read;
                }
                return buffer;
            }
        }

        private static void RequireLowercaseGuidN(string value, string label)
        {
            if (!IsLowercaseGuidN(value))
            {
                throw new ReceiptGrammarException(null, label + " must be a lowercase 32-character GUID 'N' value.");
            }
        }

        private static byte[] EncodeStrictAscii(string record)
        {
            if (record == null)
            {
                throw new ReceiptGrammarException(null, "receipt record is null.");
            }
            if (record.Length == 0 || record[record.Length - 1] != '\n')
            {
                throw new ReceiptGrammarException(null, "receipt record must terminate with exactly one LF.");
            }
            for (int index = 0; index < record.Length; index++)
            {
                char c = record[index];
                if (c > '\u007F')
                {
                    throw new ReceiptGrammarException(null, "receipt record contains a non-ASCII character at index " + index.ToString(CultureInfo.InvariantCulture) + ".");
                }
                if (c == '\r')
                {
                    throw new ReceiptGrammarException(null, "receipt record contains a CR character.");
                }
                if (c == '\n' && index != record.Length - 1)
                {
                    throw new ReceiptGrammarException(null, "receipt record contains an embedded LF character.");
                }
                if (c == '\0')
                {
                    throw new ReceiptGrammarException(null, "receipt record contains a NUL character.");
                }
                if (c < ' ' && c != '\t' && c != '\n')
                {
                    throw new ReceiptGrammarException(null, "receipt record contains a control character at index " + index.ToString(CultureInfo.InvariantCulture) + ".");
                }
            }
            byte[] bytes = new byte[record.Length];
            for (int index = 0; index < record.Length; index++)
            {
                bytes[index] = (byte)record[index];
            }
            return bytes;
        }

        private static string ResolveContainedLeaf(string root, string leaf)
        {
            if (root == null) { throw new LaunchPathIdentityException(null, "receipt root is null."); }
            if (!IsLegalReceiptLeaf(leaf))
            {
                throw new ReceiptGrammarException(leaf, "receipt leaf '" + (leaf == null ? "<null>" : leaf) + "' is not a legal bounded leaf name.");
            }
            string canonicalRoot = RequireOrdinaryNonReparseDirectory(root);
            string combined = Path.Combine(canonicalRoot, leaf);
            string fullPath;
            try { fullPath = Path.GetFullPath(combined); }
            catch (ArgumentException pathError) { throw new LaunchPathIdentityException(combined, "receipt path could not be canonicalized.", pathError); }
            catch (NotSupportedException pathError) { throw new LaunchPathIdentityException(combined, "receipt path could not be canonicalized.", pathError); }
            catch (PathTooLongException pathError) { throw new LaunchPathIdentityException(combined, "receipt path could not be canonicalized.", pathError); }
            string parent = Path.GetDirectoryName(fullPath);
            if (parent == null || !string.Equals(TrimTrailingSeparator(parent), canonicalRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new LaunchPathIdentityException(fullPath, "receipt path escapes its owner root '" + canonicalRoot + "'.");
            }
            return fullPath;
        }

        private static void WriteBoundedReceipt(string root, string leaf, byte[] bytes, int capBytes)
        {
            if (bytes == null) { throw new ArgumentNullException("bytes"); }
            if (capBytes < 1) { throw new ArgumentOutOfRangeException("capBytes"); }
            if (bytes.Length > capBytes)
            {
                throw new ReceiptGrammarException(leaf, "receipt '" + leaf + "' is " + bytes.Length.ToString(CultureInfo.InvariantCulture) + " bytes and exceeds the " + capBytes.ToString(CultureInfo.InvariantCulture) + "-byte cap.");
            }
            for (int index = 0; index < bytes.Length; index++)
            {
                if (bytes[index] > 0x7F)
                {
                    throw new ReceiptGrammarException(leaf, "receipt '" + leaf + "' contains a non-ASCII byte at offset " + index.ToString(CultureInfo.InvariantCulture) + ".");
                }
            }
            string fullPath = ResolveContainedLeaf(root, leaf);
            WriteAndVerifyCreateNew(fullPath, bytes);
        }

        private static string TrimTrailingSeparator(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return path;
            }
            if (path.Length > 3 && (path[path.Length - 1] == Path.DirectorySeparatorChar || path[path.Length - 1] == Path.AltDirectorySeparatorChar))
            {
                return path.Substring(0, path.Length - 1);
            }
            return path;
        }

        private static string RequireOrdinaryNonReparseDirectory(string path)
        {
            string fullPath;
            try { fullPath = TrimTrailingSeparator(Path.GetFullPath(path)); }
            catch (ArgumentException pathError) { throw new LaunchPathIdentityException(path, "directory path could not be canonicalized.", pathError); }
            catch (NotSupportedException pathError) { throw new LaunchPathIdentityException(path, "directory path could not be canonicalized.", pathError); }
            catch (PathTooLongException pathError) { throw new LaunchPathIdentityException(path, "directory path could not be canonicalized.", pathError); }
            DirectoryInfo info = new DirectoryInfo(fullPath);
            if (!info.Exists)
            {
                throw new LaunchPathIdentityException(fullPath, "directory '" + fullPath + "' does not exist.");
            }
            FileAttributes attributes = info.Attributes;
            if ((attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                throw new LaunchPathIdentityException(fullPath, "directory '" + fullPath + "' is a reparse point.");
            }
            if ((attributes & FileAttributes.Directory) != FileAttributes.Directory)
            {
                throw new LaunchPathIdentityException(fullPath, "path '" + fullPath + "' is not an ordinary directory.");
            }
            return fullPath;
        }

        private static void WriteAndVerifyCreateNew(string path, byte[] bytes)
        {
            using (FileStream stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            using (FileStream verify = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] readBack = new byte[bytes.Length];
                int offset = 0;
                while (offset < readBack.Length)
                {
                    int read = verify.Read(readBack, offset, readBack.Length - offset);
                    if (read <= 0)
                    {
                        throw new IOException("verification read of '" + path + "' returned fewer bytes than written.");
                    }
                    offset += read;
                }
                if (verify.ReadByte() != -1)
                {
                    throw new IOException("verification read of '" + path + "' found trailing bytes.");
                }
                for (int index = 0; index < bytes.Length; index++)
                {
                    if (bytes[index] != readBack[index])
                    {
                        throw new IOException("verification read of '" + path + "' mismatched at byte " + index.ToString(CultureInfo.InvariantCulture) + ".");
                    }
                }
            }
        }

        public static void TerminateAndProveExit(Process process, int expectedProcessId, int timeoutMilliseconds)
        {
            if (process == null) { throw new ArgumentNullException("process"); }
            if (timeoutMilliseconds < 0) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            TerminateAndProveExit(process, expectedProcessId, timeoutStopwatch, timeoutMilliseconds);
        }

        private static void TerminateAndProveExit(
            Process process,
            int expectedProcessId,
            Stopwatch timeoutStopwatch,
            int timeoutMilliseconds)
        {
            if (process == null) { throw new ArgumentNullException("process"); }
            if (timeoutStopwatch == null) { throw new ArgumentNullException("timeoutStopwatch"); }
            if (timeoutMilliseconds < 0) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            if (!process.HasExited)
            {
                try { process.Kill(); }
                catch (InvalidOperationException)
                {
                    if (!process.HasExited) { throw; }
                }
                catch (Win32Exception)
                {
                    if (!process.HasExited) { throw; }
                }
            }
            if (!process.WaitForExit(GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds)))
            {
                throw new ChildTerminationException(expectedProcessId,
                    "process " + expectedProcessId.ToString(CultureInfo.InvariantCulture) + " did not exit within " + timeoutMilliseconds.ToString(CultureInfo.InvariantCulture) + " ms of termination.");
            }
            if (!process.HasExited)
            {
                throw new ChildTerminationException(expectedProcessId,
                    "process " + expectedProcessId.ToString(CultureInfo.InvariantCulture) + " still reports as running after a completed wait.");
            }
        }

        private static void StopGatedChild(Process process, int graceMilliseconds, int childPid, List<Exception> cleanupErrors)
        {
            if (process == null)
            {
                return;
            }
            try
            {
                TerminateAndProveExit(process, childPid, graceMilliseconds);
            }
            catch (ChildTerminationException terminationError) { cleanupErrors.Add(terminationError); }
            catch (InvalidOperationException stateError) { cleanupErrors.Add(stateError); }
            catch (Win32Exception nativeError) { cleanupErrors.Add(nativeError); }
        }

        private static bool CleanupManagedProcessAndJob(
            Process managedProcess,
            int childPid,
            IntPtr job,
            Stopwatch timeoutStopwatch,
            int timeoutMilliseconds,
            string terminateJobFailureMessage,
            List<Exception> cleanupErrors,
            out long activeAfter)
        {
            if (timeoutStopwatch == null)
            {
                throw new ArgumentNullException("timeoutStopwatch");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            if (terminateJobFailureMessage == null)
            {
                throw new ArgumentNullException("terminateJobFailureMessage");
            }

            bool jobTerminated = false;
            activeAfter = -1;
            if (job != IntPtr.Zero)
            {
                if (TerminateJob(job))
                {
                    jobTerminated = true;
                }
                else
                {
                    cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), terminateJobFailureMessage));
                }
            }

            if (managedProcess != null)
            {
                try
                {
                    TerminateAndProveExit(
                        managedProcess,
                        childPid,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                }
                catch (Exception terminationError)
                {
                    cleanupErrors.Add(terminationError);
                }
            }

            if (job != IntPtr.Zero)
            {
                try
                {
                    activeAfter = PollJobActiveProcessesToZero(
                        job,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                }
                catch (Exception proofError)
                {
                    cleanupErrors.Add(proofError);
                }
            }
            return jobTerminated;
        }

        private static void StopStartedProcess(
            Process process,
            bool assignedToJob,
            IntPtr job,
            Stopwatch timeoutStopwatch,
            int timeoutMilliseconds,
            int childPid,
            List<Exception> cleanupErrors)
        {
            if (timeoutStopwatch == null)
            {
                throw new ArgumentNullException("timeoutStopwatch");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            if (process == null)
            {
                return;
            }
            try
            {
                if (assignedToJob && job != IntPtr.Zero)
                {
                    bool jobHasActive = true;
                    try
                    {
                        jobHasActive = QueryJobActiveProcesses(job) > 0;
                    }
                    catch (Win32Exception queryError)
                    {
                        cleanupErrors.Add(queryError);
                        jobHasActive = true;
                    }
                    if (jobHasActive && !TerminateJobObject(job, 1))
                    {
                        cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed while stopping the started child."));
                    }
                    TerminateAndProveExit(
                        process,
                        childPid,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                }
                else
                {
                    TerminateAndProveExit(
                        process,
                        childPid,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                }
            }
            catch (ChildTerminationException terminationError) { cleanupErrors.Add(terminationError); }
            catch (InvalidOperationException stateError) { cleanupErrors.Add(stateError); }
            catch (Win32Exception nativeError) { cleanupErrors.Add(nativeError); }
        }

        internal static bool ProveManagedProcessExit(Process process, int childPid, int timeoutMilliseconds, List<Exception> cleanupErrors)
        {
            if (process == null)
            {
                return true;
            }
            try
            {
                TerminateAndProveExit(process, childPid, timeoutMilliseconds);
                return process.HasExited;
            }
            catch (Exception proofError) { cleanupErrors.Add(proofError); }
            return false;
        }

        private static CleanupProof ProveManagedLaunchQuiescence(
            Process process,
            bool started,
            bool assignedToJob,
            IntPtr job,
            int timeoutMilliseconds,
            int childPid,
            StreamDrainer outDrainer,
            bool outStarted,
            StreamDrainer errDrainer,
            bool errStarted,
            int drainDeadlineMilliseconds,
            List<Exception> cleanupErrors)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            CleanupProof proof = new CleanupProof();
            proof.OwnsStartedProcess = started && process != null;
            proof.OwnsAssignedJob = assignedToJob && job != IntPtr.Zero;
            proof.OwnsDrainerResources =
                outStarted ||
                errStarted ||
                outDrainer != null ||
                errDrainer != null;

            if (proof.OwnsStartedProcess)
            {
                StopStartedProcess(
                    process,
                    assignedToJob,
                    job,
                    timeoutStopwatch,
                    timeoutMilliseconds,
                    childPid,
                    cleanupErrors);
                try { proof.ProcessExited = process.HasExited; }
                catch (Exception proofError) { cleanupErrors.Add(proofError); }
            }
            if (proof.OwnsAssignedJob)
            {
                try
                {
                    long active = PollJobActiveProcessesToZero(
                        job,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                    proof.JobZeroProven = active == 0;
                    if (!proof.JobZeroProven)
                    {
                        cleanupErrors.Add(new ContainedWorkerException("job still reports " + active.ToString(CultureInfo.InvariantCulture) + " active processes after terminating process " + childPid.ToString(CultureInfo.InvariantCulture) + " during partial-launch cleanup."));
                    }
                }
                catch (Exception proofError) { cleanupErrors.Add(proofError); }
            }
            if (proof.OwnsDrainerResources)
            {
                DrainCleanupOutcome drain = CleanupDrainers(
                    outDrainer, outStarted, errDrainer, errStarted,
                    drainDeadlineMilliseconds, false, cleanupErrors);
                proof.DrainersQuiesced = drain.DrainersQuiesced;
            }
            return proof;
        }

        private static CleanupProof ProveNativeLaunchQuiescence(
            bool processCreated,
            PROCESS_INFORMATION processInfo,
            bool assignedToJob,
            IntPtr job,
            int timeoutMilliseconds,
            List<Exception> cleanupErrors)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            CleanupProof proof = new CleanupProof();
            proof.OwnsStartedProcess = processCreated && processInfo.hProcess != IntPtr.Zero;
            proof.OwnsAssignedJob = assignedToJob && job != IntPtr.Zero;
            if (processCreated)
            {
                try
                {
                    if (assignedToJob && job != IntPtr.Zero)
                    {
                        if (!TerminateJob(job))
                        {
                            cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed while cleaning up a partial launch for process " + processInfo.dwProcessId.ToString(CultureInfo.InvariantCulture) + "."));
                        }
                        WaitProcessExactly(
                            processInfo.hProcess,
                            GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds),
                            processInfo.dwProcessId);
                    }
                    else
                    {
                        TerminateAndProveNativeExit(
                            processInfo.hProcess,
                            processInfo.dwProcessId,
                            timeoutStopwatch,
                            timeoutMilliseconds);
                    }
                    uint exitCode;
                    if (!GetExitCodeProcess(processInfo.hProcess, out exitCode))
                    {
                        cleanupErrors.Add(Win32("GetExitCodeProcess(partial launch)"));
                    }
                    else
                    {
                        proof.ProcessExited = exitCode != STILL_ACTIVE_STATUS;
                    }
                }
                catch (Exception proofError) { cleanupErrors.Add(proofError); }
            }
            if (proof.OwnsAssignedJob)
            {
                try
                {
                    long active = PollJobActiveProcessesToZero(
                        job,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                    proof.JobZeroProven = active == 0;
                    if (!proof.JobZeroProven)
                    {
                        cleanupErrors.Add(new ContainedWorkerException("job still reports " + active.ToString(CultureInfo.InvariantCulture) + " active processes after terminating process " + processInfo.dwProcessId.ToString(CultureInfo.InvariantCulture) + " during partial-launch cleanup."));
                    }
                }
                catch (Exception proofError) { cleanupErrors.Add(proofError); }
            }
            return proof;
        }

        private static void ReleasePartialNativeLaunch(
            ref PROCESS_INFORMATION processInfo,
            ref IntPtr job,
            ref NamedEvent gate,
            ref LaunchPathBinding paths,
            List<Exception> cleanupErrors)
        {
            if (processInfo.hThread != IntPtr.Zero)
            {
                IntPtr thread = processInfo.hThread;
                processInfo.hThread = IntPtr.Zero;
                if (!CloseHandle(thread))
                {
                    cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(primary thread) failed while cleaning up a partial launch."));
                    QuarantineRawHandle(thread);
                }
            }
            if (processInfo.hProcess != IntPtr.Zero)
            {
                IntPtr process = processInfo.hProcess;
                processInfo.hProcess = IntPtr.Zero;
                if (!CloseHandle(process))
                {
                    cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(process) failed while cleaning up a partial launch."));
                    QuarantineRawHandle(process);
                }
            }
            if (gate != null)
            {
                try { gate.Close(); }
                catch (Exception gateError) { cleanupErrors.Add(gateError); }
                gate = null;
            }
            if (job != IntPtr.Zero)
            {
                IntPtr currentJob = job;
                job = IntPtr.Zero;
                if (!CloseHandle(currentJob))
                {
                    cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(job) failed while cleaning up a partial launch."));
                    QuarantineRawHandle(currentJob);
                }
            }
            if (paths != null)
            {
                paths.ReleaseAndCleanup(cleanupErrors);
                paths = null;
            }
        }

        private static void QuarantineNativeLaunch(
            ref PROCESS_INFORMATION processInfo,
            ref IntPtr job,
            ref NamedEvent gate,
            ref LaunchPathBinding paths)
        {
            object[] owners = new object[] { gate, paths };
            IntPtr[] handles = new IntPtr[] { job, processInfo.hProcess, processInfo.hThread };
            QuarantineLaunch(owners, handles);
            processInfo.hProcess = IntPtr.Zero;
            processInfo.hThread = IntPtr.Zero;
            job = IntPtr.Zero;
            gate = null;
            paths = null;
        }

        private static void QuarantineManagedLaunch(
            ref Process process,
            ref IntPtr job,
            ref NamedEvent gate,
            ref LaunchPathBinding paths,
            ref StreamDrainer outDrainer,
            ref StreamDrainer errDrainer,
            ref ManualResetEvent overflowSignal)
        {
            object[] owners = new object[] { process, gate, paths, outDrainer, errDrainer, overflowSignal };
            QuarantineLaunch(owners, new IntPtr[] { job });
            process = null;
            job = IntPtr.Zero;
            gate = null;
            paths = null;
            outDrainer = null;
            errDrainer = null;
            overflowSignal = null;
        }

        private static void ReleaseJobSecurityAllocations(
            ref IntPtr securityDescriptor,
            ref IntPtr securityAttributes,
            List<Exception> cleanupErrors)
        {
            if (securityDescriptor != IntPtr.Zero)
            {
                IntPtr descriptor = securityDescriptor;
                securityDescriptor = IntPtr.Zero;
                if (LocalFree(descriptor) != IntPtr.Zero)
                {
                    cleanupErrors.Add(Win32("LocalFree(securityDescriptor)"));
                    QuarantineRawHandle(descriptor);
                }
            }
            if (securityAttributes != IntPtr.Zero)
            {
                IntPtr attributes = securityAttributes;
                securityAttributes = IntPtr.Zero;
                try { Marshal.FreeHGlobal(attributes); }
                catch (Exception freeError)
                {
                    cleanupErrors.Add(freeError);
                    QuarantineRawHandle(attributes);
                }
            }
        }

        internal sealed class DrainCleanupOutcome
        {
            internal bool DrainCompleted;
            internal bool DrainersQuiesced;
            internal bool ForcedClose;
            internal bool Overflow1;
            internal bool Overflow2;
            internal long TotalBytes1;
            internal long TotalBytes2;
            internal string RetainedText1;
            internal string RetainedText2;

            internal DrainCleanupOutcome()
            {
                RetainedText1 = string.Empty;
                RetainedText2 = string.Empty;
            }
        }

        private static void CaptureDrainSnapshots(
            DrainCleanupOutcome outcome,
            StreamDrainer drainer1, bool started1,
            StreamDrainer drainer2, bool started2)
        {
            if (started1 && drainer1 != null)
            {
                outcome.Overflow1 = drainer1.Overflow;
                outcome.TotalBytes1 = drainer1.TotalBytes;
                outcome.RetainedText1 = drainer1.RetainedText;
            }
            if (started2 && drainer2 != null)
            {
                outcome.Overflow2 = drainer2.Overflow;
                outcome.TotalBytes2 = drainer2.TotalBytes;
                outcome.RetainedText2 = drainer2.RetainedText;
            }
        }

        private static bool DisposeDrainerStreamCollecting(StreamDrainer drainer, List<Exception> cleanupErrors)
        {
            if (drainer == null)
            {
                return true;
            }
            Exception disposeError = drainer.DisposeStreamOnce();
            if (disposeError != null)
            {
                if (!cleanupErrors.Contains(disposeError))
                {
                    cleanupErrors.Add(disposeError);
                }
                return false;
            }
            return true;
        }

        private static DrainCleanupOutcome CleanupDrainers(
            StreamDrainer drainer1, bool started1,
            StreamDrainer drainer2, bool started2,
            int deadlineMilliseconds, bool failFastIfStuck, List<Exception> cleanupErrors)
        {
            if (deadlineMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("deadlineMilliseconds");
            }
            DrainCleanupOutcome outcome = new DrainCleanupOutcome();
            Stopwatch deadlineStopwatch = Stopwatch.StartNew();
            int forcedCloseReserveMilliseconds = Math.Min(
                DrainerForcedCloseReserveMilliseconds,
                deadlineMilliseconds == 0 ? 0 : Math.Max(1, deadlineMilliseconds / 2));
            int initialJoinDeadlineMilliseconds = deadlineMilliseconds - forcedCloseReserveMilliseconds;

            bool firstOk1 = (!started1) || (drainer1 != null && drainer1.Join(GetRemainingTimeoutMilliseconds(deadlineStopwatch, initialJoinDeadlineMilliseconds)));
            bool firstOk2 = (!started2) || (drainer2 != null && drainer2.Join(GetRemainingTimeoutMilliseconds(deadlineStopwatch, initialJoinDeadlineMilliseconds)));

            if (firstOk1 && firstOk2)
            {
                bool faulted = false;
                if (started1 && drainer1 != null && drainer1.Error != null) { faulted = true; }
                if (started2 && drainer2 != null && drainer2.Error != null) { faulted = true; }
                CaptureDrainSnapshots(outcome, drainer1, started1, drainer2, started2);
                bool disposed1 = DisposeDrainerStreamCollecting(drainer1, cleanupErrors);
                bool disposed2 = DisposeDrainerStreamCollecting(drainer2, cleanupErrors);
                outcome.DrainCompleted = !faulted;
                outcome.DrainersQuiesced = disposed1 && disposed2;
                outcome.ForcedClose = false;
                return outcome;
            }

            outcome.ForcedClose = true;
            bool forcedDisposed1 = DisposeDrainerStreamCollecting(drainer1, cleanupErrors);
            bool forcedDisposed2 = DisposeDrainerStreamCollecting(drainer2, cleanupErrors);

            bool secondOk1 = (!started1) || (drainer1 != null && drainer1.Join(GetRemainingTimeoutMilliseconds(deadlineStopwatch, deadlineMilliseconds)));
            bool secondOk2 = (!started2) || (drainer2 != null && drainer2.Join(GetRemainingTimeoutMilliseconds(deadlineStopwatch, deadlineMilliseconds)));

            bool alive1 = started1 && drainer1 != null && drainer1.IsAlive;
            bool alive2 = started2 && drainer2 != null && drainer2.IsAlive;
            if (alive1 || alive2)
            {
                if (failFastIfStuck)
                {
                    NonUnwindingFailFast("a started drainer thread still owns the process pipe after forced close and second join.");
                }
                cleanupErrors.Add(new IOException("a started drainer thread is still alive after forced stream close and both join deadlines."));
                outcome.DrainCompleted = false;
                outcome.DrainersQuiesced = false;
                return outcome;
            }
            if (!secondOk1 || !secondOk2)
            {
                cleanupErrors.Add(new IOException("a started drainer failed to join after forced stream close."));
            }
            CaptureDrainSnapshots(outcome, drainer1, started1, drainer2, started2);
            outcome.DrainCompleted = false;
            outcome.DrainersQuiesced =
                secondOk1 &&
                secondOk2 &&
                forcedDisposed1 &&
                forcedDisposed2;
            return outcome;
        }

        private static void NonUnwindingFailFast(string reason)
        {
            Environment.FailFast(reason);
        }

        private static void ReleaseNativeResources(NamedEvent gate, ref IntPtr job, ref IntPtr securityDescriptor, ref IntPtr securityAttributes, List<Exception> cleanupErrors)
        {
            if (gate != null)
            {
                try { gate.Close(); }
                catch (Exception gateError) { cleanupErrors.Add(gateError); }
            }
            if (job != IntPtr.Zero)
            {
                IntPtr currentJob = job;
                job = IntPtr.Zero;
                if (!CloseHandle(currentJob))
                {
                    cleanupErrors.Add(Win32("CloseHandle(job)"));
                    QuarantineRawHandle(currentJob);
                }
            }
            if (securityDescriptor != IntPtr.Zero)
            {
                IntPtr currentDescriptor = securityDescriptor;
                securityDescriptor = IntPtr.Zero;
                if (LocalFree(currentDescriptor) != IntPtr.Zero)
                {
                    cleanupErrors.Add(Win32("LocalFree(securityDescriptor)"));
                    QuarantineRawHandle(currentDescriptor);
                }
            }
            if (securityAttributes != IntPtr.Zero)
            {
                IntPtr currentAttributes = securityAttributes;
                securityAttributes = IntPtr.Zero;
                try { Marshal.FreeHGlobal(currentAttributes); }
                catch (Exception freeError)
                {
                    cleanupErrors.Add(freeError);
                    QuarantineRawHandle(currentAttributes);
                }
            }
        }

        public static Exception ComposeCleanupException(Exception primary, Exception[] cleanupErrors)
        {
            Exception[] errors = cleanupErrors;
            if (errors == null)
            {
                errors = new Exception[0];
            }
            if (primary == null)
            {
                if (errors.Length == 0)
                {
                    return null;
                }
                if (errors.Length == 1)
                {
                    return errors[0];
                }
                return new AggregateException("bounded-process cleanup failed.", errors);
            }
            PreAssignmentPauseException pauseException = primary as PreAssignmentPauseException;
            if (pauseException != null)
            {
                if (errors.Length == 0)
                {
                    return pauseException;
                }
                AggregateException aggregate = new AggregateException("pre-assignment pause cleanup failures.", errors);
                return new PreAssignmentPauseException(pauseException.PauseReason, pauseException.ChildProcessId, pauseException.ChildStartTimeFileTimeUtc, pauseException, aggregate);
            }
            PostAssignmentEvidenceException evidenceException = primary as PostAssignmentEvidenceException;
            if (evidenceException != null)
            {
                if (errors.Length == 0)
                {
                    return evidenceException;
                }
                AggregateException aggregate = new AggregateException("post-assignment evidence cleanup failures.", errors);
                return new PostAssignmentEvidenceException(
                    evidenceException.ChildProcessId,
                    evidenceException.ChildStartTimeFileTimeUtc,
                    evidenceException.CorrelationId,
                    evidenceException.EvidenceCause,
                    evidenceException,
                    aggregate);
            }
            if (errors.Length == 0)
            {
                return primary;
            }
            List<Exception> combined = new List<Exception>();
            combined.Add(primary);
            for (int index = 0; index < errors.Length; index++)
            {
                combined.Add(errors[index]);
            }
            return new AggregateException("bounded-process primary and cleanup failures.", combined.ToArray());
        }

        internal sealed class StreamDrainer
        {
            private const int DisposeNotStarted = 0;
            private const int DisposeInProgress = 1;
            private const int DisposeSucceeded = 2;
            private const int DisposeFailed = 3;

            private readonly Stream _stream;
            private readonly int _retainCap;
            private readonly MemoryStream _retained;
            private readonly Thread _thread;
            private readonly ManualResetEvent _overflowSignal;
            private readonly bool _injectStartFailure;
            private long _total;
            private bool _overflow;
            private Exception _error;
            private Exception _disposeError;
            private int _disposeGuard;

            internal StreamDrainer(Stream stream, int retainCap, ManualResetEvent overflowSignal, bool injectStartFailure)
            {
                _stream = stream;
                _retainCap = retainCap;
                _overflowSignal = overflowSignal;
                _injectStartFailure = injectStartFailure;
                _retained = new MemoryStream();
                _thread = new Thread(new ThreadStart(Pump));
                _thread.IsBackground = true;
                _thread.Name = "PspktPhase4Drain";
            }

            internal void Start()
            {
                if (_injectStartFailure)
                {
                    throw new InvalidOperationException("deterministic drainer start failure injected for certification.");
                }
                _thread.Start();
            }

            internal bool Join(int milliseconds)
            {
                return _thread.Join(milliseconds);
            }

            internal bool IsAlive
            {
                get { return _thread.IsAlive; }
            }

            internal Exception DisposeStreamOnce()
            {
                int disposeState = Interlocked.CompareExchange(
                    ref _disposeGuard,
                    DisposeInProgress,
                    DisposeNotStarted);
                if (disposeState == DisposeSucceeded)
                {
                    return null;
                }
                if (disposeState == DisposeFailed)
                {
                    return _disposeError;
                }
                if (disposeState == DisposeInProgress)
                {
                    return new InvalidOperationException("drainer stream disposal is already in progress.");
                }

                Exception disposeError = null;
                try { _stream.Dispose(); }
                catch (ObjectDisposedException) { }
                catch (Exception unexpectedDisposeError) { disposeError = unexpectedDisposeError; }
                _disposeError = disposeError;
                Interlocked.Exchange(
                    ref _disposeGuard,
                    disposeError == null ? DisposeSucceeded : DisposeFailed);
                return disposeError;
            }

            internal bool Overflow
            {
                get { RecordSnapshotAccess(); return _overflow; }
            }

            internal long TotalBytes
            {
                get { RecordSnapshotAccess(); return _total; }
            }

            internal Exception Error
            {
                get { RecordSnapshotAccess(); return _error; }
            }

            internal string RetainedText
            {
                get
                {
                    RecordSnapshotAccess();
                    byte[] bytes = _retained.ToArray();
                    return new UTF8Encoding(false, false).GetString(bytes);
                }
            }

            private void Pump()
            {
                byte[] buffer = new byte[8192];
                try
                {
                    while (true)
                    {
                        int read = _stream.Read(buffer, 0, buffer.Length);
                        if (read <= 0)
                        {
                            break;
                        }
                        _total += read;
                        long remainingRoom = (long)_retainCap - _retained.Length;
                        if (remainingRoom > 0)
                        {
                            int toRetain = read;
                            if (toRetain > remainingRoom)
                            {
                                toRetain = (int)remainingRoom;
                            }
                            _retained.Write(buffer, 0, toRetain);
                        }
                        if (_total > _retainCap && !_overflow)
                        {
                            _overflow = true;
                            _overflowSignal.Set();
                        }
                    }
                }
                catch (IOException ex)
                {
                    _error = ex;
                }
                catch (ObjectDisposedException ex)
                {
                    _error = ex;
                }
            }
        }

        internal sealed class DeterministicProbeStream : Stream
        {
            internal enum Mode
            {
                ImmediateEof = 0,
                BlockUntilDispose = 1,
                BlockForever = 2,
                ImmediateEofDisposeFailure = 3
            }

            private readonly Mode _mode;
            private readonly ManualResetEvent _release;
            private readonly string _disposeFailureMessage;
            private int _disposeCount;
            private bool _readEntered;

            internal DeterministicProbeStream(Mode mode)
                : this(mode, null)
            {
            }

            internal DeterministicProbeStream(Mode mode, string disposeFailureMessage)
            {
                _mode = mode;
                _release = new ManualResetEvent(false);
                _disposeFailureMessage = disposeFailureMessage;
            }

            internal int DisposeCount
            {
                get { return _disposeCount; }
            }

            internal bool ReadEntered
            {
                get { return _readEntered; }
            }

            internal void ReleaseRead()
            {
                _release.Set();
            }

            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position
            {
                get { throw new NotSupportedException(); }
                set { throw new NotSupportedException(); }
            }

            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                _readEntered = true;
                if (_mode == Mode.ImmediateEof ||
                    _mode == Mode.ImmediateEofDisposeFailure)
                {
                    return 0;
                }
                _release.WaitOne();
                return 0;
            }

            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

            protected override void Dispose(bool disposing)
            {
                Interlocked.Increment(ref _disposeCount);
                if (_mode == Mode.BlockUntilDispose)
                {
                    _release.Set();
                }
                if (_mode == Mode.ImmediateEofDisposeFailure)
                {
                    throw new IOException(_disposeFailureMessage);
                }
                base.Dispose(disposing);
            }
        }

        [DllImport("kernel32.dll")]
        private static extern void ExitProcess(uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetThreadErrorMode(uint dwNewMode, out uint lpOldMode);

        [DllImport("kernel32.dll")]
        private static extern uint GetThreadErrorMode();

        private const uint SEM_FAILCRITICALERRORS = 0x0001;
        private const uint SEM_NOGPFAULTERRORBOX = 0x0002;

        internal static long GetSnapshotAccessCount()
        {
            lock (_diagSync) { return _snapshotAccess; }
        }

        private static void RequireCleanupBudgetProbeDuration(string probeId, Stopwatch stopwatch, int deadlineMilliseconds)
        {
            long elapsedMilliseconds = stopwatch.ElapsedMilliseconds;
            long maximumMilliseconds = checked((long)deadlineMilliseconds + CleanupBudgetProbeSchedulerToleranceMilliseconds);
            if (elapsedMilliseconds > maximumMilliseconds)
            {
                throw new TimeoutException(
                    probeId + " consumed " + elapsedMilliseconds.ToString(CultureInfo.InvariantCulture) +
                    " ms for a " + deadlineMilliseconds.ToString(CultureInfo.InvariantCulture) +
                    " ms cleanup budget; maximum including scheduler tolerance is " +
                    maximumMilliseconds.ToString(CultureInfo.InvariantCulture) + " ms.");
            }
        }

        private static void RunDrainCleanupOneBudgetProbe()
        {
            DeterministicProbeStream stream1 = new DeterministicProbeStream(DeterministicProbeStream.Mode.BlockForever);
            DeterministicProbeStream stream2 = new DeterministicProbeStream(DeterministicProbeStream.Mode.BlockForever);
            ManualResetEvent overflow = new ManualResetEvent(false);
            StreamDrainer drainer1 = new StreamDrainer(stream1, 1024, overflow, false);
            StreamDrainer drainer2 = new StreamDrainer(stream2, 1024, overflow, false);
            List<Exception> cleanupErrors = new List<Exception>();
            bool started1 = false;
            bool started2 = false;
            try
            {
                drainer1.Start();
                started1 = true;
                drainer2.Start();
                started2 = true;
                WaitForProbeReads(stream1, stream2, ProbeReadEntryDeadlineMilliseconds);
                Stopwatch cleanupStopwatch = Stopwatch.StartNew();
                DrainCleanupOutcome outcome = CleanupDrainers(
                    drainer1,
                    true,
                    drainer2,
                    true,
                    CleanupBudgetProbeDeadlineMilliseconds,
                    false,
                    cleanupErrors);
                RequireCleanupBudgetProbeDuration(
                    "drain one-budget probe",
                    cleanupStopwatch,
                    CleanupBudgetProbeDeadlineMilliseconds);
                if (cleanupStopwatch.ElapsedMilliseconds < CleanupBudgetProbeDeadlineMilliseconds / 2)
                {
                    throw new InvalidOperationException("drain one-budget probe did not exercise a blocking cleanup deadline.");
                }
                if (!outcome.ForcedClose || outcome.DrainersQuiesced || outcome.DrainCompleted)
                {
                    throw new InvalidOperationException("drain one-budget probe did not report the expected stuck-drainer outcome.");
                }
                if (stream1.DisposeCount != 1 || stream2.DisposeCount != 1)
                {
                    throw new InvalidOperationException("drain one-budget probe did not force-close each stream exactly once.");
                }
                if (cleanupErrors.Count != 1 ||
                    !(cleanupErrors[0] is IOException) ||
                    !string.Equals(
                        cleanupErrors[0].Message,
                        "a started drainer thread is still alive after forced stream close and both join deadlines.",
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("drain one-budget probe did not preserve the exact stuck-drainer cleanup error.");
                }
            }

            finally
            {
                stream1.ReleaseRead();
                stream2.ReleaseRead();
                Stopwatch releaseStopwatch = Stopwatch.StartNew();
                if (started1 && !drainer1.Join(GetRemainingTimeoutMilliseconds(
                    releaseStopwatch,
                    ProbeReadEntryDeadlineMilliseconds)))
                {
                    throw new TimeoutException("drain one-budget probe stdout drainer did not exit after release.");
                }
                if (started2 && !drainer2.Join(GetRemainingTimeoutMilliseconds(
                    releaseStopwatch,
                    ProbeReadEntryDeadlineMilliseconds)))
                {
                    throw new TimeoutException("drain one-budget probe stderr drainer did not exit after release.");
                }
                overflow.Close();
            }
        }

        private static void RunStreamDisposeFailureOwnershipRegressionProbe()
        {
            const string stream1Failure = "deterministic stdout drainer stream disposal failure.";
            const string stream2Failure = "deterministic stderr drainer stream disposal failure.";
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            DeterministicProbeStream stream1 = new DeterministicProbeStream(
                DeterministicProbeStream.Mode.ImmediateEofDisposeFailure,
                stream1Failure);
            DeterministicProbeStream stream2 = new DeterministicProbeStream(
                DeterministicProbeStream.Mode.ImmediateEofDisposeFailure,
                stream2Failure);
            ManualResetEvent overflow = new ManualResetEvent(false);
            StreamDrainer drainer1 = new StreamDrainer(stream1, 1024, overflow, false);
            StreamDrainer drainer2 = new StreamDrainer(stream2, 1024, overflow, false);
            List<Exception> cleanupErrors = new List<Exception>();
            bool quarantined = false;
            try
            {
                drainer1.Start();
                drainer2.Start();
                DrainCleanupOutcome initialOutcome = CleanupDrainers(
                    drainer1,
                    true,
                    drainer2,
                    true,
                    ProbeReadEntryDeadlineMilliseconds,
                    false,
                    cleanupErrors);
                if (!initialOutcome.DrainCompleted ||
                    initialOutcome.DrainersQuiesced ||
                    drainer1.IsAlive ||
                    drainer2.IsAlive ||
                    stream1.DisposeCount != 1 ||
                    stream2.DisposeCount != 1)
                {
                    throw new InvalidOperationException("stream-disposal-failure probe did not preserve the expected joined-thread cleanup state.");
                }
                RequireStreamDisposeFailureErrors(
                    cleanupErrors,
                    stream1Failure,
                    stream2Failure);

                CleanupProof proof = ProveManagedLaunchQuiescence(
                    null,
                    false,
                    false,
                    IntPtr.Zero,
                    0,
                    0,
                    drainer1,
                    true,
                    drainer2,
                    true,
                    ProbeReadEntryDeadlineMilliseconds,
                    cleanupErrors);
                if (proof.CanRelease ||
                    proof.DrainersQuiesced ||
                    stream1.DisposeCount != 1 ||
                    stream2.DisposeCount != 1)
                {
                    throw new InvalidOperationException("stream-disposal-failure probe allowed failed stream ownership to be released.");
                }
                RequireStreamDisposeFailureErrors(
                    cleanupErrors,
                    stream1Failure,
                    stream2Failure);

                Process process = null;
                IntPtr job = IntPtr.Zero;
                NamedEvent gate = null;
                LaunchPathBinding paths = null;
                QuarantineManagedLaunch(
                    ref process,
                    ref job,
                    ref gate,
                    ref paths,
                    ref drainer1,
                    ref drainer2,
                    ref overflow);
                quarantined = true;
                BoundedProcessDiagnosticsSnapshot after = GetDiagnosticsSnapshot();
                if (after.QuarantinedLaunchCount != before.QuarantinedLaunchCount + 1 ||
                    after.QuarantinedLaunchCount == 0 ||
                    drainer1 != null ||
                    drainer2 != null ||
                    overflow != null)
                {
                    throw new InvalidOperationException("stream-disposal-failure probe did not quarantine the exact managed drainer ownership.");
                }
            }
            finally
            {
                if (!quarantined && overflow != null)
                {
                    overflow.Close();
                }
            }
        }

        private static void RequireStreamDisposeFailureErrors(
            List<Exception> cleanupErrors,
            string stream1Failure,
            string stream2Failure)
        {
            if (cleanupErrors.Count != 2 ||
                !(cleanupErrors[0] is IOException) ||
                !(cleanupErrors[1] is IOException) ||
                !string.Equals(cleanupErrors[0].Message, stream1Failure, StringComparison.Ordinal) ||
                !string.Equals(cleanupErrors[1].Message, stream2Failure, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("stream-disposal-failure probe did not preserve the exact cleanup errors.");
            }
        }

        private static Process StartCleanupBudgetProbeProcess()
        {
            string executablePath = Path.Combine(Environment.SystemDirectory, "PING.EXE");
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = executablePath;
            startInfo.Arguments = "127.0.0.1 -n 30 -w 1000";
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.RedirectStandardInput = false;
            startInfo.WorkingDirectory = Environment.SystemDirectory;
            Process probeProcess = new Process();
            probeProcess.StartInfo = startInfo;
            try
            {
                RecordProcessStart();
                probeProcess.Start();
                return probeProcess;
            }
            catch
            {
                probeProcess.Dispose();
                throw;
            }
        }

        private static void RunProcessJobCleanupOneBudgetProbe()
        {
            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr securityAttributes = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            IntPtr queryOnlyJob = IntPtr.Zero;
            Process cleanupProcess = null;
            Process survivor = null;
            List<Exception> resourceCleanupErrors = new List<Exception>();
            try
            {
                securityAttributes = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(securityAttributes);
                ReleaseJobSecurityAllocations(
                    ref securityDescriptor,
                    ref securityAttributes,
                    resourceCleanupErrors);
                if (resourceCleanupErrors.Count != 0)
                {
                    throw ComposeCleanupException(null, resourceCleanupErrors.ToArray());
                }

                cleanupProcess = StartCleanupBudgetProbeProcess();
                survivor = StartCleanupBudgetProbeProcess();
                RecordAssignmentAttempt();
                if (!AssignProcessToJobObject(job, cleanupProcess.Handle))
                {
                    throw Win32("AssignProcessToJobObject(cleanup budget process)");
                }
                RecordAssignmentAttempt();
                if (!AssignProcessToJobObject(job, survivor.Handle))
                {
                    throw Win32("AssignProcessToJobObject(cleanup budget survivor)");
                }

                using (Process currentProcess = Process.GetCurrentProcess())
                {
                    if (!DuplicateHandle(
                        currentProcess.Handle,
                        job,
                        currentProcess.Handle,
                        out queryOnlyJob,
                        JOB_OBJECT_QUERY,
                        false,
                        0))
                    {
                        throw Win32("DuplicateHandle(cleanup budget query-only job)");
                    }
                }

                List<Exception> operationalErrors = new List<Exception>();
                Stopwatch cleanupStopwatch = Stopwatch.StartNew();
                long activeAfter;
                bool jobTerminated = CleanupManagedProcessAndJob(
                    cleanupProcess,
                    cleanupProcess.Id,
                    queryOnlyJob,
                    cleanupStopwatch,
                    CleanupBudgetProbeDeadlineMilliseconds,
                    "TerminateJobObject failed for the process/job one-budget probe.",
                    operationalErrors,
                    out activeAfter);
                RequireCleanupBudgetProbeDuration(
                    "process/job one-budget probe",
                    cleanupStopwatch,
                    CleanupBudgetProbeDeadlineMilliseconds);
                if (cleanupStopwatch.ElapsedMilliseconds < CleanupBudgetProbeDeadlineMilliseconds / 2)
                {
                    throw new InvalidOperationException("process/job one-budget probe did not exercise job-zero polling for the cleanup deadline.");
                }
                if (jobTerminated)
                {
                    throw new InvalidOperationException("process/job one-budget probe unexpectedly terminated a job through its query-only handle.");
                }
                if (!cleanupProcess.HasExited)
                {
                    throw new InvalidOperationException("process/job one-budget probe did not terminate the directly-owned process after job termination failed.");
                }
                if (activeAfter < 1)
                {
                    throw new InvalidOperationException("process/job one-budget probe did not retain a live job member for deadline accounting.");
                }
                if (operationalErrors.Count != 1 ||
                    !(operationalErrors[0] is Win32Exception) ||
                    ((Win32Exception)operationalErrors[0]).NativeErrorCode != ERROR_ACCESS_DENIED)
                {
                    throw new InvalidOperationException("process/job one-budget probe did not preserve the expected job-termination error.");
                }
            }
            finally
            {
                Stopwatch cleanupStopwatch = Stopwatch.StartNew();
                long activeAfter;
                if (job != IntPtr.Zero)
                {
                    CleanupManagedProcessAndJob(
                        cleanupProcess,
                        cleanupProcess == null ? 0 : cleanupProcess.Id,
                        job,
                        cleanupStopwatch,
                        ProbeReadEntryDeadlineMilliseconds,
                        "TerminateJobObject failed while releasing the process/job one-budget probe.",
                        resourceCleanupErrors,
                        out activeAfter);
                }
                if (survivor != null)
                {
                    try
                    {
                        TerminateAndProveExit(
                            survivor,
                            survivor.Id,
                            cleanupStopwatch,
                            ProbeReadEntryDeadlineMilliseconds);
                    }
                    catch (Exception cleanupError)
                    {
                        resourceCleanupErrors.Add(cleanupError);
                    }
                }
                if (queryOnlyJob != IntPtr.Zero)
                {
                    IntPtr currentQueryOnlyJob = queryOnlyJob;
                    queryOnlyJob = IntPtr.Zero;
                    if (!CloseHandle(currentQueryOnlyJob))
                    {
                        resourceCleanupErrors.Add(Win32("CloseHandle(cleanup budget query-only job)"));
                        QuarantineRawHandle(currentQueryOnlyJob);
                    }
                }
                if (cleanupProcess != null)
                {
                    try { cleanupProcess.Dispose(); }
                    catch (Exception disposeError) { resourceCleanupErrors.Add(disposeError); }
                }
                if (survivor != null)
                {
                    try { survivor.Dispose(); }
                    catch (Exception disposeError) { resourceCleanupErrors.Add(disposeError); }
                }
                ReleaseNativeResources(
                    null,
                    ref job,
                    ref securityDescriptor,
                    ref securityAttributes,
                    resourceCleanupErrors);
                if (resourceCleanupErrors.Count != 0)
                {
                    throw ComposeCleanupException(null, resourceCleanupErrors.ToArray());
                }
            }
        }

        internal static void RunCreatedJobCompatibilityRegressionProbe()
        {
            Func<bool> configuresDelegate = CreatedJobConfiguresKillOnClose;
            Func<bool> omitsDelegate = CreatedJobOmitsKillOnClose;
            Func<bool> addressesHandlesDelegate = AddressesHandlesNonInheritable;
            Func<bool> createdHandlesDelegate = CreatedHandlesNonInheritable;
            MethodInfo configuresMethod = typeof(BoundedProcessHost).GetMethod(
                configuresDelegate.Method.Name,
                BindingFlags.Public | BindingFlags.Static,
                null,
                Type.EmptyTypes,
                null);
            MethodInfo omitsMethod = typeof(BoundedProcessHost).GetMethod(
                omitsDelegate.Method.Name,
                BindingFlags.Public | BindingFlags.Static,
                null,
                Type.EmptyTypes,
                null);
            MethodInfo addressesHandlesMethod = typeof(BoundedProcessHost).GetMethod(
                addressesHandlesDelegate.Method.Name,
                BindingFlags.Public | BindingFlags.Static,
                null,
                Type.EmptyTypes,
                null);
            MethodInfo createdHandlesMethod = typeof(BoundedProcessHost).GetMethod(
                createdHandlesDelegate.Method.Name,
                BindingFlags.Public | BindingFlags.Static,
                null,
                Type.EmptyTypes,
                null);
            if (configuresMethod == null ||
                omitsMethod == null ||
                addressesHandlesMethod == null ||
                createdHandlesMethod == null ||
                configuresMethod.ReturnType != typeof(bool) ||
                omitsMethod.ReturnType != typeof(bool) ||
                addressesHandlesMethod.ReturnType != typeof(bool) ||
                createdHandlesMethod.ReturnType != typeof(bool))
            {
                throw new InvalidOperationException("the compatibility methods do not expose the required public static Boolean signatures.");
            }
            bool configuresKillOnClose = (bool)configuresMethod.Invoke(null, null);
            bool omitsKillOnClose = (bool)omitsMethod.Invoke(null, null);
            if (configuresKillOnClose == omitsKillOnClose)
            {
                throw new InvalidOperationException("the job kill-on-close compatibility methods did not return complementary results.");
            }
            bool addressesHandlesNonInheritable = (bool)addressesHandlesMethod.Invoke(null, null);
            bool createdHandlesNonInheritable = (bool)createdHandlesMethod.Invoke(null, null);
            if (addressesHandlesNonInheritable != createdHandlesNonInheritable)
            {
                throw new InvalidOperationException("the handle-inheritance compatibility methods should return equal results.");
            }
        }

        internal static void RunDiagnosticsOwnershipRegressionProbe()
        {
            object pendingSession = new object();
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            RetainPendingSession(pendingSession);
            try
            {
                BoundedProcessDiagnosticsSnapshot retained = GetDiagnosticsSnapshot();
                if (retained.PendingManagedSessionCount != before.PendingManagedSessionCount + 1 ||
                    retained.QuarantinedLaunchCount != before.QuarantinedLaunchCount)
                {
                    throw new InvalidOperationException("the diagnostics snapshot did not report pending-session registration exactly once.");
                }
                RetainPendingSession(pendingSession);
                BoundedProcessDiagnosticsSnapshot retainedAgain = GetDiagnosticsSnapshot();
                if (retainedAgain.PendingManagedSessionCount != retained.PendingManagedSessionCount ||
                    retainedAgain.QuarantinedLaunchCount != retained.QuarantinedLaunchCount)
                {
                    throw new InvalidOperationException("the diagnostics snapshot changed after duplicate pending-session registration.");
                }
            }
            finally
            {
                ReleasePendingSession(pendingSession);
            }
            BoundedProcessDiagnosticsSnapshot released = GetDiagnosticsSnapshot();
            if (released.PendingManagedSessionCount != before.PendingManagedSessionCount ||
                released.QuarantinedLaunchCount != before.QuarantinedLaunchCount)
            {
                throw new InvalidOperationException("the diagnostics snapshot did not report pending-session release exactly once.");
            }
            ReleasePendingSession(pendingSession);
            BoundedProcessDiagnosticsSnapshot releasedAgain = GetDiagnosticsSnapshot();
            if (releasedAgain.PendingManagedSessionCount != released.PendingManagedSessionCount ||
                releasedAgain.QuarantinedLaunchCount != released.QuarantinedLaunchCount)
            {
                throw new InvalidOperationException("the diagnostics snapshot changed after duplicate pending-session release.");
            }
        }

        private static void RunPublicSurfaceRegressionProbe()
        {
            Type[] requiredExportedTypes = new Type[]
            {
                typeof(ProcessLaunchRole),
                typeof(PreNativeRejectReason),
                typeof(PauseReason),
                typeof(LauncherKind),
                typeof(EventAccessMode),
                typeof(ProbeEventDaclKind),
                typeof(EventRole),
                typeof(NativeWaitStatus),
                typeof(ContainedWorkerScenario),
                typeof(GeneratorScenario),
                typeof(ContainedWorkerState),
                typeof(HostPackagingKind),
                typeof(InvalidPreAssignmentConfigurationException),
                typeof(ProcessLaunchConfigurationException),
                typeof(EventNameGrammarException),
                typeof(CorrelationIdRequiredException),
                typeof(InvalidPauseConfigurationException),
                typeof(EnvironmentConfigurationException),
                typeof(EventSquatException),
                typeof(EventOpenException),
                typeof(PreAssignmentPauseException),
                typeof(PostAssignmentEvidenceException),
                typeof(PauseConfiguration),
                typeof(ProbeEvidence),
                typeof(ParentLossMembership),
                typeof(NestedProof),
                typeof(GeneratorBinding),
                typeof(ProcessLaunchConfiguration),
                typeof(AccessLogEntry),
                typeof(BoundedProcessDiagnosticsSnapshot),
                typeof(ResumeFailureOutcome),
                typeof(ContainedWorkerLaunchDiagnostic),
                typeof(ContainedProbeResult),
                typeof(PreNativeRejectProbeResult),
                typeof(DrainerProbeResult),
                typeof(FrozenEnvironmentSnapshot),
                typeof(LauncherRoleAcceptance),
                typeof(DirectLaunchSession),
                typeof(SchemaChildWatchdog),
                typeof(BoundedProcessResult),
                typeof(NamedEvent),
                typeof(JobProcessMember),
                typeof(JobAccountingSnapshot),
                typeof(JobProcessSnapshot),
                typeof(ContainedWorkerSession),
                typeof(RetainedPathIdentity),
                typeof(BoundedProcessHost)
            };
            Type[] newlyInternalTypes = new Type[]
            {
                typeof(WorkerResultMutation),
                typeof(NativeCommandLineException),
                typeof(LaunchPathIdentityException),
                typeof(ReceiptGrammarException),
                typeof(ChildTerminationException),
                typeof(NestedMembershipException),
                typeof(NativeWaitException),
                typeof(ContainedWorkerException),
                typeof(ContainedWorkerStateException),
                typeof(UnsupportedCertificationHostException)
            };
            Type[] internalExceptionTypes = new Type[]
            {
                typeof(NativeCommandLineException),
                typeof(LaunchPathIdentityException),
                typeof(ReceiptGrammarException),
                typeof(ChildTerminationException),
                typeof(NestedMembershipException),
                typeof(NativeWaitException),
                typeof(ContainedWorkerException),
                typeof(ContainedWorkerStateException),
                typeof(UnsupportedCertificationHostException)
            };
            Type[] exportedTypes = typeof(BoundedProcessHost).Assembly.GetExportedTypes();
            string certificationNamespace = typeof(BoundedProcessHost).Namespace;
            for (int requiredIndex = 0; requiredIndex < requiredExportedTypes.Length; requiredIndex++)
            {
                Type requiredType = requiredExportedTypes[requiredIndex];
                int simpleNameMatches = 0;
                for (int exportedIndex = 0; exportedIndex < exportedTypes.Length; exportedIndex++)
                {
                    Type exportedType = exportedTypes[exportedIndex];
                    if (string.Equals(exportedType.Namespace, certificationNamespace, StringComparison.Ordinal) &&
                        string.Equals(exportedType.Name, requiredType.Name, StringComparison.Ordinal))
                    {
                        simpleNameMatches++;
                    }
                }
                if (!requiredType.IsVisible || simpleNameMatches != 1)
                {
                    throw new InvalidOperationException(
                        "required certification type '" +
                        requiredType.FullName +
                        "' is not exposed exactly once through exported simple-name binding.");
                }
            }
            for (int internalIndex = 0; internalIndex < newlyInternalTypes.Length; internalIndex++)
            {
                Type internalType = newlyInternalTypes[internalIndex];
                if (internalType.IsVisible)
                {
                    throw new InvalidOperationException(
                        "certification implementation type '" +
                        internalType.FullName +
                        "' remains visible.");
                }
                for (int exportedIndex = 0; exportedIndex < exportedTypes.Length; exportedIndex++)
                {
                    if (exportedTypes[exportedIndex] == internalType)
                    {
                        throw new InvalidOperationException(
                            "certification implementation type '" +
                            internalType.FullName +
                            "' remains exported.");
                    }
                }
            }
            for (int exceptionIndex = 0; exceptionIndex < internalExceptionTypes.Length; exceptionIndex++)
            {
                ConstructorInfo[] constructors = internalExceptionTypes[exceptionIndex].GetConstructors(
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                if (constructors.Length == 0)
                {
                    throw new InvalidOperationException(
                        "certification implementation exception '" +
                        internalExceptionTypes[exceptionIndex].FullName +
                        "' has no instance constructor.");
                }
                for (int constructorIndex = 0; constructorIndex < constructors.Length; constructorIndex++)
                {
                    if (!constructors[constructorIndex].IsAssembly)
                    {
                        throw new InvalidOperationException(
                            "certification implementation exception '" +
                            internalExceptionTypes[exceptionIndex].FullName +
                            "' has a non-internal constructor.");
                    }
                }
            }

            Func<LauncherKind, ProcessLaunchRole[]> launcherAcceptedRolesDelegate = GetLauncherAcceptedRoles;
            string launcherAcceptedRolesName = launcherAcceptedRolesDelegate.Method.Name;
            MethodInfo launcherAcceptedRolesPublic = typeof(BoundedProcessHost).GetMethod(
                launcherAcceptedRolesName,
                BindingFlags.Public | BindingFlags.Static,
                null,
                new Type[] { typeof(LauncherKind) },
                null);
            MethodInfo launcherAcceptedRolesNonPublic = typeof(BoundedProcessHost).GetMethod(
                launcherAcceptedRolesName,
                BindingFlags.NonPublic | BindingFlags.Static,
                null,
                new Type[] { typeof(LauncherKind) },
                null);
            if (launcherAcceptedRolesPublic != null ||
                launcherAcceptedRolesNonPublic == null ||
                !launcherAcceptedRolesNonPublic.IsPrivate)
            {
                throw new InvalidOperationException(
                    launcherAcceptedRolesName +
                    " does not expose the required private static signature.");
            }

            Func<string, ProcessLaunchConfiguration, PreNativeRejectProbeResult> prelaunchRejectProbeDelegate = RunPrelaunchRejectProbe;
            string prelaunchRejectProbeName = prelaunchRejectProbeDelegate.Method.Name;
            MethodInfo prelaunchRejectProbePublic = typeof(BoundedProcessHost).GetMethod(
                prelaunchRejectProbeName,
                BindingFlags.Public | BindingFlags.Static,
                null,
                new Type[] { typeof(string), typeof(ProcessLaunchConfiguration) },
                null);
            MethodInfo prelaunchRejectProbeNonPublic = typeof(BoundedProcessHost).GetMethod(
                prelaunchRejectProbeName,
                BindingFlags.NonPublic | BindingFlags.Static,
                null,
                new Type[] { typeof(string), typeof(ProcessLaunchConfiguration) },
                null);
            if (prelaunchRejectProbePublic != null ||
                prelaunchRejectProbeNonPublic == null ||
                !prelaunchRejectProbeNonPublic.IsAssembly)
            {
                throw new InvalidOperationException(
                    prelaunchRejectProbeName +
                    " does not expose the required internal static signature.");
            }

            JobProcessSnapshot emptySnapshot = new JobProcessSnapshot(
                new JobProcessMember[0],
                new IntPtr[0]);
            Func<int, JobProcessMember> getMemberDelegate = emptySnapshot.GetMember;
            string getMemberName = getMemberDelegate.Method.Name;
            emptySnapshot.Dispose();
            MethodInfo getMemberPublic = typeof(JobProcessSnapshot).GetMethod(
                getMemberName,
                BindingFlags.Public | BindingFlags.Instance,
                null,
                new Type[] { typeof(int) },
                null);
            MethodInfo getMemberNonPublic = typeof(JobProcessSnapshot).GetMethod(
                getMemberName,
                BindingFlags.NonPublic | BindingFlags.Instance,
                null,
                new Type[] { typeof(int) },
                null);
            if (getMemberPublic != null ||
                getMemberNonPublic == null ||
                !getMemberNonPublic.IsAssembly)
            {
                throw new InvalidOperationException(
                    getMemberName +
                    " does not expose the required internal instance signature.");
            }
        }

        private static void RunCompatibilityHostValidationRegressionProbe()
        {
            string originalCurrentDirectory = Environment.CurrentDirectory;
            RequireOrdinaryNonReparseDirectory(originalCurrentDirectory);
            string callerCurrentDirectory = CreateOwnedWorkingDirectory();
            string markerLeaf = "hostile-caller-cwd-" + Guid.NewGuid().ToString("N") + ".marker";
            string markerPath = Path.Combine(callerCurrentDirectory, markerLeaf);
            string expectedCurrentDirectoryVariable = "PSPKT_COMPATIBILITY_CALLER_CWD";
            string customGateEnvironmentVariable = "MY_LEGACY_GATE";
            string gateEventName = "Local\\PspktPhase4Compatibility" + Guid.NewGuid().ToString("N");
            bool markerCreated = false;
            Exception compatibilityFailure = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                byte[] markerBytes = Encoding.ASCII.GetBytes("hostile caller current directory");
                WriteAndVerifyCreateNew(markerPath, markerBytes);
                markerCreated = true;
                Environment.CurrentDirectory = callerCurrentDirectory;

                string compatibilityCommandPath = ResolveCurrentPowerShellHostImage(ProcessLaunchRole.CompatibilityRun);
                string compatibilityCommand =
                    "$gate = [Threading.EventWaitHandle]::OpenExisting($env:" + GateEventVariable + "); " +
                    "if (-not $gate.WaitOne(5000)) { exit 87 }; " +
                    "$current = [IO.Path]::GetFullPath((Get-Location).Path); " +
                    "$caller = [IO.Path]::GetFullPath($env:" + expectedCurrentDirectoryVariable + "); " +
                    "if ([string]::Equals($current, $caller, [StringComparison]::OrdinalIgnoreCase)) { exit 88 }; " +
                    "if (Test-Path -LiteralPath (Join-Path $current '" + markerLeaf + "')) { exit 89 }; " +
                    "if ((Get-ChildItem -LiteralPath $current -Force | Measure-Object).Count -ne 0) { exit 90 }; " +
                    "[Console]::Out.Write($current); exit 0";
                string[] compatibilityCommandArguments = new string[]
                {
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    compatibilityCommand
                };
                BoundedProcessDiagnosticsSnapshot beforeCompatibilityRun = GetDiagnosticsSnapshot();
                BoundedProcessResult result = Run(
                    compatibilityCommandPath,
                    compatibilityCommandArguments,
                    gateEventName,
                    GateEventVariable,
                    new string[] { expectedCurrentDirectoryVariable },
                    new string[] { callerCurrentDirectory },
                    5000,
                    5000,
                    5000,
                    4096,
                    false);
                BoundedProcessDiagnosticsSnapshot afterCompatibilityRun = GetDiagnosticsSnapshot();
                if (!result.Started ||
                    !result.Exited ||
                    result.ExitCode != 0 ||
                    result.AssignFailed ||
                    result.TimedOut ||
                    result.Terminated ||
                    !result.DrainCompleted ||
                    result.StdOutOverflow ||
                    result.StdErrOverflow ||
                    result.ActiveProcessesAfterTerminate != 0)
                {
                    throw new InvalidOperationException("the compatibility Run regression probe did not complete a gate-first PowerShell -Command launch.");
                }
                if (afterCompatibilityRun.JobCreateCount != beforeCompatibilityRun.JobCreateCount + 1 ||
                    afterCompatibilityRun.EventCreateCount != beforeCompatibilityRun.EventCreateCount + 1 ||
                    afterCompatibilityRun.ProcessStartCount != beforeCompatibilityRun.ProcessStartCount + 1 ||
                    afterCompatibilityRun.AssignmentAttemptCount != beforeCompatibilityRun.AssignmentAttemptCount + 1)
                {
                    throw new InvalidOperationException("the compatibility Run regression probe did not create one job and gate, start one process, and attempt one assignment.");
                }
                string childWorkingDirectory = result.StdOutText;
                string ownerRoot = Path.Combine(Path.GetFullPath(Path.GetTempPath()), OwnedWorkingDirectoryRootLeaf);
                if (string.IsNullOrEmpty(childWorkingDirectory) ||
                    string.Equals(childWorkingDirectory, callerCurrentDirectory, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(Path.GetDirectoryName(childWorkingDirectory), ownerRoot, StringComparison.OrdinalIgnoreCase) ||
                    Directory.Exists(childWorkingDirectory))
                {
                    throw new InvalidOperationException("the compatibility Run regression probe did not use and clean a helper-owned unique working directory.");
                }
            }
            catch (Exception unexpected)
            {
                compatibilityFailure = unexpected;
            }
            finally
            {
                try { Environment.CurrentDirectory = originalCurrentDirectory; }
                catch (Exception restoreError) { cleanupErrors.Add(restoreError); }

                try
                {
                    if (File.Exists(markerPath))
                    {
                        File.Delete(markerPath);
                    }
                    else if (markerCreated)
                    {
                        throw new IOException("the compatibility regression marker disappeared before strict cleanup.");
                    }
                    if (File.Exists(markerPath))
                    {
                        throw new IOException("the compatibility regression marker remained after strict cleanup.");
                    }
                }
                catch (Exception markerCleanupError)
                {
                    cleanupErrors.Add(markerCleanupError);
                }

                try
                {
                    Directory.Delete(callerCurrentDirectory, false);
                    if (Directory.Exists(callerCurrentDirectory))
                    {
                        throw new IOException("the compatibility regression current directory remained after strict cleanup.");
                    }
                }
                catch (Exception directoryCleanupError)
                {
                    cleanupErrors.Add(directoryCleanupError);
                }
            }
            Exception compatibilityOutcome = ComposeCleanupException(compatibilityFailure, cleanupErrors.ToArray());
            if (compatibilityOutcome != null)
            {
                throw compatibilityOutcome;
            }

            string commandPath = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            string[] commandArguments = new string[] { "/d", "/c", "exit", "0" };
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility null gate variable",
                commandPath,
                commandArguments,
                null,
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility empty gate variable",
                commandPath,
                commandArguments,
                string.Empty,
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility custom gate variable",
                commandPath,
                commandArguments,
                customGateEnvironmentVariable,
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility gate variable case variant",
                commandPath,
                commandArguments,
                GateEventVariable.ToLowerInvariant(),
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility invalid gate variable",
                commandPath,
                commandArguments,
                "9MY_LEGACY_GATE",
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility reserved gate variable",
                commandPath,
                commandArguments,
                "PSPKT_PHASE4_LEGACY_GATE",
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility supervisor gate variable",
                commandPath,
                commandArguments,
                SupervisorGateEventVariable,
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility descendant gate variable",
                commandPath,
                commandArguments,
                DescendantGateEventVariable,
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility runtime-injection gate variable",
                commandPath,
                commandArguments,
                "COMPLUS_MY_LEGACY_GATE",
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility module-path gate variable",
                commandPath,
                commandArguments,
                "PSModulePath",
                new string[0],
                new string[0]);
            RequireCompatibilityGateEnvironmentVariableRejected(
                "compatibility duplicate gate variable",
                commandPath,
                commandArguments,
                GateEventVariable,
                new string[] { GateEventVariable.ToLowerInvariant() },
                new string[] { "collision" });

            string compatibilityPowerShellPath = ResolveCurrentPowerShellHostImage(ProcessLaunchRole.CompatibilityRun);
            RunCompatibilityPowerShellSourceRetentionRegressionProbes(
                compatibilityPowerShellPath);
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility missing -File path",
                compatibilityPowerShellPath,
                new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File" });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility empty -File path",
                compatibilityPowerShellPath,
                new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", string.Empty });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility stdin -File path",
                compatibilityPowerShellPath,
                new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", "-" });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility conflicting file and command modes",
                compatibilityPowerShellPath,
                new string[]
                {
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    Path.Combine(Environment.SystemDirectory, "not-launched.ps1"),
                    "-Command",
                    "exit 0"
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility conflicting command and file modes",
                compatibilityPowerShellPath,
                new string[]
                {
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "exit 0",
                    "-File",
                    Path.Combine(Environment.SystemDirectory, "not-launched.ps1")
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility ambiguous host option",
                compatibilityPowerShellPath,
                new string[]
                {
                    "-NoProfile",
                    "-NonInteractive",
                    "-n",
                    Path.Combine(Environment.SystemDirectory, "not-launched.ps1")
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility unknown slash host option",
                compatibilityPowerShellPath,
                new string[]
                {
                    "/UnknownOption",
                    "/Command",
                    "exit 0"
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility ambiguous slash host option",
                compatibilityPowerShellPath,
                new string[]
                {
                    "/No",
                    "/Command",
                    "exit 0"
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility ambiguous slash entry option",
                compatibilityPowerShellPath,
                new string[]
                {
                    "/Con",
                    "exit 0"
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility slash host option missing value",
                compatibilityPowerShellPath,
                new string[]
                {
                    "/ExecutionPolicy",
                    "/Command",
                    "exit 0"
                });
            RequireCompatibilityPowerShellFileArgumentsRejected(
                "compatibility conflicting slash file and command modes",
                compatibilityPowerShellPath,
                new string[]
                {
                    "/NoProfile",
                    "/File",
                    Path.Combine(Environment.SystemDirectory, "not-launched.ps1"),
                    "/Command",
                    "exit 0"
                });

            string typedHostImagePath = ResolveCurrentPowerShellHostImage(ProcessLaunchRole.GateProbeChild);
            string typedNoncanonicalGateName = "Local\\PspktPhase4TypedGateReject" + Guid.NewGuid().ToString("N");
            ProcessLaunchConfiguration typedNoncanonicalGateConfiguration = CreateProcessLaunchConfiguration(
                ProcessLaunchRole.GateProbeChild,
                typedHostImagePath,
                new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", Path.Combine(Environment.SystemDirectory, "not-launched.ps1") },
                typedNoncanonicalGateName,
                "MY_TYPED_GATE",
                new string[0],
                new string[0],
                new string[] { EnvGateTimeoutMs, EnvProbeMode, EnvProbeNonce, EnvProbeMarkerPath },
                new string[] { "5000", "typed-gate-reject", Guid.NewGuid().ToString("N"), "typed-gate-reject.marker" },
                5000,
                5000,
                5000,
                4096,
                false,
                Guid.NewGuid(),
                null,
                null,
                null,
                null,
                null);
            BoundedProcessDiagnosticsSnapshot beforeTypedNoncanonicalGateReject = GetDiagnosticsSnapshot();
            bool typedNoncanonicalGateRejected = false;
            try
            {
                Run(typedNoncanonicalGateConfiguration);
            }
            catch (EnvironmentConfigurationException)
            {
                typedNoncanonicalGateRejected = true;
            }
            BoundedProcessDiagnosticsSnapshot afterTypedNoncanonicalGateReject = GetDiagnosticsSnapshot();
            RequirePreNativeRejection(
                "typed Run noncanonical gate variable",
                typedNoncanonicalGateRejected,
                beforeTypedNoncanonicalGateReject,
                afterTypedNoncanonicalGateReject);

            string typedGateName = "Local\\PspktPhase4TypedHostReject" + Guid.NewGuid().ToString("N");
            ProcessLaunchConfiguration typedConfiguration = CreateProcessLaunchConfiguration(
                ProcessLaunchRole.GateProbeChild,
                commandPath,
                commandArguments,
                typedGateName,
                GateEventVariable,
                new string[0],
                new string[0],
                new string[] { EnvGateTimeoutMs, EnvProbeMode, EnvProbeNonce, EnvProbeMarkerPath },
                new string[] { "5000", "typed-host-reject", Guid.NewGuid().ToString("N"), "typed-host-reject.marker" },
                5000,
                5000,
                5000,
                4096,
                false,
                Guid.NewGuid(),
                null,
                null,
                null,
                null,
                null);
            BoundedProcessDiagnosticsSnapshot beforeTypedReject = GetDiagnosticsSnapshot();
            bool typedRejected = false;
            try
            {
                Run(typedConfiguration);
            }
            catch (ProcessLaunchConfigurationException)
            {
                typedRejected = true;
            }
            BoundedProcessDiagnosticsSnapshot afterTypedReject = GetDiagnosticsSnapshot();
            RequirePreNativePowerShellHostRejection(
                "typed Run",
                typedRejected,
                beforeTypedReject,
                afterTypedReject);

            ProcessLaunchConfiguration directConfiguration = CreateProcessLaunchConfiguration(
                ProcessLaunchRole.GateMissingChild,
                commandPath,
                commandArguments,
                null,
                null,
                new string[0],
                new string[0],
                new string[] { EnvProbeMode, EnvProbeNonce },
                new string[] { "direct-host-reject", Guid.NewGuid().ToString("N") },
                5000,
                5000,
                5000,
                4096,
                false,
                Guid.NewGuid(),
                null,
                null,
                null,
                null,
                null);
            BoundedProcessDiagnosticsSnapshot beforeDirectReject = GetDiagnosticsSnapshot();
            bool directRejected = false;
            try
            {
                RunDirectLaunch(directConfiguration);
            }
            catch (ProcessLaunchConfigurationException)
            {
                directRejected = true;
            }
            BoundedProcessDiagnosticsSnapshot afterDirectReject = GetDiagnosticsSnapshot();
            RequirePreNativePowerShellHostRejection(
                "direct launch",
                directRejected,
                beforeDirectReject,
                afterDirectReject);
        }

        private static void RunCompatibilityPowerShellSourceRetentionRegressionProbes(
            string executablePath)
        {
            bool allowNativeSlashRejection =
                !IsWindowsPowerShellImage(executablePath);
            string sourceRoot = CreateOwnedWorkingDirectory();
            string scriptPath = Path.Combine(
                sourceRoot,
                "compatibility-source-retention.ps1");
            string optionValuePath = Path.Combine(
                sourceRoot,
                "option-value.ps1");
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                string script =
                    "$ErrorActionPreference='Stop';" +
                    "$gate=[Threading.EventWaitHandle]::OpenExisting($env:" + GateEventVariable + ");" +
                    "try{if(-not $gate.WaitOne(5000)){exit 91}}finally{$gate.Dispose()};" +
                    "$retained=$false;" +
                    "try{$stream=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Dispose()}" +
                    "catch [IO.IOException]{$retained=$true}" +
                    "catch [UnauthorizedAccessException]{$retained=$true};" +
                    "if(-not $retained){exit 92};" +
                    "[Console]::Out.Write([IO.Path]::GetFullPath($PSCommandPath));" +
                    "exit 0";
                WriteAndVerifyCreateNew(
                    scriptPath,
                    Encoding.ASCII.GetBytes(script));

                string[] fileOptions = new string[]
                {
                    "-File",
                    "-f",
                    "-FI",
                    "-FiL"
                };
                for (int index = 0; index < fileOptions.Length; index++)
                {
                    RunCompatibilityPowerShellFileRetentionProbe(
                        "compatibility " + fileOptions[index] + " file source",
                        executablePath,
                        fileOptions[index],
                        scriptPath,
                        false,
                        false);
                }

                string[] slashFileOptions = new string[]
                {
                    "/File",
                    "/f",
                    "/FI",
                    "/FiL"
                };
                for (int index = 0; index < slashFileOptions.Length; index++)
                {
                    RunCompatibilityPowerShellFileRetentionProbe(
                        "compatibility " + slashFileOptions[index] + " file source",
                        executablePath,
                        slashFileOptions[index],
                        scriptPath,
                        false,
                        allowNativeSlashRejection);
                }

                RunCompatibilityPowerShellFileRetentionProbe(
                    "compatibility slash host file source",
                    executablePath,
                    new string[]
                    {
                        "/NoLogo",
                        "/NoProfile",
                        "/NonInteractive",
                        "/File",
                        scriptPath
                    },
                    scriptPath,
                    allowNativeSlashRejection);

                RunCompatibilityPowerShellFileRetentionProbe(
                    "compatibility positional file source",
                    executablePath,
                    null,
                    scriptPath,
                    true,
                    false);

                string[] commandOptions = new string[]
                {
                    "-Command",
                    "-c",
                    "-co",
                    "-com",
                    "-comm",
                    "-comma",
                    "-comman"
                };
                string commandPayload =
                    "$gate=[Threading.EventWaitHandle]::OpenExisting($env:" + GateEventVariable + ");" +
                    "try{if(-not $gate.WaitOne(5000)){exit 93}}finally{$gate.Dispose()};" +
                    "$text='command-payload.ps1';" +
                    "[Console]::Out.Write($text);" +
                    "exit 0";
                for (int index = 0; index < commandOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility " + commandOptions[index] + " command source",
                        executablePath,
                        new string[]
                        {
                            "-NoProfile",
                            "-NonInteractive",
                            commandOptions[index],
                            commandPayload
                        },
                        null);
                }
                RunCompatibilityPowerShellCommandExecutionProbe(
                    "compatibility -Command payload",
                    executablePath,
                    new string[]
                    {
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        commandPayload
                    },
                    "command-payload.ps1",
                    false);

                string[] slashCommandOptions = new string[]
                {
                    "/Command",
                    "/c",
                    "/co",
                    "/com",
                    "/comm",
                    "/comma",
                    "/comman"
                };
                for (int index = 0; index < slashCommandOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility " + slashCommandOptions[index] + " command source",
                        executablePath,
                        new string[]
                        {
                            "/NoProfile",
                            "/NonInteractive",
                            slashCommandOptions[index],
                            commandPayload
                        },
                        null);
                }
                RunCompatibilityPowerShellCommandExecutionProbe(
                    "compatibility /NoProfile /Command payload",
                    executablePath,
                    new string[]
                    {
                        "/NoProfile",
                        "/Command",
                        commandPayload
                    },
                    "command-payload.ps1",
                    allowNativeSlashRejection);
                RunCompatibilityPowerShellCommandExecutionProbe(
                    "compatibility slash execution policy command payload",
                    executablePath,
                    new string[]
                    {
                        "/NoProfile",
                        "/ExecutionPolicy",
                        "Bypass",
                        "/Command",
                        commandPayload
                    },
                    "command-payload.ps1",
                    allowNativeSlashRejection);

                string encodedPayload =
                    "$gate=[Threading.EventWaitHandle]::OpenExisting($env:" + GateEventVariable + ");" +
                    "try{if(-not $gate.WaitOne(5000)){exit 94}}finally{$gate.Dispose()};" +
                    "$text='encoded-command-payload.ps1';" +
                    "[Console]::Out.Write($text);" +
                    "exit 0";
                string encodedCommand = Convert.ToBase64String(
                    Encoding.Unicode.GetBytes(encodedPayload));
                string[] encodedOptions = new string[]
                {
                    "-EncodedCommand",
                    "-e",
                    "-ec",
                    "-en",
                    "-enc"
                };
                for (int index = 0; index < encodedOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility " + encodedOptions[index] + " command source",
                        executablePath,
                        new string[]
                        {
                            "-NoProfile",
                            "-NonInteractive",
                            encodedOptions[index],
                            encodedCommand
                        },
                        null);
                }
                RunCompatibilityPowerShellCommandExecutionProbe(
                    "compatibility -EncodedCommand payload",
                    executablePath,
                    new string[]
                    {
                        "-NoProfile",
                        "-NonInteractive",
                        "-EncodedCommand",
                        encodedCommand
                    },
                    "encoded-command-payload.ps1",
                    false);

                string[] slashEncodedOptions = new string[]
                {
                    "/EncodedCommand",
                    "/e",
                    "/ec",
                    "/en",
                    "/enc",
                    "/enco",
                    "/encod",
                    "/encode",
                    "/encoded",
                    "/encodedc",
                    "/encodedco",
                    "/encodedcom",
                    "/encodedcomm",
                    "/encodedcomma",
                    "/encodedcomman"
                };
                for (int index = 0; index < slashEncodedOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility " + slashEncodedOptions[index] + " command source",
                        executablePath,
                        new string[]
                        {
                            "/NoProfile",
                            "/NonInteractive",
                            slashEncodedOptions[index],
                            encodedCommand
                        },
                        null);
                }
                RunCompatibilityPowerShellCommandExecutionProbe(
                    "compatibility /EncodedCommand payload",
                    executablePath,
                    new string[]
                    {
                        "/EncodedCommand",
                        encodedCommand
                    },
                    "encoded-command-payload.ps1",
                    allowNativeSlashRejection);

                RequireCompatibilityPowerShellSourceClassification(
                    "compatibility slash command path-shaped payload",
                    executablePath,
                    new string[]
                    {
                        "/Command",
                        "command-payload.ps1"
                    },
                    null);
                RequireCompatibilityPowerShellSourceClassification(
                    "compatibility slash encoded path-shaped payload",
                    executablePath,
                    new string[]
                    {
                        "/EncodedCommand",
                        "encoded-command-payload.ps1"
                    },
                    null);

                RequireCompatibilityPowerShellSourceClassification(
                    "compatibility option value source skip",
                    executablePath,
                    new string[]
                    {
                        "-NoProfile",
                        "-NonInteractive",
                        "-WorkingDirectory",
                        optionValuePath,
                        scriptPath
                    },
                    scriptPath);
                string[] slashNoValueOptions = new string[]
                {
                    "/?",
                    "/h",
                    "/help",
                    "/mta",
                    "/sta",
                    "/noexit",
                    "/noe",
                    "/nologo",
                    "/nol",
                    "/noninteractive",
                    "/noni",
                    "/noprofile",
                    "/nop"
                };
                for (int index = 0; index < slashNoValueOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility " + slashNoValueOptions[index] + " host option",
                        executablePath,
                        new string[]
                        {
                            slashNoValueOptions[index],
                            scriptPath
                        },
                        scriptPath);
                }
                string[] slashValueOptions = new string[]
                {
                    "/version",
                    "/v",
                    "/inputformat",
                    "/inp",
                    "/if",
                    "/outputformat",
                    "/o",
                    "/of",
                    "/windowstyle",
                    "/w",
                    "/executionpolicy",
                    "/ex",
                    "/ep",
                    "/configurationname",
                    "/config",
                    "/workingdirectory",
                    "/wd"
                };
                for (int index = 0; index < slashValueOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility " + slashValueOptions[index] + " host option",
                        executablePath,
                        new string[]
                        {
                            slashValueOptions[index],
                            optionValuePath,
                            scriptPath
                        },
                        scriptPath);
                }
                if (IsWindowsPowerShellImage(executablePath))
                {
                    RequireCompatibilityPowerShellSourceClassification(
                        "compatibility /psconsolefile host option",
                        executablePath,
                        new string[]
                        {
                            "/psconsolefile",
                            optionValuePath,
                            scriptPath
                        },
                        scriptPath);
                }
                else
                {
                    string[] slashCoreNoValueOptions = new string[]
                    {
                        "/interactive",
                        "/i",
                        "/login",
                        "/l",
                        "/noprofileloadtime",
                        "/sshservermode",
                        "/sshs"
                    };
                    for (int index = 0; index < slashCoreNoValueOptions.Length; index++)
                    {
                        RequireCompatibilityPowerShellSourceClassification(
                            "compatibility " + slashCoreNoValueOptions[index] + " host option",
                            executablePath,
                            new string[]
                            {
                                slashCoreNoValueOptions[index],
                                scriptPath
                            },
                            scriptPath);
                    }
                    string[] slashCoreValueOptions = new string[]
                    {
                        "/configurationfile",
                        "/custompipename",
                        "/settingsfile",
                        "/settings"
                    };
                    for (int index = 0; index < slashCoreValueOptions.Length; index++)
                    {
                        RequireCompatibilityPowerShellSourceClassification(
                            "compatibility " + slashCoreValueOptions[index] + " host option",
                            executablePath,
                            new string[]
                            {
                                slashCoreValueOptions[index],
                                optionValuePath,
                                scriptPath
                            },
                            scriptPath);
                    }
                }

                string missingSlashSource = Path.Combine(
                    sourceRoot,
                    "missing-slash-source.ps1");
                string[] slashBindingOptions = new string[]
                {
                    "/File",
                    "/f",
                    "/fi",
                    "/fil"
                };
                for (int index = 0; index < slashBindingOptions.Length; index++)
                {
                    RequireCompatibilityPowerShellSourcePathBindingRejected(
                        "compatibility " + slashBindingOptions[index] + " source binding",
                        executablePath,
                        new string[]
                        {
                            "-NoProfile",
                            "-NonInteractive",
                            slashBindingOptions[index],
                            missingSlashSource
                        },
                        missingSlashSource);
                }
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }
            finally
            {
                try
                {
                    if (File.Exists(scriptPath))
                    {
                        File.Delete(scriptPath);
                    }
                    if (Directory.Exists(sourceRoot))
                    {
                        Directory.Delete(sourceRoot, false);
                    }
                    if (File.Exists(scriptPath) ||
                        Directory.Exists(sourceRoot))
                    {
                        throw new IOException(
                            "the compatibility source-retention probe root remained after cleanup.");
                    }
                }
                catch (Exception cleanupError)
                {
                    cleanupErrors.Add(cleanupError);
                }
            }
            Exception outcome = ComposeCleanupException(
                primary,
                cleanupErrors.ToArray());
            if (outcome != null)
            {
                throw outcome;
            }
        }

        private static void RunCompatibilityPowerShellFileRetentionProbe(
            string probeName,
            string executablePath,
            string fileOption,
            string scriptPath,
            bool positional,
            bool allowUnsupportedSlash)
        {
            string[] arguments = positional
                ? new string[]
                {
                    "-NoProfile",
                    "-NonInteractive",
                    scriptPath
                }
                : new string[]
                {
                    "-NoProfile",
                    "-NonInteractive",
                    fileOption,
                    scriptPath
                };
            RunCompatibilityPowerShellFileRetentionProbe(
                probeName,
                executablePath,
                arguments,
                scriptPath,
                allowUnsupportedSlash);
        }

        private static void RunCompatibilityPowerShellFileRetentionProbe(
            string probeName,
            string executablePath,
            string[] arguments,
            string scriptPath,
            bool allowUnsupportedSlash)
        {
            RequireCompatibilityPowerShellSourceClassification(
                probeName,
                executablePath,
                arguments,
                scriptPath);

            string gateEventName =
                "Local\\PspktPhase4CompatibilitySource" +
                Guid.NewGuid().ToString("N");
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            BoundedProcessResult result = Run(
                executablePath,
                arguments,
                gateEventName,
                GateEventVariable,
                new string[0],
                new string[0],
                10000,
                10000,
                10000,
                65536,
                false);
            BoundedProcessDiagnosticsSnapshot after = GetDiagnosticsSnapshot();
            RequireCompatibilityNativeLaunchDelta(
                probeName,
                before,
                after);

            string fullScriptPath = Path.GetFullPath(scriptPath);
            bool executed =
                result.Started &&
                result.Exited &&
                result.ExitCode == 0 &&
                !result.AssignFailed &&
                !result.TimedOut &&
                !result.Terminated &&
                result.DrainCompleted &&
                !result.StdOutOverflow &&
                !result.StdErrOverflow &&
                result.ActiveProcessesAfterTerminate == 0 &&
                string.Equals(
                    result.StdOutText,
                    fullScriptPath,
                    StringComparison.OrdinalIgnoreCase);
            if (executed)
            {
                return;
            }
            if (!allowUnsupportedSlash ||
                !result.Started ||
                !result.Exited ||
                result.ExitCode == 0 ||
                result.TimedOut ||
                result.Terminated ||
                !result.DrainCompleted ||
                result.StdOutOverflow ||
                result.StdErrOverflow)
            {
                throw new InvalidOperationException(
                    "the " + probeName +
                    " regression probe neither executed the retained source nor rejected an unsupported slash option safely.");
            }
        }

        private static void RunCompatibilityPowerShellCommandExecutionProbe(
            string probeName,
            string executablePath,
            string[] arguments,
            string expectedOutput,
            bool allowUnsupportedSlash)
        {
            RequireCompatibilityPowerShellSourceClassification(
                probeName,
                executablePath,
                arguments,
                null);
            string gateEventName =
                "Local\\PspktPhase4CompatibilityCommand" +
                Guid.NewGuid().ToString("N");
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            BoundedProcessResult result = Run(
                executablePath,
                arguments,
                gateEventName,
                GateEventVariable,
                new string[0],
                new string[0],
                10000,
                10000,
                10000,
                65536,
                false);
            BoundedProcessDiagnosticsSnapshot after = GetDiagnosticsSnapshot();
            RequireCompatibilityNativeLaunchDelta(
                probeName,
                before,
                after);
            bool executed =
                result.Started &&
                result.Exited &&
                result.ExitCode == 0 &&
                !result.AssignFailed &&
                !result.TimedOut &&
                !result.Terminated &&
                result.DrainCompleted &&
                !result.StdOutOverflow &&
                !result.StdErrOverflow &&
                result.ActiveProcessesAfterTerminate == 0 &&
                string.Equals(
                    result.StdOutText,
                    expectedOutput,
                    StringComparison.Ordinal);
            if (executed)
            {
                return;
            }
            if (!allowUnsupportedSlash ||
                !result.Started ||
                !result.Exited ||
                result.ExitCode == 0 ||
                result.TimedOut ||
                result.Terminated ||
                !result.DrainCompleted ||
                result.StdOutOverflow ||
                result.StdErrOverflow)
            {
                throw new InvalidOperationException(
                    "the " + probeName +
                    " regression probe neither completed as a non-file command launch nor rejected unsupported slash syntax safely.");
            }
        }

        private static void RequireCompatibilityPowerShellSourceClassification(
            string probeName,
            string executablePath,
            string[] arguments,
            string expectedSourcePath)
        {
            string sourcePath = GetValidatedPowerShellFileSourcePath(
                executablePath,
                arguments);
            if (!string.Equals(
                sourcePath,
                expectedSourcePath,
                StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "the " + probeName +
                    " regression probe classified the wrong PowerShell source token.");
            }
        }

        private static void RequireCompatibilityPowerShellSourcePathBindingRejected(
            string probeName,
            string executablePath,
            string[] arguments,
            string expectedSourcePath)
        {
            string gateEventName =
                "Local\\PspktPhase4CompatibilityReject" +
                Guid.NewGuid().ToString("N");
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            bool rejected = false;
            try
            {
                Run(
                    executablePath,
                    arguments,
                    gateEventName,
                    GateEventVariable,
                    new string[0],
                    new string[0],
                    5000,
                    5000,
                    5000,
                    4096,
                    false);
            }
            catch (LaunchPathIdentityException expected)
            {
                string expectedFullPath = Path.GetFullPath(
                    expectedSourcePath);
                string actualFullPath = expected.Path == null
                    ? null
                    : Path.GetFullPath(expected.Path);
                rejected = string.Equals(
                    actualFullPath,
                    expectedFullPath,
                    StringComparison.OrdinalIgnoreCase);
            }
            BoundedProcessDiagnosticsSnapshot after = GetDiagnosticsSnapshot();
            RequirePreNativeRejection(
                probeName,
                rejected,
                before,
                after);
        }

        private static void RequireCompatibilityNativeLaunchDelta(
            string probeName,
            BoundedProcessDiagnosticsSnapshot before,
            BoundedProcessDiagnosticsSnapshot after)
        {
            if (after.JobCreateCount != before.JobCreateCount + 1 ||
                after.EventCreateCount != before.EventCreateCount + 1 ||
                after.ProcessStartCount != before.ProcessStartCount + 1 ||
                after.AssignmentAttemptCount != before.AssignmentAttemptCount + 1)
            {
                throw new InvalidOperationException(
                    "the " + probeName +
                    " regression probe did not preserve the exact native launch delta.");
            }
        }

        private static void RequireCompatibilityGateEnvironmentVariableRejected(
            string probeName,
            string executablePath,
            string[] arguments,
            string gateEnvironmentVariable,
            string[] extraEnvironmentNames,
            string[] extraEnvironmentValues)
        {
            string gateEventName = "Local\\PspktPhase4CompatibilityReject" + Guid.NewGuid().ToString("N");
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            bool rejected = false;
            try
            {
                Run(
                    executablePath,
                    arguments,
                    gateEventName,
                    gateEnvironmentVariable,
                    extraEnvironmentNames,
                    extraEnvironmentValues,
                    5000,
                    5000,
                    5000,
                    4096,
                    false);
            }
            catch (EnvironmentConfigurationException)
            {
                rejected = true;
            }
            BoundedProcessDiagnosticsSnapshot after = GetDiagnosticsSnapshot();
            RequirePreNativeRejection(probeName, rejected, before, after);
        }

        private static void RequireCompatibilityPowerShellFileArgumentsRejected(
            string probeName,
            string executablePath,
            string[] arguments)
        {
            string gateEventName = "Local\\PspktPhase4CompatibilityReject" + Guid.NewGuid().ToString("N");
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            bool rejected = false;
            try
            {
                Run(
                    executablePath,
                    arguments,
                    gateEventName,
                    GateEventVariable,
                    new string[0],
                    new string[0],
                    5000,
                    5000,
                    5000,
                    4096,
                    false);
            }
            catch (NativeCommandLineException)
            {
                rejected = true;
            }
            BoundedProcessDiagnosticsSnapshot after = GetDiagnosticsSnapshot();
            RequirePreNativeRejection(probeName, rejected, before, after);
        }

        private static void RequirePreNativeRejection(
            string probeName,
            bool rejected,
            BoundedProcessDiagnosticsSnapshot before,
            BoundedProcessDiagnosticsSnapshot after)
        {
            if (!rejected ||
                after.JobCreateCount != before.JobCreateCount ||
                after.EventCreateCount != before.EventCreateCount ||
                after.ProcessStartCount != before.ProcessStartCount ||
                after.AssignmentAttemptCount != before.AssignmentAttemptCount)
            {
                throw new InvalidOperationException(
                    "the " + probeName +
                    " regression probe did not reject before native launch.");
            }
        }

        private static void RequirePreNativePowerShellHostRejection(
            string launcherName,
            bool rejected,
            BoundedProcessDiagnosticsSnapshot before,
            BoundedProcessDiagnosticsSnapshot after)
        {
            if (!rejected ||
                after.JobCreateCount != before.JobCreateCount ||
                after.EventCreateCount != before.EventCreateCount ||
                after.ProcessStartCount != before.ProcessStartCount ||
                after.AssignmentAttemptCount != before.AssignmentAttemptCount)
            {
                throw new InvalidOperationException(
                    "the " + launcherName +
                    " regression probe did not reject a non-PowerShell host before native launch.");
            }
        }

        private static void RunSessionWaitPreemptionRegressionProbes()
        {
            for (int iteration = 0; iteration < WaitPreemptionProbeRepeatCount; iteration++)
            {
                RunContainedSessionWaitPreemptionProbe((iteration & 1) == 0);
                RunDirectSessionWaitPreemptionProbe((iteration & 1) == 0);
            }
        }

        private static void RunContainedSessionWaitPreemptionProbe(bool disposeToPreempt)
        {
            long retainedHandleBaseline = Interlocked.Read(ref _retainedWaitCapabilityCount);
            string hostImagePath = ResolveCurrentPowerShellHostImage(ProcessLaunchRole.Worker);
            string gateEventName = "Local\\PspktPhase4ContainedWait" + Guid.NewGuid().ToString("N");
            ContainedWorkerSession session = null;
            Thread waitThread = null;
            NativeWaitStatus waitStatus = NativeWaitStatus.Other;
            Exception waitFailure = null;
            bool cleanupCompleted = false;
            try
            {
                session = StartCertificationSnapshotProbe(
                    hostImagePath,
                    Environment.SystemDirectory,
                    gateEventName,
                    30000);
                waitThread = new Thread(delegate()
                {
                    try
                    {
                        waitStatus = session.WaitWorker(WaitPreemptionProbeLongWaitMilliseconds);
                    }
                    catch (Exception error)
                    {
                        waitFailure = error;
                    }
                });
                waitThread.IsBackground = true;
                waitThread.Start();
                WaitForRetainedWaitCapabilityCount(
                    retainedHandleBaseline + 1,
                    ProbeReadEntryDeadlineMilliseconds);
                Thread.Sleep(WaitPreemptionProbeSettleMilliseconds);
                Stopwatch cleanupStopwatch = Stopwatch.StartNew();
                if (disposeToPreempt)
                {
                    session.Dispose();
                    cleanupCompleted = session.DisposeSucceeded;
                }
                else
                {
                    long active = session.TerminateAndWait(
                        WaitPreemptionProbeCleanupDeadlineMilliseconds);
                    cleanupCompleted = active == 0;
                }
                RequireWaitPreemptionProbeDuration(
                    "contained session",
                    cleanupStopwatch);
                if (!waitThread.Join(WaitPreemptionProbeCleanupDeadlineMilliseconds))
                {
                    throw new TimeoutException("the contained-session waiter did not finish after cleanup preempted its wait.");
                }
                if (waitFailure != null || waitStatus != NativeWaitStatus.Object0)
                {
                    throw new InvalidOperationException("the contained-session waiter did not return the retained process exit result.", waitFailure);
                }
                if (!cleanupCompleted)
                {
                    throw new InvalidOperationException("the contained-session cleanup did not prove Job zero.");
                }
                if (!disposeToPreempt)
                {
                    session.Dispose();
                    cleanupCompleted = session.DisposeSucceeded;
                    if (!cleanupCompleted)
                    {
                        throw new InvalidOperationException("the terminated contained session did not clean up successfully.");
                    }
                }
                RequireRetainedWaitCapabilityBaseline(
                    "contained session",
                    retainedHandleBaseline);
            }
            finally
            {
                if (session != null && !session.DisposeSucceeded)
                {
                    session.Dispose();
                }
                if (waitThread != null && waitThread.IsAlive)
                {
                    waitThread.Join(WaitPreemptionProbeCleanupDeadlineMilliseconds);
                }
            }
        }

        private static void RunDirectSessionWaitPreemptionProbe(bool disposeToPreempt)
        {
            long retainedHandleBaseline = Interlocked.Read(ref _retainedWaitCapabilityCount);
            Process process = null;
            DirectLaunchSession session = null;
            Thread waitThread = null;
            bool waitResult = false;
            Exception waitFailure = null;
            bool cleanupCompleted = false;
            try
            {
                process = StartCleanupBudgetProbeProcess();
                session = new DirectLaunchSession(
                    ProcessLaunchRole.GateMissingChild,
                    process,
                    process.Id,
                    ReadStartFileTime(process),
                    process.StartInfo.FileName + " " + process.StartInfo.Arguments,
                    process.StartInfo.WorkingDirectory);
                process = null;
                waitThread = new Thread(delegate()
                {
                    try
                    {
                        waitResult = session.WaitForExit(WaitPreemptionProbeLongWaitMilliseconds);
                    }
                    catch (Exception error)
                    {
                        waitFailure = error;
                    }
                });
                waitThread.IsBackground = true;
                waitThread.Start();
                WaitForRetainedWaitCapabilityCount(
                    retainedHandleBaseline + 1,
                    ProbeReadEntryDeadlineMilliseconds);
                Thread.Sleep(WaitPreemptionProbeSettleMilliseconds);
                Stopwatch cleanupStopwatch = Stopwatch.StartNew();
                if (disposeToPreempt)
                {
                    session.Dispose();
                    cleanupCompleted = true;
                }
                else
                {
                    session.TerminateAndWait(
                        WaitPreemptionProbeCleanupDeadlineMilliseconds);
                    cleanupCompleted = true;
                }
                RequireWaitPreemptionProbeDuration(
                    "direct-launch session",
                    cleanupStopwatch);
                if (!waitThread.Join(WaitPreemptionProbeCleanupDeadlineMilliseconds))
                {
                    throw new TimeoutException("the direct-launch waiter did not finish after cleanup preempted its wait.");
                }
                if (waitFailure != null || !waitResult)
                {
                    throw new InvalidOperationException("the direct-launch waiter did not return the retained process exit result.", waitFailure);
                }
                if (!cleanupCompleted)
                {
                    throw new InvalidOperationException("the direct-launch cleanup did not complete.");
                }
                if (!disposeToPreempt)
                {
                    session.Dispose();
                }
                RequireRetainedWaitCapabilityBaseline(
                    "direct-launch session",
                    retainedHandleBaseline);
            }
            finally
            {
                if (session != null)
                {
                    session.Dispose();
                }
                if (process != null)
                {
                    process.Dispose();
                }
                if (waitThread != null && waitThread.IsAlive)
                {
                    waitThread.Join(WaitPreemptionProbeCleanupDeadlineMilliseconds);
                }
            }
        }

        private static void WaitForRetainedWaitCapabilityCount(
            long expectedCount,
            int timeoutMilliseconds)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            while (Interlocked.Read(ref _retainedWaitCapabilityCount) != expectedCount)
            {
                if (stopwatch.ElapsedMilliseconds >= timeoutMilliseconds)
                {
                    throw new TimeoutException("a session waiter did not acquire its retained wait capability before the probe deadline.");
                }
                Thread.Sleep(10);
            }
        }

        private static void RequireWaitPreemptionProbeDuration(
            string probeName,
            Stopwatch cleanupStopwatch)
        {
            if (cleanupStopwatch.ElapsedMilliseconds >= WaitPreemptionProbeLongWaitMilliseconds)
            {
                throw new TimeoutException(
                    probeName +
                    " cleanup completed only after the observer wait deadline elapsed.");
            }
            if (cleanupStopwatch.ElapsedMilliseconds > WaitPreemptionProbeCleanupDeadlineMilliseconds)
            {
                throw new TimeoutException(
                    probeName +
                    " cleanup exceeded the prompt preemption deadline.");
            }
        }

        private static void RequireRetainedWaitCapabilityBaseline(
            string probeName,
            long expectedCount)
        {
            long actualCount = Interlocked.Read(ref _retainedWaitCapabilityCount);
            if (actualCount != expectedCount)
            {
                throw new InvalidOperationException(
                    probeName +
                    " leaked a retained wait capability; expected " +
                    expectedCount.ToString(CultureInfo.InvariantCulture) +
                    " but observed " +
                    actualCount.ToString(CultureInfo.InvariantCulture) + ".");
            }
        }

        public static DrainerProbeResult RunCleanDrainProbe(int deadlineMilliseconds)
        {
            if (deadlineMilliseconds < 1) { throw new ArgumentOutOfRangeException("deadlineMilliseconds"); }
            long before = GetSnapshotAccessCount();
            DeterministicProbeStream stream1 = new DeterministicProbeStream(DeterministicProbeStream.Mode.ImmediateEof);
            DeterministicProbeStream stream2 = new DeterministicProbeStream(DeterministicProbeStream.Mode.ImmediateEof);
            ManualResetEvent overflow = new ManualResetEvent(false);
            StreamDrainer drainer1 = new StreamDrainer(stream1, 1024, overflow, false);
            StreamDrainer drainer2 = new StreamDrainer(stream2, 1024, overflow, false);
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                drainer1.Start();
                drainer2.Start();
                DrainCleanupOutcome outcome = CleanupDrainers(drainer1, true, drainer2, true, deadlineMilliseconds, false, cleanupErrors);
                long after = GetSnapshotAccessCount();
                bool aliveAfter = drainer1.IsAlive || drainer2.IsAlive;
                RequireNoCleanupErrors("drain-clean", cleanupErrors);
                return new DrainerProbeResult(stream1.DisposeCount, stream2.DisposeCount, true, true, !drainer1.IsAlive, !drainer2.IsAlive, outcome.DrainCompleted, aliveAfter, before, after, outcome.ForcedClose, null);
            }
            finally
            {
                overflow.Close();
            }
        }

        public static DrainerProbeResult RunForcedCloseDrainProbe(int deadlineMilliseconds)
        {
            if (deadlineMilliseconds < 1) { throw new ArgumentOutOfRangeException("deadlineMilliseconds"); }
            RunCreatedJobCompatibilityRegressionProbe();
            RunDiagnosticsOwnershipRegressionProbe();
            RunPublicSurfaceRegressionProbe();
            RunCompatibilityHostValidationRegressionProbe();
            RunSessionWaitPreemptionRegressionProbes();
            RunDrainCleanupOneBudgetProbe();
            RunProcessJobCleanupOneBudgetProbe();
            RunStreamDisposeFailureOwnershipRegressionProbe();
            long before = GetSnapshotAccessCount();
            DeterministicProbeStream stream1 = new DeterministicProbeStream(DeterministicProbeStream.Mode.BlockUntilDispose);
            DeterministicProbeStream stream2 = new DeterministicProbeStream(DeterministicProbeStream.Mode.BlockUntilDispose);
            ManualResetEvent overflow = new ManualResetEvent(false);
            StreamDrainer drainer1 = new StreamDrainer(stream1, 1024, overflow, false);
            StreamDrainer drainer2 = new StreamDrainer(stream2, 1024, overflow, false);
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                drainer1.Start();
                drainer2.Start();
                WaitForProbeReads(stream1, stream2, ProbeReadEntryDeadlineMilliseconds);
                DrainCleanupOutcome outcome = CleanupDrainers(drainer1, true, drainer2, true, deadlineMilliseconds, false, cleanupErrors);
                long after = GetSnapshotAccessCount();
                bool aliveAfter = drainer1.IsAlive || drainer2.IsAlive;
                RequireNoCleanupErrors("drain-forced", cleanupErrors);
                return new DrainerProbeResult(stream1.DisposeCount, stream2.DisposeCount, true, true, !drainer1.IsAlive, !drainer2.IsAlive, outcome.DrainCompleted, aliveAfter, before, after, outcome.ForcedClose, null);
            }
            finally
            {
                overflow.Close();
            }
        }

        public static DrainerProbeResult RunPartialStartDrainProbe(int deadlineMilliseconds)
        {
            if (deadlineMilliseconds < 1) { throw new ArgumentOutOfRangeException("deadlineMilliseconds"); }
            long before = GetSnapshotAccessCount();
            DeterministicProbeStream stream1 = new DeterministicProbeStream(DeterministicProbeStream.Mode.ImmediateEof);
            DeterministicProbeStream stream2 = new DeterministicProbeStream(DeterministicProbeStream.Mode.ImmediateEof);
            ManualResetEvent overflow = new ManualResetEvent(false);
            StreamDrainer drainer1 = new StreamDrainer(stream1, 1024, overflow, false);
            StreamDrainer drainer2 = new StreamDrainer(stream2, 1024, overflow, true);
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                bool started1 = false;
                bool started2 = false;
                string injectedFailureTypeName = null;
                try
                {
                    drainer1.Start();
                    started1 = true;
                    drainer2.Start();
                    started2 = true;
                }
                catch (InvalidOperationException injected)
                {
                    injectedFailureTypeName = injected.GetType().FullName;
                }
                if (injectedFailureTypeName == null || started2)
                {
                    throw new InvalidOperationException("partial-start probe requires a deterministic second-drainer start failure.");
                }
                DrainCleanupOutcome outcome = CleanupDrainers(drainer1, started1, drainer2, started2, deadlineMilliseconds, false, cleanupErrors);
                long after = GetSnapshotAccessCount();
                bool aliveAfter = drainer1.IsAlive || drainer2.IsAlive;
                RequireNoCleanupErrors("drain-partial-start", cleanupErrors);
                return new DrainerProbeResult(stream1.DisposeCount, stream2.DisposeCount, started1, started2, !drainer1.IsAlive, true, outcome.DrainCompleted, aliveAfter, before, after, outcome.ForcedClose, injectedFailureTypeName);
            }
            finally
            {
                overflow.Close();
            }
        }

        private static void RequireNoCleanupErrors(string probeId, List<Exception> cleanupErrors)
        {
            if (cleanupErrors.Count == 0)
            {
                return;
            }
            if (cleanupErrors.Count == 1)
            {
                throw new AggregateException("drainer probe '" + probeId + "' recorded a cleanup failure.", cleanupErrors.ToArray());
            }
            throw new AggregateException("drainer probe '" + probeId + "' recorded cleanup failures.", cleanupErrors.ToArray());
        }

        private static void WaitForProbeReads(DeterministicProbeStream stream1, DeterministicProbeStream stream2, int deadlineMilliseconds)
        {
            Stopwatch clock = Stopwatch.StartNew();
            while (clock.ElapsedMilliseconds < deadlineMilliseconds)
            {
                if (stream1.ReadEntered && stream2.ReadEntered)
                {
                    return;
                }
                Thread.Sleep(5);
            }
            throw new TimeoutException("deterministic probe streams did not enter their blocking read within the probe deadline.");
        }

        public static void RunNonUnwindingDrainProbe(string sentinelPath, string helperVersion, string probeNonce, int deadlineMilliseconds)
        {
            if (sentinelPath == null) { throw new ArgumentNullException("sentinelPath"); }
            if (helperVersion == null) { throw new ArgumentNullException("helperVersion"); }
            if (probeNonce == null) { throw new ArgumentNullException("probeNonce"); }
            if (deadlineMilliseconds < 1) { throw new ArgumentOutOfRangeException("deadlineMilliseconds"); }
            uint previousMode;
            if (!SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX, out previousMode))
            {
                throw Win32("SetThreadErrorMode");
            }
            uint effectiveMode = GetThreadErrorMode();
            if ((effectiveMode & SEM_NOGPFAULTERRORBOX) != SEM_NOGPFAULTERRORBOX)
            {
                throw new InvalidOperationException("thread error mode did not take effect.");
            }
            DeterministicProbeStream stream1 = new DeterministicProbeStream(DeterministicProbeStream.Mode.BlockForever);
            DeterministicProbeStream stream2 = new DeterministicProbeStream(DeterministicProbeStream.Mode.BlockForever);
            ManualResetEvent overflow = new ManualResetEvent(false);
            StreamDrainer drainer1 = new StreamDrainer(stream1, 1024, overflow, false);
            StreamDrainer drainer2 = new StreamDrainer(stream2, 1024, overflow, false);
            drainer1.Start();
            drainer2.Start();
            WaitForProbeReads(stream1, stream2, ProbeReadEntryDeadlineMilliseconds);
            List<Exception> cleanupErrors = new List<Exception>();
            Stopwatch cleanupStopwatch = Stopwatch.StartNew();
            DrainCleanupOutcome outcome = CleanupDrainers(
                drainer1,
                true,
                drainer2,
                true,
                deadlineMilliseconds,
                false,
                cleanupErrors);
            long snapshotAccess = GetSnapshotAccessCount();
            WriteFailFastSentinel(sentinelPath, helperVersion, probeNonce, snapshotAccess);
            if (cleanupStopwatch.ElapsedMilliseconds >
                checked((long)deadlineMilliseconds + CleanupBudgetProbeSchedulerToleranceMilliseconds))
            {
                NonUnwindingFailFast("stuck drainer probe exceeded its single cleanup deadline plus scheduler tolerance.");
            }
            if (outcome.DrainersQuiesced ||
                cleanupErrors.Count != 1 ||
                !(cleanupErrors[0] is IOException) ||
                !string.Equals(
                    cleanupErrors[0].Message,
                    "a started drainer thread is still alive after forced stream close and both join deadlines.",
                    StringComparison.Ordinal))
            {
                NonUnwindingFailFast("stuck drainer probe did not preserve the expected forced-close outcome.");
            }
            NonUnwindingFailFast("stuck drainer probe: threads still own the pipe.");
        }

        public static void RunNonUnwindingNegativeControl(string sentinelPath, string helperVersion, string probeNonce)
        {
            if (sentinelPath == null) { throw new ArgumentNullException("sentinelPath"); }
            if (helperVersion == null) { throw new ArgumentNullException("helperVersion"); }
            if (probeNonce == null) { throw new ArgumentNullException("probeNonce"); }
            WriteFailFastSentinel(sentinelPath, helperVersion, probeNonce, 0);
            ExitProcess(123);
        }

        private static void WriteFailFastSentinel(string path, string helperVersion, string probeNonce, long snapshotAccess)
        {
            if (path == null) { throw new ArgumentNullException("path"); }
            byte[] bytes = BuildFailFastSentinelRecord(helperVersion, probeNonce, snapshotAccess);
            string root = Path.GetDirectoryName(path);
            string leaf = Path.GetFileName(path);
            WriteBoundedReceipt(root, leaf, bytes, FailFastSentinelCapBytes);
        }

        public static void RunReadyThenWaitPrelude(string gateEventName, string waiterReadyEventName, int timeoutMilliseconds, int timeoutExitCode)
        {
            if (timeoutMilliseconds < 1) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            NamedEvent gate = null;
            NamedEvent waiter = null;
            NativeWaitStatus status;
            try
            {
                gate = NamedEvent.OpenExisting(gateEventName, EventAccessMode.WaitOnly, EventRole.Gate, Guid.Empty);
                waiter = NamedEvent.OpenExisting(waiterReadyEventName, EventAccessMode.SetOnly, EventRole.WaiterReady, Guid.Empty);
                try
                {
                    status = waiter.SignalObjectAndWaitOn(gate, timeoutMilliseconds);
                }
                catch (NativeWaitException)
                {
                    ExitProcess(4);
                    return;
                }
                if (status == NativeWaitStatus.Timeout)
                {
                    ExitProcess((uint)timeoutExitCode);
                    return;
                }
                if (status != NativeWaitStatus.Object0)
                {
                    ExitProcess(4);
                    return;
                }
            }
            finally
            {
                if (waiter != null) { waiter.Dispose(); }
                if (gate != null) { gate.Dispose(); }
            }
        }

        public static NativeWaitStatus RunNestedPrelude(string nestedReadyEventName, string nestedReleaseEventName, int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 1) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            NamedEvent ready = NamedEvent.OpenExisting(nestedReadyEventName, EventAccessMode.SetOnly, EventRole.NestedReady, Guid.Empty);
            NamedEvent release = NamedEvent.OpenExisting(nestedReleaseEventName, EventAccessMode.WaitOnly, EventRole.NestedRelease, Guid.Empty);
            try
            {
                return ready.SignalObjectAndWaitOn(release, timeoutMilliseconds);
            }
            finally
            {
                ready.Dispose();
                release.Dispose();
            }
        }

        public static bool RunManagedGateWait(string gateEventName, int timeoutMilliseconds)
        {
            if (gateEventName == null) { throw new ArgumentNullException("gateEventName"); }
            if (timeoutMilliseconds < 1) { throw new ArgumentOutOfRangeException("timeoutMilliseconds"); }
            ValidateEventNameGrammar(gateEventName);
            using (EventWaitHandle handle = EventWaitHandle.OpenExisting(gateEventName))
            {
                return handle.WaitOne(timeoutMilliseconds);
            }
        }

        internal static PreNativeRejectProbeResult RunPrelaunchRejectProbe(string probeId, ProcessLaunchConfiguration configuration)
        {
            if (probeId == null) { throw new ArgumentNullException("probeId"); }
            switch (probeId)
            {
                case "reject-combined-seam": return RunCombinedSeamRejectProbe(configuration);
                case "reject-basic": return RunBasicRejectProbe(configuration);
                case "reject-event-name": return RunEventNameRejectProbe(configuration);
                case "reject-empty-correlation": return RunEmptyCorrelationRejectProbe(configuration);
                case "reject-pause-config": return RunInvalidPauseRejectProbe(configuration);
                case "reject-environment": return RunEnvironmentRejectProbe(configuration);
                default: throw new ArgumentException("unknown prelaunch probe id '" + probeId + "'.");
            }
        }

        public static PreNativeRejectProbeResult RunCombinedSeamRejectProbe(ProcessLaunchConfiguration configuration)
        {
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            Stopwatch stopwatch = Stopwatch.StartNew();
            string observed;
            try
            {
                Run(configuration);
                throw new InvalidOperationException("combined-seam probe expected a rejection but Run returned.");
            }
            catch (InvalidPreAssignmentConfigurationException expected) { observed = expected.GetType().FullName; }
            stopwatch.Stop();
            return new PreNativeRejectProbeResult("reject-combined-seam", PreNativeRejectReason.CombinedSeam, observed, stopwatch.ElapsedMilliseconds, before, GetDiagnosticsSnapshot());
        }

        public static PreNativeRejectProbeResult RunBasicRejectProbe(ProcessLaunchConfiguration configuration)
        {
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            Stopwatch stopwatch = Stopwatch.StartNew();
            string observed;
            try
            {
                Run(configuration);
                throw new InvalidOperationException("basic probe expected a rejection but Run returned.");
            }
            catch (NativeCommandLineException expected) { observed = expected.GetType().FullName; }
            catch (ArgumentException expected) { observed = expected.GetType().FullName; }
            stopwatch.Stop();
            return new PreNativeRejectProbeResult("reject-basic", PreNativeRejectReason.Basic, observed, stopwatch.ElapsedMilliseconds, before, GetDiagnosticsSnapshot());
        }

        public static PreNativeRejectProbeResult RunEventNameRejectProbe(ProcessLaunchConfiguration configuration)
        {
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            Stopwatch stopwatch = Stopwatch.StartNew();
            string observed;
            try
            {
                Run(configuration);
                throw new InvalidOperationException("event-name probe expected a rejection but Run returned.");
            }
            catch (EventNameGrammarException expected) { observed = expected.GetType().FullName; }
            stopwatch.Stop();
            return new PreNativeRejectProbeResult("reject-event-name", PreNativeRejectReason.EventName, observed, stopwatch.ElapsedMilliseconds, before, GetDiagnosticsSnapshot());
        }

        public static PreNativeRejectProbeResult RunEmptyCorrelationRejectProbe(ProcessLaunchConfiguration configuration)
        {
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            Stopwatch stopwatch = Stopwatch.StartNew();
            string observed;
            try
            {
                Run(configuration);
                throw new InvalidOperationException("empty-correlation probe expected a rejection but Run returned.");
            }
            catch (CorrelationIdRequiredException expected) { observed = expected.GetType().FullName; }
            stopwatch.Stop();
            return new PreNativeRejectProbeResult("reject-empty-correlation", PreNativeRejectReason.EmptyCorrelation, observed, stopwatch.ElapsedMilliseconds, before, GetDiagnosticsSnapshot());
        }

        public static PreNativeRejectProbeResult RunInvalidPauseRejectProbe(ProcessLaunchConfiguration configuration)
        {
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            Stopwatch stopwatch = Stopwatch.StartNew();
            string observed;
            try
            {
                Run(configuration);
                throw new InvalidOperationException("invalid-pause probe expected a rejection but Run returned.");
            }
            catch (InvalidPauseConfigurationException expected) { observed = expected.GetType().FullName; }
            stopwatch.Stop();
            return new PreNativeRejectProbeResult("reject-pause-config", PreNativeRejectReason.PauseConfig, observed, stopwatch.ElapsedMilliseconds, before, GetDiagnosticsSnapshot());
        }

        public static PreNativeRejectProbeResult RunEnvironmentRejectProbe(ProcessLaunchConfiguration configuration)
        {
            BoundedProcessDiagnosticsSnapshot before = GetDiagnosticsSnapshot();
            Stopwatch stopwatch = Stopwatch.StartNew();
            string observed;
            try
            {
                Run(configuration);
                throw new InvalidOperationException("environment probe expected a rejection but Run returned.");
            }
            catch (EnvironmentConfigurationException expected) { observed = expected.GetType().FullName; }
            stopwatch.Stop();
            return new PreNativeRejectProbeResult("reject-environment", PreNativeRejectReason.Environment, observed, stopwatch.ElapsedMilliseconds, before, GetDiagnosticsSnapshot());
        }

        public static ContainedWorkerSession RunContainedValidatorWorker(
            string hostExecutablePath,
            string[] arguments,
            string supervisorGateEventName,
            string[] reservedEnvironmentNames,
            string[] reservedEnvironmentValues,
            string workingDirectory,
            ContainedWorkerScenario scenario)
        {
            ProcessLaunchConfiguration configuration = CreateProcessLaunchConfiguration(
                ProcessLaunchRole.Worker, hostExecutablePath, arguments, supervisorGateEventName, SupervisorGateEventVariable,
                new string[0], new string[0], reservedEnvironmentNames, reservedEnvironmentValues,
                600000, 15000, 15000, 65536, false, Guid.Empty, workingDirectory,
                null, null, null, null, null);
            return RunContainedValidatorWorker(configuration, scenario);
        }

        public static ContainedWorkerSession RunContainedValidatorWorker(ProcessLaunchConfiguration configuration, ContainedWorkerScenario scenario)
        {
            if (configuration == null) { throw new ArgumentNullException("configuration"); }
            if (!Enum.IsDefined(typeof(ContainedWorkerScenario), scenario))
            {
                throw new ContainedWorkerException("unknown ContainedWorkerScenario value.");
            }

            Dictionary<string, string> frozen = ValidateConfiguration(configuration, LauncherKind.ContainedValidatorWorker);
            try { ValidateWorkerArgv(configuration, scenario); }
            catch (ContainedWorkerException) { RecordReject(PreNativeRejectReason.Environment); throw; }
            string resultRoot = RequireReservedDirectoryRoot(configuration, EnvWorkerResultPath, true);
            string controlRoot = RequireReservedDirectoryRoot(configuration, EnvNestedControlRoot, true);

            LaunchPathBinding paths;
            try
            {
                paths = BindLaunchPaths(configuration.ExecutablePath, configuration.ArgumentsInternal, configuration.WorkingDirectory);
            }
            catch (LaunchPathIdentityException)
            {
                RecordPathIdentityReject();
                throw;
            }

            string commandLine = null;
            string environmentBlock = null;

            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            NamedEvent gate = null;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            bool processCreated = false;
            bool transferred = false;
            bool assignedToJob = false;
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                commandLine = BuildNativeCommandLine(paths.ExecutableFullPath, configuration.ArgumentsInternal);
                environmentBlock = BuildNativeEnvironmentBlock(frozen);
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
                if (cleanupErrors.Count > 0)
                {
                    throw new ContainedWorkerException("contained worker job security cleanup failed before process creation.");
                }
                if (scenario != ContainedWorkerScenario.WorkerGateOpenFailure)
                {
                    gate = NamedEvent.CreateNewManualReset(configuration.GateEventName, EventRole.SupervisorGate, Guid.Empty);
                }

                processInfo = CreateSuspendedProcess(paths.ExecutableFullPath, commandLine, environmentBlock, paths.WorkingDirectoryFullPath);
                processCreated = true;
                long startFileTime = GetCreationFileTime(processInfo.hProcess);
                ContainedRootIdentity rootIdentity = ContainedRootIdentity.Capture(processInfo.hProcess, processInfo.dwProcessId, startFileTime);

                if (scenario == ContainedWorkerScenario.SimulateAssignFailure)
                {
                    Exception simulatedPrimary = new ContainedWorkerException("simulated worker assignment failure.");
                    TerminateNativeForOutcome(
                        processInfo.hProcess, processInfo.dwProcessId, false, job, 15000, simulatedPrimary);
                    ContainedWorkerSession simulated = new ContainedWorkerSession(
                        scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal,
                        rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                        resultRoot, controlRoot, ContainedWorkerState.Exited, null,
                        new ContainedWorkerLaunchDiagnostic(scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal, commandLine, processInfo.dwProcessId, startFileTime, false, true));
                    simulated.AttachPathBinding(paths);
                    transferred = true;
                    return simulated;
                }

                RecordAssignmentAttempt();
                bool assigned = AssignProcessToJobObject(job, processInfo.hProcess);
                int assignError = assigned ? 0 : Marshal.GetLastWin32Error();
                if (!assigned && assignError == 0)
                {
                    throw new ContainedWorkerException("AssignProcessToJobObject(worker) reported failure without a Win32 error.");
                }
                if (assigned) { assignedToJob = true; }
                bool inJob = false;
                if (assigned)
                {
                    if (!IsProcessInJob(processInfo.hProcess, job, out inJob))
                    {
                        int membershipError = Marshal.GetLastWin32Error();
                        throw new ContainedWorkerException("IsProcessInJob(worker) failed.", new Win32Exception(membershipError));
                    }
                }
                if (!assigned || !inJob)
                {
                    Exception assignmentPrimary = !assigned
                        ? (Exception)new ContainedWorkerException(
                            "failed to assign the suspended worker to its job.",
                            new Win32Exception(assignError))
                        : new ContainedWorkerException("suspended worker job membership could not be verified.");
                    TerminateNativeForOutcome(
                        processInfo.hProcess, processInfo.dwProcessId, assignedToJob, job, 15000, assignmentPrimary);
                    ContainedWorkerSession assignFailed = new ContainedWorkerSession(
                        scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal,
                        rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                        resultRoot, controlRoot, ContainedWorkerState.Exited, null,
                        new ContainedWorkerLaunchDiagnostic(scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal, commandLine, processInfo.dwProcessId, startFileTime, inJob, true));
                    assignFailed.AttachPathBinding(paths);
                    transferred = true;
                    return assignFailed;
                }

                uint resumeReturn;
                int nativeResumeCalls;
                int resumeWin32Error;
                bool resumeFailed;
                switch (scenario)
                {
                    case ContainedWorkerScenario.ResumeFailureZero:
                        resumeReturn = 0;
                        nativeResumeCalls = 0;
                        resumeWin32Error = 0;
                        resumeFailed = true;
                        break;
                    case ContainedWorkerScenario.ResumeFailureNative:
                        resumeReturn = RESUME_THREAD_FAILED;
                        nativeResumeCalls = 0;
                        resumeWin32Error = ResumeFailureNativePinnedError;
                        resumeFailed = true;
                        break;
                    case ContainedWorkerScenario.ResumeFailureMultiple:
                        if (SuspendThread(processInfo.hThread) == RESUME_THREAD_FAILED)
                        {
                            throw Win32("SuspendThread(worker)");
                        }
                        resumeReturn = ResumeThread(processInfo.hThread);
                        nativeResumeCalls = 1;
                        resumeWin32Error = 0;
                        resumeFailed = true;
                        break;
                    default:
                        resumeReturn = ResumeThread(processInfo.hThread);
                        nativeResumeCalls = 1;
                        resumeWin32Error = (resumeReturn == RESUME_THREAD_FAILED) ? Marshal.GetLastWin32Error() : 0;
                        resumeFailed = (resumeReturn != 1);
                        break;
                }

                if (resumeFailed)
                {
                    Exception resumePrimary = new ContainedWorkerException(
                        "worker resume failed with return value " + resumeReturn.ToString(CultureInfo.InvariantCulture) + ".");
                    long active = TerminateNativeForOutcome(
                        processInfo.hProcess, processInfo.dwProcessId, true, job, 15000, resumePrimary);
                    ResumeFailureOutcome outcome = new ResumeFailureOutcome(resumeReturn, nativeResumeCalls, resumeWin32Error, false, checked((int)active));
                    ContainedWorkerSession resumeFailedSession = new ContainedWorkerSession(
                        scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal,
                        rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                        resultRoot, controlRoot, ContainedWorkerState.Exited, outcome,
                        new ContainedWorkerLaunchDiagnostic(scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal, commandLine, processInfo.dwProcessId, startFileTime, true, false));
                    resumeFailedSession.AttachPathBinding(paths);
                    transferred = true;
                    return resumeFailedSession;
                }

                ContainedWorkerSession session = new ContainedWorkerSession(
                    scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal,
                    rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                    resultRoot, controlRoot, ContainedWorkerState.Resumed, null,
                    new ContainedWorkerLaunchDiagnostic(scenario, ProcessLaunchRole.Worker, false, GeneratorScenario.Normal, commandLine, processInfo.dwProcessId, startFileTime, true, false));
                session.AttachPathBinding(paths);
                transferred = true;
                return session;
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }
            ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
            if (!transferred)
            {
                CleanupProof proof = ProveNativeLaunchQuiescence(
                    processCreated, processInfo, assignedToJob, job, 15000, cleanupErrors);
                if (proof.CanRelease)
                {
                    ReleasePartialNativeLaunch(
                        ref processInfo, ref job, ref gate, ref paths, cleanupErrors);
                }
                else
                {
                    Exception invariant = new ContainedLaunchOwnershipQuarantinedException(
                        "contained validator worker cleanup could not prove process exit and job quiescence; ownership was quarantined.");
                    if (primary == null) { primary = invariant; }
                    else { cleanupErrors.Add(invariant); }
                    QuarantineNativeLaunch(
                        ref processInfo, ref job, ref gate, ref paths);
                }
            }

            if (primary != null)
            {
                throw ComposeCleanupException(primary, cleanupErrors.ToArray());
            }
            primary = new ContainedWorkerException("contained validator worker launch completed without returning a session or surfacing a fault.");
            throw ComposeCleanupException(primary, cleanupErrors.ToArray());
        }

        private static string RequireReservedDirectoryRoot(ProcessLaunchConfiguration configuration, string reservedName, bool required)
        {
            string[] names = configuration.ReservedEnvironmentNamesInternal;
            string[] values = configuration.ReservedEnvironmentValuesInternal;
            for (int index = 0; index < names.Length; index++)
            {
                if (string.Equals(names[index], reservedName, StringComparison.Ordinal))
                {
                    string value = values[index];
                    string candidate = value;
                    if (string.Equals(reservedName, EnvWorkerResultPath, StringComparison.Ordinal) ||
                        string.Equals(reservedName, EnvGeneratorResultPath, StringComparison.Ordinal))
                    {
                        candidate = Path.GetDirectoryName(value);
                    }
                    return RequireOrdinaryNonReparseDirectory(candidate);
                }
            }
            if (required)
            {
                throw new EnvironmentConfigurationException(reservedName, "reserved value '" + reservedName + "' is required to derive the session root.");
            }
            return null;
        }

        private static void WaitProcessExactly(IntPtr processHandle, int timeoutMilliseconds, int processId)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            uint raw = WaitForSingleObject(processHandle, (uint)timeoutMilliseconds);
            if (raw == WAIT_OBJECT_0)
            {
                return;
            }
            if (raw == WAIT_FAILED)
            {
                throw new NativeWaitException(Marshal.GetLastWin32Error(), "WaitForSingleObject failed for process " + processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            if (raw == WAIT_TIMEOUT)
            {
                throw new NativeWaitException(0, "process " + processId.ToString(CultureInfo.InvariantCulture) + " did not exit within the termination deadline.");
            }
            throw new NativeWaitException(0, "WaitForSingleObject returned unexpected status 0x" + raw.ToString("X8", CultureInfo.InvariantCulture) + " for process " + processId.ToString(CultureInfo.InvariantCulture) + ".");
        }

        private static void TerminateAndProveNativeExit(
            IntPtr processHandle,
            int processId,
            Stopwatch timeoutStopwatch,
            int timeoutMilliseconds)
        {
            if (timeoutStopwatch == null)
            {
                throw new ArgumentNullException("timeoutStopwatch");
            }
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            uint exitCode;
            if (!GetExitCodeProcess(processHandle, out exitCode))
            {
                throw Win32("GetExitCodeProcess");
            }
            if (exitCode == STILL_ACTIVE_STATUS)
            {
                if (!TerminateProcess(processHandle, 1))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (!GetExitCodeProcess(processHandle, out exitCode) || exitCode == STILL_ACTIVE_STATUS)
                    {
                        throw new Win32Exception(error, "TerminateProcess failed for process " + processId.ToString(CultureInfo.InvariantCulture) + ".");
                    }
                }
            }
            WaitProcessExactly(
                processHandle,
                GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds),
                processId);
            if (!GetExitCodeProcess(processHandle, out exitCode))
            {
                throw Win32("GetExitCodeProcess");
            }
            if (exitCode == STILL_ACTIVE_STATUS)
            {
                throw new ContainedWorkerException("process " + processId.ToString(CultureInfo.InvariantCulture) + " still reports STILL_ACTIVE after a completed wait.");
            }
        }

        private static long TerminateNativeForOutcome(
            IntPtr processHandle,
            int processId,
            bool assignedToJob,
            IntPtr job,
            int timeoutMilliseconds,
            Exception operationalPrimary)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            Stopwatch timeoutStopwatch = Stopwatch.StartNew();
            List<Exception> cleanupErrors = new List<Exception>();
            if (assignedToJob && job != IntPtr.Zero)
            {
                if (!TerminateJob(job))
                {
                    cleanupErrors.Add(Win32("TerminateJobObject(outcome cleanup)"));
                }
                try
                {
                    WaitProcessExactly(
                        processHandle,
                        GetRemainingTimeoutMilliseconds(timeoutStopwatch, timeoutMilliseconds),
                        processId);
                }
                catch (Exception waitError) { cleanupErrors.Add(waitError); }
            }
            else
            {
                try
                {
                    TerminateAndProveNativeExit(
                        processHandle,
                        processId,
                        timeoutStopwatch,
                        timeoutMilliseconds);
                }
                catch (Exception terminationError) { cleanupErrors.Add(terminationError); }
            }

            long active = -1;
            if (job != IntPtr.Zero)
            {
                try
                {
                    active = RequireJobActiveZero(
                        job,
                        timeoutStopwatch,
                        timeoutMilliseconds,
                        processId);
                }
                catch (Exception proofError) { cleanupErrors.Add(proofError); }
            }
            if (cleanupErrors.Count > 0)
            {
                throw ComposeCleanupException(operationalPrimary, cleanupErrors.ToArray());
            }
            return active < 0 ? 0 : active;
        }

        private static long RequireJobActiveZero(
            IntPtr job,
            Stopwatch timeoutStopwatch,
            int timeoutMilliseconds,
            int processId)
        {
            if (job == IntPtr.Zero)
            {
                throw new ContainedWorkerException("no job handle is available to prove zero accounting for process " + processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            long active = PollJobActiveProcessesToZero(job, timeoutStopwatch, timeoutMilliseconds);
            if (active != 0)
            {
                throw new ContainedWorkerException("job still reports " + active.ToString(CultureInfo.InvariantCulture) + " active processes after terminating process " + processId.ToString(CultureInfo.InvariantCulture) + ".");
            }
            return active;
        }

        private static PROCESS_INFORMATION CreateSuspendedProcess(string hostExecutablePath, string commandLine, string environmentBlock, string workingDirectory)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            IntPtr commandBuffer = Marshal.StringToHGlobalUni(commandLine);
            IntPtr environmentBuffer = Marshal.StringToHGlobalUni(environmentBlock);
            try
            {
                PROCESS_INFORMATION processInfo;
                uint flags = ContainedNativeCreationFlags;
                RecordProcessStart();
                bool created = CreateProcessW(hostExecutablePath, commandBuffer, IntPtr.Zero, IntPtr.Zero, false, flags, environmentBuffer, workingDirectory, ref startupInfo, out processInfo);
                if (!created)
                {
                    throw Win32("CreateProcessW(worker)");
                }
                return processInfo;
            }
            finally
            {
                Marshal.FreeHGlobal(commandBuffer);
                Marshal.FreeHGlobal(environmentBuffer);
            }
        }

        public static uint GetContainedNativeCreationFlags()
        {
            return ContainedNativeCreationFlags;
        }

        private static long GetCreationFileTime(IntPtr processHandle)
        {
            long creation;
            long exit;
            long kernel;
            long user;
            if (!GetProcessTimes(processHandle, out creation, out exit, out kernel, out user))
            {
                throw Win32("GetProcessTimes");
            }
            return creation;
        }

        private static readonly string[] PowerShellGateFirstPrefix = new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File" };

        private static void ValidateStep7GateFirstHost(ProcessLaunchConfiguration cfg)
        {
            string pinnedHost = ResolveCurrentPowerShellHostImage(cfg.Role);
            RequireRolePinnedHostImage(cfg.Role, cfg.ExecutablePath, pinnedHost);
        }

        private static string ResolveCurrentPowerShellHostImage(ProcessLaunchRole role)
        {
            string hostImagePath;
            try
            {
                Process current = Process.GetCurrentProcess();
                ProcessModule mainModule = current.MainModule;
                hostImagePath = mainModule.FileName;
            }
            catch (InvalidOperationException error)
            {
                throw new ProcessLaunchConfigurationException(role, "unable to resolve the current PowerShell host image: " + error.Message);
            }
            catch (Win32Exception error)
            {
                throw new ProcessLaunchConfigurationException(role, "unable to resolve the current PowerShell host image: " + error.Message);
            }
            catch (NotSupportedException error)
            {
                throw new ProcessLaunchConfigurationException(role, "unable to resolve the current PowerShell host image: " + error.Message);
            }
            if (!IsPowerShellImage(hostImagePath))
            {
                throw new ProcessLaunchConfigurationException(role, "the current host image '" + (hostImagePath == null ? "<null>" : hostImagePath) + "' is not a supported gate-first PowerShell host (pwsh.exe or powershell.exe).");
            }
            return hostImagePath;
        }

        private static void RequireRolePinnedHostImage(ProcessLaunchRole role, string executablePath, string pinnedHost)
        {
            if (string.IsNullOrEmpty(executablePath))
            {
                throw new ProcessLaunchConfigurationException(role, "role " + role.ToString() + " requires the role-pinned current PowerShell host image; no executable path was supplied.");
            }
            if (!IsPowerShellImage(executablePath))
            {
                throw new ProcessLaunchConfigurationException(role, "role " + role.ToString() + " requires a gate-first PowerShell host image (pwsh.exe or powershell.exe); '" + executablePath + "' is not accepted.");
            }
            string candidate = CanonicalizeHostImagePath(role, executablePath);
            string pinned = CanonicalizeHostImagePath(role, pinnedHost);
            if (!string.Equals(candidate, pinned, StringComparison.OrdinalIgnoreCase))
            {
                throw new ProcessLaunchConfigurationException(role, "role " + role.ToString() + " must launch the role-pinned current host '" + pinnedHost + "'; '" + executablePath + "' is not that host.");
            }
        }

        private static string CanonicalizeHostImagePath(ProcessLaunchRole role, string path)
        {
            string full;
            try
            {
                full = Path.GetFullPath(path);
            }
            catch (ArgumentException error)
            {
                throw new ProcessLaunchConfigurationException(role, "host image path '" + path + "' is not a canonicalizable path: " + error.Message);
            }
            catch (NotSupportedException error)
            {
                throw new ProcessLaunchConfigurationException(role, "host image path '" + path + "' is not a canonicalizable path: " + error.Message);
            }
            catch (PathTooLongException error)
            {
                throw new ProcessLaunchConfigurationException(role, "host image path '" + path + "' is not a canonicalizable path: " + error.Message);
            }
            catch (System.Security.SecurityException error)
            {
                throw new ProcessLaunchConfigurationException(role, "host image path '" + path + "' is not a canonicalizable path: " + error.Message);
            }
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        private static void ValidatePowerShellEntryArguments(ProcessLaunchRole role, string executablePath, string[] arguments)
        {
            if (!IsPowerShellImage(executablePath))
            {
                return;
            }
            if (arguments.Length < 5)
            {
                throw new ProcessLaunchConfigurationException(role, "PowerShell launches require at least 5 argv elements: -NoLogo -NoProfile -NonInteractive -File <script>.");
            }
            for (int index = 0; index < PowerShellGateFirstPrefix.Length; index++)
            {
                if (!string.Equals(arguments[index], PowerShellGateFirstPrefix[index], StringComparison.Ordinal))
                {
                    throw new ProcessLaunchConfigurationException(role, "PowerShell launches require argv[" + index.ToString(CultureInfo.InvariantCulture) + "] to equal '" + PowerShellGateFirstPrefix[index] + "'.");
                }
            }
            if (string.IsNullOrEmpty(arguments[4]) || string.Equals(arguments[4], "-", StringComparison.Ordinal))
            {
                throw new ProcessLaunchConfigurationException(role, "PowerShell launches require a nonempty script path at argv[4].");
            }
        }

        private static void ValidateContainedProbeArgv(ProcessLaunchConfiguration configuration)
        {
            string[] arguments = configuration.ArgumentsInternal;
            if (arguments.Length != 5)
            {
                throw new ProcessLaunchConfigurationException(configuration.Role, "role " + configuration.Role.ToString() + " requires exactly 5 argv elements: -NoLogo -NoProfile -NonInteractive -File <script>.");
            }
        }

        private static void ValidateWorkerArgv(ProcessLaunchConfiguration configuration, ContainedWorkerScenario scenario)
        {
            string[] arguments = configuration.ArgumentsInternal;
            if (arguments.Length != 8 && arguments.Length != 10)
            {
                throw new ContainedWorkerException("Worker argv must be exactly 8 elements, or 10 when -WorkerMutation is required.");
            }
            if (!string.Equals(arguments[5], "-Worker", StringComparison.Ordinal))
            {
                throw new ContainedWorkerException("Worker argv[5] must equal '-Worker'.");
            }
            if (!string.Equals(arguments[6], "-WorkerScenario", StringComparison.Ordinal))
            {
                throw new ContainedWorkerException("Worker argv[6] must equal '-WorkerScenario'.");
            }
            if (!string.Equals(arguments[7], scenario.ToString(), StringComparison.Ordinal))
            {
                throw new ContainedWorkerException("Worker argv[7] must equal the exact scenario name '" + scenario.ToString() + "'.");
            }
            bool mutationSupplied = arguments.Length == 10;
            if (scenario == ContainedWorkerScenario.MalformedWorkerResult)
            {
                if (!mutationSupplied)
                {
                    throw new ContainedWorkerException("the MalformedWorkerResult scenario requires '-WorkerMutation <mutation>'.");
                }
                if (!string.Equals(arguments[8], "-WorkerMutation", StringComparison.Ordinal))
                {
                    throw new ContainedWorkerException("Worker argv[8] must equal '-WorkerMutation'.");
                }
                bool known = false;
                string[] mutations = Enum.GetNames(typeof(WorkerResultMutation));
                for (int index = 0; index < mutations.Length; index++)
                {
                    if (string.Equals(mutations[index], arguments[9], StringComparison.Ordinal))
                    {
                        known = true;
                        break;
                    }
                }
                if (!known)
                {
                    throw new ContainedWorkerException("Worker argv[9] must equal a defined WorkerResultMutation name.");
                }
            }
            else if (mutationSupplied)
            {
                throw new ContainedWorkerException("-WorkerMutation is forbidden for scenario " + scenario.ToString() + ".");
            }
        }

        public static ContainedProbeResult RunContainedProbe(
            string hostExecutablePath,
            string[] arguments,
            string gateEventName,
            ProcessLaunchRole role,
            string[] reservedEnvironmentNames,
            string[] reservedEnvironmentValues,
            string workingDirectory,
            int deadlineMilliseconds)
        {
            ProcessLaunchConfiguration configuration = CreateProcessLaunchConfiguration(
                role, hostExecutablePath, arguments, gateEventName, GetRoleGateVariable(role),
                new string[0], new string[0], reservedEnvironmentNames, reservedEnvironmentValues,
                deadlineMilliseconds < 1 ? 1 : deadlineMilliseconds, 15000, 15000, 65536, false, Guid.Empty, workingDirectory,
                null, null, null, null, null);
            return RunContainedProbe(configuration, deadlineMilliseconds);
        }

        public static ContainedProbeResult RunContainedProbe(ProcessLaunchConfiguration configuration, int deadlineMilliseconds)
        {
            if (configuration == null) { throw new ArgumentNullException("configuration"); }
            if (deadlineMilliseconds < 1) { throw new ArgumentOutOfRangeException("deadlineMilliseconds"); }

            Dictionary<string, string> frozen = ValidateConfiguration(configuration, LauncherKind.ContainedProbe);
            try { ValidateContainedProbeArgv(configuration); }
            catch (ProcessLaunchConfigurationException) { RecordReject(PreNativeRejectReason.Environment); throw; }

            LaunchPathBinding paths;
            try
            {
                paths = BindLaunchPaths(configuration.ExecutablePath, configuration.ArgumentsInternal, configuration.WorkingDirectory);
            }
            catch (LaunchPathIdentityException)
            {
                RecordPathIdentityReject();
                throw;
            }

            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            NamedEvent gate = null;
            Process process = null;
            int pid = 0;
            bool started = false;
            bool assignedToJob = false;
            ContainedProbeResult result = null;
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
                if (cleanupErrors.Count > 0)
                {
                    throw new ContainedWorkerException("nested probe job security cleanup failed before process creation.");
                }
                gate = NamedEvent.CreateNewManualReset(configuration.GateEventName, EventRole.SupervisorGate, Guid.Empty);

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = paths.ExecutableFullPath;
                startInfo.Arguments = BuildCommandLine(configuration.ArgumentsInternal);
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = false;
                startInfo.RedirectStandardOutput = false;
                startInfo.RedirectStandardError = false;
                startInfo.RedirectStandardInput = false;
                startInfo.WorkingDirectory = paths.WorkingDirectoryFullPath;
                startInfo.EnvironmentVariables.Clear();
                foreach (KeyValuePair<string, string> pair in frozen)
                {
                    startInfo.EnvironmentVariables[pair.Key] = pair.Value;
                }

                process = new Process();
                process.StartInfo = startInfo;
                RecordProcessStart();
                process.Start();
                started = true;
                pid = process.Id;
                long startFileTime = ReadStartFileTime(process);

                RecordAssignmentAttempt();
                bool assigned = AssignProcessToJobObject(job, process.Handle);
                int assignError = assigned ? 0 : Marshal.GetLastWin32Error();
                if (!assigned && assignError == 0)
                {
                    throw new ContainedWorkerException("AssignProcessToJobObject(probe) reported failure without a Win32 error.");
                }
                if (assigned) { assignedToJob = true; }
                bool inJob = false;
                if (assigned && !IsProcessInJob(process.Handle, job, out inJob))
                {
                    int membershipError = Marshal.GetLastWin32Error();
                    throw new ContainedWorkerException("IsProcessInJob(probe) failed for the nested probe.", new Win32Exception(membershipError));
                }
                if (!assigned || !inJob)
                {
                    if (!assigned)
                    {
                        throw new ContainedWorkerException("failed to assign the nested probe to its job.", new Win32Exception(assignError));
                    }
                    throw new ContainedWorkerException("nested probe job membership could not be verified.");
                }

                gate.SetEvent();

                bool exited = process.WaitForExit(deadlineMilliseconds);
                bool timedOut = false;
                if (!exited)
                {
                    timedOut = true;
                    if (!TerminateJob(job))
                    {
                        cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed for the nested probe."));
                    }
                    TerminateAndProveExit(process, pid, 15000);
                }
                long active = PollJobActiveProcessesToZero(job, 15000);
                if (active != 0)
                {
                    if (!TerminateJob(job))
                    {
                        cleanupErrors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed while draining surviving nested-probe descendants."));
                    }
                    active = PollJobActiveProcessesToZero(job, 15000);
                    if (active != 0)
                    {
                        cleanupErrors.Add(new ContainedWorkerException("nested probe job still reports " + active.ToString(CultureInfo.InvariantCulture) + " active processes after termination."));
                    }
                }
                bool reallyExited = process.HasExited;
                int exitCode = -1;
                if (reallyExited)
                {
                    exitCode = process.ExitCode;
                }
                result = new ContainedProbeResult(pid, startFileTime, reallyExited, exitCode, timedOut, active);
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }

            ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
            CleanupProof proof = ProveManagedLaunchQuiescence(
                process, started, assignedToJob, job, 15000, pid,
                null, false, null, false, 0, cleanupErrors);
            if (!proof.CanRelease)
            {
                Exception invariant = new ContainedLaunchOwnershipQuarantinedException(
                    "nested probe cleanup could not prove process exit and job quiescence; ownership was quarantined.");
                if (primary == null) { primary = invariant; }
                else { cleanupErrors.Add(invariant); }
                StreamDrainer outDrainer = null;
                StreamDrainer errDrainer = null;
                ManualResetEvent overflowSignal = null;
                QuarantineManagedLaunch(
                    ref process, ref job, ref gate, ref paths,
                    ref outDrainer, ref errDrainer, ref overflowSignal);
                throw ComposeCleanupException(primary, cleanupErrors.ToArray());
            }

            if (process != null)
            {
                try { process.Dispose(); }
                catch (Exception disposeError) { cleanupErrors.Add(disposeError); }
            }
            ReleaseNativeResources(gate, ref job, ref securityDescriptor, ref saBuffer, cleanupErrors);
            if (paths != null)
            {
                paths.ReleaseAndCleanup(cleanupErrors);
            }

            if (result == null && primary == null)
            {
                primary = new ContainedWorkerException("nested probe completed without producing a result.");
            }
            Exception composed = ComposeCleanupException(primary, cleanupErrors.ToArray());
            if (composed != null)
            {
                throw composed;
            }
            return result;
        }

        public static DirectLaunchSession RunDirectLaunch(ProcessLaunchConfiguration configuration)
        {
            if (configuration == null) { throw new ArgumentNullException("configuration"); }

            Dictionary<string, string> frozen = ValidateConfiguration(configuration, LauncherKind.HelperDirectLaunch);

            LaunchPathBinding paths;
            try
            {
                paths = BindLaunchPaths(configuration.ExecutablePath, configuration.ArgumentsInternal, configuration.WorkingDirectory);
            }
            catch (LaunchPathIdentityException)
            {
                RecordPathIdentityReject();
                throw;
            }

            Process process = null;
            bool started = false;
            int pid = 0;
            bool transferred = false;
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();
            DirectLaunchSession session = null;
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = paths.ExecutableFullPath;
                startInfo.Arguments = BuildCommandLine(configuration.ArgumentsInternal);
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = false;
                startInfo.RedirectStandardOutput = false;
                startInfo.RedirectStandardError = false;
                startInfo.RedirectStandardInput = false;
                startInfo.WorkingDirectory = paths.WorkingDirectoryFullPath;
                startInfo.EnvironmentVariables.Clear();
                foreach (KeyValuePair<string, string> pair in frozen)
                {
                    startInfo.EnvironmentVariables[pair.Key] = pair.Value;
                }

                process = new Process();
                process.StartInfo = startInfo;
                RecordProcessStart();
                process.Start();
                started = true;
                pid = process.Id;
                long startFileTime = ReadStartFileTime(process);
                string commandLine = QuoteWindowsCommandLineArgument(paths.ExecutableFullPath);
                if (configuration.ArgumentsInternal.Length > 0)
                {
                    commandLine = commandLine + " " + startInfo.Arguments;
                }
                session = new DirectLaunchSession(configuration.Role, process, pid, startFileTime, commandLine, paths.WorkingDirectoryFullPath);
                session.AttachPathBinding(paths);
                transferred = true;
                return session;
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }

            if (!transferred)
            {
                CleanupProof proof = ProveManagedLaunchQuiescence(
                    process, started, false, IntPtr.Zero, 15000, pid,
                    null, false, null, false, 0, cleanupErrors);
                if (proof.CanRelease)
                {
                    if (process != null)
                    {
                        try { process.Dispose(); }
                        catch (Exception disposeError) { cleanupErrors.Add(disposeError); }
                    }
                    if (paths != null)
                    {
                        paths.ReleaseAndCleanup(cleanupErrors);
                        paths = null;
                    }
                }
                else
                {
                    Exception invariant = new ContainedLaunchOwnershipQuarantinedException(
                        "direct launch cleanup could not prove process exit; ownership was quarantined.");
                    if (primary == null) { primary = invariant; }
                    else { cleanupErrors.Add(invariant); }
                    StreamDrainer outDrainer = null;
                    StreamDrainer errDrainer = null;
                    ManualResetEvent overflowSignal = null;
                    NamedEvent gate = null;
                    IntPtr job = IntPtr.Zero;
                    QuarantineManagedLaunch(
                        ref process, ref job, ref gate, ref paths,
                        ref outDrainer, ref errDrainer, ref overflowSignal);
                }
            }

            if (primary != null)
            {
                throw ComposeCleanupException(primary, cleanupErrors.ToArray());
            }
            primary = new ContainedWorkerException("direct launch completed without returning a session or surfacing a fault.");
            throw ComposeCleanupException(primary, cleanupErrors.ToArray());
        }

        public static ContainedWorkerSession RunContainedGeneratorHost(
            string hostExecutablePath,
            string[] arguments,
            string supervisorGateEventName,
            string[] reservedEnvironmentNames,
            string[] reservedEnvironmentValues,
            string workingDirectory,
            GeneratorScenario scenario)
        {
            if (!Enum.IsDefined(typeof(GeneratorScenario), scenario))
            {
                throw new ContainedWorkerException("unknown GeneratorScenario value.");
            }
            GeneratorBinding binding;
            if (scenario == GeneratorScenario.ContainedFalse)
            {
                binding = new GeneratorBinding(scenario, null, ExtractFileArgument(arguments));
            }
            else
            {
                binding = new GeneratorBinding(scenario, ExtractFileArgument(arguments), ExtractNamedArgument(arguments, "-GeneratorScriptPath"));
            }
            ProcessLaunchConfiguration configuration = CreateProcessLaunchConfiguration(
                ProcessLaunchRole.GeneratorHost, hostExecutablePath, arguments,
                scenario == GeneratorScenario.ContainedFalse ? null : supervisorGateEventName,
                GetGeneratorGateVariable(scenario),
                new string[0], new string[0], reservedEnvironmentNames, reservedEnvironmentValues,
                600000, 15000, 15000, 65536, false, Guid.Empty, workingDirectory,
                null, null, null, null, binding);
            return RunContainedGeneratorHost(configuration);
        }

        public static ContainedWorkerSession RunContainedGeneratorHost(ProcessLaunchConfiguration configuration)
        {
            if (configuration == null) { throw new ArgumentNullException("configuration"); }

            Dictionary<string, string> frozen = ValidateConfiguration(configuration, LauncherKind.ContainedGeneratorHost);
            GeneratorScenario scenario = configuration.GeneratorBinding.Scenario;
            try { ValidateGeneratorArgv(configuration); }
            catch (ProcessLaunchConfigurationException) { RecordReject(PreNativeRejectReason.Environment); throw; }
            string resultRoot = scenario == GeneratorScenario.ContainedFalse
                ? null
                : RequireReservedDirectoryRoot(configuration, EnvGeneratorResultPath, true);
            string controlRoot = scenario == GeneratorScenario.ContainedFalse
                ? null
                : RequireReservedDirectoryRoot(configuration, EnvGeneratorHardlinkRoot, true);

            LaunchPathBinding paths;
            try
            {
                paths = BindLaunchPaths(configuration.ExecutablePath, configuration.ArgumentsInternal, configuration.WorkingDirectory);
            }
            catch (LaunchPathIdentityException)
            {
                RecordPathIdentityReject();
                throw;
            }

            string commandLine = null;
            string environmentBlock = null;

            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr saBuffer = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            NamedEvent gate = null;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            bool processCreated = false;
            bool transferred = false;
            bool assignedToJob = false;
            Exception primary = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                commandLine = BuildNativeCommandLine(paths.ExecutableFullPath, configuration.ArgumentsInternal);
                environmentBlock = BuildNativeEnvironmentBlock(frozen);
                saBuffer = BuildJobSecurityAttributes(out securityDescriptor);
                job = CreateConfiguredJob(saBuffer);
                ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
                if (cleanupErrors.Count > 0)
                {
                    throw new ContainedWorkerException("generator host job security cleanup failed before process creation.");
                }
                if (scenario != GeneratorScenario.ContainedFalse)
                {
                    gate = NamedEvent.CreateNewManualReset(configuration.GateEventName, EventRole.SupervisorGate, Guid.Empty);
                }

                processInfo = CreateSuspendedProcess(paths.ExecutableFullPath, commandLine, environmentBlock, paths.WorkingDirectoryFullPath);
                processCreated = true;
                long startFileTime = GetCreationFileTime(processInfo.hProcess);
                ContainedRootIdentity rootIdentity = ContainedRootIdentity.Capture(processInfo.hProcess, processInfo.dwProcessId, startFileTime);

                RecordAssignmentAttempt();
                bool assigned = AssignProcessToJobObject(job, processInfo.hProcess);
                int assignError = assigned ? 0 : Marshal.GetLastWin32Error();
                if (!assigned && assignError == 0)
                {
                    throw new ContainedWorkerException("AssignProcessToJobObject(generator) reported failure without a Win32 error.");
                }
                if (!assigned)
                {
                    throw new ContainedWorkerException(
                        "failed to assign the suspended generator host to its job.",
                        new Win32Exception(assignError));
                }
                assignedToJob = true;
                bool inJob;
                if (!IsProcessInJob(processInfo.hProcess, job, out inJob))
                {
                    int membershipError = Marshal.GetLastWin32Error();
                    throw new ContainedWorkerException("IsProcessInJob(generator) failed.", new Win32Exception(membershipError));
                }
                if (!inJob)
                {
                    throw new ContainedWorkerException("suspended generator host job membership could not be verified.");
                }

                uint resumeReturn = ResumeThread(processInfo.hThread);
                if (resumeReturn != 1)
                {
                    int resumeError = (resumeReturn == RESUME_THREAD_FAILED) ? Marshal.GetLastWin32Error() : 0;
                    Exception resumePrimary = new ContainedWorkerException(
                        "generator host resume failed with return value " + resumeReturn.ToString(CultureInfo.InvariantCulture) + ".");
                    long active = TerminateNativeForOutcome(
                        processInfo.hProcess, processInfo.dwProcessId, true, job, 15000, resumePrimary);
                    ResumeFailureOutcome outcome = new ResumeFailureOutcome(resumeReturn, 1, resumeError, false, checked((int)active));
                    ContainedWorkerSession failedSession = new ContainedWorkerSession(
                        ContainedWorkerScenario.Normal, ProcessLaunchRole.GeneratorHost, true, scenario,
                        rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                        resultRoot, controlRoot, ContainedWorkerState.Exited, outcome,
                        new ContainedWorkerLaunchDiagnostic(ContainedWorkerScenario.Normal, ProcessLaunchRole.GeneratorHost, true, scenario, commandLine, processInfo.dwProcessId, startFileTime, true, false));
                    failedSession.AttachPathBinding(paths);
                    transferred = true;
                    return failedSession;
                }

                ContainedWorkerSession session = new ContainedWorkerSession(
                    ContainedWorkerScenario.Normal, ProcessLaunchRole.GeneratorHost, true, scenario,
                    rootIdentity, processInfo.hProcess, processInfo.hThread, job, gate,
                    resultRoot, controlRoot, ContainedWorkerState.Resumed, null,
                    new ContainedWorkerLaunchDiagnostic(ContainedWorkerScenario.Normal, ProcessLaunchRole.GeneratorHost, true, scenario, commandLine, processInfo.dwProcessId, startFileTime, true, false));
                session.AttachPathBinding(paths);
                transferred = true;
                return session;
            }
            catch (Exception unexpected)
            {
                primary = unexpected;
            }
            ReleaseJobSecurityAllocations(ref securityDescriptor, ref saBuffer, cleanupErrors);
            if (!transferred)
            {
                CleanupProof proof = ProveNativeLaunchQuiescence(
                    processCreated, processInfo, assignedToJob, job, 15000, cleanupErrors);
                if (proof.CanRelease)
                {
                    ReleasePartialNativeLaunch(
                        ref processInfo, ref job, ref gate, ref paths, cleanupErrors);
                }
                else
                {
                    Exception invariant = new ContainedLaunchOwnershipQuarantinedException(
                        "contained generator host cleanup could not prove process exit and job quiescence; ownership was quarantined.");
                    if (primary == null) { primary = invariant; }
                    else { cleanupErrors.Add(invariant); }
                    QuarantineNativeLaunch(
                        ref processInfo, ref job, ref gate, ref paths);
                }
            }

            if (primary != null)
            {
                throw ComposeCleanupException(primary, cleanupErrors.ToArray());
            }
            primary = new ContainedWorkerException("contained generator host launch completed without returning a session or surfacing a fault.");
            throw ComposeCleanupException(primary, cleanupErrors.ToArray());
        }

        public static string[] GetGeneratorArgv(GeneratorScenario scenario, string generatorScriptPath)
        {
            return GetGeneratorArgv(scenario, null, generatorScriptPath);
        }

        public static string[] GetGeneratorArgv(GeneratorScenario scenario, string bootstrapScriptPath, string generatorScriptPath)
        {
            if (generatorScriptPath == null) { throw new ArgumentNullException("generatorScriptPath"); }
            switch (scenario)
            {
                case GeneratorScenario.Normal:
                case GeneratorScenario.GateWithheld:
                    if (bootstrapScriptPath == null)
                    {
                        throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost, "GeneratorHost scenario " + scenario.ToString() + " requires the canonical validator bootstrap script path.");
                    }
                    return new string[]
                    {
                        "-NoLogo", "-NoProfile", "-NonInteractive", "-File", bootstrapScriptPath,
                        "-GeneratorBootstrap", "-GeneratorScenario", scenario.ToString(), "-GeneratorScriptPath", generatorScriptPath
                    };
                case GeneratorScenario.ContainedFalse:
                    return new string[]
                    {
                        "-NoLogo", "-NoProfile", "-NonInteractive", "-File", generatorScriptPath, "-Contained:$false", "-SelfTest"
                    };
                default:
                    throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost, "unknown GeneratorScenario value.");
            }
        }

        private static void ValidateGeneratorArgv(ProcessLaunchConfiguration configuration)
        {
            GeneratorBinding binding = configuration.GeneratorBinding;
            if (string.IsNullOrEmpty(binding.GeneratorScriptPath))
            {
                throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost, "the GeneratorBinding must carry the exact generator script path.");
            }
            if ((binding.Scenario == GeneratorScenario.Normal || binding.Scenario == GeneratorScenario.GateWithheld)
                && string.IsNullOrEmpty(binding.BootstrapScriptPath))
            {
                throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost, "GeneratorHost scenario " + binding.Scenario.ToString() + " requires the GeneratorBinding to carry the canonical validator bootstrap script path.");
            }
            string[] expected = GetGeneratorArgv(binding.Scenario, binding.BootstrapScriptPath, binding.GeneratorScriptPath);
            string[] actual = configuration.ArgumentsInternal;
            if (actual.Length != expected.Length)
            {
                throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost,
                    "GeneratorHost scenario " + binding.Scenario.ToString() + " requires exactly " + expected.Length.ToString(CultureInfo.InvariantCulture) + " argv elements.");
            }
            for (int index = 4; index < expected.Length; index++)
            {
                if (!string.Equals(actual[index], expected[index], StringComparison.Ordinal))
                {
                    throw new ProcessLaunchConfigurationException(ProcessLaunchRole.GeneratorHost,
                        "GeneratorHost scenario " + binding.Scenario.ToString() + " requires argv[" + index.ToString(CultureInfo.InvariantCulture) + "] to equal '" + expected[index] + "'.");
                }
            }
        }

        private static string ExtractFileArgument(string[] arguments)
        {
            if (arguments == null) { return null; }
            if (arguments.Length > 4 && string.Equals(arguments[3], "-File", StringComparison.Ordinal))
            {
                return arguments[4];
            }
            return null;
        }

        private static string ExtractNamedArgument(string[] arguments, string name)
        {
            if (arguments == null) { return null; }
            for (int index = 0; index < arguments.Length - 1; index++)
            {
                if (string.Equals(arguments[index], name, StringComparison.Ordinal))
                {
                    return arguments[index + 1];
                }
            }
            return null;
        }
    }
}
