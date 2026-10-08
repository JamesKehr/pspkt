using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Pspkt.Certification.Overlay
{
    internal enum OverlayBoundedProcessFault
    {
        None = 0,
        AfterCreateBeforeResume = 1
    }

    public sealed class OverlayBoundedProcessResult
    {
        private readonly int _exitCode;
        private readonly byte[] _standardErrorBytes;
        private readonly string _standardError;
        private readonly byte[] _standardOutputBytes;
        private readonly string _standardOutput;

        internal OverlayBoundedProcessResult(
            int exitCode,
            byte[] standardOutputBytes,
            byte[] standardErrorBytes,
            string standardOutput,
            string standardError)
        {
            _exitCode = exitCode;
            _standardOutputBytes = standardOutputBytes;
            _standardErrorBytes = standardErrorBytes;
            _standardOutput = standardOutput;
            _standardError = standardError;
        }

        public int ExitCode { get { return _exitCode; } }

        public byte[] StandardErrorBytes { get { return (byte[])_standardErrorBytes.Clone(); } }

        public string StandardError { get { return _standardError; } }

        public byte[] StandardOutputBytes { get { return (byte[])_standardOutputBytes.Clone(); } }

        public string StandardOutput { get { return _standardOutput; } }
    }

    public sealed class OverlayBoundedProcessSnapshot
    {
        private readonly long _activeProcessCount;
        private readonly bool _hasOutputOverflow;
        private readonly bool _isRootExited;
        private readonly bool _standardErrorComplete;
        private readonly bool _standardOutputComplete;

        internal OverlayBoundedProcessSnapshot(
            bool isRootExited,
            long activeProcessCount,
            bool standardOutputComplete,
            bool standardErrorComplete,
            bool hasOutputOverflow)
        {
            _isRootExited = isRootExited;
            _activeProcessCount = activeProcessCount;
            _standardOutputComplete = standardOutputComplete;
            _standardErrorComplete = standardErrorComplete;
            _hasOutputOverflow = hasOutputOverflow;
        }

        public long ActiveProcessCount { get { return _activeProcessCount; } }

        public bool HasOutputOverflow { get { return _hasOutputOverflow; } }

        public bool IsRootExited { get { return _isRootExited; } }

        public bool StandardErrorComplete { get { return _standardErrorComplete; } }

        public bool StandardOutputComplete { get { return _standardOutputComplete; } }
    }

    public sealed class OverlayBoundedProcessSession : IDisposable
    {
        private const uint AbortExitCode = 0xE0000001;
        private const uint WaitObject0 = 0;
        private const uint WaitTimeout = 258;

        private readonly object _stateLock = new object();
        private NativeSafeHandle _jobHandle;
        private NativeSafeHandle _processHandle;
        private RawPipeDrainer _standardErrorDrainer;
        private RawPipeDrainer _standardOutputDrainer;
        private bool _completed;
        private bool _disposed;

        internal OverlayBoundedProcessSession(
            NativeSafeHandle jobHandle,
            NativeSafeHandle processHandle,
            RawPipeDrainer standardOutputDrainer,
            RawPipeDrainer standardErrorDrainer)
        {
            _jobHandle = jobHandle;
            _processHandle = processHandle;
            _standardOutputDrainer = standardOutputDrainer;
            _standardErrorDrainer = standardErrorDrainer;
        }

        internal static uint TerminationExitCode { get { return AbortExitCode; } }

        public void Abort(int cleanupTimeoutMilliseconds)
        {
            if (cleanupTimeoutMilliseconds < 1)
            {
                throw new ArgumentOutOfRangeException("cleanupTimeoutMilliseconds");
            }

            lock (_stateLock)
            {
                if (_disposed || _completed)
                {
                    return;
                }

                Stopwatch cleanupStopwatch = Stopwatch.StartNew();
                List<Exception> failures = new List<Exception>();
                if (!_jobHandle.IsClosed && !_jobHandle.IsInvalid)
                {
                    if (!OverlayBoundedProcessNative.TerminateJobObject(
                        _jobHandle.DangerousGetHandle(),
                        AbortExitCode))
                    {
                        int terminateError = Marshal.GetLastWin32Error();
                        if (!IsProcessExited(_processHandle))
                        {
                            failures.Add(OverlayBoundedProcessNative.Win32(
                                "TerminateJobObject",
                                terminateError));
                        }
                    }
                }

                try
                {
                    WaitForProcessExit(
                        _processHandle,
                        RemainingMilliseconds(cleanupStopwatch, cleanupTimeoutMilliseconds));
                }
                catch (Exception processFailure)
                {
                    failures.Add(processFailure);
                }

                try
                {
                    PollJobUntilEmpty(
                        _jobHandle,
                        cleanupStopwatch,
                        cleanupTimeoutMilliseconds);
                }
                catch (Exception jobFailure)
                {
                    failures.Add(jobFailure);
                }

                try
                {
                    _standardOutputDrainer.Stop(
                        RemainingMilliseconds(cleanupStopwatch, cleanupTimeoutMilliseconds));
                }
                catch (Exception outputFailure)
                {
                    failures.Add(outputFailure);
                }

                try
                {
                    _standardErrorDrainer.Stop(
                        RemainingMilliseconds(cleanupStopwatch, cleanupTimeoutMilliseconds));
                }
                catch (Exception errorFailure)
                {
                    failures.Add(errorFailure);
                }

                ReleaseHandles();
                _completed = true;
                if (failures.Count > 0)
                {
                    throw new AggregateException(
                        "Overlay bounded-process cleanup failed.",
                        failures.ToArray());
                }
            }
        }

        public OverlayBoundedProcessResult Complete()
        {
            lock (_stateLock)
            {
                ThrowIfDisposed();
                if (_completed)
                {
                    throw new InvalidOperationException("Overlay bounded-process completion was already transferred.");
                }
                if (!IsProcessExited(_processHandle))
                {
                    throw new InvalidOperationException("Overlay bounded-process root is still running.");
                }
                long activeProcessCount = OverlayBoundedProcessNative.QueryActiveProcessCount(_jobHandle);
                if (activeProcessCount != 0)
                {
                    throw new InvalidOperationException(
                        "Overlay bounded-process job still has " +
                        activeProcessCount.ToString(CultureInfo.InvariantCulture) +
                        " active processes.");
                }
                if (!_standardOutputDrainer.IsComplete || !_standardErrorDrainer.IsComplete)
                {
                    throw new InvalidOperationException("Overlay bounded-process streams are not complete.");
                }
                if (_standardOutputDrainer.HasOverflow || _standardErrorDrainer.HasOverflow)
                {
                    throw new InvalidDataException("Overlay bounded-process output exceeded its byte cap.");
                }

                byte[] standardOutputBytes = _standardOutputDrainer.GetRetainedBytes();
                byte[] standardErrorBytes = _standardErrorDrainer.GetRetainedBytes();
                string standardOutput = DecodeStrictUtf8(standardOutputBytes, "standard output");
                string standardError = DecodeStrictUtf8(standardErrorBytes, "standard error");
                uint rawExitCode = QueryProcessExitCode(_processHandle);

                ReleaseHandles();
                _completed = true;
                return new OverlayBoundedProcessResult(
                    unchecked((int)rawExitCode),
                    standardOutputBytes,
                    standardErrorBytes,
                    standardOutput,
                    standardError);
            }
        }

        public void Dispose()
        {
            lock (_stateLock)
            {
                if (_disposed)
                {
                    return;
                }
                List<Exception> cleanupFailures = new List<Exception>();
                try
                {
                    Abort(15000);
                }
                catch (Exception failure)
                {
                    cleanupFailures.Add(failure);
                }
                if (_standardOutputDrainer != null)
                {
                    try
                    {
                        _standardOutputDrainer.Dispose();
                        _standardOutputDrainer = null;
                    }
                    catch (Exception failure) { cleanupFailures.Add(failure); }
                }
                if (_standardErrorDrainer != null)
                {
                    try
                    {
                        _standardErrorDrainer.Dispose();
                        _standardErrorDrainer = null;
                    }
                    catch (Exception failure) { cleanupFailures.Add(failure); }
                }
                if (_processHandle != null)
                {
                    _processHandle.Dispose();
                    _processHandle = null;
                }
                if (_jobHandle != null)
                {
                    _jobHandle.Dispose();
                    _jobHandle = null;
                }
                if (cleanupFailures.Count > 0)
                {
                    throw new AggregateException(
                        "Overlay bounded-process disposal failed.",
                        cleanupFailures.ToArray());
                }
                _disposed = true;
            }
        }

        public OverlayBoundedProcessSnapshot Poll()
        {
            lock (_stateLock)
            {
                ThrowIfUnavailable();
                return new OverlayBoundedProcessSnapshot(
                    IsProcessExited(_processHandle),
                    OverlayBoundedProcessNative.QueryActiveProcessCount(_jobHandle),
                    _standardOutputDrainer.IsComplete,
                    _standardErrorDrainer.IsComplete,
                    _standardOutputDrainer.HasOverflow || _standardErrorDrainer.HasOverflow);
            }
        }

        public bool WaitSlice(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0 || timeoutMilliseconds > 100)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }

            lock (_stateLock)
            {
                ThrowIfUnavailable();
                uint waitStatus = OverlayBoundedProcessNative.WaitForSingleObject(
                    _processHandle.DangerousGetHandle(),
                    (uint)timeoutMilliseconds);
                if (waitStatus == WaitObject0)
                {
                    return true;
                }
                if (waitStatus == WaitTimeout)
                {
                    return false;
                }
                throw OverlayBoundedProcessNative.Win32(
                    "WaitForSingleObject",
                    Marshal.GetLastWin32Error());
            }
        }

        private static string DecodeStrictUtf8(byte[] bytes, string streamName)
        {
            if (bytes.Length >= 3 &&
                bytes[0] == 0xEF &&
                bytes[1] == 0xBB &&
                bytes[2] == 0xBF)
            {
                throw new InvalidDataException(
                    "Overlay bounded-process " + streamName + " contains a UTF-8 byte-order mark.");
            }
            try
            {
                return new UTF8Encoding(false, true).GetString(bytes);
            }
            catch (DecoderFallbackException error)
            {
                int diagnosticLength = Math.Min(bytes.Length, 4096);
                string diagnostic = Encoding.UTF8.GetString(bytes, 0, diagnosticLength);
                throw new InvalidDataException(
                    "Overlay bounded-process " + streamName +
                    " is not strict UTF-8. Lossy diagnostic: " + diagnostic,
                    error);
            }
        }

        private static bool IsProcessExited(NativeSafeHandle processHandle)
        {
            uint waitStatus = OverlayBoundedProcessNative.WaitForSingleObject(
                processHandle.DangerousGetHandle(),
                0);
            if (waitStatus == WaitObject0)
            {
                return true;
            }
            if (waitStatus == WaitTimeout)
            {
                return false;
            }
            throw OverlayBoundedProcessNative.Win32(
                "WaitForSingleObject",
                Marshal.GetLastWin32Error());
        }

        private static void PollJobUntilEmpty(
            NativeSafeHandle jobHandle,
            Stopwatch stopwatch,
            int timeoutMilliseconds)
        {
            while (OverlayBoundedProcessNative.QueryActiveProcessCount(jobHandle) != 0)
            {
                int remainingMilliseconds = RemainingMilliseconds(stopwatch, timeoutMilliseconds);
                if (remainingMilliseconds == 0)
                {
                    throw new TimeoutException("Overlay bounded-process job did not become empty.");
                }
                Thread.Sleep(Math.Min(25, remainingMilliseconds));
            }
        }

        private static uint QueryProcessExitCode(NativeSafeHandle processHandle)
        {
            uint exitCode;
            if (!OverlayBoundedProcessNative.GetExitCodeProcess(
                processHandle.DangerousGetHandle(),
                out exitCode))
            {
                throw OverlayBoundedProcessNative.Win32(
                    "GetExitCodeProcess",
                    Marshal.GetLastWin32Error());
            }
            return exitCode;
        }

        private static int RemainingMilliseconds(Stopwatch stopwatch, int timeoutMilliseconds)
        {
            long remaining = timeoutMilliseconds - stopwatch.ElapsedMilliseconds;
            if (remaining <= 0)
            {
                return 0;
            }
            return remaining > int.MaxValue ? int.MaxValue : (int)remaining;
        }

        private static void WaitForProcessExit(
            NativeSafeHandle processHandle,
            int timeoutMilliseconds)
        {
            uint waitStatus = OverlayBoundedProcessNative.WaitForSingleObject(
                processHandle.DangerousGetHandle(),
                (uint)timeoutMilliseconds);
            if (waitStatus == WaitObject0)
            {
                return;
            }
            if (waitStatus == WaitTimeout)
            {
                throw new TimeoutException("Overlay bounded-process root did not exit during cleanup.");
            }
            throw OverlayBoundedProcessNative.Win32(
                "WaitForSingleObject",
                Marshal.GetLastWin32Error());
        }

        private void ReleaseHandles()
        {
            if (_processHandle != null && !_processHandle.IsClosed)
            {
                _processHandle.Dispose();
            }
            if (_jobHandle != null && !_jobHandle.IsClosed)
            {
                _jobHandle.Dispose();
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(typeof(OverlayBoundedProcessSession).FullName);
            }
        }

        private void ThrowIfUnavailable()
        {
            ThrowIfDisposed();
            if (_completed)
            {
                throw new InvalidOperationException("Overlay bounded-process ownership is already complete.");
            }
        }
    }

    public static class OverlayBoundedProcess
    {
        public const string Version = "pspkt-overlay-bounded-process-1";
        private static readonly object s_testIdentityLock = new object();
        private static long s_testProcessCreationTimeFileTimeUtc;
        private static int s_testProcessId;
        private static NativeSafeHandle s_testRetainedProcessHandle;

        public static OverlayBoundedProcessSession Start(
            string executablePath,
            string[] arguments,
            string workingDirectory,
            string[] environmentNames,
            string[] environmentValues,
            int retainCapBytes)
        {
            return StartCore(
                executablePath,
                arguments,
                workingDirectory,
                environmentNames,
                environmentValues,
                retainCapBytes,
                OverlayBoundedProcessFault.None,
                0);
        }

        internal static OverlayBoundedProcessSession StartForTest(
            string executablePath,
            string[] arguments,
            string workingDirectory,
            string[] environmentNames,
            string[] environmentValues,
            int retainCapBytes,
            OverlayBoundedProcessFault fault,
            int outsideWriterProcessId)
        {
            return StartCore(
                executablePath,
                arguments,
                workingDirectory,
                environmentNames,
                environmentValues,
                retainCapBytes,
                fault,
                outsideWriterProcessId);
        }

        private static OverlayBoundedProcessSession StartCore(
            string executablePath,
            string[] arguments,
            string workingDirectory,
            string[] environmentNames,
            string[] environmentValues,
            int retainCapBytes,
            OverlayBoundedProcessFault fault,
            int outsideWriterProcessId)
        {
            ValidateStartArguments(
                executablePath,
                arguments,
                workingDirectory,
                environmentNames,
                environmentValues,
                retainCapBytes,
                fault,
                outsideWriterProcessId);

            OverlayBoundedProcessSession returnedSession = null;
            NativeSafeHandle jobHandle = null;
            NativeSafeHandle processHandle = null;
            NativeSafeHandle threadHandle = null;
            NativeSafeHandle standardOutputReadHandle = null;
            NativeSafeHandle standardOutputWriteHandle = null;
            NativeSafeHandle standardErrorReadHandle = null;
            NativeSafeHandle standardErrorWriteHandle = null;
            NativeSafeHandle standardInputHandle = null;
            RawPipeDrainer standardOutputDrainer = null;
            RawPipeDrainer standardErrorDrainer = null;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr jobAttributeValue = IntPtr.Zero;
            IntPtr handleListAttributeValue = IntPtr.Zero;
            IntPtr desktopPolicyAttributeValue = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            bool processCreated = false;
            bool ownershipTransferred = false;
            Exception primaryFailure = null;
            List<Exception> cleanupFailures = new List<Exception>();

            try
            {
                OverlayBoundedProcessNative.AssertAbi();
                jobHandle = OverlayBoundedProcessNative.CreateConfiguredJob();
                OverlayBoundedProcessNative.CreateRedirectedPipe(
                    out standardOutputReadHandle,
                    out standardOutputWriteHandle);
                OverlayBoundedProcessNative.CreateRedirectedPipe(
                    out standardErrorReadHandle,
                    out standardErrorWriteHandle);
                standardInputHandle = OverlayBoundedProcessNative.OpenInheritedNullInput();

                if (outsideWriterProcessId != 0)
                {
                    OverlayBoundedProcessNative.DuplicateIntoProcess(
                        standardOutputWriteHandle,
                        outsideWriterProcessId);
                }

                attributeList = OverlayBoundedProcessNative.CreateAttributeList(3);
                jobAttributeValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobAttributeValue, jobHandle.DangerousGetHandle());
                OverlayBoundedProcessNative.UpdateAttribute(
                    attributeList,
                    OverlayBoundedProcessNative.ProcThreadAttributeJobList,
                    jobAttributeValue,
                    new IntPtr(IntPtr.Size));

                handleListAttributeValue = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(
                    handleListAttributeValue,
                    0,
                    standardOutputWriteHandle.DangerousGetHandle());
                Marshal.WriteIntPtr(
                    handleListAttributeValue,
                    IntPtr.Size,
                    standardErrorWriteHandle.DangerousGetHandle());
                Marshal.WriteIntPtr(
                    handleListAttributeValue,
                    IntPtr.Size * 2,
                    standardInputHandle.DangerousGetHandle());
                OverlayBoundedProcessNative.UpdateAttribute(
                    attributeList,
                    OverlayBoundedProcessNative.ProcThreadAttributeHandleList,
                    handleListAttributeValue,
                    new IntPtr(IntPtr.Size * 3));

                desktopPolicyAttributeValue = Marshal.AllocHGlobal(sizeof(uint));
                Marshal.WriteInt32(
                    desktopPolicyAttributeValue,
                    unchecked((int)OverlayBoundedProcessNative.DisableProcessTree));
                OverlayBoundedProcessNative.UpdateAttribute(
                    attributeList,
                    OverlayBoundedProcessNative.ProcThreadAttributeDesktopAppPolicy,
                    desktopPolicyAttributeValue,
                    new IntPtr(sizeof(uint)));

                string commandLine = OverlayBoundedProcessNative.BuildCommandLine(
                    executablePath,
                    arguments);
                environmentBlock = OverlayBoundedProcessNative.BuildEnvironmentBlock(
                    environmentNames,
                    environmentValues);
                OverlayBoundedProcessNative.PROCESS_INFORMATION processInformation;
                OverlayBoundedProcessNative.CreateContainedProcess(
                    executablePath,
                    commandLine,
                    workingDirectory,
                    environmentBlock,
                    attributeList,
                    standardInputHandle,
                    standardOutputWriteHandle,
                    standardErrorWriteHandle,
                    out processInformation);
                processCreated = true;
                processHandle = new NativeSafeHandle(processInformation.hProcess, true);
                threadHandle = new NativeSafeHandle(processInformation.hThread, true);
                if (fault != OverlayBoundedProcessFault.None)
                {
                    lock (s_testIdentityLock)
                    {
                        if (s_testRetainedProcessHandle != null)
                        {
                            s_testRetainedProcessHandle.Dispose();
                        }
                        s_testProcessId = processInformation.dwProcessId;
                        s_testProcessCreationTimeFileTimeUtc =
                            OverlayBoundedProcessNative.GetCreationTime(
                                processHandle);
                        s_testRetainedProcessHandle =
                            OverlayBoundedProcessNative.DuplicateLocalHandle(
                                processHandle);
                    }
                }

                standardOutputWriteHandle.Dispose();
                standardErrorWriteHandle.Dispose();
                standardInputHandle.Dispose();

                if (fault == OverlayBoundedProcessFault.AfterCreateBeforeResume)
                {
                    throw new InvalidOperationException("Injected overlay bounded-process failure after process creation.");
                }

                if (!OverlayBoundedProcessNative.IsInJob(processHandle, jobHandle))
                {
                    OverlayBoundedProcessNative.TerminateProcessDirect(
                        processHandle,
                        OverlayBoundedProcessSession.TerminationExitCode);
                    throw new InvalidOperationException("Overlay bounded-process root was not created in its job.");
                }

                standardOutputDrainer = new RawPipeDrainer(
                    standardOutputReadHandle,
                    retainCapBytes,
                    "standard output");
                standardOutputReadHandle = null;
                standardErrorDrainer = new RawPipeDrainer(
                    standardErrorReadHandle,
                    retainCapBytes,
                    "standard error");
                standardErrorReadHandle = null;
                standardOutputDrainer.Start();
                standardErrorDrainer.Start();

                uint priorSuspendCount = OverlayBoundedProcessNative.ResumeThread(
                    threadHandle.DangerousGetHandle());
                if (priorSuspendCount == uint.MaxValue)
                {
                    throw OverlayBoundedProcessNative.Win32(
                        "ResumeThread",
                        Marshal.GetLastWin32Error());
                }
                if (priorSuspendCount != 1)
                {
                    throw new InvalidOperationException(
                        "Overlay bounded-process primary thread had an unexpected suspend count.");
                }
                threadHandle.Dispose();
                threadHandle = null;

                returnedSession = new OverlayBoundedProcessSession(
                    jobHandle,
                    processHandle,
                    standardOutputDrainer,
                    standardErrorDrainer);
                jobHandle = null;
                processHandle = null;
                standardOutputDrainer = null;
                standardErrorDrainer = null;
                ownershipTransferred = true;
            }
            catch (Exception failure)
            {
                primaryFailure = failure;
            }
            finally
            {
                if (!ownershipTransferred)
                {
                    if (processCreated && processHandle != null && !processHandle.IsClosed)
                    {
                        try
                        {
                            OverlayBoundedProcessNative.TerminateProcessDirect(
                                processHandle,
                                OverlayBoundedProcessSession.TerminationExitCode);
                        }
                        catch (Exception terminationFailure)
                        {
                            cleanupFailures.Add(terminationFailure);
                        }
                    }
                    if (jobHandle != null && !jobHandle.IsClosed)
                    {
                        try
                        {
                            OverlayBoundedProcessNative.TerminateJobObject(
                                jobHandle.DangerousGetHandle(),
                                OverlayBoundedProcessSession.TerminationExitCode);
                        }
                        catch (Exception terminationFailure)
                        {
                            cleanupFailures.Add(terminationFailure);
                        }
                    }
                    if (standardOutputDrainer != null)
                    {
                        try { standardOutputDrainer.Stop(15000); }
                        catch (Exception drainFailure) { cleanupFailures.Add(drainFailure); }
                    }
                    if (standardErrorDrainer != null)
                    {
                        try { standardErrorDrainer.Stop(15000); }
                        catch (Exception drainFailure) { cleanupFailures.Add(drainFailure); }
                    }
                }

                if (attributeList != IntPtr.Zero)
                {
                    OverlayBoundedProcessNative.DeleteProcThreadAttributeList(
                        attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (jobAttributeValue != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(jobAttributeValue);
                }
                if (handleListAttributeValue != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(handleListAttributeValue);
                }
                if (desktopPolicyAttributeValue != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(desktopPolicyAttributeValue);
                }
                if (environmentBlock != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(environmentBlock);
                }
                if (threadHandle != null)
                {
                    threadHandle.Dispose();
                }
                if (standardInputHandle != null)
                {
                    standardInputHandle.Dispose();
                }
                if (standardOutputWriteHandle != null)
                {
                    standardOutputWriteHandle.Dispose();
                }
                if (standardErrorWriteHandle != null)
                {
                    standardErrorWriteHandle.Dispose();
                }
                if (standardOutputReadHandle != null)
                {
                    standardOutputReadHandle.Dispose();
                }
                if (standardErrorReadHandle != null)
                {
                    standardErrorReadHandle.Dispose();
                }
                if (standardOutputDrainer != null)
                {
                    try { standardOutputDrainer.Dispose(); }
                    catch (Exception disposeFailure) { cleanupFailures.Add(disposeFailure); }
                }
                if (standardErrorDrainer != null)
                {
                    try { standardErrorDrainer.Dispose(); }
                    catch (Exception disposeFailure) { cleanupFailures.Add(disposeFailure); }
                }
                if (processHandle != null)
                {
                    processHandle.Dispose();
                }
                if (jobHandle != null)
                {
                    jobHandle.Dispose();
                }
            }

            if (primaryFailure != null || cleanupFailures.Count > 0)
            {
                if (cleanupFailures.Count > 0)
                {
                    if (primaryFailure != null)
                    {
                        cleanupFailures.Insert(0, primaryFailure);
                    }
                    throw new AggregateException(
                        "Overlay bounded-process startup failed.",
                        cleanupFailures.ToArray());
                }
                ExceptionDispatchInfo.Capture(primaryFailure).Throw();
                throw new InvalidOperationException(
                    "Overlay bounded-process startup failure did not propagate.");
            }
            return returnedSession;
        }

        private static void ValidateStartArguments(
            string executablePath,
            string[] arguments,
            string workingDirectory,
            string[] environmentNames,
            string[] environmentValues,
            int retainCapBytes,
            OverlayBoundedProcessFault fault,
            int outsideWriterProcessId)
        {
            if (string.IsNullOrEmpty(executablePath))
            {
                throw new ArgumentException("An executable path is required.", "executablePath");
            }
            RequireFullyQualifiedPath(executablePath, "executablePath");
            if (arguments == null)
            {
                throw new ArgumentNullException("arguments");
            }
            if (string.IsNullOrEmpty(workingDirectory))
            {
                throw new ArgumentException("A working directory is required.", "workingDirectory");
            }
            RequireFullyQualifiedPath(workingDirectory, "workingDirectory");
            if (environmentNames == null)
            {
                throw new ArgumentNullException("environmentNames");
            }
            if (environmentValues == null)
            {
                throw new ArgumentNullException("environmentValues");
            }
            if (environmentNames.Length != environmentValues.Length)
            {
                throw new ArgumentException("Environment name and value arrays differ in length.");
            }
            if (retainCapBytes < 1)
            {
                throw new ArgumentOutOfRangeException("retainCapBytes");
            }
            if (!Enum.IsDefined(typeof(OverlayBoundedProcessFault), fault))
            {
                throw new ArgumentOutOfRangeException("fault");
            }
            if (outsideWriterProcessId < 0)
            {
                throw new ArgumentOutOfRangeException("outsideWriterProcessId");
            }
        }

        private static void RequireFullyQualifiedPath(string path, string parameterName)
        {
            bool driveQualified = path.Length >= 3 &&
                char.IsLetter(path[0]) &&
                path[1] == ':' &&
                (path[2] == Path.DirectorySeparatorChar ||
                    path[2] == Path.AltDirectorySeparatorChar);
            bool uncQualified = path.Length >= 3 &&
                path[0] == Path.DirectorySeparatorChar &&
                path[1] == Path.DirectorySeparatorChar &&
                path[2] != Path.DirectorySeparatorChar;
            string normalizedPath;
            try
            {
                normalizedPath = Path.GetFullPath(path);
            }
            catch (Exception error)
            {
                throw new ArgumentException(
                    "The path must be fully qualified and normalized.",
                    parameterName,
                    error);
            }
            if ((!driveQualified && !uncQualified) ||
                !string.Equals(path, normalizedPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "The path must be fully qualified and normalized.",
                    parameterName);
            }
        }

        internal static long[] GetLastTestProcessIdentity()
        {
            lock (s_testIdentityLock)
            {
                return new long[]
                {
                    s_testProcessId,
                    s_testProcessCreationTimeFileTimeUtc
                };
            }
        }

        internal static bool WaitLastTestProcessExit(int timeoutMilliseconds)
        {
            lock (s_testIdentityLock)
            {
                if (s_testRetainedProcessHandle == null)
                {
                    throw new InvalidOperationException(
                        "No overlay bounded-process test handle is retained.");
                }
                uint waitStatus = OverlayBoundedProcessNative.WaitForSingleObject(
                    s_testRetainedProcessHandle.DangerousGetHandle(),
                    (uint)timeoutMilliseconds);
                bool exited = waitStatus == 0;
                if (!exited && waitStatus != 258)
                {
                    throw OverlayBoundedProcessNative.Win32(
                        "WaitForSingleObject",
                        Marshal.GetLastWin32Error());
                }
                s_testRetainedProcessHandle.Dispose();
                s_testRetainedProcessHandle = null;
                return exited;
            }
        }
    }

    internal static class OverlayBoundedProcessTestHooks
    {
        internal static IDisposable EnterActiveProcessLimitOneJob()
        {
            return OverlayBoundedProcessNative.EnterActiveProcessLimitOneJob();
        }

        internal static long[] GetLastStartedProcessIdentity()
        {
            return OverlayBoundedProcess.GetLastTestProcessIdentity();
        }

        internal static bool WaitLastStartedProcessExit(int timeoutMilliseconds)
        {
            return OverlayBoundedProcess.WaitLastTestProcessExit(
                timeoutMilliseconds);
        }
    }

    internal sealed class NativeSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal NativeSafeHandle()
            : base(true)
        {
        }

        internal NativeSafeHandle(IntPtr handleValue, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(handleValue);
        }

        protected override bool ReleaseHandle()
        {
            return OverlayBoundedProcessNative.CloseHandle(handle);
        }
    }

    internal sealed class RawPipeDrainer : IDisposable
    {
        private const int ErrorBrokenPipe = 109;
        private const int ErrorOperationAborted = 995;
        private const uint ThreadTerminate = 0x0001;

        private readonly ManualResetEvent _ready = new ManualResetEvent(false);
        private readonly object _stateLock = new object();
        private readonly int _retainCapBytes;
        private readonly string _streamName;
        private readonly MemoryStream _retainedBytes = new MemoryStream();
        private NativeSafeHandle _readHandle;
        private NativeSafeHandle _threadHandle;
        private Thread _thread;
        private Exception _failure;
        private bool _complete;
        private bool _disposed;
        private bool _overflow;
        private bool _stopRequested;

        internal RawPipeDrainer(
            NativeSafeHandle readHandle,
            int retainCapBytes,
            string streamName)
        {
            _readHandle = readHandle;
            _retainCapBytes = retainCapBytes;
            _streamName = streamName;
        }

        internal bool HasOverflow
        {
            get
            {
                lock (_stateLock)
                {
                    return _overflow;
                }
            }
        }

        internal bool IsComplete
        {
            get
            {
                lock (_stateLock)
                {
                    return _complete;
                }
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            Exception stopFailure = null;
            try
            {
                Stop(15000);
            }
            catch (Exception failure)
            {
                bool threadAlive;
                lock (_stateLock)
                {
                    threadAlive = _thread != null && _thread.IsAlive;
                }
                if (threadAlive)
                {
                    throw;
                }
                stopFailure = failure;
            }
            _ready.Dispose();
            _retainedBytes.Dispose();
            if (_threadHandle != null)
            {
                _threadHandle.Dispose();
                _threadHandle = null;
            }
            if (_readHandle != null)
            {
                _readHandle.Dispose();
                _readHandle = null;
            }
            _disposed = true;
            if (stopFailure != null)
            {
                ExceptionDispatchInfo.Capture(stopFailure).Throw();
                throw new InvalidOperationException(
                    "Overlay bounded-process drainer failure did not propagate.");
            }
        }

        internal byte[] GetRetainedBytes()
        {
            lock (_stateLock)
            {
                if (!_complete)
                {
                    throw new InvalidOperationException(
                        "Overlay bounded-process " + _streamName + " drainer is not complete.");
                }
                if (_failure != null)
                {
                    throw new IOException(
                        "Overlay bounded-process " + _streamName + " drainer failed.",
                        _failure);
                }
                return _retainedBytes.ToArray();
            }
        }

        internal void Start()
        {
            lock (_stateLock)
            {
                if (_thread != null)
                {
                    throw new InvalidOperationException(
                        "Overlay bounded-process " + _streamName + " drainer was already started.");
                }
                _thread = new Thread(ReadLoop);
                _thread.IsBackground = true;
                _thread.Name = "Pspkt overlay " + _streamName + " drainer";
                _thread.Start();
            }
            if (!_ready.WaitOne(5000))
            {
                throw new TimeoutException(
                    "Overlay bounded-process " + _streamName + " drainer did not initialize.");
            }
        }

        internal void Stop(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }

            Thread thread;
            lock (_stateLock)
            {
                _stopRequested = true;
                thread = _thread;
            }
            if (thread == null)
            {
                return;
            }

            Stopwatch stopwatch = Stopwatch.StartNew();
            while (thread.IsAlive)
            {
                NativeSafeHandle threadHandle;
                lock (_stateLock)
                {
                    threadHandle = _threadHandle;
                }
                if (threadHandle != null &&
                    !threadHandle.IsClosed &&
                    !threadHandle.IsInvalid &&
                    !OverlayBoundedProcessNative.CancelSynchronousIo(
                        threadHandle.DangerousGetHandle()))
                {
                    int cancelError = Marshal.GetLastWin32Error();
                    if (cancelError != 1168)
                    {
                        throw OverlayBoundedProcessNative.Win32(
                            "CancelSynchronousIo",
                            cancelError);
                    }
                }

                int remainingMilliseconds = timeoutMilliseconds - (int)Math.Min(
                    timeoutMilliseconds,
                    stopwatch.ElapsedMilliseconds);
                if (remainingMilliseconds <= 0)
                {
                    throw new TimeoutException(
                        "Overlay bounded-process " + _streamName +
                        " drainer did not stop.");
                }
                thread.Join(Math.Min(25, remainingMilliseconds));
            }

            lock (_stateLock)
            {
                if (_failure != null)
                {
                    throw new IOException(
                        "Overlay bounded-process " + _streamName +
                        " drainer failed.",
                        _failure);
                }
            }
        }

        private void ReadLoop()
        {
            NativeSafeHandle localThreadHandle = null;
            try
            {
                localThreadHandle = OverlayBoundedProcessNative.OpenThread(
                    ThreadTerminate,
                    false,
                    OverlayBoundedProcessNative.GetCurrentThreadId());
                if (localThreadHandle == null || localThreadHandle.IsInvalid)
                {
                    throw OverlayBoundedProcessNative.Win32(
                        "OpenThread",
                        Marshal.GetLastWin32Error());
                }
                lock (_stateLock)
                {
                    _threadHandle = localThreadHandle;
                    localThreadHandle = null;
                }
                _ready.Set();

                byte[] buffer = new byte[4096];
                while (true)
                {
                    lock (_stateLock)
                    {
                        if (_stopRequested)
                        {
                            break;
                        }
                    }

                    int bytesRead;
                    bool read = OverlayBoundedProcessNative.ReadFile(
                        _readHandle.DangerousGetHandle(),
                        buffer,
                        buffer.Length,
                        out bytesRead,
                        IntPtr.Zero);
                    if (!read)
                    {
                        int readError = Marshal.GetLastWin32Error();
                        bool stopping;
                        lock (_stateLock)
                        {
                            stopping = _stopRequested;
                        }
                        if (readError == ErrorBrokenPipe ||
                            (readError == ErrorOperationAborted && stopping))
                        {
                            break;
                        }
                        throw OverlayBoundedProcessNative.Win32(
                            "ReadFile",
                            readError);
                    }
                    if (bytesRead == 0)
                    {
                        break;
                    }

                    lock (_stateLock)
                    {
                        int remainingCapacity = _retainCapBytes - (int)_retainedBytes.Length;
                        if (remainingCapacity > 0)
                        {
                            int retainedCount = Math.Min(remainingCapacity, bytesRead);
                            _retainedBytes.Write(buffer, 0, retainedCount);
                        }
                        if (bytesRead > remainingCapacity)
                        {
                            _overflow = true;
                        }
                    }
                }
            }
            catch (Exception failure)
            {
                lock (_stateLock)
                {
                    _failure = failure;
                }
                _ready.Set();
            }
            finally
            {
                if (localThreadHandle != null)
                {
                    localThreadHandle.Dispose();
                }
                lock (_stateLock)
                {
                    _complete = true;
                }
                _ready.Set();
            }
        }
    }

    internal static class OverlayBoundedProcessNative
    {
        internal const uint DisableProcessTree = 0x00000002;
        internal static readonly IntPtr ProcThreadAttributeDesktopAppPolicy = new IntPtr(0x00020012);
        internal static readonly IntPtr ProcThreadAttributeHandleList = new IntPtr(0x00020002);
        internal static readonly IntPtr ProcThreadAttributeJobList = new IntPtr(0x0002000D);

        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint DuplicateSameAccess = 0x00000002;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint GenericRead = 0x80000000;
        private const uint HandleFlagInherit = 0x00000001;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const uint JobObjectLimitActiveProcess = 0x00000008;
        private const uint OpenExisting = 3;
        private const uint ProcessDuplicateHandle = 0x00000040;
        private const uint StartfUseStdHandles = 0x00000100;

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal int dwProcessId;
            internal int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            internal long TotalUserTime;
            internal long TotalKernelTime;
            internal long ThisPeriodTotalUserTime;
            internal long ThisPeriodTotalKernelTime;
            internal uint TotalPageFaultCount;
            internal uint TotalProcesses;
            internal uint ActiveProcesses;
            internal uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal IntPtr MinimumWorkingSetSize;
            internal IntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal IntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            internal IO_COUNTERS IoInfo;
            internal IntPtr ProcessMemoryLimit;
            internal IntPtr JobMemoryLimit;
            internal IntPtr PeakProcessMemoryUsed;
            internal IntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            internal int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal int dwX;
            internal int dwY;
            internal int dwXSize;
            internal int dwYSize;
            internal int dwXCountChars;
            internal int dwYCountChars;
            internal int dwFillAttribute;
            internal uint dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX
        {
            internal STARTUPINFO StartupInfo;
            internal IntPtr lpAttributeList;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(
            IntPtr jobHandle,
            IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CancelSynchronousIo(IntPtr threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            ref SECURITY_ATTRIBUTES securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(
            IntPtr jobAttributes,
            string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out IntPtr readPipe,
            out IntPtr writePipe,
            ref SECURITY_ATTRIBUTES pipeAttributes,
            uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll")]
        internal static extern void DeleteProcThreadAttributeList(
            IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateHandle(
            IntPtr sourceProcessHandle,
            IntPtr sourceHandle,
            IntPtr targetProcessHandle,
            out IntPtr targetHandle,
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetExitCodeProcess(
            IntPtr processHandle,
            out uint exitCode);

        [DllImport("kernel32.dll")]
        internal static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(
            IntPtr processHandle,
            out long creationTime,
            out long exitTime,
            out long kernelTime,
            out long userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            uint flags,
            ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessInJob(
            IntPtr processHandle,
            IntPtr jobHandle,
            [MarshalAs(UnmanagedType.Bool)] out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern NativeSafeHandle OpenThread(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr jobHandle,
            int informationClass,
            IntPtr information,
            uint informationLength,
            out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ReadFile(
            IntPtr fileHandle,
            byte[] buffer,
            int numberOfBytesToRead,
            out int numberOfBytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(
            IntPtr handle,
            uint mask,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr jobHandle,
            int informationClass,
            IntPtr information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateJobObject(
            IntPtr jobHandle,
            uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(
            IntPtr processHandle,
            uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(
            IntPtr handle,
            uint milliseconds);

        internal static void AssertAbi()
        {
            int expectedBasicLimitSize = IntPtr.Size == 8 ? 64 : 48;
            int expectedExtendedLimitSize = IntPtr.Size == 8 ? 144 : 112;
            int expectedProcessInformationSize = IntPtr.Size == 8 ? 24 : 16;
            int expectedSecurityAttributesSize = IntPtr.Size == 8 ? 24 : 12;
            int expectedStartupInfoExSize = IntPtr.Size == 8 ? 112 : 72;
            if (Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)) != 48 ||
                Marshal.SizeOf(typeof(JOBOBJECT_BASIC_LIMIT_INFORMATION)) != expectedBasicLimitSize ||
                Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) != expectedExtendedLimitSize ||
                Marshal.SizeOf(typeof(PROCESS_INFORMATION)) != expectedProcessInformationSize ||
                Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)) != expectedSecurityAttributesSize ||
                Marshal.SizeOf(typeof(STARTUPINFOEX)) != expectedStartupInfoExSize)
            {
                throw new PlatformNotSupportedException("Overlay bounded-process native ABI differs.");
            }
        }

        internal static IntPtr BuildEnvironmentBlock(
            string[] environmentNames,
            string[] environmentValues)
        {
            SortedDictionary<string, string> environment =
                new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int index = 0; index < environmentNames.Length; index++)
            {
                string name = environmentNames[index];
                string value = environmentValues[index];
                if (string.IsNullOrEmpty(name) ||
                    name.IndexOf('=') >= 0 ||
                    name.IndexOf('\0') >= 0)
                {
                    throw new ArgumentException("An environment name is invalid.", "environmentNames");
                }
                if (value == null || value.IndexOf('\0') >= 0)
                {
                    throw new ArgumentException("An environment value is invalid.", "environmentValues");
                }
                if (environment.ContainsKey(name))
                {
                    throw new ArgumentException(
                        "Environment names differ only by case: " + name,
                        "environmentNames");
                }
                environment.Add(name, value);
            }

            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> pair in environment)
            {
                block.Append(pair.Key);
                block.Append('=');
                block.Append(pair.Value);
                block.Append('\0');
            }
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        internal static string BuildCommandLine(
            string executablePath,
            string[] arguments)
        {
            StringBuilder commandLine = new StringBuilder();
            AppendQuotedArgument(commandLine, executablePath);
            for (int index = 0; index < arguments.Length; index++)
            {
                if (arguments[index] == null)
                {
                    throw new ArgumentException("A process argument is null.", "arguments");
                }
                commandLine.Append(' ');
                AppendQuotedArgument(commandLine, arguments[index]);
            }
            if (commandLine.Length >= 32767)
            {
                throw new ArgumentException("The process command line is too large.", "arguments");
            }
            return commandLine.ToString();
        }

        internal static IntPtr CreateAttributeList(int attributeCount)
        {
            IntPtr requiredSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(
                IntPtr.Zero,
                attributeCount,
                0,
                ref requiredSize);
            int firstError = Marshal.GetLastWin32Error();
            if (requiredSize == IntPtr.Zero || firstError != 122)
            {
                throw Win32("InitializeProcThreadAttributeList(size)", firstError);
            }
            IntPtr attributeList = Marshal.AllocHGlobal(requiredSize);
            if (!InitializeProcThreadAttributeList(
                attributeList,
                attributeCount,
                0,
                ref requiredSize))
            {
                int initializeError = Marshal.GetLastWin32Error();
                Marshal.FreeHGlobal(attributeList);
                throw Win32(
                    "InitializeProcThreadAttributeList",
                    initializeError);
            }
            return attributeList;
        }

        internal static NativeSafeHandle CreateConfiguredJob()
        {
            return CreateConfiguredJob(JobObjectLimitKillOnJobClose, 0);
        }

        internal static void CreateContainedProcess(
            string executablePath,
            string commandLine,
            string workingDirectory,
            IntPtr environmentBlock,
            IntPtr attributeList,
            NativeSafeHandle standardInputHandle,
            NativeSafeHandle standardOutputHandle,
            NativeSafeHandle standardErrorHandle,
            out PROCESS_INFORMATION processInformation)
        {
            STARTUPINFOEX startupInfo = new STARTUPINFOEX();
            startupInfo.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startupInfo.StartupInfo.dwFlags = StartfUseStdHandles;
            startupInfo.StartupInfo.hStdInput =
                standardInputHandle.DangerousGetHandle();
            startupInfo.StartupInfo.hStdOutput =
                standardOutputHandle.DangerousGetHandle();
            startupInfo.StartupInfo.hStdError =
                standardErrorHandle.DangerousGetHandle();
            startupInfo.lpAttributeList = attributeList;
            StringBuilder mutableCommandLine = new StringBuilder(commandLine);
            uint flags = CreateSuspended |
                CreateUnicodeEnvironment |
                ExtendedStartupInfoPresent;
            if (!CreateProcessW(
                executablePath,
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                flags,
                environmentBlock,
                workingDirectory,
                ref startupInfo,
                out processInformation))
            {
                throw Win32("CreateProcessW", Marshal.GetLastWin32Error());
            }
        }

        internal static void CreateRedirectedPipe(
            out NativeSafeHandle readHandle,
            out NativeSafeHandle writeHandle)
        {
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            securityAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            securityAttributes.bInheritHandle = 1;
            IntPtr rawReadHandle;
            IntPtr rawWriteHandle;
            if (!CreatePipe(
                out rawReadHandle,
                out rawWriteHandle,
                ref securityAttributes,
                0))
            {
                throw Win32("CreatePipe", Marshal.GetLastWin32Error());
            }
            readHandle = new NativeSafeHandle(rawReadHandle, true);
            writeHandle = new NativeSafeHandle(rawWriteHandle, true);
            if (!SetHandleInformation(
                readHandle.DangerousGetHandle(),
                HandleFlagInherit,
                0))
            {
                int setError = Marshal.GetLastWin32Error();
                readHandle.Dispose();
                writeHandle.Dispose();
                throw Win32("SetHandleInformation", setError);
            }
        }

        internal static void DuplicateIntoProcess(
            NativeSafeHandle sourceHandle,
            int targetProcessId)
        {
            NativeSafeHandle targetProcessHandle = new NativeSafeHandle(
                OpenProcess(
                    ProcessDuplicateHandle,
                    false,
                    targetProcessId),
                true);
            if (targetProcessHandle.IsInvalid)
            {
                int openError = Marshal.GetLastWin32Error();
                targetProcessHandle.Dispose();
                throw Win32("OpenProcess", openError);
            }
            try
            {
                IntPtr duplicatedHandle;
                if (!DuplicateHandle(
                    GetCurrentProcess(),
                    sourceHandle.DangerousGetHandle(),
                    targetProcessHandle.DangerousGetHandle(),
                    out duplicatedHandle,
                    0,
                    false,
                    DuplicateSameAccess))
                {
                    throw Win32(
                        "DuplicateHandle",
                        Marshal.GetLastWin32Error());
                }
            }
                finally
                {
                    targetProcessHandle.Dispose();
                }
            }

            internal static NativeSafeHandle DuplicateLocalHandle(
                NativeSafeHandle sourceHandle)
            {
                IntPtr duplicatedHandle;
                if (!DuplicateHandle(
                    GetCurrentProcess(),
                    sourceHandle.DangerousGetHandle(),
                    GetCurrentProcess(),
                    out duplicatedHandle,
                    0,
                    false,
                    DuplicateSameAccess))
                {
                    throw Win32(
                        "DuplicateHandle",
                        Marshal.GetLastWin32Error());
                }
                return new NativeSafeHandle(duplicatedHandle, true);
        }

        internal static IDisposable EnterActiveProcessLimitOneJob()
        {
            NativeSafeHandle jobHandle = CreateConfiguredJob(
                JobObjectLimitActiveProcess,
                1);
            if (!AssignProcessToJobObject(
                jobHandle.DangerousGetHandle(),
                GetCurrentProcess()))
            {
                int assignError = Marshal.GetLastWin32Error();
                jobHandle.Dispose();
                throw Win32("AssignProcessToJobObject", assignError);
            }
            return jobHandle;
        }

        private static NativeSafeHandle CreateConfiguredJob(
            uint limitFlags,
            uint activeProcessLimit)
        {
            NativeSafeHandle jobHandle = new NativeSafeHandle(
                CreateJobObjectW(IntPtr.Zero, null),
                true);
            if (jobHandle.IsInvalid)
            {
                int createError = Marshal.GetLastWin32Error();
                jobHandle.Dispose();
                throw Win32("CreateJobObjectW", createError);
            }

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = limitFlags;
            limits.BasicLimitInformation.ActiveProcessLimit =
                activeProcessLimit;
            int structureSize = Marshal.SizeOf(
                typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr structure = Marshal.AllocHGlobal(structureSize);
            try
            {
                Marshal.StructureToPtr(limits, structure, false);
                if (!SetInformationJobObject(
                    jobHandle.DangerousGetHandle(),
                    JobObjectExtendedLimitInformation,
                    structure,
                    (uint)structureSize))
                {
                    int setError = Marshal.GetLastWin32Error();
                    jobHandle.Dispose();
                    throw Win32("SetInformationJobObject", setError);
                }
                uint returnLength;
                if (!QueryInformationJobObject(
                    jobHandle.DangerousGetHandle(),
                    JobObjectExtendedLimitInformation,
                    structure,
                    (uint)structureSize,
                    out returnLength))
                {
                    int queryError = Marshal.GetLastWin32Error();
                    jobHandle.Dispose();
                    throw Win32("QueryInformationJobObject", queryError);
                }
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION configuredLimits =
                    (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(
                        structure,
                        typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                if (returnLength != structureSize ||
                    configuredLimits.BasicLimitInformation.LimitFlags !=
                    limitFlags ||
                    configuredLimits.BasicLimitInformation.ActiveProcessLimit !=
                    activeProcessLimit)
                {
                    jobHandle.Dispose();
                    throw new InvalidOperationException(
                        "Overlay bounded-process job limits differ.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(structure);
            }
            return jobHandle;
        }

        internal static bool IsInJob(
            NativeSafeHandle processHandle,
            NativeSafeHandle jobHandle)
        {
            bool inJob;
            if (!IsProcessInJob(
                processHandle.DangerousGetHandle(),
                jobHandle.DangerousGetHandle(),
                out inJob))
            {
                throw Win32("IsProcessInJob", Marshal.GetLastWin32Error());
            }
            return inJob;
        }

        internal static long GetCreationTime(NativeSafeHandle processHandle)
        {
            long creationTime;
            long exitTime;
            long kernelTime;
            long userTime;
            if (!GetProcessTimes(
                processHandle.DangerousGetHandle(),
                out creationTime,
                out exitTime,
                out kernelTime,
                out userTime))
            {
                throw Win32("GetProcessTimes", Marshal.GetLastWin32Error());
            }
            return creationTime;
        }

        internal static NativeSafeHandle OpenInheritedNullInput()
        {
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            securityAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            securityAttributes.bInheritHandle = 1;
            NativeSafeHandle nullHandle = new NativeSafeHandle(
                CreateFileW(
                    "NUL",
                    GenericRead,
                    FileShareRead | FileShareWrite,
                    ref securityAttributes,
                    OpenExisting,
                    FileAttributeNormal,
                    IntPtr.Zero),
                true);
            if (nullHandle.IsInvalid)
            {
                int openError = Marshal.GetLastWin32Error();
                nullHandle.Dispose();
                throw Win32("CreateFileW(NUL)", openError);
            }
            return nullHandle;
        }

        internal static long QueryActiveProcessCount(
            NativeSafeHandle jobHandle)
        {
            int structureSize = Marshal.SizeOf(
                typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            IntPtr structure = Marshal.AllocHGlobal(structureSize);
            try
            {
                uint returnLength;
                if (!QueryInformationJobObject(
                    jobHandle.DangerousGetHandle(),
                    JobObjectBasicAccountingInformation,
                    structure,
                    (uint)structureSize,
                    out returnLength))
                {
                    throw Win32(
                        "QueryInformationJobObject",
                        Marshal.GetLastWin32Error());
                }
                if (returnLength != structureSize)
                {
                    throw new InvalidOperationException(
                        "Overlay bounded-process job accounting size differs.");
                }
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting =
                    (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(
                        structure,
                        typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
                return accounting.ActiveProcesses;
            }
            finally
            {
                Marshal.FreeHGlobal(structure);
            }
        }

        internal static void TerminateProcessDirect(
            NativeSafeHandle processHandle,
            uint exitCode)
        {
            if (!TerminateProcess(processHandle.DangerousGetHandle(), exitCode))
            {
                int terminateError = Marshal.GetLastWin32Error();
                uint waitStatus = WaitForSingleObject(
                    processHandle.DangerousGetHandle(),
                    0);
                if (waitStatus == 258)
                {
                    throw Win32("TerminateProcess", terminateError);
                }
                if (waitStatus != 0)
                {
                    throw Win32("WaitForSingleObject", Marshal.GetLastWin32Error());
                }
            }
        }

        internal static void UpdateAttribute(
            IntPtr attributeList,
            IntPtr attribute,
            IntPtr value,
            IntPtr size)
        {
            if (!UpdateProcThreadAttribute(
                attributeList,
                0,
                attribute,
                value,
                size,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                throw Win32(
                    "UpdateProcThreadAttribute",
                    Marshal.GetLastWin32Error());
            }
        }

        internal static Win32Exception Win32(string operation, int error)
        {
            return new Win32Exception(
                error,
                operation + " failed with Win32 error " +
                error.ToString(CultureInfo.InvariantCulture) + ".");
        }

        private static void AppendQuotedArgument(
            StringBuilder commandLine,
            string argument)
        {
            commandLine.Append('"');
            int backslashCount = 0;
            for (int index = 0; index < argument.Length; index++)
            {
                char character = argument[index];
                if (character == '\\')
                {
                    backslashCount++;
                    continue;
                }
                if (character == '"')
                {
                    commandLine.Append('\\', backslashCount * 2 + 1);
                    commandLine.Append('"');
                    backslashCount = 0;
                    continue;
                }
                if (backslashCount > 0)
                {
                    commandLine.Append('\\', backslashCount);
                    backslashCount = 0;
                }
                commandLine.Append(character);
            }
            if (backslashCount > 0)
            {
                commandLine.Append('\\', backslashCount * 2);
            }
            commandLine.Append('"');
        }
    }
}
