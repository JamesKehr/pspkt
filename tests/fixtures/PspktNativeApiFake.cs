using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class PspktNativeApiFake : IPspktNativeApi
{
    private readonly Dictionary<PspktNativeOperation, int> _callCounts;
    private readonly List<PspktNativeOperation> _callSequence;
    private readonly HashSet<PspktNativeOperation> _throwingOperations;

    public PspktNativeApiFake()
    {
        _callCounts = new Dictionary<PspktNativeOperation, int>();
        _callSequence = new List<PspktNativeOperation>();
        _throwingOperations = new HashSet<PspktNativeOperation>();
        EnumData = new byte[] { };
    }

    public int InitializeStatus { get; set; }
    public IntPtr InitializeHandle { get; set; }
    public int EnumDataSourcesStatus { get; set; }
    public ulong EnumBytesNeeded { get; set; }
    public byte[] EnumData { get; set; }
    public int CreateLiveSessionStatus { get; set; }
    public IntPtr CreateLiveSessionHandle { get; set; }
    public int CreateRealtimeStreamStatus { get; set; }
    public IntPtr CreateRealtimeStreamHandle { get; set; }
    public IntPtr LastRealtimeStreamDataCallback { get; private set; }
    public int SetSessionActiveStatus { get; set; }
    public int AddSingleDataSourceStatus { get; set; }
    public int AddCaptureConstraintStatus { get; set; }
    public int AttachOutputStatus { get; set; }

    public void SetThrow(PspktNativeOperation operation, bool shouldThrow)
    {
        if (shouldThrow)
        {
            _throwingOperations.Add(operation);
        }
        else
        {
            _throwingOperations.Remove(operation);
        }
    }

    public int GetCallCount(PspktNativeOperation operation)
    {
        int count;
        return _callCounts.TryGetValue(operation, out count) ? count : 0;
    }

    public PspktNativeOperation[] GetCallSequence()
    {
        return _callSequence.ToArray();
    }

    public int PacketMonitorInitialize(uint apiVersion, IntPtr reserved, out IntPtr handle)
    {
        Record(PspktNativeOperation.Initialize);
        ThrowIfConfigured(PspktNativeOperation.Initialize);
        handle = InitializeHandle;
        return InitializeStatus;
    }

    public void PacketMonitorUninitialize(IntPtr handle)
    {
        Record(PspktNativeOperation.Uninitialize);
        ThrowIfConfigured(PspktNativeOperation.Uninitialize);
    }

    public int PacketMonitorEnumDataSources(
        IntPtr handle,
        uint sourceKind,
        bool showHidden,
        ulong bufferCapacity,
        out ulong bytesNeeded,
        IntPtr buffer)
    {
        Record(PspktNativeOperation.EnumDataSources);
        ThrowIfConfigured(PspktNativeOperation.EnumDataSources);
        bytesNeeded = EnumBytesNeeded;
        if (buffer != IntPtr.Zero && EnumData != null && EnumData.Length > 0)
        {
            int copyLength = Math.Min(EnumData.Length, checked((int)bufferCapacity));
            Marshal.Copy(EnumData, 0, buffer, copyLength);
        }
        return EnumDataSourcesStatus;
    }

    public int PacketMonitorCreateLiveSession(IntPtr handle, string sessionName, out IntPtr session)
    {
        Record(PspktNativeOperation.CreateLiveSession);
        ThrowIfConfigured(PspktNativeOperation.CreateLiveSession);
        session = CreateLiveSessionHandle;
        return CreateLiveSessionStatus;
    }

    public void PacketMonitorCloseSessionHandle(IntPtr handle)
    {
        Record(PspktNativeOperation.CloseSessionHandle);
        ThrowIfConfigured(PspktNativeOperation.CloseSessionHandle);
    }

    public int PacketMonitorCreateRealtimeStream(
        IntPtr handle,
        ref PACKETMONITOR_REALTIME_STREAM_CONFIGURATION configuration,
        out IntPtr realtimeStream)
    {
        Record(PspktNativeOperation.CreateRealtimeStream);
        ThrowIfConfigured(PspktNativeOperation.CreateRealtimeStream);
        LastRealtimeStreamDataCallback = configuration.DataCallback;
        realtimeStream = CreateRealtimeStreamHandle;
        return CreateRealtimeStreamStatus;
    }

    public void PacketMonitorCloseRealtimeStream(IntPtr realtimeStream)
    {
        Record(PspktNativeOperation.CloseRealtimeStream);
        ThrowIfConfigured(PspktNativeOperation.CloseRealtimeStream);
    }

    public int PacketMonitorSetSessionActive(IntPtr session, bool active)
    {
        Record(PspktNativeOperation.SetSessionActive);
        ThrowIfConfigured(PspktNativeOperation.SetSessionActive);
        return SetSessionActiveStatus;
    }

    public int PacketMonitorAddSingleDataSourceToSession(IntPtr session, IntPtr dataSourceSpec)
    {
        Record(PspktNativeOperation.AddSingleDataSource);
        ThrowIfConfigured(PspktNativeOperation.AddSingleDataSource);
        return AddSingleDataSourceStatus;
    }

    public int PacketMonitorAddCaptureConstraint(IntPtr session, IntPtr captureConstraint)
    {
        Record(PspktNativeOperation.AddCaptureConstraint);
        ThrowIfConfigured(PspktNativeOperation.AddCaptureConstraint);
        return AddCaptureConstraintStatus;
    }

    public int PacketMonitorAttachOutputToSession(IntPtr session, IntPtr realtimeStream)
    {
        Record(PspktNativeOperation.AttachOutput);
        ThrowIfConfigured(PspktNativeOperation.AttachOutput);
        return AttachOutputStatus;
    }

    private void Record(PspktNativeOperation operation)
    {
        int count = _callCounts.ContainsKey(operation) ? _callCounts[operation] : 0;
        _callCounts[operation] = count + 1;
        _callSequence.Add(operation);
    }

    private void ThrowIfConfigured(PspktNativeOperation operation)
    {
        if (_throwingOperations.Contains(operation))
        {
            throw new InvalidOperationException(operation.ToString());
        }
    }
}
