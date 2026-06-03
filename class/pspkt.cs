// Credit: https://github.com/Ekky-PS/PSPktmon
// Modified for performance and to fit the needs of this project.
// A huge thank you to Ekky for sharing his implementation of pktmon using PowerShell!!!

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Runtime.InteropServices;



// Constants from packetmonitor.h
internal static class PacketMonitorConstants
{
    public const int PACKETMONITOR_MAX_NAME_LENGTH = 64;   // verify against your SDK header
    public const int PACKETMONITOR_MAC_ADDRESS_SIZE = 6;
    public const int PACKETMONITOR_IPV4_ADDRESS_SIZE = 4;
    public const int PACKETMONITOR_IPV6_ADDRESS_SIZE = 16;
    public const int PACKETMONITOR_MAX_FILENAME_LENGTH = 260;
}

// Session capture type: which packets to capture.
public enum PACKETMONITOR_CAPTURE_TYPE : uint
{
    All  = 0,   // all packets
    Flow = 1,   // flow packets only (non-drop)
    Drop = 2    // dropped packets only
}

// Session logging mode.
public enum PACKETMONITOR_LOG_MODE : uint
{
    Circular  = 0,
    MultiFile = 1,
    Memory    = 2,
    RealTime  = 3
}

// Event flags bitmask (from pktmon start --flags).
[Flags]
public enum PACKETMONITOR_EVENT_FLAGS : uint
{
    None                 = 0x000,
    InternalErrors       = 0x001,
    ComponentSummary     = 0x002,
    NblSourceDest        = 0x004,
    NdisMetadata         = 0x008,
    RawPacket            = 0x010,
    RegistrationChanges  = 0x020,
    Default              = 0x032   // ComponentSummary | RawPacket | RegistrationChanges
}

// Managed representation of a packet monitor session configuration.
// Used to serialize the session state for live and real-time captures.
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct PACKETMONITOR_SESSION
{
    [MarshalAs(UnmanagedType.ByValTStr,
               SizeConst = PacketMonitorConstants.PACKETMONITOR_MAX_NAME_LENGTH)]
    public string Name;

    public PACKETMONITOR_CAPTURE_TYPE CaptureType;
    public PACKETMONITOR_LOG_MODE LogMode;
    public PACKETMONITOR_EVENT_FLAGS EventFlags;

    public uint PacketSize;       // 0 = full packet; otherwise max bytes to log per packet
    public uint FileSize;         // max log file size in MB (default 512)

    [MarshalAs(UnmanagedType.ByValTStr,
               SizeConst = PacketMonitorConstants.PACKETMONITOR_MAX_FILENAME_LENGTH)]
    public string FileName;

    [MarshalAs(UnmanagedType.U1)]
    public bool CountersOnly;     // capture counters only, no packet logging

    [MarshalAs(UnmanagedType.U1)]
    public bool Active;           // whether the session is currently active

    public uint DataSourceCount;  // number of attached data sources
    public uint ConstraintCount;  // number of capture constraints (filters)
    public uint StreamCount;      // number of attached output streams
}

[StructLayout(LayoutKind.Sequential)]
public struct PACKETMONITOR_REALTIME_STREAM_CONFIGURATION
{
    public IntPtr UserContext;                                      
    public IntPtr EventCallback;      
    public IntPtr DataCallback;        

    public UInt16 BufferSizeMultiplier;                  

    public UInt16 TruncationSize;                                  
}

[StructLayout(LayoutKind.Sequential)]
public struct PACKETMONITOR_STREAM_DATA_DESCRIPTOR
{
    public IntPtr Data;
    public UInt32 DataSize;
    public UInt32 MetadataOffset;
    public UInt32 PacketOffset;
    public UInt32 PacketLength;
    public UInt32 MissedPacketWriteCount;
    public UInt32 MissedPacketReadCount;
}

public struct PSPacketData
{
    public byte[] Data;
    public UInt32 DataSize;
    public UInt32 MetadataOffset;
    public UInt32 PacketOffset;
    public UInt32 PacketLength;
    public UInt32 MissedPacketWriteCount;
    public UInt32 MissedPacketReadCount;
    public long QpcTimestamp;  // High-resolution QPC ticks captured at callback time.
    public bool IsPooledBuffer; // True when Data was rented from PacketBytePool and must be returned.


    public PSPacketData(byte[] data, uint dataSize, uint metadataOffset, uint packetOffset, uint packetLength, uint missedPacketWriteCount, uint missedPacketReadCount)
    {
        Data = data;
        DataSize = dataSize;
        MetadataOffset = metadataOffset;
        PacketOffset = packetOffset;
        PacketLength = packetLength;
        MissedPacketWriteCount = missedPacketWriteCount;
        MissedPacketReadCount = missedPacketReadCount;
        QpcTimestamp = 0;
        IsPooledBuffer = false;
    }
}

/// <summary>
/// Simple power-of-2 bucket pool for packet byte[] buffers.
/// Reduces allocation pressure on the pktmon callback thread.
/// Thread-safe Rent/Return via lock-free stack per bucket.
/// </summary>
public static class PacketBytePool
{
    // Bucket sizes (power of 2). Packets larger than the max bucket are not pooled.
    private static readonly int[] BucketSizes = new int[]
    {
        128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
    };

    // Cap on number of arrays retained per bucket. Prevents unbounded growth under bursty load.
    private const int MaxArraysPerBucket = 1024;

    private static readonly System.Collections.Concurrent.ConcurrentStack<byte[]>[] _buckets;
    // Per-bucket array counts. Updated with Interlocked around Push/Pop to avoid the
    // O(N) walk that ConcurrentStack<T>.Count performs on every Return call.
    // The counters are advisory: small over/under-shoots vs the underlying stack are
    // tolerated (MaxArraysPerBucket is a soft cap, off-by-one is harmless).
    private static long[] _bucketCounts;
    private static long _rentCount;
    private static long _returnCount;
    private static long _missCount; // requested size > max bucket; allocated directly

    static PacketBytePool()
    {
        _buckets = new System.Collections.Concurrent.ConcurrentStack<byte[]>[BucketSizes.Length];
        _bucketCounts = new long[BucketSizes.Length];
        for (int i = 0; i < _buckets.Length; i++)
        {
            _buckets[i] = new System.Collections.Concurrent.ConcurrentStack<byte[]>();
        }
    }

    /// <summary>
    /// Find the smallest bucket index that fits the requested size, or -1 if too large.
    /// </summary>
    private static int FindBucket(int size)
    {
        for (int i = 0; i < BucketSizes.Length; i++)
        {
            if (BucketSizes[i] >= size) return i;
        }
        return -1;
    }

    /// <summary>
    /// Rent an array of at least the requested size. Returned array may be larger.
    /// Callers MUST use a separate "valid length" (e.g., PSPacketData.DataSize) for bounds.
    /// </summary>
    public static byte[] Rent(int minSize)
    {
        Interlocked.Increment(ref _rentCount);
        int idx = FindBucket(minSize);
        if (idx < 0)
        {
            Interlocked.Increment(ref _missCount);
            return new byte[minSize];
        }
        byte[] result;
        if (_buckets[idx].TryPop(out result))
        {
            Interlocked.Decrement(ref _bucketCounts[idx]);
            return result;
        }
        return new byte[BucketSizes[idx]];
    }

    /// <summary>
    /// Return an array to the pool. Safe to call with null or arrays of any size
    /// (off-bucket arrays are discarded).
    /// </summary>
    public static void Return(byte[] array)
    {
        if (array == null) return;
        Interlocked.Increment(ref _returnCount);
        int idx = FindBucket(array.Length);
        if (idx < 0 || BucketSizes[idx] != array.Length)
        {
            // Off-bucket size — let GC reclaim it.
            return;
        }
        // Soft-cap check: use the dedicated counter instead of ConcurrentStack.Count, which
        // walks the entire internal linked list (O(N)) and was the bulk of Return's cost.
        if (Interlocked.Read(ref _bucketCounts[idx]) >= MaxArraysPerBucket) return;
        _buckets[idx].Push(array);
        Interlocked.Increment(ref _bucketCounts[idx]);
    }

    public static long RentCount { get { return Interlocked.Read(ref _rentCount); } }
    public static long ReturnCount { get { return Interlocked.Read(ref _returnCount); } }
    public static long MissCount { get { return Interlocked.Read(ref _missCount); } }
}

[StructLayout(LayoutKind.Explicit, Size = PacketMonitorConstants.PACKETMONITOR_IPV6_ADDRESS_SIZE)]
public struct PACKETMONITOR_IP_ADDRESS
{
    // ULONG IPv4  -> 32-bit IPv4 address (network-byte-order as produced by PacketMonitor)
    [FieldOffset(0)]
    public uint IPv4;

    // UCHAR IPv4_bytes[4]
    [FieldOffset(0)]
    public uint IPv4_bytes_u32;   // see helper accessor below

    // ULONGLONG IPv6[2]  -> two 64-bit halves of the IPv6 address
    [FieldOffset(0)]
    public ulong IPv6_low;        // bytes  0..7

    [FieldOffset(8)]
    public ulong IPv6_high;       // bytes  8..15

    // ----------------------------------------------------------------
    // Convenience accessors. C# can't put a fixed-size byte[] inside an
    // Explicit-layout struct without `unsafe`, so we expose helpers that
    // read/write the overlapped 16 bytes safely.
    // ----------------------------------------------------------------

    public byte[] GetIPv4Bytes()
    {
        // little-endian on Windows; PacketMonitor stores IPv4 in network order
        // already packed into the ULONG, so just emit the 4 bytes as-is.
        return new[]
        {
            (byte)( IPv4        & 0xFF),
            (byte)((IPv4 >>  8) & 0xFF),
            (byte)((IPv4 >> 16) & 0xFF),
            (byte)((IPv4 >> 24) & 0xFF),
        };
    }

    public byte[] GetIPv6Bytes()
    {
        var b = new byte[16];
        BitConverter.GetBytes(IPv6_low ).CopyTo(b, 0);
        BitConverter.GetBytes(IPv6_high).CopyTo(b, 8);
        return b;
    }

    /// <summary>
    /// Returns the address as an <see cref="IPAddress"/>. Caller decides
    /// which family applies (driven by the IPv6 flag in
    /// PACKETMONITOR_PROTOCOL_CONSTRAINT.IsPresent).
    /// </summary>
    public IPAddress ToIPAddress(bool isIPv6)
    {
        if (isIPv6) { return new IPAddress(GetIPv6Bytes()); }
        return new IPAddress(GetIPv4Bytes());
    }
}



// Bitfield -> [Flags] enum. MSVC allocates bitfields from LSB,
// so Mac1 = bit 0, Mac2 = bit 1, ... ClusterHeartbeat = bit 16.
[Flags]
public enum PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS : uint
{
    None              = 0,
    Mac1              = 1u << 0,
    Mac2              = 1u << 1,
    VlanId            = 1u << 2,
    EtherType         = 1u << 3,
    DSCP              = 1u << 4,
    TransportProtocol = 1u << 5,
    Ip1               = 1u << 6,
    Ip2               = 1u << 7,
    IPv6              = 1u << 8,   // indicates IP version
    PrefixLength1     = 1u << 9,
    PrefixLength2     = 1u << 10,
    Port1             = 1u << 11,
    Port2             = 1u << 12,
    TCPFlags          = 1u << 13,
    EncapType         = 1u << 14,
    VxLanPort         = 1u << 15,
    ClusterHeartbeat  = 1u << 16,
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct PACKETMONITOR_PROTOCOL_CONSTRAINT
{
    // WCHAR Name[PACKETMONITOR_MAX_NAME_LENGTH]
    [MarshalAs(UnmanagedType.ByValTStr,
               SizeConst = PacketMonitorConstants.PACKETMONITOR_MAX_NAME_LENGTH)]
    public string Name;

    // union { struct { UINT ... :1; } IsPresent; UINT IsPresentValue; }
    // Both arms are 4 bytes, so a single uint preserves layout.
    public uint IsPresentValue;

    // Convenience accessor for the bitfield arm of the union.
    public PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS IsPresent
    {
        get { return (PACKETMONITOR_PROTOCOL_CONSTRAINT_FLAGS)IsPresentValue; }
        set { IsPresentValue = (uint)value; }
    }

    // Ethernet frame
    [MarshalAs(UnmanagedType.ByValArray,
               SizeConst = PacketMonitorConstants.PACKETMONITOR_MAC_ADDRESS_SIZE)]
    public byte[] Mac1;

    [MarshalAs(UnmanagedType.ByValArray,
               SizeConst = PacketMonitorConstants.PACKETMONITOR_MAC_ADDRESS_SIZE)]
    public byte[] Mac2;

    public ushort VlanId;
    public ushort EtherType;

    // IP header
    public ushort DSCP;
    public byte   TransportProtocol;

    public PACKETMONITOR_IP_ADDRESS Ip1;
    public PACKETMONITOR_IP_ADDRESS Ip2;

    public byte PrefixLength1;
    public byte PrefixLength2;

    // TCP or UDP header
    public ushort Port1;
    public ushort Port2;
    public byte   TCPFlags;

    // Encapsulation
    public uint   EncapType;
    public ushort VxLanPort;

    // Counters
    public ulong Packets;
    public ulong Bytes;
}




[UnmanagedFunctionPointer(CallingConvention.Winapi)]
public delegate void PACKETMONITOR_STREAM_DATA_CALLBACK(IntPtr zeroPtr, PACKETMONITOR_STREAM_DATA_DESCRIPTOR descriptor);

public static class PktMonApi
{
    public static PACKETMONITOR_STREAM_DATA_CALLBACK DataCallback;
    private static SpscPacketRingBuffer _ringBuffer = new SpscPacketRingBuffer(1048576);
    private static volatile bool _captureActive;

    // File writer integration — when set, packets are also written to file.
    // Use Volatile.Read in the callback to ensure consistent snapshot.
    private static PcapngWriter _fileWriter;
    public static PcapngWriter FileWriter
    {
        get { return Volatile.Read(ref _fileWriter); }
        set { Volatile.Write(ref _fileWriter, value); }
    }

    // High-resolution timestamp baseline for QPC → UTC conversion.
    private static long _qpcBaselineTicks;     // Stopwatch.GetTimestamp() at capture start
    private static long _utcBaselineFiletime;  // DateTime.UtcNow.ToFileTimeUtc() at capture start
    private static double _qpcToFiletimeFactor; // 10,000,000 / Stopwatch.Frequency (FILETIME units per QPC tick)

    /// <summary>
    /// Call at capture start to establish the QPC↔UTC correlation.
    /// </summary>
    public static void InitTimestampBaseline()
    {
        _qpcBaselineTicks = System.Diagnostics.Stopwatch.GetTimestamp();
        _utcBaselineFiletime = DateTime.UtcNow.ToFileTimeUtc();
        _qpcToFiletimeFactor = 10000000.0 / System.Diagnostics.Stopwatch.Frequency;
    }

    /// <summary>
    /// Convert a QPC timestamp to FILETIME (100ns units since 1601-01-01).
    /// </summary>
    public static long QpcToFiletime(long qpcTicks)
    {
        long delta = qpcTicks - _qpcBaselineTicks;
        return _utcBaselineFiletime + (long)(delta * _qpcToFiletimeFactor);
    }

    // Track component IDs seen during capture for session summary.
    //
    // ACCESS RULES: This set is mutated only from the PowerShell consumer thread
    // (via NoteComponentId, called inside PacketLineFormatter.FormatBatch) and read/cleared
    // only from the PowerShell control thread (ClearSeenComponentIds at capture start,
    // GetSeenComponentIds after the consumer loop has exited). Both happen on the same
    // PS pipeline thread, so no synchronization is required.
    //
    // Historically the producer callback added IDs under a lock on every packet. That
    // per-packet Monitor.Enter on the native callback thread has been removed; the set
    // is now populated lazily by the consumer as it walks the drain buffer in FormatBatch.
    // A trailing window between consumer-loop exit and pktmon stream close may admit a
    // handful of packets whose component IDs go unrecorded — acceptable for a session
    // summary that only enumerates IDs that appeared, and in practice those IDs are
    // already in the set from earlier batches.
    private static System.Collections.Generic.HashSet<int> _seenComponentIds = new System.Collections.Generic.HashSet<int>();

    /// <summary>
    /// Records a component ID as seen during the current capture. Must be called from
    /// the PowerShell consumer thread only (currently inside PacketLineFormatter.FormatBatch).
    /// </summary>
    public static void NoteComponentId(int componentId)
    {
        if (componentId != 0) _seenComponentIds.Add(componentId);
    }

    public static int[] GetSeenComponentIds()
    {
        int[] result = new int[_seenComponentIds.Count];
        _seenComponentIds.CopyTo(result);
        return result;
    }

    public static void ClearSeenComponentIds()
    {
        _seenComponentIds.Clear();
    }

    public static long DroppedCount { get { return _ringBuffer.DroppedCount; } }

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorInitialize
    (
        UInt32 apiVersion,
        IntPtr reserved,
        out IntPtr handle
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern void PacketMonitorUninitialize(IntPtr handle);

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorEnumDataSources
    (
        IntPtr handle,
        UInt32 sourceKind,
        [MarshalAs(UnmanagedType.U1)]bool showHidden,
        UInt64 bufferCapacity,
        out UInt64 bytesNeeded,
        IntPtr buffer
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorCreateLiveSession
    (
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPWStr)] string sessionName,
        out IntPtr session
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern void PacketMonitorCloseSessionHandle
    (
        IntPtr handle
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorAddSingleDataSourceToSession
    (
        IntPtr session,
        IntPtr dataSourceSpec
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorCreateRealtimeStream
    (
        IntPtr handle,
        ref PACKETMONITOR_REALTIME_STREAM_CONFIGURATION configuration,
        out IntPtr realtimeStream
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorAttachOutputToSession
    (
        IntPtr session,
        IntPtr realtimeStream
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern void PacketMonitorCloseRealtimeStream
    (
        IntPtr realtimeStream
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorAddCaptureConstraint
    (
        IntPtr session,
        IntPtr captureConstraint
    );

    [DllImport("pktmonapi.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int PacketMonitorSetSessionActive
    (
        IntPtr session,
        [MarshalAs(UnmanagedType.U1)] bool active
    );
    
    private static void PacketDataCallBack(IntPtr userContext, PACKETMONITOR_STREAM_DATA_DESCRIPTOR descriptor)
    {
        long qpc = System.Diagnostics.Stopwatch.GetTimestamp();
        int size = (int)descriptor.DataSize;

        // Snapshot FileWriter ONCE — this same snapshot drives both allocation strategy and write path.
        // Without this, FileWriter changing mid-packet could lead to a pooled byte[] being shared
        // with the writer thread and recycled before the writer is done with it.
        PcapngWriter fw = Volatile.Read(ref _fileWriter);
        bool writeToFile = fw != null && fw.IsActive;

        // Pool the byte[] only when no file writer is active. When writing to file, the byte[]
        // is also referenced by the (async) writer ring and must outlive the consumer ring.
        byte[] byteArray;
        bool pooled;
        if (writeToFile)
        {
            byteArray = new byte[size];
            pooled = false;
        }
        else
        {
            byteArray = PacketBytePool.Rent(size);
            pooled = true;
        }
        Marshal.Copy(descriptor.Data, byteArray, 0, size);

        // ICMP display filter (set by -Ping/-NDP/-AAv6 quick filters). Applied at the
        // producer level so filtered packets are excluded from BOTH console output AND
        // pcapng file output. WiFi packets bypass this and rely on the display-side
        // fallback in FormatSinglePacket.
        if (PacketLineFormatter.IsIcmpFilterActive &&
            PacketLineFormatter.ShouldDropForIcmpFilter(byteArray, (int)descriptor.PacketOffset, size))
        {
            if (pooled) PacketBytePool.Return(byteArray);
            return;
        }

        PSPacketData tmp = new PSPacketData
        (
            byteArray, 
            descriptor.DataSize, descriptor.MetadataOffset, 
            descriptor.PacketOffset, descriptor.PacketLength, 
            descriptor.MissedPacketWriteCount, descriptor.MissedPacketReadCount
        );
        tmp.QpcTimestamp = qpc;
        tmp.IsPooledBuffer = pooled;

        // Note: tracking of seen component IDs has moved to the consumer side
        // (PacketLineFormatter.FormatBatch). Adding here would require a Monitor.Enter
        // on every callback, which is the largest avoidable cost on the producer thread.

        bool enqueued = _ringBuffer.Enqueue(tmp);
        if (!enqueued && pooled)
        {
            // Return the rented buffer to avoid pool leak on overflow.
            PacketBytePool.Return(byteArray);
        }

        // Also write to file if active (use the same snapshot taken above).
        if (writeToFile)
        {
            fw.WritePacket(tmp);
        }
    }
    
    public static void ClearPacketBuffer()
    {
        _ringBuffer.Clear();
    }
    
    public static int GetPacketData(PSPacketData[] buffer)
    {
        return _ringBuffer.DrainTo(buffer);
    }

    /// <summary>
    /// Returns pooled byte[] for the first `count` packets in `buffer` to the pool
    /// and clears the slots. Call after FormatBatch has consumed the buffer.
    /// Safe to call with non-pooled packets (they are skipped).
    /// </summary>
    public static void ReturnPacketBuffers(PSPacketData[] buffer, int count)
    {
        if (buffer == null || count <= 0) return;
        if (count > buffer.Length) count = buffer.Length;
        for (int i = 0; i < count; i++)
        {
            if (buffer[i].IsPooledBuffer && buffer[i].Data != null)
            {
                PacketBytePool.Return(buffer[i].Data);
            }
            buffer[i] = default(PSPacketData);
        }
    }

    /// <summary>
    /// Block until at least one packet is enqueued, the captureActive flag clears, or timeoutMs expires.
    /// Returns true if a packet may be available; false on timeout. Used by the consumer to avoid
    /// busy-polling at low traffic. AutoResetEvent ensures one wakeup per non-empty drain cycle.
    /// </summary>
    public static bool WaitForPackets(int timeoutMs)
    {
        return _ringBuffer.WaitForPackets(timeoutMs);
    }

    /// <summary>
    /// Mark the capture as active/inactive. The ring buffer uses this to wake waiters on shutdown.
    /// </summary>
    public static void SetCaptureActive(bool active)
    {
        _captureActive = active;
        if (!active)
        {
            // Wake any consumer waiting on the signal so it can observe the stop request.
            _ringBuffer.WakeWaiters();
        }
    }

    public static bool IsCaptureActive { get { return _captureActive; } }

    /// <summary>
    /// Configure the ring buffer capacity. Must be called BEFORE the realtime stream is created.
    /// Capacity is rounded up to the nearest power of 2 with a minimum of 1024.
    /// Returns the actual capacity applied.
    /// </summary>
    public static int ConfigureRingBuffer(int capacity)
    {
        if (_captureActive)
        {
            throw new InvalidOperationException("Cannot reconfigure ring buffer while capture is active.");
        }
        if (capacity < 1024) capacity = 1024;
        // Round up to next power of 2.
        int cap = 1;
        while (cap < capacity) cap <<= 1;

        // Return any pooled buffers still sitting in the old ring (defensive cleanup).
        if (_ringBuffer != null)
        {
            var drain = new PSPacketData[cap];
            int drained;
            while ((drained = _ringBuffer.DrainTo(drain)) > 0)
            {
                for (int i = 0; i < drained; i++)
                {
                    if (drain[i].IsPooledBuffer && drain[i].Data != null)
                    {
                        PacketBytePool.Return(drain[i].Data);
                    }
                }
            }
        }
        _ringBuffer = new SpscPacketRingBuffer(cap);
        return cap;
    }
    
    public static void ResetDroppedCount()
    {
        _ringBuffer.ResetDroppedCount();
    }
    
    public static IntPtr CreateRealtimeStream(IntPtr pktmonHandle, PACKETMONITOR_REALTIME_STREAM_CONFIGURATION cfg)
    {
        DataCallback = new PACKETMONITOR_STREAM_DATA_CALLBACK(PacketDataCallBack);
        cfg.DataCallback = Marshal.GetFunctionPointerForDelegate(DataCallback);
        IntPtr streamHandle = IntPtr.Zero;
        
        var hr = PacketMonitorCreateRealtimeStream(pktmonHandle, ref cfg, out streamHandle);
        if (hr != 0)
        {
            return IntPtr.Zero;
        }
        
        return streamHandle;
    }
}

// PacketParseHelper and PacketFormatter have been moved to Parsers\parserCommon.cs

/// <summary>
/// Single-Producer Single-Consumer lock-free ring buffer for packet data.
/// Producer: pktmonapi callback thread. Consumer: PowerShell poll loop.
/// Capacity must be a power of 2. When full, new packets are dropped and counted.
/// </summary>
public class SpscPacketRingBuffer
{
    // Cache-line padding wrapper (typical x86/x64 cache line = 64 bytes).
    // Size = 128 ensures _head and _tail land in separate cache lines and stay there
    // even if the runtime allocates them next to each other in the heap.
    [StructLayout(LayoutKind.Explicit, Size = 128)]
    private struct PaddedInt
    {
        [FieldOffset(64)] public int Value;
    }

    private readonly PSPacketData[] _buffer;
    private readonly int _mask;
    private PaddedInt _head; // written only by producer
    private PaddedInt _tail; // written only by consumer
    private long _droppedCount;
    // AutoResetEvent for producer→consumer signaling. Producer signals on empty→non-empty
    // transition; consumer waits when drain returns 0.
    private readonly AutoResetEvent _signal = new AutoResetEvent(false);

    public long DroppedCount { get { return Volatile.Read(ref _droppedCount); } }

    public SpscPacketRingBuffer(int capacity)
    {
        if (capacity < 2 || (capacity & (capacity - 1)) != 0)
            throw new ArgumentException("Capacity must be a power of 2 and >= 2.");
        _buffer = new PSPacketData[capacity];
        _mask = capacity - 1;
    }

    /// <summary>
    /// Enqueue a packet. Called by producer (callback thread) only.
    /// Returns true if enqueued, false if buffer was full (packet dropped).
    /// </summary>
    public bool Enqueue(PSPacketData item)
    {
        int head = _head.Value;
        int next = (head + 1) & _mask;
        int tail = Volatile.Read(ref _tail.Value);
        if (next == tail)
        {
            // Buffer full — drop packet and count it.
            Interlocked.Increment(ref _droppedCount);
            return false;
        }
        bool wasEmpty = (head == tail);
        _buffer[head] = item;
        Volatile.Write(ref _head.Value, next);

        // Wake the consumer. We want to signal at minimum on empty→non-empty transitions so
        // an idle waiter wakes promptly. The naive `if (wasEmpty)` check has a missed-wakeup
        // window: between our initial `Volatile.Read(ref tail)` and our head publish, the
        // consumer can drain the previous batch, observe head==tail, and head into WaitOne.
        // If our earlier `wasEmpty` was false (because we observed an older tail), we'd skip
        // the Set and the consumer waits the full timeout for no reason.
        //
        // Fix: re-read tail after head publish. Signal if either (a) we observed empty pre-write
        // or (b) the consumer's tail caught up to us during the write (it's now waiting again).
        if (wasEmpty)
        {
            _signal.Set();
        }
        else
        {
            int tail2 = Volatile.Read(ref _tail.Value);
            if (tail2 != tail) _signal.Set();
        }
        return true;
    }

    /// <summary>
    /// Drain up to output.Length packets into the provided array.
    /// Called by consumer (PowerShell poll loop) only.
    /// Returns number of packets written to output.
    /// </summary>
    public int DrainTo(PSPacketData[] output)
    {
        int count = 0;
        int tail = _tail.Value;
        int head = Volatile.Read(ref _head.Value);
        while (tail != head && count < output.Length)
        {
            output[count] = _buffer[tail];
            _buffer[tail] = default(PSPacketData); // release reference for GC
            tail = (tail + 1) & _mask;
            count++;
        }
        Volatile.Write(ref _tail.Value, tail);
        return count;
    }

    /// <summary>
    /// Wait for at least one packet to be enqueued, or for timeoutMs to expire.
    /// Returns true if signaled (a packet may be available), false on timeout.
    /// Caller should always re-check via DrainTo (may be a spurious wakeup).
    /// </summary>
    public bool WaitForPackets(int timeoutMs)
    {
        return _signal.WaitOne(timeoutMs);
    }

    /// <summary>
    /// Manually wake any waiting consumer (used on capture shutdown to unblock the wait).
    /// </summary>
    public void WakeWaiters()
    {
        _signal.Set();
    }

    /// <summary>
    /// Clear all buffered packets. Safe to call from consumer thread only.
    /// Returns pooled byte[] arrays to the pool to avoid leaks.
    /// </summary>
    public void Clear()
    {
        int tail = _tail.Value;
        int head = Volatile.Read(ref _head.Value);
        while (tail != head)
        {
            if (_buffer[tail].IsPooledBuffer && _buffer[tail].Data != null)
            {
                PacketBytePool.Return(_buffer[tail].Data);
            }
            _buffer[tail] = default(PSPacketData);
            tail = (tail + 1) & _mask;
        }
        Volatile.Write(ref _tail.Value, tail);
    }

    public void ResetDroppedCount()
    {
        Interlocked.Exchange(ref _droppedCount, 0);
    }
}

/// <summary>
/// High-performance pcapng file writer that captures raw packet data from the
/// pktmon real-time callback. Writes Ethernet II frames in pcapng format directly
/// compatible with Wireshark and tcpdump. Thread-safe via a dedicated writer thread
/// consuming from a lock-free ring buffer.
/// </summary>
public class PcapngWriter
{
    // pcapng block types
    private const uint SHB_TYPE = 0x0A0D0D0A;
    private const uint IDB_TYPE = 0x00000001;
    private const uint EPB_TYPE = 0x00000006;

    // pcapng constants
    private const uint PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D;
    private const ushort PCAPNG_VERSION_MAJOR = 1;
    private const ushort PCAPNG_VERSION_MINOR = 0;
    private const long SECTION_LENGTH_UNSPECIFIED = -1;
    private const ushort LINKTYPE_ETHERNET = 1;
    private const ushort LINKTYPE_RAW = 101; // raw IP

    // Component lookup for enriched packet comments.
    private struct ComponentInfo
    {
        public string Name;
        public string Group;
        public int ParentId;
    }
    private Dictionary<int, ComponentInfo> _componentMap = new Dictionary<int, ComponentInfo>();

    /// <summary>
    /// Registers a component for name resolution in packet comments.
    /// Call before starting capture so EPB opt_comment can include component/group names.
    /// </summary>
    public void RegisterComponent(int componentId, string name, string group, int parentId)
    {
        _componentMap[componentId] = new ComponentInfo { Name = name, Group = group, ParentId = parentId };
        // Re-registration invalidates any cached opt_comment prefix that referenced the
        // old name/group. Cheap to rebuild lazily on the next packet for that component.
        lock (_writeLock) { _commentCache.Clear(); }
    }

    /// <summary>
    /// Clears all registered components.
    /// </summary>
    public void ClearComponents()
    {
        _componentMap.Clear();
        lock (_writeLock) { _commentCache.Clear(); }
    }

    // Writer state
    private System.IO.FileStream _fileStream;
    private System.IO.BinaryWriter _binaryWriter;
    private string _fileName;          // user-supplied base path (no rotation suffix)
    private string _currentFilePath;   // actual current open file path (with rotation suffix when active)
    // _isActive is read by the pktmon callback thread via fw.IsActive — must be volatile so
    // the JIT cannot hoist the read past Start()/Stop() side effects on the PS thread.
    private volatile bool _isActive;
    private long _packetCount;
    private object _writeLock = new object();

    // Ring buffer for async writing
    private SpscPacketRingBuffer _fileRing;
    private Thread _writerThread;
    private volatile bool _stopWriter;
    private PSPacketData[] _drainBuf;
    private bool _useAsyncWriter;
    private bool _flushPerBatch; // when true, Flush() is called after each drained batch
    // Records the most recent unhandled write/rotate error. The PS layer reads this on shutdown
    // so users see a meaningful message instead of a silent broken file.
    private volatile string _lastError;
    public string LastError { get { return _lastError; } }

    // Reusable per-writer scratch storage for opt_comment building. Accessed only under _writeLock.
    private readonly StringBuilder _commentSb = new StringBuilder(192);
    private byte[] _commentScratch = new byte[512];
    private static readonly Encoding _utf8 = Encoding.UTF8;
    // Up to 3 zero bytes needed for opt_comment 4-byte alignment padding.
    private static readonly byte[] _zeroPad = new byte[4];

    // Cache for the per-packet opt_comment prefix bytes (everything up to and including
    // "CPU: <processor>"). Keyed by a packed (componentId, edgeId, direction, processor)
    // tuple — these are the only metadata fields that vary across packets from the same
    // capture, and the resulting comment for any given tuple is stable. The drop suffix
    // (when dropReason or dropLocation != 0) is built per-packet on top of the cached
    // bytes. The cache is bounded so a pathological capture (e.g., spoofed componentIds)
    // can't grow it without limit; on overflow the build path runs but skips caching.
    // Accessed only under _writeLock.
    private readonly Dictionary<long, byte[]> _commentCache = new Dictionary<long, byte[]>(256);
    private const int CommentCacheCap = 10000;

    // File rotation state.
    private long _maxFileSizeBytes;     // 0 = no rotation
    private int _numFiles;              // total files in rotation (>=1). 1 = no rotation suffix.
    private int _currentFileIndex;      // 1-based current file index
    private long _currentFileBytes;     // bytes written to current file (tracked for rotation)
    private string _baseDirectory;      // directory portion of _fileName
    private string _baseStem;           // file name without extension
    private string _baseExt;            // file extension (including dot)
    private bool _rotationEnabled;

    public bool IsActive { get { return _isActive; } }
    public string FileName { get { return _fileName; } }
    public long PacketCount { get { return Interlocked.Read(ref _packetCount); } }
    /// <summary>
    /// Number of packets the async file ring rejected because the writer thread couldn't
    /// keep up. Non-zero means the pcapng file is missing data.
    /// </summary>
    public long FileDroppedCount { get { return _fileRing != null ? _fileRing.DroppedCount : 0L; } }

    /// <summary>
    /// Opens a pcapng file for writing. Defaults to async mode (writer thread + ring buffer)
    /// for non-blocking writes from the callback. Set asyncMode=false only when you require
    /// guaranteed write-before-callback-return semantics (rare).
    /// </summary>
    /// <param name="fileName">Full path to the output .pcapng file.</param>
    /// <param name="asyncMode">True (default): writer thread; False: inline on callback thread.</param>
    /// <param name="ringCapacity">Ring buffer capacity for async mode (rounded up to power of 2).</param>
    /// <param name="flushPerBatch">True: flush BinaryWriter after each drained batch (durability vs throughput).</param>
    /// <param name="maxFileSizeBytes">Max bytes per file before rotation. 0 disables rotation.</param>
    /// <param name="numFiles">Number of files in the rotation. 1 = no rotation suffix. >1 = circular rotation (.001, .002, ...).</param>
    public void Start(string fileName, bool asyncMode, int ringCapacity, bool flushPerBatch, long maxFileSizeBytes, int numFiles)
    {
        if (_isActive) return;

        _fileName = fileName;
        _stopWriter = false;
        _packetCount = 0;
        _useAsyncWriter = asyncMode;
        _flushPerBatch = flushPerBatch;
        _maxFileSizeBytes = maxFileSizeBytes;
        _numFiles = numFiles < 1 ? 1 : numFiles;
        _rotationEnabled = maxFileSizeBytes > 0 && _numFiles > 1;
        _currentFileIndex = 1;
        _currentFileBytes = 0;

        // Split user path into directory/stem/ext so we can build .NNN suffixes for rotation.
        _baseDirectory = System.IO.Path.GetDirectoryName(_fileName) ?? "";
        _baseStem = System.IO.Path.GetFileNameWithoutExtension(_fileName);
        _baseExt = System.IO.Path.GetExtension(_fileName);
        if (string.IsNullOrEmpty(_baseExt)) _baseExt = ".pcapng";

        if (!string.IsNullOrEmpty(_baseDirectory) && !System.IO.Directory.Exists(_baseDirectory))
        {
            System.IO.Directory.CreateDirectory(_baseDirectory);
        }

        OpenCurrentFile();

        _isActive = true;

        if (asyncMode)
        {
            // Round up to power of 2.
            int cap = 1;
            while (cap < ringCapacity) cap <<= 1;
            _fileRing = new SpscPacketRingBuffer(cap);
            _drainBuf = new PSPacketData[Math.Min(cap, 4096)];
            _writerThread = new Thread(WriterLoop);
            _writerThread.IsBackground = true;
            _writerThread.Priority = ThreadPriority.BelowNormal;
            _writerThread.Name = "PcapngWriter";
            _writerThread.Start();
        }
    }

    /// <summary>
    /// Backwards-compatible overload — no rotation.
    /// </summary>
    public void Start(string fileName, bool asyncMode, int ringCapacity, bool flushPerBatch)
    {
        Start(fileName, asyncMode, ringCapacity, flushPerBatch, 0, 1);
    }

    /// <summary>
    /// Backwards-compatible overload — defaults flushPerBatch=false, no rotation.
    /// </summary>
    public void Start(string fileName, bool asyncMode, int ringCapacity)
    {
        Start(fileName, asyncMode, ringCapacity, false, 0, 1);
    }

    /// <summary>
    /// Builds the path for a rotation file index. When rotation is disabled, returns _fileName as-is.
    /// </summary>
    private string BuildFilePath(int index)
    {
        if (!_rotationEnabled) return _fileName;
        // Insert .NNN suffix between stem and extension: foo.pcapng -> foo.001.pcapng
        string indexed = _baseStem + "." + index.ToString("D3") + _baseExt;
        if (string.IsNullOrEmpty(_baseDirectory)) return indexed;
        return System.IO.Path.Combine(_baseDirectory, indexed);
    }

    /// <summary>
    /// Opens the current file (overwriting any existing) and writes SHB + IDB headers.
    /// Tracks the bytes written so rotation thresholds account for them.
    /// </summary>
    private void OpenCurrentFile()
    {
        _currentFilePath = BuildFilePath(_currentFileIndex);
        _fileStream = new System.IO.FileStream(_currentFilePath, System.IO.FileMode.Create,
            System.IO.FileAccess.Write, System.IO.FileShare.Read, 65536);
        _binaryWriter = new System.IO.BinaryWriter(_fileStream);

        // Reset byte counter and write headers.
        _currentFileBytes = 0;
        long before = _fileStream.Position;
        WriteSHB();
        WriteIDB();
        _currentFileBytes = _fileStream.Position - before;
    }

    /// <summary>
    /// Rotates to the next file in the circular sequence. Must be called under _writeLock.
    /// </summary>
    private void RotateFile()
    {
        if (_binaryWriter != null)
        {
            _binaryWriter.Flush();
            _binaryWriter.Close();
            _binaryWriter = null;
        }
        if (_fileStream != null)
        {
            _fileStream.Close();
            _fileStream = null;
        }
        // Circular: 1..numFiles..1..numFiles...
        _currentFileIndex++;
        if (_currentFileIndex > _numFiles) _currentFileIndex = 1;
        OpenCurrentFile();
    }

    /// <summary>
    /// Enqueues a packet for writing (async mode) or writes directly (sync mode).
    /// Called from the pktmon callback thread — must be fast.
    /// </summary>
    public void WritePacket(PSPacketData packet)
    {
        if (!_isActive) return;

        if (_useAsyncWriter)
        {
            _fileRing.Enqueue(packet);
        }
        else
        {
            WritePacketDirect(packet);
        }
    }

    /// <summary>
    /// Stops the writer, flushes all remaining data, and closes the file.
    /// Idempotent — safe to call more than once.
    /// </summary>
    public void Stop()
    {
        if (!_isActive) return;
        _isActive = false;

        bool writerJoined = true;
        if (_useAsyncWriter)
        {
            _stopWriter = true;
            // Wake the writer thread in case it's sleeping.
            if (_fileRing != null) _fileRing.WakeWaiters();
            if (_writerThread != null)
            {
                writerJoined = _writerThread.Join(5000);
                _writerThread = null;
            }
            // Only drain the file ring ourselves if the writer thread actually exited.
            // If it timed out, the writer is still running and would race us as a second
            // consumer on the SPSC ring (and on the file stream).
            if (writerJoined && _fileRing != null)
            {
                int remaining;
                try
                {
                    while ((remaining = _fileRing.DrainTo(_drainBuf)) > 0)
                    {
                        for (int i = 0; i < remaining; i++)
                        {
                            WritePacketDirect(_drainBuf[i]);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _lastError = "Final drain failed: " + ex.Message;
                }
            }
            else if (!writerJoined)
            {
                _lastError = "PcapngWriter thread did not exit within 5s; remaining packets may be lost.";
            }
        }

        // Close the file under _writeLock so we can never race a sync-mode caller (or a
        // still-running writer thread that we failed to join) doing w.Write/Flush.
        lock (_writeLock)
        {
            try
            {
                if (_binaryWriter != null)
                {
                    _binaryWriter.Flush();
                    _binaryWriter.Close();
                    _binaryWriter = null;
                }
                if (_fileStream != null)
                {
                    _fileStream.Close();
                    _fileStream = null;
                }
            }
            catch (Exception ex)
            {
                _lastError = (_lastError == null) ? ("Close failed: " + ex.Message)
                                                  : (_lastError + " | Close failed: " + ex.Message);
            }
        }
    }

    private void WriterLoop()
    {
        try
        {
            while (!_stopWriter)
            {
                int count = 0;
                try
                {
                    count = _fileRing.DrainTo(_drainBuf);
                    if (count > 0)
                    {
                        for (int i = 0; i < count; i++)
                        {
                            WritePacketDirect(_drainBuf[i]);
                        }
                        if (_flushPerBatch)
                        {
                            // Flush under _writeLock so Stop()'s close cannot race with us.
                            lock (_writeLock)
                            {
                                if (_binaryWriter != null) _binaryWriter.Flush();
                            }
                        }
                    }
                    else
                    {
                        // Wait on the file ring's signal instead of fixed-interval sleep — produces
                        // immediate wakeup when a packet arrives and zero CPU at idle.
                        _fileRing.WaitForPackets(100);
                    }
                }
                catch (Exception ex)
                {
                    // Record the first error and stop further writes for this writer instance.
                    // Common causes: disk full, ACL change, file locked by AV. Without this,
                    // an exception would terminate the thread and Stop() would then re-throw
                    // from the post-join drain, escaping Start-Pspkt's finally block.
                    _lastError = ex.GetType().Name + ": " + ex.Message;
                    _isActive = false;
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            // Last-resort safety net so the thread method never throws.
            _lastError = ex.GetType().Name + ": " + ex.Message;
            _isActive = false;
        }
    }

    // opt_comment code and opt_endofopt
    private const ushort OPT_COMMENT = 1;
    private const ushort OPT_ENDOFOPT = 0;

    // Direction names matching PKTMON_DIRECTION_TAG enum
    private static readonly string[] DirectionNames = new string[] {
        "Unknown", "In", "Out", "Rx", "Tx", "Ingress", "Egress", "Drop"
    };

    private void WritePacketDirect(PSPacketData pkt)
    {
        if (pkt.Data == null || pkt.PacketLength == 0 || pkt.PacketOffset >= pkt.DataSize) return;

        uint capturedLen = Math.Min(pkt.PacketLength, pkt.DataSize - pkt.PacketOffset);
        if (capturedLen == 0) return;

        // Parse metadata for timestamp and comment.
        long tsHigh64 = 0;
        long tsLow64 = 0;
        bool hasComment = pkt.MetadataOffset + 40 <= pkt.DataSize;
        int commentLen = 0; // length of comment bytes in _commentScratch (0 = no comment)

        ushort direction = 0, componentId = 0, edgeId = 0, processor = 0;
        uint dropReason = 0, dropLocation = 0;

        if (hasComment)
        {
            int mo = (int)pkt.MetadataOffset;
            byte[] d = pkt.Data;
            // Extract fields from PACKETMONITOR_STREAM_METADATA. Inline LE reads avoid
            // BitConverter call/bounds-check overhead in the file-writer hot path.
            direction    = (ushort)(d[mo + 12] | (d[mo + 13] << 8));
            componentId  = (ushort)(d[mo + 16] | (d[mo + 17] << 8));
            edgeId       = (ushort)(d[mo + 18] | (d[mo + 19] << 8));
            dropReason   = (uint)(d[mo + 22] | (d[mo + 23] << 8) | (d[mo + 24] << 16) | (d[mo + 25] << 24));
            dropLocation = (uint)(d[mo + 26] | (d[mo + 27] << 8) | (d[mo + 28] << 16) | (d[mo + 29] << 24));
            processor    = (ushort)(d[mo + 30] | (d[mo + 31] << 8));
        }

        // Use QPC-based timestamp for per-packet precision (each callback gets a unique QPC value).
        // Falls back to metadata FILETIME, then DateTime.UtcNow.
        long fileTimeForTs = 0;
        if (pkt.QpcTimestamp != 0)
        {
            fileTimeForTs = PktMonApi.QpcToFiletime(pkt.QpcTimestamp);
        }
        else if (hasComment)
        {
            // Inline LE Int64 read.
            int to = (int)pkt.MetadataOffset + 32;
            byte[] d = pkt.Data;
            fileTimeForTs =
                ((long)d[to])
                | ((long)d[to + 1] << 8)
                | ((long)d[to + 2] << 16)
                | ((long)d[to + 3] << 24)
                | ((long)d[to + 4] << 32)
                | ((long)d[to + 5] << 40)
                | ((long)d[to + 6] << 48)
                | ((long)d[to + 7] << 56);
        }

        if (fileTimeForTs > 116444736000000000L)
        {
            long micros = (fileTimeForTs - 116444736000000000L) / 10;
            tsHigh64 = micros >> 32;
            tsLow64 = micros & 0xFFFFFFFF;
        }

        if (tsHigh64 == 0 && tsLow64 == 0)
        {
            long ticks = DateTime.UtcNow.Ticks - 621355968000000000L;
            long micros = ticks / 10;
            tsHigh64 = micros >> 32;
            tsLow64 = micros & 0xFFFFFFFF;
        }

        lock (_writeLock)
        {
            var w = _binaryWriter;
            if (w == null) return;

            // Build opt_comment into reusable scratch buffer under the lock.
            // Skipped entirely when metadata isn't present, preserving the fast path.
            if (hasComment)
            {
                // Pack the four metadata shorts into a single long key. componentId and
                // direction are unsigned shorts; edgeId is read as ushort from metadata
                // so it fits cleanly. Processor is a ushort. 64 bits is enough for all four.
                long cacheKey = ((long)componentId << 48)
                              | ((long)(ushort)edgeId << 32)
                              | ((long)direction << 16)
                              | (long)processor;

                byte[] prefixBytes;
                if (!_commentCache.TryGetValue(cacheKey, out prefixBytes))
                {
                    // Build the stable prefix (up to "CPU: ${processor}") once per tuple.
                    string dirName = (direction < DirectionNames.Length) ? DirectionNames[direction] : null;
                    string edgeName = (edgeId == 1) ? "Ingress" : (edgeId == 2) ? "Egress" : null;
                    string compName = null;
                    string compGroup = "";
                    int compParentId = 0;
                    ComponentInfo ci;
                    if (_componentMap.TryGetValue((int)componentId, out ci))
                    {
                        compName = ci.Name;
                        compGroup = ci.Group ?? "";
                        compParentId = ci.ParentId;
                    }

                    var sb = _commentSb;
                    sb.Length = 0;
                    sb.Append("Group:     ").Append(compGroup).Append(" (").Append(compParentId).Append(")\n");
                    sb.Append("Component: ");
                    if (compName != null) sb.Append(compName); else sb.Append(componentId);
                    sb.Append(" (").Append(componentId).Append(")\n");
                    sb.Append("Edge:      ");
                    if (edgeName != null) sb.Append(edgeName); else sb.Append(edgeId);
                    sb.Append('\n');
                    sb.Append("Direction: ");
                    if (dirName != null) sb.Append(dirName); else sb.Append(direction);
                    sb.Append('\n');
                    sb.Append("CPU:       ").Append(processor);

                    string s = sb.ToString();
                    prefixBytes = _utf8.GetBytes(s);
                    if (_commentCache.Count < CommentCacheCap)
                    {
                        _commentCache[cacheKey] = prefixBytes;
                    }
                }

                // Copy cached prefix bytes into scratch. For the common case (no drop)
                // this is the entire comment — no SB build, no per-packet UTF-8 encode,
                // no per-packet string allocation.
                bool hasDrop = (dropReason != 0 || dropLocation != 0);
                int reserved = prefixBytes.Length + (hasDrop ? 64 : 0);
                if (reserved > _commentScratch.Length)
                {
                    _commentScratch = new byte[reserved + 64];
                }
                Buffer.BlockCopy(prefixBytes, 0, _commentScratch, 0, prefixBytes.Length);
                commentLen = prefixBytes.Length;

                if (hasDrop)
                {
                    // Drop suffix is built per packet because (dropReason, dropLocation)
                    // are unbounded in principle; caching them would defeat the cap.
                    var sb = _commentSb;
                    sb.Length = 0;
                    sb.Append("\nDrop:      reason=0x").Append(dropReason.ToString("X"))
                      .Append(" location=0x").Append(dropLocation.ToString("X"));
                    string s = sb.ToString();
                    int suffixMax = _utf8.GetMaxByteCount(s.Length);
                    if (commentLen + suffixMax > _commentScratch.Length)
                    {
                        byte[] grown = new byte[commentLen + suffixMax + 64];
                        Buffer.BlockCopy(_commentScratch, 0, grown, 0, commentLen);
                        _commentScratch = grown;
                    }
                    int suffixLen = _utf8.GetBytes(s, 0, s.Length, _commentScratch, commentLen);
                    commentLen += suffixLen;
                }
            }

            // Calculate block length.
            // EPB fixed: type(4) + totalLen(4) + ifId(4) + tsHi(4) + tsLo(4) + capLen(4) + origLen(4) = 28
            // + paddedPacketData + options + totalLen(4) = 32 + paddedData + optionsLen
            uint paddedLen = (capturedLen + 3u) & ~3u;
            uint optionsLen = 0;
            int commentPadBytes = 0;
            if (commentLen > 0)
            {
                int commentPaddedLen = (commentLen + 3) & ~3;
                commentPadBytes = commentPaddedLen - commentLen;
                // opt_comment header(4) + padded value + opt_endofopt(4)
                optionsLen = 4u + (uint)commentPaddedLen + 4u;
            }
            uint blockLen = 32u + paddedLen + optionsLen;

            // Rotate file BEFORE writing this packet if adding it would exceed the threshold.
            // This keeps every packet's EPB intact within a single file.
            if (_rotationEnabled && _currentFileBytes + blockLen > _maxFileSizeBytes)
            {
                RotateFile();
                w = _binaryWriter;
                if (w == null) return;
            }

            w.Write(EPB_TYPE);                  // block type
            w.Write(blockLen);                  // total block length
            w.Write((uint)0);                   // interface ID
            w.Write((uint)tsHigh64);            // timestamp high
            w.Write((uint)tsLow64);             // timestamp low
            w.Write(capturedLen);               // captured packet length
            w.Write(pkt.PacketLength);          // original packet length
            w.Write(pkt.Data, (int)pkt.PacketOffset, (int)capturedLen);

            // Packet data padding (write in one call instead of byte-by-byte).
            int pad = (int)(paddedLen - capturedLen);
            if (pad > 0) w.Write(_zeroPad, 0, pad);

            // Options section.
            if (commentLen > 0)
            {
                // opt_comment
                w.Write(OPT_COMMENT);                           // option code
                w.Write((ushort)commentLen);                     // option length (unpadded)
                w.Write(_commentScratch, 0, commentLen);         // option value
                if (commentPadBytes > 0) w.Write(_zeroPad, 0, commentPadBytes);

                // opt_endofopt
                w.Write(OPT_ENDOFOPT);                          // option code
                w.Write((ushort)0);                             // option length
            }

            w.Write(blockLen);                  // total block length (repeated)

            // Track bytes written for rotation accounting.
            _currentFileBytes += blockLen;
        }

        Interlocked.Increment(ref _packetCount);
    }

    private void WriteSHB()
    {
        // Section Header Block with opt_comment identifying pspkt.
        byte[] comment = System.Text.Encoding.UTF8.GetBytes("pspkt capture via Windows Packet Monitor (pktmon)");
        uint commentPaddedLen = (uint)((comment.Length + 3) & ~3);
        uint optionsLen = 4u + commentPaddedLen + 4u; // opt_comment + opt_endofopt
        uint blockLen = 28u + optionsLen;
        _binaryWriter.Write(SHB_TYPE);
        _binaryWriter.Write(blockLen);
        _binaryWriter.Write(PCAPNG_BYTE_ORDER_MAGIC);
        _binaryWriter.Write(PCAPNG_VERSION_MAJOR);
        _binaryWriter.Write(PCAPNG_VERSION_MINOR);
        _binaryWriter.Write(SECTION_LENGTH_UNSPECIFIED);
        // opt_comment
        _binaryWriter.Write(OPT_COMMENT);
        _binaryWriter.Write((ushort)comment.Length);
        _binaryWriter.Write(comment);
        int pad = (int)(commentPaddedLen - comment.Length);
        for (int p = 0; p < pad; p++) _binaryWriter.Write((byte)0);
        // opt_endofopt
        _binaryWriter.Write(OPT_ENDOFOPT);
        _binaryWriter.Write((ushort)0);
        _binaryWriter.Write(blockLen);
    }

    private void WriteIDB()
    {
        // Interface Description Block with if_tsresol option (microsecond = 6).
        // if_tsresol: code(2) + len(2) + value(1) + pad(3) = 8 bytes
        // opt_endofopt: code(2) + len(2) = 4 bytes
        // Options total = 12 bytes
        uint optionsLen = 12u;
        uint blockLen = 20u + optionsLen;  // 20 = type(4)+len(4)+linkType(2)+reserved(2)+snapLen(4)+trailingLen(4)
        _binaryWriter.Write(IDB_TYPE);
        _binaryWriter.Write(blockLen);
        _binaryWriter.Write(LINKTYPE_ETHERNET);
        _binaryWriter.Write((ushort)0); // reserved
        _binaryWriter.Write((uint)0);   // snap length (0 = no limit)
        // if_tsresol: code=9, len=1, value=6 (10^-6 = microseconds), pad to 4
        _binaryWriter.Write((ushort)9);
        _binaryWriter.Write((ushort)1);
        _binaryWriter.Write((byte)6);
        _binaryWriter.Write((byte)0); _binaryWriter.Write((byte)0); _binaryWriter.Write((byte)0);
        // opt_endofopt
        _binaryWriter.Write(OPT_ENDOFOPT);
        _binaryWriter.Write((ushort)0);
        _binaryWriter.Write(blockLen);
    }

    /// <summary>
    /// Gets whether this writer instance is enabled on the PktMonApi callback.
    /// </summary>
    public static PcapngWriter ActiveWriter
    {
        get { return PktMonApi.FileWriter; }
    }
}