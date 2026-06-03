# Architecture

A high-level tour of how pspkt captures, parses, and renders packets — useful when extending the module or debugging unexpected behavior.

## Layers

```
┌────────────────────────────────────────────────────────────────────┐
│  PowerShell (user-facing)                                          │
│    function/PspktSession.psm1  — Start-Pspkt, Stop-Pspkt, ...      │
│    function/PspktFilter.psm1   — New/Set/Add/Remove-PspktFilter    │
│    function/PspktComponent.psm1 — Get/Set/Add/Remove-PspktComponent│
│    Parsers/libParser.psm1      — display/color profile setters     │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  PowerShell classes (class/*.psm1)                                 │
│    pspktSession, pspktFilter, pspktComponent                       │
│    PktmonRealTimeStream  (drain wrapper)                           │
│    Enums (PKTMON_DROP_REASON, PKTMON_DROP_LOCATION, ...)           │
│    Type accelerator registration                                   │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  C# interop (class/pspkt.cs)  — compiled by Add-Type at load       │
│    P/Invoke into pktmonapi.dll                                     │
│    PktMonApi.PacketDataCallBack  (native callback)                 │
│    SpscPacketRingBuffer          (lock-free queue + signaling)     │
│    PacketBytePool                (bucket pool for packet byte[])   │
│    PcapngWriter                  (async writer + rotation)         │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  C# formatters (Parsers/*.cs)                                      │
│    PacketLineFormatter.FormatBatch / FormatSinglePacket            │
│    parserCommon.cs   — helpers, colorize                           │
│    Transport/tcp.cs  — TcpParser                                   │
│    Application/dns.cs, smb2.cs                                     │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  Native Windows: pktmonapi.dll  →  pktmon.sys                      │
└────────────────────────────────────────────────────────────────────┘
```

## Module load order

`pspkt.psm1` imports submodules in a hard-coded order (do not use `Get-ChildItem`):

```
class/loader.psm1
  └─ Add-Type compiles class/pspkt.cs (P/Invoke + ring buffer + writer)
class/pspktEnum.psm1
class/pspktUtil.psm1
class/pspktTypes.psm1
class/pspktPacketParser.psm1
class/pspktClass.psm1
Parsers/libParser.psm1
  └─ Add-Type compiles Parsers/parserCommon.cs + protocol parsers + PacketLineFormatter
function/PspktFilter.psm1
function/PspktComponent.psm1
function/PspktSession.psm1
```

Each `class/*.psm1` file registers its PowerShell types as type accelerators on load and unregisters them on module removal.

## Capture data flow

```
                          ┌────────────────────────┐
                          │  pktmon.sys (kernel)   │
                          └───────────┬────────────┘
                                      │ packets
                                      ▼
                  ┌─────────────────────────────────────┐
                  │  pktmonapi.dll → PacketDataCallBack │  ◄── producer thread
                  │  (class/pspkt.cs:409)               │
                  └───────────┬─────────────────────────┘
                              │ snapshot FileWriter once,
                              │ rent byte[] from pool if no writer,
                              │ allocate fresh if pool would race
                              ▼
                  ┌─────────────────────────────────────┐
                  │  ICMP filter check (if active)      │
                  │  PacketLineFormatter                │
                  │   .ShouldDropForIcmpFilter()        │
                  │  → walks IPv6 ext headers, drops    │
                  │    non-echo / non-NDP packets       │
                  │    BEFORE ring enqueue + file write │
                  └───────────┬─────────────────────────┘
                              ▼
       ┌──────────────────────────────────────────────────────┐
       │  SpscPacketRingBuffer  (lock-free SPSC + AutoReset)  │
       │  cache-line-padded head/tail                         │
       │  capacity: BufferSizeMultiplier × 1,048,576          │
       └─┬────────────────────────────────────────────────┬───┘
         │                                                │
         │ if FileWriter set, enqueue                     │ consumer loop
         │ to file ring too                               │ (PS thread)
         ▼                                                ▼
  ┌──────────────────┐                       ┌────────────────────────────┐
  │ PcapngWriter     │                       │ PktmonRealTimeStream       │
  │  - writer thread │                       │   .DrainAllRawPackets()    │
  │  - async ring    │                       └──────────┬─────────────────┘
  │  - rotation      │                                  │
  │  - flushPerBatch │                                  ▼
  └────────┬─────────┘                       ┌────────────────────────────┐
           │                                 │ PacketLineFormatter        │
           ▼                                 │   .FormatBatch(buffer, n)  │
    [...].pcapng file                        │   → BatchResult            │
                                             └──────────┬─────────────────┘
                                                        │
                                                        ▼
                                       ┌────────────────────────────────┐
                                       │  ReturnPacketBuffers (pool)    │
                                       │  [Console]::Write(result.Out)  │
                                       │  Handle TriggerAction (stop/   │
                                       │  pause)                        │
                                       └────────────────────────────────┘
```

## Performance design summary

| Concern | Mechanism |
|---|---|
| Producer-thread allocations | `PacketBytePool` rents from per-bucket `ConcurrentStack<byte[]>` |
| Producer→consumer signal | `AutoResetEvent` set only on empty→non-empty transition |
| False sharing on ring indices | `_head`/`_tail` wrapped in 128-byte padded structs |
| File I/O blocking the callback | `PcapngWriter` always async — writer thread drains a second ring |
| pcapng comment building | Reused per-writer `StringBuilder` + `byte[]` scratch under `_writeLock` |
| Per-segment colorize string allocation | `PacketFormatter.AppendColorized` writes directly into the per-batch SB |
| Outer `+` concat chains | `[ThreadStatic]` scratch SB in `FormatDefaultLine` / `FormatMinimalLine` |
| Per-octet `.ToString()` in IPv4 | Precomputed `DecBytes[256]` lookup table |
| Detail-mode payload slice allocs | `TcpParser.FormatTcpOptions(byte[], offset, length)` range overload |
| Pcapng file size limit | `-FileSize` + `-NumFiles` rotation in `PcapngWriter` |
| BitConverter overhead in callback | Inline bit-shift LE reads |
| ICMP type filtering (`-Ping`/`-NDP` etc.) | Producer-side `PacketLineFormatter.ShouldDropForIcmpFilter` runs in the callback so filtered packets never enter the ring buffer and are never written to pcapng |
| IPv6 extension headers (HBH, Routing, Frag, AH, DOH) | `PacketParseHelper.FindIPv6UpperLayer` walks the chain so the filter and the formatters correctly classify MLDv2 reports and outbound packets that Windows prefixes with a Hop-by-Hop header |

## Key C# types

| Type | Purpose |
|---|---|
| `PktMonApi` | Static facade: P/Invoke, ring buffer config, wait/signal, drop-trigger config |
| `SpscPacketRingBuffer` | Lock-free queue between callback and consumer (and between callback and file writer) |
| `PSPacketData` | Struct carrying packet bytes + metadata + QPC timestamp + IsPooledBuffer ownership flag |
| `PacketBytePool` | Bucket pool of `byte[]` for packet receive |
| `PcapngWriter` | Async pcapng writer with rotation and decoupled flush |
| `PacketLineFormatter` | The bulk formatter — `FormatBatch` is the C# entry point for the consumer loop |
| `PacketFormatter` | Colorize / FormatTransportLine / FormatMinimalColors helpers |
| `PacketParseHelper` | Low-level byte readers and address formatters |
| `TcpParser`, `DnsParser`, `Smb2Parser` | Protocol-specific detailed formatters |

## Where the PowerShell layer touches the hot path

- **Consumer loop** (`function\PspktSession.psm1::Start-Pspkt`): drains the C# ring, calls `FormatBatch`, writes output, handles trigger actions. Wakes via `[PktMonApi]::WaitForPackets($PollingIntervalMs)` (signaled).
- **Setup**: registers components into the `PacketLineFormatter` component map; configures drop triggers (`SetDropTriggers`); sizes the ring buffer (`ConfigureRingBuffer`); marks capture active (`SetCaptureActive($true)`).
- **Teardown**: `SetCaptureActive($false)` wakes the consumer; pcapng `Stop()` drains its file ring and closes files.

No PowerShell code runs **per packet** during a capture.

## See also

- [Examples](./Examples.md)
- [Drop Triggers](./Drop-Triggers.md)
