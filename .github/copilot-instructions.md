# pspkt – Copilot Instructions

## What is pspkt

pspkt is a PowerShell module that wraps the Windows Packet Monitor (`pktmon`) native API (`pktmonapi.dll`) via P/Invoke, providing cmdlets for real-time packet capture, filtering, and component enumeration. It requires an elevated (Administrator) PowerShell session and targets **Windows PowerShell 5.1+** (Desktop edition) as well as PowerShell 7+ (Core edition).

## Compatibility

This module must remain compatible with **Windows PowerShell 5.1**. Avoid PS 7+-only syntax:

- No ternary operator (`$x ? $a : $b`) — use `if`/`else`
- No null-coalescing (`??`) or null-conditional (`?.`)
- No pipeline chain operators (`&&`, `||`)
- No `clean {}` block in functions
- Use `[type]::new()` constructors (supported since 5.0), but not `[type]::new` as a method reference

## Architecture

### Type system layers

1. **C# interop** (`class/pspkt.cs`) – P/Invoke declarations for `pktmonapi.dll`, structs (`PACKETMONITOR_IP_ADDRESS`, `PSPacketData`, etc.), the native callback, the lock-free `SpscPacketRingBuffer`, `PacketBytePool`, and async `PcapngWriter`. Compiled at module load via `Add-Type` in `class/loader.psm1`.
2. **PowerShell classes** (`class/*.psm1`) – Domain objects built on top of the C# types:
   - `pspkt` – core handle lifecycle (initialize / uninitialize / enum data sources / create sessions)
   - `pspktSession`, `pspktFilter`, `pspktComponent` – session, filter, and component wrappers
   - Packet-parsing hierarchy: `PacketData` → `ParsedPacket` → link-layer (`EthernetII` / `IEEE80211`) → `IPv4Data` → protocol (`TCPData` / `UDPData` / `ICMPData`) — used by tests/scratch, **not** by `Start-Pspkt`'s hot path
   - Utility classes: `BitUtils` (big-endian helpers), `PAUtils` (MAC address conversion)
   - Enums: `pspktEnum.psm1` (protocol numbers, ICMP types, pktmon direction/drop enums)
3. **Real-time formatters** (`Parsers/`) – The hot-path display/file-write pipeline:
   - `Parsers/parserCommon.cs` + `Parsers/packetLineFormatter.cs` + protocol-specific `.cs` files (`Transport/tcp.cs`, `Application/dns.cs`, `Application/smb2.cs`) – compiled by `Add-Type` inside `Parsers/libParser.psm1`. `PacketLineFormatter.FormatBatch` is the C# entry point the consumer loop calls.
   - `Parsers/{DataLink,Network,Transport,Application}/*.psm1` – per-protocol PowerShell helpers loaded by `libParser.psm1` (ethernet, ipv4/ipv6, icmp, ndp, arp, tcp, dns, dhcp, http, smb2).
   - `Parsers/libParser.psm1` – owns display state (`$script:DetailLevel`, `$script:ShowTimestamp`, `$script:ColorScheme`, `$script:ComponentMap`) and exports the `*-Pspkt*ColorProfile`, `*-PspktDetail*`, `*-PspktShowTimestamp`, `*-PspktComponentMap`, and `Get-PspktCaptureHeader` cmdlets.
   - `Parsers/ColorProfiles/*.psd1` – built-in color schemes; `active.txt` records the currently active profile name.
4. **Public functions** (`function/*.psm1`) – Verb-Noun cmdlets (`New-`, `Get-`, `Set-`, `Add-`, `Remove-`) for Filter, Component, and Session, plus `Start-Pspkt` / `Stop-Pspkt`. These are the user-facing capture/management API.

### Hot path: no PowerShell per packet

`Start-Pspkt`'s consumer loop is intentionally minimal: it blocks on `[PktMonApi]::WaitForPackets()`, drains the C# ring with `PktmonRealTimeStream.DrainAllRawPackets()`, calls `[PacketLineFormatter]::FormatBatch(...)`, and `[Console]::Write`s the result. **No PowerShell code runs per packet during a capture.** When extending the formatter:

- Add per-packet logic in C# (`Parsers/*.cs`), not in the PS consumer loop.
- ICMP/quick-filter drop checks live in `PacketLineFormatter.ShouldDropForIcmpFilter` so dropped packets never enter the ring buffer or pcapng file.
- The producer (native callback) rents byte buffers from `PacketBytePool`; the consumer must call the pool-return helper after `FormatBatch` so buffers are recycled.
- File writes are decoupled: when a `FileWriter` is set, the callback enqueues into the writer's own ring; `PcapngWriter` flushes on its own thread.

### Module loading order is critical

`pspkt.psm1` loads sub-modules in a **specific, hard-coded order** to satisfy class dependencies. **Do not** use `Get-ChildItem` to discover and load modules dynamically – the comment in `pspkt.psm1` explains why.

The load sequence (see `$loadList` in `pspkt.psm1`) is:
```
class/loader.psm1   (Add-Type compiles class/pspkt.cs)
  → class/pspktEnum.psm1
  → class/pspktUtil.psm1
  → class/pspktTypes.psm1
  → class/pspktPacketParser.psm1
  → class/pspktClass.psm1
  → Parsers/libParser.psm1   (Add-Type compiles parserCommon.cs + protocol .cs + PacketLineFormatter; also Import-Modules every Parsers/{DataLink,Network,Transport,Application}/*.psm1)
  → function/PspktFilter.psm1
  → function/PspktComponent.psm1
  → function/PspktSession.psm1
```

When adding a new class, parser, or function module, insert it in the `$loadList` array in `pspkt.psm1` at the correct position based on its dependencies. Per-protocol parser modules (`Parsers/Network/myproto.psm1`, etc.) are loaded by `libParser.psm1` itself, not by `pspkt.psm1`.

### PowerShell ↔ C# bridge

The PS layer pushes state into the compiled C# formatter at load/configure time so the hot path stays pure C#:

- **Drop reason / location names** – `libParser.psm1` enumerates `[PKTMON_DROP_REASON]` / `[PKTMON_DROP_LOCATION]` and calls `[PacketLineFormatter]::RegisterDropReason` / `RegisterDropLocation` so the C# formatter can render symbolic names.
- **Color scheme** – `Sync-PspktFormatterColors` flattens the PS hashtable scheme into a 12-element `string[]` of SGR codes and calls `[PacketFormatter]::InitColorScheme($sgrs, $resetSgr)`. Call this after any change to `$script:ColorScheme`.
- **Component map** – `Register-PspktComponentMap` / `Clear-PspktComponentMap` populate the C# formatter's component-id → friendly-name table used in capture output.

### Type accelerators

Every `class/*.psm1` file registers its types as PowerShell type accelerators on load and removes them on module removal. When adding a new class file:

1. Define `$ExportableTypes` as an array of the types in the file.
2. Use `[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')` to register them.
3. Set up `$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove` to unregister them.

Copy the boilerplate block from the bottom of any existing `class/*.psm1` file (e.g., `loader.psm1`).

### Script-scoped session collection

`$script:PspktSessions` (an `ArrayList` in `pspkt.psm1`) tracks active sessions. All session management goes through `Add-/Get-/Remove-PspktSession`.

## Conventions

- **Verb-Noun cmdlets** follow the pattern: public functions use `Update-Pspkt*Internal` as a private helper that takes all settable parameters, called by the corresponding `New-` / `Set-` public function via splatting (`@PSBoundParameters`). The `New-` function creates the object then calls `Update-*Internal`; `Set-` takes an existing object and calls the same helper.
- **Triple export requirement** – When adding or renaming an exported function, update all three locations:
  1. `Export-ModuleMember` at the bottom of the relevant `function/*.psm1` or `Parsers/libParser.psm1` file
  2. `Export-ModuleMember` at the bottom of `pspkt.psm1`
  3. `$allExportedCommands` array in `tests/pspkt.Unit.Tests.ps1` (Precheck tests validate this list)
- Every exported function must have **comment-based help** (`<# .SYNOPSIS ... #>`) immediately before the `function` keyword – the Precheck tests enforce this. The Precheck scanner reads a fixed `$filesToScan` allow-list in `tests/pspkt.Unit.Tests.ps1` (currently `pspkt.psm1`, `function/*.psm1`, `Parsers/libParser.psm1`, `Parsers/Application/smb2.psm1`); add new files holding exported functions to that list so their help blocks are validated.
- **Filtering parameters** default to `-match` (regex). Add an `-Exact` switch for literal equality when the parameter set supports both.
- Use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'` at module/script scope.
- Network byte-order conversions use `[BitUtils]::ToUInt16BigEndian()` / `ToUInt32BigEndian()` – not `[BitConverter]` directly for multi-byte network fields.
- Enum resolution uses `Resolve-PspktEnumValue` (in `function/PspktFilter.psm1`) to accept names, integers, and hex strings for enum-typed parameters. Use it for any new enum-backed cmdlet parameter so users can pass `'IPv4'`, `0x0800`, `'0x0800'`, `2048`, or `[ETHERTYPE]::IPv4` interchangeably.
- The module manifest `pspkt.psd1` declares `PowerShellVersion = '5.1'` and `CompatiblePSEditions = @('Desktop','Core')`; do not raise either without explicit justification.
- Ignore root-level dev scratch (`scratch.ps1`, `test.ps1`, `pspkt.psd1.bah`, `class/class speed test.ps1`) and the unloaded `function/PspktFilter-JAK-TOOLS.psm1` – they are not part of the shipped module surface.

## Testing

Tests use **Pester 5+** and live in `tests/`.

```powershell
# Run all applicable tests (Precheck when non-admin, Precheck + Unit when admin)
pwsh -File .\tests\Invoke-Tests.ps1

# Run only prechecks (no admin required, safe for CI)
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Precheck

# Run only unit tests (requires elevated shell)
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Unit

# Run a single test by name
Invoke-Pester -Path .\tests -Filter @{ FullName = '*converts IPv4*' }
```

- **Precheck** tests validate file presence, function definitions, help blocks, and the exported command list – no admin needed.
- **Unit** tests import the module (needs admin due to `#Requires -RunAsAdministrator`) and exercise command exports, parameter sets, and stateful behavior using `[IntPtr]::Zero` handles to avoid needing live pktmon sessions.
- Tests save/restore `$script:PspktSessions` in `BeforeAll`/`AfterAll` to avoid side effects.
- Tag tests with `@('Unit')` or `@('Precheck')` so the test runner can filter correctly.

## CI

GitHub Actions workflows in `.github/workflows/` use a matrix of `pwsh` (PS 7+) and `powershell` (Windows PS 5.1) shells to validate both editions. `ci-precheck.yml` runs Precheck tests on `windows-latest` for pushes and PRs. Unit tests require an elevated runner (see `ci-unit-elevated-example.yml`).
