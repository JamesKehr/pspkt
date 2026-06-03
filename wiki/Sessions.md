# Sessions

Session commands manage the lifecycle of a `pspktSession` object — the wrapper around a pktmon live session handle. Most users never call these directly; [`Start-Pspkt`](./Start-Pspkt.md) creates a session on demand. They're documented here for advanced workflows where you build a session, attach filters/components, and pipe it into `Start-Pspkt`.

| Command | Purpose |
|---|---|
| [`New-PspktSession`](#new-pspktsession) | Create a live pktmon session |
| [`Get-PspktSession`](#get-pspktsession) | Report the current pktmon status (via `pktmon status`) |
| [`Set-PspktSession`](#set-pspktsession) | Update mutable properties on a session |
| [`Stop-Pspkt`](#stop-pspkt) | Deactivate (or tear down) a session |

---

## New-PspktSession

### Synopsis
Creates a new live packet monitor session.

### Description
Initializes a `pspkt` instance, creates a live session, and returns it. The `pspkt` instance is stored on the session for lifecycle management. The caller is responsible for storing the returned session object.

### Syntax
```powershell
New-PspktSession -Name <string>
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Name` | `string` | Yes | Name for the new session. |

### Output
`pspktSession`

### Examples
```powershell
$s = New-PspktSession -Name 'forensics'
$s | Add-PspktFilter -Filter (New-PspktFilter -Name 'tls' -TransportProtocol TCP -Port1 443)
$s | Start-Pspkt -pl Detailed
```

---

## Get-PspktSession

### Synopsis
Gets the current packet monitor status.

### Description
Parses the output of `pktmon status` to report whether pktmon is actively capturing, what filters are configured, and what components are being monitored. This detects any active pktmon session — including sessions not created by pspkt or orphaned from a previous run.

### Syntax
```powershell
Get-PspktSession
```

### Output
`PSCustomObject` with properties: `Active`, `CaptureType`, `MonitoredComponents`, `Filters`.

### Example
```powershell
Get-PspktSession
# Active              : True
# CaptureType         : All
# MonitoredComponents : ...
# Filters             : ...
```

---

## Set-PspktSession

### Synopsis
Updates an existing session.

### Description
Applies bound parameters to an existing `pspktSession` object. Note: most properties (other than `Name`) only take effect at session restart.

### Syntax
```powershell
Set-PspktSession -Session <pspktSession> [-Name <string>] [-Active <bool>]
                 [-CaptureType <PspktCaptureType>] [-LogMode <PspktLogMode>]
                 [-PacketSize <uint32>] [-FileSize <uint32>] [-FileName <string>]
                 [-CountersOnly <bool>]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | Yes (pipeline) | The session to update. |
| `-Name` | `string` | No | New session name. |
| `-Active` | `bool` | No | Toggle session active state. |
| `-CaptureType` | `PspktCaptureType` | No | `All`, `Flow`, or `Drop`. |
| `-LogMode` | `PspktLogMode` | No | Stream mode (e.g. `RealTime`). |
| `-PacketSize` | `uint32` | No | Max bytes to log per packet. 0 = full packet. |
| `-FileSize` | `uint32` | No | Max log file size in MB (for log-mode sessions). |
| `-FileName` | `string` | No | Log file name (for log-mode sessions). |
| `-CountersOnly` | `bool` | No | Capture counters only without packet logging. |

### Output
`pspktSession`

---

## Stop-Pspkt

### Synopsis
Stops a packet monitor session.

### Description
Deactivates the pktmon session. Without `-Teardown`, the session can be restarted with `Start-Pspkt`. With `-Teardown`, the session handle is closed, the pktmon API is uninitialized, and the session object is no longer usable.

### Syntax
```powershell
Stop-Pspkt -Session <pspktSession> [-Teardown]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | Yes (pipeline) | The session to stop. |
| `-Teardown` | `switch` | No | Fully close the session and release all native resources. The session object cannot be reused after teardown. |

### Output
- Without `-Teardown`: `pspktSession`
- With `-Teardown`: nothing

### Examples
```powershell
# Deactivate but keep handle (can restart)
$s | Stop-Pspkt

# Full teardown
$s | Stop-Pspkt -Teardown
```

## See also

- [Start-Pspkt](./Start-Pspkt.md)
- [Filters](./Filters.md)
- [Components](./Components.md)
