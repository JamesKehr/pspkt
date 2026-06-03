# Display

Commands that control how parsed packets are rendered to the console. All these settings are also exposed as `Start-Pspkt` parameters (`-pl`, `-t`, `-Spaced`), but the underlying setters can be called directly when scripting or building a custom pipeline.

| Command | Purpose |
|---|---|
| [`Set-PspktDetailLevel`](#set-pspktdetaillevel) | Set Minimal / Default / Detailed / VeryDetailed output |
| [`Get-PspktDetailLevel`](#get-pspktdetaillevel) | Read the current detail level |
| [`Set-PspktDetailSpacing`](#set-pspktdetailspacing) | Toggle blank-line spacing between packets |
| [`Get-PspktDetailSpacing`](#get-pspktdetailspacing) | Read current spacing setting |
| [`Set-PspktShowTimestamp`](#set-pspktshowtimestamp) | Toggle timestamp prefix on each line |
| [`Get-PspktShowTimestamp`](#get-pspktshowtimestamp) | Read current timestamp setting |
| [`Register-PspktComponentMap`](#register-pspktcomponentmap) | Populate the component ID→name lookup used by output |
| [`Clear-PspktComponentMap`](#clear-pspktcomponentmap) | Empty the component name map |
| [`Get-PspktCaptureHeader`](#get-pspktcaptureheader) | Returns the colored header row shown at capture start |

---

## Set-PspktDetailLevel

### Synopsis
Sets the detail level for real-time packet output.

### Description
Controls how much per-packet information is rendered. Settings are persistent for the session and apply to subsequent captures.

| Level | Constant | Description |
|---|---|---|
| `-1` | Minimal | Condensed single-line summary |
| `0` | Default | Header summary per layer |
| `1` | Detailed | Multi-line per-layer breakdown |
| `2` | VeryDetailed | Detailed plus blank line between packets |

### Syntax
```powershell
Set-PspktDetailLevel -Level <int>
```

### Parameters

| Parameter | Type | Mandatory | Range |
|---|---|---|---|
| `-Level` | `int` | Yes | -1, 0, 1, or 2 |

### Example
```powershell
Set-PspktDetailLevel -Level 1   # Detailed
```

---

## Get-PspktDetailLevel

### Synopsis
Gets the current detail level for real-time packet output.

### Syntax
```powershell
Get-PspktDetailLevel
```

### Output
`int` (-1 to 2)

---

## Set-PspktDetailSpacing

### Synopsis
Enables or disables blank-line spacing between packets in detailed mode.

### Description
When enabled, the formatter emits a blank line after each packet in detailed/very-detailed modes — easier to read at the cost of vertical space. The `Start-Pspkt -Spaced` switch toggles this for a single capture.

### Syntax
```powershell
Set-PspktDetailSpacing -Enabled <bool>
```

### Parameters

| Parameter | Type | Mandatory |
|---|---|---|
| `-Enabled` | `bool` | Yes |

---

## Get-PspktDetailSpacing

### Synopsis
Gets whether blank-line spacing between packets is enabled.

### Syntax
```powershell
Get-PspktDetailSpacing
```

### Output
`bool`

---

## Set-PspktShowTimestamp

### Synopsis
Enables or disables timestamp display on packet output.

### Description
When enabled, each packet line is prefixed with the local timestamp in `yyyy-MM-dd HH:mm:ss.fffffff` format (derived from a high-resolution QPC timestamp captured at packet receive time). Equivalent to `Start-Pspkt -Timestamp`/`-t`.

### Syntax
```powershell
Set-PspktShowTimestamp -Enabled <bool>
```

### Parameters

| Parameter | Type | Mandatory |
|---|---|---|
| `-Enabled` | `bool` | Yes |

---

## Get-PspktShowTimestamp

### Synopsis
Gets whether timestamp display is enabled.

### Syntax
```powershell
Get-PspktShowTimestamp
```

### Output
`bool`

---

## Register-PspktComponentMap

### Synopsis
Registers a component ID-to-name mapping for packet output.

### Description
Populates the internal lookup table used to render component IDs as friendly names in the packet line prefix (e.g. `034:001 (Host vNic)`). `Start-Pspkt` calls this automatically with the output of `Get-PspktComponent`. You only need it when running a custom capture pipeline.

### Syntax
```powershell
Register-PspktComponentMap -Components <object>
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Components` | `object` (array of `pspktComponent`) | Yes | Components to register. Any object with `Id`, `Name`, `Group`, `ParentId` works. |

### Example
```powershell
Get-PspktComponent | Register-PspktComponentMap
```

---

## Clear-PspktComponentMap

### Synopsis
Clears the component ID-to-name mapping.

### Description
Empties the lookup table — subsequent packets will render with bare numeric IDs.

### Syntax
```powershell
Clear-PspktComponentMap
```

---

## Get-PspktCaptureHeader

### Synopsis
Returns a color-correlated header line for real-time capture output.

### Description
Outputs a tab-separated header with each column label colored using the Bright variant of its corresponding layer color: `Group:Component`, `Data Link`, `Network`, `Transport`, `Application`. `Start-Pspkt` prints this once at the top of a capture; call it directly when emulating that behavior.

### Syntax
```powershell
Get-PspktCaptureHeader
```

### Output
`string` (a single colored line)

## See also

- [Start-Pspkt](./Start-Pspkt.md) — `-pl`, `-t`, `-Spaced` parameters
- [Color Profiles](./Color-Profiles.md) — change the colors used
- [Components](./Components.md)
