# Components

A **pspkt component** wraps a pktmon data source — a NIC, a virtual switch, a Windows networking driver, or a virtual NIC inside a Hyper-V VM. Capture is constrained to specific components by attaching them to a session.

Think of components as _where_ pktmonapi will collect network data. This can be a network adapter (NIC), transport layer (TCP/IP), WFP (network filtering like firewall), Hyper-V vmSwitch, and more.

Please be aware that pktmonapi can only capture from registered components. This is almost exclusively Windows-native networking subsystems. Security applications — including third-party antivirus and even Microsoft Defender — typically use WFP callout drivers that do not register as pktmon components. This can result in packets "disappearing" from the network stack in unexpected places without a DROP event. This behavior is most commonly caused by WFP callout drivers intercepting or absorbing the traffic.

| Command | Purpose |
|---|---|
| [`Get-PspktComponent`](#get-pspktcomponent) | Enumerate components by NIC, VM, group, type, or name |
| [`Get-PspktComponentGroupName`](#get-pspktcomponentgroupname) | List all valid component group names |
| [`Get-PspktComponentNICName`](#get-pspktcomponentnicname) | List NIC component names as pktmon sees them |
| [`Set-PspktComponent`](#set-pspktcomponent) | Update fields on a component |
| [`Add-PspktComponent`](#add-pspktcomponent) | Attach a component to a session |
| [`Remove-PspktComponent`](#remove-pspktcomponent) | Detach a component from a session |

## Component data model

| Field | Type | Description |
|---|---|---|
| `Id` | `int` | pktmon component ID. |
| `SecondaryId` | `int` | Secondary ID (used for filtering some components). |
| `ParentId` | `int` | Parent component ID. |
| `Name` | `string` | Friendly name (e.g. `"vEthernet (Lab)"`). |
| `DriverName` | `string` | Backing driver name. |
| `Group` | `string` | Component group (e.g. `"NIC"`, `"Driver"`, `"Protocol"`). |
| `Type` | `string` | Component type. |
| `TypeId` | `int` | Type ID. |
| `IsNetworkAdapter` | `bool` | True for NIC-type components. |
| `MacAddress` | `string` | MAC for NIC components. |

---

## Get-PspktComponent

### Synopsis
Gets packet monitor components.

### Description
Returns `pspktComponent` instances and supports filtering by NIC, VM, group, type, or name. Multiple parameter sets:

| Parameter set | Required parameters |
|---|---|
| `All` | (none — returns everything) |
| `NIC` | `-NIC` switch, optional `-NICName` |
| `VM` | `-VM <object>` (from `Get-VM`) |
| `VMName` | `-VMName <string>` |
| `Group` | `-GroupName <string>` |
| `ByType` | `-Type <string>` (regex), optional `-GroupName` |
| `ByName` | `-Name <string>` (regex), optional `-GroupName` |

### Parameters

| Parameter | Type | Set | Description |
|---|---|---|---|
| `-NIC` | `switch` | `NIC` | Returns only NIC components. |
| `-NICName` | `string` | `NIC` | Filters NICs by name (regex by default). |
| `-VM` | `object` | `VM` | Hyper-V VM object. Returns all components in the VM's network data path. |
| `-VMName` | `string` | `VMName` | Hyper-V VM name (exact match). Returns all components in the VM's network data path. |
| `-GroupName` | `string` | `Group`/`ByType`/`ByName` | Filter by component group (exact match). |
| `-Type` | `string` | `ByType` | Filter by component type (regex). |
| `-Name` | `string` | `ByName` | Filter by component name (regex). |
| `-Exact` | `switch` | `NIC`/`ByType`/`ByName` | Use literal `-eq` match instead of regex. |

### Output
`pspktComponent[]`

### Examples
```powershell
# All components
Get-PspktComponent

# All NICs
Get-PspktComponent -NIC

# NIC by name (regex)
Get-PspktComponent -NIC -NICName 'Default'

# Components in a VM's data path
Get-PspktComponent -VMName 'Win11-Dev'

# All components in the NIC group
Get-PspktComponent -GroupName 'NIC'

# Components of a specific type (regex)
Get-PspktComponent -Type 'Filter'
```

---

## Get-PspktComponentGroupName

### Synopsis
Gets available component group names.

### Description
Returns the list of group names pktmon recognizes. Useful for picking valid values to pass to `-GroupName`.

### Syntax
```powershell
Get-PspktComponentGroupName
```

### Output
`string[]`

---

## Get-PspktComponentNICName

### Synopsis
Gets packet monitor NIC component names.

### Description
Returns the names of NIC components as pktmon sees them. These are not always the same as the Windows network adapter names — use this when picking a value for `Get-PspktComponent -NICName`.

### Syntax
```powershell
Get-PspktComponentNICName
```

### Output
`string[]`

---

## Set-PspktComponent

### Synopsis
Updates an existing pspktComponent.

### Description
Accepts a component from parameter or pipeline and updates bound fields. You typically don't need this — components are immutable as enumerated from pktmon. Provided for advanced manipulation.

### Syntax
```powershell
Set-PspktComponent -Component <pspktComponent> [-Name <string>] [-DriverName <string>]
                   [-Id <int>] [-SecondaryId <int>] [-ParentId <int>]
                   [-Group <string>] [-Type <string>] [-TypeId <int>]
                   [-IsNetworkAdapter <bool>] [-MacAddress <string>]
```

### Output
`pspktComponent`

---

## Add-PspktComponent

### Synopsis
Adds a component to a session.

### Description
Adds a data source component to a `pspktSession`. Capture from this component is now included in the session.

### Syntax
```powershell
Add-PspktComponent -Session <pspktSession> -Component <pspktComponent> [-PassThru]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | Yes | Session that receives the component. |
| `-Component` | `pspktComponent` | Yes (pipeline) | Component to add. |
| `-PassThru` | `switch` | No | Return the session for chaining. |

### Example
```powershell
$s = New-PspktSession -Name 'cap'
Get-PspktComponent -NIC | Add-PspktComponent -Session $s
$s | Start-Pspkt
```

---

## Remove-PspktComponent

### Synopsis
Removes a component from a session.

### Description
Removes a component by object reference or by index from the session's component collection.

### Syntax
```powershell
Remove-PspktComponent -Session <pspktSession> -Component <pspktComponent> [-PassThru]
Remove-PspktComponent -Session <pspktSession> -Index <int> [-PassThru]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | Yes (pipeline) | Session to remove component from. |
| `-Component` | `pspktComponent` | Yes (`ByComponent` set) | Component object to remove. |
| `-Index` | `int` | Yes (`ByIndex` set) | Zero-based index in the session's Components list. |
| `-PassThru` | `switch` | No | Return the session instead of the removal bool. |

### Output
`System.Boolean` (or `pspktSession` when `-PassThru` is set).

## See also

- [Start-Pspkt](./Start-Pspkt.md) — accepts `-Component`, `-VM`, `-VMName` directly
- [Sessions](./Sessions.md)
- [Filters](./Filters.md)
