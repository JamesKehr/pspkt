# Filters

A **pspkt filter** is called a [Constraint](https://learn.microsoft.com/en-us/windows/win32/pktmon/packetmonitor/nf-packetmonitor-packetmonitoraddcaptureconstraint) in the pktmonapi documentation. pspkt follows the pktmon.exe, and other packet capture tools, term: Filter.

Think of a filter as _what_ network data pktmon will collect. A filter is the familiar concept of capturing or displaying a subset of network data used by tools like tcpdump, Wireshark, etc.; however, pktmon does filtering slightly different because there is no filter language with pktmon.

Multiple filters are OR-combined at the pktmon driver level: any packet matching at least one attached filter is captured.

Within a single filter, all set fields are AND-combined (e.g. one filter with `TransportProtocol=TCP`, `Port1=443`, `Ip1=10.0.0.5` matches only TCP/443 to/from 10.0.0.5). This is how [`Start-Pspkt`](./Start-Pspkt.md) combines `-IPAddress` with quick filters — by AND-merging the IP into each generated filter.

For example, this display filter in Wireshark will capture HTTPS traffic to Microsoft.com (150.171.109.118) or DNS traffic to Cloudflare (1.1.1.1).

```
(tcp.port==443 && ip.addr==150.171.109.118) || (udp.port==53 && ip.addr==1.1.1.1) || (tcp.port==53 && ip.addr==1.1.1.1)
```

With pktmon and pspkt, add three filters to the session to achieve the same behavior. The settings in each filter are automatically AND-combined, and the individual filters are OR-combined.

```
Filter01 (TCP AND 443 AND 150.171.109.118)
OR
Filter02 (UDP AND 53 AND 1.1.1.1)
OR
Filter03 (TCP AND 53 AND 1.1.1.1)
```

# Functions

| Command | Purpose |
|---|---|
| [`New-PspktFilter`](#new-pspktfilter) | Create a filter |
| [`Set-PspktFilter`](#set-pspktfilter) | Update fields on an existing filter |
| [`Add-PspktFilter`](#add-pspktfilter) | Attach a filter to a session |
| [`Remove-PspktFilter`](#remove-pspktfilter) | Detach a filter from a session |
| [`Get-PspktFilter`](#get-pspktfilter) | List filters on a session |
| [`ConvertTo-PspktIpAddress`](#convertto-pspktipaddress) | Convert `[IPAddress]` to the native struct |

## Filter field reference

Used by `New-PspktFilter` and `Set-PspktFilter`. Setting a field marks it `IsPresent` in the underlying constraint (the field becomes part of the AND match); leaving it unset means "don't constrain on this field".

| Field | Type | Description |
|---|---|---|
| `Name` | `string` | Friendly name shown in session summaries. |
| `Mac1` | `byte[]` or `string` | First MAC address. Strings accept 12 hex digits, colon pairs, hyphen pairs, or Cisco-dot form. |
| `Mac2` | `byte[]` or `string` | Second MAC address. Uses the same four string layouts as `Mac1`. |
| `VlanId` | `uint16` | VLAN ID. |
| `EtherType` | enum name, int, or hex string | EtherType (e.g. `'IPv4'`, `'ARP'`, `'IPv6'`, `0x0800`, `'0x0806'`). |
| `DSCP` | enum name or numeric | IPv4 DSCP code point. |
| `TransportProtocol` | enum name or numeric | `'TCP'`, `'UDP'`, `'ICMP'`, `'IPv6_ICMP'`, etc. |
| `Ip1` | `System.Net.IPAddress` | First IP address. AddressFamily determines IPv4/IPv6. |
| `Ip2` | `System.Net.IPAddress` | Second IP address. |
| `PrefixLength1` | `byte` | Prefix length for `Ip1` (for subnet match). |
| `PrefixLength2` | `byte` | Prefix length for `Ip2`. |
| `Port1` | `uint16` | First port (TCP/UDP). |
| `Port2` | `uint16` | Second port. |
| `TCPFlags` | enum or numeric | TCP flags constraint. |
| `VxLanPort` | `uint16` | VXLAN port (for encapsulation matching). |
| `EncapType` | enum or numeric | Encapsulation type. |

Enum-typed parameters accept three forms:
- Enum name string (case-insensitive): `'IPv4'`, `'TCP'`
- Integer: `0x0800`, `6`
- Hex string: `'0x0806'`, `'0x06'`

---

## New-PspktFilter

### Synopsis
Creates a new pspktFilter instance.

### Description
Constructs a filter object and sets only the properties specified via parameters.

### Syntax
```powershell
New-PspktFilter [-Name <string>] [-Mac1 <object>] [-Mac2 <object>] [-VlanId <uint16>]
                [-EtherType <object>] [-DSCP <object>] [-TransportProtocol <object>]
                [-Ip1 <IPAddress>] [-Ip2 <IPAddress>] [-PrefixLength1 <byte>] [-PrefixLength2 <byte>]
                [-Port1 <uint16>] [-Port2 <uint16>] [-TCPFlags <object>]
                [-VxLanPort <uint16>] [-EncapType <object>]
```

### Output
`pspktFilter`

### Examples
```powershell
# TLS over IPv4 to/from any host
New-PspktFilter -Name 'tls' -EtherType IPv4 -TransportProtocol TCP -Port1 443

# Filter on source MAC
New-PspktFilter -Name 'vmnic1' -Mac1 '00-15-5D-00-48-00'

# Filter on subnet (10.0.0.0/24)
New-PspktFilter -Name 'lab' -Ip1 ([System.Net.IPAddress]'10.0.0.0') -PrefixLength1 24
```

Invalid or mixed-delimiter MAC strings throw. `Set-PspktFilter` validates the complete candidate
before updating the original filter, so a rejected field does not leave earlier parameters applied.
Raw `PACKETMONITOR_PROTOCOL_CONSTRAINT` values are copied when added and cannot be modified through
typed filter setters. Raw constraints cannot be combined with VM scope.

Sessions store their own filter snapshots. Changing the original filter object after
`Add-PspktFilter` does not change the session's pending or committed constraint. Retrieve the
session-owned filter before activation if you need to adjust pending configuration.

A VM-scoped session activated with no filters materializes broad MAC-only constraints. Because
pktmon cannot remove native constraints, add all narrowing filters before activation; later filter
adds and removals are rejected with a recreate-required error.

For every session, filter removal is allowed only before native configuration is committed.
After activation, committed filters also cannot be changed through `Set-PspktFilter`; recreate
the session instead of changing or removing managed state that pktmon would continue enforcing
natively.

The filter object passed to `Add-PspktFilter` keeps a stable identity while the session stores an
isolated snapshot, so the original object can still be passed to `Remove-PspktFilter` before that
snapshot is committed. On a restarted session, newly added uncommitted filters may be removed even
when older filters are already committed.

When a session has VM scope, a filter with an explicit `Mac1` must use one of that VM's
canonical vmNIC MAC addresses. A foreign pre-stamped MAC is rejected instead of bypassing the
VM capture boundary.

---

## Set-PspktFilter

### Synopsis
Updates an existing pspktFilter.

### Description
Accepts a filter from parameter or pipeline and applies any bound filter fields. Filters can be
updated until they are committed to a native session; committed filters require session
recreation.

### Syntax
```powershell
Set-PspktFilter -Filter <pspktFilter> [<field params>]
```

Field parameters are the same as [`New-PspktFilter`](#new-pspktfilter).

### Output
`pspktFilter`

### Examples
```powershell
$f = New-PspktFilter -Name 'web'
$f | Set-PspktFilter -TransportProtocol TCP -Port1 80
```

---

## Add-PspktFilter

### Synopsis
Adds a filter to a session.

### Description
Attaches a `pspktFilter` to a `pspktSession` via the session's native `AddFilter` method.

### Syntax
```powershell
Add-PspktFilter -Session <pspktSession> -Filter <pspktFilter> [-PassThru]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | Yes | Session that receives the filter. |
| `-Filter` | `pspktFilter` | Yes (pipeline) | Filter to add. |
| `-PassThru` | `switch` | No | Return the session for chaining. |

### Examples
```powershell
$s = New-PspktSession -Name 'cap'
New-PspktFilter -Name 'tls' -TransportProtocol TCP -Port1 443 | Add-PspktFilter -Session $s
```

---

## Remove-PspktFilter

### Synopsis
Removes a filter from a session.

### Description
Removes a filter by object reference or by index from the session's filter collection.

### Syntax
```powershell
Remove-PspktFilter -Session <pspktSession> -Filter <pspktFilter> [-PassThru]
Remove-PspktFilter -Session <pspktSession> -Index <int> [-PassThru]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Session` | `pspktSession` | Yes (pipeline) | Session to remove filter from. |
| `-Filter` | `pspktFilter` | Yes (`ByFilter` set) | Filter object to remove. |
| `-Index` | `int` | Yes (`ByIndex` set) | Zero-based index in the session's Filters list. |
| `-PassThru` | `switch` | No | Return the session instead of the removal bool. |

### Output
`System.Boolean` (or `pspktSession` when `-PassThru` is set).

---

## Get-PspktFilter

### Synopsis
Gets filters associated with a session.

### Description
Emits each filter currently tracked in the session's `Filters` collection.

### Syntax
```powershell
Get-PspktFilter -Session <pspktSession>
```

### Output
`pspktFilter` (one per filter on the session).

### Example
```powershell
$s | Get-PspktFilter | Format-Table Name, EtherType, TransportProtocol, Port1
```

---

## ConvertTo-PspktIpAddress

### Synopsis
Converts a `System.Net.IPAddress` into a `PACKETMONITOR_IP_ADDRESS` struct.

### Description
Builds the native packet monitor address structure used by filter/session APIs. Supports both IPv4 and IPv6 addresses. You generally don't need to call this directly — `New-PspktFilter -Ip1`/`-Ip2` accepts `IPAddress` directly and conversion is automatic.

### Syntax
```powershell
ConvertTo-PspktIpAddress -Address <IPAddress>
```

### Output
`PACKETMONITOR_IP_ADDRESS`

### Example
```powershell
$native = ConvertTo-PspktIpAddress -Address ([IPAddress]'fe80::1')
```

## See also

- [Start-Pspkt](./Start-Pspkt.md)
- [Quick Filters](./Quick-Filters.md) — pre-built filters via switch parameters
- [Sessions](./Sessions.md)
