# Quick Filters

Quick filters are switch parameters on [`Start-Pspkt`](./Start-Pspkt.md) that auto-create one or more pktmon capture filters for common protocols. Multiple quick filters can be combined — pktmon filters are OR'd at the driver level, so `-DNS -SMB` captures DNS **or** SMB traffic.

When [`-IPAddress` (`-i`)](./Start-Pspkt.md#parameters) is supplied alongside a quick filter, the IP is **AND-merged into every** quick filter (not added as a separate OR filter). So `-DNS -i 1.1.1.1` becomes "DNS to/from 1.1.1.1" rather than "DNS OR 1.1.1.1".

When [`-VM` / `-VMName`](./Start-Pspkt.md#parameters) is used together with one or more quick filters, every quick filter is **AND-combined with each vmNIC MAC** — the filter set is expanded into the cartesian product `quickFilters × vmNICs`, so all capture is constrained to the VM's network data path. For example, `pspkt -VMName 'Win11' -DNS` becomes "(MAC=vmNIC1 AND DNS) OR (MAC=vmNIC2 AND DNS)". When `-VM` / `-VMName` is used alone (no quick filter), a standalone MAC filter per vmNIC is added so all VM traffic is captured.

`-VM` / `-VMName` works for VMs in **any power state**. For Running / Starting / Paused VMs, capture attaches to the live vmNIC components. For Off / Saved VMs (where pktmon has no live vmNIC components) the MAC list is still discovered via the Hyper-V cmdlets and the capture attaches to host NIC components — the MAC filter takes over scoping as soon as the VM resumes / starts. If the VM has no discoverable MAC (a never-started dynamic-MAC VM) `Start-Pspkt` errors out instead of silently capturing host-wide traffic.

## Reference

| Switch | Alias | Generated filter(s) |
|---|---|---|
| `-ARP` | — | EtherType ARP |
| `-NDP` | — | IPv6 ICMPv6 (post-capture filtered to types 133-137 only) |
| `-AA` | — | NDP + DHCP + DHCPv6 |
| `-AAv4` | — | DHCP |
| `-AAv6` | — | NDP + DHCPv6 |
| `-DHCP` | — | UDP/IPv4 ports 67 + 68 (server + client) |
| `-DHCPv6` | — | UDP/IPv6 ports 546 + 547 |
| `-DNS` | — | TCP + UDP port 53 |
| `-DNSoverHTTPS` | `-DoH` | TCP port 443 |
| `-DNSoverTLS` | `-DoT` | TCP port 853 |
| `-SMB` | — | TCP port 445 (SMB) + TCP port 88 (Kerberos) |
| `-SMBoverQUIC` | `-SoQ` | UDP port 443 (or `-SMBoverQuicAltPort`) |
| `-SMBoverQuicAltPort <port>` | — | Sets the alternate UDP port for `-SMBoverQUIC` |
| `-SSH` | — | TCP port 22 |
| `-RDP` | — | TCP port 3389 |
| `-RPC` | — | TCP port 135 |
| `-RCP` | — | TCP + UDP port 3343 (Cluster RCP) |
| `-HTTP` | — | TCP port 80 |
| `-HTTPS` | — | TCP port 443 |
| `-WinRM` | — | TCP port 5985 |
| `-WinRMS` | — | TCP port 5986 |
| `-Ping` | — | ICMPv4 + ICMPv6 (post-capture filtered to echo types only: ICMPv4 0/8, ICMPv6 128/129) |
| `-Ping4` | — | ICMPv4 (post-capture filtered to echo types 0/8 only) |
| `-Ping6` | — | ICMPv6 (post-capture filtered to echo types 128/129 only) |

## ICMP post-capture filtering

pktmon's driver-side capture filters cannot constrain on ICMP **type** (only EtherType / transport protocol / IP / port / MAC / VLAN / DSCP / TCPFlags). So `-Ping`, `-Ping4`, `-Ping6`, `-NDP`, `-AA`, and `-AAv6` capture **all** ICMP/ICMPv6 traffic at the driver level, then drop non-matching packets in the C# producer callback before they enter the ring buffer:

- `-Ping` / `-Ping4` / `-Ping6` → only ICMP echo types pass (ICMPv4 0/8 + ICMPv6 128/129)
- `-NDP` / `-AA` / `-AAv6` → only ICMPv6 NDP types 133-137 pass

When combined (e.g. `-Ping -NDP`), a packet passes if it matches **either** filter. Non-ICMP packets are unaffected.

**Filtered packets are excluded from both console output and pcapng file output** (the drop happens on the callback thread before the ring enqueue and before `WritePacket`). They also do not increment the `Captured` count at session end.

The filter walks IPv6 extension headers (Hop-by-Hop Options, Routing, Fragment, Destination Options, AH) so MLDv2 reports and outbound packets that Windows prefixes with a Hop-by-Hop header are correctly classified. Encrypted packets (ESP) and the rare WiFi link-layer case are passed through (the WiFi display-side fallback in `FormatSinglePacket` catches console output for WiFi, but pcapng would still include them — uncommon in practice).

## Auto-bump for PacketSize

Some quick filters need more captured bytes per packet than the default 128 to parse their payloads:

| Quick filter | Min `-PacketSize` |
|---|---|
| `-DHCP`, `-DHCPv6`, `-AA`, `-AAv4`, `-AAv6` | 590 |
| `-DNS` | 512 |

If you don't set `-PacketSize` explicitly, `Start-Pspkt` auto-increases it to the larger of the existing value and the minimum required.

## Combining patterns

```powershell
# DNS to 1.1.1.1 (no other traffic)
pspkt -DNS -i 1.1.1.1

# SMB inside a VM — (MAC=vmNIC AND TCP/445) per vmNIC, so only the VM's SMB traffic.
pspkt -VMName 'Win11-Dev' -SMB

# Multiple quick filters inside a VM — each AND-combined with each vmNIC MAC.
# pktmon: (MAC=nic AND ARP) OR (MAC=nic AND DNS-UDP) OR (MAC=nic AND DNS-TCP) per vmNIC
pspkt -VMName 'Win11-Dev' -ARP -DNS

# All auto-address protocols on a specific NIC
pspkt -AA -comp 5

# DNS over both UDP/53 and DoH (DNS+DoH OR'd)
pspkt -DNS -DoH
```

## See also

- [Start-Pspkt](./Start-Pspkt.md)
- [Filters](./Filters.md) — manually build filters via `New-PspktFilter`
- [Drop Triggers](./Drop-Triggers.md)
