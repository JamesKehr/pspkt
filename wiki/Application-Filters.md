# Application-Layer Display Filters

`Start-Pspkt` supports **application-layer display filters** that drop matching packets from the console output based on parsed payload content (DNS names, response codes, etc.). These complement the kernel-level pktmon capture filters created by quick filters like `-DNS`/`-SMB` and by `New-PspktFilter`.

## Scope

| | Kernel capture filter (`-DNS`, `Add-PspktFilter`) | Application-layer display filter (this page) |
|---|---|---|
| Where it runs | pktmon driver (kernel) | Consumer thread in C# (user mode) |
| What it sees | L2/L3/L4 fields (EtherType, IP, port, protocol) | Parsed payload fields (DNS name, RCODE, etc.) |
| Affects pcapng (`-WriteFile`) | **Yes** — filtered packets never reach the writer | **No** — the pcapng file always contains every packet the driver filter accepted |
| Affects console output | Yes | Yes |
| Configuration | Switches or `New-PspktFilter` objects | Per-protocol parameters on `Start-Pspkt` |

This is the same model Wireshark uses: capture filters shape what's written to disk; display filters control only what you see on screen.

## Requirements

Application-layer filters require **`-ParsingLevel Detailed`** (or `VeryDetailed`). Application-layer parsing doesn't run at `Minimal` or `Default` levels, so a predicate there would silently match nothing. `Start-Pspkt` **auto-bumps** `-ParsingLevel` to `Detailed` whenever an application filter is configured and prints a warning so the change in output verbosity isn't a surprise.

It also **auto-bumps `-PacketSize` to at least 1500 bytes** when a name-style predicate is in play. The default `-PacketSize 128` truncates DNS messages well before any non-trivial name fits in the payload. Use `-PacketSize 0` to opt into full-packet capture without the auto-bump.

To silence the auto-bump warnings (e.g. in scripts where you've intentionally configured the predicate and don't want the verbose output), pass `-NoWarning`. Operational warnings about pcapng data loss are not affected.

## Pcapng semantics

Application-layer predicates are **display filters**. The pcapng file written via `-WriteFile` is not affected — it contains every packet that survived the driver-level capture filters. This keeps the on-disk capture useful for post-hoc analysis in Wireshark even when you've narrowed the live view to a small subset.

If you also want to shrink the pcapng file, narrow the capture using kernel-level filters (e.g. `-DNS -i 1.1.1.1`) or use the `pktmon` CLI's native ETL writer via `-WriteEtl`.

## Combining quick filters with application filters

Application filters can be combined with quick filters and with each other. The auto-implied capture filter for each predicate is added **only when no existing capture filter already covers the predicate's target protocol** — never blindly suppressed by the mere presence of an unrelated filter. Examples:

| Command | Result |
|---|---|
| `pspkt -ARP -Icmpv6Type NA,NS` | Captures ARP **and** ICMPv6 (ARP doesn't cover ICMPv6, so the ICMPv6 auto-imply fires). Predicate narrows ICMPv6 display to NS/NA. |
| `pspkt -Ping -TlsSni example.com` | Captures ICMP **and** TCP 443. Predicate narrows TLS display to SNI=example.com. |
| `pspkt -HTTPS -TlsSni example.com` | Captures TCP 443 only (the explicit `-HTTPS` covers the TLS auto-imply, no duplicate filter). |
| `pspkt -DNS -DnsName example.com` | Captures UDP/TCP 53 only (explicit `-DNS` covers the DNS auto-imply, no duplicate). |
| `pspkt -DNSoverHTTPS -TlsSni .` | Captures TCP 443 only (DoH covers the TLS auto-imply). |
| `pspkt -DNSoverTLS -TlsSni .` | Captures TCP 853 **and** TCP 443 (DoT is on 853, doesn't cover 443, so TLS auto-imply fires). Use `New-PspktFilter` directly if you want strict scoping. |

Predicates are protocol-scoped: they only filter traffic of their own protocol. Packets from other protocols pass through unfiltered. So `-IcmpType EchoRequest -DNS` captures both ICMP and DNS, displays all DNS, but narrows ICMP display to echo requests only.

### Scoping to a single Hyper-V VM

`-VM` / `-VMName` AND-combines each vmNIC MAC with every quick filter and every application-layer auto-imply filter, expanding the filter set across the cartesian product `quickFilters × vmNICs`. Each resulting filter matches "(this vmNIC MAC) AND (this protocol scope)" — so all capture stays inside the VM's network data path.

| Command | pktmon filter set |
|---|---|
| `pspkt -VMName 'Win11' -SmbCommand Create` | `(MAC=vmNIC1 AND TCP/445) OR (MAC=vmNIC2 AND TCP/445)` — only VM SMB traffic; predicate then narrows display to Create commands. |
| `pspkt -VM <vm> -DnsName foo.com` | `(MAC=vmNIC AND UDP/53) OR (MAC=vmNIC AND TCP/53)` — only VM DNS traffic; predicate narrows display to foo.com queries. |
| `pspkt -VM <vm> -Icmpv6Type NS,NA -ARP` | `(MAC=vmNIC AND ARP) OR (MAC=vmNIC AND IPv6 ICMPv6)` — only VM ARP + ICMPv6; predicate narrows ICMPv6 to NS/NA. |
| `pspkt -VM <vm> -i 10.0.0.5 -HTTPS` | `(MAC=vmNIC AND TCP/443 AND IP=10.0.0.5)` — only VM HTTPS to/from 10.0.0.5. |
| `pspkt -VM <vm>` | `(MAC=vmNIC1) OR (MAC=vmNIC2)` — all VM traffic, no quick filter, standalone per-NIC MAC filters (unchanged from earlier versions). |

vmNICs whose MAC is unassigned (`000000000000`, i.e. dynamic-MAC VM that has never started) are skipped with a warning; use `-NoWarning` to silence.

**OFF / Saved / Paused VMs.** pktmon doesn't enumerate vmNICs whose VM isn't actively bound to a vmSwitch, but the Hyper-V cmdlets (`Get-VMNetworkAdapter`, `Get-VM | Get-VMNetworkAdapter`, and `$vm.NetworkAdapters` as further fallbacks) return MAC addresses for VMs in any power state. When `Get-PspktComponent` returns no live vmNIC components, `Start-Pspkt` falls back to host NIC components and lets the MAC filter scope the capture — the AND-combined `(MAC=vmNIC AND <quick filter>)` filter starts matching as soon as the VM resumes / starts and its traffic appears on the wire. A warning announces the fallback; suppress it with `-NoWarning`.

When the VM has no live components AND no discoverable MAC addresses (a dynamic-MAC VM that has never been started, or a VM with zero vmNICs) `Start-Pspkt` throws a clear error rather than silently capturing nothing. Start the VM at least once to allocate a MAC, assign a static MAC with `Set-VMNetworkAdapter -StaticMacAddress`, or drop `-VM` and use protocol / IP / component filters directly.

## Per-protocol references

| Protocol | Parameters | Reference |
|---|---|---|
| DNS / mDNS (UDP 53 / 5353) | `-DnsName`, `-DnsType`, `-DnsRcode`, `-DnsId`, `-DnsQR`, `-DnsMatchTruncated` | [Application-Filters-DNS](./Application-Filters-DNS.md) |
| TLS (TCP 443, 8443, 993, 995, 465, 636) | `-TlsSni`, `-TlsVersion`, `-TlsContentType`, `-TlsHandshakeType`, `-TlsMatchTruncated` | [Application-Filters-TLS](./Application-Filters-TLS.md) |
| HTTP / HTTP/1.x (TCP 80, 8080, 8000, 8888) | `-HttpMethod`, `-HttpHost`, `-HttpPath`, `-HttpStatus`, `-HttpContentType`, `-HttpMatchTruncated` | [Application-Filters-HTTP](./Application-Filters-HTTP.md) |
| DHCP (UDP 67/68, 546/547) | `-DhcpMessageType`, `-DhcpClientMac`, `-DhcpFamily`, `-DhcpMatchTruncated` | [Application-Filters-DHCP](./Application-Filters-DHCP.md) |
| SMB2 / SMB3 (TCP 445) | `-SmbCommand`, `-SmbDirection`, `-SmbStatus`, `-SmbFilename`, `-SmbTreePath`, `-SmbMatchEncrypted`, `-SmbMatchTruncated` | [Application-Filters-SMB2](./Application-Filters-SMB2.md) |
| ICMP / ICMPv6 / NDP | `-IcmpType`, `-Icmpv6Type`, `-Icmpv6NdpTarget` | [Application-Filters-ICMP](./Application-Filters-ICMP.md) |

(Other protocols may be added in future versions.)

## Known limitations (v1)

- **DNS, TLS, HTTP, DHCP, SMB2, and ICMP** have typed display filters. The C# predicate framework is generic and additional per-protocol predicates can follow the same pattern.
- **UDP DNS only / standard TLS ports only / cleartext HTTP/1.x only / DHCPv4 chaddr only / SMB2/SMB3 only / NDP target on NS/NA only.** TCP DNS, non-standard TLS ports, HTTP/2 framing, HTTPS-wrapped HTTP, DHCPv6 DUIDs, SMB1/CIFS, and Redirect-message target addresses bypass the predicates. See the per-protocol pages for details and workarounds.
- **No stateful fields.** Per-packet fields only. There is no equivalent of Wireshark's `tcp.stream eq N` or `tcp.analysis.retransmission` — pspkt's hot path deliberately keeps no per-flow state.
- **No Wireshark-style filter strings.** A `-DisplayFilter "dns.qry.name == ..."` mini-language is not in v1. Use the typed parameters instead.

## See also

- [Start-Pspkt](./Start-Pspkt.md) — main command reference
- [Filters](./Filters.md) — kernel-level capture filter objects
- [Quick Filters](./Quick-Filters.md) — `-DNS`/`-SMB`/etc. switches
