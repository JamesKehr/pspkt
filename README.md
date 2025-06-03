# pspkt
A PowerShell wrapper for Windows pktmon in real-time mode designed to ease the use of pktmon, and filter the output to only the packet events. Giving pktmon a more tcpdump like feel.

# In Progress
Bug ahead!

# Examples

## Example 1
List interface numbers. This is done tcpdump-stype, not by interface index. For now...

```powershell
Import-Module <path to>\pspkt.psm1 -Force
pspkt -D
```

**Output**

```
1. vEthernet (public)         [192.168..., 2600:...]
2. vEthernet (Default Switch) [172.19.16.1]
3. Ethernet 2                 [192.168...., 2600:...]
4. VPN                        [...]
```


## Example 2
```powershell
# assumes the module has already been imported, ala example 1.
pspkt -Ping -int 1,3 -Force
```

**Output**

```
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv6 (0x86dd), length 102: 2600:... > 2606:4700:4700::1111: HBH ICMP6, echo request, seq 7, length 40
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv6 (0x86dd), length 102: 2600:... > 2606:4700:4700::1111: HBH ICMP6, echo request, seq 8, length 40
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv6 (0x86dd), length 102: 2600:... > 2606:4700:4700::1111: HBH ICMP6, echo request, seq 9, length 40
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv6 (0x86dd), length 102: 2600:... > 2606:4700:4700::1111: HBH ICMP6, echo request, seq 10, length 40
```
