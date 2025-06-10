# pspkt
A PowerShell wrapper for Windows pktmon in real-time mode designed to ease the use of pktmon, and filter the output to only the packet events. Giving pktmon a more tcpdump like feel.

# In Progress
Bugs ahead!

There is a known delay of ~1-3 seconds between the packet being send or received and appearing in the pspkt output.

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
Press Ctrl+C to stop.
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv4 (0x0800), length 74: 192.168.xxx.yyy > 1.1.1.1: ICMP echo request, id 1, seq 391, length 40
        24-A4-3C-3C-19-13 > 4C-ED-FB-B4-34-9E, ethertype IPv4 (0x0800), length 74: 1.1.1.1 > 192.168.xxx.yyy: ICMP echo reply, id 1, seq 391, length 40
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv4 (0x0800), length 74: 192.168.xxx.yyy > 1.1.1.1: ICMP echo request, id 1, seq 392, length 40
        24-A4-3C-3C-19-13 > 4C-ED-FB-B4-34-9E, ethertype IPv4 (0x0800), length 74: 1.1.1.1 > 192.168.xxx.yyy: ICMP echo reply, id 1, seq 392, length 40
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv4 (0x0800), length 74: 192.168.xxx.yyy > 1.1.1.1: ICMP echo request, id 1, seq 393, length 40
        24-A4-3C-3C-19-13 > 4C-ED-FB-B4-34-9E, ethertype IPv4 (0x0800), length 74: 1.1.1.1 > 192.168.xxx.yyy: ICMP echo reply, id 1, seq 393, length 40
        4C-ED-FB-B4-34-9E > 24-A4-3C-3C-19-13, ethertype IPv4 (0x0800), length 74: 192.168.xxx.yyy > 1.1.1.1: ICMP echo request, id 1, seq 394, length 40
        24-A4-3C-3C-19-13 > 4C-ED-FB-B4-34-9E, ethertype IPv4 (0x0800), length 74: 1.1.1.1 > 192.168.xxx.yyy: ICMP echo reply, id 1, seq 394, length 40
```
