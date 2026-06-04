First off, credit goes to Ekky's [PSPktmon project](https://github.com/Ekky-PS/PSPktmon) for building the C# foundation I used as a template for pspkt. My first iteration was a wrapper for pktmon.exe, that was honestly not great, but seeing a pktmonapi implementation for PowerShell helped get the new version working. So a huge thank you goes out to Ekky!

PowerShell Packet Monitor (pspkt) is a network analysis tool built for PowerShell. The code is primarily C# with PowerShell wrappers. pspkt is built for Windows PowerShell 5.1 and PowerShell 7 compatibility, and will work on Windows Server 2019, Windows 10 22H2, and newer.

Think of pspkt as a merger of tcpdump from Linux, plus pktmon.exe and netsh.exe in Windows, with a sprinkle of color and awesome new features for networking nerds.

# Purpose

[Packet Monitor (pktmon)](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon) is a Windows in-box network data collection and analysis tool. It can do more than just networking because of its ETW collection capabilities, but mainly it's a network tool. The [pktmonapi](https://learn.microsoft.com/en-us/windows/win32/pktmon/pktmon) Win32 APIs allow anyone to leverage pktmon for data collection, logging, analysis, and network protection.

Inside of Windows, Server 2019+ and 10 22H2+, is a command line tool called pktmon.exe. This tool can collect packets at multiple locations inside the Windows network data path. Now you may wonder what the difference between pktmon.exe and pspkt is, so let me go over some reasons why I built pspkt.

- pktmon.exe is a data collection tool that happens to have some real-time features.
- pspkt is a real-time tool that happens to have data collection capabilities.

- pktmon.exe uses a single, default session. Meaning only a single instance of pktmon.exe can run at a time.
- pspkt is a multi-session implementation. This allows multiple parallel instances of pspkt, or pktmon.exe and pspkt running simultaneously.

- pktmon.exe can only write data or do real-time.
- pspkt can output real-time data to a terminal and write the packets to a pcapng file, at the same time.

- pktmon.exe has basic real-time features.
- pspkt has a more robust real-time feature set, including:
  - Colorized output.
  - Customizable color schemes.
  - Multiple parsing levels.
  - Additional parsers.
  - Pause Mode, which allows interactive or automatic pausing of real-time output.
  - Stop Mode, which automatically stops the capture when drop conditions are met.
  - Quick Filters, which allow single line execution for common network protocols and scenarios. 

- pktmon.exe has limited abilities to generate a network data path to capture. The options here are all, NICs, and manual selection.
- pspkt has additional network data path generation capabilities. Currently this included a Hyper-V/Azure Local VM network path generation, with the ability to capture on a single NIC path coming in the future.

- pktmon.exe is a closed source operating system tool.
- pspkt is an open source tool which allows public contributions.

# Quick Start

## Unfiltered session

After downloading and importing the pspkt module, you can start a real-time analysis by simply typing in:

```powershell
Start-Pspkt
```

-OR- use the alias:

```powershell
pspkt
```

Press Ctrl+C to stop.

## Quick filter session

This command will collect both IPv4 and IPv6 pings.

```powershell
pspkt -Ping
```

There are two sub-versions of Ping, Ping4 (ICMP Echo) and Ping6 (ICMPv6 Echo). This command will only collect IPv4 based pings.

```powershell
pspkt -Ping4
```

But what if I want to just see pings to a single server? Add the `-IPAddress` parameter, of course!

```powershell
pspkt -Ping4 -IPAddress 1.1.1.1
```

Do you think that parameter it too long? No worries! The `-i` alias works, too!

```powershell
pspkt -Ping4 -i 1.1.1.1
```

Not interesting in the entire network data path? There are two options. The first is to collect only on the NIC components.

```powershell
pspkt -Ping4 -i 1.1.1.1 -Component NICs
```

Or, get a list of NIC component IDs. The parameter is not actually case sensitive in PowerShell, and `-DumpInterface` just doesn't look right to tcpdump users...

```powershell
pspkt -D
```

Then filter by the NIC's component ID.

```powershell
pspkt -Ping4 -i 1.1.1.1 -Component 12
```

Wait, isn't 1.1.1.1 Cloudflare DNS? Let's change things around to capture DNS to Cloudflare, using a detailed parser and enable manual pausing.

```powershell
pspkt -DNS -i 1.1.1.1 -Component 12 -ParsingLevel Detailed -Pause
```

Now, you can pause output to analyze results. Then press 'r' to resume the capture or 'q' to end the session.

```powershell
pspkt -DNS -i 1.1.1.1 -Component 12 -ParsingLevel Detailed -Pause
Capturing packets in real-time. Press Ctrl+C to stop... Press 'p' to pause.
Group:Component         Data Link       Network         Transport       Application
000:012 (ASUS XG-C100C 10G PC)[ In]: 4c-ed-fb-b4-34-9e > a8-9c-6c-8a-d8-15, type IPv4, len 73
 └IPv4 - Src: 192.168.0.101, Dst: 1.1.1.1; DSCP: BE; len: 59; id: 0x54b9; flg: none; TTL: 128; Next: UDP
  └UDP - Src: 53323, Dst: 53; len: 31
   └DNS 65333+ AAAA? microsoft.com. (31)
000:012 (ASUS XG-C100C 10G PC)[ In]: 4c-ed-fb-b4-34-9e > a8-9c-6c-8a-d8-15, type IPv4, len 73
 └IPv4 - Src: 192.168.0.101, Dst: 1.1.1.1; DSCP: BE; len: 59; id: 0x54ba; flg: none; TTL: 128; Next: UDP
  └UDP - Src: 56617, Dst: 53; len: 31
   └DNS 33713+ A? microsoft.com. (31)
000:012 (ASUS XG-C100C 10G PC)[ In]: a8-9c-6c-8a-d8-15 > 4c-ed-fb-b4-34-9e, type IPv4, len 101
 └IPv4 - Src: 1.1.1.1, Dst: 192.168.0.101; DSCP: BE; len: 87; id: 0xb00f; flg: DF; TTL: 50; Next: UDP
  └UDP - Src: 53, Dst: 53323; len: 59
   └DNS 65333 1/0/0 microsoft.com. AAAA 2603:1061:14:72:1 (59)
000:012 (ASUS XG-C100C 10G PC)[ In]: a8-9c-6c-8a-d8-15 > 4c-ed-fb-b4-34-9e, type IPv4, len 89
 └IPv4 - Src: 1.1.1.1, Dst: 192.168.0.101; DSCP: BE; len: 75; id: 0xc504; flg: DF; TTL: 50; Next: UDP
  └UDP - Src: 53, Dst: 56617; len: 47
   └DNS 33713 1/0/0 microsoft.com. A 150.171.109.115 (47)
000:012 (ASUS XG-C100C 10G PC): DROP - Reason: ProtocolNotBound (0x000000CC); Location: NDIS_M_DISPATCH_RECEIVE (0xE0001007); IPv4 src: 8.0.69.0, dst: 0.87.176.15
000:012 (ASUS XG-C100C 10G PC): DROP - Reason: ProtocolNotBound (0x000000CC); Location: NDIS_M_DISPATCH_RECEIVE (0xE0001007); IPv4 src: 8.0.69.0, dst: 0.75.197.4
=====  Real-time mode is Paused. Press 'r' to resume or 'q' to quit... =====
```

But what you see in the terminal is this:
<img width="1712" height="608" alt="image" src="https://github.com/user-attachments/assets/fda6bbab-3b51-454c-9a51-c9b79bd8d121" />

