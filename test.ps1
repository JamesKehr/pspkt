import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1"

$Sess = New-PspktSession -Name "test" -verbose

$gtwy = Get-NetIPConfiguration | where {$_.InterfaceAlias -match "Ethernet \d{1,3}"} | foreach {$_.IPv4DefaultGateway.Nexthop}
$f1 = New-PspktFilter -Name "ping gateway" -ip1 $gtwy -EtherType "IPv4"
$f2 = New-PspktFilter -Name "SMB" -TransportProtocol "TCP" -Port1 445

$f1 | Add-PspktFilter -Session $Sess
Add-PspktFilter -Session $Sess -Filter $f2

$all = Get-PspktComponent
$vmComp = Get-PspktComponent -Vm (Get-VM)

$vmcomp | Add-PspktComponent -Session $Sess

$pNicComp = Get-PspktComponent -Name "Microsoft NetVsc Nic #5"
Add-PspktComponent -Session $Sess -Component $pNicComp

Get-PspktSession






<#
Available Profiles: default, solarized, highcontrast

New Functions:

┌────────────────────────────────────────────────────────────────┬───────────────────────────────────────────┐
│ Function                                                       │ Purpose                                   │
├────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┤
│ Get-ParserColorProfile                                         │ List all profiles (shows which is active) │
├────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┤
│ Import-ParserColorProfile [-Name]                              │ Load a profile into memory                │
├────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┤
│ Set-ParserColorProfile -Name                                   │ Set the persistent default profile        │
├────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┤
│ New-ParserColorProfile -DataLinkBright ... -ApplicationMuted   │ Build a new profile in memory             │
├────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┤
│ Test-ParserColorProfile [-Profile]                             │ Preview sample output with a profile      │
├────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┤
│ Save-ParserColorProfile -Name -Profile [-Force]                │ Save a profile to disk                    │
└────────────────────────────────────────────────────────────────┴───────────────────────────────────────────┘

Usage examples:
#>
 # List profiles
 Get-ParserColorProfile
 
 # Switch to solarized
 Set-ParserColorProfile solarized
 
 # Preview highcontrast without switching
 Import-ParserColorProfile -Name highcontrast
 Test-ParserColorProfile

Import-ParserColorProfile -Name solarized
 Test-ParserColorProfile
 
 
 # Create and save a custom profile
 $p = New-ParserColorProfile `
     -DataLinkBright '38;2;255;128;0' -DataLinkMuted '38;2;180;90;0' `
     -NetworkBright '38;2;128;255;128' -NetworkMuted '38;2;90;180;90' `
     -TransportBright '38;2;128;128;255' -TransportMuted '38;2;90;90;180' `
     -ApplicationBright '38;2;255;128;255' -ApplicationMuted '38;2;180;90;180'
 Test-ParserColorProfile -Profile $p
 Save-ParserColorProfile -Name 'mycustom' -Profile $p
 Set-ParserColorProfile 'mycustom'






 # 1. Unfiltered capture (all traffic, Ctrl+C to stop)
 Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
 Start-Pspkt
 
 # 2. ICMP only (ping 8.8.8.8 from another terminal)
 $sess = New-PspktSession -Name "ping"
 $f = New-PspktFilter -Name "ICMP" -TransportProtocol ICMP -EtherType IPv4
 Add-PspktFilter -Filter $f -Session $sess
 $sess | Start-Pspkt
 
 # 3. DNS only (UDP port 53)
 $sess = New-PspktSession -Name "dns"
 $f = New-PspktFilter -Name "DNS" -TransportProtocol UDP -EtherType IPv4 -Port1 53
 Add-PspktFilter -Filter $f -Session $sess
 $sess | Start-Pspkt -Detailed -Spaced
 
 # 4. TCP to a specific host
 #Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
 $ip = [System.Net.Dns]::GetHostAddresses("example.com")
 $sess = New-PspktSession -Name "github"
 $c = 1
 foreach ($a in $ip) { 
    $f = New-PspktFilter -Name "example_$c" -TransportProtocol TCP -EtherType IPv4 -Ip1 $a
    Add-PspktFilter -Filter $f -Session $sess
    $c++
 }
 $sess.PacketSize = 1500
 Get-PspktComponent -NIC -NICName "Microsoft NetVsc Nic #5" | Add-PspktComponent -Session $sess
 $sess | Start-Pspkt -ParsingLevel Detailed -Spaced


 # 5. mDNS capture (port 5353, multicast)
 #Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
 $sess = New-PspktSession -Name "mdns"
 $f = New-PspktFilter -Name "mDNS" -TransportProtocol UDP -EtherType IPv4 -Port1 5353
 Add-PspktFilter -Filter $f -Session $sess
 $sess | Start-Pspkt -Detailed -Spaced -Timestamp
 # mDNS is broadcast - just wait for traffic or: Resolve-DnsName "$($env:COMPUTERNAME).local" -LlmnrOnly
 
 # 6. ARP capture
 $sess = New-PspktSession -Name "arp"
 $f = New-PspktFilter -Name "ARP" -EtherType ARP
 Add-PspktFilter -Filter $f -Session $sess
 $sess | Start-Pspkt
 # Then in another terminal: arp -d * ; ping 10.24.0.1
 

 # 7. DHCP  (UDP ports 67 and 68, broadcast)
#Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
$sess = New-PspktSession -Name "dhcp"
$f1 = New-PspktFilter -Name "DHCP-Client" -TransportProtocol UDP -EtherType IPv4 -Port1 68
$f2 = New-PspktFilter -Name "DHCP-Server" -TransportProtocol UDP -EtherType IPv4 -Port1 67
Add-PspktFilter -Filter $f1 -Session $sess
Add-PspktFilter -Filter $f2 -Session $sess
$sess.PacketSize = 1500
$sess | Start-Pspkt -ParsingLevel Minimal


# 8. Capture on a single component (e.g. a specific NIC or VM)
#Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
$sess = New-PspktSession -Name "nic"
$sess.PacketSize = 1500
Get-PspktComponent -NIC -NICName "Windows 11 dev environment" | Add-PspktComponent -Session $sess
$sess | Start-Pspkt -ParsingLevel Detailed -Spaced

# 9. Capture on a specific VM (e.g. a VM with a specific name)
#Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
$sess = New-PspktSession -Name "vm"
$sess.PacketSize = 1500
$sess | Start-Pspkt -VMName "Windows 11 dev environment" -ParsingLevel Minimal


# 10. Capture HTTP traffic on a specific VM (e.g. a VM with a specific name)
#Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
$sess = New-PspktSession -Name "vm"
$sess.PacketSize = 1500
$ip = [System.Net.Dns]::GetHostAddresses("example.com")
foreach ($a in $ip) {
    $f = New-PspktFilter -Name "example_$c" -TransportProtocol TCP -EtherType IPv4 -Ip1 $a -Port1 80
    Add-PspktFilter -Filter $f -Session $sess
    $c++
}

$sess | Start-Pspkt -VMName "Windows 11 dev environment" -ParsingLevel Minimal


# 11. Quick filter testing 
# IPv6 address acquisition + ping on NICs only
 #Import-Module "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt\pspkt.psm1" -Force
 pspkt -AAv6 -Ping6 -comp NICs

#Generate traffic from a second terminal:

 ping 8.8.8.8 -t          # for test 2
 Resolve-DnsName microsoft.com -DnsOnly  # for test 3
 curl https://example.com        # for test 4





 pktmon stop
 pktmon reset
 pktmon filter remove
 pktmon start -c -m memory
 ping bing.com
 pktmon stop
 pktmon etl2pcap Q:\temp\pktmon.etl 



# the source of that file
$file = "C:\developer\vscode\code.exe"

# check the Zone.Identity stream
$zone = Get-Item -Path $file -Stream * | where-object {$_.Stream -eq "Zone.Identifier"}

if ($zone) {
    $ZId = Get-Content -Path $zone.FileName -Stream "Zone.Identifier"
    Write-Host -ForegroundColor Yellow "The remote file has a zone identifier.`n$($ZId | Out-String)"
} else {
    Write-Host "The remote file does not have a zone identifier."
}




SMB parser: 
CD "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\SMB\Parser"
agency  copilot --resume=a28c899f-b82a-485d-8764-558143ba5b5b


pspkt: 
CD "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt"
agency copilot --resume=0ebcd9fa-6b51-48b8-a186-6332ae74a9b0