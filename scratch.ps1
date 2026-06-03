# where are the scripts
$root = "C:\Users\jakehr\OneDrive - Microsoft\Documents\scripts\pspkt"

# load things
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!! DO NOT use Get-ChildItem (dir or gci) as this does not guarantee that the modules are loaded in the correct order !!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[array]$loadList =  "class\loader.psm1",
                    "class\pspktEnum.psm1",
                    "class\pspktUtil.psm1",
                    "class\pspktTypes.psm1",
                    "class\pspktPacketParser.psm1",
                    "class\pspktClass.psm1",
                    "pspkt.psm1"

foreach ($mod in $loadList) {
    Write-Verbose "Loading: $mod"
    Import-Module "$root\$mod" -Force -Global
}


# filter/constraint
$filt = [PACKETMONITOR_PROTOCOL_CONSTRAINT]::new()
$filt.IsPresent = [PKTMON_FILTER_FLAGS]"Ip1,Ip2,TransportProtocol"
$filt

# ipaddress to pspktIpAddress
$v4 = ConvertTo-PspktIpAddress -Address ([ipaddress]'192.168.1.10')
$v6 = ConvertTo-PspktIpAddress -Address ([ipaddress]'fe80::1')

# pspktIpAddress back to ipAddress
[ipaddress]($v4.GetIPv4Bytes())
[ipaddress]($v6.GetIPv6Bytes())

# assign the address
$filt.ip1 = $v4
$filt.ip2 = $v6

# read the address back
[ipaddress]$filt.ip1.ipv4
$filt.ip2.ToIPAddress($true)









## basic comp testing
# test the new pspktComponent integration
$pspkt = [pspkt]::new()
$pspkt.PacketMonitorInitialize()  
$pspkt.EnumPktmonDataSources($true, 1)
$pspkt.PacketMonitorUninitialize()

# verify that all components are returned
$a = [pspktComponent]::GetAllComponents()
$raw = pktmon comp list --json | ConvertFrom-Json | ForEach-Object Components

if ($a.count -eq $raw.count) {
    Write-Host -ForegroundColor Green "Success!"
} else {
    Write-Host -ForegroundColor Yellow "Not Success! class: $($a.Count); raw: $($raw.Count)"
}
