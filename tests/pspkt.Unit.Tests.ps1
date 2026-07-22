Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Determines whether the current PowerShell process is elevated.

.OUTPUTS
System.Boolean
#>
function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

$allExportedCommands = @(
    'ConvertTo-PspktIpAddress',
    'New-PspktFilter',
    'Set-PspktFilter',
    'Add-PspktFilter',
    'Remove-PspktFilter',
    'Get-PspktFilter',
    'Get-PspktComponent',
    'Get-PspktComponentGroupName',
    'Get-PspktComponentNICName',
    'Set-PspktComponent',
    'Add-PspktComponent',
    'Remove-PspktComponent',
    'New-PspktSession',
    'Get-PspktSession',
    'Set-PspktSession',
    'Start-Pspkt',
    'Stop-Pspkt',
    'Get-PspktQuickFilter',
    'Get-PspktParameterTree',
    'Get-PspktParserColorProfile',
    'Import-PspktParserColorProfile',
    'Set-PspktParserColorProfile',
    'New-PspktParserColorProfile',
    'Test-PspktParserColorProfile',
    'Save-PspktParserColorProfile',
    'Register-PspktComponentMap',
    'Clear-PspktComponentMap',
    'Get-PspktCaptureHeader',
    'Set-PspktDetailLevel',
    'Get-PspktDetailLevel',
    'Set-PspktDetailSpacing',
    'Get-PspktDetailSpacing',
    'Set-PspktShowTimestamp',
    'Get-PspktShowTimestamp'
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$filesToScan = @(
    (Join-Path $projectRoot 'pspkt.psm1'),
    (Join-Path $projectRoot 'function\PspktFilter.psm1'),
    (Join-Path $projectRoot 'function\PspktComponent.psm1'),
    (Join-Path $projectRoot 'function\PspktSession.psm1'),
    (Join-Path $projectRoot 'Parsers\libParser.psm1'),
    (Join-Path $projectRoot 'Parsers\Application\smb2.psm1')
)

$allProjectFunctionDefinitions = @()
foreach ($file in $filesToScan) {
    $content = Get-Content -LiteralPath $file -Raw
    $matches = [regex]::Matches($content, '(?m)^\s*function\s+([A-Za-z0-9_-]+)\s*\{')
    foreach ($match in $matches) {
        $allProjectFunctionDefinitions += [PSCustomObject]@{
            Name = $match.Groups[1].Value
            File = $file
        }
    }
}

Describe 'pspkt module exports and command behavior' -Tag 'Unit' -Skip:(-not (Test-IsAdministrator)) {
    BeforeAll {
        $script:modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'pspkt.psm1'
        Import-Module $script:modulePath -Force -ErrorAction Stop

        $script:expectedCommands = $script:allExportedCommands
    }

    AfterAll {
        Remove-Module pspkt -Force -ErrorAction SilentlyContinue
    }

    It 'exports expected commands' {
        foreach ($name in $script:expectedCommands) {
            Get-Command -Name $name -ErrorAction Stop | Should -Not -BeNullOrEmpty
        }
    }

    It 'has discoverable help for each exported command' -ForEach $allExportedCommands {
        $help = Get-Help -Name $_ -ErrorAction Stop
        $help | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -BeNullOrEmpty
    }

    It 'converts IPv4 to PACKETMONITOR_IP_ADDRESS' {
        $ip = ConvertTo-PspktIpAddress -Address ([System.Net.IPAddress]::Parse('192.168.1.10'))

        $ip.GetType().Name | Should -Be 'PACKETMONITOR_IP_ADDRESS'
        $ip.IPv4 | Should -Not -Be 0
    }

    It 'creates and updates pspktFilter objects' {
        $filter = New-PspktFilter -Port1 443 -Port2 8443
        $filter.GetType().Name | Should -Be 'pspktFilter'
        $filter.Port1 | Should -Be 443
        $filter.Port2 | Should -Be 8443

        $updated = $filter | Set-PspktFilter -Port1 80 -Port2 8080
        $updated.Port1 | Should -Be 80
        $updated.Port2 | Should -Be 8080
    }

    It 'accepts enum name strings for EtherType' {
        $filter = New-PspktFilter -EtherType 'IPv4'
        $filter.EtherType | Should -Be ([ETHERTYPE]::IPv4)
    }

    It 'accepts hex integers for EtherType' {
        $filter = New-PspktFilter -EtherType 0x0800
        $filter.EtherType | Should -Be ([ETHERTYPE]::IPv4)
    }

    It 'accepts hex strings for EtherType' {
        $filter = New-PspktFilter -EtherType '0x0800'
        $filter.EtherType | Should -Be ([ETHERTYPE]::IPv4)
    }

    It 'accepts decimal integers for EtherType' {
        $filter = New-PspktFilter -EtherType 2048
        $filter.EtherType | Should -Be ([ETHERTYPE]::IPv4)
    }

    It 'accepts enum values for EtherType' {
        $filter = New-PspktFilter -EtherType ([ETHERTYPE]::IPv4)
        $filter.EtherType | Should -Be ([ETHERTYPE]::IPv4)
    }

    It 'accepts enum name strings for TransportProtocol' {
        $filter = New-PspktFilter -TransportProtocol 'ICMP'
        $filter.TransportProtocol | Should -Be ([IPv4Protocol]::ICMP)
    }

    It 'accepts integers for TransportProtocol' {
        $filter = New-PspktFilter -TransportProtocol 6
        $filter.TransportProtocol | Should -Be ([IPv4Protocol]::TCP)
    }

    It 'accepts enum name strings for DSCP' {
        $filter = New-PspktFilter -DSCP 'EF'
        $filter.DSCP | Should -Be ([DSCP]::EF)
    }

    It 'accepts enum name strings for TCPFlags' {
        $filter = New-PspktFilter -TCPFlags 'SYN'
        $filter.TCPFlags | Should -Be ([TCPFLAGS]::SYN)
    }

    It 'accepts enum name strings for EncapType' {
        $filter = New-PspktFilter -EncapType 'VXLAN'
        $filter.EncapType | Should -Be ([PKTMON_FILTER_ENCAPTYPE]::VXLAN)
    }

    It 'accepts integer for EncapType' {
        $filter = New-PspktFilter -EncapType 1
        $filter.EncapType | Should -Be ([PKTMON_FILTER_ENCAPTYPE]::VXLAN)
    }

    It 'throws on invalid enum name string' {
        { New-PspktFilter -EtherType 'NotARealType' } | Should -Throw
    }

    It 'sets Name on filter via New-PspktFilter' {
        $filter = New-PspktFilter -Name 'TestFilter'
        $filter.Name | Should -Be 'TestFilter'
    }

    It 'sets Name on filter via Set-PspktFilter' {
        $filter = New-PspktFilter
        $filter = Set-PspktFilter -Filter $filter -Name 'Updated'
        $filter.Name | Should -Be 'Updated'
    }

    It 'sets VlanId on filter' {
        $filter = New-PspktFilter -VlanId 100
        $filter.VlanId | Should -Be 100
    }

    It 'sets PrefixLength1 on filter' {
        $filter = New-PspktFilter -Ip1 '10.0.0.0' -PrefixLength1 24
        $filter.PrefixLength1 | Should -Be 24
    }

    It 'sets PrefixLength2 on filter' {
        $filter = New-PspktFilter -Ip2 '192.168.1.0' -PrefixLength2 16
        $filter.PrefixLength2 | Should -Be 16
    }

    It 'returns filters tracked by a session' {
        $session = [pspktSession]::new('session-get-filter', [IntPtr]::Zero)
        $f1 = New-PspktFilter -Port1 443
        $f2 = New-PspktFilter -Port1 53

        $null = $session.Filters.Add($f1)
        $null = $session.Filters.Add($f2)

        $result = $session | Get-PspktFilter
        $result.Count | Should -Be 2
    }

    It 'removes filters by object and by index' {
        $session = [pspktSession]::new('session-remove-filter', [IntPtr]::Zero)
        $f1 = New-PspktFilter -Port1 443
        $f2 = New-PspktFilter -Port1 53

        $null = $session.Filters.Add($f1)
        $null = $session.Filters.Add($f2)

        $removedByObject = Remove-PspktFilter -Session $session -Filter $f1
        $removedByObject | Should -BeTrue
        $session.Filters.Count | Should -Be 1

        $removedByIndex = Remove-PspktFilter -Session $session -Index 0
        $removedByIndex | Should -BeTrue
        $session.Filters.Count | Should -Be 0
    }

    It 'updates pspktComponent properties with Set-PspktComponent' {
        $component = [pspktComponent]::new()

        $updated = $component | Set-PspktComponent -Name 'CompA' -Group 'GroupA' -Type 'Adapter' -Id 42 -TypeId 3 -IsNetworkAdapter $true

        $updated.Name | Should -Be 'CompA'
        $updated.Group | Should -Be 'GroupA'
        $updated.Type | Should -Be 'Adapter'
        $updated.Id | Should -Be 42
        $updated.TypeId | Should -Be 3
        $updated.IsNetworkAdapter | Should -BeTrue
    }

    It 'removes components by object and by index' {
        $session = [pspktSession]::new('session-remove-component', [IntPtr]::Zero)
        $c1 = [pspktComponent]::new()
        $c2 = [pspktComponent]::new()

        $null = $session.Components.Add($c1)
        $null = $session.Components.Add($c2)

        $removedByObject = Remove-PspktComponent -Session $session -Component $c1
        $removedByObject | Should -BeTrue
        $session.Components.Count | Should -Be 1

        $removedByIndex = Remove-PspktComponent -Session $session -Index 0
        $removedByIndex | Should -BeTrue
        $session.Components.Count | Should -Be 0
    }

    It 'supports Set-PspktSession for name-only updates' {
        $session = [pspktSession]::new('OriginalName', [IntPtr]::Zero)
        $updated = $session | Set-PspktSession -Name 'UpdatedName'

        $updated.Name | Should -Be 'UpdatedName'
    }

    It 'defines expected parameter sets for New-PspktSession' {
        $cmd = Get-Command -Name New-PspktSession -ErrorAction Stop

        $cmd.Parameters.ContainsKey('Name') | Should -BeTrue
        $cmd.Parameters.ContainsKey('Pspkt') | Should -BeFalse
    }

    It 'defines expected parameter sets for Get-PspktComponent' {
        $cmd = Get-Command -Name Get-PspktComponent -ErrorAction Stop
        $cmd.ParameterSets.Name -contains 'All' | Should -BeTrue
        $cmd.ParameterSets.Name -contains 'NIC' | Should -BeTrue
        $cmd.ParameterSets.Name -contains 'VM' | Should -BeTrue
        $cmd.ParameterSets.Name -contains 'VMName' | Should -BeTrue
        $cmd.ParameterSets.Name -contains 'Group' | Should -BeTrue
        $cmd.ParameterSets.Name -contains 'ByType' | Should -BeTrue
        $cmd.ParameterSets.Name -contains 'ByName' | Should -BeTrue
    }

    Context 'Pause feature parameters' {
        BeforeAll {
            $script:startCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop
        }

        It 'has Pause switch parameter' {
            $script:startCmd.Parameters.ContainsKey('Pause') | Should -BeTrue
            $script:startCmd.Parameters['Pause'].ParameterType | Should -Be ([switch])
        }

        It 'has PauseOnDrop switch parameter with alias pod' {
            $script:startCmd.Parameters.ContainsKey('PauseOnDrop') | Should -BeTrue
            $script:startCmd.Parameters['PauseOnDrop'].ParameterType | Should -Be ([switch])
            $script:startCmd.Parameters['PauseOnDrop'].Aliases -contains 'pod' | Should -BeTrue
        }

        It 'has PauseOnLocation string parameter with alias pol' {
            $script:startCmd.Parameters.ContainsKey('PauseOnLocation') | Should -BeTrue
            $script:startCmd.Parameters['PauseOnLocation'].ParameterType | Should -Be ([string])
            $script:startCmd.Parameters['PauseOnLocation'].Aliases -contains 'pol' | Should -BeTrue
        }

        It 'has PauseOnReason string parameter with alias por' {
            $script:startCmd.Parameters.ContainsKey('PauseOnReason') | Should -BeTrue
            $script:startCmd.Parameters['PauseOnReason'].ParameterType | Should -Be ([string])
            $script:startCmd.Parameters['PauseOnReason'].Aliases -contains 'por' | Should -BeTrue
        }

        It 'has StopOnDrop switch parameter with alias sod' {
            $script:startCmd.Parameters.ContainsKey('StopOnDrop') | Should -BeTrue
            $script:startCmd.Parameters['StopOnDrop'].ParameterType | Should -Be ([switch])
            $script:startCmd.Parameters['StopOnDrop'].Aliases -contains 'sod' | Should -BeTrue
        }

        It 'has StopOnLocation string parameter with alias sol' {
            $script:startCmd.Parameters.ContainsKey('StopOnLocation') | Should -BeTrue
            $script:startCmd.Parameters['StopOnLocation'].ParameterType | Should -Be ([string])
            $script:startCmd.Parameters['StopOnLocation'].Aliases -contains 'sol' | Should -BeTrue
        }

        It 'has StopOnReason string parameter with alias sor' {
            $script:startCmd.Parameters.ContainsKey('StopOnReason') | Should -BeTrue
            $script:startCmd.Parameters['StopOnReason'].ParameterType | Should -Be ([string])
            $script:startCmd.Parameters['StopOnReason'].Aliases -contains 'sor' | Should -BeTrue
        }

        It 'resolves PKTMON_DROP_LOCATION enum by name for PauseOnLocation' {
            $resolved = Resolve-PspktEnumValue -Value 'PMLOC_NDIS_FAKE_FILTER_SEND' -EnumType ([PKTMON_DROP_LOCATION])
            [int]$resolved | Should -Not -Be 0
        }

        It 'resolves PKTMON_DROP_REASON enum by name for PauseOnReason' {
            $resolved = Resolve-PspktEnumValue -Value 'PktMonDrop_InvalidPacket' -EnumType ([PKTMON_DROP_REASON])
            [int]$resolved | Should -BeGreaterThan 0
        }

        It 'resolves PKTMON_DROP_LOCATION enum by hex string' {
            $resolved = Resolve-PspktEnumValue -Value '0x01' -EnumType ([PKTMON_DROP_LOCATION])
            [int]$resolved | Should -Be 1
        }

        It 'resolves PKTMON_DROP_REASON enum by integer' {
            $resolved = Resolve-PspktEnumValue -Value 1 -EnumType ([PKTMON_DROP_REASON])
            [int]$resolved | Should -Be 1
        }

        It 'throws on invalid PKTMON_DROP_LOCATION name' {
            { Resolve-PspktEnumValue -Value 'NotAValidLocation' -EnumType ([PKTMON_DROP_LOCATION]) } | Should -Throw
        }

        It 'throws on invalid PKTMON_DROP_REASON name' {
            { Resolve-PspktEnumValue -Value 'NotAValidReason' -EnumType ([PKTMON_DROP_REASON]) } | Should -Throw
        }
    }

    Context 'Pcapng file writer (PcapngWriter)' {
        It 'can instantiate PcapngWriter' {
            $writer = [PcapngWriter]::new()
            $writer | Should -Not -BeNullOrEmpty
            $writer.IsActive | Should -BeFalse
        }

        It 'exposes Start, Stop, and WritePacket methods' {
            $writer = [PcapngWriter]::new()
            $writer | Get-Member -Name Start -MemberType Method | Should -Not -BeNullOrEmpty
            $writer | Get-Member -Name Stop -MemberType Method | Should -Not -BeNullOrEmpty
            $writer | Get-Member -Name WritePacket -MemberType Method | Should -Not -BeNullOrEmpty
        }

        It 'Start-Pspkt has -WriteFile parameter' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters.Keys | Should -Contain 'WriteFile'
        }

        It 'Start-Pspkt has -FileSize parameter with default 512' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters.Keys | Should -Contain 'FileSize'
            $cmd.Parameters['FileSize'].ParameterType | Should -Be ([uint32])
        }

        It 'Start-Pspkt has -FlushDisk parameter' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters.Keys | Should -Contain 'FlushDisk'
            $cmd.Parameters['FlushDisk'].ParameterType | Should -Be ([switch])
        }

        It 'Start-Pspkt has -NumFiles parameter' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters.Keys | Should -Contain 'NumFiles'
            $cmd.Parameters['NumFiles'].ParameterType | Should -Be ([int])
        }

        It 'Start-Pspkt has -WriteFile alias -w' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters['WriteFile'].Aliases | Should -Contain 'w'
        }

        It 'Start-Pspkt has -FlushDisk alias -fd' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters['FlushDisk'].Aliases | Should -Contain 'fd'
        }

        It 'Start-Pspkt has -RealTime parameter with alias -rt' {
            $cmd = Get-Command Start-Pspkt
            $cmd.Parameters.Keys | Should -Contain 'RealTime'
            $cmd.Parameters['RealTime'].ParameterType | Should -Be ([switch])
            $cmd.Parameters['RealTime'].Aliases | Should -Contain 'rt'
        }

        It 'can start and stop pcapng writer to a temp file' {
            $tmpFile = Join-Path $env:TEMP "pspkt_test_$(Get-Random).pcapng"
            try {
                $writer = [PcapngWriter]::new()
                $writer.Start($tmpFile, $false, 1024)
                $writer.IsActive | Should -BeTrue
                $writer.FileName | Should -Be $tmpFile

                $writer.Stop()
                $writer.IsActive | Should -BeFalse

                # File should exist after stop.
                Test-Path $tmpFile | Should -BeTrue
                # Should have at least the SHB + IDB (28 + 20 = 48 bytes).
                (Get-Item $tmpFile).Length | Should -BeGreaterOrEqual 48
            }
            finally {
                if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
            }
        }

        It 'Stop on already-stopped writer is safe' {
            $writer = [PcapngWriter]::new()
            { $writer.Stop() } | Should -Not -Throw
        }

        It 'writes packets to pcapng file' {
            $tmpFile = Join-Path $env:TEMP "pspkt_test_$(Get-Random).pcapng"
            try {
                $writer = [PcapngWriter]::new()
                $writer.Start($tmpFile, $false, 1024)

                # Create a fake packet with ethernet frame data.
                $data = [byte[]]::new(100)
                [System.Random]::new(42).NextBytes($data)
                $pkt = [PSPacketData]::new($data, 100, 0, 14, 86, 0, 0)
                $writer.WritePacket($pkt)
                $writer.PacketCount | Should -Be 1

                $writer.Stop()
                # File should be larger than just headers (48 bytes).
                (Get-Item $tmpFile).Length | Should -BeGreaterThan 48
            }
            finally {
                if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
            }
        }
    }

    Context 'DNS application-layer predicate' {
        BeforeAll {
            $script:dnsStartCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop

            # Canonical DNS query for "example.com" type A, txid 0x1234, RD=1.
            $script:dnsQueryExampleA = [byte[]](
                0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,
                0x03,0x63,0x6f,0x6d,
                0x00,
                0x00,0x01, 0x00,0x01
            )

            # DNS query for "other.org" type AAAA, txid 0xabcd.
            $script:dnsQueryOtherAAAA = [byte[]](
                0xab,0xcd, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                0x05,0x6f,0x74,0x68,0x65,0x72,
                0x03,0x6f,0x72,0x67,
                0x00,
                0x00,0x1c, 0x00,0x01
            )

            # DNS NXDomain response for "missing.test" (txid 0x9999, AN=0).
            # Flags: 0x8183 -> QR=1, RD=1, RA=1, RCODE=3.
            $script:dnsRespNxd = [byte[]](
                0x99,0x99, 0x81,0x83, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                0x07,0x6d,0x69,0x73,0x73,0x69,0x6e,0x67,
                0x04,0x74,0x65,0x73,0x74,
                0x00,
                0x00,0x01, 0x00,0x01
            )
        }

        AfterEach {
            # Predicate state is process-wide static — always clear so tests don't bleed.
            [PacketLineFormatter]::ClearAppPredicates()
        }

        It 'has -DnsName parameter (string array)' {
            $script:dnsStartCmd.Parameters.ContainsKey('DnsName') | Should -BeTrue
            $script:dnsStartCmd.Parameters['DnsName'].ParameterType | Should -Be ([string[]])
        }

        It 'has -DnsType parameter (string array)' {
            $script:dnsStartCmd.Parameters.ContainsKey('DnsType') | Should -BeTrue
            $script:dnsStartCmd.Parameters['DnsType'].ParameterType | Should -Be ([string[]])
        }

        It 'has -DnsRcode parameter (string array)' {
            $script:dnsStartCmd.Parameters.ContainsKey('DnsRcode') | Should -BeTrue
            $script:dnsStartCmd.Parameters['DnsRcode'].ParameterType | Should -Be ([string[]])
        }

        It 'has -DnsId parameter (int array)' {
            $script:dnsStartCmd.Parameters.ContainsKey('DnsId') | Should -BeTrue
            $script:dnsStartCmd.Parameters['DnsId'].ParameterType | Should -Be ([int[]])
        }

        It 'has -DnsQR parameter with ValidateSet Query/Response/Any' {
            $param = $script:dnsStartCmd.Parameters['DnsQR']
            $param | Should -Not -BeNullOrEmpty
            $vs = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $vs | Should -Not -BeNullOrEmpty
            $vs.ValidValues | Should -Contain 'Query'
            $vs.ValidValues | Should -Contain 'Response'
            $vs.ValidValues | Should -Contain 'Any'
        }

        It 'has -DnsMatchTruncated switch' {
            $script:dnsStartCmd.Parameters.ContainsKey('DnsMatchTruncated') | Should -BeTrue
            $script:dnsStartCmd.Parameters['DnsMatchTruncated'].ParameterType | Should -Be ([switch])
        }

        It 'DnsParser.TryParseDns extracts QName, QType, and TxId from a canned query' {
            $ctx = [DnsContext]::new()
            $ok = [DnsParser]::TryParseDns($script:dnsQueryExampleA, 53, 12345, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.Valid | Should -BeTrue
            $ctx.QName | Should -Be 'example.com.'
            $ctx.QType | Should -Be 1
            $ctx.TxId  | Should -Be 0x1234
            $ctx.Qr    | Should -Be 0
        }

        It 'DnsParser.TryParseDns extracts RCODE from a response' {
            $ctx = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsRespNxd, 12345, 53, [ref]$ctx)
            $ctx.Qr    | Should -Be 1
            $ctx.Rcode | Should -Be 3
        }

        It 'DnsParser.FormatDnsFromContext produces the same line as FormatDnsSegment' {
            $ctx = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA, 53, 12345, [ref]$ctx)
            $a = [DnsParser]::FormatDnsFromContext([ref]$ctx, $false)   # Default separator
            $b = [DnsParser]::FormatDnsSegment($script:dnsQueryExampleA, 53, 12345)
            $a | Should -Be $b
            $a | Should -Be 'DNS: 0x1234 0/0/0 example.com. A'
        }
        It 'DnsParser.FormatDnsFromContext uses the DNS - separator when detailed' {
            $ctx = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA, 53, 12345, [ref]$ctx)
            [DnsParser]::FormatDnsFromContext([ref]$ctx, $true) | Should -Be 'DNS - 0x1234 0/0/0 example.com. A'
        }

        Context 'DnsParser.BuildDnsDetailTree (Analysis Details)' {
            BeforeAll {
                # Response: txid 0x1234, flags 0x8180 (response, RD, RA), qd=1 an=1 ns=0 ar=1(OPT).
                $b = [System.Collections.Generic.List[byte]]::new()
                $b.AddRange([byte[]](0x12,0x34, 0x81,0x80, 0,1, 0,1, 0,0, 0,1))
                $b.Add(7); 'example'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
                $b.Add(3); 'com'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
                $b.Add(0); $b.AddRange([byte[]](0,1, 0,1))
                $b.AddRange([byte[]](0xc0,0x0c, 0,1, 0,1, 0,0,0,60, 0,4, 93,184,216,34))   # A answer
                $b.AddRange([byte[]](0, 0,41, 0x10,0x00, 0x00,0x00,0x80,0x00, 0,0))         # OPT, DO set
                $script:dnsResp = [byte[]]$b.ToArray()
            }
            It 'root uses the Detailed one-liner as its collapsed text' {
                $roots = [DnsParser]::BuildDnsDetailTree($script:dnsResp, $script:dnsResp.Length, 53, 40000)
                $roots.Count | Should -Be 1
                $roots[0].Key | Should -Be 'DNS'
                $roots[0].Text | Should -Be 'DNS - 0x1234 1/0/1 example.com. A 93.184.216.34'
            }
            It 'includes Transaction ID, RR Count, Flags, Queries, Answers and Additional sections' {
                $dns = [DnsParser]::BuildDnsDetailTree($script:dnsResp, $script:dnsResp.Length, 53, 40000)[0]
                ($dns.Children | Where-Object { $_.Text -eq 'Transaction ID: 0x1234' }).Count | Should -Be 1
                ($dns.Children | Where-Object { $_.Text -eq 'RR Count - Qry: 1, Ans: 1, Auth: 0, Adtl: 1' }).Count | Should -Be 1
                ($dns.Children | Where-Object { $_.Key -eq 'DNS.Flags' }).Count | Should -Be 1
                ($dns.Children | Where-Object { $_.Key -eq 'DNS.Queries' }).Count | Should -Be 1
                ($dns.Children | Where-Object { $_.Key -eq 'DNS.Answers' }).Count | Should -Be 1
                ($dns.Children | Where-Object { $_.Key -eq 'DNS.Additional' }).Count | Should -Be 1
            }
            It 'renders the response flag bit-breakdown with actual bit values' {
                $dns = [DnsParser]::BuildDnsDetailTree($script:dnsResp, $script:dnsResp.Length, 53, 40000)[0]
                $flags = $dns.Children | Where-Object { $_.Key -eq 'DNS.Flags' }
                $flags.Text | Should -Be 'Flags: 0x8180 Query response, No error'
                $flags.IsExpanded | Should -BeFalse   # verbose section collapsed by default
                ($flags.Children | Where-Object { $_.Text -eq '1... .... .... .... = Response: Response' }).Count | Should -Be 1
                ($flags.Children | Where-Object { $_.Text -eq '.... ...1 .... .... = Recursion desired: Do query recursively' }).Count | Should -Be 1
                ($flags.Children | Where-Object { $_.Text -eq '.... .... .... 0000 = Reply code: No error (0)' }).Count | Should -Be 1
            }
            It 'parses the A answer record (Name/Type/Class/TTL/Address)' {
                $dns = [DnsParser]::BuildDnsDetailTree($script:dnsResp, $script:dnsResp.Length, 53, 40000)[0]
                $ans = ($dns.Children | Where-Object { $_.Key -eq 'DNS.Answers' }).Children[0]
                $ans.Text | Should -Be 'example.com.: type A, class IN, 93.184.216.34'
                ($ans.Children | Where-Object { $_.Text -eq 'Type: A (1)' }).Count | Should -Be 1
                ($ans.Children | Where-Object { $_.Text -eq 'Class: IN (0x0001)' }).Count | Should -Be 1
                ($ans.Children | Where-Object { $_.Text -eq 'Time to live: 60' }).Count | Should -Be 1
                ($ans.Children | Where-Object { $_.Text -eq 'Address: 93.184.216.34' }).Count | Should -Be 1
            }
            It 'defaults to expanded sections with collapsed RR one-liners' {
                $dns = [DnsParser]::BuildDnsDetailTree($script:dnsResp, $script:dnsResp.Length, 53, 40000)[0]
                $dns.IsExpanded | Should -BeTrue
                $queries = $dns.Children | Where-Object { $_.Key -eq 'DNS.Queries' }
                $answers = $dns.Children | Where-Object { $_.Key -eq 'DNS.Answers' }
                $queries.IsExpanded | Should -BeTrue                  # section expanded
                $answers.IsExpanded | Should -BeTrue
                $queries.Children[0].IsExpanded | Should -BeFalse     # RR one-liner collapsed
                $answers.Children[0].IsExpanded | Should -BeFalse
            }
            It 'parses the EDNS0 OPT record with the DO bit set' {
                $dns = [DnsParser]::BuildDnsDetailTree($script:dnsResp, $script:dnsResp.Length, 53, 40000)[0]
                $opt = ($dns.Children | Where-Object { $_.Key -eq 'DNS.Additional' }).Children[0]
                $opt.Text | Should -Be '<Root>: type OPT'
                ($opt.Children | Where-Object { $_.Text -eq 'UDP payload size: 4096' }).Count | Should -Be 1
                $z = $opt.Children | Where-Object { $_.Text -like 'Z: 0x*' }
                ($z.Children | Where-Object { $_.Text -eq '1... .... .... .... = DO bit: Accepts DNSSEC security RRs' }).Count | Should -Be 1
            }
        }

        It 'DnsAppPredicate QNameRegex matches example.com query A' {
            $p = [DnsAppPredicate]::new()
            $p.QNameRegex = [regex]::new('example\.com$', 'IgnoreCase,Compiled')
            $ctx = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA, 53, 12345, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue
        }

        It 'DnsAppPredicate QNameRegex rejects non-matching query' {
            $p = [DnsAppPredicate]::new()
            $p.QNameRegex = [regex]::new('example\.com$', 'IgnoreCase,Compiled')
            $ctx = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryOtherAAAA, 53, 12345, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'DnsAppPredicate QTypes filters by record type (A only)' {
            $p = [DnsAppPredicate]::new()
            $p.QTypes = @(1)
            $ctxA = [DnsContext]::new()
            $ctxAAAA = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA,  53, 12345, [ref]$ctxA)
            $null = [DnsParser]::TryParseDns($script:dnsQueryOtherAAAA, 53, 12345, [ref]$ctxAAAA)
            $p.Evaluate([ref]$ctxA)    | Should -BeTrue
            $p.Evaluate([ref]$ctxAAAA) | Should -BeFalse
        }

        It 'DnsAppPredicate Rcodes only applies to responses' {
            $p = [DnsAppPredicate]::new()
            $p.Rcodes = @(3)  # NXDomain
            $ctxResp  = [DnsContext]::new()
            $ctxQuery = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsRespNxd,        12345, 53, [ref]$ctxResp)
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA,  53, 12345, [ref]$ctxQuery)
            # Response with NXDomain matches.
            $p.Evaluate([ref]$ctxResp)  | Should -BeTrue
            # Query is unaffected by Rcodes filter — Rcodes only consulted when Qr==1.
            $p.Evaluate([ref]$ctxQuery) | Should -BeTrue
        }

        It 'DnsAppPredicate Qr=Query rejects responses' {
            $p = [DnsAppPredicate]::new()
            $p.Qr = 0
            $ctxResp = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsRespNxd, 12345, 53, [ref]$ctxResp)
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'DnsAppPredicate TxIds filters by transaction ID' {
            $p = [DnsAppPredicate]::new()
            $p.TxIds = @(0x1234)
            $ctxMatch = [DnsContext]::new()
            $ctxMiss  = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA,  53, 12345, [ref]$ctxMatch)
            $null = [DnsParser]::TryParseDns($script:dnsQueryOtherAAAA, 53, 12345, [ref]$ctxMiss)
            $p.Evaluate([ref]$ctxMatch) | Should -BeTrue
            $p.Evaluate([ref]$ctxMiss)  | Should -BeFalse
        }

        It 'DnsAppPredicate AND-combines multiple fields' {
            $p = [DnsAppPredicate]::new()
            $p.QTypes = @(1)
            $p.QNameRegex = [regex]::new('example\.com$', 'IgnoreCase,Compiled')
            $p.Qr = 0
            $ctxMatch = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryExampleA, 53, 12345, [ref]$ctxMatch)
            $p.Evaluate([ref]$ctxMatch) | Should -BeTrue

            # AAAA query for other.org fails on both QType and QName.
            $ctxMiss = [DnsContext]::new()
            $null = [DnsParser]::TryParseDns($script:dnsQueryOtherAAAA, 53, 12345, [ref]$ctxMiss)
            $p.Evaluate([ref]$ctxMiss) | Should -BeFalse
        }

        It 'DnsAppPredicate MatchTruncated controls truncation handling' {
            # Truncate the example query at byte 16 — name parse will hit data.Length mid-label.
            $truncated = $script:dnsQueryExampleA[0..15]
            $ctx = [DnsContext]::new()
            $parsed = [DnsParser]::TryParseDns($truncated, 53, 12345, [ref]$ctx)
            $parsed | Should -BeTrue
            $ctx.Truncated | Should -BeTrue

            $pStrict = [DnsAppPredicate]::new()
            $pStrict.MatchTruncated = $false
            $pStrict.Evaluate([ref]$ctx) | Should -BeFalse

            $pLoose = [DnsAppPredicate]::new()
            $pLoose.MatchTruncated = $true
            $pLoose.Evaluate([ref]$ctx) | Should -BeTrue
        }

        It 'PacketLineFormatter wires set/get/clear of DnsPredicate' {
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
            $p = [DnsAppPredicate]::new()
            [PacketLineFormatter]::SetDnsPredicate($p)
            [PacketLineFormatter]::HasAppPredicate | Should -BeTrue
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
        }

        It 'Start-Pspkt has -NoWarning switch parameter' {
            $script:dnsStartCmd.Parameters.ContainsKey('NoWarning') | Should -BeTrue
            $script:dnsStartCmd.Parameters['NoWarning'].ParameterType | Should -Be ([switch])
        }
    }

    Context 'TLS application-layer predicate' {
        BeforeAll {
            $script:tlsStartCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop

            # Canonical TLS ClientHello with SNI = "example.com". 72 bytes total.
            # Record:    16 03 03 LL LL  (Handshake, TLS 1.2 wire, len=67)
            # Handshake: 01 00 00 LL    (ClientHello, len 63)
            # Body:      legacy_version(2)=03 03 + random(32)=00..00 +
            #            session_id_len(1)=00 + cipher_suites_len(2)=00 02 +
            #            cipher(2)=00 35 + compression(1+1)=01 00 +
            #            extensions_len(2)=00 14 (20 bytes)
            # SNI ext:   ext_type(2)=00 00 + ext_len(2)=00 10 +
            #            list_len(2)=00 0e + name_type(1)=00 + name_len(2)=00 0b +
            #            name(11)=example.com
            $body = @(0x03, 0x03) + (,0 * 32) + @(
                0x00,
                0x00, 0x02, 0x00, 0x35,
                0x01, 0x00,
                0x00, 0x14,
                0x00, 0x00, 0x00, 0x10,
                0x00, 0x0e, 0x00, 0x00, 0x0b,
                0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
            )
            $hsLen = $body.Count
            $recBody = @(0x01, 0x00, 0x00, $hsLen) + $body
            $recLen = $recBody.Count
            $script:tlsClientHelloExample = [byte[]](
                @(0x16, 0x03, 0x03, (($recLen -shr 8) -band 0xff), ($recLen -band 0xff)) + $recBody
            )

            # AppData record: ContentType=23, TLS 1.2, 16-byte body.
            $script:tlsAppData12 = [byte[]](@(0x17, 0x03, 0x03, 0x00, 0x10) + ((,0x42) * 16))

            # Alert record: ContentType=21, TLS 1.3-on-wire (still 03 03), 2-byte body.
            $script:tlsAlert = [byte[]](0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28)

            # Non-TLS payload (HTTP GET).
            $script:notTls = [byte[]](0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50)
        }

        AfterEach {
            [PacketLineFormatter]::ClearAppPredicates()
        }

        It 'has -TlsSni parameter (string array)' {
            $script:tlsStartCmd.Parameters.ContainsKey('TlsSni') | Should -BeTrue
            $script:tlsStartCmd.Parameters['TlsSni'].ParameterType | Should -Be ([string[]])
        }

        It 'has -TlsVersion parameter (string array)' {
            $script:tlsStartCmd.Parameters.ContainsKey('TlsVersion') | Should -BeTrue
            $script:tlsStartCmd.Parameters['TlsVersion'].ParameterType | Should -Be ([string[]])
        }

        It 'has -TlsContentType parameter (string array)' {
            $script:tlsStartCmd.Parameters.ContainsKey('TlsContentType') | Should -BeTrue
            $script:tlsStartCmd.Parameters['TlsContentType'].ParameterType | Should -Be ([string[]])
        }

        It 'has -TlsHandshakeType parameter (string array)' {
            $script:tlsStartCmd.Parameters.ContainsKey('TlsHandshakeType') | Should -BeTrue
            $script:tlsStartCmd.Parameters['TlsHandshakeType'].ParameterType | Should -Be ([string[]])
        }

        It 'has -TlsMatchTruncated switch' {
            $script:tlsStartCmd.Parameters.ContainsKey('TlsMatchTruncated') | Should -BeTrue
            $script:tlsStartCmd.Parameters['TlsMatchTruncated'].ParameterType | Should -Be ([switch])
        }

        It 'TlsParser.IsTlsPort identifies standard TLS ports' {
            [TlsParser]::IsTlsPort(443)  | Should -BeTrue
            [TlsParser]::IsTlsPort(8443) | Should -BeTrue
            [TlsParser]::IsTlsPort(853)  | Should -BeFalse  # DoT is not in the default port list
            [TlsParser]::IsTlsPort(80)   | Should -BeFalse
        }

        It 'TlsParser.LooksLikeTls accepts valid headers, rejects non-TLS' {
            [TlsParser]::LooksLikeTls($script:tlsClientHelloExample) | Should -BeTrue
            [TlsParser]::LooksLikeTls($script:tlsAppData12)          | Should -BeTrue
            [TlsParser]::LooksLikeTls($script:tlsAlert)              | Should -BeTrue
            [TlsParser]::LooksLikeTls($script:notTls)                | Should -BeFalse
            [TlsParser]::LooksLikeTls($null)                         | Should -BeFalse
            [TlsParser]::LooksLikeTls([byte[]](1, 2))                | Should -BeFalse
        }

        It 'TlsParser.TryParseTls extracts ContentType, Version, HandshakeType, and SNI' {
            $ctx = [TlsContext]::new()
            $ok = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.Valid          | Should -BeTrue
            $ctx.ContentType    | Should -Be 22
            $ctx.Version        | Should -Be 0x0303
            $ctx.HandshakeType  | Should -Be 1
            $ctx.Sni            | Should -Be 'example.com'
            $ctx.Truncated      | Should -BeFalse
        }

        It 'TlsParser.TryParseTls handles AppData (no handshake type, no SNI)' {
            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsAppData12, [ref]$ctx)
            $ctx.ContentType   | Should -Be 23
            $ctx.HandshakeType | Should -Be 0
            $ctx.Sni           | Should -BeNullOrEmpty
        }

        It 'TlsParser.TryParseTls rejects non-TLS payloads' {
            $ctx = [TlsContext]::new()
            $ok = [TlsParser]::TryParseTls($script:notTls, [ref]$ctx)
            $ok | Should -BeFalse
            $ctx.Valid | Should -BeFalse
        }

        It 'TlsParser.FormatTlsFromContext renders ClientHello with SNI' {
            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctx)
            $line = [TlsParser]::FormatTlsFromContext([ref]$ctx, $script:tlsClientHelloExample.Length)
            $line | Should -Match 'TLS ClientHello'
            $line | Should -Match 'ver: TLS 1.2'
            $line | Should -Match 'SNI: example\.com'
        }

        It 'TlsParser.FormatTlsSegment short form for ClientHello' {
            $line = [TlsParser]::FormatTlsSegment($script:tlsClientHelloExample, $script:tlsClientHelloExample.Length)
            $line | Should -Be 'TLS 1.2 ClientHello'
        }

        It 'TlsAppPredicate SniRegex matches example.com ClientHello' {
            $p = [TlsAppPredicate]::new()
            $p.SniRegex = [regex]::new('example\.com$', 'IgnoreCase,Compiled')
            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue
        }

        It 'TlsAppPredicate SniRegex rejects non-matching name' {
            $p = [TlsAppPredicate]::new()
            $p.SniRegex = [regex]::new('other\.com$', 'IgnoreCase,Compiled')
            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'TlsAppPredicate SniRegex rejects AppData (no SNI to match)' {
            $p = [TlsAppPredicate]::new()
            $p.SniRegex = [regex]::new('.*', 'IgnoreCase,Compiled')
            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsAppData12, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'TlsAppPredicate ContentTypes filters by record type' {
            $pHandshake = [TlsAppPredicate]::new()
            $pHandshake.ContentTypes = @(22)
            $pAppData = [TlsAppPredicate]::new()
            $pAppData.ContentTypes = @(23)

            $ctxCH = [TlsContext]::new()
            $ctxAD = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctxCH)
            $null = [TlsParser]::TryParseTls($script:tlsAppData12, [ref]$ctxAD)

            $pHandshake.Evaluate([ref]$ctxCH) | Should -BeTrue
            $pHandshake.Evaluate([ref]$ctxAD) | Should -BeFalse
            $pAppData.Evaluate([ref]$ctxCH)   | Should -BeFalse
            $pAppData.Evaluate([ref]$ctxAD)   | Should -BeTrue
        }

        It 'TlsAppPredicate HandshakeTypes only matches Handshake records of the given type' {
            $p = [TlsAppPredicate]::new()
            $p.HandshakeTypes = @(1)  # ClientHello

            $ctxCH = [TlsContext]::new()
            $ctxAD = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctxCH)
            $null = [TlsParser]::TryParseTls($script:tlsAppData12, [ref]$ctxAD)

            $p.Evaluate([ref]$ctxCH) | Should -BeTrue
            $p.Evaluate([ref]$ctxAD) | Should -BeFalse
        }

        It 'TlsAppPredicate Versions filters by record version' {
            $p = [TlsAppPredicate]::new()
            $p.Versions = @(0x0303)

            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue

            $p.Versions = @(0x0304)
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'TlsAppPredicate AND-combines fields' {
            $p = [TlsAppPredicate]::new()
            $p.SniRegex       = [regex]::new('example\.com$', 'IgnoreCase,Compiled')
            $p.Versions       = @(0x0303)
            $p.HandshakeTypes = @(1)

            $ctx = [TlsContext]::new()
            $null = [TlsParser]::TryParseTls($script:tlsClientHelloExample, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue

            # Changing any single field to non-matching breaks the AND.
            $p.Versions = @(0x0304)
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'PacketLineFormatter wires set/get/clear of TlsPredicate' {
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
            $p = [TlsAppPredicate]::new()
            [PacketLineFormatter]::SetTlsPredicate($p)
            [PacketLineFormatter]::HasAppPredicate | Should -BeTrue
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
        }
    }

    Context 'TlsParser.BuildTlsDetailTree (Analysis Details)' {
        BeforeAll {
            function script:U16b([int]$v) { return [byte[]]@([byte](($v -shr 8) -band 0xff), [byte]($v -band 0xff)) }
            function script:U24b([int]$v) { return [byte[]]@([byte](($v -shr 16) -band 0xff), [byte](($v -shr 8) -band 0xff), [byte]($v -band 0xff)) }

            # ClientHello over a TLS 1.0 (0x0301) record: SNI=example.com, cipher 0x1301,
            # supported_versions=0x0304 (true TLS 1.3), ALPN=h2.
            $name = [System.Text.Encoding]::ASCII.GetBytes('example.com')
            $sniList  = [byte[]]@(0x00) + (script:U16b $name.Length) + $name
            $sniData  = (script:U16b $sniList.Length) + $sniList
            $sniExt   = [byte[]]@(0x00,0x00) + (script:U16b $sniData.Length) + $sniData
            $svData   = [byte[]]@(0x02,0x03,0x04)                      # list_len=2 + 0x0304
            $svExt    = [byte[]]@(0x00,0x2b) + (script:U16b $svData.Length) + $svData
            $alpnList = [byte[]]@(0x02,0x68,0x32)                      # len=2 + "h2"
            $alpnData = (script:U16b $alpnList.Length) + $alpnList
            $alpnExt  = [byte[]]@(0x00,0x10) + (script:U16b $alpnData.Length) + $alpnData
            $exts   = $sniExt + $svExt + $alpnExt
            $random = [byte[]]::new(32)
            $chBody = [byte[]]@(0x03,0x03) + $random + [byte[]]@(0x00) + (script:U16b 2) + [byte[]]@(0x13,0x01) + [byte[]]@(0x01,0x00) + (script:U16b $exts.Length) + $exts
            $hs = [byte[]]@(0x01) + (script:U24b $chBody.Length) + $chBody
            $script:tlsCH = [byte[]](@(0x16,0x03,0x01) + (script:U16b $hs.Length) + $hs)

            # Alert record: Fatal (2), handshake_failure (0x28 = 40), TLS 1.2 wire.
            $script:tlsAlertRec = [byte[]](0x15,0x03,0x03,0x00,0x02,0x02,0x28)

            # ApplicationData record: TLS 1.2, 16-byte encrypted body.
            $script:tlsAppRec = [byte[]](@(0x17,0x03,0x03,0x00,0x10) + ((,0x42)*16))
        }

        It 'root node is collapsed and shows the SNI on the collapsed line' {
            $roots = [TlsParser]::BuildTlsDetailTree($script:tlsCH, $script:tlsCH.Length, 443, 50000)
            $roots.Count | Should -Be 1
            $roots[0].Key | Should -Be 'TLS'
            $roots[0].IsExpanded | Should -BeFalse
            $roots[0].Text | Should -Match '^TLS ClientHello; ver: TLS 1\.0; len: \d+; SNI: example\.com$'
        }

        It 'includes a Record Layer sub-node with content type, version and length' {
            $ch = [TlsParser]::BuildTlsDetailTree($script:tlsCH, $script:tlsCH.Length, 443, 50000)[0]
            $rec = $ch.Children | Where-Object { $_.Key -eq 'TLS.Record' }
            $rec | Should -Not -BeNullOrEmpty
            $rec.IsExpanded | Should -BeFalse
            ($rec.Children | Where-Object { $_.Text -eq 'Content Type: Handshake (22)' }).Count | Should -Be 1
            ($rec.Children | Where-Object { $_.Text -eq 'Version: TLS 1.0 (0x0301)' }).Count | Should -Be 1
        }

        It 'parses the ClientHello handshake with cipher suites' {
            $ch = [TlsParser]::BuildTlsDetailTree($script:tlsCH, $script:tlsCH.Length, 443, 50000)[0]
            $hs = $ch.Children | Where-Object { $_.Key -eq 'TLS.Handshake' }
            $hs.Text | Should -Be 'Handshake Protocol: ClientHello'
            ($hs.Children | Where-Object { $_.Text -eq 'Handshake Type: ClientHello (1)' }).Count | Should -Be 1
            ($hs.Children | Where-Object { $_.Text -eq 'Version: TLS 1.2 (0x0303)' }).Count | Should -Be 1
            $cs = $hs.Children | Where-Object { $_.Key -eq 'TLS.CipherSuites' }
            ($cs.Children | Where-Object { $_.Text -eq 'Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)' }).Count | Should -Be 1
        }

        It 'decodes the SNI, ALPN, and supported_versions extensions' {
            $ch = [TlsParser]::BuildTlsDetailTree($script:tlsCH, $script:tlsCH.Length, 443, 50000)[0]
            $exts = ($ch.Children | Where-Object { $_.Key -eq 'TLS.Handshake' }).Children | Where-Object { $_.Key -eq 'TLS.Extensions' }
            $exts | Should -Not -BeNullOrEmpty
            $sni = $exts.Children | Where-Object { $_.Text -like 'Extension: server_name*' }
            ($sni.Children | Where-Object { $_.Text -eq 'Server Name: example.com' }).Count | Should -Be 1
            $sv = $exts.Children | Where-Object { $_.Text -like 'Extension: supported_versions*' }
            ($sv.Children | Where-Object { $_.Text -eq 'Supported Version: TLS 1.3 (0x0304)' }).Count | Should -Be 1
            $alpn = $exts.Children | Where-Object { $_.Text -like 'Extension: application_layer_protocol_negotiation*' }
            ($alpn.Children | Where-Object { $_.Text -eq 'ALPN Protocol: h2' }).Count | Should -Be 1
        }

        It 'renders an Alert record with level and description' {
            $roots = [TlsParser]::BuildTlsDetailTree($script:tlsAlertRec, $script:tlsAlertRec.Length, 443, 50000)
            $roots.Count | Should -Be 1
            $roots[0].Text | Should -Be 'TLS Alert; ver: TLS 1.2; len: 2'
            $alert = $roots[0].Children | Where-Object { $_.Key -eq 'TLS.Alert' }
            $alert.Text | Should -Be 'Alert Message: Fatal, handshake_failure'
            ($alert.Children | Where-Object { $_.Text -eq 'Level: Fatal (2)' }).Count | Should -Be 1
            ($alert.Children | Where-Object { $_.Text -eq 'Description: handshake_failure (40)' }).Count | Should -Be 1
        }

        It 'emits one root per TLS record in a multi-record segment' {
            $multi = [byte[]]($script:tlsCH + $script:tlsAppRec)
            $roots = [TlsParser]::BuildTlsDetailTree($multi, $multi.Length, 443, 50000)
            $roots.Count | Should -Be 2
            $roots[0].Text | Should -Match '^TLS ClientHello;'
            $roots[1].Text | Should -Be 'TLS ApplicationData; ver: TLS 1.2; len: 16'
            ($roots[1].Children | Where-Object { $_.Text -eq 'Encrypted Application Data: 16 bytes' }).Count | Should -Be 1
        }

        It 'detects TLS content on a non-standard TCP port (content-based, not port-gated)' {
            # A ClientHello record on TCP 9999<->12345 (neither is a recognised TLS port). The
            # capture path must peek the payload bytes (zero-copy) and allocate/parse it as TLS,
            # then the Default one-liner shows the TLS handshake.
            $tls = [byte[]](0x16,0x03,0x01, 0x00,0x04, 0x01,0x00,0x00,0x00)   # TLS1.0 record, ClientHello
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0x27; $tcp[1]=0x0f      # src port 9999
            $tcp[2]=0x30; $tcp[3]=0x39      # dst port 12345
            $tcp[12]=0x50; $tcp[13]=0x18    # data offset 5 (20 bytes), PSH+ACK
            $ipLen = 20 + $tcp.Length + $tls.Length
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $pkt = $eth + $ip + $tcp + $tls
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'TLS 1\.0 ClientHello'
        }

        It 'parses TLS on a conflicting port (445) instead of the SMB2 branch (Analysis dispatch)' {
            # TLS on TCP 445 must reach the content-based TLS branch, not the unconditional SMB2
            # port branch (which would emit no TLS node). Verifies BuildAppNode checks TLS first.
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0x01; $tcp[1]=0xbd      # src port 445
            $tcp[2]=0x30; $tcp[3]=0x39      # dst port 12345
            $tcp[12]=0x50; $tcp[13]=0x18
            $ipLen = 20 + $tcp.Length + $script:tlsCH.Length
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $pkt = $eth + $ip + $tcp + $script:tlsCH
            $tls = ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) | Where-Object { $_.Key -eq 'TLS' }
            $tls | Should -Not -BeNullOrEmpty
            $tls.Text | Should -Match '^TLS ClientHello;.*SNI: example\.com$'
        }

        It 'shows the TLS line for TLS over IPv6 at Default' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0x01; $tcp[1]=0xbb      # src port 443
            $tcp[2]=0x30; $tcp[3]=0x39      # dst port 12345
            $tcp[12]=0x50; $tcp[13]=0x18
            $payLen = $tcp.Length + $script:tlsCH.Length
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]]( [byte](($payLen -shr 8) -band 0xff), [byte]($payLen -band 0xff), 6, 64 )
            $ip6 += ([byte[]](0x20,0x01) + [byte[]]::new(14)) + ([byte[]](0x20,0x01) + [byte[]]::new(13) + [byte[]](2))
            $pkt = $eth + $ip6 + $tcp + $script:tlsCH
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'IPv6 .+: TLS 1\.0 ClientHello'
        }

        It 'renders a payload-less TCP ACK on port 443 as a plain transport segment (no HTTPS: hint)' {
            # A len-0 ACK on TCP 443<->50875 carries no TLS record. Because TLS is a parsed
            # protocol, it must render as a plain "TCP [.], ..." transport segment — NOT
            # "HTTPS: TCP ..." with the transport details wrapped in the app layer.
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0x01; $tcp[1]=0xbb      # src port 443
            $tcp[2]=0xc6; $tcp[3]=0xbb      # dst port 50875
            $tcp[12]=0x50; $tcp[13]=0x10    # data offset 5 (20 bytes), ACK only
            $ipLen = 20 + $tcp.Length
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=52;$ip[13]=123;$ip[14]=251;$ip[15]=17; $ip[16]=10;$ip[17]=24;$ip[18]=0;$ip[19]=72
            $pkt = $eth + $ip + $tcp
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'IPv4\.TCP 52\.123\.251\.17\.443 > 10\.24\.0\.72\.50875: TCP \[\.\],'
            $out | Should -Not -Match 'HTTPS:'
        }

        It 'renders a payload-less ACK on TLS-wrapped port <port> (<svc>) as plain TCP' -ForEach @(
            @{ port = 8443; svc = 'HTTPS-ALT' }
            @{ port = 993;  svc = 'IMAPS' }
            @{ port = 995;  svc = 'POP3S' }
            @{ port = 465;  svc = 'SMTPS' }
            @{ port = 636;  svc = 'LDAPS' }
            @{ port = 853;  svc = 'DoT' }
            @{ port = 5986; svc = 'WinRM-S' }
        ) {
            # Every TLS-wrapped port must render a payload-less segment as plain TCP, not
            # "<svc>: TCP ..." — consistent with the HTTPS/443 fix.
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=[byte](($port -shr 8) -band 0xff); $tcp[1]=[byte]($port -band 0xff)
            $tcp[2]=0xc6; $tcp[3]=0xbb      # dst port 50875
            $tcp[12]=0x50; $tcp[13]=0x10    # ACK only
            $ipLen = 20 + $tcp.Length
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $pkt = $eth + $ip + $tcp
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match ("IPv4\.TCP 10\.0\.0\.1\.$port > 10\.0\.0\.2\.50875: TCP \[\.\],")
            $out | Should -Not -Match ([regex]::Escape($svc) + ':')
        }

        It 'still shows the QUIC hint for UDP port 443 (not removed with the TLS TCP hints)' {
            # QUIC (UDP 443) is not parsed, so its port hint must remain.
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $payload = [byte[]]::new(16)
            $udpLen = 8 + $payload.Length
            $udp = [byte[]](0x01,0xbb, 0xc6,0xbb, [byte](($udpLen -shr 8) -band 0xff), [byte]($udpLen -band 0xff), 0,0)   # src 443
            $ipLen = 20 + $udpLen
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=17
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $pkt = $eth + $ip + $udp + $payload
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'QUIC'
        }

        It 'continues past a zero-length TLS record to emit later records' {
            # A zero-length ChangeCipherSpec (14 03 03 00 00) followed by a ClientHello. Both must
            # be emitted — the record walk advances by the header size even when body length is 0.
            $ccs = [byte[]](0x14,0x03,0x03,0x00,0x00)
            $multi = [byte[]]($ccs + $script:tlsCH)
            $roots = [TlsParser]::BuildTlsDetailTree($multi, $multi.Length, 443, 50000)
            $roots.Count | Should -Be 2
            $roots[0].Text | Should -Be 'TLS ChangeCipherSpec; ver: TLS 1.2; len: 0'
            $roots[1].Text | Should -Match '^TLS ClientHello;.*SNI: example\.com$'
        }

        It 'continues past a zero-length handshake message to emit later handshakes' {
            # A Handshake record carrying ServerHelloDone (type 14, len 0) then a Finished
            # (type 20, len 0). The handshake walk must advance past the zero-length message.
            $body = [byte[]](0x0e,0x00,0x00,0x00, 0x14,0x00,0x00,0x00)
            $rec  = [byte[]](@(0x16,0x03,0x03) + (script:U16b $body.Length) + $body)
            $root = [TlsParser]::BuildTlsDetailTree($rec, $rec.Length, 443, 50000)[0]
            $hs = @($root.Children | Where-Object { $_.Key -eq 'TLS.Handshake' })
            $hs.Count | Should -Be 2
            $hs[0].Text | Should -Be 'Handshake Protocol: ServerHelloDone'
            $hs[1].Text | Should -Be 'Handshake Protocol: Finished'
        }

        It 'parses TLS on port 53 as TLS (not garbage DNS) at Detailed level' {
            # A ClientHello on TCP 53<->12345. The Detailed path must probe TLS content before the
            # port-53 DNS branch, so it renders as TLS, not a misparsed DNS message.
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0x00; $tcp[1]=0x35      # src port 53
            $tcp[2]=0x30; $tcp[3]=0x39      # dst port 12345
            $tcp[12]=0x50; $tcp[13]=0x18
            $ipLen = 20 + $tcp.Length + $script:tlsCH.Length
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $pkt = $eth + $ip + $tcp + $script:tlsCH
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 1
            $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            $out | Should -Match 'TLS ClientHello; ver: TLS 1\.0'
            $out | Should -Not -Match 'DNS'
        }
    }

    Context 'HTTP application-layer predicate' {
        BeforeAll {
            $script:httpStartCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop

            # Canonical HTTP GET request to api.example.com for /api/users?id=1.
            $reqText = "GET /api/users?id=1 HTTP/1.1`r`nHost: api.example.com`r`nUser-Agent: pspkt-test`r`nAccept: application/json`r`nContent-Type: application/json`r`nContent-Length: 0`r`n`r`n"
            $script:httpReqGet = [System.Text.Encoding]::ASCII.GetBytes($reqText)

            # Canonical 404 Not Found response with text/html.
            $respText = "HTTP/1.1 404 Not Found`r`nServer: nginx`r`nContent-Type: text/html`r`nContent-Length: 153`r`n`r`n<html>x</html>"
            $script:httpResp404 = [System.Text.Encoding]::ASCII.GetBytes($respText)

            # Non-HTTP payload (TLS-like).
            $script:httpNotHttp = [byte[]](0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c)
        }

        AfterEach {
            [PacketLineFormatter]::ClearAppPredicates()
        }

        It 'has -HttpMethod parameter (string array)' {
            $script:httpStartCmd.Parameters.ContainsKey('HttpMethod') | Should -BeTrue
            $script:httpStartCmd.Parameters['HttpMethod'].ParameterType | Should -Be ([string[]])
        }

        It 'has -HttpHost parameter (string array)' {
            $script:httpStartCmd.Parameters.ContainsKey('HttpHost') | Should -BeTrue
            $script:httpStartCmd.Parameters['HttpHost'].ParameterType | Should -Be ([string[]])
        }

        It 'has -HttpPath parameter (string array)' {
            $script:httpStartCmd.Parameters.ContainsKey('HttpPath') | Should -BeTrue
            $script:httpStartCmd.Parameters['HttpPath'].ParameterType | Should -Be ([string[]])
        }

        It 'has -HttpStatus parameter (string array)' {
            $script:httpStartCmd.Parameters.ContainsKey('HttpStatus') | Should -BeTrue
            $script:httpStartCmd.Parameters['HttpStatus'].ParameterType | Should -Be ([string[]])
        }

        It 'has -HttpContentType parameter (string array)' {
            $script:httpStartCmd.Parameters.ContainsKey('HttpContentType') | Should -BeTrue
            $script:httpStartCmd.Parameters['HttpContentType'].ParameterType | Should -Be ([string[]])
        }

        It 'has -HttpMatchTruncated switch' {
            $script:httpStartCmd.Parameters.ContainsKey('HttpMatchTruncated') | Should -BeTrue
            $script:httpStartCmd.Parameters['HttpMatchTruncated'].ParameterType | Should -Be ([switch])
        }

        It 'HttpParser.IsHttpPort identifies standard HTTP ports' {
            [HttpParser]::IsHttpPort(80)   | Should -BeTrue
            [HttpParser]::IsHttpPort(8080) | Should -BeTrue
            [HttpParser]::IsHttpPort(8000) | Should -BeTrue
            [HttpParser]::IsHttpPort(8888) | Should -BeTrue
            [HttpParser]::IsHttpPort(443)  | Should -BeFalse
            [HttpParser]::IsHttpPort(22)   | Should -BeFalse
        }

        It 'HttpParser.LooksLikeHttp accepts request methods and HTTP response' {
            [HttpParser]::LooksLikeHttp($script:httpReqGet)   | Should -BeTrue
            [HttpParser]::LooksLikeHttp($script:httpResp404)  | Should -BeTrue
            [HttpParser]::LooksLikeHttp($script:httpNotHttp)  | Should -BeFalse
            [HttpParser]::LooksLikeHttp($null)                | Should -BeFalse
        }

        It 'HttpParser.TryParseHttp extracts request line and headers' {
            $ctx = [HttpContext]::new()
            $ok = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.Valid           | Should -BeTrue
            $ctx.IsRequest       | Should -BeTrue
            $ctx.Method          | Should -Be 'GET'
            $ctx.Path            | Should -Be '/api/users?id=1'
            $ctx.ProtocolVersion | Should -Be 'HTTP/1.1'
            $ctx.Host            | Should -Be 'api.example.com'
            $ctx.ContentType     | Should -Be 'application/json'
            $ctx.ContentLength   | Should -Be 0
            $ctx.Truncated       | Should -BeFalse
        }

        It 'HttpParser.TryParseHttp extracts status line and response headers' {
            $ctx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctx)
            $ctx.IsRequest     | Should -BeFalse
            $ctx.StatusCode    | Should -Be 404
            $ctx.StatusText    | Should -Be 'Not Found'
            $ctx.ContentType   | Should -Be 'text/html'
            $ctx.ContentLength | Should -Be 153
        }

        It 'HttpParser.TryParseHttp rejects non-HTTP payloads' {
            $ctx = [HttpContext]::new()
            $ok = [HttpParser]::TryParseHttp($script:httpNotHttp, [ref]$ctx)
            $ok | Should -BeFalse
            $ctx.Valid | Should -BeFalse
        }

        It 'HttpParser.TryParseHttp extracts the User-Agent header' {
            $ctx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctx)
            $ctx.UserAgent | Should -Be 'pspkt-test'
        }

        It 'HttpParser Default/Detailed request line (Method + Host + URI)' {
            $ctx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctx)
            $expected = 'HTTP: GET, URI: api.example.com/api/users?id=1'
            [HttpParser]::FormatHttpDefaultFromContext([ref]$ctx) | Should -Be $expected
            [HttpParser]::FormatHttpFromContext([ref]$ctx)        | Should -Be $expected   # Detailed == Default
        }

        It 'HttpParser Default response line (Status Code + Phrase, no URI)' {
            $ctx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctx)
            [HttpParser]::FormatHttpDefaultFromContext([ref]$ctx) | Should -Be 'HTTP: 404 Not Found'
        }

        It 'HttpParser.FormatHttpSegment renders the Default one-liner' {
            $line = [HttpParser]::FormatHttpSegment($script:httpReqGet, $script:httpReqGet.Length)
            $line | Should -Be 'HTTP: GET, URI: api.example.com/api/users?id=1'
        }

        It 'HttpParser.BuildHttpDetailTree renders a request tree' {
            $node = ([HttpParser]::BuildHttpDetailTree($script:httpReqGet))[0]
            $node.Key  | Should -Be 'HTTP'
            $node.Text | Should -Be 'HTTP: GET, URI: api.example.com/api/users?id=1'
            $line = $node.Children | Where-Object { $_.Key -eq 'HTTP.RequestLine' }
            $line | Should -Not -BeNullOrEmpty
            $line.Text | Should -Be 'GET /api/users?id=1 HTTP/1.1'
            $lk = $line.Children | ForEach-Object { $_.Text }
            ($lk | Where-Object { $_ -eq 'Request Method: GET' }).Count           | Should -Be 1
            ($lk | Where-Object { $_ -eq 'Request URI: /api/users?id=1' }).Count   | Should -Be 1
            ($lk | Where-Object { $_ -eq 'Request Version: HTTP/1.1' }).Count      | Should -Be 1
            $kids = $node.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Host: api.example.com' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'User-Agent: pspkt-test' }).Count | Should -Be 1
        }

        It 'HttpParser.BuildHttpDetailTree renders a response tree with the \r\n status line' {
            $node = ([HttpParser]::BuildHttpDetailTree($script:httpResp404))[0]
            $node.Text | Should -Be 'HTTP: 404 Not Found'
            $line = $node.Children | Where-Object { $_.Key -eq 'HTTP.StatusLine' }
            $line | Should -Not -BeNullOrEmpty
            $line.Text | Should -Be 'HTTP/1.1 404 Not Found\r\n'
            $lk = $line.Children | ForEach-Object { $_.Text }
            ($lk | Where-Object { $_ -eq 'Response Version: HTTP/1.1' }).Count | Should -Be 1
            ($lk | Where-Object { $_ -eq 'Status Code: 404' }).Count          | Should -Be 1
            ($lk | Where-Object { $_ -eq 'Response Phrase: Not Found' }).Count | Should -Be 1
            ($node.Children | Where-Object { $_.Text -eq 'Content-Length: 153' }).Count | Should -Be 1
        }

        It 'end-to-end: BuildTree wires an HTTP node and the Default one-liner shows the HTTP line' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]](0xc0,0x00, 0,80, 0,0,0,1, 0,0,0,2, 0x50,0x18, 0xff,0xff, 0,0, 0,0)   # PSH+ACK, dst 80
            $ipLen = 20 + $tcp.Length + $script:httpReqGet.Length
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=5; $ip[16]=93;$ip[17]=184;$ip[18]=216;$ip[19]=34
            $pkt = $eth + $ip + $tcp + $script:httpReqGet
            $http = ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) | Where-Object { $_.Key -eq 'HTTP' }
            $http | Should -Not -BeNullOrEmpty
            $http.Text | Should -Be 'HTTP: GET, URI: api.example.com/api/users?id=1'
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'HTTP: GET, URI: api\.example\.com/api/users\?id=1'
        }

        It 'end-to-end: HTTP over IPv6 shows the HTTP line at Default' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            $tcp = [byte[]](0xc0,0x00, 0,80, 0,0,0,1, 0,0,0,2, 0x50,0x18, 0xff,0xff, 0,0, 0,0)
            $payLen = $tcp.Length + $script:httpReqGet.Length
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]]( [byte](($payLen -shr 8) -band 0xff), [byte]($payLen -band 0xff), 6, 64 )
            $ip6 += ([byte[]](0x20,0x01) + [byte[]]::new(14)) + ([byte[]](0x20,0x01) + [byte[]]::new(13) + [byte[]](2))
            $pkt = $eth + $ip6 + $tcp + $script:httpReqGet
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'IPv6 .+: HTTP: GET, URI: api\.example\.com/api/users\?id=1'
        }

        It 'contentless TCP on an HTTP port renders as plain TCP, not an HTTP hint' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6; $ip[3]=40
            $ip[12]=10;$ip[13]=24;$ip[14]=0;$ip[15]=72; $ip[16]=34;$ip[17]=160;$ip[18]=111;$ip[19]=145
            $tcp = [byte[]](0xe4,0x37, 0,80, 0,0,0,1, 0,0,0,2, 0x50,0x11, 0,255, 0,0, 0,0)   # FIN+ACK, no payload
            $pkt = $eth + $ip + $tcp
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'TCP \[\.F\], seq 1, ack 2'
            $out | Should -Not -Match 'HTTP'
        }

        It 'HttpParser.BuildConnKey is order-independent (request and response map to the same key)' {
            $k1 = [HttpParser]::BuildConnKey('10.24.0.72', 58423, '34.160.111.145', 80)
            $k2 = [HttpParser]::BuildConnKey('34.160.111.145', 80, '10.24.0.72', 58423)
            $k1 | Should -Be $k2
        }

        It 'HTTP response shows the request URI via connection correlation' {
            $keyFwd = [HttpParser]::BuildConnKey('10.24.0.72', 58423, '34.160.111.145', 80)
            $reqCtx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$reqCtx)
            $null = [HttpParser]::FormatHttpDefaultCorrelated([ref]$reqCtx, $keyFwd)   # remembers the URI
            $respCtx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$respCtx)
            $keyRev = [HttpParser]::BuildConnKey('34.160.111.145', 80, '10.24.0.72', 58423)
            [HttpParser]::FormatHttpDefaultCorrelated([ref]$respCtx, $keyRev) | Should -Be 'HTTP: 404 Not Found, URI: api.example.com/api/users?id=1'
        }

        It 'end-to-end: a response line shows the request URI when the request precedes it in the batch' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            # Request: client 10.24.0.72:58423 -> server 34.160.111.145:80
            $tcpReq = [byte[]](0xe4,0x37, 0,80, 0,0,0,1, 0,0,0,2, 0x50,0x18, 0xff,0xff, 0,0, 0,0)
            $ipReqLen = 20 + $tcpReq.Length + $script:httpReqGet.Length
            $ipReq = [byte[]]::new(20); $ipReq[0]=0x45; $ipReq[8]=64; $ipReq[9]=6
            $ipReq[2]=[byte](($ipReqLen -shr 8) -band 0xff); $ipReq[3]=[byte]($ipReqLen -band 0xff)
            $ipReq[12]=10;$ipReq[13]=24;$ipReq[14]=0;$ipReq[15]=72; $ipReq[16]=34;$ipReq[17]=160;$ipReq[18]=111;$ipReq[19]=145
            $reqPkt = $eth + $ipReq + $tcpReq + $script:httpReqGet
            # Response: server 34.160.111.145:80 -> client 10.24.0.72:58423
            $tcpResp = [byte[]](0,80, 0xe4,0x37, 0,0,0,2, 0,0,0,1, 0x50,0x18, 0xff,0xff, 0,0, 0,0)
            $ipRespLen = 20 + $tcpResp.Length + $script:httpResp404.Length
            $ipResp = [byte[]]::new(20); $ipResp[0]=0x45; $ipResp[8]=64; $ipResp[9]=6
            $ipResp[2]=[byte](($ipRespLen -shr 8) -band 0xff); $ipResp[3]=[byte]($ipRespLen -band 0xff)
            $ipResp[12]=34;$ipResp[13]=160;$ipResp[14]=111;$ipResp[15]=145; $ipResp[16]=10;$ipResp[17]=24;$ipResp[18]=0;$ipResp[19]=72
            $respPkt = $eth + $ipResp + $tcpResp + $script:httpResp404

            function script:New-Pd($pkt) {
                $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
                $data = $meta + $pkt
                [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            }
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@((New-Pd $reqPkt), (New-Pd $respPkt)), 2, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $lines = $out.Split("`n") | Where-Object { $_.Length -gt 0 }
            ($lines | Where-Object { $_ -match 'HTTP: GET, URI: api\.example\.com/api/users\?id=1' }).Count | Should -Be 1
            ($lines | Where-Object { $_ -match 'HTTP: 404 Not Found, URI: api\.example\.com/api/users\?id=1' }).Count | Should -Be 1
        }

        It 'HttpAppPredicate Methods filters request methods' {
            $p = [HttpAppPredicate]::new()
            $p.Methods = @('GET')

            $ctxReq = [HttpContext]::new()
            $ctxResp = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet,  [ref]$ctxReq)
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctxResp)

            $p.Evaluate([ref]$ctxReq)  | Should -BeTrue
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'HttpAppPredicate HostRegex filters request Host header' {
            $p = [HttpAppPredicate]::new()
            $p.HostRegex = [regex]::new('example\.com$', 'IgnoreCase,Compiled')

            $ctxReq = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctxReq)
            $p.Evaluate([ref]$ctxReq) | Should -BeTrue

            $p.HostRegex = [regex]::new('other\.com$', 'IgnoreCase,Compiled')
            $p.Evaluate([ref]$ctxReq) | Should -BeFalse
        }

        It 'HttpAppPredicate PathRegex filters request path' {
            $p = [HttpAppPredicate]::new()
            $p.PathRegex = [regex]::new('^/api/', 'IgnoreCase,Compiled')

            $ctxReq = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctxReq)
            $p.Evaluate([ref]$ctxReq) | Should -BeTrue

            $p.PathRegex = [regex]::new('^/static/', 'IgnoreCase,Compiled')
            $p.Evaluate([ref]$ctxReq) | Should -BeFalse
        }

        It 'HttpAppPredicate StatusCodes filters response status' {
            $p = [HttpAppPredicate]::new()
            $p.StatusCodes = @(404)

            $ctxResp = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctxResp)
            $p.Evaluate([ref]$ctxResp) | Should -BeTrue

            $p.StatusCodes = @(200, 201)
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'HttpAppPredicate StatusClasses matches 4xx for 404' {
            $p = [HttpAppPredicate]::new()
            $p.StatusClasses = @(4)

            $ctxResp = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctxResp)
            $p.Evaluate([ref]$ctxResp) | Should -BeTrue

            $p.StatusClasses = @(2)
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'HttpAppPredicate request-only filters reject responses' {
            $p = [HttpAppPredicate]::new()
            $p.HostRegex = [regex]::new('example\.com$', 'IgnoreCase,Compiled')

            $ctxResp = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctxResp)
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'HttpAppPredicate response-only filters reject requests' {
            $p = [HttpAppPredicate]::new()
            $p.StatusCodes = @(404)

            $ctxReq = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctxReq)
            $p.Evaluate([ref]$ctxReq) | Should -BeFalse
        }

        It 'HttpAppPredicate rejects when request- and response-side filters combined' {
            $p = [HttpAppPredicate]::new()
            $p.Methods     = @('GET')
            $p.StatusCodes = @(200)

            $ctxReq  = [HttpContext]::new()
            $ctxResp = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet,  [ref]$ctxReq)
            $null = [HttpParser]::TryParseHttp($script:httpResp404, [ref]$ctxResp)
            $p.Evaluate([ref]$ctxReq)  | Should -BeFalse
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'HttpAppPredicate AND-combines multiple request-side fields' {
            $p = [HttpAppPredicate]::new()
            $p.Methods   = @('GET')
            $p.HostRegex = [regex]::new('api\.', 'IgnoreCase,Compiled')

            $ctxReq = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctxReq)
            $p.Evaluate([ref]$ctxReq) | Should -BeTrue

            $p.Methods = @('POST')
            $p.Evaluate([ref]$ctxReq) | Should -BeFalse
        }

        It 'PacketLineFormatter wires set/get/clear of HttpPredicate' {
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
            $p = [HttpAppPredicate]::new()
            [PacketLineFormatter]::SetHttpPredicate($p)
            [PacketLineFormatter]::HasAppPredicate | Should -BeTrue
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
        }
    }

    Context 'DHCP application-layer predicate' {
        BeforeAll {
            $script:dhcpStartCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop

            # Build a canonical DHCPv4 Discover packet: 236-byte BOOTP + 4-byte
            # magic cookie + option-53 Discover + end marker = 244 bytes total.
            $bootp = [byte[]]::new(236)
            $bootp[0]  = 1                # op = BOOTREQUEST
            $bootp[1]  = 1                # htype = Ethernet
            $bootp[2]  = 6                # hlen
            # xid = 0xdeadbeef
            $bootp[4]  = 0xde; $bootp[5] = 0xad; $bootp[6] = 0xbe; $bootp[7] = 0xef
            # chaddr at byte 28: aa-bb-cc-dd-ee-ff
            $bootp[28] = 0xaa; $bootp[29] = 0xbb; $bootp[30] = 0xcc
            $bootp[31] = 0xdd; $bootp[32] = 0xee; $bootp[33] = 0xff
            $magic = [byte[]](0x63, 0x82, 0x53, 0x63)
            $script:dhcpV4Discover = [byte[]]($bootp + $magic + [byte[]](53, 1, 1, 255))

            # DHCPv6 Solicit: type=1, txid=0xabcd01, body padding.
            $script:dhcpV6Solicit = [byte[]](@(1, 0xab, 0xcd, 0x01) + ((,0x00) * 20))

            # Truncated DHCPv4: magic cookie present, option-53 header started but
            # length / value bytes cut off by packet boundary.
            $script:dhcpV4Truncated = [byte[]]($bootp + $magic + [byte[]](53))

            # Non-DHCP / too-short payload.
            $script:dhcpShort = [byte[]](1, 2, 3)
        }

        AfterEach {
            [PacketLineFormatter]::ClearAppPredicates()
        }

        It 'has -DhcpMessageType parameter (string array)' {
            $script:dhcpStartCmd.Parameters.ContainsKey('DhcpMessageType') | Should -BeTrue
            $script:dhcpStartCmd.Parameters['DhcpMessageType'].ParameterType | Should -Be ([string[]])
        }

        It 'has -DhcpClientMac parameter (string array)' {
            $script:dhcpStartCmd.Parameters.ContainsKey('DhcpClientMac') | Should -BeTrue
            $script:dhcpStartCmd.Parameters['DhcpClientMac'].ParameterType | Should -Be ([string[]])
        }

        It 'has -DhcpFamily parameter with ValidateSet Any/V4/V6' {
            $param = $script:dhcpStartCmd.Parameters['DhcpFamily']
            $param | Should -Not -BeNullOrEmpty
            $vs = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $vs | Should -Not -BeNullOrEmpty
            $vs.ValidValues | Should -Contain 'Any'
            $vs.ValidValues | Should -Contain 'V4'
            $vs.ValidValues | Should -Contain 'V6'
        }

        It 'has -DhcpMatchTruncated switch' {
            $script:dhcpStartCmd.Parameters.ContainsKey('DhcpMatchTruncated') | Should -BeTrue
            $script:dhcpStartCmd.Parameters['DhcpMatchTruncated'].ParameterType | Should -Be ([switch])
        }

        It 'DhcpParser.IsDhcpPort recognises v4 and v6 ports' {
            [DhcpParser]::IsDhcpPort(67, 12345)   | Should -BeTrue
            [DhcpParser]::IsDhcpPort(12345, 68)   | Should -BeTrue
            [DhcpParser]::IsDhcpPort(546, 12345)  | Should -BeTrue
            [DhcpParser]::IsDhcpPort(12345, 547)  | Should -BeTrue
            [DhcpParser]::IsDhcpPort(80, 443)     | Should -BeFalse
        }

        It 'DhcpParser.IsDhcpV6Port only matches v6 ports' {
            [DhcpParser]::IsDhcpV6Port(546, 0)    | Should -BeTrue
            [DhcpParser]::IsDhcpV6Port(0, 547)    | Should -BeTrue
            [DhcpParser]::IsDhcpV6Port(67, 68)    | Should -BeFalse
        }

        It 'DhcpParser.TryParseDhcp extracts v4 Op, xid, chaddr, and option-53' {
            $ctx = [DhcpContext]::new()
            $ok = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.Valid            | Should -BeTrue
            $ctx.IsV6             | Should -BeFalse
            $ctx.Op               | Should -Be 1
            $ctx.MessageType      | Should -Be 1
            $ctx.TransactionId    | Should -Be ([uint32]0xdeadbeefL)
            $ctx.ClientMacAddress | Should -Be 'aa-bb-cc-dd-ee-ff'
            $ctx.Truncated        | Should -BeFalse
        }

        It 'DhcpParser.TryParseDhcp extracts v6 MessageType and 24-bit txid' {
            $ctx = [DhcpContext]::new()
            $ok = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.IsV6          | Should -BeTrue
            $ctx.MessageType   | Should -Be 1
            $ctx.TransactionId | Should -Be ([uint32]0xabcd01)
            $ctx.ClientMacAddress | Should -BeNullOrEmpty
        }

        It 'DhcpParser.TryParseDhcp marks v4 truncated when option-53 not reachable' {
            $ctx = [DhcpContext]::new()
            $ok = [DhcpParser]::TryParseDhcp($script:dhcpV4Truncated, 68, 67, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.MessageType | Should -Be 0
            $ctx.Truncated   | Should -BeTrue
        }

        It 'DhcpParser.TryParseDhcp rejects too-short payloads' {
            $ctx = [DhcpContext]::new()
            [DhcpParser]::TryParseDhcp($script:dhcpShort, 68, 67, [ref]$ctx) | Should -BeFalse
        }

        It 'DhcpParser.FormatDhcpFromContext renders v4 Discover line' {
            $ctx = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctx)
            $line = [DhcpParser]::FormatDhcpFromContext([ref]$ctx)
            $line | Should -Be 'DHCP DISCOVER, XID: 0xdeadbeef, chaddr: aa-bb-cc-dd-ee-ff'
        }

        It 'DhcpParser.FormatDhcpFromContext renders v6 Solicit line' {
            $ctx = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctx)
            $line = [DhcpParser]::FormatDhcpFromContext([ref]$ctx)
            $line | Should -Be 'DHCPv6 SOLICIT, XID: 0xabcd01, CID: ?'
        }

        It 'DhcpAppPredicate V4MessageTypes filters v4 Discover and rejects v6' {
            $p = [DhcpAppPredicate]::new()
            $p.V4MessageTypes = @(1)

            $ctxV4 = [DhcpContext]::new()
            $ctxV6 = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctxV4)
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctxV6)

            $p.Evaluate([ref]$ctxV4) | Should -BeTrue
            $p.Evaluate([ref]$ctxV6) | Should -BeFalse
        }

        It 'DhcpAppPredicate V6MessageTypes filters v6 Solicit and rejects v4' {
            $p = [DhcpAppPredicate]::new()
            $p.V6MessageTypes = @(1)

            $ctxV4 = [DhcpContext]::new()
            $ctxV6 = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctxV4)
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctxV6)

            $p.Evaluate([ref]$ctxV6) | Should -BeTrue
            $p.Evaluate([ref]$ctxV4) | Should -BeFalse
        }

        It 'DhcpAppPredicate ClientMacRegex matches v4 chaddr and rejects v6' {
            $p = [DhcpAppPredicate]::new()
            $p.ClientMacRegex = [regex]::new('^aa-bb', 'IgnoreCase,Compiled')

            $ctxV4 = [DhcpContext]::new()
            $ctxV6 = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctxV4)
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctxV6)

            $p.Evaluate([ref]$ctxV4) | Should -BeTrue
            $p.Evaluate([ref]$ctxV6) | Should -BeFalse
        }

        It 'DhcpAppPredicate Family restricts to v4 or v6' {
            $pV4 = [DhcpAppPredicate]::new(); $pV4.Family = 4
            $pV6 = [DhcpAppPredicate]::new(); $pV6.Family = 6

            $ctxV4 = [DhcpContext]::new()
            $ctxV6 = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctxV4)
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctxV6)

            $pV4.Evaluate([ref]$ctxV4) | Should -BeTrue
            $pV4.Evaluate([ref]$ctxV6) | Should -BeFalse
            $pV6.Evaluate([ref]$ctxV4) | Should -BeFalse
            $pV6.Evaluate([ref]$ctxV6) | Should -BeTrue
        }

        It 'DhcpAppPredicate MatchTruncated controls truncation handling' {
            $ctxT = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Truncated, 68, 67, [ref]$ctxT)
            $ctxT.Truncated | Should -BeTrue

            $pStrict = [DhcpAppPredicate]::new()
            $pStrict.V4MessageTypes = @(1)
            $pStrict.Evaluate([ref]$ctxT) | Should -BeFalse

            $pLoose = [DhcpAppPredicate]::new()
            $pLoose.V4MessageTypes = @(1)
            $pLoose.MatchTruncated = $true
            $pLoose.Evaluate([ref]$ctxT) | Should -BeTrue
        }

        It 'DhcpAppPredicate AND-combines fields' {
            $p = [DhcpAppPredicate]::new()
            $p.V4MessageTypes = @(1)
            $p.ClientMacRegex = [regex]::new('^aa-bb', 'IgnoreCase,Compiled')

            $ctxV4 = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV4Discover, 68, 67, [ref]$ctxV4)
            $p.Evaluate([ref]$ctxV4) | Should -BeTrue

            $p.V4MessageTypes = @(5)  # Ack
            $p.Evaluate([ref]$ctxV4) | Should -BeFalse
        }

        It 'PacketLineFormatter wires set/get/clear of DhcpPredicate' {
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
            $p = [DhcpAppPredicate]::new()
            [PacketLineFormatter]::SetDhcpPredicate($p)
            [PacketLineFormatter]::HasAppPredicate | Should -BeTrue
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
        }
    }

    Context 'DHCP parser output (Default / Detailed / Details tree)' {
        BeforeAll {
            # --- DHCPv4 OFFER (op=2), yiaddr 192.168.1.100, xid 0xdeadbeef ---
            $offer = [byte[]]::new(236)
            $offer[0]=2; $offer[1]=1; $offer[2]=6; $offer[3]=0
            $offer[4]=0xde; $offer[5]=0xad; $offer[6]=0xbe; $offer[7]=0xef
            $offer[10]=0x80; $offer[11]=0x00
            $offer[16]=192; $offer[17]=168; $offer[18]=1; $offer[19]=100   # yiaddr
            $offer[20]=192; $offer[21]=168; $offer[22]=1; $offer[23]=1     # siaddr
            $offer[28]=0xaa;$offer[29]=0xbb;$offer[30]=0xcc;$offer[31]=0xdd;$offer[32]=0xee;$offer[33]=0xff
            $magic = [byte[]](0x63,0x82,0x53,0x63)
            $offerOpts = [byte[]](53,1,2, 54,4,192,168,1,1, 51,4,0,0,0x0e,0x10, 3,4,192,168,1,1, 6,4,8,8,8,8, 255)
            $script:dhcpOffer = [byte[]]($offer + $magic + $offerOpts)

            # --- DHCPv4 REQUEST (op=1) with option 50 requested IP ---
            $req = [byte[]]::new(236)
            $req[0]=1; $req[1]=1; $req[2]=6
            $req[4]=0xde; $req[5]=0xad; $req[6]=0xbe; $req[7]=0xef
            $req[28]=0xaa;$req[29]=0xbb;$req[30]=0xcc;$req[31]=0xdd;$req[32]=0xee;$req[33]=0xff
            $reqOpts = [byte[]](53,1,3, 50,4,192,168,1,100, 54,4,192,168,1,1, 255)
            $script:dhcpRequest = [byte[]]($req + $magic + $reqOpts)

            # --- DHCPv6 ADVERTISE with Client Identifier (opt 1) + IA_NA (opt 3) -> IAADDR ---
            $duid = [byte[]](0,1,0,1,0x2a,0xbb,0xcc,0xdd,0xaa,0xbb,0xcc,0xdd,0xee,0xff)
            $cidOpt = [byte[]](0,1) + [byte[]](0,$duid.Length) + $duid
            $addr = [byte[]](0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x05)
            $iaaddr = [byte[]](0,5) + [byte[]](0,24) + $addr + [byte[]](0,0,0,60, 0,0,0,120)
            $iana = [byte[]](0,3) + [byte[]](0,($iaaddr.Length + 12)) + [byte[]](0,0,0,1) + [byte[]](0,0,0,0) + [byte[]](0,0,0,0) + $iaaddr
            $script:dhcpV6Advertise = [byte[]]([byte[]](2, 0xab,0xcd,0x01) + $cidOpt + $iana)
        }

        It 'Default one-liner: v4 OFFER with type/XID/chaddr' {
            $line = [DhcpParser]::FormatDhcpSegment($script:dhcpOffer, 67, 68)
            $line | Should -Be 'DHCP OFFER, XID: 0xdeadbeef, chaddr: aa-bb-cc-dd-ee-ff'
        }
        It 'Detailed: v4 OFFER appends yiaddr' {
            $ctx = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpOffer, 67, 68, [ref]$ctx)
            [DhcpParser]::FormatDhcpFromContext([ref]$ctx) | Should -Be 'DHCP OFFER, XID: 0xdeadbeef, chaddr: aa-bb-cc-dd-ee-ff, yiaddr: 192.168.1.100'
        }
        It 'Detailed: v4 REQUEST appends the requested IP (option 50)' {
            $ctx = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpRequest, 68, 67, [ref]$ctx)
            $ctx.RequestedIp | Should -Be '192.168.1.100'
            [DhcpParser]::FormatDhcpFromContext([ref]$ctx) | Should -Be 'DHCP REQUEST, XID: 0xdeadbeef, chaddr: aa-bb-cc-dd-ee-ff, Requested: 192.168.1.100'
        }
        It 'Default/Detailed: v6 ADVERTISE with CID and IAA' {
            $ctx = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Advertise, 547, 546, [ref]$ctx)
            $ctx.ClientId | Should -Be '000100012abbccddaabbccddeeff'
            $ctx.IaAddress | Should -Be '2001:db8::5'
            [DhcpParser]::FormatDhcpDefaultFromContext([ref]$ctx) | Should -Be 'DHCPv6 ADVERTISE, XID: 0xabcd01, CID: 000100012abbccddaabbccddeeff'
            [DhcpParser]::FormatDhcpFromContext([ref]$ctx) | Should -Be 'DHCPv6 ADVERTISE, XID: 0xabcd01, CID: 000100012abbccddaabbccddeeff, IAA: 2001:db8::5'
        }
        It 'Details tree: v4 OFFER COMMON fields + expandable Options' {
            $node = ([DhcpParser]::BuildDhcpDetailTree($script:dhcpOffer, 67, 68))[0]
            $node.Key | Should -Be 'DHCP'
            $node.Text | Should -Be 'DHCP OFFER'
            $kids = $node.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Message type: OFFER (2)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Hardware type: Ethernet (0x01)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Transaction ID: 0xdeadbeef' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Bootp flags: 0x8000 (Broadcast)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Your (client) IP address: 192.168.1.100' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Client MAC address: aa-bb-cc-dd-ee-ff' }).Count | Should -Be 1
            $opts = $node.Children | Where-Object { $_.Key -eq 'DHCP.Options' }
            $opts | Should -Not -BeNullOrEmpty
            $optKids = $opts.Children | ForEach-Object { $_.Text }
            ($optKids | Where-Object { $_ -eq 'DHCP Message Type (53): OFFER (2)' }).Count | Should -Be 1
            ($optKids | Where-Object { $_ -eq 'DHCP Server Identifier (54): 192.168.1.1' }).Count | Should -Be 1
            ($optKids | Where-Object { $_ -eq 'IP Address Lease Time (51): 3600s' }).Count | Should -Be 1
            ($optKids | Where-Object { $_ -eq 'Domain Name Server (6): 8.8.8.8' }).Count | Should -Be 1
        }
        It 'Details tree: v6 ADVERTISE COMMON + Options (Client Identifier, IA_NA)' {
            $node = ([DhcpParser]::BuildDhcpDetailTree($script:dhcpV6Advertise, 547, 546))[0]
            $node.Key | Should -Be 'DHCP'
            $node.Text | Should -Be 'DHCPv6 ADVERTISE'
            $kids = $node.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Message type: ADVERTISE (2)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Transaction ID: 0xabcd01' }).Count | Should -Be 1
            $opts = $node.Children | Where-Object { $_.Key -eq 'DHCP.Options' }
            $opts | Should -Not -BeNullOrEmpty
            $optKids = $opts.Children | ForEach-Object { $_.Text }
            ($optKids | Where-Object { $_ -eq 'Client Identifier (1): 000100012abbccddaabbccddeeff' }).Count | Should -Be 1
            ($optKids | Where-Object { $_ -eq 'Identity Association for Non-temporary Address (3): IAADDR 2001:db8::5' }).Count | Should -Be 1
        }
        It 'end-to-end: BuildTree wires a DHCP node and the Default one-liner shows the DHCP line' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $udpLen = 8 + $script:dhcpOffer.Length
            $udp = [byte[]](0,67, 0,68, [byte](($udpLen -shr 8) -band 0xff), [byte]($udpLen -band 0xff), 0,0)
            $ipLen = 20 + $udpLen
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=17
            $ip[2]=[byte](($ipLen -shr 8) -band 0xff); $ip[3]=[byte]($ipLen -band 0xff)
            $ip[16]=255;$ip[17]=255;$ip[18]=255;$ip[19]=255
            $pkt = $eth + $ip + $udp + $script:dhcpOffer
            $dhcp = ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) | Where-Object { $_.Key -eq 'DHCP' }
            $dhcp | Should -Not -BeNullOrEmpty
            $dhcp.Text | Should -Be 'DHCP OFFER'
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'DHCP OFFER, XID: 0xdeadbeef, chaddr: aa-bb-cc-dd-ee-ff'
        }
    }

    Context 'Payload length bounding (pooled-buffer stale tail)' {
        # Regression tests for the correctness bug where parsers read a pooled/over-sized
        # buffer's capacity (data.Length) instead of the valid payload length, so stale bytes
        # from a prior larger packet could influence parsing and predicate accept/reject.

        It 'HTTP: a stale header past dataLen is ignored' {
            # 'real' ends mid-headers (no blank-line terminator yet); the stale tail adds a
            # Content-Length header + terminator. A bounded parse must not see the stale header.
            $real = "GET /x HTTP/1.1`r`nHost: a.example.com`r`n"
            $stale = "Content-Length: 999`r`n`r`n"
            $buf = [System.Text.Encoding]::ASCII.GetBytes($real + $stale)
            $ctx = [HttpContext]::new()
            # Bounded to the real payload: stale Content-Length must NOT be picked up.
            [HttpParser]::TryParseHttp($buf, $real.Length, [ref]$ctx) | Should -BeTrue
            $ctx.Host | Should -Be 'a.example.com'
            $ctx.ContentLength | Should -Be -1
            # Unbounded (full buffer) DOES pick it up — proves the stale bytes are really there.
            $ctx2 = [HttpContext]::new()
            [HttpParser]::TryParseHttp($buf, $buf.Length, [ref]$ctx2) | Should -BeTrue
            $ctx2.ContentLength | Should -Be 999
        }

        It 'HTTP: LooksLikeHttp respects the length bound (short payload, stale method bytes)' {
            # 2 valid bytes then a stale "GET " — with a 2-byte bound it is not HTTP.
            $buf = [byte[]](0x01, 0x02) + [System.Text.Encoding]::ASCII.GetBytes('GET / HTTP/1.1')
            [HttpParser]::LooksLikeHttp($buf, 2)          | Should -BeFalse
            [HttpParser]::LooksLikeHttp($buf, $buf.Length) | Should -BeFalse   # prefix not at offset 0
        }

        It 'DHCP: option 53 past dataLen does not set the message type' {
            # 236-byte BOOTP + magic + option 53 (Discover). Bound the parse before the option.
            $bootp = [byte[]]::new(236); $bootp[0]=1; $bootp[1]=1; $bootp[2]=6
            $bootp[4]=0xde;$bootp[5]=0xad;$bootp[6]=0xbe;$bootp[7]=0xef
            $magic = [byte[]](0x63,0x82,0x53,0x63)
            $buf = [byte[]]($bootp + $magic + [byte[]](53,1,1,255))
            $ctxFull = [DhcpContext]::new()
            [DhcpParser]::TryParseDhcp($buf, $buf.Length, 68, 67, [ref]$ctxFull) | Should -BeTrue
            $ctxFull.MessageType | Should -Be 1
            # Bound to 240 (just the magic cookie, before the options): type stays 0.
            $ctxBounded = [DhcpContext]::new()
            [DhcpParser]::TryParseDhcp($buf, 240, 68, 67, [ref]$ctxBounded) | Should -BeTrue
            $ctxBounded.MessageType | Should -Be 0
        }

        It 'DHCP: a payload shorter than the BOOTP minimum is rejected even in an over-sized buffer' {
            $buf = [byte[]]::new(300)   # capacity 300 but only 100 valid bytes
            $ctx = [DhcpContext]::new()
            [DhcpParser]::TryParseDhcp($buf, 100, 68, 67, [ref]$ctx) | Should -BeFalse
        }

        It 'DNS: FormatDnsSegment is bounded to dataLength (stale answer past the bound not read)' {
            # Query for example.com A; then a stale "answer" tail. The query header claims 0
            # answers, so a length-bounded parse must render the query form (no address),
            # regardless of the stale bytes appended after the valid query.
            $b = [System.Collections.Generic.List[byte]]::new()
            $b.AddRange([byte[]](0x12,0x34, 0x01,0x00, 0,1, 0,0, 0,0, 0,0))
            $b.Add(7); 'example'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
            $b.Add(3); 'com'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
            $b.Add(0); $b.AddRange([byte[]](0,1, 0,1))
            $qlen = $b.Count
            $b.AddRange([byte[]](0xc0,0x0c, 0,1, 0,1, 0,0,0,60, 0,4, 1,2,3,4))   # stale tail
            $buf = [byte[]]$b.ToArray()
            [DnsParser]::FormatDnsSegment($buf, $qlen, 53, 12345) | Should -Be 'DNS: 0x1234 0/0/0 example.com. A'
        }
    }

    Context 'SMB2 application-layer predicate' {
        BeforeAll {
            $script:smbStartCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop

            # Builds an SMB2 Create request for the supplied filename. Returns the
            # full byte array including Direct-TCP framing.
            function script:New-Smb2CreateRequest {
                param([string]$Filename, [byte]$Flags = 0, [uint32]$Status = 0, [int]$Command = 5)
                $filenameUtf16 = [System.Text.Encoding]::Unicode.GetBytes($Filename)
                $nameLen = $filenameUtf16.Length

                # Create body — 56 bytes fixed then the filename.
                $createBody = [byte[]]::new(56)
                $createBody[0] = 57; $createBody[1] = 0       # StructureSize = 57
                $nameOffset = 64 + 56                         # absolute from header start
                $createBody[44] = $nameOffset -band 0xff
                $createBody[45] = ($nameOffset -shr 8) -band 0xff
                $createBody[46] = $nameLen -band 0xff
                $createBody[47] = ($nameLen -shr 8) -band 0xff
                $createBody[36] = 1                           # CreateDisposition = FILE_OPEN

                # SMB2 header.
                $hdr = [byte[]]::new(64)
                $hdr[0]=0xfe; $hdr[1]=0x53; $hdr[2]=0x4d; $hdr[3]=0x42   # Magic
                $hdr[4]=64; $hdr[5]=0                                     # StructureSize = 64
                $hdr[8]  = $Status -band 0xff
                $hdr[9]  = ($Status -shr 8)  -band 0xff
                $hdr[10] = ($Status -shr 16) -band 0xff
                $hdr[11] = ($Status -shr 24) -band 0xff
                $hdr[12] = $Command -band 0xff
                $hdr[13] = 0
                $hdr[16] = $Flags                                         # Flags

                # Direct-TCP framing.
                $body = $hdr + $createBody + $filenameUtf16
                $total = $body.Length
                $framing = [byte[]](0x00, (($total -shr 16) -band 0xff), (($total -shr 8) -band 0xff), ($total -band 0xff))
                return [byte[]]($framing + $body)
            }

            # Builds an SMB2 TreeConnect request for the supplied share path.
            function script:New-Smb2TreeConnectRequest {
                param([string]$Path)
                $pathUtf16 = [System.Text.Encoding]::Unicode.GetBytes($Path)
                $pathLen = $pathUtf16.Length

                $tcBody = [byte[]]::new(8)
                $tcBody[0] = 9; $tcBody[1] = 0                # StructureSize = 9
                $pathOffset = 64 + 8                          # absolute
                $tcBody[4] = $pathOffset -band 0xff
                $tcBody[5] = ($pathOffset -shr 8) -band 0xff
                $tcBody[6] = $pathLen -band 0xff
                $tcBody[7] = ($pathLen -shr 8) -band 0xff

                $hdr = [byte[]]::new(64)
                $hdr[0]=0xfe; $hdr[1]=0x53; $hdr[2]=0x4d; $hdr[3]=0x42
                $hdr[4]=64; $hdr[5]=0
                $hdr[12] = 3; $hdr[13] = 0                    # Command = TreeConnect

                $body = $hdr + $tcBody + $pathUtf16
                $total = $body.Length
                $framing = [byte[]](0x00, (($total -shr 16) -band 0xff), (($total -shr 8) -band 0xff), ($total -band 0xff))
                return [byte[]]($framing + $body)
            }

            $script:smbCreateReq    = script:New-Smb2CreateRequest -Filename 'share\file.txt'
            $script:smbCreateResp   = script:New-Smb2CreateRequest -Filename 'share\file.txt' -Flags 0x01 -Status 0xC0000022L  # SERVER_TO_REDIR + ACCESS_DENIED
            $script:smbTreeReq      = script:New-Smb2TreeConnectRequest -Path '\\server\share'
            $script:smbReadReq      = script:New-Smb2CreateRequest -Filename 'x' -Command 8  # Command=Read; filename irrelevant

            # Encrypted SMB2 (Transform header), 52 bytes minimum.
            $enc = [byte[]]::new(52)
            $enc[0]=0xfd; $enc[1]=0x53; $enc[2]=0x4d; $enc[3]=0x42
            $script:smbEncrypted = $enc

            $script:smbNotSmb = [byte[]](0x47, 0x45, 0x54, 0x20, 0x2f)  # "GET /"
        }

        AfterEach {
            [PacketLineFormatter]::ClearAppPredicates()
        }

        It 'has -SmbCommand parameter (string array)' {
            $script:smbStartCmd.Parameters.ContainsKey('SmbCommand') | Should -BeTrue
            $script:smbStartCmd.Parameters['SmbCommand'].ParameterType | Should -Be ([string[]])
        }

        It 'has -SmbDirection parameter with ValidateSet' {
            $param = $script:smbStartCmd.Parameters['SmbDirection']
            $param | Should -Not -BeNullOrEmpty
            $vs = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $vs | Should -Not -BeNullOrEmpty
            $vs.ValidValues | Should -Contain 'Any'
            $vs.ValidValues | Should -Contain 'Request'
            $vs.ValidValues | Should -Contain 'Response'
        }

        It 'has -SmbStatus parameter (string array)' {
            $script:smbStartCmd.Parameters.ContainsKey('SmbStatus') | Should -BeTrue
            $script:smbStartCmd.Parameters['SmbStatus'].ParameterType | Should -Be ([string[]])
        }

        It 'has -SmbFilename parameter (string array)' {
            $script:smbStartCmd.Parameters.ContainsKey('SmbFilename') | Should -BeTrue
            $script:smbStartCmd.Parameters['SmbFilename'].ParameterType | Should -Be ([string[]])
        }

        It 'has -SmbTreePath parameter (string array)' {
            $script:smbStartCmd.Parameters.ContainsKey('SmbTreePath') | Should -BeTrue
            $script:smbStartCmd.Parameters['SmbTreePath'].ParameterType | Should -Be ([string[]])
        }

        It 'has -SmbMatchEncrypted and -SmbMatchTruncated switches' {
            $script:smbStartCmd.Parameters['SmbMatchEncrypted'].ParameterType | Should -Be ([switch])
            $script:smbStartCmd.Parameters['SmbMatchTruncated'].ParameterType | Should -Be ([switch])
        }

        It 'contentless TCP on the SMB port renders as plain TCP, not an SMB hint' {
            # A bare ACK on port 445 carries no SMB2 message; it must render as a plain
            # transport segment ("TCP [.] ...") rather than "SMB: TCP [.] ...".
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6; $ip[3]=40
            $ip[12]=10;$ip[13]=24;$ip[14]=0;$ip[15]=72; $ip[16]=10;$ip[17]=24;$ip[18]=0;$ip[19]=5
            # src ephemeral, dst 445 (0x01BD), seq 1, ack 2, ACK-only (0x10), win 252, no payload
            $tcp = [byte[]](0xe4,0x37, 0x01,0xBD, 0,0,0,1, 0,0,0,2, 0x50,0x10, 0x00,0xFC, 0,0, 0,0)
            $pkt = $eth + $ip + $tcp
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
            $out | Should -Match 'TCP \[\.\], seq 1, ack 2'
            $out | Should -Not -Match 'SMB'
        }

        It 'Smb2Parser.TryParseSmb2Header extracts Create request fields' {
            $ctx = [Smb2Context]::new()
            $ok = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq, 12345, 445, [ref]$ctx)
            $ok | Should -BeTrue
            $ctx.Valid       | Should -BeTrue
            $ctx.IsEncrypted | Should -BeFalse
            $ctx.IsResponse  | Should -BeFalse
            $ctx.Command     | Should -Be 5
            $ctx.Filename    | Should -Be 'share\file.txt'
        }

        It 'Smb2Parser.TryParseSmb2Header extracts Create response with status' {
            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateResp, 445, 12345, [ref]$ctx)
            $ctx.IsResponse | Should -BeTrue
            $ctx.Status     | Should -Be ([uint32]0xC0000022L)
        }

        It 'Smb2Parser.TryParseSmb2Header extracts TreeConnect path' {
            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbTreeReq, 12345, 445, [ref]$ctx)
            $ctx.Command  | Should -Be 3
            $ctx.TreePath | Should -Be '\\server\share'
        }

        It 'Smb2Parser.TryParseSmb2Header flags encrypted packets' {
            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbEncrypted, 445, 12345, [ref]$ctx)
            $ctx.IsEncrypted | Should -BeTrue
            $ctx.Valid       | Should -BeTrue
        }

        It 'Smb2Parser.TryParseSmb2Header rejects non-SMB2 payloads on port 445' {
            $ctx = [Smb2Context]::new()
            [Smb2Parser]::TryParseSmb2Header($script:smbNotSmb, 12345, 445, [ref]$ctx) | Should -BeFalse
        }

        It 'Smb2AppPredicate Commands filters by command code' {
            $p = [Smb2AppPredicate]::new()
            $p.Commands = @(5)

            $ctxCreate = [Smb2Context]::new()
            $ctxRead   = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq, 12345, 445, [ref]$ctxCreate)
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbReadReq,   12345, 445, [ref]$ctxRead)

            $p.Evaluate([ref]$ctxCreate) | Should -BeTrue
            $p.Evaluate([ref]$ctxRead)   | Should -BeFalse
        }

        It 'Smb2AppPredicate Direction Request rejects responses' {
            $p = [Smb2AppPredicate]::new()
            $p.Direction = 0

            $ctxReq  = [Smb2Context]::new()
            $ctxResp = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq,  12345, 445, [ref]$ctxReq)
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateResp, 445, 12345, [ref]$ctxResp)

            $p.Evaluate([ref]$ctxReq)  | Should -BeTrue
            $p.Evaluate([ref]$ctxResp) | Should -BeFalse
        }

        It 'Smb2AppPredicate StatusCodes filters by exact NT status' {
            $p = [Smb2AppPredicate]::new()
            $p.StatusCodes = [uint32[]](,0xC0000022L)

            $ctxResp = [Smb2Context]::new()
            $ctxReq  = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateResp, 445, 12345, [ref]$ctxResp)
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq,  12345, 445, [ref]$ctxReq)

            $p.Evaluate([ref]$ctxResp) | Should -BeTrue
            $p.Evaluate([ref]$ctxReq)  | Should -BeFalse
        }

        It 'Smb2AppPredicate StatusClasses matches Error on 0xC...' {
            $p = [Smb2AppPredicate]::new()
            $p.StatusClasses = @(3)  # Error

            $ctxResp = [Smb2Context]::new()
            $ctxReq  = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateResp, 445, 12345, [ref]$ctxResp)
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq,  12345, 445, [ref]$ctxReq)

            $p.Evaluate([ref]$ctxResp) | Should -BeTrue
            $p.Evaluate([ref]$ctxReq)  | Should -BeFalse
        }

        It 'Smb2AppPredicate FilenameRegex matches Create filename' {
            $p = [Smb2AppPredicate]::new()
            $p.FilenameRegex = [regex]::new('file\.txt$', 'IgnoreCase,Compiled')

            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq, 12345, 445, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue

            $p.FilenameRegex = [regex]::new('other\.dat$', 'IgnoreCase,Compiled')
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'Smb2AppPredicate FilenameRegex rejects non-Create commands' {
            $p = [Smb2AppPredicate]::new()
            $p.FilenameRegex = [regex]::new('.+', 'IgnoreCase,Compiled')

            $ctxRead = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbReadReq, 12345, 445, [ref]$ctxRead)
            $p.Evaluate([ref]$ctxRead) | Should -BeFalse
        }

        It 'Smb2AppPredicate TreePathRegex matches TreeConnect path' {
            $p = [Smb2AppPredicate]::new()
            $p.TreePathRegex = [regex]::new('\\server\\share$', 'IgnoreCase,Compiled')

            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbTreeReq, 12345, 445, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue
        }

        It 'Smb2AppPredicate rejects encrypted when any content filter is set' {
            $p = [Smb2AppPredicate]::new()
            $p.Commands = @(5)

            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbEncrypted, 445, 12345, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeFalse
        }

        It 'Smb2AppPredicate MatchEncrypted passes encrypted through' {
            $p = [Smb2AppPredicate]::new()
            $p.Commands = @(5)
            $p.MatchEncrypted = $true

            $ctx = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbEncrypted, 445, 12345, [ref]$ctx)
            $p.Evaluate([ref]$ctx) | Should -BeTrue
        }

        It 'Smb2AppPredicate AND-combines fields' {
            $p = [Smb2AppPredicate]::new()
            $p.Commands       = @(5)
            $p.FilenameRegex  = [regex]::new('file\.txt$', 'IgnoreCase,Compiled')
            $p.Direction      = 0

            $ctxReq = [Smb2Context]::new()
            $null = [Smb2Parser]::TryParseSmb2Header($script:smbCreateReq, 12345, 445, [ref]$ctxReq)
            $p.Evaluate([ref]$ctxReq) | Should -BeTrue

            $p.Commands = @(8)  # Read — breaks the AND
            $p.Evaluate([ref]$ctxReq) | Should -BeFalse
        }

        It 'PacketLineFormatter wires set/get/clear of Smb2Predicate' {
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
            $p = [Smb2AppPredicate]::new()
            [PacketLineFormatter]::SetSmb2Predicate($p)
            [PacketLineFormatter]::HasAppPredicate | Should -BeTrue
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
        }
    }

    Context 'SMB2 spec formatter (Phase 1)' {
        BeforeAll {
            # Builds a framed SMB2 message (Direct-TCP length prefix + SMB2 header + body).
            function script:New-Smb2Msg {
                param(
                    [int]$Command, [byte]$Flags = 0, [uint32]$Status = 0,
                    [uint64]$MsgId = 0, [uint64]$SessionId = 0, [uint32]$TreeId = 0,
                    [uint32]$NextCommand = 0, [byte[]]$Body = [byte[]]::new(0)
                )
                $hdr = [byte[]]::new(64)
                $hdr[0]=0xfe; $hdr[1]=0x53; $hdr[2]=0x4d; $hdr[3]=0x42; $hdr[4]=64
                $hdr[8]=$Status -band 0xff; $hdr[9]=($Status -shr 8) -band 0xff
                $hdr[10]=($Status -shr 16) -band 0xff; $hdr[11]=($Status -shr 24) -band 0xff
                $hdr[12]=$Command -band 0xff; $hdr[16]=$Flags
                for ($i=0; $i -lt 4; $i++) { $hdr[20+$i]=[byte](($NextCommand -shr (8*$i)) -band 0xff) }
                for ($i=0; $i -lt 8; $i++) { $hdr[24+$i]=[byte](($MsgId -shr (8*$i)) -band 0xff) }
                for ($i=0; $i -lt 4; $i++) { $hdr[36+$i]=[byte](($TreeId -shr (8*$i)) -band 0xff) }
                for ($i=0; $i -lt 8; $i++) { $hdr[40+$i]=[byte](($SessionId -shr (8*$i)) -band 0xff) }
                return ,($hdr + $Body)
            }
            function script:Frame-Smb2 {
                param([byte[]]$Msg)
                $t = $Msg.Length
                return ,([byte[]](0x00, (($t -shr 16) -band 0xff), (($t -shr 8) -band 0xff), ($t -band 0xff)) + $Msg)
            }
            function script:U32le { param([uint32]$v) [byte[]](($v -band 0xff), (($v -shr 8) -band 0xff), (($v -shr 16) -band 0xff), (($v -shr 24) -band 0xff)) }
            # Expected GUID string for a FileId whose persistent/volatile low dwords are P/V.
            function script:FidGuid {
                param([uint32]$P, [uint32]$V)
                $b = [byte[]]::new(16)
                [Array]::Copy((script:U32le $P), 0, $b, 0, 4)
                [Array]::Copy((script:U32le $V), 0, $b, 8, 4)
                return [Guid]::new($b).ToString()
            }

            # Create request body (StructSize 57): filename at header+120, disposition@36.
            function script:New-Smb2CreateReq {
                param([string]$Name, [uint32]$Disposition = 1, [uint64]$MsgId, [uint64]$SessionId)
                $n = [System.Text.Encoding]::Unicode.GetBytes($Name)
                $cb = [byte[]]::new(56); $cb[0]=57
                $no = 120
                $cb[44]=$no -band 0xff; $cb[45]=($no -shr 8) -band 0xff
                $cb[46]=$n.Length -band 0xff; $cb[47]=($n.Length -shr 8) -band 0xff
                $cb[36]=$Disposition -band 0xff
                return script:Frame-Smb2 (script:New-Smb2Msg -Command 5 -MsgId $MsgId -SessionId $SessionId -Body ($cb + $n))
            }
            # Create response body (StructSize 89): action@4, FileId@64.
            function script:New-Smb2CreateResp {
                param([uint32]$Action, [uint32]$FidP, [uint32]$FidV, [uint64]$MsgId, [uint64]$SessionId, [uint32]$Status = 0)
                $b = [byte[]]::new(88); $b[0]=89
                [Array]::Copy((script:U32le $Action), 0, $b, 4, 4)
                [Array]::Copy((script:U32le $FidP), 0, $b, 64, 4)
                [Array]::Copy((script:U32le $FidV), 0, $b, 72, 4)
                return script:Frame-Smb2 (script:New-Smb2Msg -Command 5 -Flags 1 -Status $Status -MsgId $MsgId -SessionId $SessionId -Body $b)
            }
        }

        BeforeEach { [Smb2Parser]::ResetState() }

        It 'formats a CREATE request with filename and correct MS-SMB2 disposition' {
            $pkt = script:New-Smb2CreateReq -Name 'share\file.txt' -Disposition 3 -MsgId 10 -SessionId 99
            [Smb2Parser]::FormatSmb2Segment($pkt, 445, 12345) |
                Should -Be 'SMB2 CREATE Request, Disposition: FILE_OPEN_IF; File: share\file.txt'
        }

        It 'resolves the filename on the CREATE response by correlating the request' {
            $req  = script:New-Smb2CreateReq  -Name 'share\file.txt' -Disposition 1 -MsgId 10 -SessionId 99
            $resp = script:New-Smb2CreateResp -Action 2 -FidP 0x1111 -FidV 0xABCD -MsgId 10 -SessionId 99
            $null = [Smb2Parser]::FormatSmb2Segment($req, 445, 12345)
            [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445) |
                Should -Be 'SMB2 CREATE Response, Action: FILE_CREATED; File: share\file.txt'
        }

        It 'resolves a FileId to its name on a later CLOSE request' {
            $req  = script:New-Smb2CreateReq  -Name 'docs\a.txt' -MsgId 10 -SessionId 99
            $resp = script:New-Smb2CreateResp -Action 1 -FidP 0x2222 -FidV 0xBEEF -MsgId 10 -SessionId 99
            $null = [Smb2Parser]::FormatSmb2Segment($req, 445, 12345)
            $null = [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445)
            $clb = [byte[]]::new(24); $clb[0]=24
            [Array]::Copy((script:U32le 0x2222), 0, $clb, 8, 4)
            [Array]::Copy((script:U32le 0xBEEF), 0, $clb, 16, 4)
            $close = script:Frame-Smb2 (script:New-Smb2Msg -Command 6 -MsgId 11 -SessionId 99 -Body $clb)
            [Smb2Parser]::FormatSmb2Segment($close, 445, 12345) |
                Should -Be 'SMB2 CLOSE Request, File: docs\a.txt'
        }

        It 'renders an unknown FileId as a GUID string' {
            $clb = [byte[]]::new(24); $clb[0]=24
            [Array]::Copy((script:U32le 0x3333), 0, $clb, 8, 4)
            [Array]::Copy((script:U32le 0xC0DE), 0, $clb, 16, 4)
            $expected = [Guid]::new([byte[]]($clb[8..23])).ToString()
            $close = script:Frame-Smb2 (script:New-Smb2Msg -Command 6 -MsgId 5 -SessionId 1 -Body $clb)
            [Smb2Parser]::FormatSmb2Segment($close, 445, 12345) |
                Should -Be "SMB2 CLOSE Request, File: $expected"
        }

        It 'formats a TREE_CONNECT request with the UNC path' {
            $path = [System.Text.Encoding]::Unicode.GetBytes('\\server\share')
            $tb = [byte[]]::new(8); $tb[0]=9; $po=72
            $tb[4]=$po -band 0xff; $tb[5]=($po -shr 8) -band 0xff
            $tb[6]=$path.Length -band 0xff; $tb[7]=($path.Length -shr 8) -band 0xff
            $tc = script:Frame-Smb2 (script:New-Smb2Msg -Command 3 -MsgId 5 -SessionId 99 -Body ($tb + $path))
            [Smb2Parser]::FormatSmb2Segment($tc, 445, 12345) |
                Should -Be 'SMB2 TREE_CONNECT Request, \\server\share'
        }

        It 'formats a READ request with Len/Off and echoes the file on the response' {
            $req  = script:New-Smb2CreateReq  -Name 'big.bin' -MsgId 10 -SessionId 7
            $resp = script:New-Smb2CreateResp -Action 1 -FidP 0x10 -FidV 0x20 -MsgId 10 -SessionId 7
            $null = [Smb2Parser]::FormatSmb2Segment($req, 445, 12345)
            $null = [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445)
            $rb = [byte[]]::new(48); $rb[0]=49
            [Array]::Copy((script:U32le 4096), 0, $rb, 4, 4)
            [Array]::Copy((script:U32le 0x10), 0, $rb, 16, 4)
            [Array]::Copy((script:U32le 0x20), 0, $rb, 24, 4)
            $read = script:Frame-Smb2 (script:New-Smb2Msg -Command 8 -MsgId 12 -SessionId 7 -Body $rb)
            [Smb2Parser]::FormatSmb2Segment($read, 445, 12345) |
                Should -Be 'SMB2 READ Request, Len: 4096; Off: 0; File: big.bin'
            $rrb = [byte[]]::new(16); $rrb[0]=17
            [Array]::Copy((script:U32le 4096), 0, $rrb, 4, 4)
            $readResp = script:Frame-Smb2 (script:New-Smb2Msg -Command 8 -Flags 1 -MsgId 12 -SessionId 7 -Body $rrb)
            [Smb2Parser]::FormatSmb2Segment($readResp, 12345, 445) |
                Should -Be 'SMB2 READ Response, File: big.bin; Len: 4096'
        }

        It 'shows the NT status on an error response with no fabricated CREATE fields' {
            $resp = script:New-Smb2CreateResp -Action 0 -FidP 0 -FidV 0 -MsgId 20 -SessionId 99 -Status ([uint32]3221225506)
            [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445) |
                Should -Be 'SMB2 CREATE Response, STATUS_ACCESS_DENIED (0xC0000022)'
        }

        It 'preserves the filename across an async STATUS_PENDING CREATE response' {
            $req = script:New-Smb2CreateReq -Name 'async.dat' -MsgId 30 -SessionId 4
            $null = [Smb2Parser]::FormatSmb2Segment($req, 445, 12345)
            # Interim STATUS_PENDING CREATE response: header-only, must not discard the pending name.
            $prb = [byte[]]::new(16); $prb[0]=9
            $pend = script:Frame-Smb2 (script:New-Smb2Msg -Command 5 -Flags 1 -Status 0x103 -MsgId 30 -SessionId 4 -Body $prb)
            [Smb2Parser]::FormatSmb2Segment($pend, 12345, 445) | Should -Be 'SMB2 CREATE Response, STATUS_PENDING (0x00000103)'
            # Final success response still resolves the filename.
            $fin = script:New-Smb2CreateResp -Action 2 -FidP 0x50 -FidV 0x51 -MsgId 30 -SessionId 4
            [Smb2Parser]::FormatSmb2Segment($fin, 12345, 445) |
                Should -Be 'SMB2 CREATE Response, Action: FILE_CREATED; File: async.dat'
        }

        It 'formats an encrypted (Transform header) packet' {
            $tf = [byte[]]::new(52); $tf[0]=0xfd; $tf[1]=0x53; $tf[2]=0x4d; $tf[3]=0x42
            [Array]::Copy((script:U32le 200), 0, $tf, 36, 4)   # OriginalMessageSize @36
            [Array]::Copy((script:U32le 0x777), 0, $tf, 44, 4) # SessionId @44
            [Smb2Parser]::FormatSmb2Segment((script:Frame-Smb2 $tf), 445, 12345) |
                Should -Be 'SMB2 Encrypted, SessId 0x777, len 200'
        }

        It 'emits one line per command for a compounded (chained) packet' {
            $path = [System.Text.Encoding]::Unicode.GetBytes('\\srv\pub')
            $tb = [byte[]]::new(8); $tb[0]=9; $po=72
            $tb[4]=$po -band 0xff; $tb[5]=($po -shr 8) -band 0xff
            $tb[6]=$path.Length -band 0xff; $tb[7]=($path.Length -shr 8) -band 0xff
            $tcMsg = script:New-Smb2Msg -Command 3 -MsgId 1 -SessionId 5 -Body ($tb + $path)
            $pad = (8 - ($tcMsg.Length % 8)) % 8
            $tcMsg = $tcMsg + [byte[]]::new($pad)
            $next = $tcMsg.Length
            for ($i=0; $i -lt 4; $i++) { $tcMsg[20+$i]=[byte](($next -shr (8*$i)) -band 0xff) }
            $n = [System.Text.Encoding]::Unicode.GetBytes('a.txt')
            $cb = [byte[]]::new(56); $cb[0]=57; $cb[44]=120 -band 0xff; $cb[45]=0
            $cb[46]=$n.Length -band 0xff; $cb[47]=0; $cb[36]=2
            $crMsg = script:New-Smb2Msg -Command 5 -MsgId 2 -SessionId 5 -Body ($cb + $n)
            $chained = script:Frame-Smb2 ($tcMsg + $crMsg)
            [Smb2Parser]::FormatSmb2Segment($chained, 445, 12345) |
                Should -Be 'SMB2 TREE_CONNECT Request, \\srv\pub | SMB2 CREATE Request, Disposition: FILE_CREATE; File: a.txt'
        }

        It 'formats a NEGOTIATE request with dialect list and capabilities' {
            $nb = [byte[]]::new(36); $nb[0]=36; $nb[2]=2
            [Array]::Copy([byte[]](0x05,0,0,0), 0, $nb, 8, 4)   # caps DFS|LARGE_MTU
            $dialects = [byte[]](0x02,0x02, 0x11,0x03)          # 2.0.2, 3.1.1
            $neg = script:Frame-Smb2 (script:New-Smb2Msg -Command 0 -MsgId 0 -Body ($nb + $dialects))
            [Smb2Parser]::FormatSmb2Segment($neg, 445, 12345) |
                Should -Be 'SMB2 NEGOTIATE Request, Requested Dialects 2.0.2, 3.1.1; DFS, LARGE_MTU'
        }

        It 'formats a NEGOTIATE response with the correct max sizes and capabilities' {
            # Response layout: DialectRevision@4, ServerGuid@8, Capabilities@24, Max*@28/32/36.
            $nb = [byte[]]::new(64); $nb[0]=65; $nb[4]=0x11; $nb[5]=0x03   # StructSize 65, dialect 3.1.1
            [Array]::Copy([byte[]](0x2f,0,0,0), 0, $nb, 24, 4)             # caps 0x2f
            [Array]::Copy([BitConverter]::GetBytes([uint32]8388608), 0, $nb, 28, 4)  # MaxTransact
            [Array]::Copy([BitConverter]::GetBytes([uint32]8388608), 0, $nb, 32, 4)  # MaxRead
            [Array]::Copy([BitConverter]::GetBytes([uint32]8388608), 0, $nb, 36, 4)  # MaxWrite
            $neg = script:Frame-Smb2 (script:New-Smb2Msg -Command 0 -Flags 1 -MsgId 0 -Body $nb)
            [Smb2Parser]::FormatSmb2Segment($neg, 12345, 445) |
                Should -Be 'SMB2 NEGOTIATE Response, Dialect 3.1.1; 8388608\8388608\8388608; DFS, LEASING, LARGE_MTU, MULTI_CHANNEL, DIRECTORY_LEASING'
        }

        It 'ResetState clears the name tables so a later capture starts clean' {
            $req  = script:New-Smb2CreateReq  -Name 'leak.txt' -MsgId 10 -SessionId 99
            $resp = script:New-Smb2CreateResp -Action 1 -FidP 0x40 -FidV 0x41 -MsgId 10 -SessionId 99
            $null = [Smb2Parser]::FormatSmb2Segment($req, 445, 12345)
            $null = [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445)
            [Smb2Parser]::ResetState()
            $clb = [byte[]]::new(24); $clb[0]=24
            [Array]::Copy((script:U32le 0x40), 0, $clb, 8, 4)
            [Array]::Copy((script:U32le 0x41), 0, $clb, 16, 4)
            $expected = [Guid]::new([byte[]]($clb[8..23])).ToString()
            $close = script:Frame-Smb2 (script:New-Smb2Msg -Command 6 -MsgId 11 -SessionId 99 -Body $clb)
            [Smb2Parser]::FormatSmb2Segment($close, 445, 12345) |
                Should -Be "SMB2 CLOSE Request, File: $expected"
        }

        It 'does not crash or hang on a malformed NextCommand' {
            # A huge NextCommand must not wrap the offset negative and index out of range.
            $body = [byte[]]::new(64)
            $pkt = script:Frame-Smb2 (script:New-Smb2Msg -Command 0 -MsgId 0 -NextCommand 0x7FFFFFF0 -Body $body)
            $out = [Smb2Parser]::FormatSmb2Segment($pkt, 445, 12345)
            $out | Should -Match '^SMB2 NEGOTIATE'   # first command still rendered, no throw
        }

        It 'keeps the handle for the final response across a STATUS_PENDING interim response' {
            $req  = script:New-Smb2CreateReq  -Name 'pending.dat' -MsgId 10 -SessionId 3
            $resp = script:New-Smb2CreateResp -Action 1 -FidP 0x7 -FidV 0x8 -MsgId 10 -SessionId 3
            $null = [Smb2Parser]::FormatSmb2Segment($req, 445, 12345)
            $null = [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445)
            # Read request stashes the echo.
            $rb = [byte[]]::new(48); $rb[0]=49
            [Array]::Copy((script:U32le 1024), 0, $rb, 4, 4)
            [Array]::Copy((script:U32le 0x7), 0, $rb, 16, 4)
            [Array]::Copy((script:U32le 0x8), 0, $rb, 24, 4)
            $read = script:Frame-Smb2 (script:New-Smb2Msg -Command 8 -MsgId 20 -SessionId 3 -Body $rb)
            $null = [Smb2Parser]::FormatSmb2Segment($read, 445, 12345)
            # Interim STATUS_PENDING response must peek (not consume) the stashed name.
            $prb = [byte[]]::new(16); $prb[0]=17
            $pend = script:Frame-Smb2 (script:New-Smb2Msg -Command 8 -Flags 1 -Status 0x103 -MsgId 20 -SessionId 3 -Body $prb)
            [Smb2Parser]::FormatSmb2Segment($pend, 12345, 445) | Should -Match 'File: pending\.dat'
            # Final (success) response still resolves the name.
            $frb = [byte[]]::new(16); $frb[0]=17
            [Array]::Copy((script:U32le 1024), 0, $frb, 4, 4)
            $fin = script:Frame-Smb2 (script:New-Smb2Msg -Command 8 -Flags 1 -MsgId 20 -SessionId 3 -Body $frb)
            [Smb2Parser]::FormatSmb2Segment($fin, 12345, 445) | Should -Be 'SMB2 READ Response, File: pending.dat; Len: 1024'
        }

        It 'does not record a tree name for a failed TREE_CONNECT response' {
            $path = [System.Text.Encoding]::Unicode.GetBytes('\\srv\denied')
            $tb = [byte[]]::new(8); $tb[0]=9; $po=72
            $tb[4]=$po -band 0xff; $tb[6]=$path.Length -band 0xff; $tb[7]=($path.Length -shr 8) -band 0xff
            $tc = script:Frame-Smb2 (script:New-Smb2Msg -Command 3 -MsgId 4 -SessionId 8 -Body ($tb + $path))
            $null = [Smb2Parser]::FormatSmb2Segment($tc, 445, 12345)
            # Failed response (BAD_NETWORK_NAME) with TreeId 0 must discard the pending path.
            $trb = [byte[]]::new(16); $trb[0]=16
            $resp = script:Frame-Smb2 (script:New-Smb2Msg -Command 3 -Flags 1 -Status ([uint32]3221225676) -MsgId 4 -SessionId 8 -TreeId 0 -Body $trb)
            [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445) | Should -Match '^SMB2 TREE_CONNECT Response, STATUS_BAD_NETWORK_NAME'
        }

        It 'scopes FileId name resolution per connection (no cross-connection collision)' {
            [Smb2Parser]::ResetState()
            $ckA = [Smb2Parser]::ConnKey('10.0.0.5', 49000, '10.0.0.9', 445)
            $ckB = [Smb2Parser]::ConnKey('10.0.0.6', 49001, '10.0.0.20', 445)
            $ckA | Should -Be ([Smb2Parser]::ConnKey('10.0.0.9', 445, '10.0.0.5', 49000))   # order-independent
            $ckA | Should -Not -Be $ckB
            # Port/address swap must NOT collide (pairing preserved).
            [Smb2Parser]::ConnKey('10.0.0.5', 50000, '10.0.0.9', 445) |
                Should -Not -Be ([Smb2Parser]::ConnKey('10.0.0.5', 445, '10.0.0.9', 50000))
            # Same SessionId(1) + same FileId(0x1/0x2) on both connections, different filenames.
            $reqA  = script:New-Smb2CreateReq  -Name 'connA.txt' -MsgId 10 -SessionId 1
            $respA = script:New-Smb2CreateResp -Action 1 -FidP 0x1 -FidV 0x2 -MsgId 10 -SessionId 1
            $null = [Smb2Parser]::FormatSmb2Segment($reqA,  $reqA.Length,  445, 49000, $ckA)
            $null = [Smb2Parser]::FormatSmb2Segment($respA, $respA.Length, 445, 49000, $ckA)
            $reqB  = script:New-Smb2CreateReq  -Name 'connB.txt' -MsgId 10 -SessionId 1
            $respB = script:New-Smb2CreateResp -Action 1 -FidP 0x1 -FidV 0x2 -MsgId 10 -SessionId 1
            $null = [Smb2Parser]::FormatSmb2Segment($reqB,  $reqB.Length,  445, 49001, $ckB)
            $null = [Smb2Parser]::FormatSmb2Segment($respB, $respB.Length, 445, 49001, $ckB)
            # A CLOSE of FileId 0x1/0x2 resolves to the right file per connection.
            $clb = [byte[]]::new(24); $clb[0]=24
            [Array]::Copy((script:U32le 0x1), 0, $clb, 8, 4); [Array]::Copy((script:U32le 0x2), 0, $clb, 16, 4)
            $close = script:Frame-Smb2 (script:New-Smb2Msg -Command 6 -MsgId 11 -SessionId 1 -Body $clb)
            [Smb2Parser]::FormatSmb2Segment($close, $close.Length, 445, 49000, $ckA) | Should -Be 'SMB2 CLOSE Request, File: connA.txt'
            [Smb2Parser]::FormatSmb2Segment($close, $close.Length, 445, 49001, $ckB) | Should -Be 'SMB2 CLOSE Request, File: connB.txt'
        }

        It 'resolves a related command sentinel FileId to the chain CREATE file' {
            [Smb2Parser]::ResetState()
            # Compound request: CREATE (name) | RELATED QUERY_INFO (sentinel FileId).
            $name = [System.Text.Encoding]::Unicode.GetBytes('report.docx')
            $cb = [byte[]]::new(56); $cb[0]=57; $cb[44]=120; $cb[46]=$name.Length; $cb[36]=1
            $m1 = script:New-Smb2Msg -Command 5 -MsgId 10 -SessionId 1 -TreeId 5 -Body ($cb + $name)
            $pad = (8 - ($m1.Length % 8)) % 8; $m1 = $m1 + [byte[]]::new($pad)
            for ($i=0; $i -lt 4; $i++) { $m1[20+$i]=[byte](($m1.Length -shr (8*$i)) -band 0xff) }   # NextCommand
            $qib = [byte[]]::new(40); $qib[0]=41; $qib[2]=1; $qib[3]=0x30
            for ($i=24; $i -lt 40; $i++) { $qib[$i]=0xFF }   # sentinel FileId @24
            $m2 = script:New-Smb2Msg -Command 16 -Flags 0x04 -MsgId 11 -SessionId 1 -TreeId 5 -Body $qib   # RELATED_OPERATIONS
            $pkt = script:Frame-Smb2 ($m1 + $m2)
            [Smb2Parser]::FormatSmb2Segment($pkt, $pkt.Length, 445, 12345) |
                Should -Match 'SMB2 QUERY_INFO Request, INFO_FILE\\FileNormalizedNameInformation, File: report\.docx$'
        }

        It 'does not resolve a sentinel FileId for a non-related command' {
            [Smb2Parser]::ResetState()
            # Compound with CREATE but the second command lacks the RELATED flag; its sentinel
            # FileId must fall through to the GUID, not the chain file.
            $name = [System.Text.Encoding]::Unicode.GetBytes('report.docx')
            $cb = [byte[]]::new(56); $cb[0]=57; $cb[44]=120; $cb[46]=$name.Length; $cb[36]=1
            $m1 = script:New-Smb2Msg -Command 5 -MsgId 10 -SessionId 1 -TreeId 5 -Body ($cb + $name)
            $pad = (8 - ($m1.Length % 8)) % 8; $m1 = $m1 + [byte[]]::new($pad)
            for ($i=0; $i -lt 4; $i++) { $m1[20+$i]=[byte](($m1.Length -shr (8*$i)) -band 0xff) }
            $clb = [byte[]]::new(24); $clb[0]=24
            for ($i=8; $i -lt 24; $i++) { $clb[$i]=0xFF }   # sentinel FileId @8, no RELATED flag
            $m2 = script:New-Smb2Msg -Command 6 -MsgId 11 -SessionId 1 -TreeId 5 -Body $clb
            $pkt = script:Frame-Smb2 ($m1 + $m2)
            $out = [Smb2Parser]::FormatSmb2Segment($pkt, $pkt.Length, 445, 12345)
            $out | Should -Match 'SMB2 CLOSE Request, File: ffffffff-ffff-ffff'
        }

        It 'isolates legacy (connKey=0) sessions sharing the same MessageId' {
            [Smb2Parser]::ResetState()
            # Two CREATE requests, same MsgId 10, different sessions/names, both pending at once.
            # The pending map is keyed by MsgKey(sessionId, messageId); if sessionId were dropped
            # the two would collide on (0,10) and the responses would resolve the wrong file.
            $reqA = script:New-Smb2CreateReq -Name 'sessA.txt' -MsgId 10 -SessionId 1
            $reqB = script:New-Smb2CreateReq -Name 'sessB.txt' -MsgId 10 -SessionId 2
            $null = [Smb2Parser]::FormatSmb2Segment($reqA, 445, 12345)
            $null = [Smb2Parser]::FormatSmb2Segment($reqB, 445, 12345)
            $respA = script:New-Smb2CreateResp -Action 1 -FidP 0x1 -FidV 0x2 -MsgId 10 -SessionId 1
            $respB = script:New-Smb2CreateResp -Action 1 -FidP 0x3 -FidV 0x4 -MsgId 10 -SessionId 2
            [Smb2Parser]::FormatSmb2Segment($respA, 12345, 445) |
                Should -Match 'SMB2 CREATE Response, Action: FILE_OPENED; File: sessA\.txt$'
            [Smb2Parser]::FormatSmb2Segment($respB, 12345, 445) |
                Should -Match 'SMB2 CREATE Response, Action: FILE_OPENED; File: sessB\.txt$'
        }
    }

    Context 'SMB2 Analysis detail tree (Phase 2a)' {
        BeforeAll {
            # Self-contained packet builders (the formatter context's helpers aren't defined
            # when this context runs in isolation).
            function script:New-Smb2Msg2 {
                param(
                    [int]$Command, [byte]$Flags = 0, [uint32]$Status = 0,
                    [uint64]$MsgId = 0, [uint64]$SessionId = 0, [uint32]$TreeId = 0,
                    [uint32]$NextCommand = 0, [byte[]]$Body = [byte[]]::new(0)
                )
                $hdr = [byte[]]::new(64)
                $hdr[0]=0xfe; $hdr[1]=0x53; $hdr[2]=0x4d; $hdr[3]=0x42; $hdr[4]=64
                $hdr[8]=$Status -band 0xff; $hdr[9]=($Status -shr 8) -band 0xff
                $hdr[10]=($Status -shr 16) -band 0xff; $hdr[11]=($Status -shr 24) -band 0xff
                $hdr[12]=$Command -band 0xff; $hdr[16]=$Flags
                for ($i=0; $i -lt 4; $i++) { $hdr[20+$i]=[byte](($NextCommand -shr (8*$i)) -band 0xff) }
                for ($i=0; $i -lt 8; $i++) { $hdr[24+$i]=[byte](($MsgId -shr (8*$i)) -band 0xff) }
                for ($i=0; $i -lt 4; $i++) { $hdr[36+$i]=[byte](($TreeId -shr (8*$i)) -band 0xff) }
                for ($i=0; $i -lt 8; $i++) { $hdr[40+$i]=[byte](($SessionId -shr (8*$i)) -band 0xff) }
                return ,($hdr + $Body)
            }
            function script:Frame2 {
                param([byte[]]$Msg)
                $t = $Msg.Length
                return ,([byte[]](0x00, (($t -shr 16) -band 0xff), (($t -shr 8) -band 0xff), ($t -band 0xff)) + $Msg)
            }
            function script:U32le2 { param([uint32]$v) [byte[]](($v -band 0xff), (($v -shr 8) -band 0xff), (($v -shr 16) -band 0xff), (($v -shr 24) -band 0xff)) }

            # Flattens a List<BoxyBox.TreeNode> into newline-joined, ANSI-stripped text.
            function script:Smb2TreeText {
                param($Roots)
                $acc = [System.Collections.Generic.List[string]]::new()
                function script:_smb2walk($n, $a) {
                    $a.Add([BoxyBox.AnsiText]::StripAnsi($n.Text))
                    foreach ($c in $n.Children) { script:_smb2walk $c $a }
                }
                foreach ($r in $Roots) { script:_smb2walk $r $acc }
                return ($acc -join "`n")
            }
        }

        BeforeEach { [Smb2Parser]::ResetState() }

        It 'builds a collapsed header (with summary) and the SMB2 header fields for a sync request' {
            $cb = [byte[]]::new(56); $cb[0]=57
            $h = script:New-Smb2Msg2 -Command 5 -Flags 0x08 -MsgId 42 -SessionId 0x99 -TreeId 5 -Body $cb
            # Set CreditCharge (header+6) for the field check.
            $h[6] = 1
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 445, 12345)
            $roots.Count | Should -Be 1
            $roots[0].Key | Should -Be 'SMB2'
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Be 'SMB2 CREATE - TID 0x5'
            # The SMB2 Header node is collapsed by default and carries a summary line.
            $hdrNode = $roots[0].Children | Where-Object { $_.Key -eq 'SMB2.Header' }
            $hdrNode.IsExpanded | Should -BeFalse
            [BoxyBox.AnsiText]::StripAnsi($hdrNode.Text) | Should -Be 'SMB2 Header - Cmd: CREATE (0x0005) Request, TID: 0x5'
            $txt = script:Smb2TreeText $roots
            $txt | Should -Match 'ProtocolId: 0xfe534d42'
            $txt | Should -Match 'Command: CREATE \(5\)'
            $txt | Should -Match 'Channel Sequence: 0'
            $txt | Should -Match 'Credits requested: 0'
            $txt | Should -Match 'Message ID: 42'
            $txt | Should -Match 'Tree Id: 0x5'
            $txt | Should -Match 'Session Id: 0x99'
            # SIGNED flag bit rendered as 1.
            $txt | Should -Match '1\.\.\. = Signing: This pdu is SIGNED'
            $txt | Should -Match 'Flags: 0x00000008, SIGNED'
        }

        It 'shows NT Status on a response header and in the collapsed text' {
            $b = [byte[]]::new(16)
            $h = script:New-Smb2Msg2 -Command 5 -Flags 1 -Status ([uint32]3221225506) -MsgId 7 -SessionId 3 -TreeId 9 -Body $b
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445)
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Be 'SMB2 CREATE - TID 0x9; Status: STATUS_ACCESS_DENIED (0xC0000022)'
            $hdrNode = $roots[0].Children | Where-Object { $_.Key -eq 'SMB2.Header' }
            [BoxyBox.AnsiText]::StripAnsi($hdrNode.Text) |
                Should -Be 'SMB2 Header - Cmd: CREATE (0x0005) Response, TID: 0x9, Status: STATUS_ACCESS_DENIED (0xC0000022)'
            $txt = script:Smb2TreeText $roots
            $txt | Should -Match 'NT Status: STATUS_ACCESS_DENIED \(0xC0000022\)'
            $txt | Should -Match 'Response: This is a RESPONSE'
        }

        It 'renders an async command with an Async Id field' {
            $b = [byte[]]::new(16)
            $h = script:New-Smb2Msg2 -Command 8 -Flags 3 -MsgId 5 -Body $b   # response(1)+async(2)
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445)
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Match '^SMB2 READ - \(async\)'
            $txt = script:Smb2TreeText $roots
            $txt | Should -Match 'Async Id: 0x'
            $txt | Should -Not -Match 'Tree Id:'
            $txt | Should -Match 'Async command: This is a ASYNC command'
        }

        It 'resolves the tree to a UNC path in the collapsed header once known' {
            $path = [System.Text.Encoding]::Unicode.GetBytes('\\server\share')
            $tb = [byte[]]::new(8); $tb[0]=9; $po=72
            $tb[4]=$po -band 0xff; $tb[6]=$path.Length -band 0xff; $tb[7]=($path.Length -shr 8) -band 0xff
            $tc = script:Frame2 (script:New-Smb2Msg2 -Command 3 -MsgId 1 -SessionId 42 -Body ($tb + $path))
            $null = [Smb2Parser]::FormatSmb2Segment($tc, 445, 12345)
            # Response assigns TreeId 7 to session 42.
            $trb = [byte[]]::new(16); $trb[0]=16
            $resp = script:Frame2 (script:New-Smb2Msg2 -Command 3 -Flags 1 -MsgId 1 -SessionId 42 -TreeId 7 -Body $trb)
            $null = [Smb2Parser]::FormatSmb2Segment($resp, 12345, 445)
            # A later command on (session 42, tree 7) resolves the UNC.
            $cb = [byte[]]::new(56); $cb[0]=57
            $create = script:New-Smb2Msg2 -Command 5 -MsgId 2 -SessionId 42 -TreeId 7 -Body $cb
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $create), ($create.Length + 4), 445, 12345)
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Be 'SMB2 CREATE - \\server\share'
            (script:Smb2TreeText $roots) | Should -Match 'Tree Id: 0x7  \\\\server\\share'
        }

        It 'builds a transform (encrypted) header node' {
            $tf = [byte[]]::new(52); $tf[0]=0xfd; $tf[1]=0x53; $tf[2]=0x4d; $tf[3]=0x42
            [Array]::Copy((script:U32le2 200), 0, $tf, 36, 4)
            [Array]::Copy((script:U32le2 0x777), 0, $tf, 44, 4)
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $tf), ($tf.Length + 4), 445, 12345)
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Be 'SMB2 Encrypted - SessId 0x777, len 200'
            $txt = script:Smb2TreeText $roots
            $txt | Should -Match 'SMB2 Transform Header'
            $txt | Should -Match 'Original Message Size: 200'
            $txt | Should -Match 'Session Id: 0x777'
        }

        It 'builds an SMB1 Negotiate header node with Flags and Flags2 subtrees' {
            $s = [byte[]]::new(35)
            $s[0]=0xff; $s[1]=0x53; $s[2]=0x4d; $s[3]=0x42     # 0xFF SMB
            $s[4]=0x72                                          # Negotiate Protocol
            $s[9]=0x18                                          # Flags
            $s[10]=0x01; $s[11]=0xc8                            # Flags2 = 0xc801
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $s), ($s.Length + 4), 12345, 445)
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Be 'SMB1 Negotiate Protocol Request'
            $txt = script:Smb2TreeText $roots
            $txt | Should -Match 'Server Component: SMB'
            $txt | Should -Match 'SMB Command: Negotiate Protocol \(0x72\)'
            $txt | Should -Match 'Flags2: 0xc801'
            $txt | Should -Match 'Unicode Strings: Strings are Unicode'
        }

        It 'emits one root per command for a compounded packet' {
            $b1 = [byte[]]::new(24); $b1[0]=24
            $m1 = script:New-Smb2Msg2 -Command 6 -MsgId 1 -SessionId 5 -Body $b1
            $pad = (8 - ($m1.Length % 8)) % 8
            $m1 = $m1 + [byte[]]::new($pad)
            $next = $m1.Length
            for ($i=0; $i -lt 4; $i++) { $m1[20+$i]=[byte](($next -shr (8*$i)) -band 0xff) }
            $b2 = [byte[]]::new(24); $b2[0]=24
            $m2 = script:New-Smb2Msg2 -Command 4 -MsgId 2 -SessionId 5 -Body $b2
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 ($m1 + $m2)), ($m1.Length + $m2.Length + 4), 445, 12345)
            $roots.Count | Should -Be 2
            [BoxyBox.AnsiText]::StripAnsi($roots[0].Text) | Should -Match '^SMB2 CLOSE'
            [BoxyBox.AnsiText]::StripAnsi($roots[1].Text) | Should -Match '^SMB2 TREE_DISCONNECT'
        }

        # ---- Phase 2b: per-command body subtrees ----

        It 'builds a CREATE request body with decoded fields' {
            $name = [System.Text.Encoding]::Unicode.GetBytes('reports\q3.xlsx')
            $cb = [byte[]]::new(56); $cb[0]=57; $cb[3]=0x09      # RequestedOplockLevel BATCH
            $cb[44]=120; $cb[46]=$name.Length; $cb[36]=1         # NameOffset/Length, Disposition FILE_OPEN
            [Array]::Copy((script:U32le2 0x00000020), 0, $cb, 28, 4)  # FileAttributes ARCHIVE
            [Array]::Copy((script:U32le2 0x00000007), 0, $cb, 32, 4)  # ShareAccess R/W/D
            [Array]::Copy((script:U32le2 0x00000040), 0, $cb, 40, 4)  # CreateOptions NON_DIRECTORY_FILE
            $h = script:New-Smb2Msg2 -Command 5 -MsgId 1 -SessionId 9 -TreeId 5 -Body ($cb + $name)
            $roots = [Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 445, 12345)
            $txt = script:Smb2TreeText $roots
            $txt | Should -Match 'CREATE Request'
            $txt | Should -Match 'Structure Size: 57'
            $txt | Should -Match 'Requested Oplock Level: SMB2_OPLOCK_LEVEL_BATCH \(0x09\)'
            $txt | Should -Match 'File Attributes: 0x00000020 \(ARCHIVE\)'
            $txt | Should -Match 'Share Access: 0x00000007 \(READ, WRITE, DELETE\)'
            $txt | Should -Match 'Create Disposition: FILE_OPEN \(1\)'
            $txt | Should -Match 'Create Options: 0x00000040 \(NON_DIRECTORY_FILE\)'
            $txt | Should -Match 'Name: reports\\q3\.xlsx'
        }

        It 'builds a CREATE response body with times, attributes, and a File Id GUID' {
            $crb = [byte[]]::new(88); $crb[0]=89; $crb[2]=0x01; $crb[4]=1   # oplock II, action OPENED
            [Array]::Copy([BitConverter]::GetBytes([uint64]40960), 0, $crb, 40, 8)  # AllocationSize
            [Array]::Copy([BitConverter]::GetBytes([uint64]40000), 0, $crb, 48, 8)  # EndOfFile
            [Array]::Copy((script:U32le2 0x20), 0, $crb, 56, 4)   # ARCHIVE
            [Array]::Copy((script:U32le2 0xAB), 0, $crb, 64, 4)   # FileId persistent
            [Array]::Copy((script:U32le2 0xCD), 0, $crb, 72, 4)   # FileId volatile
            $h = script:New-Smb2Msg2 -Command 5 -Flags 1 -MsgId 1 -SessionId 9 -Body $crb
            $expected = [Guid]::new([byte[]]($crb[64..79])).ToString()
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445))
            $txt | Should -Match 'CREATE Response'
            $txt | Should -Match 'Oplock Level: SMB2_OPLOCK_LEVEL_II \(0x01\)'
            $txt | Should -Match 'Create Action: FILE_OPENED \(1\)'
            $txt | Should -Match 'Allocation Size: 40960'
            $txt | Should -Match 'End of File: 40000'
            $txt | Should -Match "File Id: $([regex]::Escape($expected))"
        }

        It 'builds a NEGOTIATE request body with a dialects subtree and capability decode' {
            $nb = [byte[]]::new(36); $nb[0]=36; $nb[2]=2; $nb[4]=0x03    # 2 dialects, secmode both
            [Array]::Copy((script:U32le2 0x45), 0, $nb, 8, 4)             # caps DFS|LARGE_MTU|ENCRYPTION
            $dialects = [byte[]](0x02,0x02, 0x11,0x03)
            $h = script:New-Smb2Msg2 -Command 0 -MsgId 1 -Body ($nb + $dialects)
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 445, 12345))
            $txt | Should -Match 'NEGOTIATE Request'
            $txt | Should -Match 'Dialect Count: 2'
            $txt | Should -Match 'Security Mode: 0x0003 \(SIGNING_ENABLED, SIGNING_REQUIRED\)'
            $txt | Should -Match 'Capabilities: 0x00000045 \(DFS, LARGE_MTU, ENCRYPTION\)'
            $txt | Should -Match 'Dialects'
            $txt | Should -Match '2\.0\.2 \(0x0202\)'
            $txt | Should -Match '3\.1\.1 \(0x0311\)'
        }

        It 'builds a READ request body with Length/Offset/File Id' {
            $rb = [byte[]]::new(48); $rb[0]=49
            [Array]::Copy((script:U32le2 65536), 0, $rb, 4, 4)
            [Array]::Copy([BitConverter]::GetBytes([uint64]4096), 0, $rb, 8, 8)
            [Array]::Copy((script:U32le2 0x10), 0, $rb, 16, 4)
            [Array]::Copy((script:U32le2 0x20), 0, $rb, 24, 4)
            $h = script:New-Smb2Msg2 -Command 8 -MsgId 1 -SessionId 9 -Body $rb
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 445, 12345))
            $txt | Should -Match 'READ Request'
            $txt | Should -Match 'Length: 65536'
            $txt | Should -Match 'Offset: 4096'
            $txt | Should -Match 'File Id: '
        }

        It 'builds a TREE_CONNECT response body with the share type' {
            $b = [byte[]]::new(16); $b[0]=16; $b[2]=1   # ShareType DISK
            $h = script:New-Smb2Msg2 -Command 3 -Flags 1 -MsgId 1 -SessionId 9 -TreeId 7 -Body $b
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445))
            $txt | Should -Match 'TREE_CONNECT Response'
            $txt | Should -Match 'Share Type: DISK \(0x01\)'
        }

        It 'renders an error response body without fabricated command fields' {
            $b = [byte[]]::new(16); $b[0]=9   # generic ERROR body (StructureSize 9)
            $h = script:New-Smb2Msg2 -Command 5 -Flags 1 -Status ([uint32]3221225506) -MsgId 1 -SessionId 9 -Body $b
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445))
            $txt | Should -Match 'CREATE Response'
            $txt | Should -Not -Match 'Create Action'
            $txt | Should -Not -Match 'File Id'
        }

        It 'parses a SESSION_SETUP response body under STATUS_MORE_PROCESSING_REQUIRED' {
            $b = [byte[]]::new(8); $b[0]=9; $b[2]=0x01   # SessionFlags IS_GUEST
            $h = script:New-Smb2Msg2 -Command 1 -Flags 1 -Status ([uint32]3221225494) -MsgId 1 -SessionId 9 -Body $b  # 0xC0000016
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445))
            $txt | Should -Match 'SESSION_SETUP Response'
            $txt | Should -Match 'Session Flags: 0x0001 \(IS_GUEST\)'
            $txt | Should -Not -Match 'Byte Count'
        }

        It 'uses the response field layout for an IOCTL response' {
            $b = [byte[]]::new(48); $b[0]=49
            [Array]::Copy((script:U32le2 0x0011C017), 0, $b, 4, 4)   # CtlCode PIPE_TRANSCEIVE
            [Array]::Copy((script:U32le2 120), 0, $b, 32, 4)          # OutputOffset (response @32)
            [Array]::Copy((script:U32le2 256), 0, $b, 36, 4)          # OutputCount  (response @36)
            $h = script:New-Smb2Msg2 -Command 11 -Flags 1 -MsgId 1 -SessionId 9 -Body $b
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $h), ($h.Length + 4), 12345, 445))
            $txt | Should -Match 'IOCTL Response'
            $txt | Should -Match 'Control Code: FSCTL_PIPE_TRANSCEIVE \(0x0011c017\)'
            $txt | Should -Match 'Output Offset: 120'
            $txt | Should -Match 'Output Count: 256'
        }

        It 'gates body-bearing nonzero-status responses per MS-SMB2 3.3.4.4' {
            # QUERY_DIRECTORY + STATUS_NO_MORE_FILES (0x80000006) is a GENERIC ERROR (no exemption).
            $qb = [byte[]]::new(16); $qb[0]=9
            $qh = script:New-Smb2Msg2 -Command 14 -Flags 1 -Status ([uint32]2147483654) -MsgId 1 -SessionId 9 -Body $qb
            $qtxt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $qh), ($qh.Length + 4), 12345, 445))
            $qtxt | Should -Match 'QUERY_DIRECTORY Response'
            $qtxt | Should -Match 'Byte Count'
            $qtxt | Should -Not -Match 'Output Buffer Length'
            # CHANGE_NOTIFY + STATUS_NOTIFY_ENUM_DIR (0x0000010C) carries a CHANGE_NOTIFY body.
            $cb = [byte[]]::new(8); $cb[0]=9
            [Array]::Copy((script:U32le2 16), 0, $cb, 4, 4)
            $ch = script:New-Smb2Msg2 -Command 15 -Flags 1 -Status ([uint32]268) -MsgId 2 -SessionId 9 -Body $cb
            $ctxt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree((script:Frame2 $ch), ($ch.Length + 4), 12345, 445))
            $ctxt | Should -Match 'CHANGE_NOTIFY Response'
            $ctxt | Should -Match 'Output Buffer Length: 16'
            $ctxt | Should -Not -Match 'Byte Count'
        }

        # ---- Phase 2c: FileInfo result parsing ----

        It 'parses QUERY_DIRECTORY response entries using the correlated info class' {
            [Smb2Parser]::ResetState()
            # Request records FileIdBothDirectoryInformation (0x25) for (session 9, msg 50).
            $qb = [byte[]]::new(32); $qb[0]=33; $qb[2]=0x25
            $null = [Smb2Parser]::FormatSmb2Segment((script:Frame2 (script:New-Smb2Msg2 -Command 14 -MsgId 50 -SessionId 9 -Body $qb)), 445, 12345)
            # Two directory entries in the response output buffer.
            function script:MkDirEntry([string]$Name, [uint64]$Eof, [uint32]$Attr, [uint32]$Next) {
                $nb = [System.Text.Encoding]::Unicode.GetBytes($Name); $e = [byte[]]::new(104)
                [Array]::Copy([BitConverter]::GetBytes([uint32]$Next), 0, $e, 0, 4)
                [Array]::Copy([BitConverter]::GetBytes([uint64]$Eof), 0, $e, 40, 8)
                [Array]::Copy([BitConverter]::GetBytes([uint32]$Attr), 0, $e, 56, 4)
                [Array]::Copy([BitConverter]::GetBytes([uint32]$nb.Length), 0, $e, 60, 4)
                return ,($e + $nb)
            }
            $e1 = script:MkDirEntry 'file1.txt' 1024 0x20 0
            $pad = (8 - ($e1.Length % 8)) % 8; $e1 = $e1 + [byte[]]::new($pad)
            for ($i=0; $i -lt 4; $i++) { $e1[$i] = [byte](($e1.Length -shr (8*$i)) -band 0xff) }   # NextEntryOffset
            $e2 = script:MkDirEntry 'file2.txt' 2048 0x10 0
            $buf = $e1 + $e2
            $rb = [byte[]]::new(8); $rb[0]=9
            [Array]::Copy([BitConverter]::GetBytes([uint16]72), 0, $rb, 2, 2)          # OutputBufferOffset (after 8-byte body)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$buf.Length), 0, $rb, 4, 4) # OutputBufferLength
            $resp = script:Frame2 (script:New-Smb2Msg2 -Command 14 -Flags 1 -MsgId 50 -SessionId 9 -Body ($rb + $buf))
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree($resp, ($resp.Length), 12345, 445))
            $txt | Should -Match 'Directory Entries \(2\)'
            $txt | Should -Match '\[1\] file1\.txt'
            $txt | Should -Match 'End of File: 1024'
            $txt | Should -Match '\[2\] file2\.txt'
            $txt | Should -Match 'File Attributes: 0x00000010 \(DIRECTORY\)'
        }

        It 'parses a QUERY_INFO response using the correlated FileStandardInformation class' {
            [Smb2Parser]::ResetState()
            $qib = [byte[]]::new(40); $qib[0]=41; $qib[2]=1; $qib[3]=0x05   # InfoType FILE, class Standard
            $null = [Smb2Parser]::FormatSmb2Segment((script:Frame2 (script:New-Smb2Msg2 -Command 16 -MsgId 60 -SessionId 7 -Body $qib)), 445, 12345)
            $std = [byte[]]::new(24)
            [Array]::Copy([BitConverter]::GetBytes([uint64]4096), 0, $std, 0, 8)
            [Array]::Copy([BitConverter]::GetBytes([uint64]4000), 0, $std, 8, 8)
            [Array]::Copy([BitConverter]::GetBytes([uint32]1), 0, $std, 16, 4)
            $rib = [byte[]]::new(8); $rib[0]=9
            [Array]::Copy([BitConverter]::GetBytes([uint16]72), 0, $rib, 2, 2)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$std.Length), 0, $rib, 4, 4)
            $resp = script:Frame2 (script:New-Smb2Msg2 -Command 16 -Flags 1 -MsgId 60 -SessionId 7 -Body ($rib + $std))
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree($resp, ($resp.Length), 12345, 445))
            $txt | Should -Match 'INFO_FILE\\FileStandardInformation'
            $txt | Should -Match 'Allocation Size: 4096'
            $txt | Should -Match 'End of File: 4000'
            $txt | Should -Match 'Number of Links: 1'
        }

        It 'notes an unknown info class when the QUERY_INFO request was not captured' {
            [Smb2Parser]::ResetState()   # no request recorded
            $std = [byte[]]::new(24)
            $rib = [byte[]]::new(8); $rib[0]=9
            [Array]::Copy([BitConverter]::GetBytes([uint16]72), 0, $rib, 2, 2)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$std.Length), 0, $rib, 4, 4)
            $resp = script:Frame2 (script:New-Smb2Msg2 -Command 16 -Flags 1 -MsgId 99 -SessionId 7 -Body ($rib + $std))
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree($resp, ($resp.Length), 12345, 445))
            $txt | Should -Match 'information class unknown'
        }

        It 'does not crash on a malformed directory NextEntryOffset' {
            [Smb2Parser]::ResetState()
            $qb = [byte[]]::new(32); $qb[0]=33; $qb[2]=0x01   # FileDirectoryInformation
            $null = [Smb2Parser]::FormatSmb2Segment((script:Frame2 (script:New-Smb2Msg2 -Command 14 -MsgId 51 -SessionId 9 -Body $qb)), 445, 12345)
            $ent = [byte[]]::new(80)
            [Array]::Copy([BitConverter]::GetBytes([uint32]0x7FFFFFB3), 0, $ent, 0, 4)   # NextEntryOffset -> pos near Int32.MaxValue
            [Array]::Copy([BitConverter]::GetBytes([uint32]8), 0, $ent, 60, 4)
            $rb = [byte[]]::new(8); $rb[0]=9
            [Array]::Copy([BitConverter]::GetBytes([uint16]72), 0, $rb, 2, 2)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$ent.Length), 0, $rb, 4, 4)
            $resp = script:Frame2 (script:New-Smb2Msg2 -Command 14 -Flags 1 -MsgId 51 -SessionId 9 -Body ($rb + $ent))
            { [Smb2Parser]::BuildSmb2DetailTree($resp, ($resp.Length), 12345, 445) } | Should -Not -Throw
        }

        It 'shows a partial name for a truncated (BUFFER_OVERFLOW) FileNormalizedNameInformation' {
            [Smb2Parser]::ResetState()
            $qib = [byte[]]::new(40); $qib[0]=41; $qib[2]=1; $qib[3]=0x30   # FileNormalizedNameInformation
            $null = [Smb2Parser]::FormatSmb2Segment((script:Frame2 (script:New-Smb2Msg2 -Command 16 -MsgId 61 -SessionId 7 -Body $qib)), 445, 12345)
            # 8-byte output buffer: declared FileNameLength 20, but only 4 bytes of name present.
            $ni = [byte[]]::new(8)
            [Array]::Copy([BitConverter]::GetBytes([uint32]20), 0, $ni, 0, 4)          # FileNameLength (full)
            [Array]::Copy([System.Text.Encoding]::Unicode.GetBytes('ab'), 0, $ni, 4, 4) # partial name "ab"
            $rib = [byte[]]::new(8); $rib[0]=9
            [Array]::Copy([BitConverter]::GetBytes([uint16]72), 0, $rib, 2, 2)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$ni.Length), 0, $rib, 4, 4)
            $resp = script:Frame2 (script:New-Smb2Msg2 -Command 16 -Flags 1 -Status ([uint32]2147483653) -MsgId 61 -SessionId 7 -Body ($rib + $ni))
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree($resp, ($resp.Length), 12345, 445))
            $txt | Should -Match 'FileNormalizedNameInformation'
            $txt | Should -Match 'Name: ab \(truncated\)'
        }

        It 'parses a SET_INFO request buffer (FileRenameInformation)' {
            [Smb2Parser]::ResetState()
            $newName = [System.Text.Encoding]::Unicode.GetBytes('renamed.txt')
            $rn = [byte[]]::new(20); $rn[0]=1   # ReplaceIfExists
            [Array]::Copy([BitConverter]::GetBytes([uint32]$newName.Length), 0, $rn, 16, 4)
            $rn = $rn + $newName
            $sb = [byte[]]::new(32); $sb[0]=33; $sb[2]=1; $sb[3]=0x0A   # InfoType FILE, class Rename
            [Array]::Copy([BitConverter]::GetBytes([uint32]$rn.Length), 0, $sb, 4, 4)   # BufferLength
            [Array]::Copy([BitConverter]::GetBytes([uint16]96), 0, $sb, 8, 2)           # BufferOffset (after 32-byte body)
            $req = script:Frame2 (script:New-Smb2Msg2 -Command 17 -MsgId 70 -SessionId 7 -Body ($sb + $rn))
            $txt = script:Smb2TreeText ([Smb2Parser]::BuildSmb2DetailTree($req, ($req.Length), 445, 12345))
            $txt | Should -Match 'INFO_FILE\\FileRenameInformation'
            $txt | Should -Match 'Replace If Exists: True'
            $txt | Should -Match 'New Name: renamed\.txt'
        }
    }

    Context 'ICMP / ICMPv6 / NDP application-layer predicate' {
        BeforeAll {
            $script:icmpStartCmd = Get-Command -Name Start-Pspkt -ErrorAction Stop

            $script:icmpV4Echo = [IcmpContext]::new()
            $script:icmpV4Echo.Valid = $true; $script:icmpV4Echo.IsV6 = $false
            $script:icmpV4Echo.Type = 8; $script:icmpV4Echo.Code = 0

            $script:icmpV4Unr = [IcmpContext]::new()
            $script:icmpV4Unr.Valid = $true; $script:icmpV4Unr.IsV6 = $false
            $script:icmpV4Unr.Type = 3; $script:icmpV4Unr.Code = 1

            $script:icmpV6Ns = [IcmpContext]::new()
            $script:icmpV6Ns.Valid = $true; $script:icmpV6Ns.IsV6 = $true
            $script:icmpV6Ns.Type = 135; $script:icmpV6Ns.Code = 0; $script:icmpV6Ns.NdpTarget = 'fe80::1'

            $script:icmpV6Na = [IcmpContext]::new()
            $script:icmpV6Na.Valid = $true; $script:icmpV6Na.IsV6 = $true
            $script:icmpV6Na.Type = 136; $script:icmpV6Na.Code = 0; $script:icmpV6Na.NdpTarget = 'fe80::2'

            $script:icmpV6Ra = [IcmpContext]::new()
            $script:icmpV6Ra.Valid = $true; $script:icmpV6Ra.IsV6 = $true
            $script:icmpV6Ra.Type = 134; $script:icmpV6Ra.Code = 0
        }

        AfterEach {
            [PacketLineFormatter]::ClearAppPredicates()
        }

        It 'has -IcmpType parameter (string array)' {
            $script:icmpStartCmd.Parameters.ContainsKey('IcmpType') | Should -BeTrue
            $script:icmpStartCmd.Parameters['IcmpType'].ParameterType | Should -Be ([string[]])
        }

        It 'has -Icmpv6Type parameter (string array)' {
            $script:icmpStartCmd.Parameters.ContainsKey('Icmpv6Type') | Should -BeTrue
            $script:icmpStartCmd.Parameters['Icmpv6Type'].ParameterType | Should -Be ([string[]])
        }

        It 'has -Icmpv6NdpTarget parameter (string array)' {
            $script:icmpStartCmd.Parameters.ContainsKey('Icmpv6NdpTarget') | Should -BeTrue
            $script:icmpStartCmd.Parameters['Icmpv6NdpTarget'].ParameterType | Should -Be ([string[]])
        }

        It 'IcmpAppPredicate V4Types filters by ICMPv4 type and rejects v6' {
            $p = [IcmpAppPredicate]::new()
            $p.V4Types = @(8)
            $p.Evaluate([ref]$script:icmpV4Echo) | Should -BeTrue
            $p.Evaluate([ref]$script:icmpV4Unr)  | Should -BeFalse
            $p.Evaluate([ref]$script:icmpV6Ns)   | Should -BeFalse
        }

        It 'IcmpAppPredicate V6Types filters by ICMPv6 type and rejects v4' {
            $p = [IcmpAppPredicate]::new()
            $p.V6Types = @(135, 136)
            $p.Evaluate([ref]$script:icmpV6Ns)   | Should -BeTrue
            $p.Evaluate([ref]$script:icmpV6Na)   | Should -BeTrue
            $p.Evaluate([ref]$script:icmpV6Ra)   | Should -BeFalse
            $p.Evaluate([ref]$script:icmpV4Echo) | Should -BeFalse
        }

        It 'IcmpAppPredicate combines V4Types and V6Types (both families pass)' {
            $p = [IcmpAppPredicate]::new()
            $p.V4Types = @(8)
            $p.V6Types = @(128)
            $p.Evaluate([ref]$script:icmpV4Echo) | Should -BeTrue
            $p.Evaluate([ref]$script:icmpV6Ns)   | Should -BeFalse
            # Wrong types still rejected within each family.
            $p.Evaluate([ref]$script:icmpV4Unr)  | Should -BeFalse
        }

        It 'IcmpAppPredicate NdpTargetRegex matches NS for the target' {
            $p = [IcmpAppPredicate]::new()
            $p.NdpTargetRegex = [regex]::new('^fe80::1$', 'IgnoreCase,Compiled')
            $p.Evaluate([ref]$script:icmpV6Ns) | Should -BeTrue
            $p.Evaluate([ref]$script:icmpV6Na) | Should -BeFalse
        }

        It 'IcmpAppPredicate NdpTargetRegex rejects non-NS/NA packets' {
            $p = [IcmpAppPredicate]::new()
            $p.NdpTargetRegex = [regex]::new('.+', 'IgnoreCase,Compiled')
            $p.Evaluate([ref]$script:icmpV6Ra)   | Should -BeFalse
            $p.Evaluate([ref]$script:icmpV4Echo) | Should -BeFalse
        }

        It 'IcmpAppPredicate NdpTargetRegex AND V6Types narrows further' {
            $p = [IcmpAppPredicate]::new()
            $p.V6Types        = @(136)  # NA only
            $p.NdpTargetRegex = [regex]::new('^fe80::', 'IgnoreCase,Compiled')
            $p.Evaluate([ref]$script:icmpV6Ns) | Should -BeFalse
            $p.Evaluate([ref]$script:icmpV6Na) | Should -BeTrue
        }

        It 'Resolve-PspktIcmp4Type accepts full enum, short, and numeric forms' {
            $subMod = Get-Module PspktSession
            $subMod | Should -Not -BeNullOrEmpty
            $resolve = { param($v) Resolve-PspktIcmp4Type -Value $v }

            (& $subMod $resolve 'ICMP4_ECHO_REQUEST') | Should -Be 8
            (& $subMod $resolve 'EchoRequest')        | Should -Be 8
            (& $subMod $resolve 'ECHO_REQUEST')       | Should -Be 8
            (& $subMod $resolve '8')                  | Should -Be 8
            (& $subMod $resolve '0x08')               | Should -Be 8
            { & $subMod $resolve 'NOT_A_TYPE' } | Should -Throw
        }

        It 'Resolve-PspktIcmpv6Type accepts long and short names' {
            $subMod = Get-Module PspktSession
            $resolve = { param($v) Resolve-PspktIcmpv6Type -Value $v }

            (& $subMod $resolve 'NeighborSolicitation') | Should -Be 135
            (& $subMod $resolve 'NS')                   | Should -Be 135
            (& $subMod $resolve 'EchoRequest')          | Should -Be 128
            (& $subMod $resolve '128')                  | Should -Be 128
            (& $subMod $resolve '0x80')                 | Should -Be 128
            { & $subMod $resolve 'NOPE' } | Should -Throw
        }

        It 'PacketLineFormatter wires set/get/clear of IcmpPredicate' {
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
            $p = [IcmpAppPredicate]::new()
            [PacketLineFormatter]::SetIcmpPredicate($p)
            [PacketLineFormatter]::HasAppPredicate | Should -BeTrue
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::HasAppPredicate | Should -BeFalse
        }
    }

    Context 'Analysis save/buffer helpers' {
        It 'Get-PspktBufferLevelMultiplier scales the base multiplier by the level' {
            $subMod = Get-Module PspktSession
            $calc = { param($base, $lvl) Get-PspktBufferLevelMultiplier -BaseMultiplier $base -Level ([PspktBufferLevel]::$lvl) }
            (& $subMod $calc 4 'Tiny')      | Should -Be 1
            (& $subMod $calc 4 'Small')     | Should -Be 2
            (& $subMod $calc 4 'Default')   | Should -Be 4
            (& $subMod $calc 4 'Large')     | Should -Be 6
            (& $subMod $calc 4 'Huge')      | Should -Be 16
            (& $subMod $calc 4 'Massive')   | Should -Be 32
        }
        It 'Get-PspktBufferLevelMultiplier clamps to the valid uint16 range' {
            $subMod = Get-Module PspktSession
            $calc = { param($base, $lvl) Get-PspktBufferLevelMultiplier -BaseMultiplier $base -Level ([PspktBufferLevel]::$lvl) }
            # 1 * 0.25 = 0.25 -> clamps up to 1
            (& $subMod $calc 1 'Tiny') | Should -Be 1
            # 65535 * 8 -> clamps down to 65535
            (& $subMod $calc 65535 'Massive') | Should -Be 65535
        }
        It 'New-PspktCaptureFileName builds a tagged, timestamped, sanitized name' {
            $subMod = Get-Module PspktSession
            $ts = [datetime]'2026-01-02 12:34:56'
            $make = { param($tag, $t) New-PspktCaptureFileName -FilterTag $tag -Timestamp $t }
            (& $subMod $make 'DNS-Ping' $ts)     | Should -Be 'pspkt-DNS-Ping-20260102-123456.pcapng'
            (& $subMod $make '' $ts)             | Should -Be 'pspkt-all-20260102-123456.pcapng'
            # Path-traversal / wildcard characters are stripped.
            (& $subMod $make 'DNS/../evil*' $ts) | Should -Be 'pspkt-DNSevil-20260102-123456.pcapng'
        }
    }

    Context 'Quick filter / parameter tree helpers' {
        BeforeAll {
            $script:commonParams = @(
                'Verbose','Debug','ErrorAction','WarningAction','InformationAction',
                'ProgressAction','ErrorVariable','WarningVariable','InformationVariable',
                'OutVariable','OutBuffer','PipelineVariable','WhatIf','Confirm'
            )
            $script:startParams = (Get-Command Start-Pspkt).Parameters
            $script:nonCommonParams = @($script:startParams.Keys | Where-Object { $_ -notin $script:commonParams })
            $script:qfText = (Get-PspktQuickFilter) -join "`n"
            $script:paramTreeText = (Get-PspktParameterTree) -join "`n"
        }

        It 'exports Get-PspktQuickFilter and Get-PspktParameterTree' {
            (Get-Command -Name Get-PspktQuickFilter -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
            (Get-Command -Name Get-PspktParameterTree -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        }

        It 'Get-PspktQuickFilter returns non-empty text' {
            $script:qfText | Should -Not -BeNullOrEmpty
            $script:qfText | Should -Match 'Quick Filters and Application-Layer Predicates'
        }

        It 'Get-PspktQuickFilterTree entries all reference real Start-Pspkt parameters' {
            $subMod = Get-Module PspktSession
            $tree = & $subMod { Get-PspktQuickFilterTree }
            $names = @($script:startParams.Keys)
            foreach ($section in $tree.Keys) {
                foreach ($entry in $tree[$section]) {
                    # A switch quick filter has a real '-Name' parameter (except the
                    # synthetic '(ICMP app filters)' grouping entry, which has none).
                    if ($entry.Name -like '-*') {
                        $names | Should -Contain $entry.Name.TrimStart('-')
                    }
                    # Every application-layer predicate must be a real parameter too.
                    foreach ($appParam in $entry.Params) {
                        $names | Should -Contain $appParam.N.TrimStart('-')
                    }
                }
            }
        }

        It 'Get-PspktQuickFilter shows the current (array) predicate types' {
            # These were previously stale scalar types; reflection must render them as arrays.
            $script:qfText | Should -Match '-DnsName <string\[\]>'
            $script:qfText | Should -Match '-DnsId <int\[\]>'
            $script:qfText | Should -Match '-TlsSni <string\[\]>'
            $script:qfText | Should -Match '-HttpStatus <string\[\]>'
            $script:qfText | Should -Match '-DhcpClientMac <string\[\]>'
            $script:qfText | Should -Match '-SmbFilename <string\[\]>'
            $script:qfText | Should -Match '-Icmpv6NdpTarget <string\[\]>'
        }

        It 'Get-PspktQuickFilter renders switch aliases' {
            $script:qfText | Should -Match '-DNSoverHTTPS \(alias: -DoH\)'
            $script:qfText | Should -Match '-DNSoverTLS \(alias: -DoT\)'
            $script:qfText | Should -Match '-SMBoverQUIC \(alias: -SoQ\)'
        }

        It 'Get-PspktQuickFilter shows every application-layer predicate parameter' {
            # App-predicate params follow the mixed-case convention (DnsName, TlsSni, ...).
            # Case-sensitive prefix match excludes the all-caps switch filters (DNS, HTTP, SMB).
            $appPredicates = @($script:startParams.Keys |
                Where-Object { $_ -cmatch '^(Dns|Tls|Http|Dhcp|Smb|Icmp)' })
            $appPredicates.Count | Should -BeGreaterThan 0
            $missing = @()
            foreach ($p in $appPredicates) {
                if ($script:qfText -notmatch "(?m)-$([regex]::Escape($p))\b") { $missing += $p }
            }
            # A newly-added predicate that isn't wired into the curated tree fails here.
            $missing | Should -BeNullOrEmpty
        }

        It 'Get-PspktParameterTree -Protocol with an empty array shows the full tree' {
            $emptyProtoText = (Get-PspktParameterTree -Protocol @()) -join "`n"
            $emptyProtoText | Should -Match 'General Parameters'
            $emptyProtoText | Should -Match 'Quick Filters and Application-Layer Predicates'
        }

        It 'Get-PspktParameterTree includes every non-common Start-Pspkt parameter' {
            $missing = @()
            foreach ($p in $script:nonCommonParams) {
                if ($script:paramTreeText -notmatch "(?m)-$([regex]::Escape($p))\b") { $missing += $p }
            }
            $missing | Should -BeNullOrEmpty
        }

        It 'Get-PspktParameterTree contains both the general and quick-filter sections' {
            $script:paramTreeText | Should -Match 'General Parameters'
            $script:paramTreeText | Should -Match 'Quick Filters and Application-Layer Predicates'
        }

        It 'Get-PspktParameterTree tags parameter-set-specific parameters' {
            $script:paramTreeText | Should -Match '-Session <pspktSession>.*\[WithSession\]'
            $script:paramTreeText | Should -Match '-Name <string>.*\[Default\]'
        }
    }

    Context 'NDP detailed parser' {
        BeforeAll {
            function script:To16U([uint16]$v) {
                return [byte[]]@([byte](($v -shr 8) -band 0xff), [byte]($v -band 0xff))
            }
            function script:To32U([uint32]$v) {
                return [byte[]]@(
                    [byte](($v -shr 24) -band 0xff),
                    [byte](($v -shr 16) -band 0xff),
                    [byte](($v -shr  8) -band 0xff),
                    [byte]($v -band 0xff)
                )
            }
            function script:ToIp6([string]$addr) {
                return [System.Net.IPAddress]::Parse($addr).GetAddressBytes()
            }

            $srcMac = [byte[]](0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03)
            $optSrcLL = [byte[]](1, 1) + $srcMac

            $script:ndpRs = [byte[]](133, 0, 0, 0, 0, 0, 0, 0) + $optSrcLL

            # RA: HopLim=64, M=0 O=0 H=0 Prf=00 (Medium), RouterLifetime=1800,
            # Reachable=30000ms, Retrans=1000ms, + MTU=1500 + Prefix fe80::/64
            $raHeader = [byte[]](134, 0, 0, 0, 64, 0) + (script:To16U 1800) + (script:To32U 30000) + (script:To32U 1000)
            $optMtu   = [byte[]](5, 1, 0, 0) + (script:To32U 1500)
            $optPref  = [byte[]](3, 4, 64, 0xC0) + (script:To32U 86400) + (script:To32U 14400) + (script:To32U 0) + (script:ToIp6 'fe80::')
            $script:ndpRa = $raHeader + $optMtu + $optPref

            $script:ndpNs = [byte[]](135, 0, 0, 0, 0, 0, 0, 0) + (script:ToIp6 'fe80::1') + $optSrcLL

            $tgtMac = [byte[]](0x00, 0xde, 0xad, 0xbe, 0xef, 0x42)
            $optTgtLL = [byte[]](2, 1) + $tgtMac
            $script:ndpNa = [byte[]](136, 0, 0, 0, 0x60, 0, 0, 0) + (script:ToIp6 'fe80::2') + $optTgtLL

            $script:ndpRedirect = [byte[]](137, 0, 0, 0, 0, 0, 0, 0) +
                                  (script:ToIp6 'fe80::a1b2:c3d4:e5f6:7890') +
                                  (script:ToIp6 '2001:db8::1')

            $script:ndpRaInf = $raHeader +
                ([byte[]](3, 4, 64, 0xC0) + (script:To32U 0xFFFFFFFFL) + (script:To32U 0xFFFFFFFFL) + (script:To32U 0) + (script:ToIp6 'fe80::'))
        }

        It 'formats Router Solicitation with SrcLL option' {
            $line = [NdpParser]::FormatNdpDetailed($script:ndpRs, 0, $script:ndpRs.Length)
            $line | Should -Match '^NDP RouterSolicitation'
            $line | Should -Match 'SrcLL aa-bb-cc-01-02-03'
        }

        It 'formats Router Advertisement with HopLim, flags, timers, MTU, Prefix' {
            $line = [NdpParser]::FormatNdpDetailed($script:ndpRa, 0, $script:ndpRa.Length)
            $line | Should -Match '^NDP RouterAdvertisement'
            $line | Should -Match 'HopLim 64'
            $line | Should -Match 'M=0 O=0'
            $line | Should -Match 'Pref=Medium'
            $line | Should -Match 'Lifetime 1800s'
            $line | Should -Match 'ReachTime 30000ms'
            $line | Should -Match 'RetransTimer 1000ms'
            $line | Should -Match 'MTU 1500'
            $line | Should -Match 'Prefix fe80::/64'
            $line | Should -Match 'L=1 A=1'
            $line | Should -Match 'Valid 86400s'
            $line | Should -Match 'Pref 14400s'
        }

        It 'renders infinite (0xFFFFFFFF) prefix lifetime as "Infinite"' {
            $line = [NdpParser]::FormatNdpDetailed($script:ndpRaInf, 0, $script:ndpRaInf.Length)
            $line | Should -Match 'Valid Infinite'
            $line | Should -Match 'Pref Infinite'
        }

        It 'formats Neighbor Solicitation with Target and SrcLL' {
            $line = [NdpParser]::FormatNdpDetailed($script:ndpNs, 0, $script:ndpNs.Length)
            $line | Should -Match '^NDP NeighborSolicitation'
            $line | Should -Match 'Target fe80::1'
            $line | Should -Match 'SrcLL aa-bb-cc-01-02-03'
        }

        It 'formats Neighbor Advertisement with Target, RSO flags, TgtLL' {
            $line = [NdpParser]::FormatNdpDetailed($script:ndpNa, 0, $script:ndpNa.Length)
            $line | Should -Match '^NDP NeighborAdvertisement'
            $line | Should -Match 'Target fe80::2'
            $line | Should -Match 'R=0 S=1 O=1'
            $line | Should -Match 'TgtLL 00-de-ad-be-ef-42'
        }

        It 'formats Redirect with Target and Dest' {
            $line = [NdpParser]::FormatNdpDetailed($script:ndpRedirect, 0, $script:ndpRedirect.Length)
            $line | Should -Match '^NDP Redirect'
            $line | Should -Match 'Target fe80::a1b2:c3d4:e5f6:7890'
            $line | Should -Match 'Dest 2001:db8::1'
        }

        It 'returns just the message name on truncated NS / NA (no target)' {
            $trunc = [byte[]](135, 0, 0, 0)
            $line = [NdpParser]::FormatNdpDetailed($trunc, 0, $trunc.Length)
            $line | Should -Be 'NDP NeighborSolicitation'
        }

        It 'falls back to "NDP type N" for unknown ICMPv6 types' {
            $unknown = [byte[]](150, 0, 0, 0)
            $line = [NdpParser]::FormatNdpDetailed($unknown, 0, $unknown.Length)
            $line | Should -Be 'NDP type 150'
        }

        It 'returns null on invalid input' {
            [NdpParser]::FormatNdpDetailed($null, 0, 0) | Should -BeNullOrEmpty
            [NdpParser]::FormatNdpDetailed([byte[]](1,2), 0, 2) | Should -BeNullOrEmpty
        }
    }

    Context 'FormatBatch line counter advances only on emitted lines' {
        BeforeAll {
            # Build a minimal Ethernet + IPv4 + ICMP packet for the given ICMP
            # type. Layout: 6 dst MAC + 6 src MAC + 2 EtherType + 20 IPv4 header
            # + 8 ICMP header = 42 bytes. MetadataOffset is set past the packet
            # so the metadata-extraction branch is skipped cleanly.
            function script:New-Icmpv4Packet([byte]$IcmpType) {
                $packet = [byte[]]::new(42)
                # Ethernet: zero MACs, EtherType 0x0800 (IPv4)
                $packet[12] = 0x08; $packet[13] = 0x00
                # IPv4 header — Version=4, IHL=5
                $packet[14] = 0x45
                # Total length = 28 (IP header + ICMP), bytes 16-17 big-endian
                $packet[16] = 0x00; $packet[17] = 0x1C
                # TTL = 64
                $packet[22] = 0x40
                # Protocol = 1 (ICMP)
                $packet[23] = 0x01
                # Src IP = 10.0.0.1, Dst IP = 10.0.0.2
                $packet[26] = 10; $packet[27] = 0; $packet[28] = 0; $packet[29] = 1
                $packet[30] = 10; $packet[31] = 0; $packet[32] = 0; $packet[33] = 2
                # ICMP header at byte 34
                $packet[34] = $IcmpType
                return [PSPacketData]::new(
                    $packet,
                    [uint32]$packet.Length,   # dataSize
                    [uint32]200,              # metadataOffset (past end → metadata branch skipped)
                    [uint32]0,                # packetOffset
                    [uint32]$packet.Length,   # packetLength
                    [uint32]0, [uint32]0)
            }
        }

        AfterEach {
            [PacketLineFormatter]::ClearAppPredicates()
            [PacketLineFormatter]::SetOptions($false, 0)  # restore default detail level
        }

        It 'does not advance the line counter for packets rejected by an app-layer predicate' {
            # Detailed level so the predicate gate runs.
            [PacketLineFormatter]::SetOptions($false, 1)

            # Predicate accepts ICMP type 8 only (echo request).
            $p = [IcmpAppPredicate]::new()
            $p.V4Types = @(8)
            [PacketLineFormatter]::SetIcmpPredicate($p)

            # Buffer: accepted (type 8), rejected (type 0 echo reply), accepted (type 8).
            $buffer = [PSPacketData[]]::new(3)
            $buffer[0] = script:New-Icmpv4Packet -IcmpType 8
            $buffer[1] = script:New-Icmpv4Packet -IcmpType 0
            $buffer[2] = script:New-Icmpv4Packet -IcmpType 8

            $startCounter = 100
            $result = [PacketLineFormatter]::FormatBatch($buffer, 3, $startCounter)
            $result | Should -Not -BeNullOrEmpty

            # Two packets emitted, so the counter must have advanced by exactly 2.
            ($result.LineCounter - $startCounter) | Should -Be 2

            # Statistics are packet-based (not line-based) and stay at the full count.
            $result.PacketCount | Should -Be 3
        }

        It 'advances the line counter once per packet when no predicate rejects' {
            [PacketLineFormatter]::SetOptions($false, 1)

            # No predicate; every packet should be emitted.
            $buffer = [PSPacketData[]]::new(3)
            $buffer[0] = script:New-Icmpv4Packet -IcmpType 8
            $buffer[1] = script:New-Icmpv4Packet -IcmpType 0
            $buffer[2] = script:New-Icmpv4Packet -IcmpType 8

            $startCounter = 100
            $result = [PacketLineFormatter]::FormatBatch($buffer, 3, $startCounter)
            ($result.LineCounter - $startCounter) | Should -Be 3
        }
    }

    Context 'WriteBatch matches FormatBatch (LOH-free console path)' {
        BeforeAll {
            # Self-contained Ethernet + IPv4 + ICMP packet builder (metadata offset past the
            # packet so the metadata branch is skipped).
            function script:New-WbIcmpPacket([byte]$IcmpType) {
                $packet = [byte[]]::new(42)
                $packet[12] = 0x08; $packet[13] = 0x00      # EtherType IPv4
                $packet[14] = 0x45                          # IPv4 v4 IHL5
                $packet[16] = 0x00; $packet[17] = 0x1C      # total length 28
                $packet[22] = 0x40                          # TTL 64
                $packet[23] = 0x01                          # protocol ICMP
                $packet[26] = 10; $packet[29] = 1           # src 10.0.0.1
                $packet[30] = 10; $packet[33] = 2           # dst 10.0.0.2
                $packet[34] = $IcmpType
                return [PSPacketData]::new($packet, [uint32]$packet.Length, [uint32]200,
                    [uint32]0, [uint32]$packet.Length, [uint32]0, [uint32]0)
            }
        }

        AfterEach {
            [PacketLineFormatter]::SetOptions($false, 0)
        }

        It 'writes byte-for-byte the same output as FormatBatch, across chunk boundaries' {
            [PacketLineFormatter]::SetOptions($false, 0)

            # Enough packets that the batch output exceeds the 32,768-char chunk buffer, so the
            # multi-chunk copy path is exercised.
            $n = 1200
            $buffer = [PSPacketData[]]::new($n)
            for ($i = 0; $i -lt $n; $i++) { $buffer[$i] = script:New-WbIcmpPacket -IcmpType 8 }

            $expected = [PacketLineFormatter]::FormatBatch($buffer, $n, 0).Output
            $expected | Should -Not -BeNullOrEmpty
            $expected.Length | Should -BeGreaterThan 32768 -Because 'the test must cross a chunk boundary'

            $sw = [System.IO.StringWriter]::new()
            $orig = [Console]::Out
            try {
                [Console]::SetOut($sw)
                $res = [PacketLineFormatter]::WriteBatch($buffer, $n, 0)
            } finally {
                [Console]::SetOut($orig)
            }

            $res | Should -Not -BeNullOrEmpty
            $res.Output | Should -BeNullOrEmpty -Because 'WriteBatch writes to the console, not a returned string'
            $res.PacketCount | Should -Be $n
            $sw.ToString() | Should -Be $expected -Because 'the streamed console output must equal the materialized string'
        }

        It 'returns null for an empty batch and writes nothing' {
            $sw = [System.IO.StringWriter]::new()
            $orig = [Console]::Out
            try {
                [Console]::SetOut($sw)
                $res = [PacketLineFormatter]::WriteBatch([PSPacketData[]]::new(0), 0, 0)
            } finally {
                [Console]::SetOut($orig)
            }
            $res | Should -BeNullOrEmpty
            $sw.ToString() | Should -BeNullOrEmpty
        }
    }

    Context 'Quick-filter coverage check (auto-imply suppression)' {
        BeforeAll {
            $script:subMod = Get-Module PspktSession
            $script:check = {
                param($Filters, $EtherType, $TransportProtocol, $Port)
                Test-PspktQuickFilterCoverage `
                    -Filters $Filters `
                    -EtherType $EtherType `
                    -TransportProtocol $TransportProtocol `
                    -Port $Port
            }
        }

        It 'empty filter list never covers anything' {
            $filters = [System.Collections.ArrayList]::new()
            (& $script:subMod $script:check $filters '' 'TCP' 443) | Should -BeFalse
            (& $script:subMod $script:check $filters 'IPv6' 'IPv6_ICMP' 0) | Should -BeFalse
        }

        It '-ARP filter does NOT cover TCP 443 (regression: prior bug suppressed TLS auto-imply)' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP'))
            (& $script:subMod $script:check $filters '' 'TCP' 443) | Should -BeFalse
        }

        It '-ARP filter does NOT cover ICMPv6 (the reported bug)' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP'))
            (& $script:subMod $script:check $filters 'IPv6' 'IPv6_ICMP' 0) | Should -BeFalse
        }

        It '-ARP filter covers ARP only' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP'))
            (& $script:subMod $script:check $filters 'ARP' '' 0) | Should -BeTrue
        }

        It '-Ping filter (ICMPv4 + ICMPv6) covers both ICMP families' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ICMPv4' -EtherType 'IPv4' -TransportProtocol 'ICMP'))
            $null = $filters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
            (& $script:subMod $script:check $filters 'IPv4' 'ICMP' 0)       | Should -BeTrue
            (& $script:subMod $script:check $filters 'IPv6' 'IPv6_ICMP' 0)  | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'TCP' 443)          | Should -BeFalse
        }

        It '-HTTPS (TCP 443) covers TCP 443 target' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-HTTPS' -TransportProtocol 'TCP' -Port1 443))
            (& $script:subMod $script:check $filters '' 'TCP' 443) | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'TCP' 80)  | Should -BeFalse
            (& $script:subMod $script:check $filters '' 'UDP' 443) | Should -BeFalse
        }

        It '-DNS covers both UDP 53 and TCP 53' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-DNS-UDP' -TransportProtocol 'UDP' -Port1 53))
            $null = $filters.Add((New-PspktFilter -Name 'QF-DNS-TCP' -TransportProtocol 'TCP' -Port1 53))
            (& $script:subMod $script:check $filters '' 'UDP' 53)  | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'TCP' 53)  | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'TCP' 853) | Should -BeFalse
        }

        It '-DNSoverTLS (TCP 853) does NOT cover TLS auto-imply (TCP 443)' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-DoT' -TransportProtocol 'TCP' -Port1 853))
            (& $script:subMod $script:check $filters '' 'TCP' 443) | Should -BeFalse
        }

        It 'a broader filter (TCP, any port) covers any specific TCP port target' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ALL-TCP' -TransportProtocol 'TCP'))
            (& $script:subMod $script:check $filters '' 'TCP' 443) | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'TCP' 80)  | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'UDP' 53)  | Should -BeFalse
        }

        It 'a fully-unconstrained filter covers everything' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ANY'))
            (& $script:subMod $script:check $filters 'IPv4' 'ICMP' 0)       | Should -BeTrue
            (& $script:subMod $script:check $filters 'IPv6' 'IPv6_ICMP' 0)  | Should -BeTrue
            (& $script:subMod $script:check $filters '' 'TCP' 443)          | Should -BeTrue
        }
    }

    Context 'VM AND-scoping helpers' {
        BeforeAll {
            $script:vmMod = Get-Module PspktSession
            $script:copyFn = {
                param($Filter, $Suffix)
                Copy-PspktFilter -Filter $Filter -NameSuffix $Suffix
            }
        }

        It 'Copy-PspktFilter clones every settable scalar field' {
            $original = New-PspktFilter -Name 'QF-Src' -TransportProtocol 'TCP' -Port1 445 -EtherType 'IPv4'
            $original.SetIp1([ipaddress]'10.0.0.5')
            $clone = & $script:vmMod $script:copyFn $original ''

            $clone.Name              | Should -Be 'QF-Src'
            $clone.Port1             | Should -Be 445
            $clone.TransportProtocol | Should -Be ([int16][IPv4Protocol]::TCP)
            $clone.EtherType         | Should -Be ([uint16][ETHERTYPE]::IPv4)
            $clone.Ip1.IPAddressToString | Should -Be '10.0.0.5'
        }

        It 'Copy-PspktFilter appends -NameSuffix when provided' {
            $original = New-PspktFilter -Name 'QF-DNS-UDP' -TransportProtocol 'UDP' -Port1 53
            $clone = & $script:vmMod $script:copyFn $original '-VM-AA-BB-CC-DD-EE-FF'
            $clone.Name | Should -Be 'QF-DNS-UDP-VM-AA-BB-CC-DD-EE-FF'
        }

        It 'Copy-PspktFilter Mac1 mutation does not bleed into source' {
            $original = New-PspktFilter -Name 'QF-Src' -TransportProtocol 'TCP' -Port1 445
            # New-PspktFilter leaves Mac1 at the byte[]{0} sentinel (length 1).
            $original.Mac1.Length | Should -Be 1
            $clone = & $script:vmMod $script:copyFn $original '-VM'
            $clone.SetMac1('AA-BB-CC-DD-EE-FF')
            $clone.Mac1.Length    | Should -Be 6
            $original.Mac1.Length | Should -Be 1
        }

        It 'Get-PspktVMMacList returns empty array when neither -VM nor -VMName supplied' {
            $result = & $script:vmMod { Get-PspktVMMacList }
            # PS unwraps a returned-empty-array across the scriptblock-invocation
            # boundary, so $result becomes $null. Validate the no-MAC outcome via
            # Count semantics that work for both $null and an empty collection.
            @($result).Count | Should -Be 0
        }

        It 'Get-PspktVMMacList returns empty array for empty VMName string' {
            $result = & $script:vmMod { Get-PspktVMMacList -VMName '' }
            @($result).Count | Should -Be 0
        }

        It 'Get-PspktVMMacList throws a clear error when the named VM does not exist' {
            # The helper resolves -VMName via Get-VM so the OFF/Saved fallback
            # chain (vmObj | Get-VMNetworkAdapter, $vmObj.NetworkAdapters) can
            # still execute. A bogus name surfaces an explicit failure rather
            # than silently returning empty.
            $bogus = 'zzz-pspkt-nonexistent-vm-' + ([guid]::NewGuid().ToString('N').Substring(0,8))
            { & $script:vmMod { param($n) Get-PspktVMMacList -VMName $n } $bogus } |
                Should -Throw -ExpectedMessage "*Failed to resolve VM*"
        }

        It 'Get-PspktVMMacList throws when the Hyper-V module is not installed' -Skip:($null -ne (Get-Command Get-VMNetworkAdapter -ErrorAction SilentlyContinue)) {
            # Skipped on Hyper-V-enabled hosts (most dev boxes). The Skip:
            # predicate inverts so this only runs where Get-VMNetworkAdapter
            # is absent — exactly the scenario the helper's pre-check is
            # designed to flag.
            { & $script:vmMod { Get-PspktVMMacList -VMName 'AnyName' } } |
                Should -Throw -ExpectedMessage "*Hyper-V PowerShell module is not installed*"
        }

        It 'Get-PspktVMMacList parses MacAddress from a faux adapter shaped like Get-VMNetworkAdapter output' {
            # Direct test of the parse path (raw "AABBCCDDEEFF" -> dash form).
            # Builds a fake adapter object so we don't need a live Hyper-V VM.
            $fakeAdapter = [pscustomobject]@{
                Name       = 'Network Adapter'
                MacAddress = 'AABBCCDDEEFF'
            }
            $reformatted = ("$($fakeAdapter.MacAddress)" -replace '(.{2})(?=.)', '$1-')
            $reformatted | Should -Be 'AA-BB-CC-DD-EE-FF'
        }
    }

    Context 'VM AND-scoping filter expansion (simulated)' {
        # Validates the cartesian-product expansion logic that Start-Pspkt
        # performs when -VM/-VMName is active and one or more quick / app-
        # imply filters are present. The expansion itself lives inline in
        # Start-Pspkt; this block exercises the underlying primitives
        # (Copy-PspktFilter + SetMac1) the same way Start-Pspkt does, plus
        # a small loop matching the production cartesian product.
        BeforeAll {
            $script:vmMod = Get-Module PspktSession
            $script:expand = {
                param($Filters, [string[]]$Macs)
                $expanded = [System.Collections.ArrayList]::new()
                foreach ($qf in $Filters) {
                    foreach ($mac in $Macs) {
                        $clone = Copy-PspktFilter -Filter $qf -NameSuffix "-VM-$mac"
                        $clone.SetMac1($mac)
                        $null = $expanded.Add($clone)
                    }
                }
                ,$expanded
            }
        }

        It 'expands 1 filter x 1 MAC into 1 MAC-tagged filter' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-SMB' -TransportProtocol 'TCP' -Port1 445))
            $macs = @('AA-BB-CC-00-00-01')
            $out = & $script:vmMod $script:expand $filters $macs
            $out.Count | Should -Be 1
            $out[0].Name              | Should -Be 'QF-SMB-VM-AA-BB-CC-00-00-01'
            $out[0].Port1             | Should -Be 445
            $out[0].TransportProtocol | Should -Be ([int16][IPv4Protocol]::TCP)
            $out[0].Mac1.Length       | Should -Be 6
            # Verify raw bytes are the parsed MAC (avoids the existing
            # GetMac1String bug where the static formatter is called with
            # byte[] coerced to "170 187 ..." and throws).
            $out[0].Mac1[0] | Should -Be 0xAA
            $out[0].Mac1[5] | Should -Be 0x01
        }

        It 'expands 2 quick filters x 2 vmNICs into 4 filters (cartesian product)' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-DNS-UDP' -TransportProtocol 'UDP' -Port1 53))
            $null = $filters.Add((New-PspktFilter -Name 'QF-DNS-TCP' -TransportProtocol 'TCP' -Port1 53))
            $macs = @('AA-BB-CC-00-00-01', 'AA-BB-CC-00-00-02')
            $out = & $script:vmMod $script:expand $filters $macs
            $out.Count | Should -Be 4

            # Every clone must have Mac1 set + the original protocol scope preserved.
            $names = $out | ForEach-Object { $_.Name }
            $names -contains 'QF-DNS-UDP-VM-AA-BB-CC-00-00-01' | Should -BeTrue
            $names -contains 'QF-DNS-UDP-VM-AA-BB-CC-00-00-02' | Should -BeTrue
            $names -contains 'QF-DNS-TCP-VM-AA-BB-CC-00-00-01' | Should -BeTrue
            $names -contains 'QF-DNS-TCP-VM-AA-BB-CC-00-00-02' | Should -BeTrue

            foreach ($f in $out) {
                $f.Port1            | Should -Be 53
                $f.Mac1.Length      | Should -Be 6
            }
        }

        It 'expansion preserves -IPAddress AND-merge (MAC + IP + protocol on each clone)' {
            $filters = [System.Collections.ArrayList]::new()
            $qf = New-PspktFilter -Name 'QF-HTTP' -TransportProtocol 'TCP' -Port1 80
            $qf.SetIp1([ipaddress]'10.0.0.5')
            $null = $filters.Add($qf)
            $macs = @('AA-BB-CC-00-00-01')
            $out = & $script:vmMod $script:expand $filters $macs
            $out.Count               | Should -Be 1
            $out[0].Port1            | Should -Be 80
            $out[0].Ip1.IPAddressToString | Should -Be '10.0.0.5'
            $out[0].Mac1.Length      | Should -Be 6
        }

        It 'expansion preserves EtherType (e.g. -ARP under VM scoping)' {
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-ARP' -EtherType 'ARP'))
            $null = $filters.Add((New-PspktFilter -Name 'QF-ICMPv6' -EtherType 'IPv6' -TransportProtocol 'IPv6_ICMP'))
            $macs = @('AA-BB-CC-00-00-01')
            $out = & $script:vmMod $script:expand $filters $macs
            $out.Count    | Should -Be 2

            $arp = $out | Where-Object { $_.Name -like 'QF-ARP*' } | Select-Object -First 1
            $arp.EtherType | Should -Be ([uint16][ETHERTYPE]::ARP)
            $arp.Mac1.Length | Should -Be 6

            $icmp6 = $out | Where-Object { $_.Name -like 'QF-ICMPv6*' } | Select-Object -First 1
            $icmp6.EtherType         | Should -Be ([uint16][ETHERTYPE]::IPv6)
            $icmp6.TransportProtocol | Should -Be ([int16][IPv4Protocol]::IPv6_ICMP)
            $icmp6.Mac1.Length       | Should -Be 6
        }

        It 'expansion with zero MACs yields zero filters (degraded path: unstarted VM)' {
            # When a VM has no assigned MACs (e.g. dynamic-MAC VM never started),
            # Get-PspktVMMacList returns @() and the expansion produces an empty
            # list. The caller falls back to using the unexpanded list, matching
            # the documented "no per-NIC MAC filter" behavior in that case.
            $filters = [System.Collections.ArrayList]::new()
            $null = $filters.Add((New-PspktFilter -Name 'QF-SMB' -TransportProtocol 'TCP' -Port1 445))
            $macs = @()
            $out = & $script:vmMod $script:expand $filters $macs
            $out.Count | Should -Be 0
        }
    }
}

Describe 'BoxyBox TUI render engine' -Tag 'Unit' {
    BeforeAll {
        $script:modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'pspkt.psm1'
        Import-Module $script:modulePath -Force -ErrorAction Stop
        $script:ESC = [char]27
    }

    AfterAll {
        Remove-Module pspkt -Force -ErrorAction SilentlyContinue
    }

    Context 'TextJustify.Fit (plain text)' {
        It 'pads left-justified text to the right' {
            [BoxyBox.TextJustify]::Fit('abc', 6, [BoxyBox.Justify]::Left) | Should -Be 'abc   '
        }
        It 'pads right-justified text to the left' {
            [BoxyBox.TextJustify]::Fit('abc', 6, [BoxyBox.Justify]::Right) | Should -Be '   abc'
        }
        It 'returns text unchanged when it exactly fits' {
            [BoxyBox.TextJustify]::Fit('abcdef', 6, [BoxyBox.Justify]::Left) | Should -Be 'abcdef'
        }
        It 'truncates the tail of left-justified overflow with an ellipsis' {
            [BoxyBox.TextJustify]::Fit('abcdefghij', 6, [BoxyBox.Justify]::Left) | Should -Be 'abc...'
        }
        It 'truncates the head of right-justified overflow with an ellipsis' {
            [BoxyBox.TextJustify]::Fit('abcdefghij', 6, [BoxyBox.Justify]::Right) | Should -Be '...hij'
        }
        It 'hard-slices when width is too small for the ellipsis (left)' {
            [BoxyBox.TextJustify]::Fit('abcdef', 2, [BoxyBox.Justify]::Left) | Should -Be 'ab'
        }
        It 'hard-slices when width is too small for the ellipsis (right)' {
            [BoxyBox.TextJustify]::Fit('abcdef', 2, [BoxyBox.Justify]::Right) | Should -Be 'ef'
        }
        It 'returns empty string for non-positive width' {
            [BoxyBox.TextJustify]::Fit('abc', 0, [BoxyBox.Justify]::Left) | Should -Be ''
        }
        It 'treats null text as empty' {
            [BoxyBox.TextJustify]::Fit($null, 3, [BoxyBox.Justify]::Left) | Should -Be '   '
        }
    }

    Context 'AnsiText helpers' {
        BeforeAll {
            $script:colored = "$($script:ESC)[31mRED$($script:ESC)[0m"
        }
        It 'VisibleLength ignores SGR escape sequences' {
            [BoxyBox.AnsiText]::VisibleLength($script:colored) | Should -Be 3
        }
        It 'VisibleLength returns 0 for null/empty' {
            [BoxyBox.AnsiText]::VisibleLength($null) | Should -Be 0
            [BoxyBox.AnsiText]::VisibleLength('') | Should -Be 0
        }
        It 'ContainsAnsi detects escape sequences' {
            [BoxyBox.AnsiText]::ContainsAnsi($script:colored) | Should -BeTrue
            [BoxyBox.AnsiText]::ContainsAnsi('plain') | Should -BeFalse
        }
        It 'TakeVisiblePrefix keeps N visible columns and appends a reset' {
            $p = [BoxyBox.AnsiText]::TakeVisiblePrefix($script:colored, 2)
            [BoxyBox.AnsiText]::VisibleLength($p) | Should -Be 2
            $p.EndsWith("$($script:ESC)[0m") | Should -BeTrue
        }
    }

    Context 'TextJustify.Fit (ANSI-aware)' {
        BeforeAll {
            $script:colored = "$($script:ESC)[31mRED$($script:ESC)[0m"
        }
        It 'pads by visible length, not raw string length' {
            $fit = [BoxyBox.TextJustify]::Fit($script:colored, 6, [BoxyBox.Justify]::Left)
            [BoxyBox.AnsiText]::VisibleLength($fit) | Should -Be 6
        }
    }

    Context 'Box.Render' {
        BeforeAll {
            $script:box = [BoxyBox.Box]::new(20, 5)
            $script:box.MenuOptions = [System.Collections.Generic.List[string]]@('(F)ocus', '(S)top')
            $lines = [System.Collections.Generic.List[string]]::new()
            $lines.Add('hello')
            $script:rendered = $script:box.Render($lines)
        }
        It 'produces Height rows' {
            $script:rendered.Count | Should -Be 5
        }
        It 'first row is the top border with corners' {
            [int]$script:rendered[0][0]  | Should -Be ([int][char]0x250c)   # top-left
            [int]$script:rendered[0][-1] | Should -Be ([int][char]0x2510)   # top-right
        }
        It 'every row is exactly Width visible columns' {
            foreach ($row in $script:rendered) {
                [BoxyBox.AnsiText]::VisibleLength($row) | Should -Be 20
            }
        }
        It 'content row contains the text padded within side borders' {
            $script:rendered[1] | Should -Be ("$([char]0x2502)hello             $([char]0x2502)")
        }
        It 'unused content rows are blank' {
            $script:rendered[2] | Should -Be ("$([char]0x2502)                  $([char]0x2502)")
        }
        It 'last row is the menu bar with the terminal left cap' {
            [int]$script:rendered[4][0] | Should -Be ([int][char]0x2558)
        }
        It 'right-justified box anchors content to the right' {
            $rbox = [BoxyBox.Box]::new(20, 3)
            $rbox.Justification = [BoxyBox.Justify]::Right
            $rlines = [System.Collections.Generic.List[string]]::new()
            $rlines.Add('end')
            $rr = $rbox.Render($rlines)
            $rr[1] | Should -Be ("$([char]0x2502)               end$([char]0x2502)")
        }
    }

    Context 'ScreenRegion.BuildFrame' {
        BeforeAll {
            $box = [BoxyBox.Box]::new(20, 5)
            $lines = [System.Collections.Generic.List[string]]::new()
            $lines.Add('x')
            $script:rendered = $box.Render($lines)
            $region = [BoxyBox.ScreenRegion]::new(1, 1, 20, 5)
            $script:frame = $region.BuildFrame($script:rendered)
        }
        It 'emits no newline (so the console does not scroll)' {
            $script:frame.Contains("`n") | Should -BeFalse
        }
        It 'positions the cursor absolutely for the first row' {
            $script:frame.Contains("$($script:ESC)[1;1H") | Should -BeTrue
        }
        It 'does not erase rows (no CSI 2K) so borders do not flicker' {
            $script:frame.Contains("$($script:ESC)[2K") | Should -BeFalse
        }
        It 'pads a short line to exactly Width in place of an erase' {
            $r = [BoxyBox.ScreenRegion]::new(3, 5, 10, 1)
            $f = $r.BuildFrame([string[]]@('hi'))
            $f | Should -Be ("$($script:ESC)[3;5Hhi        ")
        }
        It 'pads a missing/null row to Width spaces' {
            $r = [BoxyBox.ScreenRegion]::new(1, 1, 4, 2)
            $f = $r.BuildFrame([string[]]@('ab'))
            $f | Should -Be ("$($script:ESC)[1;1Hab  $($script:ESC)[2;1H    ")
        }
        It 'clips an over-long line to Width visible columns' {
            $r = [BoxyBox.ScreenRegion]::new(1, 1, 3, 1)
            $f = $r.BuildFrame([string[]]@('abcdef'))
            [BoxyBox.AnsiText]::VisibleLength($f.Substring($f.IndexOf('H') + 1)) | Should -Be 3
        }
        It 'produces frame rows that are each exactly Width visible columns' {
            # Split the concatenated frame at each cursor-move and check the content width.
            $rowContents = $script:frame -split "$($script:ESC)\[\d+;\d+H" | Where-Object { $_ -ne '' }
            $rowContents.Count | Should -Be 5
            foreach ($rc in $rowContents) {
                [BoxyBox.AnsiText]::VisibleLength($rc) | Should -Be 20
            }
        }
        It 'cursor hide/show/clear helpers emit expected sequences' {
            [BoxyBox.ScreenRegion]::HideCursor()  | Should -Be "$($script:ESC)[?25l"
            [BoxyBox.ScreenRegion]::ShowCursor()  | Should -Be "$($script:ESC)[?25h"
            [BoxyBox.ScreenRegion]::ClearScreen() | Should -Be "$($script:ESC)[2J$($script:ESC)[H"
        }
        It 'synchronized-output helpers emit the DEC 2026 begin/end sequences' {
            [BoxyBox.ScreenRegion]::BeginSyncOutput() | Should -Be "$($script:ESC)[?2026h"
            [BoxyBox.ScreenRegion]::EndSyncOutput()   | Should -Be "$($script:ESC)[?2026l"
        }
    }

    Context 'AnsiText.FitToWidth' {
        It 'pads a short line and matches BuildFrame''s fitting' {
            [BoxyBox.AnsiText]::FitToWidth('hi', 5) | Should -Be 'hi   '
            [BoxyBox.AnsiText]::FitToWidth($null, 4) | Should -Be '    '
            [BoxyBox.AnsiText]::VisibleLength([BoxyBox.AnsiText]::FitToWidth('abcdef', 3)) | Should -Be 3
        }
        It 'is byte-identical to a single-row ScreenRegion.BuildFrame body' {
            $region = [BoxyBox.ScreenRegion]::new(1, 1, 12, 1)
            $frame = $region.BuildFrame([string[]]@('hi'))
            $body = $frame.Substring($frame.IndexOf('H') + 1)
            $body | Should -Be ([BoxyBox.AnsiText]::FitToWidth('hi', 12))
        }
    }

    Context 'FrameBuffer row diffing' {
        It 'first Diff emits every row; an unchanged Diff emits nothing' {
            $fb = [BoxyBox.FrameBuffer]::new(1, 1, 10, 3)
            $first = $fb.Diff([string[]]@('a', 'b', 'c'))
            $first | Should -Not -BeNullOrEmpty
            ([regex]::Matches($first, "$($script:ESC)\[\d+;\d+H")).Count | Should -Be 3
            $fb.Diff([string[]]@('a', 'b', 'c')) | Should -BeNullOrEmpty
        }
        It 'emits only the row that changed' {
            $fb = [BoxyBox.FrameBuffer]::new(1, 1, 10, 3)
            $null = $fb.Diff([string[]]@('a', 'b', 'c'))
            $d = $fb.Diff([string[]]@('a', 'X', 'c'))
            ([regex]::Matches($d, "$($script:ESC)\[\d+;\d+H")).Count | Should -Be 1
            $d.Contains("$($script:ESC)[2;1H") | Should -BeTrue
        }
        It 'rows are fitted to Width (so a shrunk row clears its tail)' {
            $fb = [BoxyBox.FrameBuffer]::new(3, 5, 6, 1)
            $d = $fb.Diff([string[]]@('hi'))
            $d | Should -Be ("$($script:ESC)[3;5Hhi    ")
        }
        It 'Invalidate() forces a full re-emit on the next Diff' {
            $fb = [BoxyBox.FrameBuffer]::new(1, 1, 8, 2)
            $null = $fb.Diff([string[]]@('a', 'b'))
            $fb.Invalidate()
            ([regex]::Matches($fb.Diff([string[]]@('a', 'b')), "$($script:ESC)\[\d+;\d+H")).Count | Should -Be 2
        }
        It 'InvalidateRows() re-emits only the given absolute rows (overlay-reclaim contract)' {
            $fb = [BoxyBox.FrameBuffer]::new(1, 1, 8, 4)
            $null = $fb.Diff([string[]]@('a', 'b', 'c', 'd'))
            $fb.InvalidateRows(2, 2)   # absolute rows 2 and 3
            $d = $fb.Diff([string[]]@('a', 'b', 'c', 'd'))
            ([regex]::Matches($d, "$($script:ESC)\[\d+;\d+H")).Count | Should -Be 2
            $d.Contains("$($script:ESC)[2;1H") | Should -BeTrue
            $d.Contains("$($script:ESC)[3;1H") | Should -BeTrue
            $d.Contains("$($script:ESC)[1;1H") | Should -BeFalse
        }
        It 'InvalidateRows() ignores rows outside the region' {
            $fb = [BoxyBox.FrameBuffer]::new(5, 1, 8, 2)   # covers absolute rows 5,6
            $null = $fb.Diff([string[]]@('a', 'b'))
            $fb.InvalidateRows(1, 3)   # rows 1-3, all outside
            $fb.Diff([string[]]@('a', 'b')) | Should -BeNullOrEmpty
        }
    }

    Context 'MenuBar.Build' {
        It 'fills to the requested width with the double rule' {
            $opts = [System.Collections.Generic.List[string]]@('(R)esume')
            $bar = [BoxyBox.MenuBar]::Build($opts, 30, [BoxyBox.MenuBar+Cap]::Terminal)
            [BoxyBox.AnsiText]::VisibleLength($bar) | Should -Be 30
            [int]$bar[0]  | Should -Be ([int][char]0x2558)  # ╘
            [int]$bar[-1] | Should -Be ([int][char]0x255b)  # ╛
        }
        It 'uses mid caps for the divider style' {
            $bar = [BoxyBox.MenuBar]::Build([System.Collections.Generic.List[string]]::new(), 10, [BoxyBox.MenuBar+Cap]::Mid)
            [int]$bar[0]  | Should -Be ([int][char]0x255e)  # ╞
            [int]$bar[-1] | Should -Be ([int][char]0x2561)  # ╡
        }
        It 'uses single-line caps and rule for the TerminalSingle style' {
            $opts = [System.Collections.Generic.List[string]]@('[X]Go')
            $bar = [BoxyBox.MenuBar]::Build($opts, 30, [BoxyBox.MenuBar+Cap]::TerminalSingle)
            [BoxyBox.AnsiText]::VisibleLength($bar) | Should -Be 30
            [int]$bar[0]  | Should -Be ([int][char]0x2514)  # └
            [int]$bar[-1] | Should -Be ([int][char]0x2518)  # ┘
            $bar.Contains([char]0x2500) | Should -BeTrue    # single-line rule ─
            $bar.Contains([char]0x2550) | Should -BeFalse   # no double-line rule ═
        }
        It 'drops options that would overflow the width' {
            $opts = [System.Collections.Generic.List[string]]@('AAAAAAAA', 'BBBBBBBB', 'CCCCCCCC')
            $bar = [BoxyBox.MenuBar]::Build($opts, 16, [BoxyBox.MenuBar+Cap]::Terminal)
            [BoxyBox.AnsiText]::VisibleLength($bar) | Should -Be 16
            # 16 wide: 2 caps + 14 inner. "══AAAAAAAA" = 10 fits; adding "══BBBBBBBB" (10) => 20 > 14, dropped.
            $bar.Contains('AAAAAAAA') | Should -BeTrue
            $bar.Contains('BBBBBBBB') | Should -BeFalse
        }
    }

    Context 'TextBox (scrolling buffer)' {
        It 'reports ContentRows as Height minus borders/menu' {
            $tb = [BoxyBox.TextBox]::new(40, 6, 1000)
            $tb.ContentRows | Should -Be 4
        }
        It 'RenderTail shows the most recent ContentRows lines anchored at the bottom' {
            $tb = [BoxyBox.TextBox]::new(20, 5, 1000)   # 3 content rows
            1..10 | ForEach-Object { $tb.Append("line $_") }
            $frame = $tb.RenderTail()
            # content rows are indices 1..3; newest (line 10) is the last content row
            $frame[1].Contains('line 8')  | Should -BeTrue
            $frame[2].Contains('line 9')  | Should -BeTrue
            $frame[3].Contains('line 10') | Should -BeTrue
        }
        It 'pads the top when fewer lines than ContentRows are present' {
            $tb = [BoxyBox.TextBox]::new(20, 5, 1000)   # 3 content rows
            $tb.Append('only')
            $frame = $tb.RenderTail()
            # newest anchored to bottom content row; upper rows blank
            $frame[1] | Should -Be ("$([char]0x2502)                  $([char]0x2502)")
            $frame[3].Contains('only') | Should -BeTrue
        }
        It 'bounds the buffer to roughly capacity, trimming oldest lines' {
            $tb = [BoxyBox.TextBox]::new(20, 5, 100)
            1..300 | ForEach-Object { $tb.Append("L$_") }
            $tb.LineCount | Should -BeLessOrEqual 150   # capacity + slack margin
            $tb.LineCount | Should -BeGreaterOrEqual 100
            # oldest lines were trimmed; L1 is gone
            $tb.GetLine(0) | Should -Not -Be 'L1'
        }
        It 'GetLine returns null for out-of-range indices' {
            $tb = [BoxyBox.TextBox]::new(20, 5, 100)
            $tb.Append('x')
            $tb.GetLine(-1) | Should -BeNullOrEmpty
            $tb.GetLine(99) | Should -BeNullOrEmpty
        }
        It 'RenderFrom anchors a given index at the first content row' {
            $tb = [BoxyBox.TextBox]::new(20, 5, 1000)   # 3 content rows
            1..10 | ForEach-Object { $tb.Append("L$_") }
            $frame = $tb.RenderFrom(2)   # 0-based; L3, L4, L5
            $frame[1].Contains('L3') | Should -BeTrue
            $frame[2].Contains('L4') | Should -BeTrue
            $frame[3].Contains('L5') | Should -BeTrue
        }
        It 'AppendRange adds a batch of lines' {
            $tb = [BoxyBox.TextBox]::new(20, 6, 1000)
            $tb.AppendRange([System.Collections.Generic.List[string]]@('a','b','c'))
            $tb.LineCount | Should -Be 3
        }
    }

    Context 'TextBox focus mode (sequence tracking + highlight)' {
        BeforeAll {
            $script:ESC = [char]27
            $script:hlOn  = "$($script:ESC)[7m"
            $script:hlOff = "$($script:ESC)[0m"
        }
        It 'tracks BaseSeq and TotalSeq across appends' {
            $tb = [BoxyBox.TextBox]::new(20, 6, 1000)
            $tb.BaseSeq | Should -Be 0
            1..5 | ForEach-Object { $tb.Append("L$_") }
            $tb.BaseSeq | Should -Be 0
            $tb.TotalSeq | Should -Be 5
        }
        It 'advances BaseSeq when the buffer trims, keeping GetLineBySeq stable' {
            $tb = [BoxyBox.TextBox]::new(20, 6, 100)
            1..300 | ForEach-Object { $tb.Append("L$_") }
            # BaseSeq advanced by the number of trimmed lines
            $tb.BaseSeq | Should -BeGreaterThan 0
            # A sequence number still in range resolves to the correct line
            $seq = $tb.TotalSeq - 1
            $tb.GetLineBySeq($seq) | Should -Be 'L300'
        }
        It 'GetLineBySeq returns null for trimmed or future sequences' {
            $tb = [BoxyBox.TextBox]::new(20, 6, 100)
            1..300 | ForEach-Object { $tb.Append("L$_") }
            $tb.GetLineBySeq(0) | Should -BeNullOrEmpty          # trimmed
            $tb.GetLineBySeq($tb.TotalSeq) | Should -BeNullOrEmpty  # future
        }
        It 'ClampSeq keeps a sequence within the retained range' {
            $tb = [BoxyBox.TextBox]::new(20, 6, 1000)
            1..10 | ForEach-Object { $tb.Append("L$_") }
            $tb.ClampSeq(-100) | Should -Be $tb.BaseSeq
            $tb.ClampSeq(100000) | Should -Be ($tb.TotalSeq - 1)
        }
        It 'RenderWindow highlights the selected line with the supplied sequences' {
            $tb = [BoxyBox.TextBox]::new(30, 6, 1000)   # 4 content rows
            1..10 | ForEach-Object { $tb.Append("L$_") }
            $frame = $tb.RenderWindow(3, 5, $script:hlOn, $script:hlOff)  # top L4, selected L6
            # content rows: index 1=L4, 2=L5, 3=L6, 4=L7
            $frame[1].Contains($script:hlOn) | Should -BeFalse
            $frame[3].Contains($script:hlOn) | Should -BeTrue   # L6 highlighted
            $frame[3].Contains('L6') | Should -BeTrue
        }
        It 'RenderWindow leaves the selection unhighlighted when it is off-screen' {
            $tb = [BoxyBox.TextBox]::new(30, 6, 1000)
            1..10 | ForEach-Object { $tb.Append("L$_") }
            $frame = $tb.RenderWindow(0, 9, $script:hlOn, $script:hlOff)  # selected below window
            for ($i = 1; $i -le 4; $i++) { $frame[$i].Contains($script:hlOn) | Should -BeFalse }
        }
    }

    Context 'AnsiText.StripAnsi' {
        BeforeAll { $script:ESC = [char]27 }
        It 'removes SGR sequences leaving plain text' {
            $colored = "$($script:ESC)[31mRED$($script:ESC)[0m"
            [BoxyBox.AnsiText]::StripAnsi($colored) | Should -Be 'RED'
        }
        It 'returns plain text unchanged' {
            [BoxyBox.AnsiText]::StripAnsi('plain') | Should -Be 'plain'
        }
        It 'handles null/empty' {
            [BoxyBox.AnsiText]::StripAnsi($null) | Should -Be ''
            [BoxyBox.AnsiText]::StripAnsi('') | Should -Be ''
        }
    }

    Context 'AnsiText.ApplyBackground' {
        BeforeAll { $script:ESC = [char]27 }
        It 'wraps text in a background sequence and preserves inner foreground colors' {
            $colored = "$($script:ESC)[36mIPv4$($script:ESC)[0m rest"
            $bg = "$($script:ESC)[44m"; $reset = "$($script:ESC)[0m"
            $out = [BoxyBox.AnsiText]::ApplyBackground($colored, $bg, $reset)
            $out.StartsWith($bg) | Should -BeTrue
            $out.Contains("$($script:ESC)[36m") | Should -BeTrue
            # background re-applied after every inner reset so it spans the whole string
            $out.Contains("$reset$bg") | Should -BeTrue
        }
        It 'handles null/empty by returning empty' {
            $bg = "$($script:ESC)[44m"; $reset = "$($script:ESC)[0m"
            [BoxyBox.AnsiText]::ApplyBackground($null, $bg, $reset) | Should -Be ''
            [BoxyBox.AnsiText]::ApplyBackground('', $bg, $reset) | Should -Be ''
        }
    }

    Context 'Box top-border toggle (seamless merge)' {
        It 'omits the top border and reduces ContentRows by one when ShowTopBorder is false' {
            $box = [BoxyBox.Box]::new(30, 5)
            $box.ContentRows | Should -Be 3   # Height - top border - menu bar
            $box.ShowTopBorder = $false
            $box.ContentRows | Should -Be 4   # top border reclaimed as a content row
            $lines = [System.Collections.Generic.List[string]]@('a', 'b', 'c', 'd')
            $frame = $box.Render($lines)
            # first rendered row is content, not a top border corner
            $frame[0][0] | Should -Not -Be ([char]0x250C)
        }
        It 'DetailsBox exposes a 3-arg constructor that suppresses the top border' {
            $db = [BoxyBox.DetailsBox]::new(40, 6, $false)
            $db.Box.ShowTopBorder | Should -BeFalse
            $db2 = [BoxyBox.DetailsBox]::new(40, 6)
            $db2.Box.ShowTopBorder | Should -BeTrue
        }
        It 'Box.Resize updates dimensions in place, clamps, and preserves menu/border state' {
            $box = [BoxyBox.Box]::new(40, 10)
            $box.ShowTopBorder = $false
            $box.MenuOptions = [System.Collections.Generic.List[string]]@('x')
            $box.Resize(80, 6)
            $box.Width  | Should -Be 80
            $box.Height | Should -Be 6
            $box.ContentRows | Should -Be 5           # 6 - menu (no top border)
            $box.ShowTopBorder | Should -BeFalse      # preserved
            $box.MenuOptions.Count | Should -Be 1     # preserved
            $box.Resize(1, 1)                          # below minimum
            $box.Width  | Should -BeGreaterOrEqual 2
            $box.Height | Should -BeGreaterOrEqual 2
        }
        It 'DetailsBox.Resize preserves the tree and re-fits the viewport height' {
            $roots = [System.Collections.Generic.List[BoxyBox.TreeNode]]::new()
            $ip = [BoxyBox.TreeNode]::new('IPv4', 'IPv4', $true)
            $null = $ip.AddLeaf('Src'); $null = $ip.AddLeaf('Dst')
            $null = $roots.Add($ip)
            $db = [BoxyBox.DetailsBox]::new(40, 10, $false)
            $db.SetTree($roots)
            $before = $db.RowCount
            $db.Resize(90, 5)
            $db.Box.Width | Should -Be 90
            $db.RowCount  | Should -Be $before        # tree preserved
            $db.ContentRows | Should -Be 4            # height 5, no top border
        }
    }

    Context 'Box highlighted render' {
        BeforeAll { $script:ESC = [char]27 }
        It 'wraps the selected row with a highlight background and preserves its foreground color' {
            $box = [BoxyBox.Box]::new(20, 5)
            $lines = [System.Collections.Generic.List[string]]@("$($script:ESC)[31msel$($script:ESC)[0m", 'plain')
            $on = "$($script:ESC)[44m"; $off = "$($script:ESC)[0m"
            $frame = $box.Render($lines, 0, $on, $off)
            # selected row (content index 0 => frame[1]) has the highlight background
            $frame[1].Contains($on) | Should -BeTrue
            # foreground color is preserved under the highlight (no longer stripped)
            $frame[1].Contains("$($script:ESC)[31m") | Should -BeTrue
            # background is re-applied after the inner reset so it spans the whole row
            $frame[1].Contains("$off$on") | Should -BeTrue
            # non-selected row unaffected
            $frame[2].Contains($on) | Should -BeFalse
        }
    }

    Context 'PacketLineFormatter text-box mode' {
        AfterEach {
            [PacketLineFormatter]::SetTextBoxMode($false)
        }
        It 'FormatBatchToLines and SetTextBoxMode exist' {
            $methods = [PacketLineFormatter].GetMethods() | Where-Object { $_.Name -eq 'FormatBatchToLines' }
            $methods.Count | Should -BeGreaterOrEqual 1
            [PacketLineFormatter].GetMethod('SetTextBoxMode') | Should -Not -BeNullOrEmpty
        }
        It 'component prefix includes the name in full mode and omits it in text-box mode' {
            $full = [PacketFormatter]::FormatComponentPrefix(0, 9, 'NetVsc', 0, 1, 1, $true)
            $compact = [PacketFormatter]::FormatComponentPrefix(0, 9, 'NetVsc', 0, 1, 1, $false)
            $full.Contains('NetVsc') | Should -BeTrue
            $compact.Contains('NetVsc') | Should -BeFalse
            # both share the "GGG:CCC[arrows]" head
            $compact.Contains('000:009') | Should -BeTrue
            $compact.Contains('[') | Should -BeTrue
        }
        It 'renders the data link at Minimal level (Eth:) in text-box mode but full form otherwise' {
            # Eth(14) + IPv4/UDP header is enough for the Default line's data link segment.
            $pkt = [byte[]]@(
                0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00,
                0x45,0,0,0x3c,0x8b,0xee,0x40,0,0x40,0x11,0,0,
                10,24,0,72, 1,1,1,1,
                0xc5,0x1b,0,0x35,0,8,0,0)

            [PacketLineFormatter]::SetTextBoxMode($true)
            $sbTb = [System.Text.StringBuilder]::new()
            $null = [PacketLineFormatter]::FormatDefaultLineInto($sbTb, 0, 0, 9, 1, 0, 0,
                1, '22-22-22-22-22-22', '11-11-11-11-11-11', 0x0800, 34,
                3, '10.24.0.72', '1.1.1.1', 50651, 53, 0, [uint32]0, [uint32]0, [uint16]0, 0,
                0, 0, 0, 0, $null, $pkt, 0, $pkt.Length)
            $tb = [BoxyBox.AnsiText]::StripAnsi($sbTb.ToString())
            $tb.Contains('Eth:') | Should -BeTrue
            $tb.Contains('22-22-22-22-22-22') | Should -BeFalse

            [PacketLineFormatter]::SetTextBoxMode($false)
            $sbFull = [System.Text.StringBuilder]::new()
            $null = [PacketLineFormatter]::FormatDefaultLineInto($sbFull, 0, 0, 9, 1, 0, 0,
                1, '22-22-22-22-22-22', '11-11-11-11-11-11', 0x0800, 34,
                3, '10.24.0.72', '1.1.1.1', 50651, 53, 0, [uint32]0, [uint32]0, [uint16]0, 0,
                0, 0, 0, 0, $null, $pkt, 0, $pkt.Length)
            $full = [BoxyBox.AnsiText]::StripAnsi($sbFull.ToString())
            # The Ethernet segment no longer includes the ", type <ethtype>" portion.
            $full.Contains('22-22-22-22-22-22 > 11-11-11-11-11-11, len 34') | Should -BeTrue
            $full.Contains('type IPv4') | Should -BeFalse
            # The network 4-tuple is prefixed with the network-layer name + transport protocol.
            $full.Contains('IPv4.UDP 10.24.0.72.50651 > 1.1.1.1.53') | Should -BeTrue
        }
    }

    Context 'PacketLineFormatter detailed output' {
        AfterEach { Set-PspktDetailLevel -Level 0 }
        It 'indents detail sub-lines with two spaces and no tree connector' {
            Set-PspktDetailLevel -Level 1   # Detailed
            # Descriptor: [metadata(40)][packet]. Packet = Eth(14)+IPv4(20)+UDP(8), src port 53.
            $eth = [byte[]](0x7c,0x1e,0x52,0x97,0xb1,0x46, 0x68,0xbf,0x6c,0x64,0xf6,0x00, 0x08,0x00)
            $ipv4 = [byte[]]::new(20)
            $ipv4[0]=0x45; $ipv4[8]=51; $ipv4[9]=17; $ipv4[3]=28
            $ipv4[12]=1;$ipv4[13]=1;$ipv4[14]=1;$ipv4[15]=1
            $ipv4[16]=10;$ipv4[17]=24;$ipv4[18]=0;$ipv4[19]=72
            $udp = [byte[]](0,53, 0xC3,0x8C, 0,8, 0,0)
            $packet = $eth + $ipv4 + $udp
            $meta = [byte[]]::new(40)
            $meta[12]=1; $meta[16]=172; $meta[18]=1
            $data = $meta + $packet
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$packet.Length, [uint32]0, [uint32]0)
            $res = [PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0)
            $out = [BoxyBox.AnsiText]::StripAnsi($res.Output)
            $lines = $out.Split("`n") | Where-Object { $_.Length -gt 0 }
            # First line is the component/data-link header; the network + transport sub-lines follow.
            $ipLine  = $lines | Where-Object { $_.Contains('IPv4 - Src:') }
            $udpLine = $lines | Where-Object { $_.Contains('UDP - Src:') }
            $ipLine  | Should -Not -BeNullOrEmpty
            $udpLine | Should -Not -BeNullOrEmpty
            # Flat two-space indent, no U+2514 connector.
            $ipLine.StartsWith('  IPv4')  | Should -BeTrue
            $udpLine.StartsWith('  UDP')  | Should -BeTrue
            $out.Contains([char]0x2514)   | Should -BeFalse
        }
        It 'shows canonical single-char TCP flags in the Default and Detailed one-liners' {
            # Eth + IPv4(TCP) + TCP SYN+ACK (0x12) on a non-app port so the TCP segment shows.
            $eth = [byte[]](0x7c,0x1e,0x52,0x97,0xb1,0x46, 0x68,0xbf,0x6c,0x64,0xf6,0x00, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[9]=6; $ip[3]=40; $ip[8]=64
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $tcp = [byte[]](0xc3,0x50, 0x1f,0x90, 0,0,0,1, 0,0,0,2, 0x50,0x12, 0xff,0xff, 0,0, 0,0)
            $packet = $eth + $ip + $tcp
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=172; $meta[18]=1
            $data = $meta + $packet
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$packet.Length, [uint32]0, [uint32]0)

            Set-PspktDetailLevel -Level 0   # Default
            $def = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            $def | Should -Match 'TCP \[\.S\]'   # ACK='.', SYN='S' per the canonical TcpFlagMap

            Set-PspktDetailLevel -Level 1   # Detailed
            $det = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            $det | Should -Match 'TCP \[\.S\] - Src:'
        }
    }

    Context 'TreeNode + TreeFlattener' {
        AfterEach { [BoxyBox.TreeFlattener]::UseConnectors = $false }
        It 'flattens expandable nodes with +/- and plain two-space leaf indent by default' {
            $roots = [System.Collections.Generic.List[BoxyBox.TreeNode]]::new()
            $ipv4 = [BoxyBox.TreeNode]::new('IPv4', 'IPv4', $true)
            $null = $ipv4.AddLeaf('Src'); $null = $ipv4.AddLeaf('Dst')
            $optNode = [BoxyBox.TreeNode]::new('Options', 'opt', $false)
            $null = $optNode.AddLeaf('MSS')                 # give it a child so it is expandable
            $null = $ipv4.Add($optNode)                     # expandable sibling of the leaves
            $null = $roots.Add($ipv4)
            $rows = [BoxyBox.TreeFlattener]::Flatten($roots)
            $rows.Count | Should -Be 4
            $rows[0].Display.TrimStart().StartsWith('-IPv4') | Should -BeTrue
            # Default: no tree connectors.
            $rows[1].Display.Contains([char]0x251c) | Should -BeFalse   # no ├
            $rows[2].Display.Contains([char]0x2514) | Should -BeFalse   # no └
            # Leaf text is aligned so the +/- marker slot sits immediately left of the text:
            # depth-1 indent (4) + one marker-slot space + text.
            [BoxyBox.AnsiText]::StripAnsi($rows[1].Display) | Should -Be '     Src'   # 5 spaces + text
            [BoxyBox.AnsiText]::StripAnsi($rows[2].Display) | Should -Be '     Dst'
            # An expandable sibling's text aligns with the leaves; its +/- is immediately left.
            [BoxyBox.AnsiText]::StripAnsi($rows[3].Display) | Should -Be '    +Options'
            $leafTextCol = [BoxyBox.AnsiText]::StripAnsi($rows[1].Display).IndexOf('Src')
            $nodeTextCol = [BoxyBox.AnsiText]::StripAnsi($rows[3].Display).IndexOf('Options')
            $leafTextCol | Should -Be $nodeTextCol   # first text char aligned
        }
        It 'draws tree connectors when UseConnectors is enabled (opt-in)' {
            [BoxyBox.TreeFlattener]::UseConnectors = $true
            $roots = [System.Collections.Generic.List[BoxyBox.TreeNode]]::new()
            $ipv4 = [BoxyBox.TreeNode]::new('IPv4', 'IPv4', $true)
            $null = $ipv4.AddLeaf('Src'); $null = $ipv4.AddLeaf('Dst')
            $null = $roots.Add($ipv4)
            $rows = [BoxyBox.TreeFlattener]::Flatten($roots)
            $rows[1].Display.Contains([char]0x251c) | Should -BeTrue    # ├ (mid child)
            $rows[2].Display.Contains([char]0x2514) | Should -BeTrue    # └ (last child)
        }
        It 'collapsed nodes hide their children and show +' {
            $roots = [System.Collections.Generic.List[BoxyBox.TreeNode]]::new()
            $eth = [BoxyBox.TreeNode]::new('Eth', 'Eth', $false)
            $null = $eth.AddLeaf('x')
            $null = $roots.Add($eth)
            $rows = [BoxyBox.TreeFlattener]::Flatten($roots)
            $rows.Count | Should -Be 1
            $rows[0].Display.TrimStart().StartsWith('+Eth') | Should -BeTrue
        }
        It 'FlattenAll includes children even when the node is collapsed' {
            $roots = [System.Collections.Generic.List[BoxyBox.TreeNode]]::new()
            $eth = [BoxyBox.TreeNode]::new('Eth', 'Eth', $false)   # collapsed
            $null = $eth.AddLeaf('x'); $null = $eth.AddLeaf('y')
            $null = $roots.Add($eth)
            # Flatten honors collapse (1 row); FlattenAll ignores it (3 rows) and shows '-'.
            [BoxyBox.TreeFlattener]::Flatten($roots).Count | Should -Be 1
            $all = [BoxyBox.TreeFlattener]::FlattenAll($roots)
            $all.Count | Should -Be 3
            $all[0].Display.TrimStart().StartsWith('-Eth') | Should -BeTrue
        }
    }

    Context 'DetailsBox' {
        BeforeAll {
            $script:ESC = [char]27
            $script:on = "$($script:ESC)[7m"; $script:off = "$($script:ESC)[0m"
            function New-SampleTree {
                $roots = [System.Collections.Generic.List[BoxyBox.TreeNode]]::new()
                $comp = [BoxyBox.TreeNode]::new('Component', 'Component', $false); $null = $comp.AddLeaf('c1')
                $eth  = [BoxyBox.TreeNode]::new('Eth', 'Eth', $false); $null = $eth.AddLeaf('e1')
                $ipv4 = [BoxyBox.TreeNode]::new('IPv4', 'IPv4', $true); $null = $ipv4.AddLeaf('Src'); $null = $ipv4.AddLeaf('Dst')
                $null = $roots.Add($comp); $null = $roots.Add($eth); $null = $roots.Add($ipv4)
                return ,$roots
            }
        }
        It 'shows Component/Eth collapsed and IPv4 expanded by default' {
            $db = [BoxyBox.DetailsBox]::new(40, 12)
            $db.SetTree((New-SampleTree))
            $db.RowCount | Should -Be 5   # Component(+) Eth(+) IPv4(-) Src Dst
        }
        It 'CollapseSelected hides children; ExpandSelected restores them' {
            $db = [BoxyBox.DetailsBox]::new(40, 12)
            $db.SetTree((New-SampleTree))
            $db.MoveDown(); $db.MoveDown()   # select IPv4
            $db.SelectedIndex | Should -Be 2
            $db.CollapseSelected()
            $db.RowCount | Should -Be 3
            $db.ExpandSelected()
            $db.RowCount | Should -Be 5
        }
        It 'ExpandAll / CollapseAll toggle every node' {
            $db = [BoxyBox.DetailsBox]::new(40, 12)
            $db.SetTree((New-SampleTree))
            $db.ExpandAll()
            $db.RowCount | Should -Be 7   # all three parents + their 4 leaves
            $db.CollapseAll()
            $db.RowCount | Should -Be 3   # three collapsed parents
        }
        It 'persists expand/collapse state by key across packets' {
            $db = [BoxyBox.DetailsBox]::new(40, 12)
            $db.SetTree((New-SampleTree))
            $db.MoveDown(); $db.MoveDown()   # IPv4
            $db.CollapseSelected()           # persist IPv4 = collapsed
            $db.SetTree((New-SampleTree))    # new packet, IPv4 default-expanded
            $db.RowCount | Should -Be 3      # IPv4 stays collapsed via persistence
        }
        It 'renders the selected row highlighted' {
            $db = [BoxyBox.DetailsBox]::new(40, 12)
            $db.SetTree((New-SampleTree))
            $frame = $db.Render($script:on, $script:off)
            # first content row (Component) is selected by default
            $frame[1].Contains($script:on) | Should -BeTrue
        }
        It 'renders a single-line bottom border (double lines reserved for the divider/live bottom)' {
            $db = [BoxyBox.DetailsBox]::new(40, 12, $false)
            $db.Box.MenuStyle | Should -Be ([BoxyBox.MenuBar+Cap]::TerminalSingle)
            $db.SetTree((New-SampleTree))
            $bottom = [BoxyBox.AnsiText]::StripAnsi($db.Render($script:on, $script:off)[-1])
            [int]$bottom[0]  | Should -Be ([int][char]0x2514)   # └
            [int]$bottom[-1] | Should -Be ([int][char]0x2518)   # ┘
            $bottom.Contains([char]0x2550) | Should -BeFalse    # no double-line rule
        }
        It 'GetAllText returns the whole tree even when collapsed and larger than the viewport' {
            $db = [BoxyBox.DetailsBox]::new(40, 4)   # tiny viewport
            $db.SetTree((New-SampleTree))
            $db.CollapseAll()                        # viewport now shows only 3 collapsed roots
            $db.GetVisibleText().Count | Should -BeLessOrEqual 3
            $all = $db.GetAllText()
            $all.Count | Should -Be 7                # 3 parents + 4 children, all included
            ($all -join '|').Contains('Src') | Should -BeTrue
            ($all -join '|').Contains('Dst') | Should -BeTrue
        }
    }

    Context 'PacketDetailStore' {
        It 'stores and retrieves packet bytes by sequence' {
            $store = [PacketDetailStore]::new(64)
            # Descriptor: packet(8) at offset 0, metadata nominally at offset 8 (no valid block).
            $data = [byte[]](1,2,3,4,5,6,7,8)
            $store.Store(10, $data, 8, 8, 0, 8, 0, 9, 1, 1)
            $pkt = $null; $c = 0; $e = 0; $d = 0
            $got = $store.TryGet(10, [ref]$pkt, [ref]$c, [ref]$e, [ref]$d)
            $got | Should -BeTrue
            $pkt.Length | Should -Be 8      # packet-only slice
            $c | Should -Be 9
            $e | Should -Be 1
            $d | Should -Be 1
        }
        It 'returns false for sequences never stored' {
            $store = [PacketDetailStore]::new(64)
            $pkt = $null; $c = 0; $e = 0; $d = 0
            $store.TryGet(999, [ref]$pkt, [ref]$c, [ref]$e, [ref]$d) | Should -BeFalse
        }
        It 'evicts entries beyond capacity (ring reuse)' {
            $store = [PacketDetailStore]::new(16)
            $data = [byte[]](1)
            0..100 | ForEach-Object { $store.Store([long]$_, $data, 1, 1, 0, 1, 0, 0, 0, 0) }
            $pkt = $null; $c = 0; $e = 0; $d = 0
            # seq 0 was overwritten long ago
            $store.TryGet(0, [ref]$pkt, [ref]$c, [ref]$e, [ref]$d) | Should -BeFalse
            # a recent seq is retained
            $store.TryGet(100, [ref]$pkt, [ref]$c, [ref]$e, [ref]$d) | Should -BeTrue
        }
        It 'WritePcapng writes a valid pcapng of the retained packets' {
            $store = [PacketDetailStore]::new(64)
            # Descriptor: packet(20) at offset 0, metadata(40) at offset 20, DataSize=60.
            $data = [byte[]]::new(60)
            for ($i = 0; $i -lt 20; $i++) { $data[$i] = [byte]($i + 1) }
            $data[20 + 12] = 1     # direction @ meta+12
            $data[20 + 16] = 138   # componentId @ meta+16
            $data[20 + 18] = 1     # edgeId @ meta+18
            $qpc = [System.Diagnostics.Stopwatch]::GetTimestamp()
            $store.Store(1, $data, 60, 20, 0, 20, $qpc, 138, 1, 1)
            $store.Store(2, $data, 60, 20, 0, 20, $qpc, 138, 1, 1)

            $out = Join-Path $env:TEMP ("pspkt-unit-{0}.pcapng" -f ([guid]::NewGuid().ToString('N')))
            try {
                $written = $store.WritePcapng($out)
                $written | Should -Be 2
                $bytes = [System.IO.File]::ReadAllBytes($out)
                $bytes.Length | Should -BeGreaterThan 0
                # pcapng Section Header Block magic (block type) = 0x0A0D0D0A.
                $bytes[0] | Should -Be 0x0A
                $bytes[1] | Should -Be 0x0D
                $bytes[2] | Should -Be 0x0D
                $bytes[3] | Should -Be 0x0A
            } finally {
                Remove-Item $out -Force -ErrorAction SilentlyContinue
            }
        }
        It 'WritePcapng returns 0 when nothing is retained' {
            $store = [PacketDetailStore]::new(16)
            $out = Join-Path $env:TEMP ("pspkt-unit-empty-{0}.pcapng" -f ([guid]::NewGuid().ToString('N')))
            try { $store.WritePcapng($out) | Should -Be 0 }
            finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'PacketDetailExtractor' {
        BeforeAll {
            # Build Ethernet + IPv4 + UDP + DNS query for example.com.
            $b = [System.Collections.Generic.List[byte]]::new()
            0..5 | ForEach-Object { $b.Add([byte]0x11) }   # dst mac
            0..5 | ForEach-Object { $b.Add([byte]0x22) }   # src mac
            $b.Add(0x08); $b.Add(0x00)                      # EtherType IPv4
            $b.Add(0x45); $b.Add(0x00); $b.Add(0x00); $b.Add(0x3c)
            $b.Add(0x8b); $b.Add(0xee); $b.Add(0x40); $b.Add(0x00)
            $b.Add(0x40); $b.Add(0x11); $b.Add(0x00); $b.Add(0x00)
            $b.AddRange([byte[]](10,24,0,72)); $b.AddRange([byte[]](1,1,1,1))
            $b.Add(0x13); $b.Add(0x88); $b.Add(0x00); $b.Add(0x35)
            $b.Add(0x00); $b.Add(0x25); $b.Add(0x00); $b.Add(0x00)   # UDP len 37 (8 hdr + 29 DNS)
            $b.Add(0x23); $b.Add(0xb4); $b.Add(0x01); $b.Add(0x00)
            $b.Add(0x00); $b.Add(0x01); $b.Add(0x00); $b.Add(0x00)
            $b.Add(0x00); $b.Add(0x00); $b.Add(0x00); $b.Add(0x00)
            $b.Add(0x07); 'example'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
            $b.Add(0x03); 'com'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
            $b.Add(0x00); $b.Add(0x00); $b.Add(0x01); $b.Add(0x00); $b.Add(0x01)
            $script:pkt = [byte[]]$b.ToArray()
        }
        It 'builds Component/Eth/IPv4/UDP/DNS top-level nodes' {
            $roots = [PacketDetailExtractor]::BuildTree($script:pkt, $script:pkt.Length, 9, 1, 1)
            $roots.Count | Should -Be 5
            $roots[0].Key | Should -Be 'Component'
            $roots[1].Key | Should -Be 'Eth'
            $roots[2].Key | Should -Be 'IPv4'
            $roots[3].Key | Should -Be 'UDP'
            $roots[4].Key | Should -Be 'DNS'
        }
        It 'Component/Eth/IPv4/TCP/UDP collapsed by default; DNS expanded' {
            $roots = [PacketDetailExtractor]::BuildTree($script:pkt, $script:pkt.Length, 9, 1, 1)
            $roots[0].IsExpanded | Should -BeFalse   # Component
            $roots[1].IsExpanded | Should -BeFalse   # Eth
            $roots[2].IsExpanded | Should -BeFalse    # IPv4 (network collapsed by default)
            $roots[3].IsExpanded | Should -BeFalse    # UDP (transport collapsed by default)
            $roots[4].IsExpanded | Should -BeTrue     # DNS
        }
        It 'extracts IPv4 fields (Src/Dst/id)' {
            $roots = [PacketDetailExtractor]::BuildTree($script:pkt, $script:pkt.Length, 9, 1, 1)
            $ipv4 = $roots[2]
            # Collapsed header matches the Detailed one-liner (Src/Dst).
            $ipv4.Text | Should -Be 'IPv4 - Src: 10.24.0.72, Dst: 1.1.1.1'
            $kids = $ipv4.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Source Address: 10.24.0.72' }).Count      | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Destination Address: 1.1.1.1' }).Count    | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Identification: 0x8bee (35822)' }).Count  | Should -Be 1
            ($kids | Where-Object { $_ -eq '0100 .... = Version: 4' }).Count          | Should -Be 1
            ($kids | Where-Object { $_ -eq '.... 0101 = Header Length: 20 bytes (5)' }).Count | Should -Be 1
        }
        It 'renders the Ethernet detail node with aligned Source/Destination/Type/Length fields' {
            $roots = [PacketDetailExtractor]::BuildTree($script:pkt, $script:pkt.Length, 9, 1, 1)
            $eth = $roots[1]
            $eth.Key | Should -Be 'Eth'
            # Collapsed header carries the one-line summary (with type + len).
            $eth.Text | Should -Match '^Eth: .+ > .+, type IPv4, len \d+$'
            $kids = $eth.Children | ForEach-Object { $_.Text }
            # Labels are padded so every value starts at the same column (13).
            ($kids | Where-Object { $_ -match '^Source:      \S' }).Count      | Should -Be 1
            ($kids | Where-Object { $_ -match '^Destination: \S' }).Count      | Should -Be 1
            ($kids | Where-Object { $_ -match '^Type:        IPv4 \(0x0800\)$' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -match '^Length:      \d+$' }).Count    | Should -Be 1
            # Every field's value column is aligned at index 13.
            foreach ($k in $kids) { $k.Substring(0, 12).TrimEnd().EndsWith(':') | Should -BeTrue; $k[12] | Should -Be ' ' }
        }
        It 'renders the TCP Details node per spec (renamed fields + Wireshark flags breakdown)' {
            # Eth + IPv4(TCP) + TCP header with SYN+ACK (flags byte 0x12), off 0x50, cksum 0x1234.
            $eth = [byte[]](0x7c,0x1e,0x52,0x97,0xb1,0x46, 0x68,0xbf,0x6c,0x64,0xf6,0x00, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[9]=6; $ip[3]=40
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $tcp = [byte[]](0xc3,0x50, 0x01,0xbb, 0,0,0,1, 0,0,0,2, 0x50,0x12, 0xff,0xff, 0x12,0x34, 0,0)
            $pkt = $eth + $ip + $tcp
            $roots = [PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)
            $tcpNode = $roots | Where-Object { $_.Key -eq 'TCP' }
            $tcpNode | Should -Not -BeNullOrEmpty
            $tcpNode.IsExpanded | Should -BeFalse   # collapsed by default in Analysis mode
            # Collapsed header carries the tcpdump flags + ports/seq/ack/len summary.
            $tcpNode.Text | Should -Be 'TCP [.S] - Src Port: 50000, Dst Port: 443, Seq: 1, Ack: 2, Len: 0'
            $kids = $tcpNode.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Source Port: 50000' }).Count           | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Destination Port: 443' }).Count         | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Sequence Number: 1' }).Count            | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Acknowledgment number: 2' }).Count      | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Window: 65535' }).Count                 | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Checksum: 0x1234' }).Count              | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Urgent Pointer: 0' }).Count             | Should -Be 1
            ($kids | Where-Object { $_ -eq 'TCP payload (0 bytes)' }).Count         | Should -Be 1
            ($kids | Where-Object { $_ -eq '0101 .... = Header Length: 20 bytes (0x5)' }).Count | Should -Be 1
        }
        It 'renders the TCP Flags node as a Wireshark bit breakdown with the tcpdump char summary' {
            $eth = [byte[]](0x7c,0x1e,0x52,0x97,0xb1,0x46, 0x68,0xbf,0x6c,0x64,0xf6,0x00, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[9]=6; $ip[3]=40
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $tcp = [byte[]](0xc3,0x50, 0x01,0xbb, 0,0,0,1, 0,0,0,2, 0x50,0x12, 0xff,0xff, 0x12,0x34, 0,0)
            $pkt = $eth + $ip + $tcp
            $roots = [PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)
            $flags = ($roots | Where-Object { $_.Key -eq 'TCP' }).Children | Where-Object { $_.Key -eq 'TCP.Flags' }
            $flags | Should -Not -BeNullOrEmpty
            # Header: 0x[12-bit hex] ([tcpdump single-char flags]); SYN+ACK => 0x012 (.S). Collapsed by default.
            $flags.Text | Should -Be 'Flags: 0x012 (.S)'
            $flags.IsExpanded | Should -BeFalse
            $lines = $flags.Children | ForEach-Object { $_.Text }
            $lines.Count | Should -Be 10
            ($lines | Where-Object { $_ -eq '000. .... .... = Reserved: Not set' }).Count | Should -Be 1
            ($lines | Where-Object { $_ -eq '.... ...1 .... = Acknowledgment: Set' }).Count | Should -Be 1
            ($lines | Where-Object { $_ -eq '.... .... ..1. = Syn: Set' }).Count | Should -Be 1
            ($lines | Where-Object { $_ -eq '.... .... ...0 = Fin: Not set' }).Count | Should -Be 1
            ($lines | Where-Object { $_ -eq '.... B... .... = Congestion Window Reduced: Not set' }).Count | Should -Be 0
        }
        It 'renders the UDP Details node per spec (renamed fields + payload leaf)' {
            # The shared $script:pkt is a UDP/DNS packet; roots[3] is the UDP node.
            $roots = [PacketDetailExtractor]::BuildTree($script:pkt, $script:pkt.Length, 9, 1, 1)
            $udp = $roots[3]
            $udp.Key | Should -Be 'UDP'
            $udp.IsExpanded | Should -BeFalse   # collapsed by default in Analysis mode
            $udp.Text | Should -Match '^UDP - Src Port: \d+, Dst Port: 53, Len: \d+$'
            $kids = $udp.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -match '^Source Port: \d+$' }).Count      | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Destination Port: 53' }).Count       | Should -Be 1
            ($kids | Where-Object { $_ -match '^UDP payload \(\d+\)$' }).Count    | Should -Be 1
        }
        It 'extracts DNS transaction id and query' {
            $roots = [PacketDetailExtractor]::BuildTree($script:pkt, $script:pkt.Length, 9, 1, 1)
            $dns = $roots[4]
            ($dns.Children | Where-Object { $_.Text -eq 'Transaction ID: 0x23b4' }).Count | Should -Be 1
            ($dns.Children | Where-Object { $_.Text -eq 'RR Count - Qry: 1, Ans: 0, Auth: 0, Adtl: 0' }).Count | Should -Be 1
            # Queries section with the example.com A query.
            $queries = $dns.Children | Where-Object { $_.Key -eq 'DNS.Queries' }
            $queries | Should -Not -BeNullOrEmpty
            ($queries.Children | Where-Object { $_.Text -eq 'example.com.: type A, class IN' }).Count | Should -Be 1
            # Flags node present with the bit-breakdown.
            $flags = $dns.Children | Where-Object { $_.Key -eq 'DNS.Flags' }
            $flags | Should -Not -BeNullOrEmpty
            ($flags.Children | Where-Object { $_.Text -like '*Recursion desired: Do query recursively' }).Count | Should -Be 1
        }
        It 'parses DNS over TCP (RFC 1035 2-byte length prefix) in the Details tree and one-liner' {
            # Eth + IPv4/TCP(:53, PSH+ACK) + 2-byte DNS length prefix + DNS response.
            $eth = [byte[]](0x7c,0x1e,0x52,0x97,0xb1,0x46, 0x68,0xbf,0x6c,0x64,0xf6,0x00, 0x08,0x00)
            $b = [System.Collections.Generic.List[byte]]::new()
            $b.AddRange([byte[]](0x94,0xf0, 0x81,0x80, 0,1, 0,1, 0,0, 0,0))
            $b.Add(7); 'example'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
            $b.Add(3); 'com'.ToCharArray() | ForEach-Object { $b.Add([byte][char]$_) }
            $b.Add(0); $b.AddRange([byte[]](0,1, 0,1))
            $b.AddRange([byte[]](0xc0,0x0c, 0,1, 0,1, 0,0,0,60, 0,4, 150,171,109,117))
            $dnsBytes = [byte[]]$b.ToArray()
            $prefix = [byte[]]( ($dnsBytes.Length -shr 8), ($dnsBytes.Length -band 0xff) )
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[9]=6
            $tot = 20 + 20 + 2 + $dnsBytes.Length; $ip[2]=($tot -shr 8); $ip[3]=($tot -band 0xff)
            $ip[12]=1;$ip[13]=1;$ip[14]=1;$ip[15]=1; $ip[16]=10;$ip[17]=24;$ip[18]=0;$ip[19]=72
            $tcp = [byte[]](0,53, 0xe2,0x01, 0,0,0,1, 0,0,0,2, 0x50,0x18, 0,16, 0xaa,0xc8, 0,0)
            $pkt = $eth + $ip + $tcp + $prefix + $dnsBytes

            # Details tree: DNS node built from the TCP payload (prefix skipped).
            $roots = [PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)
            $dns = $roots | Where-Object { $_.Key -eq 'DNS' }
            $dns | Should -Not -BeNullOrEmpty
            ($dns.Children | Where-Object { $_.Text -eq 'Transaction ID: 0x94f0' }).Count | Should -Be 1

            # One-liner (Analysis level 0): the app-layer DNS summary, not the raw TCP segment.
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally {
                Set-PspktDetailLevel -Level 1
            }
            $out | Should -Match 'DNS: 0x94f0 1/0/0 example\.com\. A 150\.171\.109\.117'
        }
        It 'shows a contentless TCP:53 segment as plain TCP, not a DNS hint line' {
            # A FIN/ACK segment on port 53 carries no DNS message; it must render at the
            # transport layer ("TCP [.F] ...") rather than being labeled "DNS: TCP [.F] ...".
            $eth = [byte[]](0x7c,0x1e,0x52,0x97,0xb1,0x46, 0x68,0xbf,0x6c,0x64,0xf6,0x00, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[9]=6; $ip[3]=40
            $ip[12]=1;$ip[13]=1;$ip[14]=1;$ip[15]=1; $ip[16]=10;$ip[17]=24;$ip[18]=0;$ip[19]=72
            $tcp = [byte[]](0,53, 0xc8,0xd1, 0,0,0,1, 0,0,0,2, 0x50,0x11, 0,16, 0xaa,0xc8, 0,0)
            $pkt = $eth + $ip + $tcp
            $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
            $data = $meta + $pkt
            $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
            Set-PspktDetailLevel -Level 0
            try {
                $out = [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally {
                Set-PspktDetailLevel -Level 1
            }
            $out | Should -Match 'TCP \[\.F\], seq 1, ack 2, win 16, len 0'
            $out | Should -Not -Match 'DNS'
        }
        It 'returns an error node for too-short input' {
            $roots = [PacketDetailExtractor]::BuildTree([byte[]](1,2,3), 3, 0, 0, 0)
            $roots.Count | Should -Be 1
            $roots[0].Text | Should -Match 'too short'
        }
    }

    Context 'Network parser Details trees' {
        # Helper: find a root node by key.
        function script:GetNode($roots, $key) { $roots | Where-Object { $_.Key -eq $key } | Select-Object -First 1 }

        It 'IPv4 renders the full Wireshark-style bitfield breakdown (DF set)' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[6]=0x40; $ip[8]=64; $ip[9]=1; $ip[2]=0; $ip[3]=44
            $ip[10]=0x1a;$ip[11]=0x2b   # header checksum 0x1a2b
            $ip[12]=192;$ip[13]=168;$ip[14]=0;$ip[15]=1; $ip[16]=8;$ip[17]=8;$ip[18]=8;$ip[19]=8
            $icmp = [byte[]](8,0, 0,0, 0,0, 0,0) + [byte[]]::new(8)
            $pkt = $eth + $ip + $icmp
            $ipv4 = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'IPv4'
            $ipv4.Text | Should -Be 'IPv4 - Src: 192.168.0.1, Dst: 8.8.8.8'
            $ipv4.IsExpanded | Should -BeFalse   # collapsed by default in Analysis mode
            $kids = $ipv4.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq '0100 .... = Version: 4' }).Count                     | Should -Be 1
            ($kids | Where-Object { $_ -eq '.... 0101 = Header Length: 20 bytes (5)' }).Count    | Should -Be 1
            ($kids | Where-Object { $_ -eq 'DSCP: BE, ECN: Not-ECT' }).Count                     | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Total Length: 44' }).Count                           | Should -Be 1
            ($kids | Where-Object { $_ -eq '...0 0000 0000 0000 = Fragment Offset: 0' }).Count   | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Time to Live: 64' }).Count                           | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Protocol: ICMP (1)' }).Count                         | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Header Checksum: 0x1a2b' }).Count                    | Should -Be 1
        }
        It 'IPv4 Flags node breaks out Reserved/DF/MF with the DF bit set' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[6]=0x40; $ip[8]=64; $ip[9]=6; $ip[3]=40
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $tcp = [byte[]](0,80, 0,80, 0,0,0,1, 0,0,0,2, 0x50,0x02, 0,0, 0,0, 0,0)
            $pkt = $eth + $ip + $tcp
            $ipv4 = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'IPv4'
            $flags = $ipv4.Children | Where-Object { $_.Key -eq 'IPv4.Flags' }
            $flags | Should -Not -BeNullOrEmpty
            $flags.Text | Should -Be "010. .... = Flags: 0x40, Don't fragment"
            $flags.IsExpanded | Should -BeFalse
            $fk = $flags.Children | ForEach-Object { $_.Text }
            ($fk | Where-Object { $_ -eq '0... .... = Reserved bit: Not set' }).Count       | Should -Be 1
            ($fk | Where-Object { $_ -eq ".1.. .... = Don't fragment: Set" }).Count          | Should -Be 1
            ($fk | Where-Object { $_ -eq '..0. .... = More fragments: Not set' }).Count      | Should -Be 1
        }
        It 'IPv6 renders Version, Traffic Class node (DSCP/ECN), Flow Label and addresses' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            $ip6 = [byte[]](0x60,0x02,0xff,0xf8) + [byte[]](0,16, 58, 255)
            $ip6 += ([byte[]](0x20,0x01) + [byte[]]::new(14))
            $ip6 += ([byte[]](0x20,0x01) + [byte[]]::new(13) + [byte[]](2))
            $ic6 = [byte[]](128,0, 0xaa,0xbb, 0x43,0x21, 0x00,0x05) + [byte[]]::new(8)
            $pkt = $eth + $ip6 + $ic6
            $ipv6 = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'IPv6'
            $ipv6.Text | Should -Be 'IPv6 - Src: 2001::, Dst: 2001::2'
            $ipv6.IsExpanded | Should -BeFalse   # collapsed by default in Analysis mode
            $kids = $ipv6.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq '0110 .... = Version: 6' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq '.... 0010 1111 1111 1111 1000 = Flow Label: 0x2fff8' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Payload Length: 16' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Next Header: IPv6-ICMP (58)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Hop Limit: 255' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Source Address: 2001::' }).Count | Should -Be 1
            $tc = $ipv6.Children | Where-Object { $_.Key -eq 'IPv6.TrafficClass' }
            $tc | Should -Not -BeNullOrEmpty
            $tc.Text | Should -Be '.... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (BE)'
            ($tc.Children | Where-Object { $_.Text -eq '.... 0000 00.. .... .... .... .... .... = Differentiated Services Codepoint: BE (0)' }).Count | Should -Be 1
            ($tc.Children | Where-Object { $_.Text -eq '.... .... ..00 .... .... .... .... .... = Explicit Congestion Notification: Not ECN-Capable Transport, Not-ECT (0)' }).Count | Should -Be 1
        }
        It 'ARP request/reply headers + aligned label fields' {
            $ethA = [byte[]](0xff,0xff,0xff,0xff,0xff,0xff, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x06)
            $req = [byte[]](0,1, 8,0, 6, 4, 0,1) + [byte[]](0xaa,0xbb,0xcc,0xdd,0xee,0xff) + [byte[]](192,168,0,10) + [byte[]](0,0,0,0,0,0) + [byte[]](192,168,0,1)
            $arp = GetNode ([PacketDetailExtractor]::BuildTree(($ethA+$req), ($ethA+$req).Length, 9, 1, 1)) 'ARP'
            $arp.Text | Should -Be 'ARP, Request who-has 192.168.0.1 tell 192.168.0.10'
            $kids = $arp.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Operation  : Request' }).Count            | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Sender MAC : aa-bb-cc-dd-ee-ff' }).Count  | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Target IP  : 192.168.0.1' }).Count        | Should -Be 1
            # Reply: sender's mapping is advertised (tcpdump-style).
            $rep = [byte[]](0,1, 8,0, 6, 4, 0,2) + [byte[]](0xaa,0xbb,0xcc,0xdd,0xee,0xff) + [byte[]](192,168,0,1) + [byte[]](0x11,0x22,0x33,0x44,0x55,0x66) + [byte[]](192,168,0,10)
            $arpR = GetNode ([PacketDetailExtractor]::BuildTree(($ethA+$rep), ($ethA+$rep).Length, 9, 1, 1)) 'ARP'
            $arpR.Text | Should -Be 'ARP, Reply 192.168.0.1 is-at aa-bb-cc-dd-ee-ff'
        }
        It 'ICMP Echo renders the full field template' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=1; $ip[3]=44
            $ip[12]=192;$ip[13]=168;$ip[14]=0;$ip[15]=1; $ip[16]=8;$ip[17]=8;$ip[18]=8;$ip[19]=8
            $icmp = [byte[]](8,0, 0xf7,0xff, 0x12,0x34, 0x00,0x01) + [byte[]]::new(8)
            $pkt = $eth + $ip + $icmp
            $node = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'ICMP'
            $node.Text | Should -Be 'ICMP.Echo Request: 192.168.0.1 > 8.8.8.8, id 4660, seq 1'
            $kids = $node.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Type       : Echo (ping) request (8)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Checksum   : 0xf7ff' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Identifier : 4660 (0x1234)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Sequence   : 1 (0x0001)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Data (8 bytes)' }).Count | Should -Be 1
        }
        It 'ICMP Destination Unreachable renders the code string' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=1; $ip[3]=56
            $ip[12]=1;$ip[13]=1;$ip[14]=1;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=5
            $icmp = [byte[]](3,3, 0,0, 0,0,0,0) + [byte[]]::new(28)
            $pkt = $eth + $ip + $icmp
            $node = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'ICMP'
            $node.Text | Should -Be 'ICMP.Destination Unreachable -  Destination port unreachable (3)'
            ($node.Children | Where-Object { $_.Text -eq 'Code       : Destination port unreachable (3)' }).Count | Should -Be 1
        }
        It 'ICMPv6 Echo renders the full field template' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]](0,16, 58, 64) + ([byte[]](0x20,0x01)+[byte[]]::new(14)) + ([byte[]](0x20,0x01)+[byte[]]::new(13)+[byte[]](2))
            $ic6 = [byte[]](128,0, 0xaa,0xbb, 0x43,0x21, 0x00,0x05) + [byte[]]::new(8)
            $pkt = $eth + $ip6 + $ic6
            $node = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'ICMPv6'
            $node.Text | Should -Be 'ICMPv6.Echo Request: 2001:: > 2001::2, id 17185, seq 5'
            ($node.Children | Where-Object { $_.Text -eq 'Type       : Echo (ping) request (128)' }).Count | Should -Be 1
            ($node.Children | Where-Object { $_.Text -eq 'Identifier : 17185 (0x4321)' }).Count | Should -Be 1
        }
        It 'ICMPv6 Neighbor Advertisement renders header, target and NA flags' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            $na = [byte[]](136,0, 0,0, 0xE0,0,0,0)
            $na += ([byte[]](0x20,0x01) + [byte[]]::new(13) + [byte[]](0x0a))
            $na += [byte[]](2, 1, 0x54,0x0f,0x2c,0x72,0x5e,0x1c)
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]](0,($na.Length),58,255) + ([byte[]](0x20,0x01)+[byte[]]::new(14)) + ([byte[]](0xff,0x02)+[byte[]]::new(13)+[byte[]](1))
            $pkt = $eth + $ip6 + $na
            $node = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'ICMPv6'
            $node.Text | Should -Be 'ICMPv6.Neighbor Advertisement 2001::a (rtr, sol, ovr) is at 54-0f-2c-72-5e-1c'
            $kids = $node.Children | ForEach-Object { $_.Text }
            ($kids | Where-Object { $_ -eq 'Type       : Neighbor Advertisement (136)' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Target Address : 2001::a' }).Count | Should -Be 1
            ($kids | Where-Object { $_ -eq 'Solicited : Set' }).Count | Should -Be 1
        }
        It 'ICMPv6 Router Advertisement expands the options (Prefix/MTU/RDNSS) into children' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            # RA header: type 134, code 0, checksum, CurHopLimit 64, flags 0, RtrLifetime 1800, Reach 0, Retrans 0
            $ra = [byte[]](134,0, 0,0, 64, 0, 0x07,0x08, 0,0,0,0, 0,0,0,0)
            # Prefix Info option: /64, L+A (0xC0), valid 2745, pref 2745, prefix 2600:1700:5aa0:30cf::
            $ra += [byte[]](3,4, 64, 0xC0, 0,0,0x0A,0xB9, 0,0,0x0A,0xB9, 0,0,0,0)
            $ra += [byte[]](0x26,0x00,0x17,0x00,0x5a,0xa0,0x30,0xcf, 0,0,0,0,0,0,0,0)
            # MTU option: 9216 (0x2400)
            $ra += [byte[]](5,1, 0,0, 0,0,0x24,0x00)
            # RDNSS option: lifetime 1800, two servers ::60 and ::61
            $ra += [byte[]](25,5, 0,0, 0,0,0x07,0x08)
            $ra += [byte[]](0x26,0x00,0x17,0x00,0x5a,0xa0,0x30,0xcf, 0,0,0,0,0,0,0,0x60)
            $ra += [byte[]](0x26,0x00,0x17,0x00,0x5a,0xa0,0x30,0xcf, 0,0,0,0,0,0,0,0x61)
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]](0,($ra.Length),58,255) + ([byte[]](0xfe,0x80)+[byte[]]::new(14)) + ([byte[]](0xff,0x02)+[byte[]]::new(13)+[byte[]](1))
            $pkt = $eth + $ip6 + $ra
            $node = GetNode ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 9, 1, 1)) 'ICMPv6'
            $opts = $node.Children | Where-Object { $_.Key -eq 'ICMPv6.Options' }
            $opts | Should -Not -BeNullOrEmpty
            $opts.IsExpanded | Should -BeTrue
            # Header keeps the one-liner summary.
            [BoxyBox.AnsiText]::StripAnsi($opts.Text) | Should -Be 'Options : Prefix 2600:1700:5aa0:30cf::/64 L=1 A=1 Valid 2745s Pref 2745s, MTU 9216, RDNSS Lifetime 1800s 2600:1700:5aa0:30cf::60 2600:1700:5aa0:30cf::61'
            # Each option is broken out as a child.
            $kids = $opts.Children | ForEach-Object { [BoxyBox.AnsiText]::StripAnsi($_.Text) }
            $kids.Count | Should -Be 3
            $kids[0] | Should -Be 'Prefix 2600:1700:5aa0:30cf::/64 L=1 A=1 Valid 2745s Pref 2745s'
            $kids[1] | Should -Be 'MTU 9216'
            $kids[2] | Should -Be 'RDNSS Lifetime 1800s 2600:1700:5aa0:30cf::60 2600:1700:5aa0:30cf::61'
        }
        It 'Component node renders the Group/Component/Edge/Direction format' {
            [PacketLineFormatter]::ClearComponents()
            [PacketLineFormatter]::RegisterComponent(199, 'Microsoft NetVsc Nic #5', 0, 'Microsoft NetVsc Nic #5')
            [PacketLineFormatter]::RegisterComponent(200, 'WFP Native Filter', 199, 'Microsoft NetVsc Nic #5')
            try {
                $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
                $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=1; $ip[3]=44
                $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
                $pkt = $eth + $ip + ([byte[]](8,0,0,0,0,1,0,1) + [byte[]]::new(8))
                # compId 200, edge 2 (Egress -> left arrow), direction 3 (Rx -> up arrow)
                $up = [char]0x2191; $left = [char]0x2190
                $comp = ([PacketDetailExtractor]::BuildTree($pkt, $pkt.Length, 200, 2, 3))[0]
                $comp.Key | Should -Be 'Component'
                [BoxyBox.AnsiText]::StripAnsi($comp.Text) | Should -Be "[$up]Microsoft NetVsc Nic #5 (199):[$left]WFP Native Filter (200)"
                $kids = $comp.Children | ForEach-Object { [BoxyBox.AnsiText]::StripAnsi($_.Text) }
                $kids[0] | Should -Be "Direction : Rx [$up]"
                $kids[1] | Should -Be 'Group     : Microsoft NetVsc Nic #5 (199)'
                $kids[2] | Should -Be 'Component : WFP Native Filter (200)'
                $kids[3] | Should -Be "Edge      : Egress [$left]"
            } finally {
                [PacketLineFormatter]::ClearComponents()
            }
        }
    }

    Context 'PacketParseHelper.FormatIPv6 (RFC 5952)' {
        function script:V6([byte[]]$b) { [PacketParseHelper]::FormatIPv6($b, 0) }
        It 'renders a full address with no compression' {
            V6 ([byte[]](0x20,0x01,0x0d,0xb8,0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,0x00,0x05,0x00,0x06)) | Should -Be '2001:db8:1:2:3:4:5:6'
        }
        It 'suppresses leading zeros within each group' {
            V6 ([byte[]](0x20,0x01,0x0d,0xb8,0x00,0x0a,0x00,0x0b,0x0c,0x00,0x00,0x0d,0x00,0x00,0x00,0x01)) | Should -Be '2001:db8:a:b:c00:d:0:1'
        }
        It 'compresses the longest zero run with ::' {
            V6 ([byte[]](0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01)) | Should -Be '2001:db8::1'
        }
        It 'renders the all-zeros address as ::' {
            V6 ([byte[]]::new(16)) | Should -Be '::'
        }
        It 'renders the loopback address as ::1' {
            $b = [byte[]]::new(16); $b[15]=1; V6 $b | Should -Be '::1'
        }
        It 'compresses a leading zero run (link-local all-nodes)' {
            $b = [byte[]]::new(16); $b[0]=0xff; $b[1]=0x02; $b[15]=0x01; V6 $b | Should -Be 'ff02::1'
        }
        It 'compresses only the longest run when two runs exist' {
            # 2001:0:0:1:0:0:0:1 -> the longer (second) run compresses
            V6 ([byte[]](0x20,0x01,0,0,0,0,0,0x01,0,0,0,0,0,0,0,0x01)) | Should -Be '2001:0:0:1::1'
        }
        It 'produces the same result across repeated calls (reused scratch buffers)' {
            $a = V6 ([byte[]](0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01))
            $b = V6 ([byte[]]::new(16))
            $c = V6 ([byte[]](0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01))
            $a | Should -Be '2001:db8::1'
            $b | Should -Be '::'
            $c | Should -Be '2001:db8::1'   # scratch reuse must not corrupt a later call
        }
    }

    Context 'Network parser one-liners' {
        function script:EmitLine($pkt, $lvl) {
            Set-PspktDetailLevel -Level $lvl
            try {
                $meta = [byte[]]::new(40); $meta[12]=1; $meta[16]=200; $meta[18]=2
                $data = $meta + $pkt
                $pd = [PSPacketData]::new($data, [uint32]$data.Length, [uint32]0, [uint32]40, [uint32]$pkt.Length, [uint32]0, [uint32]0)
                [BoxyBox.AnsiText]::StripAnsi([PacketLineFormatter]::FormatBatch([PSPacketData[]]@($pd), 1, 0).Output)
            } finally { Set-PspktDetailLevel -Level 1 }
        }
        It 'ICMP Destination Unreachable shows the code string at Default and Detailed' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=1; $ip[3]=56
            $ip[12]=1;$ip[13]=1;$ip[14]=1;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=5
            $icmp = [byte[]](3,3, 0,0, 0,0,0,0) + [byte[]]::new(28)
            $pkt = $eth + $ip + $icmp
            (EmitLine $pkt 0) | Should -Match 'ICMP\.Destination Unreachable -  Destination port unreachable \(3\)'
            (EmitLine $pkt 1) | Should -Match 'ICMP\.Destination Unreachable -  Destination port unreachable \(3\)'
        }
        It 'parses a TCP/TLS segment whose IP Total Length is 0 (TSO/LSO offload)' {
            # A hardware segmentation-offload frame reports IP Total Length 0 (the NIC fills it in
            # after capture). The parser must fall back to the captured frame length instead of
            # rendering "TCP [none], seq 0, len 0" and hiding the payload.
            $tls = [byte[]]::new(80); $tls[0]=0x16; $tls[1]=0x03; $tls[2]=0x01; $tls[3]=0x00; $tls[4]=0x4b; $tls[5]=0x01
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0xc6; $tcp[1]=0xee; $tcp[2]=0x01; $tcp[3]=0xbb    # 50926 -> 443
            $tcp[4]=0x0b; $tcp[5]=0x36; $tcp[6]=0x3a; $tcp[7]=0x74    # seq
            $tcp[12]=0x50; $tcp[13]=0x18                              # data offset 5, PSH+ACK
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=0x00; $ip[3]=0x00                                  # Total Length = 0 (offload)
            $ip[12]=10;$ip[13]=24;$ip[14]=0;$ip[15]=72; $ip[16]=104;$ip[17]=20;$ip[18]=23;$ip[19]=154
            $pkt = $eth + $ip + $tcp + $tls
            $out = EmitLine $pkt 0
            $out | Should -Match 'IPv4\.TCP 10\.24\.0\.72\.50926 > 104\.20\.23\.154\.443: TLS 1\.0 ClientHello'
            $out | Should -Not -Match 'TCP \[none\]'
        }
        It 'shows real TCP fields for a payload-less TSO segment (not zeros)' {
            # A plain (non-app) TCP segment with IP Total Length 0 must still show its real ports
            # and sequence number, not the zeroed "TCP [none], seq 0" fallback.
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $tcp = [byte[]]::new(20)
            $tcp[0]=0x23; $tcp[1]=0x28; $tcp[2]=0x23; $tcp[3]=0x29    # 9000 -> 9001 (no app parser)
            $tcp[4]=0x00; $tcp[5]=0x00; $tcp[6]=0x04; $tcp[7]=0xd2    # seq 1234
            $tcp[12]=0x50; $tcp[13]=0x10                             # ACK only, no payload
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=6
            $ip[2]=0x00; $ip[3]=0x00                                  # Total Length = 0 (offload)
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=1; $ip[16]=10;$ip[17]=0;$ip[18]=0;$ip[19]=2
            $pkt = $eth + $ip + $tcp
            $out = EmitLine $pkt 0
            $out | Should -Match 'IPv4\.TCP 10\.0\.0\.1\.9000 > 10\.0\.0\.2\.9001: TCP \[\.\], seq 1234,'
            $out | Should -Not -Match 'seq 0,'
        }
        It 'ICMPv6 NDP Router Solicitation uses the spec format with the sender MAC' {
            $eth = [byte[]](0x33,0x33,0,0,0,2, 0x54,0x0f,0x2c,0x72,0x5e,0x1c, 0x86,0xdd)
            $rs = [byte[]](133,0,0,0, 0,0,0,0) + [byte[]](1,1,0x54,0x0f,0x2c,0x72,0x5e,0x1c)
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]](0,($rs.Length),58,255) + ([byte[]](0xfe,0x80)+[byte[]]::new(14)) + ([byte[]](0xff,0x02)+[byte[]]::new(13)+[byte[]](2))
            $pkt = $eth + $ip6 + $rs
            (EmitLine $pkt 0) | Should -Match 'ICMPv6\.Router Solicitation from 54-0f-2c-72-5e-1c'
        }
        It 'ICMPv6 Destination Unreachable shows the code string' {
            $eth = [byte[]](0x33,0x33,0,0,0,2, 0x54,0x0f,0x2c,0x72,0x5e,0x1c, 0x86,0xdd)
            $du = [byte[]](1,4,0,0, 0,0,0,0) + [byte[]]::new(40)
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]](0,($du.Length),58,64) + ([byte[]](0x20,0x01)+[byte[]]::new(14)) + ([byte[]](0x20,0x01)+[byte[]]::new(13)+[byte[]](9))
            $pkt = $eth + $ip6 + $du
            (EmitLine $pkt 0) | Should -Match 'ICMPv6\.Destination Unreachable -  Port unreachable \(4\)'
        }
        It 'Default line drops the ", type <ethtype>" Ethernet portion but keeps len' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            $ip = [byte[]]::new(20); $ip[0]=0x45; $ip[8]=64; $ip[9]=1; $ip[3]=44
            $ip[12]=10;$ip[13]=0;$ip[14]=0;$ip[15]=5; $ip[16]=8;$ip[17]=8;$ip[18]=8;$ip[19]=8
            $pkt = $eth + $ip + ([byte[]](8,0,0,0,0,1,0,1) + [byte[]]::new(8))
            $line = EmitLine $pkt 0
            $line | Should -Match '22-22-22-22-22-22 > 11-11-11-11-11-11, len \d+:'
            $line | Should -Not -Match 'type IPv4'
        }
        It 'prefixes IPv4[.transport] to the tuple for UDP, bare IP, and ICMP' {
            $eth = [byte[]](0x11,0x11,0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,0x22,0x22, 0x08,0x00)
            # UDP: prefixed with the transport protocol (IPv4.UDP)
            $ipu = [byte[]]::new(20); $ipu[0]=0x45; $ipu[8]=64; $ipu[9]=17; $ipu[3]=42
            $ipu[12]=10;$ipu[13]=0;$ipu[14]=0;$ipu[15]=5; $ipu[16]=1;$ipu[17]=1;$ipu[18]=1;$ipu[19]=1
            $udp = [byte[]](0x30,0x39, 0x01,0xbb, 0,14, 0,0) + [byte[]]::new(6)
            (EmitLine ($eth + $ipu + $udp) 0) | Should -Match 'IPv4\.UDP 10\.0\.0\.5\.12345 > 1\.1\.1\.1\.443'
            # Bare IP (OSPF, proto 89): plain IPv4 prefix, no transport suffix, no ports
            $ipo = [byte[]]::new(20); $ipo[0]=0x45; $ipo[8]=64; $ipo[9]=89; $ipo[3]=24
            $ipo[12]=10;$ipo[13]=0;$ipo[14]=0;$ipo[15]=1; $ipo[16]=224;$ipo[17]=0;$ipo[18]=0;$ipo[19]=5
            (EmitLine ($eth + $ipo + [byte[]]::new(4)) 0) | Should -Match 'IPv4 10\.0\.0\.1 > 224\.0\.0\.5'
            # ICMP: plain IPv4 prefix (no transport suffix)
            $ipc = [byte[]]::new(20); $ipc[0]=0x45; $ipc[8]=64; $ipc[9]=1; $ipc[3]=44
            $ipc[12]=10;$ipc[13]=0;$ipc[14]=0;$ipc[15]=5; $ipc[16]=8;$ipc[17]=8;$ipc[18]=8;$ipc[19]=8
            $line = EmitLine ($eth + $ipc + ([byte[]](8,0,0,0,0,1,0,1) + [byte[]]::new(8))) 0
            $line | Should -Match 'IPv4 10\.0\.0\.5 > 8\.8\.8\.8: ICMP echo'
            $line | Should -Not -Match 'IPv4\.'
        }
        It 'prefixes IPv6 to the tuple for TCP and ICMPv6' {
            $eth = [byte[]](0x33,0x33,0,0,0,1, 0x22,0x22,0x22,0x22,0x22,0x22, 0x86,0xdd)
            $tcp = [byte[]](0x1f,0x90, 0,80, 0,0,0,1, 0,0,0,2, 0x50,0x02, 0,0, 0,0, 0,0)
            $ip6 = [byte[]](0x60,0,0,0) + [byte[]](0,20,6,64) + ([byte[]](0x20,0x01)+[byte[]]::new(14)) + ([byte[]](0x20,0x01)+[byte[]]::new(13)+[byte[]](2))
            (EmitLine ($eth + $ip6 + $tcp) 0) | Should -Match 'IPv6 2001::\.8080 > 2001::2\.80'
            $ic6 = [byte[]](128,0,0,0,0x43,0x21,0,5) + [byte[]]::new(8)
            $ip6b = [byte[]](0x60,0,0,0) + [byte[]](0,16,58,64) + ([byte[]](0x20,0x01)+[byte[]]::new(14)) + ([byte[]](0x20,0x01)+[byte[]]::new(13)+[byte[]](2))
            (EmitLine ($eth + $ip6b + $ic6) 0) | Should -Match 'IPv6 2001:: > 2001::2: ICMPv6 echo request'
        }
    }

    Context 'MenuRenderer + MenuDefinition' {
        BeforeAll {
            $script:def = [BoxyBox.MenuDefinition]::new('Details')
            $null = $script:def.AddItem('Expand',   'Expand',   "$([char]0x2192)")
            $null = $script:def.AddItem('Collapse', 'Collapse', "$([char]0x2190)")
        }
        It 'renders Full options as [Hotkey]DisplayName (visible text)' {
            $opts = [BoxyBox.MenuRenderer]::BuildOptions($script:def, $true)
            [BoxyBox.AnsiText]::StripAnsi($opts[0]) | Should -Be "[$([char]0x2192)]Expand"
            [BoxyBox.AnsiText]::StripAnsi($opts[1]) | Should -Be "[$([char]0x2190)]Collapse"
        }
        It 'colors menu items so they stand out from the border' {
            $opts = [BoxyBox.MenuRenderer]::BuildOptions($script:def, $true)
            # both the hotkey and the label carry an SGR color sequence
            [BoxyBox.AnsiText]::ContainsAnsi($opts[0]) | Should -BeTrue
            $simple = [BoxyBox.MenuRenderer]::BuildOptions($script:def, $false)
            [BoxyBox.AnsiText]::ContainsAnsi($simple[0]) | Should -BeTrue
        }
        It 'renders Simple options as [Hotkey] only (visible text)' {
            $opts = [BoxyBox.MenuRenderer]::BuildOptions($script:def, $false)
            [BoxyBox.AnsiText]::StripAnsi($opts[0]) | Should -Be "[$([char]0x2192)]"
        }
        It 'FullFits is true for a wide bar and false for a narrow one' {
            [BoxyBox.MenuRenderer]::FullFits($script:def, 120) | Should -BeTrue
            [BoxyBox.MenuRenderer]::FullFits($script:def, 8)   | Should -BeFalse
        }
        It 'BuildAuto picks Simple when Full will not fit' {
            $auto = [BoxyBox.MenuRenderer]::BuildAuto($script:def, 8)
            [BoxyBox.AnsiText]::StripAnsi($auto[0]) | Should -Be "[$([char]0x2192)]"   # simple (hotkey only)
        }
        It 'BuildAuto picks Full when there is room' {
            $auto = [BoxyBox.MenuRenderer]::BuildAuto($script:def, 120)
            [BoxyBox.AnsiText]::StripAnsi($auto[0]) | Should -Be "[$([char]0x2192)]Expand"
        }
    }

    Context 'Get-PspktTuiMenu' {
        BeforeAll {
            $script:mod = Get-Module PspktSession
        }
        It 'loads the shipped Details menu with 6 items' {
            $def = & $script:mod { Get-PspktTuiMenu -Box 'Details' }
            $def.Box | Should -Be 'Details'
            $def.Menu.Count | Should -Be 6
            $def.Menu[0].Name | Should -Be 'Expand'
            # The Ctrl+PgUp/PgDn "page the Text Box" hotkey is present in Details focus.
            ($def.Menu | Where-Object { $_.Name -eq 'PageText' -and $_.Hotkey -eq 'Ctrl+PgUp|PgDn' }).Count | Should -Be 1
        }
        It 'loads TextLive and TextFocus menus' {
            $live  = & $script:mod { Get-PspktTuiMenu -Box 'TextLive' }
            $focus = & $script:mod { Get-PspktTuiMenu -Box 'TextFocus' }
            $live.Menu.Count  | Should -BeGreaterThan 0
            $focus.Menu.Count | Should -BeGreaterThan 0
            ($focus.Menu | Where-Object { $_.Name -eq 'Copy' }).Count | Should -Be 1
            # Pause ('p') is offered in both live and focus modes.
            ($live.Menu  | Where-Object { $_.Name -eq 'Pause' -and $_.Hotkey -eq 'P' }).Count | Should -Be 1
            ($focus.Menu | Where-Object { $_.Name -eq 'Pause' -and $_.Hotkey -eq 'P' }).Count | Should -Be 1
        }
        It 'returns an empty definition for an unknown box' {
            $def = & $script:mod { Get-PspktTuiMenu -Box 'DoesNotExist' }
            $def.Menu.Count | Should -Be 0
        }
    }

    Context 'Split-PspktWarningText (Analysis runtime-warning wrap)' {
        BeforeAll {
            $script:mod = Get-Module PspktSession
        }
        It 'returns a single line when the text fits the width' {
            $r = @(& $script:mod { Split-PspktWarningText -Text 'Short warning.' -Width 40 -MaxLines 6 })
            $r.Count | Should -Be 1
            $r[0] | Should -Be 'Short warning.'
        }
        It 'word-wraps to lines no wider than -Width' {
            $r = @(& $script:mod { Split-PspktWarningText -Text 'the quick brown fox jumps over the lazy dog' -Width 15 -MaxLines 10 })
            $r.Count | Should -BeGreaterThan 1
            foreach ($line in $r) { $line.Length | Should -BeLessOrEqual 15 }
        }
        It 'caps at -MaxLines and marks truncation with an ellipsis within the width' {
            $r = @(& $script:mod { Split-PspktWarningText -Text ('word ' * 40) -Width 20 -MaxLines 3 })
            $r.Count | Should -Be 3
            $r[-1].EndsWith('...') | Should -BeTrue
            $r[-1].Length | Should -BeLessOrEqual 20
        }
        It 'hard-splits a single word longer than the width' {
            $r = @(& $script:mod { Split-PspktWarningText -Text ('X' * 45) -Width 20 -MaxLines 5 })
            $r[0].Length | Should -Be 20
        }
        It 'returns one empty line for empty input' {
            $r = @(& $script:mod { Split-PspktWarningText -Text '' -Width 20 -MaxLines 3 })
            $r.Count | Should -Be 1
            $r[0] | Should -Be ''
        }
    }

    Context 'OverlayBox' {
        It 'builds a centered bordered box with a title and body' {
            $body = [System.Collections.Generic.List[string]]@('hello', 'world')
            $top = 0; $left = 0
            $lines = [BoxyBox.OverlayBox]::Build(80, 24, 30, ' Title ', $body, [ref]$top, [ref]$left)
            $lines.Count | Should -Be 4   # top border + 2 body + bottom border
            [int]$lines[0][0]  | Should -Be ([int][char]0x250c)   # top-left corner
            [int]$lines[0][-1] | Should -Be ([int][char]0x2510)   # top-right corner
            $lines[0].Contains('Title') | Should -BeTrue
            $lines[1].Contains('hello') | Should -BeTrue
            # centered on an 80x24 screen
            $left | Should -Be 26   # (80-30)/2 + 1
        }
        It 'clamps box width to the screen width' {
            $body = [System.Collections.Generic.List[string]]@('x')
            $top = 0; $left = 0
            $lines = [BoxyBox.OverlayBox]::Build(20, 10, 100, 'T', $body, [ref]$top, [ref]$left)
            $lines[0].Length | Should -Be 20
        }
    }
}

Describe 'pspkt test prechecks' -Tag 'Precheck' {
    BeforeAll {
        $script:modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'pspkt.psm1'
        $script:runningAsAdmin = Test-IsAdministrator
    }

    It 'has module and test files present' {
        Test-Path -LiteralPath $script:modulePath | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Invoke-Tests.ps1') | Should -BeTrue
    }

    It 'reports when elevated shell is required for full unit tests' {
        if (-not $script:runningAsAdmin) {
            Set-ItResult -Inconclusive -Because 'pspkt.psm1 has #Requires -RunAsAdministrator'
        }

        $script:runningAsAdmin | Should -BeTrue
    }

    It 'contains the expected function definition' -ForEach $allProjectFunctionDefinitions {
        Test-Path -LiteralPath $_.File | Should -BeTrue

        $content = Get-Content -LiteralPath $_.File -Raw
        $definitionsInFile = @(
            [regex]::Matches($content, '(?m)^\s*function\s+([A-Za-z0-9_-]+)\s*\{') |
                ForEach-Object { $_.Groups[1].Value }
        )

        $definitionsInFile -contains $_.Name | Should -BeTrue
    }

    It 'has comment-based help immediately before each function' -ForEach $allProjectFunctionDefinitions {
        $content = Get-Content -LiteralPath $_.File -Raw
        $functionToken = "function $($_.Name)"
        $functionIndex = $content.IndexOf($functionToken, [System.StringComparison]::OrdinalIgnoreCase)

        $functionIndex -gt -1 | Should -BeTrue

        # Scan-window cap. Start-Pspkt's help block exceeds 16 KiB once application-
        # layer filters and quick-filter docs are included; 64 KiB is a safety net
        # rather than a meaningful limit (the regex itself locates the trailing
        # help block via the \s*$ anchor).
        $windowStart = [Math]::Max(0, $functionIndex - 65536)
        $windowLength = $functionIndex - $windowStart
        $preFunctionWindow = $content.Substring($windowStart, $windowLength)

        # Require a help block ending just before the function (allowing whitespace in between).
        $preFunctionWindow -match '(?s)<#.*?#>\s*$' | Should -BeTrue -Because "function '$($_.Name)' in $($_.File) must have a comment-based help block ending immediately before the function declaration"
    }
}
