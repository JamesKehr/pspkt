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
            $a = [DnsParser]::FormatDnsFromContext([ref]$ctx, $script:dnsQueryExampleA.Length)
            $b = [DnsParser]::FormatDnsSegment($script:dnsQueryExampleA, 53, 12345)
            $a | Should -Be $b
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

        It 'HttpParser.FormatHttpFromContext renders Detailed line' {
            $ctx = [HttpContext]::new()
            $null = [HttpParser]::TryParseHttp($script:httpReqGet, [ref]$ctx)
            $line = [HttpParser]::FormatHttpFromContext([ref]$ctx)
            $line | Should -Match '^HTTP - GET /api/users\?id=1 HTTP/1\.1'
            $line | Should -Match 'Host: api\.example\.com'
            $line | Should -Match 'Content-Type: application/json'
            $line | Should -Match 'Content-Length: 0'
        }

        It 'HttpParser.FormatHttpSegment short form' {
            $line = [HttpParser]::FormatHttpSegment($script:httpReqGet, $script:httpReqGet.Length)
            $line | Should -Be 'GET /api/users?id=1 HTTP/1.1'
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
            $line | Should -Match '^DHCP Discover'
            $line | Should -Match 'xid: 0xdeadbeef'
            $line | Should -Match 'chaddr: aa-bb-cc-dd-ee-ff'
        }

        It 'DhcpParser.FormatDhcpFromContext renders v6 Solicit line' {
            $ctx = [DhcpContext]::new()
            $null = [DhcpParser]::TryParseDhcp($script:dhcpV6Solicit, 546, 547, [ref]$ctx)
            $line = [DhcpParser]::FormatDhcpFromContext([ref]$ctx)
            $line | Should -Match '^DHCPv6 Solicit'
            $line | Should -Match 'txid: 0xabcd01'
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
