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

        $windowStart = [Math]::Max(0, $functionIndex - 16000)
        $windowLength = $functionIndex - $windowStart
        $preFunctionWindow = $content.Substring($windowStart, $windowLength)

        # Require a help block ending just before the function (allowing whitespace in between).
        $preFunctionWindow -match '(?s)<#.*?#>\s*$' | Should -BeTrue
    }
}
