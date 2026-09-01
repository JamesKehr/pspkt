#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Host classifier vector parity' -Tag 'Precheck' {
    BeforeAll {
        $script:repoRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
        $script:certRoot = [System.IO.Path]::Combine($script:repoRoot, 'certification')
        $script:generatorPath = [System.IO.Path]::Combine($script:certRoot, 'vectors', 'New-PspktHostClassifierFixtures.ps1')
        $script:validatorPath = [System.IO.Path]::Combine($script:certRoot, 'validators', 'Test-PspktHostClassifierVectorParity.ps1')
        $script:hostPath = (Get-Process -Id $PID).Path
        $script:ownedScratch = New-Object 'System.Collections.Generic.List[string]'
        $nativeSourcePath = [System.IO.Path]::Combine($script:certRoot, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs')
        [byte[]]$nativeSourceBytes = [System.IO.File]::ReadAllBytes($nativeSourcePath)
        if ($nativeSourceBytes.Length -ne 22637 -or
            ($nativeSourceBytes.Length -ge 3 -and $nativeSourceBytes[0] -eq 0xEF -and $nativeSourceBytes[1] -eq 0xBB -and $nativeSourceBytes[2] -eq 0xBF) -or
            @($nativeSourceBytes | Where-Object { $_ -eq 13 }).Count -ne 0) {
            throw 'Host-classifier process containment helper source format or length is invalid.'
        }
        $nativeSha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $nativeSourceHash = ([BitConverter]::ToString($nativeSha.ComputeHash($nativeSourceBytes))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $nativeSha.Dispose()
        }
        if ($nativeSourceHash -cne '666e71c53ed6572db5d7b1c7e21bae3a938fea045bc03bf22e8e84ac9a6439be') {
            throw 'Host-classifier process containment helper source digest is invalid.'
        }
        $nativeSourceText = [System.Text.UTF8Encoding]::new($false, $true).GetString($nativeSourceBytes)
        $nativeTestNamespace = 'Pspkt.Certification.TestHost' + [guid]::NewGuid().ToString('N')
        $nativeTestSourceText = $nativeSourceText.Replace(
            'namespace Pspkt.Certification',
            ('namespace {0}' -f $nativeTestNamespace))
        if ($nativeTestSourceText -ceq $nativeSourceText) {
            throw 'Host-classifier process containment helper test namespace was not replaced.'
        }
        Add-Type -TypeDefinition $nativeTestSourceText -Language CSharp
        $script:nativeType = ('{0}.HostClassifierVectorNativeV1' -f $nativeTestNamespace) -as [type]
        $buildMarkerProperty = $null
        if ($null -ne $script:nativeType) {
            $buildMarkerProperty = $script:nativeType.GetProperty('BuildMarker', [System.Reflection.BindingFlags]'Public,Static')
        }
        if ($null -eq $script:nativeType -or $null -eq $buildMarkerProperty -or
            [string]$buildMarkerProperty.GetValue($null, $null) -cne 'pspkt-host-classifier-vector-native-5') {
            throw 'Host-classifier process containment helper did not load with the expected build marker.'
        }
        $script:expectedVectorHashes = @{
            'host-classifier/negative-ambiguous-ancestry.json' = '4c98d09f60c3824964205018577ef3e8d7e1ca1ee5e0577d6b50acebaa846b56'
            'host-classifier/negative-missing-window.json' = '5fdcdc70449ad85aab60d0932eaf892c55109b03bf5a4d9fd84e77bf3bc82d4f'
            'host-classifier/negative-openconsole.json' = '92b0993d613ad673a61d4e3e679c8c66993e4a3a47bd7ea71f1fc21e91a95568'
            'host-classifier/negative-spoofed-environment.json' = 'd04061c4a44a6997329e122c285ac1d9b0f69ce5913aa8790b533b614cf9fffc'
            'host-classifier/negative-stale-wt-session.json' = 'f1e940dff9b0a3c24012789db6039411c9d916d45e106a7901393c5ff274700d'
            'host-classifier/seat-conhost-powershell-7.json' = '569f7f1a5c47d7314ed54c7a636962eeeb3b858d95d6fd4709c1b14bd0b9b288'
            'host-classifier/seat-conhost-windows-powershell-5.1.json' = '6b08dc8782e278233b5dfc48ccc580c06d585e1a51288a7256376f62e7108660'
            'host-classifier/seat-windows-terminal-powershell-7.json' = '6e906074e737805eb34f5a3094f6d8e188b6cfb9d620291f836746d684d95c14'
            'host-classifier/seat-windows-terminal-windows-powershell-5.1.json' = 'cdc1b866c5c55cf76dbf0a55fb2f6ff86346d1dc9224147b719bc8d1d00dc3af'
            'certification-result/sample-artifact.v1.json' = '9eb691fd0411acf2a029630f0a2ef7ba82dfa5083527d3b5453b708cce3a7f2d'
            'certification-result/sample-attestation.v1.json' = 'ad6b01e3261c5a19e26a840893be93c10a355fa1a993ad248bd02ad4a0411fc0'
        }
    }

    function script:Get-PspktTestSha256 {
        param([Parameter(Mandatory = $true)][string]$Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $hash = $sha.ComputeHash($bytes)
        }
        finally {
            $sha.Dispose()
        }
        $builder = [System.Text.StringBuilder]::new($hash.Length * 2)
        foreach ($hashByte in $hash) {
            [void]$builder.Append(('{0:x2}' -f [int]$hashByte))
        }
        return $builder.ToString()
    }

    function script:ConvertTo-PspktTestSingleQuotedLiteral {
        param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
        return "'" + $Value.Replace("'", "''") + "'"
    }

    function script:Copy-PspktTestCertificationRoot {
        param([Parameter(Mandatory = $true)][string]$Name)
        $physicalRoot = [System.IO.Path]::GetFullPath($TestDrive)
        $scenarioParent = [System.IO.Path]::Combine($physicalRoot, $Name)
        [void][System.IO.Directory]::CreateDirectory($scenarioParent)
        Copy-Item -LiteralPath $script:certRoot -Destination $scenarioParent -Recurse -Force
        return [System.IO.Path]::Combine($scenarioParent, 'certification')
    }

    function script:Assert-PspktTestVectorHashes {
        param([Parameter(Mandatory = $true)][string]$CertificationRoot)
        foreach ($relativePath in $script:expectedVectorHashes.Keys) {
            $vectorPath = [System.IO.Path]::Combine(
                $CertificationRoot,
                'vectors',
                ($relativePath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
            (Get-PspktTestSha256 -Path $vectorPath) | Should -BeExactly $script:expectedVectorHashes[$relativePath]
        }
    }

    function script:Invoke-PspktTestHost {
        param(
            [Parameter(Mandatory = $true)][string]$Command,
            [string]$HostPath = $script:hostPath,
            [int]$TimeoutMilliseconds = 180000
        )
        $gateToken = [guid]::NewGuid().ToString('N')
        $gatedCommand = '$gateToken = [Console]::In.ReadLine(); if ($gateToken -cne {0}) {{ throw ''test child gate rejected'' }}; {1}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $gateToken),
            $Command
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($gatedCommand))
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $HostPath
        $startInfo.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encodedCommand
        $startInfo.WorkingDirectory = $script:repoRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.RedirectStandardInput = $true
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        $job = $script:nativeType::CreateProcessJob()
        $started = $false
        try {
            [void]$process.Start()
            $started = $true
            $job.AssignProcess($process.Handle)
            $process.StandardInput.WriteLine($gateToken)
            $process.StandardInput.Close()
            $stdoutTask = $script:nativeType::ReadStreamCappedAsync($process.StandardOutput.BaseStream, 4194304)
            $stderrTask = $script:nativeType::ReadStreamCappedAsync($process.StandardError.BaseStream, 4194304)
            $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
            while (-not $process.WaitForExit(50)) {
                if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted) {
                    if ($null -ne $job) {
                        $job.Dispose()
                        $job = $null
                    }
                    [void]$process.WaitForExit(10000)
                    [void]$stdoutTask.GetAwaiter().GetResult()
                    [void]$stderrTask.GetAwaiter().GetResult()
                }
                if ($waitClock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                    if ($null -ne $job) {
                        $job.Dispose()
                        $job = $null
                    }
                    if (-not $process.WaitForExit(10000)) {
                        throw 'Test child did not exit after Job termination.'
                    }
                    throw 'Test child timed out.'
                }
            }
            $waitClock.Stop()
            if ($null -ne $job) {
                $job.Dispose()
                $job = $null
            }
            [byte[]]$stdoutBytes = $stdoutTask.GetAwaiter().GetResult()
            [byte[]]$stderrBytes = $stderrTask.GetAwaiter().GetResult()
            $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
            $stdout = $utf8.GetString($stdoutBytes)
            $stderr = $utf8.GetString($stderrBytes)
            return [pscustomobject]@{
                ExitCode = $process.ExitCode
                Stdout = $stdout
                Stderr = $stderr
            }
        }
        finally {
            if ($null -ne $job) {
                $job.Dispose()
            }
            if ($started) {
                try {
                    if (-not $process.HasExited) {
                        $process.Kill()
                        [void]$process.WaitForExit(10000)
                    }
                }
                catch [System.InvalidOperationException] {
                    if (-not $process.HasExited) {
                        throw
                    }
                }
            }
            $process.Dispose()
        }
    }

    function script:Remove-PspktOwnedTree {
        param([Parameter(Mandatory = $true)][string]$Path)
        if (-not [System.IO.Directory]::Exists($Path)) {
            return
        }
        $rootAttributes = [System.IO.File]::GetAttributes($Path)
        if (($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            [System.IO.Directory]::Delete($Path)
            return
        }
        $directory = [System.IO.DirectoryInfo]::new($Path)
        foreach ($entry in $directory.GetFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    [System.IO.Directory]::Delete($entry.FullName)
                }
                else {
                    Remove-PspktOwnedTree -Path $entry.FullName
                }
            }
            else {
                [System.IO.File]::SetAttributes($entry.FullName, [System.IO.FileAttributes]::Normal)
                [System.IO.File]::Delete($entry.FullName)
            }
        }
        [System.IO.Directory]::Delete($Path)
    }

    AfterAll {
        $cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
        for ($scratchIndex = $script:ownedScratch.Count - 1; $scratchIndex -ge 0; $scratchIndex--) {
            $scratchPath = $script:ownedScratch[$scratchIndex]
            try {
                if ([System.IO.Directory]::Exists($scratchPath)) {
                    Remove-PspktOwnedTree -Path $scratchPath
                }
                if ([System.IO.Directory]::Exists($scratchPath)) {
                    [void]$cleanupFailures.Add(('owned scratch still present: {0}' -f $scratchPath))
                }
            }
            catch {
                [void]$cleanupFailures.Add(('scratch cleanup failed for {0}: {1}' -f $scratchPath, $_.Exception.Message))
            }
        }
        if ($cleanupFailures.Count -gt 0) {
            throw ($cleanupFailures -join [Environment]::NewLine)
        }
    }

    It 'validates repository vectors with the verified repository-root fossil contract' {
        Assert-PspktTestVectorHashes -CertificationRoot $script:certRoot
        Push-Location $script:repoRoot
        try {
            $command = '& {0} -CertificationRoot ''.\certification'' -RepositoryRoot ''.''' -f (
                ConvertTo-PspktTestSingleQuotedLiteral -Value $script:validatorPath)
            $result = Invoke-PspktTestHost -Command $command
        }
        finally {
            Pop-Location
        }
        $result.ExitCode | Should -Be 0
        ($result.Stdout + $result.Stderr) | Should -Match 'vector validation: 11 of 11 pass'
    }

    It 'covers host-classifier outcomes not represented by committed vectors' {
        . ([System.IO.Path]::Combine($script:certRoot, 'lib', 'Pspkt.Certification.HostClassifier.ps1'))
        $cases = @(
            @{
                ExpectedTerminalKind = 'unknown'
                ExpectedShellKind = 'powershell-7'
                ExpectedArchitecture = 'x64'
                ExpectedReason = 'simultaneous-positive-classification'
                Probe = @{
                    WtSession = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'
                    ConsoleWindow = 132048
                    OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'
                    Ancestry = @('pwsh.exe', 'WindowsTerminal.exe', 'conhost.exe')
                    ShellEdition = 'Core'
                    ShellVersionMajor = 7
                    ShellVersionMinor = 6
                    Architecture = 'x64'
                    SystemRoot = 'C:\WINDOWS'
                }
            },
            @{
                ExpectedTerminalKind = 'unknown'
                ExpectedShellKind = 'powershell-7'
                ExpectedArchitecture = 'x64'
                ExpectedReason = 'ambiguous-ancestry-conhost-owner-without-ancestor'
                Probe = @{
                    WtSession = ''
                    ConsoleWindow = 132048
                    OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'
                    Ancestry = @('pwsh.exe')
                    ShellEdition = 'Core'
                    ShellVersionMajor = 7
                    ShellVersionMinor = 6
                    Architecture = 'x64'
                    SystemRoot = 'C:\WINDOWS'
                }
            },
            @{
                ExpectedTerminalKind = 'unknown'
                ExpectedShellKind = 'powershell-7'
                ExpectedArchitecture = 'x64'
                ExpectedReason = 'missing-owner-image'
                Probe = @{
                    WtSession = ''
                    ConsoleWindow = 132048
                    OwnerImagePath = ''
                    Ancestry = @('pwsh.exe', 'conhost.exe')
                    ShellEdition = 'Core'
                    ShellVersionMajor = 7
                    ShellVersionMinor = 6
                    Architecture = 'x64'
                    SystemRoot = 'C:\WINDOWS'
                }
            }
        )
        foreach ($case in $cases) {
            $result = Resolve-PspktHostSeat -Probe $case.Probe
            $result.TerminalKind | Should -BeExactly $case.ExpectedTerminalKind
            $result.ShellKind | Should -BeExactly $case.ExpectedShellKind
            $result.Architecture | Should -BeExactly $case.ExpectedArchitecture
            $result.Status | Should -BeExactly 'fail'
            $result.Reason | Should -BeExactly $case.ExpectedReason
            $result.HostKey | Should -BeNullOrEmpty
        }
        $mixedCaseArchitecture = Resolve-PspktHostSeat -Probe @{
            WtSession = ''
            ConsoleWindow = 132048
            OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'
            Ancestry = @('pwsh.exe', 'conhost.exe', 'explorer.exe')
            ShellEdition = 'Core'
            ShellVersionMajor = 7
            ShellVersionMinor = 6
            Architecture = 'X64'
            SystemRoot = 'C:\WINDOWS'
        }
        $mixedCaseArchitecture.TerminalKind | Should -BeExactly 'conhost'
        $mixedCaseArchitecture.ShellKind | Should -BeExactly 'powershell-7'
        $mixedCaseArchitecture.Architecture | Should -BeExactly 'x64'
        $mixedCaseArchitecture.Status | Should -BeExactly 'pass'
        $mixedCaseArchitecture.Reason | Should -BeExactly 'conhost-signature'
        @($mixedCaseArchitecture.HostKey) | Should -BeExactly @('conhost', 'powershell-7', 'x64')
    }

    It 'resolves Git authority from an x86 Windows PowerShell host when available' -Skip:(-not [System.Environment]::Is64BitOperatingSystem) {
        $x86HostPath = [System.IO.Path]::Combine(
            [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows),
            'SysWOW64',
            'WindowsPowerShell',
            'v1.0',
            'powershell.exe')
        [System.IO.File]::Exists($x86HostPath) | Should -BeTrue
        $command = '& {0} -CertificationRoot {1} -RepositoryRoot {2}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $script:validatorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $script:certRoot),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $script:repoRoot)
        $result = Invoke-PspktTestHost -Command $command -HostPath $x86HostPath
        $result.ExitCode | Should -Be 0
        ($result.Stdout + $result.Stderr) | Should -Match 'git attribute and checkout proof: pass'
    }

    It 'runs ordinary and fault scenarios in one child over independent roots' {
        $physicalRoot = [System.IO.Path]::GetFullPath($TestDrive)
        $childScript = [System.IO.Path]::Combine($physicalRoot, 'child-ordinary.ps1')
        $childBody = @'
param(
    [Parameter(Mandatory = $true)][string]$HostPath,
    [Parameter(Mandatory = $true)][string]$SourceCertRoot,
    [Parameter(Mandatory = $true)][string]$WorkRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Copy-Shape([string]$Name) {
    $dest = [System.IO.Path]::Combine($WorkRoot, $Name, 'certification')
    $pairs = @(
        'lib\Pspkt.Certification.CanonicalJson.ps1',
        'lib\Pspkt.Certification.Math.ps1',
        'lib\Pspkt.Certification.HostClassifier.ps1',
        'lib\Pspkt.Certification.HostClassifierVectorNative.cs',
        '.gitattributes',
        'vectors\New-PspktHostClassifierFixtures.ps1',
        'validators\Test-PspktHostClassifierVectorParity.ps1',
        'vectors\host-classifier\negative-ambiguous-ancestry.json',
        'vectors\host-classifier\negative-missing-window.json',
        'vectors\host-classifier\negative-openconsole.json',
        'vectors\host-classifier\negative-spoofed-environment.json',
        'vectors\host-classifier\negative-stale-wt-session.json',
        'vectors\host-classifier\seat-conhost-powershell-7.json',
        'vectors\host-classifier\seat-conhost-windows-powershell-5.1.json',
        'vectors\host-classifier\seat-windows-terminal-powershell-7.json',
        'vectors\host-classifier\seat-windows-terminal-windows-powershell-5.1.json',
        'vectors\certification-result\sample-artifact.v1.json',
        'vectors\certification-result\sample-attestation.v1.json'
    )
    foreach ($rel in $pairs) {
        $src = [System.IO.Path]::Combine($SourceCertRoot, $rel)
        $dst = [System.IO.Path]::Combine($dest, $rel)
        $parent = [System.IO.Path]::GetDirectoryName($dst)
        if (-not [System.IO.Directory]::Exists($parent)) { [void][System.IO.Directory]::CreateDirectory($parent) }
        [System.IO.File]::Copy($src, $dst, $true)
    }
    return $dest
}
function Get-Gen([string]$Cert) { [System.IO.Path]::Combine($Cert, 'vectors', 'New-PspktHostClassifierFixtures.ps1') }
function Get-Val([string]$Cert) { [System.IO.Path]::Combine($Cert, 'validators', 'Test-PspktHostClassifierVectorParity.ps1') }
$helperTypeName = 'Pspkt.Certification.HostClassifierVectorNativeV1'
if ($null -eq ($helperTypeName -as [type])) {
    $cs = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($SourceCertRoot, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs'))
    Add-Type -TypeDefinition $cs -Language CSharp
}
$helper = $helperTypeName -as [type]
if ($null -eq $helper) { throw 'native helper type was not loaded in the ordinary child' }
function Quote-Literal([string]$Value) { "'" + $Value.Replace("'", "''") + "'" }
function Invoke-FreshHost([string]$Command) {
    $gateToken = [guid]::NewGuid().ToString('N')
    $gateLiteral = "'" + $gateToken + "'"
    $gatedCommand = '$gateToken = [Console]::In.ReadLine(); if ($gateToken -cne {0}) {{ throw ''fresh child gate rejected'' }}; {1}' -f $gateLiteral, $Command
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($gatedCommand))
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $HostPath
    $startInfo.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    $startInfo.WorkingDirectory = $WorkRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $job = $helper::CreateProcessJob()
    $started = $false
    try {
        [void]$process.Start()
        $started = $true
        $job.AssignProcess($process.Handle)
        $process.StandardInput.WriteLine($gateToken)
        $process.StandardInput.Close()
        $stdoutTask = $helper::ReadStreamCappedAsync($process.StandardOutput.BaseStream, 4194304)
        $stderrTask = $helper::ReadStreamCappedAsync($process.StandardError.BaseStream, 4194304)
        $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $process.WaitForExit(50)) {
            if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted) {
                if ($null -ne $job) {
                    $job.Dispose()
                    $job = $null
                }
                [void]$process.WaitForExit(10000)
                [void]$stdoutTask.GetAwaiter().GetResult()
                [void]$stderrTask.GetAwaiter().GetResult()
            }
            if ($waitClock.ElapsedMilliseconds -ge 60000) {
                if ($null -ne $job) {
                    $job.Dispose()
                    $job = $null
                }
                if (-not $process.WaitForExit(10000)) { throw 'fresh child did not exit after Job termination' }
                throw 'fresh child timed out'
            }
        }
        $waitClock.Stop()
        if ($null -ne $job) {
            $job.Dispose()
            $job = $null
        }
        [byte[]]$stdoutBytes = $stdoutTask.GetAwaiter().GetResult()
        [byte[]]$stderrBytes = $stderrTask.GetAwaiter().GetResult()
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        return @{
            Code = $process.ExitCode
            Out = $utf8.GetString($stdoutBytes)
            Err = $utf8.GetString($stderrBytes)
        }
    }
    finally {
        if ($null -ne $job) { $job.Dispose() }
        if ($started) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(10000)
                }
            }
            catch [System.InvalidOperationException] {
                if (-not $process.HasExited) {
                    throw
                }
            }
        }
        $process.Dispose()
    }
}
function Invoke-Gen([string]$Cert, [int]$SimulateFailureAfterRepairCount = -1) {
    $command = '& {0}' -f (Quote-Literal (Get-Gen $Cert))
    if ($SimulateFailureAfterRepairCount -ge 0) {
        $command += ' -SimulateFailureAfterRepairCount ' + [string]$SimulateFailureAfterRepairCount
    }
    return Invoke-FreshHost -Command $command
}
function Invoke-Val([string]$Cert) {
    return Invoke-FreshHost -Command ('& {0} -CertificationRoot {1}' -f (Quote-Literal (Get-Val $Cert)), (Quote-Literal $Cert))
}
function Get-Sha256([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash($Bytes))
    }
    finally {
        $sha.Dispose()
    }
}

try {
$pristine = Copy-Shape 'pristine'
$first = Invoke-Gen $pristine
if ($first.Code -ne 0) { throw ('pristine first generate failed: ' + $first.Out + $first.Err) }
$second = Invoke-Gen $pristine
if ($second.Code -ne 0) { throw ('pristine second generate failed: ' + $second.Out + $second.Err) }
if ($second.Out -notmatch '11 of 11 unchanged') { throw ('idempotence missing: ' + $second.Out) }
$validated = Invoke-Val $pristine
if ($validated.Code -ne 0) { throw ('pristine validator failed: ' + $validated.Out + $validated.Err) }

$corrupt = Copy-Shape 'corrupt'
$corruptLeaf = [System.IO.Path]::Combine($corrupt, 'vectors', 'host-classifier', 'negative-missing-window.json')
$corpusRelativePaths = @(
    'vectors\host-classifier\negative-ambiguous-ancestry.json',
    'vectors\host-classifier\negative-missing-window.json',
    'vectors\host-classifier\negative-openconsole.json',
    'vectors\host-classifier\negative-spoofed-environment.json',
    'vectors\host-classifier\negative-stale-wt-session.json',
    'vectors\host-classifier\seat-conhost-powershell-7.json',
    'vectors\host-classifier\seat-conhost-windows-powershell-5.1.json',
    'vectors\host-classifier\seat-windows-terminal-powershell-7.json',
    'vectors\host-classifier\seat-windows-terminal-windows-powershell-5.1.json',
    'vectors\certification-result\sample-artifact.v1.json',
    'vectors\certification-result\sample-attestation.v1.json'
)
function Get-CorpusManifest([string]$Cert) {
    $manifest = @{}
    foreach ($relativePath in $corpusRelativePaths) {
        $fullPath = [System.IO.Path]::Combine($Cert, $relativePath)
        if (-not [System.IO.File]::Exists($fullPath)) {
            $manifest[$relativePath] = @{ Exists = $false }
            continue
        }
        $handle = $helper::OpenFile($fullPath, $false)
        try {
            $bytes = $handle.ReadExact()
            $manifest[$relativePath] = @{
                Exists = $true
                Volume = $handle.VolumeSerialNumber
                FileIndex = $handle.FileIndex
                Links = $handle.NumberOfLinks
                Length = $bytes.Length
                Sha256 = Get-Sha256 -Bytes $bytes
            }
        }
        finally {
            $handle.Dispose()
        }
    }
    return $manifest
}
function Assert-CorpusManifest($Expected, [string]$Cert, [string]$Label) {
    $actual = Get-CorpusManifest -Cert $Cert
    foreach ($relativePath in $corpusRelativePaths) {
        $before = $Expected[$relativePath]
        $after = $actual[$relativePath]
        if ([bool]$before.Exists -ne [bool]$after.Exists) { throw ('{0} changed existence for {1}' -f $Label, $relativePath) }
        if (-not [bool]$before.Exists) { continue }
        foreach ($field in @('Volume', 'FileIndex', 'Links', 'Length', 'Sha256')) {
            if ([string]$before[$field] -cne [string]$after[$field]) {
                throw ('{0} changed {1} for {2}' -f $Label, $field, $relativePath)
            }
        }
    }
}
$before = $helper::OpenFile($corruptLeaf, $false)
try {
    $vol = $before.VolumeSerialNumber
    $idx = $before.FileIndex
} finally { $before.Dispose() }
$append = [System.IO.File]::Open($corruptLeaf, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
try { [void]$append.Seek(0, [System.IO.SeekOrigin]::End); $append.WriteByte(10) } finally { $append.Dispose() }
$repaired = Invoke-Gen $corrupt
if ($repaired.Code -ne 0) { throw ('corrupt repair failed: ' + $repaired.Out + $repaired.Err) }
if ($repaired.Out -notmatch 'repaired host-classifier/negative-missing-window.json') { throw ('repair reason missing: ' + $repaired.Out) }
$after = $helper::OpenFile($corruptLeaf, $false)
try {
    if ($after.VolumeSerialNumber -ne $vol -or $after.FileIndex -ne $idx) { throw 'corrupt repair changed file identity' }
} finally { $after.Dispose() }
$repairIdem = Invoke-Gen $corrupt
if ($repairIdem.Out -notmatch '11 of 11 unchanged') { throw ('repair was not idempotent: ' + $repairIdem.Out) }

$rollback = Copy-Shape 'rollback'
$rollbackFirst = [System.IO.Path]::Combine($rollback, 'vectors', 'host-classifier', 'seat-windows-terminal-powershell-7.json')
$rollbackSecond = [System.IO.Path]::Combine($rollback, 'vectors', 'host-classifier', 'seat-windows-terminal-windows-powershell-5.1.json')
[System.IO.File]::AppendAllText($rollbackFirst, "`n")
[System.IO.File]::AppendAllText($rollbackSecond, "`n")
$rollbackManifest = Get-CorpusManifest -Cert $rollback
$rollbackResult = Invoke-Gen $rollback -SimulateFailureAfterRepairCount 1
if ($rollbackResult.Code -eq 0) { throw 'simulated rollback failure succeeded' }
if (($rollbackResult.Err + $rollbackResult.Out) -notmatch 'simulated write failure after 1 repairs') { throw ('simulated rollback reason mismatch: ' + $rollbackResult.Out + $rollbackResult.Err) }
Assert-CorpusManifest -Expected $rollbackManifest -Cert $rollback -Label 'simulated write rollback'

$missing = Copy-Shape 'missing'
$missingLeaf = [System.IO.Path]::Combine($missing, 'vectors', 'host-classifier', 'negative-openconsole.json')
$snapshot = @{}
$hcDir = [System.IO.Path]::Combine($missing, 'vectors', 'host-classifier')
foreach ($leaf in [System.IO.Directory]::GetFiles($hcDir)) {
    $h = $helper::OpenFile($leaf, $false)
    try {
        $bytes = $h.ReadExact()
        $snapshot[$leaf] = @{ Vol = $h.VolumeSerialNumber; Idx = $h.FileIndex; Len = $bytes.Length; Sha = Get-Sha256 -Bytes $bytes }
    } finally { $h.Dispose() }
}
[System.IO.File]::Delete($missingLeaf)
$missingManifest = Get-CorpusManifest -Cert $missing
$missingResult = Invoke-Gen $missing
if ($missingResult.Code -eq 0) { throw 'missing leaf succeeded' }
if (($missingResult.Err + $missingResult.Out) -notmatch 'missing leaf') { throw ('missing leaf reason mismatch: ' + $missingResult.Out + $missingResult.Err) }
if ([System.IO.File]::Exists($missingLeaf)) { throw 'missing leaf was recreated' }
Assert-CorpusManifest -Expected $missingManifest -Cert $missing -Label 'missing-leaf rejection'
foreach ($leaf in $snapshot.Keys) {
    if ($leaf -eq $missingLeaf) { continue }
    $h = $helper::OpenFile($leaf, $false)
    try {
        $bytes = $h.ReadExact()
        $sha = Get-Sha256 -Bytes $bytes
        if ($h.VolumeSerialNumber -ne $snapshot[$leaf].Vol -or $h.FileIndex -ne $snapshot[$leaf].Idx -or $bytes.Length -ne $snapshot[$leaf].Len -or $sha -cne $snapshot[$leaf].Sha) {
            throw ('missing-leaf mutated {0}' -f $leaf)
        }
    } finally { $h.Dispose() }
}

$hard = Copy-Shape 'hardlink'
$hardEarlierLeaf = [System.IO.Path]::Combine($hard, 'vectors', 'host-classifier', 'seat-windows-terminal-powershell-7.json')
$hardEarlierStream = [System.IO.File]::Open($hardEarlierLeaf, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
try {
    [void]$hardEarlierStream.Seek(0, [System.IO.SeekOrigin]::End)
    $hardEarlierStream.WriteByte(10)
}
finally {
    $hardEarlierStream.Dispose()
}
$hardEarlierBytes = [System.IO.File]::ReadAllBytes($hardEarlierLeaf)
$hardEarlierSha = Get-Sha256 -Bytes $hardEarlierBytes
$hardLeaf = [System.IO.Path]::Combine($hard, 'vectors', 'host-classifier', 'negative-spoofed-environment.json')
$peerDir = [System.IO.Path]::Combine($WorkRoot, 'hard-peer')
[void][System.IO.Directory]::CreateDirectory($peerDir)
$peer = [System.IO.Path]::Combine($peerDir, 'peer.json')
[System.IO.File]::Copy($hardLeaf, $peer, $true)
$peerBefore = $helper::OpenFile($peer, $false)
try { $peerVol = $peerBefore.VolumeSerialNumber; $peerIdx = $peerBefore.FileIndex; $peerLinks = $peerBefore.NumberOfLinks; $peerBytes = $peerBefore.ReadExact(); $peerSha = Get-Sha256 -Bytes $peerBytes } finally { $peerBefore.Dispose() }
if ($peerLinks -ne 1) { throw 'hardlink peer did not start with one link' }
[System.IO.File]::Delete($hardLeaf)
[void](New-Item -ItemType HardLink -Path $hardLeaf -Target $peer)
$hardManifest = Get-CorpusManifest -Cert $hard
$hardResult = Invoke-Gen $hard
if ($hardResult.Code -eq 0) { throw 'hardlink succeeded' }
if (($hardResult.Err + $hardResult.Out) -notmatch 'hardlink rejected') { throw ('hardlink reason mismatch: ' + $hardResult.Out + $hardResult.Err) }
Assert-CorpusManifest -Expected $hardManifest -Cert $hard -Label 'hardlink rejection'
$hardEarlierAfterBytes = [System.IO.File]::ReadAllBytes($hardEarlierLeaf)
if ((Get-Sha256 -Bytes $hardEarlierAfterBytes) -cne $hardEarlierSha) { throw 'hardlink failure repaired an earlier corrupted output' }
$peerAfter = $helper::OpenFile($peer, $false)
try {
    $afterBytes = $peerAfter.ReadExact()
    if ($peerAfter.VolumeSerialNumber -ne $peerVol -or $peerAfter.FileIndex -ne $peerIdx -or $peerAfter.NumberOfLinks -ne 2) { throw 'hardlink topology changed' }
    if ($afterBytes.Length -ne $peerBytes.Length -or (Get-Sha256 -Bytes $afterBytes) -cne $peerSha) { throw 'hardlink peer bytes changed' }
} finally { $peerAfter.Dispose() }

$hidden = Copy-Shape 'hidden'
$hiddenFile = [System.IO.Path]::Combine($hidden, 'vectors', 'host-classifier', 'extra.bin')
[System.IO.File]::WriteAllBytes($hiddenFile, [byte[]](1, 2, 3))
[System.IO.File]::SetAttributes($hiddenFile, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
$hiddenManifest = Get-CorpusManifest -Cert $hidden
$hiddenResult = Invoke-Gen $hidden
if ($hiddenResult.Code -eq 0) { throw 'hidden extra succeeded' }
if (($hiddenResult.Err + $hiddenResult.Out) -notmatch 'host-classifier inventory is not the exact nine ordinary JSON files') { throw ('hidden inventory reason mismatch: ' + $hiddenResult.Out + $hiddenResult.Err) }
Assert-CorpusManifest -Expected $hiddenManifest -Cert $hidden -Label 'hidden-entry rejection'

$extraDirRoot = Copy-Shape 'extradir'
$extraDir = [System.IO.Path]::Combine($extraDirRoot, 'vectors', 'host-classifier', 'nested')
[void][System.IO.Directory]::CreateDirectory($extraDir)
$extraDirectoryManifest = Get-CorpusManifest -Cert $extraDirRoot
$extraDirResult = Invoke-Gen $extraDirRoot
if ($extraDirResult.Code -eq 0) { throw 'extra directory succeeded' }
if (($extraDirResult.Err + $extraDirResult.Out) -notmatch 'host-classifier inventory is not the exact nine ordinary JSON files') { throw ('extra directory reason mismatch: ' + $extraDirResult.Out + $extraDirResult.Err) }
Assert-CorpusManifest -Expected $extraDirectoryManifest -Cert $extraDirRoot -Label 'extra-directory rejection'

$juncHost = Copy-Shape 'junchost'
$hostDir = [System.IO.Path]::Combine($juncHost, 'vectors', 'host-classifier')
$hostPeer = [System.IO.Path]::Combine($WorkRoot, 'host-peer')
[System.IO.Directory]::CreateDirectory($hostPeer) | Out-Null
foreach ($file in [System.IO.Directory]::GetFiles($hostDir)) {
    [System.IO.File]::Copy($file, [System.IO.Path]::Combine($hostPeer, [System.IO.Path]::GetFileName($file)), $true)
}
[System.IO.Directory]::Delete($hostDir, $true)
[void](New-Item -ItemType Junction -Path $hostDir -Target $hostPeer)
$hostJunctionManifest = Get-CorpusManifest -Cert $juncHost
try {
    $juncHostResult = Invoke-Gen $juncHost
    if ($juncHostResult.Code -eq 0) { throw 'host junction succeeded' }
    if (($juncHostResult.Err + $juncHostResult.Out) -notmatch 'reparse point rejected') { throw ('host junction reason mismatch: ' + $juncHostResult.Out + $juncHostResult.Err) }
    Assert-CorpusManifest -Expected $hostJunctionManifest -Cert $juncHost -Label 'host-junction rejection'
}
finally {
    [System.IO.Directory]::Delete($hostDir)
}

$juncLib = Copy-Shape 'junclib'
$libDir = [System.IO.Path]::Combine($juncLib, 'lib')
$libPeer = [System.IO.Path]::Combine($WorkRoot, 'lib-peer')
[System.IO.Directory]::CreateDirectory($libPeer) | Out-Null
foreach ($file in [System.IO.Directory]::GetFiles($libDir)) {
    [System.IO.File]::Copy($file, [System.IO.Path]::Combine($libPeer, [System.IO.Path]::GetFileName($file)), $true)
}
$canary = [System.IO.Path]::Combine($libPeer, 'Pspkt.Certification.HostClassifier.ps1')
[System.IO.File]::AppendAllText($canary, "`n[System.IO.File]::WriteAllText((Join-Path `$PSScriptRoot 'CANARY.txt'), 'ran')`n")
[System.IO.Directory]::Delete($libDir, $true)
[void](New-Item -ItemType Junction -Path $libDir -Target $libPeer)
$libJunctionManifest = Get-CorpusManifest -Cert $juncLib
try {
    $juncLibResult = Invoke-Gen $juncLib
    if ($juncLibResult.Code -eq 0) { throw 'lib junction succeeded' }
    if (($juncLibResult.Err + $juncLibResult.Out) -notmatch 'reparse point rejected') { throw ('lib junction reason mismatch: ' + $juncLibResult.Out + $juncLibResult.Err) }
    if ([System.IO.File]::Exists([System.IO.Path]::Combine($libPeer, 'CANARY.txt'))) { throw 'lib junction executed canary' }
    Assert-CorpusManifest -Expected $libJunctionManifest -Cert $juncLib -Label 'lib-junction rejection'
}
finally {
    [System.IO.Directory]::Delete($libDir)
}

$retain = Copy-Shape 'retain'
$retainFile = [System.IO.Path]::Combine($WorkRoot, 'retain-leaf.ps1')
[System.IO.File]::Copy([System.IO.Path]::Combine($retain, 'lib', 'Pspkt.Certification.CanonicalJson.ps1'), $retainFile, $true)
$retainHandle = $helper::OpenFile($retainFile, $false)
try {
    $retainVol = $retainHandle.VolumeSerialNumber
    $retainIdx = $retainHandle.FileIndex
    $retainBytes = $retainHandle.ReadExact()
    $retainSha = Get-Sha256 -Bytes $retainBytes
    $writeAllowed = $false
    try {
        $writer = [System.IO.File]::Open($retainFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $writer.Dispose()
        $writeAllowed = $true
    }
    catch {
        $writeAllowed = $false
    }
    if ($writeAllowed) { throw 'source retention allowed a writer' }
    $deleteAllowed = $false
    try {
        [System.IO.File]::Delete($retainFile)
        $deleteAllowed = $true
    }
    catch {
        $deleteAllowed = $false
    }
    if ($deleteAllowed) { throw 'source retention allowed replacement' }
    $probe = [System.IO.Path]::Combine($WorkRoot, 'share-probe.ps1')
    [System.IO.File]::WriteAllText($probe, 'param([string]$Path)' + [char]10 + 'try { [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None).Dispose(); ''opened'' } catch { ''denied'' }')
    $probeResult = Invoke-FreshHost -Command ('& {0} -Path {1}' -f (Quote-Literal $probe), (Quote-Literal $retainFile))
    $procText = [string]($probeResult.Out + $probeResult.Err)
    if ($procText -match 'opened') { throw 'source retention allowed a writer from a second process' }
    $afterRetain = $retainHandle.ReadExact()
    if ($afterRetain.Length -ne $retainBytes.Length -or $retainHandle.VolumeSerialNumber -ne $retainVol -or $retainHandle.FileIndex -ne $retainIdx -or (Get-Sha256 -Bytes $afterRetain) -cne $retainSha) { throw 'source retention mutated identity or bytes' }
}
finally { $retainHandle.Dispose() }

$tamper = Copy-Shape 'tamper'
$nativePath = [System.IO.Path]::Combine($tamper, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs')
$nativeBytes = [System.IO.File]::ReadAllBytes($nativePath)
$nativeBytes[0] = [byte](($nativeBytes[0] + 1) % 256)
[System.IO.File]::WriteAllBytes($nativePath, $nativeBytes)
$tamperManifest = Get-CorpusManifest -Cert $tamper
$tamperResult = Invoke-Gen $tamper
if ($tamperResult.Code -eq 0) { throw 'native tamper succeeded' }
if (($tamperResult.Err + $tamperResult.Out) -notmatch 'native helper source (length|digest) mismatch') { throw ('native tamper reason mismatch: ' + $tamperResult.Out + $tamperResult.Err) }
Assert-CorpusManifest -Expected $tamperManifest -Cert $tamper -Label 'native-source rejection'

$marker = Copy-Shape 'marker'
$wrong = @"
using System;
namespace Pspkt.Certification {
public sealed class HostClassifierVectorNativeV1 {
public static string BuildMarker { get { return "wrong-marker"; } }
public static string TypeVersion { get { return "1"; } }
}
}
"@
[System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($marker, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs'), [System.Text.UTF8Encoding]::new($false).GetBytes($wrong.Replace("`r`n", "`n")))
$markerManifest = Get-CorpusManifest -Cert $marker
$markerResult = Invoke-Gen $marker
if ($markerResult.Code -eq 0) { throw 'wrong-marker source succeeded' }
if (($markerResult.Err + $markerResult.Out) -notmatch 'native helper source (length|digest) mismatch|build marker mismatch') { throw ('wrong-marker reason mismatch: ' + $markerResult.Out + $markerResult.Err) }
Assert-CorpusManifest -Expected $markerManifest -Cert $marker -Label 'wrong-marker-source rejection'

$libraryTamper = Copy-Shape 'library-tamper'
$classifierSource = [System.IO.Path]::Combine($libraryTamper, 'lib', 'Pspkt.Certification.HostClassifier.ps1')
[System.IO.File]::AppendAllText($classifierSource, "`n")
$libraryTamperManifest = Get-CorpusManifest -Cert $libraryTamper
$libraryTamperResult = Invoke-Gen $libraryTamper
if ($libraryTamperResult.Code -eq 0) { throw 'library tamper succeeded' }
if (($libraryTamperResult.Err + $libraryTamperResult.Out) -notmatch 'host classifier source (length|digest) mismatch') { throw ('library tamper reason mismatch: ' + $libraryTamperResult.Out + $libraryTamperResult.Err) }
Assert-CorpusManifest -Expected $libraryTamperManifest -Cert $libraryTamper -Label 'library-source rejection'
Write-Output 'ordinary-fault: pass'
} catch {
    throw ('CHILD ' + [string]$_.InvocationInfo.PositionMessage + ' :: ' + [string]$_)
}
'@
        [System.IO.File]::WriteAllBytes($childScript, [System.Text.UTF8Encoding]::new($false).GetBytes($childBody.Replace("`r`n", "`n")))
        $workRoot = [System.IO.Path]::Combine($physicalRoot, 'ordinary-work')
        [void][System.IO.Directory]::CreateDirectory($workRoot)
        [void]$script:ownedScratch.Add($workRoot)
        $command = '& {0} -HostPath {1} -SourceCertRoot {2} -WorkRoot {3}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $childScript),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $script:hostPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $script:certRoot),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $workRoot)
        $childResult = Invoke-PspktTestHost -Command $command
        $childOut = $childResult.Stdout + $childResult.Stderr
        if ($childResult.ExitCode -ne 0) {
            throw ('ordinary child failed ' + [string]$childResult.ExitCode + ': ' + $childOut)
        }
        $childOut | Should -Match 'ordinary-fault: pass'
    }

    It 'supports repeated runs when the fixed-name helper is already loaded' {
        $scenarioCertRoot = Copy-PspktTestCertificationRoot -Name 'fixed-preload'
        $nativeSourcePath = [System.IO.Path]::Combine($scenarioCertRoot, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs')
        $generatorPath = [System.IO.Path]::Combine($scenarioCertRoot, 'vectors', 'New-PspktHostClassifierFixtures.ps1')
        $validatorPath = [System.IO.Path]::Combine($scenarioCertRoot, 'validators', 'Test-PspktHostClassifierVectorParity.ps1')
        Assert-PspktTestVectorHashes -CertificationRoot $scenarioCertRoot
        $command = '$ErrorActionPreference = ''Stop''; Add-Type -TypeDefinition ([System.IO.File]::ReadAllText({0})) -Language CSharp; & {1}; & {1}; & {2} -CertificationRoot {3}; & {2} -CertificationRoot {3}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $nativeSourcePath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $generatorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $validatorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $scenarioCertRoot)
        $result = Invoke-PspktTestHost -Command $command
        $result.ExitCode | Should -Be 0
        @([regex]::Matches(($result.Stdout + $result.Stderr), '11 of 11 unchanged')).Count | Should -BeGreaterOrEqual 2
        @([regex]::Matches(($result.Stdout + $result.Stderr), 'vector validation: 11 of 11 pass')).Count | Should -BeGreaterOrEqual 2
        Assert-PspktTestVectorHashes -CertificationRoot $scenarioCertRoot
    }

    It 'ignores forged provenance for a modified fixed-name helper' {
        $physicalRoot = [System.IO.Path]::GetFullPath($TestDrive)
        $modifiedNativePath = [System.IO.Path]::Combine($physicalRoot, 'modified-native-helper.cs')
        $scenarioCertRoot = Copy-PspktTestCertificationRoot -Name 'modified-preload'
        $nativeSourcePath = [System.IO.Path]::Combine($scenarioCertRoot, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs')
        $generatorPath = [System.IO.Path]::Combine($scenarioCertRoot, 'vectors', 'New-PspktHostClassifierFixtures.ps1')
        $validatorPath = [System.IO.Path]::Combine($scenarioCertRoot, 'validators', 'Test-PspktHostClassifierVectorParity.ps1')
        Assert-PspktTestVectorHashes -CertificationRoot $scenarioCertRoot
        $nativeSourceText = [System.IO.File]::ReadAllText($nativeSourcePath)
        $modifiedNativeSourceText = $nativeSourceText.Replace(
            'private const int OpenFileAttemptCount = 20;',
            'private const int OpenFileAttemptCount = 0;')
        if ($modifiedNativeSourceText -ceq $nativeSourceText) {
            throw 'Modified native helper fixture did not change the source.'
        }
        [System.IO.File]::WriteAllBytes(
            $modifiedNativePath,
            [System.Text.UTF8Encoding]::new($false).GetBytes($modifiedNativeSourceText))
        $command = '$ErrorActionPreference = ''Stop''; Add-Type -TypeDefinition ([System.IO.File]::ReadAllText({0})) -Language CSharp; [System.AppDomain]::CurrentDomain.SetData({1}, {2}); & {3}; & {4} -CertificationRoot {5}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $modifiedNativePath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value 'Pspkt.Certification.HostClassifierVectorNativeV1.SourceSha256'),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value '666e71c53ed6572db5d7b1c7e21bae3a938fea045bc03bf22e8e84ac9a6439be'),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $generatorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $validatorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $scenarioCertRoot)
        $result = Invoke-PspktTestHost -Command $command
        $result.ExitCode | Should -Be 0
        ($result.Stdout + $result.Stderr) | Should -Match '11 of 11 unchanged'
        ($result.Stdout + $result.Stderr) | Should -Match 'vector validation: 11 of 11 pass'
        Assert-PspktTestVectorHashes -CertificationRoot $scenarioCertRoot
    }

    It 'retries a transient sharing violation when opening a vector file' {
        $physicalRoot = [System.IO.Path]::GetFullPath($TestDrive)
        $scenarioCertRoot = Copy-PspktTestCertificationRoot -Name 'sharing-retry'
        $childScript = [System.IO.Path]::Combine($physicalRoot, 'sharing-retry.ps1')
        $readyPath = [System.IO.Path]::Combine($physicalRoot, 'sharing-retry.ready')
        $releasePath = [System.IO.Path]::Combine($physicalRoot, 'sharing-retry.release')
        $vectorPath = [System.IO.Path]::Combine(
            $scenarioCertRoot,
            'vectors',
            'host-classifier',
            'negative-ambiguous-ancestry.json')
        Assert-PspktTestVectorHashes -CertificationRoot $scenarioCertRoot
        $childBody = @'
param(
    [Parameter(Mandatory = $true)][string]$NativeSourcePath,
    [Parameter(Mandatory = $true)][string]$VectorPath,
    [Parameter(Mandatory = $true)][string]$ReadyPath,
    [Parameter(Mandatory = $true)][string]$ReleasePath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText($NativeSourcePath)) -Language CSharp
$holder = Start-Job -ScriptBlock {
    param([string]$Path, [string]$Ready, [string]$Release)
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        [System.IO.File]::WriteAllText($Ready, 'ready')
        $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not [System.IO.File]::Exists($Release)) {
            if ($waitClock.ElapsedMilliseconds -ge 10000) {
                throw 'sharing holder release timed out'
            }
            Start-Sleep -Milliseconds 10
        }
    }
    finally {
        $stream.Dispose()
    }
} -ArgumentList $VectorPath, $ReadyPath, $ReleasePath
$opener = $null
try {
    $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not [System.IO.File]::Exists($ReadyPath)) {
        if ($waitClock.ElapsedMilliseconds -ge 10000) {
            throw 'sharing holder did not become ready'
        }
        Start-Sleep -Milliseconds 10
    }
    $rawOpenRejected = $false
    try {
        $rawHandle = [System.IO.File]::Open(
            $VectorPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        $rawHandle.Dispose()
    }
    catch [System.IO.IOException] {
        $rawOpenRejected = $true
    }
    if (-not $rawOpenRejected) {
        throw 'sharing holder did not reject the direct writable open'
    }
    $opener = Start-Job -ScriptBlock {
        param([string]$Source, [string]$Path)
        Add-Type -TypeDefinition ([System.IO.File]::ReadAllText($Source)) -Language CSharp
        $retryClock = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $handle = [Pspkt.Certification.HostClassifierVectorNativeV1]::OpenFile($Path, $true)
            $handle.Dispose()
            throw 'sharing retry unexpectedly succeeded while the holder was active'
        }
        catch [System.Management.Automation.MethodInvocationException] {
            if ($_.Exception.InnerException.NativeErrorCode -ne 32) {
                throw
            }
            Write-Output ('retry-exhausted:{0}' -f $retryClock.ElapsedMilliseconds)
        }
    } -ArgumentList $NativeSourcePath, $VectorPath
    [void](Wait-Job -Job $opener -Timeout 10)
    $openerOutput = @(Receive-Job -Job $opener -ErrorAction Stop)
    if ($opener.State -ne 'Completed' -or $openerOutput.Count -ne 1 -or
        [string]$openerOutput[0] -cnotmatch '^retry-exhausted:([0-9]+)$' -or
        [int64]$Matches[1] -lt 900) {
        throw ('sharing retry did not exhaust the bounded retry interval: {0}' -f ($openerOutput -join ','))
    }
    [System.IO.File]::WriteAllText($ReleasePath, 'release')
    [void](Wait-Job -Job $holder -Timeout 10)
    Receive-Job -Job $holder -ErrorAction Stop | Out-Null
    $handle = [Pspkt.Certification.HostClassifierVectorNativeV1]::OpenFile($VectorPath, $true)
    $handle.Dispose()
    Write-Output 'sharing-retry: pass'
}
finally {
    if ($null -ne $opener) {
        Remove-Job -Job $opener -Force
    }
    if (-not [System.IO.File]::Exists($ReleasePath)) {
        [System.IO.File]::WriteAllText($ReleasePath, 'release')
    }
    [void](Wait-Job -Job $holder -Timeout 10)
    Receive-Job -Job $holder -ErrorAction Stop | Out-Null
    Remove-Job -Job $holder -Force
}
'@
        [System.IO.File]::WriteAllBytes(
            $childScript,
            [System.Text.UTF8Encoding]::new($false).GetBytes($childBody.Replace("`r`n", "`n")))
        $nativeSourcePath = [System.IO.Path]::Combine($scenarioCertRoot, 'lib', 'Pspkt.Certification.HostClassifierVectorNative.cs')
        $command = '& {0} -NativeSourcePath {1} -VectorPath {2} -ReadyPath {3} -ReleasePath {4}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $childScript),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $nativeSourcePath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $vectorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $readyPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $releasePath)
        $result = Invoke-PspktTestHost -Command $command
        $result.ExitCode | Should -Be 0
        ($result.Stdout + $result.Stderr) | Should -Match 'sharing-retry: pass'
        Assert-PspktTestVectorHashes -CertificationRoot $scenarioCertRoot
    }

    It 'terminates descendant processes when a test child times out' {
        $physicalRoot = [System.IO.Path]::GetFullPath($TestDrive)
        $timeoutRoot = [System.IO.Path]::Combine($physicalRoot, 'timeout-work')
        [void][System.IO.Directory]::CreateDirectory($timeoutRoot)
        [void]$script:ownedScratch.Add($timeoutRoot)
        $descendantPath = [System.IO.Path]::Combine($timeoutRoot, 'descendant.txt')
        $command = '$child = Start-Process -FilePath {0} -ArgumentList @(''-NoProfile'',''-NonInteractive'',''-Command'',''Start-Sleep -Seconds 60'') -PassThru; [System.IO.File]::WriteAllText({1}, [string]$child.Id); Start-Sleep -Seconds 60' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $script:hostPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $descendantPath)
        $timedOut = $false
        try {
            [void](Invoke-PspktTestHost -Command $command -TimeoutMilliseconds 5000)
        }
        catch {
            $timedOut = $true
            $_.Exception.Message | Should -Match 'timed out'
        }
        $timedOut | Should -BeTrue
        [System.IO.File]::Exists($descendantPath) | Should -BeTrue
        $descendantProcessId = [int][System.IO.File]::ReadAllText($descendantPath)
        Start-Sleep -Milliseconds 250
        { [System.Diagnostics.Process]::GetProcessById($descendantProcessId) } | Should -Throw
    }

    It 'terminates a noisy child when its output exceeds the cap' {
        $failed = $false
        try {
            [void](Invoke-PspktTestHost -Command '[Console]::Out.Write((''x'' * 5000000)); Start-Sleep -Seconds 60')
        }
        catch {
            $failed = $true
            $_.Exception.ToString() | Should -Match 'Process output exceeded 4194304 bytes'
        }
        $failed | Should -BeTrue
    }

    It 'runs git authority and argument-quoting self-tests' {
        $physicalRoot = [System.IO.Path]::GetFullPath($TestDrive)
        $scratch = [System.IO.Path]::Combine($physicalRoot, 'git self tests')
        [void][System.IO.Directory]::CreateDirectory($scratch)
        [void]$script:ownedScratch.Add($scratch)
        $command = '& {0} -SelfTest -ScratchRoot {1}' -f (
            ConvertTo-PspktTestSingleQuotedLiteral -Value $script:validatorPath),
            (ConvertTo-PspktTestSingleQuotedLiteral -Value $scratch)
        $result = Invoke-PspktTestHost -Command $command
        $result.ExitCode | Should -Be 0
        ($result.Stdout + $result.Stderr) | Should -Match 'git authority and argument-quoting self-tests: pass'
    }
}
