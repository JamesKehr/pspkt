#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.3.3' }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Phase 4 schema authority Foundation catalog' -Tag 'Precheck' {
    BeforeAll {
        $script:repositoryRoot = Split-Path -Parent $PSScriptRoot
        . (Join-Path $script:repositoryRoot 'certification\lib\Pspkt.Certification.CanonicalJson.ps1')
        . (Join-Path $script:repositoryRoot 'certification\lib\Pspkt.Certification.FoundationContract.ps1')
        $script:contract = Get-PspktFoundationContract
        $gitRoots = [Collections.Generic.List[string]]::new()
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $registryBase = $null
            $registryKey = $null
            $currentVersionKey = $null
            try {
                $registryBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
                $registryKey = $registryBase.OpenSubKey('SOFTWARE\GitForWindows', $false)
                if ($null -ne $registryKey) {
                    $installPath = [string]$registryKey.GetValue('InstallPath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if (-not [string]::IsNullOrWhiteSpace($installPath)) {
                        $gitRoots.Add($installPath)
                    }
                }
                $currentVersionKey = $registryBase.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion', $false)
                if ($null -ne $currentVersionKey) {
                    $programFiles = [string]$currentVersionKey.GetValue('ProgramFilesDir', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
                        $gitRoots.Add((Join-Path $programFiles 'Git'))
                    }
                }
            }
            finally {
                if ($null -ne $currentVersionKey) { $currentVersionKey.Dispose() }
                if ($null -ne $registryKey) { $registryKey.Dispose() }
                if ($null -ne $registryBase) { $registryBase.Dispose() }
            }
        }
        $script:gitPath = $null
        foreach ($root in @($gitRoots | Sort-Object -Unique)) {
            foreach ($relativePath in @('cmd\git.exe','bin\git.exe')) {
                $candidate = Join-Path $root $relativePath
                if ([IO.File]::Exists($candidate)) {
                    $script:gitPath = [IO.Path]::GetFullPath($candidate)
                    break
                }
            }
            if ($null -ne $script:gitPath) { break }
        }
        if ($null -eq $script:gitPath) {
            throw 'Git test bootstrap could not resolve Git through Registry64/Registry32 authority.'
        }
        $script:validatorPath = Join-Path $script:repositoryRoot 'certification\validators\Invoke-PspktPhase4SchemaAuthorityFoundationValidators.ps1'
        $script:hostPath = (Get-Process -Id $PID).Path

        function script:New-FoundationBaselineRepository {
            param(
                [string]$LiteralPath,
                [string]$SourceRepository = $script:repositoryRoot
            )

            [IO.Directory]::CreateDirectory($LiteralPath) | Out-Null
            & $script:gitPath -c core.hooksPath=NUL init $LiteralPath | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to initialize isolated baseline repository.'
            }
            $sourceUri = [Uri]::new([IO.Path]::GetFullPath($SourceRepository)).AbsoluteUri
            & $script:gitPath -C $LiteralPath -c core.hooksPath=NUL -c protocol.file.allow=always fetch --no-tags $sourceUri $script:contract.BaselineOid | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $savedErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    $originOutput = @(& $script:gitPath -C $SourceRepository remote get-url origin 2>$null)
                    $originExitCode = $LASTEXITCODE
                }
                finally {
                    $ErrorActionPreference = $savedErrorActionPreference
                }
                if ($originExitCode -ne 0 -or $originOutput.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$originOutput[0])) {
                    throw 'Unable to resolve the origin for the frozen baseline.'
                }
                $originUrl = ([string]$originOutput[0]).Trim()
                & $script:gitPath -C $LiteralPath -c core.hooksPath=NUL -c protocol.file.allow=always fetch --no-tags $originUrl $script:contract.BaselineOid | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw 'Unable to fetch the frozen baseline commit.'
                }
            }
            & $script:gitPath -C $LiteralPath -c core.hooksPath=NUL branch $script:contract.Branch FETCH_HEAD
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to create the frozen validation branch.'
            }
            & $script:gitPath -C $LiteralPath -c core.hooksPath=NUL checkout $script:contract.Branch | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to checkout the frozen validation branch.'
            }
            (& $script:gitPath -C $LiteralPath rev-parse HEAD).Trim() | Should -Be $script:contract.BaselineOid
        }

        function script:Invoke-FoundationOuter {
            param([string[]]$Arguments)

            if (($Arguments -contains '-FoundationInit' -or $Arguments -contains '-FoundationReplay') -and $Arguments -notcontains '-RecoveryJournalPath') {
                $prestateArgumentIndex = [Array]::IndexOf($Arguments, '-PrestatePath')
                if ($prestateArgumentIndex -lt 0) {
                    throw 'Foundation outer test invocation lacks PrestatePath.'
                }
                $authorityRoot = Split-Path -Parent ([string]$Arguments[$prestateArgumentIndex + 1])
                $Arguments += @(
                    '-RecoveryJournalPath',(Join-Path $authorityRoot 'recovery-journal'),
                    '-CompletionReceiptPath',(Join-Path $authorityRoot 'completion-receipt.v1.json')
                )
            }
            $savedErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $output = @(& $script:hostPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $script:validatorPath @Arguments 2>&1)
                return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
            }
            finally {
                $ErrorActionPreference = $savedErrorActionPreference
            }
        }

        function script:New-FoundationTestHostAssembly {
            $validatorText = [IO.File]::ReadAllText($script:validatorPath)
            $sourceMatch = [regex]::Match($validatorText, "(?s)\`$foundationHostSource = @'\r?\n(.*?)\r?\n'@")
            if (-not $sourceMatch.Success) {
                throw 'FoundationHost source was not found.'
            }
            $compileRoot = Join-Path $script:testScratch ('foundation-host-' + [guid]::NewGuid().ToString('N'))
            [IO.Directory]::CreateDirectory($compileRoot) | Out-Null
            $sourcePath = Join-Path $compileRoot 'FoundationHost.cs'
            $assemblyPath = Join-Path $compileRoot 'FoundationHost.dll'
            [IO.File]::WriteAllText($sourcePath, $sourceMatch.Groups[1].Value, [Text.UTF8Encoding]::new($false))
            $frameworkDirectory = if ([Environment]::Is64BitProcess) { 'Framework64' } else { 'Framework' }
            $compilerPath = Join-Path ([IO.Directory]::GetParent([Environment]::SystemDirectory).FullName) "Microsoft.NET\$frameworkDirectory\v4.0.30319\csc.exe"
            & $compilerPath /nologo /target:library /langversion:5 "/out:$assemblyPath" $sourcePath
            if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($assemblyPath)) {
                throw 'FoundationHost test compilation failed.'
            }
            $script:lastFoundationHostAssemblyPath = $assemblyPath
            return [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($assemblyPath))
        }
    }

    BeforeEach {
        $script:testScratch = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:testSource = Join-Path $script:testScratch 'src'
        [IO.Directory]::CreateDirectory($script:testSource) | Out-Null
        foreach ($relativePath in $script:contract.InputPathSet) {
            $source = Resolve-PspktFoundationPath -Root $script:repositoryRoot -RelativePath $relativePath
            $destination = Resolve-PspktFoundationPath -Root $script:testSource -RelativePath $relativePath
            [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
            [IO.File]::Copy($source, $destination, $false)
        }
    }

    Context 'R3 recovery corrections' {
        BeforeAll {
            $parseErrors = $null
            $parseTokens = $null
            $validatorAst = [Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$parseTokens, [ref]$parseErrors)
            foreach ($definition in $validatorAst.EndBlock.Statements) {
                if ($definition -is [Management.Automation.Language.FunctionDefinitionAst]) {
                    . ([scriptblock]::Create($definition.Extent.Text))
                }
            }
            foreach ($assignment in $validatorAst.EndBlock.Statements) {
                if ($assignment -is [Management.Automation.Language.AssignmentStatementAst] -and $assignment.Left.Extent.Text -match '^\$bootstrap') {
                    . ([scriptblock]::Create($assignment.Extent.Text))
                }
            }
            $script:testScratch = Join-Path $TestDrive 'r3-native'
            [IO.Directory]::CreateDirectory($script:testScratch) | Out-Null
            $recoveryHostAssembly = New-FoundationTestHostAssembly
            $recoveryNativeType = $recoveryHostAssembly.GetType('Pspkt.Certification.FoundationHost.NativeFileSystem', $true, $false)
            $recoveryProcessType = $recoveryHostAssembly.GetType('Pspkt.Certification.FoundationHost.BinaryProcess', $true, $false)
            function Invoke-FoundationGitRaw {
                param([string[]]$Arguments, [byte[]]$StandardInput, [int]$StandardOutputCap=16777216, [int[]]$AcceptedExitCodes=@(0))
                $environmentNames = [Collections.Generic.List[string]]::new()
                $environmentValues = [Collections.Generic.List[string]]::new()
                foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
                    if (-not ([string]$entry.Key).StartsWith('GIT_', [StringComparison]::OrdinalIgnoreCase)) {
                        $environmentNames.Add([string]$entry.Key)
                        $environmentValues.Add([string]$entry.Value)
                    }
                }
                $environmentNames.Add('GIT_OPTIONAL_LOCKS')
                $environmentValues.Add('0')
                $result = $recoveryProcessType.GetMethod('Run').Invoke($null, @(
                    [string]$script:gitPath, [string[]]$Arguments, [string]$RepositoryRoot,
                    $environmentNames.ToArray(), $environmentValues.ToArray(), $StandardInput,
                    $StandardOutputCap, 1048576, 30000
                ))
                if ($AcceptedExitCodes -notcontains $result.ExitCode) { throw [Text.Encoding]::UTF8.GetString($result.StandardError) }
                return $result
            }
            function Get-FoundationNativeDirectoryIdentity {
                param([string]$LiteralPath)
                return $recoveryNativeType.GetMethod('GetDirectoryIdentity').Invoke($null, @($LiteralPath))
            }
            function Get-FoundationNativeFileIdentity {
                param([string]$LiteralPath)
                return $recoveryNativeType.GetMethod('GetIdentity').Invoke($null, @($LiteralPath))
            }
            function Get-FoundationNativeLinkCount {
                param([string]$LiteralPath)
                return $recoveryNativeType.GetMethod('GetLinkCount').Invoke($null, @($LiteralPath))
            }
            function Move-FoundationNativeCreateOnly {
                param([string]$Source, [string]$Destination)
                [void]$recoveryNativeType.GetMethod('MoveCreateOnly').Invoke($null, @($Source, $Destination))
            }
            function Move-FoundationNativeOwnedFileCreateOnly {
                param([string]$Source, [string]$Destination, $Record)
                [void]$recoveryNativeType.GetMethod('MoveOwnedFileCreateOnly').Invoke($null, @(
                    $Source,
                    $Destination,
                    [string]$Record.Identity,
                    [int64]$Record.Length,
                    [string]$Record.Sha256))
            }
            function Remove-FoundationNativeOwnedFile {
                param($Record)
                [void]$recoveryNativeType.GetMethod('DeleteOwnedFile').Invoke($null, @([string]$Record.Path, [string]$Record.Identity, [long]$Record.Length, [string]$Record.Sha256))
            }
            function Remove-FoundationNativeOwnedEmptyDirectory {
                param([string]$LiteralPath, [string]$ExpectedIdentity)
                [void]$recoveryNativeType.GetMethod('DeleteOwnedEmptyDirectory').Invoke($null, @($LiteralPath, $ExpectedIdentity))
            }
            function New-FoundationRecoveryTestPrestate {
                param([scriptblock]$BeforeCapture = {})
                New-FoundationBaselineRepository -LiteralPath $RepositoryRoot
                & $BeforeCapture
                New-FoundationExecutionPrestate -LiteralPath $PrestatePath
                $binding = New-FoundationFileBinding -LiteralPath $PrestatePath -Role 'authority:prestate'
                try { return Read-FoundationExecutionPrestate -Binding $binding }
                finally { $binding.Stream.Dispose() }
            }
            function New-FoundationRecoveryTestJournal {
                $inputHashes = [ordered]@{}
                $outputHashes = [ordered]@{}
                foreach ($path in $bootstrapContract.Allowlist) {
                    $destination = Resolve-FoundationHostPath -Root $promoRoot -RelativePath $path
                    [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
                    [IO.File]::WriteAllBytes($destination, [byte[]]@(1,2,3))
                    if ($bootstrapContract.InputPathSet -ccontains $path) { $inputHashes[$path] = Get-FoundationFileSha $destination }
                    else { $outputHashes[$path] = Get-FoundationFileSha $destination }
                }
                $prestateHash = Get-FoundationCanonicalHash -Value $prestate
                $initBytes = Get-PspktCanonicalJsonBytes ([ordered]@{
                    schemaVersion=1;schemaId=$bootstrapContract.InitReceiptSchemaId;baselineOid=$bootstrapContract.BaselineOid
                    catalogSha256=$inputHashes[$bootstrapContract.CatalogRelativePath];prestateSha256=$prestateHash;nonce=('a'*32)
                })
                $replayBytes = Get-PspktCanonicalJsonBytes ([ordered]@{
                    schemaVersion=2;schemaId=$bootstrapContract.ReplayReceiptSchemaId;baselineOid=$bootstrapContract.BaselineOid
                    candidateTreeOid=('a'*40);mapBlobOid=('b'*40);catalogSha256=$inputHashes[$bootstrapContract.CatalogRelativePath]
                    schemaSha256=$outputHashes[$bootstrapContract.SchemaRelativePath];mapSha256=$outputHashes[$bootstrapContract.MapRelativePath]
                    prestateSha256=$prestateHash;initReceiptSha256=(Get-FoundationHostSha256 $initBytes);inputHashes=$inputHashes;outputHashes=$outputHashes
                })
                function Invoke-FoundationGitRaw {
                    param($Arguments)
                    $bytes = [byte[]]@(4,5,6)
                    if ($null -ne $prestate.PSObject.Properties['allowedBaseline']) {
                        $relativePath = ([string]$Arguments[1]).Substring(41)
                        $bytes = [IO.File]::ReadAllBytes((Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath))
                    }
                    return [pscustomobject]@{StandardOutput=$bytes}
                }
                return New-FoundationRecoveryJournal -InitReceiptBytes $initBytes -ReplayReceiptBytes $replayBytes -ExpectedAllowlistHashes ([Text.Encoding]::UTF8.GetString($replayBytes) | ConvertFrom-Json) -PrestateSha256 $prestateHash
            }
        }

        BeforeEach {
            $RepositoryRoot = Join-Path $script:testScratch 'production'
            $promoRoot = Join-Path $script:testScratch 'promo'
            $RecoveryJournalPath = Join-Path $script:testScratch 'authority\journal'
            $InitReceiptPath = Join-Path $script:testScratch 'authority\init.json'
            $ReplayReceiptPath = Join-Path $script:testScratch 'authority\replay.json'
            $CompletionReceiptPath = Join-Path $script:testScratch 'authority\completion.json'
            $RecoveredCompletionReceiptPath = ''
            $PrestatePath = Join-Path $script:testScratch 'authority\prestate.json'
            $initialAuthorities = @()
            $prestate = [pscustomobject]@{ repo=$RepositoryRoot }
            $script:AuthorityReceiptBytes = [long]0
            $script:AuthorityFileBindings = [Collections.Generic.List[object]]::new()
            [IO.Directory]::CreateDirectory($RepositoryRoot) | Out-Null
            [IO.Directory]::CreateDirectory((Split-Path -Parent $RecoveryJournalPath)) | Out-Null
            $journal = $null
        }

        AfterEach {
            if ($null -ne $journal -and $null -ne $journal.PSObject.Properties['Lease'] -and $null -ne $journal.Lease) {
                $journal.Lease.Stream.Dispose()
            }
            foreach ($binding in $script:AuthorityFileBindings) { $binding.Stream.Dispose() }
        }

        It 'rejects a different journal root before promotion bootstrap or rollback' {
            $prestate = New-FoundationRecoveryTestPrestate
            $before = Get-FoundationCanonicalHash (Get-FoundationRepositorySnapshot)
            $originalRoot = [IO.Path]::GetPathRoot($RepositoryRoot)
            $differentRoot = if ($originalRoot -ieq 'Z:\') { 'Y:\' } else { 'Z:\' }
            $RecoveryJournalPath = $differentRoot + 'unavailable-foundation-journal'
            $mutationCalls = [Collections.Generic.List[string]]::new()
            function New-FoundationRecoveryJournal {
                $mutationCalls.Add('bootstrap')
                throw 'Unexpected journal bootstrap.'
            }
            function Invoke-FoundationRecovery {
                $mutationCalls.Add('rollback')
                throw 'Unexpected rollback.'
            }
            { Invoke-FoundationPromotionGate -Prestate $prestate -InitReceiptBytes ([byte[]]@(1)) -InitReceiptDestination $InitReceiptPath -ReplayReceiptBytes ([byte[]]@(2)) -ReplayReceiptDestination $ReplayReceiptPath -ExpectedAllowlistHashes @{} } |
                Should -Throw '*Unsupported transaction layout*'
            foreach ($differentReceipt in @('Init','Replay')) {
                $initDestination = $InitReceiptPath
                $replayDestination = $ReplayReceiptPath
                if ($differentReceipt -ceq 'Init') { $initDestination += '.different' } else { $replayDestination += '.different' }
                { Invoke-FoundationPromotionGate -Prestate $prestate -InitReceiptBytes ([byte[]]@(1)) -InitReceiptDestination $initDestination -ReplayReceiptBytes ([byte[]]@(2)) -ReplayReceiptDestination $replayDestination -ExpectedAllowlistHashes @{} } |
                    Should -Throw '*Promotion receipt destinations do not match their journal authorities*'
            }
            $mutationCalls.Count | Should -Be 0
            (Get-FoundationCanonicalHash (Get-FoundationRepositorySnapshot)) | Should -BeExactly $before
            [IO.File]::Exists($InitReceiptPath) | Should -BeFalse
            [IO.File]::Exists($ReplayReceiptPath) | Should -BeFalse
            [IO.File]::Exists($CompletionReceiptPath) | Should -BeFalse
        }

        It 'rejects a 260-character bootstrap evidence path before creating a journal nonce' {
            $parent = Split-Path -Parent $RecoveryJournalPath
            $RecoveryJournalPath = Join-Path $parent ('j' * (134 - $parent.Length - 1))
            $before = @(Get-ChildItem -LiteralPath $parent -Force).Count
            { New-FoundationRecoveryTestJournal } | Should -Throw '*Portable path budget exceeded*'
            @(Get-ChildItem -LiteralPath $parent -Force).Count | Should -Be $before
            [IO.Directory]::Exists($RecoveryJournalPath) | Should -BeFalse
        }

        It 'enforces portable UTF-16 file and directory boundaries without filesystem writes' {
            $root = [IO.Path]::GetPathRoot($script:testScratch)
            $file = $root + ('a' * 100) + '\' + ('b' * (259 - $root.Length - 101))
            (Assert-FoundationPortablePath $file -PassThru) | Should -BeExactly $file
            { Assert-FoundationPortablePath ($file + 'b') } | Should -Throw '*Portable path budget exceeded*260*259*'
            $directory = $root + ('a' * 100) + '\' + ('b' * (247 - $root.Length - 101))
            (Assert-FoundationPortablePath $directory -Directory -PassThru) | Should -BeExactly $directory
            { Assert-FoundationPortablePath ($directory + 'b') -Directory } | Should -Throw '*Portable path budget exceeded*248*247*'
            $unicodeFile = $file.Substring(0,257) + [char]0xD83D + [char]0xDE00
            $unicodeFile.Length | Should -Be 259
            { Assert-FoundationPortablePath $unicodeFile } | Should -Not -Throw
            { Assert-FoundationPortablePath ($unicodeFile + 'b') } | Should -Throw '*Portable path budget exceeded*260*'
        }

        It 'budgets portable journal evidence at new 133 and existing 181 character roots' {
            $parent = Split-Path -Parent $RecoveryJournalPath
            foreach ($case in @(@{Length=133;New=$true},@{Length=181;New=$false})) {
                $RecoveryJournalPath = Join-Path $parent ('j' * ($case.Length - $parent.Length - 1))
                { Assert-FoundationTransactionLayout -PathsOnly -NewJournal:$case.New } | Should -Not -Throw
                $RecoveryJournalPath += 'j'
                { Assert-FoundationTransactionLayout -PathsOnly -NewJournal:$case.New } | Should -Throw '*Portable path budget exceeded*evidence-*260*'
            }
            @(Get-ChildItem -LiteralPath $parent -Force).Count | Should -Be 0
        }

        It 'checks portable derived suffixes and direct mutation entry points before any intent' {
            $root = [IO.Path]::GetPathRoot($script:testScratch)
            foreach ($suffix in @(
                ('\evidence-' + ('0' * 64) + '.bin'), '\evidence-manifest.v1.json',
                '\00000000.header.json', '\00000001.not-applied.json',
                ('\.pspkt-segment-' + ('0' * 32) + '.tmp'), ('\.pspkt-content-' + ('0' * 32) + '.tmp'),
                ('.pspkt-preimage-' + ('0' * 32)), ('.' + ('0' * 32) + '.tmp')
            )) {
                $prefixLength = 259 - $suffix.Length
                $prefix = $root + ('a' * 100) + '\' + ('b' * ($prefixLength - $root.Length - 101))
                { Assert-FoundationPortablePath ($prefix + $suffix) } | Should -Not -Throw
                { Assert-FoundationPortablePath ($prefix + 'b' + $suffix) } | Should -Throw '*Portable path budget exceeded*'
            }
            $mutationCalls = [Collections.Generic.List[string]]::new()
            function Invoke-FoundationJournalOperation { $mutationCalls.Add('intent'); throw 'Unexpected intent.' }
            $longJournal = $root + ('a' * 100) + '\' + ('b' * (208 - $root.Length - 101))
            $unopenedJournal = [pscustomobject]@{Path=$longJournal}
            { Publish-FoundationJournaledFile -Journal $unopenedJournal -Destination $InitReceiptPath -Bytes ([byte[]]@(1)) -EvidenceKey '__init-receipt' } | Should -Throw '*Portable path budget exceeded*content-*260*'
            { Publish-FoundationJournalSegment -Journal $unopenedJournal -Sequence 0 -Kind header -Record @{} } | Should -Throw '*Portable path budget exceeded*segment-*260*'
            $longDirectory = $root + ('a' * 100) + '\' + ('b' * (204 - $root.Length - 101))
            { Ensure-FoundationJournaledDirectory -Journal $unopenedJournal -LiteralPath $longDirectory } | Should -Throw '*Portable path budget exceeded*248*247*'
            $shorterDirectory = $longDirectory.Substring(0,203)
            $directoryNonce = (Split-Path -Parent $shorterDirectory) + '\.' + (Split-Path -Leaf $shorterDirectory) + '.pspkt-dir-' + ('0' * 32)
            { Assert-FoundationPortablePath $directoryNonce -Directory } | Should -Not -Throw
            $longPrestate = $root + ('a' * 100) + '\' + ('b' * (223 - $root.Length - 101))
            { New-FoundationExecutionPrestate -LiteralPath $longPrestate } | Should -Throw '*Portable path budget exceeded*prestate temporary*260*'
            $longLease = $root + ('a' * 100) + '\' + ('b' * (239 - $root.Length - 101))
            { Open-FoundationJournalLease -LiteralPath $longLease } | Should -Throw '*Portable path budget exceeded*header lease*260*'
            $mutationCalls.Count | Should -Be 0
        }

        It 'rejects portable <Mode> scratch overflow before scratch creation' -ForEach @(
            @{Mode='CapturePrestateMode';Length=200;Suffix='foundation-host-*.dll'}
            @{Mode='RecoveryMode';Length=200;Suffix='foundation-host-*.dll'}
            @{Mode='InitMode';Length=164;Suffix='promo*'}
            @{Mode='ReplayCommitMode';Length=149;Suffix='committed-proof-work*'}
        ) {
            $SourceRoot = $script:testSource
            $ScratchRoot = $script:testScratch + '\' + ('s' * ($Length - $script:testScratch.Length - 1))
            { Assert-FoundationTransactionLayout -InvocationMode $Mode -PathsOnly } | Should -Not -Throw
            $ScratchRoot += 's'
            $arguments = @('-RepositoryRoot',$RepositoryRoot,'-ScratchRoot',$ScratchRoot,'-PrestatePath',$PrestatePath)
            if ($Mode -ceq 'CapturePrestateMode') { $arguments += '-FoundationCapturePrestate' }
            else {
                $arguments += @('-InitReceiptPath',$InitReceiptPath,'-ReplayReceiptPath',$ReplayReceiptPath,'-RecoveryJournalPath',$RecoveryJournalPath,'-CompletionReceiptPath',$CompletionReceiptPath)
                if ($Mode -ceq 'RecoveryMode') { $arguments += @('-FoundationRecover','-RecoveryAction','Rollback') }
                elseif ($Mode -ceq 'InitMode') { $arguments += @('-SourceRoot',$SourceRoot,'-FoundationInit','-Promote') }
                else { $arguments += @('-SourceRoot',$SourceRoot,'-FoundationReplay','-SelectedCommitOid',('a' * 40)) }
            }
            $result = Invoke-FoundationOuter -Arguments $arguments
            $result.ExitCode | Should -Not -Be 0
            ($result.Output -join "`n") | Should -BeLike "*Portable path budget exceeded*$Suffix*"
            [IO.Directory]::Exists($ScratchRoot) | Should -BeFalse
            [IO.Directory]::Exists($RecoveryJournalPath) | Should -BeFalse
            [IO.File]::Exists($PrestatePath) | Should -BeFalse
        }

        It 'admits portable fixed-root casing and missing directory ancestry without creating paths' {
            $root = [IO.Path]::GetPathRoot($RepositoryRoot)
            $authority = Get-FoundationExistingAncestorAuthority -LiteralPath $root
            $authority.ExistingPath | Should -BeExactly $root
            $authority.Remaining | Should -BeExactly ''
            $InitReceiptPath = $InitReceiptPath.Substring(0,1).ToLowerInvariant() + $InitReceiptPath.Substring(1)
            $ReplayReceiptPath = $ReplayReceiptPath.Substring(0,1).ToUpperInvariant() + $ReplayReceiptPath.Substring(1)
            $CompletionReceiptPath = Join-Path $script:testScratch 'absent\deeper\completion.json'
            { Assert-FoundationTransactionLayout -NewJournal } | Should -Not -Throw
            [IO.Directory]::Exists((Join-Path $script:testScratch 'absent')) | Should -BeFalse
        }

        It 'rejects portable <DriveKind> roots before publication' -ForEach @(
            @{DriveKind=[IO.DriveType]::Network}
            @{DriveKind=[IO.DriveType]::Removable}
        ) {
            function Get-FoundationDriveType { param($Root) return $DriveKind }
            { Assert-FoundationTransactionLayout -NewJournal } | Should -Throw '*Unsupported transaction layout*not a local fixed drive*'
            [IO.Directory]::Exists($RecoveryJournalPath) | Should -BeFalse
        }

        It 'rejects portable UNC and device roots before drive queries' {
            function Get-FoundationDriveType { throw 'Unexpected drive query.' }
            foreach ($unsupported in @('\\unused-foundation-server\share\journal', '\\?\C:\journal', '\\.\C:\journal')) {
                $RecoveryJournalPath = $unsupported
                { Assert-FoundationTransactionLayout } | Should -Throw '*Unsupported transaction layout*local fixed-drive root*'
            }
        }

        It 'rejects portable file ancestors missing journal parents and mismatched volume identities' {
            $originalCompletion = $CompletionReceiptPath
            $blocker = Join-Path $script:testScratch 'file-ancestor'
            [IO.File]::WriteAllText($blocker, 'preserved')
            $CompletionReceiptPath = Join-Path $blocker 'child\completion.json'
            { Assert-FoundationTransactionLayout } | Should -Throw '*Unsupported transaction layout*file ancestor*'
            [IO.File]::ReadAllText($blocker) | Should -BeExactly 'preserved'
            $CompletionReceiptPath = $originalCompletion
            $originalJournal = $RecoveryJournalPath
            $RecoveryJournalPath = Join-Path $script:testScratch 'missing-parent\journal'
            { Assert-FoundationTransactionLayout } | Should -Throw '*Unsupported transaction layout*journal parent must already exist*'
            $RecoveryJournalPath = $originalJournal
            $realIdentity = ${function:Get-FoundationNativeDirectoryIdentity}
            function Get-FoundationNativeDirectoryIdentity {
                param([string]$LiteralPath)
                $identity = & $realIdentity -LiteralPath $LiteralPath
                if ($LiteralPath -ine [IO.Path]::GetPathRoot($LiteralPath)) {
                    $prefix = if ($identity.StartsWith('00000000:',[StringComparison]::Ordinal)) { 'ffffffff:' } else { '00000000:' }
                    return $prefix + $identity.Substring(9)
                }
                return $identity
            }
            { Assert-FoundationTransactionLayout } | Should -Throw '*Unsupported transaction layout*different volume identity*'
        }

        It 'checks every portable receipt override and recorded operation or snapshot destination' {
            $differentRoot = if ([IO.Path]::GetPathRoot($RepositoryRoot) -ieq 'Z:\') { 'Y:\' } else { 'Z:\' }
            foreach ($variable in @('InitReceiptPath','ReplayReceiptPath','CompletionReceiptPath','RecoveredCompletionReceiptPath')) {
                $original = Get-Variable -Name $variable -ValueOnly
                try {
                    Set-Variable -Name $variable -Value ($differentRoot + 'receipt.json')
                    { Assert-FoundationTransactionLayout } | Should -Throw '*Unsupported transaction layout*root*'
                }
                finally { Set-Variable -Name $variable -Value $original }
            }
            $header = [pscustomobject]@{initReceiptPath=$InitReceiptPath;replayReceiptPath=$ReplayReceiptPath;requestedCompletionReceiptPath=$CompletionReceiptPath}
            foreach ($variant in @('unresolved-selection','applied-selection','snapshot','observed')) {
                $state = [pscustomobject]@{destination=$differentRoot + 'receipt.json'}
                if ($variant -ceq 'snapshot') { $state = [pscustomobject]@{Path=$differentRoot + 'owned.tmp'} }
                if ($variant -ceq 'observed') { $state = [pscustomobject]@{observed=[pscustomobject]@{Path=$differentRoot + 'observed.tmp'}} }
                $operation = [pscustomobject]@{
                    Intent=[pscustomobject]@{Record=[pscustomobject]@{operation='CompletionPathSelection';details=[pscustomobject]@{destination=($differentRoot + 'receipt.json');collidedPath=$CompletionReceiptPath}}}
                    Terminal=$null
                }
                if ($variant -cne 'unresolved-selection') {
                    $operation.Terminal = [pscustomobject]@{Kind='applied';Record=[pscustomobject]@{state=$state}}
                }
                if ($variant -cin @('snapshot','observed')) {
                    $operation.Intent.Record.operation = 'TempCreate'
                    $operation.Intent.Record.details = [pscustomobject]@{tempPath=(Join-Path $RecoveryJournalPath 'owned.tmp');destination=$InitReceiptPath}
                }
                $recorded = [pscustomobject]@{Path=$RecoveryJournalPath;Header=$header;Operations=@($operation)}
                { Assert-FoundationTransactionLayout -Journal $recorded } | Should -Throw '*Unsupported transaction layout*root*'
            }
        }

        It 'preserves portable recovery backups receipts and journal bytes before either recovery action' {
            $prestate = New-FoundationRecoveryTestPrestate
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $relativePath = 'certification/.gitattributes'
            $source = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
            $baseline = @($prestate.allowedBaseline | Where-Object { $_.path -ceq $relativePath })[0]
            $backup = "$source.pspkt-preimage-$('0' * 32)"
            [void](Invoke-FoundationJournalOperation -Journal $journal -Operation BackupMove -Details ([ordered]@{source=$source;destination=$backup;expectedIdentity=$baseline.identity;expectedLength=$baseline.length;expectedSha256=$baseline.sha256;relativePath=$relativePath}) -Mutation {
                Move-FoundationNativeCreateOnly -Source $source -Destination $backup
            } -AppliedState { Get-FoundationOwnedFileRecord $backup })
            $backupRecord = Get-FoundationOwnedFileRecord $backup
            [void](Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptPath -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt') -EvidenceKey '__init-receipt')
            $receiptRecord = Get-FoundationOwnedFileRecord $InitReceiptPath
            $before = Get-FoundationCanonicalHash (Get-FoundationRepositorySnapshot)
            $journal.Lease.Stream.Dispose()
            $journal = $null
            $journalRecords = @(Get-ChildItem -LiteralPath $RecoveryJournalPath -File | ForEach-Object { Get-FoundationOwnedFileRecord $_.FullName })
            $mutationCalls = [Collections.Generic.List[string]]::new()
            function Get-FoundationDriveType { param($Root) return [IO.DriveType]::Network }
            function Repair-FoundationUnmatchedJournalOperations { $mutationCalls.Add('repair'); throw 'Unexpected repair.' }
            foreach ($action in @('Finalize','Rollback')) {
                foreach ($suppliedLease in @($false,$true)) {
                    if ($suppliedLease) { $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive) }
                    try { { Invoke-FoundationRecovery -Prestate $prestate -Action $action -Journal $journal } | Should -Throw '*Unsupported transaction layout*' }
                    finally { if ($null -ne $journal) { $journal.Lease.Stream.Dispose(); $journal=$null } }
                }
            }
            $RecoveredCompletionReceiptPath = $script:testScratch + '\' + ('r' * (260 - $script:testScratch.Length - 1))
            foreach ($action in @('Finalize','Rollback')) {
                { Invoke-FoundationRecovery -Prestate $prestate -Action $action } | Should -Throw '*Portable path budget exceeded*260*'
            }
            $mutationCalls.Count | Should -Be 0
            (Get-FoundationCanonicalHash (Get-FoundationRepositorySnapshot)) | Should -BeExactly $before
            foreach ($record in @($backupRecord,$receiptRecord) + $journalRecords) { Test-FoundationOwnedFileRecord $record | Should -BeTrue }
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -File).Count | Should -Be $journalRecords.Count
        }

        It 'rejects malformed protected-object traversal instead of silently dropping evidence' {
            function Invoke-FoundationGitRaw {
                param($Arguments, $StandardOutputCap, $StandardInput)
                if ($Arguments[0] -eq 'rev-list') {
                    return [pscustomobject]@{ StandardOutput=[Text.Encoding]::ASCII.GetBytes(("a" * 40) + "`nmalformed object`n") }
                }
                return [pscustomobject]@{ StandardOutput=[Text.Encoding]::ASCII.GetBytes(("a" * 40) + " commit 10`n") }
            }
            { Get-FoundationProtectedObjectProjection } | Should -Throw '*object*'
        }

        It 'reads a journal without deleting an unproven segment temporary' {
            [void](New-FoundationRecoveryTestJournal)
            $temporaryPath = Join-Path $RecoveryJournalPath ('.pspkt-segment-' + ('a'*32) + '.tmp')
            [IO.File]::WriteAllText($temporaryPath, 'unproven')
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            [IO.File]::ReadAllText($temporaryPath) | Should -Be 'unproven'
        }

        It 'does not publish Applied when a real dispatcher evaluator returns null' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $details = [ordered]@{tempPath=(Join-Path $RecoveryJournalPath ('.pspkt-content-'+('a'*32)+'.tmp'));destination=$InitReceiptPath;tempIdentity='00000001:0000000000000001';evidenceKey='__init-receipt';expectedLength=1;expectedSha256=('a'*64)}
            { Invoke-FoundationJournalOperation -Journal $journal -Operation Publish -Details $details -Mutation {} -AppliedState { $null } } | Should -Throw
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '*.applied.json').Count | Should -Be 0
        }

        It 'rejects <Mismatch> instead of accepting a nonnull Applied state' -ForEach @(
            @{Mismatch='wrong-content'}
            @{Mismatch='wrong-identity'}
        ) {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $temporary = Join-Path $RecoveryJournalPath ('.pspkt-content-'+('a'*32)+'.tmp')
            $details = [ordered]@{tempPath=$temporary;destination=$InitReceiptPath;evidenceKey='__init-receipt';expectedLength=0;expectedSha256=(Get-FoundationHostSha256 ([byte[]]::new(0)))}
            { Invoke-FoundationJournalOperation -Journal $journal -Operation TempCreate -Details $details -Mutation {
                $bytes = [byte[]]::new(0)
                if ($Mismatch -eq 'wrong-content') { $bytes = [byte[]]@(1) }
                [IO.File]::WriteAllBytes($temporary, $bytes)
            } -AppliedState {
                $record = Get-FoundationOwnedFileRecord $temporary
                if ($Mismatch -eq 'wrong-identity') { $record.Identity = '00000000:0000000000000000' }
                return $record
            } } | Should -Throw '*conflict*'
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '*.applied.json').Count | Should -Be 0
            [IO.File]::Exists($temporary) | Should -BeTrue
        }

        It 'keeps Intent counter unchanged when Intent publication fails' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            function Publish-FoundationJournalSegment { throw [IO.IOException]::new('intent publication failure') }
            { Invoke-FoundationJournalOperation -Journal $journal -Operation RolledBack -Details @{phase='RolledBack'} -Mutation {} -AppliedState { @{satisfied=$true} } } | Should -Throw '*intent publication failure*'
            $journal.NextSequence | Should -Be 1
        }

        It 'excludes writers while shared readers retain and refresh the same header' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            $secondReader = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            try {
                { Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive } | Should -Throw '*FileShare.None*'
                $fresh = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease
                [object]::ReferenceEquals($fresh.Lease, $journal.Lease) | Should -BeTrue
                $fresh.NextSequence | Should -Be 1
            }
            finally { $secondReader.Lease.Stream.Dispose() }
            $journal.Lease.Stream.Dispose()
            $lease = Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $lease
            { Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath } | Should -Throw '*FileShare.Read*'
            [object]::ReferenceEquals((Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $lease).Lease, $lease) | Should -BeTrue
        }

        It 'rejects malformed journal records <Variant>' -ForEach @(
            @{Variant='sequence-zero';Name='00000000.intent.json';Record=@{schemaVersion=1;sequence=0;operation='RolledBack';details=@{phase='RolledBack'}}}
            @{Variant='extra-header';Name='00000001.header.json';Record=$null}
            @{Variant='body-mismatch';Name='00000001.intent.json';Record=@{schemaVersion=1;sequence=2;operation='RolledBack';details=@{phase='RolledBack'}}}
            @{Variant='unknown-operation';Name='00000001.intent.json';Record=@{schemaVersion=1;sequence=1;operation='Foreign';details=@{phase='Foreign'}}}
        ) {
            [void](New-FoundationRecoveryTestJournal)
            if ($Variant -eq 'extra-header') {
                [IO.File]::Copy((Join-Path $RecoveryJournalPath '00000000.header.json'), (Join-Path $RecoveryJournalPath $Name))
            }
            else { [IO.File]::WriteAllBytes((Join-Path $RecoveryJournalPath $Name), (Get-PspktCanonicalJsonBytes $Record)) }
            { $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath } | Should -Throw '*journal*'
        }

        It 'reuses exactly one Applied terminal after a post-publication IOException' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $realPublisher = ${function:Publish-FoundationJournalSegment}
            function Publish-FoundationJournalSegment {
                param($Journal, $Sequence, $Kind, $Record)
                & $realPublisher -Journal $Journal -Sequence $Sequence -Kind $Kind -Record $Record
                if ($Kind -eq 'applied') { throw [IO.IOException]::new('terminal persisted before I/O error') }
            }
            $temporary = Join-Path $RecoveryJournalPath ('.pspkt-content-'+('a'*32)+'.tmp')
            $details = [ordered]@{tempPath=$temporary;destination=$InitReceiptPath;evidenceKey='__init-receipt';expectedLength=0;expectedSha256=(Get-FoundationHostSha256 ([byte[]]::new(0)))}
            $result = Invoke-FoundationJournalOperation -Journal $journal -Operation TempCreate -Details $details -Mutation {
                [IO.File]::WriteAllBytes($temporary, [byte[]]::new(0))
            } -AppliedState { Get-FoundationOwnedFileRecord $temporary }
            @($result).Count | Should -Be 1 -Because ($result | ConvertTo-Json -Depth 5 -Compress)
            $result.Sequence | Should -Be 1
            $fresh = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease
            $fresh.Operations.Count | Should -Be 1
            $fresh.Operations[0].Terminal.Kind | Should -Be 'applied'
            @($fresh.Segments | Where-Object { $_.Kind -eq 'conflict' }).Count | Should -Be 0
        }

        It 'leaves a recoverable Intent after a pre-publication terminal IOException' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $realPublisher = ${function:Publish-FoundationJournalSegment}
            function Publish-FoundationJournalSegment {
                param($Journal, $Sequence, $Kind, $Record)
                if ($Kind -ne 'intent') { throw [IO.IOException]::new('before terminal rename') }
                & $realPublisher -Journal $Journal -Sequence $Sequence -Kind $Kind -Record $Record
            }
            $temporary = Join-Path $RecoveryJournalPath ('.pspkt-content-'+('a'*32)+'.tmp')
            $details = [ordered]@{tempPath=$temporary;destination=$InitReceiptPath;evidenceKey='__init-receipt';expectedLength=0;expectedSha256=(Get-FoundationHostSha256 ([byte[]]::new(0)))}
            { Invoke-FoundationJournalOperation -Journal $journal -Operation TempCreate -Details $details -Mutation {
                [IO.File]::WriteAllBytes($temporary, [byte[]]::new(0))
            } -AppliedState { Get-FoundationOwnedFileRecord $temporary } } | Should -Throw '*before terminal rename*'
            $fresh = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease
            $fresh.Operations[0].Terminal | Should -BeNullOrEmpty
        }

        It 'repairs <CrashPoint> by observation and rolls back owned remnants without Completion' -ForEach @(
            @{CrashPoint='after-terminal:TempCreate'}
            @{CrashPoint='after-intent:TempWrite'}
            @{CrashPoint='during-mutation:TempWrite'}
            @{CrashPoint='after-mutation:TempWrite'}
            @{CrashPoint='after-intent:Publish'}
            @{CrashPoint='after-mutation:Publish'}
        ) {
            $prestate = New-FoundationRecoveryTestPrestate
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $receiptBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt'
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $CrashPoint
                { Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptPath -Bytes $receiptBytes -EvidenceKey '__init-receipt' } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            $before = @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '.pspkt-content-*.tmp' | ForEach-Object { Get-FoundationOwnedFileRecord $_.FullName })
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease
            $journal = Repair-FoundationUnmatchedJournalOperations -Journal $journal
            foreach ($record in $before) { Test-FoundationOwnedFileRecord $record | Should -BeTrue }
            if ($CrashPoint -eq 'during-mutation:TempWrite') {
                $journal.Operations[1].Terminal.Kind | Should -Be 'not-applied'
                $journal.Operations[1].Terminal.Record.state.incomplete | Should -BeTrue
            }
            $result = Invoke-FoundationRecovery -Prestate $prestate -Action Rollback -Journal $journal
            $result.status | Should -Be 'rolled-back'
            [IO.File]::Exists($InitReceiptPath) | Should -BeFalse
            [IO.File]::Exists($CompletionReceiptPath) | Should -BeFalse
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '.pspkt-content-*.tmp').Count | Should -Be 0
        }

        It 'rejects wrong <Authority> before repair or cleanup writes' -ForEach @(
            @{Authority='prestate'}
            @{Authority='receipt-path'}
        ) {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'during-mutation:TempWrite'
                { Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptPath -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt') -EvidenceKey '__init-receipt' } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            $before = @(Get-ChildItem -LiteralPath $RecoveryJournalPath -File | Where-Object { $_.Name -ne '00000000.header.json' } | ForEach-Object { Get-FoundationOwnedFileRecord $_.FullName })
            if ($Authority -eq 'prestate') { $prestate = [pscustomobject]@{repo=$RepositoryRoot;foreign=$true} }
            else { $InitReceiptPath = Join-Path $script:testScratch 'wrong-init.json' }
            { Invoke-FoundationRecovery -Prestate $prestate -Action Rollback -Journal $journal } | Should -Throw '*authority*'
            foreach ($record in $before) { Test-FoundationOwnedFileRecord $record | Should -BeTrue }
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -File).Count | Should -Be ($before.Count + 1)
        }

        It 'enforces the real 1535 1536 and 1537 segment-file boundaries' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            for ($sequence = 1; $sequence -le 767; $sequence++) {
                $intent = [ordered]@{schemaVersion=1;sequence=$sequence;operation='RolledBack';details=@{phase='RolledBack'}}
                $terminal = [ordered]@{schemaVersion=1;sequence=$sequence;operation='RolledBack';state=@{satisfied=$false}}
                [IO.File]::WriteAllBytes((Join-Path $RecoveryJournalPath ('{0:D8}.intent.json' -f $sequence)), (Get-PspktCanonicalJsonBytes $intent))
                [IO.File]::WriteAllBytes((Join-Path $RecoveryJournalPath ('{0:D8}.not-applied.json' -f $sequence)), (Get-PspktCanonicalJsonBytes $terminal))
            }
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease
            $journal.Segments.Count | Should -Be 1535
            { Invoke-FoundationJournalOperation -Journal $journal -Operation RolledBack -Details @{phase='RolledBack'} -Mutation { throw 'mutation must not run' } -AppliedState { @{satisfied=$true} } } | Should -Throw '*reservation*'
            Publish-FoundationJournalSegment -Journal $journal -Sequence 768 -Kind intent -Record ([ordered]@{schemaVersion=1;sequence=768;operation='RolledBack';details=@{phase='RolledBack'}})
            (Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease).Segments.Count | Should -Be 1536
            $terminal = [ordered]@{schemaVersion=1;sequence=768;operation='RolledBack';state=@{satisfied=$false}}
            { Publish-FoundationJournalSegment -Journal $journal -Sequence 768 -Kind not-applied -Record $terminal } | Should -Throw '*segment count*'
            [IO.File]::WriteAllBytes((Join-Path $RecoveryJournalPath '00000768.not-applied.json'), (Get-PspktCanonicalJsonBytes $terminal))
            { Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease } | Should -Throw '*segment count*'
        }

        It 'rejects duplicate terminals rather than choosing a successful record' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            Publish-FoundationJournalSegment -Journal $journal -Sequence 1 -Kind intent -Record ([ordered]@{schemaVersion=1;sequence=1;operation='RolledBack';details=@{phase='RolledBack'}})
            Publish-FoundationJournalSegment -Journal $journal -Sequence 1 -Kind applied -Record ([ordered]@{schemaVersion=1;sequence=1;operation='RolledBack';state=@{satisfied=$true}})
            Publish-FoundationJournalSegment -Journal $journal -Sequence 1 -Kind conflict -Record ([ordered]@{schemaVersion=1;sequence=1;operation='RolledBack';state=@{satisfied=$false}})
            { Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease } | Should -Throw '*continuity*'
        }

        It 'never falls back to an empty TempCreate snapshot after a partial write snapshot' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'during-mutation:TempWrite'
                { Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptPath -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt') -EvidenceKey '__init-receipt' } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            $journal = Repair-FoundationUnmatchedJournalOperations -Journal (Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease)
            $ownership = Get-FoundationJournalOwnership -Journal $journal
            $entry = @($ownership.Files.Values)[0]
            $entry.Record.Length | Should -BeGreaterThan 0
            [IO.File]::WriteAllBytes($entry.Record.Path, [byte[]]::new(0))
            { Remove-FoundationJournaledFile -Journal $journal -Record $entry.Record -Operation TempDelete } | Should -Throw '*different occupant*'
            [IO.File]::Exists($entry.Record.Path) | Should -BeTrue
        }

        It 'captures historical blob tree and annotated-tag roots and rejects commit-only V3 evidence' {
            New-FoundationBaselineRepository -LiteralPath $RepositoryRoot
            $blobResult = Invoke-FoundationGitRaw -Arguments @('hash-object','-w','--stdin') -StandardInput ([Text.Encoding]::UTF8.GetBytes('historical standalone blob'))
            $blobOid = [Text.Encoding]::ASCII.GetString($blobResult.StandardOutput).Trim()
            $treeBytes = [Text.Encoding]::UTF8.GetBytes("100644 blob $blobOid`tspace`nnewline`0")
            $treeResult = Invoke-FoundationGitRaw -Arguments @('mktree','-z') -StandardInput $treeBytes
            $treeOid = [Text.Encoding]::ASCII.GetString($treeResult.StandardOutput).Trim()
            $tagBytes = [Text.Encoding]::UTF8.GetBytes("object $treeOid`ntype tree`ntag historical`ntagger Test <test@example.invalid> 1 +0000`n`nhistorical tag`n")
            $tagResult = Invoke-FoundationGitRaw -Arguments @('mktag') -StandardInput $tagBytes
            $tagOid = [Text.Encoding]::ASCII.GetString($tagResult.StandardOutput).Trim()
            foreach ($oid in @($blobOid,$tagOid,$bootstrapContract.BaselineOid)) {
                [void](Invoke-FoundationGitRaw -Arguments @('update-ref','--create-reflog','refs/test/history',$oid))
            }
            $fullProjection = @(Get-FoundationProtectedObjectProjection)
            @($fullProjection.oid) | Should -Contain $blobOid
            @($fullProjection.oid) | Should -Contain $treeOid
            @($fullProjection.oid) | Should -Contain $tagOid
            $reachableTree = @(Get-FoundationReachableObjectProjection -Object $treeOid)
            @($reachableTree.oid) | Should -Contain $blobOid
            @($reachableTree.oid) | Should -Contain $treeOid
            $captured = ConvertFrom-FoundationStrictUtf8 -Bytes (Get-PspktCanonicalJsonBytes ([ordered]@{logicalRefs=@(Get-FoundationLogicalRefs);protectedObjects=$fullProjection})) | ConvertFrom-Json
            { Assert-FoundationProtectedObjectCompleteness -Prestate $captured } | Should -Not -Throw
            $legacy = [pscustomobject]@{logicalRefs=$captured.logicalRefs;protectedObjects=@($fullProjection | Where-Object { $_.type -eq 'commit' })}
            { Assert-FoundationProtectedObjectCompleteness -Prestate $legacy } | Should -Throw '*Incomplete protected-object evidence*'
            & $script:gitPath -C $RepositoryRoot -c core.hooksPath=NUL -c user.name=Test -c user.email=test@example.invalid commit --allow-empty --quiet -m 'fixture selected commit'
            $LASTEXITCODE | Should -Be 0
            { Assert-FoundationProtectedObjectCompleteness -Prestate $captured } | Should -Not -Throw
        }

        It 'rejects incomplete V3 protected evidence through <Consumer> before journal mutation' -ForEach @(
            @{Consumer='Init'}
            @{Consumer='ReplayTree'}
            @{Consumer='ReplayCommit'}
            @{Consumer='Recovery'}
        ) {
            $prestate = New-FoundationRecoveryTestPrestate
            $prestate.protectedObjects = @($prestate.protectedObjects | Where-Object { $_.type -ceq 'commit' })
            [IO.File]::WriteAllBytes($PrestatePath, (Get-PspktCanonicalJsonBytes $prestate))
            $indexHash = Get-FoundationFileSha (Join-Path $RepositoryRoot '.git\index')
            $arguments = @(
                '-RepositoryRoot',$RepositoryRoot,'-ScratchRoot',(Join-Path $script:testScratch 'rejected-consumer'),
                '-PrestatePath',$PrestatePath,'-InitReceiptPath',$InitReceiptPath,'-ReplayReceiptPath',$ReplayReceiptPath,
                '-RecoveryJournalPath',$RecoveryJournalPath,'-CompletionReceiptPath',$CompletionReceiptPath
            )
            if ($Consumer -eq 'Recovery') { $arguments += @('-FoundationRecover','-RecoveryAction','Rollback') }
            else {
                $arguments += @('-SourceRoot',$script:testSource)
                if ($Consumer -eq 'Init') { $arguments += @('-FoundationInit','-Promote') }
                elseif ($Consumer -eq 'ReplayCommit') { $arguments += @('-FoundationReplay','-SelectedCommitOid',('a'*40)) }
                else { $arguments += @('-FoundationReplay','-SelectedTreeOid',('a'*40),'-SelectedMapBlobOid',('b'*40)) }
            }
            $result = Invoke-FoundationOuter -Arguments $arguments
            $result.ExitCode | Should -Not -Be 0
            ($result.Output -join "`n") | Should -Match 'Incomplete protected-object evidence'
            (Test-Path -LiteralPath $RecoveryJournalPath) | Should -BeFalse
            Get-FoundationFileSha (Join-Path $RepositoryRoot '.git\index') | Should -Be $indexHash
        }

        It 'preserves a same-byte foreign publication while cleaning an independent owned temporary' {
            $prestate = New-FoundationRecoveryTestPrestate
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $receiptBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt'
            [void](Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptPath -Bytes $receiptBytes -EvidenceKey '__init-receipt')
            $ownedIdentity = Get-FoundationNativeFileIdentity $InitReceiptPath
            $retiredPath = Join-Path $script:testScratch 'retired-receipt'
            [IO.File]::Move($InitReceiptPath, $retiredPath)
            [IO.File]::WriteAllBytes($InitReceiptPath, $receiptBytes)
            $foreign = Get-FoundationOwnedFileRecord $InitReceiptPath
            $foreign.Identity | Should -Not -Be $ownedIdentity
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'after-terminal:TempCreate'
                { Publish-FoundationJournaledFile -Journal $journal -Destination $ReplayReceiptPath -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__replay-receipt') -EvidenceKey '__replay-receipt' } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            { Invoke-FoundationRecovery -Prestate $prestate -Action Rollback -Journal $journal } | Should -Throw '*Rollback preserved conflicts*'
            Test-FoundationOwnedFileRecord $foreign | Should -BeTrue
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '.pspkt-content-*.tmp').Count | Should -Be 0
        }

        It 'cleans independent owned remnants before reporting an unobservable unmatched write' {
            $prestate = New-FoundationRecoveryTestPrestate
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'during-mutation:TempWrite'
                { Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptPath -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt') -EvidenceKey '__init-receipt' } | Should -Throw '*Injected crash*'
                $blockedPath = @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '.pspkt-content-*.tmp')[0].FullName
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'after-terminal:TempCreate'
                { Publish-FoundationJournaledFile -Journal $journal -Destination $ReplayReceiptPath -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__replay-receipt') -EvidenceKey '__replay-receipt' } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            $independentPath = @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '.pspkt-content-*.tmp' | Where-Object { $_.FullName -cne $blockedPath })[0].FullName
            $heldFile = [IO.File]::Open($blockedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
            try {
                { Invoke-FoundationRecovery -Prestate $prestate -Action Rollback -Journal $journal } | Should -Throw '*Rollback preserved conflicts*'
                [IO.File]::Exists($independentPath) | Should -BeFalse
                [IO.File]::Exists($blockedPath) | Should -BeTrue
            }
            finally { $heldFile.Dispose() }
        }

        It 'preserves both foreign attribute identities and unowned backup-pattern files' {
            New-FoundationBaselineRepository -LiteralPath $RepositoryRoot
            $unownedBackupPath = Join-Path $RepositoryRoot 'foreign.pspkt-preimage-existing'
            [IO.File]::WriteAllText($unownedBackupPath, 'unowned')
            New-FoundationExecutionPrestate -LiteralPath $PrestatePath
            $prestate = Read-FoundationExecutionPrestate -Binding ([pscustomobject]@{Bytes=[IO.File]::ReadAllBytes($PrestatePath);Length=(Get-Item $PrestatePath).Length})
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $foreignRecords = @()
            foreach ($relativePath in @('certification/.gitattributes','tests/.gitattributes')) {
                $destination = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
                $baselineBytes = [IO.File]::ReadAllBytes($destination)
                [IO.File]::Move($destination, (Join-Path $script:testScratch ((Split-Path -Parent $relativePath) + '-retired')))
                [IO.File]::WriteAllBytes($destination, $baselineBytes)
                $foreignRecords += Get-FoundationOwnedFileRecord $destination
            }
            { Invoke-FoundationRecovery -Prestate $prestate -Action Rollback -Journal $journal } | Should -Throw '*Rollback preserved conflicts*'
            foreach ($record in $foreignRecords) { Test-FoundationOwnedFileRecord $record | Should -BeTrue }
            [IO.File]::ReadAllText($unownedBackupPath) | Should -Be 'unowned'
        }

        It 'preserves captured empty directories and removes destination-adjacent directory nonces' {
            New-FoundationBaselineRepository -LiteralPath $RepositoryRoot
            $capturedPaths = @(
                (Join-Path $RepositoryRoot 'certification\schema\catalog'),
                (Join-Path $RepositoryRoot 'certification\vectors\phase4-schema-authority-foundation')
            )
            $identities = @{}
            foreach ($path in $capturedPaths) {
                [IO.Directory]::CreateDirectory($path) | Out-Null
                $identities[$path] = Get-FoundationNativeDirectoryIdentity $path
            }
            New-FoundationExecutionPrestate -LiteralPath $PrestatePath
            $prestate = Read-FoundationExecutionPrestate -Binding ([pscustomobject]@{Bytes=[IO.File]::ReadAllBytes($PrestatePath);Length=(Get-Item $PrestatePath).Length})
            $newParent = Join-Path $script:testScratch 'new-receipt-parent'
            $InitReceiptPath = Join-Path $newParent 'init.json'
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'after-mutation:DirectoryTempCreate'
                { Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath $newParent } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            $journal = Repair-FoundationUnmatchedJournalOperations -Journal (Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease)
            $ownership = Get-FoundationJournalOwnership -Journal $journal
            $directory = @($ownership.Directories.Values)[0]
            (Split-Path -Parent $directory.Path) | Should -Be $script:testScratch
            (Invoke-FoundationRecovery -Prestate $prestate -Action Rollback -Journal $journal).status | Should -Be 'rolled-back'
            [IO.Directory]::Exists($directory.Path) | Should -BeFalse
            foreach ($path in $capturedPaths) { Get-FoundationNativeDirectoryIdentity $path | Should -Be $identities[$path] }
        }

        It 'validates all current state before returning already-complete Finalize' {
            $prestate = New-FoundationRecoveryTestPrestate -BeforeCapture {
                [IO.File]::WriteAllText((Join-Path $RepositoryRoot 'untracked.pspkt-preimage-existing'), 'untracked preimage-pattern file')
                [IO.File]::AppendAllText((Join-Path $RepositoryRoot '.git\info\exclude'), "`nignored.pspkt-preimage-existing`n")
                [IO.File]::WriteAllText((Join-Path $RepositoryRoot 'ignored.pspkt-preimage-existing'), 'ignored preimage-pattern file')
            }
            $unownedPatterns = @(
                (Get-FoundationOwnedFileRecord (Join-Path $RepositoryRoot 'untracked.pspkt-preimage-existing')),
                (Get-FoundationOwnedFileRecord (Join-Path $RepositoryRoot 'ignored.pspkt-preimage-existing'))
            )
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            $initBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt'
            $replayBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__replay-receipt'
            $replay = ConvertFrom-FoundationStrictUtf8 -Bytes $replayBytes | ConvertFrom-Json
            $journal.Lease.Stream.Dispose()
            $journal = $null
            [IO.Directory]::Move($RecoveryJournalPath, (Join-Path $script:testScratch 'seed-journal'))
            Invoke-FoundationPromotionGate -Prestate $prestate -InitReceiptBytes $initBytes -InitReceiptDestination $InitReceiptPath -ReplayReceiptBytes $replayBytes -ReplayReceiptDestination $ReplayReceiptPath -ExpectedAllowlistHashes $replay
            (Invoke-FoundationRecovery -Prestate $prestate -Action Finalize).status | Should -Be 'already-complete'
            foreach ($record in $unownedPatterns) { Test-FoundationOwnedFileRecord $record | Should -BeTrue }
            foreach ($path in @(
                (Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $bootstrapContract.MapRelativePath),
                $InitReceiptPath,
                (Join-Path $RepositoryRoot 'README.md')
            )) {
                $bytes = [IO.File]::ReadAllBytes($path)
                try {
                    if ($path -ceq $InitReceiptPath) {
                        [IO.File]::Move($path, "$path.saved")
                    }
                    else { [IO.File]::WriteAllText($path, 'changed after completion') }
                    { Invoke-FoundationRecovery -Prestate $prestate -Action Finalize } | Should -Throw
                }
                finally {
                    if ($path -ceq $InitReceiptPath) { [IO.File]::Move("$path.saved", $path) }
                    else { [IO.File]::WriteAllBytes($path, $bytes) }
                }
            }
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            $consumedTemporary = @($journal.Operations | Where-Object { $_.Intent.Record.operation -ceq 'TempCreate' })[0].Intent.Record.details.tempPath
            $journal.Lease.Stream.Dispose()
            [IO.File]::WriteAllText($consumedTemporary, 'foreign replacement at consumed temporary')
            { Invoke-FoundationRecovery -Prestate $prestate -Action Finalize } | Should -Throw '*known temporary*'
            [IO.File]::ReadAllText($consumedTemporary) | Should -Be 'foreign replacement at consumed temporary'
        }

        It 'rolls back promoted files and receipts when receipt publication fails' {
            $prestate = New-FoundationRecoveryTestPrestate
            [void](New-FoundationRecoveryTestJournal)
            $prepared = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            $initBytes = Get-FoundationJournalEvidenceBytes -Journal $prepared -Key '__init-receipt'
            $replayBytes = Get-FoundationJournalEvidenceBytes -Journal $prepared -Key '__replay-receipt'
            $replay = ConvertFrom-FoundationStrictUtf8 -Bytes $replayBytes | ConvertFrom-Json
            $prepared.Lease.Stream.Dispose()
            [IO.Directory]::Move($RecoveryJournalPath, (Join-Path $script:testScratch 'seed-journal'))
            $publicationFailure = [pscustomobject]@{ Attempts=0; PromotedFiles=0; InitPublished=$false; Backups=0 }
            $realOwnedMove = ${function:Move-FoundationNativeOwnedFileCreateOnly}
            function Move-FoundationNativeOwnedFileCreateOnly {
                param([string]$Source,[string]$Destination,$Record)
                if ($Destination -ceq $ReplayReceiptPath) {
                    $publicationFailure.Attempts++
                    $publicationFailure.PromotedFiles = @($bootstrapContract.Allowlist | Where-Object {
                        [IO.File]::Exists((Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $_))
                    }).Count
                    $publicationFailure.InitPublished = [IO.File]::Exists($InitReceiptPath) -and
                        (Get-FoundationFileSha $InitReceiptPath) -ceq (Get-FoundationHostSha256 $initBytes)
                    $publicationFailure.Backups = @(Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.pspkt-preimage-*' -Recurse -File -Force).Count
                    throw [IO.IOException]::new('Injected replay receipt publication failure after admission.')
                }
                & $realOwnedMove -Source $Source -Destination $Destination -Record $Record
            }
            { Invoke-FoundationPromotionGate -Prestate $prestate -InitReceiptBytes $initBytes -InitReceiptDestination $InitReceiptPath -ReplayReceiptBytes $replayBytes -ReplayReceiptDestination $ReplayReceiptPath -ExpectedAllowlistHashes $replay } |
                Should -Throw '*Injected replay receipt publication failure after admission*'
            $publicationFailure.Attempts | Should -Be 1
            $publicationFailure.PromotedFiles | Should -Be 66
            $publicationFailure.InitPublished | Should -BeTrue
            $publicationFailure.Backups | Should -Be 2
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            @($journal.Operations | Where-Object { $_.Intent.Record.operation -ceq 'RolledBack' -and $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied' }).Count | Should -Be 1
            Assert-FoundationRolledBackState -Prestate $prestate -Journal $journal
            $after = Get-FoundationRepositorySnapshot
            (Get-FoundationCanonicalHash $after.index) | Should -BeExactly (Get-FoundationCanonicalHash $prestate.index)
            (Get-FoundationCanonicalHash $after.productionOdb) | Should -BeExactly (Get-FoundationCanonicalHash $prestate.productionOdb)
            foreach ($baseline in $prestate.allowedBaseline) {
                $path = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $baseline.path
                [IO.File]::Exists($path) | Should -Be $baseline.exists
                if ($baseline.exists) {
                    (Get-FoundationFileSha $path) | Should -BeExactly $baseline.sha256
                    (Get-FoundationNativeFileIdentity $path) | Should -Not -BeExactly $baseline.identity
                }
            }
            foreach ($receipt in @($InitReceiptPath,$ReplayReceiptPath,$CompletionReceiptPath)) { [IO.File]::Exists($receipt) | Should -BeFalse }
            @(Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.pspkt-preimage-*' -Recurse -Force).Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $RecoveryJournalPath -Filter '.pspkt-content-*.tmp' -File -Force).Count | Should -Be 0
            $journal.Lease.Stream.Dispose()
            $journal = $null
            $retry = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$RepositoryRoot,'-ScratchRoot',(Join-Path $script:testScratch 'rolled-back-retry'),
                '-SourceRoot',$script:testSource,'-PrestatePath',$PrestatePath,'-InitReceiptPath',$InitReceiptPath,
                '-ReplayReceiptPath',$ReplayReceiptPath,'-RecoveryJournalPath',$RecoveryJournalPath,
                '-CompletionReceiptPath',$CompletionReceiptPath,'-FoundationInit','-Promote'
            )
            $retry.ExitCode | Should -Not -Be 0
            ($retry.Output -join "`n") | Should -Match 'terminal RolledBack'
            ($retry.Output -join "`n") | Should -Not -Match 'init-already'
            $freshAuthority = Join-Path $script:testScratch 'fresh-authority'
            [IO.Directory]::CreateDirectory($freshAuthority) | Out-Null
            $freshJournalPath = Join-Path $freshAuthority 'recovery-journal'
            $staleCaptureRetry = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$RepositoryRoot,'-ScratchRoot',(Join-Path $script:testScratch 'stale-capture-retry'),
                '-SourceRoot',$script:testSource,'-PrestatePath',$PrestatePath,'-InitReceiptPath',(Join-Path $freshAuthority 'init.json'),
                '-ReplayReceiptPath',(Join-Path $freshAuthority 'replay.json'),'-RecoveryJournalPath',$freshJournalPath,
                '-CompletionReceiptPath',(Join-Path $freshAuthority 'completion.json'),'-FoundationInit','-Promote'
            )
            $staleCaptureRetry.ExitCode | Should -Not -Be 0
            ($staleCaptureRetry.Output -join "`n") | Should -Match 'Allowlist baseline identity changed'
            (Test-Path -LiteralPath $freshJournalPath) | Should -BeFalse
            $freshPrestatePath = Join-Path $freshAuthority 'prestate.json'
            $freshCapture = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$RepositoryRoot,'-ScratchRoot',(Join-Path $script:testScratch 'fresh-capture'),
                '-PrestatePath',$freshPrestatePath,'-FoundationCapturePrestate'
            )
            $freshCapture.ExitCode | Should -Be 0 -Because ($freshCapture.Output -join "`n")
            [IO.File]::Exists($freshPrestatePath) | Should -BeTrue
        }

        It 'requires exact promoted files before Finalize can retry incomplete allowlist publication' {
            $prestate = New-FoundationRecoveryTestPrestate
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $destination = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $bootstrapContract.MapRelativePath
            $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
            try {
                $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'after-intent:Publish'
                { Publish-FoundationJournaledFile -Journal $journal -Destination $destination -Bytes ([byte[]]@(1,2,3)) -EvidenceKey $bootstrapContract.MapRelativePath } | Should -Throw '*Injected crash*'
            }
            finally { $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault }
            { Invoke-FoundationRecovery -Prestate $prestate -Action Finalize -Journal $journal } | Should -Throw '*exact promoted file*'
            [IO.File]::Exists($destination) | Should -BeFalse
            [IO.File]::Exists($CompletionReceiptPath) | Should -BeFalse
        }

        It 'rechecks phase predicates after Intent publication rather than publishing a stale Applied' {
            [void](New-FoundationRecoveryTestJournal)
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease (Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive)
            $phaseState = [pscustomobject]@{Satisfied=$true}
            $realPublisher = ${function:Publish-FoundationJournalSegment}
            function Publish-FoundationJournalSegment {
                param($Journal, $Sequence, $Kind, $Record)
                & $realPublisher -Journal $Journal -Sequence $Sequence -Kind $Kind -Record $Record
                if ($Kind -eq 'intent') { $phaseState.Satisfied = $false }
            }
            { Publish-FoundationJournaledPhase -Journal $journal -Phase ReadyToCommit -Predicate { $phaseState.Satisfied } } | Should -Throw '*predicate*'
            $fresh = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $journal.Lease
            $fresh.Operations[0].Terminal.Kind | Should -Be 'not-applied'
            $fresh.Operations[0].Terminal.Record.state.satisfied | Should -BeFalse
        }

        It 'retains distinct promotion and rollback failures with the durable journal location' {
            [void](New-FoundationRecoveryTestJournal)
            $prepared = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            $initBytes = Get-FoundationJournalEvidenceBytes -Journal $prepared -Key '__init-receipt'
            $replayBytes = Get-FoundationJournalEvidenceBytes -Journal $prepared -Key '__replay-receipt'
            $prepared.Lease.Stream.Dispose()
            function New-FoundationRecoveryJournal { return [pscustomobject]@{Path=$RecoveryJournalPath} }
            function Assert-FoundationProductionUnchanged {}
            function Assert-FoundationJournalAuthority {}
            function Ensure-FoundationJournaledDirectory { throw [IO.IOException]::new('distinct promotion cause') }
            function Invoke-FoundationRecovery { throw [InvalidOperationException]::new('distinct rollback cause') }
            $prestate = [pscustomobject]@{repo=$RepositoryRoot;allowedBaseline=@()}
            $caught = $null
            try {
                Invoke-FoundationPromotionGate -Prestate $prestate -InitReceiptBytes $initBytes -InitReceiptDestination $InitReceiptPath -ReplayReceiptBytes $replayBytes -ReplayReceiptDestination $ReplayReceiptPath -ExpectedAllowlistHashes @{}
            }
            catch { $caught = $_.Exception }
            $caught | Should -BeOfType ([AggregateException])
            $caught.InnerExceptions.Count | Should -Be 2
            $caught.InnerExceptions[0].Message | Should -Match 'distinct promotion cause'
            $caught.InnerExceptions[1].Message | Should -Match 'distinct rollback cause'
            $caught.Message | Should -Match ([regex]::Escape($RecoveryJournalPath))
        }

        It 'preserves a substituted prestate temporary and keeps the move failure primary' {
            New-FoundationBaselineRepository -LiteralPath $RepositoryRoot
            $race = [pscustomobject]@{ Source=$null; Retired=$null }
            function Move-FoundationNativeOwnedFileCreateOnly {
                param([string]$Source,[string]$Destination,$Record)
                $bytes = [IO.File]::ReadAllBytes($Source)
                $race.Source = $Source
                $race.Retired = "$Source.retired"
                [IO.File]::Move($Source, $race.Retired)
                [IO.File]::WriteAllBytes($Source, $bytes)
                throw [IO.IOException]::new('owned move rejected replacement')
            }
            $caught = $null
            try { New-FoundationExecutionPrestate -LiteralPath $PrestatePath }
            catch { $caught = $_.Exception }
            $caught | Should -BeOfType ([AggregateException])
            $caught.InnerExceptions.Count | Should -Be 2
            $caught.InnerExceptions[0].Message | Should -Match 'owned move rejected replacement'
            $caught.InnerExceptions[1].Message | Should -Match 'Owned file identity changed'
            [IO.File]::Exists($race.Source) | Should -BeTrue
            [IO.File]::Exists($race.Retired) | Should -BeTrue
            [IO.File]::Exists($PrestatePath) | Should -BeFalse
        }
    }

    It 'freezes the exact disjoint 11 input and 55 output paths' {
        Assert-PspktFoundationContract -Contract $script:contract
        $script:contract.InputPathSet.Count | Should -Be 11
        $script:contract.OutputPathSet.Count | Should -Be 55
        $script:contract.Allowlist.Count | Should -Be 66
        $script:contract.OneAChildContractTimeoutSeconds | Should -Be 180
        $script:contract.OneAEmpiricalRuntimeSeconds | Should -Be 385
        $script:contract.OneASupervisorTimeoutMilliseconds | Should -Be 600000
        $script:contract.RecoveryJournalSchemaId | Should -Be 'PspktFoundationRecoveryJournalV1'
        $script:contract.CompletionReceiptSchemaId | Should -Be 'PspktFoundationCompletionReceiptV1'
        $script:contract.CandidateInputFileMaximumBytes | Should -Be 1048576
        $script:contract.CandidateInputAggregateMaximumBytes | Should -Be 8388608
        $script:contract.PrestateMaximumBytes | Should -Be 67108864
        $script:contract.AuthorityReceiptAggregateMaximumBytes | Should -Be 3145728
        $script:contract.GeneratedOutputAggregateMaximumBytes | Should -Be 16777216
        $script:contract.GitNulPathMaximumBytes | Should -Be 16777216
        $script:contract.GitLogicalProjectionAggregateMaximumBytes | Should -Be 33554432
        $script:contract.RecoveryJournalSegmentMaximumBytes | Should -Be 16384
        $script:contract.RecoveryJournalMaximumBytes | Should -Be 33554432
        $script:contract.RecoveryJournalMaximumSegments | Should -Be 1536
    }

    It 'publishes all allowlisted paths and exactly 52 fixture cases' {
        foreach ($relativePath in $script:contract.Allowlist) {
            $fullPath = Resolve-PspktFoundationPath -Root $script:repositoryRoot -RelativePath $relativePath
            [IO.File]::Exists($fullPath) | Should -BeTrue -Because $relativePath
        }
        $manifestPath = Resolve-PspktFoundationPath -Root $script:repositoryRoot -RelativePath $script:contract.ManifestRelativePath
        $manifest = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($manifestPath)) | ConvertFrom-Json
        @($manifest.cases).Count | Should -Be 52
        @($manifest.cases.path | Sort-Object -Unique).Count | Should -Be 52
    }

    It 'keeps every fixture byte hash synchronized with the manifest' {
        $manifestPath = Resolve-PspktFoundationPath -Root $script:repositoryRoot -RelativePath $script:contract.ManifestRelativePath
        $manifest = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($manifestPath)) | ConvertFrom-Json
        foreach ($case in $manifest.cases) {
            $fixturePath = Resolve-PspktFoundationPath -Root $script:repositoryRoot -RelativePath ([string]$case.path)
            $bytes = [IO.File]::ReadAllBytes($fixturePath)
            $bytes.Length | Should -Be ([int]$case.length) -Because ([string]$case.path)
            (Get-PspktFoundationSha256 -Bytes $bytes) | Should -Be ([string]$case.sha256) -Because ([string]$case.path)
        }
    }

    It 'pins text and binary attributes for every new surface' {
        $certificationAttributes = [IO.File]::ReadAllLines((Join-Path $script:repositoryRoot 'certification\.gitattributes'))
        $testAttributes = [IO.File]::ReadAllLines((Join-Path $script:repositoryRoot 'tests\.gitattributes'))
        $expectedCertificationLines = @(
            '/lib/Pspkt.Certification.FoundationCatalogEngine.cs text eol=lf -filter -ident -working-tree-encoding'
            '/lib/Pspkt.Certification.FoundationPolicy.cs text eol=lf -filter -ident -working-tree-encoding'
            '/lib/Pspkt.Certification.FoundationVerify.cs text eol=lf -filter -ident -working-tree-encoding'
            '/lib/Pspkt.Certification.FoundationContract.ps1 text eol=lf -filter -ident -working-tree-encoding'
            '/validators/Invoke-PspktPhase4SchemaAuthorityFoundationValidators.ps1 text eol=lf -filter -ident -working-tree-encoding'
            '/validators/Test-PspktPhase4SchemaAuthorityFoundation.ps1 text eol=lf -filter -ident -working-tree-encoding'
            '/vectors/New-PspktPhase4SchemaAuthorityFoundationVectors.ps1 text eol=lf -filter -ident -working-tree-encoding'
            '/schema/catalog/foundation.catalog.v1.json -text -eol -filter -ident -working-tree-encoding'
            '/schema/foundation-schema.v1.json -text -eol -filter -ident -working-tree-encoding'
            '/schema/foundation-id-map.v1.json -text -eol -filter -ident -working-tree-encoding'
            '/vectors/phase4-schema-authority-foundation/** -text -eol -filter -ident -working-tree-encoding'
        )
        foreach ($line in $expectedCertificationLines) {
            $certificationAttributes | Should -Contain $line
        }
        $testAttributes | Should -Contain '/pspkt.Phase4SchemaAuthorityFoundation.Tests.ps1 text eol=lf -filter -ident -working-tree-encoding'
    }

    It 'uses atomic create-only publication and retained source handles' {
        $validatorText = [IO.File]::ReadAllText($script:validatorPath)
        $validatorText | Should -Not -Match 'Add-Type\s+-TypeDefinition'
        $validatorText | Should -Match 'PspktFoundationHostM29'
        $validatorText | Should -Match 'int rootDirectoryOffset = IntPtr.Size == 8 \? 8 : 4;'
        $validatorText | Should -Match 'int fileNameOffset = checked\(fileNameLengthOffset \+ 4\);'
        $validatorText | Should -Not -Match '\bunsafe\b'
        $validatorText | Should -Match 'installed-version registry subkey disappeared or could not be opened'
        $hostAssembly = New-FoundationTestHostAssembly
        $nativeFileSystemType = $hostAssembly.GetType('Pspkt.Certification.FoundationHost.NativeFileSystem', $true, $false)
        $nativeJobType = $hostAssembly.GetType('Pspkt.Certification.FoundationHost.NativeJobAuthority', $true, $false)
        $nativeFileSystemType.GetField('BuildMarker').GetValue($null) | Should -Be 'PspktFoundationHostM29'
        foreach ($methodName in @('CreateKillOnCloseJob','AssignProcess','IsProcessAssigned','TerminateJob','GetActiveProcessCount','WaitForActiveProcessCountZero','CloseJob','ClearStandardHandleInheritance','CloseStandardOutputAndError')) {
            $nativeJobType.GetMethod($methodName) | Should -Not -BeNullOrEmpty
        }
        $hostAssembly.GetType('Pspkt.Certification.FoundationHost.BinaryProcess', $true, $false).GetMethod('Run') | Should -Not -BeNullOrEmpty
        $rawWrapperMatch = [regex]::Match($validatorText, "(?s)\`$foundationRawLaunchWrapperSource = @'\r?\n(.*?)\r?\n'@")
        $rawWrapperMatch.Success | Should -BeTrue
        $rawWrapperText = $rawWrapperMatch.Groups[1].Value
        $openGateIndex = $rawWrapperText.IndexOf('OpenExisting($GateName')
        $waitGateIndex = $rawWrapperText.IndexOf('WaitOne(120000)')
        $decodePayloadIndex = $rawWrapperText.IndexOf('FromBase64String($PayloadBase64)')
        $startTargetIndex = $rawWrapperText.IndexOf('$target.Start()')
        $openGateIndex | Should -BeGreaterOrEqual 0
        $waitGateIndex | Should -BeGreaterThan $openGateIndex
        $decodePayloadIndex | Should -BeGreaterThan $waitGateIndex
        $startTargetIndex | Should -BeGreaterThan $decodePayloadIndex

        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        $rawFunctionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-FoundationRawProcessResult' }, $true))[0]
        $rawFunctionText = $rawFunctionAst.Extent.Text
        $wrapperHostIndex = $rawFunctionText.IndexOf('$startInfo.FileName = $script:RawLaunchAuthority.HostPath')
        $assignIndex = $rawFunctionText.IndexOf('Add-FoundationProcessToNativeJob')
        $membershipIndex = $rawFunctionText.IndexOf('Test-FoundationProcessInNativeJob')
        $gateSetIndex = $rawFunctionText.IndexOf('$gate.Set()')
        $wrapperHostIndex | Should -BeGreaterOrEqual 0
        $assignIndex | Should -BeGreaterThan $wrapperHostIndex
        $membershipIndex | Should -BeGreaterThan $assignIndex
        $gateSetIndex | Should -BeGreaterThan $membershipIndex
        ([regex]::Matches($rawFunctionText, '\$startInfo\.FileName = \$FileName')).Count | Should -Be 1
        $job = [IntPtr]$nativeJobType.GetMethod('CreateKillOnCloseJob').Invoke($null, @())
        $jobProcess = [Diagnostics.Process]::new()
        $jobProcessStarted = $false
        try {
            $jobProcess.StartInfo = [Diagnostics.ProcessStartInfo]::new($script:hostPath, '-NoLogo -NoProfile -Command "Start-Sleep -Seconds 60"')
            $jobProcess.StartInfo.UseShellExecute = $false
            $jobProcess.StartInfo.CreateNoWindow = $true
            $jobProcess.Start() | Should -BeTrue
            $jobProcessStarted = $true
            $nativeJobType.GetMethod('AssignProcess').Invoke($null, [object[]]@($job, $jobProcess.Handle))
            $nativeJobType.GetMethod('IsProcessAssigned').Invoke($null, [object[]]@($job, $jobProcess.Handle)) | Should -BeTrue
            [uint32]$nativeJobType.GetMethod('GetActiveProcessCount').Invoke($null, [object[]]@($job)) | Should -BeGreaterOrEqual 1
            $nativeJobType.GetMethod('TerminateJob').Invoke($null, [object[]]@($job))
            $nativeJobType.GetMethod('WaitForActiveProcessCountZero').Invoke($null, [object[]]@($job, 15000))
            $jobProcess.WaitForExit(15000) | Should -BeTrue
        }

        finally {
            if ($jobProcessStarted -and -not $jobProcess.HasExited) {
                $jobProcess.Kill()
                [void]$jobProcess.WaitForExit(15000)
            }
            $jobProcess.Dispose()
            $nativeJobType.GetMethod('CloseJob').Invoke($null, [object[]]@($job))
        }
        foreach ($role in @('production','receipt')) {
            $sourcePath = Join-Path $script:testScratch "$role-source.tmp"
            $destinationPath = Join-Path $script:testScratch "$role-destination.tmp"
            [IO.File]::WriteAllText($sourcePath, 'candidate', [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($destinationPath, 'racing', [Text.UTF8Encoding]::new($false))
            { $nativeFileSystemType.GetMethod('MoveCreateOnly').Invoke($null, [object[]]@([string]$sourcePath, [string]$destinationPath)) } | Should -Throw
            [IO.File]::ReadAllText($destinationPath) | Should -Be 'racing'
            [IO.File]::Exists($sourcePath) | Should -BeTrue
        }
        $ownedMoveMethod = $nativeFileSystemType.GetMethod(
            'MoveOwnedFileCreateOnly',
            [type[]]@([string],[string],[string],[int64],[string]))
        $ownedMoveMethod | Should -Not -BeNullOrEmpty
        $ownedMoveSource = Join-Path $script:testScratch 'owned-move-source.tmp'
        $ownedMoveDestination = Join-Path $script:testScratch 'owned-move-destination.tmp'
        [IO.File]::WriteAllText($ownedMoveSource, 'owned-source', [Text.UTF8Encoding]::new($false))
        $ownedMoveIdentity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$ownedMoveSource))
        $ownedMoveLength = (Get-Item -LiteralPath $ownedMoveSource).Length
        $ownedMoveSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($ownedMoveSource))
        $ownedMoveMethod.Invoke($null, [object[]]@(
            [string]$ownedMoveSource,
            [string]$ownedMoveDestination,
            [string]$ownedMoveIdentity,
            [int64]$ownedMoveLength,
            [string]$ownedMoveSha256))
        [IO.File]::Exists($ownedMoveSource) | Should -BeFalse
        [IO.File]::ReadAllText($ownedMoveDestination) | Should -Be 'owned-source'

        $ownedCollisionSource = Join-Path $script:testScratch 'owned-collision-source.tmp'
        $ownedCollisionDestination = Join-Path $script:testScratch 'owned-collision-destination.tmp'
        [IO.File]::WriteAllText($ownedCollisionSource, 'owned-collision', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($ownedCollisionDestination, 'foreign-collision', [Text.UTF8Encoding]::new($false))
        $ownedCollisionIdentity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$ownedCollisionSource))
        $ownedCollisionLength = (Get-Item -LiteralPath $ownedCollisionSource).Length
        $ownedCollisionSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($ownedCollisionSource))
        { $ownedMoveMethod.Invoke($null, [object[]]@(
            [string]$ownedCollisionSource,
            [string]$ownedCollisionDestination,
            [string]$ownedCollisionIdentity,
            [int64]$ownedCollisionLength,
            [string]$ownedCollisionSha256)) } | Should -Throw
        [IO.File]::ReadAllText($ownedCollisionSource) | Should -Be 'owned-collision'
        [IO.File]::ReadAllText($ownedCollisionDestination) | Should -Be 'foreign-collision'

        $wrongIdentitySource = Join-Path $script:testScratch 'wrong-identity-source.tmp'
        $wrongIdentityDestination = Join-Path $script:testScratch 'wrong-identity-destination.tmp'
        [IO.File]::WriteAllText($wrongIdentitySource, 'wrong-identity', [Text.UTF8Encoding]::new($false))
        $wrongIdentityLength = (Get-Item -LiteralPath $wrongIdentitySource).Length
        $wrongIdentitySha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($wrongIdentitySource))
        { $ownedMoveMethod.Invoke($null, [object[]]@(
            [string]$wrongIdentitySource,
            [string]$wrongIdentityDestination,
            '00000000:0000000000000000',
            [int64]$wrongIdentityLength,
            [string]$wrongIdentitySha256)) } | Should -Throw
        [IO.File]::ReadAllText($wrongIdentitySource) | Should -Be 'wrong-identity'
        [IO.File]::Exists($wrongIdentityDestination) | Should -BeFalse

        $substitutionSource = Join-Path $script:testScratch 'substitution-source.tmp'
        $substitutionRetired = Join-Path $script:testScratch 'substitution-retired.tmp'
        $substitutionDestination = Join-Path $script:testScratch 'substitution-destination.tmp'
        [IO.File]::WriteAllText($substitutionSource, 'same-bytes', [Text.UTF8Encoding]::new($false))
        $substitutionIdentity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$substitutionSource))
        $substitutionLength = (Get-Item -LiteralPath $substitutionSource).Length
        $substitutionSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($substitutionSource))
        [IO.File]::Move($substitutionSource, $substitutionRetired)
        [IO.File]::WriteAllText($substitutionSource, 'same-bytes', [Text.UTF8Encoding]::new($false))
        { $ownedMoveMethod.Invoke($null, [object[]]@(
            [string]$substitutionSource,
            [string]$substitutionDestination,
            [string]$substitutionIdentity,
            [int64]$substitutionLength,
            [string]$substitutionSha256)) } | Should -Throw
        [IO.File]::ReadAllText($substitutionSource) | Should -Be 'same-bytes'
        [IO.File]::ReadAllText($substitutionRetired) | Should -Be 'same-bytes'
        [IO.File]::Exists($substitutionDestination) | Should -BeFalse

        $linkedSource = Join-Path $script:testScratch 'linked-source.tmp'
        $linkedAlias = Join-Path $script:testScratch 'linked-alias.tmp'
        $linkedDestination = Join-Path $script:testScratch 'linked-destination.tmp'
        [IO.File]::WriteAllText($linkedSource, 'linked-source', [Text.UTF8Encoding]::new($false))
        $linkedIdentity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$linkedSource))
        $linkedLength = (Get-Item -LiteralPath $linkedSource).Length
        $linkedSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($linkedSource))
        New-Item -ItemType HardLink -Path $linkedAlias -Target $linkedSource | Out-Null
        { $ownedMoveMethod.Invoke($null, [object[]]@(
            [string]$linkedSource,
            [string]$linkedDestination,
            [string]$linkedIdentity,
            [int64]$linkedLength,
            [string]$linkedSha256)) } | Should -Throw
        [IO.File]::ReadAllText($linkedSource) | Should -Be 'linked-source'
        [IO.File]::ReadAllText($linkedAlias) | Should -Be 'linked-source'
        [IO.File]::Exists($linkedDestination) | Should -BeFalse

        $retainedPath = Join-Path $script:testScratch 'retained-candidate.ps1'
        $replacementPath = Join-Path $script:testScratch 'replacement-candidate.ps1'
        [IO.File]::WriteAllText($retainedPath, 'original', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($replacementPath, 'replacement', [Text.UTF8Encoding]::new($false))
        $retainedStream = [IO.File]::Open($retainedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            { $nativeFileSystemType.GetMethod('MoveReplace').Invoke($null, [object[]]@([string]$replacementPath, [string]$retainedPath)) } | Should -Throw
            [IO.File]::ReadAllText($retainedPath) | Should -Be 'original'
        }
        finally {
            $retainedStream.Dispose()
        }
        $attributePath = Join-Path $script:testScratch 'attribute-race.txt'
        $attributeBackupPath = Join-Path $script:testScratch 'attribute-race.backup'
        $attributeCandidatePath = Join-Path $script:testScratch 'attribute-race.candidate'
        [IO.File]::WriteAllText($attributePath, 'preimage', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($attributeCandidatePath, 'candidate', [Text.UTF8Encoding]::new($false))
        $nativeFileSystemType.GetMethod('MoveCreateOnly').Invoke($null, [object[]]@([string]$attributePath, [string]$attributeBackupPath))
        [IO.File]::WriteAllText($attributePath, 'racing', [Text.UTF8Encoding]::new($false))
        { $nativeFileSystemType.GetMethod('MoveCreateOnly').Invoke($null, [object[]]@([string]$attributeCandidatePath, [string]$attributePath)) } | Should -Throw
        [IO.File]::ReadAllText($attributePath) | Should -Be 'racing'
        [IO.File]::ReadAllText($attributeBackupPath) | Should -Be 'preimage'

        $ownedPath = Join-Path $script:testScratch 'rollback-owned.txt'
        [IO.File]::WriteAllText($ownedPath, 'owned', [Text.UTF8Encoding]::new($false))
        $ownedIdentity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$ownedPath))
        $ownedLength = (Get-Item -LiteralPath $ownedPath).Length
        $ownedSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($ownedPath))
        [IO.File]::Delete($ownedPath)
        [IO.File]::WriteAllText($ownedPath, 'racing', [Text.UTF8Encoding]::new($false))
        $racingIdentity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$ownedPath))
        $racingIdentity | Should -Not -Be $ownedIdentity
        { $nativeFileSystemType.GetMethod('DeleteOwnedFile').Invoke($null, [object[]]@([string]$ownedPath, [string]$ownedIdentity, [int64]$ownedLength, [string]$ownedSha256)) } | Should -Throw
        [IO.File]::ReadAllText($ownedPath) | Should -Be 'racing'
        $privateObjectPath = Join-Path $script:testScratch 'private-object'
        $privateObjectLink = Join-Path $script:testScratch 'private-object-link'
        [IO.File]::WriteAllText($privateObjectPath, 'object', [Text.UTF8Encoding]::new($false))
        New-Item -ItemType HardLink -Path $privateObjectLink -Target $privateObjectPath | Out-Null
        $nativeFileSystemType.GetMethod('GetLinkCount').Invoke($null, [object[]]@([string]$privateObjectPath)) | Should -Be 2

        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        foreach ($functionName in @('Invoke-FoundationHostMethod','Move-FoundationNativeOwnedFileCreateOnly')) {
            $functionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true))[0]
            Invoke-Expression $functionAst.Extent.Text
        }
        $moveMethod = $nativeFileSystemType.GetMethod('MoveCreateOnly', [type[]]@([string],[string]))
        $script:FoundationHostBinding = [pscustomobject]@{ Delegates = @{
            MoveCreateOnly = [Delegate]::CreateDelegate([Action[string,string]], $moveMethod)
            MoveOwnedFileCreateOnly = [Delegate]::CreateDelegate([Action[string,string,string,int64,string]], $ownedMoveMethod)
        } }
        $wrapperSource = Join-Path $script:testScratch 'wrapper-owned-source.tmp'
        $wrapperDestination = Join-Path $script:testScratch 'wrapper-owned-destination.tmp'
        [IO.File]::WriteAllText($wrapperSource, 'wrapper-owned', [Text.UTF8Encoding]::new($false))
        $wrapperRecord = [pscustomobject]@{
            Identity = [string]$nativeFileSystemType.GetMethod('GetIdentity').Invoke($null, [object[]]@([string]$wrapperSource))
            Length = (Get-Item -LiteralPath $wrapperSource).Length
            Sha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($wrapperSource))
        }
        Move-FoundationNativeOwnedFileCreateOnly -Source $wrapperSource -Destination $wrapperDestination -Record $wrapperRecord
        [IO.File]::ReadAllText($wrapperDestination) | Should -Be 'wrapper-owned'
        $normalizedException = $null
        try {
            Invoke-FoundationHostMethod -Name 'MoveCreateOnly' -Arguments @(
                (Join-Path $script:testScratch 'missing-native-source'),
                (Join-Path $script:testScratch 'missing-native-destination')
            )
        }
        catch {
            $normalizedException = $_.Exception
        }
        $normalizedException | Should -Not -BeNullOrEmpty
        $normalizedException | Should -Not -BeOfType ([System.Management.Automation.MethodInvocationException])
        $normalizedException.Message | Should -Not -Match 'Exception calling'
        $script:FoundationHostBinding = $null
    }

    It 'decodes adversarial NUL-delimited Git paths and rejects traversal records' {
        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        foreach ($name in @('ConvertFrom-FoundationStrictUtf8','Assert-FoundationDecodedGitPath','ConvertFrom-FoundationGitNulRecords','ConvertFrom-FoundationGitNulPaths')) {
            $functionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true))[0]
            Invoke-Expression $functionAst.Extent.Text
        }
        $paths = @("café.txt","tab`tname.txt",'quote"name.txt',"line`nbreak.txt",'normal..segment.txt')
        $bytes = [Collections.Generic.List[byte]]::new()
        foreach ($path in $paths) {
            $bytes.AddRange([Text.UTF8Encoding]::new($false,$true).GetBytes($path))
            $bytes.Add(0)
        }
        ConvertFrom-FoundationGitNulPaths -Bytes $bytes.ToArray() | Should -Be $paths
        { ConvertFrom-FoundationGitNulPaths -Bytes ([Text.Encoding]::UTF8.GetBytes("../escape`0")) } | Should -Throw
        { ConvertFrom-FoundationGitNulPaths -Bytes ([Text.Encoding]::UTF8.GetBytes("a\path`0")) } | Should -Throw
        { ConvertFrom-FoundationGitNulPaths -Bytes ([byte[]]@(0xC3,0x28,0)) } | Should -Throw
        { ConvertFrom-FoundationGitNulPaths -Bytes ([byte[]]@(0)) } | Should -Throw
    }

    It 'enforces exact bounded-file and journal capacity maxima' {
        $contract = $script:contract
        ([int64]$contract.RecoveryJournalMaximumSegments * [int64]$contract.RecoveryJournalSegmentMaximumBytes + [int64]$contract.RecoveryJournalEvidenceReserveBytes) | Should -Be $contract.RecoveryJournalMaximumBytes
        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        $functionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-FoundationJournalCapacity' }, $true))[0]
        Invoke-Expression $functionAst.Extent.Text
        $bootstrapContract = $contract
        Test-FoundationJournalCapacity -SegmentCount 1536 -MaximumSegmentBytes 16384 -EvidenceBytes 8388608 | Should -BeTrue
        Test-FoundationJournalCapacity -SegmentCount 1537 -MaximumSegmentBytes 16384 -EvidenceBytes 8388608 | Should -BeFalse
        Test-FoundationJournalCapacity -SegmentCount 1536 -MaximumSegmentBytes 16385 -EvidenceBytes 8388608 | Should -BeFalse
        Test-FoundationJournalCapacity -SegmentCount 1536 -MaximumSegmentBytes 16384 -EvidenceBytes 8388609 | Should -BeFalse
        $bindingFunctionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-FoundationFileBinding' }, $true))[0]
        Invoke-Expression $bindingFunctionAst.Extent.Text
        function Assert-FoundationNoReparsePath { param([string]$LiteralPath) }
        function Get-FoundationNativeFileIdentity { param([string]$LiteralPath) return $LiteralPath }
        function Get-FoundationHostSha256 {
            param([byte[]]$Bytes)
            $hash = [Security.Cryptography.SHA256]::Create()
            try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
            finally { $hash.Dispose() }
        }
        $script:CandidateInputBytes = [int64]0
        $maximumPath = Join-Path $script:testScratch 'maximum-candidate.bin'
        $overMaximumPath = Join-Path $script:testScratch 'over-maximum-candidate.bin'
        [IO.File]::WriteAllBytes($maximumPath, [byte[]]::new(1048576))
        $maximumBinding = New-FoundationFileBinding -LiteralPath $maximumPath -Role 'candidate:maximum'
        try { $maximumBinding.Length | Should -Be 1048576 } finally { $maximumBinding.Stream.Dispose() }
        $overMaximumStream = [IO.File]::Open($overMaximumPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $overMaximumStream.SetLength(1048577) } finally { $overMaximumStream.Dispose() }
        { New-FoundationFileBinding -LiteralPath $overMaximumPath -Role 'candidate:over-maximum' } | Should -Throw '*Immutable binding exceeds its bounded-file cap*'
    }

    It 'declares Recovery and Completion authorities on Init Replay and Recovery parameter sets' {
        $command = Get-Command $script:validatorPath
        foreach ($parameterSet in @('InitMode','ReplayPrecommitMode','ReplayCommitMode','RecoveryMode')) {
            $set = @($command.ParameterSets | Where-Object Name -eq $parameterSet)
            $set.Count | Should -Be 1
            @($set[0].Parameters.Name) | Should -Contain 'RecoveryJournalPath'
            @($set[0].Parameters.Name) | Should -Contain 'CompletionReceiptPath'
        }
        $recovery = @($command.ParameterSets | Where-Object Name -eq 'RecoveryMode')[0]
        @($recovery.Parameters.Name) | Should -Contain 'FoundationRecover'
        @($recovery.Parameters.Name) | Should -Contain 'RecoveryAction'
        @($recovery.Parameters.Name) | Should -Contain 'RecoveredCompletionReceiptPath'
        @($recovery.Parameters.Name) | Should -Not -Contain 'SourceRoot'
        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        $replayStateFunction = @($validatorAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Assert-FoundationReplayProductionState'
        }, $true))[0]
        $replayStateFunction | Should -Not -BeNullOrEmpty
        $replayStateFunction.Extent.Text | Should -Not -Match 'Get-FoundationGitStageRecords'
        $validatorText = [IO.File]::ReadAllText($script:validatorPath)
        ([regex]::Matches($validatorText, 'Assert-FoundationReplayProductionState -Prestate')).Count | Should -Be 2
        $finalBindingIndex = $validatorText.LastIndexOf('Assert-FoundationImmutableBindings')
        $finalReplayIndex = $validatorText.LastIndexOf('Assert-FoundationReplayProductionState -Prestate')
        $resultWriteIndex = $validatorText.LastIndexOf('ConvertTo-PspktCanonicalJson -Value $resultDocument')
        $finalReplayIndex | Should -BeGreaterThan $finalBindingIndex
        $resultWriteIndex | Should -BeGreaterThan $finalReplayIndex
    }

    It 'retains the admitted Replay mode across terminal production checks' {
        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        $functionAst = @($validatorAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Assert-FoundationReplayProductionState'
        }, $true))[0]
        Invoke-Expression $functionAst.Extent.Text
        $bootstrapContract = $script:contract
        $script:replayProductionCalls = [Collections.Generic.List[object]]::new()
        function Read-FoundationRecoveryJournal { param($LiteralPath,$Lease) return $Journal.Fresh }
        function Assert-FoundationTransactionLayout { param($Journal) }
        function Assert-FoundationJournalAuthority { param($Journal,$Prestate) }
        function Get-FoundationCompletionAuthorityPath { param($Journal) return 'C:\completion.json' }
        function Test-FoundationCompletionReceipt {
            param($Journal,$LiteralPath,[switch]$ReturnDocument)
            return [pscustomobject]@{candidateTreeOid=('a'*40);mapBlobOid=('b'*40)}
        }
        function Get-FoundationOwnedDirectoryDeltas { param($Journal,$Prestate) return @() }
        function Get-FoundationGitOutput {
            param([string[]]$Arguments)
            if ($Arguments[0] -eq 'cat-file') { return 'commit' }
            return 'c' * 40
        }
        function Get-FoundationGitNulPaths { param([string[]]$Arguments) return $bootstrapContract.Allowlist }
        function Test-FoundationOrdinalStringSetEquality { param($Expected,$Actual) return $true }
        function Assert-FoundationProductionUnchanged {
            param(
                $Prestate,
                $ExpectedAllowlistHashes,
                [string]$CommittedReplayOid,
                [string[]]$TransactionOwnedDirectories = @(),
                [switch]$AllowStaged
            )
            $script:replayProductionCalls.Add([pscustomobject]@{
                CommittedReplayOid=$CommittedReplayOid
                AllowStaged=[bool]$AllowStaged
            })
        }
        $Journal = [pscustomobject]@{
            Path='C:\journal'
            Lease=[pscustomobject]@{}
            Fresh=[pscustomobject]@{Path='C:\journal';Lease=[pscustomobject]@{};Operations=@()}
        }
        $receipt = [pscustomobject]@{candidateTreeOid=('a'*40);mapBlobOid=('b'*40)}
        foreach ($mode in @('Unstaged','Staged','Committed')) {
            $parameters = @{
                Prestate=[pscustomobject]@{}
                ReplayReceipt=$receipt
                ReplayMode=$mode
                Journal=$Journal
                SelectedTreeOid=('a'*40)
                SelectedMapBlobOid=('b'*40)
                SelectedCommitOid=('c'*40)
            }
            [void](Assert-FoundationReplayProductionState @parameters)
        }
        $script:replayProductionCalls.Count | Should -Be 3
        $script:replayProductionCalls[0].AllowStaged | Should -BeFalse
        $script:replayProductionCalls[0].CommittedReplayOid | Should -BeNullOrEmpty
        $script:replayProductionCalls[1].AllowStaged | Should -BeTrue
        $script:replayProductionCalls[1].CommittedReplayOid | Should -BeNullOrEmpty
        $script:replayProductionCalls[2].AllowStaged | Should -BeFalse
        $script:replayProductionCalls[2].CommittedReplayOid | Should -Be ('c' * 40)
    }

    It 'terminates raw timeout and output-cap process trees and joins inherited pipe reads' {
        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        foreach ($functionName in @(
            'ConvertTo-FoundationWindowsArgument',
            'Stop-FoundationProcess',
            'Complete-FoundationRawRead',
            'Invoke-FoundationRawProcessCleanup',
            'Get-FoundationRawProcessResult',
            'ConvertTo-FoundationRawLaunchPayload',
            'New-FoundationNativeJob',
            'Invoke-FoundationJobDelegate',
            'Add-FoundationProcessToNativeJob',
            'Get-FoundationNativeJobActiveProcessCount',
            'Test-FoundationProcessInNativeJob',
            'Stop-FoundationNativeJob',
            'Wait-FoundationNativeJobEmpty',
            'Close-FoundationNativeJob'
        )) {
            $functionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true))[0]
            Invoke-Expression $functionAst.Extent.Text
        }
        function Assert-FoundationHostBinding {
            if ($null -eq $script:FoundationHostBinding) {
                throw 'FoundationHost binding is absent.'
            }
        }
        function Assert-FoundationRawLaunchAuthority {
            if ($null -eq $script:RawLaunchAuthority) {
                throw 'Raw launch authority is absent.'
            }
        }
        $script:WindowsRoot = [IO.Directory]::GetParent([Environment]::SystemDirectory).FullName
        $hostAssembly = New-FoundationTestHostAssembly
        $jobType = $hostAssembly.GetType('Pspkt.Certification.FoundationHost.NativeJobAuthority', $true, $false)
        $script:FoundationHostBinding = [pscustomobject]@{
            DllPath = $script:lastFoundationHostAssemblyPath
            Delegates = @{
                CreateKillOnCloseJob = [Delegate]::CreateDelegate([Func[IntPtr]], $jobType.GetMethod('CreateKillOnCloseJob'))
                AssignProcess = [Delegate]::CreateDelegate([Action[IntPtr,IntPtr]], $jobType.GetMethod('AssignProcess'))
                IsProcessAssigned = [Delegate]::CreateDelegate([Func[IntPtr,IntPtr,bool]], $jobType.GetMethod('IsProcessAssigned'))
                TerminateJob = [Delegate]::CreateDelegate([Action[IntPtr]], $jobType.GetMethod('TerminateJob'))
                GetActiveProcessCount = [Delegate]::CreateDelegate([Func[IntPtr,uint32]], $jobType.GetMethod('GetActiveProcessCount'))
                WaitForActiveProcessCountZero = [Delegate]::CreateDelegate([Action[IntPtr,int]], $jobType.GetMethod('WaitForActiveProcessCountZero'))
                CloseJob = [Delegate]::CreateDelegate([Action[IntPtr]], $jobType.GetMethod('CloseJob'))
            }
        }
        $validatorText = [IO.File]::ReadAllText($script:validatorPath)
        $rawWrapperMatch = [regex]::Match($validatorText, "(?s)\`$foundationRawLaunchWrapperSource = @'\r?\n(.*?)\r?\n'@")
        $rawWrapperPath = Join-Path $script:testScratch 'Invoke-FoundationRawLaunch.ps1'
        [IO.File]::WriteAllText($rawWrapperPath, $rawWrapperMatch.Groups[1].Value, [Text.UTF8Encoding]::new($false))
        $script:RawLaunchAuthority = [pscustomobject]@{
            HostPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            WrapperPath = $rawWrapperPath
        }
        $rawTargetHostPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $detachedFixtureSource = Join-Path $script:testScratch 'DetachedProcessFixture.cs'
        $detachedFixturePath = Join-Path $script:testScratch 'DetachedProcessFixture.exe'
        [IO.File]::WriteAllText($detachedFixtureSource, @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
internal static class DetachedProcessFixture
{
    private const uint CreateNoWindow = 0x08000000U;
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        internal int cb;
        internal string reserved;
        internal string desktop;
        internal string title;
        internal int x;
        internal int y;
        internal int xSize;
        internal int ySize;
        internal int xCountChars;
        internal int yCountChars;
        internal int fillAttribute;
        internal int flags;
        internal short showWindow;
        internal short reservedSize;
        internal IntPtr reservedPointer;
        internal IntPtr standardInput;
        internal IntPtr standardOutput;
        internal IntPtr standardError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr process;
        internal IntPtr thread;
        internal int processId;
        internal int threadId;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int standardHandle, IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName,
        IntPtr commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);
    private static void CloseStandardHandle(int standardHandle)
    {
        IntPtr handle = GetStdHandle(standardHandle);
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            CloseHandle(handle);
        }
        SetStdHandle(standardHandle, IntPtr.Zero);
    }
    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }
    private static void WriteIdentity(string path)
    {
        using (Process process = Process.GetCurrentProcess())
        {
            File.WriteAllText(path, process.Id.ToString() + "|" + process.StartTime.ToUniversalTime().Ticks.ToString(), new UTF8Encoding(false));
        }
    }
    private static int Main(string[] arguments)
    {
        if (arguments[0] == "child")
        {
            CloseStandardHandle(-11);
            CloseStandardHandle(-12);
            WriteIdentity(arguments[1]);
            File.WriteAllText(arguments[2], "ready", new UTF8Encoding(false));
            Thread.Sleep(60000);
            return 0;
        }
        WriteIdentity(arguments[1]);
        string executable = Process.GetCurrentProcess().MainModule.FileName;
        string commandLine = Quote(executable) + " child " + Quote(arguments[2]) + " " + Quote(arguments[3]);
        IntPtr commandBuffer = Marshal.StringToHGlobalUni(commandLine);
        try
        {
            StartupInfo startupInfo = new StartupInfo();
            startupInfo.cb = Marshal.SizeOf(typeof(StartupInfo));
            ProcessInformation processInformation;
            if (!CreateProcessW(executable, commandBuffer, IntPtr.Zero, IntPtr.Zero, false, CreateNoWindow, IntPtr.Zero, null, ref startupInfo, out processInformation))
            {
                return Marshal.GetLastWin32Error();
            }
            CloseHandle(processInformation.thread);
            CloseHandle(processInformation.process);
        }
        finally
        {
            Marshal.FreeHGlobal(commandBuffer);
        }
        Stopwatch clock = Stopwatch.StartNew();
        while (!File.Exists(arguments[3]) && clock.ElapsedMilliseconds < 10000)
        {
            Thread.Sleep(10);
        }
        if (!File.Exists(arguments[3]))
        {
            return 94;
        }
        return 0;
    }
}
'@, [Text.UTF8Encoding]::new($false))
        $frameworkDirectory = if ([Environment]::Is64BitProcess) { 'Framework64' } else { 'Framework' }
        $compilerPath = Join-Path ([IO.Directory]::GetParent([Environment]::SystemDirectory).FullName) "Microsoft.NET\$frameworkDirectory\v4.0.30319\csc.exe"
        & $compilerPath /nologo /target:exe /langversion:5 "/out:$detachedFixturePath" $detachedFixtureSource
        $LASTEXITCODE | Should -Be 0

        function Test-FoundationRecordedProcessExited {
            param([Parameter(Mandatory = $true)][string]$ReceiptPath)

            $parts = ([IO.File]::ReadAllText($ReceiptPath)).Trim().Split('|')
            $processId = [int]$parts[0]
            $creationTicks = [int64]$parts[1]
            $candidate = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($null -eq $candidate) {
                return $true
            }
            try {
                return $candidate.StartTime.ToUniversalTime().Ticks -ne $creationTicks
            }
            catch {
                return $false
            }
            finally {
                $candidate.Dispose()
            }
        }

        function Invoke-FoundationRawTreeScenario {
            param(
                [Parameter(Mandatory = $true)][string]$Name,
                [Parameter(Mandatory = $true)]
                [ValidateSet('Timeout','Flood','Normal')]
                [string]$Mode
            )

            $targetReceipt = Join-Path $script:testScratch "$Name-target.receipt"
            $descendantReceipt = Join-Path $script:testScratch "$Name-descendant.receipt"
            $descendantReady = Join-Path $script:testScratch "$Name-descendant.ready"
            $descendantScript = Join-Path $script:testScratch "$Name-descendant.ps1"
            $targetScript = Join-Path $script:testScratch "$Name-target.ps1"
            $escapedDescendantReceipt = $descendantReceipt.Replace("'", "''")
            $escapedDescendantReady = $descendantReady.Replace("'", "''")
            $escapedTargetReceipt = $targetReceipt.Replace("'", "''")
            $escapedDescendantScript = $descendantScript.Replace("'", "''")
            $escapedHostPath = $rawTargetHostPath.Replace("'", "''")
            if ($Mode -eq 'Normal') {
                $targetContent = $null
            }
            else {
                [IO.File]::WriteAllText(
                    $descendantScript,
                    "`$process = Get-Process -Id `$PID; [IO.File]::WriteAllText('$escapedDescendantReceipt', (`$PID.ToString() + '|' + `$process.StartTime.ToUniversalTime().Ticks.ToString()), [Text.UTF8Encoding]::new(`$false)); [IO.File]::WriteAllText('$escapedDescendantReady', 'ready', [Text.UTF8Encoding]::new(`$false)); Start-Sleep -Seconds 60",
                    [Text.UTF8Encoding]::new($false))
                $floodStatement = if ($Mode -eq 'Flood') { "`$bytes=[byte[]]::new(4096); [Console]::OpenStandardOutput().Write(`$bytes,0,`$bytes.Length);" } else { '' }
                $targetContent = "`$process = Get-Process -Id `$PID; [IO.File]::WriteAllText('$escapedTargetReceipt', (`$PID.ToString() + '|' + `$process.StartTime.ToUniversalTime().Ticks.ToString()), [Text.UTF8Encoding]::new(`$false)); `$startInfo=[Diagnostics.ProcessStartInfo]::new('$escapedHostPath',('-NoLogo -NoProfile -File ""$escapedDescendantScript""')); `$startInfo.UseShellExecute=`$false; `$startInfo.CreateNoWindow=`$true; `$descendant=[Diagnostics.Process]::Start(`$startInfo); while(-not [IO.File]::Exists('$escapedDescendantReady')){Start-Sleep -Milliseconds 10}; $floodStatement Start-Sleep -Seconds 60"
            }
            if ($Mode -ne 'Normal') {
                [IO.File]::WriteAllText(
                    $targetScript,
                    $targetContent,
                    [Text.UTF8Encoding]::new($false))
            }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $caught = $null
            try {
                if ($Mode -eq 'Flood') {
                    Get-FoundationRawProcessResult -FileName $rawTargetHostPath -Arguments @('-NoLogo','-NoProfile','-File',$targetScript) -TimeoutMilliseconds 30000 -RetainCapBytes 1024 -WorkingDirectory $script:testScratch | Out-Null
                }
                elseif ($Mode -eq 'Normal') {
                    Get-FoundationRawProcessResult -FileName $detachedFixturePath -Arguments @('target',$targetReceipt,$descendantReceipt,$descendantReady) -TimeoutMilliseconds 30000 -WorkingDirectory $script:testScratch | Out-Null
                }
                else {
                    $timeout = if ($Mode -eq 'Normal') { 30000 } else { 3000 }
                    Get-FoundationRawProcessResult -FileName $rawTargetHostPath -Arguments @('-NoLogo','-NoProfile','-File',$targetScript) -TimeoutMilliseconds $timeout -WorkingDirectory $script:testScratch | Out-Null
                }
            }
            catch {
                $caught = $_.Exception
            }
            $caught | Should -Not -BeNullOrEmpty
            $caught | Should -Not -BeOfType ([AggregateException])
            if ($Mode -eq 'Flood') {
                $caught.ToString() | Should -Match 'Process stdout exceeded cap'
            }
            elseif ($Mode -eq 'Normal') {
                $caught.ToString() | Should -Match 'Raw process descendants survived normal completion'
            }
            else {
                $caught.ToString() | Should -Match 'Process timed out'
            }
            $clock.ElapsedMilliseconds | Should -BeLessThan 25000
            [IO.File]::Exists($targetReceipt) | Should -BeTrue
            [IO.File]::Exists($descendantReceipt) | Should -BeTrue
            (Test-FoundationRecordedProcessExited -ReceiptPath $targetReceipt) | Should -BeTrue
            (Test-FoundationRecordedProcessExited -ReceiptPath $descendantReceipt) | Should -BeTrue
        }

        try {
            $successScript = Join-Path $script:testScratch 'raw-success.ps1'
            [IO.File]::WriteAllText($successScript, "[Console]::Out.Write('stdout-ok'); [Console]::Error.Write('stderr-ok'); exit 37", [Text.UTF8Encoding]::new($false))
            $success = Get-FoundationRawProcessResult -FileName $rawTargetHostPath -Arguments @('-NoLogo','-NoProfile','-File',$successScript) -TimeoutMilliseconds 30000 -WorkingDirectory $script:testScratch
            $success.ExitCode | Should -Be 37
            $success.StdOut | Should -Be 'stdout-ok'
            $success.StdErr | Should -Be 'stderr-ok'

            foreach ($failureCase in @(
                [pscustomobject]@{ Variable='PSPKT_FOUNDATION_TEST_FAIL_RAW_ASSIGN'; Message='Injected raw wrapper assignment failure.' }
                [pscustomobject]@{ Variable='PSPKT_FOUNDATION_TEST_FAIL_RAW_MEMBERSHIP'; Message='Raw wrapper exact Job membership verification failed.' }
            )) {
                $receiptPath = Join-Path $script:testScratch ($failureCase.Variable + '.receipt')
                $failureScript = Join-Path $script:testScratch ($failureCase.Variable + '.ps1')
                [IO.File]::WriteAllText($failureScript, "[IO.File]::WriteAllText('$($receiptPath.Replace("'","''"))','launched',[Text.UTF8Encoding]::new(`$false))", [Text.UTF8Encoding]::new($false))
                $savedValue = [Environment]::GetEnvironmentVariable($failureCase.Variable)
                try {
                    [Environment]::SetEnvironmentVariable($failureCase.Variable, '1')
                    { Get-FoundationRawProcessResult -FileName $rawTargetHostPath -Arguments @('-NoLogo','-NoProfile','-File',$failureScript) -TimeoutMilliseconds 30000 -WorkingDirectory $script:testScratch } | Should -Throw ('*' + $failureCase.Message + '*')
                }
                finally {
                    [Environment]::SetEnvironmentVariable($failureCase.Variable, $savedValue)
                }
                [IO.File]::Exists($receiptPath) | Should -BeFalse
            }

            Invoke-FoundationRawTreeScenario -Name 'timeout' -Mode Timeout
            Invoke-FoundationRawTreeScenario -Name 'flood' -Mode Flood
            Invoke-FoundationRawTreeScenario -Name 'normal-descendant' -Mode Normal
        }
        finally {
            $script:FoundationHostBinding = $null
        }
    }

    It 'releases the first attribute preimage binding when the second acquisition fails' {
        $tokens = $null
        $parseErrors = $null
        $validatorAst = [System.Management.Automation.Language.Parser]::ParseFile($script:validatorPath, [ref]$tokens, [ref]$parseErrors)
        $functionAst = @($validatorAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-FoundationAttributePreimageTransactions' }, $true))[0]
        Invoke-Expression $functionAst.Extent.Text

        $firstPath = Join-Path $script:testScratch 'first-attribute.txt'
        $secondPath = Join-Path $script:testScratch 'second-attribute.txt'
        [IO.File]::WriteAllText($firstPath, 'first', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($secondPath, 'second', [Text.UTF8Encoding]::new($false))
        $factoryState = [pscustomobject]@{ Count = 0 }
        $bindingFactory = {
            param([string]$LiteralPath,[string]$Role)

            $factoryState.Count++
            if ($factoryState.Count -eq 2) {
                throw 'Injected second attribute binding failure.'
            }
            $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            return [pscustomobject]@{
                Stream = $stream
                Sha256 = 'expected'
            }
        }.GetNewClosure()
        $specifications = @(
            [pscustomobject]@{ RelativePath='certification/.gitattributes'; Path=$firstPath; ExpectedSha256='expected' }
            [pscustomobject]@{ RelativePath='tests/.gitattributes'; Path=$secondPath; ExpectedSha256='expected' }
        )
        { New-FoundationAttributePreimageTransactions -Specifications $specifications -BindingFactory $bindingFactory } | Should -Throw 'Injected second attribute binding failure.'
        $factoryState.Count | Should -Be 2
        $exclusive = [IO.File]::Open($firstPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $exclusive.Dispose()
    }

    It 'reports a missing baseline origin without a null Trim failure' {
        $sourceRepository = Join-Path $script:testScratch 'originless-source'
        $destinationRepository = Join-Path $script:testScratch 'originless-destination'
        & $script:gitPath -c core.hooksPath=NUL init $sourceRepository | Out-Null
        $LASTEXITCODE | Should -Be 0
        { New-FoundationBaselineRepository -LiteralPath $destinationRepository -SourceRepository $sourceRepository } | Should -Throw 'Unable to resolve the origin for the frozen baseline.'
    }

    It 'rejects pre-existing scratch roots and junction aliases before writes' {
        $productionRoot = Join-Path $script:testScratch 'production'
        New-FoundationBaselineRepository -LiteralPath $productionRoot
        $preExistingScratch = Join-Path $script:testScratch 'pre-existing-scratch'
        [IO.Directory]::CreateDirectory($preExistingScratch) | Out-Null
        $preExisting = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',$preExistingScratch,
            '-PrestatePath',(Join-Path $script:testScratch 'pre-existing-prestate.json'),
            '-FoundationCapturePrestate'
        )
        $preExisting.ExitCode | Should -Not -Be 0
        ($preExisting.Output -join "`n") | Should -Match 'ScratchRoot must be absent'
        @(Get-ChildItem -LiteralPath $preExistingScratch -Force).Count | Should -Be 0

        $repositoryAlias = Join-Path $script:testScratch 'repository-alias'
        New-Item -ItemType Junction -Path $repositoryAlias -Target $productionRoot | Out-Null
        try {
            $aliasedRepository = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$repositoryAlias,
                '-ScratchRoot',(Join-Path $script:testScratch 'repository-alias-scratch'),
                '-PrestatePath',(Join-Path $script:testScratch 'repository-alias-prestate.json'),
                '-FoundationCapturePrestate'
            )
            $aliasedRepository.ExitCode | Should -Not -Be 0
            ($aliasedRepository.Output -join "`n") | Should -Match 'Reparse point rejected'
        }
        finally {
            [IO.Directory]::Delete($repositoryAlias)
        }

        $sourceAlias = Join-Path $script:testScratch 'source-alias'
        New-Item -ItemType Junction -Path $sourceAlias -Target $script:testSource | Out-Null
        try {
            $aliasedSource = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$productionRoot,
                '-ScratchRoot',(Join-Path $script:testScratch 'source-alias-scratch'),
                '-SourceRoot',$sourceAlias,
                '-PrestatePath',(Join-Path $script:testScratch 'source-alias-prestate.json'),
                '-InitReceiptPath',(Join-Path $script:testScratch 'source-alias-init.json'),
                '-ReplayReceiptPath',(Join-Path $script:testScratch 'source-alias-replay.json'),
                '-FoundationInit',
                '-Promote'
            )
            $aliasedSource.ExitCode | Should -Not -Be 0
            ($aliasedSource.Output -join "`n") | Should -Match 'Reparse point rejected'
        }
        finally {
            [IO.Directory]::Delete($sourceAlias)
        }

        $scratchTarget = Join-Path $script:testScratch 'scratch-target'
        $scratchAlias = Join-Path $script:testScratch 'scratch-alias'
        [IO.Directory]::CreateDirectory($scratchTarget) | Out-Null
        New-Item -ItemType Junction -Path $scratchAlias -Target $scratchTarget | Out-Null
        try {
            $aliasedScratch = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$productionRoot,
                '-ScratchRoot',(Join-Path $scratchAlias 'owned'),
                '-PrestatePath',(Join-Path $script:testScratch 'scratch-alias-prestate.json'),
                '-FoundationCapturePrestate'
            )
            $aliasedScratch.ExitCode | Should -Not -Be 0
            ($aliasedScratch.Output -join "`n") | Should -Match 'Reparse point rejected'
            (Test-Path -LiteralPath (Join-Path $scratchTarget 'owned')) | Should -BeFalse
        }
        finally {
            [IO.Directory]::Delete($scratchAlias)
        }

        $prestatePath = Join-Path $script:testScratch 'alias-authority\prestate.json'
        $capture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'receipt-alias-capture'),
            '-PrestatePath',$prestatePath,
            '-FoundationCapturePrestate'
        )
        $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
        $receiptTarget = Join-Path $script:testScratch 'receipt-target'
        $receiptAlias = Join-Path $script:testScratch 'receipt-alias'
        [IO.Directory]::CreateDirectory($receiptTarget) | Out-Null
        New-Item -ItemType Junction -Path $receiptAlias -Target $receiptTarget | Out-Null
        try {
            $aliasedReceipt = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$productionRoot,
                '-ScratchRoot',(Join-Path $script:testScratch 'receipt-alias-run'),
                '-SourceRoot',$script:testSource,
                '-PrestatePath',$prestatePath,
                '-InitReceiptPath',(Join-Path $receiptAlias 'init.json'),
                '-ReplayReceiptPath',(Join-Path $receiptAlias 'replay.json'),
                '-FoundationInit',
                '-Promote'
            )
            $aliasedReceipt.ExitCode | Should -Not -Be 0
            ($aliasedReceipt.Output -join "`n") | Should -Match 'Reparse point rejected'
            @(Get-ChildItem -LiteralPath $receiptTarget -Force).Count | Should -Be 0
        }
        finally {
            [IO.Directory]::Delete($receiptAlias)
        }

        $validatorText = [IO.File]::ReadAllText($script:validatorPath)
        $oneAMatch = [regex]::Match($validatorText, '(?s)function Initialize-FoundationOneA \{.*?1A root must be absent before setup\..*?^}', [Text.RegularExpressions.RegexOptions]::Multiline)
        $oneAMatch.Success | Should -BeTrue
        $oneAMatch.Value | Should -Match 'Invoke-FoundationPrivateGitRaw'
        $oneAMatch.Value | Should -Match 'protocol\.file\.allow=always'
        $oneAMatch.Value | Should -Match 'objects\\info\\alternates'
    }

    It 'rejects staged baseline and graph-rewrite state before journal or candidate execution' {
        $stagedRoot = Join-Path $script:testScratch 'staged-production'
        New-FoundationBaselineRepository -LiteralPath $stagedRoot
        [IO.File]::WriteAllBytes((Join-Path $stagedRoot 'staged-probe.bin'), [byte[]]@(1,2,3))
        & $script:gitPath -C $stagedRoot add -- staged-probe.bin
        $LASTEXITCODE | Should -Be 0
        $stagedCapture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$stagedRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'staged-capture'),
            '-PrestatePath',(Join-Path $script:testScratch 'staged-authority\prestate.json'),
            '-FoundationCapturePrestate'
        )
        $stagedCapture.ExitCode | Should -Not -Be 0
        ($stagedCapture.Output -join "`n") | Should -Match 'init-precondition: staged index differs from HEAD'
        (Test-Path -LiteralPath (Join-Path $script:testScratch 'staged-authority\recovery-journal')) | Should -BeFalse

        $graftsRoot = Join-Path $script:testScratch 'grafts-production'
        New-FoundationBaselineRepository -LiteralPath $graftsRoot
        [IO.File]::WriteAllText((Join-Path $graftsRoot '.git\info\grafts'), '', [Text.UTF8Encoding]::new($false))
        $graftsCapture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$graftsRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'grafts-capture'),
            '-PrestatePath',(Join-Path $script:testScratch 'grafts-authority\prestate.json'),
            '-FoundationCapturePrestate'
        )
        $graftsCapture.ExitCode | Should -Not -Be 0
        ($graftsCapture.Output -join "`n") | Should -Match 'Production Git graph state is forbidden'
    }

    It 'reports actual Git exits and only cleans exchange files after proven retirement' {
        $rawRoot = Join-Path $script:testScratch 'raw-git-production'
        New-FoundationBaselineRepository -LiteralPath $rawRoot
        $savedForcedExit = $env:PSPKT_FOUNDATION_TEST_FORCE_GIT_EXIT
        try {
            $env:PSPKT_FOUNDATION_TEST_FORCE_GIT_EXIT = 'raw'
            $rawFailureScratch = Join-Path $script:testScratch 'raw-git-failure'
            $rawFailure = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$rawRoot,
                '-ScratchRoot',$rawFailureScratch,
                '-PrestatePath',(Join-Path $script:testScratch 'raw-git-authority\prestate.json'),
                '-FoundationCapturePrestate'
            )
        }
        finally {
            $env:PSPKT_FOUNDATION_TEST_FORCE_GIT_EXIT = $savedForcedExit
        }
        $rawFailure.ExitCode | Should -Not -Be 0
        ($rawFailure.Output -join "`n") | Should -Match 'git failed with exit 128'
        ($rawFailure.Output -join "`n") | Should -Match 'fatal:'
        @(Get-ChildItem -LiteralPath $rawFailureScratch -Filter 'git-*' -File -Recurse -Force -ErrorAction SilentlyContinue).Count | Should -Be 0

        $boundedRoot = Join-Path $script:testScratch 'bgp'
        New-FoundationBaselineRepository -LiteralPath $boundedRoot
        $boundedAuthority = Join-Path $script:testScratch 'bga'
        $boundedPrestate = Join-Path $boundedAuthority 'p.json'
        $boundedCapture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$boundedRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'bgc'),
            '-PrestatePath',$boundedPrestate,
            '-FoundationCapturePrestate'
        )
        $boundedCapture.ExitCode | Should -Be 0 -Because ($boundedCapture.Output -join "`n")
        foreach ($case in @(
            [pscustomobject]@{ Name='x'; Variable='PSPKT_FOUNDATION_TEST_FORCE_GIT_EXIT'; Value='bounded'; Expected='git failed with exit 128'; Remaining=0 }
            [pscustomobject]@{ Name='p'; Variable='PSPKT_FOUNDATION_TEST_FAIL_POST_RUN_BINDING'; Value='1'; Expected='Injected bounded Git post-Run binding failure'; Remaining=0 }
            [pscustomobject]@{ Name='q'; Variable='PSPKT_FOUNDATION_TEST_THROW_BEFORE_BOUNDED_RUN'; Value='1'; Expected='Injected bounded Git failure before Run'; Remaining=3 }
        )) {
            $savedValue = [Environment]::GetEnvironmentVariable($case.Variable)
            try {
                [Environment]::SetEnvironmentVariable($case.Variable, $case.Value)
                $caseScratch = Join-Path $script:testScratch ("bc" + $case.Name)
                $result = Invoke-FoundationOuter -Arguments @(
                    '-RepositoryRoot',$boundedRoot,
                    '-ScratchRoot',$caseScratch,
                    '-SourceRoot',$script:testSource,
                    '-PrestatePath',$boundedPrestate,
                    '-InitReceiptPath',(Join-Path $boundedAuthority ($case.Name + 'i.json')),
                    '-ReplayReceiptPath',(Join-Path $boundedAuthority ($case.Name + 'r.json')),
                    '-RecoveryJournalPath',(Join-Path $boundedAuthority ($case.Name + 'j')),
                    '-CompletionReceiptPath',(Join-Path $boundedAuthority ($case.Name + 'c.json')),
                    '-FoundationInit',
                    '-Promote'
                )
            }
            finally {
                [Environment]::SetEnvironmentVariable($case.Variable, $savedValue)
            }
            $result.ExitCode | Should -Not -Be 0
            ($result.Output -join "`n") | Should -Match ([regex]::Escape($case.Expected))
            @(Get-ChildItem -LiteralPath $caseScratch -Filter 'git-*' -File -Recurse -Force -ErrorAction SilentlyContinue).Count | Should -Be $case.Remaining
        }
    }

    It 'isolates different candidate assemblies across same-process invocations' {
        foreach ($marker in @('first-candidate','second-candidate')) {
            $productionRoot = Join-Path $script:testScratch "$marker-production"
            New-FoundationBaselineRepository -LiteralPath $productionRoot
            $sourceRoot = Join-Path $script:testScratch "$marker-source"
            [IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
            foreach ($relativePath in $script:contract.InputPathSet) {
                $source = Resolve-PspktFoundationPath -Root $script:testSource -RelativePath $relativePath
                $destination = Resolve-PspktFoundationPath -Root $sourceRoot -RelativePath $relativePath
                [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
                [IO.File]::Copy($source, $destination, $false)
            }
            $policyPath = Join-Path $sourceRoot 'certification\lib\Pspkt.Certification.FoundationPolicy.cs'
            $policyText = [IO.File]::ReadAllText($policyPath)
            $replacement = "public static FoundationCatalogResult Evaluate(byte[] catalogBytes)`r`n        {`r`n            return FoundationCatalogResult.Failure(`"$marker`");"
            $policyText = [regex]::Replace($policyText, 'public static FoundationCatalogResult Evaluate\(byte\[\] catalogBytes\)\s*\{', $replacement, 1)
            [IO.File]::WriteAllText($policyPath, $policyText, [Text.UTF8Encoding]::new($false))
            $prestatePath = Join-Path $script:testScratch "$marker-authority\prestate.json"
            $capture = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$productionRoot,
                '-ScratchRoot',(Join-Path $script:testScratch "$marker-capture"),
                '-PrestatePath',$prestatePath,
                '-FoundationCapturePrestate'
            )
            $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
            $failureText = ''
            try {
                & $script:validatorPath `
                    -RepositoryRoot $productionRoot `
                    -ScratchRoot (Join-Path $script:testScratch "$marker-run") `
                    -SourceRoot $sourceRoot `
                    -PrestatePath $prestatePath `
                    -InitReceiptPath (Join-Path $script:testScratch "$marker-authority\init.json") `
                    -ReplayReceiptPath (Join-Path $script:testScratch "$marker-authority\replay.json") `
                    -RecoveryJournalPath (Join-Path $script:testScratch "$marker-authority\journal") `
                    -CompletionReceiptPath (Join-Path $script:testScratch "$marker-authority\completion.json") `
                    -FoundationInit `
                    -Promote 2>&1 | Out-String | ForEach-Object { $failureText += $_ }
            }
            catch {
                $failureText += $_ | Out-String
            }
            $failureText | Should -Match $marker
        }
    }

    It 'runs CapturePrestate, Init, and fresh Replay through the real outer validator' {
        $productionRoot = Join-Path $script:testScratch 'production'
        New-FoundationBaselineRepository -LiteralPath $productionRoot
        [IO.File]::AppendAllText((Join-Path $productionRoot 'README.md'), "`nM13 non-owned dirty prestate probe.`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $productionRoot 'm13-untracked-probe.txt'), 'retained', [Text.UTF8Encoding]::new($false))
        $adversarialNames = @('café.txt','normal..segment.txt')
        foreach ($name in $adversarialNames) {
            [IO.File]::WriteAllText((Join-Path $productionRoot $name), $name, [Text.UTF8Encoding]::new($false))
        }
        [IO.Directory]::CreateDirectory((Join-Path $productionRoot 'empty-directory-probe')) | Out-Null
        [IO.File]::AppendAllText((Join-Path $productionRoot '.git\info\exclude'), "`nignored-probe.txt`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $productionRoot 'ignored-probe.txt'), 'ignored', [Text.UTF8Encoding]::new($false))
        $indexPath = Join-Path $productionRoot '.git\index'
        $indexHashBeforeCapture = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($indexPath))
        $prestatePath = Join-Path $script:testScratch 'authority\execution-prestate.v2.json'
        $initReceiptPath = Join-Path $script:testScratch 'init-authority\init-receipt.v1.json'
        $replayReceiptPath = Join-Path $script:testScratch 'replay-authority\replay-receipt.v2.json'
        $captureScratch = Join-Path $script:testScratch 'capture'
        $capture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',$captureScratch,
            '-PrestatePath',$prestatePath,
            '-FoundationCapturePrestate'
        )
        $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
        (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($indexPath))) | Should -Be $indexHashBeforeCapture
        [IO.File]::Exists($prestatePath) | Should -BeTrue
        $capturedPrestate = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($prestatePath)) | ConvertFrom-Json
        foreach ($name in $adversarialNames) {
            @($capturedPrestate.untracked) | Should -Contain $name
        }
        @($capturedPrestate.ignored) | Should -Contain 'ignored-probe.txt'
        @($capturedPrestate.worktree.path) | Should -Contain 'empty-directory-probe'

        $initScratch = Join-Path $script:testScratch 'init'
        $init = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',$initScratch,
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-FoundationInit',
            '-Promote'
        )
        $init.ExitCode | Should -Be 0 -Because ($init.Output -join "`n")
        [IO.File]::Exists($initReceiptPath) | Should -BeTrue
        [IO.File]::Exists($replayReceiptPath) | Should -BeTrue
        $replayReceipt = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($replayReceiptPath)) | ConvertFrom-Json
        $initReceiptBytes = [IO.File]::ReadAllBytes($initReceiptPath)
        $replayReceipt.initReceiptSha256 | Should -Be (Get-PspktFoundationSha256 -Bytes $initReceiptBytes)
        $replayReceipt.baselineOid | Should -Be $script:contract.BaselineOid
        $replayReceipt.prestateSha256 | Should -Be (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($prestatePath)))
        $initReceiptHashBeforeReplay = Get-PspktFoundationSha256 -Bytes $initReceiptBytes
        $replayReceiptHashBeforeReplay = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($replayReceiptPath))
        $secondInitScratch = Join-Path $script:testScratch 'second-init'
        $secondInit = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',$secondInitScratch,
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-FoundationInit',
            '-Promote'
        )
        $secondInit.ExitCode | Should -Not -Be 0
        ($secondInit.Output -join "`n") | Should -Match 'init-already'
        @(Get-ChildItem -LiteralPath $secondInitScratch -Filter 'FoundationEngine.dll' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
        $rollbackBlocked = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'rollback-blocked'),
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-RecoveryJournalPath',(Join-Path (Split-Path -Parent $prestatePath) 'recovery-journal'),
            '-CompletionReceiptPath',(Join-Path (Split-Path -Parent $prestatePath) 'completion-receipt.v1.json'),
            '-FoundationRecover',
            '-RecoveryAction','Rollback'
        )
        $rollbackBlocked.ExitCode | Should -Not -Be 0
        ($rollbackBlocked.Output -join "`n") | Should -Match 'valid Completion receipt blocks rollback'

        $fakePath = Join-Path $script:testScratch 'fake-path'
        [IO.Directory]::CreateDirectory($fakePath) | Out-Null
        foreach ($name in @('pwsh.cmd','git.cmd')) {
            [IO.File]::WriteAllText((Join-Path $fakePath $name), "@echo fake>$($name).used", [Text.UTF8Encoding]::new($false))
        }
        $savedPath = $env:PATH
        try {
            $env:PATH = "$fakePath;$savedPath"
            $replayScratch = Join-Path $script:testScratch 'replay'
            $poisonHarnessPath = Join-Path $script:testScratch 'Invoke-PoisonedFoundationOuter.ps1'
            [IO.File]::WriteAllText($poisonHarnessPath, @'
param(
    [string]$ValidatorPath,
    [string]$FakeSystemRoot,
    [string]$RepositoryRoot,
    [string]$ScratchRoot,
    [string]$SourceRoot,
    [string]$PrestatePath,
    [string]$InitReceiptPath,
    [string]$ReplayReceiptPath,
    [string]$RecoveryJournalPath,
    [string]$CompletionReceiptPath,
    [string]$SelectedTreeOid,
    [string]$SelectedMapBlobOid
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$env:SystemRoot=$FakeSystemRoot
& $ValidatorPath `
    -RepositoryRoot $RepositoryRoot `
    -ScratchRoot $ScratchRoot `
    -SourceRoot $SourceRoot `
    -PrestatePath $PrestatePath `
    -InitReceiptPath $InitReceiptPath `
    -ReplayReceiptPath $ReplayReceiptPath `
    -RecoveryJournalPath $RecoveryJournalPath `
    -CompletionReceiptPath $CompletionReceiptPath `
    -FoundationReplay `
    -SelectedTreeOid $SelectedTreeOid `
    -SelectedMapBlobOid $SelectedMapBlobOid
exit 0
'@, [Text.UTF8Encoding]::new($false))
            $savedErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $replayOutput = @(& $script:hostPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $poisonHarnessPath `
                    $script:validatorPath `
                    $fakePath `
                    $productionRoot `
                    $replayScratch `
                    $script:testSource `
                    $prestatePath `
                    $initReceiptPath `
                    $replayReceiptPath `
                    (Join-Path (Split-Path -Parent $prestatePath) 'recovery-journal') `
                    (Join-Path (Split-Path -Parent $prestatePath) 'completion-receipt.v1.json') `
                    ([string]$replayReceipt.candidateTreeOid) `
                    ([string]$replayReceipt.mapBlobOid) 2>&1)
                $replay = [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $replayOutput }
            }
            finally {
                $ErrorActionPreference = $savedErrorActionPreference
            }
        }
        finally {
            $env:PATH = $savedPath
        }
        $replay.ExitCode | Should -Be 0 -Because ($replay.Output -join "`n")
        (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($initReceiptPath))) | Should -Be $initReceiptHashBeforeReplay
        (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($replayReceiptPath))) | Should -Be $replayReceiptHashBeforeReplay
        @(Get-ChildItem -LiteralPath $script:testScratch -Filter 'checkout-*' -Recurse -Force -ErrorAction SilentlyContinue).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:testScratch -Filter 'blob-*.bin' -Recurse -Force -ErrorAction SilentlyContinue).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:testScratch -Filter '*.used' -Recurse -Force -ErrorAction SilentlyContinue).Count | Should -Be 0

        $forgedReceiptPath = Join-Path $script:testScratch 'authority\forged-replay-receipt.v2.json'
        [IO.File]::WriteAllBytes($forgedReceiptPath, (Get-PspktCanonicalJsonBytes -Value ([ordered]@{
            schemaVersion = 2
            schemaId = 'PspktFoundationReplayReceiptV2'
            candidateTreeOid = '0' * 40
            mapBlobOid = '0' * 40
            baselineOid = $replayReceipt.baselineOid
            prestateSha256 = $replayReceipt.prestateSha256
            initReceiptSha256 = $replayReceipt.initReceiptSha256
            catalogSha256 = $replayReceipt.catalogSha256
            schemaSha256 = $replayReceipt.schemaSha256
            mapSha256 = $replayReceipt.mapSha256
            inputHashes = $replayReceipt.inputHashes
            outputHashes = $replayReceipt.outputHashes
        })))
        $forgedReplay = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'forged-replay'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$forgedReceiptPath,
            '-FoundationReplay',
            '-SelectedTreeOid',('0' * 40),
            '-SelectedMapBlobOid',('0' * 40)
        )
        $forgedReplay.ExitCode | Should -Not -Be 0
        ($forgedReplay.Output -join "`n") | Should -Match 'Replay authority paths do not match the Recovery journal'

        & $script:gitPath -C $productionRoot add -- $script:contract.Allowlist
        $LASTEXITCODE | Should -Be 0
        $stagedReplay = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'staged-replay'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-RecoveryJournalPath',(Join-Path (Split-Path -Parent $prestatePath) 'recovery-journal'),
            '-CompletionReceiptPath',(Join-Path (Split-Path -Parent $prestatePath) 'completion-receipt.v1.json'),
            '-FoundationReplay',
            '-SelectedTreeOid',([string]$replayReceipt.candidateTreeOid),
            '-SelectedMapBlobOid',([string]$replayReceipt.mapBlobOid)
        )
        $stagedReplay.ExitCode | Should -Be 0 -Because ($stagedReplay.Output -join "`n")
        & $script:gitPath -C $productionRoot -c user.name='Foundation Test' -c user.email='foundation@example.invalid' commit -m 'Temporary Foundation commit' | Out-Null
        $LASTEXITCODE | Should -Be 0
        $selectedCommitOid = (& $script:gitPath -C $productionRoot rev-parse HEAD).Trim()
        $committedReplayScratch = Join-Path $script:testScratch 'committed-replay'
        $committedReplay = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',$committedReplayScratch,
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-FoundationReplay',
            '-SelectedCommitOid',$selectedCommitOid
        )
        $committedReplay.ExitCode | Should -Be 0 -Because ($committedReplay.Output -join "`n")
        $committedResult = $committedReplay.Output[-1] | ConvertFrom-Json
        $committedResult.mode | Should -Be 'ReplayCommitMode'
        $committedResult.CandidateTreeOid | Should -Be $replayReceipt.candidateTreeOid
        $committedResult.MapBlobOid | Should -Be $replayReceipt.mapBlobOid
        $oneAResult = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $committedReplayScratch 'state\oneA-setup.v1.json'))) | ConvertFrom-Json
        $oneAResult.head | Should -Be $script:contract.BaselineOid
        $privateOdbManifest = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $committedReplayScratch 'state\private-odb-manifest.v1.json'))) | ConvertFrom-Json
        @($privateOdbManifest.roots).Count | Should -Be 3
        @($privateOdbManifest.roots.name | Sort-Object) | Should -Be @('generate','oneA','proof')
        foreach ($root in $privateOdbManifest.roots) {
            [string]::IsNullOrWhiteSpace([string]$root.identity) | Should -BeFalse
            foreach ($object in $root.objects) {
                $object.nlink | Should -Be 1
                [string]::IsNullOrWhiteSpace([string]$object.identity) | Should -BeFalse
            }
            (Test-Path -LiteralPath (Join-Path ([string]$root.path) 'info\alternates')) | Should -BeFalse
        }
        $savedReplayMutation = $env:PSPKT_FOUNDATION_TEST_MUTATE_README_AFTER_REPLAY
        try {
            $env:PSPKT_FOUNDATION_TEST_MUTATE_README_AFTER_REPLAY = '1'
            $terminalDriftReplay = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$productionRoot,
                '-ScratchRoot',(Join-Path $script:testScratch 'terminal-drift-replay'),
                '-SourceRoot',$script:testSource,
                '-PrestatePath',$prestatePath,
                '-InitReceiptPath',$initReceiptPath,
                '-ReplayReceiptPath',$replayReceiptPath,
                '-FoundationReplay',
                '-SelectedCommitOid',$selectedCommitOid
            )
        }
        finally {
            $env:PSPKT_FOUNDATION_TEST_MUTATE_README_AFTER_REPLAY = $savedReplayMutation
        }
        $terminalDriftReplay.ExitCode | Should -Not -Be 0
        ($terminalDriftReplay.Output -join "`n") | Should -Match 'Non-owned worktree projection changed'
        ($terminalDriftReplay.Output -join "`n") | Should -Not -Match 'PspktFoundationExecutionResultV3'
    }

    It 'rejects missing prestate, missing Init receipt, and attribute preimage drift before candidate execution' {
        $productionRoot = Join-Path $script:testScratch 'production'
        New-FoundationBaselineRepository -LiteralPath $productionRoot
        $missingPrestate = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'missing-prestate'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',(Join-Path $script:testScratch 'absent-prestate.json'),
            '-InitReceiptPath',(Join-Path $script:testScratch 'init.json'),
            '-ReplayReceiptPath',(Join-Path $script:testScratch 'replay.json'),
            '-FoundationInit',
            '-Promote'
        )
        $missingPrestate.ExitCode | Should -Not -Be 0
        ($missingPrestate.Output -join "`n") | Should -Match 'existing execution prestate is required'
        @(Get-ChildItem -LiteralPath (Join-Path $script:testScratch 'missing-prestate') -Filter 'FoundationEngine.dll' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0

        $prestatePath = Join-Path $script:testScratch 'authority\execution-prestate.v2.json'
        $capture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'capture'),
            '-PrestatePath',$prestatePath,
            '-FoundationCapturePrestate'
        )
        $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
        $prestateDocument = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($prestatePath)) | ConvertFrom-Json
        $prestateDocument.tracked = @($prestateDocument.tracked | Select-Object -Skip 1)
        $forgedPrestatePath = Join-Path $script:testScratch 'authority\forged-prestate.v2.json'
        [IO.File]::WriteAllBytes($forgedPrestatePath, (Get-PspktCanonicalJsonBytes -Value $prestateDocument))
        $forgedPrestate = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'forged-prestate'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$forgedPrestatePath,
            '-InitReceiptPath',(Join-Path $script:testScratch 'forged-init.json'),
            '-ReplayReceiptPath',(Join-Path $script:testScratch 'forged-replay.json'),
            '-FoundationInit',
            '-Promote'
        )
        $forgedPrestate.ExitCode | Should -Not -Be 0
        ($forgedPrestate.Output -join "`n") | Should -Match 'Tracked path set changed'
        @(Get-ChildItem -LiteralPath (Join-Path $script:testScratch 'forged-prestate') -Filter 'FoundationEngine.dll' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
        $missingReceipt = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'missing-receipt'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',(Join-Path $script:testScratch 'absent-init.json'),
            '-ReplayReceiptPath',(Join-Path $script:testScratch 'absent-replay.json'),
            '-FoundationReplay',
            '-SelectedTreeOid',('0' * 40),
            '-SelectedMapBlobOid',('0' * 40)
        )
        $missingReceipt.ExitCode | Should -Not -Be 0
        ($missingReceipt.Output -join "`n") | Should -Match 'Replay requires an existing Recovery journal'

        $prestateSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($prestatePath))
        $inputHashes = [ordered]@{}
        foreach ($relativePath in $script:contract.InputPathSet) {
            $inputHashes[$relativePath] = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes((Resolve-PspktFoundationPath -Root $script:testSource -RelativePath $relativePath))
            )
        }
        $outputHashes = [ordered]@{}
        foreach ($relativePath in $script:contract.OutputPathSet) {
            $outputHashes[$relativePath] = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes((Resolve-PspktFoundationPath -Root $script:repositoryRoot -RelativePath $relativePath))
            )
        }
        $initReceiptPath = Join-Path $script:testScratch 'authority\case-init.json'
        $initReceiptBytes = Get-PspktCanonicalJsonBytes -Value ([ordered]@{
            schemaVersion = 1
            schemaId = 'PspktFoundationInitReceiptV1'
            baselineOid = $script:contract.BaselineOid
            catalogSha256 = $inputHashes[$script:contract.CatalogRelativePath]
            prestateSha256 = $prestateSha256
            nonce = '0' * 32
        })
        [IO.File]::WriteAllBytes($initReceiptPath, $initReceiptBytes)
        $caseMutatedInputs = [ordered]@{}
        foreach ($property in $inputHashes.GetEnumerator()) {
            if ($property.Key -eq $script:contract.CatalogRelativePath) {
                $caseMutatedInputs[$property.Key.ToUpperInvariant()] = $property.Value
            }
            else {
                $caseMutatedInputs[$property.Key] = $property.Value
            }
        }
        $caseReceiptPath = Join-Path $script:testScratch 'authority\case-replay.json'
        [IO.File]::WriteAllBytes($caseReceiptPath, (Get-PspktCanonicalJsonBytes -Value ([ordered]@{
            schemaVersion = 2
            schemaId = 'PspktFoundationReplayReceiptV2'
            candidateTreeOid = '0' * 40
            mapBlobOid = '0' * 40
            baselineOid = $script:contract.BaselineOid
            prestateSha256 = $prestateSha256
            initReceiptSha256 = Get-PspktFoundationSha256 -Bytes $initReceiptBytes
            catalogSha256 = $inputHashes[$script:contract.CatalogRelativePath]
            schemaSha256 = $outputHashes[$script:contract.SchemaRelativePath]
            mapSha256 = $outputHashes[$script:contract.MapRelativePath]
            inputHashes = $caseMutatedInputs
            outputHashes = $outputHashes
        })))
        $caseReceipt = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'case-receipt'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$caseReceiptPath,
            '-FoundationReplay',
            '-SelectedTreeOid',('0' * 40),
            '-SelectedMapBlobOid',('0' * 40)
        )
        $caseReceipt.ExitCode | Should -Not -Be 0
        ($caseReceipt.Output -join "`n") | Should -Match 'Replay requires an existing Recovery journal'
        @(Get-ChildItem -LiteralPath (Join-Path $script:testScratch 'case-receipt') -Filter 'FoundationEngine.dll' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
        $typedReceiptPath = Join-Path $script:testScratch 'authority\typed-replay.json'
        [IO.File]::WriteAllBytes($typedReceiptPath, (Get-PspktCanonicalJsonBytes -Value ([ordered]@{
            schemaVersion = '2'
            schemaId = 'PspktFoundationReplayReceiptV2'
            candidateTreeOid = '0' * 40
            mapBlobOid = '0' * 40
            baselineOid = $script:contract.BaselineOid
            prestateSha256 = $prestateSha256
            initReceiptSha256 = Get-PspktFoundationSha256 -Bytes $initReceiptBytes
            catalogSha256 = $inputHashes[$script:contract.CatalogRelativePath]
            schemaSha256 = $outputHashes[$script:contract.SchemaRelativePath]
            mapSha256 = $outputHashes[$script:contract.MapRelativePath]
            inputHashes = $inputHashes
            outputHashes = $outputHashes
        })))
        $typedReceipt = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'typed-receipt'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$typedReceiptPath,
            '-FoundationReplay',
            '-SelectedTreeOid',('0' * 40),
            '-SelectedMapBlobOid',('0' * 40)
        )
        $typedReceipt.ExitCode | Should -Not -Be 0
        ($typedReceipt.Output -join "`n") | Should -Match 'Replay requires an existing Recovery journal'

        [IO.File]::AppendAllText((Join-Path $productionRoot 'certification\.gitattributes'), "`n/tamper text", [Text.UTF8Encoding]::new($false))
        $driftCapture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'drift-capture'),
            '-PrestatePath',(Join-Path $script:testScratch 'drift-prestate.json'),
            '-FoundationCapturePrestate'
        )
        $driftCapture.ExitCode | Should -Not -Be 0
        ($driftCapture.Output -join "`n") | Should -Match 'Pinned file mismatch'
    }

    It 'rejects captured attribute identity substitution and hardlinks before journal creation' {
        $substitutionRoot = Join-Path $script:testScratch 'substitution-production'
        New-FoundationBaselineRepository -LiteralPath $substitutionRoot
        $substitutionAuthority = Join-Path $script:testScratch 'sa'
        $substitutionPrestate = Join-Path $substitutionAuthority 'p.json'
        $capture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$substitutionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'sc'),
            '-PrestatePath',$substitutionPrestate,
            '-FoundationCapturePrestate'
        )
        $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
        $attributePath = Join-Path $substitutionRoot 'certification\.gitattributes'
        $retiredAttributePath = Join-Path $script:testScratch 'retired-certification-attributes'
        $attributeBytes = [IO.File]::ReadAllBytes($attributePath)
        [IO.File]::Move($attributePath, $retiredAttributePath)
        [IO.File]::WriteAllBytes($attributePath, $attributeBytes)
        $substitutionJournal = Join-Path $substitutionAuthority 'j'
        $substitutionResult = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$substitutionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'si'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$substitutionPrestate,
            '-InitReceiptPath',(Join-Path $substitutionAuthority 'i.json'),
            '-ReplayReceiptPath',(Join-Path $substitutionAuthority 'r.json'),
            '-RecoveryJournalPath',$substitutionJournal,
            '-CompletionReceiptPath',(Join-Path $substitutionAuthority 'c.json'),
            '-FoundationInit',
            '-Promote'
        )
        $substitutionResult.ExitCode | Should -Not -Be 0
        ($substitutionResult.Output -join "`n") | Should -Match 'Allowlist baseline identity changed'
        (Test-Path -LiteralPath $substitutionJournal) | Should -BeFalse
        @(Get-ChildItem -LiteralPath $substitutionRoot -Filter '*.pspkt-preimage-*' -Recurse -Force).Count | Should -Be 0
        [IO.File]::ReadAllBytes($attributePath) | Should -Be $attributeBytes

        $hardlinkRoot = Join-Path $script:testScratch 'hardlink-production'
        New-FoundationBaselineRepository -LiteralPath $hardlinkRoot
        $hardlinkAttributePath = Join-Path $hardlinkRoot 'certification\.gitattributes'
        $hardlinkAliasPath = Join-Path $hardlinkRoot 'certification\.gitattributes.capture-link'
        New-Item -ItemType HardLink -Path $hardlinkAliasPath -Target $hardlinkAttributePath | Out-Null
        $hardlinkAuthority = Join-Path $script:testScratch 'ha'
        $hardlinkPrestate = Join-Path $hardlinkAuthority 'p.json'
        $hardlinkCapture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$hardlinkRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'hc'),
            '-PrestatePath',$hardlinkPrestate,
            '-FoundationCapturePrestate'
        )
        $hardlinkCapture.ExitCode | Should -Not -Be 0
        ($hardlinkCapture.Output -join "`n") | Should -Match 'Allowlist baseline file changed'
        [IO.File]::Exists($hardlinkPrestate) | Should -BeFalse
        (Test-Path -LiteralPath (Join-Path $hardlinkAuthority 'j')) | Should -BeFalse
    }

    It 'rejects blocked receipt ancestry before promotion or journal creation' {
        $productionRoot = Join-Path $script:testScratch 'production'
        New-FoundationBaselineRepository -LiteralPath $productionRoot
        $prestatePath = Join-Path $script:testScratch 'authority\execution-prestate.v2.json'
        $capture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'capture'),
            '-PrestatePath',$prestatePath,
            '-FoundationCapturePrestate'
        )
        $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
        $indexPath = Join-Path $productionRoot '.git\index'
        $indexHash = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($indexPath))
        $objectRoot = Join-Path $productionRoot '.git\objects'
        $objectFiles = @(Get-ChildItem -LiteralPath $objectRoot -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
            $_.FullName + ':' + (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($_.FullName)))
        })
        $initReceiptPath = Join-Path $script:testScratch 'authority\init-receipt.v1.json'
        $blockedParent = Join-Path $script:testScratch 'blocked-parent'
        [IO.File]::WriteAllText($blockedParent, 'file', [Text.UTF8Encoding]::new($false))
        $replayReceiptPath = Join-Path $blockedParent 'replay-receipt.v2.json'
        $failedInit = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'failed-init'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-FoundationInit',
            '-Promote'
        )
        $failedInit.ExitCode | Should -Not -Be 0
        ($failedInit.Output -join "`n") | Should -Match '(?s)Unsupported transaction layout.*blocked-parent.*file ancestor'
        [IO.Directory]::Exists((Join-Path $script:testScratch 'failed-init')) | Should -BeFalse
        [IO.Directory]::Exists((Join-Path (Split-Path -Parent $prestatePath) 'recovery-journal')) | Should -BeFalse
        [IO.File]::ReadAllText($blockedParent) | Should -BeExactly 'file'
        (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($indexPath))) | Should -BeExactly $indexHash
        @(Get-ChildItem -LiteralPath $objectRoot -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
            $_.FullName + ':' + (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($_.FullName)))
        }) | Should -Be $objectFiles
        [IO.File]::Exists($initReceiptPath) | Should -BeFalse
        [IO.File]::Exists($replayReceiptPath) | Should -BeFalse
        foreach ($relativePath in $script:contract.Allowlist) {
            $fullPath = Resolve-PspktFoundationPath -Root $productionRoot -RelativePath $relativePath
            if ($relativePath -in @('certification/.gitattributes','tests/.gitattributes')) {
                [IO.File]::Exists($fullPath) | Should -BeTrue
            }
            else {
                (Test-Path -LiteralPath $fullPath) | Should -BeFalse -Because $relativePath
            }
        }
        (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes((Join-Path $productionRoot 'certification\.gitattributes')))) | Should -Be '128dc4bc640da9d9f1c99de2e46ea8e5dfd3e9bce92ab8b23d74cbc16fb48ad9'
        (Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes((Join-Path $productionRoot 'tests\.gitattributes')))) | Should -Be 'eafe8326812cb43f4eefa859e9872300abeb92a73cb6c3514d9133c83dc1736b'
        @(Get-ChildItem -LiteralPath $script:testScratch -Filter '*.tmp' -Recurse -Force -ErrorAction SilentlyContinue).Count | Should -Be 0
        $emptySource = Join-Path $script:testScratch 'empty-source'
        [IO.Directory]::CreateDirectory($emptySource) | Out-Null
        $retry = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'retry'),
            '-SourceRoot',$emptySource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',(Join-Path $script:testScratch 'retry-replay.json'),
            '-FoundationInit',
            '-Promote'
        )
        $retry.ExitCode | Should -Not -Be 0
        ($retry.Output -join "`n") | Should -Match 'Scratch SourceRoot is incomplete'
        [IO.Directory]::Exists((Join-Path (Split-Path -Parent $prestatePath) 'recovery-journal')) | Should -BeFalse
        ($retry.Output -join "`n") | Should -Not -Match 'init-already'
    }

    It 'fails closed when attribute backup cleanup fails after promotion' {
        $productionRoot = Join-Path $script:testScratch 'production'
        New-FoundationBaselineRepository -LiteralPath $productionRoot
        $prestatePath = Join-Path $script:testScratch 'prestate-authority\execution-prestate.v2.json'
        $capture = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'capture'),
            '-PrestatePath',$prestatePath,
            '-FoundationCapturePrestate'
        )
        $capture.ExitCode | Should -Be 0 -Because ($capture.Output -join "`n")
        $initReceiptPath = Join-Path $script:testScratch 'init-authority\init-receipt.v1.json'
        $replayReceiptPath = Join-Path $script:testScratch 'replay-authority\replay-receipt.v2.json'
        $faultScratch = Join-Path $script:testScratch 'backup-cleanup-failure'
        $savedFault = $env:PSPKT_FOUNDATION_TEST_CRASH_POINT
        try {
            $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = 'after-mutation:BackupDelete'
            $failedFinalization = Invoke-FoundationOuter -Arguments @(
                '-RepositoryRoot',$productionRoot,
                '-ScratchRoot',$faultScratch,
                '-SourceRoot',$script:testSource,
                '-PrestatePath',$prestatePath,
                '-InitReceiptPath',$initReceiptPath,
                '-ReplayReceiptPath',$replayReceiptPath,
                '-FoundationInit',
                '-Promote'
            )
        }
        finally {
            $env:PSPKT_FOUNDATION_TEST_CRASH_POINT = $savedFault
        }
        $failedFinalization.ExitCode | Should -Not -Be 0
        ($failedFinalization.Output -join "`n") | Should -Match 'Injected crash after mutation: BackupDelete'
        ($failedFinalization.Output -join "`n") | Should -Not -Match 'PspktFoundationExecutionResultV3'
        [IO.File]::Exists($initReceiptPath) | Should -BeTrue
        [IO.File]::Exists($replayReceiptPath) | Should -BeTrue
        foreach ($relativePath in $script:contract.Allowlist) {
            [IO.File]::Exists((Resolve-PspktFoundationPath -Root $productionRoot -RelativePath $relativePath)) | Should -BeTrue -Because $relativePath
        }
        @(Get-ChildItem -LiteralPath $productionRoot -Filter '*.pspkt-preimage-*' -Recurse -Force).Count | Should -Be 1
        $journalPath = Join-Path (Split-Path -Parent $prestatePath) 'recovery-journal'
        $completionPath = Join-Path (Split-Path -Parent $prestatePath) 'completion-receipt.v1.json'
        [IO.Directory]::Exists($journalPath) | Should -BeTrue
        [IO.File]::Exists($completionPath) | Should -BeFalse
        $preparedInit = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'prepared-init'),
            '-SourceRoot',$script:testSource,
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-RecoveryJournalPath',$journalPath,
            '-CompletionReceiptPath',$completionPath,
            '-FoundationInit',
            '-Promote'
        )
        $preparedInit.ExitCode | Should -Not -Be 0
        ($preparedInit.Output -join "`n") | Should -Match 'init-recovery-required'
        [IO.File]::WriteAllText($completionPath, 'foreign completion', [Text.UTF8Encoding]::new($false))
        $recoveredCompletionPath = Join-Path (Split-Path -Parent $prestatePath) 'recovered-completion-receipt.v1.json'
        $finalize = Invoke-FoundationOuter -Arguments @(
            '-RepositoryRoot',$productionRoot,
            '-ScratchRoot',(Join-Path $script:testScratch 'finalize-fresh-scratch'),
            '-PrestatePath',$prestatePath,
            '-InitReceiptPath',$initReceiptPath,
            '-ReplayReceiptPath',$replayReceiptPath,
            '-RecoveryJournalPath',$journalPath,
            '-CompletionReceiptPath',$completionPath,
            '-RecoveredCompletionReceiptPath',$recoveredCompletionPath,
            '-FoundationRecover',
            '-RecoveryAction','Finalize'
        )
        $finalize.ExitCode | Should -Be 0 -Because ($finalize.Output -join "`n")
        [IO.File]::ReadAllText($completionPath) | Should -Be 'foreign completion'
        [IO.File]::Exists($recoveredCompletionPath) | Should -BeTrue
        @(Get-ChildItem -LiteralPath $productionRoot -Filter '*.pspkt-preimage-*' -Recurse -Force).Count | Should -Be 0
    }
}
