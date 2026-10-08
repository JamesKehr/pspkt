Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Phase 4 overlay activation' -Tag 'Precheck' {
    BeforeAll {
        $script:repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $script:contractPath = Join-Path $script:repositoryRoot 'certification\overlay\lib\Pspkt.Certification.OverlayActivationContract.ps1'
        $script:authorityPath = Join-Path $script:repositoryRoot 'certification\overlay\lib\Pspkt.Certification.OverlayActivationAuthority.cs'
        $script:verifyPath = Join-Path $script:repositoryRoot 'certification\overlay\lib\Pspkt.Certification.OverlayActivationVerify.cs'
        $script:validatorPath = Join-Path $script:repositoryRoot 'certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1'
        $validatorTokens = $null
        $validatorErrors = $null
        $validatorTree = [Management.Automation.Language.Parser]::ParseFile(
            $script:validatorPath,
            [ref]$validatorTokens,
            [ref]$validatorErrors)
        @($validatorErrors).Count | Should -Be 0
        foreach ($functionName in @(
            'Get-PspktOverlayProcessEnvironment',
            'Clear-PspktOverlayHostEnvironment',
            'Import-PspktOverlayBoundedProcess',
            'Invoke-PspktOverlayBoundedPowerShell')) {
            $definition = $validatorTree.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
            },$true)
            $null -ne $definition | Should -BeTrue
            Set-Item -LiteralPath ('Function:\' + $functionName) -Value $definition.Body.GetScriptBlock()
        }
        . $script:contractPath
        $boundedProcessContract = Get-PspktOverlayActivationContract
        $boundedProcessRelativePath = 'certification/overlay/lib/Pspkt.Certification.OverlayBoundedProcess.cs'
        Import-PspktOverlayBoundedProcess `
            -SourcePath (Join-Path $script:repositoryRoot $boundedProcessRelativePath.Replace('/','\')) `
            -ExpectedSha256 $boundedProcessContract.Sha256ByPath[$boundedProcessRelativePath]
        $script:storeHostBridgePath = $null
        $script:storeHostRelayPath = $null

        function Import-OverlayTestAssembly {
            param([string]$Path,[switch]$PassThru)
            $bytes = [IO.File]::ReadAllBytes($Path)
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                $assembly = [Reflection.Assembly]::Load($bytes)
            } else {
                $stream = [IO.MemoryStream]::new($bytes,$false)
                try { $assembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromStream($stream) }
                finally { $stream.Dispose() }
            }
            if ($PassThru) { return $assembly }
        }

        function Get-OverlayHostPath {
            param([string]$HostName)

            $resolvedPath = (Get-Command $HostName -ErrorAction Stop).Source
            if ($HostName -ceq 'pwsh.exe' -and
                $resolvedPath.IndexOf('\WindowsApps\',[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $executionAlias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe'
                if (-not [IO.File]::Exists($executionAlias)) {
                    throw 'The Store PowerShell execution alias is unavailable.'
                }
                return $executionAlias
            }
            return $resolvedPath
        }

        function Initialize-OverlayCompilation {
            $library = Join-Path $script:repositoryRoot 'certification\lib'
            $authorityType = 'Pspkt.Certification.Overlay.OverlayActivationAuthority' -as [type]
            $assemblyRoot = Join-Path $TestDrive 'assemblies'
            [void][IO.Directory]::CreateDirectory($assemblyRoot)
            $bootstrapAssembly = Join-Path $assemblyRoot 'SchemaBootstrap.dll'
            $engineAssembly = Join-Path $assemblyRoot 'FoundationEngine.dll'
            if (-not (Test-Path -LiteralPath $engineAssembly)) {
                $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
                $result = Invoke-OverlayChild -HostPath (Join-Path $PSHOME $hostName) -Arguments @(
                    '-NoLogo','-NoProfile','-File',
                    (Join-Path $script:repositoryRoot 'certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1'),
                    '-Worker','-Mode','Compile','-RepositoryRoot',$script:repositoryRoot,'-AssemblyRoot',$assemblyRoot)
                if ($result.ExitCode -ne 0) { throw $result.StandardError }
            }
            if ($null -eq $authorityType) {
                $script:overlayBootstrapAssembly = Import-OverlayTestAssembly -Path $bootstrapAssembly -PassThru
                Import-OverlayTestAssembly -Path (Join-Path $assemblyRoot 'OverlayActivationVerify.dll')
                $script:overlayEngineAssembly = Import-OverlayTestAssembly -Path $engineAssembly -PassThru
                Import-OverlayTestAssembly -Path (Join-Path $assemblyRoot 'OverlayActivationAuthority.dll')
            } else {
                $script:overlayEngineAssembly = $authorityType.GetMethod('GenerateDeclarations').GetParameters()[2].ParameterType.Assembly
            }
            $verifierType = 'Pspkt.Certification.Overlay.OverlayActivationVerify' -as [type]
            $bootstrapReferences = @($verifierType.Assembly.GetReferencedAssemblies() | Where-Object {
                $token = $_.GetPublicKeyToken()
                ($null -eq $token -or $token.Length -eq 0) -and $_.Name -ne 'mscorlib'
            })
            if ($bootstrapReferences.Count -ne 1) { throw 'Overlay verifier bootstrap reference set differs.' }
            $bootstrapAssemblies = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
                $_.FullName -eq $bootstrapReferences[0].FullName
            })
            if ($bootstrapAssemblies.Count -eq 0) { throw 'Overlay verifier bootstrap assembly is not loaded.' }
            $script:overlayBootstrapAssembly = $bootstrapAssemblies[0]
            . (Join-Path $library 'Pspkt.Certification.ProtocolSchemaContract.ps1')
            $contract = Get-PspktProtocolSchemaContract
            $messageEnums = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
            $directions = [Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::Ordinal)
            $rangeType = $script:overlayEngineAssembly.GetType('Pspkt.Certification.FoundationEngine.GeneratedIdRange',$true)
            $rangeDictionaryType = [Collections.Generic.Dictionary[string,object]].GetGenericTypeDefinition().MakeGenericType(
                [type[]]@([string],$rangeType.MakeArrayType()))
            $kindRanges = [Activator]::CreateInstance($rangeDictionaryType)
            foreach ($channel in $contract.Channels) {
                $messageEnums.Add($channel, $contract.MessageEnumNameByChannel[$channel])
                $directions.Add($channel, $contract.PermittedDirectionsByChannel[$channel])
                $sourceRanges = @($contract.OverlayKindRangesByChannel[$channel])
                $ranges = [Array]::CreateInstance($rangeType,$sourceRanges.Count)
                for ($index=0; $index -lt $sourceRanges.Count; $index++) {
                    $ranges.SetValue([Activator]::CreateInstance($rangeType,[object[]]@($sourceRanges[$index].Start,$sourceRanges[$index].End)),$index)
                }
                $kindRanges.Add($channel,$ranges)
            }
            $contractType = $script:overlayEngineAssembly.GetType('Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2',$true)
            $typeRange = [Activator]::CreateInstance($rangeType,[object[]]@($contract.OverlayTypeRange.Start,$contract.OverlayTypeRange.End))
            $script:engineContract = [Activator]::CreateInstance($contractType,[object[]]@(
                $contract.NamePredicate, $contract.BaseCatalogSchemaId, $contract.BaseCatalogSpace,
                $contract.OverlayCatalogSchemaId, $contract.OverlayCatalogSpace, $contract.EmitSchemaId, $contract.MapSchemaId,
                $contract.Channels, $messageEnums, $directions, $kindRanges,
                $typeRange,$contract.GeneratedFieldIdMax,$contract.LiteralExtensionParentNames))
        }

        function Get-OverlayDeclarations {
            Initialize-OverlayCompilation
            return [Pspkt.Certification.Overlay.OverlayActivationAuthority]::GenerateDeclarations(
                [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json')),
                [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json')),
                $script:engineContract)
        }

        function Get-OverlayAssociations {
            param($Outputs)
            return [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildAssociations(
                [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json')),
                [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json')),
                $Outputs['certification/overlay/schema/generated-base-id-map.v1.json'])
        }

        function Get-OverlaySchedule {
            param($Outputs,[byte[]]$Associations)
            $inventory = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'))
            return [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildSchedule(
                $Outputs['certification/overlay/schema/protocol-schema.v1.json'],$Associations,
                [Pspkt.Certification.Overlay.OverlayActivationAuthority]::DeriveLifecycle($inventory),$inventory)
        }

        function Get-OverlayMatrices {
            param($Outputs,[byte[]]$Associations,[byte[]]$Schedule)
            $inventory = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'))
            return [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildMatrices(
                [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json')),
                [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json')),
                $Outputs['certification/overlay/schema/protocol-schema.v1.json'],$Associations,$Schedule,
                [Pspkt.Certification.Overlay.OverlayActivationAuthority]::DeriveLifecycle($inventory),$inventory)
        }

        function ConvertTo-OverlayTargetInvocation {
            param([string[]]$Arguments)

            if ($Arguments.Count -lt 4 -or
                $Arguments[0] -cne '-NoLogo' -or
                $Arguments[1] -cne '-NoProfile' -or
                $Arguments[2] -cne '-File') {
                throw 'Overlay child arguments must start with -NoLogo -NoProfile -File.'
            }
            $targetParameters = @{}
            $argumentIndex = 4
            while ($argumentIndex -lt $Arguments.Count) {
                $nameToken = $Arguments[$argumentIndex]
                if ($nameToken -notmatch '^-[A-Za-z][A-Za-z0-9]*$') {
                    throw "Overlay child parameter token is invalid: $nameToken"
                }
                $parameterName = $nameToken.Substring(1)
                if (($argumentIndex + 1) -ge $Arguments.Count -or $Arguments[$argumentIndex + 1] -match '^-[A-Za-z][A-Za-z0-9]*$') {
                    $targetParameters.Add($parameterName,$true)
                    $argumentIndex++
                } else {
                    $targetParameters.Add($parameterName,$Arguments[$argumentIndex + 1])
                    $argumentIndex += 2
                }
            }
            return [pscustomobject]@{
                TargetPath = $Arguments[3]
                TargetParameters = $targetParameters
            }
        }

        function Invoke-OverlayChild {
            param([string]$HostPath,[string[]]$Arguments,[int]$TimeoutSeconds=180)

            $invocation = ConvertTo-OverlayTargetInvocation -Arguments $Arguments
            $storeAliasRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
            if ($PSVersionTable.PSEdition -ceq 'Desktop' -and
                $HostPath.StartsWith($storeAliasRoot,[StringComparison]::OrdinalIgnoreCase)) {
                Initialize-OverlayStoreRelay
                $argumentsBase64 = [Convert]::ToBase64String(
                    [Text.Encoding]::UTF8.GetBytes([string]::Join([char]0,$Arguments)))
                $helperRelativePath = 'certification/overlay/lib/Pspkt.Certification.OverlayBoundedProcess.cs'
                . $script:contractPath
                $contract = Get-PspktOverlayActivationContract
                return Invoke-PspktOverlayBoundedPowerShell `
                    -HostPath (Join-Path $PSHOME 'powershell.exe') `
                    -TargetPath $script:storeHostBridgePath `
                    -TargetParameters @{
                        TargetHostPath = $HostPath
                        RelayPath = $script:storeHostRelayPath
                        ArgumentsBase64 = $argumentsBase64
                        RepositoryRoot = $script:repositoryRoot
                        HelperPath = (Join-Path $script:repositoryRoot $helperRelativePath.Replace('/','\'))
                        HelperSha256 = $contract.Sha256ByPath[$helperRelativePath]
                        TimeoutMilliseconds = ($TimeoutSeconds*1000)
                    } `
                    -WorkingDirectory $script:repositoryRoot `
                    -TimeoutMilliseconds ($TimeoutSeconds*1000)
            }
            return Invoke-PspktOverlayBoundedPowerShell `
                -HostPath $HostPath `
                -TargetPath $invocation.TargetPath `
                -TargetParameters $invocation.TargetParameters `
                -WorkingDirectory $script:repositoryRoot `
                -TimeoutMilliseconds ($TimeoutSeconds*1000)
        }

        function Invoke-OverlayValidatorChild {
            param(
                [string]$HostPath,
                [string]$TargetPath,
                [string]$Mode,
                [string]$RepositoryRoot,
                [string]$OutputRoot,
                [int]$TimeoutSeconds=180
            )

            $targetParameters = @{
                Mode = $Mode
                RepositoryRoot = $RepositoryRoot
            }
            if ($OutputRoot) { $targetParameters.OutputRoot = $OutputRoot }
            return Invoke-PspktOverlayBoundedPowerShell `
                -HostPath $HostPath `
                -TargetPath $TargetPath `
                -TargetParameters $targetParameters `
                -WorkingDirectory $RepositoryRoot `
                -TimeoutMilliseconds ($TimeoutSeconds*1000)
        }

        function Assert-OverlayReceipt {
            param($Result,[string]$ExpectedReceipt,[string]$ReceiptFamily)

            $standardOutputLines = [regex]::Split($Result.StandardOutput,'\r\n|\n|\r')
            $standardErrorLines = [regex]::Split($Result.StandardError,'\r\n|\n|\r')
            $outputFamilyLines = @($standardOutputLines | Where-Object {
                $_.StartsWith($ReceiptFamily,[StringComparison]::Ordinal)
            })
            $errorFamilyLines = @($standardErrorLines | Where-Object {
                $_.StartsWith($ReceiptFamily,[StringComparison]::Ordinal)
            })
            if ($outputFamilyLines.Count -ne 1 -or
                -not [string]::Equals($outputFamilyLines[0],$ExpectedReceipt,[StringComparison]::Ordinal) -or
                $errorFamilyLines.Count -ne 0) {
                throw "Overlay completion receipt differs: $ExpectedReceipt"
            }
        }

        function Invoke-OverlayLifecycleProbe {
            param(
                [string]$HostPath,
                [string]$TargetPath,
                [string]$RepositoryRoot,
                [string]$IdentityPath,
                [ValidateSet('Linger','Timeout','Cancel','Overflow')][string]$ProbeCase
            )

            $functionDefinitions = Get-OverlayBoundedFunctionDefinitions
            $runnerPrefix = @'
param(
    [string]$HostPath,
    [string]$TargetPath,
    [string]$RepositoryRoot,
    [string]$IdentityPath,
    [string]$ProbeCase,
    [int]$TimeoutMilliseconds
)
'@
            $runnerSuffix = @'
$invokeParameters = @{
    HostPath = $HostPath
    TargetPath = $TargetPath
    TargetParameters = @{
        Mode = $ProbeCase
        RepositoryRoot = $RepositoryRoot
        OutputRoot = $IdentityPath
    }
    WorkingDirectory = $RepositoryRoot
    TimeoutMilliseconds = $TimeoutMilliseconds
}
if ($ProbeCase -ceq 'Overflow') {
    $invokeParameters.RetainCapBytes = 1024
}
Invoke-PspktOverlayBoundedPowerShell @invokeParameters
'@
            $timeoutMilliseconds = if ($ProbeCase -ceq 'Timeout') { 5000 } else { 60000 }
            $powerShell = [PowerShell]::Create()
            $descendantProcess = $null
            $invocation = $null
            $endFailure = $null
            $stopwatch = [Diagnostics.Stopwatch]::StartNew()
            try {
                [void]$powerShell.AddScript($runnerPrefix + $functionDefinitions + $runnerSuffix)
                foreach ($argument in @(
                    $HostPath,
                    $TargetPath,
                    $RepositoryRoot,
                    $IdentityPath,
                    $ProbeCase,
                    $timeoutMilliseconds)) {
                    [void]$powerShell.AddArgument($argument)
                }
                $invocation = $powerShell.BeginInvoke()
                while (-not [IO.File]::Exists($IdentityPath) -and
                    -not $invocation.IsCompleted -and
                    $stopwatch.ElapsedMilliseconds -lt 15000) {
                    [Threading.Thread]::Sleep(25)
                }
                if (-not [IO.File]::Exists($IdentityPath)) {
                    throw "Overlay lifecycle probe did not publish descendant identity: $ProbeCase"
                }
                $identity = [IO.File]::ReadAllText($IdentityPath).Split('|')
                if ($identity.Count -ne 2) {
                    throw "Overlay lifecycle descendant identity differs: $ProbeCase"
                }
                $descendantProcess = [Diagnostics.Process]::GetProcessById([int]$identity[0])
                if ($descendantProcess.StartTime.ToFileTimeUtc() -ne [long]$identity[1]) {
                    throw "Overlay lifecycle descendant identity was reused: $ProbeCase"
                }
                if ($descendantProcess.HasExited) {
                    throw "Overlay lifecycle descendant exited before the trigger: $ProbeCase"
                }
                [IO.File]::WriteAllText($IdentityPath + '.release','release',[Text.Encoding]::ASCII)
                if ($ProbeCase -ceq 'Cancel') {
                    $stopResult = $powerShell.BeginStop($null,$null)
                    if (-not $stopResult.AsyncWaitHandle.WaitOne(30000)) {
                        throw 'Overlay lifecycle cancellation exceeded its execution limit.'
                    }
                    $powerShell.EndStop($stopResult)
                }
                if (-not $invocation.AsyncWaitHandle.WaitOne(30000)) {
                    throw "Overlay lifecycle invocation exceeded its execution limit: $ProbeCase"
                }
                try { [void]$powerShell.EndInvoke($invocation) }
                catch { $endFailure = $_.Exception }
                $descendantExited = $descendantProcess.WaitForExit(15000)
                $errorText = [string]($powerShell.Streams.Error -join [Environment]::NewLine)
                if ($null -ne $endFailure) {
                    $errorText += [Environment]::NewLine + $endFailure.ToString()
                }
                return [pscustomobject]@{
                    DescendantExited = $descendantExited
                    ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
                    Errors = $errorText
                    InvocationState = $powerShell.InvocationStateInfo.State
                }
            }
            finally {
                if ($null -ne $descendantProcess) {
                    if (-not $descendantProcess.HasExited) {
                        $descendantProcess.Kill()
                        [void]$descendantProcess.WaitForExit(15000)
                    }
                    $descendantProcess.Dispose()
                }
                if ($null -ne $invocation -and -not $invocation.IsCompleted) {
                    $stopResult = $powerShell.BeginStop($null,$null)
                    if ($stopResult.AsyncWaitHandle.WaitOne(5000)) {
                        $powerShell.EndStop($stopResult)
                    }
                }
                if ($null -eq $invocation -or $invocation.IsCompleted) {
                    $powerShell.Dispose()
                }
            }
        }

        function Get-OverlayBoundedFunctionDefinitions {
            param(
                [string[]]$FunctionNames = @(
                    'Get-PspktOverlayProcessEnvironment',
                    'Clear-PspktOverlayHostEnvironment',
                    'Import-PspktOverlayBoundedProcess',
                    'Invoke-PspktOverlayBoundedPowerShell',
                    'ConvertTo-OverlayTargetInvocation')
            )

            $functionDefinitions = [Text.StringBuilder]::new()
            foreach ($functionName in $FunctionNames) {
                [void]$functionDefinitions.AppendLine(
                    'function ' + $functionName + ' {' +
                    (Get-Item -LiteralPath ('Function:\' + $functionName)).Definition + '}')
            }
            return $functionDefinitions.ToString()
        }

        function Initialize-OverlayStoreRelay {
            if ($null -ne $script:storeHostBridgePath -and
                $null -ne $script:storeHostRelayPath) {
                return
            }

            $script:storeHostBridgePath = Join-Path $TestDrive 'Invoke-StoreHostBridge.ps1'
            $script:storeHostRelayPath = Join-Path $TestDrive 'Invoke-StoreHostRelay.ps1'
            $bridgeSource = @'
param(
    [string]$TargetHostPath,
    [string]$RelayPath,
    [string]$ArgumentsBase64,
    [string]$RepositoryRoot,
    [string]$HelperPath,
    [string]$HelperSha256,
    [int]$TimeoutMilliseconds
)
$currentProcess = [Diagnostics.Process]::GetCurrentProcess()
$relayArguments = @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-File',
    $RelayPath,
    '-ParentProcessId',
    $currentProcess.Id,
    '-ParentProcessStartTimeFileTimeUtc',
    $currentProcess.StartTime.ToFileTimeUtc(),
    '-ArgumentsBase64',
    $ArgumentsBase64,
    '-RepositoryRoot',
    $RepositoryRoot,
    '-HelperPath',
    $HelperPath,
    '-HelperSha256',
    $HelperSha256,
    '-TimeoutMilliseconds',
    $TimeoutMilliseconds)
& $TargetHostPath @relayArguments
exit $LASTEXITCODE
'@
            $relayPrefix = @'
param(
    [int]$ParentProcessId,
    [long]$ParentProcessStartTimeFileTimeUtc,
    [string]$ArgumentsBase64,
    [string]$RepositoryRoot,
    [string]$HelperPath,
    [string]$HelperSha256,
    [int]$TimeoutMilliseconds
)
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$standardOutputWriter = [IO.StreamWriter]::new([Console]::OpenStandardOutput(),$utf8)
$standardErrorWriter = [IO.StreamWriter]::new([Console]::OpenStandardError(),$utf8)
$standardOutputWriter.AutoFlush = $true
$standardErrorWriter.AutoFlush = $true
[Console]::SetOut($standardOutputWriter)
[Console]::SetError($standardErrorWriter)
'@
            $relaySuffix = @'
try {
    if ($ParentProcessId -le 0 -or $ParentProcessStartTimeFileTimeUtc -le 0) {
        throw 'Overlay Store relay parent identity is required.'
    }
    Import-PspktOverlayBoundedProcess -SourcePath $HelperPath -ExpectedSha256 $HelperSha256
    $decodedArguments = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
    $targetArguments = [string[]]@($decodedArguments.Split([char]0))
    $invocation = ConvertTo-OverlayTargetInvocation -Arguments $targetArguments
    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    $env:PSPKT_OVERLAY_RELAY_PROCESS_ID = $currentProcess.Id.ToString([Globalization.CultureInfo]::InvariantCulture)
    $env:PSPKT_OVERLAY_RELAY_PROCESS_START = $currentProcess.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
    $env:PSPKT_OVERLAY_BRIDGE_PROCESS_ID = $ParentProcessId.ToString([Globalization.CultureInfo]::InvariantCulture)
    $env:PSPKT_OVERLAY_BRIDGE_PROCESS_START = $ParentProcessStartTimeFileTimeUtc.ToString([Globalization.CultureInfo]::InvariantCulture)
    $result = Invoke-PspktOverlayBoundedPowerShell `
        -HostPath (Join-Path $PSHOME 'pwsh.exe') `
        -TargetPath $invocation.TargetPath `
        -TargetParameters $invocation.TargetParameters `
        -WorkingDirectory $RepositoryRoot `
        -TimeoutMilliseconds $TimeoutMilliseconds `
        -ParentProcessId $ParentProcessId `
        -ParentProcessStartTimeFileTimeUtc $ParentProcessStartTimeFileTimeUtc
    [Console]::Out.Write($result.StandardOutput)
    [Console]::Error.Write($result.StandardError)
    exit $result.ExitCode
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
'@
            [IO.File]::WriteAllText(
                $script:storeHostBridgePath,
                $bridgeSource,
                [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText(
                $script:storeHostRelayPath,
                $relayPrefix + "`n" + (Get-OverlayBoundedFunctionDefinitions) + "`n" + $relaySuffix,
                [Text.UTF8Encoding]::new($false))
        }

        function Invoke-OverlayStoreRelayProbe {
            param([ValidateSet('ParentLoss','Timeout')][string]$ProbeCase)

            Initialize-OverlayStoreRelay
            $probeRoot = Join-Path $TestDrive ('store-relay-' + $ProbeCase.ToLowerInvariant())
            [void][IO.Directory]::CreateDirectory($probeRoot)
            $identityPath = Join-Path $probeRoot 'identity.txt'
            $targetPath = Join-Path $probeRoot 'target.ps1'
            $targetSource = @'
param([string]$Mode,[string]$RepositoryRoot,[string]$OutputRoot)
$descendant = Start-Process -FilePath $env:ComSpec `
    -ArgumentList @('/d','/s','/c','ping -n 600 127.0.0.1 >nul') `
    -NoNewWindow `
    -PassThru
$current = [Diagnostics.Process]::GetCurrentProcess()
$temporaryPath = $OutputRoot + '.tmp'
[IO.File]::WriteAllText(
    $temporaryPath,
    ($env:PSPKT_OVERLAY_BRIDGE_PROCESS_ID + '|' +
        $env:PSPKT_OVERLAY_BRIDGE_PROCESS_START + '|' +
        $env:PSPKT_OVERLAY_RELAY_PROCESS_ID + '|' +
        $env:PSPKT_OVERLAY_RELAY_PROCESS_START + '|' +
        $current.Id.ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $current.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $descendant.Id.ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $descendant.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)),
    [Text.Encoding]::ASCII)
[IO.File]::Move($temporaryPath,$OutputRoot)
Start-Sleep -Seconds 600
'@
            [IO.File]::WriteAllText($targetPath,$targetSource,[Text.UTF8Encoding]::new($false))
            $targetArguments = [string[]]@(
                '-NoLogo','-NoProfile','-File',$targetPath,
                '-Mode',$ProbeCase,
                '-RepositoryRoot',$script:repositoryRoot,
                '-OutputRoot',$identityPath)
            $argumentsBase64 = [Convert]::ToBase64String(
                [Text.Encoding]::UTF8.GetBytes([string]::Join([char]0,$targetArguments)))
            $controllerDefinitions = Get-OverlayBoundedFunctionDefinitions -FunctionNames @(
                'Get-PspktOverlayProcessEnvironment',
                'Clear-PspktOverlayHostEnvironment',
                'Import-PspktOverlayBoundedProcess',
                'Invoke-PspktOverlayBoundedPowerShell',
                'ConvertTo-OverlayTargetInvocation',
                'Get-OverlayBoundedFunctionDefinitions',
                'Initialize-OverlayStoreRelay',
                'Invoke-OverlayChild')
            $controllerPrefix = @'
param(
    [string]$StoreHostPath,
    [string]$ArgumentsBase64,
    [string]$RepositoryRoot,
    [string]$ContractPath,
    [string]$BridgePath,
    [string]$RelayPath,
    [int]$TimeoutSeconds
)
'@
            $controllerSuffix = @'
$script:repositoryRoot = $RepositoryRoot
$script:contractPath = $ContractPath
$script:storeHostBridgePath = $BridgePath
$script:storeHostRelayPath = $RelayPath
$decodedArguments = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
$arguments = [string[]]@($decodedArguments.Split([char]0))
Invoke-OverlayChild -HostPath $StoreHostPath -Arguments $arguments -TimeoutSeconds $TimeoutSeconds
'@
            $controller = [PowerShell]::Create()
            [void]$controller.AddScript($controllerPrefix + "`n" + $controllerDefinitions + "`n" + $controllerSuffix)
            foreach ($argument in @(
                (Get-OverlayHostPath 'pwsh.exe'),
                $argumentsBase64,
                $script:repositoryRoot,
                $script:contractPath,
                $script:storeHostBridgePath,
                $script:storeHostRelayPath,
                $(if ($ProbeCase -ceq 'Timeout') { 20 } else { 60 }))) {
                [void]$controller.AddArgument($argument)
            }
            $controllerInvocation = $null
            $bridgeProcess = $null
            $relayProcess = $null
            $workerProcess = $null
            $descendantProcess = $null
            $endFailure = $null
            try {
                $controllerInvocation = $controller.BeginInvoke()
                $stopwatch = [Diagnostics.Stopwatch]::StartNew()
                while (-not [IO.File]::Exists($identityPath) -and
                    -not $controllerInvocation.IsCompleted -and
                    $stopwatch.ElapsedMilliseconds -lt 30000) {
                    [Threading.Thread]::Sleep(25)
                }
                if (-not [IO.File]::Exists($identityPath)) {
                    throw "Overlay Store relay identity was not published: $ProbeCase"
                }
                $identity = [IO.File]::ReadAllText($identityPath).Split('|')
                if ($identity.Count -ne 8) { throw "Overlay Store relay identity differs: $ProbeCase" }
                $bridgeProcess = [Diagnostics.Process]::GetProcessById([int]$identity[0])
                $relayProcess = [Diagnostics.Process]::GetProcessById([int]$identity[2])
                $workerProcess = [Diagnostics.Process]::GetProcessById([int]$identity[4])
                $descendantProcess = [Diagnostics.Process]::GetProcessById([int]$identity[6])
                $retainedProcesses = @($bridgeProcess,$relayProcess,$workerProcess,$descendantProcess)
                for ($processIndex = 0; $processIndex -lt $retainedProcesses.Count; $processIndex++) {
                    $null = $retainedProcesses[$processIndex].SafeHandle
                    if ($retainedProcesses[$processIndex].StartTime.ToFileTimeUtc() -ne [long]$identity[($processIndex*2)+1] -or
                        $retainedProcesses[$processIndex].HasExited) {
                        throw "Overlay Store relay process identity was reused or exited before trigger: $ProbeCase"
                    }
                }
                if ($ProbeCase -ceq 'ParentLoss') {
                    $stopResult = $controller.BeginStop($null,$null)
                    if (-not $stopResult.AsyncWaitHandle.WaitOne(30000)) {
                        throw 'Overlay Store bridge cancellation exceeded its execution limit.'
                    }
                    $controller.EndStop($stopResult)
                }
                if (-not $controllerInvocation.AsyncWaitHandle.WaitOne(30000)) {
                    throw "Overlay Store bridge invocation exceeded its execution limit: $ProbeCase"
                }
                try { [void]$controller.EndInvoke($controllerInvocation) }
                catch { $endFailure = $_.Exception }
                $errorText = [string]($controller.Streams.Error -join [Environment]::NewLine)
                if ($null -ne $endFailure) {
                    $errorText += [Environment]::NewLine + $endFailure.ToString()
                }
                return [pscustomobject]@{
                    BridgeExited = $bridgeProcess.WaitForExit(15000)
                    RelayExited = $relayProcess.WaitForExit(15000)
                    WorkerExited = $workerProcess.WaitForExit(15000)
                    DescendantExited = $descendantProcess.WaitForExit(15000)
                    Errors = $errorText
                }
            }
            finally {
                foreach ($process in @($descendantProcess,$workerProcess,$relayProcess,$bridgeProcess)) {
                    if ($null -ne $process) {
                        if (-not $process.HasExited) {
                            $process.Kill()
                            [void]$process.WaitForExit(15000)
                        }
                        $process.Dispose()
                    }
                }
                if ($null -ne $controllerInvocation -and -not $controllerInvocation.IsCompleted) {
                    $stopResult = $controller.BeginStop($null,$null)
                    if ($stopResult.AsyncWaitHandle.WaitOne(5000)) {
                        $controller.EndStop($stopResult)
                    }
                }
                if ($null -eq $controllerInvocation -or $controllerInvocation.IsCompleted) {
                    $controller.Dispose()
                }
            }
        }

        function Invoke-OverlayParentLossProbe {
            param(
                [string]$HostPath,
                [string]$RepositoryRoot,
                [string]$HelperPath,
                [string]$HelperSha256,
                [string]$ProbeRoot
            )

            [void][IO.Directory]::CreateDirectory($ProbeRoot)
            $identityPath = Join-Path $ProbeRoot 'identity.txt'
            $failurePath = Join-Path $ProbeRoot 'failure.txt'
            $targetPath = Join-Path $ProbeRoot 'target.ps1'
            $launcherPath = Join-Path $ProbeRoot 'launcher.ps1'
            $target = @'
param([string]$Mode,[string]$RepositoryRoot,[string]$OutputRoot)
$descendant = Start-Process -FilePath $env:ComSpec `
    -ArgumentList @('/d','/s','/c','ping -n 600 127.0.0.1 >nul') `
    -NoNewWindow `
    -PassThru
$current = [Diagnostics.Process]::GetCurrentProcess()
$identityTemporaryPath = $OutputRoot + '.tmp'
[IO.File]::WriteAllText(
    $identityTemporaryPath,
    ($current.Id.ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $current.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $descendant.Id.ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $descendant.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)),
    [Text.Encoding]::ASCII)
[IO.File]::Move($identityTemporaryPath,$OutputRoot)
Start-Sleep -Seconds 600
'@
            $launcherPrefix = @'
param(
    [string]$HostPath,
    [string]$TargetPath,
    [string]$RepositoryRoot,
    [string]$IdentityPath,
    [string]$FailurePath,
    [string]$HelperPath,
    [string]$HelperSha256
)
'@
            $launcherSuffix = @'
Import-PspktOverlayBoundedProcess -SourcePath $HelperPath -ExpectedSha256 $HelperSha256
try {
    $targetParameters = @{
        Mode = 'ParentLoss'
        RepositoryRoot = $RepositoryRoot
        OutputRoot = $IdentityPath
    }
    Invoke-PspktOverlayBoundedPowerShell `
        -HostPath $HostPath `
        -TargetPath $TargetPath `
        -TargetParameters $targetParameters `
        -WorkingDirectory $RepositoryRoot `
        -TimeoutMilliseconds 600000
}
catch {
    [IO.File]::WriteAllText($FailurePath,$_.Exception.ToString(),[Text.UTF8Encoding]::new($false))
    exit 1
}
'@
            [IO.File]::WriteAllText($targetPath,$target,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText(
                $launcherPath,
                $launcherPrefix + (Get-OverlayBoundedFunctionDefinitions) + $launcherSuffix,
                [Text.UTF8Encoding]::new($false))
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $HostPath
            $startInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $launcherPath +
                '" -HostPath "' + $HostPath + '" -TargetPath "' + $targetPath +
                '" -RepositoryRoot "' + $RepositoryRoot + '" -IdentityPath "' + $identityPath +
                '" -FailurePath "' + $failurePath + '" -HelperPath "' + $HelperPath +
                '" -HelperSha256 "' + $HelperSha256 + '"'
            $startInfo.UseShellExecute = $false
            $launcher = [Diagnostics.Process]::new()
            $launcher.StartInfo = $startInfo
            $wrapperProcess = $null
            $descendantProcess = $null
            try {
                if (-not $launcher.Start()) { throw 'Overlay parent-loss launcher did not start.' }
                $stopwatch = [Diagnostics.Stopwatch]::StartNew()
                while (-not [IO.File]::Exists($identityPath) -and
                    -not $launcher.HasExited -and
                    $stopwatch.ElapsedMilliseconds -lt 30000) {
                    [Threading.Thread]::Sleep(25)
                }
                if (-not [IO.File]::Exists($identityPath)) {
                    $failure = if ([IO.File]::Exists($failurePath)) { [IO.File]::ReadAllText($failurePath) } else { '' }
                    throw "Overlay parent-loss identity was not published. $failure"
                }
                $identity = [IO.File]::ReadAllText($identityPath).Split('|')
                if ($identity.Count -ne 4) { throw 'Overlay parent-loss identity differs.' }
                $wrapperProcess = [Diagnostics.Process]::GetProcessById([int]$identity[0])
                $descendantProcess = [Diagnostics.Process]::GetProcessById([int]$identity[2])
                if ($wrapperProcess.StartTime.ToFileTimeUtc() -ne [long]$identity[1] -or
                    $descendantProcess.StartTime.ToFileTimeUtc() -ne [long]$identity[3]) {
                    throw 'Overlay parent-loss process identity was reused.'
                }
                $launcher.Kill()
                [void]$launcher.WaitForExit(15000)
                return [pscustomobject]@{
                    WrapperExited = $wrapperProcess.WaitForExit(15000)
                    DescendantExited = $descendantProcess.WaitForExit(15000)
                    FailureMarkerExists = [IO.File]::Exists($failurePath)
                }
            }
            finally {
                foreach ($process in @($descendantProcess,$wrapperProcess,$launcher)) {
                    if ($null -ne $process) {
                        if (-not $process.HasExited) {
                            $process.Kill()
                            [void]$process.WaitForExit(15000)
                        }
                        $process.Dispose()
                    }
                }
            }
        }

        function Invoke-OverlayActiveLimitProbe {
            param(
                [string]$HostPath,
                [string]$RepositoryRoot,
                [string]$HelperPath,
                [string]$HelperSha256,
                [string]$ProbeRoot
            )

            [void][IO.Directory]::CreateDirectory($ProbeRoot)
            $targetMarkerPath = Join-Path $ProbeRoot 'target-ran.txt'
            $resultPath = Join-Path $ProbeRoot 'result.txt'
            $targetPath = Join-Path $ProbeRoot 'target.ps1'
            $launcherPath = Join-Path $ProbeRoot 'launcher.ps1'
            [IO.File]::WriteAllText(
                $targetPath,
                "param([string]`$Mode,[string]`$RepositoryRoot,[string]`$OutputRoot)`n[IO.File]::WriteAllText(`$OutputRoot,'ran')",
                [Text.UTF8Encoding]::new($false))
            $launcherPrefix = @'
param(
    [string]$HostPath,
    [string]$TargetPath,
    [string]$RepositoryRoot,
    [string]$MarkerPath,
    [string]$ResultPath,
    [string]$HelperPath,
    [string]$HelperSha256
)
'@
            $launcherSuffix = @'
Import-PspktOverlayBoundedProcess -SourcePath $HelperPath -ExpectedSha256 $HelperSha256
$testHookType = ('Pspkt.Certification.Overlay.OverlayBoundedProcess' -as [type]).Assembly.GetType(
    'Pspkt.Certification.Overlay.OverlayBoundedProcessTestHooks',
    $true)
$testHookMethod = $testHookType.GetMethod(
    'EnterActiveProcessLimitOneJob',
    [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic)
$limitJob = $testHookMethod.Invoke($null,[object[]]@())
try {
    $targetParameters = @{
        Mode = 'ActiveLimit'
        RepositoryRoot = $RepositoryRoot
        OutputRoot = $MarkerPath
    }
    try {
        Invoke-PspktOverlayBoundedPowerShell `
            -HostPath $HostPath `
            -TargetPath $TargetPath `
            -TargetParameters $targetParameters `
            -WorkingDirectory $RepositoryRoot `
            -TimeoutMilliseconds 10000
        [IO.File]::WriteAllText($ResultPath,'unexpected-success',[Text.Encoding]::ASCII)
    }
    catch {
        [IO.File]::WriteAllText($ResultPath,$_.Exception.ToString(),[Text.UTF8Encoding]::new($false))
    }
}
finally {
    $limitJob.Dispose()
}
'@
            [IO.File]::WriteAllText(
                $launcherPath,
                $launcherPrefix + (Get-OverlayBoundedFunctionDefinitions) + $launcherSuffix,
                [Text.UTF8Encoding]::new($false))
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $HostPath
            $startInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $launcherPath +
                '" -HostPath "' + $HostPath + '" -TargetPath "' + $targetPath +
                '" -RepositoryRoot "' + $RepositoryRoot + '" -MarkerPath "' + $targetMarkerPath +
                '" -ResultPath "' + $resultPath + '" -HelperPath "' + $HelperPath +
                '" -HelperSha256 "' + $HelperSha256 + '"'
            $startInfo.UseShellExecute = $false
            $launcher = [Diagnostics.Process]::new()
            $launcher.StartInfo = $startInfo
            try {
                if (-not $launcher.Start()) { throw 'Overlay active-limit launcher did not start.' }
                if (-not $launcher.WaitForExit(30000)) {
                    $launcher.Kill()
                    [void]$launcher.WaitForExit(15000)
                    throw 'Overlay active-limit launcher exceeded its execution limit.'
                }
                if (-not [IO.File]::Exists($resultPath)) { throw 'Overlay active-limit result was not written.' }
                return [pscustomobject]@{
                    Result = [IO.File]::ReadAllText($resultPath)
                    TargetMarkerExists = [IO.File]::Exists($targetMarkerPath)
                }
            }
            finally {
                if (-not $launcher.HasExited) {
                    $launcher.Kill()
                    [void]$launcher.WaitForExit(15000)
                }
                $launcher.Dispose()
            }
        }

        function Get-OverlayCombinedChildScript {
            return @'
param(
    [string]$RepositoryRoot,[string]$PesterManifestPath,[string]$ExpectedEdition,
    [ValidateSet('Discover','Run')][string]$Mode,
    [ValidateSet('None','Discovery','BeforeAll','SkippedOnly','EmptySelection','UnexpectedSkip','RuntimeSkip','UnexpectedExclusion','OneRequiredExcluded')][string]$ProbeCase='None'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -cne $ExpectedEdition) { throw 'Combined host identity differs.' }
if (($ExpectedEdition -eq 'Desktop' -and $PSVersionTable.PSVersion -lt [version]'5.1') -or ($ExpectedEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ne 7)) { throw 'Combined host version is unsupported.' }
$manifest = Import-PowerShellDataFile -LiteralPath $PesterManifestPath
if ([version]$manifest.ModuleVersion -lt [version]'5.3.3' -or [version]$manifest.ModuleVersion -ge [version]'6.0') { throw 'Combined Pester version is unsupported.' }
Import-Module $PesterManifestPath -ErrorAction Stop
$loaded = @(Get-Module Pester)
if ($loaded.Count -ne 1 -or $loaded[0].Version -ne [version]$manifest.ModuleVersion -or $loaded[0].ModuleBase -cne [IO.Path]::GetDirectoryName($PesterManifestPath)) { throw 'Combined Pester identity differs.' }
$names = @(
    'pins the six activation output paths and no frozen protocol path',
    'keeps schema typeIds IsolationAdmission 4872 and IsolationExit 4873 outside the generated type rows',
    'keeps S4UMintSlotV1 a standalone numeric schema typeId 4866',
    'inserts TokenMintAuthorizedSent only after TokenMintAuthorized in both NonInteractive variants',
    'keeps raw activated declaration order with IsolationAdmission and IsolationExit immediately before ServiceControlEventNodeProofV1',
    'emits 685 generated-assignment rows with exactly four new kind rows',
    'emits 35 associations including MintAttested 4370 and MintRevoked 4374',
    'builds 1386 applicable-profile tail rows with Mandatory None always applicable',
    'aggregates 8 channel cells and 43 message rows and omits interactive Broker and Local cells',
    'emits 16 maxima rows as four frozen payloads plus six roots times two profiles',
    'rejects target failures and the closed twelve-vector mutation set before creating an output root',
    'emits canonical lowercase-escape bytes for all six files',
    'atomically replaces each of the six files and leaves frozen protocol outputs dormant',
    'rejects verifier references to the activation authority',
    'regenerates identical six-file bytes on both hosts',
    'runs activation with protocol and evidence suites without recursive combined runs')
$paths = @(
    (Join-Path $RepositoryRoot 'tests\phase4-protocol\pspkt.ProtocolCatalogEngineV2.Tests.ps1'),
    (Join-Path $RepositoryRoot 'tests\phase4-protocol\pspkt.Phase4ProtocolSchemaAuthority.Tests.ps1'),
    (Join-Path $RepositoryRoot 'tests\phase4-evidence-ledger\pspkt.Phase4EvidenceLedgerAuthority.Tests.ps1'),
    (Join-Path $RepositoryRoot 'tests\phase4-overlay\pspkt.Phase4OverlayActivationAuthority.Tests.ps1'))
$allowedSkips = @(
    'Phase 4 protocol schema authority.runs the V2 and authority suites in one Pester process without recursive combined runs',
    'Phase 4 evidence ledger authority.runs protocol and evidence ledger suites together without recursive combined runs',
    'Phase 4 overlay activation.runs activation with protocol and evidence suites without recursive combined runs')
function Get-OverlayCombinedCount {
    param($Result,[string]$Name)
    $property = $Result.PSObject.Properties[$Name]
    if ($null -eq $property) { return 0 }
    return [int]$property.Value
}
function Test-OverlayCombinedResult {
    param($Result,[string[]]$Paths,[string[]]$Names,[string[]]$AllowedSkips)
    if ($null -eq $Result -or $Result.Result -cne 'Passed' -or $Result.TotalCount -ne 102 -or $Result.PassedCount -ne 99 -or $Result.SkippedCount -ne 3) { return $false }
    if ($Result.FailedCount -ne 0 -or $Result.FailedBlocksCount -ne 0 -or $Result.FailedContainersCount -ne 0 -or
        (Get-OverlayCombinedCount $Result 'InconclusiveCount') -ne 0 -or
        (Get-OverlayCombinedCount $Result 'NotRunCount') -ne 0) { return $false }
    if (@($Result.Containers).Count -ne 4 -or @($Result.Tests).Count -ne 102 -or $Paths.Count -ne 4) { return $false }
    if ((@($Result.Configuration.Filter.Tag.Value) -join ',') -cne 'Precheck') { return $false }
    $counts = @{}
    foreach ($path in $Paths) { $counts.Add([IO.Path]::GetFullPath($path),0) }
    $actualOverlayNames = [Collections.Generic.List[string]]::new()
    $skips = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($test in $Result.Tests) {
        if (-not $test.ScriptBlock.File) { return $false }
        $path = [IO.Path]::GetFullPath($test.ScriptBlock.File)
        if (-not $counts.ContainsKey($path)) { return $false }
        $counts[$path]++
        if ($path -eq [IO.Path]::GetFullPath($Paths[3])) { $actualOverlayNames.Add($test.Name) }
        if ($test.ExpandedPath -cin $AllowedSkips) {
            if (-not $test.ShouldRun -or -not $test.Skip -or $test.Result -cne 'Skipped' -or -not $skips.Add($test.ExpandedPath)) { return $false }
        } elseif (-not $test.ShouldRun -or -not $test.Executed -or $test.Skip -or $test.Result -cne 'Passed') {
            return $false
        }
    }
    foreach ($count in $counts.Values) { if ($count -eq 0) { return $false } }
    return $skips.Count -eq 3 -and ($actualOverlayNames -join "`n") -ceq ($Names -join "`n")
}
$configuration = New-PesterConfiguration
$configuration.Run.PassThru = $true
$configuration.Filter.Tag = @('Precheck')
$configuration.Output.Verbosity = 'Normal'
$env:PSPKT_PROTOCOL_COMBINED_CHILD = '1'
$env:PSPKT_EVIDENCE_LEDGER_COMBINED_CHILD = '1'
$env:PSPKT_OVERLAY_COMBINED_CHILD = '1'
if ($Mode -eq 'Discover') {
    $configuration.Run.Path = $paths[3]
    $configuration.Run.SkipRun = $true
    $result = Invoke-Pester -Configuration $configuration
    if (@($result.Containers).Count -ne 1 -or @($result.Tests).Count -ne 16 -or
        ($result.Tests.Name -join "`n") -cne ($names -join "`n") -or @($result.Tests | Where-Object Executed).Count -ne 0 -or
        $result.FailedCount -ne 0 -or $result.FailedBlocksCount -ne 0 -or $result.FailedContainersCount -ne 0) { throw 'Overlay exact discovery failed.' }
    "OVERLAY_DISCOVERY_OK|edition=$ExpectedEdition|tests=16|executed=0"
    exit 0
}
if ($ProbeCase -ne 'None') {
    $configuration.Run.Path = $paths
    $configuration.Run.SkipRun = $true
    $discovery = Invoke-Pester -Configuration $configuration
    if (@($discovery.Tests).Count -ne 102 -or $discovery.FailedContainersCount -ne 0) { throw 'Probe baseline discovery differs.' }
    $configuration.Run.SkipRun = $false
    $fixtureRoot = Join-Path $PSScriptRoot ($ExpectedEdition+'-'+$ProbeCase)
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    $originalPaths = $paths
    $paths = @($originalPaths | ForEach-Object { Join-Path $fixtureRoot ([IO.Path]::GetFileName($_)) })
    $descriptions = @('Protocol probe engine','Phase 4 protocol schema authority','Phase 4 evidence ledger authority','Phase 4 overlay activation')
    for ($fileIndex=0; $fileIndex -lt 4; $fileIndex++) {
        $tests = @($discovery.Tests | Where-Object { $_.ScriptBlock.File -eq $originalPaths[$fileIndex] })
        $lines = [Collections.Generic.List[string]]::new()
        $tags = "'Precheck'"
        if ($ProbeCase -eq 'UnexpectedExclusion' -and $fileIndex -eq 0) { $tags = "@('Precheck','ExcludedProbe')" }
        $lines.Add("Describe '$($descriptions[$fileIndex])' -Tag $tags {")
        if ($ProbeCase -eq 'BeforeAll' -and $fileIndex -eq 0) { $lines.Add("BeforeAll { throw 'Injected BeforeAll failure.' }") }
        for ($index=0; $index -lt $tests.Count; $index++) {
            $test = $tests[$index]
            $name = 'required-'+$fileIndex+'-'+$index
            if ($fileIndex -eq 3 -or $test.ExpandedPath -cin $allowedSkips) { $name = $test.Name }
            $parameters = ''
            $body = '1 | Should -Be 1'
            if ($test.ExpandedPath -cin $allowedSkips -or $ProbeCase -eq 'SkippedOnly' -or ($ProbeCase -eq 'UnexpectedSkip' -and $fileIndex -eq 3 -and $index -eq 0)) { $parameters = ' -Skip' }
            if ($fileIndex -eq 3 -and $index -eq 0) {
                if ($ProbeCase -eq 'RuntimeSkip') { $body = "Set-ItResult -Skipped -Because 'Injected runtime skip.'" }
                if ($ProbeCase -eq 'OneRequiredExcluded') { $parameters = " -Tag 'ExcludedProbe'" }
            }
            $lines.Add("It '$($name.Replace("'","''"))'$parameters { $body }")
        }
        $lines.Add('}')
        $text = $lines -join "`n"
        if ($ProbeCase -eq 'Discovery' -and $fileIndex -eq 0) { $text = "Describe 'unclosed discovery" }
        [IO.File]::WriteAllText($paths[$fileIndex],$text,[Text.UTF8Encoding]::new($false))
    }
    if ($ProbeCase -eq 'EmptySelection') { $configuration.Filter.ExcludeTag = @('Precheck') }
    if ($ProbeCase -eq 'UnexpectedExclusion' -or $ProbeCase -eq 'OneRequiredExcluded') { $configuration.Filter.ExcludeTag = @('ExcludedProbe') }
}
$configuration.Run.Path = $paths
$result = Invoke-Pester -Configuration $configuration
$accepted = Test-OverlayCombinedResult $result $paths $names $allowedSkips
if ($ProbeCase -ne 'None') {
    $first = @($result.Tests | Where-Object ExpandedPath -CEQ ('Phase 4 overlay activation.'+$names[0]))
    $observed = switch ($ProbeCase) {
        'Discovery' { $result.FailedContainersCount -gt 0 }
        'BeforeAll' { $result.FailedBlocksCount -gt 0 }
        'SkippedOnly' { $result.PassedCount -eq 0 -and $result.SkippedCount -eq 102 }
        'EmptySelection' { @($result.Tests | Where-Object ShouldRun).Count -eq 0 }
        'UnexpectedSkip' { $first.Count -eq 1 -and $first[0].Skip -and $first[0].Result -ceq 'Skipped' }
        'RuntimeSkip' { $first.Count -eq 1 -and -not $first[0].Skip -and $first[0].Executed -and $first[0].Result -ceq 'Skipped' }
        'UnexpectedExclusion' { @($result.Tests | Where-Object { $_.ScriptBlock.File -eq $paths[0] -and -not $_.ShouldRun }).Count -gt 0 }
        'OneRequiredExcluded' { $first.Count -eq 1 -and -not $first[0].ShouldRun -and $result.NotRunCount -eq 1 }
    }
    if (-not $observed -or $accepted) { throw "Combined rejection probe did not establish its intended failure: $ProbeCase" }
    "OVERLAY_COMBINED_REJECTED|case=$ProbeCase|edition=$ExpectedEdition"
    exit 1
}
if (-not $accepted) { throw "Overlay combined predicate failed: containers=$(@($result.Containers).Count), total=$($result.TotalCount), passed=$($result.PassedCount), skipped=$($result.SkippedCount), failed=$($result.FailedCount), blocks=$($result.FailedBlocksCount), failedContainers=$($result.FailedContainersCount), excluded=$($result.NotRunCount)." }
"OVERLAY_COMBINED_OK|edition=$ExpectedEdition|containers=4|total=102|passed=99|skipped=3|failed=0"
'@
        }
    }

    It 'pins the six activation output paths and no frozen protocol path' {
        Test-Path -LiteralPath $script:contractPath | Should -BeTrue
        . $script:contractPath
        $contract = Get-PspktOverlayActivationContract
        $expected = @(
            'certification/overlay/schema/protocol-schema.v1.json',
            'certification/overlay/schema/generated-base-id-map.v1.json',
            'certification/overlay/schema/protocol-message-association.v1.json',
            'certification/overlay/schema/mandatory-tail-schedule.v1.json',
            'certification/overlay/schema/overlay-matrices.v1.json',
            'certification/overlay/schema/overlay-maxima.v1.json')
        ($contract.OutputPathSet -join "`n") | Should -BeExactly ($expected -join "`n")
        @($contract.OutputPathSet | Select-Object -Unique).Count | Should -Be 6
        @($contract.OutputPathSet | Where-Object { $_ -notlike 'certification/overlay/schema/*' }).Count | Should -Be 0
        $validatorPath = Join-Path $script:repositoryRoot 'certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1'
        $tokens = $null
        $errors = $null
        $syntax = [Management.Automation.Language.Parser]::ParseFile($validatorPath,[ref]$tokens,[ref]$errors)
        $errors.Count | Should -Be 0
        $resolver = $syntax.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Resolve-PspktOverlayActivationPath'
        },$true)
        $resolver | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($resolver.Extent.Text))
        { Resolve-PspktOverlayActivationPath -Path '\\?\C:\overlay' -ParameterName 'Probe' } |
            Should -Throw 'Probe is not a supported filesystem path.'
        { Resolve-PspktOverlayActivationPath -Path 'C:overlay' -ParameterName 'Probe' } |
            Should -Throw 'Probe is not a supported filesystem path.'
        $resolver.Extent.Text.Contains('could not be normalized') | Should -BeTrue
        $resolver.Extent.Text.Contains("if (`$fullPath -match '^[\\/]{2}[?.][\\/]')") | Should -BeTrue
    }

    It 'keeps schema typeIds IsolationAdmission 4872 and IsolationExit 4873 outside the generated type rows' {
        Test-Path -LiteralPath $script:authorityPath | Should -BeTrue
        $outputs = Get-OverlayDeclarations
        $expectedSchema = $outputs['certification/overlay/schema/protocol-schema.v1.json']
        $script:overlayBootstrapAssembly = $null
        $script:overlayEngineAssembly = $null
        $script:engineContract = $null
        Initialize-OverlayCompilation
        $script:overlayBootstrapAssembly | Should -Not -BeNullOrEmpty
        $script:overlayEngineAssembly | Should -Not -BeNullOrEmpty
        $script:engineContract | Should -Not -BeNullOrEmpty
        [Convert]::ToBase64String((Get-OverlayDeclarations)['certification/overlay/schema/protocol-schema.v1.json']) |
            Should -BeExactly ([Convert]::ToBase64String($expectedSchema))
        $schema = [Text.Encoding]::UTF8.GetString($outputs['certification/overlay/schema/protocol-schema.v1.json']) | ConvertFrom-Json
        $map = [Text.Encoding]::UTF8.GetString($outputs['certification/overlay/schema/generated-base-id-map.v1.json']) | ConvertFrom-Json
        @($schema.types | Where-Object name -CEQ 'IsolationAdmission').Count | Should -Be 1
        @($schema.types | Where-Object name -CEQ 'IsolationExit').Count | Should -Be 1
        ($schema.types | Where-Object name -CEQ 'IsolationAdmission').typeId | Should -Be 4872
        ($schema.types | Where-Object name -CEQ 'IsolationExit').typeId | Should -Be 4873
        ($schema.types | Where-Object name -CEQ 'IsolationAdmission').fields.Count | Should -Be 7
        ($schema.types | Where-Object name -CEQ 'IsolationExit').fields.Count | Should -Be 3
        @($map | Where-Object { $_.category -eq 'type' -and $_.name -in @('IsolationAdmission','IsolationExit') }).Count | Should -Be 0
        $frozen = Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'certification\schema\protocol-schema.v1.json') -Raw | ConvertFrom-Json
        $ids = @{}
        foreach ($declaration in $schema.types) { $ids.Add($declaration.name,$declaration.typeId) }
        foreach ($declaration in $frozen.types) { $ids[$declaration.name] | Should -Be $declaration.typeId }
    }

    It 'keeps S4UMintSlotV1 a standalone numeric schema typeId 4866' {
        $outputs = Get-OverlayDeclarations
        $schemaBytes = $outputs['certification/overlay/schema/protocol-schema.v1.json']
        $schema = [Text.Encoding]::UTF8.GetString($schemaBytes) | ConvertFrom-Json
        $slot = $schema.types | Where-Object name -CEQ 'S4UMintSlotV1'
        $slot.typeId | Should -Be 4866
        $slot.production | Should -BeExactly 'Named'
        $slot.fields.Count | Should -Be 28
        $rows = [Text.Encoding]::UTF8.GetString(
            [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildS4uRows($schemaBytes)) | ConvertFrom-Json
        $rows.Count | Should -Be 28
        ($rows.fieldId -join ',') | Should -BeExactly ((1..28) -join ',')
        @($rows | Where-Object numeric).Count | Should -Be 14
        for ($index=0; $index -lt $rows.Count; $index++) {
            $rows[$index].name | Should -BeExactly $slot.fields[$index].name
            $rows[$index].type | Should -BeExactly $slot.fields[$index].type
            $rows[$index].numeric | Should -Be ($rows[$index].type -cin @('U8','U16','U32','U64','FILETIME','QPC'))
        }
        $catalog = Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json') -Raw | ConvertFrom-Json
        @($catalog.entries | Where-Object { $_.op -eq 'overlay-message' } | Where-Object payloadRoot -CEQ 'S4UMintSlotV1').Count | Should -Be 0
    }

    It 'inserts TokenMintAuthorizedSent only after TokenMintAuthorized in both NonInteractive variants' {
        Initialize-OverlayCompilation
        $path = Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'
        $bytes = [IO.File]::ReadAllBytes($path)
        $frozen = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $lifecycle = [Text.Encoding]::UTF8.GetString(
            [Pspkt.Certification.Overlay.OverlayActivationAuthority]::DeriveLifecycle($bytes)) | ConvertFrom-Json
        ($lifecycle.variantOrder -join ',') | Should -BeExactly ($frozen.lifecycle.variantOrder -join ',')
        ($lifecycle.variants | ForEach-Object { $_.states.Count }) -join ',' | Should -BeExactly '73,72,72,71,68,67'
        $allStates = @($lifecycle.variants | ForEach-Object { $_.states })
        $allStates.Count | Should -Be 423
        @($allStates | Select-Object -Unique).Count | Should -Be 92
        for ($index=0; $index -lt 6; $index++) {
            $states = $lifecycle.variants[$index].states
            if ($index -lt 4) {
                ($states -join ',') | Should -BeExactly ($frozen.lifecycle.variants[$index].states -join ',')
            } else {
                $states[30] | Should -BeExactly 'TokenMintAuthorized'
                $states[31] | Should -BeExactly 'TokenMintAuthorizedSent'
                $states[36] | Should -BeExactly 'CandidateAccessProbeAttested'
                @($states | Where-Object { $_ -ceq 'TokenMintAuthorizedSent' }).Count | Should -Be 1
                (($states | Where-Object { $_ -cne 'TokenMintAuthorizedSent' }) -join ',') |
                    Should -BeExactly ($frozen.lifecycle.variants[$index].states -join ',')
            }
        }
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) | Should -BeExactly ([Convert]::ToBase64String($bytes))
    }

    It 'keeps raw activated declaration order with IsolationAdmission and IsolationExit immediately before ServiceControlEventNodeProofV1' {
        Test-Path -LiteralPath $script:verifyPath | Should -BeTrue
        $outputs = Get-OverlayDeclarations
        $baseBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json'))
        $overlayBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json'))
        $schemaBytes = $outputs['certification/overlay/schema/protocol-schema.v1.json']
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyDeclarationOrder($baseBytes,$overlayBytes,$schemaBytes) } | Should -Not -Throw
        $schema = [Text.Encoding]::UTF8.GetString($schemaBytes) | ConvertFrom-Json
        $names = @($schema.types.name)
        $position = [Array]::IndexOf($names,'IsolationAdmission')
        ($names[($position-3)..($position+2)] -join ',') | Should -BeExactly 'ServiceLaunchProofV1,BrokerServicePrincipalAnchorV1,BrokerSessionKeyCertificateBodyV1,IsolationAdmission,IsolationExit,ServiceControlEventNodeProofV1'
        $schema.types = @($schema.types | Sort-Object typeId)
        $reordered = [Text.Encoding]::UTF8.GetBytes(($schema | ConvertTo-Json -Depth 100 -Compress))
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyDeclarationOrder($baseBytes,$overlayBytes,$reordered) } |
            Should -Throw '*Activated declaration order differs:*'
    }

    It 'emits 685 generated-assignment rows with exactly four new kind rows' {
        $outputs = Get-OverlayDeclarations
        $mapBytes = $outputs['certification/overlay/schema/generated-base-id-map.v1.json']
        $baseBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json'))
        $overlayBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json'))
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyAssignments($baseBytes,$overlayBytes,$mapBytes) } | Should -Not -Throw
        $map = [Text.Encoding]::UTF8.GetString($mapBytes) | ConvertFrom-Json
        $map.Count | Should -Be 685
        foreach ($category in @(@('type',37),@('field',507),@('kind',35),@('enum-member',53),@('union-branch',53))) {
            @($map | Where-Object category -CEQ $category[0]).Count | Should -Be $category[1]
        }
        $frozen = Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'certification\schema\generated-base-id-map.v1.json') -Raw | ConvertFrom-Json
        $frozenKindIds = @($frozen | Where-Object category -CEQ 'kind' | ForEach-Object generatedId)
        (@($map | Where-Object { $_.category -ceq 'kind' -and $_.generatedId -notin $frozenKindIds }).generatedId -join ',') |
            Should -BeExactly '4368,4370,4371,4374'
        $map[0].catalogOrdinal++
        $changed = [Text.Encoding]::UTF8.GetBytes(($map | ConvertTo-Json -Depth 100 -Compress))
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyAssignments($baseBytes,$overlayBytes,$changed) } |
            Should -Throw '*Activated assignment map differs.*'
    }

    It 'emits 35 associations including MintAttested 4370 and MintRevoked 4374' {
        $outputs = Get-OverlayDeclarations
        $bytes = Get-OverlayAssociations -Outputs $outputs
        $association = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $association.schemaId | Should -BeExactly 'PspktProtocolMessageAssociationV1'
        $rows = @($association.rows)
        $rows.Count | Should -Be 35
        @($rows | Where-Object channel -CEQ 'WorkerApp').Count | Should -Be 9
        @($rows | Where-Object channel -CEQ 'BrokerControl').Count | Should -Be 18
        @($rows | Where-Object channel -CEQ 'LocalIpc').Count | Should -Be 8
        @($rows | Where-Object mandatoryTailClass -CEQ 'Mandatory').Count | Should -Be 19
        @($rows | Where-Object { $_.mandatoryTailClass -ceq 'Mandatory' -and $_.stateAssoc -ceq 'None' }).Count | Should -Be 4
        @($rows | ForEach-Object { $_.channel + ':' + $_.name } | Select-Object -Unique).Count | Should -Be 30
        @($rows.payloadRoot | Select-Object -Unique).Count | Should -Be 28
        $mint = $rows | Where-Object kindId -EQ 4370
        $mint.name | Should -BeExactly 'MintAttested'
        $mint.direction | Should -BeExactly 'BrokerToHost'
        $mint.stateAssoc | Should -BeExactly 'CandidateAccessProbeAttested'
        ($rows | Where-Object kindId -EQ 4374).stateAssoc | Should -BeExactly 'TokenMintAuthorizedSent'
        $bytes.Length | Should -Be 7880
        $digest = [Security.Cryptography.SHA256]::Create()
        try {
            [BitConverter]::ToString($digest.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() |
                Should -BeExactly 'f17afa4eab197340d288fe3aea8154d80a696aa98559ef498844c7036b2e73ed'
        }
        finally { $digest.Dispose() }
    }

    It 'builds 1386 applicable-profile tail rows with Mandatory None always applicable' {
        $outputs = Get-OverlayDeclarations
        $associations = Get-OverlayAssociations -Outputs $outputs
        $bytes = Get-OverlaySchedule -Outputs $outputs -Associations $associations
        $schedule = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $rows = @($schedule.rows)
        $schedule.schemaId | Should -BeExactly 'PspktOverlayMandatoryTailScheduleV1'
        $rows.Count | Should -Be 1386
        @($rows | Where-Object channel -CEQ 'WorkerApp').Count | Should -Be 846
        @($rows | Where-Object channel -CEQ 'BrokerControl').Count | Should -Be 270
        @($rows | Where-Object channel -CEQ 'LocalIpc').Count | Should -Be 270
        @($rows | Where-Object records -GT 0).Count | Should -Be 949
        ($rows | Measure-Object records -Sum).Sum | Should -Be 1640
        @($rows | Where-Object { $_.profile -ceq 'InteractiveSeat' -and $_.channel -cne 'WorkerApp' }).Count | Should -Be 0
        @($rows.kinds | Where-Object name -In @('Keepalive','LocalKeepalive')).Count | Should -Be 0
        foreach ($row in $rows) {
            $row.records | Should -Be @($row.kinds).Count
            $row.records | Should -BeLessOrEqual 5535
            $row.wrapperBytes | Should -BeLessOrEqual 29360128
            if ($row.channel -ceq 'BrokerControl') { @($row.kinds | Where-Object name -CEQ 'BrokerFailure').Count | Should -Be 1 }
            if ($row.channel -ceq 'LocalIpc') { @($row.kinds | Where-Object name -CEQ 'LocalFailure').Count | Should -Be 1 }
        }
        $tailQuotaArguments = [object[]]@(5535,[Numerics.BigInteger]29360128)
        $authorityTailQuota = [Pspkt.Certification.Overlay.OverlayActivationAuthority].GetMethod(
            'RequireTailQuota',
            [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic)
        $verifierTailQuota = [Pspkt.Certification.Overlay.OverlayActivationVerify].GetMethod(
            'RequireTailQuota',
            [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic)
        { [void]$authorityTailQuota.Invoke($null,$tailQuotaArguments) } | Should -Not -Throw
        { [void]$verifierTailQuota.Invoke($null,$tailQuotaArguments) } | Should -Not -Throw
        { [void]$authorityTailQuota.Invoke($null,[object[]]@(5536,[Numerics.BigInteger]29360128)) } |
            Should -Throw '*Activated mandatory tail quota exceeded*'
        { [void]$verifierTailQuota.Invoke($null,[object[]]@(5535,[Numerics.BigInteger]29360129)) } |
            Should -Throw '*Activated schedule quota differs*'
        $bytes.Length | Should -Be 492641
        $digest = [Security.Cryptography.SHA256]::Create()
        try {
            [BitConverter]::ToString($digest.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() |
                Should -BeExactly 'd25c2997a24048e14c97dfc94c0ab05c8ffc8138d0cbc2d330c8f759760296a2'
        }
        finally { $digest.Dispose() }
    }

    It 'aggregates 8 channel cells and 43 message rows and omits interactive Broker and Local cells' {
        $outputs = Get-OverlayDeclarations
        $associations = Get-OverlayAssociations -Outputs $outputs
        $schedule = Get-OverlaySchedule -Outputs $outputs -Associations $associations
        $bytes = Get-OverlayMatrices -Outputs $outputs -Associations $associations -Schedule $schedule
        $matrix = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        foreach ($section in @(@('activatedTypes',5),@('activatedMessages',4),@('messageRows',43),@('channelRows',8),
            @('collisionRows',8),@('extensionRows',56),@('s4uRows',28),@('transcriptTypeRows',4),@('transcriptMessageRows',3),@('transcriptLinkRows',12))) {
            @($matrix.($section[0])).Count | Should -Be $section[1]
        }
        ($matrix.channelRows.peakWrapperBytes -join ',') | Should -BeExactly '789,5157,789,5277,2564,7182,601,1182'
        ($matrix.channelRows.peakRecords -join ',') | Should -BeExactly '1,5,1,5,4,6,1,2'
        @($matrix.channelRows | Where-Object { $_.profile -ceq 'InteractiveSeat' -and $_.channel -cne 'WorkerApp' }).Count | Should -Be 0
        ($matrix.activatedTypes.overlayOrdinal -join ',') | Should -BeExactly '26,55,144,152,156'
        @($matrix.extensionRows | Where-Object parentKind -CEQ 'baseType').Count | Should -Be 16
        @($matrix.transcriptLinkRows | Where-Object targetField -CEQ '*').Count | Should -Be 3
        ($matrix.transcriptMessageRows.stateIndex -join ',') | Should -BeExactly '34,34,35'
        $bytes.Length | Should -Be 35953
        $digest = [Security.Cryptography.SHA256]::Create()
        try {
            [BitConverter]::ToString($digest.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() |
                Should -BeExactly 'e10fccf716e4d935d83adb140a716e1eef9575c57277e250cc40647de07a5f13'
        }
        finally { $digest.Dispose() }
        $baseBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json'))
        $overlayBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json'))
        $protocolInventoryBytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'))
        $lifecycleBytes = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::DeriveLifecycle($protocolInventoryBytes)
        $lifecycle = [Text.Encoding]::UTF8.GetString($lifecycleBytes) | ConvertFrom-Json
        $lifecycle.variants[4].name = 'UnexpectedVariant'
        $changedLifecycle = [Text.Encoding]::UTF8.GetBytes(($lifecycle | ConvertTo-Json -Depth 100 -Compress))
        {
            [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildMatrices(
                $baseBytes,$overlayBytes,$outputs['certification/overlay/schema/protocol-schema.v1.json'],
                $associations,$schedule,$changedLifecycle,$protocolInventoryBytes)
        } | Should -Throw '*Overlay matrix lifecycle variant shape differs*'
        $lifecycle = [Text.Encoding]::UTF8.GetString($lifecycleBytes) | ConvertFrom-Json
        $lifecycle.variants[4].states = @($lifecycle.variants[4].states | Where-Object { $_ -cne 'CandidateAccessProbeAttested' })
        $changedLifecycle = [Text.Encoding]::UTF8.GetBytes(($lifecycle | ConvertTo-Json -Depth 100 -Compress))
        {
            [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildMatrices(
                $baseBytes,$overlayBytes,$outputs['certification/overlay/schema/protocol-schema.v1.json'],
                $associations,$schedule,$changedLifecycle,$protocolInventoryBytes)
        } | Should -Throw '*Activated message state is missing from matrix lifecycle*'
    }

    It 'emits 16 maxima rows as four frozen payloads plus six roots times two profiles' {
        $outputs = Get-OverlayDeclarations
        $schemaBytes = $outputs['certification/overlay/schema/protocol-schema.v1.json']
        $inventory = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'))
        $bytes = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildMaxima($schemaBytes,$inventory)
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyMaxima($schemaBytes,$bytes) } | Should -Not -Throw
        $maximums = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $maximums.rows.Count | Should -Be 16
        ($maximums.rows.maxPayloadBytes -join ',') | Should -BeExactly '1431,1529,1958,2078,744,744,912,912,114,114,5167,5287,780,884,644,644'
        $maximums.rows[4].maxPayloadBytes++
        $changed = [Text.Encoding]::UTF8.GetBytes(($maximums | ConvertTo-Json -Depth 100 -Compress))
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyMaxima($schemaBytes,$changed) } | Should -Throw '*Activated maxima differs.*'
        $overflow = [Numerics.BigInteger]::Pow(2,32)
        { [Pspkt.Certification.Overlay.OverlayActivationAuthority]::RequireUInt32($overflow) } | Should -Throw '*exceeds UInt32*'
        { [Pspkt.Certification.Overlay.OverlayActivationVerify]::RequireUInt32($overflow) } | Should -Throw '*exceeds UInt32*'
        [Pspkt.Certification.Overlay.OverlayActivationVerify]::RequireUInt32($overflow-1) | Should -Be 4294967295
        $bytes.Length | Should -Be 1632
        $digest = [Security.Cryptography.SHA256]::Create()
        try {
            [BitConverter]::ToString($digest.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() |
                Should -BeExactly '4d92ec08e2676e7d59d4cf522b3ede33a7e668e2c1fcd4b87ad41e3b8bb7d86c'
        }
        finally { $digest.Dispose() }
    }

    It 'rejects target failures and the closed twelve-vector mutation set before creating an output root' {
        $validatorRelative = 'certification/overlay/validators/Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1'
        Test-Path -LiteralPath (Join-Path $script:repositoryRoot $validatorRelative.Replace('/','\')) | Should -BeTrue
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $hostPath = Join-Path $PSHOME $hostName
        $nativeFailureTarget = Join-Path $TestDrive 'native-failure.ps1'
        [IO.File]::WriteAllText(
            $nativeFailureTarget,
            "param([string]`$Mode,[string]`$RepositoryRoot,[string]`$OutputRoot)`n& `$env:ComSpec /c exit 9",
            [Text.UTF8Encoding]::new($false))
        $nativeFailure = Invoke-OverlayValidatorChild -HostPath $hostPath -TargetPath $nativeFailureTarget `
            -Mode 'Compile' -RepositoryRoot $script:repositoryRoot
        $nativeFailure.ExitCode | Should -Be 9
        $nativeFailure.StandardOutput | Should -BeExactly ''
        $nativeFailure.StandardError | Should -BeExactly ('Overlay activation target failed with exit code 9.' + [Environment]::NewLine)
        $explicitExitTarget = Join-Path $TestDrive 'explicit-exit.ps1'
        [IO.File]::WriteAllText(
            $explicitExitTarget,
            "param([string]`$Mode,[string]`$RepositoryRoot,[string]`$OutputRoot)`nexit 7",
            [Text.UTF8Encoding]::new($false))
        $explicitExit = Invoke-OverlayValidatorChild -HostPath $hostPath -TargetPath $explicitExitTarget `
            -Mode 'Compile' -RepositoryRoot $script:repositoryRoot
        $explicitExit.ExitCode | Should -Be 7
        $explicitExit.StandardOutput | Should -BeExactly ''
        $explicitExit.StandardError | Should -BeExactly ('Overlay activation target failed with exit code 7.' + [Environment]::NewLine)
        $stillActiveValueTarget = Join-Path $TestDrive 'exit-259.ps1'
        [IO.File]::WriteAllText(
            $stillActiveValueTarget,
            "param([string]`$Mode,[string]`$RepositoryRoot,[string]`$OutputRoot)`n& `$env:ComSpec /d /c exit 259",
            [Text.UTF8Encoding]::new($false))
        $stillActiveValueFailure = Invoke-OverlayValidatorChild `
            -HostPath $hostPath `
            -TargetPath $stillActiveValueTarget `
            -Mode 'Compile' `
            -RepositoryRoot $script:repositoryRoot
        $stillActiveValueFailure.ExitCode | Should -Be 259
        $stillActiveValueFailure.StandardOutput | Should -BeExactly ''
        $stillActiveValueFailure.StandardError | Should -BeExactly (
            'Overlay activation target failed with exit code 259.' + [Environment]::NewLine)
        $unicodeTarget = Join-Path $TestDrive 'unicode-failure.ps1'
        $unicodeSource = @'
param([string]$Mode,[string]$RepositoryRoot,[string]$OutputRoot)
$value = [string][char]0x00E9 + [char]0x6F22
Write-Output $value
Write-Host $value
throw $value
'@
        [IO.File]::WriteAllText($unicodeTarget,$unicodeSource,[Text.UTF8Encoding]::new($false))
        $originalOutputEncoding = [Console]::OutputEncoding
        try {
            [Console]::OutputEncoding = [Text.Encoding]::GetEncoding(437)
            $unicodeFailure = Invoke-OverlayValidatorChild `
                -HostPath $hostPath `
                -TargetPath $unicodeTarget `
                -Mode 'Compile' `
                -RepositoryRoot $script:repositoryRoot
            [Console]::OutputEncoding.CodePage | Should -Be 437
        }
        finally {
            [Console]::OutputEncoding = $originalOutputEncoding
        }
        $unicodeValue = [string][char]0x00E9 + [char]0x6F22
        $expectedUnicodeOutput = $unicodeValue + [Environment]::NewLine + $unicodeValue + [Environment]::NewLine
        $expectedUnicodeError = $unicodeValue + [Environment]::NewLine
        $unicodeFailure.ExitCode | Should -Be 1
        [string]::Equals($unicodeFailure.StandardOutput,$expectedUnicodeOutput,[StringComparison]::Ordinal) | Should -BeTrue
        [string]::Equals($unicodeFailure.StandardError,$expectedUnicodeError,[StringComparison]::Ordinal) | Should -BeTrue
        [Convert]::ToBase64String($unicodeFailure.StandardOutputBytes) | Should -BeExactly (
            [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($expectedUnicodeOutput)))
        [Convert]::ToBase64String($unicodeFailure.StandardErrorBytes) | Should -BeExactly (
            [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($expectedUnicodeError)))
        $bomTarget = Join-Path $TestDrive 'bom-target.ps1'
        $bomSource = @'
param([string]$Mode,[string]$RepositoryRoot,[string]$OutputRoot)
$bytes = [byte[]]@(0xEF,0xBB,0xBF,0x41)
$stream = if ($Mode -ceq 'StandardOutput') {
    [Console]::OpenStandardOutput()
} else {
    [Console]::OpenStandardError()
}
$stream.Write($bytes,0,$bytes.Length)
$stream.Flush()
'@
        [IO.File]::WriteAllText($bomTarget,$bomSource,[Text.UTF8Encoding]::new($false))
        foreach ($bomMode in @('StandardOutput','StandardError')) {
            {
                Invoke-OverlayValidatorChild `
                    -HostPath $hostPath `
                    -TargetPath $bomTarget `
                    -Mode $bomMode `
                    -RepositoryRoot $script:repositoryRoot
            } | Should -Throw '*contains a UTF-8 byte-order mark*'
        }
        $lifecycleTarget = Join-Path $TestDrive 'lifecycle-target.ps1'
        $lifecycleSource = @'
param([string]$Mode,[string]$RepositoryRoot,[string]$OutputRoot)
$descendant = Start-Process -FilePath $env:ComSpec `
    -ArgumentList @('/d','/s','/c','ping -n 600 127.0.0.1 >nul') `
    -NoNewWindow `
    -PassThru
$identityTemporaryPath = $OutputRoot + '.tmp'
[IO.File]::WriteAllText(
    $identityTemporaryPath,
    ($descendant.Id.ToString([Globalization.CultureInfo]::InvariantCulture) + '|' +
        $descendant.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)),
    [Text.Encoding]::ASCII)
[IO.File]::Move($identityTemporaryPath,$OutputRoot)
$releasePath = $OutputRoot + '.release'
$releaseStopwatch = [Diagnostics.Stopwatch]::StartNew()
while (-not [IO.File]::Exists($releasePath) -and $releaseStopwatch.ElapsedMilliseconds -lt 30000) {
    Start-Sleep -Milliseconds 25
}
if (-not [IO.File]::Exists($releasePath)) {
    throw 'Overlay lifecycle release was not published.'
}
if ($Mode -ceq 'Overflow') {
    [Console]::Out.Write(('x' * 65536))
}
if ($Mode -cne 'Linger') {
    Start-Sleep -Seconds 600
}
'@
        [IO.File]::WriteAllText($lifecycleTarget,$lifecycleSource,[Text.UTF8Encoding]::new($false))
        foreach ($probeCase in @('Linger','Timeout','Cancel','Overflow')) {
            $identityPath = Join-Path $TestDrive ($probeCase.ToLowerInvariant() + '-identity.txt')
            $probeResult = Invoke-OverlayLifecycleProbe `
                -HostPath $hostPath `
                -TargetPath $lifecycleTarget `
                -RepositoryRoot $script:repositoryRoot `
                -IdentityPath $identityPath `
                -ProbeCase $probeCase
            $probeResult.DescendantExited | Should -BeTrue -Because $probeCase
            $probeResult.ElapsedMilliseconds | Should -BeLessThan 30000 -Because $probeCase
            if ($probeCase -ceq 'Linger') {
                $probeResult.Errors | Should -Match 'Overlay child root exited while a descendant remained active'
            }
            elseif ($probeCase -ceq 'Timeout') {
                $probeResult.Errors | Should -Match 'Overlay child exceeded its execution limit'
            }
            elseif ($probeCase -ceq 'Overflow') {
                $probeResult.Errors | Should -Match 'Overlay child output exceeded its byte cap'
            }
            else {
                $probeResult.InvocationState | Should -BeIn @('Stopped','Failed')
            }
        }
        . $script:contractPath
        $boundedProcessContract = Get-PspktOverlayActivationContract
        $boundedProcessRelativePath = 'certification/overlay/lib/Pspkt.Certification.OverlayBoundedProcess.cs'
        $boundedProcessPath = Join-Path $script:repositoryRoot $boundedProcessRelativePath.Replace('/','\')
        $boundedProcessSha256 = $boundedProcessContract.Sha256ByPath[$boundedProcessRelativePath]
        {
            Import-PspktOverlayBoundedProcess `
                -SourcePath $boundedProcessPath `
                -ExpectedSha256 $boundedProcessSha256
        } | Should -Not -Throw
        $bindingKey = 'Pspkt.Certification.Overlay.OverlayBoundedProcess.SourceSha256'
        [AppDomain]::CurrentDomain.SetData($bindingKey,('0' * 64))
        try {
            {
                Import-PspktOverlayBoundedProcess `
                    -SourcePath $boundedProcessPath `
                    -ExpectedSha256 $boundedProcessSha256
            } | Should -Throw '*Loaded overlay bounded-process source binding differs*'
        }
        finally {
            [AppDomain]::CurrentDomain.SetData($bindingKey,$boundedProcessSha256)
        }
        foreach ($invalidExecutablePath in @('C:','\Windows\System32\cmd.exe')) {
            {
                [Pspkt.Certification.Overlay.OverlayBoundedProcess]::Start(
                    $invalidExecutablePath,
                    [string[]]@(),
                    $script:repositoryRoot,
                    [string[]]@(),
                    [string[]]@(),
                    1024)
            } | Should -Throw '*fully qualified and normalized*'
        }
        $largeEnvironmentNames = [Collections.Generic.List[string]]::new()
        $largeEnvironmentValues = [Collections.Generic.List[string]]::new()
        $largeEnvironmentStartInfo = [Diagnostics.ProcessStartInfo]::new()
        $inheritedEnvironment = (Get-PspktOverlayProcessEnvironment $largeEnvironmentStartInfo).EnvironmentVariables
        foreach ($environmentName in @($inheritedEnvironment.Keys)) {
            $largeEnvironmentNames.Add([string]$environmentName)
            $largeEnvironmentValues.Add([string]$inheritedEnvironment[$environmentName])
        }
        $paddingPrefix = 'PSPKT_LARGE_' + [guid]::NewGuid().ToString('N') + '_'
        0..39 | ForEach-Object {
            $largeEnvironmentNames.Add($paddingPrefix + $_.ToString('D2',[Globalization.CultureInfo]::InvariantCulture))
            $largeEnvironmentValues.Add('x' * 1000)
        }
        $largeEnvironmentSession = [Pspkt.Certification.Overlay.OverlayBoundedProcess]::Start(
            $hostPath,
            [string[]]@('-NoLogo','-NoProfile','-NonInteractive','-Command','exit 0'),
            $TestDrive,
            $largeEnvironmentNames.ToArray(),
            $largeEnvironmentValues.ToArray(),
            1024)
        try {
            $largeEnvironmentStopwatch = [Diagnostics.Stopwatch]::StartNew()
            do {
                $largeEnvironmentSnapshot = $largeEnvironmentSession.Poll()
                if ($largeEnvironmentSnapshot.IsRootExited -and
                    $largeEnvironmentSnapshot.ActiveProcessCount -eq 0 -and
                    $largeEnvironmentSnapshot.StandardOutputComplete -and
                    $largeEnvironmentSnapshot.StandardErrorComplete) {
                    break
                }
                [void]$largeEnvironmentSession.WaitSlice(100)
            } while ($largeEnvironmentStopwatch.ElapsedMilliseconds -lt 15000)
            $largeEnvironmentResult = $largeEnvironmentSession.Complete()
            $largeEnvironmentResult.ExitCode | Should -Be 0 -Because (
                $largeEnvironmentResult.StandardOutput + $largeEnvironmentResult.StandardError)
            { $largeEnvironmentSession.Poll() } | Should -Throw '*ownership is already complete*'
            { $largeEnvironmentSession.WaitSlice(0) } | Should -Throw '*ownership is already complete*'
        }
        finally {
            $largeEnvironmentSession.Dispose()
        }
        $faultMarkerPath = Join-Path $TestDrive 'fault-target-ran.txt'
        $faultTarget = Join-Path $TestDrive 'fault-target.ps1'
        [IO.File]::WriteAllText(
            $faultTarget,
            "param([string]`$Mode,[string]`$RepositoryRoot,[string]`$OutputRoot)`n[IO.File]::WriteAllText(`$OutputRoot,'ran')",
            [Text.UTF8Encoding]::new($false))
        $testHookType = ('Pspkt.Certification.Overlay.OverlayBoundedProcess' -as [type]).Assembly.GetType(
            'Pspkt.Certification.Overlay.OverlayBoundedProcessTestHooks',
            $true)
        $identityMethod = $testHookType.GetMethod(
            'GetLastStartedProcessIdentity',
            [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic)
        $waitMethod = $testHookType.GetMethod(
            'WaitLastStartedProcessExit',
            [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic)
        $handleCountBeforeFaults = [Diagnostics.Process]::GetCurrentProcess().HandleCount
        1..20 | ForEach-Object {
            {
                Invoke-PspktOverlayBoundedPowerShell `
                    -HostPath $hostPath `
                    -TargetPath $faultTarget `
                    -TargetParameters @{
                        Mode = 'Fault'
                        RepositoryRoot = $script:repositoryRoot
                        OutputRoot = $faultMarkerPath
                    } `
                    -WorkingDirectory $script:repositoryRoot `
                    -Fault 'AfterCreateBeforeResume'
            } | Should -Throw '*Injected overlay bounded-process failure after process creation*'
            $faultIdentity = [long[]]$identityMethod.Invoke($null,[object[]]@())
            $faultIdentity[0] | Should -BeGreaterThan 0
            $faultIdentity[1] | Should -BeGreaterThan 0
            $waitMethod.Invoke($null,[object[]]@(15000)) | Should -BeTrue
            { [Diagnostics.Process]::GetProcessById([int]$faultIdentity[0]) } | Should -Throw
        }
        [Diagnostics.Process]::GetCurrentProcess().HandleCount | Should -BeLessOrEqual ($handleCountBeforeFaults + 4)
        Test-Path -LiteralPath $faultMarkerPath | Should -BeFalse
        $writerTarget = Join-Path $TestDrive 'writer-target.ps1'
        [IO.File]::WriteAllText(
            $writerTarget,
            'param([string]$Mode,[string]$RepositoryRoot,[string]$OutputRoot)',
            [Text.UTF8Encoding]::new($false))
        $holderStartInfo = [Diagnostics.ProcessStartInfo]::new()
        $holderStartInfo.FileName = $hostPath
        $holderStartInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 600"'
        $holderStartInfo.UseShellExecute = $false
        $holder = [Diagnostics.Process]::new()
        $holder.StartInfo = $holderStartInfo
        try {
            if (-not $holder.Start()) { throw 'Overlay writer holder did not start.' }
            $writerStopwatch = [Diagnostics.Stopwatch]::StartNew()
            {
                Invoke-PspktOverlayBoundedPowerShell `
                    -HostPath $hostPath `
                    -TargetPath $writerTarget `
                    -TargetParameters @{
                        Mode = 'Writer'
                        RepositoryRoot = $script:repositoryRoot
                    } `
                    -WorkingDirectory $script:repositoryRoot `
                    -TimeoutMilliseconds 15000 `
                    -OutsideWriterProcessId $holder.Id
            } | Should -Throw '*Overlay child stream remained open outside its process job*'
            $writerStopwatch.ElapsedMilliseconds | Should -BeLessThan 30000
            $holder.HasExited | Should -BeFalse
        }
        finally {
            if (-not $holder.HasExited) {
                $holder.Kill()
                [void]$holder.WaitForExit(15000)
            }
            $holder.Dispose()
        }
        $parentLossResult = Invoke-OverlayParentLossProbe `
            -HostPath $hostPath `
            -RepositoryRoot $script:repositoryRoot `
            -HelperPath $boundedProcessPath `
            -HelperSha256 $boundedProcessSha256 `
            -ProbeRoot (Join-Path $TestDrive 'parent-loss')
        $parentLossResult.WrapperExited | Should -BeTrue
        $parentLossResult.DescendantExited | Should -BeTrue
        $parentLossResult.FailureMarkerExists | Should -BeFalse
        $coreHostPath = Get-OverlayHostPath 'pwsh.exe'
        $storeAliasRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
        if ($PSVersionTable.PSEdition -ceq 'Desktop' -and
            $coreHostPath.StartsWith($storeAliasRoot,[StringComparison]::OrdinalIgnoreCase)) {
            foreach ($storeRelayProbeCase in @('ParentLoss','Timeout')) {
                $storeRelayResult = Invoke-OverlayStoreRelayProbe -ProbeCase $storeRelayProbeCase
                $storeRelayResult.BridgeExited | Should -BeTrue -Because $storeRelayProbeCase
                $storeRelayResult.WorkerExited | Should -BeTrue -Because $storeRelayProbeCase
                $storeRelayResult.DescendantExited | Should -BeTrue -Because $storeRelayProbeCase
                $storeRelayResult.RelayExited | Should -BeTrue -Because $storeRelayProbeCase
                if ($storeRelayProbeCase -ceq 'Timeout') {
                    $storeRelayResult.Errors | Should -Match 'execution limit'
                }
            }
        }
        $activeLimitResult = Invoke-OverlayActiveLimitProbe `
            -HostPath $hostPath `
            -RepositoryRoot $script:repositoryRoot `
            -HelperPath $boundedProcessPath `
            -HelperSha256 $boundedProcessSha256 `
            -ProbeRoot (Join-Path $TestDrive 'active-limit')
        $activeLimitResult.TargetMarkerExists | Should -BeFalse
        $activeLimitResult.Result | Should -Match 'Win32 error 1816'
        Initialize-OverlayCompilation
        . $script:contractPath
        $contract = Get-PspktOverlayActivationContract
        $overlayPath = 'certification/schema/catalog/overlay.catalog.v1.json'
        $inventoryPath = 'certification/overlay/schema/overlay-activation-inventory.v1.json'
        $cases = @(
            @('overlay-byte',$overlayPath,'/','append-lf',$false,'Pinned overlay activation hash differs: certification/schema/catalog/overlay.catalog.v1.json'),
            @('op-unknown',$overlayPath,'/entries/0/op','unknown-op',$true,'Overlay activation engine rejected: op-unknown'),
            @('channel',$overlayPath,'/entries/412/channel','WorkerApp',$true,'Overlay activation engine rejected: invalid-direction'),
            @('direction',$overlayPath,'/entries/414/direction','HostToBroker',$true,'Activated message row differs: BrokerControl:MintAttested'),
            @('unassigned-id',$inventoryPath,'/unassignedOverlayTypeIds/0',4872,$true,'Overlay activation inventory shape differs: unassignedOverlayTypeIds'),
            @('reserved-illegal-id',$overlayPath,'/entries/143/id',4881,$true,'Overlay activation engine rejected: duplicate-type-id'),
            @('kind-range',$overlayPath,'/entries/412/id',5000,$true,'Overlay activation engine rejected: overlay-id-out-of-range'),
            @('substring-omission',$inventoryPath,'/activatedTypeNames/2','Isolation',$true,'Overlay activation inventory shape differs: activatedTypeNames'),
            @('field-id-40',$inventoryPath,'/rehomeTypes/0/fields/0/id',40,$true,'Overlay activation inventory shape differs: rehomeTypes'),
            @('boolean-count',$inventoryPath,'/expectedCounts/schemaTypes',$true,$true,'Overlay activation inventory shape differs: expectedCounts.schemaTypes'),
            @('extra-key',$inventoryPath,'/unexpected',1,$true,'Overlay activation inventory shape differs: unknown property unexpected'),
            @('duplicate-message',$overlayPath,'/entries/414','append-copy',$true,'Overlay activation engine rejected: duplicate-kind'))
        $cases.Count | Should -Be 12
        foreach ($case in $cases) {
            $fixtureRoot = Join-Path $TestDrive $case[0]
            foreach ($relative in @($contract.Sha256ByPath.Keys) + 'certification/overlay/lib/Pspkt.Certification.OverlayActivationContract.ps1') {
                $destination = Join-Path $fixtureRoot $relative.Replace('/','\')
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
                [IO.File]::WriteAllBytes($destination,[IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot $relative.Replace('/','\'))))
            }
            $path = Join-Path $fixtureRoot $case[1].Replace('/','\')
            if ($case[0] -eq 'overlay-byte') {
                [IO.File]::WriteAllBytes($path,[byte[]]@([IO.File]::ReadAllBytes($path) + 10))
            } else {
                $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
                switch ($case[0]) {
                    'op-unknown' { $document.entries[0].op = $case[3] }
                    'channel' { $document.entries[412].channel = $case[3] }
                    'direction' { $document.entries[414].direction = $case[3] }
                    'unassigned-id' { $document.unassignedOverlayTypeIds[0] = $case[3] }
                    'reserved-illegal-id' { $document.entries[143].id = $case[3] }
                    'kind-range' { $document.entries[412].id = $case[3] }
                    'substring-omission' { $document.activatedTypeNames[2] = $case[3] }
                    'field-id-40' { $document.rehomeTypes[0].fields[0].id = $case[3] }
                    'boolean-count' { $document.expectedCounts.schemaTypes = $case[3] }
                    'extra-key' { $document | Add-Member -NotePropertyName unexpected -NotePropertyValue 1 }
                    'duplicate-message' { $document.entries = @($document.entries) + @($document.entries[414]) }
                }
                [IO.File]::WriteAllText($path,($document | ConvertTo-Json -Depth 100 -Compress),[Text.UTF8Encoding]::new($false))
            }
            if ($case[4]) {
                $fixtureContract = Join-Path $fixtureRoot 'certification\overlay\lib\Pspkt.Certification.OverlayActivationContract.ps1'
                $text = [IO.File]::ReadAllText($fixtureContract)
                $oldPin = "'" + $case[1] + "' = '" + $contract.Sha256ByPath[$case[1]] + "'"
                $newPin = "'" + $case[1] + "' = '" + (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() + "'"
                $text.Contains($oldPin) | Should -BeTrue
                [IO.File]::WriteAllText($fixtureContract,$text.Replace($oldPin,$newPin),[Text.UTF8Encoding]::new($false))
            }
            $outputRoot = Join-Path $fixtureRoot 'must-not-exist'
            $result = Invoke-OverlayValidatorChild -HostPath $hostPath `
                -TargetPath (Join-Path $fixtureRoot $validatorRelative.Replace('/','\')) `
                -Mode 'Generate' -RepositoryRoot $fixtureRoot -OutputRoot $outputRoot
            $result.ExitCode | Should -Not -Be 0 -Because $case[0]
            $result.StandardOutput | Should -BeExactly '' -Because $case[0]
            $result.StandardError.IndexOf($case[5],[StringComparison]::Ordinal) | Should -BeGreaterOrEqual 0 -Because $case[0]
            if ($case[0] -cne 'overlay-byte') {
                $parentOffset = $result.StandardError.IndexOf('Overlay activation child failed with exit code ',[StringComparison]::Ordinal)
                $childOffset = $result.StandardError.IndexOf($case[5],[StringComparison]::Ordinal)
                $parentOffset | Should -BeGreaterOrEqual 0 -Because $case[0]
                $childOffset | Should -BeGreaterThan $parentOffset -Because $case[0]
            }
            Test-Path -LiteralPath $outputRoot | Should -BeFalse
            if ($case[0] -eq 'direction') {
                { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyActivatedMessages([IO.File]::ReadAllBytes($path)) } |
                    Should -Throw ('*' + $case[5] + '*')
            }
        }

    }

    It 'emits canonical lowercase-escape bytes for all six files' {
            Initialize-OverlayCompilation
            $input = [Text.Encoding]::UTF8.GetBytes('{ "z":"\b\f\n\r\t\u001B\"\\/", "a":[true,123,null] }')
            $expected = '{"a":[true,123,null],"z":"\u0008\u000c\u000a\u000d\u0009\u001b\"\\/"}'
            [Text.Encoding]::UTF8.GetString([Pspkt.Certification.Overlay.OverlayActivationAuthority]::Canonicalize($input)) | Should -BeExactly $expected
            [Text.Encoding]::UTF8.GetString([Pspkt.Certification.Overlay.OverlayActivationVerify]::Canonicalize($input)) | Should -BeExactly $expected
            . $script:contractPath
            $contract = Get-PspktOverlayActivationContract
            foreach ($relative in $contract.OutputPathSet) {
                $bytes = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot $relative.Replace('/','\')))
                $encoded = [Convert]::ToBase64String($bytes)
                [Convert]::ToBase64String([Pspkt.Certification.Overlay.OverlayActivationAuthority]::Canonicalize($bytes)) | Should -BeExactly $encoded
                [Convert]::ToBase64String([Pspkt.Certification.Overlay.OverlayActivationVerify]::Canonicalize($bytes)) | Should -BeExactly $encoded
                $bytes[-1] | Should -Not -Be 10
                @($bytes | Where-Object { $_ -gt 127 -or $_ -eq 13 }).Count | Should -Be 0
            }
            $duplicate = [Text.Encoding]::UTF8.GetBytes('{"a":1,"a":2}')
            { [Pspkt.Certification.Overlay.OverlayActivationAuthority]::Canonicalize($duplicate) } | Should -Throw '*duplicate-key*'
            { [Pspkt.Certification.Overlay.OverlayActivationVerify]::Canonicalize($duplicate) } | Should -Throw '*duplicate-key*'
    }

    It 'atomically replaces each of the six files and leaves frozen protocol outputs dormant' {
            $validatorPath = Join-Path $script:repositoryRoot 'certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1'
            $tokens = $null
            $errors = $null
            $tree = [Management.Automation.Language.Parser]::ParseFile($validatorPath,[ref]$tokens,[ref]$errors)
            @($errors).Count | Should -Be 0
            $definition = $tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-PspktOverlayActivationFile'},$true)
            Set-Item -LiteralPath Function:\Write-PspktOverlayActivationFile -Value $definition.Body.GetScriptBlock()
            . $script:contractPath
            $contract = Get-PspktOverlayActivationContract
            foreach ($relative in $contract.OutputPathSet) {
                $destination = Join-Path $TestDrive ([IO.Path]::GetFileName($relative.Replace('/','\')))
                $prior = [Text.Encoding]::ASCII.GetBytes('prior:'+$relative)
                $replacement = [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot $relative.Replace('/','\')))
                [IO.File]::WriteAllBytes($destination,$prior)
                {
                    Write-PspktOverlayActivationFile -Path $destination -Bytes $replacement -BeforeReplace {
                        param($temporaryPath,$targetPath)
                        [IO.File]::Exists($temporaryPath) | Should -BeTrue
                        [IO.File]::ReadAllBytes($temporaryPath).Length | Should -Be $replacement.Length
                        $targetPath | Should -BeExactly $destination
                        throw 'Injected before replacement.'
                    }
                } | Should -Throw '*Injected before replacement.*'
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($destination)) | Should -BeExactly ([Convert]::ToBase64String($prior))
                @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp').Count | Should -Be 0
                Write-PspktOverlayActivationFile -Path $destination -Bytes $replacement
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($destination)) | Should -BeExactly ([Convert]::ToBase64String($replacement))
                [IO.File]::Delete($destination)
                { Write-PspktOverlayActivationFile -Path $destination -Bytes $replacement -BeforeReplace { throw 'Injected before first move.' } } |
                    Should -Throw '*Injected before first move.*'
                Test-Path -LiteralPath $destination | Should -BeFalse
                @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp').Count | Should -Be 0
                Write-PspktOverlayActivationFile -Path $destination -Bytes $replacement
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($destination)) | Should -BeExactly ([Convert]::ToBase64String($replacement))
            }
            $timestamps = @{}
            foreach ($relative in $contract.Sha256ByPath.Keys) {
                $path = Join-Path $script:repositoryRoot $relative.Replace('/','\')
                $timestamps.Add($relative,[IO.File]::GetLastWriteTimeUtc($path).Ticks)
            }
            $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
            $generatedRoot = Join-Path $TestDrive 'generated'
            foreach ($mode in @('Generate','Validate')) {
                $result = Invoke-OverlayChild -HostPath (Join-Path $PSHOME $hostName) -Arguments @(
                    '-NoLogo','-NoProfile','-File',$validatorPath,'-Mode',$mode,'-OutputRoot',$generatedRoot)
                $result.ExitCode | Should -Be 0 -Because ($result.StandardOutput + $result.StandardError)
            }
            @(Get-ChildItem -LiteralPath $generatedRoot -Recurse -File).Count | Should -Be 6
            foreach ($relative in $contract.Sha256ByPath.Keys) {
                $path = Join-Path $script:repositoryRoot $relative.Replace('/','\')
                (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() | Should -BeExactly $contract.Sha256ByPath[$relative]
                [IO.File]::GetLastWriteTimeUtc($path).Ticks | Should -Be $timestamps[$relative]
            }
            $changedOutputRelative = 'certification/overlay/schema/overlay-maxima.v1.json'
            $changedOutputPath = Join-Path $generatedRoot $changedOutputRelative.Replace('/','\')
            $changedOutput = Get-Content -LiteralPath $changedOutputPath -Raw | ConvertFrom-Json
            $changedOutput.rows[0].maxPayloadBytes++
            [IO.File]::WriteAllText(
                $changedOutputPath,
                ($changedOutput | ConvertTo-Json -Depth 100 -Compress),
                [Text.UTF8Encoding]::new($false))
            $changedResult = Invoke-OverlayChild -HostPath (Join-Path $PSHOME $hostName) -Arguments @(
                '-NoLogo','-NoProfile','-File',$validatorPath,'-Mode','Validate','-OutputRoot',$generatedRoot)
            $changedResult.ExitCode | Should -Not -Be 0
            $changedResult.StandardError.IndexOf(
                'Activated output identity differs: ' + $changedOutputRelative,
                [StringComparison]::Ordinal) | Should -BeGreaterOrEqual 0
    }

    It 'rejects verifier references to the activation authority' {
            Initialize-OverlayCompilation
            $bootstrapIdentity = $script:overlayBootstrapAssembly.FullName
            $assemblyRoot = Join-Path $TestDrive 'assemblies'
            $forbidden = [string[]]@(
                $script:overlayEngineAssembly.FullName,
                [Pspkt.Certification.Overlay.OverlayActivationAuthority].Assembly.FullName)
            $probeForbidden = [string[]]@(
                [Reflection.AssemblyName]::GetAssemblyName((Join-Path $assemblyRoot 'FoundationEngine.dll')).FullName,
                [Reflection.AssemblyName]::GetAssemblyName((Join-Path $assemblyRoot 'OverlayActivationAuthority.dll')).FullName)
            $verifier = [Pspkt.Certification.Overlay.OverlayActivationVerify].Assembly
            { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyAssemblyReferences($verifier,$bootstrapIdentity,$forbidden) } | Should -Not -Throw
            { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyAssemblyReferences($verifier,'UnexpectedBootstrap, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null',$forbidden) } |
                Should -Throw '*bootstrap identity differs*'
            $framework = if ($PSVersionTable.PSEdition -eq 'Desktop') {
                @('System.dll','System.Core.dll')
            } else {
                @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object FullName)
            }
            $sourcePath = Join-Path $TestDrive 'CoupledProbe.cs'
            [IO.File]::WriteAllText($sourcePath,
                'public static class CoupledProbe { public static System.Type Target() { return typeof(Pspkt.Certification.Overlay.OverlayActivationAuthority); } }',
                [Text.UTF8Encoding]::new($false))
            Push-Location -LiteralPath $TestDrive
            try {
                Add-Type -LiteralPath $sourcePath -OutputAssembly 'CoupledProbe.dll' -ReferencedAssemblies @(
                    $framework + (Join-Path $assemblyRoot 'SchemaBootstrap.dll') + (Join-Path $assemblyRoot 'FoundationEngine.dll') +
                    (Join-Path $assemblyRoot 'OverlayActivationAuthority.dll'))
                $coupledProbeAssembly = Import-OverlayTestAssembly -Path (Join-Path $TestDrive 'CoupledProbe.dll') -PassThru
            }
            finally { Pop-Location }
            { [Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyAssemblyReferences($coupledProbeAssembly,$bootstrapIdentity,$probeForbidden) } |
                Should -Throw '*forbidden assembly reference*'
    }

    It 'regenerates identical six-file bytes on both hosts' {
            $wrapper = Join-Path $script:repositoryRoot 'certification\overlay\vectors\New-PspktPhase4OverlayActivationVectors.ps1'
            Test-Path -LiteralPath $wrapper | Should -BeTrue
            $loaded = @(Get-Module Pester)
            $loaded.Count | Should -Be 1
            $manifest = Join-Path $loaded[0].ModuleBase 'Pester.psd1'
            $childPath = Join-Path $TestDrive 'Regenerate.ps1'
            $child = @'
param([string]$RepositoryRoot,[string]$OutputRoot,[string]$PesterManifestPath,[string]$ExpectedEdition)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -cne $ExpectedEdition) { throw 'Regeneration host edition differs.' }
if (($ExpectedEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -ne 5) -or ($ExpectedEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ne 7)) { throw 'Regeneration host version differs.' }
$manifest = Import-PowerShellDataFile -LiteralPath $PesterManifestPath
if ([version]$manifest.ModuleVersion -lt [version]'5.3.3' -or [version]$manifest.ModuleVersion -ge [version]'6.0') { throw 'Regeneration Pester version is unsupported.' }
Import-Module $PesterManifestPath -ErrorAction Stop
$loaded = @(Get-Module Pester)
if ($loaded.Count -ne 1 -or $loaded[0].Version -ne [version]$manifest.ModuleVersion -or $loaded[0].ModuleBase -cne [IO.Path]::GetDirectoryName($PesterManifestPath)) { throw 'Regeneration Pester identity differs.' }
$validator = Join-Path $RepositoryRoot 'certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1'
& $validator -Mode Compile -RepositoryRoot $RepositoryRoot
& $validator -Mode Validate -RepositoryRoot $RepositoryRoot
& (Join-Path $RepositoryRoot 'certification\overlay\vectors\New-PspktPhase4OverlayActivationVectors.ps1') -RepositoryRoot $RepositoryRoot -OutputRoot $OutputRoot
& $validator -Mode Validate -RepositoryRoot $RepositoryRoot -OutputRoot $OutputRoot
"OVERLAY_REGENERATED|edition=$ExpectedEdition|pester=$($loaded[0].Version)|files=6"
'@
            [IO.File]::WriteAllText($childPath,$child,[Text.UTF8Encoding]::new($false))
            . $script:contractPath
            $contract = Get-PspktOverlayActivationContract
            foreach ($hostCase in @(@('Desktop','powershell.exe'),@('Core','pwsh.exe'))) {
                $outputRoot = Join-Path $TestDrive ($hostCase[0]+' [literal space]')
                $result = Invoke-OverlayChild -HostPath (Get-OverlayHostPath $hostCase[1]) -Arguments @(
                    '-NoLogo','-NoProfile','-File',$childPath,'-RepositoryRoot',$script:repositoryRoot,'-OutputRoot',$outputRoot,
                    '-PesterManifestPath',$manifest,'-ExpectedEdition',$hostCase[0])
                $result.ExitCode | Should -Be 0 -Because ($result.StandardOutput + $result.StandardError)
                Assert-OverlayReceipt -Result $result `
                    -ExpectedReceipt ('OVERLAY_REGENERATED|edition='+$hostCase[0]+'|pester='+$loaded[0].Version+'|files=6') `
                    -ReceiptFamily 'OVERLAY_REGENERATED|'
                @(Get-ChildItem -LiteralPath $outputRoot -Recurse -File).Count | Should -Be 6
                $total = 0
                foreach ($relative in $contract.OutputPathSet) {
                    $file = Join-Path $outputRoot $relative.Replace('/','\')
                    $bytes = [IO.File]::ReadAllBytes($file)
                    $total += $bytes.Length
                    $bytes.Length | Should -BeLessThan 1048576
                    [Convert]::ToBase64String($bytes) | Should -BeExactly (
                        [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot $relative.Replace('/','\')))))
                    (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant() | Should -BeExactly $contract.Sha256ByPath[$relative]
                }
                $total | Should -Be 733833
            }
    }

    It 'runs activation with protocol and evidence suites without recursive combined runs' -Tag 'OverlayCombined' -Skip:([Environment]::GetEnvironmentVariable('PSPKT_OVERLAY_COMBINED_CHILD') -eq '1') {
            $expectedReceipt = 'OVERLAY_DISCOVERY_OK|edition=Core|tests=16|executed=0'
            {
                Assert-OverlayReceipt -Result ([pscustomobject]@{
                    StandardOutput = "ordinary output`r`n$expectedReceipt`r`n"
                    StandardError = ''
                }) -ExpectedReceipt $expectedReceipt -ReceiptFamily 'OVERLAY_DISCOVERY_'
            } | Should -Not -Throw
            foreach ($invalidReceipt in @(
                [pscustomobject]@{ StandardOutput = "prefix $expectedReceipt"; StandardError = '' },
                [pscustomobject]@{ StandardOutput = "$expectedReceipt suffix"; StandardError = '' },
                [pscustomobject]@{ StandardOutput = "$expectedReceipt`r`n$expectedReceipt"; StandardError = '' },
                [pscustomobject]@{ StandardOutput = $expectedReceipt; StandardError = $expectedReceipt },
                [pscustomobject]@{
                    StandardOutput = "$expectedReceipt`r`nOVERLAY_DISCOVERY_REJECTED|edition=Core"
                    StandardError = ''
                })) {
                {
                    Assert-OverlayReceipt -Result $invalidReceipt `
                        -ExpectedReceipt $expectedReceipt `
                        -ReceiptFamily 'OVERLAY_DISCOVERY_'
                } | Should -Throw '*Overlay completion receipt differs*'
            }
            $childPath = Join-Path $TestDrive 'Combined.ps1'
            [IO.File]::WriteAllText($childPath,(Get-OverlayCombinedChildScript),[Text.UTF8Encoding]::new($false))
            $manifest = Join-Path (Get-Module Pester).ModuleBase 'Pester.psd1'
            foreach ($hostCase in @(@('Desktop','powershell.exe'),@('Core','pwsh.exe'))) {
                $hostPath = Get-OverlayHostPath $hostCase[1]
                foreach ($mode in @('Discover','Run')) {
                    $result = Invoke-OverlayChild -HostPath $hostPath -TimeoutSeconds 900 -Arguments @(
                        '-NoLogo','-NoProfile','-File',$childPath,'-RepositoryRoot',$script:repositoryRoot,
                        '-PesterManifestPath',$manifest,'-ExpectedEdition',$hostCase[0],'-Mode',$mode)
                    $result.ExitCode | Should -Be 0 -Because ($result.StandardOutput + $result.StandardError)
                    if ($mode -eq 'Discover') {
                        Assert-OverlayReceipt -Result $result `
                            -ExpectedReceipt ('OVERLAY_DISCOVERY_OK|edition='+$hostCase[0]+'|tests=16|executed=0') `
                            -ReceiptFamily 'OVERLAY_DISCOVERY_'
                    } else {
                        Assert-OverlayReceipt -Result $result `
                            -ExpectedReceipt ('OVERLAY_COMBINED_OK|edition='+$hostCase[0]+'|containers=4|total=102|passed=99|skipped=3|failed=0') `
                            -ReceiptFamily 'OVERLAY_COMBINED_'
                    }
                    Write-Host $result.StandardOutput
                }
                foreach ($probe in @('Discovery','BeforeAll','SkippedOnly','EmptySelection','UnexpectedSkip','RuntimeSkip','UnexpectedExclusion','OneRequiredExcluded')) {
                    $result = Invoke-OverlayChild -HostPath $hostPath -Arguments @(
                        '-NoLogo','-NoProfile','-File',$childPath,'-RepositoryRoot',$script:repositoryRoot,
                        '-PesterManifestPath',$manifest,'-ExpectedEdition',$hostCase[0],'-Mode','Run','-ProbeCase',$probe)
                    $result.ExitCode | Should -Be 1 -Because ($result.StandardOutput + $result.StandardError)
                    Assert-OverlayReceipt -Result $result `
                        -ExpectedReceipt ('OVERLAY_COMBINED_REJECTED|case='+$probe+'|edition='+$hostCase[0]) `
                        -ReceiptFamily 'OVERLAY_COMBINED_'
                }
            }
    }
}
