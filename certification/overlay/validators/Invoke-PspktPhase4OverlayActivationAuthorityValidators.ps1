[CmdletBinding()]
param(
    [ValidateSet('Generate','Validate','Compile')][string]$Mode = 'Validate',
    [string]$RepositoryRoot,
    [string]$OutputRoot,
    [switch]$Worker,
    [string]$AssemblyRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PspktOverlayActivationInventory {
    param([byte[]]$Bytes)

    $inventory = [Text.Encoding]::UTF8.GetString($Bytes) | ConvertFrom-Json
    $keys = 'activatedTypeIds activatedTypeNames associations dormancy engineParameters expectedCounts expectedOutputs frozenInputHashes lifecycle lifecycleSourceSha256 matrices maxima mutationCases outputPathSet rehomeTypes reservedIllegalType schedule schemaId schemaVersion transformation unassignedOverlayTypeIds'.Split(' ')
    foreach ($key in $inventory.psobject.Properties.Name) {
        if ($key -cnotin $keys) { throw "Overlay activation inventory shape differs: unknown property $key" }
    }
    if (@($inventory.psobject.Properties).Count -ne $keys.Count) { throw 'Overlay activation inventory shape differs: root keys' }
    if ($inventory.schemaId -cne 'PspktOverlayActivationInventoryV1' -or $inventory.schemaVersion -is [bool] -or $inventory.schemaVersion -ne 1) {
        throw 'Overlay activation inventory shape differs: identity'
    }
    if (($inventory.activatedTypeNames -join ',') -cne 'S4UMintSlotV1,MintAttestedV1,IsolationAdmission,IsolationExit,ServiceControlEventNodeProofV1') {
        throw 'Overlay activation inventory shape differs: activatedTypeNames'
    }
    if (($inventory.activatedTypeIds -join ',') -cne '4866,4867,4872,4873,4874') { throw 'Overlay activation inventory shape differs: activatedTypeIds' }
    if (($inventory.unassignedOverlayTypeIds -join ',') -cne '4875,4876') { throw 'Overlay activation inventory shape differs: unassignedOverlayTypeIds' }
    if ($inventory.reservedIllegalType.name -cne 'LocalTranscriptRecordSetV1' -or $inventory.reservedIllegalType.id -ne 4881) {
        throw 'Overlay activation inventory shape differs: reservedIllegalType'
    }
    $fieldContracts = @(
        @('workerServiceLaunchProof:ServiceLaunchProofV1','workerServiceControlEventNodeProof:ServiceControlEventNodeProofV1',
            'brokerServiceLaunchProof:BrokerServiceLaunchProofV1','brokerServiceControlEventNodeProof:ServiceControlEventNodeProofV1',
            'admissionReceipt:WorkerProcessIsolationAdmissionReceiptV1','brokerAnchor:BrokerServicePrincipalAnchorV1',
            'workerProcessDaclAccessPolicyProof:WorkerProcessDaclAccessPolicyProofV1'),
        @('isolationReceipt:WorkerProcessIsolationReceiptV1','workerServiceControlEventNodeProof:ServiceControlEventNodeProofV1','localTranscriptProofDigest:SHA-256'))
    if (@($inventory.rehomeTypes).Count -ne 2) { throw 'Overlay activation inventory shape differs: rehomeTypes' }
    for ($index=0; $index -lt 2; $index++) {
        $type = $inventory.rehomeTypes[$index]
        $name = @('IsolationAdmission','IsolationExit')[$index]
        if ($type.name -cne $name -or $type.id -ne (4872+$index) -or $type.fields.Count -ne $fieldContracts[$index].Count) {
            throw 'Overlay activation inventory shape differs: rehomeTypes'
        }
        for ($fieldIndex=0; $fieldIndex -lt $type.fields.Count; $fieldIndex++) {
            $field = $type.fields[$fieldIndex]
            if ($field.id -is [bool] -or $field.id -ne ($fieldIndex+1) -or ($field.name+':'+$field.type) -cne $fieldContracts[$index][$fieldIndex]) {
                throw 'Overlay activation inventory shape differs: rehomeTypes'
            }
        }
    }
    $counts = 'schemaTypes=112 generatedTypes=90 literalTypes=22 enumTypes=7 namedTypes=105 physicalFields=906 mapRows=685 typeRows=37 fieldRows=507 kindRows=35 enumMemberRows=53 unionBranchRows=53 associations=35 messageIdentities=30 payloadRoots=28 workerAssociations=9 brokerAssociations=18 localAssociations=8 mandatoryAssociations=19 ordinaryAssociations=16 mandatoryNone=4 activatedBaseOperations=296 activatedOverlayOperations=446 lifecycleVariants=6 lifecycleStates=423 distinctStates=92 scheduleRows=1386 workerScheduleRows=846 brokerScheduleRows=270 localScheduleRows=270 nonEmptyScheduleRows=949 kindMemberships=1640 activatedTypes=5 activatedMessages=4 messageRows=43 channelRows=8 collisionRows=8 extensionRows=56 baseExtensionRows=16 unionExtensionRows=40 s4uRows=28 numericS4uRows=14 transcriptTypeRows=4 transcriptMessageRows=3 transcriptLinkRows=12 maximaRows=16 frozenTypes=107 sharedOrdinalChanges=81 extensionParents=46 outputFiles=6 outputBytes=733833'.Split(' ')
    if (@($inventory.expectedCounts.psobject.Properties).Count -ne $counts.Count) { throw 'Overlay activation inventory shape differs: expectedCounts' }
    foreach ($definition in $counts) {
        $pair = $definition.Split('=')
        $property = $inventory.expectedCounts.psobject.Properties[$pair[0]]
        if ($null -eq $property -or $property.Value -is [bool] -or
            ($property.Value -isnot [int] -and $property.Value -isnot [long]) -or $property.Value -ne [long]$pair[1]) {
            throw ('Overlay activation inventory shape differs: expectedCounts.'+$pair[0])
        }
    }
}

function Resolve-PspktOverlayActivationPath {
    param([string]$Path,[string]$ParameterName)

    if (-not $Path) { return $Path }
    if ($Path -match '^[\\/]{2}[?.][\\/]' -or $Path -match '^[A-Za-z]:(?![\\/])') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $provider = $null
    $drive = $null
    try {
        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    }
    catch { throw "$ParameterName could not be resolved: $($_.Exception.Message)" }
    if ($provider.Name -cne 'FileSystem' -or $resolved -match '^[\\/]{2}[?.][\\/]') { throw "$ParameterName is not a supported filesystem path." }
    $isDrive = $resolved -match '^[A-Za-z]:[\\/]'
    if (-not $isDrive -and $resolved -notmatch '^[\\/]{2}[^\\/]+[\\/][^\\/]+') { throw "$ParameterName must resolve to an absolute filesystem path." }
    $names = if ($isDrive) { $resolved.Substring(2) } else { $resolved.TrimStart([char[]]@('\','/')) }
    foreach ($component in $names.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)) {
        if ($component.EndsWith(' ',[StringComparison]::Ordinal) -or $component.EndsWith('.',[StringComparison]::Ordinal)) {
            throw "$ParameterName contains a normalization-sensitive path component."
        }
        if ($component.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw "$ParameterName contains an invalid filesystem path component." }
    }
    try { $fullPath = [IO.Path]::GetFullPath($resolved) }
    catch { throw "$ParameterName could not be normalized: $($_.Exception.Message)" }
    if ($fullPath -match '^[\\/]{2}[?.][\\/]') { throw "$ParameterName is not a supported filesystem path." }
    $normalized = if ($fullPath -match '^[A-Za-z]:[\\/]+$') { [IO.Path]::GetPathRoot($fullPath) } else { $fullPath.TrimEnd([char[]]@('\','/')) }
    $components = $normalized.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)
    $finalName = $components[$components.Length-1].Split('.')[0].ToUpperInvariant()
    $reserved = @('CON','PRN','AUX','NUL','CLOCK$','CONIN$','CONOUT$')
    $reserved += 1..9 | ForEach-Object { 'COM'+$_; 'LPT'+$_ }
    foreach ($suffix in @([char]0x00B9,[char]0x00B2,[char]0x00B3)) { $reserved += 'COM'+$suffix; $reserved += 'LPT'+$suffix }
    if ($finalName -cin $reserved) { throw "$ParameterName is not a supported filesystem path." }
    return $normalized
}

function Write-PspktOverlayActivationFile {
    param([string]$Path,[byte[]]$Bytes,[scriptblock]$BeforeReplace)

    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $stream = [IO.FileStream]::new($temporaryPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            $stream.Write($Bytes,0,$Bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if ($null -ne $BeforeReplace) { & $BeforeReplace $temporaryPath $Path }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporaryPath,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporaryPath,$Path) }
    }
    finally {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

function Get-PspktOverlayProcessEnvironment {
    param([Diagnostics.ProcessStartInfo]$StartInfo)

    $environmentNames = @([Environment]::GetEnvironmentVariables().Keys)
    $seenNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($environmentName in $environmentNames) {
        if (-not $seenNames.Add([string]$environmentName)) {
            throw "Process environment contains names that differ only by case: $environmentName"
        }
    }
    return [pscustomobject]@{ EnvironmentVariables = $StartInfo.EnvironmentVariables }
}

function Clear-PspktOverlayHostEnvironment {
    param([Collections.Specialized.StringDictionary]$EnvironmentVariables)

    foreach ($environmentName in @($EnvironmentVariables.Keys)) {
        if ($environmentName.StartsWith('PSPKT_OVERLAY_HOST_',[StringComparison]::OrdinalIgnoreCase)) {
            $EnvironmentVariables.Remove($environmentName)
        }
    }
}

function Import-PspktOverlayBoundedProcess {
    param([string]$SourcePath,[string]$ExpectedSha256)

    $sourceBytes = [IO.File]::ReadAllBytes($SourcePath)
    $digest = [Security.Cryptography.SHA256]::Create()
    try {
        $actualSha256 = [BitConverter]::ToString($digest.ComputeHash($sourceBytes)).Replace('-','').ToLowerInvariant()
    }
    finally { $digest.Dispose() }
    if ($actualSha256 -cne $ExpectedSha256) {
        throw 'Overlay bounded-process source hash differs.'
    }
    $bindingKey = 'Pspkt.Certification.Overlay.OverlayBoundedProcess.SourceSha256'
    $boundedProcessType = 'Pspkt.Certification.Overlay.OverlayBoundedProcess' -as [type]
    if ($null -eq $boundedProcessType) {
        Add-Type -TypeDefinition ([Text.UTF8Encoding]::new($false,$true).GetString($sourceBytes))
        [AppDomain]::CurrentDomain.SetData($bindingKey,$actualSha256)
        $boundedProcessType = 'Pspkt.Certification.Overlay.OverlayBoundedProcess' -as [type]
    }
    $loadedSha256 = [AppDomain]::CurrentDomain.GetData($bindingKey)
    if ($null -eq $boundedProcessType -or $loadedSha256 -isnot [string] -or $loadedSha256 -cne $actualSha256) {
        throw 'Loaded overlay bounded-process source binding differs.'
    }
    $versionField = $boundedProcessType.GetField('Version')
    $startMethod = $boundedProcessType.GetMethod('Start',[type[]]@(
            [string],[string[]],[string],[string[]],[string[]],[int]))
    if ($null -eq $versionField -or
        $versionField.GetRawConstantValue() -cne 'pspkt-overlay-bounded-process-1' -or
        $null -eq $startMethod) {
        throw 'Loaded overlay bounded-process API shape differs.'
    }
}

function Invoke-PspktOverlayBoundedPowerShell {
    param(
        [string]$HostPath,
        [string]$TargetPath,
        [hashtable]$TargetParameters,
        [string]$WorkingDirectory,
        [int]$TimeoutMilliseconds = 180000,
        [int]$RetainCapBytes = 8388608,
        [string]$Fault = 'None',
        [int]$OutsideWriterProcessId = 0,
        [int]$ParentProcessId = 0,
        [long]$ParentProcessStartTimeFileTimeUtc = 0
    )

    if ($TimeoutMilliseconds -lt 1) { throw 'Overlay child timeout must be positive.' }
    if ($RetainCapBytes -lt 1) { throw 'Overlay child output cap must be positive.' }
    $wrapper = @'
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
try {
    $parameterCount = [int]::Parse(
        $env:PSPKT_OVERLAY_HOST_PARAMETER_COUNT,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture)
    $invokeParameters = @{}
    for ($parameterIndex = 0; $parameterIndex -lt $parameterCount; $parameterIndex++) {
        $prefix = 'PSPKT_OVERLAY_HOST_PARAMETER_' + $parameterIndex + '_'
        $name = [Environment]::GetEnvironmentVariable($prefix + 'NAME')
        $kind = [Environment]::GetEnvironmentVariable($prefix + 'KIND')
        $value = [Environment]::GetEnvironmentVariable($prefix + 'VALUE')
        if ($name -notmatch '^[A-Za-z][A-Za-z0-9]*$' -or $invokeParameters.ContainsKey($name)) {
            throw "Overlay target parameter transport is invalid at index $parameterIndex."
        }
        if ($kind -ceq 'Switch') {
            if ($value -cne '0' -and $value -cne '1') {
                throw "Overlay target switch transport is invalid at index $parameterIndex."
            }
            $invokeParameters.Add($name,($value -ceq '1'))
        }
        elseif ($kind -ceq 'String') {
            $invokeParameters.Add($name,$value)
        }
        else {
            throw "Overlay target parameter kind is invalid at index $parameterIndex."
        }
    }
    & $env:PSPKT_OVERLAY_HOST_TARGET @invokeParameters 6>&1
    $targetSucceeded = $?
    $targetExitCode = $LASTEXITCODE
    if (-not $targetSucceeded -or ($null -ne $targetExitCode -and $targetExitCode -ne 0)) {
        $failureExitCode = if ($null -ne $targetExitCode -and $targetExitCode -ne 0) { [int]$targetExitCode } else { 1 }
        [Console]::Error.WriteLine("Overlay activation target failed with exit code $failureExitCode.")
        exit $failureExitCode
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
'@
    $arguments = [string[]]@(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-OutputFormat',
        'Text',
        '-EncodedCommand',
        [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper)))
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $environmentVariables = (Get-PspktOverlayProcessEnvironment $startInfo).EnvironmentVariables
    Clear-PspktOverlayHostEnvironment $environmentVariables
    $hostModulePath = Join-Path ([IO.Path]::GetDirectoryName($HostPath)) 'Modules'
    $environmentVariables['PSModulePath'] = $hostModulePath + [IO.Path]::PathSeparator + $environmentVariables['PSModulePath']
    $environmentVariables['PSPKT_OVERLAY_HOST_TARGET'] = $TargetPath
    $orderedParameterNames = @($TargetParameters.Keys | Sort-Object)
    $environmentVariables['PSPKT_OVERLAY_HOST_PARAMETER_COUNT'] = $orderedParameterNames.Count.ToString(
        [Globalization.CultureInfo]::InvariantCulture)
    for ($parameterIndex = 0; $parameterIndex -lt $orderedParameterNames.Count; $parameterIndex++) {
        $parameterName = [string]$orderedParameterNames[$parameterIndex]
        if ($parameterName -notmatch '^[A-Za-z][A-Za-z0-9]*$') {
            throw "Overlay target parameter name is invalid: $parameterName"
        }
        $parameterValue = $TargetParameters[$parameterName]
        $parameterKind = if ($parameterValue -is [Management.Automation.SwitchParameter] -or $parameterValue -is [bool]) {
            'Switch'
        } else {
            'String'
        }
        $transportValue = if ($parameterKind -ceq 'Switch') {
            if ([bool]$parameterValue) { '1' } else { '0' }
        } else {
            [string]$parameterValue
        }
        $prefix = 'PSPKT_OVERLAY_HOST_PARAMETER_' + $parameterIndex + '_'
        $environmentVariables[$prefix + 'NAME'] = $parameterName
        $environmentVariables[$prefix + 'KIND'] = $parameterKind
        $environmentVariables[$prefix + 'VALUE'] = $transportValue
    }
    $environmentNames = [string[]]@($environmentVariables.Keys)
    $environmentValues = [string[]]@($environmentNames | ForEach-Object { $environmentVariables[$_] })
    $boundedProcessType = 'Pspkt.Certification.Overlay.OverlayBoundedProcess' -as [type]
    $faultType = $boundedProcessType.Assembly.GetType(
        'Pspkt.Certification.Overlay.OverlayBoundedProcessFault',
        $true)
    $faultValue = [Enum]::Parse($faultType,$Fault,$false)
    $session = $null
    $parentProcess = $null
    $parentSafeHandle = $null
    $result = $null
    $primaryFailure = $null
    $cleanupFailures = [Collections.Generic.List[Exception]]::new()
    $completed = $false
    try {
        if ($ParentProcessId -ne 0) {
            $parentProcess = [Diagnostics.Process]::GetProcessById($ParentProcessId)
            $parentSafeHandle = $parentProcess.SafeHandle
            if ($null -eq $parentSafeHandle -or $parentSafeHandle.IsInvalid -or $parentSafeHandle.IsClosed) {
                throw 'Overlay bounded-process parent handle is unavailable.'
            }
            if ($parentProcess.StartTime.ToFileTimeUtc() -ne $ParentProcessStartTimeFileTimeUtc -or
                $parentProcess.WaitForExit(0)) {
                throw 'Overlay bounded-process parent identity differs or already exited.'
            }
        }
        if ($Fault -ceq 'None' -and $OutsideWriterProcessId -eq 0) {
            $session = $boundedProcessType::Start(
                $HostPath,
                $arguments,
                $WorkingDirectory,
                $environmentNames,
                $environmentValues,
                $RetainCapBytes)
        } else {
            $startForTest = $boundedProcessType.GetMethod(
                'StartForTest',
                [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic,
                $null,
                [type[]]@(
                    [string],[string[]],[string],[string[]],[string[]],[int],
                    $faultType,[int]),
                $null)
            if ($null -eq $startForTest) { throw 'Overlay bounded-process test API shape differs.' }
            $session = $startForTest.Invoke($null,[object[]]@(
                $HostPath,
                $arguments,
                $WorkingDirectory,
                $environmentNames,
                $environmentValues,
                $RetainCapBytes,
                $faultValue,
                $OutsideWriterProcessId))
        }
        $executionStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $descendantGraceMilliseconds = 15000
        $pipeGraceMilliseconds = 2000
        $descendantGraceStart = -1L
        $pipeGraceStart = -1L
        while ($true) {
            if ($null -ne $parentProcess -and $parentProcess.WaitForExit(0)) {
                throw 'Overlay bounded-process parent exited.'
            }
            $snapshot = $session.Poll()
            if ($snapshot.HasOutputOverflow) {
                throw 'Overlay child output exceeded its byte cap.'
            }
            $rootExited = $snapshot.IsRootExited
            $activeProcessCount = $snapshot.ActiveProcessCount
            $streamsComplete = $snapshot.StandardOutputComplete -and $snapshot.StandardErrorComplete
            if ($rootExited -and $activeProcessCount -eq 0 -and $streamsComplete) {
                $result = $session.Complete()
                $completed = $true
                break
            }
            if ($rootExited -and $activeProcessCount -gt 0) {
                if ($descendantGraceStart -lt 0) { $descendantGraceStart = $executionStopwatch.ElapsedMilliseconds }
                if (($executionStopwatch.ElapsedMilliseconds - $descendantGraceStart) -ge $descendantGraceMilliseconds) {
                    throw 'Overlay child root exited while a descendant remained active.'
                }
            } else {
                $descendantGraceStart = -1L
            }
            if ($activeProcessCount -eq 0 -and -not $streamsComplete) {
                if ($pipeGraceStart -lt 0) { $pipeGraceStart = $executionStopwatch.ElapsedMilliseconds }
                if (($executionStopwatch.ElapsedMilliseconds - $pipeGraceStart) -ge $pipeGraceMilliseconds) {
                    throw 'Overlay child stream remained open outside its process job.'
                }
            } else {
                $pipeGraceStart = -1L
            }
            if ($executionStopwatch.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                throw 'Overlay child exceeded its execution limit.'
            }
            if ($rootExited) {
                [Threading.Thread]::Sleep(100)
            } else {
                [void]$session.WaitSlice(100)
            }
        }
    }
    catch {
        $primaryFailure = $_
    }
    finally {
        if ($null -ne $session -and -not $completed) {
            try { $session.Abort(15000) }
            catch { $cleanupFailures.Add($_.Exception) }
        }
        if ($null -ne $session) {
            try { $session.Dispose() }
            catch { $cleanupFailures.Add($_.Exception) }
        }
        if ($null -ne $parentProcess) {
            try { $parentProcess.Dispose() }
            catch { $cleanupFailures.Add($_.Exception) }
        }
    }
    if ($null -ne $primaryFailure -or $cleanupFailures.Count -gt 0) {
        if ($cleanupFailures.Count -gt 0) {
            $allFailures = [Collections.Generic.List[Exception]]::new()
            if ($null -ne $primaryFailure) { $allFailures.Add($primaryFailure.Exception) }
            $allFailures.AddRange($cleanupFailures)
            throw [AggregateException]::new('Overlay bounded-process execution failed.',$allFailures.ToArray())
        }
        throw $primaryFailure
    }
    return [pscustomobject]@{
        ExitCode = $result.ExitCode
        StandardOutput = $result.StandardOutput
        StandardError = $result.StandardError
        StandardOutputBytes = $result.StandardOutputBytes
        StandardErrorBytes = $result.StandardErrorBytes
    }
}

if (-not $RepositoryRoot) { $RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..')) }
$RepositoryRoot = Resolve-PspktOverlayActivationPath $RepositoryRoot 'RepositoryRoot'
$OutputRoot = Resolve-PspktOverlayActivationPath $OutputRoot 'OutputRoot'
$AssemblyRoot = Resolve-PspktOverlayActivationPath $AssemblyRoot 'AssemblyRoot'
if ($Mode -eq 'Generate' -and -not $OutputRoot) { throw 'Generation requires an explicit output root.' }
. (Join-Path $RepositoryRoot 'certification\overlay\lib\Pspkt.Certification.OverlayActivationContract.ps1')
$contract = Get-PspktOverlayActivationContract
foreach ($path in $contract.Sha256ByPath.Keys) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $RepositoryRoot $path.Replace('/','\')) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $contract.Sha256ByPath[$path]) { throw "Pinned overlay activation hash differs: $path" }
}
if (-not $Worker) {
    if ($AssemblyRoot) { throw 'AssemblyRoot is valid only in worker mode.' }
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('pspkt-overlay-'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($scratch)
    try {
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $helperRelativePath = 'certification/overlay/lib/Pspkt.Certification.OverlayBoundedProcess.cs'
        Import-PspktOverlayBoundedProcess `
            -SourcePath (Join-Path $RepositoryRoot $helperRelativePath.Replace('/','\')) `
            -ExpectedSha256 $contract.Sha256ByPath[$helperRelativePath]
        $targetParameters = @{
            Mode = $Mode
            Worker = $true
            RepositoryRoot = $RepositoryRoot
            AssemblyRoot = $scratch
        }
        if ($OutputRoot) { $targetParameters.OutputRoot = $OutputRoot }
        $childResult = Invoke-PspktOverlayBoundedPowerShell `
            -HostPath (Join-Path $PSHOME $hostName) `
            -TargetPath $PSCommandPath `
            -TargetParameters $targetParameters `
            -WorkingDirectory $RepositoryRoot
        if ($childResult.ExitCode -ne 0) {
            throw "Overlay activation child failed with exit code $($childResult.ExitCode): $($childResult.StandardError)"
        }
    }
    finally { if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch,$true) } }
    return
}
if (-not $AssemblyRoot -or -not [IO.Directory]::Exists($AssemblyRoot) -or @(Get-ChildItem -LiteralPath $AssemblyRoot -Force).Count -ne 0) {
    throw 'A fresh assembly directory is required.'
}
$env:TEMP = $AssemblyRoot
$env:TMP = $AssemblyRoot
$frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
    @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll','System.Numerics.dll')
} else {
    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object { $_.FullName })
}
$library = Join-Path $RepositoryRoot 'certification\overlay\lib'
$bootstrap = Join-Path $AssemblyRoot 'SchemaBootstrap.dll'
$verify = Join-Path $AssemblyRoot 'OverlayActivationVerify.dll'
$engine = Join-Path $AssemblyRoot 'FoundationEngine.dll'
$authority = Join-Path $AssemblyRoot 'OverlayActivationAuthority.dll'
Push-Location -LiteralPath $AssemblyRoot
try {
    Add-Type -LiteralPath (Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.SchemaBootstrap.cs') -OutputAssembly 'SchemaBootstrap.dll' -ReferencedAssemblies $frameworkReferences
    Add-Type -LiteralPath $bootstrap
    Add-Type -LiteralPath (Join-Path $library 'Pspkt.Certification.OverlayActivationVerify.cs') -OutputAssembly 'OverlayActivationVerify.dll' -ReferencedAssemblies @($frameworkReferences+$bootstrap)
    Add-Type -LiteralPath $verify
    Add-Type -LiteralPath @(
        (Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.FoundationCatalogEngine.cs'),
        (Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.FoundationPolicy.cs')) -OutputAssembly 'FoundationEngine.dll' -ReferencedAssemblies @($frameworkReferences+$bootstrap)
    Add-Type -LiteralPath $engine
    Add-Type -LiteralPath (Join-Path $library 'Pspkt.Certification.OverlayActivationAuthority.cs') -OutputAssembly 'OverlayActivationAuthority.dll' -ReferencedAssemblies @($frameworkReferences+$bootstrap+$engine)
    Add-Type -LiteralPath $authority
}
finally { Pop-Location }
[Pspkt.Certification.Overlay.OverlayActivationVerify]::VerifyAssemblyReferences(
    [Pspkt.Certification.Overlay.OverlayActivationVerify].Assembly,
    [Pspkt.Certification.SchemaBootstrap].Assembly.FullName,
    [string[]]@([Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2].Assembly.FullName,
        [Pspkt.Certification.Overlay.OverlayActivationAuthority].Assembly.FullName))
$inventoryBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\overlay\schema\overlay-activation-inventory.v1.json'))
Assert-PspktOverlayActivationInventory $inventoryBytes
[Pspkt.Certification.Overlay.OverlayActivationVerify]::ValidateInventory($inventoryBytes)
if ($Mode -eq 'Compile') { return }
. (Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.ProtocolSchemaContract.ps1')
$parameters = Get-PspktProtocolSchemaContract
$messageEnums = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$directions = [Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::Ordinal)
$kindRanges = [Collections.Generic.Dictionary[string,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
foreach ($channel in $parameters.Channels) {
    $messageEnums.Add($channel,$parameters.MessageEnumNameByChannel[$channel])
    $directions.Add($channel,$parameters.PermittedDirectionsByChannel[$channel])
    $ranges = @($parameters.OverlayKindRangesByChannel[$channel] | ForEach-Object {
        [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new($_.Start,$_.End)
    })
    $kindRanges.Add($channel,[Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]$ranges)
}
$engineContract = [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]::new(
    $parameters.NamePredicate,$parameters.BaseCatalogSchemaId,$parameters.BaseCatalogSpace,$parameters.OverlayCatalogSchemaId,
    $parameters.OverlayCatalogSpace,$parameters.EmitSchemaId,$parameters.MapSchemaId,$parameters.Channels,$messageEnums,$directions,
    $kindRanges,[Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new($parameters.OverlayTypeRange.Start,$parameters.OverlayTypeRange.End),
    $parameters.GeneratedFieldIdMax,$parameters.LiteralExtensionParentNames)
$baseBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json'))
$overlayBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json'))
$protocolInventory = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-inventory.v1.json'))
$metaBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json'))
if (-not $OutputRoot) { $OutputRoot = $RepositoryRoot }
if ($Mode -eq 'Validate') {
    $outputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    foreach ($path in $contract.OutputPathSet) { $outputs.Add($path,[IO.File]::ReadAllBytes((Join-Path $OutputRoot $path.Replace('/','\')))) }
} else {
    $outputs = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::GenerateDeclarations($baseBytes,$overlayBytes,$engineContract)
    $schemaBytes = $outputs['certification/overlay/schema/protocol-schema.v1.json']
    $associations = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildAssociations(
        $baseBytes,$overlayBytes,$outputs['certification/overlay/schema/generated-base-id-map.v1.json'])
    $lifecycle = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::DeriveLifecycle($protocolInventory)
    $schedule = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildSchedule($schemaBytes,$associations,$lifecycle,$protocolInventory)
    $matrices = [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildMatrices(
        $baseBytes,$overlayBytes,$schemaBytes,$associations,$schedule,$lifecycle,$protocolInventory)
    $outputs.Add('certification/overlay/schema/protocol-message-association.v1.json',$associations)
    $outputs.Add('certification/overlay/schema/mandatory-tail-schedule.v1.json',$schedule)
    $outputs.Add('certification/overlay/schema/overlay-matrices.v1.json',$matrices)
    $outputs.Add('certification/overlay/schema/overlay-maxima.v1.json',
        [Pspkt.Certification.Overlay.OverlayActivationAuthority]::BuildMaxima($schemaBytes,$protocolInventory))
}
[Pspkt.Certification.Overlay.OverlayActivationVerify]::Verify($baseBytes,$overlayBytes,$protocolInventory,$inventoryBytes,$metaBytes,$outputs)
if ($Mode -eq 'Generate') {
    foreach ($path in $contract.OutputPathSet) {
        $destination = Join-Path $OutputRoot $path.Replace('/','\')
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        Write-PspktOverlayActivationFile $destination $outputs[$path]
    }
}
