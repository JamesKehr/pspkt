[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$WorkRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$PesterManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$invocationMarker = 'Pspkt.Certification.EvidenceRuntime.ValidationInvocation'
$invocationDomain = [AppDomain]::CurrentDomain
[Threading.Monitor]::Enter($invocationDomain)
try {
    if ($null -ne $invocationDomain.GetData($invocationMarker)) { throw 'invocation-repeat: A fresh host is required.' }
    $invocationClaim = [object]::new()
    $invocationDomain.SetData($invocationMarker, $invocationClaim)
}
finally { [Threading.Monitor]::Exit($invocationDomain) }
$invocationParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) { $invocationParameters[$parameterName] = $PSBoundParameters[$parameterName] }

function Assert-PspktEvidenceValidationResultShape {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Result)

    if ($null -eq $Result -or $Result -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'ResultShape: A plain result object is required.'
    }
    $outcomeProperty = $Result.PSObject.Properties['Outcome']
    if ($null -eq $outcomeProperty -or -not [string]::Equals($outcomeProperty.Name, 'Outcome', [StringComparison]::Ordinal) -or
        $outcomeProperty.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
        $outcomeProperty.Value -isnot [string] -or
        [Array]::IndexOf([string[]]@('ValidationSucceeded', 'ValidationFailed'), $outcomeProperty.Value) -lt 0) {
        throw 'ResultShape: Result outcome is missing or invalid.'
    }
    $schemas = @{
        success = @{
            SchemaId = 'text'; SchemaVersion = 'integer'; Outcome = 'text'; RunId = 'text'; BaseCommit = 'text'
            HostEdition = 'text'; HostVersion = 'text'; PesterVersion = 'text'; RepositoryRoot = 'text'
            WorkRoot = 'text'; RunRoot = 'text'; SourceManifestSha256 = 'text'; CompilationCount = 'integer'
            LoadCount = 'integer'; InitializedMutantKillCount = 'integer'; CompilationRecords = 'array-compilation'
            LoadRecords = 'array-load'; MutantResults = 'array-mutant'; Pester = 'pester'; Gates = 'gates'; Cleanup = 'cleanup'
        }
        failure = @{
            SchemaId = 'text'; SchemaVersion = 'integer'; Outcome = 'text'; RunId = 'nullable-text'
            FailurePhase = 'text'; Errors = 'array-text'; ObservedCounts = 'counts'; CleanupObservation = 'cleanup-observation'
        }
        compilation = @{
            Role = 'text'; AssemblyIdentity = 'text'; ImageSha256 = 'text'; ImageLength = 'integer'
            SourceCount = 'integer'; Sources = 'array-source'; LanguageVersion = 'text'; CompilerIdentity = 'text'
        }
        source = @{ Path = 'text'; Length = 'integer'; Sha256 = 'text' }
        load = @{ Role = 'text'; AssemblyIdentity = 'text'; ImagePath = 'text'; ImageSha256 = 'text'; Context = 'text'; Initialized = 'boolean' }
        mutant = @{ Role = 'text'; AssemblyIdentity = 'text'; Initialized = 'boolean'; OracleKilled = 'boolean'; OracleId = 'text'; Transform = 'transform' }
        transform = @{ SourcePath = 'text'; OriginalSha256 = 'text'; MutatedSha256 = 'text'; MatchCount = 'integer' }
        counts = @{ CompilationCount = 'integer'; LoadCount = 'integer'; InitializedMutantKillCount = 'integer' }
        pester = @{
            ContainerCount = 'integer'; TotalCount = 'integer'; SelectedCount = 'integer'; ExecutedCount = 'integer'; PassedCount = 'integer'
            FailedCount = 'integer'; SkippedCount = 'integer'; NotRunCount = 'integer'; FailedBlocksCount = 'integer'
            FailedContainersCount = 'integer'; Result = 'text'; TestIds = 'array-text'
        }
        gates = @{
            InputPinsPassed = 'boolean'; FixtureManifestPassed = 'boolean'; StageMapPassed = 'boolean'; ReferenceChecksPassed = 'boolean'
            PublicApiChecksPassed = 'boolean'; DocumentationParityPassed = 'boolean'; TokenAndDigestCategoryChecksPassed = 'boolean'
            OracleChecksPassed = 'boolean'; PesterCallerScopePassed = 'boolean'; RegistryDisabled = 'boolean'
            RegistryAbsent = 'boolean'; SourceOutputSeparationPassed = 'boolean'
        }
        cleanup = @{
            Completed = 'boolean'; ResiduePassed = 'boolean'; OwnedStreamsClosed = 'boolean'; TempRestored = 'boolean'; TmpRestored = 'boolean'
            PowerShellLocationRestored = 'boolean'; DotNetLocationRestored = 'boolean'; TestDriveCleanupPassed = 'boolean'
            RegistryDriveAbsent = 'boolean'; RegistryVariableAbsent = 'boolean'; RetainedArtifactsDeclared = 'boolean'
        }
        'cleanup-observation' = @{
            Completed = 'boolean'; TempRestored = 'boolean'; TmpRestored = 'boolean'; Errors = 'array-text'; RetainedArtifacts = 'array-text'
        }
    }
    $rootSchema = if ([string]::Equals($outcomeProperty.Value, 'ValidationSucceeded', [StringComparison]::Ordinal)) { 'success' } else { 'failure' }
    $pending = [Collections.Generic.List[object]]::new()
    $pending.Add([pscustomobject]@{ Value = $Result; Schema = $rootSchema })
    $visited = 0
    while ($pending.Count -gt 0) {
        $node = $pending[$pending.Count - 1]
        $pending.RemoveAt($pending.Count - 1)
        $visited++
        if ($visited -gt 4096) { throw 'ResultShape: Result graph exceeds its bound.' }
        $value = $node.Value
        $schema = [string]$node.Schema
        if ($schema -ceq 'nullable-text' -and $null -eq $value) { continue }
        if ($schema -ceq 'text' -or $schema -ceq 'nullable-text') {
            if ($value -isnot [string] -or $value.Length -eq 0 -or $value.Length -gt 4096) { throw 'ResultShape: A bounded string is required.' }
        }
        elseif ($schema -ceq 'integer') {
            $integral = $value -is [byte] -or $value -is [sbyte] -or $value -is [int16] -or $value -is [uint16] -or
                $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64]
            if (-not $integral -or $value -lt 0) { throw 'ResultShape: Counts must be nonnegative integral numbers.' }
        }
        elseif ($schema -ceq 'boolean') {
            if ($value -isnot [bool]) { throw 'ResultShape: A Boolean is required.' }
        }
        elseif ($schema.StartsWith('array-', [StringComparison]::Ordinal)) {
            if ($value -isnot [array] -or $value.Rank -ne 1 -or $value.Length -gt 1024) { throw 'ResultShape: A bounded array is required.' }
            foreach ($item in $value) { $pending.Add([pscustomobject]@{ Value = $item; Schema = $schema.Substring(6) }) }
        }
        else {
            if ($value -isnot [System.Management.Automation.PSCustomObject] -or -not $schemas.ContainsKey($schema)) {
                throw 'ResultShape: A closed plain-data record is required.'
            }
            $properties = @($value.PSObject.Properties)
            $fields = $schemas[$schema]
            if ($properties.Count -ne $fields.Count) { throw 'ResultShape: Record fields differ.' }
            foreach ($property in $properties) {
                if ($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
                    [Array]::IndexOf([string[]]@($fields.Keys), $property.Name) -lt 0) {
                    throw 'ResultShape: Executable or unexpected record member.'
                }
                $pending.Add([pscustomobject]@{ Value = $property.Value; Schema = $fields[$property.Name] })
            }
        }
    }
    if (-not [string]::Equals($Result.SchemaId, 'PspktEvidenceRuntimeValidationResultV1', [StringComparison]::Ordinal) -or $Result.SchemaVersion -ne 1) {
        throw 'ResultShape: Unsupported result schema.'
    }
    if ([string]::Equals($Result.Outcome, 'ValidationFailed', [StringComparison]::Ordinal) -and $Result.Errors.Count -eq 0) {
        throw 'ResultShape: A failed result requires diagnostics.'
    }
}

function Assert-PspktEvidenceValidationSuccess {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$CapturedResults,
        [Parameter(Mandatory = $true)][object]$Expected
    )

    if ($null -eq $CapturedResults -or $CapturedResults.Count -ne 1) { throw 'ResultCardinality: Exactly one result is required.' }
    $result = $CapturedResults[0]
    Assert-PspktEvidenceValidationResultShape -Result $result
    if ([string]::Equals($result.Outcome, 'ValidationFailed', [StringComparison]::Ordinal)) { throw 'ValidationFailedOutcome: The validation operation failed.' }
    foreach ($property in $Expected.Identity.PSObject.Properties) {
        if (-not [string]::Equals($result.PSObject.Properties[$property.Name].Value, $property.Value, [StringComparison]::Ordinal)) {
            throw 'ResultPostconditions: Result identity differs from the invocation.'
        }
    }
    foreach ($property in $Expected.SuccessCounts.PSObject.Properties) {
        $actual = if ($property.Name -in @('CompilationCount', 'LoadCount', 'InitializedMutantKillCount')) {
            $result.PSObject.Properties[$property.Name].Value
        } else { $result.Pester.PSObject.Properties[$property.Name].Value }
        if ($actual -ne $property.Value) { throw 'ResultCounts: An exact required count differs.' }
    }
    if ($result.CompilationRecords.Count -ne 5 -or $result.LoadRecords.Count -ne 5 -or $result.MutantResults.Count -ne 3 -or
        $result.CompilationCount -ne $result.CompilationRecords.Count -or $result.LoadCount -ne $result.LoadRecords.Count) {
        throw 'ResultCounts: Actual record populations differ.'
    }
    $initializedKills = 0
    foreach ($mutant in $result.MutantResults) { if ($mutant.Initialized -and $mutant.OracleKilled) { $initializedKills++ } }
    if ($initializedKills -ne 3 -or $result.InitializedMutantKillCount -ne $initializedKills) { throw 'ResultCounts: Three actual initialized mutant kills are required.' }
    if (-not [string]::Equals(($result.CompilationRecords.Role -join ','), 'Bootstrap,Runtime,M1,M2,M3', [StringComparison]::Ordinal) -or
        -not [string]::Equals(($result.LoadRecords.Role -join ','), 'Bootstrap,Runtime,M1,M2,M3', [StringComparison]::Ordinal) -or
        -not [string]::Equals(($result.MutantResults.Role -join ','), 'M1,M2,M3', [StringComparison]::Ordinal) -or
        -not [string]::Equals($result.Pester.Result, 'Passed', [StringComparison]::Ordinal) -or
        $result.Pester.TestIds.Count -ne 32 -or $Expected.TestIds.Count -ne 32) {
        throw 'ResultPostconditions: Exact role or test identities differ.'
    }
    for ($index = 0; $index -lt 32; $index++) {
        if (-not [string]::Equals($result.Pester.TestIds[$index], $Expected.TestIds[$index], [StringComparison]::Ordinal)) {
            throw 'ResultPostconditions: Exact test identity or order differs.'
        }
    }
    foreach ($name in $Expected.SuccessGates) {
        if ($result.Gates.PSObject.Properties[$name].Value -ne $true) { throw 'ResultPostconditions: A validation gate did not pass.' }
    }
    foreach ($name in $Expected.CleanupGates) {
        if ($result.Cleanup.PSObject.Properties[$name].Value -ne $true) { throw 'ResultPostconditions: Cleanup did not pass.' }
    }
    $pending = [Collections.Generic.List[object]]::new()
    foreach ($name in @('CompilationRecords', 'LoadRecords', 'MutantResults')) {
        $pending.Add([pscustomobject]@{ Actual = $result.PSObject.Properties[$name].Value; Expected = $Expected.PSObject.Properties[$name].Value })
    }
    while ($pending.Count -gt 0) {
        $pair = $pending[$pending.Count - 1]
        $pending.RemoveAt($pending.Count - 1)
        $actual = $pair.Actual
        $expectedValue = $pair.Expected
        if ($actual -is [array]) {
            if ($expectedValue -isnot [array] -or $actual.Length -ne $expectedValue.Length) { throw 'ResultPostconditions: Census arrays differ.' }
            for ($index = 0; $index -lt $actual.Length; $index++) {
                $pending.Add([pscustomobject]@{ Actual = $actual[$index]; Expected = $expectedValue[$index] })
            }
        }
        elseif ($actual -is [System.Management.Automation.PSCustomObject]) {
            if ($expectedValue -isnot [System.Management.Automation.PSCustomObject] -or
                @($actual.PSObject.Properties).Count -ne @($expectedValue.PSObject.Properties).Count) {
                throw 'ResultPostconditions: Census records differ.'
            }
            foreach ($property in $actual.PSObject.Properties) {
                $other = $expectedValue.PSObject.Properties[$property.Name]
                if ($null -eq $other -or -not [string]::Equals($other.Name, $property.Name, [StringComparison]::Ordinal)) { throw 'ResultPostconditions: Census fields differ.' }
                $pending.Add([pscustomobject]@{ Actual = $property.Value; Expected = $other.Value })
            }
        }
        elseif ($actual -is [string]) {
            if ($expectedValue -isnot [string] -or -not [string]::Equals($actual, $expectedValue, [StringComparison]::Ordinal)) {
                throw 'ResultPostconditions: Census binding differs.'
            }
        }
        elseif ($actual -is [bool]) {
            if ($expectedValue -isnot [bool] -or $actual -ne $expectedValue) { throw 'ResultPostconditions: Census Boolean differs.' }
        }
        elseif ([decimal]$actual -ne [decimal]$expectedValue) { throw 'ResultPostconditions: Census number differs.' }
    }
}

function Complete-PspktEvidenceValidationInvocation {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$CapturedResults,
        [Parameter(Mandatory = $true)][object]$Expected
    )

    if ($null -eq $CapturedResults -or $CapturedResults.Count -ne 1) { throw 'ResultCardinality: Exactly one result is required.' }
    $result = $CapturedResults[0]
    Assert-PspktEvidenceValidationResultShape -Result $result
    if ([string]::Equals($result.Outcome, 'ValidationFailed', [StringComparison]::Ordinal)) {
        $result
        throw 'ValidationFailedOutcome: The validation operation failed.'
    }
    Assert-PspktEvidenceValidationSuccess -CapturedResults $CapturedResults -Expected $Expected
    $result
}

function Get-PspktEvidenceCompilerContext {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    $analysisAssembly = $null
    $csharpAssembly = $null
    $providerType = $null
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $systemAssembly = [Reflection.Assembly]::Load('System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
        $providerType = $systemAssembly.GetType('Microsoft.CSharp.CSharpCodeProvider', $true)
        $frameworkRoot = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
        $paths = @('mscorlib.dll', 'System.dll', 'System.Core.dll', 'System.Xml.dll', 'System.Xml.Linq.dll', 'System.Runtime.Serialization.dll', 'System.Numerics.dll') |
            ForEach-Object { Join-Path $frameworkRoot $_ }
        $compilerIdentity = $systemAssembly.FullName
    }
    else {
        $analysisAssembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath((Join-Path $PSHOME 'Microsoft.CodeAnalysis.dll'))
        $csharpAssembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath((Join-Path $PSHOME 'Microsoft.CodeAnalysis.CSharp.dll'))
        $paths = @([IO.Directory]::GetFiles((Join-Path $PSHOME 'ref'), '*.dll') | Sort-Object)
        $compilerIdentity = $csharpAssembly.FullName
    }
    $references = @()
    foreach ($path in $paths) {
        $identity = [Reflection.AssemblyName]::GetAssemblyName($path)
        $token = $identity.GetPublicKeyToken()
        if ($null -eq $token -or $token.Length -ne 8) { throw 'toolchain-reference: An input lacks an eight-byte public key token.' }
        $bytes = [IO.File]::ReadAllBytes($path)
        $references += [pscustomobject]@{
            Path = $path
            Identity = $identity
            Key = $identity.Name + ':' + [BitConverter]::ToString($token).Replace('-', '').ToLowerInvariant()
            Culture = $identity.CultureName
            Version = $identity.Version.ToString()
            Bytes = $bytes
            Length = $bytes.Length
            Sha256 = Get-PspktEvidenceBytesDigest -Bytes $bytes
        }
    }
    [pscustomobject]@{
        Edition = $PSVersionTable.PSEdition
        CompilerIdentity = $compilerIdentity
        FrameworkReferences = $references
        AnalysisAssembly = $analysisAssembly
        CSharpAssembly = $csharpAssembly
        ProviderType = $providerType
    }
}

function New-PspktEvidenceAssemblyImage {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$ArtifactRoot,
        [Parameter(Mandatory = $true)][string[]]$Sources,
        [Parameter(Mandatory = $true)][string[]]$SourceNames,
        [Parameter(Mandatory = $true)][object]$Context,
        [object]$BootstrapImage
    )

    if (@('Bootstrap', 'Runtime', 'M1', 'M2', 'M3') -cnotcontains $Role -or $Sources.Count -ne $SourceNames.Count) {
        throw 'compilation-role: Source or role census differs.'
    }
    $expectedCount = if ($Role -ceq 'Bootstrap') { 1 } else { 7 }
    if ($Sources.Count -ne $expectedCount) { throw 'compilation-source: Retained source count differs.' }
    [string]$simpleName = if ($Role -ceq 'Bootstrap') { 'PspktEvidenceBootstrap_' + $RunId } else { 'PspktEvidenceRuntime_' + $RunId }
    if ($Role -in @('M1', 'M2', 'M3')) { $simpleName += '_' + $Role }
    $path = Join-Path $ArtifactRoot ($simpleName + '.dll')
    if ([IO.File]::Exists($path)) { throw 'image-collision: Output already exists.' }
    if ($Role -cne 'Bootstrap' -and $null -eq $BootstrapImage) { throw 'bootstrap-reference: The admitted dependency image is required.' }
    $imageBytes = $null
    if ($Context.Edition -ceq 'Desktop') {
        $stageRoot = Join-Path $ArtifactRoot ($Role + '-compiler')
        if ([IO.Directory]::Exists($stageRoot)) { throw 'compiler-collision: Staging directory already exists.' }
        [void][IO.Directory]::CreateDirectory($stageRoot)
        $stagePath = Join-Path $stageRoot ($simpleName + '.dll')
        $provider = [Activator]::CreateInstance($Context.ProviderType)
        $parameters = [CodeDom.Compiler.CompilerParameters]::new()
        $parameters.GenerateExecutable = $false
        $parameters.GenerateInMemory = $false
        $parameters.IncludeDebugInformation = $false
        $parameters.CompilerOptions = '/langversion:5 /optimize+'
        $parameters.OutputAssembly = $stagePath
        $parameters.TempFiles = [CodeDom.Compiler.TempFileCollection]::new($stageRoot, $false)
        foreach ($reference in $Context.FrameworkReferences) { [void]$parameters.ReferencedAssemblies.Add($reference.Path) }
        if ($null -ne $BootstrapImage) { [void]$parameters.ReferencedAssemblies.Add($BootstrapImage.ImagePath) }
        try {
            $compilation = $provider.CompileAssemblyFromSource($parameters, [string[]]$Sources)
            $errors = @($compilation.Errors | Where-Object { -not $_.IsWarning })
            if ($errors.Count -ne 0) { throw ('compilation-failed: ' + ($errors.ErrorText -join '; ')) }
            $imageBytes = [IO.File]::ReadAllBytes($stagePath)
        }
        finally {
            $parameters.TempFiles.Delete()
            $provider.Dispose()
            if ([IO.File]::Exists($stagePath)) { [IO.File]::Delete($stagePath) }
            if ([IO.Directory]::GetFileSystemEntries($stageRoot).Length -ne 0) { throw 'compiler-residue: Unowned staging entries remain.' }
            [IO.Directory]::Delete($stageRoot)
        }
    }
    else {
        $analysis = $Context.AnalysisAssembly
        $csharp = $Context.CSharpAssembly
        $syntaxType = $analysis.GetType('Microsoft.CodeAnalysis.SyntaxTree', $true)
        $metadataType = $analysis.GetType('Microsoft.CodeAnalysis.MetadataReference', $true)
        $parseOptionsType = $csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpParseOptions', $true)
        $languageType = $csharp.GetType('Microsoft.CodeAnalysis.CSharp.LanguageVersion', $true)
        $documentationType = $analysis.GetType('Microsoft.CodeAnalysis.DocumentationMode', $true)
        $sourceKindType = $analysis.GetType('Microsoft.CodeAnalysis.SourceCodeKind', $true)
        $parseConstructor = @($parseOptionsType.GetConstructors() | Where-Object { $_.GetParameters().Length -eq 4 })[0]
        $parseOptions = $parseConstructor.Invoke([object[]]@(
            [Enum]::Parse($languageType, 'CSharp5'),
            [Enum]::Parse($documentationType, 'Parse'),
            [Enum]::Parse($sourceKindType, 'Regular'), $null))
        $parseMethod = @($csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree', $true).GetMethods() |
            Where-Object { $_.Name -ceq 'ParseText' -and $_.GetParameters().Length -eq 5 -and $_.GetParameters()[0].ParameterType -eq [string] })[0]
        $trees = [Array]::CreateInstance($syntaxType, $Sources.Count)
        for ($index = 0; $index -lt $Sources.Count; $index++) {
            $tree = $parseMethod.Invoke($null, [object[]]@([string]$Sources[$index], $parseOptions, [string]$SourceNames[$index],
                [Text.UTF8Encoding]::new($false, $true), [Threading.CancellationToken]::None))
            $trees.SetValue($tree, $index)
        }
        $referenceInputs = @($Context.FrameworkReferences)
        if ($null -ne $BootstrapImage) {
            $referenceInputs += [pscustomobject]@{ Bytes = $BootstrapImage.ImageBytes; Path = $BootstrapImage.ImagePath }
        }
        $references = [Array]::CreateInstance($metadataType, $referenceInputs.Count)
        $metadataProperties = [Activator]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.MetadataReferenceProperties', $true))
        $referenceMethod = @($metadataType.GetMethods() | Where-Object {
            $_.Name -ceq 'CreateFromImage' -and $_.GetParameters().Length -eq 4 -and
                $_.GetParameters()[0].ParameterType.Name -ceq 'IEnumerable`1'
        })[0]
        for ($index = 0; $index -lt $referenceInputs.Count; $index++) {
            $reference = $referenceMethod.Invoke($null, [object[]]@(
                $referenceInputs[$index].Bytes, $metadataProperties, $null, [string]$referenceInputs[$index].Path))
            $references.SetValue($reference, $index)
        }
        $optionsType = $csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions', $true)
        $optionsConstructor = @($optionsType.GetConstructors() | Where-Object {
            @($_.GetParameters() | Where-Object { -not $_.IsOptional }).Count -eq 1
        })[0]
        $optionParameters = $optionsConstructor.GetParameters()
        $optionArguments = [object[]]::new($optionParameters.Length)
        for ($index = 0; $index -lt $optionParameters.Length; $index++) { $optionArguments[$index] = $optionParameters[$index].DefaultValue }
        $optionArguments[0] = [Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.OutputKind', $true), 'DynamicallyLinkedLibrary')
        $options = $optionsConstructor.Invoke($optionArguments)
        $compilationType = $csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpCompilation', $true)
        $createMethod = @($compilationType.GetMethods() | Where-Object { $_.Name -ceq 'Create' -and $_.IsStatic -and $_.GetParameters().Length -eq 4 })[0]
        $compilation = $createMethod.Invoke($null, [object[]]@([string]$simpleName, $trees, $references, $options))
        $emitMethod = @($compilationType.GetMethods() | Where-Object { $_.Name -ceq 'Emit' -and $_.GetParameters().Length -eq 7 })[0]
        $imageStream = [IO.MemoryStream]::new()
        try {
            $emission = $emitMethod.Invoke($compilation, [object[]]@(
                $imageStream, $null, $null, $null, $null, $null, [Threading.CancellationToken]::None))
            if (-not $emission.Success) { throw ('compilation-failed: ' + (($emission.Diagnostics | ForEach-Object { $_.ToString() }) -join '; ')) }
            $imageBytes = $imageStream.ToArray()
        }
        finally { $imageStream.Dispose() }
    }
    if ($null -eq $imageBytes -or $imageBytes.Length -eq 0 -or $imageBytes.Length -gt 16777216) {
        throw 'image-length: Emitted image is outside the admitted bound.'
    }
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($imageBytes, 0, $imageBytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    $identity = [Reflection.AssemblyName]::GetAssemblyName($path)
    $expectedIdentity = $simpleName + ', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'
    if ($identity.FullName -cne $expectedIdentity) { throw 'image-identity: Emitted assembly identity differs.' }
    $retainedImage = [IO.File]::ReadAllBytes($path)
    $digest = Get-PspktEvidenceBytesDigest -Bytes $imageBytes
    if ($retainedImage.Length -ne $imageBytes.Length -or (Get-PspktEvidenceBytesDigest -Bytes $retainedImage) -cne $digest) {
        throw 'image-custody: Published image bytes differ.'
    }
    $sourceRecords = @()
    for ($index = 0; $index -lt $Sources.Count; $index++) {
        $sourceBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Sources[$index])
        $sourceRecords += [pscustomobject]@{ Path = $SourceNames[$index]; Length = $sourceBytes.Length; Sha256 = Get-PspktEvidenceBytesDigest -Bytes $sourceBytes }
    }
    [pscustomobject]@{
        Role = $Role
        ImagePath = $path
        ImageIdentity = $identity.FullName
        ImageLength = $imageBytes.Length
        ImageSha256 = $digest
        ImageBytes = $retainedImage
        SourceCount = $Sources.Count
        Sources = $sourceRecords
        LanguageVersion = 'CSharp5'
        CompilerIdentity = $Context.CompilerIdentity
        LoadAttempted = $false
    }
}

function Import-PspktEvidenceAssemblyImage {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Image,
        [Parameter(Mandatory = $true)][object]$Context
    )

    $Image.LoadAttempted = $true
    if ($Context.Edition -ceq 'Desktop') { $assembly = [Reflection.Assembly]::LoadFrom($Image.ImagePath) }
    else { $assembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($Image.ImagePath) }
    if ($assembly.FullName -cne $Image.ImageIdentity -or -not [string]::Equals(
        $assembly.Location, $Image.ImagePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'assembly-load: Loaded identity or location differs.'
    }
    return $assembly
}

function Assert-PspktEvidenceLoadedAssembly {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][Reflection.Assembly]$Assembly,
        [Parameter(Mandatory = $true)][object]$Image,
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$BootstrapIdentity
    )

    if ($Assembly.FullName -cne $Image.ImageIdentity -or -not [string]::Equals(
        $Assembly.Location, $Image.ImagePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'assembly-custody: Loaded assembly differs from its admitted image.'
    }
    if (@([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -ceq $Assembly.FullName }).Count -ne 1) {
        throw 'assembly-census: Loaded full identity is not unique.'
    }
    if ($Context.Edition -ceq 'Core' -and -not [object]::ReferenceEquals(
        [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($Assembly), [System.Runtime.Loader.AssemblyLoadContext]::Default)) {
        throw 'assembly-context: Runtime image is not in the default context.'
    }
    $bootstrapReferences = 0
    foreach ($reference in $Assembly.GetReferencedAssemblies()) {
        Assert-PspktEvidenceAssemblyReference -Reference $reference -FrameworkReferences @($Context.FrameworkReferences.Identity) -BootstrapIdentity $BootstrapIdentity
        if ($reference.FullName -ceq $BootstrapIdentity) { $bootstrapReferences++ }
    }
    $expectedBootstrapReferences = if ($Image.Role -ceq 'Bootstrap') { 0 } else { 1 }
    if ($bootstrapReferences -ne $expectedBootstrapReferences) { throw 'bootstrap-reference: Emitted dependency identity differs.' }
    if ($Image.Role -ceq 'Bootstrap') { Assert-PspktEvidenceBootstrapExports -Assembly $Assembly }
}

function Invoke-PspktEvidenceMutantOracles {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$ArtifactRoot,
        [Parameter(Mandatory = $true)][string[]]$Sources,
        [Parameter(Mandatory = $true)][string[]]$SourceNames,
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][hashtable]$CompilationRecords,
        [Parameter(Mandatory = $true)][Reflection.Assembly]$BootstrapAssembly,
        [Parameter(Mandatory = $true)][Reflection.Assembly]$RuntimeAssembly,
        [Parameter(Mandatory = $true)][hashtable]$AuthorityBytes,
        [Parameter(Mandatory = $true)][hashtable]$FixtureBytes
    )

    $burn = $FixtureBytes['operation-burn-receipt-profile1']
    $receipt = $FixtureBytes['local-evidence-receipt-coverage']
    if ((Get-PspktEvidenceBytesDigest -Bytes $burn) -cne '5fca724f829c7a575f105efeea19ddf0f1fe581467fa149753444733b136b500' -or
        (Get-PspktEvidenceBytesDigest -Bytes $receipt) -cne '9a1b91246ca4d1b277cee94da1ca2b68fd251df14fd9b33706ec3b28343ef31e') {
        throw 'oracle-pin: Protected hand-authored bytes differ.'
    }
    $burnPayload = [byte[]]$burn[47..244]
    $coverage = [byte[]]([Text.Encoding]::ASCII.GetBytes('pspkt/evidence/v1/LocalEvidenceReceiptV1') + @(0) + $receipt[47..300])
    $factoryArguments = [object[]]@($AuthorityBytes.meta, $AuthorityBytes.protocolInventory,
        $AuthorityBytes.evidenceSchema, $AuthorityBytes.evidenceInventory)
    $codecTypeName = 'Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec'
    $runtimeType = $RuntimeAssembly.GetType($codecTypeName, $true)
    $runtimeCodec = $runtimeType.GetMethod('CreateFromCommittedAuthorities').Invoke($null, $factoryArguments)
    Assert-PspktEvidenceLoadedAssembly -Assembly $RuntimeAssembly -Image $CompilationRecords.Runtime -Context $Context -BootstrapIdentity $BootstrapAssembly.FullName
    $encodeArguments = [object[]]@([uint16]18, [Guid]'fedcba98-7654-3210-fedc-ba9876543210', [byte]1, $burnPayload)
    $controlEncoded = $runtimeType.GetMethod('Encode').Invoke($runtimeCodec, $encodeArguments)
    $controlCovered = $runtimeType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($runtimeCodec, [object[]]@(,$receipt))
    if ([Convert]::ToBase64String($controlEncoded) -cne [Convert]::ToBase64String($burn) -or
        [Convert]::ToBase64String($controlCovered) -cne [Convert]::ToBase64String($coverage)) {
        throw 'oracle-control: Canonical runtime fails an independent positive control.'
    }
    foreach ($role in @('M1', 'M2', 'M3')) {
        $mutantInput = Get-PspktEvidenceMutantSources -Role $role -Sources $Sources -SourceNames $SourceNames
        $image = New-PspktEvidenceAssemblyImage -Role $role -RunId $RunId -ArtifactRoot $ArtifactRoot `
            -Sources $mutantInput.Sources -SourceNames $SourceNames -Context $Context -BootstrapImage $CompilationRecords.Bootstrap
        $CompilationRecords[$role] = $image
        $assembly = Import-PspktEvidenceAssemblyImage -Image $image -Context $Context
        $exports = @($assembly.GetExportedTypes() | Sort-Object FullName)
        if (($exports.FullName -join ',') -cne 'Pspkt.Certification.EvidenceRuntime.DecodedEvidenceArtifactEnvelope,Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec') {
            throw 'mutant-api: Mutant exports differ.'
        }
        foreach ($export in $exports) {
            $canonical = $RuntimeAssembly.GetType($export.FullName, $true)
            $methods = @($export.GetMethods([Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly') | ForEach-Object { $_.ToString() } | Sort-Object)
            $canonicalMethods = @($canonical.GetMethods([Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly') | ForEach-Object { $_.ToString() } | Sort-Object)
            if (-not $export.IsSealed -or $export.GetConstructors().Length -ne 0 -or ($methods -join '|') -cne ($canonicalMethods -join '|')) {
                throw 'mutant-api: Mutant public signatures differ.'
            }
        }
        $mutantType = $assembly.GetType($codecTypeName, $true)
        $mutant = $mutantType.GetMethod('CreateFromCommittedAuthorities').Invoke($null, $factoryArguments)
        if (-not [object]::ReferenceEquals($mutant.GetType().Assembly, $assembly)) { throw 'mutant-identity: Factory initialized the wrong assembly.' }
        Assert-PspktEvidenceLoadedAssembly -Assembly $assembly -Image $image -Context $Context -BootstrapIdentity $BootstrapAssembly.FullName
        if ($role -ceq 'M3') {
            $actual = $mutantType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($mutant, [object[]]@(,$receipt))
            $killed = $actual.Length -eq $coverage.Length + 390 -and
                [Convert]::ToBase64String([byte[]]$actual[0..($coverage.Length - 1)]) -ceq [Convert]::ToBase64String($coverage)
        }
        else {
            $actual = $mutantType.GetMethod('Encode').Invoke($mutant, $encodeArguments)
            if ($role -ceq 'M1') {
                $killed = $actual.Length -eq $burn.Length -and $actual[2] -eq 2 -and
                    [Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($burn)
            }
            else {
                $killed = $actual.Length -eq $burn.Length -and
                    [Convert]::ToBase64String([byte[]]$actual[0..250]) -ceq [Convert]::ToBase64String([byte[]]$burn[0..250]) -and
                    [Convert]::ToBase64String([byte[]]$actual[251..282]) -cne [Convert]::ToBase64String([byte[]]$burn[251..282])
            }
        }
        if (-not $killed) { throw ('mutant-survived: Independent oracle did not kill ' + $role + '.') }
        [pscustomobject]@{
            Role = $role
            Assembly = $assembly
            Image = $image
            Initialized = $true
            OracleKilled = $true
            OracleId = $mutantInput.OracleId
            Transform = $mutantInput.Transform
        }
    }
}

function Invoke-PspktPhase4EvidenceRuntimeValidators {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$WorkRoot,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$PesterManifestPath
    )

    $contextVariable = Get-Variable -Name PspktEvidenceInvocationContext -ErrorAction SilentlyContinue
    $context = if ($null -eq $contextVariable) {
        New-PspktEvidenceInvocationContext -RepositoryRoot $RepositoryRoot -WorkRoot $WorkRoot -PesterManifestPath $PesterManifestPath
    } else { $contextVariable.Value }
    if ($context.Consumed -or $context.Disposed -or $context.RunId -isnot [string] -or $context.RunId -cnotmatch '^[0-9a-f]{32}$' -or
        -not [string]::Equals($context.RunRoot, (Join-Path $context.WorkRoot ('evidence-runtime-' + $context.RunId)), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($context.RepositoryRoot, (ConvertTo-PspktEvidenceDirectoryPath -Path $RepositoryRoot), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($context.WorkRoot, (ConvertTo-PspktEvidenceDirectoryPath -Path $WorkRoot), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($context.PesterManifestPath, [IO.Path]::GetFullPath($PesterManifestPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'invocation-context: Private one-call context does not match the invocation.'
    }
    if (-not [object]::ReferenceEquals($invocationDomain.GetData($invocationMarker), $invocationClaim)) {
        throw 'invocation-repeat: A fresh host is required.'
    }
    $context.Consumed = $true
    $contract = Get-PspktEvidenceRuntimeContract
    $previousTemp = [Environment]::GetEnvironmentVariable('TEMP', 'Process')
    $previousTmp = [Environment]::GetEnvironmentVariable('TMP', 'Process')
    $previousLocation = (Get-Location).Path
    $previousDotNetLocation = [Environment]::CurrentDirectory
    $compilations = @{}
    $mutantBuilds = @()
    $operationError = $null
    $cleanupErrors = [Collections.Generic.List[Exception]]::new()
    $runCreated = $false
    $cleanupFields = [ordered]@{}
    foreach ($name in $contract.CleanupGates) { $cleanupFields[$name] = $false }
    $cleanup = [pscustomobject]$cleanupFields
    $pesterRecord = $null
    $pester = $null
    $compilerContext = $null
    $bootstrapAssembly = $null
    $runtimeAssembly = $null
    try {
        $runnerTemp = if ($env:GITHUB_ACTIONS -ceq 'true') { $env:RUNNER_TEMP } else { '' }
        Assert-PspktEvidenceRootRelationships -RepositoryRoot $context.RepositoryRoot -WorkRoot $context.WorkRoot `
            -OriginalWorkspace $env:GITHUB_WORKSPACE -RunnerTemp $runnerTemp
        Assert-PspktEvidencePhysicalDirectory -Path $context.RepositoryRoot
        Assert-PspktEvidencePhysicalDirectory -Path $context.WorkRoot
        Assert-PspktEvidenceRegistryAbsent
        if (@(Get-PSDrive -Name TestDrive -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'test-storage: A preexisting TestDrive is not owned by this invocation.'
        }
        Assert-PspktEvidenceCleanHost -Assemblies ([AppDomain]::CurrentDomain.GetAssemblies())
        Assert-PspktEvidenceSourceClosure -Snapshot $context.Snapshot
        $inputData = Get-PspktEvidenceRetainedInputData -Snapshot $context.Snapshot
        Assert-PspktEvidenceGeneratorIsolation -SourceText $inputData.GeneratorText
        Assert-PspktEvidenceWorkflow -SourceText $inputData.WorkflowText
        if ([IO.Directory]::Exists($context.RunRoot) -or [IO.File]::Exists($context.RunRoot)) {
            throw 'work-root: Run directory is no longer fresh.'
        }
        [void][IO.Directory]::CreateDirectory($context.RunRoot)
        $runCreated = $true
        Assert-PspktEvidencePhysicalDirectory -Path $context.RunRoot
        if ([IO.Directory]::GetFileSystemEntries($context.RunRoot).Length -ne 0) { throw 'work-root: Run directory is not empty.' }
        [Environment]::SetEnvironmentVariable('TEMP', $context.RunRoot, 'Process')
        [Environment]::SetEnvironmentVariable('TMP', $context.RunRoot, 'Process')
        if (-not [string]::Equals([IO.Path]::GetTempPath().TrimEnd('\'), $context.RunRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'work-root: Effective temporary path differs from the owned run directory.'
        }
        $compilerContext = Get-PspktEvidenceCompilerContext
        $compilations.Bootstrap = New-PspktEvidenceAssemblyImage -Role Bootstrap -RunId $context.RunId -ArtifactRoot $context.RunRoot `
            -Sources @($inputData.BootstrapText) -SourceNames @('certification\lib\Pspkt.Certification.SchemaBootstrap.cs') -Context $compilerContext
        $compilations.Runtime = New-PspktEvidenceAssemblyImage -Role Runtime -RunId $context.RunId -ArtifactRoot $context.RunRoot `
            -Sources $inputData.RuntimeTexts -SourceNames $contract.RuntimeSourceNames -Context $compilerContext -BootstrapImage $compilations.Bootstrap
        $bootstrapAssembly = Import-PspktEvidenceAssemblyImage -Image $compilations.Bootstrap -Context $compilerContext
        $runtimeAssembly = Import-PspktEvidenceAssemblyImage -Image $compilations.Runtime -Context $compilerContext
        $factory = $runtimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec', $true).GetMethod('CreateFromCommittedAuthorities')
        $codec = $factory.Invoke($null, [object[]]@($inputData.AuthorityBytes.meta, $inputData.AuthorityBytes.protocolInventory,
            $inputData.AuthorityBytes.evidenceSchema, $inputData.AuthorityBytes.evidenceInventory))
        Assert-PspktEvidenceLoadedAssembly -Assembly $bootstrapAssembly -Image $compilations.Bootstrap -Context $compilerContext -BootstrapIdentity $bootstrapAssembly.FullName
        Assert-PspktEvidenceLoadedAssembly -Assembly $runtimeAssembly -Image $compilations.Runtime -Context $compilerContext -BootstrapIdentity $bootstrapAssembly.FullName
        Assert-PspktEvidenceDocumentation -Text $inputData.DocumentationText -RuntimeAssembly $runtimeAssembly
        $mutantBuilds = @(Invoke-PspktEvidenceMutantOracles -RunId $context.RunId -ArtifactRoot $context.RunRoot `
            -Sources $inputData.RuntimeTexts -SourceNames $contract.RuntimeSourceNames -Context $compilerContext -CompilationRecords $compilations `
            -BootstrapAssembly $bootstrapAssembly -RuntimeAssembly $runtimeAssembly -AuthorityBytes $inputData.AuthorityBytes -FixtureBytes $inputData.FixtureBytes)
        $existingPester = @(Get-Module Pester)
        if ($existingPester.Count -gt 1 -or ($existingPester.Count -eq 1 -and $existingPester[0].Version -ne [version]'5.3.3')) {
            throw 'pester-version: A conflicting Pester module is loaded.'
        }
        $pesterModule = @(Import-Module -Name $context.PesterManifestPath -PassThru -ErrorAction Stop)
        if ($pesterModule.Count -ne 1 -or $pesterModule[0].Name -cne 'Pester' -or $pesterModule[0].Version -ne [version]'5.3.3' -or
            -not [string]::Equals($pesterModule[0].ModuleBase, [IO.Path]::GetDirectoryName($context.PesterManifestPath), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'pester-version: The explicit Pester 5.3.3 manifest was not loaded.'
        }
        $testWrapper = Get-PspktEvidenceTestWrapper -OriginalBytes $inputData.TestBytes
        . $testWrapper.FixtureDefinition
        $testBlock = & $testWrapper.Factory
        if ($null -ne $testBlock.Module -or $null -ne $ExecutionContext.SessionState.Module) {
            throw 'caller-scope: Tests must be bound in a plain caller scope.'
        }
        $compileCensus = @($contract.AssemblyRoles | ForEach-Object { $compilations[$_] })
        $manifestRecords = @{
            RepositoryRoot = $context.RepositoryRoot; SourceSnapshot = $context.Snapshot; SourceTexts = $inputData.SourceTexts
            ValidatorText = $inputData.ValidatorText; FixtureRecords = $inputData.FixtureRecords; DocumentationText = $inputData.DocumentationText
            CompilerContext = $compilerContext; CompilationRecords = $compilations; TestWrapper = $testWrapper
            BeforeAllCallerScopePassed = $false; GeneratorText = $inputData.GeneratorText; WorkflowText = $inputData.WorkflowText
        }
        $testData = @{
            BootstrapAssembly = $bootstrapAssembly; RuntimeAssembly = $runtimeAssembly
            AuthorityBytesById = $inputData.AuthorityBytes; FixtureBytesById = $inputData.FixtureBytes
            ManifestRecordsByRole = $manifestRecords; CompileCensus = $compileCensus; MutantBuilds = $mutantBuilds
            ArtifactRoot = $context.RunRoot; CallerScopeMarker = 'pspkt-evidence-validation:' + $context.RunId
        }
        $manifestRecords.ExpectedData = $testData
        $container = New-PesterContainer -ScriptBlock $testBlock -Data $testData
        $manifestRecords.PesterContainer = $container
        $configuration = New-PspktEvidencePesterConfiguration -Container $container
        Assert-PspktEvidencePesterConfiguration -Configuration $configuration
        Assert-PspktEvidenceRegistryAbsent
        $pester = Invoke-Pester -Configuration $configuration
        $testIds = @()
        if (@($pester.Tests).Count -ne 32) { throw 'pester-result: Actual test population differs.' }
        for ($index = 0; $index -lt 32; $index++) {
            if ($pester.Tests[$index].ExpandedName -cne $contract.RequiredPesterTests[$index].Name -or
                $pester.Tests[$index].ExpandedPath -cne ('Evidence runtime conformance.' + $contract.RequiredPesterTests[$index].Name)) {
                throw 'pester-result: Actual test identity or order differs.'
            }
            $testIds += $contract.RequiredPesterTests[$index].Id
        }
        $pesterRecord = [pscustomobject]@{
            ContainerCount = @($pester.Containers).Count; TotalCount = $pester.TotalCount
            SelectedCount = @($pester.Tests | Where-Object { $_.ShouldRun }).Count
            ExecutedCount = @($pester.Tests | Where-Object { $_.Executed }).Count
            PassedCount = $pester.PassedCount; FailedCount = $pester.FailedCount; SkippedCount = $pester.SkippedCount
            NotRunCount = $pester.NotRunCount; FailedBlocksCount = $pester.FailedBlocksCount; FailedContainersCount = $pester.FailedContainersCount
            Result = [string]$pester.Result; TestIds = $testIds
        }
        foreach ($measurement in $contract.SuccessCounts.PSObject.Properties) {
            if ($measurement.Name -in @('CompilationCount', 'LoadCount', 'InitializedMutantKillCount')) { continue }
            if ($pesterRecord.PSObject.Properties[$measurement.Name].Value -ne $measurement.Value) {
                throw ('pester-result: Exact actual count differs: ' + $measurement.Name + '.')
            }
        }
        if ($pesterRecord.Result -cne 'Passed' -or -not $manifestRecords.BeforeAllCallerScopePassed) {
            throw 'pester-result: Full caller-bound test execution did not pass.'
        }
        $cleanup.OwnedStreamsClosed = $true
    }
    catch { $operationError = $_ }
    finally {
        try {
            Assert-PspktEvidenceRegistryAbsent
            $cleanup.RegistryDriveAbsent = $true
            $cleanup.RegistryVariableAbsent = $true
            if (@(Get-PSDrive -Name TestDrive -ErrorAction SilentlyContinue).Count -ne 0) {
                throw 'run-residue: Pester left a TestDrive.'
            }
            $cleanup.TestDriveCleanupPassed = $true
            if ($runCreated) {
                foreach ($image in @($compilations.Values)) {
                    if (-not $image.LoadAttempted -and [IO.File]::Exists($image.ImagePath)) { [IO.File]::Delete($image.ImagePath) }
                }
                $retainedImages = @($compilations.Values | Where-Object { $_.LoadAttempted })
                Assert-PspktEvidenceRunResidue -ArtifactRoot $context.RunRoot -Images $retainedImages
            }
            $cleanup.ResiduePassed = $true
            $cleanup.RetainedArtifactsDeclared = $true
        }
        catch { $cleanupErrors.Add($_.Exception) }
        try {
            [Environment]::SetEnvironmentVariable('TEMP', $previousTemp, 'Process')
            $cleanup.TempRestored = [object]::Equals([Environment]::GetEnvironmentVariable('TEMP', 'Process'), $previousTemp)
            if (-not $cleanup.TempRestored) { throw 'cleanup-restore: TEMP restoration differs.' }
        } catch { $cleanupErrors.Add($_.Exception) }
        try {
            [Environment]::SetEnvironmentVariable('TMP', $previousTmp, 'Process')
            $cleanup.TmpRestored = [object]::Equals([Environment]::GetEnvironmentVariable('TMP', 'Process'), $previousTmp)
            if (-not $cleanup.TmpRestored) { throw 'cleanup-restore: TMP restoration differs.' }
        } catch { $cleanupErrors.Add($_.Exception) }
        try {
            Set-Location -LiteralPath $previousLocation
            $cleanup.PowerShellLocationRestored = [string]::Equals((Get-Location).Path, $previousLocation, [StringComparison]::Ordinal)
            if (-not $cleanup.PowerShellLocationRestored) { throw 'cleanup-restore: PowerShell location restoration differs.' }
        } catch { $cleanupErrors.Add($_.Exception) }
        try {
            [Environment]::CurrentDirectory = $previousDotNetLocation
            $cleanup.DotNetLocationRestored = [string]::Equals([Environment]::CurrentDirectory, $previousDotNetLocation, [StringComparison]::Ordinal)
            if (-not $cleanup.DotNetLocationRestored) { throw 'cleanup-restore: CLR location restoration differs.' }
        } catch { $cleanupErrors.Add($_.Exception) }
        $cleanup.Completed = $cleanupErrors.Count -eq 0
    }
    if ($null -ne $operationError -or $cleanupErrors.Count -ne 0) {
        $failures = [Collections.Generic.List[Exception]]::new()
        if ($null -ne $operationError) { $failures.Add($operationError.Exception) }
        foreach ($failure in $cleanupErrors) { $failures.Add($failure) }
        $exception = New-PspktEvidenceValidationFailure -Failures $failures.ToArray() -Pester $pester -AllowedMessages $context.DiagnosticMessages
        Write-PspktEvidenceFailureDiagnostics -Exception $exception -AllowedMessages $context.DiagnosticMessages
        throw $exception
    }
    $compilationRecords = @()
    $loadRecords = @()
    foreach ($role in $contract.AssemblyRoles) {
        $image = $compilations[$role]
        $assembly = if ($role -ceq 'Bootstrap') { $bootstrapAssembly } elseif ($role -ceq 'Runtime') { $runtimeAssembly } else {
            ($mutantBuilds | Where-Object { $_.Role -ceq $role }).Assembly
        }
        $compilationRecords += [pscustomobject]@{
            Role = $role; AssemblyIdentity = $image.ImageIdentity; ImageSha256 = $image.ImageSha256; ImageLength = $image.ImageLength
            SourceCount = $image.SourceCount; Sources = $image.Sources; LanguageVersion = $image.LanguageVersion; CompilerIdentity = $image.CompilerIdentity
        }
        $loadContext = if ($compilerContext.Edition -ceq 'Desktop') { 'LoadFrom' } else { 'Default' }
        $loadRecords += [pscustomobject]@{
            Role = $role; AssemblyIdentity = $assembly.FullName; ImagePath = $assembly.Location
            ImageSha256 = $image.ImageSha256; Context = $loadContext; Initialized = $true
        }
    }
    $mutantResults = @($mutantBuilds | ForEach-Object {
        [pscustomobject]@{
            Role = $_.Role; AssemblyIdentity = $_.Assembly.FullName; Initialized = $_.Initialized
            OracleKilled = $_.OracleKilled; OracleId = $_.OracleId; Transform = $_.Transform
        }
    })
    $identity = [pscustomobject][ordered]@{
        RunId = $context.RunId; BaseCommit = $contract.BaseCommit; HostEdition = $PSVersionTable.PSEdition
        HostVersion = $PSVersionTable.PSVersion.ToString(); PesterVersion = '5.3.3'; RepositoryRoot = $context.RepositoryRoot
        WorkRoot = $context.WorkRoot; RunRoot = $context.RunRoot; SourceManifestSha256 = $context.Snapshot.ManifestSha256
    }
    $expected = [pscustomobject]@{
        Identity = $identity; SuccessCounts = $contract.SuccessCounts; AssemblyRoles = $contract.AssemblyRoles
        SuccessGates = $contract.SuccessGates; CleanupGates = $contract.CleanupGates; TestIds = @($contract.RequiredPesterTests.Id)
        CompilationRecords = $compilationRecords; LoadRecords = $loadRecords; MutantResults = $mutantResults
    }
    $context.Expected = $expected | ConvertTo-Json -Depth 30 -Compress | ConvertFrom-Json
    $gates = [ordered]@{}
    foreach ($name in $contract.SuccessGates) { $gates[$name] = $true }
    $resultFields = [ordered]@{ SchemaId = 'PspktEvidenceRuntimeValidationResultV1'; SchemaVersion = 1; Outcome = 'ValidationSucceeded' }
    foreach ($property in $identity.PSObject.Properties) { $resultFields[$property.Name] = $property.Value }
    $resultFields.CompilationCount = $compilationRecords.Count
    $resultFields.LoadCount = $loadRecords.Count
    $resultFields.InitializedMutantKillCount = @($mutantResults | Where-Object { $_.Initialized -and $_.OracleKilled }).Count
    $resultFields.CompilationRecords = $compilationRecords
    $resultFields.LoadRecords = $loadRecords
    $resultFields.MutantResults = $mutantResults
    $resultFields.Pester = $pesterRecord
    $resultFields.Gates = [pscustomobject]$gates
    $resultFields.Cleanup = $cleanup
    $result = [pscustomobject]$resultFields
    Assert-PspktEvidenceValidationSuccess -CapturedResults @($result) -Expected $context.Expected
    return $result
}

$existingContext = Get-Variable -Name PspktEvidenceInvocationContext -ErrorAction SilentlyContinue
if ($null -eq $existingContext) {
    $contractRelativePath = 'certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'
    $contractPath = Join-Path $RepositoryRoot $contractRelativePath
    $stream = [IO.File]::Open($contractPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 1048576) { throw 'source-length: Contract root is outside its bound.' }
        $contractBytes = [byte[]]::new([int]$stream.Length)
        $position = 0
        while ($position -lt $contractBytes.Length) {
            $read = $stream.Read($contractBytes, $position, $contractBytes.Length - $position)
            if ($read -eq 0) { throw 'source-read: Contract root ended early.' }
            $position += $read
        }
        if ($stream.ReadByte() -ne -1) { throw 'source-read: Contract root grew during admission.' }
    }
    finally { $stream.Dispose() }
    . ([scriptblock]::Create([Text.UTF8Encoding]::new($false, $true).GetString($contractBytes)))
    $preloaded = @{}
    $preloaded[$contractRelativePath] = $contractBytes
    $PspktEvidenceInvocationContext = New-PspktEvidenceInvocationContext -RepositoryRoot $RepositoryRoot -WorkRoot $WorkRoot `
        -PesterManifestPath $PesterManifestPath -PreloadedBytes $preloaded
}
else {
    $PspktEvidenceInvocationContext = $existingContext.Value
    if ($PspktEvidenceInvocationContext.Consumed -or $PspktEvidenceInvocationContext.Disposed) { throw 'invocation-repeat: A private context cannot be reused.' }
    $contractBytes = $PspktEvidenceInvocationContext.Snapshot.Files['certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'].Bytes
    . ([scriptblock]::Create([Text.UTF8Encoding]::new($false, $true).GetString($contractBytes)))
}
try {
    $capturedResults = @(Invoke-PspktPhase4EvidenceRuntimeValidators @invocationParameters)
    Complete-PspktEvidenceValidationInvocation -CapturedResults $capturedResults -Expected $PspktEvidenceInvocationContext.Expected
}
finally {
    $PspktEvidenceInvocationContext.Snapshot = $null
    $PspktEvidenceInvocationContext.Disposed = $true
}
