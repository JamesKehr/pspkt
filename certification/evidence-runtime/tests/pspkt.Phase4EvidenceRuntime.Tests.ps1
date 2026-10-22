param(
    [System.Reflection.Assembly]$BootstrapAssembly,
    [System.Reflection.Assembly]$RuntimeAssembly,
    [hashtable]$AuthorityBytesById,
    [hashtable]$FixtureBytesById,
    [hashtable]$ManifestRecordsByRole,
    [object[]]$CompileCensus,
    [object[]]$MutantBuilds,
    [string]$ArtifactRoot,
    [string]$CallerScopeMarker
)

function New-PspktEvidenceValidationResultFixture {
    param([object]$Contract, [string]$CaseId)

    $identity = [pscustomobject][ordered]@{
        RunId = '11111111111111111111111111111111'
        BaseCommit = $Contract.BaseCommit
        HostEdition = 'Desktop'
        HostVersion = '5.1.0.0'
        PesterVersion = '5.3.3'
        RepositoryRoot = 'Q:\synthetic\source'
        WorkRoot = 'Q:\synthetic\work'
        RunRoot = 'Q:\synthetic\work\run'
        SourceManifestSha256 = 'a' * 64
    }
    $compilations = @()
    $loads = @()
    $mutants = @()
    foreach ($role in $Contract.AssemblyRoles) {
        $sourceCount = if ($role -ceq 'Bootstrap') { 1 } else { 7 }
        $sources = @()
        for ($index = 0; $index -lt $sourceCount; $index++) {
            $sources += [pscustomobject]@{ Path = $role + '-' + $index + '.cs'; Length = 100; Sha256 = 'b' * 64 }
        }
        $assemblyIdentity = 'Synthetic_' + $role + ', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'
        $compilations += [pscustomobject]@{
            Role = $role; AssemblyIdentity = $assemblyIdentity; ImageSha256 = 'c' * 64; ImageLength = 1024
            SourceCount = $sourceCount; Sources = $sources; LanguageVersion = 'CSharp5'; CompilerIdentity = 'SyntheticCompiler'
        }
        $loads += [pscustomobject]@{
            Role = $role; AssemblyIdentity = $assemblyIdentity; ImagePath = 'Q:\synthetic\work\run\' + $role + '.dll'
            ImageSha256 = 'c' * 64; Context = 'LoadFrom'; Initialized = $true
        }
        if ($role -in @('M1', 'M2', 'M3')) {
            $oracle = switch ($role) {
                'M1' { 'burn-receipt-encode' }
                'M2' { 'burn-receipt-domain-hash' }
                'M3' { 'local-evidence-signature-covered-bytes' }
            }
            $mutants += [pscustomobject]@{
                Role = $role; AssemblyIdentity = $assemblyIdentity; Initialized = $true; OracleKilled = $true; OracleId = $oracle
                Transform = [pscustomobject]@{ SourcePath = $role + '.cs'; OriginalSha256 = 'd' * 64; MutatedSha256 = 'e' * 64; MatchCount = 1 }
            }
        }
    }
    $pesterFields = [ordered]@{}
    foreach ($property in $Contract.SuccessCounts.PSObject.Properties) {
        if ($property.Name -notin @('CompilationCount', 'LoadCount', 'InitializedMutantKillCount')) { $pesterFields[$property.Name] = $property.Value }
    }
    $pesterFields.Result = 'Passed'
    $pesterFields.TestIds = @($Contract.RequiredPesterTests.Id)
    $gates = [ordered]@{}
    foreach ($name in $Contract.SuccessGates) { $gates[$name] = $true }
    $cleanup = [ordered]@{}
    foreach ($name in $Contract.CleanupGates) { $cleanup[$name] = $true }
    $fields = [ordered]@{ SchemaId = 'PspktEvidenceRuntimeValidationResultV1'; SchemaVersion = 1; Outcome = 'ValidationSucceeded' }
    foreach ($property in $identity.PSObject.Properties) { $fields[$property.Name] = $property.Value }
    $fields.CompilationCount = 5
    $fields.LoadCount = 5
    $fields.InitializedMutantKillCount = 3
    $fields.CompilationRecords = $compilations
    $fields.LoadRecords = $loads
    $fields.MutantResults = $mutants
    $fields.Pester = [pscustomobject]$pesterFields
    $fields.Gates = [pscustomobject]$gates
    $fields.Cleanup = [pscustomobject]$cleanup
    $result = [pscustomobject]$fields
    $expected = [pscustomobject]@{
        Identity = $identity
        SuccessCounts = $Contract.SuccessCounts
        AssemblyRoles = $Contract.AssemblyRoles
        SuccessGates = $Contract.SuccessGates
        CleanupGates = $Contract.CleanupGates
        TestIds = @($Contract.RequiredPesterTests.Id)
        CompilationRecords = $compilations
        LoadRecords = $loads
        MutantResults = $mutants
    }
    $expected = $expected | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json
    $captured = @($result)
    switch ($CaseId) {
        'healthy' { }
        'count-mismatch' { $result.CompilationCount = 4 }
        'malformed-result' { $result.PSObject.Properties.Remove('Cleanup') }
        'missing-result' { $captured = @() }
        'multiple-results' { $captured = @($result, $result) }
        'returned-failure' {
            $captured = @([pscustomobject]@{
                SchemaId = 'PspktEvidenceRuntimeValidationResultV1'; SchemaVersion = 1; Outcome = 'ValidationFailed'
                RunId = $identity.RunId; FailurePhase = 'synthetic'; Errors = @('Synthetic validation failure.')
                ObservedCounts = [pscustomobject]@{ CompilationCount = 0; LoadCount = 0; InitializedMutantKillCount = 0 }
                CleanupObservation = [pscustomobject]@{ Completed = $true; TempRestored = $true; TmpRestored = $true; Errors = @(); RetainedArtifacts = @() }
            })
        }
        default { throw 'Unknown synthetic result case.' }
    }
    [pscustomobject]@{ Expected = $expected; Captured = $captured }
}

Describe 'Evidence runtime conformance' -Tag Precheck {
    BeforeAll {
        Assert-PspktEvidenceRegistryAbsent
        if ($null -ne $ExecutionContext.SessionState.Module) { throw 'caller-scope: BeforeAll is module-bound.' }
        foreach ($name in @('BootstrapAssembly', 'RuntimeAssembly', 'AuthorityBytesById', 'FixtureBytesById',
            'ManifestRecordsByRole', 'CompileCensus', 'MutantBuilds')) {
            if (-not [object]::ReferenceEquals((Get-Variable -Name $name -ValueOnly), $ManifestRecordsByRole.ExpectedData[$name])) {
                throw 'caller-data: BeforeAll did not receive an exact Data identity.'
            }
        }
        if ($ArtifactRoot -cne $ManifestRecordsByRole.ExpectedData.ArtifactRoot -or
            $CallerScopeMarker -cne $ManifestRecordsByRole.ExpectedData.CallerScopeMarker) {
            throw 'caller-data: BeforeAll scalar Data differs.'
        }
        $ManifestRecordsByRole.BeforeAllCallerScopePassed = $true
        $codecType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec', $true)
        $codec = $codecType.GetMethod('CreateFromCommittedAuthorities').Invoke($null, [object[]]@(
            $AuthorityBytesById.meta, $AuthorityBytesById.protocolInventory,
            $AuthorityBytesById.evidenceSchema, $AuthorityBytesById.evidenceInventory))
    }
    BeforeEach {
        Assert-PspktEvidenceRegistryAbsent
        Assert-PspktEvidenceOwnedTestStorage -ArtifactRoot $ArtifactRoot
        if ($null -ne $ExecutionContext.SessionState.Module) { throw 'caller-scope: Test is module-bound.' }
    }
    AfterEach {
        Assert-PspktEvidenceRegistryAbsent
        Assert-PspktEvidenceOwnedTestStorage -ArtifactRoot $ArtifactRoot
    }
    AfterAll {
        Assert-PspktEvidenceRegistryAbsent
    }
    It 'Rejects undeclared or malformed manifest and result contracts' {
        $contract = Get-PspktEvidenceRuntimeContract
        Assert-PspktEvidenceRuntimeContract -Contract $contract
        Assert-PspktEvidenceAuthorityManifest -Entries $contract.AuthorityInputs
        @($contract.AuthorityInputs).Count | Should -Be 4
        $contract.AuthorityInputs[0].Path | Should -BeExactly 'certification\schema\protocol-schema-meta.v1.json'
        $contract.AuthorityInputs[0].Length | Should -Be 4533
        $invalid = @($contract.AuthorityInputs) + [pscustomobject]@{
            Path = 'certification\unexpected.json'
            Length = 1L
            Sha256 = '0' * 64
        }
        { Assert-PspktEvidenceAuthorityManifest -Entries $invalid } | Should -Throw '*manifest-membership*'
        $invalid = @($contract.AuthorityInputs)
        $invalid[0] = [pscustomobject]@{
            Path = $contract.AuthorityInputs[0].Path
            Length = $true
            Sha256 = $contract.AuthorityInputs[0].Sha256
        }
        { Assert-PspktEvidenceAuthorityManifest -Entries $invalid } | Should -Throw '*manifest-length*'
        $contract.PublicDomainParameters -join ',' | Should -BeExactly 'RepositoryRoot,WorkRoot,PesterManifestPath'
        $contract.AssemblyRoles -join ',' | Should -BeExactly 'Bootstrap,Runtime,M1,M2,M3'
        @($contract.RuntimeSourceNames).Count | Should -Be 7
        @($contract.RequiredPesterTests).Count | Should -Be 32
        $contract.PesterOptions.TestRegistryEnabled | Should -BeFalse
        $contract.PesterOptions.TestDriveEnabled | Should -BeTrue
        $contract.SuccessCounts.CompilationCount | Should -Be 5
        $contract.SuccessCounts.LoadCount | Should -Be 5
        $contract.SuccessCounts.InitializedMutantKillCount | Should -Be 3
        $contract.SuccessCounts.PassedCount | Should -Be 32
        $contract | Add-Member -NotePropertyName Selector -NotePropertyValue 'partial'
        { Assert-PspktEvidenceRuntimeContract -Contract $contract } | Should -Throw '*contract-shape*'
        $contract = Get-PspktEvidenceRuntimeContract
        $contract.RuntimeSourceNames += 'Unreviewed.cs'
        { Assert-PspktEvidenceRuntimeContract -Contract $contract } | Should -Throw '*contract-shape*'
    }
    It 'Excludes unadmitted dependencies from every input route' {
        $paths = @(Get-PspktEvidenceSourcePaths)
        $paths.Count | Should -Be (@($paths | Sort-Object -Unique).Count)
        foreach ($path in $paths) { Assert-PspktEvidenceSourcePath -Path $path }
        foreach ($path in @(
            'certification\overlay\lib\OverlayBoundedProcess.cs',
            'certification\evidence-ledger\schema\signing-ledger-schema.v1.json',
            'certification\trusted-control\README.md',
            'certification\schema\protocol-schema.v1.json',
            '.git\config',
            'class\pspkt.cs',
            '..\outside.cs',
            'certification\evidence-runtime\lib\..\lib\EvidencePayloadCodec.cs',
            'certification/evidence-runtime/lib/EvidencePayloadCodec.cs'
        )) {
            { Assert-PspktEvidenceSourcePath -Path $path } | Should -Throw '*source-membership*'
        }
        $paths -ccontains '.github\workflows\ci-evidence-runtime.yml' | Should -BeTrue
        @($paths | Where-Object { $_ -like 'certification\evidence-runtime\lib\*.cs' }).Count | Should -Be 7
    }
    It 'Admits only exact authority bytes through their four declared gates' {
        $RuntimeAssembly | Should -Not -BeNullOrEmpty
        $codecType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec', $true)
        $factory = $codecType.GetMethod('CreateFromCommittedAuthorities')
        $arguments = [object[]]@(
            $AuthorityBytesById.meta,
            $AuthorityBytesById.protocolInventory,
            $AuthorityBytesById.evidenceSchema,
            $AuthorityBytesById.evidenceInventory
        )
        $factory.Invoke($null, $arguments).GetType() | Should -Be $codecType
        for ($index = 0; $index -lt 4; $index++) {
            $changed = [object[]]$arguments.Clone()
            $changed[$index] = [byte[]]$arguments[$index].Clone()
            $changed[$index][0] = $changed[$index][0] -bxor 1
            { $factory.Invoke($null, $changed) } | Should -Throw '*authority-pin*'
            $changed[$index] = [byte[]]::new($arguments[$index].Length + 1)
            { $factory.Invoke($null, $changed) } | Should -Throw '*authority-length*'
            $changed[$index] = $null
            $failure = $null
            try { $null = $factory.Invoke($null, $changed) }
            catch {
                $failure = $_.Exception
                while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
            }
            ($failure -is [ArgumentNullException]) | Should -BeTrue
            $failure.ParamName | Should -BeExactly $factory.GetParameters()[$index].Name
        }
        $snapshotType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceSchemaSnapshot', $true)
        $stages = $snapshotType.GetMethod('GetInputStages', [Reflection.BindingFlags]'Static,NonPublic').Invoke($null, @())
        $stages -join ',' | Should -BeExactly 'meta:bootstrap-meta:null,evidenceSchema:schema-against-meta:meta,evidenceInventory:json:null,protocolInventory:json:null'
        $calls = [regex]::Matches($ManifestRecordsByRole.SourceTexts['EvidenceSchemaSnapshot.cs'],
            'SchemaBootstrap\.Evaluate\("([^"]+)",\s*(\w+),\s*(\w+)\)')
        @($calls).Count | Should -Be 4
        (@($calls | ForEach-Object { $_.Groups[1].Value + ':' + $_.Groups[2].Value + ':' + $_.Groups[3].Value }) -join ',') |
            Should -BeExactly 'bootstrap-meta:meta:null,schema-against-meta:evidenceSchema:meta,json:evidenceInventory:null,json:protocolInventory:null'
    }
    It 'Exposes exactly two runtime types and three named validation parameters' {
        $exports = @($RuntimeAssembly.GetExportedTypes() | Sort-Object FullName)
        $exports.FullName -join ',' | Should -BeExactly 'Pspkt.Certification.EvidenceRuntime.DecodedEvidenceArtifactEnvelope,Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec'
        foreach ($export in $exports) {
            $export.IsSealed | Should -BeTrue
            @($export.GetConstructors()).Count | Should -Be 0
            @($export.GetFields([Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count | Should -Be 0
            @($export.GetEvents()).Count | Should -Be 0
        }
        $codecType = $exports[1]
        @($codecType.GetMethods([Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count | Should -Be 4
        $codecType.GetMethod('CreateFromCommittedAuthorities').ReturnType | Should -Be $codecType
        $codecType.GetMethod('CreateFromCommittedAuthorities').GetParameters().Name -join ',' |
            Should -BeExactly 'metaBytes,protocolInventoryBytes,evidenceSchemaBytes,evidenceInventoryBytes'
        $properties = @($exports[0].GetProperties())
        $properties.Count | Should -Be 6
        foreach ($property in $properties) { $property.GetSetMethod($true) | Should -BeNullOrEmpty }
        $exports[0].GetProperty('UncheckedSemantics').PropertyType.FullName | Should -BeExactly 'System.String[]'
        $propertyTypes = @{
            Kind = 'System.UInt16'; ArtifactId = 'System.Guid'; Profile = 'System.Byte'
            CanonicalPayload = 'System.Byte[]'; PayloadDigest = 'System.Byte[]'; UncheckedSemantics = 'System.String[]'
        }
        foreach ($name in $propertyTypes.Keys) {
            $exports[0].GetProperty($name).PropertyType.FullName | Should -BeExactly $propertyTypes[$name]
        }
        $codecType.GetMethod('Decode').GetParameters()[0].Name | Should -BeExactly 'envelopeBytes'
        $codecType.GetMethod('Decode').ReturnType | Should -Be $exports[0]
        $codecType.GetMethod('Encode').GetParameters().Name -join ',' |
            Should -BeExactly 'kind,artifactId,profile,canonicalPayloadBytes'
        $codecType.GetMethod('Encode').GetParameters().ParameterType.FullName -join ',' |
            Should -BeExactly 'System.UInt16,System.Guid,System.Byte,System.Byte[]'
        $codecType.GetMethod('Encode').ReturnType.FullName | Should -BeExactly 'System.Byte[]'
        $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').GetParameters()[0].Name |
            Should -BeExactly 'envelopeBytes'
        $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').ReturnType.FullName |
            Should -BeExactly 'System.Byte[]'
        $text = $ManifestRecordsByRole.ValidatorText
        $text | Should -Not -BeNullOrEmpty
        $parseTokens = $null
        $parseErrors = $null
        $syntax = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$parseTokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0
        $definition = $syntax.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Invoke-PspktPhase4EvidenceRuntimeValidators'
        }, $true)
        $definition | Should -Not -BeNullOrEmpty
        foreach ($parameterBlock in @($syntax.ParamBlock, $definition.Body.ParamBlock)) {
            $parameterBlock.Parameters.Name.VariablePath.UserPath -join ',' |
                Should -BeExactly 'RepositoryRoot,WorkRoot,PesterManifestPath'
            foreach ($parameter in $parameterBlock.Parameters) {
                $parameter.StaticType.FullName | Should -BeExactly 'System.String'
                $parameter.Extent.Text | Should -Match 'Mandatory\s*=\s*\$true'
                $parameter.Extent.Text | Should -Match 'ValidateNotNullOrEmpty'
                $parameter.Extent.Text | Should -Not -Match 'ValueFromPipeline|Alias\('
            }
            $parameterBlock.Attributes.Extent.Text -join '' | Should -Match 'PositionalBinding\s*=\s*\$false'
        }
    }
    It 'Rejects stale identities and repeated or unsupported invocations before work' {
        Assert-PspktEvidenceCleanHost -Assemblies @()
        { Assert-PspktEvidenceCleanHost -Assemblies @($BootstrapAssembly) } | Should -Throw '*assembly-preload*'
        { Assert-PspktEvidenceCleanHost -Assemblies @($RuntimeAssembly) } | Should -Throw '*assembly-preload*'
        Assert-PspktEvidenceInvocationAvailable -AlreadyInvoked $false
        { Assert-PspktEvidenceInvocationAvailable -AlreadyInvoked $true } | Should -Throw '*invocation-repeat*'
        $frameworkReference = [string].Assembly.GetName()
        Assert-PspktEvidenceAssemblyReference -Reference $frameworkReference -FrameworkReferences @($frameworkReference) -BootstrapIdentity $BootstrapAssembly.FullName
        Assert-PspktEvidenceAssemblyReference -Reference $BootstrapAssembly.GetName() -FrameworkReferences @($frameworkReference) -BootstrapIdentity $BootstrapAssembly.FullName
        $changedReference = [Reflection.AssemblyName]::new($frameworkReference.FullName)
        $changedReference.SetPublicKeyToken([byte[]]::new(8))
        { Assert-PspktEvidenceAssemblyReference -Reference $changedReference -FrameworkReferences @($frameworkReference) -BootstrapIdentity $BootstrapAssembly.FullName } |
            Should -Throw '*assembly-reference*'
        $command = [scriptblock]::Create($ManifestRecordsByRole.ValidatorText)
        $bindingWorkRoot = Join-Path $TestDrive 'parameter-binding'
        [void][IO.Directory]::CreateDirectory($bindingWorkRoot)
        $pesterManifest = Join-Path (Get-Module Pester).ModuleBase 'Pester.psd1'
        try {
            {
                & $command -RepositoryRoot $ManifestRecordsByRole.RepositoryRoot -WorkRoot $bindingWorkRoot -PesterManifestPath $pesterManifest -Mode 'obsolete'
            } | Should -Throw '*Mode*'
            [IO.Directory]::GetFileSystemEntries($bindingWorkRoot).Length | Should -Be 0
        }
        finally { [IO.Directory]::Delete($bindingWorkRoot) }
        $markerLiteral = "'Pspkt.Certification.EvidenceRuntime.ValidationInvocation'"
        [regex]::Matches($ManifestRecordsByRole.ValidatorText, [regex]::Escape($markerLiteral)).Count | Should -Be 1
        $probeMarker = 'Pspkt.Certification.EvidenceRuntime.PreflightTest.' + [Guid]::NewGuid().ToString('N')
        $probeText = $ManifestRecordsByRole.ValidatorText.Replace($markerLiteral, "'" + $probeMarker + "'")
        $probeRoot = Join-Path $TestDrive 'failed-preflight'
        [void][IO.Directory]::CreateDirectory($probeRoot)
        $pipeline = [PowerShell]::Create()
        try {
            foreach ($manifestPath in @((Join-Path $probeRoot 'missing.psd1'), $pesterManifest)) {
                $pipeline.Commands.Clear()
                $pipeline.Streams.Error.Clear()
                [void]$pipeline.AddScript($probeText).AddParameter('RepositoryRoot', $ManifestRecordsByRole.RepositoryRoot).
                    AddParameter('WorkRoot', $probeRoot).AddParameter('PesterManifestPath', $manifestPath)
                $invocationFailure = $null
                try { [void]$pipeline.Invoke() } catch { $invocationFailure = $_.Exception }
                $failureMessage = if ($pipeline.Streams.Error.Count -gt 0) {
                    $pipeline.Streams.Error[0].Exception.Message
                } elseif ($null -ne $invocationFailure) { $invocationFailure.GetBaseException().Message } else { '' }
                $expected = if ($manifestPath -ceq $pesterManifest) {
                    'invocation-repeat: A fresh host is required.'
                } else { 'pester-manifest: An explicit existing Pester manifest is required.' }
                $failureMessage | Should -BeExactly $expected
                ($null -ne [AppDomain]::CurrentDomain.GetData($probeMarker)) | Should -BeTrue
                [IO.Directory]::GetFileSystemEntries($probeRoot).Length | Should -Be 0
            }
        }
        finally { $pipeline.Dispose(); [IO.Directory]::Delete($probeRoot) }
    }
    It 'Matches the independently authored burn receipt bytes and fields' {
        $golden = $FixtureBytesById['operation-burn-receipt-profile1']
        $golden.Length | Should -Be 283
        $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$golden))
        $decoded.Kind | Should -Be 18
        $decoded.Profile | Should -Be 1
        $decoded.ArtifactId.ToString() | Should -BeExactly 'fedcba98-7654-3210-fedc-ba9876543210'
        $decoded.CanonicalPayload.Length | Should -Be 198
        [BitConverter]::ToString($decoded.PayloadDigest).Replace('-', '').ToLowerInvariant() |
            Should -BeExactly 'caa84da37f80a6c59961928ec61e8f7803ee6b2c2154b630f01b92359d46b086'
        $encoded = $codecType.GetMethod('Encode').Invoke($codec, [object[]]@(
            [uint16]18, [Guid]'fedcba98-7654-3210-fedc-ba9876543210', [byte]1, $decoded.CanonicalPayload))
        [Convert]::ToBase64String($encoded) | Should -BeExactly ([Convert]::ToBase64String($golden))
    }
    It 'Rejects malformed field ordering and presence' {
        $golden = $FixtureBytesById['operation-burn-receipt-profile1']
        $payload = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$golden)).CanonicalPayload
        $badTag = [byte[]]$payload.Clone()
        $badTag[1] = 2
        $mutations = @(
            $badTag,
            [byte[]]($payload + @(0)),
            [byte[]]$payload[22..197],
            [byte[]]$payload[0..196],
            [byte[]]($payload[0..21] + $payload)
        )
        foreach ($mutation in $mutations) {
            { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]18, [Guid]::Empty, [byte]1, $mutation)) } |
                Should -Throw '*tlv-*'
        }
    }
    It 'Rejects inconsistent and excessive lengths before allocation' {
        $golden = $FixtureBytesById['operation-burn-receipt-profile1']
        $payload = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$golden)).CanonicalPayload
        $wrongFixedLength = [byte[]]$payload.Clone()
        $wrongFixedLength[5] = 17
        { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]18, [Guid]::Empty, [byte]1, $wrongFixedLength)) } |
            Should -Throw '*tlv-value-bound*'
        foreach ($offset in @(2, 39, 43)) {
            $changed = [byte[]]$golden.Clone()
            for ($index = $offset; $index -lt $offset + 4; $index++) { $changed[$index] = 255 }
            $reason = if ($offset -eq 43) { '*payload-bound: Payload length differs.*' } else { '*tlv-length: Field exceeds remaining bytes.*' }
            { $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$changed)) } | Should -Throw $reason
        }
    }
    It 'Enforces only the exact evidence payload and envelope bounds' {
        $schema = $codecType.GetField('_schema', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($codec)
        $maximumMethod = $schema.GetType().GetMethod('GetMaximumPayloadLength', [Reflection.BindingFlags]'Instance,NonPublic')
        $maximumMethod | Should -Not -BeNullOrEmpty
        $maximumMethod.ReturnType.FullName | Should -BeExactly 'System.Numerics.BigInteger'
        $maximumMethod.Invoke($schema, [object[]]@([uint16]18, [byte]1)).ToString() | Should -BeExactly '198'
        $maximumMethod.Invoke($schema, [object[]]@([uint16]18, [byte]2)).ToString() | Should -BeExactly '198'
        { $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,[byte[]]::new(262229))) } | Should -Throw '*envelope-bound*'
        { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]18, [Guid]::Empty, [byte]1, [byte[]]::new(262144))) } |
            Should -Throw '*payload-bound*'
    }
    It 'Preserves canonical primitive byte representations' {
        $payloadType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidencePayloadCodec', $true)
        $primitiveMethod = $payloadType.GetMethod('ValidatePrimitive', [Reflection.BindingFlags]'Static,NonPublic')
        $primitiveMethod | Should -Not -BeNullOrEmpty
        $primitiveMethod.Invoke($null, [object[]]@('AsciiIdentifier', [byte[]]@(1, 127), 128))
        foreach ($bytes in @([byte[]]@(), [byte[]]@(0), [byte[]]@(128), [byte[]]::new(129))) {
            { $primitiveMethod.Invoke($null, [object[]]@('AsciiIdentifier', $bytes, 128)) } | Should -Throw '*ascii-identifier*'
        }
        $sid = [byte[]]@(1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0)
        $primitiveMethod.Invoke($null, [object[]]@('BinarySid', $sid, 68))
        foreach ($mutation in @([byte[]]@(2, 0, 0, 0, 0, 0, 0, 5), [byte[]]@(1, 16, 0, 0, 0, 0, 0, 5), [byte[]]@(1, 1, 0, 0, 0, 0, 0, 5))) {
            { $primitiveMethod.Invoke($null, [object[]]@('BinarySid', $mutation, 68)) } | Should -Throw '*binary-sid*'
        }
        [BitConverter]::ToString($sid) | Should -BeExactly '01-01-00-00-00-00-00-05-20-00-00-00'
    }
    It 'Resolves conditional fields and nested profiles exactly' {
        $secondProfile = $FixtureBytesById['kind-00-profile-2']
        $payload = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$secondProfile)).CanonicalPayload
        $position = 0
        $changed = [byte[]]$payload.Clone()
        $found = $false
        while ($position -lt $changed.Length) {
            $tag = 256 * $changed[$position] + $changed[$position + 1]
            $length = 16777216L * $changed[$position + 2] + 65536L * $changed[$position + 3] +
                256L * $changed[$position + 4] + $changed[$position + 5]
            if ($tag -eq 16) { $changed[$position + 6] = 1; $found = $true }
            $position += 6 + $length
        }
        $found | Should -BeTrue
        { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]0, [Guid]::Empty, [byte]2, $changed)) } |
            Should -Throw '*nested-profile*'
        $firstProfilePayload = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$FixtureBytesById['kind-00-profile-1'])).CanonicalPayload
        { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]0, [Guid]::Empty, [byte]2, $firstProfilePayload)) } |
            Should -Throw '*nested-profile: Payload profile differs from the envelope.*'
        foreach ($profile in @(0, 3, 255)) {
            { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]18, [Guid]::Empty, [byte]$profile, [byte[]]@())) } |
                Should -Throw '*evidence-profile*'
        }
    }
    It 'Processes all twenty two kinds under both evidence profiles' {
        Assert-PspktEvidenceCorpus -FixtureBytes $FixtureBytesById -FixtureRecords $ManifestRecordsByRole.FixtureRecords
        $schema = $codecType.GetField('_schema', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($codec)
        $maximumMethod = $schema.GetType().GetMethod('GetMaximumPayloadLength', [Reflection.BindingFlags]'Instance,NonPublic')
        for ($kind = 0; $kind -lt 22; $kind++) {
            for ($profile = 1; $profile -le 2; $profile++) {
                $identifier = 'kind-{0:D2}-profile-{1}' -f $kind, $profile
                $bytes = $FixtureBytesById[$identifier]
                $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
                $decoded.Kind | Should -Be $kind
                $decoded.Profile | Should -Be $profile
                $decoded.CanonicalPayload.Length | Should -Be $ManifestRecordsByRole.FixtureRecords[$identifier].payloadLength
                $maximumMethod.Invoke($schema, [object[]]@([uint16]$kind, [byte]$profile)).ToString() |
                    Should -BeExactly ([string]$decoded.CanonicalPayload.Length)
                $encoded = $codecType.GetMethod('Encode').Invoke($codec, [object[]]@(
                    [uint16]$kind, $decoded.ArtifactId, [byte]$profile, $decoded.CanonicalPayload))
                [Convert]::ToBase64String($encoded) | Should -BeExactly ([Convert]::ToBase64String($bytes))
            }
        }
        { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]23, [Guid]::Empty, [byte]1, [byte[]]@())) } |
            Should -Throw '*evidence-kind*'
    }
    It 'Rejects incorrect digest domains separators and substitutions' {
        $golden = $FixtureBytesById['operation-burn-receipt-profile1']
        $payload = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$golden)).CanonicalPayload
        $wrongPreimages = @(
            [byte[]]([Text.Encoding]::ASCII.GetBytes('PSPKT/evidence/v1/OperationBurnReceiptV1') + @(0) + $payload),
            [byte[]]([Text.Encoding]::ASCII.GetBytes('pspkt/evidence/v1/OperationBurnReceiptV1') + $payload),
            [byte[]]([Text.Encoding]::ASCII.GetBytes('pspkt/ledger/v1/OperationBurnReceiptV1') + @(0) + $payload),
            [byte[]]([Text.Encoding]::ASCII.GetBytes('pspkt/evidence/v1/OperationBurnDeferralReceiptV1') + @(0) + $payload),
            [Text.Encoding]::UTF8.GetBytes('{"payload":"not binary TLV"}')
        )
        foreach ($preimage in $wrongPreimages) {
            $algorithm = [Security.Cryptography.SHA256]::Create()
            try { $digest = $algorithm.ComputeHash($preimage) }
            finally { $algorithm.Dispose() }
            $changed = [byte[]]$golden.Clone()
            [Buffer]::BlockCopy($digest, 0, $changed, $changed.Length - 32, 32)
            { $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$changed)) } | Should -Throw '*payload-digest*'
        }
    }
    It 'Returns exactly the three declared evidence signature preimages' {
        $golden = $FixtureBytesById['local-evidence-receipt-coverage']
        $covered = $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($codec, [object[]]@(,$golden))
        [BitConverter]::ToString($covered).Replace('-', '').ToLowerInvariant() |
            Should -BeExactly $ManifestRecordsByRole.FixtureRecords['local-evidence-receipt-coverage'].signatureCoveredHex
        $kindNames = @{ 16 = 'LocalEvidenceReceiptV1'; 17 = 'LocalEvidenceProofV1'; 20 = 'OperationRehabilitationAuthorizationV1' }
        foreach ($kind in @(16, 17, 20)) {
            foreach ($profile in @(1, 2)) {
                $bytes = $FixtureBytesById[('kind-{0:D2}-profile-{1}' -f $kind, $profile)]
                $payload = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes)).CanonicalPayload
                $prefix = [Text.Encoding]::ASCII.GetBytes('pspkt/evidence/v1/' + $kindNames[$kind])
                $expected = [byte[]]($prefix + @(0) + $payload[0..($payload.Length - 391)])
                $actual = $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($codec, [object[]]@(,$bytes))
                [Convert]::ToBase64String($actual) | Should -BeExactly ([Convert]::ToBase64String($expected))
            }
        }
    }
    It 'Distinguishes signature bytes from preceding signature covered fields' {
        foreach ($kind in @(16, 17, 20)) {
            $bytes = $FixtureBytesById[('kind-{0:D2}-profile-1' -f $kind)]
            $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
            $originalCovered = $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($codec, [object[]]@(,$bytes))
            $payload = $decoded.CanonicalPayload
            $payload[$payload.Length - 1] = $payload[$payload.Length - 1] -bxor 1
            $changed = $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]$kind, $decoded.ArtifactId, [byte]1, $payload))
            $changedDecoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$changed))
            $changedCovered = $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($codec, [object[]]@(,$changed))
            [Convert]::ToBase64String($changedDecoded.PayloadDigest) | Should -Not -BeExactly ([Convert]::ToBase64String($decoded.PayloadDigest))
            [Convert]::ToBase64String($changedCovered) | Should -BeExactly ([Convert]::ToBase64String($originalCovered))
            $payload = $decoded.CanonicalPayload
            $payload[6] = $payload[6] -bxor 1
            $changed = $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]$kind, $decoded.ArtifactId, [byte]1, $payload))
            $changedCovered = $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($codec, [object[]]@(,$changed))
            [Convert]::ToBase64String($changedCovered) | Should -Not -BeExactly ([Convert]::ToBase64String($originalCovered))
        }
    }
    It 'Never invents coverage or authentication for copied signatures' {
        foreach ($kind in @(0, 2, 15)) {
            $bytes = $FixtureBytesById[('kind-{0:D2}-profile-1' -f $kind)]
            $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
            $decoded.UncheckedSemantics | Should -Contain 'signature-authentication-unchecked'
            $decoded.UncheckedSemantics | Should -Contain 'signature-key-binding-unchecked'
            $decoded.UncheckedSemantics | Should -Contain 'copied-protocol-digests-unchecked'
            { $codecType.GetMethod('GetDeclaredSignatureCoveredBytes').Invoke($codec, [object[]]@(,$bytes)) } |
                Should -Throw '*no declared evidence signature coverage*'
        }
    }
    It 'Classifies every non envelope digest without conflating references' {
        $signatureType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceSignatureContract', $true)
        $method = $signatureType.GetMethod('GetDigestCategoryBindings', [Reflection.BindingFlags]'Static,NonPublic')
        $method | Should -Not -BeNullOrEmpty
        $expected = @{
            16 = 'protocolSchemaDigest:L,evidenceSchemaDigest:L,payloadDigest:G,observerKeyId:F'
            17 = 'protocolSchemaDigest:L,evidenceSchemaDigest:L,payloadDigest:G,observerKeyId:F'
            18 = 'canonicalSemanticDigest:M,terminalRecordDigest:K,burnReasonDigest:M,observerProofDigest:M'
            19 = 'canonicalSemanticDigest:M,successorRunIntentDigest:M,deferralReasonDigest:M'
            20 = 'burnReceiptDigest:I,burnedSemanticDigest:M,successorRunIntentDigest:M,authorityKeyId:F'
            21 = 'authorizationDigest:I,successorRecordDigest:K,observerProofDigest:M'
        }
        $count = 0
        $schema = [Text.Encoding]::UTF8.GetString($AuthorityBytesById.evidenceSchema) | ConvertFrom-Json
        $kindNames = ($schema.types | Where-Object { $_.name -ceq 'EvidenceArtifactKind' }).members
        foreach ($kind in 16..21) {
            $bindings = $method.Invoke($null, [object[]]@([uint16]$kind))
            $bindings -join ',' | Should -BeExactly $expected[$kind]
            $name = ($kindNames | Where-Object { $_.value -eq $kind }).name
            $fields = @((($schema.types | Where-Object { $_.name -ceq $name }).fields |
                Where-Object { $_.type -ceq 'SHA-256' }).name)
            (@($bindings | ForEach-Object { $_.Split(':')[0] }) -join ',') | Should -BeExactly ($fields -join ',')
            $count += $bindings.Count
        }
        $count | Should -Be 22
    }
    It 'Preserves unchecked claims without resolving or authenticating them' {
        $schemaDocument = [Text.Encoding]::UTF8.GetString($AuthorityBytesById.evidenceSchema) | ConvertFrom-Json
        $kindDeclaration = $schemaDocument.types | Where-Object { $_.name -ceq 'EvidenceArtifactKind' }
        foreach ($kind in 16..21) {
            $bytes = $FixtureBytesById[('kind-{0:D2}-profile-1' -f $kind)]
            $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
            $payload = $decoded.CanonicalPayload
            $kindName = ($kindDeclaration.members | Where-Object { $_.value -eq $kind }).name
            $declaration = $schemaDocument.types | Where-Object { $_.name -ceq $kindName }
            $digestTags = @($declaration.fields | Where-Object { $_.type -ceq 'SHA-256' } | ForEach-Object { $_.fieldId })
            $position = 0
            while ($position -lt $payload.Length) {
                $tag = 256 * $payload[$position] + $payload[$position + 1]
                $length = 16777216L * $payload[$position + 2] + 65536L * $payload[$position + 3] +
                    256L * $payload[$position + 4] + $payload[$position + 5]
                if ($digestTags -contains $tag) { $payload[$position + 6] = 165 }
                $position += 6 + $length
            }
            $changed = $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]$kind, [Guid]::Empty, [byte]1, $payload))
            $roundtrip = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$changed))
            Assert-PspktEvidenceUncheckedClaims -Envelope $roundtrip -ExpectedPayload $payload -ExpectedKind $kind
            $wrongPayload = [byte[]]$payload.Clone()
            $wrongPayload[28] = $wrongPayload[28] -bxor 1
            { Assert-PspktEvidenceUncheckedClaims -Envelope $roundtrip -ExpectedPayload $wrongPayload -ExpectedKind $kind } |
                Should -Throw '*unchecked-claims*'
        }
    }
    It 'Keeps outer artifact and profile metadata explicitly unauthenticated' {
        $bytes = $FixtureBytesById['operation-burn-receipt-profile1']
        $original = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
        $changed = [byte[]]$bytes.Clone()
        $changed[14] = $changed[14] -bxor 1
        $changed[36] = 2
        $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$changed))
        $decoded.ArtifactId | Should -Not -Be $original.ArtifactId
        $decoded.Profile | Should -Be 2
        [Convert]::ToBase64String($decoded.PayloadDigest) | Should -BeExactly ([Convert]::ToBase64String($original.PayloadDigest))
        [Convert]::ToBase64String($decoded.CanonicalPayload) | Should -BeExactly ([Convert]::ToBase64String($original.CanonicalPayload))
        $decoded.UncheckedSemantics | Should -Contain 'artifact-id-unbound'
        $decoded.UncheckedSemantics | Should -Contain 'profile-value-unbound'
        $decoded.UncheckedSemantics | Should -Contain 'profile-authentication-unchecked'
    }
    It 'Rejects malformed payloads before encoding an envelope' {
        $bytes = $FixtureBytesById['operation-burn-receipt-profile1']
        $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
        $payload = $decoded.CanonicalPayload
        $payload[1] = 2
        { $codecType.GetMethod('Encode').Invoke($codec, [object[]]@([uint16]18, [Guid]::Empty, [byte]1, $payload)) } |
            Should -Throw '*tlv-tag*'
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $algorithm.ComputeHash([byte[]](
                [Text.Encoding]::ASCII.GetBytes('pspkt/evidence/v1/OperationBurnReceiptV1') + @(0) + $payload))
        }
        finally { $algorithm.Dispose() }
        $changed = [byte[]]$bytes.Clone()
        [Buffer]::BlockCopy($payload, 0, $changed, 47, $payload.Length)
        [Buffer]::BlockCopy($digest, 0, $changed, $changed.Length - 32, 32)
        { $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$changed)) } | Should -Throw '*tlv-tag*'
    }
    It 'Matches all documented tokens and categories with defensive copies' {
        Assert-PspktEvidenceDocumentation -Text $ManifestRecordsByRole.DocumentationText -RuntimeAssembly $RuntimeAssembly
        $diagnosticRows = @(
            '| Emitted closed category | Preserve the category; redact unsafe variable text. |',
            '| Unmatched uncategorized literal | Generic redacted diagnostic; no category inferred. |',
            '| Registered but un-emitted category | No runtime emission or reachability claim. |'
        )
        foreach ($row in $diagnosticRows) {
            $ManifestRecordsByRole.DocumentationText.Contains($row) | Should -BeTrue
            { Assert-PspktEvidenceDocumentation -Text ($ManifestRecordsByRole.DocumentationText.Replace($row, '| invented | behavior |')) -RuntimeAssembly $RuntimeAssembly } |
                Should -Throw '*documentation-parity*'
        }
        for ($kind = 0; $kind -lt 22; $kind++) {
            foreach ($profile in @(1, 2)) {
                $bytes = $FixtureBytesById[('kind-{0:D2}-profile-{1}' -f $kind, $profile)]
                $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
                Assert-PspktEvidenceUncheckedClaims -Envelope $decoded -ExpectedPayload $decoded.CanonicalPayload -ExpectedKind $kind
                $tokens = $decoded.UncheckedSemantics
                $tokens[0] = 'altered'
                $decoded.UncheckedSemantics[0] | Should -BeExactly 'evidence-authenticity-unchecked'
            }
        }
        { Assert-PspktEvidenceDocumentation -Text ($ManifestRecordsByRole.DocumentationText.Replace('ledger-record-references-unchecked', 'invented')) -RuntimeAssembly $RuntimeAssembly } |
            Should -Throw '*documentation-parity*'
        { Assert-PspktEvidenceDocumentation -Text ($ManifestRecordsByRole.DocumentationText.Replace(
            '| CallerScopeMarker | pspkt-evidence-validation: |', '| CallerScopeMarker | invented: |')) -RuntimeAssembly $RuntimeAssembly } |
            Should -Throw '*documentation-parity*'
    }
    It 'Preserves immutable state through rejection and interleaved calls' {
        $bytes = [byte[]]$FixtureBytesById['operation-burn-receipt-profile1'].Clone()
        $decoded = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$bytes))
        $expected = [Convert]::ToBase64String($decoded.CanonicalPayload)
        $payload = $decoded.CanonicalPayload
        $payload[0] = $payload[0] -bxor 1
        [Convert]::ToBase64String($decoded.CanonicalPayload) | Should -BeExactly $expected
        $digest = $decoded.PayloadDigest
        $originalDigest = [Convert]::ToBase64String($digest)
        $digest[0] = $digest[0] -bxor 1
        [Convert]::ToBase64String($decoded.PayloadDigest) | Should -BeExactly $originalDigest
        $bytes[47] = 255
        [Convert]::ToBase64String($decoded.CanonicalPayload) | Should -BeExactly $expected
        { $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,[byte[]]@())) } | Should -Throw '*tlv-header: Truncated field.*'
        $fresh = $codecType.GetMethod('Decode').Invoke($codec, [object[]]@(,$FixtureBytesById['operation-burn-receipt-profile1']))
        [Convert]::ToBase64String($fresh.CanonicalPayload) | Should -BeExactly $expected
    }
    It 'Binds retained C sharp five sources and admitted dependency identities' {
        $context = $ManifestRecordsByRole.CompilerContext
        $context | Should -Not -BeNullOrEmpty
        $records = $ManifestRecordsByRole.CompilationRecords
        $records.Bootstrap.SourceCount | Should -Be 1
        $records.Runtime.SourceCount | Should -Be 7
        $records.Runtime.LanguageVersion | Should -BeExactly 'CSharp5'
        Assert-PspktEvidenceBootstrapExports -Assembly $BootstrapAssembly
        { Assert-PspktEvidenceBootstrapExports -Assembly $RuntimeAssembly } |
            Should -Throw '*bootstrap-public-surface: Frozen Bootstrap exports differ.*'
        @($BootstrapAssembly.GetExportedTypes()).Count | Should -Be 2
        ($BootstrapAssembly.GetExportedTypes().FullName | Sort-Object) -join ',' |
            Should -BeExactly 'Pspkt.Certification.SchemaBootstrap,Pspkt.Certification.SchemaCheckResult'
        Assert-PspktEvidenceLoadedAssembly -Assembly $BootstrapAssembly -Image $records.Bootstrap -Context $context -BootstrapIdentity $BootstrapAssembly.FullName
        Assert-PspktEvidenceLoadedAssembly -Assembly $RuntimeAssembly -Image $records.Runtime -Context $context -BootstrapIdentity $BootstrapAssembly.FullName
        @($RuntimeAssembly.GetReferencedAssemblies() | Where-Object { $_.FullName -ceq $BootstrapAssembly.FullName }).Count | Should -Be 1
        $RuntimeAssembly.Location.StartsWith($ArtifactRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
    }
    It 'Runs retained tests in caller scope with all nine data identities' {
        ($null -eq $ExecutionContext.SessionState.Module) | Should -BeTrue
        $wrapper = $ManifestRecordsByRole.TestWrapper
        $wrapper.WrapperLength | Should -Be ($wrapper.OriginalLength + 4)
        $wrapper.OriginalSha256 | Should -Match '^[0-9a-f]{64}$'
        $wrapper.WrapperSha256 | Should -Match '^[0-9a-f]{64}$'
        foreach ($name in @('BootstrapAssembly', 'RuntimeAssembly', 'AuthorityBytesById', 'FixtureBytesById',
            'ManifestRecordsByRole', 'CompileCensus', 'MutantBuilds')) {
            [object]::ReferenceEquals((Get-Variable -Name $name -ValueOnly), $ManifestRecordsByRole.ExpectedData[$name]) | Should -BeTrue
        }
        $ArtifactRoot | Should -BeExactly $ManifestRecordsByRole.ExpectedData.ArtifactRoot
        $CallerScopeMarker | Should -BeExactly $ManifestRecordsByRole.ExpectedData.CallerScopeMarker
        [regex]::IsMatch($CallerScopeMarker, '\Apspkt-evidence-validation:[0-9a-f]{32}\z') | Should -BeTrue
        $ManifestRecordsByRole.BeforeAllCallerScopePassed | Should -BeTrue
        (Get-Module Pester).Version.ToString() | Should -BeExactly '5.3.3'
    }
    It 'Keeps generated vectors and protected goldens independent of production' {
        Assert-PspktEvidenceGeneratorIsolation -SourceText $ManifestRecordsByRole.GeneratorText
        { Assert-PspktEvidenceGeneratorIsolation -SourceText ($ManifestRecordsByRole.GeneratorText + "`n[Reflection.Assembly]::LoadFrom('codec.dll')") } |
            Should -Throw '*generator-isolation*'
        $ManifestRecordsByRole.GeneratorText | Should -Not -Match 'hand-authored|EvidenceArtifactEnvelopeCodec|EvidenceAuthorityJsonReader'
        $ManifestRecordsByRole.FixtureRecords['operation-burn-receipt-profile1'].sha256 |
            Should -BeExactly '5fca724f829c7a575f105efeea19ddf0f1fe581467fa149753444733b136b500'
        $ManifestRecordsByRole.FixtureRecords['local-evidence-receipt-coverage'].sha256 |
            Should -BeExactly '9a1b91246ca4d1b277cee94da1ca2b68fd251df14fd9b33706ec3b28343ef31e'
    }
    It 'Kills three distinct initialized mutants with independent oracles' {
        $MutantBuilds.Count | Should -Be 3
        ($MutantBuilds.Role -join ',') | Should -BeExactly 'M1,M2,M3'
        @($MutantBuilds.Assembly.FullName | Sort-Object -Unique).Count | Should -Be 3
        foreach ($build in $MutantBuilds) {
            $build.Initialized | Should -BeTrue
            $build.OracleKilled | Should -BeTrue
            $build.Assembly.FullName | Should -Not -BeExactly $RuntimeAssembly.FullName
            $build.Image.SourceCount | Should -Be 7
            $build.Transform.MatchCount | Should -Be 1
            [object]::ReferenceEquals(
                $build.Assembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec', $true).Assembly,
                $build.Assembly) | Should -BeTrue
        }
        $CompileCensus.Role -join ',' | Should -BeExactly 'Bootstrap,Runtime,M1,M2,M3'
    }
    It 'Rejects incomplete per call and aggregate evidence counts' {
        $fixture = New-PspktEvidenceValidationResultFixture -Contract (Get-PspktEvidenceRuntimeContract) -CaseId healthy
        Assert-PspktEvidenceValidationSuccess -CapturedResults $fixture.Captured -Expected $fixture.Expected
        foreach ($name in @('CompilationCount', 'LoadCount', 'InitializedMutantKillCount')) {
            $changed = New-PspktEvidenceValidationResultFixture -Contract (Get-PspktEvidenceRuntimeContract) -CaseId healthy
            $changed.Captured[0].$name = 0
            { Assert-PspktEvidenceValidationSuccess -CapturedResults $changed.Captured -Expected $changed.Expected } | Should -Throw '*ResultCounts*'
        }
        $changed = New-PspktEvidenceValidationResultFixture -Contract (Get-PspktEvidenceRuntimeContract) -CaseId healthy
        $changed.Captured[0].Pester.PassedCount = 31
        { Assert-PspktEvidenceValidationSuccess -CapturedResults $changed.Captured -Expected $changed.Expected } | Should -Throw '*ResultCounts*'
        $changed.Captured[0].Pester.PassedCount = 32
        $changed.Captured[0].Cleanup.ResiduePassed = $false
        { Assert-PspktEvidenceValidationSuccess -CapturedResults $changed.Captured -Expected $changed.Expected } | Should -Throw '*ResultPostconditions*'
        $changed = New-PspktEvidenceValidationResultFixture -Contract (Get-PspktEvidenceRuntimeContract) -CaseId healthy
        $changed.Captured[0].CompilationCount = 4
        $changed.Expected.SuccessCounts.CompilationCount = 4
        { Assert-PspktEvidenceValidationSuccess -CapturedResults $changed.Captured -Expected $changed.Expected } | Should -Throw '*ResultCounts*'
        $changed = New-PspktEvidenceValidationResultFixture -Contract (Get-PspktEvidenceRuntimeContract) -CaseId healthy
        $changed.Captured[0].Pester.TestIds = @(($changed.Captured[0].Pester.TestIds -join ','))
        { Assert-PspktEvidenceValidationSuccess -CapturedResults $changed.Captured -Expected $changed.Expected } | Should -Throw '*ResultPostconditions*'
        $CompileCensus.Count | Should -Be 5
        @($MutantBuilds | Where-Object { $_.Initialized -and $_.OracleKilled }).Count | Should -Be 3
    }
    It 'Rejects incomplete corpus discovery configuration or export evidence' {
        $configuration = New-PspktEvidencePesterConfiguration -Container $ManifestRecordsByRole.PesterContainer
        Assert-PspktEvidencePesterConfiguration -Configuration $configuration
        $configuration.Filter.FullName = @('*')
        { Assert-PspktEvidencePesterConfiguration -Configuration $configuration } | Should -Throw '*pester-configuration*'
        $configuration.Filter.FullName = @()
        $configuration.TestRegistry.Enabled = $true
        { Assert-PspktEvidencePesterConfiguration -Configuration $configuration } | Should -Throw '*pester-configuration*'
        $configuration.TestRegistry.Enabled = $false
        $incomplete = $FixtureBytesById.Clone()
        $incomplete.Remove('kind-21-profile-2')
        { Assert-PspktEvidenceCorpus -FixtureBytes $incomplete -FixtureRecords $ManifestRecordsByRole.FixtureRecords } |
            Should -Throw '*fixture-population*'
        $paths = @(Get-PspktEvidenceSourcePaths)
        Assert-PspktEvidenceExportPathSet -Paths $paths
        { Assert-PspktEvidenceExportPathSet -Paths ($paths + '.git\config') } | Should -Throw '*export-membership*'
    }
    It 'Requires exact isolated workflow invocations and fail closed receipts' {
        (Get-PspktEvidenceRuntimeContract).WorkRootMaximumLength | Should -Be 100
        $boundaryRoot = 'Q:\' + ('r' * 97)
        $boundaryRoot.Length | Should -Be 100
        Assert-PspktEvidenceWorkRootLength -WorkRoot $boundaryRoot
        { Assert-PspktEvidenceWorkRootLength -WorkRoot ($boundaryRoot + 'r') } |
            Should -Throw '*work-root: Fresh run path is colliding or exceeds the Desktop-safe length.*'
        $ManifestRecordsByRole.DocumentationText.Contains('| WorkRootMaximumLength | 100 |') | Should -BeTrue
        $wrongBoundDocumentation = $ManifestRecordsByRole.DocumentationText.Replace(
            '| WorkRootMaximumLength | 100 |', '| WorkRootMaximumLength | 101 |')
        { Assert-PspktEvidenceDocumentation -Text $wrongBoundDocumentation -RuntimeAssembly $RuntimeAssembly } |
            Should -Throw '*documentation-parity*'
        Assert-PspktEvidenceRootRelationships -RepositoryRoot 'Q:\workspace\repo' -WorkRoot 'Q:\runner-temp\unique-run' `
            -OriginalWorkspace 'Q:\workspace\repo' -RunnerTemp 'Q:\runner-temp'
        foreach ($workRoot in @('Q:\workspace\repo', 'Q:\workspace\repo\child', 'Q:\workspace', 'Q:\runner-temp')) {
            { Assert-PspktEvidenceRootRelationships -RepositoryRoot 'Q:\workspace\repo' -WorkRoot $workRoot `
                -OriginalWorkspace 'Q:\workspace\repo' -RunnerTemp 'Q:\runner-temp' } | Should -Throw '*work-root*'
        }
        (Test-PspktEvidenceDirectoryOverlap -Left 'Q:\workspace\repo' -Right 'Q:\workspace\repo-extra') | Should -BeFalse
        foreach ($alias in @('Q:\runner-temp\\unique-run', 'Q:\runner-temp\CON', 'Q:\RUNNER~1\unique-run')) {
            { ConvertTo-PspktEvidenceDirectoryPath -Path $alias } | Should -Throw '*work-root*'
        }
        Assert-PspktEvidenceWorkflow -SourceText $ManifestRecordsByRole.WorkflowText
        $setupStages = @('source-load', 'source-admission', 'temporary-storage', 'tls', 'download',
            'package-length', 'package-hash', 'compression-load', 'archive-extract', 'manifest', 'publish')
        foreach ($stage in $setupStages) {
            $message = Get-PspktEvidencePesterSetupFailureMessage -Stage $stage
            $message | Should -BeExactly ('pester-setup: ' + $stage + ' failed.')
            $message.Length | Should -BeLessOrEqual 256
            [regex]::IsMatch($message, '\A[\x20-\x7e]+\z') | Should -BeTrue
        }
        foreach ($stage in @('', 'DOWNLOAD', "download`nhttps://untrusted.invalid/private", ('x' * 1024))) {
            Get-PspktEvidencePesterSetupFailureMessage -Stage $stage |
                Should -BeExactly 'pester-setup: unknown-stage failed.'
        }
        $setupBlock = [regex]::Match($ManifestRecordsByRole.WorkflowText,
            '(?m)^        run: &pester_setup \|\r?\n((?:          .*\r?\n)+)').Groups[1].Value
        function Assert-PspktSetupStageOrdering {
            param([string]$SourceText, [string[]]$ExpectedStages)

            $tokens = $null
            $errors = $null
            $syntax = [Management.Automation.Language.Parser]::ParseInput($SourceText, [ref]$tokens, [ref]$errors)
            if (@($errors).Count -ne 0) { throw 'setup-order: Setup source must parse.' }
            $tries = @($syntax.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
            if ($tries.Count -ne 1 -or $tries[0].CatchClauses.Count -ne 1) { throw 'setup-order: Exactly one guarded setup body is required.' }
            $setupTry = $tries[0]
            $handlers = @($syntax.FindAll({ param($node)
                $node -is [Management.Automation.Language.TryStatementAst] -or
                    $node -is [Management.Automation.Language.CatchClauseAst] -or
                    $node -is [Management.Automation.Language.TrapStatementAst]
            }, $true))
            if ($handlers.Count -ne 2 -or $null -ne $setupTry.Finally -or $setupTry.CatchClauses[0].CatchTypes.Count -ne 0) {
                throw 'setup-exceptions: Only the admitted outer try/catch is allowed.'
            }
            $assignments = @($syntax.FindAll({ param($node)
                $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                    $node.Left.VariablePath.UserPath -ceq 'setupStage'
            }, $true) | Sort-Object { $_.Extent.StartOffset })
            if ($assignments.Count -ne 11 -or $ExpectedStages.Count -ne 11) { throw 'setup-order: Exactly eleven stage assignments are required.' }
            for ($index = 0; $index -lt 11; $index++) {
                $assignment = $assignments[$index]
                if ($assignment.Operator -ne [Management.Automation.Language.TokenKind]::Equals -or
                    $assignment.Right -isnot [Management.Automation.Language.CommandExpressionAst] -or
                    $assignment.Right.Expression -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
                    -not [string]::Equals($assignment.Right.Expression.Value, $ExpectedStages[$index], [StringComparison]::Ordinal)) {
                    throw 'setup-order: Stage literals or their exact order differ.'
                }
                $expectedParent = if ($index -eq 0) { $syntax.EndBlock } else { $setupTry.Body }
                if (-not [object]::ReferenceEquals($assignment.Parent, $expectedParent)) {
                    throw 'setup-order: Stage assignment is conditional or outside its required scope.'
                }
            }
            if ($assignments[0].Extent.EndOffset -ge $setupTry.Extent.StartOffset) {
                throw 'setup-order: Source-load must be established before entering setup.'
            }
            $requiredOperations = @(
                @('assign:encoding', 'assign:contractBytes', 'static:scriptblock:Create'),
                @('command:Get-PspktEvidenceDiagnosticMessages', 'command:Get-PspktEvidenceSourceSnapshot'),
                @('assign:toolRoot', 'static:IO.Directory:CreateDirectory', 'assign:env:TEMP', 'assign:env:TMP', 'assign:package'),
                @('member:Net.ServicePointManager:SecurityProtocol'),
                @('command:Invoke-WebRequest'),
                @('static:IO.FileInfo:new'),
                @('command:Assert-PspktEvidencePesterPackage'),
                @('assign:compressionIdentity', 'static:Reflection.Assembly:Load'),
                @('static:IO.Compression.ZipFile:ExtractToDirectory'),
                @('assign:manifest', 'static:IO.File:Exists'),
                @('static:IO.File:AppendAllText')
            )
            $operations = @{}
            foreach ($node in $setupTry.Body.FindAll({ param($candidate)
                $candidate -is [Management.Automation.Language.AssignmentStatementAst] -or
                    $candidate -is [Management.Automation.Language.CommandAst] -or
                    $candidate -is [Management.Automation.Language.InvokeMemberExpressionAst]
            }, $true)) {
                $key = $null
                if ($node -is [Management.Automation.Language.AssignmentStatementAst]) {
                    if ($node.Left -is [Management.Automation.Language.VariableExpressionAst]) {
                        $key = 'assign:' + $node.Left.VariablePath.UserPath
                    }
                    elseif ($node.Left -is [Management.Automation.Language.MemberExpressionAst] -and
                        $node.Left.Static -and $node.Left.Expression -is [Management.Automation.Language.TypeExpressionAst]) {
                        $key = 'member:' + $node.Left.Expression.TypeName.FullName + ':' + $node.Left.Member.Value
                    }
                }
                elseif ($node -is [Management.Automation.Language.CommandAst]) {
                    $key = 'command:' + $node.GetCommandName()
                }
                elseif ($node.Static -and $node.Expression -is [Management.Automation.Language.TypeExpressionAst]) {
                    $key = 'static:' + $node.Expression.TypeName.FullName + ':' + $node.Member.Value
                }
                if ($null -eq $key) { continue }
                $statement = $node
                while ($null -ne $statement.Parent -and -not [object]::ReferenceEquals($statement.Parent, $setupTry.Body)) {
                    $statement = $statement.Parent
                }
                if (-not $operations.ContainsKey($key)) { $operations[$key] = @() }
                $operations[$key] += $statement
            }
            $anchoredStatements = @{}
            $anchorCount = 0
            for ($index = 0; $index -lt 11; $index++) {
                $start = $assignments[$index].Extent.EndOffset
                $end = if ($index -lt 10) { $assignments[$index + 1].Extent.StartOffset } else { $setupTry.Body.Extent.EndOffset }
                foreach ($key in $requiredOperations[$index]) {
                    if (-not $operations.ContainsKey($key) -or $operations[$key].Count -ne 1) {
                        throw 'setup-order: A required semantic operation is absent or duplicated.'
                    }
                    $operation = $operations[$key][0]
                    if ($operation.Extent.StartOffset -le $start -or $operation.Extent.EndOffset -ge $end) {
                        throw 'setup-order: A stage does not precede and enclose its corresponding operation.'
                    }
                    $anchorCount++
                    $anchoredStatements[$operation.Extent.StartOffset] = $operation
                }
            }
            if ($anchorCount -ne 20 -or $anchoredStatements.Count -ne 19 -or
                $setupTry.Body.Statements.Count -ne 29 -or $syntax.EndBlock.Statements.Count -ne 4) {
                throw 'setup-operations: Setup contains an unanchored operation.'
            }
            $admittedAssignments = @{}
            foreach ($assignment in $assignments[1..10]) { $admittedAssignments[$assignment.Extent.StartOffset] = $true }
            foreach ($statement in $setupTry.Body.Statements) {
                if (-not $admittedAssignments.ContainsKey($statement.Extent.StartOffset) -and
                    -not $anchoredStatements.ContainsKey($statement.Extent.StartOffset)) {
                    throw 'setup-operations: Setup contains an unanchored operation.'
                }
            }
            function Assert-PspktSetupTokenSequence {
                param([object[]]$ActualTokens, [object[]]$ExpectedTokens, [string]$Reason)
                if ($ExpectedTokens.Count -ne $ActualTokens.Count) { throw $Reason }
                for ($tokenIndex = 0; $tokenIndex -lt $ExpectedTokens.Count; $tokenIndex++) {
                    if ($ExpectedTokens[$tokenIndex].Kind -ne $ActualTokens[$tokenIndex].Kind -or
                        -not [string]::Equals($ExpectedTokens[$tokenIndex].Text,
                            $ActualTokens[$tokenIndex].Text, [StringComparison]::Ordinal)) {
                        throw $Reason
                    }
                }
            }
            $expectedOperationSource = @'
$ErrorActionPreference = 'Stop'
$diagnosticMessages = @()
$encoding = [Text.UTF8Encoding]::new($false, $true)
$contractBytes = [IO.File]::ReadAllBytes((Join-Path $env:GITHUB_WORKSPACE 'certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'))
. ([scriptblock]::Create($encoding.GetString($contractBytes)))
$diagnosticMessages = @(Get-PspktEvidenceDiagnosticMessages -Snapshot (Get-PspktEvidenceSourceSnapshot -RepositoryRoot $env:GITHUB_WORKSPACE))
$toolRoot = Join-Path $env:RUNNER_TEMP ('pspkt-pester-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($toolRoot)
$env:TEMP = $toolRoot
$env:TMP = $toolRoot
$package = Join-Path $toolRoot 'pester.zip'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/package/Pester/5.3.3' -OutFile $package
if ([IO.FileInfo]::new($package).Length -ne 271297) { throw 'pester-package: Pinned Pester 5.3.3 package differs.' }
Assert-PspktEvidencePesterPackage -Bytes ([IO.File]::ReadAllBytes($package))
$compressionIdentity = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'System.IO.Compression.FileSystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089' } else { 'System.IO.Compression.ZipFile' }
[void][Reflection.Assembly]::Load($compressionIdentity)
[IO.Compression.ZipFile]::ExtractToDirectory($package, (Join-Path $toolRoot 'module'))
$manifest = Join-Path $toolRoot 'module\Pester.psd1'
if (-not [IO.File]::Exists($manifest)) { throw 'Pester manifest is absent.' }
[IO.File]::AppendAllText($env:GITHUB_ENV, 'PSPKT_PESTER_MANIFEST=' + $manifest + "`n", $encoding)
'@
            $expectedTokens = $null
            $expectedErrors = $null
            $expectedSyntax = [Management.Automation.Language.Parser]::ParseInput(
                $expectedOperationSource, [ref]$expectedTokens, [ref]$expectedErrors)
            $actualStatements = @($syntax.EndBlock.Statements[0..1]) +
                @($anchoredStatements.Values | Sort-Object { $_.Extent.StartOffset })
            if (@($expectedErrors).Count -ne 0 -or $expectedSyntax.EndBlock.Statements.Count -ne 21 -or
                $actualStatements.Count -ne 21 -or
                -not [object]::ReferenceEquals($syntax.EndBlock.Statements[2], $assignments[0]) -or
                -not [object]::ReferenceEquals($syntax.EndBlock.Statements[3], $setupTry)) {
                throw 'setup-operations: Admitted operation templates differ.'
            }
            for ($statementIndex = 0; $statementIndex -lt 21; $statementIndex++) {
                $expectedStatement = $expectedSyntax.EndBlock.Statements[$statementIndex]
                $actualStatement = $actualStatements[$statementIndex]
                $expectedStatementTokens = @($expectedTokens | Where-Object {
                    $_.Kind -notin @('NewLine', 'EndOfInput', 'LineContinuation') -and
                        $_.Extent.StartOffset -ge $expectedStatement.Extent.StartOffset -and
                        $_.Extent.EndOffset -le $expectedStatement.Extent.EndOffset
                })
                $actualStatementTokens = @($tokens | Where-Object {
                    $_.Kind -notin @('NewLine', 'EndOfInput', 'LineContinuation') -and
                        $_.Extent.StartOffset -ge $actualStatement.Extent.StartOffset -and
                        $_.Extent.EndOffset -le $actualStatement.Extent.EndOffset
                })
                Assert-PspktSetupTokenSequence -ActualTokens $actualStatementTokens -ExpectedTokens $expectedStatementTokens `
                    -Reason 'setup-operations: An anchored statement contains an unadmitted expression.'
            }
            $catch = $setupTry.CatchClauses[0].Body
            if ($catch.Statements.Count -ne 2 -or $catch.Statements[0] -isnot [Management.Automation.Language.IfStatementAst] -or
                $catch.Statements[1] -isnot [Management.Automation.Language.ExitStatementAst] -or
                $catch.Statements[1].Pipeline -isnot [Management.Automation.Language.PipelineAst] -or
                $catch.Statements[1].Pipeline.PipelineElements.Count -ne 1 -or
                $catch.Statements[1].Pipeline.PipelineElements[0] -isnot [Management.Automation.Language.CommandExpressionAst] -or
                $catch.Statements[1].Pipeline.PipelineElements[0].Redirections.Count -ne 0 -or
                $catch.Statements[1].Pipeline.PipelineElements[0].Expression -isnot [Management.Automation.Language.ConstantExpressionAst] -or
                $catch.Statements[1].Pipeline.PipelineElements[0].Expression.Value -ne 1) {
                throw 'setup-fallback: Exactly one formatter choice followed by exit one is required.'
            }
            $choice = $catch.Statements[0]
            if ($choice.Clauses.Count -ne 1 -or $null -eq $choice.ElseClause) { throw 'setup-fallback: A guarded fixed fallback is required.' }
            $condition = $choice.Clauses[0].Item1
            if ($condition -isnot [Management.Automation.Language.PipelineAst] -or $condition.PipelineElements.Count -ne 1 -or
                $condition.PipelineElements[0] -isnot [Management.Automation.Language.CommandAst]) {
                throw 'setup-fallback: Formatter availability must be tested directly.'
            }
            $availability = $condition.PipelineElements[0]
            if ($availability.InvocationOperator -ne [Management.Automation.Language.TokenKind]::Unknown -or
                $availability.Redirections.Count -ne 0 -or $availability.GetCommandName() -cne 'Get-Command' -or
                $availability.CommandElements.Count -ne 4 -or
                $availability.CommandElements[1] -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
                $availability.CommandElements[1].Value -cne 'Get-PspktEvidencePesterSetupFailureMessage' -or
                $availability.CommandElements[2] -isnot [Management.Automation.Language.CommandParameterAst] -or
                $null -ne $availability.CommandElements[2].Argument -or
                $availability.CommandElements[2].ParameterName -cne 'ErrorAction' -or
                $availability.CommandElements[3] -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
                $availability.CommandElements[3].Value -cne 'SilentlyContinue') {
                throw 'setup-fallback: Formatter availability contract differs.'
            }
            $branches = @($choice.Clauses[0].Item2, $choice.ElseClause)
            for ($index = 0; $index -lt 2; $index++) {
                $writes = @($branches[$index].FindAll({ param($node)
                    $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -ceq 'WriteLine'
                }, $true))
                if ($branches[$index].Statements.Count -ne 1 -or $writes.Count -ne 1 -or $writes[0].Arguments.Count -ne 1 -or
                    $branches[$index].Statements[0] -isnot [Management.Automation.Language.PipelineAst] -or
                    $branches[$index].Statements[0].PipelineElements.Count -ne 1 -or
                    $branches[$index].Statements[0].PipelineElements[0] -isnot [Management.Automation.Language.CommandExpressionAst] -or
                    $branches[$index].Statements[0].PipelineElements[0].Redirections.Count -ne 0 -or
                    -not [object]::ReferenceEquals($branches[$index].Statements[0].PipelineElements[0].Expression, $writes[0]) -or
                    $writes[0].Expression -isnot [Management.Automation.Language.MemberExpressionAst] -or
                    -not $writes[0].Expression.Static -or $writes[0].Expression.Member.Value -cne 'Error' -or
                    $writes[0].Expression.Expression -isnot [Management.Automation.Language.TypeExpressionAst] -or
                    $writes[0].Expression.Expression.TypeName.FullName -cne 'Console') {
                    throw 'setup-fallback: Each branch must emit exactly one stderr diagnostic.'
                }
                $argument = $writes[0].Arguments[0]
                if ($index -eq 0) {
                    if ($argument -isnot [Management.Automation.Language.ParenExpressionAst] -or
                        $argument.Pipeline -isnot [Management.Automation.Language.PipelineAst] -or
                        $argument.Pipeline.PipelineElements.Count -ne 1 -or
                        $argument.Pipeline.PipelineElements[0] -isnot [Management.Automation.Language.CommandAst]) {
                        throw 'setup-fallback: Available formatter must be the exact current-stage call.'
                    }
                    $formatter = $argument.Pipeline.PipelineElements[0]
                    if ($formatter.InvocationOperator -ne [Management.Automation.Language.TokenKind]::Unknown -or
                        $formatter.Redirections.Count -ne 0 -or $formatter.CommandElements.Count -ne 3 -or
                        $formatter.CommandElements[0] -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
                        $formatter.CommandElements[0].Value -cne 'Get-PspktEvidencePesterSetupFailureMessage' -or
                        $formatter.CommandElements[1] -isnot [Management.Automation.Language.CommandParameterAst] -or
                        $formatter.CommandElements[1].ParameterName -cne 'Stage' -or $null -ne $formatter.CommandElements[1].Argument -or
                        $formatter.CommandElements[2] -isnot [Management.Automation.Language.VariableExpressionAst] -or
                        $formatter.CommandElements[2].Splatted -or $formatter.CommandElements[2].VariablePath.UserPath -cne 'setupStage') {
                        throw 'setup-fallback: Available formatter must be the exact current-stage call.'
                    }
                }
                elseif ($argument -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
                    $argument.Value -cne 'pester-setup: source-load failed.') {
                    throw 'setup-fallback: Unavailable formatter must emit only the fixed source-load reason.'
                }
            }
            $expectedCatchSource = @'
if (Get-Command Get-PspktEvidencePesterSetupFailureMessage -ErrorAction SilentlyContinue) {
    [Console]::Error.WriteLine((Get-PspktEvidencePesterSetupFailureMessage -Stage $setupStage))
} else { [Console]::Error.WriteLine('pester-setup: source-load failed.') }
exit 1
'@
            $expectedCatchTokens = $null
            $expectedCatchErrors = $null
            [void][Management.Automation.Language.Parser]::ParseInput(
                $expectedCatchSource, [ref]$expectedCatchTokens, [ref]$expectedCatchErrors)
            if (@($expectedCatchErrors).Count -ne 0) { throw 'setup-fallback: Admitted catch template must parse.' }
            $expectedCatchTokens = @($expectedCatchTokens | Where-Object { $_.Kind -notin @('NewLine', 'EndOfInput', 'LineContinuation') })
            $actualCatchTokens = @($tokens | Where-Object {
                $_.Kind -notin @('NewLine', 'EndOfInput', 'LineContinuation') -and
                    $_.Extent.StartOffset -gt $catch.Extent.StartOffset -and $_.Extent.EndOffset -lt $catch.Extent.EndOffset
            })
            Assert-PspktSetupTokenSequence -ActualTokens $actualCatchTokens -ExpectedTokens $expectedCatchTokens `
                -Reason 'setup-fallback: Catch contains an unadmitted expression.'
        }
        Assert-PspktSetupStageOrdering -SourceText $setupBlock -ExpectedStages $setupStages
        Assert-PspktSetupStageOrdering -SourceText ($setupBlock.Replace('$setupStage = ', '$setupStage    =    ').Replace('try {', "try`n{")) -ExpectedStages $setupStages
        Assert-PspktSetupStageOrdering -SourceText ($setupBlock.Replace("`r`n", "`n").Replace("`n", "`r`n")) -ExpectedStages $setupStages
        for ($index = 0; $index -lt 10; $index++) {
            $first = "'" + $setupStages[$index] + "'"
            $second = "'" + $setupStages[$index + 1] + "'"
            $reordered = $setupBlock.Replace($first, "'stage-placeholder'").Replace($second, $first).Replace("'stage-placeholder'", $second)
            { Assert-PspktSetupStageOrdering -SourceText $reordered -ExpectedStages $setupStages } |
                Should -Throw '*setup-order*'
        }
        $setupTokens = $null
        $setupErrors = $null
        $setupSyntax = [Management.Automation.Language.Parser]::ParseInput($setupBlock, [ref]$setupTokens, [ref]$setupErrors)
        $stageAssignments = @($setupSyntax.FindAll({ param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq 'setupStage'
        }, $true) | Sort-Object { $_.Extent.StartOffset })
        $setupTry = @($setupSyntax.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[0]
        foreach ($assignment in $stageAssignments) {
            $following = @($setupTry.Body.Statements | Where-Object { $_.Extent.StartOffset -gt $assignment.Extent.EndOffset })[0]
            $late = $setupBlock.Remove($assignment.Extent.StartOffset, $assignment.Extent.Text.Length)
            $late = $late.Insert($following.Extent.EndOffset - $assignment.Extent.Text.Length, "`n" + $assignment.Extent.Text)
            { Assert-PspktSetupStageOrdering -SourceText $late -ExpectedStages $setupStages } | Should -Throw '*setup-order*'
        }
        $wrongFallback = $setupBlock.Replace("'pester-setup: source-load failed.'", "'pester-setup: download failed.'")
        { Assert-PspktSetupStageOrdering -SourceText $wrongFallback -ExpectedStages $setupStages } | Should -Throw '*setup-fallback*'
        $wrongStageArgument = $setupBlock.Replace('-Stage $setupStage', "-Stage 'source-load'")
        { Assert-PspktSetupStageOrdering -SourceText $wrongStageArgument -ExpectedStages $setupStages } | Should -Throw '*setup-fallback*'
        $availabilityCondition = $setupTry.CatchClauses[0].Body.Statements[0].Clauses[0].Item1.Extent.Text
        $invertedAvailability = $setupBlock.Replace($availabilityCondition, '-not (' + $availabilityCondition + ')')
        { Assert-PspktSetupStageOrdering -SourceText $invertedAvailability -ExpectedStages $setupStages } | Should -Throw '*setup-fallback*'
        $successExit = $setupBlock.Replace('exit 1', 'exit 0')
        { Assert-PspktSetupStageOrdering -SourceText $successExit -ExpectedStages $setupStages } | Should -Throw '*setup-fallback*'
        $formatterCall = '(Get-PspktEvidencePesterSetupFailureMessage -Stage $setupStage)'
        $setupMutations = @(
            [pscustomobject]@{
                Source = $setupBlock.Replace($formatterCall, $formatterCall + ' + $_.Exception.Message')
                Reason = 'setup-fallback: Available formatter must be the exact current-stage call.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace('$setupStage = ''package-length''',
                    'Invoke-RestMethod -Uri ''https://untrusted.invalid/additional-request''' + "`n" + '$setupStage = ''package-length''')
                Reason = 'setup-operations: Setup contains an unanchored operation.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace('[void][Reflection.Assembly]::Load($compressionIdentity)',
                    'try { [void][Reflection.Assembly]::Load($compressionIdentity) } catch { [Console]::Error.WriteLine($_.Exception.Message) }')
                Reason = 'setup-exceptions: Only the admitted outer try/catch is allowed.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace('[void][Reflection.Assembly]::Load($compressionIdentity)',
                    '& { trap { [Console]::Error.WriteLine($_.Exception.Message) }; [void][Reflection.Assembly]::Load($compressionIdentity) }')
                Reason = 'setup-exceptions: Only the admitted outer try/catch is allowed.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace($formatterCall, $formatterCall + '.ToString()')
                Reason = 'setup-fallback: Available formatter must be the exact current-stage call.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace('-Stage $setupStage', '-Stage $otherStage')
                Reason = 'setup-fallback: Available formatter must be the exact current-stage call.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace("'System.IO.Compression.ZipFile'",
                    "'System.IO.Compression.ZipFile'; Invoke-RestMethod -Uri 'https://untrusted.invalid/additional-request'")
                Reason = 'setup-operations: An anchored statement contains an unadmitted expression.'
            }
            [pscustomobject]@{
                Source = $setupBlock.Replace("'System.IO.Compression.ZipFile'",
                    "'System.IO.Compression.ZipFile'; [Console]::Error.WriteLine(`$_.Exception.Message)")
                Reason = 'setup-operations: An anchored statement contains an unadmitted expression.'
            }
        )
        foreach ($mutation in $setupMutations) {
            [string]::Equals($mutation.Source, $setupBlock, [StringComparison]::Ordinal) | Should -BeFalse
            $mutationTokens = $null
            $mutationErrors = $null
            [void][Management.Automation.Language.Parser]::ParseInput($mutation.Source, [ref]$mutationTokens, [ref]$mutationErrors)
            @($mutationErrors).Count | Should -Be 0
            $reason = ''
            try { Assert-PspktSetupStageOrdering -SourceText $mutation.Source -ExpectedStages $setupStages }
            catch { $reason = $_.Exception.Message }
            $reason | Should -BeExactly $mutation.Reason
        }
        Assert-PspktEvidenceWorkflowDependencies -DesktopResult success -CoreResult success
        { Assert-PspktEvidenceWorkflowDependencies -DesktopResult failure -CoreResult success } |
            Should -Throw '*workflow-dependency: Windows PowerShell validation job did not succeed.*'
        { Assert-PspktEvidenceWorkflowDependencies -DesktopResult success -CoreResult skipped } |
            Should -Throw '*workflow-dependency: PowerShell 7 validation job did not succeed.*'
        $aggregateMatch = [regex]::Match($ManifestRecordsByRole.WorkflowText, '(?m)^        run: \|\r?\n((?:          .*\r?\n)+)')
        $aggregateMatch.Success | Should -BeTrue
        $aggregateBody = $aggregateMatch.Groups[1].Value
        $formatterPosition = $aggregateBody.IndexOf('Get-PspktEvidenceDiagnosticMessages', [StringComparison]::Ordinal)
        $dependencyPosition = $aggregateBody.IndexOf('Assert-PspktEvidenceWorkflowDependencies', [StringComparison]::Ordinal)
        ($formatterPosition -ge 0 -and $dependencyPosition -gt $formatterPosition) | Should -BeTrue
        $ManifestRecordsByRole.WorkflowText.Contains('formatter is unavailable') | Should -BeFalse
        $ManifestRecordsByRole.WorkflowText.Contains('workflow-failure: Evidence runtime workflow step failed.') | Should -BeTrue
        $expectedCheckout = [pscustomobject]@{
            Repository = 'actions/checkout'
            ReleaseTag = 'v7.0.1'
            Version = '7.0.1'
            CommitSha = '3d3c42e5aac5ba805825da76410c181273ba90b1'
            Runtime = 'node24'
            MinimumRunnerVersion = '2.327.1'
            ReleaseId = 356804776
            PublishedUtc = '2026-07-20T15:10:05Z'
            ActionManifestBlob = '5b0524f730db83f9513c18ab31a6c086c7239076'
            ActionManifestBytes = 5144
            ActionManifestSha256 = 'd59219cb79590abdb877deaa14e3b65a00c05318bf5a6f3b989b9162b5d08c35'
        }
        $actualCheckout = (Get-PspktEvidenceRuntimeContract).CheckoutAction
        @($actualCheckout.PSObject.Properties).Count | Should -Be 11
        foreach ($property in $expectedCheckout.PSObject.Properties) {
            $actualProperty = $actualCheckout.PSObject.Properties[$property.Name]
            $actualProperty | Should -Not -BeNullOrEmpty
            [string]::Equals($actualProperty.Name, $property.Name, [StringComparison]::Ordinal) | Should -BeTrue
            $actualProperty.Value.GetType().FullName | Should -BeExactly $property.Value.GetType().FullName
            [string]::Equals([string]$actualProperty.Value, [string]$property.Value, [StringComparison]::Ordinal) | Should -BeTrue
        }
        $checkoutUse = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
        [regex]::Matches($ManifestRecordsByRole.WorkflowText, '(?m)^      - uses: ' + [regex]::Escape($checkoutUse) + '\r?$').Count |
            Should -Be 3
        foreach ($property in $expectedCheckout.PSObject.Properties) {
            $row = '| Checkout' + $property.Name + ' | ' + $property.Value + ' |'
            [regex]::Matches($ManifestRecordsByRole.DocumentationText, '(?m)^' + [regex]::Escape($row) + '\r?$').Count |
                Should -Be 1
            $changedDocumentation = $ManifestRecordsByRole.DocumentationText.Replace($row, '| Checkout' + $property.Name + ' | unexpected |')
            { Assert-PspktEvidenceDocumentation -Text $changedDocumentation -RuntimeAssembly $RuntimeAssembly } |
                Should -Throw '*documentation-parity: A required unique documentation row differs.*'
        }
        $ManifestRecordsByRole.DocumentationText.Contains('https://github.com/actions/checkout/releases/tag/v7.0.1') | Should -BeTrue
        $ManifestRecordsByRole.DocumentationText.Contains(
            'https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml') | Should -BeTrue
        foreach ($rejectedCheckout in @('v7', 'v7.0.1', '11bd71901bbe5b1630ceea73d27597364c9af683', ('0' * 40))) {
            $changedWorkflow = $ManifestRecordsByRole.WorkflowText.Replace($checkoutUse, 'actions/checkout@' + $rejectedCheckout)
            { Assert-PspktEvidenceWorkflow -SourceText $changedWorkflow } |
                Should -Throw '*workflow-contract: An action is not pinned to the reviewed commit.*'
        }
        $checkoutStep = '      - uses: ' + $checkoutUse + "`n" + '        with:' + "`n" + '          persist-credentials: false' + "`n"
        $checkoutStepPattern = [regex]::new([regex]::Escape($checkoutStep))
        foreach ($changedWorkflow in @(
            $checkoutStepPattern.Replace($ManifestRecordsByRole.WorkflowText, '', 1),
            $checkoutStepPattern.Replace($ManifestRecordsByRole.WorkflowText, $checkoutStep + $checkoutStep, 1)
        )) {
            { Assert-PspktEvidenceWorkflow -SourceText $changedWorkflow } |
                Should -Throw '*workflow-contract: Pinned actions or cancellation gates differ.*'
        }
        [regex]::Matches($ManifestRecordsByRole.WorkflowText, 'if: \$\{\{ !cancelled\(\) \}\}').Count | Should -Be 3
        $ManifestRecordsByRole.WorkflowText.Contains('Assert-PspktEvidencePesterPackage') | Should -BeTrue
        $ManifestRecordsByRole.WorkflowText.Contains('Write-PspktEvidenceFailureDiagnostics') | Should -BeTrue
        { Assert-PspktEvidencePesterPackage -Bytes ([byte[]]@(1)) } |
            Should -Throw '*pester-package: Pinned Pester 5.3.3 package differs.*'
        { Assert-PspktEvidencePesterPackage -Bytes ([byte[]]::new(271297)) } |
            Should -Throw '*pester-package: Pinned Pester 5.3.3 package differs.*'
        $ManifestRecordsByRole.DocumentationText.Contains(
            '| Pester 5.3.3 | 271297 | bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579 |') | Should -BeTrue
        { Assert-PspktEvidenceWorkflow -SourceText $ManifestRecordsByRole.WorkflowText.Replace(
            '!cancelled()', 'always()') } | Should -Throw '*workflow-contract*'
        [regex]::IsMatch($ManifestRecordsByRole.WorkflowText,
            'System.IO.Compression.FileSystem, Version=4\.0\.0\.0, Culture=neutral, PublicKeyToken=b77a5c561934e089') | Should -BeTrue
        $unusedDrives = @(90..65 | ForEach-Object { [string][char]$_ } |
            Where-Object { -not (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) })
        $unusedDrives.Count | Should -BeGreaterThan 0
        $syntheticDriveRoot = $unusedDrives[0] + ':\'
        @(Get-PSDrive -Name $unusedDrives[0] -ErrorAction SilentlyContinue).Count | Should -Be 0
        $environmentState = @{}
        foreach ($name in @('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA')) {
            $environmentState[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        try {
            $env:GITHUB_RUN_ID = 'synthetic-aggregate-test'
            $env:GITHUB_RUN_ATTEMPT = '1'
            $env:GITHUB_SHA = (Get-PspktEvidenceRuntimeContract).BaseCommit
            $receipts = @()
            $contract = Get-PspktEvidenceRuntimeContract
            for ($slot = 0; $slot -lt 4; $slot++) {
                $fixture = New-PspktEvidenceValidationResultFixture -Contract $contract -CaseId healthy
                $result = $fixture.Captured[0]
                $runId = ($slot + 1).ToString('x32')
                $hostSlot = if ($slot -lt 2) { 'windows_ps51' } else { 'powershell_7' }
                $edition = if ($slot -lt 2) { 'Desktop' } else { 'Core' }
                $sourceKind = if ($slot % 2 -eq 0) { 'checkout' } else { 'export' }
                $runnerTemp = [IO.Path]::Combine($syntheticDriveRoot, 'synthetic\temp')
                $workspace = [IO.Path]::Combine($syntheticDriveRoot, 'synthetic\source')
                $sourceRoot = if ($sourceKind -ceq 'checkout') { $workspace } else { [IO.Path]::Combine($runnerTemp, 'export-' + $slot) }
                $workRoot = [IO.Path]::Combine($runnerTemp, 'work-' + $slot)
                $runRoot = [IO.Path]::Combine($workRoot, 'evidence-runtime-' + $runId)
                $result.RunId = $runId
                $result.HostEdition = $edition
                $result.HostVersion = if ($edition -ceq 'Desktop') { '5.1.0.0' } else { '7.0.0' }
                $result.RepositoryRoot = $sourceRoot
                $result.WorkRoot = $workRoot
                $result.RunRoot = $runRoot
                $result.SourceManifestSha256 = $ManifestRecordsByRole.SourceSnapshot.ManifestSha256
                for ($roleIndex = 0; $roleIndex -lt 5; $roleIndex++) {
                    $role = $contract.AssemblyRoles[$roleIndex]
                    $simpleName = if ($role -ceq 'Bootstrap') { 'PspktEvidenceBootstrap_' + $runId } else { 'PspktEvidenceRuntime_' + $runId }
                    if ($roleIndex -ge 2) { $simpleName += '_' + $role }
                    $identity = $simpleName + ', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'
                    $result.CompilationRecords[$roleIndex].AssemblyIdentity = $identity
                    $result.CompilationRecords[$roleIndex].Sources = $CompileCensus[$roleIndex].Sources
                    $result.LoadRecords[$roleIndex].AssemblyIdentity = $identity
                    $result.LoadRecords[$roleIndex].ImagePath = [IO.Path]::Combine($runRoot, $simpleName + '.dll')
                    $result.LoadRecords[$roleIndex].Context = if ($edition -ceq 'Desktop') { 'LoadFrom' } else { 'Default' }
                    if ($roleIndex -ge 2) {
                        $result.MutantResults[$roleIndex - 2].AssemblyIdentity = $identity
                        $result.MutantResults[$roleIndex - 2].Transform = $MutantBuilds[$roleIndex - 2].Transform
                    }
                }
                $receipt = [pscustomobject]@{
                    SchemaId = 'PspktEvidenceRuntimeCiReceiptV1'; SchemaVersion = 1
                    Slot = $hostSlot + '/' + $sourceKind; HostSlot = $hostSlot; SourceKind = $sourceKind
                    WorkflowRunId = $env:GITHUB_RUN_ID; WorkflowRunAttempt = $env:GITHUB_RUN_ATTEMPT; Revision = $env:GITHUB_SHA
                    BaseCommit = $contract.BaseCommit; HostEdition = $edition; HostVersion = $result.HostVersion
                    SourceRoot = $sourceRoot; WorkRoot = $workRoot; RunRoot = $runRoot
                    RunnerTemp = $runnerTemp; OriginalWorkspace = $workspace; RunId = $runId
                    SourceManifestSha256 = $result.SourceManifestSha256; Result = $result
                    InvocationEvidence = [pscustomobject]@{
                        CompilationRecords = $result.CompilationRecords; LoadRecords = $result.LoadRecords; MutantResults = $result.MutantResults
                    }
                }
                $receipts += $receipt | ConvertTo-Json -Depth 30 -Compress
            }
            $probeGroups = @()
            foreach ($hostSlot in @('windows_ps51', 'powershell_7')) {
                $group = @()
                foreach ($caseId in @('returned-failure', 'malformed-result', 'missing-result', 'multiple-results', 'count-mismatch')) {
                    $probe = Invoke-PspktEvidenceBoundaryProbe -Contract $contract -CaseId $caseId
                    $receipt = New-PspktEvidenceProbeReceipt -Probe $probe -HostSlot $hostSlot
                    $receipt | Add-Member -NotePropertyName RawOutcome -NotePropertyValue 'failure'
                    $group += $receipt
                }
                $probeGroups += ConvertTo-Json -InputObject $group -Depth 10 -Compress
            }
            Assert-PspktEvidenceCiAggregate -ReceiptJson $receipts -ProbeJson $probeGroups -SourceSnapshot $ManifestRecordsByRole.SourceSnapshot
            $duplicated = [string[]]$receipts.Clone()
            $duplicated[0] = $duplicated[0].Replace('"Outcome":"ValidationSucceeded"', '"Outcome":"ValidationFailed","Outcome":"ValidationSucceeded"')
            { Assert-PspktEvidenceCiAggregate -ReceiptJson $duplicated -ProbeJson $probeGroups -SourceSnapshot $ManifestRecordsByRole.SourceSnapshot } |
                Should -Throw '*receipt-json*'
            foreach ($fault in @('missing-call', 'count-mismatch', 'duplicate-slot', 'false-cleanup', 'mixed-run-attempt')) {
                $changed = [string[]]$receipts.Clone()
                $candidate = $changed[0] | ConvertFrom-Json
                $expectedReason = 'AggregatePostconditions'
                if ($fault -ceq 'missing-call') { $changed = [string[]]$changed[0..2] }
                elseif ($fault -ceq 'count-mismatch') { $candidate.Result.CompilationCount = 4; $expectedReason = 'ResultCounts' }
                elseif ($fault -ceq 'duplicate-slot') { $candidate.Slot = 'powershell_7/checkout' }
                elseif ($fault -ceq 'mixed-run-attempt') { $candidate.WorkflowRunAttempt = '2' }
                else { $candidate.Result.Cleanup.ResiduePassed = $false; $expectedReason = 'ResultPostconditions' }
                $changed[0] = $candidate | ConvertTo-Json -Depth 30 -Compress
                { Assert-PspktEvidenceCiAggregate -ReceiptJson $changed -ProbeJson $probeGroups -SourceSnapshot $ManifestRecordsByRole.SourceSnapshot } |
                    Should -Throw ('*' + $expectedReason + '*')
            }
            $env:GITHUB_RUN_ATTEMPT = '2'
            { Assert-PspktEvidenceCiAggregate -ReceiptJson $receipts -ProbeJson $probeGroups -SourceSnapshot $ManifestRecordsByRole.SourceSnapshot } |
                Should -Throw '*AggregatePostconditions*'
            $rerunReceipts = @($receipts | ForEach-Object {
                $record = $_ | ConvertFrom-Json
                $record.WorkflowRunAttempt = '2'
                $record | ConvertTo-Json -Depth 30 -Compress
            })
            $rerunProbes = @($probeGroups | ForEach-Object {
                $group = @(ConvertFrom-PspktEvidenceReceiptJson -Json $_)
                foreach ($probe in $group) { $probe.WorkflowRunAttempt = '2' }
                ConvertTo-Json -InputObject $group -Depth 10 -Compress
            })
            Assert-PspktEvidenceCiAggregate -ReceiptJson $rerunReceipts -ProbeJson $rerunProbes -SourceSnapshot $ManifestRecordsByRole.SourceSnapshot
            @(Get-PSDrive -Name $unusedDrives[0] -ErrorAction SilentlyContinue).Count | Should -Be 0
        }
        finally {
            foreach ($name in $environmentState.Keys) {
                [Environment]::SetEnvironmentVariable($name, $environmentState[$name], 'Process')
            }
        }
    }
    It 'Requires registry absence and complete owned resource cleanup' {
        Assert-PspktEvidenceRegistryAbsent
        Assert-PspktEvidenceOwnedTestStorage -ArtifactRoot $ArtifactRoot
        Set-Variable -Name TestRegistry -Value $null -Scope Local
        try { { Assert-PspktEvidenceRegistryAbsent } | Should -Throw '*registry-state*' }
        finally { Remove-Variable -Name TestRegistry -Scope Local }
        $ownedRoot = Join-Path $TestDrive 'residue-check'
        [void][IO.Directory]::CreateDirectory($ownedRoot)
        Assert-PspktEvidenceRunResidue -ArtifactRoot $ownedRoot -Images @()
        $unexpected = Join-Path $ownedRoot 'unexpected'
        [IO.File]::WriteAllBytes($unexpected, [byte[]]@(1))
        try { { Assert-PspktEvidenceRunResidue -ArtifactRoot $ownedRoot -Images @() } | Should -Throw '*run-residue*' }
        finally { [IO.File]::Delete($unexpected); [IO.Directory]::Delete($ownedRoot) }
    }
    It 'Separates admitted sources from outputs and rejects obsolete surfaces' {
        $planMarkerPattern = '(?i)\b(?:B[0-9]{2}|R[0-9]+)\b'
        [regex]::IsMatch($ManifestRecordsByRole.DocumentationText, $planMarkerPattern) | Should -BeFalse
        [regex]::IsMatch($ManifestRecordsByRole.ValidatorText, $planMarkerPattern) | Should -BeFalse
        Assert-PspktEvidenceStableIdentifiers -SourceText 'F-7/F-8/F-9 Phase4 Rsa3072Signature 0xB05 FixtureB05 kind-05-profile-1 rejection-boundaries workflow-invocations'
        foreach ($marker in @(('B' + '05'), ('B' + '29'), ('r' + '8-validation:'), ('R' + '12'))) {
            { Assert-PspktEvidenceStableIdentifiers -SourceText $marker } |
                Should -Throw '*source-marker: Ephemeral plan identifiers are not admitted in source text.*'
        }
        Assert-PspktEvidenceSourceClosure -Snapshot $ManifestRecordsByRole.SourceSnapshot
        $snapshot = $ManifestRecordsByRole.SourceSnapshot
        @($snapshot.Files.Keys).Count | Should -Be (@(Get-PspktEvidenceSourcePaths).Count)
        $snapshot.ManifestSha256 | Should -Match '^[0-9a-f]{64}$'
        $snapshot.Files['certification\evidence-runtime\.gitattributes'].Sha256 |
            Should -BeExactly '4a67ad8dcb538c0e8723e84abc535e60064dcc610921a54a403d14a0ecf0ec9b'
        $snapshot.Files['.github\workflows\.gitattributes'].Sha256 |
            Should -BeExactly 'e9143abc8b396c78937f0b59af6dd8dd25b5099b3f2734710356c7191b0034d7'
        $sourcePath = 'certification\evidence-runtime\lib\EvidenceAuthorityJsonReader.cs'
        $original = $snapshot.Files[$sourcePath]
        $changedBytes = [byte[]]($original.Bytes + @(10))
        $changedFiles = $snapshot.Files.Clone()
        $changedFiles[$sourcePath] = [pscustomobject]@{
            Role = $original.Role; Path = $sourcePath; Length = $changedBytes.Length
            Sha256 = Get-PspktEvidenceBytesDigest -Bytes $changedBytes; Bytes = $changedBytes
        }
        $changedSnapshot = [pscustomobject]@{ Files = $changedFiles; Records = $snapshot.Records; ManifestSha256 = $snapshot.ManifestSha256 }
        { Assert-PspktEvidenceSourceClosure -Snapshot $changedSnapshot } | Should -Throw '*source-pin*'
        $copyRoot = Join-Path $TestDrive 'l'
        $createdFiles = @()
        try {
            foreach ($relativePath in @('certification\evidence-runtime\README.md', 'certification\evidence-runtime\.gitattributes')) {
                $expectedMessage = 'source-length: Retained byte length differs for ' + $relativePath + '.'
                $copyPath = Join-Path $copyRoot $relativePath
                $copyPath.Length | Should -BeLessOrEqual 240
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($copyPath))
                $createdFiles += $copyPath
                [IO.File]::WriteAllBytes($copyPath, [byte[]]($snapshot.Files[$relativePath].Bytes + @(10)))
                $failure = $null
                try { [void](Read-PspktEvidencePinnedSource -RepositoryRoot $copyRoot -RelativePath $relativePath) }
                catch { $failure = $_.Exception }
                ($null -ne $failure) | Should -BeTrue
                $failure.Message | Should -BeExactly $expectedMessage
                @(Get-PspktEvidenceFailureDiagnostics -Exception $failure)[0] | Should -BeExactly $expectedMessage
                $preloaded = @{}
                foreach ($name in $snapshot.Files.Keys) { $preloaded[$name] = $snapshot.Files[$name].Bytes }
                $preloaded[$relativePath] = [byte[]]($preloaded[$relativePath] + @(10))
                { Get-PspktEvidenceSourceSnapshot -RepositoryRoot $ManifestRecordsByRole.RepositoryRoot -PreloadedBytes $preloaded } |
                    Should -Throw ('*' + $expectedMessage)
            }
            { Read-PspktEvidencePinnedSource -RepositoryRoot $copyRoot -RelativePath '..\untrusted-marker' } |
                Should -Throw '*source-membership: Path is outside the closed source set.*'
        }
        finally {
            foreach ($path in $createdFiles) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
            foreach ($path in @((Join-Path $copyRoot 'certification\evidence-runtime'), (Join-Path $copyRoot 'certification'), $copyRoot)) {
                if ([IO.Directory]::Exists($path)) { [IO.Directory]::Delete($path) }
            }
        }
        $contractText = [Text.UTF8Encoding]::new($false, $true).GetString(
            $snapshot.Files['certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'].Bytes)
        $parseTokens = $null
        $parseErrors = $null
        $contractSyntax = [Management.Automation.Language.Parser]::ParseInput($contractText, [ref]$parseTokens, [ref]$parseErrors)
        $reader = $contractSyntax.Find({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-PspktEvidenceBoundedFile'
        }, $true).Body.Extent.Text
        $lengthPosition = $reader.IndexOf('source-length: Retained byte length differs for ', [StringComparison]::Ordinal)
        $allocationPosition = $reader.IndexOf('$bytes = [byte[]]::new', [StringComparison]::Ordinal)
        $readPosition = $reader.IndexOf('$stream.Read(', [StringComparison]::Ordinal)
        ($lengthPosition -ge 0 -and $allocationPosition -gt $lengthPosition -and $readPosition -gt $allocationPosition) | Should -BeTrue
        (Test-PspktEvidenceDirectoryOverlap -Left $ManifestRecordsByRole.RepositoryRoot -Right $ArtifactRoot) | Should -BeFalse
    }
    It 'Rejects every failed malformed missing duplicated or incomplete result' {
        $contract = Get-PspktEvidenceRuntimeContract
        ((Get-PspktEvidenceHostSlots | ForEach-Object { $_.HostSlot + '=' + $_.Edition }) -join ',') |
            Should -BeExactly 'windows_ps51=Desktop,powershell_7=Core'
        ((Get-PspktEvidenceProbeReasons).GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) -join ',' |
            Should -BeExactly 'returned-failure=ValidationFailedOutcome,malformed-result=ResultShape,missing-result=ResultCardinality,multiple-results=ResultCardinality,count-mismatch=ResultCounts'
        $diagnosticMessages = @(Get-PspktEvidenceDiagnosticMessages -Snapshot $ManifestRecordsByRole.SourceSnapshot)
        $diagnosticMessages | Should -Contain 'pester-package: Pinned Pester 5.3.3 package differs.'
        $ManifestRecordsByRole.WorkflowText.Contains("throw 'Pester manifest is absent.'") | Should -BeTrue
        foreach ($useCatalog in @($false, $true)) {
            $messages = [string[]]@()
            if ($useCatalog) { $messages = [string[]]$diagnosticMessages }
            @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new('Pester manifest is absent.')) -AllowedMessages $messages)[0] |
                Should -BeExactly 'diagnostic-redacted: Non-capsule exception details were suppressed.'
        }
        $sourceMessage = 'source-pin: Retained bytes differ for certification\evidence-runtime\README.md.'
        foreach ($useCatalog in @($false, $true)) {
            $allowed = [string[]]@()
            if ($useCatalog) { $allowed = [string[]]$diagnosticMessages }
            @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new($sourceMessage)) -AllowedMessages $allowed)[0] |
                Should -BeExactly $sourceMessage
            $lengthMessage = 'source-length: Retained byte length differs for certification\evidence-runtime\README.md.'
            @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new($lengthMessage)) -AllowedMessages $allowed)[0] |
                Should -BeExactly $lengthMessage
            foreach ($role in @('M1', 'M2', 'M3')) {
                $roleMessage = 'mutant-survived: Independent oracle did not kill ' + $role + '.'
                @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new($roleMessage)) -AllowedMessages $allowed)[0] |
                    Should -BeExactly $roleMessage
            }
            foreach ($category in @('source-pin', 'compilation-failed', 'mutant-survived', 'authority-gate', 'setup', 'validate', 'pester-manifest', 'workflow-dependency')) {
                $unsafeMessage = $category + ': untrusted-message-marker' + [char]0 + ('x' * 4096)
                $projection = @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new($unsafeMessage)) -AllowedMessages $allowed)
                $projection.Count | Should -Be 1
                $projection[0] | Should -BeExactly ($category + ': Variable details redacted.')
                $projection[0].Length | Should -BeLessOrEqual 256
            }
        }
        foreach ($unsafeSource in @(
            'source-pin: Retained bytes differ for certification\evidence-runtime\README.md.extra.',
            'source-pin: Retained bytes differ for ..\README.md.',
            "source-pin: Retained bytes differ for certification\evidence-runtime\README.md.`nextra"
        )) {
            @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new($unsafeSource)))[0] |
                Should -BeExactly 'source-pin: Variable details redacted.'
        }
        foreach ($unsafeLength in @(
            'source-length: Retained byte length differs for ..\untrusted-marker.',
            'source-length: Retained byte length differs for certification\evidence-runtime\README.md.extra.',
            "source-length: Retained byte length differs for certification\evidence-runtime\README.md.`nextra"
        )) {
            @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new($unsafeLength)))[0] |
                Should -BeExactly 'source-length: Variable details redacted.'
        }
        @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new(
            'mutant-survived: Independent oracle did not kill M4.')))[0] |
            Should -BeExactly 'mutant-survived: Variable details redacted.'
        @(Get-PspktEvidenceFailureDiagnostics -Exception ([InvalidOperationException]::new('unknown-category: untrusted-message-marker')))[0] |
            Should -BeExactly 'diagnostic-redacted: Non-capsule exception details were suppressed.'
        $failure = [AggregateException]::new('private outer text', [Exception[]]@(
            [InvalidOperationException]::new('cleanup-restore: TMP restoration differs.'),
            [AggregateException]::new('private nested text', [Exception[]]@(
                [InvalidOperationException]::new('pester-result: Full caller-bound test execution did not pass.'),
                [InvalidOperationException]::new('untrusted-message-marker')))))
        $failedPath = 'Evidence runtime conformance.' + $contract.RequiredPesterTests[4].Name
        $pesterFailure = [pscustomobject]@{ Tests = @(
            [pscustomobject]@{ Result = 'Failed'; ExpandedPath = $failedPath },
            [pscustomobject]@{ Result = 'Passed'; ExpandedPath = 'private test name' },
            [pscustomobject]@{ Result = 'Failed'; ExpandedPath = 'private test name' }
        ) }
        $failure = New-PspktEvidenceValidationFailure -Failures @($failure) -Pester $pesterFailure -AllowedMessages $diagnosticMessages
        $ManifestRecordsByRole.ValidatorText.Contains('New-PspktEvidenceValidationFailure -Failures') | Should -BeTrue
        $diagnostics = @(Get-PspktEvidenceFailureDiagnostics -Exception $failure -AllowedMessages $diagnosticMessages)
        $diagnostics -join "`n" | Should -BeExactly (
            "cleanup-restore: TMP restoration differs.`n" +
            "diagnostic-redacted: Non-capsule exception details were suppressed.`n" +
            'failed-test: ' + $failedPath + "`n" +
            'pester-result: Full caller-bound test execution did not pass.')
        $diagnostics -join '' | Should -Not -Match 'private|untrusted-message-marker'
        $previousError = [Console]::Error
        $capturedError = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
        try {
            [Console]::SetError($capturedError)
            Write-PspktEvidenceFailureDiagnostics -Exception $failure -AllowedMessages $diagnosticMessages
            $capturedError.ToString() | Should -BeExactly (($diagnostics -join [Environment]::NewLine) + [Environment]::NewLine)
        }
        finally { [Console]::SetError($previousError); $capturedError.Dispose() }
        $many = [Exception[]]@(1..80 | ForEach-Object { [InvalidOperationException]::new('x' * 8192) })
        $bounded = @(Get-PspktEvidenceFailureDiagnostics -Exception ([AggregateException]::new('outer', $many)) -AllowedMessages $diagnosticMessages)
        $bounded.Count | Should -BeLessOrEqual 49
        @($bounded | Where-Object Length -gt 256).Count | Should -Be 0
        $bounded | Should -Contain 'diagnostic-truncated: Error traversal or message bound exceeded.'
        foreach ($gate in $contract.SuccessGates) {
            $gateFixture = New-PspktEvidenceValidationResultFixture -Contract $contract -CaseId healthy
            $gateFixture.Captured[0].Gates.$gate = $false
            { Assert-PspktEvidenceValidationSuccess -CapturedResults $gateFixture.Captured -Expected $gateFixture.Expected } |
                Should -Throw '*ResultPostconditions: A validation gate did not pass.*'
        }
        foreach ($caseId in @('returned-failure', 'malformed-result', 'missing-result', 'multiple-results', 'count-mismatch')) {
            $probe = Invoke-PspktEvidenceBoundaryProbe -Contract $contract -CaseId $caseId
            $probe.PositiveControlPassed | Should -BeTrue
            $probe.WrapperRejected | Should -BeTrue
            $probe.StepRejected | Should -BeTrue
            $probe.SuccessObjectsEmitted | Should -Be 0
            $expectedDiagnostics = if ($caseId -ceq 'returned-failure') { 1 } else { 0 }
            $probe.DiagnosticCount | Should -Be $expectedDiagnostics
        }
        foreach ($wrongCount in @($true, '5', [double]5)) {
            $fixture = New-PspktEvidenceValidationResultFixture -Contract $contract -CaseId healthy
            $fixture.Captured[0].CompilationCount = $wrongCount
            { Complete-PspktEvidenceValidationInvocation -CapturedResults $fixture.Captured -Expected $fixture.Expected } |
                Should -Throw '*ResultShape*'
        }
        foreach ($field in @('Outcome', 'SchemaId')) {
            $fixture = New-PspktEvidenceValidationResultFixture -Contract $contract -CaseId healthy
            $fixture.Captured[0].$field += [char]0
            { Complete-PspktEvidenceValidationInvocation -CapturedResults $fixture.Captured -Expected $fixture.Expected } |
                Should -Throw '*ResultShape*'
        }
        $fixture = New-PspktEvidenceValidationResultFixture -Contract $contract -CaseId healthy
        $fixture.Captured[0].Pester.Result = "Pass`0ed"
        { Complete-PspktEvidenceValidationInvocation -CapturedResults $fixture.Captured -Expected $fixture.Expected } |
            Should -Throw '*ResultPostconditions*'
        $environmentState = @{}
        foreach ($name in @('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA')) {
            $environmentState[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        try {
            $env:GITHUB_RUN_ID = 'synthetic-boundary-test'
            $env:GITHUB_RUN_ATTEMPT = '1'
            $env:GITHUB_SHA = $contract.BaseCommit
            foreach ($rawOutcome in @($true, "fail`0ure")) {
                $probe = Invoke-PspktEvidenceBoundaryProbe -Contract $contract -CaseId missing-result
                $receipt = New-PspktEvidenceProbeReceipt -Probe $probe -HostSlot powershell_7
                $receipt | Add-Member -NotePropertyName RawOutcome -NotePropertyValue 'failure'
                Assert-PspktEvidenceProbeReceipt -Receipt $receipt -HostSlot powershell_7 -RequireRawOutcome $true
                $receipt.RawOutcome = $rawOutcome
                { Assert-PspktEvidenceProbeReceipt -Receipt $receipt -HostSlot powershell_7 -RequireRawOutcome $true } |
                    Should -Throw '*probe-receipt*'
            }
            $probe = Invoke-PspktEvidenceBoundaryProbe -Contract $contract -CaseId missing-result
            $receipt = New-PspktEvidenceProbeReceipt -Probe $probe -HostSlot powershell_7
            $receipt.PSObject.Properties.Remove('StepReason')
            $receipt | Add-Member -MemberType ScriptProperty -Name StepReason -Value {
                $this.DiagnosticCount = 99
                'ResultCardinality'
            }
            { Assert-PspktEvidenceProbeReceipt -Receipt $receipt -HostSlot powershell_7 } |
                Should -Throw '*probe-receipt*'
            $receipt.DiagnosticCount | Should -Be 0
            $receipts = @()
            $outcomes = [ordered]@{}
            foreach ($caseId in @('returned-failure', 'malformed-result', 'missing-result', 'multiple-results', 'count-mismatch')) {
                $probe = Invoke-PspktEvidenceBoundaryProbe -Contract $contract -CaseId $caseId
                $receipts += New-PspktEvidenceProbeReceipt -Probe $probe -HostSlot powershell_7 | ConvertTo-Json -Depth 10 -Compress
                $outcomes[$caseId] = 'failure'
            }
            @(Confirm-PspktEvidenceProbeReceipts -HostSlot powershell_7 -OutcomesJson ($outcomes | ConvertTo-Json -Compress) -ReceiptJson $receipts).Count |
                Should -Be 5
            $outcomes['missing-result'] = $true
            { Confirm-PspktEvidenceProbeReceipts -HostSlot powershell_7 -OutcomesJson ($outcomes | ConvertTo-Json -Compress) -ReceiptJson $receipts } |
                Should -Throw '*probe-confirmation*'
            { ConvertFrom-PspktEvidenceReceiptJson -Json '{"Outcome":1,"\u004futcome":2}' } | Should -Throw '*receipt-json*'
        }
        finally {
            foreach ($name in $environmentState.Keys) {
                [Environment]::SetEnvironmentVariable($name, $environmentState[$name], 'Process')
            }
        }
        $tokens = $null
        $errors = $null
        $syntax = [Management.Automation.Language.Parser]::ParseInput($ManifestRecordsByRole.ValidatorText, [ref]$tokens, [ref]$errors)
        $calls = @($syntax.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Complete-PspktEvidenceValidationInvocation'
        }, $true))
        $calls.Count | Should -Be 1
    }
}
