Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Phase 4 protocol schema authority' -Tag 'Precheck' {
    BeforeAll {
        $script:repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $script:contractPath = Join-Path $script:repositoryRoot 'certification\lib\Pspkt.Certification.ProtocolSchemaContract.ps1'

        function Invoke-ProtocolProbe {
            param([string]$Code)

            $scratch = Join-Path ([IO.Path]::GetTempPath()) ('pp-test-' + [Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($scratch)
            $probePath = Join-Path $scratch 'probe.ps1'
            $prefix = @'
param([string]$RepositoryRoot,[string]$AssemblyRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$validator = Join-Path $RepositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1'
$catalogContract = & $validator -Worker -Mode Compile -AssemblyRoot $AssemblyRoot
$utf8 = [Text.UTF8Encoding]::new($false,$true)
$basePath = Join-Path $RepositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json'
$overlayBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json'))
$inventoryBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-inventory.v1.json'))
$metaBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json'))
. (Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.ProtocolSchemaContract.ps1')
$protocolContract = Get-PspktProtocolSchemaContract
$bootstrapAssemblyIdentity = [Pspkt.Certification.SchemaBootstrap].Assembly.GetName().FullName
$forbiddenAssemblyNames = [string[]]@(
    [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2].Assembly.GetName().Name,
    [Pspkt.Certification.Protocol.ProtocolSchemaAuthority].Assembly.GetName().Name)
$pins = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($table in @($protocolContract.InputSha256ByPath,$protocolContract.OutputSha256ByPath)) {
    foreach ($path in $table.Keys) { $pins.Add([IO.Path]::GetFileName($path.Replace('/','\')), $table[$path]) }
}
foreach ($table in @($protocolContract.FilteredSha256ByName,$protocolContract.SourceSha256ByPath,$protocolContract.UnionMappingSha256ByName)) {
    foreach ($name in $table.Keys) { $pins.Add($name, $table[$name]) }
}
$outputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
foreach ($path in $protocolContract.OutputPathSet) {
    $relative = $path.Replace('/','\')
    $outputs.Add([IO.Path]::GetFileName($relative), [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $relative)))
}
'@
            try {
                [IO.File]::WriteAllText($probePath, $prefix + "`n" + $Code, [Text.UTF8Encoding]::new($false,$true))
                $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
                $output = & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $probePath -RepositoryRoot $script:repositoryRoot -AssemblyRoot $scratch 2>&1
                if ($LASTEXITCODE -ne 0) { throw ($output -join "`n") }
                return $output
            }
            finally {
                if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
            }
        }

        function Invoke-ProtocolValidationAttempt {
            param([string[]]$ValidatorArguments)

            $validator = Join-Path $script:repositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1'
            $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
            $priorPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $validator @ValidatorArguments 2>&1
                return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join "`n") }
            }
            finally {
                $ErrorActionPreference = $priorPreference
            }
        }

        function Get-ProtocolPathResolverDefinition {
            param([string]$Path)

            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) { throw "Path resolver source has parse errors: $Path" }
            $functionAst = $ast.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq 'Resolve-PspktProtocolPath'
            }, $true)
            if ($null -eq $functionAst) { throw "Path resolver is absent: $Path" }
            return $functionAst.Extent.Text
        }

        $script:protocolCombinedGateCode = @'
function Test-ProtocolCombinedResult {
    param($Result,[string[]]$ExpectedPaths)

    if ($null -eq $Result -or $Result.Result -ne 'Passed') { return $false }
    if ($Result.FailedCount -ne 0 -or $Result.FailedBlocksCount -ne 0 -or $Result.FailedContainersCount -ne 0) { return $false }
    if (@($Result.Containers).Count -ne $ExpectedPaths.Count -or $Result.PassedCount -le 0) { return $false }
    foreach ($path in $ExpectedPaths) {
        $expectedPath = [IO.Path]::GetFullPath($path)
        $containerTests = @($Result.Tests | Where-Object {
            $_.ScriptBlock.File -and
            [string]::Equals([IO.Path]::GetFullPath($_.ScriptBlock.File), $expectedPath, [StringComparison]::OrdinalIgnoreCase)
        })
        $selectedTests = @($containerTests | Where-Object { $_.ShouldRun })
        if ($selectedTests.Count -eq 0) { return $false }
        if (@($selectedTests | Where-Object { -not $_.Skip }).Count -eq 0) { return $false }
        if (@($selectedTests | Where-Object { $_.Executed -and $_.Result -eq 'Passed' }).Count -eq 0) { return $false }
        foreach ($test in $selectedTests) {
            if ($test.Result -eq 'Passed' -and $test.Executed) { continue }
            if ($test.Result -eq 'Skipped' -and $test.Skip) { continue }
            return $false
        }
    }
    return $true
}
'@
    }

    It 'pins the deferred seeds and output set' {
        (Test-Path -LiteralPath $script:contractPath -PathType Leaf) | Should -BeTrue
        if (-not (Test-Path -LiteralPath $script:contractPath -PathType Leaf)) {
            return
        }

        . $script:contractPath
        $contract = Get-PspktProtocolSchemaContract

        @($contract.DeferredSeedTypeNames) | Should -Be @(
            'MintAttestedV1',
            'S4UMintSlotV1',
            'ServiceControlEventNodeProofV1')
        @($contract.DeferredSeedMessageKeys) | Should -Be @(
            'BrokerControl:MintRevoked')
        @($contract.OutputPathSet) | Should -Be @(
            'certification/schema/protocol-schema.v1.json',
            'certification/schema/generated-base-id-map.v1.json',
            'certification/schema/protocol-message-association.v1.json',
            'certification/schema/mandatory-tail-schedule.v1.json')
    }

    It 'pins protocol identities ranges directions and literal extension parents' {
        . $script:contractPath
        $contract = Get-PspktProtocolSchemaContract

        $contract.NamePredicate | Should -Be '^[A-Za-z][A-Za-z0-9-]*$'
        $contract.BaseCatalogSchemaId | Should -Be 'PspktProtocolBaseCatalogV1'
        $contract.BaseCatalogSpace | Should -Be 'protocol-base'
        $contract.OverlayCatalogSchemaId | Should -Be 'PspktProtocolOverlayCatalogV1'
        $contract.OverlayCatalogSpace | Should -Be 'protocol-overlay'
        $contract.EmitSchemaId | Should -Be 'PspktProtocolSchemaV1'
        $contract.MapSchemaId | Should -Be 'PspktGeneratedBaseIdMapV1'
        @($contract.Channels) | Should -Be @('WorkerApp', 'BrokerControl', 'LocalIpc')
        $contract.MessageEnumNameByChannel.WorkerApp | Should -Be 'WorkerAppMessageKind'
        $contract.MessageEnumNameByChannel.BrokerControl | Should -Be 'BrokerControlMessageKind'
        $contract.MessageEnumNameByChannel.LocalIpc | Should -Be 'LocalIpcMessageKind'
        @($contract.PermittedDirectionsByChannel.WorkerApp) | Should -Be @('HostToWorker', 'WorkerToHost')
        @($contract.PermittedDirectionsByChannel.BrokerControl) | Should -Be @('HostToBroker', 'BrokerToHost')
        @($contract.PermittedDirectionsByChannel.LocalIpc) | Should -Be @('WorkerToBroker', 'BrokerToWorker')
        $contract.OverlayKindRangesByChannel.WorkerApp[0].Start | Should -Be 0x1080
        $contract.OverlayKindRangesByChannel.WorkerApp[0].End | Should -Be 0x10FF
        $contract.OverlayKindRangesByChannel.BrokerControl[0].Start | Should -Be 0x1100
        $contract.OverlayKindRangesByChannel.BrokerControl[0].End | Should -Be 0x110F
        $contract.OverlayKindRangesByChannel.BrokerControl[1].Start | Should -Be 0x1110
        $contract.OverlayKindRangesByChannel.BrokerControl[1].End | Should -Be 0x11FF
        $contract.OverlayKindRangesByChannel.LocalIpc[0].Start | Should -Be 0x1200
        $contract.OverlayKindRangesByChannel.LocalIpc[0].End | Should -Be 0x12FF
        $contract.OverlayTypeRange.Start | Should -Be 0x1300
        $contract.OverlayTypeRange.End | Should -Be 0x13FF
        $contract.GeneratedFieldIdMax | Should -Be 39
        @($contract.LiteralExtensionParentNames) | Should -Be @(
            'WorkerSessionKeyCertificateV1',
            'WorkerProcessIsolationAdmissionReceiptV1',
            'WorkerProcessIsolationReceiptV1',
            'ChallengeBound',
            'CreatorPermitInstallationV1',
            'CreatorDeadlineAuthorization',
            'LaunchFencePreparedV1',
            'LaunchFenceRevokedV1',
            'LaunchFenceCommittedV1',
            'LaunchFenceCreateIntentAcknowledgedV1',
            'LaunchFenceRevokedBeforeCreateV1',
            'LaunchFenceCreateIssuedV1',
            'LaunchFenceCreateDefinitivelyFailedV1',
            'LaunchFenceRevokedBeforeResumeV1',
            'LaunchFenceResumeIssuedV1',
            'CreatePermitUnusedV1',
            'CreatePermitConsumedV1',
            'CreatePermitRevokedV1',
            'AuthorizationLedgerPreparedV1',
            'AuthorizationLedgerSentV1',
            'AuthorizationLedgerStoredV1',
            'AuthorizationLedgerCreatingV1',
            'AuthorizationLedgerCreatedV1',
            'AuthorizationLedgerCompletedV1',
            'AuthorizationLedgerCreateDefinitivelyFailedV1',
            'AuthorizationLedgerAbortedCreateDefinitivelyFailedV1',
            'AuthorizationLedgerRevokedBeforeCreateV1',
            'AuthorizationLedgerAbortedProvenNotCreatedV1',
            'AuthorizationLedgerAbortedCreatedNeverResumedV1',
            'AuthorizationLedgerAbortedAttachmentHandshakeV1',
            'AuthorizationLedgerAbortedResourcePreparationFailedV1',
            'AuthorizationLedgerAbortedCompilationDefinitivelyFailedV1',
            'AuthorizationLedgerOutcomeUnknownV1',
            'AuthorizationLedgerBurnedUnknownV1',
            'OperationActiveWithLaunchAuthorityV1',
            'OperationCompletedWithLaunchAuthorityV1',
            'OperationBurnedUnknownWithLaunchAuthorityV1',
            'OperationAbortedProvenNotCreatedWithLaunchAuthorityV1',
            'OperationAbortedCreateDefinitivelyFailedWithLaunchAuthorityV1',
            'OperationAbortedCreatedNeverResumedWithLaunchAuthorityV1',
            'OperationAbortedAttachmentHandshakeWithLaunchAuthorityV1',
            'OperationAbortedResourcePreparationFailedWithLaunchAuthorityV1',
            'AbortedCompilationDefinitivelyFailedWithLaunchAuthority',
            'OperationBurnResolvedWithLaunchAuthorityV1',
            'OperationSuccessorAuthorizedPendingCapacityWithLaunchAuthorityV1',
            'OperationBurnResolutionDeferredWithLaunchAuthorityV1')
    }

    It 'retains the complete WorkerApp message order and shared Keepalive identity' {
        $catalogPath = Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json'
        (Test-Path -LiteralPath $catalogPath -PathType Leaf) | Should -BeTrue
        $catalog = [IO.File]::ReadAllText($catalogPath) | ConvertFrom-Json
        $messages = @($catalog.entries | Where-Object { $_.op -eq 'message' })
        @($messages.name) | Should -Be @(
            'BootstrapWorkerHello', 'BootstrapHostHello', 'BootstrapWorkerContext',
            'BootstrapWorkerFinished', 'Keepalive', 'Keepalive', 'WorkerHello',
            'WorkerSigningKeyCloseArmed')
        @($messages.channel | Select-Object -Unique) | Should -Be @('WorkerApp')
        @($messages.direction) | Should -Be @(
            'WorkerToHost', 'HostToWorker', 'WorkerToHost', 'WorkerToHost',
            'HostToWorker', 'WorkerToHost', 'WorkerToHost', 'WorkerToHost')
        @($messages.profile | Select-Object -Unique) | Should -Be @('Any')
        @($messages.mandatoryTailClass) | Should -Be @(
            'Mandatory', 'Mandatory', 'Mandatory', 'Mandatory', 'Ordinary',
            'Ordinary', 'Mandatory', 'Mandatory')
        @($messages.stateAssoc) | Should -Be @(
            'TransportListening', 'TransportListening', 'TransportAuthenticated',
            'TransportAuthenticated', 'None', 'None', 'WorkerHello',
            'WorkerSigningKeyCloseArmed')
        @($messages.payloadRoot) | Should -Be @($messages.name)
        $keepalive = @($catalog.entries | Where-Object { $_.op -eq 'field' -and $_.parent -eq 'Keepalive' })
        $keepalive.Count | Should -Be 1
        $keepalive[0].name | Should -Be 'timestamp'
        $keepalive[0].type | Should -Be 'FILETIME'
    }

    It 'pins the four ordered concrete union mappings without shortening the value eighteen exception' {
        $catalog = [IO.File]::ReadAllText((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json')) | ConvertFrom-Json
        $unions = @($catalog.entries | Where-Object { $_.op -eq 'union' })
        @($unions.name) | Should -Be @('LaunchFenceGate', 'CreatePermit', 'AuthorizationLedgerRecord', 'OperationRecord')
        @($unions.discriminator) | Should -Be @('LaunchFenceKind', 'CreatePermitKind', 'AuthorizationLedgerKind', 'OperationRecordKind')
        @($unions[0].branches.name) | Should -Be @(
            'LaunchFencePreparedV1', 'LaunchFenceRevokedV1', 'LaunchFenceCommittedV1',
            'LaunchFenceCreateIntentAcknowledgedV1', 'LaunchFenceRevokedBeforeCreateV1',
            'LaunchFenceCreateIssuedV1', 'LaunchFenceCreateDefinitivelyFailedV1',
            'LaunchFenceRevokedBeforeResumeV1', 'LaunchFenceResumeIssuedV1')
        @($unions[1].branches.name) | Should -Be @('CreatePermitUnusedV1', 'CreatePermitConsumedV1', 'CreatePermitRevokedV1')
        @($unions[2].branches.name) | Should -Be @(
            'AuthorizationLedgerPreparedV1', 'AuthorizationLedgerSentV1',
            'AuthorizationLedgerStoredV1', 'AuthorizationLedgerCreatingV1',
            'AuthorizationLedgerCreatedV1', 'AuthorizationLedgerCompletedV1',
            'AuthorizationLedgerCreateDefinitivelyFailedV1',
            'AuthorizationLedgerAbortedCreateDefinitivelyFailedV1',
            'AuthorizationLedgerRevokedBeforeCreateV1', 'AuthorizationLedgerAbortedProvenNotCreatedV1',
            'AuthorizationLedgerAbortedCreatedNeverResumedV1', 'AuthorizationLedgerAbortedAttachmentHandshakeV1',
            'AuthorizationLedgerAbortedResourcePreparationFailedV1', 'AuthorizationLedgerAbortedCompilationDefinitivelyFailedV1',
            'AuthorizationLedgerOutcomeUnknownV1', 'AuthorizationLedgerBurnedUnknownV1')
        @($unions[3].branches.name) | Should -Be @(
            'OperationUnseenV1', 'OperationActiveV1', 'OperationActiveWithLaunchAuthorityV1',
            'OperationCompletedV1', 'OperationCompletedWithLaunchAuthorityV1',
            'OperationBurnedUnknownV1', 'OperationBurnedUnknownWithLaunchAuthorityV1',
            'OperationAbortedProvenNotCreatedV1', 'OperationAbortedProvenNotCreatedWithLaunchAuthorityV1',
            'OperationAbortedCreateDefinitivelyFailedV1', 'OperationAbortedCreateDefinitivelyFailedWithLaunchAuthorityV1',
            'OperationAbortedCreatedNeverResumedV1', 'OperationAbortedCreatedNeverResumedWithLaunchAuthorityV1',
            'OperationAbortedAttachmentHandshakeV1', 'OperationAbortedAttachmentHandshakeWithLaunchAuthorityV1',
            'OperationAbortedResourcePreparationFailedV1', 'OperationAbortedResourcePreparationFailedWithLaunchAuthorityV1',
            'OperationAbortedCompilationDefinitivelyFailedV1', 'AbortedCompilationDefinitivelyFailedWithLaunchAuthority',
            'OperationBurnResolvedV1', 'OperationBurnResolvedWithLaunchAuthorityV1',
            'OperationSuccessorAuthorizedPendingCapacityV1', 'OperationSuccessorAuthorizedPendingCapacityWithLaunchAuthorityV1',
            'OperationBurnResolutionDeferredV1', 'OperationBurnResolutionDeferredWithLaunchAuthorityV1')
        $names = @($unions | ForEach-Object { $_.branches.name })
        $names.Count | Should -Be 53
        @($names | Select-Object -Unique).Count | Should -Be 53
        @($names | Where-Object { $_.Length -gt 64 }).Count | Should -Be 0
    }

    It 'retains all generated receipt launch and channel payload roots with separate host hellos' {
        $catalog = [IO.File]::ReadAllText((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json')) | ConvertFrom-Json
        $expectedFieldCounts = [ordered]@{
            WorkerProcessIsolationAdmissionReceiptV1 = 5
            WorkerProcessIsolationReceiptV1 = 3
            ChallengeBound = 12
            CreatorPermitInstallationBodyV1 = 20
            CreatorPermitInstallationV1 = 4
            CreatorDeadlineAuthorizationBodyV1 = 13
            CreatorDeadlineAuthorization = 4
            BootstrapBrokerHello = 16
            BrokerBootstrapHostHello = 13
            BootstrapBrokerContext = 5
            BootstrapBrokerFinished = 1
            IsolationAdmission = 7
            IsolationExit = 3
            BrokerFailure = 3
            LocalHelloW = 6
            LocalHelloB = 10
            MintRequest = 5
            MintResult = 7
            LocalKeepalive = 1
            LocalFailure = 3
        }
        foreach ($name in $expectedFieldCounts.Keys) {
            @($catalog.entries | Where-Object { $_.op -eq 'type' -and $_.name -eq $name }).Count | Should -Be 1 -Because $name
            @($catalog.entries | Where-Object { $_.op -eq 'field' -and $_.parent -eq $name }).Count | Should -Be $expectedFieldCounts[$name] -Because $name
        }
        @($catalog.entries | Where-Object { $_.op -eq 'field' -and $_.parent -eq 'BrokerBootstrapHostHello' } | ForEach-Object { $_.name }) | Should -Be @(
            'hostKeyId', 'echoBrokerNonce', 'hostNonce', 'leaseId', 'leaseActivationGeneration',
            'activationNonce', 'expectedHostToBrokerOrigin', 'expectedBrokerToHostOrigin',
            'protocolSchemaMetaDigest', 'protocolSchemaDigest', 'evidenceSchemaMetaDigest',
            'evidenceSchemaDigest', 'localBrokerWorkerChannelId')
    }

    It 'transcribes only the exact literal overlay type registry and message rows' {
        $catalogPath = Join-Path $script:repositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json'
        (Test-Path -LiteralPath $catalogPath -PathType Leaf) | Should -BeTrue
        $catalog = [IO.File]::ReadAllText($catalogPath) | ConvertFrom-Json
        $types = @($catalog.entries | Where-Object { $_.op -eq 'overlay-type' -or $_.op -eq 'reserve-illegal-type' })
        @($types.name) | Should -Be @(
            'TokenMintAuthorizationBodyV1', 'S4UMintSlotV1', 'MintAttestedV1', 'MintRevokedV1',
            'ServiceLaunchProofV1', 'BrokerServicePrincipalAnchorV1', 'BrokerSessionKeyCertificateBodyV1',
            'ServiceControlEventNodeProofV1', 'BrokerMintInstallSampleV1', 'BrokerMintDeadlineAuthorizationV1',
            'ServiceEnrollmentInstallProofV1', 'LocalTranscriptProofV1', 'LocalTranscriptRecordSetV1',
            'BrokerSessionKeyCertificateEnvelopeV1', 'LocalTranscriptChunkV1', 'LocalTranscriptRootV1',
            'BrokerServiceLaunchProofV1', 'LocalTranscriptRootAcceptedV1', 'WorkerProcessDaclAccessPolicyProofV1',
            'LiveCandidateAccessProbeV1', 'CandidateLaunchAuthorityV1')
        @($types.id) | Should -Be @(4865,4866,4867,4868,4869,4870,4871,4874,4877,4878,4879,4880,4881,4882,4883,4884,4885,4886,4887,4888,4889)
        $types[12].op | Should -Be 'reserve-illegal-type'
        $messages = @($catalog.entries | Where-Object { $_.op -eq 'overlay-message' })
        $messages.Count | Should -Be 27
        @($messages | Where-Object { $_.channel -eq 'BrokerControl' -and $_.name -eq 'BootstrapHostHello' } | ForEach-Object { $_.payloadRoot }) | Should -Be @('BrokerBootstrapHostHello')
        @($messages | Where-Object { $_.name -eq 'Keepalive' } | ForEach-Object { $_.payloadRoot }) | Should -Be @('Keepalive','Keepalive')
        . $script:contractPath
        $contract = Get-PspktProtocolSchemaContract
        $extensions = @($catalog.entries | Where-Object { $_.op -eq 'field-set' -and $_.id -ge 40 })
        @($extensions.parent | Select-Object -Unique) | Should -Be @($contract.LiteralExtensionParentNames)
        $extensions.Count | Should -Be 56
        foreach ($extension in $extensions) {
            @($extension.variants.profile) | Should -Be @('InteractiveSeat', 'NonInteractiveElevated')
            $extension.variants[0].status | Should -Be 'Forbidden'
        }
    }

    It 'preserves all six exact lifecycle lists and their source bytes' {
        $inventoryPath = Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'
        (Test-Path -LiteralPath $inventoryPath -PathType Leaf) | Should -BeTrue
        $inventory = [IO.File]::ReadAllText($inventoryPath) | ConvertFrom-Json
        $sourceBytes = [Convert]::FromBase64String($inventory.lifecycleSourceBase64)
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            [BitConverter]::ToString($sha256.ComputeHash($sourceBytes)).Replace('-', '').ToLowerInvariant() | Should -Be '8718dd1de27850663988c52bdd41a5ca5617c584b9a84f59e6d5a1cdfaa0d496'
        }
        finally {
            $sha256.Dispose()
        }
        $source = [Text.Encoding]::UTF8.GetString($sourceBytes) | ConvertFrom-Json
        @($inventory.lifecycle.variantOrder) | Should -Be @(
            'InteractiveWindowsTerminalPS5', 'InteractiveWindowsTerminalPS7',
            'InteractiveConhostPS5', 'InteractiveConhostPS7', 'NonInteractivePS5', 'NonInteractivePS7')
        @($inventory.lifecycle.variants | ForEach-Object { $_.states.Count }) | Should -Be @(73,72,72,71,67,66)
        for ($index = 0; $index -lt 6; $index++) {
            $inventory.lifecycle.variants[$index].name | Should -Be $source.variants[$index].name
            $inventory.lifecycle.variants[$index].profile | Should -Be $source.variants[$index].profile
            @($inventory.lifecycle.variants[$index].states) | Should -Be @($source.variants[$index].states)
        }
        ($inventory.lifecycle.variants | ForEach-Object { $_.states.Count } | Measure-Object -Sum).Sum | Should -Be 421
    }

    It 'filters the exact reverse omission closure before evaluation without omitting dependencies' {
        $validator = Join-Path $script:repositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1'
        (Test-Path -LiteralPath $validator -PathType Leaf) | Should -BeTrue
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $json = & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $validator -Mode Filter
        $LASTEXITCODE | Should -Be 0
        $projection = ($json -join "`n") | ConvertFrom-Json
        @($projection.omittedTypes) | Should -Be @('IsolationAdmission','IsolationExit','MintAttestedV1','S4UMintSlotV1','ServiceControlEventNodeProofV1')
        @($projection.omittedMessages) | Should -Be @('BrokerControl:IsolationAdmission','BrokerControl:IsolationExit','BrokerControl:MintAttested','BrokerControl:MintRevoked')
        $projection.removedOperations.Count | Should -Be 91
        @($projection.removedOperations | Where-Object { $_.catalog -eq 'base' }).Count | Should -Be 12
        @($projection.removedOperations | Where-Object { $_.catalog -eq 'overlay' }).Count | Should -Be 79
        . $script:contractPath
        $contract = Get-PspktProtocolSchemaContract
        $expected = @(foreach ($group in $contract.RemovedOperationGroups) {
            foreach ($ordinal in $group.First..$group.Last) { '{0}:{1}:{2}' -f $group.Catalog,$ordinal,$group.Category }
        })
        @($projection.removedOperations | ForEach-Object { '{0}:{1}:{2}' -f $_.catalog,$_.catalogOrdinal,$_.category }) | Should -Be $expected
        $projection.survivingBaseCount | Should -Be $contract.SurvivingOperationCounts.Base
        $projection.survivingOverlayCount | Should -Be $contract.SurvivingOperationCounts.Overlay
        $projection.filteredBaseSha256 | Should -Be $contract.FilteredSha256ByName['filtered-base']
        $projection.filteredOverlaySha256 | Should -Be $contract.FilteredSha256ByName['filtered-overlay']
        $projection.removedOperationsSha256 | Should -Be $contract.FilteredSha256ByName['removed-operations']
        $retained = @($projection.overlay.entries | Where-Object { $_.op -eq 'overlay-type' } | ForEach-Object { $_.name })
        $retained | Should -Contain 'MintRevokedV1'
        $retained | Should -Contain 'LiveCandidateAccessProbeV1'
        $retained | Should -Contain 'WorkerProcessDaclAccessPolicyProofV1'
        $retained | Should -Contain 'ServiceLaunchProofV1'
    }

    It 'generates the four protocol outputs with exact associations and profile-sized mandatory tails' {
        $generator = Join-Path $script:repositoryRoot 'certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1'
        (Test-Path -LiteralPath $generator -PathType Leaf) | Should -BeTrue
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $outputRoot = Join-Path $TestDrive 'generated'
        & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $generator -OutputRoot $outputRoot
        $LASTEXITCODE | Should -Be 0
        & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $generator -OutputRoot $outputRoot
        $LASTEXITCODE | Should -Be 0
        $schemaRoot = Join-Path $outputRoot 'certification\schema'
        @(Get-ChildItem -LiteralPath $schemaRoot -File).Count | Should -Be 4
        @(Get-ChildItem -LiteralPath $schemaRoot -File -Filter '*.tmp').Count | Should -Be 0
        $association = [IO.File]::ReadAllText((Join-Path $schemaRoot 'protocol-message-association.v1.json')) | ConvertFrom-Json
        $tail = [IO.File]::ReadAllText((Join-Path $schemaRoot 'mandatory-tail-schedule.v1.json')) | ConvertFrom-Json
        $association.rows.Count | Should -Be 31
        @($association.rows[0].PSObject.Properties.Name) | Should -Be @('channel','direction','kindId','mandatoryTailClass','name','payloadRoot','profile','stateAssoc')
        $tail.rows.Count | Should -Be 842
        $tail.rows[0].lifecycleVariant | Should -Be 'InteractiveWindowsTerminalPS5'
        $tail.rows[0].state | Should -Be 'LeaseAcquired'
        $tail.rows[0].direction | Should -Be 'HostToWorker'
        $tail.rows[1].direction | Should -Be 'WorkerToHost'
        $tail.rows[1].records | Should -Be 5
        @($tail.rows[1].kinds.name) | Should -Be @('BootstrapWorkerHello','BootstrapWorkerContext','BootstrapWorkerFinished','WorkerHello','WorkerSigningKeyCloseArmed')
        @($tail.rows[1].kinds | Where-Object { $_.name -eq 'BootstrapWorkerContext' } | ForEach-Object { $_.maxPayloadBytes }) | Should -Be @(1958)
        $nonInteractive = @($tail.rows | Where-Object { $_.lifecycleVariant -eq 'NonInteractivePS5' -and $_.state -eq 'LeaseAcquired' -and $_.direction -eq 'WorkerToHost' })[0]
        @($nonInteractive.kinds | Where-Object { $_.name -eq 'BootstrapWorkerContext' } | ForEach-Object { $_.maxPayloadBytes }) | Should -Be @(2078)
        foreach ($row in $tail.rows) {
            @($row.kinds | Where-Object { $_.name -eq 'Keepalive' -or $_.name -eq 'TokenMintAuthorized' }).Count | Should -Be 0
            $row.records | Should -Be $row.kinds.Count
            $row.records | Should -BeLessOrEqual 5535
            $row.wrapperBytes | Should -BeLessOrEqual 29360128
            foreach ($kind in $row.kinds) {
                $kind.cardinality | Should -Be 1
                $kind.maxSignedFrameBytes | Should -Be (408 + $kind.maxPayloadBytes)
                $kind.transcriptChargeBytes | Should -Be (421 + $kind.maxPayloadBytes)
            }
        }
        @($tail.rows | Where-Object { $_.state -eq 'CleanupMutexReleased' -and $_.records -eq 0 -and $_.wrapperBytes -eq 0 -and $_.kinds.Count -eq 0 }).Count | Should -Be 12
    }

    It 'normalizes only stable absolute filesystem paths identically at both native boundaries' {
        $generator = Join-Path $script:repositoryRoot 'certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1'
        $validator = Join-Path $script:repositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1'
        $generatorResolver = Get-ProtocolPathResolverDefinition -Path $generator
        $validatorResolver = Get-ProtocolPathResolverDefinition -Path $validator
        $generatorResolver | Should -BeExactly $validatorResolver

        $code = @'
param([string]$PowerShellRoot,[string]$ProcessRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
__RESOLVER__
[Environment]::CurrentDirectory = $ProcessRoot
Set-Location -LiteralPath $PowerShellRoot
$relative = Resolve-PspktProtocolPath -Path '.\relative output\' -ParameterName 'OutputRoot'
$expectedRelative = Join-Path $PowerShellRoot 'relative output'
if ($relative -cne $expectedRelative) { throw "Relative path resolved incorrectly: $relative" }
$unc = Resolve-PspktProtocolPath -Path '\\192.0.2.1\share name\' -ParameterName 'OutputRoot'
if ($unc -cne '\\192.0.2.1\share name') { throw "UNC path normalized incorrectly: $unc" }
$superscripts = @([char]0x00B9,[char]0x00B2,[char]0x00B3)
$invalid = @(
    '\\?\C:\',
    '\\./C:/',
    '//?\C:\',
    '//./C:/',
    'FileSystem::\\?\C:\',
    'Env:PATH',
    'FileSystem::relative',
    'FileSystem::C:relative',
    'C:relative',
    'C:\folder.\child',
    'C:\folder \child',
    'C:\bad"quoted"child',
    '\\server.\share\child',
    '\\server\share.\child',
    '//server/share./child',
    'MissingProvider::C:\child',
    'FileSystem::C:\folder\NUL',
    'C:\folder\CON.txt',
    'C:\folder\NUL\',
    'C:\folder\PRN',
    'C:\folder\AUX.txt',
    'C:\folder\CLOCK$',
    'C:\folder\CONIN$',
    'C:\folder\CONOUT$',
    'C:\folder\COM1',
    'C:\folder\LPT9.log')
foreach ($superscript in $superscripts) {
    $invalid += 'C:\folder\COM' + $superscript + '.txt'
    $invalid += 'C:\folder\LPT' + $superscript + '\'
}
foreach ($candidate in $invalid) {
    $rejected = $false
    try { [void](Resolve-PspktProtocolPath -Path $candidate -ParameterName 'OutputRoot') }
    catch {
        if ($_.Exception.Message -notmatch '^OutputRoot ') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "Path was accepted: $candidate" }
}
$driveRoot = [IO.Path]::GetPathRoot($PowerShellRoot)
if ((Resolve-PspktProtocolPath -Path $driveRoot -ParameterName 'OutputRoot') -cne $driveRoot) {
    throw 'Drive root was not preserved.'
}
foreach ($candidate in @('C:\CON\child','C:\folder\COM1\child','C:\Users\con.smith\out')) {
    [void](Resolve-PspktProtocolPath -Path $candidate -ParameterName 'OutputRoot')
}
$first = Resolve-PspktProtocolPath -Path $relative -ParameterName 'OutputRoot'
$second = Resolve-PspktProtocolPath -Path $first -ParameterName 'OutputRoot'
if ($first -cne $second) { throw 'Path normalization is not idempotent.' }
'path-policy-verified'
'@.Replace('__RESOLVER__',$generatorResolver)
        $path = Join-Path $TestDrive 'path-policy.ps1'
        [IO.File]::WriteAllText($path,$code,[Text.UTF8Encoding]::new($false,$true))
        $powerShellRoot = Join-Path $TestDrive 'Policy PowerShell location'
        $processRoot = Join-Path $TestDrive 'Policy process location'
        [void][IO.Directory]::CreateDirectory($powerShellRoot)
        [void][IO.Directory]::CreateDirectory($processRoot)
        foreach ($hostCommand in @('pwsh.exe','powershell.exe')) {
            $hostCommandInfo = Get-Command $hostCommand -ErrorAction SilentlyContinue
            if (-not $hostCommandInfo) { continue }
            $hostPath = $hostCommandInfo.Source
            $result = & $hostPath -NoLogo -NoProfile -File $path -PowerShellRoot $powerShellRoot -ProcessRoot $processRoot
            $LASTEXITCODE | Should -Be 0
            ($result -join "`n") | Should -Match 'path-policy-verified'
        }
    }

    It 'preserves a relative spaced output root across Windows PowerShell native forwarding' {
        $powerShellRoot = Join-Path $TestDrive 'PowerShell location'
        $processRoot = Join-Path $TestDrive 'Process location'
        [void][IO.Directory]::CreateDirectory($powerShellRoot)
        [void][IO.Directory]::CreateDirectory($processRoot)
        $code = @'
param([string]$RepositoryRoot,[string]$PowerShellRoot,[string]$ProcessRoot,[string]$HostLabel)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Environment]::CurrentDirectory = $ProcessRoot
Set-Location -LiteralPath $PowerShellRoot
$relativeOutputRoot = ".\generated output $HostLabel\"
$powerShellDestination = Join-Path $PowerShellRoot "generated output $HostLabel"
$processDestination = Join-Path $ProcessRoot "generated output $HostLabel"
if ([IO.Directory]::Exists($powerShellDestination) -or [IO.Directory]::Exists($processDestination)) { throw 'Output destination was not fresh.' }
$rejectedDestination = Join-Path $PowerShellRoot "rejected output $HostLabel."
$lookalikeDestination = Join-Path $PowerShellRoot "rejected output $HostLabel"
$rejected = $false
try {
    & (Join-Path $RepositoryRoot 'certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1') -OutputRoot $rejectedDestination
}
catch {
    if ($_.Exception.Message -notmatch '^OutputRoot contains a normalization-sensitive') { throw }
    $rejected = $true
}
if (-not $rejected -or [IO.Directory]::Exists($rejectedDestination) -or [IO.Directory]::Exists($lookalikeDestination)) {
    throw 'Rejected generator destination was written.'
}
& (Join-Path $RepositoryRoot 'certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1') -OutputRoot $relativeOutputRoot
$schemaRoot = Join-Path $powerShellDestination 'certification\schema'
foreach ($name in @(
    'protocol-schema.v1.json',
    'generated-base-id-map.v1.json',
    'protocol-message-association.v1.json',
    'mandatory-tail-schedule.v1.json')) {
    if (-not [IO.File]::Exists((Join-Path $schemaRoot $name))) { throw "Missing generated output: $name" }
}
if ([IO.Directory]::Exists($processDestination)) { throw 'Generator used the process working directory.' }
'wrapper-path-verified'
'@
        $path = Join-Path $TestDrive 'wrapper-path.ps1'
        [IO.File]::WriteAllText($path,$code,[Text.UTF8Encoding]::new($false,$true))
        foreach ($hostCommand in @('pwsh.exe','powershell.exe')) {
            $hostCommandInfo = Get-Command $hostCommand -ErrorAction SilentlyContinue
            if (-not $hostCommandInfo) { continue }
            $hostPath = $hostCommandInfo.Source
            $hostLabel = [IO.Path]::GetFileNameWithoutExtension($hostCommand)
            $result = & $hostPath -NoLogo -NoProfile -File $path -RepositoryRoot $script:repositoryRoot -PowerShellRoot $powerShellRoot -ProcessRoot $processRoot -HostLabel $hostLabel
            $LASTEXITCODE | Should -Be 0
            ($result -join "`n") | Should -Match 'wrapper-path-verified'
        }
    }

    It 'preserves a relative spaced repository root across Windows PowerShell native forwarding' {
        $powerShellRoot = Join-Path $TestDrive 'Validator PowerShell location'
        $processRoot = Join-Path $TestDrive 'Validator process location'
        [void][IO.Directory]::CreateDirectory($powerShellRoot)
        [void][IO.Directory]::CreateDirectory($processRoot)
        $code = @'
param([string]$RepositoryRoot,[string]$PowerShellRoot,[string]$ProcessRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Environment]::CurrentDirectory = $ProcessRoot
Set-Location -LiteralPath $PowerShellRoot
$junction = Join-Path $PowerShellRoot 'repository link'
try {
    $rejectedOutput = Join-Path $PowerShellRoot 'validator rejected.'
    $lookalikeOutput = Join-Path $PowerShellRoot 'validator rejected'
    $rejected = $false
    try {
        & (Join-Path $RepositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1') `
            -RepositoryRoot $RepositoryRoot -OutputRoot $rejectedOutput -Mode Generate
    }
    catch {
        if ($_.Exception.Message -notmatch '^OutputRoot contains a normalization-sensitive') { throw }
        $rejected = $true
    }
    if (-not $rejected -or [IO.Directory]::Exists($rejectedOutput) -or [IO.Directory]::Exists($lookalikeOutput)) {
        throw 'Rejected validator destination was written.'
    }
    [void](New-Item -ItemType Junction -Path $junction -Target $RepositoryRoot)
    $relativeRepositoryRoot = '.\repository link\'
    & (Join-Path $RepositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1') `
        -RepositoryRoot $relativeRepositoryRoot -Mode Validate
    if ($LASTEXITCODE -ne 0) { throw "Validator failed with exit code $LASTEXITCODE." }
}
finally {
    if ([IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) }
}
'validator-path-verified'
'@
        $path = Join-Path $TestDrive 'validator-path.ps1'
        [IO.File]::WriteAllText($path,$code,[Text.UTF8Encoding]::new($false,$true))
        foreach ($hostCommand in @('pwsh.exe','powershell.exe')) {
            $hostCommandInfo = Get-Command $hostCommand -ErrorAction SilentlyContinue
            if (-not $hostCommandInfo) { continue }
            $hostPath = $hostCommandInfo.Source
            $result = & $hostPath -NoLogo -NoProfile -File $path -RepositoryRoot $script:repositoryRoot -PowerShellRoot $powerShellRoot -ProcessRoot $processRoot
            $LASTEXITCODE | Should -Be 0
            ($result -join "`n") | Should -Match 'validator-path-verified'
        }
    }

    It 'independently verifies committed bytes without engine or authority assembly dependencies' {
        $verifyPath = Join-Path $script:repositoryRoot 'certification\lib\Pspkt.Certification.ProtocolSchemaVerify.cs'
        (Test-Path -LiteralPath $verifyPath -PathType Leaf) | Should -BeTrue
        $validator = Join-Path $script:repositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1'
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $result = & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $validator -Mode Validate
        $LASTEXITCODE | Should -Be 0
        ($result -join "`n") | Should -Match 'Verified 107 types, 681 map rows, 31 associations, 842 schedule rows'
    }

    It 'rejects a parent-mode assembly root instead of silently replacing it' {
        $attempt = Invoke-ProtocolValidationAttempt -ValidatorArguments @(
            '-AssemblyRoot',$TestDrive,
            '-Mode','Validate')
        $attempt.ExitCode | Should -Not -Be 0
        $attempt.Output | Should -Match 'AssemblyRoot is valid only in worker mode'
    }

    It 'rejects a leading __type property projected as an XML attribute' {
        $result = Invoke-ProtocolProbe -Code @'
$originalBaseBytes = [IO.File]::ReadAllBytes($basePath)
$baseText = $utf8.GetString($originalBaseBytes)
$mutatedBaseBytes = $utf8.GetBytes('{"__type":"unexpected",' + $baseText.Substring(1))
$hash = [Security.Cryptography.SHA256]::Create()
try { $pins['protocol-base.catalog.v1.json'] = [BitConverter]::ToString($hash.ComputeHash($mutatedBaseBytes)).Replace('-','').ToLowerInvariant() }
finally { $hash.Dispose() }
$rejected = $false
try {
    [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
        $mutatedBaseBytes, $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins,
        $protocolContract.LiteralExtensionParentNames, $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
}
catch {
    if ($_.Exception.Message -notmatch 'Verifier JSON attribute is not supported: __type') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Independent verifier accepted a leading __type property.' }
'attribute-verified'
'@
        ($result -join "`n") | Should -Be 'attribute-verified'
    }

    It 'preserves escaped JSON names for catalog shape validation' {
        $result = Invoke-ProtocolProbe -Code @'
$originalBaseBytes = [IO.File]::ReadAllBytes($basePath)
$baseText = $utf8.GetString($originalBaseBytes)
$mutatedBaseBytes = $utf8.GetBytes('{"a/b":0,"c/d":0,' + $baseText.Substring(1))
$hash = [Security.Cryptography.SHA256]::Create()
try { $pins['protocol-base.catalog.v1.json'] = [BitConverter]::ToString($hash.ComputeHash($mutatedBaseBytes)).Replace('-','').ToLowerInvariant() }
finally { $hash.Dispose() }
$rejected = $false
try {
    [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
        $mutatedBaseBytes, $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins,
        $protocolContract.LiteralExtensionParentNames, $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
}
catch {
    if ($_.Exception.Message -notmatch 'Catalog identity differs') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Independent verifier accepted an escaped extra property.' }
'escaped-name-verified'
'@
        ($result -join "`n") | Should -Be 'escaped-name-verified'
    }

    It 'rejects an exact forbidden verifier assembly dependency before broad name checks' {
        $result = Invoke-ProtocolProbe -Code @'
$verifyPath = Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.ProtocolSchemaVerify.cs'
$probeSource = [IO.File]::ReadAllText($verifyPath)
$probeSource = $probeSource.Replace('namespace Pspkt.Certification.Protocol', 'namespace Pspkt.Certification.ProtocolProbe')
$probeSource = $probeSource.Replace('ProtocolSchemaVerify', 'ProtocolSchemaProbe')
$probeSource = $probeSource -replace 'public static class ProtocolSchemaProbe\s*\{', @"
public static class ProtocolSchemaProbe
    {
        private static readonly Type DependencyProbe = typeof(Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2);
"@
$probeAssembly = Join-Path $AssemblyRoot 'ProtocolVerifyProbe.dll'
$frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
    @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll')
}
else {
    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object { $_.FullName })
}
Add-Type -TypeDefinition $probeSource -OutputAssembly $probeAssembly -ReferencedAssemblies @(
    $frameworkReferences +
    (Join-Path $AssemblyRoot 'SchemaBootstrap.dll') +
    (Join-Path $AssemblyRoot 'FoundationEngine.dll'))
Add-Type -Path $probeAssembly
$forbiddenAssemblyNames = @(
    [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2].Assembly.GetName().Name,
    [Pspkt.Certification.Protocol.ProtocolSchemaAuthority].Assembly.GetName().Name)
$rejected = $false
try {
    [Pspkt.Certification.ProtocolProbe.ProtocolSchemaProbe]::Verify(
        [IO.File]::ReadAllBytes($basePath), $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins,
        $protocolContract.LiteralExtensionParentNames, $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
}
catch {
    if ($_.Exception.Message -notmatch 'Verifier dependency matches forbidden assembly identity') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Exact forbidden verifier dependency was accepted.' }
'exact-dependency-verified'
'@
        ($result -join "`n") | Should -Be 'exact-dependency-verified'
    }

    It 'rejects verifier dependencies outside the bootstrap and strong-name allowlist' {
        $result = Invoke-ProtocolProbe -Code @'
$verifyPath = Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.ProtocolSchemaVerify.cs'
$probeSource = [IO.File]::ReadAllText($verifyPath)
$probeSource = $probeSource.Replace('namespace Pspkt.Certification.Protocol', 'namespace Pspkt.Certification.AllowlistProbe')
$probeSource = $probeSource.Replace('ProtocolSchemaVerify', 'ProtocolSchemaAllowlistProbe')
$probeSource = $probeSource -replace 'public static class ProtocolSchemaAllowlistProbe\s*\{', @"
public static class ProtocolSchemaAllowlistProbe
    {
        private static readonly Type DependencyProbe = typeof(Pspkt.Certification.NeutralDependency.Marker);
"@
$frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
    @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll')
}
else {
    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object { $_.FullName })
}
$dependencyAssembly = Join-Path $AssemblyRoot 'NeutralDependency.dll'
$probeAssembly = Join-Path $AssemblyRoot 'ProtocolAllowlistProbe.dll'
Add-Type -TypeDefinition 'namespace Pspkt.Certification.NeutralDependency { public static class Marker { } }' `
    -OutputAssembly $dependencyAssembly -ReferencedAssemblies $frameworkReferences
Add-Type -Path $dependencyAssembly
Add-Type -TypeDefinition $probeSource -OutputAssembly $probeAssembly -ReferencedAssemblies @(
    $frameworkReferences +
    (Join-Path $AssemblyRoot 'SchemaBootstrap.dll') +
    $dependencyAssembly)
Add-Type -Path $probeAssembly
$rejected = $false
try {
    [Pspkt.Certification.AllowlistProbe.ProtocolSchemaAllowlistProbe]::Verify(
        [IO.File]::ReadAllBytes($basePath), $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins,
        $protocolContract.LiteralExtensionParentNames, $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
}
catch {
    if ($_.Exception.Message -notmatch 'Verifier dependency is not allowed') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Unsigned verifier dependency was accepted.' }
'allowlist-verified'
'@
        ($result -join "`n") | Should -Be 'allowlist-verified'
    }

    It 'requires exactly two distinct non-empty forbidden assembly names' {
        $result = Invoke-ProtocolProbe -Code @'
$cases = @(
    [pscustomobject]@{ Names = $null; Pattern = 'forbiddenAssemblyNames' },
    [pscustomobject]@{ Names = [string[]]@(); Pattern = 'Forbidden assembly identity set differs' },
    [pscustomobject]@{ Names = [string[]]@('one'); Pattern = 'Forbidden assembly identity set differs' },
    [pscustomobject]@{ Names = [string[]]@('one',''); Pattern = 'Forbidden assembly identity set differs' },
    [pscustomobject]@{ Names = [string[]]@('one','one'); Pattern = 'Forbidden assembly identity set differs' })
foreach ($case in $cases) {
    $rejected = $false
    try {
        [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
            [IO.File]::ReadAllBytes($basePath), $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins,
            $protocolContract.LiteralExtensionParentNames, $bootstrapAssemblyIdentity, $case.Names)
    }
    catch {
        if ($_.Exception.Message -notmatch $case.Pattern) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Invalid forbidden assembly identity set was accepted.' }
}
foreach ($bootstrapCase in @(
    [pscustomobject]@{ Identity = [NullString]::Value; Pattern = 'bootstrapAssemblyIdentity' },
    [pscustomobject]@{ Identity = ''; Pattern = 'Bootstrap assembly identity differs' },
    [pscustomobject]@{ Identity = 'WrongBootstrap, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'; Pattern = 'Verifier dependency is not allowed' })) {
    $rejected = $false
    try {
        [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
            [IO.File]::ReadAllBytes($basePath), $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins,
            $protocolContract.LiteralExtensionParentNames, $bootstrapCase.Identity, $forbiddenAssemblyNames)
    }
    catch {
        if ($_.Exception.Message -notmatch $bootstrapCase.Pattern) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Invalid bootstrap assembly identity was accepted.' }
}
'identity-input-verified'
'@
        ($result -join "`n") | Should -Be 'identity-input-verified'
    }

    It 'sizes conditional bounded fields by complete shape identity and includes list framing' {
        $result = Invoke-ProtocolProbe -Code @'
$base = [IO.File]::ReadAllText($basePath) | ConvertFrom-Json
$base.entries += [pscustomobject]@{
    op='field-set'; parent='WorkerHello'; name='BoundedBody'; variants=@(
        [pscustomobject]@{ name='BoundedBody'; type='BoundedBytes'; maxBytes=20; profile='InteractiveSeat' },
        [pscustomobject]@{ name='BoundedBody'; type='BoundedBytes'; maxBytes=10; profile='NonInteractiveElevated' },
        [pscustomobject]@{ name='BoundedBody'; type='BoundedBytes'; maxBytes=20; profile='NonInteractiveElevated'; status='Forbidden' })
}
$base.entries += [pscustomobject]@{ op='type'; name='SmallValues'; production='List'; elementType='U16'; minCount=0; maxCount=2 }
$base.entries += [pscustomobject]@{ op='field'; parent='WorkerHello'; name='Values'; type='SmallValues' }
$outputs = [Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Generate(
    $utf8.GetBytes(($base | ConvertTo-Json -Depth 30 -Compress)), $overlayBytes, $inventoryBytes, $metaBytes, $catalogContract)
$schedule = $utf8.GetString($outputs['mandatory-tail-schedule.v1.json']) | ConvertFrom-Json
$row = @($schedule.rows | Where-Object { $_.lifecycleVariant -eq 'NonInteractivePS5' -and $_.state -eq 'LeaseAcquired' -and $_.direction -eq 'WorkerToHost' })[0]
$kind = @($row.kinds | Where-Object { $_.name -eq 'WorkerHello' })[0]
if ($kind.maxPayloadBytes -ne 155) { throw "Expected conditional bounded/list payload 155; got $($kind.maxPayloadBytes)." }
$base.entries[-2].maxCount = 65535
$base.entries[-2].elementType = 'Rsa3072PublicBlob'
$quotaRejected = $false
try {
    [void][Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Generate(
        $utf8.GetBytes(($base | ConvertTo-Json -Depth 30 -Compress)), $overlayBytes, $inventoryBytes, $metaBytes, $catalogContract)
}
catch {
    if ($_.Exception.Message -notmatch 'Mandatory tail quota exceeded') { throw }
    $quotaRejected = $true
}
if (-not $quotaRejected) { throw 'Oversized list tail was accepted.' }
'sizing-verified'
'@
        ($result -join "`n") | Should -Be 'sizing-verified'
    }

    It 'validates every conditional field shape independently of the meta gate' {
        $result = Invoke-ProtocolProbe -Code @'
$source = @"
using System;
using System.Collections.Generic;
using System.Reflection;
using Pspkt.Certification.Protocol;

public static class ProtocolConditionalProbe
{
    private static Dictionary<string, object> Record(params object[] pairs)
    {
        Dictionary<string, object> value = new Dictionary<string, object>(StringComparer.Ordinal);
        for (int index = 0; index < pairs.Length; index += 2) value.Add((string)pairs[index], pairs[index + 1]);
        return value;
    }

    private static Dictionary<string, object> Field(string name, string profile, string status, bool bound)
    {
        Dictionary<string, object> field = Record("fieldId", (ulong)1, "name", name, "type", "BoundedBytes");
        if (profile != null) field.Add("profile", profile);
        if (status != null) field.Add("status", status);
        if (bound) field.Add("maxBytes", (ulong)4);
        return field;
    }

    private static string InvokeEffective(List<object> fields, string profile)
    {
        Dictionary<string, object> type = Record("name", "Probe", "production", "Named", "fields", fields);
        MethodInfo method = typeof(ProtocolSchemaVerify).GetMethod("EffectiveFields", BindingFlags.NonPublic | BindingFlags.Static);
        try
        {
            object result = method.Invoke(null, new object[] { type, profile });
            return "count=" + ((List<Dictionary<string, object>>)result).Count;
        }
        catch (TargetInvocationException exception)
        {
            return "error=" + exception.InnerException.Message;
        }
    }

    public static string MissingRequiredShape()
    {
        return InvokeEffective(new List<object> {
            Field("Required", "Any", "Required", true),
            Field("Forbidden", "InteractiveSeat", "Forbidden", true)
        }, "InteractiveSeat");
    }

    public static string MultipleApplicable()
    {
        return InvokeEffective(new List<object> {
            Field("Value", "Any", "Required", true),
            Field("Value", "InteractiveSeat", "Required", true),
            Field("Value", "InteractiveSeat", "Forbidden", true)
        }, "InteractiveSeat");
    }

    public static string OneApplicableInteractive()
    {
        return InvokeEffective(new List<object> {
            Field("Value", "Any", "Required", true),
            Field("Value", "InteractiveSeat", "Forbidden", true)
        }, "InteractiveSeat");
    }

    public static string OneApplicableNonInteractive()
    {
        return InvokeEffective(new List<object> {
            Field("Value", "Any", "Required", true),
            Field("Value", "InteractiveSeat", "Forbidden", true)
        }, "NonInteractiveElevated");
    }

    public static string ZeroApplicableInteractive()
    {
        return InvokeEffective(new List<object> {
            Field("Value", "InteractiveSeat", "Required", true),
            Field("Value", "NonInteractiveElevated", "Forbidden", true)
        }, "InteractiveSeat");
    }

    public static string ZeroApplicableNonInteractive()
    {
        return InvokeEffective(new List<object> {
            Field("Value", "InteractiveSeat", "Required", true),
            Field("Value", "NonInteractiveElevated", "Forbidden", true)
        }, "NonInteractiveElevated");
    }

    public static string MissingBoundSize()
    {
        Dictionary<string, object> required = Field("Value", "InteractiveSeat", "Required", false);
        Dictionary<string, object> forbidden = Field("Value", "InteractiveSeat", "Forbidden", true);
        Dictionary<string, object> parent = Record("name", "Parent", "production", "Named",
            "fields", new List<object> { required, forbidden });
        Dictionary<string, Dictionary<string, object>> types =
            new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
        types.Add("Parent", parent);
        Dictionary<string, object> inventory = Record("maximumNamedDepth", (ulong)8,
            "primitiveValueMaxima", Record("U8", (ulong)1));
        Dictionary<string, ulong> sizes = new Dictionary<string, ulong>(StringComparer.Ordinal);
        MethodInfo method = typeof(ProtocolSchemaAuthority).GetMethod("Size", BindingFlags.NonPublic | BindingFlags.Static);
        try
        {
            object result = method.Invoke(null, new object[] {
                "Parent", "InteractiveSeat", null, types, inventory, sizes, 1
            });
            return "value=" + result;
        }
        catch (TargetInvocationException exception)
        {
            return "error=" + exception.InnerException.Message;
        }
    }

    public static string ProfiledSize(string profile)
    {
        Dictionary<string, object> required = Field("Value", "Any", "Required", true);
        Dictionary<string, object> forbidden = Field("Value", "InteractiveSeat", "Forbidden", true);
        Dictionary<string, object> parent = Record("name", "Parent", "production", "Named",
            "fields", new List<object> { required, forbidden });
        Dictionary<string, Dictionary<string, object>> types =
            new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
        types.Add("Parent", parent);
        Dictionary<string, object> inventory = Record("maximumNamedDepth", (ulong)8,
            "primitiveValueMaxima", Record("U8", (ulong)1));
        Dictionary<string, ulong> sizes = new Dictionary<string, ulong>(StringComparer.Ordinal);
        MethodInfo method = typeof(ProtocolSchemaAuthority).GetMethod("Size", BindingFlags.NonPublic | BindingFlags.Static);
        object result = method.Invoke(null, new object[] { "Parent", profile, null, types, inventory, sizes, 1 });
        return "value=" + result;
    }

    public static string MandatoryNoneState()
    {
        List<object> messages = new List<object> {
            Record("channel", "WorkerApp", "mandatoryTailClass", "Mandatory", "name", "Probe",
                "profile", "Any", "stateAssoc", "None")
        };
        List<object> variants = new List<object> {
            Record("name", "ProbeVariant", "profile", "InteractiveSeat",
                "states", new List<object> { "LeaseAcquired" })
        };
        MethodInfo method = typeof(ProtocolSchemaVerify).GetMethod("VerifyStates", BindingFlags.NonPublic | BindingFlags.Static);
        try
        {
            method.Invoke(null, new object[] { messages, variants });
            return "accepted";
        }
        catch (TargetInvocationException exception)
        {
            return "error=" + exception.InnerException.Message;
        }
    }
}
"@
$probeAssembly = Join-Path $AssemblyRoot 'ProtocolConditionalProbe.dll'
$frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
    @('System.dll','System.Core.dll')
}
else {
    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object { $_.FullName })
}
Add-Type -TypeDefinition $source -OutputAssembly $probeAssembly -ReferencedAssemblies @(
    $frameworkReferences +
    (Join-Path $AssemblyRoot 'ProtocolVerify.dll') +
    (Join-Path $AssemblyRoot 'ProtocolAuthority.dll'))
Add-Type -Path $probeAssembly
if ([ProtocolConditionalProbe]::MissingRequiredShape() -notmatch '^error=Forbidden field has no required shape') { throw 'Missing shape was accepted.' }
if ([ProtocolConditionalProbe]::MultipleApplicable() -notmatch '^error=Forbidden field has multiple applicable') { throw 'Ambiguous shape was accepted.' }
if ([ProtocolConditionalProbe]::OneApplicableInteractive() -cne 'count=0') { throw 'Forbidden profile remained effective.' }
if ([ProtocolConditionalProbe]::OneApplicableNonInteractive() -cne 'count=1') { throw 'Unaffected profile was cleared.' }
if ([ProtocolConditionalProbe]::ZeroApplicableInteractive() -cne 'count=1') { throw 'Other-profile required row was cleared.' }
if ([ProtocolConditionalProbe]::ZeroApplicableNonInteractive() -cne 'count=0') { throw 'Zero-applicable forbidden row became effective.' }
if ([ProtocolConditionalProbe]::MissingBoundSize() -notmatch '^error=Invalid conditional field bound') { throw 'Missing bound was treated as a wildcard.' }
if ([ProtocolConditionalProbe]::ProfiledSize('InteractiveSeat') -cne 'value=0') { throw 'Any required row survived its forbidden profile.' }
if ([ProtocolConditionalProbe]::ProfiledSize('NonInteractiveElevated') -cne 'value=14') { throw 'Any required row was removed from the unaffected profile.' }
if ([ProtocolConditionalProbe]::MandatoryNoneState() -notmatch '^error=Mandatory WorkerApp state is missing') { throw 'Mandatory None state was accepted.' }
'conditional-shapes-verified'
'@
        ($result -join "`n") | Should -Be 'conditional-shapes-verified'
    }

    It 'regenerates byte-identical outputs in Windows PowerShell without installing tools' {
        $desktop = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if (-not $desktop) {
            Set-ItResult -Skipped -Because 'Windows PowerShell is not installed.'
            return
        }
        $destination = Join-Path $TestDrive 'desktop'
        $generator = Join-Path $script:repositoryRoot 'certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1'
        & $desktop.Source -NoLogo -NoProfile -File $generator -OutputRoot $destination
        $LASTEXITCODE | Should -Be 0
        . $script:contractPath
        $contract = Get-PspktProtocolSchemaContract
        foreach ($path in $contract.OutputPathSet) {
            $generated = Join-Path $destination $path.Replace('/', '\')
            (Get-FileHash -LiteralPath $generated -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $contract.OutputSha256ByPath[$path]
        }
        & $desktop.Source -NoLogo -NoProfile -File (Join-Path $script:repositoryRoot 'certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1') -Mode Validate -OutputRoot $destination
        $LASTEXITCODE | Should -Be 0
    }

    It 'pins nested byte policies for protocol artifacts' {
        $expected = [ordered]@{
            'certification\schema\.gitattributes' = @(
                '/.gitattributes text eol=lf -filter -ident -working-tree-encoding',
                '/catalog/protocol-base.catalog.v1.json -text -eol -filter -ident -working-tree-encoding',
                '/catalog/overlay.catalog.v1.json -text -eol -filter -ident -working-tree-encoding',
                '/protocol-inventory.v1.json -text -eol -filter -ident -working-tree-encoding',
                '/protocol-schema.v1.json -text -eol -filter -ident -working-tree-encoding',
                '/generated-base-id-map.v1.json -text -eol -filter -ident -working-tree-encoding',
                '/protocol-message-association.v1.json -text -eol -filter -ident -working-tree-encoding',
                '/mandatory-tail-schedule.v1.json -text -eol -filter -ident -working-tree-encoding')
            'certification\lib\.gitattributes' = @(
                '/.gitattributes text eol=lf -filter -ident -working-tree-encoding',
                '/Pspkt.Certification.ProtocolSchemaAuthority.cs text eol=lf -filter -ident -working-tree-encoding',
                '/Pspkt.Certification.ProtocolSchemaVerify.cs text eol=lf -filter -ident -working-tree-encoding',
                '/Pspkt.Certification.ProtocolSchemaContract.ps1 text eol=lf -filter -ident -working-tree-encoding')
            'certification\vectors\.gitattributes' = @(
                '/.gitattributes text eol=lf -filter -ident -working-tree-encoding',
                '/New-PspktPhase4ProtocolSchemaVectors.ps1 text eol=lf -filter -ident -working-tree-encoding')
            'certification\validators\.gitattributes' = @(
                '/.gitattributes text eol=lf -filter -ident -working-tree-encoding',
                '/Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1 text eol=lf -filter -ident -working-tree-encoding')
            'tests\phase4-protocol\.gitattributes' = @(
                '/.gitattributes text eol=lf -filter -ident -working-tree-encoding',
                '/pspkt.ProtocolCatalogEngineV2.Tests.ps1 text eol=lf -filter -ident -working-tree-encoding',
                '/pspkt.Phase4ProtocolSchemaAuthority.Tests.ps1 text eol=lf -filter -ident -working-tree-encoding')
        }
        foreach ($path in $expected.Keys) {
            [IO.File]::ReadAllText((Join-Path $script:repositoryRoot $path)) | Should -Be (($expected[$path] -join "`n") + "`n")
        }
    }

    It 'rejects boolean sizing values instead of coercing them to integers' {
        $result = Invoke-ProtocolProbe -Code @'
$inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
$inventory.mandatoryCardinality = $true
$rejected = $false
try {
    [void][Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Generate(
        [IO.File]::ReadAllBytes($basePath), $overlayBytes,
        $utf8.GetBytes(($inventory | ConvertTo-Json -Depth 30 -Compress)), $metaBytes, $catalogContract)
}
catch {
    if ($_.Exception.Message -notmatch 'Invalid projection number: mandatoryCardinality') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Boolean mandatory cardinality was coerced to one.' }
'integer-verified'
'@
        ($result -join "`n") | Should -Be 'integer-verified'
    }

    It 'rejects input digest drift before evaluating the catalog or creating outputs' {
        $catalog = [IO.File]::ReadAllText((Join-Path $script:repositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json')) | ConvertFrom-Json
        $catalog.entries[1].type = 'UndefinedPayload'
        $tampered = Join-Path $TestDrive 'tampered-base.json'
        [IO.File]::WriteAllText($tampered, ($catalog | ConvertTo-Json -Depth 30 -Compress), [Text.UTF8Encoding]::new($false,$true))
        $destination = Join-Path $TestDrive 'must-not-exist'
        $attempt = Invoke-ProtocolValidationAttempt -ValidatorArguments @('-Mode','Generate','-BaseCatalogPath',$tampered,'-OutputRoot',$destination)
        $attempt.ExitCode | Should -Not -Be 0
        $attempt.Output | Should -Match 'Pinned input hash differs: protocol-base.catalog.v1.json'
        (Test-Path -LiteralPath $destination) | Should -BeFalse
    }

    It 'rejects frozen engine byte drift before compilation' {
        $fixture = Join-Path $TestDrive 'frozen'
        $paths = @(
            'certification\lib\Pspkt.Certification.FoundationCatalogEngine.cs',
            'certification\lib\Pspkt.Certification.FoundationPolicy.cs',
            'certification\lib\Pspkt.Certification.SchemaBootstrap.cs',
            'certification\lib\Pspkt.Certification.FoundationContract.ps1',
            'certification\lib\Pspkt.Certification.ProtocolSchemaContract.ps1',
            'certification\schema\protocol-schema-meta.v1.json',
            'certification\.gitattributes','tests\.gitattributes','.gitattributes',
            'certification\lib\.gitattributes','certification\schema\.gitattributes',
            'certification\vectors\.gitattributes','certification\validators\.gitattributes',
            'tests\phase4-protocol\.gitattributes')
        foreach ($path in $paths) {
            $target = Join-Path $fixture $path
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            [IO.File]::Copy((Join-Path $script:repositoryRoot $path), $target)
        }
        [IO.File]::AppendAllText((Join-Path $fixture $paths[0]), "`n", [Text.UTF8Encoding]::new($false))
        $attempt = Invoke-ProtocolValidationAttempt -ValidatorArguments @('-RepositoryRoot',$fixture,'-Mode','Validate')
        $attempt.ExitCode | Should -Not -Be 0
        $attempt.Output | Should -Match 'Pinned frozen source hash differs: certification/lib/Pspkt.Certification.FoundationCatalogEngine.cs'
    }

    It 'independently checks inventory identity provenance and union labels beyond its file digest' {
        $result = Invoke-ProtocolProbe -Code @'
foreach ($mutation in @('identity','provenance','provenance-key','profile-order','direction-order','excluded-channels','unassigned-ids','reserved-illegal','union-label','union-missing')) {
    $inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
    if ($mutation -eq 'identity') { $inventory.schemaId = 'WrongInventoryV1' }
    elseif ($mutation -eq 'provenance') { $inventory.sourceHashes.'dependency1bb-r9-normative-tables.txt' = '0' * 64 }
    elseif ($mutation -eq 'provenance-key') {
        $inventory.sourceHashes.PSObject.Properties.Remove('dependency1bb-r9-normative-tables.txt')
        $inventory.sourceHashes | Add-Member -NotePropertyName 'filtered-base' -NotePropertyValue $pins['filtered-base']
    }
    elseif ($mutation -eq 'profile-order') { $inventory.profileOrder = @($inventory.profileOrder[1],$inventory.profileOrder[0]) }
    elseif ($mutation -eq 'direction-order') { $inventory.directionOrder = @($inventory.directionOrder[1],$inventory.directionOrder[0]) }
    elseif ($mutation -eq 'excluded-channels') { $inventory.excludedTailChannels = @('BrokerControl') }
    elseif ($mutation -eq 'unassigned-ids') { $inventory.unassignedOverlayTypeIds = @(4872,4873,4875) }
    elseif ($mutation -eq 'reserved-illegal') { $inventory.reservedIllegalType.id = 4880 }
    elseif ($mutation -eq 'union-label') { $inventory.unionMappings[0].branches[0].semanticLabel = 'WrongSemanticLabel' }
    else { $inventory.unionMappings = @($inventory.unionMappings[0..($inventory.unionMappings.Count - 2)]) }
    $mutated = $utf8.GetBytes(($inventory | ConvertTo-Json -Depth 30 -Compress))
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $pins['protocol-inventory.v1.json'] = [BitConverter]::ToString($hash.ComputeHash($mutated)).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
    if ($mutation -in @('profile-order','direction-order','excluded-channels','unassigned-ids','reserved-illegal')) {
        $authorityRejected = $false
        try {
            [void][Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Generate(
                [IO.File]::ReadAllBytes($basePath),$overlayBytes,$mutated,$metaBytes,$catalogContract)
        }
        catch {
            if ($_.Exception.Message -notmatch 'Protocol profile order mismatch|Protocol direction order mismatch|Protocol excluded tail channels mismatch|Protocol unassigned overlay type ids mismatch|Protocol reserved illegal type mismatch') { throw }
            $authorityRejected = $true
        }
        if (-not $authorityRejected) { throw "Protocol authority accepted inventory $mutation drift." }
    }
    $rejected = $false
    try {
        [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
            [IO.File]::ReadAllBytes($basePath), $overlayBytes, $mutated, $metaBytes, $outputs, $pins,
            $protocolContract.LiteralExtensionParentNames, $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
    }
    catch {
        if ($_.Exception.Message -notmatch 'Inventory identity differs|Inventory source provenance differs|Profile order differs|Direction order differs|Excluded tail channels differ|Unassigned overlay type ids differ|Reserved illegal type differs|Pinned hash differs: union:LaunchFenceGate|Union inventory cardinality differs') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "Independent verifier accepted inventory $mutation drift." }
}
'inventory-verified'
'@
        ($result -join "`n") | Should -Be 'inventory-verified'
    }

    It 'removes whole dependent unions to fixpoint without substring or child-name omission' {
        $result = Invoke-ProtocolProbe -Code @'
$base = '{"schemaVersion":1,"schemaId":"PspktProtocolBaseCatalogV1","space":"protocol-base","entries":[{"op":"type","name":"MintAttestedV1","production":"Named"},{"op":"field","parent":"MintAttestedV1","name":"Forward","type":"LiveDependency"},{"op":"type","name":"LiveDependency","production":"Named"},{"op":"field","parent":"LiveDependency","name":"Value","type":"U32"},{"op":"type","name":"MintAttestedV1Copy","production":"Named"},{"op":"field","parent":"MintAttestedV1Copy","name":"Value","type":"U8"},{"op":"type","name":"Retained","production":"Named"},{"op":"field","parent":"Retained","name":"MintAttestedV1","type":"MintAttestedV1Copy"},{"op":"union","name":"Choice","discriminator":"UnionKind","branches":[{"name":"UnionBad","fields":[{"name":"Value","type":"MintAttestedV1"}]},{"name":"UnionGood","fields":[{"name":"Value","type":"U8"}]}]},{"op":"type","name":"ListOfGood","production":"List","elementType":"UnionGood","minCount":0,"maxCount":1},{"op":"type","name":"Wrapper","production":"Named"},{"op":"field","parent":"Wrapper","name":"Value","type":"ListOfGood"},{"op":"message","channel":"WorkerApp","direction":"WorkerToHost","name":"Gone","payloadRoot":"Wrapper","profile":"Any","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
$overlay = '{"schemaVersion":1,"schemaId":"PspktProtocolOverlayCatalogV1","space":"protocol-overlay","entries":[{"op":"extend","parent":"MintAttestedV1","fields":[{"name":"DoNotOmit","type":"U8","id":40}]},{"op":"delete","name":"Wrapper"}]}'
$projectionBytes = [Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Filter(
    $utf8.GetBytes($base), $utf8.GetBytes($overlay), $protocolContract.DeferredSeedTypeNames, $protocolContract.DeferredSeedMessageKeys)
$projection = $utf8.GetString($projectionBytes) | ConvertFrom-Json
$expected = 'ListOfGood,MintAttestedV1,S4UMintSlotV1,ServiceControlEventNodeProofV1,UnionBad,UnionGood,UnionKind,Wrapper'
if (($projection.omittedTypes -join ',') -cne $expected) { throw "Wrong omission closure: $($projection.omittedTypes -join ',')" }
if (($projection.omittedMessages -join ',') -cne 'BrokerControl:MintRevoked,WorkerApp:Gone') { throw 'Wrong message closure.' }
if (($projection.base.entries | Where-Object { $_.op -eq 'type' } | ForEach-Object { $_.name }) -join ',' -cne 'LiveDependency,MintAttestedV1Copy,Retained') { throw 'Forward or substring omission occurred.' }
if ($projection.overlay.entries.Count -ne 0) { throw 'Owned extension or delete survived.' }
$invalid = $base.Replace('"type":"MintAttestedV1Copy"','"type":"UndefinedPayload"')
$rejected = $false
try { [void][Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Filter($utf8.GetBytes($invalid),$utf8.GetBytes($overlay),$protocolContract.DeferredSeedTypeNames,$protocolContract.DeferredSeedMessageKeys) }
catch { if ($_.Exception.Message -notmatch 'Undefined retained reference: UndefinedPayload') { throw }; $rejected = $true }
if (-not $rejected) { throw 'Undefined retained reference was accepted.' }
'closure-verified'
'@
        ($result -join "`n") | Should -Be 'closure-verified'
    }

    It 'includes overlay-field dependencies in the independent omission closure' {
        $result = Invoke-ProtocolProbe -Code @'
$overlay = $utf8.GetString($overlayBytes) | ConvertFrom-Json
$overlay.entries += [pscustomobject]@{
    op='overlay-field'
    parent='WorkerHello'
    fields=@([pscustomobject]@{ name='DeferredProof'; type='MintAttestedV1' })
}
$mutatedOverlayBytes = $utf8.GetBytes(($overlay | ConvertTo-Json -Depth 30 -Compress))
$hash = [Security.Cryptography.SHA256]::Create()
try {
    $pins['overlay.catalog.v1.json'] = [BitConverter]::ToString(
        $hash.ComputeHash($mutatedOverlayBytes)).Replace('-','').ToLowerInvariant()
}
finally { $hash.Dispose() }
$rejected = $false
try {
    [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
        [IO.File]::ReadAllBytes($basePath),$mutatedOverlayBytes,$inventoryBytes,$metaBytes,$outputs,$pins,
        $protocolContract.LiteralExtensionParentNames,$bootstrapAssemblyIdentity,$forbiddenAssemblyNames)
}
catch {
    if ($_.Exception.Message -notmatch 'Independent omission closure differs') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Independent verifier ignored an overlay-field dependency.' }
'overlay-field-verified'
'@
        ($result -join "`n") | Should -Be 'overlay-field-verified'
    }

    It 'gates projection reads through representative frozen JSON size and shape caps' {
        $result = Invoke-ProtocolProbe -Code @'
$empty = $utf8.GetBytes('{"schemaVersion":1,"schemaId":"PspktProtocolOverlayCatalogV1","space":"protocol-overlay","entries":[]}')
$cases = @(
    @{ Reason='file-limit'; Bytes=[byte[]]::new(1048577) },
    @{ Reason='depth-limit'; Bytes=$utf8.GetBytes(('[' * 33) + '0' + (']' * 33)) },
    @{ Reason='property-limit'; Bytes=$utf8.GetBytes('{' + ((1..4097 | ForEach-Object { '"p' + $_ + '":0' }) -join ',') + '}') },
    @{ Reason='array-limit'; Bytes=$utf8.GetBytes('[' + ((1..8193 | ForEach-Object { '0' }) -join ',') + ']') },
    @{ Reason='string-limit'; Bytes=$utf8.GetBytes('"' + ('x' * 262145) + '"') },
    @{ Reason='duplicate-key'; Bytes=$utf8.GetBytes('{"entries":[],"entries":[]}') },
    @{ Reason='bom-forbidden'; Bytes=[byte[]]@(239,187,191,123,125) })
foreach ($case in $cases) {
    $rejected = $false
    try { [void][Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Filter($case.Bytes,$empty,$protocolContract.DeferredSeedTypeNames,$protocolContract.DeferredSeedMessageKeys) }
    catch { if ($_.Exception.Message -notmatch ('Protocol JSON rejected: ' + $case.Reason)) { throw }; $rejected = $true }
    if (-not $rejected) { throw "Projection bypassed $($case.Reason)." }
}
'caps-verified'
'@
        ($result -join "`n") | Should -Be 'caps-verified'
    }

    It 'preserves generated counters shared directions and literal extension policy' {
        $result = Invoke-ProtocolProbe -Code @'
$schema = $utf8.GetString($outputs['protocol-schema.v1.json']) | ConvertFrom-Json
$association = $utf8.GetString($outputs['protocol-message-association.v1.json']) | ConvertFrom-Json
$worker = @($schema.types | Where-Object { $_.name -eq 'WorkerAppMessageKind' })[0]
if (($worker.members.value -join ',') -cne '1,2,3,4,5,6,7,4224') { throw 'Generated kind counter or literal kind advanced incorrectly.' }
$owners = @($schema.types | Where-Object { $_.name -in @('WorkerAppMessageKind','BrokerControlMessageKind','LocalIpcMessageKind') })
if (($owners.typeId -join ',') -cne '88,89,90') { throw 'Generated channel owner counters differ.' }
foreach ($channel in @('WorkerApp','BrokerControl')) {
    $rows = @($association.rows | Where-Object { $_.channel -eq $channel -and $_.name -eq 'Keepalive' })
    $kindId = if ($channel -eq 'WorkerApp') { 5 } else { 4372 }
    if ($rows.Count -ne 2 -or $rows[0].kindId -ne $kindId -or $rows[1].kindId -ne $kindId -or $rows[0].payloadRoot -cne 'Keepalive' -or $rows[1].payloadRoot -cne 'Keepalive') { throw 'Repeated direction identity differs.' }
}
foreach ($mutation in @('extension','metadata')) {
    $overlay = $utf8.GetString($overlayBytes) | ConvertFrom-Json
    if ($mutation -eq 'extension') {
        $overlay.entries += [pscustomobject]@{ op='field-set'; parent='WorkerHello'; name='UnlistedExtension'; id=40; variants=@([pscustomobject]@{ name='UnlistedExtension'; type='U8' }) }
        $reason = 'extension-parent-forbidden'
    }
    else {
        $row = @($overlay.entries | Where-Object { $_.op -eq 'overlay-message' -and $_.name -eq 'Keepalive' -and $_.direction -eq 'BrokerToHost' })[0]
        $row.payloadRoot = 'BrokerFailure'
        $reason = 'message-metadata-conflict'
    }
    $rejected = $false
    try { [void][Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Generate([IO.File]::ReadAllBytes($basePath),$utf8.GetBytes(($overlay | ConvertTo-Json -Depth 30 -Compress)),$inventoryBytes,$metaBytes,$catalogContract) }
    catch { if ($_.Exception.Message -notmatch $reason) { throw }; $rejected = $true }
    if (-not $rejected) { throw "V2 policy accepted $mutation mutation." }
}
'counters-verified'
'@
        ($result -join "`n") | Should -Be 'counters-verified'
    }

    It 'independently rejects schema map association lifecycle and tail tampering beyond output hashes' {
        $result = Invoke-ProtocolProbe -Code @'
foreach ($mutation in @('schema','non-kind','missing-kind','duplicate-kind','association-missing','association-extra','association-order','association-direction','tail-charge','tail-frame','lifecycle')) {
    $mutatedOutputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    foreach ($name in $outputs.Keys) { $mutatedOutputs.Add($name,$outputs[$name]) }
    $mutatedInventory = $inventoryBytes
    $name = switch -Regex ($mutation) {
        '^schema$' { 'protocol-schema.v1.json'; break }
        'kind$' { 'generated-base-id-map.v1.json'; break }
        '^association' { 'protocol-message-association.v1.json'; break }
        '^tail' { 'mandatory-tail-schedule.v1.json'; break }
        default { 'protocol-inventory.v1.json' }
    }
    $original = if ($mutation -eq 'lifecycle') { $inventoryBytes } else { $outputs[$name] }
    $value = $utf8.GetString($original) | ConvertFrom-Json
    switch ($mutation) {
        'schema' { $value.types[0].fields[0].name = 'TamperedField' }
        'non-kind' { @($value | Where-Object { $_.category -eq 'kind' })[0].category = 'type' }
        'missing-kind' { $first = @($value | Where-Object { $_.category -eq 'kind' })[0]; $value = @($value | Where-Object { -not [object]::ReferenceEquals($_,$first) }) }
        'duplicate-kind' { $value += @($value | Where-Object { $_.category -eq 'kind' })[0] }
        'association-missing' { $value.rows = @($value.rows | Select-Object -Skip 1) }
        'association-extra' { $value.rows += $value.rows[0] }
        'association-order' { $first = $value.rows[0]; $value.rows[0] = $value.rows[1]; $value.rows[1] = $first }
        'association-direction' { $value.rows[0].direction = 'HostToWorker' }
        'tail-charge' { $value.rows[0].wrapperBytes++ }
        'tail-frame' { $value.rows[0].kinds[0].maxSignedFrameBytes++ }
        'lifecycle' { $value.lifecycle.variants[0].states[0] = 'UnknownState' }
    }
    $json = if ($name -eq 'generated-base-id-map.v1.json') {
        ConvertTo-Json -InputObject ([object[]]$value) -Depth 30 -Compress
    }
    else { ConvertTo-Json -InputObject $value -Depth 30 -Compress }
    $bytes = $utf8.GetBytes($json)
    if ($mutation -eq 'lifecycle') { $mutatedInventory = $bytes }
    else { $mutatedOutputs[$name] = $bytes }
    $priorPin = $pins[$name]
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $pins[$name] = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
    $rejected = $false
    try {
        [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
            [IO.File]::ReadAllBytes($basePath),$overlayBytes,$mutatedInventory,$metaBytes,$mutatedOutputs,$pins,
            $protocolContract.LiteralExtensionParentNames,$bootstrapAssemblyIdentity,$forbiddenAssemblyNames)
    }
    catch {
        if ($_.Exception.Message -notmatch 'Field projection differs|Map projection differs|Extra schema or map rows|Association equality or order differs|Mandatory tail equality or order differs|Lifecycle lists differ') { throw }
        $rejected = $true
    }
    finally { $pins[$name] = $priorPin }
    if (-not $rejected) { throw "Independent verifier accepted $mutation." }
}
'tamper-verified'
'@
        ($result -join "`n") | Should -Be 'tamper-verified'
    }

    It 'fails closed for discovery block skipped and excluded Pester containers' {
        $probeRoot = Join-Path $TestDrive 'combined-gate-probes'
        [void][IO.Directory]::CreateDirectory($probeRoot)
        $probeSources = [ordered]@{
            'pass.Tests.ps1' = "Describe 'pass' { It 'runs' { 1 | Should -Be 1 } }"
            'discovery.Tests.ps1' = "Describe 'discovery' {"
            'block.Tests.ps1' = "Describe 'block' { BeforeAll { throw 'block failed' }; It 'does not pass' { 1 | Should -Be 1 } }"
            'skip-one.Tests.ps1' = "Describe 'skip one' { It 'skips' -Skip { 1 | Should -Be 1 } }"
            'skip-two.Tests.ps1' = "Describe 'skip two' { It 'skips' -Skip { 1 | Should -Be 1 } }"
            'runtime-skip.Tests.ps1' = "Describe 'runtime skip' { It 'passes' { 1 | Should -Be 1 }; It 'runtime skips' { Set-ItResult -Skipped -Because 'probe' } }"
            'inconclusive.Tests.ps1' = "Describe 'inconclusive' { It 'passes' { 1 | Should -Be 1 }; It 'is inconclusive' { Set-ItResult -Inconclusive -Because 'probe' } }"
            'static-mixed.Tests.ps1' = "Describe 'static mixed' { It 'passes' { 1 | Should -Be 1 }; It 'skips' -Skip { 1 | Should -Be 1 } }"
            'excluded.Tests.ps1' = "Describe 'excluded' -Tag 'Excluded' { It 'does not run' { 1 | Should -Be 1 } }"
        }
        foreach ($name in $probeSources.Keys) {
            [IO.File]::WriteAllText((Join-Path $probeRoot $name), $probeSources[$name], [Text.UTF8Encoding]::new($false,$true))
        }
        $loadedPester = Get-Module Pester | Where-Object { $_.Version -ge [version]'5.3.3' -and $_.Version -lt [version]'6.0.0' }
        $selectedPester = if ($loadedPester) {
            $loadedPester
        }
        else {
            Get-Module -ListAvailable Pester |
                Where-Object { $_.Version -ge [version]'5.3.3' -and $_.Version -lt [version]'6.0.0' } |
                Sort-Object Version -Descending |
                Select-Object -First 1
        }
        if (-not $selectedPester) { throw 'Pester 5.3.3 through 5.x is required.' }
        $modulePath = Join-Path $selectedPester.ModuleBase 'Pester.psd1'
        $code = @'
param([string]$PesterPath,[string]$ProbeRoot)
$ErrorActionPreference = 'Stop'
Import-Module $PesterPath -Force
$pesterVersion = (Get-Module Pester).Version
if ($pesterVersion -lt [version]'5.3.3' -or $pesterVersion -ge [version]'6.0.0') { throw 'Unsupported Pester version.' }
'@ + "`n" + $script:protocolCombinedGateCode + @'
$pass = Join-Path $ProbeRoot 'pass.Tests.ps1'
$skipOne = Join-Path $ProbeRoot 'skip-one.Tests.ps1'
$scenarios = @(
    [pscustomobject]@{ Name='discovery'; Paths=@($pass,(Join-Path $ProbeRoot 'discovery.Tests.ps1')); ExcludeTag=$null },
    [pscustomobject]@{ Name='block'; Paths=@($pass,(Join-Path $ProbeRoot 'block.Tests.ps1')); ExcludeTag=$null },
    [pscustomobject]@{ Name='skipped-only'; Paths=@($skipOne,(Join-Path $ProbeRoot 'skip-two.Tests.ps1')); ExcludeTag=$null },
    [pscustomobject]@{ Name='mixed-skipped'; Paths=@($pass,$skipOne); ExcludeTag=$null },
    [pscustomobject]@{ Name='runtime-skip'; Paths=@($pass,(Join-Path $ProbeRoot 'runtime-skip.Tests.ps1')); ExcludeTag=$null },
    [pscustomobject]@{ Name='inconclusive'; Paths=@($pass,(Join-Path $ProbeRoot 'inconclusive.Tests.ps1')); ExcludeTag=$null },
    [pscustomobject]@{ Name='excluded'; Paths=@($pass,(Join-Path $ProbeRoot 'excluded.Tests.ps1')); ExcludeTag='Excluded' })
foreach ($scenario in $scenarios) {
    $parameters = @{ Path=$scenario.Paths; Output='None'; PassThru=$true }
    if ($scenario.ExcludeTag) { $parameters.ExcludeTagFilter = $scenario.ExcludeTag }
    $result = Invoke-Pester @parameters
    if ($scenario.Name -eq 'runtime-skip') {
        $probe = @($result.Tests | Where-Object Name -eq 'runtime skips')[0]
        if ($probe.Result -ne 'Skipped' -or $probe.Skip -or -not $probe.Executed) { throw 'Runtime-skip probe shape differs.' }
    }
    if ($scenario.Name -eq 'inconclusive') {
        $probe = @($result.Tests | Where-Object Name -eq 'is inconclusive')[0]
        $validShape = ($probe.Result -eq 'Inconclusive' -or ($probe.Result -eq 'Skipped' -and -not $probe.Skip)) -and $probe.Executed
        if (-not $validShape) { throw 'Inconclusive probe shape differs.' }
    }
    if (Test-ProtocolCombinedResult -Result $result -ExpectedPaths $scenario.Paths) {
        throw "Combined Pester gate accepted $($scenario.Name)."
    }
}
$staticPaths = @($pass,(Join-Path $ProbeRoot 'static-mixed.Tests.ps1'))
$staticResult = Invoke-Pester -Path $staticPaths -Output None -PassThru
if (-not (Test-ProtocolCombinedResult -Result $staticResult -ExpectedPaths $staticPaths)) {
    throw 'Combined Pester gate rejected a declaration-time skip control.'
}
'combined-gate-probes-verified'
'@
        $path = Join-Path $TestDrive 'combined-gate-probes.ps1'
        [IO.File]::WriteAllText($path,$code,[Text.UTF8Encoding]::new($false,$true))
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $result = & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $path -PesterPath $modulePath -ProbeRoot $probeRoot
        $LASTEXITCODE | Should -Be 0
        ($result -join "`n") | Should -Match 'combined-gate-probes-verified'
    }

    It 'runs the V2 and authority suites in one Pester process without recursive combined runs' -Tag 'ProtocolCombined' -Skip:([Environment]::GetEnvironmentVariable('PSPKT_PROTOCOL_COMBINED_CHILD') -eq '1') {
        $loadedPester = Get-Module Pester | Where-Object { $_.Version -ge [version]'5.3.3' -and $_.Version -lt [version]'6.0.0' }
        $selectedPester = if ($loadedPester) {
            $loadedPester
        }
        else {
            Get-Module -ListAvailable Pester |
                Where-Object { $_.Version -ge [version]'5.3.3' -and $_.Version -lt [version]'6.0.0' } |
                Sort-Object Version -Descending |
                Select-Object -First 1
        }
        if (-not $selectedPester) { throw 'Pester 5.3.3 through 5.x is required.' }
        $modulePath = Join-Path $selectedPester.ModuleBase 'Pester.psd1'
        $code = @'
param([string]$RepositoryRoot,[string]$PesterPath)
$ErrorActionPreference = 'Stop'
$env:PSPKT_PROTOCOL_COMBINED_CHILD = '1'
Import-Module $PesterPath -Force
$pesterVersion = (Get-Module Pester).Version
if ($pesterVersion -lt [version]'5.3.3' -or $pesterVersion -ge [version]'6.0.0') { exit 1 }
'@ + "`n" + $script:protocolCombinedGateCode + @'
$paths = @(
    (Join-Path $RepositoryRoot 'tests\phase4-protocol\pspkt.ProtocolCatalogEngineV2.Tests.ps1'),
    (Join-Path $RepositoryRoot 'tests\phase4-protocol\pspkt.Phase4ProtocolSchemaAuthority.Tests.ps1'))
$result = Invoke-Pester -Path $paths -ExcludeTagFilter ProtocolCombined -Output Normal -PassThru
if (-not (Test-ProtocolCombinedResult -Result $result -ExpectedPaths $paths)) { exit 1 }
'combined-verified'
'@
        $path = Join-Path $TestDrive 'combined.ps1'
        [IO.File]::WriteAllText($path,$code,[Text.UTF8Encoding]::new($false,$true))
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $result = & (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $path -RepositoryRoot $script:repositoryRoot -PesterPath $modulePath
        $LASTEXITCODE | Should -Be 0
        ($result -join "`n") | Should -Match 'combined-verified'
    }
}
