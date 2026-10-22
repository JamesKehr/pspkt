Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktEvidenceRuntimeContract {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    [pscustomobject]@{
        BaseCommit = 'adebe26f4fbff7efb427261e91bbad359cf6b616'
        PublicDomainParameters = @('RepositoryRoot', 'WorkRoot', 'PesterManifestPath')
        WorkRootMaximumLength = 100
        CheckoutAction = [pscustomobject]@{
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
        UncheckedTokens = @(
            'evidence-authenticity-unchecked', 'artifact-id-unbound',
            'profile-authentication-unchecked', 'profile-value-unbound',
            'signature-authentication-unchecked', 'signature-key-binding-unchecked',
            'subject-digest-unchecked', 'copied-protocol-digests-unchecked',
            'cross-envelope-references-unchecked', 'freshness-unchecked',
            'ledger-record-references-unchecked', 'schema-bindings-unchecked',
            'producer-digests-unchecked'
        )
        KindTokenCodes = @(
            'ABCEFHJ', 'ABCHJ', 'ABCDEFHJ', 'ABCHJ', 'ABCHJ', 'ABCHJ',
            'ABCDHJ', 'ABCDHJ', 'ABCDHJ', 'ABCDHJ', 'ABCDHJ', 'ABCDHJ', 'ABCDHJ',
            'ABCHJ', 'ABCHJ', 'ABCEFHJ', 'ABCDEFGJL', 'ABCDEFGJL', 'ABCDJKM',
            'ABCDJM', 'ABCDEFIJM', 'ABCDIJKM'
        )
        AssemblyRoles = @('Bootstrap', 'Runtime', 'M1', 'M2', 'M3')
        RuntimeSourceNames = @(
            'EvidenceArtifactEnvelopeCodec.cs',
            'DecodedEvidenceArtifactEnvelope.cs',
            'EvidenceSchemaSnapshot.cs',
            'EvidenceAuthorityJsonReader.cs',
            'EvidencePayloadCodec.cs',
            'EvidenceTlvCursor.cs',
            'EvidenceSignatureContract.cs'
        )
        ManifestRoles = @(
            'RuntimeAuthorityInputs', 'BootstrapSource', 'RuntimeSources',
            'DocumentationInputs', 'BytePolicyInputs', 'ValidationCodeInputs',
            'TestSourceInputs', 'PesterRuntimeOptions', 'RequiredPesterTests',
            'ResultBoundaryContract', 'ResultFaultFixtures', 'Fixtures', 'Generator',
            'ToolchainReferenceInputs', 'Mutants', 'PublicationSourceInputs',
            'SourceExportPaths', 'RunArtifacts', 'CIReceiptContract'
        )
        SuccessResultFields = @(
            'SchemaId', 'SchemaVersion', 'Outcome', 'RunId', 'BaseCommit',
            'HostEdition', 'HostVersion', 'PesterVersion', 'RepositoryRoot',
            'WorkRoot', 'RunRoot', 'SourceManifestSha256', 'CompilationCount',
            'LoadCount', 'InitializedMutantKillCount', 'CompilationRecords',
            'LoadRecords', 'MutantResults', 'Pester', 'Gates', 'Cleanup'
        )
        FailureResultFields = @(
            'SchemaId', 'SchemaVersion', 'Outcome', 'RunId', 'FailurePhase',
            'Errors', 'ObservedCounts', 'CleanupObservation'
        )
        SuccessCounts = [pscustomobject]@{
            CompilationCount = 5
            LoadCount = 5
            InitializedMutantKillCount = 3
            ContainerCount = 1
            TotalCount = 32
            SelectedCount = 32
            ExecutedCount = 32
            PassedCount = 32
            FailedCount = 0
            SkippedCount = 0
            NotRunCount = 0
            FailedBlocksCount = 0
            FailedContainersCount = 0
        }
        SuccessGates = @(
            'InputPinsPassed', 'FixtureManifestPassed', 'StageMapPassed',
            'ReferenceChecksPassed', 'PublicApiChecksPassed',
            'DocumentationParityPassed', 'TokenAndDigestCategoryChecksPassed',
            'OracleChecksPassed', 'PesterCallerScopePassed', 'RegistryDisabled',
            'RegistryAbsent', 'SourceOutputSeparationPassed'
        )
        CleanupGates = @(
            'Completed', 'ResiduePassed', 'OwnedStreamsClosed', 'TempRestored',
            'TmpRestored', 'PowerShellLocationRestored', 'DotNetLocationRestored',
            'TestDriveCleanupPassed', 'RegistryDriveAbsent', 'RegistryVariableAbsent',
            'RetainedArtifactsDeclared'
        )
        PesterOptions = [pscustomobject]@{
            Version = '5.3.3'
            DescribeName = 'Evidence runtime conformance'
            ContainerCount = 1
            Paths = @()
            PassThru = $true
            Exit = $false
            Throw = $false
            Tag = 'Precheck'
            ExcludeTags = @()
            FullNames = @()
            TestDriveEnabled = $true
            TestRegistryEnabled = $false
            TestResultEnabled = $false
            CodeCoverageEnabled = $false
        }
        RequiredPesterTests = @(
            [pscustomobject]@{ Id = 'manifest-shape'; Name = 'Rejects undeclared or malformed manifest and result contracts' }
            [pscustomobject]@{ Id = 'forbidden-inputs'; Name = 'Excludes unadmitted dependencies from every input route' }
            [pscustomobject]@{ Id = 'authority-gates'; Name = 'Admits only exact authority bytes through their four declared gates' }
            [pscustomobject]@{ Id = 'public-surface'; Name = 'Exposes exactly two runtime types and three named validation parameters' }
            [pscustomobject]@{ Id = 'rejection-boundaries'; Name = 'Rejects stale identities and repeated or unsupported invocations before work' }
            [pscustomobject]@{ Id = 'hand-golden'; Name = 'Matches the independently authored burn receipt bytes and fields' }
            [pscustomobject]@{ Id = 'tlv-order-and-presence'; Name = 'Rejects malformed field ordering and presence' }
            [pscustomobject]@{ Id = 'length-boundaries'; Name = 'Rejects inconsistent and excessive lengths before allocation' }
            [pscustomobject]@{ Id = 'evidence-maxima'; Name = 'Enforces only the exact evidence payload and envelope bounds' }
            [pscustomobject]@{ Id = 'primitive-representations'; Name = 'Preserves canonical primitive byte representations' }
            [pscustomobject]@{ Id = 'profile-fields'; Name = 'Resolves conditional fields and nested profiles exactly' }
            [pscustomobject]@{ Id = 'kind-coverage'; Name = 'Processes all twenty two kinds under both evidence profiles' }
            [pscustomobject]@{ Id = 'domain-separation'; Name = 'Rejects incorrect digest domains separators and substitutions' }
            [pscustomobject]@{ Id = 'signature-coverage'; Name = 'Returns exactly the three declared evidence signature preimages' }
            [pscustomobject]@{ Id = 'signature-mutation'; Name = 'Distinguishes signature bytes from preceding signature covered fields' }
            [pscustomobject]@{ Id = 'copied-signature-exclusion'; Name = 'Never invents coverage or authentication for copied signatures' }
            [pscustomobject]@{ Id = 'digest-category-coverage'; Name = 'Classifies every non envelope digest without conflating references' }
            [pscustomobject]@{ Id = 'unchecked-claims'; Name = 'Preserves unchecked claims without resolving or authenticating them' }
            [pscustomobject]@{ Id = 'outer-metadata'; Name = 'Keeps outer artifact and profile metadata explicitly unauthenticated' }
            [pscustomobject]@{ Id = 'encoder-validation'; Name = 'Rejects malformed payloads before encoding an envelope' }
            [pscustomobject]@{ Id = 'token-document-parity'; Name = 'Matches all documented tokens and categories with defensive copies' }
            [pscustomobject]@{ Id = 'immutable-state'; Name = 'Preserves immutable state through rejection and interleaved calls' }
            [pscustomobject]@{ Id = 'compiler-load-contract'; Name = 'Binds retained C sharp five sources and admitted dependency identities' }
            [pscustomobject]@{ Id = 'caller-bound-tests'; Name = 'Runs retained tests in caller scope with all nine data identities' }
            [pscustomobject]@{ Id = 'independent-generator'; Name = 'Keeps generated vectors and protected goldens independent of production' }
            [pscustomobject]@{ Id = 'initialized-mutants'; Name = 'Kills three distinct initialized mutants with independent oracles' }
            [pscustomobject]@{ Id = 'complete-census'; Name = 'Rejects incomplete per call and aggregate evidence counts' }
            [pscustomobject]@{ Id = 'corpus-and-export-integrity'; Name = 'Rejects incomplete corpus discovery configuration or export evidence' }
            [pscustomobject]@{ Id = 'workflow-invocations'; Name = 'Requires exact isolated workflow invocations and fail closed receipts' }
            [pscustomobject]@{ Id = 'registry-and-cleanup'; Name = 'Requires registry absence and complete owned resource cleanup' }
            [pscustomobject]@{ Id = 'source-and-stale-audit'; Name = 'Separates admitted sources from outputs and rejects obsolete surfaces' }
            [pscustomobject]@{ Id = 'failure-propagation'; Name = 'Rejects every failed malformed missing duplicated or incomplete result' }
        )
        AuthorityInputs = @(
            [pscustomobject]@{
                Path = 'certification\schema\protocol-schema-meta.v1.json'
                Length = 4533L
                Sha256 = 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
            }

            [pscustomobject]@{
                Path = 'certification\schema\protocol-inventory.v1.json'
                Length = 46479L
                Sha256 = 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
            }
            [pscustomobject]@{
                Path = 'certification\evidence-ledger\schema\evidence-schema.v1.json'
                Length = 22001L
                Sha256 = '49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6'
            }
            [pscustomobject]@{
                Path = 'certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json'
                Length = 47347L
                Sha256 = '07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9'
            }
        )
    }
}

function Get-PspktEvidenceProbeReasons {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    [ordered]@{
        'returned-failure' = 'ValidationFailedOutcome'
        'malformed-result' = 'ResultShape'
        'missing-result' = 'ResultCardinality'
        'multiple-results' = 'ResultCardinality'
        'count-mismatch' = 'ResultCounts'
    }
}

function Get-PspktEvidenceHostSlots {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    [pscustomobject]@{ HostSlot = 'windows_ps51'; Edition = 'Desktop' }
    [pscustomobject]@{ HostSlot = 'powershell_7'; Edition = 'Core' }
}

function Get-PspktEvidenceDiagnosticMessages {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][object]$Snapshot)

    $messages = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($record in $Snapshot.Records) {
        if ($record.Role -notin @('RuntimeSources', 'ValidationCodeInputs', 'ContractRoot')) { continue }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Snapshot.Files[$record.Path].Bytes)
        if ($record.Path.EndsWith('.ps1', [StringComparison]::Ordinal)) {
            $tokens = $null
            $errors = $null
            $syntax = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
            foreach ($statement in $syntax.FindAll({ param($node) $node -is [Management.Automation.Language.ThrowStatementAst] }, $true)) {
                foreach ($literal in $statement.FindAll({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
                    if ($literal.Value.Length -le 256) { [void]$messages.Add($literal.Value) }
                }
            }
        }
        else {
            foreach ($match in [regex]::Matches($text, 'throw new [A-Za-z]+Exception\("([^"\r\n]+)"\)')) {
                if ($match.Groups[1].Value.Length -le 256) { [void]$messages.Add($match.Groups[1].Value) }
            }
        }
    }
    foreach ($property in (Get-PspktEvidenceRuntimeContract).SuccessCounts.PSObject.Properties) {
        [void]$messages.Add('pester-result: Exact actual count differs: ' + $property.Name + '.')
    }
    foreach ($message in $messages) { $message }
}

function Get-PspktEvidenceDiagnosticCategories {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    @(
        'AggregatePostconditions', 'ascii-identifier', 'assembly-census', 'assembly-context',
        'assembly-custody', 'assembly-load', 'assembly-preload', 'assembly-reference',
        'authority-gate', 'authority-length', 'authority-pin', 'binary-sid',
        'bootstrap-public-surface', 'bootstrap-reference', 'boundary-source', 'bounded-length',
        'caller-scope', 'ci-receipt', 'cleanup-restore', 'compilation-failed',
        'compilation-role', 'compilation-source', 'compiler-collision', 'compiler-residue',
        'contract-shape', 'documentation-parity', 'envelope-bound', 'evidence-kind',
        'evidence-profile', 'export-custody', 'export-membership', 'export-pin', 'export-root',
        'field-shape', 'fixture-digest', 'fixture-membership', 'fixture-population', 'fixture-shape',
        'generator-isolation', 'image-collision', 'image-custody', 'image-identity', 'image-length',
        'integer-length', 'invocation-context', 'invocation-repeat', 'manifest-digest',
        'manifest-length', 'manifest-membership', 'manifest-shape', 'mutant-api', 'mutant-identity',
        'mutant-role', 'mutant-source', 'mutant-survived', 'nested-profile', 'oracle-control',
        'oracle-pin', 'payload-bound', 'payload-digest', 'pester-configuration', 'pester-manifest',
        'pester-package', 'pester-result', 'pester-setup', 'pester-version', 'primitive-type', 'primitive-width',
        'probe-case', 'probe-confirmation', 'probe-control', 'probe-output', 'probe-receipt',
        'probe-rejection', 'receipt-json', 'registry-state', 'ResultCardinality', 'ResultCounts',
        'ResultPostconditions', 'ResultShape', 'run-residue', 'setup', 'source-closure',
        'source-length', 'source-manifest', 'source-marker', 'source-membership', 'source-path', 'source-pin',
        'source-policy', 'source-read', 'source-stale', 'test-data', 'test-fixture',
        'test-population', 'test-source', 'test-storage', 'tlv-header', 'tlv-length',
        'tlv-payload-bound', 'tlv-tag', 'tlv-trailing', 'tlv-value-bound', 'toolchain-reference',
        'unchecked-claims', 'validate', 'ValidationFailedOutcome', 'work-root',
        'workflow-call', 'workflow-contract', 'workflow-dependency', 'workflow-failure'
    )
}

function Get-PspktEvidenceFailureDiagnostics {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][Exception]$Exception,
        [string[]]$AllowedMessages = @()
    )

    $redacted = 'diagnostic-redacted: Non-capsule exception details were suppressed.'
    $truncation = 'diagnostic-truncated: Error traversal or message bound exceeded.'
    $allowed = [Collections.Generic.HashSet[string]]::new($AllowedMessages, [StringComparer]::Ordinal)
    $categories = [Collections.Generic.HashSet[string]]::new([string[]]@(Get-PspktEvidenceDiagnosticCategories), [StringComparer]::Ordinal)
    $sourcePaths = [Collections.Generic.HashSet[string]]::new([string[]]@(Get-PspktEvidenceSourcePaths), [StringComparer]::Ordinal)
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($test in (Get-PspktEvidenceRuntimeContract).RequiredPesterTests) {
        [void]$paths.Add('Evidence runtime conformance.' + $test.Name)
    }
    $messages = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    $failedTests = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    $pending = [Collections.Generic.List[Exception]]::new()
    $pending.Add($Exception)
    $visited = 0
    $truncated = $false
    while ($pending.Count -gt 0 -and $visited -lt 64) {
        $current = $pending[0]
        $pending.RemoveAt(0)
        $visited++
        $reportedPaths = $current.Data['PspktEvidenceFailedTestPaths']
        if ($reportedPaths -is [array]) {
            for ($index = 0; $index -lt [Math]::Min(32, $reportedPaths.Length); $index++) {
                if ($reportedPaths[$index] -is [string] -and $paths.Contains($reportedPaths[$index])) {
                    [void]$failedTests.Add('failed-test: ' + $reportedPaths[$index])
                }
            }
            if ($reportedPaths.Length -gt 32) { $truncated = $true }
        }
        if ($current -is [AggregateException]) {
            foreach ($inner in $current.InnerExceptions) {
                if ($pending.Count -ge 64) { $truncated = $true; break }
                $pending.Add($inner)
            }
            continue
        }
        if ($null -ne $current.InnerException) { $pending.Add($current.InnerException); continue }
        $message = $current.Message
        if ($message.StartsWith('failed-test: ', [StringComparison]::Ordinal) -and $paths.Contains($message.Substring(13))) {
            [void]$failedTests.Add($message)
            continue
        }
        $printable = [regex]::IsMatch($message, '\A[\x20-\x7e]{1,256}\z')
        if (-not $printable -or (-not $allowed.Contains($message) -and
            -not [string]::Equals($message, $redacted, [StringComparison]::Ordinal) -and
            -not [string]::Equals($message, $truncation, [StringComparison]::Ordinal))) {
            $projection = $redacted
            $separator = $message.IndexOf(':', 0, [Math]::Min(64, $message.Length))
            if ($separator -gt 0 -and $categories.Contains($message.Substring(0, $separator))) {
                $category = $message.Substring(0, $separator)
                $projection = $category + ': Variable details redacted.'
                foreach ($sourcePrefix in @('source-pin: Retained bytes differ for ', 'source-length: Retained byte length differs for ')) {
                    if ($printable -and $message.StartsWith($sourcePrefix, [StringComparison]::Ordinal) -and
                        $message.EndsWith('.', [StringComparison]::Ordinal) -and $message.Length -gt $sourcePrefix.Length + 1) {
                        $relativePath = $message.Substring($sourcePrefix.Length, $message.Length - $sourcePrefix.Length - 1)
                        if ([regex]::IsMatch($relativePath, '\A[A-Za-z0-9_.\\-]{1,128}\z') -and $sourcePaths.Contains($relativePath)) {
                            $projection = $message
                        }
                    }
                }
                if ($printable -and [string]::Equals($category, 'mutant-survived', [StringComparison]::Ordinal)) {
                    foreach ($role in @('M1', 'M2', 'M3')) {
                        if ([string]::Equals($message, 'mutant-survived: Independent oracle did not kill ' + $role + '.', [StringComparison]::Ordinal)) {
                            $projection = $message
                        }
                    }
                }
            }
            $message = $projection
        }
        if ($messages.Count -lt 16 -or $messages.Contains($message)) { [void]$messages.Add($message) }
        else { $truncated = $true }
    }
    if ($pending.Count -gt 0) { $truncated = $true }
    foreach ($path in $failedTests) { [void]$messages.Add($path) }
    if ($truncated) { [void]$messages.Add($truncation) }
    if ($messages.Count -eq 0) { [void]$messages.Add($redacted) }
    foreach ($message in $messages) { $message }
}

function Write-PspktEvidenceFailureDiagnostics {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][Exception]$Exception,
        [string[]]$AllowedMessages = @()
    )

    foreach ($message in @(Get-PspktEvidenceFailureDiagnostics -Exception $Exception -AllowedMessages $AllowedMessages)) {
        [Console]::Error.WriteLine($message)
    }
}

function New-PspktEvidenceValidationFailure {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][Exception[]]$Failures,
        [object]$Pester,
        [string[]]$AllowedMessages = @()
    )

    $exception = [AggregateException]::new('Evidence runtime validation or cleanup failed.', $Failures)
    if ($null -ne $Pester) {
        $exception.Data['PspktEvidenceFailedTestPaths'] = @($Pester.Tests |
            Where-Object { [string]::Equals([string]$_.Result, 'Failed', [StringComparison]::Ordinal) } |
            ForEach-Object { [string]$_.ExpandedPath })
    }
    $diagnostics = @(Get-PspktEvidenceFailureDiagnostics -Exception $exception -AllowedMessages $AllowedMessages)
    $safeFailures = [Exception[]]@($diagnostics | ForEach-Object { [InvalidOperationException]::new($_) })
    [AggregateException]::new('Evidence runtime validation or cleanup failed.', $safeFailures)
}

function Get-PspktEvidencePesterSetupFailureMessage {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Stage)

    $messages = [ordered]@{
        'source-load' = 'pester-setup: source-load failed.'
        'source-admission' = 'pester-setup: source-admission failed.'
        'temporary-storage' = 'pester-setup: temporary-storage failed.'
        'tls' = 'pester-setup: tls failed.'
        'download' = 'pester-setup: download failed.'
        'package-length' = 'pester-setup: package-length failed.'
        'package-hash' = 'pester-setup: package-hash failed.'
        'compression-load' = 'pester-setup: compression-load failed.'
        'archive-extract' = 'pester-setup: archive-extract failed.'
        'manifest' = 'pester-setup: manifest failed.'
        'publish' = 'pester-setup: publish failed.'
    }
    if ([Array]::IndexOf([string[]]@($messages.Keys), $Stage) -lt 0) {
        return 'pester-setup: unknown-stage failed.'
    }
    return $messages[$Stage]
}

function Assert-PspktEvidencePesterPackage {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -ne 271297 -or -not [string]::Equals(
        (Get-PspktEvidenceBytesDigest -Bytes $Bytes),
        'bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579', [StringComparison]::Ordinal)) {
        throw 'pester-package: Pinned Pester 5.3.3 package differs.'
    }
}

function Get-PspktEvidenceWorkflowBoundaryDefinitions {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $validator = Read-PspktEvidencePinnedSource -RepositoryRoot $RepositoryRoot -RelativePath 'certification\evidence-runtime\validators\Invoke-PspktPhase4EvidenceRuntimeValidators.ps1'
    $tests = Read-PspktEvidencePinnedSource -RepositoryRoot $RepositoryRoot -RelativePath 'certification\evidence-runtime\tests\pspkt.Phase4EvidenceRuntime.Tests.ps1'
    Get-PspktEvidenceBoundaryDefinitions -ValidatorBytes $validator.Bytes -TestBytes $tests.Bytes
}

function New-PspktEvidenceWorkflowCall {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$SourceKind,
        [Parameter(Mandatory = $true)][string]$PesterManifestPath,
        [Parameter(Mandatory = $true)][byte[]]$ContractBytes
    )

    if (@('checkout', 'export') -cnotcontains $SourceKind -or $env:GITHUB_ACTIONS -cne 'true') {
        throw 'workflow-call: An exact CI source kind and runner context are required.'
    }
    $runner = ConvertTo-PspktEvidenceDirectoryPath -Path $env:RUNNER_TEMP
    Assert-PspktEvidencePhysicalDirectory -Path $runner
    $work = Join-Path $runner ('pspkt-evidence-work-' + [Guid]::NewGuid().ToString('N'))
    Assert-PspktEvidenceRootRelationships -RepositoryRoot $RepositoryRoot -WorkRoot $work -OriginalWorkspace $env:GITHUB_WORKSPACE -RunnerTemp $runner
    if ([IO.Directory]::Exists($work) -or [IO.File]::Exists($work)) { throw 'work-root: CI work directory already exists.' }
    [void][IO.Directory]::CreateDirectory($work)
    $preloaded = @{ 'certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1' = $ContractBytes }
    $sourceRoot = $RepositoryRoot
    if ($SourceKind -ceq 'export') {
        $snapshot = Get-PspktEvidenceSourceSnapshot -RepositoryRoot $RepositoryRoot -PreloadedBytes $preloaded
        Assert-PspktEvidenceSourceClosure -Snapshot $snapshot
        $sourceRoot = Join-Path $runner ('pspkt-evidence-export-' + [Guid]::NewGuid().ToString('N'))
        if (Test-PspktEvidenceDirectoryOverlap -Left $sourceRoot -Right $work) { throw 'work-root: Export and work roots overlap.' }
        $preloaded = Export-PspktEvidenceSources -Snapshot $snapshot.Files -OutputRoot $sourceRoot
    }
    $context = New-PspktEvidenceInvocationContext -RepositoryRoot $sourceRoot -WorkRoot $work `
        -PesterManifestPath $PesterManifestPath -PreloadedBytes $preloaded
    $validatorBytes = $context.Snapshot.Files['certification\evidence-runtime\validators\Invoke-PspktPhase4EvidenceRuntimeValidators.ps1'].Bytes
    [pscustomobject]@{
        SourceRoot = $sourceRoot; WorkRoot = $work; Context = $context
        Command = [scriptblock]::Create([Text.UTF8Encoding]::new($false, $true).GetString($validatorBytes))
        BoundaryDefinitions = @(Get-PspktEvidenceBoundaryDefinitions -ValidatorBytes $validatorBytes)
    }
}

function New-PspktEvidenceCiReceipt {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string]$HostSlot,
        [Parameter(Mandatory = $true)][string]$SourceKind
    )

    $hostRecords = @(Get-PspktEvidenceHostSlots | Where-Object { [string]::Equals($_.HostSlot, $HostSlot, [StringComparison]::Ordinal) })
    if ($hostRecords.Count -ne 1 -or [Array]::IndexOf([string[]]@('checkout', 'export'), $SourceKind) -lt 0) {
        throw 'ci-receipt: Invalid full-call slot.'
    }
    $edition = $hostRecords[0].Edition
    if ($PSVersionTable.PSEdition -cne $edition) { throw 'ci-receipt: Actual host differs from the slot.' }
    Assert-PspktEvidenceValidationSuccess -CapturedResults @($Result) -Expected $Expected
    $receipt = [pscustomobject]@{
        SchemaId = 'PspktEvidenceRuntimeCiReceiptV1'; SchemaVersion = 1
        Slot = $HostSlot + '/' + $SourceKind; HostSlot = $HostSlot; SourceKind = $SourceKind
        WorkflowRunId = $env:GITHUB_RUN_ID; WorkflowRunAttempt = $env:GITHUB_RUN_ATTEMPT; Revision = $env:GITHUB_SHA
        BaseCommit = (Get-PspktEvidenceRuntimeContract).BaseCommit
        HostEdition = $PSVersionTable.PSEdition; HostVersion = $PSVersionTable.PSVersion.ToString()
        SourceRoot = $Result.RepositoryRoot; WorkRoot = $Result.WorkRoot; RunRoot = $Result.RunRoot
        RunnerTemp = $env:RUNNER_TEMP; OriginalWorkspace = $env:GITHUB_WORKSPACE
        RunId = $Result.RunId; SourceManifestSha256 = $Result.SourceManifestSha256
        Result = $Result
        InvocationEvidence = [pscustomobject]@{
            CompilationRecords = $Expected.CompilationRecords
            LoadRecords = $Expected.LoadRecords
            MutantResults = $Expected.MutantResults
        }
    }
    $serialized = $receipt | ConvertTo-Json -Depth 30 -Compress
    if ($serialized.Length -gt 30000) { throw 'ci-receipt: Full receipt exceeds the Windows environment value bound.' }
    return $receipt
}

function New-PspktEvidenceProbeReceipt {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Probe,
        [Parameter(Mandatory = $true)][string]$HostSlot
    )

    if ([Array]::IndexOf([string[]]@((Get-PspktEvidenceHostSlots).HostSlot), $HostSlot) -lt 0) { throw 'probe-receipt: Invalid host slot.' }
    $fields = [ordered]@{
        SchemaId = 'PspktEvidenceRuntimeProbeReceiptV1'; SchemaVersion = 1; HostSlot = $HostSlot
        WorkflowRunId = $env:GITHUB_RUN_ID; WorkflowRunAttempt = $env:GITHUB_RUN_ATTEMPT; Revision = $env:GITHUB_SHA
    }
    foreach ($property in $Probe.PSObject.Properties) { $fields[$property.Name] = $property.Value }
    [pscustomobject]$fields
}

function Assert-PspktEvidenceProbeReceipt {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Receipt,
        [Parameter(Mandatory = $true)][string]$HostSlot,
        [bool]$RequireRawOutcome = $false
    )

    $fields = @('SchemaId', 'SchemaVersion', 'HostSlot', 'WorkflowRunId', 'WorkflowRunAttempt', 'Revision',
        'CaseId', 'PositiveControlPassed', 'WrapperRejected', 'StepRejected', 'SuccessObjectsEmitted',
        'DiagnosticCount', 'WrapperReason', 'StepReason')
    if ($RequireRawOutcome) { $fields += 'RawOutcome' }
    if ($Receipt -isnot [System.Management.Automation.PSCustomObject] -or @($Receipt.PSObject.Properties).Count -ne $fields.Count) {
        throw 'probe-receipt: Closed receipt shape differs.'
    }
    foreach ($property in $Receipt.PSObject.Properties) {
        if ($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
            [Array]::IndexOf([string[]]$fields, $property.Name) -lt 0) {
            throw 'probe-receipt: Unexpected or executable receipt field.'
        }
    }
    foreach ($name in @('SchemaId', 'HostSlot', 'WorkflowRunId', 'WorkflowRunAttempt', 'Revision', 'CaseId', 'WrapperReason', 'StepReason')) {
        if ($Receipt.$name -isnot [string] -or [string]::IsNullOrEmpty($Receipt.$name) -or $Receipt.$name.Length -gt 4096) {
            throw 'probe-receipt: A required bounded string is malformed.'
        }
    }
    if (($Receipt.SchemaVersion -isnot [int] -and $Receipt.SchemaVersion -isnot [long]) -or $Receipt.SchemaVersion -ne 1) {
        throw 'probe-receipt: Schema version is not supported.'
    }
    if (-not [string]::Equals($Receipt.SchemaId, 'PspktEvidenceRuntimeProbeReceiptV1', [StringComparison]::Ordinal) -or
        -not [string]::Equals($Receipt.HostSlot, $HostSlot, [StringComparison]::Ordinal) -or
        -not [string]::Equals($Receipt.WorkflowRunId, $env:GITHUB_RUN_ID, [StringComparison]::Ordinal) -or
        -not [string]::Equals($Receipt.WorkflowRunAttempt, $env:GITHUB_RUN_ATTEMPT, [StringComparison]::Ordinal) -or
        -not [string]::Equals($Receipt.Revision, $env:GITHUB_SHA, [StringComparison]::Ordinal)) {
        throw 'probe-receipt: Receipt host or workflow binding differs.'
    }
    $reasons = Get-PspktEvidenceProbeReasons
    if ([Array]::IndexOf([string[]]@($reasons.Keys), $Receipt.CaseId) -lt 0) { throw 'probe-receipt: Unknown case.' }
    foreach ($name in @('PositiveControlPassed', 'WrapperRejected', 'StepRejected')) {
        if ($Receipt.$name -isnot [bool] -or -not $Receipt.$name) { throw 'probe-receipt: Probe was not independently verified.' }
    }
    $diagnostics = if ([string]::Equals($Receipt.CaseId, 'returned-failure', [StringComparison]::Ordinal)) { 1 } else { 0 }
    foreach ($name in @('SuccessObjectsEmitted', 'DiagnosticCount')) {
        if ($Receipt.$name -isnot [int] -and $Receipt.$name -isnot [long]) { throw 'probe-receipt: Probe count is not integral.' }
    }
    if ($Receipt.SuccessObjectsEmitted -ne 0 -or $Receipt.DiagnosticCount -ne $diagnostics -or
        -not [string]::Equals($Receipt.WrapperReason, $reasons[$Receipt.CaseId], [StringComparison]::Ordinal) -or
        -not [string]::Equals($Receipt.StepReason, $reasons[$Receipt.CaseId], [StringComparison]::Ordinal) -or
        ($RequireRawOutcome -and ($Receipt.RawOutcome -isnot [string] -or
            -not [string]::Equals($Receipt.RawOutcome, 'failure', [StringComparison]::Ordinal)))) {
        throw 'probe-receipt: Rejection reason, output count, or raw outcome differs.'
    }
}

function ConvertFrom-PspktEvidenceReceiptJson {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$Json)

    if ([string]::IsNullOrEmpty($Json) -or $Json.Length -gt 32768) {
        throw 'receipt-json: Receipt text exceeds its bound.'
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [void][Reflection.Assembly]::Load('System.Runtime.Serialization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
    }
    else {
        [void][Reflection.Assembly]::Load('System.Runtime.Serialization.Json')
        [void][Reflection.Assembly]::Load('System.Runtime.Serialization.Xml')
    }
    $reader = $null
    try {
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Json)
        $quotas = [Xml.XmlDictionaryReaderQuotas]::new()
        $quotas.MaxDepth = 32
        $quotas.MaxArrayLength = 1024
        $quotas.MaxStringContentLength = 131072
        $quotas.MaxBytesPerRead = 131072
        $quotas.MaxNameTableCharCount = 32768
        $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes, $quotas)
        $objects = @{}
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                $parentDepth = $reader.Depth - 1
                if ($objects.ContainsKey($parentDepth)) {
                    $name = $reader.GetAttribute('item')
                    if ($null -eq $name) { $name = $reader.LocalName }
                    if (-not $objects[$parentDepth].Add($name)) {
                        throw 'receipt-json: Duplicate receipt property.'
                    }
                }
                if ($reader.GetAttribute('type') -ceq 'object' -and -not $reader.IsEmptyElement) {
                    $objects[$reader.Depth] = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                }
            }
            elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) { $objects.Remove($reader.Depth) }
        }
    }
    catch { throw 'receipt-json: Receipt must be bounded, valid and duplicate-free JSON.' }
    finally { if ($null -ne $reader) { $reader.Dispose() } }
    $parsed = $Json | ConvertFrom-Json
    if ($parsed -is [array]) {
        foreach ($item in $parsed) { ,$item }
    }
    else { $parsed }
}

function Confirm-PspktEvidenceProbeReceipts {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$HostSlot,
        [Parameter(Mandatory = $true)][string]$OutcomesJson,
        [Parameter(Mandatory = $true)][string[]]$ReceiptJson
    )

    if ($ReceiptJson.Count -ne 5 -or $OutcomesJson.Length -gt 4096) { throw 'probe-confirmation: Exact probe population is required.' }
    $outcomes = ConvertFrom-PspktEvidenceReceiptJson -Json $OutcomesJson
    $caseIds = [string[]]@((Get-PspktEvidenceProbeReasons).Keys)
    if ($outcomes -isnot [System.Management.Automation.PSCustomObject] -or @($outcomes.PSObject.Properties).Count -ne 5) {
        throw 'probe-confirmation: Exact raw outcome fields are required.'
    }
    foreach ($outcome in $outcomes.PSObject.Properties) {
        if ($outcome.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
            [Array]::IndexOf($caseIds, $outcome.Name) -lt 0 -or $outcome.Value -isnot [string] -or
            -not [string]::Equals($outcome.Value, 'failure', [StringComparison]::Ordinal)) {
            throw 'probe-confirmation: Every raw outcome must be the exact failure string.'
        }
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($text in $ReceiptJson) {
        if ([string]::IsNullOrEmpty($text) -or $text.Length -gt 32768) { throw 'probe-confirmation: A bounded verified receipt is required.' }
        $receipt = ConvertFrom-PspktEvidenceReceiptJson -Json $text
        Assert-PspktEvidenceProbeReceipt -Receipt $receipt -HostSlot $HostSlot
        if (-not $seen.Add($receipt.CaseId)) { throw 'probe-confirmation: Duplicate case.' }
        $outcome = $outcomes.PSObject.Properties[$receipt.CaseId]
        if ($null -eq $outcome -or -not [string]::Equals($outcome.Name, $receipt.CaseId, [StringComparison]::Ordinal)) {
            throw 'probe-confirmation: A probe did not have a raw failed outcome.'
        }
        $receipt | Add-Member -NotePropertyName RawOutcome -NotePropertyValue 'failure'
        Assert-PspktEvidenceProbeReceipt -Receipt $receipt -HostSlot $HostSlot -RequireRawOutcome $true
        $receipt
    }
}

function Assert-PspktEvidenceCiAggregate {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string[]]$ReceiptJson,
        [Parameter(Mandatory = $true)][string[]]$ProbeJson,
        [object]$SourceSnapshot
    )

    if ($ReceiptJson.Count -ne 4 -or $ProbeJson.Count -ne 2) { throw 'AggregatePostconditions: Exact call and probe groups are required.' }
    $contract = Get-PspktEvidenceRuntimeContract
    $snapshot = if ($null -eq $SourceSnapshot) {
        Get-PspktEvidenceSourceSnapshot -RepositoryRoot $env:GITHUB_WORKSPACE
    } else { $SourceSnapshot }
    Assert-PspktEvidenceSourceClosure -Snapshot $snapshot
    $inputData = Get-PspktEvidenceRetainedInputData -Snapshot $snapshot
    $hostSlots = @(Get-PspktEvidenceHostSlots)
    $slots = @($hostSlots | ForEach-Object { $_.HostSlot + '/checkout'; $_.HostSlot + '/export' })
    $runIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $totals = @{ CompilationCount = 0L; LoadCount = 0L; InitializedMutantKillCount = 0L; ContainerCount = 0L; SelectedCount = 0L; ExecutedCount = 0L; PassedCount = 0L }
    for ($index = 0; $index -lt 4; $index++) {
        $text = $ReceiptJson[$index]
        if ([string]::IsNullOrEmpty($text) -or $text.Length -gt 30000) { throw 'AggregatePostconditions: A full-call receipt is absent or oversized.' }
        $receipt = ConvertFrom-PspktEvidenceReceiptJson -Json $text
        $fields = @('SchemaId', 'SchemaVersion', 'Slot', 'HostSlot', 'SourceKind', 'WorkflowRunId', 'WorkflowRunAttempt', 'Revision',
            'BaseCommit', 'HostEdition', 'HostVersion', 'SourceRoot', 'WorkRoot', 'RunRoot', 'RunnerTemp', 'OriginalWorkspace',
            'RunId', 'SourceManifestSha256', 'Result', 'InvocationEvidence')
        if ($receipt -isnot [System.Management.Automation.PSCustomObject] -or @($receipt.PSObject.Properties).Count -ne $fields.Count) {
            throw 'AggregatePostconditions: Closed full-call receipt shape differs.'
        }
        foreach ($property in $receipt.PSObject.Properties) {
            if ($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
                [Array]::IndexOf([string[]]$fields, $property.Name) -lt 0) {
                throw 'AggregatePostconditions: Unexpected receipt member.'
            }
        }
        foreach ($name in $fields) {
            if ($name -in @('SchemaVersion', 'Result', 'InvocationEvidence')) { continue }
            if ($receipt.$name -isnot [string] -or [string]::IsNullOrEmpty($receipt.$name) -or $receipt.$name.Length -gt 4096) {
                throw 'AggregatePostconditions: A receipt scalar is malformed.'
            }
        }
        if ($receipt.SchemaVersion -isnot [int] -and $receipt.SchemaVersion -isnot [long]) {
            throw 'AggregatePostconditions: Schema version is not integral.'
        }
        $expectedEdition = $hostSlots[[int][Math]::Floor($index / 2)].Edition
        $slotParts = $slots[$index].Split('/')
        $bindings = @{
            SchemaId = 'PspktEvidenceRuntimeCiReceiptV1'; Slot = $slots[$index]; HostSlot = $slotParts[0]; SourceKind = $slotParts[1]
            HostEdition = $expectedEdition; WorkflowRunId = $env:GITHUB_RUN_ID; WorkflowRunAttempt = $env:GITHUB_RUN_ATTEMPT
            Revision = $env:GITHUB_SHA; BaseCommit = $contract.BaseCommit; SourceManifestSha256 = $snapshot.ManifestSha256
        }
        foreach ($name in $bindings.Keys) {
            if (-not [string]::Equals($receipt.$name, $bindings[$name], [StringComparison]::Ordinal)) {
                throw 'AggregatePostconditions: Full-call provenance or slot binding differs.'
            }
        }
        if ($receipt.SchemaVersion -ne 1 -or $receipt.RunId -cnotmatch '\A[0-9a-f]{32}\z' -or -not $runIds.Add($receipt.RunId)) {
            throw 'AggregatePostconditions: Full-call provenance or unique slot binding differs.'
        }
        Assert-PspktEvidenceRootRelationships -RepositoryRoot $receipt.SourceRoot -WorkRoot $receipt.WorkRoot `
            -OriginalWorkspace $receipt.OriginalWorkspace -RunnerTemp $receipt.RunnerTemp
        if ($receipt.RunRoot -cne [IO.Path]::Combine($receipt.WorkRoot, 'evidence-runtime-' + $receipt.RunId)) {
            throw 'AggregatePostconditions: Run root is not the bound invocation child.'
        }
        if ($receipt.SourceKind -ceq 'checkout') {
            if (-not [string]::Equals($receipt.SourceRoot, $receipt.OriginalWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'AggregatePostconditions: Checkout source differs.'
            }
        }
        elseif (-not $receipt.SourceRoot.StartsWith($receipt.RunnerTemp.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            (Test-PspktEvidenceDirectoryOverlap -Left $receipt.SourceRoot -Right $receipt.OriginalWorkspace)) {
            throw 'AggregatePostconditions: Export source is not isolated under RUNNER_TEMP.'
        }
        Assert-PspktEvidenceValidationResultShape -Result $receipt.Result
        $evidence = $receipt.InvocationEvidence
        if ($evidence -isnot [System.Management.Automation.PSCustomObject] -or @($evidence.PSObject.Properties).Count -ne 3) {
            throw 'AggregatePostconditions: Forwarded admission census is malformed.'
        }
        foreach ($property in $evidence.PSObject.Properties) {
            if ($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
                @('CompilationRecords', 'LoadRecords', 'MutantResults') -cnotcontains $property.Name) {
                throw 'AggregatePostconditions: Forwarded admission census has an unexpected field.'
            }
        }
        $expected = [pscustomobject]@{
            Identity = [pscustomobject]@{
                RunId = $receipt.RunId; BaseCommit = $contract.BaseCommit; HostEdition = $expectedEdition; HostVersion = $receipt.HostVersion
                PesterVersion = '5.3.3'; RepositoryRoot = $receipt.SourceRoot; WorkRoot = $receipt.WorkRoot; RunRoot = $receipt.RunRoot
                SourceManifestSha256 = $snapshot.ManifestSha256
            }
            SuccessCounts = $contract.SuccessCounts; AssemblyRoles = $contract.AssemblyRoles; SuccessGates = $contract.SuccessGates
            CleanupGates = $contract.CleanupGates; TestIds = @($contract.RequiredPesterTests.Id)
            CompilationRecords = $evidence.CompilationRecords; LoadRecords = $evidence.LoadRecords; MutantResults = $evidence.MutantResults
        }
        Assert-PspktEvidenceValidationSuccess -CapturedResults @($receipt.Result) -Expected $expected
        for ($roleIndex = 0; $roleIndex -lt 5; $roleIndex++) {
            $role = $contract.AssemblyRoles[$roleIndex]
            $record = $receipt.Result.CompilationRecords[$roleIndex]
            $simpleName = if ($role -ceq 'Bootstrap') { 'PspktEvidenceBootstrap_' + $receipt.RunId } else { 'PspktEvidenceRuntime_' + $receipt.RunId }
            if ($role -in @('M1', 'M2', 'M3')) { $simpleName += '_' + $role }
            if ($record.AssemblyIdentity -cne ($simpleName + ', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null') -or
                $record.ImageSha256 -cnotmatch '^[0-9a-f]{64}$' -or $record.ImageLength -lt 1 -or $record.ImageLength -gt 16777216 -or
                $record.LanguageVersion -cne 'CSharp5' -or
                $receipt.Result.LoadRecords[$roleIndex].ImagePath -cne [IO.Path]::Combine($receipt.RunRoot, $simpleName + '.dll')) {
                throw 'AggregatePostconditions: Admitted image identity, path or bound differs.'
            }
            $load = $receipt.Result.LoadRecords[$roleIndex]
            $expectedContext = if ($expectedEdition -ceq 'Desktop') { 'LoadFrom' } else { 'Default' }
            if ($load.AssemblyIdentity -cne $record.AssemblyIdentity -or $load.ImageSha256 -cne $record.ImageSha256 -or
                $load.Context -cne $expectedContext -or -not $load.Initialized) {
                throw 'AggregatePostconditions: Compilation and load witnesses differ.'
            }
            if ($role -in @('M1', 'M2', 'M3')) {
                $mutant = $receipt.Result.MutantResults[$roleIndex - 2]
                $mutation = Get-PspktEvidenceMutantSources -Role $role -Sources $inputData.RuntimeTexts -SourceNames $contract.RuntimeSourceNames
                if ($mutant.AssemblyIdentity -cne $record.AssemblyIdentity -or $mutant.OracleId -cne $mutation.OracleId -or
                    $mutant.Transform.SourcePath -cne $mutation.Transform.SourcePath -or
                    $mutant.Transform.OriginalSha256 -cne $mutation.Transform.OriginalSha256 -or
                    $mutant.Transform.MutatedSha256 -cne $mutation.Transform.MutatedSha256 -or $mutant.Transform.MatchCount -ne 1) {
                    throw 'AggregatePostconditions: Mutant oracle or source transformation binding differs.'
                }
            }
            [string[]]$sourceNames = if ($role -ceq 'Bootstrap') { @('certification\lib\Pspkt.Certification.SchemaBootstrap.cs') } else { @($contract.RuntimeSourceNames) }
            [string[]]$sourceTexts = if ($role -ceq 'Bootstrap') { @($inputData.BootstrapText) } elseif ($role -ceq 'Runtime') { $inputData.RuntimeTexts } else {
                (Get-PspktEvidenceMutantSources -Role $role -Sources $inputData.RuntimeTexts -SourceNames $contract.RuntimeSourceNames).Sources
            }
            if ($record.SourceCount -ne $sourceNames.Count -or $record.Sources.Count -ne $sourceNames.Count) {
                throw 'AggregatePostconditions: Exact source census differs.'
            }
            for ($sourceIndex = 0; $sourceIndex -lt $sourceNames.Count; $sourceIndex++) {
                $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($sourceTexts[$sourceIndex])
                if ($record.Sources[$sourceIndex].Path -cne $sourceNames[$sourceIndex] -or
                    $record.Sources[$sourceIndex].Length -ne $bytes.Length -or
                    $record.Sources[$sourceIndex].Sha256 -cne (Get-PspktEvidenceBytesDigest -Bytes $bytes)) {
                    throw 'AggregatePostconditions: Census source does not match reviewed bytes.'
                }
            }
        }
        foreach ($name in @('CompilationCount', 'LoadCount', 'InitializedMutantKillCount')) { $totals[$name] += $receipt.Result.$name }
        foreach ($name in @('ContainerCount', 'SelectedCount', 'ExecutedCount', 'PassedCount')) { $totals[$name] += $receipt.Result.Pester.$name }
    }
    if ($totals.CompilationCount -ne 20 -or $totals.LoadCount -ne 20 -or $totals.InitializedMutantKillCount -ne 12 -or
        $totals.ContainerCount -ne 4 -or $totals.SelectedCount -ne 128 -or $totals.ExecutedCount -ne 128 -or $totals.PassedCount -ne 128) {
        throw 'AggregatePostconditions: Complete four-call totals differ.'
    }
    for ($hostIndex = 0; $hostIndex -lt 2; $hostIndex++) {
        if ([string]::IsNullOrEmpty($ProbeJson[$hostIndex]) -or $ProbeJson[$hostIndex].Length -gt 32768) { throw 'AggregatePostconditions: Verified probe group is absent.' }
        $probes = @(ConvertFrom-PspktEvidenceReceiptJson -Json $ProbeJson[$hostIndex])
        if ($probes.Count -ne 5) { throw 'AggregatePostconditions: Exactly five probes per host are required.' }
        $hostSlot = $hostSlots[$hostIndex].HostSlot
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($probe in $probes) {
            Assert-PspktEvidenceProbeReceipt -Receipt $probe -HostSlot $hostSlot -RequireRawOutcome $true
            if (-not $seen.Add($probe.CaseId)) { throw 'AggregatePostconditions: Duplicate verified probe.' }
        }
    }
}

function Invoke-PspktEvidenceBoundaryProbe {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Contract,
        [Parameter(Mandatory = $true)][string]$CaseId
    )

    $reasons = Get-PspktEvidenceProbeReasons
    if ([Array]::IndexOf([string[]]@($reasons.Keys), $CaseId) -lt 0) { throw 'probe-case: Unknown result-boundary case.' }
    $healthy = New-PspktEvidenceValidationResultFixture -Contract $Contract -CaseId healthy
    $control = @(Complete-PspktEvidenceValidationInvocation -CapturedResults $healthy.Captured -Expected $healthy.Expected)
    Assert-PspktEvidenceValidationSuccess -CapturedResults $control -Expected $healthy.Expected
    if ($control.Count -ne 1 -or $control[0].Outcome -cne 'ValidationSucceeded') { throw 'probe-control: Positive control did not succeed.' }
    $fixture = New-PspktEvidenceValidationResultFixture -Contract $Contract -CaseId $CaseId
    $wrapperObjects = [Collections.Generic.List[object]]::new()
    $wrapperReason = ''
    try {
        Complete-PspktEvidenceValidationInvocation -CapturedResults $fixture.Captured -Expected $fixture.Expected |
            ForEach-Object { $wrapperObjects.Add($_) }
    }
    catch { $wrapperReason = $_.Exception.Message.Split(':')[0] }
    $stepObjects = [Collections.Generic.List[object]]::new()
    $stepReason = ''
    try {
        Assert-PspktEvidenceValidationSuccess -CapturedResults $fixture.Captured -Expected $fixture.Expected |
            ForEach-Object { $stepObjects.Add($_) }
    }
    catch { $stepReason = $_.Exception.Message.Split(':')[0] }
    $diagnosticCount = if ($CaseId -ceq 'returned-failure') { 1 } else { 0 }
    if ($wrapperReason -cne $reasons[$CaseId] -or $stepReason -cne $reasons[$CaseId] -or
        $wrapperObjects.Count -ne $diagnosticCount -or $stepObjects.Count -ne 0) {
        throw 'probe-rejection: A boundary returned, leaked output, or failed for the wrong reason.'
    }
    foreach ($item in $wrapperObjects) {
        if ($item.Outcome -cne 'ValidationFailed') { throw 'probe-output: A failed boundary emitted success.' }
    }
    [pscustomobject]@{
        CaseId = $CaseId; PositiveControlPassed = $true; WrapperRejected = $true; StepRejected = $true
        SuccessObjectsEmitted = 0; DiagnosticCount = $diagnosticCount; WrapperReason = $wrapperReason; StepReason = $stepReason
    }
}

function Get-PspktEvidenceBoundaryDefinitions {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][byte[]]$ValidatorBytes,
        [byte[]]$TestBytes
    )

    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $tokens = $null
    $errors = $null
    $syntax = [Management.Automation.Language.Parser]::ParseInput($encoding.GetString($ValidatorBytes), [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0) { throw 'boundary-source: Validator text is invalid.' }
    foreach ($name in @('Assert-PspktEvidenceValidationResultShape', 'Assert-PspktEvidenceValidationSuccess', 'Complete-PspktEvidenceValidationInvocation')) {
        $definitions = @($syntax.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $true))
        if ($definitions.Count -ne 1) { throw 'boundary-source: Exact private boundary definitions are required.' }
        [scriptblock]::Create($definitions[0].Extent.Text)
    }
    if ($null -ne $TestBytes) { (Get-PspktEvidenceTestWrapper -OriginalBytes $TestBytes).FixtureDefinition }
}

function New-PspktEvidenceInvocationContext {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$WorkRoot,
        [Parameter(Mandatory = $true)][string]$PesterManifestPath,
        [hashtable]$PreloadedBytes = @{}
    )

    $repository = ConvertTo-PspktEvidenceDirectoryPath -Path $RepositoryRoot
    $work = ConvertTo-PspktEvidenceDirectoryPath -Path $WorkRoot
    $runnerTemp = if ($env:GITHUB_ACTIONS -ceq 'true') { $env:RUNNER_TEMP } else { '' }
    Assert-PspktEvidenceRootRelationships -RepositoryRoot $repository -WorkRoot $work -OriginalWorkspace $env:GITHUB_WORKSPACE -RunnerTemp $runnerTemp
    Assert-PspktEvidencePhysicalDirectory -Path $repository
    Assert-PspktEvidencePhysicalDirectory -Path $work
    if ($runnerTemp -and [IO.Directory]::GetFileSystemEntries($work).Length -ne 0) { throw 'work-root: CI caller work root must be fresh and empty.' }
    if (-not [IO.Path]::IsPathRooted($PesterManifestPath) -or -not [IO.File]::Exists($PesterManifestPath) -or
        [IO.Path]::GetFileName($PesterManifestPath) -cne 'Pester.psd1') { throw 'pester-manifest: An explicit existing Pester manifest is required.' }
    $snapshot = Get-PspktEvidenceSourceSnapshot -RepositoryRoot $repository -PreloadedBytes $PreloadedBytes
    Assert-PspktEvidenceSourceClosure -Snapshot $snapshot
    $runId = [Guid]::NewGuid().ToString('N')
    $runRoot = Join-Path $work ('evidence-runtime-' + $runId)
    Assert-PspktEvidenceWorkRootLength -WorkRoot $work
    if ([IO.Directory]::Exists($runRoot) -or [IO.File]::Exists($runRoot)) {
        throw 'work-root: Fresh run path is colliding or exceeds the Desktop-safe length.'
    }
    [pscustomobject]@{
        RepositoryRoot = $repository; WorkRoot = $work; RunRoot = $runRoot; RunId = $runId
        PesterManifestPath = [IO.Path]::GetFullPath($PesterManifestPath)
        Snapshot = $snapshot; Expected = $null; Consumed = $false; Disposed = $false
        DiagnosticMessages = @(Get-PspktEvidenceDiagnosticMessages -Snapshot $snapshot)
    }
}

function Get-PspktEvidenceRetainedInputData {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][object]$Snapshot)

    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $contract = Get-PspktEvidenceRuntimeContract
    $authority = @{}
    $identifiers = @('meta', 'protocolInventory', 'evidenceSchema', 'evidenceInventory')
    for ($index = 0; $index -lt 4; $index++) { $authority[$identifiers[$index]] = $Snapshot.Files[$contract.AuthorityInputs[$index].Path].Bytes }
    $sourceTexts = @{}
    $runtimeTexts = @()
    foreach ($name in $contract.RuntimeSourceNames) {
        $text = $encoding.GetString($Snapshot.Files[('certification\evidence-runtime\lib\' + $name)].Bytes)
        $sourceTexts[$name] = $text
        $runtimeTexts += $text
    }
    $fixtureBytes = @{}
    $fixtureRecords = @{}
    foreach ($group in @('hand-authored', 'generated')) {
        $prefix = 'certification\evidence-runtime\vectors\' + $group + '\'
        $manifest = $encoding.GetString($Snapshot.Files[($prefix + 'manifest.v1.json')].Bytes) | ConvertFrom-Json
        foreach ($fixture in $manifest.fixtures) {
            $relative = $prefix + $fixture.file
            Assert-PspktEvidenceSourcePath -Path $relative
            if ($fixtureBytes.ContainsKey($fixture.id)) { throw 'fixture-membership: Duplicate fixture identifier.' }
            $fixtureBytes.Add($fixture.id, $Snapshot.Files[$relative].Bytes)
            $fixtureRecords.Add($fixture.id, $fixture)
        }
    }
    Assert-PspktEvidenceCorpus -FixtureBytes $fixtureBytes -FixtureRecords $fixtureRecords
    $testBytes = $Snapshot.Files['certification\evidence-runtime\tests\pspkt.Phase4EvidenceRuntime.Tests.ps1'].Bytes
    $tokens = $null
    $errors = $null
    $syntax = [Management.Automation.Language.Parser]::ParseInput($encoding.GetString($testBytes), [ref]$tokens, [ref]$errors)
    $cases = @($syntax.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'It' }, $true))
    $descriptions = @($syntax.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Describe' }, $true))
    if (@($errors).Count -ne 0 -or $cases.Count -ne 32 -or $descriptions.Count -ne 1 -or
        $descriptions[0].CommandElements[1].Value -cne 'Evidence runtime conformance') {
        throw 'test-population: Exactly one Describe and 32 cases are required.'
    }
    for ($index = 0; $index -lt 32; $index++) {
        if ($cases[$index].CommandElements.Count -ne 3 -or $cases[$index].CommandElements[1].Value -cne $contract.RequiredPesterTests[$index].Name) {
            throw 'test-population: Fixed non-parameterized test identities differ.'
        }
    }
    [pscustomobject]@{
        AuthorityBytes = $authority; SourceTexts = $sourceTexts; RuntimeTexts = [string[]]$runtimeTexts
        BootstrapText = $encoding.GetString($Snapshot.Files['certification\lib\Pspkt.Certification.SchemaBootstrap.cs'].Bytes)
        ValidatorText = $encoding.GetString($Snapshot.Files['certification\evidence-runtime\validators\Invoke-PspktPhase4EvidenceRuntimeValidators.ps1'].Bytes)
        DocumentationText = $encoding.GetString($Snapshot.Files['certification\evidence-runtime\README.md'].Bytes)
        GeneratorText = $encoding.GetString($Snapshot.Files['certification\evidence-runtime\vectors\New-PspktPhase4EvidenceRuntimeVectors.ps1'].Bytes)
        WorkflowText = $encoding.GetString($Snapshot.Files['.github\workflows\ci-evidence-runtime.yml'].Bytes)
        TestBytes = $testBytes; FixtureBytes = $fixtureBytes; FixtureRecords = $fixtureRecords
    }
}

function Get-PspktEvidenceSourcePins {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    $rows = @'
RuntimeAuthorityInputs|certification\schema\protocol-schema-meta.v1.json|4533|ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85
RuntimeAuthorityInputs|certification\schema\protocol-inventory.v1.json|46479|d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f
RuntimeAuthorityInputs|certification\evidence-ledger\schema\evidence-schema.v1.json|22001|49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6
RuntimeAuthorityInputs|certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json|47347|07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9
BootstrapSource|certification\lib\Pspkt.Certification.SchemaBootstrap.cs|90801|c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74
RuntimeSources|certification\evidence-runtime\lib\EvidenceArtifactEnvelopeCodec.cs|6155|811999bf853d250ad1b21bda0fa43366f4449243e19749eecd375a06637db12d
RuntimeSources|certification\evidence-runtime\lib\DecodedEvidenceArtifactEnvelope.cs|1360|581fd1971e34edb2321edeb758735c061b94837893f521471d7a6cc1f804897d
RuntimeSources|certification\evidence-runtime\lib\EvidenceSchemaSnapshot.cs|10463|8ff61a1cbd8eb710540e6a632d1a7a151fafcf58cf6f4120f36544a43b55bbb9
RuntimeSources|certification\evidence-runtime\lib\EvidenceAuthorityJsonReader.cs|794|023d053a22ffcf45cd5bbdd4616c12d1263fc823263f70503b700681bb62dd01
RuntimeSources|certification\evidence-runtime\lib\EvidencePayloadCodec.cs|4087|301829f7e9cd1ffa03b9b57c2be884e9b4cc6b57308584b39d8382564fee3f64
RuntimeSources|certification\evidence-runtime\lib\EvidenceTlvCursor.cs|2617|76e77d36c9c4f6922ecff7b99537349f809078cc0052b700cda7e49b5e9db166
RuntimeSources|certification\evidence-runtime\lib\EvidenceSignatureContract.cs|4164|92a5e60fb13b6d4b64ef3b7e0266c92a882baacec4a487b39a50685352427b56
BytePolicyInputs|.gitattributes|1098|4fb78db0ed73b7f5c63edfe3ce6f71baf427bb80cfda9ec0d046b68907fc0f3c
BytePolicyInputs|certification\.gitattributes|1915|d5a6013a52c5083c22a15f5287ee0e26731c8b47a26af659ca75a21fd4767f1f
BytePolicyInputs|certification\lib\.gitattributes|357|400eb5662f50e67f0a102824637cf005e6cb3d779d9e332e336caa8d66bdcc63
BytePolicyInputs|certification\schema\.gitattributes|636|26c67d27238e780a96ec8fc22a2430f95aa488f6e975104f1e2f931763f4798d
BytePolicyInputs|certification\evidence-ledger\.gitattributes|127|02569930d8b1b2dd19e1b7397aebcaa9d7a9db74ed4aebd36f86a717262e7d4b
BytePolicyInputs|certification\evidence-ledger\schema\.gitattributes|123|ebf2b8bd099a5096aecb683468622d45e74ee7948e20d3750f12442a48f97d91
BytePolicyInputs|certification\evidence-runtime\.gitattributes|750|4a67ad8dcb538c0e8723e84abc535e60064dcc610921a54a403d14a0ecf0ec9b
BytePolicyInputs|.github\workflows\.gitattributes|141|e9143abc8b396c78937f0b59af6dd8dd25b5099b3f2734710356c7191b0034d7
DocumentationInputs|certification\evidence-runtime\README.md|24483|7f7eef59b23e58cf76800a428eb2a0b679b8c32febe33e86d41140dd24d706d6
ValidationCodeInputs|certification\evidence-runtime\validators\Invoke-PspktPhase4EvidenceRuntimeValidators.ps1|54848|7f6f3d197399797f74ce6ba795ff75344ad0aeaa6477da090c6545e70fc16f75
TestSourceInputs|certification\evidence-runtime\tests\pspkt.Phase4EvidenceRuntime.Tests.ps1|114462|21c9329248c5bc56b76529b1687341c59ea6b999f4b7f30817592aacd0e45f7d
Generator|certification\evidence-runtime\vectors\New-PspktPhase4EvidenceRuntimeVectors.ps1|7290|2dcd6be3015f87f45e8cd869f95e9851f57abc201d224918778bc4ecef05ba3c
Fixtures|certification\evidence-runtime\vectors\generated\manifest.v1.json|8396|9af5b7956d4949dfe32d541319ece212dbab73edc4d595b10c3e2f6b6bdba9eb
Fixtures|certification\evidence-runtime\vectors\hand-authored\manifest.v1.json|3100|33143e66f879602f51b538e3f680a45b999414778eb9008598d45232316fdc5f
Fixtures|certification\evidence-runtime\vectors\hand-authored\operation-burn-receipt-profile1.bin|283|5fca724f829c7a575f105efeea19ddf0f1fe581467fa149753444733b136b500
Fixtures|certification\evidence-runtime\vectors\hand-authored\local-evidence-receipt-coverage.bin|729|9a1b91246ca4d1b277cee94da1ca2b68fd251df14fd9b33706ec3b28343ef31e
PublicationSourceInputs|.github\workflows\ci-evidence-runtime.yml|15046|0a7e6d4c08ae2c4aed0a97ee04af413f66ea9d96e71f3587012ca5253c0c0ef2
Fixtures|certification\evidence-runtime\vectors\generated\kind-00-profile-1.bin|1516|5645061b07524afc40208ba3617b27ef0bf009da1b2777905d8b9782308528d3
Fixtures|certification\evidence-runtime\vectors\generated\kind-00-profile-2.bin|1614|57890fba1c9caa78c2d95608bc9c44bd4f12db63b9d5f9a33ae3299c89e304ee
Fixtures|certification\evidence-runtime\vectors\generated\kind-01-profile-1.bin|1062|3bf7cc38a6828d9bc488ef7e41b2ad6bba72a7cdb626c582cfc690ef71b0bccc
Fixtures|certification\evidence-runtime\vectors\generated\kind-01-profile-2.bin|1062|74e1286fe363917cdf43c3debb961bc5890a1bd0d4c9c4e5c5588b5744ce7a99
Fixtures|certification\evidence-runtime\vectors\generated\kind-02-profile-1.bin|551|7c53055fb1145417ef433c25dfcf3847f81e7fca40f7ee1c7e0e54387764180d
Fixtures|certification\evidence-runtime\vectors\generated\kind-02-profile-2.bin|551|69719c3558348735d7bf24103a59601e8591ceffeb0d11a58e8632a8a5224837
Fixtures|certification\evidence-runtime\vectors\generated\kind-03-profile-1.bin|199|fc6e91bf649c189e0ec7abb2e2cc160fd217e5467445f29c9c55f9c5b67ee53b
Fixtures|certification\evidence-runtime\vectors\generated\kind-03-profile-2.bin|319|7d0c761686d10124a74718f5df0f8a945d9c5e669baf0fcb73971cd1877f426b
Fixtures|certification\evidence-runtime\vectors\generated\kind-04-profile-1.bin|171|53f689e9543cde648d24c6b307a941028b50bcbf56cb7acafef6312f74cfffc4
Fixtures|certification\evidence-runtime\vectors\generated\kind-04-profile-2.bin|275|3d4e691de88a0d46d6fa634ff4a3fad3f16939ea4f5bc6336cb54c8ab91e3b3d
Fixtures|certification\evidence-runtime\vectors\generated\kind-05-profile-1.bin|799|40f4690cd7a69f9368522ab00769b66ec93606475e0d7404944836775f5ec2e4
Fixtures|certification\evidence-runtime\vectors\generated\kind-05-profile-2.bin|799|4c222cd9afb7ed9c287acfad0ea7f1213eea7c882e2b59bd3579fcda5c666522
Fixtures|certification\evidence-runtime\vectors\generated\kind-06-profile-1.bin|449|66f394e762f94f283419ccce581cbf45d214112d16a3cab80c13d03f141c1c4f
Fixtures|certification\evidence-runtime\vectors\generated\kind-06-profile-2.bin|449|f3c19466808d91490567b2af2cb67f93e6d3f9c6d4027e55bb22f32b22332ed8
Fixtures|certification\evidence-runtime\vectors\generated\kind-07-profile-1.bin|1762|a76de9ee91c62232ebb002b583d4d4191d057a7bca31f0440b2bc647472dc19a
Fixtures|certification\evidence-runtime\vectors\generated\kind-07-profile-2.bin|1762|67042cfcce40571df30660c5f2092e341885234a9fc99fc64349e0c7172855b1
Fixtures|certification\evidence-runtime\vectors\generated\kind-08-profile-1.bin|476|c01b8de819b103791106483a2ade1cd59458af0e64a7effb557fd262e709882d
Fixtures|certification\evidence-runtime\vectors\generated\kind-08-profile-2.bin|476|ec108c7c4ce26d7123148a69544f3ac4b4954e6b60c4584c706e8a5c4174dc4d
Fixtures|certification\evidence-runtime\vectors\generated\kind-09-profile-1.bin|262228|fffa071c33deb4c89188f8576e6a45aacad7a711113549e36bc5befd2fd87435
Fixtures|certification\evidence-runtime\vectors\generated\kind-09-profile-2.bin|262228|ef8269ae97a3ce5c23781d473480252a4afb899513b67f988c16ea4e6157bf49
Fixtures|certification\evidence-runtime\vectors\generated\kind-10-profile-1.bin|930|0d32f2100c24db93885403e107bfd9657701bd7ad922a7c41d184c7f0031c701
Fixtures|certification\evidence-runtime\vectors\generated\kind-10-profile-2.bin|930|6f2d52303220da0ba501ec53c34f47150f65fac574fa1ae0cc7d7de66f5d6c50
Fixtures|certification\evidence-runtime\vectors\generated\kind-11-profile-1.bin|446|f775ad4bd0f149d53968a91f6b2716a6f6b7ff1a57f6885da1b0204fbe6be822
Fixtures|certification\evidence-runtime\vectors\generated\kind-11-profile-2.bin|446|250749c16d7eb1683944cde2b0b2898683eeb9ccabb03d6aa5405ddfe5dcd421
Fixtures|certification\evidence-runtime\vectors\generated\kind-12-profile-1.bin|281|d4feb44ee493f434a5d0eba7308238e1785b2ce36b0d0603313a1196a3f61286
Fixtures|certification\evidence-runtime\vectors\generated\kind-12-profile-2.bin|281|f013ef0009290b91cdd1bdf8144890bd8b392a86a1bcbdf805cbe380fe7fc229
Fixtures|certification\evidence-runtime\vectors\generated\kind-13-profile-1.bin|799|b453f555d1dd995878a0d443723148f91db59878c6aaec160a0ef354217e3bc6
Fixtures|certification\evidence-runtime\vectors\generated\kind-13-profile-2.bin|799|13bece610e45ea40dc2a2ce4ba34d07bc5c98a9e17752e59c31d733296fdfbc7
Fixtures|certification\evidence-runtime\vectors\generated\kind-14-profile-1.bin|602|e6611b571b2603acd1b776aed4c8fbff5596fc56498def8c0a4e3381025afdac
Fixtures|certification\evidence-runtime\vectors\generated\kind-14-profile-2.bin|602|56df31dfa53a05735281f01328b453dbabbcc394ceadf4d45123292b4d910ce7
Fixtures|certification\evidence-runtime\vectors\generated\kind-15-profile-1.bin|1074|bbd85cbceafe7d0e7003a8ac81a9cd46c374dd9ff7f6c151da187def53e6499d
Fixtures|certification\evidence-runtime\vectors\generated\kind-15-profile-2.bin|1112|edcdd5a31071cf87ea9351c12720ff77e59fc18f78faff5d0b5a0027e0d0b060
Fixtures|certification\evidence-runtime\vectors\generated\kind-16-profile-1.bin|729|1b3fe464248eb65bf3925b2719c8fb7579e4df19b305eccafa6379c184678d03
Fixtures|certification\evidence-runtime\vectors\generated\kind-16-profile-2.bin|729|55400d3a7eb63826fe37de3ebcc2f3a3c4b455e6112e0daaea116ecf2de7fb13
Fixtures|certification\evidence-runtime\vectors\generated\kind-17-profile-1.bin|729|238bf0590e7f34359a4f2ae14c7c724f8ab85174547e34fd07248c9d8b508a0b
Fixtures|certification\evidence-runtime\vectors\generated\kind-17-profile-2.bin|729|fef5fd6f8683e575518cb58a6e10d378577babdee2adc6f19f704c64c11bb7ed
Fixtures|certification\evidence-runtime\vectors\generated\kind-18-profile-1.bin|283|00ddd82dd4f4e4a9d298b5ef4794f946a2d02c96dba6bd6b6a396a1645880fb1
Fixtures|certification\evidence-runtime\vectors\generated\kind-18-profile-2.bin|283|66e61554332faf639fb6a20234f10c9c77d62d5aa3453617838371d7f57206ed
Fixtures|certification\evidence-runtime\vectors\generated\kind-19-profile-1.bin|289|0c1077e0aed7a33bd2c13a42766a45063d834e48c0e2244c25e89d60f5e39767
Fixtures|certification\evidence-runtime\vectors\generated\kind-19-profile-2.bin|289|688be7ae55f9025e03bb2f22111df7428b5101270553470a7c5d057785de2520
Fixtures|certification\evidence-runtime\vectors\generated\kind-20-profile-1.bin|721|85b3a383d89e85f4002b2bd3d245530bb8fb838035fc6d0fdcfa9cb3c81b8824
Fixtures|certification\evidence-runtime\vectors\generated\kind-20-profile-2.bin|721|054035fe10b229ce5ccbb2b5b36c82e07cc0d54bda1cb029f6ee8e70129a98f0
Fixtures|certification\evidence-runtime\vectors\generated\kind-21-profile-1.bin|235|2f20ba8441b85b1bb43df0ee5673d3268251eca4312454cb5b0cea9c2a238565
Fixtures|certification\evidence-runtime\vectors\generated\kind-21-profile-2.bin|235|7ee44ed86b3e4c725097a96f2d665a29844d1b6df432517f5a3729eec01c4aea
'@
    foreach ($line in $rows.Split("`n")) {
        $parts = $line.TrimEnd("`r").Split('|')
        if ($parts.Length -ne 4 -or $parts[3] -cnotmatch '^[0-9a-f]{64}$') { throw 'source-manifest: Literal pin shape differs.' }
        [pscustomobject]@{ Role = $parts[0]; Path = $parts[1]; Length = [long]$parts[2]; Sha256 = $parts[3] }
    }
}

function Read-PspktEvidenceBoundedFile {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [long]$ExpectedLength = -1,
        [string]$RelativePath = ''
    )

    if ($RelativePath) { Assert-PspktEvidenceSourcePath -Path $RelativePath }
    if ($Path.Length -gt 240 -or ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'source-path: File path is too long or is a reparse point.'
    }
    Assert-PspktEvidencePhysicalDirectory -Path ([IO.Path]::GetDirectoryName($Path))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 1048576 -or ($ExpectedLength -ge 0 -and $stream.Length -ne $ExpectedLength)) {
            if ($RelativePath) { throw ('source-length: Retained byte length differs for ' + $RelativePath + '.') }
            throw 'source-length: Source byte length differs before allocation.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $position = 0
        while ($position -lt $bytes.Length) {
            $read = $stream.Read($bytes, $position, $bytes.Length - $position)
            if ($read -eq 0) { throw 'source-read: Source ended before its admitted length.' }
            $position += $read
        }
        if ($stream.ReadByte() -ne -1) { throw 'source-read: Source grew during admission.' }
        return ,$bytes
    }
    finally { $stream.Dispose() }
}

function Read-PspktEvidencePinnedSource {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    Assert-PspktEvidenceSourcePath -Path $RelativePath
    $pins = @(Get-PspktEvidenceSourcePins | Where-Object { [string]::Equals($_.Path, $RelativePath, [StringComparison]::Ordinal) })
    if ($pins.Count -ne 1) { throw 'source-manifest: A unique literal pin is required.' }
    $pin = $pins[0]
    $bytes = Read-PspktEvidenceBoundedFile -Path (Join-Path $RepositoryRoot $RelativePath) -ExpectedLength $pin.Length -RelativePath $RelativePath
    if (-not [string]::Equals((Get-PspktEvidenceBytesDigest -Bytes $bytes), $pin.Sha256, [StringComparison]::Ordinal)) { throw ('source-pin: Retained bytes differ for ' + $RelativePath + '.') }
    [pscustomobject]@{ Role = $pin.Role; Path = $pin.Path; Length = $pin.Length; Sha256 = $pin.Sha256; Bytes = $bytes }
}

function Get-PspktEvidenceSourceSnapshot {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [hashtable]$PreloadedBytes = @{}
    )

    $rootPath = 'certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'
    $pins = @{}
    foreach ($pin in @(Get-PspktEvidenceSourcePins)) {
        if ($pins.ContainsKey($pin.Path)) { throw 'source-manifest: Duplicate source pin.' }
        $pins.Add($pin.Path, $pin)
    }
    Assert-PspktEvidenceExportPathSet -Paths @(@($pins.Keys) + $rootPath)
    foreach ($preloadedPath in $PreloadedBytes.Keys) { Assert-PspktEvidenceSourcePath -Path $preloadedPath }
    $files = @{}
    $records = @()
    $manifest = [Text.StringBuilder]::new()
    foreach ($path in @(Get-PspktEvidenceSourcePaths)) {
        if ($path -ceq $rootPath) {
            [byte[]]$bytes = if ($PreloadedBytes.ContainsKey($path)) { [byte[]]$PreloadedBytes[$path].Clone() } else {
                Read-PspktEvidenceBoundedFile -Path (Join-Path $RepositoryRoot $path) -RelativePath $path
            }
            if ($bytes.Length -eq 0 -or $bytes.Length -gt 1048576) { throw 'source-length: Reviewed contract root is outside its bound.' }
            $record = [pscustomobject]@{ Role = 'ContractRoot'; Path = $path; Length = $bytes.Length; Sha256 = Get-PspktEvidenceBytesDigest -Bytes $bytes; Bytes = $bytes }
        }
        elseif ($PreloadedBytes.ContainsKey($path)) {
            $pin = $pins[$path]
            $bytes = [byte[]]$PreloadedBytes[$path]
            if ($bytes.Length -ne $pin.Length) { throw ('source-length: Retained byte length differs for ' + $path + '.') }
            if ((Get-PspktEvidenceBytesDigest -Bytes $bytes) -cne $pin.Sha256) {
                throw 'source-pin: Preloaded source bytes differ.'
            }
            $record = [pscustomobject]@{ Role = $pin.Role; Path = $path; Length = $pin.Length; Sha256 = $pin.Sha256; Bytes = [byte[]]$bytes.Clone() }
        }
        else { $record = Read-PspktEvidencePinnedSource -RepositoryRoot $RepositoryRoot -RelativePath $path }
        $files.Add($path, $record)
        $records += [pscustomobject]@{ Role = $record.Role; Path = $path; Length = $record.Length; Sha256 = $record.Sha256 }
        $manifestLine = $record.Role + [char]0 + $path + [char]0 +
            $record.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + [char]0 + $record.Sha256 + "`n"
        [void]$manifest.Append($manifestLine)
    }
    [pscustomobject]@{
        Files = $files
        Records = $records
        ManifestSha256 = Get-PspktEvidenceBytesDigest -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes($manifest.ToString()))
    }
}

function Assert-PspktEvidenceStableIdentifiers {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$SourceText)

    if ([regex]::IsMatch($SourceText, '(?i)\b(?:B[0-9]{2}|R[0-9]+)\b')) {
        throw 'source-marker: Ephemeral plan identifiers are not admitted in source text.'
    }
}

function Assert-PspktEvidenceSourceClosure {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][object]$Snapshot)

    Assert-PspktEvidenceExportPathSet -Paths @($Snapshot.Files.Keys)
    $pins = @{}
    foreach ($pin in @(Get-PspktEvidenceSourcePins)) { $pins.Add($pin.Path, $pin) }
    $rootPath = 'certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'
    $manifest = [Text.StringBuilder]::new()
    $paths = @(Get-PspktEvidenceSourcePaths)
    if (@($Snapshot.Records).Count -ne $paths.Count) { throw 'source-manifest: Retained record population differs.' }
    for ($index = 0; $index -lt $paths.Count; $index++) {
        $path = $paths[$index]
        $record = $Snapshot.Files[$path]
        if ($record.Path -isnot [string] -or -not [string]::Equals($record.Path, $path, [StringComparison]::Ordinal) -or $record.Role -isnot [string] -or
            $record.Bytes -isnot [byte[]] -or ($record.Length -isnot [int] -and $record.Length -isnot [long]) -or
            $record.Sha256 -isnot [string] -or $record.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'source-manifest: Retained source record shape differs.'
        }
        if ($path -ceq $rootPath) {
            if (-not [string]::Equals($record.Role, 'ContractRoot', [StringComparison]::Ordinal)) { throw 'source-pin: Reviewed contract role differs.' }
        }
        else {
            $pin = $pins[$path]
            if (-not [string]::Equals($record.Role, $pin.Role, [StringComparison]::Ordinal) -or $record.Length -ne $pin.Length -or
                -not [string]::Equals($record.Sha256, $pin.Sha256, [StringComparison]::Ordinal)) {
                throw 'source-pin: Retained source cannot replace its literal admission pin.'
            }
        }
        if ($record.Bytes.Length -ne $record.Length -or (Get-PspktEvidenceBytesDigest -Bytes $record.Bytes) -cne $record.Sha256) {
            throw 'source-closure: Retained source bytes differ.'
        }
        $declared = $Snapshot.Records[$index]
        if (-not [string]::Equals($declared.Path, $path, [StringComparison]::Ordinal) -or
            -not [string]::Equals($declared.Role, $record.Role, [StringComparison]::Ordinal) -or $declared.Length -ne $record.Length -or
            -not [string]::Equals($declared.Sha256, $record.Sha256, [StringComparison]::Ordinal)) {
            throw 'source-manifest: Retained source and manifest records differ.'
        }
        $line = $record.Role + [char]0 + $path + [char]0 +
            $record.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + [char]0 + $record.Sha256 + "`n"
        [void]$manifest.Append($line)
        $newText = ($record.Path.StartsWith('certification\evidence-runtime\', [StringComparison]::Ordinal) -and
            ($record.Path.EndsWith('.ps1') -or $record.Path.EndsWith('.cs') -or $record.Path.EndsWith('.md') -or $record.Path.EndsWith('.gitattributes'))) -or
            $record.Path -ceq '.github\workflows\.gitattributes' -or $record.Path -ceq '.github\workflows\ci-evidence-runtime.yml'
        if ($newText) {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($record.Bytes)
            Assert-PspktEvidenceStableIdentifiers -SourceText $text
            if ([Array]::IndexOf($record.Bytes, [byte]13) -ge 0 -or $text.StartsWith([string][char]65279, [StringComparison]::Ordinal)) {
                throw 'source-policy: New source text must be UTF-8 without BOM and with LF.'
            }
            if ($record.Role -notin @('ContractRoot', 'TestSourceInputs') -and
                $text -match '(?i)\b(NotExecuted|CompileOnly|CompileSucceeded|CompilationSucceeded|CompileResult|CompileReport|UnsupportedMode|UnknownMode|SkipTests|SkipOracles|ValidateOnly|NoLoad)\b') {
                throw 'source-stale: An obsolete operation or result identifier remains.'
            }
            if ($record.Role -in @('RuntimeSources', 'ValidationCodeInputs') -and
                $text -match 'ReflectionOnlyLoadFrom|\.CompiledAssembly\b|AssemblyResolve|GetNewClosure|New-Module') {
                throw 'source-closure: A prohibited loader or caller-scope mechanism remains.'
            }
        }
    }
    if (-not [string]::Equals($Snapshot.ManifestSha256,
        (Get-PspktEvidenceBytesDigest -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes($manifest.ToString()))), [StringComparison]::Ordinal)) {
        throw 'source-manifest: Retained manifest identity differs.'
    }
}

function Assert-PspktEvidenceRegistryAbsent {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    if (@(Get-PSDrive -Name TestRegistry -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-Variable -Name TestRegistry -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-Variable -Name TestRegistry -Scope Global -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'registry-state: TestRegistry drive and variables must be absent.'
    }
}

function Assert-PspktEvidenceOwnedTestStorage {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$ArtifactRoot)

    $root = ConvertTo-PspktEvidenceDirectoryPath -Path $ArtifactRoot
    $temporary = ConvertTo-PspktEvidenceDirectoryPath -Path ([IO.Path]::GetTempPath())
    if (-not [string]::Equals($root, $temporary, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'test-storage: Temporary storage escaped the owned run root.'
    }
    $drives = @(Get-PSDrive -Name TestDrive -ErrorAction SilentlyContinue)
    if ($drives.Count -ne 1 -or $drives[0].Provider.Name -cne 'FileSystem') {
        throw 'test-storage: One owned filesystem TestDrive is required.'
    }
    $testPath = ConvertTo-PspktEvidenceDirectoryPath -Path $drives[0].Root
    if (-not $testPath.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'test-storage: TestDrive escaped the owned run root.'
    }
    Assert-PspktEvidencePhysicalDirectory -Path $testPath
}

function Assert-PspktEvidenceRunResidue {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Images
    )

    $root = ConvertTo-PspktEvidenceDirectoryPath -Path $ArtifactRoot
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($image in $Images) {
        if (-not $image.ImagePath.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not $expected.Add($image.ImagePath) -or -not $image.LoadAttempted) {
            throw 'run-residue: Retained image declaration differs.'
        }
        $bytes = [IO.File]::ReadAllBytes($image.ImagePath)
        if ($bytes.Length -ne $image.ImageLength -or (Get-PspktEvidenceBytesDigest -Bytes $bytes) -cne $image.ImageSha256) {
            throw 'run-residue: Retained image custody differs.'
        }
    }
    $entries = [IO.Directory]::GetFileSystemEntries($root)
    if ($entries.Length -ne $expected.Count) { throw 'run-residue: Unexpected or missing run entries remain.' }
    foreach ($entry in $entries) {
        if (-not $expected.Contains($entry) -or [IO.Directory]::Exists($entry)) { throw 'run-residue: An unowned entry remains.' }
    }
}

function ConvertTo-PspktEvidenceDirectoryPath {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path.Substring(2).Contains('\\') -or $Path.Contains('/') -or
        $Path.IndexOfAny([char[]]'*?"<>|') -ge 0 -or $Path.Length -gt 220) {
        throw 'work-root: An unaliased absolute local Windows directory is required.'
    }
    foreach ($part in $Path.Substring(3).Split('\')) {
        if ($part -ceq '.' -or $part -ceq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '~[0-9]+(?:\.|$)' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?$') {
            throw 'work-root: Directory aliases and traversal are forbidden.'
        }
    }
    $normalized = [IO.Path]::GetFullPath($Path)
    if ($normalized.Length -gt 3) { $normalized = $normalized.TrimEnd('\') }
    return $normalized
}

function Test-PspktEvidenceDirectoryOverlap {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $leftPath = ConvertTo-PspktEvidenceDirectoryPath -Path $Left
    $rightPath = ConvertTo-PspktEvidenceDirectoryPath -Path $Right
    return [string]::Equals($leftPath, $rightPath, [StringComparison]::OrdinalIgnoreCase) -or
        $leftPath.StartsWith($rightPath.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $rightPath.StartsWith($leftPath.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-PspktEvidenceWorkRootLength {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$WorkRoot)

    if ($WorkRoot.Length -gt (Get-PspktEvidenceRuntimeContract).WorkRootMaximumLength) {
        throw 'work-root: Fresh run path is colliding or exceeds the Desktop-safe length.'
    }
}

function Assert-PspktEvidenceRootRelationships {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$WorkRoot,
        [string]$OriginalWorkspace,
        [string]$RunnerTemp
    )

    $repository = ConvertTo-PspktEvidenceDirectoryPath -Path $RepositoryRoot
    $work = ConvertTo-PspktEvidenceDirectoryPath -Path $WorkRoot
    if (Test-PspktEvidenceDirectoryOverlap -Left $repository -Right $work) {
        throw 'work-root: Work and source directories overlap.'
    }
    if ($OriginalWorkspace -and (Test-PspktEvidenceDirectoryOverlap -Left $OriginalWorkspace -Right $work)) {
        throw 'work-root: Work and original checkout directories overlap.'
    }
    if ($RunnerTemp) {
        $runner = ConvertTo-PspktEvidenceDirectoryPath -Path $RunnerTemp
        if (-not $work.StartsWith($runner.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'work-root: CI work roots must be strictly beneath RUNNER_TEMP.'
        }
    }
}

function Assert-PspktEvidencePhysicalDirectory {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = ConvertTo-PspktEvidenceDirectoryPath -Path $Path
    if (-not [IO.Directory]::Exists($normalized)) { throw 'work-root: Directory does not exist.' }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($normalized))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'work-root: A local fixed volume is required.' }
    $directory = [IO.DirectoryInfo]::new($normalized)
    while ($null -ne $directory) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'work-root: Reparse points are forbidden.' }
        $directory = $directory.Parent
    }
}

function Assert-PspktEvidenceWorkflowDependencies {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [AllowNull()][AllowEmptyString()][string]$DesktopResult,
        [AllowNull()][AllowEmptyString()][string]$CoreResult
    )

    if (-not [string]::Equals($DesktopResult, 'success', [StringComparison]::Ordinal)) {
        throw 'workflow-dependency: Windows PowerShell validation job did not succeed.'
    }
    if (-not [string]::Equals($CoreResult, 'success', [StringComparison]::Ordinal)) {
        throw 'workflow-dependency: PowerShell 7 validation job did not succeed.'
    }
}

function Assert-PspktEvidenceWorkflow {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$SourceText)

    foreach ($job in @('windows_ps51', 'powershell_7', 'evidence_runtime_acceptance')) {
        if ([regex]::Matches($SourceText, '(?m)^  ' + $job + ':\r?$').Count -ne 1) {
            throw 'workflow-contract: Exact literal-shell job set is required.'
        }
    }
    if ($SourceText -match 'pull_request_target|secrets\.|matrix\.shell|\.conclusion' -or
        [regex]::Matches($SourceText, 'continue-on-error: true').Count -ne 10 -or
        [regex]::Matches($SourceText, 'id: validate_checkout').Count -ne 2 -or
        [regex]::Matches($SourceText, 'id: validate_export').Count -ne 2) {
        throw 'workflow-contract: Invocation or expected-failure step census differs.'
    }
    $actions = [regex]::Matches($SourceText, '(?m)^\s*- uses: ([^\r\n]+)')
    if ($actions.Count -ne 3 -or [regex]::Matches($SourceText, 'if: \$\{\{ !cancelled\(\) \}\}').Count -ne 3 -or
        $SourceText.Contains('always()')) { throw 'workflow-contract: Pinned actions or cancellation gates differ.' }
    $checkout = (Get-PspktEvidenceRuntimeContract).CheckoutAction
    foreach ($action in $actions) {
        if (-not [string]::Equals($action.Groups[1].Value, $checkout.Repository + '@' + $checkout.CommitSha, [StringComparison]::Ordinal)) {
            throw 'workflow-contract: An action is not pinned to the reviewed commit.'
        }
    }
    foreach ($required in @('shell: powershell', 'shell: pwsh', 'RUNNER_TEMP', 'GITHUB_WORKSPACE',
        'Assert-PspktEvidenceValidationSuccess', 'Assert-PspktEvidenceCiAggregate', 'Complete-PspktEvidenceValidationInvocation',
        'PositiveControlPassed', '.outcome', 'exit 1', 'persist-credentials: false',
        'Assert-PspktEvidencePesterPackage', 'Write-PspktEvidenceFailureDiagnostics')) {
        if (-not $SourceText.Contains($required)) { throw 'workflow-contract: A required fail-closed boundary is absent.' }
    }
    $aggregate = [regex]::Match($SourceText, '(?m)^        run: \|\r?\n((?:          .*\r?\n)+)')
    $formatterPosition = $aggregate.Groups[1].Value.IndexOf('Get-PspktEvidenceDiagnosticMessages', [StringComparison]::Ordinal)
    $dependencyPosition = $aggregate.Groups[1].Value.IndexOf('Assert-PspktEvidenceWorkflowDependencies', [StringComparison]::Ordinal)
    if (-not $aggregate.Success -or $formatterPosition -lt 0 -or $dependencyPosition -le $formatterPosition -or
        $SourceText.Contains('formatter is unavailable') -or
        -not $SourceText.Contains('workflow-failure: Evidence runtime workflow step failed.')) {
        throw 'workflow-contract: Aggregate diagnostic initialization or neutral fallback differs.'
    }
}

function New-PspktEvidencePesterConfiguration {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][object]$Container)

    $configuration = New-PesterConfiguration
    $configuration.Run.Container = @($Container)
    $configuration.Run.Path = @()
    $configuration.Run.PassThru = $true
    $configuration.Run.Exit = $false
    $configuration.Run.Throw = $false
    $configuration.Filter.Tag = @('Precheck')
    $configuration.Filter.ExcludeTag = @()
    $configuration.Filter.FullName = @()
    $configuration.TestDrive.Enabled = $true
    $configuration.TestRegistry.Enabled = $false
    $configuration.TestResult.Enabled = $false
    $configuration.CodeCoverage.Enabled = $false
    $configuration.Output.Verbosity = 'None'
    return $configuration
}

function Assert-PspktEvidencePesterConfiguration {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][object]$Configuration)

    if (@($Configuration.Run.Container.Value).Count -ne 1 -or @($Configuration.Run.Path.Value).Count -ne 0 -or
        $Configuration.Run.PassThru.Value -ne $true -or $Configuration.Run.Exit.Value -ne $false -or
        $Configuration.Run.Throw.Value -ne $false -or
        (@($Configuration.Filter.Tag.Value) -join ',') -cne 'Precheck' -or
        @($Configuration.Filter.ExcludeTag.Value).Count -ne 0 -or @($Configuration.Filter.FullName.Value).Count -ne 0 -or
        $Configuration.TestDrive.Enabled.Value -ne $true -or $Configuration.TestRegistry.Enabled.Value -ne $false -or
        $Configuration.TestResult.Enabled.Value -ne $false -or $Configuration.CodeCoverage.Enabled.Value -ne $false) {
        throw 'pester-configuration: Exact registry-disabled complete-run settings are required.'
    }
}

function Assert-PspktEvidenceExportPathSet {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string[]]$Paths)

    $expected = @(Get-PspktEvidenceSourcePaths)
    if ($Paths.Count -ne $expected.Count) { throw 'export-membership: Exact source export population is required.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($path in $Paths) {
        if (-not $seen.Add($path) -or [Array]::IndexOf([string[]]$expected, $path) -lt 0 -or
            [Array]::IndexOf([string[]]$path.Split('\'), '.git') -ge 0) {
            throw 'export-membership: Export contains a duplicate or unadmitted path.'
        }
    }
}

function Export-PspktEvidenceSources {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Snapshot,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )

    Assert-PspktEvidenceExportPathSet -Paths @($Snapshot.Keys)
    $root = ConvertTo-PspktEvidenceDirectoryPath -Path $OutputRoot
    if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) {
        throw 'export-root: A fresh destination is required.'
    }
    Assert-PspktEvidencePhysicalDirectory -Path ([IO.Path]::GetDirectoryName($root))
    [void][IO.Directory]::CreateDirectory($root)
    Assert-PspktEvidencePhysicalDirectory -Path $root
    $copiedBytes = @{}
    foreach ($relative in @(Get-PspktEvidenceSourcePaths)) {
        $record = $Snapshot[$relative]
        if ($record.Bytes.Length -ne $record.Length -or (Get-PspktEvidenceBytesDigest -Bytes $record.Bytes) -cne $record.Sha256) {
            throw 'export-pin: Retained source record differs.'
        }
        $path = Join-Path $root $relative
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        Assert-PspktEvidencePhysicalDirectory -Path ([IO.Path]::GetDirectoryName($path))
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($record.Bytes, 0, $record.Bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        $copied = [IO.File]::ReadAllBytes($path)
        if ($copied.Length -ne $record.Length -or (Get-PspktEvidenceBytesDigest -Bytes $copied) -cne $record.Sha256) {
            throw 'export-custody: Exported bytes differ.'
        }
        $copiedBytes.Add($relative, $copied)
    }
    if ([IO.Directory]::Exists((Join-Path $root '.git')) -or [IO.File]::Exists((Join-Path $root '.git'))) {
        throw 'export-membership: Export unexpectedly contains repository metadata.'
    }
    return $copiedBytes
}

function Get-PspktEvidenceMutantSources {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string[]]$Sources,
        [Parameter(Mandatory = $true)][string[]]$SourceNames
    )

    $writerOriginal = @(
        '            bytes[offset] = (byte)(value >> 24);',
        '            bytes[offset + 1] = (byte)(value >> 16);',
        '            bytes[offset + 2] = (byte)(value >> 8);',
        '            bytes[offset + 3] = (byte)value;'
    ) -join "`n"
    $writerMutated = @(
        '            bytes[offset] = (byte)value;',
        '            bytes[offset + 1] = (byte)(value >> 8);',
        '            bytes[offset + 2] = (byte)(value >> 16);',
        '            bytes[offset + 3] = (byte)(value >> 24);'
    ) -join "`n"
    $specifications = @(
        [pscustomobject]@{
            Role = 'M1'; SourceName = 'EvidenceTlvCursor.cs'; Original = $writerOriginal; Mutated = $writerMutated
            OriginalSha256 = '76e77d36c9c4f6922ecff7b99537349f809078cc0052b700cda7e49b5e9db166'
            MutatedSha256 = 'd7c36c54a0a59b88d4d3fe3f6807b90bb80cc8167a75f7de657c2931e290348e'
            OracleId = 'burn-receipt-encode'
        }
        [pscustomobject]@{
            Role = 'M2'; SourceName = 'EvidenceSignatureContract.cs'
            Original = 'byte[] hashDomainBytes = Encoding.ASCII.GetBytes(domain + "\0");'
            Mutated = 'byte[] hashDomainBytes = Encoding.ASCII.GetBytes(domain);'
            OriginalSha256 = '92a5e60fb13b6d4b64ef3b7e0266c92a882baacec4a487b39a50685352427b56'
            MutatedSha256 = '5e113766195dcc301c1afe8afcb2bef3fa5b228db86e651ccff7158c51e6663d'
            OracleId = 'burn-receipt-domain-hash'
        }
        [pscustomobject]@{
            Role = 'M3'; SourceName = 'EvidenceSignatureContract.cs'
            Original = 'int coveredLength = cursor.Position;'
            Mutated = 'int coveredLength = payload.Length;'
            OriginalSha256 = '92a5e60fb13b6d4b64ef3b7e0266c92a882baacec4a487b39a50685352427b56'
            MutatedSha256 = '32ef6028f1364aa1e99731772dc49b90ec21fda8cfda69d4a502d0eaacfc135e'
            OracleId = 'local-evidence-signature-covered-bytes'
        }
    )
    $specification = @($specifications | Where-Object { $_.Role -ceq $Role })
    if ($specification.Count -ne 1 -or $Sources.Count -ne 7 -or $SourceNames.Count -ne 7) {
        throw 'mutant-role: Exact mutant and source census is required.'
    }
    $specification = $specification[0]
    $index = [Array]::IndexOf($SourceNames, [string]$specification.SourceName)
    if ($index -lt 0) { throw 'mutant-source: Designated source is absent.' }
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $original = $Sources[$index]
    if ((Get-PspktEvidenceBytesDigest -Bytes $encoding.GetBytes($original)) -cne $specification.OriginalSha256 -or
        $original.Split(@([string]$specification.Original), [StringSplitOptions]::None).Length -ne 2) {
        throw 'mutant-source: Original source pin or single span differs.'
    }
    $changed = [string[]]$Sources.Clone()
    $changed[$index] = $original.Replace($specification.Original, $specification.Mutated)
    if ((Get-PspktEvidenceBytesDigest -Bytes $encoding.GetBytes($changed[$index])) -cne $specification.MutatedSha256) {
        throw 'mutant-source: Mutated source pin differs.'
    }
    [pscustomobject]@{
        Sources = $changed
        OracleId = $specification.OracleId
        Transform = [pscustomobject]@{
            SourcePath = 'certification\evidence-runtime\lib\' + $specification.SourceName
            OriginalSha256 = $specification.OriginalSha256
            MutatedSha256 = $specification.MutatedSha256
            MatchCount = 1
        }
    }
}

function Assert-PspktEvidenceGeneratorIsolation {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$SourceText)

    if ($SourceText -match 'EvidenceArtifactEnvelopeCodec|EvidenceAuthorityJsonReader|EvidenceRuntimeContract|hand-authored|Reflection|Assembly|Add-Type|Import-Module|Process|Registry') {
        throw 'generator-isolation: Generator contains an unadmitted dependency.'
    }
    $tokens = $null
    $errors = $null
    $syntax = [Management.Automation.Language.Parser]::ParseInput($SourceText, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0 -or ($syntax.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') -cne 'RepositoryRoot,OutputRoot') {
        throw 'generator-isolation: Generator syntax or parameters differ.'
    }
    $allowedCommands = @('Set-StrictMode', 'Join-Path', 'ConvertFrom-Json', 'Sort-Object', 'ConvertTo-Json',
        'Get-VectorDigest', 'Get-VectorProperty', 'Write-VectorLength', 'Write-VectorField', 'New-VectorPayload', 'Write-VectorBytes')
    foreach ($command in $syntax.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)) {
        if ($allowedCommands -cnotcontains $command.GetCommandName()) {
            throw 'generator-isolation: Generator invokes an unadmitted command.'
        }
    }
    $allowedTypes = @('IO.Path', 'IO.Directory', 'IO.File', 'IO.FileMode', 'IO.FileAccess', 'IO.FileShare',
        'IO.MemoryStream', 'Security.Cryptography.SHA256', 'BitConverter', 'Text.UTF8Encoding', 'Text.Encoding',
        'Math', 'Convert', 'byte[]')
    foreach ($expression in $syntax.FindAll({ param($node) $node -is [Management.Automation.Language.TypeExpressionAst] }, $true)) {
        if ($allowedTypes -cnotcontains $expression.TypeName.FullName) {
            throw 'generator-isolation: Generator references an unadmitted static type.'
        }
    }
    $reads = @($syntax.FindAll({
        param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Extent.Text -ceq 'ReadAllBytes'
    }, $true))
    if ($reads.Count -ne 1 -or $reads[0].Extent.Text -cne '[IO.File]::ReadAllBytes((Join-Path $sourceRoot $pin[0]))') {
        throw 'generator-isolation: Generator input read graph differs.'
    }
    foreach ($inputRecord in (Get-PspktEvidenceRuntimeContract).AuthorityInputs) {
        if (-not $SourceText.Contains("'" + $inputRecord.Path + "', " + $inputRecord.Length + ", '" + $inputRecord.Sha256 + "'")) {
            throw 'generator-isolation: Exact authority pin metadata differs.'
        }
    }
}

function Get-PspktEvidenceTestWrapper {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][byte[]]$OriginalBytes)

    if ($OriginalBytes.Length -eq 0 -or $OriginalBytes.Length -gt 1048576 -or
        [Array]::IndexOf($OriginalBytes, [byte]13) -ge 0 -or
        ($OriginalBytes.Length -ge 3 -and $OriginalBytes[0] -eq 239 -and $OriginalBytes[1] -eq 187 -and $OriginalBytes[2] -eq 191)) {
        throw 'test-source: Retained test bytes must be bounded UTF-8 without BOM or CR.'
    }
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $text = $encoding.GetString($OriginalBytes)
    $tokens = $null
    $errors = $null
    $syntax = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0 -or @($syntax.UsingStatements).Count -ne 0 -or $null -ne $syntax.ScriptRequirements) {
        throw 'test-source: Retained test text cannot be enclosed in the caller wrapper.'
    }
    $expectedNames = @('BootstrapAssembly', 'RuntimeAssembly', 'AuthorityBytesById', 'FixtureBytesById',
        'ManifestRecordsByRole', 'CompileCensus', 'MutantBuilds', 'ArtifactRoot', 'CallerScopeMarker')
    if (($syntax.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') -cne ($expectedNames -join ',')) {
        throw 'test-data: Exact test parameter names are required.'
    }
    $fixtureDefinitions = @($syntax.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'New-PspktEvidenceValidationResultFixture'
    }, $true))
    if ($fixtureDefinitions.Count -ne 1) { throw 'test-fixture: Exactly one retained result fixture definition is required.' }
    $wrapperBytes = [byte[]]::new($OriginalBytes.Length + 4)
    $wrapperBytes[0] = 123
    $wrapperBytes[1] = 10
    [Buffer]::BlockCopy($OriginalBytes, 0, $wrapperBytes, 2, $OriginalBytes.Length)
    $wrapperBytes[$wrapperBytes.Length - 2] = 10
    $wrapperBytes[$wrapperBytes.Length - 1] = 125
    [pscustomobject]@{
        OriginalLength = $OriginalBytes.Length
        OriginalSha256 = Get-PspktEvidenceBytesDigest -Bytes $OriginalBytes
        WrapperLength = $wrapperBytes.Length
        WrapperSha256 = Get-PspktEvidenceBytesDigest -Bytes $wrapperBytes
        Factory = [scriptblock]::Create($encoding.GetString($wrapperBytes))
        FixtureDefinition = [scriptblock]::Create($fixtureDefinitions[0].Extent.Text)
        DataNames = $expectedNames
    }
}

function Get-PspktEvidenceBytesDigest {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Assert-PspktEvidenceDocumentation {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][Reflection.Assembly]$RuntimeAssembly
    )

    function Assert-PspktEvidenceDocumentRow([string]$Row) {
        if ([regex]::Matches($Text, '(?m)^' + [regex]::Escape($Row) + '\r?$').Count -ne 1) {
            throw 'documentation-parity: A required unique documentation row differs.'
        }
    }

    $contract = Get-PspktEvidenceRuntimeContract
    foreach ($parameterName in $contract.PublicDomainParameters) {
        Assert-PspktEvidenceDocumentRow ('| ' + $parameterName + ' | System.String |')
    }
    Assert-PspktEvidenceDocumentRow ('| WorkRootMaximumLength | ' + $contract.WorkRootMaximumLength + ' |')
    foreach ($property in $contract.CheckoutAction.PSObject.Properties) {
        Assert-PspktEvidenceDocumentRow ('| Checkout' + $property.Name + ' | ' + $property.Value + ' |')
    }
    Assert-PspktEvidenceDocumentRow '| CallerScopeMarker | pspkt-evidence-validation: |'
    foreach ($row in @(
        '| Emitted closed category | Preserve the category; redact unsafe variable text. |',
        '| Unmatched uncategorized literal | Generic redacted diagnostic; no category inferred. |',
        '| Registered but un-emitted category | No runtime emission or reachability claim. |'
    )) { Assert-PspktEvidenceDocumentRow $row }
    $snapshotType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceSchemaSnapshot', $true)
    $stages = $snapshotType.GetMethod('GetInputStages', [Reflection.BindingFlags]'Static,NonPublic').Invoke($null, @())
    foreach ($stage in $stages) { Assert-PspktEvidenceDocumentRow ('| ' + (($stage -split ':') -join ' | ') + ' |') }
    for ($index = 0; $index -lt $contract.UncheckedTokens.Count; $index++) {
        Assert-PspktEvidenceDocumentRow ('| ' + [char](65 + $index) + ' | ' + $contract.UncheckedTokens[$index] + ' |')
    }
    $signatureType = $RuntimeAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceSignatureContract', $true)
    $tokenMethod = $signatureType.GetMethod('GetUncheckedSemantics', [Reflection.BindingFlags]'Static,NonPublic')
    $categoryMethod = $signatureType.GetMethod('GetDigestCategoryBindings', [Reflection.BindingFlags]'Static,NonPublic')
    for ($kind = 0; $kind -lt 22; $kind++) {
        Assert-PspktEvidenceDocumentRow ('| ' + $kind + ' | ' + $contract.KindTokenCodes[$kind] + ' |')
        $tokens = $tokenMethod.Invoke($null, [object[]]@([uint16]$kind))
        $codes = $contract.KindTokenCodes[$kind]
        if ($tokens.Count -ne $codes.Length) { throw 'documentation-parity: Compiled token count differs.' }
        for ($index = 0; $index -lt $codes.Length; $index++) {
            if (-not [string]::Equals($tokens[$index], $contract.UncheckedTokens[[int][char]$codes[$index] - 65], [StringComparison]::Ordinal)) {
                throw 'documentation-parity: Compiled token meaning differs.'
            }
        }
        if ($kind -ge 16) {
            $bindings = $categoryMethod.Invoke($null, [object[]]@([uint16]$kind))
            Assert-PspktEvidenceDocumentRow ('| ' + $kind + ' | ' + ($bindings -join ',') + ' |')
        }
    }
    foreach ($test in $contract.RequiredPesterTests) { Assert-PspktEvidenceDocumentRow ('| ' + $test.Id + ' | ' + $test.Name + ' |') }
    foreach ($measurement in $contract.SuccessCounts.PSObject.Properties) {
        Assert-PspktEvidenceDocumentRow ('| ' + $measurement.Name + ' | ' + $measurement.Value + ' |')
    }
    if (-not $Text.Contains(($contract.SuccessResultFields -join ','))) {
        throw 'documentation-parity: Closed successful result fields differ.'
    }
}

function Assert-PspktEvidenceUncheckedClaims {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Envelope,
        [Parameter(Mandatory = $true)][byte[]]$ExpectedPayload,
        [Parameter(Mandatory = $true)][int]$ExpectedKind
    )

    $contract = Get-PspktEvidenceRuntimeContract
    if ($ExpectedKind -lt 0 -or $ExpectedKind -gt 21 -or $Envelope.Kind -ne $ExpectedKind -or
        [Convert]::ToBase64String($Envelope.CanonicalPayload) -cne [Convert]::ToBase64String($ExpectedPayload)) {
        throw 'unchecked-claims: A producer claim was changed.'
    }
    $tokens = $Envelope.UncheckedSemantics
    $codes = $contract.KindTokenCodes[$ExpectedKind]
    if ($tokens.Count -ne $codes.Length) { throw 'unchecked-claims: Unchecked token population differs.' }
    for ($index = 0; $index -lt $codes.Length; $index++) {
        $expected = $contract.UncheckedTokens[[int][char]$codes[$index] - [int][char]'A']
        if (-not [string]::Equals($tokens[$index], $expected, [StringComparison]::Ordinal)) { throw 'unchecked-claims: Unchecked meaning differs.' }
    }
}

function Assert-PspktEvidenceCorpus {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][hashtable]$FixtureBytes,
        [Parameter(Mandatory = $true)][hashtable]$FixtureRecords
    )

    $identifiers = @('operation-burn-receipt-profile1', 'local-evidence-receipt-coverage')
    for ($kind = 0; $kind -lt 22; $kind++) {
        for ($profile = 1; $profile -le 2; $profile++) {
            $identifiers += 'kind-{0:D2}-profile-{1}' -f $kind, $profile
        }
    }
    if ($FixtureBytes.Count -ne 46 -or $FixtureRecords.Count -ne 46) {
        throw 'fixture-population: Exactly 44 generated and two hand-authored fixtures are required.'
    }
    foreach ($identifier in $identifiers) {
        if (@($FixtureBytes.Keys) -cnotcontains $identifier -or @($FixtureRecords.Keys) -cnotcontains $identifier) {
            throw 'fixture-membership: A required fixture is absent.'
        }
        $bytes = $FixtureBytes[$identifier]
        $record = $FixtureRecords[$identifier]
        if ($bytes -isnot [byte[]] -or $record.id -cne $identifier -or $record.file -cne ($identifier + '.bin') -or
            ($record.length -isnot [int] -and $record.length -isnot [long]) -or $record.length -ne $bytes.Length) {
            throw 'fixture-shape: Fixture identity or byte length differs.'
        }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
        if ($record.sha256 -cne $hash) { throw 'fixture-digest: Fixture bytes differ.' }
    }
}

function Assert-PspktEvidenceCleanHost {
    [CmdletBinding(PositionalBinding = $false)]
    param([AllowEmptyCollection()][Reflection.Assembly[]]$Assemblies)

    foreach ($assembly in $Assemblies) {
        foreach ($typeName in @(
            'Pspkt.Certification.SchemaBootstrap',
            'Pspkt.Certification.SchemaCheckResult',
            'Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec',
            'Pspkt.Certification.EvidenceRuntime.DecodedEvidenceArtifactEnvelope'
        )) {
            if ($null -ne $assembly.GetType($typeName, $false)) {
                throw 'assembly-preload: An authority or runtime type is already loaded.'
            }
        }
    }
}

function Assert-PspktEvidenceBootstrapExports {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][Reflection.Assembly]$Assembly)

    $expected = [string[]]@('Pspkt.Certification.SchemaBootstrap', 'Pspkt.Certification.SchemaCheckResult')
    $actual = [string[]]@($Assembly.GetExportedTypes() | ForEach-Object { $_.FullName })
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    if ($actual.Length -ne $expected.Length) { throw 'bootstrap-public-surface: Frozen Bootstrap exports differ.' }
    for ($index = 0; $index -lt $expected.Length; $index++) {
        if (-not [string]::Equals($actual[$index], $expected[$index], [StringComparison]::Ordinal)) {
            throw 'bootstrap-public-surface: Frozen Bootstrap exports differ.'
        }
    }
}

function Assert-PspktEvidenceInvocationAvailable {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][bool]$AlreadyInvoked)

    if ($AlreadyInvoked) { throw 'invocation-repeat: A fresh host is required.' }
}

function Assert-PspktEvidenceAssemblyReference {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][Reflection.AssemblyName]$Reference,
        [Parameter(Mandatory = $true)][Reflection.AssemblyName[]]$FrameworkReferences,
        [Parameter(Mandatory = $true)][string]$BootstrapIdentity
    )

    if ([string]::Equals($Reference.FullName, $BootstrapIdentity, [StringComparison]::Ordinal)) { return }
    $token = $Reference.GetPublicKeyToken()
    if ($null -eq $token -or $token.Length -ne 8) {
        throw 'assembly-reference: Framework reference has no admitted public key token.'
    }
    $key = $Reference.Name + ':' + [BitConverter]::ToString($token).Replace('-', '').ToLowerInvariant()
    foreach ($frameworkReference in $FrameworkReferences) {
        $frameworkToken = $frameworkReference.GetPublicKeyToken()
        if ($null -eq $frameworkToken -or $frameworkToken.Length -ne 8) {
            throw 'assembly-reference: Selected framework input has no public key token.'
        }
        $frameworkKey = $frameworkReference.Name + ':' + [BitConverter]::ToString($frameworkToken).Replace('-', '').ToLowerInvariant()
        if ([string]::Equals($key, $frameworkKey, [StringComparison]::Ordinal) -and
            [string]::Equals($Reference.CultureName, $frameworkReference.CultureName, [StringComparison]::Ordinal)) { return }
    }
    throw 'assembly-reference: Reference is not an admitted framework key or Bootstrap identity.'
}

function Get-PspktEvidenceSourcePaths {
    [CmdletBinding(PositionalBinding = $false)]
    param()

    $contract = Get-PspktEvidenceRuntimeContract
    foreach ($inputRecord in $contract.AuthorityInputs) { $inputRecord.Path }
    'certification\lib\Pspkt.Certification.SchemaBootstrap.cs'
    foreach ($sourceName in $contract.RuntimeSourceNames) {
        'certification\evidence-runtime\lib\' + $sourceName
    }
    '.gitattributes'
    'certification\.gitattributes'
    'certification\lib\.gitattributes'
    'certification\schema\.gitattributes'
    'certification\evidence-ledger\.gitattributes'
    'certification\evidence-ledger\schema\.gitattributes'
    'certification\evidence-runtime\.gitattributes'
    '.github\workflows\.gitattributes'
    'certification\evidence-runtime\README.md'
    'certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1'
    'certification\evidence-runtime\validators\Invoke-PspktPhase4EvidenceRuntimeValidators.ps1'
    'certification\evidence-runtime\tests\pspkt.Phase4EvidenceRuntime.Tests.ps1'
    'certification\evidence-runtime\vectors\New-PspktPhase4EvidenceRuntimeVectors.ps1'
    'certification\evidence-runtime\vectors\generated\manifest.v1.json'
    'certification\evidence-runtime\vectors\hand-authored\manifest.v1.json'
    'certification\evidence-runtime\vectors\hand-authored\operation-burn-receipt-profile1.bin'
    'certification\evidence-runtime\vectors\hand-authored\local-evidence-receipt-coverage.bin'
    '.github\workflows\ci-evidence-runtime.yml'
    for ($kind = 0; $kind -lt 22; $kind++) {
        for ($profile = 1; $profile -le 2; $profile++) {
            'certification\evidence-runtime\vectors\generated\kind-{0:D2}-profile-{1}.bin' -f $kind, $profile
        }
    }
}

function Assert-PspktEvidenceSourcePath {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([Array]::IndexOf([string[]]@(Get-PspktEvidenceSourcePaths), $Path) -lt 0) {
        throw 'source-membership: Path is outside the closed source set.'
    }
}

function Assert-PspktEvidenceRuntimeContract {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object]$Contract
    )

    function Assert-PspktEvidenceContractValue {
        param([object]$Value, [object]$Expected)

        if ($null -eq $Value -or $null -eq $Expected -or $Value.GetType() -ne $Expected.GetType()) {
            throw 'contract-shape: Contract value type differs.'
        }
        if ($Value -is [pscustomobject]) {
            $properties = @($Value.PSObject.Properties)
            $expectedProperties = @($Expected.PSObject.Properties)
            if ($properties.Count -ne $expectedProperties.Count) {
                throw 'contract-shape: Contract fields differ.'
            }
            for ($index = 0; $index -lt $properties.Count; $index++) {
                if ($properties[$index].MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty -or
                    $properties[$index].Name -cne $expectedProperties[$index].Name) {
                    throw 'contract-shape: Contract fields differ.'
                }
                Assert-PspktEvidenceContractValue -Value $properties[$index].Value -Expected $expectedProperties[$index].Value
            }
        }
        elseif ($Value -is [array]) {
            if ($Value.Count -ne $Expected.Count) { throw 'contract-shape: Contract population differs.' }
            for ($index = 0; $index -lt $Value.Count; $index++) {
                Assert-PspktEvidenceContractValue -Value $Value[$index] -Expected $Expected[$index]
            }
        }
        elseif ($Value -is [string]) {
            if (-not [string]::Equals($Value, $Expected, [StringComparison]::Ordinal)) { throw 'contract-shape: Contract value differs.' }
        }
        elseif ($Value -is [int] -or $Value -is [long] -or $Value -is [bool]) {
            if ($Value -ne $Expected) { throw 'contract-shape: Contract value differs.' }
        }
        else {
            throw 'contract-shape: Contract contains unsupported data.'
        }
    }

    Assert-PspktEvidenceContractValue -Value $Contract -Expected (Get-PspktEvidenceRuntimeContract)
}

function Assert-PspktEvidenceAuthorityManifest {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    $expected = (Get-PspktEvidenceRuntimeContract).AuthorityInputs
    if ($Entries.Count -ne $expected.Count) {
        throw 'manifest-membership: Authority input count differs.'
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        $entry = $Entries[$index]
        if ($null -eq $entry -or $entry -isnot [pscustomobject]) {
            throw 'manifest-shape: An authority input is not plain data.'
        }
        $properties = @($entry.PSObject.Properties)
        if ($properties.Count -ne 3) {
            throw 'manifest-shape: Authority input fields differ.'
        }
        foreach ($property in $properties) {
            if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty -or
                @('Path', 'Length', 'Sha256') -cnotcontains $property.Name) {
                throw 'manifest-shape: Authority input fields differ.'
            }
        }
        if ($entry.Path -isnot [string] -or -not [string]::Equals($entry.Path, $expected[$index].Path, [StringComparison]::Ordinal)) {
            throw 'manifest-membership: Authority input path or order differs.'
        }
        if (($entry.Length -isnot [int] -and $entry.Length -isnot [long]) -or
            $entry.Length -ne $expected[$index].Length) {
            throw 'manifest-length: Authority input byte length differs.'
        }
        if ($entry.Sha256 -isnot [string] -or -not [string]::Equals($entry.Sha256, $expected[$index].Sha256, [StringComparison]::Ordinal)) {
            throw 'manifest-digest: Authority input digest differs.'
        }
    }
}
