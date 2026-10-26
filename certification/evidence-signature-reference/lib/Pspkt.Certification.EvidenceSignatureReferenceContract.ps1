Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktSignatureReferenceSubordinatePins {
    $text=@'
BytePolicyInputs|certification\evidence-signature-reference\.gitattributes|716|d2374eb6aa284439f103b0edb236e54f4153171d011e33e7180de4b6a887d377
DocumentationInputs|certification\evidence-signature-reference\README.md|19421|af16a3bde52f8fa7958612ad863ec6a73e30aa098ead038cc29bc261946c5817
SchemaInputs|certification\evidence-signature-reference\schema\evidence-key-binding-snapshot-schema.v1.json|1362|039bbf800b8e6ceb934838e5ba7d5913fe3fecee4c7a81c46dedf5465212f659
SchemaInputs|certification\evidence-signature-reference\schema\evidence-signature-reference-policy.v1.json|5504|06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17
SchemaInputs|certification\evidence-signature-reference\schema\evidence-signature-reference-receipt-schema.v1.json|4716|8266dc00ec7680af7d38d81ec1474271c913fe662a06f6f7ffd10fe977ce732e
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceSetChecker.cs|8660|ba581e652c1d60bdc9830180f33bd709221d0ba6706520821bc59af6a5f630e4
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceKeyBindingSnapshot.cs|1768|8b8db5416b8108caf765cd359d35672bf069976e1345a07766a7c13c3a46a41b
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceSetAssessment.cs|1547|e3e92731490f236401928e1d4f5a65315def9a7482be5f5574e659441f31fc19
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceArtifactVerification.cs|1750|d2dedcea7acc3b69c3bcb06004f670bad3367d611f4eb36432ca64fef8a6329d
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceReferenceResolution.cs|1941|17ed5d829eea813dfd8715ac800dcce2716b2f7da198e8c46d48f220f873bd00
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceAuthoritySnapshot.cs|20807|477f30e96ae5119ce5dd7d56878aa2bd4c2a05211c3773a8c76af1bf0261b430
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceCanonicalJsonReader.cs|6211|31c48e20bb8e3841a3b64ecf5078162ddd64f759915d29523d594b5aa207daa5
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceJsonValue.cs|985|e492cfd6e2505183a76d06369c7f79d69367e6c054f572fbf38a5eff88d26ce1
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceKeyBindingReader.cs|6308|c1af4a9e9df94e90c18b71b68d2859dee4bff5672499edc06d1675f98c08b83e
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceKeyBinding.cs|682|6943ec33d59514ee0ef1c474b6ee9bfc867662a6b8d03fb05cad486bb92f8b4d
RuntimeSources|certification\evidence-signature-reference\lib\CanonicalRsaPublicKey.cs|1782|91078a1828e5d4135f2cceea6dcea4f7a0c6d549b33bf653881f7f1b79673d44
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceSignatureVerifier.cs|4801|9e20ae7e1b7a8c0801621eee968a788faad0d5a803aba6b6a7866cd2c35e74a1
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceReferenceResolver.cs|2828|1f371e4a2399ff6fc113b3959111c54b21cec76d4f22d1a8dbeebfc3f2ee485a
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceResolvedReference.cs|435|fba2494aad13e3ae5719d486d527eb29a9b19182d5cd926f48726bb70a260ce8
RuntimeSources|certification\evidence-signature-reference\lib\EvidencePayloadProjection.cs|5156|9ff18c4fa4365c9a602cd33174e5e1c73454d3f4b72c524a2150634eebe8f313
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceClaimSet.cs|7729|36e78045a8a9542d3b19e75ccc01fd346339d04bac798d8f2e781d3721a7d4d3
RuntimeSources|certification\evidence-signature-reference\lib\EvidenceFailure.cs|4532|6ca6369c81d3b19b2de7eae90ce92253e274b41fe1289ab6d284eca1f315e8be
ValidationCodeInputs|certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCompilation.ps1|25891|edae4e9a5c080fe3cef8b77532c4aee4c75bf1fe541e51d28e02ea18b3619634
ValidationCodeInputs|certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCi.ps1|54962|aef9bed3b7ebb8e13dbe53aa3f2470ec20b80ddef3bf0134bc7300d76783190a
ValidationCodeInputs|certification\evidence-signature-reference\validators\Invoke-PspktPhase4EvidenceSignatureReferenceValidators.ps1|5895|e30e5b27f1c1d9e2f8d97c643cfa9e71cd85ef5029fba1ce74ac5ac50e0f3437
TestSourceInputs|certification\evidence-signature-reference\tests\pspkt.Phase4EvidenceSignatureReference.Tests.ps1|113373|4ef7a699c8faabaf87d84313cebe9b9709aec4b4bccf2fb51294972f59a99397
OracleInputs|certification\evidence-signature-reference\tests\EvidenceSignatureReferenceOracle.ps1|15926|06de9302445083e0232c3f30ed3bb860e2b74832597455a7b5bd1e0056752596
Generator|certification\evidence-signature-reference\vectors\New-PspktPhase4EvidenceSignatureReferenceVectors.ps1|25623|22c7c78eecdfc0981a64bdfb1841baea30464ae61f22cd40aca863d04087beca
Fixtures|certification\evidence-signature-reference\vectors\hand-authored\contract-expectations.v1.json|18042|12583ed6cc774ac5798f7cb1cdd509756655b880de1472aa1f56bf9d54b9ea05
Fixtures|certification\evidence-signature-reference\vectors\hand-authored\emsa-templates.v1.json|1476|013749bd395260e65bffca817680514a1e7b9d4f1d419595e8ccddc72d9cbf76
Fixtures|certification\evidence-signature-reference\vectors\hand-authored\signature-preimages.v1.json|5111|9a191225d9171a4b9ced2e237e11865703925e993db511a2bc8d0e61eb70048c
Fixtures|certification\evidence-signature-reference\vectors\hand-authored\manifest.v1.json|473|748a83552aba70e7294945a2fd7a501857f75b18884fcdabdcf711e2283b5420
Fixtures|certification\evidence-signature-reference\vectors\generated\public-key-a.bin|512|e6f0e4a9c3f034862e4b9184324d6389fb1b75125caae8461b47037a3e2cf579
Fixtures|certification\evidence-signature-reference\vectors\generated\public-key-b.bin|512|4ce73e34bcdb0adc58f5ddc81f877c365ddae4aaf7869185eb91f0d4c6c04a0d
Fixtures|certification\evidence-signature-reference\vectors\generated\public-key-c.bin|512|c2cfc5a9ae07a5a7d63b839710e0c8781bedd86c14704eb8a99c0c636712cb78
Fixtures|certification\evidence-signature-reference\vectors\generated\synthetic-key-snapshots.v1.json|33192|989d97df94bbea7ec6454a9108d8451e6889edff891f3ec60005a0da901b68bb
Fixtures|certification\evidence-signature-reference\vectors\generated\evidence-envelopes.v1.json|46922|55a593fa622d4d73e74858390ad9b9fd38d783c9b4cb25b9c131c31a81a4c4c1
Fixtures|certification\evidence-signature-reference\vectors\generated\manifest.v1.json|8486|4b5a7a1ae3a3494c2e869c8f062082e01ee4d1b97bcc5f0842b20a5ad9c1c943
BytePolicyInputs|.github\.gitattributes|163|9f0f41af85b2461b61aa484029395d7c482c25d6061dbc27aea3e3a2a62d357e
PublicationSourceInputs|.github\workflows\ci-evidence-signature-reference.yml|25328|2b7b01e23f017ea71ad89c43e652a9c4a651b3411bb0c5acdf366785d953e029
'@
    foreach($line in $text.Split([char]10)) {
        $fields=$line.TrimEnd([char]13).Split('|')
        [pscustomobject][ordered]@{Role=$fields[0];Path=$fields[1];Length=[long]$fields[2];Sha256=$fields[3]}
    }
}

function Invoke-PspktSignatureReferenceValidation {
    [CmdletBinding(PositionalBinding=$false)]
    param([string]$RepositoryRoot,[string]$WorkRoot,[string]$PesterManifestPath,[string]$CallId,[byte[]]$ContractBytes,[object]$ExecutionState)
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $source=Get-PspktSignatureReferenceSourceSnapshot -RepositoryRoot $RepositoryRoot -ContractBytes $ContractBytes
    . ([scriptblock]::Create($source.Texts['certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCompilation.ps1']))
    . ([scriptblock]::Create($source.Texts['certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCi.ps1']))
    . ([scriptblock]::Create($source.Texts['certification\evidence-signature-reference\tests\EvidenceSignatureReferenceOracle.ps1']))
    Assert-PspktSignatureReferenceWorkflow $source.Texts['.github\workflows\ci-evidence-signature-reference.yml'] $source.Texts['.github\.gitattributes']
    Assert-PspktSignatureReferenceReceiptDescriptor $source.Files['certification\evidence-signature-reference\schema\evidence-signature-reference-receipt-schema.v1.json']
    Assert-PspktSignatureReferenceGeneratorIsolation $source.Texts['certification\evidence-signature-reference\vectors\New-PspktPhase4EvidenceSignatureReferenceVectors.ps1']
    Assert-PspktSignatureReferenceNoPreload
    Assert-PspktSignatureReferenceRegistryAbsent
    $artifactRoot=Join-Path $WorkRoot $CallId
    if([IO.Directory]::Exists($artifactRoot) -or [IO.File]::Exists($artifactRoot)) { throw 'validation:work-root' }
    [void][IO.Directory]::CreateDirectory($artifactRoot)
    $ownedTestRoot=Join-Path $artifactRoot 'testdrive'
    [void][IO.Directory]::CreateDirectory($ownedTestRoot)
    $previousLocation=(Get-Location).ProviderPath
    $previousDirectory=[Environment]::CurrentDirectory
    $previousEnvironment=[ordered]@{}
    foreach($name in @('TEMP','TMP','PSModuleAnalysisCachePath')) { $previousEnvironment[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
    $context=$null;$primary=$null;$cleanupComplete=$true;$measurements=$null
    $ExecutionState.CleanupComplete=$false
    try {
        [Environment]::SetEnvironmentVariable('TEMP',$ownedTestRoot,'Process')
        [Environment]::SetEnvironmentVariable('TMP',$ownedTestRoot,'Process')
        [Environment]::SetEnvironmentVariable('PSModuleAnalysisCachePath',(Join-Path $ownedTestRoot 'module-analysis'),'Process')
        Set-Location -LiteralPath $artifactRoot
        [Environment]::CurrentDirectory=$artifactRoot
        $context=New-PspktSignatureReferenceCompilerContext -ArtifactRoot $artifactRoot -CallId $CallId
        $manifestPath=Get-PspktSignatureReferencePesterManifestPath $PesterManifestPath
        $pesterModule=Import-PspktSignatureReferencePester $manifestPath
        $bootstrapPath='certification\lib\Pspkt.Certification.SchemaBootstrap.cs'
        $bootstrap=New-PspktSignatureReferenceAssemblyImage -Context $context -Role Bootstrap -Texts @($source.Texts[$bootstrapPath]) -Names @($bootstrapPath)
        $structuralPaths=@(Get-PspktSignatureReferenceStructuralNames | ForEach-Object {'certification\evidence-runtime\lib\'+$_})
        $structuralTexts=@($structuralPaths | ForEach-Object {$source.Texts[$_]})
        $structural=New-PspktSignatureReferenceAssemblyImage -Context $context -Role Structural -Texts $structuralTexts -Names $structuralPaths -Dependencies @($bootstrap)
        $runtimePaths=@(Get-PspktSignatureReferenceRuntimeNames | ForEach-Object {'certification\evidence-signature-reference\lib\'+$_})
        $runtimeTexts=@($runtimePaths | ForEach-Object {$source.Texts[$_]})
        $checker=New-PspktSignatureReferenceAssemblyImage -Context $context -Role Checker -Texts $runtimeTexts -Names $runtimePaths -Dependencies @($bootstrap,$structural)
        $authorityPaths=[ordered]@{Meta='certification\schema\protocol-schema-meta.v1.json';ProtocolInventory='certification\schema\protocol-inventory.v1.json';
            EvidenceSchema='certification\evidence-ledger\schema\evidence-schema.v1.json';EvidenceInventory='certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json';
            ProtocolSchema='certification\schema\protocol-schema.v1.json';TrustedControl='certification\trusted-control\schema\trusted-control-authority.v1.json';
            TrustRootsSchema='certification\trusted-control\schema\trust-roots-schema.v1.json';
            SnapshotSchema='certification\evidence-signature-reference\schema\evidence-key-binding-snapshot-schema.v1.json';
            Policy='certification\evidence-signature-reference\schema\evidence-signature-reference-policy.v1.json'}
        $authorityBytes=@{};$authorityArguments=[object[]]::new(9);$position=0
        foreach($name in $authorityPaths.Keys) {
            $authorityBytes[$name]=$source.Files[$authorityPaths[$name]]
            $authorityArguments[$position]=$authorityBytes[$name];$position++
        }
        $fixtureBytes=@{}
        foreach($name in $source.Fixtures.Fixtures.Keys) { $fixtureBytes[$name]=$source.Fixtures.Fixtures[$name] }
        $fixtureBytes['kind-00-profile-1']=$source.Files['certification\evidence-runtime\vectors\generated\kind-00-profile-1.bin']
        $expectations=$source.Fixtures.Expectations
        $publicRows=([Text.Encoding]::ASCII.GetString($fixtureBytes['eligible-three']) | ConvertFrom-Json).keys
        foreach($id in @('positive-k16-p1','positive-k16-p2','positive-k17-p1','positive-k17-p2','positive-k20-p1','positive-k20-p2')) {
            $row=$publicRows[0]
            if($id.StartsWith('positive-k20-',[StringComparison]::Ordinal)) { $row=$publicRows[2] }
            if((Get-PspktSignatureReferenceOracleSignatureReason $fixtureBytes[$id] (ConvertFrom-PspktSignatureReferenceHex $row.publicBlob)) -cne 'ok') {
                throw 'validation:oracle'
            }
        }
        $mutants=Invoke-PspktSignatureReferenceMutants -Context $context -Texts $runtimeTexts -Names $runtimePaths -Dependencies @($bootstrap,$structural) `
            -AuthorityArguments $authorityArguments -FixtureBytes $fixtureBytes -Expectations $expectations -CheckerImage $checker
        $frameworkRecords=@($context.References | ForEach-Object {[pscustomobject][ordered]@{name=$_.Name;identity=$_.Identity;length=$_.Length;sha256=$_.Sha256;path=$_.Path}})
        $compilerRecords=@($context.Compilers | ForEach-Object {[pscustomobject][ordered]@{name=$_.Name;identity=$_.Identity;length=$_.Length;sha256=$_.Sha256;path=$_.Path}})
        Write-PspktSignatureReferenceOwnedJson (Join-Path $artifactRoot 'source-records.v1.json') ([ordered]@{
            schemaId='PspktEvidenceSignatureReferenceSourceRecordsV1';schemaVersion=1;callId=$CallId;
            sourceManifestSha256=$source.ManifestSha256;sources=$source.Records;framework=$frameworkRecords;compilers=$compilerRecords})
        $testText=$source.Texts['certification\evidence-signature-reference\tests\pspkt.Phase4EvidenceSignatureReference.Tests.ps1']
        $wrapper="{`n"+$testText+"`n}"
        $testFactory=[scriptblock]::Create($wrapper)
        $testBlock=& $testFactory
        $marker='pspkt-evidence-signature-reference-validation:'+$CallId
        $records=@{RepositoryRoot=$RepositoryRoot;WorkRoot=$artifactRoot;CompilerContext=$context;RetainedTexts=$source.Texts;
            FrozenSnapshot=$source.Frozen;FixtureSnapshot=$source.Fixtures;BeforeAllCallerScopePassed=$false;PesterManifestPath=$manifestPath;
            ContainerObservation=[pscustomobject]@{ModuleBound=($null -ne $testBlock.Module -or $null -ne $ExecutionContext.SessionState.Module);
                Marker=$marker;ReferenceMatches=@();TestLength=$encoding.GetByteCount($testText);WrapperLength=$encoding.GetByteCount($wrapper);
                TestSha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $encoding.GetBytes($testText));
                WrapperSha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $encoding.GetBytes($wrapper))}}
        $testData=@{BootstrapAssembly=$bootstrap.Assembly;StructuralAssembly=$structural.Assembly;CheckerAssembly=$checker.Assembly;
            AuthorityBytesById=$authorityBytes;FixtureBytesById=$fixtureBytes;ManifestRecordsByRole=$records;
            CompileCensus=@($context.Images.ToArray());MutantBuilds=@($mutants);ArtifactRoot=$artifactRoot;CallerScopeMarker=$marker}
        $records.ExpectedData=$testData
        $container=New-PesterContainer -ScriptBlock $testBlock -Data $testData
        $configuration=New-PspktSignatureReferencePesterConfiguration $container
        $records.Configuration=$configuration;$records.Container=$container
        Assert-PspktSignatureReferencePesterConfiguration $configuration $container
        $captured=@(Invoke-Pester -Configuration $configuration 2>$null 3>$null 4>$null 5>$null 6>$null)
        if($captured.Count -ne 1) { throw 'validation:pester-result' }
        $pester=$captured[0]
        $requiredIds=@(Get-PspktSignatureReferenceCaseIds)
        if(@($pester.Tests).Count -ne 48 -or $pester.Result -cne 'Passed' -or -not $records.BeforeAllCallerScopePassed) {
            throw 'validation:pester-result'
        }
        for($index=0;$index -lt 48;$index++) {
            if($pester.Tests[$index].ExpandedName -cne $requiredIds[$index] -or
                $pester.Tests[$index].ExpandedPath -cne ('Evidence signature reference conformance.'+$requiredIds[$index])) {
                throw 'validation:pester-result'
            }
        }
        Assert-PspktSignatureReferenceContainerObservation $records.ContainerObservation
        Assert-PspktSignatureReferencePesterConfiguration $configuration $container
        $compiler='Roslyn';$loadContext='Default'
        if($context.Edition -ceq 'Desktop') { $compiler='CodeDom';$loadContext='LoadFrom' }
        $compilationRecords=@();$loadRecords=@()
        foreach($image in $context.Images) {
            $dependencies=@()
            if($image.Role -ceq 'Structural') { $dependencies=@($bootstrap) }
            elseif($image.Role -cne 'Bootstrap') { $dependencies=@($bootstrap,$structural) }
            Assert-PspktSignatureReferenceAssemblyCustody -Context $context -Image $image -Dependencies $dependencies
            $compilationRecords+=[pscustomobject][ordered]@{role=$image.Role;imageName=$image.Name;imageLength=$image.Length;imageSha256=$image.Sha256;
                sourceCount=$image.SourceCount;sourceSetSha256=$image.SourceSetSha256;referenceSetSha256=$image.ReferenceSetSha256;
                language='CSharp5';compiler=$compiler}
            $loadRecords+=[pscustomobject][ordered]@{role=$image.Role;imageSha256=$image.Sha256;context=$loadContext;initialized=[bool]$image.Initialized}
        }
        $mutantResults=@($mutants | ForEach-Object {$_.Result})
        $counts=[pscustomobject][ordered]@{compilationCount=$compilationRecords.Count;loadCount=$loadRecords.Count;
            initializedMutantKillCount=@($mutantResults | Where-Object {$_.initialized -and $_.oracleKilled}).Count;
            containerCount=@($pester.Containers).Count;totalCount=$pester.TotalCount;
            selectedCount=@($pester.Tests | Where-Object {$_.ShouldRun}).Count;
            executedCount=@($pester.Tests | Where-Object {$_.Executed}).Count;passedCount=$pester.PassedCount;failedCount=$pester.FailedCount;
            skippedCount=$pester.SkippedCount;notRunCount=$pester.NotRunCount;failedBlocksCount=$pester.FailedBlocksCount;failedContainersCount=$pester.FailedContainersCount}
        $actualIds=@($pester.Tests | ForEach-Object {$_.ExpandedName})
        $sourceExpectations=Get-PspktSignatureReferenceExpectedSourceSets $source
        $referenceExpectations=@(
            (Get-PspktSignatureReferenceReferenceSetHash @($context.References)),
            (Get-PspktSignatureReferenceReferenceSetHash (@($context.References)+@($bootstrap))))
        $checkerReferences=Get-PspktSignatureReferenceReferenceSetHash (@($context.References)+@($bootstrap,$structural))
        for($index=0;$index -lt 6;$index++) { $referenceExpectations+=$checkerReferences }
        $expected=[pscustomobject]@{callId=$CallId;hostEdition=$PSVersionTable.PSEdition;hostVersion=$PSVersionTable.PSVersion.ToString();
            sourceManifestSha256=$source.ManifestSha256;fixtureManifestSha256='4b5a7a1ae3a3494c2e869c8f062082e01ee4d1b97bcc5f0842b20a5ad9c1c943';
            frameworkManifestSha256=$context.FrameworkManifestSha256;policySha256='06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17';
            SourceSets=$sourceExpectations.SourceSets;ReferenceSets=$referenceExpectations;
            ImageHashes=@($context.Images | ForEach-Object {Get-PspktSignatureReferenceBytesDigest -Bytes $_.Bytes});
            TransformHashes=$sourceExpectations.TransformHashes;Mutants=$expectations.mutants}
        $measurements=[ordered]@{schemaId='PspktEvidenceSignatureReferenceInvocationRecordsV1';schemaVersion=1;callId=$CallId;
            compilationRecords=$compilationRecords;loadRecords=$loadRecords;mutantResults=$mutantResults;counts=$counts;testIds=$actualIds;
            callerScope=$records.ContainerObservation}
    }
    catch {
        $primary='validation:unexpected'
        if($_.Exception.Message -cin @(Get-PspktSignatureReferenceValidatorReasons)) { $primary=$_.Exception.Message }
    }
    finally {
        if($null -ne $context) {
            try { Close-PspktSignatureReferenceCompilerContext $context } catch { $cleanupComplete=$false }
        }
        foreach($name in $previousEnvironment.Keys) {
            try {
                $value=$previousEnvironment[$name]
                if($null -eq $value) { $value=[NullString]::Value }
                [Environment]::SetEnvironmentVariable($name,$value,'Process')
            }
            catch { $cleanupComplete=$false }
        }
        try { Set-Location -LiteralPath $previousLocation } catch { $cleanupComplete=$false }
        try { [Environment]::CurrentDirectory=$previousDirectory } catch { $cleanupComplete=$false }
        try { Remove-PspktSignatureReferenceOwnedDirectory -Path $ownedTestRoot -AllowedRoot $ownedTestRoot } catch { $cleanupComplete=$false }
        try { Assert-PspktSignatureReferenceRegistryAbsent } catch { $cleanupComplete=$false }
        foreach($name in $previousEnvironment.Keys) {
            if(-not [string]::Equals([Environment]::GetEnvironmentVariable($name,'Process'),$previousEnvironment[$name],[StringComparison]::Ordinal)) {
                $cleanupComplete=$false
            }
        }
        if(-not [string]::Equals((Get-Location).ProviderPath,$previousLocation,[StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([Environment]::CurrentDirectory,$previousDirectory,[StringComparison]::OrdinalIgnoreCase)) { $cleanupComplete=$false }
        if($null -ne $context) {
            foreach($reference in @($context.References)+@($context.Compilers)) { if($reference.Handle.CanRead){$cleanupComplete=$false} }
            foreach($role in @('Bootstrap','Structural','Checker','M1','M2','M3','M4','M5')) {
                if([IO.Directory]::Exists((Join-Path $artifactRoot ('compiler-'+$role)))) { $cleanupComplete=$false }
            }
        }
        try {
            $declared=@('source-records.v1.json','validation-records.v1.json')
            foreach($role in @('Bootstrap','Structural','Checker','M1','M2','M3','M4','M5')) {
                $declared+='images\PspktEvidenceSignatureReference_'+$CallId+'_'+$role+'.dll'
            }
            foreach($entry in @(Get-PspktSignatureReferenceOwnedEntries -Path $artifactRoot -Root $artifactRoot)) {
                if(($entry.Directory -and $entry.RelativePath -cne 'images') -or
                    (-not $entry.Directory -and $entry.RelativePath -cnotin $declared)) { $cleanupComplete=$false }
            }
        }
        catch { $cleanupComplete=$false }
        $ExecutionState.CleanupComplete=$cleanupComplete
    }
    if($null -ne $primary) { throw $primary }
    if(-not $cleanupComplete) { throw 'validation:cleanup' }
    Write-PspktSignatureReferenceOwnedJson (Join-Path $artifactRoot 'validation-records.v1.json') $measurements
    try { Assert-PspktSignatureReferenceOwnedArtifacts -ArtifactRoot $artifactRoot -Images $context.Images.ToArray() }
    catch { $ExecutionState.CleanupComplete=$false;throw 'validation:cleanup' }
    $result=[pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceValidationResultV1';schemaVersion=1;outcome='ValidationSucceeded';
        callId=$CallId;baseCommit='ad0bf32da25271ba7354bd1d276e56b8b34654ec';hostEdition=$PSVersionTable.PSEdition;
        hostVersion=$PSVersionTable.PSVersion.ToString();pesterVersion=$pesterModule.Version.ToString();
        sourceManifestSha256=$source.ManifestSha256;fixtureManifestSha256=$expected.fixtureManifestSha256;frameworkManifestSha256=$context.FrameworkManifestSha256;
        policySha256=$expected.policySha256;compilationRecords=$compilationRecords;loadRecords=$loadRecords;mutantResults=$mutantResults;
        counts=$counts;testIds=$actualIds;checks=@(Get-PspktSignatureReferenceCompletionChecks);cleanup=@(Get-PspktSignatureReferenceCleanupChecks)}
    $completed=Complete-PspktSignatureReferenceResult -Captured @($result) -Expected $expected
    return [pscustomobject]@{Result=$completed;Expected=$expected;ArtifactRoot=$artifactRoot}
}

function Get-PspktSignatureReferenceAdditionalPins {
    $text=@'
RuntimeAuthorityInputs|certification\schema\protocol-schema.v1.json|66838|6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4
RuntimeAuthorityInputs|certification\trusted-control\schema\trusted-control-authority.v1.json|55414|f72d4175e0a94bf9a4cb86823b7f7595df81f96af39d15aef2497d7d89f29eab
RuntimeAuthorityInputs|certification\trusted-control\schema\trust-roots-schema.v1.json|984|2f18159cc6229d23f3b7ecca0edd820b1c15bd9d2fed8ad906f63a0829717be5
BytePolicyInputs|certification\trusted-control\.gitattributes|127|02569930d8b1b2dd19e1b7397aebcaa9d7a9db74ed4aebd36f86a717262e7d4b
BytePolicyInputs|certification\trusted-control\schema\.gitattributes|123|ebf2b8bd099a5096aecb683468622d45e74ee7948e20d3750f12442a48f97d91
DocumentationInputs|certification\trusted-control\README.md|11622|e4690ae346c52e1db4d70b92181e9bfc374982d8972b21d904838b17241b3f59
DocumentationInputs|certification\evidence-ledger\README.md|23053|649059f3797b22cb0b7c832aa63d37c2d7bd8c43af186dec80aa429e5773c7f2
'@
    foreach($line in $text.Split([char]10)) {
        $fields=$line.TrimEnd([char]13).Split('|')
        [pscustomobject][ordered]@{Role=$fields[0];Path=$fields[1];Length=[long]$fields[2];Sha256=$fields[3]}
    }
}

function Read-PspktSignatureReferenceBoundedFile {
    param([string]$Path,[int]$MaximumBytes=16777216)
    if(-not [IO.File]::Exists($Path)) { throw 'validation:source-membership' }
    $current=[IO.Path]::GetFullPath($Path)
    while(-not [string]::IsNullOrEmpty($current)) {
        if([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) { throw 'validation:source-membership' }
        $parent=[IO.Directory]::GetParent($current)
        if($null -eq $parent) { break }
        $current=$parent.FullName
    }
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw 'validation:source-length' }
        $bytes=[byte[]]::new([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length) {
            $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($read -le 0) { throw 'validation:source-length' }
            $offset+=$read
        }
        return ,$bytes
    }
    finally { $stream.Dispose() }
}

function Get-PspktSignatureReferenceSourceSnapshot {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string]$RepositoryRoot,[byte[]]$ContractBytes)
    $root=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char]92)
    $contractPath='certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceContract.ps1'
    if($null -eq $ContractBytes) { $ContractBytes=Read-PspktSignatureReferenceBoundedFile (Join-Path $root $contractPath) }
    $pins=@(Get-PspktSignatureReferenceFrozenPins)+@(Get-PspktSignatureReferenceAdditionalPins)
    $newPins=@(Get-PspktSignatureReferenceSubordinatePins)
    if($pins.Count -ne 81 -or $newPins.Count -ne 40) { throw 'validation:contract' }
    $newNames=@(Get-PspktSignatureReferenceNewPaths)
    $byName=@{}
    foreach($pin in $newPins) { if($byName.ContainsKey($pin.Path)){throw 'validation:contract'};$byName[$pin.Path]=$pin }
    foreach($path in $newNames) {
        if($path -ceq $contractPath) {
            $pins+=[pscustomobject][ordered]@{Role='ContractRoot';Path=$path;Length=[long]$ContractBytes.Length;
                Sha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $ContractBytes)}
        }
        else {
            if(-not $byName.ContainsKey($path)) { throw 'validation:contract' }
            $pins+=$byName[$path]
        }
    }
    if($pins.Count -ne 122) { throw 'validation:contract' }
    $files=@{};$texts=@{};$records=@();$framing=[Text.StringBuilder]::new()
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    foreach($pin in $pins) {
        if($files.ContainsKey($pin.Path)) { throw 'validation:source-membership' }
        if($pin.Path -ceq $contractPath) { $bytes=[byte[]]$ContractBytes.Clone() }
        else {
            $absolute=Join-Path $root $pin.Path
            $bytes=Read-PspktSignatureReferenceBoundedFile $absolute ([int]$pin.Length)
            if($bytes.Length -ne $pin.Length) { throw 'validation:source-length' }
            if((Get-PspktSignatureReferenceBytesDigest -Bytes $bytes) -cne $pin.Sha256) { throw 'validation:source-pin' }
        }
        $files.Add($pin.Path,$bytes)
        if(-not $pin.Path.EndsWith('.bin',[StringComparison]::Ordinal)) {
            $text=$encoding.GetString($bytes)
            if($pin.Path -cin $newNames) {
                if($text.Contains([string][char]13) -or $text.Contains([string][char]65279)) { throw 'validation:source-policy' }
                if($pin.Path.EndsWith('.json',[StringComparison]::Ordinal) -and ($text.EndsWith("`n",[StringComparison]::Ordinal) -or
                    $text -cmatch '[^\x20-\x7e]')) { throw 'validation:source-policy' }
                if($pin.Path.EndsWith('.ps1',[StringComparison]::Ordinal)) {
                    $tokens=$null;$problems=$null
                    [void][Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$problems)
                    if($problems.Count -ne 0 -or @($tokens | Where-Object {$_.Kind -eq 'Comment'}).Count -ne 0) {
                        throw 'validation:source-policy'
                    }
                }
                if($pin.Path.EndsWith('.cs',[StringComparison]::Ordinal) -and
                    $text -match '\bunsafe\b|DllImport|RSACng|RSACryptoServiceProvider|RSAParameters|X509Certificate|ImportCspBlob|VerifyHash|VerifySignature') {
                    throw 'validation:source-policy'
                }
            }
            $texts[$pin.Path]=$text
        }
        $record=[pscustomobject][ordered]@{Role=$pin.Role;Path=$pin.Path;Length=[long]$bytes.Length;Sha256=$pin.Sha256}
        $records+=,$record
        [void]$framing.Append($pin.Role+[char]0+$pin.Path+[char]0+$bytes.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+[char]0+$pin.Sha256+"`n")
    }
    $capsule=Join-Path $root 'certification\evidence-signature-reference'
    $actual=@(Get-PspktSignatureReferenceOwnedEntries -Path $capsule -Root $capsule | Where-Object {-not $_.Directory})
    $expectedCapsule=@($newNames | Where-Object {$_.StartsWith('certification\evidence-signature-reference\',[StringComparison]::Ordinal)})
    if($actual.Count -ne 39) { throw 'validation:source-membership' }
    foreach($file in $actual) {
        if(('certification\evidence-signature-reference\'+$file.RelativePath) -cnotin $expectedCapsule) { throw 'validation:source-membership' }
    }
    $fixtureFiles=@{}
    foreach($pin in @(Get-PspktSignatureReferenceFixturePins)) {
        $fixtureFiles[$pin.Path]=$files['certification\evidence-signature-reference\'+$pin.Path]
    }
    $fixtureSnapshot=New-PspktSignatureReferenceFixtureSnapshot -Files $fixtureFiles
    $frozenFiles=@{}
    foreach($pin in @(Get-PspktSignatureReferenceFrozenPins)) { $frozenFiles[$pin.Path]=$files[$pin.Path] }
    $frozenSnapshot=[pscustomobject]@{Records=@($records[0..73]);Files=$frozenFiles}
    Assert-PspktSignatureReferenceFrozenSnapshot -Snapshot $frozenSnapshot
    return [pscustomobject]@{RepositoryRoot=$root;Records=$records;Files=$files;Texts=$texts;
        ManifestSha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $encoding.GetBytes($framing.ToString()));
        Fixtures=$fixtureSnapshot;Frozen=$frozenSnapshot}
}

function Export-PspktSignatureReferenceSourceSnapshot {
    [CmdletBinding(PositionalBinding=$false)]
    param([object]$Source,[string]$Destination)
    $destination=[IO.Path]::GetFullPath($Destination).TrimEnd([char]92)
    if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination) -or
        $destination.StartsWith($Source.RepositoryRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $Source.RepositoryRoot.StartsWith($destination+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'validation:source-export' }
    [void][IO.Directory]::CreateDirectory($destination)
    foreach($record in $Source.Records) {
        $path=Join-Path $destination $record.Path
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $bytes=$Source.Files[$record.Path];$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    if([IO.File]::Exists((Join-Path $destination '.git')) -or [IO.Directory]::Exists((Join-Path $destination '.git'))) {
        throw 'validation:source-export'
    }
    $verified=Get-PspktSignatureReferenceSourceSnapshot -RepositoryRoot $destination
    if($verified.ManifestSha256 -cne $Source.ManifestSha256 -or
        @(Get-PspktSignatureReferenceOwnedEntries -Path $destination -Root $destination | Where-Object {-not $_.Directory}).Count -ne 122) {
        throw 'validation:source-export'
    }
    return $verified
}

function Write-PspktSignatureReferenceOwnedJson {
    param([string]$Path,[object]$Value)
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $Value -Depth 16 -Compress))
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Assert-PspktSignatureReferenceCleanupObservation {
    param([object]$Observation)
    $names=@('HashesDisposed','StreamsClosed','CompilerStagingRemoved','TestDriveRemoved','TestRegistryAbsent',
        'EnvironmentRestored','LocationsRestored','LoadedImagesDeclared','NoUnownedResidue')
    if(($Observation.PSObject.Properties.Name -join '|') -cne ($names -join '|')) { throw 'validation:cleanup' }
    foreach($name in $names) {
        if($Observation.$name -isnot [bool] -or -not $Observation.$name) { throw 'validation:cleanup' }
    }
}

function Assert-PspktSignatureReferenceRegistryAbsent {
    if(@(Get-PSDrive -Name TestRegistry -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-Variable -Name TestRegistry -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-Variable -Name TestRegistry -Scope Global -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'validation:registry'
    }
}

function Get-PspktSignatureReferenceOwnedEntries {
    param([string]$Path,[string]$Root)
    if(-not [IO.Directory]::Exists($Path) -or ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'validation:cleanup'
    }
    foreach($entry in [IO.Directory]::GetFileSystemEntries($Path)) {
        $attributes=[IO.File]::GetAttributes($entry)
        if($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'validation:cleanup' }
        $relative=$entry.Substring($Root.TrimEnd([char]92).Length+1)
        $directory=($attributes -band [IO.FileAttributes]::Directory) -ne 0
        [pscustomobject]@{Path=$entry;RelativePath=$relative;Directory=$directory}
        if($directory) { Get-PspktSignatureReferenceOwnedEntries -Path $entry -Root $Root }
    }
}

function Assert-PspktSignatureReferenceOwnedArtifacts {
    [CmdletBinding(PositionalBinding=$false)]
    param([string]$ArtifactRoot,[object[]]$Images)
    if($Images.Count -ne 8) { throw 'validation:cleanup' }
    $expected=@('source-records.v1.json','validation-records.v1.json')+@($Images | ForEach-Object {'images\'+$_.Name})
    $entries=@(Get-PspktSignatureReferenceOwnedEntries -Path $ArtifactRoot -Root $ArtifactRoot)
    $files=@($entries | Where-Object {-not $_.Directory})
    if($files.Count -ne 10 -or @($entries | Where-Object {$_.Directory -and $_.RelativePath -cne 'images'}).Count -ne 0) {
        throw 'validation:cleanup'
    }
    foreach($file in $files) {
        if($file.RelativePath -cnotin $expected) { throw 'validation:cleanup' }
    }
    foreach($image in $Images) {
        $path=Join-Path $ArtifactRoot ('images\'+$image.Name)
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if($stream.Length -ne $image.Length) { throw 'validation:cleanup' }
            $bytes=[byte[]]::new([int]$stream.Length);$offset=0
            while($offset -lt $bytes.Length) {
                $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
                if($read -le 0) { throw 'validation:cleanup' }
                $offset+=$read
            }
            if((Get-PspktSignatureReferenceBytesDigest -Bytes $bytes) -cne $image.Sha256) { throw 'validation:cleanup' }
        }
        finally { $stream.Dispose() }
    }
}

function Remove-PspktSignatureReferenceOwnedDirectory {
    [CmdletBinding(PositionalBinding=$false)]
    param([string]$Path,[string]$AllowedRoot)
    $pathFull=[IO.Path]::GetFullPath($Path).TrimEnd([char]92)
    $allowedFull=[IO.Path]::GetFullPath($AllowedRoot).TrimEnd([char]92)
    if($allowedFull.Length -le 3 -or (-not [string]::Equals($pathFull,$allowedFull,[StringComparison]::OrdinalIgnoreCase) -and
        -not $pathFull.StartsWith($allowedFull+'\',[StringComparison]::OrdinalIgnoreCase))) { throw 'validation:cleanup' }
    if([IO.File]::Exists($pathFull)) { throw 'validation:cleanup' }
    if(-not [IO.Directory]::Exists($pathFull)) { return }
    if([IO.File]::GetAttributes($pathFull) -band [IO.FileAttributes]::ReparsePoint) { throw 'validation:cleanup' }
    foreach($entry in [IO.Directory]::GetFileSystemEntries($pathFull)) {
        $attributes=[IO.File]::GetAttributes($entry)
        if($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'validation:cleanup' }
        if($attributes -band [IO.FileAttributes]::Directory) {
            Remove-PspktSignatureReferenceOwnedDirectory -Path $entry -AllowedRoot $allowedFull
        }
        else { [IO.File]::Delete($entry) }
    }
    [IO.Directory]::Delete($pathFull,$false)
}

function Get-PspktSignatureReferenceNewPaths {
    $names=@'
.gitattributes
README.md
schema\evidence-key-binding-snapshot-schema.v1.json
schema\evidence-signature-reference-policy.v1.json
schema\evidence-signature-reference-receipt-schema.v1.json
lib\EvidenceSetChecker.cs
lib\EvidenceKeyBindingSnapshot.cs
lib\EvidenceSetAssessment.cs
lib\EvidenceArtifactVerification.cs
lib\EvidenceReferenceResolution.cs
lib\EvidenceAuthoritySnapshot.cs
lib\EvidenceCanonicalJsonReader.cs
lib\EvidenceJsonValue.cs
lib\EvidenceKeyBindingReader.cs
lib\EvidenceKeyBinding.cs
lib\CanonicalRsaPublicKey.cs
lib\EvidenceSignatureVerifier.cs
lib\EvidenceReferenceResolver.cs
lib\EvidenceResolvedReference.cs
lib\EvidencePayloadProjection.cs
lib\EvidenceClaimSet.cs
lib\EvidenceFailure.cs
lib\Pspkt.Certification.EvidenceSignatureReferenceContract.ps1
lib\Pspkt.Certification.EvidenceSignatureReferenceCompilation.ps1
lib\Pspkt.Certification.EvidenceSignatureReferenceCi.ps1
validators\Invoke-PspktPhase4EvidenceSignatureReferenceValidators.ps1
tests\pspkt.Phase4EvidenceSignatureReference.Tests.ps1
tests\EvidenceSignatureReferenceOracle.ps1
vectors\New-PspktPhase4EvidenceSignatureReferenceVectors.ps1
vectors\hand-authored\contract-expectations.v1.json
vectors\hand-authored\emsa-templates.v1.json
vectors\hand-authored\signature-preimages.v1.json
vectors\hand-authored\manifest.v1.json
vectors\generated\public-key-a.bin
vectors\generated\public-key-b.bin
vectors\generated\public-key-c.bin
vectors\generated\synthetic-key-snapshots.v1.json
vectors\generated\evidence-envelopes.v1.json
vectors\generated\manifest.v1.json
'@
    foreach($name in $names.Split([char]10)) { 'certification\evidence-signature-reference\'+$name.TrimEnd([char]13) }
    '.github\.gitattributes'
    '.github\workflows\ci-evidence-signature-reference.yml'
}

function Get-PspktSignatureReferencePesterManifestPath {
    param([string]$Path)
    try {
        if([string]::IsNullOrEmpty($Path) -or -not [IO.Path]::IsPathRooted($Path) -or
            [IO.Path]::GetFileName($Path) -cne 'Pester.psd1' -or -not [IO.File]::Exists($Path)) {
            throw 'validation:pester-manifest'
        }
        return [IO.Path]::GetFullPath($Path)
    }
    catch { throw 'validation:pester-manifest' }
}

function Assert-PspktSignatureReferenceExistingPester {
    param([object[]]$Modules)
    if($Modules.Count -gt 1) { throw 'validation:pester-version' }
    if($Modules.Count -eq 1 -and ($Modules[0].Version -isnot [version] -or $Modules[0].Version -ne [version]'5.3.3')) {
        throw 'validation:pester-version'
    }
}

function Assert-PspktSignatureReferenceImportedPester {
    param([object[]]$Modules,[string]$ManifestDirectory)
    if($Modules.Count -ne 1 -or $Modules[0].Name -cne 'Pester' -or $Modules[0].Version -isnot [version] -or
        $Modules[0].Version -ne [version]'5.3.3' -or
        -not [string]::Equals($Modules[0].ModuleBase,$ManifestDirectory,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'validation:pester-version'
    }
}

function Import-PspktSignatureReferencePester {
    param([string]$PesterManifestPath)
    $path=Get-PspktSignatureReferencePesterManifestPath $PesterManifestPath
    Assert-PspktSignatureReferenceExistingPester @(Get-Module Pester)
    try { $modules=@(Import-Module -Name $path -PassThru -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null) }
    catch { throw 'validation:pester-version' }
    Assert-PspktSignatureReferenceImportedPester $modules ([IO.Path]::GetDirectoryName($path))
    return $modules[0]
}

function New-PspktSignatureReferencePesterConfiguration {
    param([object]$Container)
    $configuration=[PesterConfiguration]::Default
    $configuration.Run.Path=@()
    $configuration.Run.Container=@($Container)
    $configuration.Run.PassThru=$true
    $configuration.Run.Exit=$false
    $configuration.Run.Throw=$false
    $configuration.Filter.Tag=@('Precheck')
    $configuration.Filter.ExcludeTag=@()
    $configuration.Filter.FullName=@()
    $configuration.TestDrive.Enabled=$true
    $configuration.TestRegistry.Enabled=$false
    $configuration.TestResult.Enabled=$false
    $configuration.CodeCoverage.Enabled=$false
    $configuration.Output.Verbosity='None'
    return $configuration
}

function Assert-PspktSignatureReferencePesterConfiguration {
    param([object]$Configuration,[object]$Container)
    if($Configuration.Run.Path.Value.Count -ne 0 -or $Configuration.Run.Container.Value.Count -ne 1 -or
        -not [object]::ReferenceEquals($Configuration.Run.Container.Value[0],$Container) -or
        -not $Configuration.Run.PassThru.Value -or $Configuration.Run.Exit.Value -or $Configuration.Run.Throw.Value -or
        ($Configuration.Filter.Tag.Value -join '|') -cne 'Precheck' -or $Configuration.Filter.ExcludeTag.Value.Count -ne 0 -or
        $Configuration.Filter.FullName.Value.Count -ne 0 -or -not $Configuration.TestDrive.Enabled.Value -or
        $Configuration.TestRegistry.Enabled.Value -or $Configuration.TestResult.Enabled.Value -or
        $Configuration.CodeCoverage.Enabled.Value -or $Configuration.Output.Verbosity.Value -cne 'None') {
        throw 'validation:pester-container'
    }
}

function Assert-PspktSignatureReferenceContainerObservation {
    param([object]$Observation)
    if($Observation.ModuleBound -isnot [bool] -or $Observation.ModuleBound -or
        $Observation.Marker -cnotmatch '\Apspkt-evidence-signature-reference-validation:[0-9a-f]{32}\z' -or
        $Observation.ReferenceMatches.Count -ne 10 -or @($Observation.ReferenceMatches | Where-Object {$_ -isnot [bool] -or -not $_}).Count -ne 0 -or
        $Observation.TestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $Observation.WrapperSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $Observation.TestLength -le 0 -or $Observation.WrapperLength -ne $Observation.TestLength+4) { throw 'validation:pester-container' }
}

function New-PspktSignatureReferenceChecker {
    param([Reflection.Assembly]$Assembly,[object[]]$AuthorityArguments)
    $type=$Assembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$true)
    return $type.GetMethod('CreateFromCommittedAuthorities').Invoke($null,$AuthorityArguments)
}

function New-PspktSignatureReferenceBindings {
    param([object]$Checker,[byte[]]$SnapshotBytes)
    $arguments=[object[]]::new(5)
    $arguments[0]=[byte[]]$SnapshotBytes.Clone()
    $arguments[1]=ConvertFrom-PspktSignatureReferenceHex (Get-PspktSignatureReferenceBytesDigest -Bytes $SnapshotBytes)
    $arguments[2]=[uint64]1500
    $arguments[3]=[Guid]'11111111-2222-4333-8444-555555555555'
    $arguments[4]=[byte[]](@(17)*32)
    return $Checker.GetType().GetMethod('AdmitKeyBindings').Invoke($Checker,$arguments)
}

function Get-PspktSignatureReferenceRuntimeOutcome {
    param([object]$Checker,[object]$Binding,[byte[][]]$Envelopes,[string[]]$Reasons)
    $arguments=[object[]]::new(2);$arguments[0]=$Envelopes;$arguments[1]=$Binding
    try {
        $assessment=$Checker.GetType().GetMethod('CheckSet').Invoke($Checker,$arguments)
        return [pscustomobject]@{Reason='ok';Assessment=$assessment}
    }
    catch {
        $exception=$_.Exception;$depth=0
        while(($exception -is [Reflection.TargetInvocationException] -or $exception -is [Management.Automation.MethodInvocationException]) -and
            $null -ne $exception.InnerException -and $depth -lt 8) {
            $exception=$exception.InnerException;$depth++
        }
        if($null -ne $exception.InnerException -or ($exception.GetType() -ne [IO.InvalidDataException] -and
            $exception.GetType() -ne [ArgumentException])) { throw 'validation:unexpected' }
        $literal=$exception.Message
        if($literal -cnotin $Reasons) { throw 'validation:unexpected' }
        return [pscustomobject]@{Reason=$literal;Assessment=$null}
    }
}

function Assert-PspktSignatureReferenceAssessment {
    param([object]$Assessment,[byte[][]]$Envelopes,[byte[]]$SnapshotBytes,[object]$Expectations,[string]$ExpectedSetCodes='')
    if($null -eq $Assessment -or $Assessment.Artifacts.Count -ne $Envelopes.Length) { throw 'validation:oracle' }
    $snapshot=[Text.UTF8Encoding]::new($false,$true).GetString($SnapshotBytes) | ConvertFrom-Json
    if([BitConverter]::ToString($Assessment.KeyBindings.SnapshotSha256).Replace('-','').ToLowerInvariant() -cne
        (Get-PspktSignatureReferenceBytesDigest -Bytes $SnapshotBytes) -or $Assessment.KeyBindings.EvaluationTime -ne [uint64]1500 -or
        $Assessment.KeyBindings.LedgerIdentity -ne [Guid]'11111111-2222-4333-8444-555555555555' -or
        [BitConverter]::ToString($Assessment.KeyBindings.HostInventoryPolicyDigest).Replace('-','').ToLowerInvariant() -cne ('11'*32) -or
        $Assessment.KeyBindings.KeyCount -ne $snapshot.keys.Count -or
        [BitConverter]::ToString($Assessment.PolicySha256).Replace('-','').ToLowerInvariant() -cne '06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17') {
        throw 'validation:oracle'
    }
    $packets=@()
    for($index=0;$index -lt $Envelopes.Length;$index++) {
        $bytes=$Envelopes[$index]
        $kind=[int]$bytes[6]*256+$bytes[7]
        $guid=[byte[]]$bytes[14..29]
        [Array]::Reverse($guid,0,4);[Array]::Reverse($guid,4,2);[Array]::Reverse($guid,6,2)
        $digest=[byte[]]$bytes[($bytes.Length-32)..($bytes.Length-1)]
        $fields=Get-PspktSignatureReferenceOracleFields $bytes
        $artifact=$Assessment.Artifacts[$index]
        $key=[byte[]]::new(0)
        if($kind -in @(16,17,20)) { $key=$fields[9] }
        if($artifact.InputIndex -ne $index -or $artifact.Kind -ne $kind -or $artifact.ArtifactId -ne [Guid]::new($guid) -or
            $artifact.Profile -ne $bytes[36] -or [Convert]::ToBase64String($artifact.PayloadDigest) -cne [Convert]::ToBase64String($digest) -or
            [Convert]::ToBase64String($artifact.VerifiedKeyId) -cne [Convert]::ToBase64String($key)) { throw 'validation:oracle' }
        $packets+=[pscustomobject]@{Index=$index;Kind=$kind;Digest=$digest;Fields=$fields}
    }
    $referenceIndex=0
    foreach($source in @($packets | Where-Object {$_.Kind -in @(20,21)} | Sort-Object Kind,Index)) {
        $targetKind=18
        if($source.Kind -eq 21) { $targetKind=20 }
        $referenceDigest=[Convert]::ToBase64String($source.Fields[1])
        $targets=@($packets | Where-Object {$_.Kind -eq $targetKind -and [Convert]::ToBase64String($_.Digest) -ceq $referenceDigest})
        if($targets.Count -ne 1 -or $referenceIndex -ge $Assessment.References.Count) { throw 'validation:oracle' }
        $target=$targets[0];$edge=$Assessment.References[$referenceIndex]
        $matched=@('burned-logical-operation-id-equal','burned-semantic-digest-equal')
        if($source.Kind -eq 21) { $matched=@('successor-logical-operation-id-equal') }
        if($edge.SourceInputIndex -ne $source.Index -or $edge.SourceKind -ne $source.Kind -or $edge.SourceFieldId -ne 1 -or
            [Convert]::ToBase64String($edge.ReferenceDigest) -cne $referenceDigest -or $edge.TargetInputIndex -ne $target.Index -or
            $edge.TargetKind -ne $targetKind -or $edge.SourceFieldCoveredByVerifiedSignature -ne ($source.Kind -eq 20) -or
            ($edge.MatchedAssertions -join '|') -cne ($matched -join '|')) { throw 'validation:oracle' }
        $referenceIndex++
    }
    if($Assessment.References.Count -ne $referenceIndex) { throw 'validation:oracle' }
    if([string]::IsNullOrEmpty($ExpectedSetCodes)) {
        Assert-PspktSignatureReferenceTokenTransitions -Assessment $Assessment -Expectations $Expectations
    }
    else {
        $expectedUnion=@()
        foreach($artifact in $Assessment.Artifacts) {
            $expectedUnion+=@($Expectations.kindTransitions[[int]$artifact.Kind].residualCodes.ToCharArray() |
                ForEach-Object {$Expectations.tokens[[int]$_-65]})
        }
        $normal=[pscustomobject]@{Artifacts=$Assessment.Artifacts;UncheckedSemantics=@($Expectations.tokens | Where-Object {$_ -cin $expectedUnion})}
        Assert-PspktSignatureReferenceTokenTransitions -Assessment $normal -Expectations $Expectations
        $specified=@($ExpectedSetCodes.ToCharArray() | ForEach-Object {$Expectations.tokens[[int]$_-65]})
        if(($Assessment.UncheckedSemantics -join '|') -cne ($specified -join '|')) { throw 'validation:oracle' }
    }
}

function Assert-PspktSignatureReferenceMutantResult {
    param([object]$Result,[object]$Expected)
    $properties=@('role','initialized','controlId','controlOutcome','challengeId','baseReason','mutantObservation','transformationSha256','oracleKilled')
    if(($Result.PSObject.Properties.Name -join '|') -cne ($properties -join '|') -or $Result.role -cne $Expected.role -or
        $Result.initialized -isnot [bool] -or -not $Result.initialized -or $Result.controlId -cne $Expected.controlId -or
        $Result.controlOutcome -cne 'ok') { throw 'validation:mutant-control' }
    if($Result.challengeId -cne $Expected.challengeId -or $Result.baseReason -cne $Expected.baseReason -or
        $Result.mutantObservation -cne $Expected.observation -or $Result.oracleKilled -isnot [bool] -or -not $Result.oracleKilled -or
        $Result.transformationSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'validation:mutant-observation' }
}

function New-PspktSignatureReferenceFixtureSet {
    param([hashtable]$FixtureBytes,[string[]]$Ids)
    $set=[byte[][]]::new($Ids.Length)
    for($index=0;$index -lt $Ids.Length;$index++) {
        if(-not $FixtureBytes.ContainsKey($Ids[$index])) { throw 'validation:fixture-pin' }
        $set[$index]=[byte[]]$FixtureBytes[$Ids[$index]].Clone()
    }
    return ,$set
}

function Invoke-PspktSignatureReferenceMutants {
    param([object]$Context,[string[]]$Texts,[string[]]$Names,[object[]]$Dependencies,
        [object[]]$AuthorityArguments,[hashtable]$FixtureBytes,[object]$Expectations,[object]$CheckerImage)
    $baseChecker=New-PspktSignatureReferenceChecker $CheckerImage.Assembly $AuthorityArguments
    foreach($image in @($Dependencies)+@($CheckerImage)) { $image.Initialized=$true }
    $results=[Collections.Generic.List[object]]::new()
    foreach($recipe in $Expectations.mutants) {
        $transform=Get-PspktSignatureReferenceMutantSource -Role $recipe.role -Texts $Texts -Names $Names
        $image=New-PspktSignatureReferenceAssemblyImage -Context $Context -Role $recipe.role -Texts $transform.Texts -Names $Names -Dependencies $Dependencies
        $checker=New-PspktSignatureReferenceChecker $image.Assembly $AuthorityArguments
        $snapshot=$FixtureBytes[$recipe.snapshot]
        $controlSet=New-PspktSignatureReferenceFixtureSet $FixtureBytes $recipe.control
        $binding=New-PspktSignatureReferenceBindings $checker $snapshot
        $control=Get-PspktSignatureReferenceRuntimeOutcome $checker $binding $controlSet $Expectations.runtimeReasons
        if($control.Reason -cne 'ok') { throw 'validation:mutant-control' }
        try { Assert-PspktSignatureReferenceAssessment -Assessment $control.Assessment -Envelopes $controlSet -SnapshotBytes $snapshot -Expectations $Expectations }
        catch { throw 'validation:mutant-control' }
        $image.Initialized=$true
        $challengeSnapshot=$snapshot
        if($null -ne $recipe.PSObject.Properties['challengeSnapshot']) { $challengeSnapshot=$FixtureBytes[$recipe.challengeSnapshot] }
        $challengeSet=New-PspktSignatureReferenceFixtureSet $FixtureBytes $recipe.challenge
        $baseBinding=New-PspktSignatureReferenceBindings $baseChecker $challengeSnapshot
        $base=Get-PspktSignatureReferenceRuntimeOutcome $baseChecker $baseBinding $challengeSet $Expectations.runtimeReasons
        if($base.Reason -cne $recipe.baseReason) { throw 'validation:mutant-observation' }
        if($base.Reason -ceq 'ok') {
            Assert-PspktSignatureReferenceAssessment -Assessment $base.Assessment -Envelopes $challengeSet -SnapshotBytes $challengeSnapshot -Expectations $Expectations
        }
        $challengeBinding=New-PspktSignatureReferenceBindings $checker $challengeSnapshot
        $challenge=Get-PspktSignatureReferenceRuntimeOutcome $checker $challengeBinding $challengeSet $Expectations.runtimeReasons
        if($challenge.Reason -cne 'ok' -or $null -eq $challenge.Assessment) { throw 'validation:mutant-observation' }
        if($recipe.role -cin @('M1','M2')) {
            $rows=([Text.Encoding]::ASCII.GetString($challengeSnapshot) | ConvertFrom-Json).keys
            $public=ConvertFrom-PspktSignatureReferenceHex $rows[0].publicBlob
            if((Get-PspktSignatureReferenceOracleSignatureReason $challengeSet[0] $public) -cne $recipe.baseReason) {
                throw 'validation:mutant-observation'
            }
            $alternatePublic=ConvertFrom-PspktSignatureReferenceHex $rows[1].publicBlob
            if($recipe.role -ceq 'M2' -and (Get-PspktSignatureReferenceOracleSignatureReason $challengeSet[0] $alternatePublic) -cne 'ok') {
                throw 'validation:mutant-observation'
            }
            Assert-PspktSignatureReferenceAssessment -Assessment $challenge.Assessment -Envelopes $challengeSet -SnapshotBytes $challengeSnapshot -Expectations $Expectations
        }
        elseif($recipe.role -ceq 'M3') {
            $rows=([Text.Encoding]::ASCII.GetString($challengeSnapshot) | ConvertFrom-Json).keys
            if($rows[0].role -cne 'RecoveryAuthority') { throw 'validation:mutant-observation' }
            Assert-PspktSignatureReferenceAssessment -Assessment $challenge.Assessment -Envelopes $challengeSet -SnapshotBytes $challengeSnapshot -Expectations $Expectations
        }
        elseif($recipe.role -ceq 'M4') {
            if($challenge.Assessment.Artifacts.Count -ne 1 -or $challenge.Assessment.Artifacts[0].Kind -ne 20 -or
                $challenge.Assessment.References.Count -ne 0) { throw 'validation:mutant-observation' }
        }
        else {
            Assert-PspktSignatureReferenceAssessment -Assessment $challenge.Assessment -Envelopes $challengeSet -SnapshotBytes $challengeSnapshot -Expectations $Expectations -ExpectedSetCodes 'ABCJST'
            $rejected=$false
            try { Assert-PspktSignatureReferenceTokenTransitions -Assessment $challenge.Assessment -Expectations $Expectations }
            catch { $rejected=$_.Exception.Message -ceq 'validation:residual-contract' }
            if(-not $rejected) { throw 'validation:mutant-observation' }
        }
        $record=[pscustomobject][ordered]@{role=$recipe.role;initialized=$true;controlId=$recipe.controlId;controlOutcome='ok';
            challengeId=$recipe.challengeId;baseReason=$base.Reason;mutantObservation=$recipe.observation;
            transformationSha256=$transform.TransformationSha256;oracleKilled=$true}
        Assert-PspktSignatureReferenceMutantResult -Result $record -Expected $recipe
        $results.Add([pscustomobject]@{Result=$record;Build=$image;OriginalSourceSetSha256=$transform.OriginalSourceSetSha256;
            ControlAssessment=$control.Assessment;ControlEnvelopes=$controlSet;ControlSnapshot=$snapshot;ChallengeAssessment=$challenge.Assessment})
    }
    return ,$results.ToArray()
}

function Get-PspktSignatureReferenceFixturePins {
    $text=@'
vectors\generated\public-key-a.bin|512|e6f0e4a9c3f034862e4b9184324d6389fb1b75125caae8461b47037a3e2cf579
vectors\generated\public-key-b.bin|512|4ce73e34bcdb0adc58f5ddc81f877c365ddae4aaf7869185eb91f0d4c6c04a0d
vectors\generated\public-key-c.bin|512|c2cfc5a9ae07a5a7d63b839710e0c8781bedd86c14704eb8a99c0c636712cb78
vectors\generated\synthetic-key-snapshots.v1.json|33192|989d97df94bbea7ec6454a9108d8451e6889edff891f3ec60005a0da901b68bb
vectors\generated\evidence-envelopes.v1.json|46922|55a593fa622d4d73e74858390ad9b9fd38d783c9b4cb25b9c131c31a81a4c4c1
vectors\generated\manifest.v1.json|8486|4b5a7a1ae3a3494c2e869c8f062082e01ee4d1b97bcc5f0842b20a5ad9c1c943
vectors\hand-authored\contract-expectations.v1.json|18042|12583ed6cc774ac5798f7cb1cdd509756655b880de1472aa1f56bf9d54b9ea05
vectors\hand-authored\emsa-templates.v1.json|1476|013749bd395260e65bffca817680514a1e7b9d4f1d419595e8ccddc72d9cbf76
vectors\hand-authored\signature-preimages.v1.json|5111|9a191225d9171a4b9ced2e237e11865703925e993db511a2bc8d0e61eb70048c
vectors\hand-authored\manifest.v1.json|473|748a83552aba70e7294945a2fd7a501857f75b18884fcdabdcf711e2283b5420
'@
    foreach($line in $text.Split([char]10)) {
        $fields=$line.TrimEnd([char]13).Split('|')
        [pscustomobject][ordered]@{Role='Fixtures';Path=$fields[0];Length=[long]$fields[1];Sha256=$fields[2]}
    }
}

function ConvertFrom-PspktSignatureReferenceHex {
    param([string]$Text)
    if([string]::IsNullOrEmpty($Text) -or $Text.Length -gt 2097152 -or $Text.Length%2 -ne 0 -or
        $Text -cnotmatch '\A[0-9a-f]+\z') { throw 'validation:fixture-pin' }
    $bytes=[byte[]]::new($Text.Length/2)
    for($index=0;$index -lt $bytes.Length;$index++) { $bytes[$index]=[Convert]::ToByte($Text.Substring($index*2,2),16) }
    return ,$bytes
}

function Assert-PspktSignatureReferencePublicBytes {
    param([byte[]]$Bytes)
    if($null -eq $Bytes -or $Bytes.Length -gt 1048576) { throw 'validation:fixture-pin' }
    $text=[Text.Encoding]::ASCII.GetString($Bytes)
    if($text.Contains('-----BEGIN ') -or $text.Contains('-----END ') -or $text.Contains('RSA2') -or
        $text -match '(?i)0x(?:32415352|33415352)|"(?:DP|DQ|InverseQ)"\s*:|<(?:DP|DQ|InverseQ)>') {
        throw 'validation:fixture-pin'
    }
    if($Bytes.Length -ge 8) {
        $header=[BitConverter]::ToString($Bytes,0,8)
        if($header -ceq '52-53-41-32-00-0C-00-00' -or $header -ceq '52-53-41-33-00-0C-00-00') {
            throw 'validation:fixture-pin'
        }
    }
}

function Get-PspktSignatureReferenceFixtureSnapshot {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string]$RepositoryRoot)
    $files=@{}
    $root=Join-Path $RepositoryRoot 'certification\evidence-signature-reference'
    try {
        foreach($pin in @(Get-PspktSignatureReferenceFixturePins)) {
            $files[$pin.Path]=Read-PspktSignatureReferencePinnedFile -RepositoryRoot $root -Pin $pin
        }
    }
    catch { throw 'validation:fixture-pin' }
    return (New-PspktSignatureReferenceFixtureSnapshot -Files $files)
}

function New-PspktSignatureReferenceFixtureSnapshot {
    param([hashtable]$Files)
    $fixtures=@{}
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    foreach($bundleName in @('synthetic-key-snapshots.v1.json','evidence-envelopes.v1.json')) {
        $bundle=$encoding.GetString($Files['vectors\generated\'+$bundleName]) | ConvertFrom-Json
        foreach($item in $bundle.items) {
            if($fixtures.ContainsKey($item.id)) { throw 'validation:fixture-pin' }
            $fixtures[$item.id]=ConvertFrom-PspktSignatureReferenceHex $item.bytesHex
        }
    }
    $expectations=$encoding.GetString($Files['vectors\hand-authored\contract-expectations.v1.json']) | ConvertFrom-Json
    $snapshot=[pscustomobject]@{Files=$Files;Fixtures=$fixtures;Expectations=$expectations}
    Assert-PspktSignatureReferenceFixtureSnapshot $snapshot
    return $snapshot
}

function Assert-PspktSignatureReferenceFixtureSnapshot {
    param([object]$Snapshot)
    $pins=@(Get-PspktSignatureReferenceFixturePins)
    if($Snapshot.Files.Count -ne 10 -or $Snapshot.Fixtures.Count -ne 42) { throw 'validation:fixture-pin' }
    foreach($pin in $pins) {
        if(-not $Snapshot.Files.ContainsKey($pin.Path)) { throw 'validation:fixture-pin' }
        $bytes=$Snapshot.Files[$pin.Path]
        if($bytes -isnot [byte[]] -or $bytes.Length -ne $pin.Length -or
            (Get-PspktSignatureReferenceBytesDigest -Bytes $bytes) -cne $pin.Sha256) { throw 'validation:fixture-pin' }
        if($pin.Path.StartsWith('vectors\generated\',[StringComparison]::Ordinal)) { Assert-PspktSignatureReferencePublicBytes $bytes }
    }
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $manifest=$encoding.GetString($Snapshot.Files['vectors\generated\manifest.v1.json']) | ConvertFrom-Json
    $expected=$encoding.GetString($Snapshot.Files['vectors\hand-authored\contract-expectations.v1.json']) | ConvertFrom-Json
    if($manifest.schemaId -cne 'PspktEvidenceSignatureReferenceVectorsV1' -or $manifest.schemaVersion -ne 1 -or
        $manifest.syntheticNonEnrolled -isnot [bool] -or -not $manifest.syntheticNonEnrolled -or
        $manifest.files.Count -ne 5 -or $manifest.fixtures.Count -ne 42 -or $expected.fixtures.Count -ne 42) {
        throw 'validation:fixture-pin'
    }
    for($index=0;$index -lt 5;$index++) {
        $record=$manifest.files[$index];$pin=$pins[$index]
        if(('vectors\generated\'+$record.path) -cne $pin.Path -or $record.length -ne $pin.Length -or $record.sha256 -cne $pin.Sha256) {
            throw 'validation:fixture-pin'
        }
    }
    $allIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($bundleName in @('synthetic-key-snapshots.v1.json','evidence-envelopes.v1.json')) {
        $bytes=$Snapshot.Files['vectors\generated\'+$bundleName]
        if($bytes.Length -gt 524288) { throw 'validation:fixture-pin' }
        $bundle=$encoding.GetString($bytes) | ConvertFrom-Json
        $isSnapshot=$bundleName -ceq 'synthetic-key-snapshots.v1.json'
        $expectedCount=37
        $schemaId='PspktEvidenceSignatureReferenceEnvelopeFixturesV1'
        if($isSnapshot) { $expectedCount=5;$schemaId='PspktEvidenceSignatureReferenceSnapshotFixturesV1' }
        if($bundle.schemaId -cne $schemaId -or $bundle.schemaVersion -ne 1 -or $bundle.syntheticNonEnrolled -isnot [bool] -or
            -not $bundle.syntheticNonEnrolled -or $bundle.items.Count -ne $expectedCount) { throw 'validation:fixture-pin' }
        foreach($item in $bundle.items) {
            if($item.id -isnot [string] -or $item.id.Length -gt 48 -or -not $allIds.Add($item.id)) { throw 'validation:fixture-pin' }
            $decoded=ConvertFrom-PspktSignatureReferenceHex $item.bytesHex
            Assert-PspktSignatureReferencePublicBytes $decoded
            if($isSnapshot) {
                $keys=($encoding.GetString($decoded) | ConvertFrom-Json).keys
                foreach($key in $keys) { Assert-PspktSignatureReferencePublicBytes (ConvertFrom-PspktSignatureReferenceHex $key.publicBlob) }
            }
        }
    }
    for($index=0;$index -lt 42;$index++) {
        $record=$manifest.fixtures[$index]
        $oracle=$expected.fixtures[$index]
        if($record.id -cne $oracle.id -or $record.expectedReason -cne $oracle.expectedReason -or -not $Snapshot.Fixtures.ContainsKey($record.id)) {
            throw 'validation:fixture-pin'
        }
        $bytes=$Snapshot.Fixtures[$record.id]
        if($bytes.Length -ne $record.length -or (Get-PspktSignatureReferenceBytesDigest -Bytes $bytes) -cne $record.sha256) {
            throw 'validation:fixture-pin'
        }
    }
    $hand=$encoding.GetString($Snapshot.Files['vectors\hand-authored\manifest.v1.json']) | ConvertFrom-Json
    if($hand.schemaId -cne 'PspktEvidenceSignatureReferenceHandAuthoredV1' -or $hand.schemaVersion -ne 1 -or $hand.files.Count -ne 3) {
        throw 'validation:fixture-pin'
    }
    for($index=0;$index -lt 3;$index++) {
        $record=$hand.files[$index];$pin=$pins[$index+6]
        if(('vectors\hand-authored\'+$record.path) -cne $pin.Path -or $record.length -ne $pin.Length -or $record.sha256 -cne $pin.Sha256) {
            throw 'validation:fixture-pin'
        }
    }
}

function Assert-PspktSignatureReferenceGeneratorIsolation {
    param([string]$Source)
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count -ne 0 -or ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') -cne 'RepositoryRoot|OutputRoot') {
        throw 'validation:generator-isolation'
    }
    foreach($required in @('NONDETERMINISTIC, TEST-ONLY, NOT AN ENROLLMENT TOOL','RSACng','IsEphemeral','ExportParameters($true)',
        'privateParameters','[Array]::Clear','provider.Dispose()','GetFileSystemEntries','Assert-PublicBytes','4096','3071','3072')) {
        if(-not $Source.Contains($required)) { throw 'validation:generator-isolation' }
    }
    if($Source -match 'hand-authored|EvidenceSetChecker|EvidenceArtifactEnvelopeCodec|Add-Type|Import-Module|Invoke-Pester|ReadAllBytes|ReadAllText|PersistKeyInCsp|ToXmlString|ExportCspBlob|CngKey\.Create') {
        throw 'validation:generator-isolation'
    }
    $commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
    foreach($command in $commands) {
        if($command.GetCommandName() -in @('Set-Content','Add-Content','Out-File','Export-Clixml','Export-Csv','Get-Content')) {
            throw 'validation:generator-isolation'
        }
    }
}

function Get-PspktSignatureReferenceFrozenPins {
    [CmdletBinding(PositionalBinding = $false)]
    param()
    $text = @'
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
FrozenContract|certification\evidence-runtime\lib\Pspkt.Certification.EvidenceRuntimeContract.ps1|118909|cb1c6693a7d6e1beedd2e0bfed20c6d37c20e3f4c893b44da4fa5df63e562a1d
'@
    foreach($line in $text.Split([char]10)) {
        $fields = $line.TrimEnd([char]13).Split('|')
        if($fields.Length -ne 4) { throw 'validation:contract' }
        [pscustomobject][ordered]@{
            Role = $fields[0]
            Path = $fields[1]
            Length = [long]$fields[2]
            Sha256 = $fields[3]
        }
    }
}

function Get-PspktSignatureReferenceBytesDigest {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Read-PspktSignatureReferencePinnedFile {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot,[Parameter(Mandatory = $true)][object]$Pin)
    $path = Join-Path $RepositoryRoot $Pin.Path
    if(-not [IO.File]::Exists($path)) { throw 'validation:source-membership' }
    $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -ne $Pin.Length) { throw 'validation:source-length' }
        $bytes = [byte[]]::new([int]$Pin.Length)
        $offset = 0
        while($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($read -le 0) { throw 'validation:source-length' }
            $offset += $read
        }
        if((Get-PspktSignatureReferenceBytesDigest -Bytes $bytes) -cne $Pin.Sha256) { throw 'validation:source-pin' }
        return ,$bytes
    }
    finally { $stream.Dispose() }
}

function Get-PspktSignatureReferenceFrozenSnapshot {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)
    $records = @()
    $files = @{}
    foreach($pin in @(Get-PspktSignatureReferenceFrozenPins)) {
        $bytes = Read-PspktSignatureReferencePinnedFile -RepositoryRoot $RepositoryRoot -Pin $pin
        $files.Add($pin.Path,$bytes)
        $records += [pscustomobject][ordered]@{ Role=$pin.Role; Path=$pin.Path; Length=$pin.Length; Sha256=$pin.Sha256 }
    }
    return [pscustomobject]@{ Records=$records; Files=$files }
}

function Assert-PspktSignatureReferenceFrozenSnapshot {
    [CmdletBinding(PositionalBinding = $false)]
    param([Parameter(Mandatory = $true)][object]$Snapshot)
    $pins = @(Get-PspktSignatureReferenceFrozenPins)
    if($Snapshot.Records.Count -ne $pins.Count -or $Snapshot.Files.Count -ne $pins.Count) { throw 'validation:source-membership' }
    for($index=0;$index -lt $pins.Count;$index++) {
        $pin = $pins[$index]
        $record = $Snapshot.Records[$index]
        if($record.Role -cne $pin.Role -or $record.Path -cne $pin.Path -or
            $record.Length -ne $pin.Length -or $record.Sha256 -cne $pin.Sha256) { throw 'validation:source-pin' }
        if(-not $Snapshot.Files.ContainsKey($pin.Path)) { throw 'validation:source-membership' }
        $bytes = $Snapshot.Files[$pin.Path]
        if($bytes -isnot [byte[]] -or $bytes.Length -ne $pin.Length) { throw 'validation:source-length' }
        if((Get-PspktSignatureReferenceBytesDigest -Bytes $bytes) -cne $pin.Sha256) { throw 'validation:source-pin' }
    }
}

function Assert-PspktSignatureReferenceTokenTransitions {
    param([object]$Assessment,[object]$Expectations)
    $union = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($artifact in $Assessment.Artifacts) {
        if($artifact.Kind -lt 0 -or $artifact.Kind -gt 21) { throw 'validation:residual-contract' }
        $row = $Expectations.kindTransitions[[int]$artifact.Kind]
        $tokens = @($row.residualCodes.ToCharArray() | ForEach-Object { $Expectations.tokens[[int]$_-65] })
        if(($artifact.UncheckedSemantics -join '|') -cne ($tokens -join '|')) { throw 'validation:residual-contract' }
        $claims = $Expectations.verifiedClaims.other
        if($artifact.Kind -in @(16,17)) { $claims = $Expectations.verifiedClaims.localEvidence }
        elseif($artifact.Kind -eq 20) { $claims = $Expectations.verifiedClaims.rehabilitationAuthorization }
        elseif($artifact.Kind -eq 21) { $claims = $Expectations.verifiedClaims.rehabilitationReceipt }
        if(($artifact.VerifiedClaims -join '|') -cne ($claims -join '|')) { throw 'validation:residual-contract' }
        foreach($token in $tokens) { [void]$union.Add($token) }
    }
    $ordered = @($Expectations.tokens | Where-Object { $union.Contains($_) })
    if(($Assessment.UncheckedSemantics -join '|') -cne ($ordered -join '|')) { throw 'validation:residual-contract' }
}

function Assert-PspktSignatureReferenceTrustResiduals {
    param([object[]]$Artifacts)
    foreach($artifact in $Artifacts) {
        $signed = $artifact.Kind -in @(16,17,20)
        $graph = $artifact.Kind -in @(18,20,21)
        $requirements = [ordered]@{
            'evidence-authenticity-unchecked' = $true
            'freshness-unchecked' = $true
            'caller-pinned-key-provenance-unchecked' = $signed
            'key-enrollment-unchecked' = $signed
            'caller-time-eligibility-basis-unchecked' = $signed
            'reference-uniqueness-unchecked' = $graph
            'reference-timing-unchecked' = $graph
            'ledger-state-unchecked' = $true
            'lifecycle-certification-unchecked' = $true
        }
        foreach($token in $requirements.Keys) {
            $expected = 0
            if($requirements[$token]) { $expected = 1 }
            if(@($artifact.UncheckedSemantics | Where-Object { $_ -ceq $token }).Count -ne $expected) {
                throw 'validation:residual-contract'
            }
        }
    }
}

function Assert-PspktSignatureReferenceDigestResiduals {
    param([object[]]$Artifacts)
    foreach($artifact in $Artifacts) {
        $requirements = [ordered]@{
            'subject-digest-unchecked' = ($artifact.Kind -in @(16,17))
            'copied-protocol-digests-unchecked' = ($artifact.Kind -le 15)
            'ledger-record-references-unchecked' = ($artifact.Kind -in @(18,21))
            'producer-digests-unchecked' = ($artifact.Kind -in @(18,19,20,21))
        }
        foreach($token in $requirements.Keys) {
            $expected = 0
            if($requirements[$token]) { $expected = 1 }
            if(@($artifact.UncheckedSemantics | Where-Object { $_ -ceq $token }).Count -ne $expected) {
                throw 'validation:residual-contract'
            }
        }
    }
}

function Assert-PspktSignatureReferenceOuterResiduals {
    param([object[]]$Artifacts)
    foreach($artifact in $Artifacts) {
        foreach($token in @('artifact-id-unbound','profile-authentication-unchecked')) {
            if(@($artifact.UncheckedSemantics | Where-Object { $_ -ceq $token }).Count -ne 1) {
                throw 'validation:residual-contract'
            }
        }
        $expectedProfileValue = 0
        if($artifact.Kind -in @(2,6,7,8,9,10,11,12,16,17,18,19,20,21)) { $expectedProfileValue = 1 }
        if(@($artifact.UncheckedSemantics | Where-Object { $_ -ceq 'profile-value-unbound' }).Count -ne $expectedProfileValue) {
            throw 'validation:residual-contract'
        }
    }
}

function Assert-PspktSignatureReferenceSchemaClaims {
    param([object[]]$Artifacts)
    foreach($artifact in $Artifacts) {
        $local = $artifact.Kind -eq 16 -or $artifact.Kind -eq 17
        $protocol = @($artifact.VerifiedClaims | Where-Object { $_ -ceq 'protocol-schema-bytes-bound' }).Count
        $evidence = @($artifact.VerifiedClaims | Where-Object { $_ -ceq 'evidence-schema-bytes-bound' }).Count
        $expected = 0
        if($local) { $expected = 1 }
        if($protocol -ne $expected -or $evidence -ne $expected -or
            ($local -and $artifact.UncheckedSemantics -ccontains 'schema-bindings-unchecked')) {
            throw 'validation:residual-contract'
        }
    }

}

function Assert-PspktSignatureReferenceCardinalityResiduals {
    param([object[]]$Artifacts)
    foreach($artifact in $Artifacts) {
        if($artifact.Kind -notin @(18,20,21)) { continue }
        foreach($token in @('reference-uniqueness-unchecked','reference-timing-unchecked','ledger-state-unchecked')) {
            if(@($artifact.UncheckedSemantics | Where-Object { $_ -ceq $token }).Count -ne 1) {
                throw 'validation:residual-contract'
            }
        }
    }
}
