Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Phase 4 trusted-control authority' -Tag 'Precheck' {
    BeforeAll {
        $script:repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $script:sliceRoot = Join-Path $script:repositoryRoot 'certification\trusted-control'
        $script:validatorPath = Join-Path $script:sliceRoot 'validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1'
        $script:generatorPath = Join-Path $script:sliceRoot 'vectors\New-PspktPhase4TrustedControlVectors.ps1'
        $script:contractPath = Join-Path $script:sliceRoot 'lib\Pspkt.Certification.TrustedControlContract.ps1'
        $script:authorityPath = Join-Path $script:sliceRoot 'schema\trusted-control-authority.v1.json'
        $script:inventoryPath = Join-Path $script:repositoryRoot 'certification\schema\protocol-inventory.v1.json'
        $script:authority = Get-Content -LiteralPath $script:authorityPath -Raw | ConvertFrom-Json
        $validatorText = [IO.File]::ReadAllText($script:validatorPath)
        $validatorFunctionStart = $validatorText.IndexOf('function Resolve-PspktTrustedControlPath {')
        $validatorFunctionEnd = $validatorText.IndexOf(
            "`nif (-not `$RepositoryRoot) {",$validatorFunctionStart)
        $script:r9ValidatorFunctions = $validatorText.Substring(
            $validatorFunctionStart,
            $validatorFunctionEnd - $validatorFunctionStart)
        . $script:contractPath
        $script:contract = Get-PspktTrustedControlContract
        $script:RepinTrustedControlFixture = {
            param(
                [string]$FixtureRoot,
                [string[]]$RelativePaths
            )

            $contractPath = Join-Path $FixtureRoot (
                'certification\trusted-control\lib\Pspkt.Certification.TrustedControlContract.ps1')
            $contractText = [IO.File]::ReadAllText($contractPath)
            foreach ($relativePath in $RelativePaths) {
                $hash = (Get-FileHash -LiteralPath (
                    Join-Path $FixtureRoot $relativePath.Replace('/','\')) -Algorithm SHA256).
                        Hash.ToLowerInvariant()
                $pattern = "('" + [regex]::Escape($relativePath) + "' = ')[0-9a-f]{64}(')"
                $contractText = [regex]::Replace(
                    $contractText,
                    $pattern,
                    { param($match) $match.Groups[1].Value + $hash + $match.Groups[2].Value })
            }
            [IO.File]::WriteAllText(
                $contractPath,
                $contractText,
                [Text.UTF8Encoding]::new($false,$true))
            $contractHash = (Get-FileHash -LiteralPath $contractPath -Algorithm SHA256).
                Hash.ToLowerInvariant()
            $validatorPath = Join-Path $FixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            $validatorText = [IO.File]::ReadAllText($validatorPath)
            $validatorText = [regex]::Replace(
                $validatorText,
                "ExpectedTrustedControlContractSha256 = '[0-9a-f]{64}'",
                "ExpectedTrustedControlContractSha256 = '$contractHash'")
            [IO.File]::WriteAllText(
                $validatorPath,
                $validatorText,
                [Text.UTF8Encoding]::new($false,$true))
        }
        $script:AssertR9SourceFixture = {
            param(
                [string]$Name,
                [string]$RelativePath,
                [scriptblock]$Mutate,
                [string]$ExpectedFailure
            )

            $fixtureRoot = Join-Path $TestDrive ('r9-' + $Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $sourcePath = Join-Path $fixtureRoot $RelativePath.Replace('/','\')
            $original = [IO.File]::ReadAllText($sourcePath)
            $mutated = & $Mutate $original
            if ($original -ceq $mutated) {
                throw "R9 fixture did not mutate its source: $Name"
            }
            [IO.File]::WriteAllText(
                $sourcePath,
                $mutated,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($RelativePath)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$ExpectedFailure*"
        }
        $script:NewR9MetadataImage = {
            param(
                [int]$AdditionalTable = -1,
                [uint32]$AdditionalRows = 1,
                [int]$SecondTable = -1,
                [uint32]$SecondRows = 1,
                [int]$DeclaredAdjustment = 0,
                [int]$PhysicalAdjustment = 0,
                [byte]$HeapFlags = 0
            )

            [int[]]$smallWidths = @(
                10,6,14,2,6,2,14,2,6,4,6,6,6,4,6,
                8,6,2,4,2,6,4,2,6,6,6,2,2,8,6,
                8,4,22,4,12,20,6,14,8,14,12,4,8,4,4)
            if ($smallWidths.Count -ne 45) { throw 'Metadata oracle has an invalid table count.' }
            [int[]]$stringColumns = @(
                1,2,2,0,1,0,1,0,1,0,1,0,0,0,0,
                0,0,0,0,0,1,0,0,1,0,0,1,0,1,0,
                0,0,2,0,0,2,0,0,1,2,1,0,1,0,0)
            [int[]]$guidColumns = @(
                3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
            [int[]]$blobColumns = @(
                0,0,0,0,1,0,1,0,0,0,1,1,1,1,1,
                0,0,1,0,0,0,0,0,1,0,0,0,1,0,0,
                0,0,1,0,0,2,0,0,1,0,0,0,0,1,0)
            for ($columnTable = 0; $columnTable -lt 45; $columnTable++) {
                if (($HeapFlags -band 1) -ne 0) {
                    $smallWidths[$columnTable] += 2 * $stringColumns[$columnTable]
                }
                if (($HeapFlags -band 2) -ne 0) {
                    $smallWidths[$columnTable] += 2 * $guidColumns[$columnTable]
                }
                if (($HeapFlags -band 4) -ne 0) {
                    $smallWidths[$columnTable] += 2 * $blobColumns[$columnTable]
                }
            }
            $rowCounts = [uint32[]]::new(45)
            $rowCounts[0] = 1
            $rowCounts[2] = 2
            $rowCounts[6] = 1
            if ($AdditionalTable -ge 0 -and $AdditionalTable -notin @(0,2)) {
                $rowCounts[$AdditionalTable] = $AdditionalRows
            }
            if ($SecondTable -ge 0 -and $SecondTable -notin @(0,2,6)) {
                $rowCounts[$SecondTable] = $SecondRows
            }
            foreach ($family in @(
                @{ Tables=@(0,26,35,1); Bits=2; Columns=@(1) },
                @{ Tables=@(2,1,27); Bits=2; Columns=@(2,9,20,44) },
                @{ Tables=@(2,1,26,6,27); Bits=3; Columns=@(10) },
                @{ Tables=@(4,8,23); Bits=2; Columns=@(11) },
                @{ Tables=@(6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43); Bits=5; Columns=@(12) },
                @{ Tables=@(6,10); Bits=3; Columns=@(12) },
                @{ Tables=@(4,8); Bits=1; Columns=@(13) },
                @{ Tables=@(2,6,32); Bits=2; Columns=@(14) },
                @{ Tables=@(20,23); Bits=1; Columns=@(24) },
                @{ Tables=@(6,10); Bits=1; Columns=@(25,25,43) },
                @{ Tables=@(4,6); Bits=1; Columns=@(28) },
                @{ Tables=@(38,35,39); Bits=2; Columns=@(39,40) },
                @{ Tables=@(2,6); Bits=1; Columns=@(42) }
            )) {
                foreach ($target in $family.Tables) {
                    if ($rowCounts[$target] -ge (1 -shl (16 - $family.Bits))) {
                        foreach ($column in $family.Columns) {
                            $smallWidths[$column] += 2
                        }
                        break
                    }
                }
            }
            foreach ($column in @(
                @{ Target=4; Owners=@(2,16,29) },
                @{ Target=6; Owners=@(2,24) },
                @{ Target=8; Owners=@(6) },
                @{ Target=20; Owners=@(18) },
                @{ Target=23; Owners=@(21) },
                @{ Target=26; Owners=@(28) },
                @{ Target=35; Owners=@(36,37) },
                @{ Target=42; Owners=@(44) }
            )) {
                if ($rowCounts[$column.Target] -ge 65536) {
                    foreach ($owner in $column.Owners) {
                        $smallWidths[$owner] += 2
                    }
                }
            }
            [uint64]$valid = 0
            [long]$tableExtent = 24
            for ($tableIndex = 0; $tableIndex -lt 45; $tableIndex++) {
                if ($rowCounts[$tableIndex] -ne 0 -or
                    $tableIndex -eq $AdditionalTable -or
                    $tableIndex -eq $SecondTable) {
                    $valid = $valid -bor ([uint64]1 -shl $tableIndex)
                    $tableExtent += 4
                    $tableExtent += [long]$smallWidths[$tableIndex] * $rowCounts[$tableIndex]
                }
            }
            $declared = [int]($tableExtent + $DeclaredAdjustment)
            $physical = [int]($tableExtent + $PhysicalAdjustment)
            $metadataStart = 0x500
            $tablesStart = $metadataStart + 0x200
            $bytes = [byte[]]::new($tablesStart + $physical)
            [BitConverter]::GetBytes([int]0x80).CopyTo($bytes,0x3c)
            [Text.Encoding]::ASCII.GetBytes("PE`0`0").CopyTo($bytes,0x80)
            [BitConverter]::GetBytes([uint16]1).CopyTo($bytes,0x86)
            [BitConverter]::GetBytes([uint16]0xe0).CopyTo($bytes,0x94)
            [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes,0x98)
            [BitConverter]::GetBytes([uint32]16).CopyTo($bytes,0x98 + 92)
            [BitConverter]::GetBytes([uint32]0x2100).CopyTo($bytes,0x98 + 96 + 112)
            [BitConverter]::GetBytes([uint32]0x48).CopyTo($bytes,0x98 + 96 + 116)
            [BitConverter]::GetBytes([uint32]0x200000).CopyTo($bytes,0x178 + 8)
            [BitConverter]::GetBytes([uint32]0x2000).CopyTo($bytes,0x178 + 12)
            [BitConverter]::GetBytes([uint32]0x200000).CopyTo($bytes,0x178 + 16)
            [BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes,0x178 + 20)
            [BitConverter]::GetBytes([uint32]0x2300).CopyTo($bytes,0x300 + 8)
            [BitConverter]::GetBytes([uint32](0x200 + $declared)).CopyTo($bytes,0x300 + 12)
            [BitConverter]::GetBytes([uint32]0x424a5342).CopyTo($bytes,$metadataStart)
            [BitConverter]::GetBytes([uint32]12).CopyTo($bytes,$metadataStart + 12)
            [Text.Encoding]::ASCII.GetBytes("v4.0.30319`0`0").CopyTo(
                $bytes,$metadataStart + 16)
            [BitConverter]::GetBytes([uint16]5).CopyTo($bytes,$metadataStart + 30)
            $directoryCursor = $metadataStart + 32
            foreach ($stream in @(
                @{ Name = '#Strings'; Offset = 0x100; Size = 0x20 },
                @{ Name = '#US'; Offset = 0x130; Size = 0x10 },
                @{ Name = '#GUID'; Offset = 0x140; Size = 0x10 },
                @{ Name = '#Blob'; Offset = 0x150; Size = 0x10 },
                @{ Name = '#~'; Offset = 0x200; Size = $declared }
            )) {
                [BitConverter]::GetBytes([uint32]$stream.Offset).CopyTo($bytes,$directoryCursor)
                [BitConverter]::GetBytes([uint32]$stream.Size).CopyTo($bytes,$directoryCursor + 4)
                [Text.Encoding]::ASCII.GetBytes($stream.Name).CopyTo($bytes,$directoryCursor + 8)
                $directoryCursor += 8 + [int](
                    ($stream.Name.Length + 1 + 3) -band -4)
            }
            [Text.Encoding]::ASCII.GetBytes("`0<Module>`0Probe`0").CopyTo(
                $bytes,$metadataStart + 0x100)
            $bytes[$tablesStart + 4] = 2
            $bytes[$tablesStart + 6] = $HeapFlags
            $bytes[$tablesStart + 7] = 1
            [BitConverter]::GetBytes($valid).CopyTo($bytes,$tablesStart + 8)
            $rowCursor = $tablesStart + 24
            for ($tableIndex = 0; $tableIndex -lt 45; $tableIndex++) {
                if (($valid -band ([uint64]1 -shl $tableIndex)) -ne 0) {
                    [BitConverter]::GetBytes($rowCounts[$tableIndex]).CopyTo($bytes,$rowCursor)
                    $rowCursor += 4
                }
            }
            $typeDefStart = $rowCursor + [int](
                $rowCounts[0] * $smallWidths[0] +
                $rowCounts[1] * $smallWidths[1])
            $stringWidth = if (($HeapFlags -band 1) -ne 0) { 4 } else { 2 }
            $typeDefRowWidth = $smallWidths[2]
            $moduleNameBytes = if ($stringWidth -eq 4) {
                [BitConverter]::GetBytes([uint32]1)
            } else { [BitConverter]::GetBytes([uint16]1) }
            $probeNameBytes = if ($stringWidth -eq 4) {
                [BitConverter]::GetBytes([uint32]10)
            } else { [BitConverter]::GetBytes([uint16]10) }
            $moduleNameBytes.CopyTo($bytes,$typeDefStart + 4)
            $extendsWidth = if ($rowCounts[1] -ge 16384 -or
                $rowCounts[27] -ge 16384) { 4 } else { 2 }
            $methodListOffset = 6 + (2 * $stringWidth) + $extendsWidth
            [BitConverter]::GetBytes([uint16]1).CopyTo(
                $bytes,$typeDefStart + $methodListOffset)
            $probeNameBytes.CopyTo(
                $bytes,$typeDefStart + $typeDefRowWidth + 4)
            [BitConverter]::GetBytes([uint16]1).CopyTo(
                $bytes,$typeDefStart + $typeDefRowWidth + $methodListOffset)
            return ,$bytes
        }
    }

    It 'generates the authority-declared output set and no production instances' {
        $outputRoot = Join-Path $TestDrive 'generated'
        $result = & $script:validatorPath -Mode Generate -OutputRoot $outputRoot

        $result | Should -BeExactly "TRUSTED_CONTROL_GENERATE_OK|outputs=$(@($script:authority.outputSchemas).Count)"
        $actualPaths = @(
            Get-ChildItem -LiteralPath $outputRoot -File -Recurse |
                ForEach-Object { $_.FullName.Substring($outputRoot.Length + 1).Replace('\','/') }
        )
        [Array]::Sort($actualPaths,[StringComparer]::Ordinal)
        $expectedPaths = [string[]]@($script:authority.outputSchemas.path)
        [Array]::Sort($expectedPaths,[StringComparer]::Ordinal)
        $actualPaths | Should -Be $expectedPaths
        $actualPaths | Where-Object {
            [IO.Path]::GetFileName($_) -in @(
                'trusted-control-artifact-set.v1.json',
                'supported-builds.v1.json',
                'timing-policy.v1.json',
                'trust-roots.v1.json')
        } | Should -BeNullOrEmpty
    }

    It 'compiles independent authority and verifier assemblies and validates all output formats' {
        $result = & $script:validatorPath -Mode Compile
        $tlvCount = @($script:authority.outputSchemas | Where-Object format -CEQ 'ProtocolTlv').Count
        $jsonCount = @($script:authority.outputSchemas | Where-Object format -CEQ 'JsonRegistry').Count

        $result | Should -BeExactly (
            "TRUSTED_CONTROL_COMPILE_OK|outputs=$(@($script:authority.outputSchemas).Count)" +
            "|tlv=$tlvCount|json=$jsonCount|verifyAuthorityReferences=0")
    }

    It 'validates the committed schema outputs' {
        $result = & $script:validatorPath -Mode Validate

        $result | Should -BeExactly (
            "TRUSTED_CONTROL_VALIDATE_OK|outputs=$(@($script:authority.outputSchemas).Count)" +
            "|tlv=$(@($script:authority.outputSchemas | Where-Object format -CEQ 'ProtocolTlv').Count)" +
            "|json=$(@($script:authority.outputSchemas | Where-Object format -CEQ 'JsonRegistry').Count)")
    }

    It 'rejects a real generated output mutation through the independent verifier' {
        $outputRoot = Join-Path $TestDrive 'mutated-output'
        & $script:validatorPath -Mode Generate -OutputRoot $outputRoot | Out-Null
        $targetRelativePath = @(
            $script:authority.outputSchemas |
                Where-Object schemaId -CEQ 'PspktTimingPolicySchemaV1'
        )[0].path
        $targetPath = Join-Path $outputRoot $targetRelativePath.Replace('/','\')
        $text = [IO.File]::ReadAllText($targetPath)
        [IO.File]::WriteAllText(
            $targetPath,
            $text.Replace('TIM-LT-001','XIM-LT-001'),
            [Text.UTF8Encoding]::new($false,$true))

        { & $script:validatorPath -Mode Validate -OutputRoot $outputRoot } |
            Should -Throw '*output-bytes-differ*timing-policy-schema.v1.json*'
    }

    It 'derives TLV declaration and field counts from committed outputs' {
        $tlvOutputs = @($script:authority.outputSchemas | Where-Object format -CEQ 'ProtocolTlv')
        $tlvOutputs.Count | Should -Be 3
        foreach ($output in $tlvOutputs) {
            $document = Get-Content -LiteralPath (Join-Path $script:repositoryRoot $output.path.Replace('/','\')) -Raw |
                ConvertFrom-Json
            @($document.types).Count | Should -BeGreaterThan 0
            @($document.types.typeId) | Should -Be @(1..@($document.types).Count)
        }
        $supported = Get-Content -LiteralPath (
            Join-Path $script:sliceRoot 'schema\supported-build-entry-schema.v1.json') -Raw |
                ConvertFrom-Json
        $root = @($supported.types | Where-Object name -CEQ 'SupportedBuildEntryV1')[0]
        @($root.fields.fieldId) | Should -Be @(1..41)
        $upcase = @($supported.types | Where-Object name -CEQ 'UnicodeUpcaseReferenceV1')[0]
        $upcase.fields[0].name | Should -BeExactly 'supportedBuildKey'
        $entrypoints = Get-Content -LiteralPath (
            Join-Path $script:sliceRoot 'schema\powershell-entrypoints-schema.v1.json') -Raw |
                ConvertFrom-Json
        $argumentList = @($entrypoints.types | Where-Object name -CEQ 'PowerShellArgumentList')[0]
        $sourceSiteList = @($entrypoints.types | Where-Object name -CEQ 'SourceSiteList')[0]
        $interpreterIdentity = @(
            $entrypoints.types | Where-Object name -CEQ 'HostInterpreterIdentityV1')[0]
        $argumentList.maxCount | Should -Be 2
        $sourceSiteList.maxCount | Should -Be 1
        @($interpreterIdentity.fields.name) | Should -Be @(
            'key','path','imageDigest','volumeSerial','fileId')
        @($interpreterIdentity.fields.type) | Should -Be @(
            'AsciiIdentifier','WindowsAbsolutePath','SHA-256','U64','Opaque16')
    }

    It 'enforces the maintained timing binary and counter contracts' {
        $definedRules = @($script:authority.rules.ruleId)
        foreach ($output in $script:authority.outputSchemas) {
            foreach ($rule in $output.semanticRules) {
                $definedRules | Should -Contain $rule
            }
        }

        $timing = Get-Content -LiteralPath (
            Join-Path $script:sliceRoot 'schema\timing-policy-schema.v1.json') -Raw |
                ConvertFrom-Json
        foreach ($arrayProperty in @($timing.root.properties | Where-Object type -CEQ 'Array')) {
            $arrayProperty.items.type | Should -BeExactly 'Object'
            @($arrayProperty.items.properties).Count | Should -BeGreaterThan 0
            if ($arrayProperty.PSObject.Properties.Name -ccontains 'uniqueBy') {
                @($arrayProperty.items.properties.name) | Should -Contain $arrayProperty.uniqueBy
            }
        }
        @($timing.root.properties | Where-Object name -CEQ 'deadlineRelation')[0].members |
            Should -Be @('LT')
        @($timing.root.properties | Where-Object name -CEQ 'capacityRelation')[0].members |
            Should -Be @('LE')
        $constraintProperties = @(
            @($timing.root.properties | Where-Object name -CEQ 'constraints')[0].items.properties)
        @($constraintProperties | Where-Object name -CEQ 'relation')[0].members |
            Should -Be @('LT','LE')
        @($constraintProperties | Where-Object name -CEQ 'leftRpn')[0].maxItems | Should -Be 32
        @($constraintProperties | Where-Object name -CEQ 'rightRpn')[0].maxItems | Should -Be 32
        @($timing.root.properties | Where-Object name -CEQ 'derivedWFormula')[0].const |
            Should -BeExactly (
                'consoleFenceRetirementDeadline+consoleMainReaderJoinDeadline+' +
                'terminalRestoreEpisodeDeadline+consoleAuxiliaryQuiescenceDeadline+' +
                'consoleTopologyRevalidationDeadline+finalFrameOutputDeadline+' +
                'consoleTopologyRevalidationDeadline+consoleControlCallbackDrainDeadline')

        $trust = Get-Content -LiteralPath (
            Join-Path $script:sliceRoot 'schema\trust-roots-schema.v1.json') -Raw |
                ConvertFrom-Json
        @($trust.root.properties.name) | Should -Be @(
            'schemaVersion','ledgerIdentity','keys','maximumSkewHundredNanoseconds')
        @($trust.root.properties | Where-Object name -CEQ 'keys')[0].items.properties |
            Where-Object name -CEQ 'keyId' |
            Select-Object -ExpandProperty type |
            Should -BeExactly 'Sha256Hex'

        $script:authority.encodingTables.masks.brokerProcessMask | Should -Be 0x00120400
        $script:authority.encodingTables.masks.workerAceMask | Should -Be 0x00100400
        @($script:authority.encodingTables.argv.tokens) | Should -Be @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File')
        $script:authority.encodingTables.argv.maximumUtf16CodeUnits | Should -Be 32767
        @($script:authority.provenance.sha256) | Should -Not -Contain $null
        $script:authority.encodingTables.membershipTotalMaximum | Should -Be 512
        @($script:authority.encodingTables.membershipRows.maximumCardinality | Measure-Object -Sum).Sum |
            Should -BeLessOrEqual 512
        @($script:authority.encodingTables.supportedBuildPropertyMirror).Count | Should -Be 41
        @($script:authority.encodingTables.membershipRows.role) |
            Should -Contain 'EnrolledHostRoot'
        @($script:authority.encodingTables.membershipRows.source | Select-Object -Unique) |
            Should -Be @('TrustedWorkflowRevision','EnrolledHostRoot')
        @($script:authority.encodingTables.membershipRows.path) | Where-Object {
            $_ -match '^[A-Za-z]:[\\/]'
        } | Should -BeNullOrEmpty
        $script:authority.encodingTables.membershipPathGrammar.TrustedWorkflowRevision |
            Should -BeExactly (
                'tracked selected-revision artifact under certification/ satisfying TCAST-PATH-001')
        $script:authority.encodingTables.membershipPathGrammar.PSObject.Properties.Name |
            Should -Not -Contain 'acceptedProbePaths'
        $authorityMembership = @(
            $script:authority.encodingTables.membershipRows |
                Where-Object role -CEQ 'TrustedControlAuthority')[0]
        $authorityMembership.path | Should -BeExactly (
            'certification/trusted-control/schema/trusted-control-authority.v1.json')

        $schedule = Get-Content -LiteralPath (
            Join-Path $script:repositoryRoot 'certification\schema\mandatory-tail-schedule.v1.json') -Raw |
                ConvertFrom-Json
        $expectedLifecycle = [Collections.Generic.List[string]]::new()
        $seenLifecycle = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($row in $schedule.rows) {
            $key = [string]$row.lifecycleVariant + '|' + [string]$row.state
            if ($seenLifecycle.Add($key)) { $expectedLifecycle.Add($key) }
        }
        @($script:authority.encodingTables.lifecycleSchedule.keys) |
            Should -Be $expectedLifecycle.ToArray()

        $mirror = @($script:authority.encodingTables.supportedBuildPropertyMirror)
        $mirror[31].name | Should -BeExactly 'tokenSourceIdentifier'
        $mirror[31].type | Should -BeExactly 'LUID'
        $mirror[29].name | Should -BeExactly 'directAbsent'
        $supportedRegistry = Get-Content -LiteralPath (
            Join-Path $script:sliceRoot 'schema\supported-builds-schema.v1.json') -Raw |
                ConvertFrom-Json
        $supportedProperties = @(
            @($supportedRegistry.root.properties | Where-Object name -CEQ 'entries')[0].items.properties)
        $directAbsent = @($supportedProperties | Where-Object name -CEQ 'directAbsent')[0]
        $directAbsent.max | Should -Be 255
        $directAbsent.const | Should -Be 1
        $t0 = @($supportedProperties | Where-Object name -CEQ 't0ImpersonationLevel')[0]
        $t0.max | Should -Be 255
        $t0.const | Should -Be 2
        @($supportedProperties | Where-Object name -CEQ 'brokerProcessMask')[0].const |
            Should -Be 0x00120400
        @($supportedProperties | Where-Object name -CEQ 'workerAceMask')[0].const |
            Should -Be 0x00100400

        $schemaText = Get-ChildItem -LiteralPath (Join-Path $script:sliceRoot 'schema') -Filter '*.json' -File |
            ForEach-Object { [IO.File]::ReadAllText($_.FullName) }
        ($schemaText -join '') | Should -Not -Match '"Declared"'

        $counter = Get-Content -LiteralPath (
            Join-Path $script:sliceRoot 'schema\counter-mutation-manifest-schema.v1.json') -Raw |
                ConvertFrom-Json
        @($counter.root.properties | Where-Object name -CEQ 'operation')[0].const |
            Should -BeExactly 'Increment'
        @($counter.root.properties | Where-Object name -CEQ 'delta')[0].const | Should -Be 1
        @($counter.semanticRules) | Should -Contain 'COUNTER-METRIC-DISJOINT-001'
    }

    It 'rejects BOM CR and trailing data before vector interpretation' {
        $sourceVector = Join-Path $script:sliceRoot 'vectors\synthetic\accept-baseline.json'
        $sourceBytes = [IO.File]::ReadAllBytes($sourceVector)
        $cases = @(
            @{ Name = 'bom.json'; Bytes = [byte[]](@(0xEF,0xBB,0xBF) + $sourceBytes); Reason = 'bom-forbidden' },
            @{ Name = 'cr.json'; Bytes = [Text.Encoding]::UTF8.GetBytes("`r") + $sourceBytes; Reason = 'trailing-data' },
            @{ Name = 'trailing.json'; Bytes = [byte[]]($sourceBytes + [Text.Encoding]::UTF8.GetBytes('x')); Reason = 'trailing-data' },
            @{ Name = 'whitespace.json'; Bytes = [Text.Encoding]::UTF8.GetBytes(
                '{ ' + ([Text.Encoding]::UTF8.GetString($sourceBytes)).Substring(1)); Reason = 'noncanonical-json' }
        )
        foreach ($case in $cases) {
            $path = Join-Path $TestDrive $case.Name
            [IO.File]::WriteAllBytes($path,$case.Bytes)
            { & $script:validatorPath -Mode VerifyVector -VectorPath $path } |
                Should -Throw "*$($case.Reason)*"
        }

        $solidusSource = Join-Path $script:sliceRoot (
            'vectors\synthetic\reject-trusted-artifact-path-collision.json')
        $solidusText = [IO.File]::ReadAllText($solidusSource).Replace('certification/a.json','certification\/a.json')
        $solidusPath = Join-Path $TestDrive 'escaped-solidus.json'
        [IO.File]::WriteAllText($solidusPath,$solidusText,[Text.UTF8Encoding]::new($false,$true))
        { & $script:validatorPath -Mode VerifyVector -VectorPath $solidusPath } |
            Should -Throw '*noncanonical-json*'

        $junkPath = Join-Path $TestDrive 'junk-vector.json'
        [IO.File]::WriteAllText(
            $junkPath,
            ([ordered]@{
                schemaId = 'PspktTrustedControlVerificationVectorV1'
                schemaVersion = 1
                syntheticOnly = $true
                expectedReason = 'ok'
                caseKind = 'baseline'
                input = [ordered]@{ junk = 1 }
            } | ConvertTo-Json -Compress),
            [Text.UTF8Encoding]::new($false,$true))
        { & $script:validatorPath -Mode VerifyVector -VectorPath $junkPath } |
            Should -Throw '*$.input:property-set*'
    }

    It 'pins LF worktree bytes and reports expected and actual hashes' {
        $script:contract.Sha256ByPath.Contains(
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlContract.ps1') |
                Should -BeFalse
        foreach ($relativePath in $script:contract.LfTextPathSet) {
            [IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot $relativePath.Replace('/','\'))) |
                Should -Not -Contain ([byte]13)
        }

        $fixtureRoot = Join-Path $TestDrive 'pin-fixture'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $readmePath = Join-Path $fixtureRoot 'certification\trusted-control\README.md'
        $replacementPath = Join-Path $fixtureRoot 'replacement-readme.md'
        [IO.File]::WriteAllText($replacementPath,'replacement')
        $lockedReadme = [IO.FileStream]::new(
            $readmePath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            { [IO.File]::Replace($replacementPath,$readmePath,[NullString]::Value) } |
                Should -Throw
        }
        finally {
            $lockedReadme.Dispose()
        }
        if ([IO.File]::Exists($replacementPath)) { [IO.File]::Delete($replacementPath) }
        [IO.File]::AppendAllText($readmePath,"`nmutation",[Text.UTF8Encoding]::new($false,$true))
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')

        { & $fixtureValidator -Mode Validate -RepositoryRoot $fixtureRoot -OutputRoot $fixtureRoot } |
            Should -Throw '*expected=????????????????????????????????????????????????????????????????; actual=????????????????????????????????????????????????????????????????*'
    }

    It 'treats validator bytes as the local root and rejects an independently changed contract' {
        $fixtureRoot = Join-Path $TestDrive 'contract-root-fixture'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $fixtureContractPath = Join-Path $fixtureRoot (
            'certification\trusted-control\lib\Pspkt.Certification.TrustedControlContract.ps1')
        [IO.File]::AppendAllText(
            $fixtureContractPath,
            "`n",
            [Text.UTF8Encoding]::new($false,$true))
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')

        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*contract root hash differs*'
    }

    It 'pins the semantic rule set and every output assignment independently' {
        foreach ($mutationKind in @('delete','reassign')) {
            $fixtureRoot = Join-Path $TestDrive ('semantic-' + $mutationKind)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $fixtureAuthorityPath = Join-Path $fixtureRoot (
                'certification\trusted-control\schema\trusted-control-authority.v1.json')
            $authorityText = [IO.File]::ReadAllText($fixtureAuthorityPath)
            if ($mutationKind -ceq 'delete') {
                $authorityText = $authorityText.Replace(
                    ',{"ruleId":"TRUST-EPOCH-001","definition":"Trust epoch satisfies notBefore less than notAfter"}',
                    '')
                $authorityText = $authorityText.Replace(
                    '["TC-CANON-001","TRUST-RSA-512-001","TRUST-EPOCH-001","TRUST-ROLE-001"]',
                    '["TC-CANON-001","TRUST-RSA-512-001","TRUST-ROLE-001"]')
            } else {
                $authorityText = $authorityText.Replace(
                    '["TC-CANON-001","TRUST-RSA-512-001","TRUST-EPOCH-001","TRUST-ROLE-001"]',
                    '["TC-CANON-001","TIM-LT-001","TRUST-RSA-512-001","TRUST-ROLE-001"]')
            }
            [IO.File]::WriteAllText(
                $fixtureAuthorityPath,
                $authorityText,
                [Text.UTF8Encoding]::new($false,$true))
            $fixtureContractPath = Join-Path $fixtureRoot (
                'certification\trusted-control\lib\Pspkt.Certification.TrustedControlContract.ps1')
            $contractText = [IO.File]::ReadAllText($fixtureContractPath)
            $oldAuthorityHash = $script:contract.Sha256ByPath[
                'certification/trusted-control/schema/trusted-control-authority.v1.json']
            $newAuthorityHash =
                (Get-FileHash -LiteralPath $fixtureAuthorityPath -Algorithm SHA256).Hash.ToLowerInvariant()
            [IO.File]::WriteAllText(
                $fixtureContractPath,
                $contractText.Replace($oldAuthorityHash,$newAuthorityHash),
                [Text.UTF8Encoding]::new($false,$true))
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            $contractHash =
                (Get-FileHash -LiteralPath $fixtureContractPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $validatorText = [IO.File]::ReadAllText($fixtureValidator)
            $validatorText = [regex]::Replace(
                $validatorText,
                "ExpectedTrustedControlContractSha256 = '[0-9a-f]{64}'",
                "ExpectedTrustedControlContractSha256 = '$contractHash'")
            [IO.File]::WriteAllText(
                $fixtureValidator,
                $validatorText,
                [Text.UTF8Encoding]::new($false,$true))

            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw '*semantic-rule*'
        }
    }

    It 'rejects a frozen protocol meta mutation after its pin is deliberately advanced' {
        $fixtureRoot = Join-Path $TestDrive 'meta-fixture'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $metaPath = Join-Path $fixtureRoot 'certification\schema\protocol-schema-meta.v1.json'
        $metaText = [IO.File]::ReadAllText($metaPath)
        [IO.File]::WriteAllText(
            $metaPath,
            $metaText.Replace('PspktProtocolSchemaMetaV1','QspktProtocolSchemaMetaV1'),
            [Text.UTF8Encoding]::new($false,$true))
        $newHash = (Get-FileHash -LiteralPath $metaPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $fixtureContractPath = Join-Path $fixtureRoot (
            'certification\trusted-control\lib\Pspkt.Certification.TrustedControlContract.ps1')
        $contractText = [IO.File]::ReadAllText($fixtureContractPath)
        $oldHash = $script:contract.Sha256ByPath['certification/schema/protocol-schema-meta.v1.json']
        [IO.File]::WriteAllText(
            $fixtureContractPath,
            $contractText.Replace($oldHash,$newHash),
            [Text.UTF8Encoding]::new($false,$true))
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        $fixtureContractHash = (Get-FileHash -LiteralPath $fixtureContractPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $fixtureValidatorText = [IO.File]::ReadAllText($fixtureValidator)
        $fixtureValidatorText = [regex]::Replace(
            $fixtureValidatorText,
            "ExpectedTrustedControlContractSha256 = '[0-9a-f]{64}'",
            "ExpectedTrustedControlContractSha256 = '$fixtureContractHash'")
        [IO.File]::WriteAllText(
            $fixtureValidator,
            $fixtureValidatorText,
            [Text.UTF8Encoding]::new($false,$true))

        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*meta-authority-mismatch*'

        $trustedFixtureRoot = Join-Path $TestDrive 'trusted-meta-fixture'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $trustedFixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $trustedFixtureRoot 'tests\phase4-trusted-control') -Recurse
        $trustedMetaPath = Join-Path $trustedFixtureRoot (
            'certification\trusted-control\schema\trusted-control-json-schema-meta.v1.json')
        $trustedMeta = Get-Content -LiteralPath $trustedMetaPath -Raw | ConvertFrom-Json
        $trustedMeta | Add-Member -NotePropertyName unexpected -NotePropertyValue 1
        [IO.File]::WriteAllText(
            $trustedMetaPath,
            ($trustedMeta | ConvertTo-Json -Depth 32 -Compress),
            [Text.UTF8Encoding]::new($false,$true))
        $trustedContractPath = Join-Path $trustedFixtureRoot (
            'certification\trusted-control\lib\Pspkt.Certification.TrustedControlContract.ps1')
        $trustedContractText = [IO.File]::ReadAllText($trustedContractPath)
        $oldTrustedHash = $script:contract.Sha256ByPath[
            'certification/trusted-control/schema/trusted-control-json-schema-meta.v1.json']
        $newTrustedHash = (Get-FileHash -LiteralPath $trustedMetaPath -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText(
            $trustedContractPath,
            $trustedContractText.Replace($oldTrustedHash,$newTrustedHash),
            [Text.UTF8Encoding]::new($false,$true))
        $trustedValidator = Join-Path $trustedFixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        $trustedContractHash = (Get-FileHash -LiteralPath $trustedContractPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $trustedValidatorText = [IO.File]::ReadAllText($trustedValidator)
        $trustedValidatorText = [regex]::Replace(
            $trustedValidatorText,
            "ExpectedTrustedControlContractSha256 = '[0-9a-f]{64}'",
            "ExpectedTrustedControlContractSha256 = '$trustedContractHash'")
        [IO.File]::WriteAllText(
            $trustedValidator,
            $trustedValidatorText,
            [Text.UTF8Encoding]::new($false,$true))
        { & $trustedValidator -Mode Compile -RepositoryRoot $trustedFixtureRoot } |
            Should -Throw '*property-set*'
    }

    It 'rejects unsafe roots and forbidden production filenames' {
        { & $script:validatorPath -Mode Compile -RepositoryRoot 'Q:relative' } |
            Should -Throw '*not a supported filesystem path*'

        $junctionPath = Join-Path $TestDrive 'repository-junction'
        [void](New-Item -ItemType Junction -Path $junctionPath -Target $script:repositoryRoot)
        $junctionValidator = Join-Path $junctionPath (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $junctionValidator -Mode Compile -RepositoryRoot $junctionPath } |
            Should -Throw '*reparse-point ancestor*'

        $wrongImageAssemblyRoot = Join-Path $TestDrive 'wrong-image-assembly'
        [void][IO.Directory]::CreateDirectory($wrongImageAssemblyRoot)
        $eventName = 'Local\PspktWrongImage-' + [Guid]::NewGuid().ToString('N')
        $created = $false
        $event = [Threading.EventWaitHandle]::new(
            $true,
            [Threading.EventResetMode]::ManualReset,
            $eventName,
            [ref]$created)
        try {
            {
                & $script:validatorPath -Worker -Mode TimeoutProbe `
                    -RepositoryRoot $script:repositoryRoot `
                    -AssemblyRoot $wrongImageAssemblyRoot `
                    -AdmissionEventName $eventName `
                    -ExpectedChildImageHash ('0' * 64) `
                    -ExpectedChildImageIdentity '0:00000000000000000000000000000000'
            } | Should -Throw '*child image identity differs*'
        }
        finally {
            $event.Dispose()
        }

        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $timeoutPidPath = Join-Path $TestDrive 'timeout-pids.txt'
        { & $script:validatorPath -Mode TimeoutProbe -ChildTimeoutMilliseconds 10000 `
                -TimeoutProbePidFile $timeoutPidPath } |
            Should -Throw '*10000-millisecond timeout*'
        $stopwatch.Stop()
        $stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 25
        foreach ($processId in Get-Content -LiteralPath $timeoutPidPath) {
            { Get-Process -Id ([int]$processId) -ErrorAction Stop } | Should -Throw
        }
        foreach ($invalidTimeout in @(-1,0,120001)) {
            { & $script:validatorPath -Mode TimeoutProbe -ChildTimeoutMilliseconds $invalidTimeout } |
                Should -Throw
        }

        $fixtureRoot = Join-Path $TestDrive 'forbidden-name-fixture'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $forbiddenPath = Join-Path $fixtureRoot (
            'certification\trusted-control\vectors\supported-builds.v1.json')
        [IO.File]::WriteAllBytes($forbiddenPath,[Text.Encoding]::UTF8.GetBytes('{}'))
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*forbidden production filename*'
    }

    It 'pins and verifies every real vector case' {
        $outputRoot = Join-Path $TestDrive 'vectors'
        $result = & $script:generatorPath -OutputRoot $outputRoot -SelfTest
        $manifest = Get-Content -LiteralPath (
            Join-Path $outputRoot 'certification\trusted-control\vectors\synthetic\manifest.v1.json') -Raw |
                ConvertFrom-Json

        $manifest.syntheticOnly | Should -BeTrue
        $result | Should -BeExactly "TRUSTED_CONTROL_VECTORS_OK|schemas=10|cases=$(@($manifest.cases).Count)"
        @($manifest.cases.expectedReason) | Should -Contain 'schema-meta-mismatch'
        @($manifest.cases.expectedReason) | Should -Contain 'timing-deadline-equality-expired'
        @($manifest.cases.expectedReason) | Should -Contain 'rsa-envelope-length-or-conversion-invalid'
        @($manifest.cases.expectedReason) | Should -Contain 'guid-rfc4122-bytes-invalid'
        @($manifest.cases.expectedReason) | Should -Contain 'luid-big-endian-bytes-invalid'
        @($manifest.cases.path) | Should -Contain 'accept-tcast-digest-framing-golden.json'
        @($manifest.cases.path) | Should -Contain 'accept-entrypoint-digest-framing-golden.json'
        @($manifest.cases.path) | Should -Contain 'accept-supported-build-digest-framing-golden.json'
        @($manifest.cases.path) | Should -Contain 'accept-rsa-native-411.json'
        @($manifest.cases.path) | Should -Contain 'accept-rsa-native-412.json'
        @($manifest.cases.path) | Should -Contain 'reject-timing-deadline-le-invalid.json'
        @($manifest.cases.path) | Should -Contain 'reject-rsa-native-rsa2.json'
        @($manifest.cases.path) | Should -Contain 'reject-rsa-native-2048.json'
        @($manifest.cases.path) | Should -Contain 'reject-rsa-native-prime.json'
        foreach ($requiredVector in @(
            'reject-rsa-envelope-cb-public-exp.json',
            'reject-rsa-envelope-cb-modulus.json',
            'reject-rsa-envelope-cb-prime1.json',
            'reject-rsa-envelope-cb-prime2.json',
            'reject-rsa-envelope-native-length-mismatch.json',
            'reject-rsa-envelope-native-length-rule.json',
            'reject-rsa-envelope-canonical-exponent.json',
            'reject-rsa-native-cb-modulus.json',
            'reject-rsa-native-cb-prime2.json',
            'reject-rsa-native-exponent-value.json',
            'reject-rsa-native-top-bit.json',
            'reject-rsa-native-canonical-hex.json',
            'reject-rsa-native-key-id.json',
            'reject-digest-wrong-meta-only.json',
            'reject-digest-placeholder-schema-only.json',
            'reject-digest-mismatched-schema-only.json',
            'reject-digest-tlv-framing.json',
            'reject-guid-variant-invalid.json',
            'reject-guid-version-invalid.json')) {
            @($manifest.cases.path) | Should -Contain $requiredVector
        }
        @($manifest.cases.path) | Should -Contain 'reject-timing-kind-unknown.json'
        @($manifest.cases.path) | Should -Contain 'accept-vt-raise-only.json'
        @($manifest.cases.path) | Should -Contain 'accept-membership-protocol-meta.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-outside-certification.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-malformed.json'
        @($manifest.cases.path) | Should -Contain 'accept-membership-protocol-schema.json'
        @($manifest.cases.path) | Should -Contain 'accept-membership-overlay-schedule.json'
        @($manifest.cases.path) | Should -Contain 'accept-membership-protocol-authority.json'
        @($manifest.cases.path) | Should -Contain 'accept-membership-evidence-inventory.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-trusted-authority-pending.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-fixture-unsorted.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-fixture-duplicate.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-fixture-overlap.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-fixture-invalid-path.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-tracked-only-invalid.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-pending-only-invalid.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-pending-unsorted.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-pending-duplicate.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-enrolled-present.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-enrolled-pending-missing.json'
        @($manifest.cases.path) | Should -Contain 'reject-membership-enrolled-tracked.json'
        $pendingVectorDocument = Get-Content -LiteralPath (
            Join-Path $outputRoot (
                'certification\trusted-control\vectors\synthetic\' +
                'reject-membership-trusted-authority-pending.json')) -Raw |
                    ConvertFrom-Json
        @($pendingVectorDocument.input.pendingPaths) | Should -Contain (
            'certification/trusted-control/schema/trusted-control-authority.v1.json')

        $generatedSchemaRoot = Join-Path $outputRoot 'certification\trusted-control\schema'
        $committedSchemaRoot = Join-Path $script:sliceRoot 'schema'
        [string[]]$generatedSchemaNames = @(
            Get-ChildItem -LiteralPath $generatedSchemaRoot -Filter '*.json' -File |
                Select-Object -ExpandProperty Name)
        [Array]::Sort($generatedSchemaNames,[StringComparer]::Ordinal)
        [string[]]$expectedSchemaNames = @(
            $script:contract.OutputPathSet | ForEach-Object { [IO.Path]::GetFileName($_) })
        [Array]::Sort($expectedSchemaNames,[StringComparer]::Ordinal)
        $generatedSchemaNames | Should -Be $expectedSchemaNames
        foreach ($schemaName in $generatedSchemaNames) {
            $generatedPath = Join-Path $generatedSchemaRoot $schemaName
            $committedPath = Join-Path $committedSchemaRoot $schemaName
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($generatedPath)) |
                Should -BeExactly ([Convert]::ToBase64String([IO.File]::ReadAllBytes($committedPath)))
            $relativePath = 'certification/trusted-control/schema/' + $schemaName
            (Get-FileHash -LiteralPath $committedPath -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly $script:contract.Sha256ByPath[$relativePath]
        }

        $generatedVectorRoot = Join-Path $outputRoot 'certification\trusted-control\vectors\synthetic'
        $committedVectorRoot = Join-Path $script:sliceRoot 'vectors\synthetic'
        [string[]]$generatedVectorNames = @(
            Get-ChildItem -LiteralPath $generatedVectorRoot -Filter '*.json' -File |
                Select-Object -ExpandProperty Name)
        [string[]]$committedVectorNames = @(
            Get-ChildItem -LiteralPath $committedVectorRoot -Filter '*.json' -File |
                Select-Object -ExpandProperty Name)
        [Array]::Sort($generatedVectorNames,[StringComparer]::Ordinal)
        [Array]::Sort($committedVectorNames,[StringComparer]::Ordinal)
        $generatedVectorNames | Should -Be $committedVectorNames
        foreach ($vectorName in $generatedVectorNames) {
            $generatedPath = Join-Path $generatedVectorRoot $vectorName
            $committedPath = Join-Path $committedVectorRoot $vectorName
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($generatedPath)) |
                Should -BeExactly ([Convert]::ToBase64String([IO.File]::ReadAllBytes($committedPath)))
            $relativePath = 'certification/trusted-control/vectors/synthetic/' + $vectorName
            (Get-FileHash -LiteralPath $committedPath -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly $script:contract.Sha256ByPath[$relativePath]
        }
        $committedManifestResult = & $script:validatorPath -Mode VerifyVector `
            -VectorPath (Join-Path $committedVectorRoot 'manifest.v1.json')
        $committedManifestResult |
            Should -BeExactly "TRUSTED_CONTROL_MANIFEST_OK|cases=$(@($manifest.cases).Count)"

        $customManifestRoot = Join-Path $TestDrive 'custom-manifest'
        [void][IO.Directory]::CreateDirectory($customManifestRoot)
        $customCase = @($manifest.cases)[0]
        Copy-Item -LiteralPath (Join-Path $generatedVectorRoot $customCase.path) `
            -Destination (Join-Path $customManifestRoot $customCase.path)
        $customManifestPath = Join-Path $customManifestRoot 'manifest.v1.json'
        [IO.File]::WriteAllText(
            $customManifestPath,
            ([ordered]@{
                schemaId = 'PspktTrustedControlVectorManifestV1'
                schemaVersion = 1
                syntheticOnly = $true
                cases = @($customCase)
            } | ConvertTo-Json -Depth 8 -Compress),
            [Text.UTF8Encoding]::new($false,$true))
        (& $script:validatorPath -Mode VerifyVector -VectorPath $customManifestPath) |
            Should -BeExactly 'TRUSTED_CONTROL_CUSTOM_MANIFEST_OK|cases=1'
        [IO.File]::WriteAllText(
            $customManifestPath,
            '{"schemaId":"PspktTrustedControlVectorManifestV1","schemaVersion":1,"syntheticOnly":true,"cases":[]}',
            [Text.UTF8Encoding]::new($false,$true))
        { & $script:validatorPath -Mode VerifyVector -VectorPath $customManifestPath } |
            Should -Throw '*manifest-shape*'

        $missingPendingPath = Join-Path $generatedVectorRoot (
            'reject-membership-enrolled-pending-missing.json')
        $mutatedMissingPending = Get-Content -LiteralPath $missingPendingPath -Raw | ConvertFrom-Json
        $mutatedMissingPending.expectedReason = 'ok'
        $mutatedMissingPendingPath = Join-Path $TestDrive 'mutated-enrolled-pending-missing.json'
        [IO.File]::WriteAllText(
            $mutatedMissingPendingPath,
            ($mutatedMissingPending | ConvertTo-Json -Depth 32 -Compress),
            [Text.UTF8Encoding]::new($false,$true))
        { & $script:validatorPath -Mode VerifyVector -VectorPath $mutatedMissingPendingPath } |
            Should -Throw '*vector-reason-mismatch:expected=ok;actual=membership-path-pending-missing*'
        foreach ($case in $manifest.cases) {
            $path = Join-Path $outputRoot (
                'certification\trusted-control\vectors\synthetic\' + $case.path)
            $bytes = [IO.File]::ReadAllBytes($path)
            $vectorDocument = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
            $vectorDocument.syntheticOnly | Should -BeTrue
            if ($vectorDocument.caseKind -ceq 'membershipPath') {
                $vectorDocument.input.PSObject.Properties.Name | Should -Contain 'trackedPaths'
                $vectorDocument.input.PSObject.Properties.Name | Should -Contain 'pendingPaths'
            }
            $bytes.LongLength | Should -Be $case.byteLength
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly $case.sha256
        }
    }

    It 'pins inventory as the sixth maintained sizing input without provenance' {
        @($script:authority.maintainedInputs).Count | Should -Be 6
        @($script:authority.maintainedInputs)[5] |
            Should -BeExactly 'certification/schema/protocol-inventory.v1.json'
        @($script:authority.provenance.source) |
            Should -Not -Contain 'certification/schema/protocol-inventory.v1.json'
        $script:contract.MaintainedInputPathSet | Should -Contain (
            'certification/schema/protocol-inventory.v1.json')
        $script:contract.Sha256ByPath[
            'certification/schema/protocol-inventory.v1.json'] |
                Should -BeExactly 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
        (Get-FileHash -LiteralPath $script:inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant() |
            Should -BeExactly 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
    }

    It 'exposes only inventory-explicit public sizing APIs' {
        $bootstrapSource = [IO.File]::ReadAllText((Join-Path $script:sliceRoot (
            'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))
        $authoritySource = [IO.File]::ReadAllText((Join-Path $script:sliceRoot (
            'lib\Pspkt.Certification.TrustedControlAuthority.cs')))
        $verifySource = [IO.File]::ReadAllText((Join-Path $script:sliceRoot (
            'lib\Pspkt.Certification.TrustedControlVerify.cs')))
        ([regex]::Matches($bootstrapSource,'public static TrustedJsonResult Evaluate\(')).Count |
            Should -Be 1
        ([regex]::Matches($authoritySource,'public static IDictionary<string, byte\[\]> Generate\(')).Count |
            Should -Be 1
        ([regex]::Matches($verifySource,'public static void Verify\(')).Count | Should -Be 1
        ([regex]::Matches($verifySource,'public static string VerifyVector\(')).Count | Should -Be 1
        $bootstrapSource | Should -Not -Match 'ValidateAuthority\('
        $bootstrapSource | Should -Not -Match 'NormalizeProtocolDeclaration'
        $bootstrapSource | Should -Not -Match 'ValidateEntrypointAggregateLimits'
        $bootstrapSource | Should -Match 'byte\[\] inventoryBytes'
        $authoritySource | Should -Match 'byte\[\] inventoryBytes'
        ([regex]::Matches($verifySource,'byte\[\] inventoryBytes')).Count | Should -Be 3
        $bootstrapSource | Should -Not -Match 'sourceSiteBytes\s*!=\s*824UL'
        $verifySource | Should -Not -Match 'sourceSiteBytes\s*!=\s*824UL'
        $bootstrapSource | Should -Match (
            'limits\.GetInteger\("entrypointReviewedSourceSiteBytes"\)')
        $verifySource | Should -Match (
            'limits\.GetInteger\("entrypointReviewedSourceSiteBytes"\)')
        $bootstrapSource | Should -Match (
            'public static IDictionary<string, byte\[\]> Generate\(\s*byte\[\] authorityBytes,\s*byte\[\] jsonMetaBytes,\s*byte\[\] inventoryBytes\)')
        $bootstrapSource | Should -Not -Match (
            'public static IDictionary<string, byte\[\]> Generate\(\s*TrustedJsonObject')
        $bootstrapSource | Should -Match (
            'internal static void Validate\(')
        $bootstrapSource | Should -Match (
            'ValidateAuthorityRaw\(\s*authority,\s*meta,\s*inventory\)')
    }

    It 'rejects every reviewed authority sizing mutation in Raw' {
        $reviewedValues = [ordered]@{
            entrypointReviewedSourceSiteBytes = 824
            entrypointReviewedInterpreterBytes = 2266
            entrypointReviewedArgumentBytes = 2058
            entrypointReviewedHostToolBytes = 7690
            entrypointReviewedGuestCandidateBytes = 1248
            entrypointReviewedHostRunspaceBytes = 1056
            entrypointReviewedRootBytes = 640422
            entrypointReviewedTotalSourceSites = 192
            entrypointReviewedTotalUserArguments = 128
            entrypointReviewedMaximumDepth = 6
        }
        @($script:authority.limits.PSObject.Properties.Name) |
            Should -Contain 'entrypointReviewedMaximumDepth'
        foreach ($entry in $reviewedValues.GetEnumerator()) {
            $script:authority.limits.($entry.Key) | Should -Be $entry.Value
            $fixtureRoot = Join-Path $TestDrive ('authority-' + $entry.Key)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $authorityRelative =
                'certification/trusted-control/schema/trusted-control-authority.v1.json'
            $authorityPath = Join-Path $fixtureRoot $authorityRelative.Replace('/','\')
            $oldValue = '"' + $entry.Key + '":' + $entry.Value
            $newValue = '"' + $entry.Key + '":' + ([int64]$entry.Value + 1)
            [IO.File]::WriteAllText(
                $authorityPath,
                [IO.File]::ReadAllText($authorityPath).Replace($oldValue,$newValue),
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($authorityRelative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$.limits.$($entry.Key):property-value*"
        }
    }

    It 'keeps authority projection A and verifier projection B independent' {
        foreach ($projection in @(
            @{ Name = 'authority'; Relative = 'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'; Mode = 'Compile'; Prefix = 'authority-' },
            @{ Name = 'verify'; Relative = 'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'; Mode = 'Validate'; Prefix = 'verify-' }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('projection-' + $projection.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $sourcePath = Join-Path $fixtureRoot $projection.Relative.Replace('/','\')
            $sourceText = [regex]::Replace(
                [IO.File]::ReadAllText($sourcePath),
                'rootBytes\s+!= limits\.GetInteger\("entrypointReviewedRootBytes"\)',
                'rootBytes + 1UL != limits.GetInteger("entrypointReviewedRootBytes")')
            [IO.File]::WriteAllText(
                $sourcePath,
                $sourceText,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($projection.Relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode $projection.Mode -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$($projection.Prefix)entrypoint-reviewed-sizing*"
            if ($projection.Name -ceq 'authority') {
                (& $fixtureValidator -Mode Validate -RepositoryRoot $fixtureRoot) |
                    Should -BeExactly 'TRUSTED_CONTROL_VALIDATE_OK|outputs=10|tlv=3|json=7'
            } else {
                (& $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot) |
                    Should -BeExactly (
                        'TRUSTED_CONTROL_COMPILE_OK|outputs=10|tlv=3|json=7|' +
                        'verifyAuthorityReferences=0')
                $generatedRoot = Join-Path $fixtureRoot 'generated'
                (& $fixtureValidator -Mode Generate -RepositoryRoot $fixtureRoot `
                    -OutputRoot $generatedRoot) |
                        Should -BeExactly 'TRUSTED_CONTROL_GENERATE_OK|outputs=10'
            }
        }
    }

    It 'rejects an A call reachable through an allowed TrustedJson accessor' {
        $fixtureRoot = Join-Path $TestDrive 'call-graph-negative'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $relative = 'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
        $sourceText = [IO.File]::ReadAllText($sourcePath).Replace(
            'return Require<TrustedJsonString>(name).Value;',
            'TrustedControlAuthorityProjectionA.Validate(null, null, null); return Require<TrustedJsonString>(name).Value;')
        [IO.File]::WriteAllText(
            $sourcePath,
            $sourceText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*Bootstrap assembly metadata references authority projection A*'
    }

    It 'rejects an A call in an allowed shared type static constructor' {
        $fixtureRoot = Join-Path $TestDrive 'call-graph-static-constructor'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $relative = 'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
        $sourceText = [IO.File]::ReadAllText($sourcePath).Replace(
            "    public sealed class TrustedJsonObject : TrustedJsonNode`n    {",
            "    public sealed class TrustedJsonObject : TrustedJsonNode`n    {`n        static TrustedJsonObject()`n        {`n            TrustedControlAuthorityProjectionA.Validate(null, null, null);`n        }")
        [IO.File]::WriteAllText(
            $sourcePath,
            $sourceText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*Bootstrap assembly metadata references authority projection A*'
    }

    It 'rejects direct and indirect A calls from verifier static constructors' {
        foreach ($case in @(
            @{
                Name = 'direct'
                Insertion = @'
        static TrustedControlVerify()
        {
            TrustedControlAuthorityProjectionA.Generate(null, null, null);
        }
'@
            },
            @{
                Name = 'indirect'
                Insertion = @'
        static TrustedControlVerify()
        {
            ReachAuthorityProjection();
        }

        private static void ReachAuthorityProjection()
        {
            TrustedControlAuthorityProjectionA.Generate(null, null, null);
        }
'@
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('verify-static-constructor-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $relative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
            $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
            $sourceText = [IO.File]::ReadAllText($sourcePath).Replace(
                "    public static class TrustedControlVerify`n    {",
                "    public static class TrustedControlVerify`n    {`n" + $case.Insertion)
            [IO.File]::WriteAllText(
                $sourcePath,
                $sourceText,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw '*Verify binary contains forbidden authority name*'
        }
    }

    It 'rejects A-calling static constructors reached only through static fields' {
        foreach ($case in @(
            @{
                Name = 'verify'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                MethodOld = "        {`n            if (actual == null)"
                MethodNew = "        {`n            if (VerifierFieldProbe.Value == -1) { throw new InvalidOperationException(`"probe`"); }`n            if (actual == null)"
                TypeOld = '        private sealed class VerifierContext'
                TypeNew = @'
        private static class VerifierFieldProbe
        {
            internal static readonly int Value = 0;

            static VerifierFieldProbe()
            {
                TrustedControlAuthorityProjectionA.Generate(null, null, null);
            }
        }

        private sealed class VerifierContext
'@
                Reason = 'Verify binary contains forbidden authority name'
            },
            @{
                Name = 'bootstrap'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
                MethodOld = '            return Require<TrustedJsonString>(name).Value;'
                MethodNew = '            if (BootstrapFieldProbe.Value == -1) { throw new InvalidOperationException("probe"); } return Require<TrustedJsonString>(name).Value;'
                TypeOld = '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode'
                TypeNew = @'
        private static class BootstrapFieldProbe
        {
            internal static readonly int Value = 0;

            static BootstrapFieldProbe()
            {
                TrustedControlAuthorityProjectionA.Validate(null, null, null);
            }
        }

        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode
'@
                Reason = 'Bootstrap assembly metadata references authority projection A'
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('field-static-constructor-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $sourcePath = Join-Path $fixtureRoot $case.Relative.Replace('/','\')
            $sourceText = [IO.File]::ReadAllText($sourcePath)
            $sourceText = $sourceText.Replace($case.MethodOld,$case.MethodNew)
            $sourceText = $sourceText.Replace($case.TypeOld,$case.TypeNew)
            [IO.File]::WriteAllText(
                $sourcePath,
                $sourceText,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($case.Relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$($case.Reason)*"
        }
    }

    It 'rejects dead A references anywhere in Verify or shared Bootstrap' {
        foreach ($case in @(
            @{
                Name = 'verify'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                Old = '        private static string ToHex(byte[] bytes)'
                New = @'
        private static void DeadAuthorityReference()
        {
            TrustedControlAuthorityProjectionA.Generate(null, null, null);
        }

        private static string ToHex(byte[] bytes)
'@
                Reason = 'Verify binary contains forbidden authority name'
            },
            @{
                Name = 'bootstrap'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
                Old = '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode'
                New = @'
        private static void DeadAuthorityReference()
        {
            TrustedControlAuthorityProjectionA.Validate(null, null, null);
        }

        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode
'@
                Reason = 'Bootstrap assembly metadata references authority projection A'
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('dead-reference-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $sourcePath = Join-Path $fixtureRoot $case.Relative.Replace('/','\')
            [IO.File]::WriteAllText(
                $sourcePath,
                [IO.File]::ReadAllText($sourcePath).Replace($case.Old,$case.New),
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($case.Relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$($case.Reason)*"
        }
    }

    It 'runs shared Bootstrap isolation before Generate emits files' {
        $fixtureRoot = Join-Path $TestDrive 'generate-bootstrap-isolation'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $relative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
        $sourceText = [IO.File]::ReadAllText($sourcePath).Replace(
            '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode',
            @'
        private static void DeadAuthorityReference()
        {
            TrustedControlAuthorityProjectionA.Validate(null, null, null);
        }

        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode
'@)
        [IO.File]::WriteAllText(
            $sourcePath,
            $sourceText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        $outputRoot = Join-Path $fixtureRoot 'generated'
        { & $fixtureValidator -Mode Generate -RepositoryRoot $fixtureRoot `
                -OutputRoot $outputRoot } |
            Should -Throw '*Bootstrap assembly metadata references authority projection A*'
    }

    It 'rejects module initializers that reference authority projection A' {
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            Set-ItResult -Skipped -Because 'The Windows PowerShell C# compiler cannot emit module initializers.'
            return
        }
        $fixtureRoot = Join-Path $TestDrive 'bootstrap-module-initializer'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $relative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
        $sourceText = [IO.File]::ReadAllText($sourcePath)
        $sourceText = $sourceText.Replace(
            'using System.Security.Cryptography;',
            "using System.Runtime.CompilerServices;`nusing System.Security.Cryptography;")
        $sourceText = $sourceText.Replace(
            '    public sealed class TrustedJsonResult',
            @'
    internal static class BootstrapModuleInitializerProbe
    {
        [ModuleInitializer]
        internal static void Initialize()
        {
        }
    }

    public sealed class TrustedJsonResult
'@)
        [IO.File]::WriteAllText(
            $sourcePath,
            $sourceText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*Bootstrap assembly contains forbidden module method definitions*'
    }

    It 'rejects authority types from assembly metadata in Verify and shared Bootstrap' {
        $cases = @(
            @{ Name = 'field'; Target = 'verify'; Anchor = '    public static class TrustedControlVerify' ; Replacement = "    public static class TrustedControlVerify`n    {`n        public static TrustedControlAuthorityProjectionA.NestedProbe DeadField;"; ReplaceOpening = $true },
            @{ Name = 'generic-field'; Target = 'verify'; Anchor = '    public static class TrustedControlVerify'; Replacement = "    public static class TrustedControlVerify`n    {`n        public static List<TrustedControlAuthorityProjectionA.NestedProbe> DeadList;"; ReplaceOpening = $true },
            @{ Name = 'parameter'; Target = 'verify'; Code = "        private static void DeadParameter(TrustedControlAuthorityProjectionA.NestedProbe value) { }`n`n" },
            @{ Name = 'return'; Target = 'verify'; Code = "        private static TrustedControlAuthorityProjectionA.NestedProbe DeadReturn() { return null; }`n`n" },
            @{ Name = 'local'; Target = 'verify'; Code = "        private static int DeadLocal()`n        {`n            TrustedControlAuthorityProjectionA.NestedProbe value = new TrustedControlAuthorityProjectionA.NestedProbe();`n            GC.KeepAlive(value);`n            return 0;`n        }`n`n" },
            @{ Name = 'catch'; Target = 'verify'; Code = "        private static void DeadCatch()`n        {`n            try { throw new InvalidOperationException(); }`n            catch (TrustedControlAuthorityProjectionA.NestedException) { }`n        }`n`n" },
            @{ Name = 'constraint'; Target = 'verify'; Code = "        private static void DeadConstraint<T>() where T : TrustedControlAuthorityProjectionA.NestedProbe { }`n`n" },
            @{ Name = 'attribute'; Target = 'verify'; Code = "        [AuthorityType(typeof(TrustedControlAuthorityProjectionA.NestedProbe))]`n        private static void DeadAttribute() { }`n`n        [AttributeUsage(AttributeTargets.Method)]`n        private sealed class AuthorityTypeAttribute : Attribute`n        {`n            public AuthorityTypeAttribute(Type type) { }`n        }`n`n" },
            @{ Name = 'bootstrap-signature'; Target = 'bootstrap' }
        )
        foreach ($case in $cases) {
            $fixtureRoot = Join-Path $TestDrive ('metadata-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $bootstrapRelative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
            $verifyRelative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
            $bootstrapPath = Join-Path $fixtureRoot $bootstrapRelative.Replace('/','\')
            $bootstrapText = [IO.File]::ReadAllText($bootstrapPath).Replace(
                "    public static class TrustedControlAuthorityProjectionA`n    {",
                "    public static class TrustedControlAuthorityProjectionA`n    {`n        public class NestedProbe { }`n        public sealed class NestedException : Exception { }")
            if ($case.Target -ceq 'bootstrap') {
                $bootstrapText = $bootstrapText.Replace(
                    '        public string GetString(string name)',
                    '        public string GetString(string name, TrustedControlAuthorityProjectionA.NestedProbe probe = null)')
            }
            [IO.File]::WriteAllText(
                $bootstrapPath,
                $bootstrapText,
                [Text.UTF8Encoding]::new($false,$true))
            $repin = [Collections.Generic.List[string]]::new()
            $repin.Add($bootstrapRelative)
            if ($case.Target -ceq 'verify') {
                $verifyPath = Join-Path $fixtureRoot $verifyRelative.Replace('/','\')
                $verifyText = [IO.File]::ReadAllText($verifyPath)
                if ($case.ContainsKey('ReplaceOpening')) {
                    $verifyText = $verifyText.Replace(
                        "    public static class TrustedControlVerify`n    {",
                        $case.Replacement)
                } else {
                    $verifyText = $verifyText.Replace(
                        '        private static string ToHex(byte[] bytes)',
                        $case.Code + '        private static string ToHex(byte[] bytes)')
                }
                [IO.File]::WriteAllText(
                    $verifyPath,
                    $verifyText,
                    [Text.UTF8Encoding]::new($false,$true))
                $repin.Add($verifyRelative)
            }
            & $script:RepinTrustedControlFixture $fixtureRoot $repin.ToArray()
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            $failure = $null
            try {
                & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot
            }
            catch {
                $failure = $_.Exception.ToString()
            }
            $failure | Should -Match (
                'Verify binary contains forbidden authority name|' +
                'Bootstrap assembly metadata references authority projection A')
        }
    }

    It 'rejects forbidden authority names in raw Verify assembly bytes' {
        foreach ($case in @(
            @{
                Name = 'generic'
                AddNested = $true
                Code = "        private static T DeadIdentity<T>(T value) { return value; }`n`n        private static void DeadGenericAuthorityType()`n        {`n            DeadIdentity<TrustedControlAuthorityProjectionA.NestedProbe>(null);`n        }`n`n"
            },
            @{
                Name = 'reflection-string'
                AddNested = $false
                Code = "        private static Type DeadReflectionAuthorityType()`n        {`n            return Type.GetType(`"Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA`");`n        }`n`n"
            },
            @{
                Name = 'generic-declaring-type'
                AddNested = $true
                Code = "        private sealed class DeadHolder<T>`n        {`n            internal static void Touch() { }`n        }`n`n        private static void DeadGenericDeclaringType()`n        {`n            DeadHolder<TrustedControlAuthorityProjectionA.NestedProbe>.Touch();`n        }`n`n"
            },
            @{
                Name = 'uppercase-concatenated'
                AddNested = $false
                Code = "        private static Type DeadUppercaseAuthorityName()`n        {`n            return Type.GetType(`"TRUSTEDCONTROLAUTHORITY`" + `"PROJECTIONA`");`n        }`n`n"
            },
            @{
                Name = 'lowercase-concatenated'
                AddNested = $false
                Code = "        private static Type DeadLowercaseAuthorityName()`n        {`n            return Type.GetType(`"pspkt.certification.trustedcontrol.`" + `"trustedcontrolauthorityprojectiona`");`n        }`n`n"
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('binary-isolation-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $bootstrapRelative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
            $verifyRelative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
            $repin = [Collections.Generic.List[string]]::new()
            if ($case.AddNested) {
                $bootstrapPath = Join-Path $fixtureRoot $bootstrapRelative.Replace('/','\')
                [IO.File]::WriteAllText(
                    $bootstrapPath,
                    [IO.File]::ReadAllText($bootstrapPath).Replace(
                        "    public static class TrustedControlAuthorityProjectionA`n    {",
                        "    public static class TrustedControlAuthorityProjectionA`n    {`n        public class NestedProbe { }"),
                    [Text.UTF8Encoding]::new($false,$true))
                $repin.Add($bootstrapRelative)
            }
            $verifyPath = Join-Path $fixtureRoot $verifyRelative.Replace('/','\')
            [IO.File]::WriteAllText(
                $verifyPath,
                [IO.File]::ReadAllText($verifyPath).Replace(
                    '        private static string ToHex(byte[] bytes)',
                    $case.Code + '        private static string ToHex(byte[] bytes)'),
                [Text.UTF8Encoding]::new($false,$true))
            $repin.Add($verifyRelative)
            if ($case.Name -like '*concatenated') {
                $probeRoot = Join-Path $fixtureRoot 'binary-probe'
                [void][IO.Directory]::CreateDirectory($probeRoot)
                $bootstrapProbePath = Join-Path $probeRoot 'Bootstrap.dll'
                $verifyProbePath = Join-Path $probeRoot 'Verify.dll'
                $frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
                    @('System.dll','System.Core.dll','System.Security.dll')
                } else {
                    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' |
                        ForEach-Object { $_.FullName })
                }
                Add-Type -TypeDefinition ([IO.File]::ReadAllText($bootstrapPath)) `
                    -OutputAssembly $bootstrapProbePath `
                    -ReferencedAssemblies $frameworkReferences
                Add-Type -TypeDefinition ([IO.File]::ReadAllText($verifyPath)) `
                    -OutputAssembly $verifyProbePath `
                    -ReferencedAssemblies @($frameworkReferences + $bootstrapProbePath)
                $probeBytes = [IO.File]::ReadAllBytes($verifyProbePath)
                $asciiText = [Text.Encoding]::ASCII.GetString($probeBytes).ToLowerInvariant()
                $unicodeEvenText =
                    [Text.Encoding]::Unicode.GetString($probeBytes).ToLowerInvariant()
                $unicodeOddText = [Text.Encoding]::Unicode.GetString(
                    $probeBytes,
                    1,
                    $probeBytes.Length - 1).ToLowerInvariant()
                ($asciiText.Contains('trustedcontrolauthorityprojectiona') -or
                    $unicodeEvenText.Contains('trustedcontrolauthorityprojectiona') -or
                    $unicodeOddText.Contains('trustedcontrolauthorityprojectiona')) |
                    Should -BeTrue
            }
            & $script:RepinTrustedControlFixture $fixtureRoot $repin.ToArray()
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw '*Verify binary contains forbidden authority name*'
        }
    }

    It 'rejects reflection and dynamic resolution capabilities in Verify and shared Bootstrap' {
        foreach ($case in @(
            @{
                Name = 'verify-assembly-gettype'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Code = "        private static Type DeadAssemblyGetType()`n        {`n            return typeof(TrustedControlVerify).Assembly.GetType(`"missing`", false, true);`n        }`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-formatter-services'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Desktop')
                Code = "#pragma warning disable 618`n        private static Type DeadFormatterServicesType()`n        {`n            string name = string.Concat(`"TrustedControlAuthority`", `"ProjectionA`");`n            return System.Runtime.Serialization.FormatterServices.GetTypeFromAssembly(typeof(TrustedControlVerify).Assembly, name);`n        }`n#pragma warning restore 618`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-codedom'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Desktop')
                Code = "        private static object DeadCodeDomProvider()`n        {`n            return System.CodeDom.Compiler.CodeDomProvider.CreateProvider(`"CSharp`");`n        }`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-crypto-config'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Desktop')
                Code = "        private static object DeadCryptoConfigCreate()`n        {`n            return System.Security.Cryptography.CryptoConfig.CreateFromName(string.Concat(`"System.Text.`", `"StringBuilder`"));`n        }`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-hash-algorithm-create-desktop'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Desktop')
                Code = "#pragma warning disable 618`n        private static object DeadHashAlgorithmCreate()`n        {`n            return System.Security.Cryptography.HashAlgorithm.Create(`"System.Text.StringBuilder, mscorlib`");`n        }`n#pragma warning restore 618`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-hash-algorithm-create-core'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Core')
                Code = "#pragma warning disable SYSLIB0045`n        private static object DeadHashAlgorithmCreate()`n        {`n            return System.Security.Cryptography.HashAlgorithm.Create(`"System.Text.StringBuilder, System.Private.CoreLib`");`n        }`n#pragma warning restore SYSLIB0045`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-appdomain-interface'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Desktop')
                Code = "        private static object DeadAppDomainInterfaceLoad()`n        {`n            System._AppDomain domain = (System._AppDomain)System.Threading.Thread.GetDomain();`n            return domain.Load(new byte[0]);`n        }`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-scriptblock'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Desktop')
                Code = "        private static object DeadScriptBlockCreate()`n        {`n            return System.Management.Automation.ScriptBlock.Create(`"1 + 1`");`n        }`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'verify-visual-basic'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                AddNested = $false
                Editions = @('Core')
                Code = "        private static object DeadVisualBasicCreateObject()`n        {`n            return Microsoft.VisualBasic.Interaction.CreateObject(`"Scripting.Dictionary`", `"`");`n        }`n`n"
                Reason = 'Verify assembly uses forbidden dynamic resolution'
            },
            @{
                Name = 'bootstrap-generic-helper'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
                AddNested = $true
                Code = "        private static T DeadIdentity<T>(T value) { return value; }`n`n        private static void DeadBootstrapGenericHelper()`n        {`n            DeadIdentity<TrustedControlAuthorityProjectionA.NestedProbe>(null);`n        }`n`n"
                Reason = 'Bootstrap assembly metadata references authority projection A'
            }
        )) {
            if ($case.ContainsKey('Editions') -and
                $case.Editions -cnotcontains $PSVersionTable.PSEdition) {
                continue
            }
            $fixtureRoot = Join-Path $TestDrive ('dynamic-isolation-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $bootstrapRelative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
            $sourcePath = Join-Path $fixtureRoot $case.Relative.Replace('/','\')
            $sourceText = [IO.File]::ReadAllText($sourcePath)
            if ($case.AddNested) {
                $sourceText = $sourceText.Replace(
                    "    public static class TrustedControlAuthorityProjectionA`n    {",
                    "    public static class TrustedControlAuthorityProjectionA`n    {`n        public class NestedProbe { }")
            }
            $sourceText = $sourceText.Replace(
                '        private static string ToHex(byte[] bytes)',
                $case.Code + '        private static string ToHex(byte[] bytes)')
            if ($case.Name -ceq 'bootstrap-generic-helper') {
                $sourceText = $sourceText.Replace(
                    '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode',
                    $case.Code +
                    '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode')
            }
            [IO.File]::WriteAllText(
                $sourcePath,
                $sourceText,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($case.Relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$($case.Reason)*"
        }
    }

    It 'rejects authority projection A delegate capture from the Evaluate bridge' {
        $fixtureRoot = Join-Path $TestDrive 'bootstrap-authority-delegate'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $relative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
        $sourceText = [IO.File]::ReadAllText($sourcePath).Replace(
            '                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);',
            @'
                    Action<TrustedJsonObject, TrustedJsonObject, TrustedJsonObject> escaped =
                        TrustedControlAuthorityProjectionA.Validate;
                    escaped(authority, meta, inventory);
'@)
        [IO.File]::WriteAllText(
            $sourcePath,
            $sourceText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*Bootstrap assembly metadata references authority projection A*'
    }

    It 'pins the Evaluate bridge to exact source and target method identities' {
        foreach ($case in @(
            @{
                Name = 'private-evaluate-overload'
                Mutate = {
                    param([string]$SourceText)
                    return $SourceText.Replace(
                        '        public static string ComputeSha256Hex(byte[] bytes)',
                        @'
        private static void Evaluate(
            TrustedJsonObject authority,
            TrustedJsonObject meta,
            TrustedJsonObject inventory)
        {
            TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);
        }

        public static string ComputeSha256Hex(byte[] bytes)
'@)
                }
                Reason = 'Bootstrap assembly metadata references authority projection A'
            },
            @{
                Name = 'delegate-returning-validate'
                Mutate = {
                    param([string]$SourceText)
                    $SourceText = $SourceText.Replace(
                        '                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);',
                        '                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory).Invoke();')
                    $SourceText = $SourceText.Replace(
                        '        internal static void Validate(',
                        '        internal static Action Validate(')
                    return $SourceText.Replace(
                        '                GenerateCore(authority, meta, inventory);',
                        "                GenerateCore(authority, meta, inventory);`n                return delegate { };")
                }
                Reason = 'Bootstrap authority bridge shape differs'
            },
            @{
                Name = 'generic-validate'
                Mutate = {
                    param([string]$SourceText)
                    $SourceText = $SourceText.Replace(
                        '                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);',
                        '                    TrustedControlAuthorityProjectionA.Validate<string>(authority, meta, inventory);')
                    return $SourceText.Replace(
                        '        internal static void Validate(',
                        '        internal static void Validate<T>(')
                }
                Reason = 'Bootstrap authority bridge shape differs'
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('bridge-identity-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $relative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
            $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
            [IO.File]::WriteAllText(
                $sourcePath,
                (& $case.Mutate ([IO.File]::ReadAllText($sourcePath))),
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$($case.Reason)*"
        }
    }

    It 'rejects native and COM imports in Verify and shared Bootstrap' {
        foreach ($case in @(
            @{
                Name = 'verify-pinvoke'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                Anchor = '        private static string ToHex(byte[] bytes)'
                Code = "        [System.Runtime.InteropServices.DllImport(`"kernel32.dll`")]`n        private static extern IntPtr DeadLoadLibrary(string path);`n`n"
                Reason = 'Verify assembly uses forbidden native import'
            },
            @{
                Name = 'bootstrap-pinvoke'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
                Anchor = '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode'
                Code = "        [System.Runtime.InteropServices.DllImport(`"kernel32.dll`")]`n        private static extern IntPtr DeadLoadLibrary(string path);`n`n"
                Reason = 'Bootstrap assembly uses forbidden native import'
            },
            @{
                Name = 'verify-comimport'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                Anchor = '        private static string ToHex(byte[] bytes)'
                Code = "        [System.Runtime.InteropServices.ComImport]`n        [System.Runtime.InteropServices.Guid(`"00000000-0000-0000-C000-000000000046`")]`n        private class DeadComImport`n        {`n        }`n`n"
                Reason = 'Verify assembly uses forbidden COM import'
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('native-import-' + $case.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $sourcePath = Join-Path $fixtureRoot $case.Relative.Replace('/','\')
            [IO.File]::WriteAllText(
                $sourcePath,
                [IO.File]::ReadAllText($sourcePath).Replace(
                    $case.Anchor,
                    $case.Code + $case.Anchor),
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($case.Relative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*$($case.Reason)*"
        }
    }

    It 'traverses verifier virtual overrides before admitting Bootstrap calls' {
        $fixtureRoot = Join-Path $TestDrive 'verify-virtual-override'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $relative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        $sourcePath = Join-Path $fixtureRoot $relative.Replace('/','\')
        $sourceText = [IO.File]::ReadAllText($sourcePath)
        $sourceText = $sourceText.Replace(
            "        {`n            if (actual == null)",
            "        {`n            VerifyBridge bridge = new VerifyBridgeImplementation();`n            bridge.Run(authorityBytes, jsonMetaBytes, inventoryBytes);`n            if (actual == null)")
        $sourceText = $sourceText.Replace(
            '        private static string ToHex(byte[] bytes)',
            @'
        private abstract class VerifyBridge
        {
            internal abstract void Run(
                byte[] authorityBytes,
                byte[] jsonMetaBytes,
                byte[] inventoryBytes);
        }

        private sealed class VerifyBridgeImplementation : VerifyBridge
        {
            internal override void Run(
                byte[] authorityBytes,
                byte[] jsonMetaBytes,
                byte[] inventoryBytes)
            {
                TrustedControlJsonSchemaBootstrap.Evaluate(
                    "authority",
                    authorityBytes,
                    jsonMetaBytes,
                    inventoryBytes);
            }
        }

        private static string ToHex(byte[] bytes)
'@)
        [IO.File]::WriteAllText(
            $sourcePath,
            $sourceText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($relative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*Verifier uses a forbidden Bootstrap member: Evaluate*'
    }

    It 'traverses external virtual and cross-assembly interface dispatch' {
        $externalRoot = Join-Path $TestDrive 'verify-external-virtual'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $externalRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $externalRoot 'tests\phase4-trusted-control') -Recurse
        $verifyRelative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        $verifyPath = Join-Path $externalRoot $verifyRelative.Replace('/','\')
        $verifyText = [IO.File]::ReadAllText($verifyPath)
        $verifyText = $verifyText.Replace(
            "        {`n            if (actual == null)",
            "        {`n            object bridge = new ExternalVirtualBridge(authorityBytes, jsonMetaBytes, inventoryBytes);`n            bridge.ToString();`n            if (actual == null)")
        $verifyText = $verifyText.Replace(
            '        private static string ToHex(byte[] bytes)',
            @'
        private sealed class ExternalVirtualBridge
        {
            private readonly byte[] _authorityBytes;
            private readonly byte[] _jsonMetaBytes;
            private readonly byte[] _inventoryBytes;

            internal ExternalVirtualBridge(
                byte[] authorityBytes,
                byte[] jsonMetaBytes,
                byte[] inventoryBytes)
            {
                _authorityBytes = authorityBytes;
                _jsonMetaBytes = jsonMetaBytes;
                _inventoryBytes = inventoryBytes;
            }

            public override string ToString()
            {
                TrustedControlJsonSchemaBootstrap.Evaluate(
                    "authority",
                    _authorityBytes,
                    _jsonMetaBytes,
                    _inventoryBytes);
                return string.Empty;
            }
        }

        private static string ToHex(byte[] bytes)
'@)
        [IO.File]::WriteAllText(
            $verifyPath,
            $verifyText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $externalRoot @($verifyRelative)
        $externalValidator = Join-Path $externalRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $externalValidator -Mode Compile -RepositoryRoot $externalRoot } |
            Should -Throw '*Verifier uses a forbidden Bootstrap member: Evaluate*'

        $interfaceRoot = Join-Path $TestDrive 'verify-interface-dispatch'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $interfaceRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $interfaceRoot 'tests\phase4-trusted-control') -Recurse
        $bootstrapRelative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        $bootstrapPath = Join-Path $interfaceRoot $bootstrapRelative.Replace('/','\')
        [IO.File]::WriteAllText(
            $bootstrapPath,
            [IO.File]::ReadAllText($bootstrapPath).Replace(
                '    public sealed class TrustedJsonResult',
                "    public interface TrustedJsonHook`n    {`n        string GetString(string name);`n    }`n`n    public sealed class TrustedJsonResult"),
            [Text.UTF8Encoding]::new($false,$true))
        $verifyPath = Join-Path $interfaceRoot $verifyRelative.Replace('/','\')
        $verifyText = [IO.File]::ReadAllText($verifyPath)
        $verifyText = $verifyText.Replace(
            "        {`n            if (actual == null)",
            "        {`n            TrustedJsonHook hook = new InterfaceBridge(authorityBytes, jsonMetaBytes, inventoryBytes);`n            hook.GetString(`"path`");`n            if (actual == null)")
        $verifyText = $verifyText.Replace(
            '        private static string ToHex(byte[] bytes)',
            @'
        private sealed class InterfaceBridge : TrustedJsonHook
        {
            private readonly byte[] _authorityBytes;
            private readonly byte[] _jsonMetaBytes;
            private readonly byte[] _inventoryBytes;

            internal InterfaceBridge(
                byte[] authorityBytes,
                byte[] jsonMetaBytes,
                byte[] inventoryBytes)
            {
                _authorityBytes = authorityBytes;
                _jsonMetaBytes = jsonMetaBytes;
                _inventoryBytes = inventoryBytes;
            }

            public string GetString(string name)
            {
                TrustedControlJsonSchemaBootstrap.Evaluate(
                    "authority",
                    _authorityBytes,
                    _jsonMetaBytes,
                    _inventoryBytes);
                return name;
            }
        }

        private static string ToHex(byte[] bytes)
'@)
        [IO.File]::WriteAllText(
            $verifyPath,
            $verifyText,
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture `
            $interfaceRoot `
            @($bootstrapRelative,$verifyRelative)
        $interfaceValidator = Join-Path $interfaceRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $interfaceValidator -Mode Compile -RepositoryRoot $interfaceRoot } |
            Should -Throw '*Verifier uses a forbidden Bootstrap member: Evaluate*'
    }

    It 'rejects metadata tables that exceed their declared stream' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        $assemblyPath = Join-Path $TestDrive 'metadata-stream-probe.dll'
        Add-Type -TypeDefinition 'public static class MetadataStreamProbe { }' `
            -OutputAssembly $assemblyPath
        $bytes = [IO.File]::ReadAllBytes($assemblyPath)
        $streamNameOffset = -1
        for ($index = 8; $index -lt $bytes.Length - 3; $index++) {
            if ($bytes[$index] -eq [byte][char]'#' -and
                $bytes[$index + 1] -eq [byte][char]'~' -and
                $bytes[$index + 2] -eq 0) {
                $streamNameOffset = $index
                break
            }
        }
        $streamNameOffset | Should -BeGreaterThan 7
        $sizeOffset = $streamNameOffset - 4
        [BitConverter]::GetBytes([uint32]24).CopyTo($bytes,$sizeOffset)
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($bytes,'Malformed')
        } | Should -Throw '*metadata stream is truncated*'
    }

    It 'accepts a synthetic metadata root with exact table extent' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        $bytes = & $script:NewR9MetadataImage
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
        } | Should -Not -Throw
    }

    It 'rejects every supported metadata table when its computed extent exceeds the declared stream' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($tableIndex in 0..44) {
            if ($tableIndex -in @(3,5,7,19,22,30,31)) { continue }
            $exact = & $script:NewR9MetadataImage -AdditionalTable $tableIndex
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($exact,'MetadataOracle')
            } | Should -Not -Throw
            $truncated = & $script:NewR9MetadataImage `
                -AdditionalTable $tableIndex `
                -DeclaredAdjustment (-1)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($truncated,'MetadataOracle')
            } | Should -Throw '*metadata table extent exceeds declared #~ stream*'
        }
    }

    It 'uses the coded-index and table-index width thresholds at their exact boundaries' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($case in @(
            @{ Target = 38; Before = [uint32]2047; At = [uint32]2048; Dependent = 12 },
            @{ Target = 43; Before = [uint32]2047; At = [uint32]2048; Dependent = 12 },
            @{ Target = 10; Before = [uint32]8191; At = [uint32]8192; Dependent = 12 },
            @{ Target = 42; Before = [uint32]65535; At = [uint32]65536; Dependent = 44 }
        )) {
            foreach ($rowCount in @($case.Before,$case.At)) {
                $exact = & $script:NewR9MetadataImage `
                    -AdditionalTable $case.Target `
                    -AdditionalRows $rowCount `
                    -SecondTable $case.Dependent
                {
                    [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                        AssertNoModuleMethodDefinitions($exact,'MetadataOracle')
                } | Should -Not -Throw
                $short = & $script:NewR9MetadataImage `
                    -AdditionalTable $case.Target `
                    -AdditionalRows $rowCount `
                    -SecondTable $case.Dependent `
                    -DeclaredAdjustment (-1)
                {
                    [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                        AssertNoModuleMethodDefinitions($short,'MetadataOracle')
                } | Should -Throw '*metadata table extent exceeds declared #~ stream*'
            }
        }
    }

    It 'checks every coded-index family at the narrow-to-wide boundary' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($family in @(
            @{ Name='ResolutionScope'; Target=26; Limit=16384; Owner=1 },
            @{ Name='TypeDefOrRef'; Target=27; Limit=16384; Owner=9 },
            @{ Name='MemberRefParent'; Target=26; Limit=8192; Owner=10 },
            @{ Name='HasConstant'; Target=23; Limit=16384; Owner=11 },
            @{ Name='HasCustomAttribute'; Target=38; Limit=2048; Owner=12 },
            @{ Name='CustomAttributeType'; Target=10; Limit=8192; Owner=12 },
            @{ Name='HasFieldMarshal'; Target=8; Limit=32768; Owner=13 },
            @{ Name='HasDeclSecurity'; Target=32; Limit=16384; Owner=14 },
            @{ Name='HasSemantics'; Target=23; Limit=32768; Owner=24 },
            @{ Name='MethodDefOrRef'; Target=10; Limit=32768; Owner=25 },
            @{ Name='MemberForwarded'; Target=4; Limit=32768; Owner=28 },
            @{ Name='Implementation'; Target=39; Limit=16384; Owner=40 },
            @{ Name='TypeOrMethodDef'; Target=6; Limit=32768; Owner=42 }
        )) {
            foreach ($rows in @(($family.Limit - 1),$family.Limit)) {
                if ($family.Name -eq 'TypeOrMethodDef') {
                    $rowCounts = [uint32[]]::new(45)
                    $rowCounts[2] = 2
                    $rowCounts[6] = [uint32]$rows
                    $rowSizer = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity].
                        GetMethod('GetMetadataTableRowSize',
                            [Reflection.BindingFlags]'NonPublic,Static')
                    $expectedWidth = if ($rows -eq $family.Limit) { 10 } else { 8 }
                    $rowSizer.Invoke(
                        $null,[object[]]@(42,$rowCounts,2,2,2)) |
                        Should -Be $expectedWidth
                }
                $exact = & $script:NewR9MetadataImage `
                    -AdditionalTable $family.Target `
                    -AdditionalRows ([uint32]$rows) `
                    -SecondTable $family.Owner
                {
                    [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                        AssertNoModuleMethodDefinitions($exact,$family.Name)
                } | Should -Not -Throw
                $short = & $script:NewR9MetadataImage `
                    -AdditionalTable $family.Target `
                    -AdditionalRows ([uint32]$rows) `
                    -SecondTable $family.Owner `
                    -DeclaredAdjustment (-1)
                {
                    [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                        AssertNoModuleMethodDefinitions($short,$family.Name)
                } | Should -Throw '*metadata table extent exceeds declared #~ stream*'
            }
        }
    }

    It 'computes exact table extents for all valid heap-width flag combinations' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($heapFlags in 0..7) {
            $exact = & $script:NewR9MetadataImage -HeapFlags ([byte]$heapFlags)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($exact,'MetadataOracle')
            } | Should -Not -Throw
            $short = & $script:NewR9MetadataImage `
                -HeapFlags ([byte]$heapFlags) `
                -DeclaredAdjustment (-1)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($short,'MetadataOracle')
            } | Should -Throw '*metadata table extent exceeds declared #~ stream*'
        }
    }

    It 'distinguishes physical table truncation from missing advertised padding' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        $truncated = & $script:NewR9MetadataImage -PhysicalAdjustment (-1)
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($truncated,'MetadataOracle')
        } | Should -Throw '*metadata table extent exceeds physical #~ stream*'
        $missingPadding = & $script:NewR9MetadataImage -DeclaredAdjustment 1
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($missingPadding,'MetadataOracle')
        } | Should -Throw '*metadata #~ padding is truncated*'
        $presentPadding = & $script:NewR9MetadataImage `
            -DeclaredAdjustment 1 `
            -PhysicalAdjustment 1
        $presentPadding[$presentPadding.Length - 1] = 0xa5
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($presentPadding,'MetadataOracle')
        } | Should -Not -Throw
    }

    It 'rejects malformed metadata root and directory by validation stage' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($case in @(
            @{ Name = 'version-zero'; Offset = 0x500 + 12; Value = [uint32]0; Expected = 'metadata directory A0' },
            @{ Name = 'version-odd'; Offset = 0x500 + 12; Value = [uint32]11; Expected = 'metadata directory A0' },
            @{ Name = 'flags'; Offset = 0x500 + 28; Value = [uint16]1; Expected = 'metadata directory A0' },
            @{ Name = 'count'; Offset = 0x500 + 30; Value = [uint16]33; Expected = 'metadata directory A0' },
            @{ Name = 'version-too-long'; Offset = 0x500 + 12; Value = [uint32]256; Expected = 'metadata directory A0' },
            @{ Name = 'overlap'; Offset = 0x500 + 52; Value = [uint32]0x110; Expected = 'metadata directory A1' },
            @{ Name = 'zero-count'; Offset = 0x500 + 30; Value = [uint16]0; Expected = 'metadata directory A5' },
            @{ Name = 'missing'; Offset = 0x500 + 30; Value = [uint16]4; Expected = 'metadata directory A5' }
        )) {
            $bytes = & $script:NewR9MetadataImage
            [BitConverter]::GetBytes($case.Value).CopyTo($bytes,$case.Offset)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
            } | Should -Throw "*$($case.Expected)*"
        }
        $badPadding = & $script:NewR9MetadataImage
        $badPadding[0x500 + 49] = 1
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($badPadding,'MetadataOracle')
        } | Should -Throw '*metadata directory A0*'
        foreach ($case in @(
            @{ Name = 'duplicate'; NameOffset = 0x500 + 64 + 8; NameBytes = [byte[]]@(
                    [byte][char]'#',[byte][char]'B',[byte][char]'l',
                    [byte][char]'o',[byte][char]'b',0); Expected = 'metadata directory A2' },
            @{ Name = 'unoptimized'; NameOffset = 0x500 + 96 + 8; NameBytes = [byte[]]@(
                    [byte][char]'#',[byte][char]'-',0); Expected = 'metadata directory A3' },
            @{ Name = 'unknown'; NameOffset = 0x500 + 52 + 8; NameBytes = [byte[]]@(
                    [byte][char]'#',[byte][char]'X',[byte][char]'X',0); Expected = 'metadata directory A4' }
        )) {
            $bytes = & $script:NewR9MetadataImage
            $case.NameBytes.CopyTo($bytes,$case.NameOffset)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
            } | Should -Throw "*$($case.Expected)*"
        }
    }

    It 'finishes A0 directory validation before rejecting an oversized stream at A1' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($case in @(
            @{ LaterA0Defect=$false; Expected='metadata directory A1' },
            @{ LaterA0Defect=$true; Expected='metadata directory A0' }
        )) {
            $bytes = & $script:NewR9MetadataImage
            [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo(
                $bytes,0x500 + 36)
            if ($case.LaterA0Defect) {
                $bytes[0x500 + 78] = 1
            }
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
            } | Should -Throw "*$($case.Expected)*"
        }
    }

    It 'rejects zero-size metadata streams even at a distinct interval boundary' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($offset in @([uint32]0x110,[uint32]0x120)) {
            $bytes = & $script:NewR9MetadataImage
            [BitConverter]::GetBytes($offset).CopyTo($bytes,0x500 + 64)
            [BitConverter]::GetBytes([uint32]0).CopyTo($bytes,0x500 + 68)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
            } | Should -Throw '*metadata directory A1*'
        }
    }

    It 'bounds negative, overflowing, and truncated IL switch tables' {
        Invoke-Expression $script:r9ValidatorFunctions
        $probeSource = @'
public static class R9InlineSwitchProbe
{
    public static void Return() { }
}
'@
        $probeType = @(Add-Type -TypeDefinition $probeSource -PassThru)[0]
        $method = $probeType.GetMethod('Return')
        foreach ($case in @(
            @{ Count=-1; Tail=@(0x2a); Failure='switch has an invalid count' },
            @{ Count=[int]::MaxValue; Tail=@(0x2a); Failure='switch is truncated' },
            @{ Count=1; Tail=@(0x2a); Failure='switch is truncated' }
        )) {
            $bytes = [byte[]](@(0x45) +
                [BitConverter]::GetBytes([int]$case.Count) + $case.Tail)
            {
                Get-PspktTrustedControlCalledMethodReferences `
                    -Method $method -IlBytes $bytes -IncludeInstructions
            } | Should -Throw "*$($case.Failure)*"
        }
        {
            Get-PspktTrustedControlCalledMethodReferences `
                -Method $method -IlBytes ([byte[]]@(0x45,0x01))
        } | Should -Throw '*switch is truncated*'
        {
            Get-PspktTrustedControlCalledMethodReferences `
                -Method $method -IlBytes ([byte[]]@(0x45,0,0,0,0,0x2a))
        } | Should -Not -Throw
    }

    It 'rejects unsupported #~ headers and pointer or EnC tables even when empty' {
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        foreach ($case in @(
            @{ Offset = 0x700; Value = [uint32]1 },
            @{ Offset = 0x700 + 4; Value = [byte]3 },
            @{ Offset = 0x700 + 5; Value = [byte]1 },
            @{ Offset = 0x700 + 6; Value = [byte]8 },
            @{ Offset = 0x700 + 7; Value = [byte]0 }
        )) {
            $bytes = & $script:NewR9MetadataImage
            if ($case.Value -is [byte]) {
                $bytes[$case.Offset] = $case.Value
            } else {
                [BitConverter]::GetBytes($case.Value).CopyTo($bytes,$case.Offset)
            }
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
            } | Should -Throw '*metadata #~ header is invalid*'
        }
        foreach ($tableIndex in @(3,5,7,19,22,30,31,45)) {
            if ($tableIndex -eq 45) {
                $bytes = & $script:NewR9MetadataImage
                [BitConverter]::GetBytes([uint64](([uint64]1 -shl 45) -bor 69)).CopyTo(
                    $bytes,0x700 + 8)
            } else {
                $bytes = & $script:NewR9MetadataImage `
                    -AdditionalTable $tableIndex `
                    -AdditionalRows 0
            }
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($bytes,'MetadataOracle')
            } | Should -Throw '*metadata #~ table mask is unsupported*'
        }
        $tooManyRows = & $script:NewR9MetadataImage
        [BitConverter]::GetBytes([uint32]0x01000000).CopyTo($tooManyRows,0x700 + 24)
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                AssertNoModuleMethodDefinitions($tooManyRows,'MetadataOracle')
        } | Should -Throw '*metadata #~ row count is unsupported*'
        foreach ($tableIndex in @(3,5,7,19,22,30,31,45)) {
            $sorted = & $script:NewR9MetadataImage
            [BitConverter]::GetBytes([uint64]([uint64]1 -shl $tableIndex)).CopyTo(
                $sorted,0x700 + 16)
            {
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    AssertNoModuleMethodDefinitions($sorted,'MetadataOracle')
            } | Should -Throw '*metadata #~ table mask is unsupported*'
        }
    }

    It 'admits the clean wrapper while rejecting extra W MethodDefs and token capabilities' {
        (& $script:validatorPath -Mode Compile) |
            Should -BeExactly (
                'TRUSTED_CONTROL_COMPILE_OK|outputs=10|tlv=3|json=7|' +
                'verifyAuthorityReferences=0')
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlAuthority.cs'
        foreach ($case in @(
            @{
                Name = 'wrapper-extra-method'
                Mutate = {
                    param($text)
                    $text.Replace(
                        '        public static IDictionary<string, byte[]> Generate(',
                        "        private static int Unreviewed() { return 0; }`n`n" +
                        '        public static IDictionary<string, byte[]> Generate(')
                }
                Expected = 'authority wrapper shape differs'
            },
            @{
                Name = 'wrapper-file-capability'
                Mutate = {
                    param($text)
                    $text.Replace(
                        '            return TrustedControlAuthorityProjectionA.Generate(',
                        '            if (System.IO.File.Exists("r9-absent")) { throw new System.InvalidOperationException(); }' +
                        "`n            return TrustedControlAuthorityProjectionA.Generate(")
                }
                Expected = 'authority wrapper IL differs'
            },
            @{
                Name = 'wrapper-delegate'
                Mutate = {
                    param($text)
                    $text.Replace(
                        '            return TrustedControlAuthorityProjectionA.Generate(',
                        '            System.Func<byte[],byte[],byte[],IDictionary<string,byte[]>> callback =' +
                        " TrustedControlAuthorityProjectionA.Generate;`n" +
                        '            return callback(')
                }
                Expected = 'authority wrapper'
            }
        )) {
            & $script:AssertR9SourceFixture `
                -Name $case.Name `
                -RelativePath $relativePath `
                -Mutate $case.Mutate `
                -ExpectedFailure $case.Expected
        }
    }

    It 'rejects an unreviewed A method or instance shape before authority execution' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        foreach ($case in @(
            @{
                Name = 'authority-extra-helper'
                Mutate = {
                    param($text)
                    $text.Replace(
                        '        private const int MaximumSizingRecursionDepth = 64;',
                        "        private const int MaximumSizingRecursionDepth = 64;`n" +
                        '        private static int Unreviewed() { return 0; }')
                }
            },
            @{
                Name = 'authority-instance-method'
                Mutate = {
                    param($text)
                    $text.Replace(
                        '    public static class TrustedControlAuthorityProjectionA',
                        '    public class TrustedControlAuthorityProjectionA').Replace(
                        '        private const int MaximumSizingRecursionDepth = 64;',
                        "        private const int MaximumSizingRecursionDepth = 64;`n" +
                        '        private int Unreviewed() { return 0; }')
                }
            }
        )) {
            & $script:AssertR9SourceFixture `
                -Name $case.Name `
                -RelativePath $relativePath `
                -Mutate $case.Mutate `
                -ExpectedFailure 'authority projection A shape differs'
        }
    }

    It 'rejects an exact-shape A method without an IL body before the A exemption' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        & $script:AssertR9SourceFixture `
            -Name 'authority-native-exact-shape' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $start = $text.LastIndexOf(
                    '        private static bool BytesEqual(byte[] left, byte[] right)')
                $end = $text.IndexOf("`n        }",$start) + "`n        }".Length
                $text.Substring(0,$start) +
                    '        [System.Runtime.InteropServices.DllImport("kernel32.dll")]' +
                    "`n        private static extern bool BytesEqual(byte[] left, byte[] right);" +
                    $text.Substring($end)
            } `
            -ExpectedFailure 'Bootstrap assembly uses forbidden native import'
    }

    It 'rejects A field operands and dormant cryptography locals at the A token gate' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        & $script:AssertR9SourceFixture `
            -Name 'authority-field-token' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $start = $text.IndexOf(
                    '    public static class TrustedControlAuthorityProjectionA')
                $text.Substring(0,$start) +
                    $text.Substring($start).Replace(
                        '            Dictionary<string, byte[]> outputs =',
                        '            if (meta == null) { meta.JsonPath = "tampered-by-A"; }' +
                        "`n            Dictionary<string, byte[]> outputs =")
            } `
            -ExpectedFailure 'authority projection A token surface differs'
        & $script:AssertR9SourceFixture `
            -Name 'authority-crypto-local' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $text.Replace(
                    '            return exception.Message.StartsWith("authority-", StringComparison.Ordinal)',
                    @'
            if (exception.Message.Length < 0)
            {
                Dictionary<int,System.Security.Cryptography.MD5> dormant =
                    new Dictionary<int,System.Security.Cryptography.MD5>();
                dormant.Clear();
            }
            return exception.Message.StartsWith("authority-", StringComparison.Ordinal)
'@)
            } `
            -ExpectedFailure 'authority projection A type surface differs'
    }

    It 'pins A parameter modifiers, optional defaults, and attributes' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        foreach ($case in @(
            @{ Name='in-attribute'; Replacement='[System.Runtime.InteropServices.In] byte[] left, byte[] right' },
            @{ Name='optional-default'; Replacement='byte[] left, byte[] right = null' },
            @{ Name='param-array'; Replacement='byte[] left, params byte[] right' }
        )) {
            $replacement = $case.Replacement
            & $script:AssertR9SourceFixture `
                -Name ('authority-parameter-' + $case.Name) `
                -RelativePath $relativePath `
                -Mutate {
                    param($text)
                    $start = $text.LastIndexOf(
                        '        private static bool BytesEqual(byte[] left, byte[] right)')
                    $text.Substring(0,$start) +
                        $text.Substring($start).Replace(
                            'byte[] left, byte[] right',
                            $replacement)
                } `
                -ExpectedFailure 'authority projection A shape differs'
        }
    }

    It 'rejects an A helper that calls an unreviewed framework or Bootstrap target' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        foreach ($case in @(
            @{
                Name = 'authority-file-read'
                Insert = 'if (exception.Message.Length < 0) { System.IO.File.ReadAllBytes("r9-absent"); }'
                Expected = 'authority projection A type surface differs'
            },
            @{
                Name = 'authority-evaluate-escape'
                Insert = 'if (exception.Message.Length < 0) { TrustedControlJsonSchemaBootstrap.Evaluate("authority", null, null, null); }'
                Expected = 'authority projection A type surface differs'
            },
            @{
                Name = 'authority-unreviewed-caller-target'
                Insert = 'if (exception.Message.Length < 0) { string.Equals("x", "x", StringComparison.Ordinal); }'
            },
            @{
                Name = 'authority-self-delegate'
                Insert = 'Action<TrustedJsonObject,TrustedJsonObject,TrustedJsonObject> callback = Validate; if (exception.Message.Length < 0) { callback(null, null, null); }'
                Expected = 'authority projection A'
            }
        )) {
            $statement = $case.Insert
            & $script:AssertR9SourceFixture `
                -Name $case.Name `
                -RelativePath $relativePath `
                -Mutate {
                    param($text)
                    $text.Replace(
                        '            return exception.Message.StartsWith("authority-", StringComparison.Ordinal)',
                        "            $statement`n" +
                        '            return exception.Message.StartsWith("authority-", StringComparison.Ordinal)')
                } `
                -ExpectedFailure $(if ($case.ContainsKey('Expected')) {
                    $case.Expected
                } else { 'authority projection A call target differs' })
        }
    }

    It 'rejects a hidden Evaluate callback and an A self reference' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        & $script:AssertR9SourceFixture `
            -Name 'evaluate-self-delegate' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $text.Replace(
                    '                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);',
                    '                    Func<string,byte[],byte[],byte[],TrustedJsonResult> callback = Evaluate;' +
                    "`n                    if (authority == null) { callback(`"authority`", null, null, null); }`n" +
                    '                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);')
            } `
            -ExpectedFailure 'Bootstrap authority bridge shape differs'
    }

    It 'rejects a dormant cryptography capability in Verify and shared Bootstrap' {
        foreach ($case in @(
            @{
                Name = 'verify-dead-sha1'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                Anchor = '        private static string ToHex(byte[] bytes)'
                Code = @'
        private static object DeadSha1()
        {
            return System.Security.Cryptography.SHA1.Create();
        }

'@
                Expected = 'Verify assembly uses forbidden cryptography'
            },
            @{
                Name = 'bootstrap-crypto-interface'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
                Anchor = '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode'
                Code = @'
        private static System.Security.Cryptography.ICryptoTransform DeadCryptoTransform()
        {
            return null;
        }

'@
                Expected = 'Bootstrap assembly uses forbidden cryptography'
            },
            @{
                Name = 'verify-dead-lazy-md5'
                Relative =
                    'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
                Anchor = '        private static string ToHex(byte[] bytes)'
                Code = if ($PSVersionTable.PSEdition -eq 'Desktop') {
                    @'
#pragma warning disable 618
        private static Lazy<System.Security.Cryptography.MD5CryptoServiceProvider> DeadMd5()
        {
            return null;
        }
#pragma warning restore 618

'@
                } else {
                    @'
#pragma warning disable SYSLIB0021
        private static Lazy<System.Security.Cryptography.MD5CryptoServiceProvider> DeadMd5()
        {
            return null;
        }
#pragma warning restore SYSLIB0021

'@
                }
                Expected = 'Verify assembly uses forbidden cryptography'
            }
        )) {
            $anchor = $case.Anchor
            $code = $case.Code
            & $script:AssertR9SourceFixture `
                -Name $case.Name `
                -RelativePath $case.Relative `
                -Mutate { param($text) $text.Replace($anchor,$code + $anchor) } `
                -ExpectedFailure $case.Expected
        }
    }

    It 'checks type and method generic-parameter attributes in Verify and Bootstrap' {
        Invoke-Expression $script:r9ValidatorFunctions
        foreach ($case in @(
            @{
                Name = 'Type'
                Holder = 'public sealed class Holder<[Probe(typeof(MD5))] T> { public void Dead<TResult>() { } }'
            },
            @{
                Name = 'Method'
                Holder = 'public sealed class Holder<T> { public void Dead<[Probe(typeof(MD5))] TResult>() { } }'
            }
        )) {
            $source = @'
using System;
using System.Security.Cryptography;
namespace R9GenericAttributeCase
{
    [AttributeUsage(AttributeTargets.GenericParameter)]
    public sealed class ProbeAttribute : Attribute
    {
        public ProbeAttribute(Type capability) { }
    }
'@
            $source = $source.Replace(
                'R9GenericAttributeCase',
                'R9GenericAttribute' + $case.Name) +
                $case.Holder + "`n}"
            $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
            $flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
            $methodCount = 0
            foreach ($type in $assembly.GetTypes()) {
                $methodCount += $type.GetMethods($flags).Count +
                    $type.GetConstructors($flags).Count
            }
            {
                Assert-PspktTrustedControlAssemblyWideAuthorityIsolation `
                    -Assembly $assembly `
                    -Label Verify `
                    -MethodDefinitionCount $methodCount
            } | Should -Throw '*Verify assembly uses forbidden cryptography*'
        }
        $bootstrapSource = [IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))
        $bootstrapSource = $bootstrapSource.Replace(
            '    public sealed class TrustedJsonResult',
            @'
    [AttributeUsage(AttributeTargets.GenericParameter)]
    public sealed class R9GenericParameterAttribute : Attribute
    {
        public R9GenericParameterAttribute(Type capability) { }
    }

    public sealed class TrustedJsonResult
'@).Replace(
            '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode',
            '        private TNode Require<[R9GenericParameter(typeof(System.Security.Cryptography.MD5))] TNode>(string name) where TNode : TrustedJsonNode')
        $bootstrapPath = Join-Path $TestDrive 'R9GenericAttributeBootstrap.dll'
        Add-Type -TypeDefinition $bootstrapSource -OutputAssembly $bootstrapPath `
            -ReferencedAssemblies (Get-PspktTrustedControlFrameworkReferences)
        $bootstrapAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($bootstrapPath))
        $methodCount = 0
        foreach ($type in $bootstrapAssembly.GetTypes()) {
            $methodCount += $type.GetMethods($flags).Count +
                $type.GetConstructors($flags).Count
        }
        {
            Assert-PspktTrustedControlAssemblyWideAuthorityIsolation `
                -Assembly $bootstrapAssembly `
                -Label Bootstrap `
                -MethodDefinitionCount $methodCount `
                -SkipAuthorityImplementation
        } | Should -Throw '*Bootstrap assembly uses forbidden cryptography*'
    }

    It 'rejects open generic method targets carrying crypto or dynamic capabilities' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        foreach ($case in @(
            @{
                Name = 'generic-md5-call'
                Code = @'
        private static void DeadGenericCrypto<T>()
        {
            new Dictionary<T,System.Security.Cryptography.MD5>().Clear();
        }

'@
                Failure = 'Verify assembly uses forbidden cryptography'
            },
            @{
                Name = 'generic-expression-compile'
                Code = @'
        private static object DeadGenericDynamic<TDelegate>(
            System.Linq.Expressions.Expression<TDelegate> expression)
        {
            return expression.Compile();
        }

'@
                Failure = 'Verify assembly uses forbidden dynamic resolution'
            }
        )) {
            $code = $case.Code
            & $script:AssertR9SourceFixture `
                -Name $case.Name `
                -RelativePath $relativePath `
                -Mutate {
                    param($text)
                    $text.Replace(
                        '        private static string ToHex(byte[] bytes)',
                        $code + '        private static string ToHex(byte[] bytes)')
                } `
                -ExpectedFailure $case.Failure
        }
    }

    It 'rejects sibling and compiler-generated Bootstrap authority escapes' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
        & $script:AssertR9SourceFixture `
            -Name 'sibling-lambda-authority' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $text.Replace(
                    '        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode',
                    @'
        private sealed class SiblingProbe
        {
            internal void Touch()
            {
                Func<byte[],byte[],byte[],IDictionary<string,byte[]>> callback =
                    (first, second, third) =>
                        TrustedControlAuthorityProjectionA.Generate(first, second, third);
                callback(null, null, null);
            }
        }

        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode
'@)
            } `
            -ExpectedFailure 'Bootstrap assembly metadata references authority projection A'
    }

    It 'distinguishes constructed generic verifier dispatch targets' {
        Invoke-Expression $script:r9ValidatorFunctions
        $source = @'
namespace R9GenericDispatch
{
    public interface IProvider<T> { void Execute(); }
    public sealed class SafeProvider : IProvider<int> { public void Execute() { } }
    public sealed class UnsafeProvider : IProvider<string> { public void Execute() { } }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        $provider = $assembly.GetType('R9GenericDispatch.IProvider`1')
        $integerMethod = $provider.MakeGenericType([Type[]]@([int])).GetMethod('Execute')
        $stringMethod = $provider.MakeGenericType([Type[]]@([string])).GetMethod('Execute')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $integerMethod -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name }
        ) | Should -Be @('SafeProvider')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $stringMethod -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name }
        ) | Should -Be @('UnsafeProvider')
        (Get-PspktTrustedControlMethodIdentity -Method $integerMethod) |
            Should -Not -BeExactly (
                Get-PspktTrustedControlMethodIdentity -Method $stringMethod)
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        & $script:AssertR9SourceFixture `
            -Name 'constructed-generic-dispatch' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $text.Replace(
                    '            TrustedJsonArray declarations = context.Authority.GetArray("outputSchemas");',
                    "            new GenericBridge<int>().Run(new SafeProvider());`n" +
                    "            new GenericBridge<string>().Run(new UnsafeProvider());`n" +
                    '            TrustedJsonArray declarations = context.Authority.GetArray("outputSchemas");'
                ).Replace(
                    '        private static string ToHex(byte[] bytes)',
                    @'
        private interface IProvider<T>
        {
            void Execute();
        }

        private sealed class GenericBridge<T>
        {
            internal void Run(IProvider<T> provider)
            {
                provider.Execute();
            }
        }

        private sealed class SafeProvider : IProvider<int>
        {
            public void Execute() { }
        }

        private sealed class UnsafeProvider : IProvider<string>
        {
            public void Execute()
            {
                TrustedControlJsonSchemaBootstrap.Evaluate("authority", null, null, null);
            }
        }

        private static string ToHex(byte[] bytes)
'@)
            } `
            -ExpectedFailure 'Verifier uses a forbidden Bootstrap member: Evaluate'
    }

    It 'reaches a forbidden Bootstrap call through a closed generic class override' {
        Invoke-Expression $script:r9ValidatorFunctions
        $bootstrapAssemblyPath = Join-Path $TestDrive 'R9GraphBootstrap.dll'
        Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))) `
            -OutputAssembly $bootstrapAssemblyPath `
            -ReferencedAssemblies (Get-PspktTrustedControlFrameworkReferences)
        $bootstrapAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($bootstrapAssemblyPath))
        $verifySource = @'
namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        public static void Verify()
        {
            OverrideBase<int> provider = new OverrideDerived<int>();
            provider.Execute();
        }
        public static void VerifyVector() { }
    }

    public class OverrideBase<T>
    {
        public virtual void Execute() { }
    }

    public sealed class OverrideDerived<T> : OverrideBase<T>
    {
        public override void Execute()
        {
            TrustedControlJsonSchemaBootstrap.Evaluate(
                "authority", null, null, null);
        }
    }

    public sealed class ImpossibleOverride<T> : OverrideBase<T> where T : class
    {
        public override void Execute() { }
    }

    public sealed class NestedPossibleOverride<T> :
        OverrideBase<System.Collections.Generic.List<T>>
    {
        public override void Execute() { }
    }

    public sealed class NestedImpossibleOverride<T> :
        OverrideBase<System.Collections.Generic.List<T>> where T : class
    {
        public override void Execute() { }
    }
}
'@
        $verifyAssemblyPath = Join-Path $TestDrive 'R9GraphVerify.dll'
        $references = @($bootstrapAssemblyPath) +
            @(Get-PspktTrustedControlFrameworkReferences)
        Add-Type -TypeDefinition $verifySource `
            -OutputAssembly $verifyAssemblyPath `
            -ReferencedAssemblies $references
        $verifyAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($verifyAssemblyPath))
        $bootstrapName = $bootstrapAssembly.GetName().Name
        $resolver = [ResolveEventHandler]({
                param($sender,$assemblyName)
                if ($assemblyName.Name.StartsWith(
                    $bootstrapName + ',',[StringComparison]::Ordinal)) {
                    return $bootstrapAssembly
                }
                return $null
            }.GetNewClosure())
        [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
        try {
            $baseType = $verifyAssembly.GetType(
                'Pspkt.Certification.TrustedControl.OverrideBase`1')
            $method = $baseType.MakeGenericType([Type[]]@([int])).GetMethod('Execute')
            $targets = @(Get-PspktTrustedControlDispatchTargets `
                -Method $method -Assemblies @($verifyAssembly,$bootstrapAssembly))
            @($targets | Where-Object {
                    $_.DeclaringType.Name -ceq 'OverrideDerived`1'
                }).Count | Should -Be 1
            @($targets | Where-Object {
                    $_.DeclaringType.Name -ceq 'ImpossibleOverride`1'
                }).Count | Should -Be 1
            $nestedType = $baseType.MakeGenericType(
                [Type[]]@([Collections.Generic.List[int]]))
            $nestedTargets = @(Get-PspktTrustedControlDispatchTargets `
                -Method $nestedType.GetMethod('Execute') `
                -Assemblies @($verifyAssembly))
            @($nestedTargets | Where-Object {
                    $_.DeclaringType.Name -ceq 'NestedPossibleOverride`1'
                }).Count | Should -Be 1
            @($nestedTargets | Where-Object {
                    $_.DeclaringType.Name -ceq 'NestedImpossibleOverride`1'
                }).Count | Should -Be 1
            function Assert-PspktTrustedControlAssemblyWideAuthorityIsolation { }
            {
                Assert-PspktTrustedControlVerifierCallGraph `
                    -VerifyAssembly $verifyAssembly `
                    -BootstrapAssembly $bootstrapAssembly `
                    -VerifyMethodDefinitionCount 0 `
                    -BootstrapMethodDefinitionCount 0
            } | Should -Throw '*Verifier uses a forbidden Bootstrap member: Evaluate*'
        }
        finally {
            [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
        }
    }

    It 'skips interface types but maps inherited instance slots and rejects null targets' {
        $source = @'
namespace R13InheritedInterface
{
    public interface IParent
    {
        void Execute();
        void Ignore();
    }
    public interface IChild : IParent { }
    public interface IOther { void Execute(); }
    public sealed class Child : IChild
    {
        public void Execute() { }
        public void Ignore() { }
    }
    public sealed class Other : IOther { public void Execute() { } }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $parent = $assembly.GetType('R13InheritedInterface.IParent')
        $child = $assembly.GetType('R13InheritedInterface.Child')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $parent.GetMethod('Execute') -Assemblies @($assembly) |
                ForEach-Object { "$($_.DeclaringType.Name).$($_.Name)" }
        ) | Should -Be @('Child.Execute')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $parent.GetMethod('Ignore') -Assemblies @($assembly) |
                ForEach-Object { "$($_.DeclaringType.Name).$($_.Name)" }
        ) | Should -Be @('Child.Ignore')
        $other = $assembly.GetType('R13InheritedInterface.IOther')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $other.GetMethod('Execute') -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name }
        ) | Should -Be @('Other')
        $interfaceMap = $child.GetInterfaceMap($parent)
        $interfaceMap.TargetMethods[1] = $null
        {
            Assert-PspktTrustedControlInterfaceMapTargets `
                -InterfaceMap $interfaceMap -Implementer $child
        } | Should -Throw '*interface map has a null target*'
    }

    It 'accepts only canonical core bases of checked declarations' {
        Invoke-Expression $script:r9ValidatorFunctions
        $cleanSource = @'
namespace R13CheckedBases
{
    public class Base { public virtual void Execute() { } }
    public class Mid : Base { public override void Execute() { } }
    public sealed class Leaf : Mid { public override void Execute() { } }
    public struct Value { public int Number; }
    public enum Choice { First }
    public sealed class Fields
    {
        public int[] PacketBytes;
        public System.Func<int> Callback;
    }
}
'@
        $cleanAssembly = @(Add-Type -TypeDefinition $cleanSource -PassThru)[0].Assembly
        {
            Assert-PspktTrustedControlCheckedAssemblyShape `
                -Assembly $cleanAssembly -Label Verify
        } | Should -Not -Throw
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $cleanAssembly.GetType('R13CheckedBases.Base').GetMethod('Execute') `
                -Assemblies @($cleanAssembly) |
                ForEach-Object { $_.DeclaringType.Name } |
                Sort-Object
        ) | Should -Be @('Base','Leaf','Mid')
        foreach ($case in @(
            @{ Name='Framework'; Base='System.Collections.Generic.List<int>' },
            @{ Name='Delegate'; Base='System.MulticastDelegate' }
        )) {
            if ($case.Name -eq 'Delegate') {
                $source = 'namespace R13ExternalDelegate { public delegate void Callback(); }'
            } else {
                $source = "namespace R13ExternalFramework { public sealed class Leaf : $($case.Base) { } }"
            }
            $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
            {
                Assert-PspktTrustedControlCheckedAssemblyShape `
                    -Assembly $assembly -Label Verify
            } | Should -Throw '*unsupported external base*'
        }
        foreach ($name in @('Unmarked','Marked')) {
            $markerAssembly = $null
            $markerPath = $null
            if ($name -eq 'Marked' -and $PSVersionTable.PSEdition -eq 'Desktop') {
                $markerSource = @'
using System;
namespace System.Runtime.CompilerServices
{
    public sealed class PreserveBaseOverridesAttribute : Attribute { }
}
'@
                $markerPath = Join-Path $TestDrive 'R13ExternalMarker.dll'
                Add-Type -TypeDefinition $markerSource -OutputAssembly $markerPath
                $markerAssembly = [Reflection.Assembly]::Load(
                    [IO.File]::ReadAllBytes($markerPath))
            }
            $marker = if ($name -eq 'Marked' -and
                $PSVersionTable.PSEdition -eq 'Desktop') {
                '[System.Runtime.CompilerServices.PreserveBaseOverrides]'
            } else { '' }
            $returnType = if ($name -eq 'Marked' -and
                $PSVersionTable.PSEdition -ne 'Desktop') { 'string' } else { 'object' }
            $externalPath = Join-Path $TestDrive ("R13External$name.dll")
            $externalSource = @"
namespace R13External$name
{
    public class Base { public virtual object Execute() { return null; } }
    public class Mid : Base
    {
        $marker
        public override $returnType Execute() { return null; }
    }
}
"@
            if ($null -ne $markerPath) {
                Add-Type -TypeDefinition $externalSource -OutputAssembly $externalPath `
                    -ReferencedAssemblies @($markerPath)
            } else {
                Add-Type -TypeDefinition $externalSource -OutputAssembly $externalPath
            }
            $externalAssembly = [Reflection.Assembly]::Load(
                [IO.File]::ReadAllBytes($externalPath))
            $leafSource = "namespace R13Checked$name { public sealed class Leaf : R13External$name.Mid { public override $returnType Execute() { return null; } } }"
            $leafPath = Join-Path $TestDrive ("R13Checked$name.dll")
            $references = @($externalPath)
            if ($null -ne $markerPath) { $references += $markerPath }
            Add-Type -TypeDefinition $leafSource -OutputAssembly $leafPath `
                -ReferencedAssemblies $references
            $leafAssembly = [Reflection.Assembly]::Load(
                [IO.File]::ReadAllBytes($leafPath))
            $resolver = [ResolveEventHandler]({
                    param($sender,$assemblyName)
                    if ($assemblyName.Name.StartsWith(
                        $externalAssembly.GetName().Name + ',',
                        [StringComparison]::Ordinal)) {
                        return $externalAssembly
                    }
                    if ($null -ne $markerAssembly -and
                        $assemblyName.Name.StartsWith(
                            $markerAssembly.GetName().Name + ',',
                            [StringComparison]::Ordinal)) {
                        return $markerAssembly
                    }
                    return $null
                }.GetNewClosure())
            [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
            try {
                $mid = $externalAssembly.GetType("R13External$name.Mid")
                $leaf = $leafAssembly.GetType("R13Checked$name.Leaf")
                $markerCount = @($mid.GetMethod('Execute').CustomAttributes |
                    Where-Object { $_.AttributeType.FullName -ceq
                        'System.Runtime.CompilerServices.PreserveBaseOverridesAttribute' }).Count
                $markerCount | Should -Be $(if ($name -eq 'Marked') { 1 } else { 0 })
                @($leaf.GetMethod('Execute').CustomAttributes | Where-Object {
                    $_.AttributeType.FullName -ceq
                        'System.Runtime.CompilerServices.PreserveBaseOverridesAttribute'
                }).Count | Should -Be 0
                {
                    Assert-PspktTrustedControlCheckedAssemblyShape `
                        -Assembly $leafAssembly -Label Verify
                } | Should -Throw '*unsupported external base*'
            }
            finally {
                [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
            }
        }
    }

    It 'decodes generic explicit MethodImpl rows and rejects invalid column identities' {
        Invoke-Expression $script:r9ValidatorFunctions
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        $source = @'
using System;
using System.Collections.Generic;
namespace R13MethodImpl
{
    public interface IGeneric { void Invoke<U>(U value); }
    public sealed class Generic<T> : IComparer<T>, IDisposable, IGeneric
    {
        int IComparer<T>.Compare(T first,T second) { return 0; }
        void IDisposable.Dispose() { }
        void IGeneric.Invoke<U>(U value) { }
    }
}
'@
        $assemblyPath = Join-Path $TestDrive 'R13MethodImpl.dll'
        Add-Type -TypeDefinition $source -OutputAssembly $assemblyPath
        $bytes = [IO.File]::ReadAllBytes($assemblyPath)
        $assembly = [Reflection.Assembly]::Load($bytes)
        $rows = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
            GetMethodImplRows($bytes,'Verify')
        $rows.Count | Should -Be 3
        {
            Assert-PspktTrustedControlMethodImplRows `
                -Assembly $assembly -AssemblyBytes $bytes -Label Verify
        } | Should -Not -Throw
        $module = $assembly.ManifestModule
        $resolvedRows = @(
            foreach ($row in $rows) {
                $owner = $module.ResolveType($row.ClassToken)
                [Type[]]$typeArguments = @($owner.GetGenericArguments())
                $body = $module.ResolveMethod(
                    $row.MethodBodyToken,$typeArguments,[Type[]]@())
                [Type[]]$methodArguments = if ($body.IsGenericMethod) {
                    @($body.GetGenericArguments())
                } else { @() }
                $declaration = $module.ResolveMethod(
                    $row.MethodDeclarationToken,$typeArguments,$methodArguments)
                [pscustomobject]@{
                    Row = $row
                    Owner = $owner
                    Body = $body
                    Declaration = $declaration
                }
            }
        )
        $genericSelection = @($resolvedRows | Where-Object {
                $_.Owner.FullName -ceq 'R13MethodImpl.Generic`1' -and
                $_.Body.DeclaringType -eq $_.Owner -and
                $_.Body.Name.EndsWith('.Compare',[StringComparison]::Ordinal) -and
                $_.Declaration.DeclaringType.IsGenericType -and
                $_.Declaration.DeclaringType.GetGenericTypeDefinition() -eq
                    [Collections.Generic.IComparer[int]].GetGenericTypeDefinition() -and
                $_.Declaration.Name -ceq 'Compare'
            })
        $genericSelection.Count | Should -Be 1
        $genericRow = $genericSelection[0].Row
        $owner = $genericSelection[0].Owner
        $genericRow.ClassToken -band 0xFF000000 | Should -Be 0x02000000
        {
            $module.ResolveMethod($genericRow.MethodDeclarationToken)
        } | Should -Throw
        $resolved = $module.ResolveMethod(
            $genericRow.MethodDeclarationToken,
            [Type[]]@($owner.GetGenericArguments()),
            [Type[]]@())
        $resolved.DeclaringType.GetGenericTypeDefinition() |
            Should -Be ([Collections.Generic.IComparer[int]].
                GetGenericTypeDefinition())
        $genericMethod = @($resolvedRows | Where-Object {
                $_.Owner -eq $owner -and
                $_.Body.Name -ceq 'R13MethodImpl.IGeneric.Invoke' -and
                $_.Declaration.DeclaringType -eq
                    $assembly.GetType('R13MethodImpl.IGeneric') -and
                $_.Declaration.Name -ceq 'Invoke'
            })
        $genericMethod.Count | Should -Be 1
        $disposableSelection = @($resolvedRows | Where-Object {
                $_.Owner -eq $owner -and
                $_.Declaration.DeclaringType -eq [IDisposable] -and
                $_.Declaration.Name -ceq 'Dispose' -and
                $_.Body.DeclaringType -eq $owner
            })
        $disposableSelection.Count | Should -Be 1
        $offset = $genericRow.FileOffset
        $offset | Should -BeGreaterThan 0
        $swapped = [byte[]]$bytes.Clone()
        for ($index = 0; $index -lt 2; $index++) {
            $swapped[$offset + 2 + $index] = $bytes[$offset + 4 + $index]
            $swapped[$offset + 4 + $index] = $bytes[$offset + 2 + $index]
        }
        {
            Assert-PspktTrustedControlMethodImplRows `
                -Assembly $assembly -AssemblyBytes $swapped -Label Verify
        } | Should -Throw '*MethodImpl*'
        $mismatch = [byte[]]$bytes.Clone()
        $disposableDeclaration =
            (($disposableSelection[0].Row.MethodDeclarationToken -band 0x00FFFFFF) -shl 1) -bor 1
        $mismatch[$offset + 4] = [byte]($disposableDeclaration -band 255)
        $mismatch[$offset + 5] = [byte](($disposableDeclaration -shr 8) -band 255)
        {
            Assert-PspktTrustedControlMethodImplRows `
                -Assembly $assembly -AssemblyBytes $mismatch -Label Verify
        } | Should -Throw '*does not match its interface map*'
        $invalid = [byte[]]$bytes.Clone()
        $invalid[$offset + 2] = 255
        $invalid[$offset + 3] = 255
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                GetMethodImplRows($invalid,'Verify')
        } | Should -Throw '*MethodImpl method index is invalid*'
        $invalidClass = [byte[]]$bytes.Clone()
        $invalidClass[$offset] = 255
        $invalidClass[$offset + 1] = 255
        {
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                GetMethodImplRows($invalidClass,'Verify')
        } | Should -Throw '*MethodImpl Class is invalid*'
        {
            $owner.GetInterfaceMap([ICloneable])
        } | Should -Throw
    }

    It 'rejects a checked covariant override marker by full attribute name' {
        Invoke-Expression $script:r9ValidatorFunctions
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $attributeSource = @'
using System;
namespace System.Runtime.CompilerServices
{
    public sealed class PreserveBaseOverridesAttribute : Attribute { }
}
'@
            $attributePath = Join-Path $TestDrive 'R13CovariantAttribute.dll'
            Add-Type -TypeDefinition $attributeSource -OutputAssembly $attributePath
            $attributeAssembly = [Reflection.Assembly]::Load(
                [IO.File]::ReadAllBytes($attributePath))
            $source = @'
namespace R13OwnCovariantDesktop
{
    public class Base { public virtual object Execute() { return null; } }
    public sealed class Child : Base
    {
        [System.Runtime.CompilerServices.PreserveBaseOverrides]
        public override object Execute() { return null; }
    }
}
'@
            $checkedPath = Join-Path $TestDrive 'R13CovariantDesktop.dll'
            Add-Type -TypeDefinition $source -OutputAssembly $checkedPath `
                -ReferencedAssemblies @($attributePath)
            $assembly = [Reflection.Assembly]::Load(
                [IO.File]::ReadAllBytes($checkedPath))
            $resolver = [ResolveEventHandler]({
                    param($sender,$assemblyName)
                    if ($assemblyName.Name.StartsWith(
                        $attributeAssembly.GetName().Name + ',',
                        [StringComparison]::Ordinal)) {
                        return $attributeAssembly
                    }
                    return $null
                }.GetNewClosure())
            [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
        } else {
            $source = @'
namespace R13OwnCovariantCore
{
    public class Base { public virtual object Execute() { return null; } }
    public sealed class Child : Base
    {
        public override string Execute() { return string.Empty; }
    }
}
'@
            $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
            $resolver = $null
        }
        try {
            {
                Assert-PspktTrustedControlCheckedAssemblyShape `
                    -Assembly $assembly -Label Verify
            } | Should -Throw '*unsupported covariant override*'
        }
        finally {
            if ($null -ne $resolver) {
                [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
            }
        }
    }

    It 'rejects static abstract and virtual interface members before graph dispatch' {
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            Set-ItResult -Skipped -Because 'Windows PowerShell C# 5 cannot compile static virtual interface methods.'
            return
        }
        Invoke-Expression $script:r9ValidatorFunctions
        $source = @'
namespace R13StaticInterface
{
    public interface IStatic<T> where T : IStatic<T>
    {
        static abstract int Parse();
        static virtual int Default() { return 1; }
        static int Plain() { return 0; }
    }
    public sealed class Implementation : IStatic<Implementation>
    {
        public static int Parse() { return 1; }
    }
    public static class Caller
    {
        public static int Invoke<T>() where T : IStatic<T> { return T.Parse(); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        $interface = $assembly.GetType('R13StaticInterface.IStatic`1')
        foreach ($name in @('Parse','Default')) {
            $method = $interface.GetMethod($name)
            {
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly)
            } | Should -Throw '*unsupported static interface member*'
            {
                Assert-PspktTrustedControlCheckedAssemblyShape `
                    -Assembly $assembly -Label Verify
            } | Should -Throw '*unsupported static interface member*'
        }
        $caller = $assembly.GetType('R13StaticInterface.Caller').GetMethod('Invoke')
        $operand = @(Get-PspktTrustedControlCalledMethodReferences -Method $caller |
            Where-Object { $_.Method.Name -ceq 'Parse' })[0].Method
        {
            Assert-PspktTrustedControlSupportedInterfaceMethod `
                -Method $operand -Label 'Verify assembly IL'
        } | Should -Throw '*unsupported static interface member*'
        $externalSource = @'
using System.Numerics;
namespace R13ExternalStaticOperand
{
    public static class Caller
    {
        public static T Add<T>(T left,T right)
            where T : IAdditionOperators<T,T,T>
        {
            return left + right;
        }
    }
}
'@
        $externalAssembly = @(Add-Type -TypeDefinition $externalSource -PassThru)[0].Assembly
        $externalCaller = $externalAssembly.GetType(
            'R13ExternalStaticOperand.Caller').GetMethod('Add')
        $externalOperand = @(Get-PspktTrustedControlCalledMethodReferences `
            -Method $externalCaller | Where-Object {
                $_.Method.Name -ceq 'op_Addition'
            })[0].Method
        $externalOperand.DeclaringType.Assembly -eq $externalAssembly |
            Should -BeFalse
        {
            Assert-PspktTrustedControlSupportedInterfaceMethod `
                -Method $externalOperand -Label 'Verify assembly IL'
        } | Should -Throw '*unsupported static interface member*'
        {
            Get-PspktTrustedControlDispatchTargets `
                -Method $externalOperand -Assemblies @($externalAssembly)
        } | Should -Throw '*unsupported static interface member*'
        {
            Get-PspktTrustedControlDispatchTargets `
                -Method $interface.GetMethod('Plain') -Assemblies @($assembly)
        } | Should -Not -Throw
    }

    It 'rejects forbidden calls in deliberately overincluded open graph targets' {
        Invoke-Expression $script:r9ValidatorFunctions
        $bootstrapPath = Join-Path $TestDrive 'R13GraphBootstrap.dll'
        Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))) `
            -OutputAssembly $bootstrapPath `
            -ReferencedAssemblies (Get-PspktTrustedControlFrameworkReferences)
        $bootstrapAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($bootstrapPath))
        $bootstrapName = $bootstrapAssembly.GetName().Name
        $resolver = [ResolveEventHandler]({
                param($sender,$assemblyName)
                if ($assemblyName.Name.StartsWith(
                    $bootstrapName + ',',[StringComparison]::Ordinal)) {
                    return $bootstrapAssembly
                }
                return $null
            }.GetNewClosure())
        [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
        try {
            foreach ($case in @('Interface','Class')) {
                $source = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        public static void Verify()
        {
            IGrouping<string,int> group = null;
            if (group != null && group.Key == null) { throw new Exception(); }
            Base<int> instance = null;
            if (instance != null) { instance.Execute(); }
        }
        public static void VerifyVector() { }
    }
    public sealed class ImpossibleGroup<T> : IGrouping<T,int>
        where T : Stream, new()
    {
        public T Key
        {
            get
            {
                __GROUP_CALL__
                return default(T);
            }
        }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
    public class Base<T> { public virtual void Execute() { } }
    public sealed class ImpossibleDerived<T> : Base<T> where T : class
    {
        public override void Execute() { __CLASS_CALL__ }
    }
}
'@
                $forbidden =
                    'TrustedControlJsonSchemaBootstrap.Evaluate("authority", null, null, null);'
                $groupCall = if ($case -eq 'Interface') { $forbidden } else { '' }
                $classCall = if ($case -eq 'Class') { $forbidden } else { '' }
                $source = $source.Replace('__GROUP_CALL__',$groupCall).
                    Replace('__CLASS_CALL__',$classCall)
                $verifyPath = Join-Path $TestDrive ("R13GraphVerify$case.dll")
                Add-Type -TypeDefinition $source -OutputAssembly $verifyPath `
                    -ReferencedAssemblies (@($bootstrapPath) +
                        @(Get-PspktTrustedControlFrameworkReferences))
                $verifyAssembly = [Reflection.Assembly]::Load(
                    [IO.File]::ReadAllBytes($verifyPath))
                $key = [System.Linq.IGrouping[string,int]].
                    GetProperty('Key').GetGetMethod()
                @(
                    Get-PspktTrustedControlDispatchTargets `
                        -Method $key -Assemblies @($verifyAssembly) |
                        Where-Object { $_.DeclaringType.Name -ceq 'ImpossibleGroup`1' }
                ).Count | Should -Be 1
                $base = $verifyAssembly.GetType(
                    'Pspkt.Certification.TrustedControl.Base`1').
                    MakeGenericType([Type[]]@([int]))
                @(
                    Get-PspktTrustedControlDispatchTargets `
                        -Method $base.GetMethod('Execute') -Assemblies @($verifyAssembly) |
                        Where-Object { $_.DeclaringType.Name -ceq 'ImpossibleDerived`1' }
                ).Count | Should -Be 1
                function Assert-PspktTrustedControlAssemblyWideAuthorityIsolation { }
                {
                    Assert-PspktTrustedControlVerifierCallGraph `
                        -VerifyAssembly $verifyAssembly `
                        -BootstrapAssembly $bootstrapAssembly `
                        -VerifyMethodDefinitionCount 0 `
                        -BootstrapMethodDefinitionCount 0
                } | Should -Throw '*Verifier uses a forbidden Bootstrap member: Evaluate*'
            }
        }
        finally {
            [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
        }
    }

    It 'admits only exact Bootstrap method signatures and generic shapes' {
        Invoke-Expression $script:r9ValidatorFunctions
        $source = [IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))
        $source = $source.Replace(
            '        public static TrustedJsonNode ParseCanonical(byte[] bytes)',
            @'
        public static TrustedJsonNode ParseCanonical(int bytes) { return null; }
        public static TrustedJsonNode ParseCanonical<T>(byte[] bytes) { return null; }

        public static TrustedJsonNode ParseCanonical(byte[] bytes)
'@).Replace(
            '        public string GetString(string name)',
            @'
        public string GetString(int name) { return string.Empty; }

        public string GetString(string name)
'@)
        $assemblyPath = Join-Path $TestDrive 'R9BootstrapAdmissions.dll'
        Add-Type -TypeDefinition $source -OutputAssembly $assemblyPath `
            -ReferencedAssemblies (Get-PspktTrustedControlFrameworkReferences)
        $assembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($assemblyPath))
        $admissions = Get-PspktTrustedControlBootstrapAdmissions `
            -BootstrapAssembly $assembly
        $bootstrap = $assembly.GetType(
            'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap')
        $objectType = $assembly.GetType(
            'Pspkt.Certification.TrustedControl.TrustedJsonObject')
        $parseBytes = @($bootstrap.GetMethods() | Where-Object {
                $_.Name -ceq 'ParseCanonical' -and -not $_.IsGenericMethod -and
                $_.GetParameters().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType -eq [byte[]]
            })[0]
        $parseInteger = $bootstrap.GetMethod('ParseCanonical',[Type[]]@([int]))
        $parseGeneric = @($bootstrap.GetMethods() | Where-Object {
                $_.Name -ceq 'ParseCanonical' -and $_.IsGenericMethod
            })[0]
        $getStringInteger = $objectType.GetMethod('GetString',[Type[]]@([int]))
        $admissions.Members.ContainsKey(
            (Get-PspktTrustedControlMethodIdentity -Method $parseBytes)) |
            Should -BeTrue
        foreach ($unreviewed in @($parseInteger,$parseGeneric,$getStringInteger)) {
            $admissions.Members.ContainsKey(
                (Get-PspktTrustedControlMethodIdentity -Method $unreviewed)) |
                Should -BeFalse
        }
        $verifySource = @'
namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        public static void Verify()
        {
            TrustedControlJsonSchemaBootstrap.ParseCanonical(1);
        }
        public static void VerifyVector() { }
    }
}
'@
        $verifyAssemblyPath = Join-Path $TestDrive 'R9OverloadVerify.dll'
        $references = @($assemblyPath) +
            @(Get-PspktTrustedControlFrameworkReferences)
        Add-Type -TypeDefinition $verifySource `
            -OutputAssembly $verifyAssemblyPath `
            -ReferencedAssemblies $references
        $verifyAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($verifyAssemblyPath))
        $bootstrapName = $assembly.GetName().Name
        $resolver = [ResolveEventHandler]({
                param($sender,$assemblyName)
                if ($assemblyName.Name.StartsWith(
                    $bootstrapName + ',',[StringComparison]::Ordinal)) {
                    return $assembly
                }
                return $null
            }.GetNewClosure())
        [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
        try {
            function Assert-PspktTrustedControlAssemblyWideAuthorityIsolation { }
            {
                Assert-PspktTrustedControlVerifierCallGraph `
                    -VerifyAssembly $verifyAssembly `
                    -BootstrapAssembly $assembly `
                    -VerifyMethodDefinitionCount 0 `
                    -BootstrapMethodDefinitionCount 0
            } | Should -Throw '*Verifier uses a forbidden Bootstrap member: ParseCanonical*'
        }
        finally {
            [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
        }
    }

    It 'fails closed at the structural generic depth and node bounds' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        $deepType = 'string'
        for ($depth = 0; $depth -lt 34; $depth++) {
            $deepType = "System.Collections.Generic.List<$deepType>"
        }
        $binaryType = 'string'
        for ($depth = 0; $depth -lt 9; $depth++) {
            $binaryType =
                "System.Collections.Generic.KeyValuePair<$binaryType,$binaryType>"
        }
        foreach ($case in @(
            @{ Name = 'generic-depth-bound'; Type = $deepType },
            @{ Name = 'generic-node-bound'; Type = $binaryType }
        )) {
            $declaration = "        private static void DeadStructuralType($($case.Type) value) { }`n`n"
            & $script:AssertR9SourceFixture `
                -Name $case.Name `
                -RelativePath $relativePath `
                -Mutate {
                    param($text)
                    $text.Replace(
                        '        private static string ToHex(byte[] bytes)',
                        $declaration + '        private static string ToHex(byte[] bytes)')
                } `
                -ExpectedFailure 'structural type identity exceeded its bounds'
        }
    }

    It 'includes all same-slot open interfaces under generic constraints' {
        $source = @'
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace R9OpenInterfaceConstraints
{
    public sealed class ClassConstrainedGroup<T> : IGrouping<string,T> where T : class
    {
        public string Key { get { return string.Empty; } }
        public IEnumerator<T> GetEnumerator() { return new List<T>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class UnconstrainedGroup<T> : IGrouping<string,T>
    {
        public string Key { get { return string.Empty; } }
        public IEnumerator<T> GetEnumerator() { return new List<T>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class StructConstrainedGroup<T> : IGrouping<string,T> where T : struct
    {
        public string Key { get { return string.Empty; } }
        public IEnumerator<T> GetEnumerator() { return new List<T>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class StreamConstrainedGroup<T> : IGrouping<T,int>
        where T : System.IO.Stream, new()
    {
        public T Key { get { return new T(); } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $integerKey = [System.Linq.IGrouping[object,int]].GetProperty('Key').GetGetMethod()
        $stringKey = [System.Linq.IGrouping[object,string]].GetProperty('Key').GetGetMethod()
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $integerKey `
                -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name } |
                Sort-Object
        ) | Should -Be @(
            'ClassConstrainedGroup`1','StreamConstrainedGroup`1',
            'StructConstrainedGroup`1','UnconstrainedGroup`1')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $stringKey `
                -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name } |
                Sort-Object
        ) | Should -Be @(
            'ClassConstrainedGroup`1','StreamConstrainedGroup`1',
            'StructConstrainedGroup`1','UnconstrainedGroup`1')
    }

    It 'includes impossible open covariance and legal Stream targets' {
        $source = @'
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace R9StreamCovariance
{
    public sealed class StreamGroup<T> : IGrouping<T,int> where T : Stream, new()
    {
        public T Key { get { return new T(); } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $stringKey = [System.Linq.IGrouping[string,int]].GetProperty('Key').GetGetMethod()
        $objectKey = [System.Linq.IGrouping[object,int]].GetProperty('Key').GetGetMethod()
        $streamKey = [System.Linq.IGrouping[IO.MemoryStream,int]].GetProperty('Key').
            GetGetMethod()
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $stringKey -Assemblies @($assembly)
        ).Count | Should -Be 1
        foreach ($method in @($objectKey,$streamKey)) {
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    ForEach-Object { $_.DeclaringType.Name }
            ) | Should -Be @('StreamGroup`1')
        }
    }

    It 'includes open contravariant targets independent of constraints' {
        $source = @'
using System.Collections.Generic;
using System.IO;

namespace R9StreamContravariance
{
    public sealed class StreamComparer<T> : IComparer<T> where T : Stream, new()
    {
        public int Compare(T first, T second) { return 0; }
    }

    public sealed class ConstructorComparer<T> : IComparer<T> where T : new()
    {
        public int Compare(T first, T second) { return 0; }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        foreach ($method in @(
            [Collections.Generic.IComparer[string]].GetMethod('Compare'),
            [Collections.Generic.IComparer[object]].GetMethod('Compare')
        )) {
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    ForEach-Object { $_.DeclaringType.Name } |
                    Sort-Object
            ) | Should -Be @('ConstructorComparer`1','StreamComparer`1')
        }
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method ([Collections.Generic.IComparer[IO.MemoryStream]].
                    GetMethod('Compare')) `
                -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name } |
                Sort-Object
        ) | Should -Be @('ConstructorComparer`1','StreamComparer`1')
    }

    It 'uses open definition and slot but closed CLR mapping' {
        $source = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace R9VarianceMatrix
{
    public sealed class ArrayGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<string>
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class DelegateGroup<T> : IGrouping<T,int>
        where T : class, ICloneable
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class StreamGroup<T> : IGrouping<T,int>
        where T : Stream, new()
    {
        public T Key { get { return new T(); } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class InterfaceGroup<T> : IGrouping<T,int>
        where T : class, IDisposable
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class StructGroup<T> : IGrouping<T,int> where T : struct
    {
        public T Key { get { return default(T); } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class BoxGroup<TUnused> : IGrouping<int,int>
    {
        public int Key { get { return 0; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class BoxComparer<TUnused> : IComparer<object>
    {
        public int Compare(object left, object right) { return 0; }
    }

    public sealed class InvariantList<T> : List<T>
        where T : class, IEnumerable<string>
    {
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $groupDefinition = [System.Linq.IGrouping[object,int]].GetGenericTypeDefinition()
        $groupKey = {
            param([Type]$KeyType)
            $groupDefinition.MakeGenericType([Type[]]@($KeyType,[int])).
                GetProperty('Key').GetGetMethod()
        }
        foreach ($case in @(
            @{ Method=(& $groupKey ([object[]])); Owner='ArrayGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Func[object]])); Owner='DelegateGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([string])); Owner='StreamGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Exception])); Owner='StreamGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([IO.Stream])); Owner='StreamGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([IO.MemoryStream])); Owner='StreamGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object])); Owner='StreamGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Exception])); Owner='InterfaceGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([string])); Owner='InterfaceGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Nullable[int]])); Owner='StructGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([int])); Owner='StructGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object])); Owner='StructGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object])); Owner='BoxGroup`1'; Count=0 },
            @{ Method=(& $groupKey ([int])); Owner='BoxGroup`1'; Count=1 },
            @{ Method=[Collections.Generic.IComparer[int]].GetMethod('Compare'); Owner='BoxComparer`1'; Count=0 },
            @{ Method=[Collections.Generic.IComparer[object]].GetMethod('Compare'); Owner='BoxComparer`1'; Count=1 }
        )) {
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $case.Method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count
        }
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method ($groupDefinition.GetProperty('Key').GetGetMethod()) `
                -Assemblies @($assembly) |
                Where-Object { $_.DeclaringType.Name -ceq 'ArrayGroup`1' }
        ).Count | Should -Be 1
        $collectionDefinition =
            [Collections.Generic.ICollection[object]].GetGenericTypeDefinition()
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method ($collectionDefinition.MakeGenericType([Type[]]@([object[]])).
                    GetMethod('Add')) `
                -Assemblies @($assembly)
        ).Count | Should -Be 1
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method ($collectionDefinition.MakeGenericType([Type[]]@([string[]])).
                    GetMethod('Add')) `
                -Assemblies @($assembly)
        ).Count | Should -Be 1
        $arrayGroup = $assembly.GetType('R9VarianceMatrix.ArrayGroup`1').
            MakeGenericType([Type[]]@([string[]]))
        (& $groupKey ([object[]])).DeclaringType.IsAssignableFrom($arrayGroup) |
            Should -BeTrue
        $delegateGroup = $assembly.GetType('R9VarianceMatrix.DelegateGroup`1').
            MakeGenericType([Type[]]@([Func[string]]))
        (& $groupKey ([Func[object]])).DeclaringType.IsAssignableFrom($delegateGroup) |
            Should -BeTrue
    }

    It 'includes repeated and nested open substitutions' {
        $source = @'
using System;
using System.Collections.Generic;

namespace R9RepeatedBindings
{
    public interface IPair<TFirst,TSecond> { void Execute(); }
    public sealed class Same<T> : IPair<T,T> { public void Execute() { } }
    public interface IInvariant<TFirst,TSecond> { void Execute(); }
    public sealed class Nested<T> : IInvariant<T,List<T>>
    {
        public void Execute() { }
    }
    public interface IOut<out T> { T Read(); }
    public sealed class StructList<T> : IOut<List<T>> where T : struct
    {
        public List<T> Read() { return new List<T>(); }
    }
    public class Base<T> { public virtual void Execute() { } }
    public class Repeated<T> : Base<KeyValuePair<T,T>>
    {
        public override void Execute() { }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $pairDefinition = $assembly.GetType('R9RepeatedBindings.IPair`2')
        $invariantDefinition = $assembly.GetType('R9RepeatedBindings.IInvariant`2')
        $outDefinition = $assembly.GetType('R9RepeatedBindings.IOut`1')
        $baseDefinition = $assembly.GetType('R9RepeatedBindings.Base`1')
        $listDefinition = [Collections.Generic.List[object]].GetGenericTypeDefinition()
        $keyValueDefinition = [Collections.Generic.KeyValuePair[object,object]].
            GetGenericTypeDefinition()
        foreach ($case in @(
            @{
                Method=$pairDefinition.MakeGenericType([Type[]]@([string],[int])).
                    GetMethod('Execute'); Owner='Same`1'; Count=1
            },
            @{
                Method=$pairDefinition.MakeGenericType([Type[]]@([string],[string])).
                    GetMethod('Execute'); Owner='Same`1'; Count=1
            },
            @{
                Method=$invariantDefinition.MakeGenericType([Type[]]@(
                    [string],$listDefinition.MakeGenericType([Type[]]@([int])))).
                    GetMethod('Execute'); Owner='Nested`1'; Count=1
            },
            @{
                Method=$invariantDefinition.MakeGenericType([Type[]]@(
                    [string],$listDefinition.MakeGenericType([Type[]]@([string])))).
                    GetMethod('Execute'); Owner='Nested`1'; Count=1
            },
            @{
                Method=$outDefinition.MakeGenericType([Type[]]@(
                    $listDefinition.MakeGenericType([Type[]]@([string])))).
                    GetMethod('Read'); Owner='StructList`1'; Count=1
            },
            @{
                Method=$outDefinition.MakeGenericType([Type[]]@(
                    $listDefinition.MakeGenericType([Type[]]@([int])))).
                    GetMethod('Read'); Owner='StructList`1'; Count=1
            },
            @{
                Method=$baseDefinition.MakeGenericType([Type[]]@(
                    $keyValueDefinition.MakeGenericType([Type[]]@([string],[int])))).
                    GetMethod('Execute'); Owner='Repeated`1'; Count=1
            },
            @{
                Method=$baseDefinition.MakeGenericType([Type[]]@(
                    $keyValueDefinition.MakeGenericType([Type[]]@([string],[string])))).
                    GetMethod('Execute'); Owner='Repeated`1'; Count=1
            }
        )) {
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $case.Method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Method.DeclaringType) -> $($case.Owner)")
        }

    }

    It 'overincludes open dependent constraints' {
        $source = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace R9DependentConstraints
{
    public interface IPair<TFirst,TSecond> { void Execute(); }
    public sealed class Dependent<T,U> : IPair<T,U>
        where U : class where T : U
    {
        public void Execute() { }
    }
    public sealed class Boxed<T,U> : IPair<T,U> where T : U
    {
        public void Execute() { }
    }
    public enum EnumValue : int { Zero = 0 }
    public struct DisposableValue : IDisposable { public void Dispose() { } }
    public sealed class ComparableCross<T,U> : IPair<T,U>
        where T : IComparable<U>
    {
        public void Execute() { }
    }
    public sealed class EnumerableCross<T,U> : IPair<T,U>
        where T : IEnumerable<U>
    {
        public void Execute() { }
    }
    public sealed class Comparable<T> : IPair<T,T>
        where T : IComparable<T>
    {
        public void Execute() { }
    }
    public sealed class Enumerable<T> : IPair<T,T>
        where T : IEnumerable<T>
    {
        public void Execute() { }
    }
    public sealed class LinkedArray<T,U> : IPair<T,U>
        where U : class where T : IList<U[]>
    {
        public void Execute() { }
    }
    public sealed class Node : IEnumerable<Node>
    {
        public IEnumerator<Node> GetEnumerator() { return new List<Node>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $pairDefinition = $assembly.GetType('R9DependentConstraints.IPair`2')
        $node = $assembly.GetType('R9DependentConstraints.Node')
        foreach ($case in @(
            @{ First=[string]; Second=[IO.Stream]; Owner='Dependent`2'; Count=1 },
            @{ First=[string]; Second=[string]; Owner='Dependent`2'; Count=1 },
            @{ First=[IO.MemoryStream]; Second=[IO.Stream]; Owner='Dependent`2'; Count=1 },
            @{ First=[int]; Second=[object]; Owner='Boxed`2'; Count=1 },
            @{ First=[int]; Second=[ValueType]; Owner='Boxed`2'; Count=1 },
            @{ First=[int]; Second=[IComparable]; Owner='Boxed`2'; Count=1 },
            @{ First=$assembly.GetType('R9DependentConstraints.EnumValue'); Second=[ValueType]; Owner='Boxed`2'; Count=1 },
            @{ First=$assembly.GetType('R9DependentConstraints.DisposableValue'); Second=[IDisposable]; Owner='Boxed`2'; Count=1 },
            @{ First=[string]; Second=[int]; Owner='Boxed`2'; Count=1 },
            @{ First=[int]; Second=[int]; Owner='ComparableCross`2'; Count=1 },
            @{ First=[string]; Second=[int]; Owner='ComparableCross`2'; Count=1 },
            @{ First=[string]; Second=[char]; Owner='EnumerableCross`2'; Count=1 },
            @{ First=[string]; Second=[string]; Owner='EnumerableCross`2'; Count=1 },
            @{ First=[IO.MemoryStream]; Second=[IO.MemoryStream]; Owner='Comparable`1'; Count=1 },
            @{ First=[string]; Second=[string]; Owner='Comparable`1'; Count=1 },
            @{ First=[string]; Second=[string]; Owner='Enumerable`1'; Count=1 },
            @{ First=$node; Second=$node; Owner='Enumerable`1'; Count=1 },
            @{ First=[string[]]; Second=[string]; Owner='LinkedArray`2'; Count=1 },
            @{ First=[string[][]]; Second=[string]; Owner='LinkedArray`2'; Count=1 }
        )) {
            $method = $pairDefinition.MakeGenericType(
                [Type[]]@($case.First,$case.Second)).GetMethod('Execute')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.First),$($case.Second) -> $($case.Owner)")
        }
        $legal = $assembly.GetType('R9DependentConstraints.LinkedArray`2').
            MakeGenericType([Type[]]@([string[][]],[string]))
        $pairDefinition.MakeGenericType([Type[]]@([string[][]],[string])).
            IsAssignableFrom($legal) | Should -BeTrue

    }

    It 'includes impossible joint constraints and legal witnesses' {
        $source = @'
using System;
using System.Collections.Generic;
using System.IO;

namespace R9JointConstraints
{
    public interface IOut<out T> { T Read(); }
    public sealed class JointArray<T> : IOut<T>
        where T : class, IList<string>, IList<Uri>
    {
        public T Read() { return null; }
    }
    public sealed class CompatibleArray<T> : IOut<T>
        where T : class, IList<string>, IEnumerable<object>
    {
        public T Read() { return null; }
    }
    public sealed class EnumerableArray<T> : IOut<T>
        where T : class, IEnumerable<string>
    {
        public T Read() { return null; }
    }
    public interface IDual<out TFirst,out TSecond>
    {
        TFirst First();
        TSecond Second();
    }
    public sealed class SharedDelegate<T> : IDual<T,T>
        where T : class, ICloneable
    {
        public T First() { return null; }
        public T Second() { return null; }
    }
    public sealed class StreamComparer<T> : IComparer<T>
        where T : Stream, new()
    {
        public int Compare(T first,T second) { return 0; }
    }
    public sealed class ConstructorComparer<T> : IComparer<T> where T : new()
    {
        public int Compare(T first,T second) { return 0; }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $outDefinition = $assembly.GetType('R9JointConstraints.IOut`1')
        foreach ($case in @(
            @{ Requested=[object[]]; Owner='JointArray`1'; Count=1 },
            @{ Requested=[object]; Owner='JointArray`1'; Count=1 },
            @{ Requested=[object[]]; Owner='CompatibleArray`1'; Count=1 },
            @{ Requested=[object].MakeArrayType(1); Owner='EnumerableArray`1'; Count=1 },
            @{ Requested=[object[,]]; Owner='EnumerableArray`1'; Count=1 }
        )) {
            $method = $outDefinition.MakeGenericType(
                [Type[]]@($case.Requested)).GetMethod('Read')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Requested) -> $($case.Owner)")
        }
        $dualDefinition = $assembly.GetType('R9JointConstraints.IDual`2')
        $dualMethod = $dualDefinition.MakeGenericType([Type[]]@(
            [Func[IComparable]],[Func[ICloneable]])).GetMethod('First')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $dualMethod -Assemblies @($assembly) |
                Where-Object { $_.DeclaringType.Name -ceq 'SharedDelegate`1' }
        ).Count | Should -Be 1
        $legalDelegate = $assembly.GetType('R9JointConstraints.SharedDelegate`1').
            MakeGenericType([Type[]]@([Func[string]]))
        $dualMethod.DeclaringType.IsAssignableFrom($legalDelegate) | Should -BeTrue
        foreach ($case in @(
            @{ First=[Func[string]]; Second=[Action[string]] },
            @{ First=[Func[int]]; Second=[Func[uint32]] },
            @{ First=[string[]]; Second=[Func[string]] }
        )) {
            $requested = $dualDefinition.MakeGenericType([Type[]]@(
                $case.First,$case.Second))
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $requested.GetMethod('First') -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq 'SharedDelegate`1' }
            ).Count | Should -Be 1
        }
        foreach ($case in @(
            @{ Requested=[IO.Stream]; Owner='StreamComparer`1'; Count=1 },
            @{ Requested=[IO.MemoryStream]; Owner='StreamComparer`1'; Count=1 },
            @{ Requested=[string]; Owner='ConstructorComparer`1'; Count=1 }
        )) {
            $method = [Collections.Generic.IComparer[object]].
                GetGenericTypeDefinition().MakeGenericType(
                    [Type[]]@($case.Requested)).GetMethod('Compare')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count
        }
    }

    It 'overincludes open arrays while retaining CLR closed conversion' {
        $source = @'
using System;
using System.Collections.Generic;
using System.IO;

namespace R9ArrayConversions
{
    public enum Signed : int { Zero = 0 }
    public enum Unsigned : uint { Zero = 0 }
    public interface IOut<out T> { T Read(); }
    public interface IDual<out TFirst,out TSecond> { TFirst First(); TSecond Second(); }
    public sealed class OpenArray<T> : IOut<T[]>
    {
        public T[] Read() { return null; }
    }
    public sealed class GenericHolder<U> where U : Stream { }
    public sealed class StructHolder<U> where U : struct { }
    public sealed class ExceptionArray<T> : IOut<T[]> where T : Exception, new()
    {
        public T[] Read() { return null; }
    }
    public sealed class StreamArray<T> : IOut<T[]> where T : MemoryStream, new()
    {
        public T[] Read() { return null; }
    }
    public sealed class StructArray<T> : IOut<T[]> where T : struct
    {
        public T[] Read() { return null; }
    }
    public sealed class RefArray<T> : IOut<T[]> where T : class
    {
        public T[] Read() { return null; }
    }
    public sealed class Multidimensional<T> : IOut<T[,]>
    {
        public T[,] Read() { return null; }
    }
    public sealed class FixedUnsigned<TUnused> : IOut<uint[]>
    {
        public uint[] Read() { return null; }
    }
    public interface IMixed<out TArray,TElement> { TArray Read(); }
    public sealed class BoundArray<T> : IMixed<T[],T> where T : struct
    {
        public T[] Read() { return null; }
    }
    public interface IContravariantMixed<in TArray,TElement>
    {
        void Write(TArray value);
    }
    public sealed class BoundContravariant<T> : IContravariantMixed<T[],T>
        where T : struct
    {
        public void Write(T[] value) { }
    }
    public sealed class BoundReference<T> : IContravariantMixed<T[],T>
        where T : class
    {
        public void Write(T[] value) { }
    }
    public sealed class Repeated<T> : IDual<T,T>
    {
        public T First() { return default(T); }
        public T Second() { return default(T); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $outDefinition = $assembly.GetType('R9ArrayConversions.IOut`1')
        $dualDefinition = $assembly.GetType('R9ArrayConversions.IDual`2')
        $signed = $assembly.GetType('R9ArrayConversions.Signed').MakeArrayType()
        $unsigned = $assembly.GetType('R9ArrayConversions.Unsigned').MakeArrayType()
        foreach ($case in @(
            @{ Destination=[int[]]; Source=[uint32[]] },
            @{ Destination=[uint32[]]; Source=[int[]] },
            @{ Destination=$signed; Source=$unsigned },
            @{ Destination=$unsigned; Source=$signed }
        )) {
            $case.Destination.IsAssignableFrom($case.Source) | Should -BeTrue

        }
        foreach ($case in @(
            @{ Requested=[object]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[Array]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[Collections.IEnumerable]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[Collections.ICollection]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[Collections.IList]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[ICloneable]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[Collections.Generic.IEnumerable[string]]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[string]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[System.IO.Stream]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[IDisposable]; Owner='OpenArray`1'; Count=1 },
            @{ Requested=[Array]; Owner='Multidimensional`1'; Count=1 },
            @{ Requested=[Collections.Generic.IEnumerable[string]]; Owner='Multidimensional`1'; Count=1 },
            @{ Requested=[int[]]; Owner='FixedUnsigned`1'; Count=1 }
        )) {
            $method = $outDefinition.MakeGenericType(
                [Type[]]@($case.Requested)).GetMethod('Read')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Requested) -> $($case.Owner)")
        }
        $multidimensional = [string].MakeArrayType(1)
        foreach ($case in @(
            @{ First=[string[]]; Second=[string[,]]; Count=1 },
            @{ First=[string[]]; Second=$multidimensional; Count=1 }
        )) {
            $method = $dualDefinition.MakeGenericType([Type[]]@(
                $case.First,$case.Second)).GetMethod('First')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq 'Repeated`1' }
            ).Count | Should -Be $case.Count
        }
        $mixedDefinition = $assembly.GetType('R9ArrayConversions.IMixed`2')
        foreach ($case in @(
            @{ Element=[uint32]; Count=1 },
            @{ Element=[DayOfWeek]; Count=1 },
            @{ Element=[int]; Count=1 },
            @{ Element=[long]; Count=1 }
        )) {
            $requested = $mixedDefinition.MakeGenericType(
                [Type[]]@([int[]],$case.Element))
            $method = $requested.GetMethod('Read')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq 'BoundArray`1' }
            ).Count | Should -Be $case.Count
            if ($case.Element -ne [long]) {
                $closed = $assembly.GetType('R9ArrayConversions.BoundArray`1').
                    MakeGenericType([Type[]]@($case.Element))
                $requested.IsAssignableFrom($closed) | Should -BeTrue
            }
        }
        $contravariantDefinition =
            $assembly.GetType('R9ArrayConversions.IContravariantMixed`2')
        foreach ($case in @(
            @{ Array=[int[]]; Element=[uint32]; Owner='BoundContravariant`1'; Count=1 },
            @{ Array=[int[]]; Element=[DayOfWeek]; Owner='BoundContravariant`1'; Count=1 },
            @{ Array=[long[]]; Element=[int]; Owner='BoundContravariant`1'; Count=1 },
            @{ Array=[string[]]; Element=[object]; Owner='BoundReference`1'; Count=1 },
            @{ Array=[object[]]; Element=[string]; Owner='BoundReference`1'; Count=1 }
        )) {
            $requested = $contravariantDefinition.MakeGenericType(
                [Type[]]@($case.Array,$case.Element))
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $requested.GetMethod('Write') -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count
        }
        $streamParameter = $assembly.GetType(
            'R9ArrayConversions.GenericHolder`1').GetGenericArguments()[0]
        $structParameter = $assembly.GetType(
            'R9ArrayConversions.StructHolder`1').GetGenericArguments()[0]
        $listDefinition = [Collections.Generic.List[object]].GetGenericTypeDefinition()
        $enumerableDefinition =
            [Collections.Generic.IEnumerable[object]].GetGenericTypeDefinition()
        foreach ($case in @(
            @{
                Requested=$listDefinition.MakeGenericType([Type[]]@($streamParameter))
                Owner='OpenArray`1'; Count=1
            },
            @{
                Requested=$enumerableDefinition.MakeGenericType(
                    [Type[]]@($streamParameter)); Owner='OpenArray`1'; Count=1
            },
            @{
                Requested=$enumerableDefinition.MakeGenericType(
                    [Type[]]@($streamParameter)); Owner='ExceptionArray`1'; Count=1
            },
            @{
                Requested=$enumerableDefinition.MakeGenericType(
                    [Type[]]@($streamParameter)); Owner='StreamArray`1'; Count=1
            },
            @{
                Requested=$enumerableDefinition.MakeGenericType(
                    [Type[]]@($streamParameter)); Owner='StructArray`1'; Count=1
            },
            @{
                Requested=$enumerableDefinition.MakeGenericType(
                    [Type[]]@($structParameter)); Owner='RefArray`1'; Count=1
            }
        )) {
            $method = $outDefinition.MakeGenericType(
                [Type[]]@($case.Requested)).GetMethod('Read')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Requested) -> $($case.Owner)")
        }

    }

    It 'includes impossible open interface constructor constraints' {
        $source = @'
using System;
using System.Collections.Generic;
using System.IO;

namespace R9InterfaceConstructors
{
    public sealed class Disposable<T> : IComparer<T> where T : IDisposable, new()
    {
        public int Compare(T first,T second) { return 0; }
    }
    public sealed class Enumerable<T> : IComparer<T>
        where T : IEnumerable<string>, new()
    {
        public int Compare(T first,T second) { return 0; }
    }
    public sealed class Constructor<T> : IComparer<T> where T : new()
    {
        public int Compare(T first,T second) { return 0; }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $definition = [Collections.Generic.IComparer[object]].GetGenericTypeDefinition()
        foreach ($case in @(
            @{ Requested=[IDisposable]; Owner='Disposable`1'; Count=1 },
            @{ Requested=[Collections.Generic.IEnumerable[string]]; Owner='Enumerable`1'; Count=1 },
            @{ Requested=[IO.MemoryStream]; Owner='Disposable`1'; Count=1 },
            @{ Requested=[Collections.Generic.List[string]]; Owner='Enumerable`1'; Count=1 },
            @{ Requested=[string]; Owner='Constructor`1'; Count=1 },
            @{ Requested=[IDisposable]; Owner='Constructor`1'; Count=1 }
        )) {
            $method = $definition.MakeGenericType(
                [Type[]]@($case.Requested)).GetMethod('Compare')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Requested) -> $($case.Owner)")
        }
    }

    It 'includes repeated open contravariant bounds' {
        $source = @'
using System;
using System.IO;

namespace R9ContravariantBounds
{
    public interface IBoth<in TFirst,in TSecond>
    {
        void Visit(TFirst first,TSecond second);
    }
    public sealed class SameStream<T> : IBoth<T,T> where T : Stream, new()
    {
        public void Visit(T first,T second) { }
    }
    public sealed class Same<T> : IBoth<T,T>
    {
        public void Visit(T first,T second) { }
    }
    public class StreamA : Stream
    {
        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return 0; } }
        public override long Position { get; set; }
        public override void Flush() { }
        public override int Read(byte[] buffer,int offset,int count) { return 0; }
        public override long Seek(long offset,SeekOrigin origin) { return 0; }
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer,int offset,int count) { }
    }
    public class StreamB : Stream
    {
        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return 0; } }
        public override long Position { get; set; }
        public override void Flush() { }
        public override int Read(byte[] buffer,int offset,int count) { return 0; }
        public override long Seek(long offset,SeekOrigin origin) { return 0; }
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer,int offset,int count) { }
    }
    public sealed class StreamChildA : StreamA { }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $definition = $assembly.GetType('R9ContravariantBounds.IBoth`2')
        $streamA = $assembly.GetType('R9ContravariantBounds.StreamA')
        $streamB = $assembly.GetType('R9ContravariantBounds.StreamB')
        $streamChild = $assembly.GetType('R9ContravariantBounds.StreamChildA')
        foreach ($case in @(
            @{ First=$streamA; Second=$streamB; Count=1 },
            @{ First=$streamA; Second=$streamChild; Count=1 },
            @{ First=$streamA; Second=$streamA; Count=1 }
        )) {
            $requested = $definition.MakeGenericType(
                [Type[]]@($case.First,$case.Second))
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $requested.GetMethod('Visit') -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq 'SameStream`1' }
            ).Count | Should -Be $case.Count
        }
        foreach ($case in @(
            @{ First=[int]; Second=[string]; Count=1 },
            @{ First=[int]; Second=[long]; Count=1 },
            @{ First=[int]; Second=[int]; Count=1 }
        )) {
            $requested = $definition.MakeGenericType(
                [Type[]]@($case.First,$case.Second))
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $requested.GetMethod('Visit') -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq 'Same`1' }
            ).Count | Should -Be $case.Count
        }
        $closed = $assembly.GetType('R9ContravariantBounds.SameStream`1').
            MakeGenericType([Type[]]@($streamA))
        $definition.MakeGenericType([Type[]]@($streamA,$streamChild)).
            IsAssignableFrom($closed) | Should -BeTrue
    }

    It 'retains every constructible witness in a bounded CLR variance matrix' {
        $source = @'
using System;
using System.Collections.Generic;
using System.IO;

namespace R9DifferentialDispatch
{
    public enum Signed : int { Zero = 0 }
    public enum Unsigned : uint { Zero = 0 }
    public interface IOut<out T> { T Read(); }
    public interface IInvariant<T> { void Accept(T value); }
    public interface IPair<TFirst,TSecond> { void Execute(); }
    public sealed class Any<T> : IOut<T> { public T Read() { return default(T); } }
    public sealed class Reference<T> : IOut<T> where T : class
    {
        public T Read() { return null; }
    }
    public sealed class Value<T> : IOut<T> where T : struct
    {
        public T Read() { return default(T); }
    }
    public sealed class Constructor<T> : IOut<T> where T : new()
    {
        public T Read() { return default(T); }
    }
    public sealed class StreamValue<T> : IOut<T> where T : Stream, new()
    {
        public T Read() { return null; }
    }
    public sealed class Enumerable<T> : IOut<T>
        where T : class, IEnumerable<string>
    {
        public T Read() { return null; }
    }
    public sealed class Cloneable<T> : IOut<T> where T : class, ICloneable
    {
        public T Read() { return null; }
    }
    public sealed class Disposable<T> : IOut<T> where T : class, IDisposable
    {
        public T Read() { return null; }
    }
    public sealed class ArrayShape<T> : IOut<T[]>
    {
        public T[] Read() { return null; }
    }
    public sealed class ConstantUnsigned<TUnused> : IOut<uint[]>
    {
        public uint[] Read() { return null; }
    }
    public sealed class AnyComparer<T> : IComparer<T>
    {
        public int Compare(T first,T second) { return 0; }
    }
    public sealed class NewComparer<T> : IComparer<T> where T : new()
    {
        public int Compare(T first,T second) { return 0; }
    }
    public sealed class StreamComparer<T> : IComparer<T> where T : Stream, new()
    {
        public int Compare(T first,T second) { return 0; }
    }
    public sealed class AnyInvariant<T> : IInvariant<T>
    {
        public void Accept(T value) { }
    }
    public sealed class NestedInvariant<T> : IInvariant<List<T[]>>
    {
        public void Accept(List<T[]> value) { }
    }
    public sealed class Same<T> : IPair<T,T> { public void Execute() { } }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $listDefinition = [Collections.Generic.List[object]].GetGenericTypeDefinition()
        $typeCatalog = [Type[]]@(
            [object],[string],[Uri],[Exception],[InvalidOperationException],
            [IO.Stream],[IO.MemoryStream],[int],[uint32],[long],[DayOfWeek],[Nullable[int]],
            [object[]],[string[]],[Uri[]],[object[,]], [string[,]],
            [int[]],[uint32[]],[DayOfWeek[]],
            $assembly.GetType('R9DifferentialDispatch.Signed').MakeArrayType(),
            $assembly.GetType('R9DifferentialDispatch.Unsigned').MakeArrayType(),
            [object].MakeArrayType(1),[string].MakeArrayType(1),
            [Func[object]],[Func[string]],[ICloneable],[IDisposable],
            [Collections.Generic.IEnumerable[string]],
            $listDefinition.MakeGenericType([Type[]]@([string[]])),
            $listDefinition.MakeGenericType([Type[]]@([int[]])),
            [Array],[Delegate]
        )
        $openNames = @(
            'Any`1','Reference`1','Value`1','Constructor`1',
            'StreamValue`1','Enumerable`1','Cloneable`1','Disposable`1',
            'ArrayShape`1','ConstantUnsigned`1',
            'AnyComparer`1','NewComparer`1','StreamComparer`1',
            'AnyInvariant`1','NestedInvariant`1','Same`1')
        $constructible = [Collections.Generic.List[object]]::new()
        foreach ($name in $openNames) {
            $definition = $assembly.GetType('R9DifferentialDispatch.' + $name)
            foreach ($argument in $typeCatalog) {
                try {
                    $closed = $definition.MakeGenericType([Type[]]@($argument))
                }
                catch {
                    if ($_.Exception.GetBaseException() -isnot [ArgumentException] -and
                        $_.Exception.GetBaseException() -isnot [TypeLoadException]) {
                        throw
                    }
                    continue
                }
                $constructible.Add([pscustomobject]@{
                    Type = $closed
                    Owner = $name
                })
            }
        }
        $interfaces = @(
            @{ Definition=$assembly.GetType('R9DifferentialDispatch.IOut`1'); Method='Read' },
            @{ Definition=[Collections.Generic.IComparer[object]].GetGenericTypeDefinition(); Method='Compare' },
            @{ Definition=$assembly.GetType('R9DifferentialDispatch.IInvariant`1'); Method='Accept' }
        )
        $witnesses = 0
        $underapproximations = 0
        $missingWitnesses = [Collections.Generic.List[string]]::new()
        foreach ($entry in $interfaces) {
            foreach ($argument in $typeCatalog) {
                $requested = $entry.Definition.MakeGenericType([Type[]]@($argument))
                $targets = @(Get-PspktTrustedControlDispatchTargets `
                    -Method $requested.GetMethod($entry.Method) `
                    -Assemblies @($assembly))
                $owners = @($targets | ForEach-Object { $_.DeclaringType.Name })
                foreach ($candidate in $constructible) {
                    if (-not $requested.IsAssignableFrom($candidate.Type)) {
                        continue
                    }
                    $witnesses++
                    if ($owners -cnotcontains $candidate.Owner) {
                        $underapproximations++
                        $missingWitnesses.Add(
                            "$($requested.FullName) <- $($candidate.Type.FullName)")
                    }
                }
                $pairDefinition = $assembly.GetType('R9DifferentialDispatch.IPair`2')
                $sameDefinition = $assembly.GetType('R9DifferentialDispatch.Same`1')
                foreach ($argument in $typeCatalog) {
                    $requested = $pairDefinition.MakeGenericType(
                        [Type[]]@($argument,$argument))
                    $candidate = $sameDefinition.MakeGenericType(
                        [Type[]]@($argument))
                    if ($requested.IsAssignableFrom($candidate)) {
                        $witnesses++
                        $owners = @(Get-PspktTrustedControlDispatchTargets `
                            -Method $requested.GetMethod('Execute') -Assemblies @($assembly) |
                            ForEach-Object { $_.DeclaringType.Name })
                        if ($owners -cnotcontains 'Same`1') {
                            $underapproximations++
                            $missingWitnesses.Add(
                                "$($requested.FullName) <- $($candidate.FullName)")
                        }
                    }
                }
            }
        }
        $witnesses | Should -BeGreaterThan 200
        $underapproximations | Should -Be 0 -Because (
            $missingWitnesses.ToArray() -join '; ')
    }

    It 'includes open arrays delegates partial boxing and invariant shapes' {
        $source = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace R9VarianceClosure
{
    public sealed class DisposableException : Exception, IDisposable
    {
        public void Dispose() { }
    }

    public sealed class ArrayEnumerableGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<string>
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class ArrayDisposableElementGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<IDisposable>
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class ArrayConstructorGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<string>, new()
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class DelegateGroup<T> : IGrouping<T,int>
        where T : class, ICloneable
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class DelegateConstructorGroup<T> : IGrouping<T,int>
        where T : class, ICloneable, new()
    {
        public T Key { get { return new T(); } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class DisposableGroup<T> : IGrouping<T,int>
        where T : class, IDisposable
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class PartialGroup<TUnused> : IGrouping<int,TUnused>
    {
        public int Key { get { return 0; } }
        public IEnumerator<TUnused> GetEnumerator() { return new List<TUnused>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public interface IPartialComparer<in TKey,TValue>
    {
        void Accept(TKey key);
    }

    public sealed class PartialComparer<TUnused> : IPartialComparer<object,TUnused>
    {
        public void Accept(object key) { }
    }

    public interface IInvariant<T> { void Accept(T value); }

    public sealed class InvariantArray<T> : IInvariant<T[]>
    {
        public void Accept(T[] value) { }
    }

    public sealed class InvariantNested<T> : IInvariant<List<T[]>>
    {
        public void Accept(List<T[]> value) { }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $groupDefinition = [System.Linq.IGrouping[object,int]].GetGenericTypeDefinition()
        $groupKey = {
            param([Type]$KeyType,[Type]$ElementType)
            $groupDefinition.MakeGenericType([Type[]]@($KeyType,$ElementType)).
                GetProperty('Key').GetGetMethod()
        }
        foreach ($case in @(
            @{ Method=(& $groupKey ([object[]]) ([int])); Owner='ArrayEnumerableGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object[,]]) ([int])); Owner='ArrayEnumerableGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Exception[]]) ([int])); Owner='ArrayDisposableElementGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object[]]) ([int])); Owner='ArrayConstructorGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Func[object]]) ([int])); Owner='DelegateGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Func[object]]) ([int])); Owner='DelegateConstructorGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object[]]) ([int])); Owner='DisposableGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Func[object]]) ([int])); Owner='DisposableGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([Exception]) ([int])); Owner='DisposableGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([object]) ([string])); Owner='PartialGroup`1'; Count=1 },
            @{ Method=(& $groupKey ([int]) ([string])); Owner='PartialGroup`1'; Count=1 }
        )) {
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $case.Method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Method.DeclaringType).$($case.Method.Name) -> $($case.Owner)")
        }
        $partialDefinition = $assembly.GetType('R9VarianceClosure.IPartialComparer`2')
        foreach ($case in @(
            @{ Key=[int]; Count=1 },
            @{ Key=[string]; Count=1 }
        )) {
            $method = $partialDefinition.MakeGenericType(
                [Type[]]@($case.Key,[string])).GetMethod('Accept')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq 'PartialComparer`1' }
            ).Count | Should -Be $case.Count
        }
        $invariantDefinition = $assembly.GetType('R9VarianceClosure.IInvariant`1')
        $listDefinition = [Collections.Generic.List[object]].GetGenericTypeDefinition()
        foreach ($case in @(
            @{ Argument=[string[]]; Owner='InvariantArray`1'; Count=1 },
            @{ Argument=[string[,]]; Owner='InvariantArray`1'; Count=1 },
            @{ Argument=[string].MakeArrayType(1); Owner='InvariantArray`1'; Count=1 },
            @{ Argument=$listDefinition.MakeGenericType([Type[]]@([string[]])); Owner='InvariantNested`1'; Count=1 },
            @{ Argument=$listDefinition.MakeGenericType([Type[]]@([string[,]])); Owner='InvariantNested`1'; Count=1 },
            @{ Argument=$listDefinition.MakeGenericType([Type[]]@([int[]])); Owner='InvariantNested`1'; Count=1 }
        )) {
            $method = $invariantDefinition.MakeGenericType(
                [Type[]]@($case.Argument)).GetMethod('Accept')
            @(
                Get-PspktTrustedControlDispatchTargets `
                    -Method $method -Assemblies @($assembly) |
                    Where-Object { $_.DeclaringType.Name -ceq $case.Owner }
            ).Count | Should -Be $case.Count -Because (
                "$($case.Argument) -> $($case.Owner)")
        }
        $legalArrayGroup =
            $assembly.GetType('R9VarianceClosure.ArrayDisposableElementGroup`1').
                MakeGenericType([Type[]]@(
                    $assembly.GetType('R9VarianceClosure.DisposableException').MakeArrayType()))
        (& $groupKey ([Exception[]]) ([int])).DeclaringType.
            IsAssignableFrom($legalArrayGroup) | Should -BeTrue
    }

    It 'finds an array-covariant forbidden graph target but not boxed interface targets' {
        Invoke-Expression $script:r9ValidatorFunctions
        $bootstrapPath = Join-Path $TestDrive 'R9VarianceBootstrap.dll'
        Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))) `
            -OutputAssembly $bootstrapPath `
            -ReferencedAssemblies (Get-PspktTrustedControlFrameworkReferences)
        $bootstrapAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($bootstrapPath))
        $arraySource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        public static void Verify()
        {
            IGrouping<object[],int> group = new ArrayGroup<string[]>();
            if (group.Key == null) { throw new InvalidOperationException(); }
        }
        public static void VerifyVector() { }
    }

    public sealed class ArrayGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<string>
    {
        public T Key
        {
            get
            {
                TrustedControlJsonSchemaBootstrap.Evaluate(
                    "authority", null, null, null);
                return null;
            }
        }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
}
'@
        $boxingSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        public static void Verify()
        {
            IGrouping<object,int> group = null;
            if (group != null && group.Key != null) { throw new InvalidOperationException(); }
        }
        public static void VerifyVector()
        {
            IComparer<int> comparer = null;
            if (comparer != null) { comparer.Compare(1,2); }
        }
    }

    public sealed class BoxGroup<TUnused> : IGrouping<int,int>
    {
        public int Key
        {
            get
            {
                TrustedControlJsonSchemaBootstrap.Evaluate(
                    "authority", null, null, null);
                return 0;
            }
        }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class BoxComparer<TUnused> : IComparer<object>
    {
        public int Compare(object first, object second)
        {
            TrustedControlJsonSchemaBootstrap.Evaluate(
                "authority", null, null, null);
            return 0;
        }
    }
}
'@
        $bootstrapName = $bootstrapAssembly.GetName().Name
        $resolver = [ResolveEventHandler]({
                param($sender,$assemblyName)
                if ($assemblyName.Name.StartsWith(
                    $bootstrapName + ',',[StringComparison]::Ordinal)) {
                    return $bootstrapAssembly
                }
                return $null
            }.GetNewClosure())
        [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
        try {
            foreach ($case in @(
                @{ Name='Array'; Source=$arraySource; Forbidden=$true },
                @{ Name='Boxing'; Source=$boxingSource; Forbidden=$false }
            )) {
                $verifyPath = Join-Path $TestDrive ('R9VarianceVerify' + $case.Name + '.dll')
                Add-Type -TypeDefinition $case.Source -OutputAssembly $verifyPath `
                    -ReferencedAssemblies (@($bootstrapPath) +
                        @(Get-PspktTrustedControlFrameworkReferences))
                $verifyAssembly = [Reflection.Assembly]::Load(
                    [IO.File]::ReadAllBytes($verifyPath))
                $groupDefinition = [System.Linq.IGrouping[object,int]].
                    GetGenericTypeDefinition()
                if ($case.Forbidden) {
                    $key = $groupDefinition.MakeGenericType(
                        [Type[]]@([object[]],[int])).GetProperty('Key').GetGetMethod()
                    @(
                        Get-PspktTrustedControlDispatchTargets `
                            -Method $key -Assemblies @($verifyAssembly) |
                            Where-Object { $_.DeclaringType.Name -ceq 'ArrayGroup`1' }
                    ).Count | Should -Be 1
                } else {
                    $key = $groupDefinition.MakeGenericType(
                        [Type[]]@([object],[int])).GetProperty('Key').GetGetMethod()
                    @(
                        Get-PspktTrustedControlDispatchTargets `
                            -Method $key -Assemblies @($verifyAssembly) |
                            Where-Object { $_.DeclaringType.Name -ceq 'BoxGroup`1' }
                    ).Count | Should -Be 0
                    @(
                        Get-PspktTrustedControlDispatchTargets `
                            -Method ([Collections.Generic.IComparer[int]].GetMethod('Compare')) `
                            -Assemblies @($verifyAssembly) |
                            Where-Object { $_.DeclaringType.Name -ceq 'BoxComparer`1' }
                    ).Count | Should -Be 0
                }
                function Assert-PspktTrustedControlAssemblyWideAuthorityIsolation { }
                if ($case.Forbidden) {
                    {
                        Assert-PspktTrustedControlVerifierCallGraph `
                            -VerifyAssembly $verifyAssembly `
                            -BootstrapAssembly $bootstrapAssembly `
                            -VerifyMethodDefinitionCount 0 `
                            -BootstrapMethodDefinitionCount 0
                    } | Should -Throw '*Verifier uses a forbidden Bootstrap member: Evaluate*'
                } else {
                    {
                        Assert-PspktTrustedControlVerifierCallGraph `
                            -VerifyAssembly $verifyAssembly `
                            -BootstrapAssembly $bootstrapAssembly `
                            -VerifyMethodDefinitionCount 0 `
                            -BootstrapMethodDefinitionCount 0
                    } | Should -Not -Throw
                }
            }
        }
        finally {
            [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
        }
    }

    It 'validates viable and impossible interface paths through the unmodified graph' {
        Invoke-Expression $script:r9ValidatorFunctions
        if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
            Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                    'lib\Pspkt.Certification.TrustedControlNativeSecurity.cs'))))
        }
        $bootstrapPath = Join-Path $TestDrive 'R9UnmodifiedGraphBootstrap.dll'
        Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:sliceRoot (
                'lib\Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))) `
            -OutputAssembly $bootstrapPath `
            -ReferencedAssemblies (Get-PspktTrustedControlFrameworkReferences)
        $bootstrapAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($bootstrapPath))
        $verifySource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        public static void Verify()
        {
            IGrouping<object[],int> array = new ArrayGroup<string[]>();
            IGrouping<Func<object>,int> callback = new DelegateGroup<Func<string>>();
            if (array.Key == null || callback.Key == null) { throw new InvalidOperationException(); }
            IGrouping<object,string> boxed = null;
            IComparer<int> comparer = null;
            if (boxed != null && boxed.Key == null) { throw new InvalidOperationException(); }
            if (comparer != null) { comparer.Compare(1,2); }
        }

        public static void VerifyVector()
        {
            IGrouping<object[,],int> multidimensional = null;
            IGrouping<object[],int> arrayConstructor = null;
            IGrouping<Func<object>,int> disposableDelegate = null;
            IGrouping<Exception,int> disjointClasses = null;
            IInvariant<string[,]> invariant = null;
            IInvariant<List<string[,]>> nested = null;
            if (multidimensional != null && multidimensional.Key == null)
            {
                throw new InvalidOperationException();
            }
            if (arrayConstructor != null && arrayConstructor.Key == null)
            {
                throw new InvalidOperationException();
            }
            if (disposableDelegate != null && disposableDelegate.Key == null)
            {
                throw new InvalidOperationException();
            }
            if (disjointClasses != null && disjointClasses.Key == null)
            {
                throw new InvalidOperationException();
            }
            IPair<string,int> pair = null;
            IOut<List<string>> nestedStruct = null;
            IDependent<int,object> boxedDependency = null;
            IOut<object[]> jointArray = null;
            IOut<string> impossibleArray = null;
            IOut<System.IO.Stream> impossibleStreamArray = null;
            IOut<IDisposable> impossibleDisposableArray = null;
            IOut<int[]> primitiveArray = null;
            IComparer<System.IO.Stream> constrainedComparer = null;
            IComparer<IDisposable> interfaceConstructor = null;
            IComparer<IEnumerable<string>> enumerableConstructor = null;
            Base<KeyValuePair<string,int>> repeatedBase = null;
            if (pair != null) { pair.Execute(); }
            if (nestedStruct != null) { nestedStruct.Read(); }
            if (boxedDependency != null) { boxedDependency.Visit(); }
            if (jointArray != null) { jointArray.Read(); }
            if (impossibleArray != null) { impossibleArray.Read(); }
            if (impossibleStreamArray != null) { impossibleStreamArray.Read(); }
            if (impossibleDisposableArray != null) { impossibleDisposableArray.Read(); }
            if (primitiveArray != null) { primitiveArray.Read(); }
            if (constrainedComparer != null) { constrainedComparer.Compare(null,null); }
            if (interfaceConstructor != null) { interfaceConstructor.Compare(null,null); }
            if (enumerableConstructor != null) { enumerableConstructor.Compare(null,null); }
            if (repeatedBase != null) { repeatedBase.Execute(); }
            IOut<Array> legalArray = new OpenArray<string>();
            if (legalArray.Read() == null) { throw new InvalidOperationException(); }
            IDual<Func<IComparable>,Func<ICloneable>> shared =
                new SharedDelegate<Func<string>>();
            if (shared.First() == null) { throw new InvalidOperationException(); }
            if (invariant != null) { invariant.Accept(null); }
            if (nested != null) { nested.Accept(null); }
        }
    }

    public sealed class ArrayGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<string>
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class DelegateGroup<T> : IGrouping<T,int>
        where T : class, ICloneable
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class ArrayConstructorGroup<T> : IGrouping<T,int>
        where T : class, IEnumerable<string>, new()
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class DisposableGroup<T> : IGrouping<T,int>
        where T : class, IDisposable
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class StreamGroup<T> : IGrouping<T,int>
        where T : System.IO.Stream, new()
    {
        public T Key { get { return null; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class BoxGroup<TUnused> : IGrouping<int,TUnused>
    {
        public int Key { get { return 0; } }
        public IEnumerator<TUnused> GetEnumerator()
        {
            return new List<TUnused>().GetEnumerator();
        }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    public sealed class BoxComparer<TUnused> : IComparer<object>
    {
        public int Compare(object first, object second) { return 0; }
    }

    public interface IInvariant<T> { void Accept(T value); }

    public sealed class InvariantArray<T> : IInvariant<T[]>
    {
        public void Accept(T[] value) { }
    }

    public sealed class InvariantNested<T> : IInvariant<List<T[]>>
    {
        public void Accept(List<T[]> value) { }
    }

    public interface IPair<TFirst,TSecond> { void Execute(); }

    public sealed class PairSame<T> : IPair<T,T>
    {
        public void Execute() { }
    }

    public interface IOut<out T> { T Read(); }

    public interface IDependent<T,U> { void Visit(); }

    public sealed class BoxedDependent<T,U> : IDependent<T,U> where T : U
    {
        public void Visit() { }
    }

    public sealed class JointArray<T> : IOut<T>
        where T : class, IList<string>, IList<Uri>
    {
        public T Read() { return null; }
    }

    public sealed class OpenArray<T> : IOut<T[]>
    {
        public T[] Read() { return null; }
    }

    public sealed class ConstantUnsigned<TUnused> : IOut<uint[]>
    {
        public uint[] Read() { return null; }
    }

    public sealed class StructList<T> : IOut<List<T>> where T : struct
    {
        public List<T> Read() { return new List<T>(); }
    }

    public interface IDual<out TFirst,out TSecond>
    {
        TFirst First();
        TSecond Second();
    }

    public sealed class SharedDelegate<T> : IDual<T,T>
        where T : class, ICloneable
    {
        public T First() { return null; }
        public T Second() { return null; }
    }

    public sealed class ConstrainedComparer<T> : IComparer<T>
        where T : System.IO.Stream, new()
    {
        public int Compare(T first,T second) { return 0; }
    }

    public sealed class DisposableComparer<T> : IComparer<T>
        where T : IDisposable, new()
    {
        public int Compare(T first,T second) { return 0; }
    }

    public sealed class EnumerableComparer<T> : IComparer<T>
        where T : IEnumerable<string>, new()
    {
        public int Compare(T first,T second) { return 0; }
    }

    public class Base<T> { public virtual void Execute() { } }

    public sealed class Repeated<T> : Base<KeyValuePair<T,T>>
    {
        public override void Execute() { }
    }
}
'@
        $verifyPath = Join-Path $TestDrive 'R9UnmodifiedGraphVerify.dll'
        Add-Type -TypeDefinition $verifySource -OutputAssembly $verifyPath `
            -ReferencedAssemblies (@($bootstrapPath) +
                @(Get-PspktTrustedControlFrameworkReferences))
        $verifyAssembly = [Reflection.Assembly]::Load(
            [IO.File]::ReadAllBytes($verifyPath))
        $bootstrapName = $bootstrapAssembly.GetName().Name
        $resolver = [ResolveEventHandler]({
                param($sender,$assemblyName)
                if ($assemblyName.Name.StartsWith(
                    $bootstrapName + ',',[StringComparison]::Ordinal)) {
                    return $bootstrapAssembly
                }
                return $null
            }.GetNewClosure())
        [AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
        try {
            $bootstrapCount =
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    GetMethodDefinitionCount(
                        [IO.File]::ReadAllBytes($bootstrapPath),'Bootstrap')
            $verifyCount =
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::
                    GetMethodDefinitionCount(
                        [IO.File]::ReadAllBytes($verifyPath),'Verify')
            {
                Assert-PspktTrustedControlVerifierCallGraph `
                    -VerifyAssembly $verifyAssembly `
                    -BootstrapAssembly $bootstrapAssembly `
                    -VerifyMethodDefinitionCount $verifyCount `
                    -BootstrapMethodDefinitionCount $bootstrapCount
            } | Should -Not -Throw
        }
        finally {
            [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
        }
    }

    It 'includes nullable struct keys for open interface dispatch' {
        $source = @'
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace R9NullableStructDispatch
{
    public sealed class StructGroup<T> : IGrouping<T,int> where T : struct
    {
        public T Key { get { return default(T); } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $nullableKey = [System.Linq.IGrouping[Nullable[int],int]].
            GetProperty('Key').GetGetMethod()
        $integerKey = [System.Linq.IGrouping[int,int]].
            GetProperty('Key').GetGetMethod()
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $nullableKey -Assemblies @($assembly)
        ).Count | Should -Be 1
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $integerKey -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name }
        ) | Should -Be @('StructGroup`1')
    }

    It 'selects only compatible non-generic closed IGrouping implementations' {
        $source = @'
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace R9ClosedGroupingDispatch
{
    public sealed class BadGroup : IGrouping<string,int>
    {
        public string Key { get { return string.Empty; } }
        public IEnumerator<int> GetEnumerator() { return new List<int>().GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        Invoke-Expression $script:r9ValidatorFunctions
        $compatibleKey = [System.Linq.IGrouping[object,int]].
            GetProperty('Key').GetGetMethod()
        $incompatibleKey = [System.Linq.IGrouping[object,string]].
            GetProperty('Key').GetGetMethod()
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $compatibleKey -Assemblies @($assembly) |
                ForEach-Object { $_.DeclaringType.Name }
        ) | Should -Be @('BadGroup')
        @(
            Get-PspktTrustedControlDispatchTargets `
                -Method $incompatibleKey -Assemblies @($assembly)
        ).Count | Should -Be 0
    }

    It 'includes a covariant IGrouping key escape and excludes incompatible element types' {
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        & $script:AssertR9SourceFixture `
            -Name 'covariant-interface-dispatch' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $text.Replace(
                    '            TrustedJsonArray declarations = context.Authority.GetArray("outputSchemas");',
                    "            System.Linq.IGrouping<object,int> group = new BadGroup<int>();`n" +
                    "            if (group.Key == null) { throw new InvalidOperationException(); }`n" +
                    '            TrustedJsonArray declarations = context.Authority.GetArray("outputSchemas");'
                ).Replace(
                    '        private static string ToHex(byte[] bytes)',
                    @'
        private sealed class BadGroup<T> : System.Linq.IGrouping<string,T>
        {
            public string Key
            {
                get
                {
                    TrustedControlJsonSchemaBootstrap.Evaluate(
                        "authority", null, null, null);
                    return string.Empty;
                }
            }

            public System.Collections.Generic.IEnumerator<T> GetEnumerator()
            {
                return new List<T>().GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }
        }

        private static string ToHex(byte[] bytes)
'@)
            } `
            -ExpectedFailure 'Verifier uses a forbidden Bootstrap member: Evaluate'
        $negative = [System.Linq.IGrouping[object,string]]
        $closed = [System.Linq.IGrouping[string,int]]
        $negative.IsAssignableFrom($closed) | Should -BeFalse
    }

    It 'rejects an unexecuted Verify delegate bound to Bootstrap Evaluate' {
        Invoke-Expression $script:r9ValidatorFunctions
        $source = @'
using System;
namespace Pspkt.Certification.TrustedControl
{
    public sealed class TrustedJsonResult { }
    public static class TrustedControlJsonSchemaBootstrap
    {
        public static TrustedJsonResult Evaluate(
            string kind, byte[] first, byte[] second, byte[] third)
        {
            return null;
        }
    }
    public static class R9DelegateProbe
    {
        public static object Dead()
        {
            Func<string,byte[],byte[],byte[],TrustedJsonResult> callback =
                TrustedControlJsonSchemaBootstrap.Evaluate;
            return callback;
        }
    }
}
'@
        $assembly = @(Add-Type -TypeDefinition $source -PassThru)[0].Assembly
        $dead = $assembly.GetType(
            'Pspkt.Certification.TrustedControl.R9DelegateProbe').GetMethod('Dead')
        $evaluate = $assembly.GetType(
            'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap').
                GetMethod('Evaluate')
        $matches = @(Get-PspktTrustedControlCalledMethodReferences -Method $dead |
            Where-Object {
                $_.Operation.Name -ceq 'ldftn' -and
                (Get-PspktTrustedControlMethodIdentity -Method $_.Method) -ceq
                (Get-PspktTrustedControlMethodIdentity -Method $evaluate)
            })
        $matches.Count | Should -Be 1
        $relativePath =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        & $script:AssertR9SourceFixture `
            -Name 'verify-dead-evaluate-delegate' `
            -RelativePath $relativePath `
            -Mutate {
                param($text)
                $text.Replace(
                    '        private static string ToHex(byte[] bytes)',
                    @'
        private static object DeadEvaluateDelegate()
        {
            Func<string,byte[],byte[],byte[],TrustedJsonResult> callback =
                TrustedControlJsonSchemaBootstrap.Evaluate;
            return callback;
        }

        private static string ToHex(byte[] bytes)
'@)
            } `
            -ExpectedFailure 'Verifier uses a forbidden Bootstrap member: Evaluate'
    }

    It 'keeps the clean Verify binary free of banned names and A free of nested types' {
        (& $script:validatorPath -Mode Compile) |
            Should -BeExactly (
                'TRUSTED_CONTROL_COMPILE_OK|outputs=10|tlv=3|json=7|' +
                'verifyAuthorityReferences=0')
    }

    It 'gates the public A Generate surface before projection' {
        $fixtureRoot = Join-Path $TestDrive 'direct-a-gate'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $authorityRelative =
            'certification/trusted-control/schema/trusted-control-authority.v1.json'
        $authorityPath = Join-Path $fixtureRoot $authorityRelative.Replace('/','\')
        [IO.File]::WriteAllText(
            $authorityPath,
            [IO.File]::ReadAllText($authorityPath).Replace(
                '"activation":"Forbidden"',
                '"activation":"Allowed"'),
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($authorityRelative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*$.decisions.activation:property-value*'
    }

    It 'rejects deep acyclic and overflowing sizing in A and B deterministically' {
        foreach ($mutation in @(
            @{
                Name = 'deep'
                Old = '"fieldId":4,"name":"line","type":"U32"'
                New = '"fieldId":4,"name":"line","type":"HostInterpreterIdentityV1"'
                Reason = 'entrypoint-root-policy-ceiling'
            },
            @{
                Name = 'overflow'
                Old = '{"typeId":16,"production":"List","name":"HostToolProcessEntryPointList","elementType":"HostToolProcessEntryPointV1","minCount":0,"maxCount":64}'
                New = '{"typeId":16,"production":"List","name":"HostToolProcessEntryPointList","elementType":"HostToolProcessEntryPointV1","minCount":0,"maxCount":18446744073709551615}'
                Reason = 'entrypoint-sizing-overflow'
            },
            @{
                Name = 'depth-under-policy'
                Old = '{"fieldId":1,"name":"value","type":"BoundedBytes","maxBytes":2048}'
                New = '{"fieldId":1,"name":"value","type":"DepthLeafV1","maxBytes":2048}'
                AdditionalOld = '{"typeId":19,"production":"Named","name":"PowerShellEntryPointRegistryV1"'
                AdditionalNew = '{"typeId":20,"production":"Named","name":"DepthLeafV1","fields":[{"fieldId":1,"name":"value","type":"U8"}]},{"typeId":19,"production":"Named","name":"PowerShellEntryPointRegistryV1"'
                Reason = 'entrypoint-reviewed-sizing'
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('recursive-' + $mutation.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $authorityRelative =
                'certification/trusted-control/schema/trusted-control-authority.v1.json'
            $authorityPath = Join-Path $fixtureRoot $authorityRelative.Replace('/','\')
            $authorityText = [IO.File]::ReadAllText($authorityPath)
            ([regex]::Matches($authorityText,[regex]::Escape($mutation.Old))).Count |
                Should -Be 1
            $mutatedAuthorityText = $authorityText.Replace($mutation.Old,$mutation.New)
            if ($mutation.ContainsKey('AdditionalOld')) {
                ([regex]::Matches(
                    $mutatedAuthorityText,
                    [regex]::Escape($mutation.AdditionalOld))).Count |
                        Should -Be 1
                $mutatedAuthorityText = $mutatedAuthorityText.Replace(
                    $mutation.AdditionalOld,
                    $mutation.AdditionalNew)
            }
            [IO.File]::WriteAllText(
                $authorityPath,
                $mutatedAuthorityText,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture $fixtureRoot @($authorityRelative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*authority-$($mutation.Reason)*"
            { & $fixtureValidator -Mode Validate -RepositoryRoot $fixtureRoot } |
                Should -Throw "*verify-$($mutation.Reason)*"
        }
    }

    It 'rejects a true 65-level acyclic Named chain at the recursion safety bound' {
        $fixtureRoot = Join-Path $TestDrive 'recursive-safety-chain'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $authorityRelative =
            'certification/trusted-control/schema/trusted-control-authority.v1.json'
        $authorityPath = Join-Path $fixtureRoot $authorityRelative.Replace('/','\')
        $chainTypes = [Collections.Generic.List[string]]::new()
        foreach ($level in 1..65) {
            $fieldType = if ($level -eq 65) { 'U8' } else { 'DepthChain' + ($level + 1) }
            $chainTypes.Add(
                '{"typeId":' + (19 + $level) +
                ',"production":"Named","name":"DepthChain' + $level +
                '","fields":[{"fieldId":1,"name":"value","type":"' + $fieldType + '"}]}')
        }
        $oldRootPrefix =
            '{"typeId":19,"production":"Named","name":"PowerShellEntryPointRegistryV1","fields":[{"fieldId":1,"name":"schemaVersion","type":"U16"'
        $newRootPrefix =
            ($chainTypes.ToArray() -join ',') +
            ',{"typeId":19,"production":"Named","name":"PowerShellEntryPointRegistryV1","fields":[{"fieldId":1,"name":"schemaVersion","type":"DepthChain1"'
        $authorityText = [IO.File]::ReadAllText($authorityPath)
        ([regex]::Matches($authorityText,[regex]::Escape($oldRootPrefix))).Count |
            Should -Be 1
        [IO.File]::WriteAllText(
            $authorityPath,
            $authorityText.Replace($oldRootPrefix,$newRootPrefix),
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($authorityRelative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
            Should -Throw '*authority-entrypoint-recursion-safety-depth:65*'
        { & $fixtureValidator -Mode Validate -RepositoryRoot $fixtureRoot } |
            Should -Throw '*verify-entrypoint-recursion-safety-depth:65*'
    }

    It 'rejects policy ceiling violations before reviewed sizing mismatches in A and B' {
        foreach ($mutation in @(
            @{
                Name = 'root'
                Old = '{"typeId":16,"production":"List","name":"HostToolProcessEntryPointList","elementType":"HostToolProcessEntryPointV1","minCount":0,"maxCount":64}'
                New = '{"typeId":16,"production":"List","name":"HostToolProcessEntryPointList","elementType":"HostToolProcessEntryPointV1","minCount":0,"maxCount":128}'
                Reason = 'entrypoint-root-policy-ceiling'
            },
            @{
                Name = 'sites'
                Old = '{"fieldId":7,"name":"sourceSites","type":"SourceSiteList"}]}'
                New = '{"fieldId":7,"name":"sourceSites","type":"SourceSiteList"},{"fieldId":8,"name":"sourceSite2","type":"SourceSiteV1"},{"fieldId":9,"name":"sourceSite3","type":"SourceSiteV1"}]}'
                Reason = 'entrypoint-sites-policy-ceiling'
                Target = 'SourceSiteV1'
                ExpectedTotal = 320
            },
            @{
                Name = 'arguments'
                Old = '{"fieldId":7,"name":"sourceSites","type":"SourceSiteList"}]}'
                New = '{"fieldId":7,"name":"sourceSites","type":"SourceSiteList"},{"fieldId":8,"name":"userArguments2","type":"AlternatePowerShellArgumentList"}]}'
                AdditionalOld = '{"typeId":19,"production":"Named","name":"PowerShellEntryPointRegistryV1"'
                AdditionalNew = '{"typeId":20,"production":"List","name":"AlternatePowerShellArgumentList","elementType":"PowerShellArgumentV1","minCount":0,"maxCount":2},{"typeId":19,"production":"Named","name":"PowerShellEntryPointRegistryV1"'
                Reason = 'entrypoint-arguments-policy-ceiling'
                Target = 'PowerShellArgumentV1'
                ExpectedTotal = 256
            }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('policy-' + $mutation.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $authorityRelative =
                'certification/trusted-control/schema/trusted-control-authority.v1.json'
            $authorityPath = Join-Path $fixtureRoot $authorityRelative.Replace('/','\')
            $authorityText = [IO.File]::ReadAllText($authorityPath)
            ([regex]::Matches($authorityText,[regex]::Escape($mutation.Old))).Count |
                Should -Be 1
            $mutatedAuthorityText = $authorityText.Replace($mutation.Old,$mutation.New)
            if ($mutation.ContainsKey('AdditionalOld')) {
                ([regex]::Matches(
                    $mutatedAuthorityText,
                    [regex]::Escape($mutation.AdditionalOld))).Count |
                        Should -Be 1
                $mutatedAuthorityText = $mutatedAuthorityText.Replace(
                    $mutation.AdditionalOld,
                    $mutation.AdditionalNew)
            }
            [IO.File]::WriteAllText(
                $authorityPath,
                $mutatedAuthorityText,
                [Text.UTF8Encoding]::new($false,$true))
            if ($mutation.ContainsKey('Target')) {
                $mutatedAuthority = $mutatedAuthorityText | ConvertFrom-Json
                $entrypointOutput = @($mutatedAuthority.outputSchemas |
                    Where-Object schemaId -CEQ 'PspktPowerShellEntryPointSchemaV1')[0]
                $typeByName = @{}
                foreach ($type in $entrypointOutput.declaration.types) {
                    $typeByName[[string]$type.name] = $type
                }
                $countReachable = $null
                $countReachable = {
                    param([string]$TypeName,[int64]$Multiplier)
                    if (-not $typeByName.ContainsKey($TypeName)) { return 0L }
                    if ($TypeName -ceq $mutation.Target) { return $Multiplier }
                    $type = $typeByName[$TypeName]
                    if ($type.production -ceq 'List') {
                        $maximum = if ($type.name -ceq 'SourceSiteList') {
                            1L
                        } elseif ($type.name -ceq 'PowerShellArgumentList') {
                            2L
                        } else {
                            [int64]$type.maxCount
                        }
                        $elementMultiplier = $Multiplier * $maximum
                        return & $countReachable (
                            [string]$type.elementType) $elementMultiplier
                    }
                    if ($type.production -ceq 'Named') {
                        $result = 0L
                        foreach ($field in $type.fields) {
                            $result += & $countReachable ([string]$field.type) $Multiplier
                        }
                        return $result
                    }
                    return 0L
                }
                (& $countReachable 'PowerShellEntryPointRegistryV1' 1L) |
                    Should -Be $mutation.ExpectedTotal
            }
            & $script:RepinTrustedControlFixture $fixtureRoot @($authorityRelative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*authority-$($mutation.Reason)*"
            { & $fixtureValidator -Mode Validate -RepositoryRoot $fixtureRoot } |
                Should -Throw "*verify-$($mutation.Reason)*"
        }
    }

    It 'keeps verifier sizing gates outside vector expected-reason handling' {
        $fixtureRoot = Join-Path $TestDrive 'verify-gate-vector'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $verifyRelative =
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'
        $verifyPath = Join-Path $fixtureRoot $verifyRelative.Replace('/','\')
        [IO.File]::WriteAllText(
            $verifyPath,
            [regex]::Replace(
                [IO.File]::ReadAllText($verifyPath),
                'rootBytes\s+!= limits\.GetInteger\("entrypointReviewedRootBytes"\)',
                'rootBytes + 1UL != limits.GetInteger("entrypointReviewedRootBytes")'),
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($verifyRelative)
        $baselinePath = Join-Path $fixtureRoot (
            'certification\trusted-control\vectors\synthetic\accept-baseline.json')
        $vectorPath = Join-Path $fixtureRoot 'custom-vector.json'
        $vector = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
        $vector.expectedReason =
            'verify-entrypoint-reviewed-sizing:824/2266/2058/7690/1248/1056/640422/192/128/6'
        [IO.File]::WriteAllText(
            $vectorPath,
            ($vector | ConvertTo-Json -Depth 8 -Compress),
            [Text.UTF8Encoding]::new($false,$true))
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        { & $fixtureValidator -Mode VerifyVector -RepositoryRoot $fixtureRoot -VectorPath $vectorPath } |
            Should -Throw '*verify-entrypoint-reviewed-sizing*'
    }

    It 'rejects unpinned inventory changes through every public entry path' {
        $fixtureRoot = Join-Path $TestDrive 'unrepinned-inventory'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $inventoryPath = Join-Path $fixtureRoot 'certification\schema\protocol-inventory.v1.json'
        [IO.File]::WriteAllText(
            $inventoryPath,
            [IO.File]::ReadAllText($inventoryPath).Replace(
                '"maximumNamedDepth": 4',
                '"maximumNamedDepth": 5'),
            [Text.UTF8Encoding]::new($false,$true))
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        foreach ($mode in @('Compile','Generate','Validate')) {
            $parameters = @{
                Mode = $mode
                RepositoryRoot = $fixtureRoot
            }
            if ($mode -ceq 'Generate') {
                $parameters.OutputRoot = Join-Path $fixtureRoot 'generated'
            }
            { & $fixtureValidator @parameters } |
                Should -Throw '*pinned hash differs*protocol-inventory.v1.json*'
        }
        $vectorPath = Join-Path $fixtureRoot (
            'certification\trusted-control\vectors\synthetic\accept-baseline.json')
        { & $fixtureValidator -Mode VerifyVector -RepositoryRoot $fixtureRoot -VectorPath $vectorPath } |
            Should -Throw '*pinned hash differs*protocol-inventory.v1.json*'
    }

    It 'enforces the C# inventory hash after the PowerShell pin is advanced' {
        $fixtureRoot = Join-Path $TestDrive 'bootstrap-inventory-hash'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
            -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
        $inventoryRelative = 'certification/schema/protocol-inventory.v1.json'
        $inventoryPath = Join-Path $fixtureRoot $inventoryRelative.Replace('/','\')
        [IO.File]::WriteAllText(
            $inventoryPath,
            [IO.File]::ReadAllText($inventoryPath).Replace(
                '"maximumNamedDepth": 4',
                '"maximumNamedDepth": 5'),
            [Text.UTF8Encoding]::new($false,$true))
        & $script:RepinTrustedControlFixture $fixtureRoot @($inventoryRelative)
        $fixtureValidator = Join-Path $fixtureRoot (
            'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
        foreach ($mode in @('Compile','Generate','Validate')) {
            $parameters = @{
                Mode = $mode
                RepositoryRoot = $fixtureRoot
            }
            if ($mode -ceq 'Generate') {
                $parameters.OutputRoot = Join-Path $fixtureRoot 'generated'
            }
            $failure = $null
            try { & $fixtureValidator @parameters }
            catch { $failure = $_.Exception.ToString() }
            $failure | Should -Match 'protocol-inventory-mismatch'
            $failure | Should -Not -Match 'pinned hash differs'
        }
        $vectorPath = Join-Path $fixtureRoot (
            'certification\trusted-control\vectors\synthetic\accept-baseline.json')
        $failure = $null
        try {
            & $fixtureValidator -Mode VerifyVector -RepositoryRoot $fixtureRoot `
                -VectorPath $vectorPath
        }
        catch { $failure = $_.Exception.ToString() }
        $failure | Should -Match 'protocol-inventory-mismatch'
        $failure | Should -Not -Match 'pinned hash differs'
    }

    It 'enforces inventory hash and null parameter names through direct public APIs' {
        $fixtureRoot = Join-Path $TestDrive 'direct-public-api-inventory'
        Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
            -Destination (Join-Path $fixtureRoot 'certification') -Recurse
        $inventoryPath = Join-Path $fixtureRoot 'certification\schema\protocol-inventory.v1.json'
        $validInventoryPath = Join-Path $fixtureRoot 'protocol-inventory-valid.v1.json'
        Copy-Item -LiteralPath $inventoryPath -Destination $validInventoryPath
        [IO.File]::WriteAllText(
            $inventoryPath,
            [IO.File]::ReadAllText($inventoryPath).Replace(
                '"maximumNamedDepth": 4',
                '"maximumNamedDepth": 5'),
            [Text.UTF8Encoding]::new($false,$true))
        $probePath = Join-Path $fixtureRoot 'direct-api-probe.ps1'
        $probe = @'
param([string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'

function Get-FrameworkReferences {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return @('System.dll','System.Core.dll','System.Security.dll')
    }
    return @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' |
        ForEach-Object { $_.FullName })
}

function Get-BaseException {
    param([Exception]$Exception)
    while ($null -ne $Exception.InnerException) {
        $Exception = $Exception.InnerException
    }
    return $Exception
}

function Get-InvalidOperationException {
    param([Exception]$Exception)
    while ($null -ne $Exception -and
        -not ($Exception -is [InvalidOperationException])) {
        $Exception = $Exception.InnerException
    }
    return $Exception
}

function Assert-Message {
    param([scriptblock]$Action,[string]$Expected)
    $caught = $null
    try {
        & $Action
        throw 'Expected an exception.'
    }
    catch {
        $caught = Get-InvalidOperationException -Exception $_.Exception
    }
    if ($null -eq $caught -or $caught.Message -cne $Expected) {
        throw "Expected '$Expected' but received '$($caught.Message)'."
    }
}

function Assert-InventoryNull {
    param([scriptblock]$Action)
    $caught = $null
    try {
        & $Action
        throw 'Expected an exception.'
    }
    catch {
        $caught = Get-BaseException -Exception $_.Exception
    }
    if (-not ($caught -is [ArgumentNullException]) -or
        $caught.ParamName -cne 'inventoryBytes') {
        throw "Expected ArgumentNullException inventoryBytes but received $($caught.GetType().FullName) $($caught.ParamName)."
    }
}

$assemblyRoot = Join-Path $RepositoryRoot 'direct-api-assemblies'
[void][IO.Directory]::CreateDirectory($assemblyRoot)
$bootstrapPath = Join-Path $assemblyRoot 'Bootstrap.dll'
$authorityPath = Join-Path $assemblyRoot 'Authority.dll'
$verifyPath = Join-Path $assemblyRoot 'Verify.dll'
$framework = Get-FrameworkReferences
$sourceRoot = Join-Path $RepositoryRoot 'certification\trusted-control\lib'
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $sourceRoot (
        'Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs')))) `
    -OutputAssembly $bootstrapPath `
    -ReferencedAssemblies $framework
Add-Type -LiteralPath $bootstrapPath
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $sourceRoot (
        'Pspkt.Certification.TrustedControlAuthority.cs')))) `
    -OutputAssembly $authorityPath `
    -ReferencedAssemblies @($framework + $bootstrapPath)
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $sourceRoot (
        'Pspkt.Certification.TrustedControlVerify.cs')))) `
    -OutputAssembly $verifyPath `
    -ReferencedAssemblies @($framework + $bootstrapPath)
Add-Type -LiteralPath $authorityPath
Add-Type -LiteralPath $verifyPath

$authorityBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot (
    'certification\trusted-control\schema\trusted-control-authority.v1.json')))
$metaBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot (
    'certification\trusted-control\schema\trusted-control-json-schema-meta.v1.json')))
$inventoryBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot (
    'certification\schema\protocol-inventory.v1.json')))
$validInventoryBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot (
    'protocol-inventory-valid.v1.json')))
$vectorBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot (
    'certification\trusted-control\vectors\synthetic\accept-baseline.json')))
$empty = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)

$evaluation =
    [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'json',$authorityBytes,$null,$inventoryBytes)
if ($evaluation.Accepted -or $evaluation.Reason -cne 'protocol-inventory-mismatch') {
    throw "Evaluate reason differed: $($evaluation.Reason)"
}
$authorityText = [Text.Encoding]::UTF8.GetString($authorityBytes)
$oversizedAuthorityBytes = [Text.Encoding]::UTF8.GetBytes($authorityText.Replace(
    '{"typeId":16,"production":"List","name":"HostToolProcessEntryPointList","elementType":"HostToolProcessEntryPointV1","minCount":0,"maxCount":64}',
    '{"typeId":16,"production":"List","name":"HostToolProcessEntryPointList","elementType":"HostToolProcessEntryPointV1","minCount":0,"maxCount":128}'))
$oversizedEvaluation =
    [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'authority',$oversizedAuthorityBytes,$metaBytes,$validInventoryBytes)
if ($oversizedEvaluation.Accepted -or
    $oversizedEvaluation.Reason -cne 'authority-entrypoint-root-policy-ceiling') {
    throw "Oversized Evaluate reason differed: $($oversizedEvaluation.Reason)"
}
$shapeAuthorityBytes = [Text.Encoding]::UTF8.GetBytes($authorityText.Replace(
    '{"fieldId":7,"name":"sourceSites","type":"SourceSiteList"}]}',
    '{"fieldId":7,"name":"sourceSites","type":"SourceSiteList"},{"fieldId":8,"name":"sourceSite2","type":"SourceSiteV1"},{"fieldId":9,"name":"sourceSite3","type":"SourceSiteV1"}]}'))
$shapeEvaluation =
    [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'authority',$shapeAuthorityBytes,$metaBytes,$validInventoryBytes)
if ($shapeEvaluation.Accepted -or
    $shapeEvaluation.Reason -cne 'authority-entrypoint-sites-policy-ceiling') {
    throw "Shape Evaluate reason differed: $($shapeEvaluation.Reason)"
}
$decoyAuthorityText = [Text.Encoding]::UTF8.GetString($oversizedAuthorityBytes).Replace(
    '"schemaId":"PspktUnicodeTablesSchemaV1"',
    '"schemaId":"PspktPowerShellEntryPointSchemaV1"')
$decoyAuthorityBytes = [Text.Encoding]::UTF8.GetBytes($decoyAuthorityText)
$duplicateReason = 'duplicate-output-schema-id:PspktPowerShellEntryPointSchemaV1'
$decoyEvaluation =
    [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'authority',$decoyAuthorityBytes,$metaBytes,$validInventoryBytes)
if ($decoyEvaluation.Accepted -or $decoyEvaluation.Reason -cne $duplicateReason) {
    throw "Decoy Evaluate reason differed: $($decoyEvaluation.Reason)"
}
Assert-Message -Expected $duplicateReason -Action {
    [void][Pspkt.Certification.TrustedControl.TrustedControlAuthority]::Generate(
        $decoyAuthorityBytes,$metaBytes,$validInventoryBytes)
}
Assert-Message -Expected $duplicateReason -Action {
    [Pspkt.Certification.TrustedControl.TrustedControlVerify]::Verify(
        $decoyAuthorityBytes,$metaBytes,$validInventoryBytes,$empty)
}
Assert-Message -Expected 'protocol-inventory-mismatch' -Action {
    [void][Pspkt.Certification.TrustedControl.TrustedControlAuthority]::Generate(
        $authorityBytes,$metaBytes,$inventoryBytes)
}
Assert-Message -Expected 'protocol-inventory-mismatch' -Action {
    [Pspkt.Certification.TrustedControl.TrustedControlVerify]::Verify(
        $authorityBytes,$metaBytes,$inventoryBytes,$empty)
}
Assert-Message -Expected 'protocol-inventory-mismatch' -Action {
    [void][Pspkt.Certification.TrustedControl.TrustedControlVerify]::VerifyVector(
        $vectorBytes,$authorityBytes,$metaBytes,$inventoryBytes)
}
Assert-InventoryNull -Action {
    [void][Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'json',$authorityBytes,$null,$null)
}
Assert-InventoryNull -Action {
    [void][Pspkt.Certification.TrustedControl.TrustedControlAuthority]::Generate(
        $authorityBytes,$metaBytes,$null)
}
Assert-InventoryNull -Action {
    [Pspkt.Certification.TrustedControl.TrustedControlVerify]::Verify(
        $authorityBytes,$metaBytes,$null,$empty)
}
Assert-InventoryNull -Action {
    [void][Pspkt.Certification.TrustedControl.TrustedControlVerify]::VerifyVector(
        $vectorBytes,$authorityBytes,$metaBytes,$null)
}
'DIRECT_API_INVENTORY_OK'
'@
        [IO.File]::WriteAllText(
            $probePath,
            $probe,
            [Text.UTF8Encoding]::new($false,$true))
        $hostExecutable = Join-Path $PSHOME $(
            if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' })
        $probeOutput = & $hostExecutable -NoLogo -NoProfile -File $probePath `
            -RepositoryRoot $fixtureRoot 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($probeOutput -join [Environment]::NewLine)
        }
        $LASTEXITCODE | Should -Be 0
        @($probeOutput)[-1] | Should -BeExactly 'DIRECT_API_INVENTORY_OK'
    }

    It 'reports reviewed recursive sizing mutations independently in A and B' {
        foreach ($mutation in @(
            @{ Name = 'ascii'; Old = '"AsciiIdentifier": 128'; New = '"AsciiIdentifier": 129'; Detail = '824/2267/2058/7692/1251/1057/640806/192/128/6' },
            @{ Name = 'u64'; Old = '"U64": 8'; New = '"U64": 9'; Detail = '824/2267/2058/7691/1248/1056/640486/192/128/6' },
            @{ Name = 'sha'; Old = '"SHA-256": 32'; New = '"SHA-256": 33'; Detail = '824/2267/2058/7692/1248/1058/640678/192/128/6' }
        )) {
            $fixtureRoot = Join-Path $TestDrive ('sizing-' + $mutation.Name)
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'certification') `
                -Destination (Join-Path $fixtureRoot 'certification') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:repositoryRoot 'tests\phase4-trusted-control') `
                -Destination (Join-Path $fixtureRoot 'tests\phase4-trusted-control') -Recurse
            $inventoryRelative = 'certification/schema/protocol-inventory.v1.json'
            $inventoryPath = Join-Path $fixtureRoot $inventoryRelative.Replace('/','\')
            [IO.File]::WriteAllText(
                $inventoryPath,
                [IO.File]::ReadAllText($inventoryPath).Replace($mutation.Old,$mutation.New),
                [Text.UTF8Encoding]::new($false,$true))
            $inventoryHash = (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).
                Hash.ToLowerInvariant()
            $bootstrapRelative =
                'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'
            $bootstrapPath = Join-Path $fixtureRoot $bootstrapRelative.Replace('/','\')
            $bootstrapText = [regex]::Replace(
                [IO.File]::ReadAllText($bootstrapPath),
                'ProtocolInventorySha256 = "[0-9a-f]{64}"',
                "ProtocolInventorySha256 = `"$inventoryHash`"")
            [IO.File]::WriteAllText(
                $bootstrapPath,
                $bootstrapText,
                [Text.UTF8Encoding]::new($false,$true))
            & $script:RepinTrustedControlFixture `
                $fixtureRoot `
                @($inventoryRelative,$bootstrapRelative)
            $fixtureValidator = Join-Path $fixtureRoot (
                'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1')
            { & $fixtureValidator -Mode Compile -RepositoryRoot $fixtureRoot } |
                Should -Throw "*authority-entrypoint-reviewed-sizing:$($mutation.Detail)*"
            { & $fixtureValidator -Mode Validate -RepositoryRoot $fixtureRoot } |
                Should -Throw "*verify-entrypoint-reviewed-sizing:$($mutation.Detail)*"
        }
    }

    It 'sizes the projected entrypoint tree with an independent maximal TLV emitter' {
        $schema = Get-Content -LiteralPath (Join-Path $script:sliceRoot (
            'schema\powershell-entrypoints-schema.v1.json')) -Raw | ConvertFrom-Json
        $types = @{}
        foreach ($type in $schema.types) { $types[[string]$type.name] = $type }
        $primitiveWidths = @{
            U8 = 1L; U16 = 2L; U32 = 4L; U64 = 8L; FILETIME = 8L; QPC = 8L
            GUID = 16L; Opaque16 = 16L; FixedAscii8 = 8L; 'SHA-256' = 32L
            Opaque32 = 32L; AsciiIdentifier = 128L; BinarySid = 68L
            Utf8Short = 256L; Rsa3072PublicBlob = 512L
            Rsa3072Signature = 384L; LUID = 8L
        }
        $active = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $depthState = [pscustomobject]@{ Maximum = 0 }
        $emit = $null
        $emit = {
            param([string]$TypeName,$Field,[int]$Depth)
            if ($Depth -gt $depthState.Maximum) { $depthState.Maximum = $Depth }
            if ($TypeName -ceq 'BoundedBytes') {
                return [byte[]]::new(4 + [int64]$Field.maxBytes)
            }
            if ($primitiveWidths.ContainsKey($TypeName)) {
                return [byte[]]::new([int64]$primitiveWidths[$TypeName])
            }
            if (-not $types.ContainsKey($TypeName)) { throw "undefined:$TypeName" }
            if (-not $active.Add($TypeName)) { throw "cycle:$TypeName" }
            try {
                $type = $types[$TypeName]
                if ($type.production -ceq 'EnumU16') { return [byte[]]::new(2) }
                if ($type.production -ceq 'SemanticString') {
                    return [byte[]]::new(4 + [int64]$type.maxBytes)
                }
                if ($type.production -ceq 'List') {
                    $element = & $emit ([string]$type.elementType) $null ($Depth + 1)
                    return [byte[]]::new(4 + ([int64]$type.maxCount * (4 + $element.LongLength)))
                }
                if ($type.production -ceq 'Named') {
                    $length = 0L
                    foreach ($fieldValue in $type.fields) {
                        $payload = & $emit ([string]$fieldValue.type) $fieldValue ($Depth + 1)
                        $length += 6 + $payload.LongLength
                    }
                    return [byte[]]::new($length)
                }
                throw "production:$($type.production)"
            }
            finally {
                [void]$active.Remove($TypeName)
            }
        }
        (& $emit 'SourceSiteV1' $null 1).LongLength | Should -Be 824
        (& $emit 'HostInterpreterIdentityV1' $null 1).LongLength | Should -Be 2266
        (& $emit 'PowerShellArgumentV1' $null 1).LongLength | Should -Be 2058
        (& $emit 'HostToolProcessEntryPointV1' $null 1).LongLength | Should -Be 7690
        (& $emit 'GuestCandidateProcessEntryPointV1' $null 1).LongLength | Should -Be 1248
        (& $emit 'HostInProcessRunspaceEntryPointV1' $null 1).LongLength | Should -Be 1056
        (& $emit 'PowerShellEntryPointRegistryV1' $null 1).LongLength | Should -Be 640422
        $depthState.Maximum | Should -Be 6
    }
}
