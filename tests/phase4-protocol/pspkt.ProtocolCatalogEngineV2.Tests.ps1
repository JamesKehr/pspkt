Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Protocol schema profile fields' -Tag 'Precheck' {
    BeforeAll {
        $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $schemaBootstrapPath = Join-Path $repositoryRoot 'certification\lib\Pspkt.Certification.SchemaBootstrap.cs'
        $catalogEnginePath = Join-Path $repositoryRoot 'certification\lib\Pspkt.Certification.FoundationCatalogEngine.cs'
        $policyPath = Join-Path $repositoryRoot 'certification\lib\Pspkt.Certification.FoundationPolicy.cs'
        $metaPath = Join-Path $repositoryRoot 'certification\schema\protocol-schema-meta.v1.json'

        Add-Type -Path @($schemaBootstrapPath, $catalogEnginePath, $policyPath)
        $script:metaBytes = [IO.File]::ReadAllBytes($metaPath)
        $script:utf8 = [Text.UTF8Encoding]::new($false, $true)

        function New-TestProtocolContract {
            param(
                [int]$GeneratedFieldIdMax = 39,
                [string]$MapSchemaId = 'EmittedMapV1',
                [int]$KindRangeStart = 40000,
                [int]$KindRangeEnd = 40010,
                [string]$NamePredicate = '^[A-Z][A-Za-z0-9-]*$',
                [string]$ContractTypeName = 'ControlMessageKind',
                [int]$OverlayTypeRangeStart = 30000,
                [int]$OverlayTypeRangeEnd = 31000,
                [string[]]$LiteralExtensionParentNames = [string[]]@('Payload')
            )
            $messageEnums = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
            $messageEnums.Add('Control', $ContractTypeName)
            $directions = [Collections.Generic.Dictionary[string, string[]]]::new([StringComparer]::Ordinal)
            $directions.Add('Control', [string[]]@('HostToWorker', 'WorkerToHost'))
            $kindRanges = [Collections.Generic.Dictionary[string, Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
            $kindRanges.Add(
                'Control',
                [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]@(
                    [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(
                        $KindRangeStart,
                        $KindRangeEnd)))

            return [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]::new(
                $NamePredicate,
                'BaseCatalogV1',
                'base',
                'OverlayCatalogV1',
                'overlay',
                'EmittedSchemaV1',
                $MapSchemaId,
                [string[]]@('Control'),
                $messageEnums,
                $directions,
                $kindRanges,
                [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(
                    $OverlayTypeRangeStart,
                    $OverlayTypeRangeEnd),
                $GeneratedFieldIdMax,
                $LiteralExtensionParentNames)
        }

        function New-FieldCatalog {
            param([int]$FieldsPerType)

            $builder = [Text.StringBuilder]::new()
            [void]$builder.Append('{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Alpha","production":"Named"},{"op":"type","name":"Beta","production":"Named"}')
            foreach ($parent in @('Alpha', 'Beta')) {
                for ($index = 1; $index -le $FieldsPerType; $index++) {
                    [void]$builder.Append(',{"op":"field","parent":"')
                    [void]$builder.Append($parent)
                    [void]$builder.Append('","name":"F')
                    [void]$builder.Append($index.ToString('D4', [Globalization.CultureInfo]::InvariantCulture))
                    [void]$builder.Append('","type":"U8"}')
                }
            }
            [void]$builder.Append(']}')
            return $builder.ToString()
        }

        function New-EnumCatalog {
            param([int]$MemberCount)

            $builder = [Text.StringBuilder]::new()
            [void]$builder.Append('{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"enum","name":"Modes","members":[')
            for ($index = 0; $index -lt $MemberCount; $index++) {
                if ($index -gt 0) { [void]$builder.Append(',') }
                [void]$builder.Append('{"name":"M')
                [void]$builder.Append($index.ToString('D4', [Globalization.CultureInfo]::InvariantCulture))
                [void]$builder.Append('","value":')
                [void]$builder.Append($index.ToString([Globalization.CultureInfo]::InvariantCulture))
                [void]$builder.Append('}')
            }
            [void]$builder.Append(']}]}')
            return $builder.ToString()
        }

        function New-OneTypeFieldCatalog {
            param([int]$FieldCount)

            $builder = [Text.StringBuilder]::new()
            [void]$builder.Append('{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"}')
            for ($index = 1; $index -le $FieldCount; $index++) {
                [void]$builder.Append(',{"op":"field","parent":"Payload","name":"F')
                [void]$builder.Append($index.ToString('D4', [Globalization.CultureInfo]::InvariantCulture))
                [void]$builder.Append('","type":"U8"}')
            }
            [void]$builder.Append(']}')
            return $builder.ToString()
        }

        function Get-TestMethodSignature {
            param([Reflection.MethodInfo]$Method)

            $parameterNames = @($Method.GetParameters() | ForEach-Object { $_.ParameterType.Name })
            return '{0}({1})->{2}' -f $Method.Name, ($parameterNames -join ','), $Method.ReturnType.Name
        }

        function Get-TestConstructorSignature {
            param([Reflection.ConstructorInfo]$Constructor)

            $parameterNames = @($Constructor.GetParameters() | ForEach-Object { $_.ParameterType.Name })
            return '.ctor({0})' -f ($parameterNames -join ',')
        }

        function Get-TestPropertySignature {
            param([Reflection.PropertyInfo]$Property)

            return '{0}:{1}:write={2}' -f $Property.Name, $Property.PropertyType.Name, $Property.CanWrite
        }

        function Get-TestTypeName {
            param([Type]$Type)

            if ($Type.IsByRef) {
                return (Get-TestTypeName -Type $Type.GetElementType()) + '&'
            }
            if ($Type.IsArray) {
                return (Get-TestTypeName -Type $Type.GetElementType()) + '[]'
            }
            if ($Type.IsGenericType) {
                $genericName = $Type.GetGenericTypeDefinition().FullName
                $genericName = $genericName.Substring(0, $genericName.IndexOf('`'))
                $arguments = @($Type.GetGenericArguments() | ForEach-Object {
                    Get-TestTypeName -Type $_
                })
                return $genericName + '<' + ($arguments -join ',') + '>'
            }
            return $Type.FullName
        }

        function Get-TestTypeSurface {
            param([Type]$Type)

            $bindingFlags = [Reflection.BindingFlags]'Public,Instance,Static,DeclaredOnly'
            $surface = [Collections.Generic.List[string]]::new()
            $surface.Add((
                'TYPE|{0}|sealed={1}|abstract={2}' -f $Type.Name, $Type.IsSealed, $Type.IsAbstract))
            foreach ($constructor in $Type.GetConstructors()) {
                $parameters = @($constructor.GetParameters() | ForEach-Object {
                    Get-TestTypeName -Type $_.ParameterType
                })
                $surface.Add('CTOR|' + ($parameters -join ','))
            }
            foreach ($property in @($Type.GetProperties($bindingFlags) | Sort-Object Name)) {
                $surface.Add((
                    'PROP|{0}|{1}|write={2}' -f
                        $property.Name,
                        (Get-TestTypeName -Type $property.PropertyType),
                        $property.CanWrite))
            }
            $methodSignatures = [Collections.Generic.List[string]]::new()
            foreach ($method in @($Type.GetMethods($bindingFlags) |
                    Where-Object { -not $_.IsSpecialName })) {
                $parameters = @($method.GetParameters() | ForEach-Object {
                    Get-TestTypeName -Type $_.ParameterType
                })
                $methodSignatures.Add((
                    'METHOD|{0}|{1}|{2}' -f
                        $method.Name,
                        ($parameters -join ','),
                        (Get-TestTypeName -Type $method.ReturnType)))
            }
            $orderedMethodSignatures = $methodSignatures.ToArray()
            [Array]::Sort($orderedMethodSignatures, [StringComparer]::Ordinal)
            $surface.AddRange($orderedMethodSignatures)
            foreach ($field in @($Type.GetFields($bindingFlags) | Sort-Object Name)) {
                $surface.Add((
                    'FIELD|{0}|{1}' -f $field.Name, (Get-TestTypeName -Type $field.FieldType)))
            }
            foreach ($event in @($Type.GetEvents($bindingFlags) | Sort-Object Name)) {
                $surface.Add('EVENT|' + $event.Name)
            }
            return $surface.ToArray()
        }
    }

    It 'accepts a profile-local forbidden override' {
        $schema = '{"schemaVersion":1,"schemaId":"ProfileFields","types":[{"production":"Named","name":"Payload","typeId":1,"fields":[{"fieldId":1,"name":"Common","type":"U8"},{"fieldId":2,"name":"SeatOnly","type":"U16","profile":"InteractiveSeat","status":"Required"},{"fieldId":2,"name":"SeatOnly","type":"U16","profile":"NonInteractiveElevated","status":"Required"},{"fieldId":2,"name":"SeatOnly","type":"U16","profile":"InteractiveSeat","status":"Forbidden"}]}]}'

        $result = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
            'schema-against-meta',
            $script:utf8.GetBytes($schema),
            $script:metaBytes)

        $result.Accepted | Should -BeTrue
        $result.Reason | Should -Be 'ok'
    }

    It 'emits a minimal catalog that passes the current schema authority' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeTrue
        $result.Reason | Should -Be 'ok'
        $result.SchemaBytes | Should -Not -BeNullOrEmpty
        $result.IdMapBytes | Should -Not -BeNullOrEmpty
        $schemaResult = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
            'schema-against-meta',
            $result.SchemaBytes,
            $script:metaBytes)
        $schemaResult.Accepted | Should -BeTrue
        $schemaResult.Reason | Should -Be 'ok'
    }

    It 'resolves forbidden variants within their field set' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Common","type":"U8"},{"op":"field-set","parent":"Payload","name":"SeatValue","variants":[{"name":"SharedValue","type":"U16"},{"name":"SharedValue","type":"U16","profile":"InteractiveSeat","status":"Forbidden"},{"name":"InteractiveFallback","type":"U32","profile":"InteractiveSeat"}]}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeTrue
        $schemaResult = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
            'schema-against-meta',
            $result.SchemaBytes,
            $script:metaBytes)
        $schemaResult.Accepted | Should -BeTrue
    }

    It 'rejects cross-operation conditional shape reuse in either operation order' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
        $overlayCatalogs = @(
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"field-set","parent":"Payload","name":"SeatValue","id":40,"variants":[{"name":"SharedValue","type":"U16","profile":"InteractiveSeat"},{"name":"SharedValue","type":"U16","profile":"InteractiveSeat","status":"Forbidden"},{"name":"Fallback","type":"U8"}]},{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"SharedValue","type":"U16"}]}]}',
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"SharedValue","type":"U16"}]},{"op":"field-set","parent":"Payload","name":"SeatValue","id":40,"variants":[{"name":"SharedValue","type":"U16"},{"name":"SharedValue","type":"U16","profile":"InteractiveSeat","status":"Forbidden"},{"name":"Fallback","type":"U8"}]}]}',
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"SharedValue","type":"U16"}]},{"op":"field-set","parent":"Payload","name":"SeatValue","id":40,"variants":[{"name":"SharedValue","type":"U16"},{"name":"SharedValue","type":"U16","profile":"InteractiveSeat","status":"Forbidden"},{"name":"SharedValue","type":"U16","profile":"NonInteractiveElevated","status":"Forbidden"},{"name":"Fallback","type":"U8"}]}]}')

        foreach ($overlayCatalog in $overlayCatalogs) {
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes($baseCatalog),
                $script:utf8.GetBytes($overlayCatalog),
                (New-TestProtocolContract))

            $result.Accepted | Should -BeFalse
            $result.Reason | Should -Be 'invalid-field-condition'
            $result.SchemaBytes | Should -BeNullOrEmpty
            $result.IdMapBytes | Should -BeNullOrEmpty
        }
    }

    It 'returns a defensive reason-code snapshot' {
        $first = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::ReasonCodes()
        $conditionIndex = [Array]::IndexOf($first, 'invalid-field-condition')
        $metaIndex = [Array]::IndexOf($first, 'meta-authority-mismatch')
        $first[0] = 'changed'
        $second = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::ReasonCodes()
        $expected = @(
            'ok', 'invalid-utf8', 'bom-forbidden', 'nul-forbidden', 'comment-forbidden',
            'duplicate-key', 'trailing-comma', 'trailing-data', 'float-forbidden',
            'exponent-forbidden', 'negative-integer', 'leading-zero-integer',
            'integer-overflow', 'invalid-escape', 'unpaired-surrogate',
            'replacement-character-forbidden', 'file-limit', 'depth-limit',
            'property-limit', 'array-limit', 'string-limit', 'allocation-budget',
            'unknown-property', 'missing-property', 'duplicate-identifier',
            'unknown-primitive', 'undefined-reference', 'type-cycle',
            'duplicate-type-id', 'duplicate-field-id', 'field-order',
            'invalid-cardinality', 'bound-overflow', 'non-ascii-symbol',
            'meta-authority-mismatch', 'invalid-field-condition', 'extra-key',
            'op-unknown', 'op-replace-forbidden', 'op-source-forbidden',
            'catalog-identity', 'catalog-name', 'base-literal-id',
            'primitive-forbidden', 'invalid-production', 'invalid-profile',
            'invalid-tail-class', 'invalid-state-association', 'invalid-direction',
            'invalid-channel', 'field-undefined-parent', 'extend-invalid-parent',
            'extension-parent-forbidden', 'undefined-payload-root', 'delete-unknown',
            'delete-double', 'delete-then-use', 'reserve-missing-literal',
            'reserve-id-out-of-range', 'reserve-illegal-encoded',
            'overlay-id-out-of-range', 'enum-duplicate-name', 'enum-duplicate-value',
            'enum-value-overflow', 'union-empty', 'union-duplicate-branch',
            'extend-missing-literal', 'extend-dup-name', 'extend-dup-id',
            'message-metadata-conflict', 'duplicate-kind', 'duplicate-field-set',
            'field-overflow', 'reserved-kind-range', 'reserved-type-range',
            'generated-id-overflow', 'id-map-drift', 'map-tamper')

        $conditionIndex | Should -Be ($metaIndex + 1)
        $second[0] | Should -Be 'ok'
        $second | Should -Be $expected
    }

    It 'rejects malformed predicates and invalid emitted schema identifiers' {
        { [regex]::new('A)|(B') } | Should -Throw

        $messageEnums = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
        $messageEnums.Add('Control', 'ControlMessageKind')
        $directions = [Collections.Generic.Dictionary[string, string[]]]::new([StringComparer]::Ordinal)
        $directions.Add('Control', [string[]]@('HostToWorker'))
        $kindRanges = [Collections.Generic.Dictionary[string, Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
        $kindRanges.Add('Control', [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]@())

        $predicateException = $null
        try {
            [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]::new(
                'A)|(B',
                'BaseCatalogV1',
                'base',
                'OverlayCatalogV1',
                'overlay',
                'EmittedSchemaV1',
                'EmittedMapV1',
                [string[]]@('Control'),
                $messageEnums,
                $directions,
                $kindRanges,
                [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(30000, 31000),
                39,
                [string[]]@('Payload'))
        }
        catch {
            $predicateException = $_.Exception
        }
        $predicateException | Should -BeOfType ([Management.Automation.MethodInvocationException])
        $predicateException.InnerException | Should -BeOfType ([ArgumentException])
        $predicateException.InnerException.ParamName | Should -Be 'namePredicate'

        $schemaIdException = $null
        try {
            [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]::new(
                '^[A-Z][A-Za-z0-9-]*$',
                'BaseCatalogV1',
                'base',
                'OverlayCatalogV1',
                'overlay',
                'Bad_Id',
                'EmittedMapV1',
                [string[]]@('Control'),
                $messageEnums,
                $directions,
                $kindRanges,
                [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(30000, 31000),
                39,
                [string[]]@('Payload'))
        }
        catch {
            $schemaIdException = $_.Exception
        }
        $schemaIdException | Should -BeOfType ([Management.Automation.MethodInvocationException])
        $schemaIdException.InnerException | Should -BeOfType ([ArgumentException])
        $schemaIdException.InnerException.ParamName | Should -Be 'emitSchemaId'
    }

    It 'records an overlay message literal kind in the replay map' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-message","id":40000,"channel":"Control","direction":"HostToWorker","name":"Notify","payloadRoot":"Payload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))
        $result.Accepted | Should -BeTrue -Because $result.Reason
        $map = $script:utf8.GetString($result.IdMapBytes) | ConvertFrom-Json
        $kindRow = @($map | Where-Object { $_.category -ceq 'kind' })[0]

        $kindRow.catalog | Should -Be 'overlay'
        $kindRow.generatedId | Should -Be 40000
        $kindRow.name | Should -Be 'Notify'
    }

    It 'makes every accepted map row replay authoritative' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $contract = New-TestProtocolContract
        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $contract)
        $exactReplay = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Replay(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $result.SchemaBytes,
            $result.IdMapBytes,
            $contract)
        $changedSchema = $script:utf8.GetBytes(
            $script:utf8.GetString($result.SchemaBytes).Replace('EmittedSchemaV1', 'ChangedSchemaV1'))
        $schemaReplay = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Replay(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $changedSchema,
            $result.IdMapBytes,
            $contract)
        $map = $script:utf8.GetString($result.IdMapBytes) | ConvertFrom-Json
        $map[0].generatedId = [int]$map[0].generatedId + 1
        $changedMap = $script:utf8.GetBytes(($map | ConvertTo-Json -Compress -Depth 10))
        $mapReplay = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Replay(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $result.SchemaBytes,
            $changedMap,
            $contract)

        $exactReplay.Accepted | Should -BeTrue
        $schemaReplay.Accepted | Should -BeFalse
        $schemaReplay.Reason | Should -Be 'id-map-drift'
        $mapReplay.Accepted | Should -BeFalse
        $mapReplay.Reason | Should -Be 'map-tamper'
    }

    It 'rejects semantic strings that the schema authority cannot encode' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"BadText","production":"SemanticString","encoding":"Utf8","grammar":"None","minBytes":4,"maxBytes":100,"maxUtf16CodeUnits":1}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeFalse
        $result.Reason | Should -Be 'invalid-cardinality'
    }

    It 'checks raw opaque bounds before forbidden subtraction' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field-set","parent":"Payload","name":"ConditionalValue","variants":[{"name":"HugeValue","type":"OpaqueUtf16","maxCodeUnits":2147483646},{"name":"HugeValue","type":"OpaqueUtf16","maxCodeUnits":2147483646,"profile":"InteractiveSeat","status":"Forbidden"},{"name":"HugeValue","type":"OpaqueUtf16","maxCodeUnits":2147483646,"profile":"NonInteractiveElevated","status":"Forbidden"},{"name":"Fallback","type":"U8"}]}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeFalse
        $result.Reason | Should -Be 'bound-overflow'
    }

    It 'parses bounded byte limits across the unsigned 32-bit range' {
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        foreach ($maximum in [uint64[]]@(2147483647, 2147483648, 4294967291)) {
            $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"BoundedBytes","maxBytes":' + $maximum + '}]}'
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes($baseCatalog),
                $script:utf8.GetBytes($overlayCatalog),
                (New-TestProtocolContract))

            $result.Accepted | Should -BeTrue -Because ('maxBytes {0} is encodable' -f $maximum)
            ([uint64](($script:utf8.GetString($result.SchemaBytes) | ConvertFrom-Json).types[0].fields[0].maxBytes)) |
                Should -Be $maximum
        }

        $overflowCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"BoundedBytes","maxBytes":4294967292}]}'
        $overflow = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($overflowCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $overflow.Accepted | Should -BeFalse
        $overflow.Reason | Should -Be 'bound-overflow'

        $integerOverflowCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"BoundedBytes","maxBytes":4294967296}]}'
        $integerOverflow = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($integerOverflowCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $integerOverflow.Accepted | Should -BeFalse
        $integerOverflow.Reason | Should -Be 'integer-overflow'
    }

    It 'parses semantic string limits beyond the signed 32-bit range' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"LargeText","production":"SemanticString","encoding":"Utf8","grammar":"None","minBytes":1,"maxBytes":2147483648,"maxUtf16CodeUnits":2147483648}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeTrue -Because $result.Reason
        $emitted = ($script:utf8.GetString($result.SchemaBytes) | ConvertFrom-Json).types[0]
        ([uint64]$emitted.maxBytes) | Should -Be 2147483648
        ([uint64]$emitted.maxUtf16CodeUnits) | Should -Be 2147483648
    }

    It 'exposes only the pinned V2 public API' {
        $bindingFlags = [Reflection.BindingFlags]'Public,Instance,Static,DeclaredOnly'
        $contractType = [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]
        $resultType = [Pspkt.Certification.FoundationEngine.ProtocolCatalogResultV2]
        $engineType = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]
        $contractProperties = @(
            $contractType.GetProperties($bindingFlags) |
                ForEach-Object { Get-TestPropertySignature -Property $_ } |
                Sort-Object)
        $resultProperties = @(
            $resultType.GetProperties($bindingFlags) |
                ForEach-Object { Get-TestPropertySignature -Property $_ } |
                Sort-Object)
        $engineMethods = @(
            $engineType.GetMethods($bindingFlags) |
                Where-Object { -not $_.IsSpecialName } |
                ForEach-Object { Get-TestMethodSignature -Method $_ } |
                Sort-Object)
        $contractConstructor = Get-TestConstructorSignature -Constructor $contractType.GetConstructors()[0]

        $contractType.IsSealed | Should -BeTrue
        $contractType.IsAbstract | Should -BeFalse
        @($contractType.GetConstructors()).Count | Should -Be 1
        $contractConstructor | Should -Be '.ctor(String,String,String,String,String,String,String,String[],IDictionary`2,IDictionary`2,IDictionary`2,GeneratedIdRange,Int32,String[])'
        $contractProperties | Should -Be @(
            'BaseCatalogSchemaId:String:write=False',
            'BaseCatalogSpace:String:write=False',
            'Channels:String[]:write=False',
            'EmitSchemaId:String:write=False',
            'GeneratedFieldIdMax:Int32:write=False',
            'LiteralExtensionParentNames:String[]:write=False',
            'MapSchemaId:String:write=False',
            'MessageEnumNameByChannel:IDictionary`2:write=False',
            'NamePredicate:String:write=False',
            'OverlayCatalogSchemaId:String:write=False',
            'OverlayCatalogSpace:String:write=False',
            'OverlayKindRangesByChannel:IDictionary`2:write=False',
            'OverlayTypeRange:GeneratedIdRange:write=False',
            'PermittedDirectionsByChannel:IDictionary`2:write=False')
        @($contractType.GetFields($bindingFlags)).Count | Should -Be 0
        @($contractType.GetEvents($bindingFlags)).Count | Should -Be 0
        $resultType.IsSealed | Should -BeTrue
        $resultType.IsAbstract | Should -BeFalse
        @($resultType.GetConstructors()).Count | Should -Be 0
        $resultProperties | Should -Be @(
            'Accepted:Boolean:write=False',
            'IdMapBytes:Byte[]:write=False',
            'Reason:String:write=False',
            'SchemaBytes:Byte[]:write=False')
        @($resultType.GetMethods($bindingFlags) | Where-Object { -not $_.IsSpecialName }).Count | Should -Be 0
        @($resultType.GetFields($bindingFlags)).Count | Should -Be 0
        @($resultType.GetEvents($bindingFlags)).Count | Should -Be 0
        $engineType.IsSealed | Should -BeTrue
        $engineType.IsAbstract | Should -BeTrue
        @($engineType.GetConstructors()).Count | Should -Be 0
        @($engineType.GetProperties($bindingFlags)).Count | Should -Be 0
        @($engineType.GetFields($bindingFlags)).Count | Should -Be 0
        @($engineType.GetEvents($bindingFlags)).Count | Should -Be 0
        $engineMethods | Should -Be @(
            'Evaluate(Byte[],Byte[],ProtocolCatalogContractV2)->ProtocolCatalogResultV2',
            'ReasonCodes()->String[]',
            'Replay(Byte[],Byte[],Byte[],Byte[],ProtocolCatalogContractV2)->FoundationReplayResult')
    }

    It 'defensively copies contract inputs and getters' {
        $channels = [string[]]@('Control')
        $messageEnums = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
        $messageEnums.Add('Control', 'ControlMessageKind')
        $directions = [Collections.Generic.Dictionary[string, string[]]]::new([StringComparer]::Ordinal)
        $directionValues = [string[]]@('HostToWorker')
        $directions.Add('Control', $directionValues)
        $kindRanges = [Collections.Generic.Dictionary[string, Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
        $rangeValues = [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]@(
            [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(40000, 40010))
        $kindRanges.Add('Control', $rangeValues)
        $parents = [string[]]@('Payload')
        $contract = [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]::new(
            '^[A-Z][A-Za-z0-9-]*$',
            'BaseCatalogV1',
            'base',
            'OverlayCatalogV1',
            'overlay',
            'EmittedSchemaV1',
            'EmittedMapV1',
            $channels,
            $messageEnums,
            $directions,
            $kindRanges,
            [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(30000, 31000),
            39,
            $parents)

        $channels[0] = 'Changed'
        $messageEnums['Control'] = 'Changed'
        $directionValues[0] = 'Changed'
        $rangeValues[0] = [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(1, 2)
        $parents[0] = 'Changed'
        $returnedChannels = $contract.Channels
        $returnedChannels[0] = 'ChangedAgain'
        $returnedDirections = $contract.PermittedDirectionsByChannel
        $returnedDirections['Control'][0] = 'ChangedAgain'

        $contract.Channels | Should -Be @('Control')
        $contract.MessageEnumNameByChannel['Control'] | Should -Be 'ControlMessageKind'
        $contract.PermittedDirectionsByChannel['Control'] | Should -Be @('HostToWorker')
        $contract.OverlayKindRangesByChannel['Control'][0].Start | Should -Be 40000
        $contract.LiteralExtensionParentNames | Should -Be @('Payload')

        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $contract)
        $schemaBytes = $result.SchemaBytes
        $mapBytes = $result.IdMapBytes
        $expectedSchemaFirst = $schemaBytes[0]
        $expectedMapFirst = $mapBytes[0]
        $schemaBytes[0] = 0
        $mapBytes[0] = 0

        $result.SchemaBytes[0] | Should -Be $expectedSchemaFirst
        $result.IdMapBytes[0] | Should -Be $expectedMapFirst
    }

    It 'preserves the pinned V1 public API' {
        $bindingFlags = [Reflection.BindingFlags]'Public,Instance,Static,DeclaredOnly'
        $engineType = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]
        $engineSignatures = @(
            $engineType.GetMethods($bindingFlags) |
                Where-Object { -not $_.IsSpecialName } |
                ForEach-Object { Get-TestMethodSignature -Method $_ } |
                Sort-Object)
        $expectedEngineSignatures = @(
            'Assign(FoundationCatalogExpansion,FoundationPolicyContract)->FoundationCatalogAssignment',
            'Emit(FoundationCatalogAssignment,FoundationPolicyContract)->FoundationCatalogResult',
            'EvaluateJson(Byte[],FoundationPolicyContract)->FoundationCatalogEvaluation',
            'Expand(Byte[],FoundationPolicyContract)->FoundationCatalogExpansion',
            'Expand(FoundationCatalogEvaluation,FoundationPolicyContract)->FoundationCatalogExpansion',
            'Replay(Byte[],Byte[],Byte[],FoundationPolicyContract)->FoundationReplayResult',
            'Sha256(Byte[])->String',
            'TestGeneratedIdAllowed(String,String,Int32,FoundationPolicyContract)->Boolean',
            'TryAdvanceGeneratedId(Int32,Int32&)->Boolean',
            'TryAdvanceGeneratedId(Int32,Int32&,String&)->Boolean') | Sort-Object
        $expectedProperties = @{
            FoundationCatalogAssignment = @('Accepted', 'IdMapBytes', 'IrJson', 'Reason', 'SchemaBytes')
            FoundationCatalogEvaluation = @('Accepted', 'Reason', 'Space')
            FoundationCatalogExpansion = @('Accepted', 'IrJson', 'Reason')
            FoundationCatalogResult = @('Accepted', 'IdMapBytes', 'IrJson', 'Reason', 'SchemaBytes')
            FoundationPolicyContract = @(
                'AllowedOps',
                'AssignIds',
                'CatalogSchemaId',
                'Channels',
                'EmitSchemaId',
                'FieldIdMax',
                'MessageEnumNameByChannel',
                'NamePredicate',
                'PermittedDirections',
                'ReservedKindRanges',
                'ReservedTypeRange')
            FoundationReplayResult = @('Accepted', 'Reason')
            GeneratedIdRange = @('End', 'Start')
        }
        $expectedConstructors = @{
            FoundationCatalogAssignment = @()
            FoundationCatalogEvaluation = @()
            FoundationCatalogExpansion = @()
            FoundationCatalogResult = @()
            FoundationPolicyContract = @('.ctor(String,String[],IDictionary`2,String[],IDictionary`2,GeneratedIdRange,Int32,Boolean,String,String,String[])')
            FoundationReplayResult = @()
            GeneratedIdRange = @('.ctor(Int32,Int32)')
        }

        $engineType.IsAbstract | Should -BeTrue
        $engineType.IsSealed | Should -BeTrue
        $engineSignatures | Should -Be $expectedEngineSignatures
        foreach ($typeName in $expectedProperties.Keys) {
            $type = $engineType.Assembly.GetType(
                'Pspkt.Certification.FoundationEngine.' + $typeName,
                $true,
                $false)
            $type.IsSealed | Should -BeTrue
            $type.IsAbstract | Should -BeFalse
            @($type.GetProperties($bindingFlags).Name | Sort-Object) |
                Should -Be @($expectedProperties[$typeName] | Sort-Object)
            @($type.GetProperties($bindingFlags) | Where-Object { $_.CanWrite }).Count | Should -Be 0
            @($type.GetConstructors() | ForEach-Object { Get-TestConstructorSignature -Constructor $_ } | Sort-Object) |
                Should -Be @($expectedConstructors[$typeName] | Sort-Object)
            @($type.GetFields($bindingFlags)).Count | Should -Be 0
            @($type.GetEvents($bindingFlags)).Count | Should -Be 0
        }
        $rangeType = [Pspkt.Certification.FoundationEngine.GeneratedIdRange]
        @(
            $rangeType.GetMethods($bindingFlags) |
                Where-Object { -not $_.IsSpecialName } |
                ForEach-Object { Get-TestMethodSignature -Method $_ }) |
            Should -Be @('Contains(Int32)->Boolean')
        $resultType = [Pspkt.Certification.FoundationEngine.FoundationCatalogResult]
        @(
            $resultType.GetMethods($bindingFlags) |
                Where-Object { -not $_.IsSpecialName } |
                ForEach-Object { Get-TestMethodSignature -Method $_ } |
                Sort-Object) |
            Should -Be (@(
                'Failure(String)->FoundationCatalogResult',
                'Failure(String,Byte[],String)->FoundationCatalogResult') | Sort-Object)
    }

    It 'matches the complete V1 and V2 public surface inventories' {
        $assembly = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1].Assembly
        $typeNames = @(
            'GeneratedIdRange',
            'FoundationPolicyContract',
            'FoundationPolicy',
            'FoundationCatalogV1',
            'FoundationCatalogEvaluation',
            'FoundationCatalogExpansion',
            'FoundationCatalogAssignment',
            'FoundationCatalogResult',
            'FoundationReplayResult',
            'FoundationCatalogEngineV1',
            'ProtocolCatalogContractV2',
            'ProtocolCatalogResultV2',
            'ProtocolCatalogEngineV2')
        $actual = [Collections.Generic.List[string]]::new()
        foreach ($typeName in $typeNames) {
            $type = $assembly.GetType(
                'Pspkt.Certification.FoundationEngine.' + $typeName,
                $true,
                $false)
            $actual.AddRange([string[]](Get-TestTypeSurface -Type $type))
        }
        $expected = @(
            'TYPE|GeneratedIdRange|sealed=True|abstract=False',
            'CTOR|System.Int32,System.Int32',
            'PROP|End|System.Int32|write=False',
            'PROP|Start|System.Int32|write=False',
            'METHOD|Contains|System.Int32|System.Boolean',
            'TYPE|FoundationPolicyContract|sealed=True|abstract=False',
            'CTOR|System.String,System.String[],System.Collections.Generic.IDictionary<System.String,System.String>,System.String[],System.Collections.Generic.IDictionary<System.String,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]>,Pspkt.Certification.FoundationEngine.GeneratedIdRange,System.Int32,System.Boolean,System.String,System.String,System.String[]',
            'PROP|AllowedOps|System.String[]|write=False',
            'PROP|AssignIds|System.Boolean|write=False',
            'PROP|CatalogSchemaId|System.String|write=False',
            'PROP|Channels|System.String[]|write=False',
            'PROP|EmitSchemaId|System.String|write=False',
            'PROP|FieldIdMax|System.Int32|write=False',
            'PROP|MessageEnumNameByChannel|System.Collections.Generic.IDictionary<System.String,System.String>|write=False',
            'PROP|NamePredicate|System.String|write=False',
            'PROP|PermittedDirections|System.String[]|write=False',
            'PROP|ReservedKindRanges|System.Collections.Generic.IDictionary<System.String,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]>|write=False',
            'PROP|ReservedTypeRange|Pspkt.Certification.FoundationEngine.GeneratedIdRange|write=False',
            'TYPE|FoundationPolicy|sealed=True|abstract=True',
            'METHOD|Create||Pspkt.Certification.FoundationEngine.FoundationPolicyContract',
            'TYPE|FoundationCatalogV1|sealed=True|abstract=True',
            'METHOD|Evaluate|System.Byte[]|Pspkt.Certification.FoundationEngine.FoundationCatalogResult',
            'METHOD|Replay|System.Byte[],System.Byte[],System.Byte[]|Pspkt.Certification.FoundationEngine.FoundationReplayResult',
            'TYPE|FoundationCatalogEvaluation|sealed=True|abstract=False',
            'PROP|Accepted|System.Boolean|write=False',
            'PROP|Reason|System.String|write=False',
            'PROP|Space|System.String|write=False',
            'TYPE|FoundationCatalogExpansion|sealed=True|abstract=False',
            'PROP|Accepted|System.Boolean|write=False',
            'PROP|IrJson|System.String|write=False',
            'PROP|Reason|System.String|write=False',
            'TYPE|FoundationCatalogAssignment|sealed=True|abstract=False',
            'PROP|Accepted|System.Boolean|write=False',
            'PROP|IdMapBytes|System.Byte[]|write=False',
            'PROP|IrJson|System.String|write=False',
            'PROP|Reason|System.String|write=False',
            'PROP|SchemaBytes|System.Byte[]|write=False',
            'TYPE|FoundationCatalogResult|sealed=True|abstract=False',
            'PROP|Accepted|System.Boolean|write=False',
            'PROP|IdMapBytes|System.Byte[]|write=False',
            'PROP|IrJson|System.String|write=False',
            'PROP|Reason|System.String|write=False',
            'PROP|SchemaBytes|System.Byte[]|write=False',
            'METHOD|Failure|System.String,System.Byte[],System.String|Pspkt.Certification.FoundationEngine.FoundationCatalogResult',
            'METHOD|Failure|System.String|Pspkt.Certification.FoundationEngine.FoundationCatalogResult',
            'TYPE|FoundationReplayResult|sealed=True|abstract=False',
            'PROP|Accepted|System.Boolean|write=False',
            'PROP|Reason|System.String|write=False',
            'TYPE|FoundationCatalogEngineV1|sealed=True|abstract=True',
            'METHOD|Assign|Pspkt.Certification.FoundationEngine.FoundationCatalogExpansion,Pspkt.Certification.FoundationEngine.FoundationPolicyContract|Pspkt.Certification.FoundationEngine.FoundationCatalogAssignment',
            'METHOD|Emit|Pspkt.Certification.FoundationEngine.FoundationCatalogAssignment,Pspkt.Certification.FoundationEngine.FoundationPolicyContract|Pspkt.Certification.FoundationEngine.FoundationCatalogResult',
            'METHOD|EvaluateJson|System.Byte[],Pspkt.Certification.FoundationEngine.FoundationPolicyContract|Pspkt.Certification.FoundationEngine.FoundationCatalogEvaluation',
            'METHOD|Expand|Pspkt.Certification.FoundationEngine.FoundationCatalogEvaluation,Pspkt.Certification.FoundationEngine.FoundationPolicyContract|Pspkt.Certification.FoundationEngine.FoundationCatalogExpansion',
            'METHOD|Expand|System.Byte[],Pspkt.Certification.FoundationEngine.FoundationPolicyContract|Pspkt.Certification.FoundationEngine.FoundationCatalogExpansion',
            'METHOD|Replay|System.Byte[],System.Byte[],System.Byte[],Pspkt.Certification.FoundationEngine.FoundationPolicyContract|Pspkt.Certification.FoundationEngine.FoundationReplayResult',
            'METHOD|Sha256|System.Byte[]|System.String',
            'METHOD|TestGeneratedIdAllowed|System.String,System.String,System.Int32,Pspkt.Certification.FoundationEngine.FoundationPolicyContract|System.Boolean',
            'METHOD|TryAdvanceGeneratedId|System.Int32,System.Int32&,System.String&|System.Boolean',
            'METHOD|TryAdvanceGeneratedId|System.Int32,System.Int32&|System.Boolean',
            'TYPE|ProtocolCatalogContractV2|sealed=True|abstract=False',
            'CTOR|System.String,System.String,System.String,System.String,System.String,System.String,System.String,System.String[],System.Collections.Generic.IDictionary<System.String,System.String>,System.Collections.Generic.IDictionary<System.String,System.String[]>,System.Collections.Generic.IDictionary<System.String,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]>,Pspkt.Certification.FoundationEngine.GeneratedIdRange,System.Int32,System.String[]',
            'PROP|BaseCatalogSchemaId|System.String|write=False',
            'PROP|BaseCatalogSpace|System.String|write=False',
            'PROP|Channels|System.String[]|write=False',
            'PROP|EmitSchemaId|System.String|write=False',
            'PROP|GeneratedFieldIdMax|System.Int32|write=False',
            'PROP|LiteralExtensionParentNames|System.String[]|write=False',
            'PROP|MapSchemaId|System.String|write=False',
            'PROP|MessageEnumNameByChannel|System.Collections.Generic.IDictionary<System.String,System.String>|write=False',
            'PROP|NamePredicate|System.String|write=False',
            'PROP|OverlayCatalogSchemaId|System.String|write=False',
            'PROP|OverlayCatalogSpace|System.String|write=False',
            'PROP|OverlayKindRangesByChannel|System.Collections.Generic.IDictionary<System.String,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]>|write=False',
            'PROP|OverlayTypeRange|Pspkt.Certification.FoundationEngine.GeneratedIdRange|write=False',
            'PROP|PermittedDirectionsByChannel|System.Collections.Generic.IDictionary<System.String,System.String[]>|write=False',
            'TYPE|ProtocolCatalogResultV2|sealed=True|abstract=False',
            'PROP|Accepted|System.Boolean|write=False',
            'PROP|IdMapBytes|System.Byte[]|write=False',
            'PROP|Reason|System.String|write=False',
            'PROP|SchemaBytes|System.Byte[]|write=False',
            'TYPE|ProtocolCatalogEngineV2|sealed=True|abstract=True',
            'METHOD|Evaluate|System.Byte[],System.Byte[],Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2|Pspkt.Certification.FoundationEngine.ProtocolCatalogResultV2',
            'METHOD|ReasonCodes||System.String[]',
            'METHOD|Replay|System.Byte[],System.Byte[],System.Byte[],System.Byte[],Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2|Pspkt.Certification.FoundationEngine.FoundationReplayResult')

        $actual.ToArray() | Should -Be $expected
    }

    It 'applies row byte and allocation limits in order' {
        $overlayBytes = $script:utf8.GetBytes(
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}')
        $acceptedCatalog = $script:utf8.GetBytes((New-FieldCatalog -FieldsPerType 2047))
        $allocationCatalog = $script:utf8.GetBytes((New-FieldCatalog -FieldsPerType 4095))
        $overCapCatalog = $script:utf8.GetBytes((New-EnumCatalog -MemberCount 8192))
        $accepted = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $acceptedCatalog,
            $overlayBytes,
            (New-TestProtocolContract -GeneratedFieldIdMax 4096))
        $allocation = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $allocationCatalog,
            $overlayBytes,
            (New-TestProtocolContract -GeneratedFieldIdMax 4096))
        $fileLimit = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $allocationCatalog,
            $overlayBytes,
            (New-TestProtocolContract -GeneratedFieldIdMax 4096 -MapSchemaId ('M' * 64)))
        $overCap = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $overCapCatalog,
            $overlayBytes,
            (New-TestProtocolContract -GeneratedFieldIdMax 4096))

        $accepted.Accepted | Should -BeTrue
        ($script:utf8.GetString($accepted.IdMapBytes) | ConvertFrom-Json).Count | Should -Be 4096
        $allocation.Accepted | Should -BeFalse
        $allocation.Reason | Should -Be 'allocation-budget'
        $fileLimit.Accepted | Should -BeFalse
        $fileLimit.Reason | Should -Be 'file-limit'
        $overCap.Accepted | Should -BeFalse
        $overCap.Reason | Should -Be 'invalid-cardinality'
    }

    It 'checks empty nested collections before names and parents' {
        $overlayBytes = $script:utf8.GetBytes(
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}')
        $cases = @(
            @{
                Catalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"enum","name":"_Bad","members":[]}]}'
                Reason = 'missing-property'
            },
            @{
                Catalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"field-set","parent":"Missing","name":"Group","variants":[]}]}'
                Reason = 'missing-property'
            },
            @{
                Catalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
                Overlay = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"extend","parent":"Missing","fields":[]}]}'
                Reason = 'missing-property'
            },
            @{
                Catalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"union","name":"Choice","discriminator":"_Bad","branches":[]}]}'
                Reason = 'union-empty'
            })

        foreach ($case in $cases) {
            $currentOverlay = if ($case.ContainsKey('Overlay')) {
                $script:utf8.GetBytes([string]$case.Overlay)
            }
            else {
                $overlayBytes
            }
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes([string]$case.Catalog),
                $currentOverlay,
                (New-TestProtocolContract))

            $result.Accepted | Should -BeFalse
            $result.Reason | Should -Be $case.Reason
        }
    }

    It 'accepts every V2 operation form in one deterministic stream' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"primitive","name":"U8"},{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"},{"op":"enum","name":"Mode","members":[{"name":"Off"},{"name":"On"}]},{"op":"type","name":"ModeList","production":"List","elementType":"Mode","minCount":0,"maxCount":4},{"op":"type","name":"ModeSet","production":"Set","elementType":"Mode","minCount":0,"maxCount":4},{"op":"type","name":"Label","production":"SemanticString","encoding":"Utf8","grammar":"None","minBytes":1,"maxBytes":64,"maxUtf16CodeUnits":64},{"op":"union","name":"Choice","discriminator":"ChoiceKind","branches":[{"name":"ChoiceA","fields":[{"name":"AValue","type":"U8"}]},{"name":"ChoiceB","fields":[{"name":"BValue","type":"U16"}]}]},{"op":"message","channel":"Control","direction":"HostToWorker","name":"Ping","payloadRoot":"Payload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"},{"op":"type","name":"Deleted","production":"Named"},{"op":"field","parent":"Deleted","name":"DeletedValue","type":"U8"},{"op":"delete","name":"Deleted"},{"op":"reserve-illegal-type","name":"ReservedType","id":30001}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Extra","production":"Named"},{"op":"extend","parent":"Extra","fields":[{"id":40,"name":"ExtraValue","type":"U16"}]},{"op":"field-set","parent":"Payload","name":"OverlayValue","id":40,"variants":[{"name":"OverlayValue","type":"U32"}]},{"op":"overlay-message","id":40000,"channel":"Control","direction":"WorkerToHost","name":"Notify","payloadRoot":"Extra","profile":"NonInteractiveElevated","mandatoryTailClass":"Mandatory","stateAssoc":"Ready"}]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))
        $schemaResult = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
            'schema-against-meta',
            $result.SchemaBytes,
            $script:metaBytes)
        $map = $script:utf8.GetString($result.IdMapBytes) | ConvertFrom-Json

        $result.Accepted | Should -BeTrue -Because $result.Reason
        $schemaResult.Accepted | Should -BeTrue -Because $schemaResult.Reason
        @($map.category | Sort-Object -Unique) | Should -Be @(
            'enum-member',
            'field',
            'kind',
            'type',
            'union-branch')
        @($map.name) | Should -Not -Contain 'Deleted'
    }

    It 'returns exact reasons for representative invalid operations' {
        $overlayEmpty = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $cases = @(
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
                Overlay = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"type","name":"WrongSource","production":"Named"}]}'
                Reason = 'op-source-forbidden'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"reserve-illegal-type","name":"MissingId"}]}'
                Overlay = $overlayEmpty
                Reason = 'reserve-missing-literal'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
                Overlay = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"extend","parent":"Payload","fields":[{"name":"MissingId","type":"U8"}]}]}'
                Reason = 'extend-missing-literal'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"First","type":"U8"},{"op":"field","parent":"Payload","name":"Second","type":"U8"}]}'
                Overlay = $overlayEmpty
                FieldMaximum = 1
                Reason = 'field-overflow'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"},{"op":"message","channel":"Control","direction":"HostToWorker","name":"Ping","payloadRoot":"Payload","profile":"Desktop","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Overlay = $overlayEmpty
                Reason = 'invalid-profile'
            })

        foreach ($case in $cases) {
            $fieldMaximum = if ($case.ContainsKey('FieldMaximum')) { [int]$case.FieldMaximum } else { 39 }
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes([string]$case.Base),
                $script:utf8.GetBytes([string]$case.Overlay),
                (New-TestProtocolContract -GeneratedFieldIdMax $fieldMaximum))

            $result.Accepted | Should -BeFalse
            $result.Reason | Should -Be $case.Reason
        }
    }

    It 'does not reserve map identities for non-emitted overlay field sets' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
        $orders = @(
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"field-set","parent":"Payload","name":"Slot","id":40,"variants":[{"name":"Value","type":"U8"}]},{"op":"extend","parent":"Payload","fields":[{"id":41,"name":"Slot","type":"U16"}]}]}',
            '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"extend","parent":"Payload","fields":[{"id":41,"name":"Slot","type":"U16"}]},{"op":"field-set","parent":"Payload","name":"Slot","id":40,"variants":[{"name":"Value","type":"U8"}]}]}')

        foreach ($overlayCatalog in $orders) {
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes($baseCatalog),
                $script:utf8.GetBytes($overlayCatalog),
                (New-TestProtocolContract))
            $map = $script:utf8.GetString($result.IdMapBytes) | ConvertFrom-Json

            $result.Accepted | Should -BeTrue -Because $result.Reason
            @($map | Where-Object { $_.category -ceq 'field' }).Count | Should -Be 1
            @($map | Where-Object { $_.name -ceq 'Payload.Slot' }).Count | Should -Be 1
        }
    }

    It 'preserves unconditional duplicate extend precedence' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"Value","type":"U8"}]},{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"Value","type":"U8"}]}]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeFalse
        $result.Reason | Should -Be 'extend-dup-name'
    }

    It 'reports deleted field-set parents as delete then use' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Existing","type":"U8"},{"op":"delete","name":"Payload"},{"op":"field-set","parent":"Payload","name":"Conditional","variants":[{"name":"Value","type":"U8"}]}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $result.Accepted | Should -BeFalse
        $result.Reason | Should -Be 'delete-then-use'
    }

    It 'preserves conditional validation reason precedence' {
        $cases = @(
            @{
                Schema = '{"schemaVersion":1,"schemaId":"DuplicateBeforeOrder","types":[{"production":"Named","name":"Payload","typeId":1,"fields":[{"fieldId":2,"name":"Same","type":"U8","profile":"InteractiveSeat"},{"fieldId":1,"name":"Other","type":"U8","profile":"InteractiveSeat"},{"fieldId":3,"name":"Same","type":"U8","profile":"InteractiveSeat"},{"fieldId":1,"name":"Service","type":"U8","profile":"NonInteractiveElevated"}]}]}'
                Reason = 'duplicate-identifier'
            },
            @{
                Schema = '{"schemaVersion":1,"schemaId":"MatchBeforeCollision","types":[{"production":"Named","name":"Payload","typeId":1,"fields":[{"fieldId":1,"name":"Same","type":"U8","profile":"InteractiveSeat"},{"fieldId":2,"name":"Same","type":"U16","profile":"InteractiveSeat"},{"fieldId":1,"name":"Service","type":"U8","profile":"NonInteractiveElevated"},{"fieldId":3,"name":"Missing","type":"U32","profile":"NonInteractiveElevated","status":"Forbidden"}]}]}'
                Reason = 'invalid-field-condition'
            },
            @{
                Schema = '{"schemaVersion":1,"schemaId":"RawBeforeDeclaration","types":[{"production":"Named","name":"Payload","typeId":1,"fields":[{"fieldId":1,"name":"Same","type":"U8","profile":"InteractiveSeat"},{"fieldId":1,"name":"Same","type":"U8","profile":"InteractiveSeat"},{"fieldId":2,"name":"MissingBound","type":"BoundedBytes","profile":"NonInteractiveElevated"}]}]}'
                Reason = 'missing-property'
            })

        foreach ($case in $cases) {
            $result = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
                'schema-against-meta',
                $script:utf8.GetBytes([string]$case.Schema),
                $script:metaBytes)

            $result.Accepted | Should -BeFalse
            $result.Reason | Should -Be $case.Reason
        }
    }

    It 'rejects forbidden primitives at collection and message reference sites' {
        $overlayEmpty = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $cases = @(
            '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"BadList","production":"List","elementType":"I64","minCount":0,"maxCount":1}]}',
            '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"BadSet","production":"Set","elementType":"OpaqueUtf16","minCount":0,"maxCount":1}]}',
            '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"message","channel":"Control","direction":"HostToWorker","name":"BadMessage","payloadRoot":"I32","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}')

        foreach ($baseCatalog in $cases) {
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes($baseCatalog),
                $script:utf8.GetBytes($overlayEmpty),
                (New-TestProtocolContract))

            $result.Accepted | Should -BeFalse
            $result.Reason | Should -Be 'primitive-forbidden'
        }
    }

    It 'orders collection and message reference failures exactly' {
        $overlayEmpty = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $cases = @(
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"reserve-illegal-type","name":"I64","id":30000},{"op":"type","name":"ReservedList","production":"List","elementType":"I64","minCount":0,"maxCount":1}]}'
                Overlay = $overlayEmpty
                Reason = 'reserve-illegal-encoded'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"BadList","production":"List","elementType":"I64","minCount":0,"maxCount":0}]}'
                Overlay = $overlayEmpty
                Reason = 'invalid-cardinality'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"message","channel":"Control","direction":"HostToWorker","name":"BadMessage","payloadRoot":"I32","profile":"Desktop","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Overlay = $overlayEmpty
                Reason = 'invalid-profile'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
                Overlay = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-message","id":39999,"channel":"Control","direction":"HostToWorker","name":"BadMessage","payloadRoot":"I32","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Reason = 'overlay-id-out-of-range'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"message","channel":"Control","direction":"HostToWorker","name":"Same","payloadRoot":"I32","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"},{"op":"message","channel":"Control","direction":"HostToWorker","name":"Same","payloadRoot":"I32","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Overlay = $overlayEmpty
                Reason = 'duplicate-kind'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"UnknownList","production":"List","elementType":"Missing","minCount":0,"maxCount":1}]}'
                Overlay = $overlayEmpty
                Reason = 'undefined-reference'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"message","channel":"Control","direction":"HostToWorker","name":"UnknownMessage","payloadRoot":"Missing","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Overlay = $overlayEmpty
                Reason = 'undefined-payload-root'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Gone","production":"Named"},{"op":"field","parent":"Gone","name":"Value","type":"U8"},{"op":"delete","name":"Gone"},{"op":"type","name":"DeletedList","production":"List","elementType":"Gone","minCount":0,"maxCount":1}]}'
                Overlay = $overlayEmpty
                Reason = 'delete-then-use'
            })

        foreach ($case in $cases) {
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes([string]$case.Base),
                $script:utf8.GetBytes([string]$case.Overlay),
                (New-TestProtocolContract))

            $result.Accepted | Should -BeFalse
            $result.Reason | Should -Be $case.Reason
        }

        $baseReservedCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"message","channel":"Control","direction":"HostToWorker","name":"ReservedMessage","payloadRoot":"I32","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
        $baseReserved = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseReservedCatalog),
            $script:utf8.GetBytes($overlayEmpty),
            (New-TestProtocolContract -KindRangeStart 1 -KindRangeEnd 1))
        $baseReserved.Reason | Should -Be 'primitive-forbidden'
    }

    It 'checks every union field id before any encoded bound' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"union","name":"Choice","discriminator":"ChoiceKind","branches":[{"name":"First","fields":[{"name":"Huge","type":"OpaqueUtf16","maxCodeUnits":2147483647}]},{"name":"Second","fields":[{"name":"A","type":"U8"},{"name":"B","type":"U8"}]}]}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'

        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract -GeneratedFieldIdMax 1))

        $result.Accepted | Should -BeFalse
        $result.Reason | Should -Be 'field-overflow'
    }

    It 'sorts outer generator digest paths ordinally' {
        $validatorPath = Join-Path $repositoryRoot 'certification\validators\Invoke-PspktPhase4SchemaValidators.ps1'
        $validatorSource = [IO.File]::ReadAllText($validatorPath)
        $functionMatch = [regex]::Match(
            $validatorSource,
            '(?s)function Get-PspktGeneratorOutputDigest \{.*?^}',
            [Text.RegularExpressions.RegexOptions]::Multiline)

        $functionMatch.Success | Should -BeTrue
        $sortIndex = $functionMatch.Value.IndexOf(
            '[System.Array]::Sort($expectedOutputPaths, [System.StringComparer]::Ordinal)',
            [StringComparison]::Ordinal)
        $digestLoopIndex = $functionMatch.Value.IndexOf(
            'foreach ($relativePath in $expectedOutputPaths)',
            [StringComparison]::Ordinal)
        $sortIndex | Should -BeGreaterThan -1
        $digestLoopIndex | Should -BeGreaterThan $sortIndex
    }

    It 'uses caller regex semantics after schema identifier validation' {
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        foreach ($pattern in @('(?x)Foo#comment', 'Foo|FooBar', 'Foo.*?', 'Foo')) {
            $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"FooBar","production":"Named"},{"op":"field","parent":"FooBar","name":"FooValue","type":"U8"}]}'
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes($baseCatalog),
                $script:utf8.GetBytes($overlayCatalog),
                (New-TestProtocolContract -NamePredicate $pattern -ContractTypeName 'FooBar' -LiteralExtensionParentNames ([string[]]@('FooBar'))))
            $result.Accepted | Should -BeTrue -Because "$pattern returned $($result.Reason)"
        }
        $anchored = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"FooBar","production":"Named"}]}'),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract -NamePredicate '^Foo$' -ContractTypeName 'Foo' -LiteralExtensionParentNames ([string[]]@('Foo'))))
        $anchored.Reason | Should -Be 'catalog-name'

        $catastrophicName = ('A' * 63) + 'B'
        $catastrophicCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"' + $catastrophicName + '","production":"Named"}]}'
        $catastrophic = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($catastrophicCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract -NamePredicate '^(A+)+$' -ContractTypeName 'A' -LiteralExtensionParentNames ([string[]]@('A'))))
        $catastrophic.Reason | Should -Be 'catalog-name'
    }

    It 'rejects representative identity reservation and message collisions' {
        $overlayEmpty = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $cases = @(
            @{
                Base = '{"schemaVersion":1,"schemaId":"WrongCatalog","space":"base","entries":[]}'
                Overlay = $overlayEmpty
                Reason = 'catalog-identity'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"GUID","production":"Named"}]}'
                Overlay = $overlayEmpty
                Reason = 'duplicate-identifier'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"}]}'
                Overlay = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"Value","type":"U8"}]}]}'
                Contract = @{ LiteralExtensionParentNames = [string[]]@('Other') }
                Reason = 'extension-parent-forbidden'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field-set","parent":"Payload","name":"Group","variants":[{"name":"First","type":"U8"}]},{"op":"field-set","parent":"Payload","name":"Group","variants":[{"name":"Second","type":"U16"}]}]}'
                Overlay = $overlayEmpty
                Reason = 'duplicate-field-set'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"FirstPayload","production":"Named"},{"op":"field","parent":"FirstPayload","name":"Value","type":"U8"},{"op":"type","name":"SecondPayload","production":"Named"},{"op":"field","parent":"SecondPayload","name":"Value","type":"U8"},{"op":"message","channel":"Control","direction":"HostToWorker","name":"Same","payloadRoot":"FirstPayload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"},{"op":"message","channel":"Control","direction":"WorkerToHost","name":"Same","payloadRoot":"SecondPayload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Overlay = $overlayEmpty
                Reason = 'message-metadata-conflict'
            },
            @{
                Base = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'
                Overlay = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Payload","production":"Named"},{"op":"extend","parent":"Payload","fields":[{"id":40,"name":"Value","type":"U8"}]},{"op":"overlay-message","id":40000,"channel":"Control","direction":"HostToWorker","name":"First","payloadRoot":"Payload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"},{"op":"overlay-message","id":40000,"channel":"Control","direction":"WorkerToHost","name":"Second","payloadRoot":"Payload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'
                Reason = 'enum-duplicate-value'
            })

        foreach ($case in $cases) {
            $contractArguments = if ($case.ContainsKey('Contract')) { $case.Contract } else { @{} }
            $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
                $script:utf8.GetBytes([string]$case.Base),
                $script:utf8.GetBytes([string]$case.Overlay),
                (New-TestProtocolContract @contractArguments))
            $result.Reason | Should -Be $case.Reason
        }
    }

    It 'orders reserve and generated range failures' {
        $overlayEmpty = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $reservedThenEncoded = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"reserve-illegal-type","name":"Reserved","id":30000}]}'),
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Encoded","production":"Named"}]}'),
            (New-TestProtocolContract))
        $encodedThenReserved = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[]}'),
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[{"op":"overlay-type","id":30000,"name":"Encoded","production":"Named"},{"op":"reserve-illegal-type","name":"Reserved","id":30000}]}'),
            (New-TestProtocolContract))
        $reservedType = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"reserve-illegal-type","name":"Reserved","id":1},{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"}]}'),
            $script:utf8.GetBytes($overlayEmpty),
            (New-TestProtocolContract -OverlayTypeRangeStart 1))
        $reservedKind = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"},{"op":"message","channel":"Control","direction":"HostToWorker","name":"Ping","payloadRoot":"Payload","profile":"InteractiveSeat","mandatoryTailClass":"Ordinary","stateAssoc":"None"}]}'),
            $script:utf8.GetBytes($overlayEmpty),
            (New-TestProtocolContract -KindRangeStart 1 -KindRangeEnd 1))

        $reservedThenEncoded.Reason | Should -Be 'reserve-illegal-encoded'
        $encodedThenReserved.Reason | Should -Be 'duplicate-type-id'
        $reservedType.Reason | Should -Be 'reserved-type-range'
        $reservedKind.Reason | Should -Be 'reserved-kind-range'
    }

    It 'pins raw field and opaque bounds at exact limits' {
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $exactFields = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes((New-OneTypeFieldCatalog -FieldCount 4096)),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract -GeneratedFieldIdMax 4096))
        $overFields = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes((New-OneTypeFieldCatalog -FieldCount 4097)),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract -GeneratedFieldIdMax 5000))
        $opaqueBoundary = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes(
                '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field-set","parent":"Payload","name":"Conditional","variants":[{"name":"Huge","type":"OpaqueUtf16","maxCodeUnits":2147483645},{"name":"Huge","type":"OpaqueUtf16","maxCodeUnits":2147483645,"profile":"InteractiveSeat","status":"Forbidden"},{"name":"Huge","type":"OpaqueUtf16","maxCodeUnits":2147483645,"profile":"NonInteractiveElevated","status":"Forbidden"},{"name":"Fallback","type":"U8"}]}]}'),
            $script:utf8.GetBytes($overlayCatalog),
            (New-TestProtocolContract))

        $exactFields.Accepted | Should -BeTrue -Because $exactFields.Reason
        $overFields.Reason | Should -Be 'invalid-cardinality'
        $opaqueBoundary.Accepted | Should -BeTrue -Because $opaqueBoundary.Reason
    }

    It 'returns schema drift before map drift when both outputs change' {
        $baseCatalog = '{"schemaVersion":1,"schemaId":"BaseCatalogV1","space":"base","entries":[{"op":"type","name":"Payload","production":"Named"},{"op":"field","parent":"Payload","name":"Value","type":"U8"}]}'
        $overlayCatalog = '{"schemaVersion":1,"schemaId":"OverlayCatalogV1","space":"overlay","entries":[]}'
        $contract = New-TestProtocolContract
        $result = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Evaluate(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $contract)
        $changedSchema = $script:utf8.GetBytes(
            $script:utf8.GetString($result.SchemaBytes).Replace('EmittedSchemaV1', 'ChangedSchemaV1'))
        $map = $script:utf8.GetString($result.IdMapBytes) | ConvertFrom-Json
        $map[0].name = 'Changed'
        $changedMap = $script:utf8.GetBytes(($map | ConvertTo-Json -Compress -Depth 10))

        $replay = [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2]::Replay(
            $script:utf8.GetBytes($baseCatalog),
            $script:utf8.GetBytes($overlayCatalog),
            $changedSchema,
            $changedMap,
            $contract)

        $replay.Reason | Should -Be 'id-map-drift'
    }
}
