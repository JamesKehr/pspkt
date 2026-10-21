[CmdletBinding()]
param(
    [ValidateSet('Generate','Validate','Compile','VerifyVector','TimeoutProbe')]
    [string]$Mode = 'Validate',
    [string]$RepositoryRoot,
    [string]$OutputRoot,
    [string]$VectorPath,
    [switch]$Worker,
    [string]$AssemblyRoot,
    [string]$AdmissionEventName,
    [string]$ExpectedChildImageHash,
    [string]$ExpectedChildImageIdentity,
    [string]$ExpectedChildImageEvidenceFile,
    [string]$ExpectedPinIdentityFile,
    [string]$TimeoutProbePidFile,
    [ValidateRange(1,120000)]
    [int]$ChildTimeoutMilliseconds = 120000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ExpectedTrustedControlContractSha256 = '602a6e7fb85ca40848630f97fd1907c5ab244a0e72d4abdcd03534ebfe483141'

if ($Worker -and $AdmissionEventName) {
    $admissionEvent = [Threading.EventWaitHandle]::OpenExisting($AdmissionEventName)
    try {
        if (-not $admissionEvent.WaitOne(30000)) {
            throw 'Trusted-control child admission timed out.'
        }
    }
    finally {
        $admissionEvent.Dispose()
    }
}

function Resolve-PspktTrustedControlPath {
    param(
        [string]$Path,
        [string]$ParameterName
    )

    if (-not $Path) {
        return $Path
    }
    if ($Path -match '^[\\/]{2}' -or $Path -match '^[A-Za-z]:(?![\\/])') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $provider = $null
    $drive = $null
    try {
        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path,
            [ref]$provider,
            [ref]$drive)
    }
    catch {
        throw "$ParameterName could not be resolved: $($_.Exception.Message)"
    }
    if ($provider.Name -cne 'FileSystem' -or $resolved -match '^[\\/]{2}[?.][\\/]') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $isDrivePath = $resolved -match '^[A-Za-z]:[\\/]'
    if (-not $isDrivePath) {
        throw "$ParameterName must resolve to an absolute filesystem path."
    }
    $invalidCharacters = [IO.Path]::GetInvalidFileNameChars()
    $componentPath = if ($isDrivePath) {
        $resolved.Substring(2)
    } else {
        $resolved.TrimStart([char[]]@('\','/'))
    }
    $reservedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('CON','PRN','AUX','NUL','CLOCK$','CONIN$','CONOUT$')) {
        [void]$reservedNames.Add($name)
    }
    foreach ($index in 1..9) {
        [void]$reservedNames.Add('COM' + $index)
        [void]$reservedNames.Add('LPT' + $index)
    }
    foreach ($component in $componentPath.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)) {
        if ($component.EndsWith(' ',[StringComparison]::Ordinal) -or
            $component.EndsWith('.',[StringComparison]::Ordinal)) {
            throw "$ParameterName contains a normalization-sensitive path component."
        }
        if ($component.IndexOfAny($invalidCharacters) -ge 0) {
            throw "$ParameterName contains an invalid filesystem path component."
        }
        $baseName = $component.TrimEnd([char[]]@(' ','.')).Split('.')[0]
        if ($reservedNames.Contains($baseName)) {
            throw "$ParameterName contains a reserved filesystem path component."
        }
    }
    try {
        $fullPath = [IO.Path]::GetFullPath($resolved)
    }
    catch {
        throw "$ParameterName could not be normalized: $($_.Exception.Message)"
    }
    if ($fullPath -match '^[\\/]{2}[?.][\\/]') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $root = [IO.Path]::GetPathRoot($fullPath)
    $ancestor = $root
    foreach ($component in $fullPath.Substring($root.Length).Split(
        [char[]]@('\','/'),
        [StringSplitOptions]::RemoveEmptyEntries)) {
        $ancestor = Join-Path $ancestor $component
        if ([IO.File]::Exists($ancestor) -or [IO.Directory]::Exists($ancestor)) {
            if (([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$ParameterName contains a reparse-point ancestor."
            }
        }
    }
    if ($fullPath -ceq $root) {
        return $root
    }
    return $fullPath.TrimEnd([char[]]@('\','/'))
}

function Get-PspktTrustedControlHash {
    param([string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-PspktTrustedControlByteHash {
    param([byte[]]$Bytes)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Test-PspktTrustedControlByteSequence {
    param(
        [byte[]]$Bytes,
        [byte[]]$Pattern
    )

    if ($Pattern.Length -eq 0 -or $Pattern.Length -gt $Bytes.Length) {
        return $false
    }
    for ($offset = 0; $offset -le $Bytes.Length - $Pattern.Length; $offset++) {
        $matched = $true
        for ($index = 0; $index -lt $Pattern.Length; $index++) {
            $actual = $Bytes[$offset + $index]
            $expected = $Pattern[$index]
            if ($actual -ge [byte][char]'A' -and $actual -le [byte][char]'Z') {
                $actual = [byte]($actual + 32)
            }
            if ($expected -ge [byte][char]'A' -and $expected -le [byte][char]'Z') {
                $expected = [byte]($expected + 32)
            }
            if ($actual -ne $expected) {
                $matched = $false
                break
            }
        }
        if ($matched) { return $true }
    }
    return $false
}

function Assert-PspktTrustedControlVerifyBinaryIsolation {
    param([string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $fullName =
        'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA'
    $simpleName = 'TrustedControlAuthorityProjectionA'
    foreach ($name in @($fullName,$simpleName,($fullName + '+'),($simpleName + '+'))) {
        foreach ($encoding in @(
            @{ Name = 'ASCII'; Value = [Text.Encoding]::ASCII },
            @{ Name = 'UTF16'; Value = [Text.Encoding]::Unicode }
        )) {
            if (Test-PspktTrustedControlByteSequence `
                -Bytes $bytes `
                -Pattern $encoding.Value.GetBytes($name)) {
                throw "Trusted-control Verify binary contains forbidden authority name: $name/$($encoding.Name)"
            }
        }
    }
}

function Assert-PspktTrustedControlPins {
    param(
        $Contract,
        [ref]$IdentityByPath,
        [ref]$BytesByPath
    )

    $identities = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    $pinnedBytes = [Collections.Generic.Dictionary[string,byte[]]]::new(
        [StringComparer]::Ordinal)
    foreach ($relativePath in $Contract.Sha256ByPath.Keys) {
        $fullPath = Join-Path $RepositoryRoot $relativePath.Replace('/','\')
        if (-not [IO.File]::Exists($fullPath)) {
            throw "Trusted-control pinned path is missing: $relativePath"
        }
        $stream = [IO.FileStream]::new(
            $fullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $identityBefore = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
                $stream.SafeFileHandle).ToString()
            $bytes = [byte[]]::new($stream.Length)
            $bytesRead = $stream.Read($bytes,0,$bytes.Length)
            if ($bytesRead -ne $bytes.Length) {
                throw "Trusted-control pinned file read was incomplete: $relativePath"
            }
            $expectedHash = $Contract.Sha256ByPath[$relativePath]
            $actualHash =
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::ComputeSha256($bytes)
            $identityAfter = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
                $stream.SafeFileHandle).ToString()
            if ($identityBefore -cne $identityAfter) {
                throw "Trusted-control pinned identity changed while reading: $relativePath"
            }
            $identities.Add($relativePath,$identityBefore)
            $pinnedBytes.Add($relativePath,$bytes)
            if ($actualHash -cne $expectedHash) {
                throw "Trusted-control pinned hash differs: $relativePath; expected=$expectedHash; actual=$actualHash"
            }
        }
        finally {
            $stream.Dispose()
        }
        if ($Contract.LfTextPathSet -ccontains $relativePath) {
            if ($bytes -contains [byte]13) {
                throw "Trusted-control pinned LF text contains CR: $relativePath"
            }
        }
    }
    $IdentityByPath.Value = $identities
    $BytesByPath.Value = $pinnedBytes
}

function Assert-PspktTrustedControlClosedSet {
    param($Contract)

    $actualPaths = [Collections.Generic.List[string]]::new()
    foreach ($relativeRoot in @('certification\trusted-control','tests\phase4-trusted-control')) {
        $fullRoot = Join-Path $RepositoryRoot $relativeRoot
        if (-not [IO.Directory]::Exists($fullRoot)) {
            throw "Trusted-control slice directory is missing: $relativeRoot"
        }
        foreach ($file in Get-ChildItem -LiteralPath $fullRoot -File -Recurse -Force) {
            $actualPaths.Add($file.FullName.Substring($RepositoryRoot.Length + 1).Replace('\','/'))
        }
    }
    $forbiddenNames = [string[]]@(
        'trusted-control-artifact-set.v1',
        'trusted-control-artifact-set.v1.json',
        'supported-builds.v1.json',
        'timing-policy.v1.json',
        'resource-registry.v1.json',
        'unicode-tables.v1.json',
        'trust-roots.v1.json',
        'counter-mutation-manifest.v1.json',
        'nonclosed-metric-manifest.v1.json',
        'powershell-entrypoints.v1.json')
    $actual = $actualPaths.ToArray()
    foreach ($relativePath in $actual) {
        if ($forbiddenNames -ccontains [IO.Path]::GetFileName($relativePath)) {
            throw "Trusted-control forbidden production filename exists: $relativePath"
        }
    }
    $expectedPaths = [string[]]$Contract.AllowedPathSet.Clone()
    [Array]::Sort($expectedPaths,[StringComparer]::Ordinal)
    [Array]::Sort($actual,[StringComparer]::Ordinal)
    $missingPaths = @($expectedPaths | Where-Object { $actual -cnotcontains $_ })
    $extraPaths = @($actual | Where-Object { $expectedPaths -cnotcontains $_ })
    if ($missingPaths.Count -ne 0 -or $extraPaths.Count -ne 0) {
        throw "Trusted-control closed file set differs: missing=[$($missingPaths -join ',')]; extra=[$($extraPaths -join ',')]"
    }
}

function Write-PspktTrustedControlFileAtomically {
    param(
        [string]$Path,
        [byte[]]$Bytes
    )

    $directory = [IO.Path]::GetDirectoryName($Path)
    [void][IO.Directory]::CreateDirectory($directory)
    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.Write($Bytes,0,$Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        if ([IO.File]::Exists($Path)) {
            [IO.File]::Replace($temporaryPath,$Path,[NullString]::Value)
        } else {
            [IO.File]::Move($temporaryPath,$Path)
        }
    }
    finally {
        if ([IO.File]::Exists($temporaryPath)) {
            [IO.File]::Delete($temporaryPath)
        }
    }
}

function Get-PspktTrustedControlFrameworkReferences {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return @('System.dll','System.Core.dll','System.Security.dll')
    }

    return @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' |
        ForEach-Object { $_.FullName })
}

function Get-PspktTrustedControlCalledMethodReferences {
    param(
        [Reflection.MethodBase]$Method,
        [switch]$IncludeInstructions,
        [byte[]]$IlBytes
    )

    $body = $Method.GetMethodBody()
    if ($null -eq $body) { return @() }
    $bytes = $body.GetILAsByteArray()
    if ($PSBoundParameters.ContainsKey('IlBytes')) { $bytes = $IlBytes }
    $oneByte = @{}
    $twoByte = @{}
    foreach ($field in [Reflection.Emit.OpCodes].GetFields(
        [Reflection.BindingFlags]'Public,Static')) {
        $operation = [Reflection.Emit.OpCode]$field.GetValue($null)
        $value = [int]$operation.Value -band 0xffff
        if ($value -le 0xff) { $oneByte[$value] = $operation }
        else { $twoByte[$value -band 0xff] = $operation }
    }
    $references = [Collections.Generic.List[object]]::new()
    $index = 0
    while ($index -lt $bytes.Length) {
        $first = [int]$bytes[$index++]
        if ($first -eq 0xfe) {
            if ($index -ge $bytes.Length) { throw 'Trusted-control IL contains a truncated opcode.' }
            $operation = $twoByte[[int]$bytes[$index++]]
        } else {
            $operation = $oneByte[$first]
        }
        if ($null -eq $operation) { throw 'Trusted-control IL contains an unknown opcode.' }
        if ($operation.Value -eq [Reflection.Emit.OpCodes]::Calli.Value -or
            $operation.Value -eq [Reflection.Emit.OpCodes]::Jmp.Value) {
            throw 'Trusted-control IL contains an unsupported indirect transfer.'
        }
        $operandType = $operation.OperandType
        $operandSize = 0
        if ($operandType -eq [Reflection.Emit.OperandType]::InlineSwitch) {
            if ($index + 4 -gt $bytes.Length) { throw 'Trusted-control IL switch is truncated.' }
            $count = [BitConverter]::ToInt32($bytes,$index)
            if ($count -lt 0) { throw 'Trusted-control IL switch has an invalid count.' }
            if ($count -gt [math]::Floor(($bytes.Length - $index - 4) / 4)) {
                throw 'Trusted-control IL switch is truncated.'
            }
            $operandSize = 4 + ($count * 4)
        } elseif ($operandType -in @(
            [Reflection.Emit.OperandType]::InlineBrTarget,
            [Reflection.Emit.OperandType]::InlineField,
            [Reflection.Emit.OperandType]::InlineI,
            [Reflection.Emit.OperandType]::InlineMethod,
            [Reflection.Emit.OperandType]::InlineSig,
            [Reflection.Emit.OperandType]::InlineString,
            [Reflection.Emit.OperandType]::InlineTok,
            [Reflection.Emit.OperandType]::InlineType,
            [Reflection.Emit.OperandType]::ShortInlineR)) {
            $operandSize = 4
        } elseif ($operandType -in @(
            [Reflection.Emit.OperandType]::InlineI8,
            [Reflection.Emit.OperandType]::InlineR)) {
            $operandSize = 8
        } elseif ($operandType -eq [Reflection.Emit.OperandType]::InlineVar) {
            $operandSize = 2
        } elseif ($operandType -in @(
            [Reflection.Emit.OperandType]::ShortInlineBrTarget,
            [Reflection.Emit.OperandType]::ShortInlineI,
            [Reflection.Emit.OperandType]::ShortInlineVar)) {
            $operandSize = 1
        }
        if ($index + $operandSize -gt $bytes.Length) {
            throw 'Trusted-control IL operand is truncated.'
        }
        $isTokenOperand = $operandType -in @(
            [Reflection.Emit.OperandType]::InlineMethod,
            [Reflection.Emit.OperandType]::InlineTok,
            [Reflection.Emit.OperandType]::InlineField,
            [Reflection.Emit.OperandType]::InlineType,
            [Reflection.Emit.OperandType]::InlineString,
            [Reflection.Emit.OperandType]::InlineSig)
        if ($isTokenOperand -and
            ($IncludeInstructions -or
                $operandType -eq [Reflection.Emit.OperandType]::InlineMethod -or
                $operandType -eq [Reflection.Emit.OperandType]::InlineTok)) {
            $token = [BitConverter]::ToInt32($bytes,$index)
            try {
                $typeArguments = if ($Method.DeclaringType -and $Method.DeclaringType.IsGenericType) {
                    $Method.DeclaringType.GetGenericArguments()
                } else { $null }
                $methodArguments = if ($Method.IsGenericMethod) {
                    $Method.GetGenericArguments()
                } else { $null }
                $member = if ($operandType -eq [Reflection.Emit.OperandType]::InlineString) {
                    $Method.Module.ResolveString($token)
                } elseif ($operandType -eq [Reflection.Emit.OperandType]::InlineSig) {
                    $Method.Module.ResolveSignature($token)
                } else {
                    $Method.Module.ResolveMember($token,$typeArguments,$methodArguments)
                }
                if ($member -is [Reflection.MethodBase]) {
                    $references.Add([pscustomobject]@{
                            Method = $member
                            Member = $member
                            Operation = $operation
                            Token = $token
                        })
                } elseif ($IncludeInstructions) {
                    $references.Add([pscustomobject]@{
                            Method = $null
                            Member = $member
                            Operation = $operation
                            Token = $token
                        })
                }
            }
            catch {
                throw "Trusted-control IL member token could not be resolved: $token"
            }
        } elseif ($IncludeInstructions) {
            $references.Add([pscustomobject]@{
                    Method = $null
                    Member = $null
                    Operation = $operation
                    Token = $null
                })
        }
        $index += $operandSize
    }
    return $references.ToArray()
}

function Get-PspktTrustedControlReferencedTypes {
    param([Reflection.MethodBase]$Method)

    $types = [Collections.Generic.List[Type]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($reference in Get-PspktTrustedControlCalledMethodReferences `
        -Method $Method -IncludeInstructions) {
        if ($reference.Operation.OperandType -cnotin @(
            [Reflection.Emit.OperandType]::InlineField,
            [Reflection.Emit.OperandType]::InlineType,
            [Reflection.Emit.OperandType]::InlineTok)) {
            continue
        }
        $member = $reference.Member
        $candidates = [Collections.Generic.List[Type]]::new()
        if ($member -is [Type]) {
            $candidates.Add($member)
        } elseif ($member -is [Reflection.FieldInfo]) {
            if ($null -ne $member.DeclaringType) { $candidates.Add($member.DeclaringType) }
            $candidates.Add($member.FieldType)
        } elseif ($member -is [Reflection.MethodBase] -and
            $null -ne $member.DeclaringType) {
            $candidates.Add($member.DeclaringType)
        }
        foreach ($candidate in $candidates) {
            if ($null -ne $candidate) {
                $nodes = 0
                $identity = Get-PspktTrustedControlTypeIdentity `
                    -Type $candidate -Depth 0 -NodeCount ([ref]$nodes)
                if ($seen.Add($identity)) { $types.Add($candidate) }
            }
        }
    }
    return $types.ToArray()
}

function Get-PspktTrustedControlAssemblyMethods {
    param(
        [Reflection.Assembly]$Assembly,
        [int]$MethodDefinitionCount
    )

    $methods = [Collections.Generic.List[Reflection.MethodBase]]::new()
    $byToken = [Collections.Generic.Dictionary[int,Reflection.MethodBase]]::new()
    $flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
    try {
        $types = @($Assembly.GetTypes())
    }
    catch {
        throw "Trusted-control MethodDef type inventory could not be loaded: $($_.Exception.Message)"
    }
    foreach ($type in $types) {
        foreach ($method in @($type.GetMethods($flags)) +
            @($type.GetConstructors($flags)) + @($type.TypeInitializer)) {
            if ($null -eq $method) { continue }
            if ($byToken.ContainsKey($method.MetadataToken)) {
                $existing = $byToken[$method.MetadataToken]
                if ($existing.DeclaringType -ne $method.DeclaringType -or
                    $existing.Name -cne $method.Name) {
                    throw "Trusted-control MethodDef inventory has a duplicate token: $($method.MetadataToken)"
                }
                continue
            }
            $byToken.Add($method.MetadataToken,$method)
        }
    }
    if ($byToken.Count -ne $MethodDefinitionCount) {
        throw "Trusted-control MethodDef inventory is incomplete: native=$MethodDefinitionCount reflection=$($byToken.Count)"
    }
    for ($row = 1; $row -le $MethodDefinitionCount; $row++) {
        $token = 0x06000000 -bor $row
        $method = $null
        if (-not $byToken.TryGetValue($token,[ref]$method)) {
            throw "Trusted-control MethodDef inventory is missing token: $token"
        }
        $methods.Add($method)
    }
    return $methods.ToArray()
}

function Get-PspktTrustedControlTypeIdentity {
    param(
        [Type]$Type,
        [int]$Depth,
        [ref]$NodeCount
    )

    if ($Depth -gt 32 -or ++$NodeCount.Value -gt 512) {
        throw 'Trusted-control structural type identity exceeded its bounds.'
    }
    if ($Type.IsGenericParameter) {
        $owner = if ($null -ne $Type.DeclaringMethod) {
            $Type.DeclaringMethod
        } else {
            $Type.DeclaringType
        }
        $ownerKind = if ($null -ne $Type.DeclaringMethod) { 'M' } else { 'T' }
        return '{0}|{1}|{2}|{3}|{4}' -f $ownerKind,
            $owner.Module.ModuleVersionId.ToString('D'),
            $owner.MetadataToken,
            $Type.GenericParameterPosition,
            $Type.GenericParameterAttributes
    }
    if ($Type.HasElementType) {
        $element = $Type.GetElementType()
        $elementIdentity = Get-PspktTrustedControlTypeIdentity `
            -Type $element `
            -Depth ($Depth + 1) `
            -NodeCount $NodeCount
        $kind = if ($Type.IsByRef) {
            'R'
        } elseif ($Type.IsPointer) {
            'P'
        } elseif ($Type.GetArrayRank() -eq 1 -and
            $Type -eq $element.MakeArrayType()) {
            'S'
        } else {
            'A' + $Type.GetArrayRank()
        }
        return '{0}|{1}:{2}' -f $kind,$elementIdentity.Length,$elementIdentity
    }
    $definition = if ($Type.IsGenericType) {
        $Type.GetGenericTypeDefinition()
    } else {
        $Type
    }
    $identity = '{0}|{1}' -f
        $definition.Module.ModuleVersionId.ToString('D'),
        $definition.MetadataToken
    if ($Type.IsGenericType) {
        foreach ($argument in $Type.GetGenericArguments()) {
            $argumentIdentity = Get-PspktTrustedControlTypeIdentity `
                -Type $argument `
                -Depth ($Depth + 1) `
                -NodeCount $NodeCount
            $identity += '|{0}:{1}' -f $argumentIdentity.Length,$argumentIdentity
        }
    }
    return $identity
}

function Get-PspktTrustedControlMethodIdentity {
    param([Reflection.MethodBase]$Method)

    $nodes = 0
    $ownerIdentity = Get-PspktTrustedControlTypeIdentity `
        -Type $Method.DeclaringType `
        -Depth 0 `
        -NodeCount ([ref]$nodes)
    $identity = '{0}|{1}|{2}:{3}' -f
        $Method.Module.ModuleVersionId.ToString('D'),
        $Method.MetadataToken,
        $ownerIdentity.Length,
        $ownerIdentity
    if ($Method.IsGenericMethod) {
        foreach ($argument in $Method.GetGenericArguments()) {
            $argumentIdentity = Get-PspktTrustedControlTypeIdentity `
                -Type $argument `
                -Depth 0 `
                -NodeCount ([ref]$nodes)
            $identity += '|{0}:{1}' -f $argumentIdentity.Length,$argumentIdentity
        }
    }
    return $identity
}

function Test-PspktTrustedControlAuthorityTypeReference {
    param(
        [Type]$Type,
        [Collections.Generic.HashSet[string]]$Visited
    )

    if ($null -eq $Type) { return $false }
    $authorityTypeName =
        'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA'
    $typeName = $Type.FullName
    if ($null -ne $typeName -and
        ($typeName -ceq $authorityTypeName -or
        $typeName.StartsWith($authorityTypeName + '+',[StringComparison]::Ordinal))) {
        return $true
    }
    $nodes = 0
    $identity = Get-PspktTrustedControlTypeIdentity `
        -Type $Type `
        -Depth 0 `
        -NodeCount ([ref]$nodes)
    if (-not $Visited.Add($identity)) { return $false }
    if ($Type.HasElementType -and
        (Test-PspktTrustedControlAuthorityTypeReference `
            -Type $Type.GetElementType() `
            -Visited $Visited)) {
        return $true
    }
    if ($Type.IsGenericType) {
        foreach ($argument in $Type.GetGenericArguments()) {
            if (Test-PspktTrustedControlAuthorityTypeReference `
                -Type $argument `
                -Visited $Visited) {
                return $true
            }
        }
    }
    if ($Type.IsGenericParameter) {
        foreach ($constraint in $Type.GetGenericParameterConstraints()) {
            if (Test-PspktTrustedControlAuthorityTypeReference `
                -Type $constraint `
                -Visited $Visited) {
                return $true
            }
        }
    }
    return $false
}

function Test-PspktTrustedControlAuthorityAttributeArgument {
    param(
        [Reflection.CustomAttributeTypedArgument]$Argument,
        [Collections.Generic.HashSet[string]]$Visited
    )

    if (Test-PspktTrustedControlAuthorityTypeReference `
        -Type $Argument.ArgumentType `
        -Visited $Visited) {
        return $true
    }
    if ($Argument.Value -is [Type]) {
        return Test-PspktTrustedControlAuthorityTypeReference `
            -Type $Argument.Value `
            -Visited $Visited
    }
    if ($Argument.Value -is [Collections.IEnumerable] -and
        -not ($Argument.Value -is [string])) {
        foreach ($item in $Argument.Value) {
            if ($item -is [Reflection.CustomAttributeTypedArgument] -and
                (Test-PspktTrustedControlAuthorityAttributeArgument `
                    -Argument $item `
                    -Visited $Visited)) {
                return $true
            }
        }
    }
    return $false
}

function Test-PspktTrustedControlAuthorityCustomAttributes {
    param($Provider)

    foreach ($attribute in @($Provider.CustomAttributes)) {
        $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        if (Test-PspktTrustedControlAuthorityTypeReference `
            -Type $attribute.Constructor.DeclaringType `
            -Visited $visited) {
            return $true
        }
        foreach ($argument in $attribute.ConstructorArguments) {
            if (Test-PspktTrustedControlAuthorityAttributeArgument `
                -Argument $argument `
                -Visited $visited) {
                return $true
            }
        }
        foreach ($argument in $attribute.NamedArguments) {
            if (Test-PspktTrustedControlAuthorityAttributeArgument `
                -Argument $argument.TypedValue `
                -Visited $visited) {
                return $true
            }
        }
    }
    return $false
}

function Test-PspktTrustedControlForbiddenCryptoType {
    param(
        [Type]$Type,
        [Collections.Generic.HashSet[string]]$Visited
    )

    if ($null -eq $Type) { return $false }
    $nodes = 0
    $identity = Get-PspktTrustedControlTypeIdentity `
        -Type $Type `
        -Depth 0 `
        -NodeCount ([ref]$nodes)
    if (-not $Visited.Add($identity)) { return $false }
    if ($Visited.Count -gt 512) {
        throw 'Trusted-control cryptography type closure exceeded its bound.'
    }
    if ($Type.HasElementType -and
        (Test-PspktTrustedControlForbiddenCryptoType `
            -Type $Type.GetElementType() `
            -Visited $Visited)) {
        return $true
    }
    $namespace = $Type.Namespace
    if ($null -ne $namespace -and
        ($namespace -eq 'System.Security.Policy' -or
        $namespace.StartsWith('System.Security.Policy.',[StringComparison]::Ordinal))) {
        return $true
    }
    if ($null -ne $namespace -and
        ($namespace -eq 'System.Security.Cryptography' -or
        $namespace.StartsWith(
            'System.Security.Cryptography.',
            [StringComparison]::Ordinal))) {
        return $Type.FullName -cnotin @(
            'System.Security.Cryptography.SHA256',
            'System.Security.Cryptography.HashAlgorithm')
    }
    if ($Type.IsGenericType) {
        foreach ($argument in $Type.GetGenericArguments()) {
            if (Test-PspktTrustedControlForbiddenCryptoType `
                -Type $argument `
                -Visited $Visited) {
                return $true
            }
        }
    }
    if ($Type.IsGenericParameter) {
        foreach ($constraint in $Type.GetGenericParameterConstraints()) {
            if (Test-PspktTrustedControlForbiddenCryptoType `
                -Type $constraint `
                -Visited $Visited) {
                return $true
            }
        }
    }
    if ($Type.Assembly.GetName().Name -cin @(
        'TrustedControlJsonBootstrap','TrustedControlVerify')) {
        if ($null -ne $Type.BaseType -and
            $Type.BaseType.FullName -cin @(
                'System.Security.Cryptography.SHA256',
                'System.Security.Cryptography.HashAlgorithm')) {
            return $true
        }
        if (Test-PspktTrustedControlForbiddenCryptoType `
            -Type $Type.BaseType `
            -Visited $Visited) {
            return $true
        }
        foreach ($interface in $Type.GetInterfaces()) {
            if (Test-PspktTrustedControlForbiddenCryptoType `
                -Type $interface `
                -Visited $Visited) {
                return $true
            }
        }
    }
    return $false
}

function Test-PspktTrustedControlForbiddenCryptoAttributeArgument {
    param(
        [Reflection.CustomAttributeTypedArgument]$Argument,
        [Collections.Generic.HashSet[string]]$Visited
    )

    if (Test-PspktTrustedControlForbiddenCryptoType `
        -Type $Argument.ArgumentType `
        -Visited $Visited) {
        return $true
    }
    if ($Argument.Value -is [Type]) {
        return Test-PspktTrustedControlForbiddenCryptoType `
            -Type $Argument.Value `
            -Visited $Visited
    }
    if ($Argument.Value -is [Collections.IEnumerable] -and
        -not ($Argument.Value -is [string])) {
        foreach ($item in $Argument.Value) {
            if ($item -is [Reflection.CustomAttributeTypedArgument] -and
                (Test-PspktTrustedControlForbiddenCryptoAttributeArgument `
                    -Argument $item `
                    -Visited $Visited)) {
                return $true
            }
        }
    }
    return $false
}

function Assert-PspktTrustedControlCustomAttributes {
    param(
        $Provider,
        [string]$Label,
        [string]$Site
    )

    foreach ($attribute in @($Provider.CustomAttributes)) {
        $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        if (Test-PspktTrustedControlForbiddenCryptoType `
            -Type $attribute.Constructor.DeclaringType `
            -Visited $visited) {
            throw "$Label assembly uses forbidden cryptography: $Site"
        }
        foreach ($argument in $attribute.ConstructorArguments) {
            if (Test-PspktTrustedControlForbiddenCryptoAttributeArgument `
                -Argument $argument `
                -Visited $visited) {
                throw "$Label assembly uses forbidden cryptography: $Site"
            }
        }
        foreach ($argument in $attribute.NamedArguments) {
            if (Test-PspktTrustedControlForbiddenCryptoAttributeArgument `
                -Argument $argument.TypedValue `
                -Visited $visited) {
                throw "$Label assembly uses forbidden cryptography: $Site"
            }
        }
    }
    if (Test-PspktTrustedControlAuthorityCustomAttributes -Provider $Provider) {
        throw "$Label assembly metadata references authority projection A: $Site"
    }
}

function Assert-PspktTrustedControlMetadataType {
    param(
        [Type]$Type,
        [string]$Label,
        [string]$Site
    )

    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if (Test-PspktTrustedControlAuthorityTypeReference -Type $Type -Visited $visited) {
        throw "$Label assembly metadata references authority projection A: $Site"
    }
    $visited.Clear()
    if (Test-PspktTrustedControlForbiddenCryptoType -Type $Type -Visited $visited) {
        throw "$Label assembly uses forbidden cryptography: $Site"
    }
}

function Test-PspktTrustedControlForbiddenDynamicCall {
    param([Reflection.MethodBase]$Method)

    if ($null -eq $Method.DeclaringType) { return $false }
    $declaringType = $Method.DeclaringType
    $namespace = $declaringType.Namespace
    $typeName = $declaringType.FullName
    $methodName = $Method.Name
    if ($namespace -eq 'System.Reflection' -or
        ($null -ne $namespace -and $namespace.StartsWith(
            'System.Reflection.',
            [StringComparison]::Ordinal))) {
        return $true
    }
    if ($null -ne $namespace -and
        ($namespace.StartsWith('System.Reflection.Emit',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('System.Linq.Expressions',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('Microsoft.CSharp',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('Microsoft.VisualBasic',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('System.CodeDom',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('System.Management.Automation',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('System.Runtime.InteropServices',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('System.Runtime.Loader',[StringComparison]::Ordinal) -or
        $namespace.StartsWith('System.Runtime.Serialization',[StringComparison]::Ordinal))) {
        return $true
    }
    if ($typeName -eq 'System.Type' -or
        $typeName -eq 'System.Activator' -or
        $typeName -eq 'System.AppDomain' -or
        $typeName -eq 'System._AppDomain' -or
        $typeName -eq 'System.ComponentModel.TypeDescriptor') {
        return $true
    }
    if ($typeName -eq 'System.Security.Cryptography.CryptoConfig' -and
        $methodName -eq 'CreateFromName') {
        return $true
    }
    if ($namespace -eq 'System.Security.Cryptography' -and
        $methodName -eq 'Create') {
        $parameters = $Method.GetParameters()
        if ($parameters.Count -eq 1 -and $parameters[0].ParameterType -eq [string]) {
            return $true
        }
    }
    if (($typeName -eq 'System.Delegate' -or $typeName -eq 'System.MulticastDelegate') -and
        ($methodName -eq 'CreateDelegate' -or $methodName -eq 'DynamicInvoke')) {
        return $true
    }
    if ($typeName -eq 'System.Runtime.CompilerServices.RuntimeHelpers' -and
        $methodName -eq 'RunClassConstructor') {
        return $true
    }
    return $false
}

function Assert-PspktTrustedControlCryptoCall {
    param(
        [Reflection.MethodBase]$Called,
        [string]$Label,
        [string]$Site
    )

    if ($null -eq $Called.DeclaringType) { return }
    $owner = $Called.DeclaringType.FullName
    if ($null -eq $owner -or
        -not $owner.StartsWith(
            'System.Security.Cryptography.',
            [StringComparison]::Ordinal)) {
        return
    }
    $method = $Called -as [Reflection.MethodInfo]
    $parameters = $Called.GetParameters()
    if ($owner -ceq 'System.Security.Cryptography.SHA256' -and
        $Called.Name -ceq 'Create' -and
        $Called.IsStatic -and
        $null -ne $method -and
        $method.ReturnType -eq [Security.Cryptography.SHA256] -and
        $parameters.Count -eq 0) {
        return
    }
    if ($owner -ceq 'System.Security.Cryptography.HashAlgorithm' -and
        $Called.Name -ceq 'ComputeHash' -and
        -not $Called.IsStatic -and
        $null -ne $method -and
        $method.ReturnType -eq [byte[]] -and
        $parameters.Count -eq 1 -and
        $parameters[0].ParameterType -eq [byte[]]) {
        return
    }
    throw "$Label assembly uses forbidden cryptography: $Site -> $owner.$($Called.Name)"
}

function Assert-PspktTrustedControlSupportedInterfaceMethod {
    param(
        [Reflection.MethodBase]$Method,
        [string]$Label
    )

    $interfaceMethod = $Method -as [Reflection.MethodInfo]
    if ($null -ne $interfaceMethod -and
        $null -ne $interfaceMethod.DeclaringType -and
        $interfaceMethod.DeclaringType.IsInterface -and
        $interfaceMethod.IsStatic -and
        ($interfaceMethod.IsAbstract -or $interfaceMethod.IsVirtual)) {
        throw "$Label uses an unsupported static interface member: $($interfaceMethod.DeclaringType).$($interfaceMethod.Name)"
    }
}

function Assert-PspktTrustedControlInterfaceMapTargets {
    param(
        [Reflection.InterfaceMapping]$InterfaceMap,
        [Type]$Implementer
    )

    if ($null -eq $InterfaceMap.InterfaceMethods -or
        $null -eq $InterfaceMap.TargetMethods -or
        $InterfaceMap.InterfaceMethods.Count -ne $InterfaceMap.TargetMethods.Count) {
        throw "Trusted-control interface map has an incomplete target set: $Implementer"
    }
    foreach ($target in $InterfaceMap.TargetMethods) {
        if ($null -eq $target) {
            throw "Trusted-control interface map has a null target: $Implementer"
        }
    }
}

function Assert-PspktTrustedControlCheckedAssemblyShape {
    param(
        [Reflection.Assembly]$Assembly,
        [string]$Label
    )

    $flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
    foreach ($type in $Assembly.GetTypes()) {
        if ($type.IsInterface) {
            foreach ($method in $type.GetMethods($flags)) {
                Assert-PspktTrustedControlSupportedInterfaceMethod `
                    -Method $method -Label "$Label interface shape"
            }
            continue
        }
        $baseType = $type.BaseType
        $depth = 0
        while ($null -ne $baseType) {
            if (++$depth -gt 16384) {
                throw "$Label assembly base hierarchy exceeded its bound: $type"
            }
            if (-not [object]::ReferenceEquals($baseType.Assembly,$Assembly)) {
                $canonicalType = switch -CaseSensitive ($baseType.FullName) {
                    'System.Object' { [object]; break }
                    'System.ValueType' { [ValueType]; break }
                    'System.Enum' { [Enum]; break }
                    default { $null }
                }
                if ($null -eq $canonicalType -or $baseType -ne $canonicalType) {
                    throw "$Label assembly has an unsupported external base: $type -> $baseType"
                }
            }
            $baseType = $baseType.BaseType
        }
        foreach ($interfaceType in $type.GetInterfaces()) {
            foreach ($method in $interfaceType.GetMethods($flags)) {
                Assert-PspktTrustedControlSupportedInterfaceMethod `
                    -Method $method -Label "$Label interface shape"
            }
        }
        foreach ($method in $type.GetMethods($flags)) {
            if (-not $method.IsVirtual) { continue }
            foreach ($attribute in $method.CustomAttributes) {
                if ($attribute.AttributeType.FullName -ceq
                    'System.Runtime.CompilerServices.PreserveBaseOverridesAttribute') {
                    throw "$Label assembly uses an unsupported covariant override: $type.$($method.Name)"
                }
            }
        }
    }
}

function Assert-PspktTrustedControlMethodImplRows {
    param(
        [Reflection.Assembly]$Assembly,
        [byte[]]$AssemblyBytes,
        [string]$Label
    )

    $module = $Assembly.ManifestModule
    $seenDeclarations = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    foreach ($row in [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetMethodImplRows(
            $AssemblyBytes,$Label)) {
        try {
            $owner = $module.ResolveType($row.ClassToken)
            if ($null -eq $owner -or $owner.IsInterface -or
                -not [object]::ReferenceEquals($owner.Assembly,$Assembly)) {
                throw 'MethodImpl Class is not a checked class or struct.'
            }
            [Type[]]$typeArguments = @($owner.GetGenericArguments())
            [Type[]]$methodArguments = @()
            $body = $module.ResolveMethod(
                $row.MethodBodyToken,$typeArguments,$methodArguments)
            if ($body -isnot [Reflection.MethodInfo] -or
                $body.DeclaringType -ne $owner) {
                throw 'MethodImpl Body does not belong to Class.'
            }
            if ($body.IsGenericMethod) {
                $methodArguments = [Type[]]@($body.GetGenericArguments())
            }
            $declaration = $module.ResolveMethod(
                $row.MethodDeclarationToken,$typeArguments,$methodArguments)
            if ($declaration -isnot [Reflection.MethodInfo] -or
                $null -eq $declaration.DeclaringType) {
                throw 'MethodImpl Declaration is not a method.'
            }
        }
        catch {
            throw "$Label assembly MethodImpl row could not be resolved: $($_.Exception.Message)"
        }
        if (-not $declaration.DeclaringType.IsInterface) {
            throw "$Label assembly has an unsupported class MethodImpl: $owner.$($body.Name)"
        }
        $declarationKey = "$($row.ClassToken):$($declaration.Module.ModuleVersionId):$($declaration.MetadataToken):$($declaration.DeclaringType)"
        $bodyKey = Get-PspktTrustedControlMethodIdentity -Method $body
        $existingBody = $null
        if ($seenDeclarations.TryGetValue($declarationKey,[ref]$existingBody)) {
            throw "$Label assembly has an ambiguous MethodImpl declaration: $owner.$($declaration.Name)"
        }
        $seenDeclarations.Add($declarationKey,$bodyKey)
        $matched = $false
        foreach ($interfaceType in $owner.GetInterfaces()) {
            if ($interfaceType -ne $declaration.DeclaringType) { continue }
            try {
                $interfaceMap = $owner.GetInterfaceMap($interfaceType)
            }
            catch {
                throw "$Label assembly MethodImpl interface map failed: $owner.$($declaration.Name)"
            }
            Assert-PspktTrustedControlInterfaceMapTargets `
                -InterfaceMap $interfaceMap -Implementer $owner
            for ($index = 0; $index -lt $interfaceMap.InterfaceMethods.Count; $index++) {
                $target = $interfaceMap.TargetMethods[$index]
                $interfaceMethod = $interfaceMap.InterfaceMethods[$index]
                if ($interfaceMethod.Module.ModuleVersionId -eq
                        $declaration.Module.ModuleVersionId -and
                    $interfaceMethod.MetadataToken -eq $declaration.MetadataToken -and
                    $target.Module.ModuleVersionId -eq $body.Module.ModuleVersionId -and
                    $target.MetadataToken -eq $body.MetadataToken -and
                    $target.DeclaringType -eq $body.DeclaringType) {
                    $matched = $true
                }
            }
        }
        if (-not $matched) {
            throw "$Label assembly MethodImpl declaration/body does not match its interface map: $owner.$($body.Name)"
        }
    }
}

function Assert-PspktTrustedControlAssemblyWideAuthorityIsolation {
    param(
        [Reflection.Assembly]$Assembly,
        [string]$Label,
        [int]$MethodDefinitionCount,
        [switch]$SkipAuthorityImplementation
    )

    $authorityTypeName =
        'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA'
    $expectedEvaluateMethod = $null
    $expectedValidateMethod = $null
    $bridgeCalls = 0
    if ($Label -ceq 'Bootstrap') {
        $bootstrapType = $Assembly.GetType(
            'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap',
            $true)
        $trustedJsonObjectType = $Assembly.GetType(
            'Pspkt.Certification.TrustedControl.TrustedJsonObject',
            $true)
        $authorityType = $Assembly.GetType($authorityTypeName,$true)
        $evaluateCandidates = @($bootstrapType.GetMethods(
                [Reflection.BindingFlags]'Public,Static,DeclaredOnly') | Where-Object {
                $_.Name -ceq 'Evaluate' -and
                -not $_.IsGenericMethod -and
                $_.ReturnType.FullName -ceq (
                    'Pspkt.Certification.TrustedControl.TrustedJsonResult') -and
                $_.GetParameters().Count -eq 4 -and
                $_.GetParameters()[0].ParameterType -eq [string] -and
                $_.GetParameters()[1].ParameterType -eq [byte[]] -and
                $_.GetParameters()[2].ParameterType -eq [byte[]] -and
                $_.GetParameters()[3].ParameterType -eq [byte[]]
            })
        $validateCandidates = @($authorityType.GetMethods(
                [Reflection.BindingFlags]'NonPublic,Static,DeclaredOnly') | Where-Object {
                $_.Name -ceq 'Validate' -and
                -not $_.IsGenericMethod -and
                $_.ReturnType -eq [void] -and
                $_.GetParameters().Count -eq 3 -and
                $_.GetParameters()[0].ParameterType -eq $trustedJsonObjectType -and
                $_.GetParameters()[1].ParameterType -eq $trustedJsonObjectType -and
                $_.GetParameters()[2].ParameterType -eq $trustedJsonObjectType
            })
        if ($evaluateCandidates.Count -ne 1 -or $validateCandidates.Count -ne 1) {
            throw 'Bootstrap authority bridge shape differs.'
        }
        $expectedEvaluateMethod = $evaluateCandidates[0]
        $expectedValidateMethod = $validateCandidates[0]
    }
    Assert-PspktTrustedControlCustomAttributes `
        -Provider $Assembly -Label $Label -Site 'assembly custom attributes'
    Assert-PspktTrustedControlCustomAttributes `
        -Provider $Assembly.ManifestModule -Label $Label -Site 'module custom attributes'
    $flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
    foreach ($type in $Assembly.GetTypes()) {
        $typeName = $type.FullName
        if ($null -eq $typeName) { $typeName = '<GenericType>' }
        $typeIsAuthority = $typeName -ceq $authorityTypeName -or
            $typeName.StartsWith($authorityTypeName + '+',[StringComparison]::Ordinal)
        if ($type.IsImport) {
            throw "$Label assembly uses forbidden COM import: $typeName"
        }
        if ($SkipAuthorityImplementation -and $typeIsAuthority) { continue }
        Assert-PspktTrustedControlMetadataType `
            -Type $type.BaseType `
            -Label $Label `
            -Site "$typeName base type"
        foreach ($interfaceType in $type.GetInterfaces()) {
            Assert-PspktTrustedControlMetadataType `
                -Type $interfaceType `
                -Label $Label `
                -Site "$typeName interface"
        }
        foreach ($genericArgument in $type.GetGenericArguments()) {
            Assert-PspktTrustedControlMetadataType `
                -Type $genericArgument `
                -Label $Label `
                -Site "$typeName generic argument or constraint"
            if ($genericArgument.IsGenericParameter) {
                Assert-PspktTrustedControlCustomAttributes `
                    -Provider $genericArgument `
                    -Label $Label `
                    -Site "$typeName generic parameter attributes"
            }
        }
        Assert-PspktTrustedControlCustomAttributes `
            -Provider $type -Label $Label -Site "$typeName custom attributes"
        foreach ($field in $type.GetFields($flags)) {
            Assert-PspktTrustedControlMetadataType `
                -Type $field.FieldType `
                -Label $Label `
                -Site "$typeName.$($field.Name) field"
            Assert-PspktTrustedControlCustomAttributes `
                -Provider $field `
                -Label $Label `
                -Site "$typeName.$($field.Name) field attributes"
        }
        foreach ($property in $type.GetProperties($flags)) {
            Assert-PspktTrustedControlMetadataType `
                -Type $property.PropertyType `
                -Label $Label `
                -Site "$typeName.$($property.Name) property"
            foreach ($parameter in $property.GetIndexParameters()) {
                Assert-PspktTrustedControlMetadataType `
                    -Type $parameter.ParameterType `
                    -Label $Label `
                    -Site "$typeName.$($property.Name) index parameter"
                Assert-PspktTrustedControlCustomAttributes `
                    -Provider $parameter `
                    -Label $Label `
                    -Site "$typeName.$($property.Name) index parameter attributes"
            }
            Assert-PspktTrustedControlCustomAttributes `
                -Provider $property `
                -Label $Label `
                -Site "$typeName.$($property.Name) property attributes"
        }
        foreach ($event in $type.GetEvents($flags)) {
            Assert-PspktTrustedControlMetadataType `
                -Type $event.EventHandlerType `
                -Label $Label `
                -Site "$typeName.$($event.Name) event"
            Assert-PspktTrustedControlCustomAttributes `
                -Provider $event `
                -Label $Label `
                -Site "$typeName.$($event.Name) event attributes"
        }
    }
    foreach ($method in Get-PspktTrustedControlAssemblyMethods `
        -Assembly $Assembly `
        -MethodDefinitionCount $MethodDefinitionCount) {
        $sourceTypeName = if ($null -ne $method.DeclaringType) {
            $method.DeclaringType.FullName
        } else {
            '<Module>'
        }
        if ($null -eq $sourceTypeName) { $sourceTypeName = '<GenericType>' }
        $sourceIsAuthority = $sourceTypeName -ceq $authorityTypeName -or
            $sourceTypeName.StartsWith($authorityTypeName + '+',[StringComparison]::Ordinal)
        $implementation = $method.GetMethodImplementationFlags()
        if (($method.Attributes -band [Reflection.MethodAttributes]::PinvokeImpl) -ne 0 -or
            $method.IsDefined([Runtime.InteropServices.DllImportAttribute],$false) -or
            ($implementation -band [Reflection.MethodImplAttributes]::InternalCall) -ne 0 -or
            ($implementation -band [Reflection.MethodImplAttributes]::CodeTypeMask) -ne
                [Reflection.MethodImplAttributes]::IL -or
            ($implementation -band [Reflection.MethodImplAttributes]::ManagedMask) -ne
                [Reflection.MethodImplAttributes]::Managed) {
            throw "$Label assembly uses forbidden native import: $sourceTypeName.$($method.Name)"
        }
        $body = $method.GetMethodBody()
        if ($null -eq $body -and
            -not ($method.IsAbstract -and $null -ne $method.DeclaringType -and
                ($method.DeclaringType.IsAbstract -or $method.DeclaringType.IsInterface))) {
            throw "$Label assembly MethodDef has no verifiable body: $sourceTypeName.$($method.Name)"
        }
        if ($SkipAuthorityImplementation -and $sourceIsAuthority) {
            foreach ($callReference in Get-PspktTrustedControlCalledMethodReferences `
                -Method $method) {
                Assert-PspktTrustedControlSupportedInterfaceMethod `
                    -Method $callReference.Method -Label "$Label assembly IL"
            }
            continue
        }
        $methodInfo = $method -as [Reflection.MethodInfo]
        if ($null -ne $methodInfo) {
            Assert-PspktTrustedControlMetadataType `
                -Type $methodInfo.ReturnType `
                -Label $Label `
                -Site "$sourceTypeName.$($method.Name) return type"
            Assert-PspktTrustedControlCustomAttributes `
                -Provider $methodInfo.ReturnParameter `
                -Label $Label `
                -Site "$sourceTypeName.$($method.Name) return attributes"
        }
        foreach ($parameter in $method.GetParameters()) {
            Assert-PspktTrustedControlMetadataType `
                -Type $parameter.ParameterType `
                -Label $Label `
                -Site "$sourceTypeName.$($method.Name) parameter $($parameter.Name)"
            Assert-PspktTrustedControlCustomAttributes `
                -Provider $parameter `
                -Label $Label `
                -Site "$sourceTypeName.$($method.Name) parameter attributes"
        }
        if ($null -ne $methodInfo) {
            foreach ($genericArgument in $methodInfo.GetGenericArguments()) {
                Assert-PspktTrustedControlMetadataType `
                    -Type $genericArgument `
                    -Label $Label `
                    -Site "$sourceTypeName.$($method.Name) generic argument or constraint"
                if ($genericArgument.IsGenericParameter) {
                    Assert-PspktTrustedControlCustomAttributes `
                        -Provider $genericArgument `
                        -Label $Label `
                        -Site "$sourceTypeName.$($method.Name) generic parameter attributes"
                }
            }
        }
        Assert-PspktTrustedControlCustomAttributes `
            -Provider $method `
            -Label $Label `
            -Site "$sourceTypeName.$($method.Name) custom attributes"
        if ($null -ne $body) {
            foreach ($local in $body.LocalVariables) {
                Assert-PspktTrustedControlMetadataType `
                    -Type $local.LocalType `
                    -Label $Label `
                    -Site "$sourceTypeName.$($method.Name) local"
            }
            foreach ($handler in $body.ExceptionHandlingClauses) {
                Assert-PspktTrustedControlMetadataType `
                    -Type $handler.CatchType `
                    -Label $Label `
                    -Site "$sourceTypeName.$($method.Name) catch"
            }
        }
        foreach ($callReference in Get-PspktTrustedControlCalledMethodReferences -Method $method) {
            $called = $callReference.Method
            Assert-PspktTrustedControlSupportedInterfaceMethod `
                -Method $called -Label "$Label assembly IL"
            if ($null -eq $called.DeclaringType) {
                throw "$Label assembly IL method has no declaring type: $sourceTypeName.$($method.Name)"
            }
            $targetName = $called.DeclaringType.FullName
            if ($null -eq $targetName) { $targetName = $called.DeclaringType.ToString() }
            if ($targetName -ceq (
                    'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap') -and
                $called.Name -ceq 'Evaluate') {
                if ($Label -ceq 'Verify') {
                    throw 'Verifier uses a forbidden Bootstrap member: Evaluate'
                }
                throw 'Bootstrap authority bridge shape differs: Evaluate is rebound.'
            }
            $isBootstrapEvaluateValidation =
                $Label -ceq 'Bootstrap' -and
                -not $method.IsGenericMethod -and
                -not $called.IsGenericMethod -and
                $method.Module.ModuleVersionId -eq
                    $expectedEvaluateMethod.Module.ModuleVersionId -and
                $method.MetadataToken -eq $expectedEvaluateMethod.MetadataToken -and
                $called.Module.ModuleVersionId -eq
                    $expectedValidateMethod.Module.ModuleVersionId -and
                $called.MetadataToken -eq $expectedValidateMethod.MetadataToken -and
                $callReference.Operation.Value -eq [Reflection.Emit.OpCodes]::Call.Value
            if ($isBootstrapEvaluateValidation) { $bridgeCalls++ }
            if (-not $isBootstrapEvaluateValidation) {
                if (Test-PspktTrustedControlForbiddenDynamicCall -Method $called) {
                    throw "$Label assembly uses forbidden dynamic resolution: $sourceTypeName.$($method.Name) -> $targetName.$($called.Name)"
                }
                Assert-PspktTrustedControlCryptoCall `
                    -Called $called `
                    -Label $Label `
                    -Site "$sourceTypeName.$($method.Name)"
                Assert-PspktTrustedControlMetadataType `
                    -Type $called.DeclaringType `
                    -Label $Label `
                    -Site "$sourceTypeName.$($method.Name) called declaring type"
                $calledMethodInfo = $called -as [Reflection.MethodInfo]
                if ($null -ne $calledMethodInfo) {
                    Assert-PspktTrustedControlMetadataType `
                        -Type $calledMethodInfo.ReturnType `
                        -Label $Label `
                        -Site "$sourceTypeName.$($method.Name) called return type"
                    foreach ($genericArgument in $calledMethodInfo.GetGenericArguments()) {
                        Assert-PspktTrustedControlMetadataType `
                            -Type $genericArgument `
                            -Label $Label `
                            -Site "$sourceTypeName.$($method.Name) MethodSpec generic argument"
                    }
                }
                foreach ($calledParameter in $called.GetParameters()) {
                    Assert-PspktTrustedControlMetadataType `
                            -Type $calledParameter.ParameterType `
                            -Label $Label `
                            -Site "$sourceTypeName.$($method.Name) called parameter"
                }
            }
            if ($targetName -ceq $authorityTypeName -or
                $targetName.StartsWith($authorityTypeName + '+',[StringComparison]::Ordinal)) {
                if ($isBootstrapEvaluateValidation) { continue }
                throw "$Label assembly-wide IL references authority projection A: $sourceTypeName.$($method.Name) -> $targetName.$($called.Name)"
            }
        }
        foreach ($referencedType in Get-PspktTrustedControlReferencedTypes -Method $method) {
            $targetName = $referencedType.FullName
            Assert-PspktTrustedControlMetadataType `
                -Type $referencedType `
                -Label $Label `
                -Site "$sourceTypeName.$($method.Name) IL type/field/token"
        }
    }
    Assert-PspktTrustedControlCheckedAssemblyShape -Assembly $Assembly -Label $Label
    if ($Label -ceq 'Bootstrap' -and $bridgeCalls -ne 1) {
        throw 'Bootstrap authority bridge shape differs: direct Validate call count.'
    }
}

function Assert-PspktTrustedControlAuthorityProjectionShape {
    param(
        [Type]$ProjectionType,
        [int]$BootstrapMethodDefinitionCount
    )

    $flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
    $objectType = $ProjectionType.Assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonObject',$true)
    $arrayType = $ProjectionType.Assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonArray',$true)
    $dictionaryType = [Collections.Generic.Dictionary[string,object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@([string],$objectType))
    $returnType = [Collections.Generic.IDictionary[string,byte[]]]
    if (-not $ProjectionType.IsClass -or
        -not $ProjectionType.IsPublic -or
        -not $ProjectionType.IsAbstract -or
        -not $ProjectionType.IsSealed -or
        $ProjectionType.DeclaringType -ne $null -or
        $ProjectionType.IsGenericType -or
        $ProjectionType.BaseType -ne [object] -or
        $ProjectionType.GetInterfaces().Count -ne 0 -or
        $ProjectionType.GetConstructors($flags).Count -ne 0 -or
        $null -ne $ProjectionType.TypeInitializer -or
        $ProjectionType.GetNestedTypes($flags).Count -ne 0 -or
        $ProjectionType.GetProperties($flags).Count -ne 0 -or
        $ProjectionType.GetEvents($flags).Count -ne 0 -or
        $ProjectionType.CustomAttributes.Count -ne 0) {
        throw 'Trusted-control authority projection A shape differs.'
    }
    $fields = @($ProjectionType.GetFields($flags))
    if ($fields.Count -ne 1 -or
        $fields[0].Name -cne 'MaximumSizingRecursionDepth' -or
        -not $fields[0].IsPrivate -or
        -not $fields[0].IsStatic -or
        -not $fields[0].IsLiteral -or
        $fields[0].FieldType -ne [int] -or
        $fields[0].GetRawConstantValue() -ne 64 -or
        $fields[0].CustomAttributes.Count -ne 0 -or
        $fields[0].GetRequiredCustomModifiers().Count -ne 0 -or
        $fields[0].GetOptionalCustomModifiers().Count -ne 0) {
        throw 'Trusted-control authority projection A shape differs.'
    }
    $expected = @(
        @{ Name='Generate'; Return=$returnType; Parameters=@([byte[]],[byte[]],[byte[]]); Access='Public' },
        @{ Name='Validate'; Return=[void]; Parameters=@($objectType,$objectType,$objectType); Access='Assembly' },
        @{ Name='GenerateCore'; Return=$returnType; Parameters=@($objectType,$objectType,$objectType); Access='Private' },
        @{ Name='Prefix'; Return=[InvalidOperationException]; Parameters=@([InvalidOperationException]); Access='Private' },
        @{ Name='Project'; Return=[byte[]]; Parameters=@($objectType); Access='Private' },
        @{ Name='ProjectEntrypointDeclaration'; Return=[string]; Parameters=@([string]); Access='Private' },
        @{ Name='ReplaceExactlyOnce'; Return=[string]; Parameters=@([string],[string],[string]); Access='Private' },
        @{ Name='ValidateSizing'; Return=[void]; Parameters=@($objectType,$objectType,$arrayType); Access='Private' },
        @{ Name='SizeType'; Return=[uint64]; Parameters=@([string],$objectType,$dictionaryType,$objectType,[Collections.Generic.HashSet[string]],[int],[int].MakeByRefType()); Access='Private' },
        @{ Name='CountReachableRecordOccurrences'; Return=[uint64]; Parameters=@([string],[string],$dictionaryType,$objectType,[Collections.Generic.HashSet[string]],[uint64],[int]); Access='Private' },
        @{ Name='BytesEqual'; Return=[bool]; Parameters=@([byte[]],[byte[]]); Access='Private' }
    )
    $methods = @($ProjectionType.GetMethods($flags))
    $inventory = @(Get-PspktTrustedControlAssemblyMethods `
        -Assembly $ProjectionType.Assembly `
        -MethodDefinitionCount $BootstrapMethodDefinitionCount)
    if ($methods.Count -ne $expected.Count -or
        @($inventory | Where-Object DeclaringType -EQ $ProjectionType).Count -ne 11) {
        throw 'Trusted-control authority projection A shape differs.'
    }
    foreach ($shape in $expected) {
        $candidates = @($methods | Where-Object Name -CEQ $shape.Name)
        if ($candidates.Count -ne 1) {
            throw 'Trusted-control authority projection A shape differs.'
        }
        $method = $candidates[0]
        $access = if ($shape.Access -eq 'Public') {
            [Reflection.MethodAttributes]::Public
        } elseif ($shape.Access -eq 'Assembly') {
            [Reflection.MethodAttributes]::Assembly
        } else {
            [Reflection.MethodAttributes]::Private
        }
        $expectedAttributes = [Reflection.MethodAttributes](
            [int]$access -bor [int][Reflection.MethodAttributes]::Static -bor
            [int][Reflection.MethodAttributes]::HideBySig)
        if (-not $method.IsStatic -or $method.IsGenericMethod -or
            $method.ReturnType -ne $shape.Return -or
            $method.Attributes -ne $expectedAttributes -or
            $method.GetMethodImplementationFlags() -ne
                [Reflection.MethodImplAttributes]::IL -or
            $null -eq $method.GetMethodBody() -or
            $method.CustomAttributes.Count -ne 0 -or
            $method.ReturnParameter.Attributes -ne
                [Reflection.ParameterAttributes]::None -or
            $method.ReturnParameter.CustomAttributes.Count -ne 0 -or
            $method.ReturnParameter.GetRequiredCustomModifiers().Count -ne 0 -or
            $method.ReturnParameter.GetOptionalCustomModifiers().Count -ne 0) {
            throw 'Trusted-control authority projection A shape differs.'
        }
        $parameters = @($method.GetParameters())
        if ($parameters.Count -ne $shape.Parameters.Count) {
            throw 'Trusted-control authority projection A shape differs.'
        }
        for ($index = 0; $index -lt $parameters.Count; $index++) {
            if ($parameters[$index].ParameterType -ne $shape.Parameters[$index] -or
                $parameters[$index].Attributes -ne
                    [Reflection.ParameterAttributes]::None -or
                $parameters[$index].IsIn -or $parameters[$index].IsOut -or
                $parameters[$index].IsOptional -or
                $parameters[$index].HasDefaultValue -or
                $parameters[$index].CustomAttributes.Count -ne 0 -or
                $parameters[$index].GetRequiredCustomModifiers().Count -ne 0 -or
                $parameters[$index].GetOptionalCustomModifiers().Count -ne 0) {
                throw 'Trusted-control authority projection A shape differs.'
            }
        }
    }
}

function Assert-PspktTrustedControlAuthorityTokenSurface {
    param([Type]$ProjectionType)

    $assembly = $ProjectionType.Assembly
    $nodeType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonNode',$true)
    $objectType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonObject',$true)
    $arrayType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonArray',$true)
    $bootstrapType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap',$true)
    $objectDictionary = [Collections.Generic.Dictionary[string,object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@([string],$objectType))
    $nodeList = [Collections.Generic.IList[object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@($nodeType))
    $nodeCollection = [Collections.Generic.ICollection[object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@($nodeType))
    $approvedTypes = [Collections.Generic.HashSet[Type]]::new()
    foreach ($type in [Type[]]@(
        $ProjectionType,$bootstrapType,$nodeType,$objectType,$arrayType,
        [void],[bool],[byte[]],[int],[uint64],[string],[string[]],
        [object],[object[]],
        [StringComparison],[StringComparer],[Exception],[InvalidOperationException],
        [OverflowException],[Text.Encoding],[Text.UTF8Encoding],
        [Collections.Generic.IDictionary[string,byte[]]],
        [Collections.Generic.Dictionary[string,byte[]]],
        $objectDictionary,[Collections.Generic.HashSet[string]],
        [Collections.Generic.IEqualityComparer[string]],$nodeList,$nodeCollection,
        $objectType.MakeByRefType(),[int].MakeByRefType()
    )) {
        [void]$approvedTypes.Add($type)
    }
    $approvedOperandTypes = [Collections.Generic.HashSet[Type]]::new()
    foreach ($type in [Type[]]@([string],$objectType)) {
        [void]$approvedOperandTypes.Add($type)
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        foreach ($type in [Type[]]@([object],[int],[uint64])) {
            [void]$approvedOperandTypes.Add($type)
        }
    }
    foreach ($method in $ProjectionType.GetMethods(
        [Reflection.BindingFlags]'Public,NonPublic,Static,DeclaredOnly')) {
        $body = $method.GetMethodBody()
        if ($null -eq $body) {
            throw "Trusted-control authority projection A has no IL body: $($method.Name)"
        }
        $types = [Collections.Generic.List[Type]]::new()
        $types.Add($method.ReturnType)
        foreach ($parameter in $method.GetParameters()) {
            $types.Add($parameter.ParameterType)
        }
        foreach ($local in $body.LocalVariables) {
            $types.Add($local.LocalType)
        }
        foreach ($handler in $body.ExceptionHandlingClauses) {
            if ($null -ne $handler.CatchType) { $types.Add($handler.CatchType) }
        }
        foreach ($instruction in Get-PspktTrustedControlCalledMethodReferences `
            -Method $method -IncludeInstructions) {
            if ($null -eq $instruction.Token) { continue }
            $operand = $instruction.Operation.OperandType
            $member = $instruction.Member
            if ($operand -eq [Reflection.Emit.OperandType]::InlineMethod -and
                $member -is [Reflection.MethodBase] -and
                $instruction.Operation.Name -cin @('call','callvirt','newobj')) {
                if ($null -eq $member.DeclaringType -or
                    $member.IsGenericMethod -or
                    (Test-PspktTrustedControlForbiddenDynamicCall -Method $member)) {
                    throw "Trusted-control authority projection A token surface differs: $($method.Name)"
                }
                $types.Add($member.DeclaringType)
                $calledInfo = $member -as [Reflection.MethodInfo]
                if ($null -ne $calledInfo) { $types.Add($calledInfo.ReturnType) }
                foreach ($parameter in $member.GetParameters()) {
                    $types.Add($parameter.ParameterType)
                }
            } elseif ($operand -eq [Reflection.Emit.OperandType]::InlineType -and
                $member -is [Type] -and
                $approvedOperandTypes.Contains($member)) {
                $types.Add($member)
            } elseif ($operand -eq [Reflection.Emit.OperandType]::InlineString -and
                $member -is [string]) {
                continue
            } else {
                throw "Trusted-control authority projection A token surface differs: $($method.Name)"
            }
        }
        foreach ($type in $types) {
            if (-not $approvedTypes.Contains($type)) {
                throw "Trusted-control authority projection A type surface differs: $($method.Name) -> $type"
            }
        }
    }
}

function Assert-PspktTrustedControlAuthorityWrapper {
    param(
        [Reflection.Assembly]$AuthorityAssembly,
        [int]$MethodDefinitionCount,
        [Reflection.MethodInfo]$ProjectionGenerate
    )

    $type = $AuthorityAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedControlAuthority',$true)
    $flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
    $methods = @(Get-PspktTrustedControlAssemblyMethods `
        -Assembly $AuthorityAssembly `
        -MethodDefinitionCount $MethodDefinitionCount)
    if ($MethodDefinitionCount -ne 1 -or
        $methods.Count -ne 1 -or
        @($AuthorityAssembly.GetTypes()).Count -ne 1 -or
        -not $type.IsClass -or
        -not $type.IsPublic -or
        -not $type.IsAbstract -or
        -not $type.IsSealed -or
        $null -ne $type.DeclaringType -or
        $type.IsGenericType -or
        $type.BaseType -ne [object] -or
        $type.GetInterfaces().Count -ne 0 -or
        $type.GetFields($flags).Count -ne 0 -or
        $type.GetConstructors($flags).Count -ne 0 -or
        $null -ne $type.TypeInitializer -or
        $type.GetNestedTypes($flags).Count -ne 0 -or
        $type.GetProperties($flags).Count -ne 0 -or
        $type.GetEvents($flags).Count -ne 0) {
        throw 'Trusted-control authority wrapper shape differs.'
    }
    $method = $methods[0] -as [Reflection.MethodInfo]
    if ($null -eq $method -or
        $method.DeclaringType -ne $type -or
        $method.Name -cne 'Generate' -or
        -not $method.IsPublic -or
        -not $method.IsStatic -or
        $method.IsGenericMethod -or
        $method.ReturnType -ne [Collections.Generic.IDictionary[string,byte[]]] -or
        @($method.GetParameters()).Count -ne 3 -or
        @($method.GetParameters() | Where-Object ParameterType -NE ([byte[]])).Count -ne 0) {
        throw 'Trusted-control authority wrapper shape differs.'
    }
    $body = $method.GetMethodBody()
    if ($null -eq $body -or $body.ExceptionHandlingClauses.Count -ne 0) {
        throw 'Trusted-control authority wrapper IL differs.'
    }
    try {
        $instructions = @(Get-PspktTrustedControlCalledMethodReferences `
            -Method $method -IncludeInstructions)
    }
    catch {
        throw "Trusted-control authority wrapper IL differs: $($_.Exception.Message)"
    }
    $tokens = @($instructions | Where-Object { $null -ne $_.Token })
    if ($tokens.Count -ne 1 -or
        $tokens[0].Operation.Value -ne [Reflection.Emit.OpCodes]::Call.Value -or
        $null -eq $tokens[0].Method -or
        (Get-PspktTrustedControlMethodIdentity -Method $tokens[0].Method) -cne
            (Get-PspktTrustedControlMethodIdentity -Method $ProjectionGenerate)) {
        throw 'Trusted-control authority wrapper IL differs.'
    }
    $allowed = @('nop','ldarg.0','ldarg.1','ldarg.2','call',
        'stloc.0','stloc.1','stloc.2','stloc.3','stloc.s',
        'ldloc.0','ldloc.1','ldloc.2','ldloc.3','ldloc.s',
        'br','br.s','ret')
    foreach ($instruction in $instructions) {
        if ($allowed -cnotcontains $instruction.Operation.Name) {
            throw 'Trusted-control authority wrapper IL differs.'
        }
    }
}

function Register-PspktTrustedControlAuthorityTarget {
    param(
        [Collections.Generic.Dictionary[string,Collections.Generic.HashSet[string]]]$ByCaller,
        [Type]$Owner,
        [string]$Name,
        [Type]$ReturnType,
        [Type[]]$Parameters,
        [string]$Operation,
        [string[]]$Callers
    )

    $flags = [Reflection.BindingFlags]'Public,NonPublic,Static,Instance'
    $target = if ($Name -ceq '.ctor') {
        $Owner.GetConstructor($flags,$null,$Parameters,$null)
    } else {
        $Owner.GetMethod($Name,$flags,$null,$Parameters,$null)
    }
    if ($null -eq $target -or
        $target.DeclaringType -ne $Owner -or
        $target.IsGenericMethod -or
        ($Name -cne '.ctor' -and $target.ReturnType -ne $ReturnType)) {
        throw "Trusted-control authority projection A target shape differs: $($Owner.FullName).$Name"
    }
    $key = $Operation + '|' +
        (Get-PspktTrustedControlMethodIdentity -Method $target)
    foreach ($caller in $Callers) {
        [void]$ByCaller[$caller].Add($key)
    }
}

function Assert-PspktTrustedControlAuthorityCallTargets {
    param([Type]$ProjectionType)

    Assert-PspktTrustedControlAuthorityTokenSurface -ProjectionType $ProjectionType
    $assembly = $ProjectionType.Assembly
    $bootstrap = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap',$true)
    $objectType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonObject',$true)
    $arrayType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonArray',$true)
    $nodeType = $assembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonNode',$true)
    $objectDictionary = [Collections.Generic.Dictionary[string,object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@([string],$objectType))
    $byteDictionary = [Collections.Generic.Dictionary[string,byte[]]]
    $nodeList = [Collections.Generic.IList[object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@($nodeType))
    $nodeCollection = [Collections.Generic.ICollection[object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@($nodeType))
    $stringComparer = [Collections.Generic.IEqualityComparer[string]]
    $byCaller = [Collections.Generic.Dictionary[string,Collections.Generic.HashSet[string]]]::new(
        [StringComparer]::Ordinal)
    foreach ($method in $ProjectionType.GetMethods(
        [Reflection.BindingFlags]'Public,NonPublic,Static,DeclaredOnly')) {
        $byCaller.Add($method.Name,
            [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal))
    }
    $descriptors = @(
        @{ O=$bootstrap; N='ParseAndValidateMeta'; R=$objectType; P=@([byte[]]); C=@('Generate') },
        @{ O=$bootstrap; N='ParsePinnedInventory'; R=$objectType; P=@([byte[]]); C=@('Generate') },
        @{ O=$bootstrap; N='ParseCanonical'; R=$nodeType; P=@([byte[]]); C=@('Generate','GenerateCore') },
        @{ O=$bootstrap; N='ValidateAuthorityRaw'; R=[void]; P=@($objectType,$objectType,$objectType); C=@('Generate') },
        @{ O=$bootstrap; N='ValidateSchema'; R=[void]; P=@($objectType,$objectType); C=@('GenerateCore') },
        @{ O=$objectType; N='GetObject'; R=$objectType; P=@([string]); V=1; C=@('Generate','GenerateCore','Project','ValidateSizing') },
        @{ O=$objectType; N='GetArray'; R=$arrayType; P=@([string]); V=1; C=@('GenerateCore','Project','SizeType','CountReachableRecordOccurrences') },
        @{ O=$objectType; N='GetString'; R=[string]; P=@([string]); V=1; C=@('Generate','GenerateCore','Project','ValidateSizing','SizeType','CountReachableRecordOccurrences') },
        @{ O=$objectType; N='GetInteger'; R=[uint64]; P=@([string]); V=1; C=@('ValidateSizing','SizeType','CountReachableRecordOccurrences') },
        @{ O=$objectType; N='Contains'; R=[bool]; P=@([string]); V=1; C=@('SizeType','CountReachableRecordOccurrences') },
        @{ O=$arrayType; N='get_Items'; R=$nodeList; P=@(); V=1; C=@('GenerateCore','ValidateSizing','SizeType','CountReachableRecordOccurrences') },
        @{ O=$nodeType; N='ToCanonicalBytes'; R=[byte[]]; P=@(); V=1; C=@('GenerateCore','Project') },
        @{ O=[string]; N='Equals'; R=[bool]; P=@([string],[string],[StringComparison]); C=@('Generate','GenerateCore','Project','SizeType','CountReachableRecordOccurrences') },
        @{ O=[string]; N='StartsWith'; R=[bool]; P=@([string],[StringComparison]); V=1; C=@('Prefix') },
        @{ O=[string]; N='IndexOf'; R=[int]; P=@([string],[StringComparison]); V=1; C=@('ReplaceExactlyOnce') },
        @{ O=[string]; N='IndexOf'; R=[int]; P=@([string],[int],[StringComparison]); V=1; C=@('ReplaceExactlyOnce') },
        @{ O=[string]; N='Substring'; R=[string]; P=@([int]); V=1; C=@('ReplaceExactlyOnce') },
        @{ O=[string]; N='Substring'; R=[string]; P=@([int],[int]); V=1; C=@('ReplaceExactlyOnce') },
        @{ O=[string]; N='get_Length'; R=[int]; P=@(); V=1; C=@('ReplaceExactlyOnce') },
        @{ O=[string]; N='Concat'; R=[string]; P=@([string],[string]); C=@('Prefix','SizeType','CountReachableRecordOccurrences') },
        @{ O=[string]; N='Concat'; R=[string]; P=@([string],[string],[string]); C=@('ReplaceExactlyOnce') },
        @{ O=[string]; N='Concat'; R=[string]; P=@([string[]]); C=@('Project') },
        @{ O=[StringComparer]; N='get_Ordinal'; R=[StringComparer]; P=@(); C=@('GenerateCore','ValidateSizing') },
        @{ O=[Exception]; N='get_Message'; R=[string]; P=@(); V=1; C=@('Prefix') },
        @{ O=[InvalidOperationException]; N='.ctor'; P=@([string]); X=1; C=@('Generate','GenerateCore','ReplaceExactlyOnce','ValidateSizing','SizeType','CountReachableRecordOccurrences') },
        @{ O=[InvalidOperationException]; N='.ctor'; P=@([string],[Exception]); X=1; C=@('Generate','Validate','Prefix') },
        @{ O=[Text.Encoding]; N='get_UTF8'; R=[Text.Encoding]; P=@(); C=@('Project') },
        @{ O=[Text.Encoding]; N='GetString'; R=[string]; P=@([byte[]]); V=1; C=@('Project') },
        @{ O=[Text.Encoding]; N='GetBytes'; R=[byte[]]; P=@([string]); V=1; C=@('Project') },
        @{ O=[Text.UTF8Encoding]; N='.ctor'; P=@([bool],[bool]); X=1; C=@('Project') },
        @{ O=$objectDictionary; N='.ctor'; P=@($stringComparer); X=1; C=@('ValidateSizing') },
        @{ O=$objectDictionary; N='Add'; R=[void]; P=@([string],$objectType); V=1; C=@('ValidateSizing') },
        @{ O=$objectDictionary; N='ContainsKey'; R=[bool]; P=@([string]); V=1; C=@('ValidateSizing') },
        @{ O=$objectDictionary; N='TryGetValue'; R=[bool]; P=@([string],$objectType.MakeByRefType()); V=1; C=@('SizeType','CountReachableRecordOccurrences') },
        @{ O=$byteDictionary; N='.ctor'; P=@($stringComparer); X=1; C=@('GenerateCore') },
        @{ O=$byteDictionary; N='Add'; R=[void]; P=@([string],[byte[]]); V=1; C=@('GenerateCore') },
        @{ O=[Collections.Generic.HashSet[string]]; N='.ctor'; P=@($stringComparer); X=1; C=@('ValidateSizing') },
        @{ O=[Collections.Generic.HashSet[string]]; N='Add'; R=[bool]; P=@([string]); V=1; C=@('SizeType','CountReachableRecordOccurrences') },
        @{ O=[Collections.Generic.HashSet[string]]; N='Remove'; R=[bool]; P=@([string]); V=1; C=@('SizeType','CountReachableRecordOccurrences') },
        @{ O=$nodeCollection; N='get_Count'; R=[int]; P=@(); V=1; C=@('GenerateCore','ValidateSizing','SizeType','CountReachableRecordOccurrences') },
        @{ O=$nodeList; N='get_Item'; R=$nodeType; P=@([int]); V=1; C=@('GenerateCore','ValidateSizing','SizeType','CountReachableRecordOccurrences') }
    )
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $descriptors += @{
            O=[string]; N='Concat'; R=[string]; P=@([object[]]);
            C=@('ValidateSizing')
        }
        $descriptors += @{
            O=[string]; N='Concat'; R=[string]; P=@([object],[object]);
            C=@('SizeType','CountReachableRecordOccurrences')
        }
    } else {
        $descriptors += @{
            O=[string]; N='Concat'; R=[string]; P=@([string[]]); C=@('ValidateSizing')
        }
        $descriptors += @{
            O=[int]; N='ToString'; R=[string]; P=@();
            C=@('ValidateSizing','SizeType','CountReachableRecordOccurrences')
        }
        $descriptors += @{
            O=[uint64]; N='ToString'; R=[string]; P=@(); C=@('ValidateSizing')
        }
    }
    foreach ($descriptor in $descriptors) {
        $operation = if ($descriptor.ContainsKey('X')) { 'newobj' }
        elseif ($descriptor.ContainsKey('V')) { 'callvirt' }
        else { 'call' }
        Register-PspktTrustedControlAuthorityTarget `
            -ByCaller $byCaller `
            -Owner $descriptor.O `
            -Name $descriptor.N `
            -ReturnType $(if ($descriptor.ContainsKey('R')) {
                $descriptor.R
            } else { $null }) `
            -Parameters ([Type[]]$descriptor.P) `
            -Operation $operation `
            -Callers $descriptor.C
    }
    $internalEdges = @{
        Generate = @('GenerateCore','Prefix')
        Validate = @('GenerateCore','Prefix')
        GenerateCore = @('Project','BytesEqual','ValidateSizing')
        Project = @('ProjectEntrypointDeclaration')
        ProjectEntrypointDeclaration = @('ReplaceExactlyOnce')
        ValidateSizing = @('SizeType','CountReachableRecordOccurrences')
        SizeType = @('SizeType')
        CountReachableRecordOccurrences = @('CountReachableRecordOccurrences')
    }
    foreach ($caller in $internalEdges.Keys) {
        foreach ($name in $internalEdges[$caller]) {
            $callee = $ProjectionType.GetMethod($name,
                [Reflection.BindingFlags]'Public,NonPublic,Static,DeclaredOnly')
            [void]$byCaller[$caller].Add('call|' +
                (Get-PspktTrustedControlMethodIdentity -Method $callee))
        }
    }
    foreach ($method in $ProjectionType.GetMethods(
        [Reflection.BindingFlags]'Public,NonPublic,Static,DeclaredOnly')) {
        $actualTargets = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($reference in Get-PspktTrustedControlCalledMethodReferences -Method $method) {
            if ($reference.Operation.Name -cnotin @('call','callvirt','newobj') -or
                $null -eq $reference.Method) {
                throw "Trusted-control authority projection A call target differs: $($method.Name)"
            }
            $key = $reference.Operation.Name + '|' +
                (Get-PspktTrustedControlMethodIdentity -Method $reference.Method)
            if (-not $byCaller[$method.Name].Contains($key)) {
                throw "Trusted-control authority projection A call target differs: $($method.Name)"
            }
            [void]$actualTargets.Add($key)
        }
        if (-not $byCaller[$method.Name].SetEquals($actualTargets)) {
            throw "Trusted-control authority projection A call inventory differs: $($method.Name)"
        }
    }
}

function Get-PspktTrustedControlBootstrapAdmissions {
    param([Reflection.Assembly]$BootstrapAssembly)

    $bootstrapType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap',$true)
    $nodeType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonNode',$true)
    $objectType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonObject',$true)
    $arrayType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonArray',$true)
    $stringType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonString',$true)
    $integerType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonInteger',$true)
    $booleanType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedJsonBoolean',$true)
    $nodeList = [Collections.Generic.IList[object]].
        GetGenericTypeDefinition().MakeGenericType([Type[]]@($nodeType))
    $admissions = [Collections.Generic.Dictionary[string,Reflection.MethodInfo]]::new(
        [StringComparer]::Ordinal)
    $bootstrapMethods = [Collections.Generic.List[Reflection.MethodInfo]]::new()
    $descriptors = @(
        @{ O=$bootstrapType; N='ParseCanonical'; R=$nodeType; P=@([byte[]]); B=1 },
        @{ O=$bootstrapType; N='ParseAndValidateMeta'; R=$objectType; P=@([byte[]]); B=1 },
        @{ O=$bootstrapType; N='ParsePinnedInventory'; R=$objectType; P=@([byte[]]); B=1 },
        @{ O=$bootstrapType; N='ValidateAuthorityRaw'; R=[void]; P=@($objectType,$objectType,$objectType); B=1 },
        @{ O=$bootstrapType; N='ValidateSchema'; R=[void]; P=@($objectType,$objectType); B=1 },
        @{ O=$bootstrapType; N='ValidateVector'; R=[void]; P=@($objectType); B=1 },
        @{ O=$bootstrapType; N='ComputeSha256Hex'; R=[string]; P=@([byte[]]); B=1 },
        @{ O=$nodeType; N='get_Path'; R=[string]; P=@() },
        @{ O=$nodeType; N='ToCanonicalBytes'; R=[byte[]]; P=@() },
        @{ O=$objectType; N='get_Keys'; R=[Collections.Generic.IList[string]]; P=@() },
        @{ O=$objectType; N='get_Item'; R=$nodeType; P=@([string]) },
        @{ O=$objectType; N='Contains'; R=[bool]; P=@([string]) },
        @{ O=$objectType; N='GetArray'; R=$arrayType; P=@([string]) },
        @{ O=$objectType; N='GetBoolean'; R=[bool]; P=@([string]) },
        @{ O=$objectType; N='GetInteger'; R=[uint64]; P=@([string]) },
        @{ O=$objectType; N='GetObject'; R=$objectType; P=@([string]) },
        @{ O=$objectType; N='GetString'; R=[string]; P=@([string]) },
        @{ O=$arrayType; N='get_Items'; R=$nodeList; P=@() },
        @{ O=$stringType; N='get_Value'; R=[string]; P=@() },
        @{ O=$integerType; N='get_Value'; R=[uint64]; P=@() },
        @{ O=$booleanType; N='get_Value'; R=[bool]; P=@() }
    )
    foreach ($descriptor in $descriptors) {
        $parameters = [Type[]]$descriptor.P
        $flags = [Reflection.BindingFlags]'Public,DeclaredOnly'
        if ($descriptor.ContainsKey('B')) {
            $flags = $flags -bor [Reflection.BindingFlags]::Static
        } else {
            $flags = $flags -bor [Reflection.BindingFlags]::Instance
        }
        $candidates = @($descriptor.O.GetMethods($flags) | Where-Object {
                if ($_.Name -cne $descriptor.N -or $_.IsGenericMethod -or
                    $_.ReturnType -ne $descriptor.R) {
                    return $false
                }
                $actualParameters = @($_.GetParameters())
                if ($actualParameters.Count -ne $parameters.Count) { return $false }
                for ($index = 0; $index -lt $parameters.Count; $index++) {
                    if ($actualParameters[$index].ParameterType -ne $parameters[$index]) {
                        return $false
                    }
                }
                return $true
            })
        if ($candidates.Count -ne 1 -or
            $candidates[0].DeclaringType -ne $descriptor.O) {
            throw "Trusted-control Bootstrap admission shape differs: $($descriptor.O.FullName).$($descriptor.N)"
        }
        $method = $candidates[0]
        $admissions.Add(
            (Get-PspktTrustedControlMethodIdentity -Method $method),$method)
        if ($descriptor.ContainsKey('B')) { $bootstrapMethods.Add($method) }
    }
    return [pscustomobject]@{
        Members = $admissions
        Entrypoints = $bootstrapMethods.ToArray()
    }
}

function Assert-PspktTrustedControlVerifierCallGraph {
    param(
        [Reflection.Assembly]$VerifyAssembly,
        [Reflection.Assembly]$BootstrapAssembly,
        [int]$VerifyMethodDefinitionCount,
        [int]$BootstrapMethodDefinitionCount
    )

    Assert-PspktTrustedControlAssemblyWideAuthorityIsolation `
        -Assembly $VerifyAssembly `
        -Label 'Verify' `
        -MethodDefinitionCount $VerifyMethodDefinitionCount
    Assert-PspktTrustedControlAssemblyWideAuthorityIsolation `
        -Assembly $BootstrapAssembly `
        -Label 'Bootstrap' `
        -MethodDefinitionCount $BootstrapMethodDefinitionCount `
        -SkipAuthorityImplementation

    $admissions = Get-PspktTrustedControlBootstrapAdmissions `
        -BootstrapAssembly $BootstrapAssembly
    $dispatchAssemblies = @($VerifyAssembly,$BootstrapAssembly)
    $queue = [Collections.Generic.Queue[Reflection.MethodBase]]::new()
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $verifyType = $VerifyAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedControlVerify',
        $true)
    foreach ($name in @('Verify','VerifyVector')) {
        $queue.Enqueue($verifyType.GetMethod($name))
    }
    if ($null -ne $verifyType.TypeInitializer) {
        $queue.Enqueue($verifyType.TypeInitializer)
    }
    while ($queue.Count -ne 0) {
        $method = $queue.Dequeue()
        $key = Get-PspktTrustedControlMethodIdentity -Method $method
        if (-not $visited.Add($key)) { continue }
        if ($method.Module.Assembly -eq $VerifyAssembly -and
            $null -ne $method.DeclaringType -and
            $null -ne $method.DeclaringType.TypeInitializer -and
            $method.MetadataToken -ne $method.DeclaringType.TypeInitializer.MetadataToken) {
            $queue.Enqueue($method.DeclaringType.TypeInitializer)
        }
        foreach ($callReference in Get-PspktTrustedControlCalledMethodReferences -Method $method) {
            $called = $callReference.Method
            $declaringName = if ($called.DeclaringType) { $called.DeclaringType.FullName } else { '' }
            if ($called.Module.Assembly -eq $BootstrapAssembly) {
                if ($declaringName -ceq (
                        'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA')) {
                    throw 'Verifier call graph reaches authority projection A.'
                }
                if ($declaringName -ceq (
                        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap')) {
                    if (-not $admissions.Members.ContainsKey(
                        (Get-PspktTrustedControlMethodIdentity -Method $called))) {
                        throw "Verifier uses a forbidden Bootstrap member: $($called.Name)"
                    }
                } elseif ($declaringName -like 'Pspkt.Certification.TrustedControl.TrustedJson*') {
                    if (-not $admissions.Members.ContainsKey(
                        (Get-PspktTrustedControlMethodIdentity -Method $called))) {
                        throw "Verifier uses a forbidden TrustedJson member: $declaringName.$($called.Name)"
                    }
                } else {
                    throw "Verifier uses a forbidden Bootstrap type: $declaringName"
                }
            }
            if ($called.Module.Assembly -eq $VerifyAssembly) {
                $queue.Enqueue($called)
                if ($null -ne $called.DeclaringType -and
                    $null -ne $called.DeclaringType.TypeInitializer) {
                    $queue.Enqueue($called.DeclaringType.TypeInitializer)
                }
            }
            foreach ($dispatchTarget in Get-PspktTrustedControlDispatchTargets `
                -Method $called `
                -Assemblies $dispatchAssemblies) {
                $queue.Enqueue($dispatchTarget)
                if ($null -ne $dispatchTarget.DeclaringType -and
                    $null -ne $dispatchTarget.DeclaringType.TypeInitializer) {
                    $queue.Enqueue($dispatchTarget.DeclaringType.TypeInitializer)
                }
            }
        }
        foreach ($referencedType in Get-PspktTrustedControlReferencedTypes -Method $method) {
            if ($referencedType.Assembly -eq $BootstrapAssembly) {
                $referencedName = $referencedType.FullName
                if ($referencedName -ceq (
                        'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA')) {
                    throw 'Verifier type reference reaches authority projection A.'
                }
                if ($referencedName -cne (
                        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap') -and
                    $referencedName -notlike (
                        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap+*') -and
                    $referencedName -notlike 'Pspkt.Certification.TrustedControl.TrustedJson*') {
                    throw "Verifier uses a forbidden Bootstrap type reference: $referencedName"
                }
                if ($null -ne $referencedType.TypeInitializer) {
                    $queue.Enqueue($referencedType.TypeInitializer)
                }
            } elseif ($referencedType.Assembly -eq $VerifyAssembly -and
                $null -ne $referencedType.TypeInitializer) {
                $queue.Enqueue($referencedType.TypeInitializer)
            }
        }
    }

    $queue.Clear()
    $visited.Clear()
    $bootstrapType = $BootstrapAssembly.GetType(
        'Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap',
        $true)
    foreach ($method in $admissions.Entrypoints) {
        $queue.Enqueue($method)
    }
    if ($null -ne $bootstrapType.TypeInitializer) {
        $queue.Enqueue($bootstrapType.TypeInitializer)
    }
    foreach ($type in $BootstrapAssembly.GetTypes() | Where-Object {
            $_.FullName -like 'Pspkt.Certification.TrustedControl.TrustedJson*' }) {
        if ($null -ne $type.TypeInitializer) {
            $queue.Enqueue($type.TypeInitializer)
        }
        foreach ($method in $type.GetMethods(
                [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly')) {
            if ($admissions.Members.ContainsKey(
                (Get-PspktTrustedControlMethodIdentity -Method $method))) {
                $queue.Enqueue($method)
            }
        }
    }
    while ($queue.Count -ne 0) {
        $method = $queue.Dequeue()
        $key = Get-PspktTrustedControlMethodIdentity -Method $method
        if (-not $visited.Add($key)) { continue }
        if ($null -ne $method.DeclaringType.TypeInitializer -and
            $method.MetadataToken -ne $method.DeclaringType.TypeInitializer.MetadataToken) {
            $queue.Enqueue($method.DeclaringType.TypeInitializer)
        }
        if ($method.DeclaringType.FullName -ceq (
                'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA')) {
            throw "Allowed Bootstrap call graph reaches authority projection A: $($method.Name)"
        }
        foreach ($callReference in Get-PspktTrustedControlCalledMethodReferences -Method $method) {
            $called = $callReference.Method
            if ($called.Module.Assembly -eq $BootstrapAssembly) {
                $queue.Enqueue($called)
                if ($null -ne $called.DeclaringType.TypeInitializer) {
                    $queue.Enqueue($called.DeclaringType.TypeInitializer)
                }
            }
            foreach ($dispatchTarget in Get-PspktTrustedControlDispatchTargets `
                -Method $called `
                -Assemblies @($BootstrapAssembly)) {
                $queue.Enqueue($dispatchTarget)
                if ($null -ne $dispatchTarget.DeclaringType -and
                    $null -ne $dispatchTarget.DeclaringType.TypeInitializer) {
                    $queue.Enqueue($dispatchTarget.DeclaringType.TypeInitializer)
                }
            }
        }
        foreach ($referencedType in Get-PspktTrustedControlReferencedTypes -Method $method) {
            if ($referencedType.Assembly -eq $BootstrapAssembly) {
                if ($referencedType.FullName -ceq (
                        'Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA')) {
                    throw "Allowed Bootstrap type reference reaches authority projection A: $($method.Name)"
                }
                if ($null -ne $referencedType.TypeInitializer) {
                    $queue.Enqueue($referencedType.TypeInitializer)
                }
            }
        }
    }
}

function Get-PspktTrustedControlDispatchTargets {
    param(
        [Reflection.MethodBase]$Method,
        [Reflection.Assembly[]]$Assemblies
    )

    $methodInfo = $Method -as [Reflection.MethodInfo]
    Assert-PspktTrustedControlSupportedInterfaceMethod `
        -Method $Method -Label 'Trusted-control dispatch'
    if ($null -eq $methodInfo -or $methodInfo.IsStatic -or
        $null -eq $methodInfo.DeclaringType) {
        return @()
    }
    $targets = [Collections.Generic.List[Reflection.MethodInfo]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $states = 0
    foreach ($assembly in $Assemblies) {
        foreach ($type in $assembly.GetTypes()) {
            if (++$states -gt 16384) {
                throw 'Trusted-control dispatch exceeded its structural bound.'
            }
            if ($type.IsInterface) { continue }
            if ($methodInfo.DeclaringType.IsInterface) {
                foreach ($implementedInterface in $type.GetInterfaces()) {
                    if (++$states -gt 16384) {
                        throw 'Trusted-control dispatch exceeded its structural bound.'
                    }
                    $requested = $methodInfo.DeclaringType
                    $sameDefinition = $requested.IsGenericType -and
                        $implementedInterface.IsGenericType -and
                        $requested.GetGenericTypeDefinition() -eq
                            $implementedInterface.GetGenericTypeDefinition()
                    if ($requested -ne $implementedInterface -and -not $sameDefinition) {
                        continue
                    }
                    $closed = -not $requested.ContainsGenericParameters -and
                        -not $implementedInterface.ContainsGenericParameters
                    if ($closed -and
                        -not $requested.IsAssignableFrom($implementedInterface)) {
                        continue
                    }
                    try {
                        $interfaceMap = $type.GetInterfaceMap($implementedInterface)
                    }
                    catch {
                        throw "Trusted-control dispatch could not be resolved: $($requested.FullName).$($methodInfo.Name)"
                    }
                    Assert-PspktTrustedControlInterfaceMapTargets `
                        -InterfaceMap $interfaceMap -Implementer $type
                    for ($index = 0; $index -lt $interfaceMap.InterfaceMethods.Count; $index++) {
                        $target = $interfaceMap.TargetMethods[$index]
                        $interfaceMethod = $interfaceMap.InterfaceMethods[$index]
                        if ($interfaceMethod.Module.ModuleVersionId -eq
                                $methodInfo.Module.ModuleVersionId -and
                            $interfaceMethod.MetadataToken -eq $methodInfo.MetadataToken) {
                            $key = Get-PspktTrustedControlMethodIdentity -Method $target
                            if ($seen.Add($key)) { $targets.Add($target) }
                        }
                    }
                }
            } elseif ($methodInfo.IsVirtual) {
                $owner = $methodInfo.DeclaringType
                if (-not $owner.ContainsGenericParameters -and
                    -not $type.ContainsGenericParameters) {
                    if (-not $owner.IsAssignableFrom($type)) { continue }
                } else {
                    $baseType = $type
                    $sameDefinition = $false
                    while ($null -ne $baseType) {
                        if (++$states -gt 16384) {
                            throw 'Trusted-control dispatch exceeded its structural bound.'
                        }
                        if ($baseType -eq $owner -or
                            ($owner.IsGenericType -and $baseType.IsGenericType -and
                            $baseType.GetGenericTypeDefinition() -eq
                                $owner.GetGenericTypeDefinition())) {
                            $sameDefinition = $true
                            break
                        }
                        $baseType = $baseType.BaseType
                    }
                    if (-not $sameDefinition) { continue }
                }
                $baseDefinition = $methodInfo.GetBaseDefinition()
                foreach ($candidate in $type.GetMethods(
                        [Reflection.BindingFlags]'Public,NonPublic,Instance,DeclaredOnly')) {
                    if (-not $candidate.IsVirtual) { continue }
                    $candidateBase = $candidate.GetBaseDefinition()
                    if ($candidateBase.Module.ModuleVersionId -eq
                            $baseDefinition.Module.ModuleVersionId -and
                        $candidateBase.MetadataToken -eq $baseDefinition.MetadataToken) {
                        $key = Get-PspktTrustedControlMethodIdentity -Method $candidate
                        if ($seen.Add($key)) { $targets.Add($candidate) }
                    }
                }
            }
        }
    }
    return $targets.ToArray()
}

function ConvertTo-PspktTrustedControlProcessArgument {
    param([string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-PspktTrustedControlWorker {
    param(
        [string]$WorkerMode,
        [string]$ScratchRoot
    )

    $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') {
        'powershell.exe'
    } else {
        'pwsh.exe'
    }
    $childPath = [IO.Path]::GetFullPath((Join-Path $PSHOME $hostName))
    $childStream = [IO.FileStream]::new(
        $childPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $childIdentity = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
        $childStream.SafeFileHandle).ToString()
    $childHash = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::ComputeSha256(
        $childStream)
    $eventName = 'Local\PspktTrustedControlAdmission-' + [Guid]::NewGuid().ToString('N')
    $createdNew = $false
    $admissionEvent = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $eventName,
        [ref]$createdNew)
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $PSCommandPath,
        '-Worker',
        '-Mode',
        $WorkerMode,
        '-RepositoryRoot',
        $RepositoryRoot,
        '-AssemblyRoot',
        $ScratchRoot,
        '-AdmissionEventName',
        $eventName,
        '-ExpectedChildImageHash',
        $childHash,
        '-ExpectedChildImageIdentity',
        $childIdentity,
        '-ExpectedChildImageEvidenceFile',
        (Join-Path $ScratchRoot 'expected-child-image-evidence.txt'),
        '-ExpectedPinIdentityFile',
        (Join-Path $ScratchRoot 'expected-pin-identities.txt'))
    if ($OutputRoot) {
        $arguments += @('-OutputRoot',$OutputRoot)
    }
    if ($VectorPath) {
        $arguments += @('-VectorPath',$VectorPath)
    }
    if ($TimeoutProbePidFile) {
        $arguments += @('-TimeoutProbePidFile',$TimeoutProbePidFile)
    }
    $quotedArguments = @($arguments | ForEach-Object {
        ConvertTo-PspktTrustedControlProcessArgument -Value $_
    })
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Join-Path $PSHOME $hostName
    $startInfo.WorkingDirectory = $RepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Arguments = $quotedArguments -join ' '
    $savedEnvironment = [ordered]@{}
    foreach ($name in @(
        'SystemDrive','SystemRoot','WINDIR','ProgramData','LOCALAPPDATA','APPDATA',
        'TEMP','TMP')) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $startInfo.EnvironmentVariables.Clear()
    foreach ($name in $savedEnvironment.Keys) {
        if ($null -ne $savedEnvironment[$name]) {
            $startInfo.EnvironmentVariables[$name] = $savedEnvironment[$name]
        }
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $job = [Pspkt.Certification.TrustedControl.TrustedJob]::CreateKillOnClose()
    try {
        if (-not $process.Start()) {
            throw 'Trusted-control child process did not start.'
        }
        try {
            $job.AssignProcess($process.Handle)
        }
        catch {
            Stop-Process -Id $process.Id -Force
            [void]$process.WaitForExit(5000)
            throw
        }
        $actualImagePath = [IO.Path]::GetFullPath(
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetProcessImagePath(
                $process.Handle))
        if ($actualImagePath -cne $childPath) {
            throw "Trusted-control child image differs: expected=$childPath; actual=$actualImagePath"
        }
        $mappedImageHash =
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::ComputeMappedExecutableSha256(
                $process.Handle,
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetProcessImageBase(
                    $process.Handle))
        [IO.File]::WriteAllText(
            (Join-Path $ScratchRoot 'expected-child-image-evidence.txt'),
            "$mappedImageHash`n$childIdentity`n",
            [Text.UTF8Encoding]::new($false,$true))
        [void]$admissionEvent.Set()
        $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
        $standardErrorTask = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($ChildTimeoutMilliseconds)
        if ($timedOut) {
            $job.Dispose()
            [void]$process.WaitForExit(5000)
        }
        else {
            $job.Dispose()
        }
        $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
        $standardError = $standardErrorTask.GetAwaiter().GetResult()
        if ($timedOut) {
            throw "Trusted-control child exceeded the $ChildTimeoutMilliseconds-millisecond timeout."
        }
        if ($process.ExitCode -ne 0) {
            throw "Trusted-control child failed with exit code $($process.ExitCode)`: $standardError"
        }
        if ($standardOutput.Length -gt 0) {
            $standardOutput.TrimEnd([char[]]@("`r","`n"))
        }
    }
    finally {
        $job.Dispose()
        $admissionEvent.Dispose()
        $childStream.Dispose()
        $process.Dispose()
    }
}

if (-not $RepositoryRoot) {
    $RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
}
$RepositoryRoot = Resolve-PspktTrustedControlPath -Path $RepositoryRoot -ParameterName 'RepositoryRoot'
$OutputRoot = Resolve-PspktTrustedControlPath -Path $OutputRoot -ParameterName 'OutputRoot'
$VectorPath = Resolve-PspktTrustedControlPath -Path $VectorPath -ParameterName 'VectorPath'
$AssemblyRoot = Resolve-PspktTrustedControlPath -Path $AssemblyRoot -ParameterName 'AssemblyRoot'
$ExpectedPinIdentityFile = Resolve-PspktTrustedControlPath `
    -Path $ExpectedPinIdentityFile `
    -ParameterName 'ExpectedPinIdentityFile'
$ExpectedChildImageEvidenceFile = Resolve-PspktTrustedControlPath `
    -Path $ExpectedChildImageEvidenceFile `
    -ParameterName 'ExpectedChildImageEvidenceFile'
$TimeoutProbePidFile = Resolve-PspktTrustedControlPath `
    -Path $TimeoutProbePidFile `
    -ParameterName 'TimeoutProbePidFile'

$expectedValidatorPath = Join-Path $RepositoryRoot 'certification\trusted-control\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1'
if ([IO.Path]::GetFullPath($PSCommandPath) -cne [IO.Path]::GetFullPath($expectedValidatorPath)) {
    throw 'Running trusted-control validator path does not correspond to the repository source.'
}

$contractPath = Join-Path $RepositoryRoot (
    'certification\trusted-control\lib\Pspkt.Certification.TrustedControlContract.ps1')
$contractStream = [IO.FileStream]::new(
    $contractPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    $contractBytes = [byte[]]::new($contractStream.Length)
    $contractBytesRead = $contractStream.Read($contractBytes,0,$contractBytes.Length)
    if ($contractBytesRead -ne $contractBytes.Length) {
        throw 'Trusted-control contract root read was incomplete.'
    }
    $actualContractHash = Get-PspktTrustedControlByteHash -Bytes $contractBytes
    if ($actualContractHash -cne $script:ExpectedTrustedControlContractSha256) {
        throw "Trusted-control contract root hash differs: expected=$script:ExpectedTrustedControlContractSha256; actual=$actualContractHash"
    }
    $contractScript = [ScriptBlock]::Create(
        [Text.UTF8Encoding]::new($false,$true).GetString($contractBytes))
    . $contractScript
}
finally {
    $contractStream.Dispose()
}
$contract = Get-PspktTrustedControlContract
$nativeSecurityPath = Join-Path $RepositoryRoot (
    'certification\trusted-control\lib\Pspkt.Certification.TrustedControlNativeSecurity.cs')
$nativeSecurityStream = [IO.FileStream]::new(
    $nativeSecurityPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    $nativeIdentityBefore = $null
    if ($null -ne ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
        $nativeIdentityBefore = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
            $nativeSecurityStream.SafeFileHandle).ToString()
    }
    $nativeSecurityBytes = [byte[]]::new($nativeSecurityStream.Length)
    $nativeSecurityBytesRead = $nativeSecurityStream.Read(
        $nativeSecurityBytes,
        0,
        $nativeSecurityBytes.Length)
    if ($nativeSecurityBytesRead -ne $nativeSecurityBytes.Length) {
        throw 'Trusted-control native security source read was incomplete.'
    }
    $nativeSecurityHash = Get-PspktTrustedControlByteHash -Bytes $nativeSecurityBytes
    $nativeSecurityRelativePath =
        'certification/trusted-control/lib/Pspkt.Certification.TrustedControlNativeSecurity.cs'
    if ($contract.Sha256ByPath[$nativeSecurityRelativePath] -cne $nativeSecurityHash) {
        throw "Trusted-control native security source pin differs: expected=$($contract.Sha256ByPath[$nativeSecurityRelativePath]); actual=$nativeSecurityHash"
    }
    if ($null -eq ('Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity' -as [type])) {
        Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($nativeSecurityBytes))
        $nativeIdentityBefore = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
            $nativeSecurityStream.SafeFileHandle).ToString()
    }
    $nativeIdentityAfter = [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
        $nativeSecurityStream.SafeFileHandle).ToString()
    if ($nativeIdentityBefore -cne $nativeIdentityAfter) {
        throw 'Trusted-control native security source identity drifted.'
    }
}
finally {
    $nativeSecurityStream.Dispose()
}
if ($Worker) {
    $currentImagePath = [IO.Path]::GetFullPath(
        [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    $currentImageStream = [IO.FileStream]::new(
        $currentImagePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $currentImageIdentity =
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetIdentity(
                $currentImageStream.SafeFileHandle).ToString()
        $currentImageHash =
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::ComputeSha256(
                $currentImageStream)
        $currentMappedImageHash =
            [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::ComputeMappedExecutableSha256(
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetCurrentProcessHandle(),
                [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetProcessImageBase(
                    [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetCurrentProcessHandle()))
    }
    finally {
        $currentImageStream.Dispose()
    }
    if ($currentImageHash -cne $ExpectedChildImageHash -or
        $currentImageIdentity -cne $ExpectedChildImageIdentity) {
        throw "Trusted-control child image identity differs: expectedHash=$ExpectedChildImageHash; actualHash=$currentImageHash; expectedIdentity=$ExpectedChildImageIdentity; actualIdentity=$currentImageIdentity"
    }
    if (-not $ExpectedChildImageEvidenceFile -or
        -not [IO.File]::Exists($ExpectedChildImageEvidenceFile)) {
        throw 'Trusted-control child requires mapped image evidence.'
    }
    $expectedImageEvidence = [IO.File]::ReadAllLines($ExpectedChildImageEvidenceFile)
    if ($expectedImageEvidence.Count -ne 2 -or
        $expectedImageEvidence[0] -cne $currentMappedImageHash -or
        $expectedImageEvidence[1] -cne $currentImageIdentity) {
        throw 'Trusted-control child mapped image evidence differs.'
    }
}
$pinIdentities = $null
$pinBytes = $null
Assert-PspktTrustedControlPins `
    -Contract $contract `
    -IdentityByPath ([ref]$pinIdentities) `
    -BytesByPath ([ref]$pinBytes)
Assert-PspktTrustedControlClosedSet -Contract $contract

if ($Worker) {
    if (-not $ExpectedPinIdentityFile -or -not [IO.File]::Exists($ExpectedPinIdentityFile)) {
        throw 'Trusted-control worker requires expected pin identities.'
    }
    $expectedPinIdentities = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    foreach ($identityLine in Get-Content -LiteralPath $ExpectedPinIdentityFile) {
        $separator = $identityLine.IndexOf("`t",[StringComparison]::Ordinal)
        if ($separator -lt 1) { throw 'Trusted-control expected pin identity line is malformed.' }
        $expectedPinIdentities.Add(
            $identityLine.Substring(0,$separator),
            $identityLine.Substring($separator + 1))
    }
    foreach ($relativePath in $contract.Sha256ByPath.Keys) {
        $expectedIdentity = $null
        if (-not $expectedPinIdentities.TryGetValue($relativePath,[ref]$expectedIdentity)) {
            throw "Trusted-control expected pin identity is missing: $relativePath"
        }
        if ($pinIdentities[$relativePath] -cne $expectedIdentity) {
            throw "Trusted-control pinned identity differs before child use: $relativePath"
        }
    }
}

if ($Worker -and $Mode -eq 'TimeoutProbe') {
    $probeHost = Join-Path $PSHOME $(
        if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' })
    $probeStartInfo = [Diagnostics.ProcessStartInfo]::new()
    $probeStartInfo.FileName = $probeHost
    $probeStartInfo.UseShellExecute = $false
    $probeStartInfo.CreateNoWindow = $true
    $probeStartInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 60"'
    $descendant = [Diagnostics.Process]::Start($probeStartInfo)
    if ($TimeoutProbePidFile) {
        [IO.File]::WriteAllText(
            $TimeoutProbePidFile,
            "$PID`n$($descendant.Id)`n",
            [Text.UTF8Encoding]::new($false,$true))
    }
    Start-Sleep -Seconds 60
    return
}

if (-not $Worker) {
    if ($AssemblyRoot) {
        throw 'AssemblyRoot is valid only in worker mode.'
    }
    $scratchRoot = Join-Path ([IO.Path]::GetTempPath()) ('pspkt-tc-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($scratchRoot)
    try {
        [IO.File]::WriteAllText(
            (Join-Path $scratchRoot 'expected-pin-identities.txt'),
            (($contract.Sha256ByPath.Keys | ForEach-Object {
                $_ + "`t" + [string]$pinIdentities[$_]
            }) -join "`n") + "`n",
            [Text.UTF8Encoding]::new($false,$true))
        Invoke-PspktTrustedControlWorker -WorkerMode $Mode -ScratchRoot $scratchRoot
    }
    finally {
        if ([IO.Directory]::Exists($scratchRoot)) {
            [IO.Directory]::Delete($scratchRoot,$true)
        }
    }
    return
}

if (-not $AssemblyRoot -or -not [IO.Directory]::Exists($AssemblyRoot)) {
    throw 'A fresh trusted-control assembly directory is required.'
}
$env:TEMP = $AssemblyRoot
$env:TMP = $AssemblyRoot

$libraryRoot = Join-Path $RepositoryRoot 'certification\trusted-control\lib'
$bootstrapAssemblyPath = Join-Path $AssemblyRoot 'TrustedControlJsonBootstrap.dll'
$authorityAssemblyPath = Join-Path $AssemblyRoot 'TrustedControlAuthority.dll'
$verifyAssemblyPath = Join-Path $AssemblyRoot 'TrustedControlVerify.dll'
$frozenBootstrapAssemblyPath = Join-Path $AssemblyRoot 'SchemaBootstrap.dll'
foreach ($assemblyPath in @(
    $bootstrapAssemblyPath,
    $authorityAssemblyPath,
    $verifyAssemblyPath,
    $frozenBootstrapAssemblyPath)) {
    if ([IO.File]::Exists($assemblyPath)) {
        throw "Trusted-control assembly path is not fresh: $assemblyPath"
    }
}

$frameworkReferences = Get-PspktTrustedControlFrameworkReferences
Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($pinBytes[
        'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs'])) `
    -OutputAssembly $bootstrapAssemblyPath `
    -ReferencedAssemblies $frameworkReferences
$bootstrapMethodDefinitionCount =
    [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetMethodDefinitionCount(
    [IO.File]::ReadAllBytes($bootstrapAssemblyPath),
    'Bootstrap')
Add-Type -LiteralPath $bootstrapAssemblyPath
$authorityMethodDefinitionCount = 0
if ($Mode -eq 'Generate' -or $Mode -eq 'Compile') {
    Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($pinBytes[
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlAuthority.cs'])) `
        -OutputAssembly $authorityAssemblyPath `
        -ReferencedAssemblies @($frameworkReferences + $bootstrapAssemblyPath)
    $authorityMethodDefinitionCount =
        [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetMethodDefinitionCount(
        [IO.File]::ReadAllBytes($authorityAssemblyPath),
        'Authority')
}
$verifyMethodDefinitionCount = 0
if ($Mode -eq 'Validate' -or $Mode -eq 'VerifyVector' -or $Mode -eq 'Compile') {
    Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($pinBytes[
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs'])) `
        -OutputAssembly $verifyAssemblyPath `
        -ReferencedAssemblies @($frameworkReferences + $bootstrapAssemblyPath)
    $verifyMethodDefinitionCount =
        [Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::GetMethodDefinitionCount(
        [IO.File]::ReadAllBytes($verifyAssemblyPath),
        'Verify')
    Assert-PspktTrustedControlVerifyBinaryIsolation -Path $verifyAssemblyPath
}
Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($pinBytes[
        'certification/lib/Pspkt.Certification.SchemaBootstrap.cs'])) `
    -OutputAssembly $frozenBootstrapAssemblyPath `
    -ReferencedAssemblies $frameworkReferences
[Pspkt.Certification.TrustedControl.TrustedControlNativeSecurity]::AssertNoModuleMethodDefinitions(
    [IO.File]::ReadAllBytes($frozenBootstrapAssemblyPath),
    'Frozen Bootstrap')
if ([IO.File]::Exists($authorityAssemblyPath)) { Add-Type -LiteralPath $authorityAssemblyPath }
if ([IO.File]::Exists($verifyAssemblyPath)) { Add-Type -LiteralPath $verifyAssemblyPath }
$frozenBootstrapAssembly = [Reflection.Assembly]::LoadFrom($frozenBootstrapAssemblyPath)
$frozenBootstrapType = $frozenBootstrapAssembly.GetType('Pspkt.Certification.SchemaBootstrap',$true)
$publicApiShapes = @(
    @{ Type = [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]; Name = 'Evaluate'; Types = @([string],[byte[]],[byte[]],[byte[]]) },
    @{ Type = [Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA]; Name = 'Generate'; Types = @([byte[]],[byte[]],[byte[]]) },
    @{ Type = if ([IO.File]::Exists($authorityAssemblyPath)) {
            [Pspkt.Certification.TrustedControl.TrustedControlAuthority]
        } else { $null }; Name = 'Generate'; Types = @([byte[]],[byte[]],[byte[]]) },
    @{ Type = if ([IO.File]::Exists($verifyAssemblyPath)) {
            [Pspkt.Certification.TrustedControl.TrustedControlVerify]
        } else { $null }; Name = 'Verify'; Types = @(
            [byte[]],[byte[]],[byte[]],
            [Collections.Generic.IDictionary[string,byte[]]]) },
    @{ Type = if ([IO.File]::Exists($verifyAssemblyPath)) {
            [Pspkt.Certification.TrustedControl.TrustedControlVerify]
        } else { $null }; Name = 'VerifyVector'; Types = @([byte[]],[byte[]],[byte[]],[byte[]]) }
)
foreach ($shape in $publicApiShapes) {
    if ($null -eq $shape.Type) { continue }
    $methods = @($shape.Type.GetMethods(
            [Reflection.BindingFlags]'Public,Static') | Where-Object Name -CEQ $shape.Name)
    if ($methods.Count -ne 1 -or
        $methods[0].GetParameters().Count -ne $shape.Types.Count) {
        throw "Trusted-control public API shape differs: $($shape.Type.FullName).$($shape.Name)"
    }
    $parameters = $methods[0].GetParameters()
    for ($index = 0; $index -lt $parameters.Count; $index++) {
        if ($parameters[$index].ParameterType -ne $shape.Types[$index]) {
            throw "Trusted-control public API parameter differs: $($shape.Type.FullName).$($shape.Name)[$index]"
        }
    }
}
$projectionType =
    [Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA]
$bootstrapAssembly =
    [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap].Assembly
Assert-PspktTrustedControlMethodImplRows `
    -Assembly $bootstrapAssembly `
    -AssemblyBytes ([IO.File]::ReadAllBytes($bootstrapAssemblyPath)) `
    -Label 'Bootstrap'
Assert-PspktTrustedControlAssemblyWideAuthorityIsolation `
    -Assembly $bootstrapAssembly `
    -Label 'Bootstrap' `
    -MethodDefinitionCount $bootstrapMethodDefinitionCount `
    -SkipAuthorityImplementation
if ($projectionType.GetNestedTypes(
        [Reflection.BindingFlags]'Public,NonPublic').Count -ne 0) {
    throw 'Trusted-control authority projection A exposes nested types.'
}
$projectionGenerate = $projectionType.GetMethod(
    'Generate',
    [Reflection.BindingFlags]'Public,Static')
foreach ($parameter in $projectionGenerate.GetParameters()) {
    if ($parameter.ParameterType -ne [byte[]]) {
        throw 'Trusted-control public authority projection accepts parsed objects.'
    }
}
$publicProjectionValidate = @($projectionType.GetMethods(
        [Reflection.BindingFlags]'Public,Static') | Where-Object Name -CEQ 'Validate')
if ($publicProjectionValidate.Count -ne 0) {
    throw 'Trusted-control parsed authority validation is public.'
}
Assert-PspktTrustedControlAuthorityProjectionShape `
    -ProjectionType $projectionType `
    -BootstrapMethodDefinitionCount $bootstrapMethodDefinitionCount
Assert-PspktTrustedControlAuthorityCallTargets -ProjectionType $projectionType
if ([IO.File]::Exists($authorityAssemblyPath)) {
    $authorityAssembly =
        [Pspkt.Certification.TrustedControl.TrustedControlAuthority].Assembly
    Assert-PspktTrustedControlCheckedAssemblyShape `
        -Assembly $authorityAssembly -Label 'Authority'
    Assert-PspktTrustedControlMethodImplRows `
        -Assembly $authorityAssembly `
        -AssemblyBytes ([IO.File]::ReadAllBytes($authorityAssemblyPath)) `
        -Label 'Authority'
    Assert-PspktTrustedControlAuthorityWrapper `
        -AuthorityAssembly $authorityAssembly `
        -MethodDefinitionCount $authorityMethodDefinitionCount `
        -ProjectionGenerate $projectionGenerate
}

$authorityReferences = @()
if ([IO.File]::Exists($verifyAssemblyPath)) {
    $verifyAssembly = [Pspkt.Certification.TrustedControl.TrustedControlVerify].Assembly
    Assert-PspktTrustedControlMethodImplRows `
        -Assembly $verifyAssembly `
        -AssemblyBytes ([IO.File]::ReadAllBytes($verifyAssemblyPath)) `
        -Label 'Verify'
    Assert-PspktTrustedControlVerifierCallGraph `
        -VerifyAssembly $verifyAssembly `
        -BootstrapAssembly $bootstrapAssembly `
        -VerifyMethodDefinitionCount $verifyMethodDefinitionCount `
        -BootstrapMethodDefinitionCount $bootstrapMethodDefinitionCount
    $authorityReferences = @(
        $verifyAssembly.GetReferencedAssemblies() |
            Where-Object { $_.Name -ceq 'TrustedControlAuthority' })
    if ($authorityReferences.Count -ne 0) {
        throw 'Trusted-control verifier references Authority.'
    }
}

$authorityPath = Join-Path $RepositoryRoot 'certification\trusted-control\schema\trusted-control-authority.v1.json'
$jsonMetaPath = Join-Path $RepositoryRoot 'certification\trusted-control\schema\trusted-control-json-schema-meta.v1.json'
$protocolMetaPath = Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json'
$mandatoryTailSchedulePath = Join-Path $RepositoryRoot 'certification\schema\mandatory-tail-schedule.v1.json'
$authorityBytes = [IO.File]::ReadAllBytes($authorityPath)
$jsonMetaBytes = [IO.File]::ReadAllBytes($jsonMetaPath)
$protocolMetaBytes = [IO.File]::ReadAllBytes($protocolMetaPath)
$mandatoryTailScheduleBytes = [IO.File]::ReadAllBytes($mandatoryTailSchedulePath)
$protocolInventoryBytes =
    $pinBytes['certification/schema/protocol-inventory.v1.json']

function Assert-PspktFrozenJson {
    param(
        [byte[]]$Bytes,
        [string]$Label
    )

    $arguments = [object[]]::new(3)
    $arguments[0] = 'json'
    $arguments[1] = $Bytes
    $arguments[2] = $null
    $result = $frozenBootstrapType.GetMethod('Evaluate').Invoke($null,$arguments)
    if (-not $result.Accepted) {
        throw "Trusted-control JSON failed frozen bootstrap: $Label ($($result.Reason))"
    }
}

Assert-PspktFrozenJson -Bytes $authorityBytes -Label 'trusted-control-authority.v1.json'
Assert-PspktFrozenJson -Bytes $jsonMetaBytes -Label 'trusted-control-json-schema-meta.v1.json'
Assert-PspktFrozenJson -Bytes $protocolMetaBytes -Label 'protocol-schema-meta.v1.json'
Assert-PspktFrozenJson -Bytes $mandatoryTailScheduleBytes -Label 'mandatory-tail-schedule.v1.json'
Assert-PspktFrozenJson -Bytes $protocolInventoryBytes -Label 'protocol-inventory.v1.json'
$authorityObject = [Text.Encoding]::UTF8.GetString($authorityBytes) | ConvertFrom-Json
$scheduleObject = [Text.Encoding]::UTF8.GetString($mandatoryTailScheduleBytes) | ConvertFrom-Json
$derivedLifecycleKeys = [Collections.Generic.List[string]]::new()
$seenLifecycleKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($row in $scheduleObject.rows) {
    $key = [string]$row.lifecycleVariant + '|' + [string]$row.state
    if ($seenLifecycleKeys.Add($key)) {
        $derivedLifecycleKeys.Add($key)
    }
}
$declaredLifecycle = @($authorityObject.encodingTables.lifecycleSchedule.keys)
if ($declaredLifecycle.Count -ne $derivedLifecycleKeys.Count) {
    throw 'Trusted-control lifecycle schedule key count differs.'
}
for ($index = 0; $index -lt $declaredLifecycle.Count; $index++) {
    if ($declaredLifecycle[$index] -cne $derivedLifecycleKeys[$index]) {
        throw "Trusted-control lifecycle schedule key differs at index $index."
    }
}
$scheduleHash = Get-PspktTrustedControlHash -Path $mandatoryTailSchedulePath
if ($authorityObject.encodingTables.lifecycleSchedule.sha256 -cne $scheduleHash) {
    throw 'Trusted-control lifecycle schedule digest differs.'
}
$jsonEvaluation = [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
    'json',
    $authorityBytes,
    $null,
    $protocolInventoryBytes)
if (-not $jsonEvaluation.Accepted) {
    throw "Trusted-control authority failed JSON bootstrap: $($jsonEvaluation.Reason)"
}
if ($Mode -eq 'Compile') {
    $directProjection =
        [Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA]::Generate(
            $authorityBytes,
            $jsonMetaBytes,
            $protocolInventoryBytes)
    if ($directProjection.Count -ne @($authorityObject.outputSchemas).Count) {
        throw 'Trusted-control direct authority projection cardinality differs.'
    }
}
if ($Mode -eq 'Generate' -or $Mode -eq 'Compile') {
    $authorityEvaluation = [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'authority',
        $authorityBytes,
        $jsonMetaBytes,
        $protocolInventoryBytes)
    if (-not $authorityEvaluation.Accepted) {
        throw "Trusted-control authority failed maintained meta: $($authorityEvaluation.Reason)"
    }
}
if ($Mode -eq 'Compile') {
    $nullInventoryCalls = @(
        {
            [void][Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
                'json',$authorityBytes,$null,$null)
        },
        {
            [void][Pspkt.Certification.TrustedControl.TrustedControlAuthority]::Generate(
                $authorityBytes,$jsonMetaBytes,$null)
        },
        {
            [void][Pspkt.Certification.TrustedControl.TrustedControlAuthorityProjectionA]::Generate(
                $authorityBytes,$jsonMetaBytes,$null)
        },
        {
            $empty = [Collections.Generic.Dictionary[string,byte[]]]::new(
                [StringComparer]::Ordinal)
            [Pspkt.Certification.TrustedControl.TrustedControlVerify]::Verify(
                $authorityBytes,$jsonMetaBytes,$null,$empty)
        },
        {
            $baselineBytes = $pinBytes[
                'certification/trusted-control/vectors/synthetic/accept-baseline.json']
            [void][Pspkt.Certification.TrustedControl.TrustedControlVerify]::VerifyVector(
                $baselineBytes,$authorityBytes,$jsonMetaBytes,$null)
        }
    )
    foreach ($call in $nullInventoryCalls) {
        $rejected = $false
        try { & $call }
        catch {
            $rejected = $_.Exception.ToString().Contains('inventoryBytes')
        }
        if (-not $rejected) {
            throw 'Trusted-control public API accepted a null inventory.'
        }
    }
}
$generated = $null
if ($Mode -eq 'Generate' -or $Mode -eq 'Compile') {
    $generated = [Pspkt.Certification.TrustedControl.TrustedControlAuthority]::Generate(
        $authorityBytes,
        $jsonMetaBytes,
        $protocolInventoryBytes)
}
$tlvCount = @($authorityObject.outputSchemas | Where-Object format -CEQ 'ProtocolTlv').Count
$jsonCount = @($authorityObject.outputSchemas | Where-Object format -CEQ 'JsonRegistry').Count
if ($null -ne $generated) {
foreach ($relativePath in $generated.Keys) {
    $bytes = $generated[$relativePath]
    Assert-PspktFrozenJson -Bytes $bytes -Label $relativePath
    $jsonResult = [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
        'json',
        $bytes,
        $null,
        $protocolInventoryBytes)
    if (-not $jsonResult.Accepted) {
        throw "Trusted-control generated JSON failed bootstrap: $relativePath ($($jsonResult.Reason))"
    }
    $fileName = [IO.Path]::GetFileName($relativePath)
    if ($contract.TlvSchemaNameSet -ccontains $fileName) {
        $arguments = [object[]]::new(3)
        $arguments[0] = 'schema-against-meta'
        $arguments[1] = [byte[]]$bytes
        $arguments[2] = [byte[]]$protocolMetaBytes
        $result = $frozenBootstrapType.GetMethod('Evaluate').Invoke($null,$arguments)
        if (-not $result.Accepted) {
            throw "Trusted-control TLV schema failed frozen meta: $fileName ($($result.Reason))"
        }
    } else {
        $result = [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
            'schema',
            $bytes,
            $jsonMetaBytes,
            $protocolInventoryBytes)
        if (-not $result.Accepted) {
            throw "Trusted-control registry schema failed maintained meta: $fileName ($($result.Reason))"
        }
    }
}
}

if ($Mode -eq 'Compile') {
    "TRUSTED_CONTROL_COMPILE_OK|outputs=$($generated.Count)|tlv=$tlvCount|json=$jsonCount|verifyAuthorityReferences=$($authorityReferences.Count)"
    return
}

if ($Mode -eq 'VerifyVector') {
    if (-not $VectorPath -or -not [IO.File]::Exists($VectorPath)) {
        throw 'VerifyVector requires an existing VectorPath.'
    }
    $vectorBytes = [IO.File]::ReadAllBytes($VectorPath)
    Assert-PspktFrozenJson -Bytes $vectorBytes -Label $VectorPath
    if ([IO.Path]::GetFileName($VectorPath) -ceq 'manifest.v1.json') {
        $manifest = [Text.Encoding]::UTF8.GetString($vectorBytes) | ConvertFrom-Json
        if ($manifest.schemaId -cne 'PspktTrustedControlVectorManifestV1' -or
            $manifest.schemaVersion -ne 1 -or
            -not $manifest.syntheticOnly -or
            @($manifest.cases).Count -eq 0) {
            throw '$:manifest-shape'
        }
        $vectorDirectory = [IO.Path]::GetDirectoryName($VectorPath)
        $trustedManifestPath = Join-Path $RepositoryRoot (
            'certification\trusted-control\vectors\synthetic\manifest.v1.json')
        $isTrustedManifest =
            [IO.Path]::GetFullPath($VectorPath) -ceq [IO.Path]::GetFullPath($trustedManifestPath)
        if ($isTrustedManifest) {
            [string[]]$declaredNames = @($manifest.cases | ForEach-Object { [string]$_.path })
            [string[]]$committedNames = @(
                Get-ChildItem -LiteralPath $vectorDirectory -Filter '*.json' -File -Force |
                    Where-Object Name -cne 'manifest.v1.json' |
                    Select-Object -ExpandProperty Name)
            [Array]::Sort($declaredNames,[StringComparer]::Ordinal)
            [Array]::Sort($committedNames,[StringComparer]::Ordinal)
            if ($declaredNames.Count -ne $committedNames.Count) {
                throw '$.cases:trusted-corpus-count'
            }
            for ($index = 0; $index -lt $declaredNames.Count; $index++) {
                if ($declaredNames[$index] -cne $committedNames[$index]) {
                    throw "$.cases[$index]:trusted-corpus-path"
                }
            }
        }
        foreach ($case in @($manifest.cases)) {
            if ([IO.Path]::GetFileName([string]$case.path) -cne [string]$case.path) {
                throw '$.cases.path:manifest-path'
            }
            $casePath = Join-Path $vectorDirectory ([string]$case.path)
            $caseBytes = [IO.File]::ReadAllBytes($casePath)
            if ($caseBytes.LongLength -ne [long]$case.byteLength) {
                throw "$.cases.$($case.path):length"
            }
            $caseHash = Get-PspktTrustedControlHash -Path $casePath
            if ($caseHash -cne [string]$case.sha256) {
                throw "$.cases.$($case.path):sha256"
            }
            Assert-PspktFrozenJson -Bytes $caseBytes -Label $casePath
            [void][Pspkt.Certification.TrustedControl.TrustedControlVerify]::VerifyVector(
                $caseBytes,
                $authorityBytes,
                $jsonMetaBytes,
                $protocolInventoryBytes)
        }
        if ($isTrustedManifest) {
            "TRUSTED_CONTROL_MANIFEST_OK|cases=$(@($manifest.cases).Count)"
        }
        else {
            "TRUSTED_CONTROL_CUSTOM_MANIFEST_OK|cases=$(@($manifest.cases).Count)"
        }
        return
    }
    $reason = [Pspkt.Certification.TrustedControl.TrustedControlVerify]::VerifyVector(
        $vectorBytes,
        $authorityBytes,
        $jsonMetaBytes,
        $protocolInventoryBytes)
    "TRUSTED_CONTROL_VECTOR_OK|reason=$reason"
    return
}

if (-not $OutputRoot) {
    if ($Mode -eq 'Generate') {
        throw 'Generation requires an explicit OutputRoot.'
    }
    $OutputRoot = $RepositoryRoot
}

if ($Mode -eq 'Generate') {
    foreach ($relativePath in $generated.Keys) {
        Write-PspktTrustedControlFileAtomically `
            -Path (Join-Path $OutputRoot $relativePath.Replace('/','\')) `
            -Bytes $generated[$relativePath]
    }
    "TRUSTED_CONTROL_GENERATE_OK|outputs=$($generated.Count)"
    return
}

$actual = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
$schemaRoot = Join-Path $OutputRoot 'certification\trusted-control\schema'
$actualTreePaths = @(
    Get-ChildItem -LiteralPath $schemaRoot -File -Recurse -Force |
        ForEach-Object { $_.FullName.Substring($OutputRoot.Length + 1).Replace('\','/') })
$missingPaths = @($contract.OutputPathSet | Where-Object { $actualTreePaths -cnotcontains $_ })
$allowedTreePaths = @(
    $contract.OutputPathSet +
    $contract.MaintainedInputPathSet +
    @('certification/trusted-control/schema/.gitattributes'))
$extraPaths = @($actualTreePaths | Where-Object { $allowedTreePaths -cnotcontains $_ })
if ($missingPaths.Count -ne 0 -or $extraPaths.Count -ne 0) {
    throw "Trusted-control output tree differs: missing=[$($missingPaths -join ',')]; extra=[$($extraPaths -join ',')]"
}
foreach ($relativePath in $contract.OutputPathSet) {
    $fullPath = Join-Path $OutputRoot $relativePath.Replace('/','\')
    if (-not [IO.File]::Exists($fullPath)) {
        throw "Trusted-control output is missing: $relativePath"
    }
    $actualBytes = [IO.File]::ReadAllBytes($fullPath)
    Assert-PspktFrozenJson -Bytes $actualBytes -Label $relativePath
    $actualFileName = [IO.Path]::GetFileName($relativePath)
    if ($contract.TlvSchemaNameSet -ccontains $actualFileName) {
        $arguments = [object[]]::new(3)
        $arguments[0] = 'schema-against-meta'
        $arguments[1] = [byte[]]$actualBytes
        $arguments[2] = [byte[]]$protocolMetaBytes
        $actualResult = $frozenBootstrapType.GetMethod('Evaluate').Invoke($null,$arguments)
        if (-not $actualResult.Accepted) {
            throw "Trusted-control TLV schema failed frozen meta: $actualFileName ($($actualResult.Reason))"
        }
    } else {
        $actualResult = [Pspkt.Certification.TrustedControl.TrustedControlJsonSchemaBootstrap]::Evaluate(
            'schema',
            $actualBytes,
            $jsonMetaBytes,
            $protocolInventoryBytes)
        if (-not $actualResult.Accepted) {
            throw "Trusted-control registry schema failed maintained meta: $actualFileName ($($actualResult.Reason))"
        }
    }
    $actual.Add($relativePath,$actualBytes)
}
[Pspkt.Certification.TrustedControl.TrustedControlVerify]::Verify(
    $authorityBytes,
    $jsonMetaBytes,
    $protocolInventoryBytes,
    $actual)

"TRUSTED_CONTROL_VALIDATE_OK|outputs=$($actual.Count)|tlv=$tlvCount|json=$jsonCount"
