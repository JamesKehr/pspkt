[CmdletBinding(DefaultParameterSetName = 'Slice')]
param(
    [Parameter(ParameterSetName = 'Release', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedBaselineCommit,

    [Parameter(ParameterSetName = 'Release', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$RequireExclusiveSlice,

    [Parameter(ParameterSetName = 'Worker', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$Worker,

    [Parameter(ParameterSetName = 'Worker', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkerScenario,

    [Parameter(ParameterSetName = 'Worker', Mandatory = $false)]
    [string]$WorkerMutation,

    [Parameter(ParameterSetName = 'GeneratorBootstrap', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$GeneratorBootstrap,

    [Parameter(ParameterSetName = 'GeneratorBootstrap', Mandatory = $true)]
    [ValidateSet('Normal', 'GateWithheld')]
    [string]$GeneratorScenario,

    [Parameter(ParameterSetName = 'GeneratorBootstrap', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GeneratorScriptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ParameterSetName -ceq 'GeneratorBootstrap') {
    $bootstrapExpectedEnvironmentNames = [string[]]@(
        'PSPKT_PHASE4_SUPERVISOR_GATE_EVENT',
        'PSPKT_PHASE4_SNAPSHOT_ROOT',
        'PSPKT_PHASE4_REPOSITORY_ROOT',
        'PSPKT_PHASE4_GENERATOR_RESULT_PATH',
        'PSPKT_PHASE4_GENERATOR_NONCE',
        'PSPKT_PHASE4_GENERATOR_SOURCE_SHA256',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_ROOT',
        'PSPKT_PHASE4_GENERATOR_TARGET_ROOT',
        'PSPKT_PHASE4_GENERATOR_GATE_PREPARED',
        'PSPKT_PHASE4_GENERATOR_GATE_AUTHORIZE',
        'PSPKT_PHASE4_GENERATOR_GATE_WAIT_ARMED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_PRE_RESULT'
    )
    $bootstrapExpectedEnvironmentSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($bootstrapExpectedEnvironmentName in $bootstrapExpectedEnvironmentNames) {
        if (-not $bootstrapExpectedEnvironmentSet.Add($bootstrapExpectedEnvironmentName)) { exit 21 }
    }

    $bootstrapEnvironment = [Environment]::GetEnvironmentVariables()
    $bootstrapActualEnvironmentSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($bootstrapEnvironmentKey in $bootstrapEnvironment.Keys) {
        $bootstrapEnvironmentName = [string]$bootstrapEnvironmentKey
        if ($bootstrapEnvironmentName.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase)) {
            if (-not $bootstrapActualEnvironmentSet.Add($bootstrapEnvironmentName)) { exit 21 }
        }
    }
    if ($bootstrapActualEnvironmentSet.Count -ne $bootstrapExpectedEnvironmentSet.Count) { exit 21 }
    foreach ($bootstrapExpectedEnvironmentName in $bootstrapExpectedEnvironmentNames) {
        if (-not $bootstrapActualEnvironmentSet.Contains($bootstrapExpectedEnvironmentName)) { exit 21 }
        $bootstrapEnvironmentValue = [Environment]::GetEnvironmentVariable($bootstrapExpectedEnvironmentName)
        if ([string]::IsNullOrEmpty($bootstrapEnvironmentValue)) { exit 21 }
    }

    $bootstrapSourceDigest = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GENERATOR_SOURCE_SHA256')
    $bootstrapGeneratorNonce = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GENERATOR_NONCE')
    if (-not [regex]::IsMatch($bootstrapSourceDigest, '^[0-9a-f]{64}$') -or
        -not [regex]::IsMatch($bootstrapGeneratorNonce, '^[0-9a-f]{32}$')) {
        exit 21
    }

    try {
        if (-not [System.IO.Path]::IsPathRooted($GeneratorScriptPath)) { exit 21 }
        $bootstrapCanonicalGeneratorPath = [System.IO.Path]::GetFullPath($GeneratorScriptPath)
    }
    catch [System.ArgumentException] { exit 21 }
    catch [System.NotSupportedException] { exit 21 }
    catch [System.IO.PathTooLongException] { exit 21 }
    if ($bootstrapCanonicalGeneratorPath -cne $GeneratorScriptPath) { exit 21 }

    $bootstrapEventEnvironmentNames = [string[]]@(
        'PSPKT_PHASE4_SUPERVISOR_GATE_EVENT',
        'PSPKT_PHASE4_GENERATOR_GATE_PREPARED',
        'PSPKT_PHASE4_GENERATOR_GATE_AUTHORIZE',
        'PSPKT_PHASE4_GENERATOR_GATE_WAIT_ARMED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED'
    )
    $bootstrapEventNameSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($bootstrapEventEnvironmentName in $bootstrapEventEnvironmentNames) {
        $bootstrapEventName = [Environment]::GetEnvironmentVariable($bootstrapEventEnvironmentName)
        if (-not [regex]::IsMatch($bootstrapEventName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$') -or
            -not $bootstrapEventNameSet.Add($bootstrapEventName)) {
            exit 21
        }
    }

    $bootstrapSignalAndWaitMethod = [System.Threading.WaitHandle].GetMethod(
        'SignalAndWait',
        [System.Reflection.BindingFlags]'Public, Static',
        $null,
        [Type[]]@(
            [System.Threading.WaitHandle],
            [System.Threading.WaitHandle],
            [int],
            [bool]),
        $null)
    if ($null -eq $bootstrapSignalAndWaitMethod -or $bootstrapSignalAndWaitMethod.ReturnType -ne [bool]) {
        exit 21
    }
    $bootstrapDynamicMethod = [System.Reflection.Emit.DynamicMethod]::new(
        'PspktGeneratorBootstrapSignalAndWait',
        [void],
        [Type[]]@([object]),
        $false)
    $bootstrapIl = $bootstrapDynamicMethod.GetILGenerator()
    $bootstrapStateLocal = $bootstrapIl.DeclareLocal([object[]])
    $bootstrapExceptionLocal = $bootstrapIl.DeclareLocal([Exception])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldarg_0)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Castclass, [object[]])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Stloc, $bootstrapStateLocal)
    $bootstrapEndLabel = $bootstrapIl.BeginExceptionBlock()
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldloc, $bootstrapStateLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4_3)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldloc, $bootstrapStateLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4_0)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldelem_Ref)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Castclass, [System.Threading.WaitHandle])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldloc, $bootstrapStateLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4_1)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldelem_Ref)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Castclass, [System.Threading.WaitHandle])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldloc, $bootstrapStateLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4_2)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldelem_Ref)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Unbox_Any, [int])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4_0)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Call, $bootstrapSignalAndWaitMethod)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Box, [bool])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Stelem_Ref)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Leave, $bootstrapEndLabel)
    [void]$bootstrapIl.BeginCatchBlock([Exception])
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Stloc, $bootstrapExceptionLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldloc, $bootstrapStateLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4_4)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ldloc, $bootstrapExceptionLocal)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Stelem_Ref)
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Leave, $bootstrapEndLabel)
    $bootstrapIl.EndExceptionBlock()
    $bootstrapIl.Emit([System.Reflection.Emit.OpCodes]::Ret)
    $bootstrapSignalAndWaitDelegate = $bootstrapDynamicMethod.CreateDelegate(
        [System.Threading.ParameterizedThreadStart])

    $bootstrapPreparedEvent = $null
    $bootstrapAuthorizeEvent = $null
    try {
        try {
            $bootstrapPreparedEvent = [System.Threading.EventWaitHandle]::OpenExisting(
                [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GENERATOR_GATE_PREPARED'))
            $bootstrapAuthorizeEvent = [System.Threading.EventWaitHandle]::OpenExisting(
                [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GENERATOR_GATE_AUTHORIZE'))
        }
        catch [System.Threading.WaitHandleCannotBeOpenedException] { exit 21 }
        catch [System.UnauthorizedAccessException] { exit 21 }
        catch [System.IO.IOException] { exit 21 }
        $bootstrapAuthorizationState = [object[]]@(
            $bootstrapPreparedEvent,
            $bootstrapAuthorizeEvent,
            [int]30000,
            $null,
            $null)
        $bootstrapAuthorizationThread = [System.Threading.Thread]::new(
            [System.Threading.ParameterizedThreadStart]$bootstrapSignalAndWaitDelegate)
        $bootstrapAuthorizationThread.IsBackground = $true
        $bootstrapAuthorizationThread.SetApartmentState([System.Threading.ApartmentState]::MTA)
        $bootstrapAuthorizationThread.Start($bootstrapAuthorizationState)
        if (-not $bootstrapAuthorizationThread.Join(35000) -or
            $null -ne $bootstrapAuthorizationState[4]) {
            exit 21
        }
        if ($bootstrapAuthorizationState[3] -isnot [bool] -or
            -not [bool]$bootstrapAuthorizationState[3]) {
            exit 24
        }
    }
    finally {
        if ($null -ne $bootstrapAuthorizeEvent) { $bootstrapAuthorizeEvent.Dispose() }
        if ($null -ne $bootstrapPreparedEvent) { $bootstrapPreparedEvent.Dispose() }
    }

    $bootstrapArmedEvent = $null
    $bootstrapSupervisorGateEvent = $null
    try {
        try {
            $bootstrapArmedEvent = [System.Threading.EventWaitHandle]::OpenExisting(
                [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GENERATOR_GATE_WAIT_ARMED'))
            $bootstrapSupervisorGateEvent = [System.Threading.EventWaitHandle]::OpenExisting(
                [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SUPERVISOR_GATE_EVENT'))
        }
        catch [System.Threading.WaitHandleCannotBeOpenedException] { exit 21 }
        catch [System.UnauthorizedAccessException] { exit 21 }
        catch [System.IO.IOException] { exit 21 }
        $bootstrapGateState = [object[]]@(
            $bootstrapArmedEvent,
            $bootstrapSupervisorGateEvent,
            [int]60000,
            $null,
            $null)
        $bootstrapGateThread = [System.Threading.Thread]::new(
            [System.Threading.ParameterizedThreadStart]$bootstrapSignalAndWaitDelegate)
        $bootstrapGateThread.IsBackground = $true
        $bootstrapGateThread.SetApartmentState([System.Threading.ApartmentState]::MTA)
        $bootstrapGateThread.Start($bootstrapGateState)
        if (-not $bootstrapGateThread.Join(65000) -or
            $null -ne $bootstrapGateState[4]) {
            exit 21
        }
        if ($bootstrapGateState[3] -isnot [bool] -or
            -not [bool]$bootstrapGateState[3]) {
            exit 22
        }
    }
    finally {
        if ($null -ne $bootstrapSupervisorGateEvent) { $bootstrapSupervisorGateEvent.Dispose() }
        if ($null -ne $bootstrapArmedEvent) { $bootstrapArmedEvent.Dispose() }
    }

    try {
        $bootstrapSnapshotRootText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SNAPSHOT_ROOT')
        $bootstrapCanonicalSnapshotRoot = [System.IO.Path]::GetFullPath($bootstrapSnapshotRootText)
        if ($bootstrapCanonicalSnapshotRoot -cne $bootstrapSnapshotRootText) {
            throw [System.IO.InvalidDataException]::new('snapshot root is not canonical.')
        }
        $bootstrapSnapshotDirectory = [System.IO.DirectoryInfo]::new($bootstrapCanonicalSnapshotRoot)
        if (-not $bootstrapSnapshotDirectory.Exists -or
            ($bootstrapSnapshotDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw [System.IO.InvalidDataException]::new('snapshot root is absent or reparsed.')
        }
        $bootstrapSnapshotPrefix = $bootstrapCanonicalSnapshotRoot.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) +
            [System.IO.Path]::DirectorySeparatorChar
        if (-not $bootstrapCanonicalGeneratorPath.StartsWith(
                $bootstrapSnapshotPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.IO.InvalidDataException]::new('generator source is outside the snapshot root.')
        }
        $bootstrapRelativeSourcePath = $bootstrapCanonicalGeneratorPath.Substring($bootstrapSnapshotPrefix.Length)
        $bootstrapRelativeParts = $bootstrapRelativeSourcePath.Split(
            [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
            [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($bootstrapRelativeParts.Length -lt 1) {
            throw [System.IO.InvalidDataException]::new('generator source has no contained leaf.')
        }
        $bootstrapCurrentDirectoryPath = $bootstrapCanonicalSnapshotRoot
        for ($bootstrapPartIndex = 0; $bootstrapPartIndex -lt ($bootstrapRelativeParts.Length - 1); $bootstrapPartIndex++) {
            $bootstrapCurrentDirectoryPath = [System.IO.Path]::Combine(
                $bootstrapCurrentDirectoryPath, $bootstrapRelativeParts[$bootstrapPartIndex])
            $bootstrapCurrentDirectory = [System.IO.DirectoryInfo]::new($bootstrapCurrentDirectoryPath)
            if (-not $bootstrapCurrentDirectory.Exists -or
                ($bootstrapCurrentDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw [System.IO.InvalidDataException]::new('generator source ancestry is absent or reparsed.')
            }
        }
        $bootstrapSourceInfo = [System.IO.FileInfo]::new($bootstrapCanonicalGeneratorPath)
        if (-not $bootstrapSourceInfo.Exists -or
            ($bootstrapSourceInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($bootstrapSourceInfo.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
            $bootstrapSourceInfo.Length -gt 8388608) {
            throw [System.IO.InvalidDataException]::new('generator source is not a bounded ordinary file.')
        }

        $bootstrapSourceStream = [System.IO.FileStream]::new(
            $bootstrapCanonicalGeneratorPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        try {
            if ($bootstrapSourceStream.Length -gt 8388608 -or $bootstrapSourceStream.Length -gt [int]::MaxValue) {
                throw [System.IO.InvalidDataException]::new('generator source exceeds the byte cap.')
            }
            $bootstrapSourceBytes = [byte[]]::new([int]$bootstrapSourceStream.Length)
            $bootstrapSourceOffset = 0
            while ($bootstrapSourceOffset -lt $bootstrapSourceBytes.Length) {
                $bootstrapSourceRead = $bootstrapSourceStream.Read(
                    $bootstrapSourceBytes,
                    $bootstrapSourceOffset,
                    $bootstrapSourceBytes.Length - $bootstrapSourceOffset)
                if ($bootstrapSourceRead -le 0) {
                    throw [System.IO.EndOfStreamException]::new('generator source read ended early.')
                }
                $bootstrapSourceOffset += $bootstrapSourceRead
            }
            if ($bootstrapSourceStream.ReadByte() -ne -1) {
                throw [System.IO.InvalidDataException]::new('generator source changed length during the bounded read.')
            }
        }
        finally {
            $bootstrapSourceStream.Dispose()
        }

        $bootstrapSha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bootstrapComputedHashBytes = $bootstrapSha256.ComputeHash($bootstrapSourceBytes)
        }
        finally {
            $bootstrapSha256.Dispose()
        }
        $bootstrapComputedDigestBuilder = [System.Text.StringBuilder]::new(64)
        foreach ($bootstrapComputedHashByte in $bootstrapComputedHashBytes) {
            [void]$bootstrapComputedDigestBuilder.Append(
                $bootstrapComputedHashByte.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture))
        }
        if ($bootstrapComputedDigestBuilder.ToString() -cne $bootstrapSourceDigest) {
            throw [System.IO.InvalidDataException]::new('generator source digest mismatch.')
        }

        $bootstrapUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $bootstrapSourceText = $bootstrapUtf8.GetString($bootstrapSourceBytes)
        $bootstrapTokens = $null
        $bootstrapParseErrors = $null
        $bootstrapSourceAst = [System.Management.Automation.Language.Parser]::ParseInput(
            $bootstrapSourceText,
            $bootstrapCanonicalGeneratorPath,
            [ref]$bootstrapTokens,
            [ref]$bootstrapParseErrors)
        if ($bootstrapParseErrors.Count -ne 0) {
            throw [System.Management.Automation.ParseException]::new('verified generator source did not parse.')
        }
        $bootstrapGeneratorScript = $bootstrapSourceAst.GetScriptBlock()
        & $bootstrapGeneratorScript -Contained -SelfTest
        exit 0
    }
    catch [System.ArgumentException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.NotSupportedException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.IO.PathTooLongException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.IO.IOException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.UnauthorizedAccessException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.Security.SecurityException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.Management.Automation.ParseException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.Management.Automation.ParameterBindingException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.Management.Automation.RuntimeException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
    catch [System.Security.Cryptography.CryptographicException] { [Console]::Error.WriteLine($_.Exception.ToString()); exit 23 }
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$certRoot = Split-Path -Parent $here
$repositoryRoot = Split-Path -Parent $certRoot
$script:Phase4ValidatorSourcePath = [string]$MyInvocation.MyCommand.Path

$script:HelperVersion = 'pspkt-phase4-bounded-process-2'
$script:PinnedBaselineCommit = 'f805e9af8171b619a49a982e8f562355eddb1116'
$script:HelperByteCap = 4194304
$script:GitBlobByteCap = 8388608
$script:GitSnapshotTotalCap = 67108864
$script:GitStdoutCap = 65536
$script:GitBlobStdoutCap = 8388609
$script:GitWaitMs = 60000
$script:CscWaitMs = 120000
$script:CscBinaryByteCap = 33554432
$script:GitIndexByteCap = 33554432
$script:GitConfigByteCap = 1048576
$script:ProcessExitWaitMs = 15000
$script:PendingReadRecheckMs = 2000

$script:Phase4QuarantineRegistryCapacity = 64
$script:Phase4QuarantineRegistry = [System.Collections.Generic.List[object]]::new()
$script:Phase4QuarantineEmergencySlot = $null
$script:Phase4BootstrapProcessQuarantineCapacity = 64
$script:Phase4BootstrapProcessQuarantine = [System.Collections.Generic.List[object]]::new()
$script:Phase4BootstrapProcessEmergencySlot = $null
$script:SnapshotCorruptionSeam = $null

$script:PassCount = 0
$script:FailCount = 0

$script:ExpectedSlicePaths = @(
    '.gitattributes',
    'certification/lib/Pspkt.Certification.BoundedProcess.cs',
    'certification/lib/Pspkt.Certification.CanonicalJson.ps1',
    'certification/lib/Pspkt.Certification.SchemaBootstrap.cs',
    'certification/lib/Pspkt.Certification.SchemaFixtureContract.ps1',
    'certification/schema/README.md',
    'certification/schema/protocol-schema-meta.v1.json',
    'certification/validators/Invoke-PspktPhase4SchemaValidators.ps1',
    'certification/validators/Test-PspktPhase4Schema.ps1',
    'certification/vectors/New-PspktPhase4SchemaVectors.ps1',
    'certification/vectors/phase4-schema/bootstrap-meta/duplicate-identifier.json',
    'certification/vectors/phase4-schema/bootstrap-meta/enum-member-cardinality.json',
    'certification/vectors/phase4-schema/bootstrap-meta/meta-authority-extension.json',
    'certification/vectors/phase4-schema/bootstrap-meta/meta-authority-rename.json',
    'certification/vectors/phase4-schema/bootstrap-meta/meta-authority-schema-id.json',
    'certification/vectors/phase4-schema/bootstrap-meta/missing-property.json',
    'certification/vectors/phase4-schema/bootstrap-meta/type-cycle.json',
    'certification/vectors/phase4-schema/bootstrap-meta/unknown-primitive.json',
    'certification/vectors/phase4-schema/bootstrap-meta/unknown-property.json',
    'certification/vectors/phase4-schema/fixture-manifest.v1.json',
    'certification/vectors/phase4-schema/json/allocation-budget-exact.json',
    'certification/vectors/phase4-schema/json/allocation-budget-over.json',
    'certification/vectors/phase4-schema/json/array-limit-exact.json',
    'certification/vectors/phase4-schema/json/array-limit-over.json',
    'certification/vectors/phase4-schema/json/block-comment.json',
    'certification/vectors/phase4-schema/json/byte-order-mark.json',
    'certification/vectors/phase4-schema/json/depth-limit-exact.json',
    'certification/vectors/phase4-schema/json/depth-limit-over.json',
    'certification/vectors/phase4-schema/json/duplicate-key.json',
    'certification/vectors/phase4-schema/json/exponent-value.json',
    'certification/vectors/phase4-schema/json/file-limit-exact.json',
    'certification/vectors/phase4-schema/json/file-limit-over.json',
    'certification/vectors/phase4-schema/json/float-value.json',
    'certification/vectors/phase4-schema/json/integer-overflow.json',
    'certification/vectors/phase4-schema/json/invalid-escape.json',
    'certification/vectors/phase4-schema/json/leading-zero-integer.json',
    'certification/vectors/phase4-schema/json/line-comment.json',
    'certification/vectors/phase4-schema/json/malformed-utf8.json',
    'certification/vectors/phase4-schema/json/negative-integer.json',
    'certification/vectors/phase4-schema/json/nul-byte.json',
    'certification/vectors/phase4-schema/json/overlong-utf8.json',
    'certification/vectors/phase4-schema/json/property-limit-exact.json',
    'certification/vectors/phase4-schema/json/property-limit-over.json',
    'certification/vectors/phase4-schema/json/replacement-character-escape.json',
    'certification/vectors/phase4-schema/json/replacement-character-raw.json',
    'certification/vectors/phase4-schema/json/string-limit-exact.json',
    'certification/vectors/phase4-schema/json/string-limit-over.json',
    'certification/vectors/phase4-schema/json/trailing-comma-array.json',
    'certification/vectors/phase4-schema/json/trailing-comma-object.json',
    'certification/vectors/phase4-schema/json/trailing-data.json',
    'certification/vectors/phase4-schema/json/trailing-newline.json',
    'certification/vectors/phase4-schema/json/unpaired-surrogate.json',
    'certification/vectors/phase4-schema/json/valid-unicode-value.json',
    'certification/vectors/phase4-schema/schema/bound-overflow.json',
    'certification/vectors/phase4-schema/schema/duplicate-field-id.json',
    'certification/vectors/phase4-schema/schema/duplicate-type-id.json',
    'certification/vectors/phase4-schema/schema/field-limit-exact.json',
    'certification/vectors/phase4-schema/schema/field-limit-over.json',
    'certification/vectors/phase4-schema/schema/field-order.json',
    'certification/vectors/phase4-schema/schema/impossible-semantic-domain.json',
    'certification/vectors/phase4-schema/schema/invalid-cardinality.json',
    'certification/vectors/phase4-schema/schema/invented-alias.json',
    'certification/vectors/phase4-schema/schema/non-ascii-symbol.json',
    'certification/vectors/phase4-schema/schema/type-limit-exact.json',
    'certification/vectors/phase4-schema/schema/type-limit-over.json',
    'certification/vectors/phase4-schema/schema/undefined-reference.json',
    'certification/vectors/phase4-schema/schema/utf8short-as-semantic-reference.json',
    'certification/vectors/phase4-schema/schema/valid-enum-use.json',
    'certification/vectors/phase4-schema/schema/valid-named-list-set-use.json',
    'certification/vectors/phase4-schema/schema/valid-primitive-use.json',
    'certification/vectors/phase4-schema/schema/valid-semantic-string-use.json',
    'certification/vectors/phase4-schema/schema/profile-fields-ok.json',
    'certification/vectors/phase4-schema/schema/profile-invalid.json',
    'certification/vectors/phase4-schema/schema/field-status-invalid.json',
    'certification/vectors/phase4-schema/schema/forbidden-without-profile.json',
    'certification/vectors/phase4-schema/schema/profile-duplicate-field-id.json',
    'certification/vectors/phase4-schema/schema/profile-field-order.json',
    'certification/vectors/phase4-schema/schema/profile-forbidden-override-ok.json'
)

$script:PinnedGitAttributesRelPath = '.gitattributes'
$script:PinnedGitAttributesIndexOid = '0849eff6db27ac0e31ae353f898982e676fb6b20'
$script:PinnedGitAttributesLength = 1098
$script:PinnedGitAttributesSha256 = '4fb78db0ed73b7f5c63edfe3ce6f71baf427bb80cfda9ec0d046b68907fc0f3c'
$script:PinnedGitAttributesTextPolicy = 'text eol=lf -filter -ident -working-tree-encoding'
$script:PinnedGitAttributesBinaryPolicy = '-text -eol -filter -ident -working-tree-encoding'
$script:PinnedGitAttributesLines = @(
    '/.gitattributes text eol=lf -filter -ident -working-tree-encoding',
    '/certification/lib/Pspkt.Certification.CanonicalJson.ps1 text eol=lf -filter -ident -working-tree-encoding',
    '/certification/lib/Pspkt.Certification.SchemaBootstrap.cs text eol=lf -filter -ident -working-tree-encoding',
    '/certification/lib/Pspkt.Certification.BoundedProcess.cs text eol=lf -filter -ident -working-tree-encoding',
    '/certification/lib/Pspkt.Certification.SchemaFixtureContract.ps1 text eol=lf -filter -ident -working-tree-encoding',
    '/certification/validators/Test-PspktPhase4Schema.ps1 text eol=lf -filter -ident -working-tree-encoding',
    '/certification/validators/Invoke-PspktPhase4SchemaValidators.ps1 text eol=lf -filter -ident -working-tree-encoding',
    '/certification/vectors/New-PspktPhase4SchemaVectors.ps1 text eol=lf -filter -ident -working-tree-encoding',
    '/certification/schema/README.md text eol=lf -filter -ident -working-tree-encoding',
    '/certification/schema/protocol-schema-meta.v1.json -text -eol -filter -ident -working-tree-encoding',
    '/certification/vectors/phase4-schema/** -text -eol -filter -ident -working-tree-encoding'
)
$script:PinnedGitAttributesBytes = [System.Text.Encoding]::ASCII.GetBytes((($script:PinnedGitAttributesLines -join "`n") + "`n"))

$script:ExpectedWorkerCheckIds = @(
    'nested-job-inner-membership',
    'combined-seam-rejection',
    'reject-basic',
    'reject-event-name',
    'validation-precedence-overlap',
    'invalid-pause-rejection',
    'empty-correlation-rejection',
    'environment-gate-collision-rejection',
    'environment-duplicate-extra-rejection',
    'environment-name-rejection',
    'environment-value-rejection',
    'environment-value-limit-rejection',
    'environment-block-limit-rejection',
    'environment-ambient-scrub',
    'environment-snapshot-isolation',
    'launch-role-environment-matrix',
    'launcher-role-cross-product',
    'prelaunch-host-argv',
    'quoter-edge-cases',
    'security-attributes-abi',
    'job-accounting-abi',
    'job-kill-on-close-flag',
    'job-event-handles-noninheritable',
    'event-open-absent',
    'event-duplicate-access-denied',
    'event-duplicate-handle-close',
    'event-production-dacl',
    'event-restricted-dacl',
    'pause-positive-release',
    'pause-ack-timeout',
    'pause-release-timeout',
    'parent-loss-gate-timeout',
    'post-assignment-kill-on-close',
    'post-assignment-evidence-failure',
    'drain-clean',
    'drain-forced',
    'drain-partial-start',
    'drain-nonunwinding',
    'drain-nonunwinding-negative-control',
    'exception-composer',
    'gate-success',
    'gate-missing-environment',
    'gate-wrong-name',
    'gate-timeout',
    'gate-delayed-signal',
    'gate-name-squat',
    'assignment-failure',
    'watchdog-complete-once',
    'watchdog-timeout',
    'descendant-timeout',
    'output-overflow',
    'helper-digest-mismatch',
    'manifest-negative-vectors',
    'schema-child-result'
)

$script:ExpectedOuterCheckIdsSlice = @(
    'git-authority-negative-vectors',
    'source-snapshot-authority',
    'csc-authority',
    'csc-output',
    'index-tree-initial',
    'outer-launch-inventory',
    'worker-assign-failure',
    'worker-resume-failure',
    'worker-gate-timeout',
    'worker-gate-open-failure',
    'worker-timeout-cleanup',
    'worker-descendant-detected',
    'worker-nonzero-exit-rejected',
    'worker-result-negative-vectors',
    'schema-result-negative-vectors',
    'generator-result-negative-vectors',
    'worker-helper-handoff',
    'nested-job-outer-count-rise',
    'nested-job-outer-count-fall',
    'worker-normal-exit-zero',
    'worker-normal-result-accepted',
    'worker-normal-no-descendants',
    'generator-contained-false',
    'generator-gate-first',
    'generator-selftest',
    'generator-hardlink',
    'generator-output-68',
    'generator-index-stable',
    'index-tree-final',
    'outer-cleanup'
)

$script:ExpectedGeneratorCheckIds = @(
    'selftest-pass',
    'hardlink-pass',
    'output-count-pass',
    'output-digest-pass'
)

function Get-PspktReleaseCheckIds {
    $sliceCore = @()
    foreach ($id in $script:ExpectedOuterCheckIdsSlice) {
        if ($id -ceq 'index-tree-final' -or $id -ceq 'outer-cleanup') { continue }
        $sliceCore += $id
    }
    return @('baseline-commit-valid', 'exclusive-slice-initial') + $sliceCore + @('exclusive-slice-final', 'index-tree-final', 'outer-cleanup')
}
$script:ExpectedOuterCheckIdsRelease = Get-PspktReleaseCheckIds

$script:WorkerScenarioInventory = @(
    'Normal',
    'SimulateAssignFailure',
    'ResumeFailureZero',
    'ResumeFailureNative',
    'ResumeFailureMultiple',
    'WorkerGateTimeout',
    'WorkerGateOpenFailure',
    'WorkerTimeout',
    'WorkerLeavesDescendant',
    'WorkerNonzeroExit'
)

$script:WorkerResultMutationInventory = @(
    'NonceMismatch',
    'VersionMismatch',
    'MissingCheck',
    'UnknownCheck',
    'DuplicateCheck',
    'OutOfOrderCheck',
    'SkipStatus',
    'FailStatus',
    'BadOrdinal',
    'BadSummaryCount',
    'BadSummaryStatus',
    'MissingSummary',
    'ExtraBytes',
    'Oversize',
    'MalformedUtf8',
    'Bom'
)

$script:GeneratorScenarioInventory = @('Normal', 'ContainedFalse', 'GateWithheld')

$script:SchemaResultMutationInventory = @(
    'HeaderTag',
    'HeaderFieldCount',
    'NonceMismatch',
    'VersionMismatch',
    'CaseTag',
    'CaseFieldCount',
    'BadOrdinal',
    'NameMismatch',
    'PathMismatch',
    'StageMismatch',
    'ExpectedOutcomeMismatch',
    'ExpectedReasonMismatch',
    'ByteLengthMismatch',
    'Sha256Mismatch',
    'ActualOutcomeMismatch',
    'ActualReasonMismatch',
    'MissingCase',
    'ExtraCase',
    'DuplicateCase',
    'ReorderedCases',
    'UnknownRecord',
    'MissingSummary',
    'DuplicateSummary',
    'BadSummaryCount',
    'BadSummaryStatus',
    'SummaryFieldCount',
    'MissingTerminalNewline',
    'CarriageReturn',
    'ExtraTrailingData',
    'Oversize',
    'MalformedUtf8',
    'Bom'
)

function New-PspktUtf8NoBom {
    return [System.Text.UTF8Encoding]::new($false, $true)
}

function Get-PspktQuotedArg {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Arg)
    if ($Arg.Length -ne 0 -and -not ($Arg -match '[ \t\n\v"]')) {
        return $Arg
    }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append([char]0x22)
    $i = 0
    while ($i -lt $Arg.Length) {
        $backslashes = 0
        while ($i -lt $Arg.Length -and $Arg[$i] -eq [char]0x5C) {
            $i++
            $backslashes++
        }
        if ($i -eq $Arg.Length) {
            [void]$sb.Append([char]0x5C, ($backslashes * 2))
            break
        }
        elseif ($Arg[$i] -eq [char]0x22) {
            [void]$sb.Append([char]0x5C, ($backslashes * 2 + 1))
            [void]$sb.Append([char]0x22)
            $i++
        }
        else {
            [void]$sb.Append([char]0x5C, $backslashes)
            [void]$sb.Append($Arg[$i])
            $i++
        }
    }
    [void]$sb.Append([char]0x22)
    return $sb.ToString()
}

function Join-PspktArgv {
    param([Parameter(Mandatory = $true)][string[]]$Argv)
    $quoted = @()
    foreach ($arg in $Argv) {
        $quoted += (Get-PspktQuotedArg -Arg ([string]$arg))
    }
    return ($quoted -join ' ')
}

function Get-PspktSha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    }
    finally {
        $sha.Dispose()
    }
    $builder = [System.Text.StringBuilder]::new($hash.Length * 2)
    foreach ($b in $hash) {
        [void]$builder.Append($b.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    return $builder.ToString()
}

function Test-PspktLowercaseHexOid {
    param([Parameter(Mandatory = $true)][string]$Value)
    return [regex]::IsMatch($Value, '^[0-9a-f]{40}$') -or [regex]::IsMatch($Value, '^[0-9a-f]{64}$')
}

function Read-PspktBoundedFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][int]$ByteCap
    )
    $stream = [System.IO.FileStream]::new($FullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        [int64]$length = $stream.Length
        if ($length -lt 0) {
            throw ('bounded read: "{0}" reports a negative length {1}.' -f $FullPath, $length)
        }
        if ($length -gt [int64]$ByteCap) {
            throw ('bounded read: "{0}" is {1} bytes, over the {2}-byte cap.' -f $FullPath, $length, $ByteCap)
        }
        if ($length -gt [int64][int]::MaxValue) {
            throw ('bounded read: "{0}" is {1} bytes, over the addressable buffer limit.' -f $FullPath, $length)
        }
        $count = [int]$length
        $buffer = [byte[]]::new($count)
        $offset = 0
        while ($offset -lt $count) {
            $read = $stream.Read($buffer, $offset, $count - $offset)
            if ($read -le 0) { break }
            $offset += $read
        }
        if ($offset -ne $count) {
            throw ('bounded read: short read on "{0}".' -f $FullPath)
        }
        if ($stream.ReadByte() -ne -1) {
            throw ('bounded read: "{0}" grew during the read.' -f $FullPath)
        }
        return ,$buffer
    }
    finally {
        $stream.Dispose()
    }
}

function Read-PspktBoundedStreamBytes {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][int]$ByteCap
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'bounded stream read: retained handle must be readable and seekable.'
    }
    [int64]$length = $Stream.Length
    if ($length -lt 0) {
        throw ('bounded stream read: retained handle reports a negative length {0}.' -f $length)
    }
    if ($length -gt [int64]$ByteCap) {
        throw ('bounded stream read: retained handle is {0} bytes, over the {1}-byte cap.' -f $length, $ByteCap)
    }
    if ($length -gt [int64][int]::MaxValue) {
        throw ('bounded stream read: retained handle is {0} bytes, over the addressable buffer limit.' -f $length)
    }
    $count = [int]$length
    $buffer = [byte[]]::new($count)
    $Stream.Position = 0
    $offset = 0
    while ($offset -lt $count) {
        $read = $Stream.Read($buffer, $offset, $count - $offset)
        if ($read -le 0) { break }
        $offset += $read
    }
    if ($offset -ne $count) {
        throw 'bounded stream read: short read on the retained handle.'
    }
    if ($Stream.ReadByte() -ne -1) {
        throw 'bounded stream read: the retained handle grew during the read.'
    }
    return ,$buffer
}

function Open-PspktRetainedReadonlyFile {
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][int]$ByteCap,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not [System.IO.Path]::IsPathRooted($FullPath)) {
        throw ('{0}: "{1}" is not a rooted path.' -f $Label, $FullPath)
    }
    $canonical = [System.IO.Path]::GetFullPath($FullPath)
    $info = [System.IO.FileInfo]::new($canonical)
    if (-not $info.Exists) {
        throw ('{0}: "{1}" is not present as an ordinary file.' -f $Label, $canonical)
    }
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw ('{0}: "{1}" is a reparse point.' -f $Label, $canonical)
    }
    if (($info.Attributes -band [System.IO.FileAttributes]::Directory) -eq [System.IO.FileAttributes]::Directory) {
        throw ('{0}: "{1}" resolved to a directory.' -f $Label, $canonical)
    }
    $stream = [System.IO.FileStream]::new($canonical, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $bound = $false
    try {
        [byte[]]$bytes = Read-PspktBoundedStreamBytes -Stream $stream -ByteCap $ByteCap
        $retained = [pscustomobject]@{
            Label = $Label
            FullName = $info.FullName
            Stream = $stream
            Bytes = $bytes
            Sha256 = (Get-PspktSha256Hex -Bytes $bytes)
            Length = [int64]$bytes.Length
            Attributes = $info.Attributes
            CreationTimeUtc = $info.CreationTimeUtc
            LastWriteTimeUtc = $info.LastWriteTimeUtc
            ByteCap = $ByteCap
        }
        $bound = $true
        return $retained
    }
    finally {
        if (-not $bound) { $stream.Dispose() }
    }
}

function Assert-PspktRetainedFileUnchanged {
    param([Parameter(Mandatory = $true)]$Retained)
    if ($null -eq $Retained -or $null -eq $Retained.Stream) {
        throw 'retained-file authority: handle is not established.'
    }
    $label = [string]$Retained.Label
    [byte[]]$retainedBytes = Read-PspktBoundedStreamBytes -Stream $Retained.Stream -ByteCap ([int]$Retained.ByteCap)
    if ($retainedBytes.Length -ne [int]$Retained.Length) {
        throw ('{0}: retained handle length {1} drifted from {2}.' -f $label, $retainedBytes.Length, $Retained.Length)
    }
    $retainedDigest = Get-PspktSha256Hex -Bytes $retainedBytes
    if ($retainedDigest -cne [string]$Retained.Sha256) {
        throw ('{0}: retained handle content drifted.' -f $label)
    }
    $info = [System.IO.FileInfo]::new([string]$Retained.FullName)
    if (-not $info.Exists) {
        throw ('{0}: "{1}" is no longer present as an ordinary file.' -f $label, $Retained.FullName)
    }
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw ('{0}: "{1}" became a reparse point.' -f $label, $Retained.FullName)
    }
    if ($info.Attributes -ne $Retained.Attributes) {
        throw ('{0}: "{1}" attributes drifted.' -f $label, $Retained.FullName)
    }
    if ($info.CreationTimeUtc -ne $Retained.CreationTimeUtc) {
        throw ('{0}: "{1}" creation time drifted.' -f $label, $Retained.FullName)
    }
    if ($info.LastWriteTimeUtc -ne $Retained.LastWriteTimeUtc) {
        throw ('{0}: "{1}" last-write time drifted.' -f $label, $Retained.FullName)
    }
    [byte[]]$pathCopy = Read-PspktBoundedFileBytes -FullPath ([string]$Retained.FullName) -ByteCap ([int]$Retained.ByteCap)
    if ($pathCopy.Length -ne [int]$Retained.Length) {
        throw ('{0}: "{1}" path-copy length drifted.' -f $label, $Retained.FullName)
    }
    $pathCopyDigest = Get-PspktSha256Hex -Bytes $pathCopy
    if ($pathCopyDigest -cne [string]$Retained.Sha256) {
        throw ('{0}: "{1}" path-copy content drifted.' -f $label, $Retained.FullName)
    }
}

function Close-PspktRetainedFile {
    param([AllowNull()]$Retained)
    if ($null -ne $Retained -and $null -ne $Retained.Stream) {
        $Retained.Stream.Dispose()
    }
}

function New-PspktBclDirectoryIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $info = [System.IO.DirectoryInfo]::new($FullPath)
    if (-not $info.Exists) {
        throw ('{0}: "{1}" is not present as an ordinary directory.' -f $Label, $FullPath)
    }
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw ('{0}: "{1}" is a reparse point.' -f $Label, $FullPath)
    }
    return [pscustomobject]@{
        Label = $Label
        FullName = $info.FullName
        Attributes = $info.Attributes
        CreationTimeUtc = $info.CreationTimeUtc
    }
}

function Assert-PspktBclDirectoryIdentityUnchanged {
    param([Parameter(Mandatory = $true)]$Identity)
    $label = [string]$Identity.Label
    $info = [System.IO.DirectoryInfo]::new([string]$Identity.FullName)
    if (-not $info.Exists) {
        throw ('{0}: "{1}" is no longer an ordinary directory.' -f $label, $Identity.FullName)
    }
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw ('{0}: "{1}" became a reparse point.' -f $label, $Identity.FullName)
    }
    if ($info.FullName -cne [string]$Identity.FullName) {
        throw ('{0}: "{1}" canonical path drifted to "{2}".' -f $label, $Identity.FullName, $info.FullName)
    }
    if ($info.Attributes -ne $Identity.Attributes) {
        throw ('{0}: "{1}" attributes drifted.' -f $label, $Identity.FullName)
    }
    if ($info.CreationTimeUtc -ne $Identity.CreationTimeUtc) {
        throw ('{0}: "{1}" creation time drifted.' -f $label, $Identity.FullName)
    }
}

function Assert-PspktContainedDirectLeaf {
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedRoot,
        [Parameter(Mandatory = $true)][string]$LeafPath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrEmpty($ExpectedRoot)) { throw ('{0}: expected root authority is absent.' -f $Label) }
    if ([string]::IsNullOrEmpty($LeafPath)) { throw ('{0}: path authority is absent.' -f $Label) }
    $canonicalRoot = [System.IO.Path]::GetFullPath($ExpectedRoot)
    $canonicalLeaf = [System.IO.Path]::GetFullPath($LeafPath)
    if ($canonicalLeaf -cne $LeafPath) { throw ('{0}: path "{1}" is not canonical.' -f $Label, $LeafPath) }
    if (-not (Test-PspktNonReparseDirectory -FullPath $canonicalRoot)) {
        throw ('{0}: expected root "{1}" is absent or a reparse point.' -f $Label, $canonicalRoot)
    }
    $trimmedRoot = $canonicalRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
    $rootPrefix = $trimmedRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $canonicalLeaf.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('{0}: path "{1}" is outside the expected root.' -f $Label, $canonicalLeaf)
    }
    $leafParent = [System.IO.Path]::GetDirectoryName($canonicalLeaf)
    if ([string]::IsNullOrEmpty($leafParent) -or
        ($leafParent.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar) -cne $trimmedRoot)) {
        throw ('{0}: path "{1}" is not a direct child of the expected root.' -f $Label, $canonicalLeaf)
    }
    if (-not (Test-Path -LiteralPath $canonicalLeaf -PathType Leaf)) {
        throw ('{0}: path "{1}" is absent.' -f $Label, $canonicalLeaf)
    }
    $leafInfo = [System.IO.FileInfo]::new($canonicalLeaf)
    if (($leafInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw ('{0}: path "{1}" is a reparse point.' -f $Label, $canonicalLeaf)
    }
    if (($leafInfo.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw ('{0}: path "{1}" is a directory.' -f $Label, $canonicalLeaf)
    }
    return $canonicalLeaf
}

function Assert-PspktStrictAuthorityRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrEmpty($Root)) { throw ('{0}: authority root is absent.' -f $Label) }
    $canonicalRoot = [System.IO.Path]::GetFullPath($Root)
    if (-not (Test-PspktNonReparseDirectory -FullPath $canonicalRoot)) {
        throw ('{0}: authority root "{1}" is absent or a reparse point.' -f $Label, $canonicalRoot)
    }
    return $canonicalRoot
}

function Resolve-PspktStrictContainedLeaf {
    param(
        [Parameter(Mandatory = $true)][string]$AuthorityRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $canonicalRoot = Assert-PspktStrictAuthorityRoot -Root $AuthorityRoot -Label $Label
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $trimmedRoot = $canonicalRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
    $rootPrefix = $trimmedRoot + $separator
    if ([string]::IsNullOrEmpty($RelativePath)) {
        throw ('{0}: relative path authority is absent.' -f $Label)
    }
    if ($RelativePath.IndexOf('\') -ge 0) {
        throw ('{0}: relative path "{1}" must use forward-slash separators.' -f $Label, $RelativePath)
    }
    $components = $RelativePath.Split([char]'/')
    $currentPath = $trimmedRoot
    for ($componentIndex = 0; $componentIndex -lt $components.Length; $componentIndex++) {
        $component = [string]$components[$componentIndex]
        if ([string]::IsNullOrEmpty($component)) {
            throw ('{0}: relative path "{1}" has an empty component.' -f $Label, $RelativePath)
        }
        if ($component.IndexOf([char]0) -ge 0) {
            throw ('{0}: relative path "{1}" contains a NUL component.' -f $Label, $RelativePath)
        }
        if ($component -ceq '.' -or $component -ceq '..') {
            throw ('{0}: relative path "{1}" contains a dot-traversal component.' -f $Label, $RelativePath)
        }
        if ($component.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw ('{0}: relative path "{1}" contains an invalid component character.' -f $Label, $RelativePath)
        }
        $currentPath = $currentPath + $separator + $component
        $canonicalCurrent = [System.IO.Path]::GetFullPath($currentPath)
        if ($canonicalCurrent -cne $currentPath) {
            throw ('{0}: path "{1}" is not canonical.' -f $Label, $currentPath)
        }
        if (-not $canonicalCurrent.StartsWith($rootPrefix, [System.StringComparison]::Ordinal)) {
            throw ('{0}: path "{1}" escaped the authority root.' -f $Label, $canonicalCurrent)
        }
        if ($componentIndex -eq ($components.Length - 1)) {
            if (-not (Test-Path -LiteralPath $canonicalCurrent -PathType Leaf)) {
                throw ('{0}: leaf "{1}" is absent.' -f $Label, $canonicalCurrent)
            }
            $leafInfo = [System.IO.FileInfo]::new($canonicalCurrent)
            if (($leafInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('{0}: leaf "{1}" is a reparse point.' -f $Label, $canonicalCurrent)
            }
            if (($leafInfo.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                throw ('{0}: leaf "{1}" is a directory.' -f $Label, $canonicalCurrent)
            }
        }
        else {
            if (-not (Test-PspktNonReparseDirectory -FullPath $canonicalCurrent)) {
                throw ('{0}: ancestor "{1}" is absent or a reparse point.' -f $Label, $canonicalCurrent)
            }
        }
    }
    return $currentPath
}

function Get-PspktStrictTreeRelativeFiles {
    param(
        [Parameter(Mandatory = $true)][string]$CanonicalRoot,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$MaxEntries = 8192,
        [int]$MaxDepth = 24
    )
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $trimmedRoot = $CanonicalRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
    $rootPrefix = $trimmedRoot + $separator
    $files = [System.Collections.Generic.List[string]]::new()
    $ordinalSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $caseFoldedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Stack[object]]::new()
    [void]$pending.Push([pscustomobject]@{ FullPath = $trimmedRoot; Relative = ''; Depth = 0 })
    $visited = 0
    while ($pending.Count -gt 0) {
        $frame = $pending.Pop()
        if ([int]$frame.Depth -gt $MaxDepth) {
            throw ('{0}: directory depth exceeded the {1}-level ceiling.' -f $Label, $MaxDepth)
        }
        $directoryInfo = [System.IO.DirectoryInfo]::new([string]$frame.FullPath)
        if (-not $directoryInfo.Exists) {
            throw ('{0}: directory "{1}" vanished during traversal.' -f $Label, $frame.FullPath)
        }
        if (($directoryInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('{0}: directory "{1}" is a reparse point.' -f $Label, $frame.FullPath)
        }
        $children = @($directoryInfo.GetFileSystemInfos())
        foreach ($child in $children) {
            $visited++
            if ($visited -gt $MaxEntries) {
                throw ('{0}: entry count exceeded the {1}-entry ceiling.' -f $Label, $MaxEntries)
            }
            $name = [string]$child.Name
            if ([string]::IsNullOrEmpty($name)) {
                throw ('{0}: an entry under "{1}" has an empty name.' -f $Label, $frame.FullPath)
            }
            if ($name.IndexOf([char]0) -ge 0) {
                throw ('{0}: an entry under "{1}" has a NUL name.' -f $Label, $frame.FullPath)
            }
            if ($name -ceq '.' -or $name -ceq '..') {
                throw ('{0}: an entry under "{1}" is a dot-traversal name.' -f $Label, $frame.FullPath)
            }
            if ($name.IndexOf($separator) -ge 0 -or $name.IndexOf([char]'/') -ge 0) {
                throw ('{0}: an entry under "{1}" carries a separator in its name.' -f $Label, $frame.FullPath)
            }
            if ($name.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw ('{0}: an entry under "{1}" has an invalid name character.' -f $Label, $frame.FullPath)
            }
            $childFull = [string]$frame.FullPath + $separator + $name
            $canonicalChild = [System.IO.Path]::GetFullPath($childFull)
            if ($canonicalChild -cne $childFull) {
                throw ('{0}: entry "{1}" is not canonical.' -f $Label, $childFull)
            }
            if (-not $canonicalChild.StartsWith($rootPrefix, [System.StringComparison]::Ordinal)) {
                throw ('{0}: entry "{1}" escaped the authority root.' -f $Label, $canonicalChild)
            }
            if ([string]$frame.Relative -eq '') {
                $childRelative = $name
            }
            else {
                $childRelative = [string]$frame.Relative + '/' + $name
            }
            $attributes = $child.Attributes
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('{0}: entry "{1}" is a reparse point.' -f $Label, $childRelative)
            }
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                [void]$pending.Push([pscustomobject]@{ FullPath = $canonicalChild; Relative = $childRelative; Depth = [int]$frame.Depth + 1 })
            }
            elseif ($child -is [System.IO.FileInfo]) {
                if (-not $ordinalSet.Add($childRelative)) {
                    throw ('{0}: duplicate relative path "{1}".' -f $Label, $childRelative)
                }
                if (-not $caseFoldedSet.Add($childRelative)) {
                    throw ('{0}: case-colliding relative path "{1}".' -f $Label, $childRelative)
                }
                [void]$files.Add($childRelative)
            }
            else {
                throw ('{0}: entry "{1}" is neither an ordinary file nor directory.' -f $Label, $childRelative)
            }
        }
    }
    return ,$files
}

function New-PspktTempDirectory {
    param([Parameter(Mandatory = $true)][string]$Prefix)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ($Prefix + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return (Resolve-Path -LiteralPath $path).ProviderPath
}

function Test-PspktNonReparseDirectory {
    param([Parameter(Mandatory = $true)][string]$FullPath)
    $info = [System.IO.DirectoryInfo]::new($FullPath)
    if (-not $info.Exists) { return $false }
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) { return $false }
    return $true
}

function New-PspktGateEventName {
    param([Parameter(Mandatory = $true)][string]$Tag)
    return ('Local\PspktPhase4' + $Tag + [guid]::NewGuid().ToString('N'))
}

function Get-PspktStreamSha256Hex {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)
    $Stream.Position = 0
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Stream)
    }
    finally {
        $sha.Dispose()
    }
    $builder = [System.Text.StringBuilder]::new($hash.Length * 2)
    foreach ($b in $hash) {
        [void]$builder.Append($b.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    return $builder.ToString()
}

function Get-PspktRemainingCleanupBudgetMs {
    param(
        [AllowNull()][System.Diagnostics.Stopwatch]$CleanupStopwatch = $null,
        [int]$CleanupBudgetMs = -1
    )
    if ($null -eq $CleanupStopwatch -or $CleanupBudgetMs -lt 0) {
        return $script:ProcessExitWaitMs
    }
    $remaining = $CleanupBudgetMs - [int]$CleanupStopwatch.ElapsedMilliseconds
    if ($remaining -lt 0) { $remaining = 0 }
    return $remaining
}

function Stop-PspktProcessBounded {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowNull()][System.Diagnostics.Stopwatch]$CleanupStopwatch = $null,
        [int]$CleanupBudgetMs = -1
    )
    if ($Process.HasExited) { return }
    try {
        $Process.Kill()
    }
    catch {
        if (-not $Process.HasExited) { throw }
    }
    $waitBudget = Get-PspktRemainingCleanupBudgetMs -CleanupStopwatch $CleanupStopwatch -CleanupBudgetMs $CleanupBudgetMs
    if (-not $Process.WaitForExit($waitBudget)) {
        throw ('{0} did not exit within {1} ms after kill.' -f $Label, $waitBudget)
    }
}

function Test-PspktProcessProvenExited {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    try {
        return [bool]$Process.HasExited
    }
    catch [System.InvalidOperationException] { return $false }
    catch [System.ComponentModel.Win32Exception] { return $false }
    catch [System.NotSupportedException] { return $false }
}

function Get-PspktBootstrapProcessQuarantineCount {
    if ($null -eq $script:Phase4BootstrapProcessQuarantine) { return 0 }
    return $script:Phase4BootstrapProcessQuarantine.Count
}

function Reset-PspktBootstrapProcessQuarantineTo {
    param([Parameter(Mandatory = $true)][int]$RetainedCount)
    if ($null -eq $script:Phase4BootstrapProcessQuarantine) { return }
    while ($script:Phase4BootstrapProcessQuarantine.Count -gt $RetainedCount) {
        $script:Phase4BootstrapProcessQuarantine.RemoveAt($script:Phase4BootstrapProcessQuarantine.Count - 1)
    }
}

function Add-PspktBootstrapProcessQuarantineFailure {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $quarantineProcessId = -1
    try { $quarantineProcessId = [int]$Process.Id }
    catch [System.InvalidOperationException] { $quarantineProcessId = -1 }
    if ($null -eq $script:Phase4BootstrapProcessQuarantine) {
        return [System.InvalidOperationException]::new(
            ('{0}: bootstrap-process quarantine authority is absent; a possibly-live OS child was dropped without proven termination.' -f $Label))
    }
    if ($script:Phase4BootstrapProcessQuarantine.Count -ge $script:Phase4BootstrapProcessQuarantineCapacity) {
        if ($null -eq $script:Phase4BootstrapProcessEmergencySlot) {
            $script:Phase4BootstrapProcessEmergencySlot = [pscustomobject]@{
                Label = $Label
                Process = $Process
                ProcessId = $quarantineProcessId
                RegisteredUtc = [datetime]::UtcNow
            }
            return [System.InvalidOperationException]::new(
                ('{0}: bootstrap-process quarantine primary reached its fixed capacity of {1}; the exact overflow child (pid {2}) was atomically retained in the non-droppable emergency ownership slot before this capacity error was surfaced, and every later bootstrap launch is now refused so no second overflow can occur (descendant containment is not claimed).' -f $Label, $script:Phase4BootstrapProcessQuarantineCapacity, $quarantineProcessId))
        }
        return [System.InvalidOperationException]::new(
            ('{0}: bootstrap-process quarantine primary is at its fixed capacity of {1} and the non-droppable emergency ownership slot is already occupied by pid {2}; the launch-admission guard should have refused starting another OS child, so this indicates a fatal admission-guard invariant violation for overflow child pid {3}.' -f $Label, $script:Phase4BootstrapProcessQuarantineCapacity, [int]$script:Phase4BootstrapProcessEmergencySlot.ProcessId, $quarantineProcessId))
    }
    $quarantineRecord = [pscustomobject]@{
        Label = $Label
        Process = $Process
        ProcessId = $quarantineProcessId
        RegisteredUtc = [datetime]::UtcNow
    }
    [void]$script:Phase4BootstrapProcessQuarantine.Add($quarantineRecord)
    return [System.InvalidOperationException]::new(
        ('{0}: bootstrap child (pid {1}) could not be proven terminated within the bounded cleanup budget; the exact Process wrapper was retained in the bootstrap-process quarantine for outer zero-gating (descendant containment is not claimed).' -f $Label, $quarantineProcessId))
}

function Test-PspktBootstrapProcessQuarantined {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    $emergency = $script:Phase4BootstrapProcessEmergencySlot
    if ($null -ne $emergency -and [object]::ReferenceEquals($emergency.Process, $Process)) { return $true }
    $registry = $script:Phase4BootstrapProcessQuarantine
    if ($null -eq $registry) { return $false }
    $count = $registry.Count
    for ($index = 0; $index -lt $count; $index++) {
        $record = $registry[$index]
        if ($null -eq $record) { continue }
        if ([object]::ReferenceEquals($record.Process, $Process)) { return $true }
    }
    return $false
}

function Test-PspktBootstrapProcessLaunchBlocked {
    return ($null -ne $script:Phase4BootstrapProcessEmergencySlot)
}

function Assert-PspktBootstrapProcessLaunchAdmitted {
    param([Parameter(Mandatory = $true)][string]$Label)
    $emergency = $script:Phase4BootstrapProcessEmergencySlot
    if ($null -ne $emergency) {
        throw ([System.InvalidOperationException]::new(
                ('{0}: bootstrap process launch admission is refused; the non-droppable emergency ownership slot already holds an un-terminated overflow child (pid {1}) that primary quarantine could not accept, so no further OS child may be started.' -f $Label, [int]$emergency.ProcessId)))
    }
}

function Reset-PspktBootstrapProcessEmergencySlotForProvenExit {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    $emergency = $script:Phase4BootstrapProcessEmergencySlot
    if ($null -eq $emergency) { return $false }
    if (-not [object]::ReferenceEquals($emergency.Process, $Process)) { return $false }
    if (-not (Test-PspktProcessProvenExited -Process $Process)) { return $false }
    $script:Phase4BootstrapProcessEmergencySlot = $null
    return $true
}

function Invoke-PspktBootstrapCallerProcessDisposal {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    $ownershipTransferred = $true
    try {
        $ownershipTransferred = [bool](Test-PspktBootstrapProcessQuarantined -Process $Process)
    }
    catch {
        $ownershipTransferred = $true
    }
    if ($ownershipTransferred) { return }
    $Process.Dispose()
}

function Complete-PspktPendingRead {
    param(
        [AllowNull()][System.Threading.Tasks.Task]$Task,
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowNull()]$Stream = $null,
        [AllowNull()][System.Diagnostics.Stopwatch]$CleanupStopwatch = $null,
        [int]$CleanupBudgetMs = -1
    )
    if ($null -eq $Task) { return }
    $waitBudget = Get-PspktRemainingCleanupBudgetMs -CleanupStopwatch $CleanupStopwatch -CleanupBudgetMs $CleanupBudgetMs
    $initialWaitBudget = $waitBudget
    if ($null -ne $Stream -and $waitBudget -gt 0) {
        $reservedCloseBudget = [Math]::Min(
            $script:PendingReadRecheckMs,
            [Math]::Max(1, [int]($waitBudget / 2)))
        $initialWaitBudget = $waitBudget - $reservedCloseBudget
    }
    try {
        [void]$Task.Wait($initialWaitBudget)
    }
    catch [System.AggregateException] {
        $null = $Task.Exception
    }
    if (-not $Task.IsCompleted -and $null -ne $Stream) {
        $Stream.Dispose()
        $remainingBudget = Get-PspktRemainingCleanupBudgetMs -CleanupStopwatch $CleanupStopwatch -CleanupBudgetMs $CleanupBudgetMs
        try {
            [void]$Task.Wait($remainingBudget)
        }
        catch [System.AggregateException] {
            $null = $Task.Exception
        }
    }
    if (-not $Task.IsCompleted) {
        throw ([System.InvalidOperationException]::new(
                ('{0}: pending redirected read did not reach terminal completion within the cleanup budget.' -f $Label)))
    }
    $null = $Task.Exception
}

function Invoke-PspktDrainedProcess {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$StdoutCap,
        [Parameter(Mandatory = $true)][int]$StderrCap,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$Label
    )
    return (Invoke-PspktDrainedStreams -Process $Process -StdoutStream $Process.StandardOutput.BaseStream -StderrStream $Process.StandardError.BaseStream -StdoutCap $StdoutCap -StderrCap $StderrCap -TimeoutMs $TimeoutMs -Label $Label)
}

function Invoke-PspktDrainedStreams {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][System.IO.Stream]$StdoutStream,
        [Parameter(Mandatory = $true)][System.IO.Stream]$StderrStream,
        [Parameter(Mandatory = $true)][int]$StdoutCap,
        [Parameter(Mandatory = $true)][int]$StderrCap,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $stdoutStream = $StdoutStream
    $stderrStream = $StderrStream
    $stdoutBuffer = [System.IO.MemoryStream]::new()
    $stderrBuffer = [System.IO.MemoryStream]::new()
    $stdoutChunk = [byte[]]::new(65536)
    $stderrChunk = [byte[]]::new(65536)
    $stdoutTask = $null
    $stderrTask = $null
    $stdoutDone = $false
    $stderrDone = $false
    $overflow = $false
    $failure = $null
    $primaryException = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $cleanupStopwatch = $null
    try {
        try {
        while (-not ($stdoutDone -and $stderrDone)) {
            if (-not $stdoutDone -and $null -eq $stdoutTask) {
                $allow = ($StdoutCap + 1) - [int]$stdoutBuffer.Length
                if ($allow -gt $stdoutChunk.Length) { $allow = $stdoutChunk.Length }
                if ($allow -le 0) { $allow = 1 }
                $stdoutTask = $stdoutStream.ReadAsync($stdoutChunk, 0, $allow)
            }
            if (-not $stderrDone -and $null -eq $stderrTask) {
                $allow = ($StderrCap + 1) - [int]$stderrBuffer.Length
                if ($allow -gt $stderrChunk.Length) { $allow = $stderrChunk.Length }
                if ($allow -le 0) { $allow = 1 }
                $stderrTask = $stderrStream.ReadAsync($stderrChunk, 0, $allow)
            }
            $pending = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
            if ($null -ne $stdoutTask) { [void]$pending.Add($stdoutTask) }
            if ($null -ne $stderrTask) { [void]$pending.Add($stderrTask) }
            if ($pending.Count -eq 0) { break }
            $remaining = $TimeoutMs - [int]$stopwatch.ElapsedMilliseconds
            if ($remaining -le 0) {
                $failure = ('{0} exceeded the {1} ms wait deadline.' -f $Label, $TimeoutMs)
                break
            }
            $signaled = [System.Threading.Tasks.Task]::WaitAny($pending.ToArray(), $remaining)
            if ($signaled -lt 0) {
                $failure = ('{0} exceeded the {1} ms wait deadline.' -f $Label, $TimeoutMs)
                break
            }
            if ($null -ne $stdoutTask -and $stdoutTask.IsCompleted) {
                $count = $stdoutTask.GetAwaiter().GetResult()
                $stdoutTask = $null
                if ($count -le 0) {
                    $stdoutDone = $true
                }
                else {
                    $stdoutBuffer.Write($stdoutChunk, 0, $count)
                    if ($stdoutBuffer.Length -gt $StdoutCap) { $overflow = $true; $stdoutDone = $true }
                }
            }
            if ($null -ne $stderrTask -and $stderrTask.IsCompleted) {
                $count = $stderrTask.GetAwaiter().GetResult()
                $stderrTask = $null
                if ($count -le 0) {
                    $stderrDone = $true
                }
                else {
                    $stderrBuffer.Write($stderrChunk, 0, $count)
                    if ($stderrBuffer.Length -gt $StderrCap) { $overflow = $true; $stderrDone = $true }
                }
            }
            if ($overflow) {
                $failure = ('{0} exceeded the redirected-output cap.' -f $Label)
                break
            }
        }

        if ($null -eq $failure) {
            $remainingExitMs = $TimeoutMs - [int]$stopwatch.ElapsedMilliseconds
            if ($remainingExitMs -lt 0) { $remainingExitMs = 0 }
            if (($remainingExitMs -le 0) -or (-not $Process.WaitForExit($remainingExitMs))) {
                $failure = ('{0} exceeded the {1} ms wait deadline.' -f $Label, $TimeoutMs)
            }
        }
        if ($null -ne $failure) {
            $primaryException = [System.InvalidOperationException]::new([string]$failure)
        }
        }
        catch {
            $primaryException = Get-PspktInnermostException -Exception $_.Exception
        }

        if ($null -eq $cleanupStopwatch) { $cleanupStopwatch = [System.Diagnostics.Stopwatch]::StartNew() }

        $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()

        if (-not (Test-PspktProcessProvenExited -Process $Process)) {
            try {
                Stop-PspktProcessBounded -Process $Process -Label $Label -CleanupStopwatch $cleanupStopwatch -CleanupBudgetMs $script:ProcessExitWaitMs
            }
            catch {
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
            if (-not (Test-PspktProcessProvenExited -Process $Process)) {
                [void]$cleanupFailures.Add((Add-PspktBootstrapProcessQuarantineFailure -Process $Process -Label $Label))
            }
        }

        try {
            Complete-PspktPendingRead -Task $stdoutTask -Label ('{0} stdout' -f $Label) -Stream $stdoutStream -CleanupStopwatch $cleanupStopwatch -CleanupBudgetMs $script:ProcessExitWaitMs
            $stdoutTask = $null
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        try {
            Complete-PspktPendingRead -Task $stderrTask -Label ('{0} stderr' -f $Label) -Stream $stderrStream -CleanupStopwatch $cleanupStopwatch -CleanupBudgetMs $script:ProcessExitWaitMs
            $stderrTask = $null
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }

        $composed = New-PspktComposedFailure -Message ('{0}: redirected drain composed failure.' -f $Label) -PrimaryFailure $primaryException -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
        if ($null -ne $composed) {
            throw $composed
        }

        [void]$Process.WaitForExit()
        return [pscustomobject]@{
            StdoutBytes = $stdoutBuffer.ToArray()
            StderrBytes = $stderrBuffer.ToArray()
            ExitCode = $Process.ExitCode
        }
    }
    finally {
        $stdoutBuffer.Dispose()
        $stderrBuffer.Dispose()
    }
}

function Test-PspktDrainedProcessEarlyPipeClosureVector {
    $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-earlypipe-'
    $ok = $false
    $process = $null
    try {
        $childLines = [System.Collections.Generic.List[string]]::new()
        [void]$childLines.Add('$ErrorActionPreference = ''Stop''')
        [void]$childLines.Add('$pspktEarlyPipeSig = ''using System;using System.Runtime.InteropServices;public static class PspktEarlyPipeClose{[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr GetStdHandle(int nStdHandle);[DllImport("kernel32.dll",SetLastError=true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool CloseHandle(IntPtr hObject);}''')
        [void]$childLines.Add('Add-Type -TypeDefinition $pspktEarlyPipeSig')
        [void]$childLines.Add('[void][PspktEarlyPipeClose]::CloseHandle([PspktEarlyPipeClose]::GetStdHandle(-11))')
        [void]$childLines.Add('[void][PspktEarlyPipeClose]::CloseHandle([PspktEarlyPipeClose]::GetStdHandle(-12))')
        [void]$childLines.Add('Start-Sleep -Seconds 30')
        $childScriptPath = Join-Path $root ('earlypipe-child-' + [Guid]::NewGuid().ToString('N') + '.ps1')
        $childBytes = (New-PspktUtf8NoBom).GetBytes(($childLines -join "`r`n") + "`r`n")
        $childStream = [System.IO.FileStream]::new($childScriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $childStream.Write($childBytes, 0, $childBytes.Length)
            $childStream.Flush($true)
        }
        finally {
            $childStream.Dispose()
        }

        $hostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $hostExe
        $startInfo.Arguments = Join-PspktArgv -Argv @('-NoProfile', '-NonInteractive', '-File', $childScriptPath)
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.WorkingDirectory = $root
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        Assert-PspktBootstrapProcessLaunchAdmitted -Label 'early-pipe-closure child'
        [void]$process.Start()

        $timeoutMs = 4000
        $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
        $threwTimeout = $false
        try {
            [void](Invoke-PspktDrainedProcess -Process $process -StdoutCap 65536 -StderrCap 65536 -TimeoutMs $timeoutMs -Label 'early-pipe-closure timeout probe')
        }
        catch {
            if ([string](Get-PspktInnermostException -Exception $_.Exception).Message -match 'exceeded') { $threwTimeout = $true }
        }
        $elapsed.Stop()
        $noSurvivor = $process.HasExited
        $ok = ($threwTimeout -and $noSurvivor -and ([int]$elapsed.ElapsedMilliseconds -lt 12000))
    }
    finally {
        if ($null -ne $process) {
            if (-not $process.HasExited) {
                try {
                    $process.Kill()
                    [void]$process.WaitForExit(5000)
                }
                catch {
                    $null = $_
                }
            }
            Invoke-PspktBootstrapCallerProcessDisposal -Process $process
        }
        $rootFailure = Remove-PspktStrictVectorRoot -Root $root -Label 'early-pipe-closure root'
        if ($null -ne $rootFailure) { $ok = $false }
    }
    return $ok
}

function Test-PspktRedirectedCleanupBudgetVector {
    $budgetMs = 500

    $neverSource = [System.Threading.Tasks.TaskCompletionSource[int]]::new()
    $neverStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $neverThrew = $false
    try {
        Complete-PspktPendingRead -Task $neverSource.Task -Label 'never-completing pending read' -Stream $null -CleanupStopwatch $neverStopwatch -CleanupBudgetMs $budgetMs
    }
    catch {
        $neverThrew = $true
    }
    finally {
        $neverSource.SetResult(0)
    }
    $neverElapsedMs = [int]$neverStopwatch.ElapsedMilliseconds

    $realSource = [System.Threading.Tasks.TaskCompletionSource[int]]::new()
    $realOwner = [pscustomobject]@{ Source = $realSource }
    $realOwner | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        [void]$this.Source.TrySetResult(0)
    }
    $realStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $realThrew = $false
    try {
        Complete-PspktPendingRead -Task $realSource.Task -Label 'real pending read' -Stream $realOwner -CleanupStopwatch $realStopwatch -CleanupBudgetMs $budgetMs
    }
    catch {
        $realThrew = $true
    }
    finally {
        [void]$realSource.TrySetResult(0)
    }
    $realTerminated = $realSource.Task.IsCompleted

    $sharedSourceOne = [System.Threading.Tasks.TaskCompletionSource[int]]::new()
    $sharedSourceTwo = [System.Threading.Tasks.TaskCompletionSource[int]]::new()
    $sharedSourceOne.SetResult(0)
    $sharedSourceTwo.SetResult(0)
    $sharedStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $sharedThrew = $false
    try {
        Complete-PspktPendingRead -Task $sharedSourceOne.Task -Label 'shared budget one' -CleanupStopwatch $sharedStopwatch -CleanupBudgetMs $budgetMs
        Complete-PspktPendingRead -Task $sharedSourceTwo.Task -Label 'shared budget two' -CleanupStopwatch $sharedStopwatch -CleanupBudgetMs $budgetMs
    }
    catch {
        $sharedThrew = $true
    }
    $sharedElapsedMs = [int]$sharedStopwatch.ElapsedMilliseconds

    return (
        $neverThrew -and
        ($neverElapsedMs -ge ($budgetMs - 250)) -and
        ($neverElapsedMs -lt ([int]($budgetMs * 3 / 2) + $script:PendingReadRecheckMs)) -and
        $realTerminated -and
        (-not $realThrew) -and
        (-not $sharedThrew) -and
        ($sharedElapsedMs -lt $budgetMs))
}

function Initialize-PspktInjectingStreamType {
    if ($null -ne ('PspktPhase4.InjectingReadStream' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PspktPhase4
{
    public sealed class InjectingReadStream : Stream
    {
        public const int ModeEof = 0;
        public const int ModeThrowOnSetup = 1;
        public const int ModeFaultedTask = 2;
        public const int ModeNeverCompletes = 3;

        private readonly int mode;
        private readonly string marker;
        private int disposeCount;

        public InjectingReadStream(int mode, string marker)
        {
            this.mode = mode;
            this.marker = marker;
        }

        public int DisposeCount { get { return disposeCount; } }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (mode == ModeThrowOnSetup)
            {
                throw new IOException("injected synchronous read failure: " + marker);
            }
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (mode == ModeThrowOnSetup)
            {
                throw new IOException("injected ReadAsync setup failure: " + marker);
            }
            if (mode == ModeFaultedTask)
            {
                TaskCompletionSource<int> faulted = new TaskCompletionSource<int>();
                faulted.SetException(new IOException("injected faulted ReadAsync result: " + marker));
                return faulted.Task;
            }
            if (mode == ModeNeverCompletes)
            {
                return new TaskCompletionSource<int>().Task;
            }
            TaskCompletionSource<int> eof = new TaskCompletionSource<int>();
            eof.SetResult(0);
            return eof.Task;
        }

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref disposeCount);
            base.Dispose(disposing);
        }
    }
}
'@
}

function Get-PspktExceptionTreeLeaves {
    param([Parameter(Mandatory = $true)][Exception]$Exception)
    $leaves = [System.Collections.Generic.List[Exception]]::new()
    $stack = [System.Collections.Generic.Stack[Exception]]::new()
    $stack.Push($Exception)
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        if ($null -eq $current) { continue }
        if ($current -is [System.AggregateException]) {
            foreach ($inner in ([System.AggregateException]$current).InnerExceptions) {
                if ($null -ne $inner) { $stack.Push($inner) }
            }
            continue
        }
        [void]$leaves.Add($current)
        if ($null -ne $current.InnerException) { $stack.Push($current.InnerException) }
    }
    return , ([Exception[]]$leaves.ToArray())
}

function Get-PspktFirstAggregateException {
    param([AllowNull()][Exception]$Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.AggregateException]) { return $current }
        $current = $current.InnerException
    }
    return $null
}

function Start-PspktInjectionSleepChild {
    $hostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $hostExe
    $startInfo.Arguments = Join-PspktArgv -Argv @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $child = [System.Diagnostics.Process]::new()
    $child.StartInfo = $startInfo
    Assert-PspktBootstrapProcessLaunchAdmitted -Label 'injection-sleep child'
    [void]$child.Start()
    return $child
}

function Test-PspktDrainedProcessInjectedFailureVectors {
    Initialize-PspktInjectingStreamType
    $savedExitWaitMs = $script:ProcessExitWaitMs
    $bootstrapBaseline = Get-PspktBootstrapProcessQuarantineCount
    $overallOk = $true
    try {
        $script:ProcessExitWaitMs = 1500
        $cases = @(
            [pscustomobject]@{ Name = 'readasync-setup'; StdoutMode = [PspktPhase4.InjectingReadStream]::ModeThrowOnSetup; StderrMode = [PspktPhase4.InjectingReadStream]::ModeEof; TimeoutMs = 4000; PrimaryPattern = 'injected ReadAsync setup failure'; ExpectSibling = $false },
            [pscustomobject]@{ Name = 'getresult-fault'; StdoutMode = [PspktPhase4.InjectingReadStream]::ModeFaultedTask; StderrMode = [PspktPhase4.InjectingReadStream]::ModeNeverCompletes; TimeoutMs = 4000; PrimaryPattern = 'injected faulted ReadAsync result'; ExpectSibling = $true },
            [pscustomobject]@{ Name = 'waitany-deadline'; StdoutMode = [PspktPhase4.InjectingReadStream]::ModeNeverCompletes; StderrMode = [PspktPhase4.InjectingReadStream]::ModeEof; TimeoutMs = 300; PrimaryPattern = 'exceeded the'; ExpectSibling = $true }
        )
        foreach ($case in $cases) {
            $child = $null
            $stdoutStream = $null
            $stderrStream = $null
            $caseOk = $false
            try {
                $child = Start-PspktInjectionSleepChild
                $stdoutStream = [PspktPhase4.InjectingReadStream]::new([int]$case.StdoutMode, ('stdout-' + $case.Name))
                $stderrStream = [PspktPhase4.InjectingReadStream]::new([int]$case.StderrMode, ('stderr-' + $case.Name))
                $thrown = $null
                try {
                    [void](Invoke-PspktDrainedStreams -Process $child -StdoutStream $stdoutStream -StderrStream $stderrStream -StdoutCap 65536 -StderrCap 65536 -TimeoutMs ([int]$case.TimeoutMs) -Label ('injected-failure ' + $case.Name))
                }
                catch {
                    $thrown = $_.Exception
                }
                $noSurvivor = Test-PspktProcessProvenExited -Process $child
                $primaryPresent = $false
                $siblingAggregated = $false
                if ($null -ne $thrown) {
                    foreach ($leaf in (Get-PspktExceptionTreeLeaves -Exception $thrown)) {
                        if ([string]$leaf.Message -match [regex]::Escape([string]$case.PrimaryPattern)) { $primaryPresent = $true }
                    }
                    $aggregate = Get-PspktFirstAggregateException -Exception $thrown
                    if ($null -ne $aggregate -and $aggregate.InnerExceptions.Count -ge 2) {
                        foreach ($aggLeaf in $aggregate.InnerExceptions) {
                            if ([string]$aggLeaf.Message -match 'did not reach terminal completion') { $siblingAggregated = $true }
                        }
                    }
                }
                $caseSiblingOk = $true
                if ([bool]$case.ExpectSibling) { $caseSiblingOk = $siblingAggregated }
                $caseOk = (
                    ($null -ne $thrown) -and
                    $noSurvivor -and
                    $primaryPresent -and
                    $caseSiblingOk -and
                    ((Get-PspktBootstrapProcessQuarantineCount) -eq $bootstrapBaseline))
            }
            finally {
                if ($null -ne $child) {
                    if (-not (Test-PspktProcessProvenExited -Process $child)) {
                        try { $child.Kill(); [void]$child.WaitForExit(5000) } catch { $null = $_ }
                    }
                    Invoke-PspktBootstrapCallerProcessDisposal -Process $child
                }
                if ($null -ne $stdoutStream) { try { $stdoutStream.Dispose() } catch { $null = $_ } }
                if ($null -ne $stderrStream) { try { $stderrStream.Dispose() } catch { $null = $_ } }
            }
            if (-not $caseOk) { $overallOk = $false }
        }
    }
    finally {
        $script:ProcessExitWaitMs = $savedExitWaitMs
        Reset-PspktBootstrapProcessQuarantineTo -RetainedCount $bootstrapBaseline
    }
    return $overallOk
}

function Test-PspktBootstrapProcessQuarantineVectors {
    $bootstrapBaseline = Get-PspktBootstrapProcessQuarantineCount
    $registerOk = $false
    $retainOk = $false
    $ownershipOk = $false
    $callerSkipsDisposeOk = $false
    $usableOk = $false
    $emergencyOverflowOk = $false
    $emergencyUsableOk = $false
    $emergencyOwnershipOk = $false
    $emergencyCallerSkipsDisposeOk = $false
    $admissionRejectedOk = $false
    $genuineOverflowNotClearedOk = $false
    $emergencyClearedAfterExitOk = $false
    $disposableAfterRemovalOk = $false
    $child = $null
    $emergencyChild = $null
    try {
        if ($null -ne $script:Phase4BootstrapProcessEmergencySlot) { return $false }

        $child = Start-PspktInjectionSleepChild
        try {
            $child.Kill()
            [void]$child.WaitForExit(5000)
        }
        catch {
            $null = $_
        }
        $countBefore = Get-PspktBootstrapProcessQuarantineCount
        $childId = [int]$child.Id
        $surfaced = Add-PspktBootstrapProcessQuarantineFailure -Process $child -Label 'bootstrap-quarantine unit'
        $registerOk = (
            ((Get-PspktBootstrapProcessQuarantineCount) -eq ($countBefore + 1)) -and
            ($surfaced -is [System.InvalidOperationException]) -and
            ([string]$surfaced.Message -match 'could not be proven terminated') -and
            ([string]$surfaced.Message -match ('pid ' + [regex]::Escape($childId.ToString([System.Globalization.CultureInfo]::InvariantCulture)))))
        $record = $script:Phase4BootstrapProcessQuarantine[$countBefore]
        $retainOk = (
            ($null -ne $record) -and
            [object]::ReferenceEquals($record.Process, $child) -and
            ($record.ProcessId -eq $childId))

        $ownershipOk = (Test-PspktBootstrapProcessQuarantined -Process $child)

        $preCallerCount = Get-PspktBootstrapProcessQuarantineCount
        Invoke-PspktBootstrapCallerProcessDisposal -Process $child
        $callerSkipsDisposeOk = (
            ((Get-PspktBootstrapProcessQuarantineCount) -eq $preCallerCount) -and
            (Test-PspktBootstrapProcessQuarantined -Process $child) -and
            [object]::ReferenceEquals($script:Phase4BootstrapProcessQuarantine[$countBefore].Process, $child))

        try {
            $retainedHasExited = [bool]$child.HasExited
            [void]$child.WaitForExit(0)
            $retainedHandle = $child.Handle
            $usableOk = ($retainedHasExited -and ($retainedHandle -ne [System.IntPtr]::Zero))
        }
        catch {
            $usableOk = $false
        }

        while ($script:Phase4BootstrapProcessQuarantine.Count -lt $script:Phase4BootstrapProcessQuarantineCapacity) {
            [void]$script:Phase4BootstrapProcessQuarantine.Add([pscustomobject]@{ Label = 'capacity-filler'; Process = $null; ProcessId = -1; RegisteredUtc = [datetime]::UtcNow })
        }

        $emergencyChild = Start-PspktInjectionSleepChild
        $emergencyChildId = [int]$emergencyChild.Id
        $emergencyChildLiveBefore = -not (Test-PspktProcessProvenExited -Process $emergencyChild)
        $overflow = Add-PspktBootstrapProcessQuarantineFailure -Process $emergencyChild -Label 'bootstrap-quarantine overflow'
        $emergencyOverflowOk = (
            $emergencyChildLiveBefore -and
            ($overflow -is [System.InvalidOperationException]) -and
            ([string]$overflow.Message -match 'emergency ownership slot') -and
            ([string]$overflow.Message -match 'every later bootstrap launch is now refused') -and
            ($script:Phase4BootstrapProcessQuarantine.Count -eq $script:Phase4BootstrapProcessQuarantineCapacity) -and
            ($null -ne $script:Phase4BootstrapProcessEmergencySlot) -and
            [object]::ReferenceEquals($script:Phase4BootstrapProcessEmergencySlot.Process, $emergencyChild) -and
            ($script:Phase4BootstrapProcessEmergencySlot.ProcessId -eq $emergencyChildId))

        try {
            $emergencyHandle = $emergencyChild.Handle
            $emergencyIdReadable = [int]$emergencyChild.Id
            $emergencyUsableOk = (
                ($null -ne $script:Phase4BootstrapProcessEmergencySlot) -and
                [object]::ReferenceEquals($script:Phase4BootstrapProcessEmergencySlot.Process, $emergencyChild) -and
                ($emergencyHandle -ne [System.IntPtr]::Zero) -and
                ($emergencyIdReadable -eq $emergencyChildId))
        }
        catch {
            $emergencyUsableOk = $false
        }

        $emergencyOwnershipOk = (Test-PspktBootstrapProcessQuarantined -Process $emergencyChild)

        Invoke-PspktBootstrapCallerProcessDisposal -Process $emergencyChild
        try {
            $emergencyIdStillReadable = [int]$emergencyChild.Id
            $emergencyCallerSkipsDisposeOk = (
                ($null -ne $script:Phase4BootstrapProcessEmergencySlot) -and
                (Test-PspktBootstrapProcessQuarantined -Process $emergencyChild) -and
                [object]::ReferenceEquals($script:Phase4BootstrapProcessEmergencySlot.Process, $emergencyChild) -and
                ($emergencyIdStillReadable -eq $emergencyChildId))
        }
        catch {
            $emergencyCallerSkipsDisposeOk = $false
        }

        $admissionChild = $null
        $admissionThrown = $null
        try {
            $admissionChild = Start-PspktInjectionSleepChild
        }
        catch {
            $admissionThrown = $_.Exception
        }
        $admissionRejectedOk = (
            ($null -eq $admissionChild) -and
            ($null -ne $admissionThrown) -and
            ([string](Get-PspktInnermostException -Exception $admissionThrown).Message -match 'launch admission is refused'))
        if ($null -ne $admissionChild) {
            if (-not (Test-PspktProcessProvenExited -Process $admissionChild)) {
                try { $admissionChild.Kill(); [void]$admissionChild.WaitForExit(5000) } catch { $null = $_ }
            }
            Invoke-PspktBootstrapCallerProcessDisposal -Process $admissionChild
        }

        Reset-PspktBootstrapProcessQuarantineTo -RetainedCount $bootstrapBaseline
        $prematureClear = Reset-PspktBootstrapProcessEmergencySlotForProvenExit -Process $emergencyChild
        $genuineOverflowNotClearedOk = (
            (-not $prematureClear) -and
            ($null -ne $script:Phase4BootstrapProcessEmergencySlot) -and
            [object]::ReferenceEquals($script:Phase4BootstrapProcessEmergencySlot.Process, $emergencyChild))

        try { $emergencyChild.Kill(); [void]$emergencyChild.WaitForExit(5000) } catch { $null = $_ }
        $emergencyProvenExited = Test-PspktProcessProvenExited -Process $emergencyChild
        $clearedAfterExit = $false
        if ($emergencyProvenExited) {
            $clearedAfterExit = Reset-PspktBootstrapProcessEmergencySlotForProvenExit -Process $emergencyChild
        }
        $emergencyClearedAfterExitOk = (
            $emergencyProvenExited -and
            $clearedAfterExit -and
            ($null -eq $script:Phase4BootstrapProcessEmergencySlot) -and
            (-not (Test-PspktBootstrapProcessQuarantined -Process $emergencyChild)))
        if ($emergencyClearedAfterExitOk) {
            $emergencyChild.Dispose()
            $emergencyChild = $null
        }

        $noLongerQuarantined = -not (Test-PspktBootstrapProcessQuarantined -Process $child)
        $provenExited = Test-PspktProcessProvenExited -Process $child
        if ($noLongerQuarantined -and $provenExited) {
            $child.Dispose()
            $child = $null
            $disposableAfterRemovalOk = $true
        }
    }
    finally {
        Reset-PspktBootstrapProcessQuarantineTo -RetainedCount $bootstrapBaseline
        if ($null -ne $emergencyChild) {
            if (-not (Test-PspktProcessProvenExited -Process $emergencyChild)) {
                try { $emergencyChild.Kill(); [void]$emergencyChild.WaitForExit(5000) } catch { $null = $_ }
            }
            [void](Reset-PspktBootstrapProcessEmergencySlotForProvenExit -Process $emergencyChild)
            Invoke-PspktBootstrapCallerProcessDisposal -Process $emergencyChild
        }
        $leakedEmergency = $script:Phase4BootstrapProcessEmergencySlot
        if ($null -ne $leakedEmergency -and $null -ne $leakedEmergency.Process) {
            if (-not (Test-PspktProcessProvenExited -Process $leakedEmergency.Process)) {
                try { $leakedEmergency.Process.Kill(); [void]$leakedEmergency.Process.WaitForExit(5000) } catch { $null = $_ }
            }
            [void](Reset-PspktBootstrapProcessEmergencySlotForProvenExit -Process $leakedEmergency.Process)
        }
        if ($null -ne $child) {
            if (-not (Test-PspktProcessProvenExited -Process $child)) {
                try { $child.Kill(); [void]$child.WaitForExit(5000) } catch { $null = $_ }
            }
            Invoke-PspktBootstrapCallerProcessDisposal -Process $child
        }
    }
    return (
        $registerOk -and $retainOk -and $ownershipOk -and $callerSkipsDisposeOk -and $usableOk -and
        $emergencyOverflowOk -and $emergencyUsableOk -and $emergencyOwnershipOk -and $emergencyCallerSkipsDisposeOk -and
        $admissionRejectedOk -and $genuineOverflowNotClearedOk -and $emergencyClearedAfterExitOk -and $disposableAfterRemovalOk)
}

function Test-PspktNoFinalizerWaitFossilVector {
    $sourceScanOk = $false
    try {
        $scanTokens = $null
        $scanErrors = $null
        $scanAst = [System.Management.Automation.Language.Parser]::ParseFile($script:Phase4ValidatorSourcePath, [ref]$scanTokens, [ref]$scanErrors)
        if ($scanErrors.Count -eq 0) {
            $forbiddenInvocations = $scanAst.FindAll(
                {
                    param($node)
                    ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
                    ($node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
                    ($node.Member.Value -ceq ('WaitForPending' + 'Finalizers'))
                },
                $true)
            $sourceScanOk = ($forbiddenInvocations.Count -eq 0)
        }
    }
    catch [System.IO.IOException] { $sourceScanOk = $false }
    catch [System.UnauthorizedAccessException] { $sourceScanOk = $false }
    catch [System.Management.Automation.ParseException] { $sourceScanOk = $false }

    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $rootingDeterministicOk = $true
    try {
        for ($iteration = 0; $iteration -lt 3; $iteration++) {
            $probe = & {
                $context = [pscustomobject]@{
                    OwnedEvents = [System.Collections.Generic.List[object]]::new()
                    TempDirs = [string[]]@()
                    CleanupState = 'Quarantined'
                }
                $heldStream = [System.IO.MemoryStream]::new()
                [void]$context.OwnedEvents.Add($heldStream)
                $session = [pscustomobject]@{ Marker = 'finalizer-fossil-session' }
                $launch = [pscustomobject]@{ Session = $session; Context = $context }
                $snapshotObject = [pscustomobject]@{ Marker = 'finalizer-fossil-snapshot' }
                $index = Get-PspktQuarantineRegistrationCount
                [void](Add-PspktQuarantineRegistration -Kind 'FinalizerFossilProbe' -Launch $launch -Snapshots ([object[]]@($snapshotObject)))
                [pscustomobject]@{
                    RegistrationIndex = $index
                    WeakLaunch = [System.WeakReference]::new($launch)
                    WeakContext = [System.WeakReference]::new($context)
                    WeakSession = [System.WeakReference]::new($session)
                    WeakStream = [System.WeakReference]::new($heldStream)
                    WeakSnapshot = [System.WeakReference]::new($snapshotObject)
                }
            }
            [System.GC]::Collect()
            $record = $script:Phase4QuarantineRegistry[$probe.RegistrationIndex]
            $iterationOk = (
                $probe.WeakLaunch.IsAlive -and
                $probe.WeakContext.IsAlive -and
                $probe.WeakSession.IsAlive -and
                $probe.WeakStream.IsAlive -and
                $probe.WeakSnapshot.IsAlive -and
                [object]::ReferenceEquals($record.Launch, $probe.WeakLaunch.Target) -and
                [object]::ReferenceEquals($record.Context, $probe.WeakContext.Target) -and
                [object]::ReferenceEquals($record.Launch.Session, $probe.WeakSession.Target) -and
                [object]::ReferenceEquals($record.Context.OwnedEvents[0], $probe.WeakStream.Target) -and
                [object]::ReferenceEquals($record.Snapshots[0], $probe.WeakSnapshot.Target))
            if (-not $iterationOk) { $rootingDeterministicOk = $false }
        }
    }
    finally {
        for ($recordIndex = $registryBaseline; $recordIndex -lt $script:Phase4QuarantineRegistry.Count; $recordIndex++) {
            $sweepRecord = $script:Phase4QuarantineRegistry[$recordIndex]
            if ($null -ne $sweepRecord.Context) {
                foreach ($ownedAuthority in $sweepRecord.Context.OwnedEvents) {
                    if ($ownedAuthority -is [System.IDisposable]) {
                        try { $ownedAuthority.Dispose() } catch { $null = $_ }
                    }
                }
            }
        }
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
    }
    return ($sourceScanOk -and $rootingDeterministicOk)
}

function Test-PspktDrainedProcessHardeningVectors {
    return (
        (Test-PspktDrainedProcessInjectedFailureVectors) -and
        (Test-PspktBootstrapProcessQuarantineVectors) -and
        (Test-PspktNoFinalizerWaitFossilVector))
}

function Invoke-PspktBoundedComSpecCommand {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$TimeoutMs = 0,
        [int]$StdoutCap = 65536,
        [int]$StderrCap = 65536
    )
    if ($TimeoutMs -le 0) { $TimeoutMs = $script:ProcessExitWaitMs }
    $comSpec = [System.Environment]::GetEnvironmentVariable('ComSpec')
    if ([string]::IsNullOrEmpty($comSpec)) {
        throw ('{0}: ComSpec authority is unavailable.' -f $Label)
    }
    $comSpecInfo = [System.IO.FileInfo]::new($comSpec)
    if (-not $comSpecInfo.Exists) {
        throw ('{0}: ComSpec "{1}" is absent.' -f $Label, $comSpec)
    }
    if (($comSpecInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw ('{0}: ComSpec "{1}" is a reparse point.' -f $Label, $comSpec)
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $comSpec
    $startInfo.Arguments = '/c ' + $CommandLine
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $captured = $null
    try {
        Assert-PspktBootstrapProcessLaunchAdmitted -Label $Label
        [void]$process.Start()
        $captured = Invoke-PspktDrainedProcess -Process $process -StdoutCap $StdoutCap -StderrCap $StderrCap -TimeoutMs $TimeoutMs -Label $Label
    }
    finally {
        Invoke-PspktBootstrapCallerProcessDisposal -Process $process
    }
    return [pscustomobject]@{
        ExitCode = [int]$captured.ExitCode
        StdoutBytes = $captured.StdoutBytes
        StderrBytes = $captured.StderrBytes
    }
}

function Set-PspktGitProcessEnvironment {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.ProcessStartInfo]$StartInfo,
        [Parameter(Mandatory = $true)][string]$ConfigRoot
    )
    $removeNames = @()
    foreach ($envEntry in $StartInfo.EnvironmentVariables.Keys) {
        $envName = [string]$envEntry
        if ($envName.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $envName.StartsWith('GIT_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $envName -ceq 'HOME' -or $envName -ceq 'USERPROFILE' -or $envName -ceq 'XDG_CONFIG_HOME') {
            $removeNames += $envName
        }
    }
    foreach ($removeName in $removeNames) {
        [void]$StartInfo.EnvironmentVariables.Remove($removeName)
    }
    $StartInfo.EnvironmentVariables['HOME'] = $ConfigRoot
    $StartInfo.EnvironmentVariables['USERPROFILE'] = $ConfigRoot
    $StartInfo.EnvironmentVariables['XDG_CONFIG_HOME'] = $ConfigRoot
    $StartInfo.EnvironmentVariables['GIT_NO_REPLACE_OBJECTS'] = '1'
    $StartInfo.EnvironmentVariables['GIT_CONFIG_NOSYSTEM'] = '1'
    $StartInfo.EnvironmentVariables['GIT_CONFIG_GLOBAL'] = 'NUL'
    $StartInfo.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
}

function Assert-PspktGitBindingIdentity {
    param([Parameter(Mandatory = $true)]$GitBinding)
    if ($null -eq $GitBinding -or $null -eq $GitBinding.Stream) {
        throw 'git authority: executable binding is not established.'
    }
    $info = [System.IO.FileInfo]::new($GitBinding.Path)
    if (-not $info.Exists) {
        throw ('git authority: "{0}" is no longer present.' -f $GitBinding.Path)
    }
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw ('git authority: "{0}" became a reparse point.' -f $GitBinding.Path)
    }
    if (-not $info.FullName.StartsWith($GitBinding.Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('git authority: "{0}" moved outside the trusted Git root.' -f $info.FullName)
    }
    if ($GitBinding.Stream.Length -ne $GitBinding.Length) {
        throw ('git authority: "{0}" length drifted.' -f $GitBinding.Path)
    }
    if ($info.CreationTimeUtc -ne $GitBinding.CreationTimeUtc) {
        throw ('git authority: "{0}" creation time drifted.' -f $GitBinding.Path)
    }
    $digest = Get-PspktStreamSha256Hex -Stream $GitBinding.Stream
    if ($digest -cne $GitBinding.Sha256) {
        throw ('git authority: "{0}" content drifted.' -f $GitBinding.Path)
    }
}

function Close-PspktGitBinding {
    param([AllowNull()]$GitBinding)
    if ($null -ne $GitBinding -and $null -ne $GitBinding.Stream) {
        $GitBinding.Stream.Dispose()
    }
}

function Resolve-PspktGitExecutable {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrEmpty($programFiles)) {
        throw 'git authority: ProgramFiles folder is unavailable.'
    }
    $gitRoot = Join-Path $programFiles 'Git'
    $candidateCmd = Join-Path $gitRoot 'cmd\git.exe'
    $candidateBin = Join-Path $gitRoot 'bin\git.exe'
    $selected = $null
    if (Test-Path -LiteralPath $candidateCmd -PathType Leaf) {
        $selected = $candidateCmd
    }
    elseif (Test-Path -LiteralPath $candidateBin -PathType Leaf) {
        $selected = $candidateBin
    }
    if ($null -eq $selected) {
        throw 'git authority: no canonical Git executable under ProgramFiles\Git.'
    }
    $info = [System.IO.FileInfo]::new($selected)
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw ('git authority: "{0}" is a reparse point.' -f $selected)
    }
    $fullGitRoot = (Resolve-Path -LiteralPath $gitRoot).ProviderPath
    $fullSelected = (Resolve-Path -LiteralPath $selected).ProviderPath
    if (-not $fullSelected.StartsWith($fullGitRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('git authority: "{0}" is outside the trusted Git root.' -f $fullSelected)
    }
    $stream = [System.IO.File]::Open($fullSelected, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $bound = $false
    try {
        $length = $stream.Length
        if ($length -le 0) {
            throw ('git authority: "{0}" is empty.' -f $fullSelected)
        }
        $digest = Get-PspktStreamSha256Hex -Stream $stream
        $binding = [pscustomobject]@{
            Path = $fullSelected
            Root = $fullGitRoot
            Stream = $stream
            Length = $length
            Sha256 = $digest
            CreationTimeUtc = $info.CreationTimeUtc
        }
        $bound = $true
        return $binding
    }
    finally {
        if (-not $bound) { $stream.Dispose() }
    }
}

function New-PspktGitConfigRoot {
    return New-PspktTempDirectory -Prefix 'pspkt-phase4-gitcfg-'
}

function Invoke-PspktCheckedGit {
    param(
        [Parameter(Mandatory = $true)]$GitAuthority,
        [Parameter(Mandatory = $true)][string]$ConfigRoot,
        [Parameter(Mandatory = $true)][string[]]$GitArgs
    )
    Assert-PspktGitAuthorityUnchanged -Authority $GitAuthority
    $gitBinding = $GitAuthority.GitBinding
    $repoRoot = [string]$GitAuthority.RepositoryRoot
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $gitBinding.Path
    $fixedPrefix = @('-C', $repoRoot, '--no-replace-objects', '-c', 'core.hooksPath=NUL')
    $allArgs = @($fixedPrefix + $GitArgs)
    $startInfo.Arguments = Join-PspktArgv -Argv $allArgs
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $repoRoot
    Set-PspktGitProcessEnvironment -StartInfo $startInfo -ConfigRoot $ConfigRoot

    $label = ('git "{0}"' -f ($GitArgs -join ' '))
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $captured = $null
    try {
        Assert-PspktBootstrapProcessLaunchAdmitted -Label $label
        [void]$process.Start()
        $captured = Invoke-PspktDrainedProcess -Process $process -StdoutCap $script:GitStdoutCap -StderrCap $script:GitStdoutCap -TimeoutMs $script:GitWaitMs -Label $label
    }
    finally {
        Invoke-PspktBootstrapCallerProcessDisposal -Process $process
    }
    $stderr = [System.Text.Encoding]::UTF8.GetString($captured.StderrBytes)
    if ($captured.ExitCode -ne 0) {
        throw ('{0} exited {1}: {2}' -f $label, $captured.ExitCode, $stderr)
    }
    $stdout = [System.Text.Encoding]::UTF8.GetString($captured.StdoutBytes)
    Assert-PspktGitAuthorityUnchanged -Authority $GitAuthority
    return [pscustomobject]@{ StdOut = $stdout; StdErr = $stderr; ExitCode = $captured.ExitCode }
}

function Get-PspktGitSingleOid {
    param([Parameter(Mandatory = $true)]$Result)
    $trimmed = ($Result.StdOut -replace "`r", '').Trim()
    if (-not (Test-PspktLowercaseHexOid -Value $trimmed)) {
        throw ('git output "{0}" is not a single lowercase 40/64-hex object id.' -f $trimmed)
    }
    return $trimmed
}

function Assert-PspktGitLayoutClean {
    param([Parameter(Mandatory = $true)][string]$GitDir)
    $forbidden = @(
        (Join-Path $GitDir 'objects\info\alternates'),
        (Join-Path $GitDir 'objects\info\http-alternates'),
        (Join-Path $GitDir 'info\grafts')
    )
    foreach ($forbiddenPath in $forbidden) {
        if (Test-Path -LiteralPath $forbiddenPath) {
            throw ('git authority: forbidden replacement/alternate file "{0}" is present.' -f $forbiddenPath)
        }
    }
    $configWorktreePath = Join-Path $GitDir 'config.worktree'
    if (Test-Path -LiteralPath $configWorktreePath) {
        throw 'git authority: config.worktree is present.'
    }
    $replaceDir = Join-Path $GitDir 'refs\replace'
    if (Test-Path -LiteralPath $replaceDir) {
        $replaceEntries = @(Get-ChildItem -LiteralPath $replaceDir -Force -ErrorAction Stop)
        if ($replaceEntries.Count -gt 0) {
            throw 'git authority: refs\replace contains replacement entries.'
        }
    }
    $packedRefsPath = Join-Path $GitDir 'packed-refs'
    if (Test-Path -LiteralPath $packedRefsPath -PathType Leaf) {
        $packedBytes = Read-PspktBoundedFileBytes -FullPath $packedRefsPath -ByteCap $script:GitIndexByteCap
        $packedText = (New-PspktUtf8NoBom).GetString($packedBytes)
        if ($packedText.Contains('refs/replace/')) {
            throw 'git authority: packed-refs contains replace refs.'
        }
    }
}

function Assert-PspktGitRepositoryAuthority {
    param(
        [Parameter(Mandatory = $true)]$GitBinding,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )
    $canonicalRepoRoot = (Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath
    $repoDirIdentity = New-PspktBclDirectoryIdentity -FullPath $canonicalRepoRoot -Label 'git authority repository root'
    $gitDir = Join-Path $canonicalRepoRoot '.git'
    $gitDirIdentity = New-PspktBclDirectoryIdentity -FullPath $gitDir -Label 'git authority .git'
    $canonicalGitDir = [string]$gitDirIdentity.FullName
    $objectsPath = Join-Path $canonicalGitDir 'objects'
    $objectsIdentity = New-PspktBclDirectoryIdentity -FullPath $objectsPath -Label 'git authority .git\objects'

    $parents = [System.Collections.Generic.List[object]]::new()
    $parentDir = [System.IO.DirectoryInfo]::new($canonicalRepoRoot).Parent
    $parentGuard = 0
    while ($null -ne $parentDir -and $parentGuard -lt 64) {
        [void]$parents.Add((New-PspktBclDirectoryIdentity -FullPath $parentDir.FullName -Label ('git authority ancestor "{0}"' -f $parentDir.FullName)))
        $parentDir = $parentDir.Parent
        $parentGuard++
    }

    Assert-PspktGitLayoutClean -GitDir $canonicalGitDir

    $indexPath = Join-Path $canonicalGitDir 'index'
    $indexInfo = [System.IO.FileInfo]::new($indexPath)
    if (-not $indexInfo.Exists) {
        throw '.git\index is absent; a linked-worktree or bare layout is unsupported.'
    }
    $configPath = Join-Path $canonicalGitDir 'config'
    $indexRetained = $null
    $configRetained = $null
    $bound = $false
    try {
        $indexRetained = Open-PspktRetainedReadonlyFile -FullPath $indexPath -ByteCap $script:GitIndexByteCap -Label 'git authority .git\index'
        if (Test-Path -LiteralPath $configPath -PathType Leaf) {
            $configRetained = Open-PspktRetainedReadonlyFile -FullPath $configPath -ByteCap $script:GitConfigByteCap -Label 'git authority .git\config'
            Assert-PspktGitConfigAllowlistBytes -Bytes $configRetained.Bytes
        }
        Assert-PspktGitBindingIdentity -GitBinding $GitBinding
        $authority = [pscustomobject]@{
            GitBinding = $GitBinding
            RepositoryRoot = $canonicalRepoRoot
            GitDir = $canonicalGitDir
            ObjectsPath = [string]$objectsIdentity.FullName
            IndexPath = [string]$indexRetained.FullName
            ConfigPath = $configPath
            RepoDirIdentity = $repoDirIdentity
            GitDirIdentity = $gitDirIdentity
            ObjectsIdentity = $objectsIdentity
            ParentIdentities = $parents.ToArray()
            IndexRetained = $indexRetained
            ConfigRetained = $configRetained
        }
        $bound = $true
        return $authority
    }
    finally {
        if (-not $bound) {
            Close-PspktRetainedFile -Retained $configRetained
            Close-PspktRetainedFile -Retained $indexRetained
        }
    }
}

function Assert-PspktGitAuthorityUnchanged {
    param([Parameter(Mandatory = $true)]$Authority)
    Assert-PspktGitBindingIdentity -GitBinding $Authority.GitBinding
    Assert-PspktBclDirectoryIdentityUnchanged -Identity $Authority.RepoDirIdentity
    Assert-PspktBclDirectoryIdentityUnchanged -Identity $Authority.GitDirIdentity
    Assert-PspktBclDirectoryIdentityUnchanged -Identity $Authority.ObjectsIdentity
    foreach ($parentIdentity in $Authority.ParentIdentities) {
        Assert-PspktBclDirectoryIdentityUnchanged -Identity $parentIdentity
    }
    Assert-PspktGitLayoutClean -GitDir $Authority.GitDir
    Assert-PspktRetainedFileUnchanged -Retained $Authority.IndexRetained
    if ($null -ne $Authority.ConfigRetained) {
        Assert-PspktRetainedFileUnchanged -Retained $Authority.ConfigRetained
        Assert-PspktGitConfigAllowlistBytes -Bytes $Authority.ConfigRetained.Bytes
    }
}

function Close-PspktGitAuthority {
    param([AllowNull()]$Authority)
    $failures = [System.Collections.Generic.List[Exception]]::new()
    if ($null -eq $Authority) {
        return [Exception[]]$failures.ToArray()
    }
    try {
        Close-PspktRetainedFile -Retained $Authority.ConfigRetained
    }
    catch {
        [void]$failures.Add((Get-PspktInnermostException -Exception $_.Exception))
    }
    try {
        Close-PspktRetainedFile -Retained $Authority.IndexRetained
    }
    catch {
        [void]$failures.Add((Get-PspktInnermostException -Exception $_.Exception))
    }
    return [Exception[]]$failures.ToArray()
}

function Assert-PspktGitConfigAllowlist {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)
    $bytes = Read-PspktBoundedFileBytes -FullPath $ConfigPath -ByteCap $script:GitConfigByteCap
    Assert-PspktGitConfigAllowlistBytes -Bytes $bytes
}

function Assert-PspktGitConfigAllowlistBytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )
    $text = (New-PspktUtf8NoBom).GetString($Bytes)
    $lines = $text -split "`n"
    $currentSection = ''
    $allowedKeys = @{
        'core' = @('repositoryformatversion', 'filemode', 'bare', 'logallrefupdates', 'symlinks', 'ignorecase')
        'extensions' = @('objectformat')
    }
    foreach ($rawLine in $lines) {
        $line = ($rawLine -replace "`r", '').Trim()
        if ([string]::IsNullOrEmpty($line)) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        $sectionMatch = [regex]::Match($line, '^\[([^\]]+)\]$')
        if ($sectionMatch.Success) {
            $sectionRaw = $sectionMatch.Groups[1].Value.Trim()
            $subMatch = [regex]::Match($sectionRaw, '^(?<name>[A-Za-z0-9]+)(\s+"(?<sub>[^"]*)")?$')
            if (-not $subMatch.Success) {
                throw ('git config: malformed section "{0}".' -f $sectionRaw)
            }
            $sectionName = $subMatch.Groups['name'].Value.ToLowerInvariant()
            if ($sectionName -eq 'core' -or $sectionName -eq 'extensions' -or $sectionName -eq 'remote' -or $sectionName -eq 'branch') {
                $currentSection = $sectionName
                continue
            }
            throw ('git config: section "{0}" is outside the allowlist.' -f $sectionRaw)
        }
        $kvMatch = [regex]::Match($line, '^(?<key>[A-Za-z0-9\-]+)\s*=\s*(?<value>.*)$')
        if (-not $kvMatch.Success) {
            throw ('git config: malformed key line "{0}".' -f $line)
        }
        $key = $kvMatch.Groups['key'].Value.ToLowerInvariant()
        if ($key -eq 'worktree' -or $key -eq 'includeif' -or $key -eq 'include') {
            throw ('git config: forbidden key "{0}".' -f $key)
        }
        if ($currentSection -eq 'core' -or $currentSection -eq 'extensions') {
            if ($allowedKeys[$currentSection] -notcontains $key) {
                throw ('git config: key "{0}" not permitted in [{1}].' -f $key, $currentSection)
            }
        }
        elseif ($currentSection -eq 'remote') {
            if ($key -ne 'url' -and $key -ne 'fetch') {
                throw ('git config: key "{0}" not permitted in a remote section.' -f $key)
            }
        }
        elseif ($currentSection -eq 'branch') {
            if (@('remote', 'merge', 'vscode-merge-base', 'gk-last-accessed') -notcontains $key) {
                throw ('git config: key "{0}" not permitted in a branch section.' -f $key)
            }
        }
        else {
            throw ('git config: key "{0}" appears outside any allowed section.' -f $key)
        }
    }
}

function Test-PspktGitAuthorityMutationVectors {
    param([Parameter(Mandatory = $true)]$GitBinding)
    $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-gitauth-'
    $ok = $false
    $authority = $null
    try {
        $gitDir = Join-Path $root '.git'
        New-Item -ItemType Directory -Path $gitDir -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $gitDir 'objects') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $gitDir 'objects\info') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $gitDir 'info') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $gitDir 'refs') -Force | Out-Null
        $configPath = Join-Path $gitDir 'config'
        $configText = "[core]`n`trepositoryformatversion = 0`n`tfilemode = false`n`tbare = false`n"
        [System.IO.File]::WriteAllBytes($configPath, (New-PspktUtf8NoBom).GetBytes($configText))
        $indexPath = Join-Path $gitDir 'index'
        [System.IO.File]::WriteAllBytes($indexPath, [byte[]](68, 73, 82, 67, 0, 0, 0, 2))

        $authority = Assert-PspktGitRepositoryAuthority -GitBinding $GitBinding -RepositoryRoot $root

        $positiveOk = $false
        try { Assert-PspktGitAuthorityUnchanged -Authority $authority; $positiveOk = $true }
        catch { $positiveOk = $false }

        $grownLeaf = Join-Path $gitDir 'objects\ab'
        New-Item -ItemType Directory -Path $grownLeaf -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $grownLeaf 'cdef0123456789'), [byte[]](1, 2, 3))
        $grownObjectsOk = $false
        try { Assert-PspktGitAuthorityUnchanged -Authority $authority; $grownObjectsOk = $true }
        catch { $grownObjectsOk = $false }

        $denyConfigWriteOk = $false
        try {
            $configWriteStream = [System.IO.FileStream]::new($configPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $configWriteStream.Dispose()
        }
        catch [System.IO.IOException] { $denyConfigWriteOk = $true }
        $denyIndexWriteOk = $false
        try {
            $indexWriteStream = [System.IO.FileStream]::new($indexPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $indexWriteStream.Dispose()
        }
        catch [System.IO.IOException] { $denyIndexWriteOk = $true }

        $alternatesPath = Join-Path $gitDir 'objects\info\alternates'
        [System.IO.File]::WriteAllBytes($alternatesPath, [byte[]](47))
        $alternatesDetectOk = (Test-PspktThrows { Assert-PspktGitAuthorityUnchanged -Authority $authority })
        [System.IO.File]::Delete($alternatesPath)
        $alternatesRestoreOk = $false
        try { Assert-PspktGitAuthorityUnchanged -Authority $authority; $alternatesRestoreOk = $true }
        catch { $alternatesRestoreOk = $false }

        $worktreePath = Join-Path $gitDir 'config.worktree'
        [System.IO.File]::WriteAllBytes($worktreePath, [byte[]](0))
        $worktreeDetectOk = (Test-PspktThrows { Assert-PspktGitAuthorityUnchanged -Authority $authority })
        [System.IO.File]::Delete($worktreePath)

        $replaceDir = Join-Path $gitDir 'refs\replace'
        New-Item -ItemType Directory -Path $replaceDir -Force | Out-Null
        $replaceEntry = Join-Path $replaceDir 'deadbeef'
        [System.IO.File]::WriteAllBytes($replaceEntry, [byte[]](48))
        $replaceDetectOk = (Test-PspktThrows { Assert-PspktGitAuthorityUnchanged -Authority $authority })
        [System.IO.File]::Delete($replaceEntry)
        Remove-Item -LiteralPath $replaceDir -Recurse -Force

        $packedRefsPath = Join-Path $gitDir 'packed-refs'
        [System.IO.File]::WriteAllBytes($packedRefsPath, (New-PspktUtf8NoBom).GetBytes("# pack-refs`nabc123 refs/replace/deadbeef`n"))
        $packedDetectOk = (Test-PspktThrows { Assert-PspktGitAuthorityUnchanged -Authority $authority })
        [System.IO.File]::Delete($packedRefsPath)

        $finalRestoreOk = $false
        try { Assert-PspktGitAuthorityUnchanged -Authority $authority; $finalRestoreOk = $true }
        catch { $finalRestoreOk = $false }

        $badRepo = Join-Path $root 'badcfg'
        $badGit = Join-Path $badRepo '.git'
        New-Item -ItemType Directory -Path (Join-Path $badGit 'objects') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $badGit 'info') -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $badGit 'index'), [byte[]](1))
        [System.IO.File]::WriteAllBytes((Join-Path $badGit 'config'), (New-PspktUtf8NoBom).GetBytes("[evil]`n`tkey = value`n"))
        $badConfigRejectOk = (Test-PspktThrows { Assert-PspktGitRepositoryAuthority -GitBinding $GitBinding -RepositoryRoot $badRepo })

        $ok = ($positiveOk -and $grownObjectsOk -and $denyConfigWriteOk -and $denyIndexWriteOk -and
            $alternatesDetectOk -and $alternatesRestoreOk -and $worktreeDetectOk -and
            $replaceDetectOk -and $packedDetectOk -and $finalRestoreOk -and $badConfigRejectOk)
    }
    finally {
        foreach ($authorityCloseFailure in (Close-PspktGitAuthority -Authority $authority)) {
            if ($null -ne $authorityCloseFailure) {
                Write-Host ('  [git-authority-mutation] close failure :: {0}' -f $authorityCloseFailure.Message)
            }
        }
        [void](Remove-PspktStrictVectorRoot -Root $root -Label 'git-authority mutation vector root')
    }
    return $ok
}

function Get-PspktIndexStageMap {
    param(
        [Parameter(Mandatory = $true)]$GitAuthority,
        [Parameter(Mandatory = $true)][string]$ConfigRoot,
        [Parameter(Mandatory = $true)][string[]]$Paths
    )
    $map = @{}
    foreach ($relPath in $Paths) {
        $result = Invoke-PspktCheckedGit -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -GitArgs @('ls-files', '--stage', '--', $relPath)
        $stageLine = ($result.StdOut -replace "`r", '').TrimEnd("`n")
        $stageMatch = [regex]::Match($stageLine, '^(?<mode>\S+) (?<oid>\S+) (?<stage>\S+)\t(?<path>.+)$')
        if (-not $stageMatch.Success) {
            throw ('index authority: "{0}" is not a single stage-0 entry.' -f $relPath)
        }
        if ($stageMatch.Groups['mode'].Value -cne '100644') {
            throw ('index authority: "{0}" is not mode 100644.' -f $relPath)
        }
        if ($stageMatch.Groups['stage'].Value -cne '0') {
            throw ('index authority: "{0}" is not stage 0.' -f $relPath)
        }
        $oid = $stageMatch.Groups['oid'].Value
        if (-not (Test-PspktLowercaseHexOid -Value $oid)) {
            throw ('index authority: "{0}" has a malformed OID.' -f $relPath)
        }
        $map[$relPath] = $oid
    }
    return $map
}

function Complete-PspktSnapshotTreeFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][Exception]$PrimaryFailure
    )
    $removalFailure = Remove-PspktStrictVectorRoot -Root $Root -Label 'snapshot-tree partial root'
    $cleanupArray = [Exception[]]@()
    if ($null -ne $removalFailure) { $cleanupArray = [Exception[]]@($removalFailure) }
    return (New-PspktComposedFailure -Message 'snapshot-tree construction failed; partial root cleanup composed with the primary failure.' -PrimaryFailure $PrimaryFailure -CleanupFailures $cleanupArray)
}

function Invoke-PspktSnapshotCorruptionSeam {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$RelPath
    )
    $seam = $script:SnapshotCorruptionSeam
    if ($null -eq $seam) {
        return ,([byte[]]$Bytes)
    }
    $seamResult = & $seam $Bytes $RelPath
    return ,([byte[]]$seamResult)
}

function New-PspktSnapshotTree {
    param(
        [Parameter(Mandatory = $true)]$GitAuthority,
        [Parameter(Mandatory = $true)][string]$ConfigRoot,
        [Parameter(Mandatory = $true)][hashtable]$IndexOidByPath,
        [Parameter(Mandatory = $true)][string[]]$Paths
    )
    $snapshotRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-snapshot-'
    try {
        $manifest = @{}
        $cumulative = 0
        foreach ($relPath in $Paths) {
            $oid = [string]$IndexOidByPath[$relPath]
            $typeResult = Invoke-PspktCheckedGit -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -GitArgs @('cat-file', '-t', $oid)
            $type = ($typeResult.StdOut -replace "`r", '').Trim()
            if ($type -cne 'blob') {
                throw ('snapshot: object {0} for "{1}" is not a blob.' -f $oid, $relPath)
            }
            $sizeResult = Invoke-PspktCheckedGit -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -GitArgs @('cat-file', '-s', $oid)
            $sizeText = ($sizeResult.StdOut -replace "`r", '').Trim()
            if (-not [regex]::IsMatch($sizeText, '^[0-9]+$')) {
                throw ('snapshot: malformed size "{0}" for {1}.' -f $sizeText, $oid)
            }
            $declaredSize = [int64]$sizeText
            if ($declaredSize -lt 0 -or $declaredSize -gt $script:GitBlobByteCap) {
                throw ('snapshot: blob {0} is {1} bytes, over cap.' -f $oid, $declaredSize)
            }
            $cumulative += $declaredSize
            if ($cumulative -gt $script:GitSnapshotTotalCap) {
                throw 'snapshot: cumulative blob bytes exceed the snapshot cap.'
            }
            $blobBytes = Get-PspktGitBlobBytes -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -Oid $oid -DeclaredSize $declaredSize
            $computedOid = Get-PspktGitBlobOid -Bytes $blobBytes -ExpectedOid $oid
            if ($computedOid -cne $oid) {
                throw ('snapshot: recomputed blob OID {0} does not equal expected {1}.' -f $computedOid, $oid)
            }
            if ($relPath -ceq $script:PinnedGitAttributesRelPath) {
                Assert-PspktGitAttributesPolicyBytes -Bytes $blobBytes -Context ('source-snapshot index blob for "{0}"' -f $relPath) -IndexOid $oid
            }
            $destPath = Join-Path $snapshotRoot ($relPath -replace '/', '\')
            $destDir = Split-Path -Parent $destPath
            if (-not (Test-Path -LiteralPath $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            $writeStream = [System.IO.FileStream]::new($destPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $writeStream.Write($blobBytes, 0, $blobBytes.Length)
                $writeStream.Flush($true)
            }
            finally {
                $writeStream.Dispose()
            }
            $reread = Read-PspktBoundedFileBytes -FullPath $destPath -ByteCap $script:GitBlobByteCap
            $reread = Invoke-PspktSnapshotCorruptionSeam -Bytes $reread -RelPath $relPath
            if ($reread.Length -ne $blobBytes.Length) {
                throw ('snapshot: reopened length mismatch for "{0}".' -f $relPath)
            }
            $expectedSha = Get-PspktSha256Hex -Bytes $blobBytes
            $actualSha = Get-PspktSha256Hex -Bytes $reread
            if ($actualSha -cne $expectedSha) {
                throw ('snapshot: materialized digest {0} does not equal the OID-verified source digest {1} for "{2}".' -f $actualSha, $expectedSha, $relPath)
            }
            $manifest[$relPath] = [pscustomobject]@{
                IndexOid = $oid
                Length = $blobBytes.Length
                Sha256 = $expectedSha
            }
        }
        return [pscustomobject]@{
            Root = $snapshotRoot
            Manifest = $manifest
        }
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
        throw (Complete-PspktSnapshotTreeFailure -Root $snapshotRoot -PrimaryFailure $primaryFailure)
    }
}

function Get-PspktGitBlobBytes {
    param(
        [Parameter(Mandatory = $true)]$GitAuthority,
        [Parameter(Mandatory = $true)][string]$ConfigRoot,
        [Parameter(Mandatory = $true)][string]$Oid,
        [Parameter(Mandatory = $true)][int64]$DeclaredSize
    )
    if ($DeclaredSize -lt 0 -or $DeclaredSize -gt $script:GitBlobByteCap) {
        throw ('git cat-file blob {0} declared size {1} is out of range.' -f $Oid, $DeclaredSize)
    }
    Assert-PspktGitAuthorityUnchanged -Authority $GitAuthority
    $gitBinding = $GitAuthority.GitBinding
    $repoRoot = [string]$GitAuthority.RepositoryRoot
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $gitBinding.Path
    $startInfo.Arguments = Join-PspktArgv -Argv @('-C', $repoRoot, '--no-replace-objects', '-c', 'core.hooksPath=NUL', 'cat-file', 'blob', $Oid)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $repoRoot
    Set-PspktGitProcessEnvironment -StartInfo $startInfo -ConfigRoot $ConfigRoot

    $label = ('git cat-file blob {0}' -f $Oid)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $captured = $null
    try {
        Assert-PspktBootstrapProcessLaunchAdmitted -Label $label
        [void]$process.Start()
        $captured = Invoke-PspktDrainedProcess -Process $process -StdoutCap ([int]$DeclaredSize) -StderrCap $script:GitStdoutCap -TimeoutMs $script:GitWaitMs -Label $label
    }
    finally {
        Invoke-PspktBootstrapCallerProcessDisposal -Process $process
    }
    if ($captured.ExitCode -ne 0) {
        $stderr = [System.Text.Encoding]::UTF8.GetString($captured.StderrBytes)
        throw ('{0} exited {1}: {2}' -f $label, $captured.ExitCode, $stderr)
    }
    $bytes = $captured.StdoutBytes
    if ($bytes.Length -ne $DeclaredSize) {
        throw ('{0} returned {1} bytes, expected {2}.' -f $label, $bytes.Length, $DeclaredSize)
    }
    Assert-PspktGitAuthorityUnchanged -Authority $GitAuthority
    return ,$bytes
}

function Get-PspktGitBlobOid {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$ExpectedOid
    )
    if ([regex]::IsMatch($ExpectedOid, '^[0-9a-f]{40}$')) {
        $algorithm = [System.Security.Cryptography.SHA1]::Create()
    }
    elseif ([regex]::IsMatch($ExpectedOid, '^[0-9a-f]{64}$')) {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
    }
    else {
        throw ('git object id "{0}" is not a lowercase 40-hex (SHA-1) or 64-hex (SHA-256) object id.' -f $ExpectedOid)
    }
    try {
        $header = [System.Text.Encoding]::ASCII.GetBytes('blob ' + $Bytes.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture))
        $preimage = [byte[]]::new($header.Length + 1 + $Bytes.Length)
        [System.Array]::Copy($header, 0, $preimage, 0, $header.Length)
        $preimage[$header.Length] = 0
        [System.Array]::Copy($Bytes, 0, $preimage, $header.Length + 1, $Bytes.Length)
        $hash = $algorithm.ComputeHash($preimage)
    }
    finally {
        $algorithm.Dispose()
    }
    $builder = [System.Text.StringBuilder]::new($hash.Length * 2)
    foreach ($b in $hash) {
        [void]$builder.Append($b.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    return $builder.ToString()
}

function Assert-PspktGitAttributesPolicyBytes {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Context,
        [AllowNull()][string]$IndexOid = $null
    )
    if ($Bytes.Length -ne $script:PinnedGitAttributesLength) {
        throw ([System.InvalidOperationException]::new(
                ('{0}: .gitattributes policy length {1} does not equal the pinned length {2}.' -f $Context, $Bytes.Length, $script:PinnedGitAttributesLength)))
    }
    $pinned = $script:PinnedGitAttributesBytes
    for ($offset = 0; $offset -lt $pinned.Length; $offset++) {
        if ($Bytes[$offset] -ne $pinned[$offset]) {
            throw ([System.InvalidOperationException]::new(
                    ('{0}: .gitattributes policy byte at offset {1} ({2}) does not equal the pinned byte ({3}).' -f $Context, $offset, $Bytes[$offset], $pinned[$offset])))
        }
    }
    $actualSha = Get-PspktSha256Hex -Bytes $Bytes
    if ($actualSha -cne $script:PinnedGitAttributesSha256) {
        throw ([System.InvalidOperationException]::new(
                ('{0}: .gitattributes policy digest {1} does not equal the pinned digest {2}.' -f $Context, $actualSha, $script:PinnedGitAttributesSha256)))
    }
    if (-not [string]::IsNullOrEmpty($IndexOid)) {
        if ($IndexOid -cne $script:PinnedGitAttributesIndexOid) {
            throw ([System.InvalidOperationException]::new(
                    ('{0}: .gitattributes index object id {1} does not equal the pinned object id {2}.' -f $Context, $IndexOid, $script:PinnedGitAttributesIndexOid)))
        }
    }
}

function Test-PspktGitAttributesPolicyPinVectors {
    $pinnedBytes = $script:PinnedGitAttributesBytes
    $selfConsistentOk = (
        ($pinnedBytes.Length -eq $script:PinnedGitAttributesLength) -and
        ((Get-PspktSha256Hex -Bytes $pinnedBytes) -ceq $script:PinnedGitAttributesSha256) -and
        ((Get-PspktGitBlobOid -Bytes $pinnedBytes -ExpectedOid $script:PinnedGitAttributesIndexOid) -ceq $script:PinnedGitAttributesIndexOid))

    $pinnedText = [System.Text.Encoding]::ASCII.GetString($pinnedBytes)
    $splitLines = @($pinnedText.Split([char]10))
    $policyLines = @($splitLines | Where-Object { $_ -ne '' })
    $textSuffix = ' ' + $script:PinnedGitAttributesTextPolicy
    $binarySuffix = ' ' + $script:PinnedGitAttributesBinaryPolicy
    $policyTokensOk = ($policyLines.Count -eq 11)
    foreach ($policyLine in $policyLines) {
        $hasFilter = $policyLine.Contains(' -filter ')
        $hasIdent = $policyLine.Contains(' -ident ')
        $hasWorkingTree = $policyLine.EndsWith(' -working-tree-encoding')
        $isText = $policyLine.EndsWith($textSuffix)
        $isBinary = $policyLine.EndsWith($binarySuffix)
        if (-not ($hasFilter -and $hasIdent -and $hasWorkingTree -and ($isText -or $isBinary))) {
            $policyTokensOk = $false
        }
    }
    $textPolicyCount = @($policyLines | Where-Object { $_.EndsWith($textSuffix) }).Count
    $binaryPolicyCount = @($policyLines | Where-Object { $_.EndsWith($binarySuffix) }).Count
    $eolLfCount = @($policyLines | Where-Object { $_.Contains(' eol=lf ') }).Count
    $policyTokensOk = ($policyTokensOk -and ($textPolicyCount -eq 9) -and ($binaryPolicyCount -eq 2) -and ($eolLfCount -eq 9))

    $acceptExactOk = -not (Test-PspktThrows { Assert-PspktGitAttributesPolicyBytes -Bytes $script:PinnedGitAttributesBytes -Context 'pin self-accept' -IndexOid $script:PinnedGitAttributesIndexOid })

    $byteFlip = [byte[]]::new($pinnedBytes.Length)
    [System.Array]::Copy($pinnedBytes, $byteFlip, $pinnedBytes.Length)
    $byteFlip[0] = [byte]((([int]$byteFlip[0]) + 1) -band 0xFF)
    $rejectByteFlipOk = (Test-PspktThrows { Assert-PspktGitAttributesPolicyBytes -Bytes $byteFlip -Context 'pin byte-flip' })

    $truncated = [byte[]]::new($pinnedBytes.Length - 1)
    [System.Array]::Copy($pinnedBytes, $truncated, $truncated.Length)
    $rejectTruncationOk = (Test-PspktThrows { Assert-PspktGitAttributesPolicyBytes -Bytes $truncated -Context 'pin one-byte-removal' })

    $lineRemovalText = (($policyLines[0..($policyLines.Count - 2)] -join "`n") + "`n")
    $lineRemoval = [System.Text.Encoding]::ASCII.GetBytes($lineRemovalText)
    $rejectLineRemovalOk = (
        ($lineRemoval.Length -ne $pinnedBytes.Length) -and
        (Test-PspktThrows { Assert-PspktGitAttributesPolicyBytes -Bytes $lineRemoval -Context 'pin line-removal' }))

    $crlfText = $pinnedText.Replace("`n", "`r`n")
    $crlf = [System.Text.Encoding]::ASCII.GetBytes($crlfText)
    $rejectCrlfOk = (
        ($crlf.Length -ne $pinnedBytes.Length) -and
        ($crlf -contains 13) -and
        (Test-PspktThrows { Assert-PspktGitAttributesPolicyBytes -Bytes $crlf -Context 'pin crlf' }))

    $oidMismatchOk = (Test-PspktThrows { Assert-PspktGitAttributesPolicyBytes -Bytes $script:PinnedGitAttributesBytes -Context 'pin oid-mismatch' -IndexOid 'ffffffffffffffffffffffffffffffffffffffff' })

    return (
        $selfConsistentOk -and $policyTokensOk -and $acceptExactOk -and $rejectByteFlipOk -and
        $rejectTruncationOk -and $rejectLineRemovalOk -and $rejectCrlfOk -and $oidMismatchOk)
}

function Test-PspktExactOrdinalPathSet {
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$Actual,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )
    $expectedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($expectedPath in $Expected) {
        if ([string]::IsNullOrEmpty($expectedPath)) { return $false }
        if (-not $expectedSet.Add($expectedPath)) { return $false }
    }
    if ($null -eq $Actual) { return $false }
    $seenSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($actualPath in $Actual) {
        if ([string]::IsNullOrEmpty($actualPath)) { return $false }
        if (-not $expectedSet.Contains($actualPath)) { return $false }
        if (-not $seenSet.Add($actualPath)) { return $false }
    }
    if ($seenSet.Count -ne $expectedSet.Count) { return $false }
    return $true
}

function Test-PspktPathSetHelperNegativeVectors {
    param([Parameter(Mandatory = $true)][string[]]$Expected)
    if ($Expected.Count -lt 2) { return $false }
    $exactCopy = @($Expected | ForEach-Object { $_ })
    if (-not (Test-PspktExactOrdinalPathSet -Actual $exactCopy -Expected $Expected)) { return $false }
    $substitution = @($Expected | ForEach-Object { $_ })
    $substitution[0] = $Expected[0] + '.substituted'
    if (Test-PspktExactOrdinalPathSet -Actual $substitution -Expected $Expected) { return $false }
    $duplicate = @($Expected | ForEach-Object { $_ })
    $duplicate[$duplicate.Count - 1] = $Expected[0]
    if (Test-PspktExactOrdinalPathSet -Actual $duplicate -Expected $Expected) { return $false }
    $caseVariant = @($Expected | ForEach-Object { $_ })
    $caseVariant[0] = $Expected[0].ToUpperInvariant()
    if ($caseVariant[0] -ceq $Expected[0]) { $caseVariant[0] = $Expected[0].ToLowerInvariant() }
    if ($caseVariant[0] -ceq $Expected[0]) { return $false }
    if (Test-PspktExactOrdinalPathSet -Actual $caseVariant -Expected $Expected) { return $false }
    $missing = @($Expected[0..($Expected.Count - 2)])
    if (Test-PspktExactOrdinalPathSet -Actual $missing -Expected $Expected) { return $false }
    $extra = @($Expected + ($Expected[0] + '.extra'))
    if (Test-PspktExactOrdinalPathSet -Actual $extra -Expected $Expected) { return $false }
    $emptyEntry = @($Expected | ForEach-Object { $_ })
    $emptyEntry[0] = ''
    if (Test-PspktExactOrdinalPathSet -Actual $emptyEntry -Expected $Expected) { return $false }
    return $true
}

function Test-PspktStageMapEquality {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Expected,
        [Parameter(Mandatory = $true)][hashtable]$Actual,
        [Parameter(Mandatory = $true)][string[]]$Paths
    )
    if ($Expected.Count -ne $Paths.Count) { return $false }
    if ($Actual.Count -ne $Paths.Count) { return $false }
    foreach ($relPath in $Paths) {
        if (-not $Expected.ContainsKey($relPath)) { return $false }
        if (-not $Actual.ContainsKey($relPath)) { return $false }
        if (([string]$Expected[$relPath]) -cne ([string]$Actual[$relPath])) { return $false }
    }
    return $true
}

function Resolve-PspktRepoContainedOrdinaryFile {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$RelPath
    )
    if ([string]::IsNullOrEmpty($RelPath)) {
        throw 'worktree binding: empty relative path.'
    }
    if ($RelPath.IndexOf([char]0) -ge 0) {
        throw 'worktree binding: relative path contains NUL.'
    }
    if ($RelPath.IndexOf('\') -ge 0) {
        throw ('worktree binding: "{0}" must use forward slashes.' -f $RelPath)
    }
    $segments = $RelPath -split '/'
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..') {
            throw ('worktree binding: "{0}" has an invalid path segment.' -f $RelPath)
        }
    }
    $rootPrefix = ([System.IO.Path]::GetFullPath($RepositoryRoot)).TrimEnd('\')
    $current = $rootPrefix
    for ($segmentIndex = 0; $segmentIndex -lt $segments.Count; $segmentIndex++) {
        $current = Join-Path $current $segments[$segmentIndex]
        if ($segmentIndex -eq $segments.Count - 1) {
            $leafFileInfo = [System.IO.FileInfo]::new($current)
            if (-not $leafFileInfo.Exists) {
                throw ('worktree binding: file "{0}" is absent.' -f $RelPath)
            }
            if (($leafFileInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
                throw ('worktree binding: "{0}" is a reparse point.' -f $RelPath)
            }
        }
        else {
            $dirInfo = [System.IO.DirectoryInfo]::new($current)
            if (-not $dirInfo.Exists) {
                throw ('worktree binding: directory component "{0}" of "{1}" is absent.' -f $segments[$segmentIndex], $RelPath)
            }
            if (($dirInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
                throw ('worktree binding: directory component "{0}" of "{1}" is a reparse point.' -f $segments[$segmentIndex], $RelPath)
            }
        }
    }
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $rootPrefix ($RelPath -replace '/', '\')))
    if (-not ($fullPath.StartsWith($rootPrefix + '\', [System.StringComparison]::Ordinal))) {
        throw ('worktree binding: "{0}" resolves outside the repository root.' -f $RelPath)
    }
    return $fullPath
}

function Get-PspktWorktreeBlobOid {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$RelPath,
        [Parameter(Mandatory = $true)][int]$ByteCap,
        [Parameter(Mandatory = $true)][string]$ExpectedOid
    )
    if (-not (Test-PspktLowercaseHexOid -Value $ExpectedOid)) {
        throw ('worktree binding: expected OID for "{0}" is malformed.' -f $RelPath)
    }
    $fullPath = Resolve-PspktRepoContainedOrdinaryFile -RepositoryRoot $RepositoryRoot -RelPath $RelPath
    $stream = [System.IO.FileStream]::new($fullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        [int64]$length = $stream.Length
        if ($length -lt 0 -or $length -gt [int64]$ByteCap -or $length -gt [int64][int]::MaxValue) {
            throw ('worktree binding: "{0}" length {1} is out of range.' -f $RelPath, $length)
        }
        $count = [int]$length
        $buffer = [byte[]]::new($count)
        $offset = 0
        while ($offset -lt $count) {
            $read = $stream.Read($buffer, $offset, $count - $offset)
            if ($read -le 0) { break }
            $offset += $read
        }
        if ($offset -ne $count) {
            throw ('worktree binding: short read on "{0}".' -f $RelPath)
        }
        if ($stream.ReadByte() -ne -1) {
            throw ('worktree binding: "{0}" grew during hashing.' -f $RelPath)
        }
        return (Get-PspktGitBlobOid -Bytes $buffer -ExpectedOid $ExpectedOid)
    }
    finally {
        $stream.Dispose()
    }
}

function Test-PspktWorktreeIndexBinding {
    param(
        [Parameter(Mandatory = $true)][hashtable]$IndexOidByPath,
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )
    if ($IndexOidByPath.Count -ne $Paths.Count) {
        throw ('worktree binding: bound OID count {0} does not equal path count {1}.' -f $IndexOidByPath.Count, $Paths.Count)
    }
    foreach ($relPath in $Paths) {
        if (-not $IndexOidByPath.ContainsKey($relPath)) {
            throw ('worktree binding: no bound index OID for "{0}".' -f $relPath)
        }
        $expectedOid = [string]$IndexOidByPath[$relPath]
        if (-not (Test-PspktLowercaseHexOid -Value $expectedOid)) {
            throw ('worktree binding: bound OID for "{0}" is malformed.' -f $relPath)
        }
        $computedOid = Get-PspktWorktreeBlobOid -RepositoryRoot $RepositoryRoot -RelPath $relPath -ByteCap $script:GitBlobByteCap -ExpectedOid $expectedOid
        if ($computedOid -cne $expectedOid) {
            throw ('worktree binding: "{0}" hashes to {1}, expected stage-0 index OID {2}.' -f $relPath, $computedOid, $expectedOid)
        }
    }
    return $true
}

function Invoke-PspktCscBootstrap {
    param(
        [Parameter(Mandatory = $true)][string]$SnapshotSourcePath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )
    $systemDir = [Environment]::SystemDirectory
    $windowsRoot = Split-Path -Parent $systemDir
    if ([IntPtr]::Size -eq 8) {
        $frameworkDir = Join-Path $windowsRoot 'Microsoft.NET\Framework64\v4.0.30319'
    }
    else {
        $frameworkDir = Join-Path $windowsRoot 'Microsoft.NET\Framework\v4.0.30319'
    }
    $canonicalOutputDir = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (-not (Test-PspktNonReparseDirectory -FullPath $canonicalOutputDir)) {
        throw ('csc bootstrap: output directory "{0}" is absent or a reparse point.' -f $canonicalOutputDir)
    }
    if (-not (Test-PspktNonReparseDirectory -FullPath $frameworkDir)) {
        throw ('csc bootstrap: framework directory "{0}" is absent or a reparse point.' -f $frameworkDir)
    }
    if (-not (Test-PspktNonReparseDirectory -FullPath $systemDir)) {
        throw ('csc bootstrap: system directory "{0}" is absent or a reparse point.' -f $systemDir)
    }
    $cscPath = Join-Path $frameworkDir 'csc.exe'
    $systemDll = Join-Path $frameworkDir 'System.dll'
    $canonicalSource = [System.IO.Path]::GetFullPath($SnapshotSourcePath)
    $sourceDir = [System.IO.Path]::GetDirectoryName($canonicalSource)
    if ([string]::IsNullOrEmpty($sourceDir) -or -not (Test-PspktNonReparseDirectory -FullPath $sourceDir)) {
        throw ('csc bootstrap: source directory for "{0}" is absent or a reparse point.' -f $canonicalSource)
    }
    $outputDll = [System.IO.Path]::GetFullPath((Join-Path $canonicalOutputDir ('pspkt-phase4-helper-' + [guid]::NewGuid().ToString('N') + '.dll')))
    if (Test-Path -LiteralPath $outputDll) {
        throw 'csc bootstrap: output leaf already exists.'
    }

    $cscRetained = $null
    $systemDllRetained = $null
    $sourceRetained = $null
    $primaryFailure = $null
    $resultPath = $null
    try {
        $cscRetained = Open-PspktRetainedReadonlyFile -FullPath $cscPath -ByteCap $script:CscBinaryByteCap -Label 'csc bootstrap csc.exe authority'
        $systemDllRetained = Open-PspktRetainedReadonlyFile -FullPath $systemDll -ByteCap $script:CscBinaryByteCap -Label 'csc bootstrap System.dll reference authority'
        $sourceRetained = Open-PspktRetainedReadonlyFile -FullPath $canonicalSource -ByteCap $script:GitBlobByteCap -Label 'csc bootstrap BoundedProcess.cs source authority'

        Assert-PspktRetainedFileUnchanged -Retained $cscRetained
        Assert-PspktRetainedFileUnchanged -Retained $systemDllRetained
        Assert-PspktRetainedFileUnchanged -Retained $sourceRetained
        if (Test-Path -LiteralPath $outputDll) {
            throw 'csc bootstrap: output leaf materialized before compiler launch.'
        }

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $cscRetained.FullName
        $argv = @(
            '/noconfig', '/nologo', '/target:library', '/optimize+',
            ('/reference:' + $systemDllRetained.FullName),
            ('/out:' + $outputDll),
            $sourceRetained.FullName
        )
        $startInfo.Arguments = Join-PspktArgv -Argv $argv
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.WorkingDirectory = $canonicalOutputDir
        $startInfo.EnvironmentVariables.Clear()
        $startInfo.EnvironmentVariables['SystemRoot'] = $windowsRoot
        $startInfo.EnvironmentVariables['WINDIR'] = $windowsRoot
        $startInfo.EnvironmentVariables['TEMP'] = $canonicalOutputDir
        $startInfo.EnvironmentVariables['TMP'] = $canonicalOutputDir
        $startInfo.EnvironmentVariables['PATH'] = ($frameworkDir + ';' + $systemDir)

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        $captured = $null
        try {
            Assert-PspktBootstrapProcessLaunchAdmitted -Label 'csc bootstrap'
            [void]$process.Start()
            $captured = Invoke-PspktDrainedProcess -Process $process -StdoutCap $script:GitStdoutCap -StderrCap $script:GitStdoutCap -TimeoutMs $script:CscWaitMs -Label 'csc bootstrap'
        }
        finally {
            Invoke-PspktBootstrapCallerProcessDisposal -Process $process
        }

        Assert-PspktRetainedFileUnchanged -Retained $cscRetained
        Assert-PspktRetainedFileUnchanged -Retained $systemDllRetained
        Assert-PspktRetainedFileUnchanged -Retained $sourceRetained

        if ($captured.ExitCode -ne 0) {
            $stdout = [System.Text.Encoding]::UTF8.GetString($captured.StdoutBytes)
            $stderr = [System.Text.Encoding]::UTF8.GetString($captured.StderrBytes)
            throw ('csc bootstrap: exit {0}: {1} {2}' -f $captured.ExitCode, $stdout, $stderr)
        }
        $containedOutput = Assert-PspktContainedDirectLeaf -ExpectedRoot $canonicalOutputDir -LeafPath $outputDll -Label 'csc bootstrap output assembly'
        [void](Read-PspktBoundedFileBytes -FullPath $containedOutput -ByteCap $script:HelperByteCap)
        $resultPath = (Resolve-Path -LiteralPath $containedOutput).ProviderPath
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    foreach ($retained in @($cscRetained, $systemDllRetained, $sourceRetained)) {
        try {
            Close-PspktRetainedFile -Retained $retained
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    $composed = New-PspktComposedFailure -Message 'csc bootstrap: compiler authority operational and retained-stream cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
    if ($null -ne $composed) {
        throw $composed
    }
    return $resultPath
}

function Test-PspktCscAuthorityIdentityVectors {
    $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-cscid-'
    $ok = $false
    $retained = $null
    try {
        $fileA = Join-Path $root 'authority-a.bin'
        [System.IO.File]::WriteAllBytes($fileA, [byte[]](10, 20, 30, 40, 50))
        $retained = Open-PspktRetainedReadonlyFile -FullPath $fileA -ByteCap $script:CscBinaryByteCap -Label 'csc-id positive'

        $positiveOk = $false
        try {
            Assert-PspktRetainedFileUnchanged -Retained $retained
            $positiveOk = $true
        }
        catch {
            $positiveOk = $false
        }

        $denyWriteOk = $false
        try {
            $writeStream = [System.IO.FileStream]::new($fileA, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $writeStream.Dispose()
        }
        catch [System.IO.IOException] {
            $denyWriteOk = $true
        }

        $digestTamper = [pscustomobject]@{
            Label = $retained.Label; FullName = $retained.FullName; Stream = $retained.Stream
            Bytes = $retained.Bytes; Sha256 = ('f' * 64); Length = $retained.Length
            Attributes = $retained.Attributes; CreationTimeUtc = $retained.CreationTimeUtc
            LastWriteTimeUtc = $retained.LastWriteTimeUtc; ByteCap = $retained.ByteCap
        }
        $digestTamperOk = (Test-PspktThrows { Assert-PspktRetainedFileUnchanged -Retained $digestTamper })

        $attrTamperAttributes = ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]$retained.Attributes)
        $attrTamperOk = $false
        if ($attrTamperAttributes -ne $retained.Attributes) {
            $attrTamper = [pscustomobject]@{
                Label = $retained.Label; FullName = $retained.FullName; Stream = $retained.Stream
                Bytes = $retained.Bytes; Sha256 = $retained.Sha256; Length = $retained.Length
                Attributes = $attrTamperAttributes; CreationTimeUtc = $retained.CreationTimeUtc
                LastWriteTimeUtc = $retained.LastWriteTimeUtc; ByteCap = $retained.ByteCap
            }
            $attrTamperOk = (Test-PspktThrows { Assert-PspktRetainedFileUnchanged -Retained $attrTamper })
        }

        $fileB = Join-Path $root 'authority-b.bin'
        [System.IO.File]::WriteAllBytes($fileB, [byte[]](99, 98, 97, 96, 95, 94))
        $swapTamper = [pscustomobject]@{
            Label = $retained.Label; FullName = ([System.IO.Path]::GetFullPath($fileB)); Stream = $retained.Stream
            Bytes = $retained.Bytes; Sha256 = $retained.Sha256; Length = $retained.Length
            Attributes = $retained.Attributes; CreationTimeUtc = $retained.CreationTimeUtc
            LastWriteTimeUtc = $retained.LastWriteTimeUtc; ByteCap = $retained.ByteCap
        }
        $swapOk = (Test-PspktThrows { Assert-PspktRetainedFileUnchanged -Retained $swapTamper })

        $dirRejectOk = (Test-PspktThrows { Open-PspktRetainedReadonlyFile -FullPath $root -ByteCap $script:CscBinaryByteCap -Label 'csc-id dir-reject' })
        $missingRejectOk = (Test-PspktThrows { Open-PspktRetainedReadonlyFile -FullPath (Join-Path $root 'no-such-file.bin') -ByteCap $script:CscBinaryByteCap -Label 'csc-id missing-reject' })

        $ok = ($positiveOk -and $denyWriteOk -and $digestTamperOk -and $attrTamperOk -and $swapOk -and $dirRejectOk -and $missingRejectOk)
    }
    finally {
        Close-PspktRetainedFile -Retained $retained
        [void](Remove-PspktStrictVectorRoot -Root $root -Label 'csc-id vector root')
    }
    return $ok
}

function New-PspktHelperBinding {
    param([Parameter(Mandatory = $true)][string]$HelperPath)
    [byte[]]$bytes = Read-PspktBoundedFileBytes -FullPath $HelperPath -ByteCap $script:HelperByteCap
    $digest = Get-PspktSha256Hex -Bytes $bytes
    $assembly = [System.Reflection.Assembly]::Load($bytes)
    $hostType = $assembly.GetType('Pspkt.Certification.BoundedProcessHost', $true)
    $types = @{}
    foreach ($exportedType in $assembly.GetExportedTypes()) {
        if ($exportedType.Namespace -cne 'Pspkt.Certification') {
            continue
        }
        if ($types.ContainsKey($exportedType.Name)) {
            throw ('helper binding: duplicate exported type name "{0}".' -f $exportedType.Name)
        }
        $types.Add($exportedType.Name, $exportedType)
    }
    $versionField = $hostType.GetField('Version', ([System.Reflection.BindingFlags]'Public, Static'))
    $version = [string]$versionField.GetValue($null)
    if ($version -cne $script:HelperVersion) {
        throw ('helper binding: version "{0}" does not equal "{1}".' -f $version, $script:HelperVersion)
    }
    return [pscustomobject]@{
        Path = $HelperPath
        Bytes = $bytes
        Digest = $digest
        Assembly = $assembly
        HostType = $hostType
        Types = $types
        Version = $version
    }
}

function Get-PspktHelperType {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SimpleName
    )
    if (-not $Binding.Types.ContainsKey($SimpleName)) {
        throw ('helper binding: exported type "{0}" is absent.' -f $SimpleName)
    }
    return $Binding.Types[$SimpleName]
}

function Get-PspktHelperEnum {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$EnumName,
        [Parameter(Mandatory = $true)][string]$Member
    )
    $enumType = Get-PspktHelperType -Binding $Binding -SimpleName $EnumName
    return [System.Enum]::Parse($enumType, $Member)
}

function Invoke-PspktHelperStatic {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Method,
        [object[]]$Arguments = @()
    )
    $flags = [System.Reflection.BindingFlags]'InvokeMethod, Public, Static'
    if ($Method -ceq 'GetGeneratorArgv') {
        if ($Arguments.Count -ne 3) {
            throw ('helper binding: unsupported GetGeneratorArgv arity {0}.' -f $Arguments.Count)
        }
        $parameterTypes = [Type[]]@(
            (Get-PspktHelperType -Binding $Binding -SimpleName 'GeneratorScenario'),
            [string],
            [string]
        )
        $candidate = $Binding.HostType.GetMethod(
            $Method,
            ([System.Reflection.BindingFlags]'Public, Static'),
            $null,
            $parameterTypes,
            $null)
        if ($null -eq $candidate) {
            throw 'helper binding: three-parameter GetGeneratorArgv overload is absent.'
        }
        return $candidate.Invoke($null, [object[]]@(
            $Arguments[0].PSObject.BaseObject,
            [string]$Arguments[1],
            [string]$Arguments[2]))
    }
    if ($Method -ceq 'CreateProcessLaunchConfiguration') {
        $parameterTypes = [System.Collections.Generic.List[Type]]::new()
        [void]$parameterTypes.Add((Get-PspktHelperType -Binding $Binding -SimpleName 'ProcessLaunchRole'))
        [void]$parameterTypes.Add([string])
        [void]$parameterTypes.Add([string[]])
        [void]$parameterTypes.Add([string])
        [void]$parameterTypes.Add([string])
        [void]$parameterTypes.Add([string[]])
        [void]$parameterTypes.Add([string[]])
        [void]$parameterTypes.Add([string[]])
        [void]$parameterTypes.Add([string[]])
        [void]$parameterTypes.Add([int])
        [void]$parameterTypes.Add([int])
        [void]$parameterTypes.Add([int])
        [void]$parameterTypes.Add([int])
        [void]$parameterTypes.Add([bool])
        [void]$parameterTypes.Add([Guid])
        [void]$parameterTypes.Add([string])
        [void]$parameterTypes.Add((Get-PspktHelperType -Binding $Binding -SimpleName 'PauseConfiguration'))
        [void]$parameterTypes.Add((Get-PspktHelperType -Binding $Binding -SimpleName 'ProbeEvidence'))
        [void]$parameterTypes.Add((Get-PspktHelperType -Binding $Binding -SimpleName 'ParentLossMembership'))
        [void]$parameterTypes.Add((Get-PspktHelperType -Binding $Binding -SimpleName 'NestedProof'))
        if ($Arguments.Count -eq 21) {
            [void]$parameterTypes.Add((Get-PspktHelperType -Binding $Binding -SimpleName 'GeneratorBinding'))
        }
        elseif ($Arguments.Count -ne 20) {
            throw ('helper binding: unsupported configuration factory arity {0}.' -f $Arguments.Count)
        }
        $candidate = $Binding.HostType.GetMethod(
            $Method,
            ([System.Reflection.BindingFlags]'Public, Static'),
            $null,
            $parameterTypes.ToArray(),
            $null)
        if ($null -eq $candidate) {
            throw ('helper binding: {0}-parameter configuration factory is absent.' -f $Arguments.Count)
        }
        $normalizedArguments = [object[]]::new($Arguments.Count)
        for ($index = 0; $index -lt $Arguments.Count; $index++) {
            $value = $Arguments[$index]
            if ($null -ne $value) {
                $value = $value.PSObject.BaseObject
            }
            $targetType = $parameterTypes[$index]
            if ($null -ne $value -and $targetType -eq [string]) {
                $value = [string]$value
            }
            elseif ($null -ne $value -and $targetType -eq [int]) {
                $value = [int]$value
            }
            elseif ($null -ne $value -and $targetType -eq [bool]) {
                $value = [bool]$value
            }
            elseif ($null -ne $value -and $targetType -eq [Guid]) {
                $value = [Guid]$value
            }
            $normalizedArguments[$index] = $value
        }
        return $candidate.Invoke($null, $normalizedArguments)
    }
    return $Binding.HostType.InvokeMember($Method, $flags, $null, $null, $Arguments)
}

function Invoke-PspktHelperTypeStatic {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SimpleName,
        [Parameter(Mandatory = $true)][string]$Method,
        [object[]]$Arguments = @()
    )
    $type = Get-PspktHelperType -Binding $Binding -SimpleName $SimpleName
    $flags = [System.Reflection.BindingFlags]'InvokeMethod, Public, Static'
    return $type.InvokeMember($Method, $flags, $null, $null, $Arguments)
}

function New-PspktHelperObject {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SimpleName,
        [object[]]$Arguments = @()
    )
    $type = Get-PspktHelperType -Binding $Binding -SimpleName $SimpleName
    return [System.Activator]::CreateInstance($type, $Arguments)
}

function Test-PspktHelperEnumEquals {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Member
    )
    return ([string]$Value.ToString()) -ceq $Member
}

function Write-PspktResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Condition,
        [string]$Detail = ''
    )
    if ($Condition) {
        $script:PassCount++
        Write-Host ('  [pass] {0}' -f $Name)
    }
    else {
        $script:FailCount++
        if ([string]::IsNullOrEmpty($Detail)) {
            Write-Host ('  [FAIL] {0}' -f $Name)
        }
        else {
            Write-Host ('  [FAIL] {0} :: {1}' -f $Name, $Detail)
        }
    }
    return $Condition
}

function Test-PspktThrows {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)
    try { & $Action | Out-Null; return $false } catch { return $true }
}

function Get-PspktThrownException {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)
    try {
        & $Action | Out-Null
        return $null
    }
    catch {
        if ($null -ne $_.Exception) { return $_.Exception }
        return $_
    }
}

function Find-PspktInnerException {
    param(
        [AllowNull()]$Exception,
        [Parameter(Mandatory = $true)][string]$FullName
    )
    $cursor = $Exception
    while ($null -ne $cursor) {
        if ($cursor.GetType().FullName -ceq $FullName) { return $cursor }
        $cursor = $cursor.InnerException
    }
    return $null
}

function Get-PspktDiagnosticsSnapshot {
    param([Parameter(Mandatory = $true)]$Binding)
    return (Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot')
}

function Get-PspktAccessEntriesForName {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$EventName
    )
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $Snapshot.GetEntries()) {
        if (([string]$entry.EventName) -ceq $EventName) { [void]$matched.Add($entry) }
    }
    return $matched.ToArray()
}

function Get-PspktHostExecutable {
    return [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
}

function New-PspktCheckLedger {
    param([Parameter(Mandatory = $true)][string[]]$ExpectedIds)
    return [pscustomobject]@{
        Expected = $ExpectedIds
        Recorded = [System.Collections.Generic.List[string]]::new()
        Failed = $false
    }
}

function Add-PspktCheck {
    param(
        [Parameter(Mandatory = $true)]$Ledger,
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Condition,
        [string]$Detail = ''
    )
    [void](Write-PspktResult -Name $Id -Condition $Condition -Detail $Detail)
    if ($Condition) {
        $Ledger.Recorded.Add($Id)
    }
    else {
        $Ledger.Failed = $true
    }
    return $Condition
}

function Test-PspktLedgerComplete {
    param([Parameter(Mandatory = $true)]$Ledger)
    if ($Ledger.Failed) { return $false }
    if ($Ledger.Recorded.Count -ne $Ledger.Expected.Count) { return $false }
    for ($i = 0; $i -lt $Ledger.Expected.Count; $i++) {
        if ($Ledger.Recorded[$i] -cne $Ledger.Expected[$i]) { return $false }
    }
    return $true
}

function Write-PspktWorkerResult {
    param(
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$HelperVersion,
        [Parameter(Mandatory = $true)][string[]]$CheckIds,
        [string]$Mutation = ''
    )
    $tab = [string][char]0x09
    $lf = [string][char]0x0A
    $lines = [System.Collections.Generic.List[string]]::new()
    $headerNonce = $Nonce
    $headerVersion = $HelperVersion
    if ($Mutation -ceq 'NonceMismatch') { $headerNonce = [guid]::NewGuid().ToString('N') }
    if ($Mutation -ceq 'VersionMismatch') { $headerVersion = 'pspkt-phase4-bounded-process-0' }
    $lines.Add('pspkt-phase4-worker-result-v1' + $tab + $headerNonce + $tab + $headerVersion)
    $ordinal = 0
    $emitted = @($CheckIds)
    if ($Mutation -ceq 'MissingCheck' -and $emitted.Count -gt 0) {
        $emitted = $emitted[1..($emitted.Count - 1)]
    }
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $emitted) {
        $status = 'pass'
        $rowOrdinal = $ordinal
        if ($Mutation -ceq 'SkipStatus' -and $ordinal -eq 0) { $status = 'skip' }
        if ($Mutation -ceq 'FailStatus' -and $ordinal -eq 0) { $status = 'fail' }
        if ($Mutation -ceq 'BadOrdinal' -and $ordinal -eq 0) { $rowOrdinal = 999 }
        $rows.Add('check' + $tab + $rowOrdinal.ToString([System.Globalization.CultureInfo]::InvariantCulture) + $tab + $id + $tab + $status)
        $ordinal++
    }
    if ($Mutation -ceq 'UnknownCheck') {
        $rows.Add('check' + $tab + $ordinal.ToString([System.Globalization.CultureInfo]::InvariantCulture) + $tab + 'not-a-real-check' + $tab + 'pass')
        $ordinal++
    }
    if ($Mutation -ceq 'DuplicateCheck' -and $rows.Count -gt 0) {
        $rows.Add($rows[0])
    }
    if ($Mutation -ceq 'OutOfOrderCheck' -and $rows.Count -ge 2) {
        $swap = $rows[0]; $rows[0] = $rows[1]; $rows[1] = $swap
    }
    foreach ($row in $rows) { $lines.Add($row) }
    $summaryCount = $emitted.Count
    $summaryStatus = 'pass'
    if ($Mutation -ceq 'BadSummaryCount') { $summaryCount = $summaryCount + 1 }
    if ($Mutation -ceq 'BadSummaryStatus') { $summaryStatus = 'fail' }
    if ($Mutation -cne 'MissingSummary') {
        $lines.Add('summary' + $tab + $summaryCount.ToString([System.Globalization.CultureInfo]::InvariantCulture) + $tab + $summaryStatus)
    }
    $text = ($lines -join $lf) + $lf
    $bytes = (New-PspktUtf8NoBom).GetBytes($text)
    if ($Mutation -ceq 'ExtraBytes') {
        $bytes = $bytes + [byte[]](0x78, 0x79, 0x7A)
    }
    if ($Mutation -ceq 'Oversize') {
        $bytes = $bytes + [byte[]]::new(70000)
    }
    if ($Mutation -ceq 'MalformedUtf8') {
        $bytes = $bytes + [byte[]](0xC0, 0x80)
    }
    if ($Mutation -ceq 'Bom') {
        $bytes = [byte[]](0xEF, 0xBB, 0xBF) + $bytes
    }
    $stream = [System.IO.FileStream]::new($ResultPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Read-PspktSealedWorkerResult {
    param(
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string[]]$ExpectedCheckIds
    )
    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        throw 'worker result: path is absent.'
    }
    $info = [System.IO.FileInfo]::new($ResultPath)
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw 'worker result: path is a reparse point.'
    }
    $bytes = Read-PspktBoundedFileBytes -FullPath $ResultPath -ByteCap 65536
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'worker result: unexpected BOM.'
    }
    $text = (New-PspktUtf8NoBom).GetString($bytes)
    $tab = [char]0x09
    $lines = @($text -split "`n")
    if ($lines.Count -lt 2) { throw 'worker result: too few lines.' }
    if ($lines[$lines.Count - 1] -cne '') { throw 'worker result: missing terminal newline.' }
    $body = @($lines[0..($lines.Count - 2)])
    $header = $body[0] -split $tab
    if ($header.Count -ne 3 -or $header[0] -cne 'pspkt-phase4-worker-result-v1') { throw 'worker result: bad header tag.' }
    if ($header[1] -cne $ExpectedNonce) { throw 'worker result: nonce mismatch.' }
    if ($header[2] -cne $ExpectedVersion) { throw 'worker result: version mismatch.' }
    $checkRows = @()
    $summaryRow = $null
    for ($i = 1; $i -lt $body.Count; $i++) {
        $fields = $body[$i] -split $tab
        if ($fields[0] -ceq 'check') { $checkRows += , $fields; continue }
        if ($fields[0] -ceq 'summary') {
            if ($null -ne $summaryRow) { throw 'worker result: duplicate summary.' }
            $summaryRow = $fields
            continue
        }
        throw ('worker result: unknown record "{0}".' -f $fields[0])
    }
    if ($null -eq $summaryRow) { throw 'worker result: missing summary.' }
    if ($checkRows.Count -ne $ExpectedCheckIds.Count) { throw 'worker result: check-row count mismatch.' }
    $seen = @{}
    for ($i = 0; $i -lt $ExpectedCheckIds.Count; $i++) {
        $fields = $checkRows[$i]
        if ($fields.Count -ne 4) { throw 'worker result: malformed check row.' }
        if ($fields[1] -cne $i.ToString([System.Globalization.CultureInfo]::InvariantCulture)) { throw 'worker result: out-of-order ordinal.' }
        if ($fields[2] -cne $ExpectedCheckIds[$i]) { throw 'worker result: unexpected check id.' }
        if ($seen.ContainsKey($fields[2])) { throw 'worker result: duplicate check id.' }
        $seen[$fields[2]] = $true
        if ($fields[3] -cne 'pass') { throw 'worker result: non-pass check status.' }
    }
    if ($summaryRow.Count -ne 3) { throw 'worker result: malformed summary row.' }
    if ($summaryRow[1] -cne $ExpectedCheckIds.Count.ToString([System.Globalization.CultureInfo]::InvariantCulture)) { throw 'worker result: summary count mismatch.' }
    if ($summaryRow[2] -cne 'pass') { throw 'worker result: summary status not pass.' }
    return $true
}

function Read-PspktSealedGeneratorResult {
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedResultRoot,
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce
    )
    $canonicalPath = Assert-PspktContainedDirectLeaf -ExpectedRoot $ExpectedResultRoot -LeafPath $ResultPath -Label 'generator result'
    $preAuthorityInfo = [System.IO.FileInfo]::new($canonicalPath)
    $preAuthorityLength = [long]$preAuthorityInfo.Length
    $stream = [System.IO.FileStream]::new(
        $canonicalPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $bytes = Read-PspktBoundedStreamBytes -Stream $stream -ByteCap 8192
        $postAuthorityInfo = [System.IO.FileInfo]::new($canonicalPath)
        $postAuthorityInfo.Refresh()
        if (($postAuthorityInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($postAuthorityInfo.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
            [long]$postAuthorityInfo.Length -ne $preAuthorityLength -or
            [long]$stream.Length -ne [long]$bytes.Length) {
            throw 'generator result: retained result handle changed identity during the bounded read.'
        }
    }
    finally {
        $stream.Dispose()
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'generator result: unexpected BOM.'
    }
    $text = (New-PspktUtf8NoBom).GetString($bytes)
    $tab = [char]0x09
    $lines = @($text -split "`n")
    if ($lines.Count -lt 2 -or $lines[$lines.Count - 1] -cne '') { throw 'generator result: missing terminal newline.' }
    $body = @($lines[0..($lines.Count - 2)])
    $header = $body[0] -split $tab
    if ($header.Count -ne 4 -or $header[0] -cne 'pspkt-phase4-generator-result-v1') { throw 'generator result: bad header.' }
    if ($header[1] -cne $ExpectedNonce) { throw 'generator result: nonce mismatch.' }
    $checkRows = @()
    $digestRow = $null
    $hardlinkRow = $null
    $summaryRow = $null
    for ($i = 1; $i -lt $body.Count; $i++) {
        $fields = $body[$i] -split $tab
        switch ($fields[0]) {
            'check' { $checkRows += , $fields }
            'digest' { if ($null -ne $digestRow) { throw 'generator result: duplicate digest.' }; $digestRow = $fields }
            'hardlink' { if ($null -ne $hardlinkRow) { throw 'generator result: duplicate hardlink.' }; $hardlinkRow = $fields }
            'summary' { if ($null -ne $summaryRow) { throw 'generator result: duplicate summary.' }; $summaryRow = $fields }
            default { throw ('generator result: unknown record "{0}".' -f $fields[0]) }
        }
    }
    if ($checkRows.Count -ne $script:ExpectedGeneratorCheckIds.Count) { throw 'generator result: check-row count mismatch.' }
    for ($i = 0; $i -lt $script:ExpectedGeneratorCheckIds.Count; $i++) {
        $fields = $checkRows[$i]
        if ($fields.Count -ne 4) { throw 'generator result: malformed check row.' }
        if ($fields[1] -cne $i.ToString([System.Globalization.CultureInfo]::InvariantCulture)) { throw 'generator result: out-of-order ordinal.' }
        if ($fields[2] -cne $script:ExpectedGeneratorCheckIds[$i]) { throw 'generator result: unexpected check id.' }
        if ($fields[3] -cne 'pass') { throw 'generator result: non-pass status.' }
    }
    if ($null -eq $digestRow -or $digestRow.Count -ne 2 -or -not [regex]::IsMatch($digestRow[1], '^[0-9a-f]{64}$')) { throw 'generator result: malformed digest.' }
    if ($null -eq $hardlinkRow -or $hardlinkRow.Count -ne 13) { throw 'generator result: malformed hardlink record.' }
    if (-not [regex]::IsMatch($hardlinkRow[1], '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') -or
        -not [regex]::IsMatch($hardlinkRow[2], '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') -or
        $hardlinkRow[1] -ceq $hardlinkRow[2]) {
        throw 'generator result: malformed hardlink leaf.'
    }
    $sourcePreFileId = $hardlinkRow[3]
    $linkPreFileId = $hardlinkRow[4]
    $sourcePostFileId = $hardlinkRow[7]
    $linkPostFileId = $hardlinkRow[8]
    foreach ($fileId in @($sourcePreFileId, $linkPreFileId, $sourcePostFileId, $linkPostFileId)) {
        if (-not [regex]::IsMatch($fileId, '^[0-9a-f]{48}$')) { throw 'generator result: malformed hardlink file id.' }
    }
    if ($sourcePreFileId -cne $linkPreFileId -or $linkPostFileId -cne $sourcePreFileId) { throw 'generator result: pre/link file identity mismatch.' }
    if ($sourcePostFileId -ceq $linkPostFileId) { throw 'generator result: post replacement identity did not diverge.' }
    foreach ($lengthIndex in @(5, 9, 11)) {
        if (-not [regex]::IsMatch($hardlinkRow[$lengthIndex], '^(0|[1-9][0-9]*)$')) {
            throw 'generator result: malformed hardlink length.'
        }
    }
    foreach ($hashIndex in @(6, 10, 12)) {
        if (-not [regex]::IsMatch($hardlinkRow[$hashIndex], '^[0-9a-f]{64}$')) {
            throw 'generator result: malformed hardlink digest.'
        }
    }
    if ($hardlinkRow[5] -cne $hardlinkRow[11] -or $hardlinkRow[6] -cne $hardlinkRow[12] -or
        ($hardlinkRow[9] -ceq $hardlinkRow[11] -and $hardlinkRow[10] -ceq $hardlinkRow[12])) {
        throw 'generator result: hardlink pre/post content equations failed.'
    }
    if ($null -eq $summaryRow -or $summaryRow.Count -ne 3 -or $summaryRow[1] -cne '4' -or $summaryRow[2] -cne 'pass') { throw 'generator result: malformed summary.' }
    return [pscustomobject]@{
        HostEdition = $header[2]
        HostVersion = $header[3]
        Digest = $digestRow[1]
        HardlinkRow = [string[]]$hardlinkRow
    }
}

function Get-PspktRejectReservedValues {
    param(
        [AllowNull()]
        [string[]]$Names
    )
    if ($null -eq $Names) { return $null }
    $values = @()
    for ($index = 0; $index -lt $Names.Count; $index++) {
        $values += ('pspkt-phase4-reject-value-' + $index.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    }
    return [string[]]$values
}

function Remove-PspktRejectTempDirectories {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$TempDirectories
    )
    for ($index = $TempDirectories.Count - 1; $index -ge 0; $index--) {
        $path = $TempDirectories[$index]
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $path) {
            throw ('reject probe cleanup did not remove "{0}".' -f $path)
        }
    }
}

function New-PspktGateProbeChildConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)][string[]]$ReservedNames,
        [Parameter(Mandatory = $true)][string[]]$ReservedValues,
        [Parameter(Mandatory = $true)][string]$GateEventName,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    $role = Get-PspktHelperEnum -Binding $Binding -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
    $gateVariable = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRoleGateVariable' -Arguments @($role)
    return Invoke-PspktHelperStatic -Binding $Binding -Method 'CreateProcessLaunchConfiguration' -Arguments @(
        $role,
        $ExecutablePath,
        ([string[]]$Arguments),
        $GateEventName,
        $gateVariable,
        ([string[]]@()),
        ([string[]]@()),
        ([string[]]$ReservedNames),
        ([string[]]$ReservedValues),
        60000, 15000, 15000, 65536,
        $false,
        $CorrelationId,
        $WorkingDirectory,
        $null,
        $null,
        $null,
        $null
    )
}

function ConvertTo-PspktSingleQuotedLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )
    return "'" + $Value.Replace("'", "''") + "'"
}

function New-PspktProcessOracleContext {
    param(
        [Parameter(Mandatory = $true)][string]$Tag,
        [AllowNull()][AllowEmptyString()][string]$ParentAuthorityRoot = $null
    )
    Assert-PspktQuarantineLaunchAdmitted -Label ('process oracle context "{0}"' -f $Tag)
    if ([string]::IsNullOrEmpty($ParentAuthorityRoot)) {
        $root = New-PspktTempDirectory -Prefix ('pspkt-phase4-' + $Tag + '-')
    }
    else {
        $canonicalParent = Assert-PspktStrictAuthorityRoot -Root $ParentAuthorityRoot -Label ('process oracle parent authority for "{0}"' -f $Tag)
        $trimmedParent = $canonicalParent.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar)
        $childCandidate = Join-Path $trimmedParent ('oracle-' + $Tag + '-' + [Guid]::NewGuid().ToString('N'))
        if (Test-Path -LiteralPath $childCandidate) {
            throw ('process oracle: child directory "{0}" already exists beneath authority root "{1}".' -f $childCandidate, $canonicalParent)
        }
        [void][System.IO.Directory]::CreateDirectory($childCandidate)
        $root = [System.IO.Path]::GetFullPath($childCandidate)
        $parentPrefix = $trimmedParent + [System.IO.Path]::DirectorySeparatorChar
        if (-not $root.StartsWith($parentPrefix, [System.StringComparison]::Ordinal)) {
            throw ('process oracle: child root "{0}" is not canonically contained by authority root "{1}".' -f $root, $canonicalParent)
        }
        $rootParent = [System.IO.Path]::GetDirectoryName($root)
        if ([string]::IsNullOrEmpty($rootParent) -or
            ($rootParent.TrimEnd(
                [System.IO.Path]::DirectorySeparatorChar,
                [System.IO.Path]::AltDirectorySeparatorChar) -cne $trimmedParent)) {
            throw ('process oracle: child root "{0}" is not a direct child of authority root "{1}".' -f $root, $canonicalParent)
        }
    }
    $workingDirectory = Join-Path $root ('working-' + [Guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($workingDirectory)
    if (-not (Test-PspktNonReparseDirectory -FullPath $root) -or
        -not (Test-PspktNonReparseDirectory -FullPath $workingDirectory)) {
        throw ('process oracle: private directories for "{0}" are unavailable or reparse points.' -f $Tag)
    }
    return [pscustomobject]@{
        Root = $root
        WorkingDirectory = $workingDirectory
    }
}

function Remove-PspktProcessOracleContext {
    param([Parameter(Mandatory = $true)]$Context)
    if (Test-Path -LiteralPath $Context.Root) {
        Remove-Item -LiteralPath $Context.Root -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $Context.Root) {
        throw ('process oracle cleanup did not remove "{0}".' -f $Context.Root)
    }
}

function New-PspktGateFirstScript {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][ValidateSet('Required', 'Missing')][string]$GateMode,
        [int]$LiteralGateTimeoutMilliseconds = 60000,
        [switch]$UseGateTimeoutEnvironment,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$PostGateLines
    )
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add("`$gateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GATE_EVENT')")
    if ($GateMode -ceq 'Missing') {
        [void]$lines.Add('if ([string]::IsNullOrEmpty($gateName)) { exit 10 }')
        [void]$lines.Add('exit 12')
    }
    else {
        [void]$lines.Add("if ([string]::IsNullOrEmpty(`$gateName) -or -not [regex]::IsMatch(`$gateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 10 }")
        if ($UseGateTimeoutEnvironment.IsPresent) {
            [void]$lines.Add("`$gateTimeoutText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GATE_TIMEOUT_MS')")
            [void]$lines.Add('$gateTimeoutMilliseconds = 0')
            [void]$lines.Add('if (-not [int]::TryParse($gateTimeoutText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$gateTimeoutMilliseconds) -or $gateTimeoutMilliseconds -lt 1) { exit 10 }')
        }
        else {
            [void]$lines.Add(('$gateTimeoutMilliseconds = {0}' -f $LiteralGateTimeoutMilliseconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)))
        }
        [void]$lines.Add('try {')
        [void]$lines.Add('    $gate = [System.Threading.EventWaitHandle]::OpenExisting($gateName)')
        [void]$lines.Add('}')
        [void]$lines.Add('catch [System.Threading.WaitHandleCannotBeOpenedException] {')
        [void]$lines.Add('    exit 10')
        [void]$lines.Add('}')
        [void]$lines.Add('catch [System.UnauthorizedAccessException] {')
        [void]$lines.Add('    exit 10')
        [void]$lines.Add('}')
        [void]$lines.Add('try {')
        [void]$lines.Add('    if (-not $gate.WaitOne($gateTimeoutMilliseconds)) { exit 11 }')
        [void]$lines.Add('}')
        [void]$lines.Add('finally {')
        [void]$lines.Add('    $gate.Close()')
        [void]$lines.Add('}')
    }
    foreach ($line in $PostGateLines) {
        [void]$lines.Add($line)
    }

    $scriptPath = Join-Path $Context.Root ('gate-first-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $bytes = (New-PspktUtf8NoBom).GetBytes(($lines -join "`r`n") + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function Get-PspktMarkerWriterLines {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$Tag
    )
    $pathLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $MarkerPath
    $tagLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $Tag
    return [string[]]@(
        ('$markerPath = {0}' -f $pathLiteral),
        '$probeNonce = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_PROBE_NONCE'')',
        ('$markerRecord = {0} + [char]0x09 + $probeNonce + [char]0x0A' -f $tagLiteral),
        '$markerBytes = [System.Text.Encoding]::ASCII.GetBytes($markerRecord)',
        '$markerStream = [System.IO.FileStream]::new($markerPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)',
        'try {',
        '    $markerStream.Write($markerBytes, 0, $markerBytes.Length)',
        '    $markerStream.Flush($true)',
        '}',
        'finally {',
        '    $markerStream.Dispose()',
        '}'
    )
}

function Get-PspktVerifiedHelperLoadLines {
    param(
        [AllowNull()]
        $Binding = $null
    )
    $authorityLines = if ($null -eq $Binding) {
        [string[]]@(
            '$helperPath = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_HELPER_PATH'')',
            '$expectedHelperSha = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_HELPER_SHA256'')',
            '$expectedHelperVersion = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_HELPER_VERSION'')'
        )
    }
    else {
        [string[]]@(
            ('$helperPath = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value ([string]$Binding.Path))),
            ('$expectedHelperSha = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value ([string]$Binding.Digest))),
            ('$expectedHelperVersion = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value ([string]$Binding.Version)))
        )
    }
    return [string[]]@($authorityLines + @(
        'if ([string]::IsNullOrEmpty($helperPath) -or [string]::IsNullOrEmpty($expectedHelperSha) -or [string]::IsNullOrEmpty($expectedHelperVersion)) { exit 3 }',
        '$helperInfo = [System.IO.FileInfo]::new($helperPath)',
        'if (-not $helperInfo.Exists -or ($helperInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $helperInfo.Length -gt 4194304) { exit 3 }',
        '$helperStream = [System.IO.FileStream]::new($helperPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)',
        'try {',
        '    $helperBytes = [byte[]]::new([int]$helperStream.Length)',
        '    $helperOffset = 0',
        '    while ($helperOffset -lt $helperBytes.Length) {',
        '        $helperRead = $helperStream.Read($helperBytes, $helperOffset, $helperBytes.Length - $helperOffset)',
        '        if ($helperRead -le 0) { exit 3 }',
        '        $helperOffset += $helperRead',
        '    }',
        '}',
        'finally {',
        '    $helperStream.Dispose()',
        '}',
        '$helperHasher = [System.Security.Cryptography.SHA256]::Create()',
        'try {',
        '    $helperHash = $helperHasher.ComputeHash($helperBytes)',
        '}',
        'finally {',
        '    $helperHasher.Dispose()',
        '}',
        '$helperDigestBuilder = [System.Text.StringBuilder]::new(64)',
        'foreach ($helperHashByte in $helperHash) { [void]$helperDigestBuilder.Append($helperHashByte.ToString(''x2'', [System.Globalization.CultureInfo]::InvariantCulture)) }',
        'if ($helperDigestBuilder.ToString() -cne $expectedHelperSha) { exit 4 }',
        '$helperAssembly = [System.Reflection.Assembly]::Load($helperBytes)',
        '$helperHostType = $helperAssembly.GetType(''Pspkt.Certification.BoundedProcessHost'', $true)',
        '$helperVersionField = $helperHostType.GetField(''Version'', [System.Reflection.BindingFlags]''Public, Static'')',
        'if ([string]$helperVersionField.GetValue($null) -cne $expectedHelperVersion) { exit 5 }'
    ))
}

function New-PspktProcessOracleConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ReservedValueByName,
        [AllowNull()]
        [object]$GateEventName = $null,
        [int]$WaitTimeoutMilliseconds = 10000,
        [int]$TerminateGraceMilliseconds = 10000,
        [int]$DrainDeadlineMilliseconds = 10000,
        [int]$RetainCapBytes = 65536,
        [bool]$SimulateAssignFailure = $false,
        [string[]]$ExtraArguments = @()
    )
    $roleValue = Get-PspktHelperEnum -Binding $Binding -EnumName 'ProcessLaunchRole' -Member $Role
    $requiredNames = [string[]]@(Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRequiredReservedNames' -Arguments @($roleValue))
    if ($requiredNames.Count -ne $ReservedValueByName.Count) {
        throw ('process oracle: role {0} requires {1} reserved values, but {2} were supplied.' -f $Role, $requiredNames.Count, $ReservedValueByName.Count)
    }
    $reservedValues = [System.Collections.Generic.List[string]]::new()
    foreach ($requiredName in $requiredNames) {
        $matchingKey = $null
        foreach ($candidateKey in $ReservedValueByName.Keys) {
            if ([string]$candidateKey -ceq $requiredName) {
                $matchingKey = [string]$candidateKey
                break
            }
        }
        if ($null -eq $matchingKey) {
            throw ('process oracle: role {0} is missing exact reserved value "{1}".' -f $Role, $requiredName)
        }
        $reservedValue = $ReservedValueByName[$matchingKey]
        if ($null -eq $reservedValue) {
            throw ('process oracle: role {0} has a null reserved value for "{1}".' -f $Role, $requiredName)
        }
        [void]$reservedValues.Add([string]$reservedValue)
    }
    $gateVariable = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRoleGateVariable' -Arguments @($roleValue)
    $factoryArguments = [object[]]::new(20)
    $factoryArguments[0] = $roleValue
    $factoryArguments[1] = [string](Get-PspktHostExecutable)
    $factoryArguments[2] = [string[]]@(@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ScriptPath) + $ExtraArguments)
    $gateEventNameValue = $GateEventName
    if ($GateEventName -is [System.Management.Automation.PSObject]) {
        $gateEventNameValue = $GateEventName.BaseObject
    }
    if ($null -eq $gateEventNameValue) {
        $factoryArguments[3] = $null
    }
    else {
        $factoryArguments[3] = [string]$gateEventNameValue
    }
    if ($null -eq $gateVariable) {
        $factoryArguments[4] = $null
    }
    else {
        $factoryArguments[4] = [string]$gateVariable
    }
    $factoryArguments[5] = [string[]]@()
    $factoryArguments[6] = [string[]]@()
    $factoryArguments[7] = [string[]]$requiredNames
    $factoryArguments[8] = [string[]]$reservedValues.ToArray()
    $factoryArguments[9] = $WaitTimeoutMilliseconds
    $factoryArguments[10] = $TerminateGraceMilliseconds
    $factoryArguments[11] = $DrainDeadlineMilliseconds
    $factoryArguments[12] = $RetainCapBytes
    $factoryArguments[13] = $SimulateAssignFailure
    $factoryArguments[14] = [Guid]::NewGuid()
    $factoryArguments[15] = [string]$Context.WorkingDirectory
    $factoryArguments[16] = $null
    $factoryArguments[17] = $null
    $factoryArguments[18] = $null
    $factoryArguments[19] = $null
    return Invoke-PspktHelperStatic -Binding $Binding -Method 'CreateProcessLaunchConfiguration' -Arguments $factoryArguments
}

function Close-PspktDirectLaunchSession {
    param([Parameter(Mandatory = $true)]$Session)
    if (-not $Session.HasExited) {
        $Session.TerminateAndWait(15000)
    }
    if (-not $Session.HasExited) {
        throw ('direct-launch child {0} remained active after termination.' -f $Session.ProcessId)
    }
    $pathErrors = @($Session.ReleasePathBinding())
    if ($pathErrors.Count -ne 0) {
        throw [System.AggregateException]::new('direct-launch path cleanup failed.', [Exception[]]$pathErrors)
    }
    $Session.Dispose()
}

function Test-PspktExactAsciiFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $expectedBytes = [System.Text.Encoding]::ASCII.GetBytes($Expected)
    $actualBytes = Read-PspktBoundedFileBytes -FullPath $Path -ByteCap ([Math]::Max(1, $expectedBytes.Length))
    if ($actualBytes.Length -ne $expectedBytes.Length) { return $false }
    for ($index = 0; $index -lt $expectedBytes.Length; $index++) {
        if ($actualBytes[$index] -ne $expectedBytes[$index]) { return $false }
    }
    return $true
}

function Test-PspktExpectedHelperException {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$ExpectedTypeName
    )
    try {
        & $Action | Out-Null
    }
    catch [System.Management.Automation.MethodInvocationException] {
        $exception = $_.Exception
        while ($null -ne $exception.InnerException) {
            $exception = $exception.InnerException
        }
        if ($exception.GetType().FullName -cne $ExpectedTypeName) {
            throw
        }
        return $true
    }
    catch [System.Reflection.TargetInvocationException] {
        $exception = $_.Exception
        while ($null -ne $exception.InnerException) {
            $exception = $exception.InnerException
        }
        if ($exception.GetType().FullName -cne $ExpectedTypeName) {
            throw
        }
        return $true
    }
    throw ('process oracle: expected helper exception "{0}" was not thrown.' -f $ExpectedTypeName)
}

function Add-PspktFlattenedFailure {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[Exception]]$Target,
        [Parameter(Mandatory = $true)][Exception]$Failure
    )
    if ($Failure -is [System.AggregateException]) {
        foreach ($inner in ([System.AggregateException]$Failure).InnerExceptions) {
            if ($null -ne $inner) {
                Add-PspktFlattenedFailure -Target $Target -Failure $inner
            }
        }
        return
    }
    [void]$Target.Add($Failure)
}

function New-PspktComposedFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [AllowNull()]
        [Exception]$PrimaryFailure = $null,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Exception[]]$CleanupFailures
    )
    if ($null -eq $PrimaryFailure -and $CleanupFailures.Count -eq 0) {
        return $null
    }
    if ($null -ne $PrimaryFailure -and $CleanupFailures.Count -eq 0) {
        return $PrimaryFailure
    }
    $failures = [System.Collections.Generic.List[Exception]]::new()
    if ($null -ne $PrimaryFailure) {
        Add-PspktFlattenedFailure -Target $failures -Failure $PrimaryFailure
    }
    foreach ($cleanupFailure in $CleanupFailures) {
        if ($null -ne $cleanupFailure) {
            Add-PspktFlattenedFailure -Target $failures -Failure $cleanupFailure
        }
    }
    if ($failures.Count -eq 0) {
        return $null
    }
    return [System.AggregateException]::new($Message, [Exception[]]$failures.ToArray())
}

function Test-PspktExceptionTreeContainsType {
    param(
        [Parameter(Mandatory = $true)][Exception]$Exception,
        [Parameter(Mandatory = $true)][string]$FullTypeName
    )
    if ($Exception.GetType().FullName -ceq $FullTypeName) {
        return $true
    }
    if ($Exception -is [System.AggregateException]) {
        foreach ($inner in ([System.AggregateException]$Exception).InnerExceptions) {
            if ($null -ne $inner -and (Test-PspktExceptionTreeContainsType -Exception $inner -FullTypeName $FullTypeName)) {
                return $true
            }
        }
        return $false
    }
    if ($null -ne $Exception.InnerException) {
        return (Test-PspktExceptionTreeContainsType -Exception $Exception.InnerException -FullTypeName $FullTypeName)
    }
    return $false
}

function Get-PspktInnermostException {
    param([Parameter(Mandatory = $true)][Exception]$Exception)
    $current = $Exception
    while ($true) {
        if ($current -is [System.AggregateException]) {
            break
        }
        if ($null -eq $current.InnerException) {
            break
        }
        $current = $current.InnerException
    }
    return $current
}

function New-PspktDelayedEventSignalThread {
    param(
        [Parameter(Mandatory = $true)]$NamedEvent,
        [Parameter(Mandatory = $true)][int]$DelayMilliseconds
    )
    $state = [object[]]@($NamedEvent, $null)
    $stateExpression = [System.Linq.Expressions.Expression]::Constant($state, [object[]])
    $sleepMethod = [System.Threading.Thread].GetMethod('Sleep', ([Type[]]@([int])))
    $sleepExpression = [System.Linq.Expressions.Expression]::Call(
        $sleepMethod,
        ([System.Linq.Expressions.Expression[]]@(
            [System.Linq.Expressions.Expression]::Constant($DelayMilliseconds)
        )))
    $eventExpression = [System.Linq.Expressions.Expression]::Convert(
        [System.Linq.Expressions.Expression]::ArrayIndex(
            $stateExpression,
            [System.Linq.Expressions.Expression]::Constant(0)),
        $NamedEvent.GetType())
    $setExpression = [System.Linq.Expressions.Expression]::Call(
        $eventExpression,
        $NamedEvent.GetType().GetMethod('SetEvent', ([Type[]]@())),
        ([System.Linq.Expressions.Expression[]]@()))
    $tryBody = [System.Linq.Expressions.Expression]::Block(
        [System.Linq.Expressions.Expression[]]@($sleepExpression, $setExpression))
    $caughtException = [System.Linq.Expressions.Expression]::Parameter([Exception], 'signalError')
    $storeException = [System.Linq.Expressions.Expression]::Assign(
        [System.Linq.Expressions.Expression]::ArrayAccess(
            $stateExpression,
            ([System.Linq.Expressions.Expression[]]@(
                [System.Linq.Expressions.Expression]::Constant(1)
            ))),
        [System.Linq.Expressions.Expression]::Convert($caughtException, [object]))
    $catchBody = [System.Linq.Expressions.Expression]::Block(
        [System.Linq.Expressions.Expression[]]@(
            $storeException,
            [System.Linq.Expressions.Expression]::Empty()
        ))
    $catchBlock = [System.Linq.Expressions.Expression]::Catch($caughtException, $catchBody)
    $threadBody = [System.Linq.Expressions.Expression]::TryCatch(
        $tryBody,
        ([System.Linq.Expressions.CatchBlock[]]@($catchBlock)))
    $threadStart = [System.Linq.Expressions.Expression]::Lambda(
        [System.Threading.ThreadStart],
        $threadBody,
        ([System.Linq.Expressions.ParameterExpression[]]@())).Compile()
    $thread = [System.Threading.Thread]::new($threadStart)
    $thread.IsBackground = $true
    $thread.Name = 'PspktPhase4DelayedGateSignal'
    return [pscustomobject]@{
        Thread = $thread
        State = $state
    }
}

function Initialize-PspktPauseObserverType {
    if ($null -ne ('PspktPhase4.PauseObserver' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Threading;

namespace PspktPhase4
{
    public sealed class PauseObserver : IDisposable
    {
        private readonly string identityDirectory;
        private readonly string expectedGateName;
        private readonly object readinessEvent;
        private readonly object acknowledgementEvent;
        private readonly object armedEvent;
        private readonly object releaseEvent;
        private readonly string evidenceDirectory;
        private readonly long assignmentCountBefore;
        private readonly bool acknowledge;
        private readonly bool release;
        private readonly ManualResetEvent started = new ManualResetEvent(false);
        private readonly ManualResetEvent completed = new ManualResetEvent(false);
        private readonly ManualResetEvent cancelled = new ManualResetEvent(false);
        private readonly Thread thread;
        private Exception exception;
        private int childProcessId;
        private long childStartFileTimeUtc;
        private readonly int joinTimeoutMilliseconds;
        private readonly ManualResetEvent stallGate;
        private readonly object disposeLock = new object();
        private bool disposed;

        public PauseObserver(
            string identityDirectory,
            string expectedGateName,
            object readinessEvent,
            object acknowledgementEvent,
            object armedEvent,
            object releaseEvent,
            string evidenceDirectory,
            long assignmentCountBefore,
            bool acknowledge,
            bool release)
        {
            this.identityDirectory = identityDirectory;
            this.expectedGateName = expectedGateName;
            this.readinessEvent = readinessEvent;
            this.acknowledgementEvent = acknowledgementEvent;
            this.armedEvent = armedEvent;
            this.releaseEvent = releaseEvent;
            this.evidenceDirectory = evidenceDirectory;
            this.assignmentCountBefore = assignmentCountBefore;
            this.acknowledge = acknowledge;
            this.release = release;
            this.joinTimeoutMilliseconds = 10000;
            this.stallGate = null;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "PspktPhase4PauseObserver";
        }

        private PauseObserver(int joinTimeoutMilliseconds)
        {
            this.stallGate = new ManualResetEvent(false);
            this.joinTimeoutMilliseconds = joinTimeoutMilliseconds;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "PspktPhase4PauseObserverStall";
        }

        public static PauseObserver CreateCertificationStallProbe(int joinTimeoutMilliseconds)
        {
            return new PauseObserver(joinTimeoutMilliseconds);
        }

        public void ReleaseCertificationStall()
        {
            ManualResetEvent gate = stallGate;
            if (gate != null) { gate.Set(); }
        }

        public bool StallHandlesUsable()
        {
            try
            {
                started.WaitOne(0);
                completed.WaitOne(0);
                cancelled.WaitOne(0);
                if (stallGate != null) { stallGate.WaitOne(0); }
                return true;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        public int ChildProcessId { get { return childProcessId; } }
        public long ChildStartFileTimeUtc { get { return childStartFileTimeUtc; } }
        public Exception Exception { get { return exception; } }

        public void Start()
        {
            thread.Start();
            if (!started.WaitOne(10000))
            {
                throw new InvalidOperationException("pause observer did not reach its startup latch.");
            }
        }

        public bool Join(int milliseconds)
        {
            return thread.Join(milliseconds);
        }

        public void Cancel()
        {
            cancelled.Set();
        }

        private void Run()
        {
            try
            {
                started.Set();
                if (stallGate != null)
                {
                    stallGate.WaitOne();
                    return;
                }
                WaitForNamedEvent(readinessEvent, 10000, "pause observer did not receive readiness.");

                ParseIdentity();
                using (Process child = Process.GetProcessById(childProcessId))
                {
                    if (child.StartTime.ToFileTimeUtc() != childStartFileTimeUtc)
                    {
                        throw new InvalidDataException("pause child identity receipt did not retain the exact child start time.");
                    }
                }

                if (!acknowledge) { return; }

                SetNamedEvent(acknowledgementEvent);
                WaitForNamedEvent(armedEvent, 10000, "pause observer did not receive release-wait-armed.");

                Stopwatch hold = Stopwatch.StartNew();
                while (hold.ElapsedMilliseconds < 250)
                {
                    if (cancelled.WaitOne(0)) { return; }
                    if (GetAssignmentCount() != assignmentCountBefore)
                    {
                        throw new InvalidOperationException("assignment occurred before the observer released the pre-assignment pause.");
                    }
                    if (File.Exists(Path.Combine(evidenceDirectory, "assignment-evidence.txt")))
                    {
                        throw new InvalidOperationException("assignment evidence existed before the observer released the pre-assignment pause.");
                    }
                    Thread.Sleep(10);
                }

                if (release) { SetNamedEvent(releaseEvent); }
            }
            catch (Exception observed)
            {
                exception = observed;
            }
            finally
            {
                completed.Set();
            }
        }

        private void WaitForNamedEvent(object namedEvent, int timeoutMilliseconds, string timeoutMessage)
        {
            Stopwatch wait = Stopwatch.StartNew();
            while (wait.ElapsedMilliseconds < timeoutMilliseconds)
            {
                if (cancelled.WaitOne(0)) { return; }
                if (IsNamedEventSignaled(namedEvent)) { return; }
                Thread.Sleep(10);
            }
            if (IsNamedEventSignaled(namedEvent)) { return; }
            throw new TimeoutException(timeoutMessage);
        }

        private static bool IsNamedEventSignaled(object namedEvent)
        {
            MethodInfo method = namedEvent.GetType().GetMethod("IsSignaledNow", Type.EmptyTypes);
            if (method == null) { throw new InvalidOperationException("pause observer NamedEvent has no IsSignaledNow method."); }
            return (bool)method.Invoke(namedEvent, null);
        }

        private static void SetNamedEvent(object namedEvent)
        {
            MethodInfo method = namedEvent.GetType().GetMethod("SetEvent", Type.EmptyTypes);
            if (method == null) { throw new InvalidOperationException("pause observer NamedEvent has no SetEvent method."); }
            method.Invoke(namedEvent, null);
        }

        private void ParseIdentity()
        {
            string identityPath = Path.Combine(identityDirectory, "child-identity.txt");
            string gatePath = Path.Combine(identityDirectory, "gate-name.txt");
            byte[] identityBytes = File.ReadAllBytes(identityPath);
            byte[] gateBytes = File.ReadAllBytes(gatePath);
            string identity = StrictAscii(identityBytes, identityPath);
            string gate = StrictAscii(gateBytes, gatePath);
            string[] fields = identity.Split(new char[] { '\t' });
            if (fields.Length != 2 || !identity.EndsWith("\n", StringComparison.Ordinal))
            {
                throw new InvalidDataException("pause child identity receipt grammar is invalid.");
            }
            string processText = fields[0];
            string startText = fields[1].Substring(0, fields[1].Length - 1);
            if (!int.TryParse(processText, NumberStyles.None, CultureInfo.InvariantCulture, out childProcessId) || childProcessId < 1 ||
                !long.TryParse(startText, NumberStyles.None, CultureInfo.InvariantCulture, out childStartFileTimeUtc) || childStartFileTimeUtc < 1)
            {
                throw new InvalidDataException("pause child identity receipt values are invalid.");
            }
            if (!string.Equals(gate, expectedGateName + "\n", StringComparison.Ordinal))
            {
                throw new InvalidDataException("pause gate receipt did not preserve the exact gate name.");
            }
        }

        private static string StrictAscii(byte[] bytes, string path)
        {
            if (bytes == null || bytes.Length == 0 || bytes.Length > 4096) { throw new InvalidDataException("receipt size is invalid: " + path); }
            for (int index = 0; index < bytes.Length; index++)
            {
                if (bytes[index] > 0x7f) { throw new InvalidDataException("receipt is not strict ASCII: " + path); }
            }
            return System.Text.Encoding.ASCII.GetString(bytes);
        }

        private static long GetAssignmentCount()
        {
            foreach (System.Reflection.Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type host = assembly.GetType("Pspkt.Certification.BoundedProcessHost", false);
                if (host == null) { continue; }
                object snapshot = host.GetMethod("GetDiagnosticsSnapshot").Invoke(null, null);
                return (long)snapshot.GetType().GetProperty("AssignmentAttemptCount").GetValue(snapshot, null);
            }
            throw new InvalidOperationException("bounded-process helper assembly is unavailable to pause observer.");
        }

        public void Dispose()
        {
            lock (disposeLock)
            {
                if (disposed) { return; }
                if (Thread.CurrentThread == thread)
                {
                    throw new InvalidOperationException("pause observer cannot dispose itself from its own worker thread.");
                }
                cancelled.Set();
                bool joined = thread.Join(joinTimeoutMilliseconds);
                if (!joined)
                {
                    throw new InvalidOperationException("pause observer worker thread did not terminate within the bounded join; handles retained.");
                }
                started.Close();
                completed.Close();
                cancelled.Close();
                if (stallGate != null) { stallGate.Close(); }
                disposed = true;
            }
        }
    }
}
'@
}

function Test-PspktEmptyDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    return ([System.IO.DirectoryInfo]::new($Path).GetFileSystemInfos().Length -eq 0)
}

function New-PspktPauseConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId,
        [Parameter(Mandatory = $true)][string]$IdentityDirectory,
        [Parameter(Mandatory = $true)][string]$ReadinessEventName,
        [Parameter(Mandatory = $true)][string]$ObserverAckEventName,
        [Parameter(Mandatory = $true)][string]$ReleaseWaitArmedEventName,
        [Parameter(Mandatory = $true)][string]$ReleaseEventName,
        [Parameter(Mandatory = $true)][int]$AckTimeoutMilliseconds,
        [Parameter(Mandatory = $true)][int]$ReleaseTimeoutMilliseconds
    )
    $type = Get-PspktHelperType -Binding $Binding -SimpleName 'PauseConfiguration'
    $parameterTypes = [Type[]]@(
        [Guid], [string], [string], [string], [string], [string], [int], [int])
    $constructor = $type.GetConstructor($parameterTypes)
    if ($null -eq $constructor) {
        throw 'PauseConfiguration constructor contract is absent.'
    }

    return $constructor.Invoke([object[]]@(
        $CorrelationId,
        $IdentityDirectory,
        $ReadinessEventName,
        $ObserverAckEventName,
        $ReleaseWaitArmedEventName,
        $ReleaseEventName,
        $AckTimeoutMilliseconds,
        $ReleaseTimeoutMilliseconds))
}

function New-PspktProbeEvidence {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId
    )
    $type = Get-PspktHelperType -Binding $Binding -SimpleName 'ProbeEvidence'
    $constructor = $type.GetConstructor([Type[]]@([string], [Guid]))
    if ($null -eq $constructor) {
        throw 'ProbeEvidence constructor contract is absent.'
    }
    return $constructor.Invoke([object[]]@($EvidenceDirectory, $CorrelationId))
}

function New-PspktTypedProcessOracleConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ReservedValueByName,
        [Parameter(Mandatory = $true)][string]$GateEventName,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId,
        $PauseConfiguration = $null,
        $ProbeEvidence = $null,
        $ParentLossMembership = $null,
        [int]$WaitTimeoutMilliseconds = 15000
    )
    $roleValue = Get-PspktHelperEnum -Binding $Binding -EnumName 'ProcessLaunchRole' -Member $Role
    $requiredNames = [string[]]@(Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRequiredReservedNames' -Arguments @($roleValue))
    $reservedValues = [System.Collections.Generic.List[string]]::new()
    foreach ($requiredName in $requiredNames) {
        if (-not $ReservedValueByName.Contains($requiredName)) {
            throw ('process oracle: missing required reserved value "{0}" for role "{1}".' -f $requiredName, $Role)
        }
        [void]$reservedValues.Add([string]$ReservedValueByName[$requiredName])
    }
    if ($reservedValues.Count -ne $requiredNames.Count) { throw 'process oracle: required reserved-array cardinality changed.' }
    $gateVariable = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRoleGateVariable' -Arguments @($roleValue)
    return Invoke-PspktHelperStatic -Binding $Binding -Method 'CreateProcessLaunchConfiguration' -Arguments @(
        $roleValue, (Get-PspktHostExecutable), ([string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ScriptPath)),
        $GateEventName, $gateVariable, ([string[]]@()), ([string[]]@()), $requiredNames, ([string[]]$reservedValues.ToArray()),
        $WaitTimeoutMilliseconds, 10000, 10000, 65536, $false, $CorrelationId, $Context.WorkingDirectory,
        $PauseConfiguration, $ProbeEvidence, $ParentLossMembership, $null, $null)
}

function Invoke-PspktPauseLifecycleOracle {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][ValidateSet('positive', 'ack-timeout', 'release-timeout')][string]$Mode
    )
    Initialize-PspktPauseObserverType
    $context = New-PspktProcessOracleContext -Tag ('pause-' + $Mode)
    $events = [System.Collections.Generic.List[object]]::new()
    $observer = $null
    $oracleResult = $false
    $primaryFailure = $null
    try {
        $correlation = [Guid]::NewGuid()
        $nonce = [Guid]::NewGuid().ToString('N')
        $identityDirectory = Join-Path $context.Root 'identity'
        $evidenceDirectory = Join-Path $context.Root 'evidence'
        [void][System.IO.Directory]::CreateDirectory($identityDirectory)
        [void][System.IO.Directory]::CreateDirectory($evidenceDirectory)
        $gateName = New-PspktGateEventName -Tag 'PauseGate'
        $readinessName = New-PspktGateEventName -Tag 'PauseReady'
        $ackName = New-PspktGateEventName -Tag 'PauseAck'
        $armedName = New-PspktGateEventName -Tag 'PauseArmed'
        $releaseName = New-PspktGateEventName -Tag 'PauseRelease'
        $eventDefinitions = @(
            @{ Name = $readinessName; Role = 'Readiness' },
            @{ Name = $ackName; Role = 'ObserverAck' },
            @{ Name = $armedName; Role = 'ReleaseWaitArmed' },
            @{ Name = $releaseName; Role = 'Release' }
        )
        $eventByRole = @{}
        foreach ($definition in $eventDefinitions) {
            $role = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member $definition.Role
            $createdEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($definition.Name, $role, $correlation)
            [void]$events.Add($createdEvent)
            $eventByRole[$definition.Role] = $createdEvent
        }
        $markerPath = Join-Path $context.Root 'post-gate.marker'
        $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 10000 -PostGateLines (@(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-pause-post-gate-v1') + @('exit 0'))
        $pause = New-PspktPauseConfiguration -Binding $Binding -CorrelationId $correlation `
            -IdentityDirectory $identityDirectory -ReadinessEventName $readinessName `
            -ObserverAckEventName $ackName -ReleaseWaitArmedEventName $armedName `
            -ReleaseEventName $releaseName -AckTimeoutMilliseconds 1000 -ReleaseTimeoutMilliseconds 1000
        $evidence = New-PspktProbeEvidence -Binding $Binding -EvidenceDirectory $evidenceDirectory -CorrelationId $correlation
        $reserved = @{
            'PSPKT_PHASE4_PROBE_MODE' = ('pause-' + $Mode)
            'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            'PSPKT_PHASE4_PROBE_MARKER_PATH' = $markerPath
        }
        $configuration = New-PspktTypedProcessOracleConfiguration -Binding $Binding -Role 'PauseReleaseChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reserved -GateEventName $gateName -CorrelationId $correlation -PauseConfiguration $pause -ProbeEvidence $evidence
        $before = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot' -Arguments @()
        $observer = [PspktPhase4.PauseObserver]::new(
            $identityDirectory,
            $gateName,
            $eventByRole['Readiness'],
            $eventByRole['ObserverAck'],
            $eventByRole['ReleaseWaitArmed'],
            $eventByRole['Release'],
            $evidenceDirectory,
            $before.AssignmentAttemptCount,
            ($Mode -cne 'ack-timeout'),
            ($Mode -ceq 'positive'))
        $observer.Start()
        $caught = $null
        $result = $null
        try { $result = Invoke-PspktHelperStatic -Binding $Binding -Method 'Run' -Arguments @($configuration) }
        catch { $caught = $_.Exception; while ($null -ne $caught.InnerException) { $caught = $caught.InnerException } }
        if (-not $observer.Join(10000)) { throw 'pause lifecycle observer did not quiesce within 10 seconds.' }
        if ($null -ne $observer.Exception) { throw $observer.Exception }
        $childStopped = $false
        $childProcess = $null
        try {
            $childProcess = [System.Diagnostics.Process]::GetProcessById($observer.ChildProcessId)
            [void]$childProcess.Handle
            if ($childProcess.StartTime.ToFileTimeUtc() -ne $observer.ChildStartFileTimeUtc) {
                throw 'pause lifecycle child identity changed before stopped-state verification.'
            }
            $childProcess.Refresh()
            $childStopped = $childProcess.HasExited
        }
        catch [System.ArgumentException] {
            $childStopped = $true
        }
        finally {
            if ($null -ne $childProcess) {
                $childProcess.Dispose()
            }
        }
        if (-not $childStopped) { throw 'pause lifecycle child remained active after Run completed.' }
        $after = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot' -Arguments @()
        $expectedAssignment = [System.Text.Encoding]::ASCII.GetString((Invoke-PspktHelperStatic -Binding $Binding -Method 'BuildAssignmentEvidenceRecord' -Arguments @($correlation, $observer.ChildProcessId, $observer.ChildStartFileTimeUtc, $before.AssignmentAttemptCount, ($before.AssignmentAttemptCount + 1))))
        $expectedMarker = 'pspkt-phase4-pause-post-gate-v1' + [char]0x09 + $nonce + [char]0x0A
        if ($Mode -ceq 'positive') {
            $oracleResult = ($null -eq $caught -and $null -ne $result -and $result.ExitCode -eq 0 -and $result.Exited -and
                $result.ActiveProcessesAfterTerminate -eq 0 -and ($after.AssignmentAttemptCount -eq ($before.AssignmentAttemptCount + 1)) -and
                (Test-PspktExactAsciiFile -Path (Join-Path $evidenceDirectory 'assignment-evidence.txt') -Expected $expectedAssignment) -and
                (Test-PspktExactAsciiFile -Path $markerPath -Expected $expectedMarker))
        }
        else {
            $expectedReason = if ($Mode -ceq 'ack-timeout') { 'AckTimeout' } else { 'ReleaseTimeout' }
            $expectedType = (Get-PspktHelperType -Binding $Binding -SimpleName 'PreAssignmentPauseException').FullName
            $oracleResult = ($null -ne $caught -and $caught.GetType().FullName -ceq $expectedType -and
                $caught.PauseReason.ToString() -ceq $expectedReason -and $caught.ChildProcessId -eq $observer.ChildProcessId -and
                $caught.ChildStartTimeFileTimeUtc -eq $observer.ChildStartFileTimeUtc -and
                $after.AssignmentAttemptCount -eq $before.AssignmentAttemptCount -and
                (Test-PspktEmptyDirectory -Path $evidenceDirectory) -and -not (Test-Path -LiteralPath $markerPath))
        }
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    $ownershipClean = $true
    $observerDisposeFailed = $false
    if ($null -ne $observer) {
        try {
            $observer.Dispose()
        }
        catch {
            $ownershipClean = $false
            $observerDisposeFailed = $true
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    if ($observerDisposeFailed) {
        try {
            [void](Add-PspktObserverQuarantineRegistration -Kind 'PauseObserver' -Observer $observer -AuthorityHandles ([object[]]$events.ToArray()) -OracleContext $context)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('pause lifecycle event and context cleanup was withheld because the observer worker thread did not quiesce; the observer, authority events, and context were rooted in the quarantine registry.'))
    }
    else {
        foreach ($eventHandle in $events) {
            try {
                $eventHandle.Close()
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if ($ownershipClean) {
            try {
                Remove-PspktProcessOracleContext -Context $context
            }
            catch {
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        else {
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new('pause lifecycle context cleanup was withheld because event ownership was not clean.'))
        }
    }
    $failure = New-PspktComposedFailure -Message 'pause lifecycle primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
    if ($null -ne $failure) {
        throw $failure
    }
    return $oracleResult
}

function Test-PspktDiagnosticsUnchanged {
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )
    if ($null -eq $Before -or $null -eq $After) { return $false }
    if ($After.JobCreateCount -ne $Before.JobCreateCount) { return $false }
    if ($After.EventCreateCount -ne $Before.EventCreateCount) { return $false }
    if ($After.EventOpenCount -ne $Before.EventOpenCount) { return $false }
    if ($After.ProcessStartCount -ne $Before.ProcessStartCount) { return $false }
    if ($After.AssignmentAttemptCount -ne $Before.AssignmentAttemptCount) { return $false }
    if ($After.RejectCombinedSeamCount -ne $Before.RejectCombinedSeamCount) { return $false }
    if ($After.RejectBasicCount -ne $Before.RejectBasicCount) { return $false }
    if ($After.RejectEventNameCount -ne $Before.RejectEventNameCount) { return $false }
    if ($After.RejectEmptyCorrelationCount -ne $Before.RejectEmptyCorrelationCount) { return $false }
    if ($After.RejectPauseConfigCount -ne $Before.RejectPauseConfigCount) { return $false }
    if ($After.RejectEnvironmentCount -ne $Before.RejectEnvironmentCount) { return $false }
    if ($After.AccessLogHighWater -ne $Before.AccessLogHighWater) { return $false }
    if ([bool]$After.AccessLogOverflow -ne [bool]$Before.AccessLogOverflow) { return $false }
    if ($After.SnapshotAccessCount -ne $Before.SnapshotAccessCount) { return $false }
    if ($After.PathIdentityRejectCount -ne $Before.PathIdentityRejectCount) { return $false }
    return $true
}

function Invoke-PspktTypedRunReject {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)]$Configuration,
        [Parameter(Mandatory = $true)]$ExpectedReason
    )
    $before = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot' -Arguments @()
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $observedExceptionTypeName = ''
    try {
        [void](Invoke-PspktHelperStatic -Binding $Binding -Method 'Run' -Arguments @($Configuration))
    }
    catch {
        $observed = $_.Exception
        while ($null -ne $observed.InnerException) {
            $observed = $observed.InnerException
        }
        $observedExceptionTypeName = $observed.GetType().FullName
    }
    finally {
        $stopwatch.Stop()
    }
    return [pscustomobject]@{
        ObservedExceptionTypeName = $observedExceptionTypeName
        ExpectedReason = $ExpectedReason
        ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
        Before = $before
        After = (Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot' -Arguments @())
    }
}

function New-PspktRejectConfig {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$TempDirectories,
        [AllowNull()]
        [string]$GateName,
        [bool]$SimulateAssignFailure = $false,
        [int]$WaitTimeoutMilliseconds = 60000,
        [int]$TerminateGraceMilliseconds = 15000,
        [int]$DrainDeadlineMilliseconds = 15000,
        [int]$RetainCapBytes = 65536,
        $PauseConfiguration = $null,
        $ProbeEvidence = $null,
        [Guid]$CorrelationId = [Guid]::Empty,
        [AllowNull()]
        [string[]]$ReservedNames,
        [AllowNull()]
        [string[]]$ReservedValues,
        [AllowNull()]
        [string[]]$ExtraNames,
        [AllowNull()]
        [string[]]$ExtraValues
    )
    $roleValue = Get-PspktHelperEnum -Binding $Binding -EnumName 'ProcessLaunchRole' -Member $Role
    $gate = New-PspktGateEventName -Tag 'Reject'
    if ($PSBoundParameters.ContainsKey('GateName')) { $gate = $GateName }
    $correlation = [Guid]::NewGuid()
    if ($PSBoundParameters.ContainsKey('CorrelationId')) { $correlation = $CorrelationId }
    $gateEnvironmentVariable = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRoleGateVariable' -Arguments @($roleValue)
    $requiredReservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRequiredReservedNames' -Arguments @($roleValue))
    $selectedReservedNames = $requiredReservedNames
    if ($PSBoundParameters.ContainsKey('ReservedNames')) { $selectedReservedNames = $ReservedNames }
    $selectedReservedValues = Get-PspktRejectReservedValues -Names $selectedReservedNames
    if ($PSBoundParameters.ContainsKey('ReservedValues')) { $selectedReservedValues = $ReservedValues }
    $selectedExtraNames = [string[]]@()
    if ($PSBoundParameters.ContainsKey('ExtraNames')) { $selectedExtraNames = $ExtraNames }
    $selectedExtraValues = [string[]]@()
    if ($PSBoundParameters.ContainsKey('ExtraValues')) { $selectedExtraValues = $ExtraValues }
    $hostExe = Get-PspktHostExecutable
    $workingDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-rejwd-'
    [void]$TempDirectories.Add($workingDir)
    $scriptPath = Join-Path $workingDir ('reject-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $escapedGateEnvironmentVariable = $gateEnvironmentVariable.Replace("'", "''")
    $scriptLines = @(
        "`$gateName = [Environment]::GetEnvironmentVariable('$escapedGateEnvironmentVariable')",
        'if ([string]::IsNullOrEmpty($gateName)) { exit 10 }',
        'if (-not [regex]::IsMatch($gateName, ''^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$'')) { exit 10 }',
        '$gate = [System.Threading.EventWaitHandle]::OpenExisting($gateName)',
        'try {',
        '    if (-not $gate.WaitOne(60000)) { exit 11 }',
        '}',
        'finally {',
        '    $gate.Close()',
        '}',
        'exit 0'
    )
    $scriptBytes = (New-PspktUtf8NoBom).GetBytes(($scriptLines -join "`r`n") + "`r`n")
    $scriptStream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $scriptStream.Write($scriptBytes, 0, $scriptBytes.Length)
        $scriptStream.Flush($true)
    }
    finally {
        $scriptStream.Dispose()
    }
    return Invoke-PspktHelperStatic -Binding $Binding -Method 'CreateProcessLaunchConfiguration' -Arguments @(
        $roleValue,
        $hostExe,
        ([string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath)),
        $gate,
        $gateEnvironmentVariable,
        ([string[]]$selectedExtraNames),
        ([string[]]$selectedExtraValues),
        ([string[]]$selectedReservedNames),
        ([string[]]$selectedReservedValues),
        $WaitTimeoutMilliseconds, $TerminateGraceMilliseconds, $DrainDeadlineMilliseconds, $RetainCapBytes,
        $SimulateAssignFailure,
        $correlation,
        $workingDir,
        $PauseConfiguration,
        $ProbeEvidence,
        $null,
        $null
    )
}

function Test-PspktRejectProbe {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Result,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedExceptionTypeName,
        [Parameter(Mandatory = $true)]$ExpectedReason
    )
    if ($null -eq $Result) { return $false }
    if ($null -eq $Result.Before -or $null -eq $Result.After -or $null -eq $ExpectedReason) { return $false }
    if ($Result.ObservedExceptionTypeName -cne $ExpectedExceptionTypeName) { return $false }
    if ($Result.ExpectedReason -ne $ExpectedReason) { return $false }
    if ($Result.ElapsedMilliseconds -lt 0 -or $Result.ElapsedMilliseconds -gt 1000) { return $false }
    $reasons = @([System.Enum]::GetValues($ExpectedReason.GetType()))
    if ($reasons.Count -ne 6) { return $false }
    foreach ($reason in $reasons) {
        $expectedDelta = 0
        if ($reason -eq $ExpectedReason) { $expectedDelta = 1 }
        $actualDelta = $Result.After.CountFor($reason) - $Result.Before.CountFor($reason)
        if ($actualDelta -ne $expectedDelta) { return $false }
    }
    if ($Result.After.JobCreateCount -ne $Result.Before.JobCreateCount) { return $false }
    if ($Result.After.EventCreateCount -ne $Result.Before.EventCreateCount) { return $false }
    if ($Result.After.EventOpenCount -ne $Result.Before.EventOpenCount) { return $false }
    if ($Result.After.ProcessStartCount -ne $Result.Before.ProcessStartCount) { return $false }
    if ($Result.After.AssignmentAttemptCount -ne $Result.Before.AssignmentAttemptCount) { return $false }
    if ($Result.After.AccessLogHighWater -ne $Result.Before.AccessLogHighWater) { return $false }
    if ([bool]$Result.After.AccessLogOverflow -ne [bool]$Result.Before.AccessLogOverflow) { return $false }
    if ($Result.After.SnapshotAccessCount -ne $Result.Before.SnapshotAccessCount) { return $false }
    return $true
}

function New-PspktParentLossChildScript {
    param([Parameter(Mandatory = $true)]$Context)
    $childScript = @'
$ErrorActionPreference = 'Stop'
try {
    $gateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GATE_EVENT')
    $waiterReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_WAITER_READY_EVENT')
    $helperPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_PATH')
    $expectedHelperSha = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_SHA256')
    $expectedHelperVersion = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_VERSION')
    $timeoutText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS')
    $timeoutExitText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE')
    if ([string]::IsNullOrEmpty($gateName) -or [string]::IsNullOrEmpty($waiterReadyName) -or [string]::IsNullOrEmpty($helperPath) -or [string]::IsNullOrEmpty($expectedHelperSha) -or [string]::IsNullOrEmpty($expectedHelperVersion) -or [string]::IsNullOrEmpty($timeoutText) -or [string]::IsNullOrEmpty($timeoutExitText)) { exit 7 }
    if (-not [regex]::IsMatch($gateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 7 }
    if (-not [regex]::IsMatch($waiterReadyName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 7 }
    $timeoutMilliseconds = 0
    $timeoutExitCode = 0
    if (-not [int]::TryParse($timeoutText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$timeoutMilliseconds) -or $timeoutMilliseconds -ne 60000) { exit 7 }
    if (-not [int]::TryParse($timeoutExitText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$timeoutExitCode) -or $timeoutExitCode -ne 5) { exit 7 }
    $helperInfo = [System.IO.FileInfo]::new($helperPath)
    if (-not $helperInfo.Exists -or ($helperInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $helperInfo.Length -gt 4194304) { exit 7 }
    $helperStream = [System.IO.FileStream]::new($helperPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $helperBytes = [byte[]]::new([int]$helperStream.Length)
        $helperOffset = 0
        while ($helperOffset -lt $helperBytes.Length) {
            $helperRead = $helperStream.Read($helperBytes, $helperOffset, $helperBytes.Length - $helperOffset)
            if ($helperRead -le 0) { exit 7 }
            $helperOffset += $helperRead
        }
    }
    finally {
        $helperStream.Dispose()
    }
    $helperHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $helperHash = $helperHasher.ComputeHash($helperBytes)
    }
    finally {
        $helperHasher.Dispose()
    }
    $helperDigestBuilder = [System.Text.StringBuilder]::new(64)
    foreach ($helperHashByte in $helperHash) { [void]$helperDigestBuilder.Append($helperHashByte.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture)) }
    if ($helperDigestBuilder.ToString() -cne $expectedHelperSha) { exit 7 }
    $helperAssembly = [System.Reflection.Assembly]::Load($helperBytes)
    $helperHostType = $helperAssembly.GetType('Pspkt.Certification.BoundedProcessHost', $true)
    $helperVersionField = $helperHostType.GetField('Version', [System.Reflection.BindingFlags]'Public, Static')
    if ([string]$helperVersionField.GetValue($null) -cne $expectedHelperVersion) { exit 7 }
    $preludeMethod = $helperHostType.GetMethod('RunReadyThenWaitPrelude', [Type[]]@([string], [string], [int], [int]))
    if ($null -eq $preludeMethod) { exit 7 }
    [void]$preludeMethod.Invoke($null, @($gateName, $waiterReadyName, $timeoutMilliseconds, $timeoutExitCode))
    exit 6
}
catch {
    exit 7
}
'@
    $scriptPath = Join-Path $Context.Root ('parent-loss-child-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $normalized = [regex]::Replace($childScript, "\r\n|\r|\n", "`r`n")
    $bytes = (New-PspktUtf8NoBom).GetBytes($normalized + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function New-PspktParentLossLauncherScript {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$GateName,
        [Parameter(Mandatory = $true)][string]$ChildScriptPath,
        [Parameter(Mandatory = $true)][string]$ChildWorkingDirectory
    )
    $partA = @'
$ErrorActionPreference = 'Stop'
$supervisorGateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SUPERVISOR_GATE_EVENT')
if ([string]::IsNullOrEmpty($supervisorGateName) -or -not [regex]::IsMatch($supervisorGateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 30 }
try {
    $supervisorGate = [System.Threading.EventWaitHandle]::OpenExisting($supervisorGateName)
}
catch [System.Threading.WaitHandleCannotBeOpenedException] {
    exit 30
}
catch [System.UnauthorizedAccessException] {
    exit 30
}
try {
    if (-not $supervisorGate.WaitOne(10000)) { exit 31 }
}
finally {
    $supervisorGate.Close()
}
'@
    $partB = @'
$plParentNonce = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_NONCE')
$plIdentityRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_IDENTITY_ROOT')
$plCorrelationText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_CORRELATION_ID')
$plReadinessName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_READINESS_EVENT')
$plAckName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_ACK_EVENT')
$plArmedName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_RELEASE_ARMED_EVENT')
$plReleaseName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_RELEASE_EVENT')
$plMembershipReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PARENT_MEMBERSHIP_READY_EVENT')
$plWaiterReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_WAITER_READY_EVENT')
$plProbeGateTimeout = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS')
$plProbeExitCode = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE')
$plSnapshotRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SNAPSHOT_ROOT')
$plRepositoryRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_REPOSITORY_ROOT')
foreach ($plRequired in @($plParentNonce, $plIdentityRoot, $plCorrelationText, $plReadinessName, $plAckName, $plArmedName, $plReleaseName, $plMembershipReadyName, $plWaiterReadyName, $plProbeGateTimeout, $plProbeExitCode, $plSnapshotRoot, $plRepositoryRoot)) {
    if ([string]::IsNullOrEmpty($plRequired)) { exit 32 }
}
if (-not [regex]::IsMatch($plParentNonce, '^[0-9a-f]{32}$')) { exit 32 }
if (-not [regex]::IsMatch($plCorrelationText, '^[0-9a-f]{32}$')) { exit 32 }
$plTimeoutMilliseconds = 0
$plTimeoutExitCode = 0
if (-not [int]::TryParse($plProbeGateTimeout, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$plTimeoutMilliseconds) -or $plTimeoutMilliseconds -ne 60000) { exit 32 }
if (-not [int]::TryParse($plProbeExitCode, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$plTimeoutExitCode) -or $plTimeoutExitCode -ne 5) { exit 32 }
$plEventNames = @($supervisorGateName, $plGateName, $plReadinessName, $plAckName, $plArmedName, $plReleaseName, $plMembershipReadyName, $plWaiterReadyName)
$plUniqueEvents = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($plEventName in $plEventNames) {
    if (-not [regex]::IsMatch($plEventName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 32 }
    if (-not $plUniqueEvents.Add($plEventName)) { exit 32 }
}
$plExpectedEnvironmentNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($plExpectedName in @(
    'PSPKT_PHASE4_SUPERVISOR_GATE_EVENT', 'PSPKT_PHASE4_SNAPSHOT_ROOT', 'PSPKT_PHASE4_REPOSITORY_ROOT',
    'PSPKT_PHASE4_HELPER_PATH', 'PSPKT_PHASE4_HELPER_SHA256', 'PSPKT_PHASE4_HELPER_VERSION',
    'PSPKT_PHASE4_PARENT_NONCE', 'PSPKT_PHASE4_PARENT_IDENTITY_ROOT', 'PSPKT_PHASE4_PARENT_CORRELATION_ID',
    'PSPKT_PHASE4_PARENT_READINESS_EVENT', 'PSPKT_PHASE4_PARENT_ACK_EVENT',
    'PSPKT_PHASE4_PARENT_RELEASE_ARMED_EVENT', 'PSPKT_PHASE4_PARENT_RELEASE_EVENT',
    'PSPKT_PHASE4_PARENT_MEMBERSHIP_READY_EVENT', 'PSPKT_PHASE4_WAITER_READY_EVENT',
    'PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS', 'PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE')) {
    [void]$plExpectedEnvironmentNames.Add($plExpectedName)
}
$plActualEnvironmentNames = [System.Collections.Generic.List[string]]::new()
foreach ($plEnvironmentName in [Environment]::GetEnvironmentVariables().Keys) {
    $plEnvironmentNameText = [string]$plEnvironmentName
    if ($plEnvironmentNameText.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase)) {
        [void]$plActualEnvironmentNames.Add($plEnvironmentNameText)
        if (-not $plExpectedEnvironmentNames.Contains($plEnvironmentNameText)) { exit 32 }
    }
}
if ($plActualEnvironmentNames.Count -ne $plExpectedEnvironmentNames.Count) { exit 32 }
$plCorrelation = [Guid]::Parse($plCorrelationText)
'@
    $partC = @'
$plAsm = $helperAssembly
$plRoleType = $plAsm.GetType('Pspkt.Certification.ProcessLaunchRole', $true)
$plPauseType = $plAsm.GetType('Pspkt.Certification.PauseConfiguration', $true)
$plMembershipType = $plAsm.GetType('Pspkt.Certification.ParentLossMembership', $true)
$plProbeEvidenceType = $plAsm.GetType('Pspkt.Certification.ProbeEvidence', $true)
$plNestedType = $plAsm.GetType('Pspkt.Certification.NestedProof', $true)
$plCfgType = $plAsm.GetType('Pspkt.Certification.ProcessLaunchConfiguration', $true)
$plPauseCtor = $plPauseType.GetConstructor([Type[]]@([Guid], [string], [string], [string], [string], [string], [int], [int]))
if ($null -eq $plPauseCtor) { exit 33 }
$plPause = $plPauseCtor.Invoke([object[]]@($plCorrelation, $plIdentityRoot, $plReadinessName, $plAckName, $plArmedName, $plReleaseName, 10000, 90000))
$plMembershipCtor = $plMembershipType.GetConstructor([Type[]]@([string], [string], [string], [string], [Guid]))
if ($null -eq $plMembershipCtor) { exit 33 }
$plMembership = $plMembershipCtor.Invoke([object[]]@($plParentNonce, $plIdentityRoot, 'parent-loss-membership.txt', $plMembershipReadyName, $plCorrelation))
$plChildRole = [System.Enum]::Parse($plRoleType, 'ParentLossProbeChild')
$plChildHost = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$plChildArgv = [string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $plChildScript)
$plChildReservedNames = [string[]]@('PSPKT_PHASE4_HELPER_PATH', 'PSPKT_PHASE4_HELPER_SHA256', 'PSPKT_PHASE4_HELPER_VERSION', 'PSPKT_PHASE4_WAITER_READY_EVENT', 'PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS', 'PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE')
$plChildReservedValues = [string[]]@($helperPath, $expectedHelperSha, $expectedHelperVersion, $plWaiterReadyName, $plProbeGateTimeout, $plProbeExitCode)
$plFactoryTypes = [Type[]]@($plRoleType, [string], [string[]], [string], [string], [string[]], [string[]], [string[]], [string[]], [int], [int], [int], [int], [bool], [Guid], [string], $plPauseType, $plProbeEvidenceType, $plMembershipType, $plNestedType)
$plFactory = $helperHostType.GetMethod('CreateProcessLaunchConfiguration', $plFactoryTypes)
if ($null -eq $plFactory) { exit 34 }
$plChildConfig = $plFactory.Invoke($null, [object[]]@($plChildRole, $plChildHost, $plChildArgv, $plGateName, 'PSPKT_PHASE4_GATE_EVENT', ([string[]]@()), ([string[]]@()), $plChildReservedNames, $plChildReservedValues, 60000, 10000, 10000, 65536, $false, $plCorrelation, $plChildWorkingDirectory, $plPause, $null, $plMembership, $null))
$plRunMethod = $helperHostType.GetMethod('Run', [Type[]]@($plCfgType))
if ($null -eq $plRunMethod) { exit 34 }
[void]$plRunMethod.Invoke($null, [object[]]@($plChildConfig))
exit 39
'@
    $helperLoad = (Get-PspktVerifiedHelperLoadLines) -join "`r`n"
    $gateLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $GateName
    $childScriptLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $ChildScriptPath
    $childWorkingLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $ChildWorkingDirectory
    $text = $partA + "`r`n" + $helperLoad + "`r`n" +
        ('$plGateName = ' + $gateLiteral) + "`r`n" +
        ('$plChildScript = ' + $childScriptLiteral) + "`r`n" +
        ('$plChildWorkingDirectory = ' + $childWorkingLiteral) + "`r`n" +
        $partB + "`r`n" +
        $partC
    $normalized = [regex]::Replace($text, "\r\n|\r|\n", "`r`n")
    $scriptPath = Join-Path $Context.Root ('parent-loss-launcher-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $bytes = (New-PspktUtf8NoBom).GetBytes($normalized + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function New-PspktObserverNamedEvent {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId
    )
    $roleValue = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member $Role
    return Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($Name, $roleValue, $CorrelationId)
}

function Wait-PspktNamedEventWhileLive {
    param(
        [Parameter(Mandatory = $true)]$NamedEvent,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        $LaunchSession = $null,
        $ChildProcess = $null
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if ($NamedEvent.IsSignaledNow()) { return $true }
        if ($null -ne $LaunchSession -and $LaunchSession.HasExited) { return $false }
        if ($null -ne $ChildProcess) {
            $ChildProcess.Refresh()
            if ($ChildProcess.HasExited) { return $false }
        }
        [System.Threading.Thread]::Sleep(25)
    }
    return ($NamedEvent.IsSignaledNow())
}

function Add-PspktParentLossQuarantineRegistration {
    param(
        [AllowNull()]$ChildProcess = $null,
        [AllowNull()]$LaunchSession = $null,
        [AllowNull()]$GateEvent = $null,
        [AllowNull()]
        [AllowEmptyCollection()]
        $OwnedEvents = $null,
        [Parameter(Mandatory = $true)]$Context
    )
    $ownedList = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $GateEvent) { [void]$ownedList.Add($GateEvent) }
    if ($null -ne $OwnedEvents) {
        foreach ($ownedEvent in $OwnedEvents) {
            if ($null -ne $ownedEvent) { [void]$ownedList.Add($ownedEvent) }
        }
    }
    $contextRoot = ''
    if ($null -ne $Context) {
        $rootProperty = $Context.PSObject.Properties['Root']
        if ($null -ne $rootProperty) { $contextRoot = [string]$rootProperty.Value }
    }
    $tempDirs = [string[]]@()
    if (-not [string]::IsNullOrEmpty($contextRoot)) {
        $tempDirs = [string[]]@($contextRoot)
    }
    $quarantineContext = [pscustomobject]@{
        CleanupState = 'Quarantined'
        TempDirs = $tempDirs
        OwnedEvents = $ownedList
        ChildProcess = $ChildProcess
        GateEvent = $GateEvent
        OracleContext = $Context
    }
    $quarantineLaunch = [pscustomobject]@{
        Session = $LaunchSession
        Context = $quarantineContext
        ChildProcess = $ChildProcess
        GateEvent = $GateEvent
    }
    $snapshots = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $ChildProcess) { [void]$snapshots.Add($ChildProcess) }
    if ($null -ne $LaunchSession) { [void]$snapshots.Add($LaunchSession) }
    if ($null -ne $GateEvent) { [void]$snapshots.Add($GateEvent) }
    if ($null -ne $OwnedEvents) {
        foreach ($ownedEvent in $OwnedEvents) {
            if ($null -ne $ownedEvent) { [void]$snapshots.Add($ownedEvent) }
        }
    }
    return (Add-PspktQuarantineRegistration -Kind 'ParentLoss' -Launch $quarantineLaunch -Snapshots ([object[]]$snapshots.ToArray()))
}

function Close-PspktParentLossLaunch {
    param(
        [AllowNull()]$ChildProcess = $null,
        [AllowNull()]$LaunchSession = $null,
        [AllowNull()]$GateEvent = $null,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $OwnedEvents,
        [Parameter(Mandatory = $true)]$Context,
        [int]$ChildExitDeadlineMilliseconds = 15000
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()

    $childClean = $true
    if ($null -ne $ChildProcess) {
        $childExitProven = $false
        try {
            $ChildProcess.Refresh()
            if ($ChildProcess.HasExited) {
                $childExitProven = $true
            }
            else {
                $ChildProcess.Kill()
                [void]$ChildProcess.WaitForExit($ChildExitDeadlineMilliseconds)
                $ChildProcess.Refresh()
                $childExitProven = [bool]$ChildProcess.HasExited
            }
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            $childExitProven = $false
            try {
                $ChildProcess.Refresh()
                $childExitProven = [bool]$ChildProcess.HasExited
            }
            catch {
                $childExitProven = $false
            }
        }
        if ($childExitProven) {
            try {
                $ChildProcess.Dispose()
            }
            catch {
                $childExitProven = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if (-not $childExitProven) {
            $childClean = $false
            $childPidText = '(unknown)'
            try { $childPidText = [string]$ChildProcess.Id } catch { $childPidText = '(unknown)' }
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                    ('parent-loss cleanup: child process {0} exit could not be proven within the {1} ms bounded deadline; the Process wrapper was retained and rooted in the quarantine registry.' -f $childPidText, $ChildExitDeadlineMilliseconds)))
        }
    }

    $sessionClean = $true
    if ($null -ne $LaunchSession) {
        try {
            Close-PspktDirectLaunchSession -Session $LaunchSession
        }
        catch {
            $sessionClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    $eventsClean = $true
    if ($childClean -and $sessionClean) {
        if ($null -ne $GateEvent) {
            try {
                $GateEvent.Dispose()
            }
            catch {
                $eventsClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if ($null -ne $OwnedEvents) {
            foreach ($ownedEvent in $OwnedEvents) {
                if ($null -eq $ownedEvent) { continue }
                try {
                    $ownedEvent.Dispose()
                }
                catch {
                    $eventsClean = $false
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
            }
        }
    }
    else {
        $eventsClean = $false
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                'parent-loss cleanup: gate and owned-event disposal was withheld because child and/or launch-session ownership was not proven clean; the events were retained and rooted in the quarantine registry.'))
    }

    $contextClean = $true
    if ($childClean -and $sessionClean -and $eventsClean) {
        try {
            Remove-PspktProcessOracleContext -Context $Context
        }
        catch {
            $contextClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    else {
        $contextClean = $false
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                'parent-loss cleanup: process-oracle context removal was withheld because child, session, and/or event ownership was not proven clean; the context root was retained and rooted in the quarantine registry.'))
    }

    if (-not ($childClean -and $sessionClean -and $eventsClean -and $contextClean)) {
        try {
            [void](Add-PspktParentLossQuarantineRegistration -ChildProcess $ChildProcess -LaunchSession $LaunchSession -GateEvent $GateEvent -OwnedEvents $OwnedEvents -Context $Context)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    return ,([Exception[]]$cleanupFailures.ToArray())
}

function Invoke-PspktParentLossGateTimeoutOracle {
    param([Parameter(Mandatory = $true)]$Binding)
    $b = $Binding
    $context = New-PspktProcessOracleContext -Tag 'parent-loss'
    $ownedEvents = [System.Collections.Generic.List[object]]::new()
    $gateEvent = $null
    $childProcess = $null
    $launchSession = $null
    $primaryFailure = $null
    $oracleResult = $false
    try {
        $parentNonce = [Guid]::NewGuid().ToString('N')
        $correlation = [Guid]::NewGuid()
        $correlationN = $correlation.ToString('N')
        $identityRoot = Join-Path $context.Root 'identity'
        [void][System.IO.Directory]::CreateDirectory($identityRoot)
        $childWorkingDirectory = Join-Path $context.Root ('child-cwd-' + [Guid]::NewGuid().ToString('N'))
        [void][System.IO.Directory]::CreateDirectory($childWorkingDirectory)

        $supervisorGateName = New-PspktGateEventName -Tag 'PLoSup'
        $gateName = New-PspktGateEventName -Tag 'PLoGate'
        $readinessName = New-PspktGateEventName -Tag 'PLoRdy'
        $ackName = New-PspktGateEventName -Tag 'PLoAck'
        $armedName = New-PspktGateEventName -Tag 'PLoArmed'
        $releaseName = New-PspktGateEventName -Tag 'PLoRel'
        $membershipReadyName = New-PspktGateEventName -Tag 'PLoMem'
        $waiterReadyName = New-PspktGateEventName -Tag 'PLoWaiter'
        $allNames = @($supervisorGateName, $gateName, $readinessName, $ackName, $armedName, $releaseName, $membershipReadyName, $waiterReadyName)
        $nameSet = @{}
        foreach ($candidateName in $allNames) {
            $lowered = $candidateName.ToLowerInvariant()
            if ($nameSet.ContainsKey($lowered)) { throw 'parent-loss oracle: generated event names were not unique.' }
            $nameSet[$lowered] = $true
        }

        $supervisorGate = New-PspktObserverNamedEvent -Binding $b -Name $supervisorGateName -Role 'SupervisorGate' -CorrelationId ([Guid]::Empty)
        $ownedEvents.Add($supervisorGate)
        $readinessEvent = New-PspktObserverNamedEvent -Binding $b -Name $readinessName -Role 'Readiness' -CorrelationId $correlation
        $ownedEvents.Add($readinessEvent)
        $ackEvent = New-PspktObserverNamedEvent -Binding $b -Name $ackName -Role 'ObserverAck' -CorrelationId $correlation
        $ownedEvents.Add($ackEvent)
        $armedEvent = New-PspktObserverNamedEvent -Binding $b -Name $armedName -Role 'ReleaseWaitArmed' -CorrelationId $correlation
        $ownedEvents.Add($armedEvent)
        $membershipReadyEvent = New-PspktObserverNamedEvent -Binding $b -Name $membershipReadyName -Role 'MembershipReady' -CorrelationId $correlation
        $ownedEvents.Add($membershipReadyEvent)
        $waiterReadyEvent = New-PspktObserverNamedEvent -Binding $b -Name $waiterReadyName -Role 'WaiterReady' -CorrelationId $correlation
        $ownedEvents.Add($waiterReadyEvent)
        foreach ($createdEvent in @($supervisorGate, $readinessEvent, $ackEvent, $armedEvent, $membershipReadyEvent, $waiterReadyEvent)) {
            if ($createdEvent.IsSignaledNow()) { return $false }
        }

        $childScriptPath = New-PspktParentLossChildScript -Context $context
        $launcherScriptPath = New-PspktParentLossLauncherScript -Context $context -GateName $gateName -ChildScriptPath $childScriptPath -ChildWorkingDirectory $childWorkingDirectory

        $reserved = @{
            'PSPKT_PHASE4_SNAPSHOT_ROOT'                  = $context.Root
            'PSPKT_PHASE4_REPOSITORY_ROOT'                = $context.Root
            'PSPKT_PHASE4_HELPER_PATH'                    = $b.Path
            'PSPKT_PHASE4_HELPER_SHA256'                  = $b.Digest
            'PSPKT_PHASE4_HELPER_VERSION'                 = $b.Version
            'PSPKT_PHASE4_PARENT_NONCE'                   = $parentNonce
            'PSPKT_PHASE4_PARENT_IDENTITY_ROOT'           = $identityRoot
            'PSPKT_PHASE4_PARENT_CORRELATION_ID'          = $correlationN
            'PSPKT_PHASE4_PARENT_READINESS_EVENT'         = $readinessName
            'PSPKT_PHASE4_PARENT_ACK_EVENT'               = $ackName
            'PSPKT_PHASE4_PARENT_RELEASE_ARMED_EVENT'     = $armedName
            'PSPKT_PHASE4_PARENT_RELEASE_EVENT'           = $releaseName
            'PSPKT_PHASE4_PARENT_MEMBERSHIP_READY_EVENT'  = $membershipReadyName
            'PSPKT_PHASE4_WAITER_READY_EVENT'             = $waiterReadyName
            'PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS'          = '60000'
            'PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE'        = '5'
        }
        $launcherConfig = New-PspktProcessOracleConfiguration -Binding $b -Role 'ParentLossLauncher' -ScriptPath $launcherScriptPath -Context $context -ReservedValueByName $reserved -GateEventName $supervisorGateName -WaitTimeoutMilliseconds 10000

        $supervisorGate.SetEvent()
        $launchSession = Invoke-PspktHelperStatic -Binding $b -Method 'RunDirectLaunch' -Arguments @($launcherConfig)

        if (-not (Wait-PspktNamedEventWhileLive -NamedEvent $readinessEvent -TimeoutMilliseconds 10000 -LaunchSession $launchSession)) { return $false }

        $identityPath = Join-Path $identityRoot 'child-identity.txt'
        $gatePath = Join-Path $identityRoot 'gate-name.txt'
        if (-not (Test-Path -LiteralPath $identityPath -PathType Leaf)) { return $false }
        if (-not (Test-Path -LiteralPath $gatePath -PathType Leaf)) { return $false }
        $identityBytes = Read-PspktBoundedFileBytes -FullPath $identityPath -ByteCap 4096
        $gateBytes = Read-PspktBoundedFileBytes -FullPath $gatePath -ByteCap 4096
        foreach ($identityByte in $identityBytes) { if ($identityByte -gt 0x7f) { return $false } }
        foreach ($gateByte in $gateBytes) { if ($gateByte -gt 0x7f) { return $false } }
        $identityText = [System.Text.Encoding]::ASCII.GetString($identityBytes)
        $gateText = [System.Text.Encoding]::ASCII.GetString($gateBytes)
        if (-not $identityText.EndsWith("`n")) { return $false }
        $identityBody = $identityText.Substring(0, $identityText.Length - 1)
        $identityParts = $identityBody.Split([char]0x09)
        if ($identityParts.Length -ne 2) { return $false }
        $processText = $identityParts[0]
        $startText = $identityParts[1]
        if (-not [regex]::IsMatch($processText, '^[0-9]+$')) { return $false }
        if (-not [regex]::IsMatch($startText, '^-?[0-9]+$')) { return $false }
        $childPid = [int]::Parse($processText, [System.Globalization.CultureInfo]::InvariantCulture)
        $childStart = [long]::Parse($startText, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($childPid -lt 1 -or $childStart -lt 1) { return $false }
        if ($gateText -cne ($gateName + "`n")) { return $false }

        $childProcess = [System.Diagnostics.Process]::GetProcessById($childPid)
        [void]$childProcess.Handle
        if ($childProcess.StartTime.ToFileTimeUtc() -ne $childStart) { return $false }

        $gateWaitMode = Get-PspktHelperEnum -Binding $b -EnumName 'EventAccessMode' -Member 'WaitOnly'
        $gateRole = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Gate'
        $gateEvent = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($gateName, $gateWaitMode, $gateRole, [Guid]::Empty)
        if ($gateEvent.IsSignaledNow()) { return $false }

        $releaseEvent = New-PspktObserverNamedEvent -Binding $b -Name $releaseName -Role 'Release' -CorrelationId $correlation
        $ownedEvents.Add($releaseEvent)
        if ($releaseEvent.IsSignaledNow()) { return $false }

        $ackEvent.SetEvent()

        if (-not (Wait-PspktNamedEventWhileLive -NamedEvent $membershipReadyEvent -TimeoutMilliseconds 10000 -LaunchSession $launchSession -ChildProcess $childProcess)) { return $false }
        if (-not (Wait-PspktNamedEventWhileLive -NamedEvent $armedEvent -TimeoutMilliseconds 10000 -LaunchSession $launchSession -ChildProcess $childProcess)) { return $false }
        if (-not (Wait-PspktNamedEventWhileLive -NamedEvent $waiterReadyEvent -TimeoutMilliseconds 10000 -LaunchSession $launchSession -ChildProcess $childProcess)) { return $false }

        $membershipPath = Join-Path $identityRoot 'parent-loss-membership.txt'
        if (-not (Test-Path -LiteralPath $membershipPath -PathType Leaf)) { return $false }
        $membershipBytes = Read-PspktBoundedFileBytes -FullPath $membershipPath -ByteCap 320
        foreach ($membershipByte in $membershipBytes) { if ($membershipByte -gt 0x7f) { return $false } }
        $membershipText = [System.Text.Encoding]::ASCII.GetString($membershipBytes)
        $expectedMembership = 'pspkt-phase4-parent-loss-membership-v1' + [char]0x09 + $parentNonce + [char]0x09 + $correlationN + [char]0x09 + $processText + [char]0x09 + $startText + [char]0x09 + 'false' + [char]0x09 + '0' + [char]0x0A
        if ($membershipText -cne $expectedMembership) { return $false }

        if ($gateEvent.IsSignaledNow()) { return $false }
        $childProcess.Refresh()
        if ($childProcess.HasExited) { return $false }

        $launchSession.TerminateAndWait(2000)
        if (-not $launchSession.HasExited) { return $false }

        $childProcess.Refresh()
        $childLiveAfterLauncherDeath = -not $childProcess.HasExited

        $childExited = $childProcess.WaitForExit(75000)
        if (-not $childExited) { return $false }
        $childExitCode = $childProcess.ExitCode
        $gateStillUnsignaled = -not $gateEvent.IsSignaledNow()

        $oracleResult = ($childLiveAfterLauncherDeath -and ($childExitCode -eq 5) -and $gateStillUnsignaled)
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    finally {
        $cleanupFailures = Close-PspktParentLossLaunch -ChildProcess $childProcess -LaunchSession $launchSession -GateEvent $gateEvent -OwnedEvents $ownedEvents -Context $context -ChildExitDeadlineMilliseconds 15000
        $failure = New-PspktComposedFailure -Message 'parent-loss gate-timeout oracle primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures $cleanupFailures
        if ($null -ne $failure) {
            throw $failure
        }
    }
    return $oracleResult
}

function ConvertFrom-PspktAssignmentEvidenceBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][Guid]$ExpectedCorrelationId
    )
    if ($Bytes.Length -lt 1 -or $Bytes.Length -gt 320) {
        throw [System.IO.InvalidDataException]::new('assignment evidence size is invalid.')
    }
    foreach ($receiptByte in $Bytes) {
        if ($receiptByte -gt 0x7f) {
            throw [System.IO.InvalidDataException]::new('assignment evidence is not strict ASCII.')
        }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $pattern = '^pspkt-phase4-assignment-v1' + [char]0x09 +
        '([0-9a-f]{32})' + [char]0x09 +
        '([1-9][0-9]*)' + [char]0x09 +
        '([1-9][0-9]*)' + [char]0x09 +
        '(0|[1-9][0-9]*)' + [char]0x09 +
        '(0|[1-9][0-9]*)' + [char]0x0A + '\z'
    $match = [regex]::Match($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw [System.IO.InvalidDataException]::new('assignment evidence grammar is invalid.')
    }
    $correlationText = $match.Groups[1].Value
    if ($correlationText -cne $ExpectedCorrelationId.ToString('N')) {
        throw [System.IO.InvalidDataException]::new('assignment evidence correlation is invalid.')
    }
    $processId = 0
    $startFileTimeUtc = 0L
    $assignmentCountBefore = 0L
    $assignmentCountAfter = 0L
    if (-not [int]::TryParse($match.Groups[2].Value, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$processId) -or $processId -lt 1 -or
        -not [long]::TryParse($match.Groups[3].Value, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$startFileTimeUtc) -or $startFileTimeUtc -lt 1 -or
        -not [long]::TryParse($match.Groups[4].Value, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$assignmentCountBefore) -or $assignmentCountBefore -lt 0 -or
        -not [long]::TryParse($match.Groups[5].Value, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$assignmentCountAfter) -or
        $assignmentCountBefore -eq [long]::MaxValue -or $assignmentCountAfter -ne ($assignmentCountBefore + 1)) {
        throw [System.IO.InvalidDataException]::new('assignment evidence values are invalid.')
    }
    return [pscustomobject]@{
        CorrelationId = [Guid]::ParseExact($correlationText, 'N')
        ProcessId = $processId
        StartFileTimeUtc = $startFileTimeUtc
        AssignmentCountBefore = $assignmentCountBefore
        AssignmentCountAfter = $assignmentCountAfter
    }
}

function ConvertFrom-PspktPostGateReadyBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -lt 1 -or $Bytes.Length -gt 320) {
        throw [System.IO.InvalidDataException]::new('post-gate receipt size is invalid.')
    }
    foreach ($receiptByte in $Bytes) {
        if ($receiptByte -gt 0x7f) {
            throw [System.IO.InvalidDataException]::new('post-gate receipt is not strict ASCII.')
        }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $pattern = '^pspkt-phase4-post-gate-v1' + [char]0x09 +
        '([1-9][0-9]*)' + [char]0x09 +
        '([1-9][0-9]*)' + [char]0x0A + '\z'
    $match = [regex]::Match($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw [System.IO.InvalidDataException]::new('post-gate receipt grammar is invalid.')
    }
    $processId = 0
    $startFileTimeUtc = 0L
    if (-not [int]::TryParse($match.Groups[1].Value, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$processId) -or $processId -lt 1 -or
        -not [long]::TryParse($match.Groups[2].Value, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$startFileTimeUtc) -or $startFileTimeUtc -lt 1) {
        throw [System.IO.InvalidDataException]::new('post-gate receipt values are invalid.')
    }
    return [pscustomobject]@{
        ProcessId = $processId
        StartFileTimeUtc = $startFileTimeUtc
    }
}

function Test-PspktPostAssignmentReceiptParserMutations {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId
    )
    $assignmentBytes = [byte[]](Invoke-PspktHelperStatic -Binding $Binding -Method 'BuildAssignmentEvidenceRecord' -Arguments @($CorrelationId, 41, 638900000000000000L, 7L, 8L))
    $postGateBytes = [byte[]](Invoke-PspktHelperStatic -Binding $Binding -Method 'BuildPostGateReadyRecord' -Arguments @(41, 638900000000000000L))
    $assignmentText = [System.Text.Encoding]::ASCII.GetString($assignmentBytes)
    $postGateText = [System.Text.Encoding]::ASCII.GetString($postGateBytes)
    [void](ConvertFrom-PspktAssignmentEvidenceBytes -Bytes $assignmentBytes -ExpectedCorrelationId $CorrelationId)
    [void](ConvertFrom-PspktPostGateReadyBytes -Bytes $postGateBytes)
    $wrongCorrelationText = '00000000000000000000000000000000'
    if ($wrongCorrelationText -ceq $CorrelationId.ToString('N')) {
        $wrongCorrelationText = '11111111111111111111111111111111'
    }
    $assignmentMutations = [string[]]@(
        $assignmentText.Replace('assignment-v1', 'assignment-v2'),
        $assignmentText.Replace($CorrelationId.ToString('N'), $wrongCorrelationText),
        $assignmentText.Replace("`t41`t", "`t0`t"),
        $assignmentText.Replace("`t638900000000000000`t", "`t0`t"),
        $assignmentText.Replace("`t7`t8`n", "`t7`t9`n"),
        $assignmentText.Replace("`t7`t8`n", "`t-1`t0`n"),
        $assignmentText.Replace("`n", "`r`n"),
        $assignmentText.Substring(0, $assignmentText.Length - 1),
        ($assignmentText + "`n"),
        ($assignmentText + 'x')
    )
    foreach ($mutation in $assignmentMutations) {
        $rejected = $false
        try {
            [void](ConvertFrom-PspktAssignmentEvidenceBytes -Bytes ([System.Text.Encoding]::ASCII.GetBytes($mutation)) -ExpectedCorrelationId $CorrelationId)
        }
        catch [System.IO.InvalidDataException] {
            $rejected = $true
        }
        if (-not $rejected) { return $false }
    }
    $postGateMutations = [string[]]@(
        $postGateText.Replace('post-gate-v1', 'post-gate-v2'),
        $postGateText.Replace("`t41`t", "`t0`t"),
        $postGateText.Replace("`t638900000000000000`n", "`t0`n"),
        $postGateText.Replace("`t", '|'),
        $postGateText.Replace("`n", "`r`n"),
        $postGateText.Substring(0, $postGateText.Length - 1),
        ($postGateText + "`n"),
        ($postGateText + 'x')
    )
    foreach ($mutation in $postGateMutations) {
        $rejected = $false
        try {
            [void](ConvertFrom-PspktPostGateReadyBytes -Bytes ([System.Text.Encoding]::ASCII.GetBytes($mutation)))
        }
        catch [System.IO.InvalidDataException] {
            $rejected = $true
        }
        if (-not $rejected) { return $false }
    }
    return $true
}

function New-PspktPostAssignmentChildScript {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$MarkerPath
    )
    $markerLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $MarkerPath
    $helperLoadLines = Get-PspktVerifiedHelperLoadLines -Binding $Binding
    $prefixLines = [string[]]@(
        '$gateName = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_GATE_EVENT'')',
        'if ([string]::IsNullOrEmpty($gateName) -or -not [regex]::IsMatch($gateName, ''^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$'')) { exit 10 }'
    )
    $suffixLines = [string[]]@(
        '$namedEventType = $helperAssembly.GetType(''Pspkt.Certification.NamedEvent'', $true)',
        '$eventAccessModeType = $helperAssembly.GetType(''Pspkt.Certification.EventAccessMode'', $true)',
        '$eventRoleType = $helperAssembly.GetType(''Pspkt.Certification.EventRole'', $true)',
        '$eventOpenMethod = $namedEventType.GetMethod(''OpenExisting'', [Type[]]@([string], $eventAccessModeType, $eventRoleType, [Guid]))',
        'if ($null -eq $eventOpenMethod) { exit 10 }',
        '$waitOnly = [System.Enum]::Parse($eventAccessModeType, ''WaitOnly'')',
        '$gateRole = [System.Enum]::Parse($eventRoleType, ''Gate'')',
        'try {',
        '    $gate = $eventOpenMethod.Invoke($null, [object[]]@($gateName, $waitOnly, $gateRole, [Guid]::Empty))',
        '}',
        'catch {',
        '    exit 10',
        '}',
        'try {',
        '    $gateStatus = $gate.Wait(60000)',
        '    if ([string]$gateStatus -cne ''Object0'') { exit 11 }',
        '}',
        'finally {',
        '    $gate.Close()',
        '}',
        '$markerPath = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_POSTASSIGN_MARKER_PATH'')',
        ('$expectedMarkerPath = {0}' -f $markerLiteral),
        'if ($markerPath -cne $expectedMarkerPath) { exit 12 }',
        '$blockText = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_POSTASSIGN_BLOCK_MS'')',
        '$blockMilliseconds = 0',
        'if (-not [int]::TryParse($blockText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$blockMilliseconds) -or $blockMilliseconds -ne 120000) { exit 12 }',
        '$markerInfo = [System.IO.FileInfo]::new($markerPath)',
        '$markerParent = $markerInfo.Directory',
        'if ($null -eq $markerParent -or -not $markerParent.Exists -or ($markerParent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $markerInfo.Exists) { exit 12 }',
        '$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()',
        '$processId = $currentProcess.Id',
        '$startFileTimeUtc = $currentProcess.StartTime.ToFileTimeUtc()',
        '$record = ''pspkt-phase4-post-gate-v1'' + [char]0x09 + $processId.ToString([System.Globalization.CultureInfo]::InvariantCulture) + [char]0x09 + $startFileTimeUtc.ToString([System.Globalization.CultureInfo]::InvariantCulture) + [char]0x0A',
        '$recordBytes = [System.Text.Encoding]::ASCII.GetBytes($record)',
        'if ($recordBytes.Length -gt 320) { exit 12 }',
        '$markerStream = [System.IO.FileStream]::new($markerPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)',
        'try {',
        '    $markerStream.Write($recordBytes, 0, $recordBytes.Length)',
        '    $markerStream.Flush($true)',
        '}',
        'finally {',
        '    $markerStream.Dispose()',
        '}',
        '$verifyStream = [System.IO.FileStream]::new($markerPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)',
        'try {',
        '    if ($verifyStream.Length -ne $recordBytes.Length) { exit 12 }',
        '    $verifyBytes = [byte[]]::new($recordBytes.Length)',
        '    $verifyOffset = 0',
        '    while ($verifyOffset -lt $verifyBytes.Length) {',
        '        $verifyRead = $verifyStream.Read($verifyBytes, $verifyOffset, $verifyBytes.Length - $verifyOffset)',
        '        if ($verifyRead -le 0) { exit 12 }',
        '        $verifyOffset += $verifyRead',
        '    }',
        '    for ($verifyIndex = 0; $verifyIndex -lt $recordBytes.Length; $verifyIndex++) { if ($verifyBytes[$verifyIndex] -ne $recordBytes[$verifyIndex]) { exit 12 } }',
        '}',
        'finally {',
        '    $verifyStream.Dispose()',
        '}',
        '[System.Threading.Thread]::Sleep($blockMilliseconds)',
        'exit 0'
    )
    $lines = [string[]]@($prefixLines + $helperLoadLines + $suffixLines)
    $scriptPath = Join-Path $Context.Root ('post-assignment-child-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $bytes = (New-PspktUtf8NoBom).GetBytes(($lines -join "`r`n") + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function New-PspktPostAssignmentLauncherScript {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$ChildScriptPath,
        [Parameter(Mandatory = $true)][string]$ChildGateName,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][Guid]$CorrelationId
    )
    $prelude = @'
$supervisorGateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SUPERVISOR_GATE_EVENT')
if ([string]::IsNullOrEmpty($supervisorGateName) -or -not [regex]::IsMatch($supervisorGateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 10 }
$namedEventType = $helperAssembly.GetType('Pspkt.Certification.NamedEvent', $true)
$eventAccessModeType = $helperAssembly.GetType('Pspkt.Certification.EventAccessMode', $true)
$eventRoleType = $helperAssembly.GetType('Pspkt.Certification.EventRole', $true)
$eventOpenMethod = $namedEventType.GetMethod('OpenExisting', [Type[]]@([string], $eventAccessModeType, $eventRoleType, [Guid]))
if ($null -eq $eventOpenMethod) { exit 10 }
$waitOnly = [System.Enum]::Parse($eventAccessModeType, 'WaitOnly')
$supervisorGateRole = [System.Enum]::Parse($eventRoleType, 'SupervisorGate')
try {
    $supervisorGate = $eventOpenMethod.Invoke($null, [object[]]@($supervisorGateName, $waitOnly, $supervisorGateRole, [Guid]::Empty))
}
catch {
    exit 10
}
try {
    $supervisorGateStatus = $supervisorGate.Wait(30000)
    if ([string]$supervisorGateStatus -cne 'Object0') { exit 11 }
}
finally {
    $supervisorGate.Close()
}
'@
    $validation = @'
$snapshotRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SNAPSHOT_ROOT')
$repositoryRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_REPOSITORY_ROOT')
$evidenceDirectory = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_POSTASSIGN_IDENTITY_ROOT')
$correlationText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_POSTASSIGN_CORRELATION_ID')
$markerPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_POSTASSIGN_MARKER_PATH')
$blockText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_POSTASSIGN_BLOCK_MS')
foreach ($requiredValue in @($snapshotRoot, $repositoryRoot, $evidenceDirectory, $correlationText, $markerPath, $blockText)) {
    if ([string]::IsNullOrEmpty($requiredValue)) { exit 12 }
}
if ($snapshotRoot -cne $expectedRoot -or $repositoryRoot -cne $expectedRoot -or
    $evidenceDirectory -cne $expectedEvidenceDirectory -or $markerPath -cne $expectedMarkerPath -or
    $correlationText -cne $expectedCorrelationText -or $blockText -cne '120000') { exit 12 }
$expectedEnvironmentNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($expectedEnvironmentName in @(
    'PSPKT_PHASE4_SUPERVISOR_GATE_EVENT', 'PSPKT_PHASE4_SNAPSHOT_ROOT', 'PSPKT_PHASE4_REPOSITORY_ROOT',
    'PSPKT_PHASE4_HELPER_PATH', 'PSPKT_PHASE4_HELPER_SHA256', 'PSPKT_PHASE4_HELPER_VERSION',
    'PSPKT_PHASE4_POSTASSIGN_IDENTITY_ROOT', 'PSPKT_PHASE4_POSTASSIGN_CORRELATION_ID',
    'PSPKT_PHASE4_POSTASSIGN_MARKER_PATH', 'PSPKT_PHASE4_POSTASSIGN_BLOCK_MS')) {
    [void]$expectedEnvironmentNames.Add($expectedEnvironmentName)
}
$actualEnvironmentCount = 0
foreach ($environmentName in [Environment]::GetEnvironmentVariables().Keys) {
    $environmentNameText = [string]$environmentName
    if ($environmentNameText.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $expectedEnvironmentNames.Contains($environmentNameText)) { exit 12 }
        $actualEnvironmentCount++
    }
}
if ($actualEnvironmentCount -ne $expectedEnvironmentNames.Count) { exit 12 }
if (-not [regex]::IsMatch($correlationText, '^[0-9a-f]{32}$')) { exit 12 }
$correlationId = [Guid]::ParseExact($correlationText, 'N')
$rootInfo = [System.IO.DirectoryInfo]::new($snapshotRoot)
$evidenceInfo = [System.IO.DirectoryInfo]::new($evidenceDirectory)
if (-not $rootInfo.Exists -or -not $evidenceInfo.Exists -or
    ($rootInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    ($evidenceInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    [System.IO.Path]::GetDirectoryName($markerPath) -cne $evidenceDirectory -or
    [System.IO.Path]::GetFileName($markerPath) -cne 'post-gate-ready.txt' -or
    [System.IO.File]::Exists($markerPath)) { exit 12 }
'@
    $launch = @'
$roleType = $helperAssembly.GetType('Pspkt.Certification.ProcessLaunchRole', $true)
$configurationType = $helperAssembly.GetType('Pspkt.Certification.ProcessLaunchConfiguration', $true)
$probeEvidenceType = $helperAssembly.GetType('Pspkt.Certification.ProbeEvidence', $true)
$pauseType = $helperAssembly.GetType('Pspkt.Certification.PauseConfiguration', $true)
$parentLossType = $helperAssembly.GetType('Pspkt.Certification.ParentLossMembership', $true)
$nestedType = $helperAssembly.GetType('Pspkt.Certification.NestedProof', $true)
$childRole = [System.Enum]::Parse($roleType, 'PostAssignmentProbeChild')
$childHost = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$childArguments = [string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childScriptPath)
$requiredNamesMethod = $helperHostType.GetMethod('GetRequiredReservedNames', [Type[]]@($roleType))
$requiredNames = [string[]]$requiredNamesMethod.Invoke($null, [object[]]@($childRole))
$expectedRequiredNames = [string[]]@('PSPKT_PHASE4_POSTASSIGN_MARKER_PATH', 'PSPKT_PHASE4_POSTASSIGN_BLOCK_MS')
if ($requiredNames.Length -ne $expectedRequiredNames.Length) { exit 13 }
for ($nameIndex = 0; $nameIndex -lt $requiredNames.Length; $nameIndex++) {
    if ($requiredNames[$nameIndex] -cne $expectedRequiredNames[$nameIndex]) { exit 13 }
}
$requiredValues = [string[]]@($markerPath, $blockText)
$evidenceConstructor = $probeEvidenceType.GetConstructor([Type[]]@([string], [Guid]))
if ($null -eq $evidenceConstructor) { exit 13 }
$probeEvidence = $evidenceConstructor.Invoke([object[]]@($evidenceDirectory, $correlationId))
$factoryTypes = [Type[]]@($roleType, [string], [string[]], [string], [string], [string[]], [string[]], [string[]], [string[]], [int], [int], [int], [int], [bool], [Guid], [string], $pauseType, $probeEvidenceType, $parentLossType, $nestedType)
$factory = $helperHostType.GetMethod('CreateProcessLaunchConfiguration', $factoryTypes)
if ($null -eq $factory) { exit 13 }
$configuration = $factory.Invoke($null, [object[]]@(
    $childRole, $childHost, $childArguments, $childGateName, 'PSPKT_PHASE4_GATE_EVENT',
    ([string[]]@()), ([string[]]@()), $requiredNames, $requiredValues,
    60000, 15000, 15000, 65536, $false, $correlationId, $childWorkingDirectory,
    $null, $probeEvidence, $null, $null))
$runMethod = $helperHostType.GetMethod('Run', [Type[]]@($configurationType))
if ($null -eq $runMethod) { exit 13 }
[void]$runMethod.Invoke($null, [object[]]@($configuration))
exit 39
'@
    $literalLines = [string[]]@(
        ('$expectedRoot = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $Context.Root)),
        ('$expectedEvidenceDirectory = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $EvidenceDirectory)),
        ('$expectedMarkerPath = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $MarkerPath)),
        ('$expectedCorrelationText = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $CorrelationId.ToString('N'))),
        ('$childScriptPath = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $ChildScriptPath)),
        ('$childGateName = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $ChildGateName)),
        ('$childWorkingDirectory = {0}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $Context.WorkingDirectory))
    )
    $text = ((Get-PspktVerifiedHelperLoadLines) -join "`r`n") + "`r`n" +
        $prelude + "`r`n" + ($literalLines -join "`r`n") + "`r`n" +
        $validation + "`r`n" + $launch
    $normalized = [regex]::Replace($text, "\r\n|\r|\n", "`r`n")
    $scriptPath = Join-Path $Context.Root ('post-assignment-launcher-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $bytes = (New-PspktUtf8NoBom).GetBytes($normalized + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function Wait-PspktReceiptWhileLauncherLive {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$LaunchSession,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $receiptStream = $null
            try {
                $receiptStream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                return $true
            }
            catch [System.IO.IOException] {
                $receiptStream = $null
            }
            finally {
                if ($null -ne $receiptStream) {
                    $receiptStream.Dispose()
                }
            }
        }
        if ($LaunchSession.HasExited) { return $false }
        [System.Threading.Thread]::Sleep(10)
    }
    return $false
}

function Invoke-PspktPostAssignmentKillOnCloseOracle {
    param([Parameter(Mandatory = $true)]$Binding)
    $context = New-PspktProcessOracleContext -Tag 'post-assignment-kill'
    $supervisorGate = $null
    $launchSession = $null
    $childProcess = $null
    $oracleResult = $false
    $primaryFailure = $null
    try {
        $correlationId = [Guid]::NewGuid()
        if (-not (Test-PspktPostAssignmentReceiptParserMutations -Binding $Binding -CorrelationId $correlationId)) { return $false }
        $evidenceDirectory = Join-Path $context.Root 'evidence'
        [void][System.IO.Directory]::CreateDirectory($evidenceDirectory)
        if (-not (Test-PspktNonReparseDirectory -FullPath $evidenceDirectory)) { return $false }
        $assignmentPath = Join-Path $evidenceDirectory 'assignment-evidence.txt'
        $markerPath = Join-Path $evidenceDirectory 'post-gate-ready.txt'
        $supervisorGateName = New-PspktGateEventName -Tag 'PostAssignSupervisor'
        $childGateName = New-PspktGateEventName -Tag 'PostAssignChild'
        if ($supervisorGateName -ceq $childGateName) { return $false }
        $supervisorGate = New-PspktObserverNamedEvent -Binding $Binding -Name $supervisorGateName -Role 'SupervisorGate' -CorrelationId ([Guid]::Empty)
        if ($supervisorGate.IsSignaledNow()) { return $false }
        $childScriptPath = New-PspktPostAssignmentChildScript -Context $context -Binding $Binding -MarkerPath $markerPath
        $launcherScriptPath = New-PspktPostAssignmentLauncherScript -Context $context -ChildScriptPath $childScriptPath -ChildGateName $childGateName -EvidenceDirectory $evidenceDirectory -MarkerPath $markerPath -CorrelationId $correlationId
        $reserved = @{
            'PSPKT_PHASE4_SNAPSHOT_ROOT' = $context.Root
            'PSPKT_PHASE4_REPOSITORY_ROOT' = $context.Root
            'PSPKT_PHASE4_HELPER_PATH' = $Binding.Path
            'PSPKT_PHASE4_HELPER_SHA256' = $Binding.Digest
            'PSPKT_PHASE4_HELPER_VERSION' = $Binding.Version
            'PSPKT_PHASE4_POSTASSIGN_IDENTITY_ROOT' = $evidenceDirectory
            'PSPKT_PHASE4_POSTASSIGN_CORRELATION_ID' = $correlationId.ToString('N')
            'PSPKT_PHASE4_POSTASSIGN_MARKER_PATH' = $markerPath
            'PSPKT_PHASE4_POSTASSIGN_BLOCK_MS' = '120000'
        }
        $configuration = New-PspktProcessOracleConfiguration -Binding $Binding -Role 'PostAssignmentLauncher' -ScriptPath $launcherScriptPath -Context $context -ReservedValueByName $reserved -GateEventName $supervisorGateName -WaitTimeoutMilliseconds 60000
        $launchSession = Invoke-PspktHelperStatic -Binding $Binding -Method 'RunDirectLaunch' -Arguments @($configuration)
        $supervisorGate.SetEvent()
        if (-not (Wait-PspktReceiptWhileLauncherLive -Path $assignmentPath -LaunchSession $launchSession -TimeoutMilliseconds 10000)) { return $false }
        $assignment = ConvertFrom-PspktAssignmentEvidenceBytes -Bytes (Read-PspktBoundedFileBytes -FullPath $assignmentPath -ByteCap 320) -ExpectedCorrelationId $correlationId
        if (-not (Wait-PspktReceiptWhileLauncherLive -Path $markerPath -LaunchSession $launchSession -TimeoutMilliseconds 10000)) { return $false }
        $postGate = ConvertFrom-PspktPostGateReadyBytes -Bytes (Read-PspktBoundedFileBytes -FullPath $markerPath -ByteCap 320)
        if ($postGate.ProcessId -ne $assignment.ProcessId -or $postGate.StartFileTimeUtc -ne $assignment.StartFileTimeUtc -or
            $assignment.AssignmentCountAfter -ne ($assignment.AssignmentCountBefore + 1)) { return $false }
        $childProcess = [System.Diagnostics.Process]::GetProcessById($assignment.ProcessId)
        [void]$childProcess.Handle
        if ($childProcess.StartTime.ToFileTimeUtc() -ne $assignment.StartFileTimeUtc) { return $false }
        $childProcess.Refresh()
        if ($childProcess.HasExited -or $launchSession.HasExited) { return $false }
        $launcherExitClock = [System.Diagnostics.Stopwatch]::StartNew()
        $launchSession.TerminateAndWait(2000)
        $launcherExitClock.Stop()
        if (-not $launchSession.HasExited -or $launcherExitClock.ElapsedMilliseconds -gt 2000) { return $false }
        if (-not $childProcess.WaitForExit(15000)) { return $false }
        $childProcess.Refresh()
        $oracleResult = ($childProcess.HasExited -and $launchSession.HasExited)
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    finally {
        $cleanupFailures = Close-PspktPostAssignmentKillOnCloseLaunch -ChildProcess $childProcess -LaunchSession $launchSession -SupervisorEvent $supervisorGate -Context $context -ChildExitDeadlineMilliseconds 15000
        $failure = New-PspktComposedFailure -Message 'post-assignment kill-on-close oracle primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures $cleanupFailures
        if ($null -ne $failure) {
            throw $failure
        }
    }
    return $oracleResult
}

function Add-PspktPostAssignmentKillOnCloseQuarantineRegistration {
    param(
        [AllowNull()]$ChildProcess = $null,
        [AllowNull()]$LaunchSession = $null,
        [AllowNull()]$SupervisorEvent = $null,
        [Parameter(Mandatory = $true)]$Context
    )
    $ownedList = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $SupervisorEvent) { [void]$ownedList.Add($SupervisorEvent) }
    $contextRoot = ''
    if ($null -ne $Context) {
        $rootProperty = $Context.PSObject.Properties['Root']
        if ($null -ne $rootProperty) { $contextRoot = [string]$rootProperty.Value }
    }
    $tempDirs = [string[]]@()
    if (-not [string]::IsNullOrEmpty($contextRoot)) {
        $tempDirs = [string[]]@($contextRoot)
    }
    $quarantineContext = [pscustomobject]@{
        CleanupState = 'Quarantined'
        TempDirs = $tempDirs
        OwnedEvents = $ownedList
        ChildProcess = $ChildProcess
        SupervisorEvent = $SupervisorEvent
        OracleContext = $Context
    }
    $quarantineLaunch = [pscustomobject]@{
        Session = $LaunchSession
        Context = $quarantineContext
        ChildProcess = $ChildProcess
        SupervisorEvent = $SupervisorEvent
    }
    $snapshots = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $ChildProcess) { [void]$snapshots.Add($ChildProcess) }
    if ($null -ne $LaunchSession) { [void]$snapshots.Add($LaunchSession) }
    if ($null -ne $SupervisorEvent) { [void]$snapshots.Add($SupervisorEvent) }
    return (Add-PspktQuarantineRegistration -Kind 'PostAssignmentKillOnClose' -Launch $quarantineLaunch -Snapshots ([object[]]$snapshots.ToArray()))
}

function Close-PspktPostAssignmentKillOnCloseLaunch {
    param(
        [AllowNull()]$ChildProcess = $null,
        [AllowNull()]$LaunchSession = $null,
        [AllowNull()]$SupervisorEvent = $null,
        [Parameter(Mandatory = $true)]$Context,
        [int]$ChildExitDeadlineMilliseconds = 15000
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()

    $childClean = $true
    if ($null -ne $ChildProcess) {
        $childExitProven = $false
        try {
            $ChildProcess.Refresh()
            if ($ChildProcess.HasExited) {
                $childExitProven = $true
            }
            else {
                $ChildProcess.Kill()
                [void]$ChildProcess.WaitForExit($ChildExitDeadlineMilliseconds)
                $ChildProcess.Refresh()
                $childExitProven = [bool]$ChildProcess.HasExited
            }
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            $childExitProven = $false
            try {
                $ChildProcess.Refresh()
                $childExitProven = [bool]$ChildProcess.HasExited
            }
            catch {
                $childExitProven = $false
            }
        }
        if ($childExitProven) {
            try {
                $ChildProcess.Dispose()
            }
            catch {
                $childExitProven = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if (-not $childExitProven) {
            $childClean = $false
            $childPidText = '(unknown)'
            try { $childPidText = [string]$ChildProcess.Id } catch { $childPidText = '(unknown)' }
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                    ('post-assignment kill-on-close cleanup: child process {0} exit could not be proven within the {1} ms bounded deadline; the Process wrapper was retained and rooted in the quarantine registry.' -f $childPidText, $ChildExitDeadlineMilliseconds)))
        }
    }

    $sessionClean = $true
    if ($null -ne $LaunchSession) {
        try {
            Close-PspktDirectLaunchSession -Session $LaunchSession
        }
        catch {
            $sessionClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    $eventClean = $true
    if ($childClean -and $sessionClean) {
        if ($null -ne $SupervisorEvent) {
            try {
                $SupervisorEvent.Dispose()
            }
            catch {
                $eventClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    else {
        $eventClean = $false
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                'post-assignment kill-on-close cleanup: supervisor-event disposal was withheld because child and/or launch-session ownership was not proven clean; the event was retained and rooted in the quarantine registry.'))
    }

    $contextClean = $true
    if ($childClean -and $sessionClean -and $eventClean) {
        try {
            Remove-PspktProcessOracleContext -Context $Context
        }
        catch {
            $contextClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    else {
        $contextClean = $false
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                'post-assignment kill-on-close cleanup: process-oracle context removal was withheld because child, session, and/or event ownership was not proven clean; the context root was retained and rooted in the quarantine registry.'))
    }

    if (-not ($childClean -and $sessionClean -and $eventClean -and $contextClean)) {
        try {
            [void](Add-PspktPostAssignmentKillOnCloseQuarantineRegistration -ChildProcess $ChildProcess -LaunchSession $LaunchSession -SupervisorEvent $SupervisorEvent -Context $Context)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    return ,([Exception[]]$cleanupFailures.ToArray())
}

function Initialize-PspktGateSignalObserverType {
    if ($null -ne ('PspktPhase4.GateSignalObserver' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace PspktPhase4
{
    public sealed class GateSignalObserver : IDisposable
    {
        private readonly string eventName;
        private readonly ManualResetEvent started = new ManualResetEvent(false);
        private readonly ManualResetEvent acquired = new ManualResetEvent(false);
        private readonly ManualResetEvent cancelled = new ManualResetEvent(false);
        private readonly Thread thread;
        private readonly ManualResetEvent stallGate;
        private readonly int joinTimeoutMilliseconds;
        private readonly object disposeLock = new object();
        private bool joined;
        private bool handlesClosed;
        private IntPtr gateHandle;
        private Exception exception;
        private const uint Synchronize = 0x00100000;
        private const uint WaitObject0 = 0x00000000;
        private const uint WaitTimeout = 0x00000102;
        private const uint WaitFailed = 0xFFFFFFFF;
        private const int ErrorFileNotFound = 2;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenEventW(uint desiredAccess, bool inheritHandle, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public GateSignalObserver(string eventName)
        {
            this.eventName = eventName;
            this.stallGate = null;
            this.joinTimeoutMilliseconds = 10000;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "PspktPhase4GateSignalObserver";
        }

        private GateSignalObserver(int joinTimeoutMilliseconds)
        {
            this.eventName = null;
            this.stallGate = new ManualResetEvent(false);
            this.joinTimeoutMilliseconds = joinTimeoutMilliseconds;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "PspktPhase4GateSignalObserverStall";
        }

        public static GateSignalObserver CreateCertificationStallProbe(int joinTimeoutMilliseconds)
        {
            return new GateSignalObserver(joinTimeoutMilliseconds);
        }

        public void ReleaseCertificationStall()
        {
            ManualResetEvent gate = stallGate;
            if (gate != null) { gate.Set(); }
        }

        public bool StallHandlesUsable()
        {
            try
            {
                started.WaitOne(0);
                acquired.WaitOne(0);
                cancelled.WaitOne(0);
                if (stallGate != null) { stallGate.WaitOne(0); }
                return true;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        public bool Join(int milliseconds)
        {
            return thread.Join(milliseconds);
        }

        public Exception Exception { get { return exception; } }

        public void Start()
        {
            thread.Start();
            if (!started.WaitOne(10000))
            {
                throw new InvalidOperationException("gate signal observer did not reach its startup latch.");
            }
        }

        public bool WaitUntilAcquired(int timeoutMilliseconds)
        {
            return acquired.WaitOne(timeoutMilliseconds);
        }

        public bool IsSignaledNow()
        {
            if (!acquired.WaitOne(0) || gateHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException("gate signal observer has not retained the event.");
            }
            uint status = WaitForSingleObject(gateHandle, 0);
            if (status == WaitObject0) { return true; }
            if (status == WaitTimeout) { return false; }
            if (status == WaitFailed)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed for retained gate event.");
            }
            throw new InvalidOperationException("WaitForSingleObject returned an unexpected gate-event status.");
        }

        private void Run()
        {
            started.Set();
            if (stallGate != null)
            {
                stallGate.WaitOne();
                return;
            }
            try
            {
                while (!cancelled.WaitOne(0))
                {
                    gateHandle = OpenEventW(Synchronize, false, eventName);
                    if (gateHandle != IntPtr.Zero)
                    {
                        acquired.Set();
                        cancelled.WaitOne();
                        return;
                    }
                    int error = Marshal.GetLastWin32Error();
                    if (error != ErrorFileNotFound)
                    {
                        throw new Win32Exception(error, "OpenEventW failed for gate signal observer.");
                    }
                    Thread.Sleep(1);
                }
            }
            catch (Win32Exception observed)
            {
                exception = observed;
            }
        }

        public void Dispose()
        {
            lock (disposeLock)
            {
                if (handlesClosed) { return; }
                if (Thread.CurrentThread == thread)
                {
                    throw new InvalidOperationException("gate signal observer cannot dispose itself from its own worker thread.");
                }
                cancelled.Set();
                if (!joined)
                {
                    if (!thread.Join(joinTimeoutMilliseconds))
                    {
                        throw new InvalidOperationException("gate signal observer worker thread did not terminate within the bounded join; retained handles were not closed.");
                    }
                    joined = true;
                }
                if (gateHandle != IntPtr.Zero)
                {
                    if (!CloseHandle(gateHandle))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle failed for retained gate event.");
                    }
                    gateHandle = IntPtr.Zero;
                }
                started.Close();
                acquired.Close();
                cancelled.Close();
                if (stallGate != null) { stallGate.Close(); }
                handlesClosed = true;
            }
        }
    }
}
'@
}

function Invoke-PspktPostAssignmentEvidenceFailureOracle {
    param([Parameter(Mandatory = $true)]$Binding)
    Initialize-PspktGateSignalObserverType
    $context = New-PspktProcessOracleContext -Tag 'post-assignment-evidence-failure'
    $observer = $null
    $retainedProcess = $null
    $oracleResult = $false
    $primaryFailure = $null
    try {
        $correlationId = [Guid]::NewGuid()
        $evidenceDirectory = Join-Path $context.Root 'evidence'
        [void][System.IO.Directory]::CreateDirectory($evidenceDirectory)
        if (-not (Test-PspktNonReparseDirectory -FullPath $evidenceDirectory)) { return $false }
        $assignmentPath = Join-Path $evidenceDirectory 'assignment-evidence.txt'
        $markerPath = Join-Path $evidenceDirectory 'post-gate-ready.txt'
        $collisionStream = [System.IO.FileStream]::new($assignmentPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $collisionStream.Flush($true)
        }
        finally {
            $collisionStream.Dispose()
        }
        $childScriptPath = New-PspktPostAssignmentChildScript -Context $context -Binding $Binding -MarkerPath $markerPath
        $gateName = New-PspktGateEventName -Tag 'PostAssignFailure'
        $reserved = @{
            'PSPKT_PHASE4_POSTASSIGN_MARKER_PATH' = $markerPath
            'PSPKT_PHASE4_POSTASSIGN_BLOCK_MS' = '120000'
        }
        $evidence = New-PspktProbeEvidence -Binding $Binding -EvidenceDirectory $evidenceDirectory -CorrelationId $correlationId
        $configuration = New-PspktTypedProcessOracleConfiguration -Binding $Binding -Role 'PostAssignmentProbeChild' -ScriptPath $childScriptPath -Context $context -ReservedValueByName $reserved -GateEventName $gateName -CorrelationId $correlationId -ProbeEvidence $evidence -WaitTimeoutMilliseconds 60000
        $before = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot' -Arguments @()
        $observer = [PspktPhase4.GateSignalObserver]::new($gateName)
        $observer.Start()
        $expectedType = Get-PspktHelperType -Binding $Binding -SimpleName 'PostAssignmentEvidenceException'
        $caught = $null
        try {
            [void](Invoke-PspktHelperStatic -Binding $Binding -Method 'Run' -Arguments @($configuration))
            return $false
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $candidate = $_.Exception.InnerException
            if ($null -ne $candidate -and $candidate -is [System.Reflection.TargetInvocationException]) {
                $candidate = $candidate.InnerException
            }
            if ($null -eq $candidate -or $candidate.GetType() -ne $expectedType) { throw }
            $caught = $candidate
        }
        catch [System.Reflection.TargetInvocationException] {
            $candidate = $_.Exception.InnerException
            if ($null -eq $candidate -or $candidate.GetType() -ne $expectedType) { throw }
            $caught = $candidate
        }
        $after = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetDiagnosticsSnapshot' -Arguments @()
        if ($null -eq $caught) { return $false }
        $expectedMessage = 'post-assignment evidence write failed for child {0} correlation {1}.' -f $caught.ChildProcessId, $correlationId.ToString('N')
        $evidenceErrorCode = $caught.EvidenceCause.HResult -band 0xffff
        $collisionLength = [System.IO.FileInfo]::new($assignmentPath).Length
        if ($caught.ChildProcessId -lt 1 -or $caught.ChildStartTimeFileTimeUtc -lt 1 -or
            $caught.CorrelationId -ne $correlationId -or $caught.EvidenceCause.GetType() -ne [System.IO.IOException] -or
            $null -ne $caught.PrimaryCause -or $caught.InnerException -ne $caught.EvidenceCause -or
            $caught.Message -cne $expectedMessage -or ($evidenceErrorCode -ne 80 -and $evidenceErrorCode -ne 183) -or
            $collisionLength -ne 0 -or $after.JobCreateCount -ne ($before.JobCreateCount + 1) -or
            $after.ProcessStartCount -ne ($before.ProcessStartCount + 1) -or
            $after.AssignmentAttemptCount -ne ($before.AssignmentAttemptCount + 1)) { return $false }
        if (-not $observer.WaitUntilAcquired(10000)) { return $false }
        if ($null -ne $observer.Exception -or $observer.IsSignaledNow()) { return $false }
        if (Test-Path -LiteralPath $markerPath) { return $false }
        try {
            $retainedProcess = [System.Diagnostics.Process]::GetProcessById($caught.ChildProcessId)
            [void]$retainedProcess.Handle
            if ($retainedProcess.StartTime.ToFileTimeUtc() -ne $caught.ChildStartTimeFileTimeUtc) { return $false }
            $retainedProcess.Refresh()
            if (-not $retainedProcess.HasExited) { return $false }
        }
        catch [System.ArgumentException] {
            $retainedProcess = $null
        }
        $oracleResult = $true
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    finally {
        $cleanupFailures = Close-PspktPostAssignmentEvidenceLaunch -Observer $observer -RetainedProcess $retainedProcess -Context $context
        $failure = New-PspktComposedFailure -Message 'post-assignment evidence-failure oracle primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures $cleanupFailures
        if ($null -ne $failure) {
            throw $failure
        }
    }
    return $oracleResult
}

function Add-PspktPostAssignmentEvidenceQuarantineRegistration {
    param(
        [AllowNull()]$Observer = $null,
        [AllowNull()]$RetainedProcess = $null,
        [Parameter(Mandatory = $true)]$Context
    )
    $contextRoot = ''
    if ($null -ne $Context) {
        $rootProperty = $Context.PSObject.Properties['Root']
        if ($null -ne $rootProperty) { $contextRoot = [string]$rootProperty.Value }
    }
    $tempDirs = [string[]]@()
    if (-not [string]::IsNullOrEmpty($contextRoot)) {
        $tempDirs = [string[]]@($contextRoot)
    }
    $quarantineContext = [pscustomobject]@{
        CleanupState = 'Quarantined'
        TempDirs = $tempDirs
        OwnedEvents = [System.Collections.Generic.List[object]]::new()
        Observer = $Observer
        RetainedProcess = $RetainedProcess
        OracleContext = $Context
    }
    $quarantineLaunch = [pscustomobject]@{
        Session = $Observer
        Context = $quarantineContext
        Observer = $Observer
        RetainedProcess = $RetainedProcess
    }
    $snapshots = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Observer) { [void]$snapshots.Add($Observer) }
    if ($null -ne $RetainedProcess) { [void]$snapshots.Add($RetainedProcess) }
    return (Add-PspktQuarantineRegistration -Kind 'PostAssignmentEvidence' -Launch $quarantineLaunch -Snapshots ([object[]]$snapshots.ToArray()))
}

function Close-PspktPostAssignmentEvidenceLaunch {
    param(
        [AllowNull()]$Observer = $null,
        [AllowNull()]$RetainedProcess = $null,
        [Parameter(Mandatory = $true)]$Context
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()

    $observerClean = $true
    if ($null -ne $Observer) {
        try {
            $Observer.Dispose()
        }
        catch {
            $observerClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    $processClean = $true
    if ($null -ne $RetainedProcess) {
        try {
            $RetainedProcess.Dispose()
        }
        catch {
            $processClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    $contextClean = $true
    if ($observerClean -and $processClean) {
        try {
            Remove-PspktProcessOracleContext -Context $Context
        }
        catch {
            $contextClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    else {
        $contextClean = $false
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                'post-assignment evidence-failure cleanup: process-oracle context removal was withheld because observer and/or retained-process ownership was not proven clean; the context root was retained and rooted in the quarantine registry.'))
    }

    if (-not ($observerClean -and $processClean -and $contextClean)) {
        try {
            [void](Add-PspktPostAssignmentEvidenceQuarantineRegistration -Observer $Observer -RetainedProcess $RetainedProcess -Context $Context)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }

    return ,([Exception[]]$cleanupFailures.ToArray())
}

function Initialize-PspktNestedObserverType {
    if ($null -ne ('PspktPhase4.NestedObserver' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Globalization;
using System.Reflection;
using System.Threading;

namespace PspktPhase4
{
    public sealed class NestedObserver : IDisposable
    {
        private readonly string releaseAuthorizedName;
        private readonly string proofCompleteName;
        private readonly object nestedReleaseEvent;
        private readonly MethodInfo nestedReleaseSet;
        private readonly MethodInfo writeExitReceipt;
        private readonly string controlRoot;
        private readonly string nonce;
        private readonly Guid correlationId;
        private readonly string childExitedName;
        private readonly ManualResetEvent started = new ManualResetEvent(false);
        private readonly ManualResetEvent completed = new ManualResetEvent(false);
        private readonly ManualResetEvent runComplete = new ManualResetEvent(false);
        private readonly ManualResetEvent cancelled = new ManualResetEvent(false);
        private readonly Thread thread;
        private int exitCode;
        private long activeAfter;
        private int childProcessId;
        private long childStartFileTimeUtc;
        private bool proofSucceeded;
        private Exception exception;
        private readonly int joinTimeoutMilliseconds;
        private readonly ManualResetEvent stallGate;
        private readonly object disposeLock = new object();
        private bool disposed;

        public NestedObserver(
            string releaseAuthorizedName,
            string proofCompleteName,
            object nestedReleaseEvent,
            Type hostType,
            string controlRoot,
            string nonce,
            Guid correlationId,
            string childExitedName)
        {
            if (nestedReleaseEvent == null) { throw new ArgumentNullException("nestedReleaseEvent"); }
            if (hostType == null) { throw new ArgumentNullException("hostType"); }
            this.releaseAuthorizedName = releaseAuthorizedName;
            this.proofCompleteName = proofCompleteName;
            this.nestedReleaseEvent = nestedReleaseEvent;
            this.nestedReleaseSet = nestedReleaseEvent.GetType().GetMethod("SetEvent", Type.EmptyTypes);
            this.writeExitReceipt = hostType.GetMethod("WriteNestedChildExitReceipt", BindingFlags.Public | BindingFlags.Static);
            this.controlRoot = controlRoot;
            this.nonce = nonce;
            this.correlationId = correlationId;
            this.childExitedName = childExitedName;
            if (this.nestedReleaseSet == null) { throw new InvalidOperationException("the nested-release NamedEvent has no SetEvent method."); }
            if (this.writeExitReceipt == null) { throw new InvalidOperationException("the helper has no WriteNestedChildExitReceipt method."); }
            this.joinTimeoutMilliseconds = 10000;
            this.stallGate = null;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "PspktPhase4NestedObserver";
        }

        private NestedObserver(int joinTimeoutMilliseconds)
        {
            this.stallGate = new ManualResetEvent(false);
            this.joinTimeoutMilliseconds = joinTimeoutMilliseconds;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "PspktPhase4NestedObserverStall";
        }

        public static NestedObserver CreateCertificationStallProbe(int joinTimeoutMilliseconds)
        {
            return new NestedObserver(joinTimeoutMilliseconds);
        }

        public void ReleaseCertificationStall()
        {
            ManualResetEvent gate = stallGate;
            if (gate != null) { gate.Set(); }
        }

        public bool StallHandlesUsable()
        {
            try
            {
                started.WaitOne(0);
                completed.WaitOne(0);
                runComplete.WaitOne(0);
                cancelled.WaitOne(0);
                if (stallGate != null) { stallGate.WaitOne(0); }
                return true;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        public bool ProofSucceeded { get { return proofSucceeded; } }
        public Exception Exception { get { return exception; } }

        public void Start()
        {
            thread.Start();
            if (!started.WaitOne(10000))
            {
                throw new InvalidOperationException("nested observer did not reach its startup latch.");
            }
        }

        public void SetRunResult(int exitCode, long activeAfter, int childProcessId, long childStartFileTimeUtc)
        {
            this.exitCode = exitCode;
            this.activeAfter = activeAfter;
            this.childProcessId = childProcessId;
            this.childStartFileTimeUtc = childStartFileTimeUtc;
            runComplete.Set();
        }

        public bool Join(int milliseconds)
        {
            return thread.Join(milliseconds);
        }

        public void Cancel()
        {
            cancelled.Set();
        }

        private void Run()
        {
            try
            {
                started.Set();
                if (stallGate != null)
                {
                    stallGate.WaitOne();
                    return;
                }
                using (EventWaitHandle releaseAuthorized = EventWaitHandle.OpenExisting(releaseAuthorizedName))
                {
                    int signaled = WaitHandle.WaitAny(new WaitHandle[] { releaseAuthorized, cancelled }, 10000);
                    if (signaled != 0) { throw new TimeoutException("nested observer did not receive release-authorized."); }
                }
                nestedReleaseSet.Invoke(nestedReleaseEvent, null);
                int runSignaled = WaitHandle.WaitAny(new WaitHandle[] { runComplete, cancelled }, 15000);
                if (runSignaled != 0) { throw new TimeoutException("nested observer did not receive the run result."); }
                if (exitCode != 0)
                {
                    throw new InvalidOperationException("nested child exit code was " + exitCode.ToString(CultureInfo.InvariantCulture) + ".");
                }
                if (activeAfter != 0)
                {
                    throw new InvalidOperationException("inner job still reported " + activeAfter.ToString(CultureInfo.InvariantCulture) + " active processes.");
                }
                writeExitReceipt.Invoke(null, new object[] { controlRoot, nonce, correlationId, childProcessId, childStartFileTimeUtc, exitCode, childExitedName });
                using (EventWaitHandle proofComplete = EventWaitHandle.OpenExisting(proofCompleteName))
                {
                    int proofSignaled = WaitHandle.WaitAny(new WaitHandle[] { proofComplete, cancelled }, 10000);
                    if (proofSignaled != 0) { throw new TimeoutException("nested observer did not receive proof-complete."); }
                }
                proofSucceeded = true;
            }
            catch (Exception observerError)
            {
                exception = observerError;
            }
            finally
            {
                completed.Set();
            }
        }

        public void Dispose()
        {
            lock (disposeLock)
            {
                if (disposed) { return; }
                if (Thread.CurrentThread == thread)
                {
                    throw new InvalidOperationException("nested observer cannot dispose itself from its own worker thread.");
                }
                cancelled.Set();
                bool joined = thread.Join(joinTimeoutMilliseconds);
                if (!joined)
                {
                    throw new InvalidOperationException("nested observer worker thread did not terminate within the bounded join; handles retained.");
                }
                started.Close();
                completed.Close();
                runComplete.Close();
                cancelled.Close();
                if (stallGate != null) { stallGate.Close(); }
                disposed = true;
            }
        }
    }
}
'@
}

function New-PspktNestedChildPostGateLines {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($helperLine in (Get-PspktVerifiedHelperLoadLines)) {
        [void]$lines.Add($helperLine)
    }
    [void]$lines.Add("`$nestedReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_READY_EVENT')")
    [void]$lines.Add("`$nestedReleaseName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_RELEASE_EVENT')")
    [void]$lines.Add('if ([string]::IsNullOrEmpty($nestedReadyName) -or [string]::IsNullOrEmpty($nestedReleaseName)) { exit 6 }')
    [void]$lines.Add("`$nestedStatus = `$helperHostType.InvokeMember('RunNestedPrelude', [System.Reflection.BindingFlags]'InvokeMethod, Public, Static', `$null, `$null, @(`$nestedReadyName, `$nestedReleaseName, 45000))")
    [void]$lines.Add("if ([string]`$nestedStatus.ToString() -cne 'Object0') { exit 7 }")
    [void]$lines.Add('exit 0')
    return [string[]]$lines.ToArray()
}

function New-PspktNestedCapabilityChildConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$GateEventName,
        [Parameter(Mandatory = $true)][Guid]$Correlation,
        [Parameter(Mandatory = $true)]$NestedProof,
        [Parameter(Mandatory = $true)][string]$NestedReadyName,
        [Parameter(Mandatory = $true)][string]$NestedReleaseName
    )
    $role = Get-PspktHelperEnum -Binding $Binding -EnumName 'ProcessLaunchRole' -Member 'NestedCapabilityChild'
    $gateVariable = Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRoleGateVariable' -Arguments @($role)
    $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRequiredReservedNames' -Arguments @($role))
    $valueByName = @{
        'PSPKT_PHASE4_HELPER_PATH' = [string]$Binding.Path
        'PSPKT_PHASE4_HELPER_SHA256' = [string]$Binding.Digest
        'PSPKT_PHASE4_HELPER_VERSION' = [string]$Binding.Version
        'PSPKT_PHASE4_NESTED_READY_EVENT' = [string]$NestedReadyName
        'PSPKT_PHASE4_NESTED_RELEASE_EVENT' = [string]$NestedReleaseName
    }
    $reservedValues = [System.Collections.Generic.List[string]]::new()
    foreach ($reservedName in $reservedNames) {
        if (-not $valueByName.ContainsKey($reservedName)) {
            throw ('nested capability child: unexpected reserved name "{0}".' -f $reservedName)
        }
        [void]$reservedValues.Add([string]$valueByName[$reservedName])
    }
    $factoryArguments = [object[]]::new(20)
    $factoryArguments[0] = $role
    $factoryArguments[1] = [string](Get-PspktHostExecutable)
    $factoryArguments[2] = [string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ScriptPath)
    $factoryArguments[3] = [string]$GateEventName
    $factoryArguments[4] = [string]$gateVariable
    $factoryArguments[5] = [string[]]@()
    $factoryArguments[6] = [string[]]@()
    $factoryArguments[7] = [string[]]$reservedNames
    $factoryArguments[8] = [string[]]$reservedValues.ToArray()
    $factoryArguments[9] = 60000
    $factoryArguments[10] = 15000
    $factoryArguments[11] = 15000
    $factoryArguments[12] = 65536
    $factoryArguments[13] = $false
    $factoryArguments[14] = $Correlation
    $factoryArguments[15] = [string]$WorkingDirectory
    $factoryArguments[16] = $null
    $factoryArguments[17] = $null
    $factoryArguments[18] = $null
    $factoryArguments[19] = $NestedProof
    return Invoke-PspktHelperStatic -Binding $Binding -Method 'CreateProcessLaunchConfiguration' -Arguments $factoryArguments
}

function Invoke-PspktWorkerNestedMembershipOracle {
    param([Parameter(Mandatory = $true)]$Binding)

    if (-not (Test-PspktNestedMembershipReceiptNegativeVectors)) { return $false }
    if (-not (Test-PspktNestedChildExitReceiptNegativeVectors)) { return $false }

    $controlRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_CONTROL_ROOT')
    $nestedNonce = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_NONCE')
    $evidenceReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_EVIDENCE_READY')
    $releaseAuthorizedName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_RELEASE_AUTHORIZED')
    $nestedReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_READY_EVENT')
    $nestedReleaseName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_RELEASE_EVENT')
    $childExitedName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_CHILD_EXITED')
    $proofCompleteName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_NESTED_PROOF_COMPLETE')
    foreach ($authorityValue in @($controlRoot, $nestedNonce, $evidenceReadyName, $releaseAuthorizedName, $nestedReadyName, $nestedReleaseName, $childExitedName, $proofCompleteName)) {
        if ([string]::IsNullOrEmpty($authorityValue)) { return $false }
    }
    if (-not [regex]::IsMatch($nestedNonce, '^[0-9a-f]{32}$')) { return $false }

    Initialize-PspktNestedObserverType

    $nestedReadyEvent = $null
    $nestedReleaseEvent = $null
    $observer = $null
    $oracleContext = $null
    $success = $false
    $primaryFailure = $null
    try {
        $nestedReadyRole = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member 'NestedReady'
        $nestedReleaseRole = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member 'NestedRelease'
        $nestedReadyEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($nestedReadyName, $nestedReadyRole, [Guid]::Empty)
        $nestedReleaseEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($nestedReleaseName, $nestedReleaseRole, [Guid]::Empty)

        $oracleContext = New-PspktProcessOracleContext -Tag 'nested'
        $postGateLines = New-PspktNestedChildPostGateLines
        $scriptPath = New-PspktGateFirstScript -Context $oracleContext -GateMode 'Required' -LiteralGateTimeoutMilliseconds 60000 -PostGateLines $postGateLines

        $correlation = [Guid]::NewGuid()
        $nestedProof = New-PspktHelperObject -Binding $Binding -SimpleName 'NestedProof' -Arguments @($nestedNonce, $controlRoot, $correlation, $evidenceReadyName, $nestedReadyName, $nestedReleaseName)
        $childGateName = New-PspktGateEventName -Tag 'Nst'
        $childConfig = New-PspktNestedCapabilityChildConfiguration -Binding $Binding -ScriptPath $scriptPath -WorkingDirectory $oracleContext.WorkingDirectory -GateEventName $childGateName -Correlation $correlation -NestedProof $nestedProof -NestedReadyName $nestedReadyName -NestedReleaseName $nestedReleaseName

        $observer = [PspktPhase4.NestedObserver]::new($releaseAuthorizedName, $proofCompleteName, $nestedReleaseEvent, $Binding.HostType, $controlRoot, $nestedNonce, $correlation, $childExitedName)
        $observer.Start()

        $runResult = Invoke-PspktHelperStatic -Binding $Binding -Method 'Run' -Arguments @($childConfig)

        $depositOk = $false
        if ([bool]$runResult.Started -and [bool]$runResult.Exited) {
            $membership = Read-PspktNestedReceiptFile -ControlRoot $controlRoot -Leaf 'nested-membership.txt' -ExpectedTag 'pspkt-phase4-nested-membership-v1' -Kind 'membership'
            if ($membership.Nonce -ceq $nestedNonce -and $membership.Correlation -ceq $correlation.ToString('N') -and $membership.MembershipTrue) {
                $observer.SetRunResult([int]$runResult.ExitCode, [long]$runResult.ActiveProcessesAfterTerminate, [int]$membership.Pid, [long]$membership.StartFileTimeUtc)
                $depositOk = $true
            }
        }
        if (-not $depositOk) { $observer.Cancel() }

        $joined = $observer.Join(10000)
        if (-not $joined) {
            $observer.Cancel()
            [void]$observer.Join(2000)
        }

        $success = ($depositOk -and $joined -and ($null -eq $observer.Exception) -and $observer.ProofSucceeded -and
            [bool]$runResult.Started -and [bool]$runResult.Exited -and
            ([int]$runResult.ExitCode -eq 0) -and ([long]$runResult.ActiveProcessesAfterTerminate -eq 0))
    }
    catch {
        $success = $false
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
        if ($null -ne $observer) {
            try {
                $observer.Cancel()
                [void]$observer.Join(2000)
            }
            catch {
                $primaryFailure = New-PspktComposedFailure -Message 'nested membership observer primary and cancellation failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]@((Get-PspktInnermostException -Exception $_.Exception)))
            }
        }
    }
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    $ownershipClean = $true
    $observerDisposeFailed = $false
    if ($null -ne $observer) {
        try {
            $observer.Dispose()
        }
        catch {
            $ownershipClean = $false
            $observerDisposeFailed = $true
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    if ($observerDisposeFailed) {
        $nestedAuthorityHandles = [System.Collections.Generic.List[object]]::new()
        if ($null -ne $nestedReadyEvent) { [void]$nestedAuthorityHandles.Add($nestedReadyEvent) }
        if ($null -ne $nestedReleaseEvent) { [void]$nestedAuthorityHandles.Add($nestedReleaseEvent) }
        try {
            [void](Add-PspktObserverQuarantineRegistration -Kind 'NestedObserver' -Observer $observer -AuthorityHandles ([object[]]$nestedAuthorityHandles.ToArray()) -OracleContext $oracleContext)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('nested membership event and context cleanup was withheld because the observer worker thread did not quiesce; the observer, authority events, and context were rooted in the quarantine registry.'))
    }
    else {
        if ($null -ne $nestedReadyEvent) {
            try {
                $nestedReadyEvent.Close()
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if ($null -ne $nestedReleaseEvent) {
            try {
                $nestedReleaseEvent.Close()
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if ($null -ne $oracleContext) {
            if ($ownershipClean) {
                try {
                    Remove-PspktProcessOracleContext -Context $oracleContext
                }
                catch {
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
            }
            else {
                [void]$cleanupFailures.Add([System.InvalidOperationException]::new('nested membership context cleanup was withheld because event ownership was not clean.'))
            }
        }
    }
    $failure = New-PspktComposedFailure -Message 'nested membership primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
    if ($null -ne $failure) {
        throw $failure
    }
    return $success
}

function New-PspktFailFastProbeScript {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][ValidateSet('drain-nonunwinding', 'drain-nonunwinding-negative-control')][string]$ProbeMode
    )
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add("`$gateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SUPERVISOR_GATE_EVENT')")
    [void]$lines.Add("if ([string]::IsNullOrEmpty(`$gateName) -or -not [regex]::IsMatch(`$gateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 10 }")
    [void]$lines.Add('try {')
    [void]$lines.Add('    $gate = [System.Threading.EventWaitHandle]::OpenExisting($gateName)')
    [void]$lines.Add('}')
    [void]$lines.Add('catch [System.Threading.WaitHandleCannotBeOpenedException] {')
    [void]$lines.Add('    exit 10')
    [void]$lines.Add('}')
    [void]$lines.Add('catch [System.UnauthorizedAccessException] {')
    [void]$lines.Add('    exit 10')
    [void]$lines.Add('}')
    [void]$lines.Add('try {')
    [void]$lines.Add('    if (-not $gate.WaitOne(60000)) { exit 11 }')
    [void]$lines.Add('}')
    [void]$lines.Add('finally {')
    [void]$lines.Add('    $gate.Close()')
    [void]$lines.Add('}')
    foreach ($helperLine in (Get-PspktVerifiedHelperLoadLines)) {
        [void]$lines.Add($helperLine)
    }
    [void]$lines.Add("`$probeMode = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_MODE')")
    [void]$lines.Add("`$probeNonce = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_NONCE')")
    [void]$lines.Add("`$sentinelPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_FAILFAST_SENTINEL_PATH')")
    [void]$lines.Add("`$failfastResultPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_FAILFAST_RESULT_PATH')")
    [void]$lines.Add('if ([string]::IsNullOrEmpty($probeMode) -or [string]::IsNullOrEmpty($probeNonce) -or [string]::IsNullOrEmpty($sentinelPath) -or [string]::IsNullOrEmpty($failfastResultPath)) { exit 6 }')
    [void]$lines.Add(('if ($probeMode -cne {0}) {{ exit 6 }}' -f (ConvertTo-PspktSingleQuotedLiteral -Value $ProbeMode)))
    [void]$lines.Add('$helperVersionValue = [string]$helperVersionField.GetValue($null)')
    if ($ProbeMode -ceq 'drain-nonunwinding') {
        [void]$lines.Add("`$drainMethod = `$helperHostType.GetMethod('RunNonUnwindingDrainProbe', [type[]]@([string], [string], [string], [int]))")
        [void]$lines.Add('if ($null -eq $drainMethod) { exit 7 }')
        [void]$lines.Add('[void]$drainMethod.Invoke($null, [object[]]@([string]$sentinelPath, [string]$helperVersionValue, [string]$probeNonce, [int]5000))')
        [void]$lines.Add('exit 30')
    }
    else {
        [void]$lines.Add("`$negMethod = `$helperHostType.GetMethod('RunNonUnwindingNegativeControl', [type[]]@([string], [string], [string]))")
        [void]$lines.Add('if ($null -eq $negMethod) { exit 7 }')
        [void]$lines.Add('[void]$negMethod.Invoke($null, [object[]]@([string]$sentinelPath, [string]$helperVersionValue, [string]$probeNonce))')
        [void]$lines.Add('exit 31')
    }

    $scriptPath = Join-Path $Context.Root ('failfast-probe-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $bytes = (New-PspktUtf8NoBom).GetBytes(($lines -join "`r`n") + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function Read-PspktFailFastSentinel {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'failfast sentinel: path is absent.'
    }
    $bytes = Read-PspktBoundedFileBytes -FullPath $Path -ByteCap 2048
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'failfast sentinel: unexpected BOM.'
    }
    $text = (New-PspktUtf8NoBom).GetString($bytes)
    if ($text.IndexOf([char]0x0D) -ge 0) { throw 'failfast sentinel: carriage return is forbidden.' }
    $tab = [char]0x09
    $lines = @($text -split "`n")
    if ($lines.Count -ne 2 -or $lines[1] -cne '') { throw 'failfast sentinel: not exactly one terminated record.' }
    $fields = $lines[0] -split $tab
    if ($fields.Count -ne 4) { throw 'failfast sentinel: field count is not 4.' }
    if ($fields[0] -cne 'pspkt-phase4-failfast-sentinel-v1') { throw 'failfast sentinel: bad tag.' }
    if ($fields[1] -cne $ExpectedVersion) { throw 'failfast sentinel: helper version mismatch.' }
    if ($fields[2] -cne $ExpectedNonce) { throw 'failfast sentinel: probe nonce mismatch.' }
    if ($fields[3] -cnotmatch '^(0|[1-9][0-9]*)$') { throw 'failfast sentinel: snapshot-access is not a canonical integer.' }
    return [long]::Parse($fields[3], [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-PspktWorkerProbeMap {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [switch]$ProcessOraclesOnly
    )
    $b = $Binding
    $map = @{}

    if ($ProcessOraclesOnly.IsPresent) {
        $processOracleIds = [string[]]@(
            'gate-success',
            'gate-missing-environment',
            'gate-wrong-name',
            'gate-timeout',
            'gate-delayed-signal',
            'gate-name-squat',
            'assignment-failure',
            'watchdog-timeout',
            'descendant-timeout',
            'output-overflow',
            'helper-digest-mismatch'
        )
        foreach ($processOracleId in $processOracleIds) {
            $map[$processOracleId] = $null
        }
    }
    else {
        $hostExe = Get-PspktHostExecutable
    }

    $map['quoter-edge-cases'] = {
        $expectations = @(
            @{ In = ''; Out = '""' },
            @{ In = 'abc'; Out = 'abc' },
            @{ In = 'a b'; Out = '"a b"' },
            @{ In = 'a"b'; Out = '"a\"b"' },
            @{ In = 'a\'; Out = 'a\' },
            @{ In = 'a\"b'; Out = '"a\\\"b"' },
            @{ In = 'c:\p q\f.json'; Out = '"c:\p q\f.json"' }
        )
        foreach ($expect in $expectations) {
            $actual = Invoke-PspktHelperStatic -Binding $b -Method 'QuoteWindowsCommandLineArgument' -Arguments @([string]$expect.In)
            if ($actual -cne $expect.Out) { return $false }
        }
        return $true
    }.GetNewClosure()

    $map['security-attributes-abi'] = {
        $expected = 12
        if ([IntPtr]::Size -eq 8) { $expected = 24 }
        return ((Invoke-PspktHelperStatic -Binding $b -Method 'SecurityAttributesSize' -Arguments @()) -eq $expected)
    }.GetNewClosure()

    $map['job-accounting-abi'] = {
        return ((Invoke-PspktHelperStatic -Binding $b -Method 'AccountingInformationSize' -Arguments @()) -eq 48)
    }.GetNewClosure()

    $map['job-kill-on-close-flag'] = {
        return [bool](Invoke-PspktHelperStatic -Binding $b -Method 'CreatedJobConfiguresKillOnClose' -Arguments @())
    }.GetNewClosure()

    $map['job-event-handles-noninheritable'] = {
        return [bool](Invoke-PspktHelperStatic -Binding $b -Method 'CreatedHandlesNonInheritable' -Arguments @())
    }.GetNewClosure()

    $map['launcher-role-cross-product'] = {
        $pairs = Invoke-PspktHelperStatic -Binding $b -Method 'GetLauncherRoleCrossProduct' -Arguments @()
        if ($pairs.Count -lt 1) { return $false }
        foreach ($pair in $pairs) {
            $direct = Invoke-PspktHelperStatic -Binding $b -Method 'IsLauncherRoleAccepted' -Arguments @($pair.Launcher, $pair.Role)
            if ([bool]$direct -ne [bool]$pair.Accepted) { return $false }
        }
        return $true
    }.GetNewClosure()

    $map['launch-role-environment-matrix'] = {
        $roleType = Get-PspktHelperType -Binding $b -SimpleName 'ProcessLaunchRole'
        foreach ($roleName in [System.Enum]::GetNames($roleType)) {
            $roleValue = [System.Enum]::Parse($roleType, $roleName)
            $authority = @(Invoke-PspktHelperStatic -Binding $b -Method 'GetRoleReservedAuthority' -Arguments @($roleValue))
            $required = @(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($roleValue))
            if ($null -eq $authority -or $null -eq $required) { return $false }
            if ($required.Count -gt $authority.Count) { return $false }
        }
        return $true
    }.GetNewClosure()

    $map['exception-composer'] = {
        $primary = [System.InvalidOperationException]::new('primary')
        $cleanup1 = [System.IO.IOException]::new('cleanup-1')
        $cleanup2 = [System.IO.IOException]::new('cleanup-2')
        $none = Invoke-PspktHelperStatic -Binding $b -Method 'ComposeCleanupException' -Arguments @($null, ([Exception[]]@()))
        if ($null -ne $none) { return $false }
        $onlyCleanup = Invoke-PspktHelperStatic -Binding $b -Method 'ComposeCleanupException' -Arguments @($null, ([Exception[]]@($cleanup1)))
        if ($null -eq $onlyCleanup) { return $false }
        $primaryOnly = Invoke-PspktHelperStatic -Binding $b -Method 'ComposeCleanupException' -Arguments @($primary, ([Exception[]]@()))
        if ($primaryOnly -isnot [System.InvalidOperationException]) { return $false }
        $aggregate = Invoke-PspktHelperStatic -Binding $b -Method 'ComposeCleanupException' -Arguments @($primary, ([Exception[]]@($cleanup1, $cleanup2)))
        if ($aggregate -isnot [System.AggregateException]) { return $false }
        return $true
    }.GetNewClosure()

    $map['drain-clean'] = {
        $r = Invoke-PspktHelperStatic -Binding $b -Method 'RunCleanDrainProbe' -Arguments @(5000)
        return ($r.DrainCompleted -and $r.Stream1Disposals -eq 1 -and $r.Stream2Disposals -eq 1 -and (-not $r.AnyThreadAliveAfter))
    }.GetNewClosure()

    $map['drain-forced'] = {
        $r = Invoke-PspktHelperStatic -Binding $b -Method 'RunForcedCloseDrainProbe' -Arguments @(5000)
        return ((-not $r.DrainCompleted) -and $r.ForcedClose -and $r.Stream1Disposals -eq 1 -and $r.Stream2Disposals -eq 1 -and (-not $r.AnyThreadAliveAfter))
    }.GetNewClosure()

    $map['drain-partial-start'] = {
        $r = Invoke-PspktHelperStatic -Binding $b -Method 'RunPartialStartDrainProbe' -Arguments @(5000)
        return ($r.Stream1Disposals -eq 1 -and $r.Stream2Disposals -eq 1 -and $r.Thread1Started -and (-not $r.Thread2Started) -and (-not $r.AnyThreadAliveAfter) -and (-not [string]::IsNullOrEmpty($r.InjectedStartFailureTypeName)))
    }.GetNewClosure()

    $map['event-open-absent'] = {
        $absent = New-PspktGateEventName -Tag 'Absent'
        $mode = Get-PspktHelperEnum -Binding $b -EnumName 'EventAccessMode' -Member 'WaitOnly'
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Generic'
        $openExceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EventOpenException').FullName
        $before = Get-PspktDiagnosticsSnapshot -Binding $b
        $thrown = Get-PspktThrownException { Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($absent, $mode, $role, [Guid]::Empty) }
        $after = Get-PspktDiagnosticsSnapshot -Binding $b
        $openError = Find-PspktInnerException -Exception $thrown -FullName $openExceptionType
        if ($null -eq $openError) { return $false }
        if ($openError.Win32Error -ne 2) { return $false }
        if (([string]$openError.EventName) -cne $absent) { return $false }
        if (($after.EventCreateCount - $before.EventCreateCount) -ne 0) { return $false }
        if (($after.EventOpenCount - $before.EventOpenCount) -ne 1) { return $false }
        $entries = @(Get-PspktAccessEntriesForName -Snapshot $after -EventName $absent)
        if ($entries.Count -ne 1) { return $false }
        if (([string]$entries[0].Role.ToString()) -cne 'Generic') { return $false }
        if (([uint32]$entries[0].DesiredAccess) -ne ([uint32]1048576)) { return $false }
        $created = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($absent, $role, [Guid]::Empty)
        try { return (-not $created.IsSignaledNow()) } finally { $created.Close() }
    }.GetNewClosure()

    $map['event-duplicate-access-denied'] = {
        $name = New-PspktGateEventName -Tag 'Dup'
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Generic'
        $squatType = (Get-PspktHelperType -Binding $b -SimpleName 'EventSquatException').FullName
        $first = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($name, $role, [Guid]::Empty)
        try {
            $thrown = Get-PspktThrownException { Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($name, $role, [Guid]::Empty) }
            $squat = Find-PspktInnerException -Exception $thrown -FullName $squatType
            if ($null -eq $squat) { return $false }
            if ($squat.Win32Error -ne 5) { return $false }
            if (([string]$squat.EventName) -cne $name) { return $false }
            return $true
        }
        finally { $first.Close() }
    }.GetNewClosure()

    $map['event-duplicate-handle-close'] = {
        $name = New-PspktGateEventName -Tag 'DupHandle'
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Generic'
        $squatType = (Get-PspktHelperType -Binding $b -SimpleName 'EventSquatException').FullName
        $openType = (Get-PspktHelperType -Binding $b -SimpleName 'EventOpenException').FullName
        $owner = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualResetAllAccessForProbe' -Arguments @($name, $role, [Guid]::Empty)
        $squatOk = $false
        try {
            $thrown = Get-PspktThrownException { Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($name, $role, [Guid]::Empty) }
            $squat = Find-PspktInnerException -Exception $thrown -FullName $squatType
            if ($null -ne $squat -and $squat.Win32Error -eq 183 -and (([string]$squat.EventName) -ceq $name)) { $squatOk = $true }
        }
        finally { $owner.Close() }
        if (-not $squatOk) { return $false }
        $mode = Get-PspktHelperEnum -Binding $b -EnumName 'EventAccessMode' -Member 'WaitOnly'
        $reopen = Get-PspktThrownException { Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($name, $mode, $role, [Guid]::Empty) }
        $openError = Find-PspktInnerException -Exception $reopen -FullName $openType
        if ($null -eq $openError) { return $false }
        return ($openError.Win32Error -eq 2)
    }.GetNewClosure()

    $map['event-production-dacl'] = {
        $name = New-PspktGateEventName -Tag 'Prod'
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Generic'
        $created = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($name, $role, [Guid]::Empty)
        try {
            $managed = [System.Threading.EventWaitHandle]::OpenExisting($name)
            try {
                return ($managed.Set() -and $managed.WaitOne(0))
            }
            finally {
                $managed.Close()
            }
        }
        catch { return $false }
        finally { $created.Close() }
    }.GetNewClosure()

    $map['event-restricted-dacl'] = {
        $name = New-PspktGateEventName -Tag 'Restrict'
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Generic'
        $kind = Get-PspktHelperEnum -Binding $b -EnumName 'ProbeEventDaclKind' -Member 'SynchronizeOnly'
        $openType = (Get-PspktHelperType -Binding $b -SimpleName 'EventOpenException').FullName
        $created = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualResetForProbe' -Arguments @($name, $kind, $role, [Guid]::Empty)
        try {
            $waitMode = Get-PspktHelperEnum -Binding $b -EnumName 'EventAccessMode' -Member 'WaitOnly'
            $opened = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($name, $waitMode, $role, [Guid]::Empty)
            $opened.Close()
            $setMode = Get-PspktHelperEnum -Binding $b -EnumName 'EventAccessMode' -Member 'SetOnly'
            $thrown = Get-PspktThrownException { Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($name, $setMode, $role, [Guid]::Empty) }
            $openError = Find-PspktInnerException -Exception $thrown -FullName $openType
            if ($null -eq $openError) { return $false }
            if ($openError.Win32Error -ne 5) { return $false }
            if (([string]$openError.EventName) -cne $name) { return $false }
            $after = Get-PspktDiagnosticsSnapshot -Binding $b
            $entries = @(Get-PspktAccessEntriesForName -Snapshot $after -EventName $name)
            if ($entries.Count -ne 3) { return $false }
            foreach ($entry in $entries) {
                if (([string]$entry.Role.ToString()) -cne 'Generic') { return $false }
            }
            if (([uint32]$entries[0].DesiredAccess) -ne ([uint32]1048576)) { return $false }
            if (([uint32]$entries[1].DesiredAccess) -ne ([uint32]1048576)) { return $false }
            if (([uint32]$entries[2].DesiredAccess) -ne ([uint32]2)) { return $false }
            if (-not ($entries[0].Sequence -lt $entries[1].Sequence -and $entries[1].Sequence -lt $entries[2].Sequence)) { return $false }
            return $true
        }
        finally { $created.Close() }
    }.GetNewClosure()

    $map['watchdog-complete-once'] = {
        $wd = New-PspktHelperObject -Binding $b -SimpleName 'SchemaChildWatchdog' -Arguments @(60000)
        $first = $wd.Complete()
        $second = $wd.Complete()
        $quiesced = $wd.DisposeBounded(3000)
        return ($first -and (-not $second) -and $quiesced)
    }.GetNewClosure()

    $map['combined-seam-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $correlation = [Guid]::NewGuid()
            $evidenceDirectory = New-PspktTempDirectory -Prefix 'pspkt-phase4-ev-'
            [void]$tempDirectories.Add($evidenceDirectory)
            $identityDirectory = New-PspktTempDirectory -Prefix 'pspkt-phase4-id-'
            [void]$tempDirectories.Add($identityDirectory)
            $pause = New-PspktHelperObject -Binding $b -SimpleName 'PauseConfiguration' -Arguments @(
                $correlation, $identityDirectory,
                (New-PspktGateEventName -Tag 'Rdy'), (New-PspktGateEventName -Tag 'Ack'),
                (New-PspktGateEventName -Tag 'Armed'), (New-PspktGateEventName -Tag 'Rel'),
                10000, 10000
            )
            $evidence = New-PspktHelperObject -Binding $b -SimpleName 'ProbeEvidence' -Arguments @($evidenceDirectory, $correlation)
            $configuration = New-PspktRejectConfig -Binding $b -Role 'PauseReleaseChild' -TempDirectories $tempDirectories -SimulateAssignFailure $true -PauseConfiguration $pause -ProbeEvidence $evidence -CorrelationId $correlation
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunCombinedSeamRejectProbe' -Arguments @($configuration)
            $directoriesEmpty = ([System.IO.DirectoryInfo]::new($evidenceDirectory).GetFileSystemInfos().Length -eq 0) -and
                ([System.IO.DirectoryInfo]::new($identityDirectory).GetFileSystemInfos().Length -eq 0)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'InvalidPreAssignmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'CombinedSeam'
            return ($directoriesEmpty -and (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason))
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['reject-basic'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -RetainCapBytes 0
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunBasicRejectProbe' -Arguments @($configuration)
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Basic'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName ([System.ArgumentOutOfRangeException].FullName) -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['reject-event-name'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -GateName 'Global\PspktPhase4Bad'
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEventNameRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EventNameGrammarException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'EventName'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['empty-correlation-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -CorrelationId ([Guid]::Empty)
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEmptyCorrelationRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'CorrelationIdRequiredException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'EmptyCorrelation'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['invalid-pause-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $correlation = [Guid]::NewGuid()
            $evidenceDirectory = New-PspktTempDirectory -Prefix 'pspkt-phase4-ev2-'
            [void]$tempDirectories.Add($evidenceDirectory)
            $identityDirectory = New-PspktTempDirectory -Prefix 'pspkt-phase4-id2-'
            [void]$tempDirectories.Add($identityDirectory)
            $pause = New-PspktHelperObject -Binding $b -SimpleName 'PauseConfiguration' -Arguments @(
                $correlation, $identityDirectory,
                (New-PspktGateEventName -Tag 'Rdy'), (New-PspktGateEventName -Tag 'Ack'),
                (New-PspktGateEventName -Tag 'Armed'), (New-PspktGateEventName -Tag 'Rel'),
                10000, 0
            )
            $evidence = New-PspktHelperObject -Binding $b -SimpleName 'ProbeEvidence' -Arguments @($evidenceDirectory, $correlation)
            $configuration = New-PspktRejectConfig -Binding $b -Role 'PauseReleaseChild' -TempDirectories $tempDirectories -PauseConfiguration $pause -ProbeEvidence $evidence -CorrelationId $correlation
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunInvalidPauseRejectProbe' -Arguments @($configuration)
            $directoriesEmpty = ([System.IO.DirectoryInfo]::new($evidenceDirectory).GetFileSystemInfos().Length -eq 0) -and
                ([System.IO.DirectoryInfo]::new($identityDirectory).GetFileSystemInfos().Length -eq 0)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'InvalidPauseConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'PauseConfig'
            return ($directoriesEmpty -and (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason))
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['validation-precedence-overlap'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -GateName 'Global\PspktPhase4Bad' -CorrelationId ([Guid]::Empty)
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEventNameRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EventNameGrammarException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'EventName'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-gate-collision-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
            $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
            $reservedValues = Get-PspktRejectReservedValues -Names $reservedNames
            $reservedNames[0] = Invoke-PspktHelperStatic -Binding $b -Method 'GetRoleGateVariable' -Arguments @($role)
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -ReservedNames $reservedNames -ReservedValues $reservedValues
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEnvironmentRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EnvironmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-duplicate-extra-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EnvironmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
            $before = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $observedExceptionTypeName = ''
            try {
                [void](Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @(
                    $configuration.ExecutablePath,
                    ([string[]]$configuration.Arguments),
                    $configuration.GateEventName,
                    'PSPKT_PHASE4_GATE_EVENT',
                    ([string[]]@('PSPKT_REJECT_EXTRA', 'pspkt_reject_extra')),
                    ([string[]]@('a', 'b')),
                    60000, 15000, 15000, 65536, $false
                ))
                return $false
            }
            catch {
                $observed = $_.Exception
                while ($null -ne $observed.InnerException) {
                    $observed = $observed.InnerException
                }
                $observedExceptionTypeName = $observed.GetType().FullName
            }
            finally {
                $stopwatch.Stop()
            }
            $result = [pscustomobject]@{
                ObservedExceptionTypeName = $observedExceptionTypeName
                ExpectedReason = $reason
                ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
                Before = $before
                After = (Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @())
            }
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-name-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
            $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
            $reservedValues = Get-PspktRejectReservedValues -Names $reservedNames
            $reservedNames[0] = 'bad name'
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -ReservedNames $reservedNames -ReservedValues $reservedValues
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEnvironmentRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EnvironmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-value-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
            $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
            $reservedValues = Get-PspktRejectReservedValues -Names $reservedNames
            $reservedValues[0] = "valid`0invalid"
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -ReservedNames $reservedNames -ReservedValues $reservedValues
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEnvironmentRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EnvironmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-value-limit-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
            $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
            $reservedValues = Get-PspktRejectReservedValues -Names $reservedNames
            $reservedValues[0] = 'x' * 32768
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -ReservedNames $reservedNames -ReservedValues $reservedValues
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEnvironmentRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EnvironmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-block-limit-rejection'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        try {
            $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
            $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
            $reservedValues = Get-PspktRejectReservedValues -Names $reservedNames
            for ($index = 0; $index -lt $reservedValues.Count; $index++) {
                $reservedValues[$index] = 'x' * 9000
            }
            $configuration = New-PspktRejectConfig -Binding $b -Role 'GateProbeChild' -TempDirectories $tempDirectories -ReservedNames $reservedNames -ReservedValues $reservedValues
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunEnvironmentRejectProbe' -Arguments @($configuration)
            $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'EnvironmentConfigurationException').FullName
            $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
            return (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-ambient-scrub'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
        $authority = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRoleReservedAuthority' -Arguments @($role))
        $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
        $reservedValues = [string[]]@(Get-PspktRejectReservedValues -Names $reservedNames)
        $hostExe = Get-PspktHostExecutable
        $workingDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-ambient-'
        [void]$tempDirectories.Add($workingDir)
        $scriptPath = Join-Path $workingDir 'gate-first.ps1'
        $configuration = New-PspktGateProbeChildConfiguration -Binding $b -ExecutablePath $hostExe -Arguments ([string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath)) -ReservedNames $reservedNames -ReservedValues $reservedValues -GateEventName (New-PspktGateEventName -Tag 'Ambient') -CorrelationId ([Guid]::NewGuid()) -WorkingDirectory $workingDir
        $hostileNames = [string[]]@('PsPkT_PhAsE4_StAlE_MARKER', 'DOTNET_hostile_probe', 'CORECLR_PROFILER', 'COR_ENABLE_PROFILING', 'COMPLUS_hostile_probe', 'APPDOMAIN_MANAGER_ASSEMBLY', 'DEVPATH', 'PSModulePath')
        $hostileValues = [string[]]@('stale-reserved-value', 'hostile.dll', '{01234567-89ab-cdef-0123-456789abcdef}', '1', 'hostile.dll', 'hostile.dll', 'C:\pspkt-hostile-devpath', 'C:\pspkt-hostile-modules;C:\pspkt-hostile-modules2')
        $hostileModulePath = 'C:\pspkt-hostile-modules;C:\pspkt-hostile-modules2'
        $originalValues = @{}
        foreach ($name in $hostileNames) { $originalValues[$name] = [Environment]::GetEnvironmentVariable($name) }
        try {
            for ($index = 0; $index -lt $hostileNames.Length; $index++) {
                [Environment]::SetEnvironmentVariable($hostileNames[$index], $hostileValues[$index])
            }
            $before = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            $snapshot = Invoke-PspktHelperStatic -Binding $b -Method 'BuildFrozenEnvironmentSnapshot' -Arguments @($configuration)
            $after = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            if (-not (Test-PspktDiagnosticsUnchanged -Before $before -After $after)) { return $false }
            foreach ($name in @('PsPkT_PhAsE4_StAlE_MARKER', 'DOTNET_hostile_probe', 'CORECLR_PROFILER', 'COR_ENABLE_PROFILING', 'COMPLUS_hostile_probe', 'APPDOMAIN_MANAGER_ASSEMBLY', 'DEVPATH')) {
                if ([bool]$snapshot.Contains($name)) { return $false }
            }
            $hostDirectory = [System.IO.Path]::GetDirectoryName($hostExe)
            $canonicalModulePath = [System.IO.Path]::Combine($hostDirectory, 'Modules')
            $modulePathValue = $snapshot.GetValue('PSModulePath')
            if ($null -eq $modulePathValue) { return $false }
            if ($modulePathValue -ceq $hostileModulePath) { return $false }
            if ($modulePathValue -cne $canonicalModulePath) { return $false }
            $snapshotReserved = @()
            foreach ($name in $snapshot.GetNames()) {
                if ($name.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase)) { $snapshotReserved += $name }
            }
            if ($snapshotReserved.Count -ne $authority.Length) { return $false }
            foreach ($name in $snapshotReserved) {
                $authorized = $false
                foreach ($authorizedName in $authority) {
                    if ($name -ceq $authorizedName) { $authorized = $true; break }
                }
                if (-not $authorized) { return $false }
            }
            foreach ($authorizedName in $authority) {
                if (-not [bool]$snapshot.Contains($authorizedName)) { return $false }
            }
            return $true
        }
        finally {
            foreach ($name in $hostileNames) { [Environment]::SetEnvironmentVariable($name, $originalValues[$name]) }
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['environment-snapshot-isolation'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
        $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
        $reservedValues = [string[]]@(Get-PspktRejectReservedValues -Names $reservedNames)
        $originalNames = [string[]]::new($reservedNames.Length)
        [System.Array]::Copy($reservedNames, $originalNames, $reservedNames.Length)
        $originalValues = [string[]]::new($reservedValues.Length)
        [System.Array]::Copy($reservedValues, $originalValues, $reservedValues.Length)
        $hostExe = Get-PspktHostExecutable
        $workingDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-isolation-'
        [void]$tempDirectories.Add($workingDir)
        $scriptPath = Join-Path $workingDir 'gate-first.ps1'
        $arguments = [string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath)
        try {
            $configuration = New-PspktGateProbeChildConfiguration -Binding $b -ExecutablePath $hostExe -Arguments $arguments -ReservedNames $reservedNames -ReservedValues $reservedValues -GateEventName (New-PspktGateEventName -Tag 'Isolation') -CorrelationId ([Guid]::NewGuid()) -WorkingDirectory $workingDir
            $before = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            $snapshotBefore = Invoke-PspktHelperStatic -Binding $b -Method 'BuildFrozenEnvironmentSnapshot' -Arguments @($configuration)
            $reservedNames[0] = 'PSPKT_PHASE4_HIJACK'
            $reservedValues[0] = 'mutated-reserved-value'
            $arguments[4] = 'hijacked-script.ps1'
            $snapshotAfter = Invoke-PspktHelperStatic -Binding $b -Method 'BuildFrozenEnvironmentSnapshot' -Arguments @($configuration)
            $after = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            if (-not (Test-PspktDiagnosticsUnchanged -Before $before -After $after)) { return $false }
            $configNames = [string[]]$configuration.ReservedEnvironmentNames
            $configValues = [string[]]$configuration.ReservedEnvironmentValues
            if ($configNames.Length -ne $originalNames.Length) { return $false }
            for ($index = 0; $index -lt $originalNames.Length; $index++) {
                if ($configNames[$index] -cne $originalNames[$index]) { return $false }
                if ($configValues[$index] -cne $originalValues[$index]) { return $false }
            }
            $configArguments = [string[]]$configuration.Arguments
            if ($configArguments[4] -cne $scriptPath) { return $false }
            if ([bool]$snapshotAfter.Contains('PSPKT_PHASE4_HIJACK')) { return $false }
            for ($index = 0; $index -lt $originalNames.Length; $index++) {
                if ($snapshotAfter.GetValue($originalNames[$index]) -cne $originalValues[$index]) { return $false }
            }
            $namesBefore = [string[]]$snapshotBefore.GetNames()
            $valuesBefore = [string[]]$snapshotBefore.GetValues()
            $namesAfter = [string[]]$snapshotAfter.GetNames()
            $valuesAfter = [string[]]$snapshotAfter.GetValues()
            if ($namesBefore.Length -ne $namesAfter.Length) { return $false }
            for ($index = 0; $index -lt $namesAfter.Length; $index++) {
                if ($namesAfter[$index] -cne $namesBefore[$index]) { return $false }
                if ($valuesAfter[$index] -cne $valuesBefore[$index]) { return $false }
            }
            $expectedBlock = 1
            for ($index = 0; $index -lt $namesAfter.Length; $index++) {
                $expectedBlock += $namesAfter[$index].Length + 1 + $valuesAfter[$index].Length + 1
            }
            if ($snapshotAfter.BlockLength -ne $expectedBlock) { return $false }
            if ($snapshotAfter.BlockLength -gt 32767) { return $false }
            return $true
        }
        finally {
            Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
        }
    }.GetNewClosure()

    $map['prelaunch-host-argv'] = {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        $snapshotProbeSession = $null
        $snapshotProbeMembers = $null
        $role = Get-PspktHelperEnum -Binding $b -EnumName 'ProcessLaunchRole' -Member 'GateProbeChild'
        $reservedNames = [string[]]@(Invoke-PspktHelperStatic -Binding $b -Method 'GetRequiredReservedNames' -Arguments @($role))
        $reservedValues = [string[]]@(Get-PspktRejectReservedValues -Names $reservedNames)
        $hostExe = Get-PspktHostExecutable
        $exceptionType = (Get-PspktHelperType -Binding $b -SimpleName 'ProcessLaunchConfigurationException').FullName
        $reason = Get-PspktHelperEnum -Binding $b -EnumName 'PreNativeRejectReason' -Member 'Environment'
        $workingDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-argv-'
        [void]$tempDirectories.Add($workingDir)
        $scriptPath = Join-Path $workingDir 'gate-first.ps1'
        $nonPowerShellExe = $env:ComSpec
        if ([string]::IsNullOrEmpty($nonPowerShellExe)) { $nonPowerShellExe = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe') }
        try {
            $variants = [System.Collections.Generic.List[object]]::new()
            [void]$variants.Add([string[]]@('-NoProfile', '-NoLogo', '-NonInteractive', '-File', $scriptPath))
            [void]$variants.Add([string[]]@('-nologo', '-NoProfile', '-NonInteractive', '-File', $scriptPath))
            [void]$variants.Add([string[]]@('-NoProfile', '-NonInteractive', '-File', $scriptPath))
            [void]$variants.Add([string[]]@('-NoLogo', '-NoProfile', '-File', $scriptPath, '-NonInteractive'))
            [void]$variants.Add([string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', ''))
            foreach ($variant in $variants) {
                $configuration = New-PspktGateProbeChildConfiguration -Binding $b -ExecutablePath $hostExe -Arguments ([string[]]$variant) -ReservedNames $reservedNames -ReservedValues $reservedValues -GateEventName (New-PspktGateEventName -Tag 'Argv') -CorrelationId ([Guid]::NewGuid()) -WorkingDirectory $workingDir
                $result = Invoke-PspktTypedRunReject -Binding $b -Configuration $configuration -ExpectedReason $reason
                if (-not (Test-PspktRejectProbe -Result $result -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)) { return $false }
            }
            $nonPowerShellConfiguration = New-PspktGateProbeChildConfiguration -Binding $b -ExecutablePath $nonPowerShellExe -Arguments ([string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath)) -ReservedNames $reservedNames -ReservedValues $reservedValues -GateEventName (New-PspktGateEventName -Tag 'ArgvHost') -CorrelationId ([Guid]::NewGuid()) -WorkingDirectory $workingDir
            $nonPowerShellResult = Invoke-PspktTypedRunReject -Binding $b -Configuration $nonPowerShellConfiguration -ExpectedReason $reason
            if (-not (Test-PspktRejectProbe -Result $nonPowerShellResult -ExpectedExceptionTypeName $exceptionType -ExpectedReason $reason)) { return $false }
            $validConfiguration = New-PspktGateProbeChildConfiguration -Binding $b -ExecutablePath $hostExe -Arguments ([string[]]@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath)) -ReservedNames $reservedNames -ReservedValues $reservedValues -GateEventName (New-PspktGateEventName -Tag 'ArgvOk') -CorrelationId ([Guid]::NewGuid()) -WorkingDirectory $workingDir
            $before = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            $snapshot = Invoke-PspktHelperStatic -Binding $b -Method 'BuildFrozenEnvironmentSnapshot' -Arguments @($validConfiguration)
            $after = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            if (-not (Test-PspktDiagnosticsUnchanged -Before $before -After $after)) { return $false }
            if ($snapshot.Count -lt 1) { return $false }
            if (-not [bool]$snapshot.PSModulePathCanonicalized) { return $false }

            [uint32]$creationFlags = Invoke-PspktHelperStatic -Binding $b -Method 'GetContainedNativeCreationFlags' -Arguments @()
            [uint32]$expectedCreationFlags = 0x00000404
            if ($creationFlags -ne $expectedCreationFlags) { return $false }
            foreach ($forbiddenFlag in [uint32[]]@(0x08000000, 0x00000200, 0x00000008, 0x00000010)) {
                if (($creationFlags -band $forbiddenFlag) -ne 0) { return $false }
            }

            $snapshotProbeWorkingDirectory = New-PspktTempDirectory -Prefix 'pspkt-phase4-host-'
            [void]$tempDirectories.Add($snapshotProbeWorkingDirectory)
            $snapshotProbeGateName = New-PspktGateEventName -Tag 'Host'
            $snapshotProbeSession = Invoke-PspktHelperStatic -Binding $b -Method 'StartCertificationSnapshotProbe' -Arguments @(
                $hostExe, $snapshotProbeWorkingDirectory, $snapshotProbeGateName, [int]30000)
            $snapshotProbeMembers = Get-PspktStableJobSnapshot -Session $snapshotProbeSession -MinIntervalMs 50 -TimeoutMs 10000
            if ($null -eq $snapshotProbeMembers -or
                -not (Test-PspktRootTopology -Members $snapshotProbeMembers.Members -RootPid $snapshotProbeSession.RootProcessId -RootStart $snapshotProbeSession.RootStartTimeFileTimeUtc -RootImage $snapshotProbeSession.RootImagePath)) {
                return $false
            }
            $snapshotProbeAccounting = $snapshotProbeSession.QueryJobAccounting()
            if ([long]$snapshotProbeAccounting.TotalProcesses -ne [long]$snapshotProbeMembers.Members.Count -or
                [long]$snapshotProbeAccounting.ActiveProcesses -ne [long]$snapshotProbeMembers.Members.Count -or
                [long]$snapshotProbeAccounting.TotalTerminatedProcesses -ne 0) {
                return $false
            }

            $rootImageLeaf = [System.IO.Path]::GetFileName([string]$snapshotProbeSession.RootImagePath)
            $packagingKind = [string]$snapshotProbeSession.PackagingKind
            $packageFullName = [string]$snapshotProbeSession.PackageFullName
            $packageRootPath = [string]$snapshotProbeSession.PackageRootPath
            if ($PSVersionTable.PSEdition -ceq 'Core') {
                if ($PSVersionTable.PSVersion.Major -lt 7 -or
                    $rootImageLeaf -ine 'pwsh.exe' -or
                    $packagingKind -cne 'Packaged' -or
                    -not [bool]$snapshotProbeSession.HasPackagingIdentity -or
                    [string]::IsNullOrEmpty($packageFullName) -or
                    [string]::IsNullOrEmpty($packageRootPath)) {
                    return $false
                }
                $packagePrefix = $packageRootPath.TrimEnd(
                    [System.IO.Path]::DirectorySeparatorChar,
                    [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
                if (-not ([string]$snapshotProbeSession.RootImagePath).StartsWith(
                        $packagePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $false
                }
            }
            elseif ($PSVersionTable.PSEdition -ceq 'Desktop') {
                if ($PSVersionTable.PSVersion.Major -ne 5 -or
                    $PSVersionTable.PSVersion.Minor -ne 1 -or
                    $rootImageLeaf -ine 'powershell.exe' -or
                    $packagingKind -cne 'Unpackaged' -or
                    [bool]$snapshotProbeSession.HasPackagingIdentity -or
                    -not [string]::IsNullOrEmpty($packageFullName) -or
                    -not [string]::IsNullOrEmpty($packageRootPath)) {
                    return $false
                }
            }
            else {
                return $false
            }

            $snapshotProbeSession.SignalWorkerGate()
            $snapshotProbeWait = $snapshotProbeSession.WaitWorker(30000)
            if (-not (Test-PspktHelperEnumEquals -Value $snapshotProbeWait -Member 'Object0') -or
                $snapshotProbeSession.GetExitCode() -ne 0 -or
                $snapshotProbeSession.QueryActiveProcesses() -ne 0) {
                return $false
            }
            return $snapshotProbeMembers.MatchRetainedIdentityAllowExited()
        }
        finally {
            $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
            $ownershipClean = $true
            if ($null -ne $snapshotProbeMembers) {
                try {
                    if (-not (Close-PspktJobSnapshot -Snapshot $snapshotProbeMembers)) {
                        $ownershipClean = $false
                        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('prelaunch host snapshot cleanup did not report DisposeSucceeded.'))
                    }
                }
                catch {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
            }
            if ($null -ne $snapshotProbeSession) {
                try {
                    $snapshotProbeSession.Dispose()
                }
                catch {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
                $snapshotProbeDisposeErrors = @()
                try {
                    $snapshotProbeDisposeErrors = @($snapshotProbeSession.GetDisposeErrors())
                }
                catch {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
                foreach ($snapshotProbeDisposeError in $snapshotProbeDisposeErrors) {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add($snapshotProbeDisposeError)
                }
                $snapshotProbeDisposeSucceeded = $false
                $snapshotProbeState = ''
                try {
                    $snapshotProbeDisposeSucceeded = [bool]$snapshotProbeSession.DisposeSucceeded
                    $snapshotProbeState = [string]$snapshotProbeSession.State.ToString()
                }
                catch {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
                if (-not $snapshotProbeDisposeSucceeded -or $snapshotProbeState -cne 'Cleaned') {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                            ('prelaunch host contained session cleanup proof failed: DisposeSucceeded={0}; State={1}.' -f $snapshotProbeDisposeSucceeded, $snapshotProbeState)))
                }
            }
            if ($ownershipClean) {
                try {
                    Remove-PspktRejectTempDirectories -TempDirectories $tempDirectories
                }
                catch {
                    [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
            }
            else {
                [void]$cleanupFailures.Add([System.InvalidOperationException]::new('prelaunch host temporary-directory cleanup was withheld because snapshot or session ownership was not clean.'))
            }
            if ($cleanupFailures.Count -ne 0) {
                throw [System.AggregateException]::new('prelaunch host cleanup failed.', [Exception[]]$cleanupFailures.ToArray())
            }
        }
    }.GetNewClosure()

    $map['gate-success'] = {
        $context = New-PspktProcessOracleContext -Tag 'gate-success'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'gate-success.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-gate-success-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -UseGateTimeoutEnvironment -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'GateSuccess'
            $reservedValues = @{
                'PSPKT_PHASE4_GATE_TIMEOUT_MS' = '5000'
                'PSPKT_PHASE4_PROBE_MODE' = 'gate-success'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
                'PSPKT_PHASE4_PROBE_MARKER_PATH' = $markerPath
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'GateProbeChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            $expectedMarker = 'pspkt-phase4-gate-success-v1' + [char]0x09 + $nonce + [char]0x0A
            return ($result.Started -and $result.Exited -and $result.ExitCode -eq 0 -and
                (-not $result.AssignFailed) -and (-not $result.TimedOut) -and
                $result.ActiveProcessesAfterTerminate -eq 0 -and
                (Test-PspktExactAsciiFile -Path $markerPath -Expected $expectedMarker))
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['gate-missing-environment'] = {
        $context = New-PspktProcessOracleContext -Tag 'gate-missing'
        $session = $null
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'gate-missing.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-gate-missing-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Missing -PostGateLines $postGateLines
            $reservedValues = @{
                'PSPKT_PHASE4_PROBE_MODE' = 'gate-missing-environment'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'GateMissingChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $null
            $session = Invoke-PspktHelperStatic -Binding $b -Method 'RunDirectLaunch' -Arguments @($configuration)
            if (-not $session.WaitForExit(10000)) {
                throw 'gate-missing-environment: child did not reach its pinned terminal exit.'
            }
            return ($session.GetExitCode() -eq 10 -and (-not (Test-Path -LiteralPath $markerPath)))
        }
        finally {
            if ($null -ne $session) {
                Close-PspktDirectLaunchSession -Session $session
            }
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['gate-wrong-name'] = {
        $context = New-PspktProcessOracleContext -Tag 'gate-wrong-name'
        $session = $null
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'gate-wrong-name.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-gate-wrong-name-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 1000 -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'WrongName'
            $reservedValues = @{
                'PSPKT_PHASE4_PROBE_MODE' = 'gate-wrong-name'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'GateWrongNameChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $session = Invoke-PspktHelperStatic -Binding $b -Method 'RunDirectLaunch' -Arguments @($configuration)
            if (-not $session.WaitForExit(10000)) {
                throw 'gate-wrong-name: child did not reach its pinned terminal exit.'
            }
            return ($session.GetExitCode() -eq 10 -and (-not (Test-Path -LiteralPath $markerPath)))
        }
        finally {
            if ($null -ne $session) {
                Close-PspktDirectLaunchSession -Session $session
            }
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['gate-timeout'] = {
        $context = New-PspktProcessOracleContext -Tag 'gate-timeout'
        $session = $null
        $gate = $null
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'gate-timeout.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-gate-timeout-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -UseGateTimeoutEnvironment -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'GateTimeout'
            $gateRole = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Gate'
            $gate = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($gateName, $gateRole, [Guid]::Empty)
            if ($gate.IsSignaledNow()) { return $false }
            $reservedValues = @{
                'PSPKT_PHASE4_GATE_TIMEOUT_MS' = '500'
                'PSPKT_PHASE4_PROBE_MODE' = 'gate-timeout'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'GateTimeoutChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $session = Invoke-PspktHelperStatic -Binding $b -Method 'RunDirectLaunch' -Arguments @($configuration)
            if (-not $session.WaitForExit(10000)) {
                throw 'gate-timeout: child did not reach its pinned terminal exit.'
            }
            return ($session.GetExitCode() -eq 11 -and (-not $gate.IsSignaledNow()) -and
                (-not (Test-Path -LiteralPath $markerPath)))
        }
        finally {
            if ($null -ne $session) {
                Close-PspktDirectLaunchSession -Session $session
            }
            if ($null -ne $gate) {
                $gate.Close()
            }
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['gate-delayed-signal'] = {
        $context = New-PspktProcessOracleContext -Tag 'gate-delayed'
        $session = $null
        $gate = $null
        $threadState = $null
        $threadStarted = $false
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'gate-delayed.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-gate-delayed-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -UseGateTimeoutEnvironment -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'GateDelayed'
            $gateRole = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Gate'
            $gate = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($gateName, $gateRole, [Guid]::Empty)
            $reservedValues = @{
                'PSPKT_PHASE4_GATE_TIMEOUT_MS' = '5000'
                'PSPKT_PHASE4_PROBE_MODE' = 'gate-delayed-signal'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'GateDelayedSignalChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $session = Invoke-PspktHelperStatic -Binding $b -Method 'RunDirectLaunch' -Arguments @($configuration)
            $threadState = New-PspktDelayedEventSignalThread -NamedEvent $gate -DelayMilliseconds 500
            $threadState.Thread.Start()
            $threadStarted = $true
            if (-not $session.WaitForExit(10000)) {
                throw 'gate-delayed-signal: child did not reach its terminal exit.'
            }
            if (-not $threadState.Thread.Join(10000)) {
                throw 'gate-delayed-signal: delayed signal thread did not quiesce within 10 seconds.'
            }
            $threadStarted = $false
            if ($null -ne $threadState.State[1]) {
                throw $threadState.State[1]
            }
            $expectedMarker = 'pspkt-phase4-gate-delayed-v1' + [char]0x09 + $nonce + [char]0x0A
            return ($session.GetExitCode() -eq 0 -and $gate.IsSignaledNow() -and
                (Test-PspktExactAsciiFile -Path $markerPath -Expected $expectedMarker))
        }
        finally {
            if ($threadStarted) {
                if (-not $threadState.Thread.Join(10000)) {
                    throw 'gate-delayed-signal cleanup: delayed signal thread did not quiesce within 10 seconds.'
                }
                if ($null -ne $threadState.State[1]) {
                    throw $threadState.State[1]
                }
            }
            if ($null -ne $session) {
                Close-PspktDirectLaunchSession -Session $session
            }
            if ($null -ne $gate) {
                $gate.Close()
            }
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['gate-name-squat'] = {
        $context = New-PspktProcessOracleContext -Tag 'gate-squat'
        $owner = $null
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'gate-squat.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-gate-squat-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -UseGateTimeoutEnvironment -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'GateSquat'
            $gateRole = Get-PspktHelperEnum -Binding $b -EnumName 'EventRole' -Member 'Gate'
            $owner = Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'CreateNewManualResetAllAccessForProbe' -Arguments @($gateName, $gateRole, [Guid]::Empty)
            $reservedValues = @{
                'PSPKT_PHASE4_GATE_TIMEOUT_MS' = '5000'
                'PSPKT_PHASE4_PROBE_MODE' = 'gate-name-squat'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
                'PSPKT_PHASE4_PROBE_MARKER_PATH' = $markerPath
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'GateProbeChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $before = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            $exceptionTypeName = (Get-PspktHelperType -Binding $b -SimpleName 'EventSquatException').FullName
            $exactException = Test-PspktExpectedHelperException -ExpectedTypeName $exceptionTypeName -Action {
                Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            }
            $after = Invoke-PspktHelperStatic -Binding $b -Method 'GetDiagnosticsSnapshot' -Arguments @()
            $noLaunchDelta = ($after.ProcessStartCount -eq $before.ProcessStartCount -and
                $after.AssignmentAttemptCount -eq $before.AssignmentAttemptCount)
            $owner.Close()
            $owner = $null
            $waitMode = Get-PspktHelperEnum -Binding $b -EnumName 'EventAccessMode' -Member 'WaitOnly'
            $eventOpenExceptionName = (Get-PspktHelperType -Binding $b -SimpleName 'EventOpenException').FullName
            $absentAfter = Test-PspktExpectedHelperException -ExpectedTypeName $eventOpenExceptionName -Action {
                Invoke-PspktHelperTypeStatic -Binding $b -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($gateName, $waitMode, $gateRole, [Guid]::Empty)
            }
            return ($exactException -and $noLaunchDelta -and $absentAfter -and
                (-not (Test-Path -LiteralPath $markerPath)))
        }
        finally {
            if ($null -ne $owner) {
                $owner.Close()
            }
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['assignment-failure'] = {
        $context = New-PspktProcessOracleContext -Tag 'assignment-failure'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'assignment-failure.marker'
            $postGateLines = @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-assignment-failure-v1') + @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 60000 -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'AssignFailure'
            $reservedValues = @{
                'PSPKT_PHASE4_PROBE_MODE' = 'assignment-failure'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
                'PSPKT_PHASE4_PROBE_MARKER_PATH' = $markerPath
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'AssignmentFailureChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName -SimulateAssignFailure $true
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            return ($result.Started -and $result.AssignFailed -and $result.Exited -and
                (-not $result.TimedOut) -and (-not (Test-Path -LiteralPath $markerPath)))
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['watchdog-timeout'] = {
        $context = New-PspktProcessOracleContext -Tag 'watchdog'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $postGateLines = @(Get-PspktVerifiedHelperLoadLines) + @(
                '$watchdogTimeoutText = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS'')',
                '$watchdogTimeoutMilliseconds = 0',
                'if (-not [int]::TryParse($watchdogTimeoutText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$watchdogTimeoutMilliseconds) -or $watchdogTimeoutMilliseconds -lt 1) { exit 5 }',
                '$watchdogType = $helperAssembly.GetType(''Pspkt.Certification.SchemaChildWatchdog'', $true)',
                '$watchdog = [System.Activator]::CreateInstance($watchdogType, @([int]$watchdogTimeoutMilliseconds))',
                '[System.Threading.Thread]::Sleep(30000)',
                'exit 20'
            )
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 60000 -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'Watchdog'
            $reservedValues = @{
                'PSPKT_PHASE4_HELPER_PATH' = $b.Path
                'PSPKT_PHASE4_HELPER_SHA256' = $b.Digest
                'PSPKT_PHASE4_HELPER_VERSION' = $b.Version
                'PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS' = '400'
                'PSPKT_PHASE4_PROBE_MODE' = 'watchdog-timeout'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'WatchdogChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName -WaitTimeoutMilliseconds 10000
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            return ($result.Started -and $result.Exited -and $result.ExitCode -eq 6 -and
                (-not $result.AssignFailed) -and (-not $result.TimedOut) -and
                $result.ActiveProcessesAfterTerminate -eq 0)
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['descendant-timeout'] = {
        $context = New-PspktProcessOracleContext -Tag 'descendant'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $pidPath = Join-Path $context.Root 'descendant.pid'
            $descendantScriptPath = Join-Path $context.Root ('descendant-' + [Guid]::NewGuid().ToString('N') + '.ps1')
            $descendantBytes = (New-PspktUtf8NoBom).GetBytes("[System.Threading.Thread]::Sleep(60000)`r`nexit 0`r`n")
            $descendantStream = [System.IO.FileStream]::new($descendantScriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $descendantStream.Write($descendantBytes, 0, $descendantBytes.Length)
                $descendantStream.Flush($true)
            }
            finally {
                $descendantStream.Dispose()
            }
            $descendantScriptLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $descendantScriptPath
            $workingDirectoryLiteral = ConvertTo-PspktSingleQuotedLiteral -Value $context.WorkingDirectory
            $postGateLines = [string[]]@(
                ('$descendantScriptPath = {0}' -f $descendantScriptLiteral),
                ('$descendantWorkingDirectory = {0}' -f $workingDirectoryLiteral),
                '$descendantHost = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName',
                '$descendantStartInfo = [System.Diagnostics.ProcessStartInfo]::new()',
                '$descendantStartInfo.FileName = $descendantHost',
                '$descendantStartInfo.Arguments = ''-NoLogo -NoProfile -NonInteractive -File "'' + $descendantScriptPath + ''"''',
                '$descendantStartInfo.UseShellExecute = $false',
                '$descendantStartInfo.CreateNoWindow = $true',
                '$descendantStartInfo.WorkingDirectory = $descendantWorkingDirectory',
                '$descendant = [System.Diagnostics.Process]::new()',
                '$descendant.StartInfo = $descendantStartInfo',
                'if (-not $descendant.Start()) { exit 20 }',
                '$descendantPid = $descendant.Id',
                '$descendant.Dispose()',
                '$pidPath = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_PROBE_PID_PATH'')',
                '$probeNonce = [Environment]::GetEnvironmentVariable(''PSPKT_PHASE4_PROBE_NONCE'')',
                '$pidRecord = ''pspkt-phase4-descendant-pid-v1'' + [char]0x09 + $probeNonce + [char]0x09 + $descendantPid.ToString([System.Globalization.CultureInfo]::InvariantCulture) + [char]0x0A',
                '$pidBytes = [System.Text.Encoding]::ASCII.GetBytes($pidRecord)',
                '$pidStream = [System.IO.FileStream]::new($pidPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)',
                'try {',
                '    $pidStream.Write($pidBytes, 0, $pidBytes.Length)',
                '    $pidStream.Flush($true)',
                '}',
                'finally {',
                '    $pidStream.Dispose()',
                '}',
                '[System.Threading.Thread]::Sleep(60000)',
                'exit 21'
            )
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 60000 -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'Descendant'
            $reservedValues = @{
                'PSPKT_PHASE4_PROBE_MODE' = 'descendant-timeout'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
                'PSPKT_PHASE4_PROBE_PID_PATH' = $pidPath
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'DescendantHangChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName -WaitTimeoutMilliseconds 5000
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) { return $false }
            $pidBytes = Read-PspktBoundedFileBytes -FullPath $pidPath -ByteCap 256
            $pidText = [System.Text.Encoding]::ASCII.GetString($pidBytes)
            $pidPattern = '^pspkt-phase4-descendant-pid-v1' + [char]0x09 + [regex]::Escape($nonce) + [char]0x09 + '([1-9][0-9]*)' + [char]0x0A + '$'
            $pidMatch = [regex]::Match($pidText, $pidPattern)
            if (-not $pidMatch.Success) { return $false }
            $descendantPid = [int]::Parse($pidMatch.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
            $descendantAlive = $true
            try {
                $descendantProcess = [System.Diagnostics.Process]::GetProcessById($descendantPid)
                try {
                    $descendantAlive = -not $descendantProcess.HasExited
                }
                finally {
                    $descendantProcess.Dispose()
                }
            }
            catch [System.ArgumentException] {
                $descendantAlive = $false
            }
            return ($result.TimedOut -and $result.Terminated -and $result.Exited -and
                $result.ActiveProcessesAfterTerminate -eq 0 -and (-not $descendantAlive))
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['output-overflow'] = {
        $context = New-PspktProcessOracleContext -Tag 'overflow'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $postGateLines = [string[]]@(
                '$stdoutBytes = [System.Text.Encoding]::ASCII.GetBytes((''O'' * 16384))',
                '$stderrBytes = [System.Text.Encoding]::ASCII.GetBytes((''E'' * 16384))',
                '$stdoutStream = [Console]::OpenStandardOutput()',
                '$stderrStream = [Console]::OpenStandardError()',
                '$stdoutStream.Write($stdoutBytes, 0, $stdoutBytes.Length)',
                '$stdoutStream.Flush()',
                '$stderrStream.Write($stderrBytes, 0, $stderrBytes.Length)',
                '$stderrStream.Flush()',
                '[System.Threading.Thread]::Sleep(60000)',
                'exit 20'
            )
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 60000 -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'Overflow'
            $reservedValues = @{
                'PSPKT_PHASE4_PROBE_MODE' = 'output-overflow'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $retainCap = 1024
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'OverflowChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName -WaitTimeoutMilliseconds 30000 -RetainCapBytes $retainCap
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            $retainedStdOutBytes = [System.Text.Encoding]::UTF8.GetByteCount($result.StdOutText)
            $retainedStdErrBytes = [System.Text.Encoding]::UTF8.GetByteCount($result.StdErrText)
            return (($result.StdOutOverflow -or $result.StdErrOverflow) -and
                ($result.StdOutBytes -gt $retainCap -or $result.StdErrBytes -gt $retainCap) -and
                $retainedStdOutBytes -le $retainCap -and $retainedStdErrBytes -le $retainCap -and
                (-not $result.TimedOut) -and $result.Terminated -and $result.Exited -and
                $result.ActiveProcessesAfterTerminate -eq 0 -and $result.DrainCompleted)
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['helper-digest-mismatch'] = {
        $context = New-PspktProcessOracleContext -Tag 'digest-mismatch'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $markerPath = Join-Path $context.Root 'digest-mismatch.marker'
            $postGateLines = @(Get-PspktVerifiedHelperLoadLines) +
                @(Get-PspktMarkerWriterLines -MarkerPath $markerPath -Tag 'pspkt-phase4-digest-mismatch-v1') +
                @('exit 0')
            $scriptPath = New-PspktGateFirstScript -Context $context -GateMode Required -LiteralGateTimeoutMilliseconds 60000 -PostGateLines $postGateLines
            $gateName = New-PspktGateEventName -Tag 'DigestMismatch'
            $reservedValues = @{
                'PSPKT_PHASE4_HELPER_PATH' = $b.Path
                'PSPKT_PHASE4_HELPER_SHA256' = ('0' * 64)
                'PSPKT_PHASE4_HELPER_VERSION' = $b.Version
                'PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS' = '5000'
                'PSPKT_PHASE4_PROBE_MODE' = 'helper-digest-mismatch'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'WatchdogChild' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            return ($result.Started -and $result.Exited -and $result.ExitCode -eq 4 -and
                (-not $result.AssignFailed) -and (-not $result.TimedOut) -and
                $result.ActiveProcessesAfterTerminate -eq 0 -and
                (-not (Test-Path -LiteralPath $markerPath)))
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['pause-positive-release'] = {
        return (Invoke-PspktPauseLifecycleOracle -Binding $b -Mode 'positive')
    }.GetNewClosure()

    $map['pause-ack-timeout'] = {
        return (Invoke-PspktPauseLifecycleOracle -Binding $b -Mode 'ack-timeout')
    }.GetNewClosure()

    $map['pause-release-timeout'] = {
        return (Invoke-PspktPauseLifecycleOracle -Binding $b -Mode 'release-timeout')
    }.GetNewClosure()

    $map['parent-loss-gate-timeout'] = {
        return (Invoke-PspktParentLossGateTimeoutOracle -Binding $b)
    }.GetNewClosure()

    $map['post-assignment-kill-on-close'] = {
        return ((Test-PspktPostAssignmentKillOnCloseCleanupVectors) -and (Invoke-PspktPostAssignmentKillOnCloseOracle -Binding $b))
    }.GetNewClosure()

    $map['post-assignment-evidence-failure'] = {
        return ((Test-PspktPostAssignmentEvidenceCleanupVectors) -and (Invoke-PspktPostAssignmentEvidenceFailureOracle -Binding $b))
    }.GetNewClosure()

    $map['nested-job-inner-membership'] = {
        return (Invoke-PspktWorkerNestedMembershipOracle -Binding $b)
    }.GetNewClosure()

    if ($ProcessOraclesOnly.IsPresent) {
        foreach ($processOracleId in $processOracleIds) {
            if ($null -eq $map[$processOracleId]) {
                throw ('process oracle map did not populate "{0}".' -f $processOracleId)
            }
        }
        return $map
    }

    $map['drain-nonunwinding'] = {
        $context = New-PspktProcessOracleContext -Tag 'drain-nonunwinding'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $sentinelPath = Join-Path $context.Root 'failfast-sentinel.txt'
            $ordinaryResultPath = Join-Path $context.Root 'failfast-ordinary-result.txt'
            $scriptPath = New-PspktFailFastProbeScript -Context $context -ProbeMode 'drain-nonunwinding'
            $gateName = New-PspktGateEventName -Tag 'DrainNonUnwind'
            $reservedValues = @{
                'PSPKT_PHASE4_HELPER_PATH' = $b.Path
                'PSPKT_PHASE4_HELPER_SHA256' = $b.Digest
                'PSPKT_PHASE4_HELPER_VERSION' = $b.Version
                'PSPKT_PHASE4_PROBE_MODE' = 'drain-nonunwinding'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
                'PSPKT_PHASE4_FAILFAST_SENTINEL_PATH' = $sentinelPath
                'PSPKT_PHASE4_FAILFAST_RESULT_PATH' = $ordinaryResultPath
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'FailFastProbe' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunContainedProbe' -Arguments @($configuration, [int]60000)
            if (-not [bool]$result.Exited) { return $false }
            if ([bool]$result.TimedOut) { return $false }
            if ((([long]$result.ExitCode) -band 0xFFFFFFFFL) -ne 0x80131623L) { return $false }
            if ([long]$result.ActiveProcessesAfter -ne 0) { return $false }
            if (Test-Path -LiteralPath $ordinaryResultPath) { return $false }
            $snapshotAccess = Read-PspktFailFastSentinel -Path $sentinelPath -ExpectedVersion $b.Version -ExpectedNonce $nonce
            return ([long]$snapshotAccess -eq 0)
        }
        catch {
            return $false
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['drain-nonunwinding-negative-control'] = {
        $context = New-PspktProcessOracleContext -Tag 'drain-neg-control'
        try {
            $nonce = [Guid]::NewGuid().ToString('N')
            $sentinelPath = Join-Path $context.Root 'failfast-neg-sentinel.txt'
            $ordinaryResultPath = Join-Path $context.Root 'failfast-neg-ordinary-result.txt'
            $scriptPath = New-PspktFailFastProbeScript -Context $context -ProbeMode 'drain-nonunwinding-negative-control'
            $gateName = New-PspktGateEventName -Tag 'DrainNegControl'
            $reservedValues = @{
                'PSPKT_PHASE4_HELPER_PATH' = $b.Path
                'PSPKT_PHASE4_HELPER_SHA256' = $b.Digest
                'PSPKT_PHASE4_HELPER_VERSION' = $b.Version
                'PSPKT_PHASE4_PROBE_MODE' = 'drain-nonunwinding-negative-control'
                'PSPKT_PHASE4_PROBE_NONCE' = $nonce
                'PSPKT_PHASE4_FAILFAST_SENTINEL_PATH' = $sentinelPath
                'PSPKT_PHASE4_FAILFAST_RESULT_PATH' = $ordinaryResultPath
            }
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'FailFastProbe' -ScriptPath $scriptPath -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'RunContainedProbe' -Arguments @($configuration, [int]60000)
            if (-not [bool]$result.Exited) { return $false }
            if ([bool]$result.TimedOut) { return $false }
            if ((([long]$result.ExitCode) -band 0xFFFFFFFFL) -eq 0x80131623L) { return $false }
            if ([int]$result.ExitCode -ne 123) { return $false }
            if ([long]$result.ActiveProcessesAfter -ne 0) { return $false }
            if (Test-Path -LiteralPath $ordinaryResultPath) { return $false }
            $snapshotAccess = Read-PspktFailFastSentinel -Path $sentinelPath -ExpectedVersion $b.Version -ExpectedNonce $nonce
            return ([long]$snapshotAccess -eq 0)
        }
        catch {
            return $false
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    $map['manifest-negative-vectors'] = {
        $snapshotRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SNAPSHOT_ROOT')
        if ([string]::IsNullOrEmpty($snapshotRoot)) { return $false }
        return (Test-PspktManifestNegativeVectors -SnapshotRoot $snapshotRoot)
    }.GetNewClosure()

    $map['schema-child-result'] = {
        $context = New-PspktProcessOracleContext -Tag 'schema-child-result'
        try {
            $snapshotRoot = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SNAPSHOT_ROOT')
            $repositoryRootValue = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_REPOSITORY_ROOT')
            if ([string]::IsNullOrEmpty($snapshotRoot) -or [string]::IsNullOrEmpty($repositoryRootValue)) { return $false }
            $nonce = [Guid]::NewGuid().ToString('N')
            $resultDir = Join-Path $context.Root 'schema-result'
            [void][System.IO.Directory]::CreateDirectory($resultDir)
            $resultPath = Join-Path $resultDir 'schema-child-result.txt'
            $schemaChildScript = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($snapshotRoot, 'certification\validators\Test-PspktPhase4Schema.ps1'))
            $parserSourcePath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($snapshotRoot, 'certification\lib\Pspkt.Certification.SchemaBootstrap.cs'))
            $fixtureManifestPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($snapshotRoot, 'certification\vectors\phase4-schema\fixture-manifest.v1.json'))
            $metaSchemaPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($snapshotRoot, 'certification\schema\protocol-schema-meta.v1.json'))
            $gateName = New-PspktGateEventName -Tag 'SchemaChild'
            $reservedValues = @{
                'PSPKT_PHASE4_SNAPSHOT_ROOT' = $snapshotRoot
                'PSPKT_PHASE4_REPOSITORY_ROOT' = $repositoryRootValue
                'PSPKT_PHASE4_HELPER_PATH' = $b.Path
                'PSPKT_PHASE4_HELPER_SHA256' = $b.Digest
                'PSPKT_PHASE4_HELPER_VERSION' = $b.Version
                'PSPKT_PHASE4_SCHEMA_RESULT_PATH' = $resultPath
                'PSPKT_PHASE4_SCHEMA_RESULT_NONCE' = $nonce
                'PSPKT_PHASE4_GATE_TIMEOUT_MS' = '30000'
                'PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS' = '180000'
            }
            $extraArguments = [string[]]@(
                '-ParserSourcePath', $parserSourcePath,
                '-FixtureManifestPath', $fixtureManifestPath,
                '-MetaSchemaPath', $metaSchemaPath,
                '-ResultPath', $resultPath
            )
            $configuration = New-PspktProcessOracleConfiguration -Binding $b -Role 'SchemaChild' -ScriptPath $schemaChildScript -Context $context -ReservedValueByName $reservedValues -GateEventName $gateName -ExtraArguments $extraArguments -WaitTimeoutMilliseconds 240000 -TerminateGraceMilliseconds 15000 -DrainDeadlineMilliseconds 15000 -RetainCapBytes 65536
            $result = Invoke-PspktHelperStatic -Binding $b -Method 'Run' -Arguments @($configuration)
            if (-not ([bool]$result.Started -and [bool]$result.Exited -and [int]$result.ExitCode -eq 0 -and
                    (-not [bool]$result.AssignFailed) -and (-not [bool]$result.TimedOut) -and
                    [long]$result.ActiveProcessesAfterTerminate -eq 0)) {
                return $false
            }
            $cases = Get-PspktPhase4AuthorityCases -SnapshotRoot $snapshotRoot
            $accepted = Read-PspktSealedSchemaResult -ResultPath $resultPath -ExpectedNonce $nonce -ExpectedVersion $b.Version -ExpectedCases $cases
            return [bool]$accepted
        }
        catch {
            return $false
        }
        finally {
            Remove-PspktProcessOracleContext -Context $context
        }
    }.GetNewClosure()

    return $map
}

function Invoke-PspktPhase4Worker {
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [string]$Mutation = ''
    )
    $supervisorGateName = $env:PSPKT_PHASE4_SUPERVISOR_GATE_EVENT
    if ([string]::IsNullOrEmpty($supervisorGateName)) { exit 10 }
    if (-not [regex]::IsMatch($supervisorGateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 10 }
    $gate = $null
    try {
        $gate = [System.Threading.EventWaitHandle]::OpenExisting($supervisorGateName)
    }
    catch {
        exit 10
    }
    $signaled = $null
    try {
        $signaled = $gate.WaitOne(30000)
    }
    finally {
        $gate.Close()
    }
    if ($signaled -isnot [bool] -or -not $signaled) { exit 11 }

    $helperPath = $env:PSPKT_PHASE4_HELPER_PATH
    $helperSha = $env:PSPKT_PHASE4_HELPER_SHA256
    if ([string]::IsNullOrEmpty($helperPath) -or [string]::IsNullOrEmpty($helperSha)) { exit 12 }
    try {
        $binding = New-PspktHelperBinding -HelperPath $helperPath
        if ($binding.Digest -cne $helperSha) { exit 12 }
    }
    catch {
        exit 12
    }

    if ($Scenario -ceq 'WorkerNonzeroExit') { exit 13 }
    if ($Scenario -ceq 'WorkerTimeout') {
        $readyName = $env:PSPKT_PHASE4_WORKER_TIMEOUT_READY
        $ready = $null
        try {
            if ([string]::IsNullOrEmpty($readyName)) { exit 13 }
            $setMode = Get-PspktHelperEnum -Binding $binding -EnumName 'EventAccessMode' -Member 'SetOnly'
            $readyRole = Get-PspktHelperEnum -Binding $binding -EnumName 'EventRole' -Member 'WorkerTimeoutReady'
            $ready = Invoke-PspktHelperTypeStatic -Binding $binding -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($readyName, $setMode, $readyRole, [Guid]::Empty)
            $ready.SetEvent()
        }
        catch {
            exit 13
        }
        finally {
            if ($null -ne $ready) {
                try {
                    $ready.Close()
                }
                catch {
                    exit 13
                }
            }
        }
        Start-Sleep -Seconds 15
        exit 13
    }
    if ($Scenario -ceq 'WorkerLeavesDescendant') {
        $launchOk = $false
        try {
            $launchOk = Invoke-PspktWorkerLeavesDescendantLaunch -Binding $binding
        }
        catch {
            [Console]::Error.WriteLine($_.Exception.ToString())
            exit 13
        }
        if ($launchOk) { exit 0 }
        exit 13
    }
    if ($Scenario -ceq 'MalformedWorkerResult') {
        $resultPath = $env:PSPKT_PHASE4_WORKER_RESULT_PATH
        $nonce = $env:PSPKT_PHASE4_WORKER_NONCE
        Write-PspktWorkerResult -ResultPath $resultPath -Nonce $nonce -HelperVersion $binding.Version -CheckIds $script:ExpectedWorkerCheckIds -Mutation $Mutation
        exit 0
    }

    $resultPath = $env:PSPKT_PHASE4_WORKER_RESULT_PATH
    $nonce = $env:PSPKT_PHASE4_WORKER_NONCE
    if ([string]::IsNullOrEmpty($resultPath) -or [string]::IsNullOrEmpty($nonce)) { exit 12 }
    if (Test-Path -LiteralPath $resultPath) { exit 13 }

    $probeMap = Get-PspktWorkerProbeMap -Binding $binding
    $allPass = $true
    foreach ($checkId in $script:ExpectedWorkerCheckIds) {
        $probe = $probeMap[$checkId]
        $ok = $false
        if ($null -ne $probe) {
            try {
                $ok = [bool](& $probe)
            }
            catch {
                [Console]::Error.WriteLine(('worker check "{0}" failed: {1}' -f $checkId, $_.Exception.ToString()))
                $ok = $false
            }
        }
        Write-Host ('  [worker] {0} -> {1}' -f $checkId, $ok)
        if (-not $ok) { $allPass = $false }
    }
    if (-not $allPass) { exit 13 }
    Write-PspktWorkerResult -ResultPath $resultPath -Nonce $nonce -HelperVersion $binding.Version -CheckIds $script:ExpectedWorkerCheckIds
    exit 0
}

function Invoke-PspktWorkerGateProbe {
    param(
        [Parameter(Mandatory = $true)][string]$HostExe,
        [Parameter(Mandatory = $true)][string]$ValidatorPath,
        [AllowNull()][AllowEmptyString()][string]$GateName,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string]$HelperSha,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $HostExe
    $startInfo.Arguments = Join-PspktArgv -Argv @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ValidatorPath, '-Worker', '-WorkerScenario', 'Normal')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = [System.IO.Path]::GetTempPath()
    $removeNames = [System.Collections.Generic.List[string]]::new()
    foreach ($envEntry in $startInfo.EnvironmentVariables.Keys) {
        $envName = [string]$envEntry
        if ($envName.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$removeNames.Add($envName)
        }
    }
    foreach ($removeName in $removeNames) {
        [void]$startInfo.EnvironmentVariables.Remove($removeName)
    }
    if (-not [string]::IsNullOrEmpty($GateName)) {
        $startInfo.EnvironmentVariables['PSPKT_PHASE4_SUPERVISOR_GATE_EVENT'] = $GateName
    }
    $startInfo.EnvironmentVariables['PSPKT_PHASE4_HELPER_PATH'] = $HelperPath
    $startInfo.EnvironmentVariables['PSPKT_PHASE4_HELPER_SHA256'] = $HelperSha

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $captured = $null
    try {
        Assert-PspktBootstrapProcessLaunchAdmitted -Label $Label
        [void]$process.Start()
        $captured = Invoke-PspktDrainedProcess -Process $process -StdoutCap $script:GitStdoutCap -StderrCap $script:GitStdoutCap -TimeoutMs $TimeoutMs -Label $Label
    }
    finally {
        Invoke-PspktBootstrapCallerProcessDisposal -Process $process
    }
    return [pscustomobject]@{ ExitCode = [int]$captured.ExitCode }
}

function Test-PspktWorkerGatePrecedenceVectors {
    $hostExe = Get-PspktHostExecutable
    $validatorPath = [string]$script:Phase4ValidatorSourcePath
    if ([string]::IsNullOrEmpty($validatorPath) -or -not (Test-Path -LiteralPath $validatorPath -PathType Leaf)) {
        return $false
    }
    $badHelperPath = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-badhelper-' + [guid]::NewGuid().ToString('N') + '.dll')
    $badHelperSha = ('0' * 64)

    $missingGateOk = $false
    try {
        $missingGateResult = Invoke-PspktWorkerGateProbe -HostExe $hostExe -ValidatorPath $validatorPath -GateName '' -HelperPath $badHelperPath -HelperSha $badHelperSha -TimeoutMs 30000 -Label 'worker-gate-precedence missing-gate+bad-helper'
        $missingGateOk = ($missingGateResult.ExitCode -eq 10)
    }
    catch {
        Write-Host ('  [worker-gate-precedence] missing-gate probe failed :: {0}' -f (Get-PspktInnermostException -Exception $_.Exception).Message)
    }

    $timeoutOk = $false
    $timeoutGateName = New-PspktGateEventName -Tag 'GatePrecedenceTimeout'
    $timeoutGate = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::ManualReset, $timeoutGateName)
    try {
        $timeoutResult = Invoke-PspktWorkerGateProbe -HostExe $hostExe -ValidatorPath $validatorPath -GateName $timeoutGateName -HelperPath $badHelperPath -HelperSha $badHelperSha -TimeoutMs 60000 -Label 'worker-gate-precedence timeout+bad-helper'
        $timeoutOk = ($timeoutResult.ExitCode -eq 11)
    }
    catch {
        Write-Host ('  [worker-gate-precedence] timeout probe failed :: {0}' -f (Get-PspktInnermostException -Exception $_.Exception).Message)
    }
    finally {
        $timeoutGate.Close()
    }

    $successHelperFailureOk = $false
    $successGateName = New-PspktGateEventName -Tag 'GatePrecedenceSuccess'
    $successGate = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::ManualReset, $successGateName)
    try {
        [void]$successGate.Set()
        $successResult = Invoke-PspktWorkerGateProbe -HostExe $hostExe -ValidatorPath $validatorPath -GateName $successGateName -HelperPath $badHelperPath -HelperSha $badHelperSha -TimeoutMs 30000 -Label 'worker-gate-precedence success+bad-helper'
        $successHelperFailureOk = ($successResult.ExitCode -eq 12)
    }
    catch {
        Write-Host ('  [worker-gate-precedence] success-then-helper-failure probe failed :: {0}' -f (Get-PspktInnermostException -Exception $_.Exception).Message)
    }
    finally {
        $successGate.Close()
    }

    return ($missingGateOk -and $timeoutOk -and $successHelperFailureOk)
}

function Add-PspktQuarantineRegistration {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)]$Launch,
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Snapshots = @()
    )
    if ($null -eq $script:Phase4QuarantineRegistry) {
        throw 'quarantine registry authority is absent; unclean launch ownership cannot be rooted.'
    }
    $context = $null
    if ($null -ne $Launch) { $context = $Launch.Context }
    $snapshotArray = [object[]]@()
    if ($null -ne $Snapshots) { $snapshotArray = [object[]]$Snapshots }
    $record = [pscustomobject]@{
        Kind = $Kind
        Launch = $Launch
        Context = $context
        Snapshots = $snapshotArray
        RegisteredUtc = [datetime]::UtcNow
    }
    if ($script:Phase4QuarantineRegistry.Count -ge $script:Phase4QuarantineRegistryCapacity) {
        if ($null -eq $script:Phase4QuarantineEmergencySlot) {
            $script:Phase4QuarantineEmergencySlot = $record
            throw ([System.InvalidOperationException]::new(
                    ('quarantine registry primary reached its fixed capacity of {0}; the exact overflow {1} launch ownership (record, launch, context, and snapshots) was atomically retained in the non-droppable emergency ownership slot before this capacity error was surfaced, and every later general-quarantine launch is now refused so no second overflow can occur.' -f $script:Phase4QuarantineRegistryCapacity, $Kind)))
        }
        throw ([System.InvalidOperationException]::new(
                ('quarantine registry primary is at its fixed capacity of {0} and the non-droppable emergency ownership slot is already occupied by a "{1}" launch ownership; the launch-admission guard should have refused starting further work, so this is a fatal admission-guard invariant violation for overflow {2} launch ownership and the retained emergency ownership must not be dropped (fail-fast, restart required).' -f $script:Phase4QuarantineRegistryCapacity, [string]$script:Phase4QuarantineEmergencySlot.Kind, $Kind)))
    }
    [void]$script:Phase4QuarantineRegistry.Add($record)
    return $record
}

function Test-PspktQuarantineLaunchBlocked {
    return ($null -ne $script:Phase4QuarantineEmergencySlot)
}

function Assert-PspktQuarantineLaunchAdmitted {
    param([Parameter(Mandatory = $true)][string]$Label)
    $emergency = $script:Phase4QuarantineEmergencySlot
    if ($null -ne $emergency) {
        throw ([System.InvalidOperationException]::new(
                ('{0}: general-quarantine launch admission is refused; the non-droppable emergency ownership slot already holds an un-cleaned overflow "{1}" launch ownership that primary quarantine could not accept, so no further process/oracle/session/observer launch may begin.' -f $Label, [string]$emergency.Kind)))
    }
}

function Reset-PspktQuarantineEmergencySlotForProvenClean {
    param([Parameter(Mandatory = $true)]$Record)
    $emergency = $script:Phase4QuarantineEmergencySlot
    if ($null -eq $emergency) { return $false }
    if (-not [object]::ReferenceEquals($emergency, $Record)) { return $false }
    $ownedProvenClean = $true
    if ($null -ne $Record.Context) {
        $ownedEventsProperty = $Record.Context.PSObject.Properties['OwnedEvents']
        if ($null -ne $ownedEventsProperty -and $null -ne $ownedEventsProperty.Value) {
            foreach ($ownedResource in $ownedEventsProperty.Value) {
                if ($ownedResource -is [System.IO.Stream]) {
                    $ownedResource.Dispose()
                    if ($ownedResource.CanRead -or $ownedResource.CanWrite) { $ownedProvenClean = $false }
                }
                elseif ($ownedResource -is [System.IDisposable]) {
                    $ownedResource.Dispose()
                }
            }
        }
    }
    if (-not $ownedProvenClean) { return $false }
    $script:Phase4QuarantineEmergencySlot = $null
    return $true
}

function Add-PspktObserverQuarantineRegistration {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)]$Observer,
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$AuthorityHandles = @(),
        [AllowNull()]$OracleContext = $null
    )
    $ownedEvents = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $AuthorityHandles) {
        foreach ($authorityHandle in $AuthorityHandles) {
            if ($null -ne $authorityHandle) { [void]$ownedEvents.Add($authorityHandle) }
        }
    }
    $tempDirs = [string[]]@()
    if ($null -ne $OracleContext) {
        $contextRoot = ''
        $rootProperty = $OracleContext.PSObject.Properties['Root']
        if ($null -ne $rootProperty) { $contextRoot = [string]$rootProperty.Value }
        if (-not [string]::IsNullOrEmpty($contextRoot)) {
            $tempDirs = [string[]]@($contextRoot)
        }
    }
    $quarantineContext = [pscustomobject]@{
        CleanupState = 'Quarantined'
        TempDirs = $tempDirs
        OwnedEvents = $ownedEvents
        Observer = $Observer
        OracleContext = $OracleContext
    }
    $quarantineLaunch = [pscustomobject]@{ Session = $Observer; Context = $quarantineContext }
    return (Add-PspktQuarantineRegistration -Kind ('Observer:' + $Kind) -Launch $quarantineLaunch -Snapshots ([object[]]@($Observer)))
}

function Get-PspktQuarantineRegistrationCount {
    $count = 0
    if ($null -ne $script:Phase4QuarantineRegistry) { $count = $script:Phase4QuarantineRegistry.Count }
    if ($null -ne $script:Phase4QuarantineEmergencySlot) { $count += 1 }
    return $count
}

function Get-PspktQuarantineRegistrationKindList {
    $kinds = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $script:Phase4QuarantineRegistry) {
        foreach ($record in $script:Phase4QuarantineRegistry) {
            [void]$kinds.Add([string]$record.Kind)
        }
    }
    if ($null -ne $script:Phase4QuarantineEmergencySlot) {
        [void]$kinds.Add('Emergency:' + [string]$script:Phase4QuarantineEmergencySlot.Kind)
    }
    if ($kinds.Count -eq 0) {
        return ''
    }
    return ($kinds -join ',')
}

function Reset-PspktQuarantineRegistryTo {
    param([Parameter(Mandatory = $true)][int]$RetainedCount)
    if ($null -eq $script:Phase4QuarantineRegistry) { return }
    while ($script:Phase4QuarantineRegistry.Count -gt $RetainedCount) {
        $script:Phase4QuarantineRegistry.RemoveAt($script:Phase4QuarantineRegistry.Count - 1)
    }
}

function Remove-PspktStrictVectorRoot {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrEmpty($Root)) { return $null }
    $removalFailure = $null
    try {
        if (Test-Path -LiteralPath $Root) {
            Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $Root) {
            throw ('{0}: strict vector-root cleanup did not remove "{1}".' -f $Label, $Root)
        }
    }
    catch {
        $removalFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    if ($null -eq $removalFailure) {
        return $null
    }
    $quarantineContext = [pscustomobject]@{
        CleanupState = 'Quarantined'
        TempDirs = [string[]]@($Root)
        OwnedEvents = [System.Collections.Generic.List[object]]::new()
    }
    $quarantineLaunch = [pscustomobject]@{ Session = $null; Context = $quarantineContext }
    try {
        [void](Add-PspktQuarantineRegistration -Kind ('VectorRoot:' + $Label) -Launch $quarantineLaunch -Snapshots @())
    }
    catch {
        return (New-PspktComposedFailure -Message ('{0}: strict vector-root cleanup failed and quarantine registration failed.' -f $Label) -PrimaryFailure $removalFailure -CleanupFailures ([Exception[]]@((Get-PspktInnermostException -Exception $_.Exception))))
    }
    return $removalFailure
}

function New-PspktReservedContext {
    param(
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)]$Binding
    )
    Assert-PspktQuarantineLaunchAdmitted -Label 'worker/generator reserved context'
    return [pscustomobject]@{
        SnapshotRoot = $SnapshotRoot
        RepositoryRoot = $RepositoryRoot
        Binding = $Binding
        TempDirs = [System.Collections.Generic.List[string]]::new()
        OwnedEvents = [System.Collections.Generic.List[object]]::new()
        ResultPath = ''
        ResultRoot = ''
        ControlRoot = ''
        Nonce = ''
        NestedNonce = ''
        DescendantResultPath = ''
        DescendantNonce = ''
        GeneratorResultPath = ''
        GeneratorResultRoot = ''
        GeneratorNonce = ''
        GeneratorSourcePath = ''
        GeneratorSourceSha256 = ''
        GeneratorSourceLength = [long]0
        GeneratorSourceVolumeSerial = [uint32]0
        GeneratorSourceFileIndex = [uint64]0
        GeneratorSourceCreationTimeUtc = [datetime]::MinValue
        GeneratorSourceLastWriteTimeUtc = [datetime]::MinValue
        GeneratorSourceStream = $null
        GeneratorHardlinkRoot = ''
        GeneratorTargetRoot = ''
        GeneratorHardlinkPreResultPath = ''
        GeneratorHardlinkStreams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
        GeneratorHardlinkReceipt = $null
        GeneratorEvents = @{}
        EventNames = @{}
        WorkerTimeoutReadyEvent = $null
        CleanupState = 'Pending'
    }
}

function New-PspktReservedValue {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Name -ceq 'PSPKT_PHASE4_SNAPSHOT_ROOT') { return $Context.SnapshotRoot }
    if ($Name -ceq 'PSPKT_PHASE4_REPOSITORY_ROOT') { return $Context.RepositoryRoot }
    if ($Name -ceq 'PSPKT_PHASE4_HELPER_PATH') { return $Context.Binding.Path }
    if ($Name -ceq 'PSPKT_PHASE4_HELPER_SHA256') { return $Context.Binding.Digest }
    if ($Name -ceq 'PSPKT_PHASE4_HELPER_VERSION') { return $Context.Binding.Version }
    if ($Name -ceq 'PSPKT_PHASE4_GENERATOR_SOURCE_SHA256') {
        if ([string]::IsNullOrEmpty($Context.GeneratorSourceSha256)) {
            throw 'generator source digest authority was not bound before reserved environment construction.'
        }
        return $Context.GeneratorSourceSha256
    }
    if ($Name.EndsWith('_RESULT_PATH')) {
        $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-res-'
        $Context.TempDirs.Add($root)
        $leaf = Join-Path $root ('result-' + [guid]::NewGuid().ToString('N') + '.txt')
        if ($Name -ceq 'PSPKT_PHASE4_WORKER_RESULT_PATH') {
            $Context.ResultPath = $leaf
            $Context.ResultRoot = $root
        }
        if ($Name -ceq 'PSPKT_PHASE4_DESCENDANT_RESULT_PATH') {
            $Context.DescendantResultPath = $leaf
        }
        if ($Name -ceq 'PSPKT_PHASE4_GENERATOR_RESULT_PATH') {
            $Context.GeneratorResultPath = $leaf
            $Context.GeneratorResultRoot = $root
        }
        return $leaf
    }
    if ($Name.EndsWith('_ROOT')) {
        $dir = New-PspktTempDirectory -Prefix 'pspkt-phase4-root-'
        $Context.TempDirs.Add($dir)
        if ($Name -ceq 'PSPKT_PHASE4_NESTED_CONTROL_ROOT') { $Context.ControlRoot = $dir }
        if ($Name -ceq 'PSPKT_PHASE4_GENERATOR_HARDLINK_ROOT') { $Context.GeneratorHardlinkRoot = $dir }
        if ($Name -ceq 'PSPKT_PHASE4_GENERATOR_TARGET_ROOT') { $Context.GeneratorTargetRoot = $dir }
        return $dir
    }
    if ($Name.EndsWith('_NONCE')) {
        $value = [guid]::NewGuid().ToString('N')
        if ($Name -ceq 'PSPKT_PHASE4_WORKER_NONCE') { $Context.Nonce = $value }
        if ($Name -ceq 'PSPKT_PHASE4_NESTED_NONCE') { $Context.NestedNonce = $value }
        if ($Name -ceq 'PSPKT_PHASE4_DESCENDANT_NONCE') { $Context.DescendantNonce = $value }
        if ($Name -ceq 'PSPKT_PHASE4_GENERATOR_NONCE') { $Context.GeneratorNonce = $value }
        return $value
    }
    if ($Name.EndsWith('_CORRELATION_ID')) { return [guid]::NewGuid().ToString('N') }
    if ($Name.EndsWith('_MS') -or $Name.EndsWith('_EXIT_CODE') -or $Name.EndsWith('_BLOCK_MS')) { return '5000' }
    if ($Name -ceq 'PSPKT_PHASE4_GENERATOR_HARDLINK_PRE_RESULT') {
        $leaf = Join-Path $Context.GeneratorHardlinkRoot ('pre-' + [guid]::NewGuid().ToString('N') + '.txt')
        $Context.GeneratorHardlinkPreResultPath = $leaf
        return $leaf
    }
    if ($Name -match '_(EVENT|READY|AUTHORIZE|AUTHORIZED|PREPARED|EXITED|COMPLETE|ARMED)$' -or $Name.EndsWith('_GATE_EVENT')) {
        $eventName = New-PspktGateEventName -Tag 'Rsv'
        $Context.EventNames[$Name] = $eventName
        return $eventName
    }
    if ($Name.EndsWith('_PATH')) {
        $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-p-'
        $Context.TempDirs.Add($root)
        return (Join-Path $root ('item-' + [guid]::NewGuid().ToString('N') + '.txt'))
    }
    return [guid]::NewGuid().ToString('N')
}

function New-PspktWorkerReservedArrays {
    param(
        [Parameter(Mandatory = $true)]$Context
    )
    $roleValue = Get-PspktHelperEnum -Binding $Context.Binding -EnumName 'ProcessLaunchRole' -Member 'Worker'
    $names = @(Invoke-PspktHelperStatic -Binding $Context.Binding -Method 'GetRequiredReservedNames' -Arguments @($roleValue))
    $values = @()
    foreach ($name in $names) {
        $values += (New-PspktReservedValue -Context $Context -Name $name)
    }
    return [pscustomobject]@{ Names = [string[]]$names; Values = [string[]]$values }
}

function Clear-PspktReservedContext {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [bool]$OwnershipClean = $true
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    $rootRemovalFailed = $false
    if ($OwnershipClean) {
        foreach ($evt in $Context.OwnedEvents) {
            try {
                $evt.Close()
            }
            catch {
                $OwnershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    else {
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('worker reserved events were retained because session, snapshot, or event ownership was not clean.'))
    }
    if ($OwnershipClean) {
        for ($directoryIndex = $Context.TempDirs.Count - 1; $directoryIndex -ge 0; $directoryIndex--) {
            $dir = $Context.TempDirs[$directoryIndex]
            try {
                if (Test-Path -LiteralPath $dir) {
                    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $dir) {
                    throw ('worker reserved context cleanup did not remove "{0}".' -f $dir)
                }
            }
            catch {
                $rootRemovalFailed = $true
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    else {
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('worker reserved roots were retained because session, snapshot, or event ownership was not clean.'))
    }
    if ($cleanupFailures.Count -eq 0) {
        $Context.CleanupState = 'Cleaned'
    }
    elseif ($OwnershipClean -and -not $rootRemovalFailed) {
        $Context.CleanupState = 'Pending'
    }
    else {
        $Context.CleanupState = 'Quarantined'
    }
    return ,([Exception[]]$cleanupFailures.ToArray())
}

function Close-PspktWorkerLaunch {
    param(
        [Parameter(Mandatory = $true)]$Launch,
        [AllowEmptyCollection()]
        [object[]]$Snapshots = @(),
        [bool]$OwnershipClean = $true
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    $sessionClean = $OwnershipClean
    if ($null -ne $Launch.Session) {
        try {
            $Launch.Session.Dispose()
        }
        catch {
            $sessionClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        $disposeErrors = @()
        try {
            $disposeErrors = @($Launch.Session.GetDisposeErrors())
        }
        catch {
            $sessionClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        foreach ($disposeError in $disposeErrors) {
            $sessionClean = $false
            [void]$cleanupFailures.Add($disposeError)
        }
        $disposeSucceeded = $false
        $sessionState = ''
        try {
            $disposeSucceeded = [bool]$Launch.Session.DisposeSucceeded
            $sessionState = [string]$Launch.Session.State.ToString()
        }
        catch {
            $sessionClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        if (-not $disposeSucceeded -or $sessionState -cne 'Cleaned') {
            $sessionClean = $false
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                    ('contained worker cleanup proof failed: DisposeSucceeded={0}; State={1}.' -f $disposeSucceeded, $sessionState)))
        }
    }
    $ownershipClean = $sessionClean
    if ($sessionClean) {
        foreach ($snapshot in $Snapshots) {
            if ($null -eq $snapshot) { continue }
            try {
                if (-not (Close-PspktJobSnapshot -Snapshot $snapshot)) {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add([System.InvalidOperationException]::new('worker job snapshot cleanup did not report DisposeSucceeded.'))
                }
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    else {
        foreach ($snapshot in $Snapshots) {
            if ($null -eq $snapshot) { continue }
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new('worker job snapshots were retained because contained worker session ownership was not clean.'))
            break
        }
    }
    $contextFailures = Clear-PspktReservedContext -Context $Launch.Context -OwnershipClean $ownershipClean
    foreach ($contextFailure in $contextFailures) {
        [void]$cleanupFailures.Add($contextFailure)
    }
    if ($cleanupFailures.Count -eq 0 -and [string]$Launch.Context.CleanupState -cne 'Cleaned') {
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                ('worker reserved context reported unexpected cleanup state "{0}".' -f $Launch.Context.CleanupState)))
    }
    if ([string]$Launch.Context.CleanupState -ceq 'Quarantined') {
        try {
            [void](Add-PspktQuarantineRegistration -Kind 'Worker' -Launch $Launch -Snapshots $Snapshots)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    return ,([Exception[]]$cleanupFailures.ToArray())
}

function Complete-PspktWorkerLaunch {
    param(
        [AllowNull()]
        $Launch,
        [AllowNull()]
        [Exception]$PrimaryFailure = $null,
        [AllowEmptyCollection()]
        [object[]]$Snapshots = @(),
        [bool]$OwnershipClean = $true,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $cleanupFailures = [Exception[]]@()
    if ($null -ne $Launch) {
        $cleanupFailures = Close-PspktWorkerLaunch -Launch $Launch -Snapshots $Snapshots -OwnershipClean $OwnershipClean
    }
    $failure = New-PspktComposedFailure -Message $Message -PrimaryFailure $PrimaryFailure -CleanupFailures $cleanupFailures
    if ($null -ne $failure) {
        throw $failure
    }
}

function Test-PspktWorkerCleanupNegativeVectors {
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $failingSessionOk = $false
    $failingSessionRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-worker-cleanup-sess-'
    try {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        [void]$tempDirectories.Add($failingSessionRoot)
        $ownedEvents = [System.Collections.Generic.List[object]]::new()
        $eventCloseState = [pscustomobject]@{ Called = $false }
        $failingEvent = [pscustomobject]@{ State = $eventCloseState }
        $failingEvent | Add-Member -MemberType ScriptMethod -Name Close -Value {
            $this.State.Called = $true
            throw [System.IO.IOException]::new('injected worker event close failure.')
        }
        [void]$ownedEvents.Add($failingEvent)
        $context = [pscustomobject]@{
            OwnedEvents = $ownedEvents
            TempDirs = $tempDirectories
            CleanupState = 'Pending'
        }
        $failingSession = [pscustomobject]@{
            DisposeSucceeded = $false
            State = 'Released'
        }
        $failingSession | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
            throw [System.IO.IOException]::new('injected contained worker dispose failure.')
        }
        $failingSession | Add-Member -MemberType ScriptMethod -Name GetDisposeErrors -Value {
            return [Exception[]]@([System.IO.IOException]::new('recorded contained worker cleanup failure.'))
        }
        $launch = [pscustomobject]@{
            Session = $failingSession
            Context = $context
        }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $cleanupFailures = Close-PspktWorkerLaunch -Launch $launch
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $primaryFailure = [System.InvalidOperationException]::new('injected worker primary failure.')
        $aggregate = New-PspktComposedFailure -Message 'injected worker aggregate.' -PrimaryFailure $primaryFailure -CleanupFailures $cleanupFailures
        if ($aggregate -is [System.AggregateException]) {
            $messages = [string[]]@($aggregate.InnerExceptions | ForEach-Object { $_.Message })
            $failingSessionOk = (
                $registered -and
                $context.CleanupState -ceq 'Quarantined' -and
                (Test-Path -LiteralPath $failingSessionRoot -PathType Container) -and
                (-not $eventCloseState.Called) -and
                $messages -contains 'injected worker primary failure.' -and
                $messages -contains 'injected contained worker dispose failure.' -and
                $messages -contains 'recorded contained worker cleanup failure.' -and
                $messages -notcontains 'injected worker event close failure.')
        }
    }
    finally {
        if (Test-Path -LiteralPath $failingSessionRoot) {
            Remove-Item -LiteralPath $failingSessionRoot -Recurse -Force -ErrorAction Stop
        }
    }

    $cleanSessionEventOk = $false
    $cleanSessionRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-worker-cleanup-evt-'
    try {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        [void]$tempDirectories.Add($cleanSessionRoot)
        $ownedEvents = [System.Collections.Generic.List[object]]::new()
        $eventCloseState = [pscustomobject]@{ Called = $false }
        $failingEvent = [pscustomobject]@{ State = $eventCloseState }
        $failingEvent | Add-Member -MemberType ScriptMethod -Name Close -Value {
            $this.State.Called = $true
            throw [System.IO.IOException]::new('injected worker event close failure.')
        }
        [void]$ownedEvents.Add($failingEvent)
        $context = [pscustomobject]@{
            OwnedEvents = $ownedEvents
            TempDirs = $tempDirectories
            CleanupState = 'Pending'
        }
        $cleanSession = [pscustomobject]@{ DisposeSucceeded = $true; State = 'Cleaned' }
        $cleanSession | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
        $cleanSession | Add-Member -MemberType ScriptMethod -Name GetDisposeErrors -Value {
            return [Exception[]]@()
        }
        $launch = [pscustomobject]@{ Session = $cleanSession; Context = $context }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $cleanupFailures = Close-PspktWorkerLaunch -Launch $launch
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $messages = [string[]]@($cleanupFailures | ForEach-Object { $_.Message })
        $cleanSessionEventOk = (
            $registered -and
            $eventCloseState.Called -and
            $context.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $cleanSessionRoot -PathType Container) -and
            $messages -contains 'injected worker event close failure.')
    }
    finally {
        if (Test-Path -LiteralPath $cleanSessionRoot) {
            Remove-Item -LiteralPath $cleanSessionRoot -Recurse -Force -ErrorAction Stop
        }
    }

    $cleanOk = $false
    $cleanRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-worker-cleanup-clean-'
    $cleanRootFailure = $null
    try {
        $tempDirectories = [System.Collections.Generic.List[string]]::new()
        [void]$tempDirectories.Add($cleanRoot)
        $context = [pscustomobject]@{
            OwnedEvents = [System.Collections.Generic.List[object]]::new()
            TempDirs = $tempDirectories
            CleanupState = 'Pending'
        }
        $cleanSession = [pscustomobject]@{ DisposeSucceeded = $true; State = 'Cleaned' }
        $cleanSession | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
        $cleanSession | Add-Member -MemberType ScriptMethod -Name GetDisposeErrors -Value {
            return [Exception[]]@()
        }
        $launch = [pscustomobject]@{ Session = $cleanSession; Context = $context }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $cleanupFailures = Close-PspktWorkerLaunch -Launch $launch
        $cleanOk = (
            $cleanupFailures.Count -eq 0 -and
            $context.CleanupState -ceq 'Cleaned' -and
            (-not (Test-Path -LiteralPath $cleanRoot)) -and
            ((Get-PspktQuarantineRegistrationCount) -eq $countBefore))
    }
    finally {
        $cleanRootFailure = Remove-PspktStrictVectorRoot -Root $cleanRoot -Label 'worker-cleanup cleanRoot'
    }

    Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
    return ($failingSessionOk -and $cleanSessionEventOk -and $cleanOk -and ($null -eq $cleanRootFailure))
}

function Invoke-PspktWorkerScenarioLaunch {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [string]$Mutation = '',
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )
    $context = New-PspktReservedContext -SnapshotRoot $SnapshotRoot -RepositoryRoot $RepositoryRoot -Binding $Binding
    try {
        $reserved = New-PspktWorkerReservedArrays -Context $context
        if ($Scenario -ceq 'WorkerTimeout') {
            if (-not $context.EventNames.ContainsKey('PSPKT_PHASE4_WORKER_TIMEOUT_READY')) {
                throw 'worker timeout ready event authority was not reserved before launch.'
            }
            $readyRole = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member 'WorkerTimeoutReady'
            $context.WorkerTimeoutReadyEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @(
                $context.EventNames['PSPKT_PHASE4_WORKER_TIMEOUT_READY'], $readyRole, [Guid]::Empty)
            [void]$context.OwnedEvents.Add($context.WorkerTimeoutReadyEvent)
            if ($context.WorkerTimeoutReadyEvent.IsSignaledNow()) {
                throw 'worker timeout ready event was initially signaled.'
            }
        }
        $hostExe = Get-PspktHostExecutable
        $validatorPath = Join-Path $SnapshotRoot 'certification\validators\Invoke-PspktPhase4SchemaValidators.ps1'
        $gateName = New-PspktGateEventName -Tag 'Sup'
        $argv = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $validatorPath, '-Worker', '-WorkerScenario', $Scenario)
        if ($Scenario -ceq 'MalformedWorkerResult') {
            $argv += @('-WorkerMutation', $Mutation)
        }
        $workingDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-wwd-'
        $context.TempDirs.Add($workingDir)
        $scenarioValue = Get-PspktHelperEnum -Binding $Binding -EnumName 'ContainedWorkerScenario' -Member $Scenario
        $session = Invoke-PspktHelperStatic -Binding $Binding -Method 'RunContainedValidatorWorker' -Arguments @(
            $hostExe, ([string[]]$argv), $gateName, $reserved.Names, $reserved.Values, $workingDir, $scenarioValue)
        return [pscustomobject]@{ Session = $session; Context = $context; GateName = $gateName }
    }
    catch {
        $original = $_.Exception
        $launchFailure = Get-PspktInnermostException -Exception $original
        $ownershipQuarantined = Test-PspktExceptionTreeContainsType -Exception $original -FullTypeName 'Pspkt.Certification.ContainedLaunchOwnershipQuarantinedException'
        $partialLaunch = [pscustomobject]@{ Session = $null; Context = $context; GateName = '' }
        Complete-PspktWorkerLaunch -Launch $partialLaunch -PrimaryFailure $launchFailure -OwnershipClean (-not $ownershipQuarantined) -Message 'worker launch and reserved-context cleanup failures.'
        throw $launchFailure
    }
}

function Get-PspktFileStreamSha256 {
    param([Parameter(Mandatory = $true)][System.IO.FileStream]$Stream)
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'generator source authority stream must be readable and seekable.'
    }
    $originalPosition = $Stream.Position
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        $hash = $sha256.ComputeHash($Stream)
    }
    finally {
        $Stream.Position = $originalPosition
        $sha256.Dispose()
    }
    $builder = [System.Text.StringBuilder]::new(64)
    foreach ($hashByte in $hash) {
        [void]$builder.Append($hashByte.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    return $builder.ToString()
}

function Get-PspktFileStreamIdentity {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$FullPath
    )
    $identityType = Get-PspktHelperType -Binding $Binding -SimpleName 'RetainedPathIdentity'
    $queryMethod = $identityType.GetMethod(
        'QueryHandleInformation',
        ([System.Reflection.BindingFlags]'NonPublic, Static'),
        $null,
        [Type[]]@([System.IO.FileStream], [string]),
        $null)
    if ($null -eq $queryMethod) {
        throw 'helper binding: exact RetainedPathIdentity.QueryHandleInformation signature is absent.'
    }
    $nativeIdentity = $queryMethod.Invoke($null, [object[]]@($Stream, $FullPath))
    $nativeType = $nativeIdentity.GetType()
    $fieldFlags = [System.Reflection.BindingFlags]'Public, NonPublic, Instance'
    $volumeField = $nativeType.GetField('dwVolumeSerialNumber', $fieldFlags)
    $indexHighField = $nativeType.GetField('nFileIndexHigh', $fieldFlags)
    $indexLowField = $nativeType.GetField('nFileIndexLow', $fieldFlags)
    $attributesField = $nativeType.GetField('dwFileAttributes', $fieldFlags)
    if ($null -eq $volumeField -or $null -eq $indexHighField -or
        $null -eq $indexLowField -or $null -eq $attributesField) {
        throw 'helper binding: retained file identity fields are incomplete.'
    }
    [uint32]$attributes = $attributesField.GetValue($nativeIdentity)
    if (($attributes -band [uint32]0x00000400) -ne 0 -or
        ($attributes -band [uint32]0x00000010) -ne 0) {
        throw 'generator source handle resolved to a reparse point or directory.'
    }
    [uint64]$indexHigh = [uint32]$indexHighField.GetValue($nativeIdentity)
    [uint64]$indexLow = [uint32]$indexLowField.GetValue($nativeIdentity)
    return [pscustomobject]@{
        VolumeSerial = [uint32]$volumeField.GetValue($nativeIdentity)
        FileIndex = (($indexHigh -shl 32) -bor $indexLow)
    }
}

function Get-PspktFileStreamFileId48 {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$FullPath
    )
    $identityType = Get-PspktHelperType -Binding $Binding -SimpleName 'RetainedPathIdentity'
    $queryMethod = $identityType.GetMethod(
        'QueryFileId48',
        ([System.Reflection.BindingFlags]'NonPublic, Static'),
        $null,
        [Type[]]@([System.IO.FileStream], [string]),
        $null)
    if ($null -eq $queryMethod) {
        throw 'helper binding: exact RetainedPathIdentity.QueryFileId48 signature is absent.'
    }
    $fileId48 = [string]$queryMethod.Invoke($null, [object[]]@($Stream, $FullPath))
    if (-not [regex]::IsMatch($fileId48, '^[0-9a-f]{48}$')) {
        throw 'helper binding: RetainedPathIdentity.QueryFileId48 did not return a 48-hex identity.'
    }
    return $fileId48
}

function Open-PspktExclusiveGeneratorSource {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$GeneratorPath
    )
    $canonicalPath = [System.IO.Path]::GetFullPath($GeneratorPath)
    if ($canonicalPath -cne $GeneratorPath) {
        throw 'generator source authority path is not canonical.'
    }
    if (-not (Test-PspktNonReparseDirectory -FullPath $Context.SnapshotRoot)) {
        throw 'generator snapshot root is absent or reparsed.'
    }
    $snapshotPrefix = $Context.SnapshotRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $canonicalPath.StartsWith($snapshotPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'generator source authority path is outside the snapshot root.'
    }
    $sourceInfo = [System.IO.FileInfo]::new($canonicalPath)
    if (-not $sourceInfo.Exists -or
        ($sourceInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($sourceInfo.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
        $sourceInfo.Length -gt $script:GitBlobByteCap) {
        throw 'generator source authority is not a bounded ordinary file.'
    }
    $relativePath = $canonicalPath.Substring($snapshotPrefix.Length)
    $relativeParts = $relativePath.Split(
        [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
        [System.StringSplitOptions]::RemoveEmptyEntries)
    $currentDirectoryPath = $Context.SnapshotRoot
    for ($partIndex = 0; $partIndex -lt ($relativeParts.Length - 1); $partIndex++) {
        $currentDirectoryPath = [System.IO.Path]::Combine($currentDirectoryPath, $relativeParts[$partIndex])
        if (-not (Test-PspktNonReparseDirectory -FullPath $currentDirectoryPath)) {
            throw 'generator source authority has an absent or reparsed ancestor.'
        }
    }

    $stream = [System.IO.FileStream]::new(
        $canonicalPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::None)
    try {
        if ($stream.Length -ne $sourceInfo.Length -or $stream.Length -gt $script:GitBlobByteCap) {
            throw 'generator source authority length changed during exclusive open.'
        }
        $Context.GeneratorSourcePath = $canonicalPath
        $Context.GeneratorSourceLength = $stream.Length
        $Context.GeneratorSourceCreationTimeUtc = $sourceInfo.CreationTimeUtc
        $Context.GeneratorSourceLastWriteTimeUtc = $sourceInfo.LastWriteTimeUtc
        $sourceIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $stream -FullPath $canonicalPath
        $Context.GeneratorSourceVolumeSerial = $sourceIdentity.VolumeSerial
        $Context.GeneratorSourceFileIndex = $sourceIdentity.FileIndex
        $Context.GeneratorSourceSha256 = Get-PspktFileStreamSha256 -Stream $stream
        $Context.GeneratorSourceStream = $stream
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function New-PspktGeneratorControlEvents {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][ValidateSet('Normal', 'GateWithheld')][string]$Scenario
    )
    $genericRole = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member 'Generic'
    $controlEnvironmentNames = [System.Collections.Generic.List[string]]::new()
    foreach ($controlEnvironmentName in [string[]]@(
            'PSPKT_PHASE4_GENERATOR_GATE_PREPARED',
            'PSPKT_PHASE4_GENERATOR_GATE_AUTHORIZE',
            'PSPKT_PHASE4_GENERATOR_GATE_WAIT_ARMED')) {
        [void]$controlEnvironmentNames.Add($controlEnvironmentName)
    }
    if ($Scenario -ceq 'Normal') {
        [void]$controlEnvironmentNames.Add('PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED')
        [void]$controlEnvironmentNames.Add('PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED')
    }
    foreach ($environmentName in $controlEnvironmentNames) {
        if (-not $Context.EventNames.ContainsKey($environmentName)) {
            throw ('generator control event name "{0}" is absent.' -f $environmentName)
        }
        $eventName = [string]$Context.EventNames[$environmentName]
        $namedEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @(
            $eventName, $genericRole, [Guid]::Empty)
        if ($namedEvent.IsSignaledNow()) {
            $namedEvent.Close()
            throw ('generator control event "{0}" was initially signaled.' -f $environmentName)
        }
        $Context.GeneratorEvents[$environmentName] = $namedEvent
    }
}

function Invoke-PspktGeneratorLaunch {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )
    $context = New-PspktReservedContext -SnapshotRoot $SnapshotRoot -RepositoryRoot $RepositoryRoot -Binding $Binding
    try {
        $scenarioValue = Get-PspktHelperEnum -Binding $Binding -EnumName 'GeneratorScenario' -Member $Scenario
        $generatorPath = [System.IO.Path]::GetFullPath(
            (Join-Path $SnapshotRoot 'certification\vectors\New-PspktPhase4SchemaVectors.ps1'))
        $validatorPath = [System.IO.Path]::GetFullPath(
            (Join-Path $SnapshotRoot 'certification\validators\Invoke-PspktPhase4SchemaValidators.ps1'))
        if ($Scenario -cne 'ContainedFalse') {
            Open-PspktExclusiveGeneratorSource -Context $context -GeneratorPath $generatorPath
        }

        $reservedNames = @(Invoke-PspktHelperStatic -Binding $Binding -Method 'GetRequiredGeneratorReservedNames' -Arguments @($scenarioValue))
        $reservedValues = @()
        foreach ($name in $reservedNames) {
            $reservedValues += (New-PspktReservedValue -Context $context -Name $name)
        }
        if ($Scenario -cne 'ContainedFalse') {
            New-PspktGeneratorControlEvents -Binding $Binding -Context $context -Scenario $Scenario
        }

        $argv = @(Invoke-PspktHelperStatic -Binding $Binding -Method 'GetGeneratorArgv' -Arguments @(
            $scenarioValue, $validatorPath, $generatorPath))
        $hostExe = Get-PspktHostExecutable
        $gateName = New-PspktGateEventName -Tag 'Gen'
        $workingDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-gwd-'
        $context.TempDirs.Add($workingDir)
        $session = Invoke-PspktHelperStatic -Binding $Binding -Method 'RunContainedGeneratorHost' -Arguments @(
            $hostExe, ([string[]]$argv), $gateName, ([string[]]$reservedNames), ([string[]]$reservedValues), $workingDir, $scenarioValue)
        return [pscustomobject]@{ Session = $session; Context = $context; GateName = $gateName }
    }
    catch {
        $original = $_.Exception
        $launchError = Get-PspktInnermostException -Exception $original
        $ownershipQuarantined = Test-PspktExceptionTreeContainsType -Exception $original -FullTypeName 'Pspkt.Certification.ContainedLaunchOwnershipQuarantinedException'
        $partialLaunch = [pscustomobject]@{ Session = $null; Context = $context }
        Complete-PspktGeneratorLaunch -Launch $partialLaunch -PrimaryFailure $launchError -OwnershipClean (-not $ownershipQuarantined) -Message 'generator launch and reserved-context cleanup failures.'
        throw $launchError
    }
}

function Test-PspktWorkerResultNegativeVectors {
    param(
        [Parameter(Mandatory = $true)][string]$HelperVersion
    )
    $nonce = [guid]::NewGuid().ToString('N')
    $tempRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-wrneg-'
    $result = $false
    $tempRootFailure = $null
    try {
        $allReject = $true
        foreach ($mutation in $script:WorkerResultMutationInventory) {
            $path = Join-Path $tempRoot ('m-' + $mutation + '.txt')
            Write-PspktWorkerResult -ResultPath $path -Nonce $nonce -HelperVersion $HelperVersion -CheckIds $script:ExpectedWorkerCheckIds -Mutation $mutation
            $rejected = Test-PspktThrows { Read-PspktSealedWorkerResult -ResultPath $path -ExpectedNonce $nonce -ExpectedVersion $HelperVersion -ExpectedCheckIds $script:ExpectedWorkerCheckIds }
            if (-not $rejected) { $allReject = $false }
        }
        $missingPath = Join-Path $tempRoot 'never-written.txt'
        $missingRejected = Test-PspktThrows { Read-PspktSealedWorkerResult -ResultPath $missingPath -ExpectedNonce $nonce -ExpectedVersion $HelperVersion -ExpectedCheckIds $script:ExpectedWorkerCheckIds }
        if (-not $missingRejected) { $allReject = $false }
        $goodPath = Join-Path $tempRoot 'good.txt'
        Write-PspktWorkerResult -ResultPath $goodPath -Nonce $nonce -HelperVersion $HelperVersion -CheckIds $script:ExpectedWorkerCheckIds
        $accepted = $false
        try { $accepted = Read-PspktSealedWorkerResult -ResultPath $goodPath -ExpectedNonce $nonce -ExpectedVersion $HelperVersion -ExpectedCheckIds $script:ExpectedWorkerCheckIds } catch { $accepted = $false }
        $result = ($allReject -and $accepted -and
            (Test-PspktWorkerCleanupNegativeVectors) -and
            (Test-PspktComposedFailureSiblingVectors) -and
            (Test-PspktExceptionTreeDetectionVectors) -and
            (Test-PspktWorkerLaunchQuarantineVectors))
    }
    finally {
        $tempRootFailure = Remove-PspktStrictVectorRoot -Root $tempRoot -Label 'worker-result-negative tempRoot'
    }
    return ($result -and ($null -eq $tempRootFailure))
}

function Invoke-PspktRunMalformedScenarios {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot
    )
    $allRejected = $true
    foreach ($mutation in $script:WorkerResultMutationInventory) {
        $launch = $null
        $mutationRejected = $false
        $primaryFailure = $null
        try {
            $launch = Invoke-PspktWorkerScenarioLaunch -Binding $Binding -Scenario 'MalformedWorkerResult' -Mutation $mutation -SnapshotRoot $SnapshotRoot -RepositoryRoot $repositoryRoot
            $session = $launch.Session
            $context = $launch.Context
            $session.SignalWorkerGate()
            $waitStatus = $session.WaitWorker(60000)
            if (-not (Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0')) {
                throw ('malformed worker result scenario "{0}" did not exit within the worker deadline.' -f $mutation)
            }
            $exitZero = ($session.GetExitCode() -eq 0)
            $rejected = $false
            if ($exitZero -and -not [string]::IsNullOrEmpty($context.ResultPath)) {
                $rejected = Test-PspktThrows { Read-PspktSealedWorkerResult -ResultPath $context.ResultPath -ExpectedNonce $context.Nonce -ExpectedVersion $Binding.Version -ExpectedCheckIds $script:ExpectedWorkerCheckIds }
            }
            $mutationRejected = ($exitZero -and $rejected -and $session.QueryActiveProcesses() -eq 0)
        }
        catch {
            $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
        }
        Complete-PspktWorkerLaunch -Launch $launch -PrimaryFailure $primaryFailure -Message (
            'malformed worker result scenario "{0}" primary and cleanup failures.' -f $mutation)
        if (-not $mutationRejected) {
            $allRejected = $false
        }
    }
    return $allRejected
}

function Get-PspktIndexTreeId {
    param(
        [Parameter(Mandatory = $true)]$GitAuthority,
        [Parameter(Mandatory = $true)][string]$ConfigRoot
    )
    $result = Invoke-PspktCheckedGit -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -GitArgs @('write-tree')
    return (Get-PspktGitSingleOid -Result $result)
}

function Remove-PspktResolvedCleanupRoots {
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Roots
    )
    $failures = [System.Collections.Generic.List[Exception]]::new()
    if ($null -ne $Roots) {
        foreach ($root in $Roots) {
            if ([string]::IsNullOrEmpty($root)) { continue }
            try {
                if (Test-Path -LiteralPath $root) {
                    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $root) {
                    throw ('outer cleanup did not remove "{0}".' -f $root)
                }
            }
            catch {
                [void]$failures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    return ,([Exception[]]$failures.ToArray())
}

function Test-PspktBinaryReturnVector {
    $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-binret-'
    try {
        $size = 1179649
        $payload = [byte[]]::new($size)
        for ($index = 0; $index -lt $size; $index += 977) {
            $payload[$index] = [byte]($index % 251)
        }
        $filePath = Join-Path $root ('bin-' + [guid]::NewGuid().ToString('N') + '.dat')
        [System.IO.File]::WriteAllBytes($filePath, $payload)
        $readBytes = Read-PspktBoundedFileBytes -FullPath $filePath -ByteCap ($size + 16)
        return (
            ($readBytes -is [byte[]]) -and
            ($readBytes.GetType().FullName -ceq 'System.Byte[]') -and
            ($readBytes.GetType().FullName -cne 'System.Object[]') -and
            ($readBytes.Length -eq $size) -and
            ($size -gt 1048576))
    }
    finally {
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
        }
    }
}

function Test-PspktGitBlobOidPreimageVectors {
    $emptyBytes = [byte[]]::new(0)
    $helloBytes = [System.Text.Encoding]::ASCII.GetBytes("hello`n")
    $cases = @(
        [pscustomobject]@{ Bytes = $emptyBytes; Oid = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391' },
        [pscustomobject]@{ Bytes = $emptyBytes; Oid = '473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813' },
        [pscustomobject]@{ Bytes = $helloBytes; Oid = 'ce013625030ba8dba906f756967f9e9ca394464a' },
        [pscustomobject]@{ Bytes = $helloBytes; Oid = '2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4' }
    )
    foreach ($case in $cases) {
        $computed = Get-PspktGitBlobOid -Bytes $case.Bytes -ExpectedOid $case.Oid
        if ($computed -cne $case.Oid) { return $false }
    }
    $sha1Empty = Get-PspktGitBlobOid -Bytes $emptyBytes -ExpectedOid 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'
    if ($sha1Empty -ceq '473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813') { return $false }
    if (-not (Test-PspktThrows { Get-PspktGitBlobOid -Bytes $emptyBytes -ExpectedOid 'not-a-valid-object-id' })) { return $false }
    if (-not (Test-PspktThrows { Get-PspktGitBlobOid -Bytes $emptyBytes -ExpectedOid 'E69DE29BB2D1D6434B8B29AE775AD8C2E48C5391' })) { return $false }
    if (-not (Test-PspktThrows { Get-PspktGitBlobOid -Bytes $emptyBytes -ExpectedOid 'e69de29bb2d1d6434b8b29ae775ad8c2e48c539' })) { return $false }
    return $true
}

function Test-PspktOuterCleanupRootsNegativeVectors {
    $removableRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-outerclean-ok-'
    $lockedRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-outerclean-lock-'
    $lockedFile = Join-Path $lockedRoot ('held-' + [guid]::NewGuid().ToString('N') + '.bin')
    $handle = [System.IO.FileStream]::new($lockedFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $ok = $false
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    try {
        $failures = Remove-PspktResolvedCleanupRoots -Roots ([string[]]@($lockedRoot, $removableRoot))
        $emptyFailures = Remove-PspktResolvedCleanupRoots -Roots ([string[]]@())
        $ok = (
            ($failures.Count -ge 1) -and
            (Test-Path -LiteralPath $lockedRoot) -and
            (-not (Test-Path -LiteralPath $removableRoot)) -and
            ($emptyFailures.Count -eq 0))
    }
    finally {
        $handle.Dispose()
        $lockedFailure = Remove-PspktStrictVectorRoot -Root $lockedRoot -Label 'outer-cleanup-roots lockedRoot'
        if ($null -ne $lockedFailure) { [void]$rootCleanupFailures.Add($lockedFailure) }
        $removableFailure = Remove-PspktStrictVectorRoot -Root $removableRoot -Label 'outer-cleanup-roots removableRoot'
        if ($null -ne $removableFailure) { [void]$rootCleanupFailures.Add($removableFailure) }
    }
    if ($rootCleanupFailures.Count -gt 0) { return $false }
    return $ok
}

function Test-PspktDiagnosticsSnapshotClean {
    param([AllowNull()]$Snapshot)
    if ($null -eq $Snapshot) { return $false }
    $properties = $Snapshot.PSObject.Properties
    if ($null -eq $properties['PendingManagedSessionCount'] -or $null -eq $properties['QuarantinedLaunchCount']) {
        return $false
    }
    return (([int]$Snapshot.PendingManagedSessionCount -eq 0) -and ([int]$Snapshot.QuarantinedLaunchCount -eq 0))
}

function Test-PspktDiagnosticsDebtVector {
    param([Parameter(Mandatory = $true)]$Binding)
    $liveSnapshot = Get-PspktDiagnosticsSnapshot -Binding $Binding
    if ($null -eq $liveSnapshot) { return $false }
    $properties = $liveSnapshot.PSObject.Properties
    $presenceOk = (($null -ne $properties['PendingManagedSessionCount']) -and ($null -ne $properties['QuarantinedLaunchCount']))
    $liveClean = Test-PspktDiagnosticsSnapshotClean -Snapshot $liveSnapshot
    $pendingDebt = [pscustomobject]@{ PendingManagedSessionCount = 1; QuarantinedLaunchCount = 0 }
    $quarantineDebt = [pscustomobject]@{ PendingManagedSessionCount = 0; QuarantinedLaunchCount = 2 }
    $pendingDebtRejected = -not (Test-PspktDiagnosticsSnapshotClean -Snapshot $pendingDebt)
    $quarantineDebtRejected = -not (Test-PspktDiagnosticsSnapshotClean -Snapshot $quarantineDebt)
    $nullRejected = -not (Test-PspktDiagnosticsSnapshotClean -Snapshot $null)
    return ($presenceOk -and $liveClean -and $pendingDebtRejected -and $quarantineDebtRejected -and $nullRejected)
}

function Test-PspktStrictVectorRootCleanupVector {
    $registryBaseline = Get-PspktQuarantineRegistrationCount

    $cleanRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-strictroot-clean-'
    $cleanFailure = Remove-PspktStrictVectorRoot -Root $cleanRoot -Label 'strict-root clean probe'
    $cleanOk = (
        ($null -eq $cleanFailure) -and
        (-not (Test-Path -LiteralPath $cleanRoot)) -and
        ((Get-PspktQuarantineRegistrationCount) -eq $registryBaseline))

    $lockedRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-strictroot-lock-'
    $lockedFile = Join-Path $lockedRoot ('held-' + [guid]::NewGuid().ToString('N') + '.bin')
    $handle = [System.IO.FileStream]::new($lockedFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $lockedOk = $false
    try {
        $beforeLocked = Get-PspktQuarantineRegistrationCount
        $lockedFailure = Remove-PspktStrictVectorRoot -Root $lockedRoot -Label 'strict-root locked probe'
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($beforeLocked + 1))
        $lockedRecord = $null
        if ($registered) { $lockedRecord = $script:Phase4QuarantineRegistry[$beforeLocked] }
        $composed = New-PspktComposedFailure -Message 'strict-root locked composition.' -PrimaryFailure ([System.InvalidOperationException]::new('strict-root primary.')) -CleanupFailures ([Exception[]]@($lockedFailure))
        $lockedOk = (
            ($null -ne $lockedFailure) -and
            ($lockedFailure -is [Exception]) -and
            $registered -and
            (Test-Path -LiteralPath $lockedRoot -PathType Container) -and
            ((Get-PspktQuarantineRegistrationCount) -gt 0) -and
            ($null -ne $lockedRecord) -and
            ($lockedRecord.Kind -ceq 'VectorRoot:strict-root locked probe') -and
            ($lockedRecord.Context.TempDirs[0] -ceq $lockedRoot) -and
            ($composed -is [System.AggregateException]))
    }
    finally {
        $handle.Dispose()
        $teardownFailure = Remove-PspktStrictVectorRoot -Root $lockedRoot -Label 'strict-root locked teardown'
        if ($null -eq $teardownFailure -and -not (Test-Path -LiteralPath $lockedRoot)) {
            Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
        }
    }

    $teardownOk = (
        (-not (Test-Path -LiteralPath $lockedRoot)) -and
        ((Get-PspktQuarantineRegistrationCount) -eq $registryBaseline))

    return ($cleanOk -and $lockedOk -and $teardownOk)
}

function Test-PspktComposedFailureSiblingVectors {
    $siblingOne = [System.IO.IOException]::new('composed sibling one.')
    $siblingTwo = [System.InvalidOperationException]::new('composed sibling two.')
    $composed = New-PspktComposedFailure -Message 'two-sibling composition.' -PrimaryFailure $null -CleanupFailures ([Exception[]]@($siblingOne, $siblingTwo))
    if ($composed -isnot [System.AggregateException]) { return $false }
    $messages = [string[]]($composed.InnerExceptions | ForEach-Object { $_.Message })
    if ($messages -notcontains 'composed sibling one.' -or $messages -notcontains 'composed sibling two.') { return $false }
    $nested = [System.AggregateException]::new('nested pair.', [Exception[]]@(
            [System.IO.IOException]::new('nested sibling A.'),
            [System.InvalidOperationException]::new('nested sibling B.')))
    $primary = [System.InvalidOperationException]::new('composed primary.')
    $composedTwo = New-PspktComposedFailure -Message 'primary plus nested aggregate.' -PrimaryFailure $primary -CleanupFailures ([Exception[]]@($nested))
    if ($composedTwo -isnot [System.AggregateException]) { return $false }
    $messagesTwo = [string[]]($composedTwo.InnerExceptions | ForEach-Object { $_.Message })
    if ($messagesTwo -notcontains 'composed primary.' -or
        $messagesTwo -notcontains 'nested sibling A.' -or
        $messagesTwo -notcontains 'nested sibling B.') { return $false }
    foreach ($inner in $composedTwo.InnerExceptions) {
        if ($inner -is [System.AggregateException]) { return $false }
    }
    return $true
}

function Test-PspktExceptionTreeDetectionVectors {
    $quarantineTypeName = 'Pspkt.Certification.ContainedLaunchOwnershipQuarantinedException'
    $leaf = [System.IO.FileNotFoundException]::new('detection leaf.')
    $aggregate = [System.AggregateException]::new('detection aggregate.', [Exception[]]@(
            [System.InvalidOperationException]::new('detection first sibling.'),
            $leaf))
    $wrapper = [System.Exception]::new('detection wrapper.', $aggregate)
    if (-not (Test-PspktExceptionTreeContainsType -Exception $wrapper -FullTypeName 'System.IO.FileNotFoundException')) { return $false }
    if (-not (Test-PspktExceptionTreeContainsType -Exception $wrapper -FullTypeName 'System.InvalidOperationException')) { return $false }
    if (Test-PspktExceptionTreeContainsType -Exception $wrapper -FullTypeName $quarantineTypeName) { return $false }
    if (Test-PspktExceptionTreeContainsType -Exception $leaf -FullTypeName 'System.InvalidOperationException') { return $false }
    $innermost = Get-PspktInnermostException -Exception $wrapper
    if ($innermost -isnot [System.AggregateException]) { return $false }
    return $true
}

function Test-PspktWorkerLaunchQuarantineVectors {
    $probeBinding = [pscustomobject]@{ Path = ''; Digest = ''; Version = '' }
    $quarantineRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-wquar-'
    $quarantinedOk = $false
    try {
        $quarantineContext = New-PspktReservedContext -SnapshotRoot $quarantineRoot -RepositoryRoot $repositoryRoot -Binding $probeBinding
        [void]$quarantineContext.TempDirs.Add($quarantineRoot)
        $quarantineFailures = Clear-PspktReservedContext -Context $quarantineContext -OwnershipClean $false
        $quarantinedOk = (
            $quarantineContext.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $quarantineRoot -PathType Container) -and
            $quarantineFailures.Count -ge 1)
    }
    finally {
        if (Test-Path -LiteralPath $quarantineRoot) {
            Remove-Item -LiteralPath $quarantineRoot -Recurse -Force -ErrorAction Stop
        }
    }
    $cleanRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-wclean-'
    $cleanOk = $false
    $cleanRootFailure = $null
    try {
        $cleanContext = New-PspktReservedContext -SnapshotRoot $cleanRoot -RepositoryRoot $repositoryRoot -Binding $probeBinding
        [void]$cleanContext.TempDirs.Add($cleanRoot)
        $cleanFailures = Clear-PspktReservedContext -Context $cleanContext -OwnershipClean $true
        $cleanOk = (
            $cleanContext.CleanupState -ceq 'Cleaned' -and
            (-not (Test-Path -LiteralPath $cleanRoot)) -and
            $cleanFailures.Count -eq 0)
    }
    finally {
        $cleanRootFailure = Remove-PspktStrictVectorRoot -Root $cleanRoot -Label 'worker-launch-quarantine cleanRoot'
    }
    return ($quarantinedOk -and $cleanOk -and ($null -eq $cleanRootFailure))
}

function New-PspktGeneratorCleanupProbeContext {
    param([Parameter(Mandatory = $true)][string]$Root)
    $tempDirectories = [System.Collections.Generic.List[string]]::new()
    [void]$tempDirectories.Add($Root)
    return [pscustomobject]@{
        GeneratorEvents = @{}
        GeneratorHardlinkStreams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
        GeneratorSourceStream = $null
        OwnedEvents = [System.Collections.Generic.List[object]]::new()
        TempDirs = $tempDirectories
        CleanupState = 'Pending'
    }
}

function Test-PspktGeneratorCleanupNegativeVectors {
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $failingSessionRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-genclean-sess-'
    $failingSessionOk = $false
    try {
        $context = New-PspktGeneratorCleanupProbeContext -Root $failingSessionRoot
        $authorityCloseState = [pscustomobject]@{ Called = $false }
        $authorityEvent = [pscustomobject]@{ State = $authorityCloseState }
        $authorityEvent | Add-Member -MemberType ScriptMethod -Name Close -Value {
            $this.State.Called = $true
        }
        $context.GeneratorEvents['authority'] = $authorityEvent
        $failingSession = [pscustomobject]@{ DisposeSucceeded = $false; State = 'Released' }
        $failingSession | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
            throw [System.IO.IOException]::new('injected generator dispose failure.')
        }
        $failingSession | Add-Member -MemberType ScriptMethod -Name GetDisposeErrors -Value {
            return [Exception[]]@([System.IO.IOException]::new('recorded generator cleanup failure.'))
        }
        $launch = [pscustomobject]@{ Session = $failingSession; Context = $context }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $failures = Close-PspktGeneratorLaunch -Launch $launch
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $composed = New-PspktComposedFailure -Message 'injected generator aggregate.' -PrimaryFailure ([System.InvalidOperationException]::new('injected generator primary failure.')) -CleanupFailures $failures
        $messages = @()
        if ($composed -is [System.AggregateException]) {
            $messages = [string[]]($composed.InnerExceptions | ForEach-Object { $_.Message })
        }
        $failingSessionOk = (
            $registered -and
            $context.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $failingSessionRoot -PathType Container) -and
            -not $authorityCloseState.Called -and
            $messages -contains 'injected generator primary failure.' -and
            $messages -contains 'injected generator dispose failure.' -and
            $messages -contains 'recorded generator cleanup failure.')
    }
    finally {
        if (Test-Path -LiteralPath $failingSessionRoot) {
            Remove-Item -LiteralPath $failingSessionRoot -Recurse -Force -ErrorAction Stop
        }
    }

    $snapshotOrderRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-genclean-snap-'
    $snapshotOrderOk = $false
    try {
        $context = New-PspktGeneratorCleanupProbeContext -Root $snapshotOrderRoot
        $authorityCloseState = [pscustomobject]@{ Called = $false }
        $authorityEvent = [pscustomobject]@{ State = $authorityCloseState }
        $authorityEvent | Add-Member -MemberType ScriptMethod -Name Close -Value {
            $this.State.Called = $true
        }
        $context.GeneratorEvents['authority'] = $authorityEvent
        $disposeFlag = [pscustomobject]@{ Called = $false }
        $cleanSession = [pscustomobject]@{ DisposeSucceeded = $true; State = 'Cleaned'; Flag = $disposeFlag }
        $cleanSession | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
            $this.Flag.Called = $true
        }
        $cleanSession | Add-Member -MemberType ScriptMethod -Name GetDisposeErrors -Value {
            return [Exception[]]@()
        }
        $failingSnapshot = [pscustomobject]@{ DisposeSucceeded = $false }
        $failingSnapshot | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
            throw [System.IO.IOException]::new('injected generator snapshot dispose failure.')
        }
        $failingSnapshot | Add-Member -MemberType ScriptMethod -Name GetCloseErrors -Value {
            return [Exception[]]@()
        }
        $launch = [pscustomobject]@{ Session = $cleanSession; Context = $context }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $failures = Close-PspktGeneratorLaunch -Launch $launch -Snapshots ([object[]]@($failingSnapshot))
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $messages = [string[]]($failures | ForEach-Object { $_.Message })
        $snapshotOrderOk = (
            $registered -and
            $disposeFlag.Called -and
            $authorityCloseState.Called -and
            $context.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $snapshotOrderRoot -PathType Container) -and
            $messages -contains 'injected generator snapshot dispose failure.')
    }
    finally {
        if (Test-Path -LiteralPath $snapshotOrderRoot) {
            Remove-Item -LiteralPath $snapshotOrderRoot -Recurse -Force -ErrorAction Stop
        }
    }

    $partialQuarantineRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-genclean-part-'
    $partialQuarantineOk = $false
    try {
        $context = New-PspktGeneratorCleanupProbeContext -Root $partialQuarantineRoot
        $launch = [pscustomobject]@{ Session = $null; Context = $context }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $failures = Close-PspktGeneratorLaunch -Launch $launch -OwnershipClean $false
        $partialQuarantineOk = (
            ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1)) -and
            $context.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $partialQuarantineRoot -PathType Container) -and
            $failures.Count -ge 1)
    }
    finally {
        if (Test-Path -LiteralPath $partialQuarantineRoot) {
            Remove-Item -LiteralPath $partialQuarantineRoot -Recurse -Force -ErrorAction Stop
        }
    }

    $cleanRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-genclean-clean-'
    $context = New-PspktGeneratorCleanupProbeContext -Root $cleanRoot
    $launch = [pscustomobject]@{ Session = $null; Context = $context }
    $countBefore = Get-PspktQuarantineRegistrationCount
    $failures = Close-PspktGeneratorLaunch -Launch $launch -OwnershipClean $true
    $cleanOk = (
        $context.CleanupState -ceq 'Cleaned' -and
        (-not (Test-Path -LiteralPath $cleanRoot)) -and
        $failures.Count -eq 0 -and
        ((Get-PspktQuarantineRegistrationCount) -eq $countBefore))
    $cleanRootFailure = Remove-PspktStrictVectorRoot -Root $cleanRoot -Label 'generator-cleanup cleanRoot'

    Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
    return ($failingSessionOk -and $snapshotOrderOk -and $partialQuarantineOk -and $cleanOk -and ($null -eq $cleanRootFailure))
}

function Test-PspktQuarantineRegistryVectors {
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $rootedOk = $false
    $notRegisteredOk = $false
    $capacityOk = $false
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()

    $rootedRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-quarreg-rooted-'
    try {
        $rootedProbe = & {
            $context = New-PspktGeneratorCleanupProbeContext -Root $rootedRoot
            $heldStream = [System.IO.MemoryStream]::new()
            [void]$context.OwnedEvents.Add($heldStream)
            $failingSession = [pscustomobject]@{ DisposeSucceeded = $false; State = 'Released' }
            $failingSession | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
                throw [System.IO.IOException]::new('quarantine registry probe dispose failure.')
            }
            $failingSession | Add-Member -MemberType ScriptMethod -Name GetDisposeErrors -Value {
                return [Exception[]]@()
            }
            $launch = [pscustomobject]@{ Session = $failingSession; Context = $context }
            $snapshotObject = [pscustomobject]@{ Marker = 'quarantine-registry-snapshot' }
            $countBefore = Get-PspktQuarantineRegistrationCount
            [void](Close-PspktGeneratorLaunch -Launch $launch -Snapshots ([object[]]@($snapshotObject)))
            [pscustomobject]@{
                RegistrationIndex = $countBefore
                RegisteredDelta = ((Get-PspktQuarantineRegistrationCount) - $countBefore)
                QuarantineState = [string]$context.CleanupState
                WeakLaunch = [System.WeakReference]::new($launch)
                WeakContext = [System.WeakReference]::new($context)
                WeakSession = [System.WeakReference]::new($failingSession)
                WeakStream = [System.WeakReference]::new($heldStream)
                WeakSnapshot = [System.WeakReference]::new($snapshotObject)
            }
        }
        [System.GC]::Collect()
        $registeredRecord = $script:Phase4QuarantineRegistry[$rootedProbe.RegistrationIndex]
        $rootedOk = (
            ($rootedProbe.RegisteredDelta -eq 1) -and
            ($rootedProbe.QuarantineState -ceq 'Quarantined') -and
            $rootedProbe.WeakLaunch.IsAlive -and
            $rootedProbe.WeakContext.IsAlive -and
            $rootedProbe.WeakSession.IsAlive -and
            $rootedProbe.WeakStream.IsAlive -and
            $rootedProbe.WeakSnapshot.IsAlive -and
            [object]::ReferenceEquals($registeredRecord.Launch, $rootedProbe.WeakLaunch.Target) -and
            [object]::ReferenceEquals($registeredRecord.Context, $rootedProbe.WeakContext.Target) -and
            [object]::ReferenceEquals($registeredRecord.Launch.Session, $rootedProbe.WeakSession.Target) -and
            [object]::ReferenceEquals($registeredRecord.Context.OwnedEvents[0], $rootedProbe.WeakStream.Target) -and
            [object]::ReferenceEquals($registeredRecord.Snapshots[0], $rootedProbe.WeakSnapshot.Target))
    }
    finally {
        for ($recordIndex = $registryBaseline; $recordIndex -lt $script:Phase4QuarantineRegistry.Count; $recordIndex++) {
            $record = $script:Phase4QuarantineRegistry[$recordIndex]
            if ($null -ne $record.Context) {
                foreach ($ownedAuthority in $record.Context.OwnedEvents) {
                    if ($ownedAuthority -is [System.IDisposable]) {
                        try { $ownedAuthority.Dispose() } catch { $null = $_ }
                    }
                }
            }
        }
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
        $rootedRootFailure = Remove-PspktStrictVectorRoot -Root $rootedRoot -Label 'quarantine-registry rootedRoot'
        if ($null -ne $rootedRootFailure) { [void]$rootCleanupFailures.Add($rootedRootFailure) }
    }

    $cleanRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-quarreg-clean-'
    try {
        $cleanContext = New-PspktGeneratorCleanupProbeContext -Root $cleanRoot
        $cleanLaunch = [pscustomobject]@{ Session = $null; Context = $cleanContext }
        $countBefore = Get-PspktQuarantineRegistrationCount
        [void](Close-PspktGeneratorLaunch -Launch $cleanLaunch -OwnershipClean $true)
        $notRegisteredOk = (
            ((Get-PspktQuarantineRegistrationCount) -eq $countBefore) -and
            $cleanContext.CleanupState -ceq 'Cleaned')
    }
    finally {
        $cleanRootFailure = Remove-PspktStrictVectorRoot -Root $cleanRoot -Label 'quarantine-registry cleanRoot'
        if ($null -ne $cleanRootFailure) { [void]$rootCleanupFailures.Add($cleanRootFailure) }
    }

    $capacityBaseline = Get-PspktQuarantineRegistrationCount
    $emergencyRecord = $null
    try {
        $fillKinds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $fillRecords = [System.Collections.Generic.HashSet[object]]::new()
        $fillIndex = 0
        while ($script:Phase4QuarantineRegistry.Count -lt $script:Phase4QuarantineRegistryCapacity) {
            $fillContext = [pscustomobject]@{ CleanupState = 'Quarantined'; FillMarker = $fillIndex }
            $fillLaunch = [pscustomobject]@{ Session = [pscustomobject]@{ FillSession = $fillIndex }; Context = $fillContext }
            $fillRecord = Add-PspktQuarantineRegistration -Kind ('RegistryCapacityProbe-' + $fillIndex.ToString([System.Globalization.CultureInfo]::InvariantCulture)) -Launch $fillLaunch -Snapshots ([object[]]@([pscustomobject]@{ FillSnapshot = $fillIndex }))
            [void]$fillKinds.Add([string]$fillRecord.Kind)
            [void]$fillRecords.Add($fillRecord)
            $fillIndex++
        }
        $distinctFilled = $script:Phase4QuarantineRegistry.Count - $capacityBaseline
        $fillOk = (
            ($script:Phase4QuarantineRegistry.Count -eq $script:Phase4QuarantineRegistryCapacity) -and
            ($fillKinds.Count -eq $distinctFilled) -and
            ($fillRecords.Count -eq $distinctFilled) -and
            ($distinctFilled -gt 0) -and
            ($null -eq $script:Phase4QuarantineEmergencySlot))

        $overflowProbe = & {
            $overflowContext = [pscustomobject]@{
                CleanupState = 'Quarantined'
                OwnedEvents = [System.Collections.Generic.List[object]]::new()
                OverflowMarker = [guid]::NewGuid().ToString('N')
            }
            $overflowStream = [System.IO.MemoryStream]::new()
            [void]$overflowContext.OwnedEvents.Add($overflowStream)
            $overflowSession = [pscustomobject]@{ OverflowSession = [guid]::NewGuid().ToString('N') }
            $overflowLaunch = [pscustomobject]@{ Session = $overflowSession; Context = $overflowContext }
            $overflowSnapshot = [pscustomobject]@{ OverflowSnapshot = [guid]::NewGuid().ToString('N') }
            $threw = $false
            $messageMatched = $false
            try {
                [void](Add-PspktQuarantineRegistration -Kind 'RegistryOverflowProbe' -Launch $overflowLaunch -Snapshots ([object[]]@($overflowSnapshot)))
            }
            catch [System.InvalidOperationException] {
                $threw = $true
                $messageMatched = ([string]$_.Exception.Message -match 'emergency ownership slot')
            }
            [pscustomobject]@{
                Threw = $threw
                MessageMatched = $messageMatched
                WeakLaunch = [System.WeakReference]::new($overflowLaunch)
                WeakContext = [System.WeakReference]::new($overflowContext)
                WeakSession = [System.WeakReference]::new($overflowSession)
                WeakSnapshot = [System.WeakReference]::new($overflowSnapshot)
                WeakStream = [System.WeakReference]::new($overflowStream)
            }
        }
        $emergencyRecord = $script:Phase4QuarantineEmergencySlot
        $overflowRetainedOk = (
            $overflowProbe.Threw -and
            $overflowProbe.MessageMatched -and
            ($null -ne $emergencyRecord) -and
            ($emergencyRecord.Kind -ceq 'RegistryOverflowProbe') -and
            (Test-PspktQuarantineLaunchBlocked) -and
            ($script:Phase4QuarantineRegistry.Count -eq $script:Phase4QuarantineRegistryCapacity))

        [System.GC]::Collect()
        $emergencyRootedOk = (
            ($null -ne $emergencyRecord) -and
            $overflowProbe.WeakLaunch.IsAlive -and
            $overflowProbe.WeakContext.IsAlive -and
            $overflowProbe.WeakSession.IsAlive -and
            $overflowProbe.WeakSnapshot.IsAlive -and
            $overflowProbe.WeakStream.IsAlive -and
            [object]::ReferenceEquals($emergencyRecord.Launch, $overflowProbe.WeakLaunch.Target) -and
            [object]::ReferenceEquals($emergencyRecord.Context, $overflowProbe.WeakContext.Target) -and
            [object]::ReferenceEquals($emergencyRecord.Launch.Session, $overflowProbe.WeakSession.Target) -and
            [object]::ReferenceEquals($emergencyRecord.Snapshots[0], $overflowProbe.WeakSnapshot.Target) -and
            [object]::ReferenceEquals($emergencyRecord.Context.OwnedEvents[0], $overflowProbe.WeakStream.Target) -and
            ((Get-PspktQuarantineRegistrationCount) -eq ($script:Phase4QuarantineRegistryCapacity + 1)))

        $oracleAdmission = & {
            $threw = $false
            $messageMatched = $false
            $returned = $null
            try {
                $returned = New-PspktProcessOracleContext -Tag 'emergency-admission-probe'
            }
            catch [System.InvalidOperationException] {
                $threw = $true
                $messageMatched = ([string]$_.Exception.Message -match 'admission is refused')
            }
            [pscustomobject]@{ Threw = $threw; MessageMatched = $messageMatched; Returned = $returned }
        }
        $oracleAdmissionOk = (
            $oracleAdmission.Threw -and
            $oracleAdmission.MessageMatched -and
            ($null -eq $oracleAdmission.Returned) -and
            [object]::ReferenceEquals($script:Phase4QuarantineEmergencySlot, $emergencyRecord) -and
            ($script:Phase4QuarantineRegistry.Count -eq $script:Phase4QuarantineRegistryCapacity))

        $reservedAdmission = & {
            $threw = $false
            $messageMatched = $false
            $returned = $null
            try {
                $returned = New-PspktReservedContext -SnapshotRoot 'admission-probe-snapshot' -RepositoryRoot 'admission-probe-repo' -Binding ([pscustomobject]@{ Path = ''; Digest = ''; Version = '' })
            }
            catch [System.InvalidOperationException] {
                $threw = $true
                $messageMatched = ([string]$_.Exception.Message -match 'admission is refused')
            }
            [pscustomobject]@{ Threw = $threw; MessageMatched = $messageMatched; Returned = $returned }
        }
        $reservedAdmissionOk = (
            $reservedAdmission.Threw -and
            $reservedAdmission.MessageMatched -and
            ($null -eq $reservedAdmission.Returned) -and
            [object]::ReferenceEquals($script:Phase4QuarantineEmergencySlot, $emergencyRecord) -and
            ($script:Phase4QuarantineRegistry.Count -eq $script:Phase4QuarantineRegistryCapacity))

        $doubleOverflow = & {
            $secondContext = [pscustomobject]@{ CleanupState = 'Quarantined'; SecondOverflowMarker = [guid]::NewGuid().ToString('N') }
            $secondLaunch = [pscustomobject]@{ Session = $null; Context = $secondContext }
            $threw = $false
            $fatalMatched = $false
            try {
                [void](Add-PspktQuarantineRegistration -Kind 'RegistrySecondOverflowProbe' -Launch $secondLaunch -Snapshots @())
            }
            catch [System.InvalidOperationException] {
                $threw = $true
                $fatalMatched = ([string]$_.Exception.Message -match 'fatal admission-guard invariant violation')
            }
            [pscustomobject]@{ Threw = $threw; FatalMatched = $fatalMatched }
        }
        $doubleOverflowFatalOk = (
            $doubleOverflow.Threw -and
            $doubleOverflow.FatalMatched -and
            ($null -ne $script:Phase4QuarantineEmergencySlot) -and
            [object]::ReferenceEquals($script:Phase4QuarantineEmergencySlot, $emergencyRecord) -and
            ($script:Phase4QuarantineRegistry.Count -eq $script:Phase4QuarantineRegistryCapacity))

        Reset-PspktQuarantineRegistryTo -RetainedCount $capacityBaseline
        $listTrimmedToBaseline = ($script:Phase4QuarantineRegistry.Count -eq $capacityBaseline)
        $emergencyStillHeldBeforeReset = [object]::ReferenceEquals($script:Phase4QuarantineEmergencySlot, $emergencyRecord)
        $emergencyClearedByProof = $false
        if ($null -ne $emergencyRecord) {
            $emergencyClearedByProof = Reset-PspktQuarantineEmergencySlotForProvenClean -Record $emergencyRecord
        }
        $overflowStreamDisposed = $false
        $streamTarget = $overflowProbe.WeakStream.Target
        if ($null -ne $streamTarget) {
            $overflowStreamDisposed = ((-not $streamTarget.CanRead) -and (-not $streamTarget.CanWrite))
        }
        elseif (-not $overflowProbe.WeakStream.IsAlive) {
            $overflowStreamDisposed = $true
        }
        $teardownOk = (
            $listTrimmedToBaseline -and
            $emergencyStillHeldBeforeReset -and
            $emergencyClearedByProof -and
            $overflowStreamDisposed -and
            ($null -eq $script:Phase4QuarantineEmergencySlot) -and
            ((Get-PspktQuarantineRegistrationCount) -eq $capacityBaseline))

        $capacityOk = (
            $fillOk -and $overflowRetainedOk -and $emergencyRootedOk -and
            $oracleAdmissionOk -and $reservedAdmissionOk -and $doubleOverflowFatalOk -and $teardownOk -and
            ($script:Phase4QuarantineRegistryCapacity -ge ($script:WorkerScenarioInventory.Count + $script:WorkerResultMutationInventory.Count + $script:GeneratorScenarioInventory.Count)))
    }
    finally {
        Reset-PspktQuarantineRegistryTo -RetainedCount $capacityBaseline
        if ($null -ne $emergencyRecord) {
            [void](Reset-PspktQuarantineEmergencySlotForProvenClean -Record $emergencyRecord)
        }
    }

    return ($rootedOk -and $notRegisteredOk -and $capacityOk -and ($rootCleanupFailures.Count -eq 0))
}

function Test-PspktSnapshotTreeCleanupVectors {
    param(
        [AllowNull()]$GitAuthority = $null,
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ConfigRoot = $null
    )
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()

    $removableRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-snaptree-remove-'
    $removableFirst = Join-Path $removableRoot 'first-blob.bin'
    [System.IO.File]::WriteAllBytes($removableFirst, [byte[]](1, 2, 3, 4))
    $secondFault = [System.IO.IOException]::new('injected second-blob read/write failure.')
    $removableComposed = Complete-PspktSnapshotTreeFailure -Root $removableRoot -PrimaryFailure $secondFault
    $removableOk = (
        ($removableComposed -is [Exception]) -and
        ($removableComposed -isnot [System.AggregateException]) -and
        [object]::ReferenceEquals($removableComposed, $secondFault) -and
        (-not (Test-Path -LiteralPath $removableFirst)) -and
        (-not (Test-Path -LiteralPath $removableRoot)) -and
        ((Get-PspktQuarantineRegistrationCount) -eq $registryBaseline))

    $lockedRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-snaptree-lock-'
    $lockedFirst = Join-Path $lockedRoot 'first-blob.bin'
    [System.IO.File]::WriteAllBytes($lockedFirst, [byte[]](5, 6, 7, 8))
    $lockedHeld = Join-Path $lockedRoot ('held-' + [guid]::NewGuid().ToString('N') + '.bin')
    $handle = [System.IO.FileStream]::new($lockedHeld, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $lockedOk = $false
    try {
        $beforeLocked = Get-PspktQuarantineRegistrationCount
        $primary = [System.InvalidOperationException]::new('injected snapshot-tree primary failure.')
        $lockedComposed = Complete-PspktSnapshotTreeFailure -Root $lockedRoot -PrimaryFailure $primary
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($beforeLocked + 1))
        $lockedRecord = $null
        if ($registered) { $lockedRecord = $script:Phase4QuarantineRegistry[$beforeLocked] }
        $messages = @()
        if ($lockedComposed -is [System.AggregateException]) {
            $messages = [string[]]($lockedComposed.InnerExceptions | ForEach-Object { $_.Message })
        }
        $lockedOk = (
            $registered -and
            ($lockedComposed -is [System.AggregateException]) -and
            (Test-Path -LiteralPath $lockedRoot -PathType Container) -and
            (Test-Path -LiteralPath $lockedHeld) -and
            ((Get-PspktQuarantineRegistrationCount) -gt 0) -and
            ($null -ne $lockedRecord) -and
            ($lockedRecord.Kind -ceq 'VectorRoot:snapshot-tree partial root') -and
            ($lockedRecord.Context.TempDirs[0] -ceq $lockedRoot) -and
            ($messages -contains 'injected snapshot-tree primary failure.'))
    }
    finally {
        $handle.Dispose()
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
        $lockedFailure = Remove-PspktStrictVectorRoot -Root $lockedRoot -Label 'snapshot-tree locked teardown'
        if ($null -ne $lockedFailure) { [void]$rootCleanupFailures.Add($lockedFailure) }
        $removableTeardownFailure = Remove-PspktStrictVectorRoot -Root $removableRoot -Label 'snapshot-tree removable teardown'
        if ($null -ne $removableTeardownFailure) { [void]$rootCleanupFailures.Add($removableTeardownFailure) }
    }

    $tempBase = [System.IO.Path]::GetTempPath()
    $before = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($existing in [System.IO.Directory]::GetDirectories($tempBase, 'pspkt-phase4-snapshot-*')) {
        [void]$before.Add($existing)
    }
    $fakeAuthority = [pscustomobject]@{
        GitBinding = ([pscustomobject]@{ Stream = $null; Path = 'C:\pspkt-phase4-nonexistent-git.exe' })
        RepositoryRoot = 'C:\pspkt-phase4-nonexistent-repo'
    }
    $wiringThrew = $false
    try {
        [void](New-PspktSnapshotTree -GitAuthority $fakeAuthority -ConfigRoot 'C:\pspkt-phase4-nonexistent-config' -IndexOidByPath @{ 'a' = ('0' * 40) } -Paths @('a'))
    }
    catch {
        $wiringThrew = $true
    }
    $wiringLeaked = $false
    foreach ($candidate in [System.IO.Directory]::GetDirectories($tempBase, 'pspkt-phase4-snapshot-*')) {
        if (-not $before.Contains($candidate)) {
            $wiringLeaked = $true
            $wiringRootFailure = Remove-PspktStrictVectorRoot -Root $candidate -Label 'snapshot-tree wiring leak teardown'
            if ($null -ne $wiringRootFailure) { [void]$rootCleanupFailures.Add($wiringRootFailure) }
        }
    }
    $wiringOk = ($wiringThrew -and -not $wiringLeaked)

    $corruptionOk = $true
    if ($null -ne $GitAuthority -and -not [string]::IsNullOrEmpty($ConfigRoot)) {
        $corruptionOk = $false
        $seamPath = $script:ExpectedSlicePaths[0]
        $seamIndexMap = Get-PspktIndexStageMap -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -Paths @($seamPath)
        $corruptBefore = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($existing in [System.IO.Directory]::GetDirectories($tempBase, 'pspkt-phase4-snapshot-*')) {
            [void]$corruptBefore.Add($existing)
        }
        $corruptThrew = $false
        $corruptDigestMismatch = $false
        $corruptManifest = $null
        $script:SnapshotCorruptionSeam = {
            param($bytes, $relPath)
            $mutated = [byte[]]::new($bytes.Length)
            [System.Array]::Copy($bytes, 0, $mutated, 0, $bytes.Length)
            if ($mutated.Length -gt 0) {
                $mutated[$mutated.Length - 1] = [byte]($mutated[$mutated.Length - 1] -bxor 0xff)
            }
            return ,([byte[]]$mutated)
        }
        try {
            $corruptManifest = New-PspktSnapshotTree -GitAuthority $GitAuthority -ConfigRoot $ConfigRoot -IndexOidByPath $seamIndexMap -Paths @($seamPath)
        }
        catch {
            $corruptThrew = $true
            $corruptInner = Get-PspktInnermostException -Exception $_.Exception
            if ($corruptInner -is [System.AggregateException]) {
                foreach ($corruptLeaf in ([System.AggregateException]$corruptInner).InnerExceptions) {
                    if ($null -ne $corruptLeaf -and $corruptLeaf.Message -like 'snapshot: materialized digest * does not equal the OID-verified source digest *') {
                        $corruptDigestMismatch = $true
                    }
                }
            }
            elseif ($corruptInner.Message -like 'snapshot: materialized digest * does not equal the OID-verified source digest *') {
                $corruptDigestMismatch = $true
            }
        }
        finally {
            $script:SnapshotCorruptionSeam = $null
        }
        $corruptLeaked = $false
        foreach ($candidate in [System.IO.Directory]::GetDirectories($tempBase, 'pspkt-phase4-snapshot-*')) {
            if (-not $corruptBefore.Contains($candidate)) {
                $corruptLeaked = $true
                $corruptRootFailure = Remove-PspktStrictVectorRoot -Root $candidate -Label 'snapshot-tree corruption leak teardown'
                if ($null -ne $corruptRootFailure) { [void]$rootCleanupFailures.Add($corruptRootFailure) }
            }
        }
        $corruptionOk = ($corruptThrew -and $corruptDigestMismatch -and (-not $corruptLeaked) -and ($null -eq $corruptManifest))
    }

    return ($removableOk -and $lockedOk -and $wiringOk -and $corruptionOk -and ($rootCleanupFailures.Count -eq 0))
}

function Invoke-PspktObserverStallProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][int]$JoinBoundMs,
        [Parameter(Mandatory = $true)][scriptblock]$CreateProbe
    )
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $contextRoot = New-PspktTempDirectory -Prefix ('pspkt-phase4-obsstall-' + $Kind.ToLowerInvariant() + '-')
    $authorityHandles = [System.Collections.Generic.List[object]]::new()
    [void]$authorityHandles.Add([System.Threading.ManualResetEvent]::new($false))
    [void]$authorityHandles.Add([System.Threading.ManualResetEvent]::new($false))
    $oracleContext = [pscustomobject]@{ Root = $contextRoot }
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    $stallOk = $false
    $normalOk = $false
    $gcRootOk = $false
    $upperBoundMs = $JoinBoundMs + 5000
    try {
        $observer = & $CreateProbe $JoinBoundMs
        $observer.Start()
        $usableBefore = $observer.StallHandlesUsable()
        $disposeThrew = $false
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try { $observer.Dispose() } catch { $disposeThrew = $true }
        $stopwatch.Stop()
        $usableAfter = $observer.StallHandlesUsable()

        $countBefore = Get-PspktQuarantineRegistrationCount
        $record = Add-PspktObserverQuarantineRegistration -Kind ('Stall:' + $Kind) -Observer $observer -AuthorityHandles ([object[]]$authorityHandles.ToArray()) -OracleContext $oracleContext
        $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $recordRootsObserver = (
            $null -ne $record -and
            [object]::ReferenceEquals($record.Launch.Session, $observer) -and
            [object]::ReferenceEquals($record.Snapshots[0], $observer) -and
            [object]::ReferenceEquals($record.Context.Observer, $observer))
        $recordRootsHandles = ($null -ne $record -and $record.Context.OwnedEvents.Count -eq $authorityHandles.Count)
        $recordRootsContext = ($null -ne $record -and [object]::ReferenceEquals($record.Context.OracleContext, $oracleContext))
        $debtObserved = ((Get-PspktQuarantineRegistrationCount) -gt 0)

        $observer.ReleaseCertificationStall()
        $joinedAfterRelease = $observer.Join($upperBoundMs)
        $noWorkerFault = ($null -eq $observer.Exception)

        $secondDisposeThrew = $false
        try { $observer.Dispose() } catch { $secondDisposeThrew = $true }
        $usableAfterClose = $observer.StallHandlesUsable()
        $thirdDisposeThrew = $false
        try { $observer.Dispose() } catch { $thirdDisposeThrew = $true }

        $stallOk = (
            $usableBefore -and
            $disposeThrew -and
            ($stopwatch.ElapsedMilliseconds -lt $upperBoundMs) -and
            $usableAfter -and
            $registered -and $recordRootsObserver -and $recordRootsHandles -and $recordRootsContext -and $debtObserved -and
            $joinedAfterRelease -and $noWorkerFault -and
            (-not $secondDisposeThrew) -and (-not $usableAfterClose) -and (-not $thirdDisposeThrew))

        $normalObserver = & $CreateProbe $JoinBoundMs
        $normalObserver.Start()
        $normalObserver.ReleaseCertificationStall()
        $normalJoined = $normalObserver.Join($upperBoundMs)
        $normalDisposeThrew = $false
        try { $normalObserver.Dispose() } catch { $normalDisposeThrew = $true }
        $normalUsableAfter = $normalObserver.StallHandlesUsable()
        $normalIdempotentThrew = $false
        try { $normalObserver.Dispose() } catch { $normalIdempotentThrew = $true }
        $normalOk = (
            $normalJoined -and
            (-not $normalDisposeThrew) -and
            (-not $normalUsableAfter) -and
            (-not $normalIdempotentThrew) -and
            ($null -eq $normalObserver.Exception))

        $gcProbe = & {
            $scopedRoot = New-PspktTempDirectory -Prefix ('pspkt-phase4-obsstallgc-' + $Kind.ToLowerInvariant() + '-')
            $scopedContext = [pscustomobject]@{ Root = $scopedRoot }
            $scopedHandle = [System.Threading.ManualResetEvent]::new($false)
            $scopedObserver = & $CreateProbe $JoinBoundMs
            $scopedObserver.Start()
            try { $scopedObserver.Dispose() } catch { $null = $_ }
            $scopedIndex = Get-PspktQuarantineRegistrationCount
            [void](Add-PspktObserverQuarantineRegistration -Kind ('StallGc:' + $Kind) -Observer $scopedObserver -AuthorityHandles ([object[]]@($scopedHandle)) -OracleContext $scopedContext)
            $scopedObserver.ReleaseCertificationStall()
            [void]$scopedObserver.Join($upperBoundMs)
            try { $scopedObserver.Dispose() } catch { $null = $_ }
            [pscustomobject]@{
                RegistrationIndex = $scopedIndex
                ScopedRoot = $scopedRoot
                WeakObserver = [System.WeakReference]::new($scopedObserver)
                WeakContext = [System.WeakReference]::new($scopedContext)
                WeakHandle = [System.WeakReference]::new($scopedHandle)
            }
        }
        [System.GC]::Collect()
        $gcRecord = $script:Phase4QuarantineRegistry[$gcProbe.RegistrationIndex]
        $gcRootOk = (
            $gcProbe.WeakObserver.IsAlive -and
            $gcProbe.WeakContext.IsAlive -and
            $gcProbe.WeakHandle.IsAlive -and
            [object]::ReferenceEquals($gcRecord.Launch.Session, $gcProbe.WeakObserver.Target) -and
            [object]::ReferenceEquals($gcRecord.Context.OracleContext, $gcProbe.WeakContext.Target) -and
            [object]::ReferenceEquals($gcRecord.Context.OwnedEvents[0], $gcProbe.WeakHandle.Target))
        $gcHandleTarget = $gcProbe.WeakHandle.Target
        if ($null -ne $gcHandleTarget) {
            try { $gcHandleTarget.Close() } catch { $null = $_ }
        }
        $gcRootFailure = Remove-PspktStrictVectorRoot -Root $gcProbe.ScopedRoot -Label ('observer-stall gc root ' + $Kind)
        if ($null -ne $gcRootFailure) { [void]$rootCleanupFailures.Add($gcRootFailure) }
    }
    finally {
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
        foreach ($authorityHandle in $authorityHandles) {
            try { $authorityHandle.Close() } catch { $null = $_ }
        }
        $contextRootFailure = Remove-PspktStrictVectorRoot -Root $contextRoot -Label ('observer-stall root ' + $Kind)
        if ($null -ne $contextRootFailure) { [void]$rootCleanupFailures.Add($contextRootFailure) }
    }
    return ($stallOk -and $normalOk -and $gcRootOk -and ($rootCleanupFailures.Count -eq 0))
}

function Test-PspktObserverDisposeStallVectors {
    Initialize-PspktPauseObserverType
    Initialize-PspktNestedObserverType
    $joinBoundMs = 300
    $pauseOk = Invoke-PspktObserverStallProbe -Kind 'Pause' -JoinBoundMs $joinBoundMs -CreateProbe { param($bound) [PspktPhase4.PauseObserver]::CreateCertificationStallProbe($bound) }
    $nestedOk = Invoke-PspktObserverStallProbe -Kind 'Nested' -JoinBoundMs $joinBoundMs -CreateProbe { param($bound) [PspktPhase4.NestedObserver]::CreateCertificationStallProbe($bound) }
    return ($pauseOk -and $nestedOk)
}

function New-PspktParentLossFakeChild {
    param([bool]$AlreadyExited = $true)
    $state = [pscustomobject]@{ KillCalled = $false; WaitCalled = $false; DisposeCalled = $false }
    $fake = [pscustomobject]@{ State = $state; HasExited = $AlreadyExited; Id = 424242 }
    $fake | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
    $fake | Add-Member -MemberType ScriptMethod -Name Kill -Value { $this.State.KillCalled = $true }
    $fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param([int]$ms) $this.State.WaitCalled = $true; return [bool]$this.HasExited }
    $fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.State.DisposeCalled = $true }
    return $fake
}

function New-PspktParentLossFakeSession {
    param([bool]$PathReleaseFails = $false)
    $state = [pscustomobject]@{ TerminateCalled = $false; ReleaseCalled = $false; DisposeCalled = $false }
    $fake = [pscustomobject]@{ State = $state; HasExited = $true; ProcessId = 515151; PathReleaseFails = $PathReleaseFails }
    $fake | Add-Member -MemberType ScriptMethod -Name TerminateAndWait -Value { param([int]$ms) $this.State.TerminateCalled = $true }
    $fake | Add-Member -MemberType ScriptMethod -Name ReleasePathBinding -Value {
        $this.State.ReleaseCalled = $true
        if ($this.PathReleaseFails) {
            return [Exception[]]@([System.IO.IOException]::new('injected direct-launch path release failure.'))
        }
        return [Exception[]]@()
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.State.DisposeCalled = $true }
    return $fake
}

function New-PspktParentLossFakeEvent {
    param([bool]$ThrowOnDispose = $false)
    $state = [pscustomobject]@{ DisposeCalled = $false }
    $fake = [pscustomobject]@{ State = $state; ThrowOnDispose = $ThrowOnDispose }
    $fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $this.State.DisposeCalled = $true
        if ($this.ThrowOnDispose) {
            throw [System.IO.IOException]::new('injected owned-event dispose failure.')
        }
    }
    return $fake
}

function New-PspktPostAssignmentFakeProcess {
    param([bool]$ThrowOnDispose = $false)
    $state = [pscustomobject]@{ DisposeCalled = $false }
    $fake = [pscustomobject]@{ State = $state; ThrowOnDispose = $ThrowOnDispose }
    $fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $this.State.DisposeCalled = $true
        if ($this.ThrowOnDispose) {
            throw [System.IO.IOException]::new('injected retained-process dispose failure.')
        }
    }
    return $fake
}

function Test-PspktPostAssignmentKillOnCloseCleanupVectors {
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $childTimeoutOk = $false
    $sessionCloseOk = $false
    $eventDisposeOk = $false
    $contextRemovalOk = $false
    try {
        $eventWithheldMessage = 'post-assignment kill-on-close cleanup: supervisor-event disposal was withheld because child and/or launch-session ownership was not proven clean; the event was retained and rooted in the quarantine registry.'
        $contextWithheldMessage = 'post-assignment kill-on-close cleanup: process-oracle context removal was withheld because child, session, and/or event ownership was not proven clean; the context root was retained and rooted in the quarantine registry.'

        $childTimeoutRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-pakoc-childto-'
        try {
            $context = [pscustomobject]@{ Root = $childTimeoutRoot; WorkingDirectory = $childTimeoutRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $false
            $session = New-PspktParentLossFakeSession
            $event = New-PspktParentLossFakeEvent
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentKillOnCloseLaunch -ChildProcess $child -LaunchSession $session -SupervisorEvent $event -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $registryRecord = $null
            if ($registered) { $registryRecord = $script:Phase4QuarantineRegistry[$countBefore] }
            $primary = [System.InvalidOperationException]::new('injected post-assignment kill-on-close child-timeout primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment kill-on-close child-timeout vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $childTimeoutOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $childTimeoutRoot -PathType Container) -and
                ($null -ne $registryRecord) -and
                ($registryRecord.Kind -ceq 'PostAssignmentKillOnClose') -and
                ($registryRecord.Context.TempDirs[0] -ceq $childTimeoutRoot) -and
                $child.State.KillCalled -and
                (-not $child.State.DisposeCalled) -and
                $session.State.DisposeCalled -and
                (-not $event.State.DisposeCalled) -and
                ($messages -contains 'injected post-assignment kill-on-close child-timeout primary failure.') -and
                ($messages -contains 'post-assignment kill-on-close cleanup: child process 424242 exit could not be proven within the 50 ms bounded deadline; the Process wrapper was retained and rooted in the quarantine registry.') -and
                ($messages -contains $eventWithheldMessage) -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $childTimeoutRoot) {
                Remove-Item -LiteralPath $childTimeoutRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $sessionCloseRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-pakoc-sessclose-'
        try {
            $context = [pscustomobject]@{ Root = $sessionCloseRoot; WorkingDirectory = $sessionCloseRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $true
            $session = New-PspktParentLossFakeSession -PathReleaseFails $true
            $event = New-PspktParentLossFakeEvent
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentKillOnCloseLaunch -ChildProcess $child -LaunchSession $session -SupervisorEvent $event -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected post-assignment kill-on-close session-close primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment kill-on-close session-close vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $sessionCloseOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $sessionCloseRoot -PathType Container) -and
                $child.State.DisposeCalled -and
                $session.State.ReleaseCalled -and
                (-not $session.State.DisposeCalled) -and
                (-not $event.State.DisposeCalled) -and
                ($messages -contains 'injected post-assignment kill-on-close session-close primary failure.') -and
                ($messages -contains 'injected direct-launch path release failure.') -and
                ($messages -contains $eventWithheldMessage) -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $sessionCloseRoot) {
                Remove-Item -LiteralPath $sessionCloseRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $eventDisposeRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-pakoc-evtdisp-'
        try {
            $context = [pscustomobject]@{ Root = $eventDisposeRoot; WorkingDirectory = $eventDisposeRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $true
            $session = New-PspktParentLossFakeSession
            $event = New-PspktParentLossFakeEvent -ThrowOnDispose $true
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentKillOnCloseLaunch -ChildProcess $child -LaunchSession $session -SupervisorEvent $event -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected post-assignment kill-on-close event-dispose primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment kill-on-close event-dispose vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $eventDisposeOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $eventDisposeRoot -PathType Container) -and
                $child.State.DisposeCalled -and
                $session.State.DisposeCalled -and
                $event.State.DisposeCalled -and
                ($messages -contains 'injected post-assignment kill-on-close event-dispose primary failure.') -and
                ($messages -contains 'injected owned-event dispose failure.') -and
                ($messages -contains $contextWithheldMessage) -and
                ($messages -notcontains $eventWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $eventDisposeRoot) {
                Remove-Item -LiteralPath $eventDisposeRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $contextRemovalRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-pakoc-ctxrm-'
        $lockedFilePath = Join-Path $contextRemovalRoot ('locked-' + [Guid]::NewGuid().ToString('N') + '.bin')
        $lockHandle = [System.IO.FileStream]::new($lockedFilePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $context = [pscustomobject]@{ Root = $contextRemovalRoot; WorkingDirectory = $contextRemovalRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $true
            $session = New-PspktParentLossFakeSession
            $event = New-PspktParentLossFakeEvent
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentKillOnCloseLaunch -ChildProcess $child -LaunchSession $session -SupervisorEvent $event -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected post-assignment kill-on-close context-removal primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment kill-on-close context-removal vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            $innerCount = 0
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
                $innerCount = $composed.InnerExceptions.Count
            }
            $contextRemovalOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $contextRemovalRoot -PathType Container) -and
                $child.State.DisposeCalled -and
                $session.State.DisposeCalled -and
                $event.State.DisposeCalled -and
                ($innerCount -eq 2) -and
                ($messages -contains 'injected post-assignment kill-on-close context-removal primary failure.') -and
                ($messages -notcontains $eventWithheldMessage) -and
                ($messages -notcontains $contextWithheldMessage))
        }
        finally {
            $lockHandle.Dispose()
            if (Test-Path -LiteralPath $contextRemovalRoot) {
                Remove-Item -LiteralPath $contextRemovalRoot -Recurse -Force -ErrorAction Stop
            }
        }
    }
    finally {
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
    }

    return ($childTimeoutOk -and $sessionCloseOk -and $eventDisposeOk -and $contextRemovalOk)
}

function Test-PspktPostAssignmentEvidenceCleanupVectors {
    Initialize-PspktGateSignalObserverType
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $observerFailOk = $false
    $siblingOk = $false
    $processFailOk = $false
    $contextRemovalOk = $false
    $joinBoundMs = 300
    try {
        $contextWithheldMessage = 'post-assignment evidence-failure cleanup: process-oracle context removal was withheld because observer and/or retained-process ownership was not proven clean; the context root was retained and rooted in the quarantine registry.'
        $observerJoinTimeoutMessage = 'gate signal observer worker thread did not terminate within the bounded join; retained handles were not closed.'

        $observerFailRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-paev-obsfail-'
        $observer = $null
        try {
            $context = [pscustomobject]@{ Root = $observerFailRoot; WorkingDirectory = $observerFailRoot }
            $observer = [PspktPhase4.GateSignalObserver]::CreateCertificationStallProbe($joinBoundMs)
            $observer.Start()
            $usableBefore = $observer.StallHandlesUsable()
            $process = New-PspktPostAssignmentFakeProcess
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentEvidenceLaunch -Observer $observer -RetainedProcess $process -Context $context
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $registryRecord = $null
            if ($registered) { $registryRecord = $script:Phase4QuarantineRegistry[$countBefore] }
            $usableAfter = $observer.StallHandlesUsable()
            $primary = [System.InvalidOperationException]::new('injected post-assignment evidence observer-fail primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment evidence observer-fail vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $observerFailOk = (
                $usableBefore -and
                $usableAfter -and
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $observerFailRoot -PathType Container) -and
                ($null -ne $registryRecord) -and
                ($registryRecord.Kind -ceq 'PostAssignmentEvidence') -and
                [object]::ReferenceEquals($registryRecord.Context.Observer, $observer) -and
                [object]::ReferenceEquals($registryRecord.Context.RetainedProcess, $process) -and
                ($registryRecord.Context.TempDirs[0] -ceq $observerFailRoot) -and
                $process.State.DisposeCalled -and
                ($messages -contains 'injected post-assignment evidence observer-fail primary failure.') -and
                ($messages -contains $observerJoinTimeoutMessage) -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if ($null -ne $observer) {
                $observer.ReleaseCertificationStall()
                [void]$observer.Join(5000)
                try { $observer.Dispose() } catch { $null = $_ }
            }
            if (Test-Path -LiteralPath $observerFailRoot) {
                Remove-Item -LiteralPath $observerFailRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $siblingRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-paev-sibling-'
        $siblingObserver = $null
        try {
            $context = [pscustomobject]@{ Root = $siblingRoot; WorkingDirectory = $siblingRoot }
            $siblingObserver = [PspktPhase4.GateSignalObserver]::CreateCertificationStallProbe($joinBoundMs)
            $siblingObserver.Start()
            $process = New-PspktPostAssignmentFakeProcess -ThrowOnDispose $true
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentEvidenceLaunch -Observer $siblingObserver -RetainedProcess $process -Context $context
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected post-assignment evidence sibling primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment evidence sibling vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            $innerCount = 0
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
                $innerCount = $composed.InnerExceptions.Count
            }
            $siblingOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $siblingRoot -PathType Container) -and
                $process.State.DisposeCalled -and
                ($innerCount -eq 4) -and
                ($messages -contains 'injected post-assignment evidence sibling primary failure.') -and
                ($messages -contains $observerJoinTimeoutMessage) -and
                ($messages -contains 'injected retained-process dispose failure.') -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if ($null -ne $siblingObserver) {
                $siblingObserver.ReleaseCertificationStall()
                [void]$siblingObserver.Join(5000)
                try { $siblingObserver.Dispose() } catch { $null = $_ }
            }
            if (Test-Path -LiteralPath $siblingRoot) {
                Remove-Item -LiteralPath $siblingRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $processFailRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-paev-procfail-'
        try {
            $context = [pscustomobject]@{ Root = $processFailRoot; WorkingDirectory = $processFailRoot }
            $process = New-PspktPostAssignmentFakeProcess -ThrowOnDispose $true
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentEvidenceLaunch -Observer $null -RetainedProcess $process -Context $context
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected post-assignment evidence process-fail primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment evidence process-fail vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $processFailOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $processFailRoot -PathType Container) -and
                $process.State.DisposeCalled -and
                ($messages -contains 'injected post-assignment evidence process-fail primary failure.') -and
                ($messages -contains 'injected retained-process dispose failure.') -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $processFailRoot) {
                Remove-Item -LiteralPath $processFailRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $contextRemovalRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-paev-ctxrm-'
        $lockedFilePath = Join-Path $contextRemovalRoot ('locked-' + [Guid]::NewGuid().ToString('N') + '.bin')
        $lockHandle = [System.IO.FileStream]::new($lockedFilePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $context = [pscustomobject]@{ Root = $contextRemovalRoot; WorkingDirectory = $contextRemovalRoot }
            $process = New-PspktPostAssignmentFakeProcess
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktPostAssignmentEvidenceLaunch -Observer $null -RetainedProcess $process -Context $context
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected post-assignment evidence context-removal primary failure.')
            $composed = New-PspktComposedFailure -Message 'post-assignment evidence context-removal vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            $innerCount = 0
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
                $innerCount = $composed.InnerExceptions.Count
            }
            $contextRemovalOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $contextRemovalRoot -PathType Container) -and
                $process.State.DisposeCalled -and
                ($innerCount -eq 2) -and
                ($messages -contains 'injected post-assignment evidence context-removal primary failure.') -and
                ($messages -notcontains $contextWithheldMessage))
        }
        finally {
            $lockHandle.Dispose()
            if (Test-Path -LiteralPath $contextRemovalRoot) {
                Remove-Item -LiteralPath $contextRemovalRoot -Recurse -Force -ErrorAction Stop
            }
        }
    }
    finally {
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
    }

    return ($observerFailOk -and $siblingOk -and $processFailOk -and $contextRemovalOk)
}

function Test-PspktParentLossCleanupNegativeVectors {
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $childTimeoutOk = $false
    $sessionCloseOk = $false
    $eventDisposeOk = $false
    $contextRemovalOk = $false
    try {
        $eventsWithheldMessage = 'parent-loss cleanup: gate and owned-event disposal was withheld because child and/or launch-session ownership was not proven clean; the events were retained and rooted in the quarantine registry.'
        $contextWithheldMessage = 'parent-loss cleanup: process-oracle context removal was withheld because child, session, and/or event ownership was not proven clean; the context root was retained and rooted in the quarantine registry.'

        $childTimeoutRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-ploss-childto-'
        try {
            $context = [pscustomobject]@{ Root = $childTimeoutRoot; WorkingDirectory = $childTimeoutRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $false
            $session = New-PspktParentLossFakeSession
            $gate = New-PspktParentLossFakeEvent
            $ownedEvents = [System.Collections.Generic.List[object]]::new()
            [void]$ownedEvents.Add((New-PspktParentLossFakeEvent))
            [void]$ownedEvents.Add((New-PspktParentLossFakeEvent))
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktParentLossLaunch -ChildProcess $child -LaunchSession $session -GateEvent $gate -OwnedEvents $ownedEvents -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected parent-loss child-timeout primary failure.')
            $composed = New-PspktComposedFailure -Message 'parent-loss child-timeout vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $eventsUntouched = ((-not $gate.State.DisposeCalled) -and (-not $ownedEvents[0].State.DisposeCalled) -and (-not $ownedEvents[1].State.DisposeCalled))
            $childTimeoutOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $childTimeoutRoot -PathType Container) -and
                $child.State.KillCalled -and
                (-not $child.State.DisposeCalled) -and
                $session.State.DisposeCalled -and
                $eventsUntouched -and
                ($messages -contains 'injected parent-loss child-timeout primary failure.') -and
                ($messages -contains 'parent-loss cleanup: child process 424242 exit could not be proven within the 50 ms bounded deadline; the Process wrapper was retained and rooted in the quarantine registry.') -and
                ($messages -contains $eventsWithheldMessage) -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $childTimeoutRoot) {
                Remove-Item -LiteralPath $childTimeoutRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $sessionCloseRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-ploss-sessclose-'
        try {
            $context = [pscustomobject]@{ Root = $sessionCloseRoot; WorkingDirectory = $sessionCloseRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $true
            $session = New-PspktParentLossFakeSession -PathReleaseFails $true
            $gate = New-PspktParentLossFakeEvent
            $ownedEvents = [System.Collections.Generic.List[object]]::new()
            [void]$ownedEvents.Add((New-PspktParentLossFakeEvent))
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktParentLossLaunch -ChildProcess $child -LaunchSession $session -GateEvent $gate -OwnedEvents $ownedEvents -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected parent-loss session-close primary failure.')
            $composed = New-PspktComposedFailure -Message 'parent-loss session-close vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $eventsUntouched = ((-not $gate.State.DisposeCalled) -and (-not $ownedEvents[0].State.DisposeCalled))
            $sessionCloseOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $sessionCloseRoot -PathType Container) -and
                $child.State.DisposeCalled -and
                $session.State.ReleaseCalled -and
                (-not $session.State.DisposeCalled) -and
                $eventsUntouched -and
                ($messages -contains 'injected parent-loss session-close primary failure.') -and
                ($messages -contains 'injected direct-launch path release failure.') -and
                ($messages -contains $eventsWithheldMessage) -and
                ($messages -contains $contextWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $sessionCloseRoot) {
                Remove-Item -LiteralPath $sessionCloseRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $eventDisposeRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-ploss-evtdisp-'
        try {
            $context = [pscustomobject]@{ Root = $eventDisposeRoot; WorkingDirectory = $eventDisposeRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $true
            $session = New-PspktParentLossFakeSession
            $gate = New-PspktParentLossFakeEvent
            $ownedEvents = [System.Collections.Generic.List[object]]::new()
            $cleanEventA = New-PspktParentLossFakeEvent
            $failingEvent = New-PspktParentLossFakeEvent -ThrowOnDispose $true
            $cleanEventB = New-PspktParentLossFakeEvent
            [void]$ownedEvents.Add($cleanEventA)
            [void]$ownedEvents.Add($failingEvent)
            [void]$ownedEvents.Add($cleanEventB)
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktParentLossLaunch -ChildProcess $child -LaunchSession $session -GateEvent $gate -OwnedEvents $ownedEvents -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected parent-loss event-dispose primary failure.')
            $composed = New-PspktComposedFailure -Message 'parent-loss event-dispose vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
            }
            $independentDisposal = ($gate.State.DisposeCalled -and $cleanEventA.State.DisposeCalled -and $failingEvent.State.DisposeCalled -and $cleanEventB.State.DisposeCalled)
            $eventDisposeOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $eventDisposeRoot -PathType Container) -and
                $child.State.DisposeCalled -and
                $session.State.DisposeCalled -and
                $independentDisposal -and
                ($messages -contains 'injected parent-loss event-dispose primary failure.') -and
                ($messages -contains 'injected owned-event dispose failure.') -and
                ($messages -contains $contextWithheldMessage) -and
                ($messages -notcontains $eventsWithheldMessage))
        }
        finally {
            if (Test-Path -LiteralPath $eventDisposeRoot) {
                Remove-Item -LiteralPath $eventDisposeRoot -Recurse -Force -ErrorAction Stop
            }
        }

        $contextRemovalRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-ploss-ctxrm-'
        $lockedFilePath = Join-Path $contextRemovalRoot ('locked-' + [Guid]::NewGuid().ToString('N') + '.bin')
        $lockHandle = [System.IO.FileStream]::new($lockedFilePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $context = [pscustomobject]@{ Root = $contextRemovalRoot; WorkingDirectory = $contextRemovalRoot }
            $child = New-PspktParentLossFakeChild -AlreadyExited $true
            $session = New-PspktParentLossFakeSession
            $gate = New-PspktParentLossFakeEvent
            $ownedEvents = [System.Collections.Generic.List[object]]::new()
            [void]$ownedEvents.Add((New-PspktParentLossFakeEvent))
            [void]$ownedEvents.Add((New-PspktParentLossFakeEvent))
            $countBefore = Get-PspktQuarantineRegistrationCount
            $cleanupFailures = Close-PspktParentLossLaunch -ChildProcess $child -LaunchSession $session -GateEvent $gate -OwnedEvents $ownedEvents -Context $context -ChildExitDeadlineMilliseconds 50
            $registered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
            $primary = [System.InvalidOperationException]::new('injected parent-loss context-removal primary failure.')
            $composed = New-PspktComposedFailure -Message 'parent-loss context-removal vector.' -PrimaryFailure $primary -CleanupFailures $cleanupFailures
            $messages = @()
            $innerCount = 0
            if ($composed -is [System.AggregateException]) {
                $messages = [string[]]@($composed.InnerExceptions | ForEach-Object { $_.Message })
                $innerCount = $composed.InnerExceptions.Count
            }
            $allEventsDisposed = ($gate.State.DisposeCalled -and $ownedEvents[0].State.DisposeCalled -and $ownedEvents[1].State.DisposeCalled)
            $contextRemovalOk = (
                $registered -and
                ($composed -is [System.AggregateException]) -and
                (Test-Path -LiteralPath $contextRemovalRoot -PathType Container) -and
                $child.State.DisposeCalled -and
                $session.State.DisposeCalled -and
                $allEventsDisposed -and
                ($innerCount -eq 2) -and
                ($messages -contains 'injected parent-loss context-removal primary failure.') -and
                ($messages -notcontains $eventsWithheldMessage) -and
                ($messages -notcontains $contextWithheldMessage))
        }
        finally {
            $lockHandle.Dispose()
            if (Test-Path -LiteralPath $contextRemovalRoot) {
                Remove-Item -LiteralPath $contextRemovalRoot -Recurse -Force -ErrorAction Stop
            }
        }
    }
    finally {
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
    }

    return ($childTimeoutOk -and $sessionCloseOk -and $eventDisposeOk -and $contextRemovalOk)
}

function Invoke-PspktPhase4Outer {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Slice', 'Release')][string]$Mode,
        [string]$BaselineCommit = ''
    )
    Write-Host 'phase4-schema outer validator'
    Write-Host '============================='

    if ($Mode -ceq 'Release') {
        $ledger = New-PspktCheckLedger -ExpectedIds $script:ExpectedOuterCheckIdsRelease
    }
    else {
        $ledger = New-PspktCheckLedger -ExpectedIds $script:ExpectedOuterCheckIdsSlice
    }

    $gitBinding = $null
    $gitAuthority = $null
    $configRoot = $null
    $snapshot = $null
    $cscDir = $null
    $binding = $null
    $indexTreeInitial = $null
    $indexOidByPath = $null
    $worktreeInitialOk = $false

    try {
        $gitBinding = Resolve-PspktGitExecutable
        $configRoot = New-PspktGitConfigRoot
        $gitAuthority = Assert-PspktGitRepositoryAuthority -GitBinding $gitBinding -RepositoryRoot $repositoryRoot

        if ($Mode -ceq 'Release') {
            $baselineOk = $false
            try {
                if (-not (Test-PspktLowercaseHexOid -Value $BaselineCommit)) {
                    throw 'baseline commit is not a full lowercase hex OID.'
                }
                if ($BaselineCommit -cne $script:PinnedBaselineCommit) {
                    throw ('baseline commit "{0}" does not equal the R58-pinned baseline "{1}".' -f $BaselineCommit, $script:PinnedBaselineCommit)
                }
                $typeResult = Invoke-PspktCheckedGit -GitAuthority $gitAuthority -ConfigRoot $configRoot -GitArgs @('cat-file', '-t', $BaselineCommit)
                $baselineOk = (($typeResult.StdOut -replace "`r", '').Trim() -ceq 'commit')
            }
            catch { $baselineOk = $false }
            [void](Add-PspktCheck -Ledger $ledger -Id 'baseline-commit-valid' -Condition $baselineOk)

            $exclusiveInitial = $false
            $exclusiveInitialDetail = ''
            try {
                $helperVectorsOk = Test-PspktPathSetHelperNegativeVectors -Expected $script:ExpectedSlicePaths
                $stageResult = Invoke-PspktCheckedGit -GitAuthority $gitAuthority -ConfigRoot $configRoot -GitArgs @('ls-files', '--stage', '-z', '--', '.gitattributes', 'certification')
                $records = @(($stageResult.StdOut -split "`0") | Where-Object { $_ -ne '' })
                $indexPaths = @()
                $grammarOk = $true
                foreach ($record in $records) {
                    $m = [regex]::Match($record, '^(?<mode>[0-7]{6}) (?<oid>[0-9a-f]{40}|[0-9a-f]{64}) (?<stage>[0-3])\t(?<path>[\s\S]+)$')
                    if (-not $m.Success) { $grammarOk = $false; break }
                    if ($m.Groups['mode'].Value -cne '100644') { $grammarOk = $false; break }
                    if ($m.Groups['stage'].Value -cne '0') { $grammarOk = $false; break }
                    if (-not (Test-PspktLowercaseHexOid -Value $m.Groups['oid'].Value)) { $grammarOk = $false; break }
                    $indexPaths += $m.Groups['path'].Value
                }
                $setOk = Test-PspktExactOrdinalPathSet -Actual $indexPaths -Expected $script:ExpectedSlicePaths
                $exclusiveInitial = ($helperVectorsOk -and $grammarOk -and $setOk)
                $exclusiveInitialDetail = ('helperVectors={0} grammar={1} exactSet={2} records={3}' -f $helperVectorsOk, $grammarOk, $setOk, $records.Count)
            }
            catch { $exclusiveInitial = $false; $exclusiveInitialDetail = ('exception={0}' -f $_.Exception.Message) }
            [void](Add-PspktCheck -Ledger $ledger -Id 'exclusive-slice-initial' -Condition $exclusiveInitial -Detail $exclusiveInitialDetail)
        }

        $gitNegativeOk = (Test-PspktThrows { Invoke-PspktCheckedGit -GitAuthority $gitAuthority -ConfigRoot $configRoot -GitArgs @('cat-file', '-t', 'not-a-real-object') }) -and
            (Test-PspktBinaryReturnVector) -and
            (Test-PspktGitBlobOidPreimageVectors) -and
            (Test-PspktRedirectedCleanupBudgetVector) -and
            (Test-PspktDrainedProcessEarlyPipeClosureVector) -and
            (Test-PspktDrainedProcessHardeningVectors) -and
            (Test-PspktStrictVectorRootCleanupVector) -and
            (Test-PspktSnapshotTreeCleanupVectors -GitAuthority $gitAuthority -ConfigRoot $configRoot) -and
            (Test-PspktObserverDisposeStallVectors) -and
            (Test-PspktParentLossCleanupNegativeVectors) -and
            (Test-PspktOuterCleanupRootsNegativeVectors) -and
            (Test-PspktGitAttributesPolicyPinVectors) -and
            (Test-PspktGitAuthorityMutationVectors -GitBinding $gitBinding) -and
            (Test-PspktCscAuthorityIdentityVectors) -and
            (Test-PspktWorkerGatePrecedenceVectors)
        [void](Add-PspktCheck -Ledger $ledger -Id 'git-authority-negative-vectors' -Condition $gitNegativeOk)

        $indexOidByPath = Get-PspktIndexStageMap -GitAuthority $gitAuthority -ConfigRoot $configRoot -Paths $script:ExpectedSlicePaths
        try {
            $worktreeInitialOk = Test-PspktWorktreeIndexBinding -IndexOidByPath $indexOidByPath -Paths $script:ExpectedSlicePaths -RepositoryRoot $repositoryRoot
        }
        catch { $worktreeInitialOk = $false }
        $snapshot = New-PspktSnapshotTree -GitAuthority $gitAuthority -ConfigRoot $configRoot -IndexOidByPath $indexOidByPath -Paths $script:ExpectedSlicePaths
        $snapshotOk = ($snapshot.Manifest.Count -eq $script:ExpectedSlicePaths.Count)
        [void](Add-PspktCheck -Ledger $ledger -Id 'source-snapshot-authority' -Condition $snapshotOk -Detail ('entries={0}' -f $snapshot.Manifest.Count))

        $cscDir = New-PspktTempDirectory -Prefix 'pspkt-phase4-csc-'
        $snapshotHelperSource = Join-Path $snapshot.Root 'certification\lib\Pspkt.Certification.BoundedProcess.cs'
        $cscOk = $false
        $helperDllPath = $null
        try {
            $helperDllPath = Invoke-PspktCscBootstrap -SnapshotSourcePath $snapshotHelperSource -OutputDirectory $cscDir
            $cscOk = (Test-Path -LiteralPath $helperDllPath -PathType Leaf)
        }
        catch { $cscOk = $false }
        [void](Add-PspktCheck -Ledger $ledger -Id 'csc-authority' -Condition $cscOk)

        $bindingOk = $false
        try {
            $binding = New-PspktHelperBinding -HelperPath $helperDllPath
            $bindingOk = ($binding.Version -ceq $script:HelperVersion -and [string]::IsNullOrEmpty($binding.Assembly.Location))
        }
        catch { $bindingOk = $false }
        [void](Add-PspktCheck -Ledger $ledger -Id 'csc-output' -Condition $bindingOk)

        $indexTreeInitial = Get-PspktIndexTreeId -GitAuthority $gitAuthority -ConfigRoot $configRoot
        [void](Add-PspktCheck -Ledger $ledger -Id 'index-tree-initial' -Condition (($null -ne $indexTreeInitial) -and $worktreeInitialOk) -Detail ('worktreeInitial={0}' -f $worktreeInitialOk))

        $inventoryOk = (($script:WorkerScenarioInventory.Count + $script:WorkerResultMutationInventory.Count -eq 26) -and ($script:GeneratorScenarioInventory.Count -eq 3))
        [void](Add-PspktCheck -Ledger $ledger -Id 'outer-launch-inventory' -Condition $inventoryOk -Detail ('worker={0} generator={1}' -f ($script:WorkerScenarioInventory.Count + $script:WorkerResultMutationInventory.Count), $script:GeneratorScenarioInventory.Count))

        $faultResults = @{}
        foreach ($scenario in @('SimulateAssignFailure', 'ResumeFailureZero', 'ResumeFailureNative', 'ResumeFailureMultiple', 'WorkerGateTimeout', 'WorkerGateOpenFailure', 'WorkerTimeout', 'WorkerLeavesDescendant', 'WorkerNonzeroExit')) {
            $faultResults[$scenario] = (Invoke-PspktRunFaultScenario -Binding $binding -Scenario $scenario -SnapshotRoot $snapshot.Root)
        }

        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-assign-failure' -Condition ([bool]$faultResults['SimulateAssignFailure']))
        $resumeOk = ([bool]$faultResults['ResumeFailureZero'] -and [bool]$faultResults['ResumeFailureNative'] -and [bool]$faultResults['ResumeFailureMultiple'])
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-resume-failure' -Condition $resumeOk)
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-gate-timeout' -Condition ([bool]$faultResults['WorkerGateTimeout']))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-gate-open-failure' -Condition ([bool]$faultResults['WorkerGateOpenFailure']))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-timeout-cleanup' -Condition ([bool]$faultResults['WorkerTimeout']))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-descendant-detected' -Condition ([bool]$faultResults['WorkerLeavesDescendant']))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-nonzero-exit-rejected' -Condition ([bool]$faultResults['WorkerNonzeroExit']))

        $workerNegLaunched = Invoke-PspktRunMalformedScenarios -Binding $binding -SnapshotRoot $snapshot.Root
        $workerNegInProc = Test-PspktWorkerResultNegativeVectors -HelperVersion $binding.Version
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-result-negative-vectors' -Condition ($workerNegLaunched -and $workerNegInProc))

        $schemaNegOk = Test-PspktSchemaResultNegativeVectors -Binding $binding -SnapshotRoot $snapshot.Root
        [void](Add-PspktCheck -Ledger $ledger -Id 'schema-result-negative-vectors' -Condition $schemaNegOk)

        $generatorNegOk = (Test-PspktGeneratorResultNegativeVectors -Binding $binding) -and (Test-PspktDiagnosticsDebtVector -Binding $binding)
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-result-negative-vectors' -Condition $generatorNegOk)

        $normalResult = Invoke-PspktRunNormalWorker -Binding $binding -SnapshotRoot $snapshot.Root
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-helper-handoff' -Condition ([bool]$normalResult.HelperHandoff))
        [void](Add-PspktCheck -Ledger $ledger -Id 'nested-job-outer-count-rise' -Condition ([bool]$normalResult.CountRise))
        [void](Add-PspktCheck -Ledger $ledger -Id 'nested-job-outer-count-fall' -Condition ([bool]$normalResult.CountFall))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-normal-exit-zero' -Condition ([bool]$normalResult.ExitZero))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-normal-result-accepted' -Condition ([bool]$normalResult.ResultAccepted))
        [void](Add-PspktCheck -Ledger $ledger -Id 'worker-normal-no-descendants' -Condition ([bool]$normalResult.NoDescendants))

        $generatorResults = Invoke-PspktRunGeneratorScenarios -Binding $binding -SnapshotRoot $snapshot.Root `
            -InitialIndexTreeId $indexTreeInitial -GitAuthority $gitAuthority -GitConfigRoot $configRoot
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-contained-false' -Condition ([bool]$generatorResults.ContainedFalse))
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-gate-first' -Condition ([bool]$generatorResults.GateFirst))
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-selftest' -Condition ([bool]$generatorResults.SelfTest))
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-hardlink' -Condition ([bool]$generatorResults.Hardlink))
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-output-68' -Condition ([bool]$generatorResults.Output68))
        [void](Add-PspktCheck -Ledger $ledger -Id 'generator-index-stable' -Condition ([bool]$generatorResults.IndexStable))

        if ($Mode -ceq 'Release') {
            $exclusiveFinal = $false
            $exclusiveFinalDetail = ''
            try {
                $diffResult = Invoke-PspktCheckedGit -GitAuthority $gitAuthority -ConfigRoot $configRoot -GitArgs @('diff', '--cached', '--name-only', '-z', '--no-renames', '--diff-filter=ACDMRTUXB', $BaselineCommit, '--')
                $diffPaths = @(($diffResult.StdOut -split "`0") | Where-Object { $_ -ne '' })
                $exclusiveFinal = (Test-PspktExactOrdinalPathSet -Actual $diffPaths -Expected $script:ExpectedSlicePaths)
                $exclusiveFinalDetail = ('exactSet={0} names={1}' -f $exclusiveFinal, $diffPaths.Count)
            }
            catch { $exclusiveFinal = $false; $exclusiveFinalDetail = ('exception={0}' -f $_.Exception.Message) }
            [void](Add-PspktCheck -Ledger $ledger -Id 'exclusive-slice-final' -Condition $exclusiveFinal -Detail $exclusiveFinalDetail)
        }
    }
    catch {
        $script:FailCount++
        Write-Host ('  [FAIL] outer bootstrap error :: {0}' -f $_.Exception.Message)
    }
    finally {
        $indexTreeFinalOk = $false
        $writeTreeEqual = $false
        $stageMapEqual = $false
        $worktreeFinalOk = $false
        $gitAttributesPinFinalOk = $false
        try {
            if ($null -ne $gitAuthority -and $null -ne $configRoot -and $null -ne $indexTreeInitial -and $null -ne $indexOidByPath) {
                $indexTreeFinal = Get-PspktIndexTreeId -GitAuthority $gitAuthority -ConfigRoot $configRoot
                $writeTreeEqual = ($indexTreeFinal -ceq $indexTreeInitial)
                $finalStageMap = Get-PspktIndexStageMap -GitAuthority $gitAuthority -ConfigRoot $configRoot -Paths $script:ExpectedSlicePaths
                $stageMapEqual = Test-PspktStageMapEquality -Expected $indexOidByPath -Actual $finalStageMap -Paths $script:ExpectedSlicePaths
                $worktreeFinalOk = Test-PspktWorktreeIndexBinding -IndexOidByPath $indexOidByPath -Paths $script:ExpectedSlicePaths -RepositoryRoot $repositoryRoot
                $finalGitAttributesOid = [string]$finalStageMap[$script:PinnedGitAttributesRelPath]
                $finalGitAttributesPath = Resolve-PspktRepoContainedOrdinaryFile -RepositoryRoot $repositoryRoot -RelPath $script:PinnedGitAttributesRelPath
                $finalGitAttributesBytes = Read-PspktBoundedFileBytes -FullPath $finalGitAttributesPath -ByteCap $script:GitBlobByteCap
                Assert-PspktGitAttributesPolicyBytes -Bytes $finalGitAttributesBytes -Context 'final worktree/index .gitattributes' -IndexOid $finalGitAttributesOid
                $gitAttributesPinFinalOk = $true
                $indexTreeFinalOk = ($writeTreeEqual -and $stageMapEqual -and $worktreeFinalOk -and $gitAttributesPinFinalOk)
            }
        }
        catch { $indexTreeFinalOk = $false }
        [void](Add-PspktCheck -Ledger $ledger -Id 'index-tree-final' -Condition $indexTreeFinalOk -Detail ('writeTree={0} stageMap={1} worktree={2} gitAttributesPin={3}' -f $writeTreeEqual, $stageMapEqual, $worktreeFinalOk, $gitAttributesPinFinalOk))

        $cleanupOk = $true
        $cleanupDetail = ''
        $outerCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
        try {
            foreach ($authorityCloseFailure in (Close-PspktGitAuthority -Authority $gitAuthority)) {
                if ($null -ne $authorityCloseFailure) { [void]$outerCleanupFailures.Add($authorityCloseFailure) }
            }
        }
        catch {
            [void]$outerCleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        try {
            Close-PspktGitBinding -GitBinding $gitBinding
        }
        catch {
            [void]$outerCleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        $outerCleanupRoots = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $snapshot -and -not [string]::IsNullOrEmpty([string]$snapshot.Root)) { [void]$outerCleanupRoots.Add([string]$snapshot.Root) }
        if ($null -ne $cscDir) { [void]$outerCleanupRoots.Add([string]$cscDir) }
        if ($null -ne $configRoot) { [void]$outerCleanupRoots.Add([string]$configRoot) }
        foreach ($rootRemovalFailure in (Remove-PspktResolvedCleanupRoots -Roots ([string[]]$outerCleanupRoots.ToArray()))) {
            [void]$outerCleanupFailures.Add($rootRemovalFailure)
        }
        $quarantineRegistrationCount = Get-PspktQuarantineRegistrationCount
        if ($quarantineRegistrationCount -gt 0) {
            [void]$outerCleanupFailures.Add([System.InvalidOperationException]::new(
                    ('quarantine registry retained {0} unclean launch ownership record(s) through outer cleanup: {1}.' -f $quarantineRegistrationCount, (Get-PspktQuarantineRegistrationKindList))))
        }
        if ($null -ne $script:Phase4QuarantineEmergencySlot) {
            [void]$outerCleanupFailures.Add([System.InvalidOperationException]::new(
                    ('quarantine registry emergency ownership slot retained an un-cleaned overflow "{0}" launch ownership through outer cleanup; genuine emergency ownership is never silently cleared.' -f [string]$script:Phase4QuarantineEmergencySlot.Kind)))
        }
        $bootstrapQuarantineCount = Get-PspktBootstrapProcessQuarantineCount
        if ($bootstrapQuarantineCount -gt 0) {
            [void]$outerCleanupFailures.Add([System.InvalidOperationException]::new(
                    ('bootstrap-process quarantine retained {0} possibly-live OS child ownership record(s) through outer cleanup; descendant containment is not claimed.' -f $bootstrapQuarantineCount)))
        }
        if ($null -ne $script:Phase4BootstrapProcessEmergencySlot) {
            [void]$outerCleanupFailures.Add([System.InvalidOperationException]::new(
                    ('bootstrap-process emergency ownership slot retained an un-terminated overflow OS child (pid {0}) through outer cleanup; descendant containment is not claimed.' -f [int]$script:Phase4BootstrapProcessEmergencySlot.ProcessId)))
        }
        $diagnosticsDebtDetail = 'binding-absent'
        if ($null -ne $binding) {
            try {
                $finalDiagnostics = Get-PspktDiagnosticsSnapshot -Binding $binding
                $diagnosticsDebtDetail = ('pendingManagedSessions={0} quarantinedLaunches={1}' -f [int]$finalDiagnostics.PendingManagedSessionCount, [int]$finalDiagnostics.QuarantinedLaunchCount)
                if (-not (Test-PspktDiagnosticsSnapshotClean -Snapshot $finalDiagnostics)) {
                    [void]$outerCleanupFailures.Add([System.InvalidOperationException]::new(
                            ('final C# cleanup debt gate detected retained debt: {0}.' -f $diagnosticsDebtDetail)))
                }
            }
            catch {
                $diagnosticsDebtDetail = ('query-failure={0}' -f (Get-PspktInnermostException -Exception $_.Exception).Message)
                [void]$outerCleanupFailures.Add([System.InvalidOperationException]::new(
                        ('final C# cleanup debt gate query failed: {0}.' -f $diagnosticsDebtDetail)))
            }
        }
        if ($outerCleanupFailures.Count -gt 0) {
            $cleanupOk = $false
            $cleanupDetail = ('failures={0}; quarantined={1}; diagnostics={2}; first={3}' -f $outerCleanupFailures.Count, $quarantineRegistrationCount, $diagnosticsDebtDetail, $outerCleanupFailures[0].Message)
        }
        else {
            $cleanupDetail = ('diagnostics={0}' -f $diagnosticsDebtDetail)
        }
        [void](Add-PspktCheck -Ledger $ledger -Id 'outer-cleanup' -Condition $cleanupOk -Detail $cleanupDetail)
    }

    Write-Host ''
    Write-Host 'Cooperative trust ceiling: the user-selected host, this loaded validator, and the same-user outer'
    Write-Host 'process are trusted bootstrap authorities. This slice does not prove bytes executed before its first'
    Write-Host 'statement and does not resist a malicious outer or coordinated same-user tampering.'
    Write-Host ''
    $ledgerComplete = Test-PspktLedgerComplete -Ledger $ledger
    Write-Host ('outer ledger complete/in-order: {0} ({1}/{2} recorded)' -f $ledgerComplete, $ledger.Recorded.Count, $ledger.Expected.Count)
    Write-Host ('summary: {0} passed, {1} failed' -f $script:PassCount, $script:FailCount)
    if ($script:FailCount -gt 0 -or -not $ledgerComplete) {
        exit 1
    }
    exit 0
}

function Invoke-PspktRunFaultScenario {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot
    )
    $launch = $null
    $scenarioResult = $false
    $primaryFailure = $null
    $ownedSnapshots = [System.Collections.Generic.List[object]]::new()
    try {
        $launch = Invoke-PspktWorkerScenarioLaunch -Binding $Binding -Scenario $Scenario -SnapshotRoot $SnapshotRoot -RepositoryRoot $repositoryRoot
        $session = $launch.Session
        $context = $launch.Context
        $state = [string]$session.State.ToString()
        $resumeScenarios = @('ResumeFailureZero', 'ResumeFailureNative', 'ResumeFailureMultiple')
        if ($Scenario -ceq 'SimulateAssignFailure') {
            $scenarioResult = ($state -ceq 'Exited' -and $session.QueryActiveProcesses() -eq 0)
        }
        elseif ($resumeScenarios -contains $Scenario) {
            if ($state -ceq 'Exited') {
                $outcome = $session.GetResumeFailureOutcome()
                $scenarioResult = ($outcome.ActiveProcesses -eq 0 -and (-not $outcome.GateSignaled))
            }
        }
        elseif ($Scenario -ceq 'WorkerGateOpenFailure') {
            $waitStatus = $session.WaitWorker(15000)
            $resultAbsent = ([string]::IsNullOrEmpty($context.ResultPath)) -or (-not (Test-Path -LiteralPath $context.ResultPath))
            $scenarioResult = (
                (Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0') -and
                $session.GetExitCode() -eq 10 -and
                $session.QueryActiveProcesses() -eq 0 -and
                $resultAbsent)
        }
        elseif ($Scenario -ceq 'WorkerGateTimeout') {
            $status = $session.WaitWorker(45000)
            $resultAbsent = ([string]::IsNullOrEmpty($context.ResultPath)) -or (-not (Test-Path -LiteralPath $context.ResultPath))
            $descendantAbsent = ([string]::IsNullOrEmpty($context.DescendantResultPath)) -or (-not (Test-Path -LiteralPath $context.DescendantResultPath))
            $scenarioResult = (
                (Test-PspktHelperEnumEquals -Value $status -Member 'Object0') -and
                $session.GetExitCode() -eq 11 -and
                $resultAbsent -and
                $descendantAbsent -and
                $session.QueryActiveProcesses() -eq 0)
        }
        elseif ($Scenario -ceq 'WorkerTimeout') {
            if ($null -eq $context.WorkerTimeoutReadyEvent) {
                throw 'worker timeout parent did not retain the ready event before Worker start.'
            }
            $session.SignalWorkerGate()
            if (-not (Wait-PspktNamedEventSignal -NamedEvent $context.WorkerTimeoutReadyEvent -TimeoutMs 10000)) {
                throw 'worker timeout ready event was not observed within 10 seconds.'
            }
            $timeoutDeadline = [System.Diagnostics.Stopwatch]::StartNew()
            $liveStatus = $session.WaitWorker(0)
            if (-not (Test-PspktHelperEnumEquals -Value $liveStatus -Member 'Timeout')) {
                throw 'worker timeout process was not live when readiness was observed.'
            }
            $remainingMilliseconds = 2000 - [int]$timeoutDeadline.ElapsedMilliseconds
            if ($remainingMilliseconds -lt 0) {
                $remainingMilliseconds = 0
            }
            $status = $session.WaitWorker($remainingMilliseconds)
            if (-not (Test-PspktHelperEnumEquals -Value $status -Member 'Timeout')) {
                throw 'worker timeout process did not yield WAIT_TIMEOUT at the two-second deadline.'
            }
            if ($timeoutDeadline.ElapsedMilliseconds -lt 2000) {
                $status = $session.WaitWorker(2000 - [int]$timeoutDeadline.ElapsedMilliseconds)
                if (-not (Test-PspktHelperEnumEquals -Value $status -Member 'Timeout')) {
                    throw 'worker timeout process exited before the exact two-second deadline.'
                }
            }
            $resultAbsent = ([string]::IsNullOrEmpty($context.ResultPath)) -or (-not (Test-Path -LiteralPath $context.ResultPath))
            if (-not $resultAbsent) {
                throw 'worker timeout scenario emitted a sealed result before authoritative termination.'
            }
            $activeAfterTermination = $session.TerminateAndWait(15000)
            $scenarioResult = (
                $activeAfterTermination -eq 0 -and
                [string]$session.State.ToString() -ceq 'Exited' -and
                (([string]::IsNullOrEmpty($context.ResultPath)) -or (-not (Test-Path -LiteralPath $context.ResultPath))))
        }
        elseif ($Scenario -ceq 'WorkerLeavesDescendant') {
            $descendantEvents = New-PspktOuterOwnedDescendantEvents -Binding $Binding -Context $context
            $workerBaselineRoot = $null
            $workerBaselineRoot = Get-PspktStableJobSnapshot -Session $session -MinIntervalMs 50 -TimeoutMs 10000
            if ($null -ne $workerBaselineRoot) {
                [void]$ownedSnapshots.Add($workerBaselineRoot)
            }
            if ($null -ne $workerBaselineRoot -and
                (Test-PspktRootTopology -Members $workerBaselineRoot.Members -RootPid $session.RootProcessId -RootStart $session.RootStartTimeFileTimeUtc -RootImage $session.RootImagePath)) {
                $session.SignalWorkerGate()
                $waitStatus = $session.WaitWorker(30000)
                if ((Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0') -and
                    $session.GetExitCode() -eq 0 -and
                    -not [string]::IsNullOrEmpty($context.DescendantResultPath) -and
                    -not [string]::IsNullOrEmpty($context.DescendantNonce)) {
                    $receipt = Read-PspktWorkerDescendantReceipt -ResultPath $context.DescendantResultPath -ExpectedNonce $context.DescendantNonce
                    $rootImage = [string]$session.RootImagePath
                    $survivorOk = $false
                    $deadline = [System.Diagnostics.Stopwatch]::StartNew()
                    while ($deadline.Elapsed.TotalSeconds -lt 10) {
                        $survivor = Get-PspktStableJobSnapshot -Session $session -TimeoutMs 2000
                        if ($null -ne $survivor) {
                            $survivorPrimaryFailure = $null
                            $survivorResolved = $false
                            try {
                                $survivorMembers = $survivor.Members
                                $survivorAccounting = $session.QueryJobAccounting()
                                if ($survivor.RevalidateLive() -and
                                    [bool]$workerBaselineRoot.MatchRetainedIdentityAllowExited() -and
                                    (Test-PspktWorkerLeavesSurvivorMembership -SurvivorMembers $survivorMembers -WorkerBaselineMembers $workerBaselineRoot.Members -WorkerRootPid $session.RootProcessId -DescendantPid $receipt.Pid -DescendantStart $receipt.StartFileTimeUtc -DescendantImage $rootImage) -and
                                    [long]$survivorAccounting.ActiveProcesses -eq [long]$survivorMembers.Count) {
                                    $survivorResolved = $true
                                }
                            }
                            catch {
                                $survivorPrimaryFailure = Get-PspktInnermostException -Exception $_.Exception
                            }
                            $survivorCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
                            try {
                                if (-not (Close-PspktJobSnapshot -Snapshot $survivor)) {
                                    [void]$survivorCleanupFailures.Add([System.InvalidOperationException]::new('worker descendant survivor snapshot cleanup did not report DisposeSucceeded.'))
                                }
                            }
                            catch {
                                [void]$survivorCleanupFailures.Add($_.Exception)
                            }
                            $survivorFailure = New-PspktComposedFailure -Message 'worker descendant survivor snapshot primary and cleanup failures.' -PrimaryFailure $survivorPrimaryFailure -CleanupFailures ([Exception[]]$survivorCleanupFailures.ToArray())
                            if ($null -ne $survivorFailure) {
                                throw $survivorFailure
                            }
                            if ($survivorResolved) {
                                $survivorOk = $true
                                break
                            }
                        }
                        Start-Sleep -Milliseconds 100
                    }

                    $vectorsOk = (Test-PspktWorkerDescendantReceiptNegativeVectors) -and (Test-PspktWorkerLeavesDescendantOracleRootVector)
                    $activeAfterTermination = $session.TerminateAndWait(15000)
                    $scenarioResult = (
                        $survivorOk -and
                        $vectorsOk -and
                        $activeAfterTermination -eq 0 -and
                        [string]$session.State.ToString() -ceq 'Exited')
                }
            }
        }
        elseif ($Scenario -ceq 'WorkerNonzeroExit') {
            $session.SignalWorkerGate()
            $waitStatus = $session.WaitWorker(30000)
            $scenarioResult = (
                (Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0') -and
                $session.GetExitCode() -eq 13 -and
                $session.QueryActiveProcesses() -eq 0)
        }
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    Complete-PspktWorkerLaunch -Launch $launch -PrimaryFailure $primaryFailure -Snapshots ([object[]]$ownedSnapshots.ToArray()) -Message (
        'worker fault scenario "{0}" primary and cleanup failures.' -f $Scenario)
    return $scenarioResult
}

function Invoke-PspktRunNormalWorker {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot
    )
    $outcome = [pscustomobject]@{
        HelperHandoff = $false
        CountRise = $false
        CountFall = $false
        ExitZero = $false
        ResultAccepted = $false
        NoDescendants = $false
    }
    $launch = $null
    $ownedEvents = @{}
    $baselineRoot = $null
    $primaryFailure = $null
    try {
        $launch = Invoke-PspktWorkerScenarioLaunch -Binding $Binding -Scenario 'Normal' -SnapshotRoot $SnapshotRoot -RepositoryRoot $repositoryRoot
        $session = $launch.Session
        $context = $launch.Context
        $outcome.HelperHandoff = ($session.ProcessId -gt 0)

        $ownedEvents = New-PspktOuterOwnedNestedEvents -Binding $Binding -Context $context

        $baselineRoot = Get-PspktStableJobSnapshot -Session $session -MinIntervalMs 50 -TimeoutMs 10000
        if ($null -ne $baselineRoot -and
            (Test-PspktRootTopology -Members $baselineRoot.Members -RootPid $session.RootProcessId -RootStart $session.RootStartTimeFileTimeUtc -RootImage $session.RootImagePath)) {
            $session.SignalWorkerGate()
            $sequenceOk = Invoke-PspktNestedProofSequence -Binding $Binding -Session $session -Context $context -OwnedEvents $ownedEvents -Outcome $outcome -BaselineRoot $baselineRoot
            if ($sequenceOk) {
                $status = $session.WaitWorker(600000)
                if (Test-PspktHelperEnumEquals -Value $status -Member 'Object0') {
                    $exitCode = $session.GetExitCode()
                    $outcome.ExitZero = ($exitCode -eq 0)
                }
            }
            if ($outcome.ExitZero) {
                $fall = $session.QueryActiveProcesses()
                $outcome.NoDescendants = ($fall -eq 0)
            }
            if ($outcome.ExitZero -and -not [string]::IsNullOrEmpty($context.ResultPath)) {
                $outcome.ResultAccepted = Read-PspktSealedWorkerResult -ResultPath $context.ResultPath -ExpectedNonce $context.Nonce -ExpectedVersion $Binding.Version -ExpectedCheckIds $script:ExpectedWorkerCheckIds
            }
        }
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    $snapshots = [object[]]@()
    if ($null -ne $baselineRoot) {
        $snapshots = [object[]]@($baselineRoot)
    }
    Complete-PspktWorkerLaunch -Launch $launch -PrimaryFailure $primaryFailure -Snapshots $snapshots -Message 'normal worker primary and cleanup failures.'
    return $outcome
}

function New-PspktOuterOwnedNestedEvents {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)]$Context
    )
    $owned = @{}
    $ownedRoles = @{
        'PSPKT_PHASE4_NESTED_EVIDENCE_READY' = 'NestedEvidenceReady'
        'PSPKT_PHASE4_NESTED_RELEASE_AUTHORIZED' = 'NestedReleaseAuthorized'
        'PSPKT_PHASE4_NESTED_CHILD_EXITED' = 'NestedChildExited'
        'PSPKT_PHASE4_NESTED_PROOF_COMPLETE' = 'NestedProofComplete'
    }
    foreach ($envName in $ownedRoles.Keys) {
        if (-not $Context.EventNames.ContainsKey($envName)) { continue }
        $eventName = $Context.EventNames[$envName]
        $role = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member $ownedRoles[$envName]
        $evt = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($eventName, $role, [Guid]::Empty)
        $owned[$envName] = $evt
        [void]$Context.OwnedEvents.Add($evt)
    }
    return $owned
}

function Wait-PspktNamedEventSignal {
    param(
        [Parameter(Mandatory = $true)]$NamedEvent,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )
    $status = $NamedEvent.Wait($TimeoutMs)
    return (Test-PspktHelperEnumEquals -Value $status -Member 'Object0')
}

function ConvertFrom-PspktNestedReceiptBytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$ExpectedTag,
        [Parameter(Mandatory = $true)][ValidateSet('membership', 'exit')][string]$Kind
    )
    if ($null -eq $Bytes) { throw 'nested receipt: null bytes.' }
    $len = $Bytes.Length
    if ($len -lt 1) { throw 'nested receipt: empty payload.' }
    if ($len -gt 320) { throw 'nested receipt: exceeds the 320-byte cap.' }
    if ($len -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { throw 'nested receipt: unexpected BOM.' }
    if ($Bytes[$len - 1] -ne 0x0A) { throw 'nested receipt: missing terminal LF.' }
    for ($i = 0; $i -lt ($len - 1); $i++) {
        $bv = $Bytes[$i]
        if ($bv -eq 0x0A) { throw 'nested receipt: embedded LF.' }
        if ($bv -eq 0x09) { continue }
        if ($bv -lt 0x20 -or $bv -gt 0x7E) { throw 'nested receipt: non-printable or non-ASCII byte.' }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, $len - 1)
    $fields = $text.Split([char]0x09)
    if ($fields.Count -ne 6) { throw 'nested receipt: field count mismatch.' }
    if ($fields[0] -cne $ExpectedTag) { throw 'nested receipt: tag mismatch.' }
    if (-not [regex]::IsMatch($fields[1], '^[0-9a-f]{32}$')) { throw 'nested receipt: nonce grammar.' }
    if (-not [regex]::IsMatch($fields[2], '^[0-9a-f]{32}$')) { throw 'nested receipt: correlation grammar.' }
    if ($fields[3].Length -lt 1 -or $fields[3].Length -gt 10 -or -not [regex]::IsMatch($fields[3], '^(0|[1-9][0-9]*)$')) { throw 'nested receipt: pid grammar.' }
    [uint32]$pidValue = [uint32]::Parse($fields[3], [System.Globalization.CultureInfo]::InvariantCulture)
    if ($pidValue.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $fields[3]) { throw 'nested receipt: pid not canonical.' }
    if ($fields[4].Length -lt 1 -or $fields[4].Length -gt 19 -or -not [regex]::IsMatch($fields[4], '^(0|[1-9][0-9]*)$')) { throw 'nested receipt: start grammar.' }
    [long]$startValue = [long]::Parse($fields[4], [System.Globalization.CultureInfo]::InvariantCulture)
    if ($startValue.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $fields[4]) { throw 'nested receipt: start not canonical.' }
    $exitCode = 0
    if ($Kind -ceq 'membership') {
        if ($fields[5] -cne 'true') { throw 'nested receipt: membership flag is not the literal "true".' }
    }
    else {
        if (-not [regex]::IsMatch($fields[5], '^(0|-?[1-9][0-9]*)$')) { throw 'nested receipt: exit-code grammar.' }
        [int]$exitCode = [int]::Parse($fields[5], [System.Globalization.CultureInfo]::InvariantCulture)
        if ($exitCode.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $fields[5]) { throw 'nested receipt: exit-code not canonical.' }
    }
    return [pscustomobject]@{
        Tag = $fields[0]
        Nonce = $fields[1]
        Correlation = $fields[2]
        Pid = $pidValue
        StartFileTimeUtc = $startValue
        ExitCode = $exitCode
        MembershipTrue = ($Kind -ceq 'membership')
    }
}

function Read-PspktNestedReceiptFile {
    param(
        [Parameter(Mandatory = $true)][string]$ControlRoot,
        [Parameter(Mandatory = $true)][string]$Leaf,
        [Parameter(Mandatory = $true)][string]$ExpectedTag,
        [Parameter(Mandatory = $true)][ValidateSet('membership', 'exit')][string]$Kind
    )
    $path = Join-Path $ControlRoot $Leaf
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('nested receipt: "{0}" is absent.' -f $path) }
    $bytes = Read-PspktBoundedFileBytes -FullPath $path -ByteCap 320
    return (ConvertFrom-PspktNestedReceiptBytes -Bytes $bytes -ExpectedTag $ExpectedTag -Kind $Kind)
}

function New-PspktNestedReceiptBytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Fields,
        [string]$Terminator = "`n"
    )
    $tab = [string][char]0x09
    $text = ($Fields -join $tab) + $Terminator
    return ,[System.Text.Encoding]::ASCII.GetBytes($text)
}

function Test-PspktNestedReceiptVectors {
    param(
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][ValidateSet('membership', 'exit')][string]$Kind
    )
    $nonce = [guid]::NewGuid().ToString('N')
    $corr = [guid]::NewGuid().ToString('N')
    $sixth = if ($Kind -ceq 'membership') { 'true' } else { '0' }
    $good = @($Tag, $nonce, $corr, '4321', '132000000000000000', $sixth)

    $accepted = $false
    try {
        $parsed = ConvertFrom-PspktNestedReceiptBytes -Bytes (New-PspktNestedReceiptBytes -Fields $good) -ExpectedTag $Tag -Kind $Kind
        $accepted = ($parsed.Nonce -ceq $nonce -and $parsed.Correlation -ceq $corr -and $parsed.Pid -eq 4321 -and $parsed.StartFileTimeUtc -eq 132000000000000000)
    }
    catch { $accepted = $false }
    if (-not $accepted) { return $false }

    $badSixthField = if ($Kind -ceq 'membership') { 'True' } else { '' }
    $badSixthTwo = if ($Kind -ceq 'membership') { '1' } else { '1.0' }
    $badSixthThree = if ($Kind -ceq 'membership') { 'false ' } else { '+0' }
    $badSixthFour = if ($Kind -ceq 'membership') { '' } else { '00' }

    $fieldMutations = @(
        @(($Tag + 'X'), $nonce, $corr, '4321', '132000000000000000', $sixth),
        @('', $nonce, $corr, '4321', '132000000000000000', $sixth),
        @($Tag, $nonce.ToUpperInvariant(), $corr, '4321', '132000000000000000', $sixth),
        @($Tag, ($nonce.Substring(0, 31)), $corr, '4321', '132000000000000000', $sixth),
        @($Tag, ($nonce.Substring(0, 31) + 'g'), $corr, '4321', '132000000000000000', $sixth),
        @($Tag, ('{' + $nonce.Substring(0, 30) + '}'), $corr, '4321', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr.ToUpperInvariant(), '4321', '132000000000000000', $sixth),
        @($Tag, $nonce, ($corr.Substring(0, 30)), '4321', '132000000000000000', $sixth),
        @($Tag, $nonce, ($corr.Substring(0, 31) + 'z'), '4321', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr, '04321', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr, '43a1', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr, '', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr, ' 4321', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr, '99999999999', '132000000000000000', $sixth),
        @($Tag, $nonce, $corr, '4321', '0132000000000000000', $sixth),
        @($Tag, $nonce, $corr, '4321', '13200000000000000x', $sixth),
        @($Tag, $nonce, $corr, '4321', '', $sixth),
        @($Tag, $nonce, $corr, '4321', '-1', $sixth),
        @($Tag, $nonce, $corr, '4321', '99999999999999999999', $sixth),
        @($Tag, $nonce, $corr, '4321', '132000000000000000', $badSixthField),
        @($Tag, $nonce, $corr, '4321', '132000000000000000', $badSixthTwo),
        @($Tag, $nonce, $corr, '4321', '132000000000000000', $badSixthThree),
        @($Tag, $nonce, $corr, '4321', '132000000000000000', $badSixthFour),
        @($Tag, $nonce, $corr, '4321', '132000000000000000'),
        @($Tag, $nonce, $corr, '4321', '132000000000000000', $sixth, 'extra')
    )
    foreach ($mutation in $fieldMutations) {
        $bytes = New-PspktNestedReceiptBytes -Fields ([string[]]$mutation)
        if (-not (Test-PspktThrows { ConvertFrom-PspktNestedReceiptBytes -Bytes $bytes -ExpectedTag $Tag -Kind $Kind })) { return $false }
    }

    $tab = [string][char]0x09
    $joined = ($good -join $tab)
    $goodBytes = New-PspktNestedReceiptBytes -Fields $good
    $nulBytes = [byte[]]::new($goodBytes.Length + 1)
    [System.Array]::Copy($goodBytes, 0, $nulBytes, 0, 3)
    $nulBytes[3] = 0x00
    [System.Array]::Copy($goodBytes, 3, $nulBytes, 4, $goodBytes.Length - 3)
    $bomBytes = [byte[]]::new($goodBytes.Length + 3)
    $bomBytes[0] = 0xEF; $bomBytes[1] = 0xBB; $bomBytes[2] = 0xBF
    [System.Array]::Copy($goodBytes, 0, $bomBytes, 3, $goodBytes.Length)
    $highByteBytes = [byte[]]$goodBytes.Clone()
    $highByteBytes[0] = 0x80
    $rawMutations = @(
        [System.Text.Encoding]::ASCII.GetBytes($joined),
        [System.Text.Encoding]::ASCII.GetBytes($joined + "`r`n"),
        [System.Text.Encoding]::ASCII.GetBytes($joined + "`n`n"),
        [System.Text.Encoding]::ASCII.GetBytes($joined + "`nx"),
        [System.Text.Encoding]::ASCII.GetBytes(($good[0..4] -join $tab) + ' ' + $good[5] + "`n"),
        $highByteBytes,
        $bomBytes,
        $nulBytes,
        (New-PspktNestedReceiptBytes -Fields @($Tag, $nonce, $corr, '4321', ('1' * 400), $sixth)),
        [byte[]]@(0x0A)
    )
    foreach ($bytes in $rawMutations) {
        if (-not (Test-PspktThrows { ConvertFrom-PspktNestedReceiptBytes -Bytes ([byte[]]$bytes) -ExpectedTag $Tag -Kind $Kind })) { return $false }
    }
    return $true
}

function Test-PspktNestedMembershipReceiptNegativeVectors {
    return (Test-PspktNestedReceiptVectors -Tag 'pspkt-phase4-nested-membership-v1' -Kind 'membership')
}

function Test-PspktNestedChildExitReceiptNegativeVectors {
    return (Test-PspktNestedReceiptVectors -Tag 'pspkt-phase4-nested-exit-v1' -Kind 'exit')
}

function Close-PspktJobSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)
    $Snapshot.Dispose()
    return ([bool]$Snapshot.DisposeSucceeded -and $Snapshot.GetCloseErrors().Length -eq 0)
}

function Complete-PspktJobSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [AllowNull()]
        [Exception]$PrimaryFailure = $null,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    try {
        if (-not (Close-PspktJobSnapshot -Snapshot $Snapshot)) {
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new('job snapshot cleanup did not report DisposeSucceeded.'))
        }
    }
    catch {
        [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
    }
    $failure = New-PspktComposedFailure -Message $Message -PrimaryFailure $PrimaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
    if ($null -ne $failure) {
        throw $failure
    }
}

function Get-PspktStableJobSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [int]$MinIntervalMs = 50,
        [int]$TimeoutMs = 10000
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.Elapsed.TotalMilliseconds -lt $TimeoutMs) {
        $first = $null
        $second = $null
        $stable = $false
        $primaryFailure = $null
        try {
            $first = $Session.CaptureActiveProcessSnapshot()
            Start-Sleep -Milliseconds $MinIntervalMs
            $second = $Session.CaptureActiveProcessSnapshot()
            if ($first.RevalidateLive() -and $second.RevalidateLive() -and $second.MembersEqual($first)) {
                $stable = $true
            }
        }
        catch {
            $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
        }
        $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
        if ($null -ne $second) {
            try {
                if (-not (Close-PspktJobSnapshot -Snapshot $second)) {
                    [void]$cleanupFailures.Add([System.InvalidOperationException]::new('stable job snapshot cleanup did not report DisposeSucceeded for the second sample.'))
                }
            }
            catch {
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
            $second = $null
        }
        if ($stable -and $null -eq $primaryFailure -and $cleanupFailures.Count -eq 0) {
            $retained = $first
            $first = $null
            return $retained
        }
        if ($null -ne $first) {
            try {
                if (-not (Close-PspktJobSnapshot -Snapshot $first)) {
                    [void]$cleanupFailures.Add([System.InvalidOperationException]::new('stable job snapshot cleanup did not report DisposeSucceeded for the first sample.'))
                }
            }
            catch {
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
            $first = $null
        }
        $failure = New-PspktComposedFailure -Message 'stable job snapshot primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
        if ($null -ne $failure) {
            throw $failure
        }
    }
    return $null
}

function Test-PspktCanonicalSystem32Conhost {
    param(
        [Parameter(Mandatory = $true)]$Member,
        [Parameter(Mandatory = $true)][int]$ExpectedParentPid
    )
    if ([int]$Member.ParentProcessId -ne $ExpectedParentPid) { return $false }
    $image = [string]$Member.CanonicalImagePath
    if ([string]::IsNullOrEmpty($image)) { return $false }
    $systemRoot = [string][Environment]::GetEnvironmentVariable('SystemRoot')
    if ([string]::IsNullOrEmpty($systemRoot)) { return $false }
    $expected = [System.IO.Path]::Combine($systemRoot, 'System32', 'conhost.exe')
    if (-not [string]::Equals($image, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    $conhostInfo = [System.IO.FileInfo]::new($expected)
    return ($conhostInfo.Exists -and
        ($conhostInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        ($conhostInfo.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0)
}

function Test-PspktRootTopology {
    param(
        [Parameter(Mandatory = $true)][object[]]$Members,
        [Parameter(Mandatory = $true)][int]$RootPid,
        [Parameter(Mandatory = $true)][long]$RootStart,
        [Parameter(Mandatory = $true)][string]$RootImage
    )
    $rootMember = $null
    $others = [System.Collections.Generic.List[object]]::new()
    foreach ($member in $Members) {
        if ([int]$member.ProcessId -eq $RootPid) {
            if ($null -ne $rootMember) { return $false }
            if ([long]$member.CreationFileTimeUtc -ne $RootStart) { return $false }
            if (-not [string]::Equals([string]$member.CanonicalImagePath, $RootImage, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
            $rootMember = $member
        }
        else {
            [void]$others.Add($member)
        }
    }
    if ($null -eq $rootMember) { return $false }
    if ($others.Count -eq 0) { return $true }
    if ($others.Count -ne 1) { return $false }
    return (Test-PspktCanonicalSystem32Conhost -Member $others[0] -ExpectedParentPid $RootPid)
}

function Test-PspktWorkerLeavesSurvivorMembership {
    param(
        [Parameter(Mandatory = $true)][object[]]$SurvivorMembers,
        [Parameter(Mandatory = $true)][object[]]$WorkerBaselineMembers,
        [Parameter(Mandatory = $true)][int]$WorkerRootPid,
        [Parameter(Mandatory = $true)][int]$DescendantPid,
        [Parameter(Mandatory = $true)][long]$DescendantStart,
        [Parameter(Mandatory = $true)][string]$DescendantImage
    )
    $workerConhost = $null
    foreach ($baselineMember in $WorkerBaselineMembers) {
        if ([int]$baselineMember.ProcessId -eq $WorkerRootPid) { continue }
        if ($null -ne $workerConhost -or
            -not (Test-PspktCanonicalSystem32Conhost -Member $baselineMember -ExpectedParentPid $WorkerRootPid)) {
            return $false
        }
        $workerConhost = $baselineMember
    }

    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($survivorMember in $SurvivorMembers) {
        if ([int]$survivorMember.ProcessId -eq $WorkerRootPid) { return $false }
        [void]$remaining.Add($survivorMember)
    }
    if ($null -ne $workerConhost) {
        $workerConhostIndex = -1
        for ($index = 0; $index -lt $remaining.Count; $index++) {
            if ([bool]$remaining[$index].Equals($workerConhost)) {
                $workerConhostIndex = $index
                break
            }
        }
        if ($workerConhostIndex -lt 0) { return $false }
        $remaining.RemoveAt($workerConhostIndex)
    }

    $descendantIndex = -1
    for ($index = 0; $index -lt $remaining.Count; $index++) {
        $candidate = $remaining[$index]
        if ([int]$candidate.ProcessId -eq $DescendantPid) {
            if ([long]$candidate.CreationFileTimeUtc -ne $DescendantStart -or
                -not [string]::Equals([string]$candidate.CanonicalImagePath, $DescendantImage, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
            $descendantIndex = $index
            break
        }
    }
    if ($descendantIndex -lt 0) { return $false }
    $remaining.RemoveAt($descendantIndex)
    if ($remaining.Count -eq 0) { return $true }
    if ($remaining.Count -ne 1) { return $false }
    return (Test-PspktCanonicalSystem32Conhost -Member $remaining[0] -ExpectedParentPid $DescendantPid)
}

function Test-PspktJobMemberSetEqual {
    param(
        [Parameter(Mandatory = $true)][object[]]$Left,
        [Parameter(Mandatory = $true)][object[]]$Right
    )
    if ($Left.Count -ne $Right.Count) { return $false }
    $used = [bool[]]::new($Right.Count)
    foreach ($leftMember in $Left) {
        $matched = $false
        for ($index = 0; $index -lt $Right.Count; $index++) {
            if ($used[$index]) { continue }
            if ([bool]$leftMember.Equals($Right[$index])) {
                $used[$index] = $true
                $matched = $true
                break
            }
        }
        if (-not $matched) { return $false }
    }
    return $true
}

function Test-PspktNestedRiseMembership {
    param(
        [Parameter(Mandatory = $true)][object[]]$RiseMembers,
        [Parameter(Mandatory = $true)][object[]]$BaselineMembers,
        [Parameter(Mandatory = $true)][int]$ChildPid,
        [Parameter(Mandatory = $true)][long]$ChildStart,
        [Parameter(Mandatory = $true)][string]$ChildImage
    )
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($member in $RiseMembers) { [void]$remaining.Add($member) }
    foreach ($baselineMember in $BaselineMembers) {
        $found = -1
        for ($index = 0; $index -lt $remaining.Count; $index++) {
            if ([bool]$remaining[$index].Equals($baselineMember)) { $found = $index; break }
        }
        if ($found -lt 0) { return $false }
        $remaining.RemoveAt($found)
    }
    $childIndex = -1
    for ($index = 0; $index -lt $remaining.Count; $index++) {
        if ([int]$remaining[$index].ProcessId -eq $ChildPid) { $childIndex = $index; break }
    }
    if ($childIndex -lt 0) { return $false }
    $childMember = $remaining[$childIndex]
    if ([long]$childMember.CreationFileTimeUtc -ne $ChildStart) { return $false }
    if (-not [string]::Equals([string]$childMember.CanonicalImagePath, $ChildImage, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    $remaining.RemoveAt($childIndex)
    if ($remaining.Count -eq 0) { return $true }
    if ($remaining.Count -ne 1) { return $false }
    return (Test-PspktCanonicalSystem32Conhost -Member $remaining[0] -ExpectedParentPid $ChildPid)
}

function ConvertFrom-PspktWorkerDescendantBytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [byte[]]$Bytes,
        [AllowNull()]
        [string]$ExpectedNonce = $null
    )
    if ($null -eq $Bytes) { throw 'worker descendant receipt: null bytes.' }
    $len = $Bytes.Length
    if ($len -lt 1) { throw 'worker descendant receipt: empty payload.' }
    if ($len -gt 256) { throw 'worker descendant receipt: exceeds the 256-byte cap.' }
    if ($len -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { throw 'worker descendant receipt: unexpected BOM.' }
    if ($Bytes[$len - 1] -ne 0x0A) { throw 'worker descendant receipt: missing terminal LF.' }
    for ($index = 0; $index -lt $len - 1; $index++) {
        $bv = $Bytes[$index]
        if ($bv -eq 0x0A) { throw 'worker descendant receipt: embedded LF.' }
        if ($bv -eq 0x09) { continue }
        if ($bv -lt 0x20 -or $bv -gt 0x7E) { throw 'worker descendant receipt: non-printable or non-ASCII byte.' }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, $len - 1)
    $tab = [char]0x09
    $fields = $text.Split($tab)
    if ($fields.Count -ne 4) { throw 'worker descendant receipt: field count mismatch.' }
    if ($fields[0] -cne 'pspkt-phase4-worker-descendant-v1') { throw 'worker descendant receipt: tag mismatch.' }
    if (-not [regex]::IsMatch($fields[1], '^[0-9a-f]{32}$')) { throw 'worker descendant receipt: nonce grammar.' }
    if (-not [string]::IsNullOrEmpty($ExpectedNonce) -and $fields[1] -cne $ExpectedNonce) { throw 'worker descendant receipt: nonce mismatch.' }
    if ($fields[2].Length -lt 1 -or $fields[2].Length -gt 10 -or -not [regex]::IsMatch($fields[2], '^(0|[1-9][0-9]*)$')) { throw 'worker descendant receipt: pid grammar.' }
    $pidValue = [uint32]0
    if (-not [uint32]::TryParse($fields[2], [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$pidValue)) { throw 'worker descendant receipt: pid range.' }
    if (([uint32]$pidValue).ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $fields[2]) { throw 'worker descendant receipt: pid not canonical.' }
    if ($fields[3].Length -lt 1 -or $fields[3].Length -gt 20 -or -not [regex]::IsMatch($fields[3], '^(0|-?[1-9][0-9]*)$')) { throw 'worker descendant receipt: start grammar.' }
    $startValue = [long]0
    if (-not [long]::TryParse($fields[3], [System.Globalization.NumberStyles]::AllowLeadingSign, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$startValue)) { throw 'worker descendant receipt: start range.' }
    if ($startValue.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $fields[3]) { throw 'worker descendant receipt: start not canonical.' }
    return [pscustomobject]@{
        Tag = $fields[0]
        Nonce = $fields[1]
        Pid = [int]$pidValue
        StartFileTimeUtc = $startValue
    }
}

function Read-PspktWorkerDescendantReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce
    )
    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) { throw ('worker descendant receipt: "{0}" is absent.' -f $ResultPath) }
    $bytes = Read-PspktBoundedFileBytes -FullPath $ResultPath -ByteCap 256
    return (ConvertFrom-PspktWorkerDescendantBytes -Bytes $bytes -ExpectedNonce $ExpectedNonce)
}

function Test-PspktWorkerDescendantReceiptNegativeVectors {
    $tag = 'pspkt-phase4-worker-descendant-v1'
    $nonce = [guid]::NewGuid().ToString('N')
    $good = @($tag, $nonce, '4321', '132000000000000000')
    $tabc = [string][char]0x09
    $accepted = $false
    try {
        $goodBytes = [System.Text.Encoding]::ASCII.GetBytes(($good -join $tabc) + "`n")
        $parsed = ConvertFrom-PspktWorkerDescendantBytes -Bytes $goodBytes -ExpectedNonce $nonce
        $accepted = ($parsed.Nonce -ceq $nonce -and $parsed.Pid -eq 4321 -and $parsed.StartFileTimeUtc -eq 132000000000000000)
    }
    catch { $accepted = $false }
    if (-not $accepted) { return $false }

    $fieldMutations = @(
        @(($tag + 'X'), $nonce, '4321', '132000000000000000'),
        @('', $nonce, '4321', '132000000000000000'),
        @($tag, $nonce.ToUpperInvariant(), '4321', '132000000000000000'),
        @($tag, ($nonce.Substring(0, 31)), '4321', '132000000000000000'),
        @($tag, ($nonce.Substring(0, 31) + 'g'), '4321', '132000000000000000'),
        @($tag, ('{' + $nonce.Substring(0, 30) + '}'), '4321', '132000000000000000'),
        @($tag, $nonce, '04321', '132000000000000000'),
        @($tag, $nonce, '43a1', '132000000000000000'),
        @($tag, $nonce, '', '132000000000000000'),
        @($tag, $nonce, ' 4321', '132000000000000000'),
        @($tag, $nonce, '99999999999', '132000000000000000'),
        @($tag, $nonce, '4321', '0132000000000000000'),
        @($tag, $nonce, '4321', '13200000000000000x'),
        @($tag, $nonce, '4321', ''),
        @($tag, $nonce, '4321', '132000000000000000', 'extra'),
        @($tag, $nonce, '4321')
    )
    foreach ($mutation in $fieldMutations) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes((([string[]]$mutation) -join $tabc) + "`n")
        if (-not (Test-PspktThrows { ConvertFrom-PspktWorkerDescendantBytes -Bytes $bytes -ExpectedNonce $nonce })) { return $false }
    }

    $mismatchBytes = [System.Text.Encoding]::ASCII.GetBytes(($good -join $tabc) + "`n")
    if (-not (Test-PspktThrows { ConvertFrom-PspktWorkerDescendantBytes -Bytes $mismatchBytes -ExpectedNonce ([guid]::NewGuid().ToString('N')) })) { return $false }

    $joined = ($good -join $tabc)
    $goodRaw = [System.Text.Encoding]::ASCII.GetBytes($joined + "`n")
    $bomBytes = [byte[]]::new($goodRaw.Length + 3)
    $bomBytes[0] = 0xEF; $bomBytes[1] = 0xBB; $bomBytes[2] = 0xBF
    [System.Array]::Copy($goodRaw, 0, $bomBytes, 3, $goodRaw.Length)
    $highByteBytes = [byte[]]$goodRaw.Clone()
    $highByteBytes[0] = 0x80
    $nulBytes = [byte[]]::new($goodRaw.Length + 1)
    [System.Array]::Copy($goodRaw, 0, $nulBytes, 0, 3)
    $nulBytes[3] = 0x00
    [System.Array]::Copy($goodRaw, 3, $nulBytes, 4, $goodRaw.Length - 3)
    $oversize = [System.Text.Encoding]::ASCII.GetBytes(($tag + $tabc + $nonce + $tabc + '4321' + $tabc + ('1' * 300)) + "`n")
    $rawMutations = @(
        [System.Text.Encoding]::ASCII.GetBytes($joined),
        [System.Text.Encoding]::ASCII.GetBytes($joined + "`r`n"),
        [System.Text.Encoding]::ASCII.GetBytes($joined + "`n`n"),
        $bomBytes,
        $highByteBytes,
        $nulBytes,
        $oversize,
        ([byte[]]@(0x0A))
    )
    foreach ($bytes in $rawMutations) {
        if (-not (Test-PspktThrows { ConvertFrom-PspktWorkerDescendantBytes -Bytes ([byte[]]$bytes) -ExpectedNonce $nonce })) { return $false }
    }
    return $true
}

function Test-PspktWorkerLeavesDescendantOracleRootVector {
    $tempRoot = [System.IO.Path]::GetTempPath()
    $ok = $false
    $tempDirs = [System.Collections.Generic.List[string]]::new()
    $outerOwnedRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-res-'
    [void]$tempDirs.Add($outerOwnedRoot)
    try {
        $simulatedResultPath = Join-Path $outerOwnedRoot ('result-' + [Guid]::NewGuid().ToString('N') + '.txt')
        $descendantResultRoot = [System.IO.Path]::GetDirectoryName($simulatedResultPath)

        $wldBefore = @(Get-ChildItem -LiteralPath $tempRoot -Directory -Filter 'pspkt-phase4-wld-*' -ErrorAction Stop | ForEach-Object { $_.FullName })

        $oracleContext = New-PspktProcessOracleContext -Tag 'wld' -ParentAuthorityRoot $descendantResultRoot

        $wldAfter = @(Get-ChildItem -LiteralPath $tempRoot -Directory -Filter 'pspkt-phase4-wld-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
        $noStandaloneWld = ($wldAfter.Count -eq $wldBefore.Count)

        $descendantScriptPath = Join-Path $oracleContext.WorkingDirectory ('descendant-' + [Guid]::NewGuid().ToString('N') + '.ps1')
        [System.IO.File]::WriteAllBytes($descendantScriptPath, [byte[]](1, 2, 3))

        $canonicalOuter = [System.IO.Path]::GetFullPath($outerOwnedRoot).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar)
        $outerPrefix = $canonicalOuter + [System.IO.Path]::DirectorySeparatorChar
        $canonicalRoot = [System.IO.Path]::GetFullPath($oracleContext.Root)
        $canonicalWorking = [System.IO.Path]::GetFullPath($oracleContext.WorkingDirectory)
        $contained = (
            $canonicalRoot.StartsWith($outerPrefix, [System.StringComparison]::Ordinal) -and
            $canonicalWorking.StartsWith($outerPrefix, [System.StringComparison]::Ordinal) -and
            ([System.IO.Path]::GetDirectoryName($canonicalRoot).TrimEnd(
                [System.IO.Path]::DirectorySeparatorChar,
                [System.IO.Path]::AltDirectorySeparatorChar) -ceq $canonicalOuter))
        $nonReparse = (
            (Test-PspktNonReparseDirectory -FullPath $canonicalOuter) -and
            (Test-PspktNonReparseDirectory -FullPath $canonicalRoot) -and
            (Test-PspktNonReparseDirectory -FullPath $canonicalWorking))
        $childPresentBeforeCleanup = (Test-Path -LiteralPath $descendantScriptPath -PathType Leaf)

        Remove-Item -LiteralPath $outerOwnedRoot -Recurse -Force -ErrorAction Stop
        [void]$tempDirs.Remove($outerOwnedRoot)
        $removedByParentCleanup = (
            (-not (Test-Path -LiteralPath $oracleContext.Root)) -and
            (-not (Test-Path -LiteralPath $descendantScriptPath)) -and
            (-not (Test-Path -LiteralPath $outerOwnedRoot)))

        $referenceTemp = New-PspktTempDirectory -Prefix 'pspkt-phase4-wldref-'
        [void]$tempDirs.Add($referenceTemp)
        $canonicalTempParent = [System.IO.Path]::GetDirectoryName($referenceTemp).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar)

        $defaultContext = New-PspktProcessOracleContext -Tag 'wld-default'
        $defaultStandalone = $false
        try {
            $canonicalDefaultRoot = [System.IO.Path]::GetFullPath($defaultContext.Root)
            $defaultParent = [System.IO.Path]::GetDirectoryName($canonicalDefaultRoot).TrimEnd(
                [System.IO.Path]::DirectorySeparatorChar,
                [System.IO.Path]::AltDirectorySeparatorChar)
            $defaultStandalone = (
                ($defaultParent -ceq $canonicalTempParent) -and
                ([System.IO.Path]::GetFileName($canonicalDefaultRoot)).StartsWith('pspkt-phase4-wld-default-', [System.StringComparison]::Ordinal) -and
                (Test-PspktNonReparseDirectory -FullPath $canonicalDefaultRoot))
        }
        finally {
            Remove-PspktProcessOracleContext -Context $defaultContext
        }

        $bogusParent = Join-Path $tempRoot ('pspkt-phase4-absent-' + [Guid]::NewGuid().ToString('N'))
        $failsClosed = Test-PspktThrows { New-PspktProcessOracleContext -Tag 'wld' -ParentAuthorityRoot $bogusParent }

        $ok = (
            $noStandaloneWld -and
            $contained -and
            $nonReparse -and
            $childPresentBeforeCleanup -and
            $removedByParentCleanup -and
            $defaultStandalone -and
            $failsClosed)
    }
    finally {
        for ($directoryIndex = $tempDirs.Count - 1; $directoryIndex -ge 0; $directoryIndex--) {
            $dir = $tempDirs[$directoryIndex]
            if (Test-Path -LiteralPath $dir) {
                try {
                    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
                }
                catch {
                    $null = $_
                }
            }
        }
    }
    return $ok
}

function New-PspktOuterOwnedDescendantEvents {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)]$Context
    )
    $owned = @{}
    $ownedRoles = @{
        'PSPKT_PHASE4_DESCENDANT_GATE_EVENT' = 'Descendant'
        'PSPKT_PHASE4_DESCENDANT_WAITER_READY' = 'DescendantWaiterReady'
    }
    foreach ($envName in $ownedRoles.Keys) {
        if (-not $Context.EventNames.ContainsKey($envName)) { continue }
        $eventName = $Context.EventNames[$envName]
        $role = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member $ownedRoles[$envName]
        $evt = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'CreateNewManualReset' -Arguments @($eventName, $role, [Guid]::Empty)
        $owned[$envName] = $evt
        [void]$Context.OwnedEvents.Add($evt)
    }
    return $owned
}

function New-PspktWorkerDescendantChildScript {
    param([Parameter(Mandatory = $true)]$Context)
    $childScript = @'
$ErrorActionPreference = 'Stop'
try {
    $gateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_DESCENDANT_GATE_EVENT')
    $waiterReadyName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_DESCENDANT_WAITER_READY')
    $helperPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_PATH')
    $expectedHelperSha = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_SHA256')
    $expectedHelperVersion = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_VERSION')
    $timeoutText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS')
    $timeoutExitText = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE')
    if ([string]::IsNullOrEmpty($gateName) -or [string]::IsNullOrEmpty($waiterReadyName) -or [string]::IsNullOrEmpty($helperPath) -or [string]::IsNullOrEmpty($expectedHelperSha) -or [string]::IsNullOrEmpty($expectedHelperVersion) -or [string]::IsNullOrEmpty($timeoutText) -or [string]::IsNullOrEmpty($timeoutExitText)) { exit 7 }
    if (-not [regex]::IsMatch($gateName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 7 }
    if (-not [regex]::IsMatch($waiterReadyName, '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 7 }
    $timeoutMilliseconds = 0
    $timeoutExitCode = 0
    if (-not [int]::TryParse($timeoutText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$timeoutMilliseconds) -or $timeoutMilliseconds -lt 1) { exit 7 }
    if (-not [int]::TryParse($timeoutExitText, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$timeoutExitCode) -or $timeoutExitCode -lt 0) { exit 7 }
    $helperInfo = [System.IO.FileInfo]::new($helperPath)
    if (-not $helperInfo.Exists -or ($helperInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $helperInfo.Length -gt 4194304) { exit 7 }
    $helperStream = [System.IO.FileStream]::new($helperPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $helperBytes = [byte[]]::new([int]$helperStream.Length)
        $helperOffset = 0
        while ($helperOffset -lt $helperBytes.Length) {
            $helperRead = $helperStream.Read($helperBytes, $helperOffset, $helperBytes.Length - $helperOffset)
            if ($helperRead -le 0) { exit 7 }
            $helperOffset += $helperRead
        }
    }
    finally {
        $helperStream.Dispose()
    }
    $helperHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $helperHash = $helperHasher.ComputeHash($helperBytes)
    }
    finally {
        $helperHasher.Dispose()
    }
    $helperDigestBuilder = [System.Text.StringBuilder]::new(64)
    foreach ($helperHashByte in $helperHash) { [void]$helperDigestBuilder.Append($helperHashByte.ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture)) }
    if ($helperDigestBuilder.ToString() -cne $expectedHelperSha) { exit 7 }
    $helperAssembly = [System.Reflection.Assembly]::Load($helperBytes)
    $helperHostType = $helperAssembly.GetType('Pspkt.Certification.BoundedProcessHost', $true)
    $helperVersionField = $helperHostType.GetField('Version', [System.Reflection.BindingFlags]'Public, Static')
    if ([string]$helperVersionField.GetValue($null) -cne $expectedHelperVersion) { exit 7 }
    $preludeMethod = $helperHostType.GetMethod('RunReadyThenWaitPrelude', [Type[]]@([string], [string], [int], [int]))
    if ($null -eq $preludeMethod) { exit 7 }
    [void]$preludeMethod.Invoke($null, @($gateName, $waiterReadyName, $timeoutMilliseconds, $timeoutExitCode))
    exit 6
}
catch {
    exit 7
}
'@
    $scriptPath = Join-Path $Context.Root ('worker-descendant-child-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $normalized = [regex]::Replace($childScript, "\r\n|\r|\n", "`r`n")
    $bytes = (New-PspktUtf8NoBom).GetBytes($normalized + "`r`n")
    $stream = [System.IO.FileStream]::new($scriptPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $scriptPath
}

function Invoke-PspktWorkerLeavesDescendantLaunch {
    param([Parameter(Mandatory = $true)]$Binding)
    $gateName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_DESCENDANT_GATE_EVENT')
    $waiterName = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_DESCENDANT_WAITER_READY')
    $descendantNonce = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_DESCENDANT_NONCE')
    $resultPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_DESCENDANT_RESULT_PATH')
    $helperPath = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_PATH')
    $helperSha = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_SHA256')
    $helperVersion = [Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_VERSION')
    foreach ($authorityValue in @($gateName, $waiterName, $descendantNonce, $resultPath, $helperPath, $helperSha, $helperVersion)) {
        if ([string]::IsNullOrEmpty($authorityValue)) { return $false }
    }
    if (-not [regex]::IsMatch($descendantNonce, '^[0-9a-f]{32}$')) { return $false }
    $oracleContext = $null
    $waiterEvent = $null
    $launchResult = $false
    $primaryFailure = $null
    try {
        $descendantResultRoot = [System.IO.Path]::GetDirectoryName($resultPath)
        if ([string]::IsNullOrEmpty($descendantResultRoot)) {
            throw 'worker descendant launch: descendant result path has no parent authority root.'
        }
        $oracleContext = New-PspktProcessOracleContext -Tag 'wld' -ParentAuthorityRoot $descendantResultRoot
        $scriptPath = New-PspktWorkerDescendantChildScript -Context $oracleContext
        $reserved = @{
            'PSPKT_PHASE4_DESCENDANT_WAITER_READY' = $waiterName
            'PSPKT_PHASE4_HELPER_PATH' = $helperPath
            'PSPKT_PHASE4_HELPER_SHA256' = $helperSha
            'PSPKT_PHASE4_HELPER_VERSION' = $helperVersion
            'PSPKT_PHASE4_PROBE_GATE_TIMEOUT_MS' = '60000'
            'PSPKT_PHASE4_PROBE_TIMEOUT_EXIT_CODE' = '5'
        }
        $config = New-PspktProcessOracleConfiguration -Binding $Binding -Role 'WorkerLeavesDescendantChild' -ScriptPath $scriptPath -Context $oracleContext -ReservedValueByName $reserved -GateEventName $gateName -WaitTimeoutMilliseconds 60000
        $launchSession = Invoke-PspktHelperStatic -Binding $Binding -Method 'RunDirectLaunch' -Arguments @($config)
        $childProcessId = [int]$launchSession.ProcessId
        $childStart = [long]$launchSession.StartTimeFileTimeUtc
        $resultRoot = [System.IO.Path]::GetDirectoryName($resultPath)
        $resultLeaf = [System.IO.Path]::GetFileName($resultPath)
        [void](Invoke-PspktHelperStatic -Binding $Binding -Method 'WriteWorkerDescendantReceipt' -Arguments @([string]$resultRoot, [string]$resultLeaf, [string]$descendantNonce, [int]$childProcessId, [long]$childStart))
        $waitMode = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventAccessMode' -Member 'WaitOnly'
        $waiterRole = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member 'DescendantWaiterReady'
        $waiterEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($waiterName, $waitMode, $waiterRole, [Guid]::Empty)
        $signaled = Wait-PspktNamedEventSignal -NamedEvent $waiterEvent -TimeoutMs 10000
        $launchResult = $signaled
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    if ($null -ne $waiterEvent) {
        try {
            $waiterEvent.Close()
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    $failure = New-PspktComposedFailure -Message 'worker descendant launch primary and event cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
    if ($null -ne $failure) {
        throw $failure
    }
    return $launchResult
}

function Invoke-PspktNestedProofSequence {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][hashtable]$OwnedEvents,
        [Parameter(Mandatory = $true)]$Outcome,
        [Parameter(Mandatory = $true)]$BaselineRoot
    )
    $evidenceReady = $OwnedEvents['PSPKT_PHASE4_NESTED_EVIDENCE_READY']
    $childExited = $OwnedEvents['PSPKT_PHASE4_NESTED_CHILD_EXITED']
    $releaseAuthorized = $OwnedEvents['PSPKT_PHASE4_NESTED_RELEASE_AUTHORIZED']
    $proofComplete = $OwnedEvents['PSPKT_PHASE4_NESTED_PROOF_COMPLETE']

    if (-not (Wait-PspktNamedEventSignal -NamedEvent $evidenceReady -TimeoutMs 10000)) { return $false }

    $membership = Read-PspktNestedReceiptFile -ControlRoot $Context.ControlRoot -Leaf 'nested-membership.txt' -ExpectedTag 'pspkt-phase4-nested-membership-v1' -Kind 'membership'
    if ($membership.Nonce -cne $Context.NestedNonce) { return $false }
    if (-not $membership.MembershipTrue) { return $false }
    $expectedCorrelation = $membership.Correlation
    $expectedPid = $membership.Pid
    $expectedStart = $membership.StartFileTimeUtc

    $nestedReadyName = $Context.EventNames['PSPKT_PHASE4_NESTED_READY_EVENT']
    $waitMode = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventAccessMode' -Member 'WaitOnly'
    $nestedReadyRole = Get-PspktHelperEnum -Binding $Binding -EnumName 'EventRole' -Member 'NestedReady'
    $nestedReadyEvent = Invoke-PspktHelperTypeStatic -Binding $Binding -SimpleName 'NamedEvent' -Method 'OpenExisting' -Arguments @($nestedReadyName, $waitMode, $nestedReadyRole, [Guid]::Empty)
    $nestedReadySignaled = $false
    $nestedReadyPrimaryFailure = $null
    try {
        $nestedReadySignaled = Wait-PspktNamedEventSignal -NamedEvent $nestedReadyEvent -TimeoutMs 10000
    }
    catch {
        $nestedReadyPrimaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    $nestedReadyCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    try {
        $nestedReadyEvent.Close()
    }
    catch {
        [void]$nestedReadyCleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
    }
    $nestedReadyFailure = New-PspktComposedFailure -Message 'nested-ready event primary and cleanup failures.' -PrimaryFailure $nestedReadyPrimaryFailure -CleanupFailures ([Exception[]]$nestedReadyCleanupFailures.ToArray())
    if ($null -ne $nestedReadyFailure) {
        throw $nestedReadyFailure
    }
    if (-not $nestedReadySignaled) { return $false }

    $rootPid = [int]$Session.RootProcessId
    $rootStart = [long]$Session.RootStartTimeFileTimeUtc
    $rootImage = [string]$Session.RootImagePath
    $baselineMembers = $BaselineRoot.Members

    $rise = Get-PspktStableJobSnapshot -Session $Session -TimeoutMs 10000
    if ($null -eq $rise) { return $false }

    $riseOk = $false
    $riseTotal = [long]0
    $risePrimaryFailure = $null
    try {
        $riseMembers = $rise.Members
        $riseAccounting = $Session.QueryJobAccounting()
        $riseTotal = [long]$riseAccounting.TotalProcesses
        if ((Test-PspktNestedRiseMembership -RiseMembers $riseMembers -BaselineMembers $baselineMembers -ChildPid $expectedPid -ChildStart $expectedStart -ChildImage $rootImage) -and
            ([long]$riseAccounting.ActiveProcesses -eq [long]$riseMembers.Count)) {
            $riseOk = $true
        }
    }
    catch {
        $risePrimaryFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    if ($null -ne $risePrimaryFailure) {
        Complete-PspktJobSnapshot -Snapshot $rise -PrimaryFailure $risePrimaryFailure -Message 'nested rise snapshot primary and cleanup failures.'
    }
    if (-not $riseOk) {
        Complete-PspktJobSnapshot -Snapshot $rise -Message 'nested rise snapshot cleanup failure.'
        return $false
    }
    $Outcome.CountRise = $true

    $sequenceResult = $false
    $postRiseFailure = $null
    try {
        $releaseAuthorized.SetEvent()
        if (Wait-PspktNamedEventSignal -NamedEvent $childExited -TimeoutMs 10000) {
            $exit = Read-PspktNestedReceiptFile -ControlRoot $Context.ControlRoot -Leaf 'nested-child-exit.txt' -ExpectedTag 'pspkt-phase4-nested-exit-v1' -Kind 'exit'
            if ($exit.Nonce -ceq $Context.NestedNonce -and
                $exit.Correlation -ceq $expectedCorrelation -and
                $exit.Pid -eq $expectedPid -and
                $exit.StartFileTimeUtc -eq $expectedStart -and
                $exit.ExitCode -eq 0) {
                $fallOk = $false
                $deadline = [System.Diagnostics.Stopwatch]::StartNew()
                while ($deadline.Elapsed.TotalSeconds -lt 10) {
                    $fall = Get-PspktStableJobSnapshot -Session $Session -TimeoutMs 2000
                    if ($null -ne $fall) {
                        $fallResolved = $false
                        $fallPrimaryFailure = $null
                        try {
                            $fallMembers = $fall.Members
                            $fallAccounting = $Session.QueryJobAccounting()
                            if ($fall.RevalidateLive() -and
                                (Test-PspktRootTopology -Members $fallMembers -RootPid $rootPid -RootStart $rootStart -RootImage $rootImage) -and
                                (Test-PspktJobMemberSetEqual -Left $fallMembers -Right $baselineMembers) -and
                                [bool]$rise.MatchRetainedIdentityAllowExited() -and
                                ([long]$fallAccounting.ActiveProcesses -eq [long]$fallMembers.Count) -and
                                ([long]$fallAccounting.TotalProcesses -ge $riseTotal)) {
                                $fallResolved = $true
                            }
                        }
                        catch {
                            $fallPrimaryFailure = Get-PspktInnermostException -Exception $_.Exception
                        }
                        Complete-PspktJobSnapshot -Snapshot $fall -PrimaryFailure $fallPrimaryFailure -Message 'nested fall snapshot primary and cleanup failures.'
                        if ($fallResolved) {
                            $fallOk = $true
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 100
                }
                if ($fallOk) {
                    $Outcome.CountFall = $true
                    $proofComplete.SetEvent()
                    $sequenceResult = ($Outcome.CountRise -and $Outcome.CountFall)
                }
            }
        }
    }
    catch {
        $postRiseFailure = Get-PspktInnermostException -Exception $_.Exception
    }
    Complete-PspktJobSnapshot -Snapshot $rise -PrimaryFailure $postRiseFailure -Message 'nested rise snapshot final cleanup failure.'
    return $sequenceResult
}

function Wait-PspktGeneratorEventWhileRootLive {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$NamedEvent,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMs) {
        if (Wait-PspktNamedEventSignal -NamedEvent $NamedEvent -TimeoutMs 50) {
            return ($Session.QueryActiveProcesses() -gt 0)
        }
        if ($Session.QueryActiveProcesses() -le 0) {
            return $false
        }
    }
    return $false
}

function Test-PspktGeneratorSourceAuthority {
    param([Parameter(Mandatory = $true)]$Context)
    if ($null -eq $Context.GeneratorSourceStream) { return $false }
    try {
        $sourceInfo = [System.IO.FileInfo]::new($Context.GeneratorSourcePath)
        $sourceIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $Context.GeneratorSourceStream -FullPath $Context.GeneratorSourcePath
        return ($sourceInfo.Exists -and
            ($sourceInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $sourceInfo.Length -eq $Context.GeneratorSourceLength -and
            $sourceInfo.CreationTimeUtc -eq $Context.GeneratorSourceCreationTimeUtc -and
            $sourceInfo.LastWriteTimeUtc -eq $Context.GeneratorSourceLastWriteTimeUtc -and
            $sourceIdentity.VolumeSerial -eq $Context.GeneratorSourceVolumeSerial -and
            $sourceIdentity.FileIndex -eq $Context.GeneratorSourceFileIndex -and
            $Context.GeneratorSourceStream.Length -eq $Context.GeneratorSourceLength -and
            (Get-PspktFileStreamSha256 -Stream $Context.GeneratorSourceStream) -ceq $Context.GeneratorSourceSha256)
    }
    catch {
        return $false
    }
}

function ConvertTo-PspktReadSharedGeneratorSource {
    param([Parameter(Mandatory = $true)]$Context)
    if (-not (Test-PspktGeneratorSourceAuthority -Context $Context)) { return $false }
    $Context.GeneratorSourceStream.Dispose()
    $Context.GeneratorSourceStream = $null
    try {
        $sharedStream = [System.IO.FileStream]::new(
            $Context.GeneratorSourcePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        $Context.GeneratorSourceStream = $sharedStream
        if (-not (Test-PspktGeneratorSourceAuthority -Context $Context)) {
            $sharedStream.Dispose()
            $Context.GeneratorSourceStream = $null
            return $false
        }
        return $true
    }
    catch {
        $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
        $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
        if ($null -ne $Context.GeneratorSourceStream) {
            try {
                $Context.GeneratorSourceStream.Dispose()
                $Context.GeneratorSourceStream = $null
            }
            catch {
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        $failure = New-PspktComposedFailure -Message 'generator source sharing transition and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
        if ($null -ne $failure) {
            throw $failure
        }
    }
}

function Test-PspktGeneratorRootsEmpty {
    param([Parameter(Mandatory = $true)]$Context)
    foreach ($root in @($Context.GeneratorHardlinkRoot, $Context.GeneratorTargetRoot)) {
        if ([string]::IsNullOrEmpty($root) -or -not (Test-PspktNonReparseDirectory -FullPath $root)) {
            return $false
        }
        if ([System.IO.Directory]::GetFileSystemEntries($root).Length -ne 0) {
            return $false
        }
    }
    if (-not [string]::IsNullOrEmpty($Context.GeneratorResultPath) -and
        [System.IO.File]::Exists($Context.GeneratorResultPath)) {
        return $false
    }
    return $true
}

function Read-PspktGeneratorHardlinkPreResult {
    param([Parameter(Mandatory = $true)]$Context)
    $preResultPath = [string]$Context.GeneratorHardlinkPreResultPath
    if ([string]::IsNullOrEmpty($preResultPath)) { throw 'generator hard-link pre-result authority is absent.' }
    $expectedPrefix = $Context.GeneratorHardlinkRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $canonicalPreResultPath = [System.IO.Path]::GetFullPath($preResultPath)
    if (-not $canonicalPreResultPath.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'generator hard-link pre-result is outside its authority root.'
    }
    $preResultBytes = Read-PspktBoundedFileBytes -FullPath $canonicalPreResultPath -ByteCap 1024
    foreach ($preResultByte in $preResultBytes) {
        if ($preResultByte -gt 0x7f) { throw 'generator hard-link pre-result is not strict ASCII.' }
    }
    $preResultText = [System.Text.Encoding]::ASCII.GetString($preResultBytes)
    if (-not $preResultText.EndsWith("`n", [System.StringComparison]::Ordinal) -or
        $preResultText.Contains("`r") -or $preResultText.Substring(0, $preResultText.Length - 1).Contains("`n")) {
        throw 'generator hard-link pre-result must contain exactly one LF-terminated record.'
    }
    $fields = $preResultText.Substring(0, $preResultText.Length - 1).Split([char]0x09)
    if ($fields.Length -ne 8 -or
        $fields[0] -cne 'pspkt-phase4-hardlink-pre-v1' -or
        $fields[1] -cne $Context.GeneratorNonce -or
        -not [regex]::IsMatch($fields[2], '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') -or
        -not [regex]::IsMatch($fields[3], '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') -or
        $fields[2] -ceq $fields[3] -or
        -not [regex]::IsMatch($fields[4], '^[0-9a-f]{48}$') -or
        $fields[4] -cne $fields[5] -or
        -not [regex]::IsMatch($fields[6], '^[1-9][0-9]*$') -or
        -not [regex]::IsMatch($fields[7], '^[0-9a-f]{64}$')) {
        throw 'generator hard-link pre-result record is malformed.'
    }
    $length = [long]::Parse($fields[6], [System.Globalization.CultureInfo]::InvariantCulture)
    if ($length -gt 1048576) { throw 'generator hard-link pre-result length exceeds its cap.' }
    $sourcePath = [System.IO.Path]::Combine($Context.GeneratorHardlinkRoot, $fields[2])
    $linkPath = [System.IO.Path]::Combine($Context.GeneratorHardlinkRoot, $fields[3])
    $sourceStream = [System.IO.FileStream]::new(
        $sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
    try {
        $linkStream = [System.IO.FileStream]::new(
            $linkPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
    }
    catch {
        $sourceStream.Dispose()
        throw
    }
    try {
        $sourceIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $sourceStream -FullPath $sourcePath
        $linkIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $linkStream -FullPath $linkPath
        $parsedPreFileId48 = [string]$fields[4]
        $sourceFileId48 = Get-PspktFileStreamFileId48 -Binding $Context.Binding -Stream $sourceStream -FullPath $sourcePath
        $linkFileId48 = Get-PspktFileStreamFileId48 -Binding $Context.Binding -Stream $linkStream -FullPath $linkPath
        if ($sourceIdentity.VolumeSerial -ne $linkIdentity.VolumeSerial -or
            $sourceIdentity.FileIndex -ne $linkIdentity.FileIndex -or
            $sourceStream.Length -ne $length -or $linkStream.Length -ne $length -or
            $sourceFileId48 -cne $parsedPreFileId48 -or
            $linkFileId48 -cne $parsedPreFileId48 -or
            (Get-PspktFileStreamSha256 -Stream $sourceStream) -cne $fields[7] -or
            (Get-PspktFileStreamSha256 -Stream $linkStream) -cne $fields[7]) {
            throw 'generator hard-link pre-result does not match retained source/link handles.'
        }
        [void]$Context.GeneratorHardlinkStreams.Add($sourceStream)
        [void]$Context.GeneratorHardlinkStreams.Add($linkStream)
        $Context.GeneratorHardlinkReceipt = [pscustomobject]@{
            SourcePath = $sourcePath
            LinkPath = $linkPath
            VolumeSerial = $sourceIdentity.VolumeSerial
            FileIndex = $sourceIdentity.FileIndex
            FileId48 = $parsedPreFileId48
            Length = $length
            Sha256 = $fields[7]
        }
        return $Context.GeneratorHardlinkReceipt
    }
    catch {
        $linkStream.Dispose()
        $sourceStream.Dispose()
        throw
    }
}

function Test-PspktGeneratorHardlinkPostState {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [AllowNull()][string[]]$ResultRow
    )
    if ($null -eq $Context.GeneratorHardlinkReceipt -or
        $Context.GeneratorHardlinkStreams.Count -ne 2) {
        return $false
    }
    $sourceStream = $Context.GeneratorHardlinkStreams[0]
    $linkStream = $Context.GeneratorHardlinkStreams[1]
    $replacementSourceStream = $null
    $reopenedLinkStream = $null
    try {
        $retainedSourceIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $sourceStream -FullPath $Context.GeneratorHardlinkReceipt.SourcePath
        $retainedLinkIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $linkStream -FullPath $Context.GeneratorHardlinkReceipt.LinkPath
        if ($retainedSourceIdentity.VolumeSerial -ne $Context.GeneratorHardlinkReceipt.VolumeSerial -or
            $retainedSourceIdentity.FileIndex -ne $Context.GeneratorHardlinkReceipt.FileIndex -or
            $retainedLinkIdentity.VolumeSerial -ne $Context.GeneratorHardlinkReceipt.VolumeSerial -or
            $retainedLinkIdentity.FileIndex -ne $Context.GeneratorHardlinkReceipt.FileIndex -or
            (Get-PspktFileStreamSha256 -Stream $sourceStream) -cne $Context.GeneratorHardlinkReceipt.Sha256 -or
            (Get-PspktFileStreamSha256 -Stream $linkStream) -cne $Context.GeneratorHardlinkReceipt.Sha256) {
            return $false
        }
        $replacementSourceStream = [System.IO.FileStream]::new(
            $Context.GeneratorHardlinkReceipt.SourcePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        $reopenedLinkStream = [System.IO.FileStream]::new(
            $Context.GeneratorHardlinkReceipt.LinkPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        $replacementSourceIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $replacementSourceStream -FullPath $Context.GeneratorHardlinkReceipt.SourcePath
        $reopenedLinkIdentity = Get-PspktFileStreamIdentity -Binding $Context.Binding -Stream $reopenedLinkStream -FullPath $Context.GeneratorHardlinkReceipt.LinkPath
        $retainedSourceFileId48 = Get-PspktFileStreamFileId48 -Binding $Context.Binding -Stream $sourceStream -FullPath $Context.GeneratorHardlinkReceipt.SourcePath
        $retainedLinkFileId48 = Get-PspktFileStreamFileId48 -Binding $Context.Binding -Stream $linkStream -FullPath $Context.GeneratorHardlinkReceipt.LinkPath
        $replacementSourceFileId48 = Get-PspktFileStreamFileId48 -Binding $Context.Binding -Stream $replacementSourceStream -FullPath $Context.GeneratorHardlinkReceipt.SourcePath
        $reopenedLinkFileId48 = Get-PspktFileStreamFileId48 -Binding $Context.Binding -Stream $reopenedLinkStream -FullPath $Context.GeneratorHardlinkReceipt.LinkPath
        $replacementDigest = Get-PspktFileStreamSha256 -Stream $replacementSourceStream
        $reopenedLinkDigest = Get-PspktFileStreamSha256 -Stream $reopenedLinkStream
        if ($retainedSourceFileId48 -cne $Context.GeneratorHardlinkReceipt.FileId48 -or
            $retainedLinkFileId48 -cne $Context.GeneratorHardlinkReceipt.FileId48 -or
            $reopenedLinkFileId48 -cne $Context.GeneratorHardlinkReceipt.FileId48 -or
            $replacementSourceFileId48 -ceq $Context.GeneratorHardlinkReceipt.FileId48) {
            return $false
        }
        $resultMatches = $true
        if ($null -ne $ResultRow) {
            $resultMatches = ($ResultRow.Length -eq 13 -and
                $ResultRow[1] -ceq [System.IO.Path]::GetFileName($Context.GeneratorHardlinkReceipt.SourcePath) -and
                $ResultRow[2] -ceq [System.IO.Path]::GetFileName($Context.GeneratorHardlinkReceipt.LinkPath) -and
                $ResultRow[3] -ceq $Context.GeneratorHardlinkReceipt.FileId48 -and
                $ResultRow[4] -ceq $Context.GeneratorHardlinkReceipt.FileId48 -and
                $ResultRow[5] -ceq $Context.GeneratorHardlinkReceipt.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) -and
                $ResultRow[6] -ceq $Context.GeneratorHardlinkReceipt.Sha256 -and
                $ResultRow[7] -ceq $replacementSourceFileId48 -and
                $ResultRow[8] -ceq $reopenedLinkFileId48 -and
                $ResultRow[9] -ceq $replacementSourceStream.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) -and
                $ResultRow[10] -ceq $replacementDigest -and
                $ResultRow[11] -ceq $reopenedLinkStream.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) -and
                $ResultRow[12] -ceq $reopenedLinkDigest)
        }
        return ($resultMatches -and
            ($replacementSourceIdentity.VolumeSerial -ne $Context.GeneratorHardlinkReceipt.VolumeSerial -or
                $replacementSourceIdentity.FileIndex -ne $Context.GeneratorHardlinkReceipt.FileIndex) -and
            $reopenedLinkIdentity.VolumeSerial -eq $Context.GeneratorHardlinkReceipt.VolumeSerial -and
            $reopenedLinkIdentity.FileIndex -eq $Context.GeneratorHardlinkReceipt.FileIndex -and
            $reopenedLinkDigest -ceq $Context.GeneratorHardlinkReceipt.Sha256 -and
            $replacementDigest -cne $Context.GeneratorHardlinkReceipt.Sha256)
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $reopenedLinkStream) { $reopenedLinkStream.Dispose() }
        if ($null -ne $replacementSourceStream) { $replacementSourceStream.Dispose() }
    }
}

function Get-PspktGeneratorOutputDigest {
    param([Parameter(Mandatory = $true)]$Context)
    $canonicalRoot = Assert-PspktStrictAuthorityRoot -Root $Context.GeneratorTargetRoot -Label 'generator target root'
    $expectedOutputPaths = [string[]]$script:ExpectedSlicePaths[10..($script:ExpectedSlicePaths.Count - 1)]
    if ($expectedOutputPaths.Count -ne 68) {
        throw 'generator target root authority does not expect exactly 68 output files.'
    }
    [System.Array]::Sort($expectedOutputPaths, [System.StringComparer]::Ordinal)
    $expectedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($expectedPath in $expectedOutputPaths) {
        if (-not $expectedSet.Add($expectedPath)) {
            throw 'generator target root authority has duplicate expected output paths.'
        }
    }
    $discoveredFiles = Get-PspktStrictTreeRelativeFiles -CanonicalRoot $canonicalRoot -Label 'generator target root'
    if ($discoveredFiles.Count -ne $expectedOutputPaths.Count) {
        throw 'generator target root does not contain the exact 68-file output cardinality.'
    }
    $discoveredSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($discoveredFile in $discoveredFiles) {
        if (-not $discoveredSet.Add($discoveredFile)) {
            throw 'generator target root contains duplicate canonical relative paths.'
        }
    }
    foreach ($expectedPath in $expectedOutputPaths) {
        if (-not $discoveredSet.Contains($expectedPath)) {
            throw ('generator target root is missing "{0}".' -f $expectedPath)
        }
    }
    foreach ($discoveredFile in $discoveredFiles) {
        if (-not $expectedSet.Contains($discoveredFile)) {
            throw ('generator target root contains an unexpected file "{0}".' -f $discoveredFile)
        }
    }

    $preimage = [System.IO.MemoryStream]::new()
    try {
        $domainBytes = [System.Text.Encoding]::UTF8.GetBytes(
            'pspkt-phase4-generator-digest-v1' + [char]0)
        $preimage.Write($domainBytes, 0, $domainBytes.Length)
        foreach ($relativePath in $expectedOutputPaths) {
            $canonicalLeaf = Resolve-PspktStrictContainedLeaf -AuthorityRoot $canonicalRoot -RelativePath $relativePath -Label 'generator target file'
            $bytes = Read-PspktBoundedFileBytes -FullPath $canonicalLeaf -ByteCap $script:GitBlobByteCap
            $contentDigest = Get-PspktSha256Hex -Bytes $bytes
            $record = 'file' + [char]0x09 + $relativePath + [char]0x09 +
                $bytes.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) +
                [char]0x09 + $contentDigest + [char]0x0A
            $recordBytes = [System.Text.Encoding]::UTF8.GetBytes($record)
            $preimage.Write($recordBytes, 0, $recordBytes.Length)
        }
        return Get-PspktSha256Hex -Bytes $preimage.ToArray()
    }
    finally {
        $preimage.Dispose()
    }
}

function Close-PspktGeneratorLaunch {
    param(
        [Parameter(Mandatory = $true)]$Launch,
        [AllowEmptyCollection()]
        [object[]]$Snapshots = @(),
        [bool]$OwnershipClean = $true
    )
    $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    $sessionOwnershipClean = $OwnershipClean
    $rootRemovalFailed = $false

    if ($null -ne $Launch.Session) {
        try {
            $Launch.Session.Dispose()
        }
        catch {
            $sessionOwnershipClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        $disposeErrors = @()
        try {
            $disposeErrors = @($Launch.Session.GetDisposeErrors())
        }
        catch {
            $sessionOwnershipClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        foreach ($disposeError in $disposeErrors) {
            $sessionOwnershipClean = $false
            [void]$cleanupFailures.Add($disposeError)
        }
        $disposeSucceeded = $false
        $sessionState = ''
        try {
            $disposeSucceeded = [bool]$Launch.Session.DisposeSucceeded
            $sessionState = [string]$Launch.Session.State.ToString()
        }
        catch {
            $sessionOwnershipClean = $false
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
        if (-not $disposeSucceeded -or $sessionState -cne 'Cleaned') {
            $sessionOwnershipClean = $false
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new(
                    ('generator host cleanup proof failed: DisposeSucceeded={0}; State={1}.' -f $disposeSucceeded, $sessionState)))
        }
    }

    $ownershipClean = $sessionOwnershipClean

    if ($sessionOwnershipClean) {
        foreach ($snapshot in $Snapshots) {
            if ($null -eq $snapshot) { continue }
            try {
                if (-not (Close-PspktJobSnapshot -Snapshot $snapshot)) {
                    $ownershipClean = $false
                    [void]$cleanupFailures.Add([System.InvalidOperationException]::new('generator job snapshot cleanup did not report DisposeSucceeded.'))
                }
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        foreach ($generatorEvent in $Launch.Context.GeneratorEvents.Values) {
            try {
                $generatorEvent.Close()
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        foreach ($ownedEvent in $Launch.Context.OwnedEvents) {
            try {
                $ownedEvent.Close()
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        foreach ($hardlinkStream in $Launch.Context.GeneratorHardlinkStreams) {
            try {
                $hardlinkStream.Dispose()
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        if ($null -ne $Launch.Context.GeneratorSourceStream) {
            try {
                $Launch.Context.GeneratorSourceStream.Dispose()
                $Launch.Context.GeneratorSourceStream = $null
            }
            catch {
                $ownershipClean = $false
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    else {
        $retainedSnapshotCount = 0
        foreach ($snapshot in $Snapshots) {
            if ($null -ne $snapshot) { $retainedSnapshotCount++ }
        }
        if ($retainedSnapshotCount -gt 0) {
            [void]$cleanupFailures.Add([System.InvalidOperationException]::new('generator job snapshots were retained because generator host session ownership was not clean.'))
        }
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('generator authority events and streams were retained because session ownership was not clean.'))
    }

    if ($ownershipClean) {
        for ($directoryIndex = $Launch.Context.TempDirs.Count - 1; $directoryIndex -ge 0; $directoryIndex--) {
            $tempDirectory = $Launch.Context.TempDirs[$directoryIndex]
            try {
                if (Test-Path -LiteralPath $tempDirectory) {
                    Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $tempDirectory) {
                    throw ('generator reserved context cleanup did not remove "{0}".' -f $tempDirectory)
                }
            }
            catch {
                $rootRemovalFailed = $true
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
    }
    else {
        [void]$cleanupFailures.Add([System.InvalidOperationException]::new('generator reserved roots were retained because session, snapshot, event, or stream ownership was not clean.'))
    }

    if ($cleanupFailures.Count -eq 0) {
        $Launch.Context.CleanupState = 'Cleaned'
    }
    elseif ($ownershipClean -and -not $rootRemovalFailed) {
        $Launch.Context.CleanupState = 'Pending'
    }
    else {
        $Launch.Context.CleanupState = 'Quarantined'
    }
    if ([string]$Launch.Context.CleanupState -ceq 'Quarantined') {
        try {
            [void](Add-PspktQuarantineRegistration -Kind 'Generator' -Launch $Launch -Snapshots $Snapshots)
        }
        catch {
            [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
        }
    }
    return ,([Exception[]]$cleanupFailures.ToArray())
}

function Complete-PspktGeneratorLaunch {
    param(
        [AllowNull()]
        $Launch,
        [AllowNull()]
        [Exception]$PrimaryFailure = $null,
        [AllowEmptyCollection()]
        [object[]]$Snapshots = @(),
        [bool]$OwnershipClean = $true,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $cleanupFailures = [Exception[]]@()
    if ($null -ne $Launch) {
        $cleanupFailures = Close-PspktGeneratorLaunch -Launch $Launch -Snapshots $Snapshots -OwnershipClean $OwnershipClean
    }
    $failure = New-PspktComposedFailure -Message $Message -PrimaryFailure $PrimaryFailure -CleanupFailures $cleanupFailures
    if ($null -ne $failure) {
        throw $failure
    }
}

function Test-PspktGeneratorBaseline {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Snapshot
    )
    try {
        if (-not (Test-PspktRootTopology -Members $Snapshot.Members -RootPid $Session.RootProcessId -RootStart $Session.RootStartTimeFileTimeUtc -RootImage $Session.RootImagePath)) {
            return $false
        }
        $accounting = $Session.QueryJobAccounting()
        return ([long]$accounting.TotalProcesses -eq [long]$Snapshot.Members.Count -and
            [long]$accounting.ActiveProcesses -eq [long]$Snapshot.Members.Count -and
            [long]$accounting.TotalTerminatedProcesses -eq 0)
    }
    catch {
        return $false
    }
}

function Test-PspktGeneratorWithheldMonitor {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$BaselineSnapshot,
        [Parameter(Mandatory = $true)]$BaselineAccounting,
        [Parameter(Mandatory = $true)]$Clock,
        [Parameter(Mandatory = $true)][long]$AuthorizeMilliseconds
    )
    $deadlineMilliseconds = $AuthorizeMilliseconds + 50000
    while ($Clock.ElapsedMilliseconds -lt $deadlineMilliseconds) {
        $iterationStarted = $Clock.ElapsedMilliseconds
        $snapshot = $null
        $iterationOk = $true
        $primaryFailure = $null
        try {
            $snapshot = $Session.CaptureActiveProcessSnapshot()
            if (-not $snapshot.RevalidateLive() -or
                -not (Test-PspktJobMemberSetEqual -Left $snapshot.Members -Right $BaselineSnapshot.Members)) {
                $iterationOk = $false
            }
            else {
                $accounting = $Session.QueryJobAccounting()
                if ([long]$accounting.TotalProcesses -ne [long]$BaselineAccounting.TotalProcesses -or
                    [long]$accounting.ActiveProcesses -ne [long]$BaselineAccounting.ActiveProcesses -or
                    [long]$accounting.TotalTerminatedProcesses -ne [long]$BaselineAccounting.TotalTerminatedProcesses) {
                    $iterationOk = $false
                }
            }
        }
        catch {
            $primaryFailure = Get-PspktInnermostException -Exception $_.Exception
            $iterationOk = $false
        }
        $cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
        if ($null -ne $snapshot) {
            try {
                if (-not (Close-PspktJobSnapshot -Snapshot $snapshot)) {
                    [void]$cleanupFailures.Add([System.InvalidOperationException]::new('generator withheld-monitor snapshot cleanup did not report DisposeSucceeded.'))
                }
            }
            catch {
                [void]$cleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
            }
        }
        $composedFailure = New-PspktComposedFailure -Message 'generator withheld-monitor iteration primary and cleanup failures.' -PrimaryFailure $primaryFailure -CleanupFailures ([Exception[]]$cleanupFailures.ToArray())
        if ($null -ne $composedFailure) { return $false }
        if (-not $iterationOk) { return $false }
        $elapsedThisIteration = $Clock.ElapsedMilliseconds - $iterationStarted
        if ($elapsedThisIteration -lt 50) {
            Start-Sleep -Milliseconds ([int](50 - $elapsedThisIteration))
        }
    }
    return $true
}

function Invoke-PspktRunGeneratorScenarios {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [string]$InitialIndexTreeId = '',
        $GitAuthority = $null,
        [string]$GitConfigRoot = ''
    )
    $outcome = [pscustomobject]@{
        ContainedFalse = $false
        GateFirst = $false
        SelfTest = $false
        Hardlink = $false
        Output68 = $false
        IndexStable = $false
    }
    foreach ($scenario in $script:GeneratorScenarioInventory) {
        $launch = $null
        $baselineSnapshot = $null
        $scenarioPassed = $false
        $operationalFailure = $null
        try {
            $launch = Invoke-PspktGeneratorLaunch -Binding $Binding -Scenario $scenario -SnapshotRoot $SnapshotRoot -RepositoryRoot $repositoryRoot
            $session = $launch.Session
            if ($scenario -ceq 'ContainedFalse') {
                $waitStatus = $session.WaitWorker(30000)
                $scenarioPassed = ((Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0') -and
                    $session.GetExitCode() -eq 1 -and
                    $session.QueryActiveProcesses() -eq 0)
                $outcome.ContainedFalse = $scenarioPassed
            }
            else {
                $clock = [System.Diagnostics.Stopwatch]::StartNew()
                $preparedEvent = $launch.Context.GeneratorEvents['PSPKT_PHASE4_GENERATOR_GATE_PREPARED']
                $authorizeEvent = $launch.Context.GeneratorEvents['PSPKT_PHASE4_GENERATOR_GATE_AUTHORIZE']
                $armedEvent = $launch.Context.GeneratorEvents['PSPKT_PHASE4_GENERATOR_GATE_WAIT_ARMED']
                if (-not (Wait-PspktGeneratorEventWhileRootLive -Session $session -NamedEvent $preparedEvent -TimeoutMs 10000)) {
                    throw 'generator bootstrap did not prepare its authorization wait while the root was live.'
                }
                $baselineSnapshot = Get-PspktStableJobSnapshot -Session $session -MinIntervalMs 50 -TimeoutMs 10000
                if ($null -eq $baselineSnapshot -or
                    -not (Test-PspktGeneratorBaseline -Session $session -Snapshot $baselineSnapshot)) {
                    throw 'generator bootstrap did not establish the exact stable root baseline.'
                }
                $baselineAccounting = $session.QueryJobAccounting()
                $authorizeMilliseconds = [long]$clock.ElapsedMilliseconds
                $authorizeEvent.SetEvent()
                if (-not (Wait-PspktGeneratorEventWhileRootLive -Session $session -NamedEvent $armedEvent -TimeoutMs 10000)) {
                    throw 'generator bootstrap did not arm its supervisor-gate wait after authorization.'
                }

                if ($scenario -ceq 'GateWithheld') {
                    if (-not (Test-PspktGeneratorWithheldMonitor -Session $session -BaselineSnapshot $baselineSnapshot -BaselineAccounting $baselineAccounting -Clock $clock -AuthorizeMilliseconds $authorizeMilliseconds)) {
                        throw 'generator gate-withheld pre-gate topology or accounting changed.'
                    }
                    $remainingMilliseconds = [int](($authorizeMilliseconds + 80000) - $clock.ElapsedMilliseconds)
                    if ($remainingMilliseconds -lt 1) {
                        throw 'generator gate-withheld terminal deadline elapsed before the process wait.'
                    }
                    $waitStatus = $session.WaitWorker($remainingMilliseconds)
                    $sourceUnchanged = Test-PspktGeneratorSourceAuthority -Context $launch.Context
                    $resultAbsent = Test-PspktGeneratorRootsEmpty -Context $launch.Context
                    $finalAccounting = $session.QueryJobAccounting()
                    $scenarioPassed = ((Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0') -and
                        $session.GetExitCode() -eq 22 -and
                        $sourceUnchanged -and
                        $resultAbsent -and
                        [long]$finalAccounting.ActiveProcesses -eq 0 -and
                        [long]$finalAccounting.TotalProcesses -eq [long]$baselineAccounting.TotalProcesses -and
                        [bool]$baselineSnapshot.MatchRetainedIdentityAllowExited())
                    $outcome.GateFirst = $scenarioPassed
                }
                else {
                    if (-not (ConvertTo-PspktReadSharedGeneratorSource -Context $launch.Context)) {
                        throw 'generator source authority could not transition to retained read sharing.'
                    }
                    $session.SignalWorkerGate()
                    $hardlinkPreparedEvent = $launch.Context.GeneratorEvents['PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED']
                    $hardlinkAuthorizedEvent = $launch.Context.GeneratorEvents['PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED']
                    if (-not (Wait-PspktGeneratorEventWhileRootLive -Session $session -NamedEvent $hardlinkPreparedEvent -TimeoutMs 10000)) {
                        throw 'generator did not prepare its hard-link replacement handshake while the root was live.'
                    }
                    [void](Read-PspktGeneratorHardlinkPreResult -Context $launch.Context)
                    $hardlinkAuthorizedEvent.SetEvent()
                    $waitStatus = $session.WaitWorker(600000)
                    $exitZero = ((Test-PspktHelperEnumEquals -Value $waitStatus -Member 'Object0') -and
                        $session.GetExitCode() -eq 0 -and
                        $session.QueryActiveProcesses() -eq 0 -and
                        (Test-PspktGeneratorSourceAuthority -Context $launch.Context) -and
                        (Test-PspktGeneratorHardlinkPostState -Context $launch.Context))
                    if ($exitZero) {
                        $generatorResult = Read-PspktSealedGeneratorResult -ExpectedResultRoot $launch.Context.GeneratorResultRoot -ResultPath $launch.Context.GeneratorResultPath -ExpectedNonce $launch.Context.GeneratorNonce
                        $resultHostMatches = ($generatorResult.HostEdition -ceq $PSVersionTable.PSEdition -and
                            $generatorResult.HostVersion -ceq $PSVersionTable.PSVersion.ToString())
                        $outputDigest = Get-PspktGeneratorOutputDigest -Context $launch.Context
                        $outcome.SelfTest = $resultHostMatches
                        $outcome.Hardlink = ($resultHostMatches -and
                            (Test-PspktGeneratorHardlinkPostState -Context $launch.Context -ResultRow $generatorResult.HardlinkRow))
                        $outcome.Output68 = ($resultHostMatches -and $outputDigest -ceq $generatorResult.Digest)
                        if (-not [string]::IsNullOrEmpty($InitialIndexTreeId) -and
                            $null -ne $GitAuthority -and
                            -not [string]::IsNullOrEmpty($GitConfigRoot)) {
                            $currentIndexTreeId = Get-PspktIndexTreeId -GitAuthority $GitAuthority -ConfigRoot $GitConfigRoot
                            $outcome.IndexStable = ($currentIndexTreeId -ceq $InitialIndexTreeId)
                        }
                        $scenarioPassed = ($outcome.SelfTest -and $outcome.Hardlink -and
                            $outcome.Output68 -and $outcome.IndexStable)
                    }
                }
            }
        }
        catch {
            $scenarioPassed = $false
            $operationalFailure = Get-PspktInnermostException -Exception $_.Exception
        }
        finally {
            $snapshotsForCleanup = @()
            if ($null -ne $baselineSnapshot) {
                $snapshotsForCleanup = [object[]]@($baselineSnapshot)
            }
            $cleanupFailures = [Exception[]]@()
            if ($null -ne $launch) {
                $cleanupFailures = Close-PspktGeneratorLaunch -Launch $launch -Snapshots $snapshotsForCleanup
                if ($cleanupFailures.Count -gt 0 -or [string]$launch.Context.CleanupState -cne 'Cleaned') {
                    $scenarioPassed = $false
                }
            }
            elseif ($null -ne $baselineSnapshot) {
                $baselineCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
                try {
                    if (-not (Close-PspktJobSnapshot -Snapshot $baselineSnapshot)) {
                        [void]$baselineCleanupFailures.Add([System.InvalidOperationException]::new('generator baseline snapshot cleanup did not report DisposeSucceeded.'))
                    }
                }
                catch {
                    [void]$baselineCleanupFailures.Add((Get-PspktInnermostException -Exception $_.Exception))
                }
                if ($baselineCleanupFailures.Count -gt 0) {
                    $scenarioPassed = $false
                }
                $cleanupFailures = [Exception[]]$baselineCleanupFailures.ToArray()
            }
            $composedScenarioFailure = New-PspktComposedFailure -Message (
                'generator scenario "{0}" operational and cleanup failures.' -f $scenario) -PrimaryFailure $operationalFailure -CleanupFailures $cleanupFailures
            if ($null -ne $composedScenarioFailure) {
                $scenarioPassed = $false
                Write-Host ('  [generator-cleanup] scenario "{0}" surfaced composed failure :: {1}' -f $scenario, $composedScenarioFailure.Message)
            }
            if (-not $scenarioPassed) {
                if ($scenario -ceq 'ContainedFalse') { $outcome.ContainedFalse = $false }
                elseif ($scenario -ceq 'GateWithheld') { $outcome.GateFirst = $false }
                else {
                    $outcome.SelfTest = $false
                    $outcome.Hardlink = $false
                    $outcome.Output68 = $false
                    $outcome.IndexStable = $false
                }
            }
        }
    }
    return $outcome
}

function Get-PspktPhase4AuthorityCases {
    param([Parameter(Mandatory = $true)][string]$SnapshotRoot)
    $canonicalJsonPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, 'certification\lib\Pspkt.Certification.CanonicalJson.ps1'))
    $fixtureContractPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, 'certification\lib\Pspkt.Certification.SchemaFixtureContract.ps1'))
    $manifestPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, 'certification\vectors\phase4-schema\fixture-manifest.v1.json'))
    . $canonicalJsonPath
    . $fixtureContractPath
    $contract = Get-PspktPhase4Contract
    $manifestBytes = Read-PspktBoundedFileBytes -FullPath $manifestPath -ByteCap $contract.ManifestByteCap
    if ($manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xEF -and $manifestBytes[1] -eq 0xBB -and $manifestBytes[2] -eq 0xBF) {
        throw 'schema authority: fixture manifest carries a BOM.'
    }
    $manifestText = (New-PspktUtf8NoBom).GetString($manifestBytes)
    $manifest = $manifestText | ConvertFrom-Json
    Assert-PspktPhase4ManifestShape -Manifest $manifest
    $cases = @(Get-PspktPhase4NormalizedCases -Manifest $manifest)
    if ($cases.Count -ne [int]$contract.ExpectedCaseCount) {
        throw ('schema authority: normalized case count is {0}, expected {1}.' -f $cases.Count, $contract.ExpectedCaseCount)
    }
    return , $cases
}

function Test-PspktThrowsMatching {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern
    )
    try {
        & $Action | Out-Null
        return $false
    }
    catch {
        $message = ''
        if ($null -ne $_.Exception) { $message = [string]$_.Exception.Message }
        if ([string]::IsNullOrEmpty($message)) { $message = [string]$_ }
        return ($message -match [regex]::Escape($Pattern))
    }
}

function Test-PspktManifestNegativeVectors {
    param([Parameter(Mandatory = $true)][string]$SnapshotRoot)
    $canonicalJsonPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, 'certification\lib\Pspkt.Certification.CanonicalJson.ps1'))
    $fixtureContractPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, 'certification\lib\Pspkt.Certification.SchemaFixtureContract.ps1'))
    $manifestPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, 'certification\vectors\phase4-schema\fixture-manifest.v1.json'))
    . $canonicalJsonPath
    . $fixtureContractPath
    $contract = Get-PspktPhase4Contract
    $manifestBytes = Read-PspktBoundedFileBytes -FullPath $manifestPath -ByteCap $contract.ManifestByteCap
    if ($manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xEF -and $manifestBytes[1] -eq 0xBB -and $manifestBytes[2] -eq 0xBF) {
        return $false
    }
    $manifestText = (New-PspktUtf8NoBom).GetString($manifestBytes)

    $pristine = $manifestText | ConvertFrom-Json
    try {
        Assert-PspktPhase4ManifestShape -Manifest $pristine
        $pristineCases = @(Get-PspktPhase4NormalizedCases -Manifest $pristine)
    }
    catch {
        return $false
    }
    if ($pristineCases.Count -ne [int]$contract.ExpectedCaseCount) { return $false }

    $metaRepoPath = [string]$contract.MetaRepoPath
    $mutations = @(
        @{ Pattern = 'manifest has'; Mutate = { param($m) [void]$m.PSObject.Properties.Remove('description') } },
        @{ Pattern = 'manifest has'; Mutate = { param($m) $m | Add-Member -NotePropertyName 'phase4Extra' -NotePropertyValue 1 -Force } },
        @{ Pattern = 'schemaVersion must be an integer'; Mutate = { param($m) $m.schemaVersion = '1' } },
        @{ Pattern = 'schemaVersion must be 1'; Mutate = { param($m) $m.schemaVersion = 2 } },
        @{ Pattern = 'manifest kind must be'; Mutate = { param($m) $m.kind = 'not-the-kind' } },
        @{ Pattern = 'manifest metaSchema must be'; Mutate = { param($m) $m.metaSchema = 'certification/schema/other.json' } },
        @{ Pattern = 'manifest cases must be a JSON array'; Mutate = { param($m) $m.cases = 'not-an-array' } },
        @{ Pattern = 'keys, expected'; Mutate = { param($m) [void]$m.cases[0].PSObject.Properties.Remove('sha256') } },
        @{ Pattern = 'key set does not match'; Mutate = { param($m) [void]$m.cases[0].PSObject.Properties.Remove('sha256'); $m.cases[0] | Add-Member -NotePropertyName 'phase4Extra' -NotePropertyValue 1 -Force } },
        @{ Pattern = 'declares'; Mutate = { param($m) $m.cases = @($m.cases[0..($m.cases.Count - 2)]) } },
        @{ Pattern = 'declares'; Mutate = { param($m) $m.cases = @(@($m.cases) + $m.cases[$m.cases.Count - 1]) } },
        @{ Pattern = 'declares ordinal'; Mutate = { param($m) $m.cases[5].ordinal = 999 } },
        @{ Pattern = 'ordinal must be an integer'; Mutate = { param($m) $m.cases[5].ordinal = 'x' } },
        @{ Pattern = 'declares ordinal'; Mutate = { param($m) $arr = @($m.cases); $swap = $arr[0]; $arr[0] = $arr[1]; $arr[1] = $swap; $m.cases = $arr } },
        @{ Pattern = 'repeats name'; Mutate = { param($m) $m.cases[1].name = [string]$m.cases[0].name } },
        @{ Pattern = 'is not an ASCII identifier'; Mutate = { param($m) $m.cases[0].name = '1nvalid' } },
        @{ Pattern = 'declares unknown stage'; Mutate = { param($m) $m.cases[0].stage = 'not-a-stage' } },
        @{ Pattern = 'declares unknown outcome'; Mutate = { param($m) $m.cases[0].expectedOutcome = 'maybe' } },
        @{ Pattern = 'declares unknown reason'; Mutate = { param($m) $m.cases[0].expectedReason = 'not-a-reason' } },
        @{ Pattern = 'outcome/reason are inconsistent'; Mutate = { param($m) foreach ($c in $m.cases) { if ($c.expectedOutcome -ceq 'accepted') { $c.expectedReason = 'file-limit'; break } } } },
        @{ Pattern = 'fails the repository-path grammar'; Mutate = { param($m) $m.cases[0].path = 'certification\vectors\phase4-schema\json\backslash.json' } },
        @{ Pattern = 'repeats path'; Mutate = { param($m) $m.cases[1].path = [string]$m.cases[0].path } },
        @{ Pattern = 'byteLength must be an integer'; Mutate = { param($m) $m.cases[0].byteLength = 'x' } },
        @{ Pattern = 'byteLength is negative'; Mutate = { param($m) $m.cases[0].byteLength = -1 } },
        @{ Pattern = 'is not a lowercase 64-hex digest'; Mutate = { param($m) $m.cases[0].sha256 = 'ZZZ' } },
        @{ Pattern = 'accepted cases, expected'; Mutate = { param($m) foreach ($c in $m.cases) { if ($c.expectedOutcome -ceq 'accepted') { $c.expectedOutcome = 'rejected'; $c.expectedReason = 'file-limit'; break } } } },
        @{ Pattern = 'references the committed meta'; Mutate = { param($m) foreach ($c in $m.cases) { if ([string]$c.path -ceq $metaRepoPath) { $c.path = 'certification/vectors/phase4-schema/json/synthetic-unique-meta.json'; break } } } },
        @{ Pattern = 'distinct reasons'; Mutate = { param($m)
                $counts = @{}
                foreach ($c in $m.cases) { $r = [string]$c.expectedReason; if ($counts.ContainsKey($r)) { $counts[$r]++ } else { $counts[$r] = 1 } }
                $uniqueRejected = $null
                foreach ($c in $m.cases) { if ($c.expectedOutcome -ceq 'rejected' -and $counts[[string]$c.expectedReason] -eq 1 -and $null -eq $uniqueRejected) { $uniqueRejected = [string]$c.expectedReason } }
                $otherRejected = $null
                foreach ($c in $m.cases) { if ($c.expectedOutcome -ceq 'rejected' -and [string]$c.expectedReason -cne $uniqueRejected) { $otherRejected = [string]$c.expectedReason; break } }
                foreach ($c in $m.cases) { if ($c.expectedOutcome -ceq 'rejected' -and [string]$c.expectedReason -ceq $uniqueRejected) { $c.expectedReason = $otherRejected; break } }
            } }
    )

    for ($mutationIndex = 0; $mutationIndex -lt $mutations.Count; $mutationIndex++) {
        $mutation = $mutations[$mutationIndex]
        $m = $manifestText | ConvertFrom-Json
        & $mutation.Mutate $m
        $actualMessage = ''
        try {
            Assert-PspktPhase4ManifestShape -Manifest $m
            [void](Get-PspktPhase4NormalizedCases -Manifest $m)
        }
        catch {
            $actualMessage = [string]$_.Exception.Message
        }
        if ([string]::IsNullOrEmpty($actualMessage) -or
            $actualMessage -notmatch [regex]::Escape([string]$mutation.Pattern)) {
            throw ('manifest negative vector {0} expected text "{1}", actual "{2}".' -f $mutationIndex, $mutation.Pattern, $actualMessage)
        }
    }

    $acceptedAgain = $false
    try {
        $accept = $manifestText | ConvertFrom-Json
        Assert-PspktPhase4ManifestShape -Manifest $accept
        $acceptCases = @(Get-PspktPhase4NormalizedCases -Manifest $accept)
        $acceptedAgain = ($acceptCases.Count -eq [int]$contract.ExpectedCaseCount)
    }
    catch {
        $acceptedAgain = $false
    }

    if (-not $acceptedAgain) {
        throw 'manifest negative vectors did not re-accept the pristine manifest.'
    }
    return $true
}

function New-PspktSchemaCaseFieldRows {
    param([Parameter(Mandatory = $true)][object[]]$Cases)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Cases.Count; $index++) {
        $case = $Cases[$index]
        [void]$rows.Add([string[]]@(
                'case',
                ([int]$case.Ordinal).ToString($invariant),
                [string]$case.Name,
                [string]$case.Path,
                [string]$case.Stage,
                [string]$case.ExpectedOutcome,
                [string]$case.ExpectedReason,
                ([long]$case.ByteLength).ToString($invariant),
                [string]$case.Sha256,
                [string]$case.ExpectedOutcome,
                [string]$case.ExpectedReason
            ))
    }
    return , $rows
}

function Write-PspktSyntheticSchemaResult {
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$HelperVersion,
        [Parameter(Mandatory = $true)][object[]]$Cases,
        [string]$Mutation = ''
    )
    $tab = [string][char]0x09
    $lf = [string][char]0x0A
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    $headerFields = [System.Collections.Generic.List[string]]::new()
    $headerNonce = $Nonce
    $headerVersion = $HelperVersion
    if ($Mutation -ceq 'NonceMismatch') { $headerNonce = [guid]::NewGuid().ToString('N') }
    if ($Mutation -ceq 'VersionMismatch') { $headerVersion = 'pspkt-phase4-bounded-process-0' }
    [void]$headerFields.Add('pspkt-phase4-schema-result-v2')
    [void]$headerFields.Add($headerNonce)
    [void]$headerFields.Add($headerVersion)
    if ($Mutation -ceq 'HeaderTag') { $headerFields[0] = 'pspkt-phase4-schema-result-BAD' }
    if ($Mutation -ceq 'HeaderFieldCount') { [void]$headerFields.Add('extra') }

    $caseRows = New-PspktSchemaCaseFieldRows -Cases $Cases

    if ($Mutation -ceq 'CaseTag') { $caseRows[0][0] = 'notcase' }
    if ($Mutation -ceq 'CaseFieldCount') { $caseRows[0] = [string[]]@($caseRows[0][0..9]) }
    if ($Mutation -ceq 'BadOrdinal') { $caseRows[0][1] = '999' }
    if ($Mutation -ceq 'NameMismatch') { $caseRows[0][2] = $caseRows[0][2] + 'X' }
    if ($Mutation -ceq 'PathMismatch') { $caseRows[0][3] = $caseRows[0][3] + 'X' }
    if ($Mutation -ceq 'StageMismatch') { $caseRows[0][4] = 'not-a-stage' }
    if ($Mutation -ceq 'ExpectedOutcomeMismatch') {
        $caseRows[0][5] = $(if ($caseRows[0][5] -ceq 'accepted') { 'rejected' } else { 'accepted' })
    }
    if ($Mutation -ceq 'ExpectedReasonMismatch') { $caseRows[0][6] = 'meta-authority-mismatch-not' }
    if ($Mutation -ceq 'ByteLengthMismatch') {
        $caseRows[0][7] = ([long]::Parse($caseRows[0][7], $invariant) + 1).ToString($invariant)
    }
    if ($Mutation -ceq 'Sha256Mismatch') {
        $flip = $caseRows[0][8].ToCharArray()
        $flip[0] = $(if ($flip[0] -ceq '0') { '1' } else { '0' })
        $caseRows[0][8] = -join $flip
    }
    if ($Mutation -ceq 'ActualOutcomeMismatch') {
        $caseRows[0][9] = $(if ($caseRows[0][9] -ceq 'accepted') { 'rejected' } else { 'accepted' })
    }
    if ($Mutation -ceq 'ActualReasonMismatch') {
        $caseRows[0][10] = $(if ($caseRows[0][10] -ceq 'ok') { 'invalid-utf8' } else { 'ok' })
    }
    if ($Mutation -ceq 'MissingCase' -and $caseRows.Count -gt 0) {
        $caseRows.RemoveAt($caseRows.Count - 1)
    }
    if ($Mutation -ceq 'ExtraCase' -and $caseRows.Count -gt 0) {
        [void]$caseRows.Add([string[]]@($caseRows[$caseRows.Count - 1]))
    }
    if ($Mutation -ceq 'DuplicateCase' -and $caseRows.Count -gt 0) {
        [void]$caseRows.Add([string[]]@($caseRows[0]))
    }
    if ($Mutation -ceq 'ReorderedCases' -and $caseRows.Count -ge 2) {
        $swap = $caseRows[0]; $caseRows[0] = $caseRows[1]; $caseRows[1] = $swap
    }

    $summaryFields = [System.Collections.Generic.List[string]]::new()
    [void]$summaryFields.Add('summary')
    [void]$summaryFields.Add(([int]$Cases.Count).ToString($invariant))
    [void]$summaryFields.Add('pass')
    if ($Mutation -ceq 'BadSummaryCount') { $summaryFields[1] = ([int]$Cases.Count - 1).ToString($invariant) }
    if ($Mutation -ceq 'BadSummaryStatus') { $summaryFields[2] = 'fail' }
    if ($Mutation -ceq 'SummaryFieldCount') { $summaryFields.RemoveAt($summaryFields.Count - 1) }

    $bodyLines = [System.Collections.Generic.List[string]]::new()
    [void]$bodyLines.Add(($headerFields -join $tab))
    foreach ($row in $caseRows) { [void]$bodyLines.Add(($row -join $tab)) }
    if ($Mutation -ceq 'UnknownRecord') { [void]$bodyLines.Add('mystery' + $tab + 'x') }
    if ($Mutation -cne 'MissingSummary') { [void]$bodyLines.Add(($summaryFields -join $tab)) }
    if ($Mutation -ceq 'DuplicateSummary') { [void]$bodyLines.Add(($summaryFields -join $tab)) }

    $text = ($bodyLines -join $lf) + $lf
    if ($Mutation -ceq 'MissingTerminalNewline') { $text = ($bodyLines -join $lf) }
    if ($Mutation -ceq 'CarriageReturn') { $text = ($bodyLines -join ([string][char]0x0D + $lf)) + $lf }

    $bytes = (New-PspktUtf8NoBom).GetBytes($text)
    if ($Mutation -ceq 'ExtraTrailingData') { $bytes = $bytes + [byte[]](0x78, 0x79, 0x7A) }
    if ($Mutation -ceq 'Oversize') { $bytes = $bytes + [byte[]]::new(262145) }
    if ($Mutation -ceq 'MalformedUtf8') { $bytes = $bytes + [byte[]](0xC0, 0x80) }
    if ($Mutation -ceq 'Bom') { $bytes = [byte[]](0xEF, 0xBB, 0xBF) + $bytes }

    $stream = [System.IO.FileStream]::new($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Test-PspktSchemaResultNegativeVectors {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot
    )
    $nonce = [guid]::NewGuid().ToString('N')
    $cases = Get-PspktPhase4AuthorityCases -SnapshotRoot $SnapshotRoot
    $tempRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-scneg-'
    $result = $false
    $tempRootFailure = $null
    try {
        $allReject = $true
        foreach ($mutation in $script:SchemaResultMutationInventory) {
            $path = Join-Path $tempRoot ('m-' + $mutation + '.txt')
            Write-PspktSyntheticSchemaResult -OutputPath $path -Nonce $nonce -HelperVersion $Binding.Version -Cases $cases -Mutation $mutation
            $rejected = Test-PspktThrows { Read-PspktSealedSchemaResult -ResultPath $path -ExpectedNonce $nonce -ExpectedVersion $Binding.Version -ExpectedCases $cases }
            if (-not $rejected) { $allReject = $false }
        }

        $missingPath = Join-Path $tempRoot 'never-written.txt'
        $missingRejected = Test-PspktThrows { Read-PspktSealedSchemaResult -ResultPath $missingPath -ExpectedNonce $nonce -ExpectedVersion $Binding.Version -ExpectedCases $cases }
        if (-not $missingRejected) { $allReject = $false }

        $reparseRoot = Join-Path $tempRoot 'reparse-target'
        [void][System.IO.Directory]::CreateDirectory($reparseRoot)
        $reparsePath = Join-Path $tempRoot 'reparse-link'
        $reparseResult = Invoke-PspktBoundedComSpecCommand -CommandLine ('mklink /J "' + $reparsePath + '" "' + $reparseRoot + '"') -Label 'schema-result reparse fixture mklink /J'
        $reparseCreated = ($reparseResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $reparsePath) -and -not (Test-PspktNonReparseDirectory -FullPath $reparsePath))
        if (-not $reparseCreated) {
            $allReject = $false
        }
        else {
            $reparseRejected = Test-PspktThrows { Read-PspktSealedSchemaResult -ResultPath $reparsePath -ExpectedNonce $nonce -ExpectedVersion $Binding.Version -ExpectedCases $cases }
            if (-not $reparseRejected) { $allReject = $false }
        }

        $preexistingPath = Join-Path $tempRoot 'preexisting-empty.txt'
        [System.IO.File]::WriteAllBytes($preexistingPath, [byte[]]::new(0))
        $preexistingRejected = Test-PspktThrows { Read-PspktSealedSchemaResult -ResultPath $preexistingPath -ExpectedNonce $nonce -ExpectedVersion $Binding.Version -ExpectedCases $cases }
        if (-not $preexistingRejected) { $allReject = $false }

        $wrongNoncePath = Join-Path $tempRoot 'wrong-authority-count.txt'
        Write-PspktSyntheticSchemaResult -OutputPath $wrongNoncePath -Nonce $nonce -HelperVersion $Binding.Version -Cases $cases
        $shortAuthority = @($cases[0..($cases.Count - 2)])
        $countRejected = Test-PspktThrows { Read-PspktSealedSchemaResult -ResultPath $wrongNoncePath -ExpectedNonce $nonce -ExpectedVersion $Binding.Version -ExpectedCases $shortAuthority }
        if (-not $countRejected) { $allReject = $false }

        $goodPath = Join-Path $tempRoot 'good.txt'
        Write-PspktSyntheticSchemaResult -OutputPath $goodPath -Nonce $nonce -HelperVersion $Binding.Version -Cases $cases
        $accepted = $false
        try { $accepted = Read-PspktSealedSchemaResult -ResultPath $goodPath -ExpectedNonce $nonce -ExpectedVersion $Binding.Version -ExpectedCases $cases } catch { $accepted = $false }
        $result = ($allReject -and $accepted)
    }
    finally {
        $tempRootFailure = Remove-PspktStrictVectorRoot -Root $tempRoot -Label 'schema-result-negative tempRoot'
    }
    return ($result -and ($null -eq $tempRootFailure))
}

function Read-PspktSealedSchemaResult {
    param(
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][object[]]$ExpectedCases
    )
    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        throw 'schema result: path is absent.'
    }
    $info = [System.IO.FileInfo]::new($ResultPath)
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
        throw 'schema result: path is a reparse point.'
    }
    $expectedCaseCount = $ExpectedCases.Count
    if ($expectedCaseCount -ne 68) { throw 'schema result: authority case count is not exactly 68.' }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $bytes = Read-PspktBoundedFileBytes -FullPath $ResultPath -ByteCap 262144
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'schema result: unexpected BOM.'
    }
    $text = (New-PspktUtf8NoBom).GetString($bytes)
    if ($text.IndexOf([char]0x0D) -ge 0) { throw 'schema result: carriage return is forbidden.' }
    $tab = [char]0x09
    $lines = @($text -split "`n")
    if ($lines.Count -lt 2 -or $lines[$lines.Count - 1] -cne '') { throw 'schema result: missing terminal newline.' }
    $body = @($lines[0..($lines.Count - 2)])
    $expectedBodyCount = 2 + $expectedCaseCount
    if ($body.Count -ne $expectedBodyCount) {
        throw ('schema result: body has {0} records, expected {1}.' -f $body.Count, $expectedBodyCount)
    }
    $header = $body[0] -split $tab
    if ($header.Count -ne 3 -or $header[0] -cne 'pspkt-phase4-schema-result-v2') { throw 'schema result: bad header.' }
    if ($header[1] -cne $ExpectedNonce) { throw 'schema result: nonce mismatch.' }
    if ($header[2] -cne $ExpectedVersion) { throw 'schema result: version mismatch.' }
    for ($index = 0; $index -lt $expectedCaseCount; $index++) {
        $case = $ExpectedCases[$index]
        $fields = $body[$index + 1] -split $tab
        if ($fields.Count -ne 11) { throw ('schema result: case row {0} does not have exactly 11 fields.' -f $index) }
        if ($fields[0] -cne 'case') { throw ('schema result: record {0} is not a case row.' -f $index) }
        if ($fields[1] -cne ([int]$case.Ordinal).ToString($invariant) -or ([int]$case.Ordinal) -ne $index) { throw ('schema result: case row {0} ordinal mismatch.' -f $index) }
        if ($fields[2] -cne [string]$case.Name) { throw ('schema result: case row {0} name mismatch.' -f $index) }
        if ($fields[3] -cne [string]$case.Path) { throw ('schema result: case row {0} path mismatch.' -f $index) }
        if ($fields[4] -cne [string]$case.Stage) { throw ('schema result: case row {0} stage mismatch.' -f $index) }
        if ($fields[5] -cne [string]$case.ExpectedOutcome) { throw ('schema result: case row {0} expected-outcome mismatch.' -f $index) }
        if ($fields[6] -cne [string]$case.ExpectedReason) { throw ('schema result: case row {0} expected-reason mismatch.' -f $index) }
        if ($fields[7] -cne ([long]$case.ByteLength).ToString($invariant)) { throw ('schema result: case row {0} byte-length mismatch.' -f $index) }
        if ($fields[8] -cne [string]$case.Sha256) { throw ('schema result: case row {0} sha256 mismatch.' -f $index) }
        if ($fields[9] -cne $fields[5]) { throw ('schema result: case row {0} actual outcome does not equal expected.' -f $index) }
        if ($fields[10] -cne $fields[6]) { throw ('schema result: case row {0} actual reason does not equal expected.' -f $index) }
    }
    $summaryRow = $body[$expectedBodyCount - 1] -split $tab
    if ($summaryRow.Count -ne 3 -or $summaryRow[0] -cne 'summary') { throw 'schema result: malformed summary record.' }
    if ($summaryRow[1] -cne $expectedCaseCount.ToString($invariant)) { throw 'schema result: summary count mismatch.' }
    if ($summaryRow[2] -cne 'pass') { throw 'schema result: summary status is not pass.' }
    return $true
}

function Test-PspktGeneratorResultAuthorityVectors {
    $nonce = [guid]::NewGuid().ToString('N')
    $tab = [string][char]0x09
    $lf = [string][char]0x0A
    $badContent = (New-PspktUtf8NoBom).GetBytes('pspkt-phase4-generator-result-BAD' + $tab + $nonce + $tab + 'Core' + $tab + '7' + $lf)
    $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-genauth-'
    $ok = $false
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    try {
        $directBad = Join-Path $root 'bad-tag.txt'
        [System.IO.File]::WriteAllBytes($directBad, $badContent)
        $formatRejected = Test-PspktThrowsMatching -Pattern 'generator result: bad header.' -Action {
            Read-PspktSealedGeneratorResult -ExpectedResultRoot $root -ResultPath $directBad -ExpectedNonce $nonce
        }

        $outsideRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-genauth-out-'
        $outsideRejected = $false
        try {
            $outsideFile = Join-Path $outsideRoot 'x.txt'
            [System.IO.File]::WriteAllBytes($outsideFile, $badContent)
            $outsideRejected = Test-PspktThrowsMatching -Pattern 'is outside the expected root' -Action {
                Read-PspktSealedGeneratorResult -ExpectedResultRoot $root -ResultPath $outsideFile -ExpectedNonce $nonce
            }
        }
        finally {
            $outsideFailure = Remove-PspktStrictVectorRoot -Root $outsideRoot -Label 'generator-authority outsideRoot'
            if ($null -ne $outsideFailure) { [void]$rootCleanupFailures.Add($outsideFailure) }
        }

        $subdir = Join-Path $root 'sub'
        [void][System.IO.Directory]::CreateDirectory($subdir)
        $deepFile = Join-Path $subdir 'deep.txt'
        [System.IO.File]::WriteAllBytes($deepFile, $badContent)
        $deepRejected = Test-PspktThrowsMatching -Pattern 'is not a direct child of the expected root' -Action {
            Read-PspktSealedGeneratorResult -ExpectedResultRoot $root -ResultPath $deepFile -ExpectedNonce $nonce
        }

        $absentFile = Join-Path $root ('absent-' + $nonce + '.txt')
        $absentRejected = Test-PspktThrowsMatching -Pattern 'is absent' -Action {
            Read-PspktSealedGeneratorResult -ExpectedResultRoot $root -ResultPath $absentFile -ExpectedNonce $nonce
        }

        $nonCanonical = Join-Path $subdir (Join-Path '..' 'bad-tag.txt')
        $nonCanonicalRejected = Test-PspktThrowsMatching -Pattern 'is not canonical' -Action {
            Read-PspktSealedGeneratorResult -ExpectedResultRoot $root -ResultPath $nonCanonical -ExpectedNonce $nonce
        }

        $junctionOk = $false
        $junctionCleanupOk = $true
        $realTarget = New-PspktTempDirectory -Prefix 'pspkt-phase4-genauth-tgt-'
        $junctionRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-genauth-jr-' + [guid]::NewGuid().ToString('N'))
        try {
            [System.IO.File]::WriteAllBytes((Join-Path $realTarget 'bad-tag.txt'), $badContent)
            $junctionResult = Invoke-PspktBoundedComSpecCommand -CommandLine ('mklink /J "' + $junctionRoot + '" "' + $realTarget + '"') -Label 'generator-authority junction mklink /J'
            $junctionCreated = ($junctionResult.ExitCode -eq 0 -and
                (Test-Path -LiteralPath $junctionRoot) -and
                (-not (Test-PspktNonReparseDirectory -FullPath $junctionRoot)))
            if ($junctionCreated) {
                $junctionLeaf = Join-Path $junctionRoot 'bad-tag.txt'
                $junctionOk = Test-PspktThrowsMatching -Pattern 'is absent or a reparse point' -Action {
                    Read-PspktSealedGeneratorResult -ExpectedResultRoot $junctionRoot -ResultPath $junctionLeaf -ExpectedNonce $nonce
                }
            }
            else {
                $junctionOk = $false
            }
        }
        finally {
            if (Test-Path -LiteralPath $junctionRoot) {
                $rmdirResult = Invoke-PspktBoundedComSpecCommand -CommandLine ('rmdir "' + $junctionRoot + '"') -Label 'generator-authority junction rmdir'
                if ($rmdirResult.ExitCode -ne 0 -or (Test-Path -LiteralPath $junctionRoot)) {
                    $junctionCleanupOk = $false
                }
            }
            $realTargetFailure = Remove-PspktStrictVectorRoot -Root $realTarget -Label 'generator-authority realTarget'
            if ($null -ne $realTargetFailure) { [void]$rootCleanupFailures.Add($realTargetFailure) }
        }

        $ok = ($formatRejected -and $outsideRejected -and $deepRejected -and $absentRejected -and $nonCanonicalRejected -and $junctionOk -and $junctionCleanupOk)
    }
    finally {
        $rootFailure = Remove-PspktStrictVectorRoot -Root $root -Label 'generator-authority root'
        if ($null -ne $rootFailure) { [void]$rootCleanupFailures.Add($rootFailure) }
    }
    return ($ok -and ($rootCleanupFailures.Count -eq 0))
}

function Test-PspktGeneratorHardlinkTamperVector {
    param([Parameter(Mandatory = $true)]$Binding)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $tab = [char]0x09
    $nonce = [guid]::NewGuid().ToString('N')
    $root = New-PspktTempDirectory -Prefix 'pspkt-phase4-hltamper-'
    $context = $null
    $ok = $false
    $rootCleanupFailure = $null
    try {
        $sourceLeaf = 'src-' + $nonce + '.bin'
        $linkLeaf = 'lnk-' + $nonce + '.bin'
        $sourcePath = Join-Path $root $sourceLeaf
        $linkPath = Join-Path $root $linkLeaf
        $preBytes = [System.Text.Encoding]::ASCII.GetBytes('AAAA')
        [System.IO.File]::WriteAllBytes($sourcePath, $preBytes)

        $hardlinkResult = Invoke-PspktBoundedComSpecCommand -CommandLine ('mklink /H "' + $linkPath + '" "' + $sourcePath + '"') -Label 'generator-hardlink tamper mklink /H'
        $hardlinkCreated = ($hardlinkResult.ExitCode -eq 0 -and [System.IO.File]::Exists($linkPath))

        if (-not $hardlinkCreated) {
            return $false
        }

        $probeStream = [System.IO.FileStream]::new(
            $sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
        try {
            $preFileId = Get-PspktFileStreamFileId48 -Binding $Binding -Stream $probeStream -FullPath $sourcePath
        }
        finally {
            $probeStream.Dispose()
        }
        $preSha = Get-PspktSha256Hex -Bytes $preBytes
        $preResultPath = Join-Path $root ('pre-' + $nonce + '.txt')
        $preRecord = 'pspkt-phase4-hardlink-pre-v1' + $tab + $nonce + $tab + $sourceLeaf + $tab + $linkLeaf + $tab +
            $preFileId + $tab + $preFileId + $tab + $preBytes.Length.ToString($invariant) + $tab + $preSha + [char]0x0A
        [System.IO.File]::WriteAllBytes($preResultPath, [System.Text.Encoding]::ASCII.GetBytes($preRecord))

        $context = [pscustomobject]@{
            Binding = $Binding
            GeneratorNonce = $nonce
            GeneratorHardlinkRoot = $root
            GeneratorHardlinkPreResultPath = $preResultPath
            GeneratorHardlinkStreams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
            GeneratorHardlinkReceipt = $null
        }
        $receipt = Read-PspktGeneratorHardlinkPreResult -Context $context

        [System.IO.File]::Delete($sourcePath)
        $postBytes = [System.Text.Encoding]::ASCII.GetBytes('BB')
        [System.IO.File]::WriteAllBytes($sourcePath, $postBytes)

        $replacementStream = [System.IO.FileStream]::new($sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $reopenedLinkStream = [System.IO.FileStream]::new($linkPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $replacementFileId = Get-PspktFileStreamFileId48 -Binding $Binding -Stream $replacementStream -FullPath $sourcePath
            $reopenedLinkFileId = Get-PspktFileStreamFileId48 -Binding $Binding -Stream $reopenedLinkStream -FullPath $linkPath
            $replacementSha = Get-PspktFileStreamSha256 -Stream $replacementStream
            $reopenedLinkSha = Get-PspktFileStreamSha256 -Stream $reopenedLinkStream
            $replacementLength = [long]$replacementStream.Length
            $reopenedLinkLength = [long]$reopenedLinkStream.Length
        }
        finally {
            $reopenedLinkStream.Dispose()
            $replacementStream.Dispose()
        }

        $genuineRow = [string[]]@(
            'hardlink', $sourceLeaf, $linkLeaf,
            $receipt.FileId48, $receipt.FileId48,
            $receipt.Length.ToString($invariant), $receipt.Sha256,
            $replacementFileId, $reopenedLinkFileId,
            $replacementLength.ToString($invariant), $replacementSha,
            $reopenedLinkLength.ToString($invariant), $reopenedLinkSha)

        $genuineAccepted = Test-PspktGeneratorHardlinkPostState -Context $context -ResultRow $genuineRow
        $nullAccepted = Test-PspktGeneratorHardlinkPostState -Context $context

        $firstChar = $receipt.FileId48.Substring(0, 1)
        if ($firstChar -ceq '0') { $flippedChar = '1' } else { $flippedChar = '0' }
        $forgedPre = $flippedChar + $receipt.FileId48.Substring(1)
        $forgedRow = [string[]]@($genuineRow)
        $forgedRow[3] = $forgedPre
        $forgedRow[4] = $forgedPre
        $forgedRow[8] = $forgedPre

        $internallyConsistent = (
            $forgedRow.Length -eq 13 -and
            [regex]::IsMatch($forgedRow[3], '^[0-9a-f]{48}$') -and
            [regex]::IsMatch($forgedRow[7], '^[0-9a-f]{48}$') -and
            $forgedRow[3] -ceq $forgedRow[4] -and
            $forgedRow[8] -ceq $forgedRow[3] -and
            $forgedRow[7] -cne $forgedRow[8] -and
            $forgedRow[5] -ceq $forgedRow[11] -and
            $forgedRow[6] -ceq $forgedRow[12] -and
            -not ($forgedRow[9] -ceq $forgedRow[11] -and $forgedRow[10] -ceq $forgedRow[12]))

        $forgedRejected = -not (Test-PspktGeneratorHardlinkPostState -Context $context -ResultRow $forgedRow)

        $ok = ($genuineAccepted -and $nullAccepted -and $internallyConsistent -and $forgedRejected -and
            ($receipt.FileId48 -cne $replacementFileId) -and ($receipt.FileId48 -ceq $reopenedLinkFileId))
    }
    finally {
        if ($null -ne $context) {
            foreach ($retainedStream in $context.GeneratorHardlinkStreams) {
                try { $retainedStream.Dispose() } catch { $null = $_ }
            }
        }
        $rootCleanupFailure = Remove-PspktStrictVectorRoot -Root $root -Label 'generator-hardlink-tamper root'
    }
    return ($ok -and ($null -eq $rootCleanupFailure))
}

function Test-PspktBoundedComSpecCommandVectors {
    $successResult = Invoke-PspktBoundedComSpecCommand -CommandLine 'exit 0' -Label 'bounded-comspec success probe'
    $successOk = ($successResult.ExitCode -eq 0)

    $failureResult = Invoke-PspktBoundedComSpecCommand -CommandLine 'exit 7' -Label 'bounded-comspec failure probe'
    $failureOk = ($failureResult.ExitCode -eq 7)

    $timeoutThrew = $false
    $noDetached = $false
    $busyStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $busyStartInfo.FileName = [System.Environment]::GetEnvironmentVariable('ComSpec')
    $busyStartInfo.Arguments = '/c for /l %i in (0,0,1) do @rem'
    $busyStartInfo.UseShellExecute = $false
    $busyStartInfo.CreateNoWindow = $true
    $busyStartInfo.RedirectStandardOutput = $true
    $busyStartInfo.RedirectStandardError = $true
    $busyProcess = [System.Diagnostics.Process]::new()
    $busyProcess.StartInfo = $busyStartInfo
    try {
        Assert-PspktBootstrapProcessLaunchAdmitted -Label 'bounded-comspec timeout probe'
        [void]$busyProcess.Start()
        try {
            [void](Invoke-PspktDrainedProcess -Process $busyProcess -StdoutCap 65536 -StderrCap 65536 -TimeoutMs 750 -Label 'bounded-comspec timeout probe')
        }
        catch {
            if ([string]$_.Exception.Message -match 'exceeded') { $timeoutThrew = $true }
        }
        $noDetached = $busyProcess.HasExited
    }
    finally {
        if (-not $busyProcess.HasExited) {
            try {
                $busyProcess.Kill()
                [void]$busyProcess.WaitForExit(5000)
            }
            catch {
                $null = $_
            }
        }
        Invoke-PspktBootstrapCallerProcessDisposal -Process $busyProcess
    }

    return ($successOk -and $failureOk -and $timeoutThrew -and $noDetached)
}

function Test-PspktGeneratorTargetTraversalVectors {
    $rootReplace = New-PspktTempDirectory -Prefix 'pspkt-phase4-tgttrav-a-'
    $rootDescendant = New-PspktTempDirectory -Prefix 'pspkt-phase4-tgttrav-b-'
    $realTarget = New-PspktTempDirectory -Prefix 'pspkt-phase4-tgttrav-tgt-'
    $replaceOk = $false
    $descendantOk = $false
    $cleanupOk = $true
    $junctionsToRemove = [System.Collections.Generic.List[string]]::new()
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()
    try {
        [System.IO.File]::WriteAllBytes((Join-Path $realTarget 'stub.txt'), [byte[]](65))

        $certJunction = Join-Path $rootReplace 'certification'
        $resultA = Invoke-PspktBoundedComSpecCommand -CommandLine ('mklink /J "' + $certJunction + '" "' + $realTarget + '"') -Label 'target-traversal certification junction mklink /J'
        $createdA = ($resultA.ExitCode -eq 0 -and (Test-Path -LiteralPath $certJunction) -and -not (Test-PspktNonReparseDirectory -FullPath $certJunction))
        if ($createdA) {
            [void]$junctionsToRemove.Add($certJunction)
            $replaceOk = Test-PspktThrowsMatching -Pattern 'is a reparse point' -Action {
                Get-PspktGeneratorOutputDigest -Context ([pscustomobject]@{ GeneratorTargetRoot = $rootReplace })
            }
        }
        else {
            $replaceOk = $false
        }

        $certDir = Join-Path $rootDescendant 'certification'
        [void][System.IO.Directory]::CreateDirectory($certDir)
        $descendantJunction = Join-Path $certDir 'validators'
        $resultB = Invoke-PspktBoundedComSpecCommand -CommandLine ('mklink /J "' + $descendantJunction + '" "' + $realTarget + '"') -Label 'target-traversal descendant junction mklink /J'
        $createdB = ($resultB.ExitCode -eq 0 -and (Test-Path -LiteralPath $descendantJunction) -and -not (Test-PspktNonReparseDirectory -FullPath $descendantJunction))
        if ($createdB) {
            [void]$junctionsToRemove.Add($descendantJunction)
            $descendantOk = Test-PspktThrowsMatching -Pattern 'is a reparse point' -Action {
                Get-PspktGeneratorOutputDigest -Context ([pscustomobject]@{ GeneratorTargetRoot = $rootDescendant })
            }
        }
        else {
            $descendantOk = $false
        }
    }
    finally {
        foreach ($junction in $junctionsToRemove) {
            if (Test-Path -LiteralPath $junction) {
                $removeResult = Invoke-PspktBoundedComSpecCommand -CommandLine ('rmdir "' + $junction + '"') -Label 'target-traversal junction rmdir'
                if ($removeResult.ExitCode -ne 0 -or (Test-Path -LiteralPath $junction)) { $cleanupOk = $false }
            }
        }
        foreach ($cleanupRoot in @($rootReplace, $rootDescendant, $realTarget)) {
            $cleanupRootFailure = Remove-PspktStrictVectorRoot -Root $cleanupRoot -Label 'target-traversal cleanupRoot'
            if ($null -ne $cleanupRootFailure) { [void]$rootCleanupFailures.Add($cleanupRootFailure) }
        }
    }
    return ($replaceOk -and $descendantOk -and $cleanupOk -and ($rootCleanupFailures.Count -eq 0))
}

function Test-PspktReservedContextDeleteFailureVectors {
    $registryBaseline = Get-PspktQuarantineRegistrationCount
    $workerOk = $false
    $generatorOk = $false
    $rootCleanupFailures = [System.Collections.Generic.List[Exception]]::new()

    $workerRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-delfail-worker-'
    $workerLockPath = Join-Path $workerRoot 'locked.bin'
    [System.IO.File]::WriteAllBytes($workerLockPath, [byte[]](1, 2, 3))
    $workerLock = [System.IO.FileStream]::new($workerLockPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $workerTempDirs = [System.Collections.Generic.List[string]]::new()
        [void]$workerTempDirs.Add($workerRoot)
        $workerContext = [pscustomobject]@{
            OwnedEvents = [System.Collections.Generic.List[object]]::new()
            TempDirs = $workerTempDirs
            CleanupState = 'Pending'
        }
        $workerLaunch = [pscustomobject]@{ Session = $null; Context = $workerContext }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $workerFailures = Close-PspktWorkerLaunch -Launch $workerLaunch -OwnershipClean $true
        $workerRegistered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $workerRecord = $null
        if ($workerRegistered) { $workerRecord = $script:Phase4QuarantineRegistry[$countBefore] }
        $workerOk = (
            $workerRegistered -and
            $workerContext.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $workerRoot -PathType Container) -and
            $workerFailures.Count -ge 1 -and
            $null -ne $workerRecord -and
            $workerRecord.Kind -ceq 'Worker' -and
            [object]::ReferenceEquals($workerRecord.Context, $workerContext) -and
            ($workerRecord.Context.TempDirs[0] -ceq $workerRoot))
    }
    finally {
        $workerLock.Dispose()
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
        $workerRootFailure = Remove-PspktStrictVectorRoot -Root $workerRoot -Label 'reserved-context-delete-failure workerRoot'
        if ($null -ne $workerRootFailure) { [void]$rootCleanupFailures.Add($workerRootFailure) }
    }

    $generatorRoot = New-PspktTempDirectory -Prefix 'pspkt-phase4-delfail-gen-'
    $generatorLockPath = Join-Path $generatorRoot 'locked.bin'
    [System.IO.File]::WriteAllBytes($generatorLockPath, [byte[]](4, 5, 6))
    $generatorLock = [System.IO.FileStream]::new($generatorLockPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $generatorContext = New-PspktGeneratorCleanupProbeContext -Root $generatorRoot
        $generatorLaunch = [pscustomobject]@{ Session = $null; Context = $generatorContext }
        $countBefore = Get-PspktQuarantineRegistrationCount
        $generatorFailures = Close-PspktGeneratorLaunch -Launch $generatorLaunch -OwnershipClean $true
        $generatorRegistered = ((Get-PspktQuarantineRegistrationCount) -eq ($countBefore + 1))
        $generatorRecord = $null
        if ($generatorRegistered) { $generatorRecord = $script:Phase4QuarantineRegistry[$countBefore] }
        $generatorOk = (
            $generatorRegistered -and
            $generatorContext.CleanupState -ceq 'Quarantined' -and
            (Test-Path -LiteralPath $generatorRoot -PathType Container) -and
            $generatorFailures.Count -ge 1 -and
            $null -ne $generatorRecord -and
            $generatorRecord.Kind -ceq 'Generator' -and
            [object]::ReferenceEquals($generatorRecord.Context, $generatorContext) -and
            ($generatorRecord.Context.TempDirs[0] -ceq $generatorRoot))
    }
    finally {
        $generatorLock.Dispose()
        Reset-PspktQuarantineRegistryTo -RetainedCount $registryBaseline
        $generatorRootFailure = Remove-PspktStrictVectorRoot -Root $generatorRoot -Label 'reserved-context-delete-failure generatorRoot'
        if ($null -ne $generatorRootFailure) { [void]$rootCleanupFailures.Add($generatorRootFailure) }
    }

    return ($workerOk -and $generatorOk -and ($rootCleanupFailures.Count -eq 0))
}

function Test-PspktGeneratorResultNegativeVectors {
    param([Parameter(Mandatory = $true)]$Binding)
    return (
        (Test-PspktBoundedComSpecCommandVectors) -and
        (Test-PspktGeneratorResultAuthorityVectors) -and
        (Test-PspktGeneratorHardlinkTamperVector -Binding $Binding) -and
        (Test-PspktGeneratorTargetTraversalVectors) -and
        (Test-PspktReservedContextDeleteFailureVectors) -and
        (Test-PspktGeneratorCleanupNegativeVectors) -and
        (Test-PspktQuarantineRegistryVectors))
}

if ($env:PSPKT_PHASE4_DEFINE_ONLY -ceq '1') {
    if ($MyInvocation.InvocationName -cne '.') {
        throw 'PSPKT_PHASE4_DEFINE_ONLY is legal only for a dot-sourced test load.'
    }
    return
}

if ($PSCmdlet.ParameterSetName -ceq 'Worker') {
    Invoke-PspktPhase4Worker -Scenario $WorkerScenario -Mutation $WorkerMutation
    exit 0
}
elseif ($PSCmdlet.ParameterSetName -ceq 'Release') {
    Invoke-PspktPhase4Outer -Mode 'Release' -BaselineCommit $ExpectedBaselineCommit
}
else {
    Invoke-PspktPhase4Outer -Mode 'Slice'
}
