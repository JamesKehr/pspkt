[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($OutputRoot -match '^[\\/]{2}[?.][\\/]' -or $OutputRoot -match '^[A-Za-z]:(?![\\/])') {
    throw 'OutputRoot is not a supported absolute filesystem path.'
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$validatorPath = Join-Path $PSScriptRoot '..\validators\Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1'
& $validatorPath -Mode Generate -OutputRoot $OutputRoot | Out-Null

$vectorRoot = Join-Path $OutputRoot 'certification\trusted-control\vectors\synthetic'
[void][IO.Directory]::CreateDirectory($vectorRoot)
$encoding = [Text.UTF8Encoding]::new($false,$true)

function ConvertTo-PspktTrustedControlVectorBytes {
    param(
        [string]$ExpectedReason,
        [string]$CaseKind,
        [Collections.IDictionary]$VectorInput
    )

    $document = [ordered]@{
        schemaId = 'PspktTrustedControlVerificationVectorV1'
        schemaVersion = 1
        syntheticOnly = $true
        expectedReason = $ExpectedReason
        caseKind = $CaseKind
        input = $VectorInput
    }
    return $encoding.GetBytes(($document | ConvertTo-Json -Depth 12 -Compress))
}

$rsaEnvelope = '52534131' + '000c0000' + '04000000' + '80010000' + ('00' * 8) +
    '00010001' + '80' + ('00' * 383) + ('00' * 100)
$rsaEnvelopeExponentThree = '52534131' + '000c0000' + '04000000' + '80010000' + ('00' * 8) +
    '00000003' + '80' + ('00' * 383) + ('00' * 100)
$rsaNativeThree = '52534131' + '000c0000' + '03000000' + '80010000' + ('00' * 8) +
    '010001' + '80' + ('00' * 383)
$rsaNativeFour = '52534131' + '000c0000' + '04000000' + '80010000' + ('00' * 8) +
    '00010001' + '80' + ('00' * 383)
$rsaKeyId = (Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]]@(
    for ($index = 0; $index -lt $rsaEnvelope.Length; $index += 2) {
        [Convert]::ToByte($rsaEnvelope.Substring($index,2),16)
    }))) -Algorithm SHA256).Hash.ToLowerInvariant()
function Get-PspktTrustedControlGoldenDigest {
    param(
        [string]$Domain,
        [string]$MetaSha256,
        [string]$SchemaSha256,
        [string]$CanonicalTlvHex
    )

    $domainBytes = [Text.Encoding]::ASCII.GetBytes($Domain)
    $metaBytes = [Convert]::FromBase64String([Convert]::ToBase64String(
        [byte[]]@(for ($index = 0; $index -lt $MetaSha256.Length; $index += 2) {
            [Convert]::ToByte($MetaSha256.Substring($index,2),16)
        })))
    $schemaBytes = [byte[]]@(for ($index = 0; $index -lt $SchemaSha256.Length; $index += 2) {
        [Convert]::ToByte($SchemaSha256.Substring($index,2),16)
    })
    $tlvBytes = [byte[]]@(for ($index = 0; $index -lt $CanonicalTlvHex.Length; $index += 2) {
        [Convert]::ToByte($CanonicalTlvHex.Substring($index,2),16)
    })
    $payload = [byte[]]@($domainBytes + [byte]0 + $metaBytes + $schemaBytes + $tlvBytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash($payload)).Replace('-','').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}
$protocolMetaDigest = 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
$schemaRoot = Join-Path $PSScriptRoot '..\schema'
$tcastSchemaDigest = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'trusted-control-artifact-set-schema.v1.json') -Algorithm SHA256).Hash.ToLowerInvariant()
$entrypointSchemaDigest = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'powershell-entrypoints-schema.v1.json') -Algorithm SHA256).Hash.ToLowerInvariant()
$supportedBuildSchemaDigest = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'supported-build-entry-schema.v1.json') -Algorithm SHA256).Hash.ToLowerInvariant()
$wIds = @(
    'consoleFenceRetirementDeadline',
    'consoleMainReaderJoinDeadline',
    'terminalRestoreEpisodeDeadline',
    'consoleAuxiliaryQuiescenceDeadline',
    'consoleTopologyRevalidationDeadline',
    'finalFrameOutputDeadline',
    'consoleTopologyRevalidationDeadline',
    'consoleControlCallbackDrainDeadline')
$wTerms = for ($index = 0; $index -lt $wIds.Count; $index++) {
    [ordered]@{ id = $wIds[$index]; value = $index + 1 }
}
$cases = [ordered]@{
    'accept-baseline.json' = @('ok','baseline',[ordered]@{})
    'accept-membership-protocol-meta.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/schema/protocol-schema-meta.v1.json' })
    'accept-membership-schedule.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/schema/mandatory-tail-schedule.v1.json' })
    'accept-membership-evidence-schema.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/evidence-ledger/schema/evidence-schema.v1.json' })
    'accept-membership-signing-schema.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/evidence-ledger/schema/signing-ledger-schema.v1.json' })
    'accept-membership-validator.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/evidence-ledger/validators/Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1' })
    'accept-membership-generator.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/evidence-ledger/vectors/New-PspktPhase4EvidenceLedgerVectors.ps1' })
    'accept-membership-bootstrap.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/lib/Pspkt.Certification.SchemaBootstrap.cs' })
    'accept-membership-protocol-schema.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/schema/protocol-schema.v1.json' })
    'accept-membership-overlay-schedule.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/overlay/schema/mandatory-tail-schedule.v1.json' })
    'accept-membership-protocol-authority.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/lib/Pspkt.Certification.ProtocolSchemaAuthority.cs' })
    'accept-membership-evidence-inventory.json' = @('ok','membershipPath',[ordered]@{ path = 'certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json' })
    'reject-membership-trusted-authority-pending.json' = @(
        'membership-path-pending',
        'membershipPath',
        [ordered]@{ path = 'certification/trusted-control/schema/trusted-control-authority.v1.json' })
    'accept-fixedascii-padding.json' = @('ok','fixedAscii8',[ordered]@{ hex = '6162630000000000' })
    'accept-fixedascii-space.json' = @('ok','fixedAscii8',[ordered]@{ hex = '6120620000000000' })
    'accept-guid-rfc4122-bytes.json' = @('ok','guidBytes',[ordered]@{
        text = '00112233-4455-4677-8899-aabbccddeeff'
        rfc4122Hex = '00112233445546778899aabbccddeeff'
    })
    'accept-luid-big-endian.json' = @('ok','luidBytes',[ordered]@{
        value = [uint64]72623859790382856
        bigEndianHex = '0102030405060708'
    })
    'accept-rsa-envelope.json' = @('ok','rsaEnvelope',[ordered]@{
        hex = $rsaEnvelope
        nativeExponentHex = '010001'
        nativeExponentByteLength = 3
        keyId = $rsaKeyId
    })
    'accept-rsa-envelope-native-four-byte.json' = @('ok','rsaEnvelope',[ordered]@{
        hex = $rsaEnvelope
        nativeExponentHex = '00010001'
        nativeExponentByteLength = 4
        keyId = $rsaKeyId
    })
    'accept-rsa-native-411.json' = @('ok','rsaNative',[ordered]@{
        nativeHex = $rsaNativeThree
        expectedCanonicalHex = $rsaEnvelope
        expectedKeyId = $rsaKeyId
    })
    'accept-rsa-native-412.json' = @('ok','rsaNative',[ordered]@{
        nativeHex = $rsaNativeFour
        expectedCanonicalHex = $rsaEnvelope
        expectedKeyId = $rsaKeyId
    })
    'accept-timing-capacity-equality.json' = @('ok','timing',[ordered]@{
        constraintKind = 'CapacityFit'
        now = 7
        deadline = 7
        relation = 'LE'
    })
    'accept-timing-derived-w.json' = @('ok','timing',[ordered]@{
        now = 6
        deadline = 7
        relation = 'LE'
        constraintKind = 'DerivedW'
        orderedTerms = $wTerms
        derivedW = 36
    })
    'accept-tcast-digest-framing-golden.json' = @('ok','digest',[ordered]@{
        domain = 'pspkt-trusted-control-artifact-set-v1'
        metaSha256 = $protocolMetaDigest
        schemaSha256 = $tcastSchemaDigest
        canonicalTlvHex = '00010000000100'
        expectedDigest = (Get-PspktTrustedControlGoldenDigest 'pspkt-trusted-control-artifact-set-v1' $protocolMetaDigest $tcastSchemaDigest '00010000000100')
    })
    'accept-entrypoint-digest-framing-golden.json' = @('ok','digest',[ordered]@{
        domain = 'pspkt-powershell-entrypoints-v1'
        metaSha256 = $protocolMetaDigest
        schemaSha256 = $entrypointSchemaDigest
        canonicalTlvHex = '0001000000020405'
        expectedDigest = (Get-PspktTrustedControlGoldenDigest 'pspkt-powershell-entrypoints-v1' $protocolMetaDigest $entrypointSchemaDigest '0001000000020405')
    })
    'accept-supported-build-digest-framing-golden.json' = @('ok','digest',[ordered]@{
        domain = 'pspkt-supported-build-entry-v1'
        metaSha256 = $protocolMetaDigest
        schemaSha256 = $supportedBuildSchemaDigest
        canonicalTlvHex = '000100000003070809'
        expectedDigest = (Get-PspktTrustedControlGoldenDigest 'pspkt-supported-build-entry-v1' $protocolMetaDigest $supportedBuildSchemaDigest '000100000003070809')
    })
    'accept-interpreter-binding-set.json' = @('ok','interpreterBinding',[ordered]@{
        entrypointBindings = @([ordered]@{
            key = 'WindowsPowerShell5'
            path = 'c:\windows\system32\windowspowershell\v1.0\powershell.exe'
            imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            volumeSerial = [uint64]1234
            fileId = '00112233445566778899aabbccddeeff'
        })
        buildBindings = @([ordered]@{
            key = 'WindowsPowerShell5'
            path = 'C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe'
            imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            volumeSerial = [uint64]1234
            fileId = '00112233445566778899aabbccddeeff'
        })
    })
    'accept-vt-raise-only.json' = @('ok','timing',[ordered]@{
        constraintKind = 'VT'
        now = 1
        deadline = 2
        vtPolicy = 'raise-only'
    })
    'accept-overlay-dormant.json' = @('ok','overlay',[ordered]@{ requestedState = 'Dormant' })
    'accept-entrypoint-caps-boundary.json' = @('ok','entrypointCaps',[ordered]@{
        rootBytes = 1048576
        aggregateBytes = 2097152
        totalSourceSites = 256
        totalUserArguments = 128
    })
    'reject-aggregate-emission-forbidden.json' = @(
        'aggregate-emission-forbidden','emission',[ordered]@{
            artifactKind = 'TrustedControlArtifactSetV1'
            outputPath = 'certification/trusted-control-artifact-set.v1'
        })
    'reject-external-process-migration-blocker.json' = @(
        'external-process-migration-blocker','migrationBlockers',[ordered]@{
            sites = @([ordered]@{ kind = 'ExternalProcess'; symbol = 'pktmon.exe' })
        })
    'reject-fixedascii-padding-invalid.json' = @(
        'fixedascii-padding-invalid','fixedAscii8',[ordered]@{ hex = '6100620000000000' })
    'reject-guid-rfc4122-bytes-invalid.json' = @(
        'guid-rfc4122-bytes-invalid','guidBytes',[ordered]@{
            text = '00112233-4455-4677-8899-aabbccddeeff'
            rfc4122Hex = '33221100554477668899aabbccddeeff'
        })
    'reject-guid-uppercase.json' = @(
        'guid-rfc4122-bytes-invalid','guidBytes',[ordered]@{
            text = '00112233-4455-4677-8899-AABBCCDDEEFF'
            rfc4122Hex = '00112233445546778899aabbccddeeff'
        })
    'reject-guid-nil.json' = @(
        'guid-rfc4122-bytes-invalid','guidBytes',[ordered]@{
            text = '00000000-0000-0000-0000-000000000000'
            rfc4122Hex = '00000000000000000000000000000000'
        })
    'reject-guid-variant-invalid.json' = @(
        'guid-rfc4122-bytes-invalid','guidBytes',[ordered]@{
            text = '00112233-4455-4677-0899-aabbccddeeff'
            rfc4122Hex = '00112233445546770899aabbccddeeff'
        })
    'reject-guid-version-invalid.json' = @(
        'guid-rfc4122-bytes-invalid','guidBytes',[ordered]@{
            text = '00112233-4455-9677-8899-aabbccddeeff'
            rfc4122Hex = '00112233445596778899aabbccddeeff'
        })
    'accept-guid-version-six.json' = @(
        'ok','guidBytes',[ordered]@{
            text = '00112233-4455-6677-8899-aabbccddeeff'
            rfc4122Hex = '00112233445566778899aabbccddeeff'
        })
    'reject-interpreter-binding-mismatch.json' = @(
        'interpreter-binding-mismatch','interpreterBinding',[ordered]@{
            entrypointBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'c:\windows\system32\windowspowershell\v1.0\powershell.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
            buildBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1235
                fileId = '00112233445566778899aabbccddeefe'
            })
        })
    'reject-interpreter-same-key-different-path.json' = @(
        'interpreter-binding-mismatch','interpreterBinding',[ordered]@{
            entrypointBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'c:\windows\system32\windowspowershell\v1.0\powershell.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
            buildBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'c:\windows\system32\windowspowershell\v1.0\pwsh.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
        })
    'reject-interpreter-device-path.json' = @(
        'interpreter-binding-mismatch','interpreterBinding',[ordered]@{
            entrypointBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = '\\?\c:\windows\system32\powershell.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
            buildBindings = @()
        })
    'reject-interpreter-8dot3-path.json' = @(
        'interpreter-binding-mismatch','interpreterBinding',[ordered]@{
            entrypointBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'c:\progra~1\powershell\powershell.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
            buildBindings = @()
        })
    'reject-interpreter-ads-path.json' = @(
        'interpreter-binding-mismatch','interpreterBinding',[ordered]@{
            entrypointBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'c:\windows\powershell.exe:stream'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
            buildBindings = @()
        })
    'reject-interpreter-reserved-device.json' = @(
        'interpreter-binding-mismatch','interpreterBinding',[ordered]@{
            entrypointBindings = @([ordered]@{
                key = 'WindowsPowerShell5'
                path = 'c:\windows\CON\powershell.exe'
                imageDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                volumeSerial = [uint64]1234
                fileId = '00112233445566778899aabbccddeeff'
            })
            buildBindings = @()
        })
    'reject-luid-big-endian-invalid.json' = @(
        'luid-big-endian-bytes-invalid','luidBytes',[ordered]@{
            value = [uint64]72623859790382856
            bigEndianHex = '0807060504030201'
        })
    'reject-overlay-activation-forbidden.json' = @(
        'overlay-activation-forbidden','overlay',[ordered]@{ requestedState = 'Active' })
    'reject-overlay-token-forbidden.json' = @(
        'overlay-activation-forbidden','overlay',[ordered]@{ requestedState = 'EnableNow' })
    'reject-powershell-migration-blocker.json' = @(
        'powershell-migration-blocker','migrationBlockers',[ordered]@{
            sites = @([ordered]@{ kind = 'PowerShell'; symbol = 'Start-Process' })
        })
    'reject-migration-empty.json' = @(
        'migration-sites-empty','migrationBlockers',[ordered]@{ sites = @() })
    'reject-migration-kind-unknown.json' = @(
        'migration-kind-unknown','migrationBlockers',[ordered]@{
            sites = @([ordered]@{ kind = 'Banana'; symbol = 'Unknown' })
        })
    'reject-registry-instance-forbidden.json' = @(
        'registry-instance-forbidden','emission',[ordered]@{
            artifactKind = 'SupportedBuildRegistryV1'
            outputPath = 'certification/trusted-control/schema/supported-builds.v1.json'
        })
    'reject-rsa-envelope-length-or-conversion-invalid.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope
            nativeExponentHex = '000003'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-cb-public-exp.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,16) + '03000000' + $rsaEnvelope.Substring(24)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-cb-modulus.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,24) + '00010000' + $rsaEnvelope.Substring(32)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-cb-prime1.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,32) + '01000000' + $rsaEnvelope.Substring(40)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-cb-prime2.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,40) + '01000000' + $rsaEnvelope.Substring(48)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-native-length-mismatch.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope
            nativeExponentHex = '010001'
            nativeExponentByteLength = 4
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-native-length-rule.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope
            nativeExponentHex = '0001'
            nativeExponentByteLength = 2
            keyId = $rsaKeyId
        })
    'reject-rsa-envelope-canonical-exponent.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,48) + '01000100' + $rsaEnvelope.Substring(56)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-keyid-invalid.json' = @(
        'rsa-key-id-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = ('00' * 32)
        })
    'reject-rsa-magic-invalid.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = '52534132' + $rsaEnvelope.Substring(8)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-bits-invalid.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,8) + '00080000' + $rsaEnvelope.Substring(16)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-topbit-invalid.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,56) + '00' + $rsaEnvelope.Substring(58)
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-rsa-tail-invalid.json' = @(
        'rsa-envelope-length-or-conversion-invalid','rsaEnvelope',[ordered]@{
            hex = $rsaEnvelope.Substring(0,$rsaEnvelope.Length - 2) + '01'
            nativeExponentHex = '010001'
            nativeExponentByteLength = 3
            keyId = $rsaKeyId
        })
    'reject-schema-meta-mismatch.json' = @(
        'schema-meta-mismatch','schemaMetaHash',[ordered]@{
            expectedSha256 = '0000000000000000000000000000000000000000000000000000000000000000'
        })
    'reject-digest-placeholder.json' = @(
        'digest-input-placeholder-or-mismatch','digest',[ordered]@{
            domain = 'pspkt-trusted-control-artifact-set-v1'
            metaSha256 = ('00' * 32)
            schemaSha256 = ('11' * 32)
            canonicalTlvHex = '00010000000100'
            expectedDigest = ('00' * 32)
        })
    'reject-digest-wrong-meta-only.json' = @(
        'digest-input-placeholder-or-mismatch','digest',[ordered]@{
            domain = 'pspkt-trusted-control-artifact-set-v1'
            metaSha256 = ('22' * 32)
            schemaSha256 = $tcastSchemaDigest
            canonicalTlvHex = '00010000000100'
            expectedDigest = (Get-PspktTrustedControlGoldenDigest 'pspkt-trusted-control-artifact-set-v1' ('22' * 32) $tcastSchemaDigest '00010000000100')
        })
    'reject-digest-placeholder-schema-only.json' = @(
        'digest-input-placeholder-or-mismatch','digest',[ordered]@{
            domain = 'pspkt-trusted-control-artifact-set-v1'
            metaSha256 = $protocolMetaDigest
            schemaSha256 = ('11' * 32)
            canonicalTlvHex = '00010000000100'
            expectedDigest = ('00' * 32)
        })
    'reject-digest-mismatched-schema-only.json' = @(
        'digest-input-placeholder-or-mismatch','digest',[ordered]@{
            domain = 'pspkt-trusted-control-artifact-set-v1'
            metaSha256 = $protocolMetaDigest
            schemaSha256 = ('22' * 32)
            canonicalTlvHex = '00010000000100'
            expectedDigest = ('00' * 32)
        })
    'reject-digest-tlv-framing.json' = @(
        'digest-tlv-framing-invalid','digest',[ordered]@{
            domain = 'pspkt-trusted-control-artifact-set-v1'
            metaSha256 = $protocolMetaDigest
            schemaSha256 = $tcastSchemaDigest
            canonicalTlvHex = '00010203'
            expectedDigest = ('00' * 32)
        })
    'reject-timing-deadline-equality-expired.json' = @(
        'timing-deadline-equality-expired','timing',[ordered]@{
            constraintKind = 'Deadline'
            now = 7
            deadline = 7
            relation = 'LT'
        })
    'reject-timing-deadline-late.json' = @(
        'timing-deadline-late','timing',[ordered]@{
            constraintKind = 'Deadline'
            now = 8
            deadline = 7
            relation = 'LT'
        })
    'reject-timing-deadline-le-invalid.json' = @(
        'timing-kind-relation-invalid','timing',[ordered]@{
            constraintKind = 'Deadline'
            now = 7
            deadline = 7
            relation = 'LE'
        })
    'reject-timing-derived-w-invalid.json' = @(
        'timing-derived-w-invalid','timing',[ordered]@{
            now = 6
            deadline = 7
            relation = 'LE'
            constraintKind = 'DerivedW'
            orderedTerms = $wTerms
            derivedW = 35
        })
    'reject-timing-derived-w-count.json' = @(
        'timing-derived-w-terms','timing',[ordered]@{
            now = 6
            deadline = 7
            relation = 'LE'
            constraintKind = 'DerivedW'
            orderedTerms = @($wTerms[0..6])
            derivedW = 28
        })
    'reject-timing-derived-w-order.json' = @(
        'timing-derived-w-order','timing',[ordered]@{
            now = 6
            deadline = 7
            relation = 'LE'
            constraintKind = 'DerivedW'
            orderedTerms = @($wTerms[1],$wTerms[0],$wTerms[2],$wTerms[3],$wTerms[4],$wTerms[5],$wTerms[6],$wTerms[7])
            derivedW = 36
        })
    'reject-timing-relation-unknown.json' = @(
        'timing-relation-unknown','timing',[ordered]@{
            constraintKind = 'Deadline'
            now = 1
            deadline = 2
            relation = 'EQ'
        })
    'reject-timing-kind-unknown.json' = @(
        'timing-kind-unknown','timing',[ordered]@{
            constraintKind = 'Unknown'
            now = 1
            deadline = 2
            relation = 'LT'
        })
    'reject-vt-policy-invalid.json' = @(
        'timing-kind-relation-invalid','timing',[ordered]@{
            constraintKind = 'VT'
            now = 1
            deadline = 2
            vtPolicy = 'lower-allowed'
        })
    'reject-rsa-native-rsa2.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = '52534132' + $rsaNativeThree.Substring(8)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-2048.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree.Substring(0,8) + '00080000' + $rsaNativeThree.Substring(16)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-prime.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree.Substring(0,32) + '01000000' + $rsaNativeThree.Substring(40)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-cb-modulus.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree.Substring(0,24) + '00010000' + $rsaNativeThree.Substring(32)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-cb-prime2.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree.Substring(0,40) + '01000000' + $rsaNativeThree.Substring(48)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-exponent-value.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree.Substring(0,48) + '010002' + $rsaNativeThree.Substring(54)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-top-bit.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree.Substring(0,54) + '00' + $rsaNativeThree.Substring(56)
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-canonical-hex.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree
            expectedCanonicalHex = $rsaEnvelope.Substring(0,$rsaEnvelope.Length - 2) + '01'
            expectedKeyId = $rsaKeyId
        })
    'reject-rsa-native-key-id.json' = @(
        'rsa-native-conversion-invalid','rsaNative',[ordered]@{
            nativeHex = $rsaNativeThree
            expectedCanonicalHex = $rsaEnvelope
            expectedKeyId = ('00' * 32)
        })
    'reject-fixedascii-control-invalid.json' = @(
        'fixedascii-padding-invalid','fixedAscii8',[ordered]@{ hex = '611f620000000000' })
    'reject-fixedascii-delete-invalid.json' = @(
        'fixedascii-padding-invalid','fixedAscii8',[ordered]@{ hex = '617f620000000000' })
    'reject-artifact-path-invalid.json' = @(
        'artifact-path-invalid','pathSet',[ordered]@{ paths = @('certification\..\escape.json') })
    'reject-artifact-device-path-invalid.json' = @(
        'artifact-path-invalid','pathSet',[ordered]@{ paths = @('certification/CON/file.json') })
    'reject-artifact-trailing-alias-invalid.json' = @(
        'artifact-path-invalid','pathSet',[ordered]@{ paths = @('certification/file./x.json') })
    'reject-membership-outside-certification.json' = @(
        'membership-path-outside-certification','membershipPath',[ordered]@{ path = 'README.md' })
    'reject-membership-case-alias.json' = @(
        'membership-path-outside-certification','membershipPath',[ordered]@{
            path = 'Certification/schema/protocol-schema-meta.v1.json'
        })
    'reject-membership-fixture-case-alias.json' = @(
        'membership-case-alias','membershipPath',[ordered]@{
            path = 'certification/schema/Protocol-schema-meta.v1.json'
            trackedPaths = @(
                'certification/schema/Protocol-schema-meta.v1.json',
                'certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @()
        })
    'reject-membership-malformed.json' = @(
        'membership-path-invalid','membershipPath',[ordered]@{ path = 'certification\schema\protocol-schema-meta.v1.json' })
    'reject-membership-untracked.json' = @(
        'membership-path-untracked','membershipPath',[ordered]@{ path = 'certification/schema/not-tracked.v1.json' })
    'reject-membership-fixture-unsorted.json' = @(
        'membership-fixture-unsorted','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @(
                'certification/schema/protocol-schema.v1.json',
                'certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @()
        })
    'reject-membership-fixture-duplicate.json' = @(
        'membership-fixture-duplicate','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @(
                'certification/schema/protocol-schema-meta.v1.json',
                'certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @()
        })
    'reject-membership-fixture-overlap.json' = @(
        'membership-fixture-overlap','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @('certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @('certification/schema/protocol-schema-meta.v1.json')
        })
    'reject-membership-fixture-invalid-path.json' = @(
        'membership-fixture-invalid-path','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @('certification\schema\protocol-schema-meta.v1.json')
            pendingPaths = @('C:\host\root')
        })
    'reject-membership-tracked-only-invalid.json' = @(
        'membership-fixture-invalid-path','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @('certification\schema\protocol-schema-meta.v1.json')
            pendingPaths = @()
        })
    'reject-membership-pending-only-invalid.json' = @(
        'membership-fixture-invalid-path','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @('certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @('C:\host\root')
        })
    'reject-membership-pending-unsorted.json' = @(
        'membership-fixture-unsorted','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @('certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @(
                'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'certification/trusted-control/schema/trusted-control-authority.v1.json')
        })
    'reject-membership-pending-duplicate.json' = @(
        'membership-fixture-duplicate','membershipPath',[ordered]@{
            path = 'certification/schema/protocol-schema-meta.v1.json'
            trackedPaths = @('certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @(
                'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        })
    'reject-membership-enrolled-present.json' = @(
        'membership-path-pending','membershipPath',[ordered]@{
            path = 'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        })
    'reject-membership-enrolled-pending-missing.json' = @(
        'membership-path-pending-missing','membershipPath',[ordered]@{
            path = 'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            trackedPaths = @('certification/schema/protocol-schema-meta.v1.json')
            pendingPaths = @('certification/trusted-control/schema/trusted-control-authority.v1.json')
        })
    'reject-membership-enrolled-tracked.json' = @(
        'membership-fixture-invalid-path','membershipPath',[ordered]@{
            path = 'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            trackedPaths = @('enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
            pendingPaths = @()
        })
    'reject-entrypoint-root-cap.json' = @(
        'entrypoint-cap-exceeded','entrypointCaps',[ordered]@{
            rootBytes = 1048577
            aggregateBytes = 2097152
            totalSourceSites = 256
            totalUserArguments = 128
        })
    'reject-entrypoint-aggregate-cap.json' = @(
        'entrypoint-cap-exceeded','entrypointCaps',[ordered]@{
            rootBytes = 1048576
            aggregateBytes = 2097153
            totalSourceSites = 256
            totalUserArguments = 128
        })
    'reject-entrypoint-sites-cap.json' = @(
        'entrypoint-cap-exceeded','entrypointCaps',[ordered]@{
            rootBytes = 1048576
            aggregateBytes = 2097152
            totalSourceSites = 257
            totalUserArguments = 128
        })
    'reject-entrypoint-arguments-cap.json' = @(
        'entrypoint-cap-exceeded','entrypointCaps',[ordered]@{
            rootBytes = 1048576
            aggregateBytes = 2097152
            totalSourceSites = 256
            totalUserArguments = 129
        })
    'reject-schema-emission-undeclared.json' = @(
        'registry-instance-forbidden','emission',[ordered]@{
            artifactKind = 'Schema'
            outputPath = 'certification/trusted-control/schema/undeclared-schema.v1.json'
        })
    'reject-trusted-artifact-path-collision.json' = @(
        'trusted-artifact-path-collision','pathSet',[ordered]@{
            paths = @('certification/a.json','CERTIFICATION/A.JSON')
        })
}

$membershipTrackedPaths = [string[]]@(
    'certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json',
    'certification/evidence-ledger/schema/evidence-schema.v1.json',
    'certification/evidence-ledger/schema/signing-ledger-schema.v1.json',
    'certification/evidence-ledger/validators/Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1',
    'certification/evidence-ledger/vectors/New-PspktPhase4EvidenceLedgerVectors.ps1',
    'certification/lib/Pspkt.Certification.ProtocolSchemaAuthority.cs',
    'certification/lib/Pspkt.Certification.SchemaBootstrap.cs',
    'certification/overlay/schema/mandatory-tail-schedule.v1.json',
    'certification/schema/mandatory-tail-schedule.v1.json',
    'certification/schema/protocol-schema-meta.v1.json',
    'certification/schema/protocol-schema.v1.json')
$membershipPendingPaths = [string[]]@(
    'certification/trusted-control/schema/trusted-control-authority.v1.json',
    'enrolled-host-root/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
foreach ($caseName in $cases.Keys) {
    $caseDefinition = $cases[$caseName]
    if ($caseDefinition[1] -ceq 'membershipPath') {
        if (-not $caseDefinition[2].Contains('trackedPaths')) {
            $caseDefinition[2]['trackedPaths'] = $membershipTrackedPaths
        }
        if (-not $caseDefinition[2].Contains('pendingPaths')) {
            $caseDefinition[2]['pendingPaths'] = $membershipPendingPaths
        }
    }
}

$manifestCases = [Collections.Generic.List[object]]::new()
$expectedVectorNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in $cases.Keys) { [void]$expectedVectorNames.Add($name) }
[void]$expectedVectorNames.Add('manifest.v1.json')
foreach ($existingVector in Get-ChildItem -LiteralPath $vectorRoot -Filter '*.json' -File -Force) {
    if (-not $expectedVectorNames.Contains($existingVector.Name)) {
        throw "Trusted-control vector directory contains an unexpected file: $($existingVector.Name)"
    }
}
$stagingRoot = Join-Path ([IO.Path]::GetDirectoryName($vectorRoot)) (
    '.trusted-control-vector-stage-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stagingRoot)
try {
foreach ($name in $cases.Keys) {
    $definition = $cases[$name]
    $bytes = ConvertTo-PspktTrustedControlVectorBytes `
        -ExpectedReason $definition[0] `
        -CaseKind $definition[1] `
        -VectorInput $definition[2]
    $path = Join-Path $stagingRoot $name
    [IO.File]::WriteAllBytes($path,$bytes)
    $manifestCases.Add([ordered]@{
        path = $name
        byteLength = [long]$bytes.LongLength
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        expectedReason = $definition[0]
    })
}

$manifestBytes = $encoding.GetBytes(([ordered]@{
    schemaId = 'PspktTrustedControlVectorManifestV1'
    schemaVersion = 1
    syntheticOnly = $true
    cases = $manifestCases
} | ConvertTo-Json -Depth 8 -Compress))
[IO.File]::WriteAllBytes((Join-Path $stagingRoot 'manifest.v1.json'),$manifestBytes)
foreach ($name in $expectedVectorNames) {
    $sourcePath = Join-Path $stagingRoot $name
    $destinationPath = Join-Path $vectorRoot $name
    if ([IO.File]::Exists($destinationPath)) {
        [IO.File]::Replace($sourcePath,$destinationPath,[NullString]::Value)
    }
    else {
        [IO.File]::Move($sourcePath,$destinationPath)
    }
}
}
finally {
    if ([IO.Directory]::Exists($stagingRoot)) {
        [IO.Directory]::Delete($stagingRoot,$true)
    }
}

if ($SelfTest) {
    & $validatorPath -Mode Validate -OutputRoot $OutputRoot | Out-Null
    foreach ($case in $manifestCases) {
        $path = Join-Path $vectorRoot $case.path
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.LongLength -ne $case.byteLength) {
            throw "Trusted-control vector length differs: $($case.path)"
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne $case.sha256) {
            throw "Trusted-control vector hash differs: $($case.path)"
        }
        $result = & $validatorPath -Mode VerifyVector -VectorPath $path
        $expectedResult = "TRUSTED_CONTROL_VECTOR_OK|reason=$($case.expectedReason)"
        if ($result -cne $expectedResult) {
            throw "Trusted-control vector verification result differs: $($case.path)"
        }
    }
    "TRUSTED_CONTROL_VECTORS_OK|schemas=10|cases=$($manifestCases.Count)"
}
