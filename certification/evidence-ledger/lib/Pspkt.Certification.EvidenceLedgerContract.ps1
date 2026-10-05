Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktEvidenceLedgerContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        Sha256ByPath = [ordered]@{
            'certification/lib/Pspkt.Certification.SchemaBootstrap.cs' = 'c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74'
            'certification/schema/protocol-schema-meta.v1.json' = 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
            'certification/schema/protocol-schema.v1.json' = '6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'
            'certification/schema/protocol-inventory.v1.json' = 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
            'certification/evidence-ledger/.gitattributes' = '02569930d8b1b2dd19e1b7397aebcaa9d7a9db74ed4aebd36f86a717262e7d4b'
            'certification/evidence-ledger/lib/.gitattributes' = 'ff91d6cdb38028607d0a608d016728e3a95fe85975900d8eeb38ba3f3941e6e5'
            'certification/evidence-ledger/schema/.gitattributes' = 'ebf2b8bd099a5096aecb683468622d45e74ee7948e20d3750f12442a48f97d91'
            'certification/evidence-ledger/validators/.gitattributes' = 'ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32'
            'certification/evidence-ledger/vectors/.gitattributes' = 'ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32'
            'tests/phase4-evidence-ledger/.gitattributes' = 'ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32'
            'certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerAuthority.cs' = '6c69ee0ac5880310ee5c4b5bc0d53c8e78f123004c849b7a46fd35dd9b03500c'
            'certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerVerify.cs' = 'aea9f3d62bb671e8dcd090a9076384fba8d59502cac3ec3c60a2c50acac40771'
            'certification/evidence-ledger/validators/Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1' = 'b5912c08307879f3ce1c4ba80169f1d0c9e4e99dd25614775121155bcc291794'
            'certification/evidence-ledger/vectors/New-PspktPhase4EvidenceLedgerVectors.ps1' = '6de339879e058597c5cb2a9f099a6aa4725180169be26ec687d55928f155a772'
            'certification/evidence-ledger/README.md' = '649059f3797b22cb0b7c832aa63d37c2d7bd8c43af186dec80aa429e5773c7f2'
            'certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json' = '07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9'
            'certification/evidence-ledger/schema/evidence-schema.v1.json' = '49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6'
            'certification/evidence-ledger/schema/signing-ledger-schema.v1.json' = 'f1599ee3549e5e93783bed9c9db6f2324e41523d780decc9eda54907cd02ec85'
            'certification/evidence-ledger/schema/signing-ledger-maxima.v1.json' = 'c0e23855864de532ad5e931f75d5125f5467d44c13abc74400cfde77b49432f4'
        }
        MaintainedInputPathSet = [string[]]@(
            'certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json')
        OutputPathSet = [string[]]@(
            'certification/evidence-ledger/schema/evidence-schema.v1.json',
            'certification/evidence-ledger/schema/signing-ledger-schema.v1.json',
            'certification/evidence-ledger/schema/signing-ledger-maxima.v1.json')
        PlanSha256 = 'cadb19b8dff7db6daca6e7ffd73afc5f8665cdd67bbddfd35397c18e2db766f7'
        BaseCommit = '27014f0ffd91d3338b41c1e91f505cac2b879f37'
        EvidenceTypeCount = 24
        LedgerTypeCount = 60
        EvidenceKindCount = 22
        AuthorizationKindCount = 16
        OperationKindCount = 29
        ConsumerContractSha256 = '27ba860032b2399e2dc25d05e805fc18d601cfea53e656d4442621ab6ce65732'
        InventoryShapeSha256 = 'ed6eaad545a48454347a51da96764f0b804dd2f1bf0ce7638a96c6e09c1fa1d7'
        EvidenceRootOrder = [string[]]@(
            'WorkerSessionKeyCertificateV1','BrokerSessionKeyCertificateBodyV1','BrokerSessionKeyCertificateEnvelopeV1',
            'WorkerProcessIsolationAdmissionReceiptV1','WorkerProcessIsolationReceiptV1','ServiceLaunchProofV1',
            'ServiceEnrollmentInstallProofV1','WorkerProcessDaclAccessPolicyProofV1','LiveCandidateAccessProbeV1',
            'LocalTranscriptChunkV1','LocalTranscriptRootV1','LocalTranscriptProofV1','LocalTranscriptRootAcceptedV1',
            'BrokerServiceLaunchProofV1','CreatorPermitInstallationBodyV1','CreatorPermitInstallationV1')
        DeferredEvidenceRoots = [string[]]@('ServiceControlEventNodeProofV1')
        EvidenceAppendOrder = [string[]]@(
            'LocalEvidenceReceiptV1','LocalEvidenceProofV1','OperationBurnReceiptV1','OperationBurnDeferralReceiptV1',
            'OperationRehabilitationAuthorizationV1','OperationRehabilitationReceiptV1','EvidenceArtifactKind','EvidenceArtifactEnvelopeV1')
        LedgerAppendOrder = [string[]]@(
            'OperationBurnReceiptV1','OperationBurnDeferralReceiptV1','OperationRehabilitationAuthorizationV1',
            'OperationRehabilitationReceiptV1','OperationSigningLedgerKind','AuthorizationSigningLedgerRecordEnvelopeV1',
            'OperationSigningLedgerRecordEnvelopeV1','AuthorizationSigningLedgerRecordList','OperationSigningLedgerRecordList',
            'SigningLedgerSegmentHeaderV1','AuthorizationSigningLedgerSegmentV1','OperationSigningLedgerSegmentV1',
            'Sha256SiblingList','AuthorizationSigningLedgerInclusionProofV1','OperationSigningLedgerInclusionProofV1')
        MaximumSegmentRecords = 4096
        MaximumInclusionSiblingHashes = 12
        MaximaRowOrder = [string[]]@('Authorization', 'Operation')
    }
}
