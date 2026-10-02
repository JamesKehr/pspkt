Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktProtocolSchemaContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        FrozenSha256ByPath = [ordered]@{
            'certification/lib/Pspkt.Certification.FoundationCatalogEngine.cs' = '80dfd0493f984f19eefc704c37a2eee9ab264a3bf009957ee3f19afec9b4df71'
            'certification/lib/Pspkt.Certification.FoundationPolicy.cs' = 'e4098f6ec53d02215875ebdd64b3c755bfbf3375fecaa60e856a2d18bf1fc6dd'
            'certification/lib/Pspkt.Certification.SchemaBootstrap.cs' = 'c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74'
            'certification/lib/Pspkt.Certification.FoundationContract.ps1' = '7cd47c8be01ff2a6d6504e824ee3a6594f397a94c538ca222a8013dec757bef8'
            'certification/schema/protocol-schema-meta.v1.json' = 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
            'certification/.gitattributes' = 'd5a6013a52c5083c22a15f5287ee0e26731c8b47a26af659ca75a21fd4767f1f'
            'tests/.gitattributes' = '96ab6bee2892589cb11912947f58ea6cdd1b253552ee59d35010ffe7dd3d868f'
            '.gitattributes' = '4fb78db0ed73b7f5c63edfe3ce6f71baf427bb80cfda9ec0d046b68907fc0f3c'
        }
        AttributeSha256ByPath = [ordered]@{
            'certification/lib/.gitattributes' = '400eb5662f50e67f0a102824637cf005e6cb3d779d9e332e336caa8d66bdcc63'
            'certification/schema/.gitattributes' = '26c67d27238e780a96ec8fc22a2430f95aa488f6e975104f1e2f931763f4798d'
            'certification/vectors/.gitattributes' = 'bb9f06ec9948aff2b7fb06e7469b666968212dba4c3604499a67e8c214471a72'
            'certification/validators/.gitattributes' = 'e2f054aa25f8be5fc99b71757cc1044bf7fa35cde7bfde0a870eabb9e03bd8a6'
            'tests/phase4-protocol/.gitattributes' = '5fe227b68a19c96a91298b4ea93bb67449509fb942fc1e2bffef3d422b82e9c2'
        }
        SourceSha256ByPath = [ordered]@{
            'dependency1bb-protocol-authority-plan-r10.json' = 'e1cc216b64d524d069f32462d501e457d015ee5b236372e830140d90063d9300'
            'dependency1bb-r9-normative-tables.txt' = 'abb6b0a4939ce88791e5e90961fc8053eb896e56e34fc4f0668ac6476e85e3ba'
            'dependency1bb-r8-lifecycle-variants.json' = '8718dd1de27850663988c52bdd41a5ca5617c584b9a84f59e6d5a1cdfaa0d496'
            'dependency1b-schema-authority-plan.md' = '9d561e714839c52729a617346ebd5fe69bf147a262a39107208c8949f992c93c'
            'phase4-r6-final-design.md' = '6cfd8953c7cbcf9ee28634bd892c697df86dd43094233776b1aa9a31ddd7d241'
            'phase4-credential-free-design-delta.md' = '9b3bd129f1e7c0d89f7ecafbe42284b45bebe0676cac1c5bca1ea3529e9bf904'
        }
        InputSha256ByPath = [ordered]@{
            'certification/schema/catalog/protocol-base.catalog.v1.json' = '955b1a3042a6bf18eea4339d1a1896199a19ae3ba312ed08ac4bc1304c7bdc82'
            'certification/schema/catalog/overlay.catalog.v1.json' = '0d28afe037201403c5b05db3600268aea5599ac1221ae657a65287fe588daa79'
            'certification/schema/protocol-inventory.v1.json' = 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
        }
        OutputSha256ByPath = [ordered]@{
            'certification/schema/protocol-schema.v1.json' = '6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'
            'certification/schema/generated-base-id-map.v1.json' = '66884fb48fcd5ebc3949957c57906614ce3d0d3a6644c6808b1d1796afb45c91'
            'certification/schema/protocol-message-association.v1.json' = '031bf566279871cd79db696ff436aa6d9383f1bb26a62467c3364880a012c5af'
            'certification/schema/mandatory-tail-schedule.v1.json' = '9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312'
        }
        FilteredSha256ByName = [ordered]@{
            'filtered-base' = '39fc11bdcbb6f11ba95390a3df509738eee3eb85eb8060a2bde73b2566d1eaec'
            'filtered-overlay' = 'ea565930105baad2798daf48b512879a07c04d0d5ab66ee113b7907afa28860a'
            'removed-operations' = 'f89ba8c4907609fe2d8b84fd2e1450c3cc1681e55714e129f1fe76b351a45357'
            'retained-type-order' = '66e86ee64d9d5a64db5020b363f59816b5e1353855a05303efa2f26e61c28608'
        }
        UnionMappingSha256ByName = [ordered]@{
            'union:LaunchFenceGate' = '54fe37af83d6827e8c0461812cc608a3ac7f4179002ef47ef408a038daf40d4c'
            'union:CreatePermit' = '9fe4c9ea447bb5669f6b399f51dd139b0d387cd120615fcee18d6fd2a17d9fbb'
            'union:AuthorizationLedgerRecord' = '8f84a01aa925124afcf2e3a385dec2f44be907a5cd7066e99fefee85db7e3d33'
            'union:OperationRecord' = '8cf2da990e584c2d8ac74a0c58d32a81661cac078221bea6f0ed34f5f10aac6d'
        }
        RemovedOperationGroups = @(
            [pscustomobject]@{ Catalog = 'base'; First = 187; Last = 187; Category = 'type' },
            [pscustomobject]@{ Catalog = 'base'; First = 188; Last = 194; Category = 'field' },
            [pscustomobject]@{ Catalog = 'base'; First = 195; Last = 195; Category = 'type' },
            [pscustomobject]@{ Catalog = 'base'; First = 196; Last = 198; Category = 'field' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 26; Last = 26; Category = 'overlay-type' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 27; Last = 54; Category = 'field-set' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 55; Last = 55; Category = 'overlay-type' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 56; Last = 73; Category = 'field-set' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 144; Last = 144; Category = 'overlay-type' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 145; Last = 170; Category = 'field-set' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 413; Last = 413; Category = 'overlay-message' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 415; Last = 416; Category = 'overlay-message' },
            [pscustomobject]@{ Catalog = 'overlay'; First = 421; Last = 421; Category = 'overlay-message' })
        SurvivingOperationCounts = [ordered]@{ Base = 296; Overlay = 355 }
        NamePredicate = '^[A-Za-z][A-Za-z0-9-]*$'
        BaseCatalogSchemaId = 'PspktProtocolBaseCatalogV1'
        BaseCatalogSpace = 'protocol-base'
        OverlayCatalogSchemaId = 'PspktProtocolOverlayCatalogV1'
        OverlayCatalogSpace = 'protocol-overlay'
        EmitSchemaId = 'PspktProtocolSchemaV1'
        MapSchemaId = 'PspktGeneratedBaseIdMapV1'
        Channels = [string[]]@(
            'WorkerApp',
            'BrokerControl',
            'LocalIpc')
        MessageEnumNameByChannel = [ordered]@{
            WorkerApp = 'WorkerAppMessageKind'
            BrokerControl = 'BrokerControlMessageKind'
            LocalIpc = 'LocalIpcMessageKind'
        }
        PermittedDirectionsByChannel = [ordered]@{
            WorkerApp = [string[]]@('HostToWorker', 'WorkerToHost')
            BrokerControl = [string[]]@('HostToBroker', 'BrokerToHost')
            LocalIpc = [string[]]@('WorkerToBroker', 'BrokerToWorker')
        }
        OverlayKindRangesByChannel = [ordered]@{
            WorkerApp = @(
                [pscustomobject]@{ Start = 0x1080; End = 0x10FF })
            BrokerControl = @(
                [pscustomobject]@{ Start = 0x1100; End = 0x110F },
                [pscustomobject]@{ Start = 0x1110; End = 0x11FF })
            LocalIpc = @(
                [pscustomobject]@{ Start = 0x1200; End = 0x12FF })
        }
        OverlayTypeRange = [pscustomobject]@{ Start = 0x1300; End = 0x13FF }
        GeneratedFieldIdMax = 39
        LiteralExtensionParentNames = [string[]]@(
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
        DeferredSeedTypeNames = [string[]]@(
            'MintAttestedV1',
            'S4UMintSlotV1',
            'ServiceControlEventNodeProofV1')
        DeferredSeedMessageKeys = [string[]]@(
            'BrokerControl:MintRevoked')
        OutputPathSet = [string[]]@(
            'certification/schema/protocol-schema.v1.json',
            'certification/schema/generated-base-id-map.v1.json',
            'certification/schema/protocol-message-association.v1.json',
            'certification/schema/mandatory-tail-schedule.v1.json')
    }
}
