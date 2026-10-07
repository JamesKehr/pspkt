Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktOverlayActivationContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        Sha256ByPath = [ordered]@{
            'certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerContract.ps1' = '208d58db920c066bb2ba757467ef6223ec44f288f0300d2fc9f2959da6a7ac54'
            'certification/evidence-ledger/schema/evidence-schema.v1.json' = '49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6'
            'certification/evidence-ledger/schema/signing-ledger-maxima.v1.json' = 'c0e23855864de532ad5e931f75d5125f5467d44c13abc74400cfde77b49432f4'
            'certification/evidence-ledger/schema/signing-ledger-schema.v1.json' = 'f1599ee3549e5e93783bed9c9db6f2324e41523d780decc9eda54907cd02ec85'
            'certification/lib/Pspkt.Certification.FoundationCatalogEngine.cs' = '80dfd0493f984f19eefc704c37a2eee9ab264a3bf009957ee3f19afec9b4df71'
            'certification/lib/Pspkt.Certification.FoundationPolicy.cs' = 'e4098f6ec53d02215875ebdd64b3c755bfbf3375fecaa60e856a2d18bf1fc6dd'
            'certification/lib/Pspkt.Certification.ProtocolSchemaContract.ps1' = 'a4b591f58401bba682d31a5641e1d062051422b2ea16bd73d2d901f05bb7635e'
            'certification/lib/Pspkt.Certification.SchemaBootstrap.cs' = 'c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74'
            'certification/schema/catalog/overlay.catalog.v1.json' = '0d28afe037201403c5b05db3600268aea5599ac1221ae657a65287fe588daa79'
            'certification/schema/catalog/protocol-base.catalog.v1.json' = '955b1a3042a6bf18eea4339d1a1896199a19ae3ba312ed08ac4bc1304c7bdc82'
            'certification/schema/generated-base-id-map.v1.json' = '66884fb48fcd5ebc3949957c57906614ce3d0d3a6644c6808b1d1796afb45c91'
            'certification/schema/mandatory-tail-schedule.v1.json' = '9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312'
            'certification/schema/protocol-inventory.v1.json' = 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
            'certification/schema/protocol-message-association.v1.json' = '031bf566279871cd79db696ff436aa6d9383f1bb26a62467c3364880a012c5af'
            'certification/schema/protocol-schema-meta.v1.json' = 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
            'certification/schema/protocol-schema.v1.json' = '6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'
            'certification/overlay/.gitattributes' = '5b3ee45ca7a30103aca079c4d93fc75eb9f595774b7934483ff8f71210d073d3'
            'certification/overlay/README.md' = '205341d676d786ee67da350ee5a782513baeb85b990592ff41809b57faa787e0'
            'certification/overlay/lib/.gitattributes' = '5b3ee45ca7a30103aca079c4d93fc75eb9f595774b7934483ff8f71210d073d3'
            'certification/overlay/lib/Pspkt.Certification.OverlayActivationAuthority.cs' = 'a68b1042829b685a54129b9dd1bf393b7035f0c99d7f03b21bc4ebee7d738dd8'
            'certification/overlay/lib/Pspkt.Certification.OverlayActivationVerify.cs' = '2aec8e5cfeceaff87cd18bcc5b9403c5c849ffbb39310d4be5bdb31d9510b2d0'
            'certification/overlay/lib/Pspkt.Certification.OverlayBoundedProcess.cs' = '4c151f819d3a25ca5466ab48c4c2e2dc6f0934c338ecadbd53c36ab570e3928b'
            'certification/overlay/schema/.gitattributes' = '15ef477a8732753a6643795e71dea423c88994c5c11d15cc074a9e1d5736ea8c'
            'certification/overlay/schema/overlay-activation-inventory.v1.json' = '25ce722fb5657b315fcbd5dae779d3f657f4d67d9856dfc7080b02f835833d6f'
            'certification/overlay/schema/protocol-schema.v1.json' = '11cbae40d33c7f8da0c92a4579a003e51df7c7552b5eb9c7e65adada82f88797'
            'certification/overlay/schema/generated-base-id-map.v1.json' = '3b812c056bf63afafd540b9c61f72341a689766318c3606dcd8feba4e2a37ca3'
            'certification/overlay/schema/protocol-message-association.v1.json' = 'f17afa4eab197340d288fe3aea8154d80a696aa98559ef498844c7036b2e73ed'
            'certification/overlay/schema/mandatory-tail-schedule.v1.json' = 'd25c2997a24048e14c97dfc94c0ab05c8ffc8138d0cbc2d330c8f759760296a2'
            'certification/overlay/schema/overlay-matrices.v1.json' = 'e10fccf716e4d935d83adb140a716e1eef9575c57277e250cc40647de07a5f13'
            'certification/overlay/schema/overlay-maxima.v1.json' = '4d92ec08e2676e7d59d4cf522b3ede33a7e668e2c1fcd4b87ad41e3b8bb7d86c'
            'certification/overlay/validators/.gitattributes' = '5b3ee45ca7a30103aca079c4d93fc75eb9f595774b7934483ff8f71210d073d3'
            'certification/overlay/validators/Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1' = '25f789972abbf30ddcd4b46600eee45252529e90f02f54dab2aca194b6435eec'
            'certification/overlay/vectors/.gitattributes' = '5b3ee45ca7a30103aca079c4d93fc75eb9f595774b7934483ff8f71210d073d3'
            'certification/overlay/vectors/New-PspktPhase4OverlayActivationVectors.ps1' = 'b3f98f2c01c84e5d3d757e471057c92d6d72debe968da4a9d2c478777b4a4b01'
            'tests/phase4-overlay/.gitattributes' = '5b3ee45ca7a30103aca079c4d93fc75eb9f595774b7934483ff8f71210d073d3'
        }
        OutputPathSet = [string[]]@(
            'certification/overlay/schema/protocol-schema.v1.json',
            'certification/overlay/schema/generated-base-id-map.v1.json',
            'certification/overlay/schema/protocol-message-association.v1.json',
            'certification/overlay/schema/mandatory-tail-schedule.v1.json',
            'certification/overlay/schema/overlay-matrices.v1.json',
            'certification/overlay/schema/overlay-maxima.v1.json')
    }
}
