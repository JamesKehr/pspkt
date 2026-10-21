Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktTrustedControlContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        Sha256ByPath = [ordered]@{
            'certification/lib/Pspkt.Certification.SchemaBootstrap.cs' = 'c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74'
            'certification/schema/mandatory-tail-schedule.v1.json' = '9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312'
            'certification/schema/protocol-inventory.v1.json' = 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
            'certification/schema/protocol-schema-meta.v1.json' = 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
            'certification/schema/protocol-schema.v1.json' = '6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'
            'certification/trusted-control/.gitattributes' = '02569930d8b1b2dd19e1b7397aebcaa9d7a9db74ed4aebd36f86a717262e7d4b'
            'certification/trusted-control/lib/.gitattributes' = 'ff91d6cdb38028607d0a608d016728e3a95fe85975900d8eeb38ba3f3941e6e5'
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlAuthority.cs' = 'd70caa9878f2e45b5523cc92006bb63fa5a63ed3be9a5c05592f39d7e78b9fe8'
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs' = 'fccf6eb07bc87ce6277abf6040f7098cdc1d0d28ba886b1cb73a60abf68e7291'
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlNativeSecurity.cs' = 'a257675037066a53680532963673be05b58c8d5d92bc8b298de6d664b7fb548a'
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs' = '1f577689d364ee65a31e5807a883cbe2592df563cfed4c274d9ddac5d02260c6'
            'certification/trusted-control/README.md' = 'e4690ae346c52e1db4d70b92181e9bfc374982d8972b21d904838b17241b3f59'
            'certification/trusted-control/schema/.gitattributes' = 'ebf2b8bd099a5096aecb683468622d45e74ee7948e20d3750f12442a48f97d91'
            'certification/trusted-control/schema/counter-mutation-manifest-schema.v1.json' = '5cc4d76048e6de40af1738be00aa3749a9dc0cf191bdfa3b96ea26bd71338268'
            'certification/trusted-control/schema/nonclosed-metric-manifest-schema.v1.json' = 'eadf9b927bd5ff39b5b098d465100f6bef93596c85909fafb845e68159a11f39'
            'certification/trusted-control/schema/powershell-entrypoints-schema.v1.json' = '9455ac4d53219c3ac4564625a13d2e6446719fbb0a1b1d9ae1ef44cab4d5752f'
            'certification/trusted-control/schema/resource-registry-schema.v1.json' = 'fa90128a1a330571fe6232e8105d383542155d38c616d41a8611ff6b7679ca96'
            'certification/trusted-control/schema/supported-build-entry-schema.v1.json' = '2f5faded5220ef245aa345f7bb810516224755aded3f5f9c6eccb400679d119c'
            'certification/trusted-control/schema/supported-builds-schema.v1.json' = '0a0d7941d3646ab857c7bee01662ceceb25bf7665f842ab41ed64e7e9b44552e'
            'certification/trusted-control/schema/timing-policy-schema.v1.json' = 'c0394453a1bd58149df8c60eea697887b0b97953e07e73850ca9794b9dcdafff'
            'certification/trusted-control/schema/trust-roots-schema.v1.json' = '2f18159cc6229d23f3b7ecca0edd820b1c15bd9d2fed8ad906f63a0829717be5'
            'certification/trusted-control/schema/trusted-control-artifact-set-schema.v1.json' = 'aed89770c4b08a14a2b805876fa26cf59ece83c2065d0b239632b0b8df482170'
            'certification/trusted-control/schema/trusted-control-authority.v1.json' = 'f72d4175e0a94bf9a4cb86823b7f7595df81f96af39d15aef2497d7d89f29eab'
            'certification/trusted-control/schema/trusted-control-json-schema-meta.v1.json' = '254c61af6535b22db382c5f59f54348c87b2464eaaeffe7185589f8678dc927b'
            'certification/trusted-control/schema/unicode-tables-schema.v1.json' = 'f64adeb011947a429b6bf167055014aa331b983b3ac81054cc7b3d6d169b78ce'
            'certification/trusted-control/validators/.gitattributes' = 'ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32'
            'certification/trusted-control/vectors/.gitattributes' = '3716e8799acb3803574b63201bc9625431eccbbad654b222b40f13a094ba4f5b'
            'certification/trusted-control/vectors/New-PspktPhase4TrustedControlVectors.ps1' = '8abf4eea486affa5c9e7c940e931e6f76499400a0dff6ad9d51a6ffe6e9174d0'
            'certification/trusted-control/vectors/synthetic/accept-baseline.json' = '1702455bb22780a4c70071a0d5fba7fbd3587716478ae71d7e5803d7a0e37046'
            'certification/trusted-control/vectors/synthetic/accept-entrypoint-caps-boundary.json' = '4f679aaaa817c71588d393a4c8e7cbd915ad0f73a61a46f69a889666e597d783'
            'certification/trusted-control/vectors/synthetic/accept-entrypoint-digest-framing-golden.json' = 'a01a9d9f340a8b3b9311ed1ac1bc864c99e54db8beca3b6761c4577dea6f3afa'
            'certification/trusted-control/vectors/synthetic/accept-fixedascii-padding.json' = '2d8e5c5282ac676d2ac5694ad4cd6d8fb86356cd1294356156db121dec96afaa'
            'certification/trusted-control/vectors/synthetic/accept-fixedascii-space.json' = '455bd79db46532246eba935fb7a77edbf93931b8f1f550a045746ac10cf352ed'
            'certification/trusted-control/vectors/synthetic/accept-guid-rfc4122-bytes.json' = '2bdff58885428ae42b1f5022a1481ebb725a357c75bd4cd692068d6cd10305b7'
            'certification/trusted-control/vectors/synthetic/accept-guid-version-six.json' = '121cfb7855a8ecc8520a6c173566be2ab8ac2e44fd6b457fa2fcba74fb66b602'
            'certification/trusted-control/vectors/synthetic/accept-interpreter-binding-set.json' = '167db9c7bdd6863e2a8f1b4f99aee92f826b40288b4d1c565d90d71d86caf179'
            'certification/trusted-control/vectors/synthetic/accept-luid-big-endian.json' = '390ce4ddb734ff058f222d462a88c3187ceb31f9b3c168f6171b0a0a657fe542'
            'certification/trusted-control/vectors/synthetic/accept-membership-bootstrap.json' = '5836579ac652042709bc5a1e64cbdd85a9485b16eb93e53ef84b140e57b8267a'
            'certification/trusted-control/vectors/synthetic/accept-membership-evidence-inventory.json' = '111803d4675b99592021db50111c4394b1a1f2acd42ad44206e5735c1813e4dc'
            'certification/trusted-control/vectors/synthetic/accept-membership-evidence-schema.json' = 'd3b265b314097d768922bf806bb53d100ed7d58610b4cfe071049fd3dce79aae'
            'certification/trusted-control/vectors/synthetic/accept-membership-generator.json' = 'd8fbebd0398459025a23dca401f2d7f56caad54eb0f623d97409ecf8a6764369'
            'certification/trusted-control/vectors/synthetic/accept-membership-overlay-schedule.json' = 'bb47da1bfc409e09971c743720d4cf656f24584a0b4afd4b82659e8d44995d00'
            'certification/trusted-control/vectors/synthetic/accept-membership-protocol-authority.json' = '011ed144145fb0c3a31a2f83b3b64fafc4b3eae83494c916b6caa783a152dab7'
            'certification/trusted-control/vectors/synthetic/accept-membership-protocol-meta.json' = '6391d6d03f7cbde704511a893f11632f7e2c011ed9b60ea9f903053720ba8859'
            'certification/trusted-control/vectors/synthetic/accept-membership-protocol-schema.json' = '625ecee4d9971fb14700dc6d62a3f2b059ce2967dca5c467f148a8dbe78384d9'
            'certification/trusted-control/vectors/synthetic/accept-membership-schedule.json' = '376e3c76d39e01d38853d0a4e6db3930577223fe4e0bdd8e2a41e970beb3b9f4'
            'certification/trusted-control/vectors/synthetic/accept-membership-signing-schema.json' = '7a9a588fe065793c9ce9acd6cd5884abb37f5923de36aac5162681dc6f1f82b0'
            'certification/trusted-control/vectors/synthetic/accept-membership-validator.json' = 'd4ee6e87d31ec16195abc3793886abfe41e906314b72c79effe35ad5bb8b5057'
            'certification/trusted-control/vectors/synthetic/accept-overlay-dormant.json' = 'd21f2ab79e76aa3dbb99a718f8f9020ad1f807a800dac80917a2f77e300ecf60'
            'certification/trusted-control/vectors/synthetic/accept-rsa-envelope-native-four-byte.json' = '3c683a14e4c5b800613fc59dafa7289ef189abb35450fb371a18a2ca3c9dca66'
            'certification/trusted-control/vectors/synthetic/accept-rsa-envelope.json' = '7a55e04cc7da92bbc6f6dec5a89b3086b9294d7c04d41eef3f6044e69935700b'
            'certification/trusted-control/vectors/synthetic/accept-rsa-native-411.json' = '53a46b9ff7b331cd38586e2d382e9fe05fda72fd8cd331efc76739fe0ac00a4d'
            'certification/trusted-control/vectors/synthetic/accept-rsa-native-412.json' = '58f89a52ed3d16de2bbb6477e05e81e97552c48b8a92a4644a61b3ab5b716d59'
            'certification/trusted-control/vectors/synthetic/accept-supported-build-digest-framing-golden.json' = '04de61e55eddf1f051620f0aa91128c154d38a7446080d26eddc613b3d74d9be'
            'certification/trusted-control/vectors/synthetic/accept-tcast-digest-framing-golden.json' = '553fb537f6bf047ca7f6312661228c78d86c142f722c2514a87826f1f298d73f'
            'certification/trusted-control/vectors/synthetic/accept-timing-capacity-equality.json' = '1803983d2f44f1eb907427511c137c89b57d48e2cfd08ef01c976fdcd442f9e3'
            'certification/trusted-control/vectors/synthetic/accept-timing-derived-w.json' = 'da572428acdf7a9a1c23b76587886472eab71a0bd32c5569dbd0a7b72083e62d'
            'certification/trusted-control/vectors/synthetic/accept-vt-raise-only.json' = 'c223a065147cb374af861239db0fe912ba1e1c067e24352ed76c899a76ad9629'
            'certification/trusted-control/vectors/synthetic/manifest.v1.json' = '4add5961807ef9454c7809954ab1c9241137601b05f038e1d674bfa20c853dd5'
            'certification/trusted-control/vectors/synthetic/reject-aggregate-emission-forbidden.json' = '508a54eb40b14d4f3471a0e472618891fb043fcb7ad20ebe35bd8de0a1df3131'
            'certification/trusted-control/vectors/synthetic/reject-artifact-device-path-invalid.json' = 'ed7b8c6807bb11b2ed171815173e7ca6243d8d46f5e7da4ae2bc36aee1bdc13e'
            'certification/trusted-control/vectors/synthetic/reject-artifact-path-invalid.json' = '25f621b5765bf7af9a46802d0bd775c997f056fe2c855e8bca0631484dcf6cc5'
            'certification/trusted-control/vectors/synthetic/reject-artifact-trailing-alias-invalid.json' = '8dcb60d19a79f569e225094ceb7ed2d7bb9532537e947e24247ce8860adafde5'
            'certification/trusted-control/vectors/synthetic/reject-digest-mismatched-schema-only.json' = '5e5caf2fe8fdce7e3820645e97822d5ccb6a632f0e45247577764403cdec2ec6'
            'certification/trusted-control/vectors/synthetic/reject-digest-placeholder-schema-only.json' = 'c6531f88c4b268810c9ec640efbb769c31315603afb8640d247fb91c7a577ab8'
            'certification/trusted-control/vectors/synthetic/reject-digest-placeholder.json' = '2c70c9a5f432905490fef6907edf93e4ccd28ef8c72d23be145c6d3fd62a800d'
            'certification/trusted-control/vectors/synthetic/reject-digest-tlv-framing.json' = 'd32289775182bd31e6c04d12575b2476964fcc8754e91d330f1c288b76c8354c'
            'certification/trusted-control/vectors/synthetic/reject-digest-wrong-meta-only.json' = '6fa20fc6e0dbdf06deff60a87ced6224dc3bf6e79474b684556eb957897b8bda'
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-aggregate-cap.json' = '6ce1e760841647e1c2191e4690a00b31de3945bd0f792ccfcb6f9cfef6788bfa'
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-arguments-cap.json' = '8c85fdcd757646754a2b4d47db8486b1879a57711640684306f94544c4419d20'
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-root-cap.json' = '1465eb401f05526a1bebfc3ed346372e1be06def4ff2223ce8c70cf58a538ff6'
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-sites-cap.json' = '87bff60f4e4832154ec8c3073976d62b7b38084dde254472fd04d106ab4332aa'
            'certification/trusted-control/vectors/synthetic/reject-external-process-migration-blocker.json' = '6c2664237a359bac49561ceb3536cd7780c96e573e66520ac87ff5d5e2c3b207'
            'certification/trusted-control/vectors/synthetic/reject-fixedascii-control-invalid.json' = '94248ef83ce29713eb19bcfdb34be1d1f628efb6b4ef0b0fc85955af1ddd83ca'
            'certification/trusted-control/vectors/synthetic/reject-fixedascii-delete-invalid.json' = 'f45f0371bb81e4e100bdfbae6cb632aaf3c1c06322b83c820ad21d47fadac6af'
            'certification/trusted-control/vectors/synthetic/reject-fixedascii-padding-invalid.json' = '399b74981db1e788c16ebbdbbd20e74f8f4b79f0740d9078386f432c258b454d'
            'certification/trusted-control/vectors/synthetic/reject-guid-nil.json' = '6d5b03ae1e6d95c784e385c93b945c2c3f0acc7f8c943609f2e4f6795e406617'
            'certification/trusted-control/vectors/synthetic/reject-guid-rfc4122-bytes-invalid.json' = '88932552ad1607e5be27af044fc32bd65805d8c97e8567c45f37e98838d67fe1'
            'certification/trusted-control/vectors/synthetic/reject-guid-uppercase.json' = 'dfee4c9bfd72ace8b0ff18423da9c1475af91ecc4ce8a718bfba8779e80ca1b8'
            'certification/trusted-control/vectors/synthetic/reject-guid-variant-invalid.json' = '1e7afe5fc86a1cff4dab838727e240a7375ccd1938aa96d60d05b3768c02abb1'
            'certification/trusted-control/vectors/synthetic/reject-guid-version-invalid.json' = '0ffb3459c1e40b775e03fd7895fa6fa6465ffe374eba1cd89839287d5e168195'
            'certification/trusted-control/vectors/synthetic/reject-interpreter-8dot3-path.json' = '01ea11a944c786b96860d948a039f386bb5f7ecf1a31254265c1db06044cd6e5'
            'certification/trusted-control/vectors/synthetic/reject-interpreter-ads-path.json' = '7870f46ce5fa30620067181731fe555949584de4e3540e18bfc9c50fb0589068'
            'certification/trusted-control/vectors/synthetic/reject-interpreter-binding-mismatch.json' = 'c221a93bba14f38fc016b54f0d0984b65e6cb75412f82b964b5aebdb6bb008be'
            'certification/trusted-control/vectors/synthetic/reject-interpreter-device-path.json' = '55a62e21fb0f44b4598832234a71ac1255a08c57ce1a229a05c3fd0b994ea7c8'
            'certification/trusted-control/vectors/synthetic/reject-interpreter-reserved-device.json' = '1d3c4f47cf220dff046bdd15573a99f1195a3dbf759d4f85bcf34e68c65ba6b2'
            'certification/trusted-control/vectors/synthetic/reject-interpreter-same-key-different-path.json' = '4508aaeffa7b831a317fadc76fc3582efa5ed93f5d518529610cf9e036e9eeab'
            'certification/trusted-control/vectors/synthetic/reject-luid-big-endian-invalid.json' = 'f63a88d80ff6ddbad6c3cc23bc9bd3709168376dc8238ae81208b4aada9635d7'
            'certification/trusted-control/vectors/synthetic/reject-membership-case-alias.json' = '423b8d43fc0e42139a41fbda42bf40167542ac2c94db830b300291e7f36ba0bc'
            'certification/trusted-control/vectors/synthetic/reject-membership-enrolled-pending-missing.json' = 'c1c37ab81db7c6c082674f4ea40180a7809f7da98897031992ec36ad3b8dab19'
            'certification/trusted-control/vectors/synthetic/reject-membership-enrolled-present.json' = '8ca441c96fb915a7b091f7ed8499406be42ccecae44a2e2ca058c61dc807106c'
            'certification/trusted-control/vectors/synthetic/reject-membership-enrolled-tracked.json' = '37d98ea648bf8c0338362e712464d21f05ee0be1efc1fde5ace3e243c9aad9fc'
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-case-alias.json' = '72a0dd9f0a0861c03a3189fb8eb4a9548f2e39e6d476671bbd978a22d058f34b'
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-duplicate.json' = 'f0a3a4f213d11a38a481350668551981200be0e74d37287af9e74cdc867508bb'
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-invalid-path.json' = 'dedf7f06f1ffc588208ab4e23a12e50d4a250b28204646ab72b981bb2509790d'
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-overlap.json' = '2101a2ebcb82705ac282a7a1142a8148618fefaee05f8923e1041f8aae8e1dbd'
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-unsorted.json' = 'e0dc16ec6c9cc74fba991caac61d5a949be302f52c6f0f01efea5f9545586da2'
            'certification/trusted-control/vectors/synthetic/reject-membership-malformed.json' = 'c4fe27b7a4358ac063792a35c3d29816725336b36818d0a6b0a4043eba5a1bfd'
            'certification/trusted-control/vectors/synthetic/reject-membership-outside-certification.json' = '7bf119231a00ef265df3556cedd281363a942e6749e7fc4037694859754e6196'
            'certification/trusted-control/vectors/synthetic/reject-membership-pending-duplicate.json' = '59896df15c42cf2f45310c23bcfb5dd161d2ead06f7db2d3d97ea93bc351d707'
            'certification/trusted-control/vectors/synthetic/reject-membership-pending-only-invalid.json' = '125405926091c40a3bc561c452ecc2734320f6f219e279c2eb8e951208e5f91e'
            'certification/trusted-control/vectors/synthetic/reject-membership-pending-unsorted.json' = '87727502f96f108065599575627b5bf00c5da20d590f0192065ec92bba117361'
            'certification/trusted-control/vectors/synthetic/reject-membership-tracked-only-invalid.json' = '3487c0aabc2a172bfa536bdd375d532682004d7ec87db0c36c4bebb1321a2f9e'
            'certification/trusted-control/vectors/synthetic/reject-membership-trusted-authority-pending.json' = '85cf7cc4b0e0ac6d86f8a8475c7387930cfb89166547f440636703b3ef9559fe'
            'certification/trusted-control/vectors/synthetic/reject-membership-untracked.json' = 'd7ca686b8628e3a48c5016e980b08ec38940c907f364fafdf7c345b89a1745ce'
            'certification/trusted-control/vectors/synthetic/reject-migration-empty.json' = '4943bc78a594551cd0bb3479590cfc0f088ea7cfed80406091610faa524c3c3d'
            'certification/trusted-control/vectors/synthetic/reject-migration-kind-unknown.json' = '012d8c784307f2c00aec35a46e5a0f007fd60a32e6cf309cdc448ceb79416f0e'
            'certification/trusted-control/vectors/synthetic/reject-overlay-activation-forbidden.json' = '54f81051e9e78f303acfb821b0f58adeee126b07295fbebbf9d08192eb7eb004'
            'certification/trusted-control/vectors/synthetic/reject-overlay-token-forbidden.json' = 'e8151135139dc170022be3e6e1a8cfa38f7160c5208ec48eae6fb96fbd1e230e'
            'certification/trusted-control/vectors/synthetic/reject-powershell-migration-blocker.json' = '0f4f712db859111f3c64d3bdaa05a2f7687af99524637126d603c1bb426034b3'
            'certification/trusted-control/vectors/synthetic/reject-registry-instance-forbidden.json' = 'a78715b17e0998c3baffb5d6922ba2214af8f110042603ee4a2742af82852c9e'
            'certification/trusted-control/vectors/synthetic/reject-rsa-bits-invalid.json' = 'd8cf23ebe384553547593a9dfba5f29627ecde7e6f22f675f4b19a0cdf830d90'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-canonical-exponent.json' = 'bfed9d2952340a34893448d923e337c2dce576dfcaa13a999fa41bc59a6af9f4'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-modulus.json' = '5dc8f2a9266fa3cca1b72dbb4120bdc8b05738930ab13e419381785533352a91'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-prime1.json' = 'fe1660ff276a13e2d5622d98b8e214481944834b65f09a93b0fb40683fe74fa4'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-prime2.json' = 'ec4e4c639bb61c0b2c77814512df63d97fc0500dde4dc8c5b2942517323d212b'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-public-exp.json' = '404b29c45cd2c39635718645b25fa34b2ef7b04da14401c8379e3707904e3e7e'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-length-or-conversion-invalid.json' = '0d420c7204c7933fe7931a503eb529fc93dce4f86344ce40e5890a2e68f3f952'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-native-length-mismatch.json' = 'e1002f789a2c9ed95019571f8a0290ac9af9e6a9bdee1c7ec777c7a6b0c2d48a'
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-native-length-rule.json' = '9ffe190bc3e2226765616f18801013a85ee94e0e1e7937c33490e0d9ca3a44bf'
            'certification/trusted-control/vectors/synthetic/reject-rsa-keyid-invalid.json' = '0c3a528b442e21194574e47361aab7c908a399725cc9b8c775e39e1ccc854abf'
            'certification/trusted-control/vectors/synthetic/reject-rsa-magic-invalid.json' = '3eda49202cb28d84650c33014a33c3227959d6226add849e0b28a33158838348'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-2048.json' = '245bffd22f439e54bffccedc1348abebc05a20ff7d2829a1e5576e72c02ccf83'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-canonical-hex.json' = 'cca7e615c01998be0e2064ae3ad7433c43bb399f551f78c618ab44a0522a4780'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-cb-modulus.json' = '3d0a7d6a5014e9ec6f8fd0b60a48e654773b58f908e05c05a07acaf09701ef37'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-cb-prime2.json' = '5d0a84d849e17e8777e5720e9e9fc5cf0354aa59ba232d7d01e921da233836ac'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-exponent-value.json' = '73d0ae98e1a0440d7f340f1312dc0f03299ab11fc5f956bc16f02dd548a39e4e'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-key-id.json' = '8d5bb00c0afec9acec328b7a2f4e4cf9539754f9b101e95ac3f8a3d8d1531938'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-prime.json' = '8133ad49b43219bddfd77664e92a5854376c1cbd57c6eddbd17837d3f0dc43e7'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-rsa2.json' = '7869a7b1ad91bdf6642a599b92f253784db746c2ef256af009d05bb2165d42d3'
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-top-bit.json' = '700def6901bb1c5f37cadfcc08c8d2d209b1d86f83241372c6ad0cc74f2ea551'
            'certification/trusted-control/vectors/synthetic/reject-rsa-tail-invalid.json' = '8bce91d203e46bed2604803dea938afae1fd5759220e73895f1675518a320346'
            'certification/trusted-control/vectors/synthetic/reject-rsa-topbit-invalid.json' = '6759e49e9625abb403c01c8ad037d768dfeb32a7413d9631066de11566f5a1e8'
            'certification/trusted-control/vectors/synthetic/reject-schema-emission-undeclared.json' = '455130109005f049dd091d531d0bc17750ef7dc2971e05cbf071197ca6527880'
            'certification/trusted-control/vectors/synthetic/reject-schema-meta-mismatch.json' = '4d227a7bbbbb2b70efee38bc6612098584ecc7f6fcbb1bd7b01764ae29e6243f'
            'certification/trusted-control/vectors/synthetic/reject-timing-deadline-equality-expired.json' = '48089d878141ca8b3152040987081a1b06811195438ecf2237d94c00124f035b'
            'certification/trusted-control/vectors/synthetic/reject-timing-deadline-late.json' = '4e4bf8b2e88a4663d48832678ae57c8125817c9cb614164527d0ea7da017e6fc'
            'certification/trusted-control/vectors/synthetic/reject-timing-deadline-le-invalid.json' = '5cac95e5dae3520262f5ad6c1be4209bdd4c717772e26e64faa06ed46b093fa6'
            'certification/trusted-control/vectors/synthetic/reject-timing-derived-w-count.json' = 'b8f48452973f6194075feb4b7052be6e1942b647172cb25f6a91927cc43dd738'
            'certification/trusted-control/vectors/synthetic/reject-timing-derived-w-invalid.json' = 'd75a2b634433fcc30fcec2a83d2755f8367ca104959f31d1ceefc3ada760b6bb'
            'certification/trusted-control/vectors/synthetic/reject-timing-derived-w-order.json' = 'a8147db94a366eadb252f51896acf0f7c80c8a5dd3aeef7a9868daf3975f88bb'
            'certification/trusted-control/vectors/synthetic/reject-timing-kind-unknown.json' = '202deec4941114dbfd8d61a0727ae5d92d2c6cca5b00e8deb44b3e25461521f9'
            'certification/trusted-control/vectors/synthetic/reject-timing-relation-unknown.json' = 'd398b96db29675e603077a66fa22bba3c784136860fcab74f80b63b33714ab4a'
            'certification/trusted-control/vectors/synthetic/reject-trusted-artifact-path-collision.json' = 'ba13860242e008a1edd29929214b256c42900ed7a4a523a0971232f07d93b637'
            'certification/trusted-control/vectors/synthetic/reject-vt-policy-invalid.json' = 'debc1fcd66665f7d6909102d6cf77ac6e6929108db79dbb2c04efe041a67a398'
            'tests/phase4-trusted-control/.gitattributes' = 'ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32'
            'tests/phase4-trusted-control/pspkt.Phase4TrustedControlAuthority.Tests.ps1' = '3026824bfb42e040bf8f7c0075c727dd21dd1684c2438f04193b895a79827275'
        }
        LfTextPathSet = [string[]]@(
            'certification/lib/Pspkt.Certification.SchemaBootstrap.cs',
            'certification/schema/protocol-inventory.v1.json',
            'certification/trusted-control/.gitattributes',
            'certification/trusted-control/lib/.gitattributes',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlAuthority.cs',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlNativeSecurity.cs',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs',
            'certification/trusted-control/README.md',
            'certification/trusted-control/schema/.gitattributes',
            'certification/trusted-control/validators/.gitattributes',
            'certification/trusted-control/vectors/.gitattributes',
            'certification/trusted-control/vectors/New-PspktPhase4TrustedControlVectors.ps1',
            'tests/phase4-trusted-control/.gitattributes',
            'tests/phase4-trusted-control/pspkt.Phase4TrustedControlAuthority.Tests.ps1'
        )
        AllowedPathSet = [string[]]@(
            'certification/trusted-control/.gitattributes',
            'certification/trusted-control/lib/.gitattributes',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlAuthority.cs',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlContract.ps1',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlJsonSchemaBootstrap.cs',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlNativeSecurity.cs',
            'certification/trusted-control/lib/Pspkt.Certification.TrustedControlVerify.cs',
            'certification/trusted-control/README.md',
            'certification/trusted-control/schema/.gitattributes',
            'certification/trusted-control/schema/counter-mutation-manifest-schema.v1.json',
            'certification/trusted-control/schema/nonclosed-metric-manifest-schema.v1.json',
            'certification/trusted-control/schema/powershell-entrypoints-schema.v1.json',
            'certification/trusted-control/schema/resource-registry-schema.v1.json',
            'certification/trusted-control/schema/supported-build-entry-schema.v1.json',
            'certification/trusted-control/schema/supported-builds-schema.v1.json',
            'certification/trusted-control/schema/timing-policy-schema.v1.json',
            'certification/trusted-control/schema/trust-roots-schema.v1.json',
            'certification/trusted-control/schema/trusted-control-artifact-set-schema.v1.json',
            'certification/trusted-control/schema/trusted-control-authority.v1.json',
            'certification/trusted-control/schema/trusted-control-json-schema-meta.v1.json',
            'certification/trusted-control/schema/unicode-tables-schema.v1.json',
            'certification/trusted-control/validators/.gitattributes',
            'certification/trusted-control/validators/Invoke-PspktPhase4TrustedControlAuthorityValidators.ps1',
            'certification/trusted-control/vectors/.gitattributes',
            'certification/trusted-control/vectors/New-PspktPhase4TrustedControlVectors.ps1',
            'certification/trusted-control/vectors/synthetic/accept-baseline.json',
            'certification/trusted-control/vectors/synthetic/accept-entrypoint-caps-boundary.json',
            'certification/trusted-control/vectors/synthetic/accept-entrypoint-digest-framing-golden.json',
            'certification/trusted-control/vectors/synthetic/accept-fixedascii-padding.json',
            'certification/trusted-control/vectors/synthetic/accept-fixedascii-space.json',
            'certification/trusted-control/vectors/synthetic/accept-guid-rfc4122-bytes.json',
            'certification/trusted-control/vectors/synthetic/accept-guid-version-six.json',
            'certification/trusted-control/vectors/synthetic/accept-interpreter-binding-set.json',
            'certification/trusted-control/vectors/synthetic/accept-luid-big-endian.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-bootstrap.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-evidence-inventory.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-evidence-schema.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-generator.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-overlay-schedule.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-protocol-authority.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-protocol-meta.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-protocol-schema.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-schedule.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-signing-schema.json',
            'certification/trusted-control/vectors/synthetic/accept-membership-validator.json',
            'certification/trusted-control/vectors/synthetic/accept-overlay-dormant.json',
            'certification/trusted-control/vectors/synthetic/accept-rsa-envelope-native-four-byte.json',
            'certification/trusted-control/vectors/synthetic/accept-rsa-envelope.json',
            'certification/trusted-control/vectors/synthetic/accept-rsa-native-411.json',
            'certification/trusted-control/vectors/synthetic/accept-rsa-native-412.json',
            'certification/trusted-control/vectors/synthetic/accept-supported-build-digest-framing-golden.json',
            'certification/trusted-control/vectors/synthetic/accept-tcast-digest-framing-golden.json',
            'certification/trusted-control/vectors/synthetic/accept-timing-capacity-equality.json',
            'certification/trusted-control/vectors/synthetic/accept-timing-derived-w.json',
            'certification/trusted-control/vectors/synthetic/accept-vt-raise-only.json',
            'certification/trusted-control/vectors/synthetic/manifest.v1.json',
            'certification/trusted-control/vectors/synthetic/reject-aggregate-emission-forbidden.json',
            'certification/trusted-control/vectors/synthetic/reject-artifact-device-path-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-artifact-path-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-artifact-trailing-alias-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-digest-mismatched-schema-only.json',
            'certification/trusted-control/vectors/synthetic/reject-digest-placeholder-schema-only.json',
            'certification/trusted-control/vectors/synthetic/reject-digest-placeholder.json',
            'certification/trusted-control/vectors/synthetic/reject-digest-tlv-framing.json',
            'certification/trusted-control/vectors/synthetic/reject-digest-wrong-meta-only.json',
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-aggregate-cap.json',
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-arguments-cap.json',
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-root-cap.json',
            'certification/trusted-control/vectors/synthetic/reject-entrypoint-sites-cap.json',
            'certification/trusted-control/vectors/synthetic/reject-external-process-migration-blocker.json',
            'certification/trusted-control/vectors/synthetic/reject-fixedascii-control-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-fixedascii-delete-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-fixedascii-padding-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-guid-nil.json',
            'certification/trusted-control/vectors/synthetic/reject-guid-rfc4122-bytes-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-guid-uppercase.json',
            'certification/trusted-control/vectors/synthetic/reject-guid-variant-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-guid-version-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-interpreter-8dot3-path.json',
            'certification/trusted-control/vectors/synthetic/reject-interpreter-ads-path.json',
            'certification/trusted-control/vectors/synthetic/reject-interpreter-binding-mismatch.json',
            'certification/trusted-control/vectors/synthetic/reject-interpreter-device-path.json',
            'certification/trusted-control/vectors/synthetic/reject-interpreter-reserved-device.json',
            'certification/trusted-control/vectors/synthetic/reject-interpreter-same-key-different-path.json',
            'certification/trusted-control/vectors/synthetic/reject-luid-big-endian-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-case-alias.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-enrolled-pending-missing.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-enrolled-present.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-enrolled-tracked.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-case-alias.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-duplicate.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-invalid-path.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-overlap.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-fixture-unsorted.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-malformed.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-outside-certification.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-pending-duplicate.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-pending-only-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-pending-unsorted.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-tracked-only-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-trusted-authority-pending.json',
            'certification/trusted-control/vectors/synthetic/reject-membership-untracked.json',
            'certification/trusted-control/vectors/synthetic/reject-migration-empty.json',
            'certification/trusted-control/vectors/synthetic/reject-migration-kind-unknown.json',
            'certification/trusted-control/vectors/synthetic/reject-overlay-activation-forbidden.json',
            'certification/trusted-control/vectors/synthetic/reject-overlay-token-forbidden.json',
            'certification/trusted-control/vectors/synthetic/reject-powershell-migration-blocker.json',
            'certification/trusted-control/vectors/synthetic/reject-registry-instance-forbidden.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-bits-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-canonical-exponent.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-modulus.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-prime1.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-prime2.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-cb-public-exp.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-length-or-conversion-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-native-length-mismatch.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-envelope-native-length-rule.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-keyid-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-magic-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-2048.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-canonical-hex.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-cb-modulus.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-cb-prime2.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-exponent-value.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-key-id.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-prime.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-rsa2.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-native-top-bit.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-tail-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-rsa-topbit-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-schema-emission-undeclared.json',
            'certification/trusted-control/vectors/synthetic/reject-schema-meta-mismatch.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-deadline-equality-expired.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-deadline-late.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-deadline-le-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-derived-w-count.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-derived-w-invalid.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-derived-w-order.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-kind-unknown.json',
            'certification/trusted-control/vectors/synthetic/reject-timing-relation-unknown.json',
            'certification/trusted-control/vectors/synthetic/reject-trusted-artifact-path-collision.json',
            'certification/trusted-control/vectors/synthetic/reject-vt-policy-invalid.json',
            'tests/phase4-trusted-control/.gitattributes',
            'tests/phase4-trusted-control/pspkt.Phase4TrustedControlAuthority.Tests.ps1'
        )
        MaintainedInputPathSet = [string[]]@(
            'certification/trusted-control/schema/trusted-control-authority.v1.json',
            'certification/trusted-control/schema/trusted-control-json-schema-meta.v1.json',
            'certification/schema/protocol-schema-meta.v1.json',
            'certification/schema/protocol-schema.v1.json',
            'certification/schema/mandatory-tail-schedule.v1.json'
            'certification/schema/protocol-inventory.v1.json'
        )
        OutputPathSet = [string[]]@(
            'certification/trusted-control/schema/counter-mutation-manifest-schema.v1.json',
            'certification/trusted-control/schema/nonclosed-metric-manifest-schema.v1.json',
            'certification/trusted-control/schema/powershell-entrypoints-schema.v1.json',
            'certification/trusted-control/schema/resource-registry-schema.v1.json',
            'certification/trusted-control/schema/supported-build-entry-schema.v1.json',
            'certification/trusted-control/schema/supported-builds-schema.v1.json',
            'certification/trusted-control/schema/timing-policy-schema.v1.json',
            'certification/trusted-control/schema/trust-roots-schema.v1.json',
            'certification/trusted-control/schema/trusted-control-artifact-set-schema.v1.json',
            'certification/trusted-control/schema/unicode-tables-schema.v1.json'
        )
        TlvSchemaNameSet = [string[]]@(
            'powershell-entrypoints-schema.v1.json',
            'supported-build-entry-schema.v1.json',
            'trusted-control-artifact-set-schema.v1.json'
        )
    }
}
