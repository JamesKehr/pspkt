using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Xml;
using System.Xml.Linq;
using Pspkt.Certification.EvidenceRuntime;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class EvidenceAuthoritySnapshot
    {
        private static readonly int[] RequiredLengths = new int[] {
            4533, 46479, 22001, 47347, 66838, 55414, 984, 1362, 5504
        };

        private static readonly string[] RequiredDigests = new string[] {
            "ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85",
            "d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f",
            "49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6",
            "07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9",
            "6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4",
            "f72d4175e0a94bf9a4cb86823b7f7595df81f96af39d15aef2497d7d89f29eab",
            "2f18159cc6229d23f3b7ecca0edd820b1c15bd9d2fed8ad906f63a0829717be5",
            "039bbf800b8e6ceb934838e5ba7d5913fe3fecee4c7a81c46dedf5465212f659",
            "06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17"
        };

        private readonly byte[][] _retainedBytes;
        private readonly byte[][] _digests;
        private readonly EvidenceArtifactEnvelopeCodec _codec;

        private EvidenceAuthoritySnapshot(byte[][] retainedBytes, byte[][] digests, EvidenceArtifactEnvelopeCodec codec)
        {
            _retainedBytes = retainedBytes;
            _digests = digests;
            _codec = codec;
        }

        internal EvidenceArtifactEnvelopeCodec Codec { get { return _codec; } }
        internal byte[] PolicySha256 { get { return (byte[])_digests[8].Clone(); } }
        internal byte[] ProtocolSchemaSha256 { get { return (byte[])_digests[4].Clone(); } }
        internal byte[] EvidenceSchemaSha256 { get { return (byte[])_digests[2].Clone(); } }

        internal static EvidenceAuthoritySnapshot Create(byte[][] inputs)
        {
            foreach(byte[] input in inputs)
            {
                if(input == null) { throw new ArgumentException("argument:null"); }
            }
            foreach(byte[] input in inputs)
            {
                if(input.Length == 0) { throw new ArgumentException("argument:empty"); }
            }
            for(int index = 0; index < inputs.Length; index++)
            {
                if(inputs[index].Length != RequiredLengths[index]) { throw EvidenceFailure.Reject("authority:length"); }
            }
            byte[][] retained = new byte[inputs.Length][];
            byte[][] digests = new byte[inputs.Length][];
            for(int index = 0; index < inputs.Length; index++)
            {
                retained[index] = (byte[])inputs[index].Clone();
                digests[index] = EvidenceFailure.Hash(retained[index]);
                if(!string.Equals(EvidenceFailure.Hex(digests[index]),
                    RequiredDigests[index], StringComparison.Ordinal))
                {
                    throw EvidenceFailure.Reject("authority:pin");
                }
            }
            EvidenceArtifactEnvelopeCodec codec;
            try
            {
                codec = EvidenceArtifactEnvelopeCodec.CreateFromCommittedAuthorities(
                    retained[0], retained[1], retained[2], retained[3]);
            }
            catch(InvalidDataException) { throw EvidenceFailure.Reject("authority:codec-gate"); }
            if(!Pspkt.Certification.SchemaBootstrap.Evaluate("schema-against-meta", retained[4], retained[0]).Accepted)
            {
                throw EvidenceFailure.Reject("authority:protocol-gate");
            }
            if(!Pspkt.Certification.SchemaBootstrap.Evaluate("json", retained[5], null).Accepted ||
                !Pspkt.Certification.SchemaBootstrap.Evaluate("json", retained[6], null).Accepted)
            {
                throw EvidenceFailure.Reject("authority:json-gate");
            }
            EvidenceJsonValue policy;
            EvidenceJsonValue schema;
            try
            {
                schema = EvidenceCanonicalJsonReader.Read(retained[7], 9);
                policy = EvidenceCanonicalJsonReader.Read(retained[8], 8);
                if(schema.Get("schemaId").Text != "PspktEvidenceKeyBindingSnapshotSchemaV1" ||
                    policy.Get("schemaId").Text != "PspktEvidenceSignatureReferencePolicyV1")
                {
                    throw EvidenceFailure.Reject("authority:local-shape");
                }
                RequireLocalDocuments(schema, policy);
            }
            catch(InvalidDataException failure)
            {
                if(failure.Message == "authority:policy-contract") { throw; }
                throw EvidenceFailure.Reject("authority:local-shape");
            }
            EvidenceClaimSet.RequirePolicyAgreement(policy);
            RequireCarriedForwardFacts(ReadDocumentaryAuthority(retained[5]), ReadDocumentaryAuthority(retained[6]));
            return new EvidenceAuthoritySnapshot(retained, digests, codec);
        }

        private static void RequireLocalDocuments(EvidenceJsonValue schema, EvidenceJsonValue policy)
        {
            EvidenceCanonicalJsonReader.RequireObject(schema,
                new string[] { "schemaId", "schemaVersion", "kind", "status", "root", "rules" }, "snssoa");
            if(schema.Get("schemaVersion").Number != 1 || schema.Get("kind").Text != "CapsuleLocalSnapshot" ||
                schema.Get("status").Text != "CallerPinnedNotEnrolled") { throw EvidenceFailure.Reject("authority:policy-contract"); }
            RequireStrings(schema.Get("rules"), new string[] { "key-id-from-public-envelope", "strict-key-interval",
                "all-row-host-policy-equality", "zero-skew", "selection-during-check-only" });
            EvidenceJsonValue root = schema.Get("root");
            EvidenceCanonicalJsonReader.RequireObject(root, new string[] { "additionalProperties", "propertyOrder", "properties" }, "baa");
            if(root.Get("additionalProperties").Text != "false") { throw EvidenceFailure.Reject("authority:policy-contract"); }
            RequireStrings(root.Get("propertyOrder"), new string[] { "schemaId", "schemaVersion", "ledgerIdentity", "keys", "maximumSkewHundredNanoseconds" });
            EvidenceJsonValue properties = root.Get("properties");
            if(properties.Values.Count != 5) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            RequireDescriptor(properties.Values[0], new string[] { "name", "type", "value" }, "sss", "schemaId", "LiteralString");
            RequireDescriptor(properties.Values[1], new string[] { "name", "type", "const" }, "ssn", "schemaVersion", "UInt16");
            RequireDescriptor(properties.Values[2], new string[] { "name", "type", "nonNil", "variant", "minVersion", "maxVersion" }, "ssbnnn", "ledgerIdentity", "GuidText");
            RequireDescriptor(properties.Values[3], new string[] { "name", "type", "minItems", "maxItems", "uniqueBy", "items" }, "ssnnso", "keys", "Array");
            RequireDescriptor(properties.Values[4], new string[] { "name", "type", "const" }, "ssn", "maximumSkewHundredNanoseconds", "UInt64");
            if(properties.Values[0].Get("value").Text != "PspktEvidenceKeyBindingSnapshotV1" || properties.Values[1].Get("const").Number != 1 ||
                properties.Values[2].Get("nonNil").Text != "true" || properties.Values[2].Get("variant").Number != 2 ||
                properties.Values[2].Get("minVersion").Number != 1 || properties.Values[2].Get("maxVersion").Number != 8 ||
                properties.Values[3].Get("minItems").Number != 0 || properties.Values[3].Get("maxItems").Number != 128 ||
                properties.Values[3].Get("uniqueBy").Text != "keyId" || properties.Values[4].Get("const").Number != 0)
            {
                throw EvidenceFailure.Reject("authority:policy-contract");
            }
            EvidenceJsonValue items = properties.Values[3].Get("items");
            EvidenceCanonicalJsonReader.RequireObject(items, new string[] { "additionalProperties", "propertyOrder", "properties" }, "baa");
            if(items.Get("additionalProperties").Text != "false") { throw EvidenceFailure.Reject("authority:policy-contract"); }
            string[] rowNames = new string[] { "keyId", "publicBlob", "algorithm", "role", "notBefore", "notAfter", "hostInventoryPolicyDigest" };
            RequireStrings(items.Get("propertyOrder"), rowNames);
            EvidenceJsonValue rows = items.Get("properties");
            if(rows.Values.Count != 7) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            string[] rowTypes = new string[] { "Sha256Hex", "Rsa3072BlobHex", "Enum", "Enum", "UInt64", "UInt64", "Sha256Hex" };
            for(int index = 0; index < rowNames.Length; index++)
            {
                string[] names = index == 2 || index == 3 ? new string[] { "name", "type", "members" } :
                    index == 4 || index == 5 ? new string[] { "name", "type" } : new string[] { "name", "type", "bytes" };
                string kinds = index == 2 || index == 3 ? "ssa" : index == 4 || index == 5 ? "ss" : "ssn";
                RequireDescriptor(rows.Values[index], names, kinds, rowNames[index], rowTypes[index]);
            }
            if(rows.Values[0].Get("bytes").Number != 32 || rows.Values[1].Get("bytes").Number != 512 ||
                rows.Values[6].Get("bytes").Number != 32) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            RequireStrings(rows.Values[2].Get("members"), new string[] { "RSA3072PKCS1SHA256" });
            RequireStrings(rows.Values[3].Get("members"), new string[] { "HostEvidence", "RecoveryAuthority" });
            EvidenceCanonicalJsonReader.RequireObject(policy, new string[] { "schemaId", "schemaVersion", "snapshotSchemaId",
                "signatureAlgorithm", "limits", "evaluationTimeType", "intervalRule", "maximumSkewHundredNanoseconds", "rowPolicyRule",
                "duplicateRule", "signedKinds", "schemaBindings", "references", "cardinality", "uncheckedTokens", "kindTransitions", "verifiedClaims" },
                "snssossnssaaaoaao");
            if(policy.Get("schemaVersion").Number != 1 || policy.Get("snapshotSchemaId").Text != "PspktEvidenceKeyBindingSnapshotSchemaV1" ||
                policy.Get("signatureAlgorithm").Text != "RSA3072PKCS1SHA256" || policy.Get("evaluationTimeType").Text != "UInt64" ||
                policy.Get("intervalRule").Text != "notBefore<=evaluationTime<notAfter" || policy.Get("maximumSkewHundredNanoseconds").Number != 0 ||
                policy.Get("rowPolicyRule").Text != "all-rows-equal-expected-host-inventory-policy-digest" ||
                policy.Get("duplicateRule").Text != "reject-equal-kind-and-envelope-payload-digest")
            {
                throw EvidenceFailure.Reject("authority:policy-contract");
            }
            EvidenceJsonValue limits = policy.Get("limits");
            string[] limitNames = new string[] { "maximumEnvelopeCount", "maximumEnvelopeBytes", "maximumAggregateEnvelopeBytes", "maximumSnapshotBytes", "maximumKeyRows" };
            ulong[] limitValues = new ulong[] { 256, 262228, 16777216, 1048576, 128 };
            EvidenceCanonicalJsonReader.RequireObject(limits, limitNames, "nnnnn");
            for(int index = 0; index < limitNames.Length; index++)
            {
                if(limits.Get(limitNames[index]).Number != limitValues[index]) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            }
            EvidenceJsonValue signed = policy.Get("signedKinds");
            if(signed.Values.Count != 3) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            ushort[] signedKinds = new ushort[] { 16, 17, 20 };
            for(int index = 0; index < 3; index++)
            {
                EvidenceJsonValue row = signed.Values[index];
                EvidenceCanonicalJsonReader.RequireObject(row, new string[] { "kind", "keyFieldId", "signatureFieldId", "role" }, "nnns");
                if(row.Get("kind").Number != signedKinds[index] || row.Get("keyFieldId").Number != 9 ||
                    row.Get("signatureFieldId").Number != 10 || row.Get("role").Text != (index == 2 ? "RecoveryAuthority" : "HostEvidence"))
                {
                    throw EvidenceFailure.Reject("authority:policy-contract");
                }
            }
            EvidenceJsonValue bindings = policy.Get("schemaBindings");
            if(bindings.Values.Count != 4) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            for(int index = 0; index < 4; index++)
            {
                EvidenceJsonValue row = bindings.Values[index];
                EvidenceCanonicalJsonReader.RequireObject(row, new string[] { "kind", "fieldId", "authorityId", "preimageRule", "length", "sha256" }, "nnssns");
                int authorityIndex = index % 2 == 0 ? 4 : 2;
                if(row.Get("kind").Number != (ulong)(16 + index / 2) || row.Get("fieldId").Number != (ulong)(5 + index % 2) ||
                    row.Get("authorityId").Text != (index % 2 == 0 ? "protocol" : "evidence") || row.Get("preimageRule").Text != "raw-retained-bytes" ||
                    row.Get("length").Number != (ulong)RequiredLengths[authorityIndex] || row.Get("sha256").Text != RequiredDigests[authorityIndex])
                {
                    throw EvidenceFailure.Reject("authority:policy-contract");
                }
            }
            EvidenceJsonValue references = policy.Get("references");
            if(references.Values.Count != 2) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            for(int index = 0; index < 2; index++)
            {
                EvidenceJsonValue row = references.Values[index];
                EvidenceCanonicalJsonReader.RequireObject(row, new string[] { "sourceKind", "sourceFieldId", "targetKind", "sourceCovered", "joins" }, "nnnba");
                if(row.Get("sourceKind").Number != (ulong)(20 + index) || row.Get("sourceFieldId").Number != 1 ||
                    row.Get("targetKind").Number != (ulong)(index == 0 ? 18 : 20) || row.Get("sourceCovered").Text != (index == 0 ? "true" : "false") ||
                    row.Get("joins").Values.Count != (index == 0 ? 2 : 1)) { throw EvidenceFailure.Reject("authority:policy-contract"); }
                for(int join = 0; join < row.Get("joins").Values.Count; join++)
                {
                    EvidenceJsonValue equality = row.Get("joins").Values[join];
                    EvidenceCanonicalJsonReader.RequireObject(equality, new string[] { "sourceFieldId", "targetFieldId", "assertion" }, "nns");
                    string assertion = index == 1 ? "successor-logical-operation-id-equal" :
                        join == 0 ? "burned-logical-operation-id-equal" : "burned-semantic-digest-equal";
                    if(equality.Get("sourceFieldId").Number != (ulong)(2 + join) ||
                        equality.Get("targetFieldId").Number != (ulong)(index == 1 ? 4 : 1 + join) ||
                        equality.Get("assertion").Text != assertion) { throw EvidenceFailure.Reject("authority:policy-contract"); }
                }
            }
            EvidenceJsonValue cardinality = policy.Get("cardinality");
            EvidenceCanonicalJsonReader.RequireObject(cardinality, new string[] { "allowMultipleReferrers", "allowOrphanTargets", "requireReverseEdges" }, "bbb");
            if(cardinality.Get("allowMultipleReferrers").Text != "true" || cardinality.Get("allowOrphanTargets").Text != "true" ||
                cardinality.Get("requireReverseEdges").Text != "false") { throw EvidenceFailure.Reject("authority:policy-contract"); }
        }

        private static void RequireDescriptor(EvidenceJsonValue value, string[] names, string kinds, string name, string type)
        {
            EvidenceCanonicalJsonReader.RequireObject(value, names, kinds);
            if(value.Get("name").Text != name || value.Get("type").Text != type) { throw EvidenceFailure.Reject("authority:policy-contract"); }
        }

        private static void RequireStrings(EvidenceJsonValue value, string[] expected)
        {
            if(value.Kind != 'a' || value.Values.Count != expected.Length) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            for(int index = 0; index < expected.Length; index++)
            {
                if(value.Values[index].Kind != 's' || value.Values[index].Text != expected[index]) { throw EvidenceFailure.Reject("authority:policy-contract"); }
            }
        }

        private static XElement ReadDocumentaryAuthority(byte[] bytes)
        {
            XmlDictionaryReaderQuotas quotas = new XmlDictionaryReaderQuotas();
            quotas.MaxDepth = 64;
            quotas.MaxArrayLength = 1048576;
            quotas.MaxStringContentLength = 1048576;
            quotas.MaxBytesPerRead = 1048576;
            quotas.MaxNameTableCharCount = 1048576;
            XmlDictionaryReader reader = null;
            XElement result = null;
            Exception failure = null;
            try
            {
                reader = JsonReaderWriterFactory.CreateJsonReader(bytes, quotas);
                result = XElement.Load(reader, LoadOptions.None);
            }
            catch(Exception exception) { failure = EvidenceFailure.Normalize(exception); }
            finally { if(reader != null) { failure = EvidenceFailure.DisposeOwned(reader, failure); } }
            if(failure != null) { throw failure; }
            return result;
        }

        private static void RequireCarriedForwardFacts(XElement authority, XElement roots)
        {
            XElement encoding = authority.Element("encodingTables");
            XElement envelope = encoding.Element("rsaEnvelope");
            RequireXml(envelope, "byteLength", "512");
            RequireXml(envelope, "zeroTailBytes", "100");
            XElement header = envelope.Element("header");
            string[] names = new string[] { "magic", "bitLength", "cbPublicExp", "cbModulus", "cbPrime1", "cbPrime2", "encoding" };
            string[] values = new string[] { "826364754", "3072", "4", "384", "0", "0", "SixUInt32LittleEndian" };
            for(int index = 0; index < names.Length; index++) { RequireXml(header, names[index], values[index]); }
            RequireXml(envelope.Element("exponent"), "canonicalBytes", "00010001");
            RequireXml(envelope.Element("exponent"), "value", "65537");
            RequireXml(envelope.Element("modulus"), "byteLength", "384");
            RequireXml(envelope.Element("modulus"), "encoding", "BigEndian");
            RequireXml(envelope.Element("modulus"), "topBitSet", "true");
            RequireXml(encoding.Element("keyId"), "formula", "lowercase SHA256 of all 512 RSA envelope bytes");
            XElement epoch = authority.Element("rules").Elements("item").Single(rule => rule.Element("ruleId").Value == "TRUST-EPOCH-001");
            RequireXml(epoch, "definition", "Trust epoch satisfies notBefore less than notAfter");
            XElement keys = roots.Element("root").Element("properties").Elements("item").Single(property => property.Element("name").Value == "keys");
            XElement publicBlob = keys.Element("items").Element("properties").Elements("item").Single(property => property.Element("name").Value == "publicBlob");
            RequireXml(publicBlob, "type", "Rsa3072BlobHex");
            RequireXml(publicBlob, "bytes", "512");
            XElement algorithm = keys.Element("items").Element("properties").Elements("item").Single(property => property.Element("name").Value == "algorithm");
            XElement role = keys.Element("items").Element("properties").Elements("item").Single(property => property.Element("name").Value == "role");
            if(!algorithm.Element("members").Elements("item").Select(item => item.Value).SequenceEqual(new string[] { "RSA3072PKCS1SHA256" }, StringComparer.Ordinal) ||
                !role.Element("members").Elements("item").Select(item => item.Value).SequenceEqual(new string[] { "HostEvidence", "RecoveryAuthority" }, StringComparer.Ordinal))
            {
                throw EvidenceFailure.Reject("authority:policy-contract");
            }
        }

        private static void RequireXml(XElement element, string name, string value)
        {
            if(element == null || element.Element(name) == null || element.Element(name).Value != value)
            {
                throw EvidenceFailure.Reject("authority:policy-contract");
            }
        }
    }
}
