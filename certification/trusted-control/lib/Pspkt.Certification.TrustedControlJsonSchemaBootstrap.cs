using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Pspkt.Certification.TrustedControl
{
    public sealed class TrustedJsonResult
    {
        internal TrustedJsonResult(bool accepted, string reason)
        {
            Accepted = accepted;
            Reason = reason;
        }

        public bool Accepted { get; private set; }

        public string Reason { get; private set; }
    }

    public abstract class TrustedJsonNode
    {
        internal string JsonPath;

        public string Path { get { return JsonPath; } }

        internal abstract void WriteCanonical(StringBuilder builder);

        public byte[] ToCanonicalBytes()
        {
            StringBuilder builder = new StringBuilder();
            WriteCanonical(builder);
            return new UTF8Encoding(false, true).GetBytes(builder.ToString());
        }
    }

    public sealed class TrustedJsonObject : TrustedJsonNode
    {
        private readonly List<string> _keys = new List<string>();
        private readonly Dictionary<string, TrustedJsonNode> _members =
            new Dictionary<string, TrustedJsonNode>(StringComparer.Ordinal);

        public IList<string> Keys { get { return _keys.AsReadOnly(); } }

        public TrustedJsonNode this[string name] { get { return _members[name]; } }

        public bool Contains(string name)
        {
            return _members.ContainsKey(name);
        }

        public TrustedJsonArray GetArray(string name)
        {
            return Require<TrustedJsonArray>(name);
        }

        public bool GetBoolean(string name)
        {
            return Require<TrustedJsonBoolean>(name).Value;
        }

        public ulong GetInteger(string name)
        {
            return Require<TrustedJsonInteger>(name).Value;
        }

        public TrustedJsonObject GetObject(string name)
        {
            return Require<TrustedJsonObject>(name);
        }

        public string GetString(string name)
        {
            return Require<TrustedJsonString>(name).Value;
        }

        internal void Add(string name, TrustedJsonNode value)
        {
            _keys.Add(name);
            _members.Add(name, value);
        }

        internal override void WriteCanonical(StringBuilder builder)
        {
            builder.Append('{');
            for (int index = 0; index < _keys.Count; index++)
            {
                if (index != 0)
                {
                    builder.Append(',');
                }
                TrustedJsonString.WriteEscaped(builder, _keys[index]);
                builder.Append(':');
                _members[_keys[index]].WriteCanonical(builder);
            }
            builder.Append('}');
        }

        private TNode Require<TNode>(string name) where TNode : TrustedJsonNode
        {
            TrustedJsonNode value;
            if (!_members.TryGetValue(name, out value) || !(value is TNode))
            {
                throw new InvalidOperationException(JsonPath + "." + name + ":wrong-type");
            }
            return (TNode)value;
        }
    }

    public sealed class TrustedJsonArray : TrustedJsonNode
    {
        private readonly List<TrustedJsonNode> _items = new List<TrustedJsonNode>();

        public IList<TrustedJsonNode> Items { get { return _items.AsReadOnly(); } }

        internal void Add(TrustedJsonNode value)
        {
            _items.Add(value);
        }

        internal override void WriteCanonical(StringBuilder builder)
        {
            builder.Append('[');
            for (int index = 0; index < _items.Count; index++)
            {
                if (index != 0)
                {
                    builder.Append(',');
                }
                _items[index].WriteCanonical(builder);
            }
            builder.Append(']');
        }
    }

    public sealed class TrustedJsonString : TrustedJsonNode
    {
        internal TrustedJsonString(string value)
        {
            Value = value;
        }

        public string Value { get; private set; }

        internal override void WriteCanonical(StringBuilder builder)
        {
            WriteEscaped(builder, Value);
        }

        internal static void WriteEscaped(StringBuilder builder, string value)
        {
            builder.Append('"');
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                switch (character)
                {
                    case '"':
                        builder.Append("\\\"");
                        break;
                    case '\\':
                        builder.Append("\\\\");
                        break;
                    case '\b':
                        builder.Append("\\b");
                        break;
                    case '\f':
                        builder.Append("\\f");
                        break;
                    case '\n':
                        builder.Append("\\n");
                        break;
                    case '\r':
                        builder.Append("\\r");
                        break;
                    case '\t':
                        builder.Append("\\t");
                        break;
                    default:
                        if (character < 0x20)
                        {
                            builder.Append("\\u");
                            builder.Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            builder.Append(character);
                        }
                        break;
                }
            }
            builder.Append('"');
        }
    }

    public sealed class TrustedJsonInteger : TrustedJsonNode
    {
        internal TrustedJsonInteger(ulong value)
        {
            Value = value;
        }

        public ulong Value { get; private set; }

        internal override void WriteCanonical(StringBuilder builder)
        {
            builder.Append(Value.ToString(CultureInfo.InvariantCulture));
        }
    }

    public sealed class TrustedJsonBoolean : TrustedJsonNode
    {
        internal TrustedJsonBoolean(bool value)
        {
            Value = value;
        }

        public bool Value { get; private set; }

        internal override void WriteCanonical(StringBuilder builder)
        {
            builder.Append(Value ? "true" : "false");
        }
    }

    public sealed class TrustedJsonNull : TrustedJsonNode
    {
        internal override void WriteCanonical(StringBuilder builder)
        {
            builder.Append("null");
        }
    }

    public static class TrustedControlJsonSchemaBootstrap
    {
        public const string JsonMetaSha256 = "254c61af6535b22db382c5f59f54348c87b2464eaaeffe7185589f8678dc927b";
        private const string ProtocolInventorySha256 = "d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f";

        private const int MaximumArrayItems = 8192;
        private const int MaximumDepth = 32;
        private const int MaximumFileBytes = 1048576;
        private const int MaximumObjectProperties = 4096;
        private const int MaximumStringBytes = 262144;

        public static TrustedJsonResult Evaluate(
            string stage,
            byte[] sourceBytes,
            byte[] metaBytes,
            byte[] inventoryBytes)
        {
            try
            {
                if (!string.Equals(stage, "json", StringComparison.Ordinal)
                    && !string.Equals(stage, "meta", StringComparison.Ordinal)
                    && !string.Equals(stage, "authority", StringComparison.Ordinal)
                    && !string.Equals(stage, "schema", StringComparison.Ordinal)
                    && !string.Equals(stage, "vector", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Unknown trusted-control JSON stage.", "stage");
                }
                TrustedJsonObject inventory = ParsePinnedInventory(inventoryBytes);
                TrustedJsonNode source = ParseCanonical(sourceBytes);
                if (string.Equals(stage, "json", StringComparison.Ordinal))
                {
                    return new TrustedJsonResult(true, "ok");
                }
                TrustedJsonObject meta = ParseAndValidateMeta(metaBytes);
                if (string.Equals(stage, "meta", StringComparison.Ordinal))
                {
                    return new TrustedJsonResult(true, "ok");
                }
                if (string.Equals(stage, "authority", StringComparison.Ordinal))
                {
                    TrustedJsonObject authority = source as TrustedJsonObject;
                    if (authority == null)
                    {
                        throw new InvalidOperationException("authority-shape");
                    }
                    ValidateAuthorityRaw(authority, meta, inventory);
                    TrustedControlAuthorityProjectionA.Validate(authority, meta, inventory);
                }
                else if (string.Equals(stage, "schema", StringComparison.Ordinal))
                {
                    ValidateSchema((TrustedJsonObject)source, meta);
                }
                else
                {
                    ValidateVector((TrustedJsonObject)source);
                }
                return new TrustedJsonResult(true, "ok");
            }
            catch (InvalidOperationException exception)
            {
                return new TrustedJsonResult(false, exception.Message);
            }
        }

        public static string ComputeSha256Hex(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                for (int index = 0; index < hash.Length; index++)
                {
                    builder.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
                }
                return builder.ToString();
            }
        }

        public static TrustedJsonNode ParseCanonical(byte[] bytes)
        {
            Parser parser = new Parser(bytes);
            TrustedJsonNode node = parser.Parse();
            byte[] canonical = node.ToCanonicalBytes();
            if (!BytesEqual(bytes, canonical))
            {
                throw new InvalidOperationException("noncanonical-json");
            }
            return node;
        }

        public static TrustedJsonObject ParseAndValidateMeta(byte[] metaBytes)
        {
            TrustedJsonObject meta = ParseCanonical(metaBytes) as TrustedJsonObject;
            if (meta == null)
            {
                throw new InvalidOperationException("schema-meta-shape");
            }
            RequireKeys(meta, new string[]
            {
                "schemaId", "schemaVersion", "documentPropertyOrder", "primitives", "productions",
                "constraints", "schemaKinds", "propertyKeysByType", "requiredPropertyKeysByType"
            });
            RequireString(meta, "schemaId", "PspktTrustedControlJsonSchemaMetaV1");
            RequireInteger(meta, "schemaVersion", 1UL);
            RequireStringArray(meta.GetArray("documentPropertyOrder"), new string[]
            {
                "schemaId", "schemaVersion", "kind", "status", "root", "semanticRules"
            });
            RequireStringArray(meta.GetArray("primitives"), new string[]
            {
                "Boolean", "UInt16", "UInt32", "UInt64", "Sha256Hex", "GuidText",
                "FiletimeTicks", "Rsa3072BlobHex", "FixedAscii8", "Utf8String"
            });
            RequireStringArray(meta.GetArray("productions"), new string[]
            {
                "Object", "Array", "Enum", "TaggedUnion", "Reference"
            });
            RequireStringArray(meta.GetArray("constraints"), new string[]
            {
                "required", "const", "min", "max", "minBytes", "maxBytes", "minItems",
                "maxItems", "uniqueBy", "propertyOrder", "discriminator", "semanticRules"
            });
            RequireStringArray(meta.GetArray("schemaKinds"), new string[] { "ClosedRegistry" });
            ValidatePropertyKeyMeta(meta.GetObject("propertyKeysByType"), meta.GetObject("requiredPropertyKeysByType"));
            if (!string.Equals(ComputeSha256Hex(metaBytes), JsonMetaSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("schema-meta-mismatch");
            }
            return meta;
        }

        public static TrustedJsonObject ParsePinnedInventory(byte[] inventoryBytes)
        {
            if (inventoryBytes == null)
            {
                throw new ArgumentNullException("inventoryBytes");
            }
            if (!string.Equals(
                ComputeSha256Hex(inventoryBytes),
                ProtocolInventorySha256,
                StringComparison.Ordinal))
            {
                throw new InvalidOperationException("protocol-inventory-mismatch");
            }
            TrustedJsonObject inventory = new Parser(inventoryBytes).Parse() as TrustedJsonObject;
            if (inventory == null)
            {
                throw new InvalidOperationException("protocol-inventory-shape");
            }
            ValidateInventoryShape(inventory);
            return inventory;
        }

        public static void ValidateAuthorityRaw(
            TrustedJsonObject authority,
            TrustedJsonObject meta,
            TrustedJsonObject inventory)
        {
            if (authority == null)
            {
                throw new ArgumentNullException("authority");
            }
            if (meta == null)
            {
                throw new ArgumentNullException("meta");
            }
            if (inventory == null)
            {
                throw new ArgumentNullException("inventory");
            }
            RequireKeys(authority, new string[]
            {
                "schemaId", "schemaVersion", "decisions", "digestDomains", "limits", "maintainedInputs",
                "outputSchemas", "membershipRoles", "mutationIds", "rules", "encodingTables", "provenance"
            });
            RequireString(authority, "schemaId", "PspktTrustedControlAuthorityV1");
            RequireInteger(authority, "schemaVersion", 1UL);
            TrustedJsonObject decisions = authority.GetObject("decisions");
            RequireKeys(decisions, new string[]
            {
                "activation", "aggregate", "externalProcesses", "platform", "registryInstances",
                "rsaPublicBlob", "scanner"
            });
            RequireString(decisions, "activation", "Forbidden");
            RequireString(decisions, "aggregate", "SchemaOnly");
            RequireString(decisions, "externalProcesses", "MigrationBlocker");
            RequireString(decisions, "platform", "WindowsPowerShell5And7");
            RequireString(decisions, "registryInstances", "Forbidden");
            RequireString(decisions, "rsaPublicBlob", "Canonical512ByteEnvelope");
            RequireString(decisions, "scanner", "DeferredAstRoslynYamlHardPrerequisite");
            TrustedJsonObject domains = authority.GetObject("digestDomains");
            RequireKeys(domains, new string[] { "powerShellEntryPoints", "supportedBuildEntry", "trustedControlArtifactSet" });
            RequireString(domains, "powerShellEntryPoints", "pspkt-powershell-entrypoints-v1");
            RequireString(domains, "supportedBuildEntry", "pspkt-supported-build-entry-v1");
            RequireString(domains, "trustedControlArtifactSet", "pspkt-trusted-control-artifact-set-v1");
            TrustedJsonObject limits = authority.GetObject("limits");
            RequireKeys(limits, new string[]
            {
                "entrypointMaximumRootBytes", "entrypointTotalSourceSitesMaximum",
                "entrypointTotalUserArgumentsMaximum", "rsaPublicBlobBytes",
                "fixedAscii8HexCharacters", "entrypointMaximumAggregateBytes",
                "entrypointReviewedSourceSiteBytes", "entrypointReviewedInterpreterBytes",
                "entrypointReviewedArgumentBytes", "entrypointReviewedHostToolBytes",
                "entrypointReviewedGuestCandidateBytes", "entrypointReviewedHostRunspaceBytes",
                "entrypointReviewedRootBytes", "entrypointReviewedTotalSourceSites",
                "entrypointReviewedTotalUserArguments", "entrypointReviewedMaximumDepth"
            });
            RequireInteger(limits, "entrypointMaximumRootBytes", 1048576UL);
            RequireInteger(limits, "entrypointMaximumAggregateBytes", 2097152UL);
            RequireInteger(limits, "entrypointTotalSourceSitesMaximum", 256UL);
            RequireInteger(limits, "entrypointTotalUserArgumentsMaximum", 128UL);
            RequireInteger(limits, "rsaPublicBlobBytes", 512UL);
            RequireInteger(limits, "fixedAscii8HexCharacters", 16UL);
            RequireInteger(limits, "entrypointReviewedSourceSiteBytes", 824UL);
            RequireInteger(limits, "entrypointReviewedInterpreterBytes", 2266UL);
            RequireInteger(limits, "entrypointReviewedArgumentBytes", 2058UL);
            RequireInteger(limits, "entrypointReviewedHostToolBytes", 7690UL);
            RequireInteger(limits, "entrypointReviewedGuestCandidateBytes", 1248UL);
            RequireInteger(limits, "entrypointReviewedHostRunspaceBytes", 1056UL);
            RequireInteger(limits, "entrypointReviewedRootBytes", 640422UL);
            RequireInteger(limits, "entrypointReviewedTotalSourceSites", 192UL);
            RequireInteger(limits, "entrypointReviewedTotalUserArguments", 128UL);
            RequireInteger(limits, "entrypointReviewedMaximumDepth", 6UL);
            RequireStringArray(authority.GetArray("maintainedInputs"), new string[]
            {
                "certification/trusted-control/schema/trusted-control-authority.v1.json",
                "certification/trusted-control/schema/trusted-control-json-schema-meta.v1.json",
                "certification/schema/protocol-schema-meta.v1.json",
                "certification/schema/protocol-schema.v1.json",
                "certification/schema/mandatory-tail-schedule.v1.json",
                "certification/schema/protocol-inventory.v1.json"
            });
            RequireStringArray(authority.GetArray("membershipRoles"), new string[]
            {
                "TrustedWorkflowRevision", "EnrolledHostRoot", "HostEvidence", "RecoveryAuthority"
            });
            RequireStringArray(authority.GetArray("mutationIds"), new string[]
            {
                "CounterIncrementPlusOne", "NonClosedMetricObservation"
            });
            ValidateEncodingTables(authority.GetObject("encodingTables"), authority.GetArray("provenance"));
            TrustedJsonArray outputs = authority.GetArray("outputSchemas");
            if (outputs.Items.Count != 10)
            {
                throw new InvalidOperationException("output-schema-count");
            }
            HashSet<string> paths = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> schemaIds = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> ruleIds = ReadRuleIds(authority.GetArray("rules"));
            RequireStringSet(ruleIds, new string[]
            {
                "TC-CANON-001", "COUNTER-FIXED-PLUS-ONE-001", "COUNTER-METRIC-DISJOINT-001",
                "METRIC-RESET-001", "ENTRYPOINT-ARGV-001", "ENTRYPOINT-BINDING-001",
                "PATH-STRICT-001", "RESOURCE-13-FIELDS-001", "RESOURCE-CARDINALITY-001",
                "BUILD-FIELDS-001", "BUILD-UPCASE-JOIN-001", "FILE-ID-INFO-001", "MASKS-001",
                "LUID-BE-001", "BUILD-KEY-001", "BUILD-INTERPRETER-001", "TIM-LT-001",
                "TIM-LE-001", "TIM-DERIVED-W-001", "TIM-VT-001", "TRUST-RSA-512-001",
                "TRUST-EPOCH-001", "TRUST-ROLE-001", "TCAST-DIGEST-001", "TCAST-PATH-001",
                "GUID-RFC4122-001", "UNICODE-KIND-001", "UNICODE-UPCASE-KEYED-001",
                "ENTRYPOINT-SIZE-001"
            }, "$.rules");
            string[] expectedPaths = new string[]
            {
                "certification/trusted-control/schema/counter-mutation-manifest-schema.v1.json",
                "certification/trusted-control/schema/nonclosed-metric-manifest-schema.v1.json",
                "certification/trusted-control/schema/powershell-entrypoints-schema.v1.json",
                "certification/trusted-control/schema/resource-registry-schema.v1.json",
                "certification/trusted-control/schema/supported-build-entry-schema.v1.json",
                "certification/trusted-control/schema/supported-builds-schema.v1.json",
                "certification/trusted-control/schema/timing-policy-schema.v1.json",
                "certification/trusted-control/schema/trust-roots-schema.v1.json",
                "certification/trusted-control/schema/trusted-control-artifact-set-schema.v1.json",
                "certification/trusted-control/schema/unicode-tables-schema.v1.json"
            };
            string[] expectedSchemaIds = new string[]
            {
                "PspktCounterMutationManifestSchemaV1",
                "PspktNonClosedMetricManifestSchemaV1",
                "PspktPowerShellEntryPointSchemaV1",
                "PspktResourceRegistrySchemaV1",
                "PspktSupportedBuildEntrySchemaV1",
                "PspktSupportedBuildRegistrySchemaV1",
                "PspktTimingPolicySchemaV1",
                "PspktTrustRootsSchemaV1",
                "PspktTrustedControlArtifactSetSchemaV1",
                "PspktUnicodeTablesSchemaV1"
            };
            string[] expectedFormats = new string[]
            {
                "JsonRegistry", "JsonRegistry", "ProtocolTlv", "JsonRegistry", "ProtocolTlv",
                "JsonRegistry", "JsonRegistry", "JsonRegistry", "ProtocolTlv", "JsonRegistry"
            };
            for (int index = 0; index < outputs.Items.Count; index++)
            {
                TrustedJsonObject output = RequireObject(outputs.Items[index], "output-schema-shape");
                RequireKeys(output, new string[] { "path", "schemaId", "format", "semanticRules", "declaration" });
                string path = output.GetString("path");
                if (!string.Equals(path, expectedPaths[index], StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(output.JsonPath + ".path:unexpected-output-path");
                }
                if (!paths.Add(path))
                {
                    throw new InvalidOperationException("output-path-collision");
                }
                string schemaId = output.GetString("schemaId");
                if (!schemaIds.Add(schemaId))
                {
                    throw new InvalidOperationException("duplicate-output-schema-id:" + schemaId);
                }
                string format = output.GetString("format");
                if (!string.Equals(schemaId, expectedSchemaIds[index], StringComparison.Ordinal)
                    || !string.Equals(format, expectedFormats[index], StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        output.JsonPath + ":unexpected-output-tuple");
                }
                TrustedJsonArray outputRules = output.GetArray("semanticRules");
                RequireRuleAssignment(outputRules, ExpectedRules(schemaId));
                RequireRulesDefined(outputRules, ruleIds);
            }
            ValidateSupportedBuildMirror(authority);
            ValidateRegistryRowConstraints(authority);
        }

        public static void ValidateSchema(TrustedJsonObject schema, TrustedJsonObject meta)
        {
            RequireKeys(schema, new string[] { "schemaId", "schemaVersion", "kind", "status", "root", "semanticRules" });
            RequireInteger(schema, "schemaVersion", 1UL);
            RequireString(schema, "kind", "ClosedRegistry");
            RequireString(schema, "status", "StructuralOnly");
            TrustedJsonObject root = schema.GetObject("root");
            RequireKeys(root, new string[] { "production", "additionalProperties", "propertyOrder", "properties" });
            RequireString(root, "production", "Object");
            if (root.GetBoolean("additionalProperties"))
            {
                throw new InvalidOperationException("schema-not-closed");
            }
            TrustedJsonArray propertyOrder = root.GetArray("propertyOrder");
            TrustedJsonArray properties = root.GetArray("properties");
            if (propertyOrder.Items.Count != properties.Items.Count || propertyOrder.Items.Count == 0)
            {
                throw new InvalidOperationException(schema.JsonPath + ".root.properties:schema-property-count");
            }
            for (int index = 0; index < properties.Items.Count; index++)
            {
                TrustedJsonObject property = RequireObject(properties.Items[index], "schema-property-shape");
                ValidateProperty(property, meta);
                if (!string.Equals(
                    RequireStringNode(propertyOrder.Items[index], "schema-property-order"),
                    property.GetString("name"),
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(propertyOrder.JsonPath + "[" + index + "]:schema-property-order");
                }
            }
            if (schema.GetArray("semanticRules").Items.Count == 0)
            {
                throw new InvalidOperationException(schema.GetArray("semanticRules").JsonPath + ":schema-rules-empty");
            }
            if (string.Equals(schema.GetString("schemaId"), "PspktTimingPolicySchemaV1", StringComparison.Ordinal))
            {
                ValidateTimingSchema(schema);
            }
        }

        public static void ValidateVector(TrustedJsonObject vector)
        {
            RequireKeys(vector, new string[] { "schemaId", "schemaVersion", "syntheticOnly", "expectedReason", "caseKind", "input" });
            RequireString(vector, "schemaId", "PspktTrustedControlVerificationVectorV1");
            RequireInteger(vector, "schemaVersion", 1UL);
            if (!vector.GetBoolean("syntheticOnly"))
            {
                throw new InvalidOperationException("vector-not-synthetic");
            }
            if (vector.GetString("expectedReason").Length == 0 || vector.GetString("caseKind").Length == 0)
            {
                throw new InvalidOperationException("vector-shape");
            }
            ValidateVectorInput(vector.GetString("caseKind"), vector.GetObject("input"));
        }

        private static void ValidateInventoryShape(TrustedJsonObject inventory)
        {
            RequireKeys(inventory, new string[]
            {
                "schemaVersion", "schemaId", "sourceHashes", "lifecycleSourceBase64", "lifecycle",
                "unionMappings", "profileOrder", "directionOrder", "deferredSeedTypeNames",
                "deferredSeedMessageKeys", "omittedTypeNames", "omittedMessageKeys",
                "primitiveValueMaxima", "payloadMaxima", "mandatoryCardinality",
                "maximumNamedDepth", "maximumTailRecords", "maximumTailWrapperBytes",
                "excludedTailChannels", "unassignedOverlayTypeIds", "reservedIllegalType"
            });
            RequireInteger(inventory, "schemaVersion", 1UL);
            RequireString(inventory, "schemaId", "PspktProtocolInventoryV1");
            inventory.GetObject("sourceHashes");
            inventory.GetString("lifecycleSourceBase64");
            inventory.GetObject("lifecycle");
            inventory.GetArray("unionMappings");
            inventory.GetArray("profileOrder");
            inventory.GetArray("directionOrder");
            inventory.GetArray("deferredSeedTypeNames");
            inventory.GetArray("deferredSeedMessageKeys");
            inventory.GetArray("omittedTypeNames");
            inventory.GetArray("omittedMessageKeys");
            TrustedJsonObject primitives = inventory.GetObject("primitiveValueMaxima");
            RequireKeys(primitives, new string[]
            {
                "U8", "U16", "U32", "U64", "FILETIME", "QPC", "GUID", "Opaque16",
                "FixedAscii8", "SHA-256", "Opaque32", "AsciiIdentifier", "BinarySid",
                "Utf8Short", "Rsa3072PublicBlob", "Rsa3072Signature", "LUID"
            });
            for (int index = 0; index < primitives.Keys.Count; index++)
            {
                if (primitives.GetInteger(primitives.Keys[index]) == 0)
                {
                    throw new InvalidOperationException(
                        "$.primitiveValueMaxima." + primitives.Keys[index] + ":zero-width");
                }
            }
            inventory.GetArray("payloadMaxima");
            inventory.GetInteger("mandatoryCardinality");
            RequireInteger(inventory, "maximumNamedDepth", 4UL);
            inventory.GetInteger("maximumTailRecords");
            inventory.GetInteger("maximumTailWrapperBytes");
            inventory.GetArray("excludedTailChannels");
            inventory.GetArray("unassignedOverlayTypeIds");
            inventory.GetObject("reservedIllegalType");
        }

        private static void ValidateVectorInput(string caseKind, TrustedJsonObject input)
        {
            string path = "$.input";
            if (caseKind == "baseline") RequireKeys(input, new string[0], path);
            else if (caseKind == "fixedAscii8") RequireKeys(input, new string[] { "hex" }, path);
            else if (caseKind == "guidBytes") RequireKeys(input, new string[] { "text", "rfc4122Hex" }, path);
            else if (caseKind == "luidBytes") RequireKeys(input, new string[] { "value", "bigEndianHex" }, path);
            else if (caseKind == "rsaEnvelope") RequireKeys(input, new string[] { "hex", "nativeExponentHex", "nativeExponentByteLength", "keyId" }, path);
            else if (caseKind == "rsaNative") RequireKeys(input, new string[] { "nativeHex", "expectedCanonicalHex", "expectedKeyId" }, path);
            else if (caseKind == "digest") RequireKeys(input, new string[] { "domain", "metaSha256", "schemaSha256", "canonicalTlvHex", "expectedDigest" }, path);
            else if (caseKind == "emission") RequireKeys(input, new string[] { "artifactKind", "outputPath" }, path);
            else if (caseKind == "pathSet") RequireKeys(input, new string[] { "paths" }, path);
            else if (caseKind == "membershipPath")
            {
                RequireKeys(input, new string[] { "path", "trackedPaths", "pendingPaths" }, path);
                ValidateVectorStringArray(input.GetArray("trackedPaths"), path + ".trackedPaths");
                ValidateVectorStringArray(input.GetArray("pendingPaths"), path + ".pendingPaths");
            }
            else if (caseKind == "schemaMetaHash") RequireKeys(input, new string[] { "expectedSha256" }, path);
            else if (caseKind == "overlay") RequireKeys(input, new string[] { "requestedState" }, path);
            else if (caseKind == "entrypointCaps") RequireKeys(
                input,
                new string[] { "rootBytes", "aggregateBytes", "totalSourceSites", "totalUserArguments" },
                path);
            else if (caseKind == "migrationBlockers")
            {
                RequireKeys(input, new string[] { "sites" }, path);
                ValidateVectorObjectArray(input.GetArray("sites"), new string[] { "kind", "symbol" }, path + ".sites");
            }
            else if (caseKind == "interpreterBinding")
            {
                RequireKeys(input, new string[] { "entrypointBindings", "buildBindings" }, path);
                string[] keys = new string[] { "key", "path", "imageDigest", "volumeSerial", "fileId" };
                ValidateVectorObjectArray(input.GetArray("entrypointBindings"), keys, path + ".entrypointBindings");
                ValidateVectorObjectArray(input.GetArray("buildBindings"), keys, path + ".buildBindings");
            }
            else if (caseKind == "timing")
            {
                string kind = input.GetString("constraintKind");
                if (kind == "VT") RequireKeys(input, new string[] { "constraintKind", "now", "deadline", "vtPolicy" }, path);
                else if (kind == "DerivedW")
                {
                    RequireKeys(input, new string[] { "now", "deadline", "relation", "constraintKind", "orderedTerms", "derivedW" }, path);
                    ValidateVectorObjectArray(input.GetArray("orderedTerms"), new string[] { "id", "value" }, path + ".orderedTerms");
                }
                else RequireKeys(input, new string[] { "constraintKind", "now", "deadline", "relation" }, path);
            }
            else throw new InvalidOperationException("$.caseKind:unknown:" + caseKind);
        }

        private static void ValidateVectorObjectArray(TrustedJsonArray values, string[] keys, string path)
        {
            for (int index = 0; index < values.Items.Count; index++)
            {
                RequireKeys(RequireObject(values.Items[index], path + "[" + index + "]"), keys, path + "[" + index + "]");
            }
        }

        private static void ValidateVectorStringArray(TrustedJsonArray values, string path)
        {
            for (int index = 0; index < values.Items.Count; index++)
            {
                TrustedJsonString value = values.Items[index] as TrustedJsonString;
                if (value == null) throw new InvalidOperationException(path + "[" + index + "]:wrong-type");
            }
        }

        private static HashSet<string> ReadRuleIds(TrustedJsonArray rules)
        {
            HashSet<string> result = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < rules.Items.Count; index++)
            {
                TrustedJsonObject rule = RequireObject(rules.Items[index], "rule-shape");
                RequireKeys(rule, new string[] { "ruleId", "definition" });
                if (!result.Add(rule.GetString("ruleId")))
                {
                    throw new InvalidOperationException("duplicate-rule-id");
                }
            }
            return result;
        }

        private static void ValidateEncodingTables(TrustedJsonObject tables, TrustedJsonArray provenance)
                {
                    RequireKeys(tables, new string[]
                    {
                        "digestFormulas", "rsaEnvelope", "keyId", "guid", "luid", "argv", "timing",
                        "paths", "roles", "fileIdInfo", "masks", "jsonToTlv", "provenance",
                        "membershipRows", "supportedBuildPropertyMirror", "membershipTotalMaximum", "lifecycleSchedule"
                        , "membershipPathGrammar"
                    });
                    TrustedJsonArray formulas = tables.GetArray("digestFormulas");
                    if (formulas.Items.Count != 3)
                    {
                        throw new InvalidOperationException("encodingTables.digestFormulas");
                    }
                    for (int index = 0; index < formulas.Items.Count; index++)
                    {
                        TrustedJsonObject formula = RequireObject(formulas.Items[index], "encodingTables.digestFormulas[" + index + "]");
                        RequireKeys(formula, new string[] { "artifact", "domain", "formula" });
                        RequireString(formula, "formula", "ASCII(domain)||00||metaSha256||schemaSha256||canonicalTlv");
                    }
                    RequireString((TrustedJsonObject)formulas.Items[0], "artifact", "TrustedControlArtifactSetV1");
                    RequireString((TrustedJsonObject)formulas.Items[0], "domain", "pspkt-trusted-control-artifact-set-v1");
                    RequireString((TrustedJsonObject)formulas.Items[1], "artifact", "PowerShellEntryPointRegistryV1");
                    RequireString((TrustedJsonObject)formulas.Items[1], "domain", "pspkt-powershell-entrypoints-v1");
                    RequireString((TrustedJsonObject)formulas.Items[2], "artifact", "SupportedBuildEntryV1");
                    RequireString((TrustedJsonObject)formulas.Items[2], "domain", "pspkt-supported-build-entry-v1");
                    TrustedJsonObject rsa = tables.GetObject("rsaEnvelope");
                    RequireKeys(rsa, new string[] { "byteLength", "header", "exponent", "modulus", "zeroTailBytes" });
                    RequireInteger(rsa, "byteLength", 512UL);
                    TrustedJsonObject header = rsa.GetObject("header");
                    RequireKeys(header, new string[] { "magic", "bitLength", "cbPublicExp", "cbModulus", "cbPrime1", "cbPrime2", "encoding" });
                    RequireInteger(header, "magic", 826364754UL);
                    RequireInteger(header, "bitLength", 3072UL);
                    RequireInteger(header, "cbPublicExp", 4UL);
                    RequireInteger(header, "cbModulus", 384UL);
                    RequireInteger(header, "cbPrime1", 0UL);
                    RequireInteger(header, "cbPrime2", 0UL);
                    RequireString(header, "encoding", "SixUInt32LittleEndian");
                    TrustedJsonObject exponent = rsa.GetObject("exponent");
                    RequireKeys(exponent, new string[] { "canonicalBytes", "nativeLengths", "value" });
                    RequireString(exponent, "canonicalBytes", "00010001");
                    RequireIntegerArray(exponent.GetArray("nativeLengths"), new ulong[] { 3UL, 4UL }, "encodingTables.rsaEnvelope.exponent.nativeLengths");
                    RequireInteger(exponent, "value", 65537UL);
                    TrustedJsonObject modulus = rsa.GetObject("modulus");
                    RequireKeys(modulus, new string[] { "byteLength", "encoding", "topBitSet" });
                    RequireInteger(modulus, "byteLength", 384UL);
                    RequireString(modulus, "encoding", "BigEndian");
                    if (!modulus.GetBoolean("topBitSet")) throw new InvalidOperationException("encodingTables.rsaEnvelope.modulus.topBitSet");
                    RequireInteger(rsa, "zeroTailBytes", 100UL);

                    TrustedJsonObject keyId = tables.GetObject("keyId");
                    RequireKeys(keyId, new string[] { "type", "formula" });
                    RequireString(keyId, "type", "Sha256Hex");
                    RequireString(keyId, "formula", "lowercase SHA256 of all 512 RSA envelope bytes");

                    TrustedJsonObject guid = tables.GetObject("guid");
                    RequireKeys(guid, new string[] { "text", "nilForbidden", "bytes" });
                    RequireString(guid, "text", "lowercase-D");
                    if (!guid.GetBoolean("nilForbidden"))
                    {
                        throw new InvalidOperationException("encodingTables.guid.nilForbidden");
                    }
                    RequireString(guid, "bytes", "RFC4122NetworkOrder");

                    TrustedJsonObject luid = tables.GetObject("luid");
                    RequireKeys(luid, new string[] { "bytes" });
                    RequireString(luid, "bytes", "UInt64BigEndian");

                    TrustedJsonObject argv = tables.GetObject("argv");
                    RequireKeys(argv, new string[] { "tokens", "maximumUtf16CodeUnits", "inverseRule", "shellReconstruction" });
                    RequireStringArray(argv.GetArray("tokens"), new string[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File" });
                    RequireInteger(argv, "maximumUtf16CodeUnits", 32767UL);
                    RequireString(argv, "inverseRule", "InverseCommandLineToArgvW");
                    if (argv.GetBoolean("shellReconstruction"))
                    {
                        throw new InvalidOperationException("encodingTables.argv.shellReconstruction");
                    }

                    TrustedJsonObject timing = tables.GetObject("timing");
                    RequireKeys(timing, new string[] { "deadline", "capacity", "derivedWOrderedIds", "vtPolicy", "clockDomains", "constraintRelations" });
                    RequireString(timing, "deadline", "LT");
                    RequireString(timing, "capacity", "LE");
                    string[] orderedTimingIds = new string[]
                    {
                        "consoleFenceRetirementDeadline", "consoleMainReaderJoinDeadline", "terminalRestoreEpisodeDeadline",
                        "consoleAuxiliaryQuiescenceDeadline", "consoleTopologyRevalidationDeadline", "finalFrameOutputDeadline",
                        "consoleTopologyRevalidationDeadline", "consoleControlCallbackDrainDeadline"
                    };
                    RequireStringArray(timing.GetArray("derivedWOrderedIds"), orderedTimingIds);
                    RequireString(timing, "vtPolicy", "raise-only");
                    RequireStringArray(timing.GetArray("clockDomains"), new string[] { "HostMonotonic", "BrokerMonotonic", "None" });
                    TrustedJsonObject relations = timing.GetObject("constraintRelations");
                    RequireKeys(relations, new string[] { "Deadline", "CapacityFit", "DerivedW", "VT" }, "$.encodingTables.timing.constraintRelations");
                    RequireString(relations, "Deadline", "LT");
                    RequireString(relations, "CapacityFit", "LE");
                    TrustedJsonObject derivedRelation = relations.GetObject("DerivedW");
                    RequireKeys(derivedRelation, new string[] { "kind", "relation" });
                    RequireString(derivedRelation, "kind", "CapacityFit");
                    RequireString(derivedRelation, "relation", "LE");
                    TrustedJsonObject vtRelation = relations.GetObject("VT");
                    RequireKeys(vtRelation, new string[] { "stateRule", "relation" });
                    RequireString(vtRelation, "stateRule", "raise-only");
                    RequireString(vtRelation, "relation", "None");

                    TrustedJsonObject paths = tables.GetObject("paths");
                    RequireKeys(paths, new string[] { "repository", "windows" });
                    RequireString(paths, "repository", "relative-forward-slash-no-dot-segments");
                    RequireString(paths, "windows", "WindowsOrdinalIgnoreCaseAsciiCanonicalAbsolute");
                    RequireStringArray(tables.GetArray("roles"), new string[]
                    {
                        "TrustedWorkflowRevision", "EnrolledHostRoot", "HostEvidence", "RecoveryAuthority"
                    });

                    TrustedJsonObject fileIdInfo = tables.GetObject("fileIdInfo");
                    RequireKeys(fileIdInfo, new string[] { "volumeSerial", "fileId" });
                    RequireString(fileIdInfo, "volumeSerial", "U64");
                    RequireString(fileIdInfo, "fileId", "Opaque16");

                    TrustedJsonObject masks = tables.GetObject("masks");
                    RequireKeys(masks, new string[] { "brokerProcessMask", "workerAceMask" });
                    RequireInteger(masks, "brokerProcessMask", 1180672UL);
                    RequireInteger(masks, "workerAceMask", 1049600UL);

                    TrustedJsonObject jsonToTlv = tables.GetObject("jsonToTlv");
                    RequireKeys(jsonToTlv, new string[] { "propertyOrderIsFieldOrder", "integers", "strings", "arrays", "timingRpnSides" });
                    if (!jsonToTlv.GetBoolean("propertyOrderIsFieldOrder"))
                    {
                        throw new InvalidOperationException("encodingTables.jsonToTlv.propertyOrderIsFieldOrder");
                    }
                    RequireString(jsonToTlv, "integers", "unsigned-exact");
                    RequireString(jsonToTlv, "strings", "UTF8");
                    RequireString(jsonToTlv, "arrays", "declared-order");
                    RequireStringArray(jsonToTlv.GetArray("timingRpnSides"), new string[] { "leftRpn", "rightRpn" });

                    TrustedJsonArray tableProvenance = tables.GetArray("provenance");
                    if (tableProvenance.Items.Count != provenance.Items.Count)
                    {
                        throw new InvalidOperationException("encodingTables.provenance.count");
                    }
                    for (int index = 0; index < provenance.Items.Count; index++)
                    {
                        TrustedJsonObject source = RequireObject(provenance.Items[index], "provenance[" + index + "]");
                        TrustedJsonObject table = RequireObject(tableProvenance.Items[index], "encodingTables.provenance[" + index + "]");
                        RequireKeys(table, new string[] { "order", "source", "status", "sha256" });
                        RequireInteger(table, "order", (ulong)(index + 1));
                        RequireString(table, "source", source.GetString("source"));
                        RequireString(table, "status", source.GetString("status"));
                        RequireString(table, "sha256", source.GetString("sha256"));
                    }
                    RequireInteger(tables, "membershipTotalMaximum", 512UL);
                    TrustedJsonArray membership = tables.GetArray("membershipRows");
                    if (membership.Items.Count != 3) throw new InvalidOperationException("encodingTables.membershipRows.count");
                    TrustedJsonObject authorityRow = (TrustedJsonObject)membership.Items[0];
                    RequireKeys(authorityRow, new string[] { "role", "minimumCardinality", "maximumCardinality", "status", "source", "path" });
                    RequireString(authorityRow, "role", "TrustedControlAuthority");
                    RequireInteger(authorityRow, "minimumCardinality", 1UL);
                    RequireInteger(authorityRow, "maximumCardinality", 1UL);
                    RequireString(authorityRow, "status", "Required");
                    RequireString(authorityRow, "source", "TrustedWorkflowRevision");
                    RequireString(authorityRow, "path", "certification/trusted-control/schema/trusted-control-authority.v1.json");
                    TrustedJsonObject workflowRow = (TrustedJsonObject)membership.Items[1];
                    RequireKeys(workflowRow, new string[] { "role", "minimumCardinality", "maximumCardinality", "status", "source", "path" });
                    RequireString(workflowRow, "role", "TrustedWorkflowRevision");
                    RequireInteger(workflowRow, "minimumCardinality", 0UL);
                    RequireInteger(workflowRow, "maximumCardinality", 510UL);
                    RequireString(workflowRow, "status", "AllowedMany");
                    RequireString(workflowRow, "source", "TrustedWorkflowRevision");
                    RequireString(workflowRow, "path", "certification/");
                    TrustedJsonObject enrolledRow = (TrustedJsonObject)membership.Items[2];
                    RequireKeys(enrolledRow, new string[] { "role", "minimumCardinality", "maximumCardinality", "status", "source", "path" });
                    RequireString(enrolledRow, "role", "EnrolledHostRoot");
                    RequireInteger(enrolledRow, "minimumCardinality", 0UL);
                    RequireInteger(enrolledRow, "maximumCardinality", 1UL);
                    RequireString(enrolledRow, "status", "Deferred");
                    RequireString(enrolledRow, "source", "EnrolledHostRoot");
                    RequireString(enrolledRow, "path", "enrolled-host-root/{sha256}");
                    TrustedJsonObject membershipGrammar = tables.GetObject("membershipPathGrammar");
                    RequireKeys(membershipGrammar, new string[] { "TrustedWorkflowRevision", "EnrolledHostRoot", "absolutePathsForbidden" });
                    RequireString(membershipGrammar, "TrustedWorkflowRevision", "tracked selected-revision artifact under certification/ satisfying TCAST-PATH-001");
                    RequireString(membershipGrammar, "EnrolledHostRoot", "enrolled-host-root/<64 lowercase hex>");
                    if (!membershipGrammar.GetBoolean("absolutePathsForbidden")) throw new InvalidOperationException("$.encodingTables.membershipPathGrammar.absolutePathsForbidden");
                    TrustedJsonObject lifecycle = tables.GetObject("lifecycleSchedule");
                    RequireKeys(lifecycle, new string[] { "source", "sha256", "keyFormula", "directionalDuplicatesCollapse", "keys" });
                    RequireString(lifecycle, "source", "certification/schema/mandatory-tail-schedule.v1.json");
                    RequireString(lifecycle, "keyFormula", "lifecycleVariant|state");
                    if (!lifecycle.GetBoolean("directionalDuplicatesCollapse")) throw new InvalidOperationException("encodingTables.lifecycleSchedule.directionalDuplicatesCollapse");
                }

                private static void ValidateSupportedBuildMirror(TrustedJsonObject authority)
                {
                    TrustedJsonArray mirror = authority.GetObject("encodingTables").GetArray("supportedBuildPropertyMirror");
                    TrustedJsonArray outputs = authority.GetArray("outputSchemas");
                    TrustedJsonArray tlvFields = null;
                    TrustedJsonArray jsonProperties = null;
                    for (int outputIndex = 0; outputIndex < outputs.Items.Count; outputIndex++)
                    {
                        TrustedJsonObject output = (TrustedJsonObject)outputs.Items[outputIndex];
                        if (output.GetString("schemaId") == "PspktSupportedBuildEntrySchemaV1")
                        {
                            TrustedJsonArray types = output.GetObject("declaration").GetArray("types");
                            for (int typeIndex = 0; typeIndex < types.Items.Count; typeIndex++)
                            {
                                TrustedJsonObject type = (TrustedJsonObject)types.Items[typeIndex];
                                if (type.GetString("name") == "SupportedBuildEntryV1") tlvFields = type.GetArray("fields");
                            }
                        }
                        if (output.GetString("schemaId") == "PspktSupportedBuildRegistrySchemaV1")
                        {
                            TrustedJsonArray rootProperties = output.GetObject("declaration").GetObject("root").GetArray("properties");
                            for (int propertyIndex = 0; propertyIndex < rootProperties.Items.Count; propertyIndex++)
                            {
                                TrustedJsonObject property = (TrustedJsonObject)rootProperties.Items[propertyIndex];
                                if (property.GetString("name") == "entries") jsonProperties = property.GetObject("items").GetArray("properties");
                            }
                        }


                    }
                    if (mirror == null || tlvFields == null || jsonProperties == null
                        || mirror.Items.Count != 41 || tlvFields.Items.Count != 41 || jsonProperties.Items.Count != 42)
                    {
                        throw new InvalidOperationException("encodingTables.supportedBuildPropertyMirror.count");
                    }
                    for (int index = 0; index < 41; index++)
                    {
                        TrustedJsonObject mirrorRow = (TrustedJsonObject)mirror.Items[index];
                        TrustedJsonObject tlvRow = (TrustedJsonObject)tlvFields.Items[index];
                        TrustedJsonObject jsonRow = (TrustedJsonObject)jsonProperties.Items[index + 1];
                        RequireInteger(mirrorRow, "fieldId", (ulong)(index + 1));
                        string name = mirrorRow.GetString("name");
                        string diagnosticPath = "$.encodingTables.supportedBuildPropertyMirror[" + index + "]";
                        if (name != tlvRow.GetString("name")) throw new InvalidOperationException(diagnosticPath + ":tlv-name");
                        if (name != jsonRow.GetString("name")) throw new InvalidOperationException(diagnosticPath + ":json-name");
                        if (mirrorRow.GetString("type") != tlvRow.GetString("type")) throw new InvalidOperationException(diagnosticPath + ":tlv-type");
                        if (!JsonTypeMatchesTlv(jsonRow, tlvRow.GetString("type"))) throw new InvalidOperationException(diagnosticPath + ":json-type-or-reference-target");
                        if (!JsonConstraintsMatchField(jsonRow, name)) throw new InvalidOperationException(diagnosticPath + ":json-constraint");

                    }
                }

        private static bool JsonTypeMatchesTlv(TrustedJsonObject json, string tlvType)
        {
            string expected = tlvType == "U8" || tlvType == "U16" ? "UInt16"
                : tlvType == "U32" ? "UInt32"
                : tlvType == "U64" || tlvType == "LUID" ? "UInt64"
                : tlvType == "SHA-256" ? "Sha256Hex"
                : tlvType == "GUID" ? "GuidText"
                : tlvType == "FixedAscii8" ? "FixedAscii8"
                : "Reference";
            if (json.GetString("type") != expected) return false;
            if (expected == "Reference")
            {
                return json.Contains("target") && json.GetString("target") == tlvType;
            }

            return !json.Contains("target");
        }

        private static void ValidateRegistryRowConstraints(TrustedJsonObject authority)
        {
            TrustedJsonArray outputs = authority.GetArray("outputSchemas");
            TrustedJsonObject counterDelta = FindRegistryRowProperty(
                outputs,
                "PspktCounterMutationManifestSchemaV1",
                "mutations",
                "delta");
            RequireInteger(counterDelta, "const", 1UL);
            TrustedJsonObject resourceMaximum = FindRegistryRowProperty(
                outputs,
                "PspktResourceRegistrySchemaV1",
                "resources",
                "maximumCardinality");
            RequireInteger(resourceMaximum, "min", 1UL);
            RequireInteger(resourceMaximum, "max", 4096UL);
        }

        private static TrustedJsonObject FindRegistryRowProperty(
            TrustedJsonArray outputs,
            string schemaId,
            string arrayName,
            string propertyName)
        {
            for (int outputIndex = 0; outputIndex < outputs.Items.Count; outputIndex++)
            {
                TrustedJsonObject output = (TrustedJsonObject)outputs.Items[outputIndex];
                if (!string.Equals(output.GetString("schemaId"), schemaId, StringComparison.Ordinal)) continue;
                TrustedJsonArray properties = output.GetObject("declaration").GetObject("root").GetArray("properties");
                for (int index = 0; index < properties.Items.Count; index++)
                {
                    TrustedJsonObject property = (TrustedJsonObject)properties.Items[index];
                    if (!string.Equals(property.GetString("name"), arrayName, StringComparison.Ordinal)) continue;
                    TrustedJsonArray rowProperties = property.GetObject("items").GetArray("properties");
                    for (int rowIndex = 0; rowIndex < rowProperties.Items.Count; rowIndex++)
                    {
                        TrustedJsonObject rowProperty = (TrustedJsonObject)rowProperties.Items[rowIndex];
                        if (string.Equals(rowProperty.GetString("name"), propertyName, StringComparison.Ordinal)) return rowProperty;
                    }
                }
            }
            throw new InvalidOperationException("$.outputSchemas:registry-row-property-missing:" + schemaId + "." + arrayName + "." + propertyName);
        }

        private static bool JsonConstraintsMatchField(TrustedJsonObject json, string name)
        {
            if (name == "directAbsent") return json.GetInteger("max") == 255UL && json.GetInteger("const") == 1UL;
            if (name == "t0ImpersonationLevel") return json.GetInteger("max") == 255UL && json.GetInteger("const") == 2UL;
            if (name == "brokerProcessMask") return json.GetInteger("const") == 1180672UL;
            if (name == "workerAceMask") return json.GetInteger("const") == 1049600UL;
            return true;
        }

        private static string[] ExpectedRules(string schemaId)
        {
            if (schemaId == "PspktCounterMutationManifestSchemaV1") return new string[] { "TC-CANON-001", "COUNTER-FIXED-PLUS-ONE-001", "COUNTER-METRIC-DISJOINT-001" };
            if (schemaId == "PspktNonClosedMetricManifestSchemaV1") return new string[] { "TC-CANON-001", "METRIC-RESET-001", "COUNTER-METRIC-DISJOINT-001" };
            if (schemaId == "PspktPowerShellEntryPointSchemaV1") return new string[] { "ENTRYPOINT-ARGV-001", "ENTRYPOINT-BINDING-001", "PATH-STRICT-001", "ENTRYPOINT-SIZE-001" };
            if (schemaId == "PspktResourceRegistrySchemaV1") return new string[] { "TC-CANON-001", "RESOURCE-13-FIELDS-001", "RESOURCE-CARDINALITY-001" };
            if (schemaId == "PspktSupportedBuildEntrySchemaV1") return new string[] { "BUILD-FIELDS-001", "BUILD-UPCASE-JOIN-001", "FILE-ID-INFO-001", "MASKS-001", "LUID-BE-001" };
            if (schemaId == "PspktSupportedBuildRegistrySchemaV1") return new string[] { "TC-CANON-001", "BUILD-KEY-001", "BUILD-UPCASE-JOIN-001", "BUILD-INTERPRETER-001" };
            if (schemaId == "PspktTimingPolicySchemaV1") return new string[] { "TC-CANON-001", "TIM-LT-001", "TIM-LE-001", "TIM-DERIVED-W-001", "TIM-VT-001" };
            if (schemaId == "PspktTrustRootsSchemaV1") return new string[] { "TC-CANON-001", "TRUST-RSA-512-001", "TRUST-EPOCH-001", "TRUST-ROLE-001" };
            if (schemaId == "PspktTrustedControlArtifactSetSchemaV1") return new string[] { "TCAST-DIGEST-001", "TCAST-PATH-001", "GUID-RFC4122-001" };
            if (schemaId == "PspktUnicodeTablesSchemaV1") return new string[] { "TC-CANON-001", "UNICODE-KIND-001", "UNICODE-UPCASE-KEYED-001" };
            throw new InvalidOperationException("$.outputSchemas:schema-rule-assignment-unknown:" + schemaId);
        }

        private static void RequireStringSet(HashSet<string> actual, string[] expected, string path)
        {
            HashSet<string> expectedSet = new HashSet<string>(expected, StringComparer.Ordinal);
            if (!actual.SetEquals(expectedSet))
            {
                throw new InvalidOperationException(path + ":semantic-rule-set");
            }
        }

        private static void RequireRuleAssignment(TrustedJsonArray actual, string[] expected)
        {
            if (actual.Items.Count != expected.Length)
            {
                throw new InvalidOperationException(actual.JsonPath + ":semantic-rule-assignment-count");
            }
            for (int index = 0; index < expected.Length; index++)
            {
                if (!string.Equals(
                    RequireStringNode(actual.Items[index], "semantic-rule-assignment-type"),
                    expected[index],
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        actual.JsonPath + "[" + index + "]:semantic-rule-assignment");
                }
            }
        }

        private static void RequireIntegerArray(TrustedJsonArray value, ulong[] expected, string reason)
        {
            if (value.Items.Count != expected.Length)
            {
                throw new InvalidOperationException(value.JsonPath + ":" + reason);
            }
            for (int index = 0; index < expected.Length; index++)
            {
                TrustedJsonInteger integer = value.Items[index] as TrustedJsonInteger;
                if (integer == null || integer.Value != expected[index])
                {
                    throw new InvalidOperationException(value.JsonPath + "[" + index + "]:" + reason);
                }
            }
        }

        private static void RequireRulesDefined(TrustedJsonArray rules, HashSet<string> defined)
        {
            for (int index = 0; index < rules.Items.Count; index++)
            {
                string rule = RequireStringNode(rules.Items[index], "rule-id-type");
                if (!defined.Contains(rule))
                {
                    throw new InvalidOperationException(rules.JsonPath + "[" + index + "]:undefined-semantic-rule:" + rule);
                }
            }
        }

        private static void RequireSameStrings(TrustedJsonArray left, TrustedJsonArray right, string reason)
        {
            if (left.Items.Count != right.Items.Count)
            {
                throw new InvalidOperationException(left.JsonPath + ":" + reason);
            }
            for (int index = 0; index < left.Items.Count; index++)
            {
                if (!string.Equals(
                    RequireStringNode(left.Items[index], reason),
                    RequireStringNode(right.Items[index], reason),
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(left.JsonPath + "[" + index + "]:" + reason);
                }
            }
        }

        private static void ValidatePropertyKeyMeta(TrustedJsonObject allowed, TrustedJsonObject required)
        {
            if (allowed.Keys.Count != required.Keys.Count)
            {
                throw new InvalidOperationException("meta-property-type-set");
            }
            for (int index = 0; index < allowed.Keys.Count; index++)
            {
                string type = allowed.Keys[index];
                if (!string.Equals(type, required.Keys[index], StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("meta-property-type-order");
                }
                TrustedJsonArray allowedKeys = allowed.GetArray(type);
                TrustedJsonArray requiredKeys = required.GetArray(type);
                for (int requiredIndex = 0; requiredIndex < requiredKeys.Items.Count; requiredIndex++)
                {
                    string requiredKey = RequireStringNode(requiredKeys.Items[requiredIndex], "meta-required-key-type");
                    bool found = false;
                    for (int allowedIndex = 0; allowedIndex < allowedKeys.Items.Count; allowedIndex++)
                    {
                        if (string.Equals(requiredKey, RequireStringNode(allowedKeys.Items[allowedIndex], "meta-allowed-key-type"), StringComparison.Ordinal))
                        {
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                    {
                        throw new InvalidOperationException("meta-required-key-not-allowed");
                    }
                }
            }
        }

        private static void ValidateProperty(TrustedJsonObject property, TrustedJsonObject meta)
        {
            string type = property.GetString("type");
            TrustedJsonObject allowedByType = meta.GetObject("propertyKeysByType");
            TrustedJsonObject requiredByType = meta.GetObject("requiredPropertyKeysByType");
            if (!allowedByType.Contains(type) || !requiredByType.Contains(type))
            {
                throw new InvalidOperationException(property.JsonPath + ".type:schema-property-type:" + type);
            }
            TrustedJsonArray allowed = allowedByType.GetArray(type);
            TrustedJsonArray required = requiredByType.GetArray(type);
            for (int index = 0; index < property.Keys.Count; index++)
            {
                string key = property.Keys[index];
                bool found = false;
                for (int allowedIndex = 0; allowedIndex < allowed.Items.Count; allowedIndex++)
                {
                    if (string.Equals(key, RequireStringNode(allowed.Items[allowedIndex], "meta-allowed-key-type"), StringComparison.Ordinal))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    throw new InvalidOperationException(property.JsonPath + "." + key + ":schema-property-key");
                }
            }
            for (int index = 0; index < required.Items.Count; index++)
            {
                string key = RequireStringNode(required.Items[index], "meta-required-key-type");
                if (!property.Contains(key))
                {
                    throw new InvalidOperationException(property.JsonPath + "." + key + ":schema-property-required");
                }
            }
            if (string.Equals(type, "Array", StringComparison.Ordinal))
            {
                TrustedJsonObject items = property.GetObject("items");
                RequireKeys(items, new string[] { "type", "properties" });
                TrustedJsonArray itemProperties = items.GetArray("properties");
                if (itemProperties.Items.Count == 0)
                {
                    throw new InvalidOperationException(property.JsonPath + ".items.properties:schema-array-items-empty");
                }
                for (int itemIndex = 0; itemIndex < itemProperties.Items.Count; itemIndex++)
                {
                    ValidateProperty(RequireObject(itemProperties.Items[itemIndex], "schema-item-property"), meta);
                }
                if (property.Contains("uniqueBy"))
                {
                    string uniqueBy = property.GetString("uniqueBy");
                    bool found = false;
                    for (int itemIndex = 0; itemIndex < itemProperties.Items.Count; itemIndex++)
                    {
                        TrustedJsonObject itemProperty = RequireObject(itemProperties.Items[itemIndex], "schema-item-property");
                        if (string.Equals(itemProperty.GetString("name"), uniqueBy, StringComparison.Ordinal))
                        {
                            found = true;
                        }
                    }
                    if (!found)
                    {
                        throw new InvalidOperationException(property.JsonPath + ".uniqueBy:schema-unique-key-missing:" + uniqueBy);
                    }
                }
                if (property.Contains("requiredKinds"))
                {
                    TrustedJsonArray requiredKinds = property.GetArray("requiredKinds");
                    TrustedJsonArray kindMembers = null;
                    for (int kindIndex = 0; kindIndex < itemProperties.Items.Count; kindIndex++)
                    {
                        TrustedJsonObject kindProperty = RequireObject(itemProperties.Items[kindIndex], "schema-item-property");
                        if (string.Equals(kindProperty.GetString("name"), "kind", StringComparison.Ordinal)
                            && string.Equals(kindProperty.GetString("type"), "Enum", StringComparison.Ordinal))
                        {
                            kindMembers = kindProperty.GetArray("members");
                        }
                    }
                    if (kindMembers == null)
                    {
                        throw new InvalidOperationException(property.JsonPath + ".requiredKinds:schema-kind-missing");
                    }
                    for (int requiredIndex = 0; requiredIndex < requiredKinds.Items.Count; requiredIndex++)
                    {
                        string requiredKind = RequireStringNode(requiredKinds.Items[requiredIndex], "schema.requiredKinds[" + requiredIndex + "]");
                        bool requiredFound = false;
                        for (int memberIndex = 0; memberIndex < kindMembers.Items.Count; memberIndex++)
                        {
                            requiredFound = requiredFound || string.Equals(requiredKind, RequireStringNode(kindMembers.Items[memberIndex], "schema.kind.members"), StringComparison.Ordinal);
                        }
                        if (!requiredFound) throw new InvalidOperationException(property.JsonPath + ".requiredKinds[" + requiredIndex + "]:undefined:" + requiredKind);
                    }
                }
            }
            else if (string.Equals(type, "Object", StringComparison.Ordinal))
            {
                TrustedJsonArray objectProperties = property.GetArray("properties");
                if (objectProperties.Items.Count == 0)
                {
                    throw new InvalidOperationException(property.JsonPath + ".properties:schema-object-properties-empty");
                }
                for (int index = 0; index < objectProperties.Items.Count; index++)
                {
                    ValidateProperty(RequireObject(objectProperties.Items[index], "schema-object-property"), meta);
                }
            }
            else if (string.Equals(type, "Enum", StringComparison.Ordinal))
            {
                TrustedJsonArray members = property.GetArray("members");
                if (members.Items.Count == 0)
                {
                    throw new InvalidOperationException(property.JsonPath + ".members:schema-enum-members-empty");
                }
                for (int index = 0; index < members.Items.Count; index++)
                {
                    string member = RequireStringNode(members.Items[index], "schema." + property.GetString("name") + ".members[" + index + "]");
                    if (string.Equals(member, "Declared", StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(property.JsonPath + ".members[" + index + "]:Declared-forbidden");
                    }
                }
            }
        }

        private static void ValidateTimingSchema(TrustedJsonObject schema)
        {
            TrustedJsonArray properties = schema.GetObject("root").GetArray("properties");
            TrustedJsonObject constraints = null;
            for (int index = 0; index < properties.Items.Count; index++)
            {
                TrustedJsonObject property = (TrustedJsonObject)properties.Items[index];
                if (string.Equals(property.GetString("name"), "constraints", StringComparison.Ordinal)) constraints = property;
            }
            if (constraints == null) throw new InvalidOperationException("schema.timing.constraints");
            TrustedJsonArray rows = constraints.GetObject("items").GetArray("properties");
            TrustedJsonObject relation = null;
            TrustedJsonObject left = null;
            TrustedJsonObject right = null;
            for (int index = 0; index < rows.Items.Count; index++)
            {
                TrustedJsonObject row = (TrustedJsonObject)rows.Items[index];
                string name = row.GetString("name");
                if (name == "relation") relation = row;
                if (name == "leftRpn") left = row;
                if (name == "rightRpn") right = row;
            }
            RequireStringArray(relation.GetArray("members"), new string[] { "LT", "LE" });
            RequireInteger(left, "maxItems", 32UL);
            RequireInteger(right, "maxItems", 32UL);
        }

        private static bool BytesEqual(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; index++)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }

        private static TrustedJsonObject RequireObject(TrustedJsonNode node, string reason)
        {
            TrustedJsonObject value = node as TrustedJsonObject;
            if (value == null)
            {
                throw new InvalidOperationException(reason);
            }
            return value;
        }

        private static string RequireStringNode(TrustedJsonNode node, string reason)
        {
            TrustedJsonString value = node as TrustedJsonString;
            if (value == null)
            {
                throw new InvalidOperationException(reason);
            }
            return value.Value;
        }

        private static void RequireInteger(TrustedJsonObject value, string name, ulong expected)
        {
            if (value.GetInteger(name) != expected)
            {
                throw new InvalidOperationException(value.JsonPath + "." + name + ":property-value");
            }
        }

        private static void RequireKeys(TrustedJsonObject value, string[] expected)
        {
            RequireKeys(value, expected, value.JsonPath);
        }

        private static void RequireKeys(TrustedJsonObject value, string[] expected, string path)
        {
            if (value.Keys.Count != expected.Length)
            {
                throw new InvalidOperationException(path + ":property-set");
            }
            for (int index = 0; index < expected.Length; index++)
            {
                if (!string.Equals(value.Keys[index], expected[index], StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(path + ":property-order:" + expected[index]);
                }
            }
        }

        private static void RequireString(TrustedJsonObject value, string name, string expected)
        {
            if (!string.Equals(value.GetString(name), expected, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(value.JsonPath + "." + name + ":property-value");
            }
        }

        private static void RequireStringArray(TrustedJsonArray value, string[] expected)
        {
            RequireStringArray(value, expected, value.JsonPath);
        }

        private static void RequireStringArray(TrustedJsonArray value, string[] expected, string path)
        {
            if (value.Items.Count != expected.Length)
            {
                throw new InvalidOperationException(path + ":meta-array-count");
            }
            for (int index = 0; index < expected.Length; index++)
            {
                if (!string.Equals(RequireStringNode(value.Items[index], "meta-array-type"), expected[index], StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(path + ":meta-array-order[" + index + "]");
                }
            }
        }

        private sealed class Parser
        {
            private readonly byte[] _bytes;
            private int _index;

            internal Parser(byte[] bytes)
            {
                if (bytes == null)
                {
                    throw new ArgumentNullException("bytes");
                }
                if (bytes.Length > MaximumFileBytes)
                {
                    throw new InvalidOperationException("file-limit");
                }
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                {
                    throw new InvalidOperationException("bom-forbidden");
                }
                for (int index = 0; index < bytes.Length; index++)
                {
                    if (bytes[index] == 0)
                    {
                        throw new InvalidOperationException("nul-forbidden");
                    }
                    if (bytes[index] == 13)
                    {
                        throw new InvalidOperationException("cr-forbidden");
                    }
                }
                _bytes = bytes;
            }

            internal TrustedJsonNode Parse()
            {
                SkipWhitespace();
                TrustedJsonNode result = ParseValue(1, "$");
                SkipWhitespace();
                if (_index != _bytes.Length)
                {
                    throw new InvalidOperationException("trailing-data");
                }
                return result;
            }

            private TrustedJsonNode ParseValue(int depth, string path)
            {
                if (depth > MaximumDepth || _index >= _bytes.Length)
                {
                    throw new InvalidOperationException(depth > MaximumDepth ? "depth-limit" : "trailing-data");
                }
                byte token = _bytes[_index];
                if (token == (byte)'{')
                {
                    return ParseObject(depth, path);
                }
                if (token == (byte)'[')
                {
                    return ParseArray(depth, path);
                }
                if (token == (byte)'"')
                {
                    TrustedJsonString value = new TrustedJsonString(ParseString());
                    value.JsonPath = path;
                    return value;
                }
                if (token >= (byte)'0' && token <= (byte)'9')
                {
                    TrustedJsonInteger value = new TrustedJsonInteger(ParseInteger());
                    value.JsonPath = path;
                    return value;
                }
                if (Match("true"))
                {
                    TrustedJsonBoolean value = new TrustedJsonBoolean(true);
                    value.JsonPath = path;
                    return value;
                }
                if (Match("false"))
                {
                    TrustedJsonBoolean value = new TrustedJsonBoolean(false);
                    value.JsonPath = path;
                    return value;
                }
                if (Match("null"))
                {
                    TrustedJsonNull value = new TrustedJsonNull();
                    value.JsonPath = path;
                    return value;
                }
                if (token == (byte)'-')
                {
                    throw new InvalidOperationException("negative-integer");
                }
                if (token == (byte)'/' || token == (byte)'#')
                {
                    throw new InvalidOperationException("comment-forbidden");
                }
                throw new InvalidOperationException("invalid-json");
            }

            private TrustedJsonObject ParseObject(int depth, string path)
            {
                _index++;
                TrustedJsonObject result = new TrustedJsonObject();
                result.JsonPath = path;
                SkipWhitespace();
                if (Peek((byte)'}'))
                {
                    _index++;
                    return result;
                }
                while (true)
                {
                    if (!Peek((byte)'"'))
                    {
                        throw new InvalidOperationException("invalid-object");
                    }
                    string name = ParseString();
                    SkipWhitespace();
                    if (result.Contains(name))
                    {
                        throw new InvalidOperationException("duplicate-key");
                    }
                    if (result.Keys.Count >= MaximumObjectProperties || !Consume((byte)':'))
                    {
                        throw new InvalidOperationException(result.Keys.Count >= MaximumObjectProperties ? "property-limit" : "invalid-object");
                    }
                    SkipWhitespace();
                    result.Add(name, ParseValue(depth + 1, path + "." + name));
                    SkipWhitespace();
                    if (Consume((byte)'}'))
                    {
                        return result;
                    }
                    if (!Consume((byte)',') || Peek((byte)'}'))
                    {
                        throw new InvalidOperationException(Peek((byte)'}') ? "trailing-comma" : "invalid-object");
                    }
                    SkipWhitespace();
                }
            }

            private TrustedJsonArray ParseArray(int depth, string path)
            {
                _index++;
                TrustedJsonArray result = new TrustedJsonArray();
                result.JsonPath = path;
                SkipWhitespace();
                if (Peek((byte)']'))
                {
                    _index++;
                    return result;
                }
                while (true)
                {
                    if (result.Items.Count >= MaximumArrayItems)
                    {
                        throw new InvalidOperationException("array-limit");
                    }
                    result.Add(ParseValue(depth + 1, path + "[" + result.Items.Count + "]"));
                    SkipWhitespace();
                    if (Consume((byte)']'))
                    {
                        return result;
                    }
                    if (!Consume((byte)',') || Peek((byte)']'))
                    {
                        throw new InvalidOperationException(Peek((byte)']') ? "trailing-comma" : "invalid-array");
                    }
                    SkipWhitespace();
                }
            }

            private ulong ParseInteger()
            {
                int start = _index;
                if (_bytes[_index] == (byte)'0')
                {
                    _index++;
                    if (_index < _bytes.Length && _bytes[_index] >= (byte)'0' && _bytes[_index] <= (byte)'9')
                    {
                        throw new InvalidOperationException("leading-zero-integer");
                    }
                }
                else
                {
                    while (_index < _bytes.Length && _bytes[_index] >= (byte)'0' && _bytes[_index] <= (byte)'9')
                    {
                        _index++;
                    }
                }
                if (_index < _bytes.Length && (_bytes[_index] == (byte)'.' || _bytes[_index] == (byte)'e' || _bytes[_index] == (byte)'E'))
                {
                    throw new InvalidOperationException("float-forbidden");
                }
                ulong value = 0;
                try
                {
                    for (int index = start; index < _index; index++)
                    {
                        value = checked((value * 10UL) + (ulong)(_bytes[index] - (byte)'0'));
                    }
                }
                catch (OverflowException)
                {
                    throw new InvalidOperationException("integer-overflow");
                }
                return value;
            }

            private string ParseString()
            {
                _index++;
                StringBuilder builder = new StringBuilder();
                while (_index < _bytes.Length)
                {
                    byte value = _bytes[_index++];
                    if (value == (byte)'"')
                    {
                        string result = builder.ToString();
                        if (Encoding.UTF8.GetByteCount(result) > MaximumStringBytes)
                        {
                            throw new InvalidOperationException("string-limit");
                        }
                        return result;
                    }
                    if (value == (byte)'\\')
                    {
                        ParseEscape(builder);
                    }
                    else if (value < 0x20)
                    {
                        throw new InvalidOperationException("invalid-escape");
                    }
                    else if (value < 0x80)
                    {
                        builder.Append((char)value);
                    }
                    else
                    {
                        ParseUtf8(builder, value);
                    }
                }
                throw new InvalidOperationException("trailing-data");
            }

            private void ParseEscape(StringBuilder builder)
            {
                if (_index >= _bytes.Length)
                {
                    throw new InvalidOperationException("invalid-escape");
                }
                byte value = _bytes[_index++];
                if (value == (byte)'"' || value == (byte)'\\' || value == (byte)'/')
                {
                    builder.Append((char)value);
                    return;
                }
                if (value == (byte)'b' || value == (byte)'f' || value == (byte)'n' || value == (byte)'r' || value == (byte)'t')
                {
                    builder.Append(value == (byte)'b' ? '\b' : value == (byte)'f' ? '\f' : value == (byte)'n' ? '\n' : value == (byte)'r' ? '\r' : '\t');
                    return;
                }
                if (value != (byte)'u')
                {
                    throw new InvalidOperationException("invalid-escape");
                }
                int unit = ReadHexQuad();
                if (unit == 0 || (unit >= 0xDC00 && unit <= 0xDFFF) || unit == 0xFFFD)
                {
                    throw new InvalidOperationException(unit == 0 ? "nul-forbidden" : unit == 0xFFFD ? "replacement-character-forbidden" : "unpaired-surrogate");
                }
                if (unit >= 0xD800 && unit <= 0xDBFF)
                {
                    if (_index + 1 >= _bytes.Length || _bytes[_index] != (byte)'\\' || _bytes[_index + 1] != (byte)'u')
                    {
                        throw new InvalidOperationException("unpaired-surrogate");
                    }
                    _index += 2;
                    int low = ReadHexQuad();
                    if (low < 0xDC00 || low > 0xDFFF)
                    {
                        throw new InvalidOperationException("unpaired-surrogate");
                    }
                    builder.Append((char)unit);
                    builder.Append((char)low);
                    return;
                }
                builder.Append((char)unit);
            }

            private void ParseUtf8(StringBuilder builder, byte lead)
            {
                int length = lead <= 0xDF ? 2 : lead <= 0xEF ? 3 : lead <= 0xF4 ? 4 : 0;
                if (lead < 0xC2 || length == 0 || _index + length - 1 > _bytes.Length)
                {
                    throw new InvalidOperationException("invalid-utf8");
                }
                int codePoint = lead & (length == 2 ? 0x1F : length == 3 ? 0x0F : 0x07);
                for (int offset = 1; offset < length; offset++)
                {
                    byte continuation = _bytes[_index++];
                    if ((continuation & 0xC0) != 0x80)
                    {
                        throw new InvalidOperationException("invalid-utf8");
                    }
                    codePoint = (codePoint << 6) | (continuation & 0x3F);
                }
                if ((length == 2 && codePoint < 0x80)
                    || (length == 3 && codePoint < 0x800)
                    || (length == 4 && codePoint < 0x10000)
                    || codePoint > 0x10FFFF
                    || (codePoint >= 0xD800 && codePoint <= 0xDFFF)
                    || codePoint == 0xFFFD)
                {
                    throw new InvalidOperationException(codePoint == 0xFFFD ? "replacement-character-forbidden" : "invalid-utf8");
                }
                if (codePoint < 0x10000)
                {
                    builder.Append((char)codePoint);
                }
                else
                {
                    int adjusted = codePoint - 0x10000;
                    builder.Append((char)(0xD800 + (adjusted >> 10)));
                    builder.Append((char)(0xDC00 + (adjusted & 0x3FF)));
                }
            }

            private int ReadHexQuad()
            {
                if (_index + 4 > _bytes.Length)
                {
                    throw new InvalidOperationException("invalid-escape");
                }
                int result = 0;
                for (int offset = 0; offset < 4; offset++)
                {
                    byte value = _bytes[_index++];
                    int digit = value >= (byte)'0' && value <= (byte)'9'
                        ? value - (byte)'0'
                        : value >= (byte)'a' && value <= (byte)'f'
                            ? 10 + value - (byte)'a'
                            : value >= (byte)'A' && value <= (byte)'F'
                                ? 10 + value - (byte)'A'
                                : -1;
                    if (digit < 0)
                    {
                        throw new InvalidOperationException("invalid-escape");
                    }
                    result = (result << 4) | digit;
                }
                return result;
            }

            private bool Match(string value)
            {
                if (_index + value.Length > _bytes.Length)
                {
                    return false;
                }
                for (int offset = 0; offset < value.Length; offset++)
                {
                    if (_bytes[_index + offset] != (byte)value[offset])
                    {
                        return false;
                    }
                }
                _index += value.Length;
                return true;
            }

            private bool Consume(byte value)
            {
                if (!Peek(value))
                {
                    return false;
                }
                _index++;
                return true;
            }

            private bool Peek(byte value)
            {
                return _index < _bytes.Length && _bytes[_index] == value;
            }

            private void SkipWhitespace()
            {
                while (_index < _bytes.Length
                    && (_bytes[_index] == 0x20 || _bytes[_index] == 0x09 || _bytes[_index] == 0x0A))
                {
                    _index++;
                }
            }
        }
    }

    public static class TrustedControlAuthorityProjectionA
    {
        private const int MaximumSizingRecursionDepth = 64;

        public static IDictionary<string, byte[]> Generate(
            byte[] authorityBytes,
            byte[] jsonMetaBytes,
            byte[] inventoryBytes)
        {
            TrustedJsonObject meta =
                TrustedControlJsonSchemaBootstrap.ParseAndValidateMeta(jsonMetaBytes);
            TrustedJsonObject inventory =
                TrustedControlJsonSchemaBootstrap.ParsePinnedInventory(inventoryBytes);
            TrustedJsonObject authority =
                TrustedControlJsonSchemaBootstrap.ParseCanonical(authorityBytes)
                    as TrustedJsonObject;
            if (authority == null)
            {
                throw new InvalidOperationException("authority-shape");
            }
            TrustedControlJsonSchemaBootstrap.ValidateAuthorityRaw(
                authority,
                meta,
                inventory);
            if (!string.Equals(
                authority.GetObject("decisions").GetString("activation"),
                "Forbidden",
                StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "$.decisions.activation:must-be-Forbidden");
            }
            try
            {
                return GenerateCore(authority, meta, inventory);
            }
            catch (InvalidOperationException exception)
            {
                throw Prefix(exception);
            }
            catch (OverflowException exception)
            {
                throw new InvalidOperationException(
                    "authority-entrypoint-sizing-overflow",
                    exception);
            }
        }

        internal static void Validate(
            TrustedJsonObject authority,
            TrustedJsonObject meta,
            TrustedJsonObject inventory)
        {
            try
            {
                GenerateCore(authority, meta, inventory);
            }
            catch (InvalidOperationException exception)
            {
                throw Prefix(exception);
            }
            catch (OverflowException exception)
            {
                throw new InvalidOperationException(
                    "authority-entrypoint-sizing-overflow",
                    exception);
            }
        }

        private static InvalidOperationException Prefix(InvalidOperationException exception)
        {
            return exception.Message.StartsWith("authority-", StringComparison.Ordinal)
                ? exception
                : new InvalidOperationException("authority-" + exception.Message, exception);
        }

        private static IDictionary<string, byte[]> GenerateCore(
            TrustedJsonObject authority,
            TrustedJsonObject meta,
            TrustedJsonObject inventory)
        {
            Dictionary<string, byte[]> outputs =
                new Dictionary<string, byte[]>(StringComparer.Ordinal);
            TrustedJsonArray declarations = authority.GetArray("outputSchemas");
            TrustedJsonArray entrypointTypes = null;
            for (int index = 0; index < declarations.Items.Count; index++)
            {
                TrustedJsonObject output = (TrustedJsonObject)declarations.Items[index];
                byte[] bytes = Project(output);
                TrustedJsonObject projected =
                    TrustedControlJsonSchemaBootstrap.ParseCanonical(bytes) as TrustedJsonObject;
                if (projected == null)
                {
                    throw new InvalidOperationException("projection-shape");
                }
                if (string.Equals(output.GetString("format"), "JsonRegistry", StringComparison.Ordinal))
                {
                    TrustedControlJsonSchemaBootstrap.ValidateSchema(projected, meta);
                    if (!BytesEqual(
                        output.GetArray("semanticRules").ToCanonicalBytes(),
                        projected.GetArray("semanticRules").ToCanonicalBytes()))
                    {
                        throw new InvalidOperationException("output-rule-drift");
                    }
                }
                if (string.Equals(
                    output.GetString("path"),
                    "certification/trusted-control/schema/powershell-entrypoints-schema.v1.json",
                    StringComparison.Ordinal))
                {
                    if (entrypointTypes != null)
                    {
                        throw new InvalidOperationException("entrypoint-schema-duplicate-match");
                    }
                    if (!string.Equals(
                            output.GetString("schemaId"),
                            "PspktPowerShellEntryPointSchemaV1",
                            StringComparison.Ordinal)
                        || !string.Equals(
                            output.GetString("format"),
                            "ProtocolTlv",
                            StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("entrypoint-schema-tuple");
                    }
                    entrypointTypes = projected.GetArray("types");
                }
                outputs.Add(output.GetString("path"), bytes);
            }
            if (entrypointTypes == null)
            {
                throw new InvalidOperationException("entrypoint-schema-missing");
            }
            ValidateSizing(authority.GetObject("limits"), inventory, entrypointTypes);
            return outputs;
        }

        private static byte[] Project(TrustedJsonObject output)
        {
            string schemaId = output.GetString("schemaId");
            TrustedJsonObject declaration = output.GetObject("declaration");
            string json;
            if (string.Equals(output.GetString("format"), "ProtocolTlv", StringComparison.Ordinal))
            {
                string declarationJson =
                    Encoding.UTF8.GetString(declaration.GetArray("types").ToCanonicalBytes());
                if (string.Equals(schemaId, "PspktPowerShellEntryPointSchemaV1", StringComparison.Ordinal))
                {
                    declarationJson = ProjectEntrypointDeclaration(declarationJson);
                }
                json = "{\"schemaVersion\":1,\"schemaId\":\"" + schemaId
                    + "\",\"types\":" + declarationJson + "}";
            }
            else
            {
                json = "{\"schemaId\":\"" + schemaId + "\",\"schemaVersion\":1,\"kind\":"
                    + "\"" + declaration.GetString("kind") + "\""
                    + ",\"status\":"
                    + "\"" + declaration.GetString("status") + "\""
                    + ",\"root\":"
                    + Encoding.UTF8.GetString(declaration.GetObject("root").ToCanonicalBytes())
                    + ",\"semanticRules\":"
                    + Encoding.UTF8.GetString(output.GetArray("semanticRules").ToCanonicalBytes())
                    + "}";
            }
            return new UTF8Encoding(false, true).GetBytes(json);
        }

        private static string ProjectEntrypointDeclaration(string declarationJson)
        {
            declarationJson = ReplaceExactlyOnce(
                declarationJson,
                "{\"typeId\":9,\"production\":\"List\",\"name\":\"PowerShellArgumentList\",\"elementType\":\"PowerShellArgumentV1\",\"minCount\":0,\"maxCount\":32}",
                "{\"typeId\":9,\"production\":\"List\",\"name\":\"PowerShellArgumentList\",\"elementType\":\"PowerShellArgumentV1\",\"minCount\":0,\"maxCount\":2}");
            declarationJson = ReplaceExactlyOnce(
                declarationJson,
                "{\"typeId\":11,\"production\":\"List\",\"name\":\"SourceSiteList\",\"elementType\":\"SourceSiteV1\",\"minCount\":1,\"maxCount\":128}",
                "{\"typeId\":11,\"production\":\"List\",\"name\":\"SourceSiteList\",\"elementType\":\"SourceSiteV1\",\"minCount\":1,\"maxCount\":1}");
            declarationJson = ReplaceExactlyOnce(
                declarationJson,
                "{\"typeId\":12,\"production\":\"Named\",\"name\":\"HostInterpreterIdentityV1\",\"fields\":[{\"fieldId\":1,\"name\":\"key\",\"type\":\"AsciiIdentifier\"},{\"fieldId\":2,\"name\":\"path\",\"type\":\"WindowsAbsolutePath\"},{\"fieldId\":3,\"name\":\"imageDigest\",\"type\":\"SHA-256\"}]}",
                "{\"typeId\":12,\"production\":\"Named\",\"name\":\"HostInterpreterIdentityV1\",\"fields\":[{\"fieldId\":1,\"name\":\"key\",\"type\":\"AsciiIdentifier\"},{\"fieldId\":2,\"name\":\"path\",\"type\":\"WindowsAbsolutePath\"},{\"fieldId\":3,\"name\":\"imageDigest\",\"type\":\"SHA-256\"},{\"fieldId\":4,\"name\":\"volumeSerial\",\"type\":\"U64\"},{\"fieldId\":5,\"name\":\"fileId\",\"type\":\"Opaque16\"}]}");
            return declarationJson;
        }

        private static string ReplaceExactlyOnce(string value, string oldValue, string newValue)
        {
            int index = value.IndexOf(oldValue, StringComparison.Ordinal);
            if (index < 0 || value.IndexOf(oldValue, index + oldValue.Length, StringComparison.Ordinal) >= 0)
            {
                throw new InvalidOperationException("entrypoint-projection-shape");
            }
            return value.Substring(0, index) + newValue + value.Substring(index + oldValue.Length);
        }

        private static void ValidateSizing(
            TrustedJsonObject limits,
            TrustedJsonObject inventory,
            TrustedJsonArray types)
        {
            Dictionary<string, TrustedJsonObject> typeByName =
                new Dictionary<string, TrustedJsonObject>(StringComparer.Ordinal);
            for (int index = 0; index < types.Items.Count; index++)
            {
                TrustedJsonObject type = types.Items[index] as TrustedJsonObject;
                if (type == null)
                {
                    throw new InvalidOperationException("entrypoint-type-set");
                }
                string typeName = type.GetString("name");
                if (typeByName.ContainsKey(typeName))
                {
                    throw new InvalidOperationException("entrypoint-type-set");
                }
                typeByName.Add(typeName, type);
            }
            TrustedJsonObject primitiveWidths = inventory.GetObject("primitiveValueMaxima");
            HashSet<string> active = new HashSet<string>(StringComparer.Ordinal);
            int maximumDepth = 0;
            ulong sourceSiteBytes = SizeType(
                "SourceSiteV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong interpreterBytes = SizeType(
                "HostInterpreterIdentityV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong argumentBytes = SizeType(
                "PowerShellArgumentV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong hostBytes = SizeType(
                "HostToolProcessEntryPointV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong guestBytes = SizeType(
                "GuestCandidateProcessEntryPointV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong runspaceBytes = SizeType(
                "HostInProcessRunspaceEntryPointV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong rootBytes = SizeType(
                "PowerShellEntryPointRegistryV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong totalSourceSites = CountReachableRecordOccurrences(
                "PowerShellEntryPointRegistryV1",
                "SourceSiteV1",
                typeByName,
                primitiveWidths,
                new HashSet<string>(StringComparer.Ordinal),
                1UL,
                1);
            ulong totalArguments = CountReachableRecordOccurrences(
                "PowerShellEntryPointRegistryV1",
                "PowerShellArgumentV1",
                typeByName,
                primitiveWidths,
                new HashSet<string>(StringComparer.Ordinal),
                1UL,
                1);
            if (rootBytes > limits.GetInteger("entrypointMaximumRootBytes"))
            {
                throw new InvalidOperationException("entrypoint-root-policy-ceiling");
            }
            if (totalSourceSites > limits.GetInteger("entrypointTotalSourceSitesMaximum"))
            {
                throw new InvalidOperationException("entrypoint-sites-policy-ceiling");
            }
            if (totalArguments > limits.GetInteger("entrypointTotalUserArgumentsMaximum"))
            {
                throw new InvalidOperationException("entrypoint-arguments-policy-ceiling");
            }
            if (sourceSiteBytes
                    != limits.GetInteger("entrypointReviewedSourceSiteBytes")
                || interpreterBytes
                    != limits.GetInteger("entrypointReviewedInterpreterBytes")
                || argumentBytes
                    != limits.GetInteger("entrypointReviewedArgumentBytes")
                || hostBytes
                    != limits.GetInteger("entrypointReviewedHostToolBytes")
                || guestBytes
                    != limits.GetInteger("entrypointReviewedGuestCandidateBytes")
                || runspaceBytes
                    != limits.GetInteger("entrypointReviewedHostRunspaceBytes")
                || rootBytes
                    != limits.GetInteger("entrypointReviewedRootBytes")
                || totalSourceSites
                    != limits.GetInteger("entrypointReviewedTotalSourceSites")
                || totalArguments
                    != limits.GetInteger("entrypointReviewedTotalUserArguments")
                || (ulong)maximumDepth
                    != limits.GetInteger("entrypointReviewedMaximumDepth"))
            {
                throw new InvalidOperationException(
                    "entrypoint-reviewed-sizing:"
                    + sourceSiteBytes + "/" + interpreterBytes + "/" + argumentBytes + "/"
                    + hostBytes + "/" + guestBytes + "/" + runspaceBytes + "/" + rootBytes + "/"
                    + totalSourceSites + "/" + totalArguments + "/" + maximumDepth);
            }
        }

        private static ulong SizeType(
            string typeName,
            TrustedJsonObject field,
            Dictionary<string, TrustedJsonObject> typeByName,
            TrustedJsonObject primitiveWidths,
            HashSet<string> active,
            int depth,
            ref int maximumDepth)
        {
            if (depth > MaximumSizingRecursionDepth)
            {
                throw new InvalidOperationException(
                    "entrypoint-recursion-safety-depth:" + depth);
            }
            if (depth > maximumDepth)
            {
                maximumDepth = depth;
            }
            if (string.Equals(typeName, "BoundedBytes", StringComparison.Ordinal))
            {
                if (field == null)
                {
                    throw new InvalidOperationException("bounded-bytes-field");
                }
                return checked(4UL + field.GetInteger("maxBytes"));
            }
            if (primitiveWidths.Contains(typeName))
            {
                return primitiveWidths.GetInteger(typeName);
            }
            TrustedJsonObject declaration;
            if (!typeByName.TryGetValue(typeName, out declaration))
            {
                throw new InvalidOperationException("entrypoint-undefined-type:" + typeName);
            }
            if (!active.Add(typeName))
            {
                throw new InvalidOperationException("entrypoint-type-cycle:" + typeName);
            }
            try
            {
                string production = declaration.GetString("production");
                if (string.Equals(production, "EnumU16", StringComparison.Ordinal))
                {
                    return 2UL;
                }
                if (string.Equals(production, "SemanticString", StringComparison.Ordinal))
                {
                    return checked(4UL + declaration.GetInteger("maxBytes"));
                }
                if (string.Equals(production, "List", StringComparison.Ordinal))
                {
                    ulong elementBytes = SizeType(
                        declaration.GetString("elementType"),
                        null,
                        typeByName,
                        primitiveWidths,
                        active,
                        depth + 1,
                        ref maximumDepth);
                    return checked(
                        4UL + (declaration.GetInteger("maxCount") * checked(4UL + elementBytes)));
                }
                if (string.Equals(production, "Named", StringComparison.Ordinal))
                {
                    ulong result = 0UL;
                    TrustedJsonArray fields = declaration.GetArray("fields");
                    for (int index = 0; index < fields.Items.Count; index++)
                    {
                        TrustedJsonObject namedField = (TrustedJsonObject)fields.Items[index];
                        result = checked(
                            result
                            + 6UL
                            + SizeType(
                                namedField.GetString("type"),
                                namedField,
                                typeByName,
                                primitiveWidths,
                                active,
                                depth + 1,
                                ref maximumDepth));
                    }
                    return result;
                }
                throw new InvalidOperationException("entrypoint-production:" + production);
            }
            finally
            {
                active.Remove(typeName);
            }
        }

        private static ulong CountReachableRecordOccurrences(
            string typeName,
            string targetRecordName,
            Dictionary<string, TrustedJsonObject> typeByName,
            TrustedJsonObject primitiveWidths,
            HashSet<string> active,
            ulong multiplier,
            int depth)
        {
            if (depth > MaximumSizingRecursionDepth)
            {
                throw new InvalidOperationException(
                    "entrypoint-recursion-safety-depth:" + depth);
            }
            if (string.Equals(typeName, targetRecordName, StringComparison.Ordinal))
            {
                return multiplier;
            }
            if (string.Equals(typeName, "BoundedBytes", StringComparison.Ordinal)
                || primitiveWidths.Contains(typeName))
            {
                return 0UL;
            }
            TrustedJsonObject declaration;
            if (!typeByName.TryGetValue(typeName, out declaration))
            {
                throw new InvalidOperationException("entrypoint-undefined-type:" + typeName);
            }
            if (!active.Add(typeName))
            {
                throw new InvalidOperationException("entrypoint-type-cycle:" + typeName);
            }
            try
            {
                string production = declaration.GetString("production");
                if (string.Equals(production, "EnumU16", StringComparison.Ordinal)
                    || string.Equals(production, "SemanticString", StringComparison.Ordinal))
                {
                    return 0UL;
                }
                if (string.Equals(production, "List", StringComparison.Ordinal))
                {
                    ulong elementMultiplier =
                        checked(multiplier * declaration.GetInteger("maxCount"));
                    return CountReachableRecordOccurrences(
                        declaration.GetString("elementType"),
                        targetRecordName,
                        typeByName,
                        primitiveWidths,
                        active,
                        elementMultiplier,
                        depth + 1);
                }
                if (string.Equals(production, "Named", StringComparison.Ordinal))
                {
                    ulong result = 0UL;
                    TrustedJsonArray fields = declaration.GetArray("fields");
                    for (int index = 0; index < fields.Items.Count; index++)
                    {
                        TrustedJsonObject field = (TrustedJsonObject)fields.Items[index];
                        result = checked(
                            result
                            + CountReachableRecordOccurrences(
                                field.GetString("type"),
                                targetRecordName,
                                typeByName,
                                primitiveWidths,
                                active,
                                multiplier,
                                depth + 1));
                    }
                    return result;
                }
                throw new InvalidOperationException("entrypoint-production:" + production);
            }
            finally
            {
                active.Remove(typeName);
            }
        }

        private static bool BytesEqual(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; index++)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }
    }

}
