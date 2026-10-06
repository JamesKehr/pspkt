using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Reflection;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Pspkt.Certification.EvidenceLedger
{
    public static class EvidenceLedgerVerify
    {
        private const string ConsumerContractDigest = "27ba860032b2399e2dc25d05e805fc18d601cfea53e656d4442621ab6ce65732";
        private const string InventoryShapeDigest = "ed6eaad545a48454347a51da96764f0b804dd2f1bf0ce7638a96c6e09c1fa1d7";
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);

        public static BigInteger PayloadMaximum(byte[] schemaBytes, byte[] primitiveInventoryBytes, byte[] metaBytes, string[] names)
        {
            if (names == null || names.Length == 0) { throw new InvalidDataException("Payload kind set is empty."); }
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("schema-against-meta", schemaBytes, metaBytes);
            if (!gate.Accepted) { throw new InvalidDataException("Sizing schema meta rejected: " + gate.Reason); }
            Dictionary<string, BigInteger> interactiveSizes = CalculateMaximums(schemaBytes, primitiveInventoryBytes, "InteractiveSeat");
            Dictionary<string, BigInteger> noninteractiveSizes = CalculateMaximums(schemaBytes, primitiveInventoryBytes, "NonInteractiveElevated");
            BigInteger maximum = BigInteger.Zero;
            foreach (string name in names)
            {
                BigInteger interactive;
                BigInteger noninteractive;
                if (!interactiveSizes.TryGetValue(name, out interactive) || !noninteractiveSizes.TryGetValue(name, out noninteractive)) { throw new InvalidDataException("Undefined sizing type: " + name); }
                if (interactive > maximum) { maximum = interactive; }
                if (noninteractive > maximum) { maximum = noninteractive; }
            }
            return RequireUInt32(maximum);
        }

        public static BigInteger Maximum(byte[] schemaBytes, byte[] primitiveInventoryBytes, byte[] metaBytes, string root, string profile)
        {
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("schema-against-meta", schemaBytes, metaBytes);
            if (!gate.Accepted) { throw new InvalidDataException("Sizing schema meta rejected: " + gate.Reason); }
            if (profile != "InteractiveSeat" && profile != "NonInteractiveElevated") { throw new InvalidDataException("Sizing profile is not concrete."); }
            return RequireUInt32(CalculateUncheckedMaximum(schemaBytes, primitiveInventoryBytes, root, profile));
        }

        private static uint RequireUInt32(BigInteger value)
        {
            if (value.Sign < 0 || value > new BigInteger(uint.MaxValue)) { throw new InvalidDataException("Encoded size exceeds UInt32."); }
            return (uint)value;
        }

        private static BigInteger CalculateUncheckedMaximum(byte[] schemaBytes, byte[] primitiveInventoryBytes, string root, string profile)
        {
            Dictionary<string, BigInteger> sizes = CalculateMaximums(schemaBytes, primitiveInventoryBytes, profile);
            BigInteger maximum;
            if (!sizes.TryGetValue(root, out maximum)) { throw new InvalidDataException("Undefined sizing type: " + root); }
            return maximum;
        }

        private static Dictionary<string, BigInteger> CalculateMaximums(byte[] schemaBytes, byte[] primitiveInventoryBytes, string profile)
        {
            Dictionary<string, BigInteger> sizes = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
            Dictionary<string, object> primitives = ObjectValue(ObjectValue(Parse(primitiveInventoryBytes))["primitiveValueMaxima"]);
            foreach (KeyValuePair<string, object> primitive in primitives) { sizes.Add(primitive.Key, BigInteger.Parse(primitive.Value.ToString(), CultureInfo.InvariantCulture)); }
            sizes.Add("I16", new BigInteger(2));
            sizes.Add("I32", new BigInteger(4));
            sizes.Add("I64", new BigInteger(8));
            List<object> remaining = new List<object>(ArrayValue(ObjectValue(Parse(schemaBytes)), "types"));
            while (remaining.Count != 0)
            {
                bool progress = false;
                for (int index = remaining.Count - 1; index >= 0; index--)
                {
                    Dictionary<string, object> declaration = ObjectValue(remaining[index]);
                    string production = Text(declaration, "production");
                    BigInteger width = BigInteger.Zero;
                    bool ready = true;
                    switch (production)
                    {
                        case "EnumU16": width = 2; break;
                        case "SemanticString": width = 4 + new BigInteger((ulong)declaration["maxBytes"]); break;
                        case "List":
                        case "Set":
                            BigInteger element;
                            ready = sizes.TryGetValue(Text(declaration, "elementType"), out element);
                            if (ready) { width = 4 + new BigInteger((ulong)declaration["maxCount"]) * (element + 4); }
                            break;
                        case "Named":
                            foreach (Dictionary<string, object> field in EffectiveFields(declaration, profile))
                            {
                                string type = Text(field, "type");
                                BigInteger payload;
                                if (type == "BoundedBytes") { payload = 4 + new BigInteger((ulong)field["maxBytes"]); }
                                else if (type == "OpaqueUtf16") { payload = 4 + 2 * new BigInteger((ulong)field["maxCodeUnits"]); }
                                else if (!sizes.TryGetValue(type, out payload)) { ready = false; break; }
                                width += 6 + payload;
                            }
                            break;
                        default: throw new InvalidDataException("Unsupported sizing production: " + production);
                    }
                    if (!ready) { continue; }
                    sizes.Add(Text(declaration, "name"), width);
                    remaining.RemoveAt(index);
                    progress = true;
                }
                if (!progress) { throw new InvalidDataException("Unresolved sizing dependencies."); }
            }
            return sizes;
        }

        public static byte[] Project(byte[] schemaBytes, string[] roots, byte[] mappingBytes)
        {
            Dictionary<string, object> schema = ObjectValue(Parse(schemaBytes));
            Dictionary<string, object> mappings = ObjectValue(Parse(mappingBytes));
            List<object> declarations = ArrayValue(schema, "types");
            HashSet<string> declaredNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (object item in declarations)
            {
                declaredNames.Add(Text(ObjectValue(item), "name"));
            }
            foreach (string root in roots)
            {
                if (!declaredNames.Contains(root)) { throw new InvalidDataException("Projection root is missing: " + root); }
            }
            HashSet<string> names = new HashSet<string>(roots, StringComparer.Ordinal);
            bool changed;
            do
            {
                changed = false;
                foreach (object item in declarations)
                {
                    Dictionary<string, object> declaration = ObjectValue(item);
                    string name = Text(declaration, "name");
                    if (!names.Contains(name)) { continue; }
                    if (declaration.ContainsKey("fields"))
                    {
                        foreach (object field in ArrayValue(declaration, "fields"))
                        {
                            changed |= names.Add(Text(ObjectValue(field), "type"));
                        }
                    }
                    if (declaration.ContainsKey("elementType")) { changed |= names.Add(Text(declaration, "elementType")); }
                    if (mappings.ContainsKey(name))
                    {
                        foreach (object branch in (List<object>)mappings[name]) { changed |= names.Add((string)branch); }
                    }
                }
            } while (changed);
            List<object> selected = new List<object>();
            foreach (object item in declarations)
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                if (!names.Contains(Text(declaration, "name"))) { continue; }
                if (Text(declaration, "production") == "Named")
                {
                    EffectiveFields(declaration, "InteractiveSeat");
                    EffectiveFields(declaration, "NonInteractiveElevated");
                }
                selected.Add(declaration);
                declaration["typeId"] = selected.Count;
            }
            schema["types"] = selected;
            return Canonical(schema);
        }

        public static void Verify(byte[] protocolBytes, byte[] protocolInventoryBytes, byte[] inventoryBytes, byte[] metaBytes,
            IDictionary<string, byte[]> outputs, IDictionary<string, string> pins,
            string bootstrapAssemblyIdentity, string authorityAssemblyIdentity, byte[] readmeBytes)
        {
            CheckIndependence(bootstrapAssemblyIdentity, authorityAssemblyIdentity);
            if (outputs == null || pins == null || outputs.Count != 3)
            {
                throw new InvalidDataException("Evidence ledger output set differs.");
            }
            CheckPinned(protocolBytes, pins, "protocol-schema.v1.json");
            CheckPinned(protocolInventoryBytes, pins, "protocol-inventory.v1.json");
            CheckPinned(inventoryBytes, pins, "evidence-ledger-inventory.v1.json");
            CheckPinned(metaBytes, pins, "protocol-schema-meta.v1.json");
            CheckPinned(readmeBytes, pins, "README.md");
            foreach (string name in new string[] { "evidence-schema.v1.json", "signing-ledger-schema.v1.json", "signing-ledger-maxima.v1.json" })
            {
                if (!outputs.ContainsKey(name) || !pins.ContainsKey(name))
                {
                    throw new InvalidDataException("Evidence ledger output set differs.");
                }
                using (SHA256 digest = SHA256.Create())
                {
                    string actual = BitConverter.ToString(digest.ComputeHash(outputs[name])).Replace("-", "").ToLowerInvariant();
                    if (!string.Equals(actual, pins[name], StringComparison.Ordinal))
                    {
                        throw new InvalidDataException("Pinned evidence ledger output hash differs: " + name);
                    }
                }
            }
            Dictionary<string, object> source = ObjectValue(Parse(protocolBytes));
            Dictionary<string, object> sourceInventory = ObjectValue(Parse(protocolInventoryBytes));
            if (source.Count != 3 || Text(source, "schemaId") != "PspktProtocolSchemaV1" || (ulong)source["schemaVersion"] != 1
                || ArrayValue(source, "types").Count != 107
                || sourceInventory.Count != 21 || Text(sourceInventory, "schemaId") != "PspktProtocolInventoryV1"
                || (ulong)sourceInventory["schemaVersion"] != 1 || ArrayValue(sourceInventory, "unionMappings").Count != 4
                || ObjectValue(sourceInventory["primitiveValueMaxima"]).Count != 17)
            {
                throw new InvalidDataException("Frozen protocol input shape differs.");
            }
            CheckEqual(Canonical(Parse(inventoryBytes)), inventoryBytes, "Noncanonical input: evidence-ledger-inventory.v1.json");
            foreach (KeyValuePair<string, byte[]> output in outputs)
            {
                CheckEqual(Canonical(Parse(output.Value)), output.Value, "Noncanonical output: " + output.Key);
            }
            foreach (string name in new string[] { "evidence-schema.v1.json", "signing-ledger-schema.v1.json" })
            {
                SchemaCheckResult gate = SchemaBootstrap.Evaluate("schema-against-meta", outputs[name], metaBytes);
                if (!gate.Accepted) { throw new InvalidDataException("Schema-against-meta failed: " + name + ": " + gate.Reason); }
            }
            Dictionary<string, object> inventory = ObjectValue(Parse(inventoryBytes));
            ValidateInventory(inventory);
            ValidateDocumentation(inventory, readmeBytes);
            ValidateSemantics(protocolBytes, protocolInventoryBytes, inventoryBytes, outputs);
        }

        private static void CheckIndependence(string bootstrapAssemblyIdentity, string authorityAssemblyIdentity)
        {
            if (string.IsNullOrEmpty(bootstrapAssemblyIdentity) || string.IsNullOrEmpty(authorityAssemblyIdentity))
            {
                throw new InvalidDataException("Verifier assembly identity is missing.");
            }
            if (bootstrapAssemblyIdentity == authorityAssemblyIdentity)
            {
                throw new InvalidDataException("Verifier bootstrap and authority assembly identities are not distinct.");
            }
            Assembly assembly = typeof(EvidenceLedgerVerify).Assembly;
            foreach (AssemblyName reference in assembly.GetReferencedAssemblies())
            {
                if (string.Equals(reference.FullName, authorityAssemblyIdentity, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Verifier dependency matches forbidden assembly identity.");
                }
                byte[] token = reference.GetPublicKeyToken();
                if ((token == null || token.Length == 0)
                    && !string.Equals(reference.FullName, bootstrapAssemblyIdentity, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Verifier dependency is not allowed.");
                }
                if (reference.Name.IndexOf("Authority", StringComparison.OrdinalIgnoreCase) >= 0
                    || reference.Name.IndexOf("Engine", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    throw new InvalidDataException("Verifier dependency is not independent.");
                }
            }
            foreach (Type type in assembly.GetTypes())
            {
                if (type.FullName.IndexOf("Authority", StringComparison.OrdinalIgnoreCase) >= 0
                    || type.FullName.IndexOf("Engine", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    throw new InvalidDataException("Verifier contains a forbidden type.");
                }
            }
        }

        private static void ValidateInventory(Dictionary<string, object> inventory)
        {
            if (!inventory.ContainsKey("consumerContract") || !(inventory["consumerContract"] is List<object>))
            {
                throw new InvalidDataException("Evidence ledger inventory shape differs.");
            }
            Dictionary<string, object> shape = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, object> property in inventory)
            {
                if (property.Key != "consumerContract") { shape.Add(property.Key, property.Value); }
            }
            if (Digest(Canonical(inventory["consumerContract"])) != ConsumerContractDigest
                || Digest(Canonical(shape)) != InventoryShapeDigest)
            {
                throw new InvalidDataException("Evidence ledger inventory shape differs.");
            }
        }

        private static void ValidateDocumentation(Dictionary<string, object> inventory, byte[] readmeBytes)
        {
            List<string> lines = new List<string>();
            foreach (object clause in ArrayValue(inventory, "consumerContract")) { lines.Add("- " + (string)clause); }
            string expected = "## Deferred binary consumer contract\n\n" + string.Join("\n", lines.ToArray()) + "\n\n";
            if (!Utf8.GetString(readmeBytes).Contains(expected))
            {
                throw new InvalidDataException("Evidence ledger consumer documentation differs.");
            }
        }

        private static string Digest(byte[] bytes)
        {
            using (SHA256 hash = SHA256.Create())
            {
                return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }

        private static void CheckPinned(byte[] bytes, IDictionary<string, string> pins, string name)
        {
            string expected;
            using (SHA256 digest = SHA256.Create())
            {
                string actual = BitConverter.ToString(digest.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
                if (!pins.TryGetValue(name, out expected) || actual != expected)
                {
                    throw new InvalidDataException("Pinned evidence ledger hash differs: " + name);
                }
            }
        }

        private static void ValidateSemantics(byte[] protocolBytes, byte[] protocolInventoryBytes, byte[] inventoryBytes,
            IDictionary<string, byte[]> outputs)
        {
            Dictionary<string, object> evidence = ObjectValue(Parse(outputs["evidence-schema.v1.json"]));
            Dictionary<string, object> actualLedger = ObjectValue(Parse(outputs["signing-ledger-schema.v1.json"]));
            ValidateLedgerLimits(ArrayValue(actualLedger, "types"));
            foreach (string name in new string[] { "OperationBurnReceiptV1", "OperationBurnDeferralReceiptV1",
                "OperationRehabilitationAuthorizationV1", "OperationRehabilitationReceiptV1" })
            {
                Dictionary<string, object> left = new Dictionary<string, object>(Find(ArrayValue(evidence, "types"), name), StringComparer.Ordinal);
                Dictionary<string, object> right = new Dictionary<string, object>(Find(ArrayValue(actualLedger, "types"), name), StringComparer.Ordinal);
                left.Remove("typeId");
                right.Remove("typeId");
                CheckEqual(Canonical(left), Canonical(right), "Cross-schema operation declaration differs.");
            }
            List<object> declarations = ArrayValue(evidence, "types");
            foreach (object item in declarations)
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                if (Text(declaration, "production") != "Named") { continue; }
                EffectiveFields(declaration, "InteractiveSeat");
                EffectiveFields(declaration, "NonInteractiveElevated");
            }
            CheckEqual(Canonical(ArrayValue(Find(declarations, "LocalEvidenceReceiptV1"), "fields")),
                Canonical(ArrayValue(Find(declarations, "LocalEvidenceProofV1"), "fields")),
                "Local evidence receipt and proof shapes differ.");
            Dictionary<string, object> inventory = ObjectValue(Parse(inventoryBytes));
            Dictionary<string, object> sourceInventory = ObjectValue(Parse(protocolInventoryBytes));
            Dictionary<string, object> branches = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (object item in ArrayValue(sourceInventory, "unionMappings"))
            {
                Dictionary<string, object> mapping = ObjectValue(item);
                List<object> names = new List<object>();
                foreach (object branch in ArrayValue(mapping, "branches")) { names.Add(Text(ObjectValue(branch), "emittedIdentifier")); }
                branches.Add(Text(mapping, "discriminator"), names);
            }
            string[] roots = ArrayValue(inventory, "evidenceRoots").ConvertAll(item => (string)item).ToArray();
            Dictionary<string, object> expected = ObjectValue(Parse(Project(protocolBytes, roots, Canonical(branches))));
            expected["schemaId"] = "PspktEvidenceSchemaV1";
            List<object> expectedTypes = ArrayValue(expected, "types");
            foreach (object item in ArrayValue(inventory, "evidenceAppend"))
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                expectedTypes.Add(declaration);
                declaration["typeId"] = expectedTypes.Count;
            }
            CheckEqual(Canonical(expected), outputs["evidence-schema.v1.json"], "Evidence declaration shape differs.");
            string[] ledgerRoots = ArrayValue(inventory, "ledgerRoots").ConvertAll(item => (string)item).ToArray();
            Dictionary<string, object> ledger = ObjectValue(Parse(Project(protocolBytes, ledgerRoots, Canonical(branches))));
            ledger["schemaId"] = "PspktSigningLedgerSchemaV1";
            List<object> ledgerTypes = ArrayValue(ledger, "types");
            foreach (object item in ArrayValue(inventory, "ledgerAppend"))
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                ledgerTypes.Add(declaration);
                declaration["typeId"] = ledgerTypes.Count;
            }
            CheckEqual(Canonical(ledger), outputs["signing-ledger-schema.v1.json"], "Signing ledger declaration shape differs.");
            Dictionary<string, BigInteger> evidenceInteractive = CalculateMaximums(outputs["evidence-schema.v1.json"], protocolInventoryBytes, "InteractiveSeat");
            Dictionary<string, BigInteger> evidenceNoninteractive = CalculateMaximums(outputs["evidence-schema.v1.json"], protocolInventoryBytes, "NonInteractiveElevated");
            Dictionary<string, BigInteger> ledgerInteractive = CalculateMaximums(outputs["signing-ledger-schema.v1.json"], protocolInventoryBytes, "InteractiveSeat");
            Dictionary<string, BigInteger> ledgerNoninteractive = CalculateMaximums(outputs["signing-ledger-schema.v1.json"], protocolInventoryBytes, "NonInteractiveElevated");
            List<object> evidenceNames = new List<object>();
            foreach (object member in ArrayValue(Find(declarations, "EvidenceArtifactKind"), "members")) { evidenceNames.Add(Text(ObjectValue(member), "name")); }
            ValidatePayloadBound(declarations, "EvidenceArtifactEnvelopeV1", evidenceNames, evidenceInteractive, evidenceNoninteractive);
            ValidatePayloadBound(ledgerTypes, "AuthorizationSigningLedgerRecordEnvelopeV1", ArrayValue(inventory, "authorizationKinds"), ledgerInteractive, ledgerNoninteractive);
            ValidatePayloadBound(ledgerTypes, "OperationSigningLedgerRecordEnvelopeV1", ArrayValue(inventory, "operationKinds"), ledgerInteractive, ledgerNoninteractive);
            List<object> rows = ArrayValue(inventory, "sizingConstants");
            foreach (object item in rows)
            {
                Dictionary<string, object> row = ObjectValue(item);
                string purpose = Text(row, "purpose");
                string[] suffixes = { "RecordEnvelopeV1", "SegmentV1", "InclusionProofV1" };
                string[] columns = { "maximumRecordBytes", "maximumSegmentBytes", "maximumInclusionProofBytes" };
                for (int index = 0; index < columns.Length; index++)
                {
                    BigInteger calculated = BigInteger.Max(
                        ledgerInteractive[purpose + "SigningLedger" + suffixes[index]],
                        ledgerNoninteractive[purpose + "SigningLedger" + suffixes[index]]);
                    if (calculated != new BigInteger((ulong)row[columns[index]])) { throw new InvalidDataException("Inventory sizing oracle differs."); }
                    row[columns[index]] = RequireUInt32(calculated);
                }
                row.Add("maximumRecords", 4096);
                row.Add("maximumSiblingHashes", 12);
            }
            Dictionary<string, object> maxima = new Dictionary<string, object>(StringComparer.Ordinal);
            maxima.Add("schemaId", "PspktSigningLedgerMaximaV1");
            maxima.Add("schemaVersion", 1);
            maxima.Add("rows", rows);
            CheckEqual(Canonical(maxima), outputs["signing-ledger-maxima.v1.json"], "Signing ledger maxima differ.");
        }

        private static void ValidatePayloadBound(List<object> declarations, string envelope, List<object> names,
            Dictionary<string, BigInteger> interactive, Dictionary<string, BigInteger> noninteractive)
        {
            BigInteger maximum = BigInteger.Zero;
            foreach (object item in names)
            {
                string name = (string)item;
                maximum = BigInteger.Max(maximum, BigInteger.Max(interactive[name], noninteractive[name]));
            }
            Dictionary<string, object> payload = Find(ArrayValue(Find(declarations, envelope), "fields"), "payload");
            if (new BigInteger((ulong)payload["maxBytes"]) != RequireUInt32(maximum))
            {
                throw new InvalidDataException("Envelope payload bound differs.");
            }
        }

        private static void ValidateLedgerLimits(List<object> declarations)
        {
            if ((ulong)Find(declarations, "Sha256SiblingList")["maxCount"] > 12)
            {
                throw new InvalidDataException("Signing ledger sibling limit exceeds 12.");
            }
            foreach (string purpose in new string[] { "Authorization", "Operation" })
            {
                string listName = purpose + "SigningLedgerRecordList";
                Dictionary<string, object> segment = Find(declarations, purpose + "SigningLedgerSegmentV1");
                if (Text(Find(ArrayValue(segment, "fields"), "records"), "type") != listName
                    || Text(Find(declarations, listName), "elementType") != purpose + "SigningLedgerRecordEnvelopeV1")
                {
                    throw new InvalidDataException("Signing ledger record list purpose differs.");
                }
            }
            foreach (string name in new string[] { "AuthorizationSigningLedgerRecordList", "OperationSigningLedgerRecordList" })
            {
                if ((ulong)Find(declarations, name)["maxCount"] > 4096)
                {
                    throw new InvalidDataException("Signing ledger record limit exceeds 4096.");
                }
            }
        }

        private static void CheckEqual(byte[] expected, byte[] actual, string message)
        {
            if (expected.Length != actual.Length) { throw new InvalidDataException(message); }
            for (int index = 0; index < expected.Length; index++)
            {
                if (expected[index] != actual[index]) { throw new InvalidDataException(message); }
            }
        }

        private static Dictionary<string, object> Find(List<object> declarations, string name)
        {
            foreach (object item in declarations)
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                if (Text(declaration, "name") == name) { return declaration; }
            }
            throw new InvalidDataException("Missing declaration: " + name);
        }

        private static List<Dictionary<string, object>> EffectiveFields(Dictionary<string, object> declaration, string profile)
        {
            List<Dictionary<string, object>> selected = new List<Dictionary<string, object>>();
            Dictionary<string, List<Dictionary<string, object>>> groups = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
            foreach (object item in ArrayValue(declaration, "fields"))
            {
                Dictionary<string, object> field = ObjectValue(item);
                string shape = FieldShape(field);
                List<Dictionary<string, object>> group;
                if (!groups.TryGetValue(shape, out group))
                {
                    group = new List<Dictionary<string, object>>();
                    groups.Add(shape, group);
                }
                group.Add(field);
            }
            foreach (List<Dictionary<string, object>> group in groups.Values)
            {
                List<Dictionary<string, object>> required = new List<Dictionary<string, object>>();
                foreach (Dictionary<string, object> field in group)
                {
                    if (Optional(field, "status", "Required") != "Required") { continue; }
                    required.Add(field);
                    string scope = Optional(field, "profile", "Any");
                    if (scope == "Any" || scope == profile) { selected.Add(field); }
                }
                foreach (Dictionary<string, object> field in group)
                {
                    if (Optional(field, "status", "Required") != "Forbidden") { continue; }
                    if (required.Count == 0) { throw new InvalidDataException("Forbidden field has no required shape."); }
                    string scope = Optional(field, "profile", "Any");
                    Dictionary<string, object> applicable = null;
                    foreach (Dictionary<string, object> candidate in required)
                    {
                        string candidateScope = Optional(candidate, "profile", "Any");
                        if (candidateScope != "Any" && candidateScope != scope) { continue; }
                        if (applicable != null) { throw new InvalidDataException("Forbidden field has multiple applicable required shapes."); }
                        applicable = candidate;
                    }
                    if (scope == profile && applicable != null) { selected.Remove(applicable); }
                }
            }
            selected.Sort(delegate(Dictionary<string, object> left, Dictionary<string, object> right)
            {
                return Convert.ToUInt64(left["fieldId"], CultureInfo.InvariantCulture).CompareTo(Convert.ToUInt64(right["fieldId"], CultureInfo.InvariantCulture));
            });
            return selected;
        }

        private static string FieldShape(Dictionary<string, object> field)
        {
            Dictionary<string, object> shape = new Dictionary<string, object>(field, StringComparer.Ordinal);
            shape.Remove("status");
            shape.Remove("profile");
            return Utf8.GetString(Canonical(shape));
        }

        private static string Optional(Dictionary<string, object> value, string name, string absent)
        {
            return value.ContainsKey(name) ? Text(value, name) : absent;
        }

        private static List<object> ArrayValue(Dictionary<string, object> value, string name)
        {
            object field;
            if (!value.TryGetValue(name, out field) || !(field is List<object>))
            {
                throw new InvalidDataException("Expected array: " + name);
            }
            return (List<object>)field;
        }

        private static byte[] Canonical(object value)
        {
            StringBuilder output = new StringBuilder();
            Encode(output, value);
            return Utf8.GetBytes(output.ToString());
        }

        private static void Encode(StringBuilder output, object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties != null)
            {
                string[] keys = new string[properties.Count];
                properties.Keys.CopyTo(keys, 0);
                Array.Sort(keys, StringComparer.Ordinal);
                output.Append('{');
                bool separator = false;
                foreach (string key in keys)
                {
                    if (separator) { output.Append(','); }
                    Encode(output, key);
                    output.Append(':');
                    Encode(output, properties[key]);
                    separator = true;
                }
                output.Append('}');
                return;
            }
            if (value is string)
            {
                output.Append('"');
                foreach (char character in (string)value)
                {
                    if (character < 32) { output.Append("\\u00").Append(((int)character).ToString("x2", CultureInfo.InvariantCulture)); }
                    else
                    {
                        if (character == '"' || character == '\\') { output.Append('\\'); }
                        output.Append(character);
                    }
                }
                output.Append('"');
                return;
            }
            IEnumerable sequence = value as IEnumerable;
            if (sequence != null)
            {
                output.Append('[');
                bool separator = false;
                foreach (object item in sequence)
                {
                    if (separator) { output.Append(','); }
                    Encode(output, item);
                    separator = true;
                }
                output.Append(']');
                return;
            }
            if (value is ulong || value is uint || value is int || value is long)
            {
                output.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
            }
            else if (value is bool) { output.Append((bool)value ? "true" : "false"); }
            else if (value == null) { output.Append("null"); }
            else { throw new InvalidDataException("Unsupported canonical value."); }
        }

        private static Dictionary<string, object> ObjectValue(object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties == null) { throw new InvalidDataException("Expected object."); }
            return properties;
        }

        private static object Parse(byte[] bytes)
        {
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("json", bytes, null);
            if (!gate.Accepted) { throw new InvalidDataException("Evidence ledger JSON rejected: " + gate.Reason); }
            XmlDictionaryReaderQuotas quotas = new XmlDictionaryReaderQuotas();
            quotas.MaxDepth = 32;
            quotas.MaxArrayLength = 8192;
            quotas.MaxStringContentLength = 262144;
            quotas.MaxBytesPerRead = 1048576;
            quotas.MaxNameTableCharCount = 1048576;
            using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(bytes, quotas))
            {
                reader.MoveToContent();
                return ReadElement(reader);
            }
        }

        private static object ReadElement(XmlDictionaryReader reader)
        {
            string prefix = reader.Prefix;
            if (reader.MoveToFirstAttribute())
            {
                do
                {
                    bool projection = reader.Prefix.Length == 0 && reader.NamespaceURI.Length == 0
                        && (reader.LocalName == "type" || reader.LocalName == "item");
                    bool escapedName = prefix.Length != 0 && reader.Prefix == "xmlns"
                        && reader.NamespaceURI == "http://www.w3.org/2000/xmlns/"
                        && reader.LocalName == prefix && reader.Value == "item";
                    if (!projection && !escapedName) { throw new InvalidDataException("Unsupported JSON projection attribute."); }
                } while (reader.MoveToNextAttribute());
                reader.MoveToElement();
            }
            string kind = reader.GetAttribute("type");
            if (kind == "array" || kind == "object")
            {
                List<object> items = new List<object>();
                Dictionary<string, object> properties = new Dictionary<string, object>(StringComparer.Ordinal);
                bool empty = reader.IsEmptyElement;
                reader.ReadStartElement();
                if (!empty)
                {
                    while (reader.MoveToContent() == XmlNodeType.Element)
                    {
                        string name = reader.GetAttribute("item") ?? reader.LocalName;
                        object child = ReadElement(reader);
                        if (kind == "array") { items.Add(child); }
                        else { properties.Add(name, child); }
                    }
                    reader.ReadEndElement();
                }
                return kind == "array" ? (object)items : properties;
            }
            string content = reader.ReadElementContentAsString();
            switch (kind)
            {
                case "string": return content;
                case "number": return ulong.Parse(content, CultureInfo.InvariantCulture);
                case "boolean": return content == "true";
                case "null": return null;
                default: throw new InvalidDataException("Unsupported JSON projection value.");
            }
        }

        private static string Text(Dictionary<string, object> value, string name)
        {
            object field;
            if (!value.TryGetValue(name, out field) || !(field is string))
            {
                throw new InvalidDataException("Expected string: " + name);
            }
            return (string)field;
        }
    }
}
