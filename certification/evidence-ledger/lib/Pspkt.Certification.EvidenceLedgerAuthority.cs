using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Pspkt.Certification.EvidenceLedger
{
    public static class EvidenceLedgerAuthority
    {
        private const string ConsumerContractDigest = "27ba860032b2399e2dc25d05e805fc18d601cfea53e656d4442621ab6ce65732";
        private const string InventoryShapeDigest = "ed6eaad545a48454347a51da96764f0b804dd2f1bf0ce7638a96c6e09c1fa1d7";
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);

        public static IDictionary<string, byte[]> Generate(byte[] protocolBytes, byte[] protocolInventoryBytes, byte[] inventoryBytes, byte[] metaBytes, byte[] readmeBytes)
        {
            Dictionary<string, byte[]> outputs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            Dictionary<string, object> inventory = ObjectValue(Parse(inventoryBytes));
            Dictionary<string, object> protocolInventory = ObjectValue(Parse(protocolInventoryBytes));
            Dictionary<string, object> protocol = ObjectValue(Parse(protocolBytes));
            if (Convert.ToBase64String(Canonical(inventory)) != Convert.ToBase64String(inventoryBytes))
            {
                throw new InvalidDataException("Noncanonical input: evidence-ledger-inventory.v1.json");
            }
            ValidateInventory(inventory);
            ValidateDocumentation(inventory, readmeBytes);
            if (protocol.Count != 3 || Text(protocol, "schemaId") != "PspktProtocolSchemaV1" || (ulong)protocol["schemaVersion"] != 1
                || protocolInventory.Count != 21 || Text(protocolInventory, "schemaId") != "PspktProtocolInventoryV1"
                || (ulong)protocolInventory["schemaVersion"] != 1 || ObjectValue(protocolInventory["primitiveValueMaxima"]).Count != 17
                || ArrayValue(protocolInventory, "unionMappings").Count != 4)
            {
                throw new InvalidDataException("Frozen protocol input shape differs.");
            }
            Dictionary<string, object> mappings = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (object item in ArrayValue(protocolInventory, "unionMappings"))
            {
                Dictionary<string, object> mapping = ObjectValue(item);
                List<object> branches = new List<object>();
                foreach (object branch in ArrayValue(mapping, "branches")) { branches.Add(Text(ObjectValue(branch), "emittedIdentifier")); }
                mappings.Add(Text(mapping, "discriminator"), branches);
            }
            string[] roots = ArrayValue(inventory, "evidenceRoots").ConvertAll(item => (string)item).ToArray();
            Dictionary<string, object> evidence = ObjectValue(Parse(Project(protocolBytes, roots, Canonical(mappings))));
            evidence["schemaId"] = "PspktEvidenceSchemaV1";
            List<object> declarations = ArrayValue(evidence, "types");
            foreach (object item in ArrayValue(inventory, "evidenceAppend"))
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                declaration["typeId"] = declarations.Count + 1;
                declarations.Add(declaration);
            }
            string[] evidenceKinds = ArrayValue(Find(declarations, "EvidenceArtifactKind"), "members")
                .ConvertAll(item => Text(ObjectValue(item), "name")).ToArray();
            SetPayloadBound(declarations, "EvidenceArtifactEnvelopeV1",
                PayloadMaximum(Canonical(evidence), protocolInventoryBytes, metaBytes, evidenceKinds));
            byte[] evidenceBytes = Canonical(evidence);
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("schema-against-meta", evidenceBytes, metaBytes);
            if (!gate.Accepted) { throw new InvalidDataException("Evidence schema meta rejected: " + gate.Reason); }
            outputs.Add("evidence-schema.v1.json", evidenceBytes);
            string[] ledgerRoots = ArrayValue(inventory, "ledgerRoots").ConvertAll(item => (string)item).ToArray();
            Dictionary<string, object> ledger = ObjectValue(Parse(Project(protocolBytes, ledgerRoots, Canonical(mappings))));
            ledger["schemaId"] = "PspktSigningLedgerSchemaV1";
            List<object> ledgerTypes = ArrayValue(ledger, "types");
            foreach (object item in ArrayValue(inventory, "ledgerAppend"))
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                declaration["typeId"] = ledgerTypes.Count + 1;
                ledgerTypes.Add(declaration);
            }
            foreach (string name in new string[] { "OperationBurnReceiptV1", "OperationBurnDeferralReceiptV1",
                "OperationRehabilitationAuthorizationV1", "OperationRehabilitationReceiptV1" })
            {
                Dictionary<string, object> evidenceShape = new Dictionary<string, object>(Find(declarations, name), StringComparer.Ordinal);
                Dictionary<string, object> ledgerShape = new Dictionary<string, object>(Find(ledgerTypes, name), StringComparer.Ordinal);
                evidenceShape.Remove("typeId");
                ledgerShape.Remove("typeId");
                if (Convert.ToBase64String(Canonical(evidenceShape)) != Convert.ToBase64String(Canonical(ledgerShape)))
                {
                    throw new InvalidDataException("Cross-schema operation declaration differs.");
                }
            }
            ValidateLedgerLimits(ledgerTypes);
            SetPayloadBound(ledgerTypes, "AuthorizationSigningLedgerRecordEnvelopeV1",
                PayloadMaximum(Canonical(ledger), protocolInventoryBytes, metaBytes,
                    ArrayValue(inventory, "authorizationKinds").ConvertAll(item => (string)item).ToArray()));
            SetPayloadBound(ledgerTypes, "OperationSigningLedgerRecordEnvelopeV1",
                PayloadMaximum(Canonical(ledger), protocolInventoryBytes, metaBytes,
                    ArrayValue(inventory, "operationKinds").ConvertAll(item => (string)item).ToArray()));
            byte[] ledgerBytes = Canonical(ledger);
            gate = SchemaBootstrap.Evaluate("schema-against-meta", ledgerBytes, metaBytes);
            if (!gate.Accepted) { throw new InvalidDataException("Signing ledger schema meta rejected: " + gate.Reason); }
            outputs.Add("signing-ledger-schema.v1.json", ledgerBytes);
            List<object> rows = ArrayValue(inventory, "sizingConstants");
            foreach (object item in rows)
            {
                Dictionary<string, object> row = ObjectValue(item);
                string purpose = Text(row, "purpose");
                string[] suffixes = { "RecordEnvelopeV1", "SegmentV1", "InclusionProofV1" };
                string[] columns = { "maximumRecordBytes", "maximumSegmentBytes", "maximumInclusionProofBytes" };
                for (int index = 0; index < columns.Length; index++)
                {
                    BigInteger calculated = PayloadMaximum(ledgerBytes, protocolInventoryBytes, metaBytes,
                        new string[] { purpose + "SigningLedger" + suffixes[index] });
                    if (calculated != new BigInteger((ulong)row[columns[index]])) { throw new InvalidDataException("Inventory sizing oracle differs."); }
                    row[columns[index]] = RequireUInt32(calculated);
                }
                row.Add("maximumRecords", 4096);
                row.Add("maximumSiblingHashes", 12);
            }
            Dictionary<string, object> maxima = new Dictionary<string, object>(StringComparer.Ordinal);
            maxima.Add("rows", rows);
            maxima.Add("schemaId", "PspktSigningLedgerMaximaV1");
            maxima.Add("schemaVersion", 1);
            outputs.Add("signing-ledger-maxima.v1.json", Canonical(maxima));
            return outputs;
        }

        public static BigInteger PayloadMaximum(byte[] schemaBytes, byte[] primitiveInventoryBytes, byte[] metaBytes, string[] names)
        {
            if (names == null || names.Length == 0) { throw new InvalidDataException("Payload kind set is empty."); }
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("schema-against-meta", schemaBytes, metaBytes);
            if (!gate.Accepted) { throw new InvalidDataException("Sizing schema meta rejected: " + gate.Reason); }
            Dictionary<string, BigInteger> interactive = CalculateMaximums(schemaBytes, primitiveInventoryBytes, "InteractiveSeat");
            Dictionary<string, BigInteger> noninteractive = CalculateMaximums(schemaBytes, primitiveInventoryBytes, "NonInteractiveElevated");
            BigInteger maximum = BigInteger.Zero;
            foreach (string name in names)
            {
                if (!interactive.ContainsKey(name) || !noninteractive.ContainsKey(name)) { throw new InvalidDataException("Undefined sizing type: " + name); }
                maximum = BigInteger.Max(maximum, BigInteger.Max(interactive[name], noninteractive[name]));
            }
            return RequireUInt32(maximum);
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

        private static void ValidateLedgerLimits(List<object> declarations)
        {
            if ((ulong)Find(declarations, "Sha256SiblingList")["maxCount"] > 12)
            {
                throw new InvalidDataException("Signing ledger sibling limit exceeds 12.");
            }
            foreach (string purpose in new string[] { "Authorization", "Operation" })
            {
                Dictionary<string, object> segment = Find(declarations, purpose + "SigningLedgerSegmentV1");
                Dictionary<string, object> records = Find(ArrayValue(segment, "fields"), "records");
                Dictionary<string, object> list = Find(declarations, purpose + "SigningLedgerRecordList");
                if (Text(records, "type") != purpose + "SigningLedgerRecordList"
                    || Text(list, "elementType") != purpose + "SigningLedgerRecordEnvelopeV1")
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

        private static void SetPayloadBound(List<object> declarations, string name, BigInteger maximum)
        {
            foreach (object item in ArrayValue(Find(declarations, name), "fields"))
            {
                Dictionary<string, object> field = ObjectValue(item);
                if (Text(field, "name") != "payload") { continue; }
                if (new BigInteger((ulong)field["maxBytes"]) != maximum) { throw new InvalidDataException("Envelope payload bound differs."); }
                field["maxBytes"] = RequireUInt32(maximum);
                return;
            }
            throw new InvalidDataException("Envelope payload field is missing.");
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
            if (value < BigInteger.Zero || value > uint.MaxValue) { throw new InvalidDataException("Encoded size exceeds UInt32."); }
            return (uint)value;
        }

        private static BigInteger CalculateUncheckedMaximum(byte[] schemaBytes, byte[] primitiveInventoryBytes, string root, string profile)
        {
            Dictionary<string, BigInteger> widths = CalculateMaximums(schemaBytes, primitiveInventoryBytes, profile);
            BigInteger maximum;
            if (!widths.TryGetValue(root, out maximum)) { throw new InvalidDataException("Undefined sizing type: " + root); }
            return maximum;
        }

        private static Dictionary<string, BigInteger> CalculateMaximums(byte[] schemaBytes, byte[] primitiveInventoryBytes, string profile)
        {
            Dictionary<string, Dictionary<string, object>> types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in ArrayValue(ObjectValue(Parse(schemaBytes)), "types"))
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                types.Add(Text(declaration, "name"), declaration);
            }
            Dictionary<string, BigInteger> widths = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
            Dictionary<string, object> primitiveWidths = ObjectValue(ObjectValue(Parse(primitiveInventoryBytes))["primitiveValueMaxima"]);
            foreach (KeyValuePair<string, object> pair in primitiveWidths) { widths.Add(pair.Key, new BigInteger((ulong)pair.Value)); }
            widths.Add("I16", new BigInteger(2));
            widths.Add("I32", new BigInteger(4));
            widths.Add("I64", new BigInteger(8));
            foreach (string name in types.Keys) { WidthOf(name, null, types, widths, profile); }
            return widths;
        }

        private static BigInteger WidthOf(string name, Dictionary<string, object> field,
            Dictionary<string, Dictionary<string, object>> types, Dictionary<string, BigInteger> widths, string profile)
        {
            if (name == "BoundedBytes" || name == "OpaqueUtf16")
            {
                if (field == null) { throw new InvalidDataException("Bounded primitive requires a field bound."); }
                string bound = name == "BoundedBytes" ? "maxBytes" : "maxCodeUnits";
                return 4 + new BigInteger((ulong)field[bound]) * (name == "BoundedBytes" ? 1 : 2);
            }
            BigInteger known;
            if (widths.TryGetValue(name, out known)) { return known; }
            Dictionary<string, object> declaration;
            if (!types.TryGetValue(name, out declaration)) { throw new InvalidDataException("Undefined sizing type: " + name); }
            string production = Text(declaration, "production");
            BigInteger width;
            if (production == "EnumU16") { width = 2; }
            else if (production == "SemanticString") { width = 4 + new BigInteger((ulong)declaration["maxBytes"]); }
            else if (production == "List" || production == "Set")
            {
                width = 4 + new BigInteger((ulong)declaration["maxCount"]) * (4 + WidthOf(Text(declaration, "elementType"), null, types, widths, profile));
            }
            else if (production == "Named")
            {
                width = BigInteger.Zero;
                foreach (Dictionary<string, object> member in EffectiveFields(declaration, profile))
                {
                    width += 6 + WidthOf(Text(member, "type"), member, types, widths, profile);
                }
            }
            else { throw new InvalidDataException("Unsupported sizing production: " + production); }
            widths.Add(name, width);
            return width;
        }

        public static byte[] Project(byte[] schemaBytes, string[] roots, byte[] mappingBytes)
        {
            Dictionary<string, object> schema = ObjectValue(Parse(schemaBytes));
            Dictionary<string, object> mappings = ObjectValue(Parse(mappingBytes));
            List<object> declarations = ArrayValue(schema, "types");
            Dictionary<string, Dictionary<string, object>> byName = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in declarations)
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                byName.Add(Text(declaration, "name"), declaration);
            }
            foreach (string root in roots)
            {
                if (!byName.ContainsKey(root)) { throw new InvalidDataException("Projection root is missing: " + root); }
            }
            HashSet<string> reached = new HashSet<string>(StringComparer.Ordinal);
            Stack<string> pending = new Stack<string>(roots);
            while (pending.Count != 0)
            {
                string name = pending.Pop();
                Dictionary<string, object> declaration;
                if (!byName.TryGetValue(name, out declaration) || !reached.Add(name)) { continue; }
                if (declaration.ContainsKey("fields"))
                {
                    foreach (object field in ArrayValue(declaration, "fields")) { pending.Push(Text(ObjectValue(field), "type")); }
                }
                if (declaration.ContainsKey("elementType")) { pending.Push(Text(declaration, "elementType")); }
                if (mappings.ContainsKey(name))
                {
                    foreach (object target in (List<object>)mappings[name]) { pending.Push((string)target); }
                }
            }
            List<object> projected = new List<object>();
            foreach (object item in declarations)
            {
                Dictionary<string, object> declaration = ObjectValue(item);
                if (!reached.Contains(Text(declaration, "name"))) { continue; }
                if (Text(declaration, "production") == "Named")
                {
                    EffectiveFields(declaration, "InteractiveSeat");
                    EffectiveFields(declaration, "NonInteractiveElevated");
                }
                declaration["typeId"] = projected.Count + 1;
                projected.Add(declaration);
            }
            schema["types"] = projected;
            return Canonical(schema);
        }

        private static void ValidateInventory(Dictionary<string, object> inventory)
        {
            object clauses;
            if (!inventory.TryGetValue("consumerContract", out clauses) || !(clauses is List<object>))
            {
                throw new InvalidDataException("Evidence ledger inventory shape differs.");
            }
            Dictionary<string, object> shape = new Dictionary<string, object>(inventory, StringComparer.Ordinal);
            shape.Remove("consumerContract");
            if (Digest(Canonical(shape)) != InventoryShapeDigest || Digest(Canonical(clauses)) != ConsumerContractDigest)
            {
                throw new InvalidDataException("Evidence ledger inventory shape differs.");
            }
        }

        private static void ValidateDocumentation(Dictionary<string, object> inventory, byte[] readmeBytes)
        {
            StringBuilder expected = new StringBuilder("## Deferred binary consumer contract\n\n");
            foreach (object clause in ArrayValue(inventory, "consumerContract")) { expected.Append("- ").Append((string)clause).Append('\n'); }
            expected.Append('\n');
            if (Utf8.GetString(readmeBytes).IndexOf(expected.ToString(), StringComparison.Ordinal) < 0)
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

        private static List<Dictionary<string, object>> EffectiveFields(Dictionary<string, object> declaration, string profile)
        {
            Dictionary<string, List<Dictionary<string, object>>> required = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
            List<Dictionary<string, object>> selected = new List<Dictionary<string, object>>();
            foreach (object item in ArrayValue(declaration, "fields"))
            {
                Dictionary<string, object> field = ObjectValue(item);
                string shape = FieldShape(field);
                if (Optional(field, "status", "Required") != "Required") { continue; }
                List<Dictionary<string, object>> group;
                if (!required.TryGetValue(shape, out group))
                {
                    group = new List<Dictionary<string, object>>();
                    required.Add(shape, group);
                }
                group.Add(field);
                string scope = Optional(field, "profile", "Any");
                if (scope == "Any" || scope == profile) { selected.Add(field); }
            }
            foreach (object item in ArrayValue(declaration, "fields"))
            {
                Dictionary<string, object> field = ObjectValue(item);
                if (Optional(field, "status", "Required") != "Forbidden") { continue; }
                List<Dictionary<string, object>> candidates;
                if (!required.TryGetValue(FieldShape(field), out candidates)) { throw new InvalidDataException("Forbidden field has no required shape."); }
                string scope = Optional(field, "profile", "Any");
                Dictionary<string, object> matched = null;
                foreach (Dictionary<string, object> candidate in candidates)
                {
                    string candidateScope = Optional(candidate, "profile", "Any");
                    if (candidateScope != "Any" && candidateScope != scope) { continue; }
                    if (matched != null) { throw new InvalidDataException("Forbidden field has multiple applicable required shapes."); }
                    matched = candidate;
                }
                if (scope == profile && matched != null) { selected.Remove(matched); }
            }
            return selected;
        }

        private static string FieldShape(Dictionary<string, object> field)
        {
            Dictionary<string, object> shape = new Dictionary<string, object>(field, StringComparer.Ordinal);
            shape.Remove("profile");
            shape.Remove("status");
            return Convert.ToBase64String(Canonical(shape));
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
            StringBuilder text = new StringBuilder();
            Encode(text, value);
            return Utf8.GetBytes(text.ToString());
        }

        private static void Encode(StringBuilder text, object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties != null)
            {
                List<string> keys = new List<string>(properties.Keys);
                keys.Sort(StringComparer.Ordinal);
                text.Append('{');
                for (int index = 0; index < keys.Count; index++)
                {
                    if (index != 0) { text.Append(','); }
                    Encode(text, keys[index]);
                    text.Append(':');
                    Encode(text, properties[keys[index]]);
                }
                text.Append('}');
            }
            else if (value is string)
            {
                text.Append('"');
                foreach (char character in (string)value)
                {
                    if (character == '"' || character == '\\') { text.Append('\\').Append(character); }
                    else if (character < 32) { text.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture)); }
                    else { text.Append(character); }
                }
                text.Append('"');
            }
            else if (value is IEnumerable)
            {
                text.Append('[');
                bool separator = false;
                foreach (object item in (IEnumerable)value)
                {
                    if (separator) { text.Append(','); }
                    Encode(text, item);
                    separator = true;
                }
                text.Append(']');
            }
            else if (value is ulong || value is int || value is uint || value is long)
            {
                text.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
            }
            else if (value is bool) { text.Append((bool)value ? "true" : "false"); }
            else if (value == null) { text.Append("null"); }
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
            if (kind == "object" || kind == "array")
            {
                Dictionary<string, object> properties = new Dictionary<string, object>(StringComparer.Ordinal);
                List<object> items = new List<object>();
                bool empty = reader.IsEmptyElement;
                reader.ReadStartElement();
                if (!empty)
                {
                    while (reader.MoveToContent() == XmlNodeType.Element)
                    {
                        string name = reader.GetAttribute("item") ?? reader.LocalName;
                        object item = ReadElement(reader);
                        if (kind == "object") { properties.Add(name, item); }
                        else { items.Add(item); }
                    }
                    reader.ReadEndElement();
                }
                return kind == "object" ? (object)properties : items;
            }
            string content = reader.ReadElementContentAsString();
            if (kind == "string") { return content; }
            if (kind == "number") { return ulong.Parse(content, CultureInfo.InvariantCulture); }
            if (kind == "boolean") { return content == "true"; }
            if (kind == "null") { return null; }
            throw new InvalidDataException("Unsupported JSON projection value.");
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
