using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Pspkt.Certification;
using Pspkt.Certification.FoundationEngine;

namespace Pspkt.Certification.Protocol
{
    public static class ProtocolSchemaAuthority
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        private static readonly HashSet<string> Primitives = new HashSet<string>(
            "U8 U16 U32 U64 I16 I32 I64 FILETIME QPC GUID Opaque16 FixedAscii8 SHA-256 Opaque32 AsciiIdentifier BinarySid Utf8Short Rsa3072PublicBlob Rsa3072Signature LUID BoundedBytes OpaqueUtf16".Split(' '),
            StringComparer.Ordinal);

        public static byte[] Filter(byte[] baseBytes, byte[] overlayBytes, string[] seedTypes, string[] seedMessages)
        {
            if (seedTypes == null) throw new ArgumentNullException("seedTypes");
            if (seedMessages == null) throw new ArgumentNullException("seedMessages");
            return Encode(FilterCatalogs(Object(Read(baseBytes)), Object(Read(overlayBytes)), seedTypes, seedMessages));
        }

        public static IDictionary<string, byte[]> Generate(byte[] baseBytes, byte[] overlayBytes,
            byte[] inventoryBytes, byte[] metaBytes, ProtocolCatalogContractV2 contract)
        {
            if (contract == null) throw new ArgumentNullException("contract");
            Dictionary<string, object> inventory = Object(Read(inventoryBytes));
            Require(Text(inventory, "schemaId") == "PspktProtocolInventoryV1" && Number(inventory, "schemaVersion") == 1,
                "Protocol inventory identity mismatch.");
            ValidateInventoryAuthority(inventory);
            Dictionary<string, object> projection = FilterCatalogs(Object(Read(baseBytes)), Object(Read(overlayBytes)),
                Strings(Array(inventory, "deferredSeedTypeNames")), Strings(Array(inventory, "deferredSeedMessageKeys")));
            Require(Equal(Encode(projection["omittedTypes"]), Encode(inventory["omittedTypeNames"])), "Protocol omission type closure mismatch.");
            Require(Equal(Encode(projection["omittedMessages"]), Encode(inventory["omittedMessageKeys"])), "Protocol omission message closure mismatch.");
            Dictionary<string, object> baseCatalog = Object(projection["base"]);
            Dictionary<string, object> overlayCatalog = Object(projection["overlay"]);
            ValidateUnionMappings(baseCatalog, inventory);
            List<object> variants = ValidateLifecycle(inventory);
            ProtocolCatalogResultV2 generated = ProtocolCatalogEngineV2.Evaluate(Encode(baseCatalog), Encode(overlayCatalog), contract);
            Require(generated.Accepted, "Protocol V2 evaluation rejected: " + generated.Reason);
            SchemaCheckResult schemaGate = SchemaBootstrap.Evaluate("schema-against-meta", generated.SchemaBytes, metaBytes);
            Require(schemaGate.Accepted, "Protocol schema rejected: " + schemaGate.Reason);
            List<object> association = Associate(baseCatalog, overlayCatalog, (List<object>)Read(generated.IdMapBytes), variants);
            Dictionary<string, object> schema = Object(Read(generated.SchemaBytes));
            Dictionary<string, Dictionary<string, object>> types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in Array(schema, "types"))
            {
                Dictionary<string, object> declaration = Object(item);
                types.Add(Text(declaration, "name"), declaration);
            }
            Dictionary<string, ulong> sizes = new Dictionary<string, ulong>(StringComparer.Ordinal);
            foreach (object item in Array(inventory, "payloadMaxima"))
            {
                Dictionary<string, object> maximum = Object(item);
                Require(Size(Text(maximum, "name"), Text(maximum, "profile"), null, types, inventory, sizes, 1) == Number(maximum, "maxPayloadBytes"),
                    "Protocol payload maximum mismatch: " + Text(maximum, "name") + "/" + Text(maximum, "profile"));
            }
            List<object> schedule = Schedule(association, variants, types, inventory, sizes);
            Dictionary<string, byte[]> outputs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            outputs.Add("protocol-schema.v1.json", generated.SchemaBytes);
            outputs.Add("generated-base-id-map.v1.json", generated.IdMapBytes);
            outputs.Add("protocol-message-association.v1.json", Encode(Row("schemaVersion", 1,
                "schemaId", "PspktProtocolMessageAssociationV1", "rows", association)));
            outputs.Add("mandatory-tail-schedule.v1.json", Encode(Row("schemaVersion", 1,
                "schemaId", "PspktMandatoryTailScheduleV1", "channel", "WorkerApp", "rows", schedule)));
            return outputs;
        }

        private static void ValidateInventoryAuthority(Dictionary<string, object> inventory)
        {
            Require(Equal(Encode(Array(inventory, "profileOrder")),
                Encode(new List<object> { "InteractiveSeat", "NonInteractiveElevated" })), "Protocol profile order mismatch.");
            Require(Equal(Encode(Array(inventory, "directionOrder")),
                Encode(new List<object> { "HostToWorker", "WorkerToHost" })), "Protocol direction order mismatch.");
            Require(Equal(Encode(Array(inventory, "excludedTailChannels")),
                Encode(new List<object> { "BrokerControl", "LocalIpc" })), "Protocol excluded tail channels mismatch.");
            Require(Equal(Encode(Array(inventory, "unassignedOverlayTypeIds")),
                Encode(new List<object> { 4872, 4873, 4875, 4876 })), "Protocol unassigned overlay type ids mismatch.");
            Dictionary<string, object> illegal = Object(inventory["reservedIllegalType"]);
            Require(Text(illegal, "name") == "LocalTranscriptRecordSetV1" && Number(illegal, "id") == 4881,
                "Protocol reserved illegal type mismatch.");
        }

        private static void ValidateUnionMappings(Dictionary<string, object> catalog, Dictionary<string, object> inventory)
        {
            List<object> mappings = Array(inventory, "unionMappings");
            int unionIndex = 0;
            HashSet<string> emitted = new HashSet<string>(StringComparer.Ordinal);
            foreach (object item in Array(catalog, "entries"))
            {
                Dictionary<string, object> entry = Object(item);
                if (Text(entry, "op") != "union") continue;
                Require(unionIndex < mappings.Count, "Missing union provenance.");
                Dictionary<string, object> mapping = Object(mappings[unionIndex++]);
                Require(Text(mapping, "union") == Text(entry, "name") && Text(mapping, "discriminator") == Text(entry, "discriminator"),
                    "Union provenance order mismatch.");
                List<object> branches = Array(entry, "branches");
                List<object> mapped = Array(mapping, "branches");
                Require(branches.Count == mapped.Count, "Union branch count mismatch.");
                for (int index = 0; index < branches.Count; index++)
                {
                    string name = Text(Object(branches[index]), "name");
                    Dictionary<string, object> branch = Object(mapped[index]);
                    Require(Number(branch, "value") == (ulong)index && Text(branch, "emittedIdentifier") == name
                        && name.Length <= 64 && emitted.Add(name), "Union emitted mapping mismatch: " + name);
                    Require(Text(branch, "semanticLabel").Length != 0, "Missing semantic union label.");
                }
            }
            Require(unionIndex == mappings.Count, "Extra union provenance.");
        }

        private static List<object> ValidateLifecycle(Dictionary<string, object> inventory)
        {
            byte[] source = Convert.FromBase64String(Text(inventory, "lifecycleSourceBase64"));
            using (SHA256 sha256 = SHA256.Create())
            {
                string digest = BitConverter.ToString(sha256.ComputeHash(source)).Replace("-", "").ToLowerInvariant();
                Require(digest == "8718dd1de27850663988c52bdd41a5ca5617c584b9a84f59e6d5a1cdfaa0d496", "Lifecycle source hash mismatch.");
            }
            Dictionary<string, object> lifecycle = Object(inventory["lifecycle"]);
            string sourceText = Utf8.GetString(source);
            int summaryStart = sourceText.LastIndexOf("\"totalStates\"", StringComparison.Ordinal);
            Require(summaryStart > 0, "Lifecycle summary boundary is missing.");
            int summarySeparator = sourceText.LastIndexOf(',', summaryStart);
            Require(summarySeparator > 0, "Lifecycle summary separator is missing.");
            byte[] lifecycleProjection = Utf8.GetBytes(sourceText.Substring(0, summarySeparator) + "}");
            Require(Equal(Encode(lifecycle), Encode(Read(lifecycleProjection))), "Lifecycle source projection mismatch.");
            List<object> variants = Array(lifecycle, "variants");
            List<object> order = Array(lifecycle, "variantOrder");
            Require(variants.Count == 6 && order.Count == 6, "Lifecycle variant count mismatch.");
            int states = 0;
            for (int index = 0; index < variants.Count; index++)
            {
                Dictionary<string, object> variant = Object(variants[index]);
                Require(Text(variant, "name") == (string)order[index], "Lifecycle variant order mismatch.");
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                foreach (object state in Array(variant, "states")) Require(names.Add((string)state), "Duplicate lifecycle state.");
                states = checked(states + names.Count);
            }
            Require(states == 421, "Lifecycle state count mismatch.");
            return variants;
        }

        private static List<object> Associate(Dictionary<string, object> baseCatalog, Dictionary<string, object> overlayCatalog,
            List<object> map, List<object> variants)
        {
            Dictionary<string, Dictionary<string, object>> kinds = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in map)
            {
                Dictionary<string, object> row = Object(item);
                if (Text(row, "category") != "kind") continue;
                string key = Text(row, "catalog") + ":" + Number(row, "catalogOrdinal").ToString(CultureInfo.InvariantCulture);
                Require(!kinds.ContainsKey(key), "Duplicate kind association join: " + key);
                kinds.Add(key, row);
            }
            List<object> rows = new List<object>();
            Dictionary<string, object>[] catalogs = new Dictionary<string, object>[] { baseCatalog, overlayCatalog };
            for (int catalogIndex = 0; catalogIndex < catalogs.Length; catalogIndex++)
            {
                List<object> entries = Array(catalogs[catalogIndex], "entries");
                for (int index = 0; index < entries.Count; index++)
                {
                    Dictionary<string, object> entry = Object(entries[index]);
                    if (!IsMessage(Text(entry, "op"))) continue;
                    string key = (catalogIndex == 0 ? "base:" : "overlay:") + (index + 1).ToString(CultureInfo.InvariantCulture);
                    Dictionary<string, object> kind;
                    Require(kinds.TryGetValue(key, out kind), "Missing kind association join: " + key);
                    foreach (string property in new string[] { "channel", "direction", "profile", "mandatoryTailClass", "name", "stateAssoc" })
                    {
                        Require(Text(entry, property) == Text(kind, property), "Kind association metadata mismatch: " + key + "/" + property);
                    }
                    if (Text(entry, "op") == "overlay-message") Require(Number(entry, "id") == Number(kind, "generatedId"), "Literal kind join mismatch.");
                    string profile = Text(entry, "profile");
                    string state = Text(entry, "stateAssoc");
                    foreach (object variantItem in variants)
                    {
                        Dictionary<string, object> variant = Object(variantItem);
                        if (profile != "Any" && profile != Text(variant, "profile")) continue;
                        Require(state == "None" || Array(variant, "states").Contains(state), "Unknown lifecycle association: " + key + "/" + state);
                    }
                    rows.Add(Row("channel", Text(entry, "channel"), "direction", Text(entry, "direction"),
                        "kindId", Number(kind, "generatedId"), "mandatoryTailClass", Text(entry, "mandatoryTailClass"),
                        "name", Text(entry, "name"), "payloadRoot", Text(entry, "payloadRoot"), "profile", profile, "stateAssoc", state));
                }
            }
            Require(rows.Count == kinds.Count, "Unmatched or non-message kind association row.");
            return rows;
        }

        private static List<object> Schedule(List<object> association, List<object> variants,
            Dictionary<string, Dictionary<string, object>> types, Dictionary<string, object> inventory, Dictionary<string, ulong> sizes)
        {
            Require(Number(inventory, "mandatoryCardinality") == 1, "Mandatory cardinality mismatch.");
            List<object> rows = new List<object>();
            foreach (object variantItem in variants)
            {
                Dictionary<string, object> variant = Object(variantItem);
                string profile = Text(variant, "profile");
                List<object> states = Array(variant, "states");
                for (int stateIndex = 0; stateIndex < states.Count; stateIndex++)
                {
                    foreach (string direction in new string[] { "HostToWorker", "WorkerToHost" })
                    {
                        List<object> kinds = new List<object>();
                        ulong charge = 0;
                        foreach (object associationItem in association)
                        {
                            Dictionary<string, object> message = Object(associationItem);
                            if (Text(message, "channel") != "WorkerApp" || Text(message, "direction") != direction
                                || Text(message, "mandatoryTailClass") != "Mandatory") continue;
                            if (Text(message, "profile") != "Any" && Text(message, "profile") != profile) continue;
                            Require(Text(message, "name") != "Keepalive", "Keepalive cannot be mandatory.");
                            int associatedIndex = states.IndexOf(Text(message, "stateAssoc"));
                            Require(associatedIndex >= 0, "Mandatory WorkerApp state is missing.");
                            if (associatedIndex < stateIndex) continue;
                            ulong payload = Size(Text(message, "payloadRoot"), profile, null, types, inventory, sizes, 1);
                            ulong frame = checked(24UL + payload + 384UL);
                            ulong transcript = checked(13UL + frame);
                            charge = checked(charge + transcript);
                            kinds.Add(Row("cardinality", 1, "kindId", Number(message, "kindId"), "maxPayloadBytes", payload,
                                "maxSignedFrameBytes", frame, "name", Text(message, "name"), "transcriptChargeBytes", transcript));
                        }
                        Require((ulong)kinds.Count <= Number(inventory, "maximumTailRecords")
                            && charge <= Number(inventory, "maximumTailWrapperBytes"), "Mandatory tail quota exceeded.");
                        rows.Add(Row("direction", direction, "kinds", kinds, "lifecycleVariant", Text(variant, "name"),
                            "profile", profile, "records", kinds.Count, "state", (string)states[stateIndex], "wrapperBytes", charge));
                    }
                }
            }
            Require(rows.Count == 842, "Mandatory tail row count mismatch.");
            return rows;
        }

        private static ulong Size(string name, string profile, Dictionary<string, object> field,
            Dictionary<string, Dictionary<string, object>> types, Dictionary<string, object> inventory,
            Dictionary<string, ulong> sizes, int depth)
        {
            if (name == "BoundedBytes") return checked(4UL + Number(field, "maxBytes"));
            Dictionary<string, object> primitiveMaxima = Object(inventory["primitiveValueMaxima"]);
            if (primitiveMaxima.ContainsKey(name)) return Number(primitiveMaxima, name);
            Require((ulong)depth <= Number(inventory, "maximumNamedDepth"), "WorkerApp sizing depth exceeded: " + name);
            string key = name + ":" + profile + ":" + depth.ToString(CultureInfo.InvariantCulture);
            ulong cached;
            if (sizes.TryGetValue(key, out cached)) return cached;
            Dictionary<string, object> declaration;
            Require(types.TryGetValue(name, out declaration), "Undefined sizable type: " + name);
            string production = Text(declaration, "production");
            ulong result = 0;
            if (production == "EnumU16") result = 2;
            else if (production == "SemanticString") result = checked(4UL + Number(declaration, "maxBytes"));
            else if (production == "List" || production == "Set")
            {
                result = checked(4UL + Number(declaration, "maxCount") * checked(4UL +
                    Size(Text(declaration, "elementType"), profile, null, types, inventory, sizes, depth + 1)));
            }
            else
            {
                Require(production == "Named", "Unsupported sizing production: " + production);
                List<Dictionary<string, object>> effective = new List<Dictionary<string, object>>();
                List<object> fields = Array(declaration, "fields");
                foreach (object item in fields)
                {
                    Dictionary<string, object> candidate = Object(item);
                    FieldShape(candidate);
                    string scope = OptionalText(candidate, "profile", "Any");
                    if (OptionalText(candidate, "status", "Required") == "Required" && (scope == "Any" || scope == profile)) effective.Add(candidate);
                }
                foreach (object item in fields)
                {
                    Dictionary<string, object> forbidden = Object(item);
                    if (OptionalText(forbidden, "status", "Required") != "Forbidden" || OptionalText(forbidden, "profile", "Any") != profile) continue;
                    string forbiddenShape = FieldShape(forbidden);
                    List<Dictionary<string, object>> matches = new List<Dictionary<string, object>>();
                    foreach (object candidateItem in fields)
                    {
                        Dictionary<string, object> candidate = Object(candidateItem);
                        if (OptionalText(candidate, "status", "Required") == "Required"
                            && FieldShape(candidate) == forbiddenShape) matches.Add(candidate);
                    }
                    Require(matches.Count > 0, "Forbidden field has no required shape.");
                    Dictionary<string, object> applicable = null;
                    foreach (Dictionary<string, object> candidate in matches)
                    {
                        string candidateProfile = OptionalText(candidate, "profile", "Any");
                        if (candidateProfile != "Any" && candidateProfile != profile) continue;
                        Require(applicable == null, "Forbidden field has multiple applicable required shapes.");
                        applicable = candidate;
                    }
                    if (applicable != null) effective.Remove(applicable);
                }
                foreach (Dictionary<string, object> candidate in effective)
                {
                    result = checked(result + 6UL + Size(Text(candidate, "type"), profile, candidate, types, inventory, sizes, depth + 1));
                }
            }
            sizes.Add(key, result);
            return result;
        }

        private static string FieldShape(Dictionary<string, object> field)
        {
            string type = Text(field, "type");
            int boundKind = type == "BoundedBytes" ? 1 : type == "OpaqueUtf16" ? 2 : 0;
            ulong bound = 0;
            if (boundKind == 1)
            {
                Require(field.ContainsKey("maxBytes") && !field.ContainsKey("maxCodeUnits"), "Invalid conditional field bound.");
                bound = Number(field, "maxBytes");
            }
            else if (boundKind == 2)
            {
                Require(field.ContainsKey("maxCodeUnits") && !field.ContainsKey("maxBytes"), "Invalid conditional field bound.");
                bound = Number(field, "maxCodeUnits");
            }
            else Require(!field.ContainsKey("maxBytes") && !field.ContainsKey("maxCodeUnits"), "Invalid conditional field bound.");
            return Number(field, "fieldId").ToString(CultureInfo.InvariantCulture) + "\u001F" + Text(field, "name")
                + "\u001F" + type + "\u001F" + boundKind.ToString(CultureInfo.InvariantCulture)
                + "\u001F" + bound.ToString(CultureInfo.InvariantCulture);
        }

        private static ulong Number(Dictionary<string, object> value, string key)
        {
            object item = null;
            Require(value != null && value.TryGetValue(key, out item), "Missing projection number: " + key);
            Require(item is ulong || item is int || item is long, "Invalid projection number: " + key);
            return Convert.ToUInt64(item, CultureInfo.InvariantCulture);
        }

        private static string OptionalText(Dictionary<string, object> value, string key, string absent)
        {
            return value.ContainsKey(key) ? Text(value, key) : absent;
        }

        private static string[] Strings(List<object> values)
        {
            string[] result = new string[values.Count];
            for (int index = 0; index < values.Count; index++) result[index] = (string)values[index];
            return result;
        }

        private static bool Equal(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            for (int index = 0; index < left.Length; index++) if (left[index] != right[index]) return false;
            return true;
        }

        private static Dictionary<string, object> FilterCatalogs(
            Dictionary<string, object> baseCatalog, Dictionary<string, object> overlayCatalog,
            string[] seedTypes, string[] seedMessages)
        {
            Dictionary<string, HashSet<string>> reverse = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            List<Dictionary<string, object>> catalogs = new List<Dictionary<string, object>> { baseCatalog, overlayCatalog };
            foreach (Dictionary<string, object> catalog in catalogs)
            {
                foreach (object item in Array(catalog, "entries"))
                {
                    Dictionary<string, object> entry = Object(item);
                    string operation = Text(entry, "op");
                    if (IsChild(operation))
                    {
                        foreach (Dictionary<string, object> field in Fields(entry))
                        {
                            AddReverse(reverse, Text(field, "type"), Text(entry, "parent"));
                        }
                    }
                    else if (operation == "type" || operation == "overlay-type")
                    {
                        string production = Text(entry, "production");
                        if (production == "List" || production == "Set")
                        {
                            AddReverse(reverse, Text(entry, "elementType"), Text(entry, "name"));
                        }
                    }
                    else if (operation == "union")
                    {
                        List<string> owners = DeclaredNames(entry);
                        string discriminator = Text(entry, "discriminator");
                        foreach (string owner in owners)
                        {
                            AddReverse(reverse, owner, discriminator);
                            AddReverse(reverse, discriminator, owner);
                        }
                        foreach (object branchItem in Array(entry, "branches"))
                        {
                            Dictionary<string, object> branch = Object(branchItem);
                            foreach (object fieldItem in Array(branch, "fields"))
                            {
                                AddReverse(reverse, Text(Object(fieldItem), "type"), Text(branch, "name"));
                            }
                        }
                    }
                }
            }
            HashSet<string> omittedTypes = new HashSet<string>(seedTypes, StringComparer.Ordinal);
            Queue<string> pending = new Queue<string>(seedTypes);
            while (pending.Count != 0)
            {
                HashSet<string> dependents;
                if (!reverse.TryGetValue(pending.Dequeue(), out dependents)) continue;
                foreach (string dependent in dependents)
                {
                    if (omittedTypes.Add(dependent)) pending.Enqueue(dependent);
                }
            }
            HashSet<string> omittedMessages = new HashSet<string>(seedMessages, StringComparer.Ordinal);
            foreach (Dictionary<string, object> catalog in catalogs)
            {
                foreach (object item in Array(catalog, "entries"))
                {
                    Dictionary<string, object> entry = Object(item);
                    if (IsMessage(Text(entry, "op")) && omittedTypes.Contains(Text(entry, "payloadRoot")))
                    {
                        omittedMessages.Add(Text(entry, "channel") + ":" + Text(entry, "name"));
                    }
                }
            }
            List<object> removed = new List<object>();
            for (int catalogIndex = 0; catalogIndex < catalogs.Count; catalogIndex++)
            {
                Dictionary<string, object> catalog = catalogs[catalogIndex];
                List<object> entries = Array(catalog, "entries");
                List<object> retained = new List<object>();
                for (int index = 0; index < entries.Count; index++)
                {
                    Dictionary<string, object> entry = Object(entries[index]);
                    string operation = Text(entry, "op");
                    bool omit;
                    if (IsChild(operation)) omit = omittedTypes.Contains(Text(entry, "parent"));
                    else if (IsMessage(operation)) omit = omittedMessages.Contains(Text(entry, "channel") + ":" + Text(entry, "name"));
                    else if (operation == "union") omit = DeclaredNames(entry).Exists(omittedTypes.Contains);
                    else omit = omittedTypes.Contains(Text(entry, "name"));
                    if (omit)
                    {
                        removed.Add(Row("catalog", catalogIndex == 0 ? "base" : "overlay",
                            "catalogOrdinal", index + 1, "category", operation));
                    }
                    else retained.Add(entry);
                }
                catalog["entries"] = retained;
            }
            ValidateReferences(catalogs);
            return Row("base", baseCatalog, "overlay", overlayCatalog, "omittedTypes", Sorted(omittedTypes),
                "omittedMessages", Sorted(omittedMessages), "removedOperations", removed,
                "filteredBaseSha256", Digest(Encode(baseCatalog)), "filteredOverlaySha256", Digest(Encode(overlayCatalog)),
                "removedOperationsSha256", Digest(Encode(removed)), "survivingBaseCount", Array(baseCatalog, "entries").Count,
                "survivingOverlayCount", Array(overlayCatalog, "entries").Count);
        }

        private static void ValidateReferences(List<Dictionary<string, object>> catalogs)
        {
            HashSet<string> declarations = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> deleted = new HashSet<string>(StringComparer.Ordinal);
            foreach (Dictionary<string, object> catalog in catalogs)
            {
                foreach (object item in Array(catalog, "entries"))
                {
                    Dictionary<string, object> entry = Object(item);
                    foreach (string name in DeclaredNames(entry))
                    {
                        Require(declarations.Add(name), "Duplicate retained declaration: " + name);
                    }
                    if (Text(entry, "op") == "delete") deleted.Add(Text(entry, "name"));
                }
            }
            declarations.ExceptWith(deleted);
            foreach (Dictionary<string, object> catalog in catalogs)
            {
                foreach (object item in Array(catalog, "entries"))
                {
                    Dictionary<string, object> entry = Object(item);
                    string operation = Text(entry, "op");
                    if (IsChild(operation))
                    {
                        Require(declarations.Contains(Text(entry, "parent")), "Undefined retained parent: " + Text(entry, "parent"));
                        foreach (Dictionary<string, object> field in Fields(entry)) RequireReference(declarations, Text(field, "type"));
                    }
                    if (IsMessage(operation)) RequireReference(declarations, Text(entry, "payloadRoot"));
                    if (entry.ContainsKey("elementType")) RequireReference(declarations, Text(entry, "elementType"));
                    if (operation == "union")
                    {
                        foreach (object branch in Array(entry, "branches"))
                        {
                            foreach (object field in Array(Object(branch), "fields")) RequireReference(declarations, Text(Object(field), "type"));
                        }
                    }
                }
            }
        }

        private static void RequireReference(HashSet<string> declarations, string name)
        {
            Require(declarations.Contains(name) || Primitives.Contains(name), "Undefined retained reference: " + name);
        }

        private static List<string> DeclaredNames(Dictionary<string, object> entry)
        {
            string operation = Text(entry, "op");
            List<string> names = new List<string>();
            if (operation == "type" || operation == "overlay-type" || operation == "enum") names.Add(Text(entry, "name"));
            if (operation == "union")
            {
                names.Add(Text(entry, "discriminator"));
                foreach (object branch in Array(entry, "branches")) names.Add(Text(Object(branch), "name"));
            }
            return names;
        }

        private static IEnumerable<Dictionary<string, object>> Fields(Dictionary<string, object> entry)
        {
            string operation = Text(entry, "op");
            if (operation == "field") yield return entry;
            else
            {
                foreach (object item in Array(entry, operation == "field-set" ? "variants" : "fields")) yield return Object(item);
            }
        }

        private static bool IsChild(string operation)
        {
            return operation == "field" || operation == "field-set" || operation == "extend" || operation == "overlay-field";
        }

        private static bool IsMessage(string operation)
        {
            return operation == "message" || operation == "overlay-message";
        }

        private static void AddReverse(Dictionary<string, HashSet<string>> reverse, string dependency, string owner)
        {
            if (Primitives.Contains(dependency)) return;
            HashSet<string> owners;
            if (!reverse.TryGetValue(dependency, out owners))
            {
                owners = new HashSet<string>(StringComparer.Ordinal);
                reverse.Add(dependency, owners);
            }
            owners.Add(owner);
        }

        private static string[] Sorted(HashSet<string> values)
        {
            string[] result = new string[values.Count];
            values.CopyTo(result);
            System.Array.Sort(result, StringComparer.Ordinal);
            return result;
        }

        private static Dictionary<string, object> Row(params object[] pairs)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
            for (int index = 0; index < pairs.Length; index += 2) result.Add((string)pairs[index], pairs[index + 1]);
            return result;
        }

        private static Dictionary<string, object> Object(object value)
        {
            Dictionary<string, object> result = value as Dictionary<string, object>;
            Require(result != null, "Expected a protocol projection object.");
            return result;
        }

        private static List<object> Array(Dictionary<string, object> value, string key)
        {
            object item;
            Require(value.TryGetValue(key, out item), "Missing projection array: " + key);
            List<object> result = item as List<object>;
            Require(result != null, "Invalid projection array: " + key);
            return result;
        }

        private static string Text(Dictionary<string, object> value, string key)
        {
            object item;
            Require(value.TryGetValue(key, out item) && item is string, "Invalid projection string: " + key);
            return (string)item;
        }

        private static void Require(bool condition, string message)
        {
            if (!condition) throw new InvalidDataException(message);
        }

        private static object Read(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            bytes = (byte[])bytes.Clone();
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("json", bytes, null);
            Require(gate.Accepted, "Protocol JSON rejected: " + gate.Reason);
            return new ProjectionReader(Utf8.GetString(bytes)).ReadDocument();
        }

        private static string Digest(byte[] bytes)
        {
            using (SHA256 hash = SHA256.Create())
            {
                return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }

        private static byte[] Encode(object value)
        {
            StringBuilder output = new StringBuilder();
            Write(output, value);
            return Utf8.GetBytes(output.ToString());
        }

        private static void Write(StringBuilder output, object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties != null)
            {
                List<string> keys = new List<string>(properties.Keys);
                keys.Sort(StringComparer.Ordinal);
                output.Append('{');
                for (int index = 0; index < keys.Count; index++)
                {
                    if (index != 0) output.Append(',');
                    Write(output, keys[index]);
                    output.Append(':');
                    Write(output, properties[keys[index]]);
                }
                output.Append('}');
            }
            else if (value is string)
            {
                output.Append('"');
                foreach (char character in (string)value)
                {
                    if (character == '"' || character == '\\') output.Append('\\').Append(character);
                    else if (character < 32) output.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    else output.Append(character);
                }
                output.Append('"');
            }
            else if (value is IEnumerable)
            {
                output.Append('[');
                bool first = true;
                foreach (object item in (IEnumerable)value)
                {
                    if (!first) output.Append(',');
                    first = false;
                    Write(output, item);
                }
                output.Append(']');
            }
            else if (value is ulong || value is int || value is long)
            {
                output.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
            }
            else if (value is bool) output.Append((bool)value ? "true" : "false");
            else if (value == null) output.Append("null");
            else throw new InvalidDataException("Unsupported canonical projection value.");
        }

        private sealed class ProjectionReader
        {
            private readonly string _text;
            private int _position;

            internal ProjectionReader(string text) { _text = text; }

            internal object ReadDocument()
            {
                object result = ReadValue(0);
                SkipWhitespace();
                Require(_position == _text.Length, "Projection trailing data.");
                return result;
            }

            private object ReadValue(int depth)
            {
                Require(depth <= 32, "Projection depth limit.");
                SkipWhitespace();
                char token = _text[_position++];
                if (token == '"') return ReadString();
                if (token == '{' || token == '[')
                {
                    Dictionary<string, object> properties = new Dictionary<string, object>(StringComparer.Ordinal);
                    List<object> items = new List<object>();
                    SkipWhitespace();
                    char end = token == '{' ? '}' : ']';
                    while (_text[_position] != end)
                    {
                        if (token == '{')
                        {
                            Require(_text[_position++] == '"', "Projection property name.");
                            string name = ReadString();
                            SkipWhitespace();
                            Require(_text[_position++] == ':', "Projection property separator.");
                            properties.Add(name, ReadValue(depth + 1));
                            Require(properties.Count <= 4096, "Projection property limit.");
                        }
                        else
                        {
                            items.Add(ReadValue(depth + 1));
                            Require(items.Count <= 8192, "Projection array limit.");
                        }
                        SkipWhitespace();
                        if (_text[_position] == end) break;
                        Require(_text[_position++] == ',', "Projection item separator.");
                        SkipWhitespace();
                    }
                    _position++;
                    return token == '{' ? (object)properties : items;
                }
                _position--;
                int start = _position;
                while (_position < _text.Length && _text[_position] >= '0' && _text[_position] <= '9') _position++;
                if (_position != start) return ulong.Parse(_text.Substring(start, _position - start), CultureInfo.InvariantCulture);
                foreach (string literal in new string[] { "true", "false", "null" })
                {
                    if (string.CompareOrdinal(_text, _position, literal, 0, literal.Length) != 0) continue;
                    _position += literal.Length;
                    return literal == "null" ? null : (object)(literal == "true");
                }
                throw new InvalidDataException("Unsupported projection token.");
            }

            private string ReadString()
            {
                StringBuilder value = new StringBuilder();
                while (_text[_position] != '"')
                {
                    char character = _text[_position++];
                    if (character == '\\')
                    {
                        char escaped = _text[_position++];
                        if (escaped == 'u')
                        {
                            character = (char)int.Parse(_text.Substring(_position, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                            _position += 4;
                        }
                        else
                        {
                            string escapes = "\"\\/bfnrt";
                            string decoded = "\"\\/\b\f\n\r\t";
                            int index = escapes.IndexOf(escaped);
                            Require(index >= 0, "Projection escape.");
                            character = decoded[index];
                        }
                    }
                    value.Append(character);
                }
                _position++;
                string result = value.ToString();
                Require(Utf8.GetByteCount(result) <= 262144, "Projection string limit.");
                return result;
            }

            private void SkipWhitespace()
            {
                while (_position < _text.Length && char.IsWhiteSpace(_text[_position])) _position++;
            }
        }
    }
}
