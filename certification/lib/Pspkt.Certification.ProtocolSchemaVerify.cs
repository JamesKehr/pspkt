using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Pspkt.Certification.Protocol
{
    public static class ProtocolSchemaVerify
    {
        private static readonly UTF8Encoding Encoding = new UTF8Encoding(false, true);
        private static readonly string[] Channels = { "WorkerApp", "BrokerControl", "LocalIpc" };
        private static readonly string[] SeedTypes = { "MintAttestedV1", "S4UMintSlotV1", "ServiceControlEventNodeProofV1" };
        private static readonly string[] OmittedTypes = { "IsolationAdmission", "IsolationExit", "MintAttestedV1", "S4UMintSlotV1", "ServiceControlEventNodeProofV1" };
        private static readonly string[] OmittedMessages = { "BrokerControl:IsolationAdmission", "BrokerControl:IsolationExit", "BrokerControl:MintAttested", "BrokerControl:MintRevoked" };
        private static readonly string[] SourceNames = {
            "dependency1bb-protocol-authority-plan-r10.json", "dependency1bb-r9-normative-tables.txt",
            "dependency1bb-r8-lifecycle-variants.json", "dependency1b-schema-authority-plan.md",
            "phase4-r6-final-design.md", "phase4-credential-free-design-delta.md"
        };
        private static readonly Dictionary<string, ulong> Widths = new Dictionary<string, ulong>(StringComparer.Ordinal)
        {
            { "U8", 1 }, { "U16", 2 }, { "U32", 4 }, { "U64", 8 }, { "FILETIME", 8 }, { "QPC", 8 },
            { "GUID", 16 }, { "Opaque16", 16 }, { "FixedAscii8", 8 }, { "SHA-256", 32 }, { "Opaque32", 32 },
            { "AsciiIdentifier", 128 }, { "BinarySid", 68 }, { "Utf8Short", 256 },
            { "Rsa3072PublicBlob", 512 }, { "Rsa3072Signature", 384 }, { "LUID", 8 }
        };

        public static void Verify(byte[] baseBytes, byte[] overlayBytes, byte[] inventoryBytes, byte[] metaBytes,
            IDictionary<string, byte[]> outputs, IDictionary<string, string> pins, string[] literalParents,
            string bootstrapAssemblyIdentity, string[] forbiddenAssemblyNames)
        {
            if (outputs == null) throw new ArgumentNullException("outputs");
            if (pins == null) throw new ArgumentNullException("pins");
            if (literalParents == null) throw new ArgumentNullException("literalParents");
            if (bootstrapAssemblyIdentity == null) throw new ArgumentNullException("bootstrapAssemblyIdentity");
            if (forbiddenAssemblyNames == null) throw new ArgumentNullException("forbiddenAssemblyNames");
            Check(bootstrapAssemblyIdentity.Length != 0, "Bootstrap assembly identity differs.");
            Check(forbiddenAssemblyNames.Length == 2
                && !string.IsNullOrEmpty(forbiddenAssemblyNames[0])
                && !string.IsNullOrEmpty(forbiddenAssemblyNames[1])
                && !string.Equals(forbiddenAssemblyNames[0], forbiddenAssemblyNames[1], StringComparison.Ordinal),
                "Forbidden assembly identity set differs.");
            Assembly assembly = typeof(ProtocolSchemaVerify).Assembly;
            foreach (AssemblyName reference in assembly.GetReferencedAssemblies())
            {
                foreach (string forbiddenAssemblyName in forbiddenAssemblyNames)
                {
                    Check(!string.Equals(reference.Name, forbiddenAssemblyName, StringComparison.Ordinal),
                        "Verifier dependency matches forbidden assembly identity.");
                }
                byte[] publicKeyToken = reference.GetPublicKeyToken();
                Check((publicKeyToken != null && publicKeyToken.Length != 0)
                    || string.Equals(reference.FullName, bootstrapAssemblyIdentity, StringComparison.Ordinal),
                    "Verifier dependency is not allowed.");
                Check(reference.Name.IndexOf("Engine", StringComparison.Ordinal) < 0
                    && reference.Name.IndexOf("Authority", StringComparison.Ordinal) < 0, "Verifier dependency is not independent.");
            }
            foreach (Type type in assembly.GetTypes())
            {
                Check(type.FullName.IndexOf("Engine", StringComparison.Ordinal) < 0
                    && type.FullName.IndexOf("Authority", StringComparison.Ordinal) < 0, "Verifier contains a forbidden type.");
            }
            CheckHash(baseBytes, pins, "protocol-base.catalog.v1.json");
            CheckHash(overlayBytes, pins, "overlay.catalog.v1.json");
            CheckHash(inventoryBytes, pins, "protocol-inventory.v1.json");
            Check(outputs.Count == 4, "Output set differs.");
            foreach (string name in new string[] { "protocol-schema.v1.json", "generated-base-id-map.v1.json",
                "protocol-message-association.v1.json", "mandatory-tail-schedule.v1.json" })
            {
                Check(outputs.ContainsKey(name), "Missing output: " + name);
                CheckHash(outputs[name], pins, name);
                CheckBytes(outputs[name], Canonical(Extract(outputs[name])), "Noncanonical output: " + name);
            }
            Dictionary<string, object> inventory = Dictionary(Extract(inventoryBytes));
            Check(String(inventory, "schemaId") == "PspktProtocolInventoryV1" && Integer(inventory, "schemaVersion") == 1,
                "Inventory identity differs.");
            ValidateInventoryAuthority(inventory);
            Dictionary<string, object> provenance = Dictionary(inventory["sourceHashes"]);
            HashSet<string> provenanceNames = new HashSet<string>(provenance.Keys, StringComparer.Ordinal);
            Check(provenanceNames.SetEquals(SourceNames), "Inventory source provenance differs.");
            foreach (string source in SourceNames)
            {
                string expected;
                Check(pins.TryGetValue(source, out expected) && String(provenance, source) == expected, "Inventory source provenance differs: " + source);
            }
            Dictionary<string, object>[] catalogs = {
                Dictionary(Extract(baseBytes)), Dictionary(Extract(overlayBytes))
            };
            CheckCatalogIdentity(catalogs[0], "PspktProtocolBaseCatalogV1", "protocol-base");
            CheckCatalogIdentity(catalogs[1], "PspktProtocolOverlayCatalogV1", "protocol-overlay");
            RemoveDeferred(catalogs, pins);
            Pspkt.Certification.SchemaCheckResult schemaGate = Pspkt.Certification.SchemaBootstrap.Evaluate(
                "schema-against-meta", outputs["protocol-schema.v1.json"], metaBytes);
            Check(schemaGate.Accepted, "Schema-against-meta failed: " + schemaGate.Reason);
            Dictionary<string, object> schema = Dictionary(Extract(outputs["protocol-schema.v1.json"]));
            Check(String(schema, "schemaId") == "PspktProtocolSchemaV1" && Integer(schema, "schemaVersion") == 1, "Schema identity differs.");
            ValidateConditionalFields(schema);
            ProjectionCheck projection = new ProjectionCheck(List(schema, "types"),
                (List<object>)Extract(outputs["generated-base-id-map.v1.json"]), literalParents);
            projection.CheckCatalogs(catalogs);
            Check(projection.TypeCount == 107 && projection.MapCount == 681, "Declaration or map cardinality differs.");
            List<object> orderedNames = new List<object>();
            foreach (object declaration in List(schema, "types")) orderedNames.Add(String(Dictionary(declaration), "name"));
            CheckHash(Canonical(orderedNames), pins, "retained-type-order");
            CheckBytes(Canonical(Record("rows", projection.Associations, "schemaId", "PspktProtocolMessageAssociationV1", "schemaVersion", 1)),
                outputs["protocol-message-association.v1.json"], "Association equality or order differs.");
            VerifyUnionProvenance(catalogs[0], inventory, pins);
            List<object> variants = VerifyLifecycle(inventory);
            VerifyStates(projection.Associations, variants);
            Dictionary<string, Dictionary<string, ulong>> profileSizes = new Dictionary<string, Dictionary<string, ulong>>(StringComparer.Ordinal);
            foreach (string profile in new string[] { "InteractiveSeat", "NonInteractiveElevated" })
            {
                profileSizes.Add(profile, CalculateWidths(projection.Types, projection.Associations, profile));
            }
            Check(profileSizes["InteractiveSeat"]["WorkerSessionKeyCertificateV1"] == 1431
                && profileSizes["NonInteractiveElevated"]["WorkerSessionKeyCertificateV1"] == 1529
                && profileSizes["InteractiveSeat"]["BootstrapWorkerContext"] == 1958
                && profileSizes["NonInteractiveElevated"]["BootstrapWorkerContext"] == 2078, "Certificate or context maximum differs.");
            List<object> schedule = BuildReverseSchedule(projection.Associations, variants, profileSizes);
            Check(schedule.Count == 842, "Schedule cardinality differs.");
            CheckBytes(Canonical(Record("channel", "WorkerApp", "rows", schedule, "schemaId", "PspktMandatoryTailScheduleV1", "schemaVersion", 1)),
                outputs["mandatory-tail-schedule.v1.json"], "Mandatory tail equality or order differs.");
        }

        private static void CheckCatalogIdentity(Dictionary<string, object> catalog, string identity, string space)
        {
            Check(catalog.Count == 4 && String(catalog, "schemaId") == identity && String(catalog, "space") == space
                && Integer(catalog, "schemaVersion") == 1, "Catalog identity differs.");
            List(catalog, "entries");
        }

        private static void RemoveDeferred(Dictionary<string, object>[] catalogs, IDictionary<string, string> pins)
        {
            HashSet<string> omitted = new HashSet<string>(SeedTypes, StringComparer.Ordinal);
            bool changed;
            do
            {
                changed = false;
                foreach (Dictionary<string, object> catalog in catalogs)
                {
                    foreach (object item in List(catalog, "entries"))
                    {
                        Dictionary<string, object> entry = Dictionary(item);
                        string operation = String(entry, "op");
                        if (operation == "field" || operation == "field-set" || operation == "extend" || operation == "overlay-field")
                        {
                            if (omitted.Contains(String(entry, "parent"))) continue;
                            foreach (object field in SourceFields(entry))
                            {
                                if (omitted.Contains(String(Dictionary(field), "type"))) changed |= omitted.Add(String(entry, "parent"));
                            }
                        }
                        else if ((operation == "type" || operation == "overlay-type") && entry.ContainsKey("elementType"))
                        {
                            if (omitted.Contains(String(entry, "elementType"))) changed |= omitted.Add(String(entry, "name"));
                        }
                        else if (operation == "union")
                        {
                            bool omitUnion = omitted.Contains(String(entry, "discriminator"));
                            foreach (object branchItem in List(entry, "branches"))
                            {
                                Dictionary<string, object> branch = Dictionary(branchItem);
                                omitUnion |= omitted.Contains(String(branch, "name"));
                                foreach (object field in List(branch, "fields")) omitUnion |= omitted.Contains(String(Dictionary(field), "type"));
                            }
                            if (!omitUnion) continue;
                            changed |= omitted.Add(String(entry, "discriminator"));
                            foreach (object branch in List(entry, "branches")) changed |= omitted.Add(String(Dictionary(branch), "name"));
                        }
                    }
                }
            } while (changed);
            Check(omitted.SetEquals(OmittedTypes), "Independent omission closure differs.");
            HashSet<string> messages = new HashSet<string>(StringComparer.Ordinal) { "BrokerControl:MintRevoked" };
            List<object> removed = new List<object>();
            for (int catalogIndex = 0; catalogIndex < catalogs.Length; catalogIndex++)
            {
                List<object> original = List(catalogs[catalogIndex], "entries");
                List<object> surviving = new List<object>();
                for (int index = 0; index < original.Count; index++)
                {
                    Dictionary<string, object> entry = Dictionary(original[index]);
                    string operation = String(entry, "op");
                    bool remove = false;
                    if (operation == "message" || operation == "overlay-message")
                    {
                        string identity = String(entry, "channel") + ":" + String(entry, "name");
                        if (omitted.Contains(String(entry, "payloadRoot"))) messages.Add(identity);
                        remove = messages.Contains(identity);
                    }
                    else if (entry.ContainsKey("parent")) remove = omitted.Contains(String(entry, "parent"));
                    else if (operation == "union") remove = omitted.Contains(String(entry, "discriminator"));
                    else remove = omitted.Contains(String(entry, "name"));
                    if (remove) removed.Add(Record("catalog", catalogIndex == 0 ? "base" : "overlay", "catalogOrdinal", index + 1, "category", operation));
                    else surviving.Add(entry);
                }
                catalogs[catalogIndex]["entries"] = surviving;
            }
            Check(messages.SetEquals(OmittedMessages) && removed.Count == 91, "Independent message omission set differs.");
            Check(List(catalogs[0], "entries").Count == 296 && List(catalogs[1], "entries").Count == 355, "Filtered operation counts differ.");
            CheckHash(Canonical(catalogs[0]), pins, "filtered-base");
            CheckHash(Canonical(catalogs[1]), pins, "filtered-overlay");
            CheckHash(Canonical(removed), pins, "removed-operations");
        }

        private static IEnumerable<object> SourceFields(Dictionary<string, object> entry)
        {
            string operation = String(entry, "op");
            if (operation == "field") yield return entry;
            else foreach (object field in List(entry, operation == "field-set" ? "variants" : "fields")) yield return field;
        }

        private static void VerifyUnionProvenance(Dictionary<string, object> catalog, Dictionary<string, object> inventory, IDictionary<string, string> pins)
        {
            int position = 0;
            List<object> mappings = List(inventory, "unionMappings");
            foreach (object item in List(catalog, "entries"))
            {
                Dictionary<string, object> entry = Dictionary(item);
                if (String(entry, "op") != "union") continue;
                Check(position < mappings.Count, "Union inventory cardinality differs.");
                Dictionary<string, object> mapping = Dictionary(mappings[position++]);
                CheckHash(Canonical(mapping), pins, "union:" + String(entry, "name"));
                Check(String(entry, "name") == String(mapping, "union") && String(entry, "discriminator") == String(mapping, "discriminator"), "Union order differs.");
                List<object> branches = List(entry, "branches");
                List<object> mapped = List(mapping, "branches");
                Check(branches.Count == mapped.Count, "Union branch inventory differs.");
                for (int index = 0; index < branches.Count; index++)
                {
                    Dictionary<string, object> branch = Dictionary(mapped[index]);
                    Check(Integer(branch, "value") == (ulong)index
                        && String(branch, "emittedIdentifier") == String(Dictionary(branches[index]), "name")
                        && String(branch, "semanticLabel").Length > 0, "Union value mapping differs.");
                }
            }
            Check(position == 4 && position == mappings.Count, "Union inventory cardinality differs.");
        }

        private static List<object> VerifyLifecycle(Dictionary<string, object> inventory)
        {
            byte[] source = Convert.FromBase64String(String(inventory, "lifecycleSourceBase64"));
            Check(Hash(source) == "8718dd1de27850663988c52bdd41a5ca5617c584b9a84f59e6d5a1cdfaa0d496", "Lifecycle source bytes differ.");
            string text = Encoding.GetString(source);
            int summary = text.IndexOf("\"totalStates\"", StringComparison.Ordinal);
            Check(summary > 0, "Lifecycle source summary boundary missing.");
            int boundary = text.Substring(0, summary).LastIndexOf(',');
            Dictionary<string, object> original = Dictionary(Extract(Encoding.GetBytes(text.Substring(0, boundary) + "}")));
            Dictionary<string, object> lifecycle = Dictionary(inventory["lifecycle"]);
            CheckBytes(Canonical(original), Canonical(lifecycle), "Lifecycle lists differ.");
            List<object> variants = List(lifecycle, "variants");
            string[] names = { "InteractiveWindowsTerminalPS5", "InteractiveWindowsTerminalPS7", "InteractiveConhostPS5",
                "InteractiveConhostPS7", "NonInteractivePS5", "NonInteractivePS7" };
            int[] counts = { 73, 72, 72, 71, 67, 66 };
            Check(variants.Count == 6, "Lifecycle variant count differs.");
            int total = 0;
            for (int index = 0; index < variants.Count; index++)
            {
                Dictionary<string, object> variant = Dictionary(variants[index]);
                Check(String(variant, "name") == names[index] && List(variant, "states").Count == counts[index], "Lifecycle variant order or count differs.");
                total += counts[index];
            }
            Check(total == 421, "Lifecycle state count differs.");
            return variants;
        }

        private static void ValidateInventoryAuthority(Dictionary<string, object> inventory)
        {
            CheckBytes(Canonical(List(inventory, "profileOrder")),
                Canonical(new object[] { "InteractiveSeat", "NonInteractiveElevated" }), "Profile order differs.");
            CheckBytes(Canonical(List(inventory, "directionOrder")),
                Canonical(new object[] { "HostToWorker", "WorkerToHost" }), "Direction order differs.");
            CheckBytes(Canonical(List(inventory, "excludedTailChannels")),
                Canonical(new object[] { "BrokerControl", "LocalIpc" }), "Excluded tail channels differ.");
            CheckBytes(Canonical(List(inventory, "unassignedOverlayTypeIds")),
                Canonical(new object[] { 4872, 4873, 4875, 4876 }), "Unassigned overlay type ids differ.");
            Dictionary<string, object> illegal = Dictionary(inventory["reservedIllegalType"]);
            Check(String(illegal, "name") == "LocalTranscriptRecordSetV1" && Integer(illegal, "id") == 4881,
                "Reserved illegal type differs.");
        }

        private static void VerifyStates(List<object> messages, List<object> variants)
        {
            foreach (object item in messages)
            {
                Dictionary<string, object> message = Dictionary(item);
                string state = String(message, "stateAssoc");
                if (String(message, "channel") == "WorkerApp" && String(message, "mandatoryTailClass") == "Mandatory")
                    Check(state != "None", "Mandatory WorkerApp state is missing.");
                foreach (object variantItem in variants)
                {
                    Dictionary<string, object> variant = Dictionary(variantItem);
                    string profile = String(message, "profile");
                    if (profile != "Any" && profile != String(variant, "profile")) continue;
                    Check(state == "None" || List(variant, "states").Contains(state), "Association names an absent lifecycle state.");
                }
            }
        }

        private static List<Dictionary<string, object>> EffectiveFields(Dictionary<string, object> type, string profile)
        {
            List<Dictionary<string, object>> result = new List<Dictionary<string, object>>();
            List<object> fields = List(type, "fields");
            Dictionary<string, List<Dictionary<string, object>>> requiredByShape =
                new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
            foreach (object item in fields)
            {
                Dictionary<string, object> field = Dictionary(item);
                string shape = FieldShape(field);
                if (Optional(field, "status", "Required") == "Required")
                {
                    List<Dictionary<string, object>> required;
                    if (!requiredByShape.TryGetValue(shape, out required))
                    {
                        required = new List<Dictionary<string, object>>();
                        requiredByShape.Add(shape, required);
                    }
                    required.Add(field);
                }
                string scope = Optional(field, "profile", "Any");
                if (Optional(field, "status", "Required") == "Required" && (scope == "Any" || scope == profile))
                    result.Add(field);
            }
            foreach (object item in fields)
            {
                Dictionary<string, object> forbidden = Dictionary(item);
                if (Optional(forbidden, "status", "Required") != "Forbidden") continue;
                string forbiddenProfile = Optional(forbidden, "profile", "Any");
                List<Dictionary<string, object>> matches;
                Check(requiredByShape.TryGetValue(FieldShape(forbidden), out matches),
                    "Forbidden field has no required shape.");
                Dictionary<string, object> applicable = null;
                foreach (Dictionary<string, object> required in matches)
                {
                    string requiredProfile = Optional(required, "profile", "Any");
                    if (requiredProfile != "Any" && requiredProfile != forbiddenProfile) continue;
                    Check(applicable == null, "Forbidden field has multiple applicable required shapes.");
                    applicable = required;
                }
                if (forbiddenProfile == profile && applicable != null) result.Remove(applicable);
            }
            return result;
        }

        private static string FieldShape(Dictionary<string, object> field)
        {
            return Integer(field, "fieldId") + ":" + String(field, "name") + ":" + String(field, "type") + ":"
                + FieldBoundKind(field).ToString(CultureInfo.InvariantCulture) + ":"
                + FieldBoundValue(field).ToString(CultureInfo.InvariantCulture);
        }

        private static int FieldBoundKind(Dictionary<string, object> field)
        {
            string type = String(field, "type");
            if (type == "BoundedBytes")
            {
                Check(field.ContainsKey("maxBytes") && !field.ContainsKey("maxCodeUnits"), "Invalid verifier field bound.");
                return 1;
            }
            if (type == "OpaqueUtf16")
            {
                Check(field.ContainsKey("maxCodeUnits") && !field.ContainsKey("maxBytes"), "Invalid verifier field bound.");
                return 2;
            }
            Check(!field.ContainsKey("maxBytes") && !field.ContainsKey("maxCodeUnits"), "Invalid verifier field bound.");
            return 0;
        }

        private static ulong FieldBoundValue(Dictionary<string, object> field)
        {
            int kind = FieldBoundKind(field);
            return kind == 1 ? Integer(field, "maxBytes") : kind == 2 ? Integer(field, "maxCodeUnits") : 0;
        }

        private static void ValidateConditionalFields(Dictionary<string, object> schema)
        {
            foreach (object item in List(schema, "types"))
            {
                Dictionary<string, object> type = Dictionary(item);
                if (String(type, "production") != "Named") continue;
                EffectiveFields(type, "InteractiveSeat");
                EffectiveFields(type, "NonInteractiveElevated");
            }
        }

        private static Dictionary<string, ulong> CalculateWidths(Dictionary<string, Dictionary<string, object>> types, List<object> messages, string profile)
        {
            HashSet<string> needed = new HashSet<string>(StringComparer.Ordinal);
            Queue<string> pending = new Queue<string>();
            foreach (object item in messages)
            {
                Dictionary<string, object> message = Dictionary(item);
                if (String(message, "channel") != "WorkerApp" || String(message, "mandatoryTailClass") != "Mandatory") continue;
                if (String(message, "profile") != "Any" && String(message, "profile") != profile) continue;
                if (needed.Add(String(message, "payloadRoot"))) pending.Enqueue(String(message, "payloadRoot"));
            }
            while (pending.Count != 0)
            {
                string name = pending.Dequeue();
                Check(types.ContainsKey(name), "Missing WorkerApp sizing declaration.");
                Dictionary<string, object> type = types[name];
                List<string> dependencies = new List<string>();
                if (String(type, "production") == "Named")
                {
                    foreach (Dictionary<string, object> field in EffectiveFields(type, profile)) dependencies.Add(String(field, "type"));
                }
                if (type.ContainsKey("elementType")) dependencies.Add(String(type, "elementType"));
                foreach (string dependency in dependencies)
                {
                    if (Widths.ContainsKey(dependency) || dependency == "BoundedBytes") continue;
                    if (needed.Add(dependency)) pending.Enqueue(dependency);
                }
            }
            Dictionary<string, ulong> sizes = new Dictionary<string, ulong>(StringComparer.Ordinal);
            Dictionary<string, int> depths = new Dictionary<string, int>(StringComparer.Ordinal);
            while (sizes.Count < needed.Count)
            {
                int prior = sizes.Count;
                foreach (string name in needed)
                {
                    if (sizes.ContainsKey(name)) continue;
                    Dictionary<string, object> type = types[name];
                    string production = String(type, "production");
                    ulong sum = 0;
                    int depth = 1;
                    bool ready = true;
                    if (production == "EnumU16") sum = 2;
                    else if (production == "SemanticString") sum = checked(4UL + Integer(type, "maxBytes"));
                    else if (production == "List" || production == "Set")
                    {
                        string element = String(type, "elementType");
                        ulong elementSize;
                        if (Widths.TryGetValue(element, out elementSize)) { }
                        else if (sizes.TryGetValue(element, out elementSize)) depth = depths[element] + 1;
                        else ready = false;
                        if (ready) sum = checked(4UL + Integer(type, "maxCount") * checked(4UL + elementSize));
                    }
                    else
                    {
                        Check(production == "Named", "Unsizeable WorkerApp production.");
                        foreach (Dictionary<string, object> field in EffectiveFields(type, profile))
                        {
                            string reference = String(field, "type");
                            ulong width;
                            if (reference == "BoundedBytes") width = checked(4UL + Integer(field, "maxBytes"));
                            else if (Widths.TryGetValue(reference, out width)) { }
                            else if (sizes.TryGetValue(reference, out width)) depth = Math.Max(depth, depths[reference] + 1);
                            else { ready = false; break; }
                            sum = checked(sum + 6UL + width);
                        }
                    }
                    if (!ready) continue;
                    Check(depth <= 4, "WorkerApp nesting exceeds four.");
                    sizes.Add(name, sum);
                    depths.Add(name, depth);
                }
                Check(sizes.Count > prior, "WorkerApp sizing graph is unresolved.");
            }
            return sizes;
        }

        private static List<object> BuildReverseSchedule(List<object> associations, List<object> variants,
            Dictionary<string, Dictionary<string, ulong>> sizes)
        {
            List<object> result = new List<object>();
            foreach (object item in variants)
            {
                Dictionary<string, object> variant = Dictionary(item);
                string profile = String(variant, "profile");
                List<object> states = List(variant, "states");
                object[] rows = new object[states.Count * 2];
                SortedSet<int>[] remaining = { new SortedSet<int>(), new SortedSet<int>() };
                for (int stateIndex = states.Count - 1; stateIndex >= 0; stateIndex--)
                {
                    for (int index = 0; index < associations.Count; index++)
                    {
                        Dictionary<string, object> message = Dictionary(associations[index]);
                        if (String(message, "channel") != "WorkerApp" || String(message, "mandatoryTailClass") != "Mandatory"
                            || String(message, "stateAssoc") != (string)states[stateIndex]) continue;
                        if (String(message, "profile") != "Any" && String(message, "profile") != profile) continue;
                        Check(String(message, "name") != "Keepalive", "Keepalive appears in mandatory tails.");
                        remaining[String(message, "direction") == "HostToWorker" ? 0 : 1].Add(index);
                    }
                    for (int direction = 0; direction < 2; direction++)
                    {
                        List<object> kinds = new List<object>();
                        ulong total = 0;
                        foreach (int index in remaining[direction])
                        {
                            Dictionary<string, object> message = Dictionary(associations[index]);
                            ulong payload = sizes[profile][String(message, "payloadRoot")];
                            ulong frame = checked(payload + 408UL);
                            ulong charge = checked(frame + 13UL);
                            total = checked(total + charge);
                            kinds.Add(Record("cardinality", 1, "kindId", Integer(message, "kindId"), "maxPayloadBytes", payload,
                                "maxSignedFrameBytes", frame, "name", String(message, "name"), "transcriptChargeBytes", charge));
                        }
                        Check(kinds.Count <= 5535 && total <= 29360128UL, "Mandatory tail cap exceeded.");
                        rows[stateIndex * 2 + direction] = Record("direction", direction == 0 ? "HostToWorker" : "WorkerToHost",
                            "kinds", kinds, "lifecycleVariant", String(variant, "name"), "profile", profile, "records", kinds.Count,
                            "state", (string)states[stateIndex], "wrapperBytes", total);
                    }
                }
                result.AddRange(rows);
            }
            return result;
        }

        private sealed class ProjectionCheck
        {
            private readonly List<object> _schemaTypes;
            private readonly List<object> _map;
            private readonly HashSet<string> _literalParents;
            private readonly Dictionary<string, List<object>> _fields = new Dictionary<string, List<object>>(StringComparer.Ordinal);
            private readonly Dictionary<string, List<object>> _members = new Dictionary<string, List<object>>(StringComparer.Ordinal);
            private readonly Dictionary<string, ulong> _fieldNext = new Dictionary<string, ulong>(StringComparer.Ordinal);
            private readonly Dictionary<string, ulong> _messageIds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            private readonly Dictionary<string, ulong> _kindNext = new Dictionary<string, ulong>(StringComparer.Ordinal);
            private readonly HashSet<string> _channels = new HashSet<string>(StringComparer.Ordinal);
            private ulong _typeNext = 1;
            private int _typePosition;
            private int _mapPosition;
            internal readonly Dictionary<string, Dictionary<string, object>> Types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            internal readonly List<object> Associations = new List<object>();
            internal int TypeCount { get { return _typePosition; } }
            internal int MapCount { get { return _mapPosition; } }

            internal ProjectionCheck(List<object> schemaTypes, List<object> map, string[] literalParents)
            {
                _schemaTypes = schemaTypes;
                _map = map;
                _literalParents = new HashSet<string>(literalParents, StringComparer.Ordinal);
                Check(_literalParents.Count == 46, "Literal extension allowlist differs.");
                foreach (string channel in Channels) _kindNext.Add(channel, 1);
            }

            internal void CheckCatalogs(Dictionary<string, object>[] catalogs)
            {
                for (int catalogIndex = 0; catalogIndex < catalogs.Length; catalogIndex++)
                {
                    string catalog = catalogIndex == 0 ? "base" : "overlay";
                    List<object> entries = List(catalogs[catalogIndex], "entries");
                    for (int index = 0; index < entries.Count; index++) CheckEntry(Dictionary(entries[index]), catalog, index + 1);
                }
                Check(_typePosition == _schemaTypes.Count && _mapPosition == _map.Count, "Extra schema or map rows.");
                foreach (KeyValuePair<string, Dictionary<string, object>> pair in Types)
                {
                    if (_fields.ContainsKey(pair.Key))
                    {
                        _fields[pair.Key].Sort(CompareFields);
                        CheckBytes(Canonical(_fields[pair.Key]), Canonical(List(pair.Value, "fields")), "Field projection differs: " + pair.Key);
                    }
                    else CheckBytes(Canonical(_members[pair.Key]), Canonical(List(pair.Value, "members")), "Enum projection differs: " + pair.Key);
                }
                Check(_typeNext == 91 && Associations.Count == 31, "Generated counters differ.");
            }

            private void CheckEntry(Dictionary<string, object> entry, string catalog, int ordinal)
            {
                string operation = String(entry, "op");
                if (operation == "type" || operation == "overlay-type")
                {
                    string name = String(entry, "name");
                    ulong id = operation == "type" ? _typeNext++ : Integer(entry, "id");
                    Check(String(entry, "production") == "Named", "Unexpected retained declaration production.");
                    if (operation == "type") Map(catalog, ordinal, "type", name, id, null);
                    else Check(id >= 4864 && id <= 5119 && id != 4872 && id != 4873 && id != 4875 && id != 4876 && id != 4881, "Literal type range differs.");
                    Type(name, id, "Named");
                }
                else if (operation == "field" || operation == "field-set")
                {
                    string parent = String(entry, "parent");
                    Check(Types.ContainsKey(parent), "Catalog parent is undefined.");
                    bool generatedParent = Integer(Types[parent], "typeId") < 4864;
                    bool literal = entry.ContainsKey("id");
                    ulong id = literal ? Integer(entry, "id") : _fieldNext[parent]++;
                    if (literal && generatedParent) Check(id >= 40 && _literalParents.Contains(parent), "Non-allowlisted literal extension.");
                    if (!literal) Check(id <= 39, "Generated field counter crossed its cap.");
                    foreach (object field in SourceFields(entry)) AddField(parent, Dictionary(field), id);
                    if (generatedParent) Map(catalog, ordinal, "field", parent + "." + String(entry, "name"), id, null);
                }
                else if (operation == "union")
                {
                    string discriminator = String(entry, "discriminator");
                    ulong id = _typeNext++;
                    Type(discriminator, id, "EnumU16");
                    Map(catalog, ordinal, "type", discriminator, id, null);
                    List<object> branches = List(entry, "branches");
                    for (int index = 0; index < branches.Count; index++)
                    {
                        Dictionary<string, object> branch = Dictionary(branches[index]);
                        string name = String(branch, "name");
                        _members[discriminator].Add(Record("name", name, "value", index));
                        Map(catalog, ordinal, "enum-member", discriminator + "." + name, (ulong)index, Record("memberIndex", index));
                        ulong branchId = _typeNext++;
                        Type(name, branchId, "Named");
                        List<object> fields = List(branch, "fields");
                        for (int fieldIndex = 0; fieldIndex < fields.Count; fieldIndex++)
                        {
                            Dictionary<string, object> field = Dictionary(fields[fieldIndex]);
                            AddField(name, field, (ulong)fieldIndex + 1);
                            Map(catalog, ordinal, "field", name + "." + String(field, "name"), (ulong)fieldIndex + 1, null);
                        }
                        _fieldNext[name] = (ulong)fields.Count + 1;
                        Map(catalog, ordinal, "union-branch", name, branchId, Record("branchIndex", index));
                    }
                }
                else if (operation == "message" || operation == "overlay-message")
                {
                    string channel = String(entry, "channel");
                    string name = String(entry, "name");
                    string owner = channel + "MessageKind";
                    Check(_kindNext.ContainsKey(channel), "Unknown message channel.");
                    if (_channels.Add(channel))
                    {
                        ulong ownerId = _typeNext++;
                        Type(owner, ownerId, "EnumU16");
                        Map(catalog, ordinal, "type", owner, ownerId, null);
                    }
                    string key = channel + ":" + name;
                    ulong id;
                    if (!_messageIds.TryGetValue(key, out id))
                    {
                        id = operation == "message" ? _kindNext[channel]++ : Integer(entry, "id");
                        _messageIds.Add(key, id);
                        _members[owner].Add(Record("name", name, "value", id));
                    }
                    if (operation == "overlay-message")
                    {
                        Check(id == Integer(entry, "id") && (channel == "WorkerApp" ? id >= 4224 && id <= 4351
                            : channel == "BrokerControl" ? id >= 4352 && id <= 4607 : id >= 4608 && id <= 4863), "Literal message range differs.");
                    }
                    else Check(id < 4224, "Generated kind counter entered a reserved range.");
                    Dictionary<string, object> metadata = Record("channel", channel, "direction", String(entry, "direction"),
                        "profile", String(entry, "profile"), "mandatoryTailClass", String(entry, "mandatoryTailClass"), "stateAssoc", String(entry, "stateAssoc"));
                    Map(catalog, ordinal, "kind", name, id, metadata);
                    metadata.Add("name", name);
                    metadata.Add("kindId", id);
                    metadata.Add("payloadRoot", String(entry, "payloadRoot"));
                    Associations.Add(metadata);
                }
                else if (operation == "reserve-illegal-type")
                {
                    Check(String(entry, "name") == "LocalTranscriptRecordSetV1" && Integer(entry, "id") == 4881, "Reservation differs.");
                }
                else throw new InvalidDataException("Unexpected operation in pinned retained projection: " + operation);
            }

            private void Type(string name, ulong id, string production)
            {
                Check(_typePosition < _schemaTypes.Count, "Missing type projection.");
                Dictionary<string, object> actual = Dictionary(_schemaTypes[_typePosition++]);
                Check(actual.Count == 4 && String(actual, "name") == name && Integer(actual, "typeId") == id
                    && String(actual, "production") == production && name.Length <= 64, "Type projection differs: " + name);
                Check(id >= 1 && id <= 65535 && !System.Array.Exists(OmittedTypes, delegate(string omitted) { return omitted == name; }), "Forbidden type projection.");
                Types.Add(name, actual);
                _fieldNext.Add(name, 1);
                if (production == "Named") _fields.Add(name, new List<object>());
                else _members.Add(name, new List<object>());
            }

            private void AddField(string parent, Dictionary<string, object> source, ulong id)
            {
                Dictionary<string, object> field = Record("fieldId", id, "name", String(source, "name"), "type", String(source, "type"));
                foreach (string bound in new string[] { "maxBytes", "maxCodeUnits" }) if (source.ContainsKey(bound)) field.Add(bound, Integer(source, bound));
                if (Optional(source, "profile", "Any") != "Any") field.Add("profile", String(source, "profile"));
                if (Optional(source, "status", "Required") != "Required") field.Add("status", String(source, "status"));
                _fields[parent].Add(field);
            }

            private void Map(string catalog, int ordinal, string category, string name, ulong id, Dictionary<string, object> extra)
            {
                Dictionary<string, object> expected = Record("schemaId", "PspktGeneratedBaseIdMapV1", "catalog", catalog,
                    "catalogOrdinal", ordinal, "category", category, "name", name, "generatedId", id);
                if (extra != null) foreach (KeyValuePair<string, object> pair in extra) expected.Add(pair.Key, pair.Value);
                Check(_mapPosition < _map.Count, "Missing map projection.");
                CheckBytes(Canonical(expected), Canonical(_map[_mapPosition++]), "Map projection differs: " + catalog + "/" + ordinal + "/" + category + "/" + name);
            }

            private static int CompareFields(object first, object second)
            {
                Dictionary<string, object> left = Dictionary(first);
                Dictionary<string, object> right = Dictionary(second);
                int comparison = Integer(left, "fieldId").CompareTo(Integer(right, "fieldId"));
                if (comparison != 0) return comparison;
                string[] scopes = { "Any", "InteractiveSeat", "NonInteractiveElevated" };
                comparison = System.Array.IndexOf(scopes, Optional(left, "profile", "Any")).CompareTo(
                    System.Array.IndexOf(scopes, Optional(right, "profile", "Any")));
                if (comparison != 0) return comparison;
                comparison = (Optional(left, "status", "Required") == "Forbidden" ? 1 : 0).CompareTo(
                    Optional(right, "status", "Required") == "Forbidden" ? 1 : 0);
                if (comparison != 0) return comparison;
                comparison = string.CompareOrdinal(String(left, "name"), String(right, "name"));
                if (comparison != 0) return comparison;
                comparison = string.CompareOrdinal(String(left, "type"), String(right, "type"));
                if (comparison != 0) return comparison;
                comparison = FieldBoundKind(left).CompareTo(FieldBoundKind(right));
                if (comparison != 0) return comparison;
                return FieldBoundValue(left).CompareTo(FieldBoundValue(right));
            }
        }

        private static object Extract(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            bytes = (byte[])bytes.Clone();
            Pspkt.Certification.SchemaCheckResult gate = Pspkt.Certification.SchemaBootstrap.Evaluate("json", bytes, null);
            Check(gate.Accepted, "Verifier JSON rejected: " + gate.Reason);
            XmlDictionaryReaderQuotas quotas = new XmlDictionaryReaderQuotas();
            quotas.MaxDepth = 32;
            quotas.MaxArrayLength = 8192;
            quotas.MaxStringContentLength = 262144;
            quotas.MaxBytesPerRead = 1048576;
            quotas.MaxNameTableCharCount = 1048576;
            using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(bytes, quotas))
            {
                reader.MoveToContent();
                return ExtractElement(reader);
            }
        }

        private static object ExtractElement(XmlDictionaryReader reader)
        {
            ValidateProjectionAttributes(reader);
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
                        object value = ExtractElement(reader);
                        if (kind == "object")
                        {
                            properties.Add(name, value);
                            Check(properties.Count <= 4096, "Verifier property cap exceeded.");
                        }
                        else
                        {
                            items.Add(value);
                            Check(items.Count <= 8192, "Verifier array cap exceeded.");
                        }
                    }
                    reader.ReadEndElement();
                }
                return kind == "object" ? (object)properties : items;
            }
            string content = reader.ReadElementContentAsString();
            if (kind == "string") return content;
            if (kind == "number") return ulong.Parse(content, CultureInfo.InvariantCulture);
            if (kind == "boolean") return content == "true";
            Check(kind == "null", "Unsupported verifier projection element.");
            return null;
        }

        private static void ValidateProjectionAttributes(XmlDictionaryReader reader)
        {
            string elementPrefix = reader.Prefix;
            if (!reader.MoveToFirstAttribute()) return;
            do
            {
                bool unqualifiedProjectionAttribute = reader.Prefix.Length == 0
                    && reader.NamespaceURI.Length == 0
                    && (reader.LocalName == "type" || reader.LocalName == "item");
                bool escapedNameNamespace = elementPrefix.Length != 0
                    && reader.Prefix == "xmlns"
                    && reader.NamespaceURI == "http://www.w3.org/2000/xmlns/"
                    && reader.LocalName == elementPrefix
                    && reader.Value == "item";
                Check(unqualifiedProjectionAttribute || escapedNameNamespace,
                    "Verifier JSON attribute is not supported: " + reader.Name);
            }
            while (reader.MoveToNextAttribute());
            reader.MoveToElement();
        }

        private static Dictionary<string, object> Dictionary(object value)
        {
            Dictionary<string, object> result = value as Dictionary<string, object>;
            Check(result != null, "Expected verifier object.");
            return result;
        }

        private static List<object> List(Dictionary<string, object> value, string name)
        {
            object field;
            Check(value.TryGetValue(name, out field) && field is List<object>, "Expected verifier array: " + name);
            return (List<object>)field;
        }

        private static string String(Dictionary<string, object> value, string name)
        {
            object field;
            Check(value.TryGetValue(name, out field) && field is string, "Expected verifier string: " + name);
            return (string)field;
        }

        private static string Optional(Dictionary<string, object> value, string name, string absent)
        {
            return value.ContainsKey(name) ? String(value, name) : absent;
        }

        private static ulong Integer(Dictionary<string, object> value, string name)
        {
            object field;
            Check(value.TryGetValue(name, out field) && (field is ulong || field is int), "Expected verifier integer: " + name);
            return Convert.ToUInt64(field, CultureInfo.InvariantCulture);
        }

        private static Dictionary<string, object> Record(params object[] pairs)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
            for (int index = 0; index < pairs.Length; index += 2) result.Add((string)pairs[index], pairs[index + 1]);
            return result;
        }

        private static void Check(bool condition, string message)
        {
            if (!condition) throw new InvalidDataException(message);
        }

        private static void CheckBytes(byte[] expected, byte[] actual, string message)
        {
            Check(expected.Length == actual.Length, message);
            for (int index = 0; index < expected.Length; index++) Check(expected[index] == actual[index], message);
        }

        private static string Hash(byte[] bytes)
        {
            using (SHA256 digest = SHA256.Create())
            {
                return BitConverter.ToString(digest.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }

        private static void CheckHash(byte[] bytes, IDictionary<string, string> pins, string name)
        {
            string expected;
            Check(pins.TryGetValue(name, out expected) && Hash(bytes) == expected, "Pinned hash differs: " + name);
        }

        private static byte[] Canonical(object value)
        {
            StringBuilder text = new StringBuilder();
            AppendCanonical(text, value);
            return Encoding.GetBytes(text.ToString());
        }

        private static void AppendCanonical(StringBuilder text, object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties != null)
            {
                List<string> keys = new List<string>(properties.Keys);
                keys.Sort(StringComparer.Ordinal);
                text.Append('{');
                for (int index = 0; index < keys.Count; index++)
                {
                    if (index != 0) text.Append(',');
                    AppendCanonical(text, keys[index]);
                    text.Append(':');
                    AppendCanonical(text, properties[keys[index]]);
                }
                text.Append('}');
            }
            else if (value is string)
            {
                text.Append('"');
                foreach (char character in (string)value)
                {
                    if (character == '\\' || character == '"') text.Append('\\').Append(character);
                    else if (character < 32) text.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    else text.Append(character);
                }
                text.Append('"');
            }
            else if (value is IEnumerable)
            {
                text.Append('[');
                bool separator = false;
                foreach (object item in (IEnumerable)value)
                {
                    if (separator) text.Append(',');
                    separator = true;
                    AppendCanonical(text, item);
                }
                text.Append(']');
            }
            else if (value is ulong || value is int) text.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
            else if (value is bool) text.Append((bool)value ? "true" : "false");
            else if (value == null) text.Append("null");
            else throw new InvalidDataException("Unexpected canonical verifier value.");
        }
    }
}
