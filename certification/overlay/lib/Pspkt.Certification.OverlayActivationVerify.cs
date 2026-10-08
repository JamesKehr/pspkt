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

namespace Pspkt.Certification.Overlay
{
    public static class OverlayActivationVerify
    {
        private static readonly string[] Profiles = { "InteractiveSeat", "NonInteractiveElevated" };
        private static readonly Dictionary<string, ulong> Widths = new Dictionary<string, ulong>(StringComparer.Ordinal) {
            { "U8", 1 }, { "U16", 2 }, { "U32", 4 }, { "U64", 8 }, { "I16", 2 }, { "I32", 4 }, { "I64", 8 },
            { "FILETIME", 8 }, { "QPC", 8 }, { "GUID", 16 }, { "Opaque16", 16 }, { "FixedAscii8", 8 },
            { "SHA-256", 32 }, { "Opaque32", 32 }, { "AsciiIdentifier", 128 }, { "BinarySid", 68 },
            { "Utf8Short", 256 }, { "Rsa3072PublicBlob", 512 }, { "Rsa3072Signature", 384 }, { "LUID", 8 } };
        private const string InventoryDigest = "25ce722fb5657b315fcbd5dae779d3f657f4d67d9856dfc7080b02f835833d6f";
        private const string CountContract = "schemaTypes=112 generatedTypes=90 literalTypes=22 enumTypes=7 namedTypes=105 physicalFields=906 mapRows=685 typeRows=37 fieldRows=507 kindRows=35 enumMemberRows=53 unionBranchRows=53 associations=35 messageIdentities=30 payloadRoots=28 workerAssociations=9 brokerAssociations=18 localAssociations=8 mandatoryAssociations=19 ordinaryAssociations=16 mandatoryNone=4 activatedBaseOperations=296 activatedOverlayOperations=446 lifecycleVariants=6 lifecycleStates=423 distinctStates=92 scheduleRows=1386 workerScheduleRows=846 brokerScheduleRows=270 localScheduleRows=270 nonEmptyScheduleRows=949 kindMemberships=1640 activatedTypes=5 activatedMessages=4 messageRows=43 channelRows=8 collisionRows=8 extensionRows=56 baseExtensionRows=16 unionExtensionRows=40 s4uRows=28 numericS4uRows=14 transcriptTypeRows=4 transcriptMessageRows=3 transcriptLinkRows=12 maximaRows=16 frozenTypes=107 sharedOrdinalChanges=81 extensionParents=46 outputFiles=6 outputBytes=733833";
        private static readonly string[] OutputNames = { "protocol-schema.v1.json", "generated-base-id-map.v1.json",
            "protocol-message-association.v1.json", "mandatory-tail-schedule.v1.json", "overlay-matrices.v1.json", "overlay-maxima.v1.json" };
        private static readonly string[] OutputDigests = {
            "11cbae40d33c7f8da0c92a4579a003e51df7c7552b5eb9c7e65adada82f88797",
            "3b812c056bf63afafd540b9c61f72341a689766318c3606dcd8feba4e2a37ca3",
            "f17afa4eab197340d288fe3aea8154d80a696aa98559ef498844c7036b2e73ed",
            "d25c2997a24048e14c97dfc94c0ab05c8ffc8138d0cbc2d330c8f759760296a2",
            "e10fccf716e4d935d83adb140a716e1eef9575c57277e250cc40647de07a5f13",
            "4d92ec08e2676e7d59d4cf522b3ede33a7e668e2c1fcd4b87ad41e3b8bb7d86c" };

        public static byte[] Canonicalize(byte[] bytes)
        {
            return new UTF8Encoding(false, true).GetBytes(Canonical(Extract(bytes)));
        }

        public static void VerifyAssemblyReferences(Assembly assembly, string bootstrapIdentity, string[] forbiddenIdentities)
        {
            if (assembly == null) { throw new ArgumentNullException("assembly"); }
            Check(bootstrapIdentity == typeof(Pspkt.Certification.SchemaBootstrap).Assembly.FullName,
                "Overlay verifier bootstrap identity differs.");
            Check(forbiddenIdentities != null && forbiddenIdentities.Length == 2
                && !string.IsNullOrEmpty(forbiddenIdentities[0]) && !string.IsNullOrEmpty(forbiddenIdentities[1])
                && forbiddenIdentities[0] != forbiddenIdentities[1], "Overlay verifier forbidden identity set differs.");
            HashSet<string> forbiddenNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (string identity in forbiddenIdentities) { forbiddenNames.Add(new AssemblyName(identity).Name); }
            foreach (AssemblyName reference in assembly.GetReferencedAssemblies())
            {
                Check(!forbiddenNames.Contains(reference.Name), "Overlay verifier has a forbidden assembly reference.");
                Check(reference.Name.IndexOf("Authority", StringComparison.Ordinal) < 0
                    && reference.Name.IndexOf("Engine", StringComparison.Ordinal) < 0,
                    "Overlay verifier has a forbidden assembly reference.");
                if (reference.FullName == bootstrapIdentity) { continue; }
                byte[] token = reference.GetPublicKeyToken();
                Check(token != null && token.Length != 0
                    && (reference.Name == "mscorlib" || reference.Name == "System" || reference.Name.StartsWith("System.", StringComparison.Ordinal)),
                    "Overlay verifier has an unexpected assembly reference.");
            }
            foreach (Type type in assembly.GetTypes())
            {
                Check(type.FullName.IndexOf("Authority", StringComparison.Ordinal) < 0
                    && type.FullName.IndexOf("Engine", StringComparison.Ordinal) < 0, "Overlay verifier contains a forbidden type name.");
            }
        }

        public static void ValidateInventory(byte[] inventoryBytes)
        {
            Dictionary<string, object> inventory = Dictionary(Extract(inventoryBytes));
            HashSet<string> keys = new HashSet<string>(
                "activatedTypeIds activatedTypeNames associations dormancy engineParameters expectedCounts expectedOutputs frozenInputHashes lifecycle lifecycleSourceSha256 matrices maxima mutationCases outputPathSet rehomeTypes reservedIllegalType schedule schemaId schemaVersion transformation unassignedOverlayTypeIds".Split(' '), StringComparer.Ordinal);
            foreach (string key in inventory.Keys)
            {
                Check(keys.Contains(key), "Overlay activation inventory shape differs: unknown property " + key);
            }
            Check(keys.SetEquals(inventory.Keys), "Overlay activation inventory shape differs: root keys");
            Check(String(inventory, "schemaId") == "PspktOverlayActivationInventoryV1" && Integer(inventory, "schemaVersion") == 1,
                "Overlay activation inventory shape differs: identity");
            Check(Canonical(inventory["activatedTypeNames"]) == Canonical(new string[] {
                "S4UMintSlotV1", "MintAttestedV1", "IsolationAdmission", "IsolationExit", "ServiceControlEventNodeProofV1" }),
                "Overlay activation inventory shape differs: activatedTypeNames");
            Check(Canonical(inventory["activatedTypeIds"]) == "[4866,4867,4872,4873,4874]",
                "Overlay activation inventory shape differs: activatedTypeIds");
            Check(Canonical(inventory["unassignedOverlayTypeIds"]) == "[4875,4876]",
                "Overlay activation inventory shape differs: unassignedOverlayTypeIds");
            Check(Canonical(inventory["reservedIllegalType"]) == Canonical(Record("id", 4881, "name", "LocalTranscriptRecordSetV1")),
                "Overlay activation inventory shape differs: reservedIllegalType");
            List<object> rehome = new List<object>();
            string[][] names = {
                new string[] { "workerServiceLaunchProof", "workerServiceControlEventNodeProof", "brokerServiceLaunchProof",
                    "brokerServiceControlEventNodeProof", "admissionReceipt", "brokerAnchor", "workerProcessDaclAccessPolicyProof" },
                new string[] { "isolationReceipt", "workerServiceControlEventNodeProof", "localTranscriptProofDigest" } };
            string[][] types = {
                new string[] { "ServiceLaunchProofV1", "ServiceControlEventNodeProofV1", "BrokerServiceLaunchProofV1",
                    "ServiceControlEventNodeProofV1", "WorkerProcessIsolationAdmissionReceiptV1", "BrokerServicePrincipalAnchorV1", "WorkerProcessDaclAccessPolicyProofV1" },
                new string[] { "WorkerProcessIsolationReceiptV1", "ServiceControlEventNodeProofV1", "SHA-256" } };
            for (int index = 0; index < names.Length; index++)
            {
                List<object> fields = new List<object>();
                for (int field = 0; field < names[index].Length; field++)
                {
                    fields.Add(Record("id", field + 1, "name", names[index][field], "type", types[index][field]));
                }
                rehome.Add(Record("id", 4872 + index, "name", index == 0 ? "IsolationAdmission" : "IsolationExit", "fields", fields));
            }
            Check(Canonical(inventory["rehomeTypes"]) == Canonical(rehome), "Overlay activation inventory shape differs: rehomeTypes");
            Dictionary<string, object> counts = Dictionary(inventory["expectedCounts"]);
            string[] countRows = CountContract.Split(' ');
            Check(counts.Count == countRows.Length, "Overlay activation inventory shape differs: expectedCounts");
            foreach (string definition in countRows)
            {
                string[] pair = definition.Split('=');
                object value;
                Check(counts.TryGetValue(pair[0], out value) && value is ulong
                    && (ulong)value == ulong.Parse(pair[1], CultureInfo.InvariantCulture),
                    "Overlay activation inventory shape differs: expectedCounts." + pair[0]);
            }
            Check(Hash(new UTF8Encoding(false, true).GetBytes(Canonical(inventory))) == InventoryDigest,
                "Overlay activation inventory shape differs: contract");
            Check(Hash(inventoryBytes) == InventoryDigest, "Overlay activation inventory is not canonical.");
        }

        public static void VerifyActivatedMessages(byte[] overlayBytes)
        {
            Dictionary<string, string[]> expected = new Dictionary<string, string[]>(StringComparer.Ordinal) {
                { "IsolationAdmission", new string[] { "4368", "BrokerToHost", "Ordinary", "ServiceLaunchAttested", "IsolationAdmission" } },
                { "MintAttested", new string[] { "4370", "BrokerToHost", "Mandatory", "CandidateAccessProbeAttested", "MintAttestedV1" } },
                { "IsolationExit", new string[] { "4371", "BrokerToHost", "Mandatory", "WorkerExitObserved", "IsolationExit" } },
                { "MintRevoked", new string[] { "4374", "HostToBroker", "Mandatory", "TokenMintAuthorizedSent", "MintRevokedV1" } } };
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (object item in List(Dictionary(Extract(overlayBytes)), "entries"))
            {
                Dictionary<string, object> entry = Dictionary(item);
                if (String(entry, "op") != "overlay-message") { continue; }
                string name = String(entry, "name");
                string[] row;
                if (!expected.TryGetValue(name, out row)) { continue; }
                Check(seen.Add(name) && String(entry, "channel") == "BrokerControl"
                    && Integer(entry, "id").ToString(CultureInfo.InvariantCulture) == row[0]
                    && String(entry, "direction") == row[1] && String(entry, "mandatoryTailClass") == row[2]
                    && String(entry, "stateAssoc") == row[3] && String(entry, "payloadRoot") == row[4]
                    && String(entry, "profile") == "NonInteractiveElevated",
                    "Activated message row differs: BrokerControl:" + name);
            }
            Check(seen.Count == 4, "Activated message count differs.");
        }

        public static void Verify(byte[] baseBytes, byte[] overlayBytes, byte[] protocolInventoryBytes,
            byte[] inventoryBytes, byte[] metaBytes, IDictionary<string, byte[]> outputs)
        {
            if (outputs == null) { throw new ArgumentNullException("outputs"); }
            ValidateInventory(inventoryBytes);
            VerifyActivatedMessages(overlayBytes);
            Check(Hash(baseBytes) == "955b1a3042a6bf18eea4339d1a1896199a19ae3ba312ed08ac4bc1304c7bdc82",
                "Overlay verifier base source identity differs.");
            Check(Hash(overlayBytes) == "0d28afe037201403c5b05db3600268aea5599ac1221ae657a65287fe588daa79",
                "Overlay verifier overlay source identity differs.");
            Check(Hash(protocolInventoryBytes) == "d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f",
                "Overlay verifier protocol inventory identity differs.");
            Check(Hash(metaBytes) == "ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85",
                "Overlay verifier schema meta identity differs.");
            Check(outputs.Count == 6, "Activated output dictionary differs.");
            int[] lengths = { 72554, 123173, 7880, 492641, 35953, 1632 };
            for (int index = 0; index < OutputNames.Length; index++)
            {
                string path = "certification/overlay/schema/" + OutputNames[index];
                byte[] bytes;
                Check(outputs.TryGetValue(path, out bytes) && bytes != null, "Activated output is missing: " + path);
                Check(bytes.Length == lengths[index] && Hash(bytes) == OutputDigests[index], "Activated output identity differs: " + path);
                Check(new UTF8Encoding(false, true).GetString(bytes) == Canonical(Extract(bytes)), "Activated output is not canonical: " + path);
            }
            byte[] schemaBytes = outputs["certification/overlay/schema/protocol-schema.v1.json"];
            Pspkt.Certification.SchemaCheckResult meta = Pspkt.Certification.SchemaBootstrap.Evaluate("schema-against-meta", schemaBytes, metaBytes);
            Check(meta.Accepted, "Activated schema-against-meta rejected: " + meta.Reason);
            VerifyDeclarationOrder(baseBytes, overlayBytes, schemaBytes);
            VerifyAssignments(baseBytes, overlayBytes, outputs["certification/overlay/schema/generated-base-id-map.v1.json"]);
            VerifyDeclarations(baseBytes, overlayBytes, schemaBytes, outputs["certification/overlay/schema/generated-base-id-map.v1.json"]);
            VerifyMaxima(schemaBytes, outputs["certification/overlay/schema/overlay-maxima.v1.json"]);
            Dictionary<string, object> inventory = Dictionary(Extract(inventoryBytes));
            VerifyAssociationsAndSchedule(baseBytes, overlayBytes, protocolInventoryBytes, inventory, schemaBytes, outputs);
            Check(Canonical(inventory["matrices"]) == Canonical(Extract(outputs["certification/overlay/schema/overlay-matrices.v1.json"])),
                "Activated matrices differ from the maintained contract.");
        }

        private static void VerifyDeclarations(byte[] baseBytes, byte[] overlayBytes, byte[] schemaBytes, byte[] mapBytes)
        {
            Dictionary<string, ulong> ids = new Dictionary<string, ulong>(StringComparer.Ordinal);
            Dictionary<string, ulong> kindIds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            foreach (object item in (List<object>)Extract(mapBytes))
            {
                Dictionary<string, object> row = Dictionary(item);
                string category = String(row, "category");
                if (category == "type" || category == "union-branch") { ids.Add(String(row, "name"), Integer(row, "generatedId")); }
                if (category == "kind")
                {
                    string key = String(row, "channel") + ":" + String(row, "name");
                    ulong existing;
                    if (kindIds.TryGetValue(key, out existing)) { Check(existing == Integer(row, "generatedId"), "Shared kind ID differs."); }
                    else { kindIds.Add(key, Integer(row, "generatedId")); }
                }
            }
            Dictionary<string, object>[] catalogs = { Dictionary(Extract(baseBytes)), Dictionary(Extract(overlayBytes)) };
            foreach (object item in List(catalogs[1], "entries"))
            {
                Dictionary<string, object> entry = Dictionary(item);
                if (String(entry, "op") == "overlay-type") { ids.Add(String(entry, "name"), Integer(entry, "id")); }
            }
            ids.Add("IsolationAdmission", 4872);
            ids.Add("IsolationExit", 4873);
            Dictionary<string, Dictionary<string, object>> expected = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            Dictionary<string, ulong> nextFields = new Dictionary<string, ulong>(StringComparer.Ordinal);
            HashSet<string> emittedKinds = new HashSet<string>(StringComparer.Ordinal);
            foreach (Dictionary<string, object> catalog in catalogs)
            {
                foreach (object item in List(catalog, "entries"))
                {
                    Dictionary<string, object> entry = Dictionary(item);
                    string operation = String(entry, "op");
                    if (operation == "type" || operation == "overlay-type")
                    {
                        string name = String(entry, "name");
                        expected.Add(name, Record("name", name, "typeId", ids[name], "production", "Named", "fields", new List<object>()));
                        nextFields.Add(name, 1);
                    }
                    else if (operation == "union")
                    {
                        string discriminator = String(entry, "discriminator");
                        List<object> members = new List<object>();
                        List<object> branches = List(entry, "branches");
                        for (int index = 0; index < branches.Count; index++)
                        {
                            Dictionary<string, object> branch = Dictionary(branches[index]);
                            string name = String(branch, "name");
                            members.Add(Record("name", name, "value", index));
                            List<object> fields = new List<object>();
                            foreach (object field in List(branch, "fields")) { fields.Add(ProjectField(Dictionary(field), (ulong)fields.Count + 1)); }
                            expected.Add(name, Record("name", name, "typeId", ids[name], "production", "Named", "fields", fields));
                            nextFields.Add(name, (ulong)fields.Count + 1);
                        }
                        expected.Add(discriminator, Record("name", discriminator, "typeId", ids[discriminator], "production", "EnumU16", "members", members));
                    }
                    else if (operation == "field" || operation == "field-set")
                    {
                        string parent = String(entry, "parent");
                        ulong id = entry.ContainsKey("id") ? Integer(entry, "id") : nextFields[parent]++;
                        List<object> fields = List(expected[parent], "fields");
                        if (operation == "field") { fields.Add(ProjectField(entry, id)); }
                        else { foreach (object field in List(entry, "variants")) { fields.Add(ProjectField(Dictionary(field), id)); } }
                    }
                    else if (operation == "message" || operation == "overlay-message")
                    {
                        string channel = String(entry, "channel");
                        string owner = channel + "MessageKind";
                        if (!expected.ContainsKey(owner))
                        {
                            expected.Add(owner, Record("name", owner, "typeId", ids[owner], "production", "EnumU16", "members", new List<object>()));
                        }
                        string name = String(entry, "name");
                        string key = channel + ":" + name;
                        if (emittedKinds.Add(key)) { List(expected[owner], "members").Add(Record("name", name, "value", kindIds[key])); }
                    }
                    else { Check(operation == "reserve-illegal-type", "Unexpected declaration source operation."); }
                }
            }
            Check(expected.Count == 112, "Activated reconstructed declaration count differs.");
            int physicalFields = 0;
            foreach (object item in List(Dictionary(Extract(schemaBytes)), "types"))
            {
                Dictionary<string, object> actual = Dictionary(item);
                string name = String(actual, "name");
                Dictionary<string, object> declaration = expected[name];
                if (declaration.ContainsKey("fields"))
                {
                    List<object> fields = List(declaration, "fields");
                    fields.Sort(CompareFields);
                    physicalFields += fields.Count;
                }
                Check(Canonical(actual) == Canonical(declaration), "Activated declaration shape differs: " + name);
            }
            Check(physicalFields == 906, "Activated physical field count differs.");
        }

        private static Dictionary<string, object> ProjectField(Dictionary<string, object> source, ulong id)
        {
            Dictionary<string, object> field = Record("fieldId", id, "name", String(source, "name"), "type", String(source, "type"));
            foreach (string bound in new string[] { "maxBytes", "maxCodeUnits" }) { if (source.ContainsKey(bound)) { field.Add(bound, Integer(source, bound)); } }
            if (Optional(source, "profile", "Any") != "Any") { field.Add("profile", String(source, "profile")); }
            if (Optional(source, "status", "Required") != "Required") { field.Add("status", String(source, "status")); }
            return field;
        }

        private static int CompareFields(object first, object second)
        {
            Dictionary<string, object> left = Dictionary(first);
            Dictionary<string, object> right = Dictionary(second);
            int order = Integer(left, "fieldId").CompareTo(Integer(right, "fieldId"));
            if (order != 0) { return order; }
            string[] scopes = { "Any", "InteractiveSeat", "NonInteractiveElevated" };
            order = System.Array.IndexOf(scopes, Optional(left, "profile", "Any")).CompareTo(
                System.Array.IndexOf(scopes, Optional(right, "profile", "Any")));
            if (order != 0) { return order; }
            order = (Optional(left, "status", "Required") == "Forbidden" ? 1 : 0).CompareTo(
                Optional(right, "status", "Required") == "Forbidden" ? 1 : 0);
            if (order != 0) { return order; }
            order = string.CompareOrdinal(String(left, "name"), String(right, "name"));
            if (order != 0) { return order; }
            return string.CompareOrdinal(String(left, "type"), String(right, "type"));
        }

        private static void VerifyAssociationsAndSchedule(byte[] baseBytes, byte[] overlayBytes, byte[] protocolInventoryBytes,
            Dictionary<string, object> inventory, byte[] schemaBytes, IDictionary<string, byte[]> outputs)
        {
            List<object> associations = new List<object>();
            Dictionary<string, ulong> kindIds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            Dictionary<string, ulong> nextKinds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            foreach (byte[] source in new byte[][] { baseBytes, overlayBytes })
            {
                foreach (object item in List(Dictionary(Extract(source)), "entries"))
                {
                    Dictionary<string, object> entry = Dictionary(item);
                    string operation = String(entry, "op");
                    if (operation != "message" && operation != "overlay-message") { continue; }
                    string channel = String(entry, "channel");
                    string key = channel + ":" + String(entry, "name");
                    if (!nextKinds.ContainsKey(channel)) { nextKinds.Add(channel, 1); }
                    ulong id;
                    if (!kindIds.TryGetValue(key, out id))
                    {
                        id = operation == "message" ? nextKinds[channel]++ : Integer(entry, "id");
                        kindIds.Add(key, id);
                    }
                    Dictionary<string, object> row = Record("kindId", id);
                    foreach (string property in new string[] { "channel", "direction", "name", "payloadRoot", "profile", "stateAssoc", "mandatoryTailClass" })
                    {
                        row.Add(property, String(entry, property));
                    }
                    associations.Add(row);
                }
            }
            Check(Canonical(Record("schemaId", "PspktProtocolMessageAssociationV1", "schemaVersion", 1, "rows", associations))
                == Canonical(Extract(outputs["certification/overlay/schema/protocol-message-association.v1.json"])), "Activated associations differ.");
            Dictionary<string, object> protocolInventory = Dictionary(Extract(protocolInventoryBytes));
            Check(Hash(Convert.FromBase64String(String(protocolInventory, "lifecycleSourceBase64"))) ==
                "8718dd1de27850663988c52bdd41a5ca5617c584b9a84f59e6d5a1cdfaa0d496", "Activated lifecycle source digest differs.");
            Dictionary<string, object> lifecycle = Dictionary(protocolInventory["lifecycle"]);
            List<object> variants = List(lifecycle, "variants");
            for (int index = 4; index < 6; index++)
            {
                List<object> states = List(Dictionary(variants[index]), "states");
                Check((string)states[30] == "TokenMintAuthorized", "Activated lifecycle insertion differs.");
                states.Insert(31, "TokenMintAuthorizedSent");
            }
            Check(Canonical(lifecycle) == Canonical(inventory["lifecycle"]), "Activated lifecycle differs.");
            foreach (object associationItem in associations)
            {
                Dictionary<string, object> association = Dictionary(associationItem);
                string state = String(association, "stateAssoc");
                if (String(association, "channel") == "WorkerApp"
                    && String(association, "mandatoryTailClass") == "Mandatory")
                {
                    Check(state != "None", "Activated mandatory WorkerApp state is missing.");
                }
                foreach (object variantItem in variants)
                {
                    Dictionary<string, object> variant = Dictionary(variantItem);
                    string associationProfile = String(association, "profile");
                    if (associationProfile != "Any"
                        && associationProfile != String(variant, "profile")) { continue; }
                    Check(state == "None" || List(variant, "states").Contains(state),
                        "Activated association names an absent lifecycle state.");
                }
            }
            Dictionary<string, Dictionary<string, object>> types = TypeIndex(schemaBytes);
            Dictionary<string, Dictionary<string, BigInteger>> sizes = new Dictionary<string, Dictionary<string, BigInteger>>(StringComparer.Ordinal);
            foreach (string profile in Profiles) { sizes.Add(profile, CalculateSizes(types, profile)); }
            List<object> rows = new List<object>();
            string[] channels = { "WorkerApp", "BrokerControl", "LocalIpc" };
            string[][] directions = { new string[] { "HostToWorker", "WorkerToHost" }, new string[] { "HostToBroker", "BrokerToHost" },
                new string[] { "WorkerToBroker", "BrokerToWorker" } };
            foreach (object variantItem in variants)
            {
                Dictionary<string, object> variant = Dictionary(variantItem);
                string profile = String(variant, "profile");
                List<object> states = List(variant, "states");
                Dictionary<string, int> indices = new Dictionary<string, int>(StringComparer.Ordinal);
                for (int index = 0; index < states.Count; index++) { indices.Add((string)states[index], index); }
                int channelCount = profile == "InteractiveSeat" ? 1 : 3;
                object[] variantRows = new object[states.Count * channelCount * 2];
                for (int channel = 0; channel < channelCount; channel++)
                {
                    for (int direction = 0; direction < 2; direction++)
                    {
                        SortedSet<int> remaining = new SortedSet<int>();
                        Dictionary<int, List<int>> ending = new Dictionary<int, List<int>>();
                        for (int index = 0; index < associations.Count; index++)
                        {
                            Dictionary<string, object> message = Dictionary(associations[index]);
                            if (String(message, "channel") != channels[channel] || String(message, "direction") != directions[channel][direction]
                                || String(message, "mandatoryTailClass") != "Mandatory"
                                || (String(message, "profile") != "Any" && String(message, "profile") != profile)) { continue; }
                            string state = String(message, "stateAssoc");
                            if (state == "None") { remaining.Add(index); continue; }
                            int stateIndex = indices[state];
                            List<int> messages;
                            if (!ending.TryGetValue(stateIndex, out messages)) { messages = new List<int>(); ending.Add(stateIndex, messages); }
                            messages.Add(index);
                        }
                        for (int stateIndex = states.Count - 1; stateIndex >= 0; stateIndex--)
                        {
                            List<int> messages;
                            if (ending.TryGetValue(stateIndex, out messages)) { foreach (int index in messages) { remaining.Add(index); } }
                            List<object> kinds = new List<object>();
                            BigInteger charge = BigInteger.Zero;
                            foreach (int index in remaining)
                            {
                                Dictionary<string, object> message = Dictionary(associations[index]);
                                BigInteger payload = sizes[profile][String(message, "payloadRoot")];
                                kinds.Add(Record("cardinality", 1, "kindId", Integer(message, "kindId"),
                                    "maxPayloadBytes", RequireUInt32(payload), "maxSignedFrameBytes", RequireUInt32(payload + 408),
                                    "name", String(message, "name"), "transcriptChargeBytes", RequireUInt32(payload + 421)));
                                charge += payload + 421;
                            }
                            RequireTailQuota(kinds.Count, charge);
                            variantRows[stateIndex * channelCount * 2 + channel * 2 + direction] = Record(
                                "channel", channels[channel], "direction", directions[channel][direction], "kinds", kinds,
                                "lifecycleVariant", String(variant, "name"), "profile", profile, "records", kinds.Count,
                                "state", states[stateIndex], "wrapperBytes", RequireUInt32(charge));
                        }
                    }
                }
                rows.AddRange(variantRows);
            }
            Check(rows.Count == 1386 && Canonical(Record("schemaId", "PspktOverlayMandatoryTailScheduleV1", "schemaVersion", 1, "rows", rows))
                == Canonical(Extract(outputs["certification/overlay/schema/mandatory-tail-schedule.v1.json"])), "Activated schedule differs.");
            Dictionary<string, object> matrices = Dictionary(Extract(outputs["certification/overlay/schema/overlay-matrices.v1.json"]));
            foreach (object item in List(matrices, "messageRows"))
            {
                Dictionary<string, object> row = Dictionary(item);
                BigInteger payload = sizes[String(row, "profile")][String(row, "payloadRoot")];
                Check(Integer(row, "maxPayloadBytes") == RequireUInt32(payload)
                    && Integer(row, "maxSignedFrameBytes") == RequireUInt32(payload + 408)
                    && Integer(row, "transcriptChargeBytes") == RequireUInt32(payload + 421), "Activated message matrix size differs.");
            }
            foreach (object item in List(matrices, "transcriptTypeRows"))
            {
                Dictionary<string, object> row = Dictionary(item);
                Check(Integer(row, "maxPayloadBytes") == RequireUInt32(sizes[Profiles[1]][String(row, "name")]), "Activated transcript size differs.");
            }
        }

        private static string Hash(byte[] bytes)
        {
            using (SHA256 digest = SHA256.Create())
            {
                return BitConverter.ToString(digest.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }


        public static ulong RequireUInt32(BigInteger value)
        {
            Check(value.Sign >= 0 && value <= new BigInteger(uint.MaxValue), "Overlay verification size exceeds UInt32.");
            return (ulong)value;
        }

        internal static void RequireTailQuota(int recordCount, BigInteger wrapperBytes)
        {
            Check(recordCount <= 5535 && wrapperBytes <= 29360128,
                "Activated schedule quota differs.");
        }

        public static void VerifyMaxima(byte[] schemaBytes, byte[] maximaBytes)
        {
            Dictionary<string, Dictionary<string, object>> types = TypeIndex(schemaBytes);
            Dictionary<string, BigInteger>[] profileSizes = { CalculateSizes(types, Profiles[0]), CalculateSizes(types, Profiles[1]) };
            List<object> expected = new List<object>();
            string[] roots = { "WorkerSessionKeyCertificateV1", "BootstrapWorkerContext", "S4UMintSlotV1", "MintAttestedV1",
                "MintRevokedV1", "IsolationAdmission", "IsolationExit", "ServiceControlEventNodeProofV1" };
            ulong[] maximums = { 1431, 1529, 1958, 2078, 744, 744, 912, 912, 114, 114, 5167, 5287, 780, 884, 644, 644 };
            for (int index = 0; index < roots.Length; index++)
            {
                for (int profile = 0; profile < Profiles.Length; profile++)
                {
                    string name = roots[index];
                    ulong maximum = RequireUInt32(profileSizes[profile][name]);
                    Check(maximum == maximums[index * 2 + profile], "Activated payload size differs: " + name);
                    expected.Add(Record("name", name, "typeId", Integer(types[name], "typeId"),
                        "profile", Profiles[profile], "maxPayloadBytes", maximum));
                }
            }
            Check(Canonical(Record("schemaId", "PspktOverlayMaximaV1", "schemaVersion", 1, "rows", expected))
                == Canonical(Extract(maximaBytes)), "Activated maxima differs.");
        }

        private static Dictionary<string, Dictionary<string, object>> TypeIndex(byte[] schemaBytes)
        {
            Dictionary<string, Dictionary<string, object>> types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in List(Dictionary(Extract(schemaBytes)), "types"))
            {
                Dictionary<string, object> type = Dictionary(item);
                types.Add(String(type, "name"), type);
            }
            return types;
        }

        private static Dictionary<string, BigInteger> CalculateSizes(Dictionary<string, Dictionary<string, object>> types, string profile)
        {
            Dictionary<string, List<Dictionary<string, object>>> fields = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
            Dictionary<string, HashSet<string>> unresolved = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            Dictionary<string, List<string>> dependents = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            Dictionary<string, BigInteger> sizes = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
            Queue<string> ready = new Queue<string>();
            foreach (KeyValuePair<string, Dictionary<string, object>> pair in types)
            {
                Dictionary<string, object> type = pair.Value;
                List<Dictionary<string, object>> applicable = new List<Dictionary<string, object>>();
                HashSet<string> dependencies = new HashSet<string>(StringComparer.Ordinal);
                if (String(type, "production") == "Named")
                {
                    Dictionary<string, Dictionary<string, object>> selected = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
                    foreach (object item in List(type, "fields"))
                    {
                        Dictionary<string, object> field = Dictionary(item);
                        string scope = Optional(field, "profile", "Any");
                        if (Optional(field, "status", "Required") == "Required" && (scope == "Any" || scope == profile))
                        {
                            selected.Add(FieldIdentity(field), field);
                        }
                    }
                    HashSet<string> forbidden = new HashSet<string>(StringComparer.Ordinal);
                    foreach (object item in List(type, "fields"))
                    {
                        Dictionary<string, object> field = Dictionary(item);
                        if (Optional(field, "status", "Required") == "Forbidden" && Optional(field, "profile", "Any") == profile)
                        {
                            forbidden.Add(FieldIdentity(field));
                        }
                    }
                    foreach (KeyValuePair<string, Dictionary<string, object>> field in selected)
                    {
                        if (forbidden.Contains(field.Key)) { continue; }
                        applicable.Add(field.Value);
                        string reference = String(field.Value, "type");
                        if (!Widths.ContainsKey(reference) && reference != "BoundedBytes" && reference != "OpaqueUtf16")
                        {
                            dependencies.Add(reference);
                        }
                    }
                }
                else if (type.ContainsKey("elementType"))
                {
                    string element = String(type, "elementType");
                    if (!Widths.ContainsKey(element)) { dependencies.Add(element); }
                }
                fields.Add(pair.Key, applicable);
                unresolved.Add(pair.Key, dependencies);
                if (dependencies.Count == 0) { ready.Enqueue(pair.Key); }
                foreach (string dependency in dependencies)
                {
                    Check(types.ContainsKey(dependency), "Activated payload dependency is missing: " + dependency);
                    List<string> owners;
                    if (!dependents.TryGetValue(dependency, out owners))
                    {
                        owners = new List<string>();
                        dependents.Add(dependency, owners);
                    }
                    owners.Add(pair.Key);
                }
            }
            while (ready.Count != 0)
            {
                string name = ready.Dequeue();
                Dictionary<string, object> type = types[name];
                string production = String(type, "production");
                BigInteger total = BigInteger.Zero;
                if (production == "EnumU16") { total = 2; }
                else if (production == "SemanticString") { total = new BigInteger(Integer(type, "maxBytes")) + 4; }
                else if (production == "List" || production == "Set")
                {
                    total = new BigInteger(Integer(type, "maxCount")) * (4 + FieldWidth(String(type, "elementType"), null, sizes)) + 4;
                }
                else
                {
                    Check(production == "Named", "Unsupported activated payload production.");
                    foreach (Dictionary<string, object> field in fields[name])
                    {
                        total += 6 + FieldWidth(String(field, "type"), field, sizes);
                    }
                }
                RequireUInt32(total);
                sizes.Add(name, total);
                List<string> owners;
                if (dependents.TryGetValue(name, out owners))
                {
                    foreach (string owner in owners)
                    {
                        Check(unresolved[owner].Remove(name), "Activated payload dependency retirement differs.");
                        if (unresolved[owner].Count == 0) { ready.Enqueue(owner); }
                    }
                }
            }
            Check(sizes.Count == types.Count, "Activated payload dependencies contain a cycle.");
            return sizes;
        }

        private static BigInteger FieldWidth(string name, Dictionary<string, object> field, Dictionary<string, BigInteger> sizes)
        {
            ulong width;
            if (Widths.TryGetValue(name, out width)) { return new BigInteger(width); }
            if (name == "BoundedBytes") { return new BigInteger(Integer(field, "maxBytes")) + 4; }
            if (name == "OpaqueUtf16") { return new BigInteger(Integer(field, "maxCodeUnits")) * 2 + 4; }
            return sizes[name];
        }

        private static string FieldIdentity(Dictionary<string, object> field)
        {
            Dictionary<string, object> identity = new Dictionary<string, object>(field, StringComparer.Ordinal);
            if (identity.ContainsKey("profile")) { Check(identity.Remove("profile"), "Missing field profile."); }
            if (identity.ContainsKey("status")) { Check(identity.Remove("status"), "Missing field status."); }
            return Canonical(identity);
        }

        private static string Optional(Dictionary<string, object> value, string name, string absent)
        {
            return value.ContainsKey(name) ? String(value, name) : absent;
        }

        public static void VerifyAssignments(byte[] baseBytes, byte[] overlayBytes, byte[] mapBytes)
        {
            List<object> expected = new List<object>();
            Dictionary<string, ulong> typeIds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            Dictionary<string, ulong> nextFields = new Dictionary<string, ulong>(StringComparer.Ordinal);
            Dictionary<string, ulong> nextKinds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            HashSet<string> channels = new HashSet<string>(StringComparer.Ordinal);
            Dictionary<string, ulong> kindIds = new Dictionary<string, ulong>(StringComparer.Ordinal);
            ulong nextType = 1;
            Dictionary<string, object>[] catalogs = { Dictionary(Extract(baseBytes)), Dictionary(Extract(overlayBytes)) };
            for (int catalogIndex = 0; catalogIndex < catalogs.Length; catalogIndex++)
            {
                List<object> entries = List(catalogs[catalogIndex], "entries");
                string catalog = catalogIndex == 0 ? "base" : "overlay";
                for (int index = 0; index < entries.Count; index++)
                {
                    if (catalogIndex == 0 && index >= 186 && index <= 197) { continue; }
                    int ordinal = index + 1 + (catalogIndex == 0 ? (index >= 198 ? -12 : 0) : (index >= 143 ? 12 : 0));
                    Dictionary<string, object> entry = Dictionary(entries[index]);
                    string operation = String(entry, "op");
                    if (operation == "type" || operation == "overlay-type")
                    {
                        string name = String(entry, "name");
                        ulong typeId = operation == "type" ? nextType++ : Integer(entry, "id");
                        typeIds.Add(name, typeId);
                        nextFields.Add(name, 1);
                        if (operation == "type") { expected.Add(Assignment(catalog, ordinal, "type", name, typeId)); }
                    }
                    else if (operation == "union")
                    {
                        string discriminator = String(entry, "discriminator");
                        ulong typeId = nextType++;
                        typeIds.Add(discriminator, typeId);
                        expected.Add(Assignment(catalog, ordinal, "type", discriminator, typeId));
                        List<object> branches = List(entry, "branches");
                        for (int branchIndex = 0; branchIndex < branches.Count; branchIndex++)
                        {
                            Dictionary<string, object> branch = Dictionary(branches[branchIndex]);
                            string name = String(branch, "name");
                            Dictionary<string, object> member = Assignment(catalog, ordinal, "enum-member",
                                discriminator + "." + name, (ulong)branchIndex);
                            member.Add("memberIndex", branchIndex);
                            expected.Add(member);
                            ulong branchId = nextType++;
                            typeIds.Add(name, branchId);
                            List<object> fields = List(branch, "fields");
                            for (int fieldIndex = 0; fieldIndex < fields.Count; fieldIndex++)
                            {
                                expected.Add(Assignment(catalog, ordinal, "field",
                                    name + "." + String(Dictionary(fields[fieldIndex]), "name"), (ulong)fieldIndex + 1));
                            }
                            nextFields.Add(name, (ulong)fields.Count + 1);
                            Dictionary<string, object> branchRow = Assignment(catalog, ordinal, "union-branch", name, branchId);
                            branchRow.Add("branchIndex", branchIndex);
                            expected.Add(branchRow);
                        }
                    }
                    else if (operation == "field" || operation == "field-set")
                    {
                        string parent = String(entry, "parent");
                        Check(typeIds.ContainsKey(parent), "Activated assignment parent is undefined: " + parent);
                        ulong id = entry.ContainsKey("id") ? Integer(entry, "id") : nextFields[parent]++;
                        if (typeIds[parent] < 4864)
                        {
                            expected.Add(Assignment(catalog, ordinal, "field", parent + "." + String(entry, "name"), id));
                        }
                    }
                    else if (operation == "message" || operation == "overlay-message")
                    {
                        string channel = String(entry, "channel");
                        if (channels.Add(channel))
                        {
                            ulong typeId = nextType++;
                            typeIds.Add(channel + "MessageKind", typeId);
                            nextKinds.Add(channel, 1);
                            expected.Add(Assignment(catalog, ordinal, "type", channel + "MessageKind", typeId));
                        }
                        string name = String(entry, "name");
                        string identity = channel + ":" + name;
                        ulong id;
                        if (!kindIds.TryGetValue(identity, out id))
                        {
                            id = operation == "message" ? nextKinds[channel]++ : Integer(entry, "id");
                            kindIds.Add(identity, id);
                        }
                        Dictionary<string, object> row = Assignment(catalog, ordinal, "kind", name, id);
                        foreach (string property in new string[] { "channel", "direction", "profile", "mandatoryTailClass", "stateAssoc" })
                        {
                            row.Add(property, String(entry, property));
                        }
                        expected.Add(row);
                    }
                    else
                    {
                        Check(operation == "reserve-illegal-type", "Unexpected activated assignment operation: " + operation);
                        Check(String(entry, "name") == "LocalTranscriptRecordSetV1" && Integer(entry, "id") == 4881,
                            "Activated reservation differs.");
                    }
                }
            }
            Check(expected.Count == 685 && nextType == 91, "Activated assignment count differs.");
            Check(Canonical(expected) == Canonical(Extract(mapBytes)), "Activated assignment map differs.");
        }

        public static void VerifyDeclarationOrder(byte[] baseBytes, byte[] overlayBytes, byte[] schemaBytes)
        {
            List<object> baseEntries = List(Dictionary(Extract(baseBytes)), "entries");
            List<object> overlayEntries = List(Dictionary(Extract(overlayBytes)), "entries");
            List<string> expected = new List<string>();
            HashSet<string> channels = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < baseEntries.Count; index++)
            {
                if (index >= 186 && index <= 197) { continue; }
                AppendDeclarationNames(Dictionary(baseEntries[index]), expected, channels);
            }
            for (int index = 0; index < overlayEntries.Count; index++)
            {
                if (index == 143)
                {
                    expected.Add("IsolationAdmission");
                    expected.Add("IsolationExit");
                }
                AppendDeclarationNames(Dictionary(overlayEntries[index]), expected, channels);
            }
            List<object> declarations = List(Dictionary(Extract(schemaBytes)), "types");
            Check(expected.Count == 112 && declarations.Count == expected.Count, "Activated declaration count differs.");
            for (int index = 0; index < expected.Count; index++)
            {
                Check(String(Dictionary(declarations[index]), "name") == expected[index],
                    "Activated declaration order differs: " + expected[index]);
            }
        }

        private static void AppendDeclarationNames(Dictionary<string, object> entry,
            List<string> names, HashSet<string> channels)
        {
            string operation = String(entry, "op");
            if (operation == "type" || operation == "overlay-type" || operation == "enum")
            {
                names.Add(String(entry, "name"));
            }
            else if (operation == "union")
            {
                names.Add(String(entry, "discriminator"));
                foreach (object branch in List(entry, "branches")) { names.Add(String(Dictionary(branch), "name")); }
            }
            else if (operation == "message" || operation == "overlay-message")
            {
                string channel = String(entry, "channel");
                if (channels.Add(channel)) { names.Add(channel + "MessageKind"); }
            }
        }

        private static Dictionary<string, object> Assignment(string catalog, int ordinal, string category, string name, ulong id)
        {
            return Record("catalog", catalog, "catalogOrdinal", ordinal, "category", category, "name", name,
                "generatedId", id, "schemaId", "PspktGeneratedBaseIdMapV1");
        }

        private static string Canonical(object value)
        {
            StringBuilder builder = new StringBuilder();
            AppendCanonical(builder, value);
            return builder.ToString();
        }

        private static void AppendCanonical(StringBuilder builder, object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties != null)
            {
                string[] names = new string[properties.Count];
                properties.Keys.CopyTo(names, 0);
                System.Array.Sort(names, StringComparer.Ordinal);
                builder.Append('{');
                for (int index = 0; index < names.Length; index++)
                {
                    if (index > 0) { builder.Append(','); }
                    AppendCanonical(builder, names[index]);
                    builder.Append(':');
                    AppendCanonical(builder, properties[names[index]]);
                }
                builder.Append('}');
                return;
            }
            string text = value as string;
            if (text != null)
            {
                builder.Append('"');
                foreach (char character in text)
                {
                    if (character == '"' || character == '\\') { builder.Append('\\'); }
                    if (character < 32) { builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture)); }
                    else { builder.Append(character); }
                }
                builder.Append('"');
                return;
            }
            IEnumerable items = value as IEnumerable;
            if (items != null)
            {
                builder.Append('[');
                bool first = true;
                foreach (object item in items)
                {
                    if (!first) { builder.Append(','); }
                    first = false;
                    AppendCanonical(builder, item);
                }
                builder.Append(']');
                return;
            }
            if (value == null) { builder.Append("null"); }
            else if (value is bool) { builder.Append((bool)value ? "true" : "false"); }
            else if (value is ulong || value is int) { builder.Append(Convert.ToString(value, CultureInfo.InvariantCulture)); }
            else { throw new InvalidDataException("Unsupported activation verification canonical value."); }
        }

        private static void Check(bool condition, string diagnostic)
        {
            if (!condition) { throw new InvalidDataException(diagnostic); }
        }

        private static Dictionary<string, object> Dictionary(object value)
        {
            Dictionary<string, object> result = value as Dictionary<string, object>;
            Check(result != null, "Expected activation verification object.");
            return result;
        }

        private static object Extract(byte[] bytes)
        {
            if (bytes == null) { throw new ArgumentNullException("bytes"); }
            Pspkt.Certification.SchemaCheckResult gate = Pspkt.Certification.SchemaBootstrap.Evaluate("json", bytes, null);
            Check(gate.Accepted, "Activation verifier JSON rejected: " + gate.Reason);
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
                        if (kind == "object") { properties.Add(name, value); }
                        else { items.Add(value); }
                    }
                    reader.ReadEndElement();
                }
                return kind == "object" ? (object)properties : items;
            }
            string content = reader.ReadElementContentAsString();
            if (kind == "number") { return ulong.Parse(content, CultureInfo.InvariantCulture); }
            if (kind == "string") { return content; }
            if (kind == "boolean") { return content == "true"; }
            Check(kind == "null", "Unsupported activation verification element.");
            return null;
        }

        private static List<object> List(Dictionary<string, object> value, string name)
        {
            object result;
            Check(value.TryGetValue(name, out result) && result is List<object>,
                "Expected activation verification array: " + name);
            return (List<object>)result;
        }

        private static ulong Integer(Dictionary<string, object> value, string name)
        {
            object result;
            Check(value.TryGetValue(name, out result) && (result is ulong || result is int),
                "Expected activation verification integer: " + name);
            return Convert.ToUInt64(result, CultureInfo.InvariantCulture);
        }

        private static Dictionary<string, object> Record(params object[] pairs)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
            for (int index = 0; index < pairs.Length; index += 2) { result.Add((string)pairs[index], pairs[index + 1]); }
            return result;
        }

        private static string String(Dictionary<string, object> value, string name)
        {
            object result;
            Check(value.TryGetValue(name, out result) && result is string,
                "Expected activation verification string: " + name);
            return (string)result;
        }
    }
}
