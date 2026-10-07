using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml;
using Pspkt.Certification;
using Pspkt.Certification.FoundationEngine;

namespace Pspkt.Certification.Overlay
{
    public static class OverlayActivationAuthority
    {
        private const string OutputPrefix = "certification/overlay/schema/";
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        private static readonly string[] Profiles = { "InteractiveSeat", "NonInteractiveElevated" };
        private static readonly string[] Channels = { "WorkerApp", "BrokerControl", "LocalIpc" };
        private static readonly string[][] Directions = {
            new string[] { "HostToWorker", "WorkerToHost" },
            new string[] { "HostToBroker", "BrokerToHost" },
            new string[] { "WorkerToBroker", "BrokerToWorker" } };

        public static byte[] Canonicalize(byte[] bytes)
        {
            return Encode(Read(bytes));
        }

        public static byte[] BuildMatrices(byte[] baseBytes, byte[] overlayBytes, byte[] schemaBytes,
            byte[] associationBytes, byte[] scheduleBytes, byte[] lifecycleBytes, byte[] protocolInventoryBytes)
        {
            Dictionary<string, object> schema = Object(Read(schemaBytes));
            PayloadSizes sizes = new PayloadSizes(schema, Object(Read(protocolInventoryBytes)));
            Dictionary<string, Dictionary<string, object>> types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in Array(schema, "types"))
            {
                Dictionary<string, object> type = Object(item);
                types.Add(Text(type, "name"), type);
            }
            Dictionary<string, object>[] catalogs = ActivateCatalogs(baseBytes, overlayBytes);
            Dictionary<string, int> ordinals = new Dictionary<string, int>(StringComparer.Ordinal);
            List<object> overlayEntries = Array(catalogs[1], "entries");
            for (int index = 0; index < overlayEntries.Count; index++)
            {
                Dictionary<string, object> entry = Object(overlayEntries[index]);
                if (Text(entry, "op") == "overlay-type") { ordinals.Add(Text(entry, "name"), index + 1); }
            }
            List<object> activatedTypes = new List<object>();
            foreach (string name in new string[] { "S4UMintSlotV1", "MintAttestedV1", "IsolationAdmission", "IsolationExit", "ServiceControlEventNodeProofV1" })
            {
                Dictionary<string, object> type = types[name];
                activatedTypes.Add(Row("fieldCount", Array(type, "fields").Count,
                    "maxPayloadBytesInteractiveSeat", RequireUInt32(sizes.Get(name, Profiles[0], null)),
                    "maxPayloadBytesNonInteractiveElevated", RequireUInt32(sizes.Get(name, Profiles[1], null)),
                    "name", name, "origin", name == "IsolationAdmission" || name == "IsolationExit" ? "closure" : "seed",
                    "overlayOrdinal", ordinals[name], "typeId", Number(type, "typeId")));
            }
            List<object> variants = Array(Object(Read(lifecycleBytes)), "variants");
            Require(variants.Count == 6
                && Text(Object(variants[4]), "name") == "NonInteractivePS5"
                && Text(Object(variants[5]), "name") == "NonInteractivePS7",
                "Overlay matrix lifecycle variant shape differs.");
            List<object> nonInteractivePS5 = Array(Object(variants[4]), "states");
            List<object> nonInteractivePS7 = Array(Object(variants[5]), "states");
            List<object> associations = Array(Object(Read(associationBytes)), "rows");
            List<object> activatedMessages = new List<object>();
            List<object> messageRows = new List<object>();
            Dictionary<string, List<Dictionary<string, object>>> messageIndex = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
            List<object> transcriptMessages = new List<object>();
            for (int index = 0; index < associations.Count; index++)
            {
                Dictionary<string, object> message = Object(associations[index]);
                string identity = Text(message, "channel") + ":" + Text(message, "name");
                List<Dictionary<string, object>> identities;
                if (!messageIndex.TryGetValue(identity, out identities))
                {
                    identities = new List<Dictionary<string, object>>();
                    messageIndex.Add(identity, identities);
                }
                identities.Add(message);
                ulong id = Number(message, "kindId");
                if (id == 4368 || id == 4370 || id == 4371 || id == 4374)
                {
                    int ps5StateIndex = nonInteractivePS5.IndexOf(Text(message, "stateAssoc"));
                    int ps7StateIndex = nonInteractivePS7.IndexOf(Text(message, "stateAssoc"));
                    Require(ps5StateIndex >= 0 && ps7StateIndex >= 0,
                        "Activated message state is missing from matrix lifecycle.");
                    Dictionary<string, object> row = new Dictionary<string, object>(message, StringComparer.Ordinal);
                    Require(row.Remove("profile"), "Activated message profile is missing.");
                    row.Add("stateIndexNonInteractivePS5", ps5StateIndex);
                    row.Add("stateIndexNonInteractivePS7", ps7StateIndex);
                    activatedMessages.Add(row);
                }
                foreach (string profile in Profiles)
                {
                    if (Text(message, "profile") != "Any" && Text(message, "profile") != profile) { continue; }
                    BigInteger payload = sizes.Get(Text(message, "payloadRoot"), profile, null);
                    Dictionary<string, object> row = new Dictionary<string, object>(message, StringComparer.Ordinal);
                    Require(row.Remove("stateAssoc"), "Activated message state is missing.");
                    row["profile"] = profile;
                    row.Add("associationOrdinal", index + 1);
                    row.Add("maxPayloadBytes", RequireUInt32(payload));
                    row.Add("maxSignedFrameBytes", RequireUInt32(payload + 408));
                    row.Add("transcriptChargeBytes", RequireUInt32(payload + 421));
                    messageRows.Add(row);
                }
                if (id >= 4377 && id <= 4379)
                {
                    int stateIndex = nonInteractivePS5.IndexOf(Text(message, "stateAssoc"));
                    Require(stateIndex >= 0, "Transcript message state is missing from matrix lifecycle.");
                    Dictionary<string, object> row = Row("stateIndex", stateIndex);
                    foreach (string property in new string[] { "kindId", "name", "direction", "mandatoryTailClass", "stateAssoc" })
                    {
                        row.Add(property, message[property]);
                    }
                    transcriptMessages.Add(row);
                }
            }
            List<object> channelRows = new List<object>();
            Dictionary<string, Dictionary<string, object>> cells = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (string profile in Profiles)
            {
                List<object> variantNames = new List<object>();
                foreach (object item in variants)
                {
                    Dictionary<string, object> variant = Object(item);
                    if (Text(variant, "profile") == profile) { variantNames.Add(Text(variant, "name")); }
                }
                for (int channel = 0; channel < Channels.Length; channel++)
                {
                    if (channel != 0 && profile == Profiles[0]) { continue; }
                    foreach (string direction in Directions[channel])
                    {
                        Dictionary<string, object> row = Row("channel", Channels[channel], "direction", direction,
                            "lifecycleVariants", variantNames, "messageRows", 0, "nonEmptyRows", 0, "peakRecords", 0,
                            "peakWrapperBytes", 0, "profile", profile, "scheduleRows", 0);
                        cells.Add(profile + ":" + Channels[channel] + ":" + direction, row);
                        channelRows.Add(row);
                    }
                }
            }
            foreach (object item in Array(Object(Read(scheduleBytes)), "rows"))
            {
                Dictionary<string, object> row = Object(item);
                Dictionary<string, object> cell = cells[Text(row, "profile") + ":" + Text(row, "channel") + ":" + Text(row, "direction")];
                ulong records = Number(row, "records");
                cell["messageRows"] = Number(cell, "messageRows") + records;
                cell["scheduleRows"] = Number(cell, "scheduleRows") + 1;
                if (records != 0) { cell["nonEmptyRows"] = Number(cell, "nonEmptyRows") + 1; }
                cell["peakRecords"] = Math.Max(Number(cell, "peakRecords"), records);
                cell["peakWrapperBytes"] = Math.Max(Number(cell, "peakWrapperBytes"), Number(row, "wrapperBytes"));
            }
            List<object> collisions = new List<object>();
            foreach (string name in new string[] { "BootstrapHostHello", "Keepalive", "TokenMintAuthorized" })
            {
                Require(messageIndex.ContainsKey("WorkerApp:" + name)
                    && messageIndex["WorkerApp:" + name].Count > 0
                    && messageIndex.ContainsKey("BrokerControl:" + name)
                    && messageIndex["BrokerControl:" + name].Count > 0,
                    "Cross-channel collision source shape differs: " + name);
                collisions.Add(Collision("crossChannelName", messageIndex["WorkerApp:" + name][0], messageIndex["BrokerControl:" + name][0]));
            }
            foreach (string identity in new string[] { "WorkerApp:Keepalive", "BrokerControl:Keepalive", "BrokerControl:BrokerFailure", "LocalIpc:LocalKeepalive", "LocalIpc:LocalFailure" })
            {
                Require(messageIndex.ContainsKey(identity) && messageIndex[identity].Count == 2,
                    "Shared collision source shape differs: " + identity);
                collisions.Add(Collision("sharedDirectionKind", messageIndex[identity][0], messageIndex[identity][1]));
            }
            HashSet<string> baseTypeNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (object item in Array(catalogs[0], "entries"))
            {
                Dictionary<string, object> entry = Object(item);
                if (Text(entry, "op") == "type") { baseTypeNames.Add(Text(entry, "name")); }
            }
            List<object> extensions = new List<object>();
            foreach (object item in overlayEntries)
            {
                Dictionary<string, object> entry = Object(item);
                if (Text(entry, "op") != "field-set" || !entry.ContainsKey("id") || Number(entry, "id") < 40) { continue; }
                List<object> fields = Array(entry, "variants");
                Require(fields.Count == 2 && Text(Object(fields[0]), "profile") == Profiles[0]
                    && Text(Object(fields[0]), "status") == "Forbidden"
                    && Text(Object(fields[1]), "profile") == Profiles[1]
                    && Optional(Object(fields[1]), "status", "Required") == "Required", "Activated extension profile shape differs.");
                Dictionary<string, object> field = Object(fields[1]);
                string parent = Text(entry, "parent");
                extensions.Add(Row("parent", parent, "parentKind", baseTypeNames.Contains(parent) ? "baseType" : "unionBranch",
                    "fieldId", Number(entry, "id"), "name", Text(field, "name"), "type", Text(field, "type"),
                    "interactiveStatus", "Forbidden", "nonInteractiveStatus", "Required"));
            }
            List<object> transcriptTypes = new List<object>();
            foreach (string name in new string[] { "LocalTranscriptProofV1", "LocalTranscriptChunkV1", "LocalTranscriptRootV1", "LocalTranscriptRootAcceptedV1" })
            {
                Dictionary<string, object> type = types[name];
                transcriptTypes.Add(Row("name", name, "typeId", Number(type, "typeId"), "fieldCount", Array(type, "fields").Count,
                    "maxPayloadBytes", RequireUInt32(sizes.Get(name, Profiles[1], null))));
            }
            List<object> links = new List<object> {
                Link("digestReference", "LocalTranscriptProofV1", "localTranscriptRootDigest", "LocalTranscriptRootV1", "*"),
                Link("digestReference", "LocalTranscriptRootAcceptedV1", "localTranscriptRootDigest", "LocalTranscriptRootV1", "*"),
                Link("digestReference", "LocalTranscriptRootAcceptedV1", "localTranscriptProofDigest", "LocalTranscriptProofV1", "*") };
            HashSet<string> equalityNames = new HashSet<string>(new string[] {
                "localChannelBinding", "workerToBrokerRecordCount", "brokerToWorkerRecordCount",
                "workerToBrokerWrapperInclusiveBytes", "brokerToWorkerWrapperInclusiveBytes",
                "recordSetDigest", "workerToBrokerChunkCount", "brokerToWorkerChunkCount", "localBootstrapCompleteness" }, StringComparer.Ordinal);
            foreach (object item in Array(types["LocalTranscriptProofV1"], "fields"))
            {
                string name = Text(Object(item), "name");
                if (equalityNames.Contains(name)) { links.Add(Link("proofRootEquality", "LocalTranscriptProofV1", name, "LocalTranscriptRootV1", name)); }
            }
            return Encode(Row("schemaId", "PspktOverlayMatricesV1", "schemaVersion", 1, "activatedTypes", activatedTypes,
                "activatedMessages", activatedMessages, "messageRows", messageRows, "channelRows", channelRows,
                "collisionRows", collisions, "extensionRows", extensions, "s4uRows", Read(BuildS4uRows(schemaBytes)),
                "transcriptTypeRows", transcriptTypes, "transcriptMessageRows", transcriptMessages, "transcriptLinkRows", links));
        }

        public static byte[] BuildMaxima(byte[] schemaBytes, byte[] protocolInventoryBytes)
        {
            Dictionary<string, object> schema = Object(Read(schemaBytes));
            PayloadSizes sizes = new PayloadSizes(schema, Object(Read(protocolInventoryBytes)));
            Dictionary<string, ulong> ids = new Dictionary<string, ulong>(StringComparer.Ordinal);
            foreach (object item in Array(schema, "types"))
            {
                Dictionary<string, object> type = Object(item);
                ids.Add(Text(type, "name"), Number(type, "typeId"));
            }
            List<object> rows = new List<object>();
            foreach (string name in new string[] { "WorkerSessionKeyCertificateV1", "BootstrapWorkerContext",
                "S4UMintSlotV1", "MintAttestedV1", "MintRevokedV1", "IsolationAdmission", "IsolationExit", "ServiceControlEventNodeProofV1" })
            {
                foreach (string profile in Profiles)
                {
                    rows.Add(Row("name", name, "typeId", ids[name], "profile", profile,
                        "maxPayloadBytes", RequireUInt32(sizes.Get(name, profile, null))));
                }
            }
            return Encode(Row("schemaId", "PspktOverlayMaximaV1", "schemaVersion", 1, "rows", rows));
        }

        private static Dictionary<string, object> Collision(string category, Dictionary<string, object> first, Dictionary<string, object> second)
        {
            return Row("category", category, "key", Text(first, "name"), "firstChannel", Text(first, "channel"),
                "firstDirection", Text(first, "direction"), "firstId", Number(first, "kindId"), "firstPayloadRoot", Text(first, "payloadRoot"),
                "secondChannel", Text(second, "channel"), "secondDirection", Text(second, "direction"),
                "secondId", Number(second, "kindId"), "secondPayloadRoot", Text(second, "payloadRoot"));
        }

        private static Dictionary<string, object> Link(string category, string sourceType, string sourceField, string targetType, string targetField)
        {
            return Row("category", category, "sourceType", sourceType, "sourceField", sourceField, "targetType", targetType, "targetField", targetField);
        }

        public static byte[] BuildSchedule(byte[] schemaBytes, byte[] associationBytes,
            byte[] lifecycleBytes, byte[] protocolInventoryBytes)
        {
            PayloadSizes sizes = new PayloadSizes(Object(Read(schemaBytes)), Object(Read(protocolInventoryBytes)));
            List<object> associations = Array(Object(Read(associationBytes)), "rows");
            Dictionary<string, List<Dictionary<string, object>>> cells = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
            foreach (string profile in Profiles)
            {
                for (int channel = 0; channel < Channels.Length; channel++)
                {
                    if (channel != 0 && profile == Profiles[0]) { continue; }
                    foreach (string direction in Directions[channel])
                    {
                        cells.Add(profile + ":" + Channels[channel] + ":" + direction, new List<Dictionary<string, object>>());
                    }
                }
            }
            foreach (object item in associations)
            {
                Dictionary<string, object> message = Object(item);
                if (Text(message, "mandatoryTailClass") != "Mandatory") { continue; }
                foreach (string profile in Profiles)
                {
                    if (Text(message, "profile") != "Any" && Text(message, "profile") != profile) { continue; }
                    string key = profile + ":" + Text(message, "channel") + ":" + Text(message, "direction");
                    Require(cells.ContainsKey(key), "Activated message profile is inapplicable: " + key);
                    cells[key].Add(message);
                }
            }
            List<object> rows = new List<object>(1386);
            foreach (object item in Array(Object(Read(lifecycleBytes)), "variants"))
            {
                Dictionary<string, object> variant = Object(item);
                string profile = Text(variant, "profile");
                List<object> states = Array(variant, "states");
                Dictionary<string, int> indices = new Dictionary<string, int>(StringComparer.Ordinal);
                for (int index = 0; index < states.Count; index++) { indices.Add((string)states[index], index); }
                for (int stateIndex = 0; stateIndex < states.Count; stateIndex++)
                {
                    for (int channel = 0; channel < Channels.Length; channel++)
                    {
                        if (channel != 0 && profile == Profiles[0]) { continue; }
                        foreach (string direction in Directions[channel])
                        {
                            List<object> kinds = new List<object>();
                            BigInteger wrapperBytes = BigInteger.Zero;
                            foreach (Dictionary<string, object> message in cells[profile + ":" + Channels[channel] + ":" + direction])
                            {
                                string state = Text(message, "stateAssoc");
                                int associatedIndex;
                                if (state != "None")
                                {
                                    Require(indices.TryGetValue(state, out associatedIndex), "Activated message state is missing: " + state);
                                    if (associatedIndex < stateIndex) { continue; }
                                }
                                BigInteger payload = sizes.Get(Text(message, "payloadRoot"), profile, null);
                                BigInteger frame = payload + 408;
                                BigInteger charge = frame + 13;
                                kinds.Add(Row("cardinality", 1, "kindId", Number(message, "kindId"),
                                    "maxPayloadBytes", RequireUInt32(payload), "maxSignedFrameBytes", RequireUInt32(frame),
                                    "name", Text(message, "name"), "transcriptChargeBytes", RequireUInt32(charge)));
                                wrapperBytes += charge;
                            }
                            RequireTailQuota(kinds.Count, wrapperBytes);
                            rows.Add(Row("channel", Channels[channel], "direction", direction, "kinds", kinds,
                                "lifecycleVariant", Text(variant, "name"), "profile", profile, "records", kinds.Count,
                                "state", states[stateIndex], "wrapperBytes", RequireUInt32(wrapperBytes)));
                        }
                    }
                }
            }
            Require(rows.Count == 1386, "Activated schedule count differs.");
            return Encode(Row("schemaId", "PspktOverlayMandatoryTailScheduleV1", "schemaVersion", 1, "rows", rows));
        }

        public static ulong RequireUInt32(BigInteger value)
        {
            Require(value >= BigInteger.Zero && value <= uint.MaxValue, "Overlay activation size exceeds UInt32.");
            return (ulong)value;
        }

        internal static void RequireTailQuota(int recordCount, BigInteger wrapperBytes)
        {
            Require(recordCount <= 5535 && wrapperBytes <= 29360128,
                "Activated mandatory tail quota exceeded.");
        }

        public static byte[] BuildAssociations(byte[] baseBytes, byte[] overlayBytes, byte[] mapBytes)
        {
            Dictionary<string, object>[] catalogs = ActivateCatalogs(baseBytes, overlayBytes);
            Dictionary<string, Dictionary<string, object>> kinds = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            foreach (object item in (List<object>)Read(mapBytes))
            {
                Dictionary<string, object> row = Object(item);
                if (Text(row, "category") != "kind") { continue; }
                kinds.Add(Text(row, "catalog") + ":" + Number(row, "catalogOrdinal").ToString(CultureInfo.InvariantCulture), row);
            }
            List<object> rows = new List<object>();
            for (int catalogIndex = 0; catalogIndex < catalogs.Length; catalogIndex++)
            {
                List<object> entries = Array(catalogs[catalogIndex], "entries");
                for (int index = 0; index < entries.Count; index++)
                {
                    Dictionary<string, object> entry = Object(entries[index]);
                    string operation = Text(entry, "op");
                    if (operation != "message" && operation != "overlay-message") { continue; }
                    string key = (catalogIndex == 0 ? "base:" : "overlay:") + (index + 1).ToString(CultureInfo.InvariantCulture);
                    Dictionary<string, object> kind;
                    Require(kinds.TryGetValue(key, out kind), "Activated message assignment is missing: " + key);
                    Dictionary<string, object> row = Row("kindId", Number(kind, "generatedId"), "payloadRoot", Text(entry, "payloadRoot"));
                    foreach (string property in new string[] { "channel", "direction", "mandatoryTailClass", "name", "profile", "stateAssoc" })
                    {
                        Require(Text(entry, property) == Text(kind, property), "Activated message assignment differs: " + key);
                        row.Add(property, Text(entry, property));
                    }
                    ValidateActivatedMessage(row);
                    rows.Add(row);
                }
            }
            Require(rows.Count == 35 && kinds.Count == 35, "Activated association count differs.");
            return Encode(Row("schemaId", "PspktProtocolMessageAssociationV1", "schemaVersion", 1, "rows", rows));
        }

        private static void ValidateActivatedMessage(Dictionary<string, object> row)
        {
            string name = Text(row, "name");
            if (Text(row, "channel") != "BrokerControl") { return; }
            string payload;
            string direction = "BrokerToHost";
            string tail = "Mandatory";
            string state;
            ulong id;
            if (name == "IsolationAdmission") { id = 4368; payload = name; tail = "Ordinary"; state = "ServiceLaunchAttested"; }
            else if (name == "MintAttested") { id = 4370; payload = "MintAttestedV1"; state = "CandidateAccessProbeAttested"; }
            else if (name == "IsolationExit") { id = 4371; payload = name; state = "WorkerExitObserved"; }
            else if (name == "MintRevoked") { id = 4374; payload = "MintRevokedV1"; direction = "HostToBroker"; state = "TokenMintAuthorizedSent"; }
            else { return; }
            Require(Number(row, "kindId") == id && Text(row, "payloadRoot") == payload
                && Text(row, "direction") == direction && Text(row, "mandatoryTailClass") == tail
                && Text(row, "stateAssoc") == state && Text(row, "profile") == "NonInteractiveElevated",
                "Activated message row differs: BrokerControl:" + name);
        }

        public static byte[] BuildS4uRows(byte[] schemaBytes)
        {
            List<object> rows = new List<object>();
            HashSet<string> numericTypes = new HashSet<string>(
                new string[] { "U8", "U16", "U32", "U64", "FILETIME", "QPC" }, StringComparer.Ordinal);
            foreach (object item in Array(Object(Read(schemaBytes)), "types"))
            {
                Dictionary<string, object> declaration = Object(item);
                if (Text(declaration, "name") != "S4UMintSlotV1") { continue; }
                Require(Number(declaration, "typeId") == 4866 && Text(declaration, "production") == "Named",
                    "S4U standalone declaration differs.");
                foreach (object fieldItem in Array(declaration, "fields"))
                {
                    Dictionary<string, object> field = Object(fieldItem);
                    string type = Text(field, "type");
                    rows.Add(Row("fieldId", Number(field, "fieldId"), "name", Text(field, "name"),
                        "type", type, "numeric", numericTypes.Contains(type)));
                }
            }
            Require(rows.Count == 28, "S4U field count differs.");
            return Encode(rows);
        }

        public static IDictionary<string, byte[]> GenerateDeclarations(byte[] baseBytes, byte[] overlayBytes,
            ProtocolCatalogContractV2 contract)
        {
            if (contract == null) { throw new ArgumentNullException("contract"); }
            Dictionary<string, object>[] catalogs = ActivateCatalogs(baseBytes, overlayBytes);
            ProtocolCatalogResultV2 result = ProtocolCatalogEngineV2.Evaluate(
                Encode(catalogs[0]), Encode(catalogs[1]), contract);
            Require(result.Accepted, "Overlay activation engine rejected: " + result.Reason);
            Dictionary<string, byte[]> outputs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            outputs.Add(OutputPrefix + "protocol-schema.v1.json", result.SchemaBytes);
            outputs.Add(OutputPrefix + "generated-base-id-map.v1.json", result.IdMapBytes);
            return outputs;
        }

        public static byte[] DeriveLifecycle(byte[] protocolInventoryBytes)
        {
            Dictionary<string, object> inventory = Object(Read(protocolInventoryBytes));
            Dictionary<string, object> lifecycle = Object(inventory["lifecycle"]);
            List<object> variants = Array(lifecycle, "variants");
            string[] names = { "InteractiveWindowsTerminalPS5", "InteractiveWindowsTerminalPS7",
                "InteractiveConhostPS5", "InteractiveConhostPS7", "NonInteractivePS5", "NonInteractivePS7" };
            int[] counts = { 73, 72, 72, 71, 67, 66 };
            Require(variants.Count == names.Length, "Overlay lifecycle variant count differs.");
            for (int index = 0; index < names.Length; index++)
            {
                Dictionary<string, object> variant = Object(variants[index]);
                List<object> states = Array(variant, "states");
                Require(Text(variant, "name") == names[index] && states.Count == counts[index],
                    "Overlay lifecycle source variant differs: " + names[index]);
                if (index >= 4)
                {
                    Require((string)states[30] == "TokenMintAuthorized" && !states.Contains("TokenMintAuthorizedSent"),
                        "Overlay lifecycle insertion boundary differs.");
                    states.Insert(31, "TokenMintAuthorizedSent");
                }
            }
            return Encode(lifecycle);
        }

        private static Dictionary<string, object>[] ActivateCatalogs(byte[] baseBytes, byte[] overlayBytes)
        {
            Dictionary<string, object> baseCatalog = Object(Read(baseBytes));
            Dictionary<string, object> overlayCatalog = Object(Read(overlayBytes));
            Require(Text(baseCatalog, "schemaId") == "PspktProtocolBaseCatalogV1"
                && Text(baseCatalog, "space") == "protocol-base" && Number(baseCatalog, "schemaVersion") == 1
                && baseCatalog.Count == 4, "Overlay activation base catalog identity differs.");
            Require(Text(overlayCatalog, "schemaId") == "PspktProtocolOverlayCatalogV1"
                && Text(overlayCatalog, "space") == "protocol-overlay" && Number(overlayCatalog, "schemaVersion") == 1
                && overlayCatalog.Count == 4, "Overlay activation overlay catalog identity differs.");
            List<object> sourceBase = Array(baseCatalog, "entries");
            Require(sourceBase.Count == 308, "Overlay activation base operation count differs.");
            List<object> retainedBase = new List<object>(296);
            List<object> rehomed = new List<object>(12);
            int fieldId = 0;
            for (int index = 0; index < sourceBase.Count; index++)
            {
                if (index < 186 || index > 197)
                {
                    retainedBase.Add(sourceBase[index]);
                    continue;
                }
                Dictionary<string, object> entry = Object(sourceBase[index]);
                if (index == 186 || index == 194)
                {
                    string name = index == 186 ? "IsolationAdmission" : "IsolationExit";
                    Require(Text(entry, "op") == "type" && Text(entry, "name") == name
                        && Text(entry, "production") == "Named" && entry.Count == 3,
                        "Overlay activation rehome declaration differs: " + name);
                    rehomed.Add(Row("op", "overlay-type", "name", name, "production", "Named",
                        "id", index == 186 ? 4872 : 4873));
                    fieldId = 0;
                }
                else
                {
                    Require(Text(entry, "op") == "field" && entry.Count == 4,
                        "Overlay activation rehome field differs.");
                    rehomed.Add(Row("op", "field-set", "parent", Text(entry, "parent"), "name", Text(entry, "name"),
                        "id", ++fieldId, "variants", new List<object> {
                            Row("name", Text(entry, "name"), "type", Text(entry, "type")) }));
                }
            }
            List<object> sourceOverlay = Array(overlayCatalog, "entries");
            Require(sourceOverlay.Count >= 144, "Overlay activation insertion boundary is missing.");
            List<object> activatedOverlay = new List<object>(sourceOverlay.Count + rehomed.Count);
            for (int index = 0; index < sourceOverlay.Count; index++)
            {
                if (index == 143) { activatedOverlay.AddRange(rehomed); }
                activatedOverlay.Add(sourceOverlay[index]);
            }
            baseCatalog["entries"] = retainedBase;
            overlayCatalog["entries"] = activatedOverlay;
            return new Dictionary<string, object>[] { baseCatalog, overlayCatalog };
        }

        private static List<object> Array(Dictionary<string, object> value, string name)
        {
            object item;
            Require(value.TryGetValue(name, out item) && item is List<object>, "Expected overlay array: " + name);
            return (List<object>)item;
        }

        private static byte[] Encode(object value)
        {
            StringBuilder builder = new StringBuilder();
            Append(builder, value);
            return Utf8.GetBytes(builder.ToString());
        }

        private static void Append(StringBuilder builder, object value)
        {
            Dictionary<string, object> properties = value as Dictionary<string, object>;
            if (properties != null)
            {
                List<string> keys = new List<string>(properties.Keys);
                keys.Sort(StringComparer.Ordinal);
                builder.Append('{');
                for (int index = 0; index < keys.Count; index++)
                {
                    if (index != 0) { builder.Append(','); }
                    Append(builder, keys[index]);
                    builder.Append(':');
                    Append(builder, properties[keys[index]]);
                }
                builder.Append('}');
            }
            else if (value is string)
            {
                builder.Append('"');
                foreach (char character in (string)value)
                {
                    if (character == '"' || character == '\\') { builder.Append('\\').Append(character); }
                    else if (character < 32) { builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture)); }
                    else { builder.Append(character); }
                }
                builder.Append('"');
            }
            else if (value is IEnumerable)
            {
                builder.Append('[');
                bool separator = false;
                foreach (object item in (IEnumerable)value)
                {
                    if (separator) { builder.Append(','); }
                    separator = true;
                    Append(builder, item);
                }
                builder.Append(']');
            }
            else if (value is int)
            {
                Require((int)value >= 0, "Overlay canonical integer is negative.");
                builder.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
            }
            else if (value is ulong) { builder.Append(Convert.ToString(value, CultureInfo.InvariantCulture)); }
            else if (value is bool) { builder.Append((bool)value ? "true" : "false"); }
            else if (value == null) { builder.Append("null"); }
            else { throw new InvalidDataException("Unsupported overlay canonical value."); }
        }

        private static ulong Number(Dictionary<string, object> value, string name)
        {
            object item;
            Require(value.TryGetValue(name, out item) && (item is ulong || item is int),
                "Expected overlay integer: " + name);
            return Convert.ToUInt64(item, CultureInfo.InvariantCulture);
        }

        private static Dictionary<string, object> Object(object value)
        {
            Dictionary<string, object> result = value as Dictionary<string, object>;
            Require(result != null, "Expected overlay object.");
            return result;
        }

        private static object Read(byte[] bytes)
        {
            if (bytes == null) { throw new ArgumentNullException("bytes"); }
            SchemaCheckResult gate = SchemaBootstrap.Evaluate("json", bytes, null);
            Require(gate.Accepted, "Overlay activation JSON rejected: " + gate.Reason);
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
                        object value = ReadElement(reader);
                        if (kind == "object") { properties.Add(name, value); }
                        else { items.Add(value); }
                    }
                    reader.ReadEndElement();
                }
                return kind == "object" ? (object)properties : items;
            }
            string content = reader.ReadElementContentAsString();
            if (kind == "string") { return content; }
            if (kind == "number") { return ulong.Parse(content, CultureInfo.InvariantCulture); }
            if (kind == "boolean") { return content == "true"; }
            Require(kind == "null", "Unsupported overlay JSON element.");
            return null;
        }

        private static void Require(bool condition, string diagnostic)
        {
            if (!condition) { throw new InvalidDataException(diagnostic); }
        }

        private static Dictionary<string, object> Row(params object[] pairs)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
            for (int index = 0; index < pairs.Length; index += 2) { result.Add((string)pairs[index], pairs[index + 1]); }
            return result;
        }

        private static string Text(Dictionary<string, object> value, string name)
        {
            object item;
            Require(value.TryGetValue(name, out item) && item is string, "Expected overlay string: " + name);
            return (string)item;
        }

        private sealed class PayloadSizes
        {
            private readonly Dictionary<string, Dictionary<string, object>> _types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            private readonly Dictionary<string, object> _widths;
            private readonly Dictionary<string, BigInteger> _sizes = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
            private readonly HashSet<string> _active = new HashSet<string>(StringComparer.Ordinal);

            internal PayloadSizes(Dictionary<string, object> schema, Dictionary<string, object> inventory)
            {
                foreach (object item in Array(schema, "types"))
                {
                    Dictionary<string, object> type = Object(item);
                    _types.Add(Text(type, "name"), type);
                }
                _widths = Object(inventory["primitiveValueMaxima"]);
            }

            internal BigInteger Get(string name, string profile, Dictionary<string, object> field)
            {
                if (name == "BoundedBytes") { return new BigInteger(Number(field, "maxBytes")) + 4; }
                if (name == "OpaqueUtf16") { return new BigInteger(Number(field, "maxCodeUnits")) * 2 + 4; }
                if (_widths.ContainsKey(name)) { return new BigInteger(Number(_widths, name)); }
                string key = profile + ":" + name;
                BigInteger result;
                if (_sizes.TryGetValue(key, out result)) { return result; }
                Require(_active.Add(key), "Activated payload dependency cycle: " + name);
                Dictionary<string, object> type;
                Require(_types.TryGetValue(name, out type), "Activated payload type is missing: " + name);
                string production = Text(type, "production");
                if (production == "EnumU16") { result = 2; }
                else if (production == "SemanticString") { result = new BigInteger(Number(type, "maxBytes")) + 4; }
                else if (production == "List" || production == "Set")
                {
                    result = new BigInteger(Number(type, "maxCount")) * (4 + Get(Text(type, "elementType"), profile, null)) + 4;
                }
                else
                {
                    Require(production == "Named", "Activated payload production is unsupported: " + production);
                    List<object> fields = Array(type, "fields");
                    HashSet<string> forbidden = new HashSet<string>(StringComparer.Ordinal);
                    foreach (object item in fields)
                    {
                        Dictionary<string, object> candidate = Object(item);
                        if (Optional(candidate, "status", "Required") == "Forbidden" && Optional(candidate, "profile", "Any") == profile)
                        {
                            forbidden.Add(FieldShape(candidate));
                        }
                    }
                    result = BigInteger.Zero;
                    foreach (object item in fields)
                    {
                        Dictionary<string, object> candidate = Object(item);
                        string scope = Optional(candidate, "profile", "Any");
                        if (Optional(candidate, "status", "Required") != "Required" || (scope != "Any" && scope != profile)
                            || forbidden.Contains(FieldShape(candidate))) { continue; }
                        result += 6 + Get(Text(candidate, "type"), profile, candidate);
                    }
                }
                RequireUInt32(result);
                _sizes.Add(key, result);
                Require(_active.Remove(key), "Activated payload sizing state differs.");
                return result;
            }

            private static string FieldShape(Dictionary<string, object> field)
            {
                return Number(field, "fieldId").ToString(CultureInfo.InvariantCulture) + ":" + Text(field, "name") + ":" + Text(field, "type")
                    + ":" + (field.ContainsKey("maxBytes") ? Number(field, "maxBytes").ToString(CultureInfo.InvariantCulture) : "")
                    + ":" + (field.ContainsKey("maxCodeUnits") ? Number(field, "maxCodeUnits").ToString(CultureInfo.InvariantCulture) : "");
            }
        }

        private static string Optional(Dictionary<string, object> value, string name, string absent)
        {
            return value.ContainsKey(name) ? Text(value, name) : absent;
        }
    }
}
