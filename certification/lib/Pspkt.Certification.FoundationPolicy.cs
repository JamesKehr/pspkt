using System;
using System.Collections.Generic;

namespace Pspkt.Certification.FoundationEngine
{
    public sealed class GeneratedIdRange
    {
        private readonly int _end;
        private readonly int _start;

        public GeneratedIdRange(int start, int end)
        {
            if (start < 0 || end < start || end > 65535)
            {
                throw new ArgumentOutOfRangeException("start");
            }
            _start = start;
            _end = end;
        }

        public int End { get { return _end; } }
        public int Start { get { return _start; } }

        public bool Contains(int value)
        {
            return value >= _start && value <= _end;
        }
    }

    public sealed class FoundationPolicyContract
    {
        private readonly bool _assignIds;
        private readonly string[] _allowedOps;
        private readonly string _catalogSchemaId;
        private readonly string[] _channels;
        private readonly string _emitSchemaId;
        private readonly int _fieldIdMax;
        private readonly IDictionary<string, string> _messageEnumNameByChannel;
        private readonly string _namePredicate;
        private readonly string[] _permittedDirections;
        private readonly IDictionary<string, GeneratedIdRange[]> _reservedKindRanges;
        private readonly GeneratedIdRange _reservedTypeRange;

        public FoundationPolicyContract(
            string namePredicate,
            string[] channels,
            IDictionary<string, string> messageEnumNameByChannel,
            string[] permittedDirections,
            IDictionary<string, GeneratedIdRange[]> reservedKindRanges,
            GeneratedIdRange reservedTypeRange,
            int fieldIdMax,
            bool assignIds,
            string catalogSchemaId,
            string emitSchemaId,
            string[] allowedOps)
        {
            if (string.IsNullOrEmpty(namePredicate))
            {
                throw new ArgumentException("A name predicate is required.", "namePredicate");
            }
            if (channels == null || channels.Length == 0)
            {
                throw new ArgumentException("At least one channel is required.", "channels");
            }
            if (messageEnumNameByChannel == null)
            {
                throw new ArgumentNullException("messageEnumNameByChannel");
            }
            if (permittedDirections == null || permittedDirections.Length == 0)
            {
                throw new ArgumentException("At least one direction is required.", "permittedDirections");
            }
            if (reservedKindRanges == null)
            {
                throw new ArgumentNullException("reservedKindRanges");
            }
            if (fieldIdMax < 1 || fieldIdMax > 39)
            {
                throw new ArgumentOutOfRangeException("fieldIdMax");
            }
            if (string.IsNullOrEmpty(catalogSchemaId))
            {
                throw new ArgumentException("A catalog schema identifier is required.", "catalogSchemaId");
            }
            if (string.IsNullOrEmpty(emitSchemaId))
            {
                throw new ArgumentException("An emit schema identifier is required.", "emitSchemaId");
            }
            if (allowedOps == null || allowedOps.Length == 0)
            {
                throw new ArgumentException("At least one operation is required.", "allowedOps");
            }

            _namePredicate = namePredicate;
            _channels = Clone(channels);
            _messageEnumNameByChannel = Clone(messageEnumNameByChannel);
            _permittedDirections = Clone(permittedDirections);
            _reservedKindRanges = CloneRanges(reservedKindRanges);
            _reservedTypeRange = reservedTypeRange;
            _fieldIdMax = fieldIdMax;
            _assignIds = assignIds;
            _catalogSchemaId = catalogSchemaId;
            _emitSchemaId = emitSchemaId;
            _allowedOps = Clone(allowedOps);

            for (int index = 0; index < _channels.Length; index++)
            {
                string channel = _channels[index];
                if (string.IsNullOrEmpty(channel) || !_messageEnumNameByChannel.ContainsKey(channel))
                {
                    throw new ArgumentException("Every channel requires a message enum name.", "messageEnumNameByChannel");
                }
            }
        }

        public string[] AllowedOps { get { return Clone(_allowedOps); } }
        public bool AssignIds { get { return _assignIds; } }
        public string CatalogSchemaId { get { return _catalogSchemaId; } }
        public string[] Channels { get { return Clone(_channels); } }
        public string EmitSchemaId { get { return _emitSchemaId; } }
        public int FieldIdMax { get { return _fieldIdMax; } }
        public IDictionary<string, string> MessageEnumNameByChannel { get { return Clone(_messageEnumNameByChannel); } }
        public string NamePredicate { get { return _namePredicate; } }
        public string[] PermittedDirections { get { return Clone(_permittedDirections); } }
        public IDictionary<string, GeneratedIdRange[]> ReservedKindRanges { get { return CloneRanges(_reservedKindRanges); } }
        public GeneratedIdRange ReservedTypeRange { get { return _reservedTypeRange; } }

        private static string[] Clone(string[] source)
        {
            string[] copy = new string[source.Length];
            Array.Copy(source, copy, source.Length);
            return copy;
        }

        private static IDictionary<string, string> Clone(IDictionary<string, string> source)
        {
            Dictionary<string, string> copy = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in source)
            {
                copy.Add(pair.Key, pair.Value);
            }
            return copy;
        }

        private static IDictionary<string, GeneratedIdRange[]> CloneRanges(IDictionary<string, GeneratedIdRange[]> source)
        {
            Dictionary<string, GeneratedIdRange[]> copy = new Dictionary<string, GeneratedIdRange[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, GeneratedIdRange[]> pair in source)
            {
                GeneratedIdRange[] ranges = pair.Value == null ? new GeneratedIdRange[0] : (GeneratedIdRange[])pair.Value.Clone();
                copy.Add(pair.Key, ranges);
            }
            return copy;
        }
    }

    public static class FoundationPolicy
    {
        public static FoundationPolicyContract Create()
        {
            Dictionary<string, string> messageEnums = new Dictionary<string, string>(StringComparer.Ordinal);
            messageEnums.Add("FoundationAlpha", "FoundationAlphaMessageKind");
            messageEnums.Add("FoundationBeta", "FoundationBetaMessageKind");
            Dictionary<string, GeneratedIdRange[]> reservedKinds = new Dictionary<string, GeneratedIdRange[]>(StringComparer.Ordinal);
            reservedKinds.Add("FoundationAlpha", new GeneratedIdRange[] { new GeneratedIdRange(0x1080, 0x10FF) });
            reservedKinds.Add("FoundationBeta", new GeneratedIdRange[] { new GeneratedIdRange(0x1100, 0x12FF) });
            return new FoundationPolicyContract(
                "^Foundation[A-Z][A-Za-z0-9]*$",
                new string[] { "FoundationAlpha", "FoundationBeta" },
                messageEnums,
                new string[] { "HostToWorker", "WorkerToHost" },
                reservedKinds,
                new GeneratedIdRange(0x1300, 0x13FF),
                39,
                true,
                "PspktFoundationCatalogV1",
                "PspktFoundationSchemaV1",
                new string[] { "primitive", "enum", "type", "field", "message", "union", "delete", "extend", "reserve-illegal-type" });
        }
    }

    public static class FoundationCatalogV1
    {
        public static FoundationCatalogResult Evaluate(byte[] catalogBytes)
        {
            FoundationCatalogEvaluation evaluation = FoundationCatalogEngineV1.EvaluateJson(catalogBytes, FoundationPolicy.Create());
            if (!evaluation.Accepted)
            {
                return FoundationCatalogResult.Failure(evaluation.Reason);
            }
            if (!string.Equals(evaluation.Space, "foundation", StringComparison.Ordinal))
            {
                return FoundationCatalogResult.Failure("missing-property");
            }
            FoundationCatalogExpansion expansion = FoundationCatalogEngineV1.Expand(evaluation, FoundationPolicy.Create());
            if (!expansion.Accepted)
            {
                return FoundationCatalogResult.Failure(expansion.Reason);
            }
            FoundationCatalogAssignment assignment = FoundationCatalogEngineV1.Assign(expansion, FoundationPolicy.Create());
            if (!assignment.Accepted)
            {
                return FoundationCatalogResult.Failure(assignment.Reason, assignment.IdMapBytes, expansion.IrJson);
            }
            return FoundationCatalogEngineV1.Emit(assignment, FoundationPolicy.Create());
        }

        public static FoundationReplayResult Replay(byte[] catalogBytes, byte[] schemaBytes, byte[] mapBytes)
        {
            return FoundationCatalogEngineV1.Replay(catalogBytes, schemaBytes, mapBytes, FoundationPolicy.Create());
        }
    }
}
