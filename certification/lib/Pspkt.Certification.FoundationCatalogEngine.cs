using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Pspkt.Certification;

namespace Pspkt.Certification.FoundationEngine
{
    public sealed class FoundationCatalogEvaluation
    {
        private readonly bool _accepted;
        private readonly string _reason;
        private readonly string _space;
        internal readonly JObject Root;

        internal FoundationCatalogEvaluation(bool accepted, string reason, string space, JObject root)
        {
            _accepted = accepted;
            _reason = reason;
            _space = space;
            Root = root;
        }

        public bool Accepted { get { return _accepted; } }
        public string Reason { get { return _reason; } }
        public string Space { get { return _space; } }
    }

    public sealed class FoundationCatalogExpansion
    {
        private readonly bool _accepted;
        private readonly Dictionary<string, int> _kindNext;
        private readonly string _reason;
        private int _typeNext;
        internal readonly string Ir;
        internal readonly List<CatalogOperation> Operations;
        internal readonly Dictionary<string, CatalogType> Types;

        internal FoundationCatalogExpansion(bool accepted, string reason, List<CatalogOperation> operations, Dictionary<string, CatalogType> types, string ir, string[] channels)
        {
            _accepted = accepted;
            _reason = reason;
            Operations = operations;
            Types = types;
            Ir = ir;
            _typeNext = 1;
            _kindNext = new Dictionary<string, int>(StringComparer.Ordinal);
            if (channels != null)
            {
                for (int index = 0; index < channels.Length; index++)
                {
                    _kindNext[channels[index]] = 1;
                }
            }
        }

        public bool Accepted { get { return _accepted; } }
        public string IrJson { get { return Ir; } }
        public string Reason { get { return _reason; } }
        internal int TypeNext { get { return _typeNext; } set { _typeNext = value; } }

        internal int ReadKindNext(string channel)
        {
            return _kindNext[channel];
        }

        internal void WriteKindNext(string channel, int value)
        {
            _kindNext[channel] = value;
        }
    }

    public sealed class FoundationCatalogAssignment
    {
        private readonly bool _accepted;
        private readonly byte[] _idMapBytes;
        private readonly string _irJson;
        private readonly string _reason;
        private readonly byte[] _schemaBytes;

        internal FoundationCatalogAssignment(bool accepted, string reason, byte[] schemaBytes, byte[] idMapBytes, string irJson)
        {
            _accepted = accepted;
            _reason = reason;
            _schemaBytes = Clone(schemaBytes);
            _idMapBytes = Clone(idMapBytes);
            _irJson = irJson;
        }

        public bool Accepted { get { return _accepted; } }
        public byte[] IdMapBytes { get { return Clone(_idMapBytes); } }
        public string IrJson { get { return _irJson; } }
        public string Reason { get { return _reason; } }
        public byte[] SchemaBytes { get { return Clone(_schemaBytes); } }

        private static byte[] Clone(byte[] source)
        {
            return source == null ? null : (byte[])source.Clone();
        }
    }

    public sealed class FoundationCatalogResult
    {
        private readonly bool _accepted;
        private readonly byte[] _idMapBytes;
        private readonly string _irJson;
        private readonly string _reason;
        private readonly byte[] _schemaBytes;

        internal FoundationCatalogResult(bool accepted, string reason, byte[] schemaBytes, byte[] idMapBytes, string irJson)
        {
            _accepted = accepted;
            _reason = reason;
            _schemaBytes = Clone(schemaBytes);
            _idMapBytes = Clone(idMapBytes);
            _irJson = irJson;
        }

        public bool Accepted { get { return _accepted; } }
        public byte[] IdMapBytes { get { return Clone(_idMapBytes); } }
        public string IrJson { get { return _irJson; } }
        public string Reason { get { return _reason; } }
        public byte[] SchemaBytes { get { return Clone(_schemaBytes); } }

        public static FoundationCatalogResult Failure(string reason)
        {
            return new FoundationCatalogResult(false, reason, null, null, null);
        }

        public static FoundationCatalogResult Failure(string reason, byte[] idMapBytes, string irJson)
        {
            return new FoundationCatalogResult(false, reason, null, idMapBytes, irJson);
        }

        private static byte[] Clone(byte[] source)
        {
            return source == null ? null : (byte[])source.Clone();
        }
    }

    public sealed class FoundationReplayResult
    {
        private readonly bool _accepted;
        private readonly string _reason;

        internal FoundationReplayResult(bool accepted, string reason)
        {
            _accepted = accepted;
            _reason = reason;
        }

        public bool Accepted { get { return _accepted; } }
        public string Reason { get { return _reason; } }
    }

    internal abstract class JNode
    {
    }

    internal sealed class JObject : JNode
    {
        internal readonly Dictionary<string, JNode> Values = new Dictionary<string, JNode>(StringComparer.Ordinal);
    }

    internal sealed class JArray : JNode
    {
        internal readonly List<JNode> Values = new List<JNode>();
    }

    internal sealed class JString : JNode
    {
        internal string Value;
    }

    internal sealed class JInteger : JNode
    {
        internal string Value;
    }

    internal sealed class JBoolean : JNode
    {
        internal bool Value;
    }

    internal sealed class JNull : JNode
    {
    }

    internal sealed class JsonParser
    {
        private readonly string _text;
        private int _index;

        internal JsonParser(byte[] bytes)
        {
            _text = new UTF8Encoding(false, true).GetString(bytes);
        }

        internal JNode Parse()
        {
            SkipWhitespace();
            JNode value = ParseValue();
            SkipWhitespace();
            if (_index != _text.Length)
            {
                throw new FormatException();
            }
            return value;
        }

        private JNode ParseValue()
        {
            if (_index >= _text.Length)
            {
                throw new FormatException();
            }
            char current = _text[_index];
            if (current == '{')
            {
                return ParseObject();
            }
            if (current == '[')
            {
                return ParseArray();
            }
            if (current == '"')
            {
                return new JString { Value = ParseString() };
            }
            if (current == '-' || (current >= '0' && current <= '9'))
            {
                return new JInteger { Value = ParseInteger() };
            }
            if (ReadLiteral("true"))
            {
                return new JBoolean { Value = true };
            }
            if (ReadLiteral("false"))
            {
                return new JBoolean { Value = false };
            }
            if (ReadLiteral("null"))
            {
                return new JNull();
            }
            throw new FormatException();
        }

        private JObject ParseObject()
        {
            JObject result = new JObject();
            _index++;
            SkipWhitespace();
            if (Take('}'))
            {
                return result;
            }
            while (true)
            {
                if (_index >= _text.Length || _text[_index] != '"')
                {
                    throw new FormatException();
                }
                string key = ParseString();
                SkipWhitespace();
                Require(':');
                SkipWhitespace();
                result.Values.Add(key, ParseValue());
                SkipWhitespace();
                if (Take('}'))
                {
                    return result;
                }
                Require(',');
                SkipWhitespace();
            }
        }

        private JArray ParseArray()
        {
            JArray result = new JArray();
            _index++;
            SkipWhitespace();
            if (Take(']'))
            {
                return result;
            }
            while (true)
            {
                result.Values.Add(ParseValue());
                SkipWhitespace();
                if (Take(']'))
                {
                    return result;
                }
                Require(',');
                SkipWhitespace();
            }
        }

        private string ParseString()
        {
            Require('"');
            StringBuilder builder = new StringBuilder();
            while (_index < _text.Length)
            {
                char current = _text[_index++];
                if (current == '"')
                {
                    return builder.ToString();
                }
                if (current != '\\')
                {
                    builder.Append(current);
                    continue;
                }
                if (_index >= _text.Length)
                {
                    throw new FormatException();
                }
                char escaped = _text[_index++];
                switch (escaped)
                {
                    case '"': builder.Append('"'); break;
                    case '\\': builder.Append('\\'); break;
                    case '/': builder.Append('/'); break;
                    case 'b': builder.Append('\b'); break;
                    case 'f': builder.Append('\f'); break;
                    case 'n': builder.Append('\n'); break;
                    case 'r': builder.Append('\r'); break;
                    case 't': builder.Append('\t'); break;
                    case 'u': builder.Append((char)ParseHex4()); break;
                    default: throw new FormatException();
                }
            }
            throw new FormatException();
        }

        private int ParseHex4()
        {
            if (_index + 4 > _text.Length)
            {
                throw new FormatException();
            }
            int value = 0;
            for (int offset = 0; offset < 4; offset++)
            {
                char current = _text[_index++];
                int digit;
                if (current >= '0' && current <= '9')
                {
                    digit = current - '0';
                }
                else if (current >= 'A' && current <= 'F')
                {
                    digit = current - 'A' + 10;
                }
                else if (current >= 'a' && current <= 'f')
                {
                    digit = current - 'a' + 10;
                }
                else
                {
                    throw new FormatException();
                }
                value = checked(value * 16 + digit);
            }
            return value;
        }

        private string ParseInteger()
        {
            int start = _index;
            if (_text[_index] == '-')
            {
                _index++;
            }
            if (_index >= _text.Length || _text[_index] < '0' || _text[_index] > '9')
            {
                throw new FormatException();
            }
            if (_text[_index] == '0')
            {
                _index++;
                if (_index < _text.Length && _text[_index] >= '0' && _text[_index] <= '9')
                {
                    throw new FormatException();
                }
                return _text.Substring(start, _index - start);
            }
            while (_index < _text.Length && _text[_index] >= '0' && _text[_index] <= '9')
            {
                _index++;
            }
            return _text.Substring(start, _index - start);
        }

        private bool ReadLiteral(string value)
        {
            if (_index + value.Length > _text.Length || !string.Equals(_text.Substring(_index, value.Length), value, StringComparison.Ordinal))
            {
                return false;
            }
            _index += value.Length;
            return true;
        }

        private void Require(char expected)
        {
            if (_index >= _text.Length || _text[_index] != expected)
            {
                throw new FormatException();
            }
            _index++;
        }

        private bool Take(char expected)
        {
            if (_index < _text.Length && _text[_index] == expected)
            {
                _index++;
                return true;
            }
            return false;
        }

        private void SkipWhitespace()
        {
            while (_index < _text.Length)
            {
                char current = _text[_index];
                if (current != ' ' && current != '\t' && current != '\r' && current != '\n')
                {
                    return;
                }
                _index++;
            }
        }
    }

    internal sealed class CatalogField
    {
        internal int? Id;
        internal int? MaxBytes;
        internal int? MaxCodeUnits;
        internal string Name;
        internal int Ordinal;
        internal string Type;
    }

    internal sealed class CatalogBranch
    {
        internal readonly List<CatalogField> Fields = new List<CatalogField>();
        internal int Index;
        internal string Name;
    }

    internal sealed class CatalogMember
    {
        internal int Index;
        internal string Name;
        internal int Value;
    }

    internal sealed class CatalogOperation
    {
        internal readonly List<CatalogBranch> Branches = new List<CatalogBranch>();
        internal readonly List<CatalogField> Fields = new List<CatalogField>();
        internal readonly List<CatalogMember> Members = new List<CatalogMember>();
        internal string Channel;
        internal string Direction;
        internal string Discriminator;
        internal string ElementType;
        internal string Encoding;
        internal string Grammar;
        internal int? Id;
        internal string Kind;
        internal int MaxBytes;
        internal int MaxCount;
        internal int MaxUtf16CodeUnits;
        internal bool MessageAssignsKind;
        internal int MinBytes;
        internal int MinCount;
        internal string Name;
        internal int Ordinal;
        internal string Parent;
        internal string PayloadRoot;
        internal string Production;
        internal string Type;
    }

    internal sealed class CatalogType
    {
        internal bool Deleted;
        internal readonly List<CatalogField> Fields = new List<CatalogField>();
        internal CatalogOperation Operation;
        internal string Production;
        internal bool UnionDiscriminator;
        internal CatalogOperation UnionOperation;
    }

    internal sealed class CatalogMap : List<object>
    {
        internal int EncodedBytes = 2;
        internal long NodeCount = 1;
    }

    internal sealed class CatalogMapBudgetException : Exception
    {
    }

    internal sealed class MessageMetadata
    {
        internal readonly HashSet<string> Directions = new HashSet<string>(StringComparer.Ordinal);
        internal string PayloadRoot;
    }

    internal static class CanonicalJson
    {
        internal static byte[] Bytes(object value)
        {
            return new UTF8Encoding(false).GetBytes(Text(value));
        }

        internal static string Text(object value)
        {
            StringBuilder builder = new StringBuilder();
            Write(builder, value);
            return builder.ToString();
        }

        private static void Write(StringBuilder builder, object value)
        {
            if (value == null)
            {
                builder.Append("null");
                return;
            }
            string text = value as string;
            if (text != null)
            {
                WriteString(builder, text);
                return;
            }
            if (value is bool)
            {
                builder.Append((bool)value ? "true" : "false");
                return;
            }
            IDictionary<string, object> dictionary = value as IDictionary<string, object>;
            if (dictionary != null)
            {
                List<string> keys = new List<string>(dictionary.Keys);
                keys.Sort(StringComparer.Ordinal);
                builder.Append('{');
                for (int index = 0; index < keys.Count; index++)
                {
                    if (index > 0)
                    {
                        builder.Append(',');
                    }
                    WriteString(builder, keys[index]);
                    builder.Append(':');
                    Write(builder, dictionary[keys[index]]);
                }
                builder.Append('}');
                return;
            }
            System.Collections.IEnumerable enumerable = value as System.Collections.IEnumerable;
            if (enumerable != null)
            {
                builder.Append('[');
                bool first = true;
                foreach (object item in enumerable)
                {
                    if (!first)
                    {
                        builder.Append(',');
                    }
                    Write(builder, item);
                    first = false;
                }
                builder.Append(']');
                return;
            }
            if (value is byte || value is sbyte || value is short || value is ushort || value is int || value is uint || value is long || value is ulong)
            {
                builder.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }
            throw new InvalidOperationException("Unsupported canonical JSON value.");
        }

        private static void WriteString(StringBuilder builder, string value)
        {
            builder.Append('"');
            for (int index = 0; index < value.Length; index++)
            {
                char current = value[index];
                switch (current)
                {
                    case '"': builder.Append("\\\""); break;
                    case '\\': builder.Append("\\\\"); break;
                    case '\b': builder.Append("\\b"); break;
                    case '\f': builder.Append("\\f"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default:
                        if (current <= 0x1F)
                        {
                            builder.Append("\\u");
                            builder.Append(((int)current).ToString("X4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            builder.Append(current);
                        }
                        break;
                }
            }
            builder.Append('"');
        }
    }

    public static class FoundationCatalogEngineV1
    {
        private static readonly string[] AllEntryProperties = new string[]
        {
            "branches", "channel", "direction", "discriminator", "elementType", "encoding", "fields", "grammar", "id",
            "maxBytes", "maxCodeUnits", "maxCount", "maxUtf16CodeUnits", "members", "minBytes", "minCount", "name", "op",
            "parent", "payloadRoot", "production", "type"
        };
        private static readonly string[] BuiltinPrimitives = new string[]
        {
            "U8", "U16", "U32", "U64", "I16", "I32", "I64", "FILETIME", "QPC", "GUID", "Opaque16", "FixedAscii8",
            "SHA-256", "Opaque32", "AsciiIdentifier", "BinarySid", "Utf8Short", "Rsa3072PublicBlob", "Rsa3072Signature",
            "LUID", "BoundedBytes", "OpaqueUtf16"
        };
        private static readonly string[] ForbiddenPrimitives = new string[] { "I16", "I32", "I64", "OpaqueUtf16" };
        private static readonly string[] MapCategories = new string[] { "kind", "type", "field", "enum-member", "union-branch" };
        private static readonly string[] Productions = new string[] { "EnumU16", "SemanticString", "Named", "List", "Set" };
        private const string MapSchemaId = "PspktFoundationIdMapV1";
        private const int MaxUnionBranchCount = 65536;
        private const int MaximumEmittedJsonBytes = 1048576;
        private const int MaximumMapRows = 8192;
        private const int MaximumSchemaTypes = 4096;

        public static FoundationCatalogEvaluation EvaluateJson(byte[] catalogBytes, FoundationPolicyContract policy)
        {
            if (catalogBytes == null)
            {
                throw new ArgumentNullException("catalogBytes");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            SchemaCheckResult jsonResult = SchemaBootstrap.Evaluate("json", NormalizeIntegersForStrictJson(catalogBytes), null);
            if (!jsonResult.Accepted)
            {
                return new FoundationCatalogEvaluation(false, jsonResult.Reason, null, null);
            }
            JObject root;
            try
            {
                root = new JsonParser(catalogBytes).Parse() as JObject;
            }
            catch (Exception exception)
            {
                if (exception is OutOfMemoryException || exception is StackOverflowException)
                {
                    throw;
                }
                return new FoundationCatalogEvaluation(false, "unknown-property", null, null);
            }
            if (root == null)
            {
                return new FoundationCatalogEvaluation(false, "unknown-property", null, null);
            }
            string reason;
            if (!CheckExactKeys(root, new string[] { "entries", "schemaId", "schemaVersion", "space" }, out reason))
            {
                return new FoundationCatalogEvaluation(false, reason, null, null);
            }
            long schemaVersion;
            string schemaId;
            string space;
            JArray entries;
            if (!TryInteger(root, "schemaVersion", out schemaVersion) || schemaVersion != 1
                || !TryString(root, "schemaId", out schemaId)
                || !TryString(root, "space", out space)
                || !TryArray(root, "entries", out entries))
            {
                return new FoundationCatalogEvaluation(false, "missing-property", null, null);
            }
            if (!string.Equals(schemaId, policy.CatalogSchemaId, StringComparison.Ordinal))
            {
                return new FoundationCatalogEvaluation(false, "missing-property", null, null);
            }
            HashSet<string> allowedOperations = new HashSet<string>(policy.AllowedOps, StringComparer.Ordinal);
            for (int index = 0; index < entries.Values.Count; index++)
            {
                JObject entry = entries.Values[index] as JObject;
                if (entry == null)
                {
                    return new FoundationCatalogEvaluation(false, "unknown-property", null, null);
                }
                foreach (string key in entry.Values.Keys)
                {
                    if (!Contains(AllEntryProperties, key))
                    {
                        return new FoundationCatalogEvaluation(false, "extra-key", null, null);
                    }
                }
                string operation;
                if (!TryString(entry, "op", out operation))
                {
                    return new FoundationCatalogEvaluation(false, "missing-property", null, null);
                }
                if (string.Equals(operation, "replace", StringComparison.Ordinal))
                {
                    return new FoundationCatalogEvaluation(false, "op-replace-forbidden", null, null);
                }
                if (!allowedOperations.Contains(operation))
                {
                    return new FoundationCatalogEvaluation(false, "op-unknown", null, null);
                }
                if (!ValidateEntryShape(entry, operation, out reason))
                {
                    return new FoundationCatalogEvaluation(false, reason, null, null);
                }
                if (!ValidateNestedShapes(entry, operation, out reason))
                {
                    return new FoundationCatalogEvaluation(false, reason, null, null);
                }
                if (!ValidateNames(entry, operation, policy.NamePredicate))
                {
                    return new FoundationCatalogEvaluation(false, "foundation-name", null, null);
                }
                if ((string.Equals(operation, "type", StringComparison.Ordinal)
                    || string.Equals(operation, "enum", StringComparison.Ordinal)
                    || string.Equals(operation, "message", StringComparison.Ordinal)
                    || string.Equals(operation, "field", StringComparison.Ordinal))
                    && entry.Values.ContainsKey("id"))
                {
                    return new FoundationCatalogEvaluation(false, "base-literal-id", null, null);
                }
                if (!ValidateNumericSemantics(entry, operation, out reason))
                {
                    return new FoundationCatalogEvaluation(false, reason, null, null);
                }
                if (string.Equals(operation, "message", StringComparison.Ordinal))
                {
                    string channel;
                    string direction;
                    if (!TryString(entry, "channel", out channel) || !Contains(policy.Channels, channel))
                    {
                        return new FoundationCatalogEvaluation(false, "invalid-channel", null, null);
                    }
                    if (!TryString(entry, "direction", out direction) || !Contains(policy.PermittedDirections, direction))
                    {
                        return new FoundationCatalogEvaluation(false, "invalid-direction", null, null);
                    }
                }
                if (string.Equals(operation, "type", StringComparison.Ordinal))
                {
                    string production;
                    if (!TryString(entry, "production", out production) || !Contains(Productions, production) || string.Equals(production, "EnumU16", StringComparison.Ordinal))
                    {
                        return new FoundationCatalogEvaluation(false, "invalid-production", null, null);
                    }
                }
            }
            return new FoundationCatalogEvaluation(true, "ok", space, root);
        }

        public static FoundationCatalogExpansion Expand(byte[] catalogBytes, FoundationPolicyContract policy)
        {
            FoundationCatalogEvaluation evaluation = EvaluateJson(catalogBytes, policy);
            return evaluation.Accepted ? Expand(evaluation, policy) : FailedExpansion(evaluation.Reason, policy);
        }

        public static FoundationCatalogExpansion Expand(FoundationCatalogEvaluation evaluation, FoundationPolicyContract policy)
        {
            if (evaluation == null)
            {
                throw new ArgumentNullException("evaluation");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            if (!evaluation.Accepted)
            {
                return FailedExpansion(evaluation.Reason, policy);
            }
            List<CatalogOperation> operations = new List<CatalogOperation>();
            Dictionary<string, CatalogType> types = new Dictionary<string, CatalogType>(StringComparer.Ordinal);
            Dictionary<string, MessageMetadata> messages = new Dictionary<string, MessageMetadata>(StringComparer.Ordinal);
            HashSet<string> reservations = new HashSet<string>(StringComparer.Ordinal);
            JArray entries = (JArray)evaluation.Root.Values["entries"];
            for (int index = 0; index < entries.Values.Count; index++)
            {
                JObject entry = (JObject)entries.Values[index];
                string operationName = ((JString)entry.Values["op"]).Value;
                CatalogOperation operation = ReadOperation(entry, operationName, index + 1);
                string reason = ExpandOperation(operation, types, messages, reservations, policy);
                if (!string.Equals(reason, "ok", StringComparison.Ordinal))
                {
                    return FailedExpansion(reason, policy);
                }
                operations.Add(operation);
            }
            foreach (CatalogOperation operation in operations)
            {
                string reason = ValidateReferences(operation, types, reservations);
                if (!string.Equals(reason, "ok", StringComparison.Ordinal))
                {
                    return FailedExpansion(reason, policy);
                }
            }
            HashSet<string> synthesizedMessageEnums = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> synthesizedChannels = new HashSet<string>(StringComparer.Ordinal);
            IDictionary<string, string> messageEnumNames = policy.MessageEnumNameByChannel;
            foreach (CatalogOperation operation in operations)
            {
                if (operation.Kind != "message" || !operation.MessageAssignsKind || !synthesizedChannels.Add(operation.Channel))
                {
                    continue;
                }
                string enumName = messageEnumNames[operation.Channel];
                if (types.ContainsKey(enumName) || reservations.Contains(enumName) || !synthesizedMessageEnums.Add(enumName))
                {
                    return FailedExpansion("duplicate-identifier", policy);
                }
            }
            List<object> ir = new List<object>();
            foreach (CatalogOperation operation in operations)
            {
                Dictionary<string, object> row = NewDictionary();
                row.Add("catalogOrdinal", operation.Ordinal);
                row.Add("kind", operation.Kind == "delete" ? "tombstone" : operation.Kind == "reserve-illegal-type" ? "reservation" : operation.Kind);
                if (operation.Name != null)
                {
                    row.Add("name", operation.Name);
                }
                if (operation.Parent != null)
                {
                    row.Add("parent", operation.Parent);
                }
                ir.Add(row);
            }
            return new FoundationCatalogExpansion(true, "ok", operations, types, CanonicalJson.Text(ir), policy.Channels);
        }

        public static FoundationCatalogAssignment Assign(FoundationCatalogExpansion expansion, FoundationPolicyContract policy)
        {
            if (expansion == null)
            {
                throw new ArgumentNullException("expansion");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            if (!expansion.Accepted)
            {
                return new FoundationCatalogAssignment(false, expansion.Reason, null, null, expansion.IrJson);
            }
            bool containsUnion = false;
            try
            {
            List<object> outputTypes = new List<object>();
            CatalogMap map = new CatalogMap();
            Dictionary<string, Dictionary<string, object>> outputByName = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            Dictionary<string, int> fieldNext = new Dictionary<string, int>(StringComparer.Ordinal);
            Dictionary<string, Dictionary<string, object>> messageEnums = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            Dictionary<string, int> kindNextByChannel = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int channelIndex = 0; channelIndex < policy.Channels.Length; channelIndex++)
            {
                kindNextByChannel.Add(policy.Channels[channelIndex], expansion.ReadKindNext(policy.Channels[channelIndex]));
            }
            int typeNext = expansion.TypeNext;
            foreach (CatalogOperation operation in expansion.Operations)
            {
                if (operation.Kind == "type" || operation.Kind == "enum")
                {
                    CatalogType catalogType = expansion.Types[operation.Name];
                    if (catalogType.Deleted)
                    {
                        continue;
                    }
                    int assigned;
                    string reason = TryAssignGeneratedId("type", null, typeNext, policy, out assigned);
                    if (reason != "ok")
                    {
                        return AssignmentFailure(reason, expansion.IrJson);
                    }
                    typeNext = checked(typeNext + 1);
                    AddMapRow(map, "type", operation.Ordinal, operation.Name, assigned, null, null, null);
                    Dictionary<string, object> declaration = CreateTypeDeclaration(operation, assigned, map);
                    outputTypes.Add(declaration);
                    outputByName.Add(operation.Name, declaration);
                    if (operation.Production == "Named")
                    {
                        fieldNext.Add(operation.Name, 1);
                    }
                    continue;
                }
                if (operation.Kind == "field")
                {
                    if (expansion.Types[operation.Parent].Deleted)
                    {
                        continue;
                    }
                    int next = fieldNext[operation.Parent];
                    if (next > policy.FieldIdMax)
                    {
                        return AssignmentFailure("field-overflow-40", expansion.IrJson);
                    }
                    fieldNext[operation.Parent] = checked(next + 1);
                    CatalogField field = operation.Fields[0];
                    AddFieldInIdOrder(outputByName[operation.Parent], field, next);
                    AddMapRow(map, "field", operation.Ordinal, operation.Parent + "." + field.Name, next, null, null, null);
                    continue;
                }
                if (operation.Kind == "message" && operation.MessageAssignsKind)
                {
                    Dictionary<string, object> enumDeclaration;
                    if (!messageEnums.TryGetValue(operation.Channel, out enumDeclaration))
                    {
                        int enumTypeId;
                        string typeReason = TryAssignGeneratedId("type", null, typeNext, policy, out enumTypeId);
                        if (typeReason != "ok")
                        {
                            return AssignmentFailure(typeReason, expansion.IrJson);
                        }
                        typeNext = checked(typeNext + 1);
                        string enumName = policy.MessageEnumNameByChannel[operation.Channel];
                        enumDeclaration = NewDictionary();
                        enumDeclaration.Add("production", "EnumU16");
                        enumDeclaration.Add("name", enumName);
                        enumDeclaration.Add("typeId", enumTypeId);
                        enumDeclaration.Add("members", new List<object>());
                        outputTypes.Add(enumDeclaration);
                        outputByName.Add(enumName, enumDeclaration);
                        messageEnums.Add(operation.Channel, enumDeclaration);
                        AddMapRow(map, "type", operation.Ordinal, enumName, enumTypeId, null, null, null);
                    }
                    int kindNext = kindNextByChannel[operation.Channel];
                    int kindId;
                    string kindReason = TryAssignGeneratedId("kind", operation.Channel, kindNext, policy, out kindId);
                    if (kindReason != "ok")
                    {
                        return AssignmentFailure(kindReason, expansion.IrJson);
                    }
                    kindNextByChannel[operation.Channel] = checked(kindNext + 1);
                    Dictionary<string, object> member = NewDictionary();
                    member.Add("name", operation.Name);
                    member.Add("value", kindId);
                    ((List<object>)enumDeclaration["members"]).Add(member);
                    AddMapRow(map, "kind", operation.Ordinal, operation.Name, kindId, operation.Channel, null, null);
                    continue;
                }
                if (operation.Kind == "union")
                {
                    containsUnion = true;
                    if (expansion.Types[operation.Discriminator].Deleted)
                    {
                        continue;
                    }
                    if (operation.Branches.Count > MaxUnionBranchCount)
                    {
                        return AssignmentFailure("enum-value-overflow", expansion.IrJson);
                    }
                    int liveBranchCount = 0;
                    int projectedBranchMapRows = 0;
                    for (int liveIndex = 0; liveIndex < operation.Branches.Count; liveIndex++)
                    {
                        if (!expansion.Types[operation.Branches[liveIndex].Name].Deleted)
                        {
                            liveBranchCount++;
                            projectedBranchMapRows = checked(projectedBranchMapRows + 2 + operation.Branches[liveIndex].Fields.Count);
                        }
                    }
                    if (liveBranchCount == 0)
                    {
                        continue;
                    }
                    if (outputTypes.Count + 1 + liveBranchCount > MaximumSchemaTypes
                        || map.Count + 1 + projectedBranchMapRows > MaximumMapRows)
                    {
                        return AssignmentFailure("enum-value-overflow", expansion.IrJson);
                    }
                    if (!UnionProjectionFits(outputTypes, map, operation, expansion, typeNext, policy))
                    {
                        return AssignmentFailure("enum-value-overflow", expansion.IrJson);
                    }
                    int discriminatorId;
                    string discriminatorReason = TryAssignGeneratedId("type", null, typeNext, policy, out discriminatorId);
                    if (discriminatorReason != "ok")
                    {
                        return AssignmentFailure(discriminatorReason, expansion.IrJson);
                    }
                    typeNext = checked(typeNext + 1);
                    Dictionary<string, object> discriminator = NewDictionary();
                    discriminator.Add("production", "EnumU16");
                    discriminator.Add("name", operation.Discriminator);
                    discriminator.Add("typeId", discriminatorId);
                    List<object> members = new List<object>();
                    discriminator.Add("members", members);
                    outputTypes.Add(discriminator);
                    outputByName.Add(operation.Discriminator, discriminator);
                    AddMapRow(map, "type", operation.Ordinal, operation.Discriminator, discriminatorId, null, null, null);
                    int liveBranchIndex = 0;
                    for (int branchIndex = 0; branchIndex < operation.Branches.Count; branchIndex++)
                    {
                        CatalogBranch branch = operation.Branches[branchIndex];
                        if (expansion.Types[branch.Name].Deleted)
                        {
                            continue;
                        }
                        Dictionary<string, object> member = NewDictionary();
                        member.Add("name", branch.Name);
                        member.Add("value", liveBranchIndex);
                        members.Add(member);
                        AddMapRow(map, "enum-member", operation.Ordinal, operation.Discriminator + "." + branch.Name, liveBranchIndex, null, liveBranchIndex, null);
                        int branchTypeId;
                        string branchReason = TryAssignGeneratedId("type", null, typeNext, policy, out branchTypeId);
                        if (branchReason != "ok")
                        {
                            return AssignmentFailure(branchReason, expansion.IrJson);
                        }
                        typeNext = checked(typeNext + 1);
                        Dictionary<string, object> branchDeclaration = NewDictionary();
                        branchDeclaration.Add("production", "Named");
                        branchDeclaration.Add("name", branch.Name);
                        branchDeclaration.Add("typeId", branchTypeId);
                        branchDeclaration.Add("fields", new List<object>());
                        for (int fieldIndex = 0; fieldIndex < branch.Fields.Count; fieldIndex++)
                        {
                            CatalogField branchField = branch.Fields[fieldIndex];
                            AddField(branchDeclaration, branchField, fieldIndex + 1);
                            AddMapRow(map, "field", operation.Ordinal, branch.Name + "." + branchField.Name, fieldIndex + 1, null, null, null);
                        }
                        outputTypes.Add(branchDeclaration);
                        outputByName.Add(branch.Name, branchDeclaration);
                        fieldNext.Add(branch.Name, checked(branch.Fields.Count + 1));
                        AddMapRow(map, "union-branch", operation.Ordinal, branch.Name, branchTypeId, null, null, liveBranchIndex);
                        liveBranchIndex++;
                    }
                    continue;
                }
                if (operation.Kind == "extend")
                {
                    if (expansion.Types[operation.Parent].Deleted)
                    {
                        continue;
                    }
                    Dictionary<string, object> parentDeclaration = outputByName[operation.Parent];
                    for (int index = 0; index < operation.Fields.Count; index++)
                    {
                        CatalogField field = operation.Fields[index];
                        AddFieldInIdOrder(parentDeclaration, field, field.Id.Value);
                        AddMapRow(map, "field", operation.Ordinal, operation.Parent + "." + field.Name, field.Id.Value, null, null, null);
                    }
                }
            }
            Dictionary<string, object> schema = NewDictionary();
            schema.Add("schemaVersion", 1);
            schema.Add("schemaId", policy.EmitSchemaId);
            schema.Add("types", outputTypes);
            if (outputTypes.Count > MaximumSchemaTypes || map.Count > MaximumMapRows)
            {
                return AssignmentFailure(containsUnion ? "enum-value-overflow" : "generated-id-overflow", expansion.IrJson);
            }
            string structureReason = ValidateFinalSchemaStructure(outputTypes);
            if (!string.Equals(structureReason, "ok", StringComparison.Ordinal))
            {
                return AssignmentFailure(structureReason, expansion.IrJson);
            }
            byte[] schemaBytes = CanonicalJson.Bytes(schema);
            byte[] mapBytes = CanonicalJson.Bytes(map);
            SchemaCheckResult mapJsonCheck = SchemaBootstrap.Evaluate("json", mapBytes, null);
            if (schemaBytes.Length > MaximumEmittedJsonBytes
                || mapBytes.Length > MaximumEmittedJsonBytes
                || !mapJsonCheck.Accepted)
            {
                return AssignmentFailure(containsUnion ? "enum-value-overflow" : "generated-id-overflow", expansion.IrJson);
            }
            return new FoundationCatalogAssignment(true, "ok", schemaBytes, mapBytes, expansion.IrJson);
            }
            catch (CatalogMapBudgetException)
            {
                return AssignmentFailure(containsUnion ? "enum-value-overflow" : "generated-id-overflow", expansion.IrJson);
            }
        }

        public static FoundationCatalogResult Emit(FoundationCatalogAssignment assignment, FoundationPolicyContract policy)
        {
            if (assignment == null)
            {
                throw new ArgumentNullException("assignment");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            return assignment.Accepted
                ? new FoundationCatalogResult(true, "ok", assignment.SchemaBytes, assignment.IdMapBytes, assignment.IrJson)
                : FoundationCatalogResult.Failure(assignment.Reason, assignment.IdMapBytes, assignment.IrJson);
        }

        public static FoundationReplayResult Replay(byte[] catalogBytes, byte[] schemaBytes, byte[] mapBytes, FoundationPolicyContract policy)
        {
            if (catalogBytes == null || schemaBytes == null || mapBytes == null)
            {
                throw new ArgumentNullException("catalogBytes");
            }
            if (!ValidateMap(mapBytes))
            {
                return new FoundationReplayResult(false, "map-tamper");
            }
            FoundationCatalogExpansion expansion = Expand(catalogBytes, policy);
            if (!expansion.Accepted)
            {
                return new FoundationReplayResult(false, expansion.Reason);
            }
            FoundationCatalogAssignment assignment = Assign(expansion, policy);
            if (!assignment.Accepted)
            {
                return new FoundationReplayResult(false, assignment.Reason);
            }
            if (!EqualBytes(assignment.IdMapBytes, mapBytes) || !EqualBytes(assignment.SchemaBytes, schemaBytes))
            {
                return new FoundationReplayResult(false, "id-map-drift");
            }
            return new FoundationReplayResult(true, "ok");
        }

        public static bool TestGeneratedIdAllowed(string category, string channel, int value, FoundationPolicyContract policy)
        {
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            if (value < 1 || value > 65535)
            {
                return false;
            }
            if (category == "kind")
            {
                if (!Contains(policy.Channels, channel))
                {
                    return false;
                }
                GeneratedIdRange[] ranges;
                if (policy.ReservedKindRanges.TryGetValue(channel, out ranges))
                {
                    for (int index = 0; index < ranges.Length; index++)
                    {
                        if (ranges[index].Contains(value))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }
            if (category == "type")
            {
                return policy.ReservedTypeRange == null || !policy.ReservedTypeRange.Contains(value);
            }
            return false;
        }

        public static bool TryAdvanceGeneratedId(int current, out int assigned)
        {
            if (current < 1 || current >= 65536)
            {
                assigned = 0;
                return false;
            }
            assigned = current;
            return true;
        }

        public static bool TryAdvanceGeneratedId(int current, out int assigned, out string reason)
        {
            bool accepted = TryAdvanceGeneratedId(current, out assigned);
            reason = accepted ? "ok" : "generated-id-overflow";
            return accepted;
        }

        public static string Sha256(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                for (int index = 0; index < hash.Length; index++)
                {
                    builder.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
                }
                return builder.ToString();
            }
        }

        private static FoundationCatalogExpansion FailedExpansion(string reason, FoundationPolicyContract policy)
        {
            return new FoundationCatalogExpansion(false, reason, new List<CatalogOperation>(), new Dictionary<string, CatalogType>(StringComparer.Ordinal), "[]", policy == null ? null : policy.Channels);
        }

        private static bool ValidateEntryShape(JObject entry, string operation, out string reason)
        {
            reason = "ok";
            string[] required;
            string[] allowed;
            if (operation == "primitive" || operation == "delete")
            {
                required = new string[] { "op", "name" };
                allowed = required;
            }
            else if (operation == "enum")
            {
                required = new string[] { "op", "name", "members" };
                allowed = new string[] { "op", "name", "members", "id" };
            }
            else if (operation == "field")
            {
                required = new string[] { "op", "name", "parent", "type" };
                string fieldType;
                TryString(entry, "type", out fieldType);
                if (fieldType == "BoundedBytes")
                {
                    required = new string[] { "op", "name", "parent", "type", "maxBytes" };
                    allowed = new string[] { "op", "name", "parent", "type", "maxBytes", "id" };
                }
                else if (fieldType == "OpaqueUtf16")
                {
                    required = new string[] { "op", "name", "parent", "type", "maxCodeUnits" };
                    allowed = new string[] { "op", "name", "parent", "type", "maxCodeUnits", "id" };
                }
                else
                {
                    allowed = new string[] { "op", "name", "parent", "type", "id" };
                }
            }
            else if (operation == "message")
            {
                required = new string[] { "op", "name", "channel", "direction", "payloadRoot" };
                allowed = new string[] { "op", "name", "channel", "direction", "payloadRoot", "id" };
            }
            else if (operation == "union")
            {
                required = new string[] { "op", "name", "discriminator", "branches" };
                allowed = required;
            }
            else if (operation == "extend")
            {
                required = new string[] { "op", "parent", "fields" };
                allowed = required;
            }
            else if (operation == "reserve-illegal-type")
            {
                required = new string[] { "op", "name" };
                allowed = new string[] { "op", "name", "id" };
            }
            else
            {
                required = new string[] { "op", "name", "production" };
                string production;
                TryString(entry, "production", out production);
                if (production == "List" || production == "Set")
                {
                    required = new string[] { "op", "name", "production", "elementType", "minCount", "maxCount" };
                }
                else if (production == "SemanticString")
                {
                    required = new string[] { "op", "name", "production", "encoding", "grammar", "minBytes", "maxBytes", "maxUtf16CodeUnits" };
                }
                if (production == "List" || production == "Set")
                {
                    allowed = new string[] { "op", "name", "production", "elementType", "minCount", "maxCount", "id" };
                }
                else if (production == "SemanticString")
                {
                    allowed = new string[] { "op", "name", "production", "encoding", "grammar", "minBytes", "maxBytes", "maxUtf16CodeUnits", "id" };
                }
                else
                {
                    allowed = new string[] { "op", "name", "production", "id" };
                }
            }
            foreach (string key in entry.Values.Keys)
            {
                if (!Contains(allowed, key))
                {
                    reason = "extra-key";
                    return false;
                }
            }
            for (int index = 0; index < required.Length; index++)
            {
                if (!entry.Values.ContainsKey(required[index]))
                {
                    reason = "missing-property";
                    return false;
                }
            }
            List<string> requiredStrings = new List<string>();
            if (operation != "extend")
            {
                requiredStrings.Add("name");
            }
            if (operation == "field" || operation == "extend")
            {
                requiredStrings.Add("parent");
            }
            if (operation == "field")
            {
                requiredStrings.Add("type");
            }
            if (operation == "message")
            {
                requiredStrings.Add("channel");
                requiredStrings.Add("direction");
                requiredStrings.Add("payloadRoot");
            }
            if (operation == "union")
            {
                requiredStrings.Add("discriminator");
            }
            if (operation == "type")
            {
                requiredStrings.Add("production");
                string production;
                if (TryString(entry, "production", out production))
                {
                    if (production == "List" || production == "Set")
                    {
                        requiredStrings.Add("elementType");
                    }
                    else if (production == "SemanticString")
                    {
                        requiredStrings.Add("encoding");
                        requiredStrings.Add("grammar");
                    }
                }
            }
            for (int index = 0; index < requiredStrings.Count; index++)
            {
                string ignored;
                if (!TryString(entry, requiredStrings[index], out ignored))
                {
                    reason = "missing-property";
                    return false;
                }
            }
            return true;
        }

        private static bool ValidateNestedShapes(JObject entry, string operation, out string reason)
        {
            reason = "ok";
            if (operation == "enum")
            {
                JArray members;
                if (!TryArray(entry, "members", out members))
                {
                    reason = "missing-property";
                    return false;
                }
                for (int index = 0; index < members.Values.Count; index++)
                {
                    JObject member = members.Values[index] as JObject;
                    if (member == null || !CheckAllowedAndRequired(member, new string[] { "name", "value" }, new string[] { "name" }, out reason))
                    {
                        if (member == null) reason = "missing-property";
                        return false;
                    }
                    string memberName;
                    if (!TryString(member, "name", out memberName))
                    {
                        reason = "missing-property";
                        return false;
                    }
                }
            }
            if (operation == "extend")
            {
                JArray fields;
                if (!TryArray(entry, "fields", out fields))
                {
                    reason = "missing-property";
                    return false;
                }
                for (int index = 0; index < fields.Values.Count; index++)
                {
                    JObject field = fields.Values[index] as JObject;
                    if (field == null || !ValidateNestedFieldShape(field, true, out reason))
                    {
                        if (field == null) reason = "missing-property";
                        return false;
                    }
                }
            }
            if (operation == "union")
            {
                JArray branches;
                if (!TryArray(entry, "branches", out branches))
                {
                    reason = "missing-property";
                    return false;
                }
                for (int index = 0; index < branches.Values.Count; index++)
                {
                    JObject branch = branches.Values[index] as JObject;
                    if (branch == null || !CheckAllowedAndRequired(branch, new string[] { "fields", "name" }, new string[] { "fields", "name" }, out reason))
                    {
                        if (branch == null) reason = "missing-property";
                        return false;
                    }
                    string branchName;
                    if (!TryString(branch, "name", out branchName))
                    {
                        reason = "missing-property";
                        return false;
                    }
                    JArray fields;
                    if (!TryArray(branch, "fields", out fields))
                    {
                        reason = "missing-property";
                        return false;
                    }
                    for (int fieldIndex = 0; fieldIndex < fields.Values.Count; fieldIndex++)
                    {
                        JObject field = fields.Values[fieldIndex] as JObject;
                        if (field == null || !ValidateNestedFieldShape(field, false, out reason))
                        {
                            if (field == null) reason = "missing-property";
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private static bool ValidateNestedFieldShape(JObject field, bool requireLiteralId, out string reason)
        {
            string fieldType;
            if (!TryString(field, "type", out fieldType))
            {
                reason = "missing-property";
                return false;
            }
            string fieldName;
            if (!TryString(field, "name", out fieldName))
            {
                reason = "missing-property";
                return false;
            }
            List<string> allowed = new List<string>(new string[] { "name", "type" });
            List<string> required = new List<string>(new string[] { "name", "type" });
            if (requireLiteralId)
            {
                allowed.Add("id");
            }
            if (fieldType == "BoundedBytes")
            {
                allowed.Add("maxBytes");
                required.Add("maxBytes");
            }
            else if (fieldType == "OpaqueUtf16")
            {
                allowed.Add("maxCodeUnits");
                required.Add("maxCodeUnits");
            }
            return CheckAllowedAndRequired(field, allowed.ToArray(), required.ToArray(), out reason);
        }

        private static bool CheckAllowedAndRequired(JObject value, string[] allowed, string[] required, out string reason)
        {
            foreach (string key in value.Values.Keys)
            {
                if (!Contains(allowed, key))
                {
                    reason = "extra-key";
                    return false;
                }
            }
            for (int index = 0; index < required.Length; index++)
            {
                if (!value.Values.ContainsKey(required[index]))
                {
                    reason = "missing-property";
                    return false;
                }
            }
            reason = "ok";
            return true;
        }

        private static bool ValidateNames(JObject entry, string operation, string pattern)
        {
            if (operation != "extend")
            {
                string name;
                if (TryString(entry, "name", out name) && operation != "primitive" && !IsCatalogIdentifier(name, pattern))
                {
                    return false;
                }
            }
            JArray members;
            if (TryArray(entry, "members", out members))
            {
                for (int index = 0; index < members.Values.Count; index++)
                {
                    JObject member = members.Values[index] as JObject;
                    string name;
                    if (member == null || !TryString(member, "name", out name) || !IsCatalogIdentifier(name, pattern))
                    {
                        return false;
                    }
                }
            }
            JArray fields;
            if (TryArray(entry, "fields", out fields))
            {
                for (int index = 0; index < fields.Values.Count; index++)
                {
                    JObject field = fields.Values[index] as JObject;
                    string name;
                    if (field == null || !TryString(field, "name", out name) || !IsCatalogIdentifier(name, pattern))
                    {
                        return false;
                    }
                }
            }
            JArray branches;
            if (TryArray(entry, "branches", out branches))
            {
                string discriminator;
                if (!TryString(entry, "discriminator", out discriminator) || !IsCatalogIdentifier(discriminator, pattern))
                {
                    return false;
                }
                for (int index = 0; index < branches.Values.Count; index++)
                {
                    JObject branch = branches.Values[index] as JObject;
                    string name;
                    if (branch == null || !TryString(branch, "name", out name) || !IsCatalogIdentifier(name, pattern))
                    {
                        return false;
                    }
                    JArray branchFields;
                    if (TryArray(branch, "fields", out branchFields))
                    {
                        for (int fieldIndex = 0; fieldIndex < branchFields.Values.Count; fieldIndex++)
                        {
                            JObject field = branchFields.Values[fieldIndex] as JObject;
                            string fieldName;
                            if (field == null || !TryString(field, "name", out fieldName) || !IsCatalogIdentifier(fieldName, pattern))
                            {
                                return false;
                            }
                        }
                    }
                }
            }
            return true;
        }

        private static bool IsCatalogIdentifier(string value, string pattern)
        {
            return value != null
                && value.Length >= 1
                && value.Length <= 64
                && Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant);
        }

        private static CatalogOperation ReadOperation(JObject entry, string kind, int ordinal)
        {
            CatalogOperation operation = new CatalogOperation();
            operation.Kind = kind;
            operation.Ordinal = ordinal;
            if (kind == "enum")
            {
                operation.Production = "EnumU16";
            }
            TryString(entry, "name", out operation.Name);
            TryString(entry, "parent", out operation.Parent);
            TryString(entry, "type", out operation.Type);
            TryString(entry, "channel", out operation.Channel);
            TryString(entry, "direction", out operation.Direction);
            TryString(entry, "payloadRoot", out operation.PayloadRoot);
            string production;
            if (TryString(entry, "production", out production))
            {
                operation.Production = production;
            }
            TryString(entry, "elementType", out operation.ElementType);
            TryString(entry, "encoding", out operation.Encoding);
            TryString(entry, "grammar", out operation.Grammar);
            TryString(entry, "discriminator", out operation.Discriminator);
            long integer;
            if (TryInteger(entry, "id", out integer)) operation.Id = checked((int)integer);
            if (TryInteger(entry, "minCount", out integer)) operation.MinCount = checked((int)integer);
            if (TryInteger(entry, "maxCount", out integer)) operation.MaxCount = checked((int)integer);
            if (TryInteger(entry, "minBytes", out integer)) operation.MinBytes = checked((int)integer);
            if (TryInteger(entry, "maxBytes", out integer)) operation.MaxBytes = checked((int)integer);
            if (TryInteger(entry, "maxUtf16CodeUnits", out integer)) operation.MaxUtf16CodeUnits = checked((int)integer);
            JArray members;
            if (TryArray(entry, "members", out members))
            {
                int nextValue = 0;
                for (int index = 0; index < members.Values.Count; index++)
                {
                    JObject memberObject = (JObject)members.Values[index];
                    CatalogMember member = new CatalogMember();
                    member.Index = index;
                    TryString(memberObject, "name", out member.Name);
                    member.Value = TryInteger(memberObject, "value", out integer) ? checked((int)integer) : nextValue;
                    nextValue = checked(member.Value + 1);
                    operation.Members.Add(member);
                }
            }
            JArray fields;
            if (TryArray(entry, "fields", out fields))
            {
                for (int index = 0; index < fields.Values.Count; index++)
                {
                    operation.Fields.Add(ReadField((JObject)fields.Values[index], ordinal));
                }
            }
            JArray branches;
            if (TryArray(entry, "branches", out branches))
            {
                for (int index = 0; index < branches.Values.Count; index++)
                {
                    JObject branchObject = (JObject)branches.Values[index];
                    CatalogBranch branch = new CatalogBranch();
                    branch.Index = index;
                    TryString(branchObject, "name", out branch.Name);
                    JArray branchFields;
                    if (TryArray(branchObject, "fields", out branchFields))
                    {
                        for (int fieldIndex = 0; fieldIndex < branchFields.Values.Count; fieldIndex++)
                        {
                            branch.Fields.Add(ReadField((JObject)branchFields.Values[fieldIndex], ordinal));
                        }
                    }
                    operation.Branches.Add(branch);
                }
            }
            if (kind == "field")
            {
                CatalogField field = new CatalogField();
                field.Name = operation.Name;
                field.Type = operation.Type;
                field.Ordinal = ordinal;
                if (TryInteger(entry, "maxBytes", out integer)) field.MaxBytes = checked((int)integer);
                if (TryInteger(entry, "maxCodeUnits", out integer)) field.MaxCodeUnits = checked((int)integer);
                operation.Fields.Add(field);
            }
            return operation;
        }

        private static CatalogField ReadField(JObject fieldObject, int ordinal)
        {
            CatalogField field = new CatalogField();
            field.Ordinal = ordinal;
            TryString(fieldObject, "name", out field.Name);
            TryString(fieldObject, "type", out field.Type);
            long integer;
            if (TryInteger(fieldObject, "id", out integer)) field.Id = checked((int)integer);
            if (TryInteger(fieldObject, "maxBytes", out integer)) field.MaxBytes = checked((int)integer);
            if (TryInteger(fieldObject, "maxCodeUnits", out integer)) field.MaxCodeUnits = checked((int)integer);
            return field;
        }

        private static string ExpandOperation(CatalogOperation operation, Dictionary<string, CatalogType> types, Dictionary<string, MessageMetadata> messages, HashSet<string> reservations, FoundationPolicyContract policy)
        {
            if (operation.Kind == "primitive")
            {
                if (!Contains(BuiltinPrimitives, operation.Name)) return "unknown-primitive";
                return Contains(ForbiddenPrimitives, operation.Name) ? "primitive-forbidden" : "ok";
            }
            if (operation.Kind == "enum")
            {
                if (operation.Members.Count == 0) return "missing-property";
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                HashSet<int> values = new HashSet<int>();
                for (int index = 0; index < operation.Members.Count; index++)
                {
                    CatalogMember member = operation.Members[index];
                    if (!names.Add(member.Name)) return "enum-duplicate-name";
                    if (member.Value < 0 || member.Value > 65535) return "enum-value-overflow";
                    if (!values.Add(member.Value)) return "enum-duplicate-value";
                }
                return RegisterType(operation.Name, operation, "EnumU16", types, reservations);
            }
            if (operation.Kind == "type")
            {
                if ((operation.Production == "List" || operation.Production == "Set") && (operation.MinCount < 0 || operation.MaxCount < 1 || operation.MinCount > operation.MaxCount || operation.MaxCount > 65535)) return "invalid-production";
                if (operation.Production == "SemanticString"
                    && ((operation.Encoding != "AsciiEnvironmentName" && operation.Encoding != "Utf8")
                    || (operation.Grammar != "None" && operation.Grammar != "PspktPathCanonicalizationV1" && operation.Grammar != "InverseCommandLineToArgvW")
                    || operation.MinBytes < 1
                    || operation.MinBytes > operation.MaxBytes
                    || operation.MaxUtf16CodeUnits < 1
                    || operation.MaxUtf16CodeUnits > operation.MaxBytes)) return "invalid-production";
                return RegisterType(operation.Name, operation, operation.Production, types, reservations);
            }
            if (operation.Kind == "field")
            {
                CatalogType parent;
                if (!types.TryGetValue(operation.Parent, out parent)) return "field-undefined-parent";
                if (parent.Deleted) return "delete-then-use";
                if (parent.Production != "Named") return "field-undefined-parent";
                CatalogField field = operation.Fields[0];
                for (int index = 0; index < parent.Fields.Count; index++) if (parent.Fields[index].Name == field.Name) return "duplicate-identifier";
                if (field.Type == "BoundedBytes" && !field.MaxBytes.HasValue) return "missing-property";
                if (field.Type == "BoundedBytes" && field.MaxBytes.Value < 0) return "invalid-production";
                if (field.Type == "OpaqueUtf16") return "primitive-forbidden";
                parent.Fields.Add(field);
                return "ok";
            }
            if (operation.Kind == "message")
            {
                string key = operation.Channel + "\n" + operation.Name;
                MessageMetadata metadata;
                if (!messages.TryGetValue(key, out metadata))
                {
                    metadata = new MessageMetadata { PayloadRoot = operation.PayloadRoot };
                    metadata.Directions.Add(operation.Direction);
                    messages.Add(key, metadata);
                    operation.MessageAssignsKind = true;
                    return "ok";
                }
                if (metadata.PayloadRoot != operation.PayloadRoot) return "message-metadata-conflict";
                if (!metadata.Directions.Add(operation.Direction)) return "duplicate-kind";
                operation.MessageAssignsKind = false;
                return "ok";
            }
            if (operation.Kind == "union")
            {
                if (operation.Branches.Count == 0) return "union-empty";
                if (operation.Branches.Count > MaxUnionBranchCount) return "enum-value-overflow";
                HashSet<string> branchNames = new HashSet<string>(StringComparer.Ordinal);
                if (types.ContainsKey(operation.Discriminator) || reservations.Contains(operation.Discriminator)) return "duplicate-identifier";
                CatalogOperation discriminatorOperation = new CatalogOperation { Kind = "enum", Name = operation.Discriminator, Production = "EnumU16", Ordinal = operation.Ordinal };
                types.Add(operation.Discriminator, new CatalogType { Operation = discriminatorOperation, Production = "EnumU16", UnionDiscriminator = true, UnionOperation = operation });
                for (int index = 0; index < operation.Branches.Count; index++)
                {
                    CatalogBranch branch = operation.Branches[index];
                    if (!branchNames.Add(branch.Name)) return "union-duplicate-branch";
                    if (types.ContainsKey(branch.Name) || reservations.Contains(branch.Name)) return "duplicate-identifier";
                    if (branch.Fields.Count == 0) return "missing-property";
                    if (branch.Fields.Count > policy.FieldIdMax) return "field-overflow-40";
                    HashSet<string> fieldNames = new HashSet<string>(StringComparer.Ordinal);
                    for (int fieldIndex = 0; fieldIndex < branch.Fields.Count; fieldIndex++)
                    {
                        CatalogField field = branch.Fields[fieldIndex];
                        if (!fieldNames.Add(field.Name)) return "duplicate-identifier";
                        if (field.Type == "BoundedBytes" && !field.MaxBytes.HasValue) return "missing-property";
                        if (field.Type == "BoundedBytes" && field.MaxBytes.Value < 0) return "invalid-production";
                        if (field.Type == "OpaqueUtf16") return "primitive-forbidden";
                    }
                    CatalogType branchType = new CatalogType { Operation = operation, Production = "Named", UnionOperation = operation };
                    for (int fieldIndex = 0; fieldIndex < branch.Fields.Count; fieldIndex++)
                    {
                        branchType.Fields.Add(branch.Fields[fieldIndex]);
                    }
                    types.Add(branch.Name, branchType);
                }
                return "ok";
            }
            if (operation.Kind == "delete")
            {
                CatalogType target;
                if (!types.TryGetValue(operation.Name, out target)) return "delete-unknown";
                if (target.Deleted) return "delete-double";
                target.Deleted = true;
                if (target.UnionDiscriminator)
                {
                    for (int branchIndex = 0; branchIndex < target.UnionOperation.Branches.Count; branchIndex++)
                    {
                        types[target.UnionOperation.Branches[branchIndex].Name].Deleted = true;
                    }
                }
                else if (target.UnionOperation != null)
                {
                    bool hasLiveBranch = false;
                    for (int branchIndex = 0; branchIndex < target.UnionOperation.Branches.Count; branchIndex++)
                    {
                        if (!types[target.UnionOperation.Branches[branchIndex].Name].Deleted)
                        {
                            hasLiveBranch = true;
                            break;
                        }
                    }
                    if (!hasLiveBranch)
                    {
                        types[target.UnionOperation.Discriminator].Deleted = true;
                    }
                }
                return "ok";
            }
            if (operation.Kind == "extend")
            {
                CatalogType parent;
                if (!types.TryGetValue(operation.Parent, out parent) || parent.Deleted || parent.Production != "Named") return "extend-invalid-parent";
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                HashSet<int> ids = new HashSet<int>();
                for (int index = 0; index < parent.Fields.Count; index++)
                {
                    names.Add(parent.Fields[index].Name);
                    if (parent.Fields[index].Id.HasValue) ids.Add(parent.Fields[index].Id.Value);
                }
                for (int index = 0; index < operation.Fields.Count; index++)
                {
                    CatalogField field = operation.Fields[index];
                    if (!field.Id.HasValue) return "extend-missing-literal";
                    if (field.Id.Value < 40) return "extend-lt40";
                    if (field.Id.Value > 65535) return "extend-id-overflow";
                    if (!names.Add(field.Name)) return "extend-dup-name";
                    if (!ids.Add(field.Id.Value)) return "extend-dup-id";
                    if (field.Type == "BoundedBytes" && !field.MaxBytes.HasValue) return "missing-property";
                    if (field.Type == "BoundedBytes" && field.MaxBytes.Value < 0) return "invalid-production";
                    if (field.Type == "OpaqueUtf16") return "primitive-forbidden";
                    parent.Fields.Add(field);
                }
                return "ok";
            }
            if (operation.Kind == "reserve-illegal-type")
            {
                if (!operation.Id.HasValue) return "reserve-missing-literal";
                if (policy.ReservedTypeRange == null || !policy.ReservedTypeRange.Contains(operation.Id.Value)) return "reserve-id-out-of-range";
                if (types.ContainsKey(operation.Name) || !reservations.Add(operation.Name)) return "duplicate-identifier";
                return "ok";
            }
            return "op-unknown";
        }

        private static string RegisterType(string name, CatalogOperation operation, string production, Dictionary<string, CatalogType> types, HashSet<string> reservations)
        {
            if (types.ContainsKey(name) || reservations.Contains(name)) return "duplicate-identifier";
            types.Add(name, new CatalogType { Operation = operation, Production = production });
            return "ok";
        }

        private static string ValidateReferences(CatalogOperation operation, Dictionary<string, CatalogType> types, HashSet<string> reservations)
        {
            List<string> references = new List<string>();
            if (operation.Kind == "field") references.Add(operation.Type);
            if (operation.Kind == "message") references.Add(operation.PayloadRoot);
            if (operation.Kind == "type" && (operation.Production == "List" || operation.Production == "Set")) references.Add(operation.ElementType);
            if (operation.Kind == "union") for (int branch = 0; branch < operation.Branches.Count; branch++) for (int field = 0; field < operation.Branches[branch].Fields.Count; field++) references.Add(operation.Branches[branch].Fields[field].Type);
            if (operation.Kind == "extend") for (int field = 0; field < operation.Fields.Count; field++) references.Add(operation.Fields[field].Type);
            for (int index = 0; index < references.Count; index++)
            {
                string reference = references[index];
                if (reservations.Contains(reference)) return "reserve-illegal-encoded";
                CatalogType target;
                if (types.TryGetValue(reference, out target))
                {
                    if (target.Deleted) return "delete-then-use";
                    continue;
                }
                if (Contains(ForbiddenPrimitives, reference)) return "primitive-forbidden";
                if (Contains(BuiltinPrimitives, reference)) continue;
                return operation.Kind == "message" ? "undefined-payload-root" : "unknown-primitive";
            }
            return "ok";
        }

        private static string TryAssignGeneratedId(string category, string channel, int current, FoundationPolicyContract policy, out int assigned)
        {
            if (!TryAdvanceGeneratedId(current, out assigned)) return "generated-id-overflow";
            if (TestGeneratedIdAllowed(category, channel, assigned, policy)) return "ok";
            return category == "kind" ? "reserved-kind-range" : "reserved-type-range";
        }

        private static Dictionary<string, object> CreateTypeDeclaration(CatalogOperation operation, int typeId, List<object> map)
        {
            Dictionary<string, object> declaration = NewDictionary();
            declaration.Add("production", operation.Production);
            declaration.Add("name", operation.Name);
            declaration.Add("typeId", typeId);
            if (operation.Kind == "enum")
            {
                List<object> members = new List<object>();
                for (int index = 0; index < operation.Members.Count; index++)
                {
                    CatalogMember catalogMember = operation.Members[index];
                    Dictionary<string, object> member = NewDictionary();
                    member.Add("name", catalogMember.Name);
                    member.Add("value", catalogMember.Value);
                    members.Add(member);
                    AddMapRow(map, "enum-member", operation.Ordinal, operation.Name + "." + catalogMember.Name, catalogMember.Value, null, index, null);
                }
                declaration.Add("members", members);
            }
            else if (operation.Production == "Named")
            {
                declaration.Add("fields", new List<object>());
            }
            else if (operation.Production == "List" || operation.Production == "Set")
            {
                declaration.Add("elementType", operation.ElementType);
                declaration.Add("minCount", operation.MinCount);
                declaration.Add("maxCount", operation.MaxCount);
            }
            else
            {
                declaration.Add("encoding", operation.Encoding);
                declaration.Add("grammar", operation.Grammar);
                declaration.Add("minBytes", operation.MinBytes);
                declaration.Add("maxBytes", operation.MaxBytes);
                declaration.Add("maxUtf16CodeUnits", operation.MaxUtf16CodeUnits);
            }
            return declaration;
        }

        private static bool UnionProjectionFits(List<object> currentTypes, List<object> currentMap, CatalogOperation operation, FoundationCatalogExpansion expansion, int typeNext, FoundationPolicyContract policy)
        {
            List<object> projectedTypes = new List<object>(currentTypes);
            CatalogMap projectedMap = new CatalogMap();
            for (int currentIndex = 0; currentIndex < currentMap.Count; currentIndex++)
            {
                Dictionary<string, object> currentRow = (Dictionary<string, object>)currentMap[currentIndex];
                ReserveMapRow(projectedMap, currentRow);
                projectedMap.Add(currentRow);
            }
            int projectedTypeId = typeNext;
            Dictionary<string, object> discriminator = NewDictionary();
            discriminator.Add("production", "EnumU16");
            discriminator.Add("name", operation.Discriminator);
            discriminator.Add("typeId", projectedTypeId++);
            List<object> members = new List<object>();
            discriminator.Add("members", members);
            projectedTypes.Add(discriminator);
            AddMapRow(projectedMap, "type", operation.Ordinal, operation.Discriminator, projectedTypeId - 1, null, null, null);
            int liveBranchIndex = 0;
            for (int branchIndex = 0; branchIndex < operation.Branches.Count; branchIndex++)
            {
                CatalogBranch branch = operation.Branches[branchIndex];
                if (expansion.Types[branch.Name].Deleted)
                {
                    continue;
                }
                Dictionary<string, object> member = NewDictionary();
                member.Add("name", branch.Name);
                member.Add("value", liveBranchIndex);
                members.Add(member);
                AddMapRow(projectedMap, "enum-member", operation.Ordinal, operation.Discriminator + "." + branch.Name, liveBranchIndex, null, liveBranchIndex, null);
                Dictionary<string, object> branchDeclaration = NewDictionary();
                branchDeclaration.Add("production", "Named");
                branchDeclaration.Add("name", branch.Name);
                branchDeclaration.Add("typeId", projectedTypeId);
                branchDeclaration.Add("fields", new List<object>());
                for (int fieldIndex = 0; fieldIndex < branch.Fields.Count; fieldIndex++)
                {
                    CatalogField field = branch.Fields[fieldIndex];
                    AddField(branchDeclaration, field, fieldIndex + 1);
                    AddMapRow(projectedMap, "field", operation.Ordinal, branch.Name + "." + field.Name, fieldIndex + 1, null, null, null);
                }
                projectedTypes.Add(branchDeclaration);
                AddMapRow(projectedMap, "union-branch", operation.Ordinal, branch.Name, projectedTypeId, null, null, liveBranchIndex);
                projectedTypeId++;
                liveBranchIndex++;
            }
            if (projectedTypes.Count > MaximumSchemaTypes || projectedMap.Count > MaximumMapRows)
            {
                return false;
            }
            Dictionary<string, object> schema = NewDictionary();
            schema.Add("schemaVersion", 1);
            schema.Add("schemaId", policy.EmitSchemaId);
            schema.Add("types", projectedTypes);
            byte[] schemaBytes = CanonicalJson.Bytes(schema);
            byte[] mapBytes = CanonicalJson.Bytes(projectedMap);
            return schemaBytes.Length <= MaximumEmittedJsonBytes
                && mapBytes.Length <= MaximumEmittedJsonBytes
                && SchemaBootstrap.Evaluate("json", mapBytes, null).Accepted;
        }

        private static void AddField(Dictionary<string, object> declaration, CatalogField field, int fieldId)
        {
            ((List<object>)declaration["fields"]).Add(CreateField(field, fieldId));
        }

        private static void AddFieldInIdOrder(Dictionary<string, object> declaration, CatalogField field, int fieldId)
        {
            List<object> fields = (List<object>)declaration["fields"];
            int index = fields.Count;
            while (index > 0 && (int)((Dictionary<string, object>)fields[index - 1])["fieldId"] > fieldId)
            {
                index--;
            }
            fields.Insert(index, CreateField(field, fieldId));
        }

        private static Dictionary<string, object> CreateField(CatalogField field, int fieldId)
        {
            Dictionary<string, object> output = NewDictionary();
            output.Add("name", field.Name);
            output.Add("fieldId", fieldId);
            output.Add("type", field.Type);
            if (field.Type == "BoundedBytes") output.Add("maxBytes", field.MaxBytes.Value);
            if (field.Type == "OpaqueUtf16") output.Add("maxCodeUnits", field.MaxCodeUnits.Value);
            return output;
        }

        private static FoundationCatalogAssignment AssignmentFailure(string reason, string ir)
        {
            return new FoundationCatalogAssignment(false, reason, null, CanonicalJson.Bytes(new List<object>()), ir);
        }

        private static string ValidateFinalSchemaStructure(List<object> outputTypes)
        {
            if (outputTypes.Count == 0)
            {
                return "missing-property";
            }
            Dictionary<string, List<string>> referencesByName = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            for (int index = 0; index < outputTypes.Count; index++)
            {
                Dictionary<string, object> declaration = (Dictionary<string, object>)outputTypes[index];
                referencesByName.Add((string)declaration["name"], new List<string>());
            }
            for (int index = 0; index < outputTypes.Count; index++)
            {
                Dictionary<string, object> declaration = (Dictionary<string, object>)outputTypes[index];
                string production = (string)declaration["production"];
                List<string> references = referencesByName[(string)declaration["name"]];
                if (string.Equals(production, "Named", StringComparison.Ordinal))
                {
                    List<object> fields = (List<object>)declaration["fields"];
                    if (fields.Count == 0)
                    {
                        return "missing-property";
                    }
                    for (int fieldIndex = 0; fieldIndex < fields.Count; fieldIndex++)
                    {
                        references.Add((string)((Dictionary<string, object>)fields[fieldIndex])["type"]);
                    }
                }
                else if (string.Equals(production, "List", StringComparison.Ordinal)
                    || string.Equals(production, "Set", StringComparison.Ordinal))
                {
                    references.Add((string)declaration["elementType"]);
                }
            }
            Dictionary<string, int> states = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (string name in referencesByName.Keys)
            {
                if (states.ContainsKey(name))
                {
                    continue;
                }
                Stack<string> names = new Stack<string>();
                Stack<int> indexes = new Stack<int>();
                states.Add(name, 1);
                names.Push(name);
                indexes.Push(0);
                while (names.Count != 0)
                {
                    string current = names.Peek();
                    int referenceIndex = indexes.Pop();
                    List<string> references = referencesByName[current];
                    if (referenceIndex >= references.Count)
                    {
                        names.Pop();
                        states[current] = 2;
                        continue;
                    }
                    indexes.Push(referenceIndex + 1);
                    string target = references[referenceIndex];
                    if (!referencesByName.ContainsKey(target))
                    {
                        continue;
                    }
                    int targetState;
                    if (states.TryGetValue(target, out targetState))
                    {
                        if (targetState == 1)
                        {
                            return "type-cycle";
                        }
                        continue;
                    }
                    states.Add(target, 1);
                    names.Push(target);
                    indexes.Push(0);
                }
            }
            return "ok";
        }

        private static void AddMapRow(List<object> map, string category, int ordinal, string name, int generatedId, string channel, int? memberIndex, int? branchIndex)
        {
            Dictionary<string, object> row = NewDictionary();
            row.Add("schemaId", MapSchemaId);
            row.Add("category", category);
            row.Add("catalogOrdinal", ordinal);
            row.Add("name", name);
            row.Add("generatedId", generatedId);
            if (channel != null) row.Add("channel", channel);
            if (memberIndex.HasValue) row.Add("memberIndex", memberIndex.Value);
            if (branchIndex.HasValue) row.Add("branchIndex", branchIndex.Value);
            CatalogMap catalogMap = map as CatalogMap;
            if (catalogMap != null)
            {
                ReserveMapRow(catalogMap, row);
            }
            map.Add(row);
        }

        private static void ReserveMapRow(CatalogMap map, Dictionary<string, object> row)
        {
            byte[] rowBytes = CanonicalJson.Bytes(row);
            int separatorBytes = map.Count == 0 ? 0 : 1;
            int projectedBytes = checked(map.EncodedBytes + separatorBytes + rowBytes.Length);
            long projectedNodes = checked(map.NodeCount + 1L + (2L * row.Count));
            long projectedAllocation = checked((long)projectedBytes + (16L * projectedNodes));
            if (map.Count + 1 > MaximumMapRows
                || projectedBytes > MaximumEmittedJsonBytes
                || projectedAllocation > 2097152L)
            {
                throw new CatalogMapBudgetException();
            }
            map.EncodedBytes = projectedBytes;
            map.NodeCount = projectedNodes;
        }

        private static bool ValidateMap(byte[] mapBytes)
        {
            SchemaCheckResult jsonResult = SchemaBootstrap.Evaluate("json", mapBytes, null);
            if (!jsonResult.Accepted) return false;
            JArray rows;
            try
            {
                rows = new JsonParser(mapBytes).Parse() as JArray;
            }
            catch
            {
                return false;
            }
            if (rows == null) return false;
            for (int index = 0; index < rows.Values.Count; index++)
            {
                JObject row = rows.Values[index] as JObject;
                if (row == null) return false;
                string category;
                if (!TryString(row, "category", out category) || !Contains(MapCategories, category)) return false;
                List<string> required = new List<string>(new string[] { "schemaId", "category", "catalogOrdinal", "name", "generatedId" });
                List<string> forbidden = new List<string>();
                if (category == "kind")
                {
                    required.Add("channel");
                    forbidden.Add("memberIndex");
                    forbidden.Add("branchIndex");
                }
                else if (category == "enum-member")
                {
                    required.Add("memberIndex");
                    forbidden.Add("channel");
                    forbidden.Add("branchIndex");
                }
                else if (category == "union-branch")
                {
                    required.Add("branchIndex");
                    forbidden.Add("channel");
                    forbidden.Add("memberIndex");
                }
                else
                {
                    forbidden.Add("channel");
                    forbidden.Add("memberIndex");
                    forbidden.Add("branchIndex");
                }
                if (row.Values.Count != required.Count) return false;
                for (int requiredIndex = 0; requiredIndex < required.Count; requiredIndex++) if (!row.Values.ContainsKey(required[requiredIndex])) return false;
                for (int forbiddenIndex = 0; forbiddenIndex < forbidden.Count; forbiddenIndex++) if (row.Values.ContainsKey(forbidden[forbiddenIndex])) return false;
                string schemaId;
                string name;
                long ordinal;
                long generated;
                if (!TryString(row, "schemaId", out schemaId) || schemaId != MapSchemaId || !TryString(row, "name", out name) || !TryInteger(row, "catalogOrdinal", out ordinal) || ordinal < 1 || !TryInteger(row, "generatedId", out generated) || generated < 0 || generated > 65535) return false;
            }
            return true;
        }

        private static Dictionary<string, object> NewDictionary()
        {
            return new Dictionary<string, object>(StringComparer.Ordinal);
        }

        private static bool CheckExactKeys(JObject value, string[] expected, out string reason)
        {
            foreach (string key in value.Values.Keys)
            {
                if (!Contains(expected, key))
                {
                    reason = "extra-key";
                    return false;
                }
            }
            for (int index = 0; index < expected.Length; index++)
            {
                if (!value.Values.ContainsKey(expected[index]))
                {
                    reason = "missing-property";
                    return false;
                }
            }
            reason = "ok";
            return true;
        }

        private static bool ValidateNumericSemantics(JObject entry, string operation, out string reason)
        {
            if (operation == "enum")
            {
                JArray members;
                if (TryArray(entry, "members", out members))
                {
                    for (int index = 0; index < members.Values.Count; index++)
                    {
                        JObject member = members.Values[index] as JObject;
                        if (member != null && member.Values.ContainsKey("value")
                            && !IntegerPropertyFits(member, "value", 0, 65535))
                        {
                            reason = "enum-value-overflow";
                            return false;
                        }
                    }
                }
            }
            if (operation == "type")
            {
                string[] properties = new string[] { "minCount", "maxCount", "minBytes", "maxBytes", "maxUtf16CodeUnits" };
                for (int index = 0; index < properties.Length; index++)
                {
                    if (entry.Values.ContainsKey(properties[index])
                        && !IntegerPropertyFits(entry, properties[index], int.MinValue, int.MaxValue))
                    {
                        reason = "invalid-production";
                        return false;
                    }
                }
            }
            if (operation == "field")
            {
                if ((entry.Values.ContainsKey("maxBytes") && !IntegerPropertyFits(entry, "maxBytes", int.MinValue, int.MaxValue))
                    || (entry.Values.ContainsKey("maxCodeUnits") && !IntegerPropertyFits(entry, "maxCodeUnits", int.MinValue, int.MaxValue)))
                {
                    reason = "invalid-production";
                    return false;
                }
            }
            if (operation == "union")
            {
                JArray branches;
                if (TryArray(entry, "branches", out branches))
                {
                    if (branches.Values.Count > MaxUnionBranchCount)
                    {
                        reason = "enum-value-overflow";
                        return false;
                    }
                    for (int branchIndex = 0; branchIndex < branches.Values.Count; branchIndex++)
                    {
                        JObject branch = branches.Values[branchIndex] as JObject;
                        JArray fields;
                        if (branch != null && TryArray(branch, "fields", out fields)
                            && !ValidateFieldNumericProperties(fields, false, out reason))
                        {
                            return false;
                        }
                    }
                }
            }
            if (operation == "extend")
            {
                JArray fields;
                if (TryArray(entry, "fields", out fields)
                    && !ValidateFieldNumericProperties(fields, true, out reason))
                {
                    return false;
                }
            }
            if (operation == "reserve-illegal-type" && entry.Values.ContainsKey("id")
                && !IntegerPropertyFits(entry, "id", int.MinValue, int.MaxValue))
            {
                reason = "reserve-id-out-of-range";
                return false;
            }
            reason = "ok";
            return true;
        }

        private static bool ValidateFieldNumericProperties(JArray fields, bool extension, out string reason)
        {
            for (int index = 0; index < fields.Values.Count; index++)
            {
                JObject field = fields.Values[index] as JObject;
                if (field == null)
                {
                    continue;
                }
                if (extension && field.Values.ContainsKey("id")
                    && !IntegerPropertyFits(field, "id", int.MinValue, 65535))
                {
                    reason = "extend-id-overflow";
                    return false;
                }
                if ((field.Values.ContainsKey("maxBytes") && !IntegerPropertyFits(field, "maxBytes", int.MinValue, int.MaxValue))
                    || (field.Values.ContainsKey("maxCodeUnits") && !IntegerPropertyFits(field, "maxCodeUnits", int.MinValue, int.MaxValue)))
                {
                    reason = "invalid-production";
                    return false;
                }
            }
            reason = "ok";
            return true;
        }

        private static bool IntegerPropertyFits(JObject value, string key, int minimum, int maximum)
        {
            JNode node;
            if (!value.Values.TryGetValue(key, out node))
            {
                return false;
            }
            JInteger integer = node as JInteger;
            if (integer == null)
            {
                return false;
            }
            if (minimum >= 0 && integer.Value.Length > 0 && integer.Value[0] == '-')
            {
                return false;
            }
            long parsed;
            return long.TryParse(integer.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out parsed)
                && parsed >= minimum
                && parsed <= maximum;
        }

        private static byte[] NormalizeIntegersForStrictJson(byte[] source)
        {
            byte[] normalized = (byte[])source.Clone();
            bool escaped = false;
            bool insideString = false;
            for (int index = 0; index < normalized.Length; index++)
            {
                byte current = normalized[index];
                if (insideString)
                {
                    if (escaped)
                    {
                        escaped = false;
                    }
                    else if (current == (byte)'\\')
                    {
                        escaped = true;
                    }
                    else if (current == (byte)'"')
                    {
                        insideString = false;
                    }
                    continue;
                }
                if (current == (byte)'"')
                {
                    insideString = true;
                    continue;
                }
                if (current != (byte)'-' && (current < (byte)'0' || current > (byte)'9'))
                {
                    continue;
                }
                int start = index;
                if (current == (byte)'-')
                {
                    index++;
                }
                int firstDigit = index;
                while (index < normalized.Length && normalized[index] >= (byte)'0' && normalized[index] <= (byte)'9')
                {
                    index++;
                }
                if (index == firstDigit)
                {
                    index = start;
                    continue;
                }
                if (index < normalized.Length && (normalized[index] == (byte)'.' || normalized[index] == (byte)'e' || normalized[index] == (byte)'E'))
                {
                    index = start;
                    continue;
                }
                normalized[start] = (byte)'0';
                for (int replaceIndex = start + 1; replaceIndex < index; replaceIndex++)
                {
                    normalized[replaceIndex] = (byte)' ';
                }
                index--;
            }
            return normalized;
        }

        private static bool TryString(JObject value, string key, out string result)
        {
            result = null;
            JNode node;
            if (!value.Values.TryGetValue(key, out node)) return false;
            JString text = node as JString;
            if (text == null) return false;
            result = text.Value;
            return true;
        }

        private static bool TryInteger(JObject value, string key, out long result)
        {
            result = 0;
            JNode node;
            if (!value.Values.TryGetValue(key, out node)) return false;
            JInteger integer = node as JInteger;
            if (integer == null) return false;
            return long.TryParse(integer.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out result);
        }

        private static bool TryArray(JObject value, string key, out JArray result)
        {
            result = null;
            JNode node;
            if (!value.Values.TryGetValue(key, out node)) return false;
            result = node as JArray;
            return result != null;
        }

        private static bool Contains(string[] values, string candidate)
        {
            if (candidate == null) return false;
            for (int index = 0; index < values.Length; index++)
            {
                if (string.Equals(values[index], candidate, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        private static bool EqualBytes(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }
    }
}
