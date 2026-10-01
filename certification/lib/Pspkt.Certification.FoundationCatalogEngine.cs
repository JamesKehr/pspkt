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

    public sealed class ProtocolCatalogContractV2
    {
        private static readonly TimeSpan NameRegexTimeout = TimeSpan.FromMilliseconds(100);
        private readonly string _baseCatalogSchemaId;
        private readonly string _baseCatalogSpace;
        private readonly string[] _channels;
        private readonly string _emitSchemaId;
        private readonly int _generatedFieldIdMax;
        private readonly string[] _literalExtensionParentNames;
        private readonly string _mapSchemaId;
        private readonly Dictionary<string, string> _messageEnumNameByChannel;
        private readonly string _namePredicate;
        private readonly Regex _nameRegex;
        private readonly string _overlayCatalogSchemaId;
        private readonly string _overlayCatalogSpace;
        private readonly Dictionary<string, GeneratedIdRange[]> _overlayKindRangesByChannel;
        private readonly GeneratedIdRange _overlayTypeRange;
        private readonly Dictionary<string, string[]> _permittedDirectionsByChannel;

        public ProtocolCatalogContractV2(
            string namePredicate,
            string baseCatalogSchemaId,
            string baseCatalogSpace,
            string overlayCatalogSchemaId,
            string overlayCatalogSpace,
            string emitSchemaId,
            string mapSchemaId,
            string[] channels,
            IDictionary<string, string> messageEnumNameByChannel,
            IDictionary<string, string[]> permittedDirectionsByChannel,
            IDictionary<string, GeneratedIdRange[]> overlayKindRangesByChannel,
            GeneratedIdRange overlayTypeRange,
            int generatedFieldIdMax,
            string[] literalExtensionParentNames)
        {
            if (namePredicate == null) throw new ArgumentNullException("namePredicate");
            if (baseCatalogSchemaId == null) throw new ArgumentNullException("baseCatalogSchemaId");
            if (baseCatalogSpace == null) throw new ArgumentNullException("baseCatalogSpace");
            if (overlayCatalogSchemaId == null) throw new ArgumentNullException("overlayCatalogSchemaId");
            if (overlayCatalogSpace == null) throw new ArgumentNullException("overlayCatalogSpace");
            if (emitSchemaId == null) throw new ArgumentNullException("emitSchemaId");
            if (mapSchemaId == null) throw new ArgumentNullException("mapSchemaId");
            if (channels == null) throw new ArgumentNullException("channels");
            if (messageEnumNameByChannel == null) throw new ArgumentNullException("messageEnumNameByChannel");
            if (permittedDirectionsByChannel == null) throw new ArgumentNullException("permittedDirectionsByChannel");
            if (overlayKindRangesByChannel == null) throw new ArgumentNullException("overlayKindRangesByChannel");
            if (overlayTypeRange == null) throw new ArgumentNullException("overlayTypeRange");
            if (literalExtensionParentNames == null) throw new ArgumentNullException("literalExtensionParentNames");
            Regex nameRegex;
            try
            {
                nameRegex = new Regex(namePredicate, RegexOptions.CultureInvariant, NameRegexTimeout);
            }
            catch (ArgumentException exception)
            {
                throw new ArgumentException("The name predicate is not a valid regular expression.", "namePredicate", exception);
            }
            ValidateSchemaId(baseCatalogSchemaId, "baseCatalogSchemaId");
            ValidateSchemaId(overlayCatalogSchemaId, "overlayCatalogSchemaId");
            ValidateSchemaId(emitSchemaId, "emitSchemaId");
            ValidateSchemaId(mapSchemaId, "mapSchemaId");
            if (!ProtocolCatalogSyntax.IsProtocolIdentifier(baseCatalogSpace))
            {
                throw new ArgumentException("A protocol identifier is required.", "baseCatalogSpace");
            }
            if (!ProtocolCatalogSyntax.IsProtocolIdentifier(overlayCatalogSpace))
            {
                throw new ArgumentException("A protocol identifier is required.", "overlayCatalogSpace");
            }
            if (generatedFieldIdMax < 1 || generatedFieldIdMax > 65535)
            {
                throw new ArgumentOutOfRangeException("generatedFieldIdMax");
            }
            if (overlayTypeRange.Start < 1 || overlayTypeRange.End > 65535)
            {
                throw new ArgumentOutOfRangeException("overlayTypeRange");
            }
            if (channels.Length == 0)
            {
                throw new ArgumentException("At least one channel is required.", "channels");
            }
            HashSet<string> channelNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (string channel in channels)
            {
                if (!ProtocolCatalogSyntax.IsProtocolIdentifier(channel) || !channelNames.Add(channel))
                {
                    throw new ArgumentException("Channels must be distinct protocol identifiers.", "channels");
                }
            }
            ValidateChannelKeys(channelNames, messageEnumNameByChannel.Keys, "messageEnumNameByChannel");
            ValidateChannelKeys(channelNames, permittedDirectionsByChannel.Keys, "permittedDirectionsByChannel");
            ValidateChannelKeys(channelNames, overlayKindRangesByChannel.Keys, "overlayKindRangesByChannel");
            foreach (KeyValuePair<string, string> pair in messageEnumNameByChannel)
            {
                ValidateTypeName(pair.Value, nameRegex, "messageEnumNameByChannel");
            }
            foreach (KeyValuePair<string, string[]> pair in permittedDirectionsByChannel)
            {
                if (pair.Value == null || pair.Value.Length == 0)
                {
                    throw new ArgumentException("Every channel requires permitted directions.", "permittedDirectionsByChannel");
                }
                HashSet<string> directions = new HashSet<string>(StringComparer.Ordinal);
                foreach (string direction in pair.Value)
                {
                    if (!ProtocolCatalogSyntax.IsProtocolIdentifier(direction) || !directions.Add(direction))
                    {
                        throw new ArgumentException("Directions must be distinct protocol identifiers.", "permittedDirectionsByChannel");
                    }
                }
            }
            foreach (KeyValuePair<string, GeneratedIdRange[]> pair in overlayKindRangesByChannel)
            {
                if (pair.Value == null)
                {
                    throw new ArgumentException("Channel ranges cannot be null.", "overlayKindRangesByChannel");
                }
                int previousEnd = -1;
                foreach (GeneratedIdRange range in pair.Value)
                {
                    if (range == null || range.Start <= previousEnd)
                    {
                        throw new ArgumentException("Channel ranges must be ordered and nonoverlapping.", "overlayKindRangesByChannel");
                    }
                    previousEnd = range.End;
                }
            }
            HashSet<string> parentNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (string parentName in literalExtensionParentNames)
            {
                ValidateTypeName(parentName, nameRegex, "literalExtensionParentNames");
                if (!parentNames.Add(parentName))
                {
                    throw new ArgumentException("Extension parent names must be distinct.", "literalExtensionParentNames");
                }
            }
            _namePredicate = namePredicate;
            _nameRegex = nameRegex;
            _baseCatalogSchemaId = baseCatalogSchemaId;
            _baseCatalogSpace = baseCatalogSpace;
            _overlayCatalogSchemaId = overlayCatalogSchemaId;
            _overlayCatalogSpace = overlayCatalogSpace;
            _emitSchemaId = emitSchemaId;
            _mapSchemaId = mapSchemaId;
            _channels = (string[])channels.Clone();
            _messageEnumNameByChannel = new Dictionary<string, string>(messageEnumNameByChannel, StringComparer.Ordinal);
            _permittedDirectionsByChannel = CopyDirections(permittedDirectionsByChannel);
            _overlayKindRangesByChannel = CopyRanges(overlayKindRangesByChannel);
            _overlayTypeRange = new GeneratedIdRange(overlayTypeRange.Start, overlayTypeRange.End);
            _generatedFieldIdMax = generatedFieldIdMax;
            _literalExtensionParentNames = (string[])literalExtensionParentNames.Clone();
        }

        public string BaseCatalogSchemaId { get { return _baseCatalogSchemaId; } }
        public string BaseCatalogSpace { get { return _baseCatalogSpace; } }
        public string[] Channels { get { return (string[])_channels.Clone(); } }
        public string EmitSchemaId { get { return _emitSchemaId; } }
        public int GeneratedFieldIdMax { get { return _generatedFieldIdMax; } }
        public string[] LiteralExtensionParentNames { get { return (string[])_literalExtensionParentNames.Clone(); } }
        public string MapSchemaId { get { return _mapSchemaId; } }
        public IDictionary<string, string> MessageEnumNameByChannel { get { return new Dictionary<string, string>(_messageEnumNameByChannel, StringComparer.Ordinal); } }
        public string NamePredicate { get { return _namePredicate; } }
        public string OverlayCatalogSchemaId { get { return _overlayCatalogSchemaId; } }
        public string OverlayCatalogSpace { get { return _overlayCatalogSpace; } }
        public IDictionary<string, GeneratedIdRange[]> OverlayKindRangesByChannel { get { return CopyRanges(_overlayKindRangesByChannel); } }
        public GeneratedIdRange OverlayTypeRange { get { return new GeneratedIdRange(_overlayTypeRange.Start, _overlayTypeRange.End); } }
        public IDictionary<string, string[]> PermittedDirectionsByChannel { get { return CopyDirections(_permittedDirectionsByChannel); } }

        internal bool MatchesName(string name)
        {
            try
            {
                return _nameRegex.IsMatch(name);
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        private static Dictionary<string, string[]> CopyDirections(IDictionary<string, string[]> source)
        {
            Dictionary<string, string[]> copy = new Dictionary<string, string[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string[]> pair in source)
            {
                copy.Add(pair.Key, (string[])pair.Value.Clone());
            }
            return copy;
        }

        private static Dictionary<string, GeneratedIdRange[]> CopyRanges(IDictionary<string, GeneratedIdRange[]> source)
        {
            Dictionary<string, GeneratedIdRange[]> copy = new Dictionary<string, GeneratedIdRange[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, GeneratedIdRange[]> pair in source)
            {
                GeneratedIdRange[] ranges = new GeneratedIdRange[pair.Value.Length];
                for (int index = 0; index < ranges.Length; index++)
                {
                    ranges[index] = new GeneratedIdRange(pair.Value[index].Start, pair.Value[index].End);
                }
                copy.Add(pair.Key, ranges);
            }
            return copy;
        }

        private static void ValidateChannelKeys(HashSet<string> channels, ICollection<string> keys, string parameterName)
        {
            if (keys.Count != channels.Count || !channels.SetEquals(keys))
            {
                throw new ArgumentException("Dictionary keys must exactly match the channels.", parameterName);
            }
        }

        private static void ValidateSchemaId(string value, string parameterName)
        {
            if (!ProtocolCatalogSyntax.IsSchemaIdentifier(value))
            {
                throw new ArgumentException("A schema identifier is required.", parameterName);
            }
        }

        private static void ValidateTypeName(string value, Regex nameRegex, string parameterName)
        {
            if (!ProtocolCatalogSyntax.IsSchemaIdentifier(value))
            {
                throw new ArgumentException("A nonprimitive schema identifier matching the name predicate is required.", parameterName);
            }
            bool matches;
            try
            {
                matches = nameRegex.IsMatch(value);
            }
            catch (RegexMatchTimeoutException exception)
            {
                throw new ArgumentException("The name predicate exceeded its match timeout.", parameterName, exception);
            }
            if (!matches || ProtocolCatalogSyntax.IsPrimitive(value))
            {
                throw new ArgumentException("A nonprimitive schema identifier matching the name predicate is required.", parameterName);
            }
        }
    }

    public sealed class ProtocolCatalogResultV2
    {
        private readonly bool _accepted;
        private readonly byte[] _idMapBytes;
        private readonly string _reason;
        private readonly byte[] _schemaBytes;

        internal ProtocolCatalogResultV2(bool accepted, string reason, byte[] schemaBytes, byte[] idMapBytes)
        {
            _accepted = accepted;
            _reason = reason;
            _schemaBytes = schemaBytes == null ? null : (byte[])schemaBytes.Clone();
            _idMapBytes = idMapBytes == null ? null : (byte[])idMapBytes.Clone();
        }

        public bool Accepted { get { return _accepted; } }
        public byte[] IdMapBytes { get { return _idMapBytes == null ? null : (byte[])_idMapBytes.Clone(); } }
        public string Reason { get { return _reason; } }
        public byte[] SchemaBytes { get { return _schemaBytes == null ? null : (byte[])_schemaBytes.Clone(); } }
    }

    internal static class ProtocolCatalogSyntax
    {
        private static readonly HashSet<string> Primitives = new HashSet<string>(new string[]
        {
            "U8", "U16", "U32", "U64", "I16", "I32", "I64", "FILETIME", "QPC", "GUID", "Opaque16", "FixedAscii8",
            "SHA-256", "Opaque32", "AsciiIdentifier", "BinarySid", "Utf8Short", "Rsa3072PublicBlob", "Rsa3072Signature",
            "LUID", "BoundedBytes", "OpaqueUtf16"
        }, StringComparer.Ordinal);

        internal static bool IsForbiddenPrimitive(string value)
        {
            return value == "I16" || value == "I32" || value == "I64" || value == "OpaqueUtf16";
        }

        internal static bool IsPrimitive(string value)
        {
            return value != null && Primitives.Contains(value);
        }

        internal static bool IsProtocolIdentifier(string value)
        {
            if (value == null || value.Length < 1 || value.Length > 128) return false;
            foreach (char character in value)
            {
                if (!IsLetter(character) && (character < '0' || character > '9')
                    && character != '.' && character != '_' && character != ':' && character != '-') return false;
            }
            return true;
        }

        internal static bool IsSchemaIdentifier(string value)
        {
            if (value == null || value.Length < 1 || value.Length > 64 || !IsLetter(value[0])) return false;
            for (int index = 1; index < value.Length; index++)
            {
                char character = value[index];
                if (!IsLetter(character) && (character < '0' || character > '9') && character != '-') return false;
            }
            return true;
        }

        private static bool IsLetter(char character)
        {
            return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z');
        }
    }

    public static class ProtocolCatalogEngineV2
    {
        private const int MaximumFields = 4096;
        private const int MaximumSchemaTypes = 4096;
        private const int MaximumMapRows = 8192;
        private const int MaximumJsonBytes = 1048576;
        private const string InteractiveProfile = "InteractiveSeat";
        private const string NonInteractiveProfile = "NonInteractiveElevated";
        private static readonly string[] Profiles = new string[] { InteractiveProfile, NonInteractiveProfile };

        public static string[] ReasonCodes()
        {
            return new string[]
            {
                "ok", "invalid-utf8", "bom-forbidden", "nul-forbidden", "comment-forbidden", "duplicate-key",
                "trailing-comma", "trailing-data", "float-forbidden", "exponent-forbidden", "negative-integer",
                "leading-zero-integer", "integer-overflow", "invalid-escape", "unpaired-surrogate",
                "replacement-character-forbidden", "file-limit", "depth-limit", "property-limit", "array-limit",
                "string-limit", "allocation-budget", "unknown-property", "missing-property", "duplicate-identifier",
                "unknown-primitive", "undefined-reference", "type-cycle", "duplicate-type-id", "duplicate-field-id",
                "field-order", "invalid-cardinality", "bound-overflow", "non-ascii-symbol", "meta-authority-mismatch",
                "invalid-field-condition", "extra-key", "op-unknown", "op-replace-forbidden", "op-source-forbidden",
                "catalog-identity", "catalog-name", "base-literal-id", "primitive-forbidden", "invalid-production",
                "invalid-profile", "invalid-tail-class", "invalid-state-association", "invalid-direction",
                "invalid-channel", "field-undefined-parent", "extend-invalid-parent", "extension-parent-forbidden",
                "undefined-payload-root", "delete-unknown", "delete-double", "delete-then-use", "reserve-missing-literal",
                "reserve-id-out-of-range", "reserve-illegal-encoded", "overlay-id-out-of-range", "enum-duplicate-name",
                "enum-duplicate-value", "enum-value-overflow", "union-empty", "union-duplicate-branch",
                "extend-missing-literal", "extend-dup-name", "extend-dup-id", "message-metadata-conflict",
                "duplicate-kind", "duplicate-field-set", "field-overflow", "reserved-kind-range", "reserved-type-range",
                "generated-id-overflow", "id-map-drift", "map-tamper"
            };
        }

        public static ProtocolCatalogResultV2 Evaluate(byte[] baseCatalogBytes, byte[] overlayCatalogBytes, ProtocolCatalogContractV2 contract)
        {
            if (baseCatalogBytes == null) throw new ArgumentNullException("baseCatalogBytes");
            if (overlayCatalogBytes == null) throw new ArgumentNullException("overlayCatalogBytes");
            if (contract == null) throw new ArgumentNullException("contract");
            try
            {
                EvaluationState state = ReadCatalogs((byte[])baseCatalogBytes.Clone(), (byte[])overlayCatalogBytes.Clone(), contract);
                Expand(state);
                ValidateReferences(state);
                return AssignAndEmit(state);
            }
            catch (CatalogValidationException exception)
            {
                return new ProtocolCatalogResultV2(false, exception.Reason, null, null);
            }
            catch (OverflowException)
            {
                return new ProtocolCatalogResultV2(false, "integer-overflow", null, null);
            }
        }

        public static FoundationReplayResult Replay(byte[] baseCatalogBytes, byte[] overlayCatalogBytes, byte[] schemaBytes, byte[] mapBytes, ProtocolCatalogContractV2 contract)
        {
            if (baseCatalogBytes == null) throw new ArgumentNullException("baseCatalogBytes");
            if (overlayCatalogBytes == null) throw new ArgumentNullException("overlayCatalogBytes");
            if (schemaBytes == null) throw new ArgumentNullException("schemaBytes");
            if (mapBytes == null) throw new ArgumentNullException("mapBytes");
            if (contract == null) throw new ArgumentNullException("contract");
            schemaBytes = (byte[])schemaBytes.Clone();
            mapBytes = (byte[])mapBytes.Clone();
            ProtocolCatalogResultV2 regenerated = Evaluate(baseCatalogBytes, overlayCatalogBytes, contract);
            if (!regenerated.Accepted) return new FoundationReplayResult(false, regenerated.Reason);
            if (!ValidateMap(mapBytes, contract)) return new FoundationReplayResult(false, "map-tamper");
            if (!EqualBytes(regenerated.SchemaBytes, schemaBytes)) return new FoundationReplayResult(false, "id-map-drift");
            if (!EqualBytes(regenerated.IdMapBytes, mapBytes)) return new FoundationReplayResult(false, "map-tamper");
            return new FoundationReplayResult(true, "ok");
        }

        private static EvaluationState ReadCatalogs(byte[] baseBytes, byte[] overlayBytes, ProtocolCatalogContractV2 contract)
        {
            RequireJson(baseBytes);
            RequireJson(overlayBytes);
            JObject baseRoot = new JsonParser(baseBytes).Parse() as JObject;
            JObject overlayRoot = new JsonParser(overlayBytes).Parse() as JObject;
            JArray baseEntries = ReadRoot(baseRoot, contract.BaseCatalogSchemaId, contract.BaseCatalogSpace);
            JArray overlayEntries = ReadRoot(overlayRoot, contract.OverlayCatalogSchemaId, contract.OverlayCatalogSpace);
            EvaluationState state = new EvaluationState(contract);
            ReadOperations(baseEntries, "base", state);
            ReadOperations(overlayEntries, "overlay", state);
            return state;
        }

        private static JArray ReadRoot(JObject root, string schemaId, string space)
        {
            Require(root != null, "unknown-property");
            CheckProperties(root, new string[] { "entries", "schemaId", "schemaVersion", "space" }, new string[0]);
            Require(ReadString(root, "schemaId") == schemaId && ReadString(root, "space") == space, "catalog-identity");
            Require(ReadInteger(root, "schemaVersion", "missing-property") == 1, "missing-property");
            return ReadArray(root, "entries");
        }

        private static void ReadOperations(JArray entries, string catalog, EvaluationState state)
        {
            for (int index = 0; index < entries.Values.Count; index++)
            {
                JObject entry = entries.Values[index] as JObject;
                Require(entry != null, "unknown-property");
                string kind = ReadString(entry, "op");
                Require(kind != "replace", "op-replace-forbidden");
                Require(IsOperation(kind), "op-unknown");
                bool overlay = catalog == "overlay";
                bool shared = kind == "field-set" || kind == "delete" || kind == "reserve-illegal-type";
                bool overlayOnly = kind == "extend" || kind == "overlay-type" || kind == "overlay-message";
                Require(shared || overlay == overlayOnly, "op-source-forbidden");
                if (kind == "field-set")
                {
                    Require(overlay == entry.Values.ContainsKey("id"), "op-source-forbidden");
                }
                Operation operation = new Operation { Entry = entry, Kind = kind, Catalog = catalog, Ordinal = index + 1 };
                ValidateShape(operation);
                ValidateIdentifiers(operation, state.Contract);
                ValidateDomains(operation, state);
                ValidateTypeNames(operation);
                if (kind == "enum" || kind == "type" || kind == "field" || kind == "message")
                {
                    Require(!entry.Values.ContainsKey("id"), "base-literal-id");
                }
                ValidateProduction(operation);
                state.Operations.Add(operation);
            }
        }

        private static bool IsOperation(string kind)
        {
            return kind == "primitive" || kind == "enum" || kind == "type" || kind == "field" || kind == "field-set"
                || kind == "message" || kind == "union" || kind == "delete" || kind == "extend"
                || kind == "reserve-illegal-type" || kind == "overlay-type" || kind == "overlay-message";
        }

        private static void ValidateShape(Operation operation)
        {
            JObject entry = operation.Entry;
            List<string> required = new List<string>(new string[] { "op" });
            List<string> optional = new List<string>();
            if (operation.Kind != "extend") required.Add("name");
            if (operation.Kind == "enum")
            {
                required.Add("members");
                optional.Add("id");
            }
            else if (operation.Kind == "type" || operation.Kind == "overlay-type")
            {
                required.Add("production");
                if (operation.Kind == "type") optional.Add("id"); else required.Add("id");
                string production = ReadString(entry, "production");
                if (production == "SemanticString")
                {
                    required.AddRange(new string[] { "encoding", "grammar", "minBytes", "maxBytes", "maxUtf16CodeUnits" });
                }
                else if (production == "List" || production == "Set")
                {
                    required.AddRange(new string[] { "elementType", "minCount", "maxCount" });
                }
                else if (production == "EnumU16" && operation.Kind == "overlay-type")
                {
                    required.Add("members");
                }
            }
            else if (operation.Kind == "field")
            {
                required.AddRange(new string[] { "parent", "type" });
                optional.Add("id");
                AddBoundProperties(entry, required);
            }
            else if (operation.Kind == "field-set")
            {
                required.AddRange(new string[] { "parent", "variants" });
                optional.Add("id");
            }
            else if (operation.Kind == "message" || operation.Kind == "overlay-message")
            {
                required.AddRange(new string[] { "channel", "direction", "payloadRoot", "profile", "mandatoryTailClass", "stateAssoc" });
                if (operation.Kind == "message") optional.Add("id"); else required.Add("id");
            }
            else if (operation.Kind == "union")
            {
                required.AddRange(new string[] { "discriminator", "branches" });
            }
            else if (operation.Kind == "extend")
            {
                required.AddRange(new string[] { "parent", "fields" });
            }
            else if (operation.Kind == "reserve-illegal-type")
            {
                optional.Add("id");
            }
            CheckProperties(entry, required.ToArray(), optional.ToArray());
            foreach (string key in required)
            {
                if (key == "members" || key == "variants" || key == "fields" || key == "branches") ReadArray(entry, key);
                else if (IsNumericProperty(key)) ReadNumericProperty(entry, key, NumericReason(operation.Kind, key));
                else ReadString(entry, key);
            }
            if (entry.Values.ContainsKey("id")) ReadInteger(entry, "id", NumericReason(operation.Kind, "id"));
            if (operation.Kind == "enum" || (operation.Kind == "overlay-type" && ReadString(entry, "production") == "EnumU16"))
            {
                JArray members = ReadArray(entry, "members");
                Require(members.Values.Count > 0, "missing-property");
                foreach (JNode memberNode in members.Values)
                {
                    JObject member = RequireObject(memberNode);
                    CheckProperties(member, operation.Kind == "enum" ? new string[] { "name" } : new string[] { "name", "value" },
                        operation.Kind == "enum" ? new string[] { "value" } : new string[0]);
                    ReadString(member, "name");
                    if (member.Values.ContainsKey("value")) ReadInteger(member, "value", "enum-value-overflow");
                }
            }
            if (operation.Kind == "field")
            {
                operation.Fields.Add(ReadField(entry));
            }
            if (operation.Kind == "field-set" || operation.Kind == "extend")
            {
                JArray fields = ReadArray(entry, operation.Kind == "field-set" ? "variants" : "fields");
                Require(fields.Values.Count > 0, "missing-property");
                Require(fields.Values.Count <= MaximumFields, "invalid-cardinality");
                foreach (JNode fieldNode in fields.Values)
                {
                    JObject field = RequireObject(fieldNode);
                    ValidateFieldShape(field, operation.Kind);
                    operation.Fields.Add(ReadField(field));
                }
            }
            if (operation.Kind == "union")
            {
                JArray branches = ReadArray(entry, "branches");
                Require(branches.Values.Count > 0, "union-empty");
                foreach (JNode branchNode in branches.Values)
                {
                    JObject branch = RequireObject(branchNode);
                    CheckProperties(branch, new string[] { "name", "fields" }, new string[0]);
                    Branch branchDeclaration = new Branch { Name = ReadString(branch, "name") };
                    JArray branchFields = ReadArray(branch, "fields");
                    Require(branchFields.Values.Count > 0, "missing-property");
                    Require(branchFields.Values.Count <= MaximumFields, "invalid-cardinality");
                    foreach (JNode fieldNode in branchFields.Values)
                    {
                        JObject field = RequireObject(fieldNode);
                        ValidateFieldShape(field, "union");
                        branchDeclaration.Fields.Add(ReadField(field));
                    }
                    operation.Branches.Add(branchDeclaration);
                }
            }
        }

        private static void ValidateFieldShape(JObject field, string kind)
        {
            List<string> required = new List<string>(new string[] { "name", "type" });
            AddBoundProperties(field, required);
            string[] optional = kind == "field-set" ? new string[] { "profile", "status" }
                : kind == "extend" ? new string[] { "id" } : new string[0];
            CheckProperties(field, required.ToArray(), optional);
            ReadString(field, "name");
            foreach (string property in required)
            {
                if (IsNumericProperty(property)) ReadNumericProperty(field, property, "invalid-production");
            }
            if (field.Values.ContainsKey("id")) ReadInteger(field, "id", "field-overflow");
        }

        private static void AddBoundProperties(JObject field, List<string> required)
        {
            string type = ReadString(field, "type");
            if (type == "BoundedBytes") required.Add("maxBytes");
            if (type == "OpaqueUtf16") required.Add("maxCodeUnits");
        }

        private static Field ReadField(JObject entry)
        {
            Field field = new Field { Name = ReadString(entry, "name"), Type = ReadString(entry, "type"), Entry = entry };
            if (entry.Values.ContainsKey("id")) field.Id = ReadInteger(entry, "id", "field-overflow");
            if (entry.Values.ContainsKey("maxBytes")) field.Bound = ReadUnsignedInteger(entry, "maxBytes", "invalid-production");
            if (entry.Values.ContainsKey("maxCodeUnits")) field.Bound = ReadUnsignedInteger(entry, "maxCodeUnits", "invalid-production");
            return field;
        }

        private static void ValidateIdentifiers(Operation operation, ProtocolCatalogContractV2 contract)
        {
            List<string> identifiers = new List<string>();
            JObject entry = operation.Entry;
            if (operation.Kind != "primitive" && operation.Kind != "extend") identifiers.Add(ReadString(entry, "name"));
            foreach (string property in new string[] { "parent", "payloadRoot", "elementType", "discriminator" })
            {
                if (entry.Values.ContainsKey(property))
                {
                    string value = ReadString(entry, property);
                    if (property == "discriminator" || !ProtocolCatalogSyntax.IsPrimitive(value)) identifiers.Add(value);
                }
            }
            if (entry.Values.ContainsKey("members"))
            {
                foreach (JNode member in ReadArray(entry, "members").Values) identifiers.Add(ReadString((JObject)member, "name"));
            }
            AddFieldIdentifiers(operation.Fields, identifiers);
            foreach (Branch branch in operation.Branches)
            {
                identifiers.Add(branch.Name);
                AddFieldIdentifiers(branch.Fields, identifiers);
            }
            foreach (string identifier in identifiers)
            {
                Require(ProtocolCatalogSyntax.IsSchemaIdentifier(identifier), "non-ascii-symbol");
            }
            foreach (string identifier in identifiers)
            {
                Require(contract.MatchesName(identifier), "catalog-name");
            }
        }

        private static void AddFieldIdentifiers(List<Field> fields, List<string> identifiers)
        {
            foreach (Field field in fields)
            {
                identifiers.Add(field.Name);
                if (!ProtocolCatalogSyntax.IsPrimitive(field.Type)) identifiers.Add(field.Type);
            }
        }

        private static void ValidateDomains(Operation operation, EvaluationState state)
        {
            JObject entry = operation.Entry;
            if (operation.Kind == "message" || operation.Kind == "overlay-message")
            {
                string channel = ReadString(entry, "channel");
                Require(state.Directions.ContainsKey(channel), "invalid-channel");
                Require(Array.IndexOf(state.Directions[channel], ReadString(entry, "direction")) >= 0, "invalid-direction");
                string profile = ReadString(entry, "profile");
                Require(profile == "Any" || profile == InteractiveProfile || profile == NonInteractiveProfile, "invalid-profile");
                string tail = ReadString(entry, "mandatoryTailClass");
                Require(tail == "Ordinary" || tail == "Mandatory", "invalid-tail-class");
                Require(ProtocolCatalogSyntax.IsProtocolIdentifier(ReadString(entry, "stateAssoc")), "invalid-state-association");
            }
            foreach (Field field in operation.Fields)
            {
                if (field.Entry.Values.ContainsKey("profile"))
                {
                    field.Profile = OptionalString(field.Entry, "profile");
                    Require(field.Profile == InteractiveProfile || field.Profile == NonInteractiveProfile, "invalid-field-condition");
                }
                if (field.Entry.Values.ContainsKey("status"))
                {
                    string status = OptionalString(field.Entry, "status");
                    Require(status == "Required" || status == "Forbidden", "invalid-field-condition");
                    field.Forbidden = status == "Forbidden";
                }
                Require(!field.Forbidden || field.Profile != "Any", "invalid-field-condition");
            }
            if (operation.Kind == "type" || operation.Kind == "overlay-type")
            {
                string production = ReadString(entry, "production");
                Require(production == "Named" || production == "SemanticString" || production == "List" || production == "Set"
                    || (production == "EnumU16" && operation.Kind == "overlay-type"), "invalid-production");
                if (production == "SemanticString")
                {
                    string encoding = ReadString(entry, "encoding");
                    string grammar = ReadString(entry, "grammar");
                    Require(encoding == "Utf8" || encoding == "AsciiEnvironmentName", "unknown-primitive");
                    Require(grammar == "None" || grammar == "PspktPathCanonicalizationV1" || grammar == "InverseCommandLineToArgvW", "unknown-primitive");
                    Require(encoding != "AsciiEnvironmentName" || grammar == "None", "unknown-primitive");
                }
            }
        }

        private static void ValidateTypeNames(Operation operation)
        {
            if (operation.Kind == "type" || operation.Kind == "overlay-type" || operation.Kind == "enum")
            {
                Require(!ProtocolCatalogSyntax.IsPrimitive(ReadString(operation.Entry, "name")), "duplicate-identifier");
            }
            if (operation.Kind == "union")
            {
                Require(!ProtocolCatalogSyntax.IsPrimitive(ReadString(operation.Entry, "discriminator")), "duplicate-identifier");
                foreach (Branch branch in operation.Branches)
                {
                    Require(!ProtocolCatalogSyntax.IsPrimitive(branch.Name), "duplicate-identifier");
                }
            }
        }

        private static void ValidateProduction(Operation operation)
        {
            JObject entry = operation.Entry;
            if (operation.Kind != "type" && operation.Kind != "overlay-type") return;
            string production = ReadString(entry, "production");
            if (production == "SemanticString")
            {
                ulong minimum = ReadUnsignedInteger(entry, "minBytes", "invalid-production");
                ulong maximum = ReadUnsignedInteger(entry, "maxBytes", "invalid-production");
                ulong codeUnits = ReadUnsignedInteger(entry, "maxUtf16CodeUnits", "invalid-production");
                Require(minimum <= uint.MaxValue && maximum <= uint.MaxValue && codeUnits <= uint.MaxValue, "integer-overflow");
                Require(minimum >= 1 && minimum <= maximum, "invalid-cardinality");
                Require(checked(4UL + maximum) <= uint.MaxValue, "bound-overflow");
                if (ReadString(entry, "encoding") == "AsciiEnvironmentName")
                {
                    Require(minimum == 1 && maximum == 32767 && codeUnits == maximum, "invalid-cardinality");
                }
                else
                {
                    Require(codeUnits >= 1 && codeUnits <= maximum && minimum <= checked(3UL * codeUnits), "invalid-cardinality");
                }
            }
            if (production == "List" || production == "Set")
            {
                int minimum = ReadInteger(entry, "minCount", "invalid-production");
                int maximum = ReadInteger(entry, "maxCount", "invalid-production");
                Require(maximum >= 1 && minimum <= maximum && maximum <= 65535, "invalid-cardinality");
            }
        }

        private static void Expand(EvaluationState state)
        {
            foreach (Operation operation in state.Operations)
            {
                JObject entry = operation.Entry;
                string name = OptionalString(entry, "name");
                if (operation.Kind == "primitive")
                {
                    Require(ProtocolCatalogSyntax.IsPrimitive(name), "unknown-primitive");
                    Require(!ProtocolCatalogSyntax.IsForbiddenPrimitive(name), "primitive-forbidden");
                }
                else if (operation.Kind == "type" || operation.Kind == "enum" || operation.Kind == "overlay-type")
                {
                    string production = operation.Kind == "enum" ? "EnumU16" : ReadString(entry, "production");
                    int literalId = 0;
                    if (operation.Kind == "overlay-type")
                    {
                        literalId = ReadInteger(entry, "id", "overlay-id-out-of-range");
                        Require(state.OverlayTypeRange.Contains(literalId), "overlay-id-out-of-range");
                        Require(!state.ReservedTypeIds.Contains(literalId), "reserve-illegal-encoded");
                        Require(!state.LiteralTypeIds.Contains(literalId), "duplicate-type-id");
                    }
                    if (production == "EnumU16") ReadMembers(operation);
                    TypeDeclaration declaration = RegisterType(state, operation, name, production, operation.Kind != "overlay-type");
                    declaration.Id = literalId;
                    if (operation.Kind == "overlay-type") state.LiteralTypeIds.Add(literalId);
                    operation.Declaration = declaration;
                }
                else if (operation.Kind == "field" || operation.Kind == "field-set" || operation.Kind == "extend")
                {
                    ExpandFields(state, operation);
                }
                else if (operation.Kind == "message" || operation.Kind == "overlay-message")
                {
                    ExpandMessage(state, operation);
                }
                else if (operation.Kind == "union")
                {
                    ExpandUnion(state, operation);
                }
                else if (operation.Kind == "delete")
                {
                    DeleteType(state, name);
                }
                else if (operation.Kind == "reserve-illegal-type")
                {
                    Require(entry.Values.ContainsKey("id"), "reserve-missing-literal");
                    int literalId = ReadInteger(entry, "id", "reserve-id-out-of-range");
                    Require(state.OverlayTypeRange.Contains(literalId), "reserve-id-out-of-range");
                    Require(!state.Types.ContainsKey(name) && !state.ReservedNames.Contains(name), "duplicate-identifier");
                    Require(!state.LiteralTypeIds.Contains(literalId) && !state.ReservedTypeIds.Contains(literalId), "duplicate-type-id");
                    state.ReservedNames.Add(name);
                    state.ReservedTypeIds.Add(literalId);
                }
            }
        }

        private static TypeDeclaration RegisterType(EvaluationState state, Operation operation, string name, string production, bool generated)
        {
            Require(!state.Types.ContainsKey(name) && !state.ReservedNames.Contains(name), "duplicate-identifier");
            TypeDeclaration declaration = new TypeDeclaration { Name = name, Production = production, Operation = operation, Generated = generated };
            state.Types.Add(name, declaration);
            state.TypeOrder.Add(declaration);
            return declaration;
        }

        private static void ReadMembers(Operation operation)
        {
            JArray members = ReadArray(operation.Entry, "members");
            Require(members.Values.Count > 0, "missing-property");
            HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
            HashSet<int> values = new HashSet<int>();
            int nextValue = 0;
            foreach (JNode memberNode in members.Values)
            {
                JObject member = (JObject)memberNode;
                string name = ReadString(member, "name");
                int value = member.Values.ContainsKey("value") ? ReadInteger(member, "value", "enum-value-overflow") : nextValue;
                Require(names.Add(name), "enum-duplicate-name");
                Require(value <= 65535, "enum-value-overflow");
                Require(values.Add(value), "enum-duplicate-value");
                operation.Members.Add(new CatalogMember { Name = name, Value = value, Index = operation.Members.Count });
                nextValue = checked(value + 1);
            }
        }

        private static void ExpandFields(EvaluationState state, Operation operation)
        {
            string parentName = ReadString(operation.Entry, "parent");
            TypeDeclaration parent;
            bool found = state.Types.TryGetValue(parentName, out parent);
            string parentReason = operation.Kind == "extend" ? "extend-invalid-parent" : "field-undefined-parent";
            if ((operation.Kind == "field" || operation.Kind == "field-set") && found && parent.Deleted) Reject("delete-then-use");
            Require(found && !parent.Deleted && parent.Production == "Named", parentReason);
            operation.Declaration = parent;
            bool literal = operation.Kind == "extend" || operation.Entry.Values.ContainsKey("id");
            if (literal && parent.Generated)
            {
                Require(state.ExtensionParents.Contains(parentName), "extension-parent-forbidden");
            }
            Require(operation.Fields.Count > 0, "missing-property");
            Require(checked(parent.Fields.Count + operation.Fields.Count) <= MaximumFields, "invalid-cardinality");
            if (operation.Kind == "extend")
            {
                foreach (Field field in operation.Fields)
                {
                    Require(field.Entry.Values.ContainsKey("id"), "extend-missing-literal");
                }
                foreach (Field field in operation.Fields)
                {
                    ValidateLiteralFieldId(field.Id, parent, state.Contract.GeneratedFieldIdMax);
                }
            }
            else
            {
                int proposedId;
                if (literal)
                {
                    proposedId = ReadInteger(operation.Entry, "id", "field-overflow");
                    ValidateLiteralFieldId(proposedId, parent, state.Contract.GeneratedFieldIdMax);
                }
                else
                {
                    proposedId = parent.FieldNext;
                    Require(proposedId <= state.Contract.GeneratedFieldIdMax, "field-overflow");
                }
                foreach (Field field in operation.Fields) field.Id = proposedId;
            }
            ValidateRawBounds(operation.Fields);
            if (operation.Kind == "field-set")
            {
                string groupName = ReadString(operation.Entry, "name");
                Require(!parent.FieldSetNames.Contains(groupName), "duplicate-field-set");
                if (literal) Require(!parent.FieldSetLiteralIds.Contains(operation.Fields[0].Id), "duplicate-field-set");
                parent.FieldSetNames.Add(groupName);
                if (literal) parent.FieldSetLiteralIds.Add(operation.Fields[0].Id);
            }
            ClaimShapes(parent, operation.Fields, operation);
            if (operation.Kind == "field-set") ResolveFieldSet(operation.Fields);
            ValidateEffectivePrimitives(operation.Fields);
            if (operation.Kind == "field-set")
            {
                if (parent.Generated)
                {
                    Require(parent.MapNames.Add(ReadString(operation.Entry, "name")), "duplicate-identifier");
                }
            }
            else
            {
                foreach (Field field in operation.Fields)
                {
                    Require(parent.MapNames.Add(field.Name), operation.Kind == "extend" ? "extend-dup-name" : "duplicate-identifier");
                }
            }
            RegisterEffectiveFields(parent, operation.Fields, operation.Kind == "extend");
            parent.Fields.AddRange(operation.Fields);
            if (!literal) parent.FieldNext = checked(parent.FieldNext + 1);
        }

        private static void ValidateLiteralFieldId(int fieldId, TypeDeclaration parent, int generatedMaximum)
        {
            Require(fieldId >= 1 && fieldId <= 65535 && (!parent.Generated || fieldId > generatedMaximum), "field-overflow");
        }

        private static void ValidateRawBounds(List<Field> fields)
        {
            foreach (Field field in fields)
            {
                Require(field.Bound <= uint.MaxValue, "integer-overflow");
                if (field.Type == "BoundedBytes") Require(checked(4UL + field.Bound) <= uint.MaxValue, "bound-overflow");
                if (field.Type == "OpaqueUtf16") Require(checked(4UL + checked(2UL * field.Bound)) <= uint.MaxValue, "bound-overflow");
            }
        }

        private static void ClaimShapes(TypeDeclaration parent, List<Field> fields, Operation owner)
        {
            foreach (Field field in fields)
            {
                if (field.Forbidden) continue;
                string shape = ShapeIdentity(field);
                Operation existingOwner;
                if (parent.ShapeOwners.TryGetValue(shape, out existingOwner))
                {
                    if (object.ReferenceEquals(existingOwner, owner)) continue;
                    bool conditionalConflict = OperationHasConditionalShape(owner, shape)
                        || OperationHasConditionalShape(existingOwner, shape);
                    Require(!conditionalConflict, "invalid-field-condition");
                }
                else
                {
                    parent.ShapeOwners.Add(shape, owner);
                }
            }
        }

        private static bool IsConditionalField(Field field)
        {
            return field.Forbidden || field.Profile != "Any";
        }

        private static bool OperationHasConditionalShape(Operation operation, string shape)
        {
            if (!operation.ConditionalShapesInitialized)
            {
                HashSet<string> conditionalShapes = null;
                foreach (Field field in operation.Fields)
                {
                    if (!IsConditionalField(field)) continue;
                    if (conditionalShapes == null) conditionalShapes = new HashSet<string>(StringComparer.Ordinal);
                    conditionalShapes.Add(ShapeIdentity(field));
                }
                operation.ConditionalShapes = conditionalShapes;
                operation.ConditionalShapesInitialized = true;
            }
            return operation.ConditionalShapes != null && operation.ConditionalShapes.Contains(shape);
        }

        private static string ShapeIdentity(Field field)
        {
            return field.Id.ToString(CultureInfo.InvariantCulture) + "\u001F" + field.Name + "\u001F" + field.Type
                + "\u001F" + BoundKind(field).ToString(CultureInfo.InvariantCulture) + "\u001F" + field.Bound.ToString(CultureInfo.InvariantCulture);
        }

        private static int BoundKind(Field field)
        {
            return field.Type == "BoundedBytes" ? 1 : field.Type == "OpaqueUtf16" ? 2 : 0;
        }

        private static void ResolveFieldSet(List<Field> fields)
        {
            Dictionary<string, List<Field>> requiredByShape = new Dictionary<string, List<Field>>(StringComparer.Ordinal);
            HashSet<string> declarations = new HashSet<string>(StringComparer.Ordinal);
            foreach (Field field in fields)
            {
                string shape = ShapeIdentity(field);
                Require(declarations.Add(shape + "\u001F" + field.Profile + "\u001F" + (field.Forbidden ? "Forbidden" : "Required")), "invalid-field-condition");
                field.Effective[0] = !field.Forbidden && (field.Profile == "Any" || field.Profile == InteractiveProfile);
                field.Effective[1] = !field.Forbidden && (field.Profile == "Any" || field.Profile == NonInteractiveProfile);
                if (field.Forbidden) continue;
                List<Field> requiredRows;
                if (!requiredByShape.TryGetValue(shape, out requiredRows))
                {
                    requiredRows = new List<Field>();
                    requiredByShape.Add(shape, requiredRows);
                }
                requiredRows.Add(field);
            }
            Require(requiredByShape.Count > 0, "invalid-field-condition");
            foreach (Field forbidden in fields)
            {
                if (!forbidden.Forbidden) continue;
                List<Field> matches;
                Require(requiredByShape.TryGetValue(ShapeIdentity(forbidden), out matches), "invalid-field-condition");
                Field applicable = null;
                foreach (Field required in matches)
                {
                    if (required.Profile != "Any" && required.Profile != forbidden.Profile) continue;
                    Require(applicable == null, "invalid-field-condition");
                    applicable = required;
                }
                if (applicable != null) applicable.Effective[forbidden.Profile == InteractiveProfile ? 0 : 1] = false;
            }
        }

        private static void ValidateEffectivePrimitives(List<Field> fields)
        {
            foreach (Field field in fields)
            {
                Require((!field.Effective[0] && !field.Effective[1]) || !ProtocolCatalogSyntax.IsForbiddenPrimitive(field.Type), "primitive-forbidden");
            }
        }

        private static void RegisterEffectiveFields(TypeDeclaration parent, List<Field> fields, bool extension)
        {
            for (int profileIndex = 0; profileIndex < Profiles.Length; profileIndex++)
            {
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                foreach (Field field in fields)
                {
                    if (!field.Effective[profileIndex]) continue;
                    Require(!parent.EffectiveNames[profileIndex].Contains(field.Name) && names.Add(field.Name),
                        extension ? "extend-dup-name" : "duplicate-identifier");
                }
                HashSet<int> ids = new HashSet<int>();
                foreach (Field field in fields)
                {
                    if (!field.Effective[profileIndex]) continue;
                    Require(!parent.EffectiveIds[profileIndex].Contains(field.Id) && ids.Add(field.Id),
                        extension ? "extend-dup-id" : "duplicate-field-id");
                }
                parent.EffectiveNames[profileIndex].UnionWith(names);
                parent.EffectiveIds[profileIndex].UnionWith(ids);
            }
        }

        private static void ExpandMessage(EvaluationState state, Operation operation)
        {
            JObject entry = operation.Entry;
            string channel = ReadString(entry, "channel");
            string name = ReadString(entry, "name");
            string identity = channel + "\u001F" + name;
            string rowIdentity = ReadString(entry, "direction") + "\u001F" + ReadString(entry, "profile");
            int literalId = operation.Kind == "overlay-message" ? ReadInteger(entry, "id", "overlay-id-out-of-range") : 0;
            if (operation.Kind == "overlay-message") Require(InRanges(state.KindRanges[channel], literalId), "overlay-id-out-of-range");
            MessageKind message;
            if (state.Messages.TryGetValue(identity, out message))
            {
                Require(!message.Rows.Contains(rowIdentity), "duplicate-kind");
                Require(message.PayloadRoot == ReadString(entry, "payloadRoot") && message.TailClass == ReadString(entry, "mandatoryTailClass")
                    && message.StateAssociation == ReadString(entry, "stateAssoc")
                    && (operation.Kind != "overlay-message" || literalId == message.Id), "message-metadata-conflict");
                message.Rows.Add(rowIdentity);
            }
            else
            {
                int kindId = operation.Kind == "overlay-message" ? literalId : state.KindNext[channel];
                Require(!state.KindNamesById[channel].ContainsKey(kindId), "enum-duplicate-value");
                message = new MessageKind
                {
                    Id = kindId,
                    Name = name,
                    Channel = channel,
                    PayloadRoot = ReadString(entry, "payloadRoot"),
                    TailClass = ReadString(entry, "mandatoryTailClass"),
                    StateAssociation = ReadString(entry, "stateAssoc"),
                    FirstOperation = operation
                };
                message.Rows.Add(rowIdentity);
                state.Messages.Add(identity, message);
                state.KindNamesById[channel].Add(kindId, name);
                if (operation.Kind == "message") state.KindNext[channel] = checked(kindId + 1);
            }
            operation.Message = message;
        }

        private static void ExpandUnion(EvaluationState state, Operation operation)
        {
            Require(operation.Branches.Count > 0, "union-empty");
            foreach (Branch branch in operation.Branches)
            {
                Require(branch.Fields.Count > 0, "missing-property");
                Require(branch.Fields.Count <= MaximumFields, "invalid-cardinality");
            }
            foreach (Branch branch in operation.Branches)
            {
                Require(branch.Fields.Count <= state.Contract.GeneratedFieldIdMax, "field-overflow");
            }
            foreach (Branch branch in operation.Branches)
            {
                ValidateRawBounds(branch.Fields);
            }
            string discriminatorName = ReadString(operation.Entry, "discriminator");
            operation.Declaration = RegisterType(state, operation, discriminatorName, "EnumU16", true);
            operation.Declaration.Union = operation;
            operation.Declaration.IsDiscriminator = true;
            HashSet<string> branchNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (Branch branch in operation.Branches)
            {
                Require(branchNames.Add(branch.Name), "union-duplicate-branch");
                TypeDeclaration declaration = RegisterType(state, operation, branch.Name, "Named", true);
                declaration.Union = operation;
                branch.Declaration = declaration;
                for (int index = 0; index < branch.Fields.Count; index++) branch.Fields[index].Id = index + 1;
                ClaimShapes(declaration, branch.Fields, operation);
                ValidateEffectivePrimitives(branch.Fields);
                RegisterEffectiveFields(declaration, branch.Fields, false);
                foreach (Field field in branch.Fields) Require(declaration.MapNames.Add(field.Name), "duplicate-identifier");
                declaration.Fields.AddRange(branch.Fields);
                declaration.FieldNext = checked(branch.Fields.Count + 1);
            }
        }

        private static void DeleteType(EvaluationState state, string name)
        {
            TypeDeclaration target;
            Require(state.Types.TryGetValue(name, out target), "delete-unknown");
            Require(!target.Deleted, "delete-double");
            target.Deleted = true;
            if (target.Union == null) return;
            if (target.IsDiscriminator)
            {
                foreach (Branch branch in target.Union.Branches) branch.Declaration.Deleted = true;
            }
            else
            {
                bool hasLiveBranch = false;
                foreach (Branch branch in target.Union.Branches)
                {
                    if (!branch.Declaration.Deleted) hasLiveBranch = true;
                }
                if (!hasLiveBranch) target.Union.Declaration.Deleted = true;
            }
        }

        private static void ValidateReferences(EvaluationState state)
        {
            foreach (TypeDeclaration declaration in state.TypeOrder)
            {
                if (declaration.Deleted || declaration.Production != "Named") continue;
                Require(declaration.EffectiveNames[0].Count > 0 && declaration.EffectiveNames[1].Count > 0, "missing-property");
            }
            foreach (Operation operation in state.Operations)
            {
                foreach (Field field in operation.Fields) ValidateReference(state, field.Type, false, false);
                foreach (Branch branch in operation.Branches)
                {
                    foreach (Field field in branch.Fields) ValidateReference(state, field.Type, false, false);
                }
                if (operation.Kind == "message" || operation.Kind == "overlay-message")
                {
                    ValidateReference(state, ReadString(operation.Entry, "payloadRoot"), true, true);
                }
                if (operation.Kind == "type" || operation.Kind == "overlay-type")
                {
                    string production = ReadString(operation.Entry, "production");
                    if (production == "List" || production == "Set")
                    {
                        ValidateReference(state, ReadString(operation.Entry, "elementType"), false, true);
                    }
                }
            }
            HashSet<string> enumNames = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> channels = new HashSet<string>(StringComparer.Ordinal);
            foreach (Operation operation in state.Operations)
            {
                if (operation.Message == null || !channels.Add(operation.Message.Channel)) continue;
                string enumName = state.MessageEnumNames[operation.Message.Channel];
                Require(!state.Types.ContainsKey(enumName) && !state.ReservedNames.Contains(enumName) && enumNames.Add(enumName), "duplicate-identifier");
            }
            ValidateAcyclic(state);
        }

        private static void ValidateReference(EvaluationState state, string reference, bool payloadRoot, bool rejectForbiddenPrimitive)
        {
            Require(!state.ReservedNames.Contains(reference), "reserve-illegal-encoded");
            TypeDeclaration declaration;
            if (state.Types.TryGetValue(reference, out declaration))
            {
                Require(!declaration.Deleted, "delete-then-use");
                return;
            }
            if (rejectForbiddenPrimitive)
            {
                Require(!ProtocolCatalogSyntax.IsForbiddenPrimitive(reference), "primitive-forbidden");
            }
            Require(ProtocolCatalogSyntax.IsPrimitive(reference), payloadRoot ? "undefined-payload-root" : "undefined-reference");
        }

        private static void ValidateAcyclic(EvaluationState state)
        {
            Dictionary<string, List<string>> references = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach (TypeDeclaration declaration in state.TypeOrder)
            {
                if (declaration.Deleted) continue;
                List<string> targets = new List<string>();
                foreach (Field field in declaration.Fields) targets.Add(field.Type);
                if (declaration.Production == "List" || declaration.Production == "Set")
                {
                    targets.Add(ReadString(declaration.Operation.Entry, "elementType"));
                }
                references.Add(declaration.Name, targets);
            }
            Dictionary<string, int> states = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (TypeDeclaration declaration in state.TypeOrder)
            {
                if (declaration.Deleted || states.ContainsKey(declaration.Name)) continue;
                Stack<string> names = new Stack<string>();
                Stack<int> indexes = new Stack<int>();
                names.Push(declaration.Name);
                indexes.Push(0);
                states.Add(declaration.Name, 1);
                while (names.Count > 0)
                {
                    string current = names.Peek();
                    int index = indexes.Pop();
                    if (index == references[current].Count)
                    {
                        names.Pop();
                        states[current] = 2;
                        continue;
                    }
                    indexes.Push(index + 1);
                    string target = references[current][index];
                    if (!references.ContainsKey(target)) continue;
                    int targetState;
                    if (states.TryGetValue(target, out targetState))
                    {
                        Require(targetState != 1, "type-cycle");
                        continue;
                    }
                    states.Add(target, 1);
                    names.Push(target);
                    indexes.Push(0);
                }
            }
        }

        private static ProtocolCatalogResultV2 AssignAndEmit(EvaluationState state)
        {
            List<object> outputTypes = new List<object>();
            List<object> map = new List<object>();
            Dictionary<string, Dictionary<string, object>> messageEnums = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            int typeNext = 1;
            foreach (Operation operation in state.Operations)
            {
                if (operation.Kind == "type" || operation.Kind == "enum" || operation.Kind == "overlay-type")
                {
                    TypeDeclaration declaration = operation.Declaration;
                    if (declaration.Deleted) continue;
                    if (declaration.Generated)
                    {
                        declaration.Id = AssignTypeId(state, ref typeNext);
                        AddMapRow(state, map, operation, "type", declaration.Name, declaration.Id);
                    }
                    Dictionary<string, object> output = CreateType(declaration);
                    outputTypes.Add(output);
                    if (declaration.Production == "EnumU16" && declaration.Generated)
                    {
                        foreach (CatalogMember member in operation.Members)
                        {
                            Dictionary<string, object> row = AddMapRow(state, map, operation, "enum-member", declaration.Name + "." + member.Name, member.Value);
                            row.Add("memberIndex", member.Index);
                        }
                    }
                }
                else if (operation.Kind == "field" || operation.Kind == "field-set" || operation.Kind == "extend")
                {
                    if (operation.Declaration.Deleted) continue;
                    if (operation.Kind == "field-set")
                    {
                        if (operation.Declaration.Generated)
                        {
                            AddMapRow(state, map, operation, "field", operation.Declaration.Name + "." + ReadString(operation.Entry, "name"), operation.Fields[0].Id);
                        }
                    }
                    else
                    {
                        foreach (Field field in operation.Fields)
                        {
                            AddMapRow(state, map, operation, "field", operation.Declaration.Name + "." + field.Name, field.Id);
                        }
                    }
                }
                else if (operation.Kind == "message" || operation.Kind == "overlay-message")
                {
                    MessageKind message = operation.Message;
                    Dictionary<string, object> enumDeclaration;
                    if (!messageEnums.TryGetValue(message.Channel, out enumDeclaration))
                    {
                        int typeId = AssignTypeId(state, ref typeNext);
                        string enumName = state.MessageEnumNames[message.Channel];
                        enumDeclaration = NewObject();
                        enumDeclaration.Add("production", "EnumU16");
                        enumDeclaration.Add("name", enumName);
                        enumDeclaration.Add("typeId", typeId);
                        enumDeclaration.Add("members", new List<object>());
                        messageEnums.Add(message.Channel, enumDeclaration);
                        outputTypes.Add(enumDeclaration);
                        AddMapRow(state, map, operation, "type", enumName, typeId);
                    }
                    if (object.ReferenceEquals(operation, message.FirstOperation))
                    {
                        if (operation.Kind == "message")
                        {
                            Require(message.Id <= 65535, "generated-id-overflow");
                            Require(!InRanges(state.KindRanges[message.Channel], message.Id), "reserved-kind-range");
                        }
                        Dictionary<string, object> member = NewObject();
                        member.Add("name", message.Name);
                        member.Add("value", message.Id);
                        ((List<object>)enumDeclaration["members"]).Add(member);
                    }
                    Dictionary<string, object> row = AddMapRow(state, map, operation, "kind", message.Name, message.Id);
                    row.Add("channel", message.Channel);
                    row.Add("direction", ReadString(operation.Entry, "direction"));
                    row.Add("profile", ReadString(operation.Entry, "profile"));
                    row.Add("mandatoryTailClass", message.TailClass);
                    row.Add("stateAssoc", message.StateAssociation);
                }
                else if (operation.Kind == "union")
                {
                    if (operation.Declaration.Deleted) continue;
                    operation.Declaration.Id = AssignTypeId(state, ref typeNext);
                    Dictionary<string, object> discriminator = NewObject();
                    discriminator.Add("production", "EnumU16");
                    discriminator.Add("name", operation.Declaration.Name);
                    discriminator.Add("typeId", operation.Declaration.Id);
                    List<object> members = new List<object>();
                    discriminator.Add("members", members);
                    outputTypes.Add(discriminator);
                    AddMapRow(state, map, operation, "type", operation.Declaration.Name, operation.Declaration.Id);
                    int branchIndex = 0;
                    foreach (Branch branch in operation.Branches)
                    {
                        if (branch.Declaration.Deleted) continue;
                        Dictionary<string, object> member = NewObject();
                        member.Add("name", branch.Name);
                        member.Add("value", branchIndex);
                        members.Add(member);
                        Dictionary<string, object> memberRow = AddMapRow(state, map, operation, "enum-member",
                            operation.Declaration.Name + "." + branch.Name, branchIndex);
                        memberRow.Add("memberIndex", branchIndex);
                        branch.Declaration.Id = AssignTypeId(state, ref typeNext);
                        outputTypes.Add(CreateType(branch.Declaration));
                        foreach (Field field in branch.Fields)
                        {
                            AddMapRow(state, map, operation, "field", branch.Name + "." + field.Name, field.Id);
                        }
                        Dictionary<string, object> branchRow = AddMapRow(state, map, operation, "union-branch", branch.Name, branch.Declaration.Id);
                        branchRow.Add("branchIndex", branchIndex);
                        branchIndex = checked(branchIndex + 1);
                    }
                }
            }
            Require(outputTypes.Count > 0, "missing-property");
            Require(outputTypes.Count <= MaximumSchemaTypes && map.Count <= MaximumMapRows, "invalid-cardinality");
            Dictionary<string, object> schema = NewObject();
            schema.Add("schemaVersion", 1);
            schema.Add("schemaId", state.Contract.EmitSchemaId);
            schema.Add("types", outputTypes);
            byte[] schemaBytes = CanonicalJson.Bytes(schema);
            byte[] mapBytes = CanonicalJson.Bytes(map);
            Require(schemaBytes.Length <= MaximumJsonBytes && mapBytes.Length <= MaximumJsonBytes, "file-limit");
            RequireJson(schemaBytes);
            RequireJson(mapBytes);
            return new ProtocolCatalogResultV2(true, "ok", schemaBytes, mapBytes);
        }

        private static int AssignTypeId(EvaluationState state, ref int typeNext)
        {
            Require(typeNext >= 1 && typeNext <= 65535, "generated-id-overflow");
            Require(!state.OverlayTypeRange.Contains(typeNext), "reserved-type-range");
            int assigned = typeNext;
            typeNext = checked(typeNext + 1);
            return assigned;
        }

        private static Dictionary<string, object> CreateType(TypeDeclaration declaration)
        {
            Dictionary<string, object> output = NewObject();
            output.Add("name", declaration.Name);
            output.Add("production", declaration.Production);
            output.Add("typeId", declaration.Id);
            if (declaration.Production == "Named")
            {
                List<Field> ordered = new List<Field>(declaration.Fields);
                ordered.Sort(CompareFields);
                List<object> fields = new List<object>();
                foreach (Field field in ordered)
                {
                    Dictionary<string, object> row = NewObject();
                    row.Add("name", field.Name);
                    row.Add("fieldId", field.Id);
                    row.Add("type", field.Type);
                    if (field.Type == "BoundedBytes") row.Add("maxBytes", field.Bound);
                    if (field.Type == "OpaqueUtf16") row.Add("maxCodeUnits", field.Bound);
                    if (field.Profile != "Any") row.Add("profile", field.Profile);
                    if (field.Forbidden) row.Add("status", "Forbidden");
                    fields.Add(row);
                }
                output.Add("fields", fields);
            }
            else if (declaration.Production == "EnumU16")
            {
                List<object> members = new List<object>();
                foreach (CatalogMember member in declaration.Operation.Members)
                {
                    Dictionary<string, object> row = NewObject();
                    row.Add("name", member.Name);
                    row.Add("value", member.Value);
                    members.Add(row);
                }
                output.Add("members", members);
            }
            else if (declaration.Production == "SemanticString")
            {
                JObject entry = declaration.Operation.Entry;
                output.Add("encoding", ReadString(entry, "encoding"));
                output.Add("grammar", ReadString(entry, "grammar"));
                output.Add("minBytes", ReadUnsignedInteger(entry, "minBytes", "invalid-production"));
                output.Add("maxBytes", ReadUnsignedInteger(entry, "maxBytes", "invalid-production"));
                output.Add("maxUtf16CodeUnits", ReadUnsignedInteger(entry, "maxUtf16CodeUnits", "invalid-production"));
            }
            else
            {
                JObject entry = declaration.Operation.Entry;
                output.Add("elementType", ReadString(entry, "elementType"));
                output.Add("minCount", ReadInteger(entry, "minCount", "invalid-production"));
                output.Add("maxCount", ReadInteger(entry, "maxCount", "invalid-production"));
            }
            return output;
        }

        private static int CompareFields(Field left, Field right)
        {
            int comparison = left.Id.CompareTo(right.Id);
            if (comparison != 0) return comparison;
            comparison = ProfileOrder(left.Profile).CompareTo(ProfileOrder(right.Profile));
            if (comparison != 0) return comparison;
            comparison = left.Forbidden.CompareTo(right.Forbidden);
            if (comparison != 0) return comparison;
            comparison = string.CompareOrdinal(left.Name, right.Name);
            if (comparison != 0) return comparison;
            comparison = string.CompareOrdinal(left.Type, right.Type);
            if (comparison != 0) return comparison;
            comparison = BoundKind(left).CompareTo(BoundKind(right));
            return comparison != 0 ? comparison : left.Bound.CompareTo(right.Bound);
        }

        private static int ProfileOrder(string profile)
        {
            return profile == "Any" ? 0 : profile == InteractiveProfile ? 1 : 2;
        }

        private static Dictionary<string, object> AddMapRow(EvaluationState state, List<object> map, Operation operation, string category, string name, int generatedId)
        {
            Dictionary<string, object> row = NewObject();
            row.Add("schemaId", state.Contract.MapSchemaId);
            row.Add("category", category);
            row.Add("catalog", operation.Catalog);
            row.Add("catalogOrdinal", operation.Ordinal);
            row.Add("name", name);
            row.Add("generatedId", generatedId);
            map.Add(row);
            return row;
        }

        private static Dictionary<string, object> NewObject()
        {
            return new Dictionary<string, object>(StringComparer.Ordinal);
        }

        private static bool ValidateMap(byte[] mapBytes, ProtocolCatalogContractV2 contract)
        {
            SchemaCheckResult jsonResult = SchemaBootstrap.Evaluate("json", mapBytes, null);
            if (!jsonResult.Accepted) return false;
            JArray rows = new JsonParser(mapBytes).Parse() as JArray;
            if (rows == null || rows.Values.Count > MaximumMapRows) return false;
            IDictionary<string, string[]> directions = contract.PermittedDirectionsByChannel;
            try
            {
                foreach (JNode rowNode in rows.Values)
                {
                    JObject row = RequireObject(rowNode);
                    string category = ReadString(row, "category");
                    List<string> required = new List<string>(new string[] { "schemaId", "category", "catalog", "catalogOrdinal", "name", "generatedId" });
                    if (category == "kind") required.AddRange(new string[] { "channel", "direction", "profile", "mandatoryTailClass", "stateAssoc" });
                    else if (category == "enum-member") required.Add("memberIndex");
                    else if (category == "union-branch") required.Add("branchIndex");
                    else Require(category == "type" || category == "field", "map-tamper");
                    CheckProperties(row, required.ToArray(), new string[0]);
                    Require(ReadString(row, "schemaId") == contract.MapSchemaId, "map-tamper");
                    string catalog = ReadString(row, "catalog");
                    Require(catalog == "base" || catalog == "overlay", "map-tamper");
                    int ordinal = ReadInteger(row, "catalogOrdinal", "map-tamper");
                    Require(ordinal >= 1 && ordinal <= 8192, "map-tamper");
                    int generatedId = ReadInteger(row, "generatedId", "map-tamper");
                    Require(generatedId <= 65535 && (generatedId >= 1 || category == "kind" || category == "enum-member"), "map-tamper");
                    string[] nameParts = ReadString(row, "name").Split('.');
                    Require(nameParts.Length == (category == "field" || category == "enum-member" ? 2 : 1), "map-tamper");
                    foreach (string name in nameParts)
                    {
                        Require(ProtocolCatalogSyntax.IsSchemaIdentifier(name) && contract.MatchesName(name), "map-tamper");
                    }
                    if (category == "enum-member" || category == "union-branch")
                    {
                        Require(catalog == "base", "map-tamper");
                        int index = ReadInteger(row, category == "enum-member" ? "memberIndex" : "branchIndex", "map-tamper");
                        Require(index < 8192, "map-tamper");
                    }
                    if (category == "kind")
                    {
                        string channel = ReadString(row, "channel");
                        Require(directions.ContainsKey(channel), "map-tamper");
                        Require(Array.IndexOf(directions[channel], ReadString(row, "direction")) >= 0, "map-tamper");
                        string profile = ReadString(row, "profile");
                        Require(profile == "Any" || profile == InteractiveProfile || profile == NonInteractiveProfile, "map-tamper");
                        string tailClass = ReadString(row, "mandatoryTailClass");
                        Require(tailClass == "Ordinary" || tailClass == "Mandatory", "map-tamper");
                        Require(ProtocolCatalogSyntax.IsProtocolIdentifier(ReadString(row, "stateAssoc")), "map-tamper");
                    }
                }
                return true;
            }
            catch (CatalogValidationException)
            {
                return false;
            }
        }

        private static bool EqualBytes(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }

        private static bool InRanges(GeneratedIdRange[] ranges, int value)
        {
            foreach (GeneratedIdRange range in ranges)
            {
                if (range.Contains(value)) return true;
            }
            return false;
        }

        private static void Reject(string reason)
        {
            throw new CatalogValidationException(reason);
        }

        private static bool IsNumericProperty(string property)
        {
            return property == "id" || property == "maxBytes" || property == "maxCodeUnits" || property == "maxUtf16CodeUnits"
                || property == "minBytes" || property == "minCount" || property == "maxCount";
        }

        private static string NumericReason(string kind, string property)
        {
            if (property != "id") return "invalid-production";
            if (kind == "reserve-illegal-type") return "reserve-id-out-of-range";
            if (kind == "overlay-type" || kind == "overlay-message") return "overlay-id-out-of-range";
            if (kind == "field-set" || kind == "field") return "field-overflow";
            return "invalid-production";
        }

        private static void CheckProperties(JObject value, string[] required, string[] optional)
        {
            foreach (string key in value.Values.Keys)
            {
                Require(Array.IndexOf(required, key) >= 0 || Array.IndexOf(optional, key) >= 0, "extra-key");
            }
            foreach (string key in required) Require(value.Values.ContainsKey(key), "missing-property");
        }

        private static JObject RequireObject(JNode node)
        {
            JObject value = node as JObject;
            Require(value != null, "missing-property");
            return value;
        }

        private static JArray ReadArray(JObject value, string key)
        {
            JNode node;
            Require(value.Values.TryGetValue(key, out node) && node is JArray, "missing-property");
            return (JArray)node;
        }

        private static string ReadString(JObject value, string key)
        {
            string result = OptionalString(value, key);
            Require(result != null, "missing-property");
            return result;
        }

        private static string OptionalString(JObject value, string key)
        {
            JNode node;
            if (!value.Values.TryGetValue(key, out node)) return null;
            JString text = node as JString;
            return text == null ? null : text.Value;
        }

        private static int ReadInteger(JObject value, string key, string reason)
        {
            JNode node;
            Require(value.Values.TryGetValue(key, out node) && node is JInteger, reason);
            int result;
            Require(int.TryParse(((JInteger)node).Value, NumberStyles.None, CultureInfo.InvariantCulture, out result), reason);
            return result;
        }

        private static void ReadNumericProperty(JObject value, string key, string reason)
        {
            if (key == "minBytes" || key == "maxBytes" || key == "maxUtf16CodeUnits" || key == "maxCodeUnits")
            {
                ReadUnsignedInteger(value, key, reason);
                return;
            }
            ReadInteger(value, key, reason);
        }

        private static ulong ReadUnsignedInteger(JObject value, string key, string reason)
        {
            JNode node;
            Require(value.Values.TryGetValue(key, out node) && node is JInteger, reason);
            ulong result;
            Require(ulong.TryParse(((JInteger)node).Value, NumberStyles.None, CultureInfo.InvariantCulture, out result), reason);
            return result;
        }

        private static void Require(bool condition, string reason)
        {
            if (!condition) throw new CatalogValidationException(reason);
        }

        private static void RequireJson(byte[] bytes)
        {
            SchemaCheckResult result = SchemaBootstrap.Evaluate("json", bytes, null);
            Require(result.Accepted, result.Reason);
        }

        private sealed class EvaluationState
        {
            internal readonly ProtocolCatalogContractV2 Contract;
            internal readonly IDictionary<string, string[]> Directions;
            internal readonly HashSet<string> ExtensionParents;
            internal readonly Dictionary<string, Dictionary<int, string>> KindNamesById = new Dictionary<string, Dictionary<int, string>>(StringComparer.Ordinal);
            internal readonly Dictionary<string, int> KindNext = new Dictionary<string, int>(StringComparer.Ordinal);
            internal readonly IDictionary<string, GeneratedIdRange[]> KindRanges;
            internal readonly HashSet<int> LiteralTypeIds = new HashSet<int>();
            internal readonly IDictionary<string, string> MessageEnumNames;
            internal readonly Dictionary<string, MessageKind> Messages = new Dictionary<string, MessageKind>(StringComparer.Ordinal);
            internal readonly List<Operation> Operations = new List<Operation>();
            internal readonly GeneratedIdRange OverlayTypeRange;
            internal readonly HashSet<string> ReservedNames = new HashSet<string>(StringComparer.Ordinal);
            internal readonly HashSet<int> ReservedTypeIds = new HashSet<int>();
            internal readonly List<TypeDeclaration> TypeOrder = new List<TypeDeclaration>();
            internal readonly Dictionary<string, TypeDeclaration> Types = new Dictionary<string, TypeDeclaration>(StringComparer.Ordinal);

            internal EvaluationState(ProtocolCatalogContractV2 contract)
            {
                Contract = contract;
                Directions = contract.PermittedDirectionsByChannel;
                ExtensionParents = new HashSet<string>(contract.LiteralExtensionParentNames, StringComparer.Ordinal);
                KindRanges = contract.OverlayKindRangesByChannel;
                MessageEnumNames = contract.MessageEnumNameByChannel;
                OverlayTypeRange = contract.OverlayTypeRange;
                foreach (string channel in contract.Channels)
                {
                    KindNext.Add(channel, 1);
                    KindNamesById.Add(channel, new Dictionary<int, string>());
                }
            }
        }

        private sealed class Operation
        {
            internal readonly List<Branch> Branches = new List<Branch>();
            internal string Catalog;
            internal HashSet<string> ConditionalShapes;
            internal bool ConditionalShapesInitialized;
            internal TypeDeclaration Declaration;
            internal JObject Entry;
            internal readonly List<Field> Fields = new List<Field>();
            internal string Kind;
            internal readonly List<CatalogMember> Members = new List<CatalogMember>();
            internal MessageKind Message;
            internal int Ordinal;
        }

        private sealed class TypeDeclaration
        {
            internal bool Deleted;
            internal readonly HashSet<int>[] EffectiveIds = new HashSet<int>[] { new HashSet<int>(), new HashSet<int>() };
            internal readonly HashSet<string>[] EffectiveNames = new HashSet<string>[]
            {
                new HashSet<string>(StringComparer.Ordinal), new HashSet<string>(StringComparer.Ordinal)
            };
            internal int FieldNext = 1;
            internal readonly List<Field> Fields = new List<Field>();
            internal readonly HashSet<int> FieldSetLiteralIds = new HashSet<int>();
            internal readonly HashSet<string> FieldSetNames = new HashSet<string>(StringComparer.Ordinal);
            internal bool Generated;
            internal int Id;
            internal bool IsDiscriminator;
            internal readonly HashSet<string> MapNames = new HashSet<string>(StringComparer.Ordinal);
            internal string Name;
            internal Operation Operation;
            internal string Production;
            internal readonly Dictionary<string, Operation> ShapeOwners = new Dictionary<string, Operation>(StringComparer.Ordinal);
            internal Operation Union;
        }

        private sealed class Field
        {
            internal ulong Bound;
            internal readonly bool[] Effective = new bool[] { true, true };
            internal JObject Entry;
            internal bool Forbidden;
            internal int Id;
            internal string Name;
            internal string Profile = "Any";
            internal string Type;
        }

        private sealed class Branch
        {
            internal TypeDeclaration Declaration;
            internal readonly List<Field> Fields = new List<Field>();
            internal string Name;
        }

        private sealed class MessageKind
        {
            internal string Channel;
            internal Operation FirstOperation;
            internal int Id;
            internal string Name;
            internal string PayloadRoot;
            internal readonly HashSet<string> Rows = new HashSet<string>(StringComparer.Ordinal);
            internal string StateAssociation;
            internal string TailClass;
        }

        private sealed class CatalogValidationException : Exception
        {
            internal readonly string Reason;

            internal CatalogValidationException(string reason) : base(reason)
            {
                Reason = reason;
            }
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
