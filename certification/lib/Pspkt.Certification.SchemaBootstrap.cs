using System;
using System.Collections.Generic;
using System.Text;

namespace Pspkt.Certification
{
    public sealed class SchemaCheckResult
    {
        private readonly bool _accepted;
        private readonly string _reason;

        internal SchemaCheckResult(bool accepted, string reason)
        {
            _accepted = accepted;
            _reason = reason;
        }

        public bool Accepted { get { return _accepted; } }

        public string Reason { get { return _reason; } }
    }

    internal static class SchemaReason
    {
        internal const string Ok = "ok";
        internal const string InvalidUtf8 = "invalid-utf8";
        internal const string BomForbidden = "bom-forbidden";
        internal const string NulForbidden = "nul-forbidden";
        internal const string CommentForbidden = "comment-forbidden";
        internal const string DuplicateKey = "duplicate-key";
        internal const string TrailingComma = "trailing-comma";
        internal const string TrailingData = "trailing-data";
        internal const string FloatForbidden = "float-forbidden";
        internal const string ExponentForbidden = "exponent-forbidden";
        internal const string NegativeInteger = "negative-integer";
        internal const string LeadingZeroInteger = "leading-zero-integer";
        internal const string IntegerOverflow = "integer-overflow";
        internal const string InvalidEscape = "invalid-escape";
        internal const string UnpairedSurrogate = "unpaired-surrogate";
        internal const string FileLimit = "file-limit";
        internal const string DepthLimit = "depth-limit";
        internal const string PropertyLimit = "property-limit";
        internal const string ArrayLimit = "array-limit";
        internal const string StringLimit = "string-limit";
        internal const string AllocationBudget = "allocation-budget";
        internal const string UnknownProperty = "unknown-property";
        internal const string MissingProperty = "missing-property";
        internal const string DuplicateIdentifier = "duplicate-identifier";
        internal const string UnknownPrimitive = "unknown-primitive";
        internal const string UndefinedReference = "undefined-reference";
        internal const string TypeCycle = "type-cycle";
        internal const string DuplicateTypeId = "duplicate-type-id";
        internal const string DuplicateFieldId = "duplicate-field-id";
        internal const string FieldOrder = "field-order";
        internal const string InvalidCardinality = "invalid-cardinality";
        internal const string BoundOverflow = "bound-overflow";
        internal const string NonAsciiSymbol = "non-ascii-symbol";
        internal const string ReplacementCharacterForbidden = "replacement-character-forbidden";
        internal const string MetaAuthorityMismatch = "meta-authority-mismatch";

        internal static string[] All()
        {
            return new string[]
            {
                Ok, InvalidUtf8, BomForbidden, NulForbidden, CommentForbidden, DuplicateKey,
                TrailingComma, TrailingData, FloatForbidden, ExponentForbidden, NegativeInteger,
                LeadingZeroInteger, IntegerOverflow, InvalidEscape, UnpairedSurrogate,
                ReplacementCharacterForbidden, FileLimit,
                DepthLimit, PropertyLimit, ArrayLimit, StringLimit, AllocationBudget,
                UnknownProperty, MissingProperty, DuplicateIdentifier, UnknownPrimitive,
                UndefinedReference, TypeCycle, DuplicateTypeId, DuplicateFieldId, FieldOrder,
                InvalidCardinality, BoundOverflow, NonAsciiSymbol, MetaAuthorityMismatch
            };
        }
    }

    internal abstract class JsonNode
    {
    }

    internal sealed class JsonObject : JsonNode
    {
        internal readonly List<string> Keys = new List<string>();
        internal readonly Dictionary<string, JsonNode> Members = new Dictionary<string, JsonNode>(StringComparer.Ordinal);
    }

    internal sealed class JsonArray : JsonNode
    {
        internal readonly List<JsonNode> Items = new List<JsonNode>();
    }

    internal sealed class JsonString : JsonNode
    {
        internal string Value;
    }

    internal sealed class JsonInteger : JsonNode
    {
        internal ulong Value;
    }

    internal sealed class JsonBoolean : JsonNode
    {
        internal bool Value;
    }

    internal sealed class JsonNull : JsonNode
    {
    }

    internal sealed class StrictJsonReader
    {
        internal const int MaxFileBytes = 1048576;
        internal const int MaxDepth = 32;
        internal const int MaxProperties = 4096;
        internal const int MaxArrayItems = 8192;
        internal const int MaxStringBytes = 262144;
        internal const long AllocationBudgetBytes = 2097152;

        private readonly byte[] _bytes;
        private int _index;
        private long _nodeCount;
        private string _reason;

        internal StrictJsonReader(byte[] bytes)
        {
            _bytes = bytes;
            _index = 0;
            _nodeCount = 0;
            _reason = null;
        }

        internal string Reason { get { return _reason; } }

        internal JsonNode Parse()
        {
            if (_bytes.Length > MaxFileBytes)
            {
                return Fail(SchemaReason.FileLimit);
            }
            if (_bytes.Length >= 3 && _bytes[0] == 0xEF && _bytes[1] == 0xBB && _bytes[2] == 0xBF)
            {
                return Fail(SchemaReason.BomForbidden);
            }
            for (int scan = 0; scan < _bytes.Length; scan++)
            {
                if (_bytes[scan] == 0x00)
                {
                    return Fail(SchemaReason.NulForbidden);
                }
            }
            JsonNode root = ParseValue(1);
            if (root == null)
            {
                return null;
            }
            if (_index != _bytes.Length)
            {
                return Fail(SchemaReason.TrailingData);
            }
            return root;
        }

        private JsonNode Fail(string reason)
        {
            if (_reason == null)
            {
                _reason = reason;
            }
            return null;
        }

        private bool FailFalse(string reason)
        {
            Fail(reason);
            return false;
        }

        private bool Allocate()
        {
            _nodeCount = _nodeCount + 1;
            long used;
            try
            {
                used = checked((long)_bytes.Length + checked(16L * _nodeCount));
            }
            catch (OverflowException)
            {
                return FailFalse(SchemaReason.AllocationBudget);
            }
            if (used > AllocationBudgetBytes)
            {
                return FailFalse(SchemaReason.AllocationBudget);
            }
            return true;
        }

        private int PeekByte()
        {
            if (_index >= _bytes.Length)
            {
                return -1;
            }
            return _bytes[_index];
        }

        private bool SkipWhitespace()
        {
            while (_index < _bytes.Length)
            {
                byte b = _bytes[_index];
                if (b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D)
                {
                    _index++;
                    continue;
                }
                break;
            }
            int next = PeekByte();
            if (next == '/' || next == '#')
            {
                return FailFalse(SchemaReason.CommentForbidden);
            }
            return true;
        }

        private JsonNode ParseValue(int depth)
        {
            if (depth > MaxDepth)
            {
                return Fail(SchemaReason.DepthLimit);
            }
            if (!Allocate())
            {
                return null;
            }
            int b = PeekByte();
            if (b < 0)
            {
                return Fail(SchemaReason.TrailingData);
            }
            if (b == '{')
            {
                return ParseObject(depth);
            }
            if (b == '[')
            {
                return ParseArray(depth);
            }
            if (b == '"')
            {
                string text;
                if (!ParseString(out text))
                {
                    return null;
                }
                JsonString node = new JsonString();
                node.Value = text;
                return node;
            }
            if (b == '/' || b == '#')
            {
                return Fail(SchemaReason.CommentForbidden);
            }
            if (b == '-')
            {
                return Fail(SchemaReason.NegativeInteger);
            }
            if (b >= '0' && b <= '9')
            {
                return ParseInteger();
            }
            if (b == 't')
            {
                if (!ParseLiteral("true"))
                {
                    return null;
                }
                JsonBoolean node = new JsonBoolean();
                node.Value = true;
                return node;
            }
            if (b == 'f')
            {
                if (!ParseLiteral("false"))
                {
                    return null;
                }
                JsonBoolean node = new JsonBoolean();
                node.Value = false;
                return node;
            }
            if (b == 'n')
            {
                if (!ParseLiteral("null"))
                {
                    return null;
                }
                return new JsonNull();
            }
            return Fail(SchemaReason.TrailingData);
        }

        private bool ParseLiteral(string literal)
        {
            for (int offset = 0; offset < literal.Length; offset++)
            {
                if (_index + offset >= _bytes.Length || _bytes[_index + offset] != (byte)literal[offset])
                {
                    return FailFalse(SchemaReason.TrailingData);
                }
            }
            _index += literal.Length;
            return true;
        }

        private JsonNode ParseObject(int depth)
        {
            _index++;
            JsonObject node = new JsonObject();
            if (!SkipWhitespace())
            {
                return null;
            }
            if (PeekByte() == '}')
            {
                _index++;
                return node;
            }
            while (true)
            {
                if (PeekByte() != '"')
                {
                    return Fail(SchemaReason.TrailingData);
                }
                string key;
                if (!ParseString(out key))
                {
                    return null;
                }
                if (node.Members.ContainsKey(key))
                {
                    return Fail(SchemaReason.DuplicateKey);
                }
                if (node.Keys.Count + 1 > MaxProperties)
                {
                    return Fail(SchemaReason.PropertyLimit);
                }
                if (!Allocate())
                {
                    return null;
                }
                if (!SkipWhitespace())
                {
                    return null;
                }
                if (PeekByte() != ':')
                {
                    return Fail(SchemaReason.TrailingData);
                }
                _index++;
                if (!SkipWhitespace())
                {
                    return null;
                }
                JsonNode value = ParseValue(depth + 1);
                if (value == null)
                {
                    return null;
                }
                node.Keys.Add(key);
                node.Members[key] = value;
                if (!SkipWhitespace())
                {
                    return null;
                }
                int separator = PeekByte();
                if (separator == ',')
                {
                    _index++;
                    if (!SkipWhitespace())
                    {
                        return null;
                    }
                    if (PeekByte() == '}')
                    {
                        return Fail(SchemaReason.TrailingComma);
                    }
                    continue;
                }
                if (separator == '}')
                {
                    _index++;
                    return node;
                }
                return Fail(SchemaReason.TrailingData);
            }
        }

        private JsonNode ParseArray(int depth)
        {
            _index++;
            JsonArray node = new JsonArray();
            if (!SkipWhitespace())
            {
                return null;
            }
            if (PeekByte() == ']')
            {
                _index++;
                return node;
            }
            while (true)
            {
                if (node.Items.Count + 1 > MaxArrayItems)
                {
                    return Fail(SchemaReason.ArrayLimit);
                }
                JsonNode item = ParseValue(depth + 1);
                if (item == null)
                {
                    return null;
                }
                node.Items.Add(item);
                if (!SkipWhitespace())
                {
                    return null;
                }
                int separator = PeekByte();
                if (separator == ',')
                {
                    _index++;
                    if (!SkipWhitespace())
                    {
                        return null;
                    }
                    if (PeekByte() == ']')
                    {
                        return Fail(SchemaReason.TrailingComma);
                    }
                    continue;
                }
                if (separator == ']')
                {
                    _index++;
                    return node;
                }
                return Fail(SchemaReason.TrailingData);
            }
        }

        private JsonNode ParseInteger()
        {
            int start = _index;
            if (_bytes[_index] == (byte)'0')
            {
                _index++;
                int following = PeekByte();
                if (following >= '0' && following <= '9')
                {
                    return Fail(SchemaReason.LeadingZeroInteger);
                }
            }
            else
            {
                while (_index < _bytes.Length && _bytes[_index] >= (byte)'0' && _bytes[_index] <= (byte)'9')
                {
                    _index++;
                }
            }
            int suffix = PeekByte();
            if (suffix == '.')
            {
                return Fail(SchemaReason.FloatForbidden);
            }
            if (suffix == 'e' || suffix == 'E')
            {
                return Fail(SchemaReason.ExponentForbidden);
            }
            ulong value = 0;
            try
            {
                for (int position = start; position < _index; position++)
                {
                    value = checked(checked(value * 10UL) + (ulong)(_bytes[position] - (byte)'0'));
                }
            }
            catch (OverflowException)
            {
                return Fail(SchemaReason.IntegerOverflow);
            }
            JsonInteger node = new JsonInteger();
            node.Value = value;
            return node;
        }

        private bool ParseString(out string value)
        {
            value = null;
            _index++;
            StringBuilder builder = new StringBuilder();
            while (true)
            {
                if (_index >= _bytes.Length)
                {
                    return FailFalse(SchemaReason.TrailingData);
                }
                byte b = _bytes[_index];
                if (b == (byte)'"')
                {
                    _index++;
                    break;
                }
                if (b == (byte)'\\')
                {
                    if (!ParseEscape(builder))
                    {
                        return false;
                    }
                    continue;
                }
                if (b < 0x20)
                {
                    return FailFalse(SchemaReason.InvalidEscape);
                }
                if (b < 0x80)
                {
                    builder.Append((char)b);
                    _index++;
                    continue;
                }
                if (!ParseUtf8Sequence(builder))
                {
                    return false;
                }
            }
            string text = builder.ToString();
            if (Encoding.UTF8.GetByteCount(text) > MaxStringBytes)
            {
                return FailFalse(SchemaReason.StringLimit);
            }
            value = text;
            return true;
        }

        private bool ParseEscape(StringBuilder builder)
        {
            _index++;
            if (_index >= _bytes.Length)
            {
                return FailFalse(SchemaReason.InvalidEscape);
            }
            byte code = _bytes[_index];
            if (code == (byte)'"')
            {
                builder.Append('"');
                _index++;
                return true;
            }
            if (code == (byte)'\\')
            {
                builder.Append('\\');
                _index++;
                return true;
            }
            if (code == (byte)'/')
            {
                builder.Append('/');
                _index++;
                return true;
            }
            if (code == (byte)'b')
            {
                builder.Append('\b');
                _index++;
                return true;
            }
            if (code == (byte)'f')
            {
                builder.Append('\f');
                _index++;
                return true;
            }
            if (code == (byte)'n')
            {
                builder.Append('\n');
                _index++;
                return true;
            }
            if (code == (byte)'r')
            {
                builder.Append('\r');
                _index++;
                return true;
            }
            if (code == (byte)'t')
            {
                builder.Append('\t');
                _index++;
                return true;
            }
            if (code != (byte)'u')
            {
                return FailFalse(SchemaReason.InvalidEscape);
            }
            _index++;
            int unit;
            if (!ReadHexQuad(out unit))
            {
                return FailFalse(SchemaReason.InvalidEscape);
            }
            if (unit == 0)
            {
                return FailFalse(SchemaReason.NulForbidden);
            }
            if (unit >= 0xDC00 && unit <= 0xDFFF)
            {
                return FailFalse(SchemaReason.UnpairedSurrogate);
            }
            if (unit >= 0xD800 && unit <= 0xDBFF)
            {
                if (_index + 1 >= _bytes.Length || _bytes[_index] != (byte)'\\' || _bytes[_index + 1] != (byte)'u')
                {
                    return FailFalse(SchemaReason.UnpairedSurrogate);
                }
                _index += 2;
                int low;
                if (!ReadHexQuad(out low))
                {
                    return FailFalse(SchemaReason.InvalidEscape);
                }
                if (low < 0xDC00 || low > 0xDFFF)
                {
                    return FailFalse(SchemaReason.UnpairedSurrogate);
                }
                builder.Append((char)unit);
                builder.Append((char)low);
                return true;
            }
            if (unit == 0xFFFD)
            {
                return FailFalse(SchemaReason.ReplacementCharacterForbidden);
            }
            builder.Append((char)unit);
            return true;
        }

        private bool ReadHexQuad(out int value)
        {
            value = 0;
            if (_index + 4 > _bytes.Length)
            {
                return false;
            }
            int accumulated = 0;
            for (int offset = 0; offset < 4; offset++)
            {
                byte digit = _bytes[_index + offset];
                int nibble;
                if (digit >= (byte)'0' && digit <= (byte)'9')
                {
                    nibble = digit - (byte)'0';
                }
                else if (digit >= (byte)'a' && digit <= (byte)'f')
                {
                    nibble = 10 + (digit - (byte)'a');
                }
                else if (digit >= (byte)'A' && digit <= (byte)'F')
                {
                    nibble = 10 + (digit - (byte)'A');
                }
                else
                {
                    return false;
                }
                accumulated = (accumulated << 4) | nibble;
            }
            _index += 4;
            value = accumulated;
            return true;
        }

        private bool ParseUtf8Sequence(StringBuilder builder)
        {
            byte lead = _bytes[_index];
            if (lead < 0xC2 || lead > 0xF4)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            int length;
            int codePoint;
            if (lead <= 0xDF)
            {
                length = 2;
                codePoint = lead & 0x1F;
            }
            else if (lead <= 0xEF)
            {
                length = 3;
                codePoint = lead & 0x0F;
            }
            else
            {
                length = 4;
                codePoint = lead & 0x07;
            }
            if (_index + length > _bytes.Length)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            for (int offset = 1; offset < length; offset++)
            {
                byte continuation = _bytes[_index + offset];
                if ((continuation & 0xC0) != 0x80)
                {
                    return FailFalse(SchemaReason.InvalidUtf8);
                }
                codePoint = (codePoint << 6) | (continuation & 0x3F);
            }
            if (length == 2 && codePoint < 0x80)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            if (length == 3 && codePoint < 0x800)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            if (length == 4 && codePoint < 0x10000)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            if (codePoint > 0x10FFFF)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            if (codePoint >= 0xD800 && codePoint <= 0xDFFF)
            {
                return FailFalse(SchemaReason.InvalidUtf8);
            }
            if (codePoint == 0xFFFD)
            {
                return FailFalse(SchemaReason.ReplacementCharacterForbidden);
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
            _index += length;
            return true;
        }
    }

    internal sealed class DeclarationAuthority
    {
        internal List<string> Primitives;
        internal List<string> Productions;
        internal List<string> Encodings;
        internal List<string> Grammars;
        internal ulong TypeIdMinimum;
        internal ulong TypeIdMaximum;
        internal ulong FieldIdMinimum;
        internal ulong FieldIdMaximum;
        internal ulong CardinalityMinimum;
        internal ulong CardinalityMaximum;
        internal ulong EnvironmentNameMinBytes;
        internal ulong EnvironmentNameMaxBytes;
        internal ulong FieldDeclarationMaximum;
        internal string EnvironmentNameGrammar;
        internal string RootTypeName;
        internal ulong TypeDeclarationMaximum;
    }

    internal sealed class DeclarationRecord
    {
        internal string Name;
        internal readonly List<string> References = new List<string>();
    }

    internal static class SchemaSymbols
    {
        internal const ulong UnsignedShortMaximum = 65535UL;
        internal const ulong UnsignedIntegerMaximum = 4294967295UL;
        internal const ulong BootstrapDeclarationMaximum = 4096UL;

        internal static readonly string[] Primitives = new string[]
        {
            "U8", "U16", "U32", "U64", "I16", "I32", "I64", "FILETIME", "QPC", "GUID",
            "Opaque16", "FixedAscii8", "SHA-256", "Opaque32", "AsciiIdentifier", "BinarySid",
            "Utf8Short", "Rsa3072PublicBlob", "Rsa3072Signature", "LUID", "BoundedBytes", "OpaqueUtf16"
        };

        internal static readonly string[] Productions = new string[]
        {
            "EnumU16", "SemanticString", "Named", "List", "Set"
        };

        internal static readonly string[] SignedPrimitives = new string[] { "I16", "I32", "I64" };

        internal static readonly string[] SemanticStringEncodings = new string[]
        {
            "AsciiEnvironmentName", "Utf8"
        };

        internal static readonly string[] SemanticStringGrammars = new string[]
        {
            "None", "PspktPathCanonicalizationV1", "InverseCommandLineToArgvW"
        };

        internal static bool IsAsciiIdentifier(string value)
        {
            if (value == null || value.Length < 1 || value.Length > 64)
            {
                return false;
            }
            char first = value[0];
            if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')))
            {
                return false;
            }
            for (int index = 1; index < value.Length; index++)
            {
                char current = value[index];
                bool allowed = (current >= 'A' && current <= 'Z')
                    || (current >= 'a' && current <= 'z')
                    || (current >= '0' && current <= '9')
                    || current == '-';
                if (!allowed)
                {
                    return false;
                }
            }
            return true;
        }

        internal static bool Contains(IList<string> values, string candidate)
        {
            for (int index = 0; index < values.Count; index++)
            {
                if (string.Equals(values[index], candidate, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }
    }

    internal static class DocumentReader
    {
        internal static bool CheckPropertySet(JsonObject node, string[] allowed, ref string reason)
        {
            for (int index = 0; index < node.Keys.Count; index++)
            {
                if (!SchemaSymbols.Contains(allowed, node.Keys[index]))
                {
                    reason = SchemaReason.UnknownProperty;
                    return false;
                }
            }
            for (int index = 0; index < allowed.Length; index++)
            {
                if (!node.Members.ContainsKey(allowed[index]))
                {
                    reason = SchemaReason.MissingProperty;
                    return false;
                }
            }
            return true;
        }

        internal static bool ExpectBoolean(JsonObject node, string name, bool expected, ref string reason)
        {
            bool actual;
            if (!TryGetBoolean(node, name, out actual, ref reason))
            {
                return false;
            }
            if (actual != expected)
            {
                reason = SchemaReason.UnknownPrimitive;
                return false;
            }
            return true;
        }

        internal static bool ExpectInteger(JsonObject node, string name, ulong expected, ref string reason)
        {
            ulong actual;
            if (!TryGetInteger(node, name, out actual, ref reason))
            {
                return false;
            }
            if (actual != expected)
            {
                reason = SchemaReason.IntegerOverflow;
                return false;
            }
            return true;
        }

        internal static bool ExpectString(JsonObject node, string name, string expected, ref string reason)
        {
            string actual;
            if (!TryGetString(node, name, out actual, ref reason))
            {
                return false;
            }
            if (!string.Equals(actual, expected, StringComparison.Ordinal))
            {
                reason = SchemaReason.UnknownPrimitive;
                return false;
            }
            return true;
        }

        internal static bool TryGetArray(JsonObject node, string name, out JsonArray value, ref string reason)
        {
            return TryGetNode(node, name, SchemaReason.UnknownProperty, out value, ref reason);
        }

        internal static bool TryGetBoolean(JsonObject node, string name, out bool value, ref string reason)
        {
            value = false;
            JsonBoolean flag;
            if (!TryGetNode(node, name, SchemaReason.UnknownPrimitive, out flag, ref reason))
            {
                return false;
            }
            value = flag.Value;
            return true;
        }

        internal static bool TryGetInteger(JsonObject node, string name, out ulong value, ref string reason)
        {
            value = 0;
            JsonInteger integer;
            if (!TryGetNode(node, name, SchemaReason.IntegerOverflow, out integer, ref reason))
            {
                return false;
            }
            value = integer.Value;
            return true;
        }

        internal static bool TryGetObject(JsonObject node, string name, out JsonObject value, ref string reason)
        {
            return TryGetNode(node, name, SchemaReason.UnknownProperty, out value, ref reason);
        }

        internal static bool TryGetString(JsonObject node, string name, out string value, ref string reason)
        {
            value = null;
            JsonString text;
            if (!TryGetNode(node, name, SchemaReason.UnknownPrimitive, out text, ref reason))
            {
                return false;
            }
            value = text.Value;
            return true;
        }

        internal static bool ExpectSymbolUnion(JsonObject node, string name, string[] expected, out List<string> values, ref string reason)
        {
            values = new List<string>();
            JsonArray array;
            if (!TryGetArray(node, name, out array, ref reason))
            {
                return false;
            }
            for (int index = 0; index < array.Items.Count; index++)
            {
                JsonString entry = array.Items[index] as JsonString;
                if (entry == null)
                {
                    reason = SchemaReason.UnknownPrimitive;
                    return false;
                }
                if (!SchemaSymbols.IsAsciiIdentifier(entry.Value))
                {
                    reason = SchemaReason.NonAsciiSymbol;
                    return false;
                }
                if (!SchemaSymbols.Contains(expected, entry.Value))
                {
                    reason = SchemaReason.UnknownPrimitive;
                    return false;
                }
                if (SchemaSymbols.Contains(values, entry.Value))
                {
                    reason = SchemaReason.DuplicateIdentifier;
                    return false;
                }
                values.Add(entry.Value);
            }
            if (values.Count != expected.Length)
            {
                reason = SchemaReason.MissingProperty;
                return false;
            }
            return true;
        }

        private static bool TryGetNode<TNode>(JsonObject node, string name, string invalidReason, out TNode value, ref string reason)
            where TNode : JsonNode
        {
            value = null;
            JsonNode found;
            if (!node.Members.TryGetValue(name, out found))
            {
                reason = SchemaReason.MissingProperty;
                return false;
            }
            value = found as TNode;
            if (value == null)
            {
                reason = invalidReason;
                return false;
            }
            return true;
        }
    }

    internal static class BootstrapMetaGrammar
    {
        private static readonly string[] TopLevelProperties = new string[]
        {
            "schemaVersion", "schemaId", "documentRootType", "primitives", "productions",
            "signedPrimitives", "signedEncoding", "semanticStringEncodings", "semanticStringGrammars",
            "asciiEnvironmentName", "utf8Decoder", "opaqueUtf16", "boundedBytes", "identifiers",
            "cardinality", "types"
        };

        private static readonly string[] AsciiEnvironmentNameProperties = new string[]
        {
            "grammar", "minBytes", "maxBytes", "minByteValue", "maxByteValue", "excludedByteValue"
        };

        private static readonly string[] Utf8DecoderProperties = new string[]
        {
            "form", "forbidNul", "forbidReplacementCharacter", "forbidSurrogates", "normalization"
        };

        private static readonly string[] OpaqueUtf16Properties = new string[]
        {
            "boundProperty", "boundWidth", "encodedSizeFormula", "valueEncoding", "interpretValue"
        };

        private static readonly string[] BoundedBytesProperties = new string[]
        {
            "boundProperty", "boundWidth", "encodedSizeFormula"
        };

        private static readonly string[] IdentifierProperties = new string[]
        {
            "typeIdWidth", "typeIdMinimum", "typeIdScope", "fieldIdWidth", "fieldIdMinimum",
            "fieldIdScope", "fieldOrder"
        };

        private static readonly string[] CardinalityProperties = new string[] { "minimum", "maximum" };

        internal static bool Validate(byte[] rawBytes, JsonNode root, out DeclarationAuthority authority, out string reason)
        {
            authority = null;
            reason = SchemaReason.Ok;
            JsonObject document = root as JsonObject;
            if (document == null)
            {
                reason = SchemaReason.UnknownProperty;
                return false;
            }
            if (!DocumentReader.CheckPropertySet(document, TopLevelProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectInteger(document, "schemaVersion", 1UL, ref reason))
            {
                return false;
            }
            string schemaId;
            if (!DocumentReader.TryGetString(document, "schemaId", out schemaId, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.IsAsciiIdentifier(schemaId))
            {
                reason = SchemaReason.NonAsciiSymbol;
                return false;
            }
            string rootTypeName;
            if (!DocumentReader.TryGetString(document, "documentRootType", out rootTypeName, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.IsAsciiIdentifier(rootTypeName))
            {
                reason = SchemaReason.NonAsciiSymbol;
                return false;
            }

            List<string> primitives;
            if (!DocumentReader.ExpectSymbolUnion(document, "primitives", SchemaSymbols.Primitives, out primitives, ref reason))
            {
                return false;
            }
            List<string> productions;
            if (!DocumentReader.ExpectSymbolUnion(document, "productions", SchemaSymbols.Productions, out productions, ref reason))
            {
                return false;
            }
            List<string> signedPrimitives;
            if (!DocumentReader.ExpectSymbolUnion(document, "signedPrimitives", SchemaSymbols.SignedPrimitives, out signedPrimitives, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectString(document, "signedEncoding", "TwosComplementBigEndian", ref reason))
            {
                return false;
            }
            List<string> encodings;
            if (!DocumentReader.ExpectSymbolUnion(document, "semanticStringEncodings", SchemaSymbols.SemanticStringEncodings, out encodings, ref reason))
            {
                return false;
            }
            List<string> grammars;
            if (!DocumentReader.ExpectSymbolUnion(document, "semanticStringGrammars", SchemaSymbols.SemanticStringGrammars, out grammars, ref reason))
            {
                return false;
            }

            JsonObject environmentName;
            if (!DocumentReader.TryGetObject(document, "asciiEnvironmentName", out environmentName, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(environmentName, AsciiEnvironmentNameProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectString(environmentName, "grammar", "None", ref reason)
                || !DocumentReader.ExpectInteger(environmentName, "minBytes", 1UL, ref reason)
                || !DocumentReader.ExpectInteger(environmentName, "maxBytes", 32767UL, ref reason)
                || !DocumentReader.ExpectInteger(environmentName, "minByteValue", 1UL, ref reason)
                || !DocumentReader.ExpectInteger(environmentName, "maxByteValue", 127UL, ref reason)
                || !DocumentReader.ExpectInteger(environmentName, "excludedByteValue", 61UL, ref reason))
            {
                return false;
            }

            JsonObject utf8Decoder;
            if (!DocumentReader.TryGetObject(document, "utf8Decoder", out utf8Decoder, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(utf8Decoder, Utf8DecoderProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectString(utf8Decoder, "form", "ShortestForm", ref reason)
                || !DocumentReader.ExpectBoolean(utf8Decoder, "forbidNul", true, ref reason)
                || !DocumentReader.ExpectBoolean(utf8Decoder, "forbidReplacementCharacter", true, ref reason)
                || !DocumentReader.ExpectBoolean(utf8Decoder, "forbidSurrogates", true, ref reason)
                || !DocumentReader.ExpectString(utf8Decoder, "normalization", "None", ref reason))
            {
                return false;
            }

            JsonObject opaqueUtf16;
            if (!DocumentReader.TryGetObject(document, "opaqueUtf16", out opaqueUtf16, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(opaqueUtf16, OpaqueUtf16Properties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectString(opaqueUtf16, "boundProperty", "maxCodeUnits", ref reason)
                || !DocumentReader.ExpectString(opaqueUtf16, "boundWidth", "U32", ref reason)
                || !DocumentReader.ExpectString(opaqueUtf16, "encodedSizeFormula", "4+2*maxCodeUnits", ref reason)
                || !DocumentReader.ExpectString(opaqueUtf16, "valueEncoding", "U32BigEndianCountThenRawUtf16LittleEndian", ref reason)
                || !DocumentReader.ExpectBoolean(opaqueUtf16, "interpretValue", false, ref reason))
            {
                return false;
            }

            JsonObject boundedBytes;
            if (!DocumentReader.TryGetObject(document, "boundedBytes", out boundedBytes, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(boundedBytes, BoundedBytesProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectString(boundedBytes, "boundProperty", "maxBytes", ref reason)
                || !DocumentReader.ExpectString(boundedBytes, "boundWidth", "U32", ref reason)
                || !DocumentReader.ExpectString(boundedBytes, "encodedSizeFormula", "4+maxBytes", ref reason))
            {
                return false;
            }

            JsonObject identifiers;
            if (!DocumentReader.TryGetObject(document, "identifiers", out identifiers, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(identifiers, IdentifierProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectString(identifiers, "typeIdWidth", "U16", ref reason)
                || !DocumentReader.ExpectInteger(identifiers, "typeIdMinimum", 1UL, ref reason)
                || !DocumentReader.ExpectString(identifiers, "typeIdScope", "Global", ref reason)
                || !DocumentReader.ExpectString(identifiers, "fieldIdWidth", "U16", ref reason)
                || !DocumentReader.ExpectInteger(identifiers, "fieldIdMinimum", 1UL, ref reason)
                || !DocumentReader.ExpectString(identifiers, "fieldIdScope", "PerType", ref reason)
                || !DocumentReader.ExpectString(identifiers, "fieldOrder", "StrictlyAscending", ref reason))
            {
                return false;
            }

            JsonObject cardinality;
            if (!DocumentReader.TryGetObject(document, "cardinality", out cardinality, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(cardinality, CardinalityProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectInteger(cardinality, "minimum", 0UL, ref reason)
                || !DocumentReader.ExpectInteger(cardinality, "maximum", SchemaSymbols.UnsignedShortMaximum, ref reason))
            {
                return false;
            }

            DeclarationAuthority resolved = new DeclarationAuthority();
            resolved.Primitives = primitives;
            resolved.Productions = productions;
            resolved.Encodings = encodings;
            resolved.Grammars = grammars;
            resolved.TypeIdMinimum = 1UL;
            resolved.TypeIdMaximum = SchemaSymbols.UnsignedShortMaximum;
            resolved.FieldIdMinimum = 1UL;
            resolved.FieldIdMaximum = SchemaSymbols.UnsignedShortMaximum;
            resolved.CardinalityMinimum = 0UL;
            resolved.CardinalityMaximum = SchemaSymbols.UnsignedShortMaximum;
            resolved.EnvironmentNameMinBytes = 1UL;
            resolved.EnvironmentNameMaxBytes = 32767UL;
            resolved.FieldDeclarationMaximum = SchemaSymbols.BootstrapDeclarationMaximum;
            resolved.EnvironmentNameGrammar = "None";
            resolved.RootTypeName = rootTypeName;
            resolved.TypeDeclarationMaximum = SchemaSymbols.BootstrapDeclarationMaximum;

            JsonArray types;
            if (!DocumentReader.TryGetArray(document, "types", out types, ref reason))
            {
                return false;
            }
            List<string> declaredNames;
            if (!DeclarationValidator.Validate(types, resolved, out declaredNames, ref reason))
            {
                return false;
            }
            ulong fieldDeclarationMaximum;
            ulong typeDeclarationMaximum;
            if (!TryGetCollectionMaximum(types, "FieldDeclarationList", out fieldDeclarationMaximum, ref reason)
                || !TryGetCollectionMaximum(types, "TypeDeclarationList", out typeDeclarationMaximum, ref reason))
            {
                return false;
            }
            if (fieldDeclarationMaximum != SchemaSymbols.BootstrapDeclarationMaximum
                || typeDeclarationMaximum != SchemaSymbols.BootstrapDeclarationMaximum)
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            ulong enumMemberDeclarationMaximum;
            if (!TryGetCollectionMaximum(types, "EnumMemberDeclarationList", out enumMemberDeclarationMaximum, ref reason))
            {
                return false;
            }
            if (enumMemberDeclarationMaximum != (ulong)StrictJsonReader.MaxArrayItems)
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            resolved.FieldDeclarationMaximum = fieldDeclarationMaximum;
            resolved.TypeDeclarationMaximum = typeDeclarationMaximum;
            if (!SchemaSymbols.Contains(declaredNames, rootTypeName))
            {
                reason = SchemaReason.UndefinedReference;
                return false;
            }
            if (!string.Equals(ComputeSha256Hex(rawBytes), CommittedMetaSha256, StringComparison.Ordinal))
            {
                reason = SchemaReason.MetaAuthorityMismatch;
                return false;
            }
            authority = resolved;
            reason = SchemaReason.Ok;
            return true;
        }

        private static bool TryGetCollectionMaximum(JsonArray types, string name, out ulong maximum, ref string reason)
        {
            maximum = 0;
            for (int index = 0; index < types.Items.Count; index++)
            {
                JsonObject declaration = types.Items[index] as JsonObject;
                if (declaration == null)
                {
                    reason = SchemaReason.UnknownProperty;
                    return false;
                }
                string declarationName;
                if (!DocumentReader.TryGetString(declaration, "name", out declarationName, ref reason))
                {
                    return false;
                }
                if (!string.Equals(declarationName, name, StringComparison.Ordinal))
                {
                    continue;
                }
                if (!DocumentReader.ExpectString(declaration, "production", "List", ref reason)
                    || !DocumentReader.TryGetInteger(declaration, "maxCount", out maximum, ref reason))
                {
                    return false;
                }
                return true;
            }
            reason = SchemaReason.MissingProperty;
            return false;
        }

        internal const string CommittedMetaSha256 =
            "9b13be426d37e3da01870ff32ec5c4e5db63e9699566a1978007e1f8c07fcd2c";

        private static string ComputeSha256Hex(byte[] bytes)
        {
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                for (int index = 0; index < hash.Length; index++)
                {
                    builder.Append(hash[index].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                }
                return builder.ToString();
            }
        }
    }

    internal static class DeclarationValidator
    {
        private static readonly string[] NamedProperties = new string[] { "production", "name", "typeId", "fields" };
        private static readonly string[] EnumProperties = new string[] { "production", "name", "typeId", "members" };
        private static readonly string[] SemanticStringProperties = new string[]
        {
            "production", "name", "typeId", "encoding", "grammar", "minBytes", "maxBytes", "maxUtf16CodeUnits"
        };
        private static readonly string[] CollectionProperties = new string[]
        {
            "production", "name", "typeId", "elementType", "minCount", "maxCount"
        };
        private static readonly string[] FieldProperties = new string[] { "name", "fieldId", "type" };
        private static readonly string[] OpaqueUtf16FieldProperties = new string[] { "name", "fieldId", "type", "maxCodeUnits" };
        private static readonly string[] BoundedBytesFieldProperties = new string[] { "name", "fieldId", "type", "maxBytes" };
        private static readonly string[] EnumMemberProperties = new string[] { "name", "value" };

        internal static bool Validate(JsonArray types, DeclarationAuthority authority, out List<string> declaredNames, ref string reason)
        {
            declaredNames = new List<string>();
            if ((ulong)types.Items.Count > authority.TypeDeclarationMaximum)
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            List<DeclarationRecord> records = new List<DeclarationRecord>();
            List<ulong> typeIds = new List<ulong>();
            for (int index = 0; index < types.Items.Count; index++)
            {
                JsonObject declaration = types.Items[index] as JsonObject;
                if (declaration == null)
                {
                    reason = SchemaReason.UnknownProperty;
                    return false;
                }
                DeclarationRecord record = new DeclarationRecord();
                if (!ValidateDeclaration(declaration, authority, record, ref reason))
                {
                    return false;
                }
                if (SchemaSymbols.Contains(declaredNames, record.Name))
                {
                    reason = SchemaReason.DuplicateIdentifier;
                    return false;
                }
                ulong typeId;
                if (!DocumentReader.TryGetInteger(declaration, "typeId", out typeId, ref reason))
                {
                    return false;
                }
                for (int existing = 0; existing < typeIds.Count; existing++)
                {
                    if (typeIds[existing] == typeId)
                    {
                        reason = SchemaReason.DuplicateTypeId;
                        return false;
                    }
                }
                typeIds.Add(typeId);
                declaredNames.Add(record.Name);
                records.Add(record);
            }

            for (int index = 0; index < records.Count; index++)
            {
                DeclarationRecord record = records[index];
                for (int reference = 0; reference < record.References.Count; reference++)
                {
                    string target = record.References[reference];
                    if (SchemaSymbols.Contains(declaredNames, target))
                    {
                        continue;
                    }
                    if (SchemaSymbols.Contains(authority.Primitives, target))
                    {
                        continue;
                    }
                    reason = SchemaReason.UndefinedReference;
                    return false;
                }
            }

            if (!IsAcyclic(records))
            {
                reason = SchemaReason.TypeCycle;
                return false;
            }
            return true;
        }

        private static bool ValidateDeclaration(JsonObject declaration, DeclarationAuthority authority, DeclarationRecord record, ref string reason)
        {
            string production;
            if (!DocumentReader.TryGetString(declaration, "production", out production, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.Contains(authority.Productions, production))
            {
                reason = SchemaReason.UnknownPrimitive;
                return false;
            }
            string[] allowed;
            if (string.Equals(production, "Named", StringComparison.Ordinal))
            {
                allowed = NamedProperties;
            }
            else if (string.Equals(production, "EnumU16", StringComparison.Ordinal))
            {
                allowed = EnumProperties;
            }
            else if (string.Equals(production, "SemanticString", StringComparison.Ordinal))
            {
                allowed = SemanticStringProperties;
            }
            else
            {
                allowed = CollectionProperties;
            }
            if (!DocumentReader.CheckPropertySet(declaration, allowed, ref reason))
            {
                return false;
            }
            string name;
            if (!DocumentReader.TryGetString(declaration, "name", out name, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.IsAsciiIdentifier(name))
            {
                reason = SchemaReason.NonAsciiSymbol;
                return false;
            }
            if (SchemaSymbols.Contains(authority.Primitives, name))
            {
                reason = SchemaReason.DuplicateIdentifier;
                return false;
            }
            record.Name = name;
            ulong typeId;
            if (!DocumentReader.TryGetInteger(declaration, "typeId", out typeId, ref reason))
            {
                return false;
            }
            if (typeId < authority.TypeIdMinimum || typeId > authority.TypeIdMaximum)
            {
                reason = SchemaReason.IntegerOverflow;
                return false;
            }
            if (string.Equals(production, "Named", StringComparison.Ordinal))
            {
                return ValidateNamedFields(declaration, authority, record, ref reason);
            }
            if (string.Equals(production, "EnumU16", StringComparison.Ordinal))
            {
                return ValidateEnumMembers(declaration, ref reason);
            }
            if (string.Equals(production, "SemanticString", StringComparison.Ordinal))
            {
                return ValidateSemanticString(declaration, authority, ref reason);
            }
            return ValidateCollection(declaration, authority, record, ref reason);
        }

        private static bool ValidateNamedFields(JsonObject declaration, DeclarationAuthority authority, DeclarationRecord record, ref string reason)
        {
            JsonArray fields;
            if (!DocumentReader.TryGetArray(declaration, "fields", out fields, ref reason))
            {
                return false;
            }
            if (fields.Items.Count < 1)
            {
                reason = SchemaReason.MissingProperty;
                return false;
            }
            if ((ulong)fields.Items.Count > authority.FieldDeclarationMaximum)
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            List<string> fieldNames = new List<string>();
            List<ulong> fieldIds = new List<ulong>();
            ulong previousFieldId = 0;
            for (int index = 0; index < fields.Items.Count; index++)
            {
                JsonObject field = fields.Items[index] as JsonObject;
                if (field == null)
                {
                    reason = SchemaReason.UnknownProperty;
                    return false;
                }
                string typeReference;
                if (!DocumentReader.TryGetString(field, "type", out typeReference, ref reason))
                {
                    return false;
                }
                string[] allowed = FieldProperties;
                if (string.Equals(typeReference, "OpaqueUtf16", StringComparison.Ordinal))
                {
                    allowed = OpaqueUtf16FieldProperties;
                }
                else if (string.Equals(typeReference, "BoundedBytes", StringComparison.Ordinal))
                {
                    allowed = BoundedBytesFieldProperties;
                }
                if (!DocumentReader.CheckPropertySet(field, allowed, ref reason))
                {
                    return false;
                }
                string fieldName;
                if (!DocumentReader.TryGetString(field, "name", out fieldName, ref reason))
                {
                    return false;
                }
                if (!SchemaSymbols.IsAsciiIdentifier(fieldName))
                {
                    reason = SchemaReason.NonAsciiSymbol;
                    return false;
                }
                if (SchemaSymbols.Contains(fieldNames, fieldName))
                {
                    reason = SchemaReason.DuplicateIdentifier;
                    return false;
                }
                fieldNames.Add(fieldName);
                ulong fieldId;
                if (!DocumentReader.TryGetInteger(field, "fieldId", out fieldId, ref reason))
                {
                    return false;
                }
                if (fieldId < authority.FieldIdMinimum || fieldId > authority.FieldIdMaximum)
                {
                    reason = SchemaReason.IntegerOverflow;
                    return false;
                }
                for (int existing = 0; existing < fieldIds.Count; existing++)
                {
                    if (fieldIds[existing] == fieldId)
                    {
                        reason = SchemaReason.DuplicateFieldId;
                        return false;
                    }
                }
                if (index > 0 && fieldId <= previousFieldId)
                {
                    reason = SchemaReason.FieldOrder;
                    return false;
                }
                fieldIds.Add(fieldId);
                previousFieldId = fieldId;
                if (string.Equals(typeReference, "OpaqueUtf16", StringComparison.Ordinal))
                {
                    ulong maxCodeUnits;
                    if (!DocumentReader.TryGetInteger(field, "maxCodeUnits", out maxCodeUnits, ref reason))
                    {
                        return false;
                    }
                    if (maxCodeUnits > SchemaSymbols.UnsignedIntegerMaximum)
                    {
                        reason = SchemaReason.IntegerOverflow;
                        return false;
                    }
                    if (!FitsUnsignedInteger(4UL, 2UL, maxCodeUnits))
                    {
                        reason = SchemaReason.BoundOverflow;
                        return false;
                    }
                }
                else if (string.Equals(typeReference, "BoundedBytes", StringComparison.Ordinal))
                {
                    ulong maxBytes;
                    if (!DocumentReader.TryGetInteger(field, "maxBytes", out maxBytes, ref reason))
                    {
                        return false;
                    }
                    if (maxBytes > SchemaSymbols.UnsignedIntegerMaximum)
                    {
                        reason = SchemaReason.IntegerOverflow;
                        return false;
                    }
                    if (!FitsUnsignedInteger(4UL, 1UL, maxBytes))
                    {
                        reason = SchemaReason.BoundOverflow;
                        return false;
                    }
                }
                record.References.Add(typeReference);
            }
            return true;
        }

        private static bool ValidateEnumMembers(JsonObject declaration, ref string reason)
        {
            JsonArray members;
            if (!DocumentReader.TryGetArray(declaration, "members", out members, ref reason))
            {
                return false;
            }
            if (members.Items.Count < 1)
            {
                reason = SchemaReason.MissingProperty;
                return false;
            }
            List<string> memberNames = new List<string>();
            List<ulong> memberValues = new List<ulong>();
            for (int index = 0; index < members.Items.Count; index++)
            {
                JsonObject member = members.Items[index] as JsonObject;
                if (member == null)
                {
                    reason = SchemaReason.UnknownProperty;
                    return false;
                }
                if (!DocumentReader.CheckPropertySet(member, EnumMemberProperties, ref reason))
                {
                    return false;
                }
                string memberName;
                if (!DocumentReader.TryGetString(member, "name", out memberName, ref reason))
                {
                    return false;
                }
                if (!SchemaSymbols.IsAsciiIdentifier(memberName))
                {
                    reason = SchemaReason.NonAsciiSymbol;
                    return false;
                }
                if (SchemaSymbols.Contains(memberNames, memberName))
                {
                    reason = SchemaReason.DuplicateIdentifier;
                    return false;
                }
                memberNames.Add(memberName);
                ulong memberValue;
                if (!DocumentReader.TryGetInteger(member, "value", out memberValue, ref reason))
                {
                    return false;
                }
                if (memberValue > SchemaSymbols.UnsignedShortMaximum)
                {
                    reason = SchemaReason.IntegerOverflow;
                    return false;
                }
                for (int existing = 0; existing < memberValues.Count; existing++)
                {
                    if (memberValues[existing] == memberValue)
                    {
                        reason = SchemaReason.DuplicateIdentifier;
                        return false;
                    }
                }
                memberValues.Add(memberValue);
            }
            return true;
        }

        private static bool ValidateSemanticString(JsonObject declaration, DeclarationAuthority authority, ref string reason)
        {
            string encoding;
            if (!DocumentReader.TryGetString(declaration, "encoding", out encoding, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.Contains(authority.Encodings, encoding))
            {
                reason = SchemaReason.UnknownPrimitive;
                return false;
            }
            string grammar;
            if (!DocumentReader.TryGetString(declaration, "grammar", out grammar, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.Contains(authority.Grammars, grammar))
            {
                reason = SchemaReason.UnknownPrimitive;
                return false;
            }
            ulong minBytes;
            ulong maxBytes;
            ulong maxUtf16CodeUnits;
            if (!DocumentReader.TryGetInteger(declaration, "minBytes", out minBytes, ref reason)
                || !DocumentReader.TryGetInteger(declaration, "maxBytes", out maxBytes, ref reason)
                || !DocumentReader.TryGetInteger(declaration, "maxUtf16CodeUnits", out maxUtf16CodeUnits, ref reason))
            {
                return false;
            }
            if (minBytes > SchemaSymbols.UnsignedIntegerMaximum
                || maxBytes > SchemaSymbols.UnsignedIntegerMaximum
                || maxUtf16CodeUnits > SchemaSymbols.UnsignedIntegerMaximum)
            {
                reason = SchemaReason.IntegerOverflow;
                return false;
            }
            if (minBytes < 1UL || minBytes > maxBytes)
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            if (!FitsUnsignedInteger(4UL, 1UL, maxBytes))
            {
                reason = SchemaReason.BoundOverflow;
                return false;
            }
            if (string.Equals(encoding, "AsciiEnvironmentName", StringComparison.Ordinal))
            {
                if (!string.Equals(grammar, authority.EnvironmentNameGrammar, StringComparison.Ordinal))
                {
                    reason = SchemaReason.UnknownPrimitive;
                    return false;
                }
                if (minBytes != authority.EnvironmentNameMinBytes || maxBytes != authority.EnvironmentNameMaxBytes)
                {
                    reason = SchemaReason.InvalidCardinality;
                    return false;
                }
                if (maxUtf16CodeUnits != maxBytes)
                {
                    reason = SchemaReason.InvalidCardinality;
                    return false;
                }
            }
            else if (maxUtf16CodeUnits < 1UL
                || maxUtf16CodeUnits > maxBytes
                || minBytes > checked(3UL * maxUtf16CodeUnits))
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            return true;
        }

        private static bool ValidateCollection(JsonObject declaration, DeclarationAuthority authority, DeclarationRecord record, ref string reason)
        {
            string elementType;
            if (!DocumentReader.TryGetString(declaration, "elementType", out elementType, ref reason))
            {
                return false;
            }
            ulong minCount;
            ulong maxCount;
            if (!DocumentReader.TryGetInteger(declaration, "minCount", out minCount, ref reason)
                || !DocumentReader.TryGetInteger(declaration, "maxCount", out maxCount, ref reason))
            {
                return false;
            }
            if (minCount > SchemaSymbols.UnsignedIntegerMaximum || maxCount > SchemaSymbols.UnsignedIntegerMaximum)
            {
                reason = SchemaReason.IntegerOverflow;
                return false;
            }
            if (maxCount < 1UL
                || minCount > maxCount
                || minCount < authority.CardinalityMinimum
                || maxCount > authority.CardinalityMaximum)
            {
                reason = SchemaReason.InvalidCardinality;
                return false;
            }
            record.References.Add(elementType);
            return true;
        }

        private static bool FitsUnsignedInteger(ulong constant, ulong multiplier, ulong value)
        {
            ulong total;
            try
            {
                total = checked(constant + checked(multiplier * value));
            }
            catch (OverflowException)
            {
                return false;
            }
            return total <= SchemaSymbols.UnsignedIntegerMaximum;
        }

        private static bool IsAcyclic(List<DeclarationRecord> records)
        {
            Dictionary<string, int> indexByName = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int index = 0; index < records.Count; index++)
            {
                indexByName[records[index].Name] = index;
            }
            int[] state = new int[records.Count];
            for (int index = 0; index < records.Count; index++)
            {
                if (state[index] == 0 && HasCycle(records, indexByName, state, index))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool HasCycle(List<DeclarationRecord> records, Dictionary<string, int> indexByName, int[] state, int current)
        {
            state[current] = 1;
            DeclarationRecord record = records[current];
            for (int reference = 0; reference < record.References.Count; reference++)
            {
                int target;
                if (!indexByName.TryGetValue(record.References[reference], out target))
                {
                    continue;
                }
                if (state[target] == 1)
                {
                    return true;
                }
                if (state[target] == 0 && HasCycle(records, indexByName, state, target))
                {
                    return true;
                }
            }
            state[current] = 2;
            return false;
        }
    }

    internal static class SchemaDocumentValidator
    {
        internal static bool Validate(JsonNode root, DeclarationAuthority authority, JsonObject meta, out string reason)
        {
            reason = SchemaReason.Ok;
            JsonObject document = root as JsonObject;
            if (document == null)
            {
                reason = SchemaReason.UnknownProperty;
                return false;
            }
            string[] rootProperties;
            if (!TryGetRootPropertyNames(meta, authority, out rootProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.CheckPropertySet(document, rootProperties, ref reason))
            {
                return false;
            }
            if (!DocumentReader.ExpectInteger(document, "schemaVersion", 1UL, ref reason))
            {
                return false;
            }
            string schemaId;
            if (!DocumentReader.TryGetString(document, "schemaId", out schemaId, ref reason))
            {
                return false;
            }
            if (!SchemaSymbols.IsAsciiIdentifier(schemaId))
            {
                reason = SchemaReason.NonAsciiSymbol;
                return false;
            }
            JsonArray types;
            if (!DocumentReader.TryGetArray(document, "types", out types, ref reason))
            {
                return false;
            }
            if (types.Items.Count < 1)
            {
                reason = SchemaReason.MissingProperty;
                return false;
            }
            List<string> declaredNames;
            if (!DeclarationValidator.Validate(types, authority, out declaredNames, ref reason))
            {
                return false;
            }
            reason = SchemaReason.Ok;
            return true;
        }

        private static bool TryGetRootPropertyNames(JsonObject meta, DeclarationAuthority authority, out string[] names, ref string reason)
        {
            names = null;
            JsonArray types;
            if (!DocumentReader.TryGetArray(meta, "types", out types, ref reason))
            {
                return false;
            }
            for (int index = 0; index < types.Items.Count; index++)
            {
                JsonObject declaration = types.Items[index] as JsonObject;
                if (declaration == null)
                {
                    continue;
                }
                string name;
                string ignored = SchemaReason.Ok;
                if (!DocumentReader.TryGetString(declaration, "name", out name, ref ignored))
                {
                    continue;
                }
                if (!string.Equals(name, authority.RootTypeName, StringComparison.Ordinal))
                {
                    continue;
                }
                JsonArray fields;
                if (!DocumentReader.TryGetArray(declaration, "fields", out fields, ref reason))
                {
                    return false;
                }
                List<string> collected = new List<string>();
                for (int field = 0; field < fields.Items.Count; field++)
                {
                    JsonObject entry = fields.Items[field] as JsonObject;
                    if (entry == null)
                    {
                        reason = SchemaReason.UnknownProperty;
                        return false;
                    }
                    string fieldName;
                    if (!DocumentReader.TryGetString(entry, "name", out fieldName, ref reason))
                    {
                        return false;
                    }
                    collected.Add(fieldName);
                }
                names = collected.ToArray();
                return true;
            }
            reason = SchemaReason.UndefinedReference;
            return false;
        }
    }

    public static class SchemaBootstrap
    {
        internal const string StageJson = "json";
        internal const string StageBootstrapMeta = "bootstrap-meta";
        internal const string StageSchemaAgainstMeta = "schema-against-meta";

        public static string[] ReasonCodes()
        {
            return SchemaReason.All();
        }

        internal static string[] PrimitiveUnion()
        {
            return (string[])SchemaSymbols.Primitives.Clone();
        }

        internal static string[] ProductionUnion()
        {
            return (string[])SchemaSymbols.Productions.Clone();
        }

        public static SchemaCheckResult Evaluate(string stage, byte[] sourceBytes, byte[] metaBytes)
        {
            if (sourceBytes == null)
            {
                throw new ArgumentNullException("sourceBytes");
            }
            if (string.Equals(stage, StageJson, StringComparison.Ordinal))
            {
                return EvaluateJson(sourceBytes);
            }
            if (string.Equals(stage, StageBootstrapMeta, StringComparison.Ordinal))
            {
                return EvaluateBootstrapMeta(sourceBytes);
            }
            if (string.Equals(stage, StageSchemaAgainstMeta, StringComparison.Ordinal))
            {
                if (metaBytes == null)
                {
                    throw new ArgumentNullException("metaBytes");
                }
                return EvaluateSchemaAgainstMeta(sourceBytes, metaBytes);
            }
            throw new ArgumentException("Unknown stage.", "stage");
        }

        private static SchemaCheckResult EvaluateJson(byte[] sourceBytes)
        {
            StrictJsonReader reader = new StrictJsonReader(sourceBytes);
            JsonNode root = reader.Parse();
            if (root == null)
            {
                return new SchemaCheckResult(false, reader.Reason);
            }
            return new SchemaCheckResult(true, SchemaReason.Ok);
        }

        private static SchemaCheckResult EvaluateBootstrapMeta(byte[] sourceBytes)
        {
            StrictJsonReader reader = new StrictJsonReader(sourceBytes);
            JsonNode root = reader.Parse();
            if (root == null)
            {
                return new SchemaCheckResult(false, reader.Reason);
            }
            DeclarationAuthority authority;
            string reason;
            if (!BootstrapMetaGrammar.Validate(sourceBytes, root, out authority, out reason))
            {
                return new SchemaCheckResult(false, reason);
            }
            return new SchemaCheckResult(true, SchemaReason.Ok);
        }

        private static SchemaCheckResult EvaluateSchemaAgainstMeta(byte[] sourceBytes, byte[] metaBytes)
        {
            StrictJsonReader metaReader = new StrictJsonReader(metaBytes);
            JsonNode metaRoot = metaReader.Parse();
            if (metaRoot == null)
            {
                return new SchemaCheckResult(false, metaReader.Reason);
            }
            DeclarationAuthority authority;
            string reason;
            if (!BootstrapMetaGrammar.Validate(metaBytes, metaRoot, out authority, out reason))
            {
                return new SchemaCheckResult(false, reason);
            }
            StrictJsonReader reader = new StrictJsonReader(sourceBytes);
            JsonNode root = reader.Parse();
            if (root == null)
            {
                return new SchemaCheckResult(false, reader.Reason);
            }
            if (!SchemaDocumentValidator.Validate(root, authority, (JsonObject)metaRoot, out reason))
            {
                return new SchemaCheckResult(false, reason);
            }
            return new SchemaCheckResult(true, SchemaReason.Ok);
        }
    }
}
