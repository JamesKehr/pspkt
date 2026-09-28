using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Pspkt.Certification;

namespace Pspkt.Certification.FoundationVerify
{
    public sealed class FoundationVerifyResult
    {
        private readonly bool _accepted;
        private readonly string _reason;

        internal FoundationVerifyResult(bool accepted, string reason)
        {
            _accepted = accepted;
            _reason = reason;
        }

        public bool Accepted { get { return _accepted; } }
        public string Reason { get { return _reason; } }
    }

    internal abstract class VerifyNode
    {
    }

    internal sealed class VerifyObject : VerifyNode
    {
        internal readonly Dictionary<string, VerifyNode> Values = new Dictionary<string, VerifyNode>(StringComparer.Ordinal);
    }

    internal sealed class VerifyArray : VerifyNode
    {
        internal readonly List<VerifyNode> Values = new List<VerifyNode>();
    }

    internal sealed class VerifyString : VerifyNode
    {
        internal string Value;
    }

    internal sealed class VerifyInteger : VerifyNode
    {
        internal long Value;
    }

    internal sealed class VerifyBoolean : VerifyNode
    {
        internal bool Value;
    }

    internal sealed class VerifyNull : VerifyNode
    {
    }

    internal sealed class VerifyJsonParser
    {
        private readonly string _text;
        private int _index;

        internal VerifyJsonParser(byte[] bytes)
        {
            _text = new UTF8Encoding(false, true).GetString(bytes);
        }

        internal VerifyNode Parse()
        {
            SkipWhitespace();
            VerifyNode node = ParseValue();
            SkipWhitespace();
            if (_index != _text.Length)
            {
                throw new FormatException();
            }
            return node;
        }

        private VerifyNode ParseValue()
        {
            if (_index >= _text.Length)
            {
                throw new FormatException();
            }
            char current = _text[_index];
            if (current == '{') return ParseObject();
            if (current == '[') return ParseArray();
            if (current == '"') return new VerifyString { Value = ParseString() };
            if (current >= '0' && current <= '9') return new VerifyInteger { Value = ParseInteger() };
            if (ReadLiteral("true")) return new VerifyBoolean { Value = true };
            if (ReadLiteral("false")) return new VerifyBoolean { Value = false };
            if (ReadLiteral("null")) return new VerifyNull();
            throw new FormatException();
        }

        private VerifyObject ParseObject()
        {
            VerifyObject value = new VerifyObject();
            _index++;
            SkipWhitespace();
            if (Take('}')) return value;
            while (true)
            {
                if (_index >= _text.Length || _text[_index] != '"') throw new FormatException();
                string key = ParseString();
                SkipWhitespace();
                Require(':');
                SkipWhitespace();
                value.Values.Add(key, ParseValue());
                SkipWhitespace();
                if (Take('}')) return value;
                Require(',');
                SkipWhitespace();
            }
        }

        private VerifyArray ParseArray()
        {
            VerifyArray value = new VerifyArray();
            _index++;
            SkipWhitespace();
            if (Take(']')) return value;
            while (true)
            {
                value.Values.Add(ParseValue());
                SkipWhitespace();
                if (Take(']')) return value;
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
                if (current == '"') return builder.ToString();
                if (current != '\\')
                {
                    builder.Append(current);
                    continue;
                }
                if (_index >= _text.Length) throw new FormatException();
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
            if (_index + 4 > _text.Length) throw new FormatException();
            int value = 0;
            for (int offset = 0; offset < 4; offset++)
            {
                char current = _text[_index++];
                int digit;
                if (current >= '0' && current <= '9') digit = current - '0';
                else if (current >= 'A' && current <= 'F') digit = current - 'A' + 10;
                else if (current >= 'a' && current <= 'f') digit = current - 'a' + 10;
                else throw new FormatException();
                value = checked(value * 16 + digit);
            }
            return value;
        }

        private long ParseInteger()
        {
            int start = _index;
            while (_index < _text.Length && _text[_index] >= '0' && _text[_index] <= '9') _index++;
            return long.Parse(_text.Substring(start, _index - start), NumberStyles.None, CultureInfo.InvariantCulture);
        }

        private bool ReadLiteral(string value)
        {
            if (_index + value.Length > _text.Length || !string.Equals(_text.Substring(_index, value.Length), value, StringComparison.Ordinal)) return false;
            _index += value.Length;
            return true;
        }

        private void Require(char expected)
        {
            if (_index >= _text.Length || _text[_index] != expected) throw new FormatException();
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
                if (current != ' ' && current != '\t' && current != '\r' && current != '\n') return;
                _index++;
            }
        }
    }

    public static class FoundationVerifier
    {
        private const string CatalogSha256 = "e2a43c2e4b17b24c158a9510eeba68bdc2b6e30c00267797a8ed6c100a894100";
        private const string MapSha256 = "b684584b7cbcc7ece6307d75bc81c2f4681f9c1f458f3b6505f40cee01fd24c6";
        private const string SchemaSha256 = "4a1e7e43450dda8d4c19964f4e765f044204745bd6e1290dd840a02014a4676f";

        public static FoundationVerifyResult Verify(byte[] catalogBytes, byte[] schemaBytes, byte[] mapBytes, byte[] metaBytes)
        {
            if (catalogBytes == null || schemaBytes == null || mapBytes == null || metaBytes == null)
            {
                throw new ArgumentNullException("catalogBytes");
            }
            SchemaCheckResult catalogJson = SchemaBootstrap.Evaluate("json", catalogBytes, null);
            SchemaCheckResult schemaJson = SchemaBootstrap.Evaluate("json", schemaBytes, null);
            SchemaCheckResult mapJson = SchemaBootstrap.Evaluate("json", mapBytes, null);
            if (!catalogJson.Accepted) return new FoundationVerifyResult(false, catalogJson.Reason);
            if (!schemaJson.Accepted) return new FoundationVerifyResult(false, schemaJson.Reason);
            if (!mapJson.Accepted) return new FoundationVerifyResult(false, mapJson.Reason);
            SchemaCheckResult schemaAgainstMeta = SchemaBootstrap.Evaluate("schema-against-meta", schemaBytes, metaBytes);
            if (!schemaAgainstMeta.Accepted) return new FoundationVerifyResult(false, schemaAgainstMeta.Reason);
            VerifyObject catalog;
            VerifyObject schema;
            VerifyArray map;
            try
            {
                catalog = new VerifyJsonParser(catalogBytes).Parse() as VerifyObject;
                schema = new VerifyJsonParser(schemaBytes).Parse() as VerifyObject;
                map = new VerifyJsonParser(mapBytes).Parse() as VerifyArray;
            }
            catch
            {
                return new FoundationVerifyResult(false, "parse-failure");
            }
            if (!ValidateCatalog(catalog) || !ValidateSchema(schema) || !ValidateMap(map))
            {
                return new FoundationVerifyResult(false, "shape-mismatch");
            }
            if (!EqualSha(catalogBytes, CatalogSha256) || !EqualSha(schemaBytes, SchemaSha256) || !EqualSha(mapBytes, MapSha256))
            {
                return new FoundationVerifyResult(false, "oracle-mismatch");
            }
            return new FoundationVerifyResult(true, "ok");
        }

        private static bool ValidateCatalog(VerifyObject catalog)
        {
            if (!ExactKeys(catalog, new string[] { "entries", "schemaId", "schemaVersion", "space" })) return false;
            return IntegerEquals(catalog, "schemaVersion", 1)
                && StringEquals(catalog, "schemaId", "PspktFoundationCatalogV1")
                && StringEquals(catalog, "space", "foundation")
                && catalog.Values["entries"] is VerifyArray;
        }

        private static bool ValidateSchema(VerifyObject schema)
        {
            if (!ExactKeys(schema, new string[] { "schemaId", "schemaVersion", "types" })) return false;
            VerifyArray types = schema.Values["types"] as VerifyArray;
            return IntegerEquals(schema, "schemaVersion", 1)
                && StringEquals(schema, "schemaId", "PspktFoundationSchemaV1")
                && types != null
                && types.Values.Count > 0;
        }

        private static bool ValidateMap(VerifyArray map)
        {
            if (map == null || map.Values.Count == 0) return false;
            for (int index = 0; index < map.Values.Count; index++)
            {
                VerifyObject row = map.Values[index] as VerifyObject;
                string category;
                if (row == null || !TryString(row, "category", out category)) return false;
                List<string> required = new List<string>(new string[] { "catalogOrdinal", "category", "generatedId", "name", "schemaId" });
                if (category == "kind") required.Add("channel");
                else if (category == "enum-member") required.Add("memberIndex");
                else if (category == "union-branch") required.Add("branchIndex");
                else if (category != "type" && category != "field") return false;
                if (!ExactKeys(row, required.ToArray())) return false;
                if (!StringEquals(row, "schemaId", "PspktFoundationIdMapV1")) return false;
                long ordinal;
                long generatedId;
                string name;
                if (!TryInteger(row, "catalogOrdinal", out ordinal) || ordinal < 1
                    || !TryInteger(row, "generatedId", out generatedId) || generatedId < 0 || generatedId > 65535
                    || !TryString(row, "name", out name) || name.Length == 0) return false;
            }
            return true;
        }

        private static bool ExactKeys(VerifyObject value, string[] expected)
        {
            if (value == null || value.Values.Count != expected.Length) return false;
            for (int index = 0; index < expected.Length; index++)
            {
                if (!value.Values.ContainsKey(expected[index])) return false;
            }
            return true;
        }

        private static bool IntegerEquals(VerifyObject value, string key, long expected)
        {
            long actual;
            return TryInteger(value, key, out actual) && actual == expected;
        }

        private static bool StringEquals(VerifyObject value, string key, string expected)
        {
            string actual;
            return TryString(value, key, out actual) && string.Equals(actual, expected, StringComparison.Ordinal);
        }

        private static bool TryInteger(VerifyObject value, string key, out long result)
        {
            result = 0;
            VerifyNode node;
            if (!value.Values.TryGetValue(key, out node)) return false;
            VerifyInteger integer = node as VerifyInteger;
            if (integer == null) return false;
            result = integer.Value;
            return true;
        }

        private static bool TryString(VerifyObject value, string key, out string result)
        {
            result = null;
            VerifyNode node;
            if (!value.Values.TryGetValue(key, out node)) return false;
            VerifyString text = node as VerifyString;
            if (text == null) return false;
            result = text.Value;
            return true;
        }

        private static bool EqualSha(byte[] bytes, string expected)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                for (int index = 0; index < hash.Length; index++)
                {
                    builder.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
                }
                return string.Equals(builder.ToString(), expected, StringComparison.Ordinal);
            }
        }
    }
}
