using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class AuthorityJsonReader
    {
        private const int MaximumDepth = 32;
        private const int MaximumNodes = 100000;
        private const int MaximumStringCharacters = 65536;
        private readonly string _text;
        private int _position;
        private int _nodes;

        private AuthorityJsonReader(byte[] bytes)
        {
            if (bytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (bytes.Length == 0 || bytes.Length > BrokerLifecycleFailure.MaximumAuthorityFileBytes)
            {
                throw BrokerLifecycleFailure.Reject("authority:length");
            }
            try
            {
                _text = new UTF8Encoding(false, true).GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
        }

        internal static Dictionary<string, object> Object(object value)
        {
            Dictionary<string, object> result = value as Dictionary<string, object>;
            if (result == null)
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            return result;
        }

        internal static object Parse(byte[] bytes)
        {
            AuthorityJsonReader reader = new AuthorityJsonReader(bytes);
            object result = reader.ReadValue(1);
            reader.SkipWhitespace();
            if (reader._position != reader._text.Length)
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            return result;
        }

        internal static void RequireKeys(Dictionary<string, object> value, string[] keys)
        {
            if (value.Count != keys.Length)
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            foreach (string key in keys)
            {
                if (!value.ContainsKey(key))
                {
                    throw BrokerLifecycleFailure.Reject("authority:shape");
                }
            }
        }

        private char Current()
        {
            if (_position >= _text.Length)
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            return _text[_position];
        }

        private object ReadValue(int depth)
        {
            if (depth > MaximumDepth || ++_nodes > MaximumNodes)
            {
                throw BrokerLifecycleFailure.Reject("authority:length");
            }
            SkipWhitespace();
            char current = Current();
            if (current == '{')
            {
                _position++;
                Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
                SkipWhitespace();
                if (Current() == '}')
                {
                    _position++;
                    return result;
                }
                while (true)
                {
                    SkipWhitespace();
                    string key = ReadString();
                    if (result.ContainsKey(key))
                    {
                        throw BrokerLifecycleFailure.Reject("authority:shape");
                    }
                    Require(':');
                    result.Add(key, ReadValue(depth + 1));
                    SkipWhitespace();
                    char separator = Current();
                    _position++;
                    if (separator == '}')
                    {
                        return result;
                    }
                    if (separator != ',')
                    {
                        throw BrokerLifecycleFailure.Reject("authority:shape");
                    }
                }
            }
            if (current == '[')
            {
                _position++;
                List<object> result = new List<object>();
                SkipWhitespace();
                if (Current() == ']')
                {
                    _position++;
                    return result.ToArray();
                }
                while (true)
                {
                    result.Add(ReadValue(depth + 1));
                    SkipWhitespace();
                    char separator = Current();
                    _position++;
                    if (separator == ']')
                    {
                        return result.ToArray();
                    }
                    if (separator != ',')
                    {
                        throw BrokerLifecycleFailure.Reject("authority:shape");
                    }
                }
            }
            if (current == '"')
            {
                return ReadString();
            }
            if (current >= '0' && current <= '9')
            {
                int start = _position;
                ulong number = 0;
                while (_position < _text.Length && _text[_position] >= '0' && _text[_position] <= '9')
                {
                    ulong digit = (ulong)(_text[_position] - '0');
                    if (number > (ulong.MaxValue - digit) / 10)
                    {
                        throw BrokerLifecycleFailure.Reject("authority:shape");
                    }
                    number = number * 10 + digit;
                    _position++;
                }
                if (_position - start > 1 && current == '0')
                {
                    throw BrokerLifecycleFailure.Reject("authority:shape");
                }
                return number;
            }
            if (current == 't')
            {
                ReadLiteral("true");
                return true;
            }
            if (current == 'f')
            {
                ReadLiteral("false");
                return false;
            }
            if (current == 'n')
            {
                ReadLiteral("null");
                return null;
            }
            throw BrokerLifecycleFailure.Reject("authority:shape");
        }

        private void ReadLiteral(string literal)
        {
            foreach (char character in literal)
            {
                if (Current() != character)
                {
                    throw BrokerLifecycleFailure.Reject("authority:shape");
                }
                _position++;
            }
        }

        private string ReadString()
        {
            if (Current() != '"')
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            _position++;
            StringBuilder result = new StringBuilder();
            while (true)
            {
                char character = Current();
                _position++;
                if (character == '"')
                {
                    string value = result.ToString();
                    for (int index = 0; index < value.Length; index++)
                    {
                        if (char.IsHighSurrogate(value[index]))
                        {
                            if (++index == value.Length || !char.IsLowSurrogate(value[index]))
                            {
                                throw BrokerLifecycleFailure.Reject("authority:shape");
                            }
                        }
                        else if (char.IsLowSurrogate(value[index]))
                        {
                            throw BrokerLifecycleFailure.Reject("authority:shape");
                        }
                    }
                    return value;
                }
                if (character < 32)
                {
                    throw BrokerLifecycleFailure.Reject("authority:shape");
                }
                if (character == '\\')
                {
                    character = Current();
                    _position++;
                    switch (character)
                    {
                        case '"': break;
                        case '\\': break;
                        case '/': break;
                        case 'b': character = '\b'; break;
                        case 'f': character = '\f'; break;
                        case 'n': character = '\n'; break;
                        case 'r': character = '\r'; break;
                        case 't': character = '\t'; break;
                        case 'u':
                            if (_position > _text.Length - 4)
                            {
                                throw BrokerLifecycleFailure.Reject("authority:shape");
                            }
                            ushort codePoint;
                            if (!ushort.TryParse(_text.Substring(_position, 4), NumberStyles.AllowHexSpecifier,
                                CultureInfo.InvariantCulture, out codePoint))
                            {
                                throw BrokerLifecycleFailure.Reject("authority:shape");
                            }
                            _position += 4;
                            character = (char)codePoint;
                            break;
                        default: throw BrokerLifecycleFailure.Reject("authority:shape");
                    }
                }
                if (result.Length == MaximumStringCharacters)
                {
                    throw BrokerLifecycleFailure.Reject("authority:length");
                }
                result.Append(character);
            }
        }

        private void Require(char expected)
        {
            SkipWhitespace();
            if (Current() != expected)
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            _position++;
        }

        private void SkipWhitespace()
        {
            while (_position < _text.Length)
            {
                char character = _text[_position];
                if (character != ' ' && character != '\t' && character != '\r' && character != '\n')
                {
                    return;
                }
                _position++;
            }
        }
    }
}
