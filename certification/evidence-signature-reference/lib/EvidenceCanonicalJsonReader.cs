using System;
using System.Collections.Generic;
using System.Text;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class EvidenceCanonicalJsonReader
    {
        private const int MaximumNodes = 4096;
        private const int MaximumStringBytes = 1024;
        private const int MaximumPropertyBytes = 64;
        private const int MaximumArrayItems = 128;
        private readonly byte[] _bytes;
        private readonly int _maximumDepth;
        private int _position;
        private int _nodes;

        private EvidenceCanonicalJsonReader(byte[] bytes, int maximumDepth)
        {
            _bytes = bytes;
            _maximumDepth = maximumDepth;
        }

        internal static EvidenceJsonValue Read(byte[] bytes, int maximumDepth)
        {
            EvidenceCanonicalJsonReader reader = new EvidenceCanonicalJsonReader(bytes, maximumDepth);
            EvidenceJsonValue value = reader.ReadValue(1);
            if(reader._position != bytes.Length) { throw EvidenceFailure.Reject("snapshot:json"); }
            return value;
        }

        internal static void RequireObject(EvidenceJsonValue value, string[] names, string kinds)
        {
            if(value.Kind != 'o' || value.Names.Count != names.Length) { throw EvidenceFailure.Reject("snapshot:properties"); }
            HashSet<string> found = new HashSet<string>(StringComparer.Ordinal);
            foreach(string name in value.Names)
            {
                if(!found.Add(name) || Array.IndexOf(names, name) < 0) { throw EvidenceFailure.Reject("snapshot:properties"); }
            }
            for(int index = 0; index < names.Length; index++)
            {
                if(value.Get(names[index]).Kind != kinds[index]) { throw EvidenceFailure.Reject("snapshot:properties"); }
            }
            for(int index = 0; index < names.Length; index++)
            {
                if(value.Names[index] != names[index]) { throw EvidenceFailure.Reject("snapshot:property-order"); }
            }
        }

        private EvidenceJsonValue ReadValue(int depth)
        {
            if(depth > _maximumDepth || ++_nodes > MaximumNodes) { throw EvidenceFailure.Reject("snapshot:json-bound"); }
            if(_position >= _bytes.Length) { throw EvidenceFailure.Reject("snapshot:json"); }
            byte token = _bytes[_position];
            if(token == 123 || token == 91)
            {
                _position++;
                bool isObject = token == 123;
                byte closing = isObject ? (byte)125 : (byte)93;
                List<string> names = new List<string>();
                List<EvidenceJsonValue> values = new List<EvidenceJsonValue>();
                if(_position < _bytes.Length && _bytes[_position] == closing)
                {
                    _position++;
                    return new EvidenceJsonValue(isObject ? 'o' : 'a', null, 0, names, values);
                }
                while(true)
                {
                    if(isObject)
                    {
                        names.Add(ReadString(MaximumPropertyBytes));
                        Require(58);
                    }
                    if(!isObject && values.Count == MaximumArrayItems) { throw EvidenceFailure.Reject("resource:key-count"); }
                    values.Add(ReadValue(depth + 1));
                    if(_position >= _bytes.Length) { throw EvidenceFailure.Reject("snapshot:json"); }
                    if(_bytes[_position] == closing) { _position++; break; }
                    Require(44);
                }
                return new EvidenceJsonValue(isObject ? 'o' : 'a', null, 0, names, values);
            }
            if(token == 34)
            {
                return new EvidenceJsonValue('s', ReadString(MaximumStringBytes), 0, null, null);
            }
            if(token == 45 || token == 43) { throw EvidenceFailure.Reject("snapshot:integer"); }
            if(token >= 48 && token <= 57)
            {
                int start = _position;
                ulong number = 0;
                while(_position < _bytes.Length && _bytes[_position] >= 48 && _bytes[_position] <= 57)
                {
                    ulong digit = (ulong)(_bytes[_position] - 48);
                    if(number > (ulong.MaxValue - digit) / 10) { throw EvidenceFailure.Reject("snapshot:integer"); }
                    number = number * 10 + digit;
                    _position++;
                }
                if(_position - start > 1 && token == 48) { throw EvidenceFailure.Reject("snapshot:integer"); }
                if(_position < _bytes.Length && (_bytes[_position] == 46 || _bytes[_position] == 101 ||
                    _bytes[_position] == 69 || _bytes[_position] == 43 || _bytes[_position] == 45))
                {
                    throw EvidenceFailure.Reject("snapshot:integer");
                }
                return new EvidenceJsonValue('n', null, number, null, null);
            }
            string literal = token == 116 ? "true" : token == 102 ? "false" : null;
            if(literal != null)
            {
                foreach(char character in literal) { Require((byte)character); }
                return new EvidenceJsonValue('b', literal, 0, null, null);
            }
            throw EvidenceFailure.Reject("snapshot:json");
        }

        private string ReadString(int maximum)
        {
            Require(34);
            int start = _position;
            while(_position < _bytes.Length && _bytes[_position] != 34)
            {
                byte value = _bytes[_position];
                if(value < 32 || value > 126 || value == 92) { throw EvidenceFailure.Reject("snapshot:json"); }
                _position++;
                if(_position - start > maximum) { throw EvidenceFailure.Reject("snapshot:json-bound"); }
            }
            int length = _position - start;
            Require(34);
            return Encoding.ASCII.GetString(_bytes, start, length);
        }

        private void Require(byte value)
        {
            if(_position >= _bytes.Length || _bytes[_position++] != value) { throw EvidenceFailure.Reject("snapshot:json"); }
        }
    }
}
