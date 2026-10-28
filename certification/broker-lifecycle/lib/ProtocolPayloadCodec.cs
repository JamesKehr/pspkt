using System;
using System.Collections.Generic;
using System.Numerics;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal static class ProtocolPayloadCodec
    {
        private const int MaximumDepth = 4;
        private const int MaximumAsciiBytes = 128;
        private const int MaximumSidSubAuthorities = 15;
        private const int MinimumPublicBlobBytes = 24;
        private const int MaximumPublicBlobBytes = 512;
        private const int MaximumFieldsAndElements = 8192;
        private const int MaximumCollectionItems = 4096;
        private const int MaximumLogicalBytes = 2097152;
        private const int LogicalBytesPerItem = 16;

        internal static void Validate(ProtocolAuthoritySnapshot authority, string root, byte[] payload)
        {
            Walk(authority, root, payload, null);
        }

        internal static void ValidateSignatureContext(ProtocolAuthoritySnapshot authority, string root, byte[] payload,
            string channelField, byte[] channelIdentifier, byte[] evidenceMetaDigest, byte[] evidenceSchemaDigest)
        {
            Dictionary<string, byte[]> expected = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            expected.Add(channelField, channelIdentifier);
            expected.Add("evidenceSchemaMetaDigest", evidenceMetaDigest);
            expected.Add("evidenceSchemaDigest", evidenceSchemaDigest);
            Walk(authority, root, payload, expected);
        }

        private static void Walk(ProtocolAuthoritySnapshot authority, string root, byte[] payload, Dictionary<string, byte[]> expected)
        {
            if (payload == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            ulong fieldAndElementCount = 0;
            ValidateLogicalBudget((ulong)payload.Length, fieldAndElementCount, 1, 0);
            Stack<NamedScope> scopes = new Stack<NamedScope>();
            scopes.Push(new NamedScope(authority.TypeDefinition(root), payload, 0, payload.Length, 1));
            while (scopes.Count != 0)
            {
                NamedScope scope = scopes.Peek();
                if (scope.NextField == scope.Fields.Length)
                {
                    if (scope.Cursor.Remaining != 0)
                    {
                        throw BrokerLifecycleFailure.Reject("payload:trailing");
                    }
                    scopes.Pop();
                    continue;
                }
                Dictionary<string, object> field = AuthorityJsonReader.Object(scope.Fields[scope.NextField++]);
                int offset;
                int length;
                scope.Cursor.ReadField(checked((ushort)(ulong)field["fieldId"]), out offset, out length);
                if (fieldAndElementCount == ulong.MaxValue)
                {
                    throw BrokerLifecycleFailure.Reject("payload:budget");
                }
                fieldAndElementCount++;
                ValidateLogicalBudget((ulong)payload.Length, fieldAndElementCount, scope.Depth, 0);
                string type = (string)field["type"];
                if (authority.IsNamedType(type))
                {
                    ValidateLogicalBudget((ulong)payload.Length, fieldAndElementCount, scope.Depth + 1, 0);
                    scopes.Push(new NamedScope(authority.TypeDefinition(type), payload, offset, length, scope.Depth + 1));
                }
                else
                {
                    ValidatePrimitive(authority, field, payload, offset, length);
                    byte[] contextValue;
                    string fieldName = (string)field["name"];
                    if (expected != null && expected.TryGetValue(fieldName, out contextValue) &&
                        !EqualSlice(payload, offset, length, contextValue))
                    {
                        string reason = "context:binding-shape";
                        if (fieldName == "evidenceSchemaMetaDigest")
                        {
                            reason = "context:evidence-schema-meta";
                        }
                        else if (fieldName == "evidenceSchemaDigest")
                        {
                            reason = "context:evidence-schema";
                        }
                        throw BrokerLifecycleFailure.Reject(reason);
                    }
                }
            }

        }

        internal static void ValidateLogicalBudget(ulong payloadBytes, ulong fieldAndElementCount, int depth, int collectionCount)
        {
            if (depth < 1 || depth > MaximumDepth || collectionCount < 0 || collectionCount > MaximumCollectionItems ||
                fieldAndElementCount > MaximumFieldsAndElements ||
                new BigInteger(payloadBytes) + new BigInteger(fieldAndElementCount) * LogicalBytesPerItem > MaximumLogicalBytes)
            {
                throw BrokerLifecycleFailure.Reject("payload:budget");
            }
        }

        private static bool EqualSlice(byte[] bytes, int offset, int length, byte[] expected)
        {
            if (length != expected.Length)
            {
                return false;
            }
            for (int index = 0; index < length; index++)
            {
                if (bytes[offset + index] != expected[index])
                {
                    return false;
                }
            }
            return true;
        }

        private static void ValidatePrimitive(ProtocolAuthoritySnapshot authority, Dictionary<string, object> field,
            byte[] bytes, int offset, int length)
        {
            string type = (string)field["type"];
            string name = (string)field["name"];
            int width = 0;
            switch (type)
            {
                case "U8": width = 1; break;
                case "U16": width = 2; break;
                case "U32": width = 4; break;
                case "U64":
                case "FILETIME":
                case "QPC": width = 8; break;
                case "GUID": width = 16; break;
                case "SHA-256":
                case "Opaque32": width = 32; break;
                case "Rsa3072Signature": width = FrameCodec.SignatureBytes; break;
                case "AsciiIdentifier":
                    if (length < 1 || length > MaximumAsciiBytes)
                    {
                        throw BrokerLifecycleFailure.Reject("payload:primitive");
                    }
                    for (int index = 0; index < length; index++)
                    {
                        byte value = bytes[offset + index];
                        if (!((value >= 65 && value <= 90) || (value >= 97 && value <= 122) ||
                            (value >= 48 && value <= 57) || value == 46 || value == 95 || value == 58 || value == 45))
                        {
                            throw BrokerLifecycleFailure.Reject("payload:primitive");
                        }
                    }
                    break;
                case "BinarySid":
                    if (length < 8 || bytes[offset] != 1 || bytes[offset + 1] > MaximumSidSubAuthorities ||
                        length != 8 + 4 * bytes[offset + 1])
                    {
                        throw BrokerLifecycleFailure.Reject("payload:primitive");
                    }
                    break;
                case "Rsa3072PublicBlob":
                    if (length < MinimumPublicBlobBytes || length > MaximumPublicBlobBytes)
                    {
                        throw BrokerLifecycleFailure.Reject("payload:primitive");
                    }
                    break;
                case "BoundedBytes":
                    if (length < 4 || FrameCodec.ReadUnsigned(bytes, offset, 4) != (ulong)(length - 4))
                    {
                        throw BrokerLifecycleFailure.Reject("payload:length");
                    }
                    if (!field.ContainsKey("maxBytes") || (ulong)(length - 4) > (ulong)field["maxBytes"])
                    {
                        throw BrokerLifecycleFailure.Reject("payload:primitive");
                    }
                    break;
                default: throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            if (width != 0 && length != width)
            {
                throw BrokerLifecycleFailure.Reject("payload:primitive");
            }
            if (name == "profile" && bytes[offset] != 2)
            {
                throw BrokerLifecycleFailure.Reject("frame:profile");
            }
            if (name == "protocolSchemaMetaDigest" &&
                !EqualSlice(bytes, offset, length, authority.CopyProtocolMetaDigest()))
            {
                throw BrokerLifecycleFailure.Reject("context:protocol-schema-meta");
            }
            if (name == "protocolSchemaDigest" &&
                !EqualSlice(bytes, offset, length, authority.CopyProtocolSchemaDigest()))
            {
                throw BrokerLifecycleFailure.Reject("context:protocol-schema");
            }
            if ((name == "expectedHostToBrokerOrigin" || name == "expectedBrokerToHostOrigin") &&
                FrameCodec.ReadUnsigned(bytes, offset, length) != 1)
            {
                throw BrokerLifecycleFailure.Reject("context:sequence-origin");
            }
        }

        private sealed class NamedScope
        {
            internal readonly int Depth;
            internal readonly object[] Fields;
            internal readonly TlvCursor Cursor;
            internal int NextField;

            internal NamedScope(Dictionary<string, object> definition, byte[] bytes, int offset, int length, int depth)
            {
                Depth = depth;
                Fields = (object[])definition["fields"];
                Cursor = new TlvCursor(bytes, offset, length);
            }
        }
    }
}
