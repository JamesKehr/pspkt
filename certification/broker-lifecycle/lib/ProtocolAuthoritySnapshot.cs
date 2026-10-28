using System;
using System.Collections.Generic;
using System.Globalization;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class ProtocolAuthoritySnapshot
    {
        private const string ReadyDigest = "fee195e7a19a9502330b3e2691c53258130dfbb0b5c1b40eb2a5f81bfdbca24c";
        private const string SourceIdentityDigest = "d502c9e20a4f7107134edeb56ed655faa457e8f1bfc0e8ad1e5b313e914a605b";
        private static readonly string[] Digests = new string[]
        {
            "ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85",
            "d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f",
            "6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4",
            "031bf566279871cd79db696ff436aa6d9383f1bb26a62467c3364880a012c5af",
            "66884fb48fcd5ebc3949957c57906614ce3d0d3a6644c6808b1d1796afb45c91",
            "9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312",
            "9f00101faf660e1ea3c10904a6358ae16fe1bef4577c0e05f1af9fea86357213",
            "ae2a255f0a45f9a33fe958e9c728ff535550ea09aec8fcf11398f426f56f0a0f"
        };
        private readonly byte[][] _sources;
        private readonly byte[] _protocolMetaDigest;
        private readonly byte[] _protocolSchemaDigest;
        private readonly Dictionary<string, string> _associations = new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly HashSet<string> _ordinaryAssociations = new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string, Dictionary<string, object>> _types = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);

        private ProtocolAuthoritySnapshot(byte[][] sources)
        {
            _sources = sources;
            _protocolMetaDigest = BrokerLifecycleFailure.Hash(sources[0]);
            _protocolSchemaDigest = BrokerLifecycleFailure.Hash(sources[2]);
            ProjectClosure();
        }

        internal static ProtocolAuthoritySnapshot Admit(byte[][] sources)
        {
            if (sources == null || sources.Length != 9)
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            byte[][] retained = new byte[sources.Length][];
            long total = 0;
            for (int index = 0; index < sources.Length; index++)
            {
                if (sources[index] == null)
                {
                    throw BrokerLifecycleFailure.Argument("argument:null");
                }
                total += sources[index].Length;
                if (sources[index].Length == 0 ||
                    sources[index].Length > BrokerLifecycleFailure.MaximumAuthorityFileBytes ||
                    total > BrokerLifecycleFailure.MaximumAuthorityBytes)
                {
                    throw BrokerLifecycleFailure.Reject("authority:length");
                }
                retained[index] = (byte[])sources[index].Clone();
                if (index < Digests.Length &&
                    !string.Equals(BrokerLifecycleFailure.Hex(BrokerLifecycleFailure.Hash(retained[index])),
                        Digests[index], StringComparison.Ordinal))
                {
                    throw BrokerLifecycleFailure.Reject("authority:pin");
                }
            }
            if (!SchemaBootstrap.Evaluate("bootstrap-meta", retained[0], null).Accepted ||
                !SchemaBootstrap.Evaluate("schema-against-meta", retained[2], retained[0]).Accepted)
            {
                throw BrokerLifecycleFailure.Reject("authority:gate");
            }
            foreach (int index in new int[] { 1, 3, 4, 5 })
            {
                if (!SchemaBootstrap.Evaluate("json", retained[index], null).Accepted)
                {
                    throw BrokerLifecycleFailure.Reject("authority:gate");
                }
            }
            AuthorityJsonReader.Object(AuthorityJsonReader.Parse(retained[6]));
            Dictionary<string, object> addendum = AuthorityJsonReader.Object(AuthorityJsonReader.Parse(retained[7]));
            AuthorityJsonReader.RequireKeys(addendum, new string[]
            {
                "schemaId", "schemaVersion", "trustCeiling", "sourceStatus", "sourceClassificationBasis",
                "sourceIdentities", "reviewPolicy", "baseSelection", "clauses"
            });
            if (!object.Equals(addendum["trustCeiling"], BrokerLifecycleFailure.TrustCeiling) ||
                !object.Equals(addendum["sourceStatus"], "IdentityOnlyUnverified"))
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            AdmitActivation(retained[8], BrokerLifecycleFailure.Hex(BrokerLifecycleFailure.Hash(retained[7])));
            return new ProtocolAuthoritySnapshot(retained);
        }

        internal byte[] CopyProtocolMetaDigest()
        {
            return (byte[])_protocolMetaDigest.Clone();
        }

        internal byte[] CopyProtocolSchemaDigest()
        {
            return (byte[])_protocolSchemaDigest.Clone();
        }

        internal Dictionary<string, object> ReadDocument(int index)
        {
            if (index < 0 || index >= _sources.Length)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            return AuthorityJsonReader.Object(AuthorityJsonReader.Parse(_sources[index]));
        }

        internal string ResolvePayloadRoot(string channel, string direction, ushort kind)
        {
            string root;
            if (_associations.TryGetValue(AssociationKey(channel, direction, kind), out root))
            {
                return root;
            }
            string suffix = "\0" + kind.ToString(CultureInfo.InvariantCulture);
            foreach (string key in _associations.Keys)
            {
                if (key.StartsWith(channel + "\0", StringComparison.Ordinal) && key.EndsWith(suffix, StringComparison.Ordinal))
                {
                    throw BrokerLifecycleFailure.Reject("frame:direction");
                }
            }
            throw BrokerLifecycleFailure.Reject("frame:kind-unavailable");
        }

        internal Dictionary<string, object> TypeDefinition(string name)
        {
            Dictionary<string, object> definition;
            if (!_types.TryGetValue(name, out definition))
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            return definition;
        }

        internal bool IsOrdinary(DecodedControlFrame frame)
        {
            return _ordinaryAssociations.Contains(AssociationKey(frame.Channel, frame.Direction, frame.Kind));
        }

        internal bool IsNamedType(string name)
        {
            return _types.ContainsKey(name);
        }

        private static string AssociationKey(string channel, string direction, ushort kind)
        {
            return channel + "\0" + direction + "\0" + kind.ToString(CultureInfo.InvariantCulture);
        }

        private void AddClosure(Dictionary<string, Dictionary<string, object>> declarations, string name, HashSet<string> primitives)
        {
            if (_types.ContainsKey(name))
            {
                return;
            }
            Dictionary<string, object> definition;
            if (!declarations.TryGetValue(name, out definition) || !object.Equals(definition["production"], "Named"))
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            _types.Add(name, definition);
            foreach (object value in (object[])definition["fields"])
            {
                Dictionary<string, object> field = AuthorityJsonReader.Object(value);
                string type = (string)field["type"];
                if (declarations.ContainsKey(type))
                {
                    AddClosure(declarations, type, primitives);
                }
                else
                {
                    primitives.Add(type);
                }
            }
        }

        private void ProjectClosure()
        {
            Dictionary<string, Dictionary<string, object>> declarations = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            object[] allTypes = (object[])ReadDocument(2)["types"];
            int namedCount = 0;
            int enumCount = 0;
            foreach (object value in allTypes)
            {
                Dictionary<string, object> definition = AuthorityJsonReader.Object(value);
                declarations.Add((string)definition["name"], definition);
                if (object.Equals(definition["production"], "Named"))
                {
                    namedCount++;
                }
                else if (object.Equals(definition["production"], "EnumU16"))
                {
                    enumCount++;
                }
            }
            HashSet<string> roots = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> primitives = new HashSet<string>(StringComparer.Ordinal);
            foreach (object value in (object[])ReadDocument(3)["rows"])
            {
                Dictionary<string, object> row = AuthorityJsonReader.Object(value);
                string channel = (string)row["channel"];
                if (channel != "BrokerControl" && channel != "LocalIpc")
                {
                    continue;
                }
                if (!object.Equals(row["profile"], "NonInteractiveElevated"))
                {
                    throw BrokerLifecycleFailure.Reject("authority:shape");
                }
                string root = (string)row["payloadRoot"];
                string key = AssociationKey(channel, (string)row["direction"], checked((ushort)(ulong)row["kindId"]));
                _associations.Add(key, root);
                if (object.Equals(row["mandatoryTailClass"], "Ordinary"))
                {
                    _ordinaryAssociations.Add(key);
                }
                roots.Add(root);
                AddClosure(declarations, root, primitives);
            }
            string[] expectedTypes = new string[]
            {
                "BootstrapBrokerContext", "BootstrapBrokerFinished", "BootstrapBrokerHello", "BrokerBootstrapHostHello",
                "BrokerFailure", "BrokerMintDeadlineAuthorizationV1", "BrokerMintInstallSampleV1",
                "BrokerSessionKeyCertificateBodyV1", "BrokerSessionKeyCertificateEnvelopeV1", "Keepalive", "LocalFailure",
                "LocalHelloB", "LocalHelloW", "LocalKeepalive", "LocalTranscriptChunkV1", "LocalTranscriptRootAcceptedV1",
                "LocalTranscriptRootV1", "MintRequest", "MintResult", "TokenMintAuthorizationBodyV1"
            };
            string[] expectedPrimitives = new string[]
            {
                "U8", "U16", "U32", "U64", "FILETIME", "QPC", "GUID", "SHA-256", "Opaque32",
                "AsciiIdentifier", "BinarySid", "Rsa3072PublicBlob", "Rsa3072Signature", "BoundedBytes"
            };
            if (allTypes.Length != 107 || namedCount != 100 || enumCount != 7 || _associations.Count != 22 ||
                roots.Count != 18 || _types.Count != expectedTypes.Length || !primitives.SetEquals(expectedPrimitives))
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            foreach (string name in expectedTypes)
            {
                if (!_types.ContainsKey(name))
                {
                    throw BrokerLifecycleFailure.Reject("authority:shape");
                }
            }
        }

        private static void AdmitActivation(byte[] bytes, string addendumDigest)
        {
            if (bytes.Length > 65536)
            {
                throw BrokerLifecycleFailure.Reject("authority:length");
            }
            Dictionary<string, object> document = AuthorityJsonReader.Object(AuthorityJsonReader.Parse(bytes));
            AuthorityJsonReader.RequireKeys(document, new string[]
            {
                "schemaId", "schemaVersion", "addendumSha256", "sourceIdentitySetSha256", "activation", "reviewers"
            });
            if (object.Equals(document["activation"], "Pending"))
            {
                throw BrokerLifecycleFailure.Reject("authority:design-review-pending");
            }
            if (!object.Equals(document["schemaId"], "PspktBrokerLifecycleDesignReviewActivationV1") ||
                !object.Equals(document["schemaVersion"], (ulong)1) ||
                !object.Equals(document["activation"], "UnanimousDESIGN_READY") ||
                !object.Equals(document["addendumSha256"], addendumDigest) ||
                !object.Equals(document["sourceIdentitySetSha256"], SourceIdentityDigest))
            {
                throw BrokerLifecycleFailure.Reject("authority:design-review-binding");
            }
            object[] reviewers = document["reviewers"] as object[];
            if (reviewers == null || reviewers.Length != 2)
            {
                throw BrokerLifecycleFailure.Reject("authority:design-review-binding");
            }
            string[] names = new string[] { "Claude Opus 5.5", "Grok 4.7" };
            string[] evidence = new string[]
            {
                "b52563460c3f27021d038d322cf42fc6766b0706f84d006ecfdadebb737467ca",
                "726d22fb373370082a8fcf2fd1fadb377ad1e92abaf1f3e2f100e419be56e402"
            };
            for (int index = 0; index < reviewers.Length; index++)
            {
                Dictionary<string, object> reviewer = AuthorityJsonReader.Object(reviewers[index]);
                AuthorityJsonReader.RequireKeys(reviewer, new string[] { "name", "verdict", "evidenceSha256" });
                if (!object.Equals(reviewer["name"], names[index]) ||
                    !object.Equals(reviewer["verdict"], "DESIGN_READY") ||
                    !object.Equals(reviewer["evidenceSha256"], evidence[index]))
                {
                    throw BrokerLifecycleFailure.Reject("authority:design-review-binding");
                }
            }
            if (!string.Equals(BrokerLifecycleFailure.Hex(BrokerLifecycleFailure.Hash(bytes)), ReadyDigest, StringComparison.Ordinal))
            {
                throw BrokerLifecycleFailure.Reject("authority:design-review-binding");
            }
        }
    }
}
