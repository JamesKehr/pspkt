using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Pspkt.Certification.EvidenceRuntime;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class EvidencePayloadProjection
    {
        private readonly byte[] _envelope;
        private readonly DecodedEvidenceArtifactEnvelope _decoded;
        private readonly Dictionary<ushort, byte[]> _fields;
        private readonly int _inputIndex;

        private EvidencePayloadProjection(int inputIndex, byte[] envelope, DecodedEvidenceArtifactEnvelope decoded)
        {
            _inputIndex = inputIndex;
            _envelope = envelope;
            _decoded = decoded;
            _fields = new Dictionary<ushort, byte[]>();
            if(Kind != 16 && Kind != 17 && Kind != 18 && Kind != 20 && Kind != 21) { return; }
            byte[] payload = decoded.CanonicalPayload;
            int offset = 0;
            while(offset < payload.Length)
            {
                if(payload.Length - offset < 6) { throw EvidenceFailure.Reject("runtime:projection"); }
                ushort tag = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                uint length = ((uint)payload[offset + 2] << 24) | ((uint)payload[offset + 3] << 16) |
                    ((uint)payload[offset + 4] << 8) | payload[offset + 5];
                if(length > payload.Length - offset - 6) { throw EvidenceFailure.Reject("runtime:projection"); }
                int requiredLength = RequiredFieldLength(Kind, tag);
                if(requiredLength != 0)
                {
                    if(length != requiredLength) { throw EvidenceFailure.Reject("runtime:projection"); }
                    byte[] value = new byte[requiredLength];
                    Buffer.BlockCopy(payload, offset + 6, value, 0, value.Length);
                    _fields.Add(tag, value);
                }
                offset += 6 + (int)length;
            }
            int expectedCount = Kind == 20 ? 6 : Kind == 16 || Kind == 17 ? 4 : 2;
            if(_fields.Count != expectedCount) { throw EvidenceFailure.Reject("runtime:projection"); }
        }

        internal int InputIndex { get { return _inputIndex; } }
        internal ushort Kind { get { return _decoded.Kind; } }
        internal Guid ArtifactId { get { return _decoded.ArtifactId; } }
        internal byte Profile { get { return _decoded.Profile; } }
        internal byte[] PayloadDigest { get { return _decoded.PayloadDigest; } }
        internal byte[] Envelope { get { return (byte[])_envelope.Clone(); } }
        internal string[] StructuralResiduals { get { return _decoded.UncheckedSemantics; } }
        internal bool HasDeclaredSignature { get { return Kind == 16 || Kind == 17 || Kind == 20; } }

        private static int RequiredFieldLength(ushort kind, ushort tag)
        {
            if(kind == 16 || kind == 17)
            {
                return tag == 10 ? 384 : tag == 5 || tag == 6 || tag == 9 ? 32 : 0;
            }
            if(kind == 18) { return tag == 1 ? 16 : tag == 2 ? 32 : 0; }
            if(kind == 20)
            {
                return tag == 10 ? 384 : tag == 2 || tag == 4 ? 16 : tag == 1 || tag == 3 || tag == 9 ? 32 : 0;
            }
            return tag == 1 ? 32 : tag == 2 ? 16 : 0;
        }

        internal byte[] GetField(ushort tag)
        {
            byte[] value;
            if(!_fields.TryGetValue(tag, out value)) { throw EvidenceFailure.Reject("runtime:projection"); }
            return (byte[])value.Clone();
        }

        internal static EvidencePayloadProjection[] Decode(EvidenceArtifactEnvelopeCodec codec, byte[][] envelopes)
        {
            byte[][] retained = new byte[envelopes.Length][];
            for(int index = 0; index < retained.Length; index++)
            {
                if(envelopes[index] == null) { throw new ArgumentException("argument:envelope-slot"); }
                retained[index] = (byte[])envelopes[index].Clone();
            }
            DecodedEvidenceArtifactEnvelope[] decoded = new DecodedEvidenceArtifactEnvelope[retained.Length];
            for(int index = 0; index < retained.Length; index++)
            {
                try { decoded[index] = codec.Decode(retained[index]); }
                catch(InvalidDataException) { throw EvidenceFailure.Reject("envelope:structure"); }
            }
            HashSet<string> contentKeys = new HashSet<string>(StringComparer.Ordinal);
            foreach(DecodedEvidenceArtifactEnvelope packet in decoded)
            {
                string key = packet.Kind.ToString(CultureInfo.InvariantCulture) + ":" + EvidenceFailure.Hex(packet.PayloadDigest);
                if(!contentKeys.Add(key)) { throw EvidenceFailure.Reject("envelope:duplicate-content"); }
            }
            EvidencePayloadProjection[] result = new EvidencePayloadProjection[retained.Length];
            for(int index = 0; index < result.Length; index++)
            {
                result[index] = new EvidencePayloadProjection(index, retained[index], decoded[index]);
            }
            return result;
        }
    }
}
