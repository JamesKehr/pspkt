using System;
using System.IO;

namespace Pspkt.Certification.EvidenceRuntime
{
    public sealed class EvidenceArtifactEnvelopeCodec
    {
        private const int MaximumPayloadLength = 262143;
        private const int MaximumEnvelopeLength = MaximumPayloadLength + 85;
        private readonly EvidenceSchemaSnapshot _schema;

        private EvidenceArtifactEnvelopeCodec(EvidenceSchemaSnapshot schema)
        {
            _schema = schema;
        }

        public static EvidenceArtifactEnvelopeCodec CreateFromCommittedAuthorities(
            byte[] metaBytes, byte[] protocolInventoryBytes,
            byte[] evidenceSchemaBytes, byte[] evidenceInventoryBytes)
        {
            if (metaBytes == null) { throw new ArgumentNullException("metaBytes"); }
            if (protocolInventoryBytes == null) { throw new ArgumentNullException("protocolInventoryBytes"); }
            if (evidenceSchemaBytes == null) { throw new ArgumentNullException("evidenceSchemaBytes"); }
            if (evidenceInventoryBytes == null) { throw new ArgumentNullException("evidenceInventoryBytes"); }
            return new EvidenceArtifactEnvelopeCodec(EvidenceSchemaSnapshot.Create(
                metaBytes, protocolInventoryBytes, evidenceSchemaBytes, evidenceInventoryBytes));
        }

        public DecodedEvidenceArtifactEnvelope Decode(byte[] envelopeBytes)
        {
            if (envelopeBytes == null) { throw new ArgumentNullException("envelopeBytes"); }
            if (envelopeBytes.Length > MaximumEnvelopeLength) { throw new InvalidDataException("envelope-bound: Envelope exceeds the evidence cap."); }
            byte[] retained = (byte[])envelopeBytes.Clone();
            EvidenceTlvCursor cursor = new EvidenceTlvCursor(retained);
            byte[] kindBytes = cursor.ReadField(1, 2, 2);
            byte[] identifierBytes = cursor.ReadField(2, 16, 16);
            byte[] profileBytes = cursor.ReadField(3, 1, 1);
            ushort kind = (ushort)((kindBytes[0] << 8) | kindBytes[1]);
            byte profile = profileBytes[0];
            RequireProfile(profile);
            string domain = _schema.GetDomain(kind);
            int maximumPayloadLength = checked((int)_schema.GetMaximumPayloadLength(kind, profile));
            byte[] boundedPayload = cursor.ReadField(4, 4, checked(4 + maximumPayloadLength));
            byte[] digest = cursor.ReadField(5, 32, 32);
            if (!cursor.AtEnd) { throw new InvalidDataException("tlv-trailing: Envelope contains trailing data."); }
            uint payloadLength = EvidenceTlvCursor.ReadUInt32(boundedPayload, 0);
            if (payloadLength != (uint)(boundedPayload.Length - 4) || payloadLength > MaximumPayloadLength)
            {
                throw new InvalidDataException("payload-bound: Payload length differs.");
            }
            byte[] payload = new byte[(int)payloadLength];
            Buffer.BlockCopy(boundedPayload, 4, payload, 0, payload.Length);
            EvidencePayloadCodec.Validate(_schema, kind, profile, payload);
            byte[] expectedDigest = EvidenceSignatureContract.ComputePayloadDigest(domain, payload);
            int difference = 0;
            for (int index = 0; index < digest.Length; index++) { difference |= digest[index] ^ expectedDigest[index]; }
            if (difference != 0) { throw new InvalidDataException("payload-digest: Content digest differs."); }
            Array.Reverse(identifierBytes, 0, 4);
            Array.Reverse(identifierBytes, 4, 2);
            Array.Reverse(identifierBytes, 6, 2);
            return new DecodedEvidenceArtifactEnvelope(kind, new Guid(identifierBytes), profile,
                payload, digest, EvidenceSignatureContract.GetUncheckedSemantics(kind));
        }

        public byte[] Encode(ushort kind, Guid artifactId, byte profile, byte[] canonicalPayloadBytes)
        {
            if (canonicalPayloadBytes == null) { throw new ArgumentNullException("canonicalPayloadBytes"); }
            if (canonicalPayloadBytes.Length > MaximumPayloadLength) { throw new InvalidDataException("payload-bound: Payload exceeds the evidence cap."); }
            RequireProfile(profile);
            string domain = _schema.GetDomain(kind);
            if (canonicalPayloadBytes.Length > _schema.GetMaximumPayloadLength(kind, profile))
            {
                throw new InvalidDataException("tlv-payload-bound: Payload exceeds its evidence kind bound.");
            }
            byte[] payload = (byte[])canonicalPayloadBytes.Clone();
            EvidencePayloadCodec.Validate(_schema, kind, profile, payload);
            byte[] identifier = artifactId.ToByteArray();
            Array.Reverse(identifier, 0, 4);
            Array.Reverse(identifier, 4, 2);
            Array.Reverse(identifier, 6, 2);
            byte[] boundedPayload = new byte[4 + payload.Length];
            EvidenceTlvCursor.WriteUInt32(boundedPayload, 0, (uint)payload.Length);
            Buffer.BlockCopy(payload, 0, boundedPayload, 4, payload.Length);
            using (MemoryStream stream = new MemoryStream())
            {
                EvidenceTlvCursor.WriteField(stream, 1, new byte[] { (byte)(kind >> 8), (byte)kind });
                EvidenceTlvCursor.WriteField(stream, 2, identifier);
                EvidenceTlvCursor.WriteField(stream, 3, new byte[] { profile });
                EvidenceTlvCursor.WriteField(stream, 4, boundedPayload);
                EvidenceTlvCursor.WriteField(stream, 5, EvidenceSignatureContract.ComputePayloadDigest(domain, payload));
                return stream.ToArray();
            }
        }

        public byte[] GetDeclaredSignatureCoveredBytes(byte[] envelopeBytes)
        {
            DecodedEvidenceArtifactEnvelope envelope = Decode(envelopeBytes);
            return EvidenceSignatureContract.GetDeclaredCoveredBytes(envelope.Kind, _schema.GetDomain(envelope.Kind),
                envelope.CanonicalPayload);
        }

        private static void RequireProfile(byte profile)
        {
            if (profile != 1 && profile != 2) { throw new InvalidDataException("evidence-profile: Profile must be 1 or 2."); }
        }
    }
}
