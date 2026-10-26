using System;
using System.IO;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    public sealed class EvidenceSetChecker
    {
        private const int MaximumEnvelopeCount = 256;
        private const int MaximumEnvelopeBytes = 262228;
        private const long MaximumAggregateBytes = 16777216;
        private readonly EvidenceAuthoritySnapshot _authorities;

        private EvidenceSetChecker(EvidenceAuthoritySnapshot authorities)
        {
            _authorities = authorities;
        }

        public static EvidenceSetChecker CreateFromCommittedAuthorities(
            byte[] metaBytes,
            byte[] protocolInventoryBytes,
            byte[] evidenceSchemaBytes,
            byte[] evidenceInventoryBytes,
            byte[] protocolSchemaBytes,
            byte[] trustedControlAuthorityBytes,
            byte[] trustRootsSchemaBytes,
            byte[] keyBindingSnapshotSchemaBytes,
            byte[] signatureReferencePolicyBytes)
        {
            try
            {
                return new EvidenceSetChecker(EvidenceAuthoritySnapshot.Create(new byte[][] {
                    metaBytes, protocolInventoryBytes, evidenceSchemaBytes, evidenceInventoryBytes,
                    protocolSchemaBytes, trustedControlAuthorityBytes, trustRootsSchemaBytes,
                    keyBindingSnapshotSchemaBytes, signatureReferencePolicyBytes
                }));
            }
            catch(Exception exception) { throw EvidenceFailure.Normalize(exception); }
        }

        public EvidenceKeyBindingSnapshot AdmitKeyBindings(byte[] canonicalKeyBindingBytes,
            byte[] expectedKeyBindingSha256, ulong evaluationTime, Guid expectedLedgerIdentity,
            byte[] expectedHostInventoryPolicyDigest)
        {
            try
            {
                return EvidenceKeyBindingReader.Read(_authorities, canonicalKeyBindingBytes, expectedKeyBindingSha256,
                    evaluationTime, expectedLedgerIdentity, expectedHostInventoryPolicyDigest);
            }
            catch(Exception exception) { throw EvidenceFailure.Normalize(exception); }
        }

        public EvidenceSetAssessment CheckSet(byte[][] envelopeBytes, EvidenceKeyBindingSnapshot keyBindings)
        {
            try
            {
                if(envelopeBytes == null || keyBindings == null) { throw new ArgumentException("argument:null"); }
                if(envelopeBytes.Length == 0) { throw new ArgumentException("argument:empty"); }
                if(envelopeBytes.Length > MaximumEnvelopeCount) { throw EvidenceFailure.Reject("resource:envelope-count"); }
                if(!keyBindings.BelongsTo(_authorities)) { throw EvidenceFailure.Reject("snapshot:owner-context"); }
                long totalBytes = 0;
                foreach(byte[] envelope in envelopeBytes)
                {
                    if(envelope == null) { throw new ArgumentException("argument:envelope-slot"); }
                    if(envelope.Length == 0) { throw new ArgumentException("argument:empty-envelope"); }
                    if(envelope.Length > MaximumEnvelopeBytes) { throw EvidenceFailure.Reject("resource:envelope-bytes"); }
                    checked { totalBytes += envelope.Length; }
                }
                if(totalBytes > MaximumAggregateBytes) { throw EvidenceFailure.Reject("resource:aggregate-bytes"); }
                DecodedStage decoded = DecodedStage.Create(_authorities, envelopeBytes);
                VerifiedStage verified = VerifiedStage.Create(_authorities, decoded, keyBindings);
                ResolvedStage resolved = ResolvedStage.Create(verified);
                return resolved.Assess(keyBindings, _authorities.PolicySha256);
            }
            catch(Exception exception) { throw EvidenceFailure.Normalize(exception); }
        }

        private sealed class DecodedStage
        {
            internal readonly EvidencePayloadProjection[] Packets;

            private DecodedStage(EvidencePayloadProjection[] packets) { Packets = packets; }

            internal static DecodedStage Create(EvidenceAuthoritySnapshot authorities, byte[][] envelopes)
            {
                return new DecodedStage(EvidencePayloadProjection.Decode(authorities.Codec, envelopes));
            }
        }

        private sealed class VerifiedStage
        {
            private readonly EvidencePayloadProjection[] _packets;

            private VerifiedStage(EvidencePayloadProjection[] packets) { _packets = packets; }

            internal EvidencePayloadProjection[] Packets { get { return (EvidencePayloadProjection[])_packets.Clone(); } }

            internal static VerifiedStage Create(EvidenceAuthoritySnapshot authorities, DecodedStage decoded,
                EvidenceKeyBindingSnapshot keys)
            {
                EvidenceSignatureVerifier.Verify(authorities.Codec, decoded.Packets, keys);
                foreach(EvidencePayloadProjection packet in decoded.Packets)
                {
                    if(packet.Kind != 16 && packet.Kind != 17) { continue; }
                    if(!EvidenceSignatureVerifier.Equal(packet.GetField(5), authorities.ProtocolSchemaSha256))
                    {
                        throw EvidenceFailure.Reject("schema:protocol-digest");
                    }
                    if(!EvidenceSignatureVerifier.Equal(packet.GetField(6), authorities.EvidenceSchemaSha256))
                    {
                        throw EvidenceFailure.Reject("schema:evidence-digest");
                    }
                }
                return new VerifiedStage(decoded.Packets);
            }
        }

        private sealed class ResolvedStage
        {
            private readonly EvidencePayloadProjection[] _packets;
            private readonly EvidenceResolvedReference[] _references;

            private ResolvedStage(EvidencePayloadProjection[] packets, EvidenceResolvedReference[] references)
            {
                _packets = packets;
                _references = references;
            }

            internal static ResolvedStage Create(VerifiedStage verified)
            {
                EvidencePayloadProjection[] packets = verified.Packets;
                EvidenceResolvedReference[] references = EvidenceReferenceResolver.Resolve(packets);
                return new ResolvedStage(packets, references);
            }

            internal EvidenceSetAssessment Assess(EvidenceKeyBindingSnapshot keys, byte[] policy)
            {
                byte[][] keyIds = new byte[_packets.Length][];
                string[][] claimRows = new string[_packets.Length][];
                string[][] residualRows = new string[_packets.Length][];
                for(int index = 0; index < _packets.Length; index++)
                {
                    EvidencePayloadProjection packet = _packets[index];
                    keyIds[index] = packet.HasDeclaredSignature ? packet.GetField(9) : new byte[0];
                    claimRows[index] = EvidenceClaimSet.GetArtifactClaims(packet.Kind);
                    residualRows[index] = EvidenceClaimSet.GetArtifactResiduals(packet);
                }
                EvidenceArtifactVerification[] artifacts = new EvidenceArtifactVerification[_packets.Length];
                for(int index = 0; index < _packets.Length; index++)
                {
                    EvidencePayloadProjection packet = _packets[index];
                    artifacts[index] = new EvidenceArtifactVerification(packet.InputIndex, packet.Kind, packet.ArtifactId,
                        packet.Profile, packet.PayloadDigest, keyIds[index], claimRows[index], residualRows[index]);
                }
                EvidenceReferenceResolution[] references = new EvidenceReferenceResolution[_references.Length];
                for(int index = 0; index < references.Length; index++)
                {
                    EvidenceResolvedReference reference = _references[index];
                    references[index] = new EvidenceReferenceResolution(reference.Source.InputIndex, reference.Source.Kind,
                        1, reference.Source.GetField(1), reference.Target.InputIndex, reference.Target.Kind,
                        reference.Source.Kind == 20, reference.Source.Kind == 20 ?
                            new string[] { "burned-logical-operation-id-equal", "burned-semantic-digest-equal" } :
                            new string[] { "successor-logical-operation-id-equal" });
                }
                return new EvidenceSetAssessment(keys, policy, artifacts, references, EvidenceClaimSet.GetSetResiduals(artifacts));
            }
        }
    }
}
