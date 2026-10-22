using System;

namespace Pspkt.Certification.EvidenceRuntime
{
    public sealed class DecodedEvidenceArtifactEnvelope
    {
        private readonly ushort _kind;
        private readonly Guid _artifactId;
        private readonly byte _profile;
        private readonly byte[] _canonicalPayload;
        private readonly byte[] _payloadDigest;
        private readonly string[] _uncheckedSemantics;

        internal DecodedEvidenceArtifactEnvelope(ushort kind, Guid artifactId, byte profile,
            byte[] canonicalPayload, byte[] payloadDigest, string[] uncheckedSemantics)
        {
            _kind = kind;
            _artifactId = artifactId;
            _profile = profile;
            _canonicalPayload = (byte[])canonicalPayload.Clone();
            _payloadDigest = (byte[])payloadDigest.Clone();
            _uncheckedSemantics = (string[])uncheckedSemantics.Clone();
        }

        public ushort Kind { get { return _kind; } }
        public Guid ArtifactId { get { return _artifactId; } }
        public byte Profile { get { return _profile; } }
        public byte[] CanonicalPayload { get { return (byte[])_canonicalPayload.Clone(); } }
        public byte[] PayloadDigest { get { return (byte[])_payloadDigest.Clone(); } }
        public string[] UncheckedSemantics { get { return (string[])_uncheckedSemantics.Clone(); } }
    }
}
