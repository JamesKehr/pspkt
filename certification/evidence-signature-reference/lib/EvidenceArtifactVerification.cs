using System;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    public sealed class EvidenceArtifactVerification
    {
        private readonly int _inputIndex;
        private readonly ushort _kind;
        private readonly Guid _artifactId;
        private readonly byte _profile;
        private readonly byte[] _payloadDigest;
        private readonly byte[] _verifiedKeyId;
        private readonly string[] _verifiedClaims;
        private readonly string[] _uncheckedSemantics;

        internal EvidenceArtifactVerification(int inputIndex, ushort kind, Guid artifactId,
            byte profile, byte[] payloadDigest, byte[] verifiedKeyId, string[] verifiedClaims,
            string[] uncheckedSemantics)
        {
            _inputIndex = inputIndex;
            _kind = kind;
            _artifactId = artifactId;
            _profile = profile;
            _payloadDigest = (byte[])payloadDigest.Clone();
            _verifiedKeyId = (byte[])verifiedKeyId.Clone();
            _verifiedClaims = (string[])verifiedClaims.Clone();
            _uncheckedSemantics = (string[])uncheckedSemantics.Clone();
        }

        public int InputIndex { get { return _inputIndex; } }
        public ushort Kind { get { return _kind; } }
        public Guid ArtifactId { get { return _artifactId; } }
        public byte Profile { get { return _profile; } }
        public byte[] PayloadDigest { get { return (byte[])_payloadDigest.Clone(); } }
        public byte[] VerifiedKeyId { get { return (byte[])_verifiedKeyId.Clone(); } }
        public string[] VerifiedClaims { get { return (string[])_verifiedClaims.Clone(); } }
        public string[] UncheckedSemantics { get { return (string[])_uncheckedSemantics.Clone(); } }
    }
}
