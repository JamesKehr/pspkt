using System;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    public sealed class EvidenceSetAssessment
    {
        private readonly EvidenceKeyBindingSnapshot _keyBindings;
        private readonly byte[] _policySha256;
        private readonly EvidenceArtifactVerification[] _artifacts;
        private readonly EvidenceReferenceResolution[] _references;
        private readonly string[] _uncheckedSemantics;

        internal EvidenceSetAssessment(EvidenceKeyBindingSnapshot keyBindings, byte[] policySha256,
            EvidenceArtifactVerification[] artifacts, EvidenceReferenceResolution[] references,
            string[] uncheckedSemantics)
        {
            _keyBindings = keyBindings;
            _policySha256 = (byte[])policySha256.Clone();
            _artifacts = (EvidenceArtifactVerification[])artifacts.Clone();
            _references = (EvidenceReferenceResolution[])references.Clone();
            _uncheckedSemantics = (string[])uncheckedSemantics.Clone();
        }

        public EvidenceKeyBindingSnapshot KeyBindings { get { return _keyBindings; } }
        public byte[] PolicySha256 { get { return (byte[])_policySha256.Clone(); } }
        public EvidenceArtifactVerification[] Artifacts { get { return (EvidenceArtifactVerification[])_artifacts.Clone(); } }
        public EvidenceReferenceResolution[] References { get { return (EvidenceReferenceResolution[])_references.Clone(); } }
        public string[] UncheckedSemantics { get { return (string[])_uncheckedSemantics.Clone(); } }
    }
}
