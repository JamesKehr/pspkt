using System;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    public sealed class EvidenceReferenceResolution
    {
        private readonly int _sourceInputIndex;
        private readonly ushort _sourceKind;
        private readonly ushort _sourceFieldId;
        private readonly byte[] _referenceDigest;
        private readonly int _targetInputIndex;
        private readonly ushort _targetKind;
        private readonly bool _sourceFieldCoveredByVerifiedSignature;
        private readonly string[] _matchedAssertions;

        internal EvidenceReferenceResolution(int sourceInputIndex, ushort sourceKind, ushort sourceFieldId,
            byte[] referenceDigest, int targetInputIndex, ushort targetKind,
            bool sourceFieldCoveredByVerifiedSignature, string[] matchedAssertions)
        {
            _sourceInputIndex = sourceInputIndex;
            _sourceKind = sourceKind;
            _sourceFieldId = sourceFieldId;
            _referenceDigest = (byte[])referenceDigest.Clone();
            _targetInputIndex = targetInputIndex;
            _targetKind = targetKind;
            _sourceFieldCoveredByVerifiedSignature = sourceFieldCoveredByVerifiedSignature;
            _matchedAssertions = (string[])matchedAssertions.Clone();
        }

        public int SourceInputIndex { get { return _sourceInputIndex; } }
        public ushort SourceKind { get { return _sourceKind; } }
        public ushort SourceFieldId { get { return _sourceFieldId; } }
        public byte[] ReferenceDigest { get { return (byte[])_referenceDigest.Clone(); } }
        public int TargetInputIndex { get { return _targetInputIndex; } }
        public ushort TargetKind { get { return _targetKind; } }
        public bool SourceFieldCoveredByVerifiedSignature { get { return _sourceFieldCoveredByVerifiedSignature; } }
        public string[] MatchedAssertions { get { return (string[])_matchedAssertions.Clone(); } }
    }
}
