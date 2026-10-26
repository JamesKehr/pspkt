using System;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    public sealed class EvidenceKeyBindingSnapshot
    {
        private readonly byte[] _snapshotSha256;
        private readonly ulong _evaluationTime;
        private readonly Guid _ledgerIdentity;
        private readonly byte[] _hostInventoryPolicyDigest;
        private readonly EvidenceKeyBinding[] _bindings;
        private readonly object _owner;
        private readonly byte[] _canonicalBytes;

        internal EvidenceKeyBindingSnapshot(object owner, byte[] canonicalBytes, byte[] snapshotSha256, ulong evaluationTime,
            Guid ledgerIdentity, byte[] hostInventoryPolicyDigest, EvidenceKeyBinding[] bindings)
        {
            _snapshotSha256 = (byte[])snapshotSha256.Clone();
            _evaluationTime = evaluationTime;
            _ledgerIdentity = ledgerIdentity;
            _hostInventoryPolicyDigest = (byte[])hostInventoryPolicyDigest.Clone();
            _bindings = (EvidenceKeyBinding[])bindings.Clone();
            _owner = owner;
            _canonicalBytes = (byte[])canonicalBytes.Clone();
        }

        public byte[] SnapshotSha256 { get { return (byte[])_snapshotSha256.Clone(); } }
        public ulong EvaluationTime { get { return _evaluationTime; } }
        public Guid LedgerIdentity { get { return _ledgerIdentity; } }
        public byte[] HostInventoryPolicyDigest { get { return (byte[])_hostInventoryPolicyDigest.Clone(); } }
        public int KeyCount { get { return _bindings.Length; } }

        internal EvidenceKeyBinding[] Bindings { get { return (EvidenceKeyBinding[])_bindings.Clone(); } }

        internal bool BelongsTo(object owner)
        {
            return object.ReferenceEquals(_owner, owner);
        }
    }
}
