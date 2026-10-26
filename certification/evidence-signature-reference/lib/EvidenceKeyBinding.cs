namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class EvidenceKeyBinding
    {
        internal readonly byte[] Identifier;
        internal readonly string Role;
        internal readonly ulong NotBefore;
        internal readonly ulong NotAfter;
        internal readonly CanonicalRsaPublicKey PublicKey;

        internal EvidenceKeyBinding(byte[] identifier, string role, ulong notBefore, ulong notAfter, CanonicalRsaPublicKey publicKey)
        {
            Identifier = (byte[])identifier.Clone();
            Role = role;
            NotBefore = notBefore;
            NotAfter = notAfter;
            PublicKey = publicKey;
        }
    }
}
