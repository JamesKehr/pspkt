namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class EvidenceResolvedReference
    {
        internal readonly EvidencePayloadProjection Source;
        internal readonly EvidencePayloadProjection Target;

        internal EvidenceResolvedReference(EvidencePayloadProjection source, EvidencePayloadProjection target)
        {
            Source = source;
            Target = target;
        }
    }
}
