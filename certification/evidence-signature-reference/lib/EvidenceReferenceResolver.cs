using System;
using System.Collections.Generic;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal static class EvidenceReferenceResolver
    {
        internal static EvidenceResolvedReference[] Resolve(EvidencePayloadProjection[] packets)
        {
            List<EvidencePayloadProjection> sources = new List<EvidencePayloadProjection>();
            foreach(EvidencePayloadProjection source in packets)
            {
                if(source.Kind != 20 && source.Kind != 21) { continue; }
                sources.Add(source);
            }
            sources.Sort(delegate(EvidencePayloadProjection left, EvidencePayloadProjection right) {
                int kindOrder = left.Kind.CompareTo(right.Kind);
                return kindOrder != 0 ? kindOrder : left.InputIndex.CompareTo(right.InputIndex);
            });
            List<EvidenceResolvedReference> resolved = new List<EvidenceResolvedReference>();
            foreach(EvidencePayloadProjection source in sources)
            {
                ushort targetKind = source.Kind == 20 ? (ushort)18 : (ushort)20;
                byte[] referenceDigest = source.GetField(1);
                EvidencePayloadProjection target = null;
                foreach(EvidencePayloadProjection candidate in packets)
                {
                    if(candidate.Kind == targetKind && EvidenceSignatureVerifier.Equal(candidate.PayloadDigest, referenceDigest))
                    {
                        target = candidate;
                        break;
                    }
                }
                if(target == null) { throw EvidenceFailure.Reject("reference:target-missing"); }
                resolved.Add(new EvidenceResolvedReference(source, target));
            }
            EvidenceResolvedReference[] references = resolved.ToArray();
            foreach(EvidenceResolvedReference reference in references)
            {
                if(reference.Source.Kind == 20 &&
                    !EvidenceSignatureVerifier.Equal(reference.Source.GetField(2), reference.Target.GetField(1)))
                {
                    throw EvidenceFailure.Reject("reference:burned-operation");
                }
                if(reference.Source.Kind == 20 &&
                    !EvidenceSignatureVerifier.Equal(reference.Source.GetField(3), reference.Target.GetField(2)))
                {
                    throw EvidenceFailure.Reject("reference:burned-semantic");
                }
                if(reference.Source.Kind == 21 &&
                    !EvidenceSignatureVerifier.Equal(reference.Source.GetField(2), reference.Target.GetField(4)))
                {
                    throw EvidenceFailure.Reject("reference:successor-operation");
                }
            }
            return references;
        }
    }
}
