using System.Collections.Generic;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class EvidenceJsonValue
    {
        internal readonly char Kind;
        internal readonly string Text;
        internal readonly ulong Number;
        internal readonly List<string> Names;
        internal readonly List<EvidenceJsonValue> Values;

        internal EvidenceJsonValue(char kind, string text, ulong number,
            List<string> names, List<EvidenceJsonValue> values)
        {
            Kind = kind;
            Text = text;
            Number = number;
            Names = names;
            Values = values;
        }

        internal EvidenceJsonValue Get(string name)
        {
            if(Kind != 'o') { throw EvidenceFailure.Reject("snapshot:properties"); }
            int index = Names.IndexOf(name);
            if(index < 0) { throw EvidenceFailure.Reject("snapshot:properties"); }
            return Values[index];
        }
    }
}
