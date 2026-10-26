using System;
using System.Collections.Generic;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal static class EvidenceClaimSet
    {
        private static readonly string[] Vocabulary = new string[] {
            "evidence-authenticity-unchecked", "artifact-id-unbound", "profile-authentication-unchecked", "profile-value-unbound",
            "signature-authentication-unchecked", "signature-key-binding-unchecked", "subject-digest-unchecked",
            "copied-protocol-digests-unchecked", "cross-envelope-references-unchecked", "freshness-unchecked",
            "ledger-record-references-unchecked", "schema-bindings-unchecked", "producer-digests-unchecked",
            "caller-pinned-key-provenance-unchecked", "key-enrollment-unchecked", "caller-time-eligibility-basis-unchecked",
            "reference-uniqueness-unchecked", "reference-timing-unchecked", "ledger-state-unchecked", "lifecycle-certification-unchecked"
        };
        private static readonly string[] StructuralCodes = new string[] {
            "ABCEFHJ", "ABCHJ", "ABCDEFHJ", "ABCHJ", "ABCHJ", "ABCHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ",
            "ABCDHJ", "ABCDHJ", "ABCHJ", "ABCHJ", "ABCEFHJ", "ABCDEFGJL", "ABCDEFGJL", "ABCDJKM", "ABCDJM", "ABCDEFIJM", "ABCDIJKM"
        };
        private static readonly string[] ResidualCodes = new string[] {
            "ABCEFHJST", "ABCHJST", "ABCDEFHJST", "ABCHJST", "ABCHJST", "ABCHJST", "ABCDHJST", "ABCDHJST",
            "ABCDHJST", "ABCDHJST", "ABCDHJST", "ABCDHJST", "ABCDHJST", "ABCHJST", "ABCHJST", "ABCEFHJST",
            "ABCDGJNOPST", "ABCDGJNOPST", "ABCDJKMQRST", "ABCDJMST", "ABCDJMNOPQRST", "ABCDJKMQRST"
        };
        private static readonly string[] DischargedCodes = new string[] {
            "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "EFL", "EFL", "", "", "EFI", "I"
        };
        private static readonly string[] AddedCodes = new string[] {
            "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST", "ST",
            "NOPST", "NOPST", "QRST", "ST", "NOPQRST", "QRST"
        };
        private static readonly string[] LocalClaims = new string[] {
            "signature-verified", "signature-key-binding-checked", "protocol-schema-bytes-bound", "evidence-schema-bytes-bound"
        };
        private static readonly string[] AuthorizationClaims = new string[] {
            "signature-verified", "signature-key-binding-checked", "cross-envelope-reference-resolved", "linked-assertions-equal"
        };
        private static readonly string[] ReceiptClaims = new string[] {
            "cross-envelope-reference-resolved", "linked-assertions-equal"
        };

        internal static string[] GetArtifactClaims(ushort kind)
        {
            if(kind == 16 || kind == 17) { return (string[])LocalClaims.Clone(); }
            if(kind == 20) { return (string[])AuthorizationClaims.Clone(); }
            if(kind == 21) { return (string[])ReceiptClaims.Clone(); }
            return new string[0];
        }

        internal static string[] GetArtifactResiduals(EvidencePayloadProjection packet)
        {
            if(packet.Kind >= ResidualCodes.Length) { throw EvidenceFailure.Reject("runtime:projection"); }
            if(!Equal(packet.StructuralResiduals, Expand(StructuralCodes[packet.Kind])))
            {
                throw EvidenceFailure.Reject("runtime:projection");
            }
            return Expand(ResidualCodes[packet.Kind]);
        }

        internal static string[] GetSetResiduals(EvidenceArtifactVerification[] artifacts)
        {
            List<string> residuals = new List<string>();
            foreach(string token in Vocabulary)
            {
                if(Array.Exists(artifacts, delegate(EvidenceArtifactVerification artifact) {
                    return Array.IndexOf(artifact.UncheckedSemantics, token) >= 0;
                }))
                {
                    residuals.Add(token);
                }
            }
            return residuals.ToArray();
        }

        internal static void RequirePolicyAgreement(EvidenceJsonValue policy)
        {
            EvidenceJsonValue vocabulary = policy.Get("uncheckedTokens");
            if(vocabulary.Kind != 'a' || vocabulary.Values.Count != Vocabulary.Length)
            {
                throw EvidenceFailure.Reject("authority:policy-contract");
            }
            for(int index = 0; index < Vocabulary.Length; index++)
            {
                if(vocabulary.Values[index].Kind != 's' || vocabulary.Values[index].Text != Vocabulary[index])
                {
                    throw EvidenceFailure.Reject("authority:policy-contract");
                }
            }
            EvidenceJsonValue rows = policy.Get("kindTransitions");
            if(rows.Kind != 'a' || rows.Values.Count != ResidualCodes.Length)
            {
                throw EvidenceFailure.Reject("authority:policy-contract");
            }
            for(int index = 0; index < rows.Values.Count; index++)
            {
                EvidenceJsonValue row = rows.Values[index];
                EvidenceCanonicalJsonReader.RequireObject(row,
                    new string[] { "kind", "structuralCodes", "dischargedCodes", "addedCodes", "residualCodes" }, "nssss");
                if(row.Get("kind").Number != (ulong)index || row.Get("structuralCodes").Text != StructuralCodes[index] ||
                    row.Get("dischargedCodes").Text != DischargedCodes[index] || row.Get("addedCodes").Text != AddedCodes[index] ||
                    row.Get("residualCodes").Text != ResidualCodes[index])
                {
                    throw EvidenceFailure.Reject("authority:policy-contract");
                }
            }
            EvidenceJsonValue claims = policy.Get("verifiedClaims");
            string[] groups = new string[] { "localEvidence", "rehabilitationAuthorization", "rehabilitationReceipt", "other" };
            EvidenceCanonicalJsonReader.RequireObject(claims, groups, "aaaa");
            ushort[] kinds = new ushort[] { 16, 20, 21, 0 };
            for(int index = 0; index < groups.Length; index++)
            {
                EvidenceJsonValue values = claims.Get(groups[index]);
                string[] expected = GetArtifactClaims(kinds[index]);
                if(values.Values.Count != expected.Length) { throw EvidenceFailure.Reject("authority:policy-contract"); }
                for(int valueIndex = 0; valueIndex < expected.Length; valueIndex++)
                {
                    if(values.Values[valueIndex].Kind != 's' || values.Values[valueIndex].Text != expected[valueIndex])
                    {
                        throw EvidenceFailure.Reject("authority:policy-contract");
                    }
                }
            }
        }

        private static string[] Expand(string codes)
        {
            string[] values = new string[codes.Length];
            for(int index = 0; index < codes.Length; index++)
            {
                int tokenIndex = codes[index] - 'A';
                if(tokenIndex < 0 || tokenIndex >= Vocabulary.Length) { throw EvidenceFailure.Reject("runtime:projection"); }
                values[index] = Vocabulary[tokenIndex];
            }
            return values;
        }

        private static bool Equal(string[] left, string[] right)
        {
            if(left.Length != right.Length) { return false; }
            for(int index = 0; index < left.Length; index++)
            {
                if(!string.Equals(left[index], right[index], StringComparison.Ordinal)) { return false; }
            }
            return true;
        }
    }
}
