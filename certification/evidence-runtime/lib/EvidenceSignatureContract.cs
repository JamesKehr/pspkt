using System;
using System.Security.Cryptography;
using System.Text;

namespace Pspkt.Certification.EvidenceRuntime
{
    internal static class EvidenceSignatureContract
    {
        private static readonly string[] UncheckedTokens = new string[] {
            "evidence-authenticity-unchecked",
            "artifact-id-unbound",
            "profile-authentication-unchecked",
            "profile-value-unbound",
            "signature-authentication-unchecked",
            "signature-key-binding-unchecked",
            "subject-digest-unchecked",
            "copied-protocol-digests-unchecked",
            "cross-envelope-references-unchecked",
            "freshness-unchecked",
            "ledger-record-references-unchecked",
            "schema-bindings-unchecked",
            "producer-digests-unchecked"
        };

        private static readonly string[] KindTokenCodes = new string[] {
            "ABCEFHJ", "ABCHJ", "ABCDEFHJ", "ABCHJ", "ABCHJ", "ABCHJ",
            "ABCDHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ", "ABCDHJ",
            "ABCHJ", "ABCHJ", "ABCEFHJ", "ABCDEFGJL", "ABCDEFGJL", "ABCDJKM",
            "ABCDJM", "ABCDEFIJM", "ABCDIJKM"
        };

        internal static string[] GetUncheckedSemantics(ushort kind)
        {
            if (kind >= KindTokenCodes.Length) { throw new ArgumentOutOfRangeException("kind"); }
            string codes = KindTokenCodes[kind];
            string[] tokens = new string[codes.Length];
            for (int index = 0; index < codes.Length; index++) { tokens[index] = UncheckedTokens[codes[index] - 'A']; }
            return tokens;
        }

        internal static string[] GetDigestCategoryBindings(ushort kind)
        {
            switch (kind)
            {
                case 16:
                case 17:
                    return new string[] { "protocolSchemaDigest:L", "evidenceSchemaDigest:L", "payloadDigest:G", "observerKeyId:F" };
                case 18:
                    return new string[] { "canonicalSemanticDigest:M", "terminalRecordDigest:K", "burnReasonDigest:M", "observerProofDigest:M" };
                case 19:
                    return new string[] { "canonicalSemanticDigest:M", "successorRunIntentDigest:M", "deferralReasonDigest:M" };
                case 20:
                    return new string[] { "burnReceiptDigest:I", "burnedSemanticDigest:M", "successorRunIntentDigest:M", "authorityKeyId:F" };
                case 21:
                    return new string[] { "authorizationDigest:I", "successorRecordDigest:K", "observerProofDigest:M" };
                default:
                    return new string[0];
            }
        }

        internal static byte[] ComputePayloadDigest(string domain, byte[] payload)
        {
            byte[] hashDomainBytes = Encoding.ASCII.GetBytes(domain + "\0");
            byte[] preimage = new byte[hashDomainBytes.Length + payload.Length];
            Buffer.BlockCopy(hashDomainBytes, 0, preimage, 0, hashDomainBytes.Length);
            Buffer.BlockCopy(payload, 0, preimage, hashDomainBytes.Length, payload.Length);
            using (SHA256 algorithm = SHA256.Create()) { return algorithm.ComputeHash(preimage); }
        }

        internal static byte[] GetDeclaredCoveredBytes(ushort kind, string domain, byte[] payload)
        {
            if (kind != 16 && kind != 17 && kind != 20)
            {
                throw new NotSupportedException("This evidence kind has no declared evidence signature coverage.");
            }
            EvidenceTlvCursor cursor = new EvidenceTlvCursor(payload);
            for (ushort tag = 1; tag <= 9; tag++) { cursor.ReadField(tag); }
            int coveredLength = cursor.Position;
            cursor.ReadField(10, 384, 384);
            byte[] signatureDomainBytes = Encoding.ASCII.GetBytes(domain + "\0");
            byte[] covered = new byte[signatureDomainBytes.Length + coveredLength];
            Buffer.BlockCopy(signatureDomainBytes, 0, covered, 0, signatureDomainBytes.Length);
            Buffer.BlockCopy(payload, 0, covered, signatureDomainBytes.Length, coveredLength);
            return covered;
        }
    }
}
