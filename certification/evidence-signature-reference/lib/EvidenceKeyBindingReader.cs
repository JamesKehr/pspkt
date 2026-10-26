using System;
using System.Collections.Generic;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal static class EvidenceKeyBindingReader
    {
        private const int MaximumSnapshotBytes = 1048576;
        internal static EvidenceKeyBindingSnapshot Read(object owner, byte[] bytes, byte[] expectedPin,
            ulong evaluationTime, Guid expectedLedgerIdentity, byte[] expectedPolicyDigest)
        {
            if(bytes == null || expectedPin == null || expectedPolicyDigest == null)
            {
                throw new ArgumentException("argument:null");
            }
            if(bytes.Length == 0) { throw new ArgumentException("argument:empty"); }
            if(expectedPin.Length != 32) { throw new ArgumentException("argument:pin-width"); }
            if(!IsLedgerIdentity(expectedLedgerIdentity)) { throw new ArgumentException("argument:ledger-identity"); }
            if(expectedPolicyDigest.Length != 32) { throw new ArgumentException("argument:policy-digest-width"); }
            if(bytes.Length > MaximumSnapshotBytes) { throw EvidenceFailure.Reject("resource:snapshot-bytes"); }
            byte[] retained = (byte[])bytes.Clone();
            byte[] pin = (byte[])expectedPin.Clone();
            byte[] policy = (byte[])expectedPolicyDigest.Clone();
            byte[] digest = EvidenceFailure.Hash(retained);
            int difference = 0;
            for(int index = 0; index < digest.Length; index++) { difference |= digest[index] ^ pin[index]; }
            if(difference != 0) { throw EvidenceFailure.Reject("snapshot:pin"); }
            EvidenceJsonValue root = EvidenceCanonicalJsonReader.Read(retained, 8);
            EvidenceCanonicalJsonReader.RequireObject(root,
                new string[] { "schemaId", "schemaVersion", "ledgerIdentity", "keys", "maximumSkewHundredNanoseconds" }, "snsan");
            foreach(EvidenceJsonValue row in root.Get("keys").Values)
            {
                EvidenceCanonicalJsonReader.RequireObject(row,
                    new string[] { "keyId", "publicBlob", "algorithm", "role", "notBefore", "notAfter", "hostInventoryPolicyDigest" },
                    "ssssnns");
            }
            if(root.Get("schemaId").Text != "PspktEvidenceKeyBindingSnapshotV1" || root.Get("schemaVersion").Number != 1)
            {
                throw EvidenceFailure.Reject("snapshot:identity");
            }
            Guid parsedLedger;
            string ledgerText = root.Get("ledgerIdentity").Text;
            if(!Guid.TryParseExact(ledgerText, "D", out parsedLedger) || !IsLedgerIdentity(parsedLedger) ||
                parsedLedger.ToString("D") != ledgerText)
            {
                throw EvidenceFailure.Reject("snapshot:string-value");
            }
            if(parsedLedger != expectedLedgerIdentity) { throw EvidenceFailure.Reject("snapshot:ledger-context"); }
            if(root.Get("maximumSkewHundredNanoseconds").Number != 0) { throw EvidenceFailure.Reject("snapshot:skew"); }
            HashSet<string> identifiers = new HashSet<string>(StringComparer.Ordinal);
            List<EvidenceKeyBinding> bindings = new List<EvidenceKeyBinding>();
            foreach(EvidenceJsonValue row in root.Get("keys").Values)
            {
                byte[] identifier = DecodeHex(row.Get("keyId").Text, 32);
                byte[] publicBlob = DecodeHex(row.Get("publicBlob").Text, 512);
                byte[] rowPolicy = DecodeHex(row.Get("hostInventoryPolicyDigest").Text, 32);
                if(row.Get("algorithm").Text != "RSA3072PKCS1SHA256")
                {
                    throw EvidenceFailure.Reject("snapshot:algorithm");
                }
                string role = row.Get("role").Text;
                if(role != "HostEvidence" && role != "RecoveryAuthority") { throw EvidenceFailure.Reject("snapshot:role"); }
                ulong notBefore = row.Get("notBefore").Number;
                ulong notAfter = row.Get("notAfter").Number;
                if(notBefore >= notAfter) { throw EvidenceFailure.Reject("snapshot:interval"); }
                CanonicalRsaPublicKey publicKey = CanonicalRsaPublicKey.Parse(publicBlob);
                byte[] actualIdentifier = EvidenceFailure.Hash(publicBlob);
                int identifierDifference = 0;
                for(int index = 0; index < identifier.Length; index++) { identifierDifference |= identifier[index] ^ actualIdentifier[index]; }
                if(identifierDifference != 0) { throw EvidenceFailure.Reject("snapshot:key-id"); }
                if(!identifiers.Add(EvidenceFailure.Hex(actualIdentifier))) { throw EvidenceFailure.Reject("snapshot:duplicate-key"); }
                int policyDifference = 0;
                for(int index = 0; index < policy.Length; index++) { policyDifference |= policy[index] ^ rowPolicy[index]; }
                if(policyDifference != 0) { throw EvidenceFailure.Reject("snapshot:host-policy"); }
                bindings.Add(new EvidenceKeyBinding(identifier, role, notBefore, notAfter, publicKey));
            }
            return new EvidenceKeyBindingSnapshot(owner, retained, digest, evaluationTime, expectedLedgerIdentity,
                policy, bindings.ToArray());
        }

        internal static byte[] DecodeHex(string text, int byteCount)
        {
            if(text == null || text.Length != byteCount * 2) { throw EvidenceFailure.Reject("snapshot:string-value"); }
            byte[] result = new byte[byteCount];
            for(int index = 0; index < text.Length; index++)
            {
                char character = text[index];
                int value = character >= '0' && character <= '9' ? character - '0' :
                    character >= 'a' && character <= 'f' ? character - 'a' + 10 : -1;
                if(value < 0) { throw EvidenceFailure.Reject("snapshot:string-value"); }
                result[index / 2] |= (byte)(value << (index % 2 == 0 ? 4 : 0));
            }
            return result;
        }

        private static bool IsLedgerIdentity(Guid identifier)
        {
            string text = identifier.ToString("D");
            return identifier != Guid.Empty && text[14] >= '1' && text[14] <= '8' &&
                (text[19] == '8' || text[19] == '9' || text[19] == 'a' || text[19] == 'b');
        }
    }
}
