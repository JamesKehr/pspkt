using System;
using System.IO;
using System.Numerics;
using Pspkt.Certification.EvidenceRuntime;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal static class EvidenceSignatureVerifier
    {
        private const int SignatureBytes = 384;

        internal static EvidenceKeyBinding[] SelectKeys(EvidencePayloadProjection[] packets, EvidenceKeyBindingSnapshot snapshot)
        {
            EvidenceKeyBinding[] selected = new EvidenceKeyBinding[packets.Length];
            EvidenceKeyBinding[] bindings = snapshot.Bindings;
            for(int index = 0; index < packets.Length; index++)
            {
                if(!packets[index].HasDeclaredSignature) { continue; }
                byte[] identifier = packets[index].GetField(9);
                foreach(EvidenceKeyBinding binding in bindings)
                {
                    if(Equal(identifier, binding.Identifier)) { selected[index] = binding; break; }
                }
                if(selected[index] == null) { throw EvidenceFailure.Reject("key:missing"); }
                string requiredRole = packets[index].Kind == 20 ? "RecoveryAuthority" : "HostEvidence";
                if(!string.Equals(selected[index].Role, requiredRole, StringComparison.Ordinal))
                {
                    throw EvidenceFailure.Reject("key:role");
                }
                if(snapshot.EvaluationTime < selected[index].NotBefore || snapshot.EvaluationTime >= selected[index].NotAfter)
                {
                    throw EvidenceFailure.Reject("key:time");
                }
            }
            return selected;
        }

        internal static void Verify(EvidenceArtifactEnvelopeCodec codec, EvidencePayloadProjection[] packets,
            EvidenceKeyBindingSnapshot snapshot)
        {
            EvidenceKeyBinding[] selected = SelectKeys(packets, snapshot);
            for(int index = 0; index < packets.Length; index++)
            {
                if(!packets[index].HasDeclaredSignature) { continue; }
                byte[] signature = packets[index].GetField(10);
                BigInteger representative = ReadUnsigned(signature);
                BigInteger modulus = selected[index].PublicKey.Modulus;
                if(representative >= modulus) { throw EvidenceFailure.Reject("signature:range"); }
                BigInteger recovered = BigInteger.ModPow(representative, new BigInteger(65537), modulus);
                byte[] encodedMessage = WriteUnsigned(recovered);
                byte[] covered;
                try { covered = codec.GetDeclaredSignatureCoveredBytes(packets[index].Envelope); }
                catch(InvalidDataException) { throw EvidenceFailure.Reject("envelope:structure"); }
                byte[] digest = EvidenceFailure.Hash(covered);
                byte[] expected = new byte[SignatureBytes];
                expected[1] = 1;
                for(int position = 2; position <= 331; position++) { expected[position] = 255; }
                byte[] prefix = new byte[] { 48,49,48,13,6,9,96,134,72,1,101,3,4,2,1,5,0,4,32 };
                Buffer.BlockCopy(prefix, 0, expected, 333, prefix.Length);
                Buffer.BlockCopy(digest, 0, expected, 352, digest.Length);
                if(!Equal(encodedMessage, expected)) { throw EvidenceFailure.Reject("signature:emsa"); }
            }
        }

        internal static bool Equal(byte[] left, byte[] right)
        {
            if(left.Length != right.Length) { return false; }
            int difference = 0;
            for(int index = 0; index < left.Length; index++) { difference |= left[index] ^ right[index]; }
            return difference == 0;
        }

        private static BigInteger ReadUnsigned(byte[] bytes)
        {
            if(bytes.Length != SignatureBytes) { throw EvidenceFailure.Reject("runtime:projection"); }
            byte[] littleEndian = new byte[SignatureBytes + 1];
            for(int index = 0; index < SignatureBytes; index++) { littleEndian[index] = bytes[SignatureBytes - 1 - index]; }
            return new BigInteger(littleEndian);
        }

        private static byte[] WriteUnsigned(BigInteger value)
        {
            if(value.Sign < 0) { throw EvidenceFailure.Reject("runtime:projection"); }
            byte[] magnitude = value.ToByteArray();
            int length = magnitude.Length;
            if(length > 1 && magnitude[length - 1] == 0) { length--; }
            if(length > SignatureBytes) { throw EvidenceFailure.Reject("runtime:projection"); }
            byte[] result = new byte[SignatureBytes];
            for(int index = 0; index < length; index++)
            {
                result[SignatureBytes - length + index] = magnitude[length - 1 - index];
            }
            return result;
        }
    }
}
