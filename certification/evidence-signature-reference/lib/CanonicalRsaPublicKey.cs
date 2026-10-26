using System;
using System.Numerics;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal sealed class CanonicalRsaPublicKey
    {
        private const int EnvelopeBytes = 512;
        private const int ModulusBytes = 384;
        private readonly BigInteger _modulus;

        private CanonicalRsaPublicKey(BigInteger modulus)
        {
            _modulus = modulus;
        }

        internal BigInteger Modulus { get { return _modulus; } }

        internal static CanonicalRsaPublicKey Parse(byte[] bytes)
        {
            if(bytes.Length != EnvelopeBytes) { throw EvidenceFailure.Reject("snapshot:rsa-format"); }
            uint[] header = new uint[] { 0x31415352, 3072, 4, ModulusBytes, 0, 0 };
            for(int index = 0; index < header.Length; index++)
            {
                int offset = index * 4;
                uint actual = bytes[offset] | ((uint)bytes[offset + 1] << 8) |
                    ((uint)bytes[offset + 2] << 16) | ((uint)bytes[offset + 3] << 24);
                if(actual != header[index]) { throw EvidenceFailure.Reject("snapshot:rsa-format"); }
            }
            if(bytes[24] != 0 || bytes[25] != 1 || bytes[26] != 0 || bytes[27] != 1 || bytes[28] < 128)
            {
                throw EvidenceFailure.Reject("snapshot:rsa-format");
            }
            for(int index = 412; index < EnvelopeBytes; index++)
            {
                if(bytes[index] != 0) { throw EvidenceFailure.Reject("snapshot:rsa-format"); }
            }
            byte[] littleEndian = new byte[ModulusBytes + 1];
            for(int index = 0; index < ModulusBytes; index++) { littleEndian[index] = bytes[411 - index]; }
            return new CanonicalRsaPublicKey(new BigInteger(littleEndian));
        }
    }
}
