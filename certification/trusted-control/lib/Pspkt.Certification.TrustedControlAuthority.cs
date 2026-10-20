using System.Collections.Generic;

namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlAuthority
    {
        public static IDictionary<string, byte[]> Generate(
            byte[] authorityBytes,
            byte[] jsonMetaBytes,
            byte[] inventoryBytes)
        {
            return TrustedControlAuthorityProjectionA.Generate(
                authorityBytes,
                jsonMetaBytes,
                inventoryBytes);
        }
    }
}
