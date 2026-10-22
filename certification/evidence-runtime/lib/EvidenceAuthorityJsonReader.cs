using System.Runtime.Serialization.Json;
using System.Xml;
using System.Xml.Linq;

namespace Pspkt.Certification.EvidenceRuntime
{
    internal static class EvidenceAuthorityJsonReader
    {
        internal static XElement Read(byte[] admittedBytes)
        {
            XmlDictionaryReaderQuotas quotas = new XmlDictionaryReaderQuotas();
            quotas.MaxDepth = 64;
            quotas.MaxArrayLength = 1048576;
            quotas.MaxStringContentLength = 1048576;
            quotas.MaxBytesPerRead = 1048576;
            quotas.MaxNameTableCharCount = 1048576;
            using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(admittedBytes, quotas))
            {
                return XElement.Load(reader, LoadOptions.None);
            }
        }
    }
}
