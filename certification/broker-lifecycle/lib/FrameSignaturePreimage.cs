using System.IO;
using System.Text;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal static class FrameSignaturePreimage
    {
        private const int IdentifierBytes = 16;
        private const int DigestBytes = 32;

        internal static byte[] Build(BrokerLifecycleProtocol owner, DecodedControlFrame frame, byte role,
            byte[] identifier, byte[] evidenceMeta, byte[] evidenceSchema)
        {
            owner.RequireOwnedFrame(frame);
            if (identifier == null || evidenceMeta == null || evidenceSchema == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (identifier.Length != IdentifierBytes || evidenceMeta.Length != DigestBytes || evidenceSchema.Length != DigestBytes)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            if (role != frame.RequiredSignerRole)
            {
                throw BrokerLifecycleFailure.Reject("context:role");
            }
            bool local = frame.Channel == "LocalIpc";
            ProtocolPayloadCodec.ValidateSignatureContext(owner.Authority, frame.PayloadRoot, frame.CanonicalPayload,
                local ? "localBrokerWorkerChannelId" : "brokerControlServiceId", identifier, evidenceMeta, evidenceSchema);
            byte[] domain = Encoding.ASCII.GetBytes(local ? "pspkt-phase4-local-frame-v1\0" : "pspkt-phase4-frame-v1\0");
            byte direction = frame.Direction == "HostToBroker" || frame.Direction == "WorkerToBroker" ? (byte)1 : (byte)2;
            using (MemoryStream stream = new MemoryStream())
            {
                stream.Write(domain, 0, domain.Length);
                stream.WriteByte(direction);
                stream.WriteByte(role);
                stream.Write(identifier, 0, identifier.Length);
                byte[] protocolMeta = owner.Authority.CopyProtocolMetaDigest();
                byte[] protocolSchema = owner.Authority.CopyProtocolSchemaDigest();
                stream.Write(protocolMeta, 0, protocolMeta.Length);
                stream.Write(protocolSchema, 0, protocolSchema.Length);
                stream.Write(evidenceMeta, 0, evidenceMeta.Length);
                stream.Write(evidenceSchema, 0, evidenceSchema.Length);
                byte[] complete = frame.CompleteSignedFrame;
                stream.Write(complete, 0, FrameCodec.HeaderBytes + (int)frame.PayloadLength);
                return stream.ToArray();
            }
        }
    }
}
