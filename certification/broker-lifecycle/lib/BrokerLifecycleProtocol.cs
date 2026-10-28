using System.Threading;

namespace Pspkt.Certification.BrokerLifecycle
{
    public sealed class BrokerLifecycleProtocol
    {
        private readonly ProtocolAuthoritySnapshot _authority;
        private int _issuedGenerations;

        private BrokerLifecycleProtocol(ProtocolAuthoritySnapshot authority)
        {
            _authority = authority;
        }

        public string[] UncheckedSemantics
        {
            get { return BrokerLifecycleFailure.CopyUncheckedSemantics(); }
        }

        internal ProtocolAuthoritySnapshot Authority
        {
            get { return _authority; }
        }

        public static BrokerLifecycleProtocol CreateFromCommittedAuthorities(
            byte[] protocolMetaBytes, byte[] protocolInventoryBytes,
            byte[] protocolSchemaBytes, byte[] messageAssociationBytes,
            byte[] generatedIdMapBytes, byte[] baseTailScheduleBytes,
            byte[] framingAddendumSchemaBytes, byte[] framingAddendumBytes,
            byte[] designReviewActivationBytes)
        {
            return new BrokerLifecycleProtocol(ProtocolAuthoritySnapshot.Admit(new byte[][]
            {
                protocolMetaBytes, protocolInventoryBytes, protocolSchemaBytes, messageAssociationBytes,
                generatedIdMapBytes, baseTailScheduleBytes, framingAddendumSchemaBytes, framingAddendumBytes,
                designReviewActivationBytes
            }));
        }

        public DecodedControlFrame Decode(string channel, string direction, byte profile, byte[] frameBytes)
        {
            return FrameCodec.Decode(this, channel, direction, profile, frameBytes);
        }

        public byte[] BuildSignaturePreimage(DecodedControlFrame frame, byte signerRole, byte[] channelIdentifier,
            byte[] evidenceSchemaMetaDigest, byte[] evidenceSchemaDigest)
        {
            return FrameSignaturePreimage.Build(this, frame, signerRole, channelIdentifier,
                evidenceSchemaMetaDigest, evidenceSchemaDigest);
        }

        public byte[] Encode(string channel, string direction, byte profile, ushort kind,
            ulong sequence, byte[] canonicalPayload, byte[] signatureBytes)
        {
            return FrameCodec.Encode(this, channel, direction, profile, kind, sequence, canonicalPayload, signatureBytes);
        }

        public byte[] BuildTranscriptRecord(DecodedControlFrame frame)
        {
            return TranscriptCodec.Wrap(this, frame);
        }

        public byte[] ComputeBootstrapBrokerFinishedDigest(DecodedControlFrame[] firstThreeFrames)
        {
            return TranscriptCodec.FinishedDigest(this, firstThreeFrames);
        }

        public byte[] ComputeBrokerChannelBinding(DecodedControlFrame[] fourBootstrapFrames)
        {
            return TranscriptCodec.BrokerBinding(this, fourBootstrapFrames);
        }

        public byte[] ComputeLocalChannelBinding(byte declaredCompleteness, byte[] localChannelIdentifier,
            byte[] bootIdNetworkBytes, uint brokerPid, ulong brokerCreationTime, uint workerPid, ulong workerCreationTime,
            DecodedControlFrame workerHello, DecodedControlFrame brokerHello)
        {
            return TranscriptCodec.LocalBinding(this, declaredCompleteness, localChannelIdentifier, bootIdNetworkBytes,
                brokerPid, brokerCreationTime, workerPid, workerCreationTime, workerHello, brokerHello);
        }

        public byte[] ComputeBrokerTranscriptDigest(DecodedControlFrame[] framesInProtocolOrder)
        {
            return TranscriptCodec.BrokerTranscript(this, framesInProtocolOrder);
        }

        public byte[] ComputeLocalTranscriptDigest(DecodedControlFrame[] workerToBrokerFrames,
            DecodedControlFrame[] brokerToWorkerFrames, byte[] localChannelIdentifier)
        {
            return TranscriptCodec.LocalTranscript(this, workerToBrokerFrames, brokerToWorkerFrames, localChannelIdentifier);
        }

        public byte[] ComputeLocalRecordSetDigest(DecodedControlFrame[] workerToBrokerFrames, DecodedControlFrame[] brokerToWorkerFrames)
        {
            return TranscriptCodec.LocalRecordSet(this, workerToBrokerFrames, brokerToWorkerFrames);
        }

        internal void RequireOwnedFrame(DecodedControlFrame frame)
        {
            if (frame == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (!object.ReferenceEquals(frame.Owner, this))
            {
                throw BrokerLifecycleFailure.Argument("argument:owner");
            }
        }

        internal RunGenerationId IssueGeneration()
        {
            int current;
            do
            {
                current = Volatile.Read(ref _issuedGenerations);
                if (current >= LifecyclePolicy.MaximumControllers)
                {
                    throw BrokerLifecycleFailure.Reject("transport:capacity");
                }
            }
            while (Interlocked.CompareExchange(ref _issuedGenerations, current + 1, current) != current);
            return new RunGenerationId((ulong)(current + 1), new object());
        }
    }
}
