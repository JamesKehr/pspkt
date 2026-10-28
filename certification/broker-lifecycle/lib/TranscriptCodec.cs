using System;
using System.IO;
using System.Text;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal static class TranscriptCodec
    {
        internal const int RecordOverhead = 13;

        internal static byte[] Wrap(BrokerLifecycleProtocol owner, DecodedControlFrame frame)
        {
            owner.RequireOwnedFrame(frame);
            byte[] complete = frame.CompleteSignedFrame;
            byte[] record = new byte[RecordOverhead + complete.Length];
            record[0] = Direction(frame);
            Buffer.BlockCopy(FrameCodec.WriteUnsigned(frame.Sequence, 8), 0, record, 1, 8);
            Buffer.BlockCopy(FrameCodec.WriteUnsigned((ulong)complete.Length, 4), 0, record, 9, 4);
            Buffer.BlockCopy(complete, 0, record, RecordOverhead, complete.Length);
            return record;
        }

        internal static byte[] FinishedDigest(BrokerLifecycleProtocol owner, DecodedControlFrame[] firstThreeFrames)
        {
            if (firstThreeFrames == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (firstThreeFrames.Length != 3)
            {
                throw BrokerLifecycleFailure.Reject("context:binding-shape");
            }
            ushort[] kinds = new ushort[] { 4353, 4354, 4355 };
            for (int index = 0; index < firstThreeFrames.Length; index++)
            {
                DecodedControlFrame frame = firstThreeFrames[index];
                owner.RequireOwnedFrame(frame);
                string direction = index == 1 ? "HostToBroker" : "BrokerToHost";
                if (frame.Channel != "BrokerControl" || frame.Direction != direction || frame.Kind != kinds[index])
                {
                    throw BrokerLifecycleFailure.Reject("context:ordering");
                }
                if (frame.Sequence != 0)
                {
                    throw BrokerLifecycleFailure.Reject("context:sequence");
                }
            }
            using (MemoryStream stream = new MemoryStream())
            {
                for (int index = 0; index < firstThreeFrames.Length; index++)
                {
                    byte[] record = Wrap(owner, firstThreeFrames[index]);
                    stream.Write(record, 0, record.Length);
                }
                return BrokerLifecycleFailure.Hash(stream.ToArray());
            }
        }

        internal static byte[] BrokerBinding(BrokerLifecycleProtocol owner, DecodedControlFrame[] frames)
        {
            if (frames == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (frames.Length != 4)
            {
                throw BrokerLifecycleFailure.Reject("context:binding-shape");
            }
            byte[] expectedFinished = FinishedDigest(owner, new DecodedControlFrame[] { frames[0], frames[1], frames[2] });
            owner.RequireOwnedFrame(frames[3]);
            if (frames[3].Channel != "BrokerControl" || frames[3].Direction != "BrokerToHost" || frames[3].Kind != 4356)
            {
                throw BrokerLifecycleFailure.Reject("context:ordering");
            }
            if (frames[3].Sequence != 0)
            {
                throw BrokerLifecycleFailure.Reject("context:sequence");
            }
            if (!EqualBytes(expectedFinished, frames[3].CopyField(1)))
            {
                throw BrokerLifecycleFailure.Reject("context:binding-shape");
            }
            using (MemoryStream stream = new MemoryStream())
            {
                WriteParts(stream, Encoding.ASCII.GetBytes("pspkt-phase4-broker-bootstrap-v1\0"),
                    frames[0].CopyField(3), frames[1].CopyField(4), frames[1].CopyField(5), frames[1].CopyField(6));
                foreach (DecodedControlFrame frame in frames)
                {
                    WriteParts(stream, frame.CompleteSignedFrame);
                }
                return BrokerLifecycleFailure.Hash(stream.ToArray());
            }
        }

        internal static byte[] LocalBinding(BrokerLifecycleProtocol owner, byte completeness, byte[] channelIdentifier,
            byte[] bootId, uint brokerPid, ulong brokerTime, uint workerPid, ulong workerTime,
            DecodedControlFrame workerHello, DecodedControlFrame brokerHello)
        {
            if (channelIdentifier == null || bootId == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (channelIdentifier.Length != 16 || bootId.Length != 16)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            if (completeness > 2 ||
                (completeness == 0 && (workerHello != null || brokerHello != null ||
                    brokerPid != 0 || brokerTime != 0 || workerPid != 0 || workerTime != 0)) ||
                (completeness == 1 && (workerHello == null || brokerHello != null)) ||
                (completeness == 2 && (workerHello == null || brokerHello == null)))
            {
                throw BrokerLifecycleFailure.Reject("context:binding-shape");
            }
            if (workerHello != null)
            {
                RequireLocalHello(owner, workerHello, 4609, "WorkerToBroker");
            }
            if (brokerHello != null)
            {
                RequireLocalHello(owner, brokerHello, 4610, "BrokerToWorker");
            }
            string pipePath = @"\\.\pipe\pspkt-broker-worker-" + BrokerLifecycleFailure.Hex(bootId);
            byte[] pathBytes = Encoding.UTF8.GetBytes(pipePath);
            byte[] worker = workerHello == null ? new byte[0] : workerHello.CompleteSignedFrame;
            byte[] broker = brokerHello == null ? new byte[0] : brokerHello.CompleteSignedFrame;
            using (MemoryStream stream = new MemoryStream())
            {
                WriteParts(stream, Encoding.ASCII.GetBytes("pspkt-phase4-local-bootstrap-v1\0"),
                    new byte[] { completeness }, channelIdentifier, FrameCodec.WriteUnsigned((ulong)pathBytes.Length, 2),
                    pathBytes, bootId, FrameCodec.WriteUnsigned(brokerPid, 4), FrameCodec.WriteUnsigned(brokerTime, 8),
                    FrameCodec.WriteUnsigned(workerPid, 4), FrameCodec.WriteUnsigned(workerTime, 8),
                    FrameCodec.WriteUnsigned((ulong)worker.Length, 4), worker,
                    FrameCodec.WriteUnsigned((ulong)broker.Length, 4), broker);
                return BrokerLifecycleFailure.Hash(stream.ToArray());
            }
        }

        internal static byte[] BrokerTranscript(BrokerLifecycleProtocol owner, DecodedControlFrame[] frames)
        {
            if (frames == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (frames.Length > LifecyclePolicy.MaximumBrokerRecords * 2)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
            ulong hostRecords = 0;
            ulong brokerRecords = 0;
            ulong hostBytes = 0;
            ulong brokerBytes = 0;
            foreach (DecodedControlFrame frame in frames)
            {
                owner.RequireOwnedFrame(frame);
                if (frame.Channel != "BrokerControl")
                {
                    throw BrokerLifecycleFailure.Reject("context:ordering");
                }
                ulong charge = frame.PayloadLength + (ulong)FrameCodec.FrameOverhead + RecordOverhead;
                if (frame.Direction == "HostToBroker")
                {
                    hostRecords++;
                    hostBytes += charge;
                }
                else
                {
                    brokerRecords++;
                    brokerBytes += charge;
                }
            }
            if (hostRecords > LifecyclePolicy.MaximumBrokerRecords || brokerRecords > LifecyclePolicy.MaximumBrokerRecords)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
            if (hostBytes > LifecyclePolicy.MaximumBrokerWrapperBytes || brokerBytes > LifecyclePolicy.MaximumBrokerWrapperBytes ||
                hostBytes + brokerBytes > (ulong)LifecyclePolicy.MaximumBrokerWrapperBytes * 2)
            {
                throw BrokerLifecycleFailure.Reject("quota:wrapper-bytes");
            }
            ulong nextHost = 1;
            ulong nextBroker = 1;
            int hostKeepalives = 0;
            int brokerKeepalives = 0;
            bool hostTerminal = false;
            bool brokerTerminal = false;
            for (int index = 0; index < frames.Length; index++)
            {
                DecodedControlFrame frame = frames[index];
                if (index < 4)
                {
                    ushort expectedKind = (ushort)(4353 + index);
                    if (frame.Kind < 4353 || frame.Kind > 4356)
                    {
                        throw BrokerLifecycleFailure.Reject("context:bootstrap-incomplete");
                    }
                    if (frame.Kind != expectedKind || frame.Direction != (index == 1 ? "HostToBroker" : "BrokerToHost"))
                    {
                        throw BrokerLifecycleFailure.Reject("context:ordering");
                    }
                    if (frame.Sequence != 0)
                    {
                        throw BrokerLifecycleFailure.Reject("context:sequence");
                    }
                    if (index == 3)
                    {
                        byte[] digest = FinishedDigest(owner, new DecodedControlFrame[] { frames[0], frames[1], frames[2] });
                        if (!EqualBytes(digest, frame.CopyField(1)))
                        {
                            throw BrokerLifecycleFailure.Reject("context:binding-shape");
                        }
                    }
                    continue;
                }
                bool host = frame.Direction == "HostToBroker";
                if ((frame.Kind >= 4353 && frame.Kind <= 4356) || (host ? hostTerminal : brokerTerminal))
                {
                    throw BrokerLifecycleFailure.Reject("context:ordering");
                }
                ulong expected = host ? nextHost : nextBroker;
                if (frame.Sequence != expected)
                {
                    throw BrokerLifecycleFailure.Reject("context:sequence");
                }
                if (host)
                {
                    nextHost++;
                    if (frame.Kind == 4372 && ++hostKeepalives > LifecyclePolicy.MaximumBrokerKeepalives)
                    {
                        throw BrokerLifecycleFailure.Reject("quota:per-kind");
                    }
                    hostTerminal = frame.Kind == 4373;
                }
                else
                {
                    nextBroker++;
                    if (frame.Kind == 4372 && ++brokerKeepalives > LifecyclePolicy.MaximumBrokerKeepalives)
                    {
                        throw BrokerLifecycleFailure.Reject("quota:per-kind");
                    }
                    brokerTerminal = frame.Kind == 4373;
                }
            }
            using (MemoryStream stream = new MemoryStream())
            {
                WriteParts(stream, Encoding.ASCII.GetBytes("pspkt-phase4-transcript-v1\0"),
                    owner.Authority.CopyProtocolMetaDigest(), owner.Authority.CopyProtocolSchemaDigest(),
                    FrameCodec.WriteUnsigned((ulong)frames.Length, 4));
                foreach (DecodedControlFrame frame in frames)
                {
                    WriteParts(stream, Wrap(owner, frame));
                }
                return BrokerLifecycleFailure.Hash(stream.ToArray());
            }
        }

        internal static byte[] LocalTranscript(BrokerLifecycleProtocol owner, DecodedControlFrame[] workerToBroker,
            DecodedControlFrame[] brokerToWorker, byte[] channelIdentifier)
        {
            if (channelIdentifier == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (channelIdentifier.Length != 16)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            ValidateLocalTranscript(owner, workerToBroker, brokerToWorker);
            using (MemoryStream stream = new MemoryStream())
            {
                WriteParts(stream, Encoding.ASCII.GetBytes("pspkt-phase4-local-transcript-v1\0"), channelIdentifier,
                    owner.Authority.CopyProtocolMetaDigest(), owner.Authority.CopyProtocolSchemaDigest(),
                    FrameCodec.WriteUnsigned((ulong)workerToBroker.Length, 4));
                foreach (DecodedControlFrame frame in workerToBroker)
                {
                    WriteParts(stream, frame.CompleteSignedFrame);
                }
                WriteParts(stream, FrameCodec.WriteUnsigned((ulong)brokerToWorker.Length, 4));
                foreach (DecodedControlFrame frame in brokerToWorker)
                {
                    WriteParts(stream, frame.CompleteSignedFrame);
                }
                return BrokerLifecycleFailure.Hash(stream.ToArray());
            }
        }

        internal static byte[] LocalRecordSet(BrokerLifecycleProtocol owner, DecodedControlFrame[] workerToBroker,
            DecodedControlFrame[] brokerToWorker)
        {
            ValidateLocalTranscript(owner, workerToBroker, brokerToWorker);
            using (MemoryStream stream = new MemoryStream())
            {
                WriteParts(stream, Encoding.ASCII.GetBytes("pspkt-phase4-local-transcript-record-set-v1\0"),
                    FrameCodec.WriteUnsigned((ulong)workerToBroker.Length, 4),
                    FrameCodec.WriteUnsigned((ulong)brokerToWorker.Length, 4));
                foreach (DecodedControlFrame frame in workerToBroker)
                {
                    WriteParts(stream, Wrap(owner, frame));
                }
                foreach (DecodedControlFrame frame in brokerToWorker)
                {
                    WriteParts(stream, Wrap(owner, frame));
                }
                return BrokerLifecycleFailure.Hash(stream.ToArray());
            }
        }

        internal static byte Direction(DecodedControlFrame frame)
        {
            return frame.Direction == "HostToBroker" || frame.Direction == "WorkerToBroker" ? (byte)1 : (byte)2;
        }

        private static void ValidateLocalTranscript(BrokerLifecycleProtocol owner, DecodedControlFrame[] workerToBroker,
            DecodedControlFrame[] brokerToWorker)
        {
            if (workerToBroker == null || brokerToWorker == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (workerToBroker.Length > LifecyclePolicy.MaximumLocalRecords || brokerToWorker.Length > LifecyclePolicy.MaximumLocalRecords)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
            PreflightLocalDirection(owner, workerToBroker, "WorkerToBroker");
            PreflightLocalDirection(owner, brokerToWorker, "BrokerToWorker");
            if ((brokerToWorker.Length != 0 && workerToBroker.Length == 0) ||
                ((workerToBroker.Length > 1 || brokerToWorker.Length > 1) &&
                    (workerToBroker.Length == 0 || brokerToWorker.Length == 0)))
            {
                throw BrokerLifecycleFailure.Reject("context:bootstrap-incomplete");
            }
            ValidateLocalOrder(workerToBroker, 4609);
            ValidateLocalOrder(brokerToWorker, 4610);
        }

        private static void PreflightLocalDirection(BrokerLifecycleProtocol owner, DecodedControlFrame[] frames, string direction)
        {
            ulong fullBytes = 0;
            foreach (DecodedControlFrame frame in frames)
            {
                owner.RequireOwnedFrame(frame);
                if (frame.Channel != "LocalIpc" || frame.Direction != direction)
                {
                    throw BrokerLifecycleFailure.Reject("context:ordering");
                }
                fullBytes += frame.PayloadLength + (ulong)FrameCodec.FrameOverhead;
            }
            ulong wrapped = fullBytes + (ulong)frames.Length * RecordOverhead;
            ConnectionState.ValidateLocalQuota((ulong)frames.Length, fullBytes, wrapped);
        }

        private static void ValidateLocalOrder(DecodedControlFrame[] frames, ushort helloKind)
        {
            if (frames.Length == 0)
            {
                return;
            }
            if (frames[0].Kind != helloKind)
            {
                throw BrokerLifecycleFailure.Reject("context:bootstrap-incomplete");
            }
            if (frames[0].Sequence != 0)
            {
                throw BrokerLifecycleFailure.Reject("context:sequence");
            }
            int keepalives = 0;
            bool terminal = false;
            for (int index = 1; index < frames.Length; index++)
            {
                DecodedControlFrame frame = frames[index];
                if (terminal || frame.Kind == 4609 || frame.Kind == 4610)
                {
                    throw BrokerLifecycleFailure.Reject("context:ordering");
                }
                if (frame.Sequence != (ulong)index)
                {
                    throw BrokerLifecycleFailure.Reject("context:sequence");
                }
                if (frame.Kind == 4626 && ++keepalives > LifecyclePolicy.MaximumLocalKeepalives)
                {
                    throw BrokerLifecycleFailure.Reject("quota:per-kind");
                }
                terminal = frame.Kind == 4627;
            }
        }

        private static bool EqualBytes(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; index++)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }

        private static void RequireLocalHello(BrokerLifecycleProtocol owner, DecodedControlFrame frame, ushort kind, string direction)
        {
            owner.RequireOwnedFrame(frame);
            if (frame.Channel != "LocalIpc" || frame.Direction != direction || frame.Kind != kind)
            {
                throw BrokerLifecycleFailure.Reject("context:ordering");
            }
            if (frame.Sequence != 0)
            {
                throw BrokerLifecycleFailure.Reject("context:sequence");
            }
        }

        private static void WriteParts(MemoryStream stream, params byte[][] parts)
        {
            foreach (byte[] part in parts)
            {
                stream.Write(part, 0, part.Length);
            }
        }
    }
}
