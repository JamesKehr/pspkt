using System;
using System.Collections.Generic;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class LifecyclePolicy
    {
        internal const int MaximumControllers = 64;
        internal const int MaximumQueueFrames = 8;
        internal const int MaximumQueueBytes = 2097152;
        internal const int MaximumChunkBytes = 65536;
        internal const int MaximumFrameBytes = 1048576;
        internal const int MaximumDispatchLeases = 64;
        internal const int MaximumSchedulerItems = 256;
        internal const int MaximumOwnedBytes = 67108864;
        internal const int MaximumObservationSummaries = 1024;
        internal const string TailAuthorityUnavailable = "UnavailableForSelectedBaseSnapshot";
        internal const int MaximumLocalRecords = 256;
        internal const int MaximumLocalFullBytes = 1048576;
        internal const int MaximumLocalWrapperBytes = 1051904;
        internal const int MaximumBrokerRecords = 4096;
        internal const int MaximumBrokerWrapperBytes = 16777216;
        internal const int MaximumBrokerKeepalives = 256;
        internal const int MaximumLocalKeepalives = 64;
        internal const int MaximumBrokerOrdinaryRecords = 3840;
        internal const int MaximumBrokerOrdinaryWrapperBytes = 15728640;
        private const string PolicyDigest = "011e43d50fc6c4b00576ec8c6d08fd3636228f84509966216bba1fa1d284a536";

        private LifecyclePolicy()
        {
        }

        internal static LifecyclePolicy Admit(byte[] bytes)
        {
            if (bytes == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (bytes.Length == 0 || bytes.Length > 65536)
            {
                throw BrokerLifecycleFailure.Reject("authority:length");
            }
            byte[] retained = (byte[])bytes.Clone();
            if (!string.Equals(BrokerLifecycleFailure.Hex(BrokerLifecycleFailure.Hash(retained)), PolicyDigest, StringComparison.Ordinal))
            {
                throw BrokerLifecycleFailure.Reject("authority:pin");
            }
            Dictionary<string, object> policy = AuthorityJsonReader.Object(AuthorityJsonReader.Parse(retained));
            AuthorityJsonReader.RequireKeys(policy, new string[]
            {
                "schemaId", "schemaVersion", "trustCeiling", "serviceRoles", "servicePhases",
                "connectionPhases", "brokerHelloProgress", "localHelloProgress", "transportStatuses",
                "limits", "cardinality", "dispatchKinds", "closure"
            });
            if (!object.Equals(policy["schemaId"], "PspktBrokerLifecyclePolicyV1") ||
                !object.Equals(policy["schemaVersion"], (ulong)1) ||
                !object.Equals(policy["trustCeiling"], BrokerLifecycleFailure.TrustCeiling))
            {
                throw BrokerLifecycleFailure.Reject("authority:shape");
            }
            return new LifecyclePolicy();
        }
    }
}
