using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal static class BrokerLifecycleFailure
    {
        internal const int MaximumAuthorityFileBytes = 16777216;
        internal const int MaximumAuthorityBytes = 67108864;
        internal const string TrustCeiling = "StructuralInProcessOnly";
        private static readonly HashSet<string> ReasonCodes = new HashSet<string>(new string[]
        {
            "argument:null", "argument:range", "argument:context", "argument:owner",
            "authority:length", "authority:pin", "authority:gate", "authority:shape",
            "authority:design-review-pending", "authority:design-review-binding",
            "frame:header", "frame:version", "frame:flags", "frame:reserved", "frame:length",
            "frame:signature-width", "frame:channel-unavailable", "frame:kind-unavailable",
            "frame:direction", "frame:profile", "payload:tag", "payload:length",
            "payload:primitive", "payload:budget", "payload:trailing", "context:role",
            "context:binding-shape", "context:ordering", "context:sequence",
            "context:sequence-origin", "context:bootstrap-incomplete",
            "context:protocol-schema-meta", "context:protocol-schema",
            "context:evidence-schema-meta", "context:evidence-schema", "quota:record-count",
            "quota:full-frame-bytes", "quota:wrapper-bytes", "quota:per-kind",
            "quota:ordinary", "quota:counter-consistency", "transport:capacity",
            "transport:deadline", "transport:premature-eof", "transport:indeterminate-write",
            "lifecycle:concurrent-entry", "lifecycle:state", "lifecycle:stale-generation",
            "lifecycle:lease-invariant", "lifecycle:dispatch-out-of-scope",
            "lifecycle:base-broker-terminal-unavailable", "lifecycle:local-failure-emitted",
            "lifecycle:peer-failure-observed", "lifecycle:traffic-after-terminal",
            "lifecycle:terminal-prerequisite-missing", "lifecycle:dispose-before-quiescence",
            "lifecycle:cleanup-incomplete", "lifecycle:disposed",
            "runtime:crypto-unavailable", "runtime:unexpected"
        }, StringComparer.Ordinal);
        private static readonly string[] Unchecked = new string[]
        {
            "frame-signature-unchecked", "nested-signature-unchecked", "signer-key-binding-unchecked",
            "evidence-schema-context-unverified", "peer-identity-unchecked", "service-trust-unchecked",
            "bootstrap-authentication-unchecked", "message-operational-semantics-unchecked",
            "durable-acceptance-unchecked", "cross-lease-replay-unchecked", "mandatory-tail-completion-unchecked",
            "keepalive-timing-unchecked", "lifecycle-certification-unchecked"
        };

        internal static ArgumentException Argument(string reason)
        {
            if (!ReasonCodes.Contains(reason) || !reason.StartsWith("argument:", StringComparison.Ordinal))
            {
                return new ArgumentException("argument:context");
            }
            return new ArgumentException(reason);
        }

        internal static string[] CopyUncheckedSemantics()
        {
            return (string[])Unchecked.Clone();
        }

        internal static byte[] Hash(byte[] bytes)
        {
            SHA256 algorithm;
            try
            {
                algorithm = SHA256.Create();
            }
            catch (CryptographicException)
            {
                throw Reject("runtime:crypto-unavailable");
            }
            catch (InvalidOperationException)
            {
                throw Reject("runtime:crypto-unavailable");
            }
            if (algorithm == null)
            {
                throw Reject("runtime:crypto-unavailable");
            }
            using (algorithm)
            {
                try
                {
                    return algorithm.ComputeHash(bytes);
                }
                catch (CryptographicException)
                {
                    throw Reject("runtime:crypto-unavailable");
                }
            }
        }

        internal static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
        }

        internal static InvalidDataException Reject(string reason)
        {
            return new InvalidDataException(ReasonCodes.Contains(reason) ? reason : "runtime:unexpected");
        }
    }
}
