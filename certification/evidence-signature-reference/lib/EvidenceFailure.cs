using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Pspkt.Certification.EvidenceSignatureReference
{
    internal static class EvidenceFailure
    {
        private static readonly string[] Reasons = new string[] {
            "argument:null", "argument:empty", "argument:pin-width", "argument:ledger-identity",
            "argument:policy-digest-width", "argument:envelope-slot", "argument:empty-envelope",
            "resource:snapshot-bytes", "resource:key-count", "resource:envelope-count", "resource:envelope-bytes", "resource:aggregate-bytes",
            "authority:length", "authority:pin", "authority:codec-gate", "authority:protocol-gate", "authority:json-gate",
            "authority:local-shape", "authority:policy-contract", "snapshot:pin", "snapshot:json", "snapshot:json-bound",
            "snapshot:integer", "snapshot:properties", "snapshot:property-order", "snapshot:identity", "snapshot:ledger-context",
            "snapshot:skew", "snapshot:string-value", "snapshot:algorithm", "snapshot:role", "snapshot:interval",
            "snapshot:rsa-format", "snapshot:key-id", "snapshot:duplicate-key", "snapshot:host-policy", "snapshot:owner-context",
            "envelope:structure", "envelope:duplicate-content", "key:missing", "key:role", "key:time",
            "signature:range", "signature:emsa", "schema:protocol-digest", "schema:evidence-digest",
            "reference:target-missing", "reference:burned-operation", "reference:burned-semantic", "reference:successor-operation",
            "runtime:crypto-unavailable", "runtime:projection", "runtime:cleanup", "runtime:unexpected"
        };

        internal static InvalidDataException Reject(string reason)
        {
            return new InvalidDataException(reason);
        }

        internal static byte[] Hash(byte[] bytes)
        {
            return HashAndDispose(CreateSha256(), bytes);
        }

        internal static byte[] HashAndDispose(SHA256 algorithm, byte[] bytes)
        {
            if(algorithm == null) { throw Reject("runtime:crypto-unavailable"); }
            byte[] result = null;
            Exception failure = null;
            try
            {
                try { result = algorithm.ComputeHash(bytes); }
                catch(CryptographicException) { failure = Reject("runtime:crypto-unavailable"); }
                catch(PlatformNotSupportedException) { failure = Reject("runtime:crypto-unavailable"); }
                catch(Exception exception) { failure = Normalize(exception); }
            }
            finally { failure = DisposeOwned(algorithm, failure); }
            if(failure != null) { throw failure; }
            return result;
        }

        internal static Exception DisposeOwned(IDisposable resource, Exception primary)
        {
            Exception failure = primary == null ? null : Normalize(primary);
            try { resource.Dispose(); }
            catch(Exception)
            {
                if(failure == null) { failure = Reject("runtime:cleanup"); }
            }
            return failure;
        }

        internal static Exception Normalize(Exception exception)
        {
            if(exception != null && exception.InnerException == null &&
                (exception.GetType() == typeof(ArgumentException) || exception.GetType() == typeof(InvalidDataException)))
            {
                string message = exception.Message;
                bool argument = message.StartsWith("argument:", StringComparison.Ordinal);
                if(Array.IndexOf(Reasons, message) >= 0 && argument == (exception.GetType() == typeof(ArgumentException)))
                {
                    return exception;
                }
            }
            return Reject("runtime:unexpected");
        }

        internal static string Hex(byte[] bytes)
        {
            StringBuilder builder = new StringBuilder(bytes.Length * 2);
            foreach(byte value in bytes) { builder.Append(value.ToString("x2", CultureInfo.InvariantCulture)); }
            return builder.ToString();
        }

        private static SHA256 CreateSha256()
        {
            try { return SHA256.Create(); }
            catch(CryptographicException) { throw Reject("runtime:crypto-unavailable"); }
            catch(PlatformNotSupportedException) { throw Reject("runtime:crypto-unavailable"); }
            catch(InvalidOperationException) { throw Reject("runtime:crypto-unavailable"); }
        }
    }
}
