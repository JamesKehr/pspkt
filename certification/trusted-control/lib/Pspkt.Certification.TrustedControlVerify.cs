using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Pspkt.Certification.TrustedControl
{
    public static class TrustedControlVerify
    {
        private const int MaximumSizingRecursionDepth = 64;

        public static void Verify(
            byte[] authorityBytes,
            byte[] jsonMetaBytes,
            byte[] inventoryBytes,
            IDictionary<string, byte[]> actual)
        {
            if (actual == null)
            {
                throw new ArgumentNullException("actual");
            }
            VerifierContext context = ValidateVerifierGate(
                authorityBytes,
                jsonMetaBytes,
                inventoryBytes);
            TrustedJsonArray declarations = context.Authority.GetArray("outputSchemas");
            if (actual.Count != declarations.Items.Count)
            {
                throw new InvalidOperationException("output-cardinality");
            }
            for (int index = 0; index < declarations.Items.Count; index++)
            {
                TrustedJsonObject declaration = (TrustedJsonObject)declarations.Items[index];
                string path = declaration.GetString("path");
                byte[] candidate;
                if (!actual.TryGetValue(path, out candidate))
                {
                    throw new InvalidOperationException("output-missing:" + path);
                }
                byte[] expected = context.Projected[path];
                if (!BytesEqual(expected, candidate))
                {
                    throw new InvalidOperationException("output-bytes-differ:" + path);
                }
            }
        }

        public static string VerifyVector(
            byte[] vectorBytes,
            byte[] authorityBytes,
            byte[] jsonMetaBytes,
            byte[] inventoryBytes)
        {
            VerifierContext context = ValidateVerifierGate(
                authorityBytes,
                jsonMetaBytes,
                inventoryBytes);
            TrustedJsonObject vector =
                TrustedControlJsonSchemaBootstrap.ParseCanonical(vectorBytes) as TrustedJsonObject;
            if (vector == null)
            {
                return "vector-shape";
            }
            TrustedControlJsonSchemaBootstrap.ValidateVector(vector);
            string expectedReason = vector.GetString("expectedReason");
            string actualReason;
            try
            {
                actualReason = EvaluateVector(
                    vector.GetString("caseKind"),
                    vector.GetObject("input"),
                    context.Authority,
                    jsonMetaBytes);
            }
            catch (InvalidOperationException exception)
            {
                actualReason = exception.Message;
            }
            if (!string.Equals(expectedReason, actualReason, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "vector-reason-mismatch:expected=" + expectedReason + ";actual=" + actualReason);
            }
            return actualReason;
        }

        private static string EvaluateVector(
            string caseKind,
            TrustedJsonObject input,
            TrustedJsonObject authority,
            byte[] jsonMetaBytes)
        {
            RequireActivationForbidden(authority);
            if (string.Equals(caseKind, "baseline", StringComparison.Ordinal))
            {
                TrustedControlJsonSchemaBootstrap.ParseAndValidateMeta(jsonMetaBytes);
                return "ok";
            }
            if (string.Equals(caseKind, "schemaMetaHash", StringComparison.Ordinal))
            {
                string actual = TrustedControlJsonSchemaBootstrap.ComputeSha256Hex(jsonMetaBytes);
                return string.Equals(input.GetString("expectedSha256"), actual, StringComparison.Ordinal)
                    ? "ok"
                    : "schema-meta-mismatch";
            }
            if (string.Equals(caseKind, "emission", StringComparison.Ordinal))
            {
                string artifactKind = input.GetString("artifactKind");
                string outputPath = input.GetString("outputPath");
                if (!string.Equals(artifactKind, "Schema", StringComparison.Ordinal))
                {
                    return string.Equals(artifactKind, "TrustedControlArtifactSetV1", StringComparison.Ordinal)
                        ? "aggregate-emission-forbidden"
                        : "registry-instance-forbidden";
                }
                bool declared = false;
                TrustedJsonArray outputs = authority.GetArray("outputSchemas");
                for (int index = 0; index < outputs.Items.Count; index++)
                {
                    if (string.Equals(
                        ((TrustedJsonObject)outputs.Items[index]).GetString("path"),
                        outputPath,
                        StringComparison.Ordinal))
                    {
                        declared = true;
                    }
                }
                return declared ? "ok" : "registry-instance-forbidden";
            }
            if (string.Equals(caseKind, "pathSet", StringComparison.Ordinal))
            {
                TrustedJsonArray paths = input.GetArray("paths");
                HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (int index = 0; index < paths.Items.Count; index++)
                {
                    string path = ((TrustedJsonString)paths.Items[index]).Value;
                    if (!IsStrictArtifactPath(path))
                    {
                        return "artifact-path-invalid";
                    }
                    if (!unique.Add(path))
                    {
                        return "trusted-artifact-path-collision";
                    }
                }
                return "ok";
            }
            if (string.Equals(caseKind, "membershipPath", StringComparison.Ordinal))
            {
                string path = input.GetString("path");
                HashSet<string> fixtureTracked;
                HashSet<string> fixturePending;
                string fixtureReason = ReadMembershipSet(input.GetArray("trackedPaths"), true, out fixtureTracked);
                if (fixtureReason != null) return fixtureReason;
                fixtureReason = ReadMembershipSet(input.GetArray("pendingPaths"), false, out fixturePending);
                if (fixtureReason != null) return fixtureReason;
                foreach (string trackedPath in fixtureTracked)
                {
                    if (fixturePending.Contains(trackedPath)) return "membership-fixture-overlap";
                    foreach (string pendingPath in fixturePending)
                    {
                        if (string.Equals(trackedPath, pendingPath, StringComparison.OrdinalIgnoreCase))
                            return "membership-case-alias";
                    }
                }
                bool certificationPath = IsStrictArtifactPath(path)
                    && path.StartsWith("certification/", StringComparison.Ordinal);
                bool enrolledPath = IsEnrolledHostPath(path);
                if (!certificationPath && !enrolledPath)
                {
                    return IsStrictArtifactPath(path)
                        ? "membership-path-outside-certification"
                        : "membership-path-invalid";
                }
                if (certificationPath && fixtureTracked.Contains(path)) return "ok";
                return fixturePending.Contains(path)
                    ? "membership-path-pending"
                    : certificationPath
                        ? "membership-path-untracked"
                        : "membership-path-pending-missing";
            }
            if (string.Equals(caseKind, "timing", StringComparison.Ordinal))
            {
                ulong now = input.GetInteger("now");
                ulong deadline = input.GetInteger("deadline");
                string constraintKind = input.GetString("constraintKind");
                string relation = input.Contains("relation") ? input.GetString("relation") : null;
                if (string.Equals(constraintKind, "VT", StringComparison.Ordinal))
                {
                    return relation == null
                        && string.Equals(input.GetString("vtPolicy"), "raise-only", StringComparison.Ordinal)
                        ? "ok"
                        : "timing-kind-relation-invalid";
                }
                if (!string.Equals(relation, "LT", StringComparison.Ordinal)
                    && !string.Equals(relation, "LE", StringComparison.Ordinal))
                {
                    return "timing-relation-unknown";
                }
                if (!string.Equals(constraintKind, "Deadline", StringComparison.Ordinal)
                    && !string.Equals(constraintKind, "CapacityFit", StringComparison.Ordinal)
                    && !string.Equals(constraintKind, "DerivedW", StringComparison.Ordinal)
                    && !string.Equals(constraintKind, "VT", StringComparison.Ordinal))
                {
                    return "timing-kind-unknown";
                }
                if ((string.Equals(constraintKind, "Deadline", StringComparison.Ordinal)
                        && !string.Equals(relation, "LT", StringComparison.Ordinal))
                    || (string.Equals(constraintKind, "CapacityFit", StringComparison.Ordinal)
                        && !string.Equals(relation, "LE", StringComparison.Ordinal))
                    || (string.Equals(constraintKind, "DerivedW", StringComparison.Ordinal)
                        && !string.Equals(relation, "LE", StringComparison.Ordinal)))
                {
                    return "timing-kind-relation-invalid";
                }
                bool accepted = string.Equals(relation, "LE", StringComparison.Ordinal)
                    ? now <= deadline
                    : now < deadline;
                if (!accepted)
                {
                    return now == deadline
                        ? "timing-deadline-equality-expired"
                        : "timing-deadline-late";
                }
                if (input.Contains("derivedW"))
                {
                    ulong expectedW = CheckedOrderedSum(input.GetArray("orderedTerms"));
                    if (input.GetInteger("derivedW") != expectedW)
                    {
                        return "timing-derived-w-invalid";
                    }
                }
                return "ok";
            }
            if (string.Equals(caseKind, "rsaEnvelope", StringComparison.Ordinal))
            {
                string value = input.GetString("hex");
                if (value.Length != 1024 || !IsLowerHex(value))
                {
                    return "rsa-envelope-length-or-conversion-invalid";
                }
                byte[] envelope = ParseHex(value);
                uint magic = ReadUInt32LittleEndian(envelope, 0);
                uint bitLength = ReadUInt32LittleEndian(envelope, 4);
                uint publicExponentLength = ReadUInt32LittleEndian(envelope, 8);
                uint modulusLength = ReadUInt32LittleEndian(envelope, 12);
                uint prime1Length = ReadUInt32LittleEndian(envelope, 16);
                uint prime2Length = ReadUInt32LittleEndian(envelope, 20);
                byte[] nativeExponentBytes = ParseHex(input.GetString("nativeExponentHex"));
                ulong nativeLength = input.GetInteger("nativeExponentByteLength");
                if (nativeExponentBytes.Length != 3 && nativeExponentBytes.Length != 4)
                {
                    return "rsa-envelope-length-or-conversion-invalid";
                }
                uint nativeExponent = ReadUnsignedBigEndian(nativeExponentBytes);
                if (magic != 0x31415352U
                    || bitLength != 3072U
                    || publicExponentLength != 4U
                    || modulusLength != 384U
                    || prime1Length != 0U
                    || prime2Length != 0U
                    || nativeLength != (ulong)nativeExponentBytes.Length
                    || (nativeLength != 3UL && nativeLength != 4UL)
                    || nativeExponent != 65537U
                    || envelope[24] != 0 || envelope[25] != 1 || envelope[26] != 0 || envelope[27] != 1
                    || (envelope[28] & 0x80) == 0)
                {
                    return "rsa-envelope-length-or-conversion-invalid";
                }
                for (int index = 412; index < envelope.Length; index++)
                {
                    if (envelope[index] != 0)
                    {
                        return "rsa-envelope-length-or-conversion-invalid";
                    }
                }
                if (!string.Equals(
                    input.GetString("keyId"),
                    TrustedControlJsonSchemaBootstrap.ComputeSha256Hex(envelope),
                    StringComparison.Ordinal))
                {
                    return "rsa-key-id-invalid";
                }
                return "ok";
            }
            if (string.Equals(caseKind, "rsaNative", StringComparison.Ordinal))
            {
                byte[] native = ParseHex(input.GetString("nativeHex"));
                if (native.Length != 411 && native.Length != 412) return "rsa-native-conversion-invalid";
                if (ReadUInt32LittleEndian(native, 0) != 0x31415352U
                    || ReadUInt32LittleEndian(native, 4) != 3072U
                    || ReadUInt32LittleEndian(native, 12) != 384U
                    || ReadUInt32LittleEndian(native, 16) != 0U
                    || ReadUInt32LittleEndian(native, 20) != 0U)
                {
                    return "rsa-native-conversion-invalid";
                }
                uint exponentLength = ReadUInt32LittleEndian(native, 8);
                if (exponentLength != 3U && exponentLength != 4U) return "rsa-native-conversion-invalid";
                if (native.Length != 24 + exponentLength + 384) return "rsa-native-conversion-invalid";
                byte[] exponentBytes = new byte[exponentLength];
                Buffer.BlockCopy(native, 24, exponentBytes, 0, exponentBytes.Length);
                if (ReadUnsignedBigEndian(exponentBytes) != 65537U) return "rsa-native-conversion-invalid";
                byte[] canonical = new byte[512];
                Buffer.BlockCopy(native, 0, canonical, 0, 24);
                canonical[8] = 4;
                canonical[9] = 0;
                canonical[10] = 0;
                canonical[11] = 0;
                int exponentPadding = 4 - exponentBytes.Length;
                Buffer.BlockCopy(exponentBytes, 0, canonical, 24 + exponentPadding, exponentBytes.Length);
                Buffer.BlockCopy(native, 24 + exponentBytes.Length, canonical, 28, 384);
                if ((canonical[28] & 0x80) == 0) return "rsa-native-conversion-invalid";
                string canonicalHex = ToHex(canonical);
                string keyId = TrustedControlJsonSchemaBootstrap.ComputeSha256Hex(canonical);
                return string.Equals(canonicalHex, input.GetString("expectedCanonicalHex"), StringComparison.Ordinal)
                    && string.Equals(keyId, input.GetString("expectedKeyId"), StringComparison.Ordinal)
                    ? "ok"
                    : "rsa-native-conversion-invalid";
            }
            if (string.Equals(caseKind, "fixedAscii8", StringComparison.Ordinal))
            {
                string value = input.GetString("hex");
                if (value.Length != 16 || !IsLowerHex(value))
                {
                    return "fixedascii-padding-invalid";
                }
                bool foundNul = false;
                for (int index = 0; index < 16; index += 2)
                {
                    int byteValue = int.Parse(value.Substring(index, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    if (byteValue == 0)
                    {
                        foundNul = true;
                    }
                    else if (foundNul || byteValue < 0x20 || byteValue > 0x7E)
                    {
                        return "fixedascii-padding-invalid";
                    }
                }
                return "ok";
            }
            if (string.Equals(caseKind, "guidBytes", StringComparison.Ordinal))
            {
                string text = input.GetString("text");
                Guid parsed;
                if (!Guid.TryParseExact(text, "D", out parsed)
                    || parsed == Guid.Empty
                    || !string.Equals(text, parsed.ToString("D").ToLowerInvariant(), StringComparison.Ordinal))
                {
                    return "guid-rfc4122-bytes-invalid";
                }
                byte[] rfcBytes = ParseHex(input.GetString("rfc4122Hex"));
                int version = (rfcBytes[6] >> 4) & 0x0F;
                if ((rfcBytes[8] & 0xC0) != 0x80 || version < 1 || version > 8)
                {
                    return "guid-rfc4122-bytes-invalid";
                }
                return string.Equals(
                    input.GetString("rfc4122Hex"),
                    GuidToRfc4122Hex(parsed),
                    StringComparison.Ordinal)
                    ? "ok"
                    : "guid-rfc4122-bytes-invalid";
            }
            if (string.Equals(caseKind, "luidBytes", StringComparison.Ordinal))
            {
                ulong value = input.GetInteger("value");
                return string.Equals(input.GetString("bigEndianHex"), ToBigEndianHex(value), StringComparison.Ordinal)
                    ? "ok"
                    : "luid-big-endian-bytes-invalid";
            }
            if (string.Equals(caseKind, "interpreterBinding", StringComparison.Ordinal))
            {
                return BindingSetsEqual(input.GetArray("entrypointBindings"), input.GetArray("buildBindings"))
                    ? "ok"
                    : "interpreter-binding-mismatch";
            }
            if (string.Equals(caseKind, "migrationBlockers", StringComparison.Ordinal))
            {
                TrustedJsonArray sites = input.GetArray("sites");
                if (sites.Items.Count == 0) return "migration-sites-empty";
                for (int index = 0; index < sites.Items.Count; index++)
                {
                    TrustedJsonObject site = (TrustedJsonObject)sites.Items[index];
                    string kind = site.GetString("kind");
                    if (string.Equals(kind, "ExternalProcess", StringComparison.Ordinal))
                    {
                        return "external-process-migration-blocker";
                    }
                    if (string.Equals(kind, "PowerShell", StringComparison.Ordinal))
                    {
                        return "powershell-migration-blocker";
                    }
                    if (!string.Equals(kind, "ExternalProcess", StringComparison.Ordinal)
                        && !string.Equals(kind, "PowerShell", StringComparison.Ordinal))
                    {
                        return "migration-kind-unknown";
                    }
                }
                return "migration-kind-unknown";
            }
            if (string.Equals(caseKind, "overlay", StringComparison.Ordinal))
            {
                string requestedState = input.GetString("requestedState");
                return string.Equals(requestedState, "Dormant", StringComparison.Ordinal)
                    || string.Equals(requestedState, "Forbidden", StringComparison.Ordinal)
                    ? "ok"
                    : "overlay-activation-forbidden";
            }
            if (string.Equals(caseKind, "entrypointCaps", StringComparison.Ordinal))
            {
                TrustedJsonObject limits = authority.GetObject("limits");
                return input.GetInteger("rootBytes") <= limits.GetInteger("entrypointMaximumRootBytes")
                    && input.GetInteger("aggregateBytes") <= limits.GetInteger("entrypointMaximumAggregateBytes")
                    && input.GetInteger("totalSourceSites") <= limits.GetInteger("entrypointTotalSourceSitesMaximum")
                    && input.GetInteger("totalUserArguments") <= limits.GetInteger("entrypointTotalUserArgumentsMaximum")
                    ? "ok"
                    : "entrypoint-cap-exceeded";
            }
            if (string.Equals(caseKind, "digest", StringComparison.Ordinal))
            {
                byte[] domain = Encoding.ASCII.GetBytes(input.GetString("domain"));
                byte[] metaDigest = ParseHex(input.GetString("metaSha256"));
                byte[] schemaDigest = ParseHex(input.GetString("schemaSha256"));
                byte[] tlv = ParseHex(input.GetString("canonicalTlvHex"));
                if (!IsCanonicalTlv(tlv))
                {
                    return "digest-tlv-framing-invalid";
                }
                if (!string.Equals(input.GetString("metaSha256"), "ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85", StringComparison.Ordinal)
                    || IsPlaceholderDigest(input.GetString("schemaSha256"))
                    || !SchemaDigestMatches(authority, input.GetString("domain"), input.GetString("schemaSha256")))
                {
                    return "digest-input-placeholder-or-mismatch";
                }
                byte[] payload = new byte[domain.Length + 1 + metaDigest.Length + schemaDigest.Length + tlv.Length];
                Buffer.BlockCopy(domain, 0, payload, 0, domain.Length);
                Buffer.BlockCopy(metaDigest, 0, payload, domain.Length + 1, metaDigest.Length);
                Buffer.BlockCopy(schemaDigest, 0, payload, domain.Length + 1 + metaDigest.Length, schemaDigest.Length);
                Buffer.BlockCopy(tlv, 0, payload, domain.Length + 1 + metaDigest.Length + schemaDigest.Length, tlv.Length);
                string actual = TrustedControlJsonSchemaBootstrap.ComputeSha256Hex(payload);
                return string.Equals(actual, input.GetString("expectedDigest"), StringComparison.Ordinal)
                    ? "ok"
                    : "digest-formula-invalid";
            }
            throw new InvalidOperationException("unknown-vector-case");
        }

        private static bool BytesEqual(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
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

        private static string GuidToRfc4122Hex(Guid value)
        {
            byte[] bytes = value.ToByteArray();
            byte[] ordered = new byte[]
            {
                bytes[3], bytes[2], bytes[1], bytes[0],
                bytes[5], bytes[4],
                bytes[7], bytes[6],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]
            };
            return ToHex(ordered);
        }

        private static bool IsLowerHex(string value)
        {
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool IsStrictArtifactPath(string value)
        {
            if (string.IsNullOrEmpty(value)
                || value.Length > 512
                || value[0] == '/'
                || value[value.Length - 1] == '/'
                || value.IndexOf('\\') >= 0
                || value.IndexOf(':') >= 0
                || value.IndexOf("//", StringComparison.Ordinal) >= 0)
            {
                return false;
            }
            string[] segments = value.Split('/');
            string[] reserved = new string[] { "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$" };
            for (int index = 0; index < segments.Length; index++)
            {
                for (int characterIndex = 0; characterIndex < segments[index].Length; characterIndex++)
                {
                    char character = segments[index][characterIndex];
                    if (character < 0x21 || character > 0x7E)
                    {
                        return false;
                    }
                }
                string component = segments[index];
                string baseName = component.Split('.')[0];
                if (segments[index].Length == 0
                    || string.Equals(segments[index], ".", StringComparison.Ordinal)
                    || string.Equals(segments[index], "..", StringComparison.Ordinal)
                    || component.EndsWith(".", StringComparison.Ordinal)
                    || component.EndsWith(" ", StringComparison.Ordinal))
                {
                    return false;
                }
                for (int reservedIndex = 0; reservedIndex < reserved.Length; reservedIndex++)
                {
                    if (string.Equals(baseName, reserved[reservedIndex], StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
                for (int deviceIndex = 1; deviceIndex <= 9; deviceIndex++)
                {
                    if (string.Equals(baseName, "COM" + deviceIndex, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(baseName, "LPT" + deviceIndex, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private static ulong CheckedOrderedSum(TrustedJsonArray terms)
        {
            string[] expectedIds = new string[]
            {
                "consoleFenceRetirementDeadline",
                "consoleMainReaderJoinDeadline",
                "terminalRestoreEpisodeDeadline",
                "consoleAuxiliaryQuiescenceDeadline",
                "consoleTopologyRevalidationDeadline",
                "finalFrameOutputDeadline",
                "consoleTopologyRevalidationDeadline",
                "consoleControlCallbackDrainDeadline"
            };
            if (terms.Items.Count != expectedIds.Length)
            {
                throw new InvalidOperationException("timing-derived-w-terms");
            }
            ulong result = 0;
            checked
            {
                for (int index = 0; index < terms.Items.Count; index++)
                {
                    TrustedJsonObject term = (TrustedJsonObject)terms.Items[index];
                    if (!string.Equals(term.GetString("id"), expectedIds[index], StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("timing-derived-w-order");
                    }
                    result += term.GetInteger("value");
                }
            }
            return result;
        }

        private static byte[] ParseHex(string value)
        {
            if ((value.Length & 1) != 0 || !IsLowerHex(value))
            {
                throw new InvalidOperationException("hex-invalid");
            }
            byte[] bytes = new byte[value.Length / 2];
            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = byte.Parse(value.Substring(index * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            return bytes;
        }

        private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        {
            return (uint)(bytes[offset]
                | (bytes[offset + 1] << 8)
                | (bytes[offset + 2] << 16)
                | (bytes[offset + 3] << 24));
        }

        private static uint ReadUnsignedBigEndian(byte[] bytes)
        {
            if (bytes.Length != 3 && bytes.Length != 4)
            {
                throw new InvalidOperationException("rsa-native-exponent-length");
            }
            uint result = 0;
            for (int index = 0; index < bytes.Length; index++)
            {
                result = (result << 8) | bytes[index];
            }
            return result;
        }

        private static bool IsPlaceholderDigest(string value)
        {
            return value == new string('0', 64) || value == new string('1', 64);
        }

        private static bool IsCanonicalTlv(byte[] bytes)
        {
            if (bytes.Length == 0) return false;
            int offset = 0;
            ushort previousTag = 0;
            while (offset < bytes.Length)
            {
                if (bytes.Length - offset < 6) return false;
                ushort tag = (ushort)((bytes[offset] << 8) | bytes[offset + 1]);
                uint length = (uint)((bytes[offset + 2] << 24)
                    | (bytes[offset + 3] << 16)
                    | (bytes[offset + 4] << 8)
                    | bytes[offset + 5]);
                if (tag == 0 || tag <= previousTag || length > int.MaxValue) return false;
                offset += 6;
                if ((ulong)(bytes.Length - offset) < length) return false;
                offset += (int)length;
                previousTag = tag;
            }
            return offset == bytes.Length;
        }

        private static bool SchemaDigestMatches(TrustedJsonObject authority, string domain, string expected)
        {
            TrustedJsonObject domains = authority.GetObject("digestDomains");
            string schemaId = string.Equals(domain, domains.GetString("trustedControlArtifactSet"), StringComparison.Ordinal)
                ? "PspktTrustedControlArtifactSetSchemaV1"
                : string.Equals(domain, domains.GetString("powerShellEntryPoints"), StringComparison.Ordinal)
                    ? "PspktPowerShellEntryPointSchemaV1"
                    : string.Equals(domain, domains.GetString("supportedBuildEntry"), StringComparison.Ordinal)
                        ? "PspktSupportedBuildEntrySchemaV1"
                        : null;
            if (schemaId == null)
            {
                return false;
            }

            TrustedJsonArray outputs = authority.GetArray("outputSchemas");
            for (int index = 0; index < outputs.Items.Count; index++)
            {
                TrustedJsonObject output = (TrustedJsonObject)outputs.Items[index];
                if (string.Equals(output.GetString("schemaId"), schemaId, StringComparison.Ordinal))
                {
                    return string.Equals(
                        TrustedControlJsonSchemaBootstrap.ComputeSha256Hex(ProjectVerifierOutput(output)),
                        expected,
                        StringComparison.Ordinal);
                }
            }
            return false;
        }

        private static bool BindingSetsEqual(TrustedJsonArray left, TrustedJsonArray right)
        {
            if (left.Items.Count != right.Items.Count) return false;
            HashSet<string> leftSet = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> rightSet = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> leftKeys = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> rightKeys = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> leftIdentities = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> rightIdentities = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < left.Items.Count; index++)
            {
                TrustedJsonObject binding = (TrustedJsonObject)left.Items[index];
                string key = BindingKey(binding);
                string identity = BindingIdentity(binding);
                if (key == null || identity == null
                    || !leftKeys.Add(binding.GetString("key"))
                    || !leftIdentities.Add(identity)
                    || !leftSet.Add(key)) return false;
            }
            for (int index = 0; index < right.Items.Count; index++)
            {
                TrustedJsonObject binding = (TrustedJsonObject)right.Items[index];
                string key = BindingKey(binding);
                string identity = BindingIdentity(binding);
                if (key == null || identity == null
                    || !rightKeys.Add(binding.GetString("key"))
                    || !rightIdentities.Add(identity)
                    || !rightSet.Add(key)) return false;
            }
            return leftSet.SetEquals(rightSet);
        }

        private static string ReadMembershipSet(
            TrustedJsonArray values,
            bool tracked,
            out HashSet<string> result)
        {
            result = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> folded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string previous = null;
            for (int index = 0; index < values.Items.Count; index++)
            {
                TrustedJsonString value = values.Items[index] as TrustedJsonString;
                if (value == null) return "membership-fixture-invalid-path";
                string path = value.Value;
                bool valid = tracked
                    ? IsStrictArtifactPath(path) && path.StartsWith("certification/", StringComparison.Ordinal)
                    : (IsStrictArtifactPath(path) && path.StartsWith("certification/", StringComparison.Ordinal))
                        || IsEnrolledHostPath(path);
                if (!valid) return "membership-fixture-invalid-path";
                if (previous != null && string.CompareOrdinal(previous, path) >= 0)
                {
                    return string.Equals(previous, path, StringComparison.Ordinal)
                        ? "membership-fixture-duplicate"
                        : "membership-fixture-unsorted";
                }
                if (!result.Add(path)) return "membership-fixture-duplicate";
                if (!folded.Add(path)) return "membership-case-alias";
                previous = path;
            }
            return null;
        }

        private static bool IsEnrolledHostPath(string path)
        {
            const string prefix = "enrolled-host-root/";
            if (!path.StartsWith(prefix, StringComparison.Ordinal) || path.Length != prefix.Length + 64) return false;
            for (int index = prefix.Length; index < path.Length; index++)
            {
                char value = path[index];
                if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) return false;
            }
            return true;
        }

        private static string BindingKey(TrustedJsonObject binding)
        {
            string path = binding.GetString("path");
            string canonicalPath = CanonicalizeWindowsPath(path);
            if (canonicalPath == null) return null;
            string fileId = binding.GetString("fileId");
            if (fileId.Length != 32 || !IsLowerHex(fileId)) return null;
            return binding.GetString("key") + "\u001f" + canonicalPath + "\u001f"
                + binding.GetString("imageDigest") + "\u001f"
                + binding.GetInteger("volumeSerial").ToString(CultureInfo.InvariantCulture) + "\u001f" + fileId;
        }

        private static string BindingIdentity(TrustedJsonObject binding)
        {
            string fileId = binding.GetString("fileId");
            if (fileId.Length != 32 || !IsLowerHex(fileId)) return null;
            return binding.GetInteger("volumeSerial").ToString(CultureInfo.InvariantCulture) + "\u001f" + fileId;
        }

        private static string CanonicalizeWindowsPath(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 3 || path[1] != ':' || path[2] != '\\' || path.IndexOf('/') >= 0)
            {
                return null;
            }
            string[] components = path.Substring(3).Split('\\');
            StringBuilder builder = new StringBuilder(path.Length);
            char drive = path[0];
            if (!((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z'))) return null;
            builder.Append(FoldAsciiCase(drive));
            builder.Append(":\\");
            for (int componentIndex = 0; componentIndex < components.Length; componentIndex++)
            {
                string component = components[componentIndex];
                if (component.Length == 0 || component == "." || component == ".."
                    || component.IndexOf(':') >= 0
                    || component.IndexOf('~') >= 0
                    || component.EndsWith(".", StringComparison.Ordinal)
                    || component.EndsWith(" ", StringComparison.Ordinal))
                {
                    return null;
                }
                string baseName = component.Split('.')[0];
                if (IsReservedWindowsDevice(baseName)) return null;
                if (componentIndex != 0) builder.Append('\\');
                for (int index = 0; index < component.Length; index++) builder.Append(FoldAsciiCase(component[index]));
            }
            return builder.ToString();
        }

        private static char FoldAsciiCase(char value)
        {
            return value >= 'A' && value <= 'Z' ? (char)(value + 32) : value;
        }

        private static bool IsReservedWindowsDevice(string value)
        {
            string folded = value.ToUpperInvariant();
            if (folded == "CON" || folded == "PRN" || folded == "AUX" || folded == "NUL"
                || folded == "CLOCK$" || folded == "CONIN$" || folded == "CONOUT$") return true;
            for (int index = 1; index <= 9; index++)
            {
                if (folded == "COM" + index.ToString(CultureInfo.InvariantCulture)
                    || folded == "LPT" + index.ToString(CultureInfo.InvariantCulture)) return true;
            }
            return false;
        }

        private static string ToBigEndianHex(ulong value)
        {
            byte[] bytes = new byte[8];
            for (int index = 7; index >= 0; index--)
            {
                bytes[index] = (byte)(value & 0xFF);
                value >>= 8;
            }

            return ToHex(bytes);
        }

        private static void RequireActivationForbidden(TrustedJsonObject authority)
        {
            if (authority == null
                || !string.Equals(authority.GetObject("decisions").GetString("activation"), "Forbidden", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("$.decisions.activation:must-be-Forbidden");
            }
        }

        private static VerifierContext ValidateVerifierGate(
            byte[] authorityBytes,
            byte[] jsonMetaBytes,
            byte[] inventoryBytes)
        {
            TrustedJsonObject inventory =
                TrustedControlJsonSchemaBootstrap.ParsePinnedInventory(inventoryBytes);
            TrustedJsonObject meta =
                TrustedControlJsonSchemaBootstrap.ParseAndValidateMeta(jsonMetaBytes);
            TrustedJsonObject authority =
                TrustedControlJsonSchemaBootstrap.ParseCanonical(authorityBytes) as TrustedJsonObject;
            if (authority == null)
            {
                throw new InvalidOperationException("authority-shape");
            }
            TrustedControlJsonSchemaBootstrap.ValidateAuthorityRaw(authority, meta, inventory);
            RequireActivationForbidden(authority);
            try
            {
                return BuildVerifierProjection(authority, meta, inventory);
            }
            catch (InvalidOperationException exception)
            {
                if (exception.Message.StartsWith("verify-", StringComparison.Ordinal))
                {
                    throw;
                }
                throw new InvalidOperationException("verify-" + exception.Message, exception);
            }
            catch (OverflowException exception)
            {
                throw new InvalidOperationException(
                    "verify-entrypoint-sizing-overflow",
                    exception);
            }
        }

        private static VerifierContext BuildVerifierProjection(
            TrustedJsonObject authority,
            TrustedJsonObject meta,
            TrustedJsonObject inventory)
        {
            Dictionary<string, byte[]> projected =
                new Dictionary<string, byte[]>(StringComparer.Ordinal);
            TrustedJsonArray declarations = authority.GetArray("outputSchemas");
            TrustedJsonArray entrypointTypes = null;
            for (int index = 0; index < declarations.Items.Count; index++)
            {
                TrustedJsonObject output = (TrustedJsonObject)declarations.Items[index];
                byte[] bytes = ProjectVerifierOutput(output);
                TrustedJsonObject document =
                    TrustedControlJsonSchemaBootstrap.ParseCanonical(bytes) as TrustedJsonObject;
                if (document == null)
                {
                    throw new InvalidOperationException("projection-shape");
                }
                if (string.Equals(output.GetString("format"), "JsonRegistry", StringComparison.Ordinal))
                {
                    TrustedControlJsonSchemaBootstrap.ValidateSchema(document, meta);
                    if (!BytesEqual(
                        output.GetArray("semanticRules").ToCanonicalBytes(),
                        document.GetArray("semanticRules").ToCanonicalBytes()))
                    {
                        throw new InvalidOperationException("output-rule-drift");
                    }
                }
                if (string.Equals(
                    output.GetString("path"),
                    "certification/trusted-control/schema/powershell-entrypoints-schema.v1.json",
                    StringComparison.Ordinal))
                {
                    if (entrypointTypes != null)
                    {
                        throw new InvalidOperationException("entrypoint-schema-duplicate-match");
                    }
                    if (!string.Equals(
                            output.GetString("schemaId"),
                            "PspktPowerShellEntryPointSchemaV1",
                            StringComparison.Ordinal)
                        || !string.Equals(
                            output.GetString("format"),
                            "ProtocolTlv",
                            StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("entrypoint-schema-tuple");
                    }
                    entrypointTypes = document.GetArray("types");
                }
                projected.Add(output.GetString("path"), bytes);
            }
            if (entrypointTypes == null)
            {
                throw new InvalidOperationException("entrypoint-schema-missing");
            }
            ValidateVerifierSizing(authority.GetObject("limits"), inventory, entrypointTypes);
            return new VerifierContext(authority, projected);
        }

        private static byte[] ProjectVerifierOutput(TrustedJsonObject output)
        {
            string schemaId = output.GetString("schemaId");
            TrustedJsonObject declaration = output.GetObject("declaration");
            string json;
            if (string.Equals(output.GetString("format"), "ProtocolTlv", StringComparison.Ordinal))
            {
                string declarationJson =
                    Encoding.UTF8.GetString(declaration.GetArray("types").ToCanonicalBytes());
                if (string.Equals(schemaId, "PspktPowerShellEntryPointSchemaV1", StringComparison.Ordinal))
                {
                    declarationJson = ProjectVerifierEntrypointDeclaration(declarationJson);
                }
                json = "{\"schemaVersion\":1,\"schemaId\":\"" + schemaId
                    + "\",\"types\":" + declarationJson + "}";
            }
            else
            {
                json = "{\"schemaId\":\"" + schemaId + "\",\"schemaVersion\":1,\"kind\":\""
                    + declaration.GetString("kind") + "\",\"status\":\"" + declaration.GetString("status")
                    + "\",\"root\":" + Encoding.UTF8.GetString(declaration.GetObject("root").ToCanonicalBytes())
                    + ",\"semanticRules\":" + Encoding.UTF8.GetString(output.GetArray("semanticRules").ToCanonicalBytes()) + "}";
            }
            return new UTF8Encoding(false, true).GetBytes(json);
        }

        private static string ProjectVerifierEntrypointDeclaration(string declarationJson)
        {
            declarationJson = ReplaceVerifierExactlyOnce(
                declarationJson,
                "{\"typeId\":9,\"production\":\"List\",\"name\":\"PowerShellArgumentList\",\"elementType\":\"PowerShellArgumentV1\",\"minCount\":0,\"maxCount\":32}",
                "{\"typeId\":9,\"production\":\"List\",\"name\":\"PowerShellArgumentList\",\"elementType\":\"PowerShellArgumentV1\",\"minCount\":0,\"maxCount\":2}");
            declarationJson = ReplaceVerifierExactlyOnce(
                declarationJson,
                "{\"typeId\":11,\"production\":\"List\",\"name\":\"SourceSiteList\",\"elementType\":\"SourceSiteV1\",\"minCount\":1,\"maxCount\":128}",
                "{\"typeId\":11,\"production\":\"List\",\"name\":\"SourceSiteList\",\"elementType\":\"SourceSiteV1\",\"minCount\":1,\"maxCount\":1}");
            declarationJson = ReplaceVerifierExactlyOnce(
                declarationJson,
                "{\"typeId\":12,\"production\":\"Named\",\"name\":\"HostInterpreterIdentityV1\",\"fields\":[{\"fieldId\":1,\"name\":\"key\",\"type\":\"AsciiIdentifier\"},{\"fieldId\":2,\"name\":\"path\",\"type\":\"WindowsAbsolutePath\"},{\"fieldId\":3,\"name\":\"imageDigest\",\"type\":\"SHA-256\"}]}",
                "{\"typeId\":12,\"production\":\"Named\",\"name\":\"HostInterpreterIdentityV1\",\"fields\":[{\"fieldId\":1,\"name\":\"key\",\"type\":\"AsciiIdentifier\"},{\"fieldId\":2,\"name\":\"path\",\"type\":\"WindowsAbsolutePath\"},{\"fieldId\":3,\"name\":\"imageDigest\",\"type\":\"SHA-256\"},{\"fieldId\":4,\"name\":\"volumeSerial\",\"type\":\"U64\"},{\"fieldId\":5,\"name\":\"fileId\",\"type\":\"Opaque16\"}]}");
            return declarationJson;
        }

        private static string ReplaceVerifierExactlyOnce(
            string value,
            string oldValue,
            string newValue)
        {
            int index = value.IndexOf(oldValue, StringComparison.Ordinal);
            if (index < 0 || value.IndexOf(oldValue, index + oldValue.Length, StringComparison.Ordinal) >= 0)
            {
                throw new InvalidOperationException("entrypoint-projection-shape");
            }
            return value.Substring(0, index) + newValue + value.Substring(index + oldValue.Length);
        }

        private static void ValidateVerifierSizing(
            TrustedJsonObject limits,
            TrustedJsonObject inventory,
            TrustedJsonArray types)
        {
            Dictionary<string, TrustedJsonObject> typeByName =
                new Dictionary<string, TrustedJsonObject>(StringComparer.Ordinal);
            for (int index = 0; index < types.Items.Count; index++)
            {
                TrustedJsonObject type = types.Items[index] as TrustedJsonObject;
                if (type == null)
                {
                    throw new InvalidOperationException("entrypoint-type-set");
                }
                string typeName = type.GetString("name");
                if (typeByName.ContainsKey(typeName))
                {
                    throw new InvalidOperationException("entrypoint-type-set");
                }
                typeByName.Add(typeName, type);
            }
            TrustedJsonObject primitiveWidths = inventory.GetObject("primitiveValueMaxima");
            HashSet<string> active = new HashSet<string>(StringComparer.Ordinal);
            int maximumDepth = 0;
            ulong sourceSiteBytes = SizeVerifierType(
                "SourceSiteV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong interpreterBytes = SizeVerifierType(
                "HostInterpreterIdentityV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong argumentBytes = SizeVerifierType(
                "PowerShellArgumentV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong hostBytes = SizeVerifierType(
                "HostToolProcessEntryPointV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong guestBytes = SizeVerifierType(
                "GuestCandidateProcessEntryPointV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong runspaceBytes = SizeVerifierType(
                "HostInProcessRunspaceEntryPointV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong rootBytes = SizeVerifierType(
                "PowerShellEntryPointRegistryV1", null, typeByName, primitiveWidths, active, 1, ref maximumDepth);
            ulong totalSourceSites = CountVerifierReachableRecordOccurrences(
                "PowerShellEntryPointRegistryV1",
                "SourceSiteV1",
                typeByName,
                primitiveWidths,
                new HashSet<string>(StringComparer.Ordinal),
                1UL,
                1);
            ulong totalArguments = CountVerifierReachableRecordOccurrences(
                "PowerShellEntryPointRegistryV1",
                "PowerShellArgumentV1",
                typeByName,
                primitiveWidths,
                new HashSet<string>(StringComparer.Ordinal),
                1UL,
                1);
            if (rootBytes > limits.GetInteger("entrypointMaximumRootBytes"))
            {
                throw new InvalidOperationException("entrypoint-root-policy-ceiling");
            }
            if (totalSourceSites > limits.GetInteger("entrypointTotalSourceSitesMaximum"))
            {
                throw new InvalidOperationException("entrypoint-sites-policy-ceiling");
            }
            if (totalArguments > limits.GetInteger("entrypointTotalUserArgumentsMaximum"))
            {
                throw new InvalidOperationException("entrypoint-arguments-policy-ceiling");
            }
            if (sourceSiteBytes
                    != limits.GetInteger("entrypointReviewedSourceSiteBytes")
                || interpreterBytes
                    != limits.GetInteger("entrypointReviewedInterpreterBytes")
                || argumentBytes
                    != limits.GetInteger("entrypointReviewedArgumentBytes")
                || hostBytes
                    != limits.GetInteger("entrypointReviewedHostToolBytes")
                || guestBytes
                    != limits.GetInteger("entrypointReviewedGuestCandidateBytes")
                || runspaceBytes
                    != limits.GetInteger("entrypointReviewedHostRunspaceBytes")
                || rootBytes
                    != limits.GetInteger("entrypointReviewedRootBytes")
                || totalSourceSites
                    != limits.GetInteger("entrypointReviewedTotalSourceSites")
                || totalArguments
                    != limits.GetInteger("entrypointReviewedTotalUserArguments")
                || (ulong)maximumDepth
                    != limits.GetInteger("entrypointReviewedMaximumDepth"))
            {
                throw new InvalidOperationException(
                    "entrypoint-reviewed-sizing:"
                    + sourceSiteBytes + "/" + interpreterBytes + "/" + argumentBytes + "/"
                    + hostBytes + "/" + guestBytes + "/" + runspaceBytes + "/" + rootBytes + "/"
                    + totalSourceSites + "/" + totalArguments + "/" + maximumDepth);
            }
        }

        private static ulong SizeVerifierType(
            string typeName,
            TrustedJsonObject field,
            Dictionary<string, TrustedJsonObject> typeByName,
            TrustedJsonObject primitiveWidths,
            HashSet<string> active,
            int depth,
            ref int maximumDepth)
        {
            if (depth > MaximumSizingRecursionDepth)
            {
                throw new InvalidOperationException(
                    "entrypoint-recursion-safety-depth:" + depth);
            }
            if (depth > maximumDepth)
            {
                maximumDepth = depth;
            }
            if (string.Equals(typeName, "BoundedBytes", StringComparison.Ordinal))
            {
                if (field == null)
                {
                    throw new InvalidOperationException("bounded-bytes-field");
                }
                return checked(4UL + field.GetInteger("maxBytes"));
            }
            if (primitiveWidths.Contains(typeName))
            {
                return primitiveWidths.GetInteger(typeName);
            }
            TrustedJsonObject declaration;
            if (!typeByName.TryGetValue(typeName, out declaration))
            {
                throw new InvalidOperationException("entrypoint-undefined-type:" + typeName);
            }
            if (!active.Add(typeName))
            {
                throw new InvalidOperationException("entrypoint-type-cycle:" + typeName);
            }
            try
            {
                string production = declaration.GetString("production");
                if (string.Equals(production, "EnumU16", StringComparison.Ordinal))
                {
                    return 2UL;
                }
                if (string.Equals(production, "SemanticString", StringComparison.Ordinal))
                {
                    return checked(4UL + declaration.GetInteger("maxBytes"));
                }
                if (string.Equals(production, "List", StringComparison.Ordinal))
                {
                    ulong elementBytes = SizeVerifierType(
                        declaration.GetString("elementType"),
                        null,
                        typeByName,
                        primitiveWidths,
                        active,
                        depth + 1,
                        ref maximumDepth);
                    return checked(
                        4UL + (declaration.GetInteger("maxCount") * checked(4UL + elementBytes)));
                }
                if (string.Equals(production, "Named", StringComparison.Ordinal))
                {
                    ulong result = 0UL;
                    TrustedJsonArray fields = declaration.GetArray("fields");
                    for (int index = 0; index < fields.Items.Count; index++)
                    {
                        TrustedJsonObject namedField = (TrustedJsonObject)fields.Items[index];
                        result = checked(
                            result
                            + 6UL
                            + SizeVerifierType(
                                namedField.GetString("type"),
                                namedField,
                                typeByName,
                                primitiveWidths,
                                active,
                                depth + 1,
                                ref maximumDepth));
                    }
                    return result;
                }
                throw new InvalidOperationException("entrypoint-production:" + production);
            }
            finally
            {
                active.Remove(typeName);
            }
        }

        private static ulong CountVerifierReachableRecordOccurrences(
            string typeName,
            string targetRecordName,
            Dictionary<string, TrustedJsonObject> typeByName,
            TrustedJsonObject primitiveWidths,
            HashSet<string> active,
            ulong multiplier,
            int depth)
        {
            if (depth > MaximumSizingRecursionDepth)
            {
                throw new InvalidOperationException(
                    "entrypoint-recursion-safety-depth:" + depth);
            }
            if (string.Equals(typeName, targetRecordName, StringComparison.Ordinal))
            {
                return multiplier;
            }
            if (string.Equals(typeName, "BoundedBytes", StringComparison.Ordinal)
                || primitiveWidths.Contains(typeName))
            {
                return 0UL;
            }
            TrustedJsonObject declaration;
            if (!typeByName.TryGetValue(typeName, out declaration))
            {
                throw new InvalidOperationException("entrypoint-undefined-type:" + typeName);
            }
            if (!active.Add(typeName))
            {
                throw new InvalidOperationException("entrypoint-type-cycle:" + typeName);
            }
            try
            {
                string production = declaration.GetString("production");
                if (string.Equals(production, "EnumU16", StringComparison.Ordinal)
                    || string.Equals(production, "SemanticString", StringComparison.Ordinal))
                {
                    return 0UL;
                }
                if (string.Equals(production, "List", StringComparison.Ordinal))
                {
                    ulong elementMultiplier =
                        checked(multiplier * declaration.GetInteger("maxCount"));
                    return CountVerifierReachableRecordOccurrences(
                        declaration.GetString("elementType"),
                        targetRecordName,
                        typeByName,
                        primitiveWidths,
                        active,
                        elementMultiplier,
                        depth + 1);
                }
                if (string.Equals(production, "Named", StringComparison.Ordinal))
                {
                    ulong result = 0UL;
                    TrustedJsonArray fields = declaration.GetArray("fields");
                    for (int index = 0; index < fields.Items.Count; index++)
                    {
                        TrustedJsonObject field = (TrustedJsonObject)fields.Items[index];
                        result = checked(
                            result
                            + CountVerifierReachableRecordOccurrences(
                                field.GetString("type"),
                                targetRecordName,
                                typeByName,
                                primitiveWidths,
                                active,
                                multiplier,
                                depth + 1));
                    }
                    return result;
                }
                throw new InvalidOperationException("entrypoint-production:" + production);
            }
            finally
            {
                active.Remove(typeName);
            }
        }

        private static string ToHex(byte[] bytes)
        {
            char[] characters = new char[bytes.Length * 2];
            const string digits = "0123456789abcdef";
            for (int index = 0; index < bytes.Length; index++)
            {
                characters[index * 2] = digits[bytes[index] >> 4];
                characters[(index * 2) + 1] = digits[bytes[index] & 0x0F];
            }
            return new string(characters);
        }

        private sealed class VerifierContext
        {
            internal VerifierContext(
                TrustedJsonObject authority,
                IDictionary<string, byte[]> projected)
            {
                Authority = authority;
                Projected = projected;
            }

            internal TrustedJsonObject Authority { get; private set; }

            internal IDictionary<string, byte[]> Projected { get; private set; }
        }
    }
}
