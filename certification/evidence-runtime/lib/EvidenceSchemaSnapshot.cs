using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Pspkt.Certification.EvidenceRuntime
{
    internal sealed class EvidenceSchemaSnapshot
    {
        private readonly Dictionary<ushort, string> _domains;
        private readonly Dictionary<ushort, string> _kindNames;
        private readonly Dictionary<string, XElement> _declarations;
        private readonly Dictionary<string, int> _primitiveWidths;

        private EvidenceSchemaSnapshot(XElement schema, XElement inventory, XElement protocolInventory)
        {
            _domains = new Dictionary<ushort, string>();
            _kindNames = new Dictionary<ushort, string>();
            _declarations = new Dictionary<string, XElement>(StringComparer.Ordinal);
            _primitiveWidths = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (XElement declaration in schema.Element("types").Elements("item"))
            {
                _declarations.Add(declaration.Element("name").Value, declaration);
            }
            foreach (XElement member in _declarations["EvidenceArtifactKind"].Element("members").Elements("item"))
            {
                ushort kind = ushort.Parse(member.Element("value").Value, CultureInfo.InvariantCulture);
                string name = member.Element("name").Value;
                _kindNames.Add(kind, name);
                _domains.Add(kind, inventory.Element("evidenceDomains").Element(name).Value);
            }
            foreach (XElement declaration in _declarations.Values)
            {
                XElement fields = declaration.Element("fields");
                if (fields == null) { continue; }
                foreach (XElement field in fields.Elements("item"))
                {
                    string primitive = field.Element("type").Value;
                    if (primitive == "BoundedBytes" || _declarations.ContainsKey(primitive) || _primitiveWidths.ContainsKey(primitive)) { continue; }
                    _primitiveWidths.Add(primitive, int.Parse(protocolInventory.Element("primitiveValueMaxima").Element(primitive).Value,
                        CultureInfo.InvariantCulture));
                }
            }
        }

        internal string GetDomain(ushort kind)
        {
            string domain;
            if (!_domains.TryGetValue(kind, out domain)) { throw new InvalidDataException("evidence-kind: Unknown evidence kind."); }
            return domain;
        }

        internal XElement GetDeclaration(ushort kind)
        {
            GetDomain(kind);
            return _declarations[_kindNames[kind]];
        }

        internal XElement GetDeclaration(string name)
        {
            XElement declaration;
            return _declarations.TryGetValue(name, out declaration) ? declaration : null;
        }

        internal int GetPrimitiveWidth(string name)
        {
            int width;
            if (!_primitiveWidths.TryGetValue(name, out width)) { throw new InvalidDataException("primitive-type: Unknown primitive."); }
            return width;
        }

        internal BigInteger GetMaximumPayloadLength(ushort kind, byte profile)
        {
            if (profile != 1 && profile != 2) { throw new InvalidDataException("evidence-profile: Profile must be 1 or 2."); }
            return GetMaximumDeclarationLength(GetDeclaration(kind), profile);
        }

        internal BigInteger GetMaximumDeclarationLength(XElement declaration, byte profile)
        {
            BigInteger total = BigInteger.Zero;
            foreach (XElement field in GetEffectiveFields(declaration, profile))
            {
                string type = field.Element("type").Value;
                XElement nested = GetDeclaration(type);
                BigInteger length;
                if (nested != null) { length = GetMaximumDeclarationLength(nested, profile); }
                else if (type == "BoundedBytes")
                {
                    length = new BigInteger(4) + BigInteger.Parse(field.Element("maxBytes").Value, CultureInfo.InvariantCulture);
                }
                else { length = new BigInteger(GetPrimitiveWidth(type)); }
                total += new BigInteger(6) + length;
            }
            return total;
        }

        internal static List<XElement> GetEffectiveFields(XElement declaration, byte profile)
        {
            string profileName = profile == 1 ? "InteractiveSeat" : "NonInteractiveElevated";
            Dictionary<string, List<XElement>> groups = new Dictionary<string, List<XElement>>(StringComparer.Ordinal);
            foreach (XElement field in declaration.Element("fields").Elements("item"))
            {
                XElement shape = new XElement(field);
                if (shape.Element("profile") != null) { shape.Element("profile").Remove(); }
                if (shape.Element("status") != null) { shape.Element("status").Remove(); }
                string key = shape.ToString(SaveOptions.DisableFormatting);
                List<XElement> group;
                if (!groups.TryGetValue(key, out group)) { group = new List<XElement>(); groups.Add(key, group); }
                group.Add(field);
            }
            List<XElement> selected = new List<XElement>();
            foreach (List<XElement> group in groups.Values)
            {
                List<XElement> required = new List<XElement>();
                foreach (XElement field in group)
                {
                    if (Optional(field, "status", "Required") != "Required") { continue; }
                    required.Add(field);
                    string scope = Optional(field, "profile", "Any");
                    if (scope == "Any" || scope == profileName) { selected.Add(field); }
                }
                foreach (XElement field in group)
                {
                    if (Optional(field, "status", "Required") != "Forbidden") { continue; }
                    if (required.Count == 0) { throw new InvalidDataException("field-shape: Forbidden field has no required shape."); }
                    string scope = Optional(field, "profile", "Any");
                    XElement applicable = null;
                    foreach (XElement candidate in required)
                    {
                        string candidateScope = Optional(candidate, "profile", "Any");
                        if (candidateScope != "Any" && candidateScope != scope) { continue; }
                        if (applicable != null) { throw new InvalidDataException("field-shape: Multiple required shapes apply."); }
                        applicable = candidate;
                    }
                    if (scope == profileName && applicable != null && !selected.Remove(applicable))
                    {
                        throw new InvalidDataException("field-shape: Forbidden override has no selected required field.");
                    }
                }
            }
            selected.Sort(delegate(XElement left, XElement right) {
                return int.Parse(left.Element("fieldId").Value, CultureInfo.InvariantCulture).CompareTo(
                    int.Parse(right.Element("fieldId").Value, CultureInfo.InvariantCulture));
            });
            return selected;
        }

        private static string Optional(XElement value, string name, string fallback)
        {
            XElement property = value.Element(name);
            return property == null ? fallback : property.Value;
        }

        internal static EvidenceSchemaSnapshot Create(byte[] metaBytes, byte[] protocolInventoryBytes,
            byte[] evidenceSchemaBytes, byte[] evidenceInventoryBytes)
        {
            byte[] meta = Retain(metaBytes, 4533,
                "ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85");
            byte[] protocolInventory = Retain(protocolInventoryBytes, 46479,
                "d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f");
            byte[] evidenceSchema = Retain(evidenceSchemaBytes, 22001,
                "49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6");
            byte[] evidenceInventory = Retain(evidenceInventoryBytes, 47347,
                "07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9");

            RequireAccepted(SchemaBootstrap.Evaluate("bootstrap-meta", meta, null));
            RequireAccepted(SchemaBootstrap.Evaluate("schema-against-meta", evidenceSchema, meta));
            RequireAccepted(SchemaBootstrap.Evaluate("json", evidenceInventory, null));
            RequireAccepted(SchemaBootstrap.Evaluate("json", protocolInventory, null));
            return new EvidenceSchemaSnapshot(EvidenceAuthorityJsonReader.Read(evidenceSchema),
                EvidenceAuthorityJsonReader.Read(evidenceInventory), EvidenceAuthorityJsonReader.Read(protocolInventory));
        }

        internal static string[] GetInputStages()
        {
            return new string[] {
                "meta:bootstrap-meta:null",
                "evidenceSchema:schema-against-meta:meta",
                "evidenceInventory:json:null",
                "protocolInventory:json:null"
            };
        }

        private static byte[] Retain(byte[] bytes, int length, string expectedDigest)
        {
            if (bytes == null) { throw new ArgumentNullException("bytes"); }
            if (bytes.Length != length) { throw new InvalidDataException("authority-length: Input byte length differs."); }
            byte[] retained = (byte[])bytes.Clone();
            byte[] digest;
            using (SHA256 algorithm = SHA256.Create()) { digest = algorithm.ComputeHash(retained); }
            StringBuilder hexadecimal = new StringBuilder(64);
            foreach (byte value in digest) { hexadecimal.Append(value.ToString("x2", CultureInfo.InvariantCulture)); }
            if (!string.Equals(hexadecimal.ToString(), expectedDigest, StringComparison.Ordinal))
            {
                throw new InvalidDataException("authority-pin: Input digest differs.");
            }
            return retained;
        }

        private static void RequireAccepted(SchemaCheckResult result)
        {
            if (!result.Accepted) { throw new InvalidDataException("authority-gate: " + result.Reason); }
        }
    }
}
