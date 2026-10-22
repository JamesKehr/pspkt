using System.Globalization;
using System.IO;
using System.Xml.Linq;

namespace Pspkt.Certification.EvidenceRuntime
{
    internal static class EvidencePayloadCodec
    {
        internal static void Validate(EvidenceSchemaSnapshot schema, ushort kind, byte profile, byte[] payload)
        {
            ValidateDeclaration(schema, schema.GetDeclaration(kind), profile, payload);
        }

        private static void ValidateDeclaration(EvidenceSchemaSnapshot schema, XElement declaration, byte profile, byte[] payload)
        {
            EvidenceTlvCursor cursor = new EvidenceTlvCursor(payload);
            foreach (XElement field in EvidenceSchemaSnapshot.GetEffectiveFields(declaration, profile))
            {
                ushort tag = ushort.Parse(field.Element("fieldId").Value, CultureInfo.InvariantCulture);
                string type = field.Element("type").Value;
                XElement nested = schema.GetDeclaration(type);
                int minimumLength;
                int maximumLength;
                if (nested != null) { minimumLength = 0; maximumLength = checked((int)schema.GetMaximumDeclarationLength(nested, profile)); }
                else if (type == "BoundedBytes")
                {
                    minimumLength = 4;
                    maximumLength = 4 + int.Parse(field.Element("maxBytes").Value, CultureInfo.InvariantCulture);
                }
                else if (type == "AsciiIdentifier") { minimumLength = 1; maximumLength = schema.GetPrimitiveWidth(type); }
                else if (type == "BinarySid") { minimumLength = 8; maximumLength = schema.GetPrimitiveWidth(type); }
                else { minimumLength = schema.GetPrimitiveWidth(type); maximumLength = minimumLength; }
                byte[] value = cursor.ReadField(tag, minimumLength, maximumLength);
                if (nested != null)
                {
                    ValidateDeclaration(schema, nested, profile, value);
                }
                else if (type == "BoundedBytes")
                {
                    uint length = EvidenceTlvCursor.ReadUInt32(value, 0);
                    int maximum = int.Parse(field.Element("maxBytes").Value, CultureInfo.InvariantCulture);
                    if (length != (uint)(value.Length - 4) || length > maximum)
                    {
                        throw new InvalidDataException("bounded-length: Inner byte length differs.");
                    }
                }
                else { ValidatePrimitive(type, value, schema.GetPrimitiveWidth(type)); }
                if (field.Element("name").Value == "profile" && (value.Length != 1 || value[0] != profile))
                {
                    throw new InvalidDataException("nested-profile: Payload profile differs from the envelope.");
                }
            }
            if (!cursor.AtEnd) { throw new InvalidDataException("tlv-trailing: Payload contains unexpected fields."); }
        }

        internal static void ValidatePrimitive(string type, byte[] value, int maximum)
        {
            if (type == "AsciiIdentifier")
            {
                if (value.Length == 0 || value.Length > maximum) { throw new InvalidDataException("ascii-identifier: Byte length is outside 1 through 128."); }
                foreach (byte character in value)
                {
                    if (character == 0 || character > 127) { throw new InvalidDataException("ascii-identifier: Value must contain non-NUL seven-bit bytes."); }
                }
            }
            else if (type == "BinarySid")
            {
                if (value.Length < 8 || value.Length > maximum || value[0] != 1 || value[1] > 15 ||
                    value.Length != 8 + 4 * value[1])
                {
                    throw new InvalidDataException("binary-sid: Revision count or byte length differs.");
                }
            }
            else if (value.Length != maximum)
            {
                throw new InvalidDataException("primitive-width: Fixed primitive width differs.");
            }
        }
    }
}
