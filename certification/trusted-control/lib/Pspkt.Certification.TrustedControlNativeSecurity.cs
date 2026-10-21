using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Pspkt.Certification.TrustedControl
{
    public sealed class TrustedFileIdentity
    {
        internal TrustedFileIdentity(ulong volumeSerialNumber, string fileId)
        {
            VolumeSerialNumber = volumeSerialNumber;
            FileId = fileId;
        }

        public ulong VolumeSerialNumber { get; private set; }

        public string FileId { get; private set; }

        public override string ToString()
        {
            return VolumeSerialNumber.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + FileId;
        }
    }

    public sealed class TrustedJob : IDisposable
    {
        private IntPtr _handle;

        private TrustedJob(IntPtr handle)
        {
            _handle = handle;
        }

        public static TrustedJob CreateKillOnClose()
        {
            IntPtr handle = NativeMethods.CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");
            }
            NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION information =
                new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            information.BasicLimitInformation.LimitFlags =
                NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(information, buffer, false);
                if (!NativeMethods.SetInformationJobObject(
                    handle,
                    NativeMethods.JobObjectExtendedLimitInformation,
                    buffer,
                    (uint)size))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed.");
                }
            }
            catch
            {
                NativeMethods.CloseHandle(handle);
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return new TrustedJob(handle);
        }

        public void AssignProcess(IntPtr processHandle)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("TrustedJob");
            }
            if (!NativeMethods.AssignProcessToJobObject(_handle, processHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed.");
            }
        }

        public void Dispose()
        {
            IntPtr handle = _handle;
            _handle = IntPtr.Zero;
            if (handle != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(handle);
            }
        }
    }

    public static class TrustedControlNativeSecurity
    {
        public static IntPtr GetCurrentProcessHandle()
        {
            return NativeMethods.GetCurrentProcess();
        }

        public static TrustedFileIdentity GetIdentity(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid)
            {
                throw new ArgumentException("A valid file handle is required.", "handle");
            }
            NativeMethods.FILE_ID_INFO information = new NativeMethods.FILE_ID_INFO();
            int size = Marshal.SizeOf(typeof(NativeMethods.FILE_ID_INFO));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!NativeMethods.GetFileInformationByHandleEx(
                    handle,
                    NativeMethods.FileIdInfo,
                    buffer,
                    (uint)size))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandleEx(FileIdInfo) failed.");
                }
                information = (NativeMethods.FILE_ID_INFO)Marshal.PtrToStructure(
                    buffer,
                    typeof(NativeMethods.FILE_ID_INFO));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return new TrustedFileIdentity(
                information.VolumeSerialNumber,
                ToHex(information.FileId.Identifier));
        }

        public static string ComputeSha256(FileStream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            stream.Position = 0;
            using (SHA256 sha256 = SHA256.Create())
            {
                string result = ToHex(sha256.ComputeHash(stream));
                stream.Position = 0;
                return result;
            }
        }

        public static string ComputeSha256(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                return ToHex(sha256.ComputeHash(bytes));
            }
        }

        public static string ComputeMappedExecutableSha256(IntPtr processHandle, IntPtr imageBase)
        {
            if (processHandle == IntPtr.Zero)
            {
                throw new ArgumentException("A valid process handle is required.", "processHandle");
            }
            if (imageBase == IntPtr.Zero)
            {
                throw new ArgumentException("A valid image base is required.", "imageBase");
            }

            byte[] dosHeader = ReadProcessBytes(processHandle, imageBase, 64);
            int peOffset = ReadInt32LittleEndian(dosHeader, 60);
            if (peOffset < 64 || peOffset > 1048576)
            {
                throw new InvalidDataException("The mapped executable DOS header is invalid.");
            }
            byte[] peHeader = ReadProcessBytes(processHandle, Add(imageBase, peOffset), 24);
            if (peHeader[0] != (byte)'P' || peHeader[1] != (byte)'E'
                || peHeader[2] != 0 || peHeader[3] != 0)
            {
                throw new InvalidDataException("The mapped executable PE signature is invalid.");
            }
            int sectionCount = ReadUInt16LittleEndian(peHeader, 6);
            int optionalHeaderSize = ReadUInt16LittleEndian(peHeader, 20);
            if (sectionCount < 1 || sectionCount > 96 || optionalHeaderSize < 96)
            {
                throw new InvalidDataException("The mapped executable section table is invalid.");
            }

            IntPtr sectionTable = Add(imageBase, peOffset + 24 + optionalHeaderSize);
            using (SHA256 sha256 = SHA256.Create())
            {
                int executableSectionCount = 0;
                for (int index = 0; index < sectionCount; index++)
                {
                    byte[] sectionHeader = ReadProcessBytes(processHandle, Add(sectionTable, index * 40), 40);
                    uint virtualSize = ReadUInt32LittleEndian(sectionHeader, 8);
                    uint virtualAddress = ReadUInt32LittleEndian(sectionHeader, 12);
                    uint characteristics = ReadUInt32LittleEndian(sectionHeader, 36);
                    if ((characteristics & NativeMethods.IMAGE_SCN_MEM_EXECUTE) == 0 || virtualSize == 0)
                    {
                        continue;
                    }
                    if (virtualSize > int.MaxValue)
                    {
                        throw new InvalidDataException("The mapped executable section is too large.");
                    }
                    executableSectionCount++;
                    sha256.TransformBlock(sectionHeader, 0, sectionHeader.Length, null, 0);
                    byte[] sectionBytes = ReadProcessBytes(
                        processHandle,
                        Add(imageBase, checked((int)virtualAddress)),
                        checked((int)virtualSize));
                    sha256.TransformBlock(sectionBytes, 0, sectionBytes.Length, null, 0);
                }
                if (executableSectionCount == 0)
                {
                    throw new InvalidDataException("The mapped executable has no executable sections.");
                }
                sha256.TransformFinalBlock(new byte[0], 0, 0);
                return ToHex(sha256.Hash);
            }
        }

        public static void AssertNoModuleMethodDefinitions(byte[] assemblyBytes, string label)
        {
            GetMethodDefinitionCount(assemblyBytes, label);
        }

        public static int GetMethodDefinitionCount(byte[] assemblyBytes, string label)
        {
            return GetMethodDefinitionCount(assemblyBytes, label, null);
        }

        public static MethodImplRow[] GetMethodImplRows(byte[] assemblyBytes, string label)
        {
            List<MethodImplRow> rows = new List<MethodImplRow>();
            GetMethodDefinitionCount(assemblyBytes, label, rows);
            return rows.ToArray();
        }

        private static int GetMethodDefinitionCount(
            byte[] assemblyBytes,
            string label,
            List<MethodImplRow> methodImplRows)
        {
            if (assemblyBytes == null)
            {
                throw new ArgumentNullException("assemblyBytes");
            }
            if (string.IsNullOrEmpty(label))
            {
                throw new ArgumentException("A nonempty assembly label is required.", "label");
            }

            RequireRange(assemblyBytes, 60, 4, label);
            int peOffset = ReadInt32LittleEndian(assemblyBytes, 60);
            RequireRange(assemblyBytes, peOffset, 24, label);
            if (assemblyBytes[peOffset] != (byte)'P'
                || assemblyBytes[peOffset + 1] != (byte)'E'
                || assemblyBytes[peOffset + 2] != 0
                || assemblyBytes[peOffset + 3] != 0)
            {
                throw new InvalidDataException(label + " assembly PE signature is invalid.");
            }

            int sectionCount = ReadUInt16LittleEndian(assemblyBytes, peOffset + 6);
            int optionalHeaderSize = ReadUInt16LittleEndian(assemblyBytes, peOffset + 20);
            int optionalHeaderOffset = checked(peOffset + 24);
            RequireRange(assemblyBytes, optionalHeaderOffset, optionalHeaderSize, label);
            int optionalMagic = ReadUInt16LittleEndian(assemblyBytes, optionalHeaderOffset);
            int dataDirectoryOffset;
            int numberOfRvaAndSizesOffset;
            if (optionalMagic == 0x10b)
            {
                dataDirectoryOffset = checked(optionalHeaderOffset + 96);
                numberOfRvaAndSizesOffset = checked(optionalHeaderOffset + 92);
            }
            else if (optionalMagic == 0x20b)
            {
                dataDirectoryOffset = checked(optionalHeaderOffset + 112);
                numberOfRvaAndSizesOffset = checked(optionalHeaderOffset + 108);
            }
            else
            {
                throw new InvalidDataException(label + " assembly optional header is invalid.");
            }
            RequireRange(assemblyBytes, numberOfRvaAndSizesOffset, 4, label);
            if (ReadUInt32LittleEndian(assemblyBytes, numberOfRvaAndSizesOffset) <= 14)
            {
                throw new InvalidDataException(label + " assembly has no CLI data directory.");
            }
            int cliDirectoryOffset = checked(dataDirectoryOffset + (14 * 8));
            RequireRange(assemblyBytes, cliDirectoryOffset, 8, label);
            uint cliRva = ReadUInt32LittleEndian(assemblyBytes, cliDirectoryOffset);
            uint cliSize = ReadUInt32LittleEndian(assemblyBytes, cliDirectoryOffset + 4);
            int sectionTableOffset = checked(optionalHeaderOffset + optionalHeaderSize);
            int cliOffset = MapRvaToFileOffset(
                assemblyBytes,
                cliRva,
                cliSize,
                sectionTableOffset,
                sectionCount,
                label);
            RequireRange(assemblyBytes, cliOffset, 16, label);
            uint metadataRva = ReadUInt32LittleEndian(assemblyBytes, cliOffset + 8);
            uint metadataSize = ReadUInt32LittleEndian(assemblyBytes, cliOffset + 12);
            int metadataOffset = MapRvaToFileOffset(
                assemblyBytes,
                metadataRva,
                metadataSize,
                sectionTableOffset,
                sectionCount,
                label,
                true);
            if (metadataSize < 32 || (metadataOffset & 3) != 0)
            {
                throw new InvalidDataException(label + " assembly metadata directory A0 is invalid.");
            }
            RequireMetadataRootRange(assemblyBytes, metadataOffset, 16,
                metadataOffset, (int)metadataSize, label, "A0");
            if (ReadUInt32LittleEndian(assemblyBytes, metadataOffset) != 0x424a5342)
            {
                throw new InvalidDataException(label + " assembly metadata signature is invalid.");
            }

            uint versionLengthValue = ReadUInt32LittleEndian(assemblyBytes, metadataOffset + 12);
            if (versionLengthValue == 0 || versionLengthValue > 255 ||
                (versionLengthValue & 3) != 0)
            {
                throw new InvalidDataException(label + " assembly metadata directory A0 is invalid.");
            }
            int versionLength = (int)versionLengthValue;
            int streamHeaderOffset = Align4(checked(metadataOffset + 16 + versionLength));
            RequireMetadataRootRange(assemblyBytes, streamHeaderOffset, 4,
                metadataOffset, (int)metadataSize, label, "A0");
            if (ReadUInt16LittleEndian(assemblyBytes, streamHeaderOffset) != 0)
            {
                throw new InvalidDataException(label + " assembly metadata directory A0 is invalid.");
            }
            int streamCount = ReadUInt16LittleEndian(assemblyBytes, streamHeaderOffset + 2);
            if (streamCount > 32)
            {
                throw new InvalidDataException(label + " assembly metadata directory A0 is invalid.");
            }
            int cursor = checked(streamHeaderOffset + 4);
            List<MetadataStreamInfo> streams = new List<MetadataStreamInfo>();
            for (int streamIndex = 0; streamIndex < streamCount; streamIndex++)
            {
                RequireMetadataRootRange(assemblyBytes, cursor, 8,
                    metadataOffset, (int)metadataSize, label, "A0");
                uint relativeOffset = ReadUInt32LittleEndian(assemblyBytes, cursor);
                uint streamSize = ReadUInt32LittleEndian(assemblyBytes, cursor + 4);
                int nameStart = checked(cursor + 8);
                int nameEnd = nameStart;
                while ((long)nameEnd < (long)metadataOffset + metadataSize &&
                    nameEnd < assemblyBytes.Length &&
                    nameEnd - nameStart <= 32 &&
                    assemblyBytes[nameEnd] != 0)
                {
                    nameEnd++;
                }
                if (nameEnd == nameStart || nameEnd - nameStart > 32 ||
                    (long)nameEnd >= (long)metadataOffset + metadataSize ||
                    nameEnd >= assemblyBytes.Length || assemblyBytes[nameEnd] != 0)
                {
                    throw new InvalidDataException(label + " assembly metadata directory A0 is invalid.");
                }
                string streamName = Encoding.ASCII.GetString(
                    assemblyBytes,
                    nameStart,
                    nameEnd - nameStart);
                int nextHeader = Align4(checked(nameEnd + 1));
                RequireMetadataRootRange(assemblyBytes, nameEnd, nextHeader - nameEnd,
                    metadataOffset, (int)metadataSize, label, "A0");
                for (int padding = nameEnd + 1; padding < nextHeader; padding++)
                {
                    if (assemblyBytes[padding] != 0)
                    {
                        throw new InvalidDataException(
                            label + " assembly metadata directory A0 is invalid.");
                    }
                }
                streams.Add(new MetadataStreamInfo(
                    streamName, relativeOffset, streamSize));
                cursor = nextHeader;
            }
            int directoryEnd = cursor - metadataOffset;
            foreach (MetadataStreamInfo stream in streams)
            {
                if (stream.Size == 0 ||
                    stream.Size > int.MaxValue ||
                    stream.RelativeOffset < directoryEnd ||
                    (long)stream.RelativeOffset + stream.Size > metadataSize ||
                    (long)metadataOffset + stream.RelativeOffset > int.MaxValue)
                {
                    throw new InvalidDataException(label + " assembly metadata directory A1 is invalid.");
                }
                stream.Offset = checked(metadataOffset + (int)stream.RelativeOffset);
                if (stream.Name == "#~")
                {
                    if (stream.Size < 24 || (long)stream.Offset + 24 > assemblyBytes.LongLength)
                    {
                        throw new InvalidDataException(label + " assembly metadata directory A1 is invalid.");
                    }
                }
                else if ((long)stream.Offset + stream.Size > assemblyBytes.LongLength)
                {
                    throw new InvalidDataException(label + " assembly metadata directory A1 is invalid.");
                }
            }
            for (int left = 0; left < streams.Count; left++)
            {
                for (int right = left + 1; right < streams.Count; right++)
                {
                    if (streams[left].RelativeOffset <
                            (long)streams[right].RelativeOffset + streams[right].Size &&
                        streams[right].RelativeOffset <
                            (long)streams[left].RelativeOffset + streams[left].Size)
                    {
                        throw new InvalidDataException(
                            label + " assembly metadata directory A1 is invalid.");
                    }
                }
            }
            HashSet<string> streamNames = new HashSet<string>(StringComparer.Ordinal);
            MetadataStreamInfo tablesStream = null;
            MetadataStreamInfo stringsStream = null;
            foreach (MetadataStreamInfo stream in streams)
            {
                if (!streamNames.Add(stream.Name))
                {
                    throw new InvalidDataException(
                        label + " assembly metadata directory A2 has a duplicate stream.");
                }
            }
            if (streamNames.Contains("#-"))
            {
                throw new InvalidDataException(
                    label + " assembly metadata directory A3 uses unoptimized tables.");
            }
            foreach (string name in streamNames)
            {
                if (name != "#~" && name != "#Strings" && name != "#US" &&
                    name != "#GUID" && name != "#Blob")
                {
                    throw new InvalidDataException(
                        label + " assembly metadata directory A4 has an unknown stream.");
                }
            }
            if (streamNames.Count != 5 || !streamNames.Contains("#~") ||
                !streamNames.Contains("#Strings") || !streamNames.Contains("#US") ||
                !streamNames.Contains("#GUID") || !streamNames.Contains("#Blob"))
            {
                throw new InvalidDataException(
                    label + " assembly metadata directory A5 is incomplete.");
            }
            foreach (MetadataStreamInfo stream in streams)
            {
                if (stream.Name == "#~") { tablesStream = stream; }
                if (stream.Name == "#Strings") { stringsStream = stream; }
            }

            if (ReadUInt32LittleEndian(assemblyBytes, tablesStream.Offset) != 0 ||
                assemblyBytes[tablesStream.Offset + 4] != 2 ||
                assemblyBytes[tablesStream.Offset + 5] != 0 ||
                assemblyBytes[tablesStream.Offset + 7] != 1)
            {
                throw new InvalidDataException(label + " assembly metadata #~ header is invalid.");
            }
            byte heapSizes = assemblyBytes[tablesStream.Offset + 6];
            if ((heapSizes & ~7) != 0)
            {
                throw new InvalidDataException(label + " assembly metadata #~ header is invalid.");
            }
            ulong validTables = ReadUInt64LittleEndian(assemblyBytes, tablesStream.Offset + 8);
            ulong sortedTables = ReadUInt64LittleEndian(assemblyBytes, tablesStream.Offset + 16);
            ulong supportedTables = (1UL << 45) - 1;
            ulong unsupportedTables = (1UL << 3) | (1UL << 5) | (1UL << 7) |
                (1UL << 19) | (1UL << 22) | (1UL << 30) | (1UL << 31);
            if (((validTables | sortedTables) & ~supportedTables) != 0 ||
                ((validTables | sortedTables) & unsupportedTables) != 0)
            {
                throw new InvalidDataException(
                    label + " assembly metadata #~ table mask is unsupported.");
            }
            uint[] rowCounts = new uint[45];
            cursor = checked(tablesStream.Offset + 24);
            for (int tableIndex = 0; tableIndex < rowCounts.Length; tableIndex++)
            {
                if ((validTables & (1UL << tableIndex)) == 0)
                {
                    continue;
                }
                if ((long)cursor + 4 > (long)tablesStream.Offset + tablesStream.Size ||
                    (long)cursor + 4 > assemblyBytes.LongLength)
                {
                    throw new InvalidDataException(
                        label + " assembly metadata stream is truncated: #~ row counts.");
                }
                rowCounts[tableIndex] = ReadUInt32LittleEndian(assemblyBytes, cursor);
                if (rowCounts[tableIndex] > 0x00ffffff)
                {
                    throw new InvalidDataException(
                        label + " assembly metadata #~ row count is unsupported.");
                }
                cursor = checked(cursor + 4);
            }
            if (rowCounts[2] == 0)
            {
                throw new InvalidDataException(label + " assembly has no TypeDef table.");
            }

            int stringIndexSize = (heapSizes & 0x01) == 0 ? 2 : 4;
            int guidIndexSize = (heapSizes & 0x02) == 0 ? 2 : 4;
            int blobIndexSize = (heapSizes & 0x04) == 0 ? 2 : 4;
            long tableExtent = cursor - (long)tablesStream.Offset;
            for (int tableIndex = 0; tableIndex < rowCounts.Length; tableIndex++)
            {
                if ((validTables & (1UL << tableIndex)) != 0)
                {
                    tableExtent = checked(tableExtent + checked(
                        (long)rowCounts[tableIndex] * GetMetadataTableRowSize(
                            tableIndex, rowCounts, stringIndexSize,
                            guidIndexSize, blobIndexSize)));
                }
            }
            if (tableExtent > tablesStream.Size)
            {
                throw new InvalidDataException(
                    label + " assembly metadata table extent exceeds declared #~ stream.");
            }
            long physicalExtent = assemblyBytes.LongLength - tablesStream.Offset;
            if (tableExtent > physicalExtent)
            {
                throw new InvalidDataException(
                    label + " assembly metadata table extent exceeds physical #~ stream.");
            }
            if (tablesStream.Size > physicalExtent)
            {
                throw new InvalidDataException(
                    label + " assembly metadata #~ padding is truncated.");
            }
            int moduleRowSize = GetMetadataTableRowSize(
                0, rowCounts, stringIndexSize, guidIndexSize, blobIndexSize);
            int typeRefRowSize = GetMetadataTableRowSize(
                1, rowCounts, stringIndexSize, guidIndexSize, blobIndexSize);
            int fieldIndexSize = GetTableIndexSize(rowCounts[4]);
            int methodIndexSize = GetTableIndexSize(rowCounts[6]);
            int typeDefRowSize = GetMetadataTableRowSize(
                2, rowCounts, stringIndexSize, guidIndexSize, blobIndexSize);
            long typeDefTableOffsetLong = cursor
                + ((long)rowCounts[0] * moduleRowSize)
                + ((long)rowCounts[1] * typeRefRowSize);
            if (typeDefTableOffsetLong > int.MaxValue)
            {
                throw new InvalidDataException(label + " assembly TypeDef table is too large.");
            }
            int typeDefTableOffset = (int)typeDefTableOffsetLong;
            long typeDefTableSize = (long)typeDefRowSize * rowCounts[2];
            if (typeDefTableSize > int.MaxValue)
            {
                throw new InvalidDataException(label + " assembly TypeDef table is too large.");
            }
            RequireContainedRange(
                assemblyBytes,
                typeDefTableOffset,
                (int)typeDefTableSize,
                tablesStream.Offset,
                checked((int)tablesStream.Size),
                label);
            int nameIndexOffset = checked(typeDefTableOffset + 4);
            uint moduleNameIndex = ReadMetadataIndex(
                assemblyBytes,
                nameIndexOffset,
                stringIndexSize,
                label);
            string moduleTypeName = ReadMetadataString(
                assemblyBytes,
                stringsStream,
                moduleNameIndex,
                label);
            if (!string.Equals(moduleTypeName, "<Module>", StringComparison.Ordinal))
            {
                throw new InvalidDataException(label + " assembly first TypeDef is not <Module>.");
            }

            int methodListOffset = checked(
                typeDefTableOffset
                + 4
                + (stringIndexSize * 2)
                + GetCodedIndexSize(rowCounts, new int[] { 2, 1, 27 }, 2)
                + fieldIndexSize);
            uint moduleMethodStart = ReadMetadataIndex(
                assemblyBytes,
                methodListOffset,
                methodIndexSize,
                label);
            uint nextTypeMethodStart;
            if (rowCounts[2] > 1)
            {
                int nextTypeOffset = checked(typeDefTableOffset + typeDefRowSize);
                nextTypeMethodStart = ReadMetadataIndex(
                    assemblyBytes,
                    checked(nextTypeOffset
                        + 4
                        + (stringIndexSize * 2)
                        + GetCodedIndexSize(rowCounts, new int[] { 2, 1, 27 }, 2)
                        + fieldIndexSize),
                    methodIndexSize,
                    label);
            }
            else
            {
                nextTypeMethodStart = checked(rowCounts[6] + 1);
            }
            uint methodLimit = checked(rowCounts[6] + 1);
            if (moduleMethodStart == 0
                || moduleMethodStart > methodLimit
                || nextTypeMethodStart < moduleMethodStart
                || nextTypeMethodStart > methodLimit)
            {
                throw new InvalidDataException(label + " assembly MethodList range is invalid.");
            }
            if (nextTypeMethodStart != moduleMethodStart)
            {
                throw new InvalidDataException(
                    label + " assembly contains forbidden module method definitions.");
            }
            if (methodImplRows != null)
            {
                if (rowCounts[25] > 16384)
                {
                    throw new InvalidDataException(label + " assembly MethodImpl row count is unsupported.");
                }
                long methodImplOffset = cursor;
                for (int tableIndex = 0; tableIndex < 25; tableIndex++)
                {
                    methodImplOffset = checked(methodImplOffset +
                        (long)rowCounts[tableIndex] * GetMetadataTableRowSize(
                            tableIndex, rowCounts, stringIndexSize,
                            guidIndexSize, blobIndexSize));
                }
                int classWidth = GetTableIndexSize(rowCounts[2]);
                int methodWidth = GetCodedIndexSize(rowCounts, new int[] { 6, 10 }, 1);
                int rowWidth = checked(classWidth + (2 * methodWidth));
                RequireContainedRange(
                    assemblyBytes,
                    checked((int)methodImplOffset),
                    checked((int)(rowCounts[25] * rowWidth)),
                    tablesStream.Offset,
                    checked((int)tablesStream.Size),
                    label);
                for (int row = 0; row < rowCounts[25]; row++)
                {
                    int rowOffset = checked((int)methodImplOffset + (row * rowWidth));
                    uint classIndex = ReadMetadataIndex(
                        assemblyBytes, rowOffset, classWidth, label);
                    uint bodyIndex = ReadMetadataIndex(
                        assemblyBytes, rowOffset + classWidth, methodWidth, label);
                    uint declarationIndex = ReadMetadataIndex(
                        assemblyBytes, rowOffset + classWidth + methodWidth, methodWidth, label);
                    if (classIndex <= 1 || classIndex > rowCounts[2])
                    {
                        throw new InvalidDataException(label + " assembly MethodImpl Class is invalid.");
                    }
                    methodImplRows.Add(new MethodImplRow(
                        0x02000000 | checked((int)classIndex),
                        DecodeMethodDefOrRefToken(bodyIndex, rowCounts, label),
                        DecodeMethodDefOrRefToken(declarationIndex, rowCounts, label),
                        rowOffset));
                }
            }
            return checked((int)rowCounts[6]);
        }

        public static string GetProcessImagePath(IntPtr processHandle)
        {
            StringBuilder builder = new StringBuilder(32768);
            uint size = (uint)builder.Capacity;
            if (!NativeMethods.QueryFullProcessImageName(processHandle, 0, builder, ref size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryFullProcessImageName failed.");
            }
            return builder.ToString();
        }

        public static IntPtr GetProcessImageBase(IntPtr processHandle)
        {
            int lastError = 0;
            for (int attempt = 0; attempt < 200; attempt++)
            {
                IntPtr[] modules = new IntPtr[1];
                uint bytesNeeded;
                if (NativeMethods.EnumProcessModules(
                    processHandle,
                    modules,
                    (uint)IntPtr.Size,
                    out bytesNeeded)
                    && bytesNeeded >= (uint)IntPtr.Size
                    && modules[0] != IntPtr.Zero)
                {
                    return modules[0];
                }
                lastError = Marshal.GetLastWin32Error();
                System.Threading.Thread.Sleep(5);
            }
            throw new Win32Exception(lastError, "EnumProcessModules failed.");
        }

        private static IntPtr Add(IntPtr value, int offset)
        {
            return new IntPtr(checked(value.ToInt64() + offset));
        }

        private static int Align4(int value)
        {
            return checked((value + 3) & ~3);
        }

        private static int GetCodedIndexSize(
            uint[] rowCounts,
            int[] tableIndexes,
            int tagBits)
        {
            uint maximumRows = 0;
            for (int index = 0; index < tableIndexes.Length; index++)
            {
                if (rowCounts[tableIndexes[index]] > maximumRows)
                {
                    maximumRows = rowCounts[tableIndexes[index]];
                }
            }
            uint smallLimit = 1U << (16 - tagBits);
            return maximumRows < smallLimit ? 2 : 4;
        }

        private static int GetTableIndexSize(uint rowCount)
        {
            return rowCount < 65536 ? 2 : 4;
        }

        private static int DecodeMethodDefOrRefToken(uint index, uint[] rowCounts, string label)
        {
            int table = (index & 1) == 0 ? 6 : 10;
            uint row = index >> 1;
            if (row == 0 || row > rowCounts[table])
            {
                throw new InvalidDataException(label + " assembly MethodImpl method index is invalid.");
            }
            return (table << 24) | checked((int)row);
        }

        private static int GetMetadataTableRowSize(
            int table,
            uint[] rows,
            int strings,
            int guids,
            int blobs)
        {
            switch (table)
            {
                case 0: return 2 + strings + (3 * guids);
                case 1: return GetCodedIndexSize(rows, new int[] { 0, 26, 35, 1 }, 2) + (2 * strings);
                case 2: return 4 + (2 * strings) +
                    GetCodedIndexSize(rows, new int[] { 2, 1, 27 }, 2) +
                    GetTableIndexSize(rows[4]) + GetTableIndexSize(rows[6]);
                case 3: return GetTableIndexSize(rows[4]);
                case 4: return 2 + strings + blobs;
                case 5: return GetTableIndexSize(rows[6]);
                case 6: return 8 + strings + blobs + GetTableIndexSize(rows[8]);
                case 7: return GetTableIndexSize(rows[8]);
                case 8: return 4 + strings;
                case 9: return GetTableIndexSize(rows[2]) +
                    GetCodedIndexSize(rows, new int[] { 2, 1, 27 }, 2);
                case 10: return GetCodedIndexSize(rows, new int[] { 2, 1, 26, 6, 27 }, 3) +
                    strings + blobs;
                case 11: return 2 +
                    GetCodedIndexSize(rows, new int[] { 4, 8, 23 }, 2) + blobs;
                case 12: return
                    GetCodedIndexSize(rows, new int[] {
                        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17,
                        26, 27, 32, 35, 38, 39, 40, 42, 44, 43 }, 5) +
                    GetCodedIndexSize(rows, new int[] { 6, 10 }, 3) + blobs;
                case 13: return GetCodedIndexSize(rows, new int[] { 4, 8 }, 1) + blobs;
                case 14: return 2 +
                    GetCodedIndexSize(rows, new int[] { 2, 6, 32 }, 2) + blobs;
                case 15: return 6 + GetTableIndexSize(rows[2]);
                case 16: return 4 + GetTableIndexSize(rows[4]);
                case 17: return blobs;
                case 18: return GetTableIndexSize(rows[2]) + GetTableIndexSize(rows[20]);
                case 19: return GetTableIndexSize(rows[20]);
                case 20: return 2 + strings +
                    GetCodedIndexSize(rows, new int[] { 2, 1, 27 }, 2);
                case 21: return GetTableIndexSize(rows[2]) + GetTableIndexSize(rows[23]);
                case 22: return GetTableIndexSize(rows[23]);
                case 23: return 2 + strings + blobs;
                case 24: return 2 + GetTableIndexSize(rows[6]) +
                    GetCodedIndexSize(rows, new int[] { 20, 23 }, 1);
                case 25: return GetTableIndexSize(rows[2]) +
                    (2 * GetCodedIndexSize(rows, new int[] { 6, 10 }, 1));
                case 26: return strings;
                case 27: return blobs;
                case 28: return 2 +
                    GetCodedIndexSize(rows, new int[] { 4, 6 }, 1) +
                    strings + GetTableIndexSize(rows[26]);
                case 29: return 4 + GetTableIndexSize(rows[4]);
                case 30: return 8;
                case 31: return 4;
                case 32: return 16 + blobs + (2 * strings);
                case 33: return 4;
                case 34: return 12;
                case 35: return 12 + (2 * blobs) + (2 * strings);
                case 36: return 4 + GetTableIndexSize(rows[35]);
                case 37: return 12 + GetTableIndexSize(rows[35]);
                case 38: return 4 + strings + blobs;
                case 39: return 8 + (2 * strings) +
                    GetCodedIndexSize(rows, new int[] { 38, 35, 39 }, 2);
                case 40: return 8 + strings +
                    GetCodedIndexSize(rows, new int[] { 38, 35, 39 }, 2);
                case 41: return 2 * GetTableIndexSize(rows[2]);
                case 42: return 4 +
                    GetCodedIndexSize(rows, new int[] { 2, 6 }, 1) + strings;
                case 43: return
                    GetCodedIndexSize(rows, new int[] { 6, 10 }, 1) + blobs;
                case 44: return GetTableIndexSize(rows[42]) +
                    GetCodedIndexSize(rows, new int[] { 2, 1, 27 }, 2);
                default:
                    throw new InvalidDataException("Assembly metadata table is unsupported.");
            }
        }

        private static int MapRvaToFileOffset(
            byte[] bytes,
            uint rva,
            uint size,
            int sectionTableOffset,
            int sectionCount,
            string label,
            bool allowTruncatedPhysical = false)
        {
            if (size > int.MaxValue)
            {
                throw new InvalidDataException(label + " assembly data directory is too large.");
            }
            for (int sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++)
            {
                int sectionOffset = checked(sectionTableOffset + (sectionIndex * 40));
                RequireRange(bytes, sectionOffset, 40, label);
                uint virtualSize = ReadUInt32LittleEndian(bytes, sectionOffset + 8);
                uint virtualAddress = ReadUInt32LittleEndian(bytes, sectionOffset + 12);
                uint rawSize = ReadUInt32LittleEndian(bytes, sectionOffset + 16);
                uint rawOffset = ReadUInt32LittleEndian(bytes, sectionOffset + 20);
                uint span = virtualSize > rawSize ? virtualSize : rawSize;
                if (rva < virtualAddress || rva - virtualAddress >= span)
                {
                    continue;
                }
                uint delta = rva - virtualAddress;
                if (delta > rawSize || size > rawSize - delta)
                {
                    throw new InvalidDataException(
                        label + " assembly data directory exceeds its section.");
                }
                long fileOffset = (long)rawOffset + delta;
                if (fileOffset > int.MaxValue)
                {
                    throw new InvalidDataException(
                        label + " assembly data directory offset is too large.");
                }
                RequireRange(
                    bytes, (int)fileOffset,
                    allowTruncatedPhysical ? Math.Min((int)size, 32) : (int)size,
                    label);
                return (int)fileOffset;
            }
            throw new InvalidDataException(label + " assembly RVA is outside its sections.");
        }

        private static uint ReadMetadataIndex(
            byte[] bytes,
            int offset,
            int size,
            string label)
        {
            RequireRange(bytes, offset, size, label);
            if (size == 2)
            {
                return ReadUInt16LittleEndian(bytes, offset);
            }
            if (size == 4)
            {
                return ReadUInt32LittleEndian(bytes, offset);
            }
            throw new InvalidDataException(label + " assembly metadata index size is invalid.");
        }

        private static string ReadMetadataString(
            byte[] bytes,
            MetadataStreamInfo stringsStream,
            uint index,
            string label)
        {
            if (index >= stringsStream.Size)
            {
                throw new InvalidDataException(label + " assembly string index is invalid.");
            }
            int start = checked(stringsStream.Offset + (int)index);
            int end = start;
            int limit = checked(stringsStream.Offset + checked((int)stringsStream.Size));
            while (end < limit && bytes[end] != 0)
            {
                end++;
            }
            if (end >= limit)
            {
                throw new InvalidDataException(label + " assembly metadata string is unterminated.");
            }
            return new UTF8Encoding(false, true).GetString(bytes, start, end - start);
        }

        private static int ReadInt32LittleEndian(byte[] bytes, int offset)
        {
            return bytes[offset]
                | (bytes[offset + 1] << 8)
                | (bytes[offset + 2] << 16)
                | (bytes[offset + 3] << 24);
        }

        private static byte[] ReadProcessBytes(IntPtr processHandle, IntPtr address, int count)
        {
            byte[] bytes = new byte[count];
            UIntPtr bytesRead;
            if (!NativeMethods.ReadProcessMemory(
                processHandle,
                address,
                bytes,
                new UIntPtr((uint)count),
                out bytesRead)
                || bytesRead.ToUInt64() != (ulong)count)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed.");
            }
            return bytes;
        }

        private static ushort ReadUInt16LittleEndian(byte[] bytes, int offset)
        {
            return (ushort)(bytes[offset] | (bytes[offset + 1] << 8));
        }

        private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        {
            return (uint)(bytes[offset]
                | (bytes[offset + 1] << 8)
                | (bytes[offset + 2] << 16)
                | (bytes[offset + 3] << 24));
        }

        private static ulong ReadUInt64LittleEndian(byte[] bytes, int offset)
        {
            uint lower = ReadUInt32LittleEndian(bytes, offset);
            uint upper = ReadUInt32LittleEndian(bytes, offset + 4);
            return lower | ((ulong)upper << 32);
        }

        private static void RequireRange(byte[] bytes, int offset, int count, string label)
        {
            if (offset < 0
                || count < 0
                || (long)offset + count > bytes.LongLength)
            {
                throw new InvalidDataException(label + " assembly metadata is truncated.");
            }
        }

        private static void RequireMetadataRootRange(
            byte[] bytes,
            int offset,
            int count,
            int rootOffset,
            int rootSize,
            string label,
            string stage)
        {
            if (offset < rootOffset || count < 0 ||
                (long)offset + count > (long)rootOffset + rootSize ||
                (long)offset + count > bytes.LongLength)
            {
                throw new InvalidDataException(
                    label + " assembly metadata directory " + stage + " is invalid.");
            }
        }

        private static void RequireContainedRange(
            byte[] bytes,
            int offset,
            int count,
            int containerOffset,
            int containerSize,
            string label)
        {
            RequireRange(bytes, containerOffset, containerSize, label);
            RequireRange(bytes, offset, count, label);
            if (offset < containerOffset
                || (long)offset + count > (long)containerOffset + containerSize)
            {
                throw new InvalidDataException(
                    label + " assembly metadata stream is truncated.");
            }
        }

        private static string ToHex(byte[] bytes)
        {
            StringBuilder builder = new StringBuilder(bytes.Length * 2);
            for (int index = 0; index < bytes.Length; index++)
            {
                builder.Append(bytes[index].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
            }
            return builder.ToString();
        }

        public sealed class MethodImplRow
        {
            internal MethodImplRow(
                int classToken,
                int methodBodyToken,
                int methodDeclarationToken,
                int fileOffset)
            {
                ClassToken = classToken;
                MethodBodyToken = methodBodyToken;
                MethodDeclarationToken = methodDeclarationToken;
                FileOffset = fileOffset;
            }

            public int ClassToken { get; private set; }

            public int MethodBodyToken { get; private set; }

            public int MethodDeclarationToken { get; private set; }

            public int FileOffset { get; private set; }
        }

        private sealed class MetadataStreamInfo
        {
            internal MetadataStreamInfo(string name, uint relativeOffset, uint size)
            {
                Name = name;
                RelativeOffset = relativeOffset;
                Size = size;
            }

            internal string Name { get; private set; }

            internal uint RelativeOffset { get; private set; }

            internal int Offset { get; set; }

            internal uint Size { get; private set; }
        }
    }

    internal static class NativeMethods
    {
        internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        internal const int JobObjectExtendedLimitInformation = 9;
        internal const int FileIdInfo = 18;
        internal const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

        [StructLayout(LayoutKind.Sequential)]
        internal struct FILE_ID_128
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            internal byte[] Identifier;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FILE_ID_INFO
        {
            internal ulong VolumeSerialNumber;
            internal FILE_ID_128 FileId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IO_COUNTERS
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            internal IO_COUNTERS IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            IntPtr information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int informationClass,
            IntPtr information,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            IntPtr process,
            uint flags,
            StringBuilder executableName,
            ref uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ReadProcessMemory(
            IntPtr process,
            IntPtr baseAddress,
            [Out] byte[] buffer,
            UIntPtr size,
            out UIntPtr bytesRead);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool EnumProcessModules(
            IntPtr process,
            [Out] IntPtr[] modules,
            uint bytesAvailable,
            out uint bytesNeeded);
    }
}
