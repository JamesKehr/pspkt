using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Pspkt.Certification
{
    public sealed class HostClassifierVectorNativeV1 : IDisposable
    {
        private const string MarkerValue = "pspkt-host-classifier-vector-native-5";
        private const string VersionValue = "1";
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileBegin = 0;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const int JobObjectExtendedLimitInformation = 9;
        private const int ErrorSharingViolation = 32;
        private const int OpenFileAttemptCount = 20;
        private const int OpenFileRetryDelayMilliseconds = 50;

        private readonly SafeFileHandle _handle;
        private readonly string _path;
        private readonly bool _isDirectory;
        private bool _disposed;
        private uint _volumeSerialNumber;
        private ulong _fileIndex;
        private uint _numberOfLinks;
        private bool _isReparsePoint;

        private HostClassifierVectorNativeV1(SafeFileHandle handle, string path, bool isDirectory)
        {
            _handle = handle;
            _path = path;
            _isDirectory = isDirectory;
            _disposed = false;
            RefreshIdentity();
        }

        public static string BuildMarker
        {
            get { return MarkerValue; }
        }

        public static string TypeVersion
        {
            get { return VersionValue; }
        }

        public bool IsReparsePoint
        {
            get
            {
                ThrowIfDisposed();
                return _isReparsePoint;
            }
        }

        public uint VolumeSerialNumber
        {
            get
            {
                ThrowIfDisposed();
                return _volumeSerialNumber;
            }
        }

        public ulong FileIndex
        {
            get
            {
                ThrowIfDisposed();
                return _fileIndex;
            }
        }

        public uint NumberOfLinks
        {
            get
            {
                ThrowIfDisposed();
                return _numberOfLinks;
            }
        }

        public long Length
        {
            get
            {
                ThrowIfDisposed();
                ThrowIfDirectory("Length");
                return GetFileLength();
            }
        }

        public static ProcessJobV1 CreateProcessJob()
        {
            SafeFileHandle job = CreateJobObjectW(IntPtr.Zero, null);
            if (job.IsInvalid)
            {
                throw CreateNativeException("CreateJobObjectW", "process job");
            }

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(information, buffer, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
                {
                    throw CreateNativeException("SetInformationJobObject", "process job");
                }

                return new ProcessJobV1(job);
            }
            catch
            {
                job.Dispose();
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static HostClassifierVectorNativeV1 OpenDirectory(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("Directory path is required.", "path");
            }

            SafeFileHandle handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw CreateNativeException("CreateFileW", path);
            }

            try
            {
                return new HostClassifierVectorNativeV1(handle, path, true);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static HostClassifierVectorNativeV1 OpenFile(string path, bool writable)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("File path is required.", "path");
            }

            uint access = GenericRead;
            if (writable)
            {
                access = GenericRead | GenericWrite;
            }

            SafeFileHandle handle = null;
            for (int attempt = 0; attempt < OpenFileAttemptCount; attempt++)
            {
                handle = CreateFileW(
                    path,
                    access,
                    FileShareRead,
                    IntPtr.Zero,
                    OpenExisting,
                    FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                if (!handle.IsInvalid)
                {
                    break;
                }

                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                handle = null;
                if (error != ErrorSharingViolation || attempt == OpenFileAttemptCount - 1)
                {
                    throw CreateNativeException("CreateFileW", path, error);
                }

                System.Threading.Thread.Sleep(OpenFileRetryDelayMilliseconds);
            }

            if (handle == null || handle.IsInvalid)
            {
                throw new InvalidOperationException("CreateFileW retry state is invalid for '" + path + "'.");
            }

            try
            {
                return new HostClassifierVectorNativeV1(handle, path, false);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static Task<byte[]> ReadStreamCappedAsync(Stream stream, int maximumBytes)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            if (maximumBytes < 1)
            {
                throw new ArgumentOutOfRangeException("maximumBytes");
            }

            return ReadStreamCappedCoreAsync(stream, maximumBytes);
        }

        public byte[] ReadExact()
        {
            ThrowIfDisposed();
            ThrowIfDirectory("ReadExact");
            long length = GetFileLength();
            if (length < 0 || length > int.MaxValue)
            {
                throw new InvalidOperationException(
                    "ReadExact rejected length " + length.ToString(CultureInfo.InvariantCulture) + " for '" + _path + "'.");
            }

            return ReadExactCore((int)length);
        }

        public byte[] ReplaceExact(byte[] bytes)
        {
            ThrowIfDisposed();
            ThrowIfDirectory("ReplaceExact");
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            RefreshIdentity();
            uint originalVolumeSerialNumber = _volumeSerialNumber;
            ulong originalFileIndex = _fileIndex;
            ThrowIfUnsafeWritableIdentity();

            long newPointer;
            if (!SetFilePointerEx(_handle, 0, out newPointer, FileBegin))
            {
                throw CreateNativeException("SetFilePointerEx", _path);
            }

            if (!SetEndOfFile(_handle))
            {
                throw CreateNativeException("SetEndOfFile", _path);
            }

            WriteExactCore(bytes);

            if (!SetFilePointerEx(_handle, bytes.Length, out newPointer, FileBegin))
            {
                throw CreateNativeException("SetFilePointerEx", _path);
            }

            if (!SetEndOfFile(_handle))
            {
                throw CreateNativeException("SetEndOfFile", _path);
            }

            if (!FlushFileBuffers(_handle))
            {
                throw CreateNativeException("FlushFileBuffers", _path);
            }

            long length = GetFileLength();
            if (length != bytes.Length)
            {
                throw new InvalidOperationException(
                    "ReplaceExact final length " + length.ToString(CultureInfo.InvariantCulture) +
                    " does not match " + bytes.Length.ToString(CultureInfo.InvariantCulture) + " for '" + _path + "'.");
            }

            if (!SetFilePointerEx(_handle, 0, out newPointer, FileBegin))
            {
                throw CreateNativeException("SetFilePointerEx", _path);
            }

            byte[] written = ReadExactCore(bytes.Length);
            if (written.Length != bytes.Length)
            {
                throw new InvalidOperationException(
                    "ReplaceExact short re-read for '" + _path + "'.");
            }

            for (int index = 0; index < bytes.Length; index++)
            {
                if (written[index] != bytes[index])
                {
                    throw new InvalidOperationException(
                        "ReplaceExact re-read mismatch at index " + index.ToString(CultureInfo.InvariantCulture) +
                        " for '" + _path + "'.");
                }
            }

            RefreshIdentity();
            if (_volumeSerialNumber != originalVolumeSerialNumber || _fileIndex != originalFileIndex)
            {
                throw new InvalidOperationException(
                    "ReplaceExact changed file identity for '" + _path + "'.");
            }

            ThrowIfUnsafeWritableIdentity();
            return written;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_handle != null && !_handle.IsClosed)
            {
                _handle.Dispose();
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
        }

        private void ThrowIfDirectory(string operation)
        {
            if (_isDirectory)
            {
                throw new InvalidOperationException(
                    operation + " is not valid for directory '" + _path + "'.");
            }
        }

        private void RefreshIdentity()
        {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(_handle, out information))
            {
                throw CreateNativeException("GetFileInformationByHandle", _path);
            }

            _volumeSerialNumber = information.dwVolumeSerialNumber;
            _fileIndex = ((ulong)information.nFileIndexHigh << 32) | information.nFileIndexLow;
            _numberOfLinks = information.nNumberOfLinks;
            _isReparsePoint = (information.dwFileAttributes & FileAttributeReparsePoint) != 0;
        }

        private void ThrowIfUnsafeWritableIdentity()
        {
            if (_isReparsePoint)
            {
                throw new InvalidOperationException(
                    "ReplaceExact rejected a reparse point for '" + _path + "'.");
            }

            if (_numberOfLinks != 1)
            {
                throw new InvalidOperationException(
                    "ReplaceExact rejected link count " +
                    _numberOfLinks.ToString(CultureInfo.InvariantCulture) +
                    " for '" + _path + "'.");
            }
        }

        private long GetFileLength()
        {
            long length;
            if (!GetFileSizeEx(_handle, out length))
            {
                throw CreateNativeException("GetFileSizeEx", _path);
            }

            return length;
        }

        private byte[] ReadExactCore(int length)
        {
            long newPointer;
            if (!SetFilePointerEx(_handle, 0, out newPointer, FileBegin))
            {
                throw CreateNativeException("SetFilePointerEx", _path);
            }

            byte[] buffer = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int remaining = length - offset;
                byte[] chunk = new byte[remaining];
                uint read;
                if (!ReadFile(_handle, chunk, (uint)remaining, out read, IntPtr.Zero))
                {
                    throw CreateNativeException("ReadFile", _path);
                }

                if (read == 0 || read > remaining)
                {
                    throw new InvalidOperationException(
                        "ReadFile short read at offset " + offset.ToString(CultureInfo.InvariantCulture) +
                        " for '" + _path + "'.");
                }

                Buffer.BlockCopy(chunk, 0, buffer, offset, (int)read);
                offset += (int)read;
            }

            return buffer;
        }

        private void WriteExactCore(byte[] bytes)
        {
            int offset = 0;
            while (offset < bytes.Length)
            {
                int remaining = bytes.Length - offset;
                byte[] chunk = new byte[remaining];
                Buffer.BlockCopy(bytes, offset, chunk, 0, remaining);
                uint written;
                if (!WriteFile(_handle, chunk, (uint)remaining, out written, IntPtr.Zero))
                {
                    throw CreateNativeException("WriteFile", _path);
                }

                if (written == 0 || written > remaining)
                {
                    throw new InvalidOperationException(
                        "WriteFile short write at offset " + offset.ToString(CultureInfo.InvariantCulture) +
                        " for '" + _path + "'.");
                }

                offset += (int)written;
            }
        }

        private static Win32Exception CreateNativeException(string apiName, string path)
        {
            int error = Marshal.GetLastWin32Error();
            return CreateNativeException(apiName, path, error);
        }

        private static Win32Exception CreateNativeException(string apiName, string path, int error)
        {
            string message = apiName + " failed for '" + path + "' with Win32 error " +
                error.ToString(CultureInfo.InvariantCulture) + ".";
            return new Win32Exception(error, message);
        }

        private static async Task<byte[]> ReadStreamCappedCoreAsync(Stream stream, int maximumBytes)
        {
            MemoryStream output = new MemoryStream();
            try
            {
                byte[] buffer = new byte[8192];
                while (true)
                {
                    int read = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    if (output.Length + read > maximumBytes)
                    {
                        throw new InvalidDataException(
                            "Process output exceeded " + maximumBytes.ToString(CultureInfo.InvariantCulture) + " bytes.");
                    }

                    output.Write(buffer, 0, read);
                }

                return output.ToArray();
            }
            finally
            {
                output.Dispose();
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out BY_HANDLE_FILE_INFORMATION fileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileSizeEx(SafeFileHandle handle, out long fileSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFilePointerEx(
            SafeFileHandle handle,
            long distanceToMove,
            out long newFilePointer,
            uint moveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetEndOfFile(SafeFileHandle handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadFile(
            SafeFileHandle handle,
            byte[] buffer,
            uint numberOfBytesToRead,
            out uint numberOfBytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteFile(
            SafeFileHandle handle,
            byte[] buffer,
            uint numberOfBytesToWrite,
            out uint numberOfBytesWritten,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlushFileBuffers(SafeFileHandle handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateJobObjectW(
            IntPtr jobAttributes,
            string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            SafeFileHandle job,
            int informationClass,
            IntPtr information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(
            SafeFileHandle job,
            IntPtr process);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        public sealed class ProcessJobV1 : IDisposable
        {
            private readonly SafeFileHandle _job;
            private bool _disposed;

            internal ProcessJobV1(SafeFileHandle job)
            {
                _job = job;
            }

            public void AssignProcess(IntPtr processHandle)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(GetType().FullName);
                }

                if (processHandle == IntPtr.Zero)
                {
                    throw new ArgumentException("Process handle is required.", "processHandle");
                }

                if (!AssignProcessToJobObject(_job, processHandle))
                {
                    throw CreateNativeException("AssignProcessToJobObject", "process job");
                }
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                if (!_job.IsClosed)
                {
                    _job.Dispose();
                }
            }
        }
    }
}
