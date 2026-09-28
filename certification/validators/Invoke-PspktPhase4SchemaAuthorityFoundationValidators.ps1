#Requires -Version 5.1

<#
.SYNOPSIS
Validates and publishes the Foundation schema authority with recoverable receipts.
.NOTES
Journal publication requires one local fixed-drive root with no reparse points.
Different drive aliases, UNC, device, network and removable destinations are unsupported.
Both PowerShell editions enforce 259 UTF-16 characters for files and 247 for
directories, including temporary names, so Core transactions remain recoverable on
Windows PowerShell. Use shorter paths before starting a new transaction.
Unsupported existing journals are preserved without repair or automatic relocation.
#>
[CmdletBinding(DefaultParameterSetName = 'ReplayPrecommitMode')]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,
    [Parameter(Mandatory = $true)]
    [string]$ScratchRoot,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [string]$SourceRoot,
    [Parameter(Mandatory = $true)]
    [string]$PrestatePath,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecoveryMode', Mandatory = $true)]
    [string]$InitReceiptPath,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecoveryMode', Mandatory = $true)]
    [string]$ReplayReceiptPath,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecoveryMode', Mandatory = $true)]
    [string]$RecoveryJournalPath,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RecoveryMode', Mandatory = $true)]
    [string]$CompletionReceiptPath,
    [Parameter(ParameterSetName = 'CapturePrestateMode', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$FoundationCapturePrestate,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$FoundationInit,
    [Parameter(ParameterSetName = 'InitMode', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$Promote,
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$FoundationReplay,
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [ValidateScript({ $_ -cmatch '^[0-9a-f]{40}$' })]
    [string]$SelectedTreeOid,
    [Parameter(ParameterSetName = 'ReplayPrecommitMode', Mandatory = $true)]
    [ValidateScript({ $_ -cmatch '^[0-9a-f]{40}$' })]
    [string]$SelectedMapBlobOid,
    [Parameter(ParameterSetName = 'ReplayCommitMode', Mandatory = $true)]
    [ValidateScript({ $_ -cmatch '^[0-9a-f]{40}$' })]
    [string]$SelectedCommitOid,
    [Parameter(ParameterSetName = 'RecoveryMode', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$FoundationRecover,
    [Parameter(ParameterSetName = 'RecoveryMode', Mandatory = $true)]
    [ValidateSet('Finalize','Rollback')]
    [string]$RecoveryAction,
    [Parameter(ParameterSetName = 'RecoveryMode')]
    [string]$RecoveredCompletionReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:WindowsRoot = [IO.Directory]::GetParent([Environment]::SystemDirectory).FullName
$env:SystemRoot = $script:WindowsRoot
$env:WINDIR = $script:WindowsRoot

function Assert-FoundationPortablePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [string]$Role = 'file',
        [switch]$Directory,
        [switch]$PassThru
    )

    $maximumLength = if ($Directory) { 247 } else { 259 }
    try { $fullPath = [IO.Path]::GetFullPath($LiteralPath) }
    catch [IO.PathTooLongException] {
        throw [IO.PathTooLongException]::new("Portable path budget exceeded: $Role '$LiteralPath' ($($LiteralPath.Length) UTF-16 characters before normalization; limit $maximumLength). Use a shorter path; existing journals must be preserved.", $_.Exception)
    }
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ($Directory -and $fullPath -ine $root) { $fullPath = $fullPath.TrimEnd('\') }
    if ($fullPath.Length -gt $maximumLength) {
        throw [IO.PathTooLongException]::new("Portable path budget exceeded: $Role '$fullPath' ($($fullPath.Length) UTF-16 characters; limit $maximumLength). Use a shorter path; existing journals must be preserved.")
    }
    if ($fullPath -ine $root) {
        $parent = [IO.Path]::GetDirectoryName($fullPath)
        if (-not [string]::IsNullOrEmpty($parent) -and $parent.Length -gt 247) {
            Assert-FoundationPortablePath -LiteralPath $parent -Role "$Role parent" -Directory
        }
    }
    if ($PassThru) { return $fullPath }
}

$RepositoryRoot = Assert-FoundationPortablePath -LiteralPath $RepositoryRoot -Role RepositoryRoot -Directory -PassThru
$ScratchRoot = Assert-FoundationPortablePath -LiteralPath $ScratchRoot -Role ScratchRoot -Directory -PassThru
$PrestatePath = Assert-FoundationPortablePath -LiteralPath $PrestatePath -Role PrestatePath -PassThru
if ($PSCmdlet.ParameterSetName -ne 'CapturePrestateMode') {
    $InitReceiptPath = Assert-FoundationPortablePath -LiteralPath $InitReceiptPath -Role InitReceiptPath -PassThru
    $ReplayReceiptPath = Assert-FoundationPortablePath -LiteralPath $ReplayReceiptPath -Role ReplayReceiptPath -PassThru
    $RecoveryJournalPath = Assert-FoundationPortablePath -LiteralPath $RecoveryJournalPath -Role RecoveryJournalPath -Directory -PassThru
    $CompletionReceiptPath = Assert-FoundationPortablePath -LiteralPath $CompletionReceiptPath -Role CompletionReceiptPath -PassThru
    if ($PSCmdlet.ParameterSetName -ne 'RecoveryMode') {
        $SourceRoot = Assert-FoundationPortablePath -LiteralPath $SourceRoot -Role SourceRoot -Directory -PassThru
    }
    if (-not [string]::IsNullOrEmpty($RecoveredCompletionReceiptPath)) {
        $RecoveredCompletionReceiptPath = Assert-FoundationPortablePath -LiteralPath $RecoveredCompletionReceiptPath -Role RecoveredCompletionReceiptPath -PassThru
    }
}
$outputRoot = Join-Path $ScratchRoot 'out'
$stateRoot = Join-Path $ScratchRoot 'state'
$promoRoot = Join-Path $ScratchRoot 'promo'
$prestate = $null
$isCommittedReplay = $PSCmdlet.ParameterSetName -eq 'ReplayCommitMode'

$bootstrapInputPathSet = @(
    'certification/.gitattributes'
    'tests/.gitattributes'
    'certification/schema/catalog/foundation.catalog.v1.json'
    'certification/lib/Pspkt.Certification.FoundationCatalogEngine.cs'
    'certification/lib/Pspkt.Certification.FoundationPolicy.cs'
    'certification/lib/Pspkt.Certification.FoundationVerify.cs'
    'certification/lib/Pspkt.Certification.FoundationContract.ps1'
    'certification/vectors/New-PspktPhase4SchemaAuthorityFoundationVectors.ps1'
    'certification/validators/Invoke-PspktPhase4SchemaAuthorityFoundationValidators.ps1'
    'certification/validators/Test-PspktPhase4SchemaAuthorityFoundation.ps1'
    'tests/pspkt.Phase4SchemaAuthorityFoundation.Tests.ps1'
)
$bootstrapFixtureNames = @(
    'json-bom.json','json-comment.json','json-duplicate-key.json','json-trailing-comma.json',
    'order-ok.json','order-reorder.json','extra-key.json','missing-property.json',
    'duplicate-type-name.json','duplicate-field.json','duplicate-kind.json','emit-ok.json',
    'primitive-unknown.json','primitive-forbidden.json','enum-members-ok.json',
    'enum-duplicate-name.json','enum-duplicate-value.json','enum-value-overflow.json',
    'list-set-ok.json','semantic-string-ok.json','field-overflow-40.json',
    'field-undefined-parent.json','field40-extend-ok.json','extend-invalid-parent.json',
    'extend-lt40.json','extend-missing-literal.json','extend-id-overflow.json',
    'extend-dup-name.json','extend-dup-id.json','op-union-ok.json','op-union-empty.json',
    'op-union-duplicate-branch.json','op-delete-ok.json','op-delete-unknown.json',
    'op-delete-double.json','op-delete-then-use.json','op-reserve-ok.json',
    'op-reserve-missing.json','op-reserve-out-of-range.json','op-reserve-illegal-encoded.json',
    'message-two-direction-ok.json','message-cross-channel-ok.json',
    'message-undefined-payload.json','message-conflict.json','invalid-channel.json',
    'invalid-direction.json','invalid-production.json','op-unknown.json',
    'op-replace-forbidden.json','base-literal-id.json','foundation-name-bad.json',
    'field-defined-parent-ok.json'
)
$bootstrapFixtureRoot = 'certification/vectors/phase4-schema-authority-foundation'
$bootstrapOutputPathSet = @(
    'certification/schema/foundation-schema.v1.json'
    'certification/schema/foundation-id-map.v1.json'
    "$bootstrapFixtureRoot/fixture-manifest.v1.json"
)
$bootstrapOutputPathSet += @($bootstrapFixtureNames | ForEach-Object { "$bootstrapFixtureRoot/$_" })
$bootstrapContract = [pscustomobject]@{
    BaselineOid = '2056af494d9a545e58842fee10c2e611ba353c65'
    Branch = 'bb-phase4-schema-authority-1ba'
    CatalogRelativePath = 'certification/schema/catalog/foundation.catalog.v1.json'
    SchemaRelativePath = 'certification/schema/foundation-schema.v1.json'
    MapRelativePath = 'certification/schema/foundation-id-map.v1.json'
    InputPathSet = $bootstrapInputPathSet
    OutputPathSet = $bootstrapOutputPathSet
    Allowlist = @($bootstrapInputPathSet + $bootstrapOutputPathSet)
    ExecutionPrestateSchemaId = 'PspktFoundationExecutionPrestateV3'
    RecoveryJournalSchemaId = 'PspktFoundationRecoveryJournalV1'
    InitReceiptSchemaId = 'PspktFoundationInitReceiptV1'
    ReplayReceiptSchemaId = 'PspktFoundationReplayReceiptV2'
    CompletionReceiptSchemaId = 'PspktFoundationCompletionReceiptV1'
    CandidateInputFileMaximumBytes = 1048576
    CandidateInputAggregateMaximumBytes = 8388608
    PrestateMaximumBytes = 67108864
    AuthorityReceiptFileMaximumBytes = 1048576
    AuthorityReceiptAggregateMaximumBytes = 3145728
    GeneratedOutputFileMaximumBytes = 1048576
    GeneratedOutputAggregateMaximumBytes = 16777216
    GitScalarMaximumBytes = 1048576
    GitNulPathMaximumBytes = 16777216
    GitLogicalProjectionMaximumBytes = 16777216
    GitLogicalProjectionAggregateMaximumBytes = 33554432
    RecoveryJournalSegmentMaximumBytes = 16384
    RecoveryJournalMaximumBytes = 33554432
    RecoveryJournalMaximumSegments = 1536
    RecoveryJournalEvidenceReserveBytes = 8388608
    BoundedProcessLength = 564872
    BoundedProcessSha256 = '6aa8cfe7ef705b1ee27c88ae18f9f5f9fafedc1eec1caee598795ef893eccffb'
    CanonicalJsonLength = 8689
    CanonicalJsonSha256 = '414975df1d4b5d04d9b72a95fcaad7e8fc922b17ee0e969da856c463fc3718c3'
    SchemaBootstrapLength = 76371
    SchemaBootstrapSha256 = 'a86608847c7fdfeee4da43c50545a77a5c4b51d2e12ea77fa61f2ae4a4617f66'
    MetaLength = 4146
    MetaSha256 = '9b13be426d37e3da01870ff32ec5c4e5db63e9699566a1978007e1f8c07fcd2c'
    CertificationAttributesLength = 833
    CertificationAttributesSha256 = '128dc4bc640da9d9f1c99de2e46ea8e5dfd3e9bce92ab8b23d74cbc16fb48ad9'
    TestAttributesLength = 160
    TestAttributesSha256 = 'eafe8326812cb43f4eefa859e9872300abeb92a73cb6c3514d9133c83dc1736b'
    OneAChildContractTimeoutSeconds = 180
    OneAEmpiricalRuntimeSeconds = 385
    OneASupervisorTimeoutMilliseconds = 600000
}
if ($bootstrapContract.InputPathSet.Count -ne 11 -or $bootstrapContract.OutputPathSet.Count -ne 55 -or $bootstrapContract.Allowlist.Count -ne 66 -or ($bootstrapContract.Allowlist | Sort-Object -Unique).Count -ne 66) {
    throw 'Bootstrap path authority is invalid.'
}

function Get-FoundationHostSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Read-FoundationHostBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [int64]$MaximumLength = 1048576
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt $MaximumLength) {
        throw "Expected bounded ordinary file: $LiteralPath"
    }
    return [IO.File]::ReadAllBytes($item.FullName)
}

function Resolve-FoundationHostPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    if ([IO.Path]::IsPathRooted($RelativePath) -or $RelativePath.Contains('\') -or $RelativePath.Contains('..')) {
        throw "Invalid repository-relative path: $RelativePath"
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $fullPath = Assert-FoundationPortablePath -LiteralPath ($rootPath + $RelativePath.Replace('/', '\')) -Role $RelativePath -PassThru
    if (-not $fullPath.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes root: $RelativePath"
    }
    return $fullPath
}

function Test-FoundationOrdinalStringSetEquality {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string[]]$Actual
    )

    if ($Expected.Length -ne $Actual.Length) {
        return $false
    }
    $expectedCopy = [string[]]$Expected.Clone()
    $actualCopy = [string[]]$Actual.Clone()
    [Array]::Sort($expectedCopy, [StringComparer]::Ordinal)
    [Array]::Sort($actualCopy, [StringComparer]::Ordinal)
    for ($index = 0; $index -lt $expectedCopy.Length; $index++) {
        if ($expectedCopy[$index] -cne $actualCopy[$index]) {
            return $false
        }
    }
    return $true
}

function Test-FoundationJsonInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Value,
        [Parameter(Mandatory = $true)][int64]$Expected
    )

    return (($Value -is [int]) -or ($Value -is [int64])) -and [int64]$Value -eq $Expected
}

function Test-FoundationJsonIntegerType {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)

    return ($Value -is [int]) -or ($Value -is [int64])
}

function Test-FoundationJsonObject {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)

    return $null -ne $Value -and $Value.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject]
}

$foundationHostSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
namespace Pspkt.Certification.FoundationHost
{
    public static class NativeFileSystem
    {
        public const string BuildMarker = "PspktFoundationHostM29";
        private const uint FileFlagBackupSemantics = 0x02000000U;
        private const uint FileFlagOpenReparsePoint = 0x00200000U;
        private const uint FileAttributeDirectory = 0x00000010U;
        private const uint FileAttributeReparsePoint = 0x00000400U;
        private const uint DeleteAccess = 0x00010000U;
        private const uint GenericRead = 0x80000000U;
        private const uint OpenExisting = 3U;
        private const int FileRenameInfo = 3;
        private const int FileDispositionInfo = 4;
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInformation
        {
            [MarshalAs(UnmanagedType.Bool)]
            internal bool DeleteFile;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, FileShare share, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass, ref FileDispositionInformation information, uint bufferSize);
        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        private static extern bool SetFileInformationByHandleBuffer(SafeFileHandle handle, int informationClass, IntPtr information, uint bufferSize);
        public static string GetIdentity(string path)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(stream.SafeFileHandle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.VolumeSerialNumber.ToString("x8") + ":" + information.FileIndexHigh.ToString("x8") + information.FileIndexLow.ToString("x8");
            }
        }
        public static uint GetLinkCount(string path)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(stream.SafeFileHandle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.NumberOfLinks;
            }
        }
        public static string GetDirectoryIdentity(string path)
        {
            using (SafeFileHandle handle = CreateFile(path, 0U, FileShare.Read | FileShare.Write | FileShare.Delete, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.VolumeSerialNumber.ToString("x8") + ":" + information.FileIndexHigh.ToString("x8") + information.FileIndexLow.ToString("x8");
            }
        }
        public static void MoveReplace(string source, string destination)
        {
            if (!MoveFileEx(source, destination, 0x1U | 0x8U))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        public static void MoveCreateOnly(string source, string destination)
        {
            if (!MoveFileEx(source, destination, 0x8U))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        public static void MoveOwnedFileCreateOnly(string source, string destination, string expectedIdentity, long expectedLength, string expectedSha256)
        {
            if (!Path.IsPathRooted(destination) || !string.Equals(Path.GetFullPath(destination), destination, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Destination must be an absolute canonical path.", "destination");
            }
            SafeFileHandle handle = null;
            FileStream stream = null;
            IntPtr renameBuffer = IntPtr.Zero;
            Exception primaryError = null;
            List<Exception> cleanupErrors = new List<Exception>();
            try
            {
                handle = CreateFile(
                    source,
                    GenericRead | DeleteAccess,
                    FileShare.Read,
                    IntPtr.Zero,
                    OpenExisting,
                    FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    int openError = Marshal.GetLastWin32Error();
                    throw new Win32Exception(openError);
                }
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    int informationError = Marshal.GetLastWin32Error();
                    throw new Win32Exception(informationError);
                }
                string identity = information.VolumeSerialNumber.ToString("x8")
                    + ":"
                    + information.FileIndexHigh.ToString("x8")
                    + information.FileIndexLow.ToString("x8");
                long length = (long)(((ulong)information.FileSizeHigh << 32) | information.FileSizeLow);
                if ((information.FileAttributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0U
                    || !string.Equals(identity, expectedIdentity, StringComparison.Ordinal)
                    || length != expectedLength
                    || information.NumberOfLinks != 1U)
                {
                    throw new IOException("Owned file identity changed.");
                }
                stream = new FileStream(handle, FileAccess.Read, 4096, false);
                handle = null;
                using (SHA256 sha256 = SHA256.Create())
                {
                    string actualSha256 = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                    if (!string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
                    {
                        throw new IOException("Owned file bytes changed.");
                    }
                }
                byte[] destinationBytes = Encoding.Unicode.GetBytes(destination);
                int rootDirectoryOffset = IntPtr.Size == 8 ? 8 : 4;
                int fileNameLengthOffset = checked(rootDirectoryOffset + IntPtr.Size);
                int fileNameOffset = checked(fileNameLengthOffset + 4);
                int totalSize = checked(fileNameOffset + destinationBytes.Length + 2);
                renameBuffer = Marshal.AllocHGlobal(totalSize);
                for (int index = 0; index < totalSize; index++)
                {
                    Marshal.WriteByte(renameBuffer, index, 0);
                }
                Marshal.WriteInt32(renameBuffer, 0, 0);
                Marshal.WriteIntPtr(renameBuffer, rootDirectoryOffset, IntPtr.Zero);
                Marshal.WriteInt32(renameBuffer, fileNameLengthOffset, destinationBytes.Length);
                Marshal.Copy(destinationBytes, 0, new IntPtr(renameBuffer.ToInt64() + fileNameOffset), destinationBytes.Length);
                if (!SetFileInformationByHandleBuffer(stream.SafeFileHandle, FileRenameInfo, renameBuffer, (uint)totalSize))
                {
                    int renameError = Marshal.GetLastWin32Error();
                    throw new Win32Exception(renameError);
                }
            }
            catch (Exception exception)
            {
                primaryError = exception;
            }
            finally
            {
                if (renameBuffer != IntPtr.Zero)
                {
                    try { Marshal.FreeHGlobal(renameBuffer); }
                    catch (Exception exception) { cleanupErrors.Add(exception); }
                }
                if (stream != null)
                {
                    try { stream.Dispose(); }
                    catch (Exception exception) { cleanupErrors.Add(exception); }
                }
                else if (handle != null)
                {
                    try { handle.Dispose(); }
                    catch (Exception exception) { cleanupErrors.Add(exception); }
                }
            }
            if (primaryError != null)
            {
                if (cleanupErrors.Count != 0)
                {
                    List<Exception> errors = new List<Exception>();
                    errors.Add(primaryError);
                    errors.AddRange(cleanupErrors);
                    throw new AggregateException("Owned file move and cleanup failed.", errors);
                }
                ExceptionDispatchInfo.Capture(primaryError).Throw();
                return;
            }
            if (cleanupErrors.Count == 1)
            {
                throw cleanupErrors[0];
            }
            if (cleanupErrors.Count > 1)
            {
                throw new AggregateException("Owned file move cleanup failed.", cleanupErrors);
            }
        }
        public static void DeleteOwnedFile(string path, string expectedIdentity, long expectedLength, string expectedSha256)
        {
            using (SafeFileHandle handle = CreateFile(path, GenericRead | DeleteAccess, FileShare.Read, IntPtr.Zero, OpenExisting, 0U, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                string identity = information.VolumeSerialNumber.ToString("x8") + ":" + information.FileIndexHigh.ToString("x8") + information.FileIndexLow.ToString("x8");
                using (FileStream stream = new FileStream(handle, FileAccess.Read, 4096, false))
                {
                    if (!string.Equals(identity, expectedIdentity, StringComparison.Ordinal) || stream.Length != expectedLength)
                    {
                        throw new IOException("Owned file identity changed.");
                    }
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        string actualSha256 = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        if (!string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
                        {
                            throw new IOException("Owned file bytes changed.");
                        }
                    }
                    FileDispositionInformation disposition = new FileDispositionInformation { DeleteFile = true };
                    if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition, (uint)Marshal.SizeOf(typeof(FileDispositionInformation))))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
            }
        }
        public static void DeleteOwnedEmptyDirectory(string path, string expectedIdentity)
        {
            using (SafeFileHandle handle = CreateFile(path, DeleteAccess, FileShare.Read, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                string identity = information.VolumeSerialNumber.ToString("x8") + ":" + information.FileIndexHigh.ToString("x8") + information.FileIndexLow.ToString("x8");
                if (!string.Equals(identity, expectedIdentity, StringComparison.Ordinal))
                {
                    throw new IOException("Owned directory identity changed.");
                }
                FileDispositionInformation disposition = new FileDispositionInformation { DeleteFile = true };
                if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition, (uint)Marshal.SizeOf(typeof(FileDispositionInformation))))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
        }
    }
    public sealed class BinaryProcessResult
    {
        public int ExitCode { get; private set; }
        public byte[] StandardOutput { get; private set; }
        public byte[] StandardError { get; private set; }
        public BinaryProcessResult(int exitCode, byte[] standardOutput, byte[] standardError)
        {
            ExitCode = exitCode;
            StandardOutput = standardOutput;
            StandardError = standardError;
        }
    }
    public static class BinaryProcess
    {
        private sealed class DrainState
        {
            internal readonly Stream Source;
            internal readonly MemoryStream Destination;
            internal readonly int Cap;
            internal Exception Error;
            internal DrainState(Stream source, int cap)
            {
                Source = source;
                Cap = cap;
                Destination = new MemoryStream(Math.Min(cap, 65536));
            }
        }
        private static void Drain(object value)
        {
            DrainState state = (DrainState)value;
            byte[] buffer = new byte[8192];
            try
            {
                while (true)
                {
                    int read = state.Source.Read(buffer, 0, buffer.Length);
                    if (read == 0)
                    {
                        return;
                    }
                    if (state.Destination.Length > state.Cap - read)
                    {
                        throw new IOException("Process stream exceeded its hard cap.");
                    }
                    state.Destination.Write(buffer, 0, read);
                }
            }
            catch (Exception error)
            {
                state.Error = error;
            }
        }
        private static string Quote(string value)
        {
            if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            {
                return value;
            }
            StringBuilder builder = new StringBuilder();
            builder.Append('"');
            int index = 0;
            while (true)
            {
                int backslashes = 0;
                while (index < value.Length && value[index] == '\\')
                {
                    index++;
                    backslashes++;
                }
                if (index == value.Length)
                {
                    builder.Append('\\', backslashes * 2);
                    break;
                }
                if (value[index] == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                }
                else
                {
                    builder.Append('\\', backslashes);
                }
                builder.Append(value[index]);
                index++;
            }
            builder.Append('"');
            return builder.ToString();
        }
        public static BinaryProcessResult Run(
            string executablePath,
            string[] arguments,
            string workingDirectory,
            string[] environmentNames,
            string[] environmentValues,
            byte[] standardInput,
            int standardOutputCap,
            int standardErrorCap,
            int timeoutMilliseconds)
        {
            if (environmentNames.Length != environmentValues.Length)
            {
                throw new ArgumentException("Environment name/value arrays differ in length.");
            }
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = executablePath;
            startInfo.Arguments = string.Join(" ", Array.ConvertAll(arguments, Quote));
            startInfo.WorkingDirectory = workingDirectory;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardInput = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.EnvironmentVariables.Clear();
            for (int index = 0; index < environmentNames.Length; index++)
            {
                startInfo.EnvironmentVariables[environmentNames[index]] = environmentValues[index];
            }
            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                if (!process.Start())
                {
                    throw new InvalidOperationException("Unable to start bounded binary process.");
                }
                DrainState output = new DrainState(process.StandardOutput.BaseStream, standardOutputCap);
                DrainState error = new DrainState(process.StandardError.BaseStream, standardErrorCap);
                Thread outputThread = new Thread(Drain);
                Thread errorThread = new Thread(Drain);
                outputThread.IsBackground = true;
                errorThread.IsBackground = true;
                outputThread.Start(output);
                errorThread.Start(error);
                try
                {
                    if (standardInput != null && standardInput.Length != 0)
                    {
                        process.StandardInput.BaseStream.Write(standardInput, 0, standardInput.Length);
                    }
                    process.StandardInput.Close();
                    if (!process.WaitForExit(timeoutMilliseconds))
                    {
                        try { process.Kill(); }
                        catch (InvalidOperationException) { }
                        throw new TimeoutException("Bounded binary process timed out.");
                    }
                    if (!outputThread.Join(5000) || !errorThread.Join(5000))
                    {
                        throw new TimeoutException("Bounded binary process drain timed out.");
                    }
                    if (output.Error != null || error.Error != null)
                    {
                        List<Exception> errors = new List<Exception>();
                        if (output.Error != null) { errors.Add(output.Error); }
                        if (error.Error != null) { errors.Add(error.Error); }
                        throw new AggregateException("Bounded binary process drain failed.", errors);
                    }
                    return new BinaryProcessResult(process.ExitCode, output.Destination.ToArray(), error.Destination.ToArray());
                }
                finally
                {
                    if (!process.HasExited)
                    {
                        try { process.Kill(); }
                        catch (InvalidOperationException) { }
                    }
                    output.Destination.Dispose();
                    error.Destination.Dispose();
                }
            }
        }
    }
    public static class NativeJobAuthority
    {
        private const int JobObjectBasicAccountingInformationClass = 1;
        private const int JobObjectExtendedLimitInformationClass = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000U;
        private const uint HandleFlagInherit = 0x00000001U;
        private const int StandardOutputHandle = -11;
        private const int StandardErrorHandle = -12;
        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicAccountingInformation
        {
            internal long TotalUserTime;
            internal long TotalKernelTime;
            internal long ThisPeriodTotalUserTime;
            internal long ThisPeriodTotalKernelTime;
            internal uint TotalPageFaultCount;
            internal uint TotalProcesses;
            internal uint ActiveProcesses;
            internal uint TotalTerminatedProcesses;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicLimitInformation
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal IntPtr MinimumWorkingSetSize;
            internal IntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal IntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectExtendedLimitInformation
        {
            internal JobObjectBasicLimitInformation BasicLimitInformation;
            internal IoCounters IoInfo;
            internal IntPtr ProcessMemoryLimit;
            internal IntPtr JobMemoryLimit;
            internal IntPtr PeakProcessMemoryUsed;
            internal IntPtr PeakJobMemoryUsed;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint informationLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint informationLength, out uint returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int standardHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetStdHandle(int standardHandle, IntPtr handle);
        public static IntPtr CreateKillOnCloseJob()
        {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");
            }
            IntPtr buffer = IntPtr.Zero;
            try
            {
                JobObjectExtendedLimitInformation information = new JobObjectExtendedLimitInformation();
                information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
                int size = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
                buffer = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(information, buffer, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, buffer, (uint)size))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed.");
                }
                return job;
            }
            catch (Exception primaryError)
            {
                if (!CloseHandle(job))
                {
                    throw new AggregateException(
                        primaryError,
                        new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle failed for an unconfigured Job."));
                }
                throw;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        public static void AssignProcess(IntPtr job, IntPtr process)
        {
            if (job == IntPtr.Zero || process == IntPtr.Zero)
            {
                throw new ArgumentException("Job and process handles are required.");
            }
            if (!AssignProcessToJobObject(job, process))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed.");
            }
        }
        public static bool IsProcessAssigned(IntPtr job, IntPtr process)
        {
            if (job == IntPtr.Zero || process == IntPtr.Zero)
            {
                throw new ArgumentException("Job and process handles are required.");
            }
            bool result;
            if (!IsProcessInJob(process, job, out result))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IsProcessInJob failed.");
            }
            return result;
        }
        public static void TerminateJob(IntPtr job)
        {
            if (job == IntPtr.Zero)
            {
                throw new ArgumentException("A Job handle is required.");
            }
            if (!TerminateJobObject(job, 1U))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed.");
            }
        }
        public static uint GetActiveProcessCount(IntPtr job)
        {
            if (job == IntPtr.Zero)
            {
                throw new ArgumentException("A Job handle is required.");
            }
            int size = Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformationClass, buffer, (uint)size, out returned))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject failed.");
                }
                JobObjectBasicAccountingInformation information =
                    (JobObjectBasicAccountingInformation)Marshal.PtrToStructure(buffer, typeof(JobObjectBasicAccountingInformation));
                return information.ActiveProcesses;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        public static void WaitForActiveProcessCountZero(IntPtr job, int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            System.Diagnostics.Stopwatch stopwatch = System.Diagnostics.Stopwatch.StartNew();
            uint active = GetActiveProcessCount(job);
            while (active != 0U && stopwatch.ElapsedMilliseconds < timeoutMilliseconds)
            {
                System.Threading.Thread.Sleep(10);
                active = GetActiveProcessCount(job);
            }
            if (active != 0U)
            {
                throw new TimeoutException("Job active-process count did not reach zero.");
            }
        }
        public static void CloseJob(IntPtr job)
        {
            if (job == IntPtr.Zero)
            {
                return;
            }
            if (!CloseHandle(job))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle failed for the Job.");
            }
        }
        public static void ClearStandardHandleInheritance()
        {
            foreach (int standardHandle in new int[] { StandardOutputHandle, StandardErrorHandle })
            {
                IntPtr handle = GetStdHandle(standardHandle);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetStdHandle failed.");
                }
                if (!SetHandleInformation(handle, HandleFlagInherit, 0U))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation failed.");
                }
            }
        }
        public static void CloseStandardOutputAndError()
        {
            foreach (int standardHandle in new int[] { StandardOutputHandle, StandardErrorHandle })
            {
                IntPtr handle = GetStdHandle(standardHandle);
                if (handle != IntPtr.Zero && handle != new IntPtr(-1) && !CloseHandle(handle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle failed for a standard handle.");
                }
                if (!SetStdHandle(standardHandle, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetStdHandle failed.");
                }
            }
        }
    }
}
'@
$script:FoundationHostBinding = $null
$script:FrameworkCompilerBootstrap = $null

function Invoke-FoundationHostMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Arguments
    )

    if ($null -eq $script:FoundationHostBinding -or -not $script:FoundationHostBinding.Delegates.ContainsKey($Name)) {
        throw "FoundationHost method is unavailable: $Name"
    }
    try {
        $delegate = $script:FoundationHostBinding.Delegates[$Name]
        if ($Name -eq 'MoveOwnedFileCreateOnly') {
            return $delegate.Invoke([string]$Arguments[0], [string]$Arguments[1], [string]$Arguments[2], [int64]$Arguments[3], [string]$Arguments[4])
        }
        if ($Name -like 'Move*') {
            return $delegate.Invoke([string]$Arguments[0], [string]$Arguments[1])
        }
        if ($Name -eq 'DeleteOwnedFile') {
            return $delegate.Invoke([string]$Arguments[0], [string]$Arguments[1], [int64]$Arguments[2], [string]$Arguments[3])
        }
        if ($Name -eq 'DeleteOwnedEmptyDirectory') {
            return $delegate.Invoke([string]$Arguments[0], [string]$Arguments[1])
        }
        return $delegate.Invoke([string]$Arguments[0])
    }
    catch [System.Management.Automation.MethodInvocationException] {
        $inner = $_.Exception.InnerException
        if ($null -eq $inner) { throw $_.Exception }
        while ($null -ne $inner.InnerException -and ($inner -is [System.Management.Automation.MethodInvocationException] -or $inner -is [Reflection.TargetInvocationException])) {
            $inner = $inner.InnerException
        }
        throw $inner
    }
    catch [Reflection.TargetInvocationException] {
        $inner = $_.Exception.InnerException
        if ($null -eq $inner) { throw $_.Exception }
        while ($null -ne $inner.InnerException -and ($inner -is [System.Management.Automation.MethodInvocationException] -or $inner -is [Reflection.TargetInvocationException])) {
            $inner = $inner.InnerException
        }
        throw $inner
    }
}

function Get-FoundationNativeFileIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    return [string](Invoke-FoundationHostMethod -Name 'GetIdentity' -Arguments @($LiteralPath))
}

function Get-FoundationNativeDirectoryIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    return [string](Invoke-FoundationHostMethod -Name 'GetDirectoryIdentity' -Arguments @($LiteralPath))
}

function Get-FoundationNativeLinkCount {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    return [uint32](Invoke-FoundationHostMethod -Name 'GetLinkCount' -Arguments @($LiteralPath))
}

function Move-FoundationNativeReplace {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Source,[Parameter(Mandatory = $true)][string]$Destination)

    [void](Invoke-FoundationHostMethod -Name 'MoveReplace' -Arguments @($Source,$Destination))
}

function Move-FoundationNativeCreateOnly {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Source,[Parameter(Mandatory = $true)][string]$Destination)

    try {
        [void](Invoke-FoundationHostMethod -Name 'MoveCreateOnly' -Arguments @($Source,$Destination))
    }
    catch {
        throw [IO.IOException]::new("Create-only move failed. Source=$Source Destination=$Destination", $_.Exception)
    }
}

function Move-FoundationNativeOwnedFileCreateOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)]$Record
    )

    try {
        [void](Invoke-FoundationHostMethod -Name 'MoveOwnedFileCreateOnly' -Arguments @($Source,$Destination,$Record.Identity,$Record.Length,$Record.Sha256))
    }
    catch {
        throw [IO.IOException]::new("Owned create-only move failed. Source=$Source Destination=$Destination", $_.Exception)
    }
}

function Remove-FoundationNativeOwnedFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Record)

    try {
        [void](Invoke-FoundationHostMethod -Name 'DeleteOwnedFile' -Arguments @($Record.Path,$Record.Identity,$Record.Length,$Record.Sha256))
    }
    catch {
        throw [IO.IOException]::new("Owned-file deletion failed. Path=$($Record.Path)", $_.Exception)
    }
}

function Remove-FoundationNativeOwnedEmptyDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedIdentity
    )

    [void](Invoke-FoundationHostMethod -Name 'DeleteOwnedEmptyDirectory' -Arguments @($LiteralPath,$ExpectedIdentity))
}

function New-FoundationNativeJob {
    [CmdletBinding()]
    param()

    Assert-FoundationHostBinding
    return [IntPtr](Invoke-FoundationJobDelegate -Name 'CreateKillOnCloseJob' -Arguments @())
}

function Invoke-FoundationJobDelegate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Arguments
    )

    try {
        $delegate = $script:FoundationHostBinding.Delegates[$Name]
        switch ($Name) {
            'CreateKillOnCloseJob' { return $delegate.Invoke() }
            'AssignProcess' { return $delegate.Invoke([IntPtr]$Arguments[0], [IntPtr]$Arguments[1]) }
            'IsProcessAssigned' { return $delegate.Invoke([IntPtr]$Arguments[0], [IntPtr]$Arguments[1]) }
            'WaitForActiveProcessCountZero' { return $delegate.Invoke([IntPtr]$Arguments[0], [int]$Arguments[1]) }
            default { return $delegate.Invoke([IntPtr]$Arguments[0]) }
        }
    }
    catch [System.Management.Automation.MethodInvocationException] {
        $inner = $_.Exception.InnerException
        if ($null -eq $inner) { throw $_.Exception }
        while ($null -ne $inner.InnerException -and ($inner -is [System.Management.Automation.MethodInvocationException] -or $inner -is [Reflection.TargetInvocationException])) {
            $inner = $inner.InnerException
        }
        throw $inner
    }
    catch [Reflection.TargetInvocationException] {
        $inner = $_.Exception.InnerException
        if ($null -eq $inner) { throw $_.Exception }
        while ($null -ne $inner.InnerException -and ($inner -is [System.Management.Automation.MethodInvocationException] -or $inner -is [Reflection.TargetInvocationException])) {
            $inner = $inner.InnerException
        }
        throw $inner
    }
}

function Add-FoundationProcessToNativeJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Job,
        [Parameter(Mandatory = $true)][IntPtr]$Process
    )

    [void](Invoke-FoundationJobDelegate -Name 'AssignProcess' -Arguments @($Job,$Process))
}

function Stop-FoundationNativeJob {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][IntPtr]$Job)

    [void](Invoke-FoundationJobDelegate -Name 'TerminateJob' -Arguments @($Job))
}

function Get-FoundationNativeJobActiveProcessCount {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][IntPtr]$Job)

    return [uint32](Invoke-FoundationJobDelegate -Name 'GetActiveProcessCount' -Arguments @($Job))
}

function Test-FoundationProcessInNativeJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Job,
        [Parameter(Mandatory = $true)][IntPtr]$Process
    )

    return [bool](Invoke-FoundationJobDelegate -Name 'IsProcessAssigned' -Arguments @($Job,$Process))
}

function Wait-FoundationNativeJobEmpty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Job,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )

    [void](Invoke-FoundationJobDelegate -Name 'WaitForActiveProcessCountZero' -Arguments @($Job,$TimeoutMilliseconds))
}

function Close-FoundationNativeJob {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][IntPtr]$Job)

    [void](Invoke-FoundationJobDelegate -Name 'CloseJob' -Arguments @($Job))
}

function Assert-FoundationFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [Parameter(Mandatory = $true)]
        [int64]$Length,
        [Parameter(Mandatory = $true)]
        [string]$Sha256
    )

    $bytes = Read-FoundationHostBytes -LiteralPath $LiteralPath -MaximumLength ([Math]::Max($Length, 1048576))
    if ($bytes.Length -ne $Length -or (Get-FoundationHostSha256 -Bytes $bytes) -ne $Sha256) {
        throw "Pinned file mismatch: $LiteralPath"
    }
}

$script:GitBinding = $null
$script:CandidateFileBindings = [Collections.Generic.List[object]]::new()
$script:GeneratedFileBindings = [Collections.Generic.List[object]]::new()
$script:AssemblyFileBindings = [Collections.Generic.List[object]]::new()
$script:BootstrapFileBindings = [Collections.Generic.List[object]]::new()
$script:AuthorityFileBindings = [Collections.Generic.List[object]]::new()
$script:BoundedGitContext = $null
$script:GitProcessScriptPath = $null
$script:CandidateInputBytes = [int64]0
$script:AuthorityReceiptBytes = [int64]0
$script:GeneratedOutputBytes = [int64]0

function New-FoundationFileBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Role,
        [int64]$MaximumLength = -1
    )

    Assert-FoundationNoReparsePath -LiteralPath $LiteralPath
    $path = [IO.Path]::GetFullPath($LiteralPath)
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) {
        throw "Immutable binding is not a file: $path"
    }
    $aggregateName = $null
    $aggregateMaximum = [int64]::MaxValue
    if ($MaximumLength -lt 0) {
        if ($Role -like 'candidate:*') {
            $MaximumLength = $bootstrapContract.CandidateInputFileMaximumBytes
            $aggregateName = 'CandidateInputBytes'
            $aggregateMaximum = $bootstrapContract.CandidateInputAggregateMaximumBytes
        }
        elseif ($Role -like 'authority:prestate*') {
            $MaximumLength = $bootstrapContract.PrestateMaximumBytes
        }
        elseif ($Role -like 'authority:*receipt*') {
            $MaximumLength = $bootstrapContract.AuthorityReceiptFileMaximumBytes
            $aggregateName = 'AuthorityReceiptBytes'
            $aggregateMaximum = $bootstrapContract.AuthorityReceiptAggregateMaximumBytes
        }
        elseif ($Role -like 'output:*') {
            $MaximumLength = $bootstrapContract.GeneratedOutputFileMaximumBytes
            $aggregateName = 'GeneratedOutputBytes'
            $aggregateMaximum = $bootstrapContract.GeneratedOutputAggregateMaximumBytes
        }
        else {
            $MaximumLength = [int64]::MaxValue
        }
    }
    if ($item.Length -gt $MaximumLength -or $item.Length -gt [int]::MaxValue) {
        throw "Immutable binding exceeds its bounded-file cap: $Role"
    }
    $aggregateRegistered = $false
    if ($null -ne $aggregateName) {
        $nextAggregate = [int64](Get-Variable -Scope Script -Name $aggregateName -ValueOnly) + $item.Length
        if ($nextAggregate -gt $aggregateMaximum) {
            throw "Immutable binding aggregate exceeds its bounded-file cap: $Role"
        }
        Set-Variable -Scope Script -Name $aggregateName -Value $nextAggregate
        $aggregateRegistered = $true
    }
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $bytes = [byte[]]::new([int]$item.Length)
        $sha256 = [Security.Cryptography.SHA256]::Create()
        $offset = 0
        try {
            while ($offset -lt $bytes.Length) {
                $read = $stream.Read($bytes, $offset, [Math]::Min(65536, $bytes.Length - $offset))
                if ($read -eq 0) {
                    throw "Immutable binding read ended early: $path"
                }
                [void]$sha256.TransformBlock($bytes, $offset, $read, $null, 0)
                $offset += $read
            }
            [void]$sha256.TransformFinalBlock([byte[]]::new(0), 0, 0)
            $hash = ([BitConverter]::ToString($sha256.Hash)).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
        $stream.Position = 0
        return [pscustomobject]@{
            Path = $path
            Role = $Role
            Stream = $stream
            Identity = Get-FoundationNativeFileIdentity -LiteralPath $path
            Length = $item.Length
            Sha256 = $hash
            Bytes = $bytes
        }
    }
    catch {
        $stream.Dispose()
        if ($aggregateRegistered) {
            Set-Variable -Scope Script -Name $aggregateName -Value ([int64](Get-Variable -Scope Script -Name $aggregateName -ValueOnly) - $item.Length)
        }
        throw
    }
}

function Assert-FoundationFileBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Binding)

    $item = Get-Item -LiteralPath $Binding.Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -ne $Binding.Length -or (Get-FoundationNativeFileIdentity -LiteralPath $Binding.Path) -ne $Binding.Identity -or (Get-FoundationFileSha -LiteralPath $Binding.Path) -cne $Binding.Sha256) {
        throw "Immutable file binding changed: $($Binding.Role)"
    }
}

function Assert-FoundationImmutableBindings {
    [CmdletBinding()]
    param()

    foreach ($binding in @($script:BootstrapFileBindings) + @($script:AuthorityFileBindings) + @($script:CandidateFileBindings) + @($script:GeneratedFileBindings) + @($script:AssemblyFileBindings)) {
        Assert-FoundationFileBinding -Binding $binding
    }
}

function Copy-FoundationBindingToImmutablePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Role
    )

    $stream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Binding.Bytes, 0, $Binding.Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $copyBinding = New-FoundationFileBinding -LiteralPath $Destination -Role $Role
    if ($copyBinding.Sha256 -cne $Binding.Sha256 -or $copyBinding.Length -ne $Binding.Length) {
        $copyBinding.Stream.Dispose()
        throw "Immutable authority copy mismatch: $Role"
    }
    $script:BootstrapFileBindings.Add($copyBinding)
    return $copyBinding
}

function Resolve-FoundationGitBinding {
    [CmdletBinding()]
    param()

    $roots = [Collections.Generic.List[string]]::new()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        $gitKey = $null
        $windowsKey = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $gitKey = $base.OpenSubKey('SOFTWARE\GitForWindows', $false)
            if ($null -ne $gitKey) {
                $installPath = [string]$gitKey.GetValue('InstallPath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if (-not [string]::IsNullOrEmpty($installPath)) {
                    $roots.Add($installPath)
                }
            }
            $windowsKey = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion', $false)
            if ($null -ne $windowsKey) {
                $programFiles = [string]$windowsKey.GetValue('ProgramFilesDir', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if (-not [string]::IsNullOrEmpty($programFiles)) {
                    $roots.Add((Join-Path $programFiles 'Git'))
                }
            }
        }
        finally {
            if ($null -ne $windowsKey) { $windowsKey.Dispose() }
            if ($null -ne $gitKey) { $gitKey.Dispose() }
            if ($null -ne $base) { $base.Dispose() }
        }
    }
    $selected = $null
    $selectedRoot = $null
    foreach ($root in @($roots | Sort-Object -Unique)) {
        foreach ($relative in @('cmd\git.exe', 'bin\git.exe')) {
            $candidate = Join-Path $root $relative
            if ([IO.File]::Exists($candidate)) {
                $selected = [IO.Path]::GetFullPath($candidate)
                $selectedRoot = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
                break
            }
        }
        if ($null -ne $selected) { break }
    }
    if ($null -eq $selected) {
        throw 'Canonical Git executable was not found through Registry64/Registry32 authority.'
    }
    Assert-FoundationNoReparsePath -LiteralPath $selected
    if (-not $selected.StartsWith($selectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Canonical Git executable escapes its registry root.'
    }
    $item = Get-Item -LiteralPath $selected -Force
    $stream = [IO.File]::Open($selected, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $binding = [pscustomobject]@{
            Path = $selected
            Root = $selectedRoot
            Stream = $stream
            Length = $item.Length
            CreationTimeUtc = $item.CreationTimeUtc
            Identity = Get-FoundationNativeFileIdentity -LiteralPath $selected
            Sha256 = Get-FoundationHostSha256 -Bytes ([IO.File]::ReadAllBytes($selected))
        }
        $script:GitBinding = $binding
        return $binding
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-FoundationGitBinding {
    [CmdletBinding()]
    param()

    if ($null -eq $script:GitBinding -or $null -eq $script:GitBinding.Stream) {
        throw 'Canonical Git binding is absent.'
    }
    $item = Get-Item -LiteralPath $script:GitBinding.Path -Force
    if ($item.Length -ne $script:GitBinding.Length -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (-not $item.FullName.StartsWith($script:GitBinding.Root, [StringComparison]::OrdinalIgnoreCase)) -or (Get-FoundationNativeFileIdentity -LiteralPath $item.FullName) -ne $script:GitBinding.Identity -or (Get-FoundationHostSha256 -Bytes ([IO.File]::ReadAllBytes($item.FullName))) -ne $script:GitBinding.Sha256) {
        throw 'Canonical Git binding identity changed.'
    }
}

function Initialize-FoundationGitProcessScript {
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrEmpty($script:GitProcessScriptPath)) {
        return
    }
    $script:GitProcessScriptPath = Join-Path $stateRoot 'Invoke-FoundationGitBinary.ps1'
    $scriptText = @'
param(
    [string]$FoundationHostAssemblyPath,
    [string]$GitPath,
    [string]$WorkingDirectory,
    [string]$ArgumentsBase64,
    [string]$EnvironmentBase64,
    [string]$InputPath,
    [int]$StandardOutputCap,
    [int]$StandardErrorCap,
    [int]$TimeoutMilliseconds,
    [string]$StandardOutputPath,
    [string]$StandardErrorPath,
    [string]$ExitCodePath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Write-ExchangeBytes([string]$Path,[byte[]]$Bytes){
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    try{$stream.SetLength(0);if($Bytes.Length-ne 0){$stream.Write($Bytes,0,$Bytes.Length)};$stream.Flush($true)}
    finally{$stream.Dispose()}
}
Add-Type -Path $FoundationHostAssemblyPath
$strictUtf8=[Text.UTF8Encoding]::new($false,$true)
$decodedArguments=$strictUtf8.GetString([Convert]::FromBase64String($ArgumentsBase64))|ConvertFrom-Json
$arguments=@()
foreach($item in $decodedArguments){$arguments += [string]$item}
$environmentDocument=$strictUtf8.GetString([Convert]::FromBase64String($EnvironmentBase64))|ConvertFrom-Json
$environmentNames=[Collections.Generic.List[string]]::new()
$environmentValues=[Collections.Generic.List[string]]::new()
foreach($property in $environmentDocument.PSObject.Properties){
    $environmentNames.Add([string]$property.Name)
    $environmentValues.Add([string]$property.Value)
}
$inputBytes=if($InputPath -eq '__NONE__'){$null}else{[IO.File]::ReadAllBytes($InputPath)}
$result=[Pspkt.Certification.FoundationHost.BinaryProcess]::Run(
    $GitPath,
    [string[]]$arguments,
    $WorkingDirectory,
    $environmentNames.ToArray(),
    $environmentValues.ToArray(),
    $inputBytes,
    $StandardOutputCap,
    $StandardErrorCap,
    $TimeoutMilliseconds)
Write-ExchangeBytes -Path $StandardOutputPath -Bytes $result.StandardOutput
Write-ExchangeBytes -Path $StandardErrorPath -Bytes $result.StandardError
Write-ExchangeBytes -Path $ExitCodePath -Bytes ([Text.Encoding]::ASCII.GetBytes($result.ExitCode.ToString([Globalization.CultureInfo]::InvariantCulture)))
'@
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($scriptText)
    $stream = [IO.File]::Open($script:GitProcessScriptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $binding = New-FoundationFileBinding -LiteralPath $script:GitProcessScriptPath -Role 'generated:git-binary-process'
    $script:GeneratedFileBindings.Add($binding)
}

function New-FoundationGitEnvironment {
    [CmdletBinding()]
    param(
        [string]$GitDirectory,
        [string]$WorkTree,
        [string]$IndexPath
    )

    $scratchHome = Join-Path $ScratchRoot 'home'
    [IO.Directory]::CreateDirectory((Join-Path $scratchHome '.config')) | Out-Null
    $environment = [ordered]@{
        SystemRoot = $script:WindowsRoot
        WINDIR = $script:WindowsRoot
        TEMP = [IO.Path]::GetTempPath().TrimEnd('\')
        TMP = [IO.Path]::GetTempPath().TrimEnd('\')
        PATH = "$(Join-Path $script:WindowsRoot 'System32');$script:WindowsRoot"
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL = 'NUL'
        GIT_CONFIG_SYSTEM = 'NUL'
        GIT_DEFAULT_HASH = 'sha1'
        GIT_NO_REPLACE_OBJECTS = '1'
        GIT_OPTIONAL_LOCKS = '0'
        HOME = $scratchHome
        XDG_CONFIG_HOME = Join-Path $scratchHome '.config'
    }
    if (-not [string]::IsNullOrEmpty($GitDirectory)) { $environment.GIT_DIR = $GitDirectory }
    if (-not [string]::IsNullOrEmpty($WorkTree)) { $environment.GIT_WORK_TREE = $WorkTree }
    if (-not [string]::IsNullOrEmpty($IndexPath)) { $environment.GIT_INDEX_FILE = $IndexPath }
    return $environment
}

function New-FoundationGitExchangeFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    if ([IO.File]::Exists($LiteralPath)) { throw "Git exchange path already exists: $LiteralPath" }
    $writer = $null
    $pin = $null
    $creationIdentity = $null
    $ownedRecord = $null
    $primaryError = $null
    $cleanupErrors = [Collections.Generic.List[Exception]]::new()
    try {
        $writer = [IO.File]::Open($LiteralPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
        if ($Bytes.Length -ne 0) { $writer.Write($Bytes,0,$Bytes.Length) }
        $writer.Flush($true)
        $pin = [IO.File]::Open($LiteralPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $writer.Dispose()
        $writer = $null
        $creationIdentity = Get-FoundationNativeFileIdentity -LiteralPath $LiteralPath
        $ownedRecord = Get-FoundationOwnedFileRecord -LiteralPath $LiteralPath
        if ($ownedRecord.Identity -cne $creationIdentity) { throw 'Git exchange identity changed during creation.' }
        return [pscustomobject]@{
            Path = [IO.Path]::GetFullPath($LiteralPath)
            Pin = $pin
            Identity = $creationIdentity
        }
    }
    catch {
        $primaryError = $_.Exception
    }
    if ($null -ne $writer) {
        try { $writer.Dispose() }
        catch { $cleanupErrors.Add($_.Exception) }
    }
    if ($null -ne $pin) {
        try { $pin.Dispose() }
        catch { $cleanupErrors.Add($_.Exception) }
    }
    if ($null -ne $ownedRecord -and $ownedRecord.Identity -ceq $creationIdentity) {
        try { Remove-FoundationOwnedFile -Record $ownedRecord }
        catch { $cleanupErrors.Add($_.Exception) }
    }
    if ($cleanupErrors.Count -ne 0) {
        $errors = [Collections.Generic.List[Exception]]::new()
        $errors.Add($primaryError)
        foreach ($cleanupError in $cleanupErrors) { $errors.Add($cleanupError) }
        throw [AggregateException]::new('Git exchange creation and cleanup failed.', $errors.ToArray())
    }
    throw $primaryError
}

function Read-FoundationGitExchangeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Resource,
        [Parameter(Mandatory = $true)][int64]$MaximumLength
    )

    if (-not [IO.File]::Exists($Resource.Path) -or
        (Get-FoundationNativeFileIdentity -LiteralPath $Resource.Path) -cne [string]$Resource.Identity -or
        $Resource.Pin.Length -gt $MaximumLength -or $Resource.Pin.Length -gt [int]::MaxValue) {
        throw "Git exchange ownership changed: $($Resource.Path)"
    }
    $bytes = [byte[]]::new([int]$Resource.Pin.Length)
    $Resource.Pin.Position = 0
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Resource.Pin.Read($bytes,$offset,[Math]::Min(65536,$bytes.Length-$offset))
        if ($read -eq 0) { throw "Git exchange read ended early: $($Resource.Path)" }
        $offset += $read
    }
    return ,$bytes
}

function Remove-FoundationGitExchangeFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resource)

    $ownedRecord = $null
    $primaryError = $null
    try {
        if (-not [IO.File]::Exists($Resource.Path) -or
            (Get-FoundationNativeFileIdentity -LiteralPath $Resource.Path) -cne [string]$Resource.Identity) {
            throw "Git exchange ownership changed: $($Resource.Path)"
        }
        $ownedRecord = Get-FoundationOwnedFileRecord -LiteralPath $Resource.Path
    }
    catch { $primaryError = $_.Exception }
    $disposeError = $null
    try { $Resource.Pin.Dispose() }
    catch { $disposeError = $_.Exception }
    if ($null -ne $primaryError -and $null -ne $disposeError) {
        throw [AggregateException]::new('Git exchange verification and pin disposal failed.', [Exception[]]@($primaryError,$disposeError))
    }
    if ($null -ne $primaryError) { throw $primaryError }
    if ($null -ne $disposeError) { throw $disposeError }
    Remove-FoundationOwnedFile -Record $ownedRecord
}

function Invoke-FoundationGitRaw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepositoryRoot,
        [int[]]$AcceptedExitCodes = @(0),
        [int]$StandardOutputCap = 1048576,
        [int]$StandardErrorCap = 1048576,
        [byte[]]$StandardInput,
        [Collections.IDictionary]$Environment
    )

    Assert-FoundationGitBinding
    Assert-FoundationHostBinding
    Initialize-FoundationGitProcessScript
    if ($null -eq $Environment) {
        $Environment = New-FoundationGitEnvironment
    }
    $forcedGitRoute = [Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_FORCE_GIT_EXIT')
    if (($forcedGitRoute -ceq 'raw' -and $null -eq $script:BoundedGitContext) -or
        ($forcedGitRoute -ceq 'bounded' -and $null -ne $script:BoundedGitContext)) {
        $Arguments = @('rev-parse','--verify','refs/heads/__pspkt_missing__')
    }

    $gitArguments = [string[]]@(
        '--no-replace-objects',
        '--no-lazy-fetch',
        '-c',"core.hooksPath=$(Join-Path $ScratchRoot 'no-hooks')",
        '-c','gc.auto=0',
        '-c','maintenance.auto=false',
        '-c','core.fsmonitor=false',
        '-c','core.untrackedCache=false'
    ) + $Arguments
    $nonce = [guid]::NewGuid().ToString('N')
    $standardOutputPath = Join-Path $stateRoot "git-$nonce.stdout.bin"
    $standardErrorPath = Join-Path $stateRoot "git-$nonce.stderr.bin"
    $exitCodePath = Join-Path $stateRoot "git-$nonce.exit.txt"
    $inputPath = Join-Path $stateRoot "git-$nonce.stdin.bin"
    $argumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-PspktCanonicalJson -Value @($gitArguments))))
    $environmentBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-PspktCanonicalJson -Value $Environment)))
    $resources = [Collections.Generic.List[object]]::new()
    $standardOutputResource = $null
    $standardErrorResource = $null
    $exitCodeResource = $null
    $inputResource = $null
    $primaryError = $null
    $cleanupErrors = [Collections.Generic.List[Exception]]::new()
    $retirementProven = $false
    $handoffStarted = $false
    $result = $null
    try {
        $standardOutputResource = New-FoundationGitExchangeFile -LiteralPath $standardOutputPath -Bytes ([byte[]]::new(0))
        $resources.Add($standardOutputResource)
        $standardErrorResource = New-FoundationGitExchangeFile -LiteralPath $standardErrorPath -Bytes ([byte[]]::new(0))
        $resources.Add($standardErrorResource)
        $exitCodeResource = New-FoundationGitExchangeFile -LiteralPath $exitCodePath -Bytes ([byte[]]::new(0))
        $resources.Add($exitCodeResource)
        if ($null -ne $StandardInput) {
            $inputResource = New-FoundationGitExchangeFile -LiteralPath $inputPath -Bytes $StandardInput
            $resources.Add($inputResource)
        }
        $payloadArguments = @(
            $script:FoundationHostBinding.DllPath,
            $script:GitBinding.Path,
            $WorkingDirectory,
            $argumentsBase64,
            $environmentBase64,
            $(if ($null -eq $inputResource) { '__NONE__' } else { $inputPath }),
            [string]$StandardOutputCap,
            [string]$StandardErrorCap,
            '120000',
            $standardOutputPath,
            $standardErrorPath,
            $exitCodePath
        )
        $handoffStarted = $true
        if ($null -ne $script:BoundedGitContext) {
            $completedProcessResult = $null
            try {
                Invoke-FoundationBoundedPowerShell -HelperAssembly $script:BoundedGitContext.Assembly -HostPath $script:BoundedGitContext.HostPath -WrapperPath $script:BoundedGitContext.WrapperPath -PayloadPath $script:GitProcessScriptPath -PayloadArguments $payloadArguments -TimeoutMilliseconds 150000 -CompletedProcessResult ([ref]$completedProcessResult) | Out-Null
            }
            catch { $primaryError = $_.Exception }
            $retirementProven = $null -ne $completedProcessResult
        }
        else {
            $rawArguments = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$script:GitProcessScriptPath) + $payloadArguments
            try {
                $rawResult = Get-FoundationRawProcessResult -FileName $script:RawLaunchAuthority.HostPath -Arguments $rawArguments -TimeoutMilliseconds 150000 -WorkingDirectory $stateRoot
                $retirementProven = $true
                if ($rawResult.ExitCode -ne 0) {
                    $primaryError = [InvalidOperationException]::new("Bounded Git helper failed: $($rawResult.StdOut)$($rawResult.StdErr)")
                }
            }
            catch { $primaryError = $_.Exception }
        }
        if ($null -eq $primaryError) {
            if (-not $retirementProven) { throw 'Bounded Git helper retirement was not proven.' }
            [byte[]]$exitCodeBytes = Read-FoundationGitExchangeBytes -Resource $exitCodeResource -MaximumLength 32
            $exitCodeText = [Text.Encoding]::ASCII.GetString($exitCodeBytes)
            $parsedExitCode = 0
            if ($exitCodeText -cnotmatch '^-?[0-9]+$' -or
                -not [int]::TryParse($exitCodeText,[Globalization.NumberStyles]::Integer,[Globalization.CultureInfo]::InvariantCulture,[ref]$parsedExitCode)) {
                throw 'Git helper did not publish a valid exit code.'
            }
            [byte[]]$standardOutput = Read-FoundationGitExchangeBytes -Resource $standardOutputResource -MaximumLength $StandardOutputCap
            [byte[]]$standardError = Read-FoundationGitExchangeBytes -Resource $standardErrorResource -MaximumLength $StandardErrorCap
            if ($AcceptedExitCodes -notcontains $parsedExitCode) {
                $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
                throw "git failed with exit $parsedExitCode`: $($strictUtf8.GetString($standardError))"
            }
            $result = [pscustomobject]@{
                ExitCode = $parsedExitCode
                StandardOutput = $standardOutput
                StandardError = $standardError
            }
        }
    }
    catch {
        if ($null -eq $primaryError) { $primaryError = $_.Exception }
    }
    finally {
        if ($retirementProven -or -not $handoffStarted) {
            foreach ($resource in $resources) {
                try { Remove-FoundationGitExchangeFile -Resource $resource }
                catch { $cleanupErrors.Add($_.Exception) }
            }
        }
        try { Assert-FoundationGitBinding }
        catch { $cleanupErrors.Add($_.Exception) }
        try { Assert-FoundationHostBinding }
        catch { $cleanupErrors.Add($_.Exception) }
    }
    if ($null -ne $primaryError) {
        if ($cleanupErrors.Count -ne 0) {
            $errors = [Collections.Generic.List[Exception]]::new()
            $errors.Add($primaryError)
            foreach ($cleanupError in $cleanupErrors) { $errors.Add($cleanupError) }
            throw [AggregateException]::new('Git execution and cleanup failed.', $errors.ToArray())
        }
        throw $primaryError
    }
    if ($cleanupErrors.Count -eq 1) { throw $cleanupErrors[0] }
    if ($cleanupErrors.Count -gt 1) {
        throw [AggregateException]::new('Git cleanup failed.', $cleanupErrors.ToArray())
    }
    return $result
}

function Invoke-FoundationPrivateGitRaw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Environment,
        [int[]]$AcceptedExitCodes = @(0),
        [int]$StandardOutputCap = 1048576,
        [byte[]]$StandardInput
    )

    return Invoke-FoundationGitRaw -Arguments $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment -AcceptedExitCodes $AcceptedExitCodes -StandardOutputCap $StandardOutputCap -StandardInput $StandardInput
}

function Get-FoundationPrivateGitOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Environment
    )

    $result = Invoke-FoundationPrivateGitRaw -Arguments $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment
    $text = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$result.StandardOutput)
    if ([string]::IsNullOrEmpty($text)) { return @() }
    return @($text -split '\r?\n' | Where-Object { $_.Length -gt 0 })
}

function ConvertFrom-FoundationStrictUtf8 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
}

function Get-FoundationGitOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepositoryRoot,
        [int[]]$AcceptedExitCodes = @(0),
        [Collections.IDictionary]$Environment
    )

    $result = Invoke-FoundationGitRaw -Arguments $Arguments -WorkingDirectory $WorkingDirectory -AcceptedExitCodes $AcceptedExitCodes -StandardOutputCap $bootstrapContract.GitScalarMaximumBytes -Environment $Environment
    $text = ConvertFrom-FoundationStrictUtf8 -Bytes $result.StandardOutput
    if ([string]::IsNullOrEmpty($text)) { return @() }
    return @($text -split '\r?\n' | Where-Object { $_.Length -gt 0 })
}

function ConvertFrom-FoundationGitNulPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    if ($Bytes.Length -eq 0) { return @() }
    if ($Bytes[$Bytes.Length - 1] -ne 0) { throw 'Git NUL path projection is not terminated.' }
    $paths = [Collections.Generic.List[string]]::new()
    $recordStart = 0
    for ($index = 0; $index -lt $Bytes.Length; $index++) {
        if ($Bytes[$index] -ne 0) { continue }
        $recordLength = $index - $recordStart
        if ($recordLength -eq 0) { throw 'Git NUL path projection contains an empty record.' }
        $recordBytes = [byte[]]::new($recordLength)
        [Array]::Copy($Bytes, $recordStart, $recordBytes, 0, $recordLength)
        $path = ConvertFrom-FoundationStrictUtf8 -Bytes $recordBytes
        $paths.Add((Assert-FoundationDecodedGitPath -Path $path))
        $recordStart = $index + 1
    }
    return $paths.ToArray()
}

function Get-FoundationGitNulPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepositoryRoot,
        [Collections.IDictionary]$Environment
    )

    $result = Invoke-FoundationGitRaw -Arguments $Arguments -WorkingDirectory $WorkingDirectory -StandardOutputCap $bootstrapContract.GitNulPathMaximumBytes -Environment $Environment
    return ConvertFrom-FoundationGitNulPaths -Bytes $result.StandardOutput
}

function Get-FoundationFileSha {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    return Get-FoundationHostSha256 -Bytes ([IO.File]::ReadAllBytes($LiteralPath))
}

function Assert-FoundationNoReparsePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [switch]$AllowMissingLeaf
    )

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($fullPath)
    $relative = $fullPath.Substring($root.Length)
    $current = $root
    $rootItem = Get-Item -LiteralPath $root -Force
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse point rejected or root is not a directory: $root"
    }
    $segments = $relative.Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries)
    for ($index = 0; $index -lt $segments.Length; $index++) {
        $current = Join-Path $current $segments[$index]
        if (-not (Test-Path -LiteralPath $current)) {
            if ($AllowMissingLeaf -and $index -eq $segments.Length - 1) {
                return
            }
            throw "Path segment missing: $current"
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point rejected: $current"
        }
    }
}

function ConvertTo-FoundationWindowsArgument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -gt 0 -and $Value.IndexOfAny([char[]]@(' ', "`t", "`n", [char]11, '"')) -lt 0) {
        return $Value
    }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $index = 0
    while ($true) {
        $backslashes = 0
        while ($index -lt $Value.Length -and $Value[$index] -eq '\') {
            $index++
            $backslashes++
        }
        if ($index -eq $Value.Length) {
            [void]$builder.Append('\', $backslashes * 2)
            break
        }
        if ($Value[$index] -eq '"') {
            [void]$builder.Append('\', $backslashes * 2 + 1)
            [void]$builder.Append('"')
        }
        else {
            [void]$builder.Append('\', $backslashes)
            [void]$builder.Append($Value[$index])
        }
        $index++
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

$foundationRawLaunchWrapperSource = @'
param(
    [Parameter(Mandatory = $true)][string]$GateName,
    [Parameter(Mandatory = $true)][string]$PayloadBase64
)
try {
    $gate = [Threading.EventWaitHandle]::OpenExisting($GateName, [System.Security.AccessControl.EventWaitHandleRights]::Synchronize)
    if ($null -eq $gate -or -not $gate.WaitOne(120000)) {
        exit 92
    }
}
catch {
    exit 92
}
finally {
    if ($null -ne $gate) {
        $gate.Dispose()
    }
}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function ConvertTo-WrapperWindowsArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value.IndexOfAny([char[]]@(' ', "`t", "`n", [char]11, '"')) -lt 0) {
        return $Value
    }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $index = 0
    while ($true) {
        $backslashes = 0
        while ($index -lt $Value.Length -and $Value[$index] -eq '\') {
            $index++
            $backslashes++
        }
        if ($index -eq $Value.Length) {
            [void]$builder.Append('\', $backslashes * 2)
            break
        }
        if ($Value[$index] -eq '"') {
            [void]$builder.Append('\', $backslashes * 2 + 1)
            [void]$builder.Append('"')
        }
        else {
            [void]$builder.Append('\', $backslashes)
            [void]$builder.Append($Value[$index])
        }
        $index++
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}
try {
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PayloadBase64))
    $payload = $payloadJson | ConvertFrom-Json
    Add-Type -Path ([string]$payload.foundationHostAssemblyPath)
    [Pspkt.Certification.FoundationHost.NativeJobAuthority]::ClearStandardHandleInheritance()
    $targetArguments = @($payload.arguments | ForEach-Object { [string]$_ })
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [string]$payload.targetPath
    $startInfo.Arguments = (@($targetArguments | ForEach-Object { ConvertTo-WrapperWindowsArgument -Value $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = [string]$payload.workingDirectory
    $startInfo.EnvironmentVariables.Clear()
    foreach ($entry in @($payload.environment)) {
        $startInfo.EnvironmentVariables[[string]$entry.name] = [string]$entry.value
    }
    $target = [Diagnostics.Process]::new()
    $target.StartInfo = $startInfo
    try {
        if (-not $target.Start()) {
            exit 93
        }
        $standardOutput = [Console]::OpenStandardOutput()
        $standardError = [Console]::OpenStandardError()
        $stdoutTask = $target.StandardOutput.BaseStream.CopyToAsync($standardOutput)
        $stderrTask = $target.StandardError.BaseStream.CopyToAsync($standardError)
        $target.WaitForExit()
        $copyTasks = [Threading.Tasks.Task[]]@($stdoutTask,$stderrTask)
        if (-not [Threading.Tasks.Task]::WaitAll($copyTasks, 5000)) {
            $target.StandardOutput.Dispose()
            $target.StandardError.Dispose()
            try {
                [void][Threading.Tasks.Task]::WaitAll($copyTasks, 5000)
            }
            catch [AggregateException] {
                if (-not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted) {
                    throw
                }
            }
            if (-not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted) {
                throw [TimeoutException]::new('Raw wrapper target stream copies did not terminate.')
            }
        }
        $standardOutput.Flush()
        $standardError.Flush()
        exit $target.ExitCode
    }
    finally {
        $target.Dispose()
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 93
}
'@
$script:RawLaunchAuthority = $null

function ConvertTo-FoundationRawLaunchPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    $environmentEntries = @(
        foreach ($name in @($Environment.Keys | Sort-Object)) {
            [ordered]@{ name = [string]$name; value = [string]$Environment[$name] }
        }
    )
    $json = [ordered]@{
        foundationHostAssemblyPath = $script:FoundationHostBinding.DllPath
        targetPath = $TargetPath
        arguments = [string[]]$Arguments
        workingDirectory = $WorkingDirectory
        environment = $environmentEntries
    } | ConvertTo-Json -Compress -Depth 4
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    if ($payload.Length -gt 24000) {
        throw 'Raw launch payload exceeds the bounded wrapper command-line budget.'
    }
    return $payload
}

function Assert-FoundationRawLaunchAuthority {
    [CmdletBinding()]
    param()

    if ($null -eq $script:RawLaunchAuthority) {
        throw 'Raw launch authority is absent.'
    }
    Assert-FoundationPowerShellBinding -LiteralPath $script:RawLaunchAuthority.HostPath
    Assert-FoundationFileBinding -Binding $script:RawLaunchAuthority.WrapperBinding
}

function Stop-FoundationProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Diagnostics.Process]$Process,
        [int]$CleanupTimeoutMilliseconds = 15000
    )

    try {
        if ($Process.HasExited) {
            return
        }
        $Process.Kill()
    }
    catch [InvalidOperationException] {
        if ($Process.HasExited) {
            return
        }
        throw
    }
    if (-not $Process.WaitForExit($CleanupTimeoutMilliseconds)) {
        throw [TimeoutException]::new("Process termination timed out after $CleanupTimeoutMilliseconds ms.")
    }
    $Process.Refresh()
    if (-not $Process.HasExited) {
        throw [InvalidOperationException]::new('Process termination could not be confirmed.')
    }
}

function Complete-FoundationRawRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][Threading.Tasks.Task[int]]$ReadTask,
        [Parameter(Mandatory = $true)][byte[]]$Buffer,
        [int]$CleanupTimeoutMilliseconds = 15000
    )

    $clock = [Diagnostics.Stopwatch]::StartNew()
    $currentTask = $ReadTask
    while ($true) {
        while (-not $currentTask.IsCompleted -and $clock.ElapsedMilliseconds -lt $CleanupTimeoutMilliseconds) {
            [Threading.Thread]::Sleep(1)
        }
        if (-not $currentTask.IsCompleted) {
            $Stream.Dispose()
            $forcedCloseClock = [Diagnostics.Stopwatch]::StartNew()
            while (-not $currentTask.IsCompleted -and $forcedCloseClock.ElapsedMilliseconds -lt $CleanupTimeoutMilliseconds) {
                [Threading.Thread]::Sleep(1)
            }
            if (-not $currentTask.IsCompleted) {
                throw [TimeoutException]::new('Raw process stream read did not terminate after forced close.')
            }
        }
        $count = $currentTask.GetAwaiter().GetResult()
        if ($count -eq 0) {
            return
        }
        if ($clock.ElapsedMilliseconds -ge $CleanupTimeoutMilliseconds) {
            throw [TimeoutException]::new('Raw process stream did not reach EOF before the cleanup deadline.')
        }
        $currentTask = $Stream.ReadAsync($Buffer, 0, $Buffer.Length)
    }
}

function Invoke-FoundationRawProcessCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][bool]$ProcessStarted,
        [IntPtr]$Job,
        [IO.Stream]$StdOutStream,
        [Threading.Tasks.Task[int]]$StdOutTask,
        [byte[]]$StdOutBuffer,
        [IO.Stream]$StdErrStream,
        [Threading.Tasks.Task[int]]$StdErrTask,
        [byte[]]$StdErrBuffer,
        [Threading.EventWaitHandle]$Gate,
        [int]$CleanupTimeoutMilliseconds = 15000
    )

    $errors = [Collections.Generic.List[Exception]]::new()
    if ($Job -ne [IntPtr]::Zero) {
        try { Stop-FoundationNativeJob -Job $Job }
        catch { $errors.Add($_.Exception) }
        try { Wait-FoundationNativeJobEmpty -Job $Job -TimeoutMilliseconds $CleanupTimeoutMilliseconds }
        catch { $errors.Add($_.Exception) }
    }
    if ($ProcessStarted) {
        try { Stop-FoundationProcess -Process $Process -CleanupTimeoutMilliseconds $CleanupTimeoutMilliseconds }
        catch { $errors.Add($_.Exception) }
    }
    if ($null -ne $StdOutStream) {
        if ($null -ne $StdOutTask) {
            try { Complete-FoundationRawRead -Stream $StdOutStream -ReadTask $StdOutTask -Buffer $StdOutBuffer -CleanupTimeoutMilliseconds $CleanupTimeoutMilliseconds }
            catch { $errors.Add($_.Exception) }
            try { $StdOutStream.Dispose() }
            catch { $errors.Add($_.Exception) }
        }
        else {
            try { $StdOutStream.Dispose() }
            catch { $errors.Add($_.Exception) }
        }
    }
    if ($null -ne $StdErrStream) {
        if ($null -ne $StdErrTask) {
            try { Complete-FoundationRawRead -Stream $StdErrStream -ReadTask $StdErrTask -Buffer $StdErrBuffer -CleanupTimeoutMilliseconds $CleanupTimeoutMilliseconds }
            catch { $errors.Add($_.Exception) }
            try { $StdErrStream.Dispose() }
            catch { $errors.Add($_.Exception) }
        }
        else {
            try { $StdErrStream.Dispose() }
            catch { $errors.Add($_.Exception) }
        }
    }
    if ($Job -ne [IntPtr]::Zero) {
        try { Close-FoundationNativeJob -Job $Job }
        catch { $errors.Add($_.Exception) }
    }
    if ($null -ne $Gate) {
        try { $Gate.Dispose() }
        catch { $errors.Add($_.Exception) }
    }
    return ,$errors
}

function Get-FoundationRawProcessResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [int]$TimeoutMilliseconds,
        [int]$RetainCapBytes = 1048576,
        [string]$WorkingDirectory = [Environment]::SystemDirectory,
        [hashtable]$Environment,
        [switch]$FoundationHostBootstrap
    )

    if ($FoundationHostBootstrap) {
        if ($null -ne $script:FoundationHostBinding) {
            throw 'FoundationHost bootstrap process launch is forbidden after HostReady.'
        }
    }
    elseif ($null -eq $script:FoundationHostBinding) {
        throw 'FoundationHost must be initialized before a raw process launch.'
    }
    if ($null -eq $Environment) {
        $Environment = @{
            SystemRoot = $script:WindowsRoot
            WINDIR = $script:WindowsRoot
            TEMP = [IO.Path]::GetTempPath().TrimEnd('\')
            TMP = [IO.Path]::GetTempPath().TrimEnd('\')
            PATH = "$(Join-Path $script:WindowsRoot 'System32');$script:WindowsRoot"
        }
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $gate = $null
    $gateClosed = $false
    if ($FoundationHostBootstrap) {
        $startInfo.FileName = $FileName
        $launchArguments = [string[]]$Arguments
        $launchEnvironment = $Environment
        $launchWorkingDirectory = $WorkingDirectory
    }
    else {
        Assert-FoundationRawLaunchAuthority
        $payloadBase64 = ConvertTo-FoundationRawLaunchPayload -TargetPath $FileName -Arguments $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment
        $gateName = 'Local\PspktPhase4FoundationRaw' + [guid]::NewGuid().ToString('N')
        $createdNew = $false
        $gate = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $gateName, [ref]$createdNew)
        if (-not $createdNew) {
            $gate.Dispose()
            throw 'Raw launch gate name already exists.'
        }
        $startInfo.FileName = $script:RawLaunchAuthority.HostPath
        $launchArguments = [string[]]@(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $script:RawLaunchAuthority.WrapperPath,
            '-GateName',
            $gateName,
            '-PayloadBase64',
            $payloadBase64
        )
        $launchEnvironment = @{
            SystemRoot = $script:WindowsRoot
            WINDIR = $script:WindowsRoot
            TEMP = [IO.Path]::GetTempPath().TrimEnd('\')
            TMP = [IO.Path]::GetTempPath().TrimEnd('\')
            PATH = "$(Join-Path $script:WindowsRoot 'System32');$script:WindowsRoot"
        }
        $launchWorkingDirectory = [Environment]::SystemDirectory
    }
    $quotedArguments = @($launchArguments | ForEach-Object { ConvertTo-FoundationWindowsArgument -Value $_ })
    $startInfo.Arguments = $quotedArguments -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $launchWorkingDirectory
    $startInfo.EnvironmentVariables.Clear()
    foreach ($name in $launchEnvironment.Keys) {
        $startInfo.EnvironmentVariables[[string]$name] = [string]$launchEnvironment[$name]
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $job = [IntPtr]::Zero
    $jobClosed = $false
    $processStarted = $false
    $stdout = $null
    $stderr = $null
    $stdoutTask = $null
    $stderrTask = $null
    $stdoutBuffer = $null
    $stderrBuffer = $null
    $primaryError = $null
    $result = $null
    try {
        if (-not $FoundationHostBootstrap) {
            $job = New-FoundationNativeJob
        }
        if (-not $process.Start()) {
            throw "Unable to start $FileName"
        }
        $processStarted = $true
        if ($job -ne [IntPtr]::Zero) {
            if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_FAIL_RAW_ASSIGN') -eq '1') {
                throw 'Injected raw wrapper assignment failure.'
            }
            Add-FoundationProcessToNativeJob -Job $job -Process $process.Handle
            if ((Get-FoundationNativeJobActiveProcessCount -Job $job) -lt 1) {
                throw 'Raw wrapper Job active-process verification failed.'
            }
            if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_FAIL_RAW_MEMBERSHIP') -eq '1' -or -not (Test-FoundationProcessInNativeJob -Job $job -Process $process.Handle)) {
                throw 'Raw wrapper exact Job membership verification failed.'
            }
            if (-not $gate.Set()) {
                throw 'Raw wrapper gate signal failed.'
            }
        }
        $stdout = [IO.MemoryStream]::new()
        $stderr = [IO.MemoryStream]::new()
        $stdoutBuffer = [byte[]]::new(4096)
        $stderrBuffer = [byte[]]::new(4096)
        $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
        $stdoutDone = $false
        $stderrDone = $false
        $clock = [Diagnostics.Stopwatch]::StartNew()
        try {
            while (-not $stdoutDone -or -not $stderrDone) {
                if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                    $primaryError = [TimeoutException]::new("Process timed out: $FileName")
                    break
                }
                if (-not $stdoutDone -and $stdoutTask.IsCompleted) {
                    $count = $stdoutTask.GetAwaiter().GetResult()
                    if ($count -eq 0) {
                        $stdoutDone = $true
                    }
                    else {
                        if ($stdout.Length + $count -gt $RetainCapBytes) {
                            $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
                            $primaryError = [IO.IOException]::new("Process stdout exceeded cap: $FileName")
                            break
                        }
                        $stdout.Write($stdoutBuffer, 0, $count)
                        $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
                    }
                }
                if (-not $stderrDone -and $stderrTask.IsCompleted) {
                    $count = $stderrTask.GetAwaiter().GetResult()
                    if ($count -eq 0) {
                        $stderrDone = $true
                    }
                    else {
                        if ($stderr.Length + $count -gt $RetainCapBytes) {
                            $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
                            $primaryError = [IO.IOException]::new("Process stderr exceeded cap: $FileName")
                            break
                        }
                        $stderr.Write($stderrBuffer, 0, $count)
                        $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
                    }
                }
                if ((-not $stdoutDone -and -not $stdoutTask.IsCompleted) -or (-not $stderrDone -and -not $stderrTask.IsCompleted)) {
                    [Threading.Thread]::Sleep(1)
                }
            }
            if ($null -eq $primaryError -and -not $process.WaitForExit([Math]::Max(1, $TimeoutMilliseconds - [int]$clock.ElapsedMilliseconds))) {
                $primaryError = [TimeoutException]::new("Process exit timed out: $FileName")
            }
            if ($null -eq $primaryError -and $job -ne [IntPtr]::Zero) {
                try {
                    Wait-FoundationNativeJobEmpty -Job $job -TimeoutMilliseconds 15000
                }
                catch {
                    $primaryError = [InvalidOperationException]::new('Raw process descendants survived normal completion.', $_.Exception)
                }
            }
        }
        catch {
            $primaryError = $_.Exception
        }
        if ($null -ne $primaryError) {
            $cleanupErrors = Invoke-FoundationRawProcessCleanup -Process $process -ProcessStarted $processStarted -Job $job -StdOutStream $process.StandardOutput.BaseStream -StdOutTask $stdoutTask -StdOutBuffer $stdoutBuffer -StdErrStream $process.StandardError.BaseStream -StdErrTask $stderrTask -StdErrBuffer $stderrBuffer -Gate $gate
            $jobClosed = $job -ne [IntPtr]::Zero
            $gateClosed = $null -ne $gate
            if ($cleanupErrors.Count -gt 0) {
                $allErrors = [Collections.Generic.List[Exception]]::new()
                $allErrors.Add($primaryError)
                foreach ($cleanupError in $cleanupErrors) { $allErrors.Add($cleanupError) }
                throw [AggregateException]::new('Raw process failed and cleanup could not be fully confirmed.', $allErrors)
            }
            throw $primaryError
        }
        if ($job -ne [IntPtr]::Zero) {
            Close-FoundationNativeJob -Job $job
            $jobClosed = $true
        }
        if ($null -ne $gate) {
            $gate.Dispose()
            $gateClosed = $true
        }
        $result = [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = [Text.Encoding]::UTF8.GetString($stdout.ToArray())
            StdErr = [Text.Encoding]::UTF8.GetString($stderr.ToArray())
        }
        $process.StandardOutput.Dispose()
        $process.StandardError.Dispose()
    }
    catch {
        if ($null -eq $primaryError) {
            $primaryError = $_.Exception
            $cleanupErrors = Invoke-FoundationRawProcessCleanup -Process $process -ProcessStarted $processStarted -Job $(if ($jobClosed) { [IntPtr]::Zero } else { $job }) -StdOutStream $(if ($processStarted) { $process.StandardOutput.BaseStream } else { $null }) -StdOutTask $stdoutTask -StdOutBuffer $stdoutBuffer -StdErrStream $(if ($processStarted) { $process.StandardError.BaseStream } else { $null }) -StdErrTask $stderrTask -StdErrBuffer $stderrBuffer -Gate $(if ($gateClosed) { $null } else { $gate })
            $jobClosed = $job -ne [IntPtr]::Zero
            $gateClosed = $null -ne $gate
            if ($cleanupErrors.Count -gt 0) {
                $allErrors = [Collections.Generic.List[Exception]]::new()
                $allErrors.Add($primaryError)
                foreach ($cleanupError in $cleanupErrors) { $allErrors.Add($cleanupError) }
                throw [AggregateException]::new('Raw process failed and cleanup could not be fully confirmed.', $allErrors)
            }
        }
        throw
    }
    finally {
        if ($null -ne $stdout) { $stdout.Dispose() }
        if ($null -ne $stderr) { $stderr.Dispose() }
        if ($null -ne $gate -and -not $gateClosed) { $gate.Dispose() }
        $process.Dispose()
    }
    return $result
}

function Initialize-FoundationHostAssembly {
    [CmdletBinding()]
    param()

    if ($null -ne $script:FoundationHostBinding) {
        Assert-FoundationHostBinding
        return $script:FoundationHostBinding.Assembly
    }
    if ([Environment]::Is64BitProcess) {
        $frameworkRoot = Join-Path $script:WindowsRoot 'Microsoft.NET\Framework64\v4.0.30319'
    }
    else {
        $frameworkRoot = Join-Path $script:WindowsRoot 'Microsoft.NET\Framework\v4.0.30319'
    }
    $compilerPath = Join-Path $frameworkRoot 'csc.exe'
    Assert-FoundationNoReparsePath -LiteralPath $compilerPath
    $compilerItem = Get-Item -LiteralPath $compilerPath -Force
    if ($compilerItem.PSIsContainer -or ($compilerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'FoundationHost compiler is not an ordinary file.'
    }
    $compilerStream = [IO.File]::Open($compilerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sourceStream = $null
    $dllStream = $null
    $succeeded = $false
    try {
        $compilerLength = $compilerItem.Length
        $compilerSha256 = Get-FoundationFileSha -LiteralPath $compilerPath
        $nonce = [guid]::NewGuid().ToString('N')
        $sourcePath = Join-Path $stateRoot "foundation-host-$nonce.cs"
        $dllPath = Join-Path $stateRoot "foundation-host-$nonce.dll"
        $sourceBytes = [Text.UTF8Encoding]::new($false).GetBytes($foundationHostSource)
        $sourceWriteStream = [IO.File]::Open($sourcePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $sourceWriteStream.Write($sourceBytes, 0, $sourceBytes.Length)
            $sourceWriteStream.Flush($true)
        }
        finally {
            $sourceWriteStream.Dispose()
        }
        $sourceStream = [IO.File]::Open($sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $compileResult = Get-FoundationRawProcessResult -FileName $compilerPath -Arguments @('/nologo','/target:library','/optimize+','/langversion:5',"/out:$dllPath",$sourcePath) -TimeoutMilliseconds 120000 -WorkingDirectory $stateRoot -FoundationHostBootstrap
        if ($compileResult.ExitCode -ne 0) {
            throw "FoundationHost compilation failed: $($compileResult.StdOut)$($compileResult.StdErr)"
        }
        if ((Get-Item -LiteralPath $compilerPath -Force).Length -ne $compilerLength -or (Get-FoundationFileSha -LiteralPath $compilerPath) -cne $compilerSha256) {
            throw 'FoundationHost compiler changed during compilation.'
        }
        $dllBytes = [IO.File]::ReadAllBytes($dllPath)
        $dllStream = [IO.File]::Open($dllPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $assembly = [Reflection.Assembly]::Load($dllBytes)
        $type = $assembly.GetType('Pspkt.Certification.FoundationHost.NativeFileSystem', $true, $false)
        $jobType = $assembly.GetType('Pspkt.Certification.FoundationHost.NativeJobAuthority', $true, $false)
        $buildMarkerField = $type.GetField('BuildMarker', [Reflection.BindingFlags]'Public,Static')
        $methods = @{}
        foreach ($methodName in @('GetIdentity','GetDirectoryIdentity','GetLinkCount','MoveReplace','MoveCreateOnly','MoveOwnedFileCreateOnly','DeleteOwnedFile','DeleteOwnedEmptyDirectory')) {
            if ($methodName -eq 'DeleteOwnedFile') {
                $parameterTypes = [type[]]@([string],[string],[int64],[string])
            }
            elseif ($methodName -eq 'MoveOwnedFileCreateOnly') {
                $parameterTypes = [type[]]@([string],[string],[string],[int64],[string])
            }
            elseif ($methodName -like 'Move*' -or $methodName -eq 'DeleteOwnedEmptyDirectory') {
                $parameterTypes = [type[]]@([string],[string])
            }
            else {
                $parameterTypes = [type[]]@([string])
            }
            $method = $type.GetMethod($methodName, [Reflection.BindingFlags]'Public,Static', $null, $parameterTypes, $null)
            if ($null -eq $method) {
                throw "FoundationHost API is incomplete: $methodName"
            }
            $methods[$methodName] = $method
        }
        $jobMethodSignatures = [ordered]@{
            CreateKillOnCloseJob = [type[]]@()
            AssignProcess = [type[]]@([IntPtr],[IntPtr])
            IsProcessAssigned = [type[]]@([IntPtr],[IntPtr])
            TerminateJob = [type[]]@([IntPtr])
            GetActiveProcessCount = [type[]]@([IntPtr])
            WaitForActiveProcessCountZero = [type[]]@([IntPtr],[int])
            CloseJob = [type[]]@([IntPtr])
            ClearStandardHandleInheritance = [type[]]@()
            CloseStandardOutputAndError = [type[]]@()
        }
        foreach ($entry in $jobMethodSignatures.GetEnumerator()) {
            $method = $jobType.GetMethod([string]$entry.Key, [Reflection.BindingFlags]'Public,Static', $null, [type[]]$entry.Value, $null)
            if ($null -eq $method) {
                throw "FoundationHost Job API is incomplete: $($entry.Key)"
            }
            $methods[[string]$entry.Key] = $method
        }
        if ($null -eq $buildMarkerField -or [string]$buildMarkerField.GetValue($null) -cne 'PspktFoundationHostM29' -or $null -eq $assembly.GetType('Pspkt.Certification.FoundationHost.BinaryProcess', $false)) {
            throw 'FoundationHost BuildMarker mismatch.'
        }
        $delegates = @{
            GetIdentity = [Delegate]::CreateDelegate([Func[string,string]], [Reflection.MethodInfo]$methods['GetIdentity'])
            GetDirectoryIdentity = [Delegate]::CreateDelegate([Func[string,string]], [Reflection.MethodInfo]$methods['GetDirectoryIdentity'])
            GetLinkCount = [Delegate]::CreateDelegate([Func[string,uint32]], [Reflection.MethodInfo]$methods['GetLinkCount'])
            MoveReplace = [Delegate]::CreateDelegate([Action[string,string]], [Reflection.MethodInfo]$methods['MoveReplace'])
            MoveCreateOnly = [Delegate]::CreateDelegate([Action[string,string]], [Reflection.MethodInfo]$methods['MoveCreateOnly'])
            MoveOwnedFileCreateOnly = [Delegate]::CreateDelegate([Action[string,string,string,int64,string]], [Reflection.MethodInfo]$methods['MoveOwnedFileCreateOnly'])
            DeleteOwnedFile = [Delegate]::CreateDelegate([Action[string,string,int64,string]], [Reflection.MethodInfo]$methods['DeleteOwnedFile'])
            DeleteOwnedEmptyDirectory = [Delegate]::CreateDelegate([Action[string,string]], [Reflection.MethodInfo]$methods['DeleteOwnedEmptyDirectory'])
            CreateKillOnCloseJob = [Delegate]::CreateDelegate([Func[IntPtr]], [Reflection.MethodInfo]$methods['CreateKillOnCloseJob'])
            AssignProcess = [Delegate]::CreateDelegate([Action[IntPtr,IntPtr]], [Reflection.MethodInfo]$methods['AssignProcess'])
            IsProcessAssigned = [Delegate]::CreateDelegate([Func[IntPtr,IntPtr,bool]], [Reflection.MethodInfo]$methods['IsProcessAssigned'])
            TerminateJob = [Delegate]::CreateDelegate([Action[IntPtr]], [Reflection.MethodInfo]$methods['TerminateJob'])
            GetActiveProcessCount = [Delegate]::CreateDelegate([Func[IntPtr,uint32]], [Reflection.MethodInfo]$methods['GetActiveProcessCount'])
            WaitForActiveProcessCountZero = [Delegate]::CreateDelegate([Action[IntPtr,int]], [Reflection.MethodInfo]$methods['WaitForActiveProcessCountZero'])
            CloseJob = [Delegate]::CreateDelegate([Action[IntPtr]], [Reflection.MethodInfo]$methods['CloseJob'])
            ClearStandardHandleInheritance = [Delegate]::CreateDelegate([Action], [Reflection.MethodInfo]$methods['ClearStandardHandleInheritance'])
            CloseStandardOutputAndError = [Delegate]::CreateDelegate([Action], [Reflection.MethodInfo]$methods['CloseStandardOutputAndError'])
        }
        $script:FoundationHostBinding = [pscustomobject]@{
            Assembly = $assembly
            Methods = $methods
            Delegates = $delegates
            CompilerPath = $compilerPath
            CompilerStream = $compilerStream
            CompilerLength = $compilerLength
            CompilerSha256 = $compilerSha256
            CompilerIdentity = [string]$delegates['GetIdentity'].Invoke([string]$compilerPath)
            SourcePath = $sourcePath
            SourceStream = $sourceStream
            SourceLength = $sourceBytes.Length
            SourceSha256 = Get-FoundationHostSha256 -Bytes $sourceBytes
            SourceIdentity = [string]$delegates['GetIdentity'].Invoke([string]$sourcePath)
            DllPath = $dllPath
            DllStream = $dllStream
            DllLength = $dllBytes.Length
            DllSha256 = Get-FoundationHostSha256 -Bytes $dllBytes
            DllIdentity = [string]$delegates['GetIdentity'].Invoke([string]$dllPath)
        }
        $script:FrameworkCompilerBootstrap = $script:FoundationHostBinding
        $succeeded = $true
        return $assembly
    }
    finally {
        if (-not $succeeded) {
            if ($null -ne $dllStream) { $dllStream.Dispose() }
            if ($null -ne $sourceStream) { $sourceStream.Dispose() }
            $compilerStream.Dispose()
        }
    }
}

function Assert-FoundationHostBinding {
    [CmdletBinding()]
    param()

    if ($null -eq $script:FoundationHostBinding) {
        throw 'FoundationHost binding is absent.'
    }
    foreach ($entry in @(
        [pscustomobject]@{ Path=$script:FoundationHostBinding.CompilerPath; Length=$script:FoundationHostBinding.CompilerLength; Sha256=$script:FoundationHostBinding.CompilerSha256; Identity=$script:FoundationHostBinding.CompilerIdentity }
        [pscustomobject]@{ Path=$script:FoundationHostBinding.SourcePath; Length=$script:FoundationHostBinding.SourceLength; Sha256=$script:FoundationHostBinding.SourceSha256; Identity=$script:FoundationHostBinding.SourceIdentity }
        [pscustomobject]@{ Path=$script:FoundationHostBinding.DllPath; Length=$script:FoundationHostBinding.DllLength; Sha256=$script:FoundationHostBinding.DllSha256; Identity=$script:FoundationHostBinding.DllIdentity }
    )) {
        $item = Get-Item -LiteralPath $entry.Path -Force
        if ($item.Length -ne $entry.Length -or (Get-FoundationFileSha -LiteralPath $entry.Path) -cne $entry.Sha256 -or (Get-FoundationNativeFileIdentity -LiteralPath $entry.Path) -cne $entry.Identity) {
            throw 'FoundationHost bootstrap binding changed.'
        }
    }
}

$script:BoundedProcessCache = $null

function Assert-FoundationCompilerBinding {
    [CmdletBinding()]
    param()

    if ($null -eq $script:BoundedProcessCache) {
        return
    }
    $item = Get-Item -LiteralPath $script:BoundedProcessCache.CompilerPath -Force
    if ($item.Length -ne $script:BoundedProcessCache.CompilerLength -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FoundationNativeFileIdentity -LiteralPath $item.FullName) -ne $script:BoundedProcessCache.CompilerIdentity -or (Get-FoundationFileSha -LiteralPath $item.FullName) -ne $script:BoundedProcessCache.CompilerSha256) {
        throw 'Framework compiler binding identity changed.'
    }
}

function Assert-FoundationBoundedProcessDllBinding {
    [CmdletBinding()]
    param()

    if ($null -eq $script:BoundedProcessCache) {
        return
    }
    $item = Get-Item -LiteralPath $script:BoundedProcessCache.DllPath -Force
    if ($item.Length -ne $script:BoundedProcessCache.DllLength -or (Get-FoundationNativeFileIdentity -LiteralPath $item.FullName) -ne $script:BoundedProcessCache.DllIdentity -or (Get-FoundationFileSha -LiteralPath $item.FullName) -cne $script:BoundedProcessCache.DllSha256) {
        throw 'BoundedProcess DLL binding identity changed.'
    }
}

function Get-FoundationBoundedProcessAssembly {
    [CmdletBinding()]
    param()

    $sourcePath = $boundedProcessPath
    Assert-FoundationFile -LiteralPath $sourcePath -Length $bootstrapContract.BoundedProcessLength -Sha256 $bootstrapContract.BoundedProcessSha256
    if ($null -ne $script:BoundedProcessCache) {
        Assert-FoundationCompilerBinding
        if ((Get-FoundationFileSha -LiteralPath $script:BoundedProcessCache.DllPath) -ne $script:BoundedProcessCache.DllSha256) {
            throw 'Cached BoundedProcess DLL changed.'
        }
        Assert-FoundationBoundedProcessDllBinding
        $hostType = $script:BoundedProcessCache.Assembly.GetType('Pspkt.Certification.BoundedProcessHost', $false)
        if ($null -eq $hostType -or $null -eq $hostType.GetMethod('Run', [type[]]@(
            [string], [string[]], [string], [string], [string[]], [string[]],
            [int], [int], [int], [int], [bool]))) {
            throw 'Cached BoundedProcess API shape changed.'
        }
        return $script:BoundedProcessCache.Assembly
    }
    if ([Environment]::Is64BitProcess) {
        $frameworkRoot = Join-Path $script:WindowsRoot 'Microsoft.NET\Framework64\v4.0.30319'
    }
    else {
        $frameworkRoot = Join-Path $script:WindowsRoot 'Microsoft.NET\Framework\v4.0.30319'
    }
    $cscPath = Join-Path $frameworkRoot 'csc.exe'
    Assert-FoundationNoReparsePath -LiteralPath $cscPath
    $cscItem = Get-Item -LiteralPath $cscPath -Force
    if ($cscItem.PSIsContainer -or ($cscItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Framework compiler is not an ordinary file.'
    }
    $retainedCompiler = [IO.File]::Open($cscPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $retainedDll = $null
    $cacheWritten = $false
    try {
        $compilerLength = $cscItem.Length
        $compilerSha = Get-FoundationFileSha -LiteralPath $cscPath
        $compilerIdentity = Get-FoundationNativeFileIdentity -LiteralPath $cscPath
        $nonce = [guid]::NewGuid().ToString('N')
        $dllPath = Join-Path $stateRoot "bp-$nonce.dll"
        $arguments = @('/nologo', '/target:library', '/optimize+', "/out:$dllPath", $sourcePath)
        $compile = Get-FoundationRawProcessResult -FileName $cscPath -Arguments $arguments -TimeoutMilliseconds 120000
        if ($compile.ExitCode -ne 0) {
            throw "BoundedProcess bootstrap compilation failed: $($compile.StdOut)$($compile.StdErr)"
        }
        $cscAfter = Get-Item -LiteralPath $cscPath -Force
        if ($cscAfter.Length -ne $compilerLength -or (Get-FoundationNativeFileIdentity -LiteralPath $cscPath) -ne $compilerIdentity -or (Get-FoundationFileSha -LiteralPath $cscPath) -ne $compilerSha) {
            throw 'Framework compiler identity changed during bootstrap.'
        }
        $dllBytes = [IO.File]::ReadAllBytes($dllPath)
        $dllSha = Get-FoundationHostSha256 -Bytes $dllBytes
        $retainedDll = [IO.File]::Open($dllPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $assembly = [Reflection.Assembly]::Load($dllBytes)
        $hostType = $assembly.GetType('Pspkt.Certification.BoundedProcessHost', $false)
        if ($null -eq $hostType -or $null -eq $assembly.GetType('Pspkt.Certification.BoundedProcessResult', $false)) {
            throw 'BoundedProcess bootstrap public API is incomplete.'
        }
        $script:BoundedProcessCache = [pscustomobject]@{
            Assembly = $assembly
            DllPath = $dllPath
            DllStream = $retainedDll
            DllIdentity = Get-FoundationNativeFileIdentity -LiteralPath $dllPath
            DllLength = $dllBytes.Length
            DllSha256 = $dllSha
            SourceSha256 = $bootstrapContract.BoundedProcessSha256
            CompilerPath = $cscPath
            CompilerStream = $retainedCompiler
            CompilerLength = $compilerLength
            CompilerIdentity = $compilerIdentity
            CompilerSha256 = $compilerSha
        }
        $cacheWritten = $true
        return $assembly
    }
    finally {
        if (-not $cacheWritten) {
            if ($null -ne $retainedDll) {
                $retainedDll.Dispose()
            }
            $retainedCompiler.Dispose()
        }
    }
}

$script:PowerShellBindings = @{}

function New-FoundationExecutableBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$AuthorityRoot
    )

    $path = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetFullPath($AuthorityRoot).TrimEnd('\') + '\'
    Assert-FoundationNoReparsePath -LiteralPath $path
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Executable escapes trusted authority: $path"
    }
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        return [pscustomobject]@{
            Path = $path
            Root = $root
            Stream = $stream
            Identity = Get-FoundationNativeFileIdentity -LiteralPath $path
            Length = $item.Length
            Sha256 = Get-FoundationFileSha -LiteralPath $path
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Initialize-FoundationRawLaunchAuthority {
    [CmdletBinding()]
    param()

    if ($null -ne $script:RawLaunchAuthority) {
        Assert-FoundationRawLaunchAuthority
        return
    }
    $windowsPowerShellRoot = Join-Path $script:WindowsRoot 'System32\WindowsPowerShell\v1.0'
    $windowsPowerShellPath = Join-Path $windowsPowerShellRoot 'powershell.exe'
    $hostBinding = New-FoundationExecutableBinding -LiteralPath $windowsPowerShellPath -AuthorityRoot $windowsPowerShellRoot
    $wrapperPath = Join-Path $stateRoot 'Invoke-FoundationRawLaunch.ps1'
    $wrapperCreated = $false
    $wrapperBinding = $null
    try {
        $wrapperBytes = [Text.UTF8Encoding]::new($false).GetBytes($foundationRawLaunchWrapperSource)
        $stream = [IO.File]::Open($wrapperPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($wrapperBytes, 0, $wrapperBytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        $wrapperCreated = $true
        $wrapperBinding = New-FoundationFileBinding -LiteralPath $wrapperPath -Role 'generated:raw-launch-wrapper'
        $script:GeneratedFileBindings.Add($wrapperBinding)
        $script:PowerShellBindings[$hostBinding.Path] = $hostBinding
        $script:RawLaunchAuthority = [pscustomobject]@{
            HostPath = $hostBinding.Path
            HostBinding = $hostBinding
            WrapperPath = $wrapperPath
            WrapperBinding = $wrapperBinding
        }
        Assert-FoundationRawLaunchAuthority
    }
    catch {
        if ($null -ne $wrapperBinding) {
            $wrapperBinding.Stream.Dispose()
            [void]$script:GeneratedFileBindings.Remove($wrapperBinding)
        }
        [void]$script:PowerShellBindings.Remove($hostBinding.Path)
        $hostBinding.Stream.Dispose()
        if ($wrapperCreated -and [IO.File]::Exists($wrapperPath)) {
            [IO.File]::Delete($wrapperPath)
        }
        throw
    }
}

function Resolve-FoundationPowerShellBindings {
    [CmdletBinding()]
    param()

    $installRoots = [Collections.Generic.List[string]]::new()
    $appPathCandidates = [Collections.Generic.List[object]]::new()
    $machineBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $currentVersionKey = $machineBase.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion', $false)
        if ($null -eq $currentVersionKey) {
            throw 'Machine CurrentVersion registry authority is unavailable.'
        }
        try {
            $programFilesDirectory = [string]$currentVersionKey.GetValue('ProgramFilesDir', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        finally {
            if ($null -ne $currentVersionKey) { $currentVersionKey.Dispose() }
        }
    }
    finally {
        $machineBase.Dispose()
    }
    if ([string]::IsNullOrWhiteSpace($programFilesDirectory)) {
        throw 'Machine Program Files authority is unavailable.'
    }
    $windowsAppsRoot = [IO.Path]::GetFullPath((Join-Path $programFilesDirectory 'WindowsApps'))
    $windowsAppsPrefix = $windowsAppsRoot.TrimEnd('\') + '\'
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        $installedVersions = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $installedVersions = $base.OpenSubKey('SOFTWARE\Microsoft\PowerShellCore\InstalledVersions', $false)
            if ($null -ne $installedVersions) {
                foreach ($subkeyName in $installedVersions.GetSubKeyNames()) {
                    $subkey = $null
                    try {
                        $subkey = $installedVersions.OpenSubKey($subkeyName, $false)
                        if ($null -eq $subkey) {
                            throw "PowerShell installed-version registry subkey disappeared or could not be opened: $subkeyName"
                        }
                        $installLocation = [string]$subkey.GetValue('InstallLocation', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        if (-not [string]::IsNullOrWhiteSpace($installLocation)) {
                            $installRoots.Add([IO.Path]::GetFullPath($installLocation))
                        }
                    }
                    finally {
                        if ($null -ne $subkey) { $subkey.Dispose() }
                    }
                }
            }
        }
        finally {
            if ($null -ne $installedVersions) { $installedVersions.Dispose() }
            if ($null -ne $base) { $base.Dispose() }
        }
    }
    $pwshCandidates = @()
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $currentPath = [IO.Path]::GetFullPath((Get-Process -Id $PID).Path)
        $currentRoot = $null
        $currentPriority = 2
        foreach ($root in @($installRoots | Sort-Object -Unique)) {
            if ($currentPath.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                $currentRoot = $root
                break
            }
        }
        $currentPackageDirectory = Split-Path -Parent $currentPath
        if ($null -eq $currentRoot -and $currentPath.StartsWith($windowsAppsPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $currentPackageDirectory) -match '^Microsoft\.PowerShell_.+__8wekyb3d8bbwe$') {
            $currentRoot = $windowsAppsRoot
            $currentPriority = 0
        }
        if ($null -eq $currentRoot) {
            throw 'Current PowerShell 7 process is outside trusted installation authority.'
        }
        $pwshCandidates += [pscustomobject]@{ Path = $currentPath; Root = $currentRoot; Priority = $currentPriority }
    }
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $base = $null
            $appPathKey = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
                $appPathKey = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\pwsh.exe', $false)
                if ($null -ne $appPathKey) {
                    $appPath = [string]$appPathKey.GetValue('', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if (-not [string]::IsNullOrWhiteSpace($appPath) -and [IO.File]::Exists($appPath)) {
                        $fullAppPath = [IO.Path]::GetFullPath($appPath)
                        $packageDirectory = Split-Path -Parent $fullAppPath
                        if ($fullAppPath.StartsWith($windowsAppsPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $packageDirectory) -match '^Microsoft\.PowerShell_.+__8wekyb3d8bbwe$') {
                            $appPathCandidates.Add([pscustomobject]@{ Path = $fullAppPath; Root = $windowsAppsRoot; Priority = 1 })
                        }
                    }
                }
            }
            finally {
                if ($null -ne $appPathKey) { $appPathKey.Dispose() }
                if ($null -ne $base) { $base.Dispose() }
            }
        }
    }
    foreach ($candidate in $appPathCandidates) {
        $pwshCandidates += [pscustomobject]@{ Path = $candidate.Path; Root = $candidate.Root; Priority = $candidate.Priority }
    }
    foreach ($root in @($installRoots | Sort-Object -Unique)) {
        $candidate = Join-Path $root 'pwsh.exe'
        if ([IO.File]::Exists($candidate)) {
            $pwshCandidates += [pscustomobject]@{ Path = $candidate; Root = $root; Priority = 2 }
        }
    }
    if ($pwshCandidates.Count -eq 0) {
        throw 'PowerShell 7 was not found through current-process or installed-version registry authority.'
    }
    $pwshCandidate = @($pwshCandidates | Sort-Object Priority,Path -Unique)[0]
    $windowsPowerShellRoot = Join-Path $script:WindowsRoot 'System32\WindowsPowerShell\v1.0'
    $windowsPowerShellPath = Join-Path $windowsPowerShellRoot 'powershell.exe'
    $pwshBinding = New-FoundationExecutableBinding -LiteralPath $pwshCandidate.Path -AuthorityRoot $pwshCandidate.Root
    $windowsPowerShellBinding = $null
    try {
        if ($script:PowerShellBindings.ContainsKey([IO.Path]::GetFullPath($windowsPowerShellPath))) {
            Assert-FoundationPowerShellBinding -LiteralPath $windowsPowerShellPath
            $windowsPowerShellBinding = $script:PowerShellBindings[[IO.Path]::GetFullPath($windowsPowerShellPath)]
        }
        else {
            $windowsPowerShellBinding = New-FoundationExecutableBinding -LiteralPath $windowsPowerShellPath -AuthorityRoot $windowsPowerShellRoot
            $script:PowerShellBindings[$windowsPowerShellBinding.Path] = $windowsPowerShellBinding
        }
    }
    catch {
        $pwshBinding.Stream.Dispose()
        throw
    }
    $script:PowerShellBindings[$pwshBinding.Path] = $pwshBinding
    return [pscustomobject]@{
        Pwsh = $pwshBinding
        WindowsPowerShell = $windowsPowerShellBinding
    }
}

function Assert-FoundationPowerShellBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $path = [IO.Path]::GetFullPath($LiteralPath)
    if (-not $script:PowerShellBindings.ContainsKey($path)) {
        throw "PowerShell host binding is absent: $path"
    }
    $binding = $script:PowerShellBindings[$path]
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $path.StartsWith($binding.Root, [StringComparison]::OrdinalIgnoreCase) -or $item.Length -ne $binding.Length -or (Get-FoundationNativeFileIdentity -LiteralPath $path) -ne $binding.Identity -or (Get-FoundationFileSha -LiteralPath $path) -ne $binding.Sha256) {
        throw "PowerShell host binding identity changed: $path"
    }
}

function Write-FoundationChildScripts {
    [CmdletBinding()]
    param()

    $wrapperPath = Join-Path $stateRoot 'Invoke-FoundationBoundedChild.ps1'
    $compilePath = Join-Path $stateRoot 'Invoke-FoundationCompile.ps1'
    $contractReaderPath = Join-Path $stateRoot 'Invoke-FoundationContractReader.ps1'
    $replayPath = Join-Path $stateRoot 'Invoke-FoundationReplay.ps1'
    $wrapper = @'
param([string]$HelperAssemblyPath,[string]$PayloadPath,[string]$ArgumentsBase64)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Add-Type -Path $HelperAssemblyPath
$windowsRoot=[IO.Directory]::GetParent([Environment]::SystemDirectory).FullName
$env:SystemRoot=$windowsRoot
$env:WINDIR=$windowsRoot
$env:PATH="$([Environment]::SystemDirectory);$windowsRoot"
$gate=[Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GATE_EVENT')
if (-not [Pspkt.Certification.BoundedProcessHost]::RunManagedGateWait($gate,120000)) { exit 91 }
Remove-Item -LiteralPath Env:PSPKT_PHASE4_GATE_EVENT -ErrorAction SilentlyContinue
$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
$decoded=$json | ConvertFrom-Json
$arguments=@()
foreach($item in $decoded){$arguments += [string]$item}
$global:LASTEXITCODE=0
if([IO.Path]::GetFileName($PayloadPath) -eq 'Invoke-PspktPhase4SchemaValidators.ps1'){Set-Location -LiteralPath (Split-Path -Parent (Split-Path -Parent $PayloadPath))}
& $PayloadPath @arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
'@
    $compile = @'
param([string]$CompilerPath,[string]$OutputPath,[string]$ReferencePath,[string]$SourceListBase64)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$decoded=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SourceListBase64)) | ConvertFrom-Json
$sources=@()
foreach($item in $decoded){$sources += [string]$item}
$arguments=@('/nologo','/target:library','/optimize+',('/out:'+$OutputPath))
if ($ReferencePath -ne '__NONE__') { $arguments += ('/reference:'+$ReferencePath) }
$arguments += $sources
& $CompilerPath @arguments
exit $LASTEXITCODE
'@
    $contractReader = @'
param([string]$ContractPath,[string]$CanonicalJsonPath,[string]$ResultPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. $CanonicalJsonPath
. $ContractPath
$contract=Get-PspktFoundationContract
Assert-PspktFoundationContract -Contract $contract
[IO.File]::WriteAllBytes($ResultPath,(Get-PspktCanonicalJsonBytes -Value $contract))
'@
    $replay = @'
param([string]$CanonicalJsonPath,[string]$SchemaAssemblyPath,[string]$EngineAssemblyPath,[string]$VerifyAssemblyPath,[string]$CatalogPath,[string]$SchemaPath,[string]$MapPath,[string]$ResultPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. $CanonicalJsonPath
Add-Type -Path $SchemaAssemblyPath
Add-Type -Path $EngineAssemblyPath
Add-Type -Path $VerifyAssemblyPath
$result=[Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Replay([IO.File]::ReadAllBytes($CatalogPath),[IO.File]::ReadAllBytes($SchemaPath),[IO.File]::ReadAllBytes($MapPath))
[IO.File]::WriteAllBytes($ResultPath,(Get-PspktCanonicalJsonBytes -Value ([ordered]@{accepted=$result.Accepted;reason=$result.Reason})))
'@
    foreach ($generated in @(
        [pscustomobject]@{ Path=$wrapperPath; Text=$wrapper }
        [pscustomobject]@{ Path=$compilePath; Text=$compile }
        [pscustomobject]@{ Path=$contractReaderPath; Text=$contractReader }
        [pscustomobject]@{ Path=$replayPath; Text=$replay }
    )) {
        $generatedBytes = [Text.UTF8Encoding]::new($false).GetBytes($generated.Text)
        $generatedStream = [IO.File]::Open($generated.Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $generatedStream.Write($generatedBytes, 0, $generatedBytes.Length)
            $generatedStream.Flush($true)
        }
        finally {
            $generatedStream.Dispose()
        }
        $script:GeneratedFileBindings.Add((New-FoundationFileBinding -LiteralPath $generated.Path -Role "generated:$([IO.Path]::GetFileName($generated.Path))"))
    }
    return [pscustomobject]@{ Wrapper = $wrapperPath; Compile = $compilePath; Contract = $contractReaderPath; Replay = $replayPath }
}

function Invoke-FoundationBoundedPowerShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Reflection.Assembly]$HelperAssembly,
        [Parameter(Mandatory = $true)]
        [string]$HostPath,
        [Parameter(Mandatory = $true)]
        [string]$WrapperPath,
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$PayloadArguments,
        [Parameter(Mandatory = $true)]
        [int]$TimeoutMilliseconds,
        [ref]$CompletedProcessResult
    )

    if ($PSBoundParameters.ContainsKey('CompletedProcessResult')) {
        $CompletedProcessResult.Value = $null
    }
    $argumentsJson = ConvertTo-PspktCanonicalJson -Value @($PayloadArguments)
    $argumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($argumentsJson))
    $childArguments = [string[]]@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$WrapperPath,$script:BoundedProcessCache.DllPath,$PayloadPath,$argumentsBase64)
    $hostType = $HelperAssembly.GetType('Pspkt.Certification.BoundedProcessHost', $true)
    $runMethod = $hostType.GetMethod('Run', [type[]]@(
        [string], [string[]], [string], [string], [string[]], [string[]],
        [int], [int], [int], [int], [bool]))
    $gate = 'Local\PspktPhase4Foundation' + [guid]::NewGuid().ToString('N')
    Assert-FoundationGitBinding
    Assert-FoundationHostBinding
    Assert-FoundationCompilerBinding
    Assert-FoundationBoundedProcessDllBinding
    Assert-FoundationPowerShellBinding -LiteralPath $HostPath
    Assert-FoundationImmutableBindings
    try {
        if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_THROW_BEFORE_BOUNDED_RUN') -eq '1' -and
            [IO.Path]::GetFileName($PayloadPath) -ceq 'Invoke-FoundationGitBinary.ps1') {
            throw 'Injected bounded Git failure before Run.'
        }
        $result = $runMethod.Invoke($null, [object[]]@(
            $HostPath,
            $childArguments,
            $gate,
            'PSPKT_PHASE4_GATE_EVENT',
            [string[]]@('PATH','SystemRoot','WINDIR'),
            [string[]]@("$([Environment]::SystemDirectory);$script:WindowsRoot",$script:WindowsRoot,$script:WindowsRoot),
            $TimeoutMilliseconds,
            15000,
            15000,
            1048576,
            $false))
        if ($PSBoundParameters.ContainsKey('CompletedProcessResult')) {
            $CompletedProcessResult.Value = $result
        }
        if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_MUTATE_README_AFTER_REPLAY') -eq '1' -and
            [IO.Path]::GetFileName($PayloadPath) -ceq 'Invoke-FoundationReplay.ps1') {
            [IO.File]::AppendAllText((Join-Path $RepositoryRoot 'README.md'),"`nFoundation Replay terminal mutation probe.`n",[Text.UTF8Encoding]::new($false))
        }
        if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_FAIL_POST_RUN_BINDING') -eq '1' -and
            [IO.Path]::GetFileName($PayloadPath) -ceq 'Invoke-FoundationGitBinary.ps1') {
            throw 'Injected bounded Git post-Run binding failure.'
        }
        if (-not $result.Started -or -not $result.Exited -or $result.TimedOut -or $result.AssignFailed -or $result.StdOutOverflow -or $result.StdErrOverflow -or -not $result.DrainCompleted -or $result.ExitCode -ne 0) {
            throw "Bounded child failed. Exit=$($result.ExitCode) TimedOut=$($result.TimedOut) AssignFailed=$($result.AssignFailed) Out=$($result.StdOutText) Err=$($result.StdErrText)"
        }
        return $result
    }
    finally {
        Assert-FoundationCompilerBinding
        Assert-FoundationBoundedProcessDllBinding
        Assert-FoundationGitBinding
        Assert-FoundationHostBinding
        Assert-FoundationPowerShellBinding -LiteralPath $HostPath
        Assert-FoundationImmutableBindings
    }
}



function Assert-FoundationCanonicalAllowlistPrestate {
    [CmdletBinding()]
    param()

    foreach ($relativePath in $bootstrapContract.Allowlist) {
        $fullPath = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
        if ($relativePath -eq 'certification/.gitattributes') {
            Assert-FoundationFile -LiteralPath $fullPath -Length $bootstrapContract.CertificationAttributesLength -Sha256 $bootstrapContract.CertificationAttributesSha256
        }
        elseif ($relativePath -eq 'tests/.gitattributes') {
            Assert-FoundationFile -LiteralPath $fullPath -Length $bootstrapContract.TestAttributesLength -Sha256 $bootstrapContract.TestAttributesSha256
        }
        elseif (Test-Path -LiteralPath $fullPath) {
            throw "Canonical prestate requires absent allowlist path: $relativePath"
        }
    }
}

function Get-FoundationPathStateRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [bool]$Tracked
    )

    $fullPath = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $RelativePath
    $exists = Test-Path -LiteralPath $fullPath
    $record = [ordered]@{
        path = $RelativePath
        tracked = $Tracked
        exists = $exists
    }
    if (-not $exists) {
        return $record
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer) {
        $record.kind = 'directory'
    }
    else {
        $record.kind = 'file'
        $record.identity = Get-FoundationNativeFileIdentity -LiteralPath $fullPath
        $record.length = $item.Length
        $record.sha256 = Get-FoundationFileSha -LiteralPath $fullPath
        $record.nlink = Get-FoundationNativeLinkCount -LiteralPath $fullPath
    }
    return $record
}





function Copy-FoundationPromotionLayout {
    [CmdletBinding()]
    param()

    if (@(Get-ChildItem -LiteralPath $promoRoot -Force).Count -ne 0) {
        throw 'Promotion candidate root is not empty.'
    }
    foreach ($relativePath in $contract.InputPathSet) {
        $source = Resolve-FoundationHostPath -Root $SourceRoot -RelativePath $relativePath
        $destination = Resolve-FoundationHostPath -Root $promoRoot -RelativePath $relativePath
        Assert-FoundationNoReparsePath -LiteralPath $source
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
    foreach ($relativePath in $contract.OutputPathSet) {
        $source = Resolve-FoundationHostPath -Root $outputRoot -RelativePath $relativePath
        $destination = Resolve-FoundationHostPath -Root $promoRoot -RelativePath $relativePath
        Assert-FoundationNoReparsePath -LiteralPath $source
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
}

function Write-FoundationPrivateOdbManifest {
    [CmdletBinding()]
    param()

    $rootDefinitions = @(
        [pscustomobject]@{ Name='generate'; GitRoot=(Join-Path $ScratchRoot 'gen.bare.git') }
        [pscustomobject]@{ Name='proof'; GitRoot=(Join-Path $ScratchRoot 'proof.bare.git') }
        [pscustomobject]@{ Name='oneA'; GitRoot=(Join-Path $ScratchRoot 'oneA\.git') }
    )
    $rootRecords = @()
    foreach ($definition in $rootDefinitions) {
        $objectRoot = Join-Path $definition.GitRoot 'objects'
        if (-not (Test-Path -LiteralPath $objectRoot)) {
            continue
        }
        if (Test-Path -LiteralPath (Join-Path $objectRoot 'info\alternates')) {
            throw "Private ODB alternates file is forbidden: $($definition.Name)"
        }
        $objects = @()
        foreach ($file in Get-ChildItem -LiteralPath $objectRoot -File -Recurse -Force | Sort-Object FullName) {
            $relative = $file.FullName.Substring($objectRoot.Length).TrimStart('\').Replace('\','/')
            if ($relative -match '^[0-9a-f]{2}/[0-9a-f]{38}$') {
                $oid = $relative.Replace('/','')
            }
            else {
                $oid = $relative
            }
            $nlink = Get-FoundationNativeLinkCount -LiteralPath $file.FullName
            if ($nlink -ne 1) {
                throw "Private ODB object is hardlinked: $($definition.Name)/$relative"
            }
            $objects += [ordered]@{
                relativePath = $relative
                oid = $oid
                identity = Get-FoundationNativeFileIdentity -LiteralPath $file.FullName
                length = $file.Length
                sha256 = Get-FoundationFileSha -LiteralPath $file.FullName
                nlink = $nlink
            }
        }
        $rootRecords += [ordered]@{
            name = $definition.Name
            path = [IO.Path]::GetFullPath($objectRoot)
            identity = Get-FoundationNativeDirectoryIdentity -LiteralPath $objectRoot
            objects = $objects
        }
    }
    $path = Join-Path $stateRoot 'private-odb-manifest.v1.json'
    [IO.File]::WriteAllBytes($path, (Get-PspktCanonicalJsonBytes -Value ([ordered]@{
        schemaVersion = 1
        schemaId = 'PspktFoundationPrivateOdbManifestV1'
        roots = $rootRecords
    })))
}

function Get-FoundationOwnedFileRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $item = Get-Item -LiteralPath $LiteralPath -Force
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($LiteralPath)
        Identity = Get-FoundationNativeFileIdentity -LiteralPath $LiteralPath
        Length = $item.Length
        Sha256 = Get-FoundationFileSha -LiteralPath $LiteralPath
    }
}

function Test-FoundationOwnedFileRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Record)

    if (-not [IO.File]::Exists($Record.Path)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Record.Path -Force
    return $item.Length -eq $Record.Length -and (Get-FoundationNativeFileIdentity -LiteralPath $Record.Path) -ceq $Record.Identity -and (Get-FoundationFileSha -LiteralPath $Record.Path) -ceq $Record.Sha256
}

function Remove-FoundationOwnedFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Record)

    if (-not [IO.File]::Exists($Record.Path)) {
        return
    }
    Remove-FoundationNativeOwnedFile -Record $Record
}

function New-FoundationAttributePreimageTransactions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Specifications,
        [Parameter(Mandatory = $true)][scriptblock]$BindingFactory
    )

    $transactions = @{}
    $primaryError = $null
    try {
        foreach ($specification in $Specifications) {
            $binding = & $BindingFactory -LiteralPath $specification.Path -Role "promotion-preimage:$($specification.RelativePath)"
            if ($binding.Sha256 -cne $specification.ExpectedSha256) {
                $mismatchError = [InvalidOperationException]::new("Attribute preimage binding mismatch: $($specification.RelativePath)")
                try {
                    $binding.Stream.Dispose()
                }
                catch {
                    throw [AggregateException]::new('Attribute preimage mismatch cleanup failed.', [Exception[]]@($mismatchError,$_.Exception))
                }
                throw $mismatchError
            }
            $transactions[$specification.RelativePath] = [pscustomobject]@{
                Preimage = $binding
                Backup = $null
                Promoted = $null
            }
        }
    }
    catch {
        $primaryError = $_.Exception
    }
    if ($null -ne $primaryError) {
        $cleanupErrors = [Collections.Generic.List[Exception]]::new()
        foreach ($transaction in $transactions.Values) {
            if ($null -ne $transaction.Preimage.Stream) {
                try { $transaction.Preimage.Stream.Dispose() }
                catch { $cleanupErrors.Add($_.Exception) }
            }
        }
        if ($cleanupErrors.Count -gt 0) {
            $allErrors = [Collections.Generic.List[Exception]]::new()
            $allErrors.Add($primaryError)
            foreach ($cleanupError in $cleanupErrors) { $allErrors.Add($cleanupError) }
            throw [AggregateException]::new('Attribute preimage binding and cleanup failed.', $allErrors)
        }
        throw $primaryError
    }
    return $transactions
}



function Test-FoundationByteArrayEquality {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function Get-FoundationCanonicalHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Value)

    return Get-FoundationHostSha256 -Bytes (Get-PspktCanonicalJsonBytes -Value $Value)
}

function Test-FoundationPathIsWithin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $candidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $candidatePath.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-FoundationExistingAncestorAuthority {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    if ($fullPath -ine [IO.Path]::GetPathRoot($fullPath)) { $fullPath = $fullPath.TrimEnd('\') }
    $remaining = [Collections.Generic.List[string]]::new()
    $cursor = $fullPath
    while (-not (Test-Path -LiteralPath $cursor)) {
        $leaf = Split-Path -Leaf $cursor
        if ([string]::IsNullOrEmpty($leaf)) { throw "Path has no existing authority ancestor: $LiteralPath" }
        $remaining.Insert(0, $leaf)
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $cursor) { throw "Path has no existing authority ancestor: $LiteralPath" }
        $cursor = $parent
    }
    Assert-FoundationNoReparsePath -LiteralPath $cursor
    $item = Get-Item -LiteralPath $cursor -Force
    $identity = if ($item.PSIsContainer) {
        Get-FoundationNativeDirectoryIdentity -LiteralPath $cursor
    }
    else {
        Get-FoundationNativeFileIdentity -LiteralPath $cursor
    }
    return [pscustomobject]@{
        FullPath = $fullPath
        ExistingPath = $cursor
        ExistingIdentity = $identity
        Remaining = @($remaining | ForEach-Object { $_.ToLowerInvariant() }) -join '\'
    }
}

function Get-FoundationDriveType {
    param([Parameter(Mandatory = $true)][string]$Root)
    return [IO.DriveInfo]::new($Root).DriveType
}

function Assert-FoundationTransactionLayout {
    [CmdletBinding()]
    param(
        $Journal,
        [switch]$NewJournal,
        [switch]$PathsOnly,
        [ValidateSet('CapturePrestateMode','InitMode','ReplayPrecommitMode','ReplayCommitMode','RecoveryMode')]
        [string]$InvocationMode
    )

    $guidPlaceholder = '0' * 32
    if (-not [string]::IsNullOrEmpty($InvocationMode)) {
        Assert-FoundationPortablePath -LiteralPath $RepositoryRoot -Role RepositoryRoot -Directory
        Assert-FoundationPortablePath -LiteralPath $PrestatePath -Role PrestatePath
        if ($InvocationMode -ceq 'CapturePrestateMode') {
            Assert-FoundationPortablePath -LiteralPath "$PrestatePath.$guidPlaceholder.tmp" -Role 'prestate temporary'
        }
        $scratchFiles = @(
            "state\foundation-host-$guidPlaceholder.cs", "state\foundation-host-$guidPlaceholder.dll",
            'state\Invoke-FoundationRawLaunch.ps1', 'state\Invoke-FoundationGitBinary.ps1',
            "state\git-$guidPlaceholder.stdout.bin", "state\git-$guidPlaceholder.stderr.bin",
            "state\git-$guidPlaceholder.exit.txt", "state\git-$guidPlaceholder.stdin.bin",
            'state\authority\CanonicalJson.ps1', 'state\authority\BoundedProcess.cs',
            'state\authority\SchemaBootstrap.cs', 'state\authority\protocol-schema-meta.v1.json'
        )
        Assert-FoundationPortablePath -LiteralPath "$ScratchRoot\home\.config" -Role 'scratch Git home' -Directory
        if ($InvocationMode -cin @('InitMode','ReplayPrecommitMode','ReplayCommitMode')) {
            $scratchFiles += @(
                "state\bp-$guidPlaceholder.dll", 'state\Invoke-FoundationBoundedChild.ps1',
                'state\Invoke-FoundationCompile.ps1', 'state\Invoke-FoundationContractReader.ps1',
                'state\Invoke-FoundationReplay.ps1', 'state\candidate-contract.v1.json',
                'state\SchemaBootstrap.dll', 'state\FoundationEngine.dll', 'state\FoundationVerify.dll',
                'state\generator-result.v1.json', 'state\oneA-setup.v1.json', 'state\private-odb-manifest.v1.json',
                'gen.index', 'proof.index'
            )
            if ($InvocationMode -cne 'InitMode') { $scratchFiles += 'state\candidate-replay-result.v1.json' }
            foreach ($relativePath in $bootstrapContract.InputPathSet) {
                Assert-FoundationPortablePath -LiteralPath ($SourceRoot + '\' + $relativePath.Replace('/','\')) -Role 'candidate source'
            }
            foreach ($relativePath in $bootstrapContract.OutputPathSet) {
                $scratchFiles += 'out\' + $relativePath.Replace('/','\')
            }
            foreach ($relativePath in $bootstrapContract.Allowlist) {
                $scratchFiles += 'promo\' + $relativePath.Replace('/','\')
                if ($InvocationMode -ceq 'ReplayCommitMode') { $scratchFiles += 'committed-proof-work\' + $relativePath.Replace('/','\') }
            }
        }
        foreach ($relativePath in $scratchFiles) {
            Assert-FoundationPortablePath -LiteralPath ($ScratchRoot + '\' + $relativePath) -Role 'scratch output'
        }
        if ($InvocationMode -ceq 'CapturePrestateMode') { return }
    }
    $journalPath = if ($null -eq $Journal) { $RecoveryJournalPath } else { [string]$Journal.Path }
    $paths = [Collections.Generic.List[string]]::new()
    $directoryPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $publicationPaths = [Collections.Generic.List[string]]::new()
    foreach ($relativePath in $bootstrapContract.Allowlist) {
        $publicationPaths.Add((Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath))
    }
    foreach ($path in @($InitReceiptPath,$ReplayReceiptPath,$CompletionReceiptPath,$RecoveredCompletionReceiptPath)) {
        if (-not [string]::IsNullOrEmpty($path)) { $publicationPaths.Add($path) }
    }
    if ($null -ne $Journal) {
        foreach ($path in @($Journal.Header.initReceiptPath,$Journal.Header.replayReceiptPath,$Journal.Header.requestedCompletionReceiptPath)) {
            $publicationPaths.Add([string]$path)
        }
        foreach ($operation in $Journal.Operations) {
            $operationName = [string]$operation.Intent.Record.operation
            foreach ($property in $operation.Intent.Record.details.PSObject.Properties) {
                if ($property.Name -cin @('path','tempPath','destination','source','collidedPath')) {
                    $paths.Add([string]$property.Value)
                    if ($operationName -cin @('DirectoryTempCreate','DirectoryPublish','DirectoryDelete')) {
                        [void]$directoryPaths.Add([string]$property.Value)
                    }
                    elseif ($operationName -ceq 'CompletionPathSelection') { $publicationPaths.Add([string]$property.Value) }
                }
            }
            if ($null -ne $operation.Terminal) {
                $state = $operation.Terminal.Record.state
                foreach ($property in $state.PSObject.Properties) {
                    if ($property.Name -cin @('Path','path','destination')) { $paths.Add([string]$property.Value) }
                    elseif ($property.Name -ceq 'observed') { $paths.Add([string]$property.Value.Path) }
                }
            }
        }
    }
    $paths.Add($journalPath)
    [void]$directoryPaths.Add($journalPath)
    foreach ($path in $publicationPaths) { $paths.Add($path) }
    $root = [IO.Path]::GetPathRoot((Assert-FoundationPortablePath -LiteralPath $journalPath -Role 'journal directory' -Directory -PassThru))
    if ($root -notmatch '^[A-Za-z]:\\$') {
        throw "Unsupported transaction layout: journal '$journalPath' must use a local fixed-drive root."
    }
    foreach ($path in $paths) {
        $fullPath = Assert-FoundationPortablePath -LiteralPath $path -Role 'recorded transaction path' -Directory:($directoryPaths.Contains($path)) -PassThru
        $pathRoot = [IO.Path]::GetPathRoot($fullPath)
        if (-not $root.Equals($pathRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsupported transaction layout: '$path' uses root '$pathRoot'; journal root is '$root'. Use one local fixed-drive root for the journal and all publication destinations."
        }
    }
    foreach ($path in $publicationPaths) {
        $directory = Split-Path -Parent $path
        while (-not [IO.Directory]::Exists($directory)) {
            if ([IO.File]::Exists($directory)) { throw "Unsupported transaction layout: '$path' has a file ancestor '$directory'." }
            Assert-FoundationPortablePath -LiteralPath $directory -Role 'publication directory' -Directory
            $parent = Split-Path -Parent $directory
            if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $directory) { break }
            $nonceDirectory = $parent.TrimEnd('\') + '\.' + (Split-Path -Leaf $directory) + '.pspkt-dir-' + $guidPlaceholder
            Assert-FoundationPortablePath -LiteralPath $nonceDirectory -Role 'publication directory temporary' -Directory
            $directory = $parent
        }
    }
    $journalRoots = @($journalPath)
    if ($NewJournal) {
        $nonceRoot = (Split-Path -Parent $journalPath).TrimEnd('\') + '\.' + (Split-Path -Leaf $journalPath) + '.pspkt-journal-' + $guidPlaceholder
        $journalRoots += $nonceRoot
        foreach ($relativePath in @('certification/.gitattributes','tests/.gitattributes')) {
            $attributePath = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
            Assert-FoundationPortablePath -LiteralPath "$attributePath.pspkt-preimage-$guidPlaceholder" -Role 'attribute backup'
        }
    }
    foreach ($journalRoot in $journalRoots) {
        Assert-FoundationPortablePath -LiteralPath $journalRoot -Role 'journal directory' -Directory
        foreach ($name in @(
            ('evidence-' + ('0' * 64) + '.bin'), 'evidence-manifest.v1.json',
            '00000000.header.json', '00000001.not-applied.json',
            ".pspkt-segment-$guidPlaceholder.tmp", ".pspkt-content-$guidPlaceholder.tmp"
        )) {
            Assert-FoundationPortablePath -LiteralPath ($journalRoot.TrimEnd('\') + '\' + $name) -Role 'journal file'
        }
    }
    if ($PathsOnly) { return }
    if ((Get-FoundationDriveType -Root $root) -ne [IO.DriveType]::Fixed) {
        throw "Unsupported transaction layout: root '$root' is not a local fixed drive."
    }
    Assert-FoundationNoReparsePath -LiteralPath $root
    $rootIdentity = Get-FoundationNativeDirectoryIdentity -LiteralPath $root
    $rootVolume = $rootIdentity.Split(':')[0]
    foreach ($path in $paths) {
        $fullPath = [IO.Path]::GetFullPath($path)
        $parent = if ($fullPath -ieq $root) { $root } else { Split-Path -Parent $fullPath }
        $ancestor = Get-FoundationExistingAncestorAuthority -LiteralPath $parent
        if (-not [IO.Directory]::Exists($ancestor.ExistingPath)) {
            throw "Unsupported transaction layout: '$path' has a file ancestor '$($ancestor.ExistingPath)'."
        }
        if ($ancestor.ExistingIdentity.Split(':')[0] -cne $rootVolume) {
            throw "Unsupported transaction layout: ancestor '$($ancestor.ExistingPath)' of '$path' has a different volume identity from root '$root'."
        }
        if (Test-Path -LiteralPath $fullPath) { Assert-FoundationNoReparsePath -LiteralPath $fullPath }
    }
    if (-not [IO.Directory]::Exists((Split-Path -Parent $journalPath))) {
        throw "Unsupported transaction layout: journal parent must already exist: $journalPath"
    }
}

function Assert-FoundationPairwiseRootAuthority {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Authorities)

    $resolved = [Collections.Generic.List[object]]::new()
    foreach ($authority in $Authorities) {
        if ($null -eq $authority -or [string]::IsNullOrEmpty([string]$authority.Path)) { continue }
        $path = [IO.Path]::GetFullPath([string]$authority.Path)
        if ($path -ine [IO.Path]::GetPathRoot($path)) { $path = $path.TrimEnd('\') }
        $parent = if (Test-Path -LiteralPath $path) { $path } else { Split-Path -Parent $path }
        Assert-FoundationNoReparsePath -LiteralPath $parent -AllowMissingLeaf
        $resolved.Add([pscustomobject]@{
            Name = [string]$authority.Name
            Path = $path
            Authority = Get-FoundationExistingAncestorAuthority -LiteralPath $path
        })
    }
    for ($leftIndex = 0; $leftIndex -lt $resolved.Count; $leftIndex++) {
        for ($rightIndex = $leftIndex + 1; $rightIndex -lt $resolved.Count; $rightIndex++) {
            $left = $resolved[$leftIndex]
            $right = $resolved[$rightIndex]
            if ((Test-FoundationPathIsWithin -Candidate $left.Path -Root $right.Path) -or
                (Test-FoundationPathIsWithin -Candidate $right.Path -Root $left.Path)) {
                throw "Path authorities overlap: $($left.Name), $($right.Name)"
            }
            if ($left.Authority.ExistingIdentity -ceq $right.Authority.ExistingIdentity -and
                $left.Authority.Remaining -ceq $right.Authority.Remaining) {
                throw "Path authorities resolve to the same final target: $($left.Name), $($right.Name)"
            }
        }
    }
}

function ConvertFrom-FoundationGitStageRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ValidateSet('Index','Tree')][string]$Kind
    )

    $records = [Collections.Generic.List[object]]::new()
    foreach ($record in ConvertFrom-FoundationGitNulRecords -Bytes $Bytes) {
        $tab = $record.IndexOf("`t", [StringComparison]::Ordinal)
        if ($tab -lt 0) { throw "Git $Kind record has no path separator." }
        $prefix = $record.Substring(0, $tab)
        $path = Assert-FoundationDecodedGitPath -Path $record.Substring($tab + 1)
        $parts = $prefix.Split(' ')
        if ($Kind -eq 'Index') {
            if ($parts.Length -ne 3 -or $parts[0] -cnotmatch '^[0-7]{6}$' -or $parts[1] -cnotmatch '^[0-9a-f]{40}$' -or $parts[2] -cne '0') {
                throw 'Git index stage record is invalid.'
            }

            $mode = $parts[0]
            $oid = $parts[1]
        }
        else {
            if ($parts.Length -ne 3 -or $parts[0] -cnotmatch '^[0-7]{6}$' -or $parts[1] -cne 'blob' -or $parts[2] -cnotmatch '^[0-9a-f]{40}$') {
                throw 'Git tree record is invalid.'
            }
            $mode = $parts[0]
            $oid = $parts[2]
        }
        $records.Add([ordered]@{ mode=$mode; oid=$oid; path=$path })
    }
    return @($records | Sort-Object { $_.path })
}

function Get-FoundationPrivateGitNulPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Environment
    )

    $result = Invoke-FoundationPrivateGitRaw -Arguments $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment -StandardOutputCap $bootstrapContract.GitNulPathMaximumBytes
    return ConvertFrom-FoundationGitNulPaths -Bytes $result.StandardOutput
}

function Get-FoundationPrivateGitStageRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Index','Tree')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Environment,
        [string]$Object = 'HEAD'
    )

    $arguments = if ($Kind -eq 'Index') { @('ls-files','--stage','-z') } else { @('ls-tree','-r','-z','--full-tree',$Object) }
    $result = Invoke-FoundationPrivateGitRaw -Arguments $arguments -WorkingDirectory $WorkingDirectory -Environment $Environment -StandardOutputCap $bootstrapContract.GitNulPathMaximumBytes
    return ConvertFrom-FoundationGitStageRecords -Bytes $result.StandardOutput -Kind $Kind
}

function ConvertFrom-FoundationGitNulRecords {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    if ($Bytes.Length -eq 0) { return @() }
    if ($Bytes[$Bytes.Length - 1] -ne 0) { throw 'Git NUL projection is not terminated.' }
    $records = [Collections.Generic.List[string]]::new()
    $recordStart = 0
    for ($index = 0; $index -lt $Bytes.Length; $index++) {
        if ($Bytes[$index] -ne 0) { continue }
        $length = $index - $recordStart
        if ($length -eq 0) { throw 'Git NUL projection contains an empty record.' }
        $recordBytes = [byte[]]::new($length)
        [Array]::Copy($Bytes, $recordStart, $recordBytes, 0, $length)
        $records.Add((ConvertFrom-FoundationStrictUtf8 -Bytes $recordBytes))
        $recordStart = $index + 1
    }
    return $records.ToArray()
}

function Assert-FoundationDecodedGitPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrEmpty($Path) -or $Path.Contains('\') -or $Path.StartsWith('/') -or $Path.EndsWith('/') -or $Path -cmatch '^[A-Za-z]:') {
        throw "Git path is not repository-relative: $Path"
    }
    foreach ($segment in $Path.Split('/')) {
        if ($segment.Length -eq 0 -or $segment -ceq '.' -or $segment -ceq '..') {
            throw "Git path contains a forbidden segment: $Path"
        }
    }
    return $Path
}

function Get-FoundationGitStageRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Index','Tree')][string]$Kind,
        [string]$Object = 'HEAD',
        [Collections.IDictionary]$Environment
    )

    $arguments = if ($Kind -eq 'Index') {
        @('ls-files','--stage','-z')
    }
    else {
        @('ls-tree','-r','-z','--full-tree',$Object)
    }
    $result = Invoke-FoundationGitRaw -Arguments $arguments -StandardOutputCap $bootstrapContract.GitNulPathMaximumBytes -Environment $Environment
    return ConvertFrom-FoundationGitStageRecords -Bytes $result.StandardOutput -Kind $Kind
}

function Assert-FoundationCleanIndexReadOnly {
    [CmdletBinding()]
    param()

    $indexPathText = [string](Get-FoundationGitOutput -Arguments @('rev-parse','--git-path','index') | Select-Object -First 1)
    $indexPath = if ([IO.Path]::IsPathRooted($indexPathText)) { [IO.Path]::GetFullPath($indexPathText) } else { [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $indexPathText)) }
    $before = Get-FoundationOwnedFileRecord -LiteralPath $indexPath
    $quiet = Invoke-FoundationGitRaw -Arguments @('diff-index','--cached','--quiet','HEAD','--') -AcceptedExitCodes @(0,1)
    if ($quiet.ExitCode -eq 1) { throw 'init-precondition: staged index differs from HEAD.' }
    if ($quiet.ExitCode -ne 0) { throw 'Git authority failed while checking the staged index.' }
    $indexEntries = Get-FoundationGitStageRecords -Kind Index
    $treeEntries = Get-FoundationGitStageRecords -Kind Tree
    if ((Get-FoundationCanonicalHash -Value $indexEntries) -cne (Get-FoundationCanonicalHash -Value $treeEntries)) {
        throw 'init-precondition: normalized index entries differ from HEAD.'
    }
    if (-not (Test-FoundationOwnedFileRecord -Record $before)) {
        throw 'Read-only clean-index proof changed the production index.'
    }
    return [pscustomobject]@{ Path=$indexPath; Record=$before; Entries=$indexEntries }
}

function Assert-FoundationGitGraphState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$GitDirectory)

    foreach ($forbidden in @('info\grafts','shallow','objects\info\alternates')) {
        if (Test-Path -LiteralPath (Join-Path $GitDirectory $forbidden)) {
            throw "Production Git graph state is forbidden: $forbidden"
        }
    }
    if (@(Get-ChildItem -LiteralPath (Join-Path $GitDirectory 'objects\pack') -Filter '*.promisor' -File -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Production promisor packs are forbidden.'
    }
    $replaceRefs = @(Get-FoundationGitOutput -Arguments @('for-each-ref','--format=%(refname)','refs/replace'))
    if ($replaceRefs.Count -ne 0) { throw 'Production replace refs are forbidden.' }
    $configuration = Invoke-FoundationGitRaw -Arguments @('config','--local','--null','--list') -AcceptedExitCodes @(0,1) -StandardOutputCap $bootstrapContract.GitScalarMaximumBytes
    $configurationText = ConvertFrom-FoundationStrictUtf8 -Bytes $configuration.StandardOutput
    if ($configurationText -match '(?i)(extensions\.partialclone|remote\.[^\x00]+\.promisor|remote\.[^\x00]+\.partialclonefilter)') {
        throw 'Production partial-clone or promisor configuration is forbidden.'
    }
}

function Get-FoundationFileProjectionRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point rejected: $LiteralPath" }
    $relativePath = $item.FullName.Substring([IO.Path]::GetFullPath($Root).TrimEnd('\').Length).TrimStart('\').Replace('\','/')
    if ($item.PSIsContainer) {
        return [ordered]@{ path=$relativePath; kind='directory' }
    }
    return [ordered]@{
        path=$relativePath
        kind='file'
        length=$item.Length
        sha256=(Get-FoundationFileSha -LiteralPath $item.FullName)
        nlink=(Get-FoundationNativeLinkCount -LiteralPath $item.FullName)
    }
}

function Get-FoundationDirectoryProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string[]]$ExcludePrefixes = @()
    )

    $records = [Collections.Generic.List[object]]::new()
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        $relativePath = $item.FullName.Substring([IO.Path]::GetFullPath($Root).TrimEnd('\').Length).TrimStart('\').Replace('\','/')
        $excluded = $false
        foreach ($prefix in $ExcludePrefixes) {
            if ($relativePath -ceq $prefix -or $relativePath.StartsWith($prefix + '/', [StringComparison]::Ordinal)) {
                $excluded = $true
                break
            }
        }
        if (-not $excluded) {
            $records.Add((Get-FoundationFileProjectionRecord -Root $Root -LiteralPath $item.FullName))
        }
    }
    return @($records | Sort-Object { $_.path })
}

function Get-FoundationLogicalRefs {
    [CmdletBinding()]
    param()

    $lines = @(Get-FoundationGitOutput -Arguments @('for-each-ref','--format=%(refname) %(objectname)'))
    $records = [Collections.Generic.List[object]]::new()
    foreach ($line in $lines) {
        if ($line -cnotmatch '^(refs/[A-Za-z0-9._/-]+) ([0-9a-f]{40})$') { throw 'Logical Git ref projection is invalid.' }
        $records.Add([ordered]@{ name=$matches[1]; oid=$matches[2] })
    }
    return @($records | Sort-Object { $_.name })
}

function ConvertFrom-FoundationObjectProjection {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $text = ConvertFrom-FoundationStrictUtf8 -Bytes $Bytes
    $records = [Collections.Generic.List[object]]::new()
    foreach ($line in @($text -split '\r?\n' | Where-Object { $_.Length -gt 0 })) {
        if ($line -cnotmatch '^([0-9a-f]{40}) (blob|tree|commit|tag) ([0-9]+)$') { throw 'Git logical object projection is invalid.' }
        $records.Add([ordered]@{ oid=$matches[1]; type=$matches[2]; size=[int64]$matches[3] })
    }
    return @($records | Sort-Object { $_.oid })
}

function Get-FoundationAllObjectProjection {
    [CmdletBinding()]
    param()

    $result = Invoke-FoundationGitRaw -Arguments @('cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)') -StandardOutputCap $bootstrapContract.GitLogicalProjectionMaximumBytes
    return ConvertFrom-FoundationObjectProjection -Bytes $result.StandardOutput
}

function Get-FoundationProtectedObjectProjection {
    [CmdletBinding()]
    param()

    $oidResult = Invoke-FoundationGitRaw -Arguments @('rev-list','--objects','--no-object-names','--all','--reflog') -StandardOutputCap $bootstrapContract.GitLogicalProjectionMaximumBytes
    return Get-FoundationObjectProjectionFromOids -Bytes $oidResult.StandardOutput
}

function Get-FoundationObjectProjectionFromOids {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $oidText = ConvertFrom-FoundationStrictUtf8 -Bytes $Bytes
    $uniqueOids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($oidText.EndsWith("`n", [StringComparison]::Ordinal)) { $oidText = $oidText.Substring(0, $oidText.Length - 1).TrimEnd("`r") }
    if ($oidText.Length -eq 0) { return @() }
    foreach ($line in @($oidText -split '\r?\n')) {
        if ($line -cnotmatch '^[0-9a-f]{40}$') { throw 'Git object traversal contains an invalid OID.' }
        [void]$uniqueOids.Add($line)
    }
    $oids = @($uniqueOids | Sort-Object)
    if ($oids.Count -eq 0) { return @() }
    $input = [Text.Encoding]::ASCII.GetBytes((($oids -join "`n") + "`n"))
    $result = Invoke-FoundationGitRaw -Arguments @('cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)') -StandardInput $input -StandardOutputCap $bootstrapContract.GitLogicalProjectionMaximumBytes
    $records = @(ConvertFrom-FoundationObjectProjection -Bytes $result.StandardOutput)
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected $oids -Actual @($records | ForEach-Object { [string]$_.oid }))) { throw 'Git object batch-check differs from the requested OIDs.' }
    return $records
}

function Assert-FoundationProtectedObjectCompleteness {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Prestate)

    $seeds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($record in @($Prestate.logicalRefs) + @($Prestate.protectedObjects)) {
        if ($record.oid -isnot [string] -or $record.oid -cnotmatch '^[0-9a-f]{40}$') {
            throw 'Incomplete protected-object evidence: invalid captured root.'
        }
        [void]$seeds.Add([string]$record.oid)
    }
    $capturedOids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($record in $Prestate.protectedObjects) {
        if (-not (Test-FoundationOrdinalStringSetEquality -Expected @('oid','type','size') -Actual @($record.PSObject.Properties.Name)) -or
            -not $capturedOids.Add([string]$record.oid) -or
            $record.type -cnotmatch '^(commit|tree|blob|tag)$' -or
            -not (Test-FoundationJsonIntegerType -Value $record.size) -or $record.size -lt 0) {
            throw 'Incomplete protected-object evidence: invalid captured object.'
        }
    }
    $closure = @()
    if ($seeds.Count -ne 0) {
        $inputBytes = [Text.Encoding]::ASCII.GetBytes(((@($seeds | Sort-Object) -join "`n") + "`n"))
        $result = Invoke-FoundationGitRaw -Arguments @('rev-list','--objects','--no-object-names','--stdin') -StandardInput $inputBytes -StandardOutputCap $bootstrapContract.GitLogicalProjectionMaximumBytes
        $closure = @(Get-FoundationObjectProjectionFromOids -Bytes $result.StandardOutput)
    }
    Assert-FoundationCanonicalEquality -Expected @($Prestate.protectedObjects) -Actual $closure -Message 'Incomplete protected-object evidence: captured roots do not match their full object closure.'
}

function Get-FoundationReachableObjectProjection {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Object)

    $result = Invoke-FoundationGitRaw -Arguments @('rev-list','--objects','--no-object-names',$Object) -StandardOutputCap $bootstrapContract.GitLogicalProjectionMaximumBytes
    return Get-FoundationObjectProjectionFromOids -Bytes $result.StandardOutput
}

function Get-FoundationOptionalFileRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    if (-not [IO.File]::Exists($LiteralPath)) { return [ordered]@{ exists=$false } }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    return [ordered]@{
        exists=$true
        identity=(Get-FoundationNativeFileIdentity -LiteralPath $LiteralPath)
        length=$item.Length
        sha256=(Get-FoundationFileSha -LiteralPath $LiteralPath)
        bytesBase64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($LiteralPath))
    }
}

function Get-FoundationRepositorySnapshot {
    [CmdletBinding()]
    param([switch]$RequireCleanIndex)

    $gitDirectory = [string](Get-FoundationGitOutput -Arguments @('rev-parse','--absolute-git-dir') | Select-Object -First 1)
    Assert-FoundationGitGraphState -GitDirectory $gitDirectory
    $indexAuthority = if ($RequireCleanIndex) {
        Assert-FoundationCleanIndexReadOnly
    }
    else {
        $indexText = [string](Get-FoundationGitOutput -Arguments @('rev-parse','--git-path','index') | Select-Object -First 1)
        $indexPath = if ([IO.Path]::IsPathRooted($indexText)) { [IO.Path]::GetFullPath($indexText) } else { [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $indexText)) }
        [pscustomobject]@{ Path=$indexPath; Record=(Get-FoundationOwnedFileRecord -LiteralPath $indexPath); Entries=(Get-FoundationGitStageRecords -Kind Index) }
    }
    $tracked = @(Get-FoundationGitNulPaths -Arguments @('ls-files','-z'))
    $untracked = @(Get-FoundationGitNulPaths -Arguments @('ls-files','--others','--exclude-standard','-z'))
    $ignored = @(Get-FoundationGitNulPaths -Arguments @('ls-files','--others','--ignored','--exclude-standard','-z'))
    $worktree = Get-FoundationDirectoryProjection -Root $RepositoryRoot -ExcludePrefixes @('.git')
    $gitMetadata = Get-FoundationDirectoryProjection -Root $gitDirectory -ExcludePrefixes @('objects','refs','logs','index','COMMIT_EDITMSG')
    foreach ($record in $gitMetadata) {
        if ($record.path -match '(^|/)[^/]*\.lock$') { throw "Git lock file is forbidden: $($record.path)" }
    }
    $objectRoot = Join-Path $gitDirectory 'objects'
    $productionOdb = @()
    foreach ($file in Get-ChildItem -LiteralPath $objectRoot -File -Recurse -Force | Sort-Object FullName) {
        $productionOdb += [ordered]@{
            name=$file.FullName.Substring($objectRoot.Length).TrimStart('\').Replace('\','/')
            identity=(Get-FoundationNativeFileIdentity -LiteralPath $file.FullName)
            length=$file.Length
            sha256=(Get-FoundationFileSha -LiteralPath $file.FullName)
            nlink=(Get-FoundationNativeLinkCount -LiteralPath $file.FullName)
        }
    }
    $branch = [string](Get-FoundationGitOutput -Arguments @('branch','--show-current') | Select-Object -First 1)
    $headLogPath = Join-Path $gitDirectory 'logs\HEAD'
    $branchLogPath = Join-Path $gitDirectory ('logs\refs\heads\' + $branch.Replace('/','\'))
    $selectedBranchLogRelative = 'logs/refs/heads/' + $branch
    $otherLogs = @()
    if ([IO.Directory]::Exists((Join-Path $gitDirectory 'logs'))) {
        $otherLogs = @(Get-FoundationDirectoryProjection -Root $gitDirectory -ExcludePrefixes @('objects','refs','index','COMMIT_EDITMSG') | Where-Object {
            [string]$_.path -ne 'logs' -and [string]$_.path -ne 'logs/HEAD' -and [string]$_.path -ne $selectedBranchLogRelative
        })
    }
    return [ordered]@{
        repo=$RepositoryRoot
        gitDirectory=$gitDirectory
        branch=$branch
        head=[string](Get-FoundationGitOutput -Arguments @('rev-parse','HEAD') | Select-Object -First 1)
        index=[ordered]@{ path=$indexAuthority.Path; identity=$indexAuthority.Record.Identity; length=$indexAuthority.Record.Length; sha256=$indexAuthority.Record.Sha256; entries=$indexAuthority.Entries }
        tracked=$tracked
        untracked=$untracked
        ignored=$ignored
        worktree=$worktree
        gitMetadata=$gitMetadata
        logicalRefs=Get-FoundationLogicalRefs
        headReflog=Get-FoundationOptionalFileRecord -LiteralPath $headLogPath
        branchReflog=Get-FoundationOptionalFileRecord -LiteralPath $branchLogPath
        otherLogs=$otherLogs
        commitEditMessage=Get-FoundationOptionalFileRecord -LiteralPath (Join-Path $gitDirectory 'COMMIT_EDITMSG')
        productionOdb=$productionOdb
        allObjects=Get-FoundationAllObjectProjection
        protectedObjects=Get-FoundationProtectedObjectProjection
    }
}

function New-FoundationExecutionPrestate {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    Assert-FoundationPortablePath -LiteralPath $LiteralPath -Role PrestatePath
    Assert-FoundationPortablePath -LiteralPath "$LiteralPath.$('0' * 32).tmp" -Role 'prestate temporary'
    if (Test-Path -LiteralPath $LiteralPath) { throw "Prestate destination exists: $LiteralPath" }
    Assert-FoundationCanonicalAllowlistPrestate
    $snapshot = Get-FoundationRepositorySnapshot -RequireCleanIndex
    $allowedBaseline = @($bootstrapContract.Allowlist | ForEach-Object {
        Get-FoundationPathStateRecord -RelativePath $_ -Tracked ($snapshot.tracked -ccontains $_)
    })
    $document = [ordered]@{
        schemaVersion=3
        schemaId=$bootstrapContract.ExecutionPrestateSchemaId
        repo=$snapshot.repo
        gitDirectory=$snapshot.gitDirectory
        branch=$snapshot.branch
        head=$snapshot.head
        allowlistCount=66
        index=$snapshot.index
        allowedBaseline=$allowedBaseline
        tracked=$snapshot.tracked
        untracked=$snapshot.untracked
        ignored=$snapshot.ignored
        worktree=$snapshot.worktree
        gitMetadata=$snapshot.gitMetadata
        logicalRefs=$snapshot.logicalRefs
        headReflog=$snapshot.headReflog
        branchReflog=$snapshot.branchReflog
        commitEditMessage=$snapshot.commitEditMessage
        productionOdb=$snapshot.productionOdb
        allObjects=$snapshot.allObjects
        protectedObjects=$snapshot.protectedObjects
        otherLogs=$snapshot.otherLogs
    }
    Assert-FoundationProductionUnchanged -Prestate $document -RequireCapturedIdentity
    $bytes = Get-PspktCanonicalJsonBytes -Value $document
    if ($bytes.Length -gt $bootstrapContract.PrestateMaximumBytes) { throw 'Execution prestate exceeds its bounded-file cap.' }
    $parent = Split-Path -Parent $LiteralPath
    if (-not [IO.Directory]::Exists($parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
    $temporaryPath = "$LiteralPath.$([guid]::NewGuid().ToString('N')).tmp"
    $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $temporaryRecord = Get-FoundationOwnedFileRecord -LiteralPath $temporaryPath
    $moveError = $null
    $cleanupError = $null
    try { Move-FoundationNativeOwnedFileCreateOnly -Source $temporaryPath -Destination $LiteralPath -Record $temporaryRecord }
    catch { $moveError = $_.Exception }
    try {
        if ([IO.File]::Exists($temporaryPath)) { Remove-FoundationOwnedFile -Record $temporaryRecord }
    }
    catch { $cleanupError = $_.Exception }
    if ($null -ne $moveError -and $null -ne $cleanupError) {
        throw [AggregateException]::new('Execution prestate publication and cleanup failed.', [Exception[]]@($moveError,$cleanupError))
    }
    if ($null -ne $moveError) { throw $moveError }
    if ($null -ne $cleanupError) { throw $cleanupError }
}

function Read-FoundationExecutionPrestate {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Binding)

    if ($Binding.Length -gt $bootstrapContract.PrestateMaximumBytes) { throw 'Execution prestate exceeds its bounded-file cap.' }
    $document = ConvertFrom-FoundationStrictUtf8 -Bytes ([byte[]]$Binding.Bytes) | ConvertFrom-Json
    $canonical = Get-PspktCanonicalJsonBytes -Value $document
    if (-not (Test-FoundationByteArrayEquality -Left ([byte[]]$Binding.Bytes) -Right $canonical)) { throw 'Execution prestate is not canonical JSON.' }
    $required = @('allObjects','allowedBaseline','allowlistCount','branch','branchReflog','commitEditMessage','gitDirectory','gitMetadata','head','headReflog','ignored','index','logicalRefs','otherLogs','productionOdb','protectedObjects','repo','schemaId','schemaVersion','tracked','untracked','worktree')
    if (-not (Test-FoundationJsonObject -Value $document) -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected $required -Actual ([string[]]@($document.PSObject.Properties.Name))) -or
        -not (Test-FoundationJsonInteger -Value $document.schemaVersion -Expected 3) -or
        [string]$document.schemaId -cne 'PspktFoundationExecutionPrestateV3' -or
        [string]$document.repo -cne $RepositoryRoot -or
        [string]$document.head -cne $bootstrapContract.BaselineOid -or
        [string]$document.branch -cne $bootstrapContract.Branch -or
        @($document.allowedBaseline).Count -ne 66) {
        throw 'Execution prestate shape is invalid.'
    }
    $paths = @($document.allowedBaseline | ForEach-Object { [string]$_.path })
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.Allowlist) -Actual ([string[]]$paths))) {
        throw 'Execution prestate allowlist is invalid.'
    }
    foreach ($record in $document.allowedBaseline) {
        $requiredProperties = if ([bool]$record.exists) {
            @('exists','identity','kind','length','nlink','path','sha256','tracked')
        }
        else {
            @('exists','path','tracked')
        }
        if (-not (Test-FoundationOrdinalStringSetEquality -Expected $requiredProperties -Actual ([string[]]@($record.PSObject.Properties.Name))) -or
            $record.path -isnot [string] -or $record.tracked -isnot [bool] -or $record.exists -isnot [bool]) {
            throw 'Execution prestate allowlist record is invalid.'
        }
        if ([bool]$record.exists -and (
            [string]$record.kind -cne 'file' -or
            [string]$record.identity -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$' -or
            -not (Test-FoundationJsonIntegerType -Value $record.length) -or [int64]$record.length -lt 0 -or
            [string]$record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-FoundationJsonInteger -Value $record.nlink -Expected 1))) {
            throw 'Execution prestate allowlist record is invalid.'
        }
    }
    Assert-FoundationProtectedObjectCompleteness -Prestate $document
    return $document
}

function Assert-FoundationCanonicalEquality {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ((Get-FoundationCanonicalHash -Value $Expected) -cne (Get-FoundationCanonicalHash -Value $Actual)) { throw $Message }
}

function Assert-FoundationReflogAppend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Baseline,
        [Parameter(Mandatory = $true)]$Current,
        [Parameter(Mandatory = $true)][string]$OldOid,
        [Parameter(Mandatory = $true)][string]$NewOid,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $baselineBytes = if ([bool]$Baseline.exists) { [Convert]::FromBase64String([string]$Baseline.bytesBase64) } else { [byte[]]::new(0) }
    $currentBytes = if ([bool]$Current.exists) { [Convert]::FromBase64String([string]$Current.bytesBase64) } else { [byte[]]::new(0) }
    if ($currentBytes.Length -le $baselineBytes.Length) { throw "$Name reflog did not append exactly once." }
    $prefix = [byte[]]::new($baselineBytes.Length)
    [Array]::Copy($currentBytes,0,$prefix,0,$prefix.Length)
    if (-not (Test-FoundationByteArrayEquality -Left $baselineBytes -Right $prefix)) { throw "$Name reflog prefix changed." }
    $appendBytes = [byte[]]::new($currentBytes.Length - $baselineBytes.Length)
    [Array]::Copy($currentBytes,$baselineBytes.Length,$appendBytes,0,$appendBytes.Length)
    $append = ConvertFrom-FoundationStrictUtf8 -Bytes $appendBytes
    $lines = @($append -split "`n" | Where-Object { $_.Length -gt 0 })
    if ($lines.Count -ne 1 -or $lines[0] -cnotmatch "^$OldOid $NewOid ") { throw "$Name reflog append is invalid." }
}

function Get-FoundationExpectedHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Receipt,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $property = $Receipt.inputHashes.PSObject.Properties[$RelativePath]
    if ($null -eq $property) { $property = $Receipt.outputHashes.PSObject.Properties[$RelativePath] }
    if ($null -eq $property) { throw "Receipt lacks allowlist hash: $RelativePath" }
    return [string]$property.Value
}

function Assert-FoundationProductionUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        $ExpectedAllowlistHashes,
        [string]$CommittedReplayOid,
        [string[]]$TransactionOwnedUntrackedPaths = @(),
        [string[]]$TransactionOwnedDirectories = @(),
        [switch]$AllowStaged,
        [switch]$RequireCapturedIdentity
    )

    $current = Get-FoundationRepositorySnapshot
    if ($current.repo -cne [string]$Prestate.repo -or $current.branch -cne [string]$Prestate.branch) { throw 'Production repository identity changed.' }
    $mode = if (-not [string]::IsNullOrEmpty($CommittedReplayOid)) { 'Committed' } elseif ($AllowStaged) { 'Staged' } else { 'Unstaged' }
    if ($mode -eq 'Committed') {
        if ($current.head -cne $CommittedReplayOid) { throw 'Committed Replay HEAD differs from the selected commit.' }
    }
    elseif ($current.head -cne [string]$Prestate.head) {
        throw 'Production HEAD changed.'
    }
    $expectedTracked = if ($mode -eq 'Unstaged') {
        @($Prestate.tracked)
    }
    else {
        @(@($Prestate.tracked) + @($bootstrapContract.Allowlist) | Sort-Object -Unique)
    }
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$expectedTracked) -Actual ([string[]]$current.tracked))) {
        throw 'Tracked path set changed.'
    }
    Assert-FoundationCanonicalEquality -Expected $Prestate.ignored -Actual $current.ignored -Message 'Ignored path set changed.'
    $filteredUntracked = @($current.untracked | Where-Object {
        $path = [string]$_
        $bootstrapContract.Allowlist -cnotcontains $path -and $TransactionOwnedUntrackedPaths -cnotcontains $path
    })
    $expectedUntracked = @($Prestate.untracked | Where-Object { $bootstrapContract.Allowlist -cnotcontains [string]$_ })
    Assert-FoundationCanonicalEquality -Expected $expectedUntracked -Actual $filteredUntracked -Message 'Untracked path set changed.'
    $currentWorktree = @($current.worktree | Where-Object {
        $path = [string]$_.path
        $owned = $false
        if ($bootstrapContract.Allowlist -ccontains $path -or $TransactionOwnedUntrackedPaths -ccontains $path -or $TransactionOwnedDirectories -ccontains $path) { $owned = $true }
        -not $owned
    })
    $baselineWorktree = @($Prestate.worktree | Where-Object {
        $path = [string]$_.path
        $owned = $false
        if ($bootstrapContract.Allowlist -ccontains $path) { $owned = $true }
        -not $owned
    })
    Assert-FoundationCanonicalEquality -Expected $baselineWorktree -Actual $currentWorktree -Message 'Non-owned worktree projection changed.'
    Assert-FoundationCanonicalEquality -Expected $Prestate.gitMetadata -Actual $current.gitMetadata -Message 'Git non-ref metadata changed.'
    Assert-FoundationCanonicalEquality -Expected $Prestate.otherLogs -Actual $current.otherLogs -Message 'Unrelated Git reflogs changed.'
    if ($mode -eq 'Committed') {
        $expectedRefs = @($Prestate.logicalRefs | ForEach-Object {
            if ([string]$_.name -ceq "refs/heads/$($Prestate.branch)") { [ordered]@{ name=$_.name; oid=$CommittedReplayOid } } else { $_ }
        })
        if ($expectedRefs.Count -ne @($current.logicalRefs).Count) { throw 'Committed Replay logical refs changed outside the selected branch.' }
        foreach ($expectedRef in $expectedRefs) {
            $actualRef = @($current.logicalRefs | Where-Object { [string]$_.name -ceq [string]$expectedRef.name })
            if ($actualRef.Count -ne 1 -or [string]$actualRef[0].oid -cne [string]$expectedRef.oid) {
                throw 'Committed Replay logical refs changed outside the selected branch.'
            }
        }
        Assert-FoundationReflogAppend -Baseline $Prestate.headReflog -Current $current.headReflog -OldOid ([string]$Prestate.head) -NewOid $CommittedReplayOid -Name 'HEAD'
        Assert-FoundationReflogAppend -Baseline $Prestate.branchReflog -Current $current.branchReflog -OldOid ([string]$Prestate.head) -NewOid $CommittedReplayOid -Name 'Branch'
        $message = Invoke-FoundationGitRaw -Arguments @('log','-1','--format=%B',$CommittedReplayOid) -StandardOutputCap $bootstrapContract.GitScalarMaximumBytes
        if ($message.StandardOutput.Length -eq 0 -or $message.StandardOutput[$message.StandardOutput.Length - 1] -ne 10) { throw 'Selected commit full message is not LF-terminated.' }
        $canonicalMessage = [byte[]]::new($message.StandardOutput.Length - 1)
        [Array]::Copy($message.StandardOutput,0,$canonicalMessage,0,$canonicalMessage.Length)
        if (-not [bool]$current.commitEditMessage.exists -or -not (Test-FoundationByteArrayEquality -Left $canonicalMessage -Right ([Convert]::FromBase64String([string]$current.commitEditMessage.bytesBase64)))) {
            throw 'COMMIT_EDITMSG differs from the selected commit full message.'
        }
        $indexEntries = Get-FoundationGitStageRecords -Kind Index
        $selectedEntries = Get-FoundationGitStageRecords -Kind Tree -Object $CommittedReplayOid
        Assert-FoundationCanonicalEquality -Expected $selectedEntries -Actual $indexEntries -Message 'Committed Replay index differs from the selected commit.'
        $baselineOids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($record in $Prestate.allObjects) { [void]$baselineOids.Add([string]$record.oid) }
        $expectedNewObjects = @(Get-FoundationReachableObjectProjection -Object $CommittedReplayOid | Where-Object { -not $baselineOids.Contains([string]$_.oid) })
        $actualNewObjects = @($current.allObjects | Where-Object { -not $baselineOids.Contains([string]$_.oid) })
        Assert-FoundationCanonicalEquality -Expected $expectedNewObjects -Actual $actualNewObjects -Message 'Committed Replay introduced an unrelated Git object.'
    }
    else {
        Assert-FoundationCanonicalEquality -Expected $Prestate.logicalRefs -Actual $current.logicalRefs -Message 'Logical refs changed.'
        Assert-FoundationCanonicalEquality -Expected $Prestate.headReflog -Actual $current.headReflog -Message 'HEAD reflog changed.'
        Assert-FoundationCanonicalEquality -Expected $Prestate.branchReflog -Actual $current.branchReflog -Message 'Branch reflog changed.'
        if ($mode -eq 'Unstaged') {
            Assert-FoundationCanonicalEquality -Expected $Prestate.index -Actual $current.index -Message 'Production index changed.'
            Assert-FoundationCanonicalEquality -Expected $Prestate.allObjects -Actual $current.allObjects -Message 'Production logical object set changed.'
            Assert-FoundationCanonicalEquality -Expected $Prestate.protectedObjects -Actual $current.protectedObjects -Message 'Protected object set changed.'
            Assert-FoundationCanonicalEquality -Expected $Prestate.productionOdb -Actual $current.productionOdb -Message 'Production object database changed.'
        }
        else {
            $baselineEntries = @($Prestate.index.entries)
            $currentEntries = @($current.index.entries)
            $changedEntries = @($currentEntries | Where-Object {
                $entry = $_
                $baseline = @($baselineEntries | Where-Object { $_.path -ceq $entry.path })
                $baseline.Count -ne 1 -or $baseline[0].mode -cne $entry.mode -or $baseline[0].oid -cne $entry.oid
            })
            if ($changedEntries.Count -ne 66 -or -not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.Allowlist) -Actual ([string[]]@($changedEntries.path)))) {
                throw 'Staged Replay index delta is not exactly the allowlist.'
            }
            foreach ($entry in $changedEntries) {
                $worktreeOid = [string](Get-FoundationGitOutput -Arguments @('hash-object','--no-filters','--',[string]$entry.path) | Select-Object -First 1)
                if ([string]$entry.oid -cne $worktreeOid) { throw "Staged Replay blob differs from the promoted file: $($entry.path)" }
            }
            $baselineOids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($record in $Prestate.allObjects) { [void]$baselineOids.Add([string]$record.oid) }
            $expectedNewOids = @($changedEntries.oid | Where-Object { -not $baselineOids.Contains([string]$_) } | Sort-Object -Unique)
            $actualNewOids = @($current.allObjects | Where-Object { -not $baselineOids.Contains([string]$_.oid) } | ForEach-Object { [string]$_.oid } | Sort-Object -Unique)
            Assert-FoundationCanonicalEquality -Expected $expectedNewOids -Actual $actualNewOids -Message 'Staged Replay introduced unrelated Git objects.'
        }
    }
    $currentObjects = @{}
    foreach ($record in $current.allObjects) { $currentObjects[[string]$record.oid] = $record }
    foreach ($protected in $Prestate.protectedObjects) {
        $resolved = $currentObjects[[string]$protected.oid]
        if ($null -eq $resolved -or $resolved.type -cne $protected.type -or $resolved.size -ne $protected.size) {
            throw "Captured protected object is no longer resolvable with its recorded type and size: $($protected.oid)"
        }
    }
    foreach ($baseline in $Prestate.allowedBaseline) {
        $relativePath = [string]$baseline.path
        $fullPath = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
        if ($null -eq $ExpectedAllowlistHashes) {
            if ([IO.File]::Exists($fullPath) -ne [bool]$baseline.exists) { throw "Allowlist baseline existence changed: $relativePath" }
            if ([bool]$baseline.exists) {
                $item = Get-Item -LiteralPath $fullPath -Force
                if ($item.PSIsContainer -or [string]$baseline.kind -cne 'file' -or
                    $item.Length -ne [int64]$baseline.length -or
                    (Get-FoundationFileSha -LiteralPath $fullPath) -cne [string]$baseline.sha256 -or
                    (Get-FoundationNativeLinkCount -LiteralPath $fullPath) -ne 1) {
                    throw "Allowlist baseline file changed: $relativePath"
                }
                if ($RequireCapturedIdentity -and (Get-FoundationNativeFileIdentity -LiteralPath $fullPath) -cne [string]$baseline.identity) {
                    throw "Allowlist baseline identity changed: $relativePath"
                }
            }
        }
        else {
            if (-not [IO.File]::Exists($fullPath) -or (Get-FoundationFileSha -LiteralPath $fullPath) -cne (Get-FoundationExpectedHash -Receipt $ExpectedAllowlistHashes -RelativePath $relativePath) -or (Get-FoundationNativeLinkCount -LiteralPath $fullPath) -ne 1) {
                throw "Promoted allowlist path differs from receipt: $relativePath"
            }
        }
    }
}

function New-FoundationPrivateIndexProof {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$GitDirectory,
        [Parameter(Mandatory = $true)][string]$WorkTree,
        [Parameter(Mandatory = $true)][string]$IndexPath,
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [string]$SelectedTreeOid,
        [string]$SelectedMapBlobOid,
        [string]$SelectedCommitOid
    )

    Assert-FoundationPortablePath -LiteralPath $GitDirectory -Role 'private Git directory' -Directory
    Assert-FoundationPortablePath -LiteralPath $IndexPath -Role 'private Git index'
    foreach ($relativePath in $Paths) {
        Assert-FoundationPortablePath -LiteralPath ($WorkTree.TrimEnd('\') + '\' + $relativePath.Replace('/','\')) -Role 'private Git checkout'
    }
    if (Test-Path -LiteralPath $GitDirectory) { throw "Private Git directory already exists: $GitDirectory" }
    $baseEnvironment = New-FoundationGitEnvironment
    [void](Invoke-FoundationPrivateGitRaw -Arguments @('init','--bare','--object-format=sha1',$GitDirectory) -WorkingDirectory $ScratchRoot -Environment $baseEnvironment)
    $environment = New-FoundationGitEnvironment -GitDirectory $GitDirectory -WorkTree $WorkTree -IndexPath $IndexPath
    if ($Mode -eq 'CommittedProof') {
        $uri = [Uri]::new([IO.Path]::GetFullPath($RepositoryRoot)).AbsoluteUri
        [void](Invoke-FoundationPrivateGitRaw -Arguments @('-c','protocol.file.allow=always','fetch','--no-tags',$uri,"$SelectedCommitOid`:refs/heads/selected") -WorkingDirectory $ScratchRoot -Environment $environment)
        [IO.Directory]::CreateDirectory($WorkTree) | Out-Null
        [void](Invoke-FoundationPrivateGitRaw -Arguments @('read-tree',$SelectedCommitOid) -WorkingDirectory $WorkTree -Environment $environment)
        [void](Invoke-FoundationPrivateGitRaw -Arguments (@('checkout-index','--') + $Paths) -WorkingDirectory $WorkTree -Environment $environment)
    }
    [void](Invoke-FoundationPrivateGitRaw -Arguments @('read-tree','--empty') -WorkingDirectory $WorkTree -Environment $environment)
    foreach ($relativePath in $Paths) {
        [void](Invoke-FoundationPrivateGitRaw -Arguments @('add','--',$relativePath) -WorkingDirectory $WorkTree -Environment $environment)
    }
    $indexed = @(Get-FoundationPrivateGitNulPaths -Arguments @('ls-files','-z') -WorkingDirectory $WorkTree -Environment $environment)
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected $Paths -Actual $indexed)) { throw 'Private index path set mismatch.' }
    $tree = [string](Get-FoundationPrivateGitOutput -Arguments @('write-tree') -WorkingDirectory $WorkTree -Environment $environment | Select-Object -First 1)
    if ($Mode -eq 'Generate') {
        return [ordered]@{ treeOid=$tree; resolvedMapOid=$null; records=@() }
    }
    if ($Mode -eq 'CommittedProof' -and $tree -cne $SelectedTreeOid) { throw 'Committed allowlist-only tree differs from the Replay receipt.' }
    $treeToResolve = if ([string]::IsNullOrEmpty($SelectedTreeOid) -or $SelectedTreeOid -ceq '__GENERATED__') { $tree } else { $SelectedTreeOid }
    $mapLine = [string](Get-FoundationPrivateGitOutput -Arguments @('ls-tree','--full-tree',$treeToResolve,'--',$bootstrapContract.MapRelativePath) -WorkingDirectory $WorkTree -Environment $environment | Select-Object -First 1)
    if ($mapLine -cnotmatch '^100644 blob ([0-9a-f]{40})\t') { throw 'Private proof tree map entry is invalid.' }
    $resolvedMapOid = $matches[1]
    if (-not [string]::IsNullOrEmpty($SelectedMapBlobOid) -and $SelectedMapBlobOid -cne '__GENERATED__' -and $resolvedMapOid -cne $SelectedMapBlobOid) { throw 'Selected map blob is not the exact private proof tree entry.' }
    $records = @()
    foreach ($relativePath in $Paths) {
        $stage = @(Get-FoundationPrivateGitStageRecords -Kind Index -WorkingDirectory $WorkTree -Environment $environment | Where-Object { $_.path -ceq $relativePath })
        if ($stage.Count -ne 1) { throw "Private proof index entry is invalid: $relativePath" }
        $oid = [string]$stage[0].oid
        $hash = [string](Get-FoundationPrivateGitOutput -Arguments @('hash-object','--no-filters','--',$relativePath) -WorkingDirectory $WorkTree -Environment $environment | Select-Object -First 1)
        if ($oid -cne $hash) { throw "Index/hash-object mismatch: $relativePath" }
        $raw = [IO.File]::ReadAllBytes((Resolve-FoundationHostPath -Root $WorkTree -RelativePath $relativePath))
        $blob = (Invoke-FoundationPrivateGitRaw -Arguments @('cat-file','blob',$oid) -WorkingDirectory $WorkTree -Environment $environment -StandardOutputCap $bootstrapContract.GeneratedOutputFileMaximumBytes).StandardOutput
        Assert-FoundationPortablePath -LiteralPath ($WorkTree.TrimEnd('\') + '\.merge_file_000000') -Role 'private Git checkout temporary'
        $checkoutResult = Invoke-FoundationPrivateGitRaw -Arguments @('checkout-index','--temp','-z','--',$relativePath) -WorkingDirectory $WorkTree -Environment $environment -StandardOutputCap $bootstrapContract.GitNulPathMaximumBytes
        $checkoutRecords = @(ConvertFrom-FoundationGitNulRecords -Bytes $checkoutResult.StandardOutput)
        if ($checkoutRecords.Count -ne 1 -or $checkoutRecords[0] -cnotmatch '^([^\t/\\]+)\t') { throw "Checkout proof output is invalid: $relativePath" }
        $checkoutPath = Join-Path $WorkTree $matches[1]
        Assert-FoundationPortablePath -LiteralPath $checkoutPath -Role 'private Git checkout temporary'
        try {
            $checkout = [IO.File]::ReadAllBytes($checkoutPath)
        }
        finally {
            if ([IO.File]::Exists($checkoutPath)) { [IO.File]::Delete($checkoutPath) }
        }
        if (-not (Test-FoundationByteArrayEquality -Left $raw -Right $blob) -or -not (Test-FoundationByteArrayEquality -Left $raw -Right $checkout)) { throw "Blob proof mismatch: $relativePath" }
        $cachedAttributes = @(Get-FoundationPrivateGitOutput -Arguments @('check-attr','-a','--cached','--',$relativePath) -WorkingDirectory $WorkTree -Environment $environment)
        $worktreeAttributes = @(Get-FoundationPrivateGitOutput -Arguments @('check-attr','-a','--',$relativePath) -WorkingDirectory $WorkTree -Environment $environment)
        if ($cachedAttributes.Count -ne 5 -or $worktreeAttributes.Count -ne 5) { throw "Attribute cardinality mismatch: $relativePath" }
        $expectedText = if ($relativePath.EndsWith('.json',[StringComparison]::Ordinal)) { 'unset' } else { 'set' }
        $expectedEol = if ($relativePath.EndsWith('.json',[StringComparison]::Ordinal)) { 'unset' } else { 'lf' }
        foreach ($attributeLines in @($cachedAttributes,$worktreeAttributes)) {
            $attributes = @{}
            foreach ($attributeLine in $attributeLines) {
                if ($attributeLine -cnotmatch '^[^:]+: ([^:]+): (.+)$') { throw "Attribute parse failure: $relativePath" }
                $attributes[$matches[1]] = $matches[2]
            }
            if ($attributes.text -cne $expectedText -or $attributes.eol -cne $expectedEol -or $attributes.filter -cne 'unset' -or $attributes.ident -cne 'unset' -or $attributes.'working-tree-encoding' -cne 'unset') {
                throw "Attribute policy mismatch: $relativePath"
            }
        }
        $records += [ordered]@{
            path=$relativePath
            oid=$oid
            rawLength=$raw.Length
            rawSha256=(Get-FoundationHostSha256 -Bytes $raw)
            blobLength=$blob.Length
            blobSha256=(Get-FoundationHostSha256 -Bytes $blob)
            checkoutLength=$checkout.Length
            checkoutSha256=(Get-FoundationHostSha256 -Bytes $checkout)
            cachedAttributes=$cachedAttributes
            worktreeAttributes=$worktreeAttributes
        }
    }
    return [ordered]@{ treeOid=$tree; resolvedMapOid=$resolvedMapOid; records=$records }
}

function Initialize-FoundationOneA {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OneARoot)

    Assert-FoundationPortablePath -LiteralPath $OneARoot -Role '1A checkout root' -Directory
    if (Test-Path -LiteralPath $OneARoot) { throw '1A root must be absent before setup.' }
    [IO.Directory]::CreateDirectory($OneARoot) | Out-Null
    $environment = New-FoundationGitEnvironment
    [void](Invoke-FoundationPrivateGitRaw -Arguments @('init','--object-format=sha1') -WorkingDirectory $OneARoot -Environment $environment)
    $uri = [Uri]::new([IO.Path]::GetFullPath($RepositoryRoot)).AbsoluteUri
    [void](Invoke-FoundationPrivateGitRaw -Arguments @('-c','protocol.file.allow=always','fetch','--no-tags',$uri,"$($bootstrapContract.BaselineOid)`:refs/heads/validation") -WorkingDirectory $OneARoot -Environment $environment)
    [void](Invoke-FoundationPrivateGitRaw -Arguments @('symbolic-ref','HEAD','refs/heads/validation') -WorkingDirectory $OneARoot -Environment $environment)
    $head = [string](Get-FoundationPrivateGitOutput -Arguments @('rev-parse','HEAD^{commit}') -WorkingDirectory $OneARoot -Environment $environment | Select-Object -First 1)
    if ($head -cne $bootstrapContract.BaselineOid) { throw '1A fetched HEAD mismatch.' }
    $validatorBytes = (Invoke-FoundationPrivateGitRaw -Arguments @('show','validation:certification/validators/Invoke-PspktPhase4SchemaValidators.ps1') -WorkingDirectory $OneARoot -Environment $environment -StandardOutputCap $bootstrapContract.GitLogicalProjectionMaximumBytes).StandardOutput
    $validatorSource = ConvertFrom-FoundationStrictUtf8 -Bytes $validatorBytes
    $block = [regex]::Match($validatorSource,'(?s)\$script:ExpectedSlicePaths\s*=\s*@\((.*?)\)\s*\r?\n')
    if (-not $block.Success) { throw 'Unable to parse 1A slice paths.' }
    $paths = @([regex]::Matches($block.Groups[1].Value,"'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
    if ($paths.Count -ne 71) { throw "1A slice count mismatch: $($paths.Count)" }
    foreach ($relativePath in $paths) {
        Assert-FoundationPortablePath -LiteralPath ($OneARoot.TrimEnd('\') + '\' + $relativePath.Replace('/','\')) -Role '1A checkout'
    }
    [void](Invoke-FoundationPrivateGitRaw -Arguments @('read-tree','--empty') -WorkingDirectory $OneARoot -Environment $environment)
    [void](Invoke-FoundationPrivateGitRaw -Arguments (@('checkout','validation','--') + $paths) -WorkingDirectory $OneARoot -Environment $environment)
    if (Test-Path -LiteralPath (Join-Path $OneARoot '.git\objects\info\alternates')) { throw '1A alternates file is forbidden.' }
    return [ordered]@{ head=$head; pathCount=$paths.Count; paths=$paths }
}

function Test-FoundationJournalCapacity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$SegmentCount,
        [Parameter(Mandatory = $true)][int]$MaximumSegmentBytes,
        [Parameter(Mandatory = $true)][int64]$EvidenceBytes
    )

    if ($SegmentCount -gt $bootstrapContract.RecoveryJournalMaximumSegments -or
        $MaximumSegmentBytes -gt $bootstrapContract.RecoveryJournalSegmentMaximumBytes -or
        $EvidenceBytes -gt $bootstrapContract.RecoveryJournalEvidenceReserveBytes) {
        return $false
    }
    return ([int64]$SegmentCount * $MaximumSegmentBytes + $EvidenceBytes) -le $bootstrapContract.RecoveryJournalMaximumBytes
}

function Publish-FoundationJournalSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][ValidateSet('header','intent','applied','not-applied','conflict')][string]$Kind,
        [Parameter(Mandatory = $true)]$Record
    )

    $name = '{0:D8}.{1}.json' -f $Sequence,$Kind
    $destination = Join-Path $Journal.Path $name
    $temporary = Join-Path $Journal.Path ('.pspkt-segment-' + [guid]::NewGuid().ToString('N') + '.tmp')
    Assert-FoundationPortablePath -LiteralPath $destination -Role 'journal segment'
    Assert-FoundationPortablePath -LiteralPath $temporary -Role 'journal segment temporary'
    $bytes = Get-PspktCanonicalJsonBytes -Value $Record
    if ($Sequence -ne 0 -and ($null -eq $Journal.Lease -or -not $Journal.Lease.Exclusive -or -not $Journal.Lease.Stream.CanRead)) {
        throw 'Journal publication requires the retained exclusive header lease.'
    }
    if ($bytes.Length -gt $bootstrapContract.RecoveryJournalSegmentMaximumBytes) { throw 'Recovery journal segment exceeds its hard cap.' }
    if (Test-Path -LiteralPath $destination) { throw "Recovery journal segment already exists: $name" }
    $segmentCount = @(Get-ChildItem -LiteralPath $Journal.Path -File -Force | Where-Object { $_.Name -cmatch '^[0-9]{8}\.(header|intent|applied|not-applied|conflict)\.json$' }).Count
    if ($segmentCount -ge $bootstrapContract.RecoveryJournalMaximumSegments) { throw 'Recovery journal segment count exceeds its hard cap.' }
    $currentBytes = [int64](@(Get-ChildItem -LiteralPath $Journal.Path -File -Force | Measure-Object -Property Length -Sum).Sum)
    if ($currentBytes + $bytes.Length + $bootstrapContract.RecoveryJournalEvidenceReserveBytes -gt $bootstrapContract.RecoveryJournalMaximumBytes) {
        throw 'Recovery journal reserved capacity is exhausted.'
    }
    $stream = [IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $temporaryRecord = Get-FoundationOwnedFileRecord -LiteralPath $temporary
    Move-FoundationNativeOwnedFileCreateOnly -Source $temporary -Destination $destination -Record $temporaryRecord
    if ((Get-FoundationFileSha -LiteralPath $destination) -cne (Get-FoundationHostSha256 -Bytes $bytes)) { throw "Recovery journal segment verification failed: $name" }
}

function Assert-FoundationJournalAdmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)]$Details
    )

    if ($null -eq $Journal.Lease -or -not $Journal.Lease.Exclusive) { throw 'Journal mutation requires the retained exclusive header lease.' }
    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    $Journal.Operations = $fresh.Operations
    $Journal.Segments = $fresh.Segments
    $Journal.NextSequence = $fresh.NextSequence
    $files = @(Get-ChildItem -LiteralPath $Journal.Path -File -Force)
    $segments = @($files | Where-Object { $_.Name -cmatch '^[0-9]{8}\.(header|intent|applied|not-applied|conflict)\.json$' })
    $unmatched = @($Journal.Operations | Where-Object { $null -eq $_.Terminal }).Count
    $directoryOperations = @($Journal.Operations | Where-Object { $_.Intent.Record.operation -cin @('DirectoryTempCreate','DirectoryPublish') }).Count
    $recoveryReserve = 2 * ($bootstrapContract.Allowlist.Count * 2 + 3) + 16 + 2 * $directoryOperations + 32
    if ($Journal.Recovery) {
        $ownership = Get-FoundationJournalOwnership -Journal $fresh
        $undoFiles = @($ownership.Files.Values | Where-Object { -not ($_.Kind -ceq 'Publish' -and $_.Key.StartsWith('__baseline:', [StringComparison]::Ordinal)) }).Count
        $reserve = $unmatched + 2 * ($undoFiles + $ownership.Directories.Count) + 14
        if ($Journal.RecoveryAction -ceq 'Finalize') { $reserve += 20 }
    }
    else {
        $publishedKeys = @($fresh.Operations | Where-Object { $_.Intent.Record.operation -ceq 'Publish' -and $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied' } | ForEach-Object { [string]$_.Intent.Record.details.evidenceKey } | Sort-Object -Unique)
        $remainingForward = 6 * [Math]::Max(0, $bootstrapContract.Allowlist.Count + 3 - $publishedKeys.Count)
        $reserve = $unmatched + $recoveryReserve + $remainingForward
    }
    if ($segments.Count + 2 + $reserve -gt $bootstrapContract.RecoveryJournalMaximumSegments) {
        throw 'Recovery journal segment reservation is exhausted.'
    }
    $bytes = Get-PspktCanonicalJsonBytes -Value ([ordered]@{schemaVersion=1;sequence=$Journal.NextSequence;operation=$Operation;details=$Details})
    if ($bytes.Length -gt $bootstrapContract.RecoveryJournalSegmentMaximumBytes -or
        [int64](@($files | Measure-Object Length -Sum).Sum) + [int64](2 + $reserve) * $bootstrapContract.RecoveryJournalSegmentMaximumBytes -gt $bootstrapContract.RecoveryJournalMaximumBytes) {
        throw 'Recovery journal byte reservation is exhausted.'
    }
}

function New-FoundationRecoveryJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$InitReceiptBytes,
        [Parameter(Mandatory = $true)][byte[]]$ReplayReceiptBytes,
        [Parameter(Mandatory = $true)]$ExpectedAllowlistHashes,
        [Parameter(Mandatory = $true)][string]$PrestateSha256
    )

    Assert-FoundationTransactionLayout -NewJournal
    $evidence = [Collections.Generic.List[object]]::new()
    $evidencePayloads = [Collections.Generic.List[object]]::new()
    $evidenceBytes = [int64]0
    foreach ($relativePath in $bootstrapContract.Allowlist) {
        $source = Resolve-FoundationHostPath -Root $promoRoot -RelativePath $relativePath
        $bytes = [IO.File]::ReadAllBytes($source)
        $evidenceBytes += $bytes.Length
        $evidencePayloads.Add([pscustomobject]@{ Key=$relativePath; Bytes=$bytes })
    }
    $evidencePayloads.Add([pscustomobject]@{ Key='__init-receipt'; Bytes=$InitReceiptBytes })
    $evidencePayloads.Add([pscustomobject]@{ Key='__replay-receipt'; Bytes=$ReplayReceiptBytes })
    foreach ($relativePath in @('certification/.gitattributes','tests/.gitattributes')) {
        $baselineBytes = (Invoke-FoundationGitRaw -Arguments @('show',"$($bootstrapContract.BaselineOid):$relativePath") -StandardOutputCap $bootstrapContract.GitScalarMaximumBytes).StandardOutput
        $evidencePayloads.Add([pscustomobject]@{ Key="__baseline:$relativePath"; Bytes=$baselineBytes })
        $evidenceBytes += $baselineBytes.Length
    }
    $evidenceBytes += $InitReceiptBytes.Length + $ReplayReceiptBytes.Length
    $missingDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($destination in @($bootstrapContract.Allowlist | ForEach-Object { Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $_ }) + @($InitReceiptPath,$ReplayReceiptPath,$CompletionReceiptPath)) {
        if ($destination.Length * 12 + 2048 -gt $bootstrapContract.RecoveryJournalSegmentMaximumBytes) { throw 'Recovery journal path cannot fit its serialized record bound.' }
        $directory = Split-Path -Parent $destination
        while (-not [IO.Directory]::Exists($directory)) {
            [void]$missingDirectories.Add($directory)
            $parentDirectory = Split-Path -Parent $directory
            if ([string]::IsNullOrEmpty($parentDirectory) -or $parentDirectory -ceq $directory) { throw 'Recovery journal directory budget is not bounded.' }
            $directory = $parentDirectory
        }
    }
    $forwardSegments = 1 + 6 * ($bootstrapContract.Allowlist.Count + 3) + 8 + 4 * $missingDirectories.Count + 2
    $rollbackSegments = 2 * (2 * $bootstrapContract.Allowlist.Count + 3) + 16 + 4 * $missingDirectories.Count + 2
    $retrySegments = 32 + 4 * $missingDirectories.Count
    if ($forwardSegments + $rollbackSegments + $retrySegments -gt $bootstrapContract.RecoveryJournalMaximumSegments) { throw 'Recovery journal operation budget exceeds its segment cap.' }
    if (-not (Test-FoundationJournalCapacity -SegmentCount $bootstrapContract.RecoveryJournalMaximumSegments -MaximumSegmentBytes $bootstrapContract.RecoveryJournalSegmentMaximumBytes -EvidenceBytes $evidenceBytes)) {
        throw 'Recovery journal preflight capacity reservation failed.'
    }
    $parent = Split-Path -Parent $RecoveryJournalPath
    $leaf = Split-Path -Leaf $RecoveryJournalPath
    $nonceRoot = Join-Path $parent (".$leaf.pspkt-journal-" + [guid]::NewGuid().ToString('N'))
    $nonceAuthorities = [Collections.Generic.List[object]]::new()
    foreach ($authority in $initialAuthorities) { $nonceAuthorities.Add($authority) }
    $nonceAuthorities.Add([pscustomobject]@{Name='RecoveryJournalBootstrap';Path=$nonceRoot})
    Assert-FoundationPairwiseRootAuthority -Authorities $nonceAuthorities.ToArray()
    [IO.Directory]::CreateDirectory($nonceRoot) | Out-Null
    $journal = [pscustomobject]@{ Path=$nonceRoot; Identity=(Get-FoundationNativeDirectoryIdentity -LiteralPath $nonceRoot); NextSequence=1; Evidence=$null; Header=$null }
    foreach ($payload in $evidencePayloads) {
        $sha256 = Get-FoundationHostSha256 -Bytes ([byte[]]$payload.Bytes)
        $name = "evidence-$sha256.bin"
        $path = Join-Path $nonceRoot $name
        if (-not [IO.File]::Exists($path)) {
            $stream = [IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $stream.Write($payload.Bytes,0,$payload.Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        }
        $evidence.Add([ordered]@{ key=[string]$payload.Key; name=$name; length=$payload.Bytes.Length; sha256=$sha256 })
    }
    $evidenceManifestBytes = Get-PspktCanonicalJsonBytes -Value ([ordered]@{ schemaVersion=1; schemaId='PspktFoundationRecoveryEvidenceManifestV1'; evidence=$evidence.ToArray() })
    $evidenceManifestName = 'evidence-manifest.v1.json'
    $evidenceManifestPath = Join-Path $nonceRoot $evidenceManifestName
    $evidenceManifestStream = [IO.File]::Open($evidenceManifestPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $evidenceManifestStream.Write($evidenceManifestBytes,0,$evidenceManifestBytes.Length); $evidenceManifestStream.Flush($true) } finally { $evidenceManifestStream.Dispose() }
    $journal.Evidence = $evidence.ToArray()
    $header = [ordered]@{
        schemaVersion=1
        schemaId=$bootstrapContract.RecoveryJournalSchemaId
        baselineOid=$bootstrapContract.BaselineOid
        prestateSha256=$PrestateSha256
        requestedCompletionReceiptPath=$CompletionReceiptPath
        initReceiptPath=$InitReceiptPath
        replayReceiptPath=$ReplayReceiptPath
        initReceiptSha256=(Get-FoundationHostSha256 -Bytes $InitReceiptBytes)
        replayReceiptSha256=(Get-FoundationHostSha256 -Bytes $ReplayReceiptBytes)
        evidenceManifestName=$evidenceManifestName
        evidenceManifestLength=$evidenceManifestBytes.Length
        evidenceManifestSha256=(Get-FoundationHostSha256 -Bytes $evidenceManifestBytes)
        maximumSegments=$bootstrapContract.RecoveryJournalMaximumSegments
        maximumSegmentBytes=$bootstrapContract.RecoveryJournalSegmentMaximumBytes
        evidenceReserveBytes=$bootstrapContract.RecoveryJournalEvidenceReserveBytes
    }
    $journal.Header = $header
    try {
        Publish-FoundationJournalSegment -Journal $journal -Sequence 0 -Kind header -Record $header
        Move-FoundationNativeCreateOnly -Source $nonceRoot -Destination $RecoveryJournalPath
        $journal.Path = $RecoveryJournalPath
        $journal.Identity = Get-FoundationNativeDirectoryIdentity -LiteralPath $RecoveryJournalPath
        return $journal
    }
    catch {
        throw [IO.IOException]::new("Recovery journal bootstrap failed; unpublished artifacts are preserved at $nonceRoot and the journal authority is $RecoveryJournalPath : $($_.Exception.Message)", $_.Exception)
    }
}

function Open-FoundationJournalLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Exclusive
    )

    $path = Assert-FoundationPortablePath -LiteralPath $LiteralPath -Role 'journal directory' -Directory -PassThru
    Assert-FoundationPortablePath -LiteralPath ($path.TrimEnd('\') + '\00000000.header.json') -Role 'journal header lease'
    Assert-FoundationNoReparsePath -LiteralPath $path
    $share = if ($Exclusive) { [IO.FileShare]::None } else { [IO.FileShare]::Read }
    $stream = $null
    try {
        $stream = [IO.File]::Open((Join-Path $path '00000000.header.json'), [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
        if ($stream.Length -gt $bootstrapContract.RecoveryJournalSegmentMaximumBytes) { throw 'Recovery journal header exceeds its hard cap.' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw 'Recovery journal header ended unexpectedly.' }
            $offset += $read
        }
        return [pscustomobject]@{ Path=$path; Stream=$stream; Bytes=$bytes; Exclusive=[bool]$Exclusive; Identity=(Get-FoundationNativeDirectoryIdentity -LiteralPath $path); ValidatedSegments=@{} }
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw [IO.IOException]::new("Cannot acquire recovery journal $path with FileAccess.Read/FileShare.$share : $($_.Exception.Message)", $_.Exception)
    }
}

function Assert-FoundationJournalRecordShape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][string]$Kind
    )

    if (-not (Test-FoundationJsonObject -Value $Record) -or -not (Test-FoundationJsonInteger -Value $Record.schemaVersion -Expected 1)) {
        throw 'Recovery journal record shape is invalid.'
    }
    if ($Kind -ceq 'header') {
        $required = @('schemaVersion','schemaId','baselineOid','prestateSha256','requestedCompletionReceiptPath','initReceiptPath','replayReceiptPath','initReceiptSha256','replayReceiptSha256','evidenceManifestName','evidenceManifestLength','evidenceManifestSha256','maximumSegments','maximumSegmentBytes','evidenceReserveBytes')
        if ($Sequence -ne 0 -or $Record.schemaId -cne $bootstrapContract.RecoveryJournalSchemaId -or
            $Record.baselineOid -cne $bootstrapContract.BaselineOid -or
            $Record.evidenceManifestName -cne 'evidence-manifest.v1.json' -or
            -not (Test-FoundationJsonInteger -Value $Record.maximumSegments -Expected $bootstrapContract.RecoveryJournalMaximumSegments) -or
            -not (Test-FoundationJsonInteger -Value $Record.maximumSegmentBytes -Expected $bootstrapContract.RecoveryJournalSegmentMaximumBytes) -or
            -not (Test-FoundationJsonInteger -Value $Record.evidenceReserveBytes -Expected $bootstrapContract.RecoveryJournalEvidenceReserveBytes) -or
            -not (Test-FoundationJsonIntegerType -Value $Record.evidenceManifestLength) -or $Record.evidenceManifestLength -lt 0 -or
            $Record.evidenceManifestLength -gt $bootstrapContract.RecoveryJournalEvidenceReserveBytes) {
            throw 'Recovery journal header is invalid.'
        }
        foreach ($name in @('prestateSha256','initReceiptSha256','replayReceiptSha256','evidenceManifestSha256')) {
            if ($Record.$name -isnot [string] -or $Record.$name -cnotmatch '^[0-9a-f]{64}$') { throw 'Recovery journal header digest is invalid.' }
        }
        foreach ($name in @('requestedCompletionReceiptPath','initReceiptPath','replayReceiptPath')) {
            if ($Record.$name -is [string]) { Assert-FoundationPortablePath -LiteralPath $Record.$name -Role "journal header $name" }
            if ($Record.$name -isnot [string] -or -not [IO.Path]::IsPathRooted($Record.$name) -or
                [IO.Path]::GetFullPath($Record.$name) -cne $Record.$name) { throw 'Recovery journal header path is invalid.' }
        }
    }
    else {
        $required = @('schemaVersion','sequence','operation',$(if ($Kind -ceq 'intent') { 'details' } else { 'state' }))
        if ($Sequence -eq 0 -or -not (Test-FoundationJsonInteger -Value $Record.sequence -Expected $Sequence) -or
            $Record.operation -isnot [string] -or $Record.operation -cnotin @('TempCreate','TempWrite','Publish','BackupMove','BackupDelete','RollbackDelete','RollbackReceiptDelete','RollbackBackupDelete','TempDelete','DirectoryTempCreate','DirectoryPublish','DirectoryDelete','ReadyToCommit','RolledBack','CompletionPathSelection')) {
            throw 'Recovery journal operation or sequence is invalid.'
        }
        if ($Kind -ceq 'intent') {
            if (-not (Test-FoundationJsonObject -Value $Record.details)) { throw 'Recovery journal Intent details are invalid.' }
            $detailProperties = switch ([string]$Record.operation) {
                'TempCreate' { @('tempPath','destination','evidenceKey','expectedLength','expectedSha256') }
                'TempWrite' { @('tempPath','identity','evidenceKey','expectedLength','expectedSha256') }
                'Publish' { @('tempPath','tempIdentity','destination','evidenceKey','expectedLength','expectedSha256') }
                'BackupMove' { @('source','destination','expectedIdentity','expectedLength','expectedSha256','relativePath') }
                'DirectoryTempCreate' { @('tempPath','destination') }
                'DirectoryPublish' { @('tempPath','identity','destination') }
                'DirectoryDelete' { @('path','identity') }
                'CompletionPathSelection' { @('destination','collidedPath') }
                { $_ -cin @('ReadyToCommit','RolledBack') } { @('phase') }
                default { @('path','identity','length','sha256') }
            }
            if (-not (Test-FoundationOrdinalStringSetEquality -Expected $detailProperties -Actual @($Record.details.PSObject.Properties.Name))) { throw 'Recovery journal Intent property set is invalid.' }
            foreach ($property in $Record.details.PSObject.Properties) {
                if ($property.Name -cin @('path','tempPath','destination','source','collidedPath') -and $property.Value -is [string]) {
                    Assert-FoundationPortablePath -LiteralPath $property.Value -Role "journal $($Record.operation) $($property.Name)" -Directory:($Record.operation -cin @('DirectoryTempCreate','DirectoryPublish','DirectoryDelete'))
                }
                if ($property.Name -cin @('length','expectedLength')) {
                    if (-not (Test-FoundationJsonIntegerType -Value $property.Value) -or $property.Value -lt 0 -or $property.Value -gt $bootstrapContract.GeneratedOutputFileMaximumBytes) { throw 'Recovery journal Intent length is invalid.' }
                }
                elseif ($property.Value -isnot [string] -or [string]::IsNullOrEmpty($property.Value)) { throw 'Recovery journal Intent string is invalid.' }
                elseif ($property.Name -cin @('sha256','expectedSha256') -and $property.Value -cnotmatch '^[0-9a-f]{64}$') { throw 'Recovery journal Intent digest is invalid.' }
                elseif ($property.Name -cin @('identity','expectedIdentity','tempIdentity') -and $property.Value -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$') { throw 'Recovery journal Intent identity is invalid.' }
            }
            if ($Record.operation -cin @('ReadyToCommit','RolledBack') -and $Record.details.phase -cne $Record.operation) { throw 'Recovery journal phase mismatch.' }
        }
        elseif (-not (Test-FoundationJsonObject -Value $Record.state)) { throw 'Recovery journal terminal state is invalid.' }
        else {
            $state = $Record.state
            $properties = @($state.PSObject.Properties.Name)
            $valid = $false
            foreach ($shape in @(
                ,@('Path','Identity','Length','Sha256')
                ,@('identity')
                ,@('absent')
                ,@('satisfied')
                ,@('unverified')
                ,@('destination')
                ,@('path','foreign')
                ,@('incomplete','ownershipSequence','observed')
            )) {
                if (Test-FoundationOrdinalStringSetEquality -Expected $shape -Actual $properties) { $valid = $true; break }
            }
            if (-not $valid) { throw 'Recovery journal terminal property set is invalid.' }
            if ($properties -ccontains 'incomplete' -and ($Record.operation -cne 'TempWrite' -or $Kind -cne 'not-applied' -or
                $state.incomplete -isnot [bool] -or -not $state.incomplete -or -not (Test-FoundationJsonIntegerType -Value $state.ownershipSequence) -or
                $state.ownershipSequence -le 0 -or $state.ownershipSequence -ge $Sequence -or
                -not (Test-FoundationOrdinalStringSetEquality -Expected @('Path','Identity','Length','Sha256') -Actual @($state.observed.PSObject.Properties.Name)))) { throw 'Recovery journal incomplete snapshot is invalid.' }
            $snapshot = if ($properties -ccontains 'incomplete') { $state.observed } else { $state }
            if ($null -ne $snapshot.PSObject.Properties['Length'] -and
                (-not (Test-FoundationJsonIntegerType -Value $snapshot.Length) -or $snapshot.Length -lt 0 -or
                $snapshot.Sha256 -isnot [string] -or $snapshot.Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $snapshot.Identity -isnot [string] -or $snapshot.Identity -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$' -or
                $snapshot.Path -isnot [string] -or -not [IO.Path]::IsPathRooted($snapshot.Path))) { throw 'Recovery journal file snapshot is invalid.' }
            foreach ($flag in @('absent','satisfied','unverified','foreign')) {
                if ($properties -ccontains $flag -and $state.$flag -isnot [bool]) { throw 'Recovery journal terminal flag is invalid.' }
            }
            if ($properties -ccontains 'identity' -and ($state.identity -isnot [string] -or $state.identity -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$')) { throw 'Recovery journal directory snapshot is invalid.' }
            if ($properties -ccontains 'destination' -and ($state.destination -isnot [string] -or -not [IO.Path]::IsPathRooted($state.destination))) { throw 'Recovery journal terminal destination is invalid.' }
            if ($Kind -ceq 'applied') {
                $appliedProperties = switch ([string]$Record.operation) {
                    { $_ -cin @('TempCreate','TempWrite','Publish','BackupMove') } { @('Path','Identity','Length','Sha256') }
                    { $_ -cin @('DirectoryTempCreate','DirectoryPublish') } { @('identity') }
                    { $_ -cin @('ReadyToCommit','RolledBack') } { @('satisfied') }
                    'CompletionPathSelection' { @('destination') }
                    default { @('absent') }
                }
                if (-not (Test-FoundationOrdinalStringSetEquality -Expected $appliedProperties -Actual $properties) -or
                    ($properties -ccontains 'satisfied' -and -not $state.satisfied) -or
                    ($properties -ccontains 'absent' -and -not $state.absent)) { throw 'Recovery journal Applied record does not prove its operation.' }
            }
        }
    }
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected $required -Actual @($Record.PSObject.Properties.Name))) {
        throw 'Recovery journal record property set is invalid.'
    }
}

function Read-FoundationRecoveryJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        $Lease
    )

    Assert-FoundationPortablePath -LiteralPath $LiteralPath -Role 'journal directory' -Directory
    Assert-FoundationPortablePath -LiteralPath ($LiteralPath.TrimEnd('\') + '\evidence-' + ('0' * 64) + '.bin') -Role 'journal evidence'
    if (-not [IO.Directory]::Exists($LiteralPath)) { throw 'Recovery journal is required.' }
    Assert-FoundationNoReparsePath -LiteralPath $LiteralPath
    $ownsLease = $null -eq $Lease
    if ($ownsLease) { $Lease = Open-FoundationJournalLease -LiteralPath $LiteralPath }
    try {
    if ($Lease.Path -cne [IO.Path]::GetFullPath($LiteralPath) -or -not $Lease.Stream.CanRead -or
        $Lease.Identity -cne (Get-FoundationNativeDirectoryIdentity -LiteralPath $LiteralPath)) { throw 'Recovery journal lease does not match the journal.' }
    $files = @(Get-ChildItem -LiteralPath $LiteralPath -Force)
    $segmentFiles = @($files | Where-Object { $_.Name -cmatch '^[0-9]{8}\.(header|intent|applied|not-applied|conflict)\.json$' })
    if ($segmentFiles.Count -gt $bootstrapContract.RecoveryJournalMaximumSegments) { throw 'Recovery journal segment count exceeds its hard cap.' }
    $total = [int64]0
    $evidenceTotal = [int64]0
    $segments = [Collections.Generic.List[object]]::new()
    foreach ($file in $files) {
        Assert-FoundationPortablePath -LiteralPath $file.FullName -Role 'discovered journal entry' -Directory:$file.PSIsContainer
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unknown recovery journal entry: $($file.Name)" }
        if ($file.Name -cmatch '^\.pspkt-(segment|content)-[0-9a-f]{32}\.tmp$') {
            $total += $file.Length
            if ($total -gt $bootstrapContract.RecoveryJournalMaximumBytes) { throw 'Recovery journal exceeds its hard cap.' }
            continue
        }
        if ($file.Name -like 'evidence-*.bin' -or $file.Name -ceq 'evidence-manifest.v1.json') {
            $evidenceTotal += $file.Length
            $total += $file.Length
            if ($evidenceTotal -gt $bootstrapContract.RecoveryJournalEvidenceReserveBytes -or $total -gt $bootstrapContract.RecoveryJournalMaximumBytes) {
                throw 'Recovery journal evidence exceeds its reserved capacity.'
            }
            continue
        }
        if ($file.Name -cnotmatch '^([0-9]{8})\.(header|intent|applied|not-applied|conflict)\.json$') { throw "Unknown recovery journal record: $($file.Name)" }
        $sequence = [int]$matches[1]
        $kind = [string]$matches[2]
        if ($file.Length -gt $bootstrapContract.RecoveryJournalSegmentMaximumBytes) { throw 'Recovery journal segment exceeds its hard cap.' }
        $total += $file.Length
        if ($total -gt $bootstrapContract.RecoveryJournalMaximumBytes) { throw 'Recovery journal exceeds its hard cap.' }
        $bytes = if ($sequence -eq 0 -and $kind -ceq 'header') { $Lease.Bytes } else { [IO.File]::ReadAllBytes($file.FullName) }
        $hash = Get-FoundationHostSha256 -Bytes $bytes
        $record = ConvertFrom-FoundationStrictUtf8 -Bytes $bytes | ConvertFrom-Json
        if ($Lease.ValidatedSegments[$file.Name] -cne $hash) {
            if (-not (Test-FoundationByteArrayEquality -Left $bytes -Right (Get-PspktCanonicalJsonBytes -Value $record))) { throw "Recovery journal segment is not canonical: $($file.Name)" }
            Assert-FoundationJournalRecordShape -Record $record -Sequence $sequence -Kind $kind
            $Lease.ValidatedSegments[$file.Name] = $hash
        }
        $segments.Add([pscustomobject]@{ Name=$file.Name; Sequence=$sequence; Kind=$kind; Record=$record; Length=$bytes.Length; Sha256=$hash })
    }
    $header = @($segments | Where-Object { $_.Sequence -eq 0 -and $_.Kind -ceq 'header' })
    if ($header.Count -ne 1 -or [string]$header[0].Record.schemaId -cne $bootstrapContract.RecoveryJournalSchemaId) { throw 'Recovery journal header is invalid.' }
    $operations = [Collections.Generic.List[object]]::new()
    $maximum = 0
    $intentsBySequence = @{}
    $terminalsBySequence = @{}
    foreach ($segment in $segments) {
        if ($segment.Sequence -gt $maximum) { $maximum = $segment.Sequence }
        if ($segment.Kind -ceq 'intent') {
            if ($intentsBySequence.ContainsKey($segment.Sequence)) { throw "Recovery journal continuity failed at sequence $($segment.Sequence)." }
            $intentsBySequence[$segment.Sequence] = $segment
        }
        elseif ($segment.Kind -cne 'header') {
            if ($terminalsBySequence.ContainsKey($segment.Sequence)) { throw "Recovery journal continuity failed at sequence $($segment.Sequence)." }
            $terminalsBySequence[$segment.Sequence] = $segment
        }
    }
    for ($sequence = 1; $sequence -le $maximum; $sequence++) {
        $intent = $intentsBySequence[$sequence]
        $terminal = $terminalsBySequence[$sequence]
        if ($null -eq $intent) { throw "Recovery journal continuity failed at sequence $sequence." }
        if ($null -ne $terminal -and $terminal.Record.operation -cne $intent.Record.operation) { throw "Recovery journal terminal operation mismatch at sequence $sequence." }
        $operations.Add([pscustomobject]@{ Sequence=$sequence; Intent=$intent; Terminal=$terminal })
    }
    $evidenceManifestPath = Join-Path $LiteralPath ([string]$header[0].Record.evidenceManifestName)
    $evidenceManifestItem = Get-Item -LiteralPath $evidenceManifestPath -Force
    $evidenceManifestBytes = [IO.File]::ReadAllBytes($evidenceManifestPath)
    if ($evidenceManifestItem.Length -ne [int64]$header[0].Record.evidenceManifestLength -or
        (Get-FoundationHostSha256 -Bytes $evidenceManifestBytes) -cne [string]$header[0].Record.evidenceManifestSha256) {
        throw 'Recovery journal evidence manifest is invalid.'
    }
    $evidenceManifest = ConvertFrom-FoundationStrictUtf8 -Bytes $evidenceManifestBytes | ConvertFrom-Json
    if (-not (Test-FoundationByteArrayEquality -Left $evidenceManifestBytes -Right (Get-PspktCanonicalJsonBytes -Value $evidenceManifest)) -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected @('schemaVersion','schemaId','evidence') -Actual @($evidenceManifest.PSObject.Properties.Name)) -or
        -not (Test-FoundationJsonInteger -Value $evidenceManifest.schemaVersion -Expected 1) -or
        $evidenceManifest.schemaId -cne 'PspktFoundationRecoveryEvidenceManifestV1') { throw 'Recovery journal evidence manifest shape is invalid.' }
    $evidenceNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $evidenceKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $evidenceFiles = @{}
    foreach ($record in $evidenceManifest.evidence) {
        if (-not (Test-FoundationOrdinalStringSetEquality -Expected @('key','name','length','sha256') -Actual @($record.PSObject.Properties.Name)) -or
            -not (Test-FoundationJsonIntegerType -Value $record.length) -or $record.length -lt 0 -or
            $record.sha256 -isnot [string] -or $record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $record.key -isnot [string] -or -not $evidenceKeys.Add([string]$record.key) -or $record.name -isnot [string] -or [string]$record.name -cne "evidence-$($record.sha256).bin") {
            throw 'Recovery journal evidence manifest contains an invalid record.'
        }
        [void]$evidenceNames.Add([string]$record.name)
        $evidencePath = Join-Path $LiteralPath ([string]$record.name)
        if (-not $evidenceFiles.ContainsKey([string]$record.name)) {
            $evidenceItem = Get-Item -LiteralPath $evidencePath -Force
            $evidenceFiles[[string]$record.name] = [pscustomobject]@{Length=$evidenceItem.Length;Sha256=(Get-FoundationFileSha -LiteralPath $evidencePath)}
        }
        $evidenceFile = $evidenceFiles[[string]$record.name]
        if ($evidenceFile.Length -ne [int64]$record.length -or $evidenceFile.Sha256 -cne [string]$record.sha256) {
            throw 'Recovery journal evidence record does not match its file.'
        }
    }
    foreach ($file in Get-ChildItem -LiteralPath $LiteralPath -Filter 'evidence-*.bin' -File -Force) {
        if (-not $evidenceNames.Contains($file.Name)) { throw "Recovery journal contains unknown evidence: $($file.Name)" }
    }
    return [pscustomobject]@{
        Path=[IO.Path]::GetFullPath($LiteralPath)
        Identity=(Get-FoundationNativeDirectoryIdentity -LiteralPath $LiteralPath)
        Header=$header[0].Record
        Evidence=@($evidenceManifest.evidence)
        Segments=@($segments | Sort-Object Sequence,Kind)
        Operations=$operations
        NextSequence=$maximum + 1
        Lease=$Lease
        Recovery=$false
        RecoveryAction=''
    }
    }
    catch {
        if ($ownsLease) { $Lease.Stream.Dispose() }
        throw
    }
}

function Get-FoundationJournalEvidenceBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $record = @($Journal.Evidence | Where-Object { [string]$_.key -ceq $Key })
    if ($record.Count -ne 1) { throw "Recovery journal evidence is missing: $Key" }
    $path = Join-Path $Journal.Path ([string]$record[0].name)
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Length -ne [int64]$record[0].length -or $item.Length -gt $bootstrapContract.GeneratedOutputFileMaximumBytes) { throw "Recovery journal evidence length mismatch: $Key" }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ((Get-FoundationHostSha256 -Bytes $bytes) -cne [string]$record[0].sha256) { throw "Recovery journal evidence hash mismatch: $Key" }
    return ,$bytes
}

function Get-FoundationJournalContentBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$EvidenceKey
    )

    if ($EvidenceKey -cne '__completion-receipt') {
        return ,(Get-FoundationJournalEvidenceBytes -Journal $Journal -Key $EvidenceKey)
    }
    $replayBytes = Get-FoundationJournalEvidenceBytes -Journal $Journal -Key '__replay-receipt'
    $replayReceipt = ConvertFrom-FoundationStrictUtf8 -Bytes $replayBytes | ConvertFrom-Json
    return ,(Get-PspktCanonicalJsonBytes -Value ([ordered]@{
        schemaVersion=1
        schemaId=$bootstrapContract.CompletionReceiptSchemaId
        prestateSha256=[string]$Journal.Header.prestateSha256
        readyJournalSha256=(Get-FoundationReadyJournalSha256 -Journal $Journal)
        initReceiptSha256=[string]$Journal.Header.initReceiptSha256
        replayReceiptSha256=[string]$Journal.Header.replayReceiptSha256
        candidateTreeOid=[string]$replayReceipt.candidateTreeOid
        mapBlobOid=[string]$replayReceipt.mapBlobOid
    }))
}

function Get-FoundationOperationOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)]$Details,
        [int]$Sequence,
        $ObservedState
    )

    $kind = 'not-applied'
    $state = [ordered]@{ absent=$true }
    $filePath = $null
    switch ($Operation) {
        { $_ -cin @('TempCreate','TempWrite') } { $filePath = [string]$Details.tempPath }
        { $_ -cin @('Publish','BackupMove') } { $filePath = [string]$Details.destination }
        { $_ -cin @('BackupDelete','RollbackDelete','RollbackReceiptDelete','RollbackBackupDelete','TempDelete') } { $filePath = [string]$Details.path }
    }
    if ($null -ne $filePath) {
        $exists = Test-Path -LiteralPath $filePath
        $deleting = $Operation -cin @('BackupDelete','RollbackDelete','RollbackReceiptDelete','RollbackBackupDelete','TempDelete')
        if (-not $exists) {
            if ($deleting) { $kind = 'applied' }
        }
        elseif (-not [IO.File]::Exists($filePath)) {
            $kind = 'conflict'
            $state = [ordered]@{ path=$filePath; foreign=$true }
        }
        else {
            $state = Get-FoundationOwnedFileRecord -LiteralPath $filePath
            $identity = switch ($Operation) {
                'TempCreate' { $state.Identity }
                'Publish' { [string]$Details.tempIdentity }
                'BackupMove' { [string]$Details.expectedIdentity }
                default { [string]$Details.identity }
            }
            $length = if ($deleting) { [int64]$Details.length } else { [int64]$Details.expectedLength }
            $hash = if ($deleting) { [string]$Details.sha256 } else { [string]$Details.expectedSha256 }
            if ($state.Identity -cne $identity) { $kind = 'conflict' }
            elseif ($state.Length -eq $length -and $state.Sha256 -ceq $hash) {
                $kind = if ($deleting) { 'not-applied' } else { 'applied' }
            }
            elseif ($Operation -ceq 'TempWrite') {
                $owner = @($Journal.Operations | Where-Object {
                    $_.Sequence -lt $Sequence -and $_.Intent.Record.operation -ceq 'TempCreate' -and
                    $_.Intent.Record.details.tempPath -ceq $filePath -and $null -ne $_.Terminal -and
                    $_.Terminal.Kind -ceq 'applied' -and $_.Terminal.Record.state.Identity -ceq $identity
                })
                if ($owner.Count -eq 1) {
                    $kind = 'not-applied'
                    if ($state.Length -ne $owner[0].Terminal.Record.state.Length -or $state.Sha256 -cne $owner[0].Terminal.Record.state.Sha256) {
                        $state = [ordered]@{ incomplete=$true; ownershipSequence=$owner[0].Sequence; observed=$state }
                    }
                }
                else { $kind = 'conflict' }
            }
            else { $kind = 'conflict' }
        }
    }
    elseif ($Operation -cin @('DirectoryTempCreate','DirectoryPublish','DirectoryDelete')) {
        $path = if ($Operation -ceq 'DirectoryTempCreate') { [string]$Details.tempPath } elseif ($Operation -ceq 'DirectoryPublish') { [string]$Details.destination } else { [string]$Details.path }
        if ([IO.Directory]::Exists($path)) {
            $state = [ordered]@{ identity=(Get-FoundationNativeDirectoryIdentity -LiteralPath $path) }
            if ($Operation -ceq 'DirectoryTempCreate' -or $state.identity -ceq [string]$Details.identity) {
                $kind = if ($Operation -ceq 'DirectoryDelete') { 'not-applied' } else { 'applied' }
            }
            else { $kind = 'conflict' }
        }
        elseif (Test-Path -LiteralPath $path) {
            $kind = 'conflict'
            $state = [ordered]@{ path=$path; foreign=$true }
        }
        elseif ($Operation -ceq 'DirectoryDelete') { $kind = 'applied' }
    }
    elseif ($Operation -ceq 'CompletionPathSelection') {
        $kind = if (Test-Path -LiteralPath ([string]$Details.destination)) { 'conflict' } else { 'applied' }
        $state = [ordered]@{ destination=[string]$Details.destination }
    }
    elseif ($Operation -cin @('ReadyToCommit','RolledBack')) {
        try {
            if ($PSBoundParameters.ContainsKey('ObservedState')) {
                $satisfied = $null -ne $ObservedState -and [bool]$ObservedState.satisfied
            }
            elseif ($Operation -ceq 'ReadyToCommit') {
                $receipt = ConvertFrom-FoundationStrictUtf8 -Bytes (Get-FoundationJournalEvidenceBytes -Journal $Journal -Key '__replay-receipt') | ConvertFrom-Json
                $satisfied = Test-FoundationReadyPredicate -Prestate $prestate -ReplayReceipt $receipt -Journal $Journal -BeforeSequence $Sequence
            }
            else {
                Assert-FoundationRolledBackState -Prestate $prestate -Journal $Journal -BeforeSequence $Sequence
                $satisfied = $true
            }
        }
        catch [Management.Automation.RuntimeException] {
            $satisfied = $false
            $kind = 'conflict'
        }
        $state = [ordered]@{ satisfied=[bool]$satisfied }
        if ($satisfied) { $kind = 'applied' }
    }
    else { throw "Unknown recovery journal operation: $Operation" }
    if ($kind -ceq 'applied' -and $PSBoundParameters.ContainsKey('ObservedState')) {
        if ($null -eq $ObservedState) {
            $kind = 'not-applied'
            $state = [ordered]@{ unverified=$true }
        }
        elseif ((Get-FoundationCanonicalHash -Value $ObservedState) -cne (Get-FoundationCanonicalHash -Value $state)) {
            $kind = 'conflict'
        }
    }
    return [pscustomobject]@{ Kind=$kind; State=$state }
}

function Publish-FoundationOperationTerminal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)]$Record
    )

    try {
        Publish-FoundationJournalSegment -Journal $Journal -Sequence $Sequence -Kind $Kind -Record $Record
    }
    catch {
        $publicationError = $_.Exception
        try { $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease }
        catch {
            throw [AggregateException]::new("Terminal publication and verification failed; recovery journal: $($Journal.Path)", [Exception[]]@($publicationError, $_.Exception))
        }
        $existing = @($fresh.Operations | Where-Object { $_.Sequence -eq $Sequence -and $null -ne $_.Terminal })
        if ($existing.Count -ne 1 -or $existing[0].Terminal.Kind -cne $Kind -or
            (Get-FoundationCanonicalHash -Value $existing[0].Terminal.Record) -cne (Get-FoundationCanonicalHash -Value $Record)) {
            throw [IO.IOException]::new("Terminal publication could not be verified in recovery journal $($Journal.Path): $($publicationError.Message)", $publicationError)
        }
    }
}

function Invoke-FoundationJournalOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)]$Details,
        [Parameter(Mandatory = $true)][scriptblock]$Mutation,
        [Parameter(Mandatory = $true)][scriptblock]$AppliedState
    )

    Assert-FoundationJournalAdmission -Journal $Journal -Operation $Operation -Details $Details
    $sequence = $Journal.NextSequence
    Publish-FoundationJournalSegment -Journal $Journal -Sequence $sequence -Kind intent -Record ([ordered]@{ schemaVersion=1; sequence=$sequence; operation=$Operation; details=$Details })
    $Journal.NextSequence++
    if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_CRASH_POINT') -ceq "after-intent:$Operation") { throw "Injected crash after intent: $Operation" }
    $mutationError = $null
    try {
        & $Mutation
    }
    catch {
        if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_CRASH_POINT')) { throw }
        $mutationError = $_.Exception
    }
    if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_CRASH_POINT') -ceq "after-mutation:$Operation") { throw "Injected crash after mutation: $Operation" }
    $classificationError = $null
    try { $state = & $AppliedState }
    catch [Management.Automation.RuntimeException] {
        if ($Operation -cnotin @('ReadyToCommit','RolledBack')) { throw }
        $classificationError = $_.Exception
        $state = [ordered]@{satisfied=$false}
    }
    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    $outcome = Get-FoundationOperationOutcome -Journal $fresh -Operation $Operation -Details $Details -Sequence $sequence -ObservedState $state
    if ($null -ne $classificationError) { $outcome.Kind = 'conflict' }
    Publish-FoundationOperationTerminal -Journal $Journal -Sequence $sequence -Kind $outcome.Kind -Record ([ordered]@{ schemaVersion=1; sequence=$sequence; operation=$Operation; state=$outcome.State })
    if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_CRASH_POINT') -ceq "after-terminal:$Operation") { throw "Injected crash after terminal: $Operation" }
    if ($null -ne $mutationError) { throw $mutationError }
    if ($null -ne $classificationError) { throw $classificationError }
    if ($outcome.Kind -cne 'applied') { throw [IO.IOException]::new("Operation $Operation was $($outcome.Kind); recovery journal: $($Journal.Path)") }
    return [pscustomobject]@{ Sequence=$sequence; State=$outcome.State }
}

function Publish-FoundationJournaledFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$EvidenceKey
    )

    Assert-FoundationPortablePath -LiteralPath $Destination -Role 'publication destination'
    $expectedHash = Get-FoundationHostSha256 -Bytes $Bytes
    $temporary = Join-Path $Journal.Path ('.pspkt-content-' + [guid]::NewGuid().ToString('N') + '.tmp')
    Assert-FoundationPortablePath -LiteralPath $temporary -Role 'publication content temporary'
    $create = Invoke-FoundationJournalOperation -Journal $Journal -Operation 'TempCreate' -Details ([ordered]@{ tempPath=$temporary; destination=$Destination; evidenceKey=$EvidenceKey; expectedLength=0; expectedSha256=(Get-FoundationHostSha256 -Bytes ([byte[]]::new(0))) }) -Mutation {
        $stream = [IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Flush($true) } finally { $stream.Dispose() }
    } -AppliedState {
        if (-not [IO.File]::Exists($temporary)) { return $null }
        return Get-FoundationOwnedFileRecord -LiteralPath $temporary
    }

    $identity = [string]$create.State.Identity
    [void](Invoke-FoundationJournalOperation -Journal $Journal -Operation 'TempWrite' -Details ([ordered]@{ tempPath=$temporary; identity=$identity; evidenceKey=$EvidenceKey; expectedLength=$Bytes.Length; expectedSha256=$expectedHash }) -Mutation {
        $identityPin = [IO.File]::Open($temporary,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $stream = $null
        try {
            if ((Get-FoundationNativeFileIdentity -LiteralPath $temporary) -cne $identity) { throw [IO.IOException]::new('Journal temp identity changed before write.') }
            $stream = [IO.File]::Open($temporary,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            if ($identityPin.Length -ne 0) { throw [IO.IOException]::new('Journal temp changed after its empty ownership snapshot.') }
            $stream.SetLength(0)
            $fault = [Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_CRASH_POINT')
            if ($fault -ceq 'during-mutation:TempWrite' -and $Bytes.Length -gt 1) {
                $stream.Write($Bytes,0,[Math]::Floor($Bytes.Length / 2))
                $stream.Flush($true)
                throw 'Injected crash during TempWrite.'
            }
            $stream.Write($Bytes,0,$Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            if ($null -ne $stream) { $stream.Dispose() }
            $identityPin.Dispose()
        }
    } -AppliedState {
        if (-not [IO.File]::Exists($temporary) -or (Get-FoundationNativeFileIdentity -LiteralPath $temporary) -cne $identity) { return $null }
        $record = Get-FoundationOwnedFileRecord -LiteralPath $temporary
        if ($record.Length -ne $Bytes.Length -or $record.Sha256 -cne $expectedHash) { return $null }
        return $record
    })
    return Invoke-FoundationJournalOperation -Journal $Journal -Operation 'Publish' -Details ([ordered]@{ tempPath=$temporary; tempIdentity=$identity; destination=$Destination; evidenceKey=$EvidenceKey; expectedLength=$Bytes.Length; expectedSha256=$expectedHash }) -Mutation {
        $record = [pscustomobject]@{Path=$temporary;Identity=$identity;Length=$Bytes.Length;Sha256=$expectedHash}
        Move-FoundationNativeOwnedFileCreateOnly -Source $temporary -Destination $Destination -Record $record
    } -AppliedState {
        if (-not [IO.File]::Exists($Destination)) { return $null }
        $record = Get-FoundationOwnedFileRecord -LiteralPath $Destination
        if ($record.Length -ne $Bytes.Length -or $record.Sha256 -cne $expectedHash) { return $record }
        return $record
    }
}

function Ensure-FoundationJournaledDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )

    Assert-FoundationPortablePath -LiteralPath $LiteralPath -Role 'publication directory' -Directory
    $directory = $LiteralPath
    while (-not [IO.Directory]::Exists($directory)) {
        if ([IO.File]::Exists($directory)) { throw "Unsupported transaction layout: directory '$LiteralPath' has a file ancestor '$directory'." }
        $parentDirectory = Split-Path -Parent $directory
        if ([string]::IsNullOrEmpty($parentDirectory) -or $parentDirectory -ceq $directory) { throw "Unsupported transaction layout: directory '$LiteralPath' has no existing directory ancestor." }
        $plannedNonce = $parentDirectory.TrimEnd('\') + '\.' + (Split-Path -Leaf $directory) + '.pspkt-dir-' + ('0' * 32)
        Assert-FoundationPortablePath -LiteralPath $plannedNonce -Role 'publication directory temporary' -Directory
        $directory = $parentDirectory
    }
    if ([IO.Directory]::Exists($LiteralPath)) {
        Assert-FoundationNoReparsePath -LiteralPath $LiteralPath
        return
    }
    $parent = Split-Path -Parent $LiteralPath
    if (-not [IO.Directory]::Exists($parent)) {
        Ensure-FoundationJournaledDirectory -Journal $Journal -LiteralPath $parent
    }
    $nonceDirectory = Join-Path $parent ('.' + (Split-Path -Leaf $LiteralPath) + '.pspkt-dir-' + [guid]::NewGuid().ToString('N'))
    $created = Invoke-FoundationJournalOperation -Journal $Journal -Operation 'DirectoryTempCreate' -Details ([ordered]@{ tempPath=$nonceDirectory; destination=$LiteralPath }) -Mutation {
        [IO.Directory]::CreateDirectory($nonceDirectory) | Out-Null
    } -AppliedState {
        if ([IO.Directory]::Exists($nonceDirectory)) { return [ordered]@{ identity=(Get-FoundationNativeDirectoryIdentity -LiteralPath $nonceDirectory) } }
        return $null
    }
    $directoryIdentity = [string]$created.State.identity
    [void](Invoke-FoundationJournalOperation -Journal $Journal -Operation 'DirectoryPublish' -Details ([ordered]@{ tempPath=$nonceDirectory; identity=$directoryIdentity; destination=$LiteralPath }) -Mutation {
        Move-FoundationNativeCreateOnly -Source $nonceDirectory -Destination $LiteralPath
    } -AppliedState {
        if ([IO.Directory]::Exists($LiteralPath)) { return [ordered]@{ identity=(Get-FoundationNativeDirectoryIdentity -LiteralPath $LiteralPath) } }
        return $null
    })
}

function Publish-FoundationJournaledPhase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][ValidateSet('ReadyToCommit','RolledBack')][string]$Phase,
        [Parameter(Mandatory = $true)][scriptblock]$Predicate
    )

    return Invoke-FoundationJournalOperation -Journal $Journal -Operation $Phase -Details ([ordered]@{ phase=$Phase }) -Mutation {
        if (-not (& $Predicate)) { throw [IO.IOException]::new("$Phase predicate is not satisfied.") }
    } -AppliedState {
        if (& $Predicate) { return [ordered]@{ satisfied=$true } }
        return $null
    }
}

function Get-FoundationReadyJournalSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Journal)

    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    $ready = @($fresh.Operations | Where-Object { $_.Intent.Record.operation -ceq 'ReadyToCommit' -and $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied' })
    if ($ready.Count -ne 1) { throw 'Recovery journal does not contain exactly one applied ReadyToCommit phase.' }
    $prefix = @($fresh.Segments | Where-Object { $_.Sequence -le $ready[0].Sequence } | Sort-Object Sequence,Kind | ForEach-Object {
        [ordered]@{ name=$_.Name; length=$_.Length; sha256=$_.Sha256 }
    })
    return Get-FoundationCanonicalHash -Value $prefix
}

function Test-FoundationCompletionReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$ReturnDocument
    )

    if (-not [IO.File]::Exists($LiteralPath)) { return $false }
    try {
        $binding = New-FoundationFileBinding -LiteralPath $LiteralPath -Role 'authority:completion-receipt'
        try {
            $document = ConvertFrom-FoundationStrictUtf8 -Bytes ([byte[]]$binding.Bytes) | ConvertFrom-Json
            if (-not (Test-FoundationByteArrayEquality -Left ([byte[]]$binding.Bytes) -Right (Get-PspktCanonicalJsonBytes -Value $document))) { return $false }
            $required = @('candidateTreeOid','initReceiptSha256','mapBlobOid','prestateSha256','readyJournalSha256','replayReceiptSha256','schemaId','schemaVersion')
            if (-not (Test-FoundationOrdinalStringSetEquality -Expected $required -Actual ([string[]]@($document.PSObject.Properties.Name))) -or
                -not (Test-FoundationJsonInteger -Value $document.schemaVersion -Expected 1) -or
                [string]$document.schemaId -cne $bootstrapContract.CompletionReceiptSchemaId -or
                [string]$document.prestateSha256 -cne [string]$Journal.Header.prestateSha256 -or
                [string]$document.initReceiptSha256 -cne [string]$Journal.Header.initReceiptSha256 -or
                [string]$document.replayReceiptSha256 -cne [string]$Journal.Header.replayReceiptSha256 -or
                [string]$document.readyJournalSha256 -cne (Get-FoundationReadyJournalSha256 -Journal $Journal)) {
                return $false
            }
            $publish = @($Journal.Operations | Where-Object {
                $_.Intent.Record.operation -ceq 'Publish' -and
                [string]$_.Intent.Record.details.destination -ceq [IO.Path]::GetFullPath($LiteralPath) -and
                $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied'
            })
            if ($publish.Count -ne 1 -or [string]$publish[0].Intent.Record.details.expectedSha256 -cne $binding.Sha256 -or
                [string]$publish[0].Intent.Record.details.tempIdentity -cne $binding.Identity) { return $false }
            if ($ReturnDocument) { return $document }
            return $true
        }

        finally { $binding.Stream.Dispose() }
    }
    catch { return $false }
}

function Read-FoundationInitReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$PrestateSha256
    )

    $document = ConvertFrom-FoundationStrictUtf8 -Bytes ([byte[]]$Binding.Bytes) | ConvertFrom-Json
    $required = @('baselineOid','catalogSha256','nonce','prestateSha256','schemaId','schemaVersion')
    if (-not (Test-FoundationByteArrayEquality -Left ([byte[]]$Binding.Bytes) -Right (Get-PspktCanonicalJsonBytes -Value $document)) -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected $required -Actual ([string[]]@($document.PSObject.Properties.Name))) -or
        -not (Test-FoundationJsonInteger -Value $document.schemaVersion -Expected 1) -or
        [string]$document.schemaId -cne $bootstrapContract.InitReceiptSchemaId -or
        [string]$document.baselineOid -cne $bootstrapContract.BaselineOid -or
        [string]$document.prestateSha256 -cne $PrestateSha256 -or
        [string]$document.catalogSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$document.nonce -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Init receipt validation failed.'
    }
    return $document
}

function Read-FoundationReplayReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [Parameter(Mandatory = $true)][string]$PrestateSha256,
        [Parameter(Mandatory = $true)][string]$InitReceiptSha256
    )

    $document = ConvertFrom-FoundationStrictUtf8 -Bytes ([byte[]]$Binding.Bytes) | ConvertFrom-Json
    $required = @('baselineOid','candidateTreeOid','catalogSha256','initReceiptSha256','inputHashes','mapBlobOid','mapSha256','outputHashes','prestateSha256','schemaId','schemaSha256','schemaVersion')
    $inputNames = if (Test-FoundationJsonObject -Value $document.inputHashes) { [string[]]@($document.inputHashes.PSObject.Properties.Name) } else { @() }
    $outputNames = if (Test-FoundationJsonObject -Value $document.outputHashes) { [string[]]@($document.outputHashes.PSObject.Properties.Name) } else { @() }
    if (-not (Test-FoundationByteArrayEquality -Left ([byte[]]$Binding.Bytes) -Right (Get-PspktCanonicalJsonBytes -Value $document)) -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected $required -Actual ([string[]]@($document.PSObject.Properties.Name))) -or
        -not (Test-FoundationJsonInteger -Value $document.schemaVersion -Expected 2) -or
        [string]$document.schemaId -cne $bootstrapContract.ReplayReceiptSchemaId -or
        [string]$document.baselineOid -cne $bootstrapContract.BaselineOid -or
        [string]$document.prestateSha256 -cne $PrestateSha256 -or
        [string]$document.initReceiptSha256 -cne $InitReceiptSha256 -or
        [string]$document.candidateTreeOid -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$document.mapBlobOid -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.InputPathSet) -Actual $inputNames) -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.OutputPathSet) -Actual $outputNames)) {
        throw 'Replay receipt validation failed.'
    }
    foreach ($property in @($document.inputHashes.PSObject.Properties) + @($document.outputHashes.PSObject.Properties)) {
        if ($property.Value -isnot [string] -or [string]$property.Value -cnotmatch '^[0-9a-f]{64}$') { throw 'Replay receipt validation failed.' }
    }
    return $document
}

function Repair-FoundationUnmatchedJournalOperations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [AllowEmptyCollection()][Collections.Generic.List[Exception]]$Failures
    )

    foreach ($operation in @($Journal.Operations | Where-Object { $null -eq $_.Terminal })) {
        try {
            $intent = $operation.Intent.Record
            $outcome = Get-FoundationOperationOutcome -Journal $Journal -Operation ([string]$intent.operation) -Details $intent.details -Sequence $operation.Sequence
            Publish-FoundationOperationTerminal -Journal $Journal -Sequence $operation.Sequence -Kind $outcome.Kind -Record ([ordered]@{ schemaVersion=1; sequence=$operation.Sequence; operation=[string]$intent.operation; state=$outcome.State })
            $Journal = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
        }
        catch {
            if ($null -eq $Failures) { throw }
            $Failures.Add($_.Exception)
        }
    }
    return $Journal
}

function Get-FoundationCompletionAuthorityPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Journal)

    $path = [string]$Journal.Header.requestedCompletionReceiptPath
    foreach ($operation in $Journal.Operations) {
        if ($operation.Intent.Record.operation -ceq 'CompletionPathSelection' -and $null -ne $operation.Terminal -and $operation.Terminal.Kind -ceq 'applied') {
            $path = [string]$operation.Intent.Record.details.destination
        }
    }
    return [IO.Path]::GetFullPath($path)
}

function Assert-FoundationJournalAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)]$Prestate
    )

    if ($Journal.Header.prestateSha256 -cne (Get-FoundationCanonicalHash -Value $Prestate) -or
        $Journal.Header.initReceiptPath -cne $InitReceiptPath -or $Journal.Header.replayReceiptPath -cne $ReplayReceiptPath -or
        $Journal.Header.requestedCompletionReceiptPath -cne $CompletionReceiptPath -or $Prestate.repo -cne $RepositoryRoot) {
        throw 'Recovery authority does not match the journal header.'
    }
    $initBytes = Get-FoundationJournalEvidenceBytes -Journal $Journal -Key '__init-receipt'
    $replayBytes = Get-FoundationJournalEvidenceBytes -Journal $Journal -Key '__replay-receipt'
    if ((Get-FoundationHostSha256 -Bytes $initBytes) -cne $Journal.Header.initReceiptSha256 -or
        (Get-FoundationHostSha256 -Bytes $replayBytes) -cne $Journal.Header.replayReceiptSha256) { throw 'Recovery receipt evidence digest mismatch.' }
    [void](Read-FoundationInitReceipt -Binding ([pscustomobject]@{Bytes=$initBytes}) -PrestateSha256 $Journal.Header.prestateSha256)
    $receipt = Read-FoundationReplayReceipt -Binding ([pscustomobject]@{Bytes=$replayBytes}) -PrestateSha256 $Journal.Header.prestateSha256 -InitReceiptSha256 $Journal.Header.initReceiptSha256
    $expectedKeys = @($bootstrapContract.Allowlist) + @('__init-receipt','__replay-receipt','__baseline:certification/.gitattributes','__baseline:tests/.gitattributes')
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected $expectedKeys -Actual @($Journal.Evidence | ForEach-Object { [string]$_.key }))) {
        throw 'Recovery evidence key set differs from the allowlist.'
    }
    foreach ($relativePath in $bootstrapContract.Allowlist) {
        $record = @($Journal.Evidence | Where-Object { $_.key -ceq $relativePath })[0]
        if ($record.sha256 -cne (Get-FoundationExpectedHash -Receipt $receipt -RelativePath $relativePath)) { throw "Recovery evidence differs from receipt: $relativePath" }
    }
    foreach ($relativePath in @('certification/.gitattributes','tests/.gitattributes')) {
        $baseline = @($Prestate.allowedBaseline | Where-Object { $_.path -ceq $relativePath })
        $record = @($Journal.Evidence | Where-Object { $_.key -ceq "__baseline:$relativePath" })[0]
        if ($baseline.Count -ne 1 -or -not $baseline[0].exists -or $record.sha256 -cne $baseline[0].sha256 -or $record.length -ne $baseline[0].length) { throw 'Recovery baseline evidence differs from Capture.' }
    }
    $creations = @{}
    $completionPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$completionPaths.Add($CompletionReceiptPath)
    foreach ($operation in $Journal.Operations) {
        $name = [string]$operation.Intent.Record.operation
        $details = $operation.Intent.Record.details
        foreach ($property in $details.PSObject.Properties) {
            if ($property.Name -cin @('path','tempPath','destination','source','collidedPath')) {
                if ($property.Value -isnot [string] -or -not [IO.Path]::IsPathRooted($property.Value) -or
                    [IO.Path]::GetFullPath($property.Value) -cne $property.Value) { throw 'Recovery operation path is not canonical.' }
                Assert-FoundationNoReparsePath -LiteralPath $property.Value -AllowMissingLeaf
            }
        }
        if ($name -ceq 'CompletionPathSelection') {
            if (-not $completionPaths.Contains([string]$details.collidedPath) -or
                (Test-FoundationPathIsWithin -Candidate $details.destination -Root $RepositoryRoot) -or
                (Test-FoundationPathIsWithin -Candidate $details.destination -Root $Journal.Path) -or
                $details.destination -cin @($InitReceiptPath,$ReplayReceiptPath,$PrestatePath)) { throw 'Recovery Completion path selection authority is invalid.' }
            [void]$completionPaths.Add([string]$details.destination)
        }
        if ($name -cin @('TempCreate','TempWrite','Publish')) {
            $key = [string]$details.evidenceKey
            $destination = if ($key -ceq '__init-receipt') { $InitReceiptPath } elseif ($key -ceq '__replay-receipt') { $ReplayReceiptPath } elseif ($key -ceq '__completion-receipt') { $null } elseif ($key.StartsWith('__baseline:', [StringComparison]::Ordinal)) {
                $relativePath = $key.Substring(11)
                if ($relativePath -cnotin @('certification/.gitattributes','tests/.gitattributes')) { throw 'Recovery baseline key is invalid.' }
                Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
            }
            else {
                if ($bootstrapContract.Allowlist -cnotcontains $key) { throw 'Recovery publication key is outside the allowlist.' }
                Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $key
            }
            if ((Split-Path -Parent $details.tempPath) -cne $Journal.Path -or (Split-Path -Leaf $details.tempPath) -cnotmatch '^\.pspkt-content-[0-9a-f]{32}\.tmp$') { throw 'Recovery temporary path authority is invalid.' }
            if ($name -ceq 'TempCreate') {
                if ($creations.ContainsKey([string]$details.tempPath) -or $details.expectedLength -ne 0 -or
                    $details.expectedSha256 -cne (Get-FoundationHostSha256 -Bytes ([byte[]]::new(0)))) { throw 'Recovery TempCreate evidence is invalid.' }
                $creations[[string]$details.tempPath] = $operation
            }
            elseif (-not $creations.ContainsKey([string]$details.tempPath) -or $creations[[string]$details.tempPath].Intent.Record.details.evidenceKey -cne $key) { throw 'Recovery temporary ownership lineage is invalid.' }
            if ($name -cne 'TempWrite' -and (($null -ne $destination -and $details.destination -cne $destination) -or
                ($null -eq $destination -and -not $completionPaths.Contains([string]$details.destination)))) { throw 'Recovery publication destination is outside its evidence authority.' }
            if ($name -cne 'TempCreate' -and $key -cne '__completion-receipt') {
                $evidence = @($Journal.Evidence | Where-Object { $_.key -ceq $key })[0]
                if ($details.expectedSha256 -cne $evidence.sha256 -or $details.expectedLength -ne $evidence.length) { throw 'Recovery publication bytes differ from evidence.' }
            }
        }
        elseif ($name -ceq 'BackupMove') {
            if ($details.relativePath -cnotin @('certification/.gitattributes','tests/.gitattributes')) { throw 'Recovery backup authority is invalid.' }
            $source = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $details.relativePath
            $baseline = @($Prestate.allowedBaseline | Where-Object { $_.path -ceq $details.relativePath })[0]
            if ($details.source -cne $source -or $details.destination -cnotmatch ('^' + [regex]::Escape($source) + '\.pspkt-preimage-[0-9a-f]{32}$') -or
                $details.expectedIdentity -cne $baseline.identity -or $details.expectedLength -ne $baseline.length -or $details.expectedSha256 -cne $baseline.sha256) { throw 'Recovery backup does not match the captured preimage.' }
        }
        elseif ($name -cin @('DirectoryTempCreate','DirectoryPublish')) {
            $allowed = $false
            foreach ($filePath in @($bootstrapContract.Allowlist | ForEach-Object { Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $_ }) + @($InitReceiptPath,$ReplayReceiptPath) + @($completionPaths)) {
                if ($details.destination -cne $RepositoryRoot -and (Test-FoundationPathIsWithin -Candidate $filePath -Root $details.destination) -and
                    [IO.Path]::GetPathRoot($details.destination) -cne $details.destination) { $allowed = $true; break }
            }
            $expectedPrefix = Join-Path (Split-Path -Parent $details.destination) ('.' + (Split-Path -Leaf $details.destination) + '.pspkt-dir-')
            if (-not $allowed -or $details.tempPath -cnotmatch ('^' + [regex]::Escape($expectedPrefix) + '[0-9a-f]{32}$')) { throw 'Recovery directory authority is invalid.' }
            if (Test-FoundationPathIsWithin -Candidate $details.destination -Root $RepositoryRoot) {
                $relative = $details.destination.Substring($RepositoryRoot.TrimEnd('\').Length + 1).Replace('\','/')
                if (@($Prestate.worktree | Where-Object { $_.path -ceq $relative }).Count -ne 0) { throw 'Recovery cannot own a directory present at Capture.' }
            }
        }
    }
    [void](Get-FoundationJournalOwnership -Journal $Journal)
}

function Get-FoundationJournalOwnership {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Journal)

    $files = @{}
    $directories = @{}
    $knownPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($operation in $Journal.Operations) {
        $name = [string]$operation.Intent.Record.operation
        $details = $operation.Intent.Record.details
        foreach ($property in $details.PSObject.Properties) {
            if ($property.Name -ceq 'destination' -and $name -cin @('DirectoryTempCreate','DirectoryPublish') -and
                ($name -ceq 'DirectoryTempCreate' -or $null -eq $operation.Terminal -or $operation.Terminal.Kind -cne 'applied')) { continue }
            if ($property.Name -cin @('path','tempPath','destination')) { [void]$knownPaths.Add([string]$property.Value) }
        }
        if ($name -cin @('TempWrite','Publish')) {
            $identity = if ($name -ceq 'Publish') { [string]$details.tempIdentity } else { [string]$details.identity }
            if (-not $files.ContainsKey([string]$details.tempPath) -or $files[[string]$details.tempPath].Record.Identity -cne $identity) { throw 'Recovery Intent has no matching temp ownership.' }
        }
        elseif ($name -cin @('BackupDelete','RollbackDelete','RollbackReceiptDelete','RollbackBackupDelete','TempDelete')) {
            $path = [string]$details.path
            if (-not $files.ContainsKey($path) -or $files[$path].Record.Identity -cne $details.identity -or
                $files[$path].Record.Length -ne $details.length -or $files[$path].Record.Sha256 -cne $details.sha256) { throw 'Recovery deletion Intent has no matching owning snapshot.' }
        }
        elseif ($name -ceq 'DirectoryDelete' -and (-not $directories.ContainsKey([string]$details.path) -or $directories[[string]$details.path].Identity -cne $details.identity)) { throw 'Recovery directory deletion Intent has no matching owning snapshot.' }
        if ($null -eq $operation.Terminal) { continue }
        $state = $operation.Terminal.Record.state
        $applied = $operation.Terminal.Kind -ceq 'applied'
        if ($name -ceq 'TempWrite' -and $operation.Terminal.Kind -ceq 'not-applied' -and $null -ne $state.PSObject.Properties['incomplete'] -and $state.incomplete -eq $true) {
            $owner = @($Journal.Operations | Where-Object { $_.Sequence -eq $state.ownershipSequence })
            if ($owner.Count -ne 1 -or $owner[0].Sequence -ge $operation.Sequence -or $owner[0].Intent.Record.operation -cne 'TempCreate' -or
                $null -eq $owner[0].Terminal -or $owner[0].Terminal.Kind -cne 'applied' -or
                $owner[0].Terminal.Record.state.Identity -cne $state.observed.Identity -or $details.identity -cne $state.observed.Identity) { throw 'Incomplete temp snapshot has no intact TempCreate ownership.' }
            $files[[string]$details.tempPath] = [pscustomobject]@{Record=$state.observed;Kind='TempWrite';Key=[string]$details.evidenceKey;Sequence=$operation.Sequence}
            continue
        }
        if (-not $applied) { continue }
        switch ($name) {
            { $_ -cin @('TempCreate','TempWrite','Publish','BackupMove') } {
                $path = if ($name -cin @('TempCreate','TempWrite')) { [string]$details.tempPath } else { [string]$details.destination }
                $expectedIdentity = if ($name -ceq 'TempWrite') { $details.identity } elseif ($name -ceq 'Publish') { $details.tempIdentity } elseif ($name -ceq 'BackupMove') { $details.expectedIdentity } else { $state.Identity }
                if ($state.Path -cne $path -or $state.Identity -cne $expectedIdentity -or
                    $state.Length -ne $details.expectedLength -or $state.Sha256 -cne $details.expectedSha256) { throw 'Applied file snapshot does not prove its Intent.' }
                if ($name -cin @('TempWrite','Publish') -and (-not $files.ContainsKey([string]$details.tempPath) -or $files[[string]$details.tempPath].Record.Identity -cne $expectedIdentity)) { throw 'Applied file snapshot has no intact temp lineage.' }
                if ($name -ceq 'Publish') { $files.Remove([string]$details.tempPath) }
                $key = if ($null -ne $details.PSObject.Properties['evidenceKey']) { [string]$details.evidenceKey } else { [string]$details.relativePath }
                $files[$path] = [pscustomobject]@{Record=$state;Kind=$name;Key=$key;Sequence=$operation.Sequence}
            }
            { $_ -cin @('DirectoryTempCreate','DirectoryPublish') } {
                $path = if ($name -ceq 'DirectoryTempCreate') { [string]$details.tempPath } else { [string]$details.destination }
                if ($name -ceq 'DirectoryPublish') {
                    if (-not $directories.ContainsKey([string]$details.tempPath) -or $directories[[string]$details.tempPath].Identity -cne $state.identity -or $state.identity -cne $details.identity) { throw 'Directory publication has no intact ownership lineage.' }
                    $directories.Remove([string]$details.tempPath)
                }
                $directories[$path] = [pscustomobject]@{Path=$path;Identity=[string]$state.identity;Sequence=$operation.Sequence}
            }
            { $_ -cin @('BackupDelete','RollbackDelete','RollbackReceiptDelete','RollbackBackupDelete','TempDelete') } {
                $path = [string]$details.path
                if (-not $files.ContainsKey($path) -or $files[$path].Record.Identity -cne $details.identity -or
                    $files[$path].Record.Length -ne $details.length -or $files[$path].Record.Sha256 -cne $details.sha256) { throw 'File deletion has no matching owning snapshot.' }
                $files.Remove($path)
            }
            'DirectoryDelete' {
                if (-not $directories.ContainsKey([string]$details.path) -or $directories[[string]$details.path].Identity -cne $details.identity) { throw 'Directory deletion has no matching owning snapshot.' }
                $directories.Remove([string]$details.path)
            }
        }
    }
    return [pscustomobject]@{Files=$files;Directories=$directories;KnownPaths=$knownPaths}
}

function Remove-FoundationJournaledFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$Operation
    )

    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    $ownership = Get-FoundationJournalOwnership -Journal $fresh
    if (-not $ownership.Files.ContainsKey([string]$Record.Path) -or
        (Get-FoundationCanonicalHash -Value $ownership.Files[[string]$Record.Path].Record) -cne (Get-FoundationCanonicalHash -Value $Record)) {
        throw "Cleanup has no matching journal ownership: $($Record.Path)"
    }
    if (-not (Test-FoundationOwnedFileRecord -Record $Record)) { throw "Cleanup preserved a different occupant: $($Record.Path)" }
    [void](Invoke-FoundationJournalOperation -Journal $Journal -Operation $Operation -Details ([ordered]@{path=$Record.Path;identity=$Record.Identity;length=$Record.Length;sha256=$Record.Sha256}) -Mutation {
        Remove-FoundationOwnedFile -Record $Record
    } -AppliedState {
        if (-not (Test-Path -LiteralPath $Record.Path)) { return [ordered]@{absent=$true} }
        return $null
    })
}

function Test-FoundationReadyPredicate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        [Parameter(Mandatory = $true)]$ReplayReceipt,
        [Parameter(Mandatory = $true)]$Journal,
        [int]$BeforeSequence = [int]::MaxValue
    )

    Assert-FoundationReadyState -Prestate $Prestate -ReplayReceipt $ReplayReceipt -Journal $Journal -BeforeSequence $BeforeSequence
    return $true
}

function Assert-FoundationReadyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        [Parameter(Mandatory = $true)]$ReplayReceipt,
        [Parameter(Mandatory = $true)]$Journal,
        [int]$BeforeSequence = [int]::MaxValue
    )

    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    if (@($fresh.Operations | Where-Object { $_.Sequence -lt $BeforeSequence -and $null -eq $_.Terminal }).Count -ne 0) { throw 'ReadyToCommit has an earlier unresolved Intent.' }
    $ownership = Get-FoundationJournalOwnership -Journal $fresh
    $ownedDirectories = @(Get-FoundationOwnedDirectoryDeltas -Journal $fresh -Prestate $Prestate)
    Assert-FoundationProductionUnchanged -Prestate $Prestate -ExpectedAllowlistHashes $ReplayReceipt -TransactionOwnedDirectories $ownedDirectories
    if (-not [IO.File]::Exists($InitReceiptPath) -or -not [IO.File]::Exists($ReplayReceiptPath)) { throw 'Prepared receipts are absent.' }
    if ((Get-FoundationFileSha -LiteralPath $InitReceiptPath) -cne [string]$ReplayReceipt.initReceiptSha256) { throw 'Prepared Init receipt hash mismatch.' }
    if ((Get-FoundationFileSha -LiteralPath $ReplayReceiptPath) -cne (Get-FoundationHostSha256 -Bytes (Get-PspktCanonicalJsonBytes -Value $ReplayReceipt))) { throw 'Prepared Replay receipt hash mismatch.' }
    foreach ($entry in $ownership.Files.Values) {
        if ($entry.Kind -ceq 'BackupMove' -and (Test-Path -LiteralPath $entry.Record.Path)) { throw 'Prepared state still contains an owned backup.' }
        if ($entry.Kind -cin @('TempCreate','TempWrite') -and (Test-Path -LiteralPath $entry.Record.Path)) { throw 'Prepared state still contains an owned temporary.' }
    }
    foreach ($operation in $fresh.Operations) {
        $details = $operation.Intent.Record.details
        if ($null -ne $details.PSObject.Properties['tempPath'] -and (Test-Path -LiteralPath ([string]$details.tempPath))) {
            throw "Prepared state still contains a known temporary or replacement: $($details.tempPath)"
        }
    }
    foreach ($path in @($InitReceiptPath,$ReplayReceiptPath)) {
        if (-not $ownership.Files.ContainsKey($path) -or $ownership.Files[$path].Kind -cne 'Publish' -or
            -not (Test-FoundationOwnedFileRecord -Record $ownership.Files[$path].Record)) { throw "Prepared receipt ownership mismatch: $path" }
    }
    foreach ($relativePath in $bootstrapContract.Allowlist) {
        $path = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
        if (-not $ownership.Files.ContainsKey($path) -or $ownership.Files[$path].Kind -cne 'Publish' -or
            -not (Test-FoundationOwnedFileRecord -Record $ownership.Files[$path].Record)) { throw "Promoted file ownership mismatch: $relativePath" }
    }
}

function Get-FoundationOwnedDirectoryDeltas {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Journal,
        [Parameter(Mandatory = $true)]$Prestate
    )

    $ownership = Get-FoundationJournalOwnership -Journal $Journal
    foreach ($directory in $ownership.Directories.Values) {
        if (Test-FoundationPathIsWithin -Candidate $directory.Path -Root $RepositoryRoot) {
            if (-not [IO.Directory]::Exists($directory.Path) -or (Get-FoundationNativeDirectoryIdentity -LiteralPath $directory.Path) -cne $directory.Identity) { throw 'ReadyToCommit directory identity changed.' }
            $relative = $directory.Path.Substring($RepositoryRoot.TrimEnd('\').Length + 1).Replace('\','/')
            if (@($Prestate.worktree | Where-Object { $_.path -ceq $relative }).Count -ne 0) { throw 'A captured directory cannot be transaction-owned.' }
            $relative
        }
    }
}

function Assert-FoundationReplayProductionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        [Parameter(Mandatory = $true)]$ReplayReceipt,
        [Parameter(Mandatory = $true)][ValidateSet('Committed','Staged','Unstaged')][string]$ReplayMode,
        [Parameter(Mandatory = $true)]$Journal,
        [string]$SelectedCommitOid,
        [string]$SelectedTreeOid,
        [string]$SelectedMapBlobOid
    )

    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    Assert-FoundationTransactionLayout -Journal $fresh
    Assert-FoundationJournalAuthority -Journal $fresh -Prestate $Prestate
    if (@($fresh.Operations | Where-Object { $null -eq $_.Terminal }).Count -ne 0) {
        throw 'Replay requires a Recovery journal with no unresolved Intent.'
    }
    $completionPath = Get-FoundationCompletionAuthorityPath -Journal $fresh
    $completion = Test-FoundationCompletionReceipt -Journal $fresh -LiteralPath $completionPath -ReturnDocument
    if ($completion -is [bool] -and -not $completion) { throw 'Replay requires a valid Completion receipt.' }
    if ([string]$completion.candidateTreeOid -cne [string]$ReplayReceipt.candidateTreeOid -or
        [string]$completion.mapBlobOid -cne [string]$ReplayReceipt.mapBlobOid) {
        throw 'Replay Completion receipt differs from the authoritative Replay receipt.'
    }
    $ownedDirectories = @(Get-FoundationOwnedDirectoryDeltas -Journal $fresh -Prestate $Prestate)
    if ($ReplayMode -ceq 'Committed') {
        $commitType = [string](Get-FoundationGitOutput -Arguments @('cat-file','-t',$SelectedCommitOid) | Select-Object -First 1)
        $resolvedCommit = [string](Get-FoundationGitOutput -Arguments @('rev-parse',"$SelectedCommitOid`^{commit}") | Select-Object -First 1)
        $committedPaths = @(Get-FoundationGitNulPaths -Arguments @('diff-tree','--no-commit-id','--name-only','-r','-z',$bootstrapContract.BaselineOid,$SelectedCommitOid))
        if ($commitType -cne 'commit' -or $resolvedCommit -cne $SelectedCommitOid -or
            -not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.Allowlist) -Actual ([string[]]$committedPaths))) {
            throw 'Selected commit did not resolve through production Git.'
        }
        Assert-FoundationProductionUnchanged -Prestate $Prestate -ExpectedAllowlistHashes $ReplayReceipt -CommittedReplayOid $SelectedCommitOid -TransactionOwnedDirectories $ownedDirectories
    }
    else {
        if ([string]$ReplayReceipt.candidateTreeOid -cne $SelectedTreeOid -or
            [string]$ReplayReceipt.mapBlobOid -cne $SelectedMapBlobOid) {
            throw 'Replay selection differs from the authoritative receipt.'
        }
        Assert-FoundationProductionUnchanged -Prestate $Prestate -ExpectedAllowlistHashes $ReplayReceipt -AllowStaged:($ReplayMode -ceq 'Staged') -TransactionOwnedDirectories $ownedDirectories
    }
    return $fresh
}

function Assert-FoundationRolledBackState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        [Parameter(Mandatory = $true)]$Journal,
        [int]$BeforeSequence = [int]::MaxValue
    )

    $fresh = Read-FoundationRecoveryJournal -LiteralPath $Journal.Path -Lease $Journal.Lease
    if (@($fresh.Operations | Where-Object { $_.Sequence -lt $BeforeSequence -and $null -eq $_.Terminal }).Count -ne 0) { throw 'RolledBack has an earlier unresolved Intent.' }
    Assert-FoundationProductionUnchanged -Prestate $Prestate
    $ownership = Get-FoundationJournalOwnership -Journal $fresh
    $baselinePaths = @{}
    foreach ($baseline in $Prestate.allowedBaseline) {
        if ($baseline.exists) { $baselinePaths[(Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $baseline.path)] = $baseline }
    }
    foreach ($path in $ownership.KnownPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if ($baselinePaths.ContainsKey($path)) {
            $baseline = $baselinePaths[$path]
            $identity = Get-FoundationNativeFileIdentity -LiteralPath $path
            if ($identity -ceq $baseline.identity) { continue }
            if ($ownership.Files.ContainsKey($path) -and $ownership.Files[$path].Key.StartsWith('__baseline:', [StringComparison]::Ordinal) -and
                (Test-FoundationOwnedFileRecord -Record $ownership.Files[$path].Record)) { continue }
        }
        throw "RolledBack still contains a known artifact or foreign replacement: $path"
    }
    foreach ($path in @($InitReceiptPath,$ReplayReceiptPath)) {
        if (Test-Path -LiteralPath $path) { throw "RolledBack still contains an external receipt: $path" }
    }
}

function Invoke-FoundationPromotionGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        [Parameter(Mandatory = $true)][byte[]]$InitReceiptBytes,
        [Parameter(Mandatory = $true)][string]$InitReceiptDestination,
        [Parameter(Mandatory = $true)][byte[]]$ReplayReceiptBytes,
        [Parameter(Mandatory = $true)][string]$ReplayReceiptDestination,
        [Parameter(Mandatory = $true)]$ExpectedAllowlistHashes
    )

    if ($InitReceiptDestination -cne $InitReceiptPath -or $ReplayReceiptDestination -cne $ReplayReceiptPath) {
        throw 'Promotion receipt destinations do not match their journal authorities.'
    }
    Assert-FoundationTransactionLayout -NewJournal
    Assert-FoundationProductionUnchanged -Prestate $Prestate -RequireCapturedIdentity
    $journal = New-FoundationRecoveryJournal -InitReceiptBytes $InitReceiptBytes -ReplayReceiptBytes $ReplayReceiptBytes -ExpectedAllowlistHashes $ExpectedAllowlistHashes -PrestateSha256 (Get-FoundationHostSha256 -Bytes (Get-PspktCanonicalJsonBytes -Value $Prestate))
    $lease = Open-FoundationJournalLease -LiteralPath $journal.Path -Exclusive
    try {
        $journal = Read-FoundationRecoveryJournal -LiteralPath $journal.Path -Lease $lease
        $baselineByPath = @{}
        foreach ($baseline in $Prestate.allowedBaseline) { $baselineByPath[[string]$baseline.path] = $baseline }
        Assert-FoundationJournalAuthority -Journal $journal -Prestate $Prestate
        foreach ($relativeDirectory in @('certification/schema/catalog','certification/vectors/phase4-schema-authority-foundation')) {
            $directory = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativeDirectory
            Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath $directory
        }
        foreach ($relativePath in @('certification/.gitattributes','tests/.gitattributes')) {
            $destination = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
            $baseline = $baselineByPath[$relativePath]
            $backup = "$destination.pspkt-preimage-$([guid]::NewGuid().ToString('N'))"
            [void](Invoke-FoundationJournalOperation -Journal $journal -Operation 'BackupMove' -Details ([ordered]@{ source=$destination; destination=$backup; expectedIdentity=$baseline.identity; expectedLength=$baseline.length; expectedSha256=$baseline.sha256; relativePath=$relativePath }) -Mutation {
                $record = [pscustomobject]@{Path=$destination;Identity=$baseline.identity;Length=$baseline.length;Sha256=$baseline.sha256}
                Move-FoundationNativeOwnedFileCreateOnly -Source $destination -Destination $backup -Record $record
            } -AppliedState {
                if ([IO.File]::Exists($backup)) { return Get-FoundationOwnedFileRecord -LiteralPath $backup }
                return $null
            })
        }
        foreach ($relativePath in $bootstrapContract.Allowlist) {
            $destination = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
            [byte[]]$bytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key $relativePath
            [void](Publish-FoundationJournaledFile -Journal $journal -Destination $destination -Bytes $bytes -EvidenceKey $relativePath)
        }
        Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath (Split-Path -Parent $InitReceiptDestination)
        Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath (Split-Path -Parent $ReplayReceiptDestination)
        [void](Publish-FoundationJournaledFile -Journal $journal -Destination $InitReceiptDestination -Bytes $InitReceiptBytes -EvidenceKey '__init-receipt')
        [void](Publish-FoundationJournaledFile -Journal $journal -Destination $ReplayReceiptDestination -Bytes $ReplayReceiptBytes -EvidenceKey '__replay-receipt')
        foreach ($operation in @(Read-FoundationRecoveryJournal -LiteralPath $journal.Path -Lease $journal.Lease).Operations) {
            if ($operation.Intent.Record.operation -ceq 'BackupMove' -and $null -ne $operation.Terminal -and $operation.Terminal.Kind -ceq 'applied') {
                $backupPath = [string]$operation.Intent.Record.details.destination
                $record = $operation.Terminal.Record.state
                [void](Invoke-FoundationJournalOperation -Journal $journal -Operation 'BackupDelete' -Details ([ordered]@{ path=$backupPath; identity=$record.Identity; length=$record.Length; sha256=$record.Sha256 }) -Mutation {
                    Remove-FoundationOwnedFile -Record $record
                } -AppliedState {
                    if (-not [IO.File]::Exists($backupPath)) { return [ordered]@{ absent=$true } }
                    return $null
                })
            }
        }
        $replayReceipt = ConvertFrom-FoundationStrictUtf8 -Bytes $ReplayReceiptBytes | ConvertFrom-Json
        Assert-FoundationReadyState -Prestate $Prestate -ReplayReceipt $replayReceipt -Journal $journal
        [void](Publish-FoundationJournaledPhase -Journal $journal -Phase ReadyToCommit -Predicate {
            Test-FoundationReadyPredicate -Prestate $Prestate -ReplayReceipt $replayReceipt -Journal $journal -BeforeSequence ($journal.NextSequence - 1)
        })
        $readyHash = Get-FoundationReadyJournalSha256 -Journal $journal
        $completionBytes = Get-PspktCanonicalJsonBytes -Value ([ordered]@{
            schemaVersion=1
            schemaId=$bootstrapContract.CompletionReceiptSchemaId
            prestateSha256=[string]$journal.Header.prestateSha256
            readyJournalSha256=$readyHash
            initReceiptSha256=[string]$journal.Header.initReceiptSha256
            replayReceiptSha256=[string]$journal.Header.replayReceiptSha256
            candidateTreeOid=[string]$replayReceipt.candidateTreeOid
            mapBlobOid=[string]$replayReceipt.mapBlobOid
        })
        Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath (Split-Path -Parent $CompletionReceiptPath)
        [void](Publish-FoundationJournaledFile -Journal $journal -Destination $CompletionReceiptPath -Bytes $completionBytes -EvidenceKey '__completion-receipt')
        $validatedJournal = Read-FoundationRecoveryJournal -LiteralPath $journal.Path -Lease $journal.Lease
        if (-not (Test-FoundationCompletionReceipt -Journal $validatedJournal -LiteralPath $CompletionReceiptPath)) { throw 'Completion receipt validation failed after publication.' }
        if (@($validatedJournal.Operations | Where-Object { $null -eq $_.Terminal }).Count -ne 0) { throw 'Recovery journal contains unresolved Intents after completion.' }
    }
    catch {
        if ([Environment]::GetEnvironmentVariable('PSPKT_FOUNDATION_TEST_CRASH_POINT')) { throw }
        $promotionError = $_.Exception
        try { Invoke-FoundationRecovery -Prestate $Prestate -Action Rollback -Journal $journal | Out-Null }
        catch {
            throw [AggregateException]::new("Promotion and rollback failed; recovery journal: $($journal.Path)", [Exception[]]@($promotionError, $_.Exception))
        }
        throw $promotionError
    }
    finally { $lease.Stream.Dispose() }
}

function Invoke-FoundationRecovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Prestate,
        [Parameter(Mandatory = $true)][ValidateSet('Finalize','Rollback')][string]$Action,
        $Journal
    )

    $ownsLease = $null -eq $Journal
    $lease = if ($ownsLease) { Open-FoundationJournalLease -LiteralPath $RecoveryJournalPath -Exclusive } else { $Journal.Lease }
    try {
    if (-not $lease.Exclusive) { throw 'Recovery requires an exclusive header lease.' }
    $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath -Lease $lease
    Assert-FoundationTransactionLayout -Journal $journal
    Assert-FoundationJournalAuthority -Journal $journal -Prestate $Prestate
    $repairFailures = [Collections.Generic.List[Exception]]::new()
    if ($Action -eq 'Rollback') { $journal = Repair-FoundationUnmatchedJournalOperations -Journal $journal -Failures $repairFailures }
    else { $journal = Repair-FoundationUnmatchedJournalOperations -Journal $journal }
    $journal.Recovery = $true
    $journal.RecoveryAction = $Action
    $blockingConflicts = @($journal.Operations | Where-Object {
        $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'conflict' -and
        -not ($_.Intent.Record.operation -ceq 'Publish' -and [string]$_.Intent.Record.details.destination -ceq (Get-FoundationCompletionAuthorityPath -Journal $journal))
    })
    if ($Action -eq 'Finalize' -and $blockingConflicts.Count -ne 0) { throw 'Recovery journal contains a non-Completion conflict.' }
    $completionPath = Get-FoundationCompletionAuthorityPath -Journal $journal
    if (Test-FoundationCompletionReceipt -Journal $journal -LiteralPath $completionPath) {
        if ($Action -eq 'Rollback') { throw 'A valid Completion receipt blocks rollback.' }
        $validatedReplay = ConvertFrom-FoundationStrictUtf8 -Bytes (Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__replay-receipt') | ConvertFrom-Json
        Assert-FoundationReadyState -Prestate $Prestate -ReplayReceipt $validatedReplay -Journal $journal
        return [ordered]@{ action='Finalize'; status='already-complete'; completionReceiptPath=$completionPath }
    }
    $rolledBack = @($journal.Operations | Where-Object { $_.Intent.Record.operation -ceq 'RolledBack' -and $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied' })
    if ($rolledBack.Count -ne 0) { throw 'Recovery journal is already terminal RolledBack.' }
    $header = $journal.Header
    $initBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__init-receipt'
    $replayBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key '__replay-receipt'
    $replayReceipt = ConvertFrom-FoundationStrictUtf8 -Bytes $replayBytes | ConvertFrom-Json
    if ($Action -eq 'Rollback') {
        $conflicts = [Collections.Generic.List[Exception]]::new()
        foreach ($failure in $repairFailures) { $conflicts.Add($failure) }
        $ownership = Get-FoundationJournalOwnership -Journal $journal
        foreach ($entry in @($ownership.Files.Values | Sort-Object Sequence -Descending)) {
            if ($entry.Key.StartsWith('__baseline:', [StringComparison]::Ordinal) -and $entry.Kind -ceq 'Publish') { continue }
            if (-not (Test-Path -LiteralPath $entry.Record.Path)) { continue }
            $deleteOperation = if ($entry.Kind -ceq 'BackupMove') { 'RollbackBackupDelete' } elseif ($entry.Kind -cin @('TempCreate','TempWrite')) { 'TempDelete' } elseif ($entry.Key.StartsWith('__', [StringComparison]::Ordinal)) { 'RollbackReceiptDelete' } else { 'RollbackDelete' }
            try { Remove-FoundationJournaledFile -Journal $journal -Record $entry.Record -Operation $deleteOperation }
            catch { $conflicts.Add($_.Exception) }
        }
        foreach ($relativePath in @('certification/.gitattributes','tests/.gitattributes')) {
            $destination = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
            [byte[]]$baselineBytes = Get-FoundationJournalEvidenceBytes -Journal $journal -Key "__baseline:$relativePath"
            try {
                if (Test-Path -LiteralPath $destination) {
                    $baseline = @($Prestate.allowedBaseline | Where-Object { $_.path -ceq $relativePath })[0]
                    $original = [pscustomobject]@{Path=$destination;Identity=$baseline.identity;Length=$baseline.length;Sha256=$baseline.sha256}
                    if (Test-FoundationOwnedFileRecord -Record $original) { continue }
                    if ($ownership.Files.ContainsKey($destination) -and $ownership.Files[$destination].Key -ceq "__baseline:$relativePath" -and
                        (Test-FoundationOwnedFileRecord -Record $ownership.Files[$destination].Record)) { continue }
                    throw "Rollback preserved a foreign attribute occupant: $destination"
                }
                [void](Publish-FoundationJournaledFile -Journal $journal -Destination $destination -Bytes $baselineBytes -EvidenceKey "__baseline:$relativePath")
            }
            catch { $conflicts.Add($_.Exception) }
        }
        foreach ($directory in @($ownership.Directories.Values | Sort-Object { $_.Path.Length } -Descending)) {
            if (-not (Test-Path -LiteralPath $directory.Path)) { continue }
            try {
                [void](Invoke-FoundationJournalOperation -Journal $journal -Operation DirectoryDelete -Details ([ordered]@{path=$directory.Path;identity=$directory.Identity}) -Mutation {
                    Remove-FoundationNativeOwnedEmptyDirectory -LiteralPath $directory.Path -ExpectedIdentity $directory.Identity
                } -AppliedState {
                    if (-not (Test-Path -LiteralPath $directory.Path)) { return [ordered]@{absent=$true} }
                    return $null
                })
            }
            catch { $conflicts.Add($_.Exception) }
        }
        try { Assert-FoundationRolledBackState -Prestate $Prestate -Journal $journal }
        catch { $conflicts.Add($_.Exception) }
        if ($conflicts.Count -ne 0) { throw [AggregateException]::new("Rollback preserved conflicts; recovery journal: $($journal.Path)", $conflicts.ToArray()) }
        [void](Publish-FoundationJournaledPhase -Journal $journal -Phase RolledBack -Predicate {
            Assert-FoundationRolledBackState -Prestate $Prestate -Journal $journal -BeforeSequence ($journal.NextSequence - 1)
            return $true
        })
        return [ordered]@{ action='Rollback'; status='rolled-back'; completionReceiptPath=$null }
    }
    foreach ($relativePath in $bootstrapContract.Allowlist) {
        $destination = Resolve-FoundationHostPath -Root $RepositoryRoot -RelativePath $relativePath
        if (-not [IO.File]::Exists($destination) -or (Get-FoundationFileSha -LiteralPath $destination) -cne (Get-FoundationExpectedHash -Receipt $replayReceipt -RelativePath $relativePath)) {
            throw "Finalize requires exact promoted file: $relativePath"
        }
    }
    $ownership = Get-FoundationJournalOwnership -Journal $journal
    foreach ($entry in @($ownership.Files.Values)) {
        if ($entry.Kind -cin @('TempCreate','TempWrite') -and (Test-Path -LiteralPath $entry.Record.Path)) {
            if ($entry.Key -cnotin @('__init-receipt','__replay-receipt','__completion-receipt')) { throw 'Incomplete allowlist promotion is Rollback-only.' }
            Remove-FoundationJournaledFile -Journal $journal -Record $entry.Record -Operation TempDelete
        }
    }
    foreach ($receipt in @(
        [pscustomobject]@{ Path=$InitReceiptPath; Bytes=$initBytes; Key='__init-receipt' }
        [pscustomobject]@{ Path=$ReplayReceiptPath; Bytes=$replayBytes; Key='__replay-receipt' }
    )) {
        if (-not [IO.File]::Exists($receipt.Path)) {
            Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath (Split-Path -Parent $receipt.Path)
            [void](Publish-FoundationJournaledFile -Journal $journal -Destination $receipt.Path -Bytes $receipt.Bytes -EvidenceKey $receipt.Key)
        }
        elseif (-not $ownership.Files.ContainsKey($receipt.Path) -or
            -not (Test-FoundationOwnedFileRecord -Record $ownership.Files[$receipt.Path].Record) -or
            (Get-FoundationFileSha -LiteralPath $receipt.Path) -cne (Get-FoundationHostSha256 -Bytes $receipt.Bytes)) {
            throw "Finalize receipt conflict: $($receipt.Path)"
        }
    }
    $finalizeInitBinding = New-FoundationFileBinding -LiteralPath $InitReceiptPath -Role 'authority:init-receipt-finalize'
    $finalizeReplayBinding = New-FoundationFileBinding -LiteralPath $ReplayReceiptPath -Role 'authority:replay-receipt-finalize'
    $script:AuthorityFileBindings.Add($finalizeInitBinding)
    $script:AuthorityFileBindings.Add($finalizeReplayBinding)
    [void](Read-FoundationInitReceipt -Binding $finalizeInitBinding -PrestateSha256 ([string]$journal.Header.prestateSha256))
    [void](Read-FoundationReplayReceipt -Binding $finalizeReplayBinding -PrestateSha256 ([string]$journal.Header.prestateSha256) -InitReceiptSha256 $finalizeInitBinding.Sha256)
    foreach ($entry in $ownership.Files.Values) {
        if ($entry.Kind -ceq 'BackupMove' -and (Test-Path -LiteralPath $entry.Record.Path)) {
            Remove-FoundationJournaledFile -Journal $journal -Record $entry.Record -Operation BackupDelete
        }
    }
    Assert-FoundationReadyState -Prestate $Prestate -ReplayReceipt $replayReceipt -Journal $journal
    $ready = @($journal.Operations | Where-Object { $_.Intent.Record.operation -ceq 'ReadyToCommit' -and $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied' })
    if ($ready.Count -eq 0) {
        [void](Publish-FoundationJournaledPhase -Journal $journal -Phase ReadyToCommit -Predicate {
            Test-FoundationReadyPredicate -Prestate $Prestate -ReplayReceipt $replayReceipt -Journal $journal -BeforeSequence ($journal.NextSequence - 1)
        })
    }
    $journal = Read-FoundationRecoveryJournal -LiteralPath $journal.Path -Lease $journal.Lease
    $journal.Recovery = $true
    $journal.RecoveryAction = $Action
    $readyHash = Get-FoundationReadyJournalSha256 -Journal $journal
    $completionBytes = Get-PspktCanonicalJsonBytes -Value ([ordered]@{
        schemaVersion=1
        schemaId=$bootstrapContract.CompletionReceiptSchemaId
        prestateSha256=[string]$journal.Header.prestateSha256
        readyJournalSha256=$readyHash
        initReceiptSha256=[string]$journal.Header.initReceiptSha256
        replayReceiptSha256=[string]$journal.Header.replayReceiptSha256
        candidateTreeOid=[string]$replayReceipt.candidateTreeOid
        mapBlobOid=[string]$replayReceipt.mapBlobOid
    })
    if ([IO.File]::Exists($completionPath)) {
        if (-not (Test-FoundationCompletionReceipt -Journal $journal -LiteralPath $completionPath)) {
            if ([string]::IsNullOrEmpty($RecoveredCompletionReceiptPath)) { throw 'Finalize found a foreign Completion collision and requires RecoveredCompletionReceiptPath.' }
            if (Test-Path -LiteralPath $RecoveredCompletionReceiptPath) { throw 'Recovered Completion destination must be absent.' }
            [void](Invoke-FoundationJournalOperation -Journal $journal -Operation 'CompletionPathSelection' -Details ([ordered]@{ destination=$RecoveredCompletionReceiptPath; collidedPath=$completionPath }) -Mutation {
                if (Test-Path -LiteralPath $RecoveredCompletionReceiptPath) { throw [IO.IOException]::new('Recovered Completion destination collision.') }
            } -AppliedState { return [ordered]@{ destination=$RecoveredCompletionReceiptPath } })
            $completionPath = $RecoveredCompletionReceiptPath
        }
    }
    if (-not [IO.File]::Exists($completionPath)) {
        Ensure-FoundationJournaledDirectory -Journal $journal -LiteralPath (Split-Path -Parent $completionPath)
        [void](Publish-FoundationJournaledFile -Journal $journal -Destination $completionPath -Bytes $completionBytes -EvidenceKey '__completion-receipt')
    }
    $journal = Read-FoundationRecoveryJournal -LiteralPath $journal.Path -Lease $journal.Lease
    if (-not (Test-FoundationCompletionReceipt -Journal $journal -LiteralPath $completionPath)) { throw 'Finalize did not establish a valid Completion receipt.' }
    return [ordered]@{ action='Finalize'; status='complete'; completionReceiptPath=$completionPath }
    }
    finally { if ($ownsLease) { $lease.Stream.Dispose() } }
}


Assert-FoundationTransactionLayout -InvocationMode $PSCmdlet.ParameterSetName -PathsOnly -NewJournal:($FoundationInit -and -not [IO.Directory]::Exists($RecoveryJournalPath))
$repositoryPrefix = $RepositoryRoot.TrimEnd('\') + '\'
if (-not [IO.Directory]::Exists($RepositoryRoot)) {
    throw 'RepositoryRoot does not exist.'
}
Assert-FoundationNoReparsePath -LiteralPath $RepositoryRoot
$initialAuthorities = [Collections.Generic.List[object]]::new()
$initialAuthorities.Add([pscustomobject]@{Name='RepositoryRoot';Path=$RepositoryRoot})
$initialAuthorities.Add([pscustomobject]@{Name='ScratchRoot';Path=$ScratchRoot})
$initialAuthorities.Add([pscustomobject]@{Name='PrestatePath';Path=$PrestatePath})
if ($PSCmdlet.ParameterSetName -ne 'CapturePrestateMode') {
    if ($PSCmdlet.ParameterSetName -ne 'RecoveryMode') {
        if (-not [IO.Directory]::Exists($SourceRoot)) { throw 'SourceRoot does not exist.' }
        $initialAuthorities.Add([pscustomobject]@{Name='SourceRoot';Path=$SourceRoot})
    }
    $initialAuthorities.Add([pscustomobject]@{Name='RecoveryJournalPath';Path=$RecoveryJournalPath})
    $initialAuthorities.Add([pscustomobject]@{Name='InitReceiptPath';Path=$InitReceiptPath})
    $initialAuthorities.Add([pscustomobject]@{Name='ReplayReceiptPath';Path=$ReplayReceiptPath})
    $initialAuthorities.Add([pscustomobject]@{Name='CompletionReceiptPath';Path=$CompletionReceiptPath})
    if (-not [string]::IsNullOrEmpty($RecoveredCompletionReceiptPath)) {
        $initialAuthorities.Add([pscustomobject]@{Name='RecoveredCompletionReceiptPath';Path=$RecoveredCompletionReceiptPath})
    }
}
foreach ($authority in $initialAuthorities) {
    $path = [IO.Path]::GetFullPath([string]$authority.Path)
    if ($path -ine [IO.Path]::GetPathRoot($path)) { $path = $path.TrimEnd('\') }
    foreach ($other in $initialAuthorities) {
        if ([object]::ReferenceEquals($authority,$other)) { continue }
        $otherPath = [IO.Path]::GetFullPath([string]$other.Path)
        if ($otherPath -ine [IO.Path]::GetPathRoot($otherPath)) { $otherPath = $otherPath.TrimEnd('\') }
        if ((Test-FoundationPathIsWithin -Candidate $path -Root $otherPath) -or (Test-FoundationPathIsWithin -Candidate $otherPath -Root $path)) {
            throw "Path authorities overlap: $($authority.Name), $($other.Name)"
        }
    }
    $parent = if (Test-Path -LiteralPath $path) { $path } else { Split-Path -Parent $path }
    Assert-FoundationNoReparsePath -LiteralPath $parent -AllowMissingLeaf
}
if (Test-Path -LiteralPath $ScratchRoot) {
    throw 'ScratchRoot must be absent at invocation start.'
}
[IO.Directory]::CreateDirectory($ScratchRoot) | Out-Null
Assert-FoundationNoReparsePath -LiteralPath $ScratchRoot
[IO.Directory]::CreateDirectory($stateRoot) | Out-Null
Initialize-FoundationHostAssembly | Out-Null
Assert-FoundationHostBinding
if ($PSCmdlet.ParameterSetName -ne 'CapturePrestateMode') { Assert-FoundationTransactionLayout -NewJournal:($FoundationInit -and -not [IO.Directory]::Exists($RecoveryJournalPath)) }
Initialize-FoundationRawLaunchAuthority
Assert-FoundationRawLaunchAuthority
Assert-FoundationPairwiseRootAuthority -Authorities $initialAuthorities.ToArray()

$authorityRoot = Join-Path $stateRoot 'authority'
[IO.Directory]::CreateDirectory($authorityRoot) | Out-Null
$bootstrapSpecs = @(
    [pscustomobject]@{ Name='CanonicalJson.ps1'; Path=(Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.CanonicalJson.ps1'); Length=$bootstrapContract.CanonicalJsonLength; Sha256=$bootstrapContract.CanonicalJsonSha256 }
    [pscustomobject]@{ Name='BoundedProcess.cs'; Path=(Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.BoundedProcess.cs'); Length=$bootstrapContract.BoundedProcessLength; Sha256=$bootstrapContract.BoundedProcessSha256 }
    [pscustomobject]@{ Name='SchemaBootstrap.cs'; Path=(Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.SchemaBootstrap.cs'); Length=$bootstrapContract.SchemaBootstrapLength; Sha256=$bootstrapContract.SchemaBootstrapSha256 }
    [pscustomobject]@{ Name='protocol-schema-meta.v1.json'; Path=(Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json'); Length=$bootstrapContract.MetaLength; Sha256=$bootstrapContract.MetaSha256 }
)
$bootstrapCopies = @{}
foreach ($spec in $bootstrapSpecs) {
    $originalBinding = New-FoundationFileBinding -LiteralPath $spec.Path -Role "bootstrap-original:$($spec.Name)" -MaximumLength $spec.Length
    if ($originalBinding.Length -ne $spec.Length -or $originalBinding.Sha256 -cne $spec.Sha256) {
        $originalBinding.Stream.Dispose()
        throw "Pinned bootstrap file mismatch: $($spec.Name)"
    }
    $script:BootstrapFileBindings.Add($originalBinding)
    $copyPath = Join-Path $authorityRoot $spec.Name
    $bootstrapCopies[$spec.Name] = Copy-FoundationBindingToImmutablePath -Binding $originalBinding -Destination $copyPath -Role "bootstrap-copy:$($spec.Name)"
}
$canonicalJsonPath = $bootstrapCopies['CanonicalJson.ps1'].Path
$boundedProcessPath = $bootstrapCopies['BoundedProcess.cs'].Path
$schemaBootstrapSource = $bootstrapCopies['SchemaBootstrap.cs'].Path
$metaPath = $bootstrapCopies['protocol-schema-meta.v1.json'].Path
. $canonicalJsonPath

$resolvedPowerShellBindings = $null
$journal = $null
$replayMode = $null
try {
    [void](Resolve-FoundationGitBinding)
    if ($FoundationCapturePrestate) {
        $head = [string](Get-FoundationGitOutput -Arguments @('rev-parse','HEAD') | Select-Object -First 1)
        $branch = [string](Get-FoundationGitOutput -Arguments @('branch','--show-current') | Select-Object -First 1)
        if ($head -cne $bootstrapContract.BaselineOid -or $branch -cne $bootstrapContract.Branch) {
            throw 'init-precondition: capture repository identity mismatch.'
        }
        New-FoundationExecutionPrestate -LiteralPath $PrestatePath
        $prestateBinding = New-FoundationFileBinding -LiteralPath $PrestatePath -Role 'authority:prestate'
        $script:AuthorityFileBindings.Add($prestateBinding)
        $capturedPrestate = Read-FoundationExecutionPrestate -Binding $prestateBinding
        Assert-FoundationProductionUnchanged -Prestate $capturedPrestate -RequireCapturedIdentity
        Assert-FoundationFileBinding -Binding $prestateBinding
        ConvertTo-PspktCanonicalJson -Value ([ordered]@{
            schemaVersion=3
            schemaId='PspktFoundationPrestateCaptureResultV3'
            mode=$PSCmdlet.ParameterSetName
            allowlistCount=66
            prestateSha256=$prestateBinding.Sha256
        })
        return
    }

    if (-not [IO.File]::Exists($PrestatePath)) { throw 'init-precondition: existing execution prestate is required.' }
    $prestateBinding = New-FoundationFileBinding -LiteralPath $PrestatePath -Role 'authority:prestate'
    $script:AuthorityFileBindings.Add($prestateBinding)
    $prestate = Read-FoundationExecutionPrestate -Binding $prestateBinding
    $prestateSha256 = $prestateBinding.Sha256

    if ($FoundationRecover) {
        $recoveryResult = Invoke-FoundationRecovery -Prestate $prestate -Action $RecoveryAction
        Assert-FoundationFileBinding -Binding $prestateBinding
        ConvertTo-PspktCanonicalJson -Value ([ordered]@{
            schemaVersion=3
            schemaId='PspktFoundationRecoveryResultV1'
            mode=$PSCmdlet.ParameterSetName
            action=$recoveryResult.action
            status=$recoveryResult.status
            completionReceiptPath=$recoveryResult.completionReceiptPath
        })
        return
    }

    $initReceipt = $null
    $initReceiptBytes = $null
    $replayReceipt = $null
    $replayReceiptBytes = $null
    $journal = $null
    if ($FoundationInit) {
        if ([IO.Directory]::Exists($RecoveryJournalPath)) {
            $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
            Assert-FoundationTransactionLayout -Journal $journal
            $completionAuthority = Get-FoundationCompletionAuthorityPath -Journal $journal
            if (Test-FoundationCompletionReceipt -Journal $journal -LiteralPath $completionAuthority) { throw 'init-already' }
            if (@($journal.Operations | Where-Object { $_.Intent.Record.operation -ceq 'RolledBack' -and $null -ne $_.Terminal -and $_.Terminal.Kind -ceq 'applied' }).Count -ne 0) {
                throw 'init-precondition: the Recovery journal is terminal RolledBack; use a fresh Capture and RecoveryJournalPath.'
            }
            throw 'init-recovery-required'
        }
        if ([IO.File]::Exists($InitReceiptPath) -or [IO.File]::Exists($ReplayReceiptPath)) { throw 'init-recovery-required' }
        if (Test-Path -LiteralPath $CompletionReceiptPath) { throw 'init-precondition: Completion receipt destination must be absent.' }
        Assert-FoundationProductionUnchanged -Prestate $prestate -RequireCapturedIdentity
    }
    else {
        if (-not [IO.Directory]::Exists($RecoveryJournalPath)) { throw 'Replay requires an existing Recovery journal.' }
        $journal = Read-FoundationRecoveryJournal -LiteralPath $RecoveryJournalPath
        Assert-FoundationTransactionLayout -Journal $journal
        if ([string]$journal.Header.prestateSha256 -cne $prestateSha256 -or
            [IO.Path]::GetFullPath([string]$journal.Header.initReceiptPath) -cne $InitReceiptPath -or
            [IO.Path]::GetFullPath([string]$journal.Header.replayReceiptPath) -cne $ReplayReceiptPath -or
            [IO.Path]::GetFullPath([string]$journal.Header.requestedCompletionReceiptPath) -cne $CompletionReceiptPath) {
            throw 'Replay authority paths do not match the Recovery journal.'
        }
        if (@($journal.Operations | Where-Object { $null -eq $_.Terminal }).Count -ne 0) { throw 'Replay requires a Recovery journal with no unresolved Intent.' }
        $completionAuthority = Get-FoundationCompletionAuthorityPath -Journal $journal
        if (-not (Test-FoundationCompletionReceipt -Journal $journal -LiteralPath $completionAuthority)) { throw 'Replay requires a valid Completion receipt.' }
        if (-not [IO.File]::Exists($InitReceiptPath) -or -not [IO.File]::Exists($ReplayReceiptPath)) { throw 'Replay requires existing prepared receipts.' }
        $initReceiptBinding = New-FoundationFileBinding -LiteralPath $InitReceiptPath -Role 'authority:init-receipt'
        $replayReceiptBinding = New-FoundationFileBinding -LiteralPath $ReplayReceiptPath -Role 'authority:replay-receipt'
        $script:AuthorityFileBindings.Add($initReceiptBinding)
        $script:AuthorityFileBindings.Add($replayReceiptBinding)
        $initReceiptBytes = [byte[]]$initReceiptBinding.Bytes
        $replayReceiptBytes = [byte[]]$replayReceiptBinding.Bytes
        $initReceipt = Read-FoundationInitReceipt -Binding $initReceiptBinding -PrestateSha256 $prestateSha256
        $replayReceipt = Read-FoundationReplayReceipt -Binding $replayReceiptBinding -PrestateSha256 $prestateSha256 -InitReceiptSha256 $initReceiptBinding.Sha256
        if ([string]$journal.Header.initReceiptSha256 -cne $initReceiptBinding.Sha256 -or [string]$journal.Header.replayReceiptSha256 -cne $replayReceiptBinding.Sha256) {
            throw 'Replay receipt hashes do not match the Recovery journal.'
        }
        if ($isCommittedReplay) {
            $replayMode = 'Committed'
        }
        else {
            $currentEntries = Get-FoundationGitStageRecords -Kind Index
            $isUnstaged = (Get-FoundationCanonicalHash -Value $currentEntries) -ceq (Get-FoundationCanonicalHash -Value $prestate.index.entries)
            $replayMode = if ($isUnstaged) { 'Unstaged' } else { 'Staged' }
        }
        $journal = Assert-FoundationReplayProductionState -Prestate $prestate -ReplayReceipt $replayReceipt -ReplayMode $replayMode -Journal $journal -SelectedCommitOid $SelectedCommitOid -SelectedTreeOid $SelectedTreeOid -SelectedMapBlobOid $SelectedMapBlobOid
    }

    foreach ($directory in @($outputRoot,$promoRoot)) {
        if (Test-Path -LiteralPath $directory) { throw "Owned scratch directory already exists: $directory" }
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    foreach ($relativePath in $bootstrapContract.InputPathSet) {
        $candidatePath = Resolve-FoundationHostPath -Root $SourceRoot -RelativePath $relativePath
        if (-not [IO.File]::Exists($candidatePath)) { throw "Scratch SourceRoot is incomplete: $relativePath" }
    }
    $inputHashes = [ordered]@{}
    foreach ($relativePath in $bootstrapContract.InputPathSet) {
        $sourcePath = Resolve-FoundationHostPath -Root $SourceRoot -RelativePath $relativePath
        $sourceBinding = New-FoundationFileBinding -LiteralPath $sourcePath -Role "candidate:$relativePath"
        $script:CandidateFileBindings.Add($sourceBinding)
        $inputHashes[$relativePath] = $sourceBinding.Sha256
        if ($FoundationReplay -and $sourceBinding.Sha256 -cne [string]$replayReceipt.inputHashes.PSObject.Properties[$relativePath].Value) {
            throw "Replay input hash differs before candidate execution: $relativePath"
        }
    }

    $resolvedPowerShellBindings = Resolve-FoundationPowerShellBindings
    $pwshPath = $resolvedPowerShellBindings.Pwsh.Path
    $powershellPath = $resolvedPowerShellBindings.WindowsPowerShell.Path
    $boundedAssembly = Get-FoundationBoundedProcessAssembly
    if (-not [object]::ReferenceEquals($boundedAssembly,(Get-FoundationBoundedProcessAssembly))) { throw 'BoundedProcess assembly cache did not preserve reference identity.' }
    $childScripts = Write-FoundationChildScripts
    $script:BoundedGitContext = [pscustomobject]@{ Assembly=$boundedAssembly; HostPath=$pwshPath; WrapperPath=$childScripts.Wrapper }

    $contractResultPath = Join-Path $stateRoot 'candidate-contract.v1.json'
    Invoke-FoundationBoundedPowerShell -HelperAssembly $boundedAssembly -HostPath $pwshPath -WrapperPath $childScripts.Wrapper -PayloadPath $childScripts.Contract -PayloadArguments @(
        (Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationContract.ps1'),$canonicalJsonPath,$contractResultPath
    ) -TimeoutMilliseconds 120000 | Out-Null
    $contract = ConvertFrom-FoundationStrictUtf8 -Bytes (Read-FoundationHostBytes -LiteralPath $contractResultPath -MaximumLength $bootstrapContract.CandidateInputFileMaximumBytes) | ConvertFrom-Json
    foreach ($property in @('BaselineOid','Branch','CatalogRelativePath','SchemaRelativePath','MapRelativePath','ExecutionPrestateSchemaId','RecoveryJournalSchemaId','InitReceiptSchemaId','ReplayReceiptSchemaId','CompletionReceiptSchemaId','CandidateInputFileMaximumBytes','CandidateInputAggregateMaximumBytes','PrestateMaximumBytes','AuthorityReceiptFileMaximumBytes','AuthorityReceiptAggregateMaximumBytes','GeneratedOutputFileMaximumBytes','GeneratedOutputAggregateMaximumBytes','GitScalarMaximumBytes','GitNulPathMaximumBytes','GitLogicalProjectionMaximumBytes','GitLogicalProjectionAggregateMaximumBytes','RecoveryJournalSegmentMaximumBytes','RecoveryJournalMaximumBytes','RecoveryJournalMaximumSegments','RecoveryJournalEvidenceReserveBytes','OneAChildContractTimeoutSeconds','OneAEmpiricalRuntimeSeconds','OneASupervisorTimeoutMilliseconds')) {
        if ([string]$contract.$property -cne [string]$bootstrapContract.$property) { throw "Candidate Foundation contract differs from bootstrap authority: $property" }
    }
    if (-not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.InputPathSet) -Actual ([string[]]$contract.InputPathSet)) -or
        -not (Test-FoundationOrdinalStringSetEquality -Expected ([string[]]$bootstrapContract.OutputPathSet) -Actual ([string[]]$contract.OutputPathSet))) {
        throw 'Candidate Foundation path contract differs from bootstrap authority.'
    }

    $compilerPath = $script:BoundedProcessCache.CompilerPath
    $schemaAssemblyPath = Join-Path $stateRoot 'SchemaBootstrap.dll'
    $engineAssemblyPath = Join-Path $stateRoot 'FoundationEngine.dll'
    $verifyAssemblyPath = Join-Path $stateRoot 'FoundationVerify.dll'
    function Invoke-FoundationCompile {
        param([string]$OutputPath,[string]$ReferencePath,[string[]]$Sources)
        $sourceBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-PspktCanonicalJson -Value @($Sources))))
        Invoke-FoundationBoundedPowerShell -HelperAssembly $boundedAssembly -HostPath $pwshPath -WrapperPath $childScripts.Wrapper -PayloadPath $childScripts.Compile -PayloadArguments @($compilerPath,$OutputPath,$ReferencePath,$sourceBase64) -TimeoutMilliseconds 120000 | Out-Null
    }
    Invoke-FoundationCompile -OutputPath $schemaAssemblyPath -ReferencePath '__NONE__' -Sources @($schemaBootstrapSource)
    $script:AssemblyFileBindings.Add((New-FoundationFileBinding -LiteralPath $schemaAssemblyPath -Role 'assembly:SchemaBootstrap'))
    Invoke-FoundationCompile -OutputPath $engineAssemblyPath -ReferencePath $schemaAssemblyPath -Sources @((Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationCatalogEngine.cs'),(Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationPolicy.cs'))
    $script:AssemblyFileBindings.Add((New-FoundationFileBinding -LiteralPath $engineAssemblyPath -Role 'assembly:FoundationEngine'))
    Invoke-FoundationCompile -OutputPath $verifyAssemblyPath -ReferencePath $schemaAssemblyPath -Sources @((Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationVerify.cs'))
    $script:AssemblyFileBindings.Add((New-FoundationFileBinding -LiteralPath $verifyAssemblyPath -Role 'assembly:FoundationVerify'))

    [void](New-FoundationPrivateIndexProof -Mode Generate -GitDirectory (Join-Path $ScratchRoot 'gen.bare.git') -WorkTree $SourceRoot -IndexPath (Join-Path $ScratchRoot 'gen.index') -Paths ([string[]]$contract.InputPathSet))
    $generatorResultPath = Join-Path $stateRoot 'generator-result.v1.json'
    Invoke-FoundationBoundedPowerShell -HelperAssembly $boundedAssembly -HostPath $pwshPath -WrapperPath $childScripts.Wrapper -PayloadPath (Join-Path $SourceRoot 'certification\vectors\New-PspktPhase4SchemaAuthorityFoundationVectors.ps1') -PayloadArguments @(
        $SourceRoot,$outputRoot,$canonicalJsonPath,$schemaAssemblyPath,$engineAssemblyPath,$verifyAssemblyPath,$metaPath,$generatorResultPath
    ) -TimeoutMilliseconds 120000 | Out-Null

    $outputHashes = [ordered]@{}
    foreach ($relativePath in $contract.OutputPathSet) {
        $outputPath = Resolve-FoundationHostPath -Root $outputRoot -RelativePath $relativePath
        if (-not [IO.File]::Exists($outputPath)) { throw "OutputPathSet file missing: $relativePath" }
        $outputBinding = New-FoundationFileBinding -LiteralPath $outputPath -Role "output:$relativePath"
        $script:GeneratedFileBindings.Add($outputBinding)
        $outputHashes[$relativePath] = $outputBinding.Sha256
    }
    foreach ($hostPath in @($pwshPath,$powershellPath)) {
        Invoke-FoundationBoundedPowerShell -HelperAssembly $boundedAssembly -HostPath $hostPath -WrapperPath $childScripts.Wrapper -PayloadPath (Join-Path $SourceRoot 'certification\validators\Test-PspktPhase4SchemaAuthorityFoundation.ps1') -PayloadArguments @(
            $SourceRoot,$outputRoot,$canonicalJsonPath,$schemaAssemblyPath,$engineAssemblyPath,$verifyAssemblyPath,$metaPath
        ) -TimeoutMilliseconds 120000 | Out-Null
    }

    Copy-FoundationPromotionLayout
    foreach ($relativePath in $contract.Allowlist) {
        $script:GeneratedFileBindings.Add((New-FoundationFileBinding -LiteralPath (Resolve-FoundationHostPath -Root $promoRoot -RelativePath $relativePath) -Role "promo:$relativePath"))
    }
    $proofMode = if ($isCommittedReplay) { 'CommittedProof' } else { 'Proof' }
    $proofWorkTree = if ($isCommittedReplay) { Join-Path $ScratchRoot 'committed-proof-work' } else { $promoRoot }
    $proof = New-FoundationPrivateIndexProof -Mode $proofMode -GitDirectory (Join-Path $ScratchRoot 'proof.bare.git') -WorkTree $proofWorkTree -IndexPath (Join-Path $ScratchRoot 'proof.index') -Paths ([string[]]$contract.Allowlist) -SelectedTreeOid $(if($FoundationReplay){[string]$replayReceipt.candidateTreeOid}else{'__GENERATED__'}) -SelectedMapBlobOid $(if($FoundationReplay){[string]$replayReceipt.mapBlobOid}else{'__GENERATED__'}) -SelectedCommitOid $(if($isCommittedReplay){$SelectedCommitOid}else{$null})
    $mapRecord = @($proof.records | Where-Object { $_.path -ceq $contract.MapRelativePath })
    if ($mapRecord.Count -ne 1 -or [string]$proof.resolvedMapOid -cne [string]$mapRecord[0].oid) { throw 'Private proof map OID resolution failed.' }

    $oneASetup = Initialize-FoundationOneA -OneARoot (Join-Path $ScratchRoot 'oneA')
    [IO.File]::WriteAllBytes((Join-Path $stateRoot 'oneA-setup.v1.json'),(Get-PspktCanonicalJsonBytes -Value $oneASetup))
    foreach ($relativePath in $oneASetup.paths) {
        $script:GeneratedFileBindings.Add((New-FoundationFileBinding -LiteralPath (Resolve-FoundationHostPath -Root (Join-Path $ScratchRoot 'oneA') -RelativePath ([string]$relativePath)) -Role "oneA:$relativePath"))
    }
    foreach ($hostPath in @($pwshPath,$powershellPath)) {
        Invoke-FoundationBoundedPowerShell -HelperAssembly $boundedAssembly -HostPath $hostPath -WrapperPath $childScripts.Wrapper -PayloadPath (Join-Path $ScratchRoot 'oneA\certification\validators\Invoke-PspktPhase4SchemaValidators.ps1') -PayloadArguments @() -TimeoutMilliseconds $contract.OneASupervisorTimeoutMilliseconds | Out-Null
    }
    Write-FoundationPrivateOdbManifest

    $catalogHash = $inputHashes[$contract.CatalogRelativePath]
    $schemaHash = $outputHashes[$contract.SchemaRelativePath]
    $mapHash = $outputHashes[$contract.MapRelativePath]
    if ($FoundationReplay) {
        if ([string]$proof.treeOid -cne [string]$replayReceipt.candidateTreeOid -or [string]$proof.resolvedMapOid -cne [string]$replayReceipt.mapBlobOid -or
            $catalogHash -cne [string]$replayReceipt.catalogSha256 -or $schemaHash -cne [string]$replayReceipt.schemaSha256 -or $mapHash -cne [string]$replayReceipt.mapSha256) {
            throw 'Replay proof differs from the verified receipt.'
        }
        foreach ($relativePath in $contract.OutputPathSet) {
            if ($outputHashes[$relativePath] -cne [string]$replayReceipt.outputHashes.PSObject.Properties[$relativePath].Value) { throw "Replay output hash differs: $relativePath" }
        }
        $replayResultPath = Join-Path $stateRoot 'candidate-replay-result.v1.json'
        Invoke-FoundationBoundedPowerShell -HelperAssembly $boundedAssembly -HostPath $pwshPath -WrapperPath $childScripts.Wrapper -PayloadPath $childScripts.Replay -PayloadArguments @(
            $canonicalJsonPath,$schemaAssemblyPath,$engineAssemblyPath,$verifyAssemblyPath,
            (Resolve-FoundationHostPath -Root $SourceRoot -RelativePath $contract.CatalogRelativePath),
            (Resolve-FoundationHostPath -Root $outputRoot -RelativePath $contract.SchemaRelativePath),
            (Resolve-FoundationHostPath -Root $outputRoot -RelativePath $contract.MapRelativePath),
            $replayResultPath
        ) -TimeoutMilliseconds 120000 | Out-Null
        $replayResult = ConvertFrom-FoundationStrictUtf8 -Bytes (Read-FoundationHostBytes -LiteralPath $replayResultPath -MaximumLength $bootstrapContract.AuthorityReceiptFileMaximumBytes) | ConvertFrom-Json
        if (-not [bool]$replayResult.accepted) { throw "Replay failed: $($replayResult.reason)" }
    }
    else {
        $initReceipt = [ordered]@{
            schemaVersion=1
            schemaId=$bootstrapContract.InitReceiptSchemaId
            baselineOid=$contract.BaselineOid
            catalogSha256=$catalogHash
            prestateSha256=$prestateSha256
            nonce=[guid]::NewGuid().ToString('N')
        }
        $initReceiptBytes = Get-PspktCanonicalJsonBytes -Value $initReceipt
        $replayReceipt = [ordered]@{
            schemaVersion=2
            schemaId=$bootstrapContract.ReplayReceiptSchemaId
            candidateTreeOid=[string]$proof.treeOid
            mapBlobOid=[string]$proof.resolvedMapOid
            baselineOid=$contract.BaselineOid
            prestateSha256=$prestateSha256
            initReceiptSha256=(Get-FoundationHostSha256 -Bytes $initReceiptBytes)
            catalogSha256=$catalogHash
            schemaSha256=$schemaHash
            mapSha256=$mapHash
            inputHashes=$inputHashes
            outputHashes=$outputHashes
        }
        $replayReceiptBytes = Get-PspktCanonicalJsonBytes -Value $replayReceipt
        Invoke-FoundationPromotionGate -Prestate $prestate -InitReceiptBytes $initReceiptBytes -InitReceiptDestination $InitReceiptPath -ReplayReceiptBytes $replayReceiptBytes -ReplayReceiptDestination $ReplayReceiptPath -ExpectedAllowlistHashes $replayReceipt
    }

    $effectiveCompletionPath = if ($FoundationReplay) { Get-FoundationCompletionAuthorityPath -Journal $journal } else { $CompletionReceiptPath }
    $resultDocument = [ordered]@{
        schemaVersion=3
        schemaId='PspktFoundationExecutionResultV3'
        mode=$PSCmdlet.ParameterSetName
        InputCount=11
        OutputCount=55
        FixtureCount=52
        CandidateTreeOid=[string]$proof.treeOid
        MapBlobOid=[string]$proof.resolvedMapOid
        CatalogSha256=$catalogHash
        SchemaSha256=$schemaHash
        MapSha256=$mapHash
        InitReceiptPath=$InitReceiptPath
        ReplayReceiptPath=$ReplayReceiptPath
        RecoveryJournalPath=$RecoveryJournalPath
        CompletionReceiptPath=$effectiveCompletionPath
        SelectedCommitOid=$(if($isCommittedReplay){$SelectedCommitOid}else{$null})
        OneAChildContractTimeoutSeconds=$contract.OneAChildContractTimeoutSeconds
        OneAEmpiricalRuntimeSeconds=$contract.OneAEmpiricalRuntimeSeconds
        OneASupervisorTimeoutMilliseconds=$contract.OneASupervisorTimeoutMilliseconds
    }
    Assert-FoundationImmutableBindings
    if ($FoundationReplay) {
        $journal = Assert-FoundationReplayProductionState -Prestate $prestate -ReplayReceipt $replayReceipt -ReplayMode $replayMode -Journal $journal -SelectedCommitOid $SelectedCommitOid -SelectedTreeOid $SelectedTreeOid -SelectedMapBlobOid $SelectedMapBlobOid
        $resultDocument.CompletionReceiptPath = Get-FoundationCompletionAuthorityPath -Journal $journal
    }
    ConvertTo-PspktCanonicalJson -Value $resultDocument
}
finally {
    if ($null -ne $journal -and $null -ne $journal.Lease) { $journal.Lease.Stream.Dispose() }
    foreach ($binding in @($script:AssemblyFileBindings) + @($script:GeneratedFileBindings) + @($script:CandidateFileBindings) + @($script:BootstrapFileBindings) + @($script:AuthorityFileBindings)) {
        if ($null -ne $binding.Stream) { $binding.Stream.Dispose() }
    }
    $script:AssemblyFileBindings.Clear()
    $script:GeneratedFileBindings.Clear()
    $script:CandidateFileBindings.Clear()
    $script:BootstrapFileBindings.Clear()
    $script:AuthorityFileBindings.Clear()
    if ($null -ne $script:BoundedProcessCache -and $null -ne $script:BoundedProcessCache.CompilerStream) { $script:BoundedProcessCache.CompilerStream.Dispose() }
    if ($null -ne $script:BoundedProcessCache -and $null -ne $script:BoundedProcessCache.DllStream) { $script:BoundedProcessCache.DllStream.Dispose() }
    if ($script:PowerShellBindings -is [Collections.IDictionary]) {
        foreach ($entry in $script:PowerShellBindings.GetEnumerator()) {
            if ($null -ne $entry.Value.Stream) { $entry.Value.Stream.Dispose() }
        }
    }
    $script:PowerShellBindings = @{}
    $script:RawLaunchAuthority = $null
    if ($null -ne $script:GitBinding -and $null -ne $script:GitBinding.Stream) { $script:GitBinding.Stream.Dispose() }
    $script:GitBinding = $null
    if ($null -ne $script:FoundationHostBinding) {
        foreach ($streamName in @('CompilerStream','SourceStream','DllStream')) {
            if ($null -ne $script:FoundationHostBinding.$streamName) { $script:FoundationHostBinding.$streamName.Dispose() }
        }
    }
    $script:FoundationHostBinding = $null
}
