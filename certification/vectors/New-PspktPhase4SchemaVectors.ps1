[CmdletBinding(DefaultParameterSetName = 'Standalone')]
param(
    [Parameter(ParameterSetName = 'Standalone', Mandatory = $false)]
    [Parameter(ParameterSetName = 'Contained', Mandatory = $false)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$SelfTest,

    [Parameter(ParameterSetName = 'Contained', Mandatory = $true)]
    [ValidateScript({ $_.IsPresent })]
    [switch]$Contained
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isContainedMode = ($PSCmdlet.ParameterSetName -ceq 'Contained')

function Test-Phase4TryGetPathAttributes {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ref]$Attributes,
        [AllowNull()][scriptblock]$AttributeReader = $null
    )

    try {
        if ($null -eq $AttributeReader) {
            $resolvedAttributes = [System.IO.File]::GetAttributes($Path)
        }
        else {
            $resolvedAttributes = & $AttributeReader $Path
        }
    }
    catch {
        $pathException = $_.Exception
        while ($pathException -is [System.Management.Automation.MethodInvocationException] -and
            $null -ne $pathException.InnerException) {
            $pathException = $pathException.InnerException
        }
        if ($pathException -is [System.IO.FileNotFoundException] -or
            $pathException -is [System.IO.DirectoryNotFoundException]) {
            $Attributes.Value = [System.IO.FileAttributes]0
            return $false
        }
        throw
    }

    $Attributes.Value = [System.IO.FileAttributes]$resolvedAttributes
    return $true
}

function Assert-Phase4MissingLeaf {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][scriptblock]$AttributeReader = $null
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $currentPath = $pathRoot
    $rootAttributes = [System.IO.FileAttributes]0
    if (Test-Phase4TryGetPathAttributes -Path $currentPath -Attributes ([ref]$rootAttributes) -AttributeReader $AttributeReader) {
        if (($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('generator: path root "{0}" is a reparse point.' -f $currentPath)
        }
    }
    $relativePath = $fullPath.Substring($pathRoot.Length)
    $pathSeparators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $pathComponents = @($relativePath.Split($pathSeparators, [System.StringSplitOptions]::RemoveEmptyEntries))
    for ($pathComponentIndex = 0; $pathComponentIndex -lt ($pathComponents.Count - 1); $pathComponentIndex++) {
        $currentPath = [System.IO.Path]::Combine($currentPath, $pathComponents[$pathComponentIndex])
        $ancestorAttributes = [System.IO.FileAttributes]0
        if (Test-Phase4TryGetPathAttributes -Path $currentPath -Attributes ([ref]$ancestorAttributes) -AttributeReader $AttributeReader) {
            if (($ancestorAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('generator: path component "{0}" is a reparse point.' -f $currentPath)
            }
        }
    }
    $leafAttributes = [System.IO.FileAttributes]0
    if (Test-Phase4TryGetPathAttributes -Path $fullPath -Attributes ([ref]$leafAttributes) -AttributeReader $AttributeReader) {
        throw ('generator: output leaf "{0}" already exists.' -f $fullPath)
    }
    return $fullPath
}

if ($isContainedMode) {
    $containedReservedNames = @(
        'PSPKT_PHASE4_SNAPSHOT_ROOT',
        'PSPKT_PHASE4_REPOSITORY_ROOT',
        'PSPKT_PHASE4_GENERATOR_TARGET_ROOT',
        'PSPKT_PHASE4_GENERATOR_RESULT_PATH',
        'PSPKT_PHASE4_GENERATOR_NONCE',
        'PSPKT_PHASE4_GENERATOR_SOURCE_SHA256',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_ROOT',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED',
        'PSPKT_PHASE4_GENERATOR_HARDLINK_PRE_RESULT'
    )
    $containedReserved = @{}
    foreach ($containedReservedName in $containedReservedNames) {
        $containedReservedValue = [Environment]::GetEnvironmentVariable($containedReservedName)
        if ([string]::IsNullOrEmpty($containedReservedValue)) { exit 20 }
        $containedReserved[$containedReservedName] = $containedReservedValue
    }
    if (-not [regex]::IsMatch($containedReserved['PSPKT_PHASE4_GENERATOR_NONCE'], '^[0-9a-f]{32}$')) { exit 20 }
    if (-not [regex]::IsMatch($containedReserved['PSPKT_PHASE4_GENERATOR_SOURCE_SHA256'], '^[0-9a-f]{64}$')) { exit 20 }
    foreach ($containedEventEnvName in @(
            'PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED',
            'PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED')) {
        if (-not [regex]::IsMatch($containedReserved[$containedEventEnvName], '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$')) { exit 20 }
    }
    foreach ($containedRootName in @(
            'PSPKT_PHASE4_SNAPSHOT_ROOT',
            'PSPKT_PHASE4_GENERATOR_TARGET_ROOT',
            'PSPKT_PHASE4_GENERATOR_HARDLINK_ROOT')) {
        $containedRootValue = $containedReserved[$containedRootName]
        if ($containedRootValue -cne [System.IO.Path]::GetFullPath($containedRootValue)) { exit 20 }
        if (-not [System.IO.Directory]::Exists($containedRootValue)) { exit 20 }
    }
    foreach ($containedLeafName in @(
            'PSPKT_PHASE4_GENERATOR_RESULT_PATH',
            'PSPKT_PHASE4_GENERATOR_HARDLINK_PRE_RESULT')) {
        $containedLeafValue = $containedReserved[$containedLeafName]
        if ($containedLeafValue -cne [System.IO.Path]::GetFullPath($containedLeafValue)) { exit 20 }
        try {
            [void](Assert-Phase4MissingLeaf -Path $containedLeafValue)
        }
        catch {
            exit 20
        }
        $containedLeafParent = [System.IO.Path]::GetDirectoryName($containedLeafValue)
        if ([string]::IsNullOrEmpty($containedLeafParent) -or -not [System.IO.Directory]::Exists($containedLeafParent)) { exit 20 }
    }

    $repoRoot = $containedReserved['PSPKT_PHASE4_SNAPSHOT_ROOT']
    $certRoot = Join-Path $repoRoot 'certification'
    $publishRoot = $containedReserved['PSPKT_PHASE4_GENERATOR_TARGET_ROOT']
    $publishCertRoot = Join-Path $publishRoot 'certification'
    $generatorNonce = $containedReserved['PSPKT_PHASE4_GENERATOR_NONCE']
    $generatorResultPath = $containedReserved['PSPKT_PHASE4_GENERATOR_RESULT_PATH']
    $generatorHardlinkRoot = $containedReserved['PSPKT_PHASE4_GENERATOR_HARDLINK_ROOT']
    $generatorHardlinkPreparedName = $containedReserved['PSPKT_PHASE4_GENERATOR_HARDLINK_PREPARED']
    $generatorHardlinkAuthorizedName = $containedReserved['PSPKT_PHASE4_GENERATOR_HARDLINK_AUTHORIZED']
    $generatorHardlinkPreResultPath = $containedReserved['PSPKT_PHASE4_GENERATOR_HARDLINK_PRE_RESULT']
}
else {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $certRoot = Split-Path -Parent $here
    $repoRoot = Split-Path -Parent $certRoot
    $publishRoot = $repoRoot
    $publishCertRoot = $certRoot
}

$sourceCertRoot = $certRoot
$sourceRepoRoot = $repoRoot
$libDir = Join-Path $certRoot 'lib'
. (Join-Path $libDir 'Pspkt.Certification.CanonicalJson.ps1')
. (Join-Path $libDir 'Pspkt.Certification.SchemaFixtureContract.ps1')

if (-not ([System.Management.Automation.PSTypeName]'Pspkt.Certification.Phase4.AtomicFile').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Pspkt.Certification.Phase4
{
    public static class AtomicFile
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int fileInformationClass, out FILE_ID_INFO fileInformation, uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int fileInformationClass, IntPtr fileInformation, uint bufferSize);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ID_INFO
        {
            public ulong VolumeSerialNumber;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] FileId;
        }

        private const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
        private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
        private const uint DELETE = 0x00010000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const int FileIdInfo = 18;
        private const int FileRenameInfoEx = 22;
        private const int FILE_RENAME_FLAG_REPLACE_IF_EXISTS = 0x00000001;
        private const int FILE_RENAME_FLAG_POSIX_SEMANTICS = 0x00000002;

        public static void ReplaceExisting(string source, string destination)
        {
            if (!MoveFileExW(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "MoveFileExW REPLACE_EXISTING failed for '" + destination + "'.");
            }
        }

        public static void MoveNew(string source, string destination)
        {
            if (!MoveFileExW(source, destination, MOVEFILE_WRITE_THROUGH))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "MoveFileExW create failed for '" + destination + "'.");
            }
        }

        public static void CreateHardLink(string linkPath, string existingPath)
        {
            if (!CreateHardLinkW(linkPath, existingPath, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateHardLinkW failed for '" + linkPath + "'.");
            }
        }

        public static void ReplaceExistingPosix(string source, string destination)
        {
            using (SafeFileHandle handle = CreateFileW(
                source,
                DELETE | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(DELETE) failed for '" + source + "'.");
                }
                byte[] nameBytes = Encoding.Unicode.GetBytes(destination);
                int pointerSize = IntPtr.Size;
                int rootDirectoryOffset = pointerSize;
                int fileNameLengthOffset = rootDirectoryOffset + pointerSize;
                int fileNameOffset = fileNameLengthOffset + 4;
                int total = fileNameOffset + nameBytes.Length + 2;
                IntPtr buffer = Marshal.AllocHGlobal(total);
                try
                {
                    for (int index = 0; index < total; index++)
                    {
                        Marshal.WriteByte(buffer, index, 0);
                    }
                    Marshal.WriteInt32(buffer, 0, FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS);
                    Marshal.WriteIntPtr(buffer, rootDirectoryOffset, IntPtr.Zero);
                    Marshal.WriteInt32(buffer, fileNameLengthOffset, nameBytes.Length);
                    Marshal.Copy(nameBytes, 0, new IntPtr(buffer.ToInt64() + fileNameOffset), nameBytes.Length);
                    if (!SetFileInformationByHandle(handle, FileRenameInfoEx, buffer, (uint)total))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetFileInformationByHandle(FileRenameInfoEx) failed replacing '" + destination + "'.");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        public static string GetFileId48(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for '" + path + "'.");
                }
                FILE_ID_INFO information;
                uint size = (uint)Marshal.SizeOf(typeof(FILE_ID_INFO));
                if (!GetFileInformationByHandleEx(handle, FileIdInfo, out information, size))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandleEx(FileIdInfo) failed for '" + path + "'.");
                }
                StringBuilder builder = new StringBuilder(48);
                builder.Append(information.VolumeSerialNumber.ToString("x16", CultureInfo.InvariantCulture));
                for (int index = 0; index < information.FileId.Length; index++)
                {
                    builder.Append(information.FileId[index].ToString("x2", CultureInfo.InvariantCulture));
                }
                return builder.ToString();
            }
        }
    }
}
'@
}

function Invoke-Phase4ContainedHardlinkHandshake {
    param(
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$HardlinkRoot,
        [Parameter(Mandatory = $true)][string]$PreparedEventName,
        [Parameter(Mandatory = $true)][string]$AuthorizedEventName,
        [Parameter(Mandatory = $true)][string]$PreResultPath
    )
    $driveRoot = [System.IO.Path]::GetPathRoot($HardlinkRoot)
    $drive = [System.IO.DriveInfo]::new($driveRoot)
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or
        @('NTFS', 'ReFS') -cnotcontains $drive.DriveFormat) {
        throw ('generator self-test: contained hard-link root requires fixed NTFS/ReFS, found {0}/{1}.' -f $drive.DriveType, $drive.DriveFormat)
    }
    $sourceLeaf = 'src-' + $Nonce + '.bin'
    $linkLeaf = 'link-' + $Nonce + '.bin'
    $sourcePath = [System.IO.Path]::Combine($HardlinkRoot, $sourceLeaf)
    $linkPath = [System.IO.Path]::Combine($HardlinkRoot, $linkLeaf)

    $sourcePreBytes = [byte[]](1, 2, 3)
    [void](Assert-Phase4MissingLeaf -Path $sourcePath)
    $sourceStream = [System.IO.File]::Open($sourcePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $sourceStream.Write($sourcePreBytes, 0, $sourcePreBytes.Length)
        $sourceStream.Flush($true)
    }
    finally {
        $sourceStream.Dispose()
    }

    [Pspkt.Certification.Phase4.AtomicFile]::CreateHardLink($linkPath, $sourcePath)

    $sourcePreFileId = [Pspkt.Certification.Phase4.AtomicFile]::GetFileId48($sourcePath)
    $linkPreFileId = [Pspkt.Certification.Phase4.AtomicFile]::GetFileId48($linkPath)
    $sourcePreLength = [long]$sourcePreBytes.Length
    $sourcePreSha = Get-PspktSha256Hex -Bytes $sourcePreBytes

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $tab = [char]0x09
    $preRecord = 'pspkt-phase4-hardlink-pre-v1' + $tab + $Nonce + $tab + $sourceLeaf + $tab + $linkLeaf + $tab +
        $sourcePreFileId + $tab + $linkPreFileId + $tab +
        $sourcePreLength.ToString($invariant) + $tab + $sourcePreSha + [char]0x0A
    $preBytes = [System.Text.Encoding]::ASCII.GetBytes($preRecord)
    [void](Assert-Phase4MissingLeaf -Path $PreResultPath)
    $preStream = [System.IO.File]::Open($PreResultPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $preStream.Write($preBytes, 0, $preBytes.Length)
        $preStream.Flush($true)
    }
    finally {
        $preStream.Dispose()
    }

    $preparedEvent = [System.Threading.EventWaitHandle]::OpenExisting($PreparedEventName)
    $authorizedEvent = $null
    try {
        $authorizedEvent = [System.Threading.EventWaitHandle]::OpenExisting($AuthorizedEventName)
        [void]$preparedEvent.Set()
        if (-not $authorizedEvent.WaitOne(30000)) {
            throw 'generator self-test: hard-link replacement authorization timed out.'
        }
    }
    finally {
        if ($null -ne $authorizedEvent) { $authorizedEvent.Dispose() }
        $preparedEvent.Dispose()
    }

    $sourcePostBytes = [byte[]](9, 9, 9, 9)
    $replacementSibling = [System.IO.Path]::Combine($HardlinkRoot, ('replace-' + $Nonce + '.tmp'))
    [void](Assert-Phase4MissingLeaf -Path $replacementSibling)
    $replacementStream = [System.IO.File]::Open($replacementSibling, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $replacementStream.Write($sourcePostBytes, 0, $sourcePostBytes.Length)
        $replacementStream.Flush($true)
    }
    finally {
        $replacementStream.Dispose()
    }
    [Pspkt.Certification.Phase4.AtomicFile]::ReplaceExistingPosix($replacementSibling, $sourcePath)

    $sourcePostBytesOnDisk = [System.IO.File]::ReadAllBytes($sourcePath)
    if ((Get-PspktSha256Hex -Bytes $sourcePostBytesOnDisk) -cne
        (Get-PspktSha256Hex -Bytes $sourcePostBytes)) {
        throw 'generator self-test: source path does not contain the replacement bytes.'
    }
    $sourcePostFileId = [Pspkt.Certification.Phase4.AtomicFile]::GetFileId48($sourcePath)
    $linkPostFileId = [Pspkt.Certification.Phase4.AtomicFile]::GetFileId48($linkPath)
    $sourcePostLength = [long]$sourcePostBytesOnDisk.Length
    $sourcePostSha = Get-PspktSha256Hex -Bytes $sourcePostBytesOnDisk
    $linkPostBytes = [System.IO.File]::ReadAllBytes($linkPath)
    $linkPostLength = [long]$linkPostBytes.Length
    $linkPostSha = Get-PspktSha256Hex -Bytes $linkPostBytes

    if ($sourcePreFileId -cne $linkPreFileId -or $linkPostFileId -cne $sourcePreFileId) {
        throw 'generator self-test: hard-link pre/link file identity diverged before replacement.'
    }
    if ($sourcePostFileId -ceq $linkPostFileId) {
        throw 'generator self-test: hard-link post-replacement identity did not diverge.'
    }
    if ($linkPostSha -cne $sourcePreSha -or $linkPostLength -ne $sourcePreLength) {
        throw 'generator self-test: retained hard-link content changed after replacement.'
    }
    if ($sourcePostSha -ceq $linkPostSha -and $sourcePostLength -eq $linkPostLength) {
        throw 'generator self-test: replacement content did not diverge from the retained link.'
    }

    return [pscustomobject]@{
        SourceLeaf       = $sourceLeaf
        LinkLeaf         = $linkLeaf
        SourcePreFileId  = $sourcePreFileId
        LinkPreFileId    = $linkPreFileId
        SourcePreLength  = $sourcePreLength
        SourcePreSha     = $sourcePreSha
        SourcePostFileId = $sourcePostFileId
        LinkPostFileId   = $linkPostFileId
        SourcePostLength = $sourcePostLength
        SourcePostSha    = $sourcePostSha
        LinkPostLength   = $linkPostLength
        LinkPostSha      = $linkPostSha
        Passed           = $true
    }
}

$script:ContainedHardlinkRecord = $null
if ($isContainedMode) {
    $script:ContainedHardlinkRecord = Invoke-Phase4ContainedHardlinkHandshake `
        -Nonce $generatorNonce `
        -HardlinkRoot $generatorHardlinkRoot `
        -PreparedEventName $generatorHardlinkPreparedName `
        -AuthorizedEventName $generatorHardlinkAuthorizedName `
        -PreResultPath $generatorHardlinkPreResultPath
}

$phase4Prefix = 'certification/vectors/phase4-schema/'
$metaRepoPath = 'certification/schema/protocol-schema-meta.v1.json'
$metaFullPath = Join-Path $sourceCertRoot 'schema\protocol-schema-meta.v1.json'

$script:phase4Files = [System.Collections.Generic.List[object]]::new()
$script:phase4Cases = [System.Collections.Generic.List[object]]::new()

function Write-Phase4Fixture {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    $script:phase4Files.Add([pscustomobject]@{
            RelativePath = $RelativePath
            RepoPath     = ($phase4Prefix + $RelativePath)
            Bytes        = $Bytes
        })
}

function Add-Phase4Case {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RepoPath,
        [Parameter(Mandatory = $true)][ValidateSet('json', 'bootstrap-meta', 'schema-against-meta')][string]$Stage,
        [Parameter(Mandatory = $true)][string]$ExpectedReason
    )
    if ($ExpectedReason -ceq 'ok') {
        $outcome = 'accepted'
    }
    else {
        $outcome = 'rejected'
    }
    $script:phase4Cases.Add([pscustomobject]@{
            Ordinal        = $script:phase4Cases.Count
            Name           = $Name
            Path           = $RepoPath
            Stage          = $Stage
            Outcome        = $outcome
            ExpectedReason = $ExpectedReason
        })
}

function Add-Phase4Text {
    param(
        [Parameter(Mandatory = $true)]$Builder,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )
    foreach ($byte in [System.Text.Encoding]::UTF8.GetBytes($Text)) {
        [void]$Builder.Add($byte)
    }
}

function Add-Phase4Byte {
    param(
        [Parameter(Mandatory = $true)]$Builder,
        [Parameter(Mandatory = $true)][int]$Value
    )
    [void]$Builder.Add([byte]$Value)
}

function Add-Phase4RawCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$ExpectedReason
    )
    Write-Phase4Fixture -RelativePath $RelativePath -Bytes $Bytes
    Add-Phase4Case -Name $Name -RepoPath ($phase4Prefix + $RelativePath) -Stage 'json' -ExpectedReason $ExpectedReason
}

function Add-Phase4TextCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$ExpectedReason
    )
    Add-Phase4RawCase -Name $Name -RelativePath $RelativePath -Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text)) -ExpectedReason $ExpectedReason
}

function Add-Phase4DocumentCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][ValidateSet('bootstrap-meta', 'schema-against-meta')][string]$Stage,
        [Parameter(Mandatory = $true)][string]$ExpectedReason
    )
    Write-Phase4Fixture -RelativePath $RelativePath -Bytes (Get-PspktCanonicalJsonBytes -Value $Value)
    Add-Phase4Case -Name $Name -RepoPath ($phase4Prefix + $RelativePath) -Stage $Stage -ExpectedReason $ExpectedReason
}

function New-Phase4PaddedDocument {
    param([Parameter(Mandatory = $true)][int]$TotalBytes)
    $segmentLength = 200000
    $segments = 5
    $tailLength = $TotalBytes - (($segments * ($segmentLength + 3)) + 12)
    if ($tailLength -lt 1 -or $tailLength -gt 262144) {
        throw ('New-Phase4PaddedDocument: unusable tail length {0}.' -f $tailLength)
    }
    $builder = [System.Text.StringBuilder]::new($TotalBytes)
    [void]$builder.Append('{"pad":[')
    for ($index = 0; $index -lt $segments; $index++) {
        [void]$builder.Append('"')
        [void]$builder.Append([char]'a', $segmentLength)
        [void]$builder.Append('",')
    }
    [void]$builder.Append('"')
    [void]$builder.Append([char]'a', $tailLength)
    [void]$builder.Append('"]}')
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($builder.ToString())
    if ($bytes.Length -ne $TotalBytes) {
        throw ('New-Phase4PaddedDocument: produced {0} bytes, expected {1}.' -f $bytes.Length, $TotalBytes)
    }
    return , $bytes
}

function New-Phase4AllocationDocument {
    param([Parameter(Mandatory = $true)][long]$TargetBudget)
    $outerCount = 5000
    $innerCount = 20
    $padLength = $TargetBudget - 94 - (18 * [long]$outerCount * ($innerCount + 1))
    if ($padLength -lt 1 -or $padLength -gt 262144) {
        throw ('New-Phase4AllocationDocument: unusable pad length {0}.' -f $padLength)
    }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('{"n":[')
    for ($outer = 0; $outer -lt $outerCount; $outer++) {
        if ($outer -gt 0) { [void]$builder.Append(',') }
        [void]$builder.Append('[')
        for ($inner = 0; $inner -lt $innerCount; $inner++) {
            if ($inner -gt 0) { [void]$builder.Append(',') }
            [void]$builder.Append('0')
        }
        [void]$builder.Append(']')
    }
    [void]$builder.Append('],"p":"')
    [void]$builder.Append([char]'a', [int]$padLength)
    [void]$builder.Append('"}')
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($builder.ToString())
    $nodeCount = 5 + ([long]$outerCount * ($innerCount + 1))
    $observed = [long]$bytes.Length + (16 * $nodeCount)
    if ($observed -ne $TargetBudget) {
        throw ('New-Phase4AllocationDocument: produced budget {0}, expected {1}.' -f $observed, $TargetBudget)
    }
    return , $bytes
}

function New-Phase4NestedArrays {
    param([Parameter(Mandatory = $true)][int]$Depth)
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append([char]'[', $Depth)
    [void]$builder.Append([char]']', $Depth)
    return , ([System.Text.Encoding]::ASCII.GetBytes($builder.ToString()))
}

function New-Phase4WideObject {
    param([Parameter(Mandatory = $true)][int]$PropertyCount)
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('{')
    for ($index = 0; $index -lt $PropertyCount; $index++) {
        if ($index -gt 0) { [void]$builder.Append(',') }
        [void]$builder.Append('"p')
        [void]$builder.Append($index.ToString('D4', [System.Globalization.CultureInfo]::InvariantCulture))
        [void]$builder.Append('":0')
    }
    [void]$builder.Append('}')
    return , ([System.Text.Encoding]::ASCII.GetBytes($builder.ToString()))
}

function New-Phase4WideArray {
    param([Parameter(Mandatory = $true)][int]$ItemCount)
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('[')
    for ($index = 0; $index -lt $ItemCount; $index++) {
        if ($index -gt 0) { [void]$builder.Append(',') }
        [void]$builder.Append('0')
    }
    [void]$builder.Append(']')
    return , ([System.Text.Encoding]::ASCII.GetBytes($builder.ToString()))
}

function New-Phase4LongString {
    param([Parameter(Mandatory = $true)][int]$DecodedBytes)
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('{"s":"')
    [void]$builder.Append([char]'a', $DecodedBytes)
    [void]$builder.Append('"}')
    return , ([System.Text.Encoding]::ASCII.GetBytes($builder.ToString()))
}

function Copy-Phase4Document {
    param([Parameter(Mandatory = $true)]$Value)
    return ((ConvertTo-PspktCanonicalJson -Value $Value) | ConvertFrom-Json)
}

function New-Phase4SchemaDocument {
    param(
        [Parameter(Mandatory = $true)][string]$SchemaId,
        [Parameter(Mandatory = $true)][object[]]$Types
    )
    return [ordered]@{ schemaVersion = 1; schemaId = $SchemaId; types = $Types }
}

function New-Phase4Field {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$FieldId,
        [Parameter(Mandatory = $true)][string]$Type,
        $MaxCodeUnits,
        $MaxBytes
    )
    $field = [ordered]@{ name = $Name; fieldId = $FieldId; type = $Type }
    if ($PSBoundParameters.ContainsKey('MaxCodeUnits')) { $field['maxCodeUnits'] = $MaxCodeUnits }
    if ($PSBoundParameters.ContainsKey('MaxBytes')) { $field['maxBytes'] = $MaxBytes }
    return $field
}

function New-Phase4FieldLimitDocument {
    param(
        [Parameter(Mandatory = $true)][string]$SchemaId,
        [Parameter(Mandatory = $true)][int]$FieldCount
    )
    $fields = [object[]]::new($FieldCount)
    for ($index = 0; $index -lt $FieldCount; $index++) {
        $fields[$index] = New-Phase4Field -Name ('Field{0:D4}' -f ($index + 1)) -FieldId ($index + 1) -Type 'U8'
    }
    return New-Phase4SchemaDocument -SchemaId $SchemaId -Types @(
        [ordered]@{ production = 'Named'; name = 'FieldLimitRecord'; typeId = 1; fields = $fields }
    )
}

function New-Phase4TypeLimitDocument {
    param(
        [Parameter(Mandatory = $true)][string]$SchemaId,
        [Parameter(Mandatory = $true)][int]$TypeCount
    )
    $types = [object[]]::new($TypeCount)
    for ($index = 0; $index -lt $TypeCount; $index++) {
        $types[$index] = [ordered]@{
            production = 'Named'
            name       = 'Type{0:D4}' -f ($index + 1)
            typeId     = $index + 1
            fields     = @((New-Phase4Field -Name 'Value' -FieldId 1 -Type 'U8'))
        }
    }
    return New-Phase4SchemaDocument -SchemaId $SchemaId -Types $types
}

Add-Phase4TextCase -Name 'JsonValidUnicodeValue' -RelativePath 'json/valid-unicode-value.json' -ExpectedReason 'ok' `
    -Text ('{{"note":"h{0}llo{1}","count":1024}}' -f ([char]0x00E9), ([char]0x2713))

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Text $fixture '{"a":"'
Add-Phase4Byte $fixture 0xC3
Add-Phase4Byte $fixture 0x28
Add-Phase4Text $fixture '"}'
Add-Phase4RawCase -Name 'JsonMalformedUtf8' -RelativePath 'json/malformed-utf8.json' -Bytes $fixture.ToArray() -ExpectedReason 'invalid-utf8'

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Text $fixture '{"a":"'
Add-Phase4Byte $fixture 0xC0
Add-Phase4Byte $fixture 0xAF
Add-Phase4Text $fixture '"}'
Add-Phase4RawCase -Name 'JsonOverlongUtf8' -RelativePath 'json/overlong-utf8.json' -Bytes $fixture.ToArray() -ExpectedReason 'invalid-utf8'

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Byte $fixture 0xEF
Add-Phase4Byte $fixture 0xBB
Add-Phase4Byte $fixture 0xBF
Add-Phase4Text $fixture '{"a":1}'
Add-Phase4RawCase -Name 'JsonByteOrderMark' -RelativePath 'json/byte-order-mark.json' -Bytes $fixture.ToArray() -ExpectedReason 'bom-forbidden'

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Text $fixture '{"a":"'
Add-Phase4Byte $fixture 0x00
Add-Phase4Text $fixture '"}'
Add-Phase4RawCase -Name 'JsonNulByte' -RelativePath 'json/nul-byte.json' -Bytes $fixture.ToArray() -ExpectedReason 'nul-forbidden'

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Text $fixture '{//comment'
Add-Phase4Byte $fixture 0x0A
Add-Phase4Text $fixture '"a":1}'
Add-Phase4RawCase -Name 'JsonLineComment' -RelativePath 'json/line-comment.json' -Bytes $fixture.ToArray() -ExpectedReason 'comment-forbidden'

Add-Phase4TextCase -Name 'JsonBlockComment' -RelativePath 'json/block-comment.json' -Text '{/*comment*/"a":1}' -ExpectedReason 'comment-forbidden'
Add-Phase4TextCase -Name 'JsonDuplicateKey' -RelativePath 'json/duplicate-key.json' -Text '{"a":1,"a":2}' -ExpectedReason 'duplicate-key'
Add-Phase4TextCase -Name 'JsonTrailingCommaObject' -RelativePath 'json/trailing-comma-object.json' -Text '{"a":1,}' -ExpectedReason 'trailing-comma'
Add-Phase4TextCase -Name 'JsonTrailingCommaArray' -RelativePath 'json/trailing-comma-array.json' -Text '[1,2,]' -ExpectedReason 'trailing-comma'

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Text $fixture '{"a":1}'
Add-Phase4Byte $fixture 0x0A
Add-Phase4RawCase -Name 'JsonTrailingNewline' -RelativePath 'json/trailing-newline.json' -Bytes $fixture.ToArray() -ExpectedReason 'trailing-data'

Add-Phase4TextCase -Name 'JsonTrailingData' -RelativePath 'json/trailing-data.json' -Text '{"a":1}{}' -ExpectedReason 'trailing-data'
Add-Phase4TextCase -Name 'JsonFloatValue' -RelativePath 'json/float-value.json' -Text '{"a":1.5}' -ExpectedReason 'float-forbidden'
Add-Phase4TextCase -Name 'JsonExponentValue' -RelativePath 'json/exponent-value.json' -Text '{"a":1e3}' -ExpectedReason 'exponent-forbidden'
Add-Phase4TextCase -Name 'JsonNegativeInteger' -RelativePath 'json/negative-integer.json' -Text '{"a":-1}' -ExpectedReason 'negative-integer'
Add-Phase4TextCase -Name 'JsonLeadingZeroInteger' -RelativePath 'json/leading-zero-integer.json' -Text '{"a":01}' -ExpectedReason 'leading-zero-integer'
Add-Phase4TextCase -Name 'JsonIntegerOverflow' -RelativePath 'json/integer-overflow.json' -Text '{"a":18446744073709551616}' -ExpectedReason 'integer-overflow'
Add-Phase4TextCase -Name 'JsonInvalidEscape' -RelativePath 'json/invalid-escape.json' -Text '{"a":"\q"}' -ExpectedReason 'invalid-escape'
Add-Phase4TextCase -Name 'JsonUnpairedSurrogate' -RelativePath 'json/unpaired-surrogate.json' -Text '{"a":"\uD800"}' -ExpectedReason 'unpaired-surrogate'

Add-Phase4RawCase -Name 'JsonFileLimitExact' -RelativePath 'json/file-limit-exact.json' -Bytes (New-Phase4PaddedDocument -TotalBytes 1048576) -ExpectedReason 'ok'
Add-Phase4RawCase -Name 'JsonFileLimitOver' -RelativePath 'json/file-limit-over.json' -Bytes (New-Phase4PaddedDocument -TotalBytes 1048577) -ExpectedReason 'file-limit'
Add-Phase4RawCase -Name 'JsonDepthLimitExact' -RelativePath 'json/depth-limit-exact.json' -Bytes (New-Phase4NestedArrays -Depth 32) -ExpectedReason 'ok'
Add-Phase4RawCase -Name 'JsonDepthLimitOver' -RelativePath 'json/depth-limit-over.json' -Bytes (New-Phase4NestedArrays -Depth 33) -ExpectedReason 'depth-limit'
Add-Phase4RawCase -Name 'JsonPropertyLimitExact' -RelativePath 'json/property-limit-exact.json' -Bytes (New-Phase4WideObject -PropertyCount 4096) -ExpectedReason 'ok'
Add-Phase4RawCase -Name 'JsonPropertyLimitOver' -RelativePath 'json/property-limit-over.json' -Bytes (New-Phase4WideObject -PropertyCount 4097) -ExpectedReason 'property-limit'
Add-Phase4RawCase -Name 'JsonArrayLimitExact' -RelativePath 'json/array-limit-exact.json' -Bytes (New-Phase4WideArray -ItemCount 8192) -ExpectedReason 'ok'
Add-Phase4RawCase -Name 'JsonArrayLimitOver' -RelativePath 'json/array-limit-over.json' -Bytes (New-Phase4WideArray -ItemCount 8193) -ExpectedReason 'array-limit'
Add-Phase4RawCase -Name 'JsonStringLimitExact' -RelativePath 'json/string-limit-exact.json' -Bytes (New-Phase4LongString -DecodedBytes 262144) -ExpectedReason 'ok'
Add-Phase4RawCase -Name 'JsonStringLimitOver' -RelativePath 'json/string-limit-over.json' -Bytes (New-Phase4LongString -DecodedBytes 262145) -ExpectedReason 'string-limit'
Add-Phase4RawCase -Name 'JsonAllocationBudgetExact' -RelativePath 'json/allocation-budget-exact.json' -Bytes (New-Phase4AllocationDocument -TargetBudget 2097152) -ExpectedReason 'ok'
Add-Phase4RawCase -Name 'JsonAllocationBudgetOver' -RelativePath 'json/allocation-budget-over.json' -Bytes (New-Phase4AllocationDocument -TargetBudget 2097153) -ExpectedReason 'allocation-budget'

$fixture = [System.Collections.Generic.List[byte]]::new()
Add-Phase4Text $fixture '{"a":"'
Add-Phase4Byte $fixture 0xEF
Add-Phase4Byte $fixture 0xBF
Add-Phase4Byte $fixture 0xBD
Add-Phase4Text $fixture '"}'
Add-Phase4RawCase -Name 'JsonReplacementCharacterRaw' -RelativePath 'json/replacement-character-raw.json' -Bytes $fixture.ToArray() -ExpectedReason 'replacement-character-forbidden'

Add-Phase4TextCase -Name 'JsonReplacementCharacterEscape' -RelativePath 'json/replacement-character-escape.json' -Text '{"a":"\uFFFD"}' -ExpectedReason 'replacement-character-forbidden'

$metaContract = Get-PspktPhase4Contract
$metaResolvedFullPath = Assert-PspktPhase4ContainedNoReparse -FullPath $metaFullPath -CertRoot $sourceCertRoot
$metaBytes = Read-PspktPhase4BoundedBytes -FullPath $metaResolvedFullPath -ByteCap $metaContract.MetaByteCap
$committedMeta = [System.Text.UTF8Encoding]::new($false, $true).GetString($metaBytes) | ConvertFrom-Json
Add-Phase4Case -Name 'BootstrapMetaCommitted' -RepoPath $metaRepoPath -Stage 'bootstrap-meta' -ExpectedReason 'ok'

$metaUnknown = Copy-Phase4Document -Value $committedMeta
Add-Member -InputObject $metaUnknown -MemberType NoteProperty -Name 'reservedExtension' -Value 'None'
Add-Phase4DocumentCase -Name 'BootstrapMetaUnknownProperty' -RelativePath 'bootstrap-meta/unknown-property.json' -Value $metaUnknown -Stage 'bootstrap-meta' -ExpectedReason 'unknown-property'

$metaMissing = Copy-Phase4Document -Value $committedMeta
$metaMissing.PSObject.Properties.Remove('productions')
Add-Phase4DocumentCase -Name 'BootstrapMetaMissingProperty' -RelativePath 'bootstrap-meta/missing-property.json' -Value $metaMissing -Stage 'bootstrap-meta' -ExpectedReason 'missing-property'

$metaDuplicate = Copy-Phase4Document -Value $committedMeta
$duplicatedPrimitives = @($metaDuplicate.primitives)
$duplicatedPrimitives[$duplicatedPrimitives.Count - 1] = $duplicatedPrimitives[0]
$metaDuplicate.primitives = $duplicatedPrimitives
Add-Phase4DocumentCase -Name 'BootstrapMetaDuplicateIdentifier' -RelativePath 'bootstrap-meta/duplicate-identifier.json' -Value $metaDuplicate -Stage 'bootstrap-meta' -ExpectedReason 'duplicate-identifier'

$metaUnknownPrimitive = Copy-Phase4Document -Value $committedMeta
$metaUnknownPrimitive.primitives = @(@($metaUnknownPrimitive.primitives) + 'U24')
Add-Phase4DocumentCase -Name 'BootstrapMetaUnknownPrimitive' -RelativePath 'bootstrap-meta/unknown-primitive.json' -Value $metaUnknownPrimitive -Stage 'bootstrap-meta' -ExpectedReason 'unknown-primitive'

$metaCycle = Copy-Phase4Document -Value $committedMeta
foreach ($declaration in @($metaCycle.types)) {
    if ($declaration.name -ceq 'FieldDeclaration') {
        foreach ($field in @($declaration.fields)) {
            if ($field.name -ceq 'typeReference') {
                $field.type = 'TypeDeclaration'
            }
        }
    }
}
Add-Phase4DocumentCase -Name 'BootstrapMetaTypeCycle' -RelativePath 'bootstrap-meta/type-cycle.json' -Value $metaCycle -Stage 'bootstrap-meta' -ExpectedReason 'type-cycle'

$metaExtension = Copy-Phase4Document -Value $committedMeta
foreach ($declaration in @($metaExtension.types)) {
    if ($declaration.name -ceq 'SchemaDocument') {
        $existingFields = @($declaration.fields)
        $nextFieldId = 0
        foreach ($field in $existingFields) {
            if ([int]$field.fieldId -gt $nextFieldId) { $nextFieldId = [int]$field.fieldId }
        }
        $extensionField = [pscustomobject][ordered]@{ fieldId = ($nextFieldId + 1); name = 'extensionField'; type = 'U8' }
        $declaration.fields = @($existingFields + $extensionField)
    }
}
Add-Phase4DocumentCase -Name 'BootstrapMetaAuthorityExtension' -RelativePath 'bootstrap-meta/meta-authority-extension.json' -Value $metaExtension -Stage 'bootstrap-meta' -ExpectedReason 'meta-authority-mismatch'

$metaRename = Copy-Phase4Document -Value $committedMeta
foreach ($declaration in @($metaRename.types)) {
    if ($declaration.name -ceq 'FieldDeclaration') {
        foreach ($field in @($declaration.fields)) {
            if ($field.name -ceq 'fieldName') { $field.name = 'fieldLabel' }
        }
    }
}
Add-Phase4DocumentCase -Name 'BootstrapMetaAuthorityRename' -RelativePath 'bootstrap-meta/meta-authority-rename.json' -Value $metaRename -Stage 'bootstrap-meta' -ExpectedReason 'meta-authority-mismatch'

$metaSchemaId = Copy-Phase4Document -Value $committedMeta
$metaSchemaId.schemaId = 'PspktProtocolSchemaMetaV2'
Add-Phase4DocumentCase -Name 'BootstrapMetaAuthoritySchemaId' -RelativePath 'bootstrap-meta/meta-authority-schema-id.json' -Value $metaSchemaId -Stage 'bootstrap-meta' -ExpectedReason 'meta-authority-mismatch'

$metaEnumCardinality = Copy-Phase4Document -Value $committedMeta
foreach ($declaration in @($metaEnumCardinality.types)) {
    if ($declaration.name -ceq 'EnumMemberDeclarationList') { $declaration.maxCount = 65535 }
}
Add-Phase4DocumentCase -Name 'BootstrapMetaEnumMemberCardinality' -RelativePath 'bootstrap-meta/enum-member-cardinality.json' -Value $metaEnumCardinality -Stage 'bootstrap-meta' -ExpectedReason 'invalid-cardinality'

Add-Phase4DocumentCase -Name 'SchemaTypeLimitExact' -RelativePath 'schema/type-limit-exact.json' -Stage 'schema-against-meta' -ExpectedReason 'ok' -Value (
    New-Phase4TypeLimitDocument -SchemaId 'PspktTypeLimitExactFixture' -TypeCount 4096
)

Add-Phase4DocumentCase -Name 'SchemaTypeLimitOver' -RelativePath 'schema/type-limit-over.json' -Stage 'schema-against-meta' -ExpectedReason 'invalid-cardinality' -Value (
    New-Phase4TypeLimitDocument -SchemaId 'PspktTypeLimitOverFixture' -TypeCount 4097
)

Add-Phase4DocumentCase -Name 'SchemaFieldLimitExact' -RelativePath 'schema/field-limit-exact.json' -Stage 'schema-against-meta' -ExpectedReason 'ok' -Value (
    New-Phase4FieldLimitDocument -SchemaId 'PspktFieldLimitExactFixture' -FieldCount 4096
)

Add-Phase4DocumentCase -Name 'SchemaFieldLimitOver' -RelativePath 'schema/field-limit-over.json' -Stage 'schema-against-meta' -ExpectedReason 'invalid-cardinality' -Value (
    New-Phase4FieldLimitDocument -SchemaId 'PspktFieldLimitOverFixture' -FieldCount 4097
)

Add-Phase4DocumentCase -Name 'SchemaImpossibleSemanticDomain' -RelativePath 'schema/impossible-semantic-domain.json' -Stage 'schema-against-meta' -ExpectedReason 'invalid-cardinality' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktImpossibleSemanticDomainFixture' -Types @(
        [ordered]@{
            production = 'SemanticString'; name = 'ImpossibleText'; typeId = 1
            encoding   = 'Utf8'; grammar = 'None'
            minBytes   = 4; maxBytes = 100; maxUtf16CodeUnits = 1
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaValidPrimitiveUse' -RelativePath 'schema/valid-primitive-use.json' -Stage 'schema-against-meta' -ExpectedReason 'ok' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktPrimitiveUseFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'PrimitiveRecord'; typeId = 1
            fields     = @(
                (New-Phase4Field -Name 'sequence' -FieldId 1 -Type 'U64'),
                (New-Phase4Field -Name 'signedDelta' -FieldId 2 -Type 'I64'),
                (New-Phase4Field -Name 'digest' -FieldId 3 -Type 'SHA-256'),
                (New-Phase4Field -Name 'timestamp' -FieldId 4 -Type 'FILETIME'),
                (New-Phase4Field -Name 'ticket' -FieldId 5 -Type 'LUID'),
                (New-Phase4Field -Name 'commandLine' -FieldId 6 -Type 'OpaqueUtf16' -MaxCodeUnits 32767),
                (New-Phase4Field -Name 'payload' -FieldId 7 -Type 'BoundedBytes' -MaxBytes 65536)
            )
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaValidSemanticStringUse' -RelativePath 'schema/valid-semantic-string-use.json' -Stage 'schema-against-meta' -ExpectedReason 'ok' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktSemanticStringFixture' -Types @(
        [ordered]@{
            production = 'SemanticString'; name = 'EnvironmentVariableName'; typeId = 1
            encoding   = 'AsciiEnvironmentName'; grammar = 'None'
            minBytes   = 1; maxBytes = 32767; maxUtf16CodeUnits = 32767
        },
        [ordered]@{
            production = 'SemanticString'; name = 'CanonicalPath'; typeId = 2
            encoding   = 'Utf8'; grammar = 'PspktPathCanonicalizationV1'
            minBytes   = 1; maxBytes = 32768; maxUtf16CodeUnits = 32768
        },
        [ordered]@{
            production = 'Named'; name = 'EnvironmentEntry'; typeId = 3
            fields     = @(
                (New-Phase4Field -Name 'variableName' -FieldId 1 -Type 'EnvironmentVariableName'),
                (New-Phase4Field -Name 'resolvedPath' -FieldId 2 -Type 'CanonicalPath'),
                (New-Phase4Field -Name 'shortText' -FieldId 3 -Type 'Utf8Short')
            )
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaValidNamedListSetUse' -RelativePath 'schema/valid-named-list-set-use.json' -Stage 'schema-against-meta' -ExpectedReason 'ok' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktCollectionFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Leaf'; typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'U8'))
        },
        [ordered]@{ production = 'List'; name = 'LeafList'; typeId = 2; elementType = 'Leaf'; minCount = 0; maxCount = 64 },
        [ordered]@{ production = 'Set'; name = 'LeafSet'; typeId = 3; elementType = 'Leaf'; minCount = 1; maxCount = 32 },
        [ordered]@{
            production = 'Named'; name = 'Container'; typeId = 4
            fields     = @(
                (New-Phase4Field -Name 'ordered' -FieldId 1 -Type 'LeafList'),
                (New-Phase4Field -Name 'unique' -FieldId 2 -Type 'LeafSet')
            )
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaValidEnumUse' -RelativePath 'schema/valid-enum-use.json' -Stage 'schema-against-meta' -ExpectedReason 'ok' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktEnumFixture' -Types @(
        [ordered]@{
            production = 'EnumU16'; name = 'DeliveryKind'; typeId = 1
            members    = @(
                [ordered]@{ name = 'Immediate'; value = 0 },
                [ordered]@{ name = 'Deferred'; value = 1 },
                [ordered]@{ name = 'Discarded'; value = 2 }
            )
        },
        [ordered]@{
            production = 'Named'; name = 'DeliveryRecord'; typeId = 2
            fields     = @((New-Phase4Field -Name 'kind' -FieldId 1 -Type 'DeliveryKind'))
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaUndefinedReference' -RelativePath 'schema/undefined-reference.json' -Stage 'schema-against-meta' -ExpectedReason 'undefined-reference' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktUndefinedReferenceFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Record'; typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'MissingType'))
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaDuplicateTypeId' -RelativePath 'schema/duplicate-type-id.json' -Stage 'schema-against-meta' -ExpectedReason 'duplicate-type-id' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktDuplicateTypeIdFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'FirstRecord'; typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'U8'))
        },
        [ordered]@{
            production = 'Named'; name = 'SecondRecord'; typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'U8'))
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaDuplicateFieldId' -RelativePath 'schema/duplicate-field-id.json' -Stage 'schema-against-meta' -ExpectedReason 'duplicate-field-id' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktDuplicateFieldIdFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Record'; typeId = 1
            fields     = @(
                (New-Phase4Field -Name 'first' -FieldId 1 -Type 'U8'),
                (New-Phase4Field -Name 'second' -FieldId 1 -Type 'U16')
            )
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaFieldOrder' -RelativePath 'schema/field-order.json' -Stage 'schema-against-meta' -ExpectedReason 'field-order' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktFieldOrderFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Record'; typeId = 1
            fields     = @(
                (New-Phase4Field -Name 'second' -FieldId 2 -Type 'U8'),
                (New-Phase4Field -Name 'first' -FieldId 1 -Type 'U16')
            )
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaInvalidCardinality' -RelativePath 'schema/invalid-cardinality.json' -Stage 'schema-against-meta' -ExpectedReason 'invalid-cardinality' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktInvalidCardinalityFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Leaf'; typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'U8'))
        },
        [ordered]@{ production = 'List'; name = 'LeafList'; typeId = 2; elementType = 'Leaf'; minCount = 5; maxCount = 2 }
    )
)

Add-Phase4DocumentCase -Name 'SchemaBoundOverflow' -RelativePath 'schema/bound-overflow.json' -Stage 'schema-against-meta' -ExpectedReason 'bound-overflow' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktBoundOverflowFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Record'; typeId = 1
            fields     = @((New-Phase4Field -Name 'commandLine' -FieldId 1 -Type 'OpaqueUtf16' -MaxCodeUnits 2147483646))
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaNonAsciiSymbol' -RelativePath 'schema/non-ascii-symbol.json' -Stage 'schema-against-meta' -ExpectedReason 'non-ascii-symbol' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktNonAsciiSymbolFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = ('Typ{0}Record' -f ([char]0x00E9)); typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'U8'))
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaUtf8ShortAsSemanticReference' -RelativePath 'schema/utf8short-as-semantic-reference.json' -Stage 'schema-against-meta' -ExpectedReason 'unknown-primitive' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktUtf8ShortSemanticFixture' -Types @(
        [ordered]@{
            production = 'SemanticString'; name = 'ShortText'; typeId = 1
            encoding   = 'Utf8Short'; grammar = 'None'
            minBytes   = 1; maxBytes = 255; maxUtf16CodeUnits = 255
        }
    )
)

Add-Phase4DocumentCase -Name 'SchemaInventedAlias' -RelativePath 'schema/invented-alias.json' -Stage 'schema-against-meta' -ExpectedReason 'undefined-reference' -Value (
    New-Phase4SchemaDocument -SchemaId 'PspktInventedAliasFixture' -Types @(
        [ordered]@{
            production = 'Named'; name = 'Record'; typeId = 1
            fields     = @((New-Phase4Field -Name 'value' -FieldId 1 -Type 'UInt32'))
        }
    )
)

$metaSha = Get-PspktSha256Hex -Bytes $metaBytes

$bytesByRepoPath = @{}
foreach ($file in $script:phase4Files) {
    $bytesByRepoPath[$file.RepoPath] = $file.Bytes
}

$manifestCases = [System.Collections.Generic.List[object]]::new()
foreach ($case in $script:phase4Cases) {
    if ($case.Path -ceq $metaRepoPath) {
        $caseBytes = $metaBytes
    }
    elseif ($bytesByRepoPath.ContainsKey($case.Path)) {
        $caseBytes = $bytesByRepoPath[$case.Path]
    }
    else {
        throw ('generator: case {0} references unknown fixture "{1}".' -f $case.Ordinal, $case.Path)
    }
    $manifestCases.Add([ordered]@{
            ordinal         = $case.Ordinal
            name            = $case.Name
            path            = $case.Path
            stage           = $case.Stage
            expectedOutcome = $case.Outcome
            expectedReason  = $case.ExpectedReason
            byteLength      = [long]$caseBytes.Length
            sha256          = (Get-PspktSha256Hex -Bytes $caseBytes)
        })
}

$fixtureManifest = [ordered]@{
    schemaVersion = 1
    kind          = 'phase4-schema-fixtures'
    description   = 'Ordered phase4-schema fixture corpus. Each case names one committed fixture, the validation stage that consumes it, and the exact expected outcome and closed-enum reason.'
    metaSchema    = $metaRepoPath
    cases         = @($manifestCases)
}
$manifestBytes = Get-PspktCanonicalJsonBytes -Value $fixtureManifest
Write-Phase4Fixture -RelativePath 'fixture-manifest.v1.json' -Bytes $manifestBytes

function Test-Phase4NotReparse {
    param([Parameter(Mandatory = $true)][string]$Path)
    $attributes = [System.IO.FileAttributes]0
    if (Test-Phase4TryGetPathAttributes -Path $Path -Attributes ([ref]$attributes)) {
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
            throw ('generator: path "{0}" is a reparse point.' -f $Path)
        }
    }
}

function New-Phase4Directory {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $full = [System.IO.Path]::GetFullPath($Directory)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $parts = $full.Split($separator)
    $current = $parts[0] + $separator
    for ($index = 1; $index -lt $parts.Length; $index++) {
        if ([string]::IsNullOrEmpty($parts[$index])) { continue }
        $current = Join-Path $current $parts[$index]
        if (Test-Path -LiteralPath $current -PathType Leaf) {
            throw ('generator: expected directory but found a file at "{0}".' -f $current)
        }
        if (-not (Test-Path -LiteralPath $current -PathType Container)) {
            New-Item -ItemType Directory -Path $current -Force | Out-Null
        }
        Test-Phase4NotReparse -Path $current
    }
}

function Write-Phase4BytesToTree {
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    New-Phase4Directory -Directory (Split-Path -Parent $FullPath)
    [void](Assert-Phase4MissingLeaf -Path $FullPath)
    $stream = [System.IO.File]::Open($FullPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Publish-Phase4Target {
    param(
        [Parameter(Mandatory = $true)][string]$TargetFull,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    $directory = Split-Path -Parent $TargetFull
    New-Phase4Directory -Directory $directory
    Test-Phase4NotReparse -Path $directory

    $sibling = Join-Path $directory ('.phase4-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [void](Assert-Phase4MissingLeaf -Path $sibling)
    $stream = [System.IO.File]::Open($sibling, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    try {
        $targetAttributes = [System.IO.FileAttributes]0
        if (Test-Phase4TryGetPathAttributes -Path $TargetFull -Attributes ([ref]$targetAttributes)) {
            if (($targetAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                throw ('generator: target "{0}" is a directory.' -f $TargetFull)
            }
            if (($targetAttributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
                throw ('generator: target "{0}" is a reparse point.' -f $TargetFull)
            }
            [Pspkt.Certification.Phase4.AtomicFile]::ReplaceExisting($sibling, $TargetFull)
        }
        else {
            [Pspkt.Certification.Phase4.AtomicFile]::MoveNew($sibling, $TargetFull)
        }
    }
    finally {
        if (Test-Path -LiteralPath $sibling) {
            Remove-Item -LiteralPath $sibling -Force
        }
    }

    $written = [System.IO.File]::ReadAllBytes($TargetFull)
    if ((Get-PspktSha256Hex -Bytes $written) -cne (Get-PspktSha256Hex -Bytes $Bytes)) {
        throw ('generator: published bytes for "{0}" do not match the generated content.' -f $TargetFull)
    }
}

function Invoke-Phase4HardlinkRegression {
    param([AllowNull()][scriptblock]$BeforeCleanupAction = $null)
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-hardlink-' + [guid]::NewGuid().ToString('N'))
    $rootCreated = $false
    $operationalFailure = $null
    $cleanupLease = $null
    try {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $rootCreated = $true
        $target = Join-Path $root 'target.bin'
        $peer = Join-Path $root 'peer.bin'
        [System.IO.File]::WriteAllBytes($target, [byte[]](1, 2, 3))
        [Pspkt.Certification.Phase4.AtomicFile]::CreateHardLink($peer, $target)
        $newBytes = [byte[]](9, 9, 9, 9)
        Publish-Phase4Target -TargetFull $target -Bytes $newBytes
        $targetBytes = [System.IO.File]::ReadAllBytes($target)
        $peerBytes = [System.IO.File]::ReadAllBytes($peer)
        if ((Get-PspktSha256Hex -Bytes $targetBytes) -cne (Get-PspktSha256Hex -Bytes $newBytes)) {
            throw 'generator self-test: hardlink target was not replaced with new content.'
        }
        if ((Get-PspktSha256Hex -Bytes $peerBytes) -ceq (Get-PspktSha256Hex -Bytes $newBytes)) {
            throw 'generator self-test: MoveFileEx replaced through the hardlink instead of atomically swapping the name.'
        }
    }
    catch {
        $operationalFailure = $_.Exception
    }

    if ($rootCreated) {
        try {
            if ($null -ne $BeforeCleanupAction) {
                $cleanupLease = & $BeforeCleanupAction $root
            }
            Complete-Phase4PrivateTempRootCleanup -TempRoot $root -PrimaryFailure $operationalFailure
        }
        finally {
            if ($null -ne $cleanupLease) {
                $cleanupLease.Dispose()
            }
        }
    }
    elseif ($null -ne $operationalFailure) {
        throw $operationalFailure
    }
    else {
        throw 'generator self-test: hardlink private temp root was not created.'
    }

    Write-Host 'generator self-test: hardlink regression passed (name swap did not mutate the peer link).'
}

function Invoke-Phase4MissingLeafRegression {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-missing-leaf-' + [guid]::NewGuid().ToString('N'))
    $reparsePath = Join-Path $root 'dangling-reparse'
    $reparseTarget = Join-Path $root 'reparse-target'
    $nativeReparseTested = $false
    try {
        [void][System.IO.Directory]::CreateDirectory($root)

        $absentPath = Join-Path $root 'absent.bin'
        [void](Assert-Phase4MissingLeaf -Path $absentPath)

        $filePath = Join-Path $root 'existing.bin'
        [System.IO.File]::WriteAllBytes($filePath, [byte[]](1))
        $fileRejected = $false
        try {
            [void](Assert-Phase4MissingLeaf -Path $filePath)
        }
        catch {
            if ($_.Exception.Message -cne ('generator: output leaf "{0}" already exists.' -f $filePath)) { throw }
            $fileRejected = $true
        }
        if (-not $fileRejected) {
            throw 'generator self-test: existing file was accepted as a missing leaf.'
        }

        $directoryPath = Join-Path $root 'existing-directory'
        [void][System.IO.Directory]::CreateDirectory($directoryPath)
        $directoryRejected = $false
        try {
            [void](Assert-Phase4MissingLeaf -Path $directoryPath)
        }
        catch {
            if ($_.Exception.Message -cne ('generator: output leaf "{0}" already exists.' -f $directoryPath)) { throw }
            $directoryRejected = $true
        }
        if (-not $directoryRejected) {
            throw 'generator self-test: existing directory was accepted as a missing leaf.'
        }

        $missingOutcomes = [System.Exception[]]@(
            [System.IO.FileNotFoundException]::new('injected file-not-found'),
            [System.IO.DirectoryNotFoundException]::new('injected directory-not-found')
        )
        foreach ($missingOutcome in $missingOutcomes) {
            $missingReader = {
                param([string]$IgnoredPath)
                throw $missingOutcome
            }.GetNewClosure()
            $injectedAttributes = [System.IO.FileAttributes]0
            if (Test-Phase4TryGetPathAttributes -Path $absentPath -Attributes ([ref]$injectedAttributes) -AttributeReader $missingReader) {
                throw 'generator self-test: injected path-not-found outcome was treated as an existing object.'
            }
        }

        $unexpectedOutcomes = [System.Exception[]]@(
            [System.IO.IOException]::new('injected IO failure'),
            [System.UnauthorizedAccessException]::new('injected access failure'),
            [System.Security.SecurityException]::new('injected security failure')
        )
        foreach ($unexpectedOutcome in $unexpectedOutcomes) {
            $unexpectedReader = {
                param([string]$IgnoredPath)
                throw $unexpectedOutcome
            }.GetNewClosure()
            $unexpectedFailureObserved = $false
            try {
                $injectedAttributes = [System.IO.FileAttributes]0
                [void](Test-Phase4TryGetPathAttributes -Path $absentPath -Attributes ([ref]$injectedAttributes) -AttributeReader $unexpectedReader)
            }
            catch {
                if ($_.Exception.Message -cne $unexpectedOutcome.Message) { throw }
                $unexpectedFailureObserved = $true
            }
            if (-not $unexpectedFailureObserved) {
                throw ('generator self-test: {0} did not fail closed.' -f $unexpectedOutcome.GetType().FullName)
            }
        }

        [void][System.IO.Directory]::CreateDirectory($reparseTarget)
        $reparseSetupFailure = $null
        try {
            New-Item -ItemType Junction -Path $reparsePath -Target $reparseTarget -ErrorAction Stop | Out-Null
            [System.IO.Directory]::Delete($reparseTarget)
        }
        catch {
            $reparseSetupFailure = $_.Exception
        }

        if ($null -eq $reparseSetupFailure) {
            $reparseAttributes = [System.IO.FileAttributes]0
            if (-not (Test-Phase4TryGetPathAttributes -Path $reparsePath -Attributes ([ref]$reparseAttributes)) -or
                ($reparseAttributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                throw 'generator self-test: dangling junction was not observed as an existing reparse point.'
            }
            $reparseRejected = $false
            try {
                [void](Assert-Phase4MissingLeaf -Path $reparsePath)
            }
            catch {
                if ($_.Exception.Message -cne ('generator: output leaf "{0}" already exists.' -f $reparsePath)) { throw }
                $reparseRejected = $true
            }
            if (-not $reparseRejected) {
                throw 'generator self-test: dangling junction was accepted as a missing leaf.'
            }
            $nativeReparseTested = $true
        }
        else {
            $mockReader = {
                param([string]$CandidatePath)
                if ($CandidatePath -ceq $reparsePath) {
                    return [System.IO.FileAttributes]::ReparsePoint
                }
                return [System.IO.File]::GetAttributes($CandidatePath)
            }.GetNewClosure()
            $mockRejected = $false
            try {
                [void](Assert-Phase4MissingLeaf -Path $reparsePath -AttributeReader $mockReader)
            }
            catch {
                if ($_.Exception.Message -cne ('generator: output leaf "{0}" already exists.' -f $reparsePath)) { throw }
                $mockRejected = $true
            }
            if (-not $mockRejected) {
                throw ('generator self-test: reparse setup failed and injected terminal reparse outcome was accepted: {0}' -f $reparseSetupFailure.Message)
            }
        }
    }
    finally {
        $reparseAttributes = [System.IO.FileAttributes]0
        if (Test-Phase4TryGetPathAttributes -Path $reparsePath -Attributes ([ref]$reparseAttributes)) {
            if (($reparseAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                [System.IO.Directory]::Delete($reparsePath)
            }
            else {
                [System.IO.File]::Delete($reparsePath)
            }
        }
        if (Test-Path -LiteralPath $root -ErrorAction Stop) {
            Remove-Phase4PrivateTempRoot -TempRoot $root
        }
    }

    if ($nativeReparseTested) {
        Write-Host 'generator self-test: missing-leaf regression passed with a dangling junction.'
    }
    else {
        Write-Host 'generator self-test: missing-leaf regression passed with injected terminal reparse attributes.'
    }
}

function Get-Phase4GeneratorOutputDigest {
    param([Parameter(Mandatory = $true)]$Files)
    $paths = [string[]]@($Files | ForEach-Object { $_.RepoPath })
    [System.Array]::Sort($paths, [System.StringComparer]::Ordinal)
    $bytesByPath = @{}
    foreach ($file in $Files) {
        $bytesByPath[$file.RepoPath] = $file.Bytes
    }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $preimage = [System.IO.MemoryStream]::new()
    try {
        $domainBytes = [System.Text.Encoding]::UTF8.GetBytes('pspkt-phase4-generator-digest-v1' + [char]0)
        $preimage.Write($domainBytes, 0, $domainBytes.Length)
        foreach ($path in $paths) {
            $bytes = $bytesByPath[$path]
            $record = 'file' + [char]0x09 + $path + [char]0x09 +
                $bytes.Length.ToString($invariant) + [char]0x09 +
                (Get-PspktSha256Hex -Bytes $bytes) + [char]0x0A
            $recordBytes = [System.Text.Encoding]::UTF8.GetBytes($record)
            $preimage.Write($recordBytes, 0, $recordBytes.Length)
        }
        return Get-PspktSha256Hex -Bytes $preimage.ToArray()
    }
    finally {
        $preimage.Dispose()
    }
}

function Get-Phase4PublishedOutputDigest {
    param(
        [Parameter(Mandatory = $true)]$Files,
        [Parameter(Mandatory = $true)][string]$PublishRoot
    )
    $published = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $Files) {
        $relativeWindows = $file.RepoPath -replace '/', '\'
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $PublishRoot $relativeWindows))
        [void]$published.Add([pscustomobject]@{
            RepoPath = $file.RepoPath
            Bytes = [System.IO.File]::ReadAllBytes($fullPath)
        })
    }
    return Get-Phase4GeneratorOutputDigest -Files $published
}

function Write-Phase4SealedGeneratorResult {
    param(
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Digest,
        [Parameter(Mandatory = $true)]$Hardlink,
        [Parameter(Mandatory = $true)][bool]$SelfTestPassed,
        [Parameter(Mandatory = $true)][bool]$HardlinkPassed,
        [Parameter(Mandatory = $true)][bool]$OutputCountPassed,
        [Parameter(Mandatory = $true)][bool]$OutputDigestPassed
    )
    if (-not ($SelfTestPassed -and $HardlinkPassed -and $OutputCountPassed -and $OutputDigestPassed)) {
        throw 'generator: refusing to seal a result with a failed check.'
    }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $tab = [char]0x09
    $lf = [char]0x0A
    $checkIds = @('selftest-pass', 'hardlink-pass', 'output-count-pass', 'output-digest-pass')
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('pspkt-phase4-generator-result-v1').Append($tab).Append($Nonce).Append($tab).
        Append($PSVersionTable.PSEdition).Append($tab).Append($PSVersionTable.PSVersion.ToString()).Append($lf)
    for ($index = 0; $index -lt $checkIds.Count; $index++) {
        [void]$builder.Append('check').Append($tab).Append($index.ToString($invariant)).Append($tab).
            Append($checkIds[$index]).Append($tab).Append('pass').Append($lf)
    }
    [void]$builder.Append('digest').Append($tab).Append($Digest).Append($lf)
    [void]$builder.Append('hardlink').Append($tab).
        Append($Hardlink.SourceLeaf).Append($tab).Append($Hardlink.LinkLeaf).Append($tab).
        Append($Hardlink.SourcePreFileId).Append($tab).Append($Hardlink.LinkPreFileId).Append($tab).
        Append($Hardlink.SourcePreLength.ToString($invariant)).Append($tab).Append($Hardlink.SourcePreSha).Append($tab).
        Append($Hardlink.SourcePostFileId).Append($tab).Append($Hardlink.LinkPostFileId).Append($tab).
        Append($Hardlink.SourcePostLength.ToString($invariant)).Append($tab).Append($Hardlink.SourcePostSha).Append($tab).
        Append($Hardlink.LinkPostLength.ToString($invariant)).Append($tab).Append($Hardlink.LinkPostSha).Append($lf)
    [void]$builder.Append('summary').Append($tab).Append('4').Append($tab).Append('pass').Append($lf)
    $resultBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    if ($resultBytes.Length -gt 8192) {
        throw 'generator: sealed result exceeds the 8192-byte cap.'
    }
    [void](Assert-Phase4MissingLeaf -Path $ResultPath)
    $stream = [System.IO.File]::Open($ResultPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($resultBytes, 0, $resultBytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Remove-Phase4PrivateTempRoot {
    param([Parameter(Mandatory = $true)][string]$TempRoot)
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $TempRoot -ErrorAction Stop) {
        throw ('generator: private temp root "{0}" remained after cleanup.' -f $TempRoot)
    }
}

function Complete-Phase4PrivateTempRootCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [AllowNull()][System.Exception]$PrimaryFailure = $null,
        [AllowNull()][scriptblock]$CleanupAction = $null
    )
    $cleanupFailure = $null
    try {
        if ($null -eq $CleanupAction) {
            Remove-Phase4PrivateTempRoot -TempRoot $TempRoot
        }
        else {
            & $CleanupAction $TempRoot
        }
    }
    catch {
        $cleanupFailure = $_.Exception
    }

    if ($null -ne $PrimaryFailure -and $null -ne $cleanupFailure) {
        throw [System.AggregateException]::new(
            'generator: generation and private temp-root cleanup both failed.',
            [System.Exception[]]@($PrimaryFailure, $cleanupFailure))
    }
    if ($null -ne $PrimaryFailure) {
        throw $PrimaryFailure
    }
    if ($null -ne $cleanupFailure) {
        throw $cleanupFailure
    }
}

function Invoke-Phase4PrivateTempRootCleanupRegression {
    $regressionRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-cleanup-' + [guid]::NewGuid().ToString('N'))
    $privateTempRoot = Join-Path $regressionRoot 'private'
    $resultPath = Join-Path $regressionRoot 'sealed-result.txt'
    New-Item -ItemType Directory -Path $privateTempRoot -Force | Out-Null
    $cleanupFailureMessage = 'generator self-test: injected private temp-root cleanup failure.'
    $cleanupFailureObserved = $false
    $aggregateFailureObserved = $false
    try {
        $hardlink = [pscustomobject]@{
            SourceLeaf       = 'source.bin'
            LinkLeaf         = 'link.bin'
            SourcePreFileId  = '000000000000000000000000000000000000000000000000'
            LinkPreFileId    = '000000000000000000000000000000000000000000000000'
            SourcePreLength  = [long]3
            SourcePreSha     = '0000000000000000000000000000000000000000000000000000000000000000'
            SourcePostFileId = '111111111111111111111111111111111111111111111111'
            LinkPostFileId   = '000000000000000000000000000000000000000000000000'
            SourcePostLength = [long]4
            SourcePostSha    = '1111111111111111111111111111111111111111111111111111111111111111'
            LinkPostLength   = [long]3
            LinkPostSha      = '0000000000000000000000000000000000000000000000000000000000000000'
        }
        try {
            Complete-Phase4PrivateTempRootCleanup -TempRoot $privateTempRoot -CleanupAction {
                param([string]$BlockedTempRoot)
                throw [System.IO.IOException]::new($cleanupFailureMessage)
            }
            Write-Phase4SealedGeneratorResult -ResultPath $resultPath -Nonce ([guid]::NewGuid().ToString('N')) `
                -Digest '0000000000000000000000000000000000000000000000000000000000000000' -Hardlink $hardlink `
                -SelfTestPassed $true -HardlinkPassed $true -OutputCountPassed $true -OutputDigestPassed $true
        }
        catch {
            if ($_.Exception.Message -cne $cleanupFailureMessage) {
                throw
            }
            $cleanupFailureObserved = $true
        }
        if (Test-Path -LiteralPath $resultPath -ErrorAction Stop) {
            throw 'generator self-test: sealed result was published after private temp-root cleanup failed.'
        }
        if (-not $cleanupFailureObserved) {
            throw 'generator self-test: private temp-root cleanup failure was not surfaced.'
        }
        $primaryFailureMessage = 'generator self-test: injected generation failure.'
        try {
            Complete-Phase4PrivateTempRootCleanup -TempRoot $privateTempRoot `
                -PrimaryFailure ([System.InvalidOperationException]::new($primaryFailureMessage)) `
                -CleanupAction {
                    param([string]$BlockedTempRoot)
                    throw [System.IO.IOException]::new($cleanupFailureMessage)
                }
        }
        catch {
            $aggregateFailure = $_.Exception
            if ($aggregateFailure -isnot [System.AggregateException] -or
                $aggregateFailure.InnerExceptions.Count -ne 2 -or
                $aggregateFailure.InnerExceptions[0].Message -cne $primaryFailureMessage -or
                $aggregateFailure.InnerExceptions[1].Message -cne $cleanupFailureMessage) {
                throw
            }
            $aggregateFailureObserved = $true
        }
        if (-not $aggregateFailureObserved) {
            throw 'generator self-test: generation and cleanup failures were not aggregated.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $regressionRoot -ErrorAction Stop) {
            Remove-Phase4PrivateTempRoot -TempRoot $regressionRoot
        }
    }
}

function Invoke-Phase4GeneratorSelfTestSuite {
    param(
        [Parameter(Mandatory = $true)][int]$CaseCount,
        [Parameter(Mandatory = $true)][int]$FileCount,
        [Parameter(Mandatory = $true)][scriptblock[]]$RegressionActions
    )
    if ($CaseCount -ne 61) {
        throw ('generator self-test: expected 61 temporary cases but found {0}.' -f $CaseCount)
    }
    if ($FileCount -ne 61) {
        throw ('generator self-test: expected 61 temporary directory files but found {0}.' -f $FileCount)
    }
    if ($RegressionActions.Count -eq 0) {
        throw 'generator self-test: no regression actions were supplied.'
    }
    foreach ($regressionAction in $RegressionActions) {
        & $regressionAction | Out-Null
    }
    return $true
}

function Invoke-Phase4ContainedSelfTestFailureRegression {
    $regressionRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-selftest-fault-' + [guid]::NewGuid().ToString('N'))
    $resultPath = Join-Path $regressionRoot 'sealed-result.txt'
    New-Item -ItemType Directory -Path $regressionRoot -Force | Out-Null
    [bool]$faultSelfTestPassed = $false
    $faultObserved = $false
    $lockedCleanupState = [pscustomobject]@{
        Root = $null
    }
    try {
        $hardlink = [pscustomobject]@{
            SourceLeaf       = 'source.bin'
            LinkLeaf         = 'link.bin'
            SourcePreFileId  = '000000000000000000000000000000000000000000000000'
            LinkPreFileId    = '000000000000000000000000000000000000000000000000'
            SourcePreLength  = [long]3
            SourcePreSha     = '0000000000000000000000000000000000000000000000000000000000000000'
            SourcePostFileId = '111111111111111111111111111111111111111111111111'
            LinkPostFileId   = '000000000000000000000000000000000000000000000000'
            SourcePostLength = [long]4
            SourcePostSha    = '1111111111111111111111111111111111111111111111111111111111111111'
            LinkPostLength   = [long]3
            LinkPostSha      = '0000000000000000000000000000000000000000000000000000000000000000'
        }
        $beforeCleanupAction = {
            param([string]$privateTempRoot)
            $lockedCleanupState.Root = $privateTempRoot
            $lockedPath = Join-Path $privateTempRoot 'locked-cleanup.bin'
            [System.IO.File]::WriteAllBytes($lockedPath, [byte[]](1, 2, 3))
            return [System.IO.File]::Open(
                $lockedPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None)
        }.GetNewClosure()
        try {
            Invoke-Phase4HardlinkRegression -BeforeCleanupAction $beforeCleanupAction
            $faultSelfTestPassed = $true
            Write-Phase4SealedGeneratorResult -ResultPath $resultPath -Nonce ([guid]::NewGuid().ToString('N')) `
                -Digest '0000000000000000000000000000000000000000000000000000000000000000' -Hardlink $hardlink `
                -SelfTestPassed $faultSelfTestPassed -HardlinkPassed $true -OutputCountPassed $true -OutputDigestPassed $true
        }
        catch {
            if ($null -eq $lockedCleanupState.Root) {
                throw
            }
            $faultObserved = $true
        }
        if ($null -ne $lockedCleanupState.Root) {
            if (-not (Test-Path -LiteralPath $lockedCleanupState.Root -ErrorAction Stop)) {
                throw 'generator self-test: locked private temp-root cleanup did not fail.'
            }
            Remove-Phase4PrivateTempRoot -TempRoot $lockedCleanupState.Root
        }
        if ($faultSelfTestPassed) {
            throw 'generator self-test: locked-root cleanup failure incorrectly marked the self-test passed.'
        }
        if (Test-Path -LiteralPath $resultPath -ErrorAction Stop) {
            throw 'generator self-test: locked-root cleanup failure published a sealed result.'
        }
        if (-not $faultObserved) {
            throw 'generator self-test: locked-root cleanup failure was not surfaced.'
        }
    }
    finally {
        if ($null -ne $lockedCleanupState.Root -and
            (Test-Path -LiteralPath $lockedCleanupState.Root -ErrorAction Stop)) {
            Remove-Phase4PrivateTempRoot -TempRoot $lockedCleanupState.Root
        }
        if (Test-Path -LiteralPath $regressionRoot -ErrorAction Stop) {
            Remove-Phase4PrivateTempRoot -TempRoot $regressionRoot
        }
    }
}

$contract = Get-PspktPhase4Contract
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('pspkt-phase4-gen-' + [guid]::NewGuid().ToString('N'))
$tempRootCreated = $false
$generationFailure = $null
$tempCases = $null
$tempFiles = $null
$publishedCases = $null
$publishedFiles = $null
$generatorDigest = $null
$publishedDigest = $null
$digestPassed = $false
[bool]$selfTestPassed = $false
try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $tempRootCreated = $true
    Test-Phase4NotReparse -Path $tempRoot

    $tempCertRoot = Join-Path $tempRoot 'certification'
    $tempMetaFull = Join-Path $tempCertRoot 'schema\protocol-schema-meta.v1.json'
    Write-Phase4BytesToTree -FullPath $tempMetaFull -Bytes $metaBytes

    foreach ($file in $script:phase4Files) {
        $relativeWindows = $file.RepoPath -replace '/', '\'
        $tempTarget = Join-Path $tempRoot $relativeWindows
        Write-Phase4BytesToTree -FullPath $tempTarget -Bytes $file.Bytes
    }

    $tempManifestFull = Join-Path $tempRoot ($contract.ManifestRepoPath -replace '/', '\')
    $tempManifestBytes = Read-PspktPhase4BoundedBytes -FullPath $tempManifestFull -ByteCap $contract.ManifestByteCap
    $tempManifest = [System.Text.UTF8Encoding]::new($false, $true).GetString($tempManifestBytes) | ConvertFrom-Json
    Assert-PspktPhase4ManifestShape -Manifest $tempManifest
    $tempCases = @(Get-PspktPhase4NormalizedCases -Manifest $tempManifest)
    Assert-PspktPhase4CorpusFileSet -Cases $tempCases -RepositoryRoot $tempRoot -CertRoot $tempCertRoot | Out-Null
    Assert-PspktPhase4CanonicalFile -FullPath $tempMetaFull -ByteCap $contract.MetaByteCap -Label 'temporary meta' | Out-Null
    Assert-PspktPhase4CanonicalFile -FullPath $tempManifestFull -ByteCap $contract.ManifestByteCap -Label 'temporary manifest' | Out-Null
    foreach ($case in $tempCases) {
        Get-PspktPhase4FixtureBytes -Case $case -RepositoryRoot $tempRoot -CertRoot $tempCertRoot | Out-Null
    }
    $tempFiles = @(Assert-PspktPhase4DirectoryFileCount -RepositoryRoot $tempRoot -CertRoot $tempCertRoot)
    Write-Host ('generator: built and contract-validated {0} cases across {1} directory files.' -f $tempCases.Count, $tempFiles.Count)

    if ($SelfTest) {
        $selfTestRegressions = [scriptblock[]]@(
            { Invoke-Phase4MissingLeafRegression },
            { Invoke-Phase4HardlinkRegression },
            { Invoke-Phase4PrivateTempRootCleanupRegression },
            { Invoke-Phase4ContainedSelfTestFailureRegression }
        )
        $selfTestPassed = Invoke-Phase4GeneratorSelfTestSuite `
            -CaseCount $tempCases.Count `
            -FileCount $tempFiles.Count `
            -RegressionActions $selfTestRegressions
    }

    $phase4DirFull = [System.IO.Path]::GetFullPath((Join-Path $publishCertRoot 'vectors\phase4-schema'))
    $expectedFullPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $script:phase4Files) {
        $relativeWindows = $file.RepoPath -replace '/', '\'
        [void]$expectedFullPaths.Add([System.IO.Path]::GetFullPath((Join-Path $publishRoot $relativeWindows)))
    }
    if (Test-Path -LiteralPath $phase4DirFull -PathType Container) {
        Test-Phase4NotReparse -Path $phase4DirFull
        foreach ($existing in @(Get-ChildItem -LiteralPath $phase4DirFull -Recurse -File -Force)) {
            if (-not $expectedFullPaths.Contains($existing.FullName)) {
                throw ('generator: unexpected file "{0}" in the fixture directory; refusing to delete stale content.' -f $existing.FullName)
            }
        }
    }

    foreach ($file in $script:phase4Files) {
        $relativeWindows = $file.RepoPath -replace '/', '\'
        $targetFull = [System.IO.Path]::GetFullPath((Join-Path $publishRoot $relativeWindows))
        Publish-Phase4Target -TargetFull $targetFull -Bytes $file.Bytes
    }

    $publishedManifestFull = [System.IO.Path]::GetFullPath((Join-Path $publishRoot ($contract.ManifestRepoPath -replace '/', '\')))
    $publishedManifestBytes = Read-PspktPhase4BoundedBytes -FullPath $publishedManifestFull -ByteCap $contract.ManifestByteCap
    $publishedManifest = [System.Text.UTF8Encoding]::new($false, $true).GetString($publishedManifestBytes) | ConvertFrom-Json
    Assert-PspktPhase4ManifestShape -Manifest $publishedManifest
    $publishedCases = @(Get-PspktPhase4NormalizedCases -Manifest $publishedManifest)
    Assert-PspktPhase4CorpusFileSet -Cases $publishedCases -RepositoryRoot $publishRoot -CertRoot $publishCertRoot | Out-Null
    foreach ($case in $publishedCases) {
        if ($case.Path -ceq $contract.MetaRepoPath) {
            if ([long]$case.ByteLength -ne [long]$metaBytes.Length -or
                [string]$case.Sha256 -cne (Get-PspktSha256Hex -Bytes $metaBytes)) {
                throw 'generator: published manifest meta row does not match the captured meta authority bytes.'
            }
        }
        else {
            Get-PspktPhase4FixtureBytes -Case $case -RepositoryRoot $publishRoot -CertRoot $publishCertRoot | Out-Null
        }
    }
    $publishedFiles = @(Assert-PspktPhase4DirectoryFileCount -RepositoryRoot $publishRoot -CertRoot $publishCertRoot)

    if ($isContainedMode) {
        if ($publishedFiles.Count -ne 61) {
            throw ('generator: expected 61 published directory files but found {0}.' -f $publishedFiles.Count)
        }
        if ($null -eq $script:ContainedHardlinkRecord) {
            throw 'generator: contained hard-link self-test did not produce a sealed record.'
        }
        $generatorDigest = Get-Phase4GeneratorOutputDigest -Files $script:phase4Files
        $publishedDigest = Get-Phase4PublishedOutputDigest -Files $script:phase4Files -PublishRoot $publishRoot
        $digestPassed = $publishedDigest -ceq $generatorDigest
    }
}
catch {
    $generationFailure = $_.Exception
}

if ($tempRootCreated) {
    Complete-Phase4PrivateTempRootCleanup -TempRoot $tempRoot -PrimaryFailure $generationFailure
}
elseif ($null -ne $generationFailure) {
    throw $generationFailure
}
else {
    throw 'generator: private temp root was not created.'
}

if ($isContainedMode) {
    Write-Phase4SealedGeneratorResult -ResultPath $generatorResultPath -Nonce $generatorNonce -Digest $publishedDigest -Hardlink $script:ContainedHardlinkRecord `
        -SelfTestPassed $selfTestPassed `
        -HardlinkPassed ([bool]$script:ContainedHardlinkRecord.Passed) `
        -OutputCountPassed ($publishedFiles.Count -eq 61) `
        -OutputDigestPassed $digestPassed
    Write-Host ('generator: sealed contained result written for nonce {0} ({1} files, digest {2}).' -f $generatorNonce, $publishedFiles.Count, $generatorDigest)
}
else {
    Write-Host ('generator: published {0} directory files, {1} cases.' -f $publishedFiles.Count, $publishedCases.Count)
    Write-Host ('generator: committed meta sha256 = {0}' -f $metaSha)
    Write-Host ('generator: pin this digest into BootstrapMetaGrammar.CommittedMetaSha256 in Pspkt.Certification.SchemaBootstrap.cs.')
}
