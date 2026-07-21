# SMB2 Parser Reference

This document describes the `SMB2` output produced by the pspkt parsers across every parsing 
level. It reflects what the code actually emits.

## Notation used in this document

- `[value]` marks a parsed value that is substituted at runtime. The square brackets are
  **not** printed.
- A pipe inside brackets (`[true|false]`) is a conditional: the first word is used when the
  flag bit is set (1), the second when it is clear (0). Example: `[Do|Do not]` prints `Do`
  when the bit is 1 and `Do not` when it is 0.
- In the flags bit templates, a capital `B` is replaced by the actual bit value (`0` or `1`)
  at that position; `.`, `0`, and `1` are printed verbatim.
- `[+|-]` in the tree examples marks a collapsible node: `+` when collapsed, `-` when expanded.

## Value formatting

- Hex (`0x`): 
- Decimal: 

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---

# Special Notes

The SMB2 parser maintains tables of discovered Tree (TID) and File (FID) IDs mapped to their share/file names. Names ride on *requests* (TreeConnect share path, Create filename) and are correlated to the server-assigned IDs on the matching *response* (TreeId in the response header, FileId in the Create response body) by connection + MessageId. Later commands that carry a resolved TID/FID then display the name. When a FID is not in the table (e.g. the establishing packet wasn't captured), the FID is shown as a **GUID string**; when a TID is not in the table, its hex value is shown. The tables are **scoped per TCP connection** (an order-independent hash of the IP 4-tuple), so concurrent connections cannot collide, and are reset at the start of every capture.

In the Default/Detailed/Text-Box one-liner, a *resolved* FID shows just the file name (no GUID); the GUID is shown only when the name is unknown.

The SMB2 parser must be capable of handling chained (compounded) commands, including `SMB2_FLAGS_RELATED_OPERATIONS` chains where a command inherits the FileId (all-ones sentinel) of an earlier command in the same chain.

The SMB2 parser does not parse NTLM, GSS-API, or Kerberos.


# Levels

## Minimal

`SMB2:`

## Default

### Encrypted

`SMB2 Encrypted, SessId 0x[h], len [n]`

The `len` is the Transform header's OriginalMessageSize (the plaintext size before encryption).

### Unencrypted

Do not include length (len) outside of READ or WRITE commands.

`SMB2 [Command] [Request|Response][IF (NT STATUS != STATUS_SUCCESS (0x0) AND Response) THEN ", [Status] (0x[h])"] [see "Command:" headings]`

The status is shown only on **responses** whose status isn't STATUS_SUCCESS (a request's status field is ChannelSequence/Reserved). Compounded commands are each rendered and joined with ` | `.

#### MS-SMB2 Command Table

| Name | Value |
| --- | --- |
| SMB2 NEGOTIATE | 0x0000 |
| SMB2 SESSION\_SETUP | 0x0001 |
| SMB2 LOGOFF | 0x0002 |
| SMB2 TREE\_CONNECT | 0x0003 |
| SMB2 TREE\_DISCONNECT | 0x0004 |
| SMB2 CREATE | 0x0005 |
| SMB2 CLOSE | 0x0006 |
| SMB2 FLUSH | 0x0007 |
| SMB2 READ | 0x0008 |
| SMB2 WRITE | 0x0009 |
| SMB2 LOCK | 0x000A |
| SMB2 IOCTL | 0x000B |
| SMB2 CANCEL | 0x000C |
| SMB2 ECHO | 0x000D |
| SMB2 QUERY\_DIRECTORY | 0x000E |
| SMB2 CHANGE\_NOTIFY | 0x000F |
| SMB2 QUERY\_INFO | 0x0010 |
| SMB2 SET\_INFO | 0x0011 |
| SMB2 OPLOCK\_BREAK | 0x0012 |


#### Command: NEGOTIATE

##### REQUEST

`Requested Dialects [dialects]; [capabilities, comma separated]`

> A NEGOTIATE **request** carries no Max transaction/read/write sizes — those are server-only response fields — so they are omitted from the request line.

##### REPONSE

`Dialect [dialect]; [Max transation size]\[Max read size]\[Max write size]; [capabilities, comma separated]`

#### Command: SESSION SETUP

##### REQUEST

`Signing [enabled|required]; [capabilities, comma separated]`

##### REPONSE

No parsing beyond header.

#### Command: LOGOFF

No parsing beyond header.

#### Command: TREE CONNECT

##### REQUEST

`[Tree]`

##### REPONSE

No parsing beyond header.

#### Command: TREE DISCONNECT

No parsing beyond header.

#### Command: CREATE

##### REQUEST

`Disposition: [Disposition; See "Create Disposition"]; File: [File name; See "Special Notes"]`

> A CREATE request carries no FileId — the server assigns it in the response — so the request line shows only the filename (no `(0x…)` handle). The short detail (Disposition) leads so a long path can't hide it.

##### REPONSE

`Action: [Action; See "Create Action"]; File: [File name; See "Special Notes"]`

##### Create Disposition

The Disposition is called CreateDisposition in the MS-SMB2 spec.

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997


This table matches the CreateDisposition value to a name (per MS-SMB2 2.2.13):

+----------+---------------------+-----------------------------------------------------------+
| Value    | Name                | Description / Action if File Exists                       |
+----------+---------------------+-----------------------------------------------------------+
| 0x0000   | FILE_SUPERSEDE      | Delete existing file and create a new one.                |
| 0x0001   | FILE_OPEN           | Open the existing file.                                   |
| 0x0002   | FILE_CREATE         | Create a new file (fail if it already exists).            |
| 0x0003   | FILE_OPEN_IF        | Open file if it exists; otherwise, create a new one.      |
| 0x0004   | FILE_OVERWRITE      | Open existing file and overwrite its contents.            |
| 0x0005   | FILE_OVERWRITE_IF   | Open file if it exists and overwrite; otherwise, create.  |
+----------+---------------------+-----------------------------------------------------------+


##### Create Action

+------------+------------------+-------------------------------------------------------------+
| Value      | Name             | Description / Action Taken By Server                        |
+------------+------------------+-------------------------------------------------------------+
| 0x00000000 | FILE_SUPERSEDED  | An existing file was deleted and replaced with a new one.   |
| 0x00000001 | FILE_OPENED      | An existing file was successfully opened.                   |
| 0x00000002 | FILE_CREATED     | A brand new file was successfully created.                  |
| 0x00000003 | FILE_OVERWRITTEN | An existing file was opened and its content truncated to 0. |
+------------+------------------+-------------------------------------------------------------+



#### Command: CLOSE

`File: [File name; See "Special Notes"] (0x[h])`



#### Command: FLUSH

##### REQUEST

`File: [File name; See "Special Notes"] (0x[h])`

##### REPONSE

No parsing beyond header.


#### Command: READ

##### REQUEST

`Len: [Length]; Off: [Offset]; File: [File name; See "Special Notes"] (0x[h])`

##### REPONSE

`File: [File name; See "Special Notes"] (0x[h])`


#### Command: WRITE

##### REQUEST

`Len: [Length]; Off: [Offset]; File: [File name; See "Special Notes"] (0x[h])`

##### REPONSE

`File: [File name; See "Special Notes"] (0x[h])`


#### Command: LOCK

##### REQUEST

`File: [File name; See "Special Notes"] (0x[h])`

##### REPONSE

`File: [File name; See "Special Notes"] (0x[h])`


#### Command: IOCTL

`[IOCTL Name; see "IOCTL Table"]` (0x[h])


##### IOCTL Table

+------------+---------------------------------------------+
| CtlCode    | Name                                        |
+------------+---------------------------------------------+
| 0x00060194 | FSCTL_DFS_GET_REFERRALS                     |
| 0x0011400C | FSCTL_PIPE_PEEK                             |
| 0x00110018 | FSCTL_PIPE_WAIT                             |
| 0x0011C017 | FSCTL_PIPE_TRANSCEIVE                       |
| 0x001440F2 | FSCTL_SRV_COPYCHUNK                         |
| 0x001480F2 | FSCTL_SRV_ENUMERATE_SNAPSHOTS               |
| 0x00144064 | FSCTL_SRV_REQUEST_RESUME_KEY                |
| 0x001401D4 | FSCTL_SRV_READ_HASH                         |
| 0x001480F0 | FSCTL_SRV_COPYCHUNK_WRITE                   |
| 0x001401FC | FSCTL_LMR_REQUEST_RESILIENCY                |
| 0x00140204 | FSCTL_QUERY_NETWORK_INTERFACE_INFO          |
| 0x001401D0 | FSCTL_SET_REPARSE_POINT                     |
| 0x000900A4 | FSCTL_DFS_GET_REFERRALS_EX                  |
| 0x001401EC | FSCTL_FILE_LEVEL_TRIM                       |
| 0x00140220 | FSCTL_VALIDATE_NEGOTIATE_INFO               |
| 0x00140244 | FSCTL_QUERY_ALLOCATED_RANGES                |
| 0x001401FC | FSCTL_LMR_REQUEST_RESILIENCY                |
| 0x00140264 | FSCTL_SET_ZERO_DATA                         |
| 0x001480F4 | FSCTL_SRV_COPYCHUNK_WRITE                   |
| 0x00140168 | FSCTL_OFFLOAD_READ                          |
| 0x0014416C | FSCTL_OFFLOAD_WRITE                         |
| 0x00098208 | FSCTL_GET_INTEGRITY_INFORMATION             |
| 0x0009C280 | FSCTL_SET_INTEGRITY_INFORMATION             |
| 0x0014028C | FSCTL_QUERY_FILE_REGIONS                    |
+------------+---------------------------------------------+

#### Command: CANCEL

No parsing beyond header.


#### Command: ECHO

No parsing beyond header.


#### Command: QUERY DIRECTORY

`File: [File name; See "Special Notes"] (0x[h]); [Name from "FileInformationClass Table"] (0x[h]), Pattern: *`

##### FileInformationClass Table

+-------+------------------------------------------+----------------------------------------------+
| Value | Name                                     | Description                                  |
+-------+------------------------------------------+----------------------------------------------+
| 0x01  | FileDirectoryInformation                 | Basic file information                       |
| 0x02  | FileFullDirectoryInformation             | Basic information + EA size                  |
| 0x03  | FileBothDirectoryInformation             | Basic info + EA size + short name            |
| 0x0C  | FileNamesInformation                     | File and directory names only                |
| 0x25  | FileIdBothDirectoryInformation           | FileBothDirectoryInformation + 64-bit ID     |
| 0x26  | FileIdFullDirectoryInformation           | FileFullDirectoryInformation + 64-bit ID     |
| 0x3C  | FileIdExtdDirectoryInformation           | Extended info + reparse tag                  |
| 0x4E  | FileId64ExtdDirectoryInformation         | Extended info + 64-bit ID + reparse tag      |
| 0x4F  | FileId64ExtdBothDirectoryInformation     | Both info + 64-bit ID + reparse tag          |
| 0x50  | FileIdAllExtdDirectoryInformation        | Extd info + 64-bit & 128-bit IDs             |
| 0x51  | FileIdAllExtdBothDirectoryInformation    | Both info + 64-bit & 128-bit IDs             |
| 0x64  | FileInformationClass_Reserved            | Reserved                                     |
+-------+------------------------------------------+----------------------------------------------+



#### Command: CHANGE NOTIFY

##### REQUEST

`File: [File name; See "Special Notes"] (0x[h]); Completion Filter: 0x[h], [Comma separated filter list; see "CHANGE NOTIFY Filter Table"]`

##### REPONSE

No parsing beyond header.

##### CHANGE NOTIFY Filter Table

+------------+-------------------------------------------------------------+
| Value      | Name          | Trigger                                     |
+------------+---------------+---------------------------------------------+
| 0x00000001 | FILE_NAME     | File name changed                           |
| 0x00000002 | DIR_NAME      | Directory name changed                      |
| 0x00000004 | ATTRIBUTES    | File attributes changed                     |
| 0x00000008 | SIZE          | File size changed                           |
| 0x00000010 | LAST_WRITE    | Last write timestamp changed                |
| 0x00000020 | LAST_ACCESS   | Last access timestamp changed               |
| 0x00000040 | CREATION      | Creation timestamp changed                  |
| 0x00000080 | EA            | Extended attributes (EA) changed            |
| 0x00000100 | SECURITY      | Security descriptor / ACL changed           |
| 0x00000200 | STREAM_NAME   | Named stream added or removed               |
| 0x00000400 | STREAM_SIZE   | Named stream size changed                   |
| 0x00000800 | STREAM_WRITE  | Named stream contents modified              |
+------------+---------------+---------------------------------------------+



#### Command: QUERY INFO

##### REQUEST

`[InfoType from "InfoType Table"]\[FileInfoClass from "FileInfoClass Table"], File: [File name; See "Special Notes"] (0x[h])`

##### REPONSE

`File: [File name; See "Special Notes"] (0x[h])`

##### InfoType Table

+-------+------------------+
| Value | Name             |
+-------+------------------+
| 0x01  | INFO_FILE        |
| 0x02  | INFO_FILESYSTEM  |
| 0x03  | INFO_SECURITY    |
| 0x04  | INFO_QUOTA       |
+-------+------------------+

##### FileInfoClass Table

###### InfoType = SMB2_0_INFO_FILE (0x01)

+-------+------------------------------------------+
| Value | FileInfoClass                            |
+-------+------------------------------------------+
| 0x08  | FileAccessInformation                    |
| 0x11  | FileAlignmentInformation                 |
| 0x12  | FileAllInformation                       |
| 0x15  | FileAlternateNameInformation             |
| 0x23  | FileAttributeTagInformation              |
| 0x04  | FileBasicInformation                     |
| 0x1C  | FileCompressionInformation               |
| 0x07  | FileEaInformation                        |
| 0x0F  | FileFullEaInformation                    |
| 0x3B  | FileIdInformation                        |
| 0x06  | FileInternalInformation                  |
| 0x10  | FileModeInformation                      |
| 0x22  | FileNetworkOpenInformation               |
| 0x30  | FileNormalizedNameInformation            |
| 0x17  | FilePipeInformation                      |
| 0x18  | FilePipeLocalInformation                 |
| 0x19  | FilePipeRemoteInformation                |
| 0x0E  | FilePositionInformation                  |
| 0x05  | FileStandardInformation                  |
| 0x16  | FileStreamInformation                    |
| 0x64  | FileInfoClass_Reserved                   |
+-------+------------------------------------------+

###### InfoType = SMB2_0_INFO_FILESYSTEM (0x02)

+-------+----------------------------------+
| Value | FS_INFORMATION_CLASS             |
+-------+----------------------------------+
| 0x01  | FileFsVolumeInformation          |
| 0x03  | FileFsSizeInformation            |
| 0x04  | FileFsDeviceInformation          |
| 0x05  | FileFsAttributeInformation       |
| 0x06  | FileFsControlInformation         |
| 0x07  | FileFsFullSizeInformation        |
| 0x08  | FileFsObjectIdInformation        |
| 0x0B  | FileFsSectorSizeInformation      |
+-------+----------------------------------+


#### Command: SET INFO

##### REQUEST

`[InfoType from "InfoType Table"]\[FileInfoClass from "FileInfoClass Table"]; File: [File name; See "Special Notes"] (0x[h])`

##### REPONSE

`File: [File name; See "Special Notes"] (0x[h])`

##### InfoType Table

+-------+------------------+
| Value | Name             |
+-------+------------------+
| 0x01  | INFO_FILE        |
| 0x02  | INFO_FILESYSTEM  |
| 0x03  | INFO_SECURITY    |
| 0x04  | INFO_QUOTA       |
+-------+------------------+

##### FileInfoClass Table

###### InfoType = SMB2_0_INFO_FILE (0x01)

+-------+----------------------------------+
| Value | FileInfoClass                    |
+-------+----------------------------------+
| 0x13  | FileAllocationInformation        |
| 0x04  | FileBasicInformation             |
| 0x0D  | FileDispositionInformation       |
| 0x14  | FileEndOfFileInformation         |
| 0x0F  | FileFullEaInformation            |
| 0x0B  | FileLinkInformation              |
| 0x10  | FileModeInformation              |
| 0x17  | FilePipeInformation              |
| 0x0E  | FilePositionInformation          |
| 0x0A  | FileRenameInformation            |
| 0x28  | FileShortNameInformation         |
| 0x27  | FileValidDataLengthInformation   |
+-------+----------------------------------+

###### InfoType = SMB2_0_INFO_FILESYSTEM (0x02)

+-------+-------------------------------+
| Value | FS_INFORMATION_CLASS          |
+-------+-------------------------------+
| 0x06  | FileFsControlInformation      |
| 0x08  | FileFsObjectIdInformation     |
+-------+-------------------------------+


#### Command: OPLOCK BREAK

For Leases, each lease state is combination of R for Read, H for Handle, and W for Write. This is denoted as `R|H|W` in this document.

When showing lease details, print R, H, and/or W for each `CurrentLeaseState` or `NewLeaseState` flag that is set, or `None` when the lease state is 0x0. For example, a `CurrentLeaseState` set to 0x03 would print `RH` and a `NewLeaseState` of 0x0 would print `None`.

##### LEASE BREAK REQUEST

`Lease Break: [CurrentLeaseState R|H|W] -> [NewLeaseState R|H|W]; LeaseKey: [GUID string]`

##### LEASE BREAK ACKNOWLEDGEMENT

`Lease Ack: [LeaseState R|H|W]; LeaseKey: [GUID string]`

##### LEASE BREAK RESPONSE

`Lease Response: [LeaseState R|H|W]; LeaseKey: [GUID string]`

##### OPLOCK Break Notification

`Oplock Break: Level [See "OplockLevel Table"] (0x[h]); FileId: [File name; See "Special Notes"] (0x[h])`

##### Oplock Break Acknowledgment

`Oplock Ack: Level [See "OplockLevel Table"] (0x[h]); FileId: [File name; See "Special Notes"] (0x[h])`

##### Oplock Break Response

`Oplock Response: Level [See "OplockLevel Table"] (0x[h]); FileId: [File name; See "Special Notes"] (0x[h])`

###### OplockLevel Table

+-------+--------------------------------------+
| Value | Name                                 |
+-------+--------------------------------------+
| 0x00  | SMB2_OPLOCK_LEVEL_NONE               |
| 0x01  | SMB2_OPLOCK_LEVEL_II                 |
| 0x08  | SMB2_OPLOCK_LEVEL_EXCLUSIVE          |
| 0x09  | SMB2_OPLOCK_LEVEL_BATCH              |
| 0xFF  | SMB2_OPLOCK_LEVEL_LEASE              |
+-------+--------------------------------------+

## Detailed

Same as `Default`

## Analysis

### Text Box

Same as `Default`

### Details: Collapsed

The root node per message (one per chained command):

`SMB2 [Command] - [Tree as UNC or TID] ["; Status: [Status] (0x[h])", when present and not STATUS_SUCCESS]`

### Details: Expanded

```
SMB2
  [See `SMB Header`]
  [See `SMB Command`]
```

The `SMB Header` and the per-command body (`SMB Command`) are children of the root. QUERY_DIRECTORY responses expand to a `Directory Entries (N)` list; QUERY_INFO / SET_INFO expand to the decoded info structure (correlated from the request's information class).

#### SMB Header

The `SMB Header` node is **collapsed by default** and shows a summary line:

`SMB2 Header - Cmd: [Command] (0x[h]) [Request|Response], TID: [Tree or TID] [IF (Status != STATUS_SUCCESS) THEN ", Status: [Status] (0x[h])"]`

`Flags` and `Flags2` are both collapsed by default.

`NT Status` is based on MS-ERREF section 2.3: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781

The `SMB Negotiate Request` header is a special case. Only a single packet per SMB connection uses this format with `Flags2`.


##### SMB NEGOTIATE REQUEST

Many flags are obsolete and are set to zero (0) per MS-CIFS spec.

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f


```
SMB Header
  Server Component: SMB
  SMB Command: Negotiate Protocol (0x72)
  NT Status: STATUS_SUCCESS (0x00000000)
[Flags]
  Flags: 0x[h], [Enabled Flags, comma separated]
    0... .... = Request/Response: Message is a request to the server
    .0.. .... = Notify: Notify client only on open
    ..0. .... = Oplocks: OpLock not requested/granted
    ...B .... = Canonicalized Pathnames: Pathnames [are|are not] canonicalized
    .... B... = Case Sensitivity: Path names [are|are not] caseless
    .... ..B. = Receive Buffer Posted: Receive buffer [has|has not] been posted
    .... ...B = Lock and Read: Lock&Read, Write&Unlock [are|are not] supported
[/Flags]
[Flags]
  Flags2: 0x[h], [Enabled Flags2, comma separated]
    B... .... .... .... = Unicode Strings: Strings [are|are not] Unicode
    .B.. .... .... .... = Error Code Type: Error codes [are|are not] NT error codes
    ..B. .... .... .... = Execute-only Reads: [Do|Don't] permit reads if execute-only
    ...B .... .... .... = Dfs: [Do|Don't] resolve pathnames with Dfs
    .... B... .... .... = Extended Security Negotiation: Extended security negotiation is supported
    .... .B.. .... .... = Reparse Path: The request [does|does not] use a @GMT reparse path
    .... .... .B.. .... = Long Names Used: Path names in request [are|are not] long file names
    .... .... ...B .... = Security Signatures Required: Security signatures [are|are not] required
    .... .... .... B... = Compressed: Compression [is|is not] requested
    .... .... .... .B.. = Security Signatures: Security signatures [are|are not] supported
    .... .... .... ..B. = Extended Attributes: Extended attributes [are|are not] supported
    .... .... .... ...B = Long Names Allowed: Long file names [are|are not] allowed in the response
[/Flags]
  Process ID High: 0
  Signature: 0000000000000000
  Reserved: 0000
  Tree ID: 65535
  Process ID: 65279
  User ID: 0
  Multiplex ID: 0
```


##### SMB2

Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-fe66f1228052


###### SYNC

Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4

####### REQUEST 

```
SMB2 Header
  ProtocolId: 0x[h]
  Header Length: [n]
  Credit Charge: [n]
  Channel Sequence: [n]
  Reserved: 0000
  Command: [Command] ([n])
  Credits requested: [n]
[Flags]
  Flags: 0x[h], [Enabled Flags, comma separated]
    .... .... .... .... .... .... .... ...0 = Response: This is a REQUEST
    .... .... .... .... .... .... .... ..B. = Async command: This is a [SYNC|ASYNC] command
    .... .... .... .... .... .... .... .B.. = Chained: This pdu [is|is NOT] a chained command
    .... .... .... .... .... .... .... B... = Signing: This pdu [is|is NOT] SIGNED
    .... .... .... .... .... .... .BBB .... = Priority: This pdu contains a PRIORITY ([n])
    ...B .... .... .... .... .... .... .... = DFS operation: This is a [DFS|normal] operation
    ..B. .... .... .... .... .... .... .... = Replay operation: This [is|is NOT] a replay operation
[/Flags]
  Chain Offset: 0x[h]
  Message ID: [n]
  Reserved: 0x[h]
  Tree Id: 0x[h]  \\[server]\[share] [See `Special Notes`]
  Session Id: 0x[h]
  Signature: [h]
```


####### RESPONSE (SYNC)

```
SMB2 Header
  ProtocolId: 0x[h]
  Header Length: [n]
  Credit Charge: [n]
  NT Status: [Status] (0x[h])
  Command: [Command] ([n])
  Credits granted: [n]
[Flags]
  Flags: 0x[h], [Enabled Flags, comma separated]
    .... .... .... .... .... .... .... ...1 = Response: This is a RESPONSE
    .... .... .... .... .... .... .... ..B. = Async command: This is a [ASYNC|SYNC] command
    .... .... .... .... .... .... .... .B.. = Chained: This pdu [is|is NOT] a chained command
    .... .... .... .... .... .... .... B... = Signing: This pdu [is|is NOT] SIGNED
    .... .... .... .... .... .... .BBB .... = Priority: This pdu contains a PRIORITY ([n])
    ...B .... .... .... .... .... .... .... = DFS operation: This is a [DFS|normal] operation
    ..B. .... .... .... .... .... .... .... = Replay operation: This [is|is NOT] a replay operation
[/Flags]
  Chain Offset: 0x[h]
  Message ID: [n]
  Reserved: 0x[h]
  Tree Id: 0x[h]  \\[server]\[share] [See `Special Notes`]
  Session Id: 0x[h]
  Signature: [h]
```

###### ASYNC

Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79

Same as `SYNC`, but the post-Flags `Reserved` + `Tree Id` is replaced by `Async Id`.


#### SMB Command

Parse based on Wireshark dissection.

https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-smb2.c?ref_type=heads


The parser must be capable of outputting multiple (chained) commands per packet.

The parser must parse file and directory FileInfo results, one or more per packet, for the commands: QUERY DIRECTORY, QUERY INFO, SET INFO. Use the Wireshark dissectors when possible, use MS-SMB2 as a baseline for parsing when a Wireshark dissector is not available.