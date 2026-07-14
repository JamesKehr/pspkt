# HTTP Parser Reference

This document describes the `HTTP` output produced by the pspkt parsers across every parsing
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

- Decimal: Status Code, Content-Length.
- All other fields (method, URI, version, host, user-agent, reason phrase) are the verbatim
  ASCII text from the message.

## Notes

- Only HTTP/1.x over cleartext TCP (ports 80 / 8000 / 8080 / 8888) is parsed. HTTPS/TLS is not
  decrypted.
- **Response URI:** the `URI: [Host + Request URI]` shown in the spec for a RESPONSE requires
  correlating the response with its earlier request. pspkt parses single packets without
  request/response correlation, so a response line omits the `, URI: ...` part and shows only
  `HTTP: [Status Code] [Response Phrase]`.
- The Analysis Details node header is the Default one-liner (so the collapsed view matches the
  Default level). Expanding it reveals the request-line / status-line sub-node and the parsed
  headers.

## Tree indentation

The Analysis Details tree uses a **plain two-space indent per level** with no `├`/`└`
connectors (tree connectors are available behind an opt-in `TreeFlattener.UseConnectors`
flag). Child leaves are indented two spaces under their parent.

---


# Levels

## Minimal

`HTTP`

## Default

### REQUEST

`HTTP: [Request Method], URI: [Host + Request URI]`

### RESPONSE

`HTTP: [Status Code] [Response Phrase], URI: [Host + Request URI]`

## Detailed

Same as `Default`

## Analysis

### Text Box

Same as `Default`

### Details: Collapsed

Same as `Default`

### Details: Expanded

The node header is the Default one-liner (same as Collapsed). Expanding reveals the
request-line / status-line sub-node (collapsed by default) plus the parsed headers.

#### REQUEST

```
HTTP: [Request Method], URI: [Host + Request URI]
  [+|-][Request Method] [Request URI] [HTTP Version]
      Request Method: [Request Method]
      Request URI: [Request URI]
      Request Version: [HTTP Version]
  Host: [Host]
  User-Agent: [Agent]
```

#### RESPONSE

```
HTTP: [Status Code] [Response Phrase]
  [+|-]HTTP/1.1 200 OK\r\n
      Response Version: HTTP/1.1
      Status Code: 200
      Response Phrase: OK
  Content-Length: 15
```