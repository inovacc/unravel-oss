/*
Copyright (c) 2026 Security Research

Package rpm provides parsing and analysis of RPM package files.

RPM files have a binary format consisting of:
  - Lead (96 bytes): legacy identification with magic 0xEDABEEDB
  - Signature header: cryptographic signatures and checksums
  - Header section: package metadata (name, version, deps, file list)
  - Payload: compressed CPIO archive (gzip, xz, zstd, bzip2)

The signature and header sections share the same binary format
(16-byte preamble + index entries + data store).

Supported compression for payload extraction: gzip, bzip2 (stdlib).
XZ and zstd payloads are detected but require external tools for extraction.

Entry points:
  - Info: Parse package metadata from header tags
  - Extract: Extract payload (CPIO archive) to disk
  - Verify: Check signature presence and hash integrity
*/
package rpm
