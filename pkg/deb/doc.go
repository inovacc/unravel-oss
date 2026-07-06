/*
Copyright (c) 2026 Security Research

Package deb provides parsing, extraction, and analysis of Debian .deb packages.

DEB files are ar(1) archives containing three members:
  - debian-binary: format version string ("2.0")
  - control.tar.{gz,xz,zst}: package metadata (control file, scripts)
  - data.tar.{gz,xz,zst}: installable file tree

Supported compression: gzip, bzip2 (stdlib), xz and zstd (optional).

Entry points:
  - Info: Parse package metadata and list contents
  - Extract: Extract package contents to disk
  - Verify: Check for dpkg-sig/debsigs signatures
*/
package deb
