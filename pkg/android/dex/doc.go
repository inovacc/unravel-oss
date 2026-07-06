/*
Copyright (c) 2026 Security Research

Package dex provides parsing and security analysis of Dalvik Executable (DEX)
files found inside Android APK archives.

The parser reads DEX headers, string tables, type descriptors, class definitions,
method references, and field references. It supports multi-DEX APKs and performs
risk analysis by matching method references against known dangerous Android APIs.

Entry points:
  - Parse: parses a single DEX file from an io.ReaderAt
  - ScanAPK: opens an APK and parses all classes*.dex entries
  - AnalyzeRisk: checks a parsed DexFile for dangerous API usage
*/
package dex
