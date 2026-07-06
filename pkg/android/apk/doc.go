/*
Copyright (c) 2026 Security Research

Package apk provides parsing, extraction, and analysis of Android APK files.

APK files are ZIP archives with a specific structure containing:
  - AndroidManifest.xml (binary XML)
  - classes*.dex (Dalvik bytecode)
  - lib/<abi>/*.so (native libraries)
  - res/ and resources.arsc (compiled resources)
  - assets/ (raw assets)
  - META-INF/ (signing information)

Supported formats:
  - APK: Standard Android application package
  - AAB: Android App Bundle
  - Split: Split APK (feature/config modules)
  - XAPK: Multi-APK container (APKPure format)
  - APKS: APK Set (bundletool format)

Signature schemes:
  - v1: JAR signing (META-INF/*.SF + *.RSA/DSA/EC)
  - v2: APK Signature Scheme v2 (block ID 0x7109871a)
  - v3: APK Signature Scheme v3 (block ID 0xf05368c0)
  - v4: APK Signature Scheme v4 (external .idsig file)

Entry points:
  - Info: Enumerate APK contents and metadata
  - Extract: Extract APK contents to disk
  - Verify: Check signature schemes
  - ExtractCertificates: Parse signing certificates
*/
package apk
