/*
Copyright (c) 2026 Security Research

Package native provides analysis of native shared libraries (.so) inside Android APK files.

It scans APK archives for ELF binaries under lib/<abi>/ directories and performs:
  - ABI detection and library metadata extraction
  - JNI native method export discovery and symbol decoding
  - Anti-debug, root detection, and emulator detection pattern matching
  - Packer/protector signature identification (UPX, Bangcle, Tencent Legu, etc.)

Entry point:
  - ScanAPK: Analyze all native libraries in an APK file
*/
package native
