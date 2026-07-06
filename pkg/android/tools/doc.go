/*
Copyright (c) 2026 Security Research
*/

// Package tools provides external tool detection, execution, and orchestrated
// decompilation pipelines for Android reverse engineering.
//
// It integrates with common Android security research tools:
//   - apktool: APK resource decoding and smali disassembly
//   - jadx: DEX to Java decompilation
//   - dex2jar: DEX to JAR conversion
//   - procyon: JAR to Java decompilation (jadx fallback)
//   - jd-cli: JAR to Java decompilation (second fallback)
//   - retdec: Native .so library decompilation
//   - ilspycmd: .NET/Xamarin assembly decompilation
//   - bundletool: AAB to APK conversion
//   - adb: Android Debug Bridge for device interaction
//
// The decompilation pipeline automatically detects the input format (APK, AAB,
// XAPK, APKM, APKS), unwraps bundles, and runs available tools in sequence to
// produce human-readable source code.
package tools
