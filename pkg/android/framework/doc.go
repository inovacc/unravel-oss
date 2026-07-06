/*
Copyright (c) 2026 Security Research
*/

// Package framework detects mobile application frameworks (Flutter, React Native, Xamarin)
// used to build Android APKs by inspecting native libraries, assets, and DEX class names.
//
// Detection is heuristic-based, analyzing ZIP entries for framework-specific markers such as
// libflutter.so, index.android.bundle, assemblies/*.dll, and characteristic Java/Kotlin class
// prefixes in DEX bytecode.
package framework
