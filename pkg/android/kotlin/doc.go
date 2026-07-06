/*
Copyright (c) 2026 Security Research
*/

// Package kotlin provides Kotlin feature detection for Android APKs through DEX analysis.
//
// This package analyzes DEX bytecode to detect Kotlin language features and patterns without
// requiring full Kotlin metadata protobuf parsing. It identifies:
//
// - Kotlin stdlib presence and version
// - Data classes (via componentN and copy methods)
// - Coroutines, Flow, and Channel usage
// - Kotlinx Serialization (JSON, Protobuf, CBOR)
// - Jetpack Compose components
// - Language statistics (Kotlin vs Java class ratio, companion objects, sealed classes)
//
// The detection is heuristic-based, analyzing class names, method signatures, and string
// constants from DEX files to infer Kotlin feature usage patterns.
package kotlin
