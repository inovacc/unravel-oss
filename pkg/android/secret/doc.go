/*
Copyright (c) 2026 Security Research

Package secret provides pattern-based scanning for hardcoded API keys,
tokens, and secrets inside Android APK archives.

The scanner opens the APK as a ZIP and inspects entries in-place (no full
extraction required), scanning DEX files, XML resources, assets, and native
libraries for known secret patterns and high-entropy strings.

Entry point:
  - Scan: opens an APK and returns all detected secrets with confidence levels
*/
package secret
