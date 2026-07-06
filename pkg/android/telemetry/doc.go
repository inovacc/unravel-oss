/*
Copyright (c) 2026 Security Research
*/

// Package telemetry provides detection of analytics, advertising, attribution SDKs,
// and stealth features in Android applications.
//
// This package analyzes DEX files and AndroidManifest.xml to identify:
//   - Analytics SDKs (Firebase, Mixpanel, Amplitude, etc.)
//   - Advertising SDKs (AdMob, Meta Audience Network, Unity Ads, etc.)
//   - Attribution SDKs (AppsFlyer, Adjust, Branch, etc.)
//   - Crash reporting SDKs (Crashlytics, Sentry, Bugsnag, etc.)
//   - Push notification SDKs (FCM, OneSignal, etc.)
//   - Stealth features (accessibility abuse, overlays, device admin, etc.)
//
// The detection is performed by matching class name prefixes in DEX files
// against known SDK package patterns, and analyzing manifest components
// and permissions for stealth capabilities.
package telemetry
