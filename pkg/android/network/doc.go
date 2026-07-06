/*
Copyright (c) 2026 Security Research
*/

// Package network provides network traffic analysis for Android APKs.
//
// This package extracts and analyzes network endpoints, domain usage,
// certificate pinning configurations, and network security policies
// from APK files.
//
// Key features:
//   - URL and domain extraction from DEX strings, assets, and resources
//   - Domain classification (API, CDN, analytics, ads, social, cloud)
//   - Network security config parsing (Android 7.0+)
//   - Certificate pinning detection (network_security_config.xml, OkHttp, TrustManager)
//   - Cleartext traffic policy analysis
//
// Usage:
//
//	result, err := network.ScanAPK(apkPath, dexResult)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d endpoints across %d domains\n", result.TotalURLs, result.TotalDomains)
package network
