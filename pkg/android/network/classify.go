/*
Copyright (c) 2026 Security Research
*/

package network

import (
	"net"
	"strings"
)

// domainPatterns maps domain suffixes to categories.
// More specific patterns should be checked first.
var domainPatterns = []struct {
	suffix   string
	category DomainCategory
}{
	// Analytics (check before more general patterns)
	{"google-analytics.com", CategoryAnalytics},
	{"firebase.googleapis.com", CategoryAnalytics},
	{"mixpanel.com", CategoryAnalytics},
	{"amplitude.com", CategoryAnalytics},
	{"segment.io", CategoryAnalytics},
	{"crashlytics.com", CategoryAnalytics},

	// Ads
	{"doubleclick.net", CategoryAds},
	{"admob.com", CategoryAds},
	{"googlesyndication.com", CategoryAds},
	{"adjust.com", CategoryAds},
	{"mopub.com", CategoryAds},

	// CDN
	{"cloudfront.net", CategoryCDN},
	{"akamai.net", CategoryCDN},
	{"akamaized.net", CategoryCDN},
	{"fastly.net", CategoryCDN},
	{"cloudflare.com", CategoryCDN},

	// Cloud (check specific services before general .com domains)
	{"amazonaws.com", CategoryCloud},
	{"googleapis.com", CategoryCloud},
	{"azure.com", CategoryCloud},
	{"firebaseio.com", CategoryCloud},
	{"appspot.com", CategoryCloud},

	// Social
	{"facebook.com", CategorySocial},
	{"twitter.com", CategorySocial},
	{"instagram.com", CategorySocial},
	{"linkedin.com", CategorySocial},

	// AppsFlyer can be both analytics and ads, default to ads
	{"appsflyer.com", CategoryAds},
}

// ClassifyDomain classifies a domain based on known patterns.
func ClassifyDomain(domain string) DomainCategory {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check for internal/private addresses
	if isInternalDomain(domain) {
		return CategoryInternal
	}

	// Check for CDN pattern (cdn.*)
	if strings.HasPrefix(domain, "cdn.") {
		return CategoryCDN
	}

	// Check specific domain patterns (most specific first)
	for _, pattern := range domainPatterns {
		if strings.HasSuffix(domain, pattern.suffix) {
			return pattern.category
		}
	}

	return CategoryUnknown
}

// isInternalDomain checks if a domain is internal/private.
func isInternalDomain(domain string) bool {
	// Check for localhost and special domains
	if domain == "localhost" ||
		strings.HasSuffix(domain, ".local") ||
		strings.HasSuffix(domain, ".internal") ||
		domain == "127.0.0.1" ||
		domain == "::1" {
		return true
	}

	// Parse as IP address
	ip := net.ParseIP(domain)
	if ip == nil {
		return false
	}

	// Check RFC1918 private ranges
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}

	return false
}
