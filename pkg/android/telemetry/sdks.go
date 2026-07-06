/*
Copyright (c) 2026 Security Research
*/

package telemetry

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

type sdkPattern struct {
	Name     string
	Category SDKCategory
	Packages []string
	Manifest []string
}

var sdkPatterns = []sdkPattern{
	// Analytics
	{
		Name:     "Firebase Analytics",
		Category: CategoryAnalytics,
		Packages: []string{"com/google/firebase/analytics", "com/google/android/gms/measurement"},
	},
	{
		Name:     "Google Analytics",
		Category: CategoryAnalytics,
		Packages: []string{"com/google/android/gms/analytics"},
	},
	{
		Name:     "Mixpanel",
		Category: CategoryAnalytics,
		Packages: []string{"com/mixpanel/android"},
	},
	{
		Name:     "Amplitude",
		Category: CategoryAnalytics,
		Packages: []string{"com/amplitude/api", "com/amplitude/android"},
	},
	{
		Name:     "Segment",
		Category: CategoryAnalytics,
		Packages: []string{"com/segment/analytics"},
	},
	{
		Name:     "Flurry",
		Category: CategoryAnalytics,
		Packages: []string{"com/flurry/android"},
	},
	{
		Name:     "Countly",
		Category: CategoryAnalytics,
		Packages: []string{"ly/count/android"},
	},
	{
		Name:     "CleverTap",
		Category: CategoryAnalytics,
		Packages: []string{"com/clevertap/android"},
	},
	{
		Name:     "Braze",
		Category: CategoryAnalytics,
		Packages: []string{"com/braze/", "com/appboy/"},
	},
	{
		Name:     "Heap",
		Category: CategoryAnalytics,
		Packages: []string{"com/heapanalytics/android"},
	},
	{
		Name:     "Snowplow",
		Category: CategoryAnalytics,
		Packages: []string{"com/snowplowanalytics/"},
	},
	{
		Name:     "PostHog",
		Category: CategoryAnalytics,
		Packages: []string{"com/posthog/android"},
	},

	// Ads
	{
		Name:     "AdMob",
		Category: CategoryAds,
		Packages: []string{"com/google/android/gms/ads"},
	},
	{
		Name:     "Meta Audience Network",
		Category: CategoryAds,
		Packages: []string{"com/facebook/ads"},
	},
	{
		Name:     "Unity Ads",
		Category: CategoryAds,
		Packages: []string{"com/unity3d/ads"},
	},
	{
		Name:     "IronSource",
		Category: CategoryAds,
		Packages: []string{"com/ironsource/mediationsdk"},
	},
	{
		Name:     "AppLovin",
		Category: CategoryAds,
		Packages: []string{"com/applovin/sdk"},
	},
	{
		Name:     "Vungle",
		Category: CategoryAds,
		Packages: []string{"com/vungle/ads", "com/vungle/warren"},
	},
	{
		Name:     "Chartboost",
		Category: CategoryAds,
		Packages: []string{"com/chartboost/sdk"},
	},
	{
		Name:     "InMobi",
		Category: CategoryAds,
		Packages: []string{"com/inmobi/ads"},
	},
	{
		Name:     "MoPub",
		Category: CategoryAds,
		Packages: []string{"com/mopub/mobileads"},
	},
	{
		Name:     "Pangle (TikTok)",
		Category: CategoryAds,
		Packages: []string{"com/bytedance/sdk/openadsdk"},
	},
	{
		Name:     "StartApp",
		Category: CategoryAds,
		Packages: []string{"com/startapp/sdk"},
	},
	{
		Name:     "AdColony",
		Category: CategoryAds,
		Packages: []string{"com/adcolony/sdk"},
	},

	// Attribution
	{
		Name:     "AppsFlyer",
		Category: CategoryAttribution,
		Packages: []string{"com/appsflyer/"},
	},
	{
		Name:     "Adjust",
		Category: CategoryAttribution,
		Packages: []string{"com/adjust/sdk"},
	},
	{
		Name:     "Branch",
		Category: CategoryAttribution,
		Packages: []string{"io/branch/referral"},
	},
	{
		Name:     "Singular",
		Category: CategoryAttribution,
		Packages: []string{"com/singular/sdk"},
	},
	{
		Name:     "Kochava",
		Category: CategoryAttribution,
		Packages: []string{"com/kochava/base"},
	},
	{
		Name:     "Tenjin",
		Category: CategoryAttribution,
		Packages: []string{"com/tenjin/android"},
	},

	// Crash
	{
		Name:     "Firebase Crashlytics",
		Category: CategoryCrash,
		Packages: []string{"com/google/firebase/crashlytics", "com/crashlytics/android"},
	},
	{
		Name:     "Sentry",
		Category: CategoryCrash,
		Packages: []string{"io/sentry/android"},
	},
	{
		Name:     "Bugsnag",
		Category: CategoryCrash,
		Packages: []string{"com/bugsnag/android"},
	},
	{
		Name:     "Instabug",
		Category: CategoryCrash,
		Packages: []string{"com/instabug/library"},
	},
	{
		Name:     "Datadog",
		Category: CategoryCrash,
		Packages: []string{"com/datadog/android"},
	},

	// Push
	{
		Name:     "Firebase Cloud Messaging",
		Category: CategoryPush,
		Packages: []string{"com/google/firebase/messaging"},
	},
	{
		Name:     "OneSignal",
		Category: CategoryPush,
		Packages: []string{"com/onesignal/"},
	},
	{
		Name:     "Pushwoosh",
		Category: CategoryPush,
		Packages: []string{"com/pushwoosh/"},
	},
	{
		Name:     "Airship",
		Category: CategoryPush,
		Packages: []string{"com/urbanairship/android"},
	},
	{
		Name:     "Pusher",
		Category: CategoryPush,
		Packages: []string{"com/pusher/client"},
	},
}

func DetectSDKs(dexResult *dex.ParseResult) []SDKInfo {
	if dexResult == nil {
		return nil
	}

	var detected []SDKInfo

	for _, pattern := range sdkPatterns {
		var evidence []string

		for _, dexFile := range dexResult.DexFiles {
			for _, class := range dexFile.Classes {
				cn := strings.TrimPrefix(class.ClassName, "L")
				for _, pkg := range pattern.Packages {
					if strings.HasPrefix(cn, pkg) {
						evidence = append(evidence, class.ClassName)
						if len(evidence) >= 5 {
							break
						}
					}
				}
				if len(evidence) >= 5 {
					break
				}
			}
			if len(evidence) >= 5 {
				break
			}
		}

		if len(evidence) > 0 {
			confidence := 70.0
			if len(evidence) > 1 {
				confidence = 90.0
			}

			detected = append(detected, SDKInfo{
				Name:       pattern.Name,
				Category:   pattern.Category,
				Package:    pattern.Packages[0],
				Confidence: confidence,
				Evidence:   evidence,
			})
		}
	}

	return detected
}
