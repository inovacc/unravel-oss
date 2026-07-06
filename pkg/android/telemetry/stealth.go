/*
Copyright (c) 2026 Security Research
*/

package telemetry

import (
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/manifest"
)

func DetectStealth(m *manifest.Manifest, dexResult *dex.ParseResult) []StealthFeature {
	if m == nil {
		return nil
	}

	var features []StealthFeature

	// Accessibility Service Abuse
	features = append(features, detectAccessibilityService(m, dexResult)...)

	// Overlay/Draw Over Other Apps
	features = append(features, detectOverlay(m, dexResult)...)

	// Device Admin
	features = append(features, detectDeviceAdmin(m)...)

	// Usage Stats Access
	features = append(features, detectUsageStats(m)...)

	// Install from Unknown Sources
	features = append(features, detectInstallPackages(m)...)

	// SMS/Call Interception
	features = append(features, detectSMSCallInterception(m)...)

	// Screen Capture/Recording
	features = append(features, detectScreenCapture(m, dexResult)...)

	// Background Location
	features = append(features, detectBackgroundLocation(m)...)

	return features
}

func detectAccessibilityService(m *manifest.Manifest, dexResult *dex.ParseResult) []StealthFeature {
	var features []StealthFeature

	for _, comp := range m.Components {
		if comp.Type == "service" {
			for _, filter := range comp.IntentFilters {
				for _, action := range filter.Actions {
					if action == "android.accessibilityservice.AccessibilityService" {
						features = append(features, StealthFeature{
							Type:        "accessibility",
							Component:   comp.Name,
							Description: "Accessibility service can monitor user interactions and screen content",
							Risk:        "high",
						})
					}
				}
			}
		}
	}

	if dexResult != nil {
		for _, dexFile := range dexResult.DexFiles {
			for _, class := range dexFile.Classes {
				cn := strings.TrimPrefix(class.ClassName, "L")
				if strings.Contains(cn, "AccessibilityService") &&
					!strings.HasPrefix(cn, "android/") {
					found := false
					for _, f := range features {
						if f.Type == "accessibility" {
							found = true
							break
						}
					}
					if !found {
						features = append(features, StealthFeature{
							Type:        "accessibility",
							Component:   class.ClassName,
							Description: "Custom accessibility service implementation detected",
							Risk:        "high",
						})
					}
					break
				}
			}
		}
	}

	return features
}

func detectOverlay(m *manifest.Manifest, dexResult *dex.ParseResult) []StealthFeature {
	var features []StealthFeature

	for _, perm := range m.Permissions {
		if perm.Name == "android.permission.SYSTEM_ALERT_WINDOW" {
			features = append(features, StealthFeature{
				Type:        "overlay",
				Component:   "SYSTEM_ALERT_WINDOW",
				Description: "Can draw over other apps and capture sensitive information",
				Risk:        "high",
			})
			break
		}
	}

	if dexResult != nil {
		for _, dexFile := range dexResult.DexFiles {
			for _, method := range dexFile.Methods {
				mcn := strings.TrimPrefix(method.ClassName, "L")
				if strings.Contains(mcn, "WindowManager") &&
					(strings.Contains(mcn, "TYPE_APPLICATION_OVERLAY") ||
						strings.Contains(mcn, "TYPE_SYSTEM_ALERT")) {
					found := false
					for _, f := range features {
						if f.Type == "overlay" {
							found = true
							break
						}
					}
					if !found {
						features = append(features, StealthFeature{
							Type:        "overlay",
							Component:   method.ClassName,
							Description: "Uses overlay window types to draw over other apps",
							Risk:        "high",
						})
					}
					break
				}
			}
		}
	}

	return features
}

func detectDeviceAdmin(m *manifest.Manifest) []StealthFeature {
	var features []StealthFeature

	for _, comp := range m.Components {
		for _, filter := range comp.IntentFilters {
			for _, action := range filter.Actions {
				if action == "android.app.action.DEVICE_ADMIN_ENABLED" {
					features = append(features, StealthFeature{
						Type:        "device_admin",
						Component:   comp.Name,
						Description: "Can gain device admin privileges for device control",
						Risk:        "high",
					})
				}
			}
		}
	}

	for _, perm := range m.Permissions {
		if perm.Name == "android.permission.BIND_DEVICE_ADMIN" {
			found := false
			for _, f := range features {
				if f.Type == "device_admin" {
					found = true
					break
				}
			}
			if !found {
				features = append(features, StealthFeature{
					Type:        "device_admin",
					Component:   "BIND_DEVICE_ADMIN",
					Description: "Requests device admin binding permission",
					Risk:        "high",
				})
			}
			break
		}
	}

	return features
}

func detectUsageStats(m *manifest.Manifest) []StealthFeature {
	var features []StealthFeature

	for _, perm := range m.Permissions {
		if perm.Name == "android.permission.PACKAGE_USAGE_STATS" {
			features = append(features, StealthFeature{
				Type:        "usage_stats",
				Component:   "PACKAGE_USAGE_STATS",
				Description: "Can monitor app usage and screen time of other apps",
				Risk:        "medium",
			})
			break
		}
	}

	return features
}

func detectInstallPackages(m *manifest.Manifest) []StealthFeature {
	var features []StealthFeature

	for _, perm := range m.Permissions {
		if perm.Name == "android.permission.REQUEST_INSTALL_PACKAGES" {
			features = append(features, StealthFeature{
				Type:        "install_packages",
				Component:   "REQUEST_INSTALL_PACKAGES",
				Description: "Can install apps from unknown sources",
				Risk:        "medium",
			})
			break
		}
	}

	return features
}

func detectSMSCallInterception(m *manifest.Manifest) []StealthFeature {
	var features []StealthFeature

	smsPerms := []string{"RECEIVE_SMS", "READ_SMS", "SEND_SMS"}
	callPerms := []string{"PROCESS_OUTGOING_CALLS", "READ_CALL_LOG"}

	hasSMS := false
	hasCall := false

	for _, perm := range m.Permissions {
		permName := perm.Name
		if after, ok := strings.CutPrefix(permName, "android.permission."); ok {
			permName = after
		}

		if slices.Contains(smsPerms, permName) {
			hasSMS = true
		}

		if slices.Contains(callPerms, permName) {
			hasCall = true
		}
	}

	if hasSMS {
		for _, comp := range m.Components {
			if comp.Type == "receiver" {
				for _, filter := range comp.IntentFilters {
					for _, action := range filter.Actions {
						if action == "android.provider.Telephony.SMS_RECEIVED" {
							features = append(features, StealthFeature{
								Type:        "sms_interception",
								Component:   comp.Name,
								Description: "Can intercept and read incoming SMS messages",
								Risk:        "high",
							})
						}
					}
				}
			}
		}

		if len(features) == 0 {
			features = append(features, StealthFeature{
				Type:        "sms_interception",
				Component:   "SMS permissions",
				Description: "Has SMS permissions but no explicit receiver",
				Risk:        "high",
			})
		}
	}

	if hasCall {
		for _, comp := range m.Components {
			if comp.Type == "receiver" {
				for _, filter := range comp.IntentFilters {
					for _, action := range filter.Actions {
						if action == "android.intent.action.NEW_OUTGOING_CALL" {
							features = append(features, StealthFeature{
								Type:        "call_interception",
								Component:   comp.Name,
								Description: "Can intercept outgoing calls",
								Risk:        "high",
							})
						}
					}
				}
			}
		}

		if len(features) == 0 || features[len(features)-1].Type != "call_interception" {
			features = append(features, StealthFeature{
				Type:        "call_interception",
				Component:   "Call permissions",
				Description: "Has call permissions for monitoring",
				Risk:        "high",
			})
		}
	}

	return features
}

func detectScreenCapture(m *manifest.Manifest, dexResult *dex.ParseResult) []StealthFeature {
	var features []StealthFeature

	for _, perm := range m.Permissions {
		if perm.Name == "android.permission.CAPTURE_VIDEO_OUTPUT" ||
			perm.Name == "android.permission.CAPTURE_AUDIO_OUTPUT" {
			features = append(features, StealthFeature{
				Type:        "screen_capture",
				Component:   perm.Name,
				Description: "Can capture screen or audio output",
				Risk:        "medium",
			})
			break
		}
	}

	if dexResult != nil {
		for _, dexFile := range dexResult.DexFiles {
			for _, class := range dexFile.Classes {
				cn := strings.TrimPrefix(class.ClassName, "L")
				if strings.Contains(cn, "MediaProjectionManager") &&
					strings.HasPrefix(cn, "android/media/projection/") {
					found := false
					for _, f := range features {
						if f.Type == "screen_capture" {
							found = true
							break
						}
					}
					if !found {
						features = append(features, StealthFeature{
							Type:        "screen_capture",
							Component:   "MediaProjectionManager",
							Description: "Uses MediaProjection API for screen recording",
							Risk:        "medium",
						})
					}
					break
				}
			}
		}
	}

	return features
}

func detectBackgroundLocation(m *manifest.Manifest) []StealthFeature {
	var features []StealthFeature

	for _, perm := range m.Permissions {
		if perm.Name == "android.permission.ACCESS_BACKGROUND_LOCATION" {
			features = append(features, StealthFeature{
				Type:        "background_location",
				Component:   "ACCESS_BACKGROUND_LOCATION",
				Description: "Can track location even when app is not in use",
				Risk:        "medium",
			})
			break
		}
	}

	return features
}
