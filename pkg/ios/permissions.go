package ios

// permissionDescriptions maps iOS NS*UsageDescription plist keys to human-readable descriptions.
var permissionDescriptions = map[string]string{
	// Camera & Microphone
	"NSCameraUsageDescription":     "Camera access",
	"NSMicrophoneUsageDescription": "Microphone access",

	// Photos
	"NSPhotoLibraryUsageDescription":    "Photo library access",
	"NSPhotoLibraryAddUsageDescription": "Photo library add-only access",

	// Location
	"NSLocationWhenInUseUsageDescription":           "Location (when in use)",
	"NSLocationAlwaysUsageDescription":              "Location (always)",
	"NSLocationAlwaysAndWhenInUseUsageDescription":  "Location (always and when in use)",
	"NSLocationTemporaryUsageDescriptionDictionary": "Temporary precise location",

	// Contacts & Calendar
	"NSContactsUsageDescription":  "Contacts access",
	"NSCalendarsUsageDescription": "Calendar access",
	"NSRemindersUsageDescription": "Reminders access",

	// Health
	"NSHealthShareUsageDescription":                      "HealthKit data reading",
	"NSHealthUpdateUsageDescription":                     "HealthKit data writing",
	"NSHealthClinicalHealthRecordsShareUsageDescription": "Clinical health records",

	// Motion & Fitness
	"NSMotionUsageDescription": "Motion and fitness data",

	// Bluetooth
	"NSBluetoothAlwaysUsageDescription":     "Bluetooth access",
	"NSBluetoothPeripheralUsageDescription": "Bluetooth peripheral access",

	// Home & HomeKit
	"NSHomeKitUsageDescription": "HomeKit access",

	// Media & Apple Music
	"NSAppleMusicUsageDescription": "Media library / Apple Music access",

	// Speech Recognition
	"NSSpeechRecognitionUsageDescription": "Speech recognition",

	// Siri
	"NSSiriUsageDescription": "Siri integration",

	// Face ID
	"NSFaceIDUsageDescription": "Face ID authentication",

	// Network
	"NSLocalNetworkUsageDescription": "Local network discovery",

	// Tracking
	"NSUserTrackingUsageDescription": "App tracking transparency",

	// NFC
	"NFCReaderUsageDescription": "NFC tag reading",

	// Files
	"NSDocumentsFolderUsageDescription": "Documents folder access",
	"NSDownloadsFolderUsageDescription": "Downloads folder access",
	"NSDesktopFolderUsageDescription":   "Desktop folder access",

	// Sensors
	"NSSensorKitUsageDescription": "SensorKit data access",

	// Identity
	"NSIdentityUsageDescription": "Identity lookup",

	// Nearby Interaction
	"NSNearbyInteractionUsageDescription":          "Nearby interaction",
	"NSNearbyInteractionAllowOnceUsageDescription": "Nearby interaction (one-time)",

	// Video Subscriber
	"NSVideoSubscriberAccountUsageDescription": "TV provider account access",

	// System Extensions
	"NSSystemExtensionUsageDescription": "System extension installation",

	// Focus
	"NSFocusStatusUsageDescription": "Focus status access",

	// Fall Detection
	"NSFallDetectionUsageDescription": "Fall detection data",
}

// DescribePermission returns a human-readable description for an iOS permission key.
// If the key is unknown, it returns the key itself with " (unknown)" appended.
func DescribePermission(key string) string {
	if desc, ok := permissionDescriptions[key]; ok {
		return desc
	}
	return key + " (unknown)"
}
