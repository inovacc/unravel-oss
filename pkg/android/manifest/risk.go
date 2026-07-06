/*
Copyright (c) 2026 Security Research
*/
package manifest

import "strings"

// ClassifyPermission returns the risk level for an Android permission.
func ClassifyPermission(name string) string {
	if level, ok := dangerousPermissions[name]; ok {
		return level
	}

	if level, ok := signaturePermissions[name]; ok {
		return level
	}

	if strings.HasPrefix(name, "android.permission.") {
		return "normal"
	}

	return "unknown"
}

// dangerousPermissions maps permissions classified as "dangerous" by the Android framework.
var dangerousPermissions = map[string]string{
	// Body sensors
	"android.permission.BODY_SENSORS":            "dangerous",
	"android.permission.BODY_SENSORS_BACKGROUND": "dangerous",

	// Calendar
	"android.permission.READ_CALENDAR":  "dangerous",
	"android.permission.WRITE_CALENDAR": "dangerous",

	// Call log
	"android.permission.READ_CALL_LOG":          "dangerous",
	"android.permission.WRITE_CALL_LOG":         "dangerous",
	"android.permission.PROCESS_OUTGOING_CALLS": "dangerous",

	// Camera
	"android.permission.CAMERA": "dangerous",

	// Contacts
	"android.permission.READ_CONTACTS":  "dangerous",
	"android.permission.WRITE_CONTACTS": "dangerous",
	"android.permission.GET_ACCOUNTS":   "dangerous",

	// Location
	"android.permission.ACCESS_FINE_LOCATION":       "dangerous",
	"android.permission.ACCESS_COARSE_LOCATION":     "dangerous",
	"android.permission.ACCESS_BACKGROUND_LOCATION": "dangerous",

	// Microphone
	"android.permission.RECORD_AUDIO": "dangerous",

	// Phone
	"android.permission.READ_PHONE_STATE":   "dangerous",
	"android.permission.READ_PHONE_NUMBERS": "dangerous",
	"android.permission.CALL_PHONE":         "dangerous",
	"android.permission.ANSWER_PHONE_CALLS": "dangerous",
	"android.permission.ADD_VOICEMAIL":      "dangerous",
	"android.permission.USE_SIP":            "dangerous",

	// SMS
	"android.permission.SEND_SMS":         "dangerous",
	"android.permission.RECEIVE_SMS":      "dangerous",
	"android.permission.READ_SMS":         "dangerous",
	"android.permission.RECEIVE_WAP_PUSH": "dangerous",
	"android.permission.RECEIVE_MMS":      "dangerous",

	// Storage
	"android.permission.READ_EXTERNAL_STORAGE":   "dangerous",
	"android.permission.WRITE_EXTERNAL_STORAGE":  "dangerous",
	"android.permission.MANAGE_EXTERNAL_STORAGE": "dangerous",
	"android.permission.ACCESS_MEDIA_LOCATION":   "dangerous",
	"android.permission.READ_MEDIA_IMAGES":       "dangerous",
	"android.permission.READ_MEDIA_VIDEO":        "dangerous",
	"android.permission.READ_MEDIA_AUDIO":        "dangerous",

	// Nearby devices
	"android.permission.BLUETOOTH_CONNECT":   "dangerous",
	"android.permission.BLUETOOTH_SCAN":      "dangerous",
	"android.permission.BLUETOOTH_ADVERTISE": "dangerous",
	"android.permission.NEARBY_WIFI_DEVICES": "dangerous",

	// Notifications
	"android.permission.POST_NOTIFICATIONS": "dangerous",

	// Activity recognition
	"android.permission.ACTIVITY_RECOGNITION": "dangerous",
}

// signaturePermissions maps permissions that require signature-level protection.
var signaturePermissions = map[string]string{
	"android.permission.INSTALL_PACKAGES":               "signature",
	"android.permission.DELETE_PACKAGES":                "signature",
	"android.permission.MOUNT_UNMOUNT_FILESYSTEMS":      "signature",
	"android.permission.WRITE_SETTINGS":                 "signature",
	"android.permission.WRITE_SECURE_SETTINGS":          "signature",
	"android.permission.CHANGE_COMPONENT_ENABLED_STATE": "signature",
	"android.permission.GRANT_RUNTIME_PERMISSIONS":      "signature",
	"android.permission.DUMP":                           "signature",
	"android.permission.READ_LOGS":                      "signature",
	"android.permission.SET_DEBUG_APP":                  "signature",
	"android.permission.MANAGE_USERS":                   "signature",
	"android.permission.INTERACT_ACROSS_USERS_FULL":     "signature",
	"android.permission.MASTER_CLEAR":                   "signature",
}
