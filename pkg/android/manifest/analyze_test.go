/*
Copyright (c) 2026 Security Research
*/
package manifest

import "testing"

func TestAnalyze_BasicManifest(t *testing.T) {
	m := &Manifest{
		Package:     "com.test.app",
		VersionCode: 1,
		VersionName: "1.0",
		MinSDK:      21,
		TargetSDK:   34,
		Permissions: []Permission{
			{Name: "android.permission.INTERNET", RiskLevel: "normal"},
			{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
		},
		Security: SecurityFlags{
			Debuggable:  false,
			AllowBackup: false,
		},
	}

	a := Analyze(m)

	if a.PermissionSummary.Total != 2 {
		t.Errorf("expected 2 total permissions, got %d", a.PermissionSummary.Total)
	}
	if a.PermissionSummary.Dangerous != 1 {
		t.Errorf("expected 1 dangerous, got %d", a.PermissionSummary.Dangerous)
	}
	if a.PermissionSummary.Normal != 1 {
		t.Errorf("expected 1 normal, got %d", a.PermissionSummary.Normal)
	}
	if a.RiskLevel != "low" {
		t.Errorf("expected low risk, got %q", a.RiskLevel)
	}
}

func TestAnalyze_DebuggableHighScore(t *testing.T) {
	m := &Manifest{
		TargetSDK: 34,
		Security: SecurityFlags{
			Debuggable:           true,
			UsesCleartextTraffic: true,
		},
	}

	a := Analyze(m)

	if a.SecurityScore < 25 {
		t.Errorf("expected score >= 25 for debuggable+cleartext, got %d", a.SecurityScore)
	}

	// Should have critical + high issues
	foundDebug := false
	foundCleartext := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Application is debuggable" {
			foundDebug = true
			if issue.Severity != "critical" {
				t.Errorf("debuggable should be critical, got %q", issue.Severity)
			}
		}
		if issue.Title == "Cleartext traffic allowed" {
			foundCleartext = true
		}
	}
	if !foundDebug {
		t.Error("expected debuggable issue")
	}
	if !foundCleartext {
		t.Error("expected cleartext issue")
	}
}

func TestAnalyze_ExportedComponentRisks(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{Name: ".MainActivity", Type: ComponentActivity, Exported: &exported, Permission: ""},
			{Name: ".DataProvider", Type: ComponentProvider, Exported: &exported, Permission: ""},
		},
	}

	a := Analyze(m)

	if len(a.ComponentRisks) != 2 {
		t.Fatalf("expected 2 component risks, got %d", len(a.ComponentRisks))
	}

	for _, cr := range a.ComponentRisks {
		if cr.Risk != "high" {
			t.Errorf("expected high risk for %s, got %q", cr.Name, cr.Risk)
		}
	}
}

func TestAnalyze_ImplicitExport(t *testing.T) {
	m := &Manifest{
		TargetSDK: 30, // < 31, so intent-filter implies exported
		Components: []Component{
			{
				Name: ".DeepLinkActivity",
				Type: ComponentActivity,
				// No Exported field set
				IntentFilters: []IntentFilter{
					{Actions: []string{"android.intent.action.VIEW"}},
				},
			},
		},
	}

	a := Analyze(m)

	if len(a.ComponentRisks) != 1 {
		t.Fatalf("expected 1 component risk for implicit export, got %d", len(a.ComponentRisks))
	}

	if !a.ComponentRisks[0].ImplicitExport {
		t.Error("expected ImplicitExport=true")
	}
}

func TestAnalyze_DeepLinks(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{
				Name:     ".LinkActivity",
				Type:     ComponentActivity,
				Exported: &exported,
				IntentFilters: []IntentFilter{
					{
						Data: []IntentFilterData{
							{Scheme: "myapp", Host: "open", Path: "/home"},
							{Scheme: "https", Host: "example.com"},
						},
					},
				},
			},
		},
	}

	a := Analyze(m)

	if len(a.DeepLinks) != 2 {
		t.Fatalf("expected 2 deep links, got %d", len(a.DeepLinks))
	}

	if a.DeepLinks[0].URI != "myapp://open/home" {
		t.Errorf("expected 'myapp://open/home', got %q", a.DeepLinks[0].URI)
	}
	if a.DeepLinks[1].URI != "https://example.com" {
		t.Errorf("expected 'https://example.com', got %q", a.DeepLinks[1].URI)
	}
}

func TestAnalyze_LowTargetSDK(t *testing.T) {
	m := &Manifest{
		TargetSDK: 25,
	}

	a := Analyze(m)

	found := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Low target SDK" {
			found = true
		}
	}
	if !found {
		t.Error("expected low target SDK issue")
	}
}

func TestAnalyze_PermissionGroups(t *testing.T) {
	m := &Manifest{
		TargetSDK: 34,
		Permissions: []Permission{
			{Name: "android.permission.ACCESS_FINE_LOCATION", RiskLevel: "dangerous"},
			{Name: "android.permission.ACCESS_COARSE_LOCATION", RiskLevel: "dangerous"},
			{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
		},
	}

	a := Analyze(m)

	if len(a.PermissionSummary.Groups["location"]) != 2 {
		t.Errorf("expected 2 location permissions, got %d", len(a.PermissionSummary.Groups["location"]))
	}
	if len(a.PermissionSummary.Groups["camera"]) != 1 {
		t.Errorf("expected 1 camera permission, got %d", len(a.PermissionSummary.Groups["camera"]))
	}
}

func TestAnalyze_EmptyManifest(t *testing.T) {
	m := &Manifest{}

	a := Analyze(m)

	if a.PermissionSummary.Total != 0 {
		t.Errorf("expected 0 permissions, got %d", a.PermissionSummary.Total)
	}
	if a.SecurityScore != 0 {
		t.Errorf("expected score 0 for empty manifest, got %d", a.SecurityScore)
	}
	if a.RiskLevel != "low" {
		t.Errorf("expected low risk, got %q", a.RiskLevel)
	}
	// Should still have "no network security config" info issue
	found := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "No network security config" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'No network security config' issue for empty manifest")
	}
}

func TestAnalyze_ManyDangerousPermissions(t *testing.T) {
	perms := []Permission{
		{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
		{Name: "android.permission.RECORD_AUDIO", RiskLevel: "dangerous"},
		{Name: "android.permission.READ_CONTACTS", RiskLevel: "dangerous"},
		{Name: "android.permission.ACCESS_FINE_LOCATION", RiskLevel: "dangerous"},
		{Name: "android.permission.READ_SMS", RiskLevel: "dangerous"},
		{Name: "android.permission.CALL_PHONE", RiskLevel: "dangerous"},
	}

	m := &Manifest{
		TargetSDK:   34,
		Permissions: perms,
	}

	a := Analyze(m)

	if a.PermissionSummary.Dangerous != 6 {
		t.Errorf("expected 6 dangerous, got %d", a.PermissionSummary.Dangerous)
	}

	// Should trigger "many dangerous permissions" issue
	found := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Many dangerous permissions" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Many dangerous permissions' issue for 6 dangerous perms")
	}
}

func TestAnalyze_AllowBackup(t *testing.T) {
	m := &Manifest{
		TargetSDK: 34,
		Security: SecurityFlags{
			AllowBackup: true,
		},
	}

	a := Analyze(m)

	found := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Backup is enabled" {
			found = true
			if issue.Severity != "medium" {
				t.Errorf("backup issue severity = %q, want %q", issue.Severity, "medium")
			}
		}
	}
	if !found {
		t.Error("expected 'Backup is enabled' issue")
	}
}

func TestAnalyze_LowMinSDK(t *testing.T) {
	m := &Manifest{
		MinSDK:    19,
		TargetSDK: 34,
	}

	a := Analyze(m)

	found := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Very low minimum SDK" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Very low minimum SDK' issue for minSdk=19")
	}
}

func TestAnalyze_ExportedWithPermission(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{Name: ".GuardedActivity", Type: ComponentActivity, Exported: &exported, Permission: "com.test.PERM"},
		},
	}

	a := Analyze(m)

	if len(a.ComponentRisks) != 1 {
		t.Fatalf("expected 1 component risk, got %d", len(a.ComponentRisks))
	}
	if a.ComponentRisks[0].Risk != "medium" {
		t.Errorf("expected medium risk for guarded export, got %q", a.ComponentRisks[0].Risk)
	}
}

func TestAnalyze_NotExportedNoRisk(t *testing.T) {
	exported := false
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{Name: ".InternalService", Type: ComponentService, Exported: &exported},
		},
	}

	a := Analyze(m)

	if len(a.ComponentRisks) != 0 {
		t.Errorf("expected 0 component risks for non-exported, got %d", len(a.ComponentRisks))
	}
}

func TestAnalyze_UnguardedDeepLinks(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{
				Name:     ".OpenActivity",
				Type:     ComponentActivity,
				Exported: &exported,
				IntentFilters: []IntentFilter{
					{
						Data: []IntentFilterData{
							{Scheme: "app", Host: "open"},
						},
					},
				},
			},
		},
	}

	a := Analyze(m)

	found := false
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Unguarded deep links" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Unguarded deep links' issue")
	}
}

func TestAnalyze_MidTargetSDKScore(t *testing.T) {
	// targetSdk between 28 and 31 should add 5 points
	m := &Manifest{
		TargetSDK: 29,
	}

	a := Analyze(m)

	if a.SecurityScore < 5 {
		t.Errorf("expected score >= 5 for targetSdk=29, got %d", a.SecurityScore)
	}
}

func TestAnalyze_CriticalScore(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 25,
		Security: SecurityFlags{
			Debuggable:           true,
			UsesCleartextTraffic: true,
		},
		Permissions: []Permission{
			{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
			{Name: "android.permission.RECORD_AUDIO", RiskLevel: "dangerous"},
			{Name: "android.permission.READ_SMS", RiskLevel: "dangerous"},
			{Name: "android.permission.READ_CONTACTS", RiskLevel: "dangerous"},
			{Name: "android.permission.ACCESS_FINE_LOCATION", RiskLevel: "dangerous"},
			{Name: "android.permission.CALL_PHONE", RiskLevel: "dangerous"},
			{Name: "android.permission.READ_CALL_LOG", RiskLevel: "dangerous"},
			{Name: "android.permission.WRITE_EXTERNAL_STORAGE", RiskLevel: "dangerous"},
			{Name: "android.permission.READ_EXTERNAL_STORAGE", RiskLevel: "dangerous"},
			{Name: "android.permission.BODY_SENSORS", RiskLevel: "dangerous"},
		},
		Components: []Component{
			{Name: ".Exp1", Type: ComponentActivity, Exported: &exported},
			{Name: ".Exp2", Type: ComponentProvider, Exported: &exported},
			{Name: ".Exp3", Type: ComponentReceiver, Exported: &exported},
		},
	}

	a := Analyze(m)

	if a.RiskLevel != "critical" {
		t.Errorf("expected critical risk, got %q (score=%d)", a.RiskLevel, a.SecurityScore)
	}
	if a.SecurityScore < 70 {
		t.Errorf("expected score >= 70, got %d", a.SecurityScore)
	}
}

func TestPermissionGroup(t *testing.T) {
	tests := []struct {
		perm  string
		group string
	}{
		{"android.permission.CAMERA", "camera"},
		{"android.permission.ACCESS_FINE_LOCATION", "location"},
		{"android.permission.SEND_SMS", "sms"},
		{"android.permission.POST_NOTIFICATIONS", "notifications"},
		{"android.permission.INTERNET", ""},
		{"com.custom.PERM", ""},
	}

	for _, tt := range tests {
		got := permissionGroup(tt.perm)
		if got != tt.group {
			t.Errorf("permissionGroup(%q) = %q, want %q", tt.perm, got, tt.group)
		}
	}
}

func TestClassifyPermission_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"android.permission.BODY_SENSORS", "dangerous"},
		{"android.permission.WRITE_SETTINGS", "signature"},
		{"android.permission.WAKE_LOCK", "normal"},
		{"", "unknown"},
		{"some.random.permission", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyPermission(tt.name)
			if got != tt.expected {
				t.Errorf("ClassifyPermission(%q) = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

func TestAnalyze_SignaturePermissions(t *testing.T) {
	m := &Manifest{
		TargetSDK: 34,
		Permissions: []Permission{
			{Name: "android.permission.INSTALL_PACKAGES", RiskLevel: "signature"},
			{Name: "com.custom.PERM", RiskLevel: "unknown"},
		},
	}

	a := Analyze(m)

	if a.PermissionSummary.Signature != 1 {
		t.Errorf("expected 1 signature, got %d", a.PermissionSummary.Signature)
	}
	if a.PermissionSummary.Unknown != 1 {
		t.Errorf("expected 1 unknown, got %d", a.PermissionSummary.Unknown)
	}
}

func TestAnalyze_NetworkSecurityConfig(t *testing.T) {
	m := &Manifest{
		TargetSDK: 34,
		Security: SecurityFlags{
			NetworkSecurityConfig: true,
		},
	}

	a := Analyze(m)

	for _, issue := range a.SecurityIssues {
		if issue.Title == "No network security config" {
			t.Error("should not have 'No network security config' issue when config is present")
		}
	}
}

func TestAnalyze_DeepLinkSchemeOnly(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{
				Name:     ".SchemeOnly",
				Type:     ComponentActivity,
				Exported: &exported,
				IntentFilters: []IntentFilter{
					{
						Data: []IntentFilterData{
							{Scheme: "myapp"}, // no host, no path
							{},                // empty scheme - should be skipped
						},
					},
				},
			},
		},
	}

	a := Analyze(m)

	if len(a.DeepLinks) != 1 {
		t.Fatalf("expected 1 deep link (empty scheme skipped), got %d", len(a.DeepLinks))
	}
	if a.DeepLinks[0].URI != "myapp://" {
		t.Errorf("URI = %q, want %q", a.DeepLinks[0].URI, "myapp://")
	}
}

func TestAnalyze_GuardedDeepLink(t *testing.T) {
	exported := true
	m := &Manifest{
		TargetSDK: 34,
		Components: []Component{
			{
				Name:       ".Guarded",
				Type:       ComponentActivity,
				Exported:   &exported,
				Permission: "com.test.PERM",
				IntentFilters: []IntentFilter{
					{Data: []IntentFilterData{{Scheme: "safe", Host: "x"}}},
				},
			},
		},
	}

	a := Analyze(m)

	if len(a.DeepLinks) != 1 {
		t.Fatalf("expected 1 deep link, got %d", len(a.DeepLinks))
	}
	if !a.DeepLinks[0].Guarded {
		t.Error("expected deep link to be guarded")
	}

	// No "Unguarded deep links" issue
	for _, issue := range a.SecurityIssues {
		if issue.Title == "Unguarded deep links" {
			t.Error("should not have unguarded deep links issue")
		}
	}
}

func TestAnalyze_ImplicitExportTargetSDK31(t *testing.T) {
	// targetSdk >= 31, intent-filter does NOT imply export
	m := &Manifest{
		TargetSDK: 31,
		Components: []Component{
			{
				Name: ".NoExport",
				Type: ComponentActivity,
				IntentFilters: []IntentFilter{
					{Actions: []string{"android.intent.action.VIEW"}},
				},
			},
		},
	}

	a := Analyze(m)

	if len(a.ComponentRisks) != 0 {
		t.Errorf("expected 0 component risks for targetSdk=31 implicit, got %d", len(a.ComponentRisks))
	}
}

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score int
		level string
	}{
		{0, "low"},
		{19, "low"},
		{20, "medium"},
		{44, "medium"},
		{45, "high"},
		{69, "high"},
		{70, "critical"},
		{100, "critical"},
	}

	for _, tt := range tests {
		got := scoreToLevel(tt.score)
		if got != tt.level {
			t.Errorf("scoreToLevel(%d) = %q, want %q", tt.score, got, tt.level)
		}
	}
}
