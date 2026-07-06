/*
Copyright (c) 2026 Security Research
*/
package obfuscation

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

func TestAnalyze_Obfuscated(t *testing.T) {
	// Build a ParseResult that looks heavily obfuscated:
	// single-letter package and class names following sequential pattern.
	var classes []dex.ClassDef
	var methods []dex.MethodRef

	letters := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	for _, pkg := range letters {
		for _, cls := range letters {
			classes = append(classes, dex.ClassDef{
				ClassName: "L" + pkg + "/" + cls + ";",
			})
			for _, m := range letters[:5] {
				methods = append(methods, dex.MethodRef{
					ClassName: pkg + "." + cls,
					Name:      m,
				})
			}
		}
	}

	result := Analyze(&dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Name:    "classes.dex",
				Classes: classes,
				Methods: methods,
			},
		},
		TotalClasses: len(classes),
		TotalMethods: len(methods),
	})

	if result.Type == ObfNone {
		t.Errorf("expected obfuscation to be detected, got type=%s", result.Type)
	}
	if result.Confidence <= 30 {
		t.Errorf("expected confidence > 30, got %.1f", result.Confidence)
	}
	if result.ShortClassPct <= 30 {
		t.Errorf("expected high short class percentage, got %.1f%%", result.ShortClassPct)
	}
	if result.Label == "none" {
		t.Errorf("expected non-none label, got %q", result.Label)
	}
}

func TestAnalyze_Normal(t *testing.T) {
	classes := []dex.ClassDef{
		{ClassName: "Lcom/example/myapp/MainActivity;"},
		{ClassName: "Lcom/example/myapp/LoginActivity;"},
		{ClassName: "Lcom/example/myapp/util/NetworkHelper;"},
		{ClassName: "Lcom/example/myapp/data/UserRepository;"},
		{ClassName: "Lcom/example/myapp/ui/HomeFragment;"},
	}

	methods := []dex.MethodRef{
		{ClassName: "com.example.myapp.MainActivity", Name: "onCreate"},
		{ClassName: "com.example.myapp.LoginActivity", Name: "authenticate"},
		{ClassName: "com.example.myapp.util.NetworkHelper", Name: "fetchData"},
		{ClassName: "com.example.myapp.data.UserRepository", Name: "getUser"},
		{ClassName: "com.example.myapp.ui.HomeFragment", Name: "onCreateView"},
	}

	result := Analyze(&dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Name:    "classes.dex",
				Classes: classes,
				Methods: methods,
			},
		},
		TotalClasses: len(classes),
		TotalMethods: len(methods),
	})

	if result.Type != ObfNone {
		t.Errorf("expected no obfuscation, got type=%s confidence=%.1f", result.Type, result.Confidence)
	}
	if result.Confidence > 30 {
		t.Errorf("expected low confidence, got %.1f", result.Confidence)
	}
}

func TestDetectMapping(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	_, err = w.Create("proguard/mapping.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if !DetectMapping(apkPath) {
		t.Error("expected mapping to be detected")
	}
}

func TestDetectMapping_NoMapping(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	_, err = w.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if DetectMapping(apkPath) {
		t.Error("expected no mapping to be detected")
	}
}

func TestDetectPacker(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	_, err = w.Create("lib/armeabi-v7a/libjiagu.so")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	info := DetectPacker(apkPath)
	if info == nil {
		t.Fatal("expected packer to be detected")
	}
	if info.Name != "Qihoo 360" {
		t.Errorf("expected Qihoo 360, got %s", info.Name)
	}
	if info.Confidence < 80 {
		t.Errorf("expected confidence >= 80, got %.1f", info.Confidence)
	}
}

func TestDetectPacker_NoPacker(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	_, err = w.Create("lib/armeabi-v7a/libnative.so")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if DetectPacker(apkPath) != nil {
		t.Error("expected no packer to be detected")
	}
}

func TestAnalyze_Nil(t *testing.T) {
	result := Analyze(nil)
	if result.Type != ObfNone {
		t.Errorf("expected ObfNone for nil input, got %s", result.Type)
	}
	if result.Label != "none" {
		t.Errorf("expected label 'none', got %q", result.Label)
	}
}

func TestAnalyze_ConfidenceScoring(t *testing.T) {
	tests := []struct {
		name      string
		classes   []dex.ClassDef
		methods   []dex.MethodRef
		wantLabel string
		wantMin   float64
		wantMax   float64
	}{
		{
			name: "very high confidence - all short names",
			classes: func() []dex.ClassDef {
				var c []dex.ClassDef
				for _, pkg := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
					for _, cls := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
						c = append(c, dex.ClassDef{ClassName: "L" + pkg + "/" + cls + ";"})
					}
				}
				return c
			}(),
			methods: func() []dex.MethodRef {
				var m []dex.MethodRef
				for _, n := range []string{"a", "b", "c", "d", "e"} {
					m = append(m, dex.MethodRef{ClassName: "a.a", Name: n})
				}
				return m
			}(),
			wantLabel: "high",
			wantMin:   60,
			wantMax:   100,
		},
		{
			name: "low confidence - normal names",
			classes: []dex.ClassDef{
				{ClassName: "Lcom/example/myapp/MainActivity;"},
				{ClassName: "Lcom/example/myapp/LoginActivity;"},
				{ClassName: "Lcom/example/myapp/util/NetworkHelper;"},
				{ClassName: "Lcom/example/myapp/data/UserRepository;"},
				{ClassName: "Lcom/example/myapp/ui/HomeFragment;"},
			},
			methods: []dex.MethodRef{
				{ClassName: "com.example.MainActivity", Name: "onCreate"},
				{ClassName: "com.example.LoginActivity", Name: "authenticate"},
				{ClassName: "com.example.NetworkHelper", Name: "fetchData"},
			},
			wantLabel: "none",
			wantMin:   0,
			wantMax:   20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Analyze(&dex.ParseResult{
				DexFiles: []dex.DexFile{{
					Classes: tt.classes,
					Methods: tt.methods,
				}},
				TotalClasses: len(tt.classes),
				TotalMethods: len(tt.methods),
			})

			if result.Label != tt.wantLabel {
				t.Errorf("label = %q, want %q (confidence=%.1f)", result.Label, tt.wantLabel, result.Confidence)
			}
			if result.Confidence < tt.wantMin || result.Confidence > tt.wantMax {
				t.Errorf("confidence = %.1f, want [%.1f, %.1f]", result.Confidence, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestAnalyze_DexGuardDetection(t *testing.T) {
	classes := []dex.ClassDef{
		{ClassName: "Lcom/example/OooOoOoO;"},
		{ClassName: "Lcom/example/MainActivity;"},
	}

	result := Analyze(&dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: classes,
		}},
		TotalClasses: len(classes),
	})

	if result.Type != ObfDexGuard {
		t.Errorf("expected ObfDexGuard, got %s", result.Type)
	}
}

func TestAnalyze_R8Detection(t *testing.T) {
	classes := []dex.ClassDef{
		{ClassName: "Lcom/example/MainActivity$$ExternalSyntheticLambda0;"},
		{ClassName: "Lcom/example/Helper$$ExternalSyntheticLambda1;"},
		{ClassName: "Lcom/example/data/UserRepository;"},
		{ClassName: "Lcom/example/data/UserDAO;"},
		{ClassName: "Lcom/example/ui/HomeFragment;"},
	}

	result := Analyze(&dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: classes,
		}},
		TotalClasses: len(classes),
	})

	if result.Type != ObfR8 {
		t.Errorf("expected ObfR8, got %s", result.Type)
	}
}

func TestDetectPacker_AllSignatures(t *testing.T) {
	t.Helper()

	tests := []struct {
		name     string
		file     string
		wantName string
		wantConf float64
	}{
		{"Bangcle", "lib/armeabi-v7a/libsecexe.so", "Bangcle", 90},
		{"Tencent Legu", "lib/arm64-v8a/libtosprotection.so", "Tencent Legu", 90},
		{"DEXProtector", "lib/x86/libDexHelper.so", "DEXProtector", 90},
		{"Bangcle Shell prefix", "lib/armeabi-v7a/libshella_v3.so", "Bangcle Shell", 85},
		{"Qihoo 360 asset", "assets/libjiagu.so", "Qihoo 360", 80},
		{"Generic DEX packer", "assets/classes.dex.dat", "Generic DEX packer", 80},
		{"Ijiami prefix", "assets/ijiami_data.bin", "Ijiami", 75},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			apkPath := filepath.Join(dir, "test.apk")

			f, err := os.Create(apkPath)
			if err != nil {
				t.Fatal(err)
			}

			w := zip.NewWriter(f)
			if _, err := w.Create(tt.file); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			info := DetectPacker(apkPath)
			if info == nil {
				t.Fatal("expected packer to be detected")
			}
			if info.Name != tt.wantName {
				t.Errorf("name = %q, want %q", info.Name, tt.wantName)
			}
			if info.Confidence != tt.wantConf {
				t.Errorf("confidence = %.1f, want %.1f", info.Confidence, tt.wantConf)
			}
		})
	}
}

func TestDetectMapping_AllPaths(t *testing.T) {
	paths := []string{
		"proguard/mapping.txt",
		"mapping.txt",
		"META-INF/proguard/mapping.txt",
	}

	for _, mp := range paths {
		t.Run(mp, func(t *testing.T) {
			dir := t.TempDir()
			apkPath := filepath.Join(dir, "test.apk")

			f, err := os.Create(apkPath)
			if err != nil {
				t.Fatal(err)
			}

			w := zip.NewWriter(f)
			if _, err := w.Create(mp); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			if !DetectMapping(apkPath) {
				t.Errorf("expected mapping detected for path %q", mp)
			}
		})
	}
}

func TestDetectMapping_InvalidPath(t *testing.T) {
	if DetectMapping("/nonexistent/path.apk") {
		t.Error("expected false for nonexistent path")
	}
}

func TestDetectPacker_InvalidPath(t *testing.T) {
	if DetectPacker("/nonexistent/path.apk") != nil {
		t.Error("expected nil for nonexistent path")
	}
}

func TestMatchesDexGuardPattern(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"OooO", true},
		{"OoOoOo", true},
		{"OOOO", true},
		{"oooo", true},
		{"Ooo", false},  // too short
		{"OoXo", false}, // non-O/o character
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesDexGuardPattern(tt.name)
			if got != tt.want {
				t.Errorf("matchesDexGuardPattern(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestConfidenceLabel(t *testing.T) {
	tests := []struct {
		confidence float64
		want       string
	}{
		{0, "none"},
		{20, "none"},
		{21, "low"},
		{40, "low"},
		{41, "medium"},
		{60, "medium"},
		{61, "high"},
		{80, "high"},
		{81, "very high"},
		{100, "very high"},
	}

	for _, tt := range tests {
		got := confidenceLabel(tt.confidence)
		if got != tt.want {
			t.Errorf("confidenceLabel(%.0f) = %q, want %q", tt.confidence, got, tt.want)
		}
	}
}
