/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempXAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.xaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestParseRawXAML_ResourceKeys(t *testing.T) {
	body := `<ResourceDictionary xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Style x:Key="MyButton" />
  <SolidColorBrush x:Key="AccentBrush" />
</ResourceDictionary>`
	e, err := ParseRawXAML(tempXAML(t, body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := strings.Join(e.ResourceKeys, ",")
	if got != "MyButton,AccentBrush" {
		t.Fatalf("want MyButton,AccentBrush; got %q", got)
	}
}

func TestParseRawXAML_ControlTypes(t *testing.T) {
	body := `<Page xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Grid>
    <Button />
    <TextBlock />
    <Button />
  </Grid>
</Page>`
	e, err := ParseRawXAML(tempXAML(t, body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"Page", "Grid", "Button", "TextBlock"}
	if strings.Join(e.ControlTypes, ",") != strings.Join(want, ",") {
		t.Fatalf("want %v, got %v", want, e.ControlTypes)
	}
}

func TestParseRawXAML_Bindings(t *testing.T) {
	body := `<Page xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <TextBlock Text="{Binding Name}" />
  <Button Content="{x:Bind ViewModel.Title}" />
</Page>`
	e, err := ParseRawXAML(tempXAML(t, body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(e.Bindings) != 2 {
		t.Fatalf("want 2 bindings, got %v", e.Bindings)
	}
	if e.Bindings[0] != "{Binding Name}" || e.Bindings[1] != "{x:Bind ViewModel.Title}" {
		t.Fatalf("bindings unexpected: %v", e.Bindings)
	}
}

func TestParseRawXAML_Malformed(t *testing.T) {
	body := `<Page><Grid` // truncated
	e, err := ParseRawXAML(tempXAML(t, body))
	if err != nil {
		t.Fatalf("parse should not return os err: %v", err)
	}
	if e.Kind != "raw" {
		t.Fatalf("kind want raw got %q", e.Kind)
	}
	if len(e.Errors) == 0 {
		t.Fatalf("want errors recorded")
	}
}

func TestParseRawXAML_NamespaceVariations(t *testing.T) {
	// x:Key is namespaced via the WinFX URI; we must extract it.
	body := `<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Style x:Key="K1" />
</ResourceDictionary>`
	e, err := ParseRawXAML(tempXAML(t, body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(e.ResourceKeys) != 1 || e.ResourceKeys[0] != "K1" {
		t.Fatalf("want [K1], got %v", e.ResourceKeys)
	}
}

func TestParseRawXAML_OpenError(t *testing.T) {
	_, err := ParseRawXAML(filepath.Join(t.TempDir(), "nope.xaml"))
	if err == nil {
		t.Fatalf("want open error")
	}
}
