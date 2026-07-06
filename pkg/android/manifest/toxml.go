/*
Copyright (c) 2026 Security Research
*/
package manifest

import (
	"fmt"
	"strings"
)

// ToXML converts a parsed Manifest back to human-readable XML format.
func ToXML(m *Manifest) string {
	if m == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString("\n")

	// Root element
	b.WriteString(`<manifest xmlns:android="http://schemas.android.com/apk/res/android"`)
	_, _ = fmt.Fprintf(&b, "\n    package=%q", m.Package)

	if m.VersionCode > 0 {
		_, _ = fmt.Fprintf(&b, "\n    android:versionCode=%q", fmt.Sprintf("%d", m.VersionCode))
	}

	if m.VersionName != "" {
		_, _ = fmt.Fprintf(&b, "\n    android:versionName=%q", m.VersionName)
	}

	b.WriteString(">\n\n")

	// SDK versions
	if m.MinSDK > 0 || m.TargetSDK > 0 {
		b.WriteString("    <uses-sdk\n")

		if m.MinSDK > 0 {
			_, _ = fmt.Fprintf(&b, "        android:minSdkVersion=%q\n", fmt.Sprintf("%d", m.MinSDK))
		}

		if m.TargetSDK > 0 {
			_, _ = fmt.Fprintf(&b, "        android:targetSdkVersion=%q\n", fmt.Sprintf("%d", m.TargetSDK))
		}

		b.WriteString("        />\n\n")
	}

	// Permissions
	for _, p := range m.Permissions {
		_, _ = fmt.Fprintf(&b, "    <uses-permission android:name=%q /> <!-- %s -->\n", p.Name, p.RiskLevel)
	}

	if len(m.Permissions) > 0 {
		b.WriteString("\n")
	}

	// Features
	for _, f := range m.Features {
		_, _ = fmt.Fprintf(&b, "    <uses-feature android:name=%q />\n", f)
	}

	if len(m.Features) > 0 {
		b.WriteString("\n")
	}

	// Security flags
	b.WriteString("    <application\n")
	_, _ = fmt.Fprintf(&b, "        android:debuggable=%q\n", boolStr(m.Security.Debuggable))
	_, _ = fmt.Fprintf(&b, "        android:allowBackup=%q\n", boolStr(m.Security.AllowBackup))
	_, _ = fmt.Fprintf(&b, "        android:usesCleartextTraffic=%q\n", boolStr(m.Security.UsesCleartextTraffic))

	if m.Security.NetworkSecurityConfig {
		b.WriteString("        android:networkSecurityConfig=\"@xml/network_security_config\"\n")
	}

	b.WriteString("        >\n\n")

	// Components
	for _, c := range m.Components {
		tag := string(c.Type)
		_, _ = fmt.Fprintf(&b, "        <%s\n", tag)
		_, _ = fmt.Fprintf(&b, "            android:name=%q\n", c.Name)

		if c.Exported != nil {
			_, _ = fmt.Fprintf(&b, "            android:exported=%q\n", boolStr(*c.Exported))
		}

		if c.Permission != "" {
			_, _ = fmt.Fprintf(&b, "            android:permission=%q\n", c.Permission)
		}

		if len(c.IntentFilters) == 0 {
			b.WriteString("            />\n")
		} else {
			b.WriteString("            >\n")

			for _, f := range c.IntentFilters {
				b.WriteString("            <intent-filter>\n")

				for _, a := range f.Actions {
					_, _ = fmt.Fprintf(&b, "                <action android:name=%q />\n", a)
				}

				for _, cat := range f.Categories {
					_, _ = fmt.Fprintf(&b, "                <category android:name=%q />\n", cat)
				}

				for _, d := range f.Data {
					b.WriteString("                <data")

					if d.Scheme != "" {
						_, _ = fmt.Fprintf(&b, " android:scheme=%q", d.Scheme)
					}

					if d.Host != "" {
						_, _ = fmt.Fprintf(&b, " android:host=%q", d.Host)
					}

					if d.Path != "" {
						_, _ = fmt.Fprintf(&b, " android:path=%q", d.Path)
					}

					if d.MimeType != "" {
						_, _ = fmt.Fprintf(&b, " android:mimeType=%q", d.MimeType)
					}

					b.WriteString(" />\n")
				}

				b.WriteString("            </intent-filter>\n")
			}

			_, _ = fmt.Fprintf(&b, "        </%s>\n", tag)
		}

		b.WriteString("\n")
	}

	b.WriteString("    </application>\n\n")
	b.WriteString("</manifest>\n")

	return b.String()
}

func boolStr(v bool) string {
	if v {
		return "true"
	}

	return "false"
}
