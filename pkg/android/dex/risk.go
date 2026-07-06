/*
Copyright (c) 2026 Security Research
*/
package dex

import (
	"slices"
	"strings"
)

type riskPattern struct {
	category    string
	severity    string
	description string
	classNames  []string
	methodNames []string
}

var riskPatterns = []riskPattern{
	{
		category:    "reflection",
		severity:    "high",
		description: "Uses Java reflection to invoke methods dynamically",
		classNames:  []string{"java/lang/reflect/Method", "java/lang/Class"},
		methodNames: []string{"forName", "invoke", "getDeclaredMethod", "getMethod"},
	},
	{
		category:    "dynamic_loading",
		severity:    "high",
		description: "Dynamically loads code at runtime",
		classNames:  []string{"dalvik/system/DexClassLoader", "dalvik/system/PathClassLoader", "dalvik/system/DexFile"},
	},
	{
		category:    "crypto",
		severity:    "medium",
		description: "Uses cryptographic APIs",
		classNames:  []string{"javax/crypto/Cipher", "javax/crypto/spec/SecretKeySpec"},
	},
	{
		category:    "sms",
		severity:    "high",
		description: "Accesses SMS functionality",
		classNames:  []string{"android/telephony/SmsManager"},
	},
	{
		category:    "native_exec",
		severity:    "high",
		description: "Executes native commands on the device",
		classNames:  []string{"java/lang/Runtime", "java/lang/ProcessBuilder"},
		methodNames: []string{"exec"},
	},
	{
		category:    "device_admin",
		severity:    "high",
		description: "Uses device administrator APIs",
		classNames:  []string{"android/app/admin/DevicePolicyManager"},
	},
}

var rootCheckStrings = []string{
	"su",
	"/system/xbin/su",
	"Superuser.apk",
	"com.noshufou.android.su",
}

// AnalyzeRisk checks a parsed DexFile for dangerous API usage patterns.
func AnalyzeRisk(dex *DexFile) []RiskFinding {
	var findings []RiskFinding

	for _, method := range dex.Methods {
		for _, pattern := range riskPatterns {
			if matchesPattern(method, pattern) {
				findings = append(findings, RiskFinding{
					Category:    pattern.category,
					API:         method.ClassName + "->" + method.Name,
					ClassName:   method.ClassName,
					MethodName:  method.Name,
					Severity:    pattern.severity,
					Description: pattern.description,
				})
			}
		}
	}

	findings = append(findings, checkRootDetection(dex)...)

	return findings
}

func matchesPattern(method MethodRef, pattern riskPattern) bool {
	classMatch := false
	for _, cn := range pattern.classNames {
		if strings.Contains(method.ClassName, cn) {
			classMatch = true
			break
		}
	}
	if !classMatch {
		return false
	}

	// If no specific method names are required, class match is sufficient.
	if len(pattern.methodNames) == 0 {
		return true
	}

	return slices.Contains(pattern.methodNames, method.Name)
}

func checkRootDetection(dex *DexFile) []RiskFinding {
	var findings []RiskFinding

	for _, s := range dex.Strings {
		for _, rootStr := range rootCheckStrings {
			if s == rootStr {
				findings = append(findings, RiskFinding{
					Category:    "root_detection",
					API:         s,
					Severity:    "medium",
					Description: "Contains root detection indicator string",
				})
			}
		}
	}

	return findings
}
