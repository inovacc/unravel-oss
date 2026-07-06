/*
Copyright (c) 2026 Security Research
*/
package secret

import (
	"encoding/json"
	"strings"
)

// firebaseConfig represents a google-services.json structure.
type firebaseConfig struct {
	ProjectInfo struct {
		ProjectNumber string `json:"project_number"`
		FirebaseURL   string `json:"firebase_url"`
		ProjectID     string `json:"project_id"`
		StorageBucket string `json:"storage_bucket"`
	} `json:"project_info"`
	Client []struct {
		ClientInfo struct {
			MobileSdkAppID string `json:"mobilesdk_app_id"`
		} `json:"client_info"`
		APIKey []struct {
			CurrentKey string `json:"current_key"`
		} `json:"api_key"`
		OauthClient []struct {
			ClientID string `json:"client_id"`
		} `json:"oauth_client"`
	} `json:"client"`
}

// scanFirebaseConfig checks if content is a google-services.json and extracts secrets.
func scanFirebaseConfig(content, file string) []Finding {
	if !strings.Contains(content, "project_info") || !strings.Contains(content, "mobilesdk_app_id") {
		return nil
	}

	var cfg firebaseConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil
	}

	var findings []Finding

	if cfg.ProjectInfo.ProjectID != "" {
		findings = append(findings, Finding{
			Type:       TypeFirebaseConfig,
			Value:      "project_id=" + cfg.ProjectInfo.ProjectID,
			RawLength:  len(cfg.ProjectInfo.ProjectID),
			File:       file,
			Confidence: "high",
		})
	}

	if cfg.ProjectInfo.FirebaseURL != "" {
		findings = append(findings, Finding{
			Type:       TypeFirebaseConfig,
			Value:      "firebase_url=" + maskValue(cfg.ProjectInfo.FirebaseURL),
			RawLength:  len(cfg.ProjectInfo.FirebaseURL),
			File:       file,
			Confidence: "high",
		})
	}

	for _, client := range cfg.Client {
		for _, key := range client.APIKey {
			if key.CurrentKey != "" {
				findings = append(findings, Finding{
					Type:       TypeFirebaseAPIKey,
					Value:      maskValue(key.CurrentKey),
					RawLength:  len(key.CurrentKey),
					File:       file,
					Confidence: "high",
				})
			}
		}

		for _, oauth := range client.OauthClient {
			if oauth.ClientID != "" {
				findings = append(findings, Finding{
					Type:       TypeFirebaseConfig,
					Value:      "oauth_client_id=" + maskValue(oauth.ClientID),
					RawLength:  len(oauth.ClientID),
					File:       file,
					Confidence: "high",
				})
			}
		}
	}

	return findings
}
