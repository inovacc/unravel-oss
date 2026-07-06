/*
Copyright (c) 2026 Security Research
*/
package secret

import "regexp"

// SecretType identifies the category of a detected secret.
type SecretType string

const (
	TypeGoogleAPIKey      SecretType = "Google API Key"
	TypeAWSAccessKey      SecretType = "AWS Access Key"
	TypeAWSSecretKey      SecretType = "AWS Secret Key"
	TypeAzureKey          SecretType = "Azure Key"
	TypeGCPServiceAccount SecretType = "GCP Service Account"
	TypeStripeLiveKey     SecretType = "Stripe Live Key"
	TypeStripePublishable SecretType = "Stripe Publishable Key"
	TypeSquareKey         SecretType = "Square Key"
	TypeBraintreeKey      SecretType = "Braintree Key"
	TypeGitHubToken       SecretType = "GitHub Token"
	TypeSlackToken        SecretType = "Slack Token"
	TypeSlackWebhook      SecretType = "Slack Webhook"
	TypeFacebookToken     SecretType = "Facebook Token"
	TypeTwitterKey        SecretType = "Twitter API Key"
	TypeFirebaseURL       SecretType = "Firebase URL"
	TypeFirebaseAPIKey    SecretType = "Firebase API Key"
	TypeFirebaseFCM       SecretType = "Firebase Cloud Messaging"
	TypePrivateKey        SecretType = "Private Key"
	TypeJWT               SecretType = "JWT Token"
	TypeGenericAPIKey     SecretType = "Generic API Key"
	TypeGenericSecret     SecretType = "Generic Secret"
	TypeGenericToken      SecretType = "Generic Token"
	TypeGenericPassword   SecretType = "Generic Password"
	TypeBasicAuth         SecretType = "Basic Auth"
	TypeSendgridKey       SecretType = "SendGrid Key"
	TypeTwilioKey         SecretType = "Twilio Key"
	TypeMailgunKey        SecretType = "Mailgun Key"
	TypeHerokuKey         SecretType = "Heroku API Key"
	TypeHighEntropy       SecretType = "High-Entropy String"
	TypeURL               SecretType = "URL"
	TypeIPAddress         SecretType = "IP Address"
	TypeEndpoint          SecretType = "API Endpoint"
	TypeFirebaseConfig    SecretType = "Firebase Config"
	TypeBuildConfig       SecretType = "BuildConfig Field"
	TypeEmbeddedKeystore  SecretType = "Embedded Keystore"
)

// secretPattern defines a regex pattern for detecting a specific type of secret.
type secretPattern struct {
	Type       SecretType
	Pattern    *regexp.Regexp
	Confidence string // "high" or "medium"
}

// patterns contains all compiled secret detection patterns.
var patterns = []secretPattern{
	// Cloud providers
	{TypeGoogleAPIKey, regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "high"},
	{TypeAWSAccessKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "high"},
	{TypeAWSSecretKey, regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?([0-9A-Za-z/+=]{40})["']?`), "high"},
	{TypeAzureKey, regexp.MustCompile(`(?i)(?:AccountKey|azure[_-]?(?:storage[_-]?)?key)\s*[=:]\s*["']?([A-Za-z0-9+/=]{40,})["']?`), "medium"},
	{TypeGCPServiceAccount, regexp.MustCompile(`"type"\s*:\s*"service_account"`), "high"},

	// Payment
	{TypeStripeLiveKey, regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), "high"},
	{TypeStripePublishable, regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), "high"},
	{TypeSquareKey, regexp.MustCompile(`sq0[a-z]{3}-[0-9A-Za-z_-]{22,}`), "high"},
	{TypeBraintreeKey, regexp.MustCompile(`(?i)braintree[_-]?(?:merchant|public|private)[_-]?(?:key|id)\s*[=:]\s*["']?([0-9a-zA-Z]{16,})["']?`), "medium"},

	// Social / Auth
	{TypeGitHubToken, regexp.MustCompile(`(?:ghp|ghs|gho|ghu|ghr)_[0-9A-Za-z]{36,}`), "high"},
	{TypeSlackToken, regexp.MustCompile(`xox[baprs]-[0-9]{10,}-[0-9a-zA-Z-]+`), "high"},
	{TypeSlackWebhook, regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+`), "high"},
	{TypeFacebookToken, regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`), "high"},
	{TypeTwitterKey, regexp.MustCompile(`(?i)twitter[_-]?(?:api[_-]?)?(?:key|secret|token)\s*[=:]\s*["']?([0-9a-zA-Z]{25,})["']?`), "medium"},

	// Firebase
	{TypeFirebaseURL, regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`), "high"},
	{TypeFirebaseAPIKey, regexp.MustCompile(`(?i)firebase[_-]?(?:api[_-]?)?key\s*[=:]\s*["']?([0-9a-zA-Z_-]{20,})["']?`), "medium"},
	{TypeFirebaseFCM, regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}`), "high"},

	// Crypto / Secrets
	{TypePrivateKey, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`), "high"},
	{TypeJWT, regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`), "high"},

	// Generic patterns
	{TypeGenericAPIKey, regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?([0-9a-zA-Z_-]{16,})["']?`), "medium"},
	{TypeGenericSecret, regexp.MustCompile(`(?i)(?:secret[_-]?key|client[_-]?secret)\s*[=:]\s*["']?([0-9a-zA-Z_/+=]{16,})["']?`), "medium"},
	{TypeGenericToken, regexp.MustCompile(`(?i)(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[=:]\s*["']?([0-9a-zA-Z_-]{16,})["']?`), "medium"},
	{TypeGenericPassword, regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']`), "medium"},
	{TypeBasicAuth, regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{20,}`), "medium"},

	// Services
	{TypeSendgridKey, regexp.MustCompile(`SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`), "high"},
	{TypeTwilioKey, regexp.MustCompile(`SK[0-9a-fA-F]{32}`), "high"},
	{TypeMailgunKey, regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), "high"},
	{TypeHerokuKey, regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key\s*[=:]\s*["']?([0-9a-f-]{36})["']?`), "medium"},

	// URLs, IPs, and API endpoints
	{TypeURL, regexp.MustCompile(`https?://[^\s"'<>\x00-\x1f]{8,200}`), "high"},
	{TypeIPAddress, regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b`), "medium"},
	{TypeEndpoint, regexp.MustCompile(`/api/v[0-9]+/[a-zA-Z0-9/_-]+`), "medium"},
}

// highConfPatterns is a subset used for noisy file types like .smali
// to avoid excessive false positives and keep scanning fast.
var highConfPatterns []secretPattern

func init() {
	for _, p := range patterns {
		if p.Confidence == "high" {
			highConfPatterns = append(highConfPatterns, p)
		}
	}
}
