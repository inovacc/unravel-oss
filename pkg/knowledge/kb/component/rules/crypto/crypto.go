/*
Copyright (c) 2026 Security Research

Package crypto registers positive rules that classify modules into the crypto
taxonomy bucket.
*/
package crypto

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathCrypto = regexp.MustCompile(`(?i)(^|/)(crypto|cipher|hash|kdf|tls|x509)/`)
	nameCrypto = regexp.MustCompile(`(?i)(Cipher|Encrypt|Decrypt|Hash|Hmac|Kdf|Aes|Rsa|Curve)`)
)

func init() {
	component.Register(component.Rule{
		Name: "crypto/path-name-symbol", Component: "crypto", Confidence: 0.95, Priority: 9,
		PathRegex: pathCrypto, NameRegex: nameCrypto,
		SymbolKeywords: []string{"AesGcm", "AES", "RSA", "Curve25519", "sha256", "sha1", "hmac", "pbkdf2", "x25519", "ChaCha20"},
	})
	component.Register(component.Rule{
		Name: "crypto/name-symbol", Component: "crypto", Confidence: 0.80, Priority: 9,
		NameRegex:      nameCrypto,
		SymbolKeywords: []string{"AES", "RSA", "sha256", "hmac", "pbkdf2"},
	})
	component.Register(component.Rule{
		Name: "crypto/symbol-strict", Component: "crypto", Confidence: 0.65, Priority: 9,
		SymbolKeywords: []string{"AesGcm", "Curve25519", "ChaCha20"},
	})
}
