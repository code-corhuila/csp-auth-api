// Package token is the outbound adapter that signs access tokens with RS256 (golang-jwt/jwt/v5).
package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// MinKeyBits is the smallest RSA modulus accepted for signing.
const MinKeyBits = 2048

// LoadPrivateKey reads the signing key from exactly one source: PEM contents (literal backslash-n
// sequences are accepted, for environments that cannot hold newlines) or the path of a PEM file.
func LoadPrivateKey(pemText, file string) (*rsa.PrivateKey, error) {
	switch {
	case pemText != "" && file != "":
		return nil, errors.New("set only one of the private key contents and the private key file")
	case pemText == "" && file == "":
		return nil, errors.New("the private key is not configured: set its contents or its file")
	case file != "":
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read private key file: %w", err)
		}
		pemText = string(content)
	}
	return ParsePrivateKey(strings.ReplaceAll(pemText, "\\n", "\n"))
}

// ParsePrivateKey decodes a PKCS#1 or PKCS#8 PEM RSA key of at least MinKeyBits.
func ParsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("the private key is not valid PEM")
	}
	key, err := parseRSA(block)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < MinKeyBits {
		return nil, fmt.Errorf("the RSA key has %d bits, the minimum is %d", key.N.BitLen(), MinKeyBits)
	}
	return key, nil
}

func parseRSA(block *pem.Block) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key is neither PKCS#1 nor PKCS#8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key is not an RSA key")
	}
	return key, nil
}

// thumbprint is the RFC 7638 JWK thumbprint of an RSA key: base64url(SHA-256 of the canonical JSON).
func thumbprint(key *rsa.PublicKey) string {
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, exponent(key), modulus(key))
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// modulus is the base64url (unpadded) modulus of key, as a JWK "n".
func modulus(key *rsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(key.N.Bytes())
}

// exponent is the base64url (unpadded) exponent of key, as a JWK "e".
func exponent(key *rsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
}
