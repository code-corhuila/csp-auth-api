package httpapi

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
)

// jsonWebKey is the JsonWebKey schema of the auth-service contract (RFC 7517).
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

func jwks(source in.PublicKeys) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		keys := source.PublicKeys()
		set := jsonWebKeySet{Keys: make([]jsonWebKey, 0, len(keys))}
		for _, key := range keys {
			set.Keys = append(set.Keys, jsonWebKey{
				Kty: "RSA",
				Kid: key.KeyID,
				Alg: "RS256",
				Use: "sig",
				N:   encodeBase64URL(key.Key.N),
				E:   encodeBase64URL(big.NewInt(int64(key.Key.E))),
			})
		}
		writeJSON(w, http.StatusOK, set)
	}
}

func encodeBase64URL(value *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}
