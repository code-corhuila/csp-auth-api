package in

import "github.com/code-corhuila/csp-auth-api/internal/domain/model"

// PublicKeys lists the keys the other services use to verify access tokens (GET /jwks).
type PublicKeys interface {
	PublicKeys() []model.PublicKey
}
