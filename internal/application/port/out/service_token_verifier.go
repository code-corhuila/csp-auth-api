package out

// ServiceTokenVerifier checks the credential that another service presents (ADR-020).
type ServiceTokenVerifier interface {
	// VerifyServiceToken returns the subject of a valid RS256 token signed by this service. Any
	// token that is not valid gives model.ErrServiceTokenInvalid.
	VerifyServiceToken(token string) (subject string, err error)
}
