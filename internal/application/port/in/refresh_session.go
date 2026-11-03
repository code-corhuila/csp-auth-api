package in

import "context"

// RefreshSessionCommand carries the opaque refresh token the client presents and the client's
// user agent, which identifies the new session.
type RefreshSessionCommand struct {
	RefreshToken string
	UserAgent    string
}

// RefreshSession is the use case of HU-AUTH-002 that renews a session: the presented refresh
// token is spent and the client receives a new pair, shaped like the result of a login.
type RefreshSession interface {
	Refresh(ctx context.Context, command RefreshSessionCommand) (LoginUserResult, error)
}
