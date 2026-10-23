package redis

import (
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// ClientSettings are the explicit limits of the Redis client (Norma 5.3.10): Timeout bounds the
// connection, every read and every write.
type ClientSettings struct {
	URL     string
	Timeout time.Duration
}

// NewClient builds a client for the Redis URL, redis://auth_app:<password>@redis:6379/0. It does not
// connect: the first command does, so an unreachable Redis is an error of that command, not of the start.
func NewClient(settings ClientSettings) (*goredis.Client, error) {
	options, err := goredis.ParseURL(settings.URL)
	if err != nil {
		// The error of the parser can echo the URL, which carries the password: it is not wrapped.
		return nil, errors.New("APP_AUTH_REDIS_URL is not a valid Redis URL")
	}
	options.DialTimeout = settings.Timeout
	options.ReadTimeout = settings.Timeout
	options.WriteTimeout = settings.Timeout
	options.MaxRetries = 0
	// A call made with a context that has a deadline stops at that deadline: the login limiter bounds its own waits (ADR-048).
	options.ContextTimeoutEnabled = true
	options.DisableIndentity = true
	return goredis.NewClient(options), nil
}
