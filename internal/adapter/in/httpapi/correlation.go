package httpapi

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	headerCorrelationID = "X-Correlation-Id"
	maxCorrelationIDLen = 128
)

// correlationID reuses the X-Correlation-Id received when it is safe to echo (printable ASCII,
// at most 128 characters) and generates one otherwise (Norma 5.3.9).
func correlationID(r *http.Request) string {
	received := r.Header.Get(headerCorrelationID)
	if received != "" && len(received) <= maxCorrelationIDLen && isPrintableASCII(received) {
		return received
	}
	return newCorrelationID()
}

func isPrintableASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// fallbackSequence numbers the ids generated without randomness, so they stay unique per process.
var fallbackSequence atomic.Uint64

// newCorrelationID returns a random (version 4) UUID.
func newCorrelationID() string {
	return correlationIDFrom(rand.Reader, time.Now)
}

// correlationIDFrom builds the id from random. When random fails it must not break the request:
// the client still has to get its error envelope, so the id falls back to a non-random one made
// of the clock and a per-process counter. It is unique within the process and only meant for
// tracing, never for security.
func correlationIDFrom(random io.Reader, now func() time.Time) string {
	var id [16]byte
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return fmt.Sprintf("fallback-%d-%d", now().UnixNano(), fallbackSequence.Add(1))
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}
