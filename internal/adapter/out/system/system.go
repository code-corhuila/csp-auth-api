// Package system is the outbound adapter for the host: the wall clock and random identifiers.
package system

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Clock reads the system time in UTC.
type Clock struct{}

// Now returns the current instant.
func (Clock) Now() time.Time {
	return time.Now().UTC()
}

// UUIDGenerator creates random (version 4) UUIDs.
type UUIDGenerator struct{}

// NewID returns a new UUID in its canonical text form. It panics only if the system has no
// source of randomness, a condition the process cannot recover from.
func (UUIDGenerator) NewID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(fmt.Errorf("read random bytes: %w", err))
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}
