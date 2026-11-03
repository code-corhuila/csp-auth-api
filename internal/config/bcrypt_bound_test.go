package config

import (
	"testing"
	"time"
)

func TestLoadReadsTheBoundOnConcurrentPasswordHashes(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.BcryptMaxConcurrent != 4 || cfg.BcryptQueueTimeout != 100*time.Millisecond {
		t.Fatalf("default: %d concurrent, %v wait, err = %v; want 4 and 100ms", cfg.BcryptMaxConcurrent, cfg.BcryptQueueTimeout, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{
		"APP_AUTH_BCRYPT_MAX_CONCURRENT": "64",
		"APP_AUTH_BCRYPT_QUEUE_TIMEOUT":  "150ms",
	}))
	if err != nil || cfg.BcryptMaxConcurrent != 64 || cfg.BcryptQueueTimeout != 150*time.Millisecond {
		t.Fatalf("%d concurrent, %v wait, err = %v; want the upper bounds 64 and 150ms", cfg.BcryptMaxConcurrent, cfg.BcryptQueueTimeout, err)
	}
}

func TestLoadRejectsAnInvalidBoundOnConcurrentPasswordHashes(t *testing.T) {
	invalid := map[string][]string{
		"APP_AUTH_BCRYPT_MAX_CONCURRENT": {"0", "-1", "four", "1.5", "65"},
		"APP_AUTH_BCRYPT_QUEUE_TIMEOUT":  {"0", "-1ms", "soon", "100", "151ms", "1s"},
	}
	for key, values := range invalid {
		for _, value := range values {
			if _, err := Load(lookupFrom(map[string]string{key: value})); err == nil {
				t.Errorf("%s=%s: Load() error = nil", key, value)
			}
		}
	}
}
