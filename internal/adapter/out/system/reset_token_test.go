package system

import "testing"

func TestNewTokenDrawsDifferentValidTokens(t *testing.T) {
	seen := map[string]bool{}

	for range 100 {
		token, err := ResetTokenGenerator{}.NewToken()
		if err != nil {
			t.Fatalf("NewToken() error = %v", err)
		}
		seen[token.Reveal()] = true
	}

	if len(seen) != 100 {
		t.Errorf("%d different tokens in 100 draws, want all of them different", len(seen))
	}
}
