package proxytoken

import (
	"strings"
	"testing"
	"time"
)

func TestMintParseRoundTrip(t *testing.T) {
	s, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Mint("github", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Raw, Prefix+"github.") {
		t.Fatalf("raw token has unexpected prefix: %s", tok.Raw)
	}
	parsed, err := s.Parse(tok.Raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Service != "github" {
		t.Fatalf("service = %s", parsed.Service)
	}
	if !parsed.Expires.Equal(tok.Expires) {
		t.Fatalf("expires drift: parsed=%v mint=%v", parsed.Expires, tok.Expires)
	}
}

func TestMintRejectsBadInputs(t *testing.T) {
	s, _ := NewSigner()
	if _, err := s.Mint("Bad Service", time.Minute); err == nil {
		t.Fatalf("expected service validation error")
	}
	if _, err := s.Mint("github", 0); err == nil {
		t.Fatalf("expected ttl error")
	}
	if _, err := s.Mint("github", 2*MaxTTL); err == nil {
		t.Fatalf("expected ttl over max error")
	}
}

func TestParseRejectsTampered(t *testing.T) {
	s, _ := NewSigner()
	tok, _ := s.Mint("slack", time.Minute)
	// Replace the entire signature segment with all-A's. The decoded form
	// is 32 zero bytes, which collides with a real HMAC-SHA256 only at
	// probability 1/2^256.
	//
	// Earlier attempts that flipped a single bit in the last char flaked
	// because base64.RawURLEncoding silently discards trailing bits when
	// the input length is not a multiple of 3 — flipping those discard
	// bits decoded to the *same* signature.
	parts := strings.Split(tok.Raw, ".")
	if len(parts) != 4 {
		t.Fatalf("unexpected token shape: %q", tok.Raw)
	}
	parts[3] = strings.Repeat("A", len(parts[3]))
	if _, err := s.Parse(strings.Join(parts, "."), time.Now()); err == nil {
		t.Fatalf("expected sig failure")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	s, _ := NewSigner()
	tok, _ := s.Mint("github", time.Second)
	future := time.Now().Add(time.Hour)
	if _, err := s.Parse(tok.Raw, future); err == nil {
		t.Fatalf("expected expiry failure")
	}
}

func TestParseRejectsWrongSigner(t *testing.T) {
	a, _ := NewSigner()
	b, _ := NewSigner()
	tok, _ := a.Mint("github", time.Minute)
	if _, err := b.Parse(tok.Raw, time.Now()); err == nil {
		t.Fatalf("expected sig failure across signers")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	s, _ := NewSigner()
	bad := []string{
		"",
		"not-a-token",
		Prefix,
		Prefix + "github",
		Prefix + "github.xx.yy",        // missing sig (3 parts)
		Prefix + "github.xx.NaN.zz",    // bad exp
		Prefix + "g.x.1.y.extra",       // too many parts
		Prefix + "BAD!.xx.1.yy",        // bad service charset
	}
	for _, b := range bad {
		if _, err := s.Parse(b, time.Now()); err == nil {
			t.Fatalf("expected error for %q", b)
		}
	}
}

func TestFindLocatesTokenInHeader(t *testing.T) {
	s, _ := NewSigner()
	tok, _ := s.Mint("github", time.Minute)
	header := "Bearer " + tok.Raw
	got, start, end := Find(header)
	if got != tok.Raw {
		t.Fatalf("found %q, want %q", got, tok.Raw)
	}
	if header[start:end] != tok.Raw {
		t.Fatalf("indices wrong")
	}
}

func TestFindReturnsEmptyWhenAbsent(t *testing.T) {
	got, start, end := Find("Bearer ghp_real_token")
	if got != "" || start != -1 || end != -1 {
		t.Fatalf("unexpected match: %q [%d:%d]", got, start, end)
	}
}
