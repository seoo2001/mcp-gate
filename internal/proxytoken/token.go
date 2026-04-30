// Package proxytoken mints and validates short-lived proxy tokens.
//
// Token format (RFC-3986-safe; usable in headers, env vars, JSON):
//
//	mcpgate_<service>.<rand24>.<exp_unix>.<sig>
//
//	rand24  : 24 random bytes, base64url no-pad (32 chars)
//	exp_unix: ASCII decimal of the Unix expiry second
//	sig     : HMAC-SHA256(signingKey, "<service>|<rand24>|<exp_unix>")
//	          base64url no-pad (43 chars)
//
// We use "." as the internal separator because base64url's alphabet contains
// "-" and "_" — splitting on "_" would shred the rand and sig fields.
//
// The signing key is generated freshly per `mcp-gate wrap` invocation and
// kept only in process memory. Even if the on-disk vault leaks, captured
// tokens cannot be forged after the wrap session exits.
package proxytoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/seoo2001/mcp-gate/internal/cryptox"
)

// Prefix uniquely identifies our tokens. Anything not starting with this is
// treated as a real upstream credential and passed through untouched.
const Prefix = "mcpgate_"

// SigningKeyLen is the byte length of the HMAC signing key.
const SigningKeyLen = 32

// MaxTTL caps token lifetime. The architecture ships a 5-minute default; we
// allow up to 60 minutes so users with long-running interactive sessions can
// trade some blast-radius for fewer rotation events. Beyond that, rotation
// is the right answer.
const MaxTTL = 60 * time.Minute

// ErrInvalid covers all token validation failures — malformed, bad sig,
// expired, wrong service. We fold them into one error type so the proxy
// returns the same 401 message for every failure (no oracle for attackers).
var ErrInvalid = errors.New("proxytoken: invalid")

// b64 is the URL-safe, no-padding alphabet (RFC 4648 §5).
var b64 = base64.RawURLEncoding

// Signer mints and validates tokens. Construct with NewSigner; one signer per
// `mcp-gate wrap` invocation.
type Signer struct {
	key []byte
}

// NewSigner generates a fresh, in-memory signing key.
func NewSigner() (*Signer, error) {
	k, err := cryptox.RandomBytes(SigningKeyLen)
	if err != nil {
		return nil, fmt.Errorf("proxytoken: gen signing key: %w", err)
	}
	return &Signer{key: k}, nil
}

// Token is the parsed view of a proxy token.
type Token struct {
	Service string
	Random  string
	Expires time.Time
	Raw     string
}

// Mint creates a token for service, valid for ttl from now.
func (s *Signer) Mint(service string, ttl time.Duration) (Token, error) {
	if s == nil || len(s.key) != SigningKeyLen {
		return Token{}, errors.New("proxytoken: signer not initialised")
	}
	if err := validateService(service); err != nil {
		return Token{}, err
	}
	if ttl <= 0 {
		return Token{}, errors.New("proxytoken: ttl must be > 0")
	}
	if ttl > MaxTTL {
		return Token{}, fmt.Errorf("proxytoken: ttl %s exceeds max %s", ttl, MaxTTL)
	}
	rand, err := cryptox.RandomBytes(24)
	if err != nil {
		return Token{}, err
	}
	exp := time.Now().Add(ttl).Unix()
	rs := b64.EncodeToString(rand)
	expStr := strconv.FormatInt(exp, 10)
	sig := s.sign(service, rs, expStr)
	raw := Prefix + service + "." + rs + "." + expStr + "." + b64.EncodeToString(sig)
	return Token{
		Service: service,
		Random:  rs,
		Expires: time.Unix(exp, 0),
		Raw:     raw,
	}, nil
}

// Parse validates a token and returns its decoded form. now is injected for
// deterministic tests; pass time.Now() in production.
func (s *Signer) Parse(raw string, now time.Time) (Token, error) {
	if s == nil || len(s.key) != SigningKeyLen {
		return Token{}, errors.New("proxytoken: signer not initialised")
	}
	if !strings.HasPrefix(raw, Prefix) {
		return Token{}, ErrInvalid
	}
	body := raw[len(Prefix):]
	parts := strings.Split(body, ".")
	if len(parts) != 4 {
		return Token{}, ErrInvalid
	}
	service, rand, expStr, sigEnc := parts[0], parts[1], parts[2], parts[3]
	if validateService(service) != nil || rand == "" || expStr == "" || sigEnc == "" {
		return Token{}, ErrInvalid
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return Token{}, ErrInvalid
	}
	wantSig := s.sign(service, rand, expStr)
	gotSig, err := b64.DecodeString(sigEnc)
	if err != nil {
		return Token{}, ErrInvalid
	}
	if !hmac.Equal(wantSig, gotSig) {
		return Token{}, ErrInvalid
	}
	expires := time.Unix(exp, 0)
	if !now.Before(expires) {
		return Token{}, ErrInvalid
	}
	return Token{Service: service, Random: rand, Expires: expires, Raw: raw}, nil
}

// Find scans s for a single proxy token and returns the matched substring.
// It is service-agnostic — callers can use this to swap tokens out of any
// header value (Authorization, X-API-Key, ...).
//
// Returns ("", -1, -1) if no token is found.
func Find(s string) (token string, start, end int) {
	idx := strings.Index(s, Prefix)
	if idx < 0 {
		return "", -1, -1
	}
	// Find the end: tokens contain only [a-zA-Z0-9_.-]; stop at first char outside.
	i := idx + len(Prefix)
	for i < len(s) && isTokenByte(s[i]) {
		i++
	}
	return s[idx:i], idx, i
}

func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z',
		b >= 'A' && b <= 'Z',
		b >= '0' && b <= '9',
		b == '_', b == '-', b == '.':
		return true
	}
	return false
}

func (s *Signer) sign(service, rand, expStr string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(service))
	h.Write([]byte("|"))
	h.Write([]byte(rand))
	h.Write([]byte("|"))
	h.Write([]byte(expStr))
	return h.Sum(nil)
}

func validateService(s string) error {
	if s == "" {
		return ErrInvalid
	}
	for i := range s {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return ErrInvalid
		}
	}
	return nil
}
