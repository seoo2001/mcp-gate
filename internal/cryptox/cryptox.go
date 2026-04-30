// Package cryptox wraps the AEAD primitives mcp-gate uses everywhere it
// touches secret bytes. Centralising it keeps nonce-handling discipline in
// one place: callers can never accidentally reuse a nonce because Seal()
// always generates a fresh random one and pins it to the ciphertext.
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// AESKeyLen is the byte length expected for AES-256-GCM keys.
const AESKeyLen = 32

// Sealed bundles the ciphertext with the nonce used to produce it. Storing
// nonce alongside is standard practice for AES-GCM at rest — the nonce is
// not secret, only its uniqueness matters.
type Sealed struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ct"`
}

// SealAES256GCM encrypts plaintext under key (32 bytes) with associated data.
// A fresh 12-byte random nonce is generated; reuse is impossible by API.
func SealAES256GCM(key, plaintext, aad []byte) (Sealed, error) {
	if len(key) != AESKeyLen {
		return Sealed{}, fmt.Errorf("cryptox: key length = %d, want %d", len(key), AESKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Sealed{}, fmt.Errorf("cryptox: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Sealed{}, fmt.Errorf("cryptox: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("cryptox: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return Sealed{Nonce: nonce, Ciphertext: ct}, nil
}

// OpenAES256GCM is the inverse. AAD must match what was passed to Seal,
// otherwise authentication fails (and the function returns an error rather
// than the partial plaintext — GCM short-circuits on tag mismatch).
func OpenAES256GCM(key []byte, sealed Sealed, aad []byte) ([]byte, error) {
	if len(key) != AESKeyLen {
		return nil, fmt.Errorf("cryptox: key length = %d, want %d", len(key), AESKeyLen)
	}
	if sealed.Nonce == nil || sealed.Ciphertext == nil {
		return nil, errors.New("cryptox: sealed has nil nonce or ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptox: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptox: gcm: %w", err)
	}
	if len(sealed.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("cryptox: nonce length = %d, want %d", len(sealed.Nonce), gcm.NonceSize())
	}
	pt, err := gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		// Don't leak which step failed (tag vs structure) — same error.
		return nil, fmt.Errorf("cryptox: open: %w", err)
	}
	return pt, nil
}

// RandomBytes returns n cryptographically-random bytes or an error.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("cryptox: random length must be > 0")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("cryptox: random: %w", err)
	}
	return b, nil
}
