//go:build !darwin

package keystore

import (
	"context"
	"errors"
)

// KeychainKeystore is a non-darwin stub so packages that select backends at
// runtime can compile on every platform.
type KeychainKeystore struct {
	Service string
	Account string
}

// Load always returns ErrNotFound on non-darwin builds.
func (k *KeychainKeystore) Load(_ context.Context) ([]byte, error) {
	return nil, errors.New("keychain keystore: only available on darwin")
}

// Reset is a no-op.
func (k *KeychainKeystore) Reset(_ context.Context) error { return nil }

// Backend names the implementation.
func (k *KeychainKeystore) Backend() string { return "macos-keychain-stub" }
