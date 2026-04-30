// Package keystore stores the vault master key in the most secure place
// available on the host. The master key is a 32-byte random value used as a
// key-encryption-key (KEK); per-record data-encryption-keys (DEKs) live in
// the vault file, encrypted by this KEK.
//
// Backends, in priority order:
//
//	macos-keychain  (darwin)  — security(1) generic-password under service
//	                            "mcp-gate", account "master-key"
//	file            (any)     — $MCP_GATE_HOME/master.key, mode 0600
//
// Tests force the file backend by setting MCP_GATE_KEYSTORE=file.
package keystore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// MasterKeyLen is the byte length of the master key (AES-256).
const MasterKeyLen = 32

// ErrNotFound signals that no key exists yet for this Keystore.
var ErrNotFound = errors.New("keystore: master key not found")

// Keystore persists the vault master key.
type Keystore interface {
	// Load returns the master key, generating + persisting one if absent.
	Load(ctx context.Context) ([]byte, error)
	// Reset removes the stored master key (vault must be re-keyed).
	Reset(ctx context.Context) error
	// Backend names the implementation, e.g. "macos-keychain" or "file".
	Backend() string
}

// generate returns MasterKeyLen cryptographically random bytes.
func generate() ([]byte, error) {
	buf := make([]byte, MasterKeyLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("keystore: gen master key: %w", err)
	}
	return buf, nil
}

// encode/decode wrap base64 so backends that store strings (Keychain,
// secret-tool) round-trip raw bytes safely.
func encode(b []byte) string         { return base64.StdEncoding.EncodeToString(b) }
func decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
