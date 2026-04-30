//go:build darwin

package keystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// KeychainKeystore stores the master key in the macOS user Keychain via
// security(1) generic-password entries. This is the recommended backend on
// macOS: the key is sealed to the user account, never lands on disk in a form
// readable by other local accounts, and is rotated by Apple's keychain
// services rather than by us.
//
// Service/Account naming follows Apple's HIG for app credentials.
type KeychainKeystore struct {
	Service string // default: "mcp-gate"
	Account string // default: "master-key"
}

const (
	defaultService = "mcp-gate"
	defaultAccount = "master-key"

	// security(1) returns 44 (errSecItemNotFound) when no item exists.
	errSecItemNotFound = 44
)

func (k *KeychainKeystore) service() string {
	if k.Service == "" {
		return defaultService
	}
	return k.Service
}

func (k *KeychainKeystore) account() string {
	if k.Account == "" {
		return defaultAccount
	}
	return k.Account
}

// Load returns the stored master key, creating one on first call.
func (k *KeychainKeystore) Load(ctx context.Context) ([]byte, error) {
	switch raw, err := k.find(ctx); {
	case err == nil:
		key, decErr := decode(strings.TrimSpace(raw))
		if decErr != nil {
			return nil, fmt.Errorf("keychain keystore: decode: %w", decErr)
		}
		if len(key) != MasterKeyLen {
			return nil, fmt.Errorf("keychain keystore: master key length = %d, want %d", len(key), MasterKeyLen)
		}
		return key, nil
	case errors.Is(err, ErrNotFound):
		// fall through to generation
	default:
		return nil, err
	}

	key, err := generate()
	if err != nil {
		return nil, err
	}
	if err := k.add(ctx, encode(key)); err != nil {
		return nil, err
	}
	return key, nil
}

// Reset removes the stored entry.
func (k *KeychainKeystore) Reset(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "security", "delete-generic-password",
		"-s", k.service(), "-a", k.account())
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == errSecItemNotFound {
		return nil
	}
	return fmt.Errorf("keychain keystore: delete: %w (%s)", err, bytes.TrimSpace(out))
}

// Backend names the implementation.
func (k *KeychainKeystore) Backend() string { return "macos-keychain" }

// find returns the password value or ErrNotFound.
func (k *KeychainKeystore) find(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "security", "find-generic-password",
		"-s", k.service(), "-a", k.account(), "-w")
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == errSecItemNotFound {
		return "", ErrNotFound
	}
	return "", fmt.Errorf("keychain keystore: find: %w", err)
}

// add upserts the password (-U overwrites if present).
func (k *KeychainKeystore) add(ctx context.Context, value string) error {
	cmd := exec.CommandContext(ctx, "security", "add-generic-password",
		"-U",
		"-s", k.service(), "-a", k.account(),
		"-l", "mcp-gate vault master key",
		"-D", "mcp-gate master key",
		"-w", value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain keystore: add: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}
