package keystore

import (
	"context"
	"errors"
	"os"
	"runtime"
)

// envOverride forces a specific backend. Used by tests and by users on
// hardened laptops where Keychain access prompts are intolerable.
const envOverride = "MCP_GATE_KEYSTORE"

// Auto picks the best available backend for the current host:
//
//   - $MCP_GATE_KEYSTORE=file        → FileKeystore at filePath
//   - $MCP_GATE_KEYSTORE=keychain    → KeychainKeystore (darwin only)
//   - default on darwin              → KeychainKeystore, falling back to file
//   - default elsewhere              → FileKeystore
//
// filePath is required even when Keychain is selected — it is used as the
// fallback if Keychain access fails.
func Auto(ctx context.Context, filePath string) (Keystore, error) {
	want := os.Getenv(envOverride)
	switch want {
	case "file":
		return &FileKeystore{Path: filePath}, nil
	case "keychain":
		if runtime.GOOS != "darwin" {
			return nil, errors.New("keystore: keychain backend requested but only available on darwin")
		}
		return &KeychainKeystore{}, nil
	case "":
		// auto
	default:
		return nil, errors.New("keystore: unknown MCP_GATE_KEYSTORE value: " + want)
	}

	if runtime.GOOS == "darwin" {
		k := &KeychainKeystore{}
		// Probe: try a Load; if it fails (no security cli, sandboxed env),
		// drop to file backend with a fresh key.
		if _, err := k.Load(ctx); err == nil {
			return k, nil
		}
	}
	return &FileKeystore{Path: filePath}, nil
}
