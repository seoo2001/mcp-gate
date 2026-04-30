// Package paths centralises filesystem layout for mcp-gate state.
//
// All persistent files live under one root, configurable via $MCP_GATE_HOME
// (defaults to ~/.mcp-gate). Tests inject a temp dir via MCP_GATE_HOME so
// they never touch the user's real vault.
package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	envHome      = "MCP_GATE_HOME"
	defaultDir   = ".mcp-gate"
	vaultFile    = "vault.json"
	auditFile    = "audit.jsonl"
	caCertFile   = "ca.pem"
	caKeyFile    = "ca.key"
	servicesFile = "services.json"
	keystoreFile = "master.key" // file-based keystore fallback (never used when OS keychain is available)
)

// Layout describes resolved paths for one mcp-gate installation.
type Layout struct {
	Home     string
	Vault    string
	Audit    string
	CACert   string
	CAKey    string
	Services string
	Keystore string
}

// Resolve returns the active layout, creating the home directory (mode 0700)
// if missing. It honours $MCP_GATE_HOME, falling back to $HOME/.mcp-gate.
func Resolve() (Layout, error) {
	home := os.Getenv(envHome)
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return Layout{}, fmt.Errorf("resolve home: %w", err)
		}
		home = filepath.Join(userHome, defaultDir)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return Layout{}, fmt.Errorf("ensure home %q: %w", home, err)
	}
	// Belt + suspenders: if dir already existed with looser perms, tighten.
	if err := os.Chmod(home, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return Layout{}, fmt.Errorf("chmod home %q: %w", home, err)
	}
	return Layout{
		Home:     home,
		Vault:    filepath.Join(home, vaultFile),
		Audit:    filepath.Join(home, auditFile),
		CACert:   filepath.Join(home, caCertFile),
		CAKey:    filepath.Join(home, caKeyFile),
		Services: filepath.Join(home, servicesFile),
		Keystore: filepath.Join(home, keystoreFile),
	}, nil
}
