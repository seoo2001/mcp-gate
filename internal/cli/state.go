package cli

import (
	"context"
	"fmt"

	"github.com/seoo2001/mcp-gate/internal/keystore"
	"github.com/seoo2001/mcp-gate/internal/paths"
	"github.com/seoo2001/mcp-gate/internal/services"
	"github.com/seoo2001/mcp-gate/internal/vault"
)

// state is the bundle of long-lived dependencies a subcommand needs.
type state struct {
	layout   paths.Layout
	ks       keystore.Keystore
	registry *services.Registry
}

// loadState resolves paths, opens the keystore, and loads the service registry
// (built-ins + user overrides). It does NOT open the vault — that needs the
// keystore master key, which we only want to materialise when a subcommand
// actually needs to encrypt or decrypt something.
func loadState(ctx context.Context) (*state, error) {
	layout, err := paths.Resolve()
	if err != nil {
		return nil, err
	}
	ks, err := keystore.Auto(ctx, layout.Keystore)
	if err != nil {
		return nil, err
	}
	reg := services.NewRegistry()
	if err := reg.LoadOverrides(layout.Services); err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	return &state{layout: layout, ks: ks, registry: reg}, nil
}

func (s *state) openVault(ctx context.Context) (*vault.Vault, error) {
	return vault.Open(ctx, s.layout.Vault, s.ks)
}
