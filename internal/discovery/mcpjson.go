package discovery

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/seoo2001/mcp-gate/internal/services"
)

// mcpConfig is the loose shape of mcpServers config files. We accept extra
// fields and unknown server entries — an MCP server with no env section is
// simply skipped (nothing to import).
type mcpConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

type mcpServerEntry struct {
	// Command/Args are present in real configs but we don't care about them
	// here; the importer's job is to look at Env. Kept for forward
	// compatibility with `mcp-gate setup` (which will rewrite them).
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// ScanMCPConfig parses an mcp.json-style file at path and yields one
// Discovery per env entry that maps to a registered service.
//
// Mapping precedence:
//
//	1. exact env-var match against Service.EnvVar  → primary
//	2. case-insensitive match against Service.EnvAliases → primary alias
//	3. token prefix match against any Service.TokenPrefixes → fallback
//
// Tokens that don't match any service are skipped silently (the user might
// have a legitimate non-mcp-gate-managed credential in there; flagging
// every unknown env var would generate noise and erode trust).
func ScanMCPConfig(path string, reg *services.Registry) ([]Discovery, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var cfg mcpConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	var out []Discovery
	for serverName, entry := range cfg.MCPServers {
		for envKey, envVal := range entry.Env {
			if envVal == "" {
				continue
			}
			d := classify(reg, envKey, envVal)
			if d.Service == "" {
				continue
			}
			d.Source = path
			d.ServerName = serverName
			out = append(out, d)
		}
	}
	return out, nil
}

// classify returns a Discovery with Service set if (env, value) maps to a
// registered service. Service stays empty when nothing is recognised.
func classify(reg *services.Registry, envKey, envVal string) Discovery {
	d := Discovery{EnvVar: envKey, Token: envVal}
	if svc, ok := reg.ResolveByEnvVar(envKey); ok {
		d.Service = svc.Name
		// Cross-validate: if the token has a known prefix from a *different*
		// service, leave the env-derived mapping but flag it.
		if other, ok := reg.ResolveByTokenPrefix(envVal); ok && other.Name != svc.Name {
			d.Note = fmt.Sprintf("warning: token looks like %s but env var is %s", other.Name, svc.Name)
		} else if !envVarIsCanonical(svc, envKey) {
			d.Note = fmt.Sprintf("aliased from %s → %s", envKey, svc.EnvVar)
		}
		return d
	}
	if svc, ok := reg.ResolveByTokenPrefix(envVal); ok {
		d.Service = svc.Name
		d.Note = fmt.Sprintf("inferred from token prefix; env var %s is non-standard", envKey)
		return d
	}
	return d
}

func envVarIsCanonical(svc services.Service, name string) bool {
	return svc.EnvVar == name
}
