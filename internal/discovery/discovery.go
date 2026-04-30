// Package discovery scans well-known locations for MCP / dev-tool config
// files and pulls plaintext credentials out so `mcp-gate import` can
// silently move them into the encrypted vault.
//
// The scope is *boring credential archaeology*. We do not parse XML, we
// do not call out to other CLIs, we do not run shell expansions. Each
// supported source has a small, opinionated parser:
//
//	mcp.json (Anthropic Claude Desktop / Code, Cursor, Windsurf):
//	  { "mcpServers": { "<name>": { "env": { "FOO": "bar" } } } }
//
//	.env (POSIX-y):
//	  KEY=VALUE         (one per line, ignores blanks and # comments,
//	                     strips matching surrounding "..." or '...')
//
// One Discovery is emitted per (file, server-or-section, env-key) tuple
// that maps to a registered service. Unknown env vars are skipped silently;
// our job is to import what we can recognise, not to flag every possible
// secret in a user's home directory.
package discovery

// Discovery is one credential found in some on-disk config.
type Discovery struct {
	Service     string // canonical service name from registry
	EnvVar      string // env var observed in the source (may be an alias)
	Token       string // plaintext credential as found
	Source      string // absolute path of the file we found it in
	ServerName  string // mcpServers.<name> for mcp.json sources; empty for .env
	Note        string // human note ("aliased from GITHUB_PERSONAL_ACCESS_TOKEN")
}

// Redacted returns a non-secret rendering of Token: prefix + "..." + suffix.
// Used by import UI so the user can sanity-check which token came from where.
func (d Discovery) Redacted() string {
	t := d.Token
	switch {
	case len(t) <= 8:
		return "***" // too short to safely partial-show
	case len(t) <= 20:
		return t[:4] + "...****"
	default:
		return t[:8] + "..." + t[len(t)-4:]
	}
}
