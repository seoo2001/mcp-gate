package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seoo2001/mcp-gate/internal/services"
)

func TestScanMCPConfig_RecognisesAnthropicEnvAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude_desktop_config.json")
	body := []byte(`{
	  "mcpServers": {
	    "github": {
	      "command": "npx",
	      "args": ["-y", "@modelcontextprotocol/server-github"],
	      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_aliasedTokenValue123" }
	    },
	    "slack": {
	      "command": "npx",
	      "args": ["-y", "@modelcontextprotocol/server-slack"],
	      "env": {
	        "SLACK_BOT_TOKEN": "xoxb-realToken-abc",
	        "SLACK_TEAM_ID": "T012345"
	      }
	    },
	    "unknown": {
	      "env": { "UNRELATED_TOKEN": "blah" }
	    }
	  }
	}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	reg := services.NewRegistry()
	got, err := ScanMCPConfig(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 discoveries (github, slack); got %d:\n%+v", len(got), got)
	}
	bySvc := map[string]Discovery{}
	for _, d := range got {
		bySvc[d.Service] = d
	}
	gh, ok := bySvc["github"]
	if !ok {
		t.Fatal("missing github discovery")
	}
	if gh.Token != "ghp_aliasedTokenValue123" {
		t.Fatalf("github token wrong: %q", gh.Token)
	}
	if !strings.Contains(gh.Note, "aliased") {
		t.Fatalf("expected aliased note, got %q", gh.Note)
	}
	if gh.ServerName != "github" {
		t.Fatalf("server name wrong: %q", gh.ServerName)
	}
	sl := bySvc["slack"]
	if !strings.HasPrefix(sl.Token, "xoxb-") {
		t.Fatalf("slack token wrong: %q", sl.Token)
	}
}

func TestScanMCPConfig_FlagsCrossServiceTokenMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := []byte(`{
	  "mcpServers": {
	    "slack": { "env": { "SLACK_TOKEN": "ghp_thisIsActuallyAGitHubToken" } }
	  }
	}`)
	_ = os.WriteFile(path, body, 0o600)
	got, _ := ScanMCPConfig(path, services.NewRegistry())
	if len(got) != 1 {
		t.Fatalf("got %d discoveries", len(got))
	}
	if got[0].Service != "slack" {
		t.Fatalf("service should follow env-var mapping, got %q", got[0].Service)
	}
	if !strings.Contains(strings.ToLower(got[0].Note), "warning") {
		t.Fatalf("expected mismatch warning, got %q", got[0].Note)
	}
}

func TestScanMCPConfig_TokenPrefixFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := []byte(`{
	  "mcpServers": {
	    "weird": { "env": { "MY_PRIVATE_PAT": "ghp_definitelyAGitHubToken" } }
	  }
	}`)
	_ = os.WriteFile(path, body, 0o600)
	got, _ := ScanMCPConfig(path, services.NewRegistry())
	if len(got) != 1 || got[0].Service != "github" {
		t.Fatalf("token-prefix fallback failed: %+v", got)
	}
	if !strings.Contains(got[0].Note, "inferred from token prefix") {
		t.Fatalf("expected prefix-inference note, got %q", got[0].Note)
	}
}

func TestScanMCPConfig_SkipsEmptyEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(path, []byte(`{"mcpServers":{"x":{"env":{"GITHUB_TOKEN":""}}}}`), 0o600)
	got, _ := ScanMCPConfig(path, services.NewRegistry())
	if len(got) != 0 {
		t.Fatalf("empty token should be skipped, got %+v", got)
	}
}

func TestScanDotenv_BasicQuoting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := `# leading comment
GITHUB_TOKEN=ghp_unquoted_value
SLACK_BOT_TOKEN="xoxb-double-quoted-value"
NOTION_API_KEY='secret_single_quoted'
export STRIPE_SECRET_KEY=sk_live_abcdef
EMPTY=
JUST_A_COMMENT=# this is part of the value, by design
unrelated=foo
`
	_ = os.WriteFile(path, []byte(body), 0o600)
	got, err := ScanDotenv(path, services.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 discoveries, got %d:\n%+v", len(got), got)
	}
	tokens := map[string]string{}
	for _, d := range got {
		tokens[d.Service] = d.Token
	}
	if tokens["github"] != "ghp_unquoted_value" {
		t.Fatalf("github=%q", tokens["github"])
	}
	if tokens["slack"] != "xoxb-double-quoted-value" {
		t.Fatalf("slack=%q", tokens["slack"])
	}
	if tokens["notion"] != "secret_single_quoted" {
		t.Fatalf("notion=%q", tokens["notion"])
	}
	if tokens["stripe"] != "sk_live_abcdef" {
		t.Fatalf("stripe=%q", tokens["stripe"])
	}
}

func TestScan_Aggregates(t *testing.T) {
	dir := t.TempDir()
	mcpPath := filepath.Join(dir, "mcp.json")
	envPath := filepath.Join(dir, ".env")
	_ = os.WriteFile(mcpPath, []byte(`{"mcpServers":{"github":{"env":{"GITHUB_TOKEN":"ghp_shared"}}}}`), 0o600)
	_ = os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_shared\n"), 0o600)
	reg := services.NewRegistry()
	agg, errs := Scan([]Source{
		{Path: mcpPath, Kind: KindMCPJSON, Label: "test mcp"},
		{Path: envPath, Kind: KindDotenv, Label: "test .env"},
	}, reg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(agg) != 1 {
		t.Fatalf("want 1 aggregated, got %d:\n%+v", len(agg), agg)
	}
	if len(agg[0].Sources) != 2 {
		t.Fatalf("want 2 sources, got %d", len(agg[0].Sources))
	}
}

func TestScan_KeepsGoingOnBadFile(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	goodPath := filepath.Join(dir, ".env")
	_ = os.WriteFile(badPath, []byte("not json {{{"), 0o600)
	_ = os.WriteFile(goodPath, []byte("GITHUB_TOKEN=ghp_x\n"), 0o600)
	agg, errs := Scan([]Source{
		{Path: badPath, Kind: KindMCPJSON, Label: "bad"},
		{Path: goodPath, Kind: KindDotenv, Label: "good"},
	}, services.NewRegistry())
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %d", len(errs))
	}
	if len(agg) != 1 || agg[0].Service != "github" {
		t.Fatalf("good source dropped: %+v", agg)
	}
}

func TestRedactedShape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", "***"},
		{"abcdefghi", "abcd...****"},
		{"ghp_aaaaaaaaaaaaaaaaaaaaa1234", "ghp_aaaa...1234"},
	}
	for _, c := range cases {
		got := Discovery{Token: c.in}.Redacted()
		if got != c.want {
			t.Errorf("Redacted(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultSources_NotEmpty(t *testing.T) {
	got := DefaultSources()
	if len(got) == 0 {
		t.Fatal("DefaultSources returned no entries")
	}
	// On any platform we should be looking in at least one home + one cwd
	// path. We don't pin specific paths because they vary by OS.
	hasMCPJSON := false
	hasDotenv := false
	for _, s := range got {
		if s.Kind == KindMCPJSON {
			hasMCPJSON = true
		}
		if s.Kind == KindDotenv {
			hasDotenv = true
		}
	}
	if !hasMCPJSON {
		t.Error("no mcp.json sources in defaults")
	}
	if !hasDotenv {
		t.Error("no .env sources in defaults")
	}
}
