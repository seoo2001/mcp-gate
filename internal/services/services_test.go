package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinSetIsComplete(t *testing.T) {
	r := NewRegistry()
	want := []string{
		// MVP five
		"github", "slack", "notion", "linear", "stripe",
		// expanded set
		"gitlab", "atlassian", "airtable", "figma", "hubspot", "discord",
		"supabase", "vercel", "cloudflare", "shopify",
		"sentry", "datadog", "pagerduty",
		"twilio", "sendgrid", "resend",
		"openai", "anthropic", "perplexity", "groq", "mistral", "cohere",
		"elevenlabs", "replicate", "tavily", "firecrawl", "brave-search",
		"exa", "apify",
	}
	for _, name := range want {
		if _, ok := r.Get(name); !ok {
			t.Fatalf("built-in registry missing %q", name)
		}
	}
}

func TestResolveByEnvVar_HandlesAliases(t *testing.T) {
	r := NewRegistry()
	cases := []struct {
		envVar string
		want   string
	}{
		{"GITHUB_TOKEN", "github"},
		{"GITHUB_PERSONAL_ACCESS_TOKEN", "github"},
		{"GH_TOKEN", "github"},
		{"github_token", "github"}, // case-insensitive
		{"SLACK_BOT_TOKEN", "slack"},
		{"DD_API_KEY", "datadog"},
		{"DATADOG_APP_KEY", "datadog"},
		{"SUPABASE_SERVICE_ROLE_KEY", "supabase"},
		{"CF_API_TOKEN", "cloudflare"},
		{"VERCEL_API_TOKEN", "vercel"},
		{"FIGMA_PERSONAL_ACCESS_TOKEN", "figma"},
	}
	for _, c := range cases {
		got, ok := r.ResolveByEnvVar(c.envVar)
		if !ok {
			t.Errorf("ResolveByEnvVar(%q) = not found", c.envVar)
			continue
		}
		if got.Name != c.want {
			t.Errorf("ResolveByEnvVar(%q) = %s, want %s", c.envVar, got.Name, c.want)
		}
	}
}

// TestResolveByTokenPrefix_LongestWins guards against the OpenAI/Anthropic
// collision: every Anthropic token starts with "sk-ant-..." which also
// starts with "sk-" (an OpenAI prefix). If we returned the first match,
// Anthropic tokens would mis-classify ~50% of the time depending on map
// iteration order.
func TestResolveByTokenPrefix_LongestWins(t *testing.T) {
	r := NewRegistry()
	cases := []struct {
		token string
		want  string
	}{
		{"sk-ant-api03-aaaa1234", "anthropic"},     // longer than sk-
		{"sk-ant-oat01-xxxx", "anthropic"},
		{"sk-proj-foo", "openai"},
		{"sk-svcacct-bar", "openai"},
		{"sk-1234567890", "openai"},                 // legacy OpenAI
		{"sk_live_abc", "stripe"},                   // hyphen vs underscore separator
		{"sk_test_abc", "stripe"},
		{"rk_live_abc", "stripe"},
		{"ghp_aaaa", "github"},
		{"github_pat_xyz", "github"},
		{"glpat-abcd", "gitlab"},
		{"shpat_token", "shopify"},
		{"figd_abc", "figma"},
		{"sbp_admin", "supabase"},
		{"vcp_token", "vercel"},
		{"cfut_xyz", "cloudflare"},
		{"sntrys_org_token", "sentry"},
		{"pat-na1-uuid", "hubspot"},                 // 'pat-' vs Airtable 'pat'
		{"patAirtableToken1234.xxxx", "airtable"},   // no hyphen
		{"SG.local", "sendgrid"},
		{"re_resend_token", "resend"},
		{"gsk_groq", "groq"},
		{"r8_replicate", "replicate"},
		{"tvly-tav", "tavily"},
		{"fc-firecrawl", "firecrawl"},
		{"BSAbrave", "brave-search"},
		{"pplx-abc", "perplexity"},
	}
	for _, c := range cases {
		got, ok := r.ResolveByTokenPrefix(c.token)
		if !ok {
			t.Errorf("ResolveByTokenPrefix(%q) = not found", c.token)
			continue
		}
		if got.Name != c.want {
			t.Errorf("ResolveByTokenPrefix(%q) = %s, want %s", c.token, got.Name, c.want)
		}
	}
}

func TestResolveByTokenPrefix_NoMatch(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.ResolveByTokenPrefix("bare-uuid-1234"); ok {
		t.Fatal("expected no match for unknown prefix")
	}
}

func TestMatchHost(t *testing.T) {
	r := NewRegistry()
	cases := []struct {
		host    string
		wantSvc string
		wantOK  bool
	}{
		{"api.github.com", "github", true},
		{"api.github.com:443", "github", true},
		{"API.GitHub.com", "github", true},
		{"slack.com", "slack", true},
		{"files.slack.com", "slack", true}, // configured as exact host
		{"api.notion.com", "notion", true},
		{"api.linear.app", "linear", true},
		{"api.stripe.com", "stripe", true},
		{"api.example.com", "", false},
	}
	for _, c := range cases {
		got, ok := r.MatchHost(c.host)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v, want %v", c.host, ok, c.wantOK)
		}
		if ok && got.Name != c.wantSvc {
			t.Fatalf("%s: svc=%s, want %s", c.host, got.Name, c.wantSvc)
		}
	}
}

func TestMatchHost_Wildcard(t *testing.T) {
	r := NewRegistry()
	r.byName["custom"] = Service{Name: "custom", EnvVar: "X", Hosts: []string{"*.example.com"}}
	if got, ok := r.MatchHost("api.example.com"); !ok || got.Name != "custom" {
		t.Fatalf("wildcard match failed: %+v ok=%v", got, ok)
	}
	if _, ok := r.MatchHost("example.com"); ok {
		t.Fatalf("wildcard should not match the bare suffix")
	}
}

func TestLoadOverrides_AddAndReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "services.json")
	body := []byte(`[
	  {"name":"custom","env_var":"CUSTOM_TOKEN","hosts":["api.custom.io"]},
	  {"name":"github","env_var":"GITHUB_TOKEN","hosts":["api.github.example"]}
	]`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.LoadOverrides(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("custom"); !ok {
		t.Fatalf("custom service not added")
	}
	gh, _ := r.Get("github")
	if len(gh.Hosts) != 1 || gh.Hosts[0] != "api.github.example" {
		t.Fatalf("github not overridden: %+v", gh)
	}
}

func TestLoadOverrides_Missing(t *testing.T) {
	r := NewRegistry()
	if err := r.LoadOverrides(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("missing file should be ok, got %v", err)
	}
}

func TestLoadOverrides_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "services.json")
	_ = os.WriteFile(path, []byte(`[{"name":"","env_var":"X","hosts":["h"]}]`), 0o600)
	r := NewRegistry()
	if err := r.LoadOverrides(path); err == nil {
		t.Fatal("expected validation error")
	}
}
