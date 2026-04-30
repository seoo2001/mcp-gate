// Package services holds the registry of supported MCP-target services
// (GitHub, Slack, Notion, Linear, Stripe at MVP). The registry maps a
// service to:
//
//   - the env var name the MCP server expects its credential in,
//   - the upstream host patterns the proxy intercepts for that service.
//
// Built-ins are hard-coded so a fresh install works with zero config.
// Users can override or extend via a JSON file at $MCP_GATE_HOME/services.json.
package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
)

// Service describes one MCP-target API.
type Service struct {
	// Name is the canonical identifier ("github", "slack").
	Name string `json:"name"`
	// EnvVar is the environment variable the MCP server reads to get its
	// credential. mcp-gate sets this in the child process.
	EnvVar string `json:"env_var"`
	// EnvAliases are alternate env-var names actually seen in real configs:
	// e.g. "GITHUB_PERSONAL_ACCESS_TOKEN" (Anthropic's mcp-server-github),
	// "GH_TOKEN" (gh CLI). Used by `mcp-gate import` to recognise tokens
	// even when the user's config uses a non-canonical name.
	EnvAliases []string `json:"env_aliases,omitempty"`
	// TokenPrefixes are byte prefixes that uniquely identify a token as
	// belonging to this service (e.g. "ghp_", "github_pat_"). Used by the
	// importer to cross-validate env→service mappings; a "ghp_..." token
	// in a SLACK_TOKEN slot is almost certainly a misconfiguration we
	// should flag rather than silently accept.
	TokenPrefixes []string `json:"token_prefixes,omitempty"`
	// Hosts lists the upstream hostnames the proxy intercepts for this
	// service. Wildcard prefixes ("*.notion.com") are supported.
	Hosts []string `json:"hosts"`
	// Description is shown by `mcp-gate services`.
	Description string `json:"description,omitempty"`
}

// EnvVarMatches reports whether name matches the canonical EnvVar or any
// alias for this service (case-insensitive).
func (s Service) EnvVarMatches(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	if strings.ToUpper(s.EnvVar) == name {
		return true
	}
	for _, a := range s.EnvAliases {
		if strings.ToUpper(a) == name {
			return true
		}
	}
	return false
}

// LooksLikeToken returns true when token has a prefix associated with this
// service. False is non-committal — many services issue tokens without
// recognisable prefixes.
func (s Service) LooksLikeToken(token string) bool {
	for _, p := range s.TokenPrefixes {
		if strings.HasPrefix(token, p) {
			return true
		}
	}
	return false
}

// Builtin is the default registry shipped with mcp-gate.
//
// EnvAliases reflect what users actually put in mcp.json (Claude Desktop /
// Code, Cursor, Windsurf) and .env files. TokenPrefixes are the byte
// prefixes the issuing services document as identifying their tokens —
// validated against vendor docs as of 2026-04 and used for cross-checking
// env→service mappings during `mcp-gate import`.
//
// Coverage is intentionally broad: every service here is one we've seen in
// at least one popular MCP server config. Users can override or extend via
// $MCP_GATE_HOME/services.json.
var Builtin = []Service{
	// — Code & SCM —
	{
		Name:          "github",
		EnvVar:        "GITHUB_TOKEN",
		EnvAliases:    []string{"GITHUB_PERSONAL_ACCESS_TOKEN", "GH_TOKEN"},
		TokenPrefixes: []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		Hosts:         []string{"api.github.com", "uploads.github.com"},
		Description:   "GitHub REST + GraphQL API",
	},
	{
		Name:          "gitlab",
		EnvVar:        "GITLAB_TOKEN",
		EnvAliases:    []string{"GITLAB_PERSONAL_ACCESS_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN"},
		TokenPrefixes: []string{"glpat-", "glptt-", "gloas-", "glagent-", "glrt-"},
		Hosts:         []string{"gitlab.com"},
		Description:   "GitLab API (gitlab.com; self-hosted requires custom hosts)",
	},
	// — Comms —
	{
		Name:          "slack",
		EnvVar:        "SLACK_TOKEN",
		EnvAliases:    []string{"SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_API_TOKEN"},
		TokenPrefixes: []string{"xoxb-", "xoxp-", "xoxa-", "xapp-", "xoxe-"},
		Hosts:         []string{"slack.com", "files.slack.com"},
		Description:   "Slack Web API",
	},
	{
		Name:          "discord",
		EnvVar:        "DISCORD_TOKEN",
		EnvAliases:    []string{"DISCORD_BOT_TOKEN"},
		TokenPrefixes: nil, // bot tokens are 3-segment base64; no stable prefix
		Hosts:         []string{"discord.com"},
		Description:   "Discord HTTP API (bot tokens)",
	},
	// — Knowledge / Productivity —
	{
		Name:          "notion",
		EnvVar:        "NOTION_TOKEN",
		EnvAliases:    []string{"NOTION_API_KEY", "INTERNAL_INTEGRATION_TOKEN"},
		TokenPrefixes: []string{"ntn_", "secret_"},
		Hosts:         []string{"api.notion.com"},
		Description:   "Notion API",
	},
	{
		Name:          "linear",
		EnvVar:        "LINEAR_API_KEY",
		EnvAliases:    []string{"LINEAR_TOKEN", "LINEAR_PERSONAL_API_KEY"},
		TokenPrefixes: []string{"lin_api_", "lin_oauth_"},
		Hosts:         []string{"api.linear.app"},
		Description:   "Linear GraphQL API",
	},
	{
		Name:          "atlassian",
		EnvVar:        "ATLASSIAN_API_TOKEN",
		EnvAliases:    []string{"JIRA_API_TOKEN", "CONFLUENCE_API_TOKEN", "ATLASSIAN_TOKEN"},
		TokenPrefixes: []string{"ATATT3xFfGF0"}, // Atlassian Cloud PAT shape
		Hosts:         []string{"api.atlassian.com"},
		Description:   "Jira / Confluence Cloud (paired with email + base URL)",
	},
	{
		Name:          "airtable",
		EnvVar:        "AIRTABLE_API_KEY",
		EnvAliases:    []string{"AIRTABLE_PAT", "AIRTABLE_TOKEN", "AIRTABLE_ACCESS_TOKEN"},
		TokenPrefixes: []string{"pat"}, // 'pat' followed by 14 chars, then '.' — distinct from HubSpot 'pat-'
		Hosts:         []string{"api.airtable.com"},
		Description:   "Airtable API (personal access tokens)",
	},
	{
		Name:          "figma",
		EnvVar:        "FIGMA_ACCESS_TOKEN",
		EnvAliases:    []string{"FIGMA_PERSONAL_ACCESS_TOKEN", "FIGMA_API_KEY", "FIGMA_TOKEN"},
		TokenPrefixes: []string{"figd_"},
		Hosts:         []string{"api.figma.com"},
		Description:   "Figma REST API",
	},
	{
		Name:          "hubspot",
		EnvVar:        "HUBSPOT_ACCESS_TOKEN",
		EnvAliases:    []string{"HUBSPOT_API_KEY", "HUBSPOT_PRIVATE_APP_TOKEN"},
		TokenPrefixes: []string{"pat-na1-", "pat-na2-", "pat-na3-", "pat-eu1-"},
		Hosts:         []string{"api.hubapi.com", "api.hubspotapi.com"},
		Description:   "HubSpot CRM API",
	},
	// — Infra & deploy —
	{
		Name:          "supabase",
		EnvVar:        "SUPABASE_ACCESS_TOKEN",
		EnvAliases:    []string{"SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY", "SUPABASE_KEY", "SUPABASE_SECRET_KEY"},
		TokenPrefixes: []string{"sbp_", "sb_secret_", "sb_publishable_"},
		Hosts:         []string{"api.supabase.com", "*.supabase.co", "*.supabase.in"},
		Description:   "Supabase management + project APIs",
	},
	{
		Name:          "vercel",
		EnvVar:        "VERCEL_TOKEN",
		EnvAliases:    []string{"VERCEL_API_TOKEN", "VERCEL_ACCESS_TOKEN"},
		TokenPrefixes: []string{"vcp_", "vck_"},
		Hosts:         []string{"api.vercel.com"},
		Description:   "Vercel deployment + AI Gateway API",
	},
	{
		Name:          "cloudflare",
		EnvVar:        "CLOUDFLARE_API_TOKEN",
		EnvAliases:    []string{"CF_API_TOKEN", "CLOUDFLARE_API_KEY"},
		TokenPrefixes: []string{"cfut_"},
		Hosts:         []string{"api.cloudflare.com"},
		Description:   "Cloudflare API (tokens; legacy global key not auto-detected)",
	},
	{
		Name:          "shopify",
		EnvVar:        "SHOPIFY_ACCESS_TOKEN",
		EnvAliases:    []string{"SHOPIFY_ADMIN_API_ACCESS_TOKEN"},
		TokenPrefixes: []string{"shpat_", "shpca_", "shppa_", "shpss_"},
		Hosts:         []string{"*.myshopify.com"},
		Description:   "Shopify Admin API (per-store host)",
	},
	// — Observability —
	{
		Name:          "sentry",
		EnvVar:        "SENTRY_AUTH_TOKEN",
		EnvAliases:    []string{"SENTRY_TOKEN"},
		TokenPrefixes: []string{"sntrys_", "sntryu_"},
		Hosts:         []string{"sentry.io", "*.ingest.sentry.io"},
		Description:   "Sentry Auth API (DSN is a different surface, not handled)",
	},
	{
		Name:          "datadog",
		EnvVar:        "DD_API_KEY",
		EnvAliases:    []string{"DATADOG_API_KEY", "DD_APP_KEY", "DATADOG_APP_KEY"},
		TokenPrefixes: nil, // 32-hex API / 40-hex APP — no distinctive prefix
		Hosts:         []string{"api.datadoghq.com", "api.datadoghq.eu", "api.us3.datadoghq.com", "api.us5.datadoghq.com", "api.ap1.datadoghq.com", "api.ap2.datadoghq.com", "api.ddog-gov.com"},
		Description:   "Datadog API + APP keys (paired)",
	},
	{
		Name:          "pagerduty",
		EnvVar:        "PAGERDUTY_API_KEY",
		EnvAliases:    []string{"PAGERDUTY_TOKEN"},
		TokenPrefixes: []string{"pdus+", "pdeu+"},
		Hosts:         []string{"api.pagerduty.com", "events.pagerduty.com"},
		Description:   "PagerDuty REST API (Routing Keys are a separate surface)",
	},
	// — Payments / Comms (legacy hold-overs) —
	{
		Name:          "stripe",
		EnvVar:        "STRIPE_API_KEY",
		EnvAliases:    []string{"STRIPE_SECRET_KEY", "STRIPE_RESTRICTED_KEY"},
		TokenPrefixes: []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"},
		Hosts:         []string{"api.stripe.com"},
		Description:   "Stripe REST API",
	},
	{
		Name:          "twilio",
		EnvVar:        "TWILIO_AUTH_TOKEN",
		EnvAliases:    []string{"TWILIO_ACCOUNT_SID", "TWILIO_API_KEY", "TWILIO_API_SECRET"},
		TokenPrefixes: []string{"AC", "SK"}, // SIDs; auth token itself is unprefixed 32 hex
		Hosts:         []string{"api.twilio.com"},
		Description:   "Twilio (Account SID + Auth Token must be paired)",
	},
	{
		Name:          "sendgrid",
		EnvVar:        "SENDGRID_API_KEY",
		EnvAliases:    []string{"TWILIO_SENDGRID_API_KEY"},
		TokenPrefixes: []string{"SG."},
		Hosts:         []string{"api.sendgrid.com"},
		Description:   "SendGrid email API",
	},
	{
		Name:          "resend",
		EnvVar:        "RESEND_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: []string{"re_"},
		Hosts:         []string{"api.resend.com"},
		Description:   "Resend transactional email API",
	},
	// — AI / search —
	{
		Name:          "openai",
		EnvVar:        "OPENAI_API_KEY",
		EnvAliases:    []string{"OPENAI_KEY"},
		// "sk-ant-" must NOT match here — Anthropic owns it. Our resolver
		// picks the longest prefix, so listing "sk-" is safe (Anthropic's
		// "sk-ant-api03-" is longer and wins).
		TokenPrefixes: []string{"sk-proj-", "sk-svcacct-", "sk-admin-", "sk-None-", "sk-"},
		Hosts:         []string{"api.openai.com"},
		Description:   "OpenAI API (chat / completions / embeddings)",
	},
	{
		Name:          "anthropic",
		EnvVar:        "ANTHROPIC_API_KEY",
		EnvAliases:    []string{"CLAUDE_API_KEY"},
		TokenPrefixes: []string{"sk-ant-api03-", "sk-ant-oat01-", "sk-ant-admin-", "sk-ant-"},
		Hosts:         []string{"api.anthropic.com"},
		Description:   "Anthropic Claude API",
	},
	{
		Name:          "perplexity",
		EnvVar:        "PERPLEXITY_API_KEY",
		EnvAliases:    []string{"PPLX_API_KEY"},
		TokenPrefixes: []string{"pplx-"},
		Hosts:         []string{"api.perplexity.ai"},
		Description:   "Perplexity AI Chat API",
	},
	{
		Name:          "groq",
		EnvVar:        "GROQ_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: []string{"gsk_"},
		Hosts:         []string{"api.groq.com"},
		Description:   "Groq inference API",
	},
	{
		Name:          "mistral",
		EnvVar:        "MISTRAL_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: nil,
		Hosts:         []string{"api.mistral.ai"},
		Description:   "Mistral AI API",
	},
	{
		Name:          "cohere",
		EnvVar:        "COHERE_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: nil,
		Hosts:         []string{"api.cohere.com", "api.cohere.ai"},
		Description:   "Cohere API",
	},
	{
		Name:          "elevenlabs",
		EnvVar:        "ELEVENLABS_API_KEY",
		EnvAliases:    []string{"XI_API_KEY"},
		TokenPrefixes: nil,
		Hosts:         []string{"api.elevenlabs.io"},
		Description:   "ElevenLabs TTS API",
	},
	{
		Name:          "replicate",
		EnvVar:        "REPLICATE_API_TOKEN",
		EnvAliases:    []string{"REPLICATE_API_KEY"},
		TokenPrefixes: []string{"r8_"},
		Hosts:         []string{"api.replicate.com"},
		Description:   "Replicate model-hosting API",
	},
	{
		Name:          "tavily",
		EnvVar:        "TAVILY_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: []string{"tvly-"},
		Hosts:         []string{"api.tavily.com"},
		Description:   "Tavily search API",
	},
	{
		Name:          "firecrawl",
		EnvVar:        "FIRECRAWL_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: []string{"fc-"},
		Hosts:         []string{"api.firecrawl.dev"},
		Description:   "Firecrawl web scraping API",
	},
	{
		Name:          "brave-search",
		EnvVar:        "BRAVE_API_KEY",
		EnvAliases:    []string{"BRAVE_SEARCH_API_KEY"},
		TokenPrefixes: []string{"BSA"},
		Hosts:         []string{"api.search.brave.com"},
		Description:   "Brave Search API",
	},
	{
		Name:          "exa",
		EnvVar:        "EXA_API_KEY",
		EnvAliases:    nil,
		TokenPrefixes: nil,
		Hosts:         []string{"api.exa.ai"},
		Description:   "Exa neural search API",
	},
	{
		Name:          "apify",
		EnvVar:        "APIFY_TOKEN",
		EnvAliases:    []string{"APIFY_API_TOKEN"},
		TokenPrefixes: []string{"apify_api_"},
		Hosts:         []string{"api.apify.com"},
		Description:   "Apify scraping platform API",
	},
}

// ResolveByEnvVar returns the service whose EnvVar or EnvAliases matches name.
func (r *Registry) ResolveByEnvVar(name string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.byName {
		if s.EnvVarMatches(name) {
			return s, true
		}
	}
	return Service{}, false
}

// ResolveByTokenPrefix returns the service whose TokenPrefix is the LONGEST
// match against token. Longest-wins matters for nested namespaces:
// Anthropic's "sk-ant-api03-" is also a "sk-" string; if we picked the
// first match, OpenAI would steal Anthropic tokens 50% of the time
// (depending on map iteration order). Longest match makes it deterministic.
func (r *Registry) ResolveByTokenPrefix(token string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var (
		best       Service
		bestLen    int
		bestFound  bool
	)
	for _, s := range r.byName {
		for _, p := range s.TokenPrefixes {
			if strings.HasPrefix(token, p) && len(p) > bestLen {
				best = s
				bestLen = len(p)
				bestFound = true
			}
		}
	}
	return best, bestFound
}

// Registry holds the active service set (built-ins + user overrides).
//
// Override semantics: a user-defined service with the same Name as a built-in
// fully replaces the built-in — we do not merge fields, because half a service
// definition is worse than none.
type Registry struct {
	mu       sync.RWMutex
	byName   map[string]Service
	override string
}

// NewRegistry returns the built-in registry.
func NewRegistry() *Registry {
	r := &Registry{byName: make(map[string]Service, len(Builtin))}
	for _, s := range Builtin {
		r.byName[s.Name] = s
	}
	return r
}

// LoadOverrides reads a JSON file of additional/overriding services.
// Missing file is not an error (zero overrides is a normal state).
func (r *Registry) LoadOverrides(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.override = path
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("services: read %q: %w", path, err)
	}
	if len(b) == 0 {
		return nil
	}
	var overrides []Service
	if err := json.Unmarshal(b, &overrides); err != nil {
		return fmt.Errorf("services: parse %q: %w", path, err)
	}
	for _, s := range overrides {
		if err := s.validate(); err != nil {
			return fmt.Errorf("services: %s in %q: %w", s.Name, path, err)
		}
		r.byName[s.Name] = s
	}
	return nil
}

// Get returns the service by name (case-insensitive).
func (r *Registry) Get(name string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[strings.ToLower(strings.TrimSpace(name))]
	return s, ok
}

// All returns the registry sorted by service name.
func (r *Registry) All() []Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Service, 0, len(r.byName))
	for _, s := range r.byName {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MatchHost returns the service that owns the given upstream host, if any.
// Match is case-insensitive and supports a leading "*." wildcard segment.
func (r *Registry) MatchHost(host string) (Service, bool) {
	host = strings.ToLower(stripPort(host))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.byName {
		for _, pat := range s.Hosts {
			if hostMatch(pat, host) {
				return s, true
			}
		}
	}
	return Service{}, false
}

func stripPort(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".notion.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return false
}

func (s Service) validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(s.EnvVar) == "" {
		return errors.New("env_var is required")
	}
	if len(s.Hosts) == 0 {
		return errors.New("at least one host is required")
	}
	return nil
}
