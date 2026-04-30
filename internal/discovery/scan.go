package discovery

import (
	"sort"

	"github.com/seoo2001/mcp-gate/internal/services"
)

// ScanError attaches a source path to a non-fatal error. The scanner keeps
// going past one bad file because users on real laptops have weird perms,
// invalid JSON in old configs, etc. — surfacing the error and proceeding is
// the kindest behaviour.
type ScanError struct {
	Source Source
	Err    error
}

// Scan walks every source that exists and returns all Discoveries plus a
// list of per-source errors (zero-length on a healthy run).
//
// Discoveries are de-duplicated by (service, token): if the same credential
// shows up in three different config files (which it usually does — Claude
// Desktop, Cursor, and a project .env all carrying GITHUB_TOKEN), we report
// it once and list every source it was found in. The user only needs to
// vault-import each unique credential one time.
func Scan(sources []Source, reg *services.Registry) ([]Aggregated, []ScanError) {
	var hits []Discovery
	var errs []ScanError
	for _, s := range sources {
		if !s.Exists() {
			continue
		}
		var (
			ds  []Discovery
			err error
		)
		switch s.Kind {
		case KindMCPJSON:
			ds, err = ScanMCPConfig(s.Path, reg)
		case KindDotenv:
			ds, err = ScanDotenv(s.Path, reg)
		}
		if err != nil {
			errs = append(errs, ScanError{Source: s, Err: err})
			continue
		}
		hits = append(hits, ds...)
	}
	return aggregate(hits), errs
}

// Aggregated groups Discovery rows that share (service, token).
type Aggregated struct {
	Service string
	Token   string
	// Sources lists each (path, server-name) the credential was found in.
	Sources []DiscoverySource
	// Notes are unique informational notes from the underlying discoveries.
	Notes []string
}

// DiscoverySource records one place we saw this credential.
type DiscoverySource struct {
	Path       string
	ServerName string // for mcp.json sources; empty for .env
	EnvVar     string
}

// Redacted returns a partial-token rendering for UI display.
func (a Aggregated) Redacted() string {
	d := Discovery{Token: a.Token}
	return d.Redacted()
}

func aggregate(hits []Discovery) []Aggregated {
	type key struct{ svc, tok string }
	bucket := map[key]*Aggregated{}
	for _, h := range hits {
		k := key{h.Service, h.Token}
		a, ok := bucket[k]
		if !ok {
			a = &Aggregated{Service: h.Service, Token: h.Token}
			bucket[k] = a
		}
		a.Sources = append(a.Sources, DiscoverySource{
			Path: h.Source, ServerName: h.ServerName, EnvVar: h.EnvVar,
		})
		if h.Note != "" && !contains(a.Notes, h.Note) {
			a.Notes = append(a.Notes, h.Note)
		}
	}
	out := make([]Aggregated, 0, len(bucket))
	for _, a := range bucket {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
