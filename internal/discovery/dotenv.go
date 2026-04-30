package discovery

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/seoo2001/mcp-gate/internal/services"
)

// ScanDotenv parses a POSIX-y .env file and yields one Discovery per
// recognisable secret. Quoting rules (matching real-world .env behaviour):
//
//	KEY=value             → KEY=value
//	KEY="value"           → KEY=value     (double-quotes stripped)
//	KEY='value'           → KEY=value     (single-quotes stripped)
//	export KEY=value      → KEY=value     (leading 'export ' tolerated)
//	# comment             → skipped
//	KEY=value # trailing  → trailing comment NOT stripped (real shells don't,
//	                         and stripping would corrupt tokens that contain '#')
//
// Variable expansion ($FOO, ${FOO}) is not performed — credentials are
// almost never written that way, and naive expansion would risk leaking
// random env into the vault.
func ScanDotenv(path string, reg *services.Registry) ([]Discovery, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	var out []Discovery
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = unquote(strings.TrimSpace(val))
		if key == "" || val == "" {
			continue
		}
		d := classify(reg, key, val)
		if d.Service == "" {
			continue
		}
		d.Source = path
		out = append(out, d)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %q: %w", path, err)
	}
	return out, nil
}

// unquote strips one layer of matching surrounding quotes.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}
