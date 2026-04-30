package discovery

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SourceKind tags how to parse a candidate file.
type SourceKind int

const (
	KindMCPJSON SourceKind = iota + 1
	KindDotenv
)

// Source is one candidate file path with its parser kind. A file may be
// absent — DefaultSources() returns probable locations regardless; the
// scanner skips ones that don't exist.
type Source struct {
	Path string
	Kind SourceKind
	// Label is shown in import UI: "Claude Desktop", "Cursor", "project .env".
	Label string
}

// DefaultSources returns the platform-appropriate list of well-known config
// locations to scan. This list is intentionally narrow: we only look in
// places where a *reasonable* user actually configures their MCP servers,
// not anywhere a credential might happen to live (we are not a secrets-
// scanner).
func DefaultSources() []Source {
	out := []Source{}
	home, _ := os.UserHomeDir()

	// Claude Desktop — by far the most common MCP host.
	switch runtime.GOOS {
	case "darwin":
		out = append(out, Source{
			Path:  filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			Kind:  KindMCPJSON,
			Label: "Claude Desktop (macOS)",
		})
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			out = append(out, Source{
				Path:  filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
				Kind:  KindMCPJSON,
				Label: "Claude Desktop (Windows)",
			})
		}
	case "linux":
		out = append(out, Source{
			Path:  filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			Kind:  KindMCPJSON,
			Label: "Claude Desktop (Linux)",
		})
	}

	// Claude Code (CLI) — user-global config and a project-local override.
	out = append(out,
		Source{Path: filepath.Join(home, ".claude", "mcp.json"), Kind: KindMCPJSON, Label: "Claude Code (user)"},
		Source{Path: filepath.Join(home, ".claude.json"), Kind: KindMCPJSON, Label: "Claude Code (legacy ~/.claude.json)"},
	)

	// Cursor.
	out = append(out, Source{
		Path:  filepath.Join(home, ".cursor", "mcp.json"),
		Kind:  KindMCPJSON,
		Label: "Cursor",
	})

	// Windsurf.
	out = append(out, Source{
		Path:  filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		Kind:  KindMCPJSON,
		Label: "Windsurf",
	})

	// Project-local sources, anchored at CWD and the git root above CWD.
	if cwd, err := os.Getwd(); err == nil {
		out = append(out,
			Source{Path: filepath.Join(cwd, ".mcp.json"), Kind: KindMCPJSON, Label: "project .mcp.json (cwd)"},
			Source{Path: filepath.Join(cwd, ".env"), Kind: KindDotenv, Label: "project .env (cwd)"},
			Source{Path: filepath.Join(cwd, ".env.local"), Kind: KindDotenv, Label: "project .env.local"},
		)
		if root := gitRoot(cwd); root != "" && root != cwd {
			out = append(out,
				Source{Path: filepath.Join(root, ".mcp.json"), Kind: KindMCPJSON, Label: "project .mcp.json (git root)"},
				Source{Path: filepath.Join(root, ".env"), Kind: KindDotenv, Label: "project .env (git root)"},
			)
		}
	}

	return out
}

// gitRoot returns the git repo root containing dir, or "" if dir isn't
// inside a repo. We shell out to git rather than reimplement; rev-parse is
// universally available wherever a developer is editing MCP configs.
func gitRoot(dir string) string {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Exists reports whether s.Path is present and readable.
func (s Source) Exists() bool {
	st, err := os.Stat(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return false
	}
	return !st.IsDir()
}
