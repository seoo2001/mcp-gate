package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// run is a small helper that invokes the App with a temp $MCP_GATE_HOME and
// returns stdout, stderr, exit code.
func run(t *testing.T, env map[string]string, argv ...string) (string, string, int) {
	t.Helper()
	if env == nil {
		env = map[string]string{}
	}
	if _, ok := env["MCP_GATE_HOME"]; !ok {
		env["MCP_GATE_HOME"] = filepath.Join(t.TempDir(), "home")
	}
	if _, ok := env["MCP_GATE_KEYSTORE"]; !ok {
		env["MCP_GATE_KEYSTORE"] = "file"
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	out := &bytes.Buffer{}
	errb := &bytes.Buffer{}
	app := New("test", out, errb)
	code := app.Run(context.Background(), argv)
	return out.String(), errb.String(), code
}

func TestVersion(t *testing.T) {
	out, _, code := run(t, nil, "version")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "test") {
		t.Fatalf("expected version in output, got %q", out)
	}
}

func TestAddListGetRemoveRoundTrip(t *testing.T) {
	env := map[string]string{}
	out, errb, code := run(t, env, "add", "github", "--token=ghp_xyz")
	if code != 0 {
		t.Fatalf("add: code=%d stderr=%s", code, errb)
	}
	if !strings.Contains(out, "stored credential") {
		t.Fatalf("unexpected stdout: %q", out)
	}

	out, _, code = run(t, env, "list")
	if code != 0 {
		t.Fatalf("list code = %d", code)
	}
	if !strings.Contains(out, "github") {
		t.Fatalf("list missing github: %q", out)
	}

	out, _, code = run(t, env, "remove", "github")
	if code != 0 || !strings.Contains(out, "removed github") {
		t.Fatalf("remove failed: code=%d out=%q", code, out)
	}

	// removing again should fail
	_, errb, code = run(t, env, "remove", "github")
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing service, stderr=%s", errb)
	}
}

func TestAddRequiresTokenInput(t *testing.T) {
	_, errb, code := run(t, nil, "add", "github")
	if code == 0 {
		t.Fatalf("expected error when no token source given")
	}
	if !strings.Contains(errb, "supply") {
		t.Fatalf("unexpected stderr: %q", errb)
	}
}

func TestAddViaEnv(t *testing.T) {
	env := map[string]string{"MY_TOK": "ghp_envvar_value"}
	_, _, code := run(t, env, "add", "stripe", "--token-env=MY_TOK")
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	out, _, _ := run(t, env, "list")
	if !strings.Contains(out, "stripe") {
		t.Fatal("stripe missing")
	}
}

func TestServicesPrintsBuiltins(t *testing.T) {
	out, _, code := run(t, nil, "services")
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"github", "slack", "notion", "linear", "stripe"} {
		if !strings.Contains(out, want) {
			t.Fatalf("services output missing %q\n%s", want, out)
		}
	}
}

func TestInfoPrintsKeystoreBackend(t *testing.T) {
	out, _, code := run(t, nil, "info")
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "keystore: file") {
		t.Fatalf("info missing keystore line: %s", out)
	}
}

func TestUnknownSubcommand(t *testing.T) {
	_, errb, code := run(t, nil, "wat")
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(errb, "unknown subcommand") {
		t.Fatalf("unexpected stderr: %s", errb)
	}
}

func TestNoArgsShowsUsage(t *testing.T) {
	out, _, code := run(t, nil)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("usage not printed: %s", out)
	}
}

func TestLogsEmpty(t *testing.T) {
	out, _, code := run(t, nil, "logs")
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "no events") {
		t.Fatalf("expected '(no events)' message, got: %s", out)
	}
}
