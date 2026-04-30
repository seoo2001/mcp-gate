package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLogAndIterate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, svc := range []string{"github", "slack", "stripe"} {
		if err := l.Log(context.Background(), Event{
			Service: svc, Method: "GET", Host: "api." + svc + ".com", Path: "/v1/x",
			Status: 200 + i, Outcome: "swap",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if got, want := st.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("perm %v, want %v", got, want)
	}

	var got []Event
	if err := Iterate(path, func(e Event) bool {
		got = append(got, e)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d events, want 3", len(got))
	}
	if got[0].Service != "github" || got[2].Status != 202 {
		t.Fatalf("event order wrong: %+v", got)
	}
	for _, e := range got {
		if e.TimestampISO == "" || e.TimestampUnix == 0 {
			t.Fatalf("event missing timestamp: %+v", e)
		}
	}
}

func TestLogAfterClose(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(filepath.Join(dir, "a.jsonl"))
	_ = l.Close()
	if err := l.Log(context.Background(), Event{Service: "x", Outcome: "swap"}); err == nil {
		t.Fatalf("expected error after close")
	}
}
