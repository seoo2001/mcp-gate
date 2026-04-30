package approval

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/seoo2001/mcp-gate/internal/proxy"
)

func TestAutoDeny_AlwaysErrors(t *testing.T) {
	if err := (AutoDeny{}).Approve(context.Background(), proxy.ApprovalRequest{}); err == nil {
		t.Fatal("expected deny")
	}
}

// TestSlackApprover_PostsAndApproves boots a fake Slack webhook + drives the
// callback handler ourselves to simulate a user clicking Approve.
func TestSlackApprover_PostsAndApproves(t *testing.T) {
	posted := make(chan struct{}, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	a := &SlackApprover{
		WebhookURL:   webhook.URL,
		CallbackAddr: addr,
		Timeout:      3 * time.Second,
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.Stop(context.Background())
	// Wait for the callback server to actually be listening.
	waitForListening(t, addr)

	var wg sync.WaitGroup
	wg.Add(1)
	var approveErr error
	go func() {
		defer wg.Done()
		approveErr = a.Approve(context.Background(), proxy.ApprovalRequest{
			Service: "github", Method: "DELETE", Host: "api.github.com", Path: "/repos/x/y",
		})
	}()

	select {
	case <-posted:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never posted")
	}

	// Pull the pending id by inspecting state. Easiest: hit /decide with the
	// only outstanding id by enumerating via the unexported map.
	a.mu.Lock()
	if len(a.pending) != 1 {
		a.mu.Unlock()
		t.Fatalf("pending = %d, want 1", len(a.pending))
	}
	var id string
	for k := range a.pending {
		id = k
	}
	a.mu.Unlock()

	resp, err := http.Get("http://" + addr + "/decide?id=" + id + "&v=approve")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	wg.Wait()
	if approveErr != nil {
		t.Fatalf("approve returned: %v", approveErr)
	}
}

func TestSlackApprover_DenyPath(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	a := &SlackApprover{WebhookURL: webhook.URL, CallbackAddr: addr, Timeout: 3 * time.Second}
	a.Start(context.Background())
	defer a.Stop(context.Background())
	waitForListening(t, addr)

	done := make(chan error, 1)
	go func() {
		done <- a.Approve(context.Background(), proxy.ApprovalRequest{Service: "x"})
	}()

	// Race-free way to learn the id: poll the pending map.
	id := waitForPending(t, a)
	resp, err := http.Get("http://" + addr + "/decide?id=" + id + "&v=deny")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected denial error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approve never returned")
	}
}

func TestSlackApprover_Timeout(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	a := &SlackApprover{
		WebhookURL: webhook.URL, CallbackAddr: "127.0.0.1:0", Timeout: 100 * time.Millisecond,
	}
	a.Start(context.Background())
	defer a.Stop(context.Background())
	err := a.Approve(context.Background(), proxy.ApprovalRequest{Service: "x"})
	if err == nil || !errors.Is(err, err) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func waitForListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener at %s never came up", addr)
}

func waitForPending(t *testing.T, a *SlackApprover) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		for k := range a.pending {
			a.mu.Unlock()
			return k
		}
		a.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no pending request appeared")
	return ""
}
