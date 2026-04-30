// Package approval implements the optional human-in-the-loop gate. The
// MVP target is Slack (PLAN.md W5): a sensitive call halts in the proxy,
// mcp-gate POSTs a message to a webhook, the user clicks Approve in Slack,
// the webhook hits a tiny callback HTTP server we run on localhost, and
// the original call resumes. If the user doesn't decide within timeout,
// we deny.
//
// Why a callback server rather than polling: Slack interactive messages
// already require a public callback URL for the Approve button to work.
// In MVP we expose only a localhost endpoint; integrating with a real
// Slack workspace requires an exposed tunnel (PLAN.md W5 calls this out;
// users typically pair this with `cloudflared tunnel`).
//
// For users without Slack, the AutoDeny and ManualConsole approvers cover
// the no-config case (deny everything sensitive) and the "I'm at my
// terminal" case (prompt on stdin).
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/seoo2001/mcp-gate/internal/proxy"
)

// AutoDeny is the safe default: any call that hits an approval rule is
// rejected with no human prompt. Used when no webhook is configured.
type AutoDeny struct{}

// Approve always returns an error.
func (AutoDeny) Approve(_ context.Context, _ proxy.ApprovalRequest) error {
	return errors.New("auto-deny: no approver configured")
}

// SlackApprover posts a message to a Slack webhook URL with an Approve/Deny
// link. The link points at this approver's local callback HTTP server.
//
// MVP version: link approval (no signed buttons). The webhook URL alone is
// the authentication; whoever can hit it can approve. PLAN.md W5 lists
// fine-grained signed approval as a follow-on.
type SlackApprover struct {
	WebhookURL string
	// CallbackAddr is the host:port the user reaches to click Approve.
	// Typically loopback in MVP; pair with cloudflared for remote.
	CallbackAddr string
	// Timeout is how long to wait for a click before denying.
	Timeout time.Duration

	mu       sync.Mutex
	pending  map[string]chan bool
	server   *http.Server
	listenWG sync.WaitGroup
}

// Start brings up the callback server. Idempotent.
func (s *SlackApprover) Start(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return nil
	}
	if s.pending == nil {
		s.pending = map[string]chan bool{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/decide", s.handleDecide)
	srv := &http.Server{
		Addr:              s.CallbackAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.server = srv
	s.listenWG.Add(1)
	// The goroutine uses the local `srv` rather than s.server so that Stop()
	// nilling s.server can't race the read; the goroutine's lifetime is
	// bounded by srv.Shutdown() in Stop().
	go func() {
		defer s.listenWG.Done()
		_ = srv.ListenAndServe()
	}()
	return nil
}

// Stop shuts down the callback server.
func (s *SlackApprover) Stop(ctx context.Context) error {
	s.mu.Lock()
	srv := s.server
	s.server = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	s.listenWG.Wait()
	return err
}

// Approve posts a message and blocks until decision or timeout.
func (s *SlackApprover) Approve(ctx context.Context, req proxy.ApprovalRequest) error {
	if s.WebhookURL == "" {
		return errors.New("slack approver: no webhook configured")
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	id := fmt.Sprintf("%d-%s-%s", time.Now().UnixNano(), req.Service, req.Method)
	ch := make(chan bool, 1)
	s.mu.Lock()
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	body := slackPayload(req, id, s.CallbackAddr)
	if err := postJSON(ctx, s.WebhookURL, body); err != nil {
		return fmt.Errorf("slack approver: post: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ok := <-ch:
		if !ok {
			return errors.New("slack approver: denied by user")
		}
		return nil
	case <-timer.C:
		return errors.New("slack approver: timed out waiting for approval")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SlackApprover) handleDecide(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	verdict := r.URL.Query().Get("v")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	ch, ok := s.pending[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown or expired", http.StatusGone)
		return
	}
	ch <- verdict == "approve"
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s recorded — you can close this tab", verdict)
}

func slackPayload(req proxy.ApprovalRequest, id, callback string) []byte {
	type slackBlock struct {
		Type string `json:"type"`
		Text struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"text"`
	}
	body := struct {
		Text   string       `json:"text"`
		Blocks []slackBlock `json:"blocks"`
	}{
		Text: fmt.Sprintf("mcp-gate: %s %s on %s/%s requires approval", req.Method, req.Path, req.Service, req.Host),
	}
	header := slackBlock{Type: "section"}
	header.Text.Type = "mrkdwn"
	header.Text.Text = fmt.Sprintf("*mcp-gate approval*\n*%s* `%s`\nservice: `%s`\nhost: `%s`", req.Method, req.Path, req.Service, req.Host)
	body.Blocks = append(body.Blocks, header)
	link := slackBlock{Type: "section"}
	link.Text.Type = "mrkdwn"
	link.Text.Text = fmt.Sprintf("<http://%s/decide?id=%s&v=approve|✅ Approve>  |  <http://%s/decide?id=%s&v=deny|⛔ Deny>",
		callback, id, callback, id)
	body.Blocks = append(body.Blocks, link)
	out, _ := json.Marshal(body)
	return out
}

func postJSON(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
