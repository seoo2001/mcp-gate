package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seoo2001/mcp-gate/internal/approval"
	"github.com/seoo2001/mcp-gate/internal/audit"
	"github.com/seoo2001/mcp-gate/internal/proxy"
	"github.com/seoo2001/mcp-gate/internal/proxyca"
	"github.com/seoo2001/mcp-gate/internal/proxytoken"
	"github.com/seoo2001/mcp-gate/internal/wrapper"
)

// stringList implements flag.Value for repeatable string flags.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// runWrap is the headline subcommand: spawn a child with a proxy token,
// stand up the MITM proxy, ship the audit log, deliver child's exit code.
func (a *App) runWrap(ctx context.Context, argv []string) int {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	service := fs.String("service", "", "service name (e.g. github). Required if not inferable from command.")
	ttl := fs.Duration("ttl", 5*time.Minute, "proxy token lifetime")
	port := fs.Int("port", 0, "proxy listen port (0 = OS-assigned)")
	rotate := fs.Duration("rotate", 0, "if > 0, mint+signal a fresh token every <rotate> (SIGUSR1)")
	slackWebhook := fs.String("slack-webhook", "", "Slack incoming webhook URL for sensitive-call approval")
	callback := fs.String("callback", "127.0.0.1:8765", "host:port for approval callback link")
	approvalTimeout := fs.Duration("approval-timeout", 60*time.Second, "max wait for human approval")
	nodeShim := fs.Bool("node-shim", false, "patch Node's https.globalAgent + fetch via NODE_OPTIONS=--require=<shim> so MCP servers respect HTTPS_PROXY (recommended for any node-based MCP server)")
	var approvals stringList
	fs.Var(&approvals, "require-approval-for", `pattern "<METHOD> <path-prefix>", repeatable (e.g. "DELETE /repos/")`)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	args := fs.Args()
	if len(args) == 0 {
		fmt.Fprintln(a.Err, "usage: mcp-gate wrap [flags] <command> [args...]")
		return 2
	}

	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	v, err := st.openVault(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	defer v.Close()

	// Service: explicit flag, or single-vault-entry inference.
	svcName := strings.ToLower(strings.TrimSpace(*service))
	if svcName == "" {
		names, err := v.List(ctx)
		if err != nil {
			fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
			return 1
		}
		if len(names) == 1 {
			svcName = names[0]
		} else {
			fmt.Fprintln(a.Err, "mcp-gate wrap: --service is required (vault has", len(names), "entries)")
			return 2
		}
	}
	if !v.Has(svcName) {
		fmt.Fprintf(a.Err, "mcp-gate wrap: no credential stored for %q. Run `mcp-gate add %s --token=...` first.\n", svcName, svcName)
		return 1
	}

	// CA + Proxy token signer.
	kek, err := st.ks.Load(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		return 1
	}
	ca, err := proxyca.LoadOrCreate(st.layout.CACert, st.layout.CAKey, kek)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		return 1
	}
	signer, err := proxytoken.NewSigner()
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		return 1
	}

	// Audit log.
	logger, err := audit.Open(st.layout.Audit)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		return 1
	}
	defer logger.Close()

	// Approver (optional).
	var apr proxy.Approver = approval.AutoDeny{}
	var slack *approval.SlackApprover
	if *slackWebhook != "" {
		if _, err := url.ParseRequestURI(*slackWebhook); err != nil {
			fmt.Fprintln(a.Err, "mcp-gate wrap: invalid slack-webhook URL:", err)
			return 2
		}
		slack = &approval.SlackApprover{
			WebhookURL:   *slackWebhook,
			CallbackAddr: *callback,
			Timeout:      *approvalTimeout,
		}
		if err := slack.Start(ctx); err != nil {
			fmt.Fprintln(a.Err, "mcp-gate wrap: start approver:", err)
			return 1
		}
		defer slack.Stop(context.Background())
		apr = slack
	}

	// Proxy.
	listenAddr := fmt.Sprintf("127.0.0.1:%d", *port)
	pr, err := proxy.New(proxy.Config{
		Listen:           listenAddr,
		CA:               ca,
		Vault:            v,
		Signer:           signer,
		Registry:         st.registry,
		Audit:            logger,
		Approver:         apr,
		ApprovalPatterns: approvals,
	})
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		return 1
	}
	if err := pr.Start(ctx); err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		return 1
	}
	defer pr.Stop(context.Background())

	caAbs, err := filepath.Abs(st.layout.CACert)
	if err != nil {
		caAbs = st.layout.CACert
	}

	// Wrap.
	exit, err := wrapper.Run(ctx, wrapper.Config{
		Command:        args[0],
		Args:           args[1:],
		Service:        svcName,
		Registry:       st.registry,
		Signer:         signer,
		ProxyURL:       pr.URL(),
		CACertPath:     caAbs,
		TTL:            *ttl,
		RotateInterval: *rotate,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Stdin:          os.Stdin,
		NodeShim:       *nodeShim,
	})
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate wrap:", err)
		if errors.Is(err, context.Canceled) {
			return 130 // SIGINT convention
		}
		return 1
	}
	return exit
}
