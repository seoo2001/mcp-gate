package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/seoo2001/mcp-gate/internal/audit"
)

// runLogs streams or filters the audit log.
func (a *App) runLogs(ctx context.Context, argv []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	service := fs.String("service", "", "filter by service")
	since := fs.Duration("since", 0, "only events newer than <dur> (e.g. 24h)")
	limit := fs.Int("limit", 100, "max rows to print (0 = unlimited)")
	asJSON := fs.Bool("json", false, "print as JSON lines instead of table")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	cutoff := time.Time{}
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}
	count := 0
	if !*asJSON {
		fmt.Fprintf(a.Out, "%-20s  %-7s  %-7s  %4s  %5s  %s\n", "time", "service", "method", "stat", "ms", "path")
	}
	err = audit.Iterate(st.layout.Audit, func(e audit.Event) bool {
		if *service != "" && e.Service != *service {
			return true
		}
		if !cutoff.IsZero() && time.Unix(e.TimestampUnix, 0).Before(cutoff) {
			return true
		}
		if *asJSON {
			b, _ := json.Marshal(e)
			a.Out.Write(b)
			a.Out.Write([]byte{'\n'})
		} else {
			fmt.Fprintf(a.Out, "%-20s  %-7s  %-7s  %4d  %5d  %s\n",
				time.Unix(e.TimestampUnix, 0).UTC().Format("2006-01-02 15:04:05"),
				safe(e.Service), safe(e.Method), e.Status, e.DurationMS, e.Path)
		}
		count++
		if *limit > 0 && count >= *limit {
			return false
		}
		return true
	})
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate logs:", err)
		return 1
	}
	if count == 0 && !*asJSON {
		fmt.Fprintln(a.Out, "(no events)")
	}
	return 0
}

func safe(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
