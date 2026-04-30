package cli

import "os"

// stdin is overridable for tests. Production reads from os.Stdin; cli_test
// sets this to a bytes.Buffer or strings.Reader before invoking subcommands
// that prompt.
var stdin = os.Stdin
