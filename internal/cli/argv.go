package cli

import "strings"

// reorderArgs separates flags ("-x", "--y", "--y=z") from positional arguments
// so subcommands accept either order:
//
//	mcp-gate add github --token=ghp_xyz
//	mcp-gate add --token=ghp_xyz github
//
// Go's stdlib flag.Parse requires flags-first, which is hostile UX for a CLI
// where users naturally lead with the subject ("which service?"). Splitting
// before Parse fixes this with no special-cases.
//
// Limitation: the "--flag value" (space-separated) form is NOT supported here
// because we'd need to know which flags take values. We use only "--flag=value"
// in this CLI, so this trade-off is invisible to users.
func reorderArgs(argv []string) (flags, positional []string) {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			positional = append(positional, a)
		}
	}
	return flags, positional
}
