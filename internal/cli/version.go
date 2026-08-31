package cli

import (
	"fmt"

	"github.com/denjamio/snyk-cli/internal/output"
)

// runVersion prints the CLI version: plain text for humans, or a JSON
// envelope with --json so agents read it without parsing prose — the same
// structured-output rule as every other command.
func runVersion(args []string, s Streams) int {
	cmd, code := parseCommand(versionSpec, args, s)
	if cmd == nil {
		return code
	}
	if code := cmd.rejectPositional(s); code != 0 {
		return code
	}
	if !cmd.flags.getBool("json") {
		fmt.Fprintln(s.Out, "snyk "+Version)
		return 0
	}
	if err := output.WriteJSON(s.Out, output.Envelope{
		OK:      true,
		Command: "version",
		Data:    map[string]any{"version": Version},
	}); err != nil {
		fmt.Fprintln(s.Err, "error:", err)
		return 1
	}
	return 0
}
