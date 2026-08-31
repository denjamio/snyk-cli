//go:build !linux && !darwin && !windows

package output

import "os"

// isTerminal falls back to the ModeCharDevice heuristic on platforms
// without a known terminal probe; character devices like /dev/null may
// still be mistaken for terminals there.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
