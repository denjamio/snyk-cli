//go:build windows

package output

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	procGetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleMode")
)

// isTerminal asks GetConsoleMode, which succeeds only on console handles —
// pipes, regular files and the NUL device fail.
func isTerminal(f *os.File) bool {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(f.Fd(), uintptr(unsafe.Pointer(&mode)))
	return r != 0
}
