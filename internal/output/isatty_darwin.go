//go:build darwin

package output

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal performs a TIOCGETA ioctl, which succeeds only on real
// terminals — not on pipes, regular files or character devices like
// /dev/null.
func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCGETA,
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return errno == 0
}
