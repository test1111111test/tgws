//go:build windows

package gui

import (
	"log"
	"os"
	"syscall"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procAllocConsole = kernel32.NewProc("AllocConsole")
)

// AllocConsole создаёт консоль и подключает к ней stdout/stderr.
// Используется в GUI-сборке (windowsgui) при запуске с флагом --console.
func AllocConsole() {
	if r, _, _ := procAllocConsole.Call(); r == 0 {
		return
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err == nil {
		os.Stdout = out
		os.Stderr = out
		log.SetOutput(out)
	}
}
