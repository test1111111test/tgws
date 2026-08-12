//go:build !windows

package gui

// AllocConsole заглушка для не-Windows платформ
func AllocConsole() {}
