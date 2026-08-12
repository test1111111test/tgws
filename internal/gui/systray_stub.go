//go:build !windows

package gui

import (
	"tgws/internal/config"
	"tgws/internal/proxy"
)

// TrayManager — заглушка для не-Windows платформ.
// На Linux прокси работает headless: управление через сигналы (Ctrl+C),
// логи в stdout/файл. Трей не используется.
type TrayManager struct {
	cfg    *config.Config
	server *proxy.Server
	quit   chan struct{}
}

// NewTrayManager создаёт заглушку
func NewTrayManager(cfg *config.Config, server *proxy.Server) *TrayManager {
	return &TrayManager{cfg: cfg, server: server, quit: make(chan struct{})}
}

// Run блокирует до Quit (на Linux из main не вызывается)
func (m *TrayManager) Run() {
	<-m.quit
}

// Quit — заглушка
func Quit() {}
