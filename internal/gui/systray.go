package gui

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/getlantern/systray"

	"tgws/internal/config"
	"tgws/internal/proxy"
	"tgws/internal/stats"
)

// TrayManager управляет системным треем
type TrayManager struct {
	cfg    *config.Config
	server *proxy.Server

	status *systray.MenuItem
	toggle *systray.MenuItem

	// Инфо-пункты с живыми метриками
	mConn    *systray.MenuItem
	mTraffic *systray.MenuItem
	mRoutes  *systray.MenuItem
	mErr     *systray.MenuItem
}

// NewTrayManager создаёт менеджер трея
func NewTrayManager(cfg *config.Config, server *proxy.Server) *TrayManager {
	return &TrayManager{cfg: cfg, server: server}
}

// Run запускает трей. БЛОКИРУЕТ текущую goroutine — вызывайте из main.
func (m *TrayManager) Run() {
	systray.Run(m.onReady, m.onExit)
}

// Quit закрывает трей из любой goroutine
func Quit() {
	systray.Quit()
}

func (m *TrayManager) onReady() {
	systray.SetIcon(GenerateIcon())
	systray.SetTitle("TGWS Proxy")
	systray.SetTooltip(m.tooltip())

	if m.server.IsRunning() {
		m.status = systray.AddMenuItem("● Работает", "Состояние прокси")
	} else {
		m.status = systray.AddMenuItem("○ Остановлен", "Состояние прокси")
	}
	m.status.Disable()
	systray.AddSeparator()

	if m.server.IsRunning() {
		m.toggle = systray.AddMenuItem("■ Остановить", "Остановить прокси (программа остаётся в трее)")
	} else {
		m.toggle = systray.AddMenuItem("▶ Запустить", "Запустить прокси")
	}

	mShowLinks := systray.AddMenuItem("Скопировать ссылку подключения", "Скопировать ссылку Telegram в буфер обмена")
	mStats := systray.AddMenuItem("Статистика", "Показать статистику")
	systray.AddSeparator()

	m.mConn = systray.AddMenuItem("Подключений: 0 (активно 0)", "Счётчик подключений")
	m.mTraffic = systray.AddMenuItem("Трафик: ↑0B ↓0B", "Трафик и скорость")
	m.mRoutes = systray.AddMenuItem("Маршруты: WS 0 | CF 0 | TCP 0", "Какой маршрут используется")
	m.mErr = systray.AddMenuItem("Ошибки: WS 0 | CF 0 | bad 0", "Счётчик ошибок")
	for _, mi := range []*systray.MenuItem{m.mConn, m.mTraffic, m.mRoutes, m.mErr} {
		mi.Disable()
	}
	systray.AddSeparator()

	mOpenConfig := systray.AddMenuItem("Открыть config.ini", "Открыть конфигурацию в Блокноте")
	mOpenLogs := systray.AddMenuItem("Открыть папку с логами", "Открыть папку с файлами логов")
	mDumpIcon := systray.AddMenuItem("Сохранить icon.ico", "Записать icon.ico рядом с exe")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Выход", "Остановить прокси и закрыть программу")

	m.startMetricsUpdater()

	go func() {
		for {
			select {
			case <-m.toggle.ClickedCh:
				m.onToggle()
			case <-mShowLinks.ClickedCh:
				m.copyLinks()
			case <-mStats.ClickedCh:
				m.showStats()
			case <-mOpenConfig.ClickedCh:
				m.openConfig()
			case <-mOpenLogs.ClickedCh:
				m.openLogs()
			case <-mDumpIcon.ClickedCh:
				m.dumpIcon()
			case <-mQuit.ClickedCh:
				log.Println("Выход запрошен из системного трея")
				m.server.Stop()
				systray.Quit()
				return
			}
		}
	}()
}

func (m *TrayManager) onExit() {
	log.Println("System tray exited")
}

// startMetricsUpdater раз в 5 секунд обновляет метрики в меню и тултипе
func (m *TrayManager) startMetricsUpdater() {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()

		prevUp, prevDown := stats.S.UpBytes(), stats.S.DownBytes()
		prevT := time.Now()

		for range t.C {
			up, down := stats.S.UpBytes(), stats.S.DownBytes()
			now := time.Now()
			dt := now.Sub(prevT).Seconds()

			var upRate, downRate float64
			if dt > 0 {
				upRate = float64(up-prevUp) / dt
				downRate = float64(down-prevDown) / dt
			}
			prevUp, prevDown, prevT = up, down, now

			m.mConn.SetTitle(fmt.Sprintf("Подключений: %d (активно %d)",
				stats.S.Total(), stats.S.Active()))
			m.mTraffic.SetTitle(fmt.Sprintf("Трафик: ↑%s ↓%s | %s / %s",
				humanB(up), humanB(down), rateStr(upRate), rateStr(downRate)))
			m.mRoutes.SetTitle(fmt.Sprintf("Маршруты: WS %d | CF %d | TCP %d",
				stats.S.ViaWS(), stats.S.ViaCF(), stats.S.ViaTCP()))
			m.mErr.SetTitle(fmt.Sprintf("Ошибки: WS %d | CF %d | bad %d",
				stats.S.WSErr(), stats.S.CFErr(), stats.S.Bad()))

			systray.SetTooltip(fmt.Sprintf("TGWS | %s | act=%d | ↑%s ↓%s",
				durStr(stats.S.Uptime()), stats.S.Active(), humanB(up), humanB(down)))
		}
	}()
}

func (m *TrayManager) onToggle() {
	if m.server.IsRunning() {
		m.server.Stop()
		m.toggle.SetTitle("▶ Запустить")
		m.status.SetTitle("○ Остановлен")
		systray.SetTooltip(m.tooltip())
		log.Println("Прокси остановлен (программа в трее)")
	} else {
		if err := m.server.Start(); err != nil {
			log.Printf("Не удалось запустить сервер: %v", err)
			systray.SetTooltip("Ошибка запуска!")
			return
		}
		m.toggle.SetTitle("■ Остановить")
		m.status.SetTitle("● Работает")
		systray.SetTooltip(m.tooltip())
		log.Println("Прокси запущен")
	}
}

func (m *TrayManager) showStats() {
	log.Println("Stats requested from tray")
	report := stats.S.Report()
	log.Println(report)

	systray.SetTooltip(stats.S.Short())

	go showMessageBox(report, "TGWS Proxy - статистика")

	go func() {
		time.Sleep(5 * time.Second)
		systray.SetTooltip(m.tooltip())
	}()
}

func showMessageBox(text, title string) {
	if runtime.GOOS != "windows" {
		return
	}
	script := fmt.Sprintf("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show(@'\n%s\n'@, '%s')", text, title)
	if err := exec.Command("powershell", "-NoProfile", "-Command", script).Start(); err != nil {
		log.Printf("Не удалось показать окно статистики: %v", err)
	}
}

func (m *TrayManager) tooltip() string {
	if m.server.IsRunning() {
		return fmt.Sprintf("TGWS Proxy | %s:%d | работает", m.cfg.Host, m.cfg.Port)
	}
	return "TGWS Proxy | остановлен"
}

func (m *TrayManager) copyLinks() {
	link := fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=dd%s",
		m.cfg.Host, m.cfg.Port, m.cfg.Secret)

	if m.cfg.FakeTLSDomain != "" {
		link += "\n" + fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s",
			m.cfg.Host, m.cfg.Port, m.cfg.EESecret())
	}

	if err := copyToClipboard(link); err != nil {
		log.Printf("Не удалось скопировать: %v", err)
		systray.SetTooltip("Ошибка копирования!")
		return
	}

	log.Printf("Ссылки подключения скопированы в буфер обмена")
	systray.SetTooltip("Ссылки скопированы!")

	go func() {
		time.Sleep(3 * time.Second)
		systray.SetTooltip(m.tooltip())
	}()
}

func (m *TrayManager) openConfig() {
	configPath := filepath.Join(exeDir(), "config.ini")
	if err := openInEditor(configPath); err != nil {
		log.Printf("Не удалось открыть конфиг: %v", err)
	}
}

func (m *TrayManager) openLogs() {
	if err := openInExplorer(exeDir()); err != nil {
		log.Printf("Не удалось открыть папку с логами: %v", err)
	}
}

func (m *TrayManager) dumpIcon() {
	out := filepath.Join(exeDir(), "icon.ico")
	if err := os.WriteFile(out, GenerateIcon(), 0644); err != nil {
		log.Printf("Не удалось сохранить иконку: %v", err)
		return
	}
	log.Printf("Иконка сохранена: %s", out)
	systray.SetTooltip("icon.ico сохранён!")
	go func() {
		time.Sleep(3 * time.Second)
		systray.SetTooltip(m.tooltip())
	}()
}

func humanB(n int64) string {
	v := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if v < 1024 {
			return fmt.Sprintf("%.1f%s", v, u)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1fTB", v)
}

func rateStr(bps float64) string {
	if bps < 0 {
		bps = 0
	}
	v := bps
	for _, u := range []string{"B/s", "KB/s", "MB/s"} {
		if v < 1024 {
			return fmt.Sprintf("%.1f%s", v, u)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1fGB/s", v)
}

func durStr(d time.Duration) string { return d.Round(time.Second).String() }

func copyToClipboard(text string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("clipboard supported only on Windows")
	}
	cmd := exec.Command("powershell", "-command",
		fmt.Sprintf("Set-Clipboard -Value '%s'", escapePS(text)))
	return cmd.Run()
}

func openInEditor(path string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("notepad.exe", path).Start()
	}
	return fmt.Errorf("open editor not supported on %s", runtime.GOOS)
}

func openInExplorer(path string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("explorer.exe", path).Start()
	}
	return fmt.Errorf("open explorer not supported on %s", runtime.GOOS)
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func escapePS(s string) string {
	result := ""
	for _, c := range s {
		if c == '\'' {
			result += "''"
		} else {
			result += string(c)
		}
	}
	return result
}
