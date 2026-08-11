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

	// Статус (неактивный пункт)
	if m.server.IsRunning() {
		m.status = systray.AddMenuItem("● Работает", "Состояние прокси")
	} else {
		m.status = systray.AddMenuItem("○ Остановлен", "Состояние прокси")
	}
	m.status.Disable()
	systray.AddSeparator()

	// СТАРТ / СТОП без выгрузки exe
	if m.server.IsRunning() {
		m.toggle = systray.AddMenuItem("■ Остановить", "Остановить прокси (программа остаётся в трее)")
	} else {
		m.toggle = systray.AddMenuItem("▶ Запустить", "Запустить прокси")
	}

	mShowLinks := systray.AddMenuItem("Скопировать ссылку подключения", "Скопировать ссылку Telegram в буфер обмена")
	mStats := systray.AddMenuItem("Статистика", "Показать статистику")
	mOpenConfig := systray.AddMenuItem("Открыть config.ini", "Открыть конфигурацию в Блокноте")
	mOpenLogs := systray.AddMenuItem("Открыть папку с логами", "Открыть папку с файлами логов")
	mDumpIcon := systray.AddMenuItem("Сохранить icon.ico", "Записать icon.ico рядом с exe")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Выход", "Остановить прокси и закрыть программу")

	// Цикл обработки событий
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

// onToggle переключает СТАРТ/СТОП сервера без выгрузки exe
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

// showStats выводит статистику: в лог, в тултип и во всплывающее окно
func (m *TrayManager) showStats() {
	log.Println("Stats requested from tray")
	report := stats.S.Report()
	log.Println(report)

	systray.SetTooltip(stats.S.Short())

	// Видимое всплывающее окно — чтобы результат был заметен сразу
	go showMessageBox(report, "TGWS Proxy - статистика")

	go func() {
		time.Sleep(5 * time.Second)
		systray.SetTooltip(m.tooltip())
	}()
}

// showMessageBox показывает Windows MessageBox через PowerShell
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

// copyLinks копирует ссылки подключения в буфер обмена
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

// openConfig открывает config.ini в Блокноте
func (m *TrayManager) openConfig() {
	configPath := filepath.Join(exeDir(), "config.ini")
	if err := openInEditor(configPath); err != nil {
		log.Printf("Не удалось открыть конфиг: %v", err)
	}
}

// openLogs открывает папку с логами в проводнике
func (m *TrayManager) openLogs() {
	if err := openInExplorer(exeDir()); err != nil {
		log.Printf("Не удалось открыть папку с логами: %v", err)
	}
}

// dumpIcon выписывает icon.ico рядом с exe
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

// copyToClipboard копирует текст в буфер обмена (Windows)
func copyToClipboard(text string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("clipboard supported only on Windows")
	}
	cmd := exec.Command("powershell", "-command",
		fmt.Sprintf("Set-Clipboard -Value '%s'", escapePS(text)))
	return cmd.Run()
}

// openInEditor открывает файл в Блокноте
func openInEditor(path string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("notepad.exe", path).Start()
	}
	return fmt.Errorf("open editor not supported on %s", runtime.GOOS)
}

// openInExplorer открывает папку в проводнике
func openInExplorer(path string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("explorer.exe", path).Start()
	}
	return fmt.Errorf("open explorer not supported on %s", runtime.GOOS)
}

// exeDir возвращает путь к папке с exe
func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

// escapePS экранирует одинарные кавычки для PowerShell
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
