package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"tgws/internal/config"
	"tgws/internal/gui"
	"tgws/internal/proxy"
)

const configFileName = "config.ini"

func main() {
	noGUI := flag.Bool("no-gui", false, "Запуск без системного трея (фоновый режим)")
	dumpIcon := flag.Bool("dump-icon", false, "Записать icon.ico рядом с exe и выйти")
	flag.Parse()

	// Определяем путь к папке с exe
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// Если просят — выписываем иконку и выходим
	if *dumpIcon {
		out := filepath.Join(exeDir, "icon.ico")
		if err := os.WriteFile(out, gui.GenerateIcon(), 0644); err != nil {
			log.Fatalf("Failed to write icon: %v", err)
		}
		log.Printf("Icon written to %s", out)
		return
	}

	configPath := filepath.Join(exeDir, configFileName)

	// Загружаем или создаём конфигурацию
	cfg := loadOrCreateConfig(configPath)

	// Валидируем
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// Создаём сервер
	server, err := proxy.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Запускаем сервер
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("Server started successfully")
	log.Printf("Config file: %s", configPath)

	// Канал для сигналов остановки
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	useGUI := !*noGUI && runtime.GOOS == "windows"

	if useGUI {
		log.Println("Starting with system tray...")

		// Обработчик сигналов в фоне (Ctrl+C завершает процесс)
		go func() {
			sig := <-sigChan
			log.Printf("Received signal %v, shutting down...", sig)
			server.Stop()
			gui.Quit()
		}()

		// systray.Run блокирует main goroutine (требование Windows)
		tray := gui.NewTrayManager(cfg, server)
		tray.Run()

		// Сюда попадаем после "Выход" из трея — процесс завершится (exe выгрузится)
		server.Stop()
	} else {
		// Фоновый режим — ждём сигнала
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		server.Stop()
	}

	server.CloseLog()
	log.Printf("Server stopped")
}

// loadOrCreateConfig загружает конфиг или создаёт новый
func loadOrCreateConfig(path string) *config.Config {
	cfg := config.DefaultConfig()

	// Проверяем существование файла
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Файл не существует - создаём с параметрами по умолчанию
		log.Printf("Config file not found, creating: %s", path)
		// Генерируем новый secret для нового конфига
		cfg.GenerateSecret()
		if err := cfg.SaveToFile(path); err != nil {
			log.Printf("Warning: failed to save config file: %v", err)
		} else {
			log.Printf("Config file created with default settings")
		}
		return cfg
	}

	// Файл существует - загружаем
	log.Printf("Loading config from: %s", path)
	if err := cfg.LoadFromFile(path); err != nil {
		log.Printf("Warning: failed to load config: %v", err)
		log.Printf("Using default configuration")
		return config.DefaultConfig()
	}

	// Если secret пустой в файле - генерируем и сохраняем
	if cfg.Secret == "" {
		cfg.GenerateSecret()
		log.Printf("Generated new secret: %s", cfg.Secret)
		if err := cfg.SaveToFile(path); err != nil {
			log.Printf("Warning: failed to save generated secret: %v", err)
		}
	}

	return cfg
}
