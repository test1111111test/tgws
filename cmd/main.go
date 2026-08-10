package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"tgws/internal/config"
	"tgws/internal/proxy"
)

const configFileName = "config.ini"

func main() {
	// Определяем путь к папке с exe
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
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

	// Ждём сигнала остановки
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	// Останавливаем сервер
	server.Stop()

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
