package config

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Host          string
	Port          int
	Secret        string
	BufferSize    int
	PoolSize      int
	DCRedirects   map[int]string
	ForceTestDC   bool
	MaskDomain    string
	FakeTLSDomain string
	LogFile       string
	LogMaxSize    int
	LogMaxFiles   int
	LogToConsole  bool
	Verbose       bool

	// CloudFlare fallback
	CFDomains        string
	CFAutoUpdate     bool
	CFUpdateURL      string
	CFUpdateInterval int
	CFFirst          bool
}

func DefaultConfig() *Config {
	secret := make([]byte, 16)
	rand.Read(secret)

	return &Config{
		Host:       "127.0.0.1",
		Port:       1443,
		Secret:     hex.EncodeToString(secret),
		BufferSize: 256 * 1024,
		PoolSize:   4,
		DCRedirects: map[int]string{
			2: "149.154.167.51",
			4: "149.154.167.91",
		},
		ForceTestDC:      false,
		MaskDomain:       "www.google.com",
		FakeTLSDomain:    "www.google.com",
		LogFile:          "tgws.log",
		LogMaxSize:       10,
		LogMaxFiles:      5,
		LogToConsole:     true,
		Verbose:          false,
		CFDomains:        "",
		CFAutoUpdate:     false,
		CFUpdateURL:      "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt",
		CFUpdateInterval: 3600,
		CFFirst:          false,
	}
}

func (c *Config) GenerateSecret() {
	secret := make([]byte, 16)
	rand.Read(secret)
	c.Secret = hex.EncodeToString(secret)
}

func (c *Config) EESecret() string {
	if c.FakeTLSDomain == "" {
		return ""
	}
	return "ee" + c.Secret + hex.EncodeToString([]byte(c.FakeTLSDomain))
}

// CFDomainList возвращает список доменов из конфига
func (c *Config) CFDomainList() []string {
	var out []string
	for _, d := range strings.Split(c.CFDomains, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func (c *Config) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

	// Пропускаем UTF-8 BOM если есть
	bom := make([]byte, 3)
	n, err := file.Read(bom)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read BOM: %w", err)
	}
	if n < 3 || bom[0] != 0xEF || bom[1] != 0xBB || bom[2] != 0xBF {
		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("config.ini:%d: invalid line format: %s", lineNum, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := c.setValue(key, value); err != nil {
			log.Printf("config.ini:%d: %v", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	return nil
}

func (c *Config) setValue(key, value string) error {
	switch strings.ToLower(key) {
	case "host":
		c.Host = value
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid port: %s", value)
		}
		c.Port = port
	case "secret":
		if value == "" {
			return nil
		}
		if len(value) != 32 {
			return fmt.Errorf("secret must be 32 hex characters, got %d", len(value))
		}
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("invalid secret hex: %s", value)
		}
		c.Secret = value
	case "buffer_size":
		size, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid buffer_size: %s", value)
		}
		c.BufferSize = size
	case "pool_size":
		size, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid pool_size: %s", value)
		}
		c.PoolSize = size
	case "force_test_dc":
		c.ForceTestDC = parseBool(value)
	case "dc_ip":
		if value != "" {
			c.DCRedirects = parseDCIPs(value)
		}
	case "mask_domain":
		c.MaskDomain = value
	case "fake_tls_domain":
		c.FakeTLSDomain = value
	case "log_file":
		c.LogFile = value
	case "log_max_size":
		size, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid log_max_size: %s", value)
		}
		c.LogMaxSize = size
	case "log_max_files":
		files, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid log_max_files: %s", value)
		}
		c.LogMaxFiles = files
	case "log_to_console":
		c.LogToConsole = parseBool(value)
	case "verbose":
		c.Verbose = parseBool(value)
	case "cf_domains":
		c.CFDomains = value
	case "cf_auto_update":
		c.CFAutoUpdate = parseBool(value)
	case "cf_update_url":
		c.CFUpdateURL = value
	case "cf_update_interval":
		sec, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid cf_update_interval: %s", value)
		}
		c.CFUpdateInterval = sec
	case "cf_first":
		c.CFFirst = parseBool(value)
	default:
		return fmt.Errorf("unknown parameter: %s", key)
	}
	return nil
}

func (c *Config) SaveToFile(filename string) error {
	var sb strings.Builder

	sb.WriteString("# ========================================\n")
	sb.WriteString("# Telegram MTProto WS Proxy Configuration\n")
	sb.WriteString("# ========================================\n\n")

	sb.WriteString("# Адрес для прослушивания\n")
	sb.WriteString("# 127.0.0.1 - только локально; 0.0.0.0 - слушать снаружи\n")
	sb.WriteString(fmt.Sprintf("host = %s\n\n", c.Host))

	sb.WriteString("# Порт для прослушивания\n")
	sb.WriteString(fmt.Sprintf("port = %d\n\n", c.Port))

	sb.WriteString("# MTProto secret (32 hex символа)\n")
	sb.WriteString("# Если пусто - будет сгенерирован автоматически\n")
	sb.WriteString(fmt.Sprintf("secret = %s\n\n", c.Secret))

	sb.WriteString("# Размер буфера сокета в байтах\n")
	sb.WriteString(fmt.Sprintf("buffer_size = %d\n\n", c.BufferSize))

	sb.WriteString("# Размер пула WebSocket соединений\n")
	sb.WriteString(fmt.Sprintf("pool_size = %d\n\n", c.PoolSize))

	sb.WriteString("# Принудительно использовать тестовые DC\n")
	sb.WriteString(fmt.Sprintf("force_test_dc = %v\n\n", c.ForceTestDC))

	sb.WriteString("# Домен для маскировки HTTP трафика\n")
	sb.WriteString(fmt.Sprintf("mask_domain = %s\n\n", c.MaskDomain))

	sb.WriteString("# Домен для Fake TLS (ee-secret)\n")
	sb.WriteString("# Если пусто - ee-secret и Fake TLS выключены\n")
	sb.WriteString(fmt.Sprintf("fake_tls_domain = %s\n\n", c.FakeTLSDomain))

	sb.WriteString("# ========================================\n")
	sb.WriteString("# Логирование\n")
	sb.WriteString("# ========================================\n\n")

	sb.WriteString("# Путь к файлу логов (пусто = только консоль)\n")
	sb.WriteString(fmt.Sprintf("log_file = %s\n\n", c.LogFile))

	sb.WriteString("# Максимальный размер файла логов в мегабайтах\n")
	sb.WriteString(fmt.Sprintf("log_max_size = %d\n\n", c.LogMaxSize))

	sb.WriteString("# Количество старых файлов логов для хранения\n")
	sb.WriteString(fmt.Sprintf("log_max_files = %d\n\n", c.LogMaxFiles))

	sb.WriteString("# Выводить ли логи в консоль\n")
	sb.WriteString(fmt.Sprintf("log_to_console = %v\n\n", c.LogToConsole))

	sb.WriteString("# Подробные пакетные логи (Splitter, дампы шифров)\n")
	sb.WriteString("# false = тихие логи (рекомендуется), true = для отладки\n")
	sb.WriteString(fmt.Sprintf("verbose = %v\n\n", c.Verbose))

	sb.WriteString("# ========================================\n")
	sb.WriteString("# CloudFlare fallback\n")
	sb.WriteString("# ========================================\n\n")

	sb.WriteString("# Свои CF worker-домены, через запятую\n")
	sb.WriteString("# Можно указывать с https:// и слэшами - приведётся к чистому домену\n")
	sb.WriteString(fmt.Sprintf("cf_domains = %s\n\n", c.CFDomains))

	sb.WriteString("# Автообновление списка CF доменов с URL\n")
	sb.WriteString("# false = использовать только cf_domains (рекомендуется,\n")
	sb.WriteString("# внешний список часто содержит мёртвые домены)\n")
	sb.WriteString(fmt.Sprintf("cf_auto_update = %v\n\n", c.CFAutoUpdate))

	sb.WriteString("# URL списка доменов (текст, по домену в строке)\n")
	sb.WriteString(fmt.Sprintf("cf_update_url = %s\n\n", c.CFUpdateURL))

	sb.WriteString("# Интервал обновления, сек (мин 60)\n")
	sb.WriteString(fmt.Sprintf("cf_update_interval = %d\n\n", c.CFUpdateInterval))

	sb.WriteString("# Пробовать CF ПЕРВЫМ маршрутом (для заблокированных сетей)\n")
	sb.WriteString("# false = гонка WS/CF и авто-детект мёртвого WS (рекомендуется)\n")
	sb.WriteString(fmt.Sprintf("cf_first = %v\n\n", c.CFFirst))

	sb.WriteString("# Редиректы DC (формат: DC:IP,DC:IP)\n")
	sb.WriteString(fmt.Sprintf("dc_ip = %s\n", formatDCIPs(c.DCRedirects)))

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

func ParseFlags() *Config {
	cfg := DefaultConfig()

	configFile := flag.String("config", "", "Path to config.ini file")
	host := flag.String("host", "", "Listen host (override config.ini)")
	port := flag.Int("port", 0, "Listen port (override config.ini)")
	secret := flag.String("secret", "", "MTProto secret (override config.ini)")
	bufferSize := flag.Int("buffer", 0, "Socket buffer size (override config.ini)")
	poolSize := flag.Int("pool", 0, "WebSocket pool size (override config.ini)")
	forceTestDC := flag.Bool("test-dc", false, "Force test DC mode (override config.ini)")
	dcIPs := flag.String("dc-ip", "", "DC redirects (override config.ini)")
	maskDomain := flag.String("mask-domain", "", "Mask domain for HTTP traffic (override config.ini)")
	fakeTLSDomain := flag.String("fake-tls-domain", "", "Fake TLS domain for ee-secret (override config.ini)")
	logFile := flag.String("log-file", "", "Log file path (override config.ini)")
	logMaxSize := flag.Int("log-max-size", 0, "Max log file size in MB (override config.ini)")
	logMaxFiles := flag.Int("log-max-files", 0, "Max old log files to keep (override config.ini)")

	flag.Parse()

	if *configFile != "" {
		if err := cfg.LoadFromFile(*configFile); err != nil {
			log.Printf("Warning: failed to load config from %s: %v", *configFile, err)
		} else {
			log.Printf("Config loaded from: %s", *configFile)
		}
	}

	if *host != "" {
		cfg.Host = *host
	}
	if *port != 0 {
		cfg.Port = *port
	}
	if *secret != "" {
		cfg.Secret = *secret
	}
	if *bufferSize != 0 {
		cfg.BufferSize = *bufferSize
	}
	if *poolSize != 0 {
		cfg.PoolSize = *poolSize
	}
	if *forceTestDC {
		cfg.ForceTestDC = true
	}
	if *dcIPs != "" {
		cfg.DCRedirects = parseDCIPs(*dcIPs)
	}
	if *maskDomain != "" {
		cfg.MaskDomain = *maskDomain
	}
	if *fakeTLSDomain != "" {
		cfg.FakeTLSDomain = *fakeTLSDomain
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}
	if *logMaxSize != 0 {
		cfg.LogMaxSize = *logMaxSize
	}
	if *logMaxFiles != 0 {
		cfg.LogMaxFiles = *logMaxFiles
	}

	return cfg
}

func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if len(c.Secret) != 32 {
		return fmt.Errorf("secret must be 32 hex characters, got %d", len(c.Secret))
	}
	if c.BufferSize < 4096 {
		return fmt.Errorf("buffer_size too small: %d", c.BufferSize)
	}
	if c.PoolSize < 0 {
		return fmt.Errorf("pool_size cannot be negative: %d", c.PoolSize)
	}
	if c.MaskDomain == "" {
		return fmt.Errorf("mask_domain cannot be empty")
	}
	if c.LogMaxSize < 1 {
		return fmt.Errorf("log_max_size must be at least 1 MB")
	}
	if c.LogMaxFiles < 1 {
		return fmt.Errorf("log_max_files must be at least 1")
	}
	return nil
}

func parseDCIPs(s string) map[int]string {
	result := make(map[int]string)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		dc, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil {
			continue
		}
		result[dc] = strings.TrimSpace(kv[1])
	}
	return result
}

func formatDCIPs(m map[int]string) string {
	parts := make([]string, 0, len(m))
	for dc, ip := range m {
		parts = append(parts, fmt.Sprintf("%d:%s", dc, ip))
	}
	return strings.Join(parts, ",")
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "on"
}
