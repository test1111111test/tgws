package config

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Host        string
	Port        int
	Secret      string
	BufferSize  int
	PoolSize    int
	DCRedirects map[int]string
	ForceTestDC bool
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
		ForceTestDC: false,
	}
}

func (c *Config) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

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

	return cfg
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "on"
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
			log.Printf("Invalid DC:IP format: %s", part)
			continue
		}
		dc, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil {
			log.Printf("Invalid DC number: %s", kv[0])
			continue
		}
		result[dc] = strings.TrimSpace(kv[1])
	}
	return result
}

func formatDCIPs(m map[int]string) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for dc := 1; dc <= 203; dc++ {
		if ip, ok := m[dc]; ok {
			parts = append(parts, fmt.Sprintf("%d:%s", dc, ip))
		}
	}
	return strings.Join(parts, ",")
}

func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if len(c.Secret) != 32 {
		return fmt.Errorf("secret must be 32 hex characters, got %d", len(c.Secret))
	}
	if _, err := hex.DecodeString(c.Secret); err != nil {
		return fmt.Errorf("invalid secret hex: %w", err)
	}
	if c.BufferSize < 4096 {
		return fmt.Errorf("buffer_size too small: %d", c.BufferSize)
	}
	if c.PoolSize < 0 {
		return fmt.Errorf("pool_size cannot be negative: %d", c.PoolSize)
	}
	return nil
}

func (c *Config) GenerateSecret() {
	secret := make([]byte, 16)
	rand.Read(secret)
	c.Secret = hex.EncodeToString(secret)
}

func (c *Config) String() string {
	return fmt.Sprintf("host=%s port=%d buffer=%d pool=%d test_dc=%v",
		c.Host, c.Port, c.BufferSize, c.PoolSize, c.ForceTestDC)
}
