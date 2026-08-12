package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// RotatingFileWriter пишет логи в файл с автоматической ротацией по размеру
type RotatingFileWriter struct {
	path     string
	maxSize  int64
	maxFiles int
	file     *os.File
	size     int64
	mu       sync.Mutex
}

func NewRotatingFileWriter(path string, maxSizeMB int, maxFiles int) (*RotatingFileWriter, error) {
	if maxSizeMB < 1 {
		maxSizeMB = 10
	}
	if maxFiles < 1 {
		maxFiles = 5
	}

	w := &RotatingFileWriter{
		path:     path,
		maxSize:  int64(maxSizeMB) * 1024 * 1024,
		maxFiles: maxFiles,
	}

	if err := w.open(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *RotatingFileWriter) open() error {
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}

	w.file = f
	w.size = info.Size()
	return nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: log rotation failed: %v\n", err)
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) rotate() error {
	w.file.Close()

	for i := w.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		os.Rename(src, dst)
	}

	if err := os.Rename(w.path, w.path+".1"); err != nil {
		return w.open()
	}

	oldest := fmt.Sprintf("%s.%d", w.path, w.maxFiles+1)
	os.Remove(oldest)

	return w.open()
}

func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// swallowWriter игнорирует ошибки записи (для stdout в GUI-сборке без консоли)
type swallowWriter struct {
	w io.Writer
}

func (s swallowWriter) Write(p []byte) (int, error) {
	_, _ = s.w.Write(p)
	return len(p), nil
}

// quietSubstr — строки, скрываемые при verbose=false (пакетный шум)
var quietSubstr = []string{
	"Splitter:",
	"↑ PLAINTEXT",
	"↑ TG_CIPHER",
	"↑ SPLITTER",
	"↑ FIRST from client",
	"↓ PLAINTEXT",
	"↓ CLIENT_CIPHER",
	"↓ FIRST from DC",
	"sending relay_init",
}

// filterWriter отбрасывает шумные отладочные строки, когда verbose выключен
type filterWriter struct {
	inner   io.Writer
	verbose bool
}

func (f *filterWriter) Write(p []byte) (int, error) {
	if !f.verbose {
		s := string(p)
		for _, sub := range quietSubstr {
			if strings.Contains(s, sub) {
				return len(p), nil
			}
		}
	}
	return f.inner.Write(p)
}

// Setup настраивает логирование в файл и/или консоль с учётом verbose.
// Файл пишется ПЕРВЫМ, ошибки stdout игнорируются — поэтому логи работают
// и в GUI-сборке без консоли (windowsgui), и в обычной консольной.
func Setup(logFile string, maxSizeMB int, maxFiles int, toConsole bool, verbose bool) (io.Closer, error) {
	console := swallowWriter{os.Stdout}

	var base io.Writer
	var closer io.Closer

	if logFile == "" {
		base = console
	} else {
		writer, err := NewRotatingFileWriter(logFile, maxSizeMB, maxFiles)
		if err != nil {
			return nil, err
		}
		closer = writer
		if toConsole {
			// файл первым: даже если stdout мёртвый (GUI-сборка), файл получит данные
			base = io.MultiWriter(writer, console)
		} else {
			base = writer
		}
	}

	log.SetOutput(&filterWriter{inner: base, verbose: verbose})
	return closer, nil
}
