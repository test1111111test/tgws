package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFileWriter пишет логи в файл с автоматической ротацией по размеру
type RotatingFileWriter struct {
	path     string
	maxSize  int64 // в байтах
	maxFiles int
	file     *os.File
	size     int64
	mu       sync.Mutex
}

// NewRotatingFileWriter создаёт writer с ротацией
// maxSizeMB - максимальный размер файла в мегабайтах
// maxFiles - количество старых файлов для хранения
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

// Write реализует io.Writer
func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Проверяем нужна ли ротация
	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			// Логируем в stderr, чтобы не терять данные
			fmt.Fprintf(os.Stderr, "WARNING: log rotation failed: %v\n", err)
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate переименовывает текущий файл и создаёт новый
func (w *RotatingFileWriter) rotate() error {
	w.file.Close()

	// Сдвигаем существующие файлы: .3 -> .4, .2 -> .3, .1 -> .2
	for i := w.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		os.Rename(src, dst) // игнорируем ошибки (файл может не существовать)
	}

	// Переименовываем текущий в .1
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		// Если переименование не удалось, пробуем открыть новый файл
		return w.open()
	}

	// Удаляем самый старый файл если превысили лимит
	oldest := fmt.Sprintf("%s.%d", w.path, w.maxFiles+1)
	os.Remove(oldest)

	return w.open()
}

// Close закрывает файл
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Setup настраивает логирование в файл и/или консоль
// Возвращает Closer который нужно закрыть при завершении программы
// Если logFile пустой - только консольный вывод
func Setup(logFile string, maxSizeMB int, maxFiles int, toConsole bool) (io.Closer, error) {
	if logFile == "" {
		// Только консоль
		if !toConsole {
			log.SetOutput(io.Discard)
		}
		return nil, nil
	}

	writer, err := NewRotatingFileWriter(logFile, maxSizeMB, maxFiles)
	if err != nil {
		return nil, err
	}

	var output io.Writer
	if toConsole {
		output = io.MultiWriter(os.Stdout, writer)
	} else {
		output = writer
	}

	log.SetOutput(output)
	return writer, nil
}
