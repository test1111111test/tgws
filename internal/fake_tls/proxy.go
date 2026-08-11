package fake_tls

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ProxyToMaskingDomain перенаправляет невалидный TLS трафик на реальный сайт
// Это делает прокси невидимым: сканеры видят обычный HTTPS сайт
func ProxyToMaskingDomain(clientConn net.Conn, initialData []byte, domain string, label string) {
	defer clientConn.Close()

	// Подключаемся к реальному сайту
	upConn, err := net.DialTimeout("tcp", domain+":443", 10*time.Second)
	if err != nil {
		log.Printf("[%s] masking: cannot connect to %s:443: %v", label, domain, err)
		return
	}
	defer upConn.Close()

	log.Printf("[%s] masking -> %s:443", label, domain)

	// Отправляем начальные данные (ClientHello)
	if len(initialData) > 0 {
		if _, err := upConn.Write(initialData); err != nil {
			log.Printf("[%s] masking: write initial failed: %v", label, err)
			return
		}
	}

	// Двунаправленная передача
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> upstream
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				if _, werr := upConn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// upstream -> client
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := upConn.Read(buf)
			if n > 0 {
				if _, werr := clientConn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	_ = io.EOF
}
