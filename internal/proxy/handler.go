package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"tgws/internal/bridge"
	"tgws/internal/config"
	"tgws/internal/crypto"
	"tgws/internal/fake_tls"
)

type Handler struct {
	cfg    *config.Config
	secret []byte
}

type HandshakeInfo struct {
	DC, ProtoInt      uint32
	IsMedia, IsTestDC bool
	TargetIP          string
	WSDomains         []string
	WSPath            string
	RelayInit         []byte
	CryptoCtx         *crypto.CryptoContext
	DCInt             int
}

func NewHandler(cfg *config.Config, secret []byte) *Handler {
	return &Handler{cfg: cfg, secret: secret}
}

// ReadClientInit читает init packet от клиента
// Поддерживает оба режима одновременно:
// - Если пришёл TLS ClientHello -> Fake TLS режим (ee-secret)
// - Иначе -> обычный dd-secret режим (независимо от masking)
// - HTTP/HTTP2/TLS Alert -> masking
func (h *Handler) ReadClientInit(conn net.Conn, label string) ([]byte, bridge.ClientConn, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, firstByte); err != nil {
		return nil, nil, fmt.Errorf("read first byte: %w", err)
	}

	masking := h.cfg.FakeTLSDomain != ""

	// === РЕЖИМ 1: Fake TLS (ee-secret) ===
	// Первый байт 0x16 = TLS handshake record
	if firstByte[0] == fake_tls.TLSRecordHandshake {
		hdrRest := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdrRest); err != nil {
			return nil, nil, fmt.Errorf("read TLS header: %w", err)
		}
		tlsHeader := append(firstByte, hdrRest...)
		recLen := int(binary.BigEndian.Uint16(tlsHeader[3:5]))

		if recLen < 1 || recLen > 65535 {
			log.Printf("[%s] invalid TLS record length: %d -> masking", label, recLen)
			go h.mask(conn, tlsHeader, label)
			return nil, nil, fmt.Errorf("invalid TLS record length")
		}

		recordBody := make([]byte, recLen)
		if _, err := io.ReadFull(conn, recordBody); err != nil {
			return nil, nil, fmt.Errorf("read TLS body: %w", err)
		}
		clientHello := append(tlsHeader, recordBody...)

		if !masking {
			// Fake TLS выключен — отвечаем TLS Alert и закрываем
			log.Printf("[%s] TLS ClientHello (Fake TLS disabled), rejecting", label)
			h.HandleTLSMasking(conn, label)
			return nil, nil, fmt.Errorf("TLS traffic without Fake TLS enabled")
		}

		result, err := fake_tls.VerifyClientHello(clientHello, h.secret)
		if err != nil {
			// Невалидный ClientHello -> перенаправляем на реальный сайт (маскировка)
			log.Printf("[%s] Fake TLS verify failed -> masking to %s: %v",
				label, h.cfg.MaskDomain, err)
			go fake_tls.ProxyToMaskingDomain(conn, clientHello, h.cfg.MaskDomain, label)
			return nil, nil, fmt.Errorf("fake TLS verify failed: %w", err)
		}

		log.Printf("[%s] ✓ Fake TLS handshake OK (ts=%d)", label, result.Timestamp)

		serverHello := fake_tls.BuildServerHello(h.secret, result.ClientRandom, result.SessionID)
		if _, err := conn.Write(serverHello); err != nil {
			return nil, nil, fmt.Errorf("write server hello: %w", err)
		}

		// Дальше весь трафик идёт внутри TLS records
		stream := fake_tls.NewFakeTlsStream(conn)
		handshake, err := stream.ReadExactly(crypto.HandshakeLen)
		if err != nil {
			return nil, nil, fmt.Errorf("read handshake from TLS: %w", err)
		}
		return handshake, stream, nil
	}

	// === РЕЖИМ 2: HTTP/HTTP2/TLS Alert с masking -> redirect ===
	if masking {
		switch firstByte[0] {
		case 'G', 'P', 'H', 'D', 'O': // GET, POST, HEAD, DELETE, OPTIONS
			log.Printf("[%s] HTTP traffic '%c' -> redirect to %s", label, firstByte[0], h.cfg.MaskDomain)
			redirect := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", h.cfg.MaskDomain)
			conn.Write([]byte(redirect))
			return nil, nil, fmt.Errorf("HTTP traffic with masking")

		case 0x15: // TLS Alert
			log.Printf("[%s] TLS Alert -> masking", label)
			go h.mask(conn, firstByte, label)
			return nil, nil, fmt.Errorf("TLS alert")

		case 0x14: // TLS Change Cipher Spec (не ClientHello)
			log.Printf("[%s] TLS CCS -> masking", label)
			go h.mask(conn, firstByte, label)
			return nil, nil, fmt.Errorf("TLS CCS")
		}
		// Приоритет: HTTP/2 (PRI)
		if firstByte[0] == 'P' {
			// Уже обработано выше
		}
	}

	// === РЕЖИМ 3: Обычный MTProto (dd-secret) ===
	// Читаем оставшиеся 63 байта handshake
	rest := make([]byte, crypto.HandshakeLen-1)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, nil, fmt.Errorf("read handshake: %w", err)
	}
	handshake := append(firstByte, rest...)

	// Проверяем, не похож ли это на HTTP
	if masking && isHTTPStart(handshake) {
		log.Printf("[%s] HTTP-like handshake -> redirect", label)
		redirect := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", h.cfg.MaskDomain)
		conn.Write([]byte(redirect))
		return nil, nil, fmt.Errorf("HTTP-like traffic")
	}

	log.Printf("[%s] → dd-secret mode (first byte: 0x%02x)", label, firstByte[0])
	return handshake, conn, nil
}

// mask перенаправляет на masking domain
func (h *Handler) mask(conn net.Conn, initial []byte, label string) {
	if h.cfg.MaskDomain == "" {
		conn.Close()
		return
	}
	fake_tls.ProxyToMaskingDomain(conn, initial, h.cfg.MaskDomain, label)
}

// isHTTPStart проверяет, похожи ли байты на HTTP запрос
func isHTTPStart(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	first4 := string(data[:4])
	return first4 == "GET " || first4 == "POST" || first4 == "HEAD" ||
		first4 == "PUT " || first4 == "DELE" || first4 == "OPTI" ||
		first4 == "PATC" || first4 == "TRAC" || first4 == "PRI "
}

// HandleHandshake обрабатывает MTProto handshake
func (h *Handler) HandleHandshake(handshake []byte, label string) (*HandshakeInfo, error) {
	result, err := crypto.TryHandshake(handshake, h.secret)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	dc := result.DC
	isTest := h.cfg.ForceTestDC || dc >= 10000
	if dc >= 10000 {
		dc -= 10000
	}

	targetIP := h.cfg.DCRedirects[dc]
	if targetIP == "" {
		if isTest {
			targetIP = crypto.DCTestIPs[dc]
		} else {
			targetIP = crypto.DCDefaultIPs[dc]
		}
	}

	dcIdx := dc
	if result.IsMedia {
		dcIdx = -dc
	}
	relayInit, err := crypto.GenerateRelayInit(result.ProtoTag, dcIdx)
	if err != nil {
		return nil, fmt.Errorf("generate relay init: %w", err)
	}

	ctx, err := crypto.BuildCryptoContext(result.ClientDecPrekeyIV, h.secret, relayInit)
	if err != nil {
		return nil, fmt.Errorf("build crypto context: %w", err)
	}

	wsPath := crypto.WSPath
	if isTest {
		wsPath = crypto.WSPathTest
	}

	mt := ""
	if result.IsMedia {
		mt = " (media)"
	}
	log.Printf("[%s] handshake OK: DC%d%s proto=0x%08X -> %s",
		label, dc, mt, result.ProtoInt, targetIP)

	return &HandshakeInfo{
		DC:        uint32(dc),
		IsMedia:   result.IsMedia,
		IsTestDC:  isTest,
		ProtoInt:  result.ProtoInt,
		TargetIP:  targetIP,
		WSDomains: crypto.WSDomains(dc, result.IsMedia),
		WSPath:    wsPath,
		RelayInit: relayInit,
		CryptoCtx: ctx,
		DCInt:     dc,
	}, nil
}

// HandleTLSMasking отвечает TLS Alert
func (h *Handler) HandleTLSMasking(conn net.Conn, label string) {
	alert := []byte{
		0x15, 0x03, 0x01, 0x00, 0x02,
		0x02, 0x28,
	}
	conn.Write(alert)
	log.Printf("[%s] → TLS ClientHello rejected", label)
}
