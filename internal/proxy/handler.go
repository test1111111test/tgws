package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"tgws/internal/config"
	"tgws/internal/crypto"
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
	EncMode           int
}

func NewHandler(cfg *config.Config, secret []byte) *Handler {
	return &Handler{cfg: cfg, secret: secret}
}

func (h *Handler) HandleHandshake(conn net.Conn, label string) (*HandshakeInfo, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, crypto.HandshakeLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read handshake: %w", err)
	}

	trafficType := detectTrafficType(buf)
	if !strings.HasPrefix(trafficType, "MTProto") {
		if strings.Contains(trafficType, "HTTP") {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		}
		return nil, fmt.Errorf("not MTProto traffic: %s", trafficType)
	}

	result, err := crypto.TryHandshake(buf, h.secret)
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

	// Чередование режимов clt_enc
	mode := crypto.NextMode()
	log.Printf("[%s] using clt_enc mode=%d", label, mode)

	ctx, err := crypto.BuildCryptoContext(result.ClientDec, result.ClientDecPrekeyIV, h.secret, relayInit, mode)
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
		DC: uint32(dc), IsMedia: result.IsMedia, IsTestDC: isTest,
		ProtoInt: result.ProtoInt, TargetIP: targetIP,
		WSDomains: crypto.WSDomains(dc, result.IsMedia),
		WSPath:    wsPath, RelayInit: relayInit, CryptoCtx: ctx, DCInt: dc,
		EncMode: mode,
	}, nil
}

func detectTrafficType(data []byte) string {
	if len(data) < 4 {
		return "unknown (too short)"
	}
	first4 := string(data[:4])
	if first4 == "GET " || first4 == "POST" || first4 == "HEAD" || first4 == "PUT " {
		return "HTTP request"
	}
	if data[0] == 0x16 && data[1] == 0x03 {
		return "TLS ClientHello"
	}
	if len(data) >= 3 && string(data[:3]) == "PRI" {
		return "HTTP/2"
	}
	return "MTProto"
}
