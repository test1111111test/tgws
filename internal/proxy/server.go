package proxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"tgws/internal/bridge"
	"tgws/internal/config"
	"tgws/internal/pool"
	"tgws/internal/websocket"
)

type Server struct {
	cfg      *config.Config
	listener net.Listener
	wsPool   *pool.Pool
	secret   []byte
	mu       sync.Mutex
	active   map[string]context.CancelFunc
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewServer(cfg *config.Config) (*Server, error) {
	secret, err := hex.DecodeString(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:    cfg,
		wsPool: pool.NewPool(cfg.PoolSize, 120*time.Second),
		secret: secret,
		active: make(map[string]context.CancelFunc),
		ctx:    ctx,
		cancel: cancel,
	}
	s.wsPool.SetConnectFunc(s.connectWS)
	return s, nil
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = l

	log.Println(strings.Repeat("=", 60))
	log.Println("  Telegram MTProto WS Bridge Proxy (Go)")
	log.Printf("  Listening on   %s", addr)
	log.Printf("  Secret:        %s", s.cfg.Secret)
	log.Printf("  Secret (dd):   dd%s", s.cfg.Secret)
	log.Printf("  Pool size:     %d", s.cfg.PoolSize)
	log.Println("  Target DC IPs:")
	for dc, ip := range s.cfg.DCRedirects {
		log.Printf("    DC%d: %s", dc, ip)
	}
	log.Println(strings.Repeat("=", 60))
	log.Printf("  Connect link:")
	log.Printf("  tg://proxy?server=%s&port=%d&secret=dd%s",
		s.cfg.Host, s.cfg.Port, s.cfg.Secret)
	log.Println(strings.Repeat("=", 60))

	s.wsPool.StartRotation(s.ctx)
	go s.acceptLoop()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	label := conn.RemoteAddr().String()

	log.Printf("[%s] new connection", label)

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(s.cfg.BufferSize)
		tc.SetWriteBuffer(s.cfg.BufferSize)
	}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	s.mu.Lock()
	s.active[label] = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.active, label)
		s.mu.Unlock()
	}()

	handler := NewHandler(s.cfg, s.secret)
	info, err := handler.HandleHandshake(conn, label)
	if err != nil {
		log.Printf("[%s] handshake failed: %v", label, err)
		return
	}

	var ws *websocket.Client

	// Стратегия: пробуем ВСЕ возможные paths по порядку
	for _, path := range websocket.AllPaths {
		for _, domain := range info.WSDomains {
			log.Printf("[%s] DC%d -> trying wss://%s%s", label, info.DC, domain, path)

			ws, err = websocket.ConnectDomain(ctx, domain, path, 15*time.Second)
			if err == nil {
				log.Printf("[%s] ✓ WS connected via %s%s", label, domain, path)
				break
			}
		}
		if ws != nil {
			break
		}
	}

	// Fallback: пробуем через IP
	if ws == nil {
		for _, domain := range info.WSDomains {
			log.Printf("[%s] DC%d -> trying IP %s (SNI=%s)", label, info.DC, info.TargetIP, domain)
			ws, err = websocket.Connect(ctx, info.TargetIP, domain, info.WSPath, 15*time.Second)
			if err == nil {
				log.Printf("[%s] ✓ WS connected via IP", label)
				break
			}
			if wsErr, ok := err.(*websocket.HandshakeError); ok && wsErr.IsRedirect() {
				continue
			}
		}
	}

	if ws == nil {
		log.Printf("[%s] ✗ Failed to establish WS connection", label)
		return
	}
	defer ws.Close()

	log.Printf("[%s] sending relay_init: %d bytes, head=%x", label, len(info.RelayInit), info.RelayInit[:16])
	if err := ws.Send(info.RelayInit); err != nil {
		log.Printf("[%s] send relay init failed: %v", label, err)
		return
	}
	log.Printf("[%s] relay init sent", label)

	// Ждём первый ответ от DC (до 3 секунд)
	responseCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		data, err := ws.Recv()
		if err != nil {
			errCh <- err
		} else {
			responseCh <- data
		}
	}()

	var dcResponded bool
	select {
	case data := <-responseCh:
		log.Printf("[%s] ✓ DC responded: %d bytes, head=%x", label, len(data), headBytes(data, 32))
		dcResponded = true
	case err := <-errCh:
		log.Printf("[%s] ✗ DC error/closed: %v", label, err)
	case <-time.After(3 * time.Second):
		log.Printf("[%s] ✗ DC timeout (3s) - no response", label)
	}

	if !dcResponded {
		// DC не отвечает - проблема с relay init или path
		log.Printf("[%s] Trying alternative strategy without waiting...", label)
	}

	splitter := bridge.NewMsgSplitter(info.RelayInit, info.ProtoInt, label)
	br := bridge.NewBridge(conn, ws, info.CryptoCtx, splitter, label, info.DCInt, info.IsMedia)

	if err := br.Run(ctx); err != nil {
		if err != context.Canceled {
			log.Printf("[%s] bridge error: %v", label, err)
		}
	}
}

func headBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

func (s *Server) connectWS(ctx context.Context, ip string, domains []string) (*websocket.Client, error) {
	for _, d := range domains {
		for _, path := range websocket.AllPaths {
			ws, err := websocket.ConnectDomain(ctx, d, path, 15*time.Second)
			if err == nil {
				return ws, nil
			}
		}
	}

	for _, d := range domains {
		ws, err := websocket.Connect(ctx, ip, d, "/apiws", 15*time.Second)
		if err == nil {
			return ws, nil
		}
	}
	return nil, fmt.Errorf("all connection methods failed")
}

func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wsPool.CloseAll()
	s.mu.Lock()
	for _, c := range s.active {
		c()
	}
	s.mu.Unlock()
}
