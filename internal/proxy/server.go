package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"tgws/internal/bridge"
	"tgws/internal/config"
	"tgws/internal/logger"
	"tgws/internal/pool"
	"tgws/internal/websocket"
)

type Server struct {
	cfg    *config.Config
	secret []byte

	mu      sync.Mutex
	running bool

	ctx    context.Context
	cancel context.CancelFunc

	listener net.Listener
	wsPool   *pool.Pool
	active   map[string]context.CancelFunc

	logCloser  io.Closer
	logStarted bool
}

func NewServer(cfg *config.Config) (*Server, error) {
	secret, err := hex.DecodeString(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	return &Server{
		cfg:    cfg,
		secret: secret,
	}, nil
}

// IsRunning возвращает true если сервер запущен
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Start запускает сервер. Может вызываться повторно после Stop.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	// Логгер настраиваем только один раз
	if !s.logStarted {
		closer, err := logger.Setup(s.cfg.LogFile, s.cfg.LogMaxSize, s.cfg.LogMaxFiles, s.cfg.LogToConsole)
		if err != nil {
			return fmt.Errorf("setup logger: %w", err)
		}
		s.logCloser = closer
		s.logStarted = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel
	s.active = make(map[string]context.CancelFunc)

	s.wsPool = pool.NewPool(s.cfg.PoolSize, 120*time.Second)
	s.wsPool.SetConnectFunc(s.connectWS)

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		cancel()
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = l

	log.Println(strings.Repeat("=", 60))
	log.Println("  Telegram MTProto WS Bridge Proxy (Go)")
	log.Printf("  Listening on   %s", addr)
	log.Printf("  Secret:        %s", s.cfg.Secret)
	log.Printf("  Secret (dd):   dd%s", s.cfg.Secret)
	if s.cfg.FakeTLSDomain != "" {
		log.Printf("  Fake TLS:      %s", s.cfg.FakeTLSDomain)
		log.Printf("  Secret (ee):   %s", s.cfg.EESecret())
	}
	log.Printf("  Pool size:     %d", s.cfg.PoolSize)
	log.Printf("  Mask domain:   %s", s.cfg.MaskDomain)
	if s.cfg.LogFile != "" {
		log.Printf("  Log file:      %s (max %dMB, keep %d files)",
			s.cfg.LogFile, s.cfg.LogMaxSize, s.cfg.LogMaxFiles)
	}
	log.Println("  Target DC IPs:")
	for dc, ip := range s.cfg.DCRedirects {
		log.Printf("    DC%d: %s", dc, ip)
	}
	log.Println(strings.Repeat("=", 60))
	log.Printf("  Connect link (dd):")
	log.Printf("  tg://proxy?server=%s&port=%d&secret=dd%s",
		s.cfg.Host, s.cfg.Port, s.cfg.Secret)
	if s.cfg.FakeTLSDomain != "" {
		log.Printf("  Connect link (ee):")
		log.Printf("  tg://proxy?server=%s&port=%d&secret=%s",
			s.cfg.Host, s.cfg.Port, s.cfg.EESecret())
	}
	log.Println(strings.Repeat("=", 60))

	s.wsPool.StartRotation(ctx)
	go s.acceptLoop(ctx, l)

	s.running = true
	log.Println("Server started")
	return nil
}

// Stop останавливает сервер без завершения процесса
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	cancel := s.cancel
	listener := s.listener
	wsPool := s.wsPool
	active := s.active
	s.mu.Unlock()

	log.Println("Stopping server...")
	cancel()
	if listener != nil {
		listener.Close()
	}
	if wsPool != nil {
		wsPool.CloseAll()
	}
	for _, c := range active {
		c()
	}
	log.Println("Server stopped")
}

// CloseLog закрывает лог-файл (вызывать при завершении процесса)
func (s *Server) CloseLog() {
	if s.logCloser != nil {
		s.logCloser.Close()
	}
}

func (s *Server) acceptLoop(ctx context.Context, l net.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleClient(ctx, conn)
	}
}

func (s *Server) handleClient(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	label := conn.RemoteAddr().String()

	log.Printf("[%s] new connection", label)

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(s.cfg.BufferSize)
		tc.SetWriteBuffer(s.cfg.BufferSize)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	clientCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.active[label] = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.active, label)
		s.mu.Unlock()
	}()

	handler := NewHandler(s.cfg, s.secret)

	handshake, clientIO, err := handler.ReadClientInit(conn, label)
	if err != nil {
		log.Printf("[%s] read client init failed: %v", label, err)
		return
	}

	info, err := handler.HandleHandshake(handshake, label)
	if err != nil {
		log.Printf("[%s] handshake failed: %v", label, err)
		return
	}

	var transport bridge.Transport
	var transportType string

	for _, domain := range info.WSDomains {
		log.Printf("[%s] DC%d (test=%v) -> trying wss://%s%s (primary)",
			label, info.DC, info.IsTestDC, domain, info.WSPath)

		ws, err := websocket.ConnectDomainWithRedirect(clientCtx, domain, info.WSPath, 15*time.Second)
		if err == nil {
			log.Printf("[%s] ✓ WS connected via %s%s (primary)", label, domain, info.WSPath)
			transport = ws
			transportType = "WebSocket"
			break
		}
		log.Printf("[%s] ✗ primary path failed on %s: %v", label, domain, err)
	}

	if transport == nil {
		log.Printf("[%s] Primary path failed, trying alternatives...", label)
		for _, path := range websocket.AllPaths {
			if path == info.WSPath {
				continue
			}
			for _, domain := range info.WSDomains {
				ws, err := websocket.ConnectDomainWithRedirect(clientCtx, domain, path, 10*time.Second)
				if err == nil {
					log.Printf("[%s] ✓ WS connected via %s%s (fallback)", label, domain, path)
					transport = ws
					transportType = "WebSocket"
					break
				}
			}
			if transport != nil {
				break
			}
		}
	}

	if transport == nil {
		for _, domain := range info.WSDomains {
			ws, err := websocket.Connect(clientCtx, info.TargetIP, domain, info.WSPath, 10*time.Second)
			if err == nil {
				log.Printf("[%s] ✓ WS connected via IP %s", label, info.TargetIP)
				transport = ws
				transportType = "WebSocket"
				break
			}
		}
	}

	if transport == nil {
		log.Printf("[%s] All WS attempts failed, trying DIRECT TCP fallback to %s:443",
			label, info.TargetIP)

		tcpClient, err := bridge.ConnectDirect(clientCtx, info.TargetIP, 443, 15*time.Second)
		if err == nil {
			log.Printf("[%s] ✓ Direct TCP connected to %s:443 (fallback)", label, info.TargetIP)
			transport = tcpClient
			transportType = "Direct TCP"
		} else {
			log.Printf("[%s] ✗ Direct TCP also failed: %v", label, err)
		}
	}

	if transport == nil {
		log.Printf("[%s] ✗ ALL connection methods failed (WS + TCP)", label)
		return
	}
	defer transport.Close()

	log.Printf("[%s] sending relay_init: %d bytes, head=%x (via %s)",
		label, len(info.RelayInit), info.RelayInit[:16], transportType)
	if err := transport.Send(info.RelayInit); err != nil {
		log.Printf("[%s] send relay init failed: %v", label, err)
		return
	}
	log.Printf("[%s] relay init sent via %s, starting bridge", label, transportType)

	splitter := bridge.NewMsgSplitter(info.RelayInit, info.ProtoInt, label)
	br := bridge.NewBridge(clientIO, transport, info.CryptoCtx, splitter, label, info.DCInt, info.IsMedia)

	if err := br.Run(clientCtx); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Printf("[%s] bridge error: %v", label, err)
		}
	}
}

func (s *Server) connectWS(ctx context.Context, ip string, domains []string) (*websocket.Client, error) {
	for _, d := range domains {
		ws, err := websocket.ConnectDomainWithRedirect(ctx, d, "/apiws", 15*time.Second)
		if err == nil {
			return ws, nil
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
