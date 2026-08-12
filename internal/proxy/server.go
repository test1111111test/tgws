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
	"sync/atomic"
	"time"

	"tgws/internal/balancer"
	"tgws/internal/bridge"
	"tgws/internal/cfproxy"
	"tgws/internal/config"
	"tgws/internal/crypto"
	"tgws/internal/logger"
	"tgws/internal/pool"
	"tgws/internal/stats"
	"tgws/internal/websocket"
)

type Server struct {
	cfg    *config.Config
	secret []byte
	cf     *cfproxy.Manager
	bal    *balancer.Balancer

	// здоровье WS-маршрутов: после серии падений идём сразу в CF
	wsFailStreak atomic.Int64
	wsLastOK     atomic.Int64

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
		cf:     cfproxy.New(cfg.CFDomainList(), cfg.CFUpdateURL, cfg.CFUpdateInterval),
		bal:    balancer.New(),
	}, nil
}

// IsRunning возвращает true если сервер запущен
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// canceled — гонка/запрос отменены извне: это НЕ ошибка маршрута
func canceled(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled)
}

// === здоровье WS ===

func (s *Server) wsOK() {
	s.wsFailStreak.Store(0)
	s.wsLastOK.Store(time.Now().Unix())
}

func (s *Server) wsFail() {
	s.wsFailStreak.Add(1)
}

// wsDead: 4+ падений подряд и последнего успеха не было >2 минут
func (s *Server) wsDead() bool {
	if s.wsFailStreak.Load() < 4 {
		return false
	}
	return time.Now().Unix()-s.wsLastOK.Load() > 120
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
		closer, err := logger.Setup(s.cfg.LogFile, s.cfg.LogMaxSize, s.cfg.LogMaxFiles, s.cfg.LogToConsole, s.cfg.Verbose)
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
	log.Printf("  Verbose:       %v", s.cfg.Verbose)
	if s.cfg.LogFile != "" {
		log.Printf("  Log file:      %s (max %dMB, keep %d files)",
			s.cfg.LogFile, s.cfg.LogMaxSize, s.cfg.LogMaxFiles)
	}
	if total, black := s.cf.Count(); total > 0 {
		log.Printf("  CF domains:    %d (blacklisted %d), cf_first=%v", total, black, s.cfg.CFFirst)
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
	go s.statsLogger(ctx)

	// Автообновление CF доменов
	if s.cfg.CFAutoUpdate {
		s.cf.StartAutoUpdate(ctx)
	}

	// Warmup пула (заодно работает как пробник здоровья WS)
	if !s.cfg.CFFirst {
		s.warmupPool(ctx)
	}

	s.running = true
	log.Println("Server started")
	return nil
}

// warmupPool заранее устанавливает WS-соединения к настроенным DC
func (s *Server) warmupPool(ctx context.Context) {
	for dc, ip := range s.cfg.DCRedirects {
		go func(dc int, ip string) {
			domains := crypto.WSDomains(dc, false)
			ws, err := s.connectWS(ctx, ip, domains)
			if err != nil {
				s.wsFail()
				log.Printf("Pool warmup DC%d failed: %v", dc, err)
				return
			}
			s.wsOK()
			s.wsPool.Put(dc, false, ws)
			log.Printf("Pool warmup DC%d: connection ready", dc)
		}(dc, ip)
	}
}

// statsLogger печатает сводку статистики раз в 60 секунд
func (s *Server) statsLogger(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Printf("STATS %s", stats.S.Summary())
		}
	}
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

// tryWSChain — последовательная WS-цепочка (primary → alt → via IP).
// При отмене контекста (проигрыш в гонке) выходит тихо, без пометок ошибок.
func (s *Server) tryWSChain(ctx context.Context, info *HandshakeInfo, label string) (bridge.Transport, string) {
	for _, domain := range s.bal.Order(info.WSDomains) {
		log.Printf("[%s] DC%d (test=%v) -> trying wss://%s%s (primary)",
			label, info.DC, info.IsTestDC, domain, info.WSPath)

		ws, err := websocket.ConnectDomainWithRedirect(ctx, domain, info.WSPath, 15*time.Second)
		if err == nil {
			log.Printf("[%s] ✓ WS connected via %s%s (primary)", label, domain, info.WSPath)
			s.bal.MarkOK(domain)
			s.wsOK()
			return ws, "WebSocket"
		}
		if canceled(ctx, err) {
			return nil, "" // гонка отменена — тихо выходим
		}
		stats.S.IncWSErr()
		s.bal.MarkFail(domain)
		s.wsFail()
		log.Printf("[%s] ✗ primary path failed on %s: %v", label, domain, err)
	}

	log.Printf("[%s] Primary path failed, trying alternatives...", label)
	for _, path := range websocket.AllPaths {
		if path == info.WSPath {
			continue
		}
		for _, domain := range s.bal.Order(info.WSDomains) {
			ws, err := websocket.ConnectDomainWithRedirect(ctx, domain, path, 10*time.Second)
			if err == nil {
				log.Printf("[%s] ✓ WS connected via %s%s (fallback)", label, domain, path)
				s.bal.MarkOK(domain)
				s.wsOK()
				return ws, "WebSocket"
			}
			if canceled(ctx, err) {
				return nil, ""
			}
			stats.S.IncWSErr()
			s.bal.MarkFail(domain)
			s.wsFail()
			log.Printf("[%s] ✗ alt path %s failed on %s: %v", label, path, domain, err)
		}
	}

	for _, domain := range info.WSDomains {
		ws, err := websocket.Connect(ctx, info.TargetIP, domain, info.WSPath, 10*time.Second)
		if err == nil {
			log.Printf("[%s] ✓ WS connected via IP %s", label, info.TargetIP)
			s.wsOK()
			return ws, "WebSocket"
		}
		if canceled(ctx, err) {
			return nil, ""
		}
		stats.S.IncWSErr()
		s.wsFail()
		log.Printf("[%s] ✗ WS via IP %s (%s) failed: %v", label, info.TargetIP, domain, err)
	}

	return nil, ""
}

// raceWSvsCF — WS-цепочка и CF параллельно, берём первый успешный транспорт
func (s *Server) raceWSvsCF(ctx context.Context, info *HandshakeInfo, label string) (bridge.Transport, string) {
	total, _ := s.cf.Count()
	if total == 0 {
		return s.tryWSChain(ctx, info, label)
	}

	type res struct {
		t   bridge.Transport
		typ string
	}

	raceCtx, cancel := context.WithCancel(ctx)
	wsCh := make(chan res, 1)
	cfCh := make(chan res, 1)

	go func() {
		t, typ := s.tryWSChain(raceCtx, info, label)
		wsCh <- res{t, typ}
	}()
	go func() {
		t, typ := s.tryCF(raceCtx, info, label)
		cfCh <- res{t, typ}
	}()

	var transport bridge.Transport
	var transportType string

	for i := 0; i < 2; i++ {
		var r res
		select {
		case r = <-wsCh:
		case r = <-cfCh:
		}
		if r.t != nil {
			transport = r.t
			transportType = r.typ
			break
		}
	}
	cancel() // отменяем гонку проигравшего

	// дозакрываем транспорт проигравшего, если он доехал позже
	go func() {
		select {
		case r := <-wsCh:
			if r.t != nil {
				r.t.Close()
			}
		case r := <-cfCh:
			if r.t != nil {
				r.t.Close()
			}
		case <-time.After(90 * time.Second):
		}
	}()

	return transport, transportType
}

// tryCF пробует до 3 CF-доменов. Отмена контекста — не ошибка, worker не чернится.
func (s *Server) tryCF(ctx context.Context, info *HandshakeInfo, label string) (bridge.Transport, string) {
	dcIdx := info.DCInt
	if info.IsMedia {
		dcIdx = -dcIdx
	}
	for attempt := 0; attempt < 3; attempt++ {
		domain := s.cf.Next()
		if domain == "" {
			return nil, ""
		}
		path := cfproxy.CFPath(dcIdx)
		log.Printf("[%s] DC%d -> trying CF fallback wss://%s%s", label, info.DC, domain, path)

		ws, err := websocket.ConnectDomain(ctx, domain, path, 10*time.Second)
		if err != nil {
			if canceled(ctx, err) {
				return nil, "" // гонка отменена — worker НЕ черним
			}
			log.Printf("[%s] ✗ CF fallback failed on %s: %v", label, domain, err)
			s.cf.MarkBad(domain)
			stats.S.IncCFErr()
			continue
		}

		log.Printf("[%s] ✓ CF connected via %s", label, domain)
		s.cf.MarkGood(domain)
		return ws, "CF"
	}
	return nil, ""
}

func (s *Server) handleClient(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	label := conn.RemoteAddr().String()

	stats.S.IncTotal()
	stats.S.ActiveAdd(1)
	defer stats.S.ActiveAdd(-1)

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

	// Готовое соединение из пула (результат warmup/refill)
	var transport bridge.Transport
	var transportType string
	if !info.IsTestDC {
		if ws, _ := s.wsPool.Get(clientCtx, info.DCInt, info.IsMedia, info.TargetIP, info.WSDomains); ws != nil {
			log.Printf("[%s] ✓ WS taken from pool (DC%d)", label, info.DC)
			transport = ws
			transportType = "WebSocket"
			s.wsOK()
		}
	}

	if transport == nil {
		if s.cfg.CFFirst || s.wsDead() {
			// WS принудительно первым или признан мёртвым — CF сразу
			if s.wsDead() && !s.cfg.CFFirst {
				log.Printf("[%s] WS routes look dead — using CF first", label)
			}
			transport, transportType = s.tryCF(clientCtx, info, label)
			if transport == nil {
				transport, transportType = s.tryWSChain(clientCtx, info, label)
			}
		} else {
			// здоровье WS неизвестно/хорошее — гонка WS и CF
			transport, transportType = s.raceWSvsCF(clientCtx, info, label)
		}
	}

	if transport == nil {
		log.Printf("[%s] All WS/CF attempts failed, trying DIRECT TCP fallback to %s:443",
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
		log.Printf("[%s] ✗ ALL connection methods failed (WS + CF + TCP)", label)
		return
	}
	defer transport.Close()

	switch transportType {
	case "WebSocket":
		stats.S.IncViaWS()
	case "CF":
		stats.S.IncViaCF()
	default:
		stats.S.IncViaTCP()
	}

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
