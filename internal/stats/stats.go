package stats

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Stats — глобальные атомарные счётчики прокси.
type Stats struct {
	total   atomic.Int64 // всего клиентских подключений
	active  atomic.Int64 // открыто сейчас
	bad     atomic.Int64 // ошибочные handshake
	viaWS   atomic.Int64 // подключений через WebSocket
	viaTCP  atomic.Int64 // подключений через прямой TCP
	viaCF   atomic.Int64 // подключений через CF fallback
	masked  atomic.Int64 // замаскировано (HTTP/TLS -> mask-домен)
	fakeTLS atomic.Int64 // успешных Fake TLS handshake
	wsErr   atomic.Int64 // ошибок WS-подключений
	cfErr   atomic.Int64 // ошибок CF-подключений
	poolHit atomic.Int64 // попаданий в пул
	poolMis atomic.Int64 // промахов пула
	up      atomic.Int64 // байт от клиента к DC
	down    atomic.Int64 // байт от DC к клиенту
	start   time.Time
}

// S — глобальный экземпляр статистики.
var S = &Stats{start: time.Now()}

func (s *Stats) IncTotal()         { s.total.Add(1) }
func (s *Stats) ActiveAdd(d int64) { s.active.Add(d) }
func (s *Stats) IncBad()           { s.bad.Add(1) }
func (s *Stats) IncViaWS()         { s.viaWS.Add(1) }
func (s *Stats) IncViaTCP()        { s.viaTCP.Add(1) }
func (s *Stats) IncViaCF()         { s.viaCF.Add(1) }
func (s *Stats) IncMasked()        { s.masked.Add(1) }
func (s *Stats) IncFakeTLS()       { s.fakeTLS.Add(1) }
func (s *Stats) IncWSErr()         { s.wsErr.Add(1) }
func (s *Stats) IncCFErr()         { s.cfErr.Add(1) }
func (s *Stats) IncPoolHit()       { s.poolHit.Add(1) }
func (s *Stats) IncPoolMiss()      { s.poolMis.Add(1) }
func (s *Stats) AddUp(n int64)     { s.up.Add(n) }
func (s *Stats) AddDown(n int64)   { s.down.Add(n) }

// === Геттеры для GUI ===
func (s *Stats) Total() int64     { return s.total.Load() }
func (s *Stats) Active() int64    { return s.active.Load() }
func (s *Stats) Bad() int64       { return s.bad.Load() }
func (s *Stats) ViaWS() int64     { return s.viaWS.Load() }
func (s *Stats) ViaTCP() int64    { return s.viaTCP.Load() }
func (s *Stats) ViaCF() int64     { return s.viaCF.Load() }
func (s *Stats) Masked() int64    { return s.masked.Load() }
func (s *Stats) FakeTLS() int64   { return s.fakeTLS.Load() }
func (s *Stats) WSErr() int64     { return s.wsErr.Load() }
func (s *Stats) CFErr() int64     { return s.cfErr.Load() }
func (s *Stats) PoolHit() int64   { return s.poolHit.Load() }
func (s *Stats) PoolMiss() int64  { return s.poolMis.Load() }
func (s *Stats) UpBytes() int64   { return s.up.Load() }
func (s *Stats) DownBytes() int64 { return s.down.Load() }

// Uptime возвращает время работы.
func (s *Stats) Uptime() time.Duration { return time.Since(s.start) }

// Summary — одна строка для лога и тултипа.
func (s *Stats) Summary() string {
	return fmt.Sprintf("time=%s conn=%d act=%d bad=%d ws=%d tcp=%d cf=%d mask=%d ftls=%d wserr=%d cferr=%d ↑%s ↓%s",
		dur(s.Uptime()), s.total.Load(), s.active.Load(), s.bad.Load(),
		s.viaWS.Load(), s.viaTCP.Load(), s.viaCF.Load(), s.masked.Load(), s.fakeTLS.Load(),
		s.wsErr.Load(), s.cfErr.Load(), human(s.up.Load()), human(s.down.Load()))
}

// Short — короткая строка для тултипа трея.
func (s *Stats) Short() string {
	return fmt.Sprintf("TGWS | act=%d conn=%d ↑%s ↓%s",
		s.active.Load(), s.total.Load(), human(s.up.Load()), human(s.down.Load()))
}

// Report — многострочный отчёт для лога/окна.
func (s *Stats) Report() string {
	var b strings.Builder
	b.WriteString("================ STATS ================\n")
	fmt.Fprintf(&b, "  Uptime:            %s\n", dur(s.Uptime()))
	fmt.Fprintf(&b, "  Connections total: %d\n", s.total.Load())
	fmt.Fprintf(&b, "  Connections active:%d\n", s.active.Load())
	fmt.Fprintf(&b, "  Bad handshakes:    %d\n", s.bad.Load())
	fmt.Fprintf(&b, "  Via WebSocket:     %d\n", s.viaWS.Load())
	fmt.Fprintf(&b, "  Via direct TCP:    %d\n", s.viaTCP.Load())
	fmt.Fprintf(&b, "  Via CF fallback:   %d\n", s.viaCF.Load())
	fmt.Fprintf(&b, "  Masked (HTTP/TLS): %d\n", s.masked.Load())
	fmt.Fprintf(&b, "  Fake TLS OK:       %d\n", s.fakeTLS.Load())
	fmt.Fprintf(&b, "  WS errors:         %d\n", s.wsErr.Load())
	fmt.Fprintf(&b, "  CF errors:         %d\n", s.cfErr.Load())
	fmt.Fprintf(&b, "  Pool hit/miss:     %d/%d\n", s.poolHit.Load(), s.poolMis.Load())
	fmt.Fprintf(&b, "  Traffic up:        %s\n", human(s.up.Load()))
	fmt.Fprintf(&b, "  Traffic down:      %s\n", human(s.down.Load()))
	b.WriteString("=======================================")
	return b.String()
}

func dur(d time.Duration) string { return d.Round(time.Second).String() }

func human(n int64) string {
	v := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if v < 1024 {
			return fmt.Sprintf("%.1f%s", v, u)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1fTB", v)
}
