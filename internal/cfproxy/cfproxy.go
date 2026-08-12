package cfproxy

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NormalizeDomain приводит значение к чистому hostname:
// отрезает схему (https://), путь, query, порт, userinfo и пробелы.
// Примеры:
//
//	"https://tgws-relay.example.workers.dev/" -> "tgws-relay.example.workers.dev"
//	"MyWorker.Workers.Dev"                    -> "myworker.workers.dev"
func NormalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	if i := strings.LastIndex(d, ":"); i >= 0 {
		d = d[:i]
	}
	return strings.ToLower(d)
}

// Manager хранит список CloudFlare-доменов для fallback и управляет ими:
// round-robin выбор + чёрный список + автообновление с URL.
type Manager struct {
	mu        sync.Mutex
	user      []string             // домены из конфига
	fetched   []string             // домены из автообновления
	blacklist map[string]time.Time // домен -> время разблокировки
	rr        int

	autoURL  string
	interval time.Duration
	client   *http.Client
}

// New создаёт менеджер (домены нормализуются сразу)
func New(userDomains []string, autoURL string, intervalSec int) *Manager {
	if intervalSec < 60 {
		intervalSec = 3600
	}
	var user []string
	for _, d := range userDomains {
		if nd := NormalizeDomain(d); nd != "" && strings.Contains(nd, ".") {
			user = append(user, nd)
		}
	}
	return &Manager{
		user:      user,
		blacklist: make(map[string]time.Time),
		autoURL:   strings.TrimSpace(autoURL),
		interval:  time.Duration(intervalSec) * time.Second,
		client:    &http.Client{Timeout: 15 * time.Second},
	}
}

// StartAutoUpdate запускает периодическое обновление списка доменов
func (m *Manager) StartAutoUpdate(ctx context.Context) {
	if m.autoURL == "" {
		return
	}
	m.fetchOnce(ctx)

	go func() {
		t := time.NewTicker(m.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.fetchOnce(ctx)
			}
		}
	}()
}

func (m *Manager) fetchOnce(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.autoURL, nil)
	if err != nil {
		return
	}
	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("CF auto-update: fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("CF auto-update: bad status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}

	var domains []string
	for _, line := range strings.Split(string(body), "\n") {
		d := NormalizeDomain(line)
		if d == "" || !strings.Contains(d, ".") {
			continue
		}
		domains = append(domains, d)
	}

	m.mu.Lock()
	m.fetched = domains
	m.mu.Unlock()
	log.Printf("CF auto-update: %d domains loaded", len(domains))
}

// all возвращает объединённый список доменов (конфиг + fetched)
func (m *Manager) all() []string {
	out := make([]string, 0, len(m.user)+len(m.fetched))
	seen := map[string]bool{}
	for _, d := range m.user {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, d := range m.fetched {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// Next возвращает следующий живой домен (round-robin, чёрный список)
func (m *Manager) Next() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.all()
	if len(list) == 0 {
		return ""
	}

	now := time.Now()
	for i := 0; i < len(list); i++ {
		m.rr++
		d := list[m.rr%len(list)]
		if until, bad := m.blacklist[d]; !bad || now.After(until) {
			if bad {
				delete(m.blacklist, d)
			}
			return d
		}
	}
	return ""
}

// MarkBad помещает домен в чёрный список на 10 минут
func (m *Manager) MarkBad(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklist[domain] = time.Now().Add(10 * time.Minute)
	log.Printf("CF: domain %s blacklisted for 10m", domain)
}

// MarkGood снимает домен с чёрного списка
func (m *Manager) MarkGood(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blacklist, domain)
}

// Count возвращает (всего доменов, в чёрном списке)
func (m *Manager) Count() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	black := 0
	for _, t := range m.blacklist {
		if now.Before(t) {
			black++
		}
	}
	return len(m.all()), black
}

// CFPath формирует path для CF worker с указанием DC
func CFPath(dcIdx int) string {
	return "/tgws/" + itoa(dcIdx)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
