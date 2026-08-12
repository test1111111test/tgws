package balancer

import (
	"sort"
	"sync"
	"time"
)

type state struct {
	fails    int
	lastFail time.Time
	uses     int
}

// Balancer отслеживает здоровье доменов и упорядочивает их:
// здоровые — первыми, часто падающие — в конец.
type Balancer struct {
	mu sync.Mutex
	st map[string]*state
}

func New() *Balancer {
	return &Balancer{st: make(map[string]*state)}
}

func (b *Balancer) get(d string) *state {
	s, ok := b.st[d]
	if !ok {
		s = &state{}
		b.st[d] = s
	}
	return s
}

// Order возвращает домены, отсортированные по здоровью (меньше недавних падений — раньше)
func (b *Balancer) Order(domains []string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	type pair struct {
		domain string
		score  int
	}
	list := make([]pair, 0, len(domains))

	for _, d := range domains {
		s := b.get(d)
		score := s.fails
		// деградация штрафа: если последнее падение старше 10 минут — штраф вдвое меньше
		if !s.lastFail.IsZero() && now.Sub(s.lastFail) > 10*time.Minute {
			score = s.fails / 2
		}
		list = append(list, pair{d, score})
	}

	sort.SliceStable(list, func(i, j int) bool {
		return list[i].score < list[j].score
	})

	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.domain)
	}
	return out
}

// MarkOK отмечает домен здоровым (сбрасывает счётчик падений)
func (b *Balancer) MarkOK(d string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.get(d)
	s.fails = 0
	s.uses++
}

// MarkFail отмечает падение домена
func (b *Balancer) MarkFail(d string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.get(d)
	s.fails++
	s.lastFail = time.Now()
}
