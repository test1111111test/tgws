package pool

import (
	"context"
	"sync"
	"time"

	"tgws/internal/websocket"
)

type Pool struct {
	mu          sync.Mutex
	idle        map[key][]*conn
	poolSize    int
	maxAge      time.Duration
	connectFunc func(ctx context.Context, ip string, domains []string) (*websocket.Client, error)
}

type key struct {
	dc      int
	isMedia bool
}
type conn struct {
	ws      *websocket.Client
	created time.Time
}

func NewPool(size int, maxAge time.Duration) *Pool {
	return &Pool{idle: make(map[key][]*conn), poolSize: size, maxAge: maxAge}
}

func (p *Pool) SetConnectFunc(fn func(context.Context, string, []string) (*websocket.Client, error)) {
	p.connectFunc = fn
}

func (p *Pool) Get(ctx context.Context, dc int, isMedia bool, ip string, domains []string) (*websocket.Client, error) {
	k := key{dc, isMedia}
	p.mu.Lock()
	bucket := p.idle[k]
	for len(bucket) > 0 {
		pc := bucket[0]
		bucket = bucket[1:]
		if time.Since(pc.created) > p.maxAge {
			go pc.ws.Close()
			continue
		}
		p.idle[k] = bucket
		p.mu.Unlock()
		go p.refill(k, ip, domains)
		return pc.ws, nil
	}
	p.idle[k] = bucket
	p.mu.Unlock()
	go p.refill(k, ip, domains)
	return nil, nil
}

func (p *Pool) Put(dc int, isMedia bool, ws *websocket.Client) {
	k := key{dc, isMedia}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle[k]) >= p.poolSize {
		go ws.Close()
		return
	}
	p.idle[k] = append(p.idle[k], &conn{ws, time.Now()})
}

func (p *Pool) ReportSuccess(dc int, isMedia bool) {}

func (p *Pool) refill(k key, ip string, domains []string) {
	if p.connectFunc == nil {
		return
	}
	p.mu.Lock()
	needed := p.poolSize - len(p.idle[k])
	p.mu.Unlock()
	for i := 0; i < needed; i++ {
		if ws, err := p.connectFunc(context.Background(), ip, domains); err == nil {
			p.Put(k.dc, k.isMedia, ws)
		} else {
			return
		}
	}
}

func (p *Pool) StartRotation(ctx context.Context) {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.rotate()
			}
		}
	}()
}

func (p *Pool) rotate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, bucket := range p.idle {
		var active []*conn
		for _, pc := range bucket {
			if now.Sub(pc.created) <= p.maxAge {
				active = append(active, pc)
			} else {
				go pc.ws.Close()
			}
		}
		p.idle[k] = active
	}
}

func (p *Pool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, bucket := range p.idle {
		for _, pc := range bucket {
			go pc.ws.Close()
		}
	}
	p.idle = make(map[key][]*conn)
}
