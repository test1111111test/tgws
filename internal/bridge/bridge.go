package bridge

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"tgws/internal/crypto"
	"tgws/internal/stats"
)

// ClientConn интерфейс для клиентского соединения
// Реализуется как net.Conn (обычный режим), так и *fake_tls.FakeTlsStream (Fake TLS режим)
type ClientConn interface {
	io.Reader
	io.Writer
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

type Bridge struct {
	clientConn ClientConn
	ws         Transport
	ctx        *crypto.CryptoContext
	splitter   *MsgSplitter

	upBytes, downBytes, upPackets, downPackets uint64
	startTime                                  time.Time
	label, dcTag                               string
	firstUpLogged, firstDownLogged             bool
}

func NewBridge(cc ClientConn, ws Transport, ctx *crypto.CryptoContext,
	splitter *MsgSplitter, label string, dc int, isMedia bool) *Bridge {
	dt := fmt.Sprintf("DC%d", dc)
	if isMedia {
		dt += "m"
	}
	return &Bridge{clientConn: cc, ws: ws, ctx: ctx, splitter: splitter,
		startTime: time.Now(), label: label, dcTag: dt}
}

func (b *Bridge) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var err1, err2 error

	log.Printf("[%s] BRIDGE START (%s)", b.label, b.dcTag)

	wg.Add(2)
	go func() { defer wg.Done(); defer cancel(); err1 = b.tcpToWS(ctx) }()
	go func() { defer wg.Done(); defer cancel(); err2 = b.wsToTCP(ctx) }()
	wg.Wait()

	log.Printf("[%s] BRIDGE CLOSED (%s): ↑%s (%d pkts) ↓%s (%d pkts) in %.2fs",
		b.label, b.dcTag,
		crypto.HumanBytes(b.upBytes), b.upPackets,
		crypto.HumanBytes(b.downBytes), b.downPackets,
		time.Since(b.startTime).Seconds())

	if err1 != nil && err1 != io.EOF && err1 != context.Canceled {
		log.Printf("[%s] tcpToWS error: %v", b.label, err1)
	}
	if err2 != nil && err2 != io.EOF && err2 != context.Canceled {
		log.Printf("[%s] wsToTCP error: %v", b.label, err2)
	}

	if err1 != nil && err1 != io.EOF && err1 != context.Canceled {
		return err1
	}
	return err2
}

func (b *Bridge) tcpToWS(ctx context.Context) error {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		b.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := b.clientConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Printf("[%s] ⚠ CLIENT closed connection (EOF)", b.label)
				if b.splitter != nil {
					if t := b.splitter.Flush(); len(t) > 0 {
						for _, p := range t {
							b.ws.Send(p)
						}
					}
				}
				return nil
			}
			log.Printf("[%s] ⚠ CLIENT read error: %v", b.label, err)
			return err
		}

		b.upBytes += uint64(n)
		b.upPackets++
		stats.S.AddUp(int64(n))

		if !b.firstUpLogged {
			b.firstUpLogged = true
			log.Printf("[%s] ↑ FIRST from client: %d bytes, cipher_head=%x",
				b.label, n, head(buf[:n], 32))
		}

		plaintext := b.ctx.CltDec.Update(buf[:n])

		if b.upPackets <= 3 {
			log.Printf("[%s] ↑ PLAINTEXT (pkt %d): %d bytes, head=%x",
				b.label, b.upPackets, len(plaintext), head(plaintext, 32))
		}

		ciphertext := b.ctx.TGEnc.Update(plaintext)

		if b.upPackets <= 3 {
			log.Printf("[%s] ↑ TG_CIPHER (pkt %d): %d bytes, head=%x",
				b.label, b.upPackets, len(ciphertext), head(ciphertext, 32))
		}

		if b.splitter != nil {
			parts := b.splitter.Split(ciphertext)

			if b.upPackets <= 3 {
				log.Printf("[%s] ↑ SPLITTER (pkt %d): %d bytes -> %d parts",
					b.label, b.upPackets, len(ciphertext), len(parts))
			}

			for _, p := range parts {
				if err := b.ws.Send(p); err != nil {
					log.Printf("[%s] WS send error: %v", b.label, err)
					return err
				}
			}
		} else {
			if err := b.ws.Send(ciphertext); err != nil {
				log.Printf("[%s] WS send error: %v", b.label, err)
				return err
			}
		}
	}
}

func (b *Bridge) wsToTCP(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := b.ws.Recv()
		if err != nil {
			if err == io.EOF {
				log.Printf("[%s] ⚠ DC closed connection (EOF)", b.label)
				return nil
			}
			log.Printf("[%s] ⚠ DC recv error: %v", b.label, err)
			return err
		}

		b.downBytes += uint64(len(data))
		b.downPackets++
		stats.S.AddDown(int64(len(data)))

		if !b.firstDownLogged {
			b.firstDownLogged = true
			log.Printf("[%s] ↓ FIRST from DC: %d bytes, head=%x",
				b.label, len(data), head(data, 32))
		}

		plaintext := b.ctx.TGDec.Update(data)

		if b.downPackets <= 3 {
			log.Printf("[%s] ↓ PLAINTEXT (pkt %d): %d bytes, head=%x",
				b.label, b.downPackets, len(plaintext), head(plaintext, 32))
		}

		ciphertext := b.ctx.CltEnc.Update(plaintext)

		if b.downPackets <= 3 {
			log.Printf("[%s] ↓ CLIENT_CIPHER (pkt %d): %d bytes, head=%x",
				b.label, b.downPackets, len(ciphertext), head(ciphertext, 32))
		}

		b.clientConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := b.clientConn.Write(ciphertext); err != nil {
			log.Printf("[%s] ⚠ CLIENT write error: %v", b.label, err)
			return err
		}
	}
}

func head(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
