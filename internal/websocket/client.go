package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA
)

type Client struct {
	conn   net.Conn
	reader *bufio.Reader
	closed bool
	domain string
	path   string
}

type HandshakeError struct {
	StatusCode int
	StatusLine string
	Location   string
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("HTTP %d: %s (Location: %s)", e.StatusCode, e.StatusLine, e.Location)
}

func (e *HandshakeError) IsRedirect() bool {
	return e.StatusCode >= 300 && e.StatusCode < 400
}

var AllPaths = []string{"/apiws", "/apiws_test"}

// dialTLS — TLS-подключение, уважающее context: cancel() мгновенно обрывает dial
func dialTLS(ctx context.Context, addr string, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	nd := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	d := &tls.Dialer{NetDialer: nd, Config: cfg}
	return d.DialContext(ctx, "tcp", addr)
}

func ConnectDomain(ctx context.Context, domain, path string, timeout time.Duration) (*Client, error) {
	if path == "" {
		path = "/apiws"
	}
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	}

	conn, err := dialTLS(ctx, domain+":443", tlsConfig, timeout)
	if err != nil {
		return nil, fmt.Errorf("tls dial to %s:443: %w", domain, err)
	}

	setTCPOptions(conn)

	c := &Client{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, 64*1024),
		domain: domain,
		path:   path,
	}

	if err := c.handshake(path, timeout); err != nil {
		conn.Close()
		return nil, err
	}

	// ВАЖНО: снимаем дедлайны после хендшейка, иначе соединение
	// умрёт ровно через timeout секунд
	c.clearDeadlines()

	return c, nil
}

func Connect(ctx context.Context, host, domain, path string, timeout time.Duration) (*Client, error) {
	if path == "" {
		path = "/apiws"
	}
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	}

	conn, err := dialTLS(ctx, host+":443", tlsConfig, timeout)
	if err != nil {
		return nil, fmt.Errorf("tls dial to %s:443 (SNI=%s): %w", host, domain, err)
	}

	setTCPOptions(conn)

	c := &Client{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, 64*1024),
		domain: domain,
		path:   path,
	}

	if err := c.handshake(path, timeout); err != nil {
		conn.Close()
		return nil, err
	}

	// ВАЖНО: снимаем дедлайны после хендшейка
	c.clearDeadlines()

	return c, nil
}

// clearDeadlines снимает все дедлайны — соединение живёт пока есть трафик
func (c *Client) clearDeadlines() {
	c.conn.SetReadDeadline(time.Time{})
	c.conn.SetWriteDeadline(time.Time{})
}

func setTCPOptions(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
		return
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetReadBuffer(256 * 1024)
			tcpConn.SetWriteBuffer(256 * 1024)
		}
	}
}

func (c *Client) handshake(path string, timeout time.Duration) error {
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Protocol: binary\r\n\r\n",
		path, c.domain, base64.StdEncoding.EncodeToString(keyBytes))

	c.conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(timeout))
	resp, err := http.ReadResponse(c.reader, nil)
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 101 {
		return nil
	}

	// HTTP redirect - возвращаем Location
	location := resp.Header.Get("Location")
	return &HandshakeError{
		StatusCode: resp.StatusCode,
		StatusLine: resp.Status,
		Location:   location,
	}
}

// ConnectDomainWithRedirect следует за HTTP redirects (до 3 hops)
func ConnectDomainWithRedirect(ctx context.Context, domain, path string, timeout time.Duration) (*Client, error) {
	currentDomain := domain
	currentPath := path

	for i := 0; i < 3; i++ {
		client, err := ConnectDomain(ctx, currentDomain, currentPath, timeout)
		if err == nil {
			return client, nil
		}

		// Проверяем, не redirect ли это
		if hsErr, ok := err.(*HandshakeError); ok && hsErr.IsRedirect() && hsErr.Location != "" {
			log.Printf("[%s] Following redirect: %s -> %s", currentDomain, currentPath, hsErr.Location)

			// Парсим новый URL
			newDomain, newPath, parseErr := parseRedirectURL(hsErr.Location)
			if parseErr != nil {
				return nil, fmt.Errorf("parse redirect: %w", parseErr)
			}

			currentDomain = newDomain
			currentPath = newPath
			continue
		}

		// Не redirect - возвращаем ошибку
		return nil, err
	}

	return nil, fmt.Errorf("too many redirects")
}

// parseRedirectURL извлекает domain и path из redirect URL
func parseRedirectURL(location string) (domain, path string, err error) {
	// Простой парсер: убираем scheme и извлекаем host/path
	location = strings.TrimPrefix(location, "https://")
	location = strings.TrimPrefix(location, "http://")

	parts := strings.SplitN(location, "/", 2)
	if len(parts) == 0 {
		return "", "", fmt.Errorf("invalid redirect URL: %s", location)
	}

	domain = parts[0]
	if len(parts) == 2 {
		path = "/" + parts[1]
	} else {
		path = "/"
	}

	return domain, path, nil
}

func (c *Client) Send(data []byte) error {
	if c.closed {
		return fmt.Errorf("websocket closed")
	}
	return c.sendFrame(OpBinary, data, true)
}

func (c *Client) SendPing() error {
	if c.closed {
		return fmt.Errorf("websocket closed")
	}
	return c.sendFrame(OpPing, []byte("ping"), true)
}

func (c *Client) Recv() ([]byte, error) {
	for !c.closed {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		switch opcode {
		case OpClose:
			c.closed = true
			_ = c.sendFrame(OpClose, nil, true)
			return nil, io.EOF
		case OpPing:
			_ = c.sendFrame(OpPong, payload, true)
		case OpPong:
			continue
		case OpBinary:
			return payload, nil
		case OpText:
			log.Printf("[WS] received unexpected Text frame: %s", string(payload))
		}
	}
	return nil, io.EOF
}

func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	_ = c.sendFrame(OpClose, nil, true)
	return c.conn.Close()
}

func (c *Client) sendFrame(opcode byte, data []byte, mask bool) error {
	var header []byte
	length := len(data)
	fb := 0x80 | opcode

	if length < 126 {
		header = []byte{byte(fb), byte(length)}
	} else if length < 65536 {
		header = []byte{byte(fb), 126, byte(length >> 8), byte(length)}
	} else {
		header = []byte{byte(fb), 127}
		lb := make([]byte, 8)
		binary.BigEndian.PutUint64(lb, uint64(length))
		header = append(header, lb...)
	}

	if mask {
		mk := make([]byte, 4)
		rand.Read(mk)
		header[1] |= 0x80
		header = append(header, mk...)
		masked := make([]byte, len(data))
		for i := range data {
			masked[i] = data[i] ^ mk[i%4]
		}
		data = masked
	}

	frame := make([]byte, 0, len(header)+len(data))
	frame = append(frame, header...)
	frame = append(frame, data...)

	if _, err := c.conn.Write(frame); err != nil {
		return err
	}
	return nil
}

func (c *Client) readFrame() (byte, []byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, h); err != nil {
		return 0, nil, err
	}

	opcode := h[0] & 0x0F
	length := uint64(h[1] & 0x7F)
	hasMask := (h[1] & 0x80) != 0

	if length == 126 {
		el := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, el); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(el))
	} else if length == 127 {
		el := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, el); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(el)
	}

	var maskKey []byte
	if hasMask {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(c.reader, maskKey); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, nil, err
	}

	if hasMask {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func (c *Client) IsClosed() bool {
	return c.closed
}

func (c *Client) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
