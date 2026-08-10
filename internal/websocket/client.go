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
	"net"
	"net/http"
	"time"
)

const (
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
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.StatusLine)
}
func (e *HandshakeError) IsRedirect() bool { return e.StatusCode >= 300 && e.StatusCode < 400 }

// Все известные WebSocket paths Telegram
var AllPaths = []string{
	"/apiws",
	"/apiws_test",
	"/apiws_prod",
	"/apiws_test_prod",
	"/apiws_testv2",
	"/apiws_testv3",
	"/apiws_prodv2",
	"/apiws_prodv3",
	"/apiws_v2",
	"/apiws_v3",
}

func ConnectDomain(ctx context.Context, domain, path string, timeout time.Duration) (*Client, error) {
	if path == "" {
		path = "/apiws"
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", tlsConfig)
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

	return c, nil
}

func Connect(ctx context.Context, host, domain, path string, timeout time.Duration) (*Client, error) {
	if path == "" {
		path = "/apiws"
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", tlsConfig)
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

	return c, nil
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
		"Sec-WebSocket-Protocol: binary\r\n"+
		"Origin: https://%s\r\n"+
		"\r\n",
		path, c.domain, base64.StdEncoding.EncodeToString(keyBytes), c.domain)

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

	return &HandshakeError{
		StatusCode: resp.StatusCode,
		StatusLine: resp.Status,
		Location:   resp.Header.Get("Location"),
	}
}

func (c *Client) Send(data []byte) error {
	if c.closed {
		return fmt.Errorf("websocket closed")
	}
	return c.sendFrame(OpBinary, data, true)
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
			c.sendFrame(OpClose, nil, true)
			return nil, io.EOF
		case OpPing:
			c.sendFrame(OpPong, payload, true)
		case OpBinary:
			return payload, nil
		}
	}
	return nil, io.EOF
}

func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.sendFrame(OpClose, nil, true)
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

	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if _, err := c.conn.Write(data); err != nil {
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

func (c *Client) IsClosed() bool { return c.closed }
