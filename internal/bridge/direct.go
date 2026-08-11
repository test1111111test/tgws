package bridge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// DirectClient — прямое TCP подключение к Telegram DC (без WebSocket, без TLS)
// Telegram DC принимает plain TCP на порту 443 как MTProto proxy
type DirectClient struct {
	conn   net.Conn
	reader *bufio.Reader
	closed bool
}

// ConnectDirect устанавливает прямое TCP соединение с DC
func ConnectDirect(ctx context.Context, host string, port int, timeout time.Duration) (*DirectClient, error) {
	if port == 0 {
		port = 443
	}
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial to %s: %w", addr, err)
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	return &DirectClient{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, 64*1024),
		closed: false,
	}, nil
}

// Send отправляет данные как есть (plain TCP, без framing)
func (d *DirectClient) Send(data []byte) error {
	if d.closed {
		return fmt.Errorf("direct connection closed")
	}
	d.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := d.conn.Write(data)
	return err
}

// Recv читает следующие данные (plain TCP stream)
func (d *DirectClient) Recv() ([]byte, error) {
	if d.closed {
		return nil, io.EOF
	}

	// Читаем до 64KB за раз
	buf := make([]byte, 65536)
	d.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	n, err := d.reader.Read(buf)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.EOF
	}

	result := make([]byte, n)
	copy(result, buf[:n])
	return result, nil
}

// Close закрывает TCP соединение
func (d *DirectClient) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	return d.conn.Close()
}

// IsClosed возвращает статус закрытия
func (d *DirectClient) IsClosed() bool {
	return d.closed
}
