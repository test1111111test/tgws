package fake_tls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// FakeTlsStream обёртка для чтения/записи TLS records поверх TCP
// Реализует интерфейсы io.Reader и io.Writer для совместимости с bridge
type FakeTlsStream struct {
	conn     net.Conn
	readBuf  []byte
	readLeft int
}

// NewFakeTlsStream создаёт новый FakeTlsStream
func NewFakeTlsStream(conn net.Conn) *FakeTlsStream {
	return &FakeTlsStream{
		conn:     conn,
		readBuf:  make([]byte, 0),
		readLeft: 0,
	}
}

// Read реализует io.Reader — читает до len(p) байт из TLS потока
func (s *FakeTlsStream) Read(p []byte) (int, error) {
	data, err := s.ReadN(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, data)
	return len(data), nil
}

// Write реализует io.Writer — записывает данные, оборачивая в TLS records
func (s *FakeTlsStream) Write(p []byte) (int, error) {
	if err := s.WriteTLS(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadExactly читает ровно n байт (блокирует пока не наберёт)
func (s *FakeTlsStream) ReadExactly(n int) ([]byte, error) {
	for len(s.readBuf) < n {
		payload, err := s.readTLSPayload()
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		s.readBuf = append(s.readBuf, payload...)
	}

	result := make([]byte, n)
	copy(result, s.readBuf[:n])
	s.readBuf = s.readBuf[n:]
	return result, nil
}

// ReadN читает до n байт
func (s *FakeTlsStream) ReadN(n int) ([]byte, error) {
	if len(s.readBuf) > 0 {
		chunk := s.readBuf
		if len(chunk) > n {
			chunk = chunk[:n]
		}
		s.readBuf = s.readBuf[len(chunk):]
		return chunk, nil
	}

	payload, err := s.readTLSPayload()
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return []byte{}, nil
	}

	if len(payload) > n {
		s.readBuf = append(s.readBuf, payload[n:]...)
		return payload[:n], nil
	}
	return payload, nil
}

// readTLSPayload читает payload из следующего TLS record
func (s *FakeTlsStream) readTLSPayload() ([]byte, error) {
	// Если есть остаток от предыдущего record
	if s.readLeft > 0 {
		buf := make([]byte, s.readLeft)
		n, err := s.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return []byte{}, nil
		}
		s.readLeft -= n
		return buf[:n], nil
	}

	// Читаем TLS record header (5 байт)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return nil, err
	}

	rtype := hdr[0]
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))

	// Change Cipher Spec - пропускаем
	if rtype == TLSRecordCCS {
		if recLen > 0 {
			discard := make([]byte, recLen)
			if _, err := io.ReadFull(s.conn, discard); err != nil {
				return nil, err
			}
		}
		return s.readTLSPayload()
	}

	// Не Application Data - возвращаем пусто
	if rtype != TLSRecordAppData {
		return []byte{}, nil
	}

	// Читаем payload
	data := make([]byte, recLen)
	n, err := io.ReadFull(s.conn, data)
	if err != nil {
		return nil, err
	}

	remaining := recLen - n
	if remaining > 0 {
		s.readLeft = remaining
	}

	return data[:n], nil
}

// WriteTLS записывает данные, оборачивая в TLS Application Data records
func (s *FakeTlsStream) WriteTLS(data []byte) error {
	wrapped := WrapTLSRecord(data)
	_, err := s.conn.Write(wrapped)
	return err
}

// Close закрывает соединение
func (s *FakeTlsStream) Close() error {
	return s.conn.Close()
}

// SetDeadline устанавливает deadline для чтения/записи
func (s *FakeTlsStream) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

// SetReadDeadline устанавливает deadline для чтения
func (s *FakeTlsStream) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}

// SetWriteDeadline устанавливает deadline для записи
func (s *FakeTlsStream) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

// RemoteAddr возвращает адрес удалённого хоста
func (s *FakeTlsStream) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// LocalAddr возвращает локальный адрес
func (s *FakeTlsStream) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// Conn возвращает underlying net.Conn
func (s *FakeTlsStream) Conn() net.Conn {
	return s.conn
}

// String возвращает строковое представление
func (s *FakeTlsStream) String() string {
	return fmt.Sprintf("FakeTlsStream(%s)", s.conn.RemoteAddr().String())
}
