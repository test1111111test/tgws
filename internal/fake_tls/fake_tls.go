package fake_tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	TLSRecordHandshake = 0x16
	TLSRecordCCS       = 0x14
	TLSRecordAppData   = 0x17

	ClientRandomOffset = 11
	ClientRandomLen    = 32
	SessionIDOffset    = 44
	SessionIDLen       = 32

	TimestampTolerance = 120 // секунды
	TLSAppDataMax      = 16384
)

// CCSFrame - Change Cipher Spec frame
var CCSFrame = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

// serverHelloTemplate - шаблон ServerHello
var serverHelloTemplate = []byte{
	0x16, 0x03, 0x03, 0x00, 0x7a, // TLS record: handshake, length 122
	0x02, 0x00, 0x00, 0x76, // Handshake: ServerHello, length 118
	0x03, 0x03, // TLS 1.2
	// 32 байта random (заполнится позже)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, // session_id length = 32
	// 32 байта session_id (заполнится позже)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x13, 0x01, // cipher suite: TLS_AES_128_GCM_SHA256
	0x00,       // compression: null
	0x00, 0x2e, // extensions length = 46
	// extension: key_share
	0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
	// 32 байта public key (заполнится позже)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// extension: supported_versions
	0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
}

const (
	shRandomOff = 11
	shSessIDOff = 44
	shPubKeyOff = 89
)

// VerifyClientHelloResult результат верификации ClientHello
type VerifyClientHelloResult struct {
	ClientRandom []byte
	SessionID    []byte
	Timestamp    int64
}

// VerifyClientHello проверяет ClientHello от клиента
// Возвращает client_random, session_id, timestamp если валидно
func VerifyClientHello(data []byte, secret []byte) (*VerifyClientHelloResult, error) {
	n := len(data)
	// 5 (record hdr) + 6 (hs type+len+version) + 32 (random) = 43
	if n < 43 {
		return nil, fmt.Errorf("too short: %d bytes", n)
	}
	if data[0] != TLSRecordHandshake {
		return nil, fmt.Errorf("not a handshake record: 0x%02x", data[0])
	}
	if data[5] != 0x01 {
		return nil, fmt.Errorf("not ClientHello: 0x%02x", data[5])
	}

	clientRandom := make([]byte, ClientRandomLen)
	copy(clientRandom, data[ClientRandomOffset:ClientRandomOffset+ClientRandomLen])

	// Создаём копию data с занулённым random
	zeroed := make([]byte, len(data))
	copy(zeroed, data)
	for i := 0; i < ClientRandomLen; i++ {
		zeroed[ClientRandomOffset+i] = 0
	}

	// Вычисляем HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(zeroed)
	expected := mac.Sum(nil)

	// Сравниваем первые 28 байт
	if !hmac.Equal(expected[:28], clientRandom[:28]) {
		return nil, fmt.Errorf("HMAC mismatch")
	}

	// Извлекаем timestamp из последних 4 байт random (XOR с expected)
	tsXOR := make([]byte, 4)
	for i := 0; i < 4; i++ {
		tsXOR[i] = clientRandom[28+i] ^ expected[28+i]
	}
	timestamp := int64(binary.LittleEndian.Uint32(tsXOR))

	now := time.Now().Unix()
	if abs(now-timestamp) > TimestampTolerance {
		return nil, fmt.Errorf("timestamp out of tolerance: %d vs %d", timestamp, now)
	}

	// Извлекаем session_id
	sessionID := make([]byte, SessionIDLen)
	if n >= SessionIDOffset+SessionIDLen && data[43] == 0x20 {
		copy(sessionID, data[SessionIDOffset:SessionIDOffset+SessionIDLen])
	}

	return &VerifyClientHelloResult{
		ClientRandom: clientRandom,
		SessionID:    sessionID,
		Timestamp:    timestamp,
	}, nil
}

// BuildServerHello генерирует ServerHello ответ
func BuildServerHello(secret []byte, clientRandom []byte, sessionID []byte) []byte {
	sh := make([]byte, len(serverHelloTemplate))
	copy(sh, serverHelloTemplate)

	// Заполняем session_id
	copy(sh[shSessIDOff:shSessIDOff+32], sessionID)

	// Генерируем случайный public key (32 байта)
	pubKey := make([]byte, 32)
	rand.Read(pubKey)
	copy(sh[shPubKeyOff:shPubKeyOff+32], pubKey)

	// Генерируем случайные encrypted data (1900-2100 байт)
	encryptedSize := 1900 + int(randUint32()%201)
	encryptedData := make([]byte, encryptedSize)
	rand.Read(encryptedData)

	// Формируем application data record
	appRecord := make([]byte, 5+encryptedSize)
	appRecord[0] = TLSRecordAppData
	appRecord[1] = 0x03
	appRecord[2] = 0x03
	binary.BigEndian.PutUint16(appRecord[3:5], uint16(encryptedSize))
	copy(appRecord[5:], encryptedData)

	// Собираем полный ответ: ServerHello + CCS + AppData
	response := append(sh, CCSFrame...)
	response = append(response, appRecord...)

	// Вычисляем server random: HMAC(secret, client_random + response)
	hmacInput := append(clientRandom, response...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(hmacInput)
	serverRandom := mac.Sum(nil)

	// Вставляем server random в ServerHello
	copy(response[shRandomOff:shRandomOff+32], serverRandom)

	return response
}

// WrapTLSRecord упаковывает данные в TLS Application Data records
func WrapTLSRecord(data []byte) []byte {
	var parts []byte
	offset := 0
	for offset < len(data) {
		chunkSize := TLSAppDataMax
		if offset+chunkSize > len(data) {
			chunkSize = len(data) - offset
		}
		chunk := data[offset : offset+chunkSize]

		// TLS record header: type (1) + version (2) + length (2)
		record := make([]byte, 5+chunkSize)
		record[0] = TLSRecordAppData
		record[1] = 0x03
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(chunkSize))
		copy(record[5:], chunk)

		parts = append(parts, record...)
		offset += chunkSize
	}
	return parts
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func randUint32() uint32 {
	b := make([]byte, 4)
	rand.Read(b)
	return binary.BigEndian.Uint32(b)
}

// IsClientHello проверяет, похожи ли данные на TLS ClientHello
func IsClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	return data[0] == TLSRecordHandshake && data[5] == 0x01
}
