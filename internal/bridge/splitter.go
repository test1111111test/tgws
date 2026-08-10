package bridge

import (
	"encoding/binary"
	"log"

	"tgws/internal/crypto"
)

type MsgSplitter struct {
	dec       *crypto.MTProtoCipher
	proto     uint32
	cipherBuf []byte
	plainBuf  []byte
	disabled  bool
	label     string // для логирования
}

func NewMsgSplitter(relayInit []byte, protoInt uint32, label string) *MsgSplitter {
	key := relayInit[crypto.SkipLen : crypto.SkipLen+crypto.PrekeyLen]
	iv := relayInit[crypto.SkipLen+crypto.PrekeyLen : crypto.SkipLen+crypto.PrekeyLen+crypto.IVLen]

	dec, err := crypto.NewMTProtoCipher(key, iv)
	if err != nil {
		log.Printf("[%s] Splitter: failed to create cipher: %v", label, err)
		return &MsgSplitter{disabled: true, label: label}
	}

	dec.FastForward(crypto.HandshakeLen)

	log.Printf("[%s] Splitter: created with proto=0x%08X, key[0:8]=%x, iv=%x",
		label, protoInt, key[:8], iv)

	return &MsgSplitter{
		dec:       dec,
		proto:     protoInt,
		cipherBuf: make([]byte, 0),
		plainBuf:  make([]byte, 0),
		disabled:  false,
		label:     label,
	}
}

func (s *MsgSplitter) Split(chunk []byte) [][]byte {
	if len(chunk) == 0 {
		return nil
	}

	if s.disabled {
		log.Printf("[%s] Splitter: disabled, returning whole chunk", s.label)
		return [][]byte{chunk}
	}

	// Добавляем данные в буферы
	s.cipherBuf = append(s.cipherBuf, chunk...)
	plainChunk := s.dec.Update(chunk)
	s.plainBuf = append(s.plainBuf, plainChunk...)

	log.Printf("[%s] Splitter: added %d bytes, total cipher=%d, total plain=%d",
		s.label, len(chunk), len(s.cipherBuf), len(s.plainBuf))

	// Логируем первый plain chunk (используем head из bridge.go)
	if len(s.plainBuf) <= 256 {
		log.Printf("[%s] Splitter: plainBuf head=%x", s.label, head(s.plainBuf, 32))
	}

	var parts [][]byte
	offset := 0
	bufLen := len(s.cipherBuf)
	packetCount := 0

	// Ищем пакеты в буфере
	for offset < bufLen {
		packetLen := s.nextPacketLen(offset, bufLen-offset)
		if packetLen == nil {
			log.Printf("[%s] Splitter: nextPacketLen returned nil at offset=%d (avail=%d)",
				s.label, offset, bufLen-offset)
			break
		}

		if *packetLen <= 0 {
			log.Printf("[%s] Splitter: invalid packetLen=%d at offset=%d, disabling",
				s.label, *packetLen, offset)
			parts = append(parts, s.cipherBuf[offset:])
			offset = bufLen
			s.disabled = true
			break
		}

		packetCount++
		if packetCount <= 3 {
			log.Printf("[%s] Splitter: found packet[%d] at offset=%d, len=%d",
				s.label, packetCount, offset, *packetLen)
		}

		parts = append(parts, s.cipherBuf[offset:offset+*packetLen])
		offset += *packetLen
	}

	// Удаляем обработанные данные
	if offset > 0 {
		s.cipherBuf = s.cipherBuf[offset:]
		s.plainBuf = s.plainBuf[offset:]
	}

	log.Printf("[%s] Splitter: returning %d parts, remaining cipher=%d",
		s.label, len(parts), len(s.cipherBuf))

	return parts
}

func (s *MsgSplitter) Flush() [][]byte {
	if len(s.cipherBuf) == 0 {
		return nil
	}

	tail := make([]byte, len(s.cipherBuf))
	copy(tail, s.cipherBuf)
	s.cipherBuf = s.cipherBuf[:0]
	s.plainBuf = s.plainBuf[:0]

	return [][]byte{tail}
}

func (s *MsgSplitter) nextPacketLen(offset, avail int) *int {
	if avail <= 0 {
		return nil
	}

	switch s.proto {
	case crypto.ProtoAbridgedInt:
		return s.nextAbridgedLen(offset, avail)
	case crypto.ProtoIntermediateInt, crypto.ProtoPaddedIntermediateInt:
		return s.nextIntermediateLen(offset, avail)
	default:
		log.Printf("[%s] Splitter: unknown proto=0x%08X", s.label, s.proto)
		zero := 0
		return &zero
	}
}

func (s *MsgSplitter) nextAbridgedLen(offset, avail int) *int {
	if avail < 1 {
		return nil
	}

	first := s.plainBuf[offset]
	var payloadLen, headerLen int

	if first == 0x7F || first == 0xFF {
		if avail < 4 {
			return nil
		}
		payloadLen = int(binary.LittleEndian.Uint32(s.plainBuf[offset+1:offset+4])) * 4
		headerLen = 4
	} else {
		payloadLen = int(first&0x7F) * 4
		headerLen = 1
	}

	if payloadLen <= 0 {
		zero := 0
		return &zero
	}

	packetLen := headerLen + payloadLen
	if avail < packetLen {
		return nil
	}

	return &packetLen
}

func (s *MsgSplitter) nextIntermediateLen(offset, avail int) *int {
	if avail < 4 {
		log.Printf("[%s] Splitter: not enough data for length (need 4, have %d)",
			s.label, avail)
		return nil
	}

	// Читаем 4 байта как little-endian uint32
	lenBytes := s.plainBuf[offset : offset+4]
	rawLen := binary.LittleEndian.Uint32(lenBytes)
	payloadLen := int(rawLen & 0x7FFFFFFF)

	log.Printf("[%s] Splitter: intermediate len bytes=%x, raw=0x%08X, payload=%d",
		s.label, lenBytes, rawLen, payloadLen)

	if payloadLen <= 0 || payloadLen > 1024*1024 { // sanity check: max 1MB
		log.Printf("[%s] Splitter: invalid payloadLen=%d", s.label, payloadLen)
		zero := 0
		return &zero
	}

	packetLen := 4 + payloadLen
	if avail < packetLen {
		log.Printf("[%s] Splitter: need %d bytes, have %d", s.label, packetLen, avail)
		return nil
	}

	return &packetLen
}
