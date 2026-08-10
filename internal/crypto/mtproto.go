package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"sync/atomic"
)

type MTProtoCipher struct {
	stream cipher.Stream
	block  cipher.Block
	iv     []byte
}

func NewMTProtoCipher(key, iv []byte) (*MTProtoCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	return &MTProtoCipher{
		stream: cipher.NewCTR(block, ivCopy),
		block:  block,
		iv:     ivCopy,
	}, nil
}

func (c *MTProtoCipher) Update(data []byte) []byte {
	out := make([]byte, len(data))
	c.stream.XORKeyStream(out, data)
	return out
}

func (c *MTProtoCipher) FastForward(n int) {
	dummy := make([]byte, n)
	c.stream.XORKeyStream(dummy, dummy)
}

type HandshakeResult struct {
	DC                int
	IsMedia           bool
	ProtoTag          []byte
	ProtoInt          uint32
	ClientDecPrekeyIV []byte
	ClientDec         *MTProtoCipher
}

func TryHandshake(handshake, secret []byte) (*HandshakeResult, error) {
	if len(handshake) != HandshakeLen {
		return nil, fmt.Errorf("handshake must be %d bytes, got %d", HandshakeLen, len(handshake))
	}

	decPrekeyIV := handshake[SkipLen : SkipLen+PrekeyLen+IVLen]
	decPrekey := decPrekeyIV[:PrekeyLen]
	decIV := decPrekeyIV[PrekeyLen:]

	decKeyInput := make([]byte, len(decPrekey)+len(secret))
	copy(decKeyInput, decPrekey)
	copy(decKeyInput[len(decPrekey):], secret)
	decKeyHash := sha256.Sum256(decKeyInput)

	decryptor, err := NewMTProtoCipher(decKeyHash[:], decIV)
	if err != nil {
		return nil, fmt.Errorf("create decryptor: %w", err)
	}

	decrypted := decryptor.Update(handshake)
	protoTag := decrypted[ProtoTagPos : ProtoTagPos+4]

	if !bytesEqual(protoTag, ProtoTagAbridged) &&
		!bytesEqual(protoTag, ProtoTagIntermediate) &&
		!bytesEqual(protoTag, ProtoTagPaddedIntermediate) {
		return nil, fmt.Errorf("invalid protocol tag: %x", protoTag)
	}

	dcIdx := int(int16(binary.LittleEndian.Uint16(decrypted[DCIdxPos : DCIdxPos+2])))
	dcID := dcIdx
	isMedia := false
	if dcIdx < 0 {
		dcID = -dcIdx
		isMedia = true
	}

	var protoInt uint32
	if bytesEqual(protoTag, ProtoTagAbridged) {
		protoInt = ProtoAbridgedInt
	} else if bytesEqual(protoTag, ProtoTagIntermediate) {
		protoInt = ProtoIntermediateInt
	} else {
		protoInt = ProtoPaddedIntermediateInt
	}

	return &HandshakeResult{
		DC:                dcID,
		IsMedia:           isMedia,
		ProtoTag:          protoTag,
		ProtoInt:          protoInt,
		ClientDecPrekeyIV: decPrekeyIV,
		ClientDec:         decryptor,
	}, nil
}

func GenerateRelayInit(protoTag []byte, dcIdx int) ([]byte, error) {
	var rnd []byte
	for {
		rnd = make([]byte, HandshakeLen)
		rand.Read(rnd)
		if ReservedFirstBytes[rnd[0]] {
			continue
		}
		valid := true
		for _, r := range ReservedStarts {
			if bytesEqual(rnd[:4], r) {
				valid = false
				break
			}
		}
		if !valid || bytesEqual(rnd[4:8], ReservedContinue) {
			continue
		}
		break
	}

	encKey := rnd[SkipLen : SkipLen+PrekeyLen]
	encIV := rnd[SkipLen+PrekeyLen : SkipLen+PrekeyLen+IVLen]
	encryptor, _ := NewMTProtoCipher(encKey, encIV)

	dcBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(dcBytes, uint16(int16(dcIdx)))
	randomTail := make([]byte, 2)
	rand.Read(randomTail)
	tailPlain := append(append(protoTag, dcBytes...), randomTail...)

	encryptedFull := encryptor.Update(rnd)
	keystreamTail := make([]byte, 8)
	for i := 0; i < 8; i++ {
		keystreamTail[i] = encryptedFull[56+i] ^ rnd[56+i]
	}
	encryptedTail := make([]byte, 8)
	for i := 0; i < 8; i++ {
		encryptedTail[i] = tailPlain[i] ^ keystreamTail[i]
	}

	result := make([]byte, HandshakeLen)
	copy(result, rnd)
	copy(result[ProtoTagPos:], encryptedTail)
	return result, nil
}

type CryptoContext struct {
	CltDec, CltEnc, TGEnc, TGDec *MTProtoCipher
	Mode                         int
}

// Глобальный счётчик для чередования режимов
var modeCounter uint64

// NextMode возвращает следующий режим для перебора
func NextMode() int {
	return int(atomic.AddUint64(&modeCounter, 1) % 4)
}

// BuildCryptoContext создаёт контекст с указанным режимом clt_enc
// mode 0: reversed,  без fast-forward  (стандарт)
// mode 1: reversed,  fast-forward 64
// mode 2: non-rev,   без fast-forward
// mode 3: non-rev,   fast-forward 64
func BuildCryptoContext(clientDec *MTProtoCipher, clientDecPrekeyIV, secret, relayInit []byte, mode int) (*CryptoContext, error) {
	cltDec := clientDec

	var cltEncKey [32]byte
	var cltEncIV []byte

	if mode == 0 || mode == 1 {
		// reversed
		rev := reverseBytes(clientDecPrekeyIV)
		prekey := rev[:PrekeyLen]
		cltEncIV = rev[PrekeyLen:]
		cltEncKey = sha256.Sum256(append(prekey, secret...))
	} else {
		// non-reversed (как clt_dec)
		prekey := clientDecPrekeyIV[:PrekeyLen]
		cltEncIV = clientDecPrekeyIV[PrekeyLen:]
		cltEncKey = sha256.Sum256(append(prekey, secret...))
	}

	cltEnc, _ := NewMTProtoCipher(cltEncKey[:], cltEncIV)
	if mode == 1 || mode == 3 {
		cltEnc.FastForward(HandshakeLen)
	}

	log.Printf("DEBUG clt_enc mode=%d key[0:8]=%x iv=%x", mode, cltEncKey[:8], cltEncIV)

	// TGEnc
	tgEncKey := relayInit[SkipLen : SkipLen+PrekeyLen]
	tgEncIV := relayInit[SkipLen+PrekeyLen : SkipLen+PrekeyLen+IVLen]
	tgEnc, _ := NewMTProtoCipher(tgEncKey, tgEncIV)
	tgEnc.FastForward(HandshakeLen)

	// TGDec
	tgDecPrekeyIV := reverseBytes(relayInit[SkipLen : SkipLen+PrekeyLen+IVLen])
	tgDecKey := tgDecPrekeyIV[:KeyLen]
	tgDecIV := tgDecPrekeyIV[KeyLen:]
	tgDec, _ := NewMTProtoCipher(tgDecKey, tgDecIV)

	return &CryptoContext{
		CltDec: cltDec, CltEnc: cltEnc, TGEnc: tgEnc, TGDec: tgDec,
		Mode: mode,
	}, nil
}

func reverseBytes(data []byte) []byte {
	r := make([]byte, len(data))
	for i, b := range data {
		r[len(data)-1-i] = b
	}
	return r
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
