package gui

import (
	"encoding/binary"
)

// Пиксельный шрифт 5x7 для букв T, G, W, S
var fontTGWS = map[rune][]string{
	'T': {
		"11111",
		"00100",
		"00100",
		"00100",
		"00100",
		"00100",
		"00100",
	},
	'G': {
		"01110",
		"10001",
		"10000",
		"10111",
		"10001",
		"10001",
		"01110",
	},
	'W': {
		"10001",
		"10001",
		"10001",
		"10101",
		"10101",
		"10101",
		"01010",
	},
	'S': {
		"01111",
		"10000",
		"10000",
		"01110",
		"00001",
		"00001",
		"11110",
	},
}

const iconSize = 32

func lerp(a, b, t float64) byte {
	return byte(a + (b-a)*t)
}

// GenerateIcon собирает валидный .ico (32x32, 32-bit) в памяти.
// Синий градиент в стиле Telegram + крупные белые буквы в две строки:
//
//	TG
//	WS
func GenerateIcon() []byte {
	px := make([][][4]byte, iconSize)
	for y := 0; y < iconSize; y++ {
		px[y] = make([][4]byte, iconSize)
		t := float64(y) / float64(iconSize-1)
		// Градиент: #1E96C8 -> #17719B
		r := lerp(30, 23, t)
		g := lerp(150, 113, t)
		b := lerp(200, 155, t)
		for x := 0; x < iconSize; x++ {
			px[y][x] = [4]byte{b, g, r, 0xFF}
		}
	}

	// Рисуем две строки "TG" и "WS" с масштабом 2 (крупные буквы)
	scale := 2
	letterW := 5 * scale // 10
	letterH := 7 * scale // 14
	spacingX := 2
	spacingY := 2

	lines := []string{"TG", "WS"}
	totalW := 2*letterW + spacingX    // 22
	totalH := 2*letterH + spacingY    // 30
	startX := (iconSize - totalW) / 2 // 5
	startY := (iconSize - totalH) / 2 // 1

	for li, line := range lines {
		for i, ch := range line {
			glyph, ok := fontTGWS[ch]
			if !ok {
				continue
			}
			ox := startX + i*(letterW+spacingX)
			oy := startY + li*(letterH+spacingY)
			for gy := 0; gy < 7; gy++ {
				for gx := 0; gx < 5; gx++ {
					if glyph[gy][gx] == '1' {
						for dy := 0; dy < scale; dy++ {
							for dx := 0; dx < scale; dx++ {
								y := oy + gy*scale + dy
								x := ox + gx*scale + dx
								if y >= 0 && y < iconSize && x >= 0 && x < iconSize {
									px[y][x] = [4]byte{0xFF, 0xFF, 0xFF, 0xFF}
								}
							}
						}
					}
				}
			}
		}
	}

	// === Собираем ICO ===
	var ico []byte

	// ICONDIR
	ico = append(ico, 0, 0, 1, 0, 1, 0)

	xorSize := iconSize * iconSize * 4
	andSize := iconSize * (iconSize / 8)
	imgSize := 40 + xorSize + andSize

	// ICONDIRENTRY
	ico = append(ico, iconSize, iconSize, 0, 0)
	ico = appendU16(ico, 1)
	ico = appendU16(ico, 32)
	ico = appendU32(ico, uint32(imgSize))
	ico = appendU32(ico, 22)

	// BITMAPINFOHEADER
	ico = appendU32(ico, 40)
	ico = appendU32(ico, iconSize)
	ico = appendU32(ico, iconSize*2)
	ico = appendU16(ico, 1)
	ico = appendU16(ico, 32)
	ico = appendU32(ico, 0)
	ico = appendU32(ico, uint32(xorSize+andSize))
	ico = appendU32(ico, 0)
	ico = appendU32(ico, 0)
	ico = appendU32(ico, 0)
	ico = appendU32(ico, 0)

	// XOR данные (снизу вверх)
	for y := iconSize - 1; y >= 0; y-- {
		for x := 0; x < iconSize; x++ {
			ico = append(ico, px[y][x][:]...)
		}
	}

	// AND маска
	for i := 0; i < andSize; i++ {
		ico = append(ico, 0)
	}

	return ico
}

func appendU16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}
