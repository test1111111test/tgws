package crypto

import "fmt"

const (
	HandshakeLen = 64
	SkipLen      = 8
	PrekeyLen    = 32
	KeyLen       = 32
	IVLen        = 16
	ProtoTagPos  = 56
	DCIdxPos     = 60
)

var (
	ProtoTagAbridged           = []byte{0xef, 0xef, 0xef, 0xef}
	ProtoTagIntermediate       = []byte{0xee, 0xee, 0xee, 0xee}
	ProtoTagPaddedIntermediate = []byte{0xdd, 0xdd, 0xdd, 0xdd}
)

const (
	ProtoAbridgedInt           = 0xEFEFEFEF
	ProtoIntermediateInt       = 0xEEEEEEEE
	ProtoPaddedIntermediateInt = 0xDDDDDDDD
)

var (
	ReservedFirstBytes = map[byte]bool{0xEF: true}
	ReservedStarts     = [][]byte{
		{0x48, 0x45, 0x41, 0x44},
		{0x50, 0x4F, 0x53, 0x54},
		{0x47, 0x45, 0x54, 0x20},
		{0xee, 0xee, 0xee, 0xee},
		{0xdd, 0xdd, 0xdd, 0xdd},
		{0x16, 0x03, 0x01, 0x02},
	}
	ReservedContinue = []byte{0x00, 0x00, 0x00, 0x00}
	Zero64           = make([]byte, 64)
)

const (
	WSPath     = "/apiws"
	WSPathTest = "/apiws_test"
)

var (
	DCDefaultIPs = map[int]string{
		1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100",
		4: "149.154.167.91", 5: "149.154.171.5", 203: "91.105.192.100",
	}
	DCTestIPs = map[int]string{
		1: "149.154.175.10", 2: "149.154.167.40", 3: "149.154.175.117",
	}
)

func WSDomains(dc int, isMedia bool) []string {
	if dc == 203 {
		dc = 2
	}
	if isMedia {
		return []string{
			fmt.Sprintf("kws%d-1.web.telegram.org", dc),
			fmt.Sprintf("kws%d.web.telegram.org", dc),
		}
	}
	return []string{
		fmt.Sprintf("kws%d.web.telegram.org", dc),
		fmt.Sprintf("kws%d-1.web.telegram.org", dc),
	}
}

func HumanBytes(n uint64) string {
	units := []string{"B", "KB", "MB", "GB"}
	value := float64(n)
	idx := 0
	for value >= 1024 && idx < len(units)-1 {
		value /= 1024
		idx++
	}
	return fmt.Sprintf("%.1f%s", value, units[idx])
}
