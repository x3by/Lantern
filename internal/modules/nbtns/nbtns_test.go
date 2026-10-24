package nbtns

import (
	"net"
	"testing"
)

// encodeNBTName applies the first-level NetBIOS name encoding (the inverse of
// decodeNBTName) so we can round-trip a name through the decoder.
func encodeNBTName(name string, suffix byte) []byte {
	padded := make([]byte, 16)
	copy(padded, name)
	for i := len(name); i < 15; i++ {
		padded[i] = ' '
	}
	padded[15] = suffix

	encoded := make([]byte, 32)
	for i, b := range padded {
		encoded[i*2] = (b >> 4) + 0x41
		encoded[i*2+1] = (b & 0x0f) + 0x41
	}
	return encoded
}

func TestDecodeNBTName(t *testing.T) {
	encoded := encodeNBTName("FILESERVER", 0x20)
	name, suffix := decodeNBTName(encoded)
	if name != "FILESERVER" {
		t.Fatalf("decoded name = %q, want FILESERVER", name)
	}
	if suffix != 0x20 {
		t.Fatalf("suffix = 0x%02x, want 0x20", suffix)
	}
	if nbtRole(suffix) != "File Server" {
		t.Fatalf("role = %q, want File Server", nbtRole(suffix))
	}
}

func TestBuildNBTAnswer(t *testing.T) {
	// A minimal 50-byte NBT query: TID, flags, counts, name field.
	query := make([]byte, 50)
	query[0], query[1] = 0xab, 0xcd // Transaction ID
	query[2], query[3] = 0x01, 0x10 // Query flags
	query[12] = 0x20                // Name length
	copy(query[13:45], encodeNBTName("HOST", 0x00))

	ip := net.IPv4(192, 168, 1, 50)
	resp := buildNBTAnswer(query, ip)

	if resp[0] != 0xab || resp[1] != 0xcd {
		t.Fatalf("transaction ID not echoed: % x", resp[0:2])
	}
	if resp[2] != 0x85 || resp[3] != 0x00 {
		t.Fatalf("response flags = % x, want 85 00", resp[2:4])
	}
	// The answer address occupies the final four bytes.
	got := net.IPv4(resp[len(resp)-4], resp[len(resp)-3], resp[len(resp)-2], resp[len(resp)-1])
	if !got.Equal(ip) {
		t.Fatalf("answer IP = %s, want %s", got, ip)
	}
}
