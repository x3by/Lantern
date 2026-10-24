package ntlm

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildType3 crafts a minimal NTLMSSP Type 3 message with a UTF-16 NTLMv2
// response for testing ParseType3.
func buildType3(domain, user, workstation string, ntResponse []byte) []byte {
	const headerLen = 64
	fields := [][]byte{
		EncodeUTF16LE(domain),
		EncodeUTF16LE(user),
		EncodeUTF16LE(workstation),
	}
	payload := append([]byte{}, ntResponse...)
	for _, f := range fields {
		payload = append(payload, f...)
	}

	msg := make([]byte, headerLen)
	copy(msg[0:8], Signature)
	binary.LittleEndian.PutUint32(msg[8:12], 3)

	putField := func(off int, length, start int) {
		binary.LittleEndian.PutUint16(msg[off:off+2], uint16(length))
		binary.LittleEndian.PutUint16(msg[off+2:off+4], uint16(length))
		binary.LittleEndian.PutUint32(msg[off+4:off+8], uint32(start))
	}

	ntStart := headerLen
	putField(20, len(ntResponse), ntStart) // NtChallengeResponse
	cursor := ntStart + len(ntResponse)
	putField(28, len(fields[0]), cursor) // Domain
	cursor += len(fields[0])
	putField(36, len(fields[1]), cursor) // User
	cursor += len(fields[1])
	putField(44, len(fields[2]), cursor) // Workstation

	binary.LittleEndian.PutUint32(msg[60:64], negotiateUnicode)
	return append(msg, payload...)
}

func TestParseType3NTLMv2(t *testing.T) {
	ntResponse := make([]byte, 32) // >24 bytes => NTLMv2
	for i := range ntResponse {
		ntResponse[i] = byte(i)
	}
	msg := buildType3("CORP", "alice", "WS01", ntResponse)

	id, ok := ParseType3(msg, DefaultChallenge)
	if !ok {
		t.Fatal("ParseType3 returned ok=false")
	}
	if id.Domain != "CORP" || id.Username != "alice" || id.Workstation != "WS01" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if id.Version != 2 {
		t.Fatalf("expected NTLMv2, got v%d", id.Version)
	}
	if id.Display() != "CORP\\alice" {
		t.Fatalf("unexpected display: %q", id.Display())
	}
	// hashcat -m 5600 format: user::domain:challenge:HMAC:blob
	if !strings.HasPrefix(id.Hash, "alice::CORP:0102030405060708:") {
		t.Fatalf("unexpected hash: %q", id.Hash)
	}
}

func TestBuildType2IsParseable(t *testing.T) {
	msg := BuildType2(negotiateUnicode, DefaultChallenge)
	msgType, _, ok := MessageType(msg)
	if !ok || msgType != 2 {
		t.Fatalf("expected Type 2 message, got type=%d ok=%v", msgType, ok)
	}
	// The server challenge must be echoed at offset 24.
	for i, b := range DefaultChallenge {
		if msg[24+i] != b {
			t.Fatalf("challenge byte %d = 0x%02x, want 0x%02x", i, msg[24+i], b)
		}
	}
}
