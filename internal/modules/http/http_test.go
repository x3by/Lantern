package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"lantern/internal/core"
	"lantern/internal/ntlm"
)

func TestHandleNTLMHandshake(t *testing.T) {
	server, client := net.Pipe()
	m := New(core.NewLogger(true))

	go m.handle(context.Background(), server)

	reader := bufio.NewReader(client)
	tp := textproto.NewReader(reader)

	readResponse := func() textproto.MIMEHeader {
		t.Helper()
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := tp.ReadLine(); err != nil { // status line
			t.Fatalf("status line: %v", err)
		}
		header, err := tp.ReadMIMEHeader()
		if err != nil {
			t.Fatalf("headers: %v", err)
		}
		if cl := header.Get("Content-Length"); cl != "" && cl != "0" {
			// Drain the body so the next response parses cleanly.
			n := 0
			for _, c := range cl {
				n = n*10 + int(c-'0')
			}
			_, _ = reader.Discard(n)
		}
		return header
	}

	// 1. Unauthenticated GET -> 401 offering NTLM.
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	header := readResponse()
	if !hasNTLM(header.Values("Www-Authenticate")) {
		t.Fatalf("missing NTLM challenge header: %v", header.Values("Www-Authenticate"))
	}

	// 2. Send Type 1 -> expect Type 2 challenge in the header.
	type1 := base64.StdEncoding.EncodeToString(buildType1())
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM " + type1 + "\r\n\r\n"))
	header = readResponse()
	var challenge string
	for _, v := range header.Values("Www-Authenticate") {
		if strings.HasPrefix(v, "NTLM ") && len(v) > 5 {
			challenge = strings.TrimPrefix(v, "NTLM ")
		}
	}
	if challenge == "" {
		t.Fatalf("no Type 2 challenge returned: %v", header.Values("Www-Authenticate"))
	}
	raw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if msgType, _, ok := ntlm.MessageType(raw); !ok || msgType != 2 {
		t.Fatalf("challenge is not a Type 2 message (type=%d ok=%v)", msgType, ok)
	}
}

func hasNTLM(values []string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == "NTLM" {
			return true
		}
	}
	return false
}

// buildType1 crafts a minimal NTLMSSP NEGOTIATE message.
func buildType1() []byte {
	msg := make([]byte, 16)
	copy(msg[0:8], ntlm.Signature)
	msg[8] = 1 // message type 1
	// Negotiate Unicode flag at offset 12.
	msg[12] = 0x01
	return msg
}
