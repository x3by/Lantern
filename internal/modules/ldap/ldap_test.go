package ldap

import (
	"bufio"
	"bytes"
	"testing"

	"lantern/internal/ntlm"
)

// buildBindRequest assembles an LDAPMessage carrying a BindRequest with the
// given authentication element (tagged simple [0] or sasl [3]).
func buildBindRequest(messageID int, name string, authTag byte, authValue []byte) []byte {
	op := berElement(0x02, []byte{0x03}) // version 3
	op = append(op, berElement(0x04, []byte(name))...)
	op = append(op, berElement(authTag, authValue)...)
	bindReq := berElement(0x60, op)

	msg := berElement(0x02, encodeInt(messageID))
	msg = append(msg, bindReq...)
	return berElement(0x30, msg)
}

func TestParseSimpleBind(t *testing.T) {
	raw := buildBindRequest(1, "cn=admin,dc=corp,dc=local", 0x80, []byte("S3cret!"))
	msg, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("readLDAPMessage: %v", err)
	}
	messageID, op, opTag, err := parseLDAPMessage(msg)
	if err != nil {
		t.Fatalf("parseLDAPMessage: %v", err)
	}
	if messageID != 1 {
		t.Fatalf("messageID = %d, want 1", messageID)
	}
	if opTag != 0x60 {
		t.Fatalf("opTag = 0x%02x, want 0x60", opTag)
	}
	bind, err := parseBindRequest(op)
	if err != nil {
		t.Fatalf("parseBindRequest: %v", err)
	}
	if bind.authType != authSimple {
		t.Fatalf("authType = %d, want authSimple", bind.authType)
	}
	if bind.name != "cn=admin,dc=corp,dc=local" {
		t.Fatalf("name = %q", bind.name)
	}
	if string(bind.simplePassword) != "S3cret!" {
		t.Fatalf("password = %q", bind.simplePassword)
	}
}

func TestParseSASLNTLMBind(t *testing.T) {
	type1 := ntlm.BuildType2(0, ntlm.DefaultChallenge) // any NTLMSSP blob works for detection
	sasl := berElement(0x04, []byte("GSS-SPNEGO"))
	sasl = append(sasl, berElement(0x04, type1)...)

	raw := buildBindRequest(2, "", 0xa3, sasl)
	msg, _ := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
	_, op, _, err := parseLDAPMessage(msg)
	if err != nil {
		t.Fatalf("parseLDAPMessage: %v", err)
	}
	bind, err := parseBindRequest(op)
	if err != nil {
		t.Fatalf("parseBindRequest: %v", err)
	}
	if bind.authType != authSASL {
		t.Fatalf("authType = %d, want authSASL", bind.authType)
	}
	if bind.saslMechanism != "GSS-SPNEGO" {
		t.Fatalf("mechanism = %q", bind.saslMechanism)
	}
	if _, _, ok := ntlm.MessageType(bind.saslCredentials); !ok {
		t.Fatal("NTLMSSP not detected in SASL credentials")
	}
}

func TestBuildBindResponseRoundTrip(t *testing.T) {
	resp := buildBindResponse(5, resultSaslBindInProgress, []byte{0xde, 0xad})
	// Outer SEQUENCE
	_, seq, _, err := tlv(resp, 0)
	if err != nil {
		t.Fatalf("tlv outer: %v", err)
	}
	idTag, idVal, next, err := tlv(seq, 0)
	if err != nil || idTag != 0x02 {
		t.Fatalf("message id element: tag=0x%02x err=%v", idTag, err)
	}
	if decodeInt(idVal) != 5 {
		t.Fatalf("messageID = %d, want 5", decodeInt(idVal))
	}
	opTag, op, _, err := tlv(seq, next)
	if err != nil || opTag != 0x61 {
		t.Fatalf("bind response tag = 0x%02x err=%v", opTag, err)
	}
	rcTag, rcVal, _, err := tlv(op, 0)
	if err != nil || rcTag != 0x0a {
		t.Fatalf("result code tag = 0x%02x err=%v", rcTag, err)
	}
	if int(rcVal[0]) != resultSaslBindInProgress {
		t.Fatalf("resultCode = %d, want %d", rcVal[0], resultSaslBindInProgress)
	}
}
