package llmnr

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"lantern/internal/core"
)

const (
	ServiceName = "llmnr"
	DefaultPort = 5355
)

type Module struct {
	Address string
	Port    int
	Logger  *core.Logger

	// IPv4 da restituire nelle risposte.
	// Se vuoto, viene utilizzato l'indirizzo IPv4
	// configurato nell'interfaccia di ascolto.
	ResponseIP string

	// Nomi autorizzati a ricevere una risposta.
	// Le chiavi vengono confrontate senza distinzione
	// tra maiuscole e minuscole.
	AllowedNames []string

	mu     sync.Mutex
	conn   *net.UDPConn
	cancel context.CancelFunc
}

func New(logger *core.Logger) *Module {
	return &Module{
		Address:      "0.0.0.0",
		Port:         DefaultPort,
		Logger:       logger,
		ResponseIP:   "",
		AllowedNames: []string{"testhost"},
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
	return fmt.Errorf("LLMNR poisoning is not supported")
}

func (m *Module) StartListener(
	ctx context.Context,
	cfg core.Config,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn != nil {
		return fmt.Errorf("LLMNR listener is already running")
	}

	bindAddress := m.Address
	if cfg.InterfaceAddress != "" {
		bindAddress = cfg.InterfaceAddress
	}

	addr := net.JoinHostPort(
		bindAddress,
		fmt.Sprint(m.Port),
	)

	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("resolve listen address: %w", err)
	}

	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("bind UDP %s: %w", addr, err)
	}

	runCtx, cancel := context.WithCancel(ctx)

	m.conn = conn
	m.cancel = cancel

	go m.serve(runCtx, conn)

	return nil
}

func (m *Module) StopListener() error {
	m.mu.Lock()

	conn := m.conn
	cancel := m.cancel

	if cancel != nil {
		cancel()
	}

	m.mu.Unlock()

	if conn != nil {
		return conn.Close()
	}

	return nil
}

func (m *Module) serve(
	ctx context.Context,
	conn *net.UDPConn,
) {
	defer func() {
		_ = conn.Close()

		m.mu.Lock()
		if m.conn == conn {
			m.conn = nil
			m.cancel = nil
		}
		m.mu.Unlock()
	}()

	// Interrompe ReadFromUDP quando il contesto termina.
	go func() {
		<-ctx.Done()
		_ = conn.SetReadDeadline(time.Now())
	}()

	buf := make([]byte, 4096)

	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}

			m.packet("ERROR", "UDP receive error: %v", err)
			return
		}

		msg, err := parseQuery(buf[:n])
		if err != nil {
			m.packet(
				"INVALID",
				"Packet from %s: %v",
				peer,
				err,
			)
			continue
		}

		m.packet(
			"QUERY",
			"from=%s name=%q type=%d id=0x%04x",
			peer,
			msg.Name,
			msg.Type,
			msg.ID,
		)

		// Questo esempio risponde esclusivamente ai nomi
		// configurati nella allowlist.
		if !m.isAllowed(msg.Name) {
			continue
		}

		// Gestisce esclusivamente query IPv4 di tipo A.
		if msg.Type != 1 {
			continue
		}

		ip, err := m.responseIPv4()
		if err != nil {
			m.packet("ERROR", "Response IP: %v", err)
			continue
		}

		response, err := buildResponse(buf[:n], ip)
		if err != nil {
			m.packet("ERROR", "Build response: %v", err)
			continue
		}

		if _, err := conn.WriteToUDP(response, peer); err != nil {
			m.packet(
				"ERROR",
				"Send response to %s: %v",
				peer,
				err,
			)
			continue
		}

		m.packet(
			"RESPONSE",
			"to=%s name=%q ip=%s",
			peer,
			msg.Name,
			ip.String(),
		)
	}
}

func (m *Module) isAllowed(name string) bool {
	name = strings.TrimSuffix(
		strings.ToLower(name),
		".",
	)

	for _, allowed := range m.AllowedNames {
		allowed = strings.TrimSuffix(
			strings.ToLower(strings.TrimSpace(allowed)),
			".",
		)

		if name == allowed {
			return true
		}
	}

	return false
}

func (m *Module) responseIPv4() (net.IP, error) {
	if m.ResponseIP != "" {
		ip := net.ParseIP(m.ResponseIP)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf(
				"invalid IPv4 address %q",
				m.ResponseIP,
			)
		}

		return ip.To4(), nil
	}

	// Se l'indirizzo di bind è specifico, può essere
	// utilizzato come indirizzo da restituire.
	if m.Address != "" && m.Address != "0.0.0.0" {
		ip := net.ParseIP(m.Address)
		if ip != nil && ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	return nil, fmt.Errorf(
		"ResponseIP must be configured when listening on 0.0.0.0",
	)
}

func (m *Module) packet(
	packetType string,
	format string,
	args ...any,
) {
	if m.Logger != nil {
		m.Logger.Packet(
			ServiceName,
			packetType,
			format,
			args...,
		)
	}
}

type Query struct {
	ID   uint16
	Name string
	Type uint16
}

func parseQuery(packet []byte) (*Query, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("DNS header is incomplete")
	}

	q := &Query{
		ID: binary.BigEndian.Uint16(packet[0:2]),
	}

	flags := binary.BigEndian.Uint16(packet[2:4])
	qdCount := binary.BigEndian.Uint16(packet[4:6])

	// QR deve essere 0: il pacchetto deve essere una query.
	if flags&0x8000 != 0 {
		return nil, fmt.Errorf("packet is not a query")
	}

	// LLMNR non deve ricevere risposte a pacchetti
	// con più domande in questo parser minimale.
	if qdCount != 1 {
		return nil, fmt.Errorf(
			"expected one question, got %d",
			qdCount,
		)
	}

	name, next, err := decodeName(packet, 12)
	if err != nil {
		return nil, err
	}

	if next+4 > len(packet) {
		return nil, fmt.Errorf("question is incomplete")
	}

	q.Name = name
	q.Type = binary.BigEndian.Uint16(
		packet[next : next+2],
	)

	qclass := binary.BigEndian.Uint16(
		packet[next+2 : next+4],
	)

	// Classe IN.
	if qclass != 1 {
		return nil, fmt.Errorf(
			"unsupported question class: %d",
			qclass,
		)
	}

	return q, nil
}

func buildResponse(
	packet []byte,
	ip net.IP,
) ([]byte, error) {
	q, err := parseQuery(packet)
	if err != nil {
		return nil, err
	}

	if q.Type != 1 {
		return nil, fmt.Errorf(
			"unsupported query type: %d",
			q.Type,
		)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	_, next, err := decodeName(packet, 12)
	if err != nil {
		return nil, err
	}

	questionEnd := next + 4
	if questionEnd > len(packet) {
		return nil, fmt.Errorf("incomplete question")
	}

	response := make([]byte, 0, questionEnd+16)

	// Transaction ID della query.
	response = append(response, packet[0:2]...)

	// QR=1, AA=1, RCODE=0.
	response = append(response, 0x84, 0x00)

	// QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0.
	response = append(response, 0x00, 0x01)
	response = append(response, 0x00, 0x01)
	response = append(response, 0x00, 0x00)
	response = append(response, 0x00, 0x00)

	// Copia la domanda originale.
	response = append(
		response,
		packet[12:questionEnd]...,
	)

	// Answer name: puntatore al nome nella domanda.
	response = append(response, 0xC0, 0x0C)

	// TYPE=A, CLASS=IN.
	response = append(response, 0x00, 0x01)
	response = append(response, 0x00, 0x01)

	// TTL: 30 secondi.
	response = append(
		response,
		0x00, 0x00, 0x00, 0x1E,
	)

	// RDLENGTH=4 e indirizzo IPv4.
	response = append(response, 0x00, 0x04)
	response = append(response, ip4...)

	return response, nil
}

func decodeName(
	packet []byte,
	offset int,
) (string, int, error) {
	var labels []string

	for {
		if offset >= len(packet) {
			return "", 0, fmt.Errorf(
				"name exceeds packet",
			)
		}

		size := int(packet[offset])
		offset++

		if size == 0 {
			break
		}

		// I puntatori di compressione non sono accettati
		// nel nome della domanda.
		if size&0xC0 != 0 {
			return "", 0, fmt.Errorf(
				"unsupported compressed name",
			)
		}

		if size > 63 || offset+size > len(packet) {
			return "", 0, fmt.Errorf(
				"invalid label length",
			)
		}

		label := string(packet[offset : offset+size])

		if strings.ContainsRune(label, '.') {
			return "", 0, fmt.Errorf("invalid label")
		}

		labels = append(labels, label)
		offset += size

		if len(labels) > 127 {
			return "", 0, fmt.Errorf(
				"too many labels",
			)
		}
	}

	return strings.Join(labels, "."), offset, nil
}
