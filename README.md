# Lantern

Lantern is a small, modular network service framework written in Go. It is a
Responder-style credential-capture toolkit: each module runs a rogue service
listener and/or a name-service poisoner.

## Modules

| Module | Port | Listener | Poisoner | Captures |
| ------ | ---- | -------- | -------- | -------- |
| LLMNR  | UDP 5355 | ✓ | — | Answers allow-listed name queries |
| NBT-NS | UDP 137  | — | ✓ | Poisons NetBIOS name queries with Lantern's IP |
| SMB    | TCP 445  | ✓ | — | NetNTLMv1/v2 (NTLMSSP) |
| MSSQL  | TCP 1433 | ✓ | — | SQL / integrated login (TDS, incl. TLS) |
| HTTP   | TCP 80   | ✓ | — | NetNTLM (NTLM/Negotiate), HTTP Basic, serves WPAD |
| LDAP   | TCP 389  | ✓ | — | Simple-bind cleartext, NTLM/GSS-SPNEGO SASL bind |
| FTP    | TCP 21   | ✓ | — | Cleartext USER/PASS |
| SMTP   | TCP 25   | ✓ | — | AUTH PLAIN / AUTH LOGIN cleartext |
| POP3   | TCP 110  | ✓ | — | USER/PASS, AUTH PLAIN / LOGIN cleartext |
| IMAP   | TCP 143  | ✓ | — | LOGIN, AUTHENTICATE PLAIN / LOGIN cleartext |

Shared NTLMSSP handling (Type 2 challenge generation and Type 3 parsing into a
hashcat/john-ready NetNTLM line) lives in `internal/ntlm`. The poisoner and the
HTTP WPAD response advertise the IPv4 address selected with `-i`, or an
auto-detected non-loopback address when none is given.

Most services bind privileged ports, so run Lantern as root (or grant the
`cap_net_bind_service` capability).

## Requirements

- Go 1.27.2 or newer
- Linux or Windows

## Build

Build for the current operating system and architecture:

```sh
go build -o lantern ./cmd/lantern
```

### Linux static binary

The listeners use Go's standard library and do not require cgo. Disable cgo and build a stripped Linux binary:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o lantern ./cmd/lantern
```

For 64-bit ARM Linux, replace `GOARCH=amd64` with `GOARCH=arm64`. The output is a Linux executable; it will not run on Windows.

### Windows binary

Build a Windows x64 executable from Linux:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o lantern.exe ./cmd/lantern
```

For Windows on ARM64, use `GOARCH=arm64`. Run the resulting `.exe` on Windows; cross-compiling does not make it runnable on Linux.

## Usage

Run `./lantern --help` (or `lantern.exe --help`) to see the command options. The current command-line interface is:

```text
lantern [options]
  -i, --interface VALUE  Listen on an interface name or IPv4 address
  -v, --verbose          Enable verbose logging
  -c, --no-color         Disable ANSI colors
  -s SERVICE             Disable a service listener
  -p SERVICE             Disable a service poisoner
  --no-SERVICE           Disable a service listener
  --no-poison-SERVICE    Disable a service poisoner
  -h, --help             Show help
```

Examples:

```sh
# Listen using the selected interface's IPv4 address
sudo ./lantern --interface eth0

# Bind to a specific IPv4 address and turn off colored output
sudo ./lantern -i 192.0.2.10 --no-color

# Start without the SMB listener
sudo ./lantern --no-smb
```

Services bind to their standard ports: LLMNR UDP/5355, SMB TCP/445, and MSSQL TCP/1433. Binding to ports below 1024 on Linux generally requires elevated privileges or suitable capabilities.

## Writing a custom module

Modules implement `core.Module`, report whether they provide a listener or poisoner, and start each supported component. `StartPoisoner` is still required by the interface even when a module returns `false` from `HasPoisoner`.

```go
package example

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"lantern/internal/core"
)

type Module struct {
	Address string
	Port    int
	Logger  *core.Logger
}

func New(logger *core.Logger) *Module {
	return &Module{Address: "0.0.0.0", Port: 9000, Logger: logger}
}

func (m *Module) Name() string      { return "example" }
func (m *Module) HasListener() bool { return true }
func (m *Module) HasPoisoner() bool { return false }

func (m *Module) StartListener(ctx context.Context, cfg core.Config) error {
	address := m.Address
	if cfg.InterfaceAddress != "" {
		address = cfg.InterfaceAddress
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(m.Port)))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // shutdown closes the listener
			}
			_ = conn.Close()
		}
	}()
	return nil
}

func (m *Module) StartPoisoner(context.Context, core.Config) error {
	return fmt.Errorf("example poisoning is not supported")
}
```

The `internal` Go package rule means custom modules must be added inside this repository (for example under `internal/modules/example`) to import `lantern/internal/core`. Register the module in `cmd/lantern/main.go` before `ParseConfig`:

```go
if err := app.Register(example.New(app.Printer())); err != nil {
	fmt.Fprintf(os.Stderr, "lantern: %v\\n", err)
	os.Exit(1)
}
```

The name returned by `Name()` is used for service selection flags such as `--no-example`; keep it unique and lowercase. Use `cfg.InterfaceAddress` when set so the module honors `--interface`. Return startup errors from bind/setup operations so the core can report them. If implementing a listener loop, close the listener when `ctx` is cancelled and handle connection errors without blocking shutdown.
