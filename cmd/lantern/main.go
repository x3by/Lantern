package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"lantern/internal/core"
	"lantern/internal/modules/ftp"
	httpmod "lantern/internal/modules/http"
	"lantern/internal/modules/imap"
	"lantern/internal/modules/ldap"
	"lantern/internal/modules/llmnr"
	"lantern/internal/modules/mssql"
	"lantern/internal/modules/nbtns"
	"lantern/internal/modules/pop3"
	"lantern/internal/modules/smb"
	"lantern/internal/modules/smtp"
)

func main() {
	// Create the core first so modules can share its logger.
	cfg := core.DefaultConfig()
	app := core.New(cfg)

	// Register modules before parsing flags.
	if err := app.Register(llmnr.New(app.Printer())); err != nil {
		fmt.Fprintf(os.Stderr, "lantern: %v\n", err)
		os.Exit(1)
	}

	// Register every service listener and poisoner. A registration failure is
	// a programming error (duplicate name), so abort immediately.
	for _, module := range []core.Module{
		smb.New(app.Printer()),
		mssql.New(app.Printer()),
		httpmod.New(app.Printer()),
		ftp.New(app.Printer()),
		smtp.New(app.Printer()),
		pop3.New(app.Printer()),
		imap.New(app.Printer()),
		ldap.New(app.Printer()),
		nbtns.New(app.Printer()),
	} {
		if err := app.Register(module); err != nil {
			fmt.Fprintf(os.Stderr, "lantern: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse arguments against the registered module list.
	cfg, err := core.ParseConfig(os.Args[1:], app.Modules)
	if errors.Is(err, core.ErrHelp) {
		printHelp()
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "lantern: %v\n", err)
		os.Exit(2)
	}

	// Apply the parsed configuration and refresh the logger.
	app.Config = cfg
	app.Logger = core.NewLogger(cfg.NoColor)

	// Update modules that hold a reference to the shared logger.
	logger := app.Printer()
	for _, module := range app.Modules {
		switch m := module.(type) {
		case *smb.Module:
			m.Logger = logger
		case *llmnr.Module:
			m.Logger = logger
		case *mssql.Module:
			m.Logger = logger
		case *httpmod.Module:
			m.Logger = logger
		case *ftp.Module:
			m.Logger = logger
		case *smtp.Module:
			m.Logger = logger
		case *pop3.Module:
			m.Logger = logger
		case *imap.Module:
			m.Logger = logger
		case *ldap.Module:
			m.Logger = logger
		case *nbtns.Module:
			m.Logger = logger
		}
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := app.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "lantern: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Lantern - modular network service framework")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  lantern [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -i, --interface VALUE  Listen on an interface name or IPv4 address")
	fmt.Println("  -v, --verbose          Enable verbose logging")
	fmt.Println("  -c, --no-color         Disable ANSI colors")
	fmt.Println("  -s SERVICE             Disable a service listener")
	fmt.Println("  -p SERVICE             Disable a service poisoner")
	fmt.Println("  --no-SERVICE           Disable a service listener")
	fmt.Println("  --no-poison-SERVICE    Disable a service poisoner")
	fmt.Println("  -h, --help             Show this help")
}
