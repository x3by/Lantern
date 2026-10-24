package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"lantern/internal/core"
	"lantern/internal/modules/llmnr"
	"lantern/internal/modules/mssql"
	"lantern/internal/modules/smb"
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

	if err := app.Register(smb.New(app.Printer())); err != nil {
		fmt.Fprintf(os.Stderr, "lantern: %v\n", err)
		os.Exit(1)
	}
	if err := app.Register(mssql.New(app.Printer())); err != nil {
		fmt.Fprintf(os.Stderr, "lantern: %v\n", err)
		os.Exit(1)
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
	for _, module := range app.Modules {
		if m, ok := module.(*smb.Module); ok {
			m.Logger = app.Printer()
		}
		if m, ok := module.(*llmnr.Module); ok {
			m.Logger = app.Printer()
		}
		if m, ok := module.(*mssql.Module); ok {
			m.Logger = app.Printer()
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
