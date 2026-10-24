package core

import (
	"errors"
	"fmt"
	"strings"
)

var ErrHelp = errors.New("help requested")

type Config struct {
	Interface        string
	InterfaceAddress string
	Verbose          bool
	NoColor          bool

	DisabledServices  map[string]bool
	DisabledPoisoners map[string]bool
}

func DefaultConfig() Config {
	return Config{
		DisabledServices:  make(map[string]bool),
		DisabledPoisoners: make(map[string]bool),
	}
}

func ParseConfig(args []string, modules []Module) (Config, error) {
	cfg := DefaultConfig()
	known := make(map[string]bool)

	for _, m := range modules {
		name := strings.ToLower(strings.TrimSpace(m.Name()))

		if name == "" {
			return cfg, fmt.Errorf("module name cannot be empty")
		}
		if known[name] {
			return cfg, fmt.Errorf("duplicate module: %s", name)
		}

		known[name] = true
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--help", "-h":
			return cfg, ErrHelp
		case "--verbose", "-v":
			cfg.Verbose = true
		case "--no-color", "-c":
			cfg.NoColor = true
		case "--interface", "-i":
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("%s requires a value", arg)
			}
			i++
			cfg.Interface = args[i]
		case "-s", "-p":
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("%s requires a service name", arg)
			}
			i++
			name := strings.ToLower(args[i])
			if !known[name] {
				return cfg, fmt.Errorf("unknown service: %s", name)
			}
			if arg == "-s" {
				cfg.DisabledServices[name] = true
			} else {
				cfg.DisabledPoisoners[name] = true
			}
		default:
			if strings.HasPrefix(arg, "--interface=") || strings.HasPrefix(arg, "-i=") {
				cfg.Interface = strings.TrimPrefix(strings.TrimPrefix(arg, "--interface="), "-i=")
				if cfg.Interface == "" {
					return cfg, fmt.Errorf("%s requires a value", strings.SplitN(arg, "=", 2)[0])
				}
				continue
			}

			const poisonPrefix = "--no-poison-"
			const servicePrefix = "--no-"

			switch {
			case strings.HasPrefix(arg, poisonPrefix):
				name := strings.TrimPrefix(arg, poisonPrefix)
				if !known[name] {
					return cfg, fmt.Errorf("unknown poisoner: %s", name)
				}
				cfg.DisabledPoisoners[name] = true

			case strings.HasPrefix(arg, servicePrefix):
				name := strings.TrimPrefix(arg, servicePrefix)
				if !known[name] {
					return cfg, fmt.Errorf("unknown service: %s", name)
				}
				cfg.DisabledServices[name] = true

			default:
				return cfg, fmt.Errorf("unknown argument: %s", arg)
			}
		}
	}

	return cfg, nil
}
