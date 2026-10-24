package core

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type Core struct {
	Config  Config
	Modules []Module
	Logger  *Logger
}

func New(cfg Config) *Core {
	return &Core{
		Config:  cfg,
		Modules: make([]Module, 0),
		Logger:  NewLogger(cfg.NoColor),
	}
}

func (c *Core) Printer() *Logger {
	return c.Logger
}

func (c *Core) Register(m Module) error {
	if m == nil {
		return fmt.Errorf("cannot register a nil module")
	}

	name := strings.ToLower(strings.TrimSpace(m.Name()))
	if name == "" {
		return fmt.Errorf("module name cannot be empty")
	}

	for _, existing := range c.Modules {
		if strings.EqualFold(existing.Name(), name) {
			return fmt.Errorf("duplicate module: %s", name)
		}
	}

	c.Modules = append(c.Modules, m)
	return nil
}

func (c *Core) Validate() error {
	seen := make(map[string]bool)

	for _, m := range c.Modules {
		name := strings.ToLower(strings.TrimSpace(m.Name()))

		if name == "" {
			return fmt.Errorf("module name cannot be empty")
		}
		if seen[name] {
			return fmt.Errorf("duplicate module: %s", name)
		}

		seen[name] = true
	}

	return nil
}

func (c *Core) Run(ctx context.Context) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := c.resolveInterface(); err != nil {
		return err
	}

	c.Logger.Banner(c.Modules, c.Config)

	for _, m := range c.Modules {
		name := strings.ToLower(m.Name())

		if m.HasListener() && !c.Config.DisabledServices[name] {
			if err := m.StartListener(ctx, c.Config); err != nil {
				c.Logger.Print(Error, name,
					"Listener failed: %v", err)
				continue
			}

			c.Logger.Print(Success, name, "Listener started")
		}

		if m.HasPoisoner() && !c.Config.DisabledPoisoners[name] {
			if err := m.StartPoisoner(ctx, c.Config); err != nil {
				c.Logger.Print(Error, name,
					"Poisoner failed: %v", err)
				continue
			}

			c.Logger.Print(Success, name, "Poisoner started")
		}
	}

	c.Logger.Print(Info, "", "Initialization complete. Waiting for shutdown.")

	<-ctx.Done()

	c.Logger.Print(Info, "", "Shutdown requested.")
	return nil
}

func (c *Core) resolveInterface() error {
	name := strings.TrimSpace(c.Config.Interface)
	if name == "" {
		return nil
	}
	if ip := net.ParseIP(name); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("interface address %q must be IPv4", name)
		}
		c.Config.InterfaceAddress = ip.To4().String()
		return nil
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("read addresses for interface %q: %w", name, err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil {
			c.Config.InterfaceAddress = ip.To4().String()
			return nil
		}
	}
	return fmt.Errorf("interface %q has no IPv4 address", name)
}
