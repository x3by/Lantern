package core

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type Printer struct {
	out   io.Writer
	color bool
}

func NewPrinter(noColor bool) *Printer {
	return &Printer{
		out:   os.Stdout,
		color: !noColor,
	}
}

func (p *Printer) paint(code, value string) string {
	if !p.color {
		return value
	}
	return "\033[" + code + "m" + value + "\033[0m"
}

func (p *Printer) Info(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n",
		p.paint("36", "[*]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Success(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n",
		p.paint("32", "[+ ]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Warn(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n",
		p.paint("33", "[!]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Error(format string, args ...any) {
	fmt.Fprintf(p.out, "%s %s\n",
		p.paint("31", "[-]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Banner(modules []Module, cfg Config) {
	fmt.Fprintln(p.out, p.paint("36;1",
		"  _                    _"))
	fmt.Fprintln(p.out, p.paint("36;1",
		" | |    __ _ _ __   ___| |_ ___ _ __"))
	fmt.Fprintln(p.out, p.paint("36;1",
		" | |   / _` | '_ \\ / __| __/ _ \\ '__|"))
	fmt.Fprintln(p.out, p.paint("36;1",
		" | |__| (_| | | | | (__| ||  __/ |"))
	fmt.Fprintln(p.out, p.paint("36;1",
		" |_____\\__,_|_| |_|\\___|\\__\\___|_|"))
	fmt.Fprintln(p.out, p.paint("90", "  Lantern — modular network service framework"))
	fmt.Fprintln(p.out)

	fmt.Fprintf(p.out, "%-12s %-14s %-14s\n",
		"SERVICE", "LISTENER", "POISONER")
	fmt.Fprintln(p.out, strings.Repeat("-", 42))

	for _, m := range modules {
		name := strings.ToLower(m.Name())
		listener := "—"
		poisoner := "—"

		if m.HasListener() {
			listener = "LISTENER"
			if cfg.DisabledServices[name] {
				listener = "DISABLED"
			}
		}
		if m.HasPoisoner() {
			poisoner = "POISONER"
			if cfg.DisabledPoisoners[name] {
				poisoner = "DISABLED"
			}
		}

		fmt.Fprintf(p.out, "%-12s %-14s %-14s\n",
			strings.ToUpper(name), listener, poisoner)
	}
	fmt.Fprintln(p.out)
}
