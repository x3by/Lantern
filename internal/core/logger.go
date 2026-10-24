package core

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	Info Level = iota
	Success
	Warning
	Error
	Protocol
)

type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	color bool
}

func NewLogger(noColor bool) *Logger {
	return &Logger{
		out:   os.Stdout,
		color: !noColor,
	}
}

func (l *Logger) paint(code, value string) string {
	if !l.color {
		return value
	}
	return "\033[" + code + "m" + value + "\033[0m"
}

func (l *Logger) field(code, value string) string {
	return l.paint("37", "[") + l.paint(code, value) + l.paint("37", "]")
}

// Packet writes protocol events in the shared timestamp/service/type format.
func (l *Logger) Packet(service, packetType, format string, args ...any) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s %s %s %s\n",
		l.field("37;1", timestamp),
		l.field("34;1", strings.ToUpper(service)),
		l.field("38;5;208", strings.ToUpper(packetType)),
		message)
}

func (l *Logger) Print(level Level, service, format string, args ...any) {
	styles := map[Level]struct {
		label string
		code  string
	}{
		Info:     {"[*]", "36"},
		Success:  {"[+]", "32;1"},
		Warning:  {"[!]", "33;1"},
		Error:    {"[-]", "31;1"},
		Protocol: {"[>]", "35;1"},
	}

	style, ok := styles[level]
	if !ok {
		style = styles[Info]
	}

	message := fmt.Sprintf(format, args...)
	prefix := l.paint(style.code, style.label)

	l.mu.Lock()
	defer l.mu.Unlock()

	if service != "" {
		fmt.Fprintf(l.out, "%s %-6s %s\n",
			prefix, "["+strings.ToUpper(service)+"]", message)
		return
	}

	fmt.Fprintf(l.out, "%s %s\n", prefix, message)
}

// PrintHighlighted writes a multiline message with the selected level's color.
func (l *Logger) PrintHighlighted(level Level, service, format string, args ...any) {
	styles := map[Level]struct {
		label string
		code  string
	}{
		Info: {"[*]", "36"}, Success: {"[+]", "32;1"},
		Warning: {"[!]", "33;1"}, Error: {"[-]", "31;1"},
		Protocol: {"[>]", "35;1"},
	}
	style, ok := styles[level]
	if !ok {
		style = styles[Info]
	}

	message := fmt.Sprintf(format, args...)
	prefix := style.label
	if service != "" {
		message = "[" + strings.ToUpper(service) + "] " + message
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, l.paint(style.code, prefix+" "+message))
}

func (l *Logger) Banner(modules []Module, cfg Config) {
	l.mu.Lock()
	defer l.mu.Unlock()

	lines := []string{
		"  _                    _",
		" | |    __ _ _ __   ___| |_ ___ _ __",
		" | |   / _` | '_ \\ / __| __/ _ \\ '__|",
		" | |__| (_| | | | | (__| ||  __/ |",
		" |_____\\__,_|_| |_|\\___|\\__\\___|_|",
	}

	for _, line := range lines {
		fmt.Fprintln(l.out, l.paint("36;1", line))
	}

	fmt.Fprintln(l.out, l.paint("90",
		"  Lantern - Modular Network Service Framework"))
	if cfg.Interface != "" {
		fmt.Fprintf(l.out, "  Listen target: %s (%s)\n", cfg.Interface, cfg.InterfaceAddress)
	}
	fmt.Fprintln(l.out)

	fmt.Fprintf(l.out, "%-12s %-20s %s\n",
		"SERVICE", "LISTENER", "POISONER")
	fmt.Fprintln(l.out, strings.Repeat("-", 49))

	for _, m := range modules {
		name := strings.ToLower(m.Name())

		listener := l.paint("90", "NOT SUPPORTED")
		poisoner := l.paint("90", "NOT SUPPORTED")

		if m.HasListener() {
			listener = l.paint("32;1", "ENABLED")
			if cfg.DisabledServices[name] {
				listener = l.paint("31;1", "DISABLED")
			}
		}

		if m.HasPoisoner() {
			poisoner = l.paint("32;1", "ENABLED")
			if cfg.DisabledPoisoners[name] {
				poisoner = l.paint("31;1", "DISABLED")
			}
		}

		fmt.Fprintf(l.out, "%-12s %-20s %s\n",
			strings.ToUpper(name), listener, poisoner)
	}

	fmt.Fprintln(l.out)
}
