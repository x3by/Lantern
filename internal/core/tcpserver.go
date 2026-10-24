package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// ConnHandler processes a single accepted connection. It should return when the
// connection is finished; the server closes the connection afterwards.
type ConnHandler func(ctx context.Context, conn net.Conn)

// TCPServer is a reusable listener that binds a TCP port, accepts connections
// and dispatches each one to a handler in its own goroutine. Capture modules
// (FTP, SMTP, HTTP, ...) embed it so they only implement protocol logic.
type TCPServer struct {
	Service string
	Address string
	Port    int
	Logger  *Logger
	Handler ConnHandler

	mu       sync.Mutex
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// Start binds the port and begins accepting connections until ctx is cancelled.
func (s *TCPServer) Start(ctx context.Context, cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return fmt.Errorf("%s listener is already running", s.Service)
	}
	if s.Handler == nil {
		return fmt.Errorf("%s listener has no handler", s.Service)
	}

	bindAddress := s.Address
	if cfg.InterfaceAddress != "" {
		bindAddress = cfg.InterfaceAddress
	}
	address := net.JoinHostPort(bindAddress, strconv.Itoa(s.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("bind TCP %s: %w", address, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	s.listener = listener
	s.cancel = cancel
	s.log(Success, "Listening on %s", address)

	s.wg.Add(1)
	go s.serve(runCtx, listener)
	return nil
}

func (s *TCPServer) serve(ctx context.Context, listener net.Listener) {
	defer s.wg.Done()
	defer func() {
		_ = listener.Close()
		s.mu.Lock()
		if s.listener == listener {
			s.listener = nil
			s.cancel = nil
		}
		s.mu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log(Error, "Accept failed: %v", err)
			return
		}
		s.log(Info, "Incoming TCP connection from %s", conn.RemoteAddr())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.Handler(ctx, conn)
		}()
	}
}

// Stop closes the listener and waits for all handlers to return.
func (s *TCPServer) Stop() {
	s.mu.Lock()
	cancel, listener := s.cancel, s.listener
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	s.wg.Wait()
}

func (s *TCPServer) log(level Level, format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Print(level, s.Service, format, args...)
	}
}

// ClientIP returns the remote host of conn without the port.
func ClientIP(conn net.Conn) string {
	host := conn.RemoteAddr().String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// SetDeadline applies a read/write deadline to conn, honouring ctx's deadline
// when it is sooner than the fixed timeout.
func SetDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
}

// ErrClosed reports whether err indicates the listener/conn was closed.
func ErrClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
