package ftp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"lantern/internal/core"
)

func TestHandleCapturesCleartext(t *testing.T) {
	server, client := net.Pipe()
	m := New(core.NewLogger(true))

	done := make(chan struct{})
	go func() {
		m.handle(context.Background(), server)
		close(done)
	}()

	reader := bufio.NewReader(client)
	expect := func(prefix string) {
		t.Helper()
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("got %q, want prefix %q", line, prefix)
		}
	}

	expect("220") // greeting
	_, _ = client.Write([]byte("USER alice\r\n"))
	expect("331")
	_, _ = client.Write([]byte("PASS hunter2\r\n"))
	expect("530")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after PASS")
	}
}
