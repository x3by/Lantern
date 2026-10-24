package mssql

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestConnectionEncryptionModes(t *testing.T) {
	tests := []struct {
		name                 string
		clientEncryption     byte
		wantServerEncryption byte
		useTLS               bool
		fullTLS              bool
		tlsForOptional       bool
		maxTLSVersion        uint16
	}{
		{name: "unencrypted", clientEncryption: 0x02, wantServerEncryption: 0x02},
		{name: "optional encryption defaults to clear", clientEncryption: 0x00, wantServerEncryption: 0x02},
		{name: "login-only TLS when enabled", clientEncryption: 0x00, wantServerEncryption: 0x00, useTLS: true, tlsForOptional: true, maxTLSVersion: tls.VersionTLS10},
		{name: "full TLS", clientEncryption: 0x01, wantServerEncryption: 0x01, useTLS: true, fullTLS: true, maxTLSVersion: tls.VersionTLS12},
		{name: "TLS required", clientEncryption: 0x03, wantServerEncryption: 0x01, useTLS: true, fullTLS: true, maxTLSVersion: tls.VersionTLS12},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module := New(nil)
			module.TLSForOptionalEncryption = test.tlsForOptional
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server, conn := net.Pipe()
			defer server.Close()
			defer conn.Close()
			go module.handleConnection(ctx, server)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

			if err := writePacket(conn, tdsPrelogin, clientPrelogin(test.clientEncryption)); err != nil {
				t.Fatal(err)
			}
			packetType, response, err := readMessage(conn)
			if err != nil {
				t.Fatalf("read PRELOGIN response: %v", err)
			}
			if packetType != tdsResponse {
				t.Fatalf("PRELOGIN response type = 0x%02x, want 0x04", packetType)
			}
			options, err := parsePrelogin(response)
			if err != nil {
				t.Fatalf("parse PRELOGIN response: %v", err)
			}
			if got := options[0x01]; len(got) != 1 || got[0] != test.wantServerEncryption {
				t.Fatalf("encryption option = %v, want [%d]", got, test.wantServerEncryption)
			}

			var loginConn net.Conn = conn
			var tlsTransport *tdsTLSConn
			if test.useTLS {
				tlsTransport = &tdsTLSConn{Conn: conn, framed: true}
				tlsConfig := &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS10,
					MaxVersion:         test.maxTLSVersion,
				}
				if test.maxTLSVersion == tls.VersionTLS10 {
					tlsConfig.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA}
				}
				secureConn := tls.Client(tlsTransport, tlsConfig)
				if err := secureConn.Handshake(); err != nil {
					t.Fatalf("TLS handshake: %v", err)
				}
				tlsTransport.switchToRawTLS()
				loginConn = secureConn
			}

			if err := writePacket(loginConn, tdsLogin7, clientLogin7("workstation", "alice", "app", "db")); err != nil {
				t.Fatal(err)
			}
			responseConn := loginConn
			if test.useTLS && !test.fullTLS {
				responseConn = conn
			}
			packetType, response, err = readMessage(responseConn)
			if err != nil {
				t.Fatalf("read LOGIN7 response: %v", err)
			}
			if packetType != tdsResponse {
				t.Fatalf("LOGIN7 response type = 0x%02x, want 0x04", packetType)
			}
			if len(response) < 3 || response[0] != 0xaa {
				t.Fatalf("LOGIN7 response does not start with ERROR token: %x", response)
			}
			if got := binary.LittleEndian.Uint32(response[3:7]); got != 18456 {
				t.Fatalf("SQL error number = %d, want 18456", got)
			}
			errorLength := int(binary.LittleEndian.Uint16(response[1:3]))
			doneOffset := 3 + errorLength
			if doneOffset >= len(response) || response[doneOffset] != 0xfd {
				t.Fatalf("LOGIN7 response is missing DONE token: %x", response)
			}
			if got, want := len(response)-doneOffset, 13; got != want {
				t.Fatalf("DONE token length = %d, want %d", got, want)
			}
		})
	}
}

func TestLoginFailedResponseDoneWidths(t *testing.T) {
	for _, test := range []struct {
		version uint32
		want    int
	}{
		{version: 0x71, want: 9},
		{version: 0x74000004, want: 13},
	} {
		response := buildLoginFailedResponse(test.version)
		doneOffset := 3 + int(binary.LittleEndian.Uint16(response[1:3]))
		if doneOffset >= len(response) || response[doneOffset] != 0xfd {
			t.Fatalf("TDS version 0x%x response is missing DONE: %x", test.version, response)
		}
		if got := len(response) - doneOffset; got != test.want {
			t.Errorf("TDS version 0x%x DONE length = %d, want %d", test.version, got, test.want)
		}
	}
}

func TestParseLogin7Identity(t *testing.T) {
	identity, err := parseLogin7(clientLogin7("host-1", "user-1", "client-app", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.hostname != "host-1" || identity.username != "user-1" || identity.app != "client-app" || identity.database != "catalog" {
		t.Fatalf("parsed identity = %+v", identity)
	}
}

func TestParseLogin7LegacyIdentity(t *testing.T) {
	identity, err := parseLogin7(clientLogin7WithHeader(86, 0x71, "host-1", "user-1", "client-app", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.hostname != "host-1" || identity.username != "user-1" || identity.app != "client-app" || identity.database != "catalog" {
		t.Fatalf("parsed legacy identity = %+v", identity)
	}
}

func clientPrelogin(encryption byte) []byte {
	const tableSize = 16
	data := make([]byte, tableSize+8)
	data[0] = 0x00
	binary.BigEndian.PutUint16(data[1:3], tableSize)
	binary.BigEndian.PutUint16(data[3:5], 6)
	data[5] = 0x01
	binary.BigEndian.PutUint16(data[6:8], tableSize+6)
	binary.BigEndian.PutUint16(data[8:10], 1)
	data[10] = 0x04
	binary.BigEndian.PutUint16(data[11:13], tableSize+7)
	binary.BigEndian.PutUint16(data[13:15], 1)
	data[15] = 0xff
	data[tableSize+6] = encryption
	return data
}

func clientLogin7(hostname, username, app, database string) []byte {
	return clientLogin7WithHeader(94, 0x74000004, hostname, username, app, database)
}

func clientLogin7WithHeader(headerLength int, tdsVersion uint32, hostname, username, app, database string) []byte {
	data := make([]byte, headerLength)
	binary.BigEndian.PutUint32(data[4:8], tdsVersion)
	fields := []struct {
		value      string
		offsetSlot int
		lengthSlot int
	}{
		{hostname, 36, 38},
		{username, 40, 42},
		{app, 48, 50},
		{database, 68, 70},
	}
	for _, field := range fields {
		encoded := encodeUTF16LE(field.value)
		binary.LittleEndian.PutUint16(data[field.offsetSlot:field.offsetSlot+2], uint16(len(data)))
		binary.LittleEndian.PutUint16(data[field.lengthSlot:field.lengthSlot+2], uint16(len(encoded)/2))
		data = append(data, encoded...)
	}
	binary.LittleEndian.PutUint32(data[:4], uint32(len(data)))
	return data
}

func TestReadMessageRejectsShortPacket(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte{tdsPrelogin, tdsEndOfMessage, 0, 7, 0, 0, 1})
	}()
	if _, _, err := readMessage(server); err == nil {
		t.Fatal("readMessage accepted a packet shorter than its header")
	}
}
