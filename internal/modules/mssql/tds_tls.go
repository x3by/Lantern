package mssql

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"time"
)

const maxTDSPacketPayload = 0xffff - packetHeaderSize

// tdsTLSConn adapts TLS records to the PRELOGIN packet framing used by TDS.
type tdsTLSConn struct {
	net.Conn
	readBuffer []byte
	packetID   byte
	framed     bool
}

func (c *tdsTLSConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.framed {
		return c.Conn.Read(p)
	}
	for len(c.readBuffer) == 0 {
		var header [packetHeaderSize]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		if header[0] != tdsPrelogin {
			return 0, errors.New("expected TDS PRELOGIN packet carrying TLS data")
		}
		length := int(binary.BigEndian.Uint16(header[2:4]))
		if length < packetHeaderSize {
			return 0, errors.New("invalid TDS TLS packet length")
		}
		c.readBuffer = make([]byte, length-packetHeaderSize)
		if _, err := io.ReadFull(c.Conn, c.readBuffer); err != nil {
			c.readBuffer = nil
			return 0, err
		}
	}
	n := copy(p, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return n, nil
}

func (c *tdsTLSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.framed {
		return c.Conn.Write(p)
	}
	total := len(p)
	for len(p) > 0 {
		chunkLength := min(len(p), maxTDSPacketPayload)
		packet := make([]byte, packetHeaderSize+chunkLength)
		packet[0] = tdsPrelogin
		packet[1] = tdsEndOfMessage
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		c.packetID++
		packet[6] = c.packetID
		copy(packet[packetHeaderSize:], p[:chunkLength])
		if err := writeAll(c.Conn, packet); err != nil {
			return total - len(p), err
		}
		p = p[chunkLength:]
	}
	return total, nil
}

func (c *tdsTLSConn) switchToRawTLS() {
	c.framed = false
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func (m *Module) serverTLSConfig() (*tls.Config, error) {
	m.tlsOnce.Do(func() {
		if m.TLSConfig != nil {
			m.tlsConfig = m.TLSConfig.Clone()
			return
		}
		m.tlsConfig, m.tlsErr = newTDSTLSConfig()
	})
	return m.tlsConfig, m.tlsErr
}

func newTDSTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Lantern MSSQL"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: template}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		},
	}, nil
}
