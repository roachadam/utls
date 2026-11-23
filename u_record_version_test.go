package tls

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// recordVersionConn rewrites the version of one record the client reads: the
// nth record of type typ (counting from 1).
type recordVersionConn struct {
	net.Conn
	typ     recordType
	nth     int
	version uint16

	seen    int
	pending []byte
}

func (c *recordVersionConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		record := make([]byte, recordHeaderLen+int(binary.BigEndian.Uint16(hdr[3:])))
		copy(record, hdr[:])
		if _, err := io.ReadFull(c.Conn, record[recordHeaderLen:]); err != nil {
			return 0, err
		}
		if recordType(record[0]) == c.typ {
			if c.seen++; c.seen == c.nth {
				binary.BigEndian.PutUint16(record[1:], c.version)
			}
		}
		c.pending = record
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// helloRetryHandshake completes a handshake in which the server asks for P-256
// with a HelloRetryRequest, the client reading through conn.
func helloRetryHandshake(t *testing.T, wrap func(net.Conn) net.Conn) error {
	t.Helper()
	serverConfig := testConfigServer.Clone()
	serverConfig.CurvePreferences = []CurveID{CurveP256}
	serverConfig.MinVersion = VersionTLS13

	c, s := localPipe(t)
	client := UClient(wrap(c), &Config{InsecureSkipVerify: true, MinVersion: VersionTLS13}, HelloCustom)
	if err := client.ApplyPreset(keyShareTestSpec([]KeyShare{{Group: X25519}}, []CurveID{X25519, CurveP256})); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer s.Close()
		Server(s, serverConfig).Handshake()
	}()
	err := client.Handshake()
	c.Close()
	<-serverDone
	if err == nil && !client.ConnectionState().HelloRetryRequest {
		t.Fatal("server did not send a HelloRetryRequest")
	}
	return err
}

// The record carrying the ServerHello that answers a HelloRetryRequest is
// plaintext, and its version is neither authenticated nor hashed (RFC 8446,
// section 5.1: legacy_record_version is ignored). BoringSSL checks only its
// major version, and some servers send 0x0301. Encrypted records keep the
// exact check.
func TestPlaintextRecordVersionAfterHelloRetryRequest(t *testing.T) {
	for _, test := range []struct {
		name    string
		typ     recordType
		nth     int
		version uint16
		wantErr string
	}{
		{name: "ServerHello record 0x0301", typ: recordTypeHandshake, nth: 2, version: VersionTLS10},
		{name: "ServerHello record 0x0300", typ: recordTypeHandshake, nth: 2, version: VersionSSL30},
		{name: "ServerHello record 0x0401", typ: recordTypeHandshake, nth: 2, version: 0x0401, wantErr: "received record with version 401"},
		{name: "encrypted record 0x0301", typ: recordTypeApplicationData, nth: 1, version: VersionTLS10, wantErr: "received record with version 301"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := helloRetryHandshake(t, func(c net.Conn) net.Conn {
				return &recordVersionConn{Conn: c, typ: test.typ, nth: test.nth, version: test.version}
			})
			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("handshake failed: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("handshake error %v, want %q", err, test.wantErr)
			}
		})
	}
}
