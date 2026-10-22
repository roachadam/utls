package tls

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// helloRetryWithCookie plays a server that answers the first ClientHello with a
// HelloRetryRequest carrying only a cookie, then reads the second ClientHello
// and hangs up. It returns the client's extensions as sent in that second hello.
func helloRetryWithCookie(t *testing.T, client func(net.Conn) *UConn) []TLSExtension {
	t.Helper()
	clientConn, serverConn := localPipe(t)
	defer serverConn.Close()
	uconn := client(clientConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		uconn.Handshake() // fails once the server hangs up
	}()

	readRecord := func(wantType recordType) []byte {
		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(serverConn, hdr[:]); err != nil {
			t.Fatalf("reading record header: %v", err)
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
		if _, err := io.ReadFull(serverConn, body); err != nil {
			t.Fatalf("reading record body: %v", err)
		}
		if recordType(hdr[0]) != wantType {
			t.Fatalf("record type %d, want %d", hdr[0], wantType)
		}
		return body
	}

	var ch clientHelloMsg
	if !ch.unmarshal(readRecord(recordTypeHandshake)) {
		t.Fatal("malformed first ClientHello")
	}
	hrr, err := (&serverHelloMsg{
		vers:              VersionTLS12,
		random:            helloRetryRequestRandom,
		sessionId:         ch.sessionId,
		cipherSuite:       TLS_AES_128_GCM_SHA256,
		compressionMethod: compressionNone,
		supportedVersion:  VersionTLS13,
		cookie:            []byte("hrr-cookie"),
	}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	record := append([]byte{byte(recordTypeHandshake), 3, 3, 0, 0}, hrr...)
	binary.BigEndian.PutUint16(record[3:], uint16(len(hrr)))
	if _, err := serverConn.Write(record); err != nil {
		t.Fatal(err)
	}

	readRecord(recordTypeChangeCipherSpec)
	if !ch.unmarshal(readRecord(recordTypeHandshake)) || string(ch.cookie) != "hrr-cookie" {
		t.Fatal("second ClientHello does not echo the cookie")
	}
	serverConn.Close()
	<-done
	return uconn.Extensions
}

func cookieIndex(t *testing.T, exts []TLSExtension) int {
	t.Helper()
	for i, ext := range exts {
		if _, ok := ext.(*CookieExtension); ok {
			return i
		}
	}
	t.Fatal("no cookie extension in the second ClientHello")
	return -1
}

// Browsers add the HRR cookie among the extensions they permute anyway, so it
// never precedes the leading GREASE extension or follows the trailing one.
func TestHelloRetryCookieStaysBetweenGREASE(t *testing.T) {
	for range 300 {
		exts := helloRetryWithCookie(t, func(c net.Conn) *UConn {
			return UClient(c, &Config{ServerName: "example.com"}, HelloChrome_155)
		})
		var grease []int
		for i, ext := range exts {
			if _, ok := ext.(*UtlsGREASEExtension); ok {
				grease = append(grease, i)
			}
		}
		if len(grease) != 2 {
			t.Fatalf("want 2 GREASE extensions, got %d", len(grease))
		}
		if i := cookieIndex(t, exts); i < grease[0] || i > grease[1] {
			t.Fatalf("cookie at %d, outside the GREASE brackets at %d and %d", i, grease[0], grease[1])
		}
	}
}

// The old placement drew from len-2 slots, which on a short list always put
// the cookie ahead of the leading GREASE extension.
func TestHelloRetryCookieShortExtensionList(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin:         VersionTLS13,
		TLSVersMax:         VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
		},
	}
	for range 50 {
		exts := helloRetryWithCookie(t, func(c net.Conn) *UConn {
			u := UClient(c, &Config{ServerName: "example.com"}, HelloCustom)
			s := spec.clone()
			if err := u.ApplyPreset(s); err != nil {
				t.Fatal(err)
			}
			return u
		})
		if i := cookieIndex(t, exts); i == 0 {
			t.Fatal("cookie placed ahead of the leading GREASE extension")
		}
	}
}
