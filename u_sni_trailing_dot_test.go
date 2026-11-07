package tls

import (
	"bytes"
	"io"
	"testing"
)

// An SNIExtension with KeepTrailingDot sends an absolute name with its dot,
// on the wire and in the handshake state's hello; without it, or for an IP
// literal, it sends what crypto/tls does.
func TestSNIExtensionKeepTrailingDot(t *testing.T) {
	for _, tt := range []struct {
		name string
		keep bool
		want string // "" for no server_name
	}{
		{"dot.example.test.", true, "dot.example.test."},
		{"dot.example.test.", false, "dot.example.test"},
		{"dot.example.test", true, "dot.example.test"},
		{"192.0.2.1", true, ""},
		{"[::1]", true, ""},
	} {
		// ApplyPreset copies the spec's extensions; the UConn's own are read.
		uconn := UClient(nil, &Config{ServerName: tt.name}, HelloCustom)
		err := uconn.ApplyPreset(&ClientHelloSpec{
			TLSVersMin:         VersionTLS13,
			TLSVersMax:         VersionTLS13,
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{compressionNone},
			Extensions: []TLSExtension{
				&SNIExtension{KeepTrailingDot: tt.keep},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
				&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			},
		})
		if err != nil {
			t.Fatalf("%s (keep %v): ApplyPreset: %v", tt.name, tt.keep, err)
		}
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("%s (keep %v): BuildHandshakeState: %v", tt.name, tt.keep, err)
		}

		if got := uconn.HandshakeState.Hello.ServerName; got != tt.want {
			t.Errorf("%s (keep %v): hello's ServerName %q, want %q", tt.name, tt.keep, got, tt.want)
		}

		ext := uconn.Extensions[0]
		b := make([]byte, ext.Len())
		if _, err := ext.Read(b); err != nil && err != io.EOF {
			t.Fatalf("%s (keep %v): Read: %v", tt.name, tt.keep, err)
		}
		var want []byte
		if tt.want != "" {
			n := len(tt.want)
			want = append([]byte{0, 0, byte((n + 5) >> 8), byte(n + 5), byte((n + 3) >> 8), byte(n + 3), 0, byte(n >> 8), byte(n)}, tt.want...)
		}
		if !bytes.Equal(b, want) {
			t.Errorf("%s (keep %v): extension %x, want %x", tt.name, tt.keep, b, want)
		}
		if tt.want != "" && !bytes.Contains(uconn.HandshakeState.Hello.Raw, want) {
			t.Errorf("%s (keep %v): ClientHello lacks %x", tt.name, tt.keep, want)
		}
	}
}
