package tls

import (
	"net"
	"slices"
	"testing"
)

// A GREASE signature algorithm is advertised on the wire but must not reach
// the handshake state, where Go's checks would treat it as offered.
func TestSignatureAlgorithmGREASEStaysOnTheWire(t *testing.T) {
	client := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_155)
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}

	var wire clientHelloMsg
	if !wire.unmarshal(client.HandshakeState.Hello.Raw) {
		t.Fatal("malformed ClientHello")
	}
	if len(wire.supportedSignatureAlgorithms) == 0 || !isGREASEUint16(uint16(wire.supportedSignatureAlgorithms[0])) {
		t.Fatalf("wire signature_algorithms %v, want a leading GREASE value", wire.supportedSignatureAlgorithms)
	}

	want := wire.supportedSignatureAlgorithms[1:]
	if got := client.HandshakeState.Hello.SupportedSignatureAlgorithms; !slices.Equal(got, want) {
		t.Fatalf("handshake state signature algorithms = %v, want %v", got, want)
	}
}
