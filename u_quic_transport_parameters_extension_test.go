package tls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// The QUIC stack's transport parameters carry this connection's values, such as
// initial_source_connection_id, so they are what the ClientHello must carry,
// not the placeholder parameters baked into the preset.
func TestUQUICSendsStackTransportParameters(t *testing.T) {
	stackParams := TransportParameters{
		InitialSourceConnectionID([]byte{1, 2, 3, 4}),
		InitialMaxData(0x100000),
	}.Marshal()

	for _, presetFirst := range []bool{true, false} {
		name := map[bool]string{true: "ApplyPresetFirst", false: "SetTransportParametersFirst"}[presetFirst]
		t.Run(name, func(t *testing.T) {
			clientConfig := testConfigClient.Clone()
			clientConfig.NextProtos = []string{"h3"}
			client := UQUICClient(&QUICConfig{TLSConfig: clientConfig}, HelloCustom)
			defer client.Close()
			preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
			preset.Extensions = append(preset.Extensions,
				&ALPNExtension{AlpnProtocols: []string{"h3"}},
				&QUICTransportParametersExtension{TransportParameters: TransportParameters{InitialMaxData(1)}},
			)
			applyPreset := func() {
				if err := client.ApplyPreset(preset); err != nil {
					t.Fatal(err)
				}
			}
			if presetFirst {
				applyPreset()
				client.SetTransportParameters(stackParams)
			} else {
				client.SetTransportParameters(stackParams)
				applyPreset()
			}

			serverConfig := testConfigServer.Clone()
			serverConfig.NextProtos = []string{"h3"}
			server := QUICServer(&QUICConfig{TLSConfig: serverConfig})
			defer server.Close()
			server.SetTransportParameters(nil)

			if got := runUQUICHandshake(t, client, server); !bytes.Equal(got, stackParams) {
				t.Fatalf("server received transport parameters %x, want the QUIC stack's %x", got, stackParams)
			}
		})
	}
}

// runUQUICHandshake completes a handshake and returns the transport parameters
// the server received.
func runUQUICHandshake(t *testing.T, client *UQUICConn, server *QUICConn) []byte {
	t.Helper()
	type endpoint interface {
		Start(context.Context) error
		NextEvent() QUICEvent
		HandleData(QUICEncryptionLevel, []byte) error
	}
	endpoints := []endpoint{client, server}
	for _, e := range endpoints {
		if err := e.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var serverGot []byte
	var complete [2]bool
	for current, idle := 0, 0; idle < 2; {
		event := endpoints[current].NextEvent()
		if event.Kind == QUICNoEvent {
			idle++
			current = 1 - current
			continue
		}
		idle = 0
		switch event.Kind {
		case QUICWriteData:
			if err := endpoints[1-current].HandleData(event.Level, event.Data); err != nil {
				t.Fatal(err)
			}
		case QUICTransportParameters:
			if current == 1 {
				serverGot = bytes.Clone(event.Data)
			}
		case QUICHandshakeDone:
			complete[current] = true
		case QUICErrorEvent:
			t.Fatal(event.Err)
		}
	}
	if !complete[0] || !complete[1] {
		t.Fatalf("handshake incomplete: client=%v server=%v", complete[0], complete[1])
	}
	return serverGot
}

// A captured QUIC ClientHello parses without blunt mimicry, and the transport
// parameters are reproduced byte for byte, even where a re-encoder would
// shorten a varint.
func TestQUICTransportParametersFromRaw(t *testing.T) {
	// initial_max_data = 1, its value encoded as a two-byte varint
	body := []byte{0x04, 0x02, 0x40, 0x01}

	client := UClient(nil, &Config{ServerName: "example.com"}, HelloCustom)
	preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
	preset.Extensions = append(preset.Extensions, &GenericExtension{Id: extensionQUICTransportParameters, Data: body})
	if err := client.ApplyPreset(preset); err != nil {
		t.Fatal(err)
	}
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := client.HandshakeState.Hello.Raw
	record := append([]byte{byte(recordTypeHandshake), 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)

	spec, err := (&Fingerprinter{}).RawClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	var captured *QUICTransportParametersExtension
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*QUICTransportParametersExtension); ok {
			captured = e
		}
	}
	if captured == nil {
		t.Fatal("quic_transport_parameters missing from the parsed spec")
	}
	wire := make([]byte, captured.Len())
	if _, err := captured.Read(wire); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if want := append([]byte{0, 57, 0, byte(len(body))}, body...); !bytes.Equal(wire, want) {
		t.Fatalf("re-serialized extension %x, want %x", wire, want)
	}
}
