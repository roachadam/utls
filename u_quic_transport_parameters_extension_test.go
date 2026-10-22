package tls

import (
	"bytes"
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

			server := newUQUICTestServer()
			defer server.Close()
			server.SetTransportParameters(nil)

			got, err := runUQUICHandshake(t.Context(), client, server)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[1], stackParams) {
				t.Fatalf("server received transport parameters %x, want the QUIC stack's %x", got[1], stackParams)
			}
		})
	}
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
