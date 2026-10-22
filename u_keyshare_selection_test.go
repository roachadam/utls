package tls

import "testing"

// A server may select any group the client sent a key share for, not only the
// first classical one. The client must finish that handshake with the matching
// private key and without a HelloRetryRequest, as the browser it mimics would.
func TestServerSelectsAnyOfferedKeyShare(t *testing.T) {
	threeClassical := ClientHelloSpec{
		TLSVersMin:         VersionTLS13,
		TLSVersMax:         VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{CurveP256, X25519, CurveP384}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, Ed25519,
			}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: CurveP256}, {Group: X25519}, {Group: CurveP384}}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
		},
	}

	for _, tc := range []struct {
		name   string
		client ClientHelloID
		spec   *ClientHelloSpec
		server CurveID
	}{
		// Firefox offers X25519MLKEM768, X25519 (sharing the hybrid's X25519 key)
		// and P-256.
		{"Firefox/X25519MLKEM768", HelloFirefox_148, nil, X25519MLKEM768},
		{"Firefox/X25519", HelloFirefox_148, nil, X25519},
		{"Firefox/P-256", HelloFirefox_148, nil, CurveP256},
		{"Custom/first", HelloCustom, &threeClassical, CurveP256},
		{"Custom/second", HelloCustom, &threeClassical, X25519},
		{"Custom/third", HelloCustom, &threeClassical, CurveP384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConfig := testConfigClient.Clone()
			clientConfig.ClientSessionCache = nil
			serverConfig := testConfigServer.Clone()
			serverConfig.MinVersion, serverConfig.MaxVersion = VersionTLS13, VersionTLS13
			serverConfig.CurvePreferences = []CurveID{tc.server}
			serverConfig.SessionTicketsDisabled = true

			clientConn, serverConn := localPipe(t)
			client := UClient(clientConn, clientConfig, tc.client)
			if tc.spec != nil {
				spec := tc.spec.clone()
				if err := client.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
			}
			server := Server(serverConn, serverConfig)
			clientResult := make(chan error, 1)
			go func() { clientResult <- client.Handshake() }()
			serverErr := server.Handshake()
			if serverErr != nil {
				serverConn.Close()
			}
			if clientErr := <-clientResult; clientErr != nil || serverErr != nil {
				t.Fatalf("handshake: client=%v, server=%v", clientErr, serverErr)
			}

			state := client.ConnectionState()
			if state.CurveID != tc.server {
				t.Errorf("negotiated %v, want %v", state.CurveID, tc.server)
			}
			if state.HelloRetryRequest {
				t.Error("server sent a HelloRetryRequest for a group the client already offered")
			}
		})
	}
}
