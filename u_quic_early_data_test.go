package tls

import (
	"context"
	"testing"
)

// A UQUICConn whose preset offers early_data, resuming a ticket that allows
// 0-RTT, sends 0-RTT: it gets the early write secret and accepts the
// server's early_data. loadSession decides on a copy of the hello
// (HandshakeState.Hello.getPrivatePtr), so the decision must be copied back.
func TestUQUICEarlyDataWithPreset(t *testing.T) {
	cache := NewLRUClientSessionCache(1)
	spec := func(resume bool) *ClientHelloSpec {
		s := &ClientHelloSpec{
			TLSVersMin:         VersionTLS13,
			TLSVersMax:         VersionTLS13,
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{compressionNone},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&SupportedCurvesExtension{Curves: []CurveID{X25519}},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256, Ed25519,
				}},
				&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
				&ALPNExtension{AlpnProtocols: []string{"h3"}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
				&QUICTransportParametersExtension{},
			},
		}
		if resume {
			s.Extensions = append(s.Extensions,
				&GenericExtension{Id: extensionEarlyData},
				&UtlsPreSharedKeyExtension{},
			)
		}
		return s
	}
	connect := func(resume bool) (earlyKey bool, err error) {
		clientConfig := &QUICConfig{TLSConfig: testConfigClient.Clone()}
		clientConfig.TLSConfig.MinVersion = VersionTLS13
		clientConfig.TLSConfig.NextProtos = []string{"h3"}
		clientConfig.TLSConfig.ClientSessionCache = cache
		client := UQUICClient(clientConfig, HelloCustom)
		defer client.Close()
		if err := client.ApplyPreset(spec(resume)); err != nil {
			return false, err
		}
		client.SetTransportParameters(nil)

		serverConfig := &QUICConfig{TLSConfig: testConfigServer.Clone()}
		serverConfig.TLSConfig.MinVersion = VersionTLS13
		serverConfig.TLSConfig.NextProtos = []string{"h3"}
		server := QUICServer(serverConfig)
		defer server.Close()
		server.SetTransportParameters(nil)

		if err := client.Start(context.Background()); err != nil {
			return false, err
		}
		if err := server.Start(context.Background()); err != nil {
			return false, err
		}
		type end interface {
			NextEvent() QUICEvent
			HandleData(QUICEncryptionLevel, []byte) error
		}
		ends := [2]end{client, server}
		done := [2]bool{}
		for idle, i := 0, 0; idle < 2; {
			e := ends[i].NextEvent()
			switch e.Kind {
			case QUICNoEvent:
				idle++
				i = 1 - i
				continue
			case QUICErrorEvent:
				return earlyKey, e.Err
			case QUICSetWriteSecret:
				if i == 0 && e.Level == QUICEncryptionLevelEarly {
					earlyKey = true
				}
			case QUICWriteData:
				if err := ends[1-i].HandleData(e.Level, e.Data); err != nil {
					return earlyKey, err
				}
			case QUICHandshakeDone:
				done[i] = true
				if i == 1 {
					if err := server.SendSessionTicket(QUICSessionTicketOptions{EarlyData: true}); err != nil {
						return earlyKey, err
					}
				}
			}
			idle = 0
		}
		if !done[0] || !done[1] {
			t.Fatal("handshake incomplete")
		}
		return earlyKey, nil
	}
	if _, err := connect(false); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	earlyKey, err := connect(true)
	if err != nil {
		t.Fatalf("resumed connection: %v", err)
	}
	if !earlyKey {
		t.Error("resumed connection got no 0-RTT write secret")
	}
}
