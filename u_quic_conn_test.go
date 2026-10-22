package tls

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Close must stop a handshake that is blocked waiting for peer data, as
// QUICConn.Close does, rather than wait for it forever.
func TestUQUICCloseWhileWaitingForData(t *testing.T) {
	config := &QUICConfig{TLSConfig: testConfigClient.Clone()}
	config.TLSConfig.MinVersion = VersionTLS13
	client := UQUICClient(config, HelloGolang)
	client.SetTransportParameters(nil)
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for client.NextEvent().Kind != QUICNoEvent {
	}

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, alertCloseNotify) {
			t.Errorf("Close() = %v, want alertCloseNotify", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close() did not return while the handshake waited for data")
	}
}

// A failed handshake is reported once through NextEvent as a QUICErrorEvent,
// as QUICConn does, so a QUIC stack can close the connection with its alert.
func TestUQUICHandshakeErrorEvent(t *testing.T) {
	clientConfig := &QUICConfig{TLSConfig: testConfigClient.Clone()}
	clientConfig.TLSConfig.MinVersion = VersionTLS13
	clientConfig.TLSConfig.ServerName = "name" // not in the server certificate
	client := UQUICClient(clientConfig, HelloGolang)
	defer client.Close()
	client.SetTransportParameters(nil)

	serverConfig := &QUICConfig{TLSConfig: testConfigServer.Clone()}
	serverConfig.TLSConfig.MinVersion = VersionTLS13
	server := QUICServer(serverConfig)
	defer server.Close()
	server.SetTransportParameters(nil)

	if err := client.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	var handshakeErr error
	for handshakeErr == nil {
		e := client.NextEvent()
		if e.Kind == QUICNoEvent {
			if e = server.NextEvent(); e.Kind == QUICNoEvent {
				t.Fatal("handshake stalled without an error")
			}
			if e.Kind == QUICWriteData {
				handshakeErr = client.HandleData(e.Level, e.Data)
			}
			continue
		}
		if e.Kind == QUICWriteData {
			if err := server.HandleData(e.Level, e.Data); err != nil {
				t.Fatalf("server: %v", err)
			}
		}
	}
	if _, ok := errors.AsType[*CertificateVerificationError](handshakeErr); !ok {
		t.Fatalf("handshake error %v, want a CertificateVerificationError", handshakeErr)
	}

	if e := client.NextEvent(); e.Kind != QUICErrorEvent || e.Err != handshakeErr {
		t.Fatalf("NextEvent() = %v (%v), want QUICErrorEvent with the handshake error", e.Kind, e.Err)
	}
	if e := client.NextEvent(); e.Kind != QUICNoEvent {
		t.Fatalf("NextEvent() after the error = %v, want QUICNoEvent", e.Kind)
	}
}
