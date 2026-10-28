// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
	"testing"
)

// TestReleaseHandshakeState checks that a finished TLS 1.3 client handshake
// drops the hello, key shares, secrets and extensions while the connection
// keeps working (a NewSessionTicket read after it, resumption from that
// ticket), and that a TLS 1.2 handshake keeps them for renegotiation.
func TestReleaseHandshakeState(t *testing.T) {
	for _, tc := range []struct {
		vers     uint16
		released bool
	}{
		{
			vers:     VersionTLS13,
			released: true,
		},
		{
			vers:     VersionTLS12,
			released: false,
		},
	} {
		t.Run(VersionName(tc.vers), func(t *testing.T) {
			serverConfig := testConfigServer.Clone()
			serverConfig.MaxVersion = tc.vers
			clientConfig := testConfigClient.Clone()
			clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
			clientConfig.MaxVersion = VersionTLS13
			clientConfig.AlwaysIncludePSK = true
			clientConfig.OmitEmptyPsk = true

			for i, wantResumed := range []bool{false, true} {
				client := releaseHandshake(t, clientConfig, serverConfig)
				if got := client.ConnectionState().DidResume; got != wantResumed {
					t.Errorf("connection %d: DidResume = %v, want %v", i+1, got, wantResumed)
				}

				hs := client.HandshakeState
				kept := hs.Hello != nil || hs.ServerHello != nil || hs.MasterSecret != nil || hs.Session != nil ||
					hs.State13.KeyShareKeys != nil || hs.State13.Transcript != nil || hs.State13.EarlySecret != nil ||
					hs.State13.BinderKey != nil || hs.State13.TrafficSecret != nil ||
					client.Extensions != nil || client.ech != nil || client.echCtx != nil
				if tc.released && kept {
					t.Errorf("connection %d: TLS 1.3 handshake state kept after the handshake: %+v, %d extensions", i+1, hs, len(client.Extensions))
				}
				if !tc.released && (hs.Hello == nil || client.Extensions == nil) {
					t.Errorf("connection %d: TLS 1.2 handshake state released; renegotiation needs it", i+1)
				}
				if hs.C != client.Conn || hs.uconn != client {
					t.Errorf("connection %d: handshake state no longer points at its connection", i+1)
				}
			}
		})
	}
}

// releaseHandshake runs a Chrome handshake against serverConfig and reads
// the server's first application data, which comes after its session
// tickets.
func releaseHandshake(t *testing.T, clientConfig, serverConfig *Config) *UConn {
	t.Helper()

	c, s := localPipe(t)
	t.Cleanup(func() {
		c.Close()
		s.Close()
	})

	errc := make(chan error, 1)
	go func() {
		server := Server(s, serverConfig)
		if err := server.Handshake(); err != nil {
			errc <- err
			return
		}
		_, err := server.Write([]byte("ping"))
		errc <- err
	}()

	client := UClient(c, clientConfig, HelloChrome_Auto)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	return client
}
