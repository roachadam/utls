// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
	"testing"
)

// TestUConnWriteAllocs checks that writing application data after the
// handshake does not allocate, as with crypto/tls's Conn.Write: a defer
// inside Write's interlock loop is heap-allocated on every call.
func TestUConnWriteAllocs(t *testing.T) {
	c, s := localPipe(t)
	t.Cleanup(func() {
		c.Close()
		s.Close()
	})

	// The server reads and discards everything after its handshake.
	go func() {
		server := Server(s, testConfigServer.Clone())
		if err := server.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, server)
	}()

	client := UClient(c, testConfigClient.Clone(), HelloChrome_Auto)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	if allocs := testing.AllocsPerRun(100, func() {
		if _, err := client.Write(buf); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Errorf("UConn.Write allocated %v times per call, want 0", allocs)
	}
}
