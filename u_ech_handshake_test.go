// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// After a HelloRetryRequest that accepts ECH, the second ClientHelloInner
// sends the new key share: crypto/tls's ClientHelloInner compresses
// key_share, so the outer hello must carry it.
func TestUTLSECHHelloRetryRequest(t *testing.T) {
	env := newECHTestEnv(t)
	env.serverConfig.CurvePreferences = []CurveID{CurveP256}
	env.clientConfig.ClientSessionCache = nil
	result, err := echHandshake(t, env, chromeECHOuterSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []ConnectionState{result.client, result.server} {
		if !state.ECHAccepted || !state.HelloRetryRequest || state.CurveID != CurveP256 {
			t.Errorf("unexpected connection state: %+v", state)
		}
	}
}

// When the server rejects ECH and answers the outer hello, the client checks
// the server's ALPN against the outer hello's, and returns the retry configs.
func TestUTLSECHRejectedOuterALPN(t *testing.T) {
	env := newECHTestEnv(t)
	env.clientConfig.ClientSessionCache = nil
	otherKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherConfig := marshalECHTestConfig(45, otherKey.PublicKey().Bytes())
	env.serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{
		{Config: otherConfig, PrivateKey: otherKey.Bytes(), SendAsRetry: true},
	}
	// uTLS checks the public name's certificate against ServerName unless
	// EncryptedClientHelloRejectionVerify is set.
	env.clientConfig.EncryptedClientHelloRejectionVerify = func(ConnectionState) error { return nil }
	_, err = echHandshake(t, env, chromeECHOuterSpec(), nil)
	var rejection *ECHRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("got %v, want an ECHRejectionError", err)
	}
	if want := marshalECHTestConfigList(otherConfig); !bytes.Equal(rejection.RetryConfigList, want) {
		t.Errorf("RetryConfigList = %x, want %x", rejection.RetryConfigList, want)
	}
}

// chromeECHOuterSpec is a Chrome-like ClientHelloOuter.
func chromeECHOuterSpec() *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{compressionNone},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
			&SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384}},
			&SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}},
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384,
			}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShare{
				{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: X25519MLKEM768},
				{Group: X25519},
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
			&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
			&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			BoringGREASEECH(),
			&UtlsGREASEExtension{},
		},
	}
}

// echTestEnv is a server for secret.example behind the ECH public name
// public.example, as in testECHSpec.
type echTestEnv struct {
	clientConfig, serverConfig *Config
	echConfig, echKey          []byte
}

func newECHTestEnv(t *testing.T) *echTestEnv {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := func(name string) ([]byte, *x509.Certificate) {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			DNSNames:     []string{name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return der, cert
	}
	publicDER, publicCert := certificate("public.example")
	secretDER, secretCert := certificate("secret.example")

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echConfig := marshalECHTestConfig(123, echKey.PublicKey().Bytes())

	clientConfig, serverConfig := testConfigClient.Clone(), testConfigServer.Clone()
	clientConfig.Time = nil
	clientConfig.MinVersion = VersionTLS13
	clientConfig.ServerName = "secret.example"
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(secretCert)
	clientConfig.RootCAs.AddCert(publicCert)
	clientConfig.EncryptedClientHelloConfigList = marshalECHTestConfigList(echConfig)
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.OmitEmptyPsk = true
	serverConfig.Time = nil
	serverConfig.MinVersion = VersionTLS13
	serverConfig.NextProtos = []string{"h2"}
	serverConfig.Certificates = []Certificate{
		{Certificate: [][]byte{publicDER}, PrivateKey: k},
		{Certificate: [][]byte{secretDER}, PrivateKey: k},
	}
	serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{
		{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
	}
	// echHandshake clones serverConfig: share the ticket keys.
	serverConfig.SetSessionTicketKeys([][32]byte{{1}})
	return &echTestEnv{clientConfig, serverConfig, echConfig, echKey.Bytes()}
}

func marshalECHTestConfig(id uint8, pubKey []byte) []byte {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(extensionEncryptedClientHello)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(id)
		builder.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(pubKey)
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint16(0x0001) // HKDF-SHA256
			builder.AddUint16(0x0001) // AES-128-GCM
		})
		builder.AddUint8(32) // maximum_name_length
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte("public.example"))
		})
		builder.AddUint16(0) // extensions
	})
	return builder.BytesOrPanic()
}

func marshalECHTestConfigList(configs ...[]byte) []byte {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, config := range configs {
			builder.AddBytes(config)
		}
	})
	return builder.BytesOrPanic()
}

// echRecordingConn records what the client writes.
type echRecordingConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *echRecordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// clientHellos returns the ClientHellos among the plaintext records written.
func (c *echRecordingConn) clientHellos() [][]byte {
	c.mu.Lock()
	records := bytes.Clone(c.written.Bytes())
	c.mu.Unlock()
	var handshake []byte
	for len(records) >= recordHeaderLen {
		n := int(records[3])<<8 | int(records[4])
		if recordType(records[0]) == recordTypeApplicationData {
			break
		}
		if recordType(records[0]) == recordTypeHandshake {
			handshake = append(handshake, records[recordHeaderLen:recordHeaderLen+n]...)
		}
		records = records[recordHeaderLen+n:]
	}
	var hellos [][]byte
	for len(handshake) >= 4 {
		n := 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
		if handshake[0] == typeClientHello {
			hellos = append(hellos, handshake[:n])
		}
		handshake = handshake[n:]
	}
	return hellos
}

type echTestResult struct {
	client, server ConnectionState
	hellos         [][]byte
	// serverExtensions are the ClientHelloInfo.Extensions the server saw.
	serverExtensions []uint16
}

// echHandshake connects a UConn with spec to env's server, and reads the
// server's application data, which processes its session tickets. prepare,
// if not nil, runs before the handshake.
func echHandshake(t *testing.T, env *echTestEnv, spec *ClientHelloSpec, prepare func(*UConn) error) (echTestResult, error) {
	t.Helper()
	var result echTestResult
	serverConfig := env.serverConfig.Clone()
	serverConfig.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		result.serverExtensions = slices.Clone(chi.Extensions)
		return nil, nil
	}
	clientConn, serverConn := localPipe(t)
	recorder := &echRecordingConn{Conn: clientConn}
	defer recorder.Close()
	client := UClient(recorder, env.clientConfig, HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		serverConn.Close()
		return result, err
	}
	if prepare != nil {
		if err := prepare(client); err != nil {
			serverConn.Close()
			return result, err
		}
	}
	server := Server(serverConn, serverConfig)
	serverResult := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		if err := server.Handshake(); err != nil {
			serverResult <- err
			return
		}
		_, err := io.WriteString(server, "ok")
		serverResult <- err
	}()
	clientErr := client.Handshake()
	if clientErr == nil {
		var applicationData [2]byte
		if _, clientErr = io.ReadFull(client, applicationData[:]); clientErr == nil && string(applicationData[:]) != "ok" {
			clientErr = fmt.Errorf("unexpected application data: %q", applicationData)
		}
	} else {
		recorder.Close()
	}
	serverErr := <-serverResult
	result.hellos = recorder.clientHellos()
	result.client, result.server = client.ConnectionState(), server.ConnectionState()
	if clientErr != nil {
		return result, fmt.Errorf("client: %w", clientErr)
	}
	if serverErr != nil {
		return result, fmt.Errorf("server: %w", serverErr)
	}
	return result, nil
}
