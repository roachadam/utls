// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// echTestOpener decrypts ClientHelloOuters as env's server does.
type echTestOpener struct {
	env       *echTestEnv
	recipient *hpke.Recipient
}

// open returns the EncodedClientHelloInner of outerRaw and the
// ClientHelloInner the server reconstructs from it.
func (o *echTestOpener) open(t *testing.T, outerRaw []byte) (*clientHelloMsg, []byte, *clientHelloMsg) {
	t.Helper()
	outer := new(clientHelloMsg)
	if !outer.unmarshal(outerRaw) {
		t.Fatal("invalid ClientHelloOuter")
	}
	_, cs, _, encap, payload, err := parseECHExt(outer.encryptedClientHello)
	if err != nil {
		t.Fatal(err)
	}
	if o.recipient == nil {
		_, config, err := parseECHConfig(o.env.echConfig)
		if err != nil {
			t.Fatal(err)
		}
		kem, err := hpke.NewKEM(config.KemID)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := kem.NewPrivateKey(o.env.echKey)
		if err != nil {
			t.Fatal(err)
		}
		kdf, err := hpke.NewKDF(cs.KDFID)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := hpke.NewAEAD(cs.AEADID)
		if err != nil {
			t.Fatal(err)
		}
		if o.recipient, err = hpke.NewRecipient(encap, priv, kdf, aead, append([]byte("tls ech\x00"), o.env.echConfig...)); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := decryptECHPayload(o.recipient, outer.original, payload)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := decodeInnerClientHello(outer, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return outer, encoded, inner
}

// parseEncodedInner returns the extensions of an EncodedClientHelloInner and
// the length of its padding.
func parseEncodedInner(t *testing.T, encoded []byte) ([]rawExtension, int) {
	t.Helper()
	s := cryptobyte.String(encoded)
	var exts cryptobyte.String
	if !s.Skip(2+32) || !skipUint8LengthPrefixed(&s) || !skipUint16LengthPrefixed(&s) ||
		!skipUint8LengthPrefixed(&s) || !s.ReadUint16LengthPrefixed(&exts) {
		t.Fatal("invalid EncodedClientHelloInner")
	}
	var raw []rawExtension
	for !exts.Empty() {
		var ext rawExtension
		var data cryptobyte.String
		if !exts.ReadUint16(&ext.extType) || !exts.ReadUint16LengthPrefixed(&data) {
			t.Fatal("invalid EncodedClientHelloInner extension")
		}
		ext.data = data
		raw = append(raw, ext)
	}
	return raw, len(s)
}

// chromeECHCopiedTypes are the extensions of chromeECHOuterSpec that
// ClientHelloInner copies, GREASE as GREASE_PLACEHOLDER: BoringSSL copies
// every extension but server_name, encrypted_client_hello,
// supported_versions and the TLS 1.2 ones, GREASE included.
var chromeECHCopiedTypes = []uint16{
	GREASE_PLACEHOLDER, extensionSupportedCurves, extensionALPN, extensionStatusRequest,
	extensionSignatureAlgorithms, extensionSCT, extensionKeyShare, extensionPSKModes,
	utlsExtensionCompressCertificate, utlsExtensionApplicationSettingsNew, GREASE_PLACEHOLDER,
}

// chromeECHSpec is chromeECHOuterSpec with a Chrome-like ClientHelloInner:
// its own server_name and supported_versions, the rest copied, and the
// session resumed in it.
func chromeECHSpec(padding func(int, int, int) int) *ClientHelloSpec {
	spec := chromeECHOuterSpec()
	spec.ECHInner = &ECHInnerSpec{
		CipherSuites: []uint16{GREASE_PLACEHOLDER, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
		Extensions: []TLSExtension{
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13}},
			&ECHInnerExtension{},
			&SNIExtension{},
			&ECHOuterExtensions{Types: chromeECHCopiedTypes},
			&UtlsPreSharedKeyExtension{},
		},
		Padding: padding,
	}
	return spec
}

// firefoxECHSpec has a Firefox-like ClientHelloInner, which copies the rest
// of the outer hello after its own extensions; the outer hello sends a
// GREASE pre_shared_key when the inner one resumes.
func firefoxECHSpec() *ClientHelloSpec {
	spec := &ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{compressionNone},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
			&SupportedCurvesExtension{Curves: []CurveID{X25519MLKEM768, X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}},
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
			&FakeRecordSizeLimitExtension{Limit: 0x4001},
			BoringGREASEECH(),
			&GREASEPreSharedKeyExtension{},
		},
	}
	spec.ECHInner = &ECHInnerSpec{
		Extensions: []TLSExtension{
			&ECHInnerExtension{},
			&SNIExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&ECHOuterExtensions{Types: []uint16{
				extensionSupportedCurves, extensionALPN, extensionStatusRequest, extensionKeyShare,
				extensionSignatureAlgorithms, extensionPSKModes, 28,
			}},
			&UtlsPreSharedKeyExtension{},
		},
	}
	return spec
}

func extensionTypes(exts []rawExtension) []uint16 {
	types := make([]uint16, len(exts))
	for i, ext := range exts {
		types[i] = ext.extType
	}
	return types
}

// A ClientHelloInner built from an ECHInnerSpec reaches the server with the
// spec's extensions in its order, the copied ones listed in
// ech_outer_extensions with their outer GREASE values, and the padding the
// spec's Padding returns.
func TestUTLSECHInnerSpecShape(t *testing.T) {
	env := newECHTestEnv(t)
	var paddingArgs [3]int
	const extraPadding = 7
	padding := func(encodedLen, serverNameLen, maxNameLength int) int {
		paddingArgs = [3]int{encodedLen, serverNameLen, maxNameLength}
		return (64-encodedLen%64)%64 + extraPadding
	}
	result, err := echHandshake(t, env, chromeECHSpec(padding), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []ConnectionState{result.client, result.server} {
		if !state.ECHAccepted || state.ServerName != "secret.example" || state.NegotiatedProtocol != "h2" {
			t.Errorf("unexpected connection state: %+v", state)
		}
	}
	if len(result.hellos) != 1 {
		t.Fatalf("client sent %d ClientHellos, want 1", len(result.hellos))
	}

	outer, encoded, inner := (&echTestOpener{env: env}).open(t, result.hellos[0])
	outerExts, err := extractRawExtensions(outer)
	if err != nil {
		t.Fatal(err)
	}
	var outerGREASE []uint16
	for _, ext := range outerExts {
		if isGREASEUint16(ext.extType) {
			outerGREASE = append(outerGREASE, ext.extType)
		}
	}
	if len(outerGREASE) != 2 {
		t.Fatalf("outer hello has GREASE extensions %x", outerGREASE)
	}
	copied := slices.Clone(chromeECHCopiedTypes)
	copied[0], copied[len(copied)-1] = outerGREASE[0], outerGREASE[1]
	want := append([]uint16{extensionSupportedVersions, extensionEncryptedClientHello, extensionServerName}, copied...)
	if !slices.Equal(inner.extensions, want) {
		t.Errorf("ClientHelloInner extensions = %x, want %x", inner.extensions, want)
	}
	if !slices.Equal(result.serverExtensions, want) {
		t.Errorf("server's ClientHelloInfo.Extensions = %x, want %x", result.serverExtensions, want)
	}

	encodedExts, paddingLen := parseEncodedInner(t, encoded)
	if types := extensionTypes(encodedExts); !slices.Equal(types, []uint16{extensionSupportedVersions, extensionEncryptedClientHello, extensionServerName, extensionECHOuterExtensions}) {
		t.Errorf("EncodedClientHelloInner extensions = %x", types)
	}
	list := cryptobyte.String(encodedExts[len(encodedExts)-1].data)
	var listed []uint16
	var types cryptobyte.String
	if !list.ReadUint8LengthPrefixed(&types) {
		t.Fatal("invalid ech_outer_extensions")
	}
	for !types.Empty() {
		var typ uint16
		types.ReadUint16(&typ)
		listed = append(listed, typ)
	}
	if !slices.Equal(listed, copied) {
		t.Errorf("ech_outer_extensions = %x, want %x", listed, copied)
	}
	if want := [3]int{len(encoded) - paddingLen, len("secret.example"), 32}; paddingArgs != want {
		t.Errorf("Padding called with %v, want %v", paddingArgs, want)
	}
	if want := padding(paddingArgs[0], paddingArgs[1], paddingArgs[2]); paddingLen != want {
		t.Errorf("EncodedClientHelloInner padding = %d bytes, Padding returned %d", paddingLen, want)
	}

	// GREASE values come from the outer hello's seed.
	if inner.cipherSuites[0] != outer.cipherSuites[0] || !isGREASEUint16(inner.cipherSuites[0]) {
		t.Errorf("GREASE cipher suites: inner %x, outer %x", inner.cipherSuites[0], outer.cipherSuites[0])
	}
	if inner.supportedVersions[0] != outer.supportedVersions[0] || !isGREASEUint16(inner.supportedVersions[0]) {
		t.Errorf("GREASE versions: inner %x, outer %x", inner.supportedVersions[0], outer.supportedVersions[0])
	}
	if inner.serverName != "secret.example" || outer.serverName != "public.example" {
		t.Errorf("server names: inner %q, outer %q", inner.serverName, outer.serverName)
	}
}

// A session is resumed inside ClientHelloInner: its ticket never appears in
// ClientHelloOuter, which carries no pre_shared_key or a GREASE one of the
// same shape.
func TestUTLSECHInnerSpecResumption(t *testing.T) {
	for _, tc := range []struct {
		name        string
		spec        func() *ClientHelloSpec
		greaseOuter bool
		prepare     func(*UConn) error
	}{
		{"Chrome", func() *ClientHelloSpec { return chromeECHSpec(nil) }, false, nil},
		{"Firefox", firefoxECHSpec, true, nil},
		// Each ClientHello1 must start a new HPKE context.
		{"BuiltTwice", func() *ClientHelloSpec { return chromeECHSpec(nil) }, false, (*UConn).BuildHandshakeState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newECHTestEnv(t)
			for _, resume := range []bool{false, true} {
				var ticket []byte
				if resume {
					cs, ok := env.clientConfig.ClientSessionCache.Get(env.clientConfig.ServerName)
					if !ok || cs == nil {
						t.Fatal("no session in the client cache")
					}
					ticket = cs.session.ticket
				}
				result, err := echHandshake(t, env, tc.spec(), tc.prepare)
				if err != nil {
					t.Fatalf("resume=%v: %v", resume, err)
				}
				for _, state := range []ConnectionState{result.client, result.server} {
					if !state.ECHAccepted || state.DidResume != resume {
						t.Errorf("resume=%v: unexpected connection state: %+v", resume, state)
					}
				}
				if !resume {
					continue
				}
				outer, _, inner := (&echTestOpener{env: env}).open(t, result.hellos[0])
				if bytes.Contains(outer.original, ticket) {
					t.Error("the session ticket is in ClientHelloOuter")
				}
				if len(inner.pskIdentities) != 1 || !bytes.Equal(inner.pskIdentities[0].label, ticket) {
					t.Error("ClientHelloInner does not offer the session")
				}
				if !tc.greaseOuter {
					if len(outer.pskIdentities) != 0 {
						t.Error("ClientHelloOuter has a pre_shared_key")
					}
					continue
				}
				if len(outer.pskIdentities) != 1 || len(outer.pskIdentities[0].label) != len(ticket) ||
					len(outer.pskBinders) != 1 || len(outer.pskBinders[0]) != len(inner.pskBinders[0]) {
					t.Fatalf("ClientHelloOuter's GREASE pre_shared_key does not mirror the inner one: %d identities, %d binders", len(outer.pskIdentities), len(outer.pskBinders))
				}
				if bytes.Equal(outer.pskBinders[0], inner.pskBinders[0]) {
					t.Error("ClientHelloOuter carries the inner binder")
				}
			}
		})
	}
}

// After a HelloRetryRequest that accepts ECH, the second ClientHelloInner
// sends the new key share, whether it copies the outer key_share or has its
// own, and resumes with binders over the inner transcript.
func TestUTLSECHInnerSpecHelloRetryRequest(t *testing.T) {
	ownKeyShare := func() *ClientHelloSpec {
		spec := chromeECHSpec(nil)
		types := slices.DeleteFunc(slices.Clone(chromeECHCopiedTypes), func(typ uint16) bool { return typ == extensionKeyShare })
		spec.ECHInner.Extensions = []TLSExtension{
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13}},
			&ECHInnerExtension{},
			&SNIExtension{},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: GREASE_PLACEHOLDER}, {Group: X25519}}},
			&ECHOuterExtensions{Types: types},
			&UtlsPreSharedKeyExtension{},
		}
		return spec
	}
	for _, tc := range []struct {
		name string
		spec func() *ClientHelloSpec
	}{
		{"CopiedKeyShare", func() *ClientHelloSpec { return chromeECHSpec(nil) }},
		{"OwnKeyShare", ownKeyShare},
		{"Firefox", firefoxECHSpec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newECHTestEnv(t)
			env.serverConfig.CurvePreferences = []CurveID{CurveP256}
			for _, resume := range []bool{false, true} {
				result, err := echHandshake(t, env, tc.spec(), nil)
				if err != nil {
					t.Fatalf("resume=%v: %v", resume, err)
				}
				for _, state := range []ConnectionState{result.client, result.server} {
					if !state.ECHAccepted || !state.HelloRetryRequest || state.DidResume != resume || state.CurveID != CurveP256 {
						t.Errorf("resume=%v: unexpected connection state: %+v", resume, state)
					}
				}
				if len(result.hellos) != 2 {
					t.Fatalf("resume=%v: client sent %d ClientHellos, want 2", resume, len(result.hellos))
				}
				opener := &echTestOpener{env: env}
				opener.open(t, result.hellos[0])
				_, _, inner := opener.open(t, result.hellos[1])
				if len(inner.keyShares) != 1 || inner.keyShares[0].group != CurveP256 {
					t.Errorf("resume=%v: second ClientHelloInner key shares: %+v", resume, inner.keyShares)
				}
			}
		})
	}
}

// A QUIC connection sends ClientHelloInner from an ECHInnerSpec with the QUIC
// stack's transport parameters, and resumes with 0-RTT inside it.
func TestUQUICECHInnerSpec(t *testing.T) {
	env := newECHTestEnv(t)
	transportParams := []byte{0x04, 0x02, 0x40, 0x00}
	spec := func() *ClientHelloSpec {
		return &ClientHelloSpec{
			TLSVersMin:   VersionTLS13,
			TLSVersMax:   VersionTLS13,
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&SupportedCurvesExtension{Curves: []CurveID{X25519}},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}},
				&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
				&ALPNExtension{AlpnProtocols: []string{"h3"}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
				&QUICTransportParametersExtension{},
				BoringGREASEECH(),
			},
			ECHInner: &ECHInnerSpec{
				Extensions: []TLSExtension{
					&ECHInnerExtension{},
					&SNIExtension{},
					&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
					&QUICTransportParametersExtension{},
					&ECHOuterExtensions{Types: []uint16{
						extensionSupportedCurves, extensionSignatureAlgorithms, extensionKeyShare, extensionALPN, extensionPSKModes,
					}},
					&UtlsPreSharedKeyExtension{},
				},
			},
		}
	}
	connect := func(resume bool) (state ConnectionState, earlyKey bool, serverParams []byte) {
		clientConfig := &QUICConfig{TLSConfig: env.clientConfig.Clone()}
		clientConfig.TLSConfig.NextProtos = []string{"h3"}
		client := UQUICClient(clientConfig, HelloCustom)
		defer client.Close()
		s := spec()
		if resume {
			// early_data only goes with a pre_shared_key.
			exts := s.ECHInner.Extensions
			s.ECHInner.Extensions = slices.Insert(exts, len(exts)-1, TLSExtension(&GenericExtension{Id: extensionEarlyData}))
		}
		if err := client.ApplyPreset(s); err != nil {
			t.Fatal(err)
		}
		client.SetTransportParameters(transportParams)

		serverConfig := &QUICConfig{TLSConfig: env.serverConfig.Clone()}
		serverConfig.TLSConfig.NextProtos = []string{"h3"}
		server := QUICServer(serverConfig)
		defer server.Close()
		server.SetTransportParameters(nil)

		if err := client.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := server.Start(context.Background()); err != nil {
			t.Fatal(err)
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
				t.Fatalf("resume=%v: %v", resume, e.Err)
			case QUICTransportParameters:
				if i == 1 {
					serverParams = bytes.Clone(e.Data)
				}
			case QUICSetWriteSecret:
				if i == 0 && e.Level == QUICEncryptionLevelEarly {
					earlyKey = true
				}
			case QUICWriteData:
				if err := ends[1-i].HandleData(e.Level, e.Data); err != nil {
					t.Fatalf("resume=%v: %v", resume, err)
				}
			case QUICHandshakeDone:
				done[i] = true
				if i == 1 {
					if err := server.SendSessionTicket(QUICSessionTicketOptions{EarlyData: true}); err != nil {
						t.Fatal(err)
					}
				}
			}
			idle = 0
		}
		if !done[0] || !done[1] {
			t.Fatalf("resume=%v: handshake incomplete", resume)
		}
		serverState := server.ConnectionState()
		if !serverState.ECHAccepted || serverState.DidResume != resume {
			t.Errorf("resume=%v: unexpected server state: %+v", resume, serverState)
		}
		return client.ConnectionState(), earlyKey, serverParams
	}
	for _, resume := range []bool{false, true} {
		state, earlyKey, serverParams := connect(resume)
		if !state.ECHAccepted || state.DidResume != resume || state.ServerName != "secret.example" {
			t.Errorf("resume=%v: unexpected client state: %+v", resume, state)
		}
		if !bytes.Equal(serverParams, transportParams) {
			t.Errorf("resume=%v: server got transport parameters %x, want %x", resume, serverParams, transportParams)
		}
		if earlyKey != resume {
			t.Errorf("resume=%v: 0-RTT write secret: %v", resume, earlyKey)
		}
	}
}

// A copied padding extension is sized for the final outer hello, whose length
// depends on EncodedClientHelloInner: ClientHelloInner gets the same body.
func TestUTLSECHInnerSpecCopiedPadding(t *testing.T) {
	env := newECHTestEnv(t)
	spec := func() *ClientHelloSpec {
		spec := firefoxECHSpec()
		ech := len(spec.Extensions) - 2
		spec.Extensions = slices.Insert(spec.Extensions, ech, TLSExtension(&UtlsPaddingExtension{GetPaddingLen: AlwaysPadToLen(3000)}))
		outerExts := spec.ECHInner.Extensions[3].(*ECHOuterExtensions)
		outerExts.Types = append(outerExts.Types, utlsExtensionPadding)
		return spec
	}
	for _, resume := range []bool{false, true} {
		result, err := echHandshake(t, env, spec(), nil)
		if err != nil {
			t.Fatalf("resume=%v: %v", resume, err)
		}
		for _, state := range []ConnectionState{result.client, result.server} {
			if !state.ECHAccepted || state.DidResume != resume {
				t.Errorf("resume=%v: unexpected connection state: %+v", resume, state)
			}
		}
		if len(result.hellos[0]) != 3000 {
			t.Errorf("resume=%v: ClientHelloOuter is %d bytes, want 3000", resume, len(result.hellos[0]))
		}
	}
}

// When the server rejects ECH, the outer hello governs and the client returns
// the server's retry configs.
func TestUTLSECHInnerSpecRejected(t *testing.T) {
	env := newECHTestEnv(t)
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
	_, err = echHandshake(t, env, chromeECHSpec(nil), nil)
	var rejection *ECHRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("got %v, want an ECHRejectionError", err)
	}
	if want := marshalECHTestConfigList(otherConfig); !bytes.Equal(rejection.RetryConfigList, want) {
		t.Errorf("RetryConfigList = %x, want %x", rejection.RetryConfigList, want)
	}
}

// Malformed ECHInnerSpecs fail in ApplyPreset.
func TestUTLSECHInnerSpecInvalid(t *testing.T) {
	env := newECHTestEnv(t)
	for _, tc := range []struct {
		name   string
		modify func(*ClientHelloSpec)
	}{
		{"NoMarker", func(s *ClientHelloSpec) {
			s.ECHInner.Extensions = slices.DeleteFunc(s.ECHInner.Extensions, func(ext TLSExtension) bool {
				_, ok := ext.(*ECHInnerExtension)
				return ok
			})
		}},
		{"PSKNotLast", func(s *ClientHelloSpec) {
			exts := s.ECHInner.Extensions
			exts[0], exts[len(exts)-1] = exts[len(exts)-1], exts[0]
		}},
		{"CopiedOutOfOrder", func(s *ClientHelloSpec) {
			s.ECHInner.Extensions[3] = &ECHOuterExtensions{Types: []uint16{extensionKeyShare, extensionSupportedCurves}}
		}},
		{"CopiedMissing", func(s *ClientHelloSpec) {
			s.ECHInner.Extensions[3] = &ECHOuterExtensions{Types: []uint16{extensionCookie}}
		}},
		{"CopiedPSK", func(s *ClientHelloSpec) {
			s.ECHInner.Extensions[3] = &ECHOuterExtensions{Types: []uint16{extensionPreSharedKey}}
		}},
		{"RealPSKInOuter", func(s *ClientHelloSpec) {
			s.Extensions = append(s.Extensions, &UtlsPreSharedKeyExtension{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := chromeECHSpec(nil)
			tc.modify(spec)
			if err := UClient(nil, env.clientConfig.Clone(), HelloCustom).ApplyPreset(spec); err == nil {
				t.Fatal("ApplyPreset accepted an invalid ECHInnerSpec")
			}
		})
	}
}

// Once ECH is accepted, a compressed certificate is checked against the
// algorithms of ClientHelloInner, and ALPS against its extensions.
func TestUTLSECHInnerSpecHelloExtensions(t *testing.T) {
	body := marshalCompressionTestCertificate(t, []byte("test certificate"))
	compressed := compressZlibTestCertificate(t, body)
	for _, tc := range []struct {
		name                string
		accepted            bool
		outerAlgs, innerAlg []CertCompressionAlgo
		innerALPS           bool
		wantCert, wantALPS  bool
	}{
		{"RejectedUsesOuter", false, []CertCompressionAlgo{CertCompressionZlib}, nil, false, true, true},
		{"AcceptedUsesInner", true, nil, []CertCompressionAlgo{CertCompressionZlib}, true, true, true},
		{"AcceptedIgnoresOuter", true, []CertCompressionAlgo{CertCompressionZlib}, []CertCompressionAlgo{CertCompressionBrotli}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &Conn{buffering: true, config: &Config{ApplicationSettings: map[string][]byte{"h2": {1}}}}
			conn.echAccepted = tc.accepted
			conn.vers = VersionTLS13
			conn.clientProtocol = "h2"
			uconn := &UConn{Conn: conn, certCompressionAlgs: tc.outerAlgs}
			uconn.Extensions = []TLSExtension{&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}}
			if tc.outerAlgs != nil {
				uconn.Extensions = append(uconn.Extensions, &UtlsCompressCertExtension{Algorithms: tc.outerAlgs})
			}
			uconn.echInner = &echInnerState{sent: []TLSExtension{&UtlsCompressCertExtension{Algorithms: tc.innerAlg}}}
			if tc.innerALPS {
				uconn.echInner.sent = append(uconn.echInner.sent, &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}})
			}
			hs := &clientHandshakeStateTLS13{c: conn, uconn: uconn, transcript: sha256.New(), serverHello: &serverHelloMsg{alpnProtocol: "h2"}}

			got, err := hs.utlsReadServerCertificate(&utlsCompressedCertificateMsg{
				algorithm:                    uint16(CertCompressionZlib),
				uncompressedLength:           uint32(len(body)),
				compressedCertificateMessage: compressed,
			})
			if gotCert := err == nil && got != nil; gotCert != tc.wantCert {
				t.Errorf("decompressed certificate: %v (%v), want %v", gotCert, err, tc.wantCert)
			}

			ee := &encryptedExtensionsMsg{}
			ee.utls.applicationSettingsCodepoint = utlsExtensionApplicationSettingsNew
			if err := hs.utlsReadServerParameters(ee); (err == nil) != tc.wantALPS {
				t.Errorf("ALPS: %v, want accepted %v", err, tc.wantALPS)
			}
		})
	}
}
