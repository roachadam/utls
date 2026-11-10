// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// ECHInnerSpec describes the ClientHelloInner a UConn encrypts when it sends
// real Encrypted Client Hello (RFC 9849), that is when
// Config.EncryptedClientHelloConfigList is set. Without it, ClientHelloInner
// is crypto/tls's default hello. It is ignored without an ECHConfigList.
//
// [uTLS fork]
type ECHInnerSpec struct {
	// CipherSuites of ClientHelloInner. nil uses the outer hello's, GREASE
	// value included; a GREASE value here gets the outer hello's GREASE
	// cipher suite.
	CipherSuites []uint16

	// CompressionMethods of ClientHelloInner. nil => no compression.
	CompressionMethods []uint8

	// Extensions of ClientHelloInner in wire order, as the server sees them
	// once it has expanded ech_outer_extensions. It must hold exactly one
	// ECHInnerExtension, and at most one ECHOuterExtensions, which stands
	// for the extensions copied from the outer hello. A pre_shared_key
	// extension must come last: the session is resumed in ClientHelloInner
	// only, and its binder is computed over this hello.
	//
	// The extensions are applied like the outer hello's, with these
	// differences:
	//   - GREASE values (extensions, cipher suites, groups, signature
	//     algorithms, versions, key shares) come from the outer hello's
	//     seed, so they are equal in both hellos, as in BoringSSL.
	//   - An SNIExtension without a ServerName sends Config.ServerName.
	//   - A KeyShareExtension sends the outer hello's key shares: each group
	//     it lists must have a key share in the outer hello. A GREASE share
	//     without Data takes the outer GREASE share's.
	//   - A QUICTransportParametersExtension sends the QUIC stack's
	//     transport parameters.
	//   - A UtlsPaddingExtension pads ClientHelloInner itself.
	//   - writeToUConn is never called: these extensions do not configure
	//     the connection. Once the server accepts ECH, certificate
	//     compression, ALPS and ALPN are checked against them.
	Extensions []TLSExtension

	// Padding returns the number of zero bytes appended to the
	// EncodedClientHelloInner of encodedLen bytes. serverNameLen is the
	// length of the server_name ClientHelloInner sends (0 for none) and
	// maxNameLength is the ECHConfig's maximum_name_length. nil pads as
	// RFC 9849, Section 6.1.3 suggests.
	Padding func(encodedLen, serverNameLen, maxNameLength int) int
}

// ECHInnerExtension is the encrypted_client_hello extension of
// ClientHelloInner (RFC 9849, Section 5): the inner type, no payload. It goes
// in ECHInnerSpec.Extensions.
//
// [uTLS fork]
type ECHInnerExtension struct{}

func (*ECHInnerExtension) writeToUConn(*UConn) error {
	return nil
}

func (*ECHInnerExtension) Len() int {
	return 5
}

func (e *ECHInnerExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionEncryptedClientHello >> 8)
	b[1] = byte(extensionEncryptedClientHello & 0xff)
	b[2] = 0
	b[3] = 1
	b[4] = byte(innerECHExt)
	return e.Len(), io.EOF
}

// ECHOuterExtensions is the ech_outer_extensions extension of
// ClientHelloInner (RFC 9849, Section 5.1). In ECHInnerSpec.Extensions it
// marks where the extensions copied from the outer hello go: the server
// replaces it with them, so ClientHelloInner sends the outer hello's
// extensions of Types, in this order, at its place.
//
// Types must appear in the outer hello's extensions in the same order, since
// the server copies them in one forward pass. A GREASE value stands for the
// next GREASE extension of the outer hello, whatever its value. A type the
// outer hello leaves out of this ClientHello (an empty CookieExtension, for
// example) is left out of the list. encrypted_client_hello,
// ech_outer_extensions and pre_shared_key cannot be copied.
//
// [uTLS fork]
type ECHOuterExtensions struct {
	Types []uint16
}

func (*ECHOuterExtensions) writeToUConn(*UConn) error {
	return nil
}

// Len and Read write the extension with Types as given: ECHInnerSpec writes
// the types it copies, GREASE values resolved.
func (e *ECHOuterExtensions) Len() int {
	return 4 + 1 + 2*len(e.Types)
}

func (e *ECHOuterExtensions) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionECHOuterExtensions >> 8)
	b[1] = byte(extensionECHOuterExtensions & 0xff)
	b[2] = byte((1 + 2*len(e.Types)) >> 8)
	b[3] = byte(1 + 2*len(e.Types))
	b[4] = byte(2 * len(e.Types))
	for i, typ := range e.Types {
		binary.BigEndian.PutUint16(b[5+2*i:], typ)
	}
	return e.Len(), io.EOF
}

// GREASEPreSharedKeyExtension is a pre_shared_key extension for the outer
// hello of real ECH with an ECHInnerSpec: when ClientHelloInner offers a
// session, it sends identities and binders of the same lengths filled with
// random bytes, and random obfuscated ticket ages (RFC 9849, Section
// 10.12.3), as Firefox does. Otherwise it writes nothing. Like any
// pre_shared_key extension it must be the last extension.
//
// [uTLS fork]
type GREASEPreSharedKeyExtension struct {
	identities []PskIdentity
	binders    [][]byte
}

func (*GREASEPreSharedKeyExtension) writeToUConn(*UConn) error {
	return nil
}

func (e *GREASEPreSharedKeyExtension) Len() int {
	return pskExtLen(e.identities, e.binders)
}

func (e *GREASEPreSharedKeyExtension) Read(b []byte) (int, error) {
	if e.Len() == 0 {
		return 0, io.EOF
	}
	return readPskIntoBytes(b, e.identities, e.binders)
}

// mirror gives e the shape of the identities and binders of inner, keeping
// its random values while the shape stays the same.
func (e *GREASEPreSharedKeyExtension) mirror(inner PreSharedKeyCommon, rand io.Reader) error {
	if len(inner.Identities) == 0 || len(inner.Binders) == 0 {
		e.identities, e.binders = nil, nil
		return nil
	}
	if slices.EqualFunc(e.identities, inner.Identities, func(a, b PskIdentity) bool { return len(a.Label) == len(b.Label) }) &&
		slices.EqualFunc(e.binders, inner.Binders, func(a, b []byte) bool { return len(a) == len(b) }) {
		return nil
	}
	e.identities = make([]PskIdentity, len(inner.Identities))
	for i, identity := range inner.Identities {
		var age [4]byte
		e.identities[i].Label = make([]byte, len(identity.Label))
		if _, err := io.ReadFull(rand, e.identities[i].Label); err != nil {
			return err
		}
		if _, err := io.ReadFull(rand, age[:]); err != nil {
			return err
		}
		e.identities[i].ObfuscatedTicketAge = binary.BigEndian.Uint32(age[:])
	}
	e.binders = make([][]byte, len(inner.Binders))
	for i, binder := range inner.Binders {
		e.binders[i] = make([]byte, len(binder))
		if _, err := io.ReadFull(rand, e.binders[i]); err != nil {
			return err
		}
	}
	return nil
}

// echInnerState is the ClientHelloInner of a UConn whose spec has an
// ECHInnerSpec.
type echInnerState struct {
	spec *ECHInnerSpec // owned: the extensions take GREASE values and HRR changes

	random             []byte
	cipherSuites       []uint16
	compressionMethods []uint8

	// outerExts is the ECHOuterExtensions of spec.Extensions, if any.
	outerExts *ECHOuterExtensions

	// earlyData is whether loadSession allowed 0-RTT with the session.
	earlyData bool

	// sent are the extensions ClientHelloInner sends, copied ones as the
	// outer hello's objects.
	sent []TLSExtension

	// sealed is set once a ClientHelloInner has been sealed with the HPKE
	// context, so that building ClientHello1 again starts a new one.
	sealed bool
}

// copies reports whether ClientHelloInner copies the outer hello's
// extension of type typ.
func (inner *echInnerState) copies(typ uint16) bool {
	return inner.outerExts != nil && slices.Contains(inner.outerExts.Types, typ)
}

var errECHOuterPSK = errors.New("tls: with ECHInner, the outer ClientHello's pre_shared_key can only be a FakePreSharedKeyExtension or a GREASEPreSharedKeyExtension; the session is resumed in ECHInner.Extensions")

// applyECHInnerSpec sets up ClientHelloInner from spec, after ApplyPreset has
// applied the outer hello.
func (uconn *UConn) applyECHInnerSpec(spec *ECHInnerSpec) error {
	uconn.echInner = nil
	if spec == nil || len(uconn.config.EncryptedClientHelloConfigList) == 0 {
		return nil
	}

	inner := &echInnerState{spec: spec, random: make([]byte, 32)}
	if _, err := io.ReadFull(uconn.config.rand(), inner.random); err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}

	if spec.CipherSuites == nil {
		inner.cipherSuites = slices.Clone(uconn.HandshakeState.Hello.CipherSuites)
	} else {
		inner.cipherSuites = slices.Clone(spec.CipherSuites)
		for i := range inner.cipherSuites {
			if isGREASEUint16(inner.cipherSuites[i]) {
				inner.cipherSuites[i] = getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_cipher)
			}
		}
	}
	inner.compressionMethods = spec.CompressionMethods
	if len(inner.compressionMethods) == 0 {
		inner.compressionMethods = []uint8{compressionNone}
	}

	// GREASE as ApplyPreset does for the outer hello, from the same seed.
	greaseExtensionsSeen := 0
	for _, e := range spec.Extensions {
		switch ext := e.(type) {
		case *SNIExtension:
			if ext.ServerName == "" {
				ext.ServerName = uconn.config.ServerName
			}
		case *UtlsGREASEExtension:
			switch greaseExtensionsSeen {
			case 0:
				ext.Value = getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_extension1)
			case 1:
				ext.Value = getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_extension2)
				ext.Body = []byte{0}
			default:
				return errors.New("tls: ECHInner: at most 2 grease extensions are supported")
			}
			greaseExtensionsSeen++
		case *SupportedCurvesExtension:
			for i := range ext.Curves {
				if isGREASEUint16(uint16(ext.Curves[i])) {
					ext.Curves[i] = CurveID(getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_group))
				}
			}
		case *SignatureAlgorithmsExtension:
			for i, scheme := range ext.SupportedSignatureAlgorithms {
				if isGREASEUint16(uint16(scheme)) {
					ext.SupportedSignatureAlgorithms[i] = SignatureScheme(getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_signature_algorithm))
				}
			}
		case *KeyShareExtension:
			for i := range ext.KeyShares {
				if isGREASEUint16(uint16(ext.KeyShares[i].Group)) {
					ext.KeyShares[i].Group = CurveID(getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_group))
				}
			}
		case *SupportedVersionsExtension:
			for i := range ext.Versions {
				if isGREASEUint16(ext.Versions[i]) {
					ext.Versions[i] = getBoringGREASEValue(uconn.greaseSeed[:], ssl_grease_version)
				}
			}
		case *ECHOuterExtensions:
			if inner.outerExts != nil {
				return errors.New("tls: ECHInner: Extensions holds more than one ECHOuterExtensions")
			}
			inner.outerExts = ext
		}
	}

	if err := uconn.checkECHInnerSpec(inner); err != nil {
		return err
	}
	uconn.echInner = inner
	return nil
}

// checkECHInnerSpec checks the parts of an ECHInnerSpec that depend on neither
// the session nor the server.
func (uconn *UConn) checkECHInnerSpec(inner *echInnerState) error {
	exts := inner.spec.Extensions
	markers := 0
	for i, ext := range exts {
		if _, ok := ext.(PreSharedKeyExtension); ok && i != len(exts)-1 {
			return errors.New("tls: ECHInner: the pre_shared_key extension must be the last extension")
		}
		if typ, _ := extensionTypeOf(ext); typ == extensionEncryptedClientHello {
			markers++
		}
	}
	if markers != 1 {
		return errors.New("tls: ECHInner: Extensions must hold exactly one ECHInnerExtension")
	}
	for i, ext := range uconn.Extensions {
		if _, ok := ext.(*GREASEPreSharedKeyExtension); ok && i != len(uconn.Extensions)-1 {
			return errors.New("tls: the GREASEPreSharedKeyExtension must be the last extension")
		}
	}
	if inner.outerExts == nil {
		return nil
	}
	for _, typ := range inner.outerExts.Types {
		switch typ {
		case extensionEncryptedClientHello, extensionECHOuterExtensions, extensionPreSharedKey:
			return fmt.Errorf("tls: ECHInner: extension %d cannot be copied from the outer ClientHello", typ)
		}
	}
	_, err := uconn.echCopiedExtensions(inner.outerExts.Types)
	return err
}

// echCopiedExtensions returns the outer hello's extensions of types, found as
// the server finds them: in one forward pass over the outer extensions.
func (uconn *UConn) echCopiedExtensions(types []uint16) ([]TLSExtension, error) {
	copied := make([]TLSExtension, len(types))
	next := 0
	for i, typ := range types {
		for ; next < len(uconn.Extensions); next++ {
			if t, ok := extensionTypeOf(uconn.Extensions[next]); ok && (t == typ || isGREASEUint16(t) && isGREASEUint16(typ)) {
				copied[i] = uconn.Extensions[next]
				next++
				break
			}
		}
		if copied[i] == nil {
			return nil, fmt.Errorf("tls: ECHInner: extension %d of ECHOuterExtensions is not in the outer ClientHello after the extensions listed before it", typ)
		}
	}
	return copied, nil
}

// extensionTypeOf returns the type of ext, or false if ext writes nothing
// and its type is not fixed.
func extensionTypeOf(ext TLSExtension) (uint16, bool) {
	switch e := ext.(type) {
	case *GenericExtension:
		return e.Id, true
	case *UtlsGREASEExtension:
		return e.Value, true
	case *SNIExtension:
		return extensionServerName, true
	case *StatusRequestExtension:
		return extensionStatusRequest, true
	case *SupportedCurvesExtension:
		return extensionSupportedCurves, true
	case *SupportedPointsExtension:
		return extensionSupportedPoints, true
	case *SignatureAlgorithmsExtension:
		return extensionSignatureAlgorithms, true
	case *ALPNExtension:
		return extensionALPN, true
	case *SCTExtension:
		return extensionSCT, true
	case *UtlsPaddingExtension:
		return utlsExtensionPadding, true
	case *ExtendedMasterSecretExtension:
		return extensionExtendedMasterSecret, true
	case *UtlsCompressCertExtension:
		return utlsExtensionCompressCertificate, true
	case ISessionTicketExtension:
		return extensionSessionTicket, true
	case PreSharedKeyExtension, *GREASEPreSharedKeyExtension:
		return extensionPreSharedKey, true
	case *SupportedVersionsExtension:
		return extensionSupportedVersions, true
	case *CookieExtension:
		return extensionCookie, true
	case *PSKKeyExchangeModesExtension:
		return extensionPSKModes, true
	case *SignatureAlgorithmsCertExtension:
		return extensionSignatureAlgorithmsCert, true
	case *KeyShareExtension:
		return extensionKeyShare, true
	case *QUICTransportParametersExtension:
		return extensionQUICTransportParameters, true
	case *ApplicationSettingsExtension:
		return utlsExtensionApplicationSettings, true
	case *ApplicationSettingsExtensionNew:
		return utlsExtensionApplicationSettingsNew, true
	case *RenegotiationInfoExtension:
		return extensionRenegotiationInfo, true
	case EncryptedClientHelloExtension, *ECHInnerExtension:
		return extensionEncryptedClientHello, true
	case *ECHOuterExtensions:
		return extensionECHOuterExtensions, true
	}
	b, err := marshalExtension(ext)
	if err != nil || len(b) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

// marshalExtension returns the bytes ext writes, type and length included;
// none if it is left out of the hello.
func marshalExtension(ext TLSExtension) ([]byte, error) {
	var b bytes.Buffer
	b.Grow(ext.Len())
	if _, err := b.ReadFrom(ext); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// echDefaultPadding pads an EncodedClientHelloInner as RFC 9849, Section
// 6.1.3 suggests, as crypto/tls does.
func echDefaultPadding(encodedLen, serverNameLen, maxNameLength int) int {
	var paddingLen int
	if serverNameLen > 0 {
		paddingLen = max(0, maxNameLength-serverNameLen)
	} else {
		paddingLen = maxNameLength + 9
	}
	return paddingLen + 31 - ((encodedLen + paddingLen - 1) % 32)
}

// echInnerSessionHello returns the hello loadSession checks a cached session
// against: the session is offered in ClientHelloInner, which only offers
// TLS 1.3.
func (uconn *UConn) echInnerSessionHello() *clientHelloMsg {
	hello := &clientHelloMsg{
		vers:                 VersionTLS12,
		cipherSuites:         uconn.echInner.cipherSuites,
		supportedVersions:    []uint16{VersionTLS13},
		encryptedClientHello: []byte{byte(innerECHExt)},
	}
	for _, ext := range uconn.echInnerExtensions() {
		if alpn, ok := ext.(*ALPNExtension); ok {
			hello.alpnProtocols = alpn.AlpnProtocols
		}
	}
	return hello
}

// echInnerExtensions returns ClientHelloInner's extensions, copied ones as
// the outer hello's objects.
func (uconn *UConn) echInnerExtensions() []TLSExtension {
	inner := uconn.echInner
	if inner.sent != nil {
		return inner.sent
	}
	exts := make([]TLSExtension, 0, len(inner.spec.Extensions))
	for _, ext := range inner.spec.Extensions {
		if outerExts, ok := ext.(*ECHOuterExtensions); ok {
			copied, err := uconn.echCopiedExtensions(outerExts.Types)
			if err == nil {
				exts = append(exts, copied...)
			}
			continue
		}
		exts = append(exts, ext)
	}
	return exts
}

// helloExtensions returns the extensions of the ClientHello the server
// answered: ClientHelloInner's once the server accepted ECH with an
// ECHInnerSpec, the outer hello's otherwise.
func (uconn *UConn) helloExtensions() []TLSExtension {
	if uconn.echInner != nil && uconn.echAccepted {
		return uconn.echInnerExtensions()
	}
	return uconn.Extensions
}

// helloCertCompressionAlgs returns the certificate compression algorithms of
// the ClientHello the server answered.
func (uconn *UConn) helloCertCompressionAlgs() []CertCompressionAlgo {
	if uconn.echInner != nil && uconn.echAccepted {
		for _, ext := range uconn.echInnerExtensions() {
			if compressCert, ok := ext.(*UtlsCompressCertExtension); ok {
				return compressCert.Algorithms
			}
		}
		return nil
	}
	return uconn.certCompressionAlgs
}

// marshalECHInnerHello builds ClientHelloInner from the ECHInnerSpec, computes
// its PSK binders, encodes and seals it into the outer hello's
// encrypted_client_hello extension and marshals the outer hello. useKey is
// false for the ClientHello that answers a HelloRetryRequest, which carries
// no encapsulated key (RFC 9849, Section 6.1.5).
func (uconn *UConn) marshalECHInnerHello(useKey bool) error {
	inner := uconn.echInner
	ech := uconn.echCtx
	if ech == nil {
		return errors.New("tls: internal error: ECHInner without an ECH context")
	}
	if useKey && inner.sealed {
		// BuildHandshakeState ran before: ClientHello1 must be the first
		// message of its HPKE context.
		if err := ech.newSender(); err != nil {
			return err
		}
	}

	// The outer hello's GREASE pre_shared_key mirrors ClientHelloInner's.
	exts := inner.spec.Extensions
	var innerPSK PreSharedKeyCommon
	if psk, ok := exts[len(exts)-1].(PreSharedKeyExtension); ok && psk.Len() > 0 {
		innerPSK = psk.GetPreSharedKeyCommon()
	}
	for _, ext := range uconn.Extensions {
		if grease, ok := ext.(*GREASEPreSharedKeyExtension); ok {
			if err := grease.mirror(innerPSK, uconn.config.rand()); err != nil {
				return err
			}
		}
	}

	// A copied padding extension depends on the length of the outer hello,
	// which depends on the length of EncodedClientHelloInner: build until
	// they agree.
	for range 4 {
		innerRaw, encodedInner, err := uconn.encodeECHInnerHello(ech)
		if err != nil {
			return err
		}
		if inner.copies(utlsExtensionPadding) {
			before, err := marshalExtension(uconn.outerExtension(utlsExtensionPadding))
			if err != nil {
				return err
			}
			if err := uconn.marshalOuterECHPayload(ech, useKey, make([]byte, len(encodedInner)+16)); err != nil {
				return err
			}
			after, err := marshalExtension(uconn.outerExtension(utlsExtensionPadding))
			if err != nil {
				return err
			}
			if !bytes.Equal(before, after) {
				continue
			}
		}

		if err := uconn.sealOuterECHExtension(encodedInner, ech, useKey); err != nil {
			return err
		}
		inner.sealed = true

		innerHello := new(clientHelloMsg)
		if !innerHello.unmarshal(innerRaw) {
			return errors.New("tls: ECHInner does not form a valid ClientHelloInner")
		}
		// 0-RTT needs both the early_data extension and a session that
		// allows it.
		innerHello.earlyData = innerHello.earlyData && inner.earlyData
		ech.innerHello = innerHello
		return nil
	}
	return errors.New("tls: ECHInner: the copied padding extension does not settle")
}

// echInnerPiece is one extension of ClientHelloInner as it is built.
type echInnerPiece struct {
	data   []byte
	copied bool
}

// encodeECHInnerHello returns ClientHelloInner, as the server reconstructs it
// and with its PSK binders, and EncodedClientHelloInner, padded.
func (uconn *UConn) encodeECHInnerHello(ech *echClientContext) (innerRaw, encodedInner []byte, err error) {
	inner := uconn.echInner
	outer := uconn.HandshakeState.Hello
	exts := inner.spec.Extensions

	var outerKeyShares []KeyShare
	for _, ext := range uconn.Extensions {
		if ks, ok := ext.(*KeyShareExtension); ok {
			outerKeyShares = ks.KeyShares
		}
	}

	pieces := make([]echInnerPiece, 0, len(exts))
	sent := make([]TLSExtension, 0, len(exts))
	var copiedTypes []uint16
	var paddingExt *UtlsPaddingExtension
	paddingAt := -1
	serverNameLen := 0
	for _, ext := range exts {
		switch e := ext.(type) {
		case *ECHOuterExtensions:
			copied, err := uconn.echCopiedExtensions(e.Types)
			if err != nil {
				return nil, nil, err
			}
			for _, outerExt := range copied {
				data, err := marshalExtension(outerExt)
				if err != nil {
					return nil, nil, err
				}
				if len(data) == 0 {
					continue
				}
				copiedTypes = append(copiedTypes, binary.BigEndian.Uint16(data))
				pieces = append(pieces, echInnerPiece{data: data, copied: true})
				sent = append(sent, outerExt)
			}
			continue
		case *UtlsPaddingExtension:
			if paddingExt != nil {
				return nil, nil, errors.New("tls: ECHInner: multiple padding extensions")
			}
			paddingExt, paddingAt = e, len(pieces)
			pieces = append(pieces, echInnerPiece{})
			sent = append(sent, ext)
			continue
		case *KeyShareExtension:
			if err := copyOuterKeyShares(e, outerKeyShares); err != nil {
				return nil, nil, err
			}
		case *QUICTransportParametersExtension:
			if err := e.writeToUConn(uconn); err != nil {
				return nil, nil, err
			}
		case *SNIExtension:
			serverNameLen = len(e.hostName())
		}
		data, err := marshalExtension(ext)
		if err != nil {
			return nil, nil, err
		}
		if len(data) == 0 {
			continue
		}
		pieces = append(pieces, echInnerPiece{data: data})
		sent = append(sent, ext)
	}

	extensionsLen := 0
	for _, p := range pieces {
		extensionsLen += len(p.data)
	}
	if paddingExt != nil {
		// As MarshalClientHelloNoECH sizes the outer hello's padding.
		headerLength := 2 + 32 + 1 + len(outer.SessionId) +
			2 + len(inner.cipherSuites)*2 +
			1 + len(inner.compressionMethods)
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		data, err := marshalExtension(paddingExt)
		if err != nil {
			return nil, nil, err
		}
		pieces[paddingAt].data = data
		extensionsLen += len(data)
	}

	// ClientHelloInner as the server reconstructs it: with the outer
	// hello's legacy_session_id and copied extensions.
	b := cryptobyte.NewBuilder(make([]byte, 0, 4+2+32+1+len(outer.SessionId)+2+2*len(inner.cipherSuites)+1+len(inner.compressionMethods)+2+extensionsLen))
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(outer.Vers)
		b.AddBytes(inner.random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(outer.SessionId)
		})
		addCipherSuites(b, inner.cipherSuites)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(inner.compressionMethods)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, p := range pieces {
				b.AddBytes(p.data)
			}
		})
	})
	if innerRaw, err = b.Bytes(); err != nil {
		return nil, nil, err
	}

	// The binders cover ClientHelloInner; PatchBuiltHello writes them into
	// innerRaw.
	if psk, ok := exts[len(exts)-1].(PreSharedKeyExtension); ok && psk.Len() > 0 {
		if err := psk.PatchBuiltHello(&PubClientHelloMsg{Raw: innerRaw}); err != nil && err != io.EOF {
			return nil, nil, err
		}
	}

	// EncodedClientHelloInner: no legacy_session_id, the copied extensions
	// as ech_outer_extensions, zero padding.
	e := cryptobyte.NewBuilder(make([]byte, 0, len(innerRaw)))
	e.AddUint16(outer.Vers)
	e.AddBytes(inner.random)
	e.AddUint8(0) // legacy_session_id
	addCipherSuites(e, inner.cipherSuites)
	e.AddUint8LengthPrefixed(func(e *cryptobyte.Builder) {
		e.AddBytes(inner.compressionMethods)
	})
	e.AddUint16LengthPrefixed(func(e *cryptobyte.Builder) {
		offset := len(innerRaw) - extensionsLen
		listWritten := false
		for _, p := range pieces {
			data := innerRaw[offset : offset+len(p.data)]
			offset += len(p.data)
			if !p.copied {
				e.AddBytes(data)
				continue
			}
			if listWritten {
				continue
			}
			listWritten = true
			e.AddUint16(extensionECHOuterExtensions)
			e.AddUint16LengthPrefixed(func(e *cryptobyte.Builder) {
				e.AddUint8LengthPrefixed(func(e *cryptobyte.Builder) {
					for _, typ := range copiedTypes {
						e.AddUint16(typ)
					}
				})
			})
		}
	})
	if encodedInner, err = e.Bytes(); err != nil {
		return nil, nil, err
	}
	padding := inner.spec.Padding
	if padding == nil {
		padding = echDefaultPadding
	}
	paddingLen := padding(len(encodedInner), serverNameLen, int(ech.config.MaxNameLength))
	if paddingLen < 0 {
		return nil, nil, errors.New("tls: ECHInner: Padding returned a negative length")
	}
	encodedInner = append(encodedInner, make([]byte, paddingLen)...)

	inner.sent = sent
	return innerRaw, encodedInner, nil
}

func addCipherSuites(b *cryptobyte.Builder, cipherSuites []uint16) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, suite := range cipherSuites {
			b.AddUint16(suite)
		}
	})
}

// outerExtension returns the outer hello's extension of type typ, if any.
func (uconn *UConn) outerExtension(typ uint16) TLSExtension {
	for _, ext := range uconn.Extensions {
		if t, ok := extensionTypeOf(ext); ok && t == typ {
			return ext
		}
	}
	return nil
}

// copyOuterKeyShares sets the key exchange data of ks to the outer hello's
// shares of the same groups: ClientHelloInner has no private keys of its own.
func copyOuterKeyShares(ks *KeyShareExtension, outer []KeyShare) error {
	for i := range ks.KeyShares {
		share := &ks.KeyShares[i]
		grease := isGREASEUint16(uint16(share.Group))
		if grease && len(share.Data) > 0 {
			continue
		}
		j := slices.IndexFunc(outer, func(o KeyShare) bool {
			return o.Group == share.Group || grease && isGREASEUint16(uint16(o.Group))
		})
		if j < 0 {
			return fmt.Errorf("tls: ECHInner: key share for group %v is not among the outer ClientHello's key shares", share.Group)
		}
		share.Data = outer[j].Data
	}
	return nil
}

// newSender starts a new HPKE context for the ECH config.
func (ech *echClientContext) newSender() error {
	kem, err := hpke.NewKEM(ech.config.KemID)
	if err != nil {
		return err
	}
	pub, err := kem.NewPublicKey(ech.config.PublicKey)
	if err != nil {
		return err
	}
	kdf, err := hpke.NewKDF(ech.kdfID)
	if err != nil {
		return err
	}
	aead, err := hpke.NewAEAD(ech.aeadID)
	if err != nil {
		return err
	}
	info := append([]byte("tls ech\x00"), ech.config.raw...)
	ech.encapsulatedKey, ech.hpkeContext, err = hpke.NewSender(pub, kdf, aead, info)
	return err
}

// retryECHInner rebuilds ClientHelloInner for the second ClientHello, after a
// HelloRetryRequest that accepted ECH: the new key share, the cookie, no
// early_data, binders over the inner transcript, sealed again without an
// encapsulated key. chHash is the hash of the first ClientHelloInner.
func (uconn *UConn) retryECHInner(hs *clientHandshakeStateTLS13, chHash []byte) error {
	inner := uconn.echInner
	shares := keyShares(hs.echContext.innerHello.keyShares).ToPublic()
	cookie := hs.serverHello.cookie

	// RFC 8446, Section 4.2.10: no early_data after a HelloRetryRequest.
	exts := slices.DeleteFunc(inner.spec.Extensions, func(ext TLSExtension) bool {
		typ, ok := extensionTypeOf(ext)
		return ok && typ == extensionEarlyData
	})
	// Copied extensions follow the outer hello, which has them already.
	cookieSet := len(cookie) == 0 || inner.copies(extensionCookie)
	for _, ext := range exts {
		switch e := ext.(type) {
		case *KeyShareExtension:
			e.KeyShares = slices.Clone(shares)
		case *CookieExtension:
			if !cookieSet {
				e.Cookie = cookie
				cookieSet = true
			}
		case PreSharedKeyExtension:
			if e.Len() > 0 {
				// On error the extension drops the session, and
				// ClientHelloInner leaves pre_shared_key out.
				_ = e.UpdateOnHRR(chHash, hs, uconn.config.time())
			}
		}
	}
	if !cookieSet {
		// As for the outer hello: among the permutable extensions.
		lo, hi := cookieSpliceRange(exts)
		p, err := newPRNG()
		if err != nil {
			return err
		}
		exts = slices.Insert(exts, lo+p.Intn(hi-lo+1), TLSExtension(&CookieExtension{Cookie: cookie}))
	}
	inner.spec.Extensions = exts
	inner.earlyData = false
	return uconn.marshalECHInnerHello(false)
}
