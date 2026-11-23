package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// The server's CertificateVerify signs the transcript of the messages it sent.
// readServerCertificate must hash the CertificateRequest and Certificate it
// received as they were sent: marshalCertificate rebuilds a Certificate in one
// extension order and drops extensions it does not keep, so a transcript of
// the rebuilt message fails the signature.
func TestReadServerCertificateHashesMessagesAsReceived(t *testing.T) {
	sct := []byte{0, 18, 0, 5, 0, 3, 0, 1, 1} // signed_certificate_timestamp
	ocsp := []byte{0, 5, 0, 5, 1, 0, 0, 1, 2} // status_request, OCSP
	unknown := []byte{0xff, 0xa5, 0, 3, 3, 4, 5}
	leaf, intermediate := testECDSAP256Cert.Certificate[0], testRootCert.Certificate[0]

	for _, test := range []struct {
		name                   string
		leafExtensions         []byte
		intermediateExtensions []byte
		certificateRequest     bool
		compressed             bool // sent as a zlib CompressedCertificate
	}{
		{name: "OCSP before SCT", leafExtensions: append(bytes.Clone(ocsp), sct...)},
		{name: "SCT before OCSP", leafExtensions: append(bytes.Clone(sct), ocsp...)},
		{name: "unknown leaf extension", leafExtensions: unknown},
		{name: "intermediate extension", intermediateExtensions: sct},
		{name: "after a CertificateRequest", leafExtensions: append(bytes.Clone(sct), ocsp...), certificateRequest: true},
		{name: "compressed", leafExtensions: append(bytes.Clone(sct), ocsp...), compressed: true},
		{name: "compressed after a CertificateRequest", leafExtensions: append(bytes.Clone(sct), ocsp...), certificateRequest: true, compressed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var received []byte
			if test.certificateRequest {
				certReq, err := (&certificateRequestMsgTLS13{
					supportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256},
				}).marshal()
				if err != nil {
					t.Fatal(err)
				}
				received = append(received, certReq...)
			}

			var b cryptobyte.Builder
			b.AddUint8(typeCertificate)
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0) // certificate_request_context
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, entry := range []struct{ cert, extensions []byte }{
						{leaf, test.leafExtensions},
						{intermediate, test.intermediateExtensions},
					} {
						b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(entry.cert) })
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(entry.extensions) })
					}
				})
			})
			certificate := b.BytesOrPanic()
			if test.compressed {
				body := certificate[4:]
				var err error
				certificate, err = (&utlsCompressedCertificateMsg{
					algorithm:                    uint16(CertCompressionZlib),
					uncompressedLength:           uint32(len(body)),
					compressedCertificateMessage: compressZlibTestCertificate(t, body),
				}).marshal()
				if err != nil {
					t.Fatal(err)
				}
			}
			received = append(received, certificate...)

			earlier := []byte("ClientHello...EncryptedExtensions")
			serverTranscript := sha256.New()
			serverTranscript.Write(earlier)
			serverTranscript.Write(received)
			digest := sha256.Sum256(signedMessage(serverSignatureContext, serverTranscript))
			signature, err := ecdsa.SignASN1(rand.Reader, testECDSAP256Key, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			certVerify, err := (&certificateVerifyMsg{
				hasSignatureAlgorithm: true,
				signatureAlgorithm:    ECDSAWithP256AndSHA256,
				signature:             signature,
			}).marshal()
			if err != nil {
				t.Fatal(err)
			}

			c := &Conn{
				conn:     &discardConn{},
				isClient: true,
				vers:     VersionTLS13,
				haveVers: true,
				config:   &Config{InsecureSkipVerify: true},
			}
			c.hand.Write(received)
			c.hand.Write(certVerify)
			hs := &clientHandshakeStateTLS13{c: c, ctx: t.Context(), transcript: crypto.SHA256.New()}
			if test.compressed {
				hs.uconn = &UConn{
					Extensions:          []TLSExtension{&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}}},
					certCompressionAlgs: []CertCompressionAlgo{CertCompressionZlib},
				}
			}
			hs.transcript.Write(earlier)

			if err := hs.readServerCertificate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
