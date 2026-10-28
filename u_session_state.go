package tls

import "time"

// Version returns the TLS version the session was established with.
//
// It lets a [ClientSessionCache] sort a session without encoding it with
// [SessionState.Bytes], which copies the whole certificate chain.
func (s *SessionState) Version() uint16 {
	return s.version
}

// UseBy returns the time after which a client must not offer the TLS 1.3
// session: the ticket lifetime from when it was received, capped at seven
// days. It is the zero Time for a TLS 1.0–1.2 session and on the server.
func (s *SessionState) UseBy() time.Time {
	if !s.isClient || s.version < VersionTLS13 || s.useBy == 0 {
		return time.Time{}
	}

	return time.Unix(int64(s.useBy), 0)
}
