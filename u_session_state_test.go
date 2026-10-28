package tls

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestSessionStateAccessors(t *testing.T) {
	useBy := time.Unix(1_900_000_000, 0)
	tests := []struct {
		name  string
		s     *SessionState
		useBy time.Time
	}{
		{"client TLS 1.3", &SessionState{version: VersionTLS13, isClient: true, useBy: uint64(useBy.Unix()), ageAdd: 7}, useBy},
		{"client TLS 1.2", &SessionState{version: VersionTLS12, isClient: true}, time.Time{}},
		{"server TLS 1.3", &SessionState{version: VersionTLS13}, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := tt.s.Bytes()
			if err != nil {
				t.Fatal(err)
			}

			// The encoding starts with the version, and a client TLS 1.3
			// session's ends with use_by and age_add.
			if got, want := tt.s.Version(), binary.BigEndian.Uint16(enc); got != want {
				t.Errorf("Version() = %#x, encoding has %#x", got, want)
			}
			if !tt.s.UseBy().Equal(tt.useBy) {
				t.Errorf("UseBy() = %v, want %v", tt.s.UseBy(), tt.useBy)
			}
			if !tt.useBy.IsZero() {
				if got := binary.BigEndian.Uint64(enc[len(enc)-12:]); got != uint64(tt.useBy.Unix()) {
					t.Errorf("encoding has use_by %d, want %d", got, tt.useBy.Unix())
				}
			}
		})
	}
}
