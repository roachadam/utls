package tls

// positionInvariantExtension reports whether ext keeps its position when a
// browser permutes its extensions: GREASE brackets the list, padding sizes the
// record, and pre_shared_key must be last (RFC 8446, Section 4.2.11).
func positionInvariantExtension(ext TLSExtension) bool {
	switch ext.(type) {
	case *UtlsGREASEExtension, *UtlsPaddingExtension, PreSharedKeyExtension:
		return true
	default:
		return false
	}
}

// cookieSpliceRange returns the inclusive range of indices at which the cookie
// echoed after a HelloRetryRequest may be inserted. BoringSSL emits the cookie
// from the same extension table as every other extension, so it lands among
// the permutable ones: after the leading pinned run (GREASE) and before the
// trailing one (GREASE, padding, pre_shared_key).
func cookieSpliceRange(exts []TLSExtension) (lo, hi int) {
	first, last := -1, -1
	for i, ext := range exts {
		if !positionInvariantExtension(ext) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first >= 0 {
		return first, last + 1
	}
	// Nothing permutable: append, but keep pre_shared_key last.
	n := len(exts)
	if n > 0 {
		if _, ok := exts[n-1].(PreSharedKeyExtension); ok {
			n--
		}
	}
	return n, n
}
