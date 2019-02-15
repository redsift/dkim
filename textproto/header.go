package textproto

import "net/textproto"

// MIMEHeader is convenient alias for textproto.MIMEHeader
type MIMEHeader textproto.MIMEHeader

// A OrigHeader represents the key-value pairs in a mail message header.
type OrigHeader map[string][]string

// Get gets the first value associated with the given key.
// It is case sensitive.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, or to use non-canonical keys,
// access the map directly.
func (h OrigHeader) Get(key string) string {
	if h == nil {
		return ""
	}
	v := h[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
