package mail

import (
	"bufio"
	"bytes"
	"net/mail"
	"strings"

	"github.com/redsift/dkim/textproto"
)

// A OriginalHeader represents the key-value pairs in a mail message header.
type OriginalHeader map[string][]string

// Get gets the first value associated with the given key.
// It is case sensitive.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, or to use non-canonical keys,
// access the map directly.
func (h OriginalHeader) Get(key string) string {
	if h == nil {
		return ""
	}
	v := h[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func ParseMessage(s string) (mail.Header, []byte, error) {
	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(s)))

	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, nil, err
	}

	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(tp.R); err != nil {
		return nil, nil, err
	}

	return mail.Header(hdr), body.Bytes(), nil
}
