package dkim

import (
	"bufio"
	"net/mail"
)

func ParseEml(r *bufio.Reader) (*DKIM, error) {
	var Dkim *DKIM
	var msg *mail.Message
	var raw_headers mail.Header
	var err error
	var header string

	raw_headers, r = getRawHeaders(r)

	if msg, err = mail.ReadMessage(r); err != nil {
		return nil, err
	}

	if header, err = findDkimHeader(raw_headers); err != nil {
		return nil, ErrSignatureNotFound
	}

	if Dkim, err = NewDKIM(header, msg); err != nil {
		return nil, err
	}
	Dkim.RawMailHeader = raw_headers
	return Dkim, nil
}

// FromMessage builds DKIM from mail.Message
func FromMessage(msg *mail.Message) (*DKIM, error) {
	var (
		m   *DKIM
		err error
		hdr string
	)

	if hdr, err = findDkimHeader(msg.Header); err != nil {
		return nil, ErrSignatureNotFound
	}

	if m, err = NewDKIM(hdr, msg); err != nil {
		return nil, err
	}

	m.RawMailHeader = msg.Header
	return m, nil
}
