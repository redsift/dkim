package mail

import (
	"bufio"
	"bytes"
	"io"
	"net/mail"
	"strings"

	"github.com/redsift/dkim/textproto"
)

type Message struct {
	OrigHeader textproto.OrigHeader
	mail.Message
}

func NewMessage(h Header, b io.Reader) *Message {
	return &Message{
		OrigHeader: h.Orig,
		Message: mail.Message{
			Header: mail.Header(h.MIME),
			Body:   b,
		},
	}
}

type Header struct {
	Orig textproto.OrigHeader
	MIME textproto.MIMEHeader
}

func ParseMessage(s string) (Header, []byte, error) {
	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(s)))

	var err error
	h := Header{}

	h.MIME, h.Orig, err = tp.ReadMIMEHeader()
	if err != nil {
		return h, nil, err
	}

	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(tp.R); err != nil {
		return h, nil, err
	}

	return h, body.Bytes(), nil
}
