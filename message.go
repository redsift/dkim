package dkim

import (
	"bufio"
	"io"
	"strings"
)

type Message struct {
	Header MIMEHeader
	Body   io.ReadSeeker
}

func ParseMessage(s string) (*Message, error) {
	sr := strings.NewReader(s)
	tr := NewReader(bufio.NewReader(sr))

	var err error

	h, err := tr.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	// adjust sr position on a length of buffered by tr
	pos, _ := sr.Seek(-int64(tr.R.Buffered()), io.SeekCurrent)

	return &Message{h, strings.NewReader(s[pos:])}, nil
}
