// This is a modified copy of go1.11.5 textproto.Reader
package dkim

import (
	"bufio"
	"bytes"
	"net/textproto"
)

// A Reader implements convenience methods for reading requests
// or responses from a text protocol network connection.
type Reader struct {
	R     *bufio.Reader
	fBuf  []byte // a re-usable buffer for readContinuedLineSlice
	uBuf  []byte // a re-usable buffer for readContinuedLineSlice; holds original unfolded value
	wsBuf []byte // a re-usable buffer for skipSpaces; holds all skipped spaces
}

// NewReader returns a new Reader reading from r.
//
// To avoid denial of service attacks, the provided bufio.Reader
// should be reading from an io.LimitReader or similar Reader to bound
// the size of responses.
func NewReader(r *bufio.Reader) *Reader {
	return &Reader{R: r}
}

// KVPair holds key-value pair of the message header as it needed for DKIM verification
type KVPair struct {
	Key      string // Original header key as it was read from the message
	Original string // Original unfolded value of the header
	Folded   string // Folded value of the header
}

// A MIMEHeader represents the key-value pairs in a mail message header.
type MIMEHeader map[string][]KVPair

// CanonicalizedAndFolded converts MIMEHeader into map[string][]string, where key is canonicalized header and
// values are folded. The map could be used as mail.Headed
func (h MIMEHeader) CanonicalizedAndFolded() map[string][]string {
	m := make(map[string][]string)

	for k, p := range h {
		pLen := len(p)
		l := make([]string, pLen, pLen)
		for i := 0; i < pLen; i++ {
			l[i] = p[i].Folded
		}
		m[k] = l
	}

	return m
}

// ReadMIMEHeader reads a MIME-style header from r.
// The header is a sequence of possibly continued Key: Value lines
// ending in a blank line.
// The returned map m maps CanonicalMIMEHeaderKey(key) to a
// sequence of values in the same order encountered in the input.
//
// For example, consider this input:
//
//	my-key: Value 1
//	Long-Key: Even
//	       Longer Value
//	My-Key: Value 2
//
// Given that input, ReadMIMEHeader returns the map:
//
//  map[string][]KVPair{
//      "My-Key": {
//          {"my-key", "Value 1", "Value 1"},
//		    {"My-Key", "Value 2", "Value 2"},
//	    },
//	    "Long-Key": {
//		    {"Long-Key", "Even\n       Longer Value", "Even Longer Value"},
//	    },
//  }
func (r *Reader) ReadMIMEHeader() (MIMEHeader, error) {
	m := make(MIMEHeader, r.upcomingHeaderNewlines())

	// The first line cannot start with a leading space.
	if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t') {
		line, err := r.readLineSlice()
		if err != nil {
			return m, err
		}
		return m, textproto.ProtocolError("malformed MIME header initial line: " + string(line))
	}

	for {
		fLine, uLine, err := r.readContinuedLineSlice()
		if len(fLine) == 0 {
			return m, err
		}

		// Key ends at first colon; should not have trailing spaces
		// but they appear in the wild, violating specs, so we remove
		// them if present.
		i := bytes.IndexByte(fLine, ':')
		if i < 0 {
			return m, textproto.ProtocolError("malformed MIME header line: " + string(fLine))
		}
		endKey := i
		for endKey > 0 && fLine[endKey-1] == ' ' {
			endKey--
		}

		// As per RFC 7230 field-name is a token, tokens consist of one or more chars.
		// We could return a ProtocolError here, but better to be liberal in what we
		// accept, so if we get an empty key, skip it.
		if string(fLine[:endKey]) == "" {
			continue
		}

		hdr := KVPair{}

		// Save original key here before it could be mutated by canonicalMIMEHeaderKey
		// We use folded line as key should be trimmed anyway
		hdr.Key = newString(uLine[:bytes.IndexByte(uLine, ':')])

		key := canonicalMIMEHeaderKey(fLine[:endKey])

		// Skip initial spaces in value.
		i++ // skip colon
		for i < len(fLine) && (fLine[i] == ' ' || fLine[i] == '\t') {
			i++
		}
		hdr.Folded = newString(fLine[i:])
		// skip all checks, as fLine has been checked already
		hdr.Original = newString(uLine[bytes.IndexByte(uLine, ':')+1:])

		if pairs, found := m[key]; !found {
			// More than likely this will be a single-element key.
			// Most headers aren't multi-valued.
			// Set the capacity on pairs[0] to 1, so any future append
			// won't extend the slice
			pairs = make([]KVPair, 1, 1)
			pairs[0] = hdr
			m[key] = pairs
		} else {
			m[key] = append(pairs, hdr)
		}

		if err != nil {
			return m, err
		}
	}
}

func newString(s []byte) string {
	buf := make([]byte, len(s))
	copy(buf, s)
	return string(buf)
}

// ReadLineBytes is like ReadLine but returns a []byte instead of a string.
func (r *Reader) ReadLineBytes() ([]byte, error) {
	line, err := r.readLineSlice()
	if line != nil {
		buf := make([]byte, len(line))
		copy(buf, line)
		line = buf
	}
	return line, err
}

func (r *Reader) readLineSlice() ([]byte, error) {
	var line []byte
	for {
		l, more, err := r.R.ReadLine()
		if err != nil {
			return nil, err
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

// trim returns s with leading and trailing spaces and tabs removed.
// It does not assume Unicode or UTF-8.
func trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	n := len(s)
	for n > i && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return s[i:n]
}

func (r *Reader) readContinuedLineSlice() ([]byte, []byte, error) {
	// Read the first line.
	line, err := r.readLineSlice()
	if err != nil {
		return nil, nil, err
	}
	if len(line) == 0 { // blank line - no continuation
		return line, line, nil
	}

	// Optimistically assume that we have started to buffer the next line
	// and it starts with an ASCII letter (the next header key), so we can
	// avoid copying that buffered data around in memory and skipping over
	// non-existent whitespace.
	if r.R.Buffered() > 1 {
		peek, err := r.R.Peek(1)
		if err == nil && isASCIILetter(peek[0]) {
			return trim(line), line, nil
		}
	}

	// ReadByte or the next readLineSlice will flush the read buffer;
	// copy the slice into buf.
	r.uBuf = append(r.uBuf[:0], line...)
	r.fBuf = append(r.fBuf[:0], trim(line)...)

	// Read continuation lines.
	for {
		n, ws := r.skipSpace()
		if n == 0 {
			break
		}
		line, err := r.readLineSlice()
		if err != nil {
			break
		}

		r.fBuf = append(r.fBuf, ' ')
		r.fBuf = append(r.fBuf, trim(line)...)

		r.uBuf = append(r.uBuf, '\n')
		r.uBuf = append(r.uBuf, ws...)
		r.uBuf = append(r.uBuf, line...)
	}
	return r.fBuf, r.uBuf, nil
}

func isASCIILetter(b byte) bool {
	b |= 0x20 // make lower case
	return 'a' <= b && b <= 'z'
}

// skipSpace skips R over all spaces and returns the number of bytes skipped.
func (r *Reader) skipSpace() (int, []byte) {
	n := 0
	r.wsBuf = r.wsBuf[:0]
	for {
		c, err := r.R.ReadByte()
		if err != nil {
			// Bufio will keep err until next read.
			break
		}
		if c != ' ' && c != '\t' {
			_ = r.R.UnreadByte()
			break
		}
		r.wsBuf = append(r.wsBuf, c)
		n++
	}
	return n, r.wsBuf
}

// upcomingHeaderNewlines returns an approximation of the number of newlines
// that will be in this header. If it gets confused, it returns 0.
func (r *Reader) upcomingHeaderNewlines() (n int) {
	// Try to determine the 'hint' size.
	_, _ = r.R.Peek(1) // force a buffer load if empty
	s := r.R.Buffered()
	if s == 0 {
		return
	}
	peek, _ := r.R.Peek(s)
	for len(peek) > 0 {
		i := bytes.IndexByte(peek, '\n')
		if i < 3 {
			// Not present (-1) or found within the next few bytes,
			// implying we're at the end ("\r\n\r\n" or "\n\n")
			return
		}
		n++
		peek = peek[i+1:]
	}
	return
}

// CanonicalMIMEHeaderKey returns the canonical format of the
// MIME header key s. The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase. For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// MIME header keys are assumed to be ASCII only.
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
func CanonicalMIMEHeaderKey(s string) string {
	// Quick check for canonical encoding.
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !validHeaderFieldByte(c) {
			return s
		}
		if upper && 'a' <= c && c <= 'z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		if !upper && 'A' <= c && c <= 'Z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		upper = c == '-'
	}
	return s
}

const toLower = 'a' - 'A'

// validHeaderFieldByte reports whether b is a valid byte in a header
// field name. RFC 7230 says:
//   header-field   = field-name ":" OWS field-value OWS
//   field-name     = token
//   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
//   token = 1*tchar
func validHeaderFieldByte(b byte) bool {
	return int(b) < len(isTokenTable) && isTokenTable[b]
}

// canonicalMIMEHeaderKey is like CanonicalMIMEHeaderKey but is
// allowed to mutate the provided byte slice before returning the
// string.
//
// For invalid inputs (if a contains spaces or non-token bytes), a
// is unchanged and a string copy is returned.
func canonicalMIMEHeaderKey(a []byte) string {
	// See if a looks like a header key. If not, return it unchanged.
	for _, c := range a {
		if validHeaderFieldByte(c) {
			continue
		}
		// Don't canonicalize.
		return string(a)
	}

	upper := true
	for i, c := range a {
		// Canonicalize: first letter upper case
		// and upper case after each dash.
		// (Host, User-Agent, If-Modified-Since).
		// MIME headers are ASCII only, so no Unicode issues.
		if upper && 'a' <= c && c <= 'z' {
			c -= toLower
		} else if !upper && 'A' <= c && c <= 'Z' {
			c += toLower
		}
		a[i] = c
		upper = c == '-' // for next time
	}
	// The compiler recognizes m[string(byteSlice)] as a special
	// case, so a copy of a's bytes into a new string does not
	// happen in this map lookup:
	if v := commonHeader[string(a)]; v != "" {
		return v
	}
	return string(a)
}

// commonHeader interns common header strings.
var commonHeader = make(map[string]string)

func init() {
	for _, v := range []string{
		"Accept",
		"Accept-Charset",
		"Accept-Encoding",
		"Accept-Language",
		"Accept-Ranges",
		"Cache-Control",
		"Cc",
		"Connection",
		"Content-Id",
		"Content-Language",
		"Content-Length",
		"Content-Transfer-Encoding",
		"Content-Type",
		"Cookie",
		"Date",
		"Dkim-Signature",
		"Etag",
		"Expires",
		"From",
		"Host",
		"If-Modified-Since",
		"If-None-Match",
		"In-Reply-To",
		"Last-Modified",
		"Location",
		"Message-Id",
		"Mime-Version",
		"Pragma",
		"Received",
		"Return-Path",
		"Server",
		"Set-Cookie",
		"Subject",
		"To",
		"User-Agent",
		"Via",
		"X-Forwarded-For",
		"X-Imforwards",
		"X-Powered-By",
	} {
		commonHeader[v] = v
	}
}

// isTokenTable is a copy of net/http/lex.go's isTokenTable.
// See https://httpwg.github.io/specs/rfc7230.html#rule.token.separators
var isTokenTable = [127]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'0':  true,
	'1':  true,
	'2':  true,
	'3':  true,
	'4':  true,
	'5':  true,
	'6':  true,
	'7':  true,
	'8':  true,
	'9':  true,
	'A':  true,
	'B':  true,
	'C':  true,
	'D':  true,
	'E':  true,
	'F':  true,
	'G':  true,
	'H':  true,
	'I':  true,
	'J':  true,
	'K':  true,
	'L':  true,
	'M':  true,
	'N':  true,
	'O':  true,
	'P':  true,
	'Q':  true,
	'R':  true,
	'S':  true,
	'T':  true,
	'U':  true,
	'W':  true,
	'V':  true,
	'X':  true,
	'Y':  true,
	'Z':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'a':  true,
	'b':  true,
	'c':  true,
	'd':  true,
	'e':  true,
	'f':  true,
	'g':  true,
	'h':  true,
	'i':  true,
	'j':  true,
	'k':  true,
	'l':  true,
	'm':  true,
	'n':  true,
	'o':  true,
	'p':  true,
	'q':  true,
	'r':  true,
	's':  true,
	't':  true,
	'u':  true,
	'v':  true,
	'w':  true,
	'x':  true,
	'y':  true,
	'z':  true,
	'|':  true,
	'~':  true,
}
