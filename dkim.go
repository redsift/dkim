package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result holds all details about result of DKIM signature verification
type Result struct {
	Result    ResultCode `json:"code"`
	Error     error      `json:"error,omitempty"`
	Signature *Signature `json:"signature,omitempty"`
	Key       *PublicKey `json:"key,omitempty"`
}

// NewResult returns new *Result with provided details
func newResult(r ResultCode, e error, s *Signature) *Result {
	return &Result{
		Result:    r,
		Error:     e,
		Signature: s,
	}
}

func newResultWithKey(r ResultCode, e error, s *Signature, k *PublicKey) *Result {
	return &Result{
		Result:    r,
		Error:     e,
		Signature: s,
		Key:       k,
	}
}

// ResultCode presents a signature verification result in a form defined by
// RFC7601 in 2.7.1. DKIM and DomainKeys
type ResultCode uint8

// DKIM Verification Results
const (
	None ResultCode = iota
	Pass
	Fail
	Policy
	Neutral
	Temperror
	Permerror
)

func (r ResultCode) String() string {
	switch r {
	// https://tools.ietf.org/html/rfc7601#section-2.7.1
	// DKIM and DomainKeys Results
	// ===========================
	//
	// The message was not signed.
	case None:
		return "none"
	// The message was signed, the signature or signatures were
	// acceptable to the verifier, and the signature(s) passed
	// verification tests.
	case Pass:
		return "pass"
	// The message was signed and the signature or signatures were
	// acceptable to the verifier, but they failed the verification
	// test(s).
	case Fail:
		return "fail"
	// The message was signed but the signature or signatures were
	// not acceptable to the verifier.
	case Policy:
		return "policy"
	// The message was signed but the signature or signatures
	// contained syntax errors or were not otherwise able to be
	// processed.  This result SHOULD also be used for other failures not
	// covered elsewhere in this list.
	case Neutral:
		return "neutral"
	// The message could not be verified due to some error that
	// is likely transient in nature, such as a temporary inability to
	// retrieve a public key.  A later attempt may produce a final
	// result.
	case Temperror:
		return "temperror"
	// The message could not be verified due to some error that
	// is unrecoverable, such as a required Header field being absent.  A
	// later attempt is unlikely to produce a final result.
	case Permerror:
		return "permerror"
	default:
		return strconv.Itoa(int(r))
	}
}

type TagError struct {
	Tag string `json:"tag"`
	Val string `json:"val"`
	Err error  `json:"err"`
}

func newTagError(t, v string, err error) *TagError {
	return &TagError{t, v, err}
}

func (e *TagError) Error() string {
	var w bytes.Buffer
	w.WriteString(e.Err.Error())
	w.WriteString(`; `)
	w.WriteString(e.Tag)
	w.WriteByte('=')
	w.WriteString(e.Val)
	return w.String()
}

type SignatureError struct {
	Err error  `json:"err"`
	Exp string `json:"exp"`
}

func newSignatureError(err error, exp string) *SignatureError {
	return &SignatureError{err, exp}
}

func (e *SignatureError) Error() string {
	var w bytes.Buffer
	w.WriteString(e.Err.Error())
	w.WriteString(`; `)
	w.WriteString(e.Exp)
	return w.String()
}

// Possible reasons of failed verification
var (
	ErrSignatureNotFound           = errors.New("signature not found")
	ErrBadSignature                = errors.New("bad signature")
	ErrUnsupportedVersion          = errors.New("unsupported version")
	ErrUnsupportedAlgorithm        = errors.New("unsupported algorithm")
	ErrMalformedTagValue           = errors.New("malformed tag value")
	ErrUnsupportedQueryType        = errors.New("bad query type")
	ErrUnsupportedCanonicalization = errors.New("bad canonicalization")
	ErrInputError                  = errors.New("input error")
	ErrDomainMismatch              = errors.New("domain mismatch")
	ErrSignatureExpired            = errors.New("signature expired")
	ErrInvalidSigningEntity        = errors.New("invalid signing entity")
	ErrKeyUnavailable              = errors.New("key unavailable")
	ErrUnacceptableKey             = errors.New("unacceptable key")
	ErrTestingMode                 = errors.New("domain is testing DKIM")
	ErrKeyRevoked                  = errors.New("key revoked")
	ErrFromNotSigned               = errors.New("'From' field not signed")
	ErrNoSignedFields              = errors.New("no signed fields")
	ErrNoDomainSpecified           = errors.New("no domain specified")
	ErrEmptyUserIdentity           = errors.New("empty user identity")
	ErrNotDecimalNumber            = errors.New("not a decimal number")
	ErrEmptySelector               = errors.New("empty Selector")
	ErrUnsupportedServices         = errors.New("no supported services listed")
	ErrEmptyKey                    = errors.New("empty key")
)

// Signature holds parsed DKIM signature
type Signature struct {
	Header         string `json:"header"` // Header of the signature
	Raw            string `json:"raw"`    // Raw value of the signature
	emptyHashValue string
	algorithm      hash.Hash
	AlgorithmID    crypto.Hash       `json:"algorithmId"`             // 3 (SHA1) or 5 (SHA256)
	Hash           []byte            `json:"hash"`                    // 'h' tag value
	BodyHash       []byte            `json:"bodyHash"`                // 'bh' tag value
	RelaxedHeader  bool              `json:"relaxedHeader"`           // header canonicalization algorithm
	RelaxedBody    bool              `json:"relaxedBody"`             // body canonicalization algorithm
	SignerDomain   string            `json:"signerDomain"`            // 'd' tag value
	Headers        []string          `json:"headers"`                 // parsed 'h' tag value
	UserIdentifier string            `json:"userId"`                  // 'i' tag value
	Length         int64             `json:"length"`                  // 'l' tag value
	Selector       string            `json:"selector"`                // 's' tag value
	Timestamp      time.Time         `json:"ts"`                      // 't' tag value as time.Time
	Expiration     time.Time         `json:"exp"`                     // 'x' tag value as time.Time
	CopiedHeaders  map[string]string `json:"copiedHeaders,omitempty"` // parsed 'z' tag value
	query          PublicKeyQuery
}

// PublicKey holds parsed public key
type PublicKey struct {
	Version    string   `json:"version, omitempty"`   // 'v' tag value
	Raw        []byte   `json:"raw, omitempty"`       // 'p' tag value
	Algorithms []string `json:"algorithms,omitempty"` // parsed 'h' tag value; [] means "allowing all"
	Services   []string `json:"services,omitempty"`   // parsed 's' tag value; [] is "*"
	Flags      []string `json:"flags,omitempty"`      // parsed 't' tag value
	Notes      string   `json:"notes,omitempty"`      // 'n' tag value
	Testing    bool     `json:"testing"`              // 't' contains 'y'
	Strict     bool     `json:"strict"`               // 't' contains 's'
	revoked    bool
	key        *rsa.PublicKey // supporting "rsa" only
}

const qDNSTxt = "dns/txt"

var (
	// Queries holds implementations of public key queries
	Queries = map[string]PublicKeyQuery{
		qDNSTxt: _DNSTxtPublicKeyQuery,
	}
)

var (
	reReduceWS          = regexp.MustCompile(`[ \t]+`)
	reUnfoldAndReduceWS = regexp.MustCompile(`[\s]+`)
	sp                  = []byte(" ")
	colon               = []byte(":")
	wsp                 = "\t "
	crlf                = []byte("\r\n")
	// Tag=Value Lists
	// https://tools.ietf.org/html/rfc6376#section-3.2
	reTagValueList = regexp.MustCompile(`;?\s*([[:alpha:]][[:alnum:]]*)\s*=\s*([^[:cntrl:];](?:[^;]*[^[:cntrl:];])*)?\s*`)
	reBTagOnly     = regexp.MustCompile(`(;?\s*b\s*=)\s*([^[:cntrl:];](?:[^;]*[^[:cntrl:];])*)?\s*`)
	// c= Message canonicalization
	// https://tools.ietf.org/html/rfc6376#page-20
	reCanonicalization = regexp.MustCompile(`^([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]]))(?:/([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]])))?$`)
	// z= Copied Header fields
	// https://tools.ietf.org/html/rfc6376#page-25
	reCopiedHeaders = regexp.MustCompile(`\|?\s*([^[:cntrl:]: ]+):([^\s\|]+)\s*`)
	// a slightly relaxed version of key-h-tag or key-s-tag
	// https://tools.ietf.org/html/rfc6376#page-27
	reKeyXTag       = regexp.MustCompile(`:?\s*([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]])?)\s*`)
	reKeySTag       = regexp.MustCompile(`:?\s*([[:alnum:]*](?:[[:alnum:]-]*[[:alnum:]])?)?\s*`)
	reSignedHeaders = regexp.MustCompile(`:?\s*([^[:cntrl:]: ]+)\s*`)
	timeZero        = time.Unix(0, 0)
	algorithms      = map[string]*algorithm{
		"rsa-sha1":   {crypto.SHA1, crypto.SHA1.New},
		"rsa-sha256": {crypto.SHA256, crypto.SHA256.New},
	}
)

type algorithm struct {
	id   crypto.Hash
	hash func() hash.Hash
}

func checkRelaxed(s string) (bool, error) {
	switch s {
	case "":
		fallthrough
	case "simple":
		return false, nil
	case "relaxed":
		return true, nil
	default:
		return false, ErrUnsupportedCanonicalization
	}
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Replace(s, " ", "", -1))
}

func parseSignature(k, v string) (*Signature, error) {
	if v == "" {
		return nil, ErrSignatureNotFound
	}

	const (
		fVersion uint64 = 1 << iota
		fAlgorithm
		fHash
		fBodyHash
		fSignerDomain
		fHeaders
		fSelector
	)

	required := fVersion + fAlgorithm + fHash + fBodyHash + fSignerDomain + fHeaders + fSelector
	missedTags := func() string {
		symbols := []string{"v", "a", "b", "bh", "d", "h", "s"}
		var w bytes.Buffer
		w.WriteString("no required tags found (")
		for f, i, d := fVersion, 0, false; f <= fSelector; f, i = f<<1, i+1 {
			if (required & f) == 0 {
				continue
			}
			if d {
				w.WriteString(", ")
			}
			w.WriteString(symbols[i])
			d = true
		}
		w.WriteByte(')')
		return w.String()
	}

	s := &Signature{
		query:  Queries[qDNSTxt],
		Header: k,
		Raw:    v,
		// The DKIM-Signature Header field that exists (verifying) or will
		// be inserted (signing) in the message, with the value of the "b="
		// tag (including all surrounding whitespace) deleted
		// (i.e., treated as the empty string)
		// https://tools.ietf.org/html/rfc6376#page-30
		emptyHashValue: reBTagOnly.ReplaceAllString(v, "$1"),
	}
	for _, m := range reTagValueList.FindAllStringSubmatch(v, -1) {
		// m := ["t=v" "t" "v"]
		key, value := m[1], m[2]
		var err error
		switch key {
		case "v":
			if value != "1" {
				return nil, newTagError("v", value, ErrUnsupportedVersion)
			}
			required &^= fVersion
		case "a":
			a, found := algorithms[value]
			if !found {
				return nil, newTagError("a", value, ErrUnsupportedAlgorithm)
			}
			s.algorithm = a.hash()
			s.AlgorithmID = a.id
			required &^= fAlgorithm
		case "b":
			if s.Hash, err = decodeBase64(value); err != nil {
				return nil, newTagError("b", value, ErrMalformedTagValue)
			}
			required &^= fHash
		case "bh":
			if s.BodyHash, err = decodeBase64(value); err != nil {
				return nil, newTagError("bh", value, ErrMalformedTagValue)
			}
			required &^= fBodyHash
		case "c":
			m := reCanonicalization.FindAllStringSubmatch(value, 1)
			// m := [["headerAlgorigthm/bodyAlgorithm" "headerAlgorigthm" "bodyAlgorithm"]]
			if m == nil {
				return nil, newTagError("c", value, ErrUnsupportedCanonicalization)
			}
			if s.RelaxedHeader, err = checkRelaxed(m[0][1]); err != nil {
				return nil, newTagError("c", value, err)
			}
			if s.RelaxedBody, err = checkRelaxed(m[0][2]); err != nil {
				return nil, newTagError("c", value, err)
			}
		case "d":
			// The SDID MUST correspond to a valid DNS name under
			// which the DKIM key record is published.
			if value == "" {
				return nil, newTagError("d", "", ErrNoDomainSpecified)
			}
			s.SignerDomain = value
			required &^= fSignerDomain
		case "h":
			// The field MAY contain multiple instances of a Header field
			// name, meaning multiple occurrences of the corresponding
			// Header field are included in the Header Hash.
			// ...
			// This list MUST NOT be empty.
			// https://tools.ietf.org/html/rfc6376#page-21
			if value == "" {
				return nil, newTagError("h", "", ErrNoSignedFields)
			}
			acceptable := false
			s.Headers = mapMatches(reSignedHeaders, value, func(m []string) string {
				// m := [":v" "v"]
				if "from" == strings.ToLower(m[1]) {
					acceptable = true
				}
				return m[1]
			})
			// If the "h=" tag does not include the From Header field, the Verifier
			// MUST ignore the DKIM-Signature Header field and return PERMFAIL
			// (From field not signed).
			if !acceptable {
				return nil, newTagError("h", value, ErrFromNotSigned)
			}
			required &^= fHeaders
		case "i":
			// OPTIONAL, default is an empty local-part followed by an
			// "@" followed by the domain from the "d=" tag
			// sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
			//                            "@" domain-name
			if value == "" {
				return nil, newTagError("i", "", ErrEmptyUserIdentity)
			}
			s.UserIdentifier = value
		case "l":
			if s.Length, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, newTagError("l", value, ErrNotDecimalNumber)
			}
		case "q":
			q, found := Queries[value]
			if !found {
				return nil, newTagError("q", value, ErrUnsupportedQueryType)
			}
			s.query = q
		case "s":
			if value == "" {
				return nil, newTagError("s", "", ErrEmptySelector)
			}
			s.Selector = value
			required &^= fSelector
		case "t":
			// Implementations MAY ignore signatures that have a Timestamp in the future.
			// https://tools.ietf.org/html/rfc6376#page-24
			var t int64
			if t, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, newTagError("t", value, ErrNotDecimalNumber)
			}
			s.Timestamp = time.Unix(t, 0)
		case "x":
			// Due to clock drift, the receiver's notion of when to consider
			// the signature expired may not exactly match what the sender
			// is expecting.  Receivers MAY add a 'fudge factor' to allow
			// for such possible drift.
			// https://tools.ietf.org/html/rfc6376#page-25
			var t int64
			if t, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, newTagError("x", value, ErrNotDecimalNumber)
			}
			s.Expiration = time.Unix(t, 0)
		case "z":
			// TODO support multiple entries per field
			hdrs := reCopiedHeaders.FindAllStringSubmatch(value, -1)
			s.CopiedHeaders = make(map[string]string, len(hdrs))
			for _, m := range hdrs {
				// m := ["t:v" "t" "v"]
				s.CopiedHeaders[m[1]] = m[2]
			}
		}
	}
	if required != 0 {
		return nil, newSignatureError(ErrBadSignature, missedTags())
	}
	return s, nil
}

type counterWriter struct {
	c int
	w io.Writer
}

func (c *counterWriter) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	c.c += n
	return
}

func bodyHash(in io.Reader, h hash.Hash, relaxed bool) ([]byte, error) {
	r := textproto.NewReader(bufio.NewReader(in))
	h.Reset()
	w := &counterWriter{w: h}

	var (
		emptyLinesCnt = 0
	)
	for {
		b, err := r.ReadLineBytes()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if relaxed {
			b = bytes.TrimRight(reReduceWS.ReplaceAll(b, sp), wsp)
		}
		// ignore all empty lines
		if len(b) == 0 {
			emptyLinesCnt++
			continue
		}
		// return them back if next line is not empty
		for ; emptyLinesCnt > 0; emptyLinesCnt-- {
			_, _ = w.Write(crlf)
		}

		_, _ = w.Write(b)    // we do not expect any errors on Hash side
		_, _ = w.Write(crlf) // ReadLineBytes eliding the final \n or \r\n from the returned string
	}
	// Note that a completely empty or missing body is canonicalized as a single "CRLF"
	if w.c == 0 {
		_, _ = w.Write(crlf)
	}
	return h.Sum(nil), nil
}

// VerifyOption provides way to extend signature verification.
// Verifiers MAY ignore the DKIM-Signature Header field and return PERMFAIL
// (unacceptable signature Header) for any other reason, for example, if
// the signature does not sign Header fields that the Verifier views to be
// essential.  As a case in point, if MIME Header fields are not signed,
// certain attacks may be possible that the Verifier would prefer to avoid.
type VerifyOption func(s *Signature, k *PublicKey, m *mail.Message) *Result

// SignatureTimingOption checks if signature is expired
// Verifiers MAY ignore the DKIM-Signature Header field and return
// PERMFAIL (signature expired) if it contains an "x=" tag and
// the signature has expired.
func SignatureTimingOption() VerifyOption {
	return func(s *Signature, _ *PublicKey, _ *mail.Message) *Result {
		now := time.Now()
		if s.Timestamp.After(now) {
			return newResult(Permerror, ErrBadSignature, s)
		}
		expPresent := s.Expiration.After(timeZero)
		if expPresent && s.Expiration.Before(now) {
			return newResult(Permerror, ErrSignatureExpired, s)
		}
		if expPresent && s.Timestamp.After(timeZero) && s.Expiration.Before(s.Timestamp) {
			return newResult(Permerror, ErrBadSignature, s)
		}
		return nil
	}
}

// InvalidSigningEntityOption checks if domain of "i=" equals to "d=".
// Verifiers MAY ignore the DKIM-Signature Header field if the domain
// used by the Signer in the "d=" tag is not associated with a valid
// signing entity.  For example, signatures with "d=" values such as
// "com" and "co.uk" could be ignored.
// The list of unacceptable domains SHOULD be configurable.
func InvalidSigningEntityOption(domains ...string) VerifyOption {
	index := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		index[d] = struct{}{}
	}
	return func(s *Signature, _ *PublicKey, _ *mail.Message) *Result {
		if _, found := index[s.SignerDomain]; found {
			return newResult(Permerror, ErrInvalidSigningEntity, s)
		}
		return nil
	}
}

// PublicKeyQuery defines API for implementation of "q=".
type PublicKeyQuery func(*Signature) (*PublicKey, *Result)

// DNSTxtPublicKeyQuery provides implementation of "dns/txt" query.
func _DNSTxtPublicKeyQuery(s *Signature) (*PublicKey, *Result) {
	records, err := net.LookupTXT(s.Selector + "._domainkey." + s.SignerDomain)
	if err != nil {
		return nil, newResult(Temperror, ErrKeyUnavailable, s)
	}

	key, err := parsePublicKey(strings.Join(records, ""))
	if err != nil {
		return nil, newResult(Permerror, err, s)
	}

	return key, nil
}

func mapMatches(re *regexp.Regexp, s string, f func(g []string) string) []string {
	if s == "" {
		return nil
	}
	m := re.FindAllStringSubmatch(s, -1)
	// m := [["t1:" "t1"] ["t2:" "t2"]
	if m == nil {
		return nil
	}
	a := make([]string, 0, len(m))
	for _, g := range m {
		a = append(a, f(g))
	}
	return a
}

// parsePublicKey parses textual representation of the key
// See https://tools.ietf.org/html/rfc6376#section-3.6.1 for details
func parsePublicKey(s string) (*PublicKey, error) {
	unacceptableKey := func(t, v string, e error) (*PublicKey, error) {
		return nil, newSignatureError(ErrUnacceptableKey, newTagError(t, v, e).Error())
	}

	if s == "" {
		return nil, newSignatureError(ErrUnacceptableKey, ErrEmptyKey.Error())
	}
	const (
		fData uint64 = 1 << iota
	)
	required := fData
	missedTags := func() string {
		symbols := []string{"v", "a", "b", "bh", "d", "h", "s"}
		var w bytes.Buffer
		w.WriteString("no required tags found (")
		for f, i, d := fData, 0, false; f <= fData; f, i = f<<1, i+1 {
			if (required & f) == 0 {
				continue
			}
			if d {
				w.WriteString(", ")
			}
			w.WriteString(symbols[i])
			d = true
		}
		w.WriteByte(')')
		return w.String()
	}
	k := &PublicKey{revoked: true}
	for _, m := range reTagValueList.FindAllStringSubmatch(s, -1) {
		// m := ["t=v" "t" "v"]
		key, value := m[1], m[2]
		switch key {
		case "v": // Version of the DKIM key record
			if value != "DKIM1" {
				return unacceptableKey("v", value, ErrUnsupportedVersion)
			}
			k.Version = value
		case "h": // Acceptable Hash algorithms
			acceptable := false
			k.Algorithms = mapMatches(reKeyXTag, value, func(m []string) string {
				// m := [":a" "a"]
				s = "rsa-" + m[1]
				if _, found := algorithms[s]; found {
					acceptable = true
				}
				return s
			})
			if !acceptable {
				return unacceptableKey("h", value, ErrUnsupportedAlgorithm)
			}
		case "k": // Key type
			if value != "rsa" {
				// Unrecognized key types MUST be ignored.
				// https://tools.ietf.org/html/rfc6376#page-27
				return unacceptableKey("k", value, ErrUnsupportedAlgorithm)
			}
		case "n": // Notes that might be of interest to a human
			k.Notes = value
		case "p": // Public-key data (base64; REQUIRED)
			// An empty value means that this public key has been revoked.
			// The syntax and semantics of this tag value before being
			// encoded in base64 are defined by the "k=" tag.
			if value != "" {
				b, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return unacceptableKey("p", value, err)
				}
				i, err := x509.ParsePKIXPublicKey(b)
				if err != nil {
					return unacceptableKey("p", value, err)
				}
				pkey, ok := i.(*rsa.PublicKey)
				if !ok {
					return unacceptableKey("p", value, ErrUnacceptableKey)
				}
				k.Raw = b
				k.key = pkey
				k.revoked = false
			}
			required &^= fData
		case "s": // Service Type
			acceptable := false
			k.Services = mapMatches(reKeySTag, value, func(m []string) string {
				// m := [":v" "v"]
				switch m[1] {
				case "email":
					fallthrough
				case "*":
					acceptable = true
				}
				return m[1]
			})
			if !acceptable {
				return unacceptableKey("s", value, ErrUnsupportedServices)
			}
		case "t": // Flags
			k.Flags = mapMatches(reKeyXTag, value, func(m []string) string {
				// m := [":v" "v"]
				switch m[1] {
				case "y":
					k.Testing = true
				case "s":
					k.Strict = true
				}
				return m[1]
			})
		}
	}
	if required != 0 {
		return nil, newSignatureError(ErrUnacceptableKey, missedTags())
	}

	return k, nil
}

func (s *Signature) verifyBodyHash(r io.Reader) *Result {
	// In Hash step 1, the Signer/Verifier MUST Hash the message body,
	// canonicalized using the body canonicalization algorithm specified
	// in the "c=" tag and then truncated to the Length specified in the "l=" tag.
	// TODO cache BH for the message::Length
	if s.Length > 0 {
		r = io.LimitReader(r, s.Length)
	}

	bh, err := bodyHash(r, s.algorithm, s.RelaxedBody)
	if err != nil {
		return newResult(Temperror, ErrInputError, s)
	}

	if !bytes.Equal(bh, s.BodyHash) {
		return newResult(Fail, ErrBadSignature, s)
	}

	return nil
}

func compareDomains(u, d string, strict bool) bool {
	// If the DKIM-Signature Header field does not contain the "i="
	// tag, the Verifier MUST behave as though the value of that
	// tag were "@d", where "d" is the value from the "d=" tag.
	// https://tools.ietf.org/html/rfc6376#section-6.1.1
	if u == "" {
		return true
	}

	if strict {
		// Any DKIM-Signature Header fields using the "i=" tag MUST have
		// the same domain value on the right-hand side of the "@" in the
		// "i=" tag and the value of the "d=" tag.
		i := bytes.LastIndexByte([]byte(u), '@')
		return i >= 0 && len(u) > 1 && bytes.Equal([]byte(u)[i+1:], []byte(d))
	}

	// Verifiers MUST confirm that the domain specified in the "d=" tag is
	// the same as or a parent domain of the domain part of the "i=" tag.
	// If not, the DKIM-Signature Header field MUST be ignored, and the
	// Verifier should return PERMFAIL (domain mismatch).
	// https: //tools.ietf.org/html/rfc6376#section-6.1.1
	return strings.HasSuffix(u, d)
}

func (s *Signature) verify(m *mail.Message, options ...VerifyOption) (result *Result) {
	// TODO cache result
	if s == nil {
		return newResult(None, ErrSignatureNotFound, s)
	}

	var pkey *PublicKey
	if pkey, result = s.query(s); result != nil {
		return result
	}

	if pkey.revoked {
		return newResult(Fail, ErrKeyRevoked, s)
	}

	// Verifiers MUST NOT treat messages from Signers in testing mode
	// differently from unsigned email
	if pkey.Testing {
		return newResult(None, ErrTestingMode, s)
	}

	if ok := compareDomains(s.UserIdentifier, s.SignerDomain, pkey.Strict); !ok {
		return newResult(Permerror, ErrDomainMismatch, s)
	}

	// Fail fast here, provided options are fast
	for _, option := range options {
		if result = option(s, pkey, m); result != nil {
			result.Key = pkey
			return
		}
	}

	if result = s.verifyBodyHash(m.Body); result != nil {
		result.Key = pkey
		return
	}

	// In Hash step 2, the Signer/Verifier MUST pass the following to the
	// Hash algorithm in the indicated order.
	//
	// 1.  The Header fields specified by the "h=" tag, in the order
	//	   specified in that tag, and canonicalized using the Header
	//	   canonicalization algorithm specified in the "c=" tag.  Each
	//	   Header field MUST be terminated with a single CRLF.
	//
	// 2.  The DKIM-Signature Header field that exists (verifying) or will
	//	   be inserted (signing) in the message, with the value of the "b="
	//	   tag (including all surrounding whitespace) deleted (i.e., treated
	//	   as the empty string), canonicalized using the Header
	//	   canonicalization algorithm specified in the "c=" tag, and without
	//	   a trailing CRLF.

	// 5.4.2.  Signatures Involving Multiple Instances of a Field
	// https://tools.ietf.org/html/rfc6376#section-5.4.2
	getHeader := getHeaderFunc(m.Header)

	s.algorithm.Reset()
	w := s.algorithm
	for _, k := range s.Headers {
		_, _ = w.Write(canonicalizedHeader(k, getHeader(k), s.RelaxedHeader))
		_, _ = w.Write(crlf)
	}
	_, _ = w.Write(canonicalizedHeader(s.Header, s.emptyHashValue, s.RelaxedHeader))
	if e := rsa.VerifyPKCS1v15(pkey.key, s.AlgorithmID, s.algorithm.Sum(nil), s.Hash); e != nil {
		return newResultWithKey(Fail, ErrBadSignature, s, pkey)
	}

	return newResultWithKey(Pass, nil, s, pkey)
}

func getHeaderFunc(h mail.Header) func(k string) string {
	i := make(map[string]int, len(h))
	return func(key string) string {
		k := textproto.CanonicalMIMEHeaderKey(key)
		var (
			a     []string
			found bool
			n     int
		)
		a, found = h[k]
		if !found {
			return ""
		}
		n, found = i[k]
		if n < 0 {
			return ""
		}
		if !found {
			n = len(a) - 1
		}
		var v string
		if n >= 0 {
			v = a[n]
		}
		n--
		i[k] = n
		return v
	}
}

func canonicalizedHeader(k, v string, relaxed bool) []byte {
	if !relaxed {
		// NOTE: textproto.Reader#ReadMIMEHeader returns map of
		// CanonicalMIMEHeaderKey(key) and make impossible
		// "simple" canonicalization
		// TODO raw Headers required
		return []byte(k + `:` + v)
	}
	// 3.4.2.  The "relaxed" Header Canonicalization Algorithm
	// https://tools.ietf.org/html/rfc6376#section-3.4.2
	//
	// o  Convert all Header field names (not the Header field values) to
	//    lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
	//
	// o  Unfold all Header field continuation lines as described in
	//    [RFC5322]; in particular, lines with terminators embedded in
	//    continued Header field values (that is, CRLF sequences followed by
	//    WSP) MUST be interpreted without the CRLF.  Implementations MUST
	//    NOT remove the CRLF at the end of the Header field value.
	//
	// o  Convert all sequences of one or more WSP characters to a single SP
	//    character.  WSP characters here include those before and after a
	//    line folding boundary.
	//
	// o  Delete all WSP characters at the end of each unfolded Header field
	//    value.
	b := bytes.TrimRight(reUnfoldAndReduceWS.ReplaceAll([]byte(v), sp), wsp)
	h := make([]byte, 0, len(k)+len(b)+1)
	h = append(h, []byte(strings.ToLower(k))...)
	h = append(h, colon...)
	h = append(h, b...)
	return h
}

// Verify extracts DKIM signature from message, verifies it and returns Result
// of verification in accordance with RFC6376 (DKIM Signatures)
func Verify(hdr string, msg *mail.Message, opts ...VerifyOption) *Result {
	// TODO verify multiple signatures
	if msg == nil {
		return nil
	}
	sigs := msg.Header[textproto.CanonicalMIMEHeaderKey(hdr)]
	if len(sigs) == 0 {
		return newResult(None, nil, nil)
	}
	var (
		s   *Signature
		err error
	)
	if s, err = parseSignature(hdr, sigs[len(sigs)-1]); err != nil {
		return newResult(Permerror, err, s)
	}
	return s.verify(msg, opts...)
}

// String returns textual representation of DKIM verification result.
// The representation is NOT conformed with RFC7601, but is compilation of
// values recommended by RFC7601 and form defined for Received-SPF by RFC7208
func (r *Result) String() string {
	if r == nil {
		return ""
	}
	var w bytes.Buffer

	w.WriteString(r.Result.String())

	if r.Error != nil {
		w.WriteString("; problem=")
		w.WriteString(r.Error.Error())
	}
	if r.Signature != nil {
		if r.Signature.SignerDomain != "" {
			w.WriteString("; Header.d=")
			w.WriteString(r.Signature.SignerDomain)
		}
		if r.Signature.UserIdentifier != "" {
			w.WriteString("; Header.i=")
			w.WriteString(r.Signature.UserIdentifier)
		}
	}

	return w.String()
}
