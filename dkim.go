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

type Result struct {
	Result ResultCode
	Reason error
}

func NewResult(r ResultCode, e error) *Result {
	return &Result{
		Result: r,
		Reason: e,
	}
}

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
	// is unrecoverable, such as a required header field being absent.  A
	// later attempt is unlikely to produce a final result.
	case Permerror:
		return "permerror"
	default:
		return strconv.Itoa(int(r))
	}
}

var (
	ErrSignatureNotFound           = errors.New("signature not found")
	ErrBadSignature                = errors.New("bad signature")
	ErrUnsupportedVersion          = errors.New("unsupported version")
	ErrUnsupportedAlgorithm        = errors.New("unsupported algorithm")
	ErrMalformedTagValue           = errors.New("malformed tag value")
	ErrUnsupportedQueryType        = errors.New("bad query type")
	ErrUnknownTag                  = errors.New("bad tag")
	ErrUnsupportedCanonicalization = errors.New("bad canonicalization")
	ErrInputError                  = errors.New("input error")
	ErrDomainMismatch              = errors.New("domain mismatch")
	ErrSignatureExpired            = errors.New("signature expired")
	ErrInvalidSigningEntity        = errors.New("invalid signing entity")
	ErrKeyUnavailable              = errors.New("key unavailable")
	ErrKeyNotFound                 = errors.New("no key for signature")
	ErrUnacceptableKey             = errors.New("unacceptable key")
	ErrTestingMode                 = errors.New("domain is testing DKIM")
	ErrKeyRevoked                  = errors.New("key revoked")
	ErrFromNotSigned               = errors.New("From field not signed")
	ErrNoSignedFields              = errors.New("no signed fields")
)

type Signature struct {
	header         string
	emptyHashValue string
	algorithm      *algorithm
	hash           []byte
	bodyHash       []byte
	relaxedHeader  bool
	relaxedBody    bool
	signerDomain   string
	headers        []string
	userIdentifier string
	length         int64
	selector       string
	timestamp      time.Time
	expiration     time.Time
	copiedHeaders  map[string]string
	query          PublicKeyQuery
}

// https://tools.ietf.org/html/rfc6376#section-3.6.1
type PublicKey struct {
	algorithms []string       // [] means "allowing all"
	key        *rsa.PublicKey // supporting "rsa" only
	services   []string       // [] is "*"
	revoked    bool
	testing    bool
	strict     bool
}

const qDNSTxt = "dns/txt"

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
	// z= Copied header fields
	// https://tools.ietf.org/html/rfc6376#page-25
	reCopiedHeaders = regexp.MustCompile(`\|?\s*([^[:cntrl:]: ]+):([^\s\|]+)\s*`)
	// a slightly relaxed version of key-h-tag or key-s-tag
	// https://tools.ietf.org/html/rfc6376#page-27
	reKeyXTag       = regexp.MustCompile(`:?\s*([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]])?)\s*`)
	reKeySTag       = regexp.MustCompile(`:?\s*([[:alnum:]*](?:[[:alnum:]-]*[[:alnum:]])?)?\s*`)
	reSignedHeaders = regexp.MustCompile(`:?\s*([^[:cntrl:]: ]+)\s*`)
	timeZero        = time.Unix(0, 0)
	Queries         = map[string]PublicKeyQuery{
		qDNSTxt: DNSTxtPublicKeyQuery,
	}
	algorithms = map[string]*algorithm{
		"rsa-sha1":   {crypto.SHA1, crypto.SHA1.New()},
		"rsa-sha256": {crypto.SHA256, crypto.SHA256.New()},
	}
)

type algorithm struct {
	id crypto.Hash
	f  hash.Hash
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
	s := &Signature{
		query:  Queries[qDNSTxt],
		header: k,
		// The DKIM-Signature header field that exists (verifying) or will
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
				return nil, ErrUnsupportedVersion
			}
			required &^= fVersion
		case "a":
			a, found := algorithms[value]
			if !found {
				return nil, ErrUnsupportedAlgorithm
			}
			s.algorithm = a
			required &^= fAlgorithm
		case "b":
			if s.hash, err = decodeBase64(value); err != nil {
				return nil, ErrMalformedTagValue
			}
			required &^= fHash
		case "bh":
			if s.bodyHash, err = decodeBase64(value); err != nil {
				return nil, ErrMalformedTagValue
			}
			required &^= fBodyHash
		case "c":
			m := reCanonicalization.FindAllStringSubmatch(value, 1)
			// m := [["headerAlgorigthm/bodyAlgorithm" "headerAlgorigthm"
			// "bodyAlgorithm"]]
			if m == nil {
				return nil, ErrUnsupportedCanonicalization
			}
			if s.relaxedHeader, err = checkRelaxed(m[0][1]); err != nil {
				return nil, err
			}
			if s.relaxedBody, err = checkRelaxed(m[0][2]); err != nil {
				return nil, err
			}
		case "d":
			// The SDID MUST correspond to a valid DNS name under
			// which the DKIM key record is published.
			if value == "" {
				return nil, ErrMalformedTagValue
			}
			s.signerDomain = value
			required &^= fSignerDomain
		case "h":
			// The field MAY contain multiple instances of a header field
			// name, meaning multiple occurrences of the corresponding
			// header field are included in the header hash.
			// ...
			// This list MUST NOT be empty.
			// https://tools.ietf.org/html/rfc6376#page-21
			if value == "" {
				return nil, ErrNoSignedFields
			}
			acceptable := false
			s.headers = mapMatches(reSignedHeaders, value, func(m []string) string {
				// m := [":v" "v"]
				if "from" == strings.ToLower(m[1]) {
					acceptable = true
				}
				return m[1]
			})
			// If the "h=" tag does not include the From header field, the Verifier
			// MUST ignore the DKIM-Signature header field and return PERMFAIL
			// (From field not signed).
			if !acceptable {
				return nil, ErrFromNotSigned
			}
			required &^= fHeaders
		case "i":
			// OPTIONAL, default is an empty local-part followed by an
			// "@" followed by the domain from the "d=" tag
			// sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
			//                            "@" domain-name
			if value == "" {
				return nil, ErrMalformedTagValue
			}
			s.userIdentifier = value
		case "l":
			if s.length, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, ErrMalformedTagValue
			}
		case "q":
			q, found := Queries[value]
			if !found {
				return nil, ErrUnsupportedQueryType
			}
			s.query = q
		case "s":
			if value == "" {
				return nil, ErrMalformedTagValue
			}
			s.selector = value
			required &^= fSelector
		case "t":
			// Implementations MAY ignore signatures that have a timestamp in the future.
			// https://tools.ietf.org/html/rfc6376#page-24
			var t int64
			if t, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, ErrMalformedTagValue
			}
			s.timestamp = time.Unix(t, 0)
		case "x":
			// Due to clock drift, the receiver's notion of when to consider
			// the signature expired may not exactly match what the sender
			// is expecting.  Receivers MAY add a 'fudge factor' to allow
			// for such possible drift.
			// https://tools.ietf.org/html/rfc6376#page-25
			var t int64
			if t, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, ErrMalformedTagValue
			}
			s.expiration = time.Unix(t, 0)
		case "z":
			// TODO support multiple entries per field
			hdrs := reCopiedHeaders.FindAllStringSubmatch(value, -1)
			s.copiedHeaders = make(map[string]string, len(hdrs))
			for _, m := range hdrs {
				// m := ["t:v" "t" "v"]
				s.copiedHeaders[m[1]] = m[2]
			}
		}
	}
	if required != 0 {
		return nil, ErrBadSignature
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
			w.Write(crlf)
		}

		w.Write(b)    // we do not expect any errors on hash side
		w.Write(crlf) // ReadLineBytes eliding the final \n or \r\n from the returned string
	}
	// Note that a completely empty or missing body is canonicalized as a single "CRLF"
	if w.c == 0 {
		w.Write(crlf)
	}
	return h.Sum(nil), nil
}

// Verifiers MAY ignore the DKIM-Signature header field and return PERMFAIL
// (unacceptable signature header) for any other reason, for example, if
// the signature does not sign header fields that the Verifier views to be
// essential.  As a case in point, if MIME header fields are not signed,
// certain attacks may be possible that the Verifier would prefer to avoid.
type VerifyOption func(s *Signature, k *PublicKey, m *mail.Message) *Result

// Verifiers MAY ignore the DKIM-Signature header field and return
// PERMFAIL (signature expired) if it contains an "x=" tag and
// the signature has expired.
func SignatureTimingOption() VerifyOption {
	return func(s *Signature, _ *PublicKey, _ *mail.Message) *Result {
		now := time.Now()
		if s.timestamp.After(now) {
			return NewResult(Permerror, ErrBadSignature)
		}
		if s.expiration.After(timeZero) && s.expiration.Before(now) {
			return NewResult(Permerror, ErrSignatureExpired)
		}
		return nil
	}
}

// Verifiers MAY ignore the DKIM-Signature header field if the domain
// used by the Signer in the "d=" tag is not associated with a valid
// signing entity.  For example, signatures with "d=" values such as
// "com" and "co.uk" could be ignored.
// The list of unacceptable domains SHOULD be configurable.
func InvalidSigningEntityOption(domains ...string) VerifyOption {
	return func(s *Signature, _ *PublicKey, _ *mail.Message) *Result {
		for _, d := range domains {
			if s.signerDomain == d {
				return NewResult(Permerror, ErrInvalidSigningEntity)
			}
		}
		return nil
	}
}

type PublicKeyQuery func(selector, domain string) (*PublicKey, *Result)

func DNSTxtPublicKeyQuery(selector, domain string) (*PublicKey, *Result) {
	records, err := net.LookupTXT(selector + "._domainkey." + domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if !dnsErr.Temporary() {
				return nil, NewResult(Permerror, ErrKeyNotFound)
			}
		}
		return nil, NewResult(Temperror, ErrKeyUnavailable)
	}

	key, err := parsePublicKey(strings.Join(records, ""))
	if err != nil {
		return nil, NewResult(Permerror, err)
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

func parsePublicKey(s string) (*PublicKey, error) {
	if s == "" {
		return nil, ErrKeyNotFound
	}
	const (
		fData uint64 = 1 << iota
	)
	required := fData
	k := &PublicKey{revoked: true}
	for _, m := range reTagValueList.FindAllStringSubmatch(s, -1) {
		// m := ["t=v" "t" "v"]
		key, value := m[1], m[2]
		switch key {
		case "v": // Version of the DKIM key record
			if value != "DKIM1" {
				return nil, ErrUnacceptableKey
			}
		case "h": // Acceptable hash algorithms
			acceptable := false
			k.algorithms = mapMatches(reKeyXTag, value, func(m []string) string {
				// m := [":a" "a"]
				s = "rsa-" + m[1]
				if _, found := algorithms[s]; found {
					acceptable = true
				}
				return s
			})
			if !acceptable {
				return nil, ErrUnacceptableKey
			}
		case "k": // Key type
			if value != "rsa" {
				// Unrecognized key types MUST be ignored.
				// https://tools.ietf.org/html/rfc6376#page-27
				return nil, ErrUnacceptableKey
			}
		// case "n": // Notes that might be of interest to a human
		//	k.notes = value
		case "p": // Public-key data (base64; REQUIRED)
			// An empty value means that this public key has been revoked.
			// The syntax and semantics of this tag value before being
			// encoded in base64 are defined by the "k=" tag.
			if value != "" {
				b, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, ErrUnacceptableKey
				}
				i, err := x509.ParsePKIXPublicKey(b)
				if err != nil {
					return nil, ErrUnacceptableKey
				}
				pkey, ok := i.(*rsa.PublicKey)
				if !ok {
					return nil, ErrUnacceptableKey
				}
				k.key = pkey
				k.revoked = false
			}
			required &^= fData
		case "s": // Service Type
			acceptable := false
			k.services = mapMatches(reKeySTag, value, func(m []string) string {
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
				return nil, ErrUnacceptableKey
			}
		case "t": // Flags
			_ = mapMatches(reKeyXTag, value, func(m []string) string {
				// m := [":v" "v"]
				switch m[1] {
				case "y":
					k.testing = true
				case "s":
					k.strict = true
				}
				return s
			})
		}
	}
	if required != 0 {
		return nil, ErrUnacceptableKey
	}

	return k, nil
}

func (s *Signature) verifyBodyHash(r io.Reader) *Result {
	// In hash step 1, the Signer/Verifier MUST hash the message body,
	// canonicalized using the body canonicalization algorithm specified
	// in the "c=" tag and then truncated to the length specified in the "l=" tag.
	// TODO cache BH for the message::length
	if s.length > 0 {
		r = io.LimitReader(r, s.length)
	}

	bh, err := bodyHash(r, s.algorithm.f, s.relaxedBody)
	if err != nil {
		return NewResult(Temperror, ErrInputError)
	}

	if !bytes.Equal(bh, s.bodyHash) {
		return NewResult(Fail, ErrBadSignature)
	}

	return nil
}

func compareDomains(u, d string, strict bool) bool {
	// If the DKIM-Signature header field does not contain the "i="
	// tag, the Verifier MUST behave as though the value of that
	// tag were "@d", where "d" is the value from the "d=" tag.
	// https://tools.ietf.org/html/rfc6376#section-6.1.1
	if u == "" {
		return true
	}

	if strict {
		// Any DKIM-Signature header fields using the "i=" tag MUST have
		// the same domain value on the right-hand side of the "@" in the
		// "i=" tag and the value of the "d=" tag.
		i := bytes.LastIndexByte([]byte(u), '@')
		return i >= 0 && len(u) > 1 && bytes.Equal([]byte(u)[i+1:], []byte(d))
	}

	// Verifiers MUST confirm that the domain specified in the "d=" tag is
	// the same as or a parent domain of the domain part of the "i=" tag.
	// If not, the DKIM-Signature header field MUST be ignored, and the
	// Verifier should return PERMFAIL (domain mismatch).
	// https: //tools.ietf.org/html/rfc6376#section-6.1.1
	return strings.HasSuffix(u, d)
}

func (s *Signature) verify(m *mail.Message, options ...VerifyOption) (result *Result) {
	// TODO cache result
	if s == nil {
		return NewResult(None, ErrSignatureNotFound)
	}

	var pkey *PublicKey
	if pkey, result = s.query(s.selector, s.signerDomain); result != nil {
		return result
	}

	if pkey.revoked {
		return NewResult(Fail, ErrKeyRevoked)
	}

	// Verifiers MUST NOT treat messages from Signers in testing mode
	// differently from unsigned email
	if pkey.testing {
		return NewResult(None, ErrTestingMode)
	}

	if ok := compareDomains(s.userIdentifier, s.signerDomain, pkey.strict); !ok {
		return NewResult(Permerror, ErrDomainMismatch)
	}

	// Fail fast here, provided all VerifyOption is quite fast
	for _, option := range options {
		if result = option(s, pkey, m); result != nil {
			return
		}
	}

	if result = s.verifyBodyHash(m.Body); result != nil {
		return
	}

	// In hash step 2, the Signer/Verifier MUST pass the following to the
	// hash algorithm in the indicated order.
	//
	// 1.  The header fields specified by the "h=" tag, in the order
	//	   specified in that tag, and canonicalized using the header
	//	   canonicalization algorithm specified in the "c=" tag.  Each
	//	   header field MUST be terminated with a single CRLF.
	//
	// 2.  The DKIM-Signature header field that exists (verifying) or will
	//	   be inserted (signing) in the message, with the value of the "b="
	//	   tag (including all surrounding whitespace) deleted (i.e., treated
	//	   as the empty string), canonicalized using the header
	//	   canonicalization algorithm specified in the "c=" tag, and without
	//	   a trailing CRLF.

	// 5.4.2.  Signatures Involving Multiple Instances of a Field
	// https://tools.ietf.org/html/rfc6376#section-5.4.2
	getHeader := func(h mail.Header) func(k string) string {
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
				n = len(a)
			}
			n--
			i[k] = n
			return a[n]
		}
	}(m.Header)

	s.algorithm.f.Reset()
	w := s.algorithm.f
	for _, k := range s.headers {
		w.Write(canonicalizedHeader(k, getHeader(k), s.relaxedHeader))
		w.Write(crlf)
	}
	w.Write(canonicalizedHeader(s.header, s.emptyHashValue, s.relaxedHeader))
	if e := rsa.VerifyPKCS1v15(pkey.key, s.algorithm.id, s.algorithm.f.Sum(nil), s.hash); e != nil {
		return NewResult(Fail, ErrBadSignature)
	}

	return NewResult(Pass, nil)
}

func canonicalizedHeader(k, v string, relaxed bool) []byte {
	if !relaxed {
		// NOTE: textproto.Reader#ReadMIMEHeader returns map of
		// CanonicalMIMEHeaderKey(key) and make impossible
		// "simple" canonicalization
		// TODO raw headers required
		return []byte(k + `:` + v)
	}
	// 3.4.2.  The "relaxed" Header Canonicalization Algorithm
	// https://tools.ietf.org/html/rfc6376#section-3.4.2
	//
	// o  Convert all header field names (not the header field values) to
	//    lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
	//
	// o  Unfold all header field continuation lines as described in
	//    [RFC5322]; in particular, lines with terminators embedded in
	//    continued header field values (that is, CRLF sequences followed by
	//    WSP) MUST be interpreted without the CRLF.  Implementations MUST
	//    NOT remove the CRLF at the end of the header field value.
	//
	// o  Convert all sequences of one or more WSP characters to a single SP
	//    character.  WSP characters here include those before and after a
	//    line folding boundary.
	//
	// o  Delete all WSP characters at the end of each unfolded header field
	//    value.
	b := bytes.TrimRight(reUnfoldAndReduceWS.ReplaceAll([]byte(v), sp), wsp)
	h := make([]byte, 0, len(k)+len(b)+1)
	h = append(h, []byte(strings.ToLower(k))...)
	h = append(h, colon...)
	h = append(h, b...)
	return h
}
