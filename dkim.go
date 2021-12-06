package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result holds all details about result of DKIM signature verification
type Result struct {
	Order     int                `json:"order"`
	Result    ResultCode         `json:"code"`
	Error     *VerificationError `json:"error,omitempty"`
	Signature *Signature         `json:"signature,omitempty"`
	Key       *PublicKey         `json:"key,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

func newResult(c ResultCode, e *VerificationError, s *Signature, k *PublicKey) *Result {
	return &Result{
		Result:    c,
		Signature: s,
		Key:       k,
		Error:     e,
	}
}

// ResultCode presents a signature verification result in a form defined by
// RFC7601 in 2.7.1. DKIM and DomainKeys
type ResultCode uint8

// DKIM Verification Results
const (
	_ ResultCode = iota
	None
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
	// is unrecoverable, such as a required Header field being absent.
	// A later attempt is unlikely to produce a final result.
	case Permerror:
		return "permerror"
	default:
		return strconv.Itoa(int(r))
	}
}

func (r ResultCode) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

type ErrorSource uint8

const (
	VerifyError ErrorSource = iota
	SignatureError
	KeyError
)

type VerificationError struct {
	Err         error       `json:"error"`
	Explanation string      `json:"explanation,omitempty"`
	Source      ErrorSource `json:"source"`
	Tag         string      `json:"tag,omitempty"`
	Value       string      `json:"value,omitempty"`
}

func (e *VerificationError) Error() string {
	var w bytes.Buffer
	w.WriteString(e.Err.Error())
	if e.Explanation == "" {
		return w.String()
	}
	w.WriteString(` (`)
	w.WriteString(e.Explanation)
	if e.Tag != "" {
		w.WriteString(`; `)
		w.WriteString(e.Tag)
		w.WriteByte('=')
		w.WriteString(e.Value)
	}
	w.WriteByte(')')
	return w.String()
}

func (e *VerificationError) MarshalJSON() ([]byte, error) {
	// TODO (dmotylev) need a better way for marshalling errors
	if e == nil {
		return []byte("null"), nil
	}
	var tmp struct {
		Err         string      `json:"error"`
		Explanation string      `json:"explanation,omitempty"`
		Source      ErrorSource `json:"source"`
		Tag         string      `json:"tag,omitempty"`
		Value       string      `json:"value,omitempty"`
	}
	if e.Err != nil {
		tmp.Err = e.Err.Error()
	}
	tmp.Explanation = e.Explanation
	tmp.Source = e.Source
	tmp.Tag = e.Tag
	tmp.Value = e.Value
	return json.Marshal(&tmp)
}

// Possible reasons of failed verification
var (
	ErrUnacceptableKey             = errors.New("unacceptable key")
	ErrBadSignature                = errors.New("bad signature")
	ErrBodyHashMismatched          = errors.New("body hash mismatched")
	ErrSignatureNotFound           = errors.New("signature not found")
	ErrUnsupportedAlgorithm        = errors.New("unsupported algorithm")
	ErrInputError                  = errors.New("input error")
	ErrDomainMismatch              = errors.New("domain mismatch")
	ErrSignatureExpired            = errors.New("signature expired")
	ErrTimestampInFuture           = errors.New("timestamp in the future")
	ErrInvalidSigningEntity        = errors.New("invalid signing entity")
	ErrKeyUnavailable              = errors.New("key unavailable")
	ErrTestingMode                 = errors.New("domain is testing DKIM")
	ErrKeyRevoked                  = errors.New("key revoked")
	errUnsupportedCanonicalization = errors.New("bad canonicalization")
)

const (
	expEmptyKey             = "empty key"
	expUnsupportedVersion   = "unsupported version"
	expUnsupportedAlgorithm = "unsupported algorithm"
	expUnsupportedServices  = "no supported services listed"
	expMalformedTagValue    = "malformed tag value"
	expUnsupportedQueryType = "bad query type"
	expFromNotSigned        = "'From' field not signed"
	expNoSignedFields       = "no signed fields"
	expNoDomainSpecified    = "no domain specified"
	expEmptyUserIdentity    = "empty user identity"
	expNotDecimalNumber     = "not a decimal number"
	expEmptySelector        = "empty selector"
)

const (
	sha1           = 3
	sha256         = 5
	ed25519_sha256 = 20
)

type AlgorithmID crypto.Hash

func (id AlgorithmID) MarshalText() ([]byte, error) {
	switch id {
	case sha1:
		return []byte("SHA1"), nil
	case sha256:
		return []byte("SHA256"), nil
	case ed25519_sha256:
		return []byte("ED25519-SHA256"), nil
	default:
		return []byte(strconv.FormatUint(uint64(id), 10)), nil
	}
}

// Signature holds parsed DKIM signature
type Signature struct {
	Header         string `json:"header"` // Header of the signature
	Raw            string `json:"raw"`    // Raw value of the signature
	emptyHashValue string
	algorithm      hash.Hash
	AlgorithmID    AlgorithmID       `json:"algorithmId"`             // 3 (SHA1) or 5 (SHA256)
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
	Raw        string   `json:"raw,omitempty"`        // raw value of the key record
	Version    string   `json:"version,omitempty"`    // 'v' tag value
	KeyType    string   `json:"key_type,omitempty"`   // 'k' tag value
	Data       []byte   `json:"key,omitempty"`        // 'p' tag value
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
	reReduceFWS         = regexp.MustCompile(`[ \t\r\n]+`)
	reUnfoldAndReduceWS = regexp.MustCompile(`[\s]+`)
	sp                  = []byte(" ")
	colon               = []byte(":")
	wsp                 = "\t "
	crlf                = []byte("\r\n")
	// Tag=Value Lists
	// https://tools.ietf.org/html/rfc6376#section-3.2
	reTagValueList = regexp.MustCompile(`;?\s*([[:alpha:]][[:alnum:]]*)\s*=\s*([^[:cntrl:];](?:[^;]*[^[:cntrl:]\s;])*)?\s*`)
	reBTagOnly     = regexp.MustCompile(`(;?\s*b\s*=)\s*([^[:cntrl:];](?:[^;]*[^[:cntrl:];])*)?\s*`)
	// c= Message canonicalization
	// https://tools.ietf.org/html/rfc6376#page-20
	reCanonicalization = regexp.MustCompile(`^([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]]))(?:/([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]])))?$`)
	// z= Copied Header fields
	// https://tools.ietf.org/html/rfc6376#page-25
	reCopiedHeaders = regexp.MustCompile(`\|?\s*([^[:cntrl:]: ]+):([^\s|]+)\s*`)
	// a slightly relaxed version of key-h-tag or key-s-tag
	// https://tools.ietf.org/html/rfc6376#page-27
	reKeyXTag       = regexp.MustCompile(`:?\s*([[:alnum:]](?:[[:alnum:]-]*[[:alnum:]])?)\s*`)
	reKeySTag       = regexp.MustCompile(`:?\s*([[:alnum:]*](?:[[:alnum:]-]*[[:alnum:]])?)?\s*`)
	reSignedHeaders = regexp.MustCompile(`:?\s*([^[:cntrl:]: ]+)\s*`)
	algorithms      = map[string]*algorithm{
		"rsa-sha1":       {crypto.SHA1, crypto.SHA1.New},
		"rsa-sha256":     {crypto.SHA256, crypto.SHA256.New},
		"ed25519-sha256": {ed25519_sha256, crypto.SHA256.New},
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
		return false, errUnsupportedCanonicalization
	}
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Replace(s, " ", "", -1))
}

func parseSignature(k, folded, original string) (*Signature, *VerificationError) {
	if folded == "" || original == "" {
		return nil, &VerificationError{Source: VerifyError, Err: ErrSignatureNotFound}
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
		Raw:    original,
		// The DKIM-Signature Header field that exists (verifying) or will
		// be inserted (signing) in the message, with the value of the "b="
		// tag (including all surrounding whitespace) deleted
		// (i.e., treated as the empty string)
		// https://tools.ietf.org/html/rfc6376#page-30
		emptyHashValue: reBTagOnly.ReplaceAllString(original, "$1"),
	}

	badSignature := func(t, v string, exp string) (*Signature, *VerificationError) {
		return nil, &VerificationError{
			Source:      SignatureError,
			Tag:         t,
			Value:       v,
			Err:         ErrBadSignature,
			Explanation: exp,
		}
	}

	for _, m := range reTagValueList.FindAllStringSubmatch(folded, -1) {
		// m := ["t=v" "t" "v"]
		key, value := m[1], m[2]
		var err error
		switch key {
		case "v":
			if value != "1" {
				return badSignature("v", value, expUnsupportedVersion)
			}
			required &^= fVersion
		case "a":
			a, found := algorithms[value]
			if !found {
				return badSignature("a", value, expUnsupportedAlgorithm)
			}
			s.algorithm = a.hash()
			s.AlgorithmID = AlgorithmID(a.id)
			required &^= fAlgorithm
		case "b":
			if s.Hash, err = decodeBase64(value); err != nil {
				return badSignature("b", value, expMalformedTagValue)
			}
			required &^= fHash
		case "bh":
			if s.BodyHash, err = decodeBase64(value); err != nil {
				return badSignature("bh", value, expMalformedTagValue)
			}
			required &^= fBodyHash
		case "c":
			m := reCanonicalization.FindAllStringSubmatch(value, 1)
			// m := [["headerAlgorigthm/bodyAlgorithm" "headerAlgorigthm" "bodyAlgorithm"]]
			if m == nil {
				return badSignature("c", value, errUnsupportedCanonicalization.Error())
			}
			if s.RelaxedHeader, err = checkRelaxed(m[0][1]); err != nil {
				return badSignature("c", value, err.Error())
			}
			if s.RelaxedBody, err = checkRelaxed(m[0][2]); err != nil {
				return badSignature("c", value, err.Error())
			}
		case "d":
			// The SDID MUST correspond to a valid DNS name under
			// which the DKIM key record is published.
			if value == "" {
				return badSignature("d", "", expNoDomainSpecified)
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
				return badSignature("h", "", expNoSignedFields)
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
				return badSignature("h", value, expFromNotSigned)
			}
			required &^= fHeaders
		case "i":
			// OPTIONAL, default is an empty local-part followed by an
			// "@" followed by the domain from the "d=" tag
			// sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
			//                            "@" domain-name
			if value == "" {
				return badSignature("i", "", expEmptyUserIdentity)
			}
			s.UserIdentifier = value
		case "l":
			if s.Length, err = strconv.ParseInt(value, 10, 64); err != nil {
				return badSignature("l", value, expNotDecimalNumber)
			}
		case "q":
			q, found := Queries[value]
			if !found {
				return badSignature("q", value, expUnsupportedQueryType)
			}
			s.query = q
		case "s":
			if value == "" {
				return badSignature("s", "", expEmptySelector)
			}
			s.Selector = value
			required &^= fSelector
		case "t":
			// Implementations MAY ignore signatures that have a Timestamp in the future.
			// https://tools.ietf.org/html/rfc6376#page-24
			var t int64
			if t, err = strconv.ParseInt(value, 10, 64); err != nil {
				return badSignature("t", value, expNotDecimalNumber)
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
				return badSignature("x", value, expNotDecimalNumber)
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
		return badSignature("", "", missedTags())
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
	r := NewReader(bufio.NewReader(in))
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

	// 3.4.3.  The "simple" Body Canonicalization Algorithm
	// Note that a completely empty or missing body is canonicalized as a single "CRLF"
	// https://tools.ietf.org/html/rfc6376#section-3.4.3
	if !relaxed && w.c == 0 {
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
type VerifyOption func(s *Signature, k *PublicKey, m *Message) (ResultCode, error)

// SignatureTimingOption checks if signature is expired
// Verifiers MAY ignore the DKIM-Signature Header field and return
// PERMFAIL (signature expired) if it contains an "x=" tag and
// the signature has expired.
func SignatureTimingOption(drift time.Duration) VerifyOption {
	return func(s *Signature, _ *PublicKey, _ *Message) (ResultCode, error) {
		now := time.Now().UTC()
		if s.Timestamp.After(now.Add(drift)) {
			return Permerror, ErrTimestampInFuture
		}
		if !s.Expiration.IsZero() && s.Expiration.Add(drift).Before(now) {
			return Permerror, ErrSignatureExpired
		}
		if !s.Expiration.IsZero() && !s.Timestamp.IsZero() && s.Expiration.Before(s.Timestamp) {
			return Permerror, ErrSignatureExpired
		}
		return 0, nil
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
	return func(s *Signature, _ *PublicKey, _ *Message) (ResultCode, error) {
		if _, found := index[s.SignerDomain]; found {
			return Permerror, ErrInvalidSigningEntity
		}
		return 0, nil
	}
}

// PublicKeyQuery defines API for implementation of "q=".
type PublicKeyQuery func(*Signature) (*PublicKey, error)

// DNSTxtPublicKeyQuery provides implementation of "dns/txt" query.
func _DNSTxtPublicKeyQuery(s *Signature) (*PublicKey, error) {
	records, err := net.LookupTXT(s.Selector + "._domainkey." + s.SignerDomain)
	if err != nil {
		// Assume lookup errors are temporary
		// TODO better error handling
		return nil, ErrKeyUnavailable
	}

	key, err := parsePublicKey(strings.Join(records, ""))
	if err != nil {
		return nil, err
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
	unacceptableKey := func(t, v string, s string) (*PublicKey, error) {
		return nil, &VerificationError{
			Source:      KeyError,
			Tag:         t,
			Value:       v,
			Err:         ErrUnacceptableKey,
			Explanation: s,
		}
	}

	if s == "" {
		return unacceptableKey("", "", expEmptyKey)
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
	k := &PublicKey{revoked: true, Raw: s}
	for _, m := range reTagValueList.FindAllStringSubmatch(s, -1) {
		// m := ["t=v" "t" "v"]
		key, value := m[1], m[2]
		switch key {
		case "v": // Version of the DKIM key record
			if value != "DKIM1" {
				return unacceptableKey("v", value, expUnsupportedVersion)
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
				return unacceptableKey("h", value, expUnsupportedAlgorithm)
			}
		case "k": // Key type
			k.KeyType = value
			if value != "rsa" && value != "ed25519" {
				// Unrecognized key types MUST be ignored.
				// https://tools.ietf.org/html/rfc6376#page-27
				return unacceptableKey("k", value, expUnsupportedAlgorithm)
			}
		case "n": // Notes that might be of interest to a human
			k.Notes = value
		case "p": // Public-key data (base64; REQUIRED)
			// An empty value means that this public key has been revoked.
			// The syntax and semantics of this tag value before being
			// encoded in base64 are defined by the "k=" tag.
			if value != "" {
				// INFORMATIVE NOTE: A base64string is permitted to include
				//         whitespace (FWS) at arbitrary places; however, any CRLFs must
				//         be followed by at least one WSP character.  Implementers and
				//         administrators are cautioned to ensure that selector TXT RRs
				//         conform to this specification.
				b, err := base64.StdEncoding.DecodeString(reReduceFWS.ReplaceAllString(value, ""))
				if err != nil {
					return unacceptableKey("p", value, err.Error())
				}
				k.Data = b
				if k.KeyType == "ed25519" {
					k.revoked = false
					return k, nil
				}
				i, err := x509.ParsePKIXPublicKey(b)
				if err != nil {
					return unacceptableKey("p", value, err.Error())
				}
				pkey, ok := i.(*rsa.PublicKey)
				if !ok {
					// should not happen
					return unacceptableKey("p", value, "internal error")
				}
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
				return unacceptableKey("s", value, expUnsupportedServices)
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
		return unacceptableKey("", "", missedTags())
	}

	return k, nil
}

func (s *Signature) verifyBodyHash(rs io.ReadSeeker) (ResultCode, error) {
	defer func(offset int64, _ error) {
		_, _ = rs.Seek(offset, io.SeekStart)
	}(rs.Seek(0, io.SeekCurrent))

	var r io.Reader = rs
	// In Hash step 1, the Signer/Verifier MUST Hash the message body,
	// canonicalized using the body canonicalization algorithm specified
	// in the "c=" tag and then truncated to the Length specified in the "l=" tag.
	// TODO cache BH for the message::Length
	if s.Length > 0 {
		r = io.LimitReader(r, s.Length)
	}

	bh, err := bodyHash(r, s.algorithm, s.RelaxedBody)
	if err != nil {
		return Temperror, ErrInputError
	}

	if !bytes.Equal(bh, s.BodyHash) {
		return Fail, ErrBodyHashMismatched
	}

	return 0, nil
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

func (s *Signature) verify(m *Message, options ...VerifyOption) (result *Result) {
	// TODO cache result
	if s == nil {
		return newResult(None, &VerificationError{Err: ErrSignatureNotFound}, s, nil)
	}

	wrapErr := func(err error, exp string, tag string) *VerificationError {
		return &VerificationError{Source: VerifyError, Err: err, Explanation: exp, Tag: tag}
	}

	pkey, err := s.query(s)

	switch err {
	case nil: // no errors
	case ErrKeyUnavailable:
		return newResult(Temperror, wrapErr(ErrKeyUnavailable, "", "s"), s, nil)
	default: // others
		if e, ok := err.(*VerificationError); ok {
			return newResult(Permerror, e, s, nil)
		}
		return newResult(Permerror, wrapErr(ErrUnacceptableKey, err.Error(), "s"), s, nil)
	}

	if pkey.revoked {
		return newResult(Fail, wrapErr(ErrUnacceptableKey, ErrKeyRevoked.Error(), "s"), s, nil)
	}

	// Verifiers MUST NOT treat messages from Signers in testing mode
	// differently from unsigned email
	if pkey.Testing {
		return newResult(None, wrapErr(ErrUnacceptableKey, ErrTestingMode.Error(), "s"), s, nil)
	}

	if ok := compareDomains(s.UserIdentifier, s.SignerDomain, pkey.Strict); !ok {
		return newResult(Permerror, wrapErr(ErrDomainMismatch, "", "d"), s, nil)
	}

	// Fail fast here, provided options are fast
	for _, option := range options {
		if code, err := option(s, pkey, m); err != nil {
			return newResult(code, wrapErr(ErrBadSignature, err.Error(), ""), s, pkey)
		}
	}

	body, err := ioutil.ReadAll(m.Body)
	if err != nil {
		return newResult(None, wrapErr(ErrInputError, err.Error(), "bh"), s, pkey)

	}

	if code, err := s.verifyBodyHash(bytes.NewReader(body)); err != nil {
		return newResult(code, wrapErr(ErrBadSignature, err.Error(), "bh"), s, pkey)
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
	getHeader := getHeaderFunc(m.Header, s.RelaxedHeader)

	s.algorithm.Reset()
	w := s.algorithm
	//w := io.MultiWriter(s.algorithm, os.Stderr)
	//os.Stderr.WriteString(">>>")
	for _, k := range s.Headers {
		origK, v, found := getHeader(k)
		if !found {
			continue
		}
		_, _ = w.Write(canonicalizedHeader(origK, v, s.RelaxedHeader))
		_, _ = w.Write(crlf)
	}
	_, _ = w.Write(canonicalizedHeader(s.Header, s.emptyHashValue, s.RelaxedHeader))
	//os.Stderr.WriteString("<<<\n")
	hashed := s.algorithm.Sum(nil)
	if s.AlgorithmID == ed25519_sha256 {
		ok := ed25519.Verify(pkey.Data, hashed[:], s.Hash)
		if !ok {
			return newResult(Fail, wrapErr(ErrBadSignature, "ed25519 verify failed", "b"), s, pkey)
		}
		return newResult(Pass, nil, s, pkey)
	}
	if err := rsa.VerifyPKCS1v15(pkey.key, crypto.Hash(s.AlgorithmID), hashed[:], s.Hash); err != nil {
		return newResult(Fail, wrapErr(ErrBadSignature, err.Error(), "b"), s, pkey)
	}

	return newResult(Pass, nil, s, pkey)
}

func getHeaderFunc(h MIMEHeader, relaxed bool) func(k string) (string, string, bool) {
	i := make(map[string]int, len(h))
	return func(key string) (string, string, bool) {
		k := CanonicalMIMEHeaderKey(key)
		var (
			a     []KVPair
			found bool
			n     int
		)
		a, found = h[k]
		if !found {
			return "", "", false
		}
		n, found = i[k]
		if n < 0 {
			return "", "", false
		}
		if !found {
			n = len(a) - 1
		}
		origK := k
		v := ""
		if n >= 0 {
			if relaxed {
				v = a[n].Folded
			} else {
				v = a[n].Original
			}
			origK = a[n].Key
		}
		n--
		i[k] = n
		return origK, v, true
	}
}

func canonicalizedHeader(k, v string, relaxed bool) []byte {
	// 3.4.1.  The "simple" Header Canonicalization Algorithm
	// https://tools.ietf.org/html/rfc6376#section-3.4.1
	//
	//   The "simple" header canonicalization algorithm does not change header
	//   fields in any way.  Header fields MUST be presented to the signing or
	//   verification algorithm exactly as they are in the message being
	//   signed or verified.  In particular, header field names MUST NOT be
	//   case folded and whitespace MUST NOT be changed.
	if !relaxed {
		h := make([]byte, 0, len(k)+len(v)+1)
		// As per https://tools.ietf.org/html/rfc5322#section-2.2
		// technically we should sanitize the k as well as v (see below), but we never saw folded headers
		h = append(h, []byte(k)...)
		h = append(h, colon...)
		// replace all LF with CRLF in case v came from source different then SMTP
		h = append(h, bytes.Replace([]byte(v), []byte("\n"), crlf, -1)...)
		return h
	}
	// 3.4.2.  The "relaxed" Header Canonicalization Algorithm
	// https://tools.ietf.org/html/rfc6376#section-3.4.2
	//
	//   o  Convert all header field names (not the header field values) to
	//      lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
	//
	//   o  Unfold all header field continuation lines as described in
	//      [RFC5322]; in particular, lines with terminators embedded in
	//      continued header field values (that is, CRLF sequences followed by
	//      WSP) MUST be interpreted without the CRLF.  Implementations MUST
	//      NOT remove the CRLF at the end of the header field value.
	//
	//   o  Convert all sequences of one or more WSP characters to a single SP
	//      character.  WSP characters here include those before and after a
	//      line folding boundary.
	//
	//   o  Delete all WSP characters at the end of each unfolded header field
	//      value.
	//
	//   o  Delete any WSP characters remaining before and after the colon
	//      separating the header field name from the header field value.  The
	//      colon separator MUST be retained.
	b := trim(reUnfoldAndReduceWS.ReplaceAll([]byte(v), sp))
	h := make([]byte, 0, len(k)+len(b)+1)
	h = append(h, []byte(strings.ToLower(k))...)
	h = append(h, colon...)
	h = append(h, b...)
	return h
}

// Verify extracts DKIM signature from message, verifies it and returns Result
// of verification in accordance with RFC6376 (DKIM Signatures)
func Verify(hdr string, msg *Message, opts ...VerifyOption) ([]*Result, error) {
	if msg == nil || len(msg.Header) == 0 || msg.Body == nil {
		return []*Result{{Result: None}}, nil
	}

	sigs := msg.Header[CanonicalMIMEHeaderKey(hdr)]

	now := time.Now().UTC()

	results := make([]*Result, 0, len(sigs))
	for i, raw := range sigs {
		var r *Result
		if _, err := msg.Body.Seek(0, io.SeekStart); err != nil {
			r = &Result{Result: Temperror, Error: &VerificationError{Err: err, Explanation: "internal error (seek to 0 failed)"}}
		} else {
			if s, err := parseSignature(hdr, raw.Folded, raw.Original); err != nil {
				r = newResult(Permerror, err, s, nil)
			} else {
				r = s.verify(msg, opts...)
			}
		}
		r.Order = i
		r.Timestamp = now
		results = append(results, r)
	}
	if len(results) == 0 {
		return []*Result{{Result: None}}, nil
	}

	return results, nil
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
	if r.Signature == nil {
		return w.String()
	}

	if r.Signature.SignerDomain != "" {
		w.WriteString("; header.d=")
		w.WriteString(r.Signature.SignerDomain)
	}
	if r.Signature.UserIdentifier != "" {
		w.WriteString("; header.i=")
		w.WriteString(r.Signature.UserIdentifier)
	}

	return w.String()
}
