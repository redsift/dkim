package dkim

import (
	"bufio"
	"net/mail"
	"os"
	"reflect"
	"testing"
	"time"
)

type cacheEntry struct {
	s string
	k *PublicKey
	r *Result
}

var cache = map[string]*cacheEntry{
	`highgrade._domainkey.guerrillamail.com`: {s: `v=DKIM1; h=sha256; k=rsa; s=email; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxp5MZYH1xvKFqy8nt87DzhbagNQ00zY2hp7S/UZN8mjUwhwqh2yTsV+yMSqP6q72D6/1ZSMyRNS3n3jnPbA8pHlJmHxsDJOVeuVGHemjSlLk5HNto73fDnr1TEyLEx3cqPUNn0CRYltSjwnx9xJmRY3htX8CCapiE5hDhu0yWOw3FqKUnADlKuzJCL7xOkWXHXffKJGCrA/3HxJkaeg0ghPxhVfRv04ex0jTy9knWqDfpsftp1sxbBtmdSowaxGunfly6Vcb+N4EFcnyCrzFjfy/WUNrnVuLvRGUUHXHhujVXzpR1cD6cNJowRDyyF8nhJvr+0w3eGV8TXx6FKsuAwIDAQAB`},
	`20130820._domainkey.1e100.net`:          {s: `k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOv6+Txyz+SEc7mT719QQtOj6g2MjpErYUGVrRGGc7f5rmE1cRP1lhwx8PVoHOiuRzyok7IqjvAub9kk9fBoE9uXJB1QaRdMnKz7W/UhWemK5TEUgW1xT5qtBfUIpFRL34h6FbHbeysb4szi7aTgerxI15o73cP5BoPVkQj4BQKkfTQYGNH03J5Db9uMqW/NNJ8fKCLKWO5C1e+NQ1lD6uwFCjJ6PWFmAIeUu9+LfYW89Tz1NnwtSkFC96Oky1cmnlBf4dhZ/Up/FMZmB9l7TA6gLEu6JijlDrNmx1o50WADPjjN4rGELLt3VuXn09y2piBPlZPU2SIiDQC0qX0JWQIDAQAB`},
}

func CachedPublicKeyQuery(s, d string) (*PublicKey, *Result) {
	n := s + "._domainkey." + d
	c, found := cache[n]
	if !found {
		return nil, NewResult(Temperror, ErrKeyUnavailable)
	}
	if c.k != nil || c.r != nil {
		return c.k, c.r
	}
	k, e := parsePublicKey(c.s)
	entry := &cacheEntry{k: k}
	if e != nil {
		entry.r = NewResult(Temperror, e)
	}
	cache[n] = entry
	return entry.k, entry.r
}

func TestMain(m *testing.M) {
	Queries[qDNSTxt] = CachedPublicKeyQuery
	c := m.Run()
	Queries[qDNSTxt] = DNSTxtPublicKeyQuery
	os.Exit(c)
}

func TestDnsTxtPublicKeyQuery(t *testing.T) {
	mustKey := func(s, d string) *PublicKey {
		k, _ := CachedPublicKeyQuery(s, d)
		if k == nil {
			t.FailNow()
		}
		return k
	}
	samples := []struct {
		s string
		d string
		k *PublicKey
		r *Result
	}{
		{"highgrade", "guerrillamail.com", mustKey("highgrade", "guerrillamail.com"), nil},
		{"20130820", "1e100.net", mustKey("20130820", "1e100.net"), nil},
		{"permerror", "example.com", nil, NewResult(Temperror, ErrKeyUnavailable)},
	}
	for i, want := range samples {
		if k, r := DNSTxtPublicKeyQuery(want.s, want.d); !reflect.DeepEqual(k, want.k) || !reflect.DeepEqual(r, want.r) {
			t.Errorf("sample#%d got {%v %q}, want {%v %q}", i, k, r, want.k, want.r)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	samples := map[string]struct {
		k *PublicKey
		e error
	}{
		"":        {nil, ErrUnacceptableKey},
		"v=1":     {nil, ErrUnacceptableKey},
		"v=DKIM1": {nil, ErrUnacceptableKey},
		"h=md5":   {nil, ErrUnacceptableKey},
		"k=des":   {nil, ErrUnacceptableKey},
		"p=": {&PublicKey{
			revoked: true,
		}, nil},
		"p==":    {nil, ErrUnacceptableKey},
		"p=MAMA": {nil, ErrUnacceptableKey},
		"p=; t=y:\n\ts": {&PublicKey{
			revoked: true,
			testing: true,
			strict:  true,
		}, nil},
		"p=; s=*:email:x-teleport": {&PublicKey{
			revoked:  true,
			services: []string{"*", "email", "x-teleport"},
		}, nil},
		"p=; s=x-teleport": {nil, ErrUnacceptableKey},
	}
	for s, want := range samples {
		if k, e := parsePublicKey(s); !reflect.DeepEqual(k, want.k) || e != want.e {
			t.Errorf("for `%s` got {%q %v}, want %q", s, k, e, want)
		}
	}
}

func compareSignatures(l, r *Signature) bool {
	// Func values are deeply equal if both are nil; otherwise they are not
	// deeply equal.
	l.query = nil
	r.query = nil
	return reflect.DeepEqual(l, r)
}

func TestParseSignature(t *testing.T) {
	goodGirls := map[string]*Signature{
		`v=1; a=rsa-sha256; d=example.net; s=brisbane;
      c=simple; q=dns/txt; i=@eng.example.net;
      t=1117574938; x=1118006938;
      h=from:to:subject:date;
      z=From:foo@eng.example.net|To:joe@example.com|
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
	  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`: {
			header: "DKIM-Signature",
			emptyHashValue: `v=1; a=rsa-sha256; d=example.net; s=brisbane;
      c=simple; q=dns/txt; i=@eng.example.net;
      t=1117574938; x=1118006938;
      h=from:to:subject:date;
      z=From:foo@eng.example.net|To:joe@example.com|
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
	  b=`,
			algorithm: algorithms["rsa-sha256"],
			hash: []byte{119, 55, 85, 200, 231, 192, 40, 39, 75,
				93, 210, 78, 115, 209, 182, 171, 194, 232, 93, 41, 68, 158, 36,
				155, 106, 255, 178, 185, 78, 51, 25, 231, 171, 184, 61, 52, 150,
				204, 217, 86, 129, 184, 100, 116, 77, 137, 140, 209},
			bodyHash: []byte{49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
				49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54,
				55, 56, 57, 48, 49, 50},
			signerDomain:   "example.net",
			headers:        []string{"from", "to", "subject", "date"},
			userIdentifier: "@eng.example.net",
			selector:       "brisbane",
			timestamp:      time.Unix(1117574938, 0),
			expiration:     time.Unix(1118006938, 0),
			copiedHeaders: map[string]string{
				"From":    "foo@eng.example.net",
				"To":      "joe@example.com",
				"Subject": "demo=20run",
				"Date":    "July=205,=202005=203:44:08=20PM=20-0700",
			},
			query: Queries[qDNSTxt],
		},
		` v=1; a=rsa-sha1; d=example.net; s=brisbane;
			      c=simple/relaxed; q=dns/txt; i=@eng.example.net;
			      t=1117574938; x=1118006938;
			      h=from:to:subject:date;
			      z=From:foo@eng.example.net|To:joe@example.com|
			       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
			      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
				  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`: {
			header: "DKIM-Signature",
			emptyHashValue: ` v=1; a=rsa-sha1; d=example.net; s=brisbane;
			      c=simple/relaxed; q=dns/txt; i=@eng.example.net;
			      t=1117574938; x=1118006938;
			      h=from:to:subject:date;
			      z=From:foo@eng.example.net|To:joe@example.com|
			       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
			      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
				  b=`,
			algorithm: algorithms["rsa-sha1"],
			hash: []byte{119, 55, 85, 200, 231, 192, 40, 39,
				75, 93, 210, 78, 115, 209, 182, 171, 194, 232, 93,
				41, 68, 158, 36, 155, 106, 255, 178, 185, 78, 51,
				25, 231, 171, 184, 61, 52, 150, 204, 217, 86, 129,
				184, 100, 116, 77, 137, 140, 209},
			bodyHash: []byte{49, 50, 51, 52, 53, 54, 55, 56, 57,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50,
				51, 52, 53, 54, 55, 56, 57, 48, 49, 50},
			relaxedBody:    true,
			signerDomain:   "example.net",
			headers:        []string{"from", "to", "subject", "date"},
			userIdentifier: "@eng.example.net",
			selector:       "brisbane",
			timestamp:      time.Unix(1117574938, 0),
			expiration:     time.Unix(1118006938, 0),
			copiedHeaders: map[string]string{
				"From":    "foo@eng.example.net",
				"To":      "joe@example.com",
				"Subject": "demo=20run",
				"Date":    "July=205,=202005=203:44:08=20PM=20-0700",
			},
		},
	}
	for h, want := range goodGirls {
		got, err := parseSignature("DKIM-Signature", h)
		if err != nil {
			t.Errorf("for `%.20s...` got error `%s`", h, err)
			t.FailNow()
		}
		if eq := compareSignatures(want, got); !eq {
			t.Errorf("for `%.20s...` got `%v`, want `%v`", h, got, want)
		}
	}

	badBoys := map[string]error{
		``:                   ErrSignatureNotFound,
		`v=0`:                ErrUnsupportedVersion,
		`b==`:                ErrMalformedTagValue,
		`d=`:                 ErrMalformedTagValue,
		`h=`:                 ErrNoSignedFields,
		`s=`:                 ErrMalformedTagValue,
		`bh==`:               ErrMalformedTagValue,
		`c=complex`:          ErrUnsupportedCanonicalization,
		`c=simple/x-unknown`: ErrUnsupportedCanonicalization,
		`c=simple/`:          ErrUnsupportedCanonicalization,
		`c=/`:                ErrUnsupportedCanonicalization,
		`c=/simple`:          ErrUnsupportedCanonicalization,
		`l=a`:                ErrMalformedTagValue,
		`q=dns/svc`:          ErrUnsupportedQueryType,
		`t=z`:                ErrMalformedTagValue,
		`x=z`:                ErrMalformedTagValue,
		`xx=z`:               ErrBadSignature,
		`i=`:                 ErrMalformedTagValue,
		`a=rsa-md5`:          ErrUnsupportedAlgorithm,
		` a=rsa-sha256; d=d; s=is; h=From; bh=MA MA; b=MA==`:                     ErrBadSignature,
		`a=rsa-sha256; d=d; s=is; h=From; bh=MA==; b=MA==`:                       ErrBadSignature,
		`v=1; a=rsa-sha256; d=d; s=brisbane; h=to:subject:date; bh=MA==; b=MA==`: ErrFromNotSigned,
	}
	for h, want := range badBoys {
		_, got := parseSignature("DKIM-Signature", h)
		if got != want {
			t.Errorf("for `%.30s...` got %q, want %q", h, got, want)
		}
	}
}

func TestVerify(t *testing.T) {
	{
		var s *Signature
		want := NewResult(None, ErrSignatureNotFound)
		if got := s.Verify(nil); !reflect.DeepEqual(got, want) {
			t.Errorf("nil: got %q, want %q", got, want)
		}
	}

	samples := map[string]*Result{
		"_samples/s001.eml": NewResult(Pass, nil),
		"_samples/s002.eml": NewResult(Pass, nil),
		"_samples/s003.eml": NewResult(Pass, nil),
		"_samples/s004.eml": NewResult(Pass, nil),
		"_samples/s005.eml": NewResult(Fail, ErrBadSignature),
		"_samples/s006.eml": NewResult(Fail, ErrBadSignature),
	}
	for sample, want := range samples {
		f, _ := os.Open(sample)
		m, e := mail.ReadMessage(bufio.NewReader(f))
		if e != nil {
			t.Errorf("%v: %v", sample, e)
			continue
		}
		k := "DKIM-Signature"
		v := m.Header.Get(k)
		s, err := parseSignature(k, v)
		if err != nil {
			t.Errorf("%v: `%s` got %v", sample, v, err)
		}

		if got := s.Verify(m); !reflect.DeepEqual(got, want) {
			t.Errorf("%v got %q, want %q", sample, got, want)
		}
		f.Close()

	}
}

func TestInvalidSigningEntityOption(t *testing.T) {
	o := InvalidSigningEntityOption("com", "ru")
	samples := []struct {
		s *Signature
		r *Result
	}{
		{&Signature{signerDomain: "com"}, NewResult(Permerror, ErrInvalidSigningEntity)},
		{&Signature{signerDomain: "ru"}, NewResult(Permerror, ErrInvalidSigningEntity)},
		{&Signature{signerDomain: "io"}, nil},
	}
	for i, want := range samples {
		if got := o(want.s, nil, nil); !reflect.DeepEqual(got, want.r) {
			t.Errorf("sample#%d got %q, want %q", i, got, want.r)
		}
	}
}

func TestSignatureTimingOption(t *testing.T) {
	o := SignatureTimingOption()
	samples := []struct {
		s *Signature
		r *Result
	}{
		{&Signature{timestamp: time.Now().Add(1 * time.Minute)}, NewResult(Permerror, ErrBadSignature)},
		{&Signature{expiration: time.Now().Add(1 * time.Minute)}, nil},
		{&Signature{timestamp: time.Now().Add(-1 * time.Minute)}, nil},
		{&Signature{}, nil},
		{&Signature{expiration: time.Now().Add(-1 * time.Minute)}, NewResult(Permerror, ErrSignatureExpired)},
	}
	for i, want := range samples {
		if got := o(want.s, nil, nil); !reflect.DeepEqual(got, want.r) {
			t.Errorf("sample#%d got %q, want %q", i, got, want.r)
		}
	}
}

func TestCompareDomains(t *testing.T) {
	samples := []struct {
		u      string
		d      string
		strict bool
		got    bool
	}{
		{"", "example.com", true, true},
		{"", "example.com", false, true},
		{"@example.com", "example.com", true, true},
		{"@example.com", "example.com", false, true},
		{"@good.example.com", "example.com", false, true},
	}
	for i, want := range samples {
		if got := compareDomains(want.u, want.d, want.strict); got != want.got {
			t.Errorf("sample#%d got %v, want %v", i, got, want.got)
		}
	}
}
