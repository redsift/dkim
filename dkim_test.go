package dkim

import (
	"bufio"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"reflect"
	"sync"
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

func CachedPublicKeyQuery(s *Signature) (*PublicKey, *Result) {
	n := s.Selector + "._domainkey." + s.SignerDomain
	c, found := cache[n]
	if !found {
		return nil, newResult(Temperror, ErrKeyUnavailable, nil)
	}
	if c.k != nil || c.r != nil {
		return c.k, c.r
	}
	k, e := parsePublicKey(c.s)
	entry := &cacheEntry{k: k}
	if e != nil {
		entry.r = newResult(Temperror, e, nil)
	}
	cache[n] = entry
	return entry.k, entry.r
}

func TestMain(m *testing.M) {
	Queries[qDNSTxt] = CachedPublicKeyQuery
	os.Exit(m.Run())
}

func TestDnsTxtPublicKeyQuery(t *testing.T) {
	mustKey := func(s, d string) *PublicKey {
		k, _ := CachedPublicKeyQuery(&Signature{Selector: s, SignerDomain: d})
		if k == nil {
			t.FailNow()
		}
		return k
	}

	sigs := map[string]*Signature{
		"highgrade": &Signature{Selector: "highgrade", SignerDomain: "guerrillamail.com"},
		"20130802":  &Signature{Selector: "20130820", SignerDomain: "1e100.net"},
		"temperror": &Signature{Selector: "temperror", SignerDomain: "example.com"},
	}

	tests := []struct {
		name string
		s    *Signature
		k    *PublicKey
		r    *Result
	}{
		{"highgrade", sigs["highgrade"], mustKey("highgrade", "guerrillamail.com"), nil},
		{"20130802", sigs["20130802"], mustKey("20130820", "1e100.net"), nil},
		{"temperror", sigs["temperror"], nil, newResult(Temperror, ErrKeyUnavailable, sigs["temperror"])},
	}

	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.name), func(t *testing.T) {
			k, r := _DNSTxtPublicKeyQuery(test.s)
			if !reflect.DeepEqual(k, test.k) {
				t.Errorf("DNSTxtPublicKeyQuery()\n\t got k=%q\n\twant k=%q", k, test.k)
			}
			if !reflect.DeepEqual(r, test.r) {
				t.Errorf("DNSTxtPublicKeyQuery()\n\t got r=%q\n\twant r=%q", r, test.r)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	unacceptableKey := func(t, v string, e error) error {
		return newSignatureError(ErrUnacceptableKey, newTagError(t, v, e).Error())
	}
	tests := []struct {
		name    string
		raw     string
		wantKey *PublicKey
		wantErr error
	}{
		{"empty",
			"", nil, newSignatureError(ErrUnacceptableKey, ErrEmptyKey.Error())},
		{"wrong_version",
			"v=1", nil, unacceptableKey("v", "1", ErrUnsupportedVersion)},
		{"no data",
			"v=DKIM1", nil, newSignatureError(ErrUnacceptableKey, "no required tags found (v)")},
		{"wrong algorithm",
			"h=md5", nil, unacceptableKey("h", "md5", ErrUnsupportedAlgorithm)},
		{"wrong type",
			"k=des", nil, unacceptableKey("k", "des", ErrUnsupportedAlgorithm)},
		{"revoked",
			"p=", &PublicKey{revoked: true}, nil},
		{"wrong data",
			"p==", nil, unacceptableKey("p", "=", errors.New("illegal base64 data at input byte 0"))},
		{"not a key",
			"p=MAMA", nil, unacceptableKey("p", "MAMA", errors.New("asn1: syntax error: data truncated"))},
		{"revoked testing strict",
			"p=; t=y:\n\ts", &PublicKey{Flags: []string{"y", "s"}, revoked: true, Testing: true, Strict: true}, nil},
		{"x-teleport",
			"p=; s=*:email:x-teleport", &PublicKey{revoked: true, Services: []string{"*", "email", "x-teleport"}}, nil},
		{"no services listed",
			"p=; s=x-teleport", nil, unacceptableKey("s", "x-teleport", ErrUnsupportedServices)},
	}
	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.name), func(t *testing.T) {
			key, err := parsePublicKey(test.raw)
			if !reflect.DeepEqual(err, test.wantErr) {
				t.Errorf("parsePublicKey()\n\t    err=\"%v\"\n\twantErr=\"%v\"", err, test.wantErr)
			}
			if !reflect.DeepEqual(key, test.wantKey) {
				t.Errorf("parsePublicKey()\n\t    key=\"%#v\"\n\twantKey=\"%#v\"", key, test.wantKey)
			}
		})
	}
}

func compareSignatures(l, r *Signature) bool {
	if l == r {
		return true
	}
	if l == nil || r == nil {
		return false
	}
	// Func values are deeply equal if both are nil; otherwise they are not deeply equal.
	l.query, r.query = nil, nil

	return reflect.DeepEqual(l, r)
}

func TestParseSignature_Valid(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    *Signature
		wantErr bool
	}{
		{
			"simple",
			`v=1; a=rsa-sha256; d=example.net; s=brisbane;
      c=simple; q=dns/txt; i=@eng.example.net;
      t=1117574938; x=1118006938;
      h=from:to:subject:date;
      z=From:foo@eng.example.net|To:joe@example.com|
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
	  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`,
			&Signature{
				Header: "DKIM-Signature",
				Raw: `v=1; a=rsa-sha256; d=example.net; s=brisbane;
      c=simple; q=dns/txt; i=@eng.example.net;
      t=1117574938; x=1118006938;
      h=from:to:subject:date;
      z=From:foo@eng.example.net|To:joe@example.com|
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
	  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`,
				emptyHashValue: `v=1; a=rsa-sha256; d=example.net; s=brisbane;
      c=simple; q=dns/txt; i=@eng.example.net;
      t=1117574938; x=1118006938;
      h=from:to:subject:date;
      z=From:foo@eng.example.net|To:joe@example.com|
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
	  b=`,
				algorithm:   algorithms["rsa-sha256"].hash(),
				AlgorithmID: algorithms["rsa-sha256"].id,
				Hash: []byte{119, 55, 85, 200, 231, 192, 40, 39, 75,
					93, 210, 78, 115, 209, 182, 171, 194, 232, 93, 41, 68, 158, 36,
					155, 106, 255, 178, 185, 78, 51, 25, 231, 171, 184, 61, 52, 150,
					204, 217, 86, 129, 184, 100, 116, 77, 137, 140, 209},
				BodyHash: []byte{49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
					49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54,
					55, 56, 57, 48, 49, 50},
				SignerDomain:   "example.net",
				Headers:        []string{"from", "to", "subject", "date"},
				UserIdentifier: "@eng.example.net",
				Selector:       "brisbane",
				Timestamp:      time.Unix(1117574938, 0),
				Expiration:     time.Unix(1118006938, 0),
				CopiedHeaders: map[string]string{
					"From":    "foo@eng.example.net",
					"To":      "joe@example.com",
					"Subject": "demo=20run",
					"Date":    "July=205,=202005=203:44:08=20PM=20-0700",
				},
				query: Queries[qDNSTxt],
			},
			false,
		},
		{
			"simple/relaxed",
			` v=1; a=rsa-sha1; d=example.net; s=brisbane;
			      c=simple/relaxed; q=dns/txt; i=@eng.example.net;
			      t=1117574938; x=1118006938;
			      h=from:to:subject:date;
			      z=From:foo@eng.example.net|To:joe@example.com|
			       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
			      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
				  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`,
			&Signature{
				Header: "DKIM-Signature",
				Raw: ` v=1; a=rsa-sha1; d=example.net; s=brisbane;
			      c=simple/relaxed; q=dns/txt; i=@eng.example.net;
			      t=1117574938; x=1118006938;
			      h=from:to:subject:date;
			      z=From:foo@eng.example.net|To:joe@example.com|
			       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
			      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
				  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`,
				emptyHashValue: ` v=1; a=rsa-sha1; d=example.net; s=brisbane;
			      c=simple/relaxed; q=dns/txt; i=@eng.example.net;
			      t=1117574938; x=1118006938;
			      h=from:to:subject:date;
			      z=From:foo@eng.example.net|To:joe@example.com|
			       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
			      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
				  b=`,
				algorithm:   algorithms["rsa-sha1"].hash(),
				AlgorithmID: algorithms["rsa-sha1"].id,
				Hash: []byte{119, 55, 85, 200, 231, 192, 40, 39,
					75, 93, 210, 78, 115, 209, 182, 171, 194, 232, 93,
					41, 68, 158, 36, 155, 106, 255, 178, 185, 78, 51,
					25, 231, 171, 184, 61, 52, 150, 204, 217, 86, 129,
					184, 100, 116, 77, 137, 140, 209},
				BodyHash: []byte{49, 50, 51, 52, 53, 54, 55, 56, 57,
					48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50,
					51, 52, 53, 54, 55, 56, 57, 48, 49, 50},
				RelaxedBody:    true,
				SignerDomain:   "example.net",
				Headers:        []string{"from", "to", "subject", "date"},
				UserIdentifier: "@eng.example.net",
				Selector:       "brisbane",
				Timestamp:      time.Unix(1117574938, 0),
				Expiration:     time.Unix(1118006938, 0),
				CopiedHeaders: map[string]string{
					"From":    "foo@eng.example.net",
					"To":      "joe@example.com",
					"Subject": "demo=20run",
					"Date":    "July=205,=202005=203:44:08=20PM=20-0700",
				},
			},
			false,
		},
	}
	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.name), func(t *testing.T) {
			got, err := parseSignature("DKIM-Signature", test.raw)
			if test.wantErr != (err != nil) {
				t.Errorf("parseSignature() err=%v, wantErr=%t", err, test.wantErr)
			}
			if !compareSignatures(test.want, got) {
				t.Errorf("parseSignature()\n\tgot =\"%#v\"\n\twant=\"%#v\"", got, test.want)
			}
		})
	}
}

func TestParseSignature_Errors(t *testing.T) {
	tests := []struct {
		raw  string
		want error
	}{
		{``, ErrSignatureNotFound},
		{`v=0`, newTagError("v", "0", ErrUnsupportedVersion)},
		{`b==`, newTagError("b", "=", ErrMalformedTagValue)},
		{`d=`, newTagError("d", "", ErrNoDomainSpecified)},
		{`h=`, newTagError("h", "", ErrNoSignedFields)},
		{`s=`, newTagError("s", "", ErrEmptySelector)},
		{`bh==`, newTagError("bh", "=", ErrMalformedTagValue)},
		{`c=complex`, newTagError("c", "complex", ErrUnsupportedCanonicalization)},
		{`c=simple/x-unknown`, newTagError("c", "simple/x-unknown", ErrUnsupportedCanonicalization)},
		{`c=simple/`, newTagError("c", "simple/", ErrUnsupportedCanonicalization)},
		{`c=/`, newTagError("c", "/", ErrUnsupportedCanonicalization)},
		{`c=/simple`, newTagError("c", "/simple", ErrUnsupportedCanonicalization)},
		{`l=a`, newTagError("l", "a", ErrNotDecimalNumber)},
		{`q=dns/svc`, newTagError("q", "dns/svc", ErrUnsupportedQueryType)},
		{`t=z`, newTagError("t", "z", ErrNotDecimalNumber)},
		{`x=z`, newTagError("x", "z", ErrNotDecimalNumber)},
		{`xx=z`, newSignatureError(ErrBadSignature, "no required tags found (v, a, b, bh, d, h, s)")},
		{`i=`, newTagError("i", "", ErrEmptyUserIdentity)},
		{`a=rsa-md5`, newTagError("a", "rsa-md5", ErrUnsupportedAlgorithm)},
		{` a=rsa-sha256; d=d; s=is; h=From; bh=MA MA; b=MA==`, newSignatureError(ErrBadSignature, "no required tags found (v)")},
		{`a=rsa-sha256; d=d; s=is; h=From; bh=MA==; b=MA==`, newSignatureError(ErrBadSignature, "no required tags found (v)")},
		{`v=1; a=rsa-sha256; d=d; s=brisbane; h=to:subject:date; bh=MA==; b=MA==`, newTagError("h", "to:subject:date", ErrFromNotSigned)},
	}
	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d", testNo), func(t *testing.T) {
			_, got := parseSignature("DKIM-Signature", test.raw)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("parseSignature()\n\tgot =\"%#v\"\n\twant=\"%#v\"", got, test.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	{
		var s *Signature
		want := newResult(None, ErrSignatureNotFound, nil)
		if got := s.verify(nil); !reflect.DeepEqual(got, want) {
			t.Errorf("nil: got %v, want %v", got, want)
		}
	}

	samples := map[string]*Result{
		"_samples/s001.eml": newResult(Pass, nil, nil),
		"_samples/s002.eml": newResult(Pass, nil, nil),
		"_samples/s003.eml": newResult(Pass, nil, nil),
		"_samples/s004.eml": newResult(Pass, nil, nil),
		"_samples/s005.eml": newResult(Fail, ErrBadSignature, nil),
		"_samples/s006.eml": newResult(Fail, ErrBadSignature, nil),
	}
	for sample, want := range samples {
		f, _ := os.Open(sample)
		m, e := mail.ReadMessage(bufio.NewReader(f))
		if e != nil {
			t.Errorf("%v: %v", sample, e)
			continue
		}
		got := Verify("DKIM-Signature", m)
		//if !compareSignatures(got.Signature, want.Signature) {
		//	t.Errorf("%v\n\t got \"%#v\"\n\twant \"%#v\"", sample, got.Signature, want.Signature)
		//}

		//if b, err := json.MarshalIndent(got, "", "  "); err == nil {
		//	t.Log(sample, string(b))
		//}

		// TODO compare signatures and keys
		got.Signature = nil
		got.Key = nil
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%v\n\t got \"%#v\"\n\twant \"%#v\"", sample, got, want)
		}
		_ = f.Close()
	}
}

func TestInvalidSigningEntityOption(t *testing.T) {
	o := InvalidSigningEntityOption("com", "ru")
	samples := []struct {
		s *Signature
		r *Result
	}{
		{&Signature{SignerDomain: "com"},
			newResult(Permerror, ErrInvalidSigningEntity, &Signature{SignerDomain: "com"})},
		{&Signature{SignerDomain: "ru"},
			newResult(Permerror, ErrInvalidSigningEntity, &Signature{SignerDomain: "ru"})},
		{&Signature{SignerDomain: "io"}, nil},
	}
	for i, want := range samples {
		if got := o(want.s, nil, nil); !reflect.DeepEqual(got, want.r) {
			t.Errorf("sample#%d got %v, want %v", i, got, want.r)
		}
	}
}

func TestSignatureTimingOption(t *testing.T) {
	o := SignatureTimingOption()
	samples := []struct {
		s *Signature
		r *Result
	}{
		{&Signature{Timestamp: time.Now().Add(1 * time.Minute)}, newResult(Permerror, ErrBadSignature, nil)},
		{&Signature{Expiration: time.Now().Add(1 * time.Minute)}, nil},
		{&Signature{Timestamp: time.Now().Add(-1 * time.Minute)}, nil},
		{&Signature{}, nil},
		{&Signature{Expiration: time.Now().Add(-1 * time.Minute)}, newResult(Permerror, ErrSignatureExpired, nil)},
	}
	for i, want := range samples {
		got := o(want.s, nil, nil)
		if got != nil {
			// remove Signature and make DeepEqual useful
			got.Signature = nil
		}
		if !reflect.DeepEqual(got, want.r) {
			t.Errorf("sample#%d got %v, want %v", i, got, want.r)
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

func TestResultString(t *testing.T) {
	samples := []struct {
		result *Result
		want   string
	}{
		{nil, ""},
		{newResult(None, ErrSignatureNotFound, nil), "none; problem=signature not found"},
		{newResult(None, nil, nil), "none"},
		{newResult(Pass, nil, nil), "pass"},
		{newResult(Pass, nil, &Signature{
			SignerDomain: "example.com",
		}), "pass; Header.d=example.com"},
		{newResult(Pass, nil, &Signature{
			UserIdentifier: "jdoe@example.com",
		}), "pass; Header.i=jdoe@example.com"},
		{newResult(Pass, nil, &Signature{
			SignerDomain:   "example.com",
			UserIdentifier: "jdoe@example.com",
		}), "pass; Header.d=example.com; Header.i=jdoe@example.com"},
	}
	for i, sample := range samples {
		got := sample.result.String()
		if got != sample.want {
			t.Errorf("sample#%d got `%s`, want `%s`", i, got, sample.want)
		}
	}
}

func TestGetHeaderFunc(t *testing.T) {
	samples := []struct {
		header mail.Header
		keys   []string
		want   []string
	}{
		{
			header: mail.Header(map[string][]string{
				"From": {"from-0"},
			}),
			keys: []string{"from"},
			want: []string{"from-0"},
		},
		{
			header: mail.Header(map[string][]string{
				"From": {"from-0", "from-1"},
			}),
			keys: []string{"from", "from"},
			want: []string{"from-1", "from-0"},
		},
		{
			header: mail.Header(map[string][]string{
				"From": {"from-0"},
			}),
			keys: []string{"from", "from"},
			want: []string{"from-0", ""},
		},
		{
			header: mail.Header(map[string][]string{
				"From": {},
			}),
			keys: []string{"from", "from"},
			want: []string{"", ""},
		},
		{
			keys: []string{"from", "from"},
			want: []string{"", ""},
		},
	}

	for i, s := range samples {
		getHeader := getHeaderFunc(s.header)
		for j := range s.keys {
			got := getHeader(s.keys[j])
			if got != s.want[j] {
				t.Errorf("#%d.%d (%s) got `%s`, want `%s`", i, j, s.keys[j], got, s.want[j])
			}
		}
	}
}

func TestVerify_Concurrent(t *testing.T) {
	m := &sync.Mutex{}
	c := sync.NewCond(m)
	ready := false

	wg := sync.WaitGroup{}
	for _, f := range []string{
		"_samples/s001.eml",
		"_samples/s002.eml",
		"_samples/s003.eml",
		"_samples/s004.eml",
		"_samples/s005.eml",
		"_samples/s006.eml",
		"_samples/s007.eml",
		"_samples/s007.eml",
	} {
		wg.Add(1)
		go func(f string, c *sync.Cond) {
			defer func() {
				if x := recover(); x != nil {
					t.Errorf("concurrent usage panic %s", x)
				}
			}()
			defer wg.Done()
			r, err := os.Open(f)
			if err != nil {
				t.Errorf("error opening file %s", err)
			}

			c.L.Lock()
			for !ready {
				c.Wait()
			}
			c.L.Unlock()

			msg, err := mail.ReadMessage(r)
			if err != nil {
				t.Errorf("error reading message %s", err)
			}

			_ = Verify("DKIM-Signature", msg,
				InvalidSigningEntityOption("com", "co.uk", "org", "net", "io", "uk"),
				SignatureTimingOption(),
			)
		}(f, c)
	}
	ready = true
	c.Broadcast()
	wg.Wait()
}
