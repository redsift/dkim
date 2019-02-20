package dkim

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type cacheEntry struct {
	s string
	k *PublicKey
	e error
}

var cache = map[string]*cacheEntry{
	`highgrade._domainkey.guerrillamail.com`: {s: `v=DKIM1; h=sha256; k=rsa; s=email; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxp5MZYH1xvKFqy8nt87DzhbagNQ00zY2hp7S/UZN8mjUwhwqh2yTsV+yMSqP6q72D6/1ZSMyRNS3n3jnPbA8pHlJmHxsDJOVeuVGHemjSlLk5HNto73fDnr1TEyLEx3cqPUNn0CRYltSjwnx9xJmRY3htX8CCapiE5hDhu0yWOw3FqKUnADlKuzJCL7xOkWXHXffKJGCrA/3HxJkaeg0ghPxhVfRv04ex0jTy9knWqDfpsftp1sxbBtmdSowaxGunfly6Vcb+N4EFcnyCrzFjfy/WUNrnVuLvRGUUHXHhujVXzpR1cD6cNJowRDyyF8nhJvr+0w3eGV8TXx6FKsuAwIDAQAB`},
	`20130820._domainkey.1e100.net`:          {s: `k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOv6+Txyz+SEc7mT719QQtOj6g2MjpErYUGVrRGGc7f5rmE1cRP1lhwx8PVoHOiuRzyok7IqjvAub9kk9fBoE9uXJB1QaRdMnKz7W/UhWemK5TEUgW1xT5qtBfUIpFRL34h6FbHbeysb4szi7aTgerxI15o73cP5BoPVkQj4BQKkfTQYGNH03J5Db9uMqW/NNJ8fKCLKWO5C1e+NQ1lD6uwFCjJ6PWFmAIeUu9+LfYW89Tz1NnwtSkFC96Oky1cmnlBf4dhZ/Up/FMZmB9l7TA6gLEu6JijlDrNmx1o50WADPjjN4rGELLt3VuXn09y2piBPlZPU2SIiDQC0qX0JWQIDAQAB`},
	`20161025._domainkey.1e100.net`:          {s: `k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoesoDYpDnaUGZFoCElFKAkhbPoqBCfkmz3LqSfdAkye2DpoxlBx+qybWdYXe55mCWPeVUIk10Z/H9uriY4enbpmUM0t3mhgyrxuKwJtFg0YgQ0WGpMKecYjhYkt+pcHy7J11BrYh6lHx7mXf5SxuoOF1B6rG1MTzgBKDQqHsBvfz9xZSsNA5HW41EHu4dxRz/QLvzJYegLac8p6oU7l8O/yaVAse0DpgkVu+adfDV+flDq+nohyt2CJ+XHHdbIpE3cb01wp4Znz05zcYaTJd6WIQuis9sjGpS8sDEhY2gZkJVE2jvk1/mObTsyJuVuORapZnXO740owXe8Pvxq7uQIDAQAB`},
	`mail._domainkey.parkanyi.eu`:            {s: `v=DKIM1; h=sha256; k=rsa; s=email; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5j5tt9IUww9mdMgbuI2DCHJy0RJlOZEFQrYF8KLRfgYVi9YVSz4cUGU0c7o8Rv31hs6diz4vIO49fTL8uS84guObkI361RBwwN37Ci1q6lf9NVirDi+KjlX//7JjRgkz4arPY3FlkNi53x1VnnbuHF6C/8B2YdDVs335iriWIXLCdIhpZa2uoxeYYtvvqg3/7MgB94ZMtluZxollav/zB1dQTpAmjGQeH35eXb+L2uc6c05jr/VNFdU8Rf7ucGNMcv/aLc0/ri6JJrPEJnahYO42SsPtc29HfZSiWI/l55k0A1sFgAEIxM+GF57AVDZo3dN+JENFjrFRJ4otHUd9wIDAQAB`},
}

func CachedPublicKeyQuery(s *Signature) (*PublicKey, error) {
	n := s.Selector + "._domainkey." + s.SignerDomain
	c, found := cache[n]
	if !found {
		return _DNSTxtPublicKeyQuery(s)
	}
	if c.k != nil || c.e != nil {
		return c.k, c.e
	}
	k, e := parsePublicKey(c.s)
	entry := &cacheEntry{k: k, e: e}
	cache[n] = entry
	return entry.k, nil
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
		"highgrade":        {Selector: "highgrade", SignerDomain: "guerrillamail.com"},
		"20161025":         {Selector: "20161025", SignerDomain: "1e100.net"},
		"temperror":        {Selector: "temperror", SignerDomain: "example.com"},
		"untrimmed-domain": {Selector: "20161025", SignerDomain: " 1e100.net "},
	}

	tests := []struct {
		name string
		s    *Signature
		k    *PublicKey
		e    error
	}{
		{"highgrade", sigs["highgrade"], mustKey("highgrade", "guerrillamail.com"), nil},
		{"20161025", sigs["20161025"], mustKey("20161025", "1e100.net"), nil},
		{"temperror", sigs["temperror"], nil, ErrKeyUnavailable},
	}

	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.name), func(t *testing.T) {
			k, e := _DNSTxtPublicKeyQuery(test.s)
			if !reflect.DeepEqual(k, test.k) {
				t.Errorf("DNSTxtPublicKeyQuery()\n\t got k=%v\n\twant k=%v", k, test.k)
			}
			if !reflect.DeepEqual(e, test.e) {
				t.Errorf("DNSTxtPublicKeyQuery()\n\t got e=%v\n\twant e=%v", e, test.e)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	unacceptableKey := func(t, v string, s string) error {
		return &VerificationError{
			Source:      KeyError,
			Tag:         t,
			Value:       v,
			Err:         ErrUnacceptableKey,
			Explanation: s,
		}
	}
	tests := []struct {
		name    string
		raw     string
		wantKey *PublicKey
		wantErr error
	}{
		{"empty",
			"", nil, unacceptableKey("", "", expEmptyKey)},
		{"wrong_version",
			"v=1", nil, unacceptableKey("v", "1", expUnsupportedVersion)},
		{"no data",
			"v=DKIM1", nil, unacceptableKey("", "", "no required tags found (v)")},
		{"wrong algorithm",
			"h=md5", nil, unacceptableKey("h", "md5", expUnsupportedAlgorithm)},
		{"wrong type",
			"k=des", nil, unacceptableKey("k", "des", expUnsupportedAlgorithm)},
		{"revoked",
			"p=", &PublicKey{Raw: "p=", revoked: true}, nil},
		{"wrong data",
			"p==", nil, unacceptableKey("p", "=", "illegal base64 data at input byte 0")},
		{"not a key",
			"p=MAMA", nil, unacceptableKey("p", "MAMA", "asn1: syntax error: data truncated")},
		{"revoked testing strict",
			"p=; t=y:\n\ts", &PublicKey{Raw: "p=; t=y:\n\ts", Flags: []string{"y", "s"}, revoked: true, Testing: true, Strict: true}, nil},
		{"x-teleport",
			"p=; s=*:email:x-teleport", &PublicKey{Raw: "p=; s=*:email:x-teleport", revoked: true, Services: []string{"*", "email", "x-teleport"}}, nil},
		{"no services listed",
			"p=; s=x-teleport", nil, unacceptableKey("s", "x-teleport", expUnsupportedServices)},
		{"key with ws", `k=rsa; p=  NDM1NWE0Nm
 IxOWQzNDhkYzJmNTdjM   DQ2ZjhlZjYzZDQ1Mzh   lYmI5MzYwMDBm 
 M2M5ZWU5NTRhMjc0NjBkZDg2NSAgLQo=`, nil, unacceptableKey("p", `NDM1NWE0Nm
 IxOWQzNDhkYzJmNTdjM   DQ2ZjhlZjYzZDQ1Mzh   lYmI5MzYwMDBm 
 M2M5ZWU5NTRhMjc0NjBkZDg2NSAgLQo=`, "asn1: structure error: tags don't match (16 vs {class:0 tag:20 length:51 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} publicKeyInfo @2")},
	}
	const wantTest = 11
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
				AlgorithmID: AlgorithmID(algorithms["rsa-sha256"].id),
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
				AlgorithmID: AlgorithmID(algorithms["rsa-sha1"].id),
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
			got, err := parseSignature("DKIM-Signature", test.raw, test.raw)
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
	newTagError := func(t, v, exp string) error {
		return &VerificationError{
			Source:      SignatureError,
			Tag:         t,
			Value:       v,
			Err:         ErrBadSignature,
			Explanation: exp,
		}
	}
	tests := []struct {
		raw  string
		want error
	}{
		{``, &VerificationError{Source: VerifyError, Err: ErrSignatureNotFound}},
		{`v=0`, newTagError("v", "0", expUnsupportedVersion)},
		{`b==`, newTagError("b", "=", expMalformedTagValue)},
		{`d=`, newTagError("d", "", expNoDomainSpecified)},
		{`h=`, newTagError("h", "", expNoSignedFields)},
		{`s=`, newTagError("s", "", expEmptySelector)},
		{`bh==`, newTagError("bh", "=", expMalformedTagValue)},
		{`c=complex`, newTagError("c", "complex", errUnsupportedCanonicalization.Error())},
		{`c=simple/x-unknown`, newTagError("c", "simple/x-unknown", errUnsupportedCanonicalization.Error())},
		{`c=simple/`, newTagError("c", "simple/", errUnsupportedCanonicalization.Error())},
		{`c=/`, newTagError("c", "/", errUnsupportedCanonicalization.Error())},
		{`c=/simple`, newTagError("c", "/simple", errUnsupportedCanonicalization.Error())},
		{`l=a`, newTagError("l", "a", expNotDecimalNumber)},
		{`q=dns/svc`, newTagError("q", "dns/svc", expUnsupportedQueryType)},
		{`t=z`, newTagError("t", "z", expNotDecimalNumber)},
		{`x=z`, newTagError("x", "z", expNotDecimalNumber)},
		{`xx=z`,
			&VerificationError{Source: SignatureError, Err: ErrBadSignature, Explanation: "no required tags found (v, a, b, bh, d, h, s)"}},
		{`i=`, newTagError("i", "", expEmptyUserIdentity)},
		{`a=rsa-md5`, newTagError("a", "rsa-md5", expUnsupportedAlgorithm)},
		{` a=rsa-sha256; d=d; s=is; h=From; bh=MA MA; b=MA==`,
			&VerificationError{Source: SignatureError, Err: ErrBadSignature, Explanation: "no required tags found (v)"}},
		{`a=rsa-sha256; d=d; s=is; h=From; bh=MA==; b=MA==`,
			&VerificationError{Source: SignatureError, Err: ErrBadSignature, Explanation: "no required tags found (v)"}},
		{`v=1; a=rsa-sha256; d=d; s=brisbane; h=to:subject:date; bh=MA==; b=MA==`, newTagError("h", "to:subject:date", expFromNotSigned)},
	}
	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d", testNo), func(t *testing.T) {
			_, got := parseSignature("DKIM-Signature", test.raw, test.raw)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("parseSignature()\n\tgot =\"%#v\"\n\twant=\"%#v\"", got, test.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	{
		var s *Signature
		want := newResult(None, &VerificationError{Err: ErrSignatureNotFound}, nil, nil)
		if got := s.verify(nil); !reflect.DeepEqual(got, want) {
			t.Errorf("nil: got %v, want %v", got, want)
		}
	}

	type result struct {
		Order   int
		Code    ResultCode
		WantErr bool
		Err     *VerificationError
	}

	tests := []struct {
		file    string
		wantErr bool
		want    []result
	}{
		{"_samples/s001.eml", false, []result{{0, Pass, false, nil}}},
		{"_samples/s002.eml", false, []result{{0, Pass, false, nil}}},
		{"_samples/s003.eml", false, []result{{0, Pass, false, nil}}},
		{"_samples/s004.eml", false, []result{{0, Pass, false, nil}}},
		{"_samples/s005.eml", false, []result{{0, Fail, true, &VerificationError{Err: ErrBadSignature, Explanation: "body hash mismatched", Tag: "bh"}}}},
		{"_samples/s006.eml", false, []result{{0, Fail, true, &VerificationError{Err: ErrBadSignature, Explanation: "body hash mismatched", Tag: "bh"}}}},
		{"_samples/s007.eml", false, []result{{0, Fail, true, &VerificationError{Err: ErrBadSignature, Explanation: "crypto/rsa: verification error", Tag: "b"}}}},
		{"_samples/s008.eml", false, []result{{0, None, false, nil}}},
		{"_samples/s009.eml", false, []result{{0, None, false, nil}}},
		{"_samples/s010.eml", false, []result{{0, None, false, nil}}},
		{"_samples/case161751693.eml", false, []result{{0, Pass, false, nil}}},                                               // OverSigned header with empty Subject (or other) header
		{"_samples/case160015800.eml", false, []result{{0, Pass, false, nil}}},                                               // OverSigned header
		{"_samples/case161455451.eml", false, []result{{0, Pass, false, nil}, {1, Pass, false, nil}, {2, Pass, false, nil}}}, // Multiple DKIM-Signature headers
		{"_samples/simple-simple.eml", false, []result{{0, Pass, false, nil}}},
		{"_samples/simple-relaxed.eml", false, []result{{0, Pass, false, nil}}},
		{"_samples/relaxed-relaxed.eml", false, []result{{0, Pass, false, nil}}},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			f, _ := os.Open(test.file)
			defer f.Close()

			var (
				b, _ = ioutil.ReadAll(f)
				m    *Message
				e    error
			)
			m, e = ParseMessage(string(b))
			switch e {
			case nil:
			case io.EOF:
			default:
				t.Fatalf("can't read file: %v", e)
			}
			got, err := Verify("DKIM-Signature", m)

			if test.wantErr == (err == nil) {
				t.Errorf("Verify() err=%v,wantErr=%t", err, test.wantErr)
			}

			results := make([]result, 0, len(got))
			for i, r := range got {
				results = append(results, result{i, r.Result, r.Error != nil, r.Error})
			}

			if diff := cmp.Diff(test.want, results, cmp.Comparer(cmpVerificationErrors)); diff != "" {
				t.Errorf("Verify() results differ: (-want +got)\n%s", diff)
			}
		})
	}
}

func cmpVerificationErrors(lv, rv *VerificationError) bool {
	if lv != nil && rv != nil {
		if lv.Err != rv.Err {
			return false
		}
		if lv.Err != nil && rv.Err != nil && lv.Err.Error() != rv.Err.Error() {
			return false
		}
		if lv.Explanation != rv.Explanation {
			return false
		}
		if lv.Source != rv.Source {
			return false
		}
		if lv.Tag != rv.Tag {
			return false
		}
		return lv.Value == rv.Value
	}
	return lv == rv
}

func TestInvalidSigningEntityOption(t *testing.T) {
	o := InvalidSigningEntityOption("com", "ru")
	samples := []struct {
		s *Signature
		c ResultCode
		e error
	}{
		{&Signature{SignerDomain: "com"}, Permerror, ErrInvalidSigningEntity},
		{&Signature{SignerDomain: "ru"}, Permerror, ErrInvalidSigningEntity},
		{&Signature{SignerDomain: "io"}, 0, nil},
	}
	for i, want := range samples {
		code, err := o(want.s, nil, nil)
		if code != want.c {
			t.Errorf("sample#%d got code %v, want code %v", i, code, want.c)
		}
		if !reflect.DeepEqual(err, want.e) {
			t.Errorf("sample#%d got err %v, want err %v", i, err, want.e)
		}
	}
}

func TestSignatureTimingOption(t *testing.T) {
	o := SignatureTimingOption(5 * time.Minute)
	tests := []struct {
		name string
		s    *Signature
		c    ResultCode
		e    error
	}{
		{"t=now", &Signature{Timestamp: time.Now().UTC()}, 0, nil},
		{"t=now+1m", &Signature{Timestamp: time.Now().Add(1 * time.Minute).UTC()}, 0, nil},
		{"t=now-1m", &Signature{Timestamp: time.Now().Add(-1 * time.Minute).UTC()}, 0, nil},
		{"t=now+10m", &Signature{Timestamp: time.Now().Add(10 * time.Minute).UTC()}, Permerror, ErrTimestampInFuture},
		{"x=now", &Signature{Expiration: time.Now().UTC()}, 0, nil},
		{"x=now+1m", &Signature{Expiration: time.Now().Add(1 * time.Minute).UTC()}, 0, nil},
		{"x=now-1m", &Signature{Expiration: time.Now().Add(-1 * time.Minute).UTC()}, 0, nil},
		{"x=now-10m", &Signature{Expiration: time.Now().Add(-10 * time.Minute).UTC()}, Permerror, ErrSignatureExpired},
		{"x=now+10m", &Signature{Expiration: time.Now().Add(10 * time.Minute).UTC()}, 0, nil},
		{"t=0,x=0", &Signature{}, 0, nil},
	}
	for testNo, test := range tests {
		t.Run(fmt.Sprintf("%d_%s)", testNo, test.name), func(t *testing.T) {
			code, err := o(test.s, nil, nil)
			if code != test.c {
				t.Errorf("SignatureTimingOption() got code %v, want code %v", code, test.c)
			}
			if !reflect.DeepEqual(err, test.e) {
				t.Errorf("SignatureTimingOption() got err %v, want err %v", err, test.e)
			}
		})
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
		//{nil, ""},
		{newResult(None, &VerificationError{Err: ErrSignatureNotFound}, nil, nil), "none; problem=signature not found"},
		{newResult(None, nil, nil, nil), "none"},
		{newResult(Pass, nil, nil, nil), "pass"},
		{newResult(Pass, nil, &Signature{
			SignerDomain: "example.com",
		}, nil), "pass; Header.d=example.com"},
		{newResult(Pass, nil, &Signature{
			UserIdentifier: "jdoe@example.com",
		}, nil), "pass; Header.i=jdoe@example.com"},
		{newResult(Pass, nil, &Signature{
			SignerDomain:   "example.com",
			UserIdentifier: "jdoe@example.com",
		}, nil), "pass; Header.d=example.com; Header.i=jdoe@example.com"},
	}
	for i, sample := range samples {
		got := sample.result.String()
		if got != sample.want {
			t.Errorf("sample#%d got `%s`, want `%s`", i, got, sample.want)
		}
	}
}

func TestGetHeaderFunc(t *testing.T) {
	type result struct {
		key   string
		value string
		found bool
	}
	tests := []struct {
		name    string
		header  MIMEHeader
		relaxed bool
		keys    []string
		want    []result
	}{
		{
			name: "relaxed,1x1",
			header: MIMEHeader{
				"From": {{"from", "orig-0", "fold-0"}}},
			relaxed: true,
			keys:    []string{"from"},
			want:    []result{{"from", "fold-0", true}},
		},
		{
			name: "relaxed,2x1",
			header: MIMEHeader{
				"From": {
					{"froM", "orig-0", "fold-0"},
					{"FROM", "orig-1", "fold-1"}}},
			relaxed: true,
			keys:    []string{"from", "FROM"},
			want:    []result{{"FROM", "fold-1", true}, {"froM", "fold-0", true}},
		},
		{
			name: "relaxed,1x2",
			header: MIMEHeader{
				"From": {{"from", "orig-0", "fold-0"}}},
			relaxed: true,
			keys:    []string{"from", "From"},
			want:    []result{{"from", "fold-0", true}, {"", "", false}},
		},
		{
			name: "relaxed,0x2",
			header: MIMEHeader{
				"From": {}},
			relaxed: true,
			keys:    []string{"from", "FROM"},
			want:    []result{{"From", "", true}, {"", "", false}},
		},
		{
			name:    "relaxed,_x2",
			relaxed: true,
			keys:    []string{"from", "from"},
			want:    []result{{"", "", false}, {"", "", false}},
		},
		{
			name: "simple,1x1",
			header: MIMEHeader{
				"From": {{"From", "orig-0", "fold-0"}}},
			relaxed: false,
			keys:    []string{"from"},
			want:    []result{{"From", "orig-0", true}},
		},
		{
			name: "simple,2x1",
			header: MIMEHeader{
				"From": {
					{"From", "orig-0", "fold-0"},
					{"From", "orig-1", "fold-1"}}},
			relaxed: false,
			keys:    []string{"from", "from"},
			want:    []result{{"From", "orig-1", true}, {"From", "orig-0", true}},
		},
		{
			name: "simple,1x2",
			header: MIMEHeader{
				"From": {{"From", "orig-0", "fold-0"}}},
			relaxed: false,
			keys:    []string{"from", "from"},
			want:    []result{{"From", "orig-0", true}, {"", "", false}},
		},
		{
			name: "simple,0x2",
			header: MIMEHeader{
				"From": {}},
			relaxed: false,
			keys:    []string{"from", "from"},
			want:    []result{{"From", "", true}, {"", "", false}},
		},
		{
			name:    "simple,_x2",
			relaxed: false,
			keys:    []string{"from", "from"},
			want:    []result{{"", "", false}, {"", "", false}},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d/%s", i, test.name), func(t *testing.T) {
			getHeader := getHeaderFunc(test.header, test.relaxed)
			for j := range test.keys {
				k, v, found := getHeader(test.keys[j])
				if k != test.want[j].key {
					t.Errorf("getHeaderFunc(%q) k=`%s`, want `%s`", test.keys[j], k, test.want[j].key)
				}
				if found != test.want[j].found {
					t.Errorf("getHeaderFunc(%q) found=%t, want %t", test.keys[j], found, test.want[j].found)
				}
				if v != test.want[j].value {
					t.Errorf("getHeaderFunc(%q) v=`%s`, want `%s`", test.keys[j], v, test.want[j].value)
				}
			}
		})
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
			defer r.Close()

			c.L.Lock()
			for !ready {
				c.Wait()
			}
			c.L.Unlock()

			var (
				b, _ = ioutil.ReadAll(r)
				m    *Message
			)
			m, err = ParseMessage(string(b))
			if err != nil {
				t.Errorf("error reading message %s", err)
			}

			_, _ = Verify("DKIM-Signature", m,
				InvalidSigningEntityOption("com", "co.uk", "org", "net", "io", "uk"),
				SignatureTimingOption(5*time.Minute),
			)
		}(f, c)
	}
	ready = true
	c.Broadcast()
	wg.Wait()
}
