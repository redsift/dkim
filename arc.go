package dkim

import (
	"errors"
	"strconv"
)

const (
	asKey  = "ARC-Seal"
	amsKey = "ARC-Message-signature"
	aarKey = "ARC-Authentication-Results"
)

var (
	ErrMissingArcFields      = errors.New("missing arc fields")
	ErrInstanceMismatch      = errors.New("mismatch of arc header instances")
	ErrArcLimit              = errors.New("message over arc-set limit")
	ErrMsgNotSigned          = errors.New("message is not arc signed")
	ErrAMSValidationFailure  = errors.New("most recent ARC-Message-signature did not validate")
	ErrAMSIncludesSealHeader = errors.New("Arc-Message-signature MUST NOT sign ARC-Seal")

	requiredAARTags = fInstance
	requiredASTags  = fAlgorithm + fHash + fSignerDomain + fSelector + fInstance + fCv
	requiredAMSTags = fAlgorithm + fHash + fBodyHash + fSignerDomain + fSelector + fInstance
)

type ArcResult struct {
	// Final result of verification
	Result

	// Result data at each part of the chain until failure
	Chain []ArcSetResult `json:"chain"`
}

// ArcSetResult holds the result data for verification of a single arc set
type ArcSetResult struct {
	Instance int        `json:"instance"`
	Spf      ResultCode `json:"spf"`
	Dkim     ResultCode `json:"dkim"`
	Dmarc    ResultCode `json:"dmarc"`
	AMSValid bool       `json:"ams-vaild"`
	ASValid  bool       `json:"as-valid"`
	CV       ResultCode `json:"cv"`
}

type arcResult struct {
	instance int
	amsValid bool
	asValid  bool
	cv       ResultCode
}

type arcSet struct {
	// authenticationResults is the authentication status in which the original message is received (DMARC, SPF and DKIM).
	// https://www.rfc-editor.org/rfc/rfc8617.html#section-4.1.1
	authenticationResults *Signature
	// messageSignature is the signature of type DKIM of the message to the shipment.
	messageSignature *Signature
	// seal is the DKIM signature of the Arc chain
	seal *Signature
}

func (s *arcSet) verify(instance int, msg *Message) (*arcResult, *VerificationError) {
	if contains(s.messageSignature.Headers, "arc-seal") {
		return nil, &VerificationError{
			Err:    ErrAMSIncludesSealHeader,
			Source: VerifyError,
			Tag:    "i",
			Value:  strconv.Itoa(instance),
		}
	}

	// Validate Arc-Message-signature
	res := s.messageSignature.verify(msg)
	arcRes := &arcResult{}
	if res.Result == Pass {
		arcRes.amsValid = true
	}

	// Validate Arc-Seal
	res = s.seal.verify(msg)
	if res.Result == Pass {
		arcRes.asValid = true
	}

	arcRes.cv = s.seal.ArcCV
	arcRes.instance = instance

	return arcRes, nil
}

func (s *Signature) isArc() bool {
	switch s.Header {
	case asKey, amsKey, aarKey:
		return true
	default:
		return false
	}
}

// VerifyArc
//
// https://www.rfc-editor.org/rfc/rfc8617.html#section-5.2
func VerifyArc(msg *Message) (*ArcResult, error) {
	if msg == nil || len(msg.Header) == 0 || msg.Body == nil {
		return &ArcResult{Result: Result{Result: None}}, nil
	}

	arcSets, err := extractArcSets(msg.Header)
	if err != nil {
		return &ArcResult{Result: Result{Result: Fail, Error: &VerificationError{Source: VerifyError, Err: err}}}, nil
	}

	//	"The maximum number of ARC Sets that can be attached to a
	//	message is 50.  If more than the maximum number exist, the
	//	Chain Validation Status is "fail..."
	l := len(arcSets)
	switch {
	case l == 0:
		return &ArcResult{Result: Result{Result: None, Error: &VerificationError{Source: VerifyError, Err: ErrMsgNotSigned}}}, nil
	case l > 50:
		return &ArcResult{Result: Result{Result: Fail, Error: &VerificationError{Source: VerifyError, Err: ErrArcLimit}}}, nil
	}

	// Verify each arc set starting at the most recent
	var results []arcResult
	var chain []ArcSetResult

	for i := len(arcSets) - 1; i != -1; i-- {
		// Returns all the arc headers up until 'instance', in the correct order.
		// Headers are used to produce arc-seal signature.
		// https://www.rfc-editor.org/rfc/rfc8617.html#section-5.1.1
		getArcHeaders := func(_ *Message) [][]string {
			var res [][]string
			for _, arcSet := range arcSets {
				res = append(res,
					[]string{aarKey, arcSet.authenticationResults.Raw},
					[]string{amsKey, arcSet.messageSignature.Raw},
				)

				if arcSet.messageSignature.ArcInstance == i+1 {
					break
				}
				// skip last seal as it's not in the signature
				res = append(res, []string{asKey, arcSet.seal.Raw})
			}
			return res
		}

		arcSets[i].seal.getHeadersFunc = getArcHeaders

		res, err := arcSets[i].verify(i+1, msg)
		if err != nil {
			return &ArcResult{Result: Result{Result: Fail, Error: &VerificationError{Source: VerifyError, Err: err}}, Chain: chain}, nil
		}

		chain = append(chain, ArcSetResult{
			Instance: res.instance,
			Spf:      arcSets[i].authenticationResults.Spf,
			Dkim:     arcSets[i].authenticationResults.Dkim,
			Dmarc:    arcSets[i].authenticationResults.Dmarc,
			AMSValid: res.amsValid,
			ASValid:  res.asValid,
			CV:       res.cv,
		})

		results = append(results, *res)
	}

	arcResult := func(result ResultCode, msg string, i int) *ArcResult {
		return &ArcResult{Result: Result{Result: Fail, Error: &VerificationError{
			Source:      VerifyError,
			Explanation: msg,
			Tag:         "i",
			Value:       strconv.Itoa(i),
		}}, Chain: chain}
	}

	if !results[0].amsValid {
		return arcResult(Fail, "Most recent ARC-Message-Signature did not validate", results[0].instance), nil
	}

	// Validate results
	//
	//	"The "cv" value for all ARC-Seal header fields MUST NOT be
	//	"fail".  For ARC Sets with instance values > 1, the values
	//	MUST be "pass".  For the ARC Set with instance value = 1, the
	//	value MUST be "none"."
	for _, res := range results {
		switch {
		case res.cv == Fail:
			return arcResult(Fail, "ARC-Seal reported failure, the chain is terminated", res.instance), nil
		case !res.asValid:
			return arcResult(Fail, "ARC-Seal did not validate", res.instance), nil
		case (res.instance == 1) && (res.cv != None):
			return arcResult(Fail, "ARC-Seal reported invalid status", res.instance), nil
		case (res.instance > 1) && (res.cv != Pass):
			return arcResult(Fail, "ARC-Seal reported invalid status", res.instance), nil
		}
	}

	return &ArcResult{Result: Result{Result: Pass}, Chain: chain}, nil
}

func extractArcSets(headers MIMEHeader) ([]*arcSet, error) {
	arcSeals := headers[canonicalMIMEHeaderKey([]byte(asKey))]
	signatures := headers[canonicalMIMEHeaderKey([]byte(amsKey))]
	results := headers[canonicalMIMEHeaderKey([]byte(aarKey))]

	// Each arc-set must have exactly one of each header (seal, message signature and authentication results)
	instances := len(arcSeals)
	if (instances != len(signatures)) || (len(signatures) != len(results)) {
		return nil, ErrMissingArcFields
	}

	sets := make([]*arcSet, instances)
	for i := 0; i < instances; i++ {
		as, err := parseSignature(asKey, arcSeals[i].Folded, arcSeals[i].Original, requiredASTags)
		if err != nil {
			return nil, err
		}
		// Seals only use "relaxed" header field canonicalization
		// https://www.rfc-editor.org/rfc/rfc8617.html#section-4.1.3
		as.RelaxedHeader = true

		ams, err := parseSignature(amsKey, signatures[i].Folded, signatures[i].Original, requiredAMSTags)
		if err != nil {
			return nil, err
		}
		// if "c=" not given, use relaxed
		if !ams.canonicalization {
			ams.RelaxedHeader = true
		}

		aar, err := parseSignature(aarKey, results[i].Folded, results[i].Original, requiredAARTags)
		if err != nil {
			return nil, err
		}

		// make sure instance values are aligned
		if as.ArcInstance != ams.ArcInstance && ams.ArcInstance != aar.ArcInstance {
			return nil, ErrInstanceMismatch
		}

		// use instance id as we want them in correct order
		sets[as.ArcInstance-1] = &arcSet{
			authenticationResults: aar,
			messageSignature:      ams,
			seal:                  as,
		}
	}

	return sets, nil
}

func contains(x []string, y string) bool {
	for _, s := range x {
		if s == y {
			return true
		}
	}

	return false
}
