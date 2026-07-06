package statuslist

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// cwtDecMode is a hardened CBOR decoder for the (untrusted) CWT payload
// (conventions.md: max nesting, max array/map sizes, duplicate-key reject,
// indefinite-length and tags forbidden). Static options ⇒ any construction
// error is a programming bug and panics at init, never on input.
var cwtDecMode = mustDecMode()

func mustDecMode() cbor.DecMode {
	dm, err := cbor.DecOptions{
		MaxNestedLevels:  8,
		MaxArrayElements: 1024,
		MaxMapPairs:      1024,
		IndefLength:      cbor.IndefLengthForbidden,
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		TagsMd:           cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic("statuslist: static CBOR DecOptions invalid: " + err.Error())
	}
	return dm
}

// cwtPayload mirrors the CBOR Status List Token claims (Token Status List §5.2).
// Standard CWT claim keys: sub=2, exp=4, iat=6 (RFC 8392). The two private claim
// keys status_list=65533 and ttl=65534, and the CWT typ header label 16 (see the
// spec subpackage), are CONFIRMED directly against the vendored primary source
// (references/statuslist-draft12.txt §5.2 / §14.3) — the earlier EU Statium
// reference-verifier cross-check (eudi-lib-kmp-statium-main /
// eudi-lib-ios-statium-swift-main) independently agrees. sub (2) and iat (6) are
// REQUIRED (§5.2); decodeClaims enforces their existence (§8.3 step 3.2).
// If issuers wrap the claims set in the CWT CBOR tag 61 (RFC 8392), relax TagsMd
// or strip the tag — verify against the draft.
type cwtPayload struct {
	Sub        string        `cbor:"2,keyasint"`
	Exp        *int64        `cbor:"4,keyasint"`
	Iat        int64         `cbor:"6,keyasint"`
	TTL        *int64        `cbor:"65534,keyasint"`
	StatusList cwtStatusList `cbor:"65533,keyasint"`
}

// cwtStatusList mirrors the CBOR status_list value (§5.2): text keys "bits"
// (uint) and "lst" (byte string, zlib-compressed).
type cwtStatusList struct {
	Bits int    `cbor:"bits"`
	Lst  []byte `cbor:"lst"`
}

func decodeCWTClaims(payload []byte) (statusListClaims, error) {
	var p cwtPayload
	if err := cwtDecMode.Unmarshal(payload, &p); err != nil {
		return statusListClaims{}, fmt.Errorf("%w: cbor claims: %v", ErrMalformed, err)
	}
	if len(p.StatusList.Lst) == 0 {
		return statusListClaims{}, fmt.Errorf("%w: missing status_list.lst", ErrMalformed)
	}
	cl := statusListClaims{Sub: p.Sub, Iat: p.Iat, Bits: p.StatusList.Bits, Lst: p.StatusList.Lst}
	if p.Exp != nil {
		cl.Exp = *p.Exp
	}
	if p.TTL != nil {
		cl.TTL = *p.TTL
	}
	return cl, nil
}
