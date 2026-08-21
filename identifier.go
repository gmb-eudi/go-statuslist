package statuslist

import (
	"context"
	"encoding/json"
	"fmt"
)

// tokenMeta is the format-independent envelope of a signed revocation token
// (shared by the identifier list; Exp drives the Task 6 freshness check, TTL
// drives Task 7 caching).
type tokenMeta struct {
	Sub string
	Iat int64 // 0 = absent
	Exp int64 // 0 = absent
	TTL int64 // 0 = absent
}

// checkIdentifierList implements the ARF Attestation Revocation List
// ("Identifier List") mechanism (ARF Topic 7 VCR_11; a Relying Party that
// verifies revocation must support both this and the Attestation Status List
// mechanism per VCR_12). The list is a signed token enumerating revoked
// credential identifiers: a listed id ⇒ revoked, an absent id ⇒ valid.
//
// FORMAT FLAG: the wire shape is a documented synthetic choice, packaged and
// test-vectored with synthetic vectors (which do NOT define the ARL wire
// format itself). The format's authority is the design decisions plus the
// (unvendored) Commission TS referenced by VCR_11;
// until that TS is vendored and checked, this mechanism is experimental and
// this module only guarantees it fails closed on an unrecognized shape
// (SPECREFS.md).
func (c *Checker) checkIdentifierList(ctx context.Context, in CheckInput, prov Provenance) (Status, Provenance, error) {
	prov.Mechanism = "identifier-list"
	raw, fromCache, err := c.load(ctx, in.Ref.URI)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	prov.FromCache = fromCache
	payload, format, err := c.verifyToken(ctx, in, raw)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	prov.Format = format
	ids, meta, err := decodeIdentifierList(format, payload)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	// Same sub binding as the status list token (Task 4).
	if meta.Sub != in.Ref.URI {
		return c.failClosed(in.Policy, prov, fmt.Errorf("%w: token sub=%q ref uri=%q", ErrSubMismatch, meta.Sub, in.Ref.URI))
	}
	if err := c.applyFreshness(meta.Iat, meta.Exp, in.Policy, &prov); err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	c.maybeCache(in.Ref.URI, raw, meta.TTL, meta.Exp, prov.FromCache)
	if prov.FromCache {
		prov.Outcome = OutcomeCached
	} else {
		prov.Outcome = OutcomeChecked
	}
	if _, revoked := ids[in.Ref.ID]; revoked {
		return StatusRevoked, prov, nil
	}
	return StatusValid, prov, nil
}

// jsonIDList / cborIDList mirror the synthetic identifier-list payload. The
// CBOR private claim key 65532 is FLAGGED (verify against the VCR_11 TS).
// IdentifierList is a POINTER so a missing wrapper key (wrong-shape payload) is
// distinguishable from a legitimately-empty ids list (a revocation list with
// nobody revoked ⇒ everyone valid). IDs is ALSO a POINTER (*[]string), one
// level down, for the same reason: a wrapper that IS present but carries no
// "ids" member (e.g. a flat `{"0":1,"5":1}` map, as some issuers ship) must
// not be silently treated as an empty list. Using *[]string makes "ids
// member absent" an explicit nil pointer, unconflated with "ids": [] (a
// non-nil pointer to an empty slice) regardless of decoder quirks across the
// JSON and CBOR paths. A nil IdentifierList OR a nil IDs pointer ⇒
// ErrMalformed (fail closed) — mirrors decodeJWTClaims's
// `Lst == ""` guard. A non-nil IDs pointing at an empty slice is accepted:
// nobody is revoked, every id resolves StatusValid.
type jsonIDList struct {
	Sub            string `json:"sub"`
	Iat            int64  `json:"iat"`
	Exp            *int64 `json:"exp"`
	TTL            *int64 `json:"ttl"`
	IdentifierList *struct {
		IDs *[]string `json:"ids"`
	} `json:"identifier_list"`
}

type cborIDList struct {
	Sub            string `cbor:"2,keyasint"`
	Exp            *int64 `cbor:"4,keyasint"`
	Iat            int64  `cbor:"6,keyasint"`
	TTL            *int64 `cbor:"65534,keyasint"`
	IdentifierList *struct {
		IDs *[]string `cbor:"ids"`
	} `cbor:"65532,keyasint"`
}

func decodeIdentifierList(format string, payload []byte) (map[string]struct{}, tokenMeta, error) {
	set := map[string]struct{}{}
	switch format {
	case "jwt":
		var p jsonIDList
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: json id list: %w", ErrMalformed, err)
		}
		if p.IdentifierList == nil || p.IdentifierList.IDs == nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: missing identifier_list.ids", ErrMalformed)
		}
		for _, id := range *p.IdentifierList.IDs {
			set[id] = struct{}{}
		}
		return set, metaFrom(p.Sub, p.Iat, p.Exp, p.TTL), nil
	case "cwt":
		var p cborIDList
		if err := cwtDecMode.Unmarshal(payload, &p); err != nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: cbor id list: %w", ErrMalformed, err)
		}
		if p.IdentifierList == nil || p.IdentifierList.IDs == nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: missing identifier_list.ids", ErrMalformed)
		}
		for _, id := range *p.IdentifierList.IDs {
			set[id] = struct{}{}
		}
		return set, metaFrom(p.Sub, p.Iat, p.Exp, p.TTL), nil
	default:
		return nil, tokenMeta{}, fmt.Errorf("%w: id list format %q", ErrUnsupported, format)
	}
}

func metaFrom(sub string, iat int64, exp, ttl *int64) tokenMeta {
	m := tokenMeta{Sub: sub, Iat: iat}
	if exp != nil {
		m.Exp = *exp
	}
	if ttl != nil {
		m.TTL = *ttl
	}
	return m
}
