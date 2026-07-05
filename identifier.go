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
	Exp int64 // 0 = absent
	TTL int64 // 0 = absent
}

// checkIdentifierList implements the ARF Attestation Revocation List
// ("Identifier List") mechanism (ARF Topic 7 VCR_11; a revocation-checking RP
// must support it per VCR_02). The list is a signed token enumerating revoked
// credential identifiers: a listed id ⇒ revoked, an absent id ⇒ valid.
//
// FORMAT FLAG: the wire shape is a documented synthetic choice (ADR-0007) — the
// Commission TS referenced by VCR_11 is not vendored (SPECREFS.md). Verify
// before v1.
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
	if err := c.applyFreshness(meta.Exp, in.Policy, &prov); err != nil {
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
// nobody revoked ⇒ everyone valid). A nil pointer ⇒ ErrMalformed (fail closed,
// hard rule 7) — mirrors decodeJWTClaims's `Lst == ""` guard.
type jsonIDList struct {
	Sub            string `json:"sub"`
	Iat            int64  `json:"iat"`
	Exp            *int64 `json:"exp"`
	TTL            *int64 `json:"ttl"`
	IdentifierList *struct {
		IDs []string `json:"ids"`
	} `json:"identifier_list"`
}

type cborIDList struct {
	Sub            string `cbor:"2,keyasint"`
	Exp            *int64 `cbor:"4,keyasint"`
	Iat            int64  `cbor:"6,keyasint"`
	TTL            *int64 `cbor:"65534,keyasint"`
	IdentifierList *struct {
		IDs []string `cbor:"ids"`
	} `cbor:"65532,keyasint"`
}

func decodeIdentifierList(format string, payload []byte) (map[string]struct{}, tokenMeta, error) {
	set := map[string]struct{}{}
	switch format {
	case "jwt":
		var p jsonIDList
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: json id list: %v", ErrMalformed, err)
		}
		if p.IdentifierList == nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: missing identifier_list", ErrMalformed)
		}
		for _, id := range p.IdentifierList.IDs {
			set[id] = struct{}{}
		}
		return set, metaFrom(p.Sub, p.Exp, p.TTL), nil
	case "cwt":
		var p cborIDList
		if err := cwtDecMode.Unmarshal(payload, &p); err != nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: cbor id list: %v", ErrMalformed, err)
		}
		if p.IdentifierList == nil {
			return nil, tokenMeta{}, fmt.Errorf("%w: missing identifier_list", ErrMalformed)
		}
		for _, id := range p.IdentifierList.IDs {
			set[id] = struct{}{}
		}
		return set, metaFrom(p.Sub, p.Exp, p.TTL), nil
	default:
		return nil, tokenMeta{}, fmt.Errorf("%w: id list format %q", ErrUnsupported, format)
	}
}

func metaFrom(sub string, exp, ttl *int64) tokenMeta {
	m := tokenMeta{Sub: sub}
	if exp != nil {
		m.Exp = *exp
	}
	if ttl != nil {
		m.TTL = *ttl
	}
	return m
}
