package statuslist_test

import (
	"context"
	"testing"
	"time"

	sl "github.com/gmb-eudi/go-statuslist"
)

// Task A6: explicit conformance assertions that the verifier accepts the
// full draft-ietf-oauth-status-list shape a real issuer emits — typ + iat +
// exp + ttl all present together (§5.1/§5.2) — plus the CWT symmetric case
// for the A4 review minor (empty identifier_list ⇒ StatusValid, not
// ErrMalformed).

// TestConformantASLTokenJWT is the full realistic JWT Status List Token
// shape: typ (Task A2), iat in the past, exp far in the future, and a ttl
// hint (Task A7 caching), all present simultaneously. Confirms this, the
// exact shape a conformant issuer emits, is accepted end to end (index 0
// valid, index 1 revoked) with prov.Format == "jwt".
func TestConformantASLTokenJWT(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.jwt(t, tokenOpts{
		sub:      listURI,
		iat:      fixed.Add(-time.Hour).Unix(),
		exp:      fixed.Add(24 * time.Hour).Unix(),
		ttl:      3600,
		bits:     1,
		statuses: []int{0, 1},
	})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }))

	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if err != nil {
		t.Fatalf("index 0: err = %v, want nil", err)
	}
	if st != sl.StatusValid {
		t.Fatalf("index 0: st = %v, want StatusValid", st)
	}
	if prov.Format != "jwt" {
		t.Fatalf("index 0: prov.Format = %q, want %q", prov.Format, "jwt")
	}

	st, _, err = c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(1),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if err != nil {
		t.Fatalf("index 1: err = %v, want nil", err)
	}
	if st != sl.StatusRevoked {
		t.Fatalf("index 1: st = %v, want StatusRevoked", st)
	}
}

// TestConformantASLTokenCWT is the CWT analogue of TestConformantASLTokenJWT:
// the same full shape (COSE typ label 16, iat, exp, ttl claims) via the cwt
// builder, which emits status_list@65533 with a CBOR byte-string lst and
// ttl@65534. Confirms acceptance end to end with prov.Format == "cwt".
func TestConformantASLTokenCWT(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.cwt(t, tokenOpts{
		sub:      listURI,
		iat:      fixed.Add(-time.Hour).Unix(),
		exp:      fixed.Add(24 * time.Hour).Unix(),
		ttl:      3600,
		bits:     1,
		statuses: []int{0, 1},
	})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }))

	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if err != nil {
		t.Fatalf("index 0: err = %v, want nil", err)
	}
	if st != sl.StatusValid {
		t.Fatalf("index 0: st = %v, want StatusValid", st)
	}
	if prov.Format != "cwt" {
		t.Fatalf("index 0: prov.Format = %q, want %q", prov.Format, "cwt")
	}

	st, _, err = c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(1),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if err != nil {
		t.Fatalf("index 1: err = %v, want nil", err)
	}
	if st != sl.StatusRevoked {
		t.Fatalf("index 1: st = %v, want StatusRevoked", st)
	}
}

// TestIdentifierListEmptyCWTIsValid is the CWT symmetric case of
// TestIdentifierListEmptyIsValid (A4 review minor): a validly-signed CWT
// identifier list token WITH the identifier_list wrapper present but ids: []
// (empty) is a legitimate revocation list with nobody revoked. The A4
// pointer-vs-nil-slice fix (p.IdentifierList != nil but zero-length ids) must
// not over-reject this as ErrMalformed — every queried id resolves
// StatusValid.
func TestIdentifierListEmptyCWTIsValid(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idCWT(t, idListOpts{sub: idListURI, iat: 1_700_000_000, ids: []string{}})
	c, _ := checkerFor(tok)
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               sl.StatusRef{Kind: sl.RefIdentifierList, URI: idListURI, ID: "5"},
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if st != sl.StatusValid {
		t.Fatalf("st = %v, want StatusValid", st)
	}
}
