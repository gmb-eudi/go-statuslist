package statuslist_test

import (
	"context"
	"errors"
	"testing"

	sl "github.com/gmb-eudi/go-statuslist"
)

const idListURI = "https://issuer.example/revlists/1"

func idRef(id string) sl.StatusRef {
	return sl.StatusRef{Kind: sl.RefIdentifierList, URI: idListURI, ID: id}
}

// T-04.5: listed id ⇒ revoked; absent id ⇒ valid; for both JWT and CWT.
func TestIdentifierList(t *testing.T) {
	ti := newTestIssuer(t)
	forms := map[string]func(tb testing.TB, o idListOpts) []byte{"jwt": ti.idJWT, "cwt": ti.idCWT}
	for name, build := range forms {
		tok := build(t, idListOpts{sub: idListURI, iat: 1_700_000_000, ids: []string{"urn:cred:aaa", "urn:cred:bbb"}})
		t.Run(name+"/listed is revoked", func(t *testing.T) {
			c, _ := checkerFor(tok)
			st, prov, err := c.Check(context.Background(), sl.CheckInput{
				Ref: idRef("urn:cred:bbb"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
			})
			if err != nil {
				t.Fatal(err)
			}
			if st != sl.StatusRevoked {
				t.Errorf("st = %v, want StatusRevoked", st)
			}
			if prov.Mechanism != "identifier-list" || prov.ID != "urn:cred:bbb" || prov.Outcome != sl.OutcomeChecked {
				t.Errorf("prov %+v", prov)
			}
		})
		t.Run(name+"/absent is valid", func(t *testing.T) {
			c, _ := checkerFor(tok)
			st, _, err := c.Check(context.Background(), sl.CheckInput{
				Ref: idRef("urn:cred:zzz"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
			})
			if err != nil || st != sl.StatusValid {
				t.Fatalf("st = %v err = %v, want StatusValid", st, err)
			}
		})
	}
}

// sub binding applies to the identifier list too.
func TestIdentifierListSubBinding(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idJWT(t, idListOpts{sub: "https://issuer.example/revlists/OTHER", iat: 1_700_000_000, ids: []string{"urn:cred:aaa"}})
	c, _ := checkerFor(tok)
	_, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref: idRef("urn:cred:aaa"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
	})
	if !errors.Is(err, sl.ErrSubMismatch) {
		t.Fatalf("err = %v, want ErrSubMismatch", err)
	}
}

// Signature failure and fetch failure honour policy (fail-closed here).
func TestIdentifierListFailClosed(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idJWT(t, idListOpts{sub: idListURI, iat: 1_700_000_000, ids: []string{"urn:cred:aaa"}})
	c, _ := checkerFor(tok)
	_, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref: idRef("urn:cred:aaa"), IssuerKeyResolver: newTestIssuer(t).resolver(), Policy: sl.Policy{AllowFailOpen: false},
	})
	if !errors.Is(err, sl.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
}

// Review fix (T-04.5): a validly-signed token that OMITS the identifier_list
// wrapper entirely must fail closed (hard rule 7) rather than silently
// decoding to an empty id set — which would report StatusValid for every
// credential id, unconditionally, under any policy.
func TestIdentifierListMissingWrapperFailClosed(t *testing.T) {
	ti := newTestIssuer(t)
	t.Run("jwt", func(t *testing.T) {
		tok := ti.rawJWT(t, map[string]any{"sub": idListURI, "iat": 1_700_000_000})
		c, _ := checkerFor(tok)
		_, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: idRef("urn:cred:aaa"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("cwt", func(t *testing.T) {
		tok := ti.rawCWT(t, map[int64]any{2: idListURI, 6: int64(1_700_000_000)})
		c, _ := checkerFor(tok)
		_, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: idRef("urn:cred:aaa"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
}

// A token WITH identifier_list present but ids: [] (empty) is a legitimate
// revocation list with nobody revoked — every queried id must resolve
// StatusValid, not be rejected as malformed.
func TestIdentifierListEmptyIsValid(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idJWT(t, idListOpts{sub: idListURI, iat: 1_700_000_000, ids: []string{}})
	c, _ := checkerFor(tok)
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref: idRef("urn:cred:anything"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
	})
	if err != nil || st != sl.StatusValid {
		t.Fatalf("st = %v err = %v, want StatusValid", st, err)
	}
}

// A validly-signed token whose identifier_list wrapper IS present but is the
// wrong shape — a flat `{"id": status}` map with no "ids" member, as the
// EU/GO issuer's format ships — must fail closed rather than decode to an
// empty revoked-set (which would silently report StatusValid for every id,
// unconditionally, defeating the revocation check). T-04.5/A4.
func TestIdentifierListWrongShapeWrapperFailClosed(t *testing.T) {
	ti := newTestIssuer(t)
	t.Run("jwt", func(t *testing.T) {
		raw := ti.rawJWT(t, map[string]any{
			"sub":             idListURI,
			"iat":             int64(1_700_000_000),
			"identifier_list": map[string]any{"0": 1, "5": 1}, // a MAP, no "ids" key
		})
		c, _ := checkerFor(raw)
		st, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: idRef("5"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
		if st != sl.StatusUnknown {
			t.Fatalf("st = %v, want StatusUnknown (must NOT be StatusValid)", st)
		}
	})
	t.Run("cwt", func(t *testing.T) {
		raw := ti.rawCWT(t, map[int64]any{
			2:     idListURI,
			6:     int64(1_700_000_000),
			65532: map[string]any{"0": 1}, // wrapper present, no "ids" key
		})
		c, _ := checkerFor(raw)
		st, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: idRef("0"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
		if st != sl.StatusUnknown {
			t.Fatalf("st = %v, want StatusUnknown (must NOT be StatusValid)", st)
		}
	})
	// EU shape variant: ids live under a different claim key (65533) entirely,
	// leaving 65532 absent — also fails closed, via the p.IdentifierList == nil
	// half of the guard.
	t.Run("cwt/wrapper key entirely absent", func(t *testing.T) {
		raw := ti.rawCWT(t, map[int64]any{
			2:     idListURI,
			6:     int64(1_700_000_000),
			65533: map[string]any{"0": 1}, // wrong claim key; 65532 is absent
		})
		c, _ := checkerFor(raw)
		st, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: idRef("0"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
		if st != sl.StatusUnknown {
			t.Fatalf("st = %v, want StatusUnknown (must NOT be StatusValid)", st)
		}
	})
}

// A sub mismatch under explicit fail-open is skipped, not errored, and never
// reported as a real status — the identifier-list analogue of Task 4's
// TestSubBindingFailOpen.
func TestIdentifierListSubMismatchFailOpen(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idJWT(t, idListOpts{sub: "https://issuer.example/revlists/OTHER", iat: 1_700_000_000, ids: []string{"urn:cred:aaa"}})
	c, _ := checkerFor(tok)
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref: idRef("urn:cred:aaa"), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: true},
	})
	if err != nil || st != sl.StatusUnknown || !prov.FailOpen {
		t.Fatalf("st=%v prov=%+v err=%v", st, prov, err)
	}
}
